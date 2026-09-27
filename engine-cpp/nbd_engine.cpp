// nbd-engine — the native NBD server behind `NbdServer` / `NbdFileShare` (engine: 'cpp').
//
// Everything on the guest's block path lives here, off Node's event loop: the fixed-newstyle NBD
// protocol QEMU speaks, positional file I/O, the copy-on-write layer stack (byte-compatible with
// src/nbd/layers.ts, so a layer written by either side is read by the other), the FAT32, ext4 and
// F2FS mappers that turn a block range back into guest file names, ground-truth redirects, and path routes to other
// stores. Node keeps the control plane: it opens the export, pushes/pops/swaps layers, sets
// redirects and routes, and receives an asynchronous stream of access events — never a callback on
// the hot path.
//
//   build:  npm run engine:build:nbd            (g++ / clang++ / MSVC; dependency-free C++17)
//   run:    NBD_ENGINE_TOKEN=<secret> nbd-engine [--port N] [--bind 127.0.0.1] [--owner PID]
//           → prints "READY <port>" (the CONTROL port)
//
// Control protocol (loopback TCP, same framing as the throughX engine):
//   u32 headerLen | JSON header | u32 binLen | bin
// Requests carry an `id`; replies echo it. Frames without an `id` are unsolicited events:
//   { event: 'access', batch: [{ command, offset, length, files: [{ path, fileOffset, bytes }] }] }
//   { event: 'connection', list: [{ state: 'open' | 'close', remote }] }
//
// Who may drive it: when NBD_ENGINE_TOKEN is set (NbdEngine.start always sets it, in the child's
// environment where other users' processes cannot read it), the first frame on a control
// connection must be { op: 'hello', token }. The first connection to authenticate owns the engine
// and the control port stops accepting, so no other local process can drive it or make it open
// host files. The NBD port serves only the export's exact name (random unless the caller picks
// one; it is not listed), at most MAX_CONNECTIONS clients at a time. The engine leaves when the
// control connection drops, or when --owner is gone.
#include <algorithm>
#include <atomic>
#include <cctype>
#include <cerrno>
#include <chrono>
#include <cmath>
#include <condition_variable>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <deque>
#include <functional>
#include <memory>
#include <mutex>
#include <new>
#include <set>
#include <shared_mutex>
#include <stdexcept>
#include <string>
#include <thread>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0601 // getaddrinfo, inet_ntop
#endif
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#ifdef _MSC_VER
#pragma comment(lib, "ws2_32.lib")
#endif
typedef SOCKET sock_t;
#define CLOSESOCK closesocket
#define SHUT_BOTH SD_BOTH
static const int SEND_FLAGS = 0;
#else
#include <arpa/inet.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <poll.h>
#include <signal.h>
#include <sys/file.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <unistd.h>
typedef int sock_t;
#define INVALID_SOCKET (-1)
#define CLOSESOCK close
#define SHUT_BOTH SHUT_RDWR
#ifdef MSG_NOSIGNAL
static const int SEND_FLAGS = MSG_NOSIGNAL; // a peer that went away is an error, not a SIGPIPE
#else
static const int SEND_FLAGS = 0;
#endif
#endif

using u8 = uint8_t; using u16 = uint16_t; using u32 = uint32_t; using u64 = uint64_t; using i64 = int64_t;

/**
 * A reader/writer lock that works with std::shared_lock / std::unique_lock. On Windows it is an
 * SRWLOCK: MinGW's winpthreads std::shared_mutex leaks two kernel handles every time one that was
 * locked is destroyed — one per layer opened, so every context switch leaked handles for the
 * engine's lifetime. An SRWLOCK needs no handle and no destruction.
 */
#ifdef _WIN32
struct RwLock {
  SRWLOCK l = SRWLOCK_INIT;
  RwLock() {}
  RwLock(const RwLock&) = delete;
  RwLock& operator=(const RwLock&) = delete;
  void lock() { AcquireSRWLockExclusive(&l); }
  void unlock() { ReleaseSRWLockExclusive(&l); }
  bool try_lock() { return TryAcquireSRWLockExclusive(&l) != 0; }
  void lock_shared() { AcquireSRWLockShared(&l); }
  void unlock_shared() { ReleaseSRWLockShared(&l); }
  bool try_lock_shared() { return TryAcquireSRWLockShared(&l) != 0; }
};
#else
using RwLock = std::shared_mutex;
#endif
static bool recvAll(sock_t s, char* p, size_t n) { while (n) { int r = (int)recv(s, p, (int)std::min<size_t>(n, 1 << 20), 0); if (r <= 0) return false; p += r; n -= (size_t)r; } return true; }
static bool sendAll(sock_t s, const char* p, size_t n) { while (n) { int r = (int)send(s, p, (int)std::min<size_t>(n, 1 << 20), SEND_FLAGS); if (r <= 0) return false; p += r; n -= (size_t)r; } return true; }
static bool traceOn() { static const bool on = getenv("NBD_ENGINE_TRACE") != nullptr; return on; }

/** Wait until a socket has something to accept/read: >0 ready, 0 timeout, <0 error. */
static int waitReadable(sock_t s, int ms) {
#ifdef _WIN32
  fd_set rf; FD_ZERO(&rf); FD_SET(s, &rf); timeval tv; tv.tv_sec = ms / 1000; tv.tv_usec = (ms % 1000) * 1000;
  return select(0, &rf, nullptr, nullptr, &tv);
#else
  pollfd p; p.fd = s; p.events = POLLIN; p.revents = 0;
  int r = poll(&p, 1, ms);
  return r < 0 && errno == EINTR ? 0 : r;
#endif
}
static void setRecvTimeout(sock_t s, int ms) {
#ifdef _WIN32
  DWORD t = (DWORD)ms; setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, (const char*)&t, sizeof t);
#else
  timeval t; t.tv_sec = ms / 1000; t.tv_usec = (ms % 1000) * 1000; setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, &t, sizeof t);
#endif
}
static std::string sysErr() {
#ifdef _WIN32
  DWORD e = GetLastError(); char buf[256] = {0};
  FormatMessageA(FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS, nullptr, e, 0, buf, sizeof buf - 1, nullptr);
  std::string s(buf); while (!s.empty() && (s.back() == '\n' || s.back() == '\r' || s.back() == ' ' || s.back() == '.')) s.pop_back();
  return s.empty() ? "error " + std::to_string(e) : s;
#else
  return strerror(errno);
#endif
}

// ----------------------------------------------------------------------------------------------
// JSON (the same shape as the throughX engine's, with a parser that never reads past its input).
// ----------------------------------------------------------------------------------------------
static void putUtf8(std::string& o, u32 v) {
  if (v < 0x80) o += (char)v;
  else if (v < 0x800) { o += (char)(0xC0 | (v >> 6)); o += (char)(0x80 | (v & 0x3F)); }
  else if (v < 0x10000) { o += (char)(0xE0 | (v >> 12)); o += (char)(0x80 | ((v >> 6) & 0x3F)); o += (char)(0x80 | (v & 0x3F)); }
  else { o += (char)(0xF0 | (v >> 18)); o += (char)(0x80 | ((v >> 12) & 0x3F)); o += (char)(0x80 | ((v >> 6) & 0x3F)); o += (char)(0x80 | (v & 0x3F)); }
}
struct J {
  enum T { NUL, BOOL, NUM, STR, ARR, OBJ } t = NUL;
  bool b = false; double n = 0; std::string s; std::vector<J> a; std::vector<std::pair<std::string, J>> o;
  J() {}
  static J num(double v) { J j; j.t = NUM; j.n = v; return j; }
  static J str(const std::string& v) { J j; j.t = STR; j.s = v; return j; }
  static J boolean(bool v) { J j; j.t = BOOL; j.b = v; return j; }
  static J arr() { J j; j.t = ARR; return j; }
  static J obj() { J j; j.t = OBJ; return j; }
  J& set(const std::string& k, J v) { for (auto& kv : o) if (kv.first == k) { kv.second = std::move(v); return *this; } o.emplace_back(k, std::move(v)); return *this; }
  J& push(J v) { a.push_back(std::move(v)); return *this; }
  const J* get(const std::string& k) const { for (auto& kv : o) if (kv.first == k) return &kv.second; return nullptr; }
  double numOr(const std::string& k, double d) const { auto v = get(k); return v && v->t == NUM ? v->n : d; }
  std::string strOr(const std::string& k, const std::string& d) const { auto v = get(k); return v && v->t == STR ? v->s : d; }
  bool boolOr(const std::string& k, bool d) const { auto v = get(k); return v && v->t == BOOL ? v->b : d; }
};
static void jw(const J& j, std::string& out) {
  char buf[64];
  switch (j.t) {
    case J::NUL: out += "null"; break;
    case J::BOOL: out += j.b ? "true" : "false"; break;
    case J::NUM:
      if (!std::isfinite(j.n)) out += "null";
      else if (j.n == std::floor(j.n) && std::fabs(j.n) < 9e15) { snprintf(buf, sizeof buf, "%lld", (long long)j.n); out += buf; }
      else { snprintf(buf, sizeof buf, "%.17g", j.n); out += buf; }
      break;
    case J::STR:
      out += '"';
      for (char c : j.s) {
        if (c == '"' || c == '\\') { out += '\\'; out += c; }
        else if (c == '\n') out += "\\n"; else if (c == '\r') out += "\\r"; else if (c == '\t') out += "\\t";
        else if ((unsigned char)c < 0x20) { snprintf(buf, sizeof buf, "\\u%04x", (unsigned)(unsigned char)c); out += buf; }
        else out += c;
      }
      out += '"';
      break;
    case J::ARR: out += '['; for (size_t i = 0; i < j.a.size(); i++) { if (i) out += ','; jw(j.a[i], out); } out += ']'; break;
    case J::OBJ: out += '{'; for (size_t i = 0; i < j.o.size(); i++) { if (i) out += ','; jw(J::str(j.o[i].first), out); out += ':'; jw(j.o[i].second, out); } out += '}'; break;
  }
}
struct JP {
  const std::string& s; size_t i = 0; int depth = 0;
  explicit JP(const std::string& x) : s(x) {}
  [[noreturn]] void fail(const char* what) { throw std::runtime_error(std::string("bad JSON: ") + what); }
  char peek() const { return i < s.size() ? s[i] : '\0'; }
  char next() { if (i >= s.size()) fail("unexpected end"); return s[i++]; }
  void ws() { while (i < s.size() && isspace((unsigned char)s[i])) i++; }
  J parse() { J v = val(); ws(); if (i != s.size()) fail("trailing data"); return v; }
  J val() {
    ws(); if (i >= s.size()) fail("unexpected end");
    if (++depth > 64) fail("nested too deeply");
    J v = inner(); depth--; return v;
  }
  J inner() {
    char c = s[i];
    if (c == '{') {
      J j = J::obj(); i++; ws(); if (peek() == '}') { i++; return j; }
      for (;;) { ws(); std::string k = str(); ws(); if (next() != ':') fail("expected ':'"); j.o.emplace_back(std::move(k), val()); ws(); char d = next(); if (d == '}') return j; if (d != ',') fail("expected ',' or '}'"); }
    }
    if (c == '[') {
      J j = J::arr(); i++; ws(); if (peek() == ']') { i++; return j; }
      for (;;) { j.a.push_back(val()); ws(); char d = next(); if (d == ']') return j; if (d != ',') fail("expected ',' or ']'"); }
    }
    if (c == '"') return J::str(str());
    if (!s.compare(i, 4, "true")) { i += 4; return J::boolean(true); }
    if (!s.compare(i, 5, "false")) { i += 5; return J::boolean(false); }
    if (!s.compare(i, 4, "null")) { i += 4; return J(); }
    size_t st = i; if (peek() == '-') i++;
    while (i < s.size() && (isdigit((unsigned char)s[i]) || s[i] == '.' || s[i] == 'e' || s[i] == 'E' || s[i] == '+' || s[i] == '-')) i++;
    if (i == st) fail("unexpected character");
    std::string num = s.substr(st, i - st); char* end = nullptr; double v = strtod(num.c_str(), &end);
    if (!end || *end) fail("bad number");
    return J::num(v);
  }
  u32 hex4() {
    if (i + 4 > s.size()) fail("short \\u escape");
    u32 v = 0;
    for (int k = 0; k < 4; k++) { char h = s[i++]; v <<= 4; if (h >= '0' && h <= '9') v |= (u32)(h - '0'); else if (h >= 'a' && h <= 'f') v |= (u32)(h - 'a' + 10); else if (h >= 'A' && h <= 'F') v |= (u32)(h - 'A' + 10); else fail("bad \\u escape"); }
    return v;
  }
  std::string str() {
    if (next() != '"') fail("expected a string");
    std::string o;
    for (;;) {
      char c = next();
      if (c == '"') return o;
      if (c != '\\') { o += c; continue; }
      char e = next();
      switch (e) {
        case 'n': o += '\n'; break; case 't': o += '\t'; break; case 'r': o += '\r'; break; case 'b': o += '\b'; break; case 'f': o += '\f'; break;
        case 'u': {
          u32 v = hex4();
          if (v >= 0xD800 && v <= 0xDBFF && i + 6 <= s.size() && s[i] == '\\' && s[i + 1] == 'u') {
            size_t save = i; i += 2; u32 lo = hex4();
            if (lo >= 0xDC00 && lo <= 0xDFFF) v = 0x10000 + ((v - 0xD800) << 10) + (lo - 0xDC00); else i = save;
          }
          putUtf8(o, v); break;
        }
        default: o += e;
      }
    }
  }
};

// ----------------------------------------------------------------------------------------------
// Files: positional I/O (thread-safe, so several guest connections can hit one file at once), with
// paths taken as UTF-8 — on Windows they are widened, so a profile under a non-ASCII user
// directory opens like any other.
// ----------------------------------------------------------------------------------------------
#ifdef _WIN32
static std::wstring widen(const std::string& s) {
  if (s.empty()) return std::wstring();
  UINT cp = CP_UTF8;
  int n = MultiByteToWideChar(cp, MB_ERR_INVALID_CHARS, s.data(), (int)s.size(), nullptr, 0);
  if (n <= 0) { cp = CP_ACP; n = MultiByteToWideChar(cp, 0, s.data(), (int)s.size(), nullptr, 0); } // not UTF-8: the ANSI code page
  std::wstring w((size_t)std::max(n, 0), L'\0');
  if (n > 0) MultiByteToWideChar(cp, 0, s.data(), (int)s.size(), &w[0], n);
  return w;
}
static bool fileExists(const std::string& p) { return GetFileAttributesW(widen(p).c_str()) != INVALID_FILE_ATTRIBUTES; }
static bool removeFile(const std::string& p) { return DeleteFileW(widen(p).c_str()) != 0; }
static bool renameFile(const std::string& a, const std::string& b) { return MoveFileExW(widen(a).c_str(), widen(b).c_str(), MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH) != 0; }
#else
static bool fileExists(const std::string& p) { struct stat st; return ::stat(p.c_str(), &st) == 0; }
static bool removeFile(const std::string& p) { return ::unlink(p.c_str()) == 0; }
static bool renameFile(const std::string& a, const std::string& b) { return ::rename(a.c_str(), b.c_str()) == 0; }
#endif

// Create the missing parent directories of a file about to be created (a new layer, its index and
// lock, a new image, a mirror file), so './profiles/berlin/system.layer' works on a fresh tree.
// Failures are left to the open that follows, which reports the real error.
static void ensureParentDir(const std::string& p) {
  size_t cut = p.find_last_of("/\\");
  if (cut == std::string::npos || cut == 0) return;
  std::string dir = p.substr(0, cut);
  for (size_t i = 1; i <= dir.size(); i++) {
    if (i < dir.size() && dir[i] != '/' && dir[i] != '\\') continue;
    std::string pre = dir.substr(0, i);
    if (pre.back() == ':') continue; // a drive root such as "C:"
#ifdef _WIN32
    CreateDirectoryW(widen(pre).c_str(), nullptr);
#else
    ::mkdir(pre.c_str(), 0755);
#endif
  }
}

struct PFile {
  enum Mode { READ, RW, CREATE /* open or create, read-write */, EXCL /* create; fail if it exists */ };
#ifdef _WIN32
  HANDLE h = INVALID_HANDLE_VALUE;
  bool open(const std::string& path, Mode m) {
    DWORD access = m == READ ? GENERIC_READ : (GENERIC_READ | GENERIC_WRITE);
    DWORD disp = m == READ || m == RW ? OPEN_EXISTING : m == CREATE ? OPEN_ALWAYS : CREATE_NEW;
    if (m == CREATE || m == EXCL) ensureParentDir(path);
    h = CreateFileW(widen(path).c_str(), access, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr, disp, FILE_ATTRIBUTE_NORMAL, nullptr);
    return h != INVALID_HANDLE_VALUE;
  }
  bool isOpen() const { return h != INVALID_HANDLE_VALUE; }
  i64 size() const { LARGE_INTEGER li; if (!GetFileSizeEx(h, &li)) return -1; return li.QuadPart; }
  bool truncate(i64 n) { LARGE_INTEGER li; li.QuadPart = n; return SetFilePointerEx(h, li, nullptr, FILE_BEGIN) && SetEndOfFile(h); }
  // Reads past the end come back zero-filled, like FileBackend and CowLayer in Node.
  bool pread(void* buf, size_t n, i64 off) const {
    if (h == INVALID_HANDLE_VALUE) return false;
    char* p = (char*)buf; size_t done = 0;
    while (done < n) {
      OVERLAPPED ov; memset(&ov, 0, sizeof ov); i64 o = off + (i64)done; ov.Offset = (DWORD)(o & 0xffffffff); ov.OffsetHigh = (DWORD)(o >> 32);
      DWORD got = 0;
      if (!ReadFile(h, p + done, (DWORD)std::min<size_t>(n - done, 1 << 24), &got, &ov)) { if (GetLastError() == ERROR_HANDLE_EOF) got = 0; else return false; }
      if (got == 0) { memset(p + done, 0, n - done); return true; }
      done += got;
    }
    return true;
  }
  bool pwrite(const void* buf, size_t n, i64 off) {
    if (h == INVALID_HANDLE_VALUE) return false;
    const char* p = (const char*)buf; size_t done = 0;
    while (done < n) {
      OVERLAPPED ov; memset(&ov, 0, sizeof ov); i64 o = off + (i64)done; ov.Offset = (DWORD)(o & 0xffffffff); ov.OffsetHigh = (DWORD)(o >> 32);
      DWORD put = 0;
      if (!WriteFile(h, p + done, (DWORD)std::min<size_t>(n - done, 1 << 24), &put, &ov) || put == 0) return false;
      done += put;
    }
    return true;
  }
  bool flush() { return h != INVALID_HANDLE_VALUE && FlushFileBuffers(h) != 0; }
  void close() { if (h != INVALID_HANDLE_VALUE) CloseHandle(h); h = INVALID_HANDLE_VALUE; }
#else
  int fd = -1;
  bool open(const std::string& path, Mode m) {
    int flags = m == READ ? O_RDONLY : m == RW ? O_RDWR : m == CREATE ? (O_RDWR | O_CREAT) : (O_RDWR | O_CREAT | O_EXCL);
#ifdef O_CLOEXEC
    flags |= O_CLOEXEC;
#endif
    if (m == CREATE || m == EXCL) ensureParentDir(path);
    fd = ::open(path.c_str(), flags, 0644);
    return fd >= 0;
  }
  bool isOpen() const { return fd >= 0; }
  i64 size() const { struct stat st; if (fstat(fd, &st) != 0) return -1; return st.st_size; }
  bool truncate(i64 n) { return ftruncate(fd, n) == 0; }
  bool pread(void* buf, size_t n, i64 off) const {
    if (fd < 0) return false;
    char* p = (char*)buf; size_t done = 0;
    while (done < n) { ssize_t r = ::pread(fd, p + done, n - done, off + (i64)done); if (r < 0) { if (errno == EINTR) continue; return false; } if (r == 0) { memset(p + done, 0, n - done); return true; } done += (size_t)r; }
    return true;
  }
  bool pwrite(const void* buf, size_t n, i64 off) {
    if (fd < 0) return false;
    const char* p = (const char*)buf; size_t done = 0;
    while (done < n) { ssize_t r = ::pwrite(fd, p + done, n - done, off + (i64)done); if (r < 0 && errno == EINTR) continue; if (r <= 0) return false; done += (size_t)r; }
    return true;
  }
  bool flush() { return fd >= 0 && fsync(fd) == 0; }
  void close() { if (fd >= 0) ::close(fd); fd = -1; }
#endif
};

static long selfPid() {
#ifdef _WIN32
  return (long)GetCurrentProcessId();
#else
  return (long)getpid();
#endif
}
static bool pidAlive(long pid) {
  if (pid <= 0) return false;
#ifdef _WIN32
  HANDLE h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, (DWORD)pid);
  if (!h) return GetLastError() == ERROR_ACCESS_DENIED; // it exists; it just is not ours to look at
  DWORD code = 0; bool alive = GetExitCodeProcess(h, &code) && code == STILL_ACTIVE;
  CloseHandle(h);
  return alive;
#else
  return kill((pid_t)pid, 0) == 0 || errno == EPERM;
#endif
}

/**
 * `<layer>.lock`: an OS lock held for as long as the layer is open for writing. Two writers would
 * hand out the same slots and overwrite each other's blocks, so the second is refused. Because the
 * OS drops the lock the moment its process ends — a hard kill included — a lock is never judged
 * stale from a pid that may by now belong to someone else, and there is no takeover to race.
 *   Windows: the file stays open without write sharing — the same exclusion src/nbd/layers.ts gets
 *            from its exclusive open, so the two engines keep each other out.
 *   POSIX:   flock(). Node cannot flock, so the JS engine's lock there is its pid in the file,
 *            and a live pid other than ours is honoured as well.
 * The pid in the file is otherwise only for the error message.
 */
struct LayerLock {
  std::string path; bool held = false;
#ifdef _WIN32
  HANDLE h = INVALID_HANDLE_VALUE;
#else
  int fd = -1;
#endif
  static long ownerOf(const std::string& p) {
    PFile r; long owner = 0;
    if (r.open(p, PFile::READ)) { char b[32] = {0}; i64 n = std::min<i64>(r.size(), 31); if (n > 0) r.pread(b, (size_t)n, 0); r.close(); owner = atol(b); }
    return owner;
  }
  [[noreturn]] void busy(const std::string& layerPath) const {
    long owner = ownerOf(path);
    if (owner == selfPid()) throw std::runtime_error("layer " + layerPath + " is already open in this engine");
    throw std::runtime_error("layer " + layerPath + " is in use by " + (owner > 0 ? "process " + std::to_string(owner) : std::string("another process")) + " (" + path + ")");
  }
  void acquire(const std::string& layerPath) {
    path = layerPath + ".lock";
    std::string pid = std::to_string(selfPid()) + "\n";
    ensureParentDir(path);
#ifdef _WIN32
    h = CreateFileW(widen(path).c_str(), GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ, nullptr, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE) {
      DWORD e = GetLastError();
      if (e == ERROR_SHARING_VIOLATION || e == ERROR_LOCK_VIOLATION) busy(layerPath);
      throw std::runtime_error("cannot lock layer " + layerPath + ": " + sysErr());
    }
    DWORD put = 0; LARGE_INTEGER zero; zero.QuadPart = 0;
    SetFilePointerEx(h, zero, nullptr, FILE_BEGIN); WriteFile(h, pid.data(), (DWORD)pid.size(), &put, nullptr); SetEndOfFile(h);
#else
    fd = ::open(path.c_str(), O_RDWR | O_CREAT | O_CLOEXEC, 0644);
    if (fd < 0) throw std::runtime_error("cannot lock layer " + layerPath + ": " + sysErr());
    if (flock(fd, LOCK_EX | LOCK_NB) != 0) {
      bool held_ = errno == EWOULDBLOCK; ::close(fd); fd = -1;
      if (held_) busy(layerPath);
      throw std::runtime_error("cannot lock layer " + layerPath + ": " + sysErr());
    }
    long owner = ownerOf(path);
    if (owner > 0 && owner != selfPid() && pidAlive(owner)) { ::close(fd); fd = -1; busy(layerPath); } // the JS engine's lock
    if (ftruncate(fd, 0) != 0 || ::pwrite(fd, pid.data(), pid.size(), 0) < 0) { /* the pid is only a diagnostic */ }
#endif
    held = true;
  }
  void release() {
    if (!held) return;
    held = false;
#ifdef _WIN32
    CloseHandle(h); h = INVALID_HANDLE_VALUE;
    DeleteFileW(widen(path).c_str()); // refused, harmlessly, if another opener holds it by now
#else
    ::unlink(path.c_str()); ::close(fd); fd = -1;
#endif
  }
};

// ----------------------------------------------------------------------------------------------
// Backends: a file, a copy-on-write layer over another backend, and a stack of layers.
// `close()` releases only the backend's OWN files — never what it reads through.
// ----------------------------------------------------------------------------------------------
struct Backend {
  virtual ~Backend() {}
  virtual i64 size() const = 0;
  virtual bool read(i64 off, size_t n, char* out) = 0;
  virtual bool write(i64 off, const char* data, size_t n) = 0;
  virtual bool flush() { return true; }
  virtual bool readonly() const { return false; }
  virtual void close() {}
};

struct FileBackend : Backend {
  PFile f; i64 sz = 0; bool ro = false;
  FileBackend(const std::string& path, i64 size, bool readonly) {
    ro = readonly;
    bool existed = fileExists(path);
    // A missing image is created blank only when a size says how big; without one it would be a
    // 0-byte disk a guest cannot boot or mount. Node's FileBackend applies the same rule.
    if (!existed) {
      if (size <= 0) throw std::runtime_error("backing file not found: " + path + " (give a size to create a blank one)");
      PFile c;
      bool ok = c.open(path, PFile::CREATE) && c.truncate(size);
      c.close();
      if (!ok) throw std::runtime_error("cannot create " + path + ": " + sysErr());
    }
    if (!f.open(path, readonly ? PFile::READ : PFile::CREATE)) throw std::runtime_error("cannot open " + path + ": " + sysErr());
    i64 cur = f.size();
    if (size > 0 && cur < size && !readonly) { if (!f.truncate(size)) { f.close(); throw std::runtime_error("cannot size " + path + ": " + sysErr()); } cur = size; }
    sz = size > 0 ? size : cur;
  }
  i64 size() const override { return sz; }
  bool read(i64 off, size_t n, char* out) override { return f.pread(out, n, off); }
  bool write(i64 off, const char* data, size_t n) override { if (ro) return false; return f.pwrite(data, n, off); }
  bool flush() override { return ro || f.flush(); }
  bool readonly() const override { return ro; }
  void close() override { f.close(); }
};

static void le32w(char* p, u32 v) { p[0] = (char)v; p[1] = (char)(v >> 8); p[2] = (char)(v >> 16); p[3] = (char)(v >> 24); }
static u32 le32r(const char* p) { return (u32)(u8)p[0] | ((u32)(u8)p[1] << 8) | ((u32)(u8)p[2] << 16) | ((u32)(u8)p[3] << 24); }
static void le16w(char* p, u16 v) { p[0] = (char)v; p[1] = (char)(v >> 8); }

// crc32c (Castagnoli, reflected) — ext4's metadata_csum. Matches src/nbd/ext4.ts's crc32c.
static u32 crc32c(u32 seed, const char* p, size_t n) {
  static u32 tab[256];
  static bool init = false;
  if (!init) { for (u32 i = 0; i < 256; i++) { u32 c = i; for (int k = 0; k < 8; k++) c = (c & 1) ? (0x82F63B78u ^ (c >> 1)) : (c >> 1); tab[i] = c; } init = true; }
  u32 c = seed;
  for (size_t i = 0; i < n; i++) c = tab[(c ^ (u8)p[i]) & 0xff] ^ (c >> 8);
  return c;
}

// The on-disk format of src/nbd/layers.ts. `<path>` holds owned blocks packed in allocation order.
// `<path>.map` is a 16-byte header ("NBDLAYR1", block size u32, reserved u32) followed by one
// 12-byte entry per slot, entry i at 16 + 12·i: block u32, slot u32 (= i), check = block ^ slot ^
// CHECK_SALT, all little-endian. An entry only counts when its check matches AND its slot is its
// position, so a torn tail or a zero-filled gap is never mistaken for "block 0 lives in slot 0".
//
// A new block's entry is written only once the block itself is DURABLE — at the guest's FLUSH, on
// close, and every COMMIT_EVERY new blocks — because nothing orders write-back between two files:
// written together, the index could reach the disk first, and after a power cut an entry would
// point at a slot that holds nothing, zeroing a whole block including sectors the guest had long
// since flushed below. Until then the entries live in memory (reads see them). A crash before the
// commit loses those blocks — unflushed writes, which NBD allows to be lost — and nothing else.
static const char MAP_MAGIC[8] = {'N', 'B', 'D', 'L', 'A', 'Y', 'R', '1'};
static const u32 MAP_HEADER = 16, ENTRY = 12, CHECK_SALT = 0x4C415952u;
static const u32 DEFAULT_BS = 4096;
static const size_t COMMIT_EVERY = 1024;

struct CowLayer : Backend {
  std::shared_ptr<Backend> below; std::string path, label; u32 bs = DEFAULT_BS; bool ro = false;
  PFile data, map; LayerLock lock; std::unordered_map<u32, u32> slots; u32 nextSlot = 0;
  std::vector<std::pair<u32, u32>> pending; // (block, slot) of new blocks whose entries wait for their data
  mutable RwLock mu; bool closed = false;

  CowLayer(std::shared_ptr<Backend> b, const std::string& p, const std::string& lbl, u32 requestedBs, bool readonly)
      : below(std::move(b)), path(p), label(lbl), ro(readonly) {
    if (requestedBs % 512) throw std::runtime_error("layer block size must be a positive multiple of 512");
    if (!ro) lock.acquire(path);
    try { openFiles(requestedBs); }
    catch (...) { data.close(); map.close(); lock.release(); throw; }
  }
  void openFiles(u32 requestedBs) {
    bool fresh = !fileExists(path);
    if (fresh && ro) throw std::runtime_error("read-only layer does not exist: " + path);
    if (!data.open(path, ro ? PFile::READ : PFile::CREATE)) throw std::runtime_error("cannot open layer " + path + ": " + sysErr());
    std::string mp = path + ".map";
    if (ro && !fileExists(mp)) { bs = requestedBs ? requestedBs : DEFAULT_BS; checkBlocks(); return; } // owns nothing
    if (!map.open(mp, ro ? PFile::READ : PFile::CREATE)) throw std::runtime_error("cannot open layer index " + mp + ": " + sysErr());
    i64 sz = map.size(); if (sz < 0) throw std::runtime_error("cannot size layer index " + mp);
    std::vector<char> buf((size_t)sz);
    if (sz && !map.pread(buf.data(), (size_t)sz, 0)) throw std::runtime_error("cannot read layer index " + mp + ": " + sysErr());
    bool header = sz >= 8 && memcmp(buf.data(), MAP_MAGIC, 8) == 0;
    bool headerPrefix = sz < 8 && memcmp(buf.data(), MAP_MAGIC, (size_t)sz) == 0; // includes an empty index
    if (header && sz >= (i64)MAP_HEADER) {
      u32 stored = le32r(&buf[8]);
      if (stored == 0 || stored % 512) throw std::runtime_error("layer index " + mp + " records a bad block size (" + std::to_string(stored) + ")");
      if (requestedBs && requestedBs != stored)
        throw std::runtime_error("layer " + path + " was created with " + std::to_string(stored) + "-byte blocks, not " + std::to_string(requestedBs));
      bs = stored; replay(buf, MAP_HEADER, CHECK_SALT);
    } else if (header || headerPrefix) {
      bs = requestedBs ? requestedBs : DEFAULT_BS; // new, or its header was torn: nothing was ever allocated
      if (!ro) writeHeader();
    } else {
      // A layer from before the index had a header: entries from byte 0, check = block ^ slot.
      bs = requestedBs ? requestedBs : DEFAULT_BS;
      replay(buf, 0, 0);
      if (!ro) upgrade();
    }
    checkBlocks();
  }
  void checkBlocks() {
    u64 blocks = ((u64)below->size() + bs - 1) / bs;
    if (blocks >= 0xFFFFFFFFull) throw std::runtime_error("the image is too large for " + std::to_string(bs) + "-byte layer blocks (a layer indexes at most 2^32 - 1 blocks)");
  }
  void replay(const std::vector<char>& buf, size_t start, u32 salt) {
    u32 i = 0;
    for (size_t off = start; off + ENTRY <= buf.size(); off += ENTRY, i++) {
      u32 block = le32r(&buf[off]), slot = le32r(&buf[off + 4]), check = le32r(&buf[off + 8]);
      if ((block ^ slot ^ salt) != check || slot != i) continue; // torn, or never completed
      slots[block] = slot; if (slot + 1 > nextSlot) nextSlot = slot + 1;
    }
  }
  void writeHeader() {
    char h[MAP_HEADER]; memcpy(h, MAP_MAGIC, 8); le32w(h + 8, bs); le32w(h + 12, 0);
    if (!map.pwrite(h, MAP_HEADER, 0)) throw std::runtime_error("cannot write layer index " + path + ".map: " + sysErr());
  }
  /** Rewrite a header-less index in the current format (to a temp file, then renamed over it). */
  void upgrade() {
    std::string mp = path + ".map", tmp = mp + ".upgrade";
    std::vector<char> out(MAP_HEADER + (size_t)nextSlot * ENTRY, 0);
    memcpy(out.data(), MAP_MAGIC, 8); le32w(&out[8], bs);
    for (auto& kv : slots) { char* e = &out[MAP_HEADER + (size_t)kv.second * ENTRY]; le32w(e, kv.first); le32w(e + 4, kv.second); le32w(e + 8, kv.first ^ kv.second ^ CHECK_SALT); }
    PFile t;
    if (!t.open(tmp, PFile::CREATE) || !t.truncate(0) || !t.pwrite(out.data(), out.size(), 0) || !t.flush()) { t.close(); removeFile(tmp); throw std::runtime_error("cannot upgrade layer index " + mp + ": " + sysErr()); }
    t.close(); map.close();
    if (!renameFile(tmp, mp)) { removeFile(tmp); throw std::runtime_error("cannot upgrade layer index " + mp + ": " + sysErr()); }
    if (!map.open(mp, PFile::RW)) throw std::runtime_error("cannot reopen layer index " + mp + ": " + sysErr());
  }

  i64 size() const override { return below->size(); }
  bool readonly() const override { return ro; }
  size_t owned() const { std::shared_lock<RwLock> g(mu); return slots.size(); }

  bool read(i64 off, size_t n, char* out) override {
    if (!below->read(off, n, out)) return false;
    std::shared_lock<RwLock> g(mu);
    if (closed) return false;
    if (slots.empty()) return true;
    i64 pos = off, end = off + (i64)n;
    while (pos < end) {
      u32 block = (u32)(pos / bs); size_t inBlock = (size_t)(pos - (i64)block * bs); size_t take = std::min<size_t>(bs - inBlock, (size_t)(end - pos));
      auto it = slots.find(block);
      if (it != slots.end() && !data.pread(out + (pos - off), take, (i64)it->second * bs + (i64)inBlock)) return false;
      pos += (i64)take;
    }
    return true;
  }
  bool write(i64 off, const char* src, size_t n) override {
    if (ro) return false;
    std::unique_lock<RwLock> g(mu);
    if (closed) return false;
    i64 pos = off, end = off + (i64)n;
    std::vector<char> whole;
    while (pos < end) {
      u32 block = (u32)(pos / bs); size_t inBlock = (size_t)(pos - (i64)block * bs); size_t take = std::min<size_t>(bs - inBlock, (size_t)(end - pos));
      const char* chunk = src + (pos - off);
      auto it = slots.find(block);
      if (it != slots.end()) {
        if (!data.pwrite(chunk, take, (i64)it->second * bs + (i64)inBlock)) return false;
      } else {
        u32 slot = nextSlot;
        if (slot == 0xFFFFFFFFu) return false;
        const char* bytes = chunk;
        if (take != bs) { // copy-on-write: keep the rest of the block, which still lives below
          whole.resize(bs);
          if (!below->read((i64)block * bs, bs, whole.data())) return false;
          memcpy(whole.data() + inBlock, chunk, take); bytes = whole.data();
        }
        if (!data.pwrite(bytes, bs, (i64)slot * bs)) return false; // nothing recorded: the slot is handed out again
        slots[block] = slot; nextSlot = slot + 1;
        pending.emplace_back(block, slot); // its entry is written once the block is durable
      }
      pos += (i64)take;
    }
    if (pending.size() >= COMMIT_EVERY) commit(); // a failure here surfaces at the next FLUSH
    return true;
  }
  /** Make the new blocks durable, then write and sync the entries that point at them. Caller holds mu exclusively. */
  bool commit() {
    if (pending.empty()) return true;
    if (!data.flush()) return false; // the entries must never reach the disk before their blocks
    u32 first = pending.front().second; // slots are handed out in order, so the entries are contiguous
    std::vector<char> recs(pending.size() * ENTRY);
    for (size_t i = 0; i < pending.size(); i++) {
      char* e = &recs[i * ENTRY]; u32 block = pending[i].first, slot = pending[i].second;
      le32w(e, block); le32w(e + 4, slot); le32w(e + 8, block ^ slot ^ CHECK_SALT);
    }
    if (!map.pwrite(recs.data(), recs.size(), (i64)MAP_HEADER + (i64)first * ENTRY) || !map.flush()) return false;
    pending.clear();
    return true;
  }
  bool flush() override {
    std::unique_lock<RwLock> g(mu);
    if (closed || ro) return true;
    if (!pending.empty()) return commit();
    return data.flush() && map.flush();
  }
  void close() override {
    std::unique_lock<RwLock> g(mu);
    if (closed) return;
    if (!ro) commit(); // what a clean close has, a reopen has
    closed = true; data.close(); map.close(); lock.release();
  }
};

struct LayerSpec { std::string path, label; u32 bs = 0; bool ro = false; };
static LayerSpec specOf(const J& j) {
  LayerSpec s; s.path = j.strOr("path", "");
  if (s.path.empty()) throw std::runtime_error("a layer needs a path");
  s.label = j.strOr("label", "");
  double b = j.numOr("blockSize", 0);
  if (b < 0 || b > 16777216 || b != std::floor(b)) throw std::runtime_error("layer blockSize must be a multiple of 512 up to 16 MiB");
  s.bs = (u32)b; s.ro = j.boolOr("readonly", false);
  return s;
}

struct LayerStack {
  std::shared_ptr<Backend> base; std::vector<std::shared_ptr<CowLayer>> layers;
  std::shared_ptr<Backend> top() const { return layers.empty() ? base : std::static_pointer_cast<Backend>(layers.back()); }
  static J infoOf(const CowLayer& l) {
    size_t owned = l.owned(); J o = J::obj();
    o.set("path", J::str(l.path)).set("label", J::str(l.label)).set("blocks", J::num((double)owned)).set("bytes", J::num((double)owned * l.bs)).set("blockSize", J::num(l.bs)).set("readonly", J::boolean(l.ro));
    return o;
  }
  J info() const { J a = J::arr(); for (auto& l : layers) a.push(infoOf(*l)); return a; }
  void push(const LayerSpec& s) { layers.push_back(std::make_shared<CowLayer>(top(), s.path, s.label, s.bs, s.ro)); }
  /** Take the top layer off (its files stay), returning what it held — or null when nothing was stacked. */
  J pop() {
    if (layers.empty()) return J();
    J info = infoOf(*layers.back()); layers.back()->close(); layers.pop_back();
    return info;
  }
  /** Replace the top layer. The new one is opened FIRST, so a layer that cannot be opened changes nothing. */
  void swap(const LayerSpec& s) {
    if (layers.empty()) throw std::runtime_error("nothing is stacked to swap");
    auto old = layers.back();
    std::shared_ptr<Backend> below = layers.size() >= 2 ? std::static_pointer_cast<Backend>(layers[layers.size() - 2]) : base;
    if (old->path == s.path) {
      // The same file again: it has to be let go before it can be opened. Put it back if that fails.
      LayerSpec was{old->path, old->label, old->bs, old->ro};
      old->close(); layers.pop_back();
      try { layers.push_back(std::make_shared<CowLayer>(below, s.path, s.label, s.bs, s.ro)); }
      catch (...) { try { layers.push_back(std::make_shared<CowLayer>(below, was.path, was.label, was.bs, was.ro)); } catch (...) {} throw; }
      return;
    }
    auto next = std::make_shared<CowLayer>(below, s.path, s.label, s.bs, s.ro);
    old->close(); layers.back() = next;
  }
  bool flush() {
    bool ok = true;
    for (auto it = layers.rbegin(); it != layers.rend(); ++it) ok = (*it)->flush() && ok;
    return (base ? base->flush() : true) && ok;
  }
  void closeAll() { for (auto it = layers.rbegin(); it != layers.rend(); ++it) (*it)->close(); layers.clear(); if (base) base->close(); }
};

// ----------------------------------------------------------------------------------------------
// Sector mappers — turn a block range back into guest file names, reading the COMPOSED view
// through the stack. FAT32 (a port of src/nbd/fat32.ts) and ext4 (src/nbd/ext4.ts) both implement
// the Mapper interface, so the export names files the same way on either filesystem. The image is
// written by the guest, so every size it reports is bounded before it is believed.
// ----------------------------------------------------------------------------------------------
struct Touched { std::string path; i64 fileOffset; i64 bytes; };
struct FileRec { std::string path; bool isDir; u32 size; std::vector<u32> clusters; };

/** What the export talks to: resolve a byte range to files, list what was found, and name the fs. */
struct Mapper {
  virtual ~Mapper() {}
  virtual std::vector<Touched> mapRange(i64 offset, i64 length) const = 0;
  virtual J list() const = 0;
  virtual const char* fsName() const = 0;
};

struct Fat32 : Mapper {
  std::function<bool(i64, size_t, char*)> rd;
  u32 bytesPerSector = 0, sectorsPerCluster = 0, reservedSectors = 0, numFATs = 0, fatSz = 0, rootCluster = 0, dataStartSector = 0, clusterBytes = 0;
  std::vector<char> fat; std::vector<FileRec> files; std::unordered_map<u32, std::pair<u32, u32>> clusterToFile; // cluster → (file index, cluster index)
  i64 imageSize = 0;
  Fat32(std::function<bool(i64, size_t, char*)> r, i64 size) : rd(std::move(r)), imageSize(size) { parse(); }
  std::vector<char> read(i64 off, size_t n) { std::vector<char> b(n); if (!rd(off, n, b.data())) throw std::runtime_error("read failed"); return b; }
  static u16 le16(const char* p) { return (u16)((u8)p[0] | ((u8)p[1] << 8)); }
  static u32 le32(const char* p) { return le32r(p); }
  void parse() {
    auto bpb = read(0, 512);
    if (le16(&bpb[510]) != 0xaa55) throw std::runtime_error("not a FAT boot sector (bad 0x55AA signature)");
    bytesPerSector = le16(&bpb[11]); sectorsPerCluster = (u8)bpb[13]; reservedSectors = le16(&bpb[14]); numFATs = (u8)bpb[16];
    u16 rootEntCnt = le16(&bpb[17]), fatSz16 = le16(&bpb[22]); u32 fatSz32 = le32(&bpb[36]); rootCluster = le32(&bpb[44]);
    if (fatSz16 != 0 || rootEntCnt != 0 || !bytesPerSector || !sectorsPerCluster) throw std::runtime_error("not a FAT32 filesystem");
    if ((bytesPerSector & (bytesPerSector - 1)) || bytesPerSector < 512 || bytesPerSector > 4096 || (sectorsPerCluster & (sectorsPerCluster - 1)) || !numFATs || !fatSz32)
      throw std::runtime_error("not a FAT32 filesystem (implausible geometry)");
    if ((u64)fatSz32 * bytesPerSector > (512ull << 20)) throw std::runtime_error("FAT larger than 512 MiB");
    // The volume's own size bounds its FATs: a boot sector claiming more is not believed.
    u32 totalSectors = le32(&bpb[32]) ? le32(&bpb[32]) : le16(&bpb[19]);
    u64 metaSectors = (u64)reservedSectors + (u64)numFATs * fatSz32;
    if ((totalSectors && metaSectors > totalSectors) || (imageSize > 0 && metaSectors * bytesPerSector > (u64)imageSize))
      throw std::runtime_error("not a FAT32 filesystem (its FATs are larger than the volume)");
    fatSz = fatSz32; dataStartSector = reservedSectors + numFATs * fatSz32; clusterBytes = sectorsPerCluster * bytesPerSector;
    fat = read((i64)reservedSectors * bytesPerSector, (size_t)fatSz32 * bytesPerSector);
    files.clear(); clusterToFile.clear();
    std::unordered_set<u32> visited; walkDir(rootCluster, "", visited, 0);
  }
  u32 nextCluster(u32 c) const { if ((size_t)(c + 1) * 4 > fat.size()) return 0x0fffffff; return le32(&fat[(size_t)c * 4]) & 0x0fffffff; }
  /**
   * A cluster chain, at most `cap` long, stopping at a loop or at a cluster another entry already
   * owns: cross-linked entries (a guest can write any FAT it likes) must not multiply the work.
   */
  std::vector<u32> chain(u32 first, size_t cap) const {
    std::vector<u32> out; std::unordered_set<u32> seen; u32 c = first;
    while (c >= 2 && c < 0x0ffffff7 && !seen.count(c) && !clusterToFile.count(c) && out.size() < cap) { seen.insert(c); out.push_back(c); c = nextCluster(c); }
    return out;
  }
  i64 clusterStart(u32 c) const { return ((i64)dataStartSector + (i64)(c - 2) * sectorsPerCluster) * bytesPerSector; }
  void reg(FileRec rec) { u32 idx = (u32)files.size(); for (u32 i = 0; i < rec.clusters.size(); i++) clusterToFile[rec.clusters[i]] = {idx, i}; files.push_back(std::move(rec)); }
  static std::string shortName(const char* e) {
    std::string base(e, 8), ext(e + 8, 3);
    while (!base.empty() && base.back() == ' ') base.pop_back();
    while (!ext.empty() && ext.back() == ' ') ext.pop_back();
    std::string n = ext.empty() ? base : base + "." + ext; for (auto& ch : n) ch = (char)tolower((unsigned char)ch); return n;
  }
  static std::string lfnPart(const char* e) {
    std::string s; const int ranges[3][2] = {{1, 11}, {14, 26}, {28, 32}};
    for (auto& r : ranges) for (int i = r[0]; i < r[1]; i += 2) { u16 code = le16(e + i); if (code == 0 || code == 0xffff) return s; putUtf8(s, code); }
    return s;
  }
  void walkDir(u32 first, const std::string& parent, std::unordered_set<u32>& visited, int depth) {
    if (depth > 64 || visited.count(first)) return; visited.insert(first);
    // A FAT directory holds at most 65,536 entries (2 MiB), however long a chain the image claims.
    auto ch = chain(first, std::max<size_t>(1, (2u << 20) / clusterBytes));
    if (!parent.empty() || first != rootCluster) reg({parent.empty() ? "/" : parent, true, 0, ch});
    std::vector<char> buf; for (u32 c : ch) { auto b = read(clusterStart(c), clusterBytes); buf.insert(buf.end(), b.begin(), b.end()); }
    std::string lfn;
    for (size_t off = 0; off + 32 <= buf.size(); off += 32) {
      const char* e = &buf[off]; u8 b0 = (u8)e[0];
      if (b0 == 0x00) break;
      if (b0 == 0xe5) { lfn.clear(); continue; }
      u8 attr = (u8)e[11];
      if (attr == 0x0f) { lfn = lfnPart(e) + lfn; continue; }
      if (attr & 0x08) { lfn.clear(); continue; }
      std::string name = lfn.empty() ? shortName(e) : lfn; lfn.clear();
      if (name == "." || name == "..") continue;
      u32 firstClu = ((u32)le16(e + 20) << 16) | le16(e + 26); u32 size = le32(e + 28); std::string path = parent + "/" + name;
      if (attr & 0x10) { if (firstClu >= 2) walkDir(firstClu, path, visited, depth + 1); }
      // A file holds no more clusters than its size needs, whatever chain the FAT claims.
      else if (firstClu >= 2) reg({path, false, size, chain(firstClu, std::max<size_t>(1, ((size_t)size + clusterBytes - 1) / clusterBytes))});
      else reg({path, false, size, {}});
    }
  }
  static void pushMerged(std::vector<Touched>& out, Touched t) { if (!out.empty() && out.back().path == t.path && out.back().fileOffset + out.back().bytes == t.fileOffset) out.back().bytes += t.bytes; else out.push_back(std::move(t)); }
  const char* fsName() const override { return "fat32"; }
  std::vector<Touched> mapRange(i64 offset, i64 length) const override {
    std::vector<Touched> out; i64 dataStartByte = (i64)dataStartSector * bytesPerSector; i64 pos = offset, end = offset + length;
    while (pos < end) {
      if (pos < dataStartByte) { i64 chunk = std::min(end, dataStartByte) - pos; pushMerged(out, {"<metadata>", pos, chunk}); pos += chunk; continue; }
      u32 cluster = 2 + (u32)((pos - dataStartByte) / clusterBytes); i64 cs = dataStartByte + (i64)(cluster - 2) * clusterBytes; i64 within = pos - cs; i64 chunk = std::min(end - pos, (i64)clusterBytes - within);
      auto it = clusterToFile.find(cluster);
      if (it != clusterToFile.end()) pushMerged(out, {files[it->second.first].path, (i64)it->second.second * clusterBytes + within, chunk});
      else pushMerged(out, {"<free>", pos, chunk});
      pos += chunk;
    }
    return out;
  }
  J list() const override { J a = J::arr(); for (auto& f : files) { J o = J::obj(); o.set("path", J::str(f.path)).set("size", J::num(f.size)).set("isDir", J::boolean(f.isDir)); a.push(o); } return a; }
};

// ----------------------------------------------------------------------------------------------
// ext4 mapper — a port of src/nbd/ext4.ts. Parses the superblock, block group descriptors, inode
// table, extent trees / indirect block maps and the directory tree from the root inode, and builds
// a physical-block → file map. Handles ext2/ext3 (indirect maps) and ext4 (extents, 64-bit group
// descriptors) alike. Every count the image reports is bounded before it is believed.
// ----------------------------------------------------------------------------------------------
struct FileRec4 { std::string path; bool isDir; u64 size; std::vector<u64> blocks; std::vector<u64> logical; u32 ino = 0; };
struct Ext4 : Mapper {
  std::function<bool(i64, size_t, char*)> rd;
  i64 imageSize = 0;
  u32 blockSize = 0, blocksPerGroup = 0, inodesPerGroup = 0, inodeSize = 0, inodesCount = 0, firstDataBlock = 0, descSize = 0, groups = 0;
  u64 blocksCount = 0;
  bool is64bit = false, hasFileType = false, metadataCsum = false;
  u32 csumSeed = 0;
  std::vector<u64> inodeTableBlock;
  std::vector<FileRec4> files;
  std::unordered_map<u64, std::pair<u32, u32>> blockToFile; // physical block → (file index, index into that file's block list)
  std::unordered_set<u64> metadata;

  // Inode i_mode top nibble (own names: S_IF* are macros in <sys/stat.h>).
  static const u32 IFMT = 0xf000, IFDIR = 0x4000, IFREG = 0x8000, IFLNK = 0xa000;
  // Inode flags.
  static const u32 EXT4_EXTENTS_FL = 0x80000, EXT4_INLINE_DATA_FL = 0x10000000;
  // Feature (incompat) flags.
  static const u32 INCOMPAT_FILETYPE = 0x0002, INCOMPAT_64BIT = 0x0080;
  static const u32 ROOT_INO = 2, EXTENT_MAGIC = 0xf30a;
  // A guest can write any bytes it likes; these bound the work a malformed image can ask for.
  static const size_t MAX_FILES = 500000, MAX_BLOCKS_PER_FILE = 8000000;
  static const int MAX_DIR_DEPTH = 64, MAX_EXTENT_DEPTH = 5;

  Ext4(std::function<bool(i64, size_t, char*)> r, i64 size) : rd(std::move(r)), imageSize(size) { parse(); }
  std::vector<char> read(i64 off, size_t n) const { std::vector<char> b(n); if (!rd(off, n, b.data())) throw std::runtime_error("read failed"); return b; }
  std::vector<char> readBlock(u64 block) const { return read((i64)block * blockSize, blockSize); }
  static u16 le16(const char* p) { return (u16)((u8)p[0] | ((u8)p[1] << 8)); }
  static u32 le32(const char* p) { return le32r(p); }

  void parse() {
    auto sb = read(1024, 1024);
    if (le16(&sb[56]) != 0xef53) throw std::runtime_error("not an ext4 filesystem (bad 0xEF53 superblock magic)");
    u32 logBlockSize = le32(&sb[24]);
    if (logBlockSize > 6) throw std::runtime_error("not an ext4 filesystem (implausible block size)");
    blockSize = 1024u << logBlockSize;
    blocksPerGroup = le32(&sb[32]); inodesPerGroup = le32(&sb[40]); inodesCount = le32(&sb[0]);
    blocksCount = (u64)le32(&sb[4]) | ((u64)le32(&sb[0x150]) << 32);
    inodeSize = le16(&sb[88]); if (inodeSize == 0) inodeSize = 128;
    u32 featureIncompat = le32(&sb[96]);
    is64bit = (featureIncompat & INCOMPAT_64BIT) != 0;
    hasFileType = (featureIncompat & INCOMPAT_FILETYPE) != 0;
    firstDataBlock = le32(&sb[20]);
    descSize = is64bit ? le16(&sb[254]) : 32; if (descSize < 32) descSize = 32;
    metadataCsum = (le32(&sb[100]) & 0x400) != 0; // RO_COMPAT_METADATA_CSUM
    csumSeed = (featureIncompat & 0x2000) ? le32(&sb[0x270]) : crc32c(0xffffffffu, &sb[104], 16); // INCOMPAT_CSUM_SEED else crc32c(~0, uuid)
    if (!blocksPerGroup || !inodesPerGroup || !blocksCount || inodeSize < 128 || inodeSize > blockSize)
      throw std::runtime_error("not an ext4 filesystem (implausible geometry)");
    u64 g = (blocksCount + blocksPerGroup - 1) / blocksPerGroup;
    if (g == 0 || g > (1u << 24)) throw std::runtime_error("not an ext4 filesystem (implausible group count)");
    // The volume's own size bounds its metadata: a superblock claiming more is not believed.
    if (imageSize > 0 && (i64)((u64)firstDataBlock + 1) * blockSize > imageSize)
      throw std::runtime_error("not an ext4 filesystem (metadata past the end of the volume)");
    groups = (u32)g;
    readGroupDescriptors();
    blockToFile.clear(); metadata.clear(); files.clear();
    markStaticMetadata();
    std::unordered_set<u32> visited; walkDir(ROOT_INO, "", visited, 0);
  }

  void readGroupDescriptors() {
    i64 gdtStart = (i64)(firstDataBlock + 1) * blockSize;
    auto buf = read(gdtStart, (size_t)descSize * groups);
    inodeTableBlock.clear();
    bool wide = is64bit && descSize >= 64;
    for (u32 gi = 0; gi < groups; gi++) {
      size_t off = (size_t)gi * descSize;
      u64 it = (u64)le32(&buf[off + 8]) | (wide ? ((u64)le32(&buf[off + 40]) << 32) : 0);
      inodeTableBlock.push_back(it);
      u64 bb = (u64)le32(&buf[off + 0]) | (wide ? ((u64)le32(&buf[off + 32]) << 32) : 0);
      u64 ib = (u64)le32(&buf[off + 4]) | (wide ? ((u64)le32(&buf[off + 36]) << 32) : 0);
      metadata.insert(bb); metadata.insert(ib);
    }
  }

  void markStaticMetadata() {
    u64 gdtBlocks = ((u64)descSize * groups + blockSize - 1) / blockSize;
    for (u64 b = 0; b <= (u64)firstDataBlock + gdtBlocks; b++) metadata.insert(b);
    u64 inodeTableBlocks = ((u64)inodesPerGroup * inodeSize + blockSize - 1) / blockSize;
    for (u64 start : inodeTableBlock) for (u64 b = 0; b < inodeTableBlocks; b++) metadata.insert(start + b);
  }

  /** Raw inode bytes for a 1-based inode number, or empty when out of range. */
  std::vector<char> readInode(u32 ino) const {
    i64 offset = inodeOffset(ino);
    if (offset < 0) return {};
    return read(offset, inodeSize);
  }
  /** Byte offset of a 1-based inode in the image, or -1 when out of range. */
  i64 inodeOffset(u32 ino) const {
    if (ino < 1 || ino > inodesCount) return -1;
    u32 group = (ino - 1) / inodesPerGroup, index = (ino - 1) % inodesPerGroup;
    if (group >= inodeTableBlock.size()) return -1;
    return (i64)inodeTableBlock[group] * blockSize + (i64)index * inodeSize;
  }
  /** Look up a file by path: its inode byte offset, inode number and inode size. */
  bool inodeLoc(const std::string& path, i64& off, u32& ino, u32& isize) const {
    for (auto& f : files) if (f.path == path) { off = inodeOffset(f.ino); if (off < 0) return false; ino = f.ino; isize = inodeSize; return true; }
    return false;
  }
  /** A file's current attributes (permission bits, owner uid/gid, size). */
  bool inodeAttrs(const std::string& path, u32& mode, u32& uid, u32& gid, u64& size) const {
    for (auto& f : files) if (f.path == path) {
      auto in = readInode(f.ino); if (in.empty()) return false;
      mode = le16(&in[0]) & 0xfff; uid = le16(&in[2]) | ((u32)le16(&in[120]) << 16);
      gid = le16(&in[24]) | ((u32)le16(&in[122]) << 16);
      size = (u64)le32(&in[4]) | ((u64)le32(&in[108]) << 32); return true;
    }
    return false;
  }
  /** A file's current bytes (whole file), through the live composed view. */
  std::string readFileBytes(const std::string& path, u64 cap) const {
    for (auto& f : files) if (f.path == path) {
      if (f.size > cap) throw std::runtime_error("inode.read: file larger than cap");
      std::string out; out.reserve((size_t)f.size); u64 got = 0;
      for (u64 b : f.blocks) { if (got >= f.size) break; auto blk = readBlock(b); u64 take = std::min<u64>(blockSize, f.size - got); out.append(blk.data(), (size_t)take); got += take; }
      out.resize((size_t)f.size, '\0'); return out;
    }
    throw std::runtime_error("inode.read: no such file: " + path);
  }
  /** Rewrite mode/uid/gid in the inode bytes (each <0 = leave) and fix metadata_csum. Matches src/nbd/ext4.ts patchExt4Inode. */
  void patchInode(char* in, u32 ino, long mode, long uid, long gid) const {
    if (mode >= 0) { u16 t = le16(in) & 0xf000; le16w(in, (u16)(t | ((u32)mode & 0xfff))); }
    if (uid >= 0) { le16w(in + 2, (u16)((u64)uid & 0xffff)); le16w(in + 120, (u16)(((u64)uid >> 16) & 0xffff)); }
    if (gid >= 0) { le16w(in + 24, (u16)((u64)gid & 0xffff)); le16w(in + 122, (u16)(((u64)gid >> 16) & 0xffff)); }
    if (metadataCsum) {
      u16 extra = inodeSize > 128 ? le16(in + 128) : 0;
      bool hasHi = inodeSize > 128 && extra >= (u16)(0x82 + 2 - 128);
      std::vector<char> work(in, in + inodeSize);
      le16w(work.data() + 124, 0); if (hasHi) le16w(work.data() + 130, 0);
      char inumB[4], genB[4]; le32w(inumB, ino); le32w(genB, le32(in + 100));
      u32 c = crc32c(csumSeed, inumB, 4); c = crc32c(c, genB, 4); c = crc32c(c, work.data(), inodeSize);
      le16w(in + 124, (u16)(c & 0xffff)); if (hasHi) le16w(in + 130, (u16)((c >> 16) & 0xffff));
    }
  }

  /** The physical blocks of an inode in logical order, via its extent tree or indirect map. */
  void inodeBlocks(const std::vector<char>& inode, std::vector<u64>& blocks, std::vector<u64>& logical) const {
    if (inode.size() < 100) return;
    u32 flags = le32(&inode[32]);
    if (flags & EXT4_INLINE_DATA_FL) return; // data lives in the inode itself
    const char* iblock = &inode[40];
    if (flags & EXT4_EXTENTS_FL) { std::vector<char> node(iblock, iblock + 60); walkExtents(node, blocks, logical, 0); }
    else walkIndirect(iblock, blocks, logical);
  }

  void walkExtents(const std::vector<char>& node, std::vector<u64>& blocks, std::vector<u64>& logical, int depth) const {
    if (depth > MAX_EXTENT_DEPTH || node.size() < 12) return;
    if (le16(&node[0]) != EXTENT_MAGIC) return;
    u16 entries = le16(&node[2]), treeDepth = le16(&node[6]);
    for (u16 i = 0; i < entries; i++) {
      size_t off = 12 + (size_t)i * 12;
      if (off + 12 > node.size()) break;
      if (treeDepth == 0) {
        u32 eeBlock = le32(&node[off]); u32 len = le16(&node[off + 4]); if (len > 32768) len -= 32768;
        u64 start = (u64)le32(&node[off + 8]) | ((u64)le16(&node[off + 6]) << 32);
        for (u32 b = 0; b < len; b++) {
          if (blocks.size() >= MAX_BLOCKS_PER_FILE) return;
          u64 phys = start + b;
          if (phys >= 2 && phys < blocksCount) { blocks.push_back(phys); logical.push_back((u64)eeBlock + b); }
        }
      } else {
        u64 child = (u64)le32(&node[off + 4]) | ((u64)le16(&node[off + 8]) << 32);
        if (child >= 2 && child < blocksCount) walkExtents(readBlock(child), blocks, logical, depth + 1);
      }
      if (blocks.size() >= MAX_BLOCKS_PER_FILE) return;
    }
  }

  void walkIndirect(const char* iblock, std::vector<u64>& blocks, std::vector<u64>& logical) const {
    u32 ptrsPerBlock = blockSize / 4;
    u64 logicalBlock = 0;
    auto add = [&](u64 phys) -> bool {
      if (blocks.size() >= MAX_BLOCKS_PER_FILE) return false;
      if (phys >= 2 && phys < blocksCount) { blocks.push_back(phys); logical.push_back(logicalBlock); }
      logicalBlock++; return true;
    };
    for (int i = 0; i < 12; i++) { u32 phys = le32(iblock + i * 4); if (phys == 0) logicalBlock++; else if (!add(phys)) return; }
    std::function<bool(u32)> walkSingle = [&](u32 ind) -> bool {
      if (ind == 0) { logicalBlock += ptrsPerBlock; return true; }
      auto buf = readBlock(ind);
      for (u32 i = 0; i < ptrsPerBlock; i++) { u32 phys = le32(&buf[i * 4]); if (phys == 0) logicalBlock++; else if (!add(phys)) return false; }
      return true;
    };
    std::function<bool(u32)> walkDouble = [&](u32 ind) -> bool {
      if (ind == 0) { logicalBlock += (u64)ptrsPerBlock * ptrsPerBlock; return true; }
      auto buf = readBlock(ind);
      for (u32 i = 0; i < ptrsPerBlock; i++) if (!walkSingle(le32(&buf[i * 4]))) return false;
      return true;
    };
    if (!walkSingle(le32(iblock + 12 * 4))) return;
    if (!walkDouble(le32(iblock + 13 * 4))) return;
    u32 triple = le32(iblock + 14 * 4);
    if (triple != 0) { auto buf = readBlock(triple); for (u32 i = 0; i < ptrsPerBlock; i++) if (!walkDouble(le32(&buf[i * 4]))) return; }
  }

  void reg(FileRec4 rec) {
    if (files.size() >= MAX_FILES) return;
    u32 idx = (u32)files.size();
    for (u32 i = 0; i < rec.blocks.size(); i++) { if (!blockToFile.count(rec.blocks[i])) blockToFile[rec.blocks[i]] = {idx, i}; }
    files.push_back(std::move(rec));
  }

  void walkDir(u32 ino, const std::string& parent, std::unordered_set<u32>& visited, int depth) {
    if (depth > MAX_DIR_DEPTH || visited.count(ino) || files.size() >= MAX_FILES) return;
    visited.insert(ino);
    auto inode = readInode(ino);
    if (inode.empty()) return;
    std::vector<u64> blocks, logical; inodeBlocks(inode, blocks, logical);
    if (!parent.empty()) reg({parent, true, le32(&inode[4]), blocks, logical, ino});
    std::vector<char> dirData; for (u64 b : blocks) { auto blk = readBlock(b); dirData.insert(dirData.end(), blk.begin(), blk.end()); }
    // A directory's entries are a per-block linked list of ext4_dir_entry_2; walking each block by
    // rec_len steps entry to entry, and an htree index block (one inode-0 record spanning the block)
    // is skipped like any other empty record.
    for (size_t base = 0; base < dirData.size(); base += blockSize) {
      size_t off = base, blockEnd = std::min(base + blockSize, dirData.size());
      while (off + 8 <= blockEnd) {
        u32 childIno = le32(&dirData[off]); u16 recLen = le16(&dirData[off + 4]); u8 nameLen = (u8)dirData[off + 6];
        if (recLen < 8) break;
        if (childIno != 0 && nameLen != 0 && off + 8 + nameLen <= blockEnd) {
          std::string name(&dirData[off + 8], nameLen);
          if (name != "." && name != "..") {
            std::string path = parent + "/" + name;
            auto child = readInode(childIno);
            if (!child.empty()) {
              u32 mode = le16(&child[0]) & IFMT;
              u8 fileType = hasFileType ? (u8)dirData[off + 7] : 0;
              bool isDir = mode == IFDIR || fileType == 2;
              if (isDir) walkDir(childIno, path, visited, depth + 1);
              else if (mode == IFREG || mode == IFLNK || fileType == 1) {
                u64 size = (u64)le32(&child[4]) | ((u64)le32(&child[108]) << 32);
                std::vector<u64> cb, cl; inodeBlocks(child, cb, cl);
                reg({path, false, size, cb, cl, childIno});
              }
            }
          }
        }
        off += recLen;
      }
    }
  }

  static void pushMerged(std::vector<Touched>& out, Touched t) { if (!out.empty() && out.back().path == t.path && out.back().fileOffset + out.back().bytes == t.fileOffset) out.back().bytes += t.bytes; else out.push_back(std::move(t)); }
  std::vector<Touched> mapRange(i64 offset, i64 length) const override {
    std::vector<Touched> out; i64 pos = offset, end = offset + length;
    while (pos < end) {
      u64 block = (u64)(pos / blockSize); i64 within = pos - (i64)block * blockSize; i64 chunk = std::min(end - pos, (i64)blockSize - within);
      auto it = blockToFile.find(block);
      if (it != blockToFile.end()) pushMerged(out, {files[it->second.first].path, (i64)it->second.second * blockSize + within, chunk});
      else if (metadata.count(block)) pushMerged(out, {"<metadata>", pos, chunk});
      else pushMerged(out, {"<free>", pos, chunk});
      pos += chunk;
    }
    return out;
  }
  const char* fsName() const override { return "ext4"; }
  J list() const override { J a = J::arr(); for (auto& f : files) { J o = J::obj(); o.set("path", J::str(f.path)).set("size", J::num((double)f.size)).set("isDir", J::boolean(f.isDir)); a.push(o); } return a; }
};

// ----------------------------------------------------------------------------------------------
// F2FS mapper — a port of src/nbd/f2fs.ts. F2FS is log-structured: node blocks (inodes, direct /
// indirect nodes) are found through the Node Address Table (NAT), the current version of each NAT
// block chosen by a bitmap in the active checkpoint and overlaid by the checkpoint's NAT journal.
// From the root inode this walks the directory tree, resolves each file's data blocks (inode
// i_addr + direct/indirect/double-indirect nodes) and builds a physical-block → file map.
// ----------------------------------------------------------------------------------------------
struct F2fs : Mapper {
  std::function<bool(i64, size_t, char*)> rd;
  i64 imageSize = 0;
  u32 blockSize = 4096, blocksPerSeg = 0, logBlocksPerSeg = 0, natBlkaddr = 0, mainBlkaddr = 0, rootIno = 0;
  u64 totalBlocks = 0;
  std::vector<char> natBitmap; bool natBitmapLarge = false;
  std::unordered_map<u32, u32> natJournal, nidCache;
  std::vector<FileRec4> files;
  std::unordered_map<u64, std::pair<u32, u32>> blockToFile;
  std::unordered_set<u64> metadata;

  static const u32 F2FS_MAGIC = 0xf2f52010u;
  static const u32 NAT_ENTRY_PER_BLOCK = 455, ADDRS_PER_INODE = 923, ADDRS_PER_BLOCK = 1018, NIDS_PER_BLOCK = 1018;
  static const u32 F2FS_INLINE_XATTR = 0x01, F2FS_INLINE_DATA = 0x02, F2FS_INLINE_DENTRY = 0x04, F2FS_EXTRA_ATTR = 0x20;
  static const u32 DEF_INLINE_XATTR_ADDRS = 50;
  static const u32 NULL_ADDR = 0, NEW_ADDR = 0xffffffffu;
  static const u32 NR_DENTRY_IN_BLOCK = 214, SIZE_OF_DIR_ENTRY = 11, F2FS_SLOT_LEN = 8;
  static const u32 F2FS_FT_DIR = 2, F2FS_FT_SYMLINK = 7;
  static const u32 CP_LARGE_NAT_BITMAP_FLAG = 0x0400;
  static const size_t MAX_FILES = 500000, MAX_BLOCKS_PER_FILE = 8000000;
  static const int MAX_DIR_DEPTH = 64;

  F2fs(std::function<bool(i64, size_t, char*)> r, i64 size) : rd(std::move(r)), imageSize(size) { parse(); }
  std::vector<char> read(i64 off, size_t n) const { std::vector<char> b(n); if (!rd(off, n, b.data())) throw std::runtime_error("read failed"); return b; }
  std::vector<char> block(u64 blk) const { return read((i64)blk * blockSize, blockSize); }
  static u16 le16(const char* p) { return (u16)((u8)p[0] | ((u8)p[1] << 8)); }
  static u32 le32(const char* p) { return le32r(p); }
  static u64 le64(const char* p) { return (u64)le32r(p) | ((u64)le32r(p + 4) << 32); }

  void parse() {
    auto sb = read(1024, 1024);
    if (le32(&sb[0]) != F2FS_MAGIC) throw std::runtime_error("not an F2FS filesystem (bad 0xF2F52010 magic)");
    if (le32(&sb[16]) != 12) throw std::runtime_error("not an F2FS filesystem (block size is not 4 KiB)");
    logBlocksPerSeg = le32(&sb[20]); blocksPerSeg = 1u << logBlocksPerSeg;
    u32 cpBlkaddr = le32(&sb[76]); natBlkaddr = le32(&sb[84]); mainBlkaddr = le32(&sb[92]); rootIno = le32(&sb[96]);
    totalBlocks = le64(&sb[36]);
    if (!blocksPerSeg || !natBlkaddr || !mainBlkaddr || mainBlkaddr <= natBlkaddr || !rootIno)
      throw std::runtime_error("not an F2FS filesystem (implausible geometry)");
    if (imageSize > 0 && (i64)mainBlkaddr * blockSize > imageSize) throw std::runtime_error("not an F2FS filesystem (main area past the end of the volume)");
    readCheckpoint(cpBlkaddr);
    nidCache.clear(); blockToFile.clear(); metadata.clear(); files.clear();
    for (u64 b = 0; b < mainBlkaddr; b++) metadata.insert(b);
    std::unordered_set<u32> visited; walkDir(rootIno, "", visited, 0);
  }

  void readCheckpoint(u32 cpBlkaddr) {
    u64 v0 = le64(&block(cpBlkaddr)[0]);
    u64 v1 = le64(&block(cpBlkaddr + blocksPerSeg)[0]);
    u32 cpBlk = v1 > v0 ? cpBlkaddr + blocksPerSeg : cpBlkaddr;
    auto head = block(cpBlk);
    u32 flags = le32(&head[132]), startSum = le32(&head[140]), sitBmSize = le32(&head[156]), natBmSize = le32(&head[160]);
    natBitmapLarge = (flags & CP_LARGE_NAT_BITMAP_FLAG) != 0;
    u32 natBmOff = natBitmapLarge ? 192 + 4 : 192 + sitBmSize;
    u32 need = natBmOff + natBmSize;
    std::vector<char> buf = need <= blockSize ? head : read((i64)cpBlk * blockSize, ((need + blockSize - 1) / blockSize) * blockSize);
    natBitmap.assign(buf.begin() + natBmOff, buf.begin() + natBmOff + natBmSize);
    natJournal.clear();
    if (startSum > 0) {
      auto sum = block(cpBlk + startSum);
      u16 nNats = le16(&sum[3584]);
      u32 cap = std::min<u32>(nNats, 40);
      for (u32 i = 0; i < cap; i++) {
        size_t off = 3586 + (size_t)i * 13;
        if (off + 13 > sum.size()) break;
        natJournal[le32(&sum[off])] = le32(&sum[off + 5]);
      }
    }
  }

  int natBit(u32 blockOff) const { u8 byte = blockOff / 8 < natBitmap.size() ? (u8)natBitmap[blockOff / 8] : 0; return (byte >> (7 - (blockOff & 7))) & 1; }

  u32 resolveNid(u32 nid) {
    auto c = nidCache.find(nid); if (c != nidCache.end()) return c->second;
    u32 addr;
    auto j = natJournal.find(nid);
    if (j != natJournal.end()) addr = j->second;
    else {
      u32 blockOff = nid / NAT_ENTRY_PER_BLOCK, segOff = blockOff >> logBlocksPerSeg;
      u32 natBlock = natBlkaddr + (segOff << (logBlocksPerSeg + 1)) + (blockOff & (blocksPerSeg - 1));
      if (natBit(blockOff)) natBlock += blocksPerSeg;
      auto blk = block(natBlock);
      addr = le32(&blk[(nid % NAT_ENTRY_PER_BLOCK) * 9 + 5]);
    }
    nidCache[nid] = addr; return addr;
  }

  bool readNode(u32 nid, std::vector<char>& out) {
    if (nid == 0) return false;
    u32 addr = resolveNid(nid);
    if (addr == NULL_ADDR || addr == NEW_ADDR || addr < mainBlkaddr || addr >= totalBlocks) return false;
    metadata.insert(addr);
    out = block(addr); return true;
  }

  void addrWindow(u32 inline_, const std::vector<char>& inode, u32& start, u32& end) {
    bool extra = (inline_ & F2FS_EXTRA_ATTR) != 0;
    u32 extraSlots = extra ? le16(&inode[360]) / 4 : 0;
    u32 xattrSlots = 0;
    if (inline_ & F2FS_INLINE_XATTR) { u32 sized = extra ? le16(&inode[362]) : 0; xattrSlots = sized > 0 ? sized : DEF_INLINE_XATTR_ADDRS; }
    start = extraSlots; end = ADDRS_PER_INODE > xattrSlots ? ADDRS_PER_INODE - xattrSlots : extraSlots; if (end < start) end = start;
  }

  void inodeBlocks(const std::vector<char>& inode, u32 inline_, std::vector<u64>& blocks, std::vector<u64>& logical) {
    if (inline_ & F2FS_INLINE_DATA) return;
    u64 logicalBlock = 0;
    auto addAddr = [&](u32 addr) -> bool {
      if (blocks.size() >= MAX_BLOCKS_PER_FILE) return false;
      if (addr != NULL_ADDR && addr != NEW_ADDR && addr >= mainBlkaddr && addr < totalBlocks) { blocks.push_back(addr); logical.push_back(logicalBlock); }
      logicalBlock++; return true;
    };
    u32 start, end; addrWindow(inline_, inode, start, end);
    for (u32 s = start; s < end; s++) if (!addAddr(le32(&inode[360 + s * 4]))) return;
    auto iNid = [&](u32 k) { return le32(&inode[4052 + k * 4]); };
    std::function<bool(u32)> walkDirect = [&](u32 nid) -> bool {
      std::vector<char> node; if (!readNode(nid, node)) { logicalBlock += ADDRS_PER_BLOCK; return true; }
      for (u32 i = 0; i < ADDRS_PER_BLOCK; i++) if (!addAddr(le32(&node[i * 4]))) return false;
      return true;
    };
    std::function<bool(u32, int)> walkIndirect = [&](u32 nid, int depth) -> bool {
      std::vector<char> node;
      if (!readNode(nid, node)) { logicalBlock += (u64)(depth == 1 ? ADDRS_PER_BLOCK : (u64)NIDS_PER_BLOCK * ADDRS_PER_BLOCK) * NIDS_PER_BLOCK; return true; }
      for (u32 i = 0; i < NIDS_PER_BLOCK; i++) { u32 child = le32(&node[i * 4]); if (depth == 1 ? !walkDirect(child) : !walkIndirect(child, 1)) return false; }
      return true;
    };
    if (!walkDirect(iNid(0))) return;
    if (!walkDirect(iNid(1))) return;
    if (!walkIndirect(iNid(2), 1)) return;
    if (!walkIndirect(iNid(3), 1)) return;
    walkIndirect(iNid(4), 2);
  }

  void reg(FileRec4 rec) {
    if (files.size() >= MAX_FILES) return;
    u32 idx = (u32)files.size();
    for (u32 i = 0; i < rec.blocks.size(); i++) if (!blockToFile.count(rec.blocks[i])) blockToFile[rec.blocks[i]] = {idx, i};
    files.push_back(std::move(rec));
  }

  struct Dent { u32 nid; std::string name; u32 type; };

  void walkDir(u32 ino, const std::string& parent, std::unordered_set<u32>& visited, int depth) {
    if (depth > MAX_DIR_DEPTH || visited.count(ino) || files.size() >= MAX_FILES) return;
    visited.insert(ino);
    std::vector<char> inode; if (!readNode(ino, inode)) return;
    u32 inl = (u8)inode[3];
    if (!parent.empty()) { std::vector<u64> b, l; inodeBlocks(inode, inl, b, l); reg({parent, true, le64(&inode[16]), b, l}); }
    for (auto& c : dirEntries(inode, inl)) {
      if (c.name == "." || c.name == ".." || c.nid == 0) continue;
      std::string path = parent + "/" + c.name;
      std::vector<char> ci; if (!readNode(c.nid, ci)) continue;
      u32 cInl = (u8)ci[3]; u32 mode = le16(&ci[0]);
      bool isDir = (mode & 0xf000) == 0x4000 || c.type == F2FS_FT_DIR;
      if (isDir) walkDir(c.nid, path, visited, depth + 1);
      else if (!(c.type == F2FS_FT_SYMLINK && (mode & 0xf000) == 0xa000)) {
        std::vector<u64> b, l; inodeBlocks(ci, cInl, b, l);
        reg({path, false, le64(&ci[16]), b, l});
      }
    }
  }

  std::vector<Dent> dirEntries(const std::vector<char>& inode, u32 inl) {
    std::vector<Dent> out;
    if (inl & F2FS_INLINE_DENTRY) {
      u32 start, end; addrWindow(inl, inode, start, end);
      parseDentries(inode, 360 + start * 4, (end - start) * 4, true, out);
      return out;
    }
    std::vector<u64> blocks, logical; inodeBlocks(inode, inl, blocks, logical);
    for (u64 b : blocks) { auto buf = block(b); parseDentries(buf, 0, blockSize, false, out); }
    return out;
  }

  void parseDentries(const std::vector<char>& buf, u32 base, u32 bytes, bool inlineLayout, std::vector<Dent>& out) {
    u32 slots, bitmapOff, entryOff, nameOff;
    const u32 bitmapSizeReg = (NR_DENTRY_IN_BLOCK + 7) / 8;                 // 27
    const u32 reservedReg = 4096 - ((SIZE_OF_DIR_ENTRY + F2FS_SLOT_LEN) * NR_DENTRY_IN_BLOCK + bitmapSizeReg); // 3
    if (!inlineLayout) {
      slots = NR_DENTRY_IN_BLOCK; bitmapOff = base; entryOff = base + bitmapSizeReg + reservedReg; nameOff = entryOff + NR_DENTRY_IN_BLOCK * SIZE_OF_DIR_ENTRY;
    } else {
      slots = (bytes * 8) / (SIZE_OF_DIR_ENTRY * 8 + F2FS_SLOT_LEN * 8 + 1);
      u32 bitmapSize = (slots + 7) / 8; bitmapOff = base; entryOff = base + bitmapSize; nameOff = entryOff + slots * SIZE_OF_DIR_ENTRY;
    }
    auto bitSet = [&](u32 i) { u32 bi = bitmapOff + (i >> 3); return bi < buf.size() && (((u8)buf[bi] >> (i & 7)) & 1); };
    u32 i = 0;
    while (i < slots) {
      if (!bitSet(i)) { i++; continue; }
      size_t eo = entryOff + (size_t)i * SIZE_OF_DIR_ENTRY;
      if (eo + SIZE_OF_DIR_ENTRY > buf.size()) break;
      u32 nid = le32(&buf[eo + 4]); u16 nameLen = le16(&buf[eo + 8]); u8 type = (u8)buf[eo + 10];
      u32 usedSlots = std::max<u32>(1, (nameLen + F2FS_SLOT_LEN - 1) / F2FS_SLOT_LEN);
      size_t no = nameOff + (size_t)i * F2FS_SLOT_LEN;
      if (nid > 0 && nameLen > 0 && no + nameLen <= buf.size()) out.push_back({nid, std::string(&buf[no], nameLen), type});
      i += usedSlots;
    }
  }

  static void pushMerged(std::vector<Touched>& out, Touched t) { if (!out.empty() && out.back().path == t.path && out.back().fileOffset + out.back().bytes == t.fileOffset) out.back().bytes += t.bytes; else out.push_back(std::move(t)); }
  std::vector<Touched> mapRange(i64 offset, i64 length) const override {
    std::vector<Touched> out; i64 pos = offset, end = offset + length;
    while (pos < end) {
      u64 blk = (u64)(pos / blockSize); i64 within = pos - (i64)blk * blockSize; i64 chunk = std::min(end - pos, (i64)blockSize - within);
      auto it = blockToFile.find(blk);
      if (it != blockToFile.end()) pushMerged(out, {files[it->second.first].path, (i64)it->second.second * blockSize + within, chunk});
      else if (metadata.count(blk)) pushMerged(out, {"<metadata>", pos, chunk});
      else pushMerged(out, {"<free>", pos, chunk});
      pos += chunk;
    }
    return out;
  }
  const char* fsName() const override { return "f2fs"; }
  J list() const override { J a = J::arr(); for (auto& f : files) { J o = J::obj(); o.set("path", J::str(f.path)).set("size", J::num((double)f.size)).set("isDir", J::boolean(f.isDir)); a.push(o); } return a; }
};

// ----------------------------------------------------------------------------------------------
// Events to Node: one queue for the engine, drained by the control connection's pump.
// ----------------------------------------------------------------------------------------------
struct Ev { int kind = 0; /* 0 access, 1 connection */ std::string command; i64 offset = 0, length = 0; std::vector<Touched> files; std::string remote; };
static std::mutex gQmu; static std::condition_variable gQcv; static std::deque<Ev> gQ; static std::atomic<u64> gEvDropped{0};
static void pushEv(Ev ev) {
  std::lock_guard<std::mutex> g(gQmu);
  if (gQ.size() >= 4096) { gEvDropped++; gQ.pop_front(); }
  gQ.push_back(std::move(ev)); gQcv.notify_one();
}
static void pushAccess(const char* command, i64 offset, i64 length, std::vector<Touched> files) { Ev e; e.command = command; e.offset = offset; e.length = length; e.files = std::move(files); pushEv(std::move(e)); }

// ----------------------------------------------------------------------------------------------
// The export: stack + redirects + routes, behind one reader/writer lock.
// ----------------------------------------------------------------------------------------------
struct Redirect { std::vector<char> content; bool ro = false; std::shared_ptr<PFile> mirror; };
struct Route { std::string match; bool prefix; std::string backendId; };
struct AltStore { std::shared_ptr<Backend> b; std::string path, kind; u32 bs = 0; i64 size = 0; };
enum { EV_NONE = 0, EV_WRITES = 1, EV_ALL = 2 };
static int evModeOf(const std::string& m) {
  if (m == "none") return EV_NONE; if (m == "writes") return EV_WRITES; if (m == "all") return EV_ALL;
  throw std::runtime_error("events must be 'writes', 'all' or 'none'");
}
static const u32 NBD_EPERM = 1, NBD_EIO = 5, NBD_EINVAL = 22;

struct Export;
/** What a per-context store sits on: the stack as it is NOW (so it follows pushes, pops and swaps). */
struct StackView : Backend {
  Export* ex; explicit StackView(Export* e) : ex(e) {}
  i64 size() const override;
  bool read(i64 off, size_t n, char* out) override;
  bool write(i64, const char*, size_t) override { return false; }
  bool readonly() const override { return true; }
};

struct Export {
  RwLock mu; // shared: guest I/O; exclusive: layers / redirects / routes / rescan / close
  LayerStack stack; std::unique_ptr<Mapper> mapper; std::string fs; std::string mapError; i64 size = 0;
  std::unordered_map<std::string, Redirect> redirects; std::vector<Route> routes; std::unordered_map<std::string, AltStore> alt;
  std::string exportName = "share"; std::atomic<int> events{EV_WRITES}; std::atomic<bool> closed{false};
  std::atomic<u64> reads{0}, writes{0}, readBytes{0}, writeBytes{0}, flushFailures{0};
  /** Bumped by every push / pop / swap: a file listing is only comparable with one of the same epoch. */
  std::atomic<u64> epoch{0};
  sock_t listener = INVALID_SOCKET; int port = 0; std::thread acceptThread;
  std::mutex socksMu; std::set<sock_t> socks;

  /** Re-parse the composed view, picking the FAT32 or the ext4 mapper by what the image actually is. */
  void rescan() {
    auto rd = [this](i64 o, size_t n, char* b) { return stack.top()->read(o, n, b); };
    std::string errs;
    try { mapper.reset(new Fat32(rd, size)); fs = "fat32"; mapError.clear(); return; }
    catch (std::exception& e) { errs = std::string("fat32: ") + e.what(); }
    try { mapper.reset(new Ext4(rd, size)); fs = "ext4"; mapError.clear(); return; }
    catch (std::exception& e) { errs += std::string("; ext4: ") + e.what(); }
    try { mapper.reset(new F2fs(rd, size)); fs = "f2fs"; mapError.clear(); return; }
    catch (std::exception& e) { errs += std::string("; f2fs: ") + e.what(); }
    mapper.reset(); fs.clear(); mapError = errs;
  }
  static bool interceptable(const std::string& p) { return p != "<metadata>" && p != "<free>"; }
  /**
   * The store a path is routed to. `routed` says a route matched: a matched route whose store is
   * gone must fail the I/O, never fall through to the shared stack — that would put a context's
   * data into the profile every other context sees.
   */
  Backend* routeFor(const std::string& path, bool& routed) {
    routed = false;
    for (auto& r : routes) {
      if (r.prefix ? path.compare(0, r.match.size(), r.match) != 0 : path != r.match) continue;
      routed = true;
      auto it = alt.find(r.backendId);
      return it != alt.end() ? it->second.b.get() : nullptr;
    }
    return nullptr;
  }
  // The port of OverlayBackend.read / write, minus the synchronous JS interceptor.
  bool read(i64 off, size_t n, char* out, std::vector<Touched>* touched) {
    std::shared_lock<RwLock> g(mu);
    if (closed) return false;
    if (!stack.top()->read(off, n, out)) return false;
    if (!mapper || (redirects.empty() && routes.empty() && !touched)) return true;
    auto segs = mapper->mapRange(off, (i64)n);
    if (!redirects.empty() || !routes.empty()) {
      i64 cur = 0;
      for (auto& s : segs) {
        auto r = redirects.find(s.path);
        if (r != redirects.end()) { const auto& c = r->second.content; for (i64 i = 0; i < s.bytes; i++) { i64 fo = s.fileOffset + i; out[cur + i] = fo < (i64)c.size() ? c[(size_t)fo] : 0; } }
        if (interceptable(s.path)) {
          bool routed; Backend* b = routeFor(s.path, routed);
          if (routed && (!b || !b->read(off + cur, (size_t)s.bytes, out + cur))) return false;
        }
        cur += s.bytes;
      }
    }
    if (touched) *touched = std::move(segs);
    return true;
  }
  u32 write(i64 off, const char* data, size_t n, std::vector<Touched>* touched) {
    std::shared_lock<RwLock> g(mu);
    if (closed) return NBD_EIO;
    auto top = stack.top();
    if (top->readonly()) return NBD_EPERM;
    if (!mapper || (redirects.empty() && routes.empty() && !touched)) return top->write(off, data, n) ? 0 : NBD_EIO;
    auto segs = mapper->mapRange(off, (i64)n);
    i64 cur = 0;
    for (auto& s : segs) {
      auto r = redirects.find(s.path); bool drop = r != redirects.end() && r->second.ro; Backend* target = top.get();
      if (interceptable(s.path)) {
        bool routed; Backend* b = routeFor(s.path, routed);
        if (routed && !b) return NBD_EIO;
        if (b) { target = b; drop = false; }
      }
      if (!drop && !target->write(off + cur, data + cur, (size_t)s.bytes)) return NBD_EIO;
      if (r != redirects.end() && r->second.mirror) r->second.mirror->pwrite(data + cur, (size_t)s.bytes, s.fileOffset);
      cur += s.bytes;
    }
    if (touched) *touched = std::move(segs);
    return 0;
  }
  bool readonlyTop() { std::shared_lock<RwLock> g(mu); return closed || stack.top()->readonly(); }
  std::vector<Touched> mapOnly(i64 off, i64 n) { std::shared_lock<RwLock> g(mu); return mapper && !closed ? mapper->mapRange(off, n) : std::vector<Touched>(); }
  /** NBD_CMD_FLUSH: everything a guest write can have reached — the stack, the context stores, the mirrors. */
  bool flushAll() {
    std::shared_lock<RwLock> g(mu);
    if (closed) return false;
    bool ok = stack.flush();
    for (auto& a : alt) ok = a.second.b->flush() && ok;
    for (auto& r : redirects) if (r.second.mirror) ok = r.second.mirror->flush() && ok;
    if (!ok) flushFailures++;
    return ok;
  }
};
i64 StackView::size() const { return ex->size; }
bool StackView::read(i64 off, size_t n, char* out) { return ex->stack.top()->read(off, n, out); } // the caller holds ex->mu

static std::shared_ptr<Export> gExport; static std::mutex gExportMu;
static std::shared_ptr<Export> currentExport() { std::lock_guard<std::mutex> g(gExportMu); return gExport; }

// ----------------------------------------------------------------------------------------------
// NBD (fixed newstyle) — one thread per guest connection.
// ----------------------------------------------------------------------------------------------
static const u64 NBDMAGIC = 0x4e42444d41474943ull, IHAVEOPT = 0x49484156454f5054ull, REP_MAGIC = 0x0003e889045565a9ull;
static const u32 REQUEST_MAGIC = 0x25609513, SIMPLE_REPLY_MAGIC = 0x67446698;
static const u32 MAX_REQUEST = 32u << 20;   // what QEMU sends at most; anything bigger is refused
static const u32 MAX_OPTION = 64u << 10;
enum { OPT_EXPORT_NAME = 1, OPT_ABORT = 2, OPT_LIST = 3, OPT_INFO = 6, OPT_GO = 7 };
enum { REP_ACK = 1, REP_SERVER = 2, REP_INFO = 3 };
static const u32 REP_ERR_UNSUP = 0x80000001, REP_ERR_POLICY = 0x80000002, REP_ERR_INVALID = 0x80000003, REP_ERR_UNKNOWN = 0x80000006;
static const size_t MAX_CONNECTIONS = 64;
enum { CMD_READ = 0, CMD_WRITE = 1, CMD_DISC = 2, CMD_FLUSH = 3, CMD_TRIM = 4 };
static void be16(char* p, u16 v) { p[0] = (char)(v >> 8); p[1] = (char)v; }
static void be32(char* p, u32 v) { p[0] = (char)(v >> 24); p[1] = (char)(v >> 16); p[2] = (char)(v >> 8); p[3] = (char)v; }
static void be64(char* p, u64 v) { for (int i = 0; i < 8; i++) p[i] = (char)(v >> (56 - 8 * i)); }
static u16 rd16(const char* p) { return (u16)(((u8)p[0] << 8) | (u8)p[1]); }
static u32 rd32(const char* p) { return ((u32)(u8)p[0] << 24) | ((u32)(u8)p[1] << 16) | ((u32)(u8)p[2] << 8) | (u8)p[3]; }
static u64 rd64(const char* p) { u64 v = 0; for (int i = 0; i < 8; i++) v = (v << 8) | (u8)p[i]; return v; }

static u16 transmissionFlags(Export& ex) { u16 f = 1 /*HAS_FLAGS*/ | 4 /*SEND_FLUSH*/ | 32 /*SEND_TRIM*/; if (ex.readonlyTop()) f |= 2; return f; }
static bool optReply(sock_t s, u32 opt, u32 type, const std::string& data) {
  char h[20]; be64(h, REP_MAGIC); be32(h + 8, opt); be32(h + 12, type); be32(h + 16, (u32)data.size()); std::string f(h, 20); f += data;
  bool ok = sendAll(s, f.data(), f.size());
  if (traceOn()) fprintf(stderr, "[nbd] reply opt %u type %x len %u -> %s\n", opt, type, (unsigned)data.size(), ok ? "sent" : "FAILED");
  return ok;
}
/**
 * The export answers to its own name only. The name is what a client needs besides the port (Node
 * makes it random unless one is chosen, and it appears only on QEMU's command line), so there is
 * no "" alias for the default export and LIST does not hand the name out.
 */
static bool nameOk(const Export& ex, const std::string& n) { return n == ex.exportName; }

static bool negotiate(sock_t s, Export& ex) {
  char g[18]; be64(g, NBDMAGIC); be64(g + 8, IHAVEOPT); be16(g + 16, 1 /*FIXED_NEWSTYLE*/); if (!sendAll(s, g, 18)) return false;
  char cf[4]; if (!recvAll(s, cf, 4)) return false;
  for (;;) {
    char m[8]; if (!recvAll(s, m, 8)) return false;
    if (rd64(m) != IHAVEOPT) { if (traceOn()) fprintf(stderr, "[nbd] bad option magic %llx\n", (unsigned long long)rd64(m)); return false; }
    char hd[8]; if (!recvAll(s, hd, 8)) return false; u32 opt = rd32(hd), len = rd32(hd + 4);
    if (len > MAX_OPTION) return false; // no real option is this large
    std::string data(len, 0); if (len && !recvAll(s, &data[0], len)) return false;
    if (traceOn()) fprintf(stderr, "[nbd] option %u len %u\n", opt, len);
    if (opt == OPT_EXPORT_NAME) {
      if (!nameOk(ex, data)) return false; // this option has no error reply: the server hangs up
      std::string info(134, 0); be64(&info[0], (u64)ex.size); be16(&info[8], transmissionFlags(ex));
      return sendAll(s, info.data(), info.size());
    }
    if (opt == OPT_INFO || opt == OPT_GO) {
      if (len < 6) { if (!optReply(s, opt, REP_ERR_INVALID, "")) return false; continue; }
      u32 nl = rd32(&data[0]);
      if ((u64)nl + 6 > len) { if (!optReply(s, opt, REP_ERR_INVALID, "")) return false; continue; }
      std::string name = data.substr(4, nl); u16 nreq = rd16(&data[4 + nl]);
      if ((u64)4 + nl + 2 + 2ull * nreq != len) { if (!optReply(s, opt, REP_ERR_INVALID, "")) return false; continue; }
      if (!nameOk(ex, name)) { if (!optReply(s, opt, REP_ERR_UNKNOWN, "no export named '" + name + "' (this server exports '" + ex.exportName + "')")) return false; continue; }
      std::string info(12, 0); be16(&info[0], 0 /*INFO_EXPORT*/); be64(&info[2], (u64)ex.size); be16(&info[10], transmissionFlags(ex));
      if (!optReply(s, opt, REP_INFO, info) || !optReply(s, opt, REP_ACK, "")) return false;
      if (opt == OPT_GO) return true;
      continue;
    }
    if (opt == OPT_LIST) { if (!optReply(s, opt, REP_ERR_POLICY, "exports are not listed")) return false; continue; }
    if (opt == OPT_ABORT) { optReply(s, opt, REP_ACK, ""); return false; }
    if (!optReply(s, opt, REP_ERR_UNSUP, "")) return false;
  }
}

/** A reply whose data already sits at buf[16..]: one send, no copy. */
static bool reply(sock_t s, std::vector<char>& buf, const char* handle, u32 err, size_t dataLen) {
  if (buf.size() < 16) buf.resize(16);
  be32(&buf[0], SIMPLE_REPLY_MAGIC); be32(&buf[4], err); memcpy(&buf[8], handle, 8);
  return sendAll(s, buf.data(), 16 + (err ? 0 : dataLen));
}

static void serveNbd(sock_t s, std::shared_ptr<Export> ex, std::string remote) {
  {
    std::lock_guard<std::mutex> g(ex->socksMu);
    if (ex->closed) { CLOSESOCK(s); return; }
    ex->socks.insert(s);
  }
  { Ev e; e.kind = 1; e.command = "open"; e.remote = remote; pushEv(std::move(e)); }
  bool ok = negotiate(s, *ex);
  if (traceOn()) fprintf(stderr, "[nbd] negotiate -> %d\n", (int)ok);
  if (ok) {
    std::vector<char> buf(16), small(16);
    for (;;) {
      char req[28]; if (!recvAll(s, req, 28)) break; if (rd32(req) != REQUEST_MAGIC) break;
      u16 type = rd16(req + 6); const char* handle = req + 8; u64 offset = rd64(req + 16); u32 length = rd32(req + 24);
      if (ex->closed || type == CMD_DISC) break;
      // Reject what is outside the export — including an offset with its top bit set, which as a
      // signed number would land at the start of the disk.
      // The 32 MiB cap is for requests that carry data; a TRIM carries none (QEMU sends up to 2 GiB).
      bool fits = offset <= (u64)ex->size && (u64)length <= (u64)ex->size - offset;
      bool inRange = fits && length <= MAX_REQUEST;
      int mode = ex->events.load();
      if (type == CMD_READ) {
        if (!inRange) { if (!reply(s, small, handle, NBD_EINVAL, 0)) break; continue; }
        try { buf.resize(16 + (size_t)length); } catch (std::bad_alloc&) { if (!reply(s, small, handle, NBD_EIO, 0)) break; continue; }
        std::vector<Touched> touched; bool wantEv = mode == EV_ALL;
        bool good = ex->read((i64)offset, length, buf.data() + 16, wantEv ? &touched : nullptr);
        ex->reads++; ex->readBytes += length;
        if (wantEv) pushAccess("read", (i64)offset, length, std::move(touched));
        if (!reply(s, buf, handle, good ? 0 : NBD_EIO, length)) break;
      } else if (type == CMD_WRITE) {
        if (length > MAX_REQUEST) break; // it cannot even be buffered; the protocol lets the server hang up
        try { buf.resize((size_t)length); } catch (std::bad_alloc&) { break; } // cannot take the payload: hang up
        if (length && !recvAll(s, buf.data(), length)) break;
        u32 err = NBD_EINVAL;
        if (inRange) {
          std::vector<Touched> touched; bool wantEv = mode >= EV_WRITES;
          err = ex->write((i64)offset, buf.data(), length, wantEv ? &touched : nullptr);
          ex->writes++; ex->writeBytes += length;
          if (wantEv && !err) pushAccess("write", (i64)offset, length, std::move(touched));
        }
        if (!reply(s, small, handle, err, 0)) break;
      } else if (type == CMD_FLUSH) {
        if (!reply(s, small, handle, ex->flushAll() ? 0 : NBD_EIO, 0)) break;
      } else if (type == CMD_TRIM) {
        u32 err = !fits ? NBD_EINVAL : ex->readonlyTop() ? NBD_EPERM : 0;
        if (!err && mode >= EV_WRITES) pushAccess("trim", (i64)offset, length, ex->mapOnly((i64)offset, length));
        if (!reply(s, small, handle, err, 0)) break;
      } else if (!reply(s, small, handle, NBD_EINVAL, 0)) break;
    }
  }
  { std::lock_guard<std::mutex> g(ex->socksMu); ex->socks.erase(s); }
  { Ev e; e.kind = 1; e.command = "close"; e.remote = remote; pushEv(std::move(e)); }
  CLOSESOCK(s);
}

static std::string addrText(const sockaddr_storage& a) {
  char host[INET6_ADDRSTRLEN] = {0}; int port = 0;
  if (a.ss_family == AF_INET) { auto* v = (const sockaddr_in*)&a; inet_ntop(AF_INET, (void*)&v->sin_addr, host, sizeof host); port = ntohs(v->sin_port); }
  else if (a.ss_family == AF_INET6) { auto* v = (const sockaddr_in6*)&a; inet_ntop(AF_INET6, (void*)&v->sin6_addr, host, sizeof host); port = ntohs(v->sin6_port); }
  return std::string(host) + ":" + std::to_string(port);
}

/** Listen on a host name or address (IPv4 or IPv6). Exclusive: a port someone else holds is an error, never shared. */
static bool listenOn(const std::string& host, int port, sock_t& out, int& boundPort, std::string& err) {
  addrinfo hints; memset(&hints, 0, sizeof hints); hints.ai_family = AF_UNSPEC; hints.ai_socktype = SOCK_STREAM; hints.ai_flags = AI_PASSIVE | AI_NUMERICSERV;
  addrinfo* res = nullptr; std::string ps = std::to_string(port);
  int rc = getaddrinfo(host.empty() ? "127.0.0.1" : host.c_str(), ps.c_str(), &hints, &res);
  if (rc != 0 || !res) { err = "cannot resolve '" + host + "'"; return false; }
  err = "no usable address";
  for (addrinfo* ai = res; ai; ai = ai->ai_next) {
    sock_t srv = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
    if (srv == INVALID_SOCKET) continue;
    int one = 1;
#ifdef _WIN32
    // SO_REUSEADDR on Windows lets a second socket bind a port that is already listening — two
    // engines on one fixed port, and a VM attached to the wrong disk. Exclusive use instead.
    setsockopt(srv, SOL_SOCKET, SO_EXCLUSIVEADDRUSE, (const char*)&one, sizeof one);
#else
    setsockopt(srv, SOL_SOCKET, SO_REUSEADDR, (const char*)&one, sizeof one); // POSIX: only skips TIME_WAIT
#endif
    if (::bind(srv, ai->ai_addr, (int)ai->ai_addrlen) != 0 || listen(srv, 64) != 0) { err = "port " + ps + " on " + host + " is unavailable (" + sysErr() + ")"; CLOSESOCK(srv); continue; }
    sockaddr_storage a; socklen_t len = sizeof a; getsockname(srv, (sockaddr*)&a, &len);
    boundPort = a.ss_family == AF_INET6 ? ntohs(((sockaddr_in6*)&a)->sin6_port) : ntohs(((sockaddr_in*)&a)->sin_port);
    out = srv; freeaddrinfo(res); return true;
  }
  freeaddrinfo(res);
  return false;
}

static void nbdAcceptLoop(std::shared_ptr<Export> ex) {
  sock_t srv = ex->listener;
  while (!ex->closed) {
    if (waitReadable(srv, 100) <= 0) continue;
    sockaddr_storage peer; socklen_t pl = sizeof peer;
    sock_t c = accept(srv, (sockaddr*)&peer, &pl);
    // A failed accept (out of descriptors, a client that reset first…) is not the end of the
    // listener: back off and keep serving.
    if (c == INVALID_SOCKET) { std::this_thread::sleep_for(std::chrono::milliseconds(20)); continue; }
    if (ex->closed) { CLOSESOCK(c); break; }
    size_t open_; { std::lock_guard<std::mutex> g(ex->socksMu); open_ = ex->socks.size(); }
    if (open_ >= MAX_CONNECTIONS) { CLOSESOCK(c); continue; } // each can hold a 32 MiB buffer
    int nd = 1; setsockopt(c, IPPROTO_TCP, TCP_NODELAY, (const char*)&nd, sizeof nd);
    std::thread(serveNbd, c, ex, addrText(peer)).detach();
  }
  CLOSESOCK(srv); ex->listener = INVALID_SOCKET;
}

/** Stop serving and release every file. Waits for in-flight guest I/O; guest threads end on their own. */
static void closeExport(const std::shared_ptr<Export>& ex) {
  ex->closed = true;
  if (ex->acceptThread.joinable()) ex->acceptThread.join(); // closes the listener: the port is free once this returns
  { std::lock_guard<std::mutex> g(ex->socksMu); for (auto s : ex->socks) shutdown(s, SHUT_BOTH); }
  std::unique_lock<RwLock> g(ex->mu);
  for (auto& a : ex->alt) a.second.b->close();
  for (auto& r : ex->redirects) if (r.second.mirror) r.second.mirror->close();
  ex->alt.clear(); ex->redirects.clear(); ex->routes.clear(); ex->mapper.reset();
  ex->stack.closeAll();
}

// ----------------------------------------------------------------------------------------------
// Control plane.
// ----------------------------------------------------------------------------------------------
static std::mutex gCtlSendMu;
static bool sendFrame(sock_t s, const J& h, const std::string& bin) {
  std::string out; jw(h, out); std::string frame; u32 L = (u32)out.size(), B = (u32)bin.size();
  char lb[4], bb[4]; be32(lb, L); be32(bb, B); frame.append(lb, 4); frame += out; frame.append(bb, 4); frame += bin;
  std::lock_guard<std::mutex> g(gCtlSendMu); return sendAll(s, frame.data(), frame.size());
}
static bool readFrame(sock_t s, std::string& hdr, std::string& bin, u32 maxHdr, u32 maxBin) {
  try {
    char hl[4]; if (!recvAll(s, hl, 4)) return false; u32 n = rd32(hl); if (n > maxHdr) return false;
    hdr.assign(n, 0); if (n && !recvAll(s, &hdr[0], n)) return false;
    char bl[4]; if (!recvAll(s, bl, 4)) return false; u32 bn = rd32(bl); if (bn > maxBin) return false;
    bin.assign(bn, 0); if (bn && !recvAll(s, &bin[0], bn)) return false;
    return true;
  } catch (std::bad_alloc&) { return false; }
}

static J filesJ(Export& ex) { return ex.mapper ? ex.mapper->list() : J::arr(); }
static void stackReply(Export& ex, J& h) {
  // `fs` names the filesystem the mapper recognised ("fat32" | "ext4" | ""); `fat32` is kept for
  // older Node clients and means exactly fs == "fat32".
  h.set("ok", J::boolean(true)).set("layers", ex.stack.info()).set("fat32", J::boolean(ex.fs == "fat32")).set("fs", J::str(ex.fs)).set("files", filesJ(ex)).set("epoch", J::num((double)ex.epoch));
  if (!ex.mapError.empty()) h.set("fatError", J::str(ex.mapError));
}

static void handle(const J& req, const std::string& bin, J& h, std::string& obin) {
  (void)obin;
  std::string op = req.strOr("op", "");
  if (op == "ping" || op == "hello") { h.set("ok", J::boolean(true)).set("pong", J::boolean(true)).set("engine", J::str("nbd-cpp")).set("threads", J::num(std::thread::hardware_concurrency())); return; }
  if (op == "open") {
    std::lock_guard<std::mutex> g(gExportMu);
    if (gExport) throw std::runtime_error("an export is already open in this engine (one export per engine process)");
    std::string image = req.strOr("image", ""); if (image.empty()) throw std::runtime_error("open: image is required");
    const J* layers = req.get("layers"); bool hasLayers = layers && layers->t == J::ARR && !layers->a.empty();
    double size = req.numOr("size", 0), port = req.numOr("port", 0);
    if (size < 0 || port < 0 || port > 65535) throw std::runtime_error("open: bad size or port");
    std::string host = req.strOr("host", "127.0.0.1");
    auto ex = std::make_shared<Export>();
    try {
      ex->stack.base = std::make_shared<FileBackend>(image, (i64)size, req.boolOr("readonlyBase", hasLayers));
      if (hasLayers) for (auto& l : layers->a) ex->stack.push(specOf(l));
      ex->size = ex->stack.base->size();
      ex->exportName = req.strOr("exportName", "share");
      ex->events = evModeOf(req.strOr("events", "writes"));
      ex->rescan();
      std::string err;
      if (!listenOn(host, (int)port, ex->listener, ex->port, err)) throw std::runtime_error("cannot listen for NBD: " + err);
    } catch (...) { ex->stack.closeAll(); throw; } // nothing half-open survives a failed open
    ex->acceptThread = std::thread(nbdAcceptLoop, ex);
    gExport = ex;
    stackReply(*ex, h);
    h.set("nbdPort", J::num(ex->port)).set("size", J::num((double)ex->size));
    return;
  }
  std::shared_ptr<Export> ex = currentExport();
  if (op == "close") {
    std::lock_guard<std::mutex> g(gExportMu);
    if (gExport) { auto gone = gExport; gExport.reset(); closeExport(gone); }
    h.set("ok", J::boolean(true)); return;
  }
  if (!ex) throw std::runtime_error("no export open — send `open` first");
  if (op == "layer.push" || op == "layer.swap" || op == "layer.pop") {
    std::unique_lock<RwLock> g(ex->mu);
    J popped;
    if (op == "layer.push") ex->stack.push(specOf(req));
    else if (op == "layer.swap") ex->stack.swap(specOf(req));
    else popped = ex->stack.pop();
    ex->epoch++;
    ex->rescan();
    stackReply(*ex, h);
    if (op == "layer.pop") h.set("popped", popped);
    return;
  }
  if (op == "layers") { std::shared_lock<RwLock> g(ex->mu); h.set("ok", J::boolean(true)).set("layers", ex->stack.info()); return; }
  if (op == "rescan") { std::unique_lock<RwLock> g(ex->mu); ex->rescan(); stackReply(*ex, h); return; }
  if (op == "list") { std::shared_lock<RwLock> g(ex->mu); stackReply(*ex, h); return; }
  if (op == "redirect.set") {
    std::string path = req.strOr("path", ""); if (path.empty()) throw std::runtime_error("redirect.set: path is required");
    Redirect r; r.content.assign(bin.begin(), bin.end()); r.ro = req.boolOr("readonly", false);
    std::string mirror = req.strOr("mirrorTo", "");
    if (!mirror.empty()) { r.mirror = std::make_shared<PFile>(); if (!r.mirror->open(mirror, PFile::CREATE)) throw std::runtime_error("cannot open mirror file " + mirror + ": " + sysErr()); }
    std::unique_lock<RwLock> g(ex->mu);
    auto it = ex->redirects.find(path);
    if (it != ex->redirects.end() && it->second.mirror) it->second.mirror->close(); // the one it replaces
    ex->redirects[path] = std::move(r);
    h.set("ok", J::boolean(true)); return;
  }
  if (op == "redirect.clear") {
    std::unique_lock<RwLock> g(ex->mu);
    auto it = ex->redirects.find(req.strOr("path", ""));
    if (it != ex->redirects.end()) { if (it->second.mirror) it->second.mirror->close(); ex->redirects.erase(it); }
    h.set("ok", J::boolean(true)); return;
  }
  if (op == "inode.attrs" || op == "inode.read") {
    std::shared_lock<RwLock> g(ex->mu);
    Ext4* e4 = dynamic_cast<Ext4*>(ex->mapper.get());
    if (!e4) throw std::runtime_error(op + ": the image is not ext4");
    std::string path = req.strOr("path", "");
    if (op == "inode.attrs") {
      u32 mode, uid, gid; u64 size;
      bool exists = e4->inodeAttrs(path, mode, uid, gid, size);
      h.set("ok", J::boolean(true)).set("exists", J::boolean(exists));
      if (exists) h.set("mode", J::num(mode)).set("uid", J::num(uid)).set("gid", J::num(gid)).set("size", J::num((double)size));
      return;
    }
    obin = e4->readFileBytes(path, 256ull << 20); // cap the current-bytes read at 256 MiB
    h.set("ok", J::boolean(true));
    return;
  }
  if (op == "inode.stamp") {
    std::unique_lock<RwLock> g(ex->mu);
    Ext4* e4 = dynamic_cast<Ext4*>(ex->mapper.get());
    if (!e4) throw std::runtime_error("inode.stamp: the image is not ext4 (FAT32 has no per-file mode)");
    std::string path = req.strOr("path", "");
    i64 off; u32 ino, isize;
    if (!e4->inodeLoc(path, off, ino, isize)) throw std::runtime_error("inode.stamp: no such file: " + path);
    auto top = ex->stack.top();
    if (top->readonly()) throw std::runtime_error("inode.stamp: the top layer is read-only");
    std::vector<char> in((size_t)isize);
    if (!top->read(off, isize, in.data())) throw std::runtime_error("inode.stamp: read failed");
    long mode = req.get("mode") ? (long)req.numOr("mode", 0) : -1;
    long uid = req.get("uid") ? (long)req.numOr("uid", 0) : -1;
    long gid = req.get("gid") ? (long)req.numOr("gid", 0) : -1;
    e4->patchInode(in.data(), ino, mode, uid, gid);
    if (!top->write(off, in.data(), isize)) throw std::runtime_error("inode.stamp: write failed");
    ex->stack.flush();
    h.set("ok", J::boolean(true));
    return;
  }
  if (op == "backend.add") {
    std::string id = req.strOr("name", ""), path = req.strOr("path", ""), kind = req.strOr("kind", "layer");
    if (id.empty() || path.empty()) throw std::runtime_error("backend.add: name and path are required");
    if (kind != "layer" && kind != "file") throw std::runtime_error("backend.add: kind must be 'layer' or 'file'");
    LayerSpec spec; if (kind == "layer") { J l = J::obj(); l.set("path", J::str(path)); if (auto b = req.get("blockSize")) l.set("blockSize", *b); spec = specOf(l); }
    i64 fileSize = (i64)req.numOr("size", (double)ex->size);
    // A context layer sits over the stack as it is — base AND profile layers — never the bare base.
    auto open = [&](const std::string& k, u32 bs, i64 sz) -> AltStore {
      if (k == "layer") { auto l = std::make_shared<CowLayer>(std::make_shared<StackView>(ex.get()), path, id, bs, false); return AltStore{l, path, k, l->bs, 0}; }
      return AltStore{std::make_shared<FileBackend>(path, sz, false), path, k, 0, sz};
    };
    std::unique_lock<RwLock> g(ex->mu);
    auto it = ex->alt.find(id);
    if (it != ex->alt.end() && it->second.path == path && it->second.kind == kind) {
      // The same store again. Already open as asked: nothing to do. Otherwise it has to be let go
      // before it can be reopened (it is locked) — and put back if the reopen fails, so a refused
      // re-register never leaves the context's routes without their store.
      if (kind == "file" ? it->second.size == fileSize : (!spec.bs || spec.bs == it->second.bs)) { h.set("ok", J::boolean(true)); return; }
      AltStore was = it->second;
      was.b->close(); ex->alt.erase(it);
      try { ex->alt[id] = open(kind, spec.bs, fileSize); }
      catch (...) { try { ex->alt[id] = open(was.kind, was.bs, was.size); } catch (...) {} throw; }
      h.set("ok", J::boolean(true)); return;
    }
    AltStore next = open(kind, spec.bs, fileSize); // a different store: open it first, then let the old one go
    if (it != ex->alt.end()) it->second.b->close();
    ex->alt[id] = next;
    h.set("ok", J::boolean(true)); return;
  }
  if (op == "backend.remove") {
    std::unique_lock<RwLock> g(ex->mu); std::string id = req.strOr("name", "");
    ex->routes.erase(std::remove_if(ex->routes.begin(), ex->routes.end(), [&](const Route& r) { return r.backendId == id; }), ex->routes.end());
    auto it = ex->alt.find(id);
    if (it != ex->alt.end()) { it->second.b->close(); ex->alt.erase(it); } // its own files only
    h.set("ok", J::boolean(true)); return;
  }
  if (op == "route.set") {
    Route r; r.backendId = req.strOr("backend", ""); r.prefix = req.get("prefix") != nullptr; r.match = r.prefix ? req.strOr("prefix", "") : req.strOr("path", "");
    if (r.match.empty()) throw std::runtime_error("route.set: path or prefix is required");
    std::unique_lock<RwLock> g(ex->mu);
    if (!ex->alt.count(r.backendId)) throw std::runtime_error("route.set: unknown backend " + r.backendId);
    ex->routes.erase(std::remove_if(ex->routes.begin(), ex->routes.end(), [&](const Route& x) { return x.match == r.match && x.prefix == r.prefix; }), ex->routes.end());
    ex->routes.push_back(r);
    h.set("ok", J::boolean(true)); return;
  }
  if (op == "route.clear") {
    std::unique_lock<RwLock> g(ex->mu);
    const J* p = req.get("path"); const J* x = req.get("prefix");
    if (!p && !x) ex->routes.clear();
    else {
      bool prefix = x != nullptr; std::string m = prefix ? req.strOr("prefix", "") : req.strOr("path", "");
      ex->routes.erase(std::remove_if(ex->routes.begin(), ex->routes.end(), [&](const Route& r) { return r.match == m && r.prefix == prefix; }), ex->routes.end());
    }
    h.set("ok", J::boolean(true)); return;
  }
  if (op == "events") { ex->events = evModeOf(req.strOr("mode", "writes")); h.set("ok", J::boolean(true)); return; }
  if (op == "stats") {
    size_t conns; { std::lock_guard<std::mutex> g(ex->socksMu); conns = ex->socks.size(); }
    h.set("ok", J::boolean(true)).set("reads", J::num((double)ex->reads)).set("writes", J::num((double)ex->writes)).set("readBytes", J::num((double)ex->readBytes))
        .set("writeBytes", J::num((double)ex->writeBytes)).set("eventsDropped", J::num((double)gEvDropped)).set("flushFailures", J::num((double)ex->flushFailures))
        .set("connections", J::num((double)conns)).set("threads", J::num(std::thread::hardware_concurrency()));
    return;
  }
  throw std::runtime_error("unknown op: " + op);
}

/** Drain queued events to the control connection — a burst becomes one frame per kind, in order. */
static void eventPump(sock_t s) {
  u64 lastWrites = 0; auto lastLayers = std::chrono::steady_clock::now();
  for (;;) {
    std::vector<Ev> batch;
    {
      std::unique_lock<std::mutex> g(gQmu);
      gQcv.wait_for(g, std::chrono::milliseconds(100), [] { return !gQ.empty(); });
      while (!gQ.empty() && batch.size() < 256) { batch.push_back(std::move(gQ.front())); gQ.pop_front(); }
    }
    size_t i = 0;
    while (i < batch.size()) {
      int kind = batch[i].kind; J arr = J::arr();
      for (; i < batch.size() && batch[i].kind == kind; i++) {
        const Ev& ev = batch[i]; J o = J::obj();
        if (kind == 1) o.set("state", J::str(ev.command)).set("remote", J::str(ev.remote));
        else {
          o.set("command", J::str(ev.command)).set("offset", J::num((double)ev.offset)).set("length", J::num((double)ev.length));
          J fs = J::arr(); for (auto& t : ev.files) { J f = J::obj(); f.set("path", J::str(t.path)).set("fileOffset", J::num((double)t.fileOffset)).set("bytes", J::num((double)t.bytes)); fs.push(f); }
          o.set("files", fs);
        }
        arr.push(o);
      }
      J h = J::obj();
      if (kind == 1) h.set("event", J::str("connection")).set("list", arr); else h.set("event", J::str("access")).set("batch", arr);
      if (!sendFrame(s, h, "")) return;
    }
    // What the layers hold changes with every write that allocates a block. Node's copy is kept
    // current without a request — whether or not it asked for access events — at most twice a second.
    if (auto ex = currentExport()) {
      u64 w = ex->writes.load(); auto now = std::chrono::steady_clock::now();
      if (w != lastWrites && now - lastLayers >= std::chrono::milliseconds(500)) {
        J h = J::obj(); h.set("event", J::str("layers"));
        { std::shared_lock<RwLock> g(ex->mu); if (ex->closed) continue; h.set("layers", ex->stack.info()).set("epoch", J::num((double)ex->epoch)); }
        if (!sendFrame(s, h, "")) return;
        lastWrites = w; lastLayers = now;
      }
    }
  }
}

[[noreturn]] static void shutdownAndExit() {
  { std::lock_guard<std::mutex> g(gExportMu); if (gExport) { auto ex = gExport; gExport.reset(); closeExport(ex); } }
  fflush(stdout); fflush(stderr); _exit(0);
}

static std::string gToken; static std::atomic<bool> gClaimed{false};
static bool sameToken(const std::string& a, const std::string& b) {
  if (a.size() != b.size()) return false;
  unsigned char d = 0; for (size_t i = 0; i < a.size(); i++) d |= (unsigned char)(a[i] ^ b[i]);
  return d == 0;
}

static void serveControl(sock_t s) {
  std::string hdr, bin;
  J hello;
  if (!gToken.empty()) {
    // Until it proves who it is, a connection gets a small frame and ten seconds.
    setRecvTimeout(s, 10000);
    bool ok = readFrame(s, hdr, bin, 64u << 10, 0);
    J req; if (ok) { try { req = JP(hdr).parse(); } catch (...) { ok = false; } }
    if (!ok || req.strOr("op", "") != "hello" || !sameToken(req.strOr("token", ""), gToken)) {
      J h = J::obj(); h.set("ok", J::boolean(false)).set("error", J::str("unauthorized")); if (auto id = req.get("id")) h.set("id", *id);
      sendFrame(s, h, ""); CLOSESOCK(s); return;
    }
    hello = req;
  }
  bool expected = false;
  if (!gClaimed.compare_exchange_strong(expected, true)) {
    J h = J::obj(); h.set("ok", J::boolean(false)).set("error", J::str("this engine already has a controller")); if (auto id = hello.get("id")) h.set("id", *id);
    sendFrame(s, h, ""); CLOSESOCK(s); return;
  }
  setRecvTimeout(s, 0);
  if (hello.t == J::OBJ) {
    J h = J::obj(); h.set("ok", J::boolean(true)).set("engine", J::str("nbd-cpp")); if (auto id = hello.get("id")) h.set("id", *id);
    if (!sendFrame(s, h, "")) { CLOSESOCK(s); shutdownAndExit(); }
  }
  std::thread(eventPump, s).detach();
  for (;;) {
    if (!readFrame(s, hdr, bin, 16u << 20, 1u << 30)) break;
    J h = J::obj(), req; std::string obin;
    try { req = JP(hdr).parse(); handle(req, bin, h, obin); }
    catch (std::exception& e) { h = J::obj(); h.set("ok", J::boolean(false)).set("error", J::str(e.what())); }
    if (auto id = req.get("id")) h.set("id", *id);
    if (!sendFrame(s, h, obin)) break;
  }
  CLOSESOCK(s);
  // The controlling process is gone: nothing else can drive this engine, so it leaves with it.
  shutdownAndExit();
}

/**
 * Leave when the process that started us is gone. The control socket normally tells us that, but a
 * hard-killed parent on Windows can leave the socket half-open while we still hold the base image
 * open. The owner is watched through ONE handle opened at start, so a recycled pid cannot keep an
 * orphaned engine alive.
 */
static void ownerWatch(long pid) {
#ifdef _WIN32
  HANDLE h = OpenProcess(SYNCHRONIZE, FALSE, (DWORD)pid);
  if (h) WaitForSingleObject(h, INFINITE);
  else if (GetLastError() == ERROR_ACCESS_DENIED) while (pidAlive(pid)) std::this_thread::sleep_for(std::chrono::milliseconds(750));
#else
  bool parent = (pid_t)pid == getppid(); // a child is re-parented the moment its parent dies
  for (;;) {
    std::this_thread::sleep_for(std::chrono::milliseconds(500));
    if (parent ? getppid() != (pid_t)pid : !pidAlive(pid)) break;
  }
#endif
  shutdownAndExit();
}

int main(int argc, char** argv) {
  int port = 0; std::string bind = "127.0.0.1"; long owner = 0;
  for (int i = 1; i < argc; i++) { if (!strcmp(argv[i], "--port") && i + 1 < argc) port = atoi(argv[++i]); else if (!strcmp(argv[i], "--bind") && i + 1 < argc) bind = argv[++i]; else if (!strcmp(argv[i], "--owner") && i + 1 < argc) owner = atol(argv[++i]); }
#ifdef _WIN32
  WSADATA wsa; WSAStartup(MAKEWORD(2, 2), &wsa);
#else
  signal(SIGPIPE, SIG_IGN); // a guest that hangs up mid-reply must not take the engine with it
#endif
  if (const char* t = getenv("NBD_ENGINE_TOKEN")) gToken = t;
  if (gToken.empty()) fprintf(stderr, "[nbd-engine] NBD_ENGINE_TOKEN is not set: the first local connection controls this engine\n");
  if (owner > 0) std::thread(ownerWatch, owner).detach();
  sock_t srv; int bound; std::string err;
  if (!listenOn(bind, port, srv, bound, err)) { fprintf(stderr, "control port: %s\n", err.c_str()); return 1; }
  printf("READY %d\n", bound); fflush(stdout);
  // Accept until a connection has claimed the engine, then stop listening altogether.
  while (!gClaimed) {
    if (waitReadable(srv, 100) <= 0) continue;
    sock_t c = accept(srv, nullptr, nullptr);
    if (c == INVALID_SOCKET) { std::this_thread::sleep_for(std::chrono::milliseconds(20)); continue; }
    if (gClaimed) { CLOSESOCK(c); break; }
    int nd = 1; setsockopt(c, IPPROTO_TCP, TCP_NODELAY, (const char*)&nd, sizeof nd);
    std::thread(serveControl, c).detach();
  }
  CLOSESOCK(srv);
  for (;;) std::this_thread::sleep_for(std::chrono::hours(1)); // the control connection or the watchdog ends the process
}
