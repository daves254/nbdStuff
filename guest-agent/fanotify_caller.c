// fanotify_caller — the accurate-caller reporter that runs INSIDE the guest.
//
// NBD is block-level and page-cache writeback is asynchronous, so the host can never see which
// process wrote a block. fanotify, in the guest, reports the *pid the kernel attributes each
// filesystem operation to* — the real caller — at the moment of the syscall. This tiny agent marks
// the given mount(s) and prints one tab-separated line per write:
//
//     <empty-ts>\t<op>\t<pid>\t<uid>\t<comm>\t<path>\n
//
// The ts field is left empty on purpose: the guest clock is not the host's, so the host stamps the
// record with its own clock on ingest (see src/nbd/caller.ts, parseCallerLine / FanotifyCallerSource).
//
//   build (for the guest arch, e.g. x86_64 BlissOS):  cc -O2 -static -o fanotify_caller fanotify_caller.c
//   run  (in the guest, needs CAP_SYS_ADMIN / root):  fanotify_caller /mnt/media_rw/share [more mounts...]
//
// Classic FAN_CLASS_NOTIF mode is used (an object fd + meta.pid per event) rather than the newer
// FID/pidfd reporting, because it is available on the widest range of kernels. It attributes writes
// (FAN_MODIFY / FAN_CLOSE_WRITE); create/delete are recovered host-side by the block mapper's
// snapshot diff, so they need no agent.
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <poll.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <unistd.h>

// fanotify constants / struct: from <sys/fanotify.h> where it exists (glibc, musl), otherwise from
// the kernel UAPI header. The Android NDK (bionic) ships <linux/fanotify.h> but NOT <sys/fanotify.h>,
// so detect it. A second guarded include covers the rare libc whose <sys/fanotify.h> omits the
// FAN_EVENT_* macros (musl defines them itself, so its build never re-includes the UAPI header,
// which musl's sysroot doesn't carry).
#if defined(__has_include)
#if __has_include(<sys/fanotify.h>)
#include <sys/fanotify.h>
#else
#include <linux/fanotify.h>
#endif
#else
#include <sys/fanotify.h>
#endif
#ifndef FAN_EVENT_OK
#include <linux/fanotify.h>
#endif

// Invoke the syscalls directly, depending on neither the libc wrapper nor <sys/fanotify.h> (which
// bionic lacks). 64-bit only — the u64 mask is a single register there; the CI builds x86_64 and
// arm64-v8a, the ABIs Android actually runs.
static int fan_init(unsigned int flags, unsigned int event_f_flags) {
  return (int)syscall(__NR_fanotify_init, flags, event_f_flags);
}
static int fan_mark(int fd, unsigned int flags, uint64_t mask, int dfd, const char *path) {
  return (int)syscall(__NR_fanotify_mark, fd, flags, mask, dfd, path);
}

static long g_self_pid;

// Read a small text file (e.g. /proc/<pid>/comm) into buf, NUL-terminated. Returns bytes read.
static int read_small(const char *path, char *buf, size_t cap) {
  int fd = open(path, O_RDONLY);
  if (fd < 0) return -1;
  ssize_t n = read(fd, buf, cap - 1);
  close(fd);
  if (n < 0) n = 0;
  buf[n] = '\0';
  return (int)n;
}

// The real uid of a pid, from /proc/<pid>/status ("Uid:\t<real>\t<eff>..."). -1 if unknown.
static long uid_of(long pid) {
  char path[64];
  snprintf(path, sizeof path, "/proc/%ld/status", pid);
  char buf[4096];
  if (read_small(path, buf, sizeof buf) <= 0) return -1;
  char *p = strstr(buf, "\nUid:");
  if (!p) { if (strncmp(buf, "Uid:", 4) == 0) p = buf; else return -1; }
  else p += 1;
  p += 4; // past "Uid:"
  while (*p == ' ' || *p == '\t') p++;
  return strtol(p, NULL, 10);
}

// The comm (short name) of a pid; tabs/newlines stripped so the record stays one clean line.
static void comm_of(long pid, char *out, size_t cap) {
  char path[64];
  snprintf(path, sizeof path, "/proc/%ld/comm", pid);
  if (read_small(path, out, cap) <= 0) { out[0] = '\0'; return; }
  for (char *c = out; *c; c++) if (*c == '\n' || *c == '\t' || *c == '\r') *c = ' ';
  // trim trailing spaces
  size_t len = strlen(out);
  while (len > 0 && out[len - 1] == ' ') out[--len] = '\0';
}

// Resolve the path an event fd points at, via /proc/self/fd/<fd>.
static int path_of_fd(int fd, char *out, size_t cap) {
  char link[64];
  snprintf(link, sizeof link, "/proc/self/fd/%d", fd);
  ssize_t n = readlink(link, out, cap - 1);
  if (n < 0) return -1;
  out[n] = '\0';
  // strip a trailing " (deleted)" the kernel appends for unlinked files
  char *del = strstr(out, " (deleted)");
  if (del) *del = '\0';
  return 0;
}

int main(int argc, char **argv) {
  if (argc < 2) {
    fprintf(stderr, "usage: %s <mount> [mount...]\n", argv[0]);
    return 2;
  }
  g_self_pid = (long)getpid();

  int fan = fan_init(FAN_CLASS_NOTIF | FAN_NONBLOCK, O_RDONLY | O_LARGEFILE);
  if (fan < 0) {
    int e = errno;
    fprintf(stderr, "fanotify_init failed: %s (errno %d)\n", strerror(e), e);
    if (e == ENOSYS)
      fprintf(stderr,
              "  ENOSYS = the syscall is unavailable here. On Android this is usually the seccomp\n"
              "  filter of the shell/app domain masking fanotify as \"not implemented\", or a kernel\n"
              "  built without CONFIG_FANOTIFY. Run under root/su (e.g. `su -c '%s <mount>'`), which\n"
              "  escapes the shell seccomp filter; if it still returns ENOSYS the kernel lacks fanotify.\n",
              argv[0]);
    else if (e == EPERM || e == EACCES)
      fprintf(stderr, "  Need CAP_SYS_ADMIN — run as root (`adb root`, or `su -c`).\n");
    return 1;
  }

  int marked = 0;
  for (int i = 1; i < argc; i++) {
    // Watch the whole mount; report writes and write-closes with the causing process.
    if (fan_mark(fan, FAN_MARK_ADD | FAN_MARK_MOUNT, FAN_MODIFY | FAN_CLOSE_WRITE, AT_FDCWD, argv[i]) == 0) {
      marked++;
    } else {
      fprintf(stderr, "fanotify_mark %s: %s\n", argv[i], strerror(errno));
    }
  }
  if (marked == 0) {
    fprintf(stderr, "fanotify_caller: no mounts could be watched\n");
    return 1;
  }

  // Line-buffer stdout so the host's log drain sees whole records promptly.
  setvbuf(stdout, NULL, _IOLBF, 0);

  char buf[8192];
  struct pollfd pfd = { .fd = fan, .events = POLLIN };
  for (;;) {
    int pr = poll(&pfd, 1, -1);
    if (pr < 0) { if (errno == EINTR) continue; break; }
    if (!(pfd.revents & POLLIN)) continue;

    ssize_t len = read(fan, buf, sizeof buf);
    if (len < 0) { if (errno == EAGAIN || errno == EINTR) continue; break; }
    if (len == 0) continue;

    struct fanotify_event_metadata *meta = (struct fanotify_event_metadata *)buf;
    while (FAN_EVENT_OK(meta, len)) {
      if (meta->vers != FANOTIFY_METADATA_VERSION) { close(meta->fd >= 0 ? meta->fd : -1); break; }
      long pid = (long)meta->pid;
      int fd = meta->fd;
      // Skip our own I/O and any event without a usable fd/pid.
      if (pid != g_self_pid && fd >= 0) {
        char path[PATH_MAX];
        if (path_of_fd(fd, path, sizeof path) == 0) {
          long uid = uid_of(pid);
          char comm[256];
          comm_of(pid, comm, sizeof comm);
          const char *op = (meta->mask & FAN_CLOSE_WRITE) ? "close" : "modify";
          // Leading empty ts field: the host stamps its own clock on ingest.
          printf("\t%s\t%ld\t%ld\t%s\t%s\n", op, pid, uid, comm, path);
        }
      }
      if (fd >= 0) close(fd);
      meta = FAN_EVENT_NEXT(meta, len);
    }
  }

  close(fan);
  return 0;
}
