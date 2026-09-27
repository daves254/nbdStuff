/**
 * Accurate attribution of the *caller* of a filesystem operation.
 *
 * NBD is a block protocol and Linux page-cache writeback is asynchronous, so by the time a write
 * crosses NBD to the host the calling process is long detached — the host can recover *which file*
 * a block belongs to (the sector mappers) but never *who* wrote it. The only accurate source of the
 * caller is the guest kernel, at the moment of the syscall.
 *
 * `fanotify` provides exactly that: a watch on the mount reports, per event, the **pid** of the
 * process that made the call (unlike `inotify`, whose events carry no pid), which resolves to the
 * uid. A tiny guest agent streams those records to the host; {@link GuestCallerTracker} correlates
 * them to the file operations the share observes.
 *
 * This module is deliberately free of adb / VM / event-emitter dependencies so the correlation logic
 * is pure and unit-testable: a {@link CallerSource} is any stream of kernel-reported records, and
 * {@link FanotifyCallerSource} is the concrete guest-backed one.
 */

/** One kernel-reported filesystem operation and the process that made it. */
export interface CallerRecord {
  /** Guest path the operation touched, exactly as the reporter saw it (an absolute guest path). */
  path: string;
  /** The operation, when the reporter distinguishes them. */
  op?: 'create' | 'modify' | 'delete' | 'open' | 'close';
  /** The pid the kernel attributed the operation to. */
  pid?: number;
  /** The uid the calling process runs as. */
  uid?: number;
  /** The calling process's `comm` (short name), when reported. */
  comm?: string;
  /** When the record was produced, in ms (defaults to the tracker's clock on ingest). */
  ts: number;
}

/**
 * A stream of {@link CallerRecord}s from a kernel-authoritative source (fanotify, eBPF, …). `start`
 * begins delivering records to `onRecord`; `stop` ends the stream and releases resources. A source
 * must never throw from the delivery path — a failure to produce a record simply means no
 * attribution for that operation.
 */
export interface CallerSource {
  start(onRecord: (record: CallerRecord) => void): Promise<void>;
  stop(): Promise<void>;
}

export type CallerMode = 'live' | 'cached';

export interface GuestCallerOptions {
  /**
   * `cached` (default): correlate against the freshest record already streamed for the path — an
   * instant, non-blocking lookup. `live`: additionally wait briefly for a record to arrive if none
   * fresh is cached yet, trading a little latency for catching the just-happened caller.
   */
  mode?: CallerMode;
  /**
   * How long (ms) a streamed record stays valid to attribute a later filesystem event to — the
   * window that bridges the gap between the guest syscall and the host seeing the write. Default 200.
   */
  timeToCacheMs?: number;
  /**
   * In `live` mode, how long (ms) to wait for a fresh record for a path before giving up. Defaults
   * to {@link timeToCacheMs}.
   */
  liveWaitMs?: number;
  /** Clock, for tests. Defaults to `Date.now`. */
  now?: () => number;
}

const DEFAULT_TIME_TO_CACHE_MS = 200;

interface Waiter {
  resolve: (record: CallerRecord | undefined) => void;
  timer: ReturnType<typeof setTimeout>;
}

/**
 * Correlates a {@link CallerSource}'s records to filesystem operations. Keeps the newest record per
 * path and answers "who did the operation on this path?" either from the cache ({@link resolve}) or,
 * in `live` mode, by waiting briefly for the next record ({@link resolveLive}).
 */
export class GuestCallerTracker {
  private readonly mode: CallerMode;
  private readonly timeToCacheMs: number;
  private readonly liveWaitMs: number;
  private readonly now: () => number;
  /** Newest record seen per guest path. */
  private readonly latest = new Map<string, CallerRecord>();
  /** Pending live waiters, per path. */
  private readonly waiters = new Map<string, Set<Waiter>>();
  private started = false;

  constructor(private readonly source: CallerSource, opts: GuestCallerOptions = {}) {
    this.mode = opts.mode ?? 'cached';
    this.timeToCacheMs = opts.timeToCacheMs ?? DEFAULT_TIME_TO_CACHE_MS;
    this.liveWaitMs = opts.liveWaitMs ?? this.timeToCacheMs;
    this.now = opts.now ?? Date.now;
  }

  /** Begin consuming the source. Safe to call once; subsequent calls are no-ops. */
  async start(): Promise<void> {
    if (this.started) return;
    this.started = true;
    await this.source.start((r) => this.ingest(r));
  }

  /** Stop the source and reject any outstanding live waiters. */
  async stop(): Promise<void> {
    if (!this.started) return;
    this.started = false;
    for (const set of this.waiters.values()) for (const w of set) { clearTimeout(w.timer); w.resolve(undefined); }
    this.waiters.clear();
    this.latest.clear();
    await this.source.stop();
  }

  /** Feed a record in directly (the source's callback, and the unit tests, use this). */
  ingest(record: CallerRecord): void {
    const ts = Number.isFinite(record.ts) ? record.ts : this.now();
    const prev = this.latest.get(record.path);
    if (!prev || ts >= prev.ts) this.latest.set(record.path, { ...record, ts });
    const set = this.waiters.get(record.path);
    if (set) {
      for (const w of set) { clearTimeout(w.timer); w.resolve({ ...record, ts }); }
      this.waiters.delete(record.path);
    }
  }

  /** The default mode for this tracker. */
  get defaultMode(): CallerMode {
    return this.mode;
  }

  /** Cached lookup: the freshest record for `path` still within `timeToCacheMs`, else undefined. */
  resolve(path: string): CallerRecord | undefined {
    const rec = this.latest.get(path);
    if (!rec) return undefined;
    if (this.now() - rec.ts > this.timeToCacheMs) return undefined;
    return rec;
  }

  /**
   * Resolve the caller of an operation on `path`. In `cached` mode (or when a fresh record is
   * already cached) this returns synchronously-fresh data; in `live` mode with nothing cached it
   * waits up to `liveWaitMs` for the next record before resolving `undefined`.
   */
  async resolveLive(path: string, waitMs = this.liveWaitMs): Promise<CallerRecord | undefined> {
    const cached = this.resolve(path);
    if (cached) return cached;
    if (waitMs <= 0) return undefined;
    return new Promise<CallerRecord | undefined>((resolve) => {
      const timer = setTimeout(() => {
        const set = this.waiters.get(path);
        if (set) { set.delete(waiter); if (set.size === 0) this.waiters.delete(path); }
        resolve(undefined);
      }, waitMs);
      if (typeof (timer as { unref?: () => void }).unref === 'function') (timer as { unref: () => void }).unref();
      const waiter: Waiter = { resolve, timer };
      let set = this.waiters.get(path);
      if (!set) { set = new Set(); this.waiters.set(path, set); }
      set.add(waiter);
    });
  }

  /** Resolve using this tracker's configured mode. */
  resolveByMode(path: string): CallerRecord | undefined | Promise<CallerRecord | undefined> {
    return this.mode === 'live' ? this.resolveLive(path) : this.resolve(path);
  }

  /** Drop cached records older than `timeToCacheMs` (bounded memory for busy shares). */
  prune(): void {
    const cutoff = this.now() - this.timeToCacheMs;
    for (const [path, rec] of this.latest) if (rec.ts < cutoff) this.latest.delete(path);
  }
}

/**
 * Parse one line the fanotify guest agent writes: tab-separated `ts<TAB>op<TAB>pid<TAB>uid<TAB>comm<TAB>path`.
 * `ts`/`op`/`comm` may be empty; a line without a usable path is ignored (returns undefined).
 * Robust to trailing whitespace, missing trailing fields, and tabs inside `comm` never occur
 * because the agent replaces them. The `path` is the last field so it may itself contain no tab.
 */
export function parseCallerLine(line: string, nowMs: number): CallerRecord | undefined {
  const raw = line.replace(/\r$/, '');
  if (!raw) return undefined;
  const parts = raw.split('\t');
  if (parts.length < 6) return undefined;
  const [tsStr, opStr, pidStr, uidStr, comm, ...pathParts] = parts;
  const path = pathParts.join('\t').trim();
  if (!path) return undefined;
  const num = (s: string | undefined): number | undefined => (s && /^\d+$/.test(s.trim()) ? Number(s.trim()) : undefined);
  const opRaw = (opStr ?? '').trim();
  const op = opRaw === 'create' || opRaw === 'modify' || opRaw === 'delete' || opRaw === 'open' || opRaw === 'close' ? opRaw : undefined;
  const ts = num(tsStr) ?? nowMs;
  return {
    path,
    ...(op ? { op } : {}),
    ...(num(pidStr) !== undefined ? { pid: num(pidStr) } : {}),
    ...(num(uidStr) !== undefined ? { uid: num(uidStr) } : {}),
    ...(comm && comm.trim() ? { comm: comm.trim() } : {}),
    ts,
  };
}

/** The minimal adb surface {@link FanotifyCallerSource} needs (matches NbdFileShare's device). */
export interface CallerAdb {
  exec(command: string, timeoutMs?: number): Promise<string>;
}

export interface FanotifyCallerSourceOptions {
  /** Guest paths (mount points) to watch. */
  mounts: string[];
  /**
   * Absolute guest path of the fanotify reporter binary. It must already be present in the guest
   * (pushed by the caller); the source runs it, it never compiles anything. The reporter is expected
   * to print `ts<TAB>op<TAB>pid<TAB>uid<TAB>comm<TAB>path` lines, one per operation, to stdout.
   */
  agentPath: string;
  /** Where the reporter's output is collected in the guest. Default: a temp file under /data/local/tmp. */
  logPath?: string;
  /** How often (ms) to drain the guest log. Default 100 (kept below timeToCacheMs so records are fresh). */
  pollMs?: number;
  now?: () => number;
}

/** Shell-quote a single argument for the guest shell. */
function shq(v: string): string {
  return "'" + v.split("'").join("'\\''") + "'";
}

/**
 * A {@link CallerSource} backed by the fanotify guest agent, driven over adb — the same pattern as
 * `NbdFileShare.watchInGuest`, but with pid/uid on every record. It launches the reporter watching
 * the given mounts, then polls its output. `start` throws if the agent cannot be launched (the
 * caller treats that as "no attribution", never a crash).
 */
export class FanotifyCallerSource implements CallerSource {
  private timer?: ReturnType<typeof setInterval>;
  private readonly log: string;
  private readonly now: () => number;
  private stopped = false;

  constructor(private readonly adb: CallerAdb, private readonly opts: FanotifyCallerSourceOptions) {
    this.log = opts.logPath ?? `/data/local/tmp/.nbdcaller-${Math.random().toString(36).slice(2, 10)}.log`;
    this.now = opts.now ?? Date.now;
  }

  async start(onRecord: (record: CallerRecord) => void): Promise<void> {
    if (!this.opts.mounts.length) throw new Error('FanotifyCallerSource: no mounts to watch');
    const agent = shq(this.opts.agentPath);
    const log = shq(this.log);
    // Confirm the reporter exists and is runnable before relying on it.
    const probe = await this.adb.exec(`[ -x ${agent} ] && echo ok || echo no`).catch(() => 'no');
    if (!/\bok\b/.test(probe)) throw new Error(`FanotifyCallerSource: reporter not found or not executable at ${this.opts.agentPath}`);
    const mounts = this.opts.mounts.map(shq).join(' ');
    // Kill any prior instance for this log, then launch backgrounded, surviving the adb shell.
    await this.adb.exec(`pkill -f ${log} 2>/dev/null; : > ${log}; ( ${agent} ${mounts} >> ${log} 2>/dev/null & ); echo ok`);
    const drain = async (): Promise<void> => {
      if (this.stopped) return;
      const out = await this.adb
        .exec(`T=${shq(this.log + '.r')}; cp ${log} $T 2>/dev/null && : > ${log}; cat $T 2>/dev/null; rm -f $T`)
        .catch(() => '');
      if (!out) return;
      const now = this.now();
      for (const line of out.split('\n')) {
        const rec = parseCallerLine(line, now);
        if (rec) onRecord(rec);
      }
    };
    this.timer = setInterval(() => void drain().catch(() => undefined), this.opts.pollMs ?? 100);
    if (typeof (this.timer as { unref?: () => void }).unref === 'function') (this.timer as { unref: () => void }).unref();
  }

  async stop(): Promise<void> {
    this.stopped = true;
    if (this.timer) clearInterval(this.timer);
    this.timer = undefined;
    await this.adb.exec(`pkill -f ${shq(this.log)} 2>/dev/null; rm -f ${shq(this.log)} ${shq(this.log + '.r')}; echo ok`).catch(() => undefined);
  }
}

// ------------------------------------------------------------------------------------------------
// ftrace source — the accurate caller from the kernel's own tracepoints, for kernels WITHOUT
// fanotify. Android's ext4/f2fs ship write tracepoints (e.g. ext4_da_write_begin) that carry the
// causing pid/comm and the device + inode number. There is no path in the event, so unlike fanotify
// this source resolves inode → path through the block mapper (which parses the very image the guest
// mounts, so its inode numbers match the kernel's). Enable with a guest that has CONFIG_FTRACE=y and
// the ext4/f2fs events present under tracefs — no CAP for fanotify or CONFIG_FANOTIFY needed.
// ------------------------------------------------------------------------------------------------

/** One parsed ftrace tracepoint line: the fields we correlate a write to a file and a caller with. */
export interface FtraceEvent {
  /** The causing process's comm (short name). */
  comm: string;
  /** The causing pid. */
  pid: number;
  /** The block device the inode is on, as the tracepoint prints it (`"maj,min"`), when present. */
  dev?: string;
  /** The inode number the operation touched — the bridge to a path via the mapper. */
  ino: number;
  /** The operation, mapped from the tracepoint name. */
  op: CallerRecord['op'];
}

/** Tracepoints this source understands, mapped to a {@link CallerRecord} op. Extend via options. */
export const FTRACE_WRITE_TRACEPOINTS: Record<string, CallerRecord['op']> = {
  ext4_da_write_begin: 'modify',
  ext4_write_begin: 'modify',
  f2fs_write_begin: 'modify',
  f2fs_datawrite_begin: 'modify',
};

/**
 * Parse one ftrace `trace_pipe` line into an {@link FtraceEvent}, or undefined when it is not a
 * recognised write tracepoint. Handles the standard format, e.g.:
 *
 *     sh-13786 [001] ..... 1531.713920: ext4_da_write_begin: dev 254,0 ino 245771 pos 0 len 3
 *
 * `comm` may itself contain dashes (`kworker/u16:2-1234`); the pid is the last `-<digits>` before the
 * CPU field, so the comm is everything up to it. `tracepoints` maps a tracepoint name to an op; pass
 * your own to widen or narrow the set (defaults to {@link FTRACE_WRITE_TRACEPOINTS}).
 */
export function parseFtraceEventLine(
  line: string,
  tracepoints: Record<string, CallerRecord['op']> = FTRACE_WRITE_TRACEPOINTS,
): FtraceEvent | undefined {
  const raw = line.replace(/\r$/, '');
  // <comm>-<pid> [<cpu>] <flags> <ts>: <tracepoint>: <rest>
  const m = /^\s*(.+)-(\d+)\s+\[\d+\]\s+\S+\s+[\d.]+:\s+(\w+):\s*(.*)$/.exec(raw);
  if (!m) return undefined;
  const [, comm, pidStr, tp, rest] = m;
  const op = tracepoints[tp];
  if (op === undefined) return undefined;
  const inoM = /\bino\s+(\d+)/.exec(rest);
  if (!inoM) return undefined;
  const devM = /\bdev\s+(\d+,\d+)/.exec(rest);
  return {
    comm: comm.trim(),
    pid: Number(pidStr),
    ...(devM ? { dev: devM[1] } : {}),
    ino: Number(inoM[1]),
    op,
  };
}

export interface FtraceCallerSourceOptions {
  /**
   * Resolve a reported inode (and device, when the event carried one) to the guest path the share
   * attributes events by — i.e. the same key `NbdFileShare.dispatch` looks up (mount point + the
   * in-image path). Returning undefined drops the record (unknown inode, or another device's).
   */
  resolve: (ino: number, dev: string | undefined) => string | undefined;
  /** tracefs mount. Default: `/sys/kernel/tracing`, falling back to `/sys/kernel/debug/tracing`. */
  tracefs?: string;
  /**
   * `subsystem/event` tracepoints to enable and honour. Default the ext4 write-begin set. Each name's
   * op comes from `tracepoints` (defaults to {@link FTRACE_WRITE_TRACEPOINTS}); add f2fs by passing
   * e.g. `['f2fs/f2fs_write_begin']` and a matching `tracepoints` entry.
   */
  events?: string[];
  /** Tracepoint→op map for {@link parseFtraceEventLine}. Defaults to {@link FTRACE_WRITE_TRACEPOINTS}. */
  tracepoints?: Record<string, CallerRecord['op']>;
  /** Only accept events on this device (`"maj,min"`, e.g. `"254,0"`); others are dropped. */
  dev?: string;
  /** Where the trace stream is collected in the guest. Default: a temp file under /data/local/tmp. */
  logPath?: string;
  /** How often (ms) to drain the guest log. Default 100 (kept below timeToCacheMs so records are fresh). */
  pollMs?: number;
  now?: () => number;
}

/**
 * A {@link CallerSource} backed by the guest kernel's ftrace tracepoints, driven over adb — the
 * fanotify-free path for kernels without CONFIG_FANOTIFY (BlissOS, many Android-x86 builds). It
 * enables the configured ext4/f2fs write tracepoints, streams `trace_pipe` to a guest log, polls it,
 * and turns each event into a {@link CallerRecord} — resolving the inode to a path via `resolve`.
 *
 * `start` throws if tracefs or the events are not present (the caller treats that as "no accurate
 * attribution", falling back to image-derived owner). The pid/comm come straight from the kernel, so
 * the caller is accurate; uid is left unset (ftrace does not report it — the owner fallback fills it,
 * or resolve a pid via /proc yourself).
 */
export class FtraceCallerSource implements CallerSource {
  private timer?: ReturnType<typeof setInterval>;
  private readonly log: string;
  private readonly now: () => number;
  private readonly events: string[];
  private readonly tracepoints: Record<string, CallerRecord['op']>;
  private tracefs = '';
  private stopped = false;

  constructor(private readonly adb: CallerAdb, private readonly opts: FtraceCallerSourceOptions) {
    this.log = opts.logPath ?? `/data/local/tmp/.nbdftrace-${Math.random().toString(36).slice(2, 10)}.log`;
    this.now = opts.now ?? Date.now;
    this.events = opts.events?.length ? opts.events : ['ext4/ext4_da_write_begin', 'ext4/ext4_write_begin'];
    this.tracepoints = opts.tracepoints ?? FTRACE_WRITE_TRACEPOINTS;
  }

  async start(onRecord: (record: CallerRecord) => void): Promise<void> {
    // Locate tracefs (the two standard mounts), and require it and at least one event to exist.
    const cand = this.opts.tracefs ? [this.opts.tracefs] : ['/sys/kernel/tracing', '/sys/kernel/debug/tracing'];
    const probe = await this.adb
      .exec(`for T in ${cand.map(shq).join(' ')}; do [ -d "$T/events" ] && { echo "$T"; break; }; done`)
      .catch(() => '');
    this.tracefs = probe.trim().split('\n')[0]?.trim() ?? '';
    if (!this.tracefs) throw new Error(`FtraceCallerSource: tracefs not found (looked in ${cand.join(', ')})`);
    const T = shq(this.tracefs);
    // Enable each event; count how many took, so a kernel missing them all fails loudly.
    const enableCmds = this.events
      .map((e) => `[ -w ${shq(this.tracefs + '/events/' + e + '/enable')} ] && { echo 1 > ${shq(this.tracefs + '/events/' + e + '/enable')}; echo y; }`)
      .join('; ');
    const enabled = await this.adb.exec(`{ ${enableCmds}; } 2>/dev/null | grep -c y`).catch(() => '0');
    if (parseInt(enabled.trim(), 10) < 1) throw new Error(`FtraceCallerSource: none of the events could be enabled (${this.events.join(', ')}) under ${this.tracefs}`);
    const log = shq(this.log);
    // Fresh log, make sure tracing is on, then stream trace_pipe backgrounded; record its pid so stop
    // kills exactly this reader (trace_pipe is consuming — never pkill every reader on the device).
    await this.adb.exec(`echo 1 > ${T}/tracing_on 2>/dev/null; : > ${log}; ( cat ${T}/trace_pipe >> ${log} 2>/dev/null & echo $! > ${log}.pid ); echo ok`);
    const drain = async (): Promise<void> => {
      if (this.stopped) return;
      const out = await this.adb
        .exec(`R=${shq(this.log + '.r')}; cp ${log} $R 2>/dev/null && : > ${log}; cat $R 2>/dev/null; rm -f $R`)
        .catch(() => '');
      if (!out) return;
      const now = this.now();
      for (const line of out.split('\n')) {
        const ev = parseFtraceEventLine(line, this.tracepoints);
        if (!ev) continue;
        if (this.opts.dev && ev.dev && ev.dev !== this.opts.dev) continue;
        const path = this.opts.resolve(ev.ino, ev.dev);
        if (!path) continue;
        onRecord({ path, op: ev.op, pid: ev.pid, ...(ev.comm ? { comm: ev.comm } : {}), ts: now });
      }
    };
    this.timer = setInterval(() => void drain().catch(() => undefined), this.opts.pollMs ?? 100);
    if (typeof (this.timer as { unref?: () => void }).unref === 'function') (this.timer as { unref: () => void }).unref();
  }

  async stop(): Promise<void> {
    this.stopped = true;
    if (this.timer) clearInterval(this.timer);
    this.timer = undefined;
    if (!this.tracefs) return;
    const T = shq(this.tracefs);
    const log = shq(this.log);
    // Disable the events we turned on, kill our trace_pipe reader by its recorded pid, and clean up.
    const disableCmds = this.events.map((e) => `echo 0 > ${shq(this.tracefs + '/events/' + e + '/enable')} 2>/dev/null`).join('; ');
    await this.adb
      .exec(`P=$(cat ${log}.pid 2>/dev/null); [ -n "$P" ] && kill "$P" 2>/dev/null; ${disableCmds}; rm -f ${log} ${log}.r ${log}.pid; echo ok`)
      .catch(() => undefined);
  }
}
