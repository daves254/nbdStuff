import { TypedEventEmitter } from '../events';
import { randomBytes } from 'node:crypto';
import { openSync, writeSync, closeSync, fsyncSync, existsSync, mkdirSync } from 'node:fs';
import { dirname } from 'node:path';
import { FileBackend, NbdServer } from './server';
import type { NbdAccessEvent, NbdBackend, TouchedFile } from './server';
import { Fat32Mapper } from './fat32';
import { resolveLogger } from '../logger';
import { BlissError } from '../errors';
import { GuestProcess, guestProcess } from '../guestProcess';
import type { DriveConfig, Logger } from '../types';
import { CowLayer, LayerStack, type LayerInfo, type LayerSpec } from './layers';
import { NbdEngine, resolveNbdEngine, type NbdEngineKind } from './engine';

/**
 * The app/process the guest attributes a file operation to. Best-effort: NBD is
 * block-level and cannot see processes, so this is resolved by querying the
 * guest over adb at event time (see {@link NbdFileShareOptions.attributeApp}).
 */
export interface AppInfo {
  pid?: number;
  /** Linux uid the process runs as (resolved by the built-in attributors; enables `process.isSystem()`). */
  uid?: number;
  /** Android package id, e.g. `com.example.app`, when it can be resolved. */
  package?: string;
  /** Raw process name / cmdline, when a package can't be resolved. */
  process?: string;
}

/** A file create/delete/modify observed on the share. */
export interface FileEvent {
  type: 'create' | 'delete' | 'modify';
  /** Guest path as the FAT mapper reports it, e.g. `/config.json`. */
  path: string;
  size: number;
  isDir: boolean;
  /**
   * The guest process the write is attributed to, when attribution is on and it resolved:
   * `e.process.getPackage()`, `.getUID()`, `.isSystem()`, … See {@link GuestProcess}.
   */
  process?: GuestProcess;
  /** @deprecated Use {@link process}. The same data as a plain object. */
  app?: AppInfo;
}

/** AppInfo → the shared GuestProcess (processName falls back to the package id). */
function toProcess(app: AppInfo): GuestProcess {
  return guestProcess({
    ...(app.pid !== undefined ? { pid: app.pid } : {}),
    ...(app.uid !== undefined ? { uid: app.uid } : {}),
    ...(app.package !== undefined ? { package: app.package } : {}),
    ...(app.process !== undefined ? { processName: app.process } : {}),
  });
}

/**
 * Authoritative bytes for a {@link FileRedirect}: a fixed `Buffer`/`string`, or a
 * **function** returning the bytes for the requested path. The function is
 * evaluated on the NBD read path, which is synchronous — so it must return
 * synchronously (no promises), and should be cheap and deterministic (it may be
 * called once per read request). Return a `string` and it's UTF-8 encoded.
 */
export type RedirectContent = Buffer | string | ((path: string) => Buffer | string);

/**
 * A "ground truth" file: the guest sees {@link content} when it reads this path,
 * regardless of what is on the underlying image — so several VM instances can be
 * handed identical authoritative files, or a file can be overridden at runtime.
 * `content` may be a function, so the served bytes can be computed per read.
 */
export interface FileRedirect {
  /** Guest path exactly as the mapper reports it (e.g. `/config.json`). */
  path: string;
  /** Authoritative bytes served on read — fixed, or a function of the path. */
  content: RedirectContent;
  /** Drop guest writes to this file, keeping the ground truth immutable. */
  readonly?: boolean;
  /** Also mirror guest writes to this host file (offset-preserving). */
  mirrorTo?: string;
}

export type AppAttributor = (path: string, share: NbdFileShare) => Promise<AppInfo | undefined>;

export interface NbdFileShareOptions {
  /** FAT32 image backing the share. Created (empty) if missing when `size` set. */
  image: string;
  /** Size in bytes when creating the backing file. */
  size?: number;
  /**
   * Stack writable **copy-on-write layers** over `image` (bottom layer first) — one base system
   * image shared by every VM, a layer per profile, another per context. Reads fall through to the
   * base for anything nobody has written; writes land in the top layer. See {@link LayerStack}.
   *
   * The share sits ABOVE the layers, so redirects, file events, app attribution and the block
   * interceptor all keep working on the composed view — which is why this lives here and not in a
   * QEMU `overlay` (a qcow2 overlay swallows the writes before they ever reach the share).
   */
  layers?: LayerSpec[];
  /**
   * Open `image` read-only. Defaults to **true when `layers` are given**, because the point of
   * layering is that the shared base cannot be written by the guests stacking on it.
   */
  readonlyBase?: boolean;
  /**
   * Export name QEMU connects to. Default: a random `share-…` name. Besides the port it is all a
   * client needs, so both engines answer to it alone (no "" alias, no listing) — pick one only when
   * something other than this process has to know it.
   */
  exportName?: string;
  host?: string;
  port?: number;
  /** Emit create/delete/modify by re-parsing the FS after writes. Default true. */
  watch?: boolean;
  /** Quiet period (ms) after a write burst before re-parsing. Default 300. */
  settleMs?: number;
  /** Ground-truth / redirected files. */
  redirects?: FileRedirect[];
  /**
   * Which app touched a file. **Off by default** (`false`) — zero overhead on
   * the event path. Turn it on with:
   * - `'live'` (or `true`): query the guest over adb per event (accurate, adds
   *   a few adb round-trips of latency to each event);
   * - `'cached'`: a background poller keeps an in-RAM path→app index, so
   *   event-time attribution is an instant lookup with no adb on the hot path
   *   (uses more RAM/CPU in the background; index can lag by up to `attributionPollMs`);
   * - a custom {@link AppAttributor} function.
   * Requires the share to be attached to a started VM and a {@link mountPoint}.
   */
  attributeApp?: boolean | 'live' | 'cached' | AppAttributor;
  /** Poll interval (ms) for `attributeApp: 'cached'`. Default 1500. */
  attributionPollMs?: number;
  /** Guest mount point of this share, e.g. `/mnt/media_rw/share`, for attribution. */
  mountPoint?: string;
  /**
   * Which engine serves the block path — see {@link NbdEngine}. `cpp` (the default) runs it in the
   * native engine process; `js` runs it in-process. Two things exist only in `js`: a synchronous
   * {@link BlockInterceptor}, and a redirect whose `content` is a function. Everything else —
   * layers, redirects with fixed bytes, per-context stores via {@link NbdFileShare.routeContext},
   * file events, attribution — works on both.
   */
  engine?: NbdEngineKind;
  log?: Logger | 'silent' | 'error' | 'warn' | 'info' | 'debug';
}

/**
 * Where and how the share is mounted inside the guest. Any path: a scratch directory, somewhere
 * under `/data`, or straight over a directory that already exists (then use {@link
 * NbdFileShare.bindInGuest} to put parts of it over any number of other directories).
 *
 * FAT32 stores no ownership, permissions or SELinux labels, so the mount carries ONE of each for
 * everything on it: set `uid`/`gid`/`fmask`/`dmask` for who owns it and `context` (or
 * `contextFrom`, to copy a directory's label) for what SELinux calls it. Without them the mount
 * belongs to root and an app cannot write to it. Binds inherit these from the mount.
 */
export interface GuestMountOptions {
  /** Mount point in the guest. Defaults to the share's `mountPoint`. */
  at?: string;
  /** Filesystem type. Default `vfat`. */
  type?: string;
  /** Owner of everything on the mount — an app's uid to make it that app's directory. */
  uid?: number;
  gid?: number;
  /** Permission masks as `mount` takes them, e.g. `fmask: '0177'` gives files 0600. */
  fmask?: string;
  dmask?: string;
  /** SELinux label for everything on the mount, e.g. `u:object_r:app_data_file:s0:c221,c256,c512,c768`. */
  context?: string;
  /** Copy the SELinux label of this guest path instead of naming one. */
  contextFrom?: string;
  readonly?: boolean;
  /** Any further `-o` options, verbatim. */
  options?: string[];
}

/** Minimal shape of the device used for app attribution (a started BlissVM). */
export interface AttributableDevice {
  readonly adb: { exec(command: string, timeoutMs?: number): Promise<string> };
}

/**
 * A single guest **block operation** on one file segment, as seen at the NBD
 * block level (the mapper resolves which file a block belongs to). This is what a
 * {@link BlockInterceptor} receives — one call per touched file segment of a
 * read/write.
 */
export interface BlockOp {
  command: 'read' | 'write';
  /** Guest file path this segment belongs to, or `<free>` / `<metadata>`. */
  path: string;
  /** Byte offset within that file. */
  fileOffset: number;
  /**
   * The bytes in play: for a `read`, what the base/redirect would return (so you
   * can inspect/replace it); for a `write`, the guest's payload for this segment.
   */
  bytes: Buffer;
}

/** What a {@link BlockInterceptor} decides for one op. Return nothing to pass through. */
export interface BlockDecision {
  /** Replace the bytes — the read result, or the bytes actually written. */
  bytes?: Buffer;
  /** For a `write`: don't persist it to the base image. Ignored for reads. */
  drop?: boolean;
  /**
   * Route this segment to another store instead of the base — read from / write
   * to the backend registered under this id (see
   * {@link NbdFileShare.registerContextBackend}). Used by app contexting so each
   * context's data lives in its own backing store.
   */
  redirectTo?: string;
}

/** Helpers handed to a {@link BlockInterceptor}. */
export interface InterceptSelf {
  /** Sugar for `return { redirectTo: contextId }` — route this op to another store. */
  redirectOp(contextId: string): BlockDecision;
}

/**
 * A synchronous hook invoked for every read/write at the **guest block level**,
 * per touched file segment. Transform bytes, `drop` a write, or `redirectOp` to
 * another context's store. Must be synchronous (the NBD I/O path is sync) and
 * fast. `<free>` / `<metadata>` segments are not passed to it.
 */
export type BlockInterceptor = (op: BlockOp, self: InterceptSelf) => BlockDecision | void;

/** Block-level hooks wired into {@link OverlayBackend} (used by app contexting). */
export interface OverlayHooks {
  /** Returns the interceptor to run right now (or undefined), so it can change live. */
  interceptor?: () => BlockInterceptor | undefined;
  /** Backends `redirectTo` can route to, keyed by id (e.g. a context id). */
  altBackends?: Map<string, NbdBackend>;
}

const INTERCEPT_SELF: InterceptSelf = { redirectOp: (contextId) => ({ redirectTo: contextId }) };

/** Truncate or zero-pad `buf` to exactly `n` bytes (keeps block layout aligned). */
function fit(buf: Buffer, n: number): Buffer {
  if (buf.length === n) return buf;
  if (buf.length > n) return buf.subarray(0, n);
  const out = Buffer.alloc(n);
  buf.copy(out);
  return out;
}

/** A redirect resolved to bytes (or a bytes-producing fn) plus its write policy. */
export interface ResolvedRedirect {
  /** Fixed bytes, or a synchronous function returning the path's bytes per read. */
  content: Buffer | ((path: string) => Buffer);
  readonly: boolean;
  /** Host file guest writes are mirrored into (offset-preserving), if any. */
  mirrorTo?: string;
  /** Its open fd, while the in-process engine is serving. */
  mirrorFd?: number;
}

/** Open a mirror file for positional writes — never append mode, which ignores the offset. */
/**
 * The guest command listing open files under the share: every process's fd links, filtered to the
 * mount point and the targets of its binds (an app opens its data through the bind target). Android's
 * toybox lsof has no `+D`, so the fd table is read directly, in one command.
 */
export function openFilesCommand(mounts: string | string[], binds: ReadonlyArray<{ source: string; target: string }>): string {
  const points = typeof mounts === 'string' ? [mounts] : mounts;
  const esc = (p: string) => p.replace(/[.[\]()*+?^$|\\]/g, '\\$&');
  const under = (src: string) => points.some((m) => src.startsWith(m + '/'));
  const prefixes = [...points, ...binds.filter((b) => under(b.source)).map((b) => b.target)];
  return `ls -l /proc/[0-9]*/fd/ 2>/dev/null | grep -E '^/proc/|-> (${prefixes.map(esc).join('|')})/'`;
}

/**
 * Parse {@link openFilesCommand} output into pid → share paths, written under the FIRST mount point
 * (`<mounts[0]><path>`) whichever mount point or bind target a process opened them through.
 */
export function parseOpenFiles(out: string, mounts: string | string[], binds: ReadonlyArray<{ source: string; target: string }>): Map<number, string[]> {
  const points = typeof mounts === 'string' ? [mounts] : mounts;
  const canonical = points[0] ?? '';
  const toShare = (p: string): string | undefined => {
    const m = points.find((x) => p.startsWith(x + '/'));
    return m === undefined ? undefined : canonical + p.slice(m.length);
  };
  const byPid = new Map<number, string[]>();
  let pid = NaN;
  for (const raw of out.split('\n')) {
    const line = raw.trim();
    const head = /^\/proc\/(\d+)\/fd\/?:$/.exec(line);
    if (head) {
      pid = Number(head[1]);
      continue;
    }
    const arrow = line.indexOf(' -> ');
    if (arrow < 0 || !Number.isFinite(pid)) continue;
    const opened = line.slice(arrow + 4);
    let p = toShare(opened);
    if (p === undefined) {
      const b = binds.find((x) => toShare(x.source) !== undefined && (opened === x.target || opened.startsWith(x.target + '/')));
      if (b) p = toShare(b.source + opened.slice(b.target.length));
    }
    if (p === undefined) continue;
    let arr = byPid.get(pid);
    if (!arr) byPid.set(pid, (arr = []));
    arr.push(p);
  }
  return byPid;
}

/**
 * Requested vfat owner/mask options that the kernel did NOT apply, from a /proc/mounts line. The
 * kernel omits uid=/gid= when they are 0 and always prints both masks. Unreadable → no complaint.
 */
export function mismatchedVfatOptions(o: GuestMountOptions, mountsLine: string): string[] {
  const fields = mountsLine.trim().split(/\s+/);
  if (fields.length < 4) return [];
  const got = new Map(
    fields[3]!.split(',').map((kv): [string, string] => {
      const i = kv.indexOf('=');
      return i < 0 ? [kv, ''] : [kv.slice(0, i), kv.slice(i + 1)];
    }),
  );
  const out: string[] = [];
  for (const k of ['uid', 'gid'] as const) {
    const have = Number(got.get(k) ?? 0);
    if (o[k] !== undefined && have !== o[k]) out.push(`${k}=${have}, not ${o[k]}`);
  }
  for (const k of ['fmask', 'dmask'] as const) {
    const have = got.get(k);
    if (o[k] !== undefined && have !== undefined && parseInt(have, 8) !== parseInt(o[k]!, 8)) out.push(`${k}=${have}, not ${o[k]}`);
  }
  return out;
}

function openMirror(path: string): number {
  if (!existsSync(path)) mkdirSync(dirname(path), { recursive: true });
  return openSync(path, existsSync(path) ? 'r+' : 'w+');
}

/** Single-quote a value for a guest shell command. */
function shq(v: string): string {
  return "'" + v.split("'").join("'\\''") + "'";
}

function closeMirror(r: ResolvedRedirect): void {
  if (r.mirrorFd === undefined) return;
  const fd = r.mirrorFd;
  r.mirrorFd = undefined; // before closing: a recycled fd number must never be written through again
  try {
    closeSync(fd);
  } catch {
    /* already closed */
  }
}

/**
 * An {@link NbdBackend} that overlays {@link FileRedirect}s onto a base backend,
 * using a {@link Fat32Mapper} to know which file each block belongs to. Reads of
 * a redirected file return the authoritative content; writes to a `readonly`
 * redirect are dropped, and `mirrorTo` writes are copied to a host file.
 */
export class OverlayBackend implements NbdBackend {
  constructor(
    private readonly base: NbdBackend,
    private readonly mapper: Fat32Mapper | undefined,
    private readonly redirects: Map<string, ResolvedRedirect>,
    private readonly hooks?: OverlayHooks,
  ) {}

  /** Whatever is on top of the stack NOW — a layer pushed after listen() changes it. */
  get readonly(): boolean {
    return !!this.base.readonly;
  }

  size(): number | Promise<number> {
    return this.base.size();
  }

  private interceptable(path: string): boolean {
    return path !== '<free>' && path !== '<metadata>';
  }

  read(offset: number, length: number): Buffer {
    const out = this.base.read(offset, length) as Buffer;
    const interceptor = this.hooks?.interceptor?.();
    if (!this.mapper || (this.redirects.size === 0 && !interceptor)) return out;
    let cur = 0;
    for (const seg of this.mapper.mapRange(offset, length)) {
      // Bytes the base/redirect would serve for this segment.
      let segBuf: Buffer = out.subarray(cur, cur + seg.bytes);
      const r = this.redirects.get(seg.path);
      if (r) {
        const src = typeof r.content === 'function' ? r.content(seg.path) : r.content;
        const b = Buffer.alloc(seg.bytes);
        for (let i = 0; i < seg.bytes; i++) {
          const fo = seg.fileOffset + i;
          b[i] = fo < src.length ? src[fo]! : 0;
        }
        segBuf = b;
      }
      // Guest-block-level interceptor: transform, or redirect to another store.
      if (interceptor && this.interceptable(seg.path)) {
        const d = interceptor({ command: 'read', path: seg.path, fileOffset: seg.fileOffset, bytes: Buffer.from(segBuf) }, INTERCEPT_SELF);
        const alt = d?.redirectTo ? this.hooks?.altBackends?.get(d.redirectTo) : undefined;
        if (alt) segBuf = fit(alt.read(offset + cur, seg.bytes) as Buffer, seg.bytes);
        else if (d?.bytes) segBuf = fit(d.bytes, seg.bytes);
      }
      segBuf.copy(out, cur, 0, seg.bytes);
      cur += seg.bytes;
    }
    return out;
  }

  write(offset: number, data: Buffer): void {
    const interceptor = this.hooks?.interceptor?.();
    if (!this.mapper || (this.redirects.size === 0 && !interceptor)) {
      this.base.write(offset, data);
      return;
    }
    let cur = 0;
    for (const seg of this.mapper.mapRange(offset, data.length)) {
      let chunk = data.subarray(cur, cur + seg.bytes);
      const r = this.redirects.get(seg.path);
      let drop = !!(r && r.readonly);
      let target: NbdBackend = this.base;
      if (interceptor && this.interceptable(seg.path)) {
        const d = interceptor({ command: 'write', path: seg.path, fileOffset: seg.fileOffset, bytes: Buffer.from(chunk) }, INTERCEPT_SELF);
        if (d?.bytes) chunk = fit(d.bytes, seg.bytes);
        if (d?.drop) drop = true;
        if (d?.redirectTo) {
          const alt = this.hooks?.altBackends?.get(d.redirectTo);
          if (alt) {
            target = alt;
            drop = false; // an explicit redirect overrides a readonly-redirect drop
          }
        }
      }
      if (!drop) target.write(offset + cur, chunk);
      if (r?.mirrorFd !== undefined) writeSync(r.mirrorFd, chunk, 0, chunk.length, seg.fileOffset);
      cur += seg.bytes;
    }
  }

  /** NBD_CMD_FLUSH: the image and its layers, every context store, every mirror file. */
  async flush(): Promise<void> {
    await this.base.flush?.();
    for (const alt of this.hooks?.altBackends?.values() ?? []) await alt.flush?.();
    for (const r of this.redirects.values()) if (r.mirrorFd !== undefined) fsyncSync(r.mirrorFd);
  }

  close(): void {
    for (const r of this.redirects.values()) closeMirror(r);
    this.base.close?.();
  }
}

/**
 * A host-side file share for a QEMU BlissOS guest, attached as an NBD-backed
 * disk. Pass it as `new BlissVM({ fileShare })` — the VM starts it before boot
 * and injects the drive automatically.
 *
 * It gives you, on a FAT32 image:
 * - **change events**: `create` / `delete` / `modify` per guest file, plus the
 *   raw block-level `access` event ({@link NbdAccessEvent});
 * - **ground-truth / redirect files**: hand every instance identical
 *   authoritative files, or override a file's bytes at runtime, optionally
 *   read-only or mirrored to a host file;
 * - **best-effort app attribution**: which package/process touched a file
 *   (resolved over adb; block I/O alone can't know, so this is a live query).
 *
 * Attribution is **off by default** (zero overhead). Turn it on with
 * `attributeApp: 'live'` (adb query per event) or `'cached'` (a background
 * poller keeps a small path→app index so events stay fast).
 *
 * @example
 * const share = new NbdFileShare({ image: './share.img', size: 64 * 1024 * 1024,
 *   redirects: [{ path: '/policy.json', content: JSON.stringify(policy), readonly: true }],
 *   attributeApp: 'cached', mountPoint: '/mnt/media_rw/share' });
 * share.on('modify', (e) => console.log(e.path, 'changed by', e.process));
 * const vm = new BlissVM({ iso, fileShare: share });
 * // in the guest, mount the exported disk at mountPoint, then read/write files.
 */
export type NbdFileShareEvents = {
  /** A guest file was created (its data clusters appeared on the share). */
  create: [event: FileEvent];
  /** A guest file was deleted. */
  delete: [event: FileEvent];
  /** A guest file's contents or size changed. */
  modify: [event: FileEvent];
  /** Any of create/delete/modify (a convenience firehose). */
  change: [event: FileEvent];
  /** The raw block-level access (read/write/trim) with resolved files. */
  access: [event: NbdAccessEvent];
  /** A server / engine error (e.g. the native engine exited). */
  error: [err: Error];
}

export class NbdFileShare extends TypedEventEmitter<NbdFileShareEvents> {
  private readonly opts: NbdFileShareOptions;
  private readonly log: Logger;
  /** The export's name ({@link driveFile} carries it). */
  readonly exportName: string;
  private readonly watch: boolean;
  private readonly settleMs: number;
  private readonly redirects = new Map<string, ResolvedRedirect>();
  private server?: NbdServer;
  private mapper?: Fat32Mapper;
  private base?: NbdBackend;
  /** The layer stack, when this share was given `layers` (else undefined). */
  private _stack?: LayerStack;
  /** Which engine this share runs on. */
  readonly engine: NbdEngineKind;
  private native?: NbdEngine;
  private nbdPort = 0;
  private nativeSize = 0;
  /** The native engine's last file listing and layer report. */
  private engineFiles: Array<{ path: string; size: number; isDir: boolean }> = [];
  private engineLayers: LayerInfo[] = [];
  /** Path routes to per-context stores (both engines). */
  private routes: Array<{ match: string; prefix: boolean; backendId: string }> = [];
  /**
   * Context layers by id — kept across listen()/close(), so a share that listens again (a VM
   * restart) reopens them and replays its routes, whichever engine it runs on.
   */
  private readonly contextLayers = new Map<string, { path: string; blockSize?: number }>();
  /** The context layers the in-process engine opened (closed with the share). */
  private readonly openContextLayers = new Map<string, CowLayer>();
  /** Bumped by every layer operation and rescan, so a slower refresh never overwrites a newer one. */
  private generation = 0;
  /** Native: the engine's stack epoch now, and the one `prev` was listed at. A listing is only diffed against a snapshot of the same stack. */
  private stackEpoch = 0;
  private prevEpoch = 0;
  private newListenerHook?: (ev: string | symbol) => void;
  /** Where the share is mounted in the guest right now, and how. */
  /** Every guest mount of this share, by mount point (one device can be mounted at many places). */
  private mounts = new Map<string, { dev: string; opts: GuestMountOptions; command: string }>();
  /** Binds made from the mounted share over other guest directories. */
  private binds: Array<{ source: string; target: string }> = [];
  /** Binds taken down, still used to name the app of writes the guest made while they were up. */
  private pastBinds: Array<{ source: string; target: string }> = [];
  private device?: AttributableDevice;
  private prev = new Map<string, { size: number; isDir: boolean }>();
  private dirty = new Set<string>();
  /** Guest-block-level interceptor currently installed (e.g. the active context). */
  private blockInterceptor?: BlockInterceptor;
  /** Alternate backends `redirectTo` can route to (e.g. per-context stores). */
  private readonly contextBackends = new Map<string, NbdBackend>();
  private settleTimer?: ReturnType<typeof setTimeout>;
  private listening = false;
  /** Resolved attribution mode: off, per-event 'live', in-RAM 'cached', or a fn. */
  private readonly attrMode: 'off' | 'live' | 'cached' | AppAttributor;
  /** In-RAM path→app index for `attributeApp: 'cached'` (guest path keys). */
  private readonly attrCache = new Map<string, AppInfo>();
  private attrTimer?: ReturnType<typeof setInterval>;

  constructor(opts: NbdFileShareOptions) {
    super();
    this.opts = opts;
    this.log = resolveLogger(typeof opts.log === 'object' ? opts.log : (opts.log ?? 'info'));
    this.exportName = opts.exportName ?? `share-${randomBytes(8).toString('hex')}`;
    this.watch = opts.watch !== false;
    this.settleMs = opts.settleMs ?? 300;
    this.engine = resolveNbdEngine(opts.engine);
    this.attrMode =
      typeof opts.attributeApp === 'function'
        ? opts.attributeApp
        : opts.attributeApp === true || opts.attributeApp === 'live'
          ? 'live'
          : opts.attributeApp === 'cached'
            ? 'cached'
            : 'off';
    for (const r of opts.redirects ?? []) this.setRedirect(r);
  }

  /** Add or replace a ground-truth / redirect file (safe before or after listen). */
  setRedirect(r: FileRedirect): void {
    if (this.engine === 'cpp' && typeof r.content === 'function') {
      throw new BlissError(`redirect ${r.path}: a content FUNCTION runs in Node on every read, which only the in-process engine can do — pass fixed bytes, or use { engine: "js" }`);
    }
    const toBuf = (v: Buffer | string): Buffer => (typeof v === 'string' ? Buffer.from(v, 'utf8') : v);
    const src = r.content;
    const content: Buffer | ((path: string) => Buffer) =
      typeof src === 'function' ? (path) => toBuf(src(path)) : toBuf(src);
    const old = this.redirects.get(r.path);
    if (old) closeMirror(old);
    // The native engine mirrors in its own process; Node opens the file only when it serves the
    // block path itself (and only while it does — listen() opens, close() closes).
    const mirrorFd = r.mirrorTo && this.engine === 'js' && this.listening ? this.tryOpenMirror(r.path, r.mirrorTo) : undefined;
    const entry: ResolvedRedirect = { content, readonly: !!r.readonly, ...(r.mirrorTo ? { mirrorTo: r.mirrorTo } : {}), mirrorFd };
    this.redirects.set(r.path, entry);
    if (this.native) {
      const native = this.native;
      const apply = (withMirror: boolean) =>
        native.setRedirect(r.path, content as Buffer, { readonly: r.readonly, ...(withMirror && r.mirrorTo ? { mirrorTo: r.mirrorTo } : {}) });
      void apply(true)
        .catch((e) => {
          if (!r.mirrorTo) throw e;
          // Same rule as listen() and the js engine: the ground truth still applies, only the mirror is lost.
          this.log.warn(`redirect ${r.path}: cannot mirror to ${r.mirrorTo} (${(e as Error).message}) — serving it without the mirror`);
          return apply(false);
        })
        .catch((e) => {
          this.log.warn(`redirect ${r.path}: ${(e as Error).message}`);
          // The engine did not take it: do not keep it, or the next listen() would replay a failure.
          if (this.redirects.get(r.path) === entry) this.redirects.delete(r.path);
        });
    }
  }

  /** Open a redirect's mirror file for the js engine; on failure warn and serve without it (as the native engine does). */
  private tryOpenMirror(redirectPath: string, mirrorTo: string): number | undefined {
    try {
      return openMirror(mirrorTo);
    } catch (e) {
      this.log.warn(`redirect ${redirectPath}: cannot mirror to ${mirrorTo} (${(e as Error).message}) — serving it without the mirror`);
      return undefined;
    }
  }

  /** Remove a redirect; the guest then sees the underlying image again. */
  clearRedirect(path: string): void {
    if (this.native) void this.native.clearRedirect(path).catch(() => undefined);
    const r = this.redirects.get(path);
    if (r) closeMirror(r);
    this.redirects.delete(path);
  }

  /** Whether {@link setBlockInterceptor} can be used: only on the in-process engine. */
  get supportsBlockInterceptor(): boolean {
    return this.engine === 'js';
  }

  /**
   * Install (or clear, with `undefined`) the guest-block-level interceptor — a
   * synchronous hook run on every read/write per touched file (see
   * {@link BlockInterceptor}). App contexting swaps this as the active context
   * changes; you can also set it directly.
   */
  setBlockInterceptor(fn?: BlockInterceptor): void {
    if (this.engine === 'cpp' && fn) {
      throw new BlissError(
        'a block interceptor is a synchronous Node callback on every guest operation, which only the in-process engine can run. ' +
          'Route paths to per-context stores with registerContextLayer() + routeContext() (both engines), or use { engine: "js" }.',
      );
    }
    this.blockInterceptor = fn;
  }

  /**
   * Register a backend that a {@link BlockDecision.redirectTo} (or
   * `self.redirectOp(id)`) can route a block op into — e.g. a per-context store,
   * so a context's writes land in its own image and its reads come from it. The
   * backend should mirror the share's image layout/size.
   */
  registerContextBackend(id: string, backend: NbdBackend): void {
    if (this.engine === 'cpp') {
      throw new BlissError('a JS NbdBackend object cannot run in the native engine — use registerContextLayer(id, path) instead, which works on both engines');
    }
    this.contextBackends.set(id, backend);
  }

  /** Remove a previously registered context backend. */
  /**
   * Register a per-context store as a **copy-on-write layer file** (works on both engines), so
   * {@link routeContext} can send paths to it. The layer sits over the base image and holds only
   * what that context wrote.
   */
  async registerContextLayer(id: string, path: string, opts: { blockSize?: number } = {}): Promise<void> {
    const spec = { path, ...(opts.blockSize ? { blockSize: opts.blockSize } : {}) };
    if (this.listening) await this.openContextLayer(id, spec);
    this.contextLayers.set(id, spec);
  }

  /** Open (or reopen) one context layer in whichever engine is serving. */
  private async openContextLayer(id: string, spec: { path: string; blockSize?: number }): Promise<void> {
    if (this.native) {
      await this.native.addBackend(id, spec.path, { kind: 'layer', ...(spec.blockSize ? { blockSize: spec.blockSize } : {}) });
      return;
    }
    if (!this.base) return;
    const base = this.base;
    // Over the stack itself, so the context store sees the base AND the profile layers under it.
    const open = (s: { path: string; blockSize?: number }) => new CowLayer(base, { path: s.path, label: id, ...(s.blockSize ? { blockSize: s.blockSize } : {}) });
    const existing = this.openContextLayers.get(id);
    let layer: CowLayer;
    if (existing && existing.path === spec.path) {
      // The same store again. Already open as asked: nothing to do. Otherwise it has to be let go
      // before it can be reopened (it is locked) — and put back if that fails, so a refused
      // re-register never leaves the context's routes without their store.
      if (!spec.blockSize || spec.blockSize === existing.blockSize) return;
      const was = { path: existing.path, blockSize: existing.blockSize };
      existing.closeSelf();
      try {
        layer = open(spec);
      } catch (e) {
        try {
          const back = open(was);
          this.openContextLayers.set(id, back);
          this.contextBackends.set(id, back);
        } catch {
          /* it cannot be reopened either: its routes now fail loudly, never fall through */
        }
        throw e;
      }
    } else {
      layer = open(spec); // a different store: open it first, then let the old one go
      existing?.closeSelf();
    }
    this.openContextLayers.set(id, layer);
    this.contextBackends.set(id, layer);
  }

  /**
   * Send a file (exact path) or everything under a prefix to a registered context store — the
   * declarative form of `self.redirectOp(id)`, and the one that runs inside the native engine.
   */
  async routeContext(match: { path: string } | { prefix: string }, backendId: string): Promise<void> {
    const prefix = 'prefix' in match;
    const m = prefix ? match.prefix : match.path;
    if (this.native) await this.native.setRoute(match, backendId); // refuses an unknown store: record only what took
    this.routes = this.routes.filter((r) => !(r.match === m && r.prefix === prefix));
    this.routes.push({ match: m, prefix, backendId });
  }

  /** Remove one route, or all of them. */
  async clearContextRoute(match?: { path: string } | { prefix: string }): Promise<void> {
    if (!match) this.routes = [];
    else {
      const prefix = 'prefix' in match;
      const m = prefix ? match.prefix : match.path;
      this.routes = this.routes.filter((r) => !(r.match === m && r.prefix === prefix));
    }
    if (this.native) await this.native.clearRoute(match);
  }

  /** The routes in force, for the in-process engine's interceptor. */
  private routeFor(path: string): string | undefined {
    for (const r of this.routes) if (r.prefix ? path.startsWith(r.match) : path === r.match) return r.backendId;
    return undefined;
  }

  /** The user's interceptor plus the declarative routes, as one function for OverlayBackend. */
  private effectiveInterceptor(): BlockInterceptor | undefined {
    const user = this.blockInterceptor;
    if (!this.routes.length) return user;
    return (op, self) => {
      const d = user?.(op, self);
      if (d?.redirectTo) return d;
      const id = this.routeFor(op.path);
      if (id) return { ...(d ?? {}), redirectTo: id };
      return d;
    };
  }

  /**
   * Remove a context store — a layer from {@link registerContextLayer} or a backend from
   * {@link registerContextBackend} — and every route to it. A layer the share opened is closed (its
   * files stay); a backend you passed in is yours to close.
   */
  unregisterContextBackend(id: string): void {
    if (this.native) void this.native.removeBackend(id).catch(() => undefined);
    this.contextLayers.delete(id);
    this.routes = this.routes.filter((r) => r.backendId !== id);
    this.openContextLayers.get(id)?.closeSelf();
    this.openContextLayers.delete(id);
    this.contextBackends.delete(id);
  }

  /** Bind the started device used for app attribution. */
  bindDevice(device: AttributableDevice): void {
    this.device = device;
    if (this.listening) this.startAttributionPoller();
  }

  /** The QEMU drive to attach (nbd source, raw format). */
  driveSpec(): DriveConfig {
    if (!this.listening) throw new Error('NbdFileShare.driveSpec() called before listen()');
    return { file: this.driveFile(), format: 'raw' };
  }
  /** QEMU `-drive file=` string for this export. */
  driveFile(): string {
    const host = this.opts.host ?? '127.0.0.1';
    return `nbd:${host}:${this.nbdPort}:exportname=${this.exportName}`;
  }

  /** The NBD port, while listening (either engine). */
  get port(): number | undefined {
    return this.listening ? this.nbdPort : undefined;
  }

  /** Exported size in bytes (available after {@link listen}). */
  size(): number | Promise<number> | undefined {
    return this.native ? this.nativeSize : this.base?.size();
  }

  /** List the files currently parsed on the share. */
  list(): Array<{ path: string; size: number; isDir: boolean }> {
    return this.native ? this.engineFiles : (this.mapper?.list() ?? []);
  }

  /**
   * The writable layers stacked over the base image, when this share has any. Push, pop or swap the
   * top one to move a guest between contexts without restarting it — then {@link remountInGuest},
   * because the guest is still holding the previous filesystem's metadata.
   */
  get stack(): LayerStack | undefined {
    return this._stack;
  }

  /** What the layers hold right now, asked of the engine (the native engine's {@link layers} is a cache). */
  async refreshLayers(): Promise<LayerInfo[]> {
    if (this.native) this.engineLayers = await this.native.layers();
    return this.layers();
  }

  /**
   * What is layered over the base image, bottom first. On the native engine this is the engine's
   * last report — refreshed by every layer operation and rescan, and within half a second of writes;
   * {@link refreshLayers} asks for the current one.
   */
  layers(): LayerInfo[] {
    return this.native ? this.engineLayers : (this._stack?.layers() ?? []);
  }

  /**
   * Whether the guest would see an ext4 filesystem here: the superblock magic 0xEF53 at byte 1080
   * of the composed view (base + layers). It reads the files directly, so it works for either
   * engine but only while the share is not listening. A missing image or layer reads as blank.
   * BlissVM uses it to format a share used as /data (`persistData`) on first boot.
   */
  async isExt4(): Promise<boolean> {
    if (this.listening) throw new BlissError('NbdFileShare.isExt4() reads the files directly: call it before listen() or after close()');
    if (!existsSync(this.opts.image)) return false;
    const image = new FileBackend(this.opts.image, { readonly: true, create: false });
    const present = (this.opts.layers ?? []).filter((l) => existsSync(l.path)).map((l) => ({ ...l, readonly: true }));
    let stack: LayerStack;
    try {
      stack = new LayerStack(image, present);
    } catch (e) {
      image.close();
      throw e;
    }
    try {
      const b = await stack.read(1080, 2);
      return b[0] === 0x53 && b[1] === 0xef;
    } finally {
      stack.close();
    }
  }

  /** Start the NBD server. The VM calls this automatically before boot. */
  async listen(): Promise<{ port: number; driveFile: string }> {
    if (this.listening) return { port: this.nbdPort, driveFile: this.driveFile() };
    if (this.engine === 'cpp') return this.listenNative();
    const image = new FileBackend(this.opts.image, {
      size: this.opts.size,
      readonly: this.opts.readonlyBase ?? !!this.opts.layers?.length,
    });
    // The mapper and everything above it parse the COMPOSED view, so a file written into a layer is
    // a file the share can still see, name and attribute. The stack always exists — with no layers
    // it is the base image itself, and a layer can still be pushed later, which is how a base gets
    // SEEDED (boot once with no layers, write the system data, then layer profiles over it).
    try {
      this._stack = new LayerStack(image, this.opts.layers ?? []);
    } catch (e) {
      image.close(); // a locked or unreadable layer must not leave the image open
      throw e;
    }
    this.base = this._stack;
    // FAT32 parsing is optional: a freshly-created/blank or non-FAT image just
    // becomes a raw block share (no file-name events) rather than throwing.
    try {
      this.mapper = Fat32Mapper.fromBackend(this.base);
      this.prev = this.snapshot();
    } catch (e) {
      this.log.warn(`NbdFileShare: image is not FAT32 (${(e as Error).message}) — host file events off; use share.watchInGuest([...]) for guest-side events (e.g. on /data)`);
      this.mapper = undefined;
    }
    try {
      for (const [id, spec] of this.contextLayers) await this.openContextLayer(id, spec);
      for (const [path, r] of this.redirects) if (r.mirrorTo && r.mirrorFd === undefined) r.mirrorFd = this.tryOpenMirror(path, r.mirrorTo);
    } catch (e) {
      this.closeContextLayers();
      for (const r of this.redirects.values()) closeMirror(r);
      this._stack.close();
      this.base = undefined;
      this._stack = undefined;
      throw e;
    }
    const overlay = new OverlayBackend(this.base, this.mapper, this.redirects, {
      interceptor: () => this.effectiveInterceptor(),
      altBackends: this.contextBackends,
    });
    this.server = new NbdServer({
      backend: overlay,
      mapper: this.mapper,
      exportName: this.exportName,
      host: this.opts.host,
      // A free port unless one was asked for: the VM reads the real port from listen(), and a
      // fixed default (NbdServer's 10809) made two shares in one process collide.
      port: this.opts.port ?? 0,
      log: this.log,
    });
    this.server.on('access', (e: NbdAccessEvent) => this.onAccess(e));
    this.server.on('error', (err: Error) => this.emit('error', err));
    try {
      await this.server.listen();
    } catch (e) {
      await this.server.close().catch(() => undefined);
      this.server = undefined;
      this.closeContextLayers();
      this.base = undefined;
      this._stack = undefined;
      throw e;
    }
    this.nbdPort = this.server.port;
    this.listening = true;
    this.startAttributionPoller();
    return { port: this.nbdPort, driveFile: this.driveFile() };
  }

  /** The native engine: everything on the block path runs in its process; Node keeps the control plane. */
  private async listenNative(): Promise<{ port: number; driveFile: string }> {
    if (!NbdEngine.available()) throw new BlissError(NbdEngine.missingMessage());
    const engine = await NbdEngine.start({ log: this.log });
    engine.on('access', (e: NbdAccessEvent) => this.onAccess(e));
    engine.on('exit', () => {
      if (!this.listening) return;
      const err = new BlissError('the native NBD engine exited');
      // 'error' with nobody listening would throw out of the event loop and take the process down.
      if (this.listenerCount('error') > 0) this.emit('error', err);
      else this.log.error(err.message);
    });
    // Before open(): an 'access' listener added while the export is opening must still switch reads on.
    this.newListenerHook = (ev) => {
      if (ev === 'access') engine.setEvents('all').catch(() => undefined);
    };
    this.on('newListener', this.newListenerHook);
    try {
      const opened = await engine.open({
        image: this.opts.image,
        ...(this.opts.size ? { size: this.opts.size } : {}),
        readonlyBase: this.opts.readonlyBase ?? !!this.opts.layers?.length,
        layers: this.opts.layers ?? [],
        exportName: this.exportName,
        host: this.opts.host,
        port: this.opts.port ?? 0,
        events: this.listenerCount('access') > 0 ? 'all' : this.watch ? 'writes' : 'none',
      });
      this.native = engine;
      this.stackEpoch = this.prevEpoch = opened.epoch;
      engine.on('layers', (l: { layers: LayerInfo[]; epoch: number }) => {
        if (l.epoch === this.stackEpoch) this.engineLayers = l.layers; // a report from before a layer move is dropped
      });
      this.nbdPort = opened.nbdPort;
      this.nativeSize = opened.size;
      this.engineFiles = opened.files;
      this.engineLayers = opened.layers;
      if (!opened.fat32) this.log.warn(`NbdFileShare: image is not FAT32 (${opened.fatError ?? 'unparsable'}) — host file events off; use share.watchInGuest([...]) for guest-side events (e.g. on /data)`);
      this.prev = this.snapshot();
      // Everything configured before this listen() — or kept from the last one — goes to the engine now.
      for (const [path, r] of this.redirects) {
        if (typeof r.content === 'function') throw new BlissError(`redirect ${path}: a content function needs { engine: "js" }`);
        try {
          await engine.setRedirect(path, r.content, { readonly: r.readonly, ...(r.mirrorTo ? { mirrorTo: r.mirrorTo } : {}) });
        } catch (e) {
          if (!r.mirrorTo) throw e;
          // The ground truth still applies; only the mirroring is lost, and that is said.
          this.log.warn(`redirect ${path}: cannot mirror to ${r.mirrorTo} (${(e as Error).message}) — serving it without the mirror`);
          await engine.setRedirect(path, r.content, { readonly: r.readonly });
        }
      }
      for (const [id, spec] of this.contextLayers) await this.openContextLayer(id, spec);
      for (const r of this.routes) await engine.setRoute(r.prefix ? { prefix: r.match } : { path: r.match }, r.backendId);
    } catch (e) {
      // Nothing may outlive a failed listen: not the engine process, not its hold on the image.
      this.native = undefined;
      if (this.newListenerHook) this.off('newListener', this.newListenerHook);
      this.newListenerHook = undefined;
      await engine.close().catch(() => undefined);
      throw e;
    }
    this.listening = true;
    this.startAttributionPoller();
    this.log.info(`NbdFileShare (native engine) serving ${this.opts.image} on ${this.driveFile()}`);
    return { port: this.nbdPort, driveFile: this.driveFile() };
  }

  /** The native engine behind this share, when `engine` is `cpp` and it is listening. */
  get nativeEngine(): NbdEngine | undefined {
    return this.native;
  }

  /**
   * Put a different layer on top and make the guest see it — how a device moves between contexts
   * without rebooting.
   *
   * A layer swap alone is not enough: the guest is holding FAT metadata and page cache from the
   * layer that was there, so it would keep writing into a filesystem that is no longer underneath
   * it. This re-parses the composed image on the host and remounts it in the guest. Do it while the
   * apps using the share are stopped (which contexting does anyway).
   */
  async swapLayer(spec: LayerSpec, opts: { remount?: boolean } = {}): Promise<LayerInfo> {
    if (this.native) {
      if (!this.engineLayers.length) throw new BlissError('nothing is stacked to swap — pushLayer() first, or construct the share with { layers: [...] }');
      const native = this.native;
      return this.moveLayers('swap', opts, async () => {
        this.engineLayers = await native.swapLayer(spec);
        return this.engineLayers[this.engineLayers.length - 1]!;
      });
    }
    if (!this._stack) throw new BlissError('the share is not listening yet — call listen() (or start the VM) first');
    if (!this._stack.depth) throw new BlissError('nothing is stacked to swap — pushLayer() first, or construct the share with { layers: [...] }');
    const stack = this._stack;
    return this.moveLayers('swap', opts, async () => stack.swapTop(spec));
  }

  /** Stack another layer on top (writes land in it from now on). */
  async pushLayer(spec: LayerSpec, opts: { remount?: boolean } = {}): Promise<LayerInfo> {
    if (this.native) {
      const native = this.native;
      return this.moveLayers('push', opts, async () => {
        this.engineLayers = await native.pushLayer(spec);
        return this.engineLayers[this.engineLayers.length - 1]!;
      });
    }
    if (!this._stack) throw new BlissError('the share is not listening yet — call listen() (or start the VM) first');
    const stack = this._stack;
    return this.moveLayers('push', opts, async () => stack.push(spec));
  }

  /** Take the top layer off, leaving its file for later. Returns what it held when it came off. */
  async popLayer(opts: { remount?: boolean } = {}): Promise<LayerInfo | undefined> {
    if (this.native) {
      const native = this.native;
      return this.moveLayers('pop', opts, async () => {
        const r = await native.popLayer();
        this.engineLayers = r.layers;
        return r.popped;
      });
    }
    if (!this._stack) return undefined;
    const stack = this._stack;
    return this.moveLayers('pop', opts, async () => stack.pop());
  }

  /**
   * Move layers under a mounted guest safely: the guest syncs and unmounts FIRST — while the layer
   * its dirty pages belong to is still underneath — then the layers move, the host re-parses, and
   * the guest mounts again (binds re-applied). The other way round, the old context's write-back
   * would land in the new context's layer. If the layer operation fails the guest is remounted on
   * what is still there, and the share's view of the stack is refreshed.
   */
  private async moveLayers<T>(what: string, opts: { remount?: boolean }, op: () => Promise<T>): Promise<T> {
    // Every mount of the share comes off (and goes back), not just one: a mount left in place
    // would keep reading the old layer's cached blocks.
    const previous = this.pointsFor().map((at) => ({ at, opts: this.mounts.get(at)?.opts ?? {} }));
    const guest = opts.remount !== false && !!this.device && previous.length > 0;
    const binds = [...this.binds];
    this.generation++;
    if (guest) await this.detachFromGuest(previous.map((p) => p.at), what); // throws, and nothing moves, when the guest still holds it
    try {
      return await op();
    } catch (e) {
      if (this.native) this.engineLayers = await this.native.layers().catch(() => this.engineLayers);
      throw e;
    } finally {
      await this.rescan().catch((e) => this.log.warn(`rescan after layer ${what} failed: ${(e as Error).message}`));
      if (guest) {
        try {
          for (const p of previous) await this.mountInGuest({ ...p.opts, at: p.at });
          for (const b of binds) await this.bindInGuest(b.source, b.target).catch(() => undefined);
        } catch (e) {
          this.log.warn(`remount after layer ${what} failed: ${(e as Error).message}`);
        }
      }
    }
  }

  /**
   * Take the share out of the guest before its layers move — and make sure it is out. A lazy
   * unmount (`umount -l`) only hides a mount: a process with a file open keeps writing through it,
   * into whichever layer is on top by then. So: sync, unmount the binds and the mount itself, and
   * confirm the device is mounted nowhere. If it still is (an app holds a file) or the guest cannot
   * be asked, the binds go back on and the move is refused.
   */
  private async detachFromGuest(ats: string[], what: string): Promise<void> {
    const device = this.device!;
    const dev = [...this.mounts.values()][0]?.dev ?? (await this.findGuestDevice().catch(() => undefined));
    const binds = [...this.binds].reverse();
    const probe = dev ? `grep -c "^${dev} " /proc/mounts` : `grep -cE " (${ats.join('|')}) " /proc/mounts`;
    const script = [
      'sync',
      ...binds.map((b) => `umount ${b.target} 2>/dev/null`),
      ...[...ats].reverse().map((at) => `umount ${at} 2>/dev/null`),
      `echo "left=$(${probe})"`,
    ].join('; ');
    let out: string;
    try {
      out = await device.adb.exec(script);
    } catch (e) {
      throw new BlissError(`cannot take the share out of the guest before the layer ${what} (${(e as Error).message}) — the layers did not move`);
    }
    const left = Number(/left=(\d+)/.exec(out)?.[1] ?? NaN);
    if (left === 0) {
      this.binds = [];
      this.mounts.clear();
      return;
    }
    // Still mounted: put back whatever did come off — the mounts FIRST, since a bind re-made over
    // an unmounted point would show the empty directory underneath — and refuse.
    const still = await device.adb.exec('cat /proc/mounts').catch(() => '');
    for (const at of ats) {
      const m = this.mounts.get(at);
      if (m && !still.includes(` ${at} `)) await device.adb.exec(m.command).catch(() => undefined);
    }
    for (const b of [...binds].reverse()) {
      if (!still.includes(` ${b.target} `)) await device.adb.exec(`mount --bind ${b.source} ${b.target}`).catch(() => undefined);
    }
    throw new BlissError(
      `the share is still mounted in the guest (${Number.isNaN(left) ? 'could not check' : `${left} mount(s) left`}) — stop what is using ${ats.join(', ')} first; the layers did not move`,
    );
  }

  /** Re-parse the composed image and take a fresh snapshot (after the bytes underneath changed). */
  async rescan(): Promise<void> {
    this.generation++;
    if (this.native) {
      const r = await this.native.rescan();
      // Again after the await: a reconcile that started while it ran captured the old snapshot
      // with the new generation, and must not diff the two stacks against each other.
      this.generation++;
      this.stackEpoch = this.prevEpoch = r.epoch;
      this.engineFiles = r.files;
      this.engineLayers = r.layers;
      if (!r.fat32) this.log.warn(`NbdFileShare: composed image is not FAT32 — file events disabled (${r.fatError ?? 'unparsable'})`);
      this.prev = this.snapshot();
      this.dirty.clear();
      return;
    }
    if (!this.base) return;
    try {
      this.mapper = Fat32Mapper.fromBackend(this.base);
      this.prev = this.snapshot();
      this.dirty.clear();
    } catch (e) {
      this.log.warn(`NbdFileShare: composed image is not FAT32 — file events disabled (${(e as Error).message})`);
      this.mapper = undefined;
    }
  }

  /**
   * The guest device node this share is attached as, found by size among the virtio disks. The
   * share is exported as its own disk, so it is the one whose size matches what NBD reports.
   */
  async findGuestDevice(): Promise<string | undefined> {
    if (!this.device) throw new BlissError('no device bound — call bindDevice(vm) or attach the share to a VM');
    const want = await this.size();
    if (!want) return undefined;
    const out = await this.device.adb.exec('for d in /dev/block/vd*; do echo "$d $(blockdev --getsize64 $d 2>/dev/null)"; done').catch(() => '');
    for (const line of out.split('\n')) {
      const [dev, size] = line.trim().split(/\s+/);
      if (dev && size && Number(size) === want) return dev;
    }
    return undefined;
  }

  /**
   * Where and how to mount this share inside the guest. Any path, not a special place: a scratch
   * directory, somewhere under `/data`, or straight over a directory that already exists.
   */
  async mountInGuest(where: string | GuestMountOptions = {}): Promise<string | undefined> {
    const o: GuestMountOptions = typeof where === 'string' ? { at: where } : where;
    const at = o.at ?? this.opts.mountPoint;
    if (!at) throw new BlissError('no mount point — pass one, or set mountPoint in the share options');
    if (!this.device) throw new BlissError('no device bound — call bindDevice(vm) or attach the share to a VM');
    const dev = await this.findGuestDevice();
    if (!dev) return undefined;

    const opts: string[] = [];
    if (o.readonly) opts.push('ro');
    // FAT32 stores no ownership or permissions, so without these the mount belongs to root and an
    // app cannot write a byte to it. This is what makes an arbitrary target — an app's data
    // directory, say — actually usable rather than just occupied.
    if (o.uid !== undefined) opts.push(`uid=${o.uid}`);
    if (o.gid !== undefined) opts.push(`gid=${o.gid}`);
    if (o.fmask !== undefined) opts.push(`fmask=${o.fmask}`);
    if (o.dmask !== undefined) opts.push(`dmask=${o.dmask}`);
    // Likewise SELinux: a vfat mount carries ONE label for everything on it. Copying the label of
    // the directory being replaced is what lets the app that owns it keep working.
    const context = o.context ?? (o.contextFrom ? await this.labelOf(o.contextFrom) : undefined);
    // Quoted: an app's label has categories (s0:c221,c256,…) whose commas would otherwise split
    // into separate, unknown mount options, and the mount fails with EINVAL.
    if (context) opts.push(`context="${context}"`);
    for (const extra of o.options ?? []) opts.push(extra);

    const type = o.type ?? 'vfat';
    // Single-quoted for the guest shell, so the double quotes reach mount intact.
    const flags = opts.length ? ` -o '${opts.join(',')}'` : '';
    const command = `mkdir -p ${at} && mount -t ${type}${flags} ${dev} ${at}`;
    const out = await this.device.adb.exec(`${command} 2>&1; echo rc=$?`);
    if (!/rc=0/.test(out)) {
      // The kernel's only word for "this device is mounted elsewhere with another label" is EINVAL.
      const elsewhere = (await this.device.adb.exec(`grep "^${dev} " /proc/mounts | cut -d' ' -f2`).catch(() => '')).trim();
      const hint = elsewhere
        ? ` (the share is already mounted at ${elsewhere.split('\n').join(', ')}; every mount of one vfat device must use the same owner, masks and label)`
        : '';
      throw new BlissError(`mounting the share at ${at} failed: ${out.replace(/rc=\d+$/, '').trim()}${hint}`);
    }
    // A vfat device carries ONE owner and ONE set of masks: mounted again while it is mounted
    // elsewhere, the kernel silently reuses the first mount's options. Check what it applied.
    if (type === 'vfat') {
      const applied = await this.device.adb.exec(`grep " ${at} " /proc/mounts | tail -1`).catch(() => '');
      const wrong = mismatchedVfatOptions(o, applied);
      if (wrong.length) {
        await this.device.adb.exec(`umount ${at} 2>/dev/null; echo ok`).catch(() => undefined);
        throw new BlissError(
          `the share is already mounted with other options (${wrong.join('; ')}): every mount of one vfat device gets the same owner and masks. Mount it again with the same options, or give apps their own directories with bindInGuest().`,
        );
      }
    }
    this.mounts.delete(at); // re-mounting a point moves it to the end: the newest mount last
    this.mounts.set(at, { dev, opts: o, command });
    this.startAttributionPoller(); // cached attribution needs a mount point to look under
    this.log.info(`share mounted in the guest: ${dev} → ${at}${flags}`);
    return dev;
  }

  /** Where the share is mounted in the guest: every mount point, oldest first. */
  guestMounts(): string[] {
    return [...this.mounts.keys()];
  }

  /** Mount points to look under for this share's files: the configured one first, then the rest. */
  private mountPoints(): string[] {
    return [...new Set([...(this.opts.mountPoint ? [this.opts.mountPoint] : []), ...this.mounts.keys()])];
  }

  /** The SELinux label of a guest path, for reuse as a mount `context=`. */
  async labelOf(path: string): Promise<string | undefined> {
    if (!this.device) return undefined;
    const out = await this.device.adb.exec(`stat -c %C ${path} 2>/dev/null || true`).catch(() => '');
    const label = out.trim();
    return label && label !== '?' ? label : undefined;
  }

  /**
   * Bind a directory of the mounted share over any existing guest directory — how a layered image
   * becomes an app's data directory, or anything else already in place.
   *
   * The share itself has to be mounted somewhere first (`mountInGuest`); this makes part of it
   * appear at `target` as well. Android propagates such a bind into already-running apps' mount
   * namespaces, which is the same mechanism app contexting relies on.
   */
  async bindInGuest(source: string, target: string): Promise<void> {
    if (!this.device) throw new BlissError('no device bound — call bindDevice(vm) or attach the share to a VM');
    const out = await this.device.adb.exec(
      `mkdir -p ${source} ${target} && mount --bind ${source} ${target} 2>&1; echo rc=$?`,
    );
    if (!/rc=0/.test(out)) throw new BlissError(`binding ${source} over ${target} failed: ${out.replace(/rc=\d+$/, '').trim()}`);
    this.binds.push({ source, target });
    this.log.info(`bound ${source} over ${target} in the guest`);
  }

  /** Undo a bind made by {@link bindInGuest} (or all of them). */
  async unbindInGuest(target?: string): Promise<void> {
    if (!this.device) return;
    const targets = target ? [target] : [...this.binds].reverse().map((b) => b.target);
    for (const t of targets) {
      await this.device.adb.exec(`umount ${t} 2>/dev/null || umount -l ${t} 2>/dev/null; echo ok`).catch(() => undefined);
      for (const b of this.binds) if (b.target === t) this.pastBinds = [b, ...this.pastBinds.filter((p) => p.source !== b.source)];
      this.binds = this.binds.filter((b) => b.target !== t);
    }
  }

  /** The mount points an unmount/remount of `at` covers: that one, or every mount of the share. */
  private pointsFor(at?: string): string[] {
    if (at) return [at];
    if (this.mounts.size) return [...this.mounts.keys()];
    return this.opts.mountPoint ? [this.opts.mountPoint] : [];
  }

  /**
   * Unmount the share in the guest: at one mount point, or (no argument) every mount of it. Binds
   * made from under an unmounted point come off first.
   */
  async unmountInGuest(at?: string): Promise<void> {
    if (!this.device) return;
    for (const p of this.pointsFor(at).reverse()) {
      for (const b of [...this.binds].reverse()) if (b.source === p || b.source.startsWith(p + '/')) await this.unbindInGuest(b.target);
      await this.device.adb.exec(`sync; umount ${p} 2>/dev/null || umount -l ${p} 2>/dev/null; echo ok`).catch(() => undefined);
      this.mounts.delete(p);
    }
    if (!at) await this.unbindInGuest(); // and any bind left over, as before
  }

  /**
   * Flush and remount the share in the guest, so it re-reads the filesystem instead of trusting
   * what it cached from the layer that was there before. Mount options and binds are re-applied,
   * at one mount point or (no argument) at every one.
   */
  async remountInGuest(at?: string): Promise<void> {
    if (!this.device) return;
    const points = this.pointsFor(at);
    if (!points.length) return;
    const previous = new Map(points.map((p) => [p, this.mounts.get(p)?.opts] as const));
    const binds = this.binds.filter((b) => !at || b.source === at || b.source.startsWith(at + '/'));
    await this.unmountInGuest(at);
    for (const p of points) await this.mountInGuest({ ...(previous.get(p) ?? {}), at: p });
    for (const b of binds) await this.bindInGuest(b.source, b.target).catch(() => undefined);
  }

  // --- guest-side file watching (for ext4 / non-FAT shares, e.g. /data) -----------------------------

  /** State of a running guest watcher started by {@link watchInGuest}. */
  private guestWatch?: {
    log: string;
    dirs: Set<string>;
    paths: string[];
    poll: ReturnType<typeof setInterval>;
    rescan: ReturnType<typeof setInterval>;
    stopped: boolean;
  };

  /**
   * Emit `create` / `modify` / `delete` {@link FileEvent}s (with `e.process`) for changes the guest
   * makes under `paths`, by running `inotifyd` in the guest. This is how you get file events on an
   * **ext4** share such as `/data`, where the host-side FAT mapper can't name files. Needs the share
   * attached to a VM (so a device is bound) and root.
   *
   * Recursive by default: every existing subdirectory of each path is watched, and new subdirectories
   * are picked up on a periodic rescan (`rescanMs`). Returns a stop function; {@link close} also stops it.
   *
   * `paths` defaults to this share's guest mount points. Watching the whole of `/data` is heavy — pass
   * the subtrees you care about (e.g. `['/data/data/com.example.app']`).
   */
  async watchInGuest(
    paths?: string[],
    opts: { recursive?: boolean; pollMs?: number; rescanMs?: number } = {},
  ): Promise<() => Promise<void>> {
    if (!this.device) throw new BlissError('watchInGuest needs a bound device — attach the share to a VM');
    const targets = paths?.length ? paths : this.guestMounts();
    if (!targets.length) throw new BlissError('watchInGuest: no paths — pass guest paths (e.g. ["/data/data/com.app"]) or mount the share first');
    if (!/inotifyd/.test(await this.device.adb.exec('command -v inotifyd 2>/dev/null || echo no').catch(() => 'no'))) {
      throw new BlissError('watchInGuest needs `inotifyd` in the guest (toybox); this image has none');
    }
    await this.stopGuestWatch();
    const recursive = opts.recursive !== false;
    const log = `/data/local/tmp/.nbdwatch-${randomBytes(6).toString('hex')}.log`;
    const dirs = await this.expandWatchDirs(targets, recursive);
    await this.startInotifyd(log, dirs);
    const state = {
      log,
      dirs,
      paths: targets,
      poll: setInterval(() => void this.drainGuestWatch().catch(() => undefined), opts.pollMs ?? 700),
      rescan: setInterval(() => void this.rescanGuestWatch(recursive).catch(() => undefined), opts.rescanMs ?? 5000),
      stopped: false,
    };
    if (typeof state.poll.unref === 'function') state.poll.unref();
    if (typeof state.rescan.unref === 'function') state.rescan.unref();
    this.guestWatch = state;
    this.log.info(`watching ${dirs.size} guest dir(s) under ${targets.join(', ')} via inotifyd`);
    return () => this.stopGuestWatch();
  }

  /** The set of guest directories to watch: each path, plus its subdirectories when recursive. */
  private async expandWatchDirs(paths: string[], recursive: boolean): Promise<Set<string>> {
    const dirs = new Set<string>();
    for (const p of paths) {
      if (recursive) {
        // Cap the expansion so a huge tree can't blow the command line / watch limit.
        const out = await this.device!.adb.exec(`find ${shq(p)} -type d 2>/dev/null | head -n 4000`).catch(() => '');
        for (const d of out.split('\n').map((s) => s.trim()).filter(Boolean)) dirs.add(d);
      }
      dirs.add(p.replace(/\/$/, ''));
    }
    return dirs;
  }

  /** (Re)start inotifyd watching `dirs`, writing tab-separated `EVENT<TAB>DIR<TAB>FILE` lines to `log`. */
  private async startInotifyd(log: string, dirs: Set<string>): Promise<void> {
    const q = shq(log);
    // inotifyd ABORTS if any single path can't be watched, which would silently watch nothing — so
    // start one inotifyd PER directory (a failed dir only loses that dir). A plain backgrounded
    // subshell survives the adb shell closing here (verified); the log path on the command line lets
    // stopGuestWatch pkill exactly these watchers.
    await this.device!.adb.exec(`pkill -f ${q} 2>/dev/null; : > ${q}; echo ok`);
    // One backgrounded inotifyd per dir, separated by ';' (adjacent `)(` is a shell syntax error).
    const cmds = [...dirs].map((d) => `( inotifyd - ${shq(d)} >> ${q} 2>&1 & )`);
    // Launch in batches to keep the command line sane for large trees.
    for (let i = 0; i < cmds.length; i += 80) {
      await this.device!.adb.exec(`${cmds.slice(i, i + 80).join('; ')}; true`);
    }
  }

  /** Read and clear the inotifyd log, turning each line into a FileEvent. */
  private async drainGuestWatch(): Promise<void> {
    const w = this.guestWatch;
    if (!w || w.stopped || !this.device) return;
    // Copy-then-truncate so events between read and clear are (mostly) not lost.
    const out = await this.device.adb.exec(`T=${shq(w.log + '.r')}; cp ${shq(w.log)} $T 2>/dev/null && : > ${shq(w.log)}; cat $T 2>/dev/null; rm -f $T`).catch(() => '');
    if (!out) return;
    const seen = new Set<string>(); // collapse repeat modifies within a batch
    for (const line of out.split('\n')) {
      const parts = line.split('\t');
      if (parts.length < 2) continue;
      const ev = parts[0]!;
      const dir = parts[1]!;
      const file = parts[2] ?? '';
      const path = file ? `${dir}/${file}` : dir;
      const type = ev.includes('n') ? 'create' : ev.includes('d') || ev.includes('x') ? 'delete' : ev.includes('w') || ev.includes('c') || ev.includes('M') ? 'modify' : undefined;
      if (!type) continue; // ignore opens/accesses ('r','a')
      const key = `${type}:${path}`;
      if (seen.has(key)) continue;
      seen.add(key);
      const fev: FileEvent = { type, path, size: 0, isDir: !file };
      this.attribute(fev, this.appFromGuestPath(path));
      this.emitEvent(fev);
    }
  }

  /** Pick up directories created since the watcher started (inotifyd is not recursive on its own). */
  private async rescanGuestWatch(recursive: boolean): Promise<void> {
    const w = this.guestWatch;
    if (!w || w.stopped || !recursive) return;
    const fresh = await this.expandWatchDirs(w.paths, true);
    let grew = false;
    for (const d of fresh) if (!w.dirs.has(d)) { w.dirs.add(d); grew = true; }
    if (grew) await this.startInotifyd(w.log, w.dirs); // re-arm with the larger set
  }

  /** The app a guest `/data/(data|user/N|user_de/N)/<pkg>/…` path belongs to. */
  private appFromGuestPath(path: string): AppInfo | undefined {
    const m = /^\/data\/(?:data|user\/\d+|user_de\/\d+)\/([^/]+)/.exec(path);
    return m ? { package: m[1] } : undefined;
  }

  /** Stop the guest watcher (kill inotifyd, clear timers, remove the log). */
  private async stopGuestWatch(): Promise<void> {
    const w = this.guestWatch;
    if (!w) return;
    w.stopped = true;
    clearInterval(w.poll);
    clearInterval(w.rescan);
    this.guestWatch = undefined;
    if (this.device) await this.device.adb.exec(`pkill -f ${shq(w.log)} 2>/dev/null; rm -f ${shq(w.log)} ${shq(w.log + '.r')}; echo ok`).catch(() => undefined);
  }

  /** Stop the server and release resources. The VM calls this on stop/kill. */
  async close(): Promise<void> {
    await this.stopGuestWatch().catch(() => undefined);
    if (this.settleTimer) clearTimeout(this.settleTimer);
    if (this.attrTimer) clearInterval(this.attrTimer);
    // Unset, not just stopped: listen() after close() (a VM restart) starts them again only if they are.
    this.settleTimer = undefined;
    this.attrTimer = undefined;
    this.generation++;
    if (this.newListenerHook) this.off('newListener', this.newListenerHook);
    this.newListenerHook = undefined;
    if (this.native) {
      this.listening = false;
      await this.native.close().catch(() => undefined);
      this.native = undefined;
      return;
    }
    this.listening = false;
    await this.server?.close().catch(() => undefined);
    // The server closed its overlay, which closed the stack, the image and the mirror files. Closing
    // `this.base` again here used to double-close the image's fd — harmless alone, but under
    // vitest's thread pool that fd number may already belong to another file, whose owner then saw EBADF.
    if (!this.server) this.base?.close?.();
    for (const r of this.redirects.values()) closeMirror(r);
    this.closeContextLayers();
    this.server = undefined;
    this.base = undefined;
    this._stack = undefined;
  }

  /** Close the context layers this share opened (their files, and their registrations, stay). */
  private closeContextLayers(): void {
    for (const [id, layer] of this.openContextLayers) {
      layer.closeSelf();
      this.contextBackends.delete(id);
    }
    this.openContextLayers.clear();
  }

  // --- change detection -----------------------------------------------------

  private snapshot(): Map<string, { size: number; isDir: boolean }> {
    const m = new Map<string, { size: number; isDir: boolean }>();
    for (const f of this.list()) m.set(f.path, { size: f.size, isDir: f.isDir });
    return m;
  }

  private onAccess(e: NbdAccessEvent): void {
    this.emit('access', e);
    if (!this.watch || (!this.mapper && !this.native) || e.command === 'read') return;
    for (const f of e.files) {
      if (f.path !== '<metadata>' && f.path !== '<free>') this.dirty.add(f.path);
    }
    if (this.settleTimer) clearTimeout(this.settleTimer);
    this.settleTimer = setTimeout(() => this.reconcile(), this.settleMs);
  }

  /** Re-parse the FS and emit create/delete/modify vs the last snapshot. */
  private reconcile(): void {
    if (this.native) {
      // The mapper lives in the engine: ask it for a fresh listing, then diff exactly as below.
      const prevSnap = this.prev;
      const dirty = this.dirty;
      this.dirty = new Set();
      const gen = this.generation;
      const epoch = this.prevEpoch;
      void this.native
        .rescan()
        .then((r) => {
          // A listing of a different stack than the snapshot's — the engine's epoch says so, whatever
          // order the replies and the layer operation's own rescan happened to resolve in — is dropped.
          if (r.epoch !== epoch) return;
          // A layer push/pop/swap (or an explicit rescan) happened meanwhile: the listing belongs to
          // a different stack, and diffing it against the old snapshot would invent creates and deletes.
          if (gen !== this.generation || prevSnap !== this.prev) return;
          this.engineFiles = r.files;
          this.engineLayers = r.layers;
          const next = this.snapshot();
          for (const ev of computeFileEvents(prevSnap, next, dirty)) this.dispatch(ev);
          this.prev = next;
        })
        .catch((e) => this.log.debug(`NbdFileShare refresh failed: ${(e as Error).message}`));
      return;
    }
    if (!this.mapper) return;
    try {
      this.mapper.refresh();
    } catch (e) {
      this.log.debug(`NbdFileShare refresh failed: ${(e as Error).message}`);
      return;
    }
    const next = this.snapshot();
    const dirty = this.dirty;
    this.dirty = new Set();
    for (const ev of computeFileEvents(this.prev, next, dirty)) this.dispatch(ev);
    this.prev = next;
  }

  private emitEvent(ev: FileEvent): void {
    this.emit(ev.type, ev);
    this.emit('change', ev);
  }

  /**
   * The app whose data directory a share path is, when it lies under a directory bound over
   * /data/data/<pkg>, /data/user/<n>/<pkg> or /data/user_de/<n>/<pkg> (see bindInGuest). Exact and
   * free, and it catches short-lived writes that a poller never sees open.
   */
  appFromBinds(path: string): AppInfo | undefined {
    const points = this.mountPoints();
    if (!points.length) return undefined;
    // Current binds first; then ones already taken down, since the guest's write-back of what an
    // app wrote while bound can reach the host after the unbind.
    for (const b of [...this.binds, ...this.pastBinds]) {
      const mount = points.find((p) => b.source.startsWith(p + '/'));
      if (!mount) continue;
      const rel = b.source.slice(mount.length);
      if (path !== rel && !path.startsWith(rel + '/')) continue;
      const m = /^\/data\/(?:data|user\/\d+|user_de\/\d+)\/([^/]+)\/?$/.exec(b.target);
      if (m) return { package: m[1] };
    }
    return undefined;
  }

  /** Attach a resolved AppInfo to an event as both `process` (the new API) and `app` (deprecated). */
  private attribute(ev: FileEvent, app: AppInfo | undefined): void {
    if (!app) return;
    ev.app = app;
    ev.process = toProcess(app);
  }

  private dispatch(ev: FileEvent): void {
    // A file in a bound app data directory belongs to that app: no lookup needed, in any mode.
    const bound = this.appFromBinds(ev.path);
    if (bound) {
      this.attribute(ev, bound);
      return this.emitEvent(ev);
    }
    // Off / cached → emit synchronously with no adb on the hot path. (Cached does
    // an instant RAM lookup; a background poller keeps the index fresh.)
    if (this.attrMode === 'off') return this.emitEvent(ev);
    if (this.attrMode === 'cached') {
      this.attribute(ev, this.attrCache.get((this.mountPoints()[0] ?? '') + ev.path));
      return this.emitEvent(ev);
    }
    // Live / custom → enrich asynchronously; never let a failure drop the event.
    const resolver: AppAttributor = typeof this.attrMode === 'function' ? this.attrMode : (p, s) => defaultAttributor(p, s);
    resolver(ev.path, this)
      .then((app) => this.attribute(ev, app))
      .catch(() => undefined)
      .finally(() => this.emitEvent(ev));
  }

  // --- cached attribution (background poller → in-RAM index) -----------------

  private startAttributionPoller(): void {
    if (this.attrMode !== 'cached' || this.attrTimer || !this.device || !this.mountPoints().length) return;
    const pollMs = this.opts.attributionPollMs ?? 1500;
    const tick = () => {
      this.refreshAttrCache().catch((e) => this.log.debug(`attr poll failed: ${(e as Error).message}`));
    };
    tick();
    this.attrTimer = setInterval(tick, pollMs);
    if (typeof this.attrTimer.unref === 'function') this.attrTimer.unref();
  }

  /** One sweep: list open files under the mount and index guestPath → app. */
  private async refreshAttrCache(): Promise<void> {
    const dev = this.device;
    const points = this.mountPoints();
    if (!dev || !points.length) return;
    const byPid = parseOpenFiles(await dev.adb.exec(openFilesCommand(points, this.binds), 10_000).catch(() => ''), points, this.binds);
    if (byPid.size === 0) {
      this.attrCache.clear();
      return;
    }
    // Resolve each pid → package + uid once, then index every path it holds open.
    const next = new Map<string, AppInfo>();
    for (const [pid, paths] of byPid) {
      const app = await resolvePidApp(dev.adb, pid);
      for (const p of paths) next.set(p, app);
    }
    this.attrCache.clear();
    for (const [k, v] of next) this.attrCache.set(k, v);
  }

  /** Exposed for the default attributor / custom resolvers. */
  get boundDevice(): AttributableDevice | undefined {
    return this.device;
  }
  get guestMountPoint(): string | undefined {
    return this.opts.mountPoint;
  }
}

type FileMeta = { size: number; isDir: boolean };

/**
 * Diff two filesystem snapshots into create/delete/modify events. A path present
 * only in `next` is a create; only in `prev` a delete; a size change — or a path
 * in `dirty` (its data clusters were written this burst) — is a modify. Pure and
 * exported so the change-detection logic is unit-testable without an NBD client.
 */
export function computeFileEvents(
  prev: Map<string, FileMeta>,
  next: Map<string, FileMeta>,
  dirty: Set<string> = new Set(),
): FileEvent[] {
  const events: FileEvent[] = [];
  for (const [path, meta] of next) {
    const before = prev.get(path);
    if (!before) events.push({ type: 'create', path, size: meta.size, isDir: meta.isDir });
    else if (before.size !== meta.size || dirty.has(path))
      events.push({ type: 'modify', path, size: meta.size, isDir: meta.isDir });
  }
  for (const [path, meta] of prev) {
    if (!next.has(path)) events.push({ type: 'delete', path, size: meta.size, isDir: meta.isDir });
  }
  return events;
}

/**
 * Best-effort attribution over adb: try `lsof`/`fuser` on the mounted path to
 * find an owning pid, resolve its package via `/proc/<pid>/cmdline`; fall back
 * to the current foreground package. Returns undefined if nothing resolves.
 */
export async function defaultAttributor(path: string, share: NbdFileShare): Promise<AppInfo | undefined> {
  const dev = share.boundDevice;
  if (!dev) return undefined;
  const adb = dev.adb;
  const guestPath = (share.guestMountPoint ?? '') + path;

  const pidFrom = (out: string): number | undefined => {
    for (const line of out.split('\n')) {
      const m = line.match(/\b(\d{2,})\b/);
      if (m) return Number(m[1]);
    }
    return undefined;
  };

  let pid: number | undefined;
  if (share.guestMountPoint) {
    const lsof = await adb.exec(`lsof '${guestPath}' 2>/dev/null | tail -n +2`, 8000).catch(() => '');
    pid = pidFrom(lsof);
    if (pid === undefined) {
      const fuser = await adb.exec(`fuser '${guestPath}' 2>/dev/null`, 8000).catch(() => '');
      pid = pidFrom(fuser);
    }
  }

  if (pid !== undefined) return resolvePidApp(adb, pid);

  // Fallback: whoever is in the foreground is the most likely writer.
  const fg = await adb
    .exec(`dumpsys activity activities 2>/dev/null | grep -m1 mResumedActivity`, 8000)
    .catch(() => '');
  const m = fg.match(/\s([a-zA-Z][\w.]+)\/[\w.$]+/);
  return m ? { package: m[1] } : undefined;
}

/**
 * Resolve a guest pid to its package, raw process name and uid, in one adb round trip: cmdline for
 * the name (a package id has no path; a native process is a path), and `/proc/<pid>` ownership for
 * the uid (which is what makes `process.isSystem()` / `.getUID()` work).
 */
export async function resolvePidApp(adb: AttributableDevice['adb'], pid: number): Promise<AppInfo> {
  const out = await adb.exec(`cat /proc/${pid}/cmdline 2>/dev/null | tr '\\0' ' '; echo; stat -c %u /proc/${pid} 2>/dev/null`, 8000).catch(() => '');
  const lines = out.split('\n');
  const proc = (lines[0] ?? '').trim().split(' ')[0] || undefined;
  const uidStr = (lines[1] ?? '').trim();
  const uid = /^\d+$/.test(uidStr) ? Number(uidStr) : undefined;
  const pkg = proc && /^[a-zA-Z][\w.]*\.[\w.]+$/.test(proc) && !proc.startsWith('/') ? proc : undefined;
  return { pid, ...(uid !== undefined ? { uid } : {}), ...(pkg ? { package: pkg } : {}), ...(proc ? { process: proc } : {}) };
}
