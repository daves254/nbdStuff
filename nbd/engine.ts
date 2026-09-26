/**
 * The native NBD engine (`engine-cpp/nbd_engine.cpp`) from Node's side.
 *
 * Which engine serves a share:
 *
 * | `engine` | What runs the guest's block path |
 * |---|---|
 * | `'cpp'` (default) | the native engine: a separate process, one thread per guest connection, positional I/O, the layer stack and the FAT32 mapper all in C++ — Node's event loop never sees a block |
 * | `'js'` | the in-process TypeScript server (`NbdServer` / `OverlayBackend`), synchronous on the event loop |
 *
 * The native engine is the default because it is the one that scales. The JS engine is kept for
 * two things it alone can do — a synchronous {@link BlockInterceptor} callback per operation, and
 * a redirect whose content is a *function* — and for machines with no C++ compiler. It is chosen
 * only by asking: `engine: 'js'` on the share/server, or `NBD_ENGINE=js` in the environment. When
 * the native binary is missing and nothing asked for JS, the share refuses to start and says how
 * to build it, rather than quietly running the slow path.
 *
 * Node keeps the control plane over loopback TCP with the same framing as the throughX engine
 * (`u32 headerLen | JSON | u32 binLen | bin`): open the export, push/pop/swap layers, set
 * redirects and routes, and receive the asynchronous stream of access events.
 *
 * Only this process can drive the engine it starts: a random token goes to the child in its
 * environment (`NBD_ENGINE_TOKEN`), the first frame proves it, and the engine stops accepting
 * control connections once one has. Without that, any local process could connect to the control
 * port and read or write the guest's disk, or have the engine open host files.
 */
import { spawn, type ChildProcess } from 'node:child_process';
import { randomBytes } from 'node:crypto';
import { existsSync } from 'node:fs';
import { createConnection, type Socket } from 'node:net';
import { dirname, join, resolve } from 'node:path';
import { TypedEventEmitter } from '../events';
import { BlissError } from '../errors';
import type { Logger } from '../types';
import type { NbdAccessEvent, TouchedFile } from './server';
import type { LayerInfo, LayerSpec } from './layers';

export type NbdEngineKind = 'cpp' | 'js';

/** Which engine a share/server should use, from an explicit choice, the environment, or the default. */
export function resolveNbdEngine(explicit?: NbdEngineKind): NbdEngineKind {
  if (explicit) return explicit;
  const env = process.env.NBD_ENGINE?.trim().toLowerCase();
  if (env === 'js' || env === 'cpp') return env;
  return 'cpp';
}

export interface NbdEngineStartOptions {
  /** The native binary (default: `engine-cpp/build/nbd-engine[.exe]` of this package). */
  binary?: string;
  /** Attach to an engine already listening on this control port instead of spawning one. */
  port?: number;
  /** The token that engine was started with (`NBD_ENGINE_TOKEN`), when attaching with `port`. */
  token?: string;
  log?: Logger;
}

export interface OpenExportOptions {
  image: string;
  size?: number;
  readonlyBase?: boolean;
  layers?: LayerSpec[];
  exportName?: string;
  host?: string;
  /** NBD port (0 = pick a free one). */
  port?: number;
  /** Which operations produce access events: writes only (default), all, or none. */
  events?: 'writes' | 'all' | 'none';
}

export interface OpenedExport {
  nbdPort: number;
  /** The stack's epoch: bumped by every push / pop / swap. */
  epoch: number;
  size: number;
  /** Whether the composed image parsed as FAT32 (kept for compatibility; prefer {@link fs}). */
  fat32: boolean;
  /** Which filesystem the engine's mapper parsed the composed image as, if any (FAT32 or ext4). */
  fs?: 'fat32' | 'ext4' | 'f2fs';
  /** Why the image could not be mapped (when {@link fs} is absent). */
  fatError?: string;
  layers: LayerInfo[];
  files: Array<{ path: string; size: number; isDir: boolean }>;
}

export interface EngineStats {
  reads: number;
  writes: number;
  readBytes: number;
  writeBytes: number;
  eventsDropped: number;
  /** NBD flushes that could not make everything durable (each answered the guest with EIO). */
  flushFailures: number;
  connections: number;
  threads: number;
}

/** A guest connection opening or closing on the export. */
export interface NbdConnectionEvent {
  state: 'open' | 'close';
  /** `host:port` of the client. */
  remote: string;
}

type Reply = { header: Record<string, unknown>; bin: Buffer };

/**
 * A running native NBD engine. Emits `access` ({@link NbdAccessEvent}) for every operation the
 * engine reports, `connection` ({@link NbdConnectionEvent}) as guests connect and leave, and `exit`
 * when the process goes away.
 */
export type NbdEngineEvents = {
  access: [event: NbdAccessEvent];
  connection: [event: NbdConnectionEvent];
  /** The engine's layer stack changed / was refreshed (with the stack epoch). */
  layers: [event: { layers: LayerInfo[]; epoch: number }];
  /** The engine process exited. */
  exit: [event: { code: number | null; signal: NodeJS.Signals | null }];
}

export class NbdEngine extends TypedEventEmitter<NbdEngineEvents> {
  private buf: Buffer = Buffer.alloc(0);
  private nextId = 1;
  private readonly pending = new Map<number, { resolve: (r: Reply) => void; reject: (e: Error) => void }>();
  private closed = false;

  private constructor(
    private readonly socket: Socket,
    private readonly child: ChildProcess | null,
    readonly controlPort: number,
    private readonly log?: Logger,
  ) {
    super();
    socket.on('data', (d) => this.onData(d));
    socket.on('close', () => this.onGone(new BlissError('nbd engine connection closed')));
    socket.on('error', (e) => this.onGone(e));
    child?.on('exit', (code, signal) => {
      this.log?.debug(`nbd engine exited (code ${code}, signal ${signal})`);
      this.emit('exit', { code, signal });
    });
  }

  /** This package's root (where engine-cpp/ and scripts/ ship). */
  private static packageRoot(): string {
    return resolve(dirname(__filename), '..', '..');
  }

  /** The native binary, if it has been built. */
  static defaultBinary(): string | undefined {
    const root = NbdEngine.packageRoot();
    for (const p of [join(root, 'engine-cpp', 'build', 'nbd-engine.exe'), join(root, 'engine-cpp', 'build', 'nbd-engine')]) {
      if (existsSync(p)) return p;
    }
    return undefined;
  }

  /** Whether the native engine can be used on this machine (the binary exists). */
  static available(): boolean {
    return !!NbdEngine.defaultBinary();
  }

  /** The message given when the native engine was wanted but is not there. */
  static missingMessage(): string {
    // A command that works from a checkout and from an installed copy alike: the sources ship with
    // the package, and its install step builds them when a compiler is there.
    const script = join(NbdEngine.packageRoot(), 'scripts', 'build-engine-cpp.js');
    return (
      `the native NBD engine is not built (engine-cpp/build/nbd-engine). Build it with \`node "${script}" --target nbd\` ` +
      '(needs g++, clang++ or MSVC), or ask for the slower in-process engine explicitly with { engine: "js" } or NBD_ENGINE=js.'
    );
  }

  static async start(opts: NbdEngineStartOptions = {}): Promise<NbdEngine> {
    const log = opts.log;
    let child: ChildProcess | null = null;
    let port = opts.port ?? 0;
    let token = opts.token;
    if (!port) {
      const bin = opts.binary ?? NbdEngine.defaultBinary();
      if (!bin) throw new BlissError(NbdEngine.missingMessage());
      token = randomBytes(24).toString('hex');
      // `--owner`: the engine leaves when this process is gone, so a hard-killed Node can never leave
      // an engine behind holding the base image open. The token rides in the environment, not argv,
      // where every local user could read it.
      child = spawn(bin, ['--port', '0', '--owner', String(process.pid)], {
        stdio: ['ignore', 'pipe', 'pipe'],
        windowsHide: true,
        env: { ...process.env, NBD_ENGINE_TOKEN: token },
      });
      child.stderr?.on('data', (d) => log?.debug(`[nbd-engine] ${String(d).trim()}`));
      port = await new Promise<number>((res, rej) => {
        let out = '';
        const timer = setTimeout(() => rej(new BlissError('nbd engine did not start within 15 s')), 15_000);
        child!.stdout?.on('data', (d) => {
          out += String(d);
          const m = /READY (\d+)/.exec(out);
          if (m) {
            clearTimeout(timer);
            res(Number(m[1]));
          }
        });
        child!.on('exit', (code) => {
          clearTimeout(timer);
          rej(new BlissError(`nbd engine exited with code ${code} before READY`));
        });
        child!.on('error', (e) => {
          clearTimeout(timer);
          rej(e);
        });
      });
    }
    const socket = await new Promise<Socket>((res, rej) => {
      const s = createConnection({ host: '127.0.0.1', port }, () => res(s));
      s.once('error', rej);
    }).catch((e: Error) => {
      child?.kill();
      throw e;
    });
    socket.setNoDelay(true);
    const engine = new NbdEngine(socket, child, port, log);
    try {
      if (token) await engine.request('hello', { token });
    } catch (e) {
      await engine.close();
      throw new BlissError(`the nbd engine refused this process: ${(e as Error).message}`);
    }
    const pong = await engine.request('ping');
    log?.debug(`nbd engine ready on :${port} (${String(pong.header.engine)}, ${String(pong.header.threads)} threads)`);
    return engine;
  }

  private onGone(e: Error): void {
    if (this.closed) return;
    this.closed = true;
    for (const p of this.pending.values()) p.reject(e);
    this.pending.clear();
  }

  private onData(d: Buffer): void {
    this.buf = this.buf.length ? Buffer.concat([this.buf, d]) : d;
    for (;;) {
      if (this.buf.length < 4) return;
      const hl = this.buf.readUInt32BE(0);
      if (this.buf.length < 4 + hl + 4) return;
      const bl = this.buf.readUInt32BE(4 + hl);
      if (this.buf.length < 8 + hl + bl) return;
      const header = JSON.parse(this.buf.subarray(4, 4 + hl).toString('utf8')) as Record<string, unknown>;
      const bin = Buffer.from(this.buf.subarray(8 + hl, 8 + hl + bl));
      this.buf = this.buf.subarray(8 + hl + bl);
      if (header.event === 'layers') {
        // What the layers hold now (sent after writes, at most twice a second).
        this.emit('layers', { layers: layersOf(header), epoch: Number(header.epoch ?? 0) });
        continue;
      }
      if (header.event === 'connection') {
        for (const c of (header.list as Array<Record<string, unknown>>) ?? []) {
          this.emit('connection', { state: c.state === 'close' ? 'close' : 'open', remote: String(c.remote ?? '') } satisfies NbdConnectionEvent);
        }
        continue;
      }
      if (header.event === 'access') {
        // Unsolicited: a batch of guest operations, already resolved to file names by the engine.
        for (const ev of (header.batch as Array<Record<string, unknown>>) ?? []) {
          this.emit('access', {
            command: ev.command as NbdAccessEvent['command'],
            offset: Number(ev.offset),
            length: Number(ev.length),
            files: ((ev.files as Array<Record<string, unknown>>) ?? []).map(
              (f): TouchedFile => ({ path: String(f.path), fileOffset: Number(f.fileOffset), bytes: Number(f.bytes) }),
            ),
          } satisfies NbdAccessEvent);
        }
        continue;
      }
      const id = Number(header.id);
      const p = this.pending.get(id);
      if (!p) continue;
      this.pending.delete(id);
      if (header.ok === false) p.reject(new BlissError(String(header.error ?? 'nbd engine error')));
      else p.resolve({ header, bin });
    }
  }

  /** Send one request and wait for its reply. */
  request(op: string, params: Record<string, unknown> = {}, bin: Buffer = Buffer.alloc(0)): Promise<Reply> {
    if (this.closed) return Promise.reject(new BlissError('nbd engine is closed'));
    const id = this.nextId++;
    // Params first: a parameter can never shadow the frame's own id or op.
    const header = Buffer.from(JSON.stringify({ ...params, id, op }), 'utf8');
    const frame = Buffer.alloc(8 + header.length + bin.length);
    frame.writeUInt32BE(header.length, 0);
    header.copy(frame, 4);
    frame.writeUInt32BE(bin.length, 4 + header.length);
    bin.copy(frame, 8 + header.length);
    return new Promise((resolve, reject) => {
      this.pending.set(id, { resolve, reject });
      this.socket.write(frame);
    });
  }

  // --- the export --------------------------------------------------------

  async open(opts: OpenExportOptions): Promise<OpenedExport> {
    const r = await this.request('open', {
      image: opts.image,
      ...(opts.size ? { size: opts.size } : {}),
      ...(opts.readonlyBase !== undefined ? { readonlyBase: opts.readonlyBase } : {}),
      layers: (opts.layers ?? []).map(layerParams),
      exportName: opts.exportName ?? 'share',
      host: opts.host ?? '127.0.0.1',
      port: opts.port ?? 0,
      events: opts.events ?? 'writes',
    });
    return {
      nbdPort: Number(r.header.nbdPort),
      epoch: Number(r.header.epoch ?? 0),
      size: Number(r.header.size),
      fat32: !!r.header.fat32,
      ...(fsOf(r.header) ? { fs: fsOf(r.header) } : {}),
      ...(r.header.fatError ? { fatError: String(r.header.fatError) } : {}),
      layers: layersOf(r.header),
      files: filesOf(r.header),
    };
  }

  async pushLayer(spec: LayerSpec): Promise<LayerInfo[]> {
    return layersOf((await this.request('layer.push', layerParams(spec))).header);
  }
  /** Take the top layer off. `popped` is what it held — counted by the engine as it closed it. */
  async popLayer(): Promise<{ layers: LayerInfo[]; popped?: LayerInfo }> {
    const h = (await this.request('layer.pop')).header;
    const popped = h.popped && typeof h.popped === 'object' ? layersOf({ layers: [h.popped] })[0] : undefined;
    return { layers: layersOf(h), ...(popped ? { popped } : {}) };
  }
  async swapLayer(spec: LayerSpec): Promise<LayerInfo[]> {
    return layersOf((await this.request('layer.swap', layerParams(spec))).header);
  }
  async layers(): Promise<LayerInfo[]> {
    return layersOf((await this.request('layers')).header);
  }

  /** Re-parse the composed image and return its files (empty when it is neither FAT32 nor ext4). */
  async rescan(): Promise<{ fat32: boolean; fs?: 'fat32' | 'ext4' | 'f2fs'; files: Array<{ path: string; size: number; isDir: boolean }>; layers: LayerInfo[]; epoch: number; fatError?: string }> {
    const r = await this.request('rescan');
    return {
      fat32: !!r.header.fat32,
      ...(fsOf(r.header) ? { fs: fsOf(r.header) } : {}),
      files: filesOf(r.header),
      layers: layersOf(r.header),
      epoch: Number(r.header.epoch ?? 0),
      ...(r.header.fatError ? { fatError: String(r.header.fatError) } : {}),
    };
  }
  async list(): Promise<Array<{ path: string; size: number; isDir: boolean }>> {
    return filesOf((await this.request('list')).header);
  }

  /** Pin a file's bytes (ground truth), optionally dropping guest writes and/or mirroring them to a host file. */
  async setRedirect(path: string, content: Buffer, opts: { readonly?: boolean; mirrorTo?: string } = {}): Promise<void> {
    await this.request('redirect.set', { path, readonly: !!opts.readonly, ...(opts.mirrorTo ? { mirrorTo: opts.mirrorTo } : {}) }, content);
  }
  async clearRedirect(path: string): Promise<void> {
    await this.request('redirect.clear', { path });
  }

  /** Register a store other paths can be routed to: a copy-on-write layer over the base, or a raw file. */
  async addBackend(id: string, path: string, opts: { kind?: 'layer' | 'file'; size?: number; blockSize?: number } = {}): Promise<void> {
    await this.request('backend.add', { name: id, path, kind: opts.kind ?? 'layer', ...(opts.size ? { size: opts.size } : {}), ...(opts.blockSize ? { blockSize: opts.blockSize } : {}) });
  }
  async removeBackend(id: string): Promise<void> {
    await this.request('backend.remove', { name: id });
  }
  /** Route a file (exact path) or everything under a prefix to a registered backend. */
  async setRoute(match: { path: string } | { prefix: string }, backend: string): Promise<void> {
    await this.request('route.set', { ...match, backend });
  }
  async clearRoute(match?: { path: string } | { prefix: string }): Promise<void> {
    await this.request('route.clear', match ?? {});
  }

  async setEvents(mode: 'writes' | 'all' | 'none'): Promise<void> {
    await this.request('events', { mode });
  }

  async stats(): Promise<EngineStats> {
    const h = (await this.request('stats')).header;
    return {
      reads: Number(h.reads),
      writes: Number(h.writes),
      readBytes: Number(h.readBytes),
      writeBytes: Number(h.writeBytes),
      eventsDropped: Number(h.eventsDropped),
      flushFailures: Number(h.flushFailures ?? 0),
      connections: Number(h.connections),
      threads: Number(h.threads),
    };
  }

  /** Close the export and the engine. Requests still in flight are rejected, never left hanging. */
  async close(): Promise<void> {
    if (this.closed) return;
    await this.request('close').catch(() => undefined);
    this.onGone(new BlissError('nbd engine is closed'));
    this.socket.destroy();
    if (this.child && this.child.exitCode === null) {
      await new Promise<void>((res) => {
        const t = setTimeout(() => {
          this.child?.kill();
          res();
        }, 1500);
        this.child?.once('exit', () => {
          clearTimeout(t);
          res();
        });
      });
    }
  }
}

function layerParams(l: LayerSpec): Record<string, unknown> {
  // No blockSize means "the layer's own": the engine reads it from the layer's index.
  return { path: l.path, ...(l.label ? { label: l.label } : {}), ...(l.blockSize ? { blockSize: l.blockSize } : {}), ...(l.readonly ? { readonly: true } : {}) };
}
function layersOf(h: Record<string, unknown>): LayerInfo[] {
  return ((h.layers as Array<Record<string, unknown>>) ?? []).map((l) => ({
    path: String(l.path),
    ...(l.label ? { label: String(l.label) } : {}),
    blocks: Number(l.blocks),
    bytes: Number(l.bytes),
    ...(l.blockSize ? { blockSize: Number(l.blockSize) } : {}),
    readonly: !!l.readonly,
  }));
}
function filesOf(h: Record<string, unknown>): Array<{ path: string; size: number; isDir: boolean }> {
  return ((h.files as Array<Record<string, unknown>>) ?? []).map((f) => ({ path: String(f.path), size: Number(f.size), isDir: !!f.isDir }));
}
/** The filesystem the engine's mapper recognised, from the new `fs` field or the legacy `fat32` flag. */
function fsOf(h: Record<string, unknown>): 'fat32' | 'ext4' | 'f2fs' | undefined {
  const fs = typeof h.fs === 'string' ? h.fs : '';
  if (fs === 'fat32' || fs === 'ext4' || fs === 'f2fs') return fs;
  return h.fat32 ? 'fat32' : undefined;
}
