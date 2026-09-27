import { createServer, type Server, type Socket } from 'node:net';
import { openSync, closeSync, readSync, writeSync, fstatSync, fsyncSync, existsSync, ftruncateSync, mkdirSync } from 'node:fs';
import { dirname } from 'node:path';
import { TypedEventEmitter } from '../events';
import { randomBytes } from 'node:crypto';
import { BlissError } from '../errors';
import type { Logger } from '../types';
import { resolveLogger } from '../logger';
import { NbdEngine, resolveNbdEngine, type NbdEngineKind } from './engine';
import {
  ByteReader,
  writeAll,
  IHAVEOPT,
  NBDMAGIC,
  REP_MAGIC,
  REQUEST_MAGIC,
  SIMPLE_REPLY_MAGIC,
  NBD_FLAG_FIXED_NEWSTYLE,
  NBD_FLAG_HAS_FLAGS,
  NBD_FLAG_READ_ONLY,
  NBD_FLAG_SEND_FLUSH,
  NBD_FLAG_SEND_TRIM,
  NBD_OPT_EXPORT_NAME,
  NBD_OPT_ABORT,
  NBD_OPT_LIST,
  NBD_OPT_INFO,
  NBD_OPT_GO,
  NBD_REP_ACK,
  NBD_REP_SERVER,
  NBD_REP_INFO,
  NBD_REP_ERR_UNSUP,
  NBD_REP_ERR_POLICY,
  NBD_REP_ERR_INVALID,
  NBD_REP_ERR_UNKNOWN,
  NBD_INFO_EXPORT,
  NBD_CMD_READ,
  NBD_CMD_WRITE,
  NBD_CMD_DISC,
  NBD_CMD_FLUSH,
  NBD_CMD_TRIM,
  NBD_EINVAL,
  NBD_EIO,
  NBD_EPERM,
  NBD_MAX_REQUEST,
  NBD_MAX_OPTION,
  NBD_MAX_CONNECTIONS,
} from './protocol';

/** A pluggable block backend for {@link NbdServer}. Sizes/offsets are byte counts. */
export interface NbdBackend {
  /** Total exported size in bytes. */
  size(): number | Promise<number>;
  /** Read `length` bytes at `offset`. Must return exactly `length` bytes. */
  read(offset: number, length: number): Buffer | Promise<Buffer>;
  /** Write `data` at `offset`. */
  write(offset: number, data: Buffer): void | Promise<void>;
  /** Flush pending writes (optional). */
  flush?(): void | Promise<void>;
  /** Discard/trim a range (optional). */
  trim?(offset: number, length: number): void | Promise<void>;
  /** Whether the export is read-only. */
  readonly?: boolean;
  /** Release resources. */
  close?(): void | Promise<void>;
}

/** A file-backed {@link NbdBackend} using positional reads/writes. */
export class FileBackend implements NbdBackend {
  private fd: number;
  private _size: number;
  readonly readonly: boolean;

  constructor(path: string, opts: { size?: number; readonly?: boolean; create?: boolean } = {}) {
    this.readonly = !!opts.readonly;
    if (!existsSync(path)) {
      if (opts.create === false) throw new BlissError(`Backing file not found: ${path}`);
      // A missing image is created blank only when a size says how big; without one it would be a
      // 0-byte disk a guest cannot boot or mount. The native engine applies the same rule.
      if (!opts.size) throw new BlissError(`backing file not found: ${path} (give a size to create a blank one)`);
      mkdirSync(dirname(path), { recursive: true });
      const fd = openSync(path, 'w');
      if (opts.size) ftruncateSync(fd, opts.size);
      closeSync(fd);
    }
    this.fd = openSync(path, this.readonly ? 'r' : 'r+');
    const st = fstatSync(this.fd);
    this._size = opts.size ?? st.size;
    if (opts.size && st.size < opts.size && !this.readonly) ftruncateSync(this.fd, opts.size);
  }

  size(): number {
    return this._size;
  }

  read(offset: number, length: number): Buffer {
    const buf = Buffer.alloc(length); // zero-filled (holes read as zeros)
    let done = 0;
    while (done < length) {
      const n = readSync(this.fd, buf, done, length - done, offset + done);
      if (n <= 0) break; // EOF → remainder stays zero
      done += n;
    }
    return buf;
  }

  write(offset: number, data: Buffer): void {
    if (this.readonly) throw new BlissError('read-only backend');
    let done = 0;
    while (done < data.length) {
      done += writeSync(this.fd, data, done, data.length - done, offset + done);
    }
  }

  /** NBD_CMD_FLUSH: what the guest has written must survive a power cut once this returns. */
  flush(): void {
    if (this.readonly || this.closed) return;
    fsyncSync(this.fd);
  }

  private closed = false;
  /**
   * Idempotent on purpose: fd numbers are recycled the instant they close, so a second
   * `closeSync` here would close whatever file some other code — another test thread, another
   * share — has just been handed, and its next read comes back EBADF.
   */
  close(): void {
    if (this.closed) return;
    this.closed = true;
    try {
      closeSync(this.fd);
    } catch {
      /* already closed */
    }
  }
}

/** A file (path or offset range) touched by a block request, via a mapper. */
export interface TouchedFile {
  path: string;
  fileOffset: number;
  bytes: number;
}

/** Maps a byte offset in the image to a guest filesystem file. */
export interface SectorMapper {
  mapRange(offset: number, length: number): TouchedFile[];
}

/**
 * A {@link SectorMapper} that also enumerates the files it found and can re-parse the filesystem —
 * what {@link NbdFileShare} needs to raise create/delete/modify events. Implemented by both the
 * FAT32, ext4 and F2FS mappers, so the share works the same way on any of them.
 */
export interface FileMapper extends SectorMapper {
  /** List the files currently parsed (path + size + isDir). */
  list(): Array<{ path: string; size: number; isDir: boolean }>;
  /** Re-parse the filesystem after the guest changed it. */
  refresh(): void;
  /** The byte extents (offset/length pairs) a file occupies in the image. */
  extents(path: string): Array<{ offset: number; length: number }>;
  /**
   * The file's owner uid / gid and permission bits, read from the inode — image-derived attribution
   * (whose file this is), available on ext4/f2fs. Absent on filesystems with no per-file owner (FAT32).
   */
  owner?(path: string): { uid: number; gid: number; mode: number } | undefined;
  /**
   * The guest path of an inode number, when the mapper indexes by inode (ext4, f2fs). Lets a
   * kernel-reported source that names inodes rather than paths (ftrace tracepoints) be correlated
   * back to a file. Absent on filesystems whose mapper has no inode index (FAT32).
   */
  pathForInode?(ino: number): string | undefined;
}

export interface NbdAccessEvent {
  command: 'read' | 'write' | 'trim';
  offset: number;
  length: number;
  /** Resolved guest files, if a mapper is attached. */
  files: TouchedFile[];
}

export interface NbdServerOptions {
  /** The block backend. Either this or `file` is required. */
  backend?: NbdBackend;
  /** Convenience: back the export with a file (uses {@link FileBackend}). */
  file?: string;
  /** Export size when creating a file backend, e.g. 100 * 1024 * 1024. */
  size?: number;
  /**
   * Export name QEMU connects to (`nbd://host:port/EXPORT`). Default: a random name. Besides the
   * port it is all a client needs, so the server answers to it alone (no "" alias, no listing) —
   * pick one only when something other than this process has to know it.
   */
  exportName?: string;
  host?: string; // default 127.0.0.1
  port?: number; // default 10809
  /** Optional sector→file mapper; enables `access` events with resolved files. */
  mapper?: SectorMapper;
  /** Called on every read/write (raw block level). */
  onRead?: (offset: number, length: number) => void;
  onWrite?: (offset: number, data: Buffer) => void;
  /**
   * Which engine serves the export — see {@link NbdEngine}. `cpp` (the default) runs the block
   * path in the native engine process; `js` runs it here, on the event loop. A JS `backend`,
   * `mapper`, `onRead` or `onWrite` can only run in-process, so giving one selects `js`.
   */
  engine?: NbdEngineKind;
  log?: Logger | 'silent' | 'error' | 'warn' | 'info' | 'debug';
}

/**
 * A QEMU-compatible NBD server (fixed newstyle). Attach a guest disk to it with
 * `nbd:HOST:PORT:exportname=NAME` (or `nbd://HOST:PORT/NAME`), and intercept
 * every block read/write — optionally resolved to guest **file names** via a
 * {@link SectorMapper} (see `Fat32Mapper`, `Ext4Mapper` and `F2fsMapper`).
 *
 * Emits `access` ({@link NbdAccessEvent}), `connection`, and `error`.
 *
 * @example
 * const nbd = new NbdServer({ file: './shared.img', size: 64 * 1024 * 1024, exportName: 'data' });
 * const { port } = await nbd.listen();
 * nbd.on('access', (e) => console.log(e.command, e.files.map(f => f.path)));
 * // BlissVM drive: { file: `nbd:127.0.0.1:${port}:exportname=data`, format: 'raw' }
 */
export type NbdServerEvents = {
  /** A guest block read / write / trim (with resolved files when a mapper is attached). */
  access: [event: NbdAccessEvent];
  /** A guest connected; the argument is its remote address. */
  connection: [remote: string | undefined];
  /** A server-level error. */
  error: [err: Error];
}

export class NbdServer extends TypedEventEmitter<NbdServerEvents> {
  private server?: Server;
  /** Guest connections being served, so close() can end them rather than wait on them. */
  private readonly sockets = new Set<Socket>();
  private readonly backend: NbdBackend;
  /** Which engine this server runs on. */
  readonly engine: NbdEngineKind;
  private native?: NbdEngine;
  private nativeSize = 0;
  private readonly file?: string;
  private readonly fileSize?: number;
  /** The export's name ({@link driveFile} and {@link url} carry it). */
  readonly exportName: string;
  private readonly host: string;
  private _port: number;
  private readonly mapper?: SectorMapper;
  private readonly log: Logger;
  private readonly onRead?: (offset: number, length: number) => void;
  private readonly onWrite?: (offset: number, data: Buffer) => void;
  /** Whether the caller chose the port (the native engine otherwise takes a free one). */
  private readonly portGiven: boolean;

  constructor(opts: NbdServerOptions) {
    super();
    if (!opts.backend && !opts.file) throw new BlissError('NbdServer requires `backend` or `file`');
    const inProcessOnly = !!(opts.backend || opts.mapper || opts.onRead || opts.onWrite);
    const wanted = resolveNbdEngine(opts.engine);
    this.engine = inProcessOnly ? 'js' : wanted;
    this.file = opts.file;
    this.fileSize = opts.size;
    // The in-process engine opens the file now (its tests read the backend synchronously); the
    // native engine opens it in its own process at listen().
    this.backend = opts.backend ?? (this.engine === 'js' ? new FileBackend(opts.file!, { size: opts.size }) : (undefined as unknown as NbdBackend));
    this.exportName = opts.exportName ?? `export-${randomBytes(8).toString('hex')}`;
    this.host = opts.host ?? '127.0.0.1';
    this._port = opts.port ?? 10809;
    this.portGiven = opts.port !== undefined;
    this.mapper = opts.mapper;
    this.onRead = opts.onRead;
    this.onWrite = opts.onWrite;
    this.log = resolveLogger(typeof opts.log === 'object' ? opts.log : (opts.log ?? 'info'));
    if (inProcessOnly && wanted === 'cpp' && opts.engine !== 'js') {
      this.log.debug('NbdServer: a JS backend/mapper/hook was given, which only the in-process engine can run — using engine "js"');
    }
  }

  get port(): number {
    return this._port;
  }

  /** `nbd://host:port/export` URL (for `qemu-img`, etc.). */
  url(): string {
    return `nbd://${this.host}:${this._port}/${this.exportName}`;
  }

  /** Exported size in bytes (of the backend). */
  size(): number | Promise<number> {
    return this.engine === 'cpp' ? this.nativeSize : this.backend.size();
  }

  /** QEMU `-drive file=` string for this export. */
  driveFile(): string {
    return `nbd:${this.host}:${this._port}:exportname=${this.exportName}`;
  }

  async listen(): Promise<{ host: string; port: number }> {
    if (this.engine === 'cpp') return this.listenNative();
    return new Promise((resolve, reject) => {
      const server = createServer((sock) => this.handle(sock));
      server.maxConnections = NBD_MAX_CONNECTIONS; // each can hold a 32 MiB request
      server.on('error', reject);
      server.listen(this._port, this.host, () => {
        const addr = server.address();
        if (addr && typeof addr === 'object') this._port = addr.port;
        this.server = server;
        this.log.info(`NBD server listening on ${this.url()}`);
        resolve({ host: this.host, port: this._port });
      });
    });
  }

  /** The native engine: spawn it, open the export there, and relay its access events. */
  private async listenNative(): Promise<{ host: string; port: number }> {
    if (!NbdEngine.available()) throw new BlissError(NbdEngine.missingMessage());
    const engine = await NbdEngine.start({ log: this.log });
    engine.on('access', (e: NbdAccessEvent) => this.emit('access', e));
    engine.on('connection', (c: { state: string; remote: string }) => {
      if (c.state === 'open') this.emit('connection', c.remote);
    });
    // Before open(): a listener added while the export is opening must still switch reads on.
    const onListener = (ev: string | symbol): void => {
      if (ev === 'access') engine.setEvents('all').catch(() => undefined);
    };
    this.on('newListener', onListener);
    let opened: Awaited<ReturnType<NbdEngine['open']>>;
    try {
      opened = await engine.open({
        image: this.file!,
        ...(this.fileSize ? { size: this.fileSize } : {}),
        readonlyBase: false,
        exportName: this.exportName,
        host: this.host,
        // The JS engine's 10809 default is not the native one's: without an explicit port it takes a free one.
        port: this.portGiven ? this._port : 0,
        events: this.listenerCount('access') > 0 ? 'all' : 'none',
      });
    } catch (e) {
      // Nothing may outlive a failed open: not the engine process, not its hold on the image.
      this.off('newListener', onListener);
      await engine.close();
      throw e;
    }
    this.native = engine;
    this.nativeSize = opened.size;
    this._port = opened.nbdPort;
    this.log.info(`NBD server (native engine) listening on ${this.url()}`);
    return { host: this.host, port: this._port };
  }

  /** The native engine behind this server, when `engine` is `cpp` and it is listening. */
  get nativeEngine(): NbdEngine | undefined {
    return this.native;
  }

  async close(): Promise<void> {
    if (this.native) {
      await this.native.close();
      this.native = undefined;
      return;
    }
    // server.close() only stops accepting; it waits for every open connection to end, which a
    // connected guest never does on its own.
    const closed = new Promise<void>((resolve) => (this.server ? this.server.close(() => resolve()) : resolve()));
    for (const s of this.sockets) s.destroy();
    await closed;
    await this.backend?.close?.();
  }

  private async handle(sock: Socket): Promise<void> {
    this.sockets.add(sock);
    sock.on('close', () => this.sockets.delete(sock));
    sock.on('error', (e) => this.log.debug(`NBD client error: ${e.message}`));
    this.emit('connection', sock.remoteAddress);
    const reader = new ByteReader(sock);
    try {
      await this.negotiate(sock, reader);
      await this.transmit(sock, reader);
    } catch (err) {
      this.log.debug(`NBD session ended: ${(err as Error).message}`);
    } finally {
      sock.destroy();
    }
  }

  private async transmissionFlags(): Promise<number> {
    let f = NBD_FLAG_HAS_FLAGS | NBD_FLAG_SEND_FLUSH | NBD_FLAG_SEND_TRIM;
    if (this.backend.readonly) f |= NBD_FLAG_READ_ONLY;
    return f;
  }

  // --- Fixed newstyle negotiation ------------------------------------------

  private async negotiate(sock: Socket, reader: ByteReader): Promise<void> {
    // Server greeting: NBDMAGIC + IHAVEOPT + handshake flags (fixed newstyle).
    const greeting = Buffer.alloc(18);
    greeting.writeBigUInt64BE(NBDMAGIC, 0);
    greeting.writeBigUInt64BE(IHAVEOPT, 8);
    greeting.writeUInt16BE(NBD_FLAG_FIXED_NEWSTYLE, 16);
    await writeAll(sock, greeting);
    this.log.debug('NBD greeting sent');

    const cf = await reader.read(4); // client flags (uint32) — we don't require NO_ZEROES
    this.log.debug(`NBD client flags ${cf.readUInt32BE(0).toString(16)}`);

    // Option haggling.
    for (;;) {
      const optMagic = (await reader.read(8)).readBigUInt64BE(0);
      if (optMagic !== IHAVEOPT) throw new BlissError('bad option magic');
      const head = await reader.read(8);
      const opt = head.readUInt32BE(0);
      const len = head.readUInt32BE(4);
      // No real option is this large; buffering whatever a client claims would let one connection
      // hold gigabytes of Node's memory.
      if (len > NBD_MAX_OPTION) throw new BlissError(`option ${opt} claims ${len} bytes`);
      const data = len > 0 ? await reader.read(len) : Buffer.alloc(0);
      this.log.debug(`NBD option ${opt} (len ${len})`);

      if (opt === NBD_OPT_EXPORT_NAME) {
        // This option has no error reply: a name that is not ours ends the connection.
        const asked = data.toString('utf8');
        if (!this.nameOk(asked)) throw new BlissError(`client asked for export "${asked}", not "${this.exportName}"`);
        // Reply is the raw export info; transmission starts next.
        const size = await this.backend.size();
        const info = Buffer.alloc(10 + 124);
        info.writeBigUInt64BE(BigInt(size), 0);
        info.writeUInt16BE(await this.transmissionFlags(), 8);
        await writeAll(sock, info);
        this.log.info(`NBD export "${this.exportName}" (${size} bytes) ready`);
        return;
      } else if (opt === NBD_OPT_INFO || opt === NBD_OPT_GO) {
        const name = this.requestedName(data);
        if (name === undefined) {
          await this.optReply(sock, opt, NBD_REP_ERR_INVALID, Buffer.alloc(0));
          continue;
        }
        if (!this.nameOk(name)) {
          await this.optReply(sock, opt, NBD_REP_ERR_UNKNOWN, Buffer.from(`no export named '${name}' (this server exports '${this.exportName}')`));
          continue;
        }
        await this.replyInfo(sock, opt, data);
        if (opt === NBD_OPT_GO) return; // enter transmission
      } else if (opt === NBD_OPT_LIST) {
        // The name is the capability: it is not handed out.
        await this.optReply(sock, opt, NBD_REP_ERR_POLICY, Buffer.from('exports are not listed'));
      } else if (opt === NBD_OPT_ABORT) {
        await this.optReply(sock, opt, NBD_REP_ACK, Buffer.alloc(0));
        throw new BlissError('client aborted negotiation');
      } else {
        await this.optReply(sock, opt, NBD_REP_ERR_UNSUP, Buffer.alloc(0));
      }
    }
  }

  /** The export answers to its own name only (see {@link NbdServerOptions.exportName}). */
  private nameOk(name: string): boolean {
    return name === this.exportName;
  }

  /** The export name in an INFO/GO option, or undefined when the option is malformed. */
  private requestedName(data: Buffer): string | undefined {
    if (data.length < 6) return undefined;
    const nl = data.readUInt32BE(0);
    if (nl + 6 > data.length) return undefined;
    const nreq = data.readUInt16BE(4 + nl);
    if (4 + nl + 2 + 2 * nreq !== data.length) return undefined;
    return data.subarray(4, 4 + nl).toString('utf8');
  }

  private async replyInfo(sock: Socket, opt: number, _data: Buffer): Promise<void> {
    const size = await this.backend.size();
    const info = Buffer.alloc(2 + 8 + 2);
    info.writeUInt16BE(NBD_INFO_EXPORT, 0);
    info.writeBigUInt64BE(BigInt(size), 2);
    info.writeUInt16BE(await this.transmissionFlags(), 10);
    await this.optReply(sock, opt, NBD_REP_INFO, info);
    await this.optReply(sock, opt, NBD_REP_ACK, Buffer.alloc(0));
  }

  private optReply(sock: Socket, opt: number, replyType: number, data: Buffer): Promise<void> {
    const head = Buffer.alloc(20);
    head.writeBigUInt64BE(REP_MAGIC, 0);
    head.writeUInt32BE(opt, 8);
    head.writeUInt32BE(replyType >>> 0, 12);
    head.writeUInt32BE(data.length, 16);
    return writeAll(sock, data.length ? Buffer.concat([head, data]) : head);
  }

  // --- Transmission --------------------------------------------------------

  private async transmit(sock: Socket, reader: ByteReader): Promise<void> {
    for (;;) {
      const req = await reader.read(28);
      if (req.readUInt32BE(0) !== REQUEST_MAGIC) throw new BlissError('bad request magic');
      const type = req.readUInt16BE(6);
      const handle = req.subarray(8, 16); // echo verbatim
      const rawOffset = req.readBigUInt64BE(16);
      const length = req.readUInt32BE(24);
      // Refuse what lies outside the export — an offset with its top bit set included — before it
      // becomes a Number, and anything larger than a request can be.
      const size = BigInt(await this.backend.size());
      // The 32 MiB cap is for requests that carry data; a TRIM carries none (QEMU sends up to 2 GiB).
      const fits = rawOffset <= size && BigInt(length) <= size - rawOffset;
      const inRange = fits && length <= NBD_MAX_REQUEST;
      const offset = Number(rawOffset);

      if (type === NBD_CMD_DISC) {
        this.log.debug('NBD client disconnected');
        return;
      } else if (type === NBD_CMD_READ) {
        if (!inRange) {
          await this.simpleReply(sock, handle, NBD_EINVAL);
          continue;
        }
        this.onRead?.(offset, length);
        this.emitAccess('read', offset, length);
        let data: Buffer;
        try {
          data = await this.backend.read(offset, length);
        } catch (err) {
          await this.simpleReply(sock, handle, NBD_EIO);
          this.log.warn(`NBD read failed @${offset}: ${(err as Error).message}`);
          continue;
        }
        await this.simpleReply(sock, handle, 0, data);
      } else if (type === NBD_CMD_WRITE) {
        if (length > NBD_MAX_REQUEST) throw new BlissError(`write of ${length} bytes is larger than any request can be`);
        const data = await reader.read(length);
        if (!inRange || this.backend.readonly) {
          await this.simpleReply(sock, handle, !inRange ? NBD_EINVAL : NBD_EPERM);
          continue;
        }
        this.onWrite?.(offset, data);
        this.emitAccess('write', offset, length);
        try {
          await this.backend.write(offset, data);
          await this.simpleReply(sock, handle, 0);
        } catch (err) {
          await this.simpleReply(sock, handle, NBD_EIO);
          this.log.warn(`NBD write failed @${offset}: ${(err as Error).message}`);
        }
      } else if (type === NBD_CMD_FLUSH) {
        // A flush that did not reach the disk must not be acknowledged as one that did.
        let err = 0;
        try {
          await this.backend.flush?.();
        } catch (e) {
          err = NBD_EIO;
          this.log.warn(`NBD flush failed: ${(e as Error).message}`);
        }
        await this.simpleReply(sock, handle, err);
      } else if (type === NBD_CMD_TRIM) {
        if (!fits || this.backend.readonly) {
          await this.simpleReply(sock, handle, !fits ? NBD_EINVAL : NBD_EPERM);
          continue;
        }
        this.emitAccess('trim', offset, length);
        await this.backend.trim?.(offset, length);
        await this.simpleReply(sock, handle, 0);
      } else {
        await this.simpleReply(sock, handle, NBD_EINVAL);
      }
    }
  }

  private emitAccess(command: NbdAccessEvent['command'], offset: number, length: number): void {
    if (this.listenerCount('access') === 0) return;
    const files = this.mapper ? this.mapper.mapRange(offset, length) : [];
    this.emit('access', { command, offset, length, files } satisfies NbdAccessEvent);
  }

  private simpleReply(sock: Socket, handle: Buffer, error: number, data?: Buffer): Promise<void> {
    const head = Buffer.alloc(16);
    head.writeUInt32BE(SIMPLE_REPLY_MAGIC, 0);
    head.writeUInt32BE(error >>> 0, 4);
    handle.copy(head, 8);
    return writeAll(sock, data && data.length ? Buffer.concat([head, data]) : head);
  }
}
