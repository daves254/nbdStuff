/**
 * **Layered block storage** — one base image, a writable layer per profile, another per context.
 *
 * ```
 *  guest  →  NBD  →  redirects + interceptor  →  LayerStack
 *                                                  ├── context layer   (writes land here)
 *                                                  ├── profile layer
 *                                                  └── base image      (read-only, shared)
 * ```
 *
 * Reads walk the stack from the top down: the first layer that owns a block answers, and anything
 * nobody has written falls through to the base. Writes always go to the top layer. So every profile
 * shares one system image byte-for-byte, keeps its own divergence, and can be thrown away by
 * deleting a file.
 *
 * ### Why on the host, and not as a QEMU overlay
 *
 * QEMU can already do this: `nbdDisks: [{ source: share, overlay: 'profile.qcow2' }]` layers a
 * qcow2 over the NBD export. But then the guest's writes stop at the overlay and **never reach the
 * share**, so the file-change events, the redirects, the app attribution and the block interceptor
 * all go blind the moment a block is written — which is precisely when they matter. Layering inside
 * the backend keeps the share above the layers, so all of that keeps working, and a layer can be
 * swapped without restarting the VM.
 *
 * ### Storage format
 *
 * Each layer is a pair of files: `<path>` holds the blocks it owns, packed in allocation order, and
 * `<path>.map` records which virtual block lives in which slot. The map is a 16-byte header
 * (`NBDLAYR1`, the block size, 4 reserved bytes) and then one 12-byte entry per slot — entry `i` at
 * `16 + 12·i`: block, slot (= `i`), and a check (`block ^ slot ^ 0x4C415952`), little-endian. An
 * entry counts only when its check matches AND its slot is its position, so a torn tail or a
 * zero-filled gap is never taken for "block 0 lives in slot 0". A new block's entry is written only
 * once the block itself is durable — at the guest's FLUSH, on close, and every 1024 new blocks —
 * because nothing orders write-back between two files: written together, the index could reach
 * the disk first and, after a power cut, point at a slot holding nothing. A crash before the
 * commit loses those blocks (unflushed writes, which NBD allows to be lost) and nothing else. A layer file is exactly as large as what was written to it, not as large
 * as the image, which matters because a sparse file is not portable (writing at a high offset in a
 * fresh file on NTFS allocates the gap rather than leaving a hole). The native engine
 * (`engine-cpp/nbd_engine.cpp`) reads and writes the same files.
 *
 * A writable layer is locked while open (`<path>.lock`): two writers would hand out the same slots
 * and overwrite each other's blocks. On Windows the lock is the file held open exclusively, which
 * the OS releases the moment its process ends — so a lock is never judged stale from a pid that
 * may belong to someone else by now, and the native engine is kept out the same way. Node cannot
 * `flock` on POSIX, so there the lock is the owner's pid, and a stale one is taken over under an
 * exclusive takeover token so that two openers cannot both take it.
 */
import { closeSync, constants, existsSync, fstatSync, fsyncSync, ftruncateSync, mkdirSync, openSync, readFileSync, readSync, renameSync, statSync, unlinkSync, writeSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { BlissError } from '../errors';
import type { NbdBackend } from './server';

/** Bytes per copy-on-write block. Small enough that a partial write copies little. */
export const DEFAULT_BLOCK_SIZE = 4096;

const MAP_MAGIC = Buffer.from('NBDLAYR1', 'latin1');
const MAP_HEADER = 16;
/** One index entry: block u32, slot u32, check u32. */
const ENTRY = 12;
const CHECK_SALT = 0x4c415952;
const MAX_BLOCKS = 0xffffffff;
/** New blocks whose entries may wait in memory before they are committed. */
const COMMIT_EVERY = 1024;
const WIN = process.platform === 'win32';
/** libuv's exclusive-open flag on Windows: nobody else can open the file until it is closed. */
const UV_FS_O_EXLOCK = 0x10000000;

/** A writable layer in a {@link LayerStack}. */
export interface LayerSpec {
  /** Where the layer's blocks live. Created if missing; `<path>.map` sits beside it. */
  path: string;
  /** A name for reports, e.g. the profile or context id. */
  label?: string;
  /**
   * Bytes per block, for a NEW layer (default 4096). An existing layer records its own; asking for
   * a different one is an error rather than a misread of every block.
   */
  blockSize?: number;
  /** Refuse writes to this layer (a shared template others stack on). */
  readonly?: boolean;
}

/** What a layer currently holds. */
export interface LayerInfo {
  path: string;
  label?: string;
  /** Blocks this layer owns (i.e. has diverged from everything below it). */
  blocks: number;
  bytes: number;
  /** The layer's block size. */
  blockSize?: number;
  readonly: boolean;
}

function pidAlive(pid: number): boolean {
  try {
    process.kill(pid, 0);
    return true;
  } catch (e) {
    return (e as NodeJS.ErrnoException).code === 'EPERM'; // it exists; it just is not ours
  }
}

function sleepSync(ms: number): void {
  Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, ms);
}

/** A lock this process holds on a layer. */
interface HeldLock {
  path: string;
  key: string;
  /** Windows: the exclusively-open handle that IS the lock. */
  fd?: number;
}

/** Locks held by this process, so a second open here gets a plain answer instead of a stale-lock guess. */
const heldLocks = new Set<string>();

function lockOwner(lockPath: string): number {
  try {
    return Number.parseInt(readFileSync(lockPath, 'utf8'), 10) || 0;
  } catch {
    return 0; // gone, or held exclusively (Windows) — then there is no pid to read
  }
}

function busy(layerPath: string, lockPath: string): BlissError {
  const owner = lockOwner(lockPath);
  return new BlissError(`layer ${layerPath} is in use by ${owner > 0 ? `process ${owner}` : 'another process'} (${lockPath})`);
}

/** Take `<layer>.lock` for this process, or say who has it. */
function lockLayer(layerPath: string): HeldLock {
  const path = `${layerPath}.lock`;
  const key = WIN ? resolve(path).toLowerCase() : resolve(path);
  if (heldLocks.has(key)) throw new BlissError(`layer ${layerPath} is already open in this process`);
  if (WIN) {
    let fd: number;
    try {
      fd = openSync(path, constants.O_RDWR | constants.O_CREAT | UV_FS_O_EXLOCK);
    } catch (e) {
      const code = (e as NodeJS.ErrnoException).code;
      if (code === 'EBUSY' || code === 'EPERM' || code === 'EACCES') throw busy(layerPath, path);
      throw new BlissError(`cannot lock layer ${layerPath}: ${(e as Error).message}`);
    }
    try {
      ftruncateSync(fd, 0);
      writeSync(fd, `${process.pid}
`, 0); // only for the other side's error message
    } catch {
      /* the lock is the open handle, not its contents */
    }
    heldLocks.add(key);
    return { path, key, fd };
  }
  for (let attempt = 0; attempt < 40; attempt++) {
    try {
      const fd = openSync(path, 'wx');
      try {
        writeSync(fd, `${process.pid}
`);
      } finally {
        closeSync(fd);
      }
      heldLocks.add(key);
      return { path, key };
    } catch (e) {
      if ((e as NodeJS.ErrnoException).code !== 'EEXIST') throw new BlissError(`cannot lock layer ${layerPath}: ${(e as Error).message}`);
    }
    const owner = lockOwner(path);
    if (owner > 0 && owner !== process.pid && pidAlive(owner)) throw busy(layerPath, path);
    if (owner === 0 && attempt < 4) {
      sleepSync(25); // being written right now
      continue;
    }
    // Stale. Only the holder of the takeover token may remove it — otherwise two openers could each
    // remove the other's fresh lock and both believe they hold the layer.
    const token = `${path}.takeover`;
    let tfd: number;
    try {
      tfd = openSync(token, 'wx');
    } catch {
      try {
        if (Date.now() - statSync(token).mtimeMs > 10_000) unlinkSync(token); // its holder died mid-takeover
      } catch {
        /* gone */
      }
      sleepSync(25);
      continue;
    }
    try {
      const again = lockOwner(path);
      if (!(again > 0 && again !== process.pid && pidAlive(again))) {
        try {
          unlinkSync(path);
        } catch {
          /* already gone */
        }
      }
    } finally {
      closeSync(tfd);
      try {
        unlinkSync(token);
      } catch {
        /* already gone */
      }
    }
  }
  throw new BlissError(`could not lock layer ${layerPath} (${path})`);
}

function unlockLayer(lock: HeldLock): void {
  heldLocks.delete(lock.key);
  if (lock.fd !== undefined) {
    try {
      closeSync(lock.fd);
    } catch {
      /* already closed */
    }
    lock.fd = undefined;
    try {
      unlinkSync(lock.path); // refused, harmlessly, if another opener holds it by now
    } catch {
      /* in use or gone */
    }
    return;
  }
  // POSIX: remove it only while it is still ours.
  if (lockOwner(lock.path) === process.pid) {
    try {
      unlinkSync(lock.path);
    } catch {
      /* already gone */
    }
  }
}

function readAll(fd: number, into: Buffer, at: number, length: number, position: number): number {
  let done = 0;
  while (done < length) {
    const n = readSync(fd, into, at + done, length - done, position + done);
    if (n <= 0) break;
    done += n;
  }
  return done;
}

function writeAll(fd: number, data: Buffer, position: number): void {
  let done = 0;
  while (done < data.length) done += writeSync(fd, data, done, data.length - done, position + done);
}

/**
 * A copy-on-write layer over some lower backend. Reads fall through for blocks it does not own;
 * writes make it own them.
 */
export class CowLayer implements NbdBackend {
  readonly label?: string;
  readonly readonly: boolean;
  readonly path: string;
  private _blockSize = DEFAULT_BLOCK_SIZE;
  private dataFd = -1;
  private mapFd = -1;
  private lock?: HeldLock;
  /** [block, slot] of new blocks whose index entries wait for their data to be durable. */
  private pending: Array<[number, number]> = [];
  /** virtual block → slot in the data file. */
  private readonly slots = new Map<number, number>();
  private nextSlot = 0;
  private closed = false;

  constructor(
    private readonly below: NbdBackend,
    spec: LayerSpec,
  ) {
    this.label = spec.label;
    this.readonly = !!spec.readonly;
    this.path = spec.path;
    const requested = spec.blockSize ?? 0;
    if (requested < 0 || requested % 512 !== 0 || (spec.blockSize !== undefined && requested === 0)) {
      throw new BlissError(`layer block size must be a positive multiple of 512 (got ${spec.blockSize})`);
    }
    if (!this.readonly) {
      mkdirSync(dirname(spec.path), { recursive: true }); // a new layer may live in a fresh profile folder
      this.lock = lockLayer(spec.path);
    }
    try {
      this.open(requested);
    } catch (e) {
      this.release();
      throw e;
    }
  }

  private open(requested: number): void {
    const path = this.path;
    const mapPath = `${path}.map`;
    const fresh = !existsSync(path);
    if (fresh && this.readonly) throw new BlissError(`read-only layer ${path} does not exist`);
    this.dataFd = openSync(path, this.readonly ? 'r' : fresh ? 'w+' : 'r+');
    if (this.readonly && !existsSync(mapPath)) {
      this._blockSize = requested || DEFAULT_BLOCK_SIZE; // owns nothing
      this.checkBlocks();
      return;
    }
    this.mapFd = openSync(mapPath, this.readonly ? 'r' : existsSync(mapPath) ? 'r+' : 'w+');
    const size = fstatSync(this.mapFd).size;
    const buf = Buffer.alloc(size);
    if (readAll(this.mapFd, buf, 0, size, 0) !== size) throw new BlissError(`cannot read layer index ${mapPath}`);
    const header = size >= 8 && buf.subarray(0, 8).equals(MAP_MAGIC);
    const headerPrefix = size < 8 && buf.equals(MAP_MAGIC.subarray(0, size)); // includes an empty index
    if (header && size >= MAP_HEADER) {
      const stored = buf.readUInt32LE(8);
      if (stored === 0 || stored % 512 !== 0) throw new BlissError(`layer index ${mapPath} records a bad block size (${stored})`);
      if (requested && requested !== stored) throw new BlissError(`layer ${path} was created with ${stored}-byte blocks, not ${requested}`);
      this._blockSize = stored;
      this.replay(buf, MAP_HEADER, CHECK_SALT);
    } else if (header || headerPrefix) {
      this._blockSize = requested || DEFAULT_BLOCK_SIZE; // new, or its header was torn: nothing was allocated
      if (!this.readonly) this.writeHeader();
    } else {
      // A layer from before the index had a header: entries from byte 0, check = block ^ slot.
      this._blockSize = requested || DEFAULT_BLOCK_SIZE;
      this.replay(buf, 0, 0);
      if (!this.readonly) this.upgrade();
    }
    this.checkBlocks();
  }

  private checkBlocks(): void {
    const size = this.below.size();
    if (typeof size === 'number' && Math.ceil(size / this._blockSize) >= MAX_BLOCKS) {
      throw new BlissError(`the image is too large for ${this._blockSize}-byte layer blocks (a layer indexes at most 2^32 - 1 blocks)`);
    }
  }

  /** Rebuild the block→slot table from the index. */
  private replay(buf: Buffer, start: number, salt: number): void {
    for (let off = start, i = 0; off + ENTRY <= buf.length; off += ENTRY, i++) {
      const block = buf.readUInt32LE(off);
      const slot = buf.readUInt32LE(off + 4);
      const check = buf.readUInt32LE(off + 8);
      if (((block ^ slot ^ salt) >>> 0) !== check || slot !== i) continue; // torn, or never completed
      this.slots.set(block, slot);
      if (slot + 1 > this.nextSlot) this.nextSlot = slot + 1;
    }
  }

  private header(): Buffer {
    const h = Buffer.alloc(MAP_HEADER);
    MAP_MAGIC.copy(h, 0);
    h.writeUInt32LE(this._blockSize, 8);
    return h;
  }

  private writeHeader(): void {
    writeAll(this.mapFd, this.header(), 0);
  }

  /** Rewrite a header-less index in the current format (to a temp file, then renamed over it). */
  private upgrade(): void {
    const mapPath = `${this.path}.map`;
    const tmp = `${mapPath}.upgrade`;
    const out = Buffer.alloc(MAP_HEADER + this.nextSlot * ENTRY);
    this.header().copy(out, 0);
    for (const [block, slot] of this.slots) {
      const at = MAP_HEADER + slot * ENTRY;
      out.writeUInt32LE(block, at);
      out.writeUInt32LE(slot, at + 4);
      out.writeUInt32LE((block ^ slot ^ CHECK_SALT) >>> 0, at + 8);
    }
    const fd = openSync(tmp, 'w');
    try {
      writeAll(fd, out, 0);
      fsyncSync(fd);
    } finally {
      closeSync(fd);
    }
    closeSync(this.mapFd);
    this.mapFd = -1;
    renameSync(tmp, mapPath);
    this.mapFd = openSync(mapPath, 'r+');
  }

  size(): number | Promise<number> {
    return this.below.size();
  }

  /** Blocks this layer owns. */
  get ownedBlocks(): number {
    return this.slots.size;
  }

  /** The layer's block size (recorded in its index). */
  get blockSize(): number {
    return this._blockSize;
  }

  info(path = this.path): LayerInfo {
    return { path, label: this.label, blocks: this.slots.size, bytes: this.slots.size * this._blockSize, blockSize: this._blockSize, readonly: this.readonly };
  }

  /** Whether this layer (not anything below it) has the block covering `offset`. */
  owns(offset: number): boolean {
    return this.slots.has(Math.floor(offset / this._blockSize));
  }

  read(offset: number, length: number): Buffer {
    if (this.closed) throw new BlissError(`layer ${this.label ?? this.path} is closed`);
    // Everything this layer does not own comes from below, in one call, so a cold read costs the
    // same as it would with no layer at all.
    const out = this.below.read(offset, length) as Buffer;
    if (!this.slots.size) return out;
    const bs = this._blockSize;
    let pos = offset;
    const end = offset + length;
    while (pos < end) {
      const block = Math.floor(pos / bs);
      const inBlock = pos - block * bs;
      const take = Math.min(bs - inBlock, end - pos);
      const slot = this.slots.get(block);
      if (slot !== undefined) {
        const at = pos - offset;
        const got = readAll(this.dataFd, out, at, take, slot * bs + inBlock);
        if (got < take) out.fill(0, at + got, at + take); // a slot past the end of the data file reads as zeros, as in the native engine
      }
      pos += take;
    }
    return out;
  }

  write(offset: number, data: Buffer): void {
    if (this.readonly) throw new BlissError(`layer ${this.label ?? ''} is read-only`);
    if (this.closed) throw new BlissError(`layer ${this.label ?? this.path} is closed`);
    const bs = this._blockSize;
    let pos = offset;
    const end = offset + data.length;
    while (pos < end) {
      const block = Math.floor(pos / bs);
      const inBlock = pos - block * bs;
      const take = Math.min(bs - inBlock, end - pos);
      const chunk = data.subarray(pos - offset, pos - offset + take);
      const slot = this.slots.get(block);
      if (slot !== undefined) {
        writeAll(this.dataFd, chunk, slot * bs + inBlock);
      } else {
        const fresh = this.nextSlot;
        if (fresh >= MAX_BLOCKS) throw new BlissError(`layer ${this.label ?? this.path} is full`);
        let bytes = chunk;
        if (take !== bs) {
          // Copy-on-write: a partial write has to keep the rest of the block, which still lives
          // below us. A full-block write needs no copy.
          bytes = Buffer.from(this.below.read(block * bs, bs) as Buffer);
          chunk.copy(bytes, inBlock);
        }
        writeAll(this.dataFd, bytes, fresh * bs); // if this throws nothing is recorded, and the slot is handed out again
        this.slots.set(block, fresh);
        this.nextSlot = fresh + 1;
        this.pending.push([block, fresh]); // its entry is written once the block is durable
      }
      pos += take;
    }
    if (this.pending.length >= COMMIT_EVERY) {
      try {
        this.commit();
      } catch {
        /* the next flush reports it */
      }
    }
  }

  /** Make the new blocks durable, then write and sync the entries that point at them. */
  private commit(): void {
    if (!this.pending.length) return;
    fsyncSync(this.dataFd); // the entries must never reach the disk before their blocks
    const first = this.pending[0]![1]; // slots are handed out in order, so the entries are contiguous
    const recs = Buffer.alloc(this.pending.length * ENTRY);
    this.pending.forEach(([block, slot], i) => {
      recs.writeUInt32LE(block, i * ENTRY);
      recs.writeUInt32LE(slot, i * ENTRY + 4);
      recs.writeUInt32LE((block ^ slot ^ CHECK_SALT) >>> 0, i * ENTRY + 8);
    });
    writeAll(this.mapFd, recs, MAP_HEADER + first * ENTRY);
    fsyncSync(this.mapFd);
    this.pending = [];
  }

  /** Make this layer's own writes durable: the blocks, then the index that points at them. */
  flush(): void {
    if (this.closed || this.readonly) return;
    if (this.pending.length) return this.commit();
    fsyncSync(this.dataFd);
    if (this.mapFd >= 0) fsyncSync(this.mapFd);
  }

  private release(): void {
    for (const fd of [this.dataFd, this.mapFd]) {
      if (fd < 0) continue;
      try {
        closeSync(fd);
      } catch {
        /* already closed */
      }
    }
    this.dataFd = -1;
    this.mapFd = -1;
    if (this.lock) {
      unlockLayer(this.lock);
      this.lock = undefined;
    }
  }

  /** Close only this layer's own files (and its lock), leaving what it reads through open. */
  closeSelf(): void {
    if (this.closed) return;
    this.closed = true;
    if (!this.readonly) {
      try {
        this.commit(); // what a clean close has, a reopen has
      } catch {
        /* the blocks since the last flush are lost — as a crash would lose them */
      }
    }
    this.release();
  }

  /** Close this layer and everything below it. */
  close(): void {
    this.closeSelf();
    this.below.close?.();
  }
}

/** Remove a layer's files. The layer must not be open. */
export function discardLayer(path: string): void {
  for (const p of [path, `${path}.map`, `${path}.lock`]) {
    try {
      if (existsSync(p)) unlinkSync(p);
    } catch {
      /* nothing to remove */
    }
  }
}

/**
 * A base backend with writable layers stacked on it.
 *
 * The stack is a stable object: whatever holds it — an `NbdFileShare`, its FAT32 mapper, the block
 * interceptor, a context layer stacked over it — keeps working while layers are pushed, popped or
 * swapped underneath. That is what makes a context switch a file swap rather than a VM restart.
 *
 * **Swapping under a mounted guest filesystem is not safe on its own**: the guest has FAT metadata
 * and page cache from the old layer. Unmount it in the guest first and mount it again after —
 * {@link NbdFileShare.pushLayer} and friends do that.
 */
export class LayerStack implements NbdBackend {
  private readonly stack: CowLayer[] = [];

  constructor(
    private readonly base: NbdBackend,
    layers: LayerSpec[] = [],
  ) {
    try {
      for (const l of layers) this.push(l);
    } catch (e) {
      for (let i = this.stack.length - 1; i >= 0; i--) this.stack[i]!.closeSelf();
      this.stack.length = 0;
      throw e;
    }
  }

  /** The backend reads and writes go to: the top layer, or the base when nothing is stacked. */
  private get top(): NbdBackend {
    return this.stack.length ? this.stack[this.stack.length - 1]! : this.base;
  }

  /** Add a layer on top. Writes from now on land in it. */
  push(spec: LayerSpec): LayerInfo {
    const layer = new CowLayer(this.top, spec);
    this.stack.push(layer);
    return layer.info();
  }

  /**
   * Remove the top layer. Its file is left alone, so the same layer can be pushed again later —
   * that is how a context is put away and picked back up.
   */
  pop(): LayerInfo | undefined {
    const layer = this.stack.pop();
    if (!layer) return undefined;
    const info = layer.info();
    // Only this layer is closed; `below` stays open because the stack still uses it.
    layer.closeSelf();
    return info;
  }

  /**
   * Replace the top layer with another. The new layer is opened FIRST, so one that cannot be
   * opened leaves the stack exactly as it was — writes never fall through to the layer below.
   */
  swapTop(spec: LayerSpec): LayerInfo {
    const old = this.stack[this.stack.length - 1];
    if (!old) throw new BlissError('nothing is stacked to swap');
    const below = this.stack.length >= 2 ? this.stack[this.stack.length - 2]! : this.base;
    if (old.path === spec.path) {
      // The same file again: it has to be let go before it can be opened. Put it back if that fails.
      const was: LayerSpec = { path: old.path, label: old.label, blockSize: old.blockSize, readonly: old.readonly };
      old.closeSelf();
      this.stack.pop();
      try {
        this.stack.push(new CowLayer(below, spec));
      } catch (e) {
        try {
          this.stack.push(new CowLayer(below, was));
        } catch {
          /* it cannot be reopened either */
        }
        throw e;
      }
      return this.stack[this.stack.length - 1]!.info();
    }
    const next = new CowLayer(below, spec);
    old.closeSelf();
    this.stack[this.stack.length - 1] = next;
    return next.info();
  }

  /** What is stacked, bottom layer first. */
  layers(): LayerInfo[] {
    return this.stack.map((l) => l.info());
  }

  /** How deep the stack is (0 = the base alone). */
  get depth(): number {
    return this.stack.length;
  }

  size(): number | Promise<number> {
    return this.base.size();
  }
  get readonly(): boolean {
    return this.stack.length ? !!this.top.readonly : !!this.base.readonly;
  }
  read(offset: number, length: number): Buffer | Promise<Buffer> {
    return this.top.read(offset, length);
  }
  write(offset: number, data: Buffer): void | Promise<void> {
    return this.top.write(offset, data);
  }
  /** Make every layer's writes, and the base's, durable. */
  flush(): void | Promise<void> {
    for (let i = this.stack.length - 1; i >= 0; i--) this.stack[i]!.flush();
    return this.base.flush?.();
  }
  private closed = false;
  close(): void {
    if (this.closed) return;
    this.closed = true;
    // Top-down, so each layer closes before the one it reads through.
    for (let i = this.stack.length - 1; i >= 0; i--) this.stack[i]!.closeSelf();
    this.stack.length = 0;
    this.base.close?.();
  }
}
