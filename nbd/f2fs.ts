import { openSync, readSync } from 'node:fs';
import { BlissError } from '../errors';
import type { FileMapper, NbdBackend, TouchedFile } from './server';

/** A synchronous reader over the disk image (offset/length in bytes). */
export type ImageReader = (offset: number, length: number) => Buffer;

interface FileRec {
  path: string;
  isDir: boolean;
  size: number;
  /** The file's inode number (in f2fs the inode's node id equals its inode number). */
  ino: number;
  /** Owner uid / gid and permission bits, from the inode (image-derived attribution). */
  uid: number;
  gid: number;
  mode: number;
  /** Physical blocks in logical order. */
  blocks: number[];
  /** The file's logical block index for each entry of {@link blocks} (holes leave gaps). */
  logical: number[];
}

interface Geometry {
  blockSize: number;
  blocksPerSeg: number;
  natBlkaddr: number;
  mainBlkaddr: number;
  rootIno: number;
  totalBlocks: number;
}

// F2FS is fixed at 4 KiB blocks; a node/inode/dentry block is one block.
const F2FS_MAGIC = 0xf2f52010;
const NAT_ENTRY_PER_BLOCK = 455; // f2fs_nat_entry is 9 bytes packed
const ADDRS_PER_INODE = 923;
const ADDRS_PER_BLOCK = 1018; // direct node
const NIDS_PER_BLOCK = 1018; // indirect node
const NODE_FOOTER_NID_OFF = 4072;

// i_inline flags.
const F2FS_INLINE_XATTR = 0x01;
const F2FS_INLINE_DATA = 0x02;
const F2FS_INLINE_DENTRY = 0x04;
const F2FS_EXTRA_ATTR = 0x20;
const DEF_INLINE_XATTR_ADDRS = 50; // 200 bytes at the tail of i_addr

// Block-address sentinels.
const NULL_ADDR = 0;
const NEW_ADDR = 0xffffffff;

// Directory (regular dentry block) geometry.
const NR_DENTRY_IN_BLOCK = 214;
const SIZE_OF_DIR_ENTRY = 11;
const F2FS_SLOT_LEN = 8;
const DENTRY_BITMAP_SIZE = Math.ceil(NR_DENTRY_IN_BLOCK / 8); // 27
const DENTRY_RESERVED = 4096 - ((SIZE_OF_DIR_ENTRY + F2FS_SLOT_LEN) * NR_DENTRY_IN_BLOCK + DENTRY_BITMAP_SIZE); // 3
const DENTRY_ARRAY_OFF = DENTRY_BITMAP_SIZE + DENTRY_RESERVED; // 30
const DENTRY_NAME_OFF = DENTRY_ARRAY_OFF + NR_DENTRY_IN_BLOCK * SIZE_OF_DIR_ENTRY; // 2384

const F2FS_FT_DIR = 2;
const F2FS_FT_SYMLINK = 7;

// Bounds — the image is guest-written, so a malformed one cannot ask for unbounded work.
const MAX_FILES = 500_000;
const MAX_BLOCKS_PER_FILE = 8_000_000;
const MAX_DIR_DEPTH = 64;
const CP_LARGE_NAT_BITMAP_FLAG = 0x0400;

/**
 * Maps byte offsets in an **F2FS** image (Android's default `/data` filesystem) back to guest file
 * names. F2FS is log-structured: node blocks (inodes, direct/indirect nodes) are found through the
 * Node Address Table (NAT), whose current version per block is chosen by a bitmap in the active
 * checkpoint, with the most recent entries overlaid from the checkpoint's NAT journal. From the
 * root inode this walks the directory tree, resolves each file's data blocks (inode `i_addr` plus
 * direct/indirect/double-indirect node blocks), and builds a physical-block → file map — the same
 * thing {@link Fat32Mapper} and `Ext4Mapper` do for their filesystems.
 *
 * Parsing is a snapshot; call {@link refresh} after the guest changed the filesystem.
 *
 * @example
 * const mapper = F2fsMapper.fromFile('./data.img');
 * const nbd = new NbdServer({ file: './data.img', size, mapper });
 * nbd.on('access', (e) => console.log(e.command, e.files.map(f => f.path)));
 */
export class F2fsMapper implements FileMapper {
  private geo!: Geometry;
  private natBitmap!: Buffer;
  private natBitmapLarge = false;
  private logBlocksPerSeg = 0;
  /** NID → block address, overriding the NAT table (from the checkpoint's NAT journal). */
  private natJournal = new Map<number, number>();
  private nidCache = new Map<number, number>();
  private blockToFile = new Map<number, { rec: FileRec; index: number }>();
  private metadata = new Set<number>();
  files: FileRec[] = [];
  /** Lazy inode→path index (built on first pathForInode, cleared on each parse). */
  private inoIndex?: Map<number, string>;

  constructor(private readonly read: ImageReader) {
    this.parse();
  }

  static fromFile(path: string): F2fsMapper {
    const fd = openSync(path, 'r');
    const read: ImageReader = (offset, length) => {
      const b = Buffer.alloc(length);
      let done = 0;
      while (done < length) {
        const n = readSync(fd, b, done, length - done, offset + done);
        if (n <= 0) break;
        done += n;
      }
      return b;
    };
    return new F2fsMapper(read);
  }

  /** Build a mapper from a synchronous NbdBackend (e.g. FileBackend or a layer stack). */
  static fromBackend(backend: NbdBackend): F2fsMapper {
    return new F2fsMapper((offset, length) => backend.read(offset, length) as Buffer);
  }

  /** Re-parse the filesystem (after the guest wrote a new checkpoint). */
  refresh(): void {
    this.parse();
  }

  private block(blk: number): Buffer {
    return this.read(blk * this.geo.blockSize, this.geo.blockSize);
  }

  // --- parsing --------------------------------------------------------------

  private parse(): void {
    // The superblock is at byte offset 1024 (there are two copies; the first is enough here).
    const sb = this.read(1024, 1024);
    if (sb.readUInt32LE(0) !== F2FS_MAGIC) throw new BlissError('Not an F2FS filesystem (bad 0xF2F52010 magic)');
    const logBlockSize = sb.readUInt32LE(16);
    if (logBlockSize !== 12) throw new BlissError('Not an F2FS filesystem (block size is not 4 KiB)');
    const blockSize = 4096;
    this.logBlocksPerSeg = sb.readUInt32LE(20);
    const blocksPerSeg = 1 << this.logBlocksPerSeg;
    const cpBlkaddr = sb.readUInt32LE(76);
    const natBlkaddr = sb.readUInt32LE(84);
    const mainBlkaddr = sb.readUInt32LE(92);
    const rootIno = sb.readUInt32LE(96);
    const blockCount = Number(sb.readBigUInt64LE(36));
    if (!blocksPerSeg || !natBlkaddr || !mainBlkaddr || mainBlkaddr <= natBlkaddr || !rootIno) {
      throw new BlissError('Not an F2FS filesystem (implausible geometry)');
    }
    this.geo = { blockSize, blocksPerSeg, natBlkaddr, mainBlkaddr, rootIno, totalBlocks: blockCount };

    this.readCheckpoint(cpBlkaddr);

    this.nidCache = new Map();
    this.blockToFile = new Map();
    this.metadata = new Set();
    this.files = [];
    this.inoIndex = undefined; // stale after a re-parse; rebuilt lazily by pathForInode
    // Everything before the main area (superblock, checkpoint, SIT, NAT, SSA) is metadata.
    for (let b = 0; b < mainBlkaddr; b++) this.metadata.add(b);

    this.walkDir(rootIno, '', new Set(), 0);
  }

  /** Pick the newer of the two checkpoint packs and read its NAT version bitmap and NAT journal. */
  private readCheckpoint(cpBlkaddr: number): void {
    const { blocksPerSeg } = this.geo;
    const verOf = (blk: number): bigint => this.block(blk).readBigUInt64LE(0);
    const v0 = verOf(cpBlkaddr);
    const v1 = verOf(cpBlkaddr + blocksPerSeg);
    const cpBlk = v1 > v0 ? cpBlkaddr + blocksPerSeg : cpBlkaddr;

    const head = this.block(cpBlk);
    const flags = head.readUInt32LE(132);
    const startSum = head.readUInt32LE(140);
    const sitBmSize = head.readUInt32LE(156);
    const natBmSize = head.readUInt32LE(160);
    this.natBitmapLarge = (flags & CP_LARGE_NAT_BITMAP_FLAG) !== 0;
    // The version bitmaps live right after the fixed checkpoint header (offset 192) and may spill
    // into the following payload blocks, so read a contiguous run big enough to cover them.
    const natBmOff = this.natBitmapLarge ? 192 + 4 /* skip checksum */ : 192 + sitBmSize;
    const need = natBmOff + natBmSize;
    const buf = need <= this.geo.blockSize ? head : this.read(cpBlk * this.geo.blockSize, Math.ceil(need / this.geo.blockSize) * this.geo.blockSize);
    this.natBitmap = buf.subarray(natBmOff, natBmOff + natBmSize);

    // NAT journal: recently changed NID→block entries kept in the hot-data summary of this pack.
    this.natJournal = new Map();
    if (startSum > 0) {
      const sum = this.block(cpBlk + startSum);
      const nNats = sum.readUInt16LE(3584);
      const cap = Math.min(nNats, 40); // the journal holds at most ~38 entries
      for (let i = 0; i < cap; i++) {
        const off = 3586 + i * 13;
        if (off + 13 > sum.length) break;
        const nid = sum.readUInt32LE(off);
        const blkaddr = sum.readUInt32LE(off + 5); // {nid u32}{version u8, ino u32, blkaddr u32}
        this.natJournal.set(nid, blkaddr);
      }
    }
  }

  /** NAT version bitmap uses MSB-first bit order. */
  private natBit(blockOff: number): number {
    const byte = this.natBitmap[blockOff >> 3] ?? 0;
    return (byte >> (7 - (blockOff & 7))) & 1;
  }

  /** The physical block address of a node NID, from the NAT journal or the NAT table. */
  private resolveNid(nid: number): number {
    const cached = this.nidCache.get(nid);
    if (cached !== undefined) return cached;
    let addr: number;
    const j = this.natJournal.get(nid);
    if (j !== undefined) {
      addr = j;
    } else {
      const { natBlkaddr, blocksPerSeg } = this.geo;
      const blockOff = Math.floor(nid / NAT_ENTRY_PER_BLOCK);
      const segOff = blockOff >> this.logBlocksPerSeg;
      let natBlock = natBlkaddr + (segOff << (this.logBlocksPerSeg + 1)) + (blockOff & (blocksPerSeg - 1));
      if (this.natBit(blockOff)) natBlock += blocksPerSeg;
      const blk = this.block(natBlock);
      const entryOff = (nid % NAT_ENTRY_PER_BLOCK) * 9; // {version u8, ino u32, block_addr u32}
      addr = blk.readUInt32LE(entryOff + 5);
    }
    this.nidCache.set(nid, addr);
    return addr;
  }

  /** Read a node block by NID, or undefined when the NID maps nowhere valid. */
  private readNode(nid: number): Buffer | undefined {
    if (nid <= 0) return undefined;
    const addr = this.resolveNid(nid);
    if (addr === NULL_ADDR || addr === NEW_ADDR || addr < this.geo.mainBlkaddr || addr >= this.geo.totalBlocks) return undefined;
    this.metadata.add(addr); // node blocks are filesystem metadata
    return this.block(addr);
  }

  /** The data-address window inside an inode's i_addr array, accounting for extra attrs and inline xattr. */
  private addrWindow(inline: number, inode: Buffer): { start: number; end: number } {
    const extra = (inline & F2FS_EXTRA_ATTR) !== 0;
    const extraSlots = extra ? Math.floor(inode.readUInt16LE(360) / 4) : 0;
    let xattrSlots = 0;
    if (inline & F2FS_INLINE_XATTR) {
      const sized = extra ? inode.readUInt16LE(362) : 0;
      xattrSlots = sized > 0 ? sized : DEF_INLINE_XATTR_ADDRS;
    }
    return { start: extraSlots, end: Math.max(extraSlots, ADDRS_PER_INODE - xattrSlots) };
  }

  /** Collect a file/dir inode's physical data blocks in logical order (holes skipped). */
  private inodeBlocks(inode: Buffer, inline: number): { blocks: number[]; logical: number[] } {
    const blocks: number[] = [];
    const logical: number[] = [];
    if (inline & F2FS_INLINE_DATA) return { blocks, logical }; // data lives inside the inode
    let logicalBlock = 0;
    const addAddr = (addr: number): boolean => {
      if (blocks.length >= MAX_BLOCKS_PER_FILE) return false;
      if (addr !== NULL_ADDR && addr !== NEW_ADDR && addr >= this.geo.mainBlkaddr && addr < this.geo.totalBlocks) {
        blocks.push(addr);
        logical.push(logicalBlock);
      }
      logicalBlock++;
      return true;
    };
    // i_addr[] in the inode itself.
    const { start, end } = this.addrWindow(inline, inode);
    for (let s = start; s < end; s++) {
      if (!addAddr(inode.readUInt32LE(360 + s * 4))) return { blocks, logical };
    }
    // i_nid[0..4]: two direct nodes, two indirect, one double-indirect.
    const iNid = (k: number): number => inode.readUInt32LE(4052 + k * 4);
    const walkDirectNode = (nid: number): boolean => {
      const node = this.readNode(nid);
      if (!node) { logicalBlock += ADDRS_PER_BLOCK; return true; }
      for (let i = 0; i < ADDRS_PER_BLOCK; i++) if (!addAddr(node.readUInt32LE(i * 4))) return false;
      return true;
    };
    const walkIndirectNode = (nid: number, depth: number): boolean => {
      const node = this.readNode(nid);
      if (!node) { logicalBlock += (depth === 1 ? ADDRS_PER_BLOCK : NIDS_PER_BLOCK * ADDRS_PER_BLOCK) * NIDS_PER_BLOCK; return true; }
      for (let i = 0; i < NIDS_PER_BLOCK; i++) {
        const child = node.readUInt32LE(i * 4);
        if (depth === 1 ? !walkDirectNode(child) : !walkIndirectNode(child, 1)) return false;
      }
      return true;
    };
    if (!walkDirectNode(iNid(0))) return { blocks, logical };
    if (!walkDirectNode(iNid(1))) return { blocks, logical };
    if (!walkIndirectNode(iNid(2), 1)) return { blocks, logical };
    if (!walkIndirectNode(iNid(3), 1)) return { blocks, logical };
    walkIndirectNode(iNid(4), 2);
    return { blocks, logical };
  }

  private register(rec: FileRec): void {
    if (this.files.length >= MAX_FILES) return;
    this.files.push(rec);
    rec.blocks.forEach((b, index) => {
      if (!this.blockToFile.has(b)) this.blockToFile.set(b, { rec, index });
    });
  }

  private walkDir(ino: number, parentPath: string, visited: Set<number>, depth: number): void {
    if (depth > MAX_DIR_DEPTH || visited.has(ino) || this.files.length >= MAX_FILES) return;
    visited.add(ino);
    const inode = this.readNode(ino);
    if (!inode) return;
    const inline = inode[3]!;
    if (parentPath !== '') {
      const { blocks, logical } = this.inodeBlocks(inode, inline);
      this.register({ path: parentPath, isDir: true, size: Number(inode.readBigUInt64LE(16)), ino, ...ownerOfNode(inode), blocks, logical });
    }
    for (const child of this.dirEntries(inode, inline)) {
      if (child.name === '.' || child.name === '..' || child.nid <= 0) continue;
      const path = `${parentPath}/${child.name}`;
      const childInode = this.readNode(child.nid);
      if (!childInode) continue;
      const cInline = childInode[3]!;
      const mode = childInode.readUInt16LE(0);
      const isDir = (mode & 0xf000) === 0x4000 || child.type === F2FS_FT_DIR;
      if (isDir) {
        this.walkDir(child.nid, path, visited, depth + 1);
      } else if (child.type !== F2FS_FT_SYMLINK || (mode & 0xf000) !== 0xa000) {
        const size = Number(childInode.readBigUInt64LE(16));
        const cb = this.inodeBlocks(childInode, cInline);
        this.register({ path, isDir: false, size, ino: child.nid, ...ownerOfNode(childInode), blocks: cb.blocks, logical: cb.logical });
      }
    }
  }

  /** Directory entries, from inline dentries in the inode or from the directory's data blocks. */
  private dirEntries(inode: Buffer, inline: number): Array<{ nid: number; name: string; type: number }> {
    if (inline & F2FS_INLINE_DENTRY) {
      const { start, end } = this.addrWindow(inline, inode);
      // Inline dentry occupies the i_addr data window; slot count derives from its byte size.
      const areaOff = 360 + start * 4;
      const areaBytes = (end - start) * 4;
      return this.parseDentries(inode, areaOff, areaBytes, true);
    }
    const { blocks } = this.inodeBlocks(inode, inline);
    const out: Array<{ nid: number; name: string; type: number }> = [];
    for (const b of blocks) {
      const buf = this.block(b);
      for (const e of this.parseDentries(buf, 0, this.geo.blockSize, false)) out.push(e);
    }
    return out;
  }

  /**
   * Parse a run of f2fs dentries. A regular directory block is
   * `[bitmap][reserved][dir_entry[214]][filename[214][8]]`; an inline dentry has the same shape but
   * its slot count is derived from the available byte area.
   */
  private parseDentries(buf: Buffer, base: number, bytes: number, inlineLayout: boolean): Array<{ nid: number; name: string; type: number }> {
    const out: Array<{ nid: number; name: string; type: number }> = [];
    let slots: number, bitmapOff: number, entryOff: number, nameOff: number;
    if (!inlineLayout) {
      slots = NR_DENTRY_IN_BLOCK;
      bitmapOff = base;
      entryOff = base + DENTRY_ARRAY_OFF;
      nameOff = base + DENTRY_NAME_OFF;
    } else {
      // slots such that ceil(slots/8) + slots*11 + slots*8 <= bytes  ->  slots*(11+8) + slots/8 <= bytes
      slots = Math.floor((bytes * 8) / (SIZE_OF_DIR_ENTRY * 8 + F2FS_SLOT_LEN * 8 + 1));
      const bitmapSize = Math.ceil(slots / 8);
      bitmapOff = base;
      entryOff = base + bitmapSize;
      nameOff = entryOff + slots * SIZE_OF_DIR_ENTRY;
    }
    const bitSet = (i: number): boolean => (((buf[bitmapOff + (i >> 3)] ?? 0) >> (i & 7)) & 1) === 1;
    let i = 0;
    while (i < slots) {
      if (!bitSet(i)) { i++; continue; }
      const eo = entryOff + i * SIZE_OF_DIR_ENTRY;
      if (eo + SIZE_OF_DIR_ENTRY > buf.length) break;
      const nid = buf.readUInt32LE(eo + 4);
      const nameLen = buf.readUInt16LE(eo + 8);
      const type = buf[eo + 10]!;
      const usedSlots = Math.max(1, Math.ceil(nameLen / F2FS_SLOT_LEN));
      const no = nameOff + i * F2FS_SLOT_LEN;
      if (nid > 0 && nameLen > 0 && no + nameLen <= buf.length) {
        const name = buf.subarray(no, no + nameLen).toString('utf8');
        out.push({ nid, name, type });
      }
      i += usedSlots;
    }
    return out;
  }

  // --- SectorMapper / FileMapper -------------------------------------------

  /** Resolve the guest files touched by a byte range, merged per file. */
  mapRange(offset: number, length: number): TouchedFile[] {
    const out: TouchedFile[] = [];
    const { blockSize } = this.geo;
    let pos = offset;
    const end = offset + length;
    while (pos < end) {
      const block = Math.floor(pos / blockSize);
      const within = pos - block * blockSize;
      const chunk = Math.min(end - pos, blockSize - within);
      const hit = this.blockToFile.get(block);
      if (hit) {
        pushMerged(out, { path: hit.rec.path, fileOffset: hit.index * blockSize + within, bytes: chunk });
      } else if (this.metadata.has(block)) {
        pushMerged(out, { path: '<metadata>', fileOffset: pos, bytes: chunk });
      } else {
        pushMerged(out, { path: '<free>', fileOffset: pos, bytes: chunk });
      }
      pos += chunk;
    }
    return out;
  }

  /** List parsed files (path + size). */
  list(): Array<{ path: string; size: number; isDir: boolean }> {
    return this.files.map((f) => ({ path: f.path, size: f.size, isDir: f.isDir }));
  }

  /** The file's owner uid / gid and permission bits (image-derived attribution). */
  owner(path: string): { uid: number; gid: number; mode: number } | undefined {
    const rec = this.files.find((f) => f.path === path);
    return rec ? { uid: rec.uid, gid: rec.gid, mode: rec.mode } : undefined;
  }

  /** The guest path of an inode number (for correlating ftrace tracepoints, which name inodes). */
  pathForInode(ino: number): string | undefined {
    if (!this.inoIndex) {
      this.inoIndex = new Map();
      for (const f of this.files) if (!this.inoIndex.has(f.ino)) this.inoIndex.set(f.ino, f.path);
    }
    return this.inoIndex.get(ino);
  }

  /** The byte extents (offset/length pairs) a file occupies in the image, in logical order. */
  extents(path: string): Array<{ offset: number; length: number }> {
    const rec = this.files.find((f) => f.path === path);
    if (!rec) return [];
    return rec.blocks.map((b) => ({ offset: b * this.geo.blockSize, length: this.geo.blockSize }));
  }
}

/** Owner uid / gid and permission bits from an f2fs inode node buffer. */
function ownerOfNode(inode: Buffer): { uid: number; gid: number; mode: number } {
  return { uid: inode.readUInt32LE(4), gid: inode.readUInt32LE(8), mode: inode.readUInt16LE(0) & 0o7777 };
}

function pushMerged(out: TouchedFile[], t: TouchedFile): void {
  const last = out[out.length - 1];
  if (last && last.path === t.path && last.fileOffset + last.bytes === t.fileOffset) {
    last.bytes += t.bytes;
  } else {
    out.push(t);
  }
}
