import { openSync, readSync } from 'node:fs';
import { BlissError } from '../errors';
import type { FileMapper, NbdBackend, TouchedFile } from './server';

/** A synchronous reader over the disk image (offset/length in bytes). */
export type ImageReader = (offset: number, length: number) => Buffer;

interface FileRec {
  path: string;
  isDir: boolean;
  size: number;
  /** The file's inode number. */
  ino: number;
  /** Physical blocks in logical order (index i = the file's logical block i). */
  blocks: number[];
  /** The logical block number each entry of {@link blocks} stands for (holes leave gaps). */
  logical: number[];
}

/** Enough of the superblock to recompute an inode's metadata_csum when rewriting mode/owner. */
export interface Ext4CsumInfo {
  inodeSize: number;
  /** The seed crc32c(~0, uuid) — or the explicit s_checksum_seed when the fs stores one. */
  csumSeed: number;
  /** Whether metadata_csum is on (an inode checksum must be written when it is). */
  metadataCsum: boolean;
}

// crc32c (Castagnoli, reflected) — the checksum ext4's metadata_csum uses.
const CRC32C_TABLE = (() => {
  const t = new Uint32Array(256);
  for (let n = 0; n < 256; n++) {
    let c = n;
    for (let k = 0; k < 8; k++) c = c & 1 ? 0x82f63b78 ^ (c >>> 1) : c >>> 1;
    t[n] = c >>> 0;
  }
  return t;
})();
function crc32c(seed: number, buf: Buffer): number {
  let c = seed >>> 0;
  for (let i = 0; i < buf.length; i++) c = (CRC32C_TABLE[(c ^ buf[i]!) & 0xff]! ^ (c >>> 8)) >>> 0;
  return c >>> 0;
}

/**
 * Rewrite an ext4 inode's mode / owner uid / owner gid in place and fix its metadata_csum, returning
 * the patched inode bytes. `mode` keeps the file-type bits and replaces the permission bits. Pure and
 * exported so it can be unit-tested against e2fsck.
 */
export function patchExt4Inode(
  inode: Buffer,
  ino: number,
  changes: { mode?: number; uid?: number; gid?: number },
  info: Ext4CsumInfo,
): Buffer {
  const out = Buffer.from(inode);
  if (changes.mode !== undefined) {
    const type = out.readUInt16LE(0) & 0xf000;
    out.writeUInt16LE((type | (changes.mode & 0x0fff)) & 0xffff, 0);
  }
  if (changes.uid !== undefined) {
    out.writeUInt16LE(changes.uid & 0xffff, 2);
    out.writeUInt16LE((changes.uid >>> 16) & 0xffff, 120); // l_i_uid_high
  }
  if (changes.gid !== undefined) {
    out.writeUInt16LE(changes.gid & 0xffff, 24);
    out.writeUInt16LE((changes.gid >>> 16) & 0xffff, 122); // l_i_gid_high
  }
  if (info.metadataCsum) {
    const extraIsize = info.inodeSize > 128 ? out.readUInt16LE(128) : 0;
    const hasHi = info.inodeSize > 128 && extraIsize >= 0x82 + 2 - 128; // room for i_checksum_hi
    const work = Buffer.from(out);
    work.writeUInt16LE(0, 124); // l_i_checksum_lo
    if (hasHi) work.writeUInt16LE(0, 130); // i_checksum_hi
    const inumB = Buffer.alloc(4);
    inumB.writeUInt32LE(ino >>> 0, 0);
    const genB = Buffer.alloc(4);
    genB.writeUInt32LE(out.readUInt32LE(100) >>> 0, 0); // i_generation
    let c = crc32c(info.csumSeed, inumB);
    c = crc32c(c, genB);
    c = crc32c(c, work);
    out.writeUInt16LE(c & 0xffff, 124);
    if (hasHi) out.writeUInt16LE((c >>> 16) & 0xffff, 130);
  }
  return out;
}

interface Geometry {
  blockSize: number;
  blocksPerGroup: number;
  inodesPerGroup: number;
  inodeSize: number;
  inodesCount: number;
  blocksCount: number;
  firstDataBlock: number;
  descSize: number;
  is64bit: boolean;
  hasFileType: boolean;
  groups: number;
  /** metadata_csum is on (an inode's checksum must be recomputed when its inode is rewritten). */
  metadataCsum: boolean;
  /** Seed for the inode checksum: crc32c(~0, uuid), or s_checksum_seed when the fs stores one. */
  csumSeed: number;
}

const RO_COMPAT_METADATA_CSUM = 0x0400;
const INCOMPAT_CSUM_SEED = 0x2000;

// Inode i_mode top nibble.
const S_IFMT = 0xf000;
const S_IFDIR = 0x4000;
const S_IFREG = 0x8000;
const S_IFLNK = 0xa000;
// Inode flags.
const EXT4_EXTENTS_FL = 0x80000;
const EXT4_INLINE_DATA_FL = 0x10000000;
// Feature flags.
const INCOMPAT_FILETYPE = 0x0002;
const INCOMPAT_64BIT = 0x0080;

const ROOT_INO = 2;
const EXTENT_MAGIC = 0xf30a;
// A guest can write any bytes it likes; these bound the work a malformed image can ask for.
const MAX_FILES = 500_000;
const MAX_BLOCKS_PER_FILE = 8_000_000; // ~32 GiB at 4 KiB blocks
const MAX_DIR_DEPTH = 64;
const MAX_EXTENT_DEPTH = 5;

/**
 * Maps byte offsets in an **ext4** (also ext2/ext3) image back to guest file names by parsing the
 * superblock, block group descriptors, inode table, extent trees / indirect block maps and the
 * directory tree. This is the "sector-mapping" approach: QEMU works at the block level, and this
 * recovers *which file* a read/write touches — the same thing {@link Fat32Mapper} does for FAT32,
 * so per-file backup, redirects, dedup and file events work on an ext4 share (e.g. `/data`) too,
 * host-side, without a guest agent.
 *
 * Parsing is a snapshot; call {@link refresh} after the guest changes the filesystem to pick up
 * new/renamed/deleted files.
 *
 * @example
 * const mapper = Ext4Mapper.fromFile('./data.img');
 * const nbd = new NbdServer({ file: './data.img', size, mapper });
 * nbd.on('access', (e) => console.log(e.command, e.files.map(f => `${f.path}+${f.fileOffset}`)));
 */
export class Ext4Mapper implements FileMapper {
  private geo!: Geometry;
  /** group index → first block of that group's inode table. */
  private inodeTableBlock: number[] = [];
  private blockToFile = new Map<number, { rec: FileRec; index: number }>();
  private metadata = new Set<number>();
  files: FileRec[] = [];

  constructor(private readonly read: ImageReader) {
    this.parse();
  }

  static fromFile(path: string): Ext4Mapper {
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
    return new Ext4Mapper(read);
  }

  /** Build a mapper from a synchronous NbdBackend (e.g. FileBackend or a layer stack). */
  static fromBackend(backend: NbdBackend): Ext4Mapper {
    return new Ext4Mapper((offset, length) => backend.read(offset, length) as Buffer);
  }

  /** Re-parse the filesystem (after the guest wrote inodes / directory blocks). */
  refresh(): void {
    this.parse();
  }

  // --- parsing --------------------------------------------------------------

  private parse(): void {
    // The superblock sits at byte 1024, whatever the block size.
    const sb = this.read(1024, 1024);
    if (sb.readUInt16LE(56) !== 0xef53) throw new BlissError('Not an ext4 filesystem (bad 0xEF53 superblock magic)');
    const logBlockSize = sb.readUInt32LE(24);
    if (logBlockSize > 6) throw new BlissError('Not an ext4 filesystem (implausible block size)');
    const blockSize = 1024 << logBlockSize;
    const blocksPerGroup = sb.readUInt32LE(32);
    const inodesPerGroup = sb.readUInt32LE(40);
    const inodesCount = sb.readUInt32LE(0);
    const blocksCountLo = sb.readUInt32LE(4);
    const blocksCountHi = sb.readUInt32LE(0x150);
    const blocksCount = blocksCountLo + blocksCountHi * 0x1_0000_0000;
    let inodeSize = sb.readUInt16LE(88);
    if (inodeSize === 0) inodeSize = 128; // ext2 default (feature: no s_inode_size)
    const featureIncompat = sb.readUInt32LE(96);
    const is64bit = (featureIncompat & INCOMPAT_64BIT) !== 0;
    const hasFileType = (featureIncompat & INCOMPAT_FILETYPE) !== 0;
    const firstDataBlock = sb.readUInt32LE(20);
    let descSize = is64bit ? sb.readUInt16LE(254) : 32;
    if (descSize < 32) descSize = 32;

    if (!blocksPerGroup || !inodesPerGroup || !blocksCount || inodeSize < 128 || inodeSize > blockSize) {
      throw new BlissError('Not an ext4 filesystem (implausible geometry)');
    }
    const groups = Math.ceil(blocksCount / blocksPerGroup);
    if (groups <= 0 || groups > 1 << 24) throw new BlissError('Not an ext4 filesystem (implausible group count)');

    const featureRoCompat = sb.readUInt32LE(100);
    const metadataCsum = (featureRoCompat & RO_COMPAT_METADATA_CSUM) !== 0;
    const csumSeed = (featureIncompat & INCOMPAT_CSUM_SEED) !== 0 ? sb.readUInt32LE(0x270) >>> 0 : crc32c(0xffffffff, sb.subarray(104, 120));

    this.geo = {
      blockSize,
      blocksPerGroup,
      inodesPerGroup,
      inodeSize,
      inodesCount,
      blocksCount,
      firstDataBlock,
      descSize,
      is64bit,
      hasFileType,
      groups,
      metadataCsum,
      csumSeed,
    };

    this.readGroupDescriptors();
    this.blockToFile = new Map();
    this.metadata = new Set();
    this.files = [];
    this.markStaticMetadata();

    // Walk the tree from the root inode; only reachable files are mapped, exactly as the FAT walk does.
    this.walkDir(ROOT_INO, '', new Set(), 0);
  }

  /** The group descriptor table follows the block holding the superblock. */
  private readGroupDescriptors(): void {
    const { blockSize, descSize, firstDataBlock, groups, is64bit } = this.geo;
    const gdtStart = (firstDataBlock + 1) * blockSize;
    const buf = this.read(gdtStart, descSize * groups);
    this.inodeTableBlock = [];
    for (let g = 0; g < groups; g++) {
      const off = g * descSize;
      const lo = buf.readUInt32LE(off + 8);
      const hi = is64bit && descSize >= 64 ? buf.readUInt32LE(off + 40) : 0;
      this.inodeTableBlock.push(lo + hi * 0x1_0000_0000);
      // The group's bitmaps and inode table are filesystem metadata.
      const bbLo = buf.readUInt32LE(off + 0);
      const bbHi = is64bit && descSize >= 64 ? buf.readUInt32LE(off + 32) : 0;
      const ibLo = buf.readUInt32LE(off + 4);
      const ibHi = is64bit && descSize >= 64 ? buf.readUInt32LE(off + 36) : 0;
      this.metadata.add(bbLo + bbHi * 0x1_0000_0000);
      this.metadata.add(ibLo + ibHi * 0x1_0000_0000);
    }
  }

  /** Superblock + descriptor blocks, and every group's inode table, are metadata (not file data). */
  private markStaticMetadata(): void {
    const { blockSize, descSize, firstDataBlock, groups, inodesPerGroup, inodeSize } = this.geo;
    // Block 0 (boot), the superblock block and the descriptor table blocks of group 0.
    const gdtBlocks = Math.ceil((descSize * groups) / blockSize);
    for (let b = 0; b <= firstDataBlock + gdtBlocks; b++) this.metadata.add(b);
    const inodeTableBlocks = Math.ceil((inodesPerGroup * inodeSize) / blockSize);
    for (const start of this.inodeTableBlock) {
      for (let b = 0; b < inodeTableBlocks; b++) this.metadata.add(start + b);
    }
  }

  private readBlock(block: number): Buffer {
    return this.read(block * this.geo.blockSize, this.geo.blockSize);
  }

  /** The byte offset of a 1-based inode number in the image, or undefined when out of range. */
  private inodeOffset(ino: number): number | undefined {
    const { inodesPerGroup, inodeSize, blockSize, inodesCount } = this.geo;
    if (ino < 1 || ino > inodesCount) return undefined;
    const group = Math.floor((ino - 1) / inodesPerGroup);
    const index = (ino - 1) % inodesPerGroup;
    const tableBlock = this.inodeTableBlock[group];
    if (tableBlock === undefined) return undefined;
    return tableBlock * blockSize + index * inodeSize;
  }

  /** The raw inode bytes for a 1-based inode number, or undefined when it is out of range. */
  private readInode(ino: number): Buffer | undefined {
    const offset = this.inodeOffset(ino);
    if (offset === undefined) return undefined;
    return this.read(offset, this.geo.inodeSize);
  }

  /**
   * The physical blocks of an inode in logical order, resolved from its extent tree or its indirect
   * block map, capped so a malformed image cannot ask for unbounded work. Holes are skipped, so the
   * returned lists carry only blocks that actually exist on disk.
   */
  private inodeBlocks(inode: Buffer): { blocks: number[]; logical: number[] } {
    const flags = inode.readUInt32LE(32);
    const blocks: number[] = [];
    const logical: number[] = [];
    if (flags & EXT4_INLINE_DATA_FL) return { blocks, logical }; // data lives in the inode itself
    const iblock = inode.subarray(40, 40 + 60);
    if (flags & EXT4_EXTENTS_FL) this.walkExtents(iblock, blocks, logical, 0);
    else this.walkIndirect(iblock, blocks, logical);
    return { blocks, logical };
  }

  /** Walk an extent header (12 bytes) + its entries, recursing through index nodes. */
  private walkExtents(node: Buffer, blocks: number[], logical: number[], depth: number): void {
    if (depth > MAX_EXTENT_DEPTH || node.length < 12) return;
    if (node.readUInt16LE(0) !== EXTENT_MAGIC) return;
    const entries = node.readUInt16LE(2);
    const treeDepth = node.readUInt16LE(6);
    for (let i = 0; i < entries; i++) {
      const off = 12 + i * 12;
      if (off + 12 > node.length) break;
      if (treeDepth === 0) {
        // Leaf: an ext4_extent — a run of contiguous blocks.
        const eeBlock = node.readUInt32LE(off);
        let len = node.readUInt16LE(off + 4);
        if (len > 32768) len = len - 32768; // uninitialized extent; the blocks are still allocated
        const startHi = node.readUInt16LE(off + 6);
        const startLo = node.readUInt32LE(off + 8);
        const start = startLo + startHi * 0x1_0000_0000;
        for (let b = 0; b < len; b++) {
          if (blocks.length >= MAX_BLOCKS_PER_FILE) return;
          const phys = start + b;
          if (phys >= 2 && phys < this.geo.blocksCount) {
            blocks.push(phys);
            logical.push(eeBlock + b);
          }
        }
      } else {
        // Index: points at a child node one block long.
        const leafLo = node.readUInt32LE(off + 4);
        const leafHi = node.readUInt16LE(off + 8);
        const child = leafLo + leafHi * 0x1_0000_0000;
        if (child >= 2 && child < this.geo.blocksCount) this.walkExtents(this.readBlock(child), blocks, logical, depth + 1);
      }
      if (blocks.length >= MAX_BLOCKS_PER_FILE) return;
    }
  }

  /** Walk the classic ext2/ext3 indirect block map: 12 direct, then single/double/triple indirect. */
  private walkIndirect(iblock: Buffer, blocks: number[], logical: number[]): void {
    const ptrsPerBlock = this.geo.blockSize / 4;
    let logicalBlock = 0;
    const add = (phys: number): boolean => {
      if (blocks.length >= MAX_BLOCKS_PER_FILE) return false;
      if (phys >= 2 && phys < this.geo.blocksCount) {
        blocks.push(phys);
        logical.push(logicalBlock);
      }
      logicalBlock++;
      return true;
    };
    // 12 direct pointers.
    for (let i = 0; i < 12; i++) {
      const phys = iblock.readUInt32LE(i * 4);
      if (phys === 0) logicalBlock++;
      else if (!add(phys)) return;
    }
    const single = iblock.readUInt32LE(12 * 4);
    const double = iblock.readUInt32LE(13 * 4);
    const triple = iblock.readUInt32LE(14 * 4);

    const walkSingle = (ind: number): boolean => {
      if (ind === 0) {
        logicalBlock += ptrsPerBlock;
        return true;
      }
      const buf = this.readBlock(ind);
      for (let i = 0; i < ptrsPerBlock; i++) {
        const phys = buf.readUInt32LE(i * 4);
        if (phys === 0) logicalBlock++;
        else if (!add(phys)) return false;
      }
      return true;
    };
    const walkDouble = (ind: number): boolean => {
      if (ind === 0) {
        logicalBlock += ptrsPerBlock * ptrsPerBlock;
        return true;
      }
      const buf = this.readBlock(ind);
      for (let i = 0; i < ptrsPerBlock; i++) {
        if (!walkSingle(buf.readUInt32LE(i * 4))) return false;
      }
      return true;
    };
    if (!walkSingle(single)) return;
    if (!walkDouble(double)) return;
    if (triple !== 0) {
      const buf = this.readBlock(triple);
      for (let i = 0; i < ptrsPerBlock; i++) {
        if (!walkDouble(buf.readUInt32LE(i * 4))) return;
      }
    }
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
    const inode = this.readInode(ino);
    if (!inode) return;
    const { blocks, logical } = this.inodeBlocks(inode);
    if (parentPath !== '') {
      // Record the directory's own blocks so metadata writes to it map to the directory.
      this.register({ path: parentPath, isDir: true, size: inode.readUInt32LE(4), ino, blocks, logical });
    }
    const dirData = this.readAll(blocks);
    // A directory's entries are a per-block linked list of ext4_dir_entry_2; walking the whole data
    // by rec_len steps block by block, and an htree index block (a single inode-0 record spanning
    // the block) is skipped like any other empty record.
    const { blockSize, hasFileType } = this.geo;
    for (let base = 0; base < dirData.length; base += blockSize) {
      let off = base;
      const blockEnd = Math.min(base + blockSize, dirData.length);
      while (off + 8 <= blockEnd) {
        const childIno = dirData.readUInt32LE(off);
        const recLen = dirData.readUInt16LE(off + 4);
        const nameLen = dirData[off + 6]!;
        if (recLen < 8) break; // corrupt: stop this block
        if (childIno !== 0 && nameLen !== 0 && off + 8 + nameLen <= blockEnd) {
          const name = dirData.subarray(off + 8, off + 8 + nameLen).toString('utf8');
          if (name !== '.' && name !== '..') {
            const path = `${parentPath}/${name}`;
            const child = this.readInode(childIno);
            if (child) {
              const mode = child.readUInt16LE(0) & S_IFMT;
              const fileType = hasFileType ? dirData[off + 7]! : 0;
              const isDir = mode === S_IFDIR || fileType === 2;
              if (isDir) {
                this.walkDir(childIno, path, visited, depth + 1);
              } else if (mode === S_IFREG || mode === S_IFLNK || fileType === 1) {
                const sizeLo = child.readUInt32LE(4);
                const sizeHi = child.readUInt32LE(108);
                const size = sizeLo + sizeHi * 0x1_0000_0000;
                const cb = this.inodeBlocks(child);
                this.register({ path, isDir: false, size, ino: childIno, blocks: cb.blocks, logical: cb.logical });
              }
            }
          }
        }
        off += recLen;
      }
    }
  }

  private readAll(blocks: number[]): Buffer {
    if (blocks.length === 0) return Buffer.alloc(0);
    return Buffer.concat(blocks.map((b) => this.readBlock(b)));
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

  /** The byte extents (offset/length pairs) a file occupies in the image, in logical order. */
  extents(path: string): Array<{ offset: number; length: number }> {
    const rec = this.files.find((f) => f.path === path);
    if (!rec) return [];
    return rec.blocks.map((b) => ({ offset: b * this.geo.blockSize, length: this.geo.blockSize }));
  }

  /** A file's current inode attributes: permission bits, owner uid/gid, and size. */
  inodeAttrs(path: string): { mode: number; uid: number; gid: number; size: number } | undefined {
    const rec = this.files.find((f) => f.path === path);
    if (!rec) return undefined;
    const inode = this.readInode(rec.ino);
    if (!inode) return undefined;
    return {
      mode: inode.readUInt16LE(0) & 0o7777, // permission bits (type bits stripped)
      uid: inode.readUInt16LE(2) | (inode.readUInt16LE(120) << 16),
      gid: inode.readUInt16LE(24) | (inode.readUInt16LE(122) << 16),
      size: inode.readUInt32LE(4) + inode.readUInt32LE(108) * 0x1_0000_0000,
    };
  }

  /** The byte offset + size of a file's inode in the image (for rewriting its mode/owner). */
  inodeLocation(path: string): { offset: number; size: number; ino: number } | undefined {
    const rec = this.files.find((f) => f.path === path);
    if (!rec) return undefined;
    const offset = this.inodeOffset(rec.ino);
    if (offset === undefined) return undefined;
    return { offset, size: this.geo.inodeSize, ino: rec.ino };
  }

  /** What {@link patchExt4Inode} needs to recompute an inode's checksum for this filesystem. */
  csumInfo(): Ext4CsumInfo {
    return { inodeSize: this.geo.inodeSize, csumSeed: this.geo.csumSeed, metadataCsum: this.geo.metadataCsum };
  }
}

function pushMerged(out: TouchedFile[], t: TouchedFile): void {
  const last = out[out.length - 1];
  if (last && last.path === t.path && last.fileOffset + last.bytes === t.fileOffset) {
    last.bytes += t.bytes;
  } else {
    out.push(t);
  }
}
