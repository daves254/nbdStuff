import { openSync, readSync } from 'node:fs';
import { BlissError } from '../errors';
import type { FileMapper, NbdBackend, TouchedFile } from './server';

/** A synchronous reader over the disk image (offset/length in bytes). */
export type ImageReader = (offset: number, length: number) => Buffer;

interface FileRec {
  path: string;
  isDir: boolean;
  size: number;
  /** Ordered cluster chain. */
  clusters: number[];
}

interface Geometry {
  bytesPerSector: number;
  sectorsPerCluster: number;
  reservedSectors: number;
  numFATs: number;
  fatSizeSectors: number;
  rootCluster: number;
  dataStartSector: number;
  clusterBytes: number;
  totalSectors: number;
}

/**
 * Maps byte offsets in a **FAT32** image back to guest file names by parsing the
 * BPB, FAT and directory tree. This is the "sector-mapping" approach: QEMU works
 * at the block level, and this recovers *which file* a read/write touches —
 * enabling per-file backup, dedup/reuse across instances, and folder sharing.
 *
 * Parsing is a snapshot; call {@link refresh} after the guest changes the
 * directory/FAT to pick up new/renamed files.
 *
 * @example
 * const mapper = Fat32Mapper.fromFile('./shared.img');
 * const nbd = new NbdServer({ file: './shared.img', size, mapper });
 * nbd.on('access', (e) => console.log(e.command, e.files.map(f => `${f.path}+${f.fileOffset}`)));
 */
export class Fat32Mapper implements FileMapper {
  private geo!: Geometry;
  private fat!: Buffer;
  private clusterToFile = new Map<number, { rec: FileRec; index: number }>();
  files: FileRec[] = [];

  constructor(private readonly read: ImageReader) {
    this.parse();
  }

  static fromFile(path: string): Fat32Mapper {
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
    return new Fat32Mapper(read);
  }

  /** Build a mapper from a synchronous NbdBackend (e.g. FileBackend). */
  static fromBackend(backend: NbdBackend): Fat32Mapper {
    return new Fat32Mapper((offset, length) => backend.read(offset, length) as Buffer);
  }

  /** Re-parse the filesystem (after the guest wrote directory/FAT metadata). */
  refresh(): void {
    this.parse();
  }

  private parse(): void {
    const bpb = this.read(0, 512);
    if (bpb.readUInt16LE(510) !== 0xaa55) throw new BlissError('Not a FAT boot sector (bad 0x55AA signature)');
    const bytesPerSector = bpb.readUInt16LE(11);
    const sectorsPerCluster = bpb[13]!;
    const reservedSectors = bpb.readUInt16LE(14);
    const numFATs = bpb[16]!;
    const rootEntCnt = bpb.readUInt16LE(17);
    const fatSz16 = bpb.readUInt16LE(22);
    const totSec16 = bpb.readUInt16LE(19);
    const totSec32 = bpb.readUInt32LE(32);
    const fatSz32 = bpb.readUInt32LE(36);
    const rootCluster = bpb.readUInt32LE(44);
    if (fatSz16 !== 0 || rootEntCnt !== 0 || !bytesPerSector || !sectorsPerCluster) {
      throw new BlissError('Not a FAT32 filesystem (use ext4 mapper or reformat as FAT32)');
    }
    const dataStartSector = reservedSectors + numFATs * fatSz32;
    // The guest writes this image, so a size it claims is bounded before it is believed: the FATs
    // cannot be larger than the volume (the native engine checks the same).
    const totalSectors = totSec32 || totSec16;
    if (fatSz32 * bytesPerSector > 512 * 1024 * 1024 || (totalSectors && dataStartSector > totalSectors)) {
      throw new BlissError('Not a FAT32 filesystem (its FATs are larger than the volume)');
    }
    this.geo = {
      bytesPerSector,
      sectorsPerCluster,
      reservedSectors,
      numFATs,
      fatSizeSectors: fatSz32,
      rootCluster,
      dataStartSector,
      clusterBytes: sectorsPerCluster * bytesPerSector,
      totalSectors: totSec32 || totSec16,
    };

    // Load the first FAT.
    this.fat = this.read(reservedSectors * bytesPerSector, fatSz32 * bytesPerSector);

    this.clusterToFile = new Map();
    this.files = [];
    this.walkDir(rootCluster, '', new Set(), 0);
  }

  private nextCluster(c: number): number {
    if ((c + 1) * 4 > this.fat.length) return 0x0fffffff;
    return this.fat.readUInt32LE(c * 4) & 0x0fffffff;
  }

  /**
   * A cluster chain, at most `cap` long, stopping at a loop or at a cluster another entry already
   * owns: cross-linked entries (a guest can write any FAT it likes) must not multiply the work.
   */
  private clusterChain(first: number, cap: number): number[] {
    const out: number[] = [];
    let c = first;
    const seen = new Set<number>();
    while (c >= 2 && c < 0x0ffffff7 && !seen.has(c) && !this.clusterToFile.has(c) && out.length < cap) {
      seen.add(c);
      out.push(c);
      c = this.nextCluster(c);
    }
    return out;
  }

  private clusterStartByte(c: number): number {
    return (this.geo.dataStartSector + (c - 2) * this.geo.sectorsPerCluster) * this.geo.bytesPerSector;
  }

  private readCluster(c: number): Buffer {
    return this.read(this.clusterStartByte(c), this.geo.clusterBytes);
  }

  private register(rec: FileRec): void {
    this.files.push(rec);
    rec.clusters.forEach((c, index) => this.clusterToFile.set(c, { rec, index }));
  }

  private walkDir(firstCluster: number, parentPath: string, visited: Set<number>, depth: number): void {
    if (depth > 64 || visited.has(firstCluster)) return;
    visited.add(firstCluster);
    // A FAT directory holds at most 65,536 entries (2 MiB), however long a chain the image claims.
    const chain = this.clusterChain(firstCluster, Math.max(1, Math.floor((2 * 1024 * 1024) / this.geo.clusterBytes)));
    if (parentPath !== '' || firstCluster !== this.geo.rootCluster) {
      // record the directory's own clusters too (so metadata writes map to it)
      this.register({ path: parentPath || '/', isDir: true, size: 0, clusters: chain });
    }
    const buf = Buffer.concat(chain.map((c) => this.readCluster(c)));
    let lfn = '';
    for (let off = 0; off + 32 <= buf.length; off += 32) {
      const b0 = buf[off]!;
      if (b0 === 0x00) break; // end of directory
      if (b0 === 0xe5) {
        lfn = '';
        continue;
      }
      const attr = buf[off + 11]!;
      if (attr === 0x0f) {
        // Long file name entry — assemble UCS-2 fragments (13 chars per entry).
        lfn = decodeLfn(buf, off) + lfn;
        continue;
      }
      if (attr & 0x08) {
        lfn = '';
        continue;
      } // volume label
      const name = lfn || decodeShortName(buf, off);
      lfn = '';
      if (name === '.' || name === '..') continue;
      const firstClu = ((buf.readUInt16LE(off + 20) << 16) | buf.readUInt16LE(off + 26)) >>> 0;
      const size = buf.readUInt32LE(off + 28);
      const path = `${parentPath}/${name}`;
      if (attr & 0x10) {
        if (firstClu >= 2) this.walkDir(firstClu, path, visited, depth + 1);
      } else if (firstClu >= 2) {
        // A file holds no more clusters than its size needs, whatever chain the FAT claims.
        this.register({ path, isDir: false, size, clusters: this.clusterChain(firstClu, Math.max(1, Math.ceil(size / this.geo.clusterBytes))) });
      } else {
        this.register({ path, isDir: false, size, clusters: [] }); // empty file
      }
    }
  }

  // --- SectorMapper ---------------------------------------------------------

  /** Resolve the guest files touched by a byte range, merged per file. */
  mapRange(offset: number, length: number): TouchedFile[] {
    const out: TouchedFile[] = [];
    const { clusterBytes, dataStartSector, bytesPerSector, sectorsPerCluster } = this.geo;
    const dataStartByte = dataStartSector * bytesPerSector;
    let pos = offset;
    const end = offset + length;
    while (pos < end) {
      if (pos < dataStartByte) {
        // Reserved / FAT region — filesystem metadata.
        const chunk = Math.min(end, dataStartByte) - pos;
        pushMerged(out, { path: '<metadata>', fileOffset: pos, bytes: chunk });
        pos += chunk;
        continue;
      }
      const cluster = 2 + Math.floor((pos - dataStartByte) / clusterBytes);
      const clusterStart = dataStartByte + (cluster - 2) * clusterBytes;
      const within = pos - clusterStart;
      const chunk = Math.min(end - pos, clusterBytes - within);
      const hit = this.clusterToFile.get(cluster);
      if (hit) {
        pushMerged(out, {
          path: hit.rec.path,
          fileOffset: hit.index * clusterBytes + within,
          bytes: chunk,
        });
      } else {
        pushMerged(out, { path: '<free>', fileOffset: pos, bytes: chunk });
      }
      pos += chunk;
      void sectorsPerCluster;
    }
    return out;
  }

  /** List parsed files (path + size). */
  list(): Array<{ path: string; size: number; isDir: boolean }> {
    return this.files.map((f) => ({ path: f.path, size: f.size, isDir: f.isDir }));
  }

  /** The byte extents (offset/length pairs) a file occupies in the image. */
  extents(path: string): Array<{ offset: number; length: number }> {
    const rec = this.files.find((f) => f.path === path);
    if (!rec) return [];
    return rec.clusters.map((c) => ({ offset: this.clusterStartByte(c), length: this.geo.clusterBytes }));
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

function decodeShortName(buf: Buffer, off: number): string {
  const raw = buf.subarray(off, off + 11);
  const base = raw.subarray(0, 8).toString('latin1').replace(/ +$/, '');
  const ext = raw.subarray(8, 11).toString('latin1').replace(/ +$/, '');
  const name = ext ? `${base}.${ext}` : base;
  return name.toLowerCase();
}

function decodeLfn(buf: Buffer, off: number): string {
  // 13 UCS-2 chars at offsets 1..10, 14..25, 28..31.
  const ranges = [
    [1, 11],
    [14, 26],
    [28, 32],
  ];
  let s = '';
  for (const [a, b] of ranges) {
    for (let i = a!; i < b!; i += 2) {
      const code = buf.readUInt16LE(off + i);
      if (code === 0 || code === 0xffff) return s;
      s += String.fromCharCode(code);
    }
  }
  return s;
}
