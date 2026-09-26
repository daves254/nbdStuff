/**
 * Make a FAT32 image on the host — the base system image profiles layer over.
 *
 * The library could already *read* FAT32 ({@link Fat32Mapper}); creating one meant booting a
 * throwaway guest just to run `newfs_msdos` against an attached NBD disk. That is a five-minute
 * detour for a file that is entirely determined by its size, so this writes it directly.
 *
 * What it produces is a plain FAT32 volume with no partition table — the whole image is the
 * filesystem, which is what `mount -t vfat /dev/block/vdX` expects and what the mapper parses.
 */
import { closeSync, mkdirSync, openSync, writeSync, ftruncateSync } from 'node:fs';
import { dirname } from 'node:path';
import { BlissError } from '../errors';

const SECTOR = 512;
/** FAT32 is only valid at 65525 clusters or more; below that a driver may read it as FAT16. */
const MIN_CLUSTERS = 65525;

export interface Fat32Options {
  /** Volume size in bytes. Rounded down to a whole sector. */
  size: number;
  /** Volume label, up to 11 characters. Default `SYSTEMDATA`. */
  label?: string;
  /** Sectors per cluster. Chosen from the size when omitted (as `mkfs.vfat` does). */
  sectorsPerCluster?: number;
  /** Volume serial. Derived from the clock when omitted. */
  volumeId?: number;
}

/** The geometry a {@link formatFat32} image was built with. */
export interface Fat32Geometry {
  size: number;
  totalSectors: number;
  reservedSectors: number;
  sectorsPerCluster: number;
  fatSectors: number;
  clusters: number;
  dataStart: number;
  label: string;
}

/** What `mkfs.vfat` picks: bigger clusters for bigger volumes. */
function clusterSizeFor(bytes: number): number {
  const mb = bytes / (1024 * 1024);
  if (mb <= 260) return 1; // 512 B clusters — needed to reach 65525 on a small volume
  if (mb <= 8192) return 8; // 4 KiB
  if (mb <= 16384) return 16; // 8 KiB
  if (mb <= 32768) return 32; // 16 KiB
  return 64; // 32 KiB
}

/** Work out a consistent geometry: the FAT has to be big enough for the clusters it maps. */
export function fat32Geometry(opts: Fat32Options): Fat32Geometry {
  const totalSectors = Math.floor(opts.size / SECTOR);
  const reserved = 32;
  const spc = opts.sectorsPerCluster ?? clusterSizeFor(opts.size);
  if (spc < 1 || (spc & (spc - 1)) !== 0 || spc > 128) {
    throw new BlissError(`sectors per cluster must be a power of two between 1 and 128 (got ${spc})`);
  }
  // Each FAT entry is 4 bytes and there are two FATs, so the FAT size and the cluster count depend
  // on each other. Two passes converge: guess the clusters, size the FAT, re-derive the clusters.
  let fatSectors = 1;
  let clusters = 0;
  for (let i = 0; i < 4; i++) {
    const dataSectors = totalSectors - reserved - 2 * fatSectors;
    clusters = Math.floor(dataSectors / spc);
    fatSectors = Math.ceil(((clusters + 2) * 4) / SECTOR);
  }
  if (clusters < MIN_CLUSTERS) {
    const need = Math.ceil(((MIN_CLUSTERS * spc + reserved + 2 * fatSectors) * SECTOR) / (1024 * 1024));
    throw new BlissError(
      `a FAT32 volume needs at least ${MIN_CLUSTERS} clusters; ${Math.round(opts.size / 1024 / 1024)} MiB at ` +
        `${(spc * SECTOR) / 1024} KiB clusters gives ${clusters}. Use at least ~${need} MiB, or a smaller sectorsPerCluster.`,
    );
  }
  return {
    size: totalSectors * SECTOR,
    totalSectors,
    reservedSectors: reserved,
    sectorsPerCluster: spc,
    fatSectors,
    clusters,
    dataStart: (reserved + 2 * fatSectors) * SECTOR,
    label: (opts.label ?? 'SYSTEMDATA').slice(0, 11).padEnd(11, ' '),
  };
}

/** The 512-byte boot sector (BPB) for a geometry. */
function bootSector(g: Fat32Geometry, volumeId: number): Buffer {
  const b = Buffer.alloc(SECTOR);
  b[0] = 0xeb;
  b[1] = 0x58;
  b[2] = 0x90; // jmp short +0x58; nop
  Buffer.from('MSWIN4.1').copy(b, 3);
  b.writeUInt16LE(SECTOR, 11); // bytes per sector
  b[13] = g.sectorsPerCluster;
  b.writeUInt16LE(g.reservedSectors, 14);
  b[16] = 2; // two FATs, as every formatter writes
  b.writeUInt16LE(0, 17); // root entries: 0 on FAT32
  b.writeUInt16LE(0, 19); // total sectors 16: 0, see offset 32
  b[21] = 0xf8; // fixed disk
  b.writeUInt16LE(0, 22); // FAT size 16: 0 on FAT32
  b.writeUInt16LE(63, 24); // sectors per track
  b.writeUInt16LE(255, 26); // heads
  b.writeUInt32LE(0, 28); // hidden sectors: no partition table
  b.writeUInt32LE(g.totalSectors, 32);
  b.writeUInt32LE(g.fatSectors, 36);
  b.writeUInt16LE(0, 40); // ext flags: both FATs live
  b.writeUInt16LE(0, 42); // version
  b.writeUInt32LE(2, 44); // root directory cluster
  b.writeUInt16LE(1, 48); // FSInfo sector
  b.writeUInt16LE(6, 50); // backup boot sector
  b[64] = 0x80; // drive number
  b[66] = 0x29; // extended boot signature
  b.writeUInt32LE(volumeId >>> 0, 67);
  Buffer.from(g.label).copy(b, 71);
  Buffer.from('FAT32   ').copy(b, 82);
  b.writeUInt16LE(0xaa55, 510);
  return b;
}

/** The FSInfo sector: free-cluster bookkeeping a driver trusts but recomputes when unsure. */
function fsInfoSector(freeClusters: number): Buffer {
  const b = Buffer.alloc(SECTOR);
  b.writeUInt32LE(0x41615252, 0);
  b.writeUInt32LE(0x61417272, 484);
  b.writeUInt32LE(freeClusters, 488);
  b.writeUInt32LE(3, 492); // next free cluster hint (2 is the root directory)
  b.writeUInt32LE(0xaa550000, 508);
  return b;
}

/**
 * Write a FAT32 volume to `path`, replacing whatever is there. Returns the geometry, so a caller
 * knows the cluster size it will be layering over.
 *
 * ```ts
 * formatFat32('./base-system-data.img', { size: 512 * 1024 * 1024, label: 'SYSTEM' });
 * ```
 */
export function formatFat32(path: string, opts: Fat32Options): Fat32Geometry {
  const g = fat32Geometry(opts);
  const volumeId = opts.volumeId ?? (Date.now() & 0xffffffff);
  mkdirSync(dirname(path), { recursive: true }); // like a new layer or image, it may start a fresh folder
  const fd = openSync(path, 'w+');
  try {
    // The image is sized first so the filesystem's last sector really exists.
    ftruncateSync(fd, g.size);

    const boot = bootSector(g, volumeId);
    writeSync(fd, boot, 0, SECTOR, 0);
    writeSync(fd, fsInfoSector(g.clusters - 1), 0, SECTOR, SECTOR);
    // The backup pair at sector 6, which is what a driver falls back to when sector 0 is damaged.
    writeSync(fd, boot, 0, SECTOR, 6 * SECTOR);
    writeSync(fd, fsInfoSector(g.clusters - 1), 0, SECTOR, 7 * SECTOR);

    // Both FATs: the media descriptor, the end-of-chain marker, and cluster 2 (the root directory)
    // as a one-cluster chain that ends there.
    const fatHead = Buffer.alloc(12);
    fatHead.writeUInt32LE(0x0ffffff8, 0);
    fatHead.writeUInt32LE(0x0fffffff, 4);
    fatHead.writeUInt32LE(0x0ffffff8, 8);
    for (const i of [0, 1]) {
      writeSync(fd, fatHead, 0, fatHead.length, (g.reservedSectors + i * g.fatSectors) * SECTOR);
    }

    // The root directory cluster, zeroed apart from its volume label entry.
    const root = Buffer.alloc(g.sectorsPerCluster * SECTOR);
    Buffer.from(g.label).copy(root, 0);
    root[11] = 0x08; // volume-label attribute
    writeSync(fd, root, 0, root.length, g.dataStart);
  } finally {
    closeSync(fd);
  }
  return g;
}
