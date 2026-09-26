import type { DriveConfig, NbdDiskSpec } from '../types';

/** The drive to attach for an {@link NbdDiskSpec}, plus any overlay to create. */
export interface ResolvedNbdDisk {
  drive: DriveConfig;
  /**
   * When present, the VM must ensure a qcow2 overlay at `path` backed by
   * `backingFile` (the NBD url) exists before attaching `drive` — reads fall
   * through to the NBD base, writes stay local (copy-on-write "layering").
   */
  overlay?: { path: string; backingFile: string; backingFormat: 'raw' | 'qcow2' };
}

/**
 * Turn an {@link NbdDiskSpec} + its resolved `nbd:` url into a {@link DriveConfig}
 * (and, when layering, the overlay to create). Pure — no I/O — so it's unit
 * tested; the VM performs the actual overlay creation/rebase at start.
 */
export function nbdDiskToDrive(spec: NbdDiskSpec, nbdUrl: string, id: string): ResolvedNbdDisk {
  const format = spec.format ?? 'raw';
  const bootindex = spec.bootindex ?? (spec.role === 'boot' ? 0 : undefined);
  const iface = spec.interface ?? 'virtio';

  if (spec.overlay) {
    // Layering: attach the local writable overlay; the base is read over NBD.
    return {
      drive: { file: spec.overlay, format: 'qcow2', interface: iface, bootindex, id },
      overlay: { path: spec.overlay, backingFile: nbdUrl, backingFormat: format },
    };
  }
  // Direct: attach the NBD export itself (optionally read-only).
  return {
    drive: { file: nbdUrl, format, interface: iface, readonly: spec.readonly, bootindex, id },
  };
}
