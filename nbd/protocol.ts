import type { Socket } from 'node:net';
import { BlissError } from '../errors';

/**
 * NBD (Network Block Device) protocol constants and framing helpers.
 * Implements the "fixed newstyle" negotiation that QEMU speaks. See
 * https://github.com/NetworkBlockDevice/nbd/blob/master/doc/proto.md
 */

// Handshake magics.
export const NBDMAGIC = 0x4e42444d41474943n; // "NBDMAGIC"
export const IHAVEOPT = 0x49484156454f5054n; // "IHAVEOPT"
export const REP_MAGIC = 0x0003e889045565a9n; // option reply magic
export const REQUEST_MAGIC = 0x25609513; // transmission request
export const SIMPLE_REPLY_MAGIC = 0x67446698; // transmission simple reply

// Server handshake flags (uint16).
export const NBD_FLAG_FIXED_NEWSTYLE = 1 << 0;
export const NBD_FLAG_NO_ZEROES = 1 << 1;
// Client handshake flags (uint32).
export const NBD_FLAG_C_FIXED_NEWSTYLE = 1 << 0;
export const NBD_FLAG_C_NO_ZEROES = 1 << 1;

// Per-export transmission flags (uint16).
export const NBD_FLAG_HAS_FLAGS = 1 << 0;
export const NBD_FLAG_READ_ONLY = 1 << 1;
export const NBD_FLAG_SEND_FLUSH = 1 << 2;
export const NBD_FLAG_SEND_FUA = 1 << 3;
export const NBD_FLAG_SEND_TRIM = 1 << 5;

// Options (client → server).
export const NBD_OPT_EXPORT_NAME = 1;
export const NBD_OPT_ABORT = 2;
export const NBD_OPT_LIST = 3;
export const NBD_OPT_INFO = 6;
export const NBD_OPT_GO = 7;

// Option replies (server → client).
export const NBD_REP_ACK = 1;
export const NBD_REP_SERVER = 2;
export const NBD_REP_INFO = 3;
export const NBD_REP_ERR_UNSUP = 0x80000001;
export const NBD_REP_ERR_POLICY = 0x80000002;
export const NBD_REP_ERR_INVALID = 0x80000003;
export const NBD_REP_ERR_UNKNOWN = 0x80000006;

// Info types (for INFO/GO).
export const NBD_INFO_EXPORT = 0;
export const NBD_INFO_NAME = 1;
export const NBD_INFO_BLOCK_SIZE = 3;

// Transmission commands.
export const NBD_CMD_READ = 0;
export const NBD_CMD_WRITE = 1;
export const NBD_CMD_DISC = 2;
export const NBD_CMD_FLUSH = 3;
export const NBD_CMD_TRIM = 4;

// Reply/command errors (errno-style).
export const NBD_EPERM = 1;
export const NBD_EINVAL = 22;
export const NBD_ENOSPC = 28;
export const NBD_EIO = 5;

/** The largest request either engine accepts (what QEMU sends at most). */
export const NBD_MAX_REQUEST = 32 * 1024 * 1024;
/** The largest option either engine reads during negotiation. */
export const NBD_MAX_OPTION = 64 * 1024;
/** Guest connections either engine serves at once. */
export const NBD_MAX_CONNECTIONS = 64;

/**
 * Reads an exact number of bytes from a socket, buffering incoming chunks.
 * `read(n)` resolves once `n` bytes are available, or rejects if the connection
 * ends first.
 */
export class ByteReader {
  private chunks: Buffer[] = [];
  private length = 0;
  private ended = false;
  private error?: Error;
  private waiter?: { n: number; resolve: (b: Buffer) => void; reject: (e: unknown) => void };

  constructor(sock: Socket) {
    sock.on('data', (d: Buffer) => {
      this.chunks.push(d);
      this.length += d.length;
      this.settle();
    });
    sock.on('end', () => {
      this.ended = true;
      this.settle();
    });
    sock.on('close', () => {
      this.ended = true;
      this.settle();
    });
    sock.on('error', (e) => {
      this.error = e;
      this.settle();
    });
  }

  read(n: number): Promise<Buffer> {
    if (this.waiter) return Promise.reject(new BlissError('ByteReader: concurrent read'));
    return new Promise<Buffer>((resolve, reject) => {
      this.waiter = { n, resolve, reject };
      this.settle();
    });
  }

  private settle(): void {
    const w = this.waiter;
    if (!w) return;
    if (this.length >= w.n) {
      const all = this.chunks.length === 1 ? this.chunks[0]! : Buffer.concat(this.chunks, this.length);
      const out = all.subarray(0, w.n);
      const rest = all.subarray(w.n);
      this.chunks = rest.length ? [rest] : [];
      this.length = rest.length;
      this.waiter = undefined;
      w.resolve(out);
    } else if (this.error) {
      this.waiter = undefined;
      w.reject(this.error);
    } else if (this.ended) {
      this.waiter = undefined;
      w.reject(new BlissError('connection closed'));
    }
  }
}

/** Write a buffer to a socket, awaiting drain on backpressure. */
export function writeAll(sock: Socket, buf: Buffer): Promise<void> {
  return new Promise((resolve, reject) => {
    const onErr = (e: Error) => reject(e);
    sock.once('error', onErr);
    const ok = sock.write(buf, (err) => {
      sock.off('error', onErr);
      if (err) reject(err);
      else if (ok) resolve();
    });
    if (!ok) sock.once('drain', () => {
      sock.off('error', onErr);
      resolve();
    });
  });
}
