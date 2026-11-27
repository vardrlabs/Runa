export const MAGIC = [0x52, 0x55] as const;
export const PROTOCOL_VERSION = 0x01;
export const HEADER_LEN = 32;

export const FT = {
  JOIN: 0x01,
  JOIN_ACK: 0x02,
  DOC_UPDATE: 0x03,
  DOC_SYNC_REQ: 0x04,
  DOC_SYNC_RESP: 0x05,
  AWARENESS: 0x06,
  PEER_JOIN: 0x07,
  PEER_LEAVE: 0x08,
  DOC_ACK: 0x09,
  SHRED_REQUEST: 0x10,
  SHRED_VOTE: 0x11,
  SHRED_CANCEL: 0x12,
  PURGE: 0x13,
  PURGE_ACK: 0x14,
  RESTART_NOTICE: 0x15,
  RESTART_TICKET: 0x16,
  PING: 0x17,
  PONG: 0x18,
  EPOCH_KEY: 0x20,
  TTL_EXTEND: 0x22,
  SNAPSHOT: 0x21,
  EVICT_COMMIT: 0x23,
  EVICT_REQUEST: 0x24,
  EVICT_VOTE: 0x25,
  EVICT_CANCEL: 0x26,
  ERROR: 0x30,
} as const;

export type FrameType = (typeof FT)[keyof typeof FT];

export interface FrameHeader {
  version: number;
  frameType: number;
  roomId: Uint8Array;
  epoch: number;
  nonceSess: Uint8Array;
  flags: number;
}

export function encodeHeader(h: FrameHeader): Uint8Array {
  if (h.roomId.length !== 16) throw new Error("roomId must be 16 bytes");
  if (h.nonceSess.length !== 4) throw new Error("nonceSess must be 4 bytes");
  const out = new Uint8Array(HEADER_LEN);
  out[0] = MAGIC[0];
  out[1] = MAGIC[1];
  out[2] = h.version;
  out[3] = h.frameType;
  out.set(h.roomId, 4);
  new DataView(out.buffer).setUint32(20, h.epoch, false);
  out.set(h.nonceSess, 24);
  new DataView(out.buffer).setUint32(28, h.flags, false);
  return out;
}

export interface ParsedFrame {
  header: FrameHeader;
  body: Uint8Array;
}

export function parseFrame(bytes: Uint8Array): ParsedFrame | null {
  if (bytes.length < HEADER_LEN) return null;
  if (bytes[0] !== MAGIC[0] || bytes[1] !== MAGIC[1]) return null;
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  const header: FrameHeader = {
    version: bytes[2],
    frameType: bytes[3],
    roomId: bytes.slice(4, 20),
    epoch: view.getUint32(20, false),
    nonceSess: bytes.slice(24, 28),
    flags: view.getUint32(28, false),
  };
  return { header, body: bytes.slice(HEADER_LEN) };
}

export interface EnvelopedFrame extends ParsedFrame {
  senderId: Uint8Array;
}

export function stripEnvelope(bytes: Uint8Array): EnvelopedFrame | null {
  const parsed = parseFrame(bytes);
  if (!parsed) return null;
  if (bytes.length < HEADER_LEN + 16) return null;
  return { ...parsed, senderId: bytes.slice(HEADER_LEN, HEADER_LEN + 16), body: bytes.slice(HEADER_LEN + 16) };
}

export function buildFrame(
  frameType: number,
  roomId: Uint8Array,
  epoch: number,
  sess: Uint8Array,
  payload?: Uint8Array,
  flags = 0,
): Uint8Array {
  const header = encodeHeader({ version: PROTOCOL_VERSION, frameType, roomId, epoch, nonceSess: sess, flags });
  if (!payload?.length) return header;
  const out = new Uint8Array(HEADER_LEN + payload.length);
  out.set(header);
  out.set(payload, HEADER_LEN);
  return out;
}

export function buildJsonFrame(
  frameType: number,
  roomId: Uint8Array,
  epoch: number,
  value: unknown,
): Uint8Array {
  return buildFrame(frameType, roomId, epoch, new Uint8Array(4), new TextEncoder().encode(JSON.stringify(value)));
}

export function snapshotCovers(body: Uint8Array): bigint {
  if (body.length < 8) throw new Error("snapshot body missing covers index");
  let c = 0n;
  for (let i = 0; i < 8; i++) c = (c << 8n) | BigInt(body[i]);
  return c;
}

export function concatBytes(...parts: Uint8Array[]): Uint8Array {
  const total = parts.reduce((n, p) => n + p.length, 0);
  const out = new Uint8Array(total);
  let off = 0;
  for (const p of parts) {
    out.set(p, off);
    off += p.length;
  }
  return out;
}
