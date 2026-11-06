import { toB64, fromB64 } from "../transport/socket";

export interface RosterEntry {
  peerId: Uint8Array;
  pubkey?: Uint8Array;
  /// Key-agreement key and its signature (amendment J). The canonical bytes
  /// ignore them, so roster hashes do not change.
  kxPub?: Uint8Array;
  kxSig?: Uint8Array;
  joinedAtSeq: number;
}

export function canonicalRosterBytes(roster: RosterEntry[]): Uint8Array {
  const sorted = [...roster].sort((a, b) => {
    const seqDiff = a.joinedAtSeq - b.joinedAtSeq;
    if (seqDiff !== 0) return seqDiff;
    return cmp(a.peerId, b.peerId);
  });
  const enc = new TextEncoder();
  const parts: Uint8Array[] = [];
  for (const entry of sorted) {
    parts.push(enc.encode(toB64(entry.peerId)));
    parts.push(new Uint8Array([entry.pubkey ? entry.pubkey.length : 0]));
    if (entry.pubkey) parts.push(entry.pubkey);
    const seq = new Uint8Array(8);
    new DataView(seq.buffer).setBigUint64(0, BigInt(entry.joinedAtSeq), false);
    parts.push(seq);
  }
  const total = parts.reduce((n, p) => n + p.length, 0);
  const out = new Uint8Array(total);
  let off = 0;
  for (const p of parts) {
    out.set(p, off);
    off += p.length;
  }
  return out;
}

function cmp(a: Uint8Array, b: Uint8Array): number {
  for (let i = 0; i < Math.min(a.length, b.length); i++) {
    if (a[i] !== b[i]) return a[i] - b[i];
  }
  return a.length - b.length;
}

export async function rosterHash(roster: RosterEntry[]): Promise<string> {
  const digest = await crypto.subtle.digest("SHA-256", canonicalRosterBytes(roster) as BufferSource);
  return toB64(new Uint8Array(digest));
}

export { toB64, fromB64 };
