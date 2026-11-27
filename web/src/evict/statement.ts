import { concatBytes } from "../crypto/keys";
import { canonicalRosterBytes, type RosterEntry } from "../shred/roster";

/// The fixed statement each vote to remove someone or change the link signs
/// (PROTOCOL.md amendment K). The server checks these signatures itself, so
/// the layout is binary and fixed rather than CBOR:
/// `"runa/v1/evict" || room_id || request_id || root (u32 BE) || target
/// || target key digest || voter || verifier`. The u32 is the room's root
/// epoch when the request was made: it moves only on a re-root, so a vote
/// survives the room's ordinary key steps and is never good after a re-root.
/// The digest is SHA-256 of the target's signing key (`keyDigest`); the
/// server knows the target's other connections by it. A link change names
/// neither, and both are all zero.
export const EVICT_DOMAIN = new TextEncoder().encode("runa/v1/evict");
export const ZERO_PEER = new Uint8Array(16);
export const ZERO_KEY_DIGEST = new Uint8Array(32);
const ID_LEN = 16;
const DIGEST_LEN = 32;
const VERIFIER_LEN = 32;

export function voteStatement(
  roomId: Uint8Array,
  requestId: Uint8Array,
  root: number,
  target: Uint8Array | null,
  targetKeyDigest: Uint8Array | null,
  voter: Uint8Array,
  newVerifier: Uint8Array,
): Uint8Array {
  if (roomId.length !== ID_LEN || requestId.length !== ID_LEN || voter.length !== ID_LEN) {
    throw new Error("room, request and peer ids are 16 bytes");
  }
  if ((target === null) !== (targetKeyDigest === null)) throw new Error("a target is named by its peer id and its key");
  if (target && (target.length !== ID_LEN || bytesEqual(target, ZERO_PEER))) throw new Error("a peer id is 16 bytes, not all zero");
  if (targetKeyDigest && (targetKeyDigest.length !== DIGEST_LEN || bytesEqual(targetKeyDigest, ZERO_KEY_DIGEST))) {
    throw new Error("a key digest is 32 bytes, not all zero");
  }
  if (newVerifier.length !== VERIFIER_LEN) throw new Error("a verifier is 32 bytes");
  if (!Number.isInteger(root) || root < 0 || root > 0xffffffff) throw new Error("a root epoch is a u32");
  const r = new Uint8Array(4);
  new DataView(r.buffer).setUint32(0, root, false);
  return concatBytes(EVICT_DOMAIN, roomId, requestId, r, target ?? ZERO_PEER, targetKeyDigest ?? ZERO_KEY_DIGEST, voter, newVerifier);
}

/// SHA-256 of a signing key's raw bytes (32 for Ed25519, the 65-byte
/// uncompressed point for P-256), exactly as the server digests the key a
/// peer sent in its JOIN.
export async function keyDigest(pubkey: Uint8Array): Promise<Uint8Array> {
  return new Uint8Array(await crypto.subtle.digest("SHA-256", pubkey as BufferSource));
}

/// SHA-256 of the canonical roster bytes the shred machine hashes, as raw
/// bytes: what a request carries so every member can see it was made with
/// the same list of people.
export async function rosterDigest(roster: RosterEntry[]): Promise<Uint8Array> {
  return new Uint8Array(await crypto.subtle.digest("SHA-256", canonicalRosterBytes(roster) as BufferSource));
}

export function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return false;
  return true;
}

export function hexOf(b: Uint8Array): string {
  return Array.from(b, (x) => x.toString(16).padStart(2, "0")).join("");
}
