import * as cbor2 from "cbor2";
import { signPayload, verifyPayload, type Identity, type SignatureAlg } from "../crypto/identity";
import { concatBytes } from "../crypto/keys";
import type { Wrap } from "../epoch/frame";
import type { Policy } from "../shred/machine";
import { MAX_WRAP_CT } from "./reroot";
import { ZERO_KEY_DIGEST, ZERO_PEER } from "./statement";

/// The EVICT frames of PROTOCOL.md amendment K. EVICT_REQUEST, EVICT_VOTE and
/// EVICT_CANCEL are canonical CBOR maps sealed under the room's content key
/// like the shred frames. EVICT_COMMIT is a fixed binary clear part the
/// server reads, then a signed CBOR tail only members read.

export const MAX_VOTES = 32;
export const MAX_DEADLINE_MS = 3_600_000;
export const MAX_CONFIG_LEN = 4096;
export const SIG_LEN = 64;
const MAX_TAIL = 64 * 1024;
const COMMIT_DOMAIN = new TextEncoder().encode("runa/v1/evict-commit");
const EMPTY = new Uint8Array(0);

export interface EvictRequest {
  id: Uint8Array;
  epoch: number;
  /// Null for a link change.
  target: Uint8Array | null;
  /// The target's signing key as the proposer's roster shows it.
  targetKey: Uint8Array | null;
  verifier: Uint8Array;
  /// SHA-256 of the proposer's canonical roster.
  roster: Uint8Array;
  policy: Policy;
  deadline: number;
  /// The proposer's signature over the vote statement: its own approval.
  sig: Uint8Array;
}

export interface EvictVote {
  id: Uint8Array;
  vote: "APPROVE" | "REJECT";
  sig: Uint8Array | null;
}

export interface EvictCancel {
  id: Uint8Array;
}

export interface Ballot {
  voter: Uint8Array;
  sig: Uint8Array;
}

export interface CommitClear {
  requestId: Uint8Array;
  target: Uint8Array | null;
  /// SHA-256 of the target's signing key, as every vote signs it (Task 5's
  /// `keyDigest`). Null exactly when `target` is.
  targetKeyDigest: Uint8Array | null;
  verifier: Uint8Array;
  salt: Uint8Array;
  config: Uint8Array;
  votes: Ballot[];
}

export interface CommitTail {
  root: number;
  sender: Uint8Array;
  confirm: Uint8Array;
  wraps: Wrap[];
}

export interface DecodedCommit {
  clear: CommitClear;
  clearBytes: Uint8Array;
  tail: CommitTail;
  /// The tail's CBOR without "sig": what the signature covers.
  unsigned: Uint8Array;
  sig: Uint8Array;
}

const isU32 = (v: unknown): v is number => typeof v === "number" && Number.isInteger(v) && v >= 0 && v <= 0xffffffff;

function isBytes(v: unknown, min: number, max = min): v is Uint8Array {
  return v instanceof Uint8Array && v.length >= min && v.length <= max;
}

const isZero = (b: Uint8Array): boolean => b.every((x) => x === 0);

function sameBytes(a: Uint8Array, b: Uint8Array): boolean {
  return a.length === b.length && a.every((x, i) => x === b[i]);
}

function decodeMap(bytes: Uint8Array): Record<string, unknown> | null {
  let raw: unknown;
  try {
    raw = cbor2.decode(bytes);
  } catch {
    return null;
  }
  if (typeof raw !== "object" || raw === null || Array.isArray(raw) || raw instanceof Uint8Array) return null;
  return raw as Record<string, unknown>;
}

/// The one object shape each direction uses, so key order cannot drift.
function requestShape(r: EvictRequest) {
  return {
    type: "EVICT_REQUEST",
    id: r.id,
    epoch: r.epoch,
    target: r.target ?? ZERO_PEER,
    targetKey: r.targetKey ?? EMPTY,
    verifier: r.verifier,
    roster: r.roster,
    policy: r.policy,
    deadline: r.deadline,
    sig: r.sig,
  };
}

export function encodeRequest(r: EvictRequest): Uint8Array {
  return cbor2.encode(requestShape(r));
}

export function decodeRequest(bytes: Uint8Array): EvictRequest | null {
  const o = decodeMap(bytes);
  if (!o || o.type !== "EVICT_REQUEST") return null;
  if (!isBytes(o.id, 16) || !isU32(o.epoch) || !isBytes(o.target, 16) || !isBytes(o.targetKey, 0, 65)) return null;
  if (!isBytes(o.verifier, 32) || !isBytes(o.roster, 32) || !isBytes(o.sig, SIG_LEN)) return null;
  if (o.policy !== "UNANIMOUS") return null;
  if (!isU32(o.deadline) || o.deadline > MAX_DEADLINE_MS) return null;
  const target = isZero(o.target) ? null : o.target;
  const keyLen = o.targetKey.length;
  if (target ? keyLen !== 32 && keyLen !== 65 : keyLen !== 0) return null;
  const r: EvictRequest = {
    id: o.id,
    epoch: o.epoch,
    target,
    targetKey: target ? o.targetKey : null,
    verifier: o.verifier,
    roster: o.roster,
    policy: o.policy,
    deadline: o.deadline,
    sig: o.sig,
  };
  return sameBytes(cbor2.encode(requestShape(r)), bytes) ? r : null;
}

function voteShape(v: EvictVote) {
  return { type: "EVICT_VOTE", id: v.id, vote: v.vote, sig: v.sig ?? EMPTY };
}

export function encodeVote(v: EvictVote): Uint8Array {
  return cbor2.encode(voteShape(v));
}

export function decodeVote(bytes: Uint8Array): EvictVote | null {
  const o = decodeMap(bytes);
  if (!o || o.type !== "EVICT_VOTE" || !isBytes(o.id, 16)) return null;
  if (o.vote !== "APPROVE" && o.vote !== "REJECT") return null;
  if (!(o.sig instanceof Uint8Array)) return null;
  if (o.vote === "APPROVE" ? o.sig.length !== SIG_LEN : o.sig.length !== 0) return null;
  const v: EvictVote = { id: o.id, vote: o.vote, sig: o.vote === "APPROVE" ? o.sig : null };
  return sameBytes(cbor2.encode(voteShape(v)), bytes) ? v : null;
}

export function encodeCancel(c: EvictCancel): Uint8Array {
  return cbor2.encode({ type: "EVICT_CANCEL", id: c.id });
}

export function decodeCancel(bytes: Uint8Array): EvictCancel | null {
  const o = decodeMap(bytes);
  if (!o || o.type !== "EVICT_CANCEL" || !isBytes(o.id, 16)) return null;
  const c: EvictCancel = { id: o.id };
  return sameBytes(encodeCancel(c), bytes) ? c : null;
}

/// `id || target || target key digest || verifier || salt || config_len
/// (u32 BE) || config || n || n * (voter || 64 || sig)`, exactly as the server
/// parses it.
export function encodeClear(c: CommitClear): Uint8Array {
  if (c.votes.length < 1 || c.votes.length > MAX_VOTES) throw new Error("a commit carries 1 to 32 votes");
  if (c.config.length > MAX_CONFIG_LEN) throw new Error("config too large");
  if ((c.target === null) !== (c.targetKeyDigest === null)) throw new Error("a target is named by its peer id and its key");
  if (c.target && (c.target.length !== 16 || isZero(c.target))) throw new Error("malformed target");
  if (c.targetKeyDigest && (c.targetKeyDigest.length !== 32 || isZero(c.targetKeyDigest))) throw new Error("malformed key digest");
  if (c.requestId.length !== 16 || c.verifier.length !== 32 || c.salt.length !== 16) throw new Error("malformed request id, verifier or salt");
  const len = new Uint8Array(4);
  new DataView(len.buffer).setUint32(0, c.config.length, false);
  const parts: Uint8Array[] = [
    c.requestId,
    c.target ?? ZERO_PEER,
    c.targetKeyDigest ?? ZERO_KEY_DIGEST,
    c.verifier,
    c.salt,
    len,
    c.config,
    new Uint8Array([c.votes.length]),
  ];
  for (const v of c.votes) {
    if (v.voter.length !== 16 || v.sig.length !== SIG_LEN) throw new Error("malformed vote");
    parts.push(v.voter, new Uint8Array([SIG_LEN]), v.sig);
  }
  return concatBytes(...parts);
}

function tailShape(t: CommitTail) {
  return { root: t.root, sender: t.sender, confirm: t.confirm, wraps: t.wraps.map((w) => ({ p: w.p, iv: w.iv, ct: w.ct })) };
}

function signedBytes(header: Uint8Array, clearBytes: Uint8Array, unsigned: Uint8Array): Uint8Array {
  return concatBytes(COMMIT_DOMAIN, header, clearBytes, unsigned);
}

/// The checks on a tail's fields, shared by both directions so that the
/// encoder never emits what a member's decoder refuses.
function tailFieldsOk(tt: object): boolean {
  const t = tt as Record<string, unknown>;
  if (!isU32(t.root) || !isBytes(t.sender, 16) || !isBytes(t.confirm, 16)) return false;
  if (!Array.isArray(t.wraps) || t.wraps.length > MAX_VOTES) return false;
  return t.wraps.every((w) => {
    if (typeof w !== "object" || w === null) return false;
    const ww = w as Record<string, unknown>;
    return isBytes(ww.p, 16) && isBytes(ww.iv, 12) && isBytes(ww.ct, 16, MAX_WRAP_CT);
  });
}

export async function encodeCommit(header: Uint8Array, clear: CommitClear, tail: CommitTail, identity: Identity): Promise<Uint8Array> {
  if (header.length !== 32) throw new Error("header must be 32 bytes");
  const clearBytes = encodeClear(clear);
  if (!tailFieldsOk(tail)) throw new Error("a commit's tail would be refused by its readers");
  const unsigned = cbor2.encode(tailShape(tail));
  const sig = await signPayload(identity, signedBytes(header, clearBytes, unsigned));
  if (sig.length !== SIG_LEN) throw new Error("unexpected signature length");
  const signed = cbor2.encode({ ...tailShape(tail), sig });
  if (signed.length > MAX_TAIL) throw new Error("a commit's tail is too large");
  return concatBytes(clearBytes, signed);
}

export function decodeCommit(body: Uint8Array): DecodedCommit | null {
  let off = 0;
  const take = (n: number): Uint8Array | null => {
    if (body.length - off < n) return null;
    const s = body.slice(off, off + n);
    off += n;
    return s;
  };
  const requestId = take(16);
  const target = take(16);
  const targetKeyDigest = take(32);
  const verifier = take(32);
  const salt = take(16);
  const lenBytes = take(4);
  if (!requestId || !target || !targetKeyDigest || !verifier || !salt || !lenBytes) return null;
  // Both zero for a link change, neither otherwise, as the server holds it.
  const named = !isZero(target);
  if (named === isZero(targetKeyDigest)) return null;
  const configLen = new DataView(lenBytes.buffer, lenBytes.byteOffset, 4).getUint32(0, false);
  if (configLen > MAX_CONFIG_LEN) return null;
  const config = take(configLen);
  const count = take(1);
  if (!config || !count || count[0] < 1 || count[0] > MAX_VOTES) return null;
  const votes: Ballot[] = [];
  for (let i = 0; i < count[0]; i++) {
    const voter = take(16);
    const sigLen = take(1);
    if (!voter || !sigLen || sigLen[0] !== SIG_LEN) return null;
    const sig = take(SIG_LEN);
    if (!sig) return null;
    votes.push({ voter, sig });
  }
  const clearBytes = body.slice(0, off);
  const tailBytes = body.slice(off);
  if (tailBytes.length === 0 || tailBytes.length > MAX_TAIL) return null;
  const o = decodeMap(tailBytes);
  if (!o || !isBytes(o.sig, SIG_LEN) || !tailFieldsOk(o)) return null;
  const wraps = (o.wraps as Wrap[]).map((w) => ({ p: w.p, iv: w.iv, ct: w.ct }));
  const tail: CommitTail = { root: o.root as number, sender: o.sender as Uint8Array, confirm: o.confirm as Uint8Array, wraps };
  if (!sameBytes(cbor2.encode({ ...tailShape(tail), sig: o.sig }), tailBytes)) return null;
  return {
    clear: {
      requestId,
      target: named ? target : null,
      targetKeyDigest: named ? targetKeyDigest : null,
      verifier,
      salt,
      config,
      votes,
    },
    clearBytes,
    tail,
    unsigned: cbor2.encode(tailShape(tail)),
    sig: o.sig,
  };
}

export function verifyCommit(header: Uint8Array, d: DecodedCommit, alg: SignatureAlg, pubkey: Uint8Array): Promise<boolean> {
  return verifyPayload(alg, pubkey, d.sig, signedBytes(header, d.clearBytes, d.unsigned));
}
