import * as cbor2 from "cbor2";
import { signPayload, verifyPayload, type Identity, type SignatureAlg } from "../crypto/identity";
import { concatBytes } from "../crypto/keys";

/// The EPOCH_KEY body (PROTOCOL.md amendment J): `len u32 BE || cbor || sig`.
/// Not encrypted under the content key, because a newcomer does not hold the
/// current one; each wrap inside is sealed to one member. The signature covers
/// the frame header too, so a body cannot be moved to another epoch or room.

export type EpochKeyKind = "step" | "handover";

export interface Wrap {
  p: Uint8Array;
  iv: Uint8Array;
  ct: Uint8Array;
}

export interface EpochKeyBody {
  kind: EpochKeyKind;
  from: number;
  to: number;
  root: number;
  sender: Uint8Array;
  roster: Uint8Array;
  confirm: Uint8Array;
  wraps: Wrap[];
}

export interface DecodedEpochKey {
  body: EpochKeyBody;
  cbor: Uint8Array;
  sig: Uint8Array;
}

export const MAX_WRAPS = 32;
export const MAX_HANDOVER_SECRETS = 8192;
const MAX_CT = MAX_HANDOVER_SECRETS * 32 + 16;
/// Invariant: a handover has exactly one wrap (it is addressed to one newcomer), while a step
/// carries up to 31 small wraps. The largest legitimate body is therefore one handover wrap of
/// 8192 secrets, about 262 KB of ct, plus overhead.
export const MAX_CBOR_LEN = 300_000;
const SIG_LEN = 64;
const SIG_DOMAIN = new TextEncoder().encode("runa/v1/epoch-key");

function signedBytes(header: Uint8Array, cbor: Uint8Array): Uint8Array {
  return concatBytes(SIG_DOMAIN, header, cbor);
}

/// The one object shape both directions use, so key order cannot drift.
function canonicalShape(body: EpochKeyBody) {
  return {
    kind: body.kind,
    from: body.from,
    to: body.to,
    root: body.root,
    sender: body.sender,
    roster: body.roster,
    confirm: body.confirm,
    wraps: body.wraps.map((w) => ({ p: w.p, iv: w.iv, ct: w.ct })),
  };
}

export async function encodeEpochKey(
  header: Uint8Array,
  body: EpochKeyBody,
  identity: Identity,
): Promise<Uint8Array> {
  if (header.length !== 32) throw new Error("header must be 32 bytes");
  const cbor = cbor2.encode(canonicalShape(body));
  const sig = await signPayload(identity, signedBytes(header, cbor));
  if (sig.length !== SIG_LEN) throw new Error("unexpected signature length");
  const len = new Uint8Array(4);
  new DataView(len.buffer).setUint32(0, cbor.length, false);
  return concatBytes(len, cbor, sig);
}

const isU32 = (v: unknown): v is number =>
  typeof v === "number" && Number.isInteger(v) && v >= 0 && v <= 0xffffffff;

function isBytes(v: unknown, min: number, max = min): v is Uint8Array {
  return v instanceof Uint8Array && v.length >= min && v.length <= max;
}

export function decodeEpochKey(bytes: Uint8Array): DecodedEpochKey | null {
  if (bytes.length < 4 + SIG_LEN) return null;
  const len = new DataView(bytes.buffer, bytes.byteOffset, 4).getUint32(0, false);
  if (bytes.length !== 4 + len + SIG_LEN) return null;
  const cbor = bytes.slice(4, 4 + len);
  const sig = bytes.slice(4 + len);
  if (cbor.length > MAX_CBOR_LEN || cbor[0] !== 0xa8) return null;
  let raw: unknown;
  try {
    raw = cbor2.decode(cbor);
  } catch {
    return null;
  }
  if (typeof raw !== "object" || raw === null || Array.isArray(raw) || raw instanceof Uint8Array) return null;
  const o = raw as Record<string, unknown>;
  if (o.kind !== "step" && o.kind !== "handover") return null;
  if (!isU32(o.from) || !isU32(o.to) || !isU32(o.root)) return null;
  if (!isBytes(o.sender, 16) || !isBytes(o.roster, 32) || !isBytes(o.confirm, 16)) return null;
  if (!Array.isArray(o.wraps) || o.wraps.length > MAX_WRAPS) return null;
  const wraps: Wrap[] = [];
  for (const w of o.wraps) {
    if (typeof w !== "object" || w === null) return null;
    const ww = w as Record<string, unknown>;
    if (!isBytes(ww.p, 16) || !isBytes(ww.iv, 12) || !isBytes(ww.ct, 16, MAX_CT)) return null;
    wraps.push({ p: ww.p, iv: ww.iv, ct: ww.ct });
  }
  if (o.root > o.to) return null;
  if (o.kind === "step" && o.to !== o.from + 1) return null;
  if (o.kind === "handover" && wraps.length !== 1) return null;
  const body: EpochKeyBody = {
    kind: o.kind,
    from: o.from,
    to: o.to,
    root: o.root,
    sender: o.sender,
    roster: o.roster,
    confirm: o.confirm,
    wraps,
  };
  const again = cbor2.encode(canonicalShape(body));
  if (again.length !== cbor.length || again.some((b, i) => b !== cbor[i])) return null;
  return { body, cbor, sig };
}

export function verifyEpochKey(
  header: Uint8Array,
  decoded: DecodedEpochKey,
  alg: SignatureAlg,
  pubkey: Uint8Array,
): Promise<boolean> {
  return verifyPayload(alg, pubkey, decoded.sig, signedBytes(header, decoded.cbor));
}
