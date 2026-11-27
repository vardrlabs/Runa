import * as cbor2 from "cbor2";
import { confirmFor } from "../crypto/epoch";
import { hkdfBits, INFO_FP } from "../crypto/keys";
import { deriveRoomKeys, fragmentWithKey, passphraseMaterial, randomLinkSecret, randomSalt } from "../keys-session";

/// The new way into a room after an eviction or a link change (PROTOCOL.md
/// amendment K). The proposer makes it; each remaining member receives it
/// sealed to them alone, derives the new root from it exactly as for a new
/// room, and shows it once.
export type WayKind = "link" | "pass";

export interface WayIn {
  kind: WayKind;
  /// The link secret, or the passphrase's Argon2id output.
  secret: Uint8Array;
  salt: Uint8Array;
  /// The passphrase as typed, to show once. Empty for a link.
  phrase: string;
}

export interface ReRootKeys {
  /// The new JOIN key. Raw: whoever ends up holding it zeroes it.
  authKey: Uint8Array;
  /// SHA-256 of `authKey`: what the votes sign and the server stores.
  verifier: Uint8Array;
  contentKey: CryptoKey;
  chainKey: CryptoKey;
  /// The new root's confirmation value, which the commit carries.
  confirm: Uint8Array;
  /// The seed of the six-word fingerprint, as the room page derives it.
  fingerprintSeed: Uint8Array;
}

export const MAX_PHRASE_LEN = 512;
const SECRET_LEN = 32;
const SALT_LEN = 16;

export function newLinkWayIn(): WayIn {
  return { kind: "link", secret: randomLinkSecret(), salt: randomSalt(), phrase: "" };
}

/// Runs Argon2id, which takes seconds on a phone. The caller checks the
/// passphrase's strength first, with the create form's check.
export async function newPassWayIn(phrase: string): Promise<WayIn> {
  if (!phrase || phrase.length > MAX_PHRASE_LEN) throw new Error("a passphrase is required");
  const salt = randomSalt();
  const { material } = await passphraseMaterial(phrase, salt);
  if (!material) throw new Error("a passphrase is required");
  return { kind: "pass", secret: material, salt, phrase };
}

/// The new root, derived exactly as a new room's is, from the same function.
export async function deriveReRoot(way: WayIn): Promise<ReRootKeys> {
  const pass = way.kind === "pass" ? way.secret.slice() : null;
  const link = way.kind === "link" ? way.secret.slice() : null;
  try {
    const { authKey, contentKey, chainKey } = await deriveRoomKeys(pass, link, way.salt);
    const verifier = new Uint8Array(await crypto.subtle.digest("SHA-256", authKey as BufferSource));
    const confirm = await confirmFor(chainKey);
    const fingerprintSeed = await hkdfBits(way.secret, way.salt, INFO_FP, 32);
    return { authKey, verifier, contentKey, chainKey, confirm, fingerprintSeed };
  } finally {
    pass?.fill(0);
    link?.fill(0);
  }
}

function shape(w: WayIn) {
  return { kind: w.kind, secret: w.secret, salt: w.salt, phrase: w.phrase };
}

/// What one member's wrap in an EVICT_COMMIT holds.
export function encodeWayIn(w: WayIn): Uint8Array {
  return cbor2.encode(shape(w));
}

export function decodeWayIn(bytes: Uint8Array): WayIn | null {
  let raw: unknown;
  try {
    raw = cbor2.decode(bytes);
  } catch {
    return null;
  }
  if (typeof raw !== "object" || raw === null || Array.isArray(raw) || raw instanceof Uint8Array) return null;
  const o = raw as Record<string, unknown>;
  if (o.kind !== "link" && o.kind !== "pass") return null;
  if (!(o.secret instanceof Uint8Array) || o.secret.length !== SECRET_LEN) return null;
  if (!(o.salt instanceof Uint8Array) || o.salt.length !== SALT_LEN) return null;
  if (typeof o.phrase !== "string" || o.phrase.length > MAX_PHRASE_LEN) return null;
  if ((o.kind === "link") !== (o.phrase === "")) return null;
  const w: WayIn = { kind: o.kind, secret: o.secret.slice(), salt: o.salt.slice(), phrase: o.phrase };
  const again = cbor2.encode(shape(w));
  if (again.length !== bytes.length || again.some((b, i) => b !== bytes[i])) {
    w.secret.fill(0);
    return null;
  }
  return w;
}

/// The AES-GCM tag every wrap's ciphertext carries after the sealed bytes.
const GCM_TAG_LEN = 16;

/// The longest ciphertext a wrap can hold: the largest way in `encodeWayIn`
/// can produce, a passphrase of `MAX_PHRASE_LEN` code units of three bytes each
/// in UTF-8, plus the tag. The commit's encoder and decoder both use this.
export const MAX_WRAP_CT =
  encodeWayIn({
    kind: "pass",
    secret: new Uint8Array(SECRET_LEN),
    salt: new Uint8Array(SALT_LEN),
    phrase: "\u20ac".repeat(MAX_PHRASE_LEN),
  }).length + GCM_TAG_LEN;

/// The new link's `#k=…&s=…`, or null for a passphrase.
export function wayFragment(w: WayIn): string | null {
  return w.kind === "link" ? fragmentWithKey(w.secret, w.salt) : null;
}

export function wipeWayIn(w: WayIn): void {
  w.secret.fill(0);
  w.phrase = "";
}
