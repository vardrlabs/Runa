import { deriveFromPassphrase, ARGON2_M_KIB, ARGON2_T, ARGON2_P } from "./crypto/kdf";
import { deriveChainKey } from "./crypto/epoch";
import { hkdfBits, INFO_AUTH, INFO_CONTENT, concatBytes } from "./crypto/keys";
import type { SecurityLevel } from "./security-level";

export type { SecurityLevel } from "./security-level";

export type RoomClass = "unlisted" | "named";

export interface KeyMaterial {
  passMaterial: Uint8Array | null;
  linkMaterial: Uint8Array | null;
}

const LINK_SECRET_LEN = 32;
const SALT_LEN = 16;

function b64url(bytes: Uint8Array): string {
  let s = "";
  for (const b of bytes) s += String.fromCharCode(b);
  return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function fromB64url(s: string): Uint8Array {
  const stripped = s.replace(/=+$/, "").replace(/-/g, "+").replace(/_/g, "/");
  const padded = stripped + "=".repeat((4 - (stripped.length % 4)) % 4);
  const bin = atob(padded);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

export function randomLinkSecret(): Uint8Array {
  const b = new Uint8Array(LINK_SECRET_LEN);
  crypto.getRandomValues(b);
  return b;
}

export function randomSalt(): Uint8Array {
  const b = new Uint8Array(SALT_LEN);
  crypto.getRandomValues(b);
  return b;
}

export interface FragmentKeys {
  linkSecret: Uint8Array;
  roomSalt: Uint8Array;
}

/// The URL fragment carries the key material and the KDF salt. Browsers never
/// transmit the fragment to the server, which is the entire point (spec §3.3).
export function parseFragment(fragment: string): FragmentKeys | null {
  const raw = fragment.replace(/^#/, "");
  if (!raw) return null;
  const params = new URLSearchParams(raw);
  const k = params.get("k");
  const s = params.get("s");
  if (!k || !s) return null;
  try {
    const linkSecret = fromB64url(k);
    const roomSalt = fromB64url(s);
    if (linkSecret.length !== LINK_SECRET_LEN || roomSalt.length !== SALT_LEN) return null;
    return { linkSecret, roomSalt };
  } catch {
    return null;
  }
}

export function fragmentWithKey(linkSecret: Uint8Array, roomSalt: Uint8Array): string {
  return `#k=${b64url(linkSecret)}&s=${b64url(roomSalt)}`;
}

/// Throws KdfUnavailableError when this browser cannot run Argon2id. There is
/// deliberately no weaker fallback; that error says why.
export async function passphraseMaterial(
  passphrase: string,
  salt: Uint8Array,
): Promise<{ material: Uint8Array | null }> {
  if (!passphrase) return { material: null };
  const result = await deriveFromPassphrase(passphrase, salt);
  return { material: result.material };
}

function mergeMaterials(pass: Uint8Array | null, link: Uint8Array | null): Uint8Array {
  if (pass && link) return concatBytes(pass, link);
  if (pass) return pass;
  if (link) return link;
  throw new Error("no key material");
}

export interface DerivedRoomKeys {
  authKey: Uint8Array;
  contentKey: CryptoKey;
  chainKey: CryptoKey;
}

/// Single derivation point shared by creation and join so both sides compute
/// identical verifier and document keys (spec §3.3).
export async function deriveRoomKeys(
  passMaterial: Uint8Array | null,
  linkMaterial: Uint8Array | null,
  roomSalt: Uint8Array,
): Promise<DerivedRoomKeys> {
  const ikm = mergeMaterials(passMaterial, linkMaterial);
  const [authKey, contentRaw] = await Promise.all([
    hkdfBits(ikm, roomSalt, INFO_AUTH, 32),
    hkdfBits(ikm, roomSalt, INFO_CONTENT, 32),
  ]);
  const contentKey = await crypto.subtle.importKey(
    "raw",
    contentRaw as BufferSource,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"],
  );
  contentRaw.fill(0);
  const chainKey = await deriveChainKey(ikm, roomSalt);
  return { authKey, contentKey, chainKey };
}

export async function newIdentity(): Promise<Awaited<ReturnType<typeof import("./crypto/identity").generateIdentity>>> {
  const { generateIdentity } = await import("./crypto/identity");
  return generateIdentity();
}

export function defaultKdfParams(): { m_kib: number; t: number; p: number } {
  void ARGON2_M_KIB;
  void ARGON2_T;
  void ARGON2_P;
  return { m_kib: 65536, t: 3, p: 1 };
}

export async function verifierForAuthKey(authKey: Uint8Array): Promise<string> {
  const digest = await crypto.subtle.digest("SHA-256", authKey as BufferSource);
  let s = "";
  for (const b of new Uint8Array(digest)) s += String.fromCharCode(b);
  return btoa(s);
}

export async function encryptRoomConfig(
  contentKey: CryptoKey,
  ttl: { kind: string; secs: number },
  ceilingOptout: boolean,
  level: SecurityLevel = "everyday",
): Promise<Uint8Array> {
  const payload = new TextEncoder().encode(JSON.stringify({ ttl, ceilingOptout, level }));
  const iv = new Uint8Array(12);
  crypto.getRandomValues(iv);
  const ct = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv },
    contentKey,
    payload as BufferSource,
  );
  const out = new Uint8Array(12 + ct.byteLength);
  out.set(iv);
  out.set(new Uint8Array(ct), 12);
  return out;
}
