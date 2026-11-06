/// The epoch key schedule (PROTOCOL.md amendment J).
///
/// A room's root gives epoch 0's content key and a chain key. Each step mixes
/// a fresh 32-byte secret into the chain, and gives the next content key, the
/// next chain key and a 16-byte confirmation value that every member compares
/// before trusting what it derived. Content and chain keys are
/// non-extractable from the moment they exist; the spec's
/// `HKDF(content_key || epoch_secret)` could not be computed for that reason,
/// so the chain is a separate key (ADR 0016).

const enc = new TextEncoder();
export const INFO_CHAIN = enc.encode("runa/v1/chain");
export const INFO_EPOCH_CONTENT = enc.encode("runa/v1/epoch/content");
export const INFO_EPOCH_CHAIN = enc.encode("runa/v1/epoch/chain");
export const INFO_EPOCH_CONFIRM = enc.encode("runa/v1/epoch/confirm");
export const EPOCH_SECRET_LEN = 32;
export const CONFIRM_LEN = 16;
const EMPTY = new Uint8Array(0);

export interface EpochKeys {
  epoch: number;
  contentKey: CryptoKey;
  chainKey: CryptoKey;
  confirm: Uint8Array;
}

function importHkdf(raw: Uint8Array): Promise<CryptoKey> {
  return crypto.subtle.importKey("raw", raw as BufferSource, "HKDF", false, ["deriveBits", "deriveKey"]);
}

function hkdf(salt: Uint8Array, info: Uint8Array): HkdfParams {
  return { name: "HKDF", hash: "SHA-256", salt: salt as BufferSource, info: info as BufferSource };
}

export async function deriveChainKey(ikm: Uint8Array, roomSalt: Uint8Array): Promise<CryptoKey> {
  const base = await importHkdf(ikm);
  const raw = new Uint8Array(await crypto.subtle.deriveBits(hkdf(roomSalt, INFO_CHAIN), base, 256));
  try {
    return await importHkdf(raw);
  } finally {
    raw.fill(0);
  }
}

export async function confirmFor(chainKey: CryptoKey): Promise<Uint8Array> {
  return new Uint8Array(
    await crypto.subtle.deriveBits(hkdf(EMPTY, INFO_EPOCH_CONFIRM), chainKey, CONFIRM_LEN * 8),
  );
}

export async function rootEpochKeys(
  epoch: number,
  contentKey: CryptoKey,
  chainKey: CryptoKey,
): Promise<EpochKeys> {
  return { epoch, contentKey, chainKey, confirm: await confirmFor(chainKey) };
}

export async function stepKeys(prev: EpochKeys, secret: Uint8Array): Promise<EpochKeys> {
  if (secret.length !== EPOCH_SECRET_LEN) throw new Error("an epoch secret is 32 bytes");
  if (prev.epoch >= 0xffffffff) throw new Error("no epoch after the last");
  const contentKey = await crypto.subtle.deriveKey(
    hkdf(secret, INFO_EPOCH_CONTENT),
    prev.chainKey,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"],
  );
  const raw = new Uint8Array(await crypto.subtle.deriveBits(hkdf(secret, INFO_EPOCH_CHAIN), prev.chainKey, 256));
  let chainKey: CryptoKey;
  try {
    chainKey = await importHkdf(raw);
  } finally {
    raw.fill(0);
  }
  return { epoch: prev.epoch + 1, contentKey, chainKey, confirm: await confirmFor(chainKey) };
}

export function randomEpochSecret(): Uint8Array {
  const s = new Uint8Array(EPOCH_SECRET_LEN);
  crypto.getRandomValues(s);
  return s;
}

/// Compares every byte whatever it finds, so the time taken says nothing about
/// where two values first differ.
export function confirmsEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i];
  return diff === 0;
}
