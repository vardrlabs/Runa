export const INFO_AUTH = new TextEncoder().encode("runa/v1/auth");
export const INFO_CONTENT = new TextEncoder().encode("runa/v1/content");
export const INFO_FP = new TextEncoder().encode("runa/v1/fp");

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

export async function hkdfBits(
  ikm: Uint8Array,
  salt: Uint8Array,
  info: Uint8Array,
  lengthBytes: number,
): Promise<Uint8Array> {
  const key = await crypto.subtle.importKey("raw", ikm as BufferSource, "HKDF", false, [
    "deriveBits",
  ]);
  const bits = await crypto.subtle.deriveBits(
    {
      name: "HKDF",
      hash: "SHA-256",
      salt: salt as BufferSource,
      info: info as BufferSource,
    },
    key,
    lengthBytes * 8,
  );
  return new Uint8Array(bits);
}

export interface RoomKeys {
  authKey: Uint8Array;
  contentKey: CryptoKey;
  fingerprintSeed: Uint8Array;
}

const CONTENT_INFO = INFO_CONTENT;

export async function deriveRoomKeys(
  passMaterial: Uint8Array | null,
  linkMaterial: Uint8Array | null,
  roomSalt: Uint8Array,
): Promise<RoomKeys> {
  if (!passMaterial && !linkMaterial) {
    throw new Error("at least one key source is required");
  }
  const ikm = concatBytes(
    ...(passMaterial ? [passMaterial] : []),
    ...(linkMaterial ? [linkMaterial] : []),
  );
  const [authKey, contentRaw, fpSeed] = await Promise.all([
    hkdfBits(ikm, roomSalt, INFO_AUTH, 32),
    hkdfBits(ikm, roomSalt, CONTENT_INFO, 32),
    hkdfBits(ikm, roomSalt, INFO_FP, 32),
  ]);

  const contentKey = await crypto.subtle.importKey(
    "raw",
    contentRaw as BufferSource,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"],
  );

  contentRaw.fill(0);
  ikm.fill(0);

  return { authKey, contentKey, fingerprintSeed: fpSeed };
}
