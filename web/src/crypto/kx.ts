import type { SignatureAlg } from "./identity";
import { concatBytes } from "./keys";

/// Key agreement for handing epoch secrets to one member at a time
/// (PROTOCOL.md amendment J). Every session uses ECDH P-256, whatever it signs
/// with: two peers on different curves could not agree a key, and P-256 ECDH
/// is in every browser's WebCrypto (ADR 0016).

const enc = new TextEncoder();
export const KX_PUBKEY_LEN = 65;
const KX_DOMAIN = enc.encode("runa/v1/kx");
const WRAP_INFO = enc.encode("runa/v1/epoch-wrap");
const P256: EcKeyImportParams = { name: "ECDH", namedCurve: "P-256" };

export interface KxPair {
  privateKey: CryptoKey;
  publicKeyRaw: Uint8Array;
}

export async function generateKx(): Promise<KxPair> {
  const kp = (await crypto.subtle.generateKey(P256, false, ["deriveBits"])) as CryptoKeyPair;
  const raw = new Uint8Array(await crypto.subtle.exportKey("raw", kp.publicKey));
  return { privateKey: kp.privateKey, publicKeyRaw: raw };
}

/// What a session signs so its key-agreement key cannot be swapped for
/// another without breaking the signature, or replayed into another room.
export function kxStatement(roomId: Uint8Array, kxPub: Uint8Array): Uint8Array {
  return concatBytes(KX_DOMAIN, roomId, kxPub);
}

export function algForPubkey(raw: Uint8Array): SignatureAlg | null {
  if (raw.length === 32) return "Ed25519";
  if (raw.length === 65) return "ECDSA-P256";
  return null;
}

export async function wrapKey(
  own: KxPair,
  theirPub: Uint8Array,
  roomId: Uint8Array,
  epoch: number,
  senderPeerId: Uint8Array,
  recipientPeerId: Uint8Array,
): Promise<CryptoKey> {
  if (theirPub.length !== KX_PUBKEY_LEN || theirPub[0] !== 0x04) {
    throw new Error("not an uncompressed P-256 key");
  }
  const their = await crypto.subtle.importKey("raw", theirPub as BufferSource, P256, false, []);
  const shared = new Uint8Array(
    await crypto.subtle.deriveBits({ name: "ECDH", public: their }, own.privateKey, 256),
  );
  try {
    const base = await crypto.subtle.importKey("raw", shared as BufferSource, "HKDF", false, ["deriveKey"]);
    const salt = new Uint8Array(20);
    salt.set(roomId, 0);
    new DataView(salt.buffer).setUint32(16, epoch, false);
    return await crypto.subtle.deriveKey(
      {
        name: "HKDF",
        hash: "SHA-256",
        salt: salt as BufferSource,
        info: concatBytes(WRAP_INFO, senderPeerId, recipientPeerId) as BufferSource,
      },
      base,
      { name: "AES-GCM", length: 256 },
      false,
      ["encrypt", "decrypt"],
    );
  } finally {
    shared.fill(0);
  }
}

/// A wrap key is used for at most a handful of messages (one step, perhaps a
/// resent handover), so a random IV is safe here, unlike the frame cipher.
export async function sealWrap(
  key: CryptoKey,
  aad: Uint8Array,
  plaintext: Uint8Array,
): Promise<{ iv: Uint8Array; ct: Uint8Array }> {
  const iv = new Uint8Array(12);
  crypto.getRandomValues(iv);
  const ct = new Uint8Array(
    await crypto.subtle.encrypt(
      { name: "AES-GCM", iv: iv as BufferSource, additionalData: aad as BufferSource, tagLength: 128 },
      key,
      plaintext as BufferSource,
    ),
  );
  return { iv, ct };
}

export async function openWrap(
  key: CryptoKey,
  aad: Uint8Array,
  iv: Uint8Array,
  ct: Uint8Array,
): Promise<Uint8Array> {
  return new Uint8Array(
    await crypto.subtle.decrypt(
      { name: "AES-GCM", iv: iv as BufferSource, additionalData: aad as BufferSource, tagLength: 128 },
      key,
      ct as BufferSource,
    ),
  );
}
