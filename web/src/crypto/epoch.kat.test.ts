import { describe, expect, it } from "vitest";
import { decryptWithExplicitNonce, encryptWithExplicitNonce } from "./aead";
import { confirmFor, deriveChainKey, INFO_CHAIN, rootEpochKeys, stepKeys } from "./epoch";
import { wrapKey, type KxPair } from "./kx";

/// Known-answer vectors for amendment J (master spec §10.1). Every value below
/// was printed by `node scripts/kat-epoch.mjs`, which computes them with
/// node:crypto and a hand-written HKDF, independent of the WebCrypto HKDF the
/// app uses. A change to an info string, a salt, an input order or a length
/// shows up here.

const h = (s: string): Uint8Array => Uint8Array.from(s.match(/../g)!.map((x) => parseInt(x, 16)));
const toHex = (b: Uint8Array): string => Array.from(b, (x) => x.toString(16).padStart(2, "0")).join("");
const b64url = (b: Uint8Array): string =>
  btoa(String.fromCharCode(...b)).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");

const IKM = h("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
const ROOM_SALT = h("a0a1a2a3a4a5a6a7a8a9aaabacadaeaf");
const ROOM_ID = h("b0b1b2b3b4b5b6b7b8b9babbbcbdbebf");
const EPOCH_SECRET = h("c0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedf");
const PRIV_A = h("0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20");
const PRIV_B = h("2122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f40");
const PEER_A = h("11111111111111111111111111111111");
const PEER_B = h("22222222222222222222222222222222");
const HEADER = h("303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f");
const IV = h("505152535455565758595a5b");
const PLAINTEXT = h("72756e612065706f6368206b6e6f776e2d616e7377657220766563746f72");
const WRAP_EPOCH = 1;

const CHAIN_0 = "2094edf63671688520f1e3d03164dcf02d197b2a95e8843fcd23509920a11bfc";
const CONFIRM_0 = "0df8279076b71eaf55d33988c30e4b6c";
const CONTENT_1_CT = "7d95f8639381b1daee260dba4f3ccdab3d7969d97e6d0a6d90f4dc6c624321f4e0b67c37ad5a4b3433629da2178b";
const CONFIRM_1 = "46a1dded595efa339484af0460be5505";
const PUB_A = h("04515c3d6eb9e396b904d3feca7f54fdcd0cc1e997bf375dca515ad0a6c3b4035f4536be3a50f318fbf9a5475902a221502bef0d57e08c53b2cc0a56f17d9f9354");
const PUB_B = h("041f140146bfb1b251f84f4ddbe0d4cdcfd77afd984a9520e35794021f8312bb9eec995a08b1fa7704df3dcc0b50a9665263fb7711f95f9f8a449c5096e47c892b");
const WRAP_CT = "42355770a31673c05ff1a5f56ce1d0719d950182922fc71349cc34dda05afde550c405d8ccc6b3f9f5271e0d4e2269c5";

/// WebCrypto has no raw import for an ECDH private key, so the fixed scalar
/// goes in as a JWK with its public point.
async function kxFrom(d: Uint8Array, pub: Uint8Array): Promise<KxPair> {
  const privateKey = await crypto.subtle.importKey(
    "jwk",
    { kty: "EC", crv: "P-256", d: b64url(d), x: b64url(pub.slice(1, 33)), y: b64url(pub.slice(33, 65)), ext: false },
    { name: "ECDH", namedCurve: "P-256" },
    false,
    ["deriveBits"],
  );
  return { privateKey, publicKeyRaw: pub };
}

async function rootKeys() {
  const content = await crypto.subtle.importKey("raw", new Uint8Array(32), { name: "AES-GCM" }, false, ["encrypt", "decrypt"]);
  return rootEpochKeys(0, content, await deriveChainKey(IKM, ROOM_SALT));
}

describe("epoch schedule known answers", () => {
  it("chain_0 is HKDF(ikm, room_salt, \"runa/v1/chain\")", async () => {
    const base = await crypto.subtle.importKey("raw", IKM as BufferSource, "HKDF", false, ["deriveBits"]);
    const raw = await crypto.subtle.deriveBits(
      { name: "HKDF", hash: "SHA-256", salt: ROOM_SALT as BufferSource, info: INFO_CHAIN as BufferSource },
      base,
      256,
    );
    expect(toHex(new Uint8Array(raw))).toBe(CHAIN_0);
  });

  it("confirm_0 matches", async () => {
    expect(toHex(await confirmFor(await deriveChainKey(IKM, ROOM_SALT)))).toBe(CONFIRM_0);
    expect(toHex((await rootKeys()).confirm)).toBe(CONFIRM_0);
  });

  it("content_1 seals the fixed plaintext to the known ciphertext", async () => {
    const next = await stepKeys(await rootKeys(), EPOCH_SECRET);
    expect(next.epoch).toBe(1);
    expect(toHex(await encryptWithExplicitNonce(next.contentKey, IV, PLAINTEXT, undefined))).toBe(CONTENT_1_CT);
  });

  it("confirm_1 matches", async () => {
    const next = await stepKeys(await rootKeys(), EPOCH_SECRET);
    expect(toHex(next.confirm)).toBe(CONFIRM_1);
  });

  it("content and chain keys cannot be exported", async () => {
    const root = await rootKeys();
    expect(root.chainKey.extractable).toBe(false);
    const next = await stepKeys(root, EPOCH_SECRET);
    expect(next.contentKey.extractable).toBe(false);
    expect(next.chainKey.extractable).toBe(false);
  });
});

describe("key agreement known answers", () => {
  it("the wrap key seals the fixed secret to the known ciphertext, and the other end opens it", async () => {
    const a = await kxFrom(PRIV_A, PUB_A);
    const b = await kxFrom(PRIV_B, PUB_B);
    const ka = await wrapKey(a, PUB_B, ROOM_ID, WRAP_EPOCH, PEER_A, PEER_B);
    expect(ka.extractable).toBe(false);
    expect(toHex(await encryptWithExplicitNonce(ka, IV, EPOCH_SECRET, HEADER))).toBe(WRAP_CT);
    const kb = await wrapKey(b, PUB_A, ROOM_ID, WRAP_EPOCH, PEER_A, PEER_B);
    expect(await decryptWithExplicitNonce(kb, IV, h(WRAP_CT), HEADER)).toEqual(EPOCH_SECRET);
  });
});
