// Known-answer vectors for amendment K: the fixed vote statement (with the
// target's key digest bound in), the re-root derivation, and one signature
// of each kind for the server's own test. Run with `node scripts/kat-evict.mjs`.
//
// Computed with node:crypto primitives only, and with HKDF-SHA-256 written
// out by hand over HMAC (RFC 5869), so the vectors do not depend on the
// WebCrypto HKDF the app uses or on the Rust crates the server verifies with.
// src/evict/statement.test.ts, src/evict/reroot.kat.test.ts and
// server/src/runar/evict.rs hardcode what this prints, and must agree with
// it: statement, linkStatement, targetKeyDigest, p256PubDigest, edPub, edSig
// and p256Pub are deterministic. The P-256 signature uses a random nonce, so
// it differs on every run; any run's output is a valid vector, and the one
// in evict.rs came from an earlier run.

import { createHash, createHmac, createPrivateKey, createPublicKey, createECDH, sign } from "node:crypto";

const seq = (start, len) => Uint8Array.from({ length: len }, (_, i) => (start + i) & 0xff);
const hex = (b) => Buffer.from(b).toString("hex");
const utf8 = (s) => Buffer.from(s, "utf8");

function hkdf(ikm, salt, info, length) {
  const prk = createHmac("sha256", salt.length ? Buffer.from(salt) : Buffer.alloc(32)).update(ikm).digest();
  const blocks = [];
  let prev = Buffer.alloc(0);
  for (let i = 1; Buffer.concat(blocks).length < length; i++) {
    prev = createHmac("sha256", prk).update(Buffer.concat([prev, Buffer.from(info), Buffer.from([i])])).digest();
    blocks.push(prev);
  }
  return new Uint8Array(Buffer.concat(blocks).subarray(0, length));
}

// The statement: fixed inputs.
const ROOM_ID = seq(0xb0, 16);
const REQUEST_ID = seq(0x60, 16);
const EPOCH = 7;
const TARGET = new Uint8Array(16).fill(0x33);
// The target's signing key as sent in its JOIN: 32 bytes of 0x33 stand in for
// an Ed25519 key. The statement carries SHA-256 of whatever raw bytes it is.
const TARGET_KEY = new Uint8Array(32).fill(0x33);
const TARGET_KEY_DIGEST = createHash("sha256").update(TARGET_KEY).digest();
const VOTER = new Uint8Array(16).fill(0x11);
const NEW_VERIFIER = seq(0x80, 32);
const epochBytes = Buffer.alloc(4);
epochBytes.writeUInt32BE(EPOCH);
const statement = Buffer.concat([
  utf8("runa/v1/evict"), ROOM_ID, REQUEST_ID, epochBytes, TARGET, TARGET_KEY_DIGEST, VOTER, NEW_VERIFIER,
]);
// A link change names no peer and no key: both fields all zero.
const linkStatement = Buffer.concat([
  utf8("runa/v1/evict"), ROOM_ID, REQUEST_ID, epochBytes, Buffer.alloc(16), Buffer.alloc(32), VOTER, NEW_VERIFIER,
]);

// The re-root: a link and a passphrase's Argon2id output stand in as fixed
// 32-byte secrets; the derivation after Argon2id is what is pinned here.
const LINK = seq(0x00, 32);
const PASS = seq(0x40, 32);
const SALT = seq(0xa0, 16);
const EMPTY = new Uint8Array(0);
function root(secret) {
  const auth = hkdf(secret, SALT, utf8("runa/v1/auth"), 32);
  const chain = hkdf(secret, SALT, utf8("runa/v1/chain"), 32);
  return {
    auth: hex(auth),
    verifier: createHash("sha256").update(auth).digest("hex"),
    confirm: hex(hkdf(chain, EMPTY, utf8("runa/v1/epoch/confirm"), 16)),
    fingerprintSeed: hex(hkdf(secret, SALT, utf8("runa/v1/fp"), 32)),
  };
}

// Signatures for the server's test: Ed25519 from a fixed seed (deterministic),
// and P-256 from a fixed scalar in WebCrypto's r||s form.
const seed = seq(0x01, 32);
const edPriv = createPrivateKey({
  key: Buffer.concat([Buffer.from("302e020100300506032b657004220420", "hex"), seed]),
  format: "der",
  type: "pkcs8",
});
const edPub = createPublicKey(edPriv).export({ format: "der", type: "spki" }).subarray(12);
const d = seq(0x21, 32);
const ecdh = createECDH("prime256v1");
ecdh.setPrivateKey(Buffer.from(d));
const p256Pub = ecdh.getPublicKey(null, "uncompressed");
const b64u = (b) => Buffer.from(b).toString("base64url");
const pPriv = createPrivateKey({
  key: { kty: "EC", crv: "P-256", d: b64u(d), x: b64u(p256Pub.subarray(1, 33)), y: b64u(p256Pub.subarray(33)) },
  format: "jwk",
});
const p256Sig = sign("sha256", statement, { key: pPriv, dsaEncoding: "ieee-p1363" });
const n = BigInt("0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551");
const s = BigInt("0x" + hex(p256Sig.subarray(32)));
const low = s > n / 2n ? n - s : s;
const r = hex(p256Sig.subarray(0, 32));

console.log(
  JSON.stringify(
    {
      statement: hex(statement),
      linkStatement: hex(linkStatement),
      targetKeyDigest: hex(TARGET_KEY_DIGEST),
      p256PubDigest: createHash("sha256").update(p256Pub).digest("hex"),
      link: root(LINK),
      pass: root(PASS),
      edPub: hex(edPub),
      edSig: hex(sign(null, statement, edPriv)),
      p256Pub: hex(p256Pub),
      p256SigLowS: r + low.toString(16).padStart(64, "0"),
      p256SigHighS: r + (n - low).toString(16).padStart(64, "0"),
    },
    null,
    2,
  ),
);
