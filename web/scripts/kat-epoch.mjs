// Known-answer vectors for the epoch key schedule and key agreement
// (PROTOCOL.md amendment J). Run with `node scripts/kat-epoch.mjs`.
//
// Computed with node:crypto primitives only, and with HKDF-SHA-256 written
// out by hand over HMAC (RFC 5869), so the vectors do not depend on the
// WebCrypto HKDF the app uses. src/crypto/epoch.kat.test.ts hardcodes what
// this prints and checks the app's code against it.

import { createCipheriv, createECDH, createHmac } from "node:crypto";

const seq = (start, len) => Uint8Array.from({ length: len }, (_, i) => (start + i) & 0xff);
const hex = (b) => Buffer.from(b).toString("hex");
const utf8 = (s) => Buffer.from(s, "utf8");

/// RFC 5869. An empty salt is HashLen zero bytes, which HMAC treats the same
/// as an empty key.
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

function aesGcm(key, iv, plaintext, aad) {
  const c = createCipheriv("aes-256-gcm", key, iv);
  if (aad) c.setAAD(aad);
  const ct = Buffer.concat([c.update(plaintext), c.final()]);
  return new Uint8Array(Buffer.concat([ct, c.getAuthTag()]));
}

// Fixed inputs.
const IKM = seq(0x00, 32);
const ROOM_SALT = seq(0xa0, 16);
const ROOM_ID = seq(0xb0, 16);
const EPOCH_SECRET = seq(0xc0, 32);
const PRIV_A = seq(0x01, 32);
const PRIV_B = seq(0x21, 32);
const PEER_A = new Uint8Array(16).fill(0x11);
const PEER_B = new Uint8Array(16).fill(0x22);
const HEADER = seq(0x30, 32);
const IV = seq(0x50, 12);
const PLAINTEXT = utf8("runa epoch known-answer vector");
const WRAP_EPOCH = 1;

// Info strings, exactly as amendment J.
const INFO_CHAIN = utf8("runa/v1/chain");
const INFO_CONTENT = utf8("runa/v1/epoch/content");
const INFO_EPOCH_CHAIN = utf8("runa/v1/epoch/chain");
const INFO_CONFIRM = utf8("runa/v1/epoch/confirm");
const INFO_WRAP = utf8("runa/v1/epoch-wrap");
const EMPTY = new Uint8Array(0);

const chain0 = hkdf(IKM, ROOM_SALT, INFO_CHAIN, 32);
const confirm0 = hkdf(chain0, EMPTY, INFO_CONFIRM, 16);
const content1 = hkdf(chain0, EPOCH_SECRET, INFO_CONTENT, 32);
const chain1 = hkdf(chain0, EPOCH_SECRET, INFO_EPOCH_CHAIN, 32);
const confirm1 = hkdf(chain1, EMPTY, INFO_CONFIRM, 16);
const content1Ct = aesGcm(content1, IV, PLAINTEXT, null);

const a = createECDH("prime256v1");
a.setPrivateKey(Buffer.from(PRIV_A));
const b = createECDH("prime256v1");
b.setPrivateKey(Buffer.from(PRIV_B));
const pubA = new Uint8Array(a.getPublicKey(null, "uncompressed"));
const pubB = new Uint8Array(b.getPublicKey(null, "uncompressed"));
const shared = new Uint8Array(a.computeSecret(Buffer.from(pubB)));
const sharedB = new Uint8Array(b.computeSecret(Buffer.from(pubA)));
if (hex(shared) !== hex(sharedB)) throw new Error("ECDH disagrees with itself");
const wrapSalt = new Uint8Array(20);
wrapSalt.set(ROOM_ID, 0);
new DataView(wrapSalt.buffer).setUint32(16, WRAP_EPOCH, false);
const wrapInfo = Buffer.concat([INFO_WRAP, PEER_A, PEER_B]);
const wrap = hkdf(shared, wrapSalt, wrapInfo, 32);
const wrapCt = aesGcm(wrap, IV, EPOCH_SECRET, HEADER);

const out = {
  inputs: {
    ikm: hex(IKM),
    room_salt: hex(ROOM_SALT),
    room_id: hex(ROOM_ID),
    epoch_secret: hex(EPOCH_SECRET),
    priv_a: hex(PRIV_A),
    priv_b: hex(PRIV_B),
    peer_a: hex(PEER_A),
    peer_b: hex(PEER_B),
    header: hex(HEADER),
    iv: hex(IV),
    plaintext: hex(PLAINTEXT),
    wrap_epoch: WRAP_EPOCH,
  },
  vectors: {
    chain_0: hex(chain0),
    confirm_0: hex(confirm0),
    content_1: hex(content1),
    content_1_ct: hex(content1Ct),
    chain_1: hex(chain1),
    confirm_1: hex(confirm1),
    pub_a: hex(pubA),
    pub_b: hex(pubB),
    ecdh_shared: hex(shared),
    wrap_key_a_to_b: hex(wrap),
    wrap_ct: hex(wrapCt),
  },
};
console.log(JSON.stringify(out, null, 2));
