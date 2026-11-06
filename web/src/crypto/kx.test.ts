import { describe, expect, it } from "vitest";
import { generateIdentity, signPayload, verifyPayload } from "./identity";
import { algForPubkey, generateKx, kxStatement, openWrap, sealWrap, wrapKey } from "./kx";

const ROOM = new Uint8Array(16).fill(7);
const PA = new Uint8Array(16).fill(1);
const PB = new Uint8Array(16).fill(2);
const PC = new Uint8Array(16).fill(3);
const AAD = new Uint8Array(32).fill(9);
const SECRET = new Uint8Array(32).fill(0x5a);

describe("key agreement", () => {
  it("publishes 65-byte uncompressed P-256 keys", async () => {
    const a = await generateKx();
    expect(a.publicKeyRaw.length).toBe(65);
    expect(a.publicKeyRaw[0]).toBe(4);
  });

  it("gives both ends the same wrap key", async () => {
    const a = await generateKx();
    const b = await generateKx();
    const ka = await wrapKey(a, b.publicKeyRaw, ROOM, 1, PA, PB);
    const kb = await wrapKey(b, a.publicKeyRaw, ROOM, 1, PA, PB);
    const { iv, ct } = await sealWrap(ka, AAD, SECRET);
    expect(await openWrap(kb, AAD, iv, ct)).toEqual(SECRET);
  });

  it("binds the epoch", async () => {
    const a = await generateKx();
    const b = await generateKx();
    const { iv, ct } = await sealWrap(await wrapKey(a, b.publicKeyRaw, ROOM, 1, PA, PB), AAD, SECRET);
    await expect(openWrap(await wrapKey(b, a.publicKeyRaw, ROOM, 2, PA, PB), AAD, iv, ct)).rejects.toThrow();
  });

  it("binds who it is for", async () => {
    const a = await generateKx();
    const b = await generateKx();
    const { iv, ct } = await sealWrap(await wrapKey(a, b.publicKeyRaw, ROOM, 1, PA, PB), AAD, SECRET);
    await expect(openWrap(await wrapKey(b, a.publicKeyRaw, ROOM, 1, PA, PC), AAD, iv, ct)).rejects.toThrow();
  });

  it("binds the frame header", async () => {
    const a = await generateKx();
    const b = await generateKx();
    const { iv, ct } = await sealWrap(await wrapKey(a, b.publicKeyRaw, ROOM, 1, PA, PB), AAD, SECRET);
    const other = AAD.slice();
    other[20] ^= 1;
    await expect(openWrap(await wrapKey(b, a.publicKeyRaw, ROOM, 1, PA, PB), other, iv, ct)).rejects.toThrow();
  });

  it("refuses a key that is not an uncompressed P-256 point", async () => {
    const a = await generateKx();
    await expect(wrapKey(a, new Uint8Array(64).fill(4), ROOM, 1, PA, PB)).rejects.toThrow();
  });

  it("names the signing algorithm from the key's shape", () => {
    const p256 = new Uint8Array(65);
    p256[0] = 0x04;
    expect(algForPubkey(new Uint8Array(32))).toBe("Ed25519");
    expect(algForPubkey(p256)).toBe("ECDSA-P256");
    expect(algForPubkey(new Uint8Array(65))).toBeNull();
    expect(algForPubkey(new Uint8Array(65).fill(0x02))).toBeNull();
    expect(algForPubkey(new Uint8Array(33))).toBeNull();
  });

  it("refuses a 65-byte key that is not on the curve", async () => {
    const a = await generateKx();
    const b = await generateKx();
    const off = b.publicKeyRaw.slice();
    off[64] ^= 1;
    await expect(wrapKey(a, off, ROOM, 1, PA, PB)).rejects.toThrow();
  });

  it("binds the room", async () => {
    const a = await generateKx();
    const b = await generateKx();
    const other = ROOM.slice();
    other[0] ^= 1;
    const { iv, ct } = await sealWrap(await wrapKey(a, b.publicKeyRaw, ROOM, 1, PA, PB), AAD, SECRET);
    await expect(openWrap(await wrapKey(b, a.publicKeyRaw, other, 1, PA, PB), AAD, iv, ct)).rejects.toThrow();
  });

  it("binds who sent it", async () => {
    const a = await generateKx();
    const b = await generateKx();
    const { iv, ct } = await sealWrap(await wrapKey(a, b.publicKeyRaw, ROOM, 1, PA, PB), AAD, SECRET);
    await expect(openWrap(await wrapKey(b, a.publicKeyRaw, ROOM, 1, PC, PB), AAD, iv, ct)).rejects.toThrow();
  });

  it("checks every input's size at the boundary", async () => {
    const a = await generateKx();
    const b = await generateKx();
    const pub = b.publicKeyRaw;
    const short = new Uint8Array(15);
    const long = new Uint8Array(17);
    expect(() => kxStatement(short, pub)).toThrow();
    expect(() => kxStatement(long, pub)).toThrow();
    expect(() => kxStatement(ROOM, pub.slice(0, 64))).toThrow();
    expect(() => kxStatement(ROOM, new Uint8Array(66))).toThrow();
    await expect(wrapKey(a, pub, short, 1, PA, PB)).rejects.toThrow();
    await expect(wrapKey(a, pub, long, 1, PA, PB)).rejects.toThrow();
    await expect(wrapKey(a, pub, ROOM, 1, short, PB)).rejects.toThrow();
    await expect(wrapKey(a, pub, ROOM, 1, PA, long)).rejects.toThrow();
    await expect(wrapKey(a, pub.slice(0, 64), ROOM, 1, PA, PB)).rejects.toThrow();
    for (const epoch of [-1, 0x1_0000_0000, 1.5, Number.NaN]) {
      await expect(wrapKey(a, pub, ROOM, epoch, PA, PB)).rejects.toThrow();
    }
    await expect(wrapKey(a, pub, ROOM, 0, PA, PB)).resolves.toBeDefined();
    await expect(wrapKey(a, pub, ROOM, 0xffffffff, PA, PB)).resolves.toBeDefined();
    const key = await wrapKey(a, pub, ROOM, 1, PA, PB);
    const { iv, ct } = await sealWrap(key, AAD, SECRET);
    await expect(openWrap(key, AAD, iv.slice(0, 11), ct)).rejects.toThrow();
    await expect(openWrap(key, AAD, new Uint8Array(16), ct)).rejects.toThrow();
    expect(await openWrap(key, AAD, iv, ct)).toEqual(SECRET);
  });

  it("lets a peer sign its key-agreement key to this room", async () => {
    const id = await generateIdentity();
    const kx = await generateKx();
    const sig = await signPayload(id, kxStatement(ROOM, kx.publicKeyRaw));
    expect(sig.length).toBe(64);
    expect(await verifyPayload(id.alg, id.publicKeyRaw, sig, kxStatement(ROOM, kx.publicKeyRaw))).toBe(true);
    expect(await verifyPayload(id.alg, id.publicKeyRaw, sig, kxStatement(PA, kx.publicKeyRaw))).toBe(false);
  });
});
