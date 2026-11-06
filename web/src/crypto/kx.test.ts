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

  it("names the signing algorithm from the key length", () => {
    expect(algForPubkey(new Uint8Array(32))).toBe("Ed25519");
    expect(algForPubkey(new Uint8Array(65))).toBe("ECDSA-P256");
    expect(algForPubkey(new Uint8Array(33))).toBeNull();
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
