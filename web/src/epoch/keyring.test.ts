import { describe, expect, it } from "vitest";
import { decryptWithExplicitNonce, encryptWithExplicitNonce } from "../crypto/aead";
import { deriveChainKey, randomEpochSecret, stepKeys } from "../crypto/epoch";
import { Keyring } from "./keyring";

const IV = new Uint8Array(12).fill(1);
const PT = new Uint8Array([1, 2, 3]);

async function rootParts() {
  const content = await crypto.subtle.importKey("raw", new Uint8Array(32).fill(7), { name: "AES-GCM" }, false, [
    "encrypt",
    "decrypt",
  ]);
  const chain = await deriveChainKey(new Uint8Array(32).fill(8), new Uint8Array(16).fill(9));
  return { content, chain };
}

async function ring(): Promise<Keyring> {
  const { content, chain } = await rootParts();
  return Keyring.fromRoot(0, content, chain);
}

async function sameKey(a: CryptoKey, b: CryptoKey): Promise<boolean> {
  const ct = await encryptWithExplicitNonce(a, IV, PT, undefined);
  try {
    await decryptWithExplicitNonce(b, IV, ct, undefined);
    return true;
  } catch {
    return false;
  }
}

describe("Keyring", () => {
  it("starts at its root", async () => {
    const r = await ring();
    expect(r.rootEpoch).toBe(0);
    expect(r.current.epoch).toBe(0);
    expect(r.has(0)).toBe(true);
    expect(r.keyFor(1)).toBeNull();
  });

  it("applies a step whose confirmation matches, and keeps the old key for reading", async () => {
    const r = await ring();
    const s = randomEpochSecret();
    const expected = await stepKeys(r.current, s);
    const k = await r.applyStep(1, s, expected.confirm);
    expect(k?.epoch).toBe(1);
    expect(r.current.epoch).toBe(1);
    expect(r.has(0)).toBe(true);
    expect(await sameKey(r.keyFor(1)!, expected.contentKey)).toBe(true);
  });

  it("leaves itself unchanged when the confirmation does not match", async () => {
    const r = await ring();
    expect(await r.applyStep(1, randomEpochSecret(), new Uint8Array(16))).toBeNull();
    expect(r.current.epoch).toBe(0);
  });

  it("refuses a step that is not the next epoch", async () => {
    const r = await ring();
    const s = randomEpochSecret();
    const expected = await stepKeys(r.current, s);
    expect(await r.applyStep(2, s, expected.confirm)).toBeNull();
  });

  it("brings a newcomer to the same keys through a handover", async () => {
    const a = await ring();
    for (let i = 1; i <= 3; i++) {
      const s = randomEpochSecret();
      await a.applyStep(i, s, (await stepKeys(a.current, s)).confirm);
    }
    const blob = a.secretsBlob();
    expect(blob.length).toBe(96);
    const b = await ring();
    const k = await b.applyHandover(3, blob, a.current.confirm);
    expect(k?.epoch).toBe(3);
    for (const e of [0, 1, 2, 3]) expect(await sameKey(a.keyFor(e)!, b.keyFor(e)!)).toBe(true);
  });

  it("refuses a handover whose confirmation does not match", async () => {
    const a = await ring();
    const s = randomEpochSecret();
    await a.applyStep(1, s, (await stepKeys(a.current, s)).confirm);
    const b = await ring();
    expect(await b.applyHandover(1, a.secretsBlob(), new Uint8Array(16))).toBeNull();
    expect(b.current.epoch).toBe(0);
  });

  it("refuses a handover of the wrong length", async () => {
    const b = await ring();
    expect(await b.applyHandover(2, new Uint8Array(32), new Uint8Array(16))).toBeNull();
  });

  it("forgets everything on wipe", async () => {
    const r = await ring();
    const s = randomEpochSecret();
    await r.applyStep(1, s, (await stepKeys(r.current, s)).confirm);
    r.wipe();
    expect(r.keyFor(0)).toBeNull();
    expect(r.keyFor(1)).toBeNull();
    expect(r.secretsBlob().length).toBe(0);
  });
});
