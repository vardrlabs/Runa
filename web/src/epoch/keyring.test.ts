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

  it("lets exactly one of two concurrent steps to the same epoch commit", async () => {
    const r = await ring();
    const s = randomEpochSecret();
    const confirm = (await stepKeys(r.current, s)).confirm;
    const [x, y] = await Promise.all([r.applyStep(1, s, confirm), r.applyStep(1, s, confirm)]);
    expect([x, y].filter((k) => k !== null).length).toBe(1);
    expect(r.current.epoch).toBe(1);
    expect(r.secretsBlob().length).toBe(32);
  });

  it("stays consistent when a step lands during a handover", async () => {
    const a = await ring();
    const secrets: Uint8Array[] = [];
    for (let i = 1; i <= 3; i++) {
      const s = randomEpochSecret();
      secrets.push(s);
      await a.applyStep(i, s, (await stepKeys(a.current, s)).confirm);
    }
    const blob = a.secretsBlob();
    const b = await ring();
    const first = (await stepKeys(b.current, secrets[0])).confirm;
    await Promise.all([b.applyHandover(3, blob, a.current.confirm), b.applyStep(1, secrets[0], first)]);
    expect(b.secretsBlob().length).toBe((b.current.epoch - b.rootEpoch) * 32);
    expect(b.current.epoch).toBe(3);
  });

  it("stays consistent when a handover lands during a step", async () => {
    const a = await ring();
    const secrets: Uint8Array[] = [];
    for (let i = 1; i <= 3; i++) {
      const s = randomEpochSecret();
      secrets.push(s);
      await a.applyStep(i, s, (await stepKeys(a.current, s)).confirm);
    }
    const blob = a.secretsBlob();
    const b = await ring();
    const first = (await stepKeys(b.current, secrets[0])).confirm;
    await Promise.all([b.applyStep(1, secrets[0], first), b.applyHandover(3, blob, a.current.confirm)]);
    expect(b.secretsBlob().length).toBe((b.current.epoch - b.rootEpoch) * 32);
  });

  it("is unusable after wipe", async () => {
    const r = await ring();
    const s = randomEpochSecret();
    const confirm = (await stepKeys(r.current, s)).confirm;
    expect(r.wiped).toBe(false);
    r.wipe();
    expect(r.wiped).toBe(true);
    expect(await r.applyStep(1, s, confirm)).toBeNull();
    expect(await r.applyHandover(1, s, confirm)).toBeNull();
    expect(r.keyFor(0)).toBeNull();
    expect(r.secretsBlob().length).toBe(0);
  });

  it("accepts a handover that agrees with what the member holds", async () => {
    const a = await ring();
    for (let i = 1; i <= 3; i++) {
      const s = randomEpochSecret();
      await a.applyStep(i, s, (await stepKeys(a.current, s)).confirm);
    }
    const b = await ring();
    const blob = a.secretsBlob();
    const first = blob.slice(0, 32);
    await b.applyStep(1, first, (await stepKeys(b.current, first)).confirm);
    const k = await b.applyHandover(3, blob, a.current.confirm);
    expect(k?.epoch).toBe(3);
    expect(b.secretsBlob()).toEqual(blob);
    for (const e of [0, 1, 2, 3]) expect(await sameKey(a.keyFor(e)!, b.keyFor(e)!)).toBe(true);
  });

  it("refuses a handover that disagrees with what the member holds", async () => {
    const a = await ring();
    for (let i = 1; i <= 3; i++) {
      const s = randomEpochSecret();
      await a.applyStep(i, s, (await stepKeys(a.current, s)).confirm);
    }
    const b = await ring();
    const mine = randomEpochSecret();
    await b.applyStep(1, mine, (await stepKeys(b.current, mine)).confirm);
    const key1 = b.keyFor(1)!;
    const before = b.secretsBlob();
    expect(await b.applyHandover(3, a.secretsBlob(), a.current.confirm)).toBeNull();
    expect(b.current.epoch).toBe(1);
    expect(b.keyFor(1)).toBe(key1);
    expect(b.keyFor(3)).toBeNull();
    expect(b.secretsBlob()).toEqual(before);
  });

  it("hands out a copy of the secrets", async () => {
    const r = await ring();
    const s = randomEpochSecret();
    await r.applyStep(1, s, (await stepKeys(r.current, s)).confirm);
    r.secretsBlob().fill(0);
    expect(r.secretsBlob()).toEqual(s);
  });
});
