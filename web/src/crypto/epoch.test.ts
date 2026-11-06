import fc from "fast-check";
import { describe, expect, it } from "vitest";
import { deriveRoomKeys } from "../keys-session";
import { decryptWithExplicitNonce, encryptWithExplicitNonce } from "./aead";
import {
  CONFIRM_LEN,
  confirmsEqual,
  deriveChainKey,
  randomEpochSecret,
  rootEpochKeys,
  stepKeys,
  type EpochKeys,
} from "./epoch";

const IV = new Uint8Array(12).fill(3);
const PT = new TextEncoder().encode("a line written after the rotation");

async function root(seed = 1): Promise<EpochKeys> {
  const content = await crypto.subtle.importKey(
    "raw",
    new Uint8Array(32).fill(seed + 100),
    { name: "AES-GCM" },
    false,
    ["encrypt", "decrypt"],
  );
  const chain = await deriveChainKey(new Uint8Array(32).fill(seed), new Uint8Array(16).fill(2));
  return rootEpochKeys(0, content, chain);
}

/// Two non-extractable keys are the same key exactly when one opens what the
/// other sealed.
async function sameKey(a: CryptoKey, b: CryptoKey): Promise<boolean> {
  const ct = await encryptWithExplicitNonce(a, IV, PT, undefined);
  try {
    await decryptWithExplicitNonce(b, IV, ct, undefined);
    return true;
  } catch {
    return false;
  }
}

describe("epoch key schedule", () => {
  it("gives two members who step with one secret the same key", async () => {
    const s = randomEpochSecret();
    const a = await stepKeys(await root(), s);
    const b = await stepKeys(await root(), s);
    expect(a.epoch).toBe(1);
    expect(await sameKey(a.contentKey, b.contentKey)).toBe(true);
    expect(confirmsEqual(a.confirm, b.confirm)).toBe(true);
    expect(a.confirm.length).toBe(CONFIRM_LEN);
  });

  it("gives a key that the previous epoch cannot open", async () => {
    const r = await root();
    const next = await stepKeys(r, randomEpochSecret());
    expect(await sameKey(next.contentKey, r.contentKey)).toBe(false);
  });

  it("depends on the secret, so someone without it cannot follow", async () => {
    const r = await root();
    const a = await stepKeys(r, randomEpochSecret());
    const b = await stepKeys(r, randomEpochSecret());
    expect(await sameKey(a.contentKey, b.contentKey)).toBe(false);
    expect(confirmsEqual(a.confirm, b.confirm)).toBe(false);
  });

  it("depends on the chain, so the secret alone is not enough", async () => {
    const s = randomEpochSecret();
    const a = await stepKeys(await root(1), s);
    const b = await stepKeys(await root(9), s);
    expect(await sameKey(a.contentKey, b.contentKey)).toBe(false);
  });

  it("refuses a secret of the wrong length", async () => {
    await expect(stepKeys(await root(), new Uint8Array(31))).rejects.toThrow();
  });

  it("never repeats a confirmation value along a chain", async () => {
    await fc.assert(
      fc.asyncProperty(
        fc.array(fc.uint8Array({ minLength: 32, maxLength: 32 }), { minLength: 1, maxLength: 6 }),
        async (secrets) => {
          let k = await root();
          const seen = new Set<string>([Buffer.from(k.confirm).toString("hex")]);
          for (const s of secrets) {
            k = await stepKeys(k, s);
            const h = Buffer.from(k.confirm).toString("hex");
            expect(seen.has(h)).toBe(false);
            seen.add(h);
          }
          expect(k.epoch).toBe(secrets.length);
        },
      ),
      { numRuns: 25 },
    );
  });

  it("derives the same chain from the same link on every device", async () => {
    const link = new Uint8Array(32).fill(4);
    const salt = new Uint8Array(16).fill(5);
    const a = await deriveRoomKeys(null, link, salt);
    const b = await deriveRoomKeys(null, link.slice(), salt);
    const s = randomEpochSecret();
    const ka = await stepKeys(await rootEpochKeys(0, a.contentKey, a.chainKey), s);
    const kb = await stepKeys(await rootEpochKeys(0, b.contentKey, b.chainKey), s);
    expect(await sameKey(ka.contentKey, kb.contentKey)).toBe(true);
  });
});
