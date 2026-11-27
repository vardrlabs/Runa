import { describe, expect, it } from "vitest";
import { hexOf } from "./statement";
import { deriveReRoot, type WayIn } from "./reroot";

/// Known answers printed by `node scripts/kat-evict.mjs`. The link case uses
/// the same inputs as amendment J's vectors, so its confirm is CONFIRM_0.
const seq = (start: number, len: number): Uint8Array => Uint8Array.from({ length: len }, (_, i) => (start + i) & 0xff);
const SALT = seq(0xa0, 16);

describe("re-root derivation known answers", () => {
  it("derives a new link's verifier, confirm and fingerprint seed exactly as for a new room", async () => {
    const way: WayIn = { kind: "link", secret: seq(0x00, 32), salt: SALT, phrase: "" };
    const k = await deriveReRoot(way);
    expect(hexOf(k.verifier)).toBe("751bb8128ddb6f1e93622ed06a024d05f708ddaefc91af6fe775f948b61d1ee0");
    expect(hexOf(k.confirm)).toBe("0df8279076b71eaf55d33988c30e4b6c");
    expect(hexOf(k.fingerprintSeed)).toBe("8ed4865ff796131c2e68a6c0f1149254394cb31951d937103c2fe66957998680");
    expect(hexOf(k.authKey)).toBe("d096a3cad60a2475986fdd2df631aa67f60989ac3a4c18f2b4ccf6b6933680ce");
  });

  it("derives a new passphrase's root from its Argon2id output", async () => {
    const way: WayIn = { kind: "pass", secret: seq(0x40, 32), salt: SALT, phrase: "any words" };
    const k = await deriveReRoot(way);
    expect(hexOf(k.verifier)).toBe("fcc6595af8da139b6a1fbfdfb31199caa5ead791a3edf12c289844a191b2d940");
    expect(hexOf(k.confirm)).toBe("82aac7850d8ae2c7730ae8bc5bd7a66d");
    expect(hexOf(k.fingerprintSeed)).toBe("fc0156f4953a9fa5b3a3092f9eb53dece2f52df949ddeb00962d64fefd3e908c");
    expect(hexOf(k.authKey)).toBe("1a7a6dba6aafbf05bd06f5245b57aba31585cd1dda81c8dcefe6477fa55e37de");
  });

  it("keeps the content and chain keys non-extractable, and leaves the way in intact", async () => {
    const way: WayIn = { kind: "link", secret: seq(0x00, 32), salt: SALT, phrase: "" };
    const k = await deriveReRoot(way);
    expect(k.contentKey.extractable).toBe(false);
    expect(k.chainKey.extractable).toBe(false);
    expect(way.secret).toEqual(seq(0x00, 32));
  });
});
