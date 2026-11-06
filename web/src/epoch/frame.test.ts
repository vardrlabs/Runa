import fc from "fast-check";
import { describe, expect, it } from "vitest";
import { generateIdentity } from "../crypto/identity";
import { decodeEpochKey, encodeEpochKey, MAX_WRAPS, verifyEpochKey, type EpochKeyBody } from "./frame";

const HEADER = new Uint8Array(32).fill(1);
const bytes = (n: number, v: number) => new Uint8Array(n).fill(v);

function body(over: Partial<EpochKeyBody> = {}): EpochKeyBody {
  return {
    kind: "step",
    from: 0,
    to: 1,
    root: 0,
    sender: bytes(16, 2),
    roster: bytes(32, 3),
    confirm: bytes(16, 4),
    wraps: [{ p: bytes(16, 5), iv: bytes(12, 6), ct: bytes(48, 7) }],
    ...over,
  };
}

describe("EPOCH_KEY codec", () => {
  it("round-trips and verifies", async () => {
    const id = await generateIdentity();
    const enc = await encodeEpochKey(HEADER, body(), id);
    const dec = decodeEpochKey(enc);
    expect(dec).not.toBeNull();
    expect(dec!.body).toEqual(body());
    expect(await verifyEpochKey(HEADER, dec!, id.alg, id.publicKeyRaw)).toBe(true);
  });

  it("does not verify under a different header", async () => {
    const id = await generateIdentity();
    const dec = decodeEpochKey(await encodeEpochKey(HEADER, body(), id))!;
    const other = HEADER.slice();
    other[23] = 2;
    expect(await verifyEpochKey(other, dec, id.alg, id.publicKeyRaw)).toBe(false);
  });

  it("does not verify once a byte of the body changes", async () => {
    const id = await generateIdentity();
    const enc = await encodeEpochKey(HEADER, body(), id);
    enc[enc.length - 70] ^= 1;
    const dec = decodeEpochKey(enc);
    if (dec) expect(await verifyEpochKey(HEADER, dec, id.alg, id.publicKeyRaw)).toBe(false);
  });

  it("refuses a step that does not name the next epoch", async () => {
    const id = await generateIdentity();
    expect(decodeEpochKey(await encodeEpochKey(HEADER, body({ from: 0, to: 2 }), id))).toBeNull();
  });

  it("refuses a root past the epoch", async () => {
    const id = await generateIdentity();
    expect(decodeEpochKey(await encodeEpochKey(HEADER, body({ root: 2 }), id))).toBeNull();
  });

  it("refuses too many wraps", async () => {
    const id = await generateIdentity();
    const wraps = Array.from({ length: MAX_WRAPS + 1 }, () => ({ p: bytes(16, 5), iv: bytes(12, 6), ct: bytes(48, 7) }));
    expect(decodeEpochKey(await encodeEpochKey(HEADER, body({ wraps }), id))).toBeNull();
  });

  it("refuses fields of the wrong size", async () => {
    const id = await generateIdentity();
    expect(decodeEpochKey(await encodeEpochKey(HEADER, body({ sender: bytes(15, 2) }), id))).toBeNull();
    expect(decodeEpochKey(await encodeEpochKey(HEADER, body({ confirm: bytes(17, 4) }), id))).toBeNull();
  });

  it("refuses a body whose length prefix lies", async () => {
    const id = await generateIdentity();
    const enc = await encodeEpochKey(HEADER, body(), id);
    expect(decodeEpochKey(enc.slice(0, enc.length - 1))).toBeNull();
  });

  it("never throws on arbitrary bytes", () => {
    fc.assert(
      fc.property(fc.uint8Array({ maxLength: 512 }), (b) => {
        decodeEpochKey(b);
      }),
      { numRuns: 2000 },
    );
  });
});
