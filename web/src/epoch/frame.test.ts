import fc from "fast-check";
import * as cbor2 from "cbor2";
import { describe, expect, it } from "vitest";
import { generateIdentity } from "../crypto/identity";
import { decodeEpochKey, encodeEpochKey, MAX_CBOR_LEN, MAX_WRAPS, verifyEpochKey, type EpochKeyBody } from "./frame";

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

function frame(c: Uint8Array, sig: Uint8Array = new Uint8Array(64)): Uint8Array {
  const out = new Uint8Array(4 + c.length + sig.length);
  new DataView(out.buffer).setUint32(0, c.length, false);
  out.set(c, 4);
  out.set(sig, 4 + c.length);
  return out;
}

function map(b: EpochKeyBody, extra: Record<string, unknown> = {}): Map<string, unknown> {
  return new Map<string, unknown>([
    ["kind", b.kind],
    ["from", b.from],
    ["to", b.to],
    ["root", b.root],
    ["sender", b.sender],
    ["roster", b.roster],
    ["confirm", b.confirm],
    ["wraps", b.wraps.map((w) => ({ p: w.p, iv: w.iv, ct: w.ct }))],
    ...Object.entries(extra),
  ]);
}

function raw(m: Map<string, unknown>): Uint8Array {
  return frame(cbor2.encode(m));
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
    expect(dec).not.toBeNull();
    expect(await verifyEpochKey(HEADER, dec!, id.alg, id.publicKeyRaw)).toBe(false);
  });

  it("does not verify once a byte of the signature changes", async () => {
    const id = await generateIdentity();
    const enc = await encodeEpochKey(HEADER, body(), id);
    enc[enc.length - 1] ^= 1;
    const dec = decodeEpochKey(enc);
    expect(dec).not.toBeNull();
    expect(await verifyEpochKey(HEADER, dec!, id.alg, id.publicKeyRaw)).toBe(false);
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

  it("refuses a body with an extra key", () => {
    const b = body();
    expect(decodeEpochKey(raw(map(b, { extra: 1 })))).toBeNull();
  });

  it("refuses a body whose keys are in another order", () => {
    const b = body();
    const m = map(b);
    expect(decodeEpochKey(raw(m))).not.toBeNull();
    expect(decodeEpochKey(raw(new Map([...m].reverse())))).toBeNull();
  });

  it("refuses a 2 MB body of nested empty arrays quickly", () => {
    const n = 2_000_000;
    const c = new Uint8Array(n).fill(0x81);
    c[n - 1] = 0x80;
    const t = Date.now();
    expect(decodeEpochKey(frame(c))).toBeNull();
    expect(Date.now() - t).toBeLessThan(500);
    expect(MAX_CBOR_LEN).toBe(300_000);
  });

  it("never throws on a well-sized body of arbitrary bytes", () => {
    fc.assert(
      fc.property(fc.uint8Array({ maxLength: 600 }), fc.uint8Array({ minLength: 64, maxLength: 64 }), (c, sig) => {
        decodeEpochKey(frame(c, sig));
      }),
      { numRuns: 3000 },
    );
  });

  it("never throws on a valid body with flipped bytes or truncation", async () => {
    const id = await generateIdentity();
    const enc = await encodeEpochKey(HEADER, body(), id);
    const cb = enc.slice(4, enc.length - 64);
    const sig = enc.slice(enc.length - 64);
    fc.assert(
      fc.property(
        fc.array(fc.tuple(fc.nat(cb.length - 1), fc.integer({ min: 1, max: 255 })), { maxLength: 6 }),
        fc.nat(cb.length),
        (flips, cut) => {
          const c = cb.slice();
          for (const [i, x] of flips) c[i] ^= x;
          decodeEpochKey(frame(c, sig));
          decodeEpochKey(frame(c.slice(0, cut), sig));
        },
      ),
      { numRuns: 3000 },
    );
  });
});
