import fc from "fast-check";
import { describe, expect, it } from "vitest";
import { bytesEqual, hexOf, keyDigest, rosterDigest, voteStatement, ZERO_KEY_DIGEST, ZERO_PEER } from "./statement";

const h = (s: string): Uint8Array => Uint8Array.from(s.match(/../g)!.map((x) => parseInt(x, 16)));
const seq = (start: number, len: number): Uint8Array => Uint8Array.from({ length: len }, (_, i) => (start + i) & 0xff);

/// Printed by `node scripts/kat-evict.mjs`; server/src/runar/evict.rs pins
/// the same bytes.
const STATEMENT =
  "72756e612f76312f6576696374b0b1b2b3b4b5b6b7b8b9babbbcbdbebf606162636465666768696a6b6c6d6e6f0000000733333333333333333333333333333333deb0e38ced1e41de6f92e70e80c418d2d356afaaa99e26f5939dbc7d3ef4772a11111111111111111111111111111111808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f";
const LINK_STATEMENT =
  "72756e612f76312f6576696374b0b1b2b3b4b5b6b7b8b9babbbcbdbebf606162636465666768696a6b6c6d6e6f0000000700000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000011111111111111111111111111111111808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f";
/// SHA-256 of 32 bytes of 0x33, the target key in the statement above.
const TARGET_KEY_DIGEST = "deb0e38ced1e41de6f92e70e80c418d2d356afaaa99e26f5939dbc7d3ef4772a";
/// SHA-256 of the 65-byte P-256 key the server's test uses.
const P256_PUB = "041f140146bfb1b251f84f4ddbe0d4cdcfd77afd984a9520e35794021f8312bb9eec995a08b1fa7704df3dcc0b50a9665263fb7711f95f9f8a449c5096e47c892b";
const P256_PUB_DIGEST = "f6140efc538823718229c03b61bdac222543e69b5d0cba12d9dcf917284fa5a6";

describe("the vote statement", () => {
  it("is the fixed layout amendment K gives", () => {
    const s = voteStatement(
      seq(0xb0, 16), seq(0x60, 16), 7, new Uint8Array(16).fill(0x33), h(TARGET_KEY_DIGEST), new Uint8Array(16).fill(0x11), seq(0x80, 32),
    );
    expect(hexOf(s)).toBe(STATEMENT);
    expect(s.length).toBe(145);
  });

  it("names no peer and no key for a link change", () => {
    const s = voteStatement(seq(0xb0, 16), seq(0x60, 16), 7, null, null, new Uint8Array(16).fill(0x11), seq(0x80, 32));
    expect(bytesEqual(s.slice(49, 65), ZERO_PEER)).toBe(true);
    expect(bytesEqual(s.slice(65, 97), ZERO_KEY_DIGEST)).toBe(true);
    expect(hexOf(s)).toBe(LINK_STATEMENT);
    expect(hexOf(s)).toBe(STATEMENT.slice(0, 98) + "00".repeat(48) + STATEMENT.slice(194));
  });

  it("refuses fields of the wrong size, and a target without its key or a key without its target", () => {
    const ok = new Uint8Array(16);
    const d = new Uint8Array(32).fill(1);
    expect(() => voteStatement(new Uint8Array(15), ok, 0, null, null, ok, new Uint8Array(32))).toThrow();
    expect(() => voteStatement(ok, ok, 0, new Uint8Array(17), d, ok, new Uint8Array(32))).toThrow();
    expect(() => voteStatement(ok, ok, 0, new Uint8Array(16).fill(1), new Uint8Array(31), ok, new Uint8Array(32))).toThrow();
    expect(() => voteStatement(ok, ok, 0, new Uint8Array(16).fill(1), null, ok, new Uint8Array(32))).toThrow();
    expect(() => voteStatement(ok, ok, 0, null, d, ok, new Uint8Array(32))).toThrow();
    expect(() => voteStatement(ok, ok, 0, ZERO_PEER, d, ok, new Uint8Array(32))).toThrow();
    expect(() => voteStatement(ok, ok, 0, new Uint8Array(16).fill(1), ZERO_KEY_DIGEST, ok, new Uint8Array(32))).toThrow();
    expect(() => voteStatement(ok, ok, 0, null, null, ok, new Uint8Array(31))).toThrow();
    expect(() => voteStatement(ok, ok, -1, null, null, ok, new Uint8Array(32))).toThrow();
    expect(() => voteStatement(ok, ok, 2 ** 32, null, null, ok, new Uint8Array(32))).toThrow();
  });

  it("changes when any field changes", () => {
    fc.assert(
      fc.property(fc.integer({ min: 0, max: 6 }), fc.integer({ min: 0, max: 15 }), (field, at) => {
        const parts = [
          new Uint8Array(16), new Uint8Array(16), new Uint8Array(16).fill(9), new Uint8Array(32).fill(9), new Uint8Array(16), new Uint8Array(32),
        ];
        const base = voteStatement(parts[0], parts[1], 3, parts[2], parts[3], parts[4], parts[5]);
        if (field === 6) {
          return !bytesEqual(base, voteStatement(parts[0], parts[1], 4, parts[2], parts[3], parts[4], parts[5]));
        }
        parts[field][at] ^= 1;
        return !bytesEqual(base, voteStatement(parts[0], parts[1], 3, parts[2], parts[3], parts[4], parts[5]));
      }),
    );
  });
});

describe("keyDigest", () => {
  it("is SHA-256 of a signing key's raw bytes, as the server computes it", async () => {
    expect(hexOf(await keyDigest(new Uint8Array(32).fill(0x33)))).toBe(TARGET_KEY_DIGEST);
    expect(hexOf(await keyDigest(h(P256_PUB)))).toBe(P256_PUB_DIGEST);
  });
});

describe("rosterDigest", () => {
  it("is SHA-256 of the canonical roster bytes, so it matches the shred hash", async () => {
    const roster = [{ peerId: new Uint8Array(16).fill(1), pubkey: new Uint8Array(32).fill(2), joinedAtSeq: 1 }];
    const d = await rosterDigest(roster);
    expect(d.length).toBe(32);
    expect(await rosterDigest([...roster])).toEqual(d);
    expect(await rosterDigest([])).not.toEqual(d);
  });
});

describe("bytesEqual and hexOf", () => {
  it("compare and print bytes", () => {
    expect(bytesEqual(h("0102"), h("0102"))).toBe(true);
    expect(bytesEqual(h("0102"), h("0103"))).toBe(false);
    expect(bytesEqual(h("01"), h("0102"))).toBe(false);
    expect(hexOf(h("00ff10"))).toBe("00ff10");
  });
});
