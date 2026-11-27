import * as cbor2 from "cbor2";
import fc from "fast-check";
import { describe, expect, it } from "vitest";
import { parseFragment } from "../keys-session";
import { bytesEqual } from "./statement";
import {
  decodeWayIn,
  deriveReRoot,
  encodeWayIn,
  MAX_PHRASE_LEN,
  newLinkWayIn,
  newPassWayIn,
  wayFragment,
  wipeWayIn,
  type WayIn,
} from "./reroot";

describe("a new way into a room", () => {
  it("is a fresh link secret and salt for a private room, and makes a link", () => {
    const a = newLinkWayIn();
    const b = newLinkWayIn();
    expect(a.kind).toBe("link");
    expect(a.secret.length).toBe(32);
    expect(a.salt.length).toBe(16);
    expect(bytesEqual(a.secret, b.secret)).toBe(false);
    const parsed = parseFragment(wayFragment(a)!)!;
    expect(parsed.linkSecret).toEqual(a.secret);
    expect(parsed.roomSalt).toEqual(a.salt);
  });

  it("is the passphrase's Argon2id output and a fresh salt for a shared room, with no link", async () => {
    const w = await newPassWayIn("correct horse battery staple again");
    expect(w.kind).toBe("pass");
    expect(w.secret.length).toBe(32);
    expect(w.phrase).toBe("correct horse battery staple again");
    expect(wayFragment(w)).toBeNull();
  });

  it("refuses an empty passphrase", async () => {
    await expect(newPassWayIn("")).rejects.toThrow();
  });

  it("is zeroed by wipeWayIn", () => {
    const w = newLinkWayIn();
    wipeWayIn(w);
    expect(w.secret.every((x) => x === 0)).toBe(true);
    expect(w.phrase).toBe("");
  });
});

describe("the wrap payload", () => {
  it("round-trips", () => {
    fc.assert(
      fc.property(
        fc.uint8Array({ minLength: 32, maxLength: 32 }),
        fc.uint8Array({ minLength: 16, maxLength: 16 }),
        fc.string({ minLength: 1, maxLength: 40 }),
        fc.boolean(),
        (secret, salt, phrase, isLink) => {
          const w: WayIn = isLink ? { kind: "link", secret, salt, phrase: "" } : { kind: "pass", secret, salt, phrase };
          const back = decodeWayIn(encodeWayIn(w))!;
          return back.kind === w.kind && bytesEqual(back.secret, secret) && bytesEqual(back.salt, salt) && back.phrase === w.phrase;
        },
      ),
    );
  });

  it("refuses anything that is not exactly one well-formed way in", () => {
    const good = { kind: "link", secret: new Uint8Array(32), salt: new Uint8Array(16), phrase: "" };
    expect(decodeWayIn(cbor2.encode(good))).not.toBeNull();
    for (const bad of [
      { ...good, kind: "both" },
      { ...good, secret: new Uint8Array(31) },
      { ...good, salt: new Uint8Array(15) },
      { ...good, phrase: "a link carries no phrase" },
      { ...good, kind: "pass", phrase: "" },
      { ...good, kind: "pass", phrase: "x".repeat(MAX_PHRASE_LEN + 1) },
      { secret: good.secret, kind: "link", salt: good.salt, phrase: "" },
    ]) {
      expect(decodeWayIn(cbor2.encode(bad))).toBeNull();
    }
    expect(decodeWayIn(new Uint8Array([0xff, 0x00]))).toBeNull();
  });

  it("never throws on arbitrary bytes", () => {
    fc.assert(
      fc.property(fc.uint8Array({ maxLength: 200 }), (b) => {
        decodeWayIn(b);
        return true;
      }),
    );
  });
});

describe("deriveReRoot", () => {
  it("is deterministic, and different ways in give different verifiers", async () => {
    const w = newLinkWayIn();
    const a = await deriveReRoot(w);
    const b = await deriveReRoot(w);
    expect(a.verifier).toEqual(b.verifier);
    expect(a.confirm).toEqual(b.confirm);
    const other = await deriveReRoot(newLinkWayIn());
    expect(bytesEqual(a.verifier, other.verifier)).toBe(false);
  });
});
