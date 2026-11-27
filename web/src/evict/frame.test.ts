import * as cbor2 from "cbor2";
import fc from "fast-check";
import { describe, expect, it } from "vitest";
import { generateIdentity } from "../crypto/identity";
import { MAX_PHRASE_LEN, MAX_WRAP_CT, encodeWayIn } from "./reroot";
import { encodeHeader, FT, PROTOCOL_VERSION } from "../transport/frame";
import {
  decodeCancel,
  decodeCommit,
  decodeRequest,
  decodeVote,
  encodeCancel,
  encodeClear,
  encodeCommit,
  encodeRequest,
  encodeVote,
  MAX_VOTES,
  verifyCommit,
  type CommitClear,
  type CommitTail,
  type EvictRequest,
} from "./frame";

const ROOM = new Uint8Array(16).fill(7);
const header = (epoch: number) =>
  encodeHeader({ version: PROTOCOL_VERSION, frameType: FT.EVICT_COMMIT, roomId: ROOM, epoch, nonceSess: new Uint8Array(4), flags: 0 });

function request(over: Partial<EvictRequest> = {}): EvictRequest {
  return {
    id: new Uint8Array(16).fill(1),
    epoch: 3,
    target: new Uint8Array(16).fill(2),
    targetKey: new Uint8Array(32).fill(3),
    verifier: new Uint8Array(32).fill(4),
    roster: new Uint8Array(32).fill(5),
    policy: "UNANIMOUS",
    deadline: 60_000,
    sig: new Uint8Array(64).fill(6),
    ...over,
  };
}

function clear(over: Partial<CommitClear> = {}): CommitClear {
  return {
    requestId: new Uint8Array(16).fill(1),
    target: new Uint8Array(16).fill(2),
    targetKeyDigest: new Uint8Array(32).fill(3),
    verifier: new Uint8Array(32).fill(4),
    salt: new Uint8Array(16).fill(8),
    config: new Uint8Array([9, 9, 9]),
    votes: [{ voter: new Uint8Array(16).fill(10), sig: new Uint8Array(64).fill(11) }],
    ...over,
  };
}

function tail(over: Partial<CommitTail> = {}): CommitTail {
  return {
    root: 4,
    sender: new Uint8Array(16).fill(10),
    confirm: new Uint8Array(16).fill(12),
    wraps: [{ p: new Uint8Array(16).fill(13), iv: new Uint8Array(12).fill(14), ct: new Uint8Array(40).fill(15) }],
    ...over,
  };
}

describe("EVICT_REQUEST", () => {
  it("round-trips, for a removal and for a link change", () => {
    expect(decodeRequest(encodeRequest(request()))).toEqual(request());
    const relink = request({ target: null, targetKey: null });
    expect(decodeRequest(encodeRequest(relink))).toEqual(relink);
  });

  it("refuses what amendment K does not allow", () => {
    for (const bad of [
      request({ id: new Uint8Array(15) }),
      request({ verifier: new Uint8Array(31) }),
      request({ roster: new Uint8Array(33) }),
      request({ sig: new Uint8Array(63) }),
      request({ deadline: 3_600_001 }),
      request({ targetKey: null }),
      request({ targetKey: new Uint8Array(40) }),
      request({ target: null, targetKey: new Uint8Array(32) }),
      request({ policy: "INITIATOR" as never }),
      request({ policy: "MAJORITY" }),
      request({ policy: "THRESHOLD" }),
    ]) {
      expect(decodeRequest(encodeRequest(bad))).toBeNull();
    }
  });

  it("refuses a map with its keys in another order", () => {
    const r = request();
    const reordered = cbor2.encode({
      id: r.id, type: "EVICT_REQUEST", epoch: r.epoch, target: r.target, targetKey: r.targetKey,
      verifier: r.verifier, roster: r.roster, policy: r.policy, deadline: r.deadline, sig: r.sig,
    });
    expect(decodeRequest(reordered)).toBeNull();
  });
});

describe("EVICT_VOTE and EVICT_CANCEL", () => {
  it("round-trip", () => {
    const yes = { id: new Uint8Array(16).fill(1), vote: "APPROVE" as const, sig: new Uint8Array(64).fill(2) };
    const no = { id: new Uint8Array(16).fill(1), vote: "REJECT" as const, sig: null };
    expect(decodeVote(encodeVote(yes))).toEqual(yes);
    expect(decodeVote(encodeVote(no))).toEqual(no);
    expect(decodeCancel(encodeCancel({ id: new Uint8Array(16).fill(3) }))).toEqual({ id: new Uint8Array(16).fill(3) });
  });

  it("an approval must be signed and a refusal must not be", () => {
    expect(decodeVote(encodeVote({ id: new Uint8Array(16), vote: "APPROVE", sig: null }))).toBeNull();
    expect(decodeVote(encodeVote({ id: new Uint8Array(16), vote: "REJECT", sig: new Uint8Array(64) }))).toBeNull();
  });

  it("a frame of one type never decodes as another", () => {
    const req = encodeRequest(request());
    expect(decodeVote(req)).toBeNull();
    expect(decodeCancel(req)).toBeNull();
    expect(decodeRequest(encodeCancel({ id: new Uint8Array(16) }))).toBeNull();
  });
});

describe("EVICT_COMMIT", () => {
  it("lays out the clear part exactly as the server parses it", () => {
    const c = clear();
    const b = encodeClear(c);
    expect(b.length).toBe(16 + 16 + 32 + 32 + 16 + 4 + 3 + 1 + 16 + 1 + 64);
    expect(b.slice(0, 16)).toEqual(c.requestId);
    expect(b.slice(16, 32)).toEqual(c.target);
    expect(b.slice(32, 64)).toEqual(c.targetKeyDigest);
    expect(b.slice(64, 96)).toEqual(c.verifier);
    expect(new DataView(b.buffer).getUint32(112, false)).toBe(3);
    expect(b[119]).toBe(1);
    expect(b[119 + 1 + 16]).toBe(64);
    expect(encodeClear(clear({ target: null, targetKeyDigest: null })).slice(16, 64)).toEqual(new Uint8Array(48));
  });

  it("names a target by its peer id and its key digest together, or names neither", async () => {
    expect(() => encodeClear(clear({ targetKeyDigest: null }))).toThrow();
    expect(() => encodeClear(clear({ target: null }))).toThrow();
    expect(() => encodeClear(clear({ targetKeyDigest: new Uint8Array(31) }))).toThrow();
    const id = await generateIdentity();
    const body = await encodeCommit(header(0), clear(), tail(), id);
    const noKey = body.slice();
    noKey.fill(0, 32, 64);
    expect(decodeCommit(noKey)).toBeNull();
    const noPeer = body.slice();
    noPeer.fill(0, 16, 32);
    expect(decodeCommit(noPeer)).toBeNull();
  });

  it("round-trips and its signature covers the header, the clear part and the tail", async () => {
    const id = await generateIdentity();
    const h = header(3);
    const body = await encodeCommit(h, clear(), tail(), id);
    const d = decodeCommit(body)!;
    expect(d.clear).toEqual(clear());
    expect(d.tail).toEqual(tail());
    expect(await verifyCommit(h, d, id.alg, id.publicKeyRaw)).toBe(true);
    expect(await verifyCommit(header(4), d, id.alg, id.publicKeyRaw)).toBe(false);
    const flipped = body.slice();
    flipped[20] ^= 1;
    const d2 = decodeCommit(flipped)!;
    expect(await verifyCommit(h, d2, id.alg, id.publicKeyRaw)).toBe(false);
  });

  it("reads a zero target as a link change", async () => {
    const id = await generateIdentity();
    const d = decodeCommit(await encodeCommit(header(0), clear({ target: null, targetKeyDigest: null }), tail(), id))!;
    expect(d.clear.target).toBeNull();
    expect(d.clear.targetKeyDigest).toBeNull();
  });

  it("refuses a truncated or padded body, and any tail that is not one canonical map", async () => {
    const id = await generateIdentity();
    const body = await encodeCommit(header(0), clear(), tail(), id);
    for (let n = 0; n < body.length; n += 7) expect(decodeCommit(body.slice(0, n))).toBeNull();
    const padded = new Uint8Array(body.length + 1);
    padded.set(body);
    expect(decodeCommit(padded)).toBeNull();
    const clearBytes = encodeClear(clear());
    const noSig = cbor2.encode({ root: 4, sender: new Uint8Array(16), confirm: new Uint8Array(16), wraps: [] });
    const joined = new Uint8Array(clearBytes.length + noSig.length);
    joined.set(clearBytes);
    joined.set(noSig, clearBytes.length);
    expect(decodeCommit(joined)).toBeNull();
  });

  it("holds the vote count to 1..32 and every vote signature to 64 bytes", () => {
    expect(() => encodeClear(clear({ votes: [] }))).toThrow();
    const many = Array.from({ length: MAX_VOTES + 1 }, () => ({ voter: new Uint8Array(16), sig: new Uint8Array(64) }));
    expect(() => encodeClear(clear({ votes: many }))).toThrow();
  });

  it("refuses a signature length byte that is not 64 when nothing else is wrong", async () => {
    const id = await generateIdentity();
    const body = await encodeCommit(header(0), clear(), tail(), id);
    expect(decodeCommit(body)).not.toBeNull();
    const bad = body.slice();
    expect(bad[119 + 1 + 16]).toBe(64);
    bad[119 + 1 + 16] = 63;
    expect(decodeCommit(bad)).toBeNull();
  });

  it("encodeClear checks the request id, the verifier and the salt", () => {
    expect(() => encodeClear(clear({ requestId: new Uint8Array(15) }))).toThrow();
    expect(() => encodeClear(clear({ verifier: new Uint8Array(33) }))).toThrow();
    expect(() => encodeClear(clear({ salt: new Uint8Array(17) }))).toThrow();
  });

  it("carries a wrap of the largest way in, a maximum-length passphrase of three-byte characters", async () => {
    const phrase = "\u20ac".repeat(MAX_PHRASE_LEN);
    const plain = encodeWayIn({ kind: "pass", secret: new Uint8Array(32), salt: new Uint8Array(16), phrase });
    const key = await crypto.subtle.generateKey({ name: "AES-GCM", length: 256 }, false, ["encrypt"]);
    const iv = new Uint8Array(12).fill(14);
    const ct = new Uint8Array(await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, plain as BufferSource));
    expect(ct.length).toBe(MAX_WRAP_CT);
    const id = await generateIdentity();
    const t = tail({ wraps: [{ p: new Uint8Array(16).fill(13), iv, ct }] });
    const d = decodeCommit(await encodeCommit(header(0), clear(), t, id));
    expect(d).not.toBeNull();
    expect(d!.tail.wraps[0].ct).toEqual(ct);
  });

  it("encodeCommit refuses a tail the decoder would refuse", async () => {
    const id = await generateIdentity();
    const w = { p: new Uint8Array(16).fill(13), iv: new Uint8Array(12).fill(14), ct: new Uint8Array(40) };
    const bad: CommitTail[] = [
      tail({ wraps: [{ ...w, ct: new Uint8Array(MAX_WRAP_CT + 1) }] }),
      tail({ wraps: [{ ...w, ct: new Uint8Array(15) }] }),
      tail({ wraps: [{ ...w, p: new Uint8Array(15) }] }),
      tail({ wraps: [{ ...w, iv: new Uint8Array(13) }] }),
      tail({ wraps: Array.from({ length: MAX_VOTES + 1 }, () => w) }),
      tail({ sender: new Uint8Array(15) }),
      tail({ confirm: new Uint8Array(17) }),
      tail({ root: -1 }),
    ];
    for (const t of bad) await expect(encodeCommit(header(0), clear(), t, id)).rejects.toThrow();
  });

  it("never throws on arbitrary bytes", () => {
    fc.assert(
      fc.property(fc.uint8Array({ maxLength: 400 }), (b) => {
        decodeCommit(b);
        decodeRequest(b);
        decodeVote(b);
        decodeCancel(b);
        return true;
      }),
    );
  });

  it("round-trips arbitrary well-formed clear parts", () => {
    fc.assert(
      fc.property(
        fc.uint8Array({ minLength: 16, maxLength: 16 }),
        fc.option(fc.uint8Array({ minLength: 16, maxLength: 16 }).filter((t) => t.some((x) => x !== 0)), { nil: null }),
        fc.uint8Array({ maxLength: 64 }),
        fc.integer({ min: 1, max: MAX_VOTES }),
        (requestId, target, config, n) => {
          const c = clear({
            requestId,
            target,
            targetKeyDigest: target ? new Uint8Array(32).fill(target[0] | 1) : null,
            config,
            votes: Array.from({ length: n }, (_, i) => ({ voter: new Uint8Array(16).fill(i), sig: new Uint8Array(64).fill(i) })),
          });
          const body = new Uint8Array([...encodeClear(c), ...cbor2.encode({ root: 1, sender: new Uint8Array(16), confirm: new Uint8Array(16), wraps: [], sig: new Uint8Array(64) })]);
          const d = decodeCommit(body);
          return (
            d !== null &&
            d.clear.votes.length === n &&
            (d.clear.target === null) === (target === null) &&
            (d.clear.targetKeyDigest === null) === (target === null)
          );
        },
      ),
    );
  });
});
