import fc from "fast-check";
import { describe, expect, it } from "vitest";
import { generateIdentity, signPayload, type Identity } from "../crypto/identity";
import type { RosterEntry } from "../shred/roster";
import type { EvictRequest, EvictVote } from "./frame";
import { COMMIT_WAIT_MS, EvictMachine, MAX_SEEN_REQUESTS, requestStatement } from "./machine";
import { keyDigest, rosterDigest, voteStatement } from "./statement";

const ROOM = new Uint8Array(16).fill(9);

interface Person {
  id: Uint8Array;
  identity: Identity;
  entry: RosterEntry;
}

interface Room {
  people: Person[];
  roster: RosterEntry[];
  clock: { now: number };
  epoch: { value: number };
}

async function makeRoom(n: number): Promise<Room> {
  const people: Person[] = [];
  for (let i = 0; i < n; i++) {
    const identity = await generateIdentity();
    const id = new Uint8Array(16).fill(i + 1);
    people.push({ id, identity, entry: { peerId: id, pubkey: identity.publicKeyRaw, joinedAtSeq: i + 1 } });
  }
  return { people, roster: people.map((p) => p.entry), clock: { now: 1_000_000 }, epoch: { value: 0 } };
}

function machineFor(room: Room, me: Person): EvictMachine {
  return new EvictMachine({
    roomId: ROOM,
    me: () => me.id,
    members: () => room.roster,
    now: () => room.clock.now,
    epoch: () => room.epoch.value,
  });
}

const VERIFIER = new Uint8Array(32).fill(0x44);

type Signed = { id: Uint8Array; epoch: number; target: Uint8Array | null; targetKey: Uint8Array | null; verifier: Uint8Array };

/// A signature over the statement, which names the target's key by its
/// SHA-256, as every member computes it from the request's `targetKey`.
async function sign(p: Person, req: Signed): Promise<Uint8Array> {
  const digest = req.target && req.targetKey ? await keyDigest(req.targetKey) : null;
  return signPayload(p.identity, voteStatement(ROOM, req.id, req.epoch, req.target, digest, p.id, req.verifier));
}

/// The digest `start` is handed by the member who made the request.
const digestOf = (req: EvictRequest): Promise<Uint8Array | null> =>
  req.target && req.targetKey ? keyDigest(req.targetKey) : Promise.resolve(null);

async function requestBy(room: Room, proposer: Person, target: Person | null, over: Partial<EvictRequest> = {}): Promise<EvictRequest> {
  // The signature covers the statement fields, overrides included, so a test
  // that changes the id or the epoch still sends a request signed for it.
  const base: Signed = {
    id: new Uint8Array(16).fill(0x77),
    epoch: room.epoch.value,
    target: target?.id ?? null,
    targetKey: target?.identity.publicKeyRaw ?? null,
    verifier: VERIFIER,
    ...(over.id ? { id: over.id } : {}),
    ...(over.epoch !== undefined ? { epoch: over.epoch } : {}),
    ...(over.target !== undefined ? { target: over.target } : {}),
    ...(over.targetKey !== undefined ? { targetKey: over.targetKey } : {}),
  };
  return {
    ...base,
    roster: await rosterDigest(room.roster),
    policy: "UNANIMOUS",
    deadline: 60_000,
    sig: await sign(proposer, base),
    ...over,
  };
}

async function approve(p: Person, req: EvictRequest): Promise<EvictVote> {
  return { id: req.id, vote: "APPROVE", sig: await sign(p, req) };
}

describe("the evict machine fails closed (amendment K)", () => {
  it("approves only when everyone but the target has approved", async () => {
    const room = await makeRoom(4);
    const [a, b, c, t] = room.people;
    const req = await requestBy(room, a, t);
    const m = machineFor(room, b);
    expect(await m.onRequest(req, a.id)).toBeNull();
    expect(m.state).toBe("VOTING");
    expect(await m.onVote(await approve(c, req), c.id)).toBeNull();
    expect(m.state).toBe("VOTING");
    m.recordOwn(await sign(b, req));
    expect(m.state).toBe("APPROVED");
    expect(m.ballots().map((x) => x.voter)).toEqual([a.id, b.id, c.id]);
  });

  it("a link change needs everyone, the proposer included", async () => {
    const room = await makeRoom(3);
    const [a, b, c] = room.people;
    const req = await requestBy(room, a, null);
    const m = machineFor(room, b);
    await m.onRequest(req, a.id);
    m.recordOwn(await sign(b, req));
    expect(m.state).toBe("VOTING");
    await m.onVote(await approve(c, req), c.id);
    expect(m.state).toBe("APPROVED");
  });

  it("in a room of two the proposer's own request is already approved", async () => {
    const room = await makeRoom(2);
    const [a, t] = room.people;
    const req = await requestBy(room, a, t);
    const m = machineFor(room, a);
    m.start(req, a.id, room.roster, await digestOf(req));
    expect(m.state).toBe("APPROVED");
  });

  it("any refusal ends it at once", async () => {
    const room = await makeRoom(3);
    const [a, b, t] = room.people;
    const req = await requestBy(room, a, t);
    const m = machineFor(room, a);
    m.start(req, a.id, room.roster, await digestOf(req));
    expect(await m.onVote({ id: req.id, vote: "REJECT", sig: null }, b.id)).toBeNull();
    expect(m.state).toBe("REJECTED");
    expect(await m.onVote(await approve(b, req), b.id)).toBe("not-voting");
  });

  it("drops forged signatures and never counts them", async () => {
    const room = await makeRoom(3);
    const [a, b, t] = room.people;
    const req = await requestBy(room, a, t);
    const m = machineFor(room, a);
    m.start(req, a.id, room.roster, await digestOf(req));
    const forged = { id: req.id, vote: "APPROVE" as const, sig: await sign(t, req) };
    expect(await m.onVote(forged, b.id)).toBe("bad-signature");
    expect(m.state).toBe("VOTING");
  });

  it("drops a second vote from the same member", async () => {
    const room = await makeRoom(4);
    const [a, b, c, t] = room.people;
    const req = await requestBy(room, a, t);
    const m = machineFor(room, a);
    m.start(req, a.id, room.roster, await digestOf(req));
    const v = await approve(b, req);
    expect(await m.onVote(v, b.id)).toBeNull();
    expect(await m.onVote(v, b.id)).toBe("duplicate-vote");
    expect(await m.onVote({ id: req.id, vote: "REJECT", sig: null }, b.id)).toBe("duplicate-vote");
    expect(m.state).toBe("VOTING");
    void c;
  });

  it("never counts the target or anyone outside the frozen roster", async () => {
    const room = await makeRoom(3);
    const [a, b, t] = room.people;
    const req = await requestBy(room, a, t);
    const m = machineFor(room, a);
    m.start(req, a.id, room.roster, await digestOf(req));
    expect(await m.onVote(await approve(t, req), t.id)).toBe("not-in-policy-set");
    const late = (await makeRoom(5)).people[4];
    room.roster = [...room.roster, late.entry];
    expect(await m.onVote(await approve(late, req), late.id)).toBe("not-in-policy-set");
    expect(m.state).toBe("VOTING");
    void b;
  });

  it("refuses a request made with a different list of people", async () => {
    const room = await makeRoom(3);
    const [a, b, t] = room.people;
    const req = await requestBy(room, a, t, { roster: new Uint8Array(32) });
    expect(await machineFor(room, b).onRequest(req, a.id)).toBe("roster-mismatch");
  });

  it("refuses a request at another epoch, under another policy, or with a bad signature", async () => {
    const room = await makeRoom(3);
    const [a, b, t] = room.people;
    expect(await machineFor(room, b).onRequest(await requestBy(room, a, t, { epoch: 1 }), a.id)).toBe("wrong-epoch");
    expect(await machineFor(room, b).onRequest(await requestBy(room, a, t, { policy: "MAJORITY" }), a.id)).toBe("policy-not-permitted");
    // Signed by t, delivered as if from a: a's key does not verify it.
    const signedByT = await requestBy(room, t, t);
    expect(await machineFor(room, b).onRequest(signedByT, a.id)).toBe("bad-signature");
  });

  it("refuses a target the roster does not show with that key, and a proposer naming itself", async () => {
    const room = await makeRoom(3);
    const [a, b, t] = room.people;
    const wrongKey = await requestBy(room, a, t, { targetKey: b.identity.publicKeyRaw });
    expect(await machineFor(room, b).onRequest(wrongKey, a.id)).toBe("target-key-mismatch");
    const absent = await requestBy(room, a, t, { target: new Uint8Array(16).fill(0xee) });
    expect(await machineFor(room, b).onRequest(absent, a.id)).toBe("unknown-target");
    const self = await requestBy(room, a, a);
    expect(await machineFor(room, b).onRequest(self, a.id)).toBe("proposer-is-target");
  });

  it("is busy while a vote is open, and takes a fresh request after one settles", async () => {
    const room = await makeRoom(3);
    const [a, b, t] = room.people;
    const m = machineFor(room, b);
    const first = await requestBy(room, a, t);
    await m.onRequest(first, a.id);
    expect(await m.onRequest(await requestBy(room, a, t, { id: new Uint8Array(16).fill(1) }), a.id)).toBe("busy");
    m.rejectOwn();
    expect(m.state).toBe("REJECTED");
    expect(await m.onRequest(await requestBy(room, a, t, { id: new Uint8Array(16).fill(2) }), a.id)).toBeNull();
    expect(m.state).toBe("VOTING");
  });

  it("expires at its deadline, and an approved vote with no commit fails", async () => {
    const room = await makeRoom(3);
    const [a, b, t] = room.people;
    const m = machineFor(room, b);
    await m.onRequest(await requestBy(room, a, t, { deadline: 5_000 }), a.id);
    room.clock.now += 4_999;
    expect(m.tick(room.clock.now)).toBeNull();
    room.clock.now += 1;
    expect(m.tick(room.clock.now)?.state).toBe("EXPIRED");

    const m2 = machineFor(room, b);
    const req = await requestBy(room, a, t, { id: new Uint8Array(16).fill(3) });
    await m2.onRequest(req, a.id);
    m2.recordOwn(await sign(b, req));
    expect(m2.state).toBe("APPROVED");
    room.clock.now += COMMIT_WAIT_MS;
    expect(m2.tick(room.clock.now)).toEqual({ state: "FAILED", reason: "no-commit" });
  });

  it("fails when the room's epoch moves during the vote", async () => {
    const room = await makeRoom(3);
    const [a, b, t] = room.people;
    const m = machineFor(room, b);
    await m.onRequest(await requestBy(room, a, t), a.id);
    room.epoch.value = 1;
    expect(m.tick(room.clock.now)).toEqual({ state: "FAILED", reason: "epoch-moved" });
  });

  it("fails closed when the proposer or a needed voter leaves", async () => {
    const room = await makeRoom(4);
    const [a, b, c, t] = room.people;
    for (const [gone, reason] of [[a, "proposer-left"], [c, "voter-left"]] as const) {
      const m = machineFor(room, b);
      await m.onRequest(await requestBy(room, a, t), a.id);
      expect(m.memberLeft(gone.id)).toBe(reason);
      expect(m.state).toBe("FAILED");
    }
    const m = machineFor(room, b);
    await m.onRequest(await requestBy(room, a, t), a.id);
    expect(m.memberLeft(new Uint8Array(16).fill(0xee))).toBeNull();
    expect(m.state).toBe("VOTING");
  });

  it("carries on when the target leaves, so reconnecting does not dodge the vote", async () => {
    const room = await makeRoom(3);
    const [a, b, t] = room.people;
    const req = await requestBy(room, a, t);
    const m = machineFor(room, b);
    await m.onRequest(req, a.id);
    room.roster = room.roster.filter((r) => r !== t.entry);
    expect(m.memberLeft(t.id)).toBeNull();
    expect(m.state).toBe("VOTING");
    m.recordOwn(await sign(b, req));
    expect(m.state).toBe("APPROVED");
    expect(await m.commitSatisfies({ ...(await requestStatement(req)), votes: m.ballots() })).toBe(true);
  });

  it("leaves out every connection that holds the target's signing key", async () => {
    const room = await makeRoom(3);
    const [a, b, t] = room.people;
    // The target's earlier connection, not yet gone, under the same key.
    const ghost: RosterEntry = { peerId: new Uint8Array(16).fill(0xdd), pubkey: t.identity.publicKeyRaw, joinedAtSeq: 9 };
    room.roster = [...room.roster, ghost];
    const req = await requestBy(room, a, t);
    const m = machineFor(room, b);
    expect(await m.onRequest(req, a.id)).toBeNull();
    expect(m.current()!.policySet.map((r) => r.peerId)).toEqual([a.id, b.id]);
    expect(await m.onVote({ id: req.id, vote: "APPROVE", sig: await sign(t, req) }, ghost.peerId)).toBe("not-in-policy-set");
    m.recordOwn(await sign(b, req));
    expect(m.state).toBe("APPROVED");
    // A member that never saw the request leaves the ghost out too, by the
    // key digest the commit names, even once the named connection is gone.
    const late = machineFor(room, room.people[1]);
    const st = await requestStatement(req);
    expect(await late.commitSatisfies({ ...st, votes: [{ voter: a.id, sig: req.sig }] })).toBe(true);
    const full = room.roster;
    room.roster = room.roster.filter((r) => r !== t.entry);
    expect(await late.commitSatisfies({ ...st, votes: [{ voter: a.id, sig: req.sig }] })).toBe(true);
    room.roster = full;
    // A proposer cannot name a connection that holds its own key.
    const selfGhost: RosterEntry = { peerId: new Uint8Array(16).fill(0xcc), pubkey: a.identity.publicKeyRaw, joinedAtSeq: 10 };
    room.roster = [...room.roster, selfGhost];
    const base = { id: new Uint8Array(16).fill(0x78), epoch: 0, target: selfGhost.peerId, targetKey: a.identity.publicKeyRaw, verifier: VERIFIER };
    const named: EvictRequest = {
      ...base,
      roster: await rosterDigest(room.roster),
      policy: "UNANIMOUS",
      deadline: 60_000,
      sig: await sign(a, base),
    };
    expect(await machineFor(room, b).onRequest(named, a.id)).toBe("proposer-is-target");
  });

  it("is cancelled only by its proposer, for that request", async () => {
    const room = await makeRoom(3);
    const [a, b, t] = room.people;
    const m = machineFor(room, b);
    const req = await requestBy(room, a, t);
    await m.onRequest(req, a.id);
    expect(m.onCancel(req.id, t.id)).toBe("cancel-not-from-proposer");
    expect(m.onCancel(new Uint8Array(16), a.id)).toBe("unknown-request");
    expect(m.state).toBe("VOTING");
    expect(m.onCancel(req.id, a.id)).toBeNull();
    expect(m.state).toBe("CANCELLED");
  });
});

describe("the deadline holds whether or not tick has run", () => {
  it("does not count an approval that arrives after the deadline", async () => {
    const room = await makeRoom(4);
    const [a, b, c, t] = room.people;
    const req = await requestBy(room, a, t, { deadline: 5_000 });
    const m = machineFor(room, b);
    await m.onRequest(req, a.id);
    m.recordOwn(await sign(b, req));
    room.clock.now += 5_000;
    expect(await m.onVote(await approve(c, req), c.id)).toBe("not-voting");
    expect(m.state).toBe("EXPIRED");
  });

  it("does not count an approval whose signature check outlasts the deadline", async () => {
    const room = await makeRoom(4);
    const [a, b, c, t] = room.people;
    const req = await requestBy(room, a, t, { deadline: 5_000 });
    const m = machineFor(room, b);
    await m.onRequest(req, a.id);
    m.recordOwn(await sign(b, req));
    const late = m.onVote(await approve(c, req), c.id);
    room.clock.now += 5_000;
    expect(await late).toBe("not-voting");
    expect(m.state).toBe("EXPIRED");
  });

  it("does not approve on the member's own vote after the deadline", async () => {
    const room = await makeRoom(3);
    const [a, b, t] = room.people;
    const req = await requestBy(room, a, t, { deadline: 5_000 });
    const m = machineFor(room, b);
    await m.onRequest(req, a.id);
    room.clock.now += 5_000;
    m.recordOwn(await sign(b, req));
    expect(m.state).toBe("EXPIRED");
  });

  it("still approves one millisecond before the deadline", async () => {
    const room = await makeRoom(3);
    const [a, b, t] = room.people;
    const req = await requestBy(room, a, t, { deadline: 5_000 });
    const m = machineFor(room, b);
    await m.onRequest(req, a.id);
    room.clock.now += 4_999;
    m.recordOwn(await sign(b, req));
    expect(m.state).toBe("APPROVED");
  });
});

describe("starting a vote locally", () => {
  it("refuses while another member's request is open, and keeps it", async () => {
    const room = await makeRoom(3);
    const [a, b, t] = room.people;
    const theirs = await requestBy(room, a, t);
    const m = machineFor(room, b);
    await m.onRequest(theirs, a.id);
    const mine = await requestBy(room, b, t, { id: new Uint8Array(16).fill(5) });
    expect(() => m.start(mine, b.id, room.roster, null)).toThrow(Error);
    expect(m.state).toBe("VOTING");
    expect(m.current()!.request.id).toEqual(theirs.id);
  });

  it("is allowed again once the earlier vote has finished", async () => {
    const room = await makeRoom(3);
    const [a, b, t] = room.people;
    const m = machineFor(room, b);
    await m.onRequest(await requestBy(room, a, t), a.id);
    m.rejectOwn();
    const mine = await requestBy(room, b, t, { id: new Uint8Array(16).fill(5) });
    m.start(mine, b.id, room.roster, await digestOf(mine));
    expect(m.state).toBe("VOTING");
    expect(m.current()!.request.id).toEqual(mine.id);
  });
});

describe("calls that overlap", () => {
  it("lets only one of two requests arriving together open the vote", async () => {
    const room = await makeRoom(3);
    const [a, b, t] = room.people;
    const m = machineFor(room, b);
    const r1 = await requestBy(room, a, t, { id: new Uint8Array(16).fill(1) });
    const r2 = await requestBy(room, a, t, { id: new Uint8Array(16).fill(2) });
    const results = await Promise.all([m.onRequest(r1, a.id), m.onRequest(r2, a.id)]);
    // Whichever finishes its signature check first opens the vote.
    expect([...results].sort()).toEqual(["busy", null]);
    expect(m.current()!.request.id).toEqual(results[0] === null ? r1.id : r2.id);
  });

  it("counts one of two identical votes arriving together", async () => {
    const room = await makeRoom(4);
    const [a, b, c, t] = room.people;
    const req = await requestBy(room, a, t);
    const m = machineFor(room, a);
    m.start(req, a.id, room.roster, await digestOf(req));
    const v = await approve(b, req);
    expect([...(await Promise.all([m.onVote(v, b.id), m.onVote(v, b.id)]))].sort()).toEqual(["duplicate-vote", null]);
    expect(m.state).toBe("VOTING");
    void c;
  });

  it("drops a vote whose signature check finishes after the proposal was cancelled", async () => {
    const room = await makeRoom(3);
    const [a, b, t] = room.people;
    const req = await requestBy(room, a, t);
    const m = machineFor(room, a);
    m.start(req, a.id, room.roster, await digestOf(req));
    const pending = m.onVote(await approve(b, req), b.id);
    m.cancel();
    expect(await pending).toBe("not-voting");
    expect(m.state).toBe("CANCELLED");
  });
});

describe("requests that cannot be read", () => {
  it("refuses a request from someone the roster does not show", async () => {
    const room = await makeRoom(3);
    const [a, b, t] = room.people;
    const req = await requestBy(room, a, t);
    expect(await machineFor(room, b).onRequest(req, new Uint8Array(16).fill(0xee))).toBe("unknown-proposer");
    const keyless = { ...a.entry, pubkey: undefined };
    room.roster = [keyless, ...room.roster.slice(1)];
    expect(await machineFor(room, b).onRequest(req, a.id)).toBe("unknown-proposer");
  });

  it("refuses as malformed when the statement cannot be built", async () => {
    const room = await makeRoom(3);
    const [a, b, t] = room.people;
    const req = await requestBy(room, a, t);
    const m = new EvictMachine({
      roomId: ROOM,
      me: () => b.id,
      members: () => room.roster,
      now: () => room.clock.now,
      epoch: () => room.epoch.value,
      statement: () => {
        throw new Error("cannot build");
      },
    });
    expect(await m.onRequest(req, a.id)).toBe("malformed");
    expect(m.state).toBe("IDLE");
  });
});

describe("checking a commit against the policy", () => {
  async function approvedRoom() {
    const room = await makeRoom(4);
    const [a, b, c, t] = room.people;
    const req = await requestBy(room, a, t);
    const votes = [
      { voter: a.id, sig: req.sig },
      { voter: b.id, sig: await sign(b, req) },
      { voter: c.id, sig: await sign(c, req) },
    ];
    return { room, a, b, c, t, req, votes };
  }

  it("accepts exactly the members the request froze, each signed", async () => {
    const { room, a, b, req, votes } = await approvedRoom();
    const m = machineFor(room, b);
    await m.onRequest(req, a.id);
    expect(await m.commitSatisfies({ ...(await requestStatement(req)), votes })).toBe(true);
  });

  it("refuses a missing voter, an extra one, a bad signature, another verifier, another target or another key", async () => {
    const { room, a, b, c, t, req, votes } = await approvedRoom();
    const m = machineFor(room, b);
    await m.onRequest(req, a.id);
    const st = await requestStatement(req);
    expect(await m.commitSatisfies({ ...st, votes: votes.slice(0, 2) })).toBe(false);
    expect(await m.commitSatisfies({ ...st, votes: [...votes, { voter: t.id, sig: await sign(t, req) }] })).toBe(false);
    const bad = votes.map((v) => (v.voter === c.id ? { voter: c.id, sig: votes[0].sig } : v));
    expect(await m.commitSatisfies({ ...st, votes: bad })).toBe(false);
    expect(await m.commitSatisfies({ ...st, verifier: new Uint8Array(32), votes })).toBe(false);
    expect(await m.commitSatisfies({ ...st, target: null, targetKeyDigest: null, votes })).toBe(false);
    // The commit must name the key the request named, whatever its votes say.
    expect(await m.commitSatisfies({ ...st, targetKeyDigest: await keyDigest(b.identity.publicKeyRaw), votes })).toBe(false);
  });

  it("for a member that never saw the request, checks its own roster without the target and itself", async () => {
    const room = await makeRoom(4);
    const [a, b, c, t] = room.people;
    const req = await requestBy(room, a, t);
    const votes = [
      { voter: a.id, sig: req.sig },
      { voter: b.id, sig: await sign(b, req) },
    ];
    const m = machineFor(room, c);
    const st = await requestStatement(req);
    expect(await m.commitSatisfies({ ...st, votes })).toBe(true);
    expect(await m.commitSatisfies({ ...st, votes: votes.slice(0, 1) })).toBe(false);
    // A digest that is not the key its roster shows for the named target.
    const otherKey = { ...st, targetKeyDigest: await keyDigest(c.identity.publicKeyRaw) };
    const signedOther = [
      { voter: a.id, sig: await signPayload(a.identity, voteStatement(ROOM, req.id, req.epoch, req.target, otherKey.targetKeyDigest, a.id, req.verifier)) },
      { voter: b.id, sig: await signPayload(b.identity, voteStatement(ROOM, req.id, req.epoch, req.target, otherKey.targetKeyDigest, b.id, req.verifier)) },
    ];
    expect(await m.commitSatisfies({ ...otherKey, votes: signedOther })).toBe(false);
  });
});

describe("model check", () => {
  it("never approves unless every member but the target has a valid approval", async () => {
    const room = await makeRoom(4);
    const [a, b, c, t] = room.people;
    const req = await requestBy(room, a, t);
    const good = new Map([
      [b, await approve(b, req)],
      [c, await approve(c, req)],
    ]);
    const forged = new Map([
      [b, { id: req.id, vote: "APPROVE" as const, sig: await sign(t, req) }],
      [c, { id: req.id, vote: "APPROVE" as const, sig: await sign(t, req) }],
    ]);
    const targetVote = await approve(t, req);
    type Ev = { who: 0 | 1 | 2; kind: "good" | "forged" | "dup" };
    await fc.assert(
      fc.asyncProperty(
        fc.array(fc.record({ who: fc.constantFrom<0 | 1 | 2>(0, 1, 2), kind: fc.constantFrom<"good" | "forged" | "dup">("good", "forged", "dup") }), { maxLength: 8 }),
        async (events: Ev[]) => {
          const m = machineFor(room, a);
          m.start(req, a.id, room.roster, await digestOf(req));
          const valid = new Set<string>();
          for (const e of events) {
            if (e.who === 2) {
              await m.onVote(targetVote, t.id);
              continue;
            }
            const p = e.who === 0 ? b : c;
            const v = e.kind === "forged" ? forged.get(p)! : good.get(p)!;
            if ((await m.onVote(v, p.id)) === null && e.kind !== "forged") valid.add(p === b ? "b" : "c");
          }
          return (m.state === "APPROVED") === (valid.has("b") && valid.has("c"));
        },
      ),
      { numRuns: 60 },
    );
  });
});

describe("request limits", () => {
  it("refuses a deadline of zero or beyond an hour, and takes exactly an hour", async () => {
    const room = await makeRoom(3);
    const [a, b, t] = room.people;
    expect(await machineFor(room, b).onRequest(await requestBy(room, a, t, { deadline: 0 }), a.id)).toBe("malformed");
    expect(await machineFor(room, b).onRequest(await requestBy(room, a, t, { deadline: 3_600_001 }), a.id)).toBe("malformed");
    expect(await machineFor(room, b).onRequest(await requestBy(room, a, t, { deadline: 3_600_000 }), a.id)).toBeNull();
  });
});

describe("a commit for a request this member saw (fix wave 1, A2)", () => {
  /// A proposes R1 against T; B refuses (or never answers) and A's R2
  /// replaces it in B's machine. A commit for R1 carries every vote but B's.
  async function replaced(refuse: "reject" | "expire") {
    const room = await makeRoom(4);
    const [a, b, c, t] = room.people;
    const r1 = await requestBy(room, a, t, { id: new Uint8Array(16).fill(0x31), deadline: 5_000 });
    const m = machineFor(room, b);
    expect(await m.onRequest(r1, a.id)).toBeNull();
    if (refuse === "reject") m.rejectOwn();
    else room.clock.now += 5_000;
    const r2 = await requestBy(room, a, t, { id: new Uint8Array(16).fill(0x32) });
    expect(await m.onRequest(r2, a.id)).toBeNull();
    expect(m.current()!.request.id).toEqual(r2.id);
    const votes = [
      { voter: a.id, sig: r1.sig },
      { voter: c.id, sig: await sign(c, r1) },
    ];
    return { m, r1, votes };
  }

  it("judges it against that request's frozen set, which holds this member, after a refusal", async () => {
    const { m, r1, votes } = await replaced("reject");
    expect(await m.commitSatisfies({ ...(await requestStatement(r1)), votes })).toBe(false);
  });

  it("does the same for a request it never answered", async () => {
    const { m, r1, votes } = await replaced("expire");
    expect(await m.commitSatisfies({ ...(await requestStatement(r1)), votes })).toBe(false);
  });

  it("still accepts that request's commit when it carries every vote it froze", async () => {
    const room = await makeRoom(3);
    const [a, b, t] = room.people;
    const r1 = await requestBy(room, a, t, { id: new Uint8Array(16).fill(0x31) });
    const m = machineFor(room, b);
    await m.onRequest(r1, a.id);
    m.recordOwn(await sign(b, r1));
    m.fail();
    await m.onRequest(await requestBy(room, a, t, { id: new Uint8Array(16).fill(0x32) }), a.id);
    const votes = [
      { voter: a.id, sig: r1.sig },
      { voter: b.id, sig: await sign(b, r1) },
    ];
    expect(await m.commitSatisfies({ ...(await requestStatement(r1)), votes })).toBe(true);
  });

  it("does not place a request it received but could not open, and checks its commit as one it never saw", async () => {
    const room = await makeRoom(4);
    const [a, b, c, t] = room.people;
    const m = machineFor(room, b);
    await m.onRequest(await requestBy(room, a, t), a.id);
    // c's request arrives while a's is open and is refused as busy.
    const theirs = await requestBy(room, c, t, { id: new Uint8Array(16).fill(0x33) });
    expect(await m.onRequest(theirs, c.id)).toBe("busy");
    const votes = [
      { voter: c.id, sig: theirs.sig },
      { voter: a.id, sig: await sign(a, theirs) },
    ];
    // The checks a member that never saw it makes pass, and nothing places it,
    // so the coordinator never applies it.
    expect(m.wasSeen(theirs.id)).toBe(true);
    expect(m.requestFor(theirs.id)).toBeNull();
    expect(await m.commitSatisfies({ ...(await requestStatement(theirs)), votes })).toBe(true);
    expect(await m.commitSatisfies({ ...(await requestStatement(theirs)), votes: votes.slice(0, 1) })).toBe(false);
  });

  it("never opens the same request id twice in one epoch, and forgets the ids when the epoch moves", async () => {
    const room = await makeRoom(3);
    const [a, b, t] = room.people;
    const m = machineFor(room, b);
    const r1 = await requestBy(room, a, t);
    expect(await m.onRequest(r1, a.id)).toBeNull();
    m.rejectOwn();
    expect(await m.onRequest(r1, a.id)).toBe("busy");
    expect(m.state).toBe("REJECTED");
    room.epoch.value = 1;
    expect(await m.onRequest(await requestBy(room, a, t, { epoch: 1 }), a.id)).toBeNull();
  });
});

describe("the record of seen requests is best effort (fix wave 2, F2)", () => {
  const idOf = (i: number, tag: number): Uint8Array => {
    const id = new Uint8Array(16).fill(tag);
    new DataView(id.buffer).setUint32(0, i + 1);
    return id;
  };
  /// A well-formed request with a signature nobody made, as a hostile member
  /// can send as many of as it likes.
  const junk = async (room: Room, from: Person, i: number): Promise<EvictRequest> =>
    ({ ...(await requestBy(room, from, null, { id: idOf(i, 0xee) })), sig: new Uint8Array(64).fill(5) });

  it("never lets go of the proposal open now, however many requests arrive", async () => {
    const room = await makeRoom(4);
    const [a, b, c, t] = room.people;
    const m = machineFor(room, b);
    const r1 = await requestBy(room, a, t, { id: new Uint8Array(16).fill(0x51) });
    expect(await m.onRequest(r1, a.id)).toBeNull();
    for (let i = 0; i < MAX_SEEN_REQUESTS * 3; i++) expect(await m.onRequest(await junk(room, i % 2 ? t : c, i), t.id)).toBe("busy");
    expect(m.requestFor(r1.id)?.request).toBe(r1);
    m.recordOwn(await sign(b, r1));
    const votes = [
      { voter: a.id, sig: r1.sig },
      { voter: b.id, sig: await sign(b, r1) },
      { voter: c.id, sig: await sign(c, r1) },
    ];
    expect(await m.commitSatisfies({ ...(await requestStatement(r1)), votes })).toBe(true);
  });

  it("lets refused ids go before settled proposals, oldest first, and stays bounded", async () => {
    const room = await makeRoom(4);
    const [a, b, , t] = room.people;
    const m = machineFor(room, b);
    const s1 = await requestBy(room, a, t, { id: new Uint8Array(16).fill(0x61) });
    const s2 = await requestBy(room, a, t, { id: new Uint8Array(16).fill(0x62) });
    for (const s of [s1, s2]) {
      expect(await m.onRequest(s, a.id)).toBeNull();
      m.rejectOwn();
    }
    const n = MAX_SEEN_REQUESTS * 2;
    // Signed by nobody, so refused, and recorded as refused.
    for (let i = 0; i < n; i++) await m.onRequest(await junk(room, t, i), t.id);
    expect(m.requestFor(s1.id)?.request).toBe(s1);
    expect(m.requestFor(s2.id)?.request).toBe(s2);
    expect(m.wasSeen(idOf(0, 0xee))).toBe(false);
    expect(m.wasSeen(idOf(n - 1, 0xee))).toBe(true);
    // Settled proposals go once no refused id is left, the oldest first, and
    // never the one this member holds now.
    for (let i = 0; i < MAX_SEEN_REQUESTS; i++) {
      expect(await m.onRequest(await requestBy(room, a, t, { id: idOf(i, 0x70) }), a.id)).toBeNull();
      m.rejectOwn();
    }
    expect(m.requestFor(s1.id)).toBeNull();
    expect(m.wasSeen(idOf(n - 1, 0xee))).toBe(false);
    expect(m.requestFor(idOf(MAX_SEEN_REQUESTS - 1, 0x70))).not.toBeNull();
    let held = 0;
    for (const id of [s1.id, s2.id, ...Array.from({ length: MAX_SEEN_REQUESTS }, (_, i) => idOf(i, 0x70))]) if (m.wasSeen(id)) held += 1;
    expect(held).toBe(MAX_SEEN_REQUESTS);
  });

  it("checks a commit for an id it let go of as one it never saw, and never refuses it for overflowing", async () => {
    const room = await makeRoom(4);
    const [a, b, c, t] = room.people;
    const m = machineFor(room, b);
    const unseen = await requestBy(room, a, t, { id: new Uint8Array(16).fill(0xfe) });
    const votes = [
      { voter: a.id, sig: unseen.sig },
      { voter: c.id, sig: await sign(c, unseen) },
    ];
    const st = await requestStatement(unseen);
    for (let i = 0; i <= MAX_SEEN_REQUESTS * 2; i++) {
      expect(await m.onRequest(await requestBy(room, a, t, { id: idOf(i, 0x80) }), a.id)).toBeNull();
      m.rejectOwn();
    }
    expect(m.wasSeen(unseen.id)).toBe(false);
    expect(m.requestFor(unseen.id)).toBeNull();
    expect(await m.commitSatisfies({ ...st, votes })).toBe(true);
  });
});

describe("a vote past its deadline that tick has not seen (fix wave 1, C1)", () => {
  it("does not make the next request busy", async () => {
    const room = await makeRoom(3);
    const [a, b, t] = room.people;
    const m = machineFor(room, b);
    await m.onRequest(await requestBy(room, a, t, { deadline: 5_000 }), a.id);
    room.clock.now += 5_000;
    expect(await m.onRequest(await requestBy(room, a, t, { id: new Uint8Array(16).fill(0x41) }), a.id)).toBeNull();
    expect(m.state).toBe("VOTING");
  });

  it("does not stop this member starting its own", async () => {
    const room = await makeRoom(3);
    const [a, b, t] = room.people;
    const m = machineFor(room, b);
    await m.onRequest(await requestBy(room, a, t, { deadline: 5_000 }), a.id);
    room.clock.now += 5_000;
    const mine = await requestBy(room, b, t, { id: new Uint8Array(16).fill(0x42) });
    expect(() => m.start(mine, b.id, room.roster, null)).not.toThrow();
    expect(m.current()!.request.id).toEqual(mine.id);
  });
});
