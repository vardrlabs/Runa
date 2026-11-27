import { describe, expect, it } from "vitest";
import { decryptWithExplicitNonce, encryptWithExplicitNonce } from "../crypto/aead";
import { deriveChainKey } from "../crypto/epoch";
import { generateIdentity, type Identity } from "../crypto/identity";
import { generateKx, sealWrap, wrapKey, type KxPair } from "../crypto/kx";
import type { MemberView } from "../epoch/coordinator";
import { Keyring } from "../epoch/keyring";
import { encodeHeader, FT, PROTOCOL_VERSION } from "../transport/frame";
import { COMMIT_ECHO_MS, EvictCoordinator, type EvictPrompt, type ReRooted, type SealedConfig } from "./coordinator";
import { decodeCommit, encodeCommit } from "./frame";
import { COMMIT_WAIT_MS, type EvictState } from "./machine";
import { deriveReRoot, encodeWayIn, newLinkWayIn } from "./reroot";
import { bytesEqual, hexOf, keyDigest } from "./statement";

const ROOM = new Uint8Array(16).fill(7);
const IV = new Uint8Array(12).fill(1);

const header = (ft: number, epoch: number) =>
  encodeHeader({ version: PROTOCOL_VERSION, frameType: ft, roomId: ROOM, epoch, nonceSess: new Uint8Array(4), flags: 0 });

async function sameKey(a: CryptoKey, b: CryptoKey): Promise<boolean> {
  const ct = await encryptWithExplicitNonce(a, IV, new Uint8Array([1]), undefined);
  try {
    await decryptWithExplicitNonce(b, IV, ct, undefined);
    return true;
  } catch {
    return false;
  }
}

/// A stand-in relay: sealed frames go to everyone else, and a commit follows
/// the server's order (the first one at the room's epoch wins, the target is
/// removed and everyone else, the sender too, gets it). The target is the
/// named peer and every peer holding the key the clear part's digest names,
/// as the server holds it. Signatures are the server's business and are
/// tested in Rust.
class Hub {
  epoch = 0;
  peers: Peer[] = [];
  now = 1_000_000;
  pending: Promise<unknown>[] = [];
  dropCommits = false;
  /// False stands in for a server that closes only the named connection, so
  /// a tab still holding the target's key sees the commit.
  byKey = true;
  captured: { from: Peer; h: Uint8Array; body: Uint8Array }[] = [];
  /// Peers nobody can agree a key with.
  unverified = new Set<Peer>();

  sealed(from: Peer, ft: number, pt: Uint8Array): boolean {
    for (const p of this.peers) if (p !== from) this.pending.push(p.ev.receiveFrame(ft, from.id, pt));
    return true;
  }

  commit(from: Peer, h: Uint8Array, body: Uint8Array): boolean {
    this.captured.push({ from, h, body });
    if (this.dropCommits) return true;
    this.deliver(from, h, body);
    return true;
  }

  deliver(from: Peer, h: Uint8Array, body: Uint8Array): void {
    const e = new DataView(h.buffer, h.byteOffset).getUint32(20, false);
    if (e !== this.epoch) return;
    this.epoch += 1;
    const target = body.slice(16, 32);
    const digest = hexOf(body.slice(32, 64));
    const named = target.some((x) => x !== 0);
    const removed = this.peers.filter((p) => named && (bytesEqual(p.id, target) || (this.byKey && p.keyHex === digest)));
    for (const r of removed) r.removed = true;
    this.peers = this.peers.filter((p) => !removed.includes(p));
    for (const p of this.peers) this.pending.push(p.ev.receiveCommit(h, e, from.id, body));
    for (const r of removed) for (const p of this.peers) this.pending.push(p.ev.memberLeft(r.view()));
  }

  leave(gone: Peer): void {
    this.peers = this.peers.filter((p) => p !== gone);
    for (const p of this.peers) this.pending.push(p.ev.memberLeft(gone.view()));
  }

  async flush(): Promise<void> {
    while (this.pending.length) await this.pending.shift();
  }

  members(): MemberView[] {
    return this.peers.map((p) => p.view());
  }
}

let nextSeq = 1;

class Peer {
  ev!: EvictCoordinator;
  removed = false;
  /// Hex of SHA-256 of this peer's signing key, as the hub matches it.
  keyHex = "";
  applied: ReRooted[] = [];
  states: EvictState[] = [];
  prompts: EvictPrompt[] = [];
  refusals: string[] = [];
  leftOut = 0;
  removedCount = 0;
  config: SealedConfig = { ttl: { kind: "idle-peers", secs: 3600 }, ceilingOptout: false, level: "everyday" };
  private queue: Promise<unknown> = Promise.resolve();
  /// Stands in for a socket that throws instead of answering.
  sendThrows = false;

  constructor(
    readonly hub: Hub,
    public id: Uint8Array,
    readonly seq: number,
    readonly identity: Identity,
    readonly kx: KxPair,
    readonly keyring: Keyring,
  ) {
    this.ev = new EvictCoordinator({
      roomId: ROOM,
      identity,
      kx,
      keyring,
      now: () => hub.now,
      me: () => this.id,
      members: () => hub.members(),
      exclusive: <T>(fn: () => Promise<T>): Promise<T> => this.exclusive(fn),
      kxOf: async (m) => {
        const p = hub.peers.find((q) => bytesEqual(q.id, m.peerId));
        return p && !hub.unverified.has(p) ? p.kx.publicKeyRaw : null;
      },
      header,
      sendSealed: async (ft, pt) => {
        if (this.sendThrows) throw new Error("socket closed");
        return hub.sealed(this, ft, pt);
      },
      sendSigned: (h, b) => hub.commit(this, h, b),
      sealedConfig: () => this.config,
      applyReRoot: (r) => this.applied.push(r),
      prompt: (p) => this.prompts.push(p),
      state: (s) => this.states.push(s),
      refused: (reason) => this.refusals.push(reason),
      leftOut: () => {
        this.leftOut += 1;
      },
      removed: () => {
        this.removedCount += 1;
      },
    });
  }

  exclusive<T>(fn: () => Promise<T>): Promise<T> {
    // A task that waited on this queue from inside itself would never finish,
    // so every test that completes shows no entry point does that.
    const run = this.queue.then(fn, fn);
    this.queue = run.catch(() => undefined);
    return run;
  }

  /// The same tab, connected again under a new peer id.
  reconnectAs(id: Uint8Array): void {
    this.id = id;
  }

  view(): MemberView {
    return { peerId: this.id, pubkey: this.identity.publicKeyRaw, kxPub: this.kx.publicKeyRaw, joinedAtSeq: this.seq };
  }
}

async function room(n: number): Promise<{ hub: Hub; peers: Peer[] }> {
  const hub = new Hub();
  const content = await crypto.subtle.importKey("raw", new Uint8Array(32).fill(42), { name: "AES-GCM" }, false, ["encrypt", "decrypt"]);
  const chain = await deriveChainKey(new Uint8Array(32).fill(43), new Uint8Array(16).fill(44));
  for (let i = 0; i < n; i++) {
    const seq = nextSeq++;
    const p = new Peer(hub, new Uint8Array(16).fill(seq), seq, await generateIdentity(), await generateKx(), await Keyring.fromRoot(0, content, chain));
    p.keyHex = hexOf(await keyDigest(p.identity.publicKeyRaw));
    hub.peers.push(p);
  }
  return { hub, peers: [...hub.peers] };
}

describe("EvictCoordinator (amendment K)", () => {
  it("removes someone once everyone else agrees, and the two who stay share the new root", async () => {
    const { hub, peers } = await room(3);
    const [a, b, c] = peers;
    const way = newLinkWayIn();
    const secret = way.secret.slice();
    expect(await a.ev.propose(c.view(), way)).toBeNull();
    await hub.flush();
    expect(b.prompts).toHaveLength(1);
    expect(b.prompts[0].target).toEqual(c.id);
    expect(c.prompts).toHaveLength(0);
    await b.ev.vote("APPROVE");
    await hub.flush();

    expect(hub.epoch).toBe(1);
    expect(c.removed).toBe(true);
    for (const p of [a, b]) {
      expect(p.keyring.current.epoch).toBe(1);
      expect(p.keyring.rootEpoch).toBe(1);
      expect(p.keyring.keyFor(0)).not.toBeNull();
      expect(p.applied).toHaveLength(1);
      expect(p.applied[0].root).toBe(1);
      expect(p.applied[0].target).toEqual(c.id);
      expect(p.applied[0].targetKey).toEqual(c.identity.publicKeyRaw);
      expect(p.applied[0].way.secret).toEqual(secret);
      expect(p.states.at(-1)).toBe("DONE");
    }
    expect(await sameKey(a.keyring.keyFor(1)!, b.keyring.keyFor(1)!)).toBe(true);
    expect(hexOf(a.applied[0].keys.verifier)).toBe(hexOf(b.applied[0].keys.verifier));
    expect(c.keyring.current.epoch).toBe(0);
  });

  it("changes the link only when everyone, the proposer included, agrees", async () => {
    const { hub, peers } = await room(3);
    const [a, b, c] = peers;
    await a.ev.propose(null, newLinkWayIn());
    await hub.flush();
    await b.ev.vote("APPROVE");
    await hub.flush();
    expect(hub.epoch).toBe(0);
    await c.ev.vote("APPROVE");
    await hub.flush();
    expect(hub.epoch).toBe(1);
    for (const p of [a, b, c]) expect(p.keyring.rootEpoch).toBe(1);
  });

  it("in a room of two, sends the commit at once", async () => {
    const { hub, peers } = await room(2);
    const [a, b] = peers;
    await a.ev.propose(b.view(), newLinkWayIn());
    await hub.flush();
    expect(hub.epoch).toBe(1);
    expect(b.removed).toBe(true);
    expect(a.keyring.rootEpoch).toBe(1);
  });

  it("ends on a refusal, commits nothing, and wipes the proposer's new way in", async () => {
    const { hub, peers } = await room(3);
    const [a, b, c] = peers;
    const way = newLinkWayIn();
    await a.ev.propose(c.view(), way);
    await hub.flush();
    await b.ev.vote("REJECT");
    await hub.flush();
    expect(a.states.at(-1)).toBe("REJECTED");
    expect(hub.epoch).toBe(0);
    expect(way.secret.every((x) => x === 0)).toBe(true);
  });

  it("fails closed when the proposer leaves mid-vote", async () => {
    const { hub, peers } = await room(3);
    const [a, b, c] = peers;
    await a.ev.propose(c.view(), newLinkWayIn());
    await hub.flush();
    hub.leave(a);
    await hub.flush();
    expect(b.states.at(-1)).toBe("FAILED");
    await b.ev.vote("APPROVE");
    await hub.flush();
    expect(hub.epoch).toBe(0);
  });

  it("tells a member nobody could wrap for that it was left out", async () => {
    const { hub, peers } = await room(3);
    const [a, b, c] = peers;
    hub.unverified.add(b);
    await a.ev.propose(c.view(), newLinkWayIn());
    await hub.flush();
    await b.ev.vote("APPROVE");
    await hub.flush();
    expect(hub.epoch).toBe(1);
    expect(a.keyring.rootEpoch).toBe(1);
    expect(b.leftOut).toBe(1);
    expect(b.keyring.rootEpoch).toBe(0);
  });

  it("refuses a commit whose way in does not derive the verifier everyone voted for", async () => {
    const { hub, peers } = await room(3);
    const [a, b, c] = peers;
    hub.dropCommits = true;
    await a.ev.propose(c.view(), newLinkWayIn());
    await hub.flush();
    await b.ev.vote("APPROVE");
    await hub.flush();
    const { h, body } = hub.captured[0];
    const real = decodeCommit(body)!;
    // The same votes and verifier, but a different link sealed to b.
    const other = newLinkWayIn();
    const key = await wrapKey(a.kx, b.kx.publicKeyRaw, ROOM, 1, a.id, b.id);
    const { iv, ct } = await sealWrap(key, h, encodeWayIn({ ...other, salt: real.clear.salt }));
    const forged = await encodeCommit(h, real.clear, { ...real.tail, wraps: [{ p: b.id, iv, ct }] }, a.identity);
    await b.ev.receiveCommit(h, 0, a.id, forged);
    expect(b.refusals).toContain("commit-keys");
    expect(b.keyring.rootEpoch).toBe(0);
  });

  it("refuses a commit that would weaken the room's security level", async () => {
    const { hub, peers } = await room(3);
    const [a, b, c] = peers;
    b.config = { ...b.config, level: "highest" };
    await a.ev.propose(c.view(), newLinkWayIn());
    await hub.flush();
    await b.ev.vote("APPROVE");
    await hub.flush();
    expect(b.refusals).toContain("commit-config");
    expect(b.keyring.rootEpoch).toBe(0);
  });

  it("refuses a commit the proposer did not sign", async () => {
    const { hub, peers } = await room(3);
    const [a, b, c] = peers;
    hub.dropCommits = true;
    await a.ev.propose(c.view(), newLinkWayIn());
    await hub.flush();
    await b.ev.vote("APPROVE");
    await hub.flush();
    const { h, body } = hub.captured[0];
    const flipped = body.slice();
    flipped[body.length - 3] ^= 1;
    await b.ev.receiveCommit(h, 0, a.id, flipped);
    expect(b.refusals.some((r) => r === "commit-signature" || r === "malformed-commit")).toBe(true);
    expect(b.keyring.rootEpoch).toBe(0);
  });

  it("gives up and wipes the new way in when the commit is never echoed", async () => {
    const { hub, peers } = await room(3);
    const [a, b, c] = peers;
    hub.dropCommits = true;
    const way = newLinkWayIn();
    await a.ev.propose(c.view(), way);
    await hub.flush();
    await b.ev.vote("APPROVE");
    await hub.flush();
    expect(hub.captured).toHaveLength(1);
    hub.now += COMMIT_ECHO_MS + 1;
    await a.ev.tick();
    expect(a.states.at(-1)).toBe("FAILED");
    expect(way.secret.every((x) => x === 0)).toBe(true);
    expect(a.ev.isOpen()).toBe(false);
  });

  it("removes a target that reconnected mid-vote, and does not hand its new connection the new way in", async () => {
    const { hub, peers } = await room(3);
    const [a, b, c] = peers;
    await a.ev.propose(c.view(), newLinkWayIn());
    await hub.flush();
    // c's connection drops and the same tab comes back under a new peer id.
    hub.leave(c);
    await hub.flush();
    expect(a.states.at(-1)).toBe("VOTING");
    c.reconnectAs(new Uint8Array(16).fill(0xcc));
    hub.peers.push(c);
    await b.ev.vote("APPROVE");
    await hub.flush();

    expect(hub.epoch).toBe(1);
    for (const p of [a, b]) {
      expect(p.keyring.rootEpoch).toBe(1);
      expect(p.states.at(-1)).toBe("DONE");
      expect(p.applied[0].targetKey).toEqual(c.identity.publicKeyRaw);
    }
    const commit = decodeCommit(hub.captured[0].body)!;
    expect(commit.tail.wraps.map((w) => hexOf(w.p))).toEqual([hexOf(b.id)]);
    expect(hexOf(commit.clear.targetKeyDigest!)).toBe(c.keyHex);
    // The server knows the new connection by its key and closes it too.
    expect(c.removed).toBe(true);
    expect(c.keyring.rootEpoch).toBe(0);
    expect(c.applied).toHaveLength(0);
  });

  it("a tab under the target's key that still sees the commit says it was removed", async () => {
    const { hub, peers } = await room(3);
    const [a, b, c] = peers;
    hub.byKey = false;
    await a.ev.propose(c.view(), newLinkWayIn());
    await hub.flush();
    hub.leave(c);
    await hub.flush();
    c.reconnectAs(new Uint8Array(16).fill(0xcd));
    hub.peers.push(c);
    await b.ev.vote("APPROVE");
    await hub.flush();

    expect(hub.epoch).toBe(1);
    expect(c.removed).toBe(false);
    expect(c.removedCount).toBe(1);
    expect(c.keyring.rootEpoch).toBe(0);
    expect(c.applied).toHaveLength(0);
  });

  it("refuses a commit that names another key for the target than the request did", async () => {
    const { hub, peers } = await room(3);
    const [a, b, c] = peers;
    hub.dropCommits = true;
    await a.ev.propose(c.view(), newLinkWayIn());
    await hub.flush();
    await b.ev.vote("APPROVE");
    await hub.flush();
    const { h, body } = hub.captured[0];
    const real = decodeCommit(body)!;
    // Signed by the proposer, but its votes were cast over c's key digest.
    const otherKey = await keyDigest(b.identity.publicKeyRaw);
    const forged = await encodeCommit(h, { ...real.clear, targetKeyDigest: otherKey }, real.tail, a.identity);
    await b.ev.receiveCommit(h, 0, a.id, forged);
    expect(b.refusals).toContain("commit-policy");
    expect(b.keyring.rootEpoch).toBe(0);
  });

  it("does not let the target vote", async () => {
    const { hub, peers } = await room(3);
    const [a, , c] = peers;
    await a.ev.propose(c.view(), newLinkWayIn());
    await hub.flush();
    await c.ev.vote("APPROVE");
    await hub.flush();
    expect(hub.epoch).toBe(0);
  });

  it("refuses to propose while a vote is open", async () => {
    const { hub, peers } = await room(3);
    const [a, b, c] = peers;
    await a.ev.propose(c.view(), newLinkWayIn());
    await hub.flush();
    expect(await a.ev.propose(null, newLinkWayIn())).toBe("busy");
    expect(await b.ev.propose(null, newLinkWayIn())).toBe("busy");
  });

  it("the derived keys it applies are the ones the way in gives", async () => {
    const { hub, peers } = await room(2);
    const [a, b] = peers;
    const way = newLinkWayIn();
    const expected = await deriveReRoot({ ...way, secret: way.secret.slice() });
    await a.ev.propose(b.view(), way);
    await hub.flush();
    expect(a.applied[0].keys.verifier).toEqual(expected.verifier);
    expect(await sameKey(a.keyring.keyFor(1)!, expected.contentKey)).toBe(true);
  });
  it("does not hold the queue while it waits for its commit to be echoed", async () => {
    const { hub, peers } = await room(3);
    const [a, b, c] = peers;
    hub.dropCommits = true;
    await a.ev.propose(c.view(), newLinkWayIn());
    await hub.flush();
    await b.ev.vote("APPROVE");
    await hub.flush();
    expect(hub.captured).toHaveLength(1);
    expect(await a.exclusive(async () => "free")).toBe("free");
    expect(a.ev.isOpen()).toBe(true);
  });

  it("members give up on a commit that never comes, 15 seconds after every approval is in", async () => {
    const { hub, peers } = await room(3);
    const [a, b, c] = peers;
    hub.dropCommits = true;
    await a.ev.propose(c.view(), newLinkWayIn());
    await hub.flush();
    await b.ev.vote("APPROVE");
    await hub.flush();
    hub.now += COMMIT_WAIT_MS - 1;
    await b.ev.tick();
    expect(b.states.at(-1)).toBe("APPROVED");
    hub.now += 1;
    await b.ev.tick();
    expect(b.states.at(-1)).toBe("FAILED");
    expect(b.ev.isOpen()).toBe(false);
  });

  it("fails a vote at its deadline on the machine's clock, with no tick, and wipes the new way in", async () => {
    const { hub, peers } = await room(3);
    const [a, b, c] = peers;
    const way = newLinkWayIn();
    await a.ev.propose(c.view(), way, 5_000);
    await hub.flush();
    hub.now += 5_000;
    // A vote cast at the deadline neither counts nor goes out.
    await b.ev.vote("APPROVE");
    await hub.flush();
    expect(hub.epoch).toBe(0);
    expect(b.states.at(-1)).toBe("EXPIRED");
    expect(a.states.at(-1)).toBe("VOTING");
    // The proposer's own clock reaches the deadline the same way.
    await a.ev.tick();
    expect(a.states.at(-1)).toBe("EXPIRED");
    expect(way.secret.every((x) => x === 0)).toBe(true);
    expect(a.ev.isOpen()).toBe(false);
  });

  it("answers a deadline out of range without opening a vote, and wipes the way in", async () => {
    const { peers } = await room(3);
    const [a, , c] = peers;
    for (const ms of [0, -1, 3_600_001, 1.5, Number.NaN]) {
      const way = newLinkWayIn();
      expect(await a.ev.propose(c.view(), way, ms)).toBe("failed");
      expect(way.secret.every((x) => x === 0)).toBe(true);
    }
    expect(a.ev.isOpen()).toBe(false);
  });

  it("accepts the longest deadline", async () => {
    const { hub, peers } = await room(3);
    const [a, , c] = peers;
    expect(await a.ev.propose(c.view(), newLinkWayIn(), 3_600_000)).toBeNull();
    await hub.flush();
  });

  it("refuses to name itself or a key it holds as the target, and wipes the way in", async () => {
    const { peers } = await room(3);
    const [a, b] = peers;
    const w1 = newLinkWayIn();
    expect(await a.ev.propose(a.view(), w1)).toBe("bad-target");
    expect(w1.secret.every((x) => x === 0)).toBe(true);
    const w2 = newLinkWayIn();
    const same = { ...b.view(), pubkey: a.identity.publicKeyRaw };
    expect(await a.ev.propose(same, w2)).toBe("bad-target");
    expect(w2.secret.every((x) => x === 0)).toBe(true);
    expect(await a.ev.propose({ ...b.view(), peerId: new Uint8Array(16).fill(0xee) }, newLinkWayIn())).toBe("bad-target");
  });

  it("does not let the proposer vote its own request down by a vote", async () => {
    const { hub, peers } = await room(3);
    const [a, b, c] = peers;
    await a.ev.propose(c.view(), newLinkWayIn());
    await hub.flush();
    await a.ev.vote("REJECT");
    await hub.flush();
    expect(a.ev.isOpen()).toBe(true);
    await b.ev.vote("APPROVE");
    await hub.flush();
    expect(hub.epoch).toBe(1);
  });

  it("does not let the target reject either", async () => {
    const { hub, peers } = await room(3);
    const [a, , c] = peers;
    await a.ev.propose(c.view(), newLinkWayIn());
    await hub.flush();
    await c.ev.vote("REJECT");
    await hub.flush();
    expect(a.states.at(-1)).toBe("VOTING");
  });

  it("answers failed, and settles, when the socket throws on the request", async () => {
    const { peers } = await room(3);
    const [a, , c] = peers;
    a.sendThrows = true;
    const way = newLinkWayIn();
    expect(await a.ev.propose(c.view(), way)).toBe("failed");
    expect(way.secret.every((x) => x === 0)).toBe(true);
    expect(a.ev.isOpen()).toBe(false);
    expect(a.states.at(-1)).toBe("FAILED");
  });

  it("answers not-sent when the request does not go out", async () => {
    const { hub, peers } = await room(3);
    const [a, , c] = peers;
    hub.sealed = () => false;
    const way = newLinkWayIn();
    expect(await a.ev.propose(c.view(), way)).toBe("not-sent");
    expect(way.secret.every((x) => x === 0)).toBe(true);
    expect(a.ev.isOpen()).toBe(false);
  });

  it("answers not-joined without a peer id", async () => {
    const { peers } = await room(3);
    const [a, , c] = peers;
    const way = newLinkWayIn();
    const saved = a.id;
    a.id = null as unknown as Uint8Array;
    expect(await a.ev.propose(c.view(), way)).toBe("not-joined");
    a.id = saved;
    expect(way.secret.every((x) => x === 0)).toBe(true);
  });

  it("refuses everything once wiped, and wipes what it held", async () => {
    const { hub, peers } = await room(3);
    const [a, , c] = peers;
    const way = newLinkWayIn();
    await a.ev.propose(c.view(), way);
    await hub.flush();
    a.ev.wipe();
    expect(way.secret.every((x) => x === 0)).toBe(true);
    expect(a.ev.isOpen()).toBe(false);
    const w2 = newLinkWayIn();
    expect(await a.ev.propose(c.view(), w2)).toBe("failed");
    expect(w2.secret.every((x) => x === 0)).toBe(true);
  });

  it("lets the proposer cancel before anyone has approved, and wipes the way in", async () => {
    const { hub, peers } = await room(3);
    const [a, b, c] = peers;
    const way = newLinkWayIn();
    await a.ev.propose(c.view(), way);
    await hub.flush();
    await a.ev.cancel();
    await hub.flush();
    expect(a.states.at(-1)).toBe("CANCELLED");
    expect(b.states.at(-1)).toBe("CANCELLED");
    expect(way.secret.every((x) => x === 0)).toBe(true);
    await b.ev.cancel();
    expect(b.states.at(-1)).toBe("CANCELLED");
  });

  it("refuses a request that asks for a policy other than unanimity, and a malformed frame", async () => {
    const { hub, peers } = await room(3);
    const [a, b, c] = peers;
    hub.dropCommits = true;
    await b.ev.receiveFrame(FT.EVICT_REQUEST, a.id, new Uint8Array([1, 2, 3]));
    expect(b.refusals).toContain("malformed");
    expect(b.ev.isOpen()).toBe(false);
    void c;
  });

  it("refuses a commit that fails to parse, from a member, without touching its keyring", async () => {
    const { peers } = await room(3);
    const [a, b] = peers;
    await b.ev.receiveCommit(header(FT.EVICT_COMMIT, 0), 0, a.id, new Uint8Array(40));
    expect(b.refusals).toContain("malformed-commit");
    expect(b.keyring.rootEpoch).toBe(0);
  });

  it("says it was left out when a commit names a later epoch than its own", async () => {
    const { hub, peers } = await room(3);
    const [a, b, c] = peers;
    hub.dropCommits = true;
    await a.ev.propose(c.view(), newLinkWayIn());
    await hub.flush();
    await b.ev.vote("APPROVE");
    await hub.flush();
    const { h, body } = hub.captured[0];
    await b.ev.receiveCommit(h, 3, a.id, body);
    expect(b.leftOut).toBe(1);
    expect(b.keyring.rootEpoch).toBe(0);
  });
});
