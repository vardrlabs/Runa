import * as cbor2 from "cbor2";
import { describe, expect, it } from "vitest";
import { decryptWithExplicitNonce, encryptWithExplicitNonce } from "../crypto/aead";
import { deriveChainKey } from "../crypto/epoch";
import { generateIdentity, type Identity } from "../crypto/identity";
import { generateKx, sealWrap, wrapKey, type KxPair } from "../crypto/kx";
import type { MemberView } from "../epoch/coordinator";
import { Keyring } from "../epoch/keyring";
import { encodeHeader, FT, PROTOCOL_VERSION } from "../transport/frame";
import { encryptRoomConfig } from "../keys-session";
import {
  COMMIT_ECHO_MS,
  EARLY_HOLD_MS,
  EvictCoordinator,
  MAX_EARLY_IDS,
  type EvictPrompt,
  type ReRooted,
  type SealedConfig,
} from "./coordinator";
import { decodeCommit, decodeRequest, decodeVote, encodeCancel, encodeCommit, encodeRequest, encodeVote, MAX_VOTES, type EvictRequest } from "./frame";
import { COMMIT_WAIT_MS, MAX_SEEN_REQUESTS, type EvictState } from "./machine";
import { deriveReRoot, encodeWayIn, newLinkWayIn, type WayIn } from "./reroot";
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
  /// Every sealed frame, in the order it was sent.
  sent: { from: Peer; ft: number; pt: Uint8Array }[] = [];

  sealed(from: Peer, ft: number, pt: Uint8Array): boolean {
    this.sent.push({ from, ft, pt });
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
  /// Stands in for a page whose state callback throws.
  stateThrows = false;

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
      state: (s) => {
        if (this.stateThrows) throw new Error("the page threw");
        this.states.push(s);
      },
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

/// Sealed frames go nowhere until a test hands each one over itself, in the
/// order the test chooses: decrypts that resolve out of order.
function holdFrames(hub: Hub): { from: Peer; ft: number; pt: Uint8Array }[] {
  const held: { from: Peer; ft: number; pt: Uint8Array }[] = [];
  hub.sealed = (from, ft, pt) => {
    held.push({ from, ft, pt });
    return true;
  };
  return held;
}

async function rootKeys(): Promise<{ content: CryptoKey; chain: CryptoKey }> {
  const content = await crypto.subtle.importKey("raw", new Uint8Array(32).fill(42), { name: "AES-GCM" }, false, ["encrypt", "decrypt"]);
  const chain = await deriveChainKey(new Uint8Array(32).fill(43), new Uint8Array(16).fill(44));
  return { content, chain };
}

/// A copy of a way in that a call taking ownership cannot wipe.
const keep = (w: WayIn): WayIn => ({ ...w, secret: w.secret.slice(), salt: w.salt.slice() });

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

  it("gives up at 10 seconds when the commit is never echoed, and wipes the new way in once members stop waiting", async () => {
    const { hub, peers } = await room(3);
    const [a, b, c] = peers;
    hub.dropCommits = true;
    const way = newLinkWayIn();
    await a.ev.propose(c.view(), way);
    await hub.flush();
    await b.ev.vote("APPROVE");
    await hub.flush();
    expect(hub.captured).toHaveLength(1);
    hub.now += COMMIT_ECHO_MS - 1;
    await a.ev.tick();
    expect(a.ev.isOpen()).toBe(true);
    hub.now += 1;
    await a.ev.tick();
    expect(a.states.at(-1)).toBe("FAILED");
    expect(a.ev.isOpen()).toBe(false);
    // Kept, closed, while a late echo could still come back.
    expect(way.secret.every((x) => x === 0)).toBe(false);
    hub.now += COMMIT_WAIT_MS - COMMIT_ECHO_MS - 1;
    await a.ev.tick();
    expect(way.secret.every((x) => x === 0)).toBe(false);
    hub.now += 1;
    await a.ev.tick();
    expect(way.secret.every((x) => x === 0)).toBe(true);
    // An echo after that finds nothing of its own to apply.
    hub.deliver(a, hub.captured[0].h, hub.captured[0].body);
    await hub.flush();
    expect(a.applied).toHaveLength(0);
    expect(a.keyring.rootEpoch).toBe(0);
  });

  it("applies its own commit when the echo comes back after it gave up", async () => {
    const { hub, peers } = await room(3);
    const [a, b, c] = peers;
    hub.dropCommits = true;
    const way = newLinkWayIn();
    const secret = way.secret.slice();
    await a.ev.propose(c.view(), way);
    await hub.flush();
    await b.ev.vote("APPROVE");
    await hub.flush();
    hub.now += COMMIT_ECHO_MS;
    await a.ev.tick();
    expect(a.states.at(-1)).toBe("FAILED");
    hub.now += COMMIT_WAIT_MS - COMMIT_ECHO_MS - 1;
    hub.deliver(a, hub.captured[0].h, hub.captured[0].body);
    await hub.flush();
    for (const p of [a, b]) {
      expect(p.keyring.rootEpoch).toBe(1);
      expect(p.applied).toHaveLength(1);
    }
    expect(a.applied[0].way.secret).toEqual(secret);
    expect(a.states.at(-1)).toBe("DONE");
    expect(a.leftOut).toBe(0);
    expect(a.refusals).toEqual([]);
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
    const held = holdFrames(hub);
    await a.ev.propose(c.view(), newLinkWayIn());
    const req = decodeRequest(held[0].pt)!;
    // The request as signed, with only its policy changed, built in the
    // frame's own layout since encodeRequest refuses to write it.
    const majority = cbor2.encode({
      type: "EVICT_REQUEST", id: req.id, epoch: req.epoch, target: req.target, targetKey: req.targetKey,
      verifier: req.verifier, roster: req.roster, policy: "MAJORITY", deadline: req.deadline, sig: req.sig,
    });
    await b.ev.receiveFrame(FT.EVICT_REQUEST, a.id, majority);
    expect(b.refusals).toEqual(["malformed"]);
    expect(b.ev.isOpen()).toBe(false);
    expect(b.prompts).toHaveLength(0);
    await b.ev.receiveFrame(FT.EVICT_REQUEST, a.id, new Uint8Array([1, 2, 3]));
    expect(b.refusals).toEqual(["malformed", "malformed"]);
    expect(b.ev.isOpen()).toBe(false);
    // The same request under unanimity opens the vote.
    await b.ev.receiveFrame(FT.EVICT_REQUEST, a.id, held[0].pt);
    expect(b.prompts).toHaveLength(1);
  });

  it("refuses a commit that fails to parse, from a member, without touching its keyring", async () => {
    const { peers } = await room(3);
    const [a, b] = peers;
    await b.ev.receiveCommit(header(FT.EVICT_COMMIT, 0), 0, a.id, new Uint8Array(40));
    expect(b.refusals).toContain("malformed-commit");
    expect(b.keyring.rootEpoch).toBe(0);
  });

  it("says it was left out when a commit a member signed names a later epoch than its own", async () => {
    const { hub, peers } = await room(3);
    const [a, b, c] = peers;
    hub.dropCommits = true;
    await a.ev.propose(c.view(), newLinkWayIn());
    await hub.flush();
    await b.ev.vote("APPROVE");
    await hub.flush();
    const real = decodeCommit(hub.captured[0].body)!;
    const h3 = header(FT.EVICT_COMMIT, 3);
    const later = await encodeCommit(h3, real.clear, { ...real.tail, root: 4 }, a.identity);
    await b.ev.receiveCommit(h3, 3, a.id, later);
    expect(b.leftOut).toBe(1);
    expect(b.keyring.rootEpoch).toBe(0);
  });
});

describe("frames that arrive before their request (fix wave 1, A1)", () => {
  it("holds a cancel until its request comes: nothing is left open and nobody is asked", async () => {
    const { hub, peers } = await room(3);
    const [a, b, c] = peers;
    const held = holdFrames(hub);
    await a.ev.propose(c.view(), newLinkWayIn());
    await a.ev.cancel();
    const [req, cancel] = held;
    expect(cancel.ft).toBe(FT.EVICT_CANCEL);
    await b.ev.receiveFrame(cancel.ft, a.id, cancel.pt);
    await b.ev.receiveFrame(req.ft, a.id, req.pt);
    expect(b.prompts).toHaveLength(0);
    expect(b.ev.isOpen()).toBe(false);
    expect(b.states.at(-1)).toBe("CANCELLED");
    expect(b.refusals).toEqual([]);
  });

  it("holds a refusal until its request comes: the vote ends at once and nobody is asked", async () => {
    const { hub, peers } = await room(4);
    const [a, b, c, t] = peers;
    const held = holdFrames(hub);
    await a.ev.propose(t.view(), newLinkWayIn());
    const req = held[0];
    await c.ev.receiveFrame(req.ft, a.id, req.pt);
    await c.ev.vote("REJECT");
    const reject = held[1];
    expect(decodeVote(reject.pt)!.vote).toBe("REJECT");
    await b.ev.receiveFrame(reject.ft, c.id, reject.pt);
    await b.ev.receiveFrame(req.ft, a.id, req.pt);
    expect(b.prompts).toHaveLength(0);
    expect(b.ev.isOpen()).toBe(false);
    expect(b.states.at(-1)).toBe("REJECTED");
    expect(b.refusals).toEqual([]);
  });

  it("holds an approval until its request comes, so the member reaches APPROVED and waits 15 seconds", async () => {
    const { hub, peers } = await room(4);
    const [a, b, c, t] = peers;
    const held = holdFrames(hub);
    await a.ev.propose(t.view(), newLinkWayIn());
    const req = held[0];
    await c.ev.receiveFrame(req.ft, a.id, req.pt);
    await c.ev.vote("APPROVE");
    const approval = held[1];
    await b.ev.receiveFrame(approval.ft, c.id, approval.pt);
    await b.ev.receiveFrame(req.ft, a.id, req.pt);
    expect(b.prompts).toHaveLength(1);
    expect(b.refusals).toEqual([]);
    await b.ev.vote("APPROVE");
    expect(b.states.at(-1)).toBe("APPROVED");
    hub.now += COMMIT_WAIT_MS - 1;
    await b.ev.tick();
    expect(b.states.at(-1)).toBe("APPROVED");
    hub.now += 1;
    await b.ev.tick();
    expect(b.states.at(-1)).toBe("FAILED");
    expect(b.ev.isOpen()).toBe(false);
  });

  it("verifies a held approval when it replays it, and never counts a forged one", async () => {
    const { hub, peers } = await room(4);
    const [a, b, c, t] = peers;
    const held = holdFrames(hub);
    await a.ev.propose(t.view(), newLinkWayIn());
    const req = held[0];
    const id = decodeRequest(req.pt)!.id;
    const forged = encodeVote({ id, vote: "APPROVE", sig: new Uint8Array(64).fill(9) });
    await b.ev.receiveFrame(FT.EVICT_VOTE, c.id, forged);
    await b.ev.receiveFrame(req.ft, a.id, req.pt);
    expect(b.refusals).toEqual(["bad-signature"]);
    await b.ev.vote("APPROVE");
    expect(b.states.at(-1)).toBe("VOTING");
  });

  it("holds a bounded number of frames, lets them go in time, and junk never holds the member busy", async () => {
    const { hub, peers } = await room(3);
    const [a, b, c] = peers;
    const junk = (): Uint8Array =>
      encodeVote({ id: crypto.getRandomValues(new Uint8Array(16)), vote: "APPROVE", sig: crypto.getRandomValues(new Uint8Array(64)) });
    // One sender holds frames for one id at a time; many senders fill the bound.
    for (let i = 0; i < 100; i++) await b.ev.receiveFrame(FT.EVICT_VOTE, c.id, junk());
    expect(b.ev.heldFrames()).toBe(1);
    for (let i = 0; i < 20; i++) await b.ev.receiveFrame(FT.EVICT_VOTE, new Uint8Array(16).fill(0x60 + i), junk());
    for (let i = 0; i < 20; i++) await b.ev.receiveFrame(FT.EVICT_CANCEL, new Uint8Array(16).fill(0x90 + i), encodeCancel({ id: crypto.getRandomValues(new Uint8Array(16)) }));
    expect(b.ev.heldFrames()).toBe(MAX_EARLY_IDS);
    expect(b.ev.isOpen()).toBe(false);
    hub.now += EARLY_HOLD_MS;
    await b.ev.tick();
    expect(b.ev.heldFrames()).toBe(0);

    // One id: at most one vote per sender, MAX_VOTES votes and one cancel.
    const id = crypto.getRandomValues(new Uint8Array(16));
    const vote = encodeVote({ id, vote: "REJECT", sig: null });
    for (let i = 0; i < MAX_VOTES + 8; i++) await b.ev.receiveFrame(FT.EVICT_VOTE, new Uint8Array(16).fill(0x80 + i), vote);
    await b.ev.receiveFrame(FT.EVICT_VOTE, new Uint8Array(16).fill(0x80), vote);
    for (let i = 0; i < 3; i++) await b.ev.receiveFrame(FT.EVICT_CANCEL, c.id, encodeCancel({ id }));
    expect(b.ev.heldFrames()).toBe(MAX_VOTES + 1);
    expect(b.refusals).toEqual([]);

    // A real request is not delayed by any of it.
    hub.sealed = Hub.prototype.sealed;
    expect(await a.ev.propose(c.view(), newLinkWayIn())).toBeNull();
    await hub.flush();
    expect(b.prompts).toHaveLength(1);
    expect(b.ev.isOpen()).toBe(true);
  });

  it("lets every held frame go when the epoch moves", async () => {
    const { peers } = await room(3);
    const [, b, c] = peers;
    await b.ev.receiveFrame(FT.EVICT_CANCEL, c.id, encodeCancel({ id: new Uint8Array(16).fill(3) }));
    expect(b.ev.heldFrames()).toBe(1);
    const { content, chain } = await rootKeys();
    expect(await b.keyring.reroot(1, content, chain)).not.toBeNull();
    await b.ev.tick();
    expect(b.ev.heldFrames()).toBe(0);
  });
});

describe("a member that refused is never made to apply the commit (fix wave 1, A2)", () => {
  /// A proposes R1 against T. C approves; B refuses or never answers. A then
  /// sends R2, which replaces R1 in B's machine, and sends a commit for R1
  /// carrying every vote but B's.
  async function scenario(how: "reject" | "unanswered", wrapForB: boolean, flush = false) {
    const { hub, peers } = await room(4);
    const [a, b, c, t] = peers;
    const held = holdFrames(hub);
    const w1 = newLinkWayIn();
    const copy = keep(w1);
    await a.ev.propose(t.view(), w1, 5_000);
    const r1 = held[0];
    for (const p of [b, c]) await p.ev.receiveFrame(r1.ft, a.id, r1.pt);
    await c.ev.vote("APPROVE");
    const cVote = decodeVote(held[1].pt)!;
    await a.ev.receiveFrame(held[1].ft, c.id, held[1].pt);
    if (how === "reject") {
      await b.ev.vote("REJECT");
      await a.ev.receiveFrame(held[2].ft, b.id, held[2].pt);
      expect(a.states.at(-1)).toBe("REJECTED");
    } else {
      hub.now += 5_000;
      await a.ev.tick();
      expect(a.states.at(-1)).toBe("EXPIRED");
    }
    const req = decodeRequest(r1.pt)!;
    if (flush) {
      // T, still a member, asks for a link change and cancels it, over and
      // over, until B's record has let go of R1.
      for (let i = 0; i < MAX_SEEN_REQUESTS && b.ev.machine.requestFor(req.id); i++) {
        const at = held.length;
        expect(await t.ev.propose(null, newLinkWayIn())).toBeNull();
        await t.ev.cancel();
        for (const f of held.slice(at)) await b.ev.receiveFrame(f.ft, t.id, f.pt);
      }
      expect(b.ev.machine.requestFor(req.id)).toBeNull();
      expect(b.refusals).toEqual([]);
    }
    const before = held.length;
    expect(await a.ev.propose(t.view(), newLinkWayIn())).toBeNull();
    await b.ev.receiveFrame(held[before].ft, a.id, held[before].pt);
    expect(b.prompts.at(-1)!.requestId).toEqual(decodeRequest(held[before].pt)!.id);
    expect(b.ev.isOpen()).toBe(true);

    const keys = await deriveReRoot(keep(copy));
    const config = await encryptRoomConfig(keys.contentKey, b.config.ttl, b.config.ceilingOptout, b.config.level);
    const h = header(FT.EVICT_COMMIT, 0);
    const wraps = [];
    for (const p of wrapForB ? [b, c] : [c]) {
      const key = await wrapKey(a.kx, p.kx.publicKeyRaw, ROOM, 1, a.id, p.id);
      wraps.push({ p: p.id, ...(await sealWrap(key, h, encodeWayIn(copy))) });
    }
    const body = await encodeCommit(
      h,
      {
        requestId: req.id,
        target: req.target,
        targetKeyDigest: await keyDigest(req.targetKey!),
        verifier: req.verifier,
        salt: copy.salt,
        config,
        votes: [
          { voter: a.id, sig: req.sig },
          { voter: c.id, sig: cVote.sig! },
        ],
      },
      { root: 1, sender: a.id, confirm: keys.confirm, wraps },
      a.identity,
    );
    await b.ev.receiveCommit(h, 0, a.id, body);
    return b;
  }

  for (const how of ["reject", "unanswered"] as const) {
    for (const wrapForB of [true, false]) {
      it(`refuses it on policy after a ${how === "reject" ? "refusal" : "vote it never answered"}, ${wrapForB ? "with" : "without"} a wrap for it`, async () => {
        const b = await scenario(how, wrapForB);
        expect(b.refusals).toEqual(["commit-policy"]);
        expect(b.applied).toHaveLength(0);
        expect(b.leftOut).toBe(0);
        expect(b.keyring.rootEpoch).toBe(0);
        expect(b.keyring.current.epoch).toBe(0);
      });
      it(`tells it it was left out once its record of the request is gone, after a ${how === "reject" ? "refusal" : "vote it never answered"}, ${wrapForB ? "with" : "without"} a wrap for it (fix wave 2, F1)`, async () => {
        const b = await scenario(how, wrapForB, true);
        expect(b.refusals).toEqual([]);
        expect(b.leftOut).toBe(1);
        expect(b.applied).toHaveLength(0);
        expect(b.keyring.rootEpoch).toBe(0);
        expect(b.keyring.current.epoch).toBe(0);
      });
    }
  }
});

describe("a commit naming a later epoch is checked before it is believed (fix wave 1, A3 and B2)", () => {
  async function laterCommit() {
    const { hub, peers } = await room(4);
    const [a, b, c, t] = peers;
    hub.dropCommits = true;
    await a.ev.propose(t.view(), newLinkWayIn());
    await hub.flush();
    await b.ev.vote("APPROVE");
    await c.ev.vote("APPROVE");
    await hub.flush();
    const real = decodeCommit(hub.captured[0].body)!;
    return { a, b, c, t, real, h3: header(FT.EVICT_COMMIT, 3) };
  }

  it("says nothing about junk, a wrong root, a wrong sender, a non-voter or a signer it does not know", async () => {
    const { a, b, c, t, real, h3 } = await laterCommit();
    const stranger = await generateIdentity();
    const strangerId = new Uint8Array(16).fill(0x5e);
    const cases: [Uint8Array, Uint8Array][] = [
      [a.id, new Uint8Array(200).fill(7)],
      // Signed for epoch 0, delivered under a header that says 3.
      [a.id, await encodeCommit(header(FT.EVICT_COMMIT, 0), real.clear, { ...real.tail, root: 4 }, a.identity)],
      [a.id, await encodeCommit(h3, real.clear, { ...real.tail, root: 9 }, a.identity)],
      [c.id, await encodeCommit(h3, real.clear, { ...real.tail, root: 4 }, a.identity)],
      [c.id, await encodeCommit(h3, real.clear, { ...real.tail, root: 4 }, c.identity)],
      [t.id, await encodeCommit(h3, real.clear, { ...real.tail, root: 4, sender: t.id }, t.identity)],
      [strangerId, await encodeCommit(h3, real.clear, { ...real.tail, root: 4, sender: strangerId }, stranger)],
    ];
    for (const [sender, body] of cases) await b.ev.receiveCommit(h3, 3, sender, body);
    expect(b.leftOut).toBe(0);
    expect(b.refusals).toHaveLength(cases.length);
    expect(b.keyring.rootEpoch).toBe(0);
  });

  it("reads the epoch from the header, and refuses a separate one that disagrees", async () => {
    const { a, b, real, h3 } = await laterCommit();
    const body0 = await encodeCommit(header(FT.EVICT_COMMIT, 0), real.clear, real.tail, a.identity);
    await b.ev.receiveCommit(header(FT.EVICT_COMMIT, 0), 3, a.id, body0);
    const body3 = await encodeCommit(h3, real.clear, { ...real.tail, root: 4 }, a.identity);
    await b.ev.receiveCommit(h3, 0, a.id, body3);
    expect(b.leftOut).toBe(0);
    expect(b.applied).toHaveLength(0);
    expect(b.refusals).toEqual(["malformed-commit", "malformed-commit"]);
    expect(b.keyring.rootEpoch).toBe(0);
  });
});

describe("fix wave 1, the Minors", () => {
  it("the named target that sees the commit says it was removed (B1)", async () => {
    const { hub, peers } = await room(3);
    const [a, b, c] = peers;
    hub.dropCommits = true;
    await a.ev.propose(c.view(), newLinkWayIn());
    await hub.flush();
    await b.ev.vote("APPROVE");
    await hub.flush();
    const { h, body } = hub.captured[0];
    await c.ev.receiveCommit(h, 0, a.id, body);
    expect(c.removedCount).toBe(1);
    expect(c.applied).toHaveLength(0);
    expect(c.keyring.rootEpoch).toBe(0);
    // A commit it cannot verify says nothing of the kind.
    const flipped = body.slice();
    flipped[body.length - 3] ^= 1;
    await c.ev.receiveCommit(h, 0, a.id, flipped);
    expect(c.removedCount).toBe(1);
  });

  it("ignores a vote or a cancel for a vote that is already done (B5)", async () => {
    const { hub, peers } = await room(4);
    const [a, b, c, t] = peers;
    await a.ev.propose(t.view(), newLinkWayIn());
    await hub.flush();
    await b.ev.vote("APPROVE");
    await c.ev.vote("APPROVE");
    await hub.flush();
    expect(b.states.at(-1)).toBe("DONE");
    const cVote = hub.sent.find((x) => x.from === c && x.ft === FT.EVICT_VOTE)!;
    const req = decodeRequest(hub.sent[0].pt)!;
    await b.ev.receiveFrame(cVote.ft, c.id, cVote.pt);
    await b.ev.receiveFrame(FT.EVICT_CANCEL, a.id, encodeCancel({ id: req.id }));
    expect(b.refusals).toEqual([]);
    // Nor held as if their request were still to come.
    expect(b.ev.heldFrames()).toBe(0);
    expect(b.states.at(-1)).toBe("DONE");
  });

  it("does not send a request when the roster changed while it was being made (B6)", async () => {
    const { hub, peers } = await room(4);
    const [a, b, c, d] = peers;
    hub.peers = hub.peers.filter((p) => p !== d);
    const cfg = a.config;
    Object.defineProperty(a, "config", {
      get: () => {
        if (!hub.peers.includes(d)) hub.peers.push(d);
        return cfg;
      },
    });
    const way = newLinkWayIn();
    expect(await a.ev.propose(c.view(), way)).toBe("roster-changed");
    await hub.flush();
    expect(way.secret.every((x) => x === 0)).toBe(true);
    expect(a.ev.isOpen()).toBe(false);
    expect(hub.sent).toHaveLength(0);
    expect(b.prompts).toHaveLength(0);
  });

  it("does not send a request when this member reconnected or the epoch moved while it was being made", async () => {
    const { hub, peers } = await room(3);
    const [a, , c] = peers;
    const cfg = a.config;
    let side: () => void = () => undefined;
    Object.defineProperty(a, "config", {
      get: () => {
        side();
        side = () => undefined;
        return cfg;
      },
    });
    const w1 = newLinkWayIn();
    const id = a.id;
    side = () => {
      a.id = new Uint8Array(16).fill(0xab);
    };
    expect(await a.ev.propose(c.view(), w1)).toBe("failed");
    expect(w1.secret.every((x) => x === 0)).toBe(true);
    a.id = id;
    const { content, chain } = await rootKeys();
    side = () => void a.keyring.reroot(1, content, chain);
    const w2 = newLinkWayIn();
    expect(await a.ev.propose(c.view(), w2)).toBe("busy");
    expect(a.keyring.current.epoch).toBe(1);
    expect(w2.secret.every((x) => x === 0)).toBe(true);
    expect(hub.sent).toHaveLength(0);
    expect(a.ev.isOpen()).toBe(false);
  });

  it("a page callback that throws never wipes the way in of a live vote (B7)", async () => {
    const { hub, peers } = await room(3);
    const [a, b, c] = peers;
    a.stateThrows = true;
    const way = newLinkWayIn();
    expect(await a.ev.propose(c.view(), way)).toBeNull();
    expect(way.secret.every((x) => x === 0)).toBe(false);
    expect(a.ev.isOpen()).toBe(true);
    await hub.flush();
    await b.ev.vote("APPROVE");
    await hub.flush();
    expect(hub.epoch).toBe(1);
    expect(a.keyring.rootEpoch).toBe(1);
    expect(b.keyring.rootEpoch).toBe(1);
  });

  it("does not wrap for a member whose roster key is no longer the one it voted with (B8)", async () => {
    const { hub, peers } = await room(3);
    const [a, b, c] = peers;
    hub.dropCommits = true;
    await a.ev.propose(c.view(), newLinkWayIn());
    await hub.flush();
    const other = (await generateIdentity()).publicKeyRaw;
    const view = b.view.bind(b);
    b.view = () => ({ ...view(), pubkey: other });
    await b.ev.vote("APPROVE");
    await hub.flush();
    expect(hub.captured).toHaveLength(1);
    expect(decodeCommit(hub.captured[0].body)!.tail.wraps).toHaveLength(0);
  });
});

describe("checks that a test pins (fix wave 1, B9)", () => {
  async function approved(n: 3 | 4) {
    const { hub, peers } = await room(n);
    const t = peers[n - 1];
    hub.dropCommits = true;
    await peers[0].ev.propose(t.view(), newLinkWayIn());
    await hub.flush();
    for (const p of peers.slice(1, n - 1)) await p.ev.vote("APPROVE");
    await hub.flush();
    const { h, body } = hub.captured[0];
    return { hub, peers, t, h, body, real: decodeCommit(body)! };
  }

  it("refuses a commit sent by someone who did not vote, the target here", async () => {
    const { peers, t, h, real } = await approved(3);
    const b = peers[1];
    const forged = await encodeCommit(h, real.clear, { ...real.tail, sender: t.id }, t.identity);
    await b.ev.receiveCommit(h, 0, t.id, forged);
    expect(b.refusals).toEqual(["commit-policy"]);
    expect(b.leftOut).toBe(0);
    expect(b.removedCount).toBe(0);
    expect(b.keyring.rootEpoch).toBe(0);
  });

  it("refuses a commit whose tail names a sender other than the one it came from", async () => {
    const { peers, h, real } = await approved(4);
    const [, b, c] = peers;
    // c voted and signs it, but the tail still says the proposer sent it.
    const forged = await encodeCommit(h, real.clear, real.tail, c.identity);
    await b.ev.receiveCommit(h, 0, c.id, forged);
    expect(b.refusals).toEqual(["malformed-commit"]);
    expect(b.leftOut).toBe(0);
    expect(b.keyring.rootEpoch).toBe(0);
  });

  it("refuses a commit whose config changes the room's expiry", async () => {
    const { peers, h, body } = await approved(3);
    const b = peers[1];
    b.config = { ...b.config, ttl: { ...b.config.ttl, secs: b.config.ttl.secs + 1 } };
    await b.ev.receiveCommit(h, 0, peers[0].id, body);
    expect(b.refusals).toEqual(["commit-config"]);
    expect(b.keyring.rootEpoch).toBe(0);
  });

  it("tells a member that arrived during the vote, and never saw the request, that it was left out", async () => {
    const { hub, peers } = await room(4);
    const [a, b, t, d] = peers;
    hub.peers = hub.peers.filter((p) => p !== d);
    await a.ev.propose(t.view(), newLinkWayIn());
    await hub.flush();
    hub.peers.push(d);
    await b.ev.vote("APPROVE");
    await hub.flush();
    expect(hub.epoch).toBe(1);
    expect(b.keyring.rootEpoch).toBe(1);
    expect(d.leftOut).toBe(1);
    expect(d.refusals).toEqual([]);
    expect(d.keyring.rootEpoch).toBe(0);
  });

  it("applies nothing when this member reconnected while it checked the commit", async () => {
    const { peers, h, body } = await approved(3);
    const [a, b] = peers;
    const cfg = b.config;
    Object.defineProperty(b, "config", {
      get: () => {
        b.id = new Uint8Array(16).fill(0xba);
        return cfg;
      },
    });
    await b.ev.receiveCommit(h, 0, a.id, body);
    expect(b.applied).toHaveLength(0);
    expect(b.keyring.rootEpoch).toBe(0);
  });
});

/// A commit built by hand from a request and the way in it named, with the
/// votes and wraps a test chooses: what a proposer that deviates can send.
async function forgeCommit(from: Peer, req: EvictRequest, way: WayIn, votes: { voter: Uint8Array; sig: Uint8Array }[], wrapFor: Peer[]) {
  const keys = await deriveReRoot(keep(way));
  const config = await encryptRoomConfig(keys.contentKey, from.config.ttl, from.config.ceilingOptout, from.config.level);
  const h = header(FT.EVICT_COMMIT, req.epoch);
  const wraps = [];
  for (const p of wrapFor) {
    const key = await wrapKey(from.kx, p.kx.publicKeyRaw, ROOM, req.epoch + 1, from.id, p.id);
    wraps.push({ p: p.id, ...(await sealWrap(key, h, encodeWayIn(way))) });
  }
  const body = await encodeCommit(
    h,
    {
      requestId: req.id,
      target: req.target,
      targetKeyDigest: req.targetKey ? await keyDigest(req.targetKey) : null,
      verifier: req.verifier,
      salt: way.salt,
      config,
      votes,
    },
    { root: req.epoch + 1, sender: from.id, confirm: keys.confirm, wraps },
    from.identity,
  );
  return { h, body };
}

/// A well-formed request nobody signed, with a fresh id.
const junkRequest = (): Uint8Array =>
  encodeRequest({
    id: crypto.getRandomValues(new Uint8Array(16)),
    epoch: 0,
    target: null,
    targetKey: null,
    verifier: crypto.getRandomValues(new Uint8Array(32)),
    roster: crypto.getRandomValues(new Uint8Array(32)),
    policy: "UNANIMOUS",
    deadline: 60_000,
    sig: crypto.getRandomValues(new Uint8Array(64)),
  });

describe("a member that cannot place a commit's request never applies it (fix wave 2, F1)", () => {
  it("a member that never saw the request and is wrapped for anyway says it was left out and opens nothing", async () => {
    const { hub, peers } = await room(4);
    const [a, b, d, t] = peers;
    const held = holdFrames(hub);
    const way = newLinkWayIn();
    const copy = keep(way);
    await a.ev.propose(t.view(), way);
    const req = decodeRequest(held[0].pt)!;
    await b.ev.receiveFrame(held[0].ft, a.id, held[0].pt);
    await b.ev.vote("APPROVE");
    const bVote = decodeVote(held[1].pt)!;
    // Every vote d's own roster needs but d's, and a wrap for d all the same.
    const { h, body } = await forgeCommit(
      a,
      req,
      copy,
      [
        { voter: a.id, sig: req.sig },
        { voter: b.id, sig: bVote.sig! },
      ],
      [b, d],
    );
    await d.ev.receiveCommit(h, 0, a.id, body);
    expect(d.applied).toHaveLength(0);
    expect(d.leftOut).toBe(1);
    expect(d.refusals).toEqual([]);
    expect(d.keyring.rootEpoch).toBe(0);
    expect(d.keyring.current.epoch).toBe(0);
  });

  it("a member that never saw the request and holds the target's key says it was removed", async () => {
    const { hub, peers } = await room(3);
    const [a, b, t] = peers;
    const held = holdFrames(hub);
    await a.ev.propose(t.view(), newLinkWayIn());
    await b.ev.receiveFrame(held[0].ft, a.id, held[0].pt);
    await b.ev.vote("APPROVE");
    hub.dropCommits = true;
    await a.ev.receiveFrame(held[1].ft, b.id, held[1].pt);
    const { h, body } = hub.captured[0];
    await t.ev.receiveCommit(h, 0, a.id, body);
    expect(t.removedCount).toBe(1);
    expect(t.leftOut).toBe(0);
    expect(t.applied).toHaveLength(0);
    expect(t.keyring.rootEpoch).toBe(0);
  });
});

describe("the record of seen requests cannot be turned against the room (fix wave 2, F2)", () => {
  for (const flooder of ["the target", "another member"] as const) {
    it(`every member applies the real commit after a flood of junk requests from ${flooder}`, async () => {
      const { hub, peers } = await room(4);
      const [a, b, c, t] = peers;
      expect(await a.ev.propose(t.view(), newLinkWayIn())).toBeNull();
      await hub.flush();
      const from = flooder === "the target" ? t : c;
      for (let i = 0; i < MAX_SEEN_REQUESTS * 2; i++) {
        const junk = junkRequest();
        for (const p of [a, b, c, t]) await p.ev.receiveFrame(FT.EVICT_REQUEST, from.id, junk);
      }
      await b.ev.vote("APPROVE");
      await c.ev.vote("APPROVE");
      await hub.flush();
      expect(hub.epoch).toBe(1);
      for (const p of [a, b, c]) {
        expect(p.refusals.filter((r) => r.startsWith("commit"))).toEqual([]);
        expect(p.applied).toHaveLength(1);
        expect(p.keyring.rootEpoch).toBe(1);
        expect(p.states.at(-1)).toBe("DONE");
      }
    });
  }
});

describe("fix wave 2, the Minors", () => {
  it("a commit for an earlier request ends the newer vote as the epoch moving, not as done (Minor 1)", async () => {
    const { hub, peers } = await room(4);
    const [a, b, c, t] = peers;
    hub.dropCommits = true;
    await a.ev.propose(t.view(), newLinkWayIn());
    await hub.flush();
    await b.ev.vote("APPROVE");
    await c.ev.vote("APPROVE");
    await hub.flush();
    const { h, body } = hub.captured[0];
    // a gives up on its echo; b and c on the commit.
    hub.now += COMMIT_ECHO_MS;
    await a.ev.tick();
    hub.now += COMMIT_WAIT_MS - COMMIT_ECHO_MS;
    for (const p of [b, c]) await p.ev.tick();
    for (const p of [a, b, c]) expect(p.states.at(-1)).toBe("FAILED");
    // c asks for a link change, and a and b open it.
    expect(await c.ev.propose(null, newLinkWayIn())).toBeNull();
    await hub.flush();
    for (const p of [a, b, c]) expect(p.states.at(-1)).toBe("VOTING");
    // Then the commit for the first request arrives after all.
    hub.dropCommits = false;
    hub.deliver(a, h, body);
    await hub.flush();
    for (const p of [a, b, c]) {
      expect(p.applied).toHaveLength(1);
      expect(p.keyring.rootEpoch).toBe(1);
      expect(p.states.at(-1)).toBe("FAILED");
      expect(p.states).not.toContain("DONE");
    }
  });

  it("junk from one sender cannot push a real early frame from another out of the buffer (Minor 2)", async () => {
    const { hub, peers } = await room(4);
    const [a, b, c, t] = peers;
    const held = holdFrames(hub);
    for (let i = 0; i < 100; i++) {
      const v = encodeVote({ id: crypto.getRandomValues(new Uint8Array(16)), vote: "APPROVE", sig: crypto.getRandomValues(new Uint8Array(64)) });
      await b.ev.receiveFrame(FT.EVICT_VOTE, t.id, v);
    }
    expect(b.ev.heldFrames()).toBe(1);
    await a.ev.propose(t.view(), newLinkWayIn());
    await c.ev.receiveFrame(held[0].ft, a.id, held[0].pt);
    await c.ev.vote("REJECT");
    // c's refusal reaches b before the request does.
    await b.ev.receiveFrame(held[1].ft, c.id, held[1].pt);
    expect(b.ev.heldFrames()).toBe(2);
    await b.ev.receiveFrame(held[0].ft, a.id, held[0].pt);
    expect(b.states.at(-1)).toBe("REJECTED");
    expect(b.prompts).toHaveLength(0);
  });

  it("a target that refused the request as busy still says it was removed (Minor 3)", async () => {
    const { hub, peers } = await room(4);
    const [a, b, c, t] = peers;
    const held = holdFrames(hub);
    // c asks for a link change that only t hears, then gives up on it.
    await c.ev.propose(null, newLinkWayIn());
    await t.ev.receiveFrame(held[0].ft, c.id, held[0].pt);
    await c.ev.cancel();
    const at = held.length;
    await a.ev.propose(t.view(), newLinkWayIn());
    const r1 = held[at];
    for (const p of [b, c, t]) await p.ev.receiveFrame(r1.ft, a.id, r1.pt);
    expect(t.refusals).toEqual(["busy"]);
    hub.dropCommits = true;
    for (const p of [b, c]) await p.ev.vote("APPROVE");
    for (const f of held.slice(at + 1)) if (f.ft === FT.EVICT_VOTE) await a.ev.receiveFrame(f.ft, f.from.id, f.pt);
    expect(hub.captured).toHaveLength(1);
    const { h, body } = hub.captured[0];
    await t.ev.receiveCommit(h, 0, a.id, body);
    expect(t.removedCount).toBe(1);
    expect(t.refusals).toEqual(["busy"]);
    expect(t.applied).toHaveLength(0);
    expect(t.keyring.rootEpoch).toBe(0);
  });

  it("a member the proposer's roster did not include is told it was left out, not refused (Minor 4)", async () => {
    const { hub, peers } = await room(4);
    const [a, b, t, d] = peers;
    const held = holdFrames(hub);
    hub.peers = hub.peers.filter((p) => p !== d);
    await a.ev.propose(t.view(), newLinkWayIn());
    await b.ev.receiveFrame(held[0].ft, a.id, held[0].pt);
    // d's arrival reaches d before the request does.
    hub.peers.push(d);
    await d.ev.receiveFrame(held[0].ft, a.id, held[0].pt);
    expect(d.refusals).toEqual(["roster-mismatch"]);
    hub.sealed = Hub.prototype.sealed;
    await b.ev.vote("APPROVE");
    await hub.flush();
    expect(hub.epoch).toBe(1);
    expect(b.keyring.rootEpoch).toBe(1);
    expect(d.leftOut).toBe(1);
    expect(d.refusals).toEqual(["roster-mismatch"]);
    expect(d.keyring.rootEpoch).toBe(0);
  });

  it("ignores a repeated copy of the request open now, or of one already settled, quietly (Minor 5)", async () => {
    const { hub, peers } = await room(3);
    const [a, b, t] = peers;
    const held = holdFrames(hub);
    await a.ev.propose(t.view(), newLinkWayIn());
    await b.ev.receiveFrame(held[0].ft, a.id, held[0].pt);
    await b.ev.receiveFrame(held[0].ft, a.id, held[0].pt);
    expect(b.refusals).toEqual([]);
    expect(b.prompts).toHaveLength(1);
    await b.ev.vote("REJECT");
    await b.ev.receiveFrame(held[0].ft, a.id, held[0].pt);
    expect(b.refusals).toEqual([]);
    expect(b.prompts).toHaveLength(1);
    expect(b.states).toEqual(["VOTING", "REJECTED"]);
  });

  it("reports a vote past its deadline as expired before a new request replaces it (Minor 6)", async () => {
    const { hub, peers } = await room(3);
    const [a, b, t] = peers;
    await a.ev.propose(t.view(), newLinkWayIn(), 5_000);
    await hub.flush();
    hub.now += 5_000;
    await a.ev.tick();
    expect(await a.ev.propose(t.view(), newLinkWayIn())).toBeNull();
    await hub.flush();
    expect(b.states).toEqual(["VOTING", "EXPIRED", "VOTING"]);
    expect(b.prompts).toHaveLength(2);
  });
});
