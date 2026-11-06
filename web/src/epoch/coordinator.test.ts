import { describe, expect, it } from "vitest";
import { decryptWithExplicitNonce, encryptWithExplicitNonce } from "../crypto/aead";
import { deriveChainKey, randomEpochSecret, stepKeys } from "../crypto/epoch";
import { generateIdentity, signPayload, type Identity } from "../crypto/identity";
import { generateKx, kxStatement, sealWrap, wrapKey, type KxPair } from "../crypto/kx";
import { encodeHeader, FT, PROTOCOL_VERSION } from "../transport/frame";
import { EpochCoordinator, type KeyStatus, type MemberView } from "./coordinator";
import { encodeEpochKey } from "./frame";
import { Keyring } from "./keyring";
import { LEAVE_GRACE_MS, ROTATOR_FALLBACK_MS } from "./rotation";

const ROOM = new Uint8Array(16).fill(7);
const IV = new Uint8Array(12).fill(1);

function header(epoch: number): Uint8Array {
  return encodeHeader({ version: PROTOCOL_VERSION, frameType: FT.EPOCH_KEY, roomId: ROOM, epoch, nonceSess: new Uint8Array(4), flags: 0 });
}

async function sameKey(a: CryptoKey, b: CryptoKey): Promise<boolean> {
  const ct = await encryptWithExplicitNonce(a, IV, new Uint8Array([1]), undefined);
  try {
    await decryptWithExplicitNonce(b, IV, ct, undefined);
    return true;
  } catch {
    return false;
  }
}

/// A stand-in relay that applies the server's amendment J rules.
class Hub {
  epoch = 0;
  peers: Peer[] = [];
  now = 1_000_000;
  pending: Promise<void>[] = [];
  phantom: MemberView | null = null;
  /// While set, frames are held here instead of relayed.
  captured: { from: Peer; h: Uint8Array; body: Uint8Array }[] | null = null;

  route(from: Peer, h: Uint8Array, body: Uint8Array): boolean {
    if (this.captured) {
      this.captured.push({ from, h, body });
      return true;
    }
    const e = new DataView(h.buffer, h.byteOffset).getUint32(20, false);
    let to: Peer[];
    if (e === this.epoch + 1) {
      this.epoch = e;
      to = this.peers;
    } else if (e === this.epoch) {
      to = this.peers.filter((p) => p !== from);
    } else return true;
    for (const p of to) this.pending.push(p.coord.receive(h, e, from.id, body));
    return true;
  }

  async flush(): Promise<void> {
    while (this.pending.length) await this.pending.shift();
  }

  members(): MemberView[] {
    return this.peers.map((p) => ({ peerId: p.id, pubkey: p.identity.publicKeyRaw, kxPub: p.kx.publicKeyRaw, kxSig: p.kxSig, joinedAtSeq: p.seq }));
  }
}

let nextSeq = 1;

class Peer {
  coord!: EpochCoordinator;
  statuses: KeyStatus[] = [];
  adopted: number[] = [];
  rejoined = 0;
  extraMember: MemberView | null = null;
  constructor(
    readonly hub: Hub,
    readonly id: Uint8Array,
    readonly seq: number,
    readonly identity: Identity,
    readonly kx: KxPair,
    public kxSig: Uint8Array,
    readonly keyring: Keyring,
    public highest: boolean,
  ) {
    this.coord = new EpochCoordinator({
      roomId: ROOM,
      identity,
      kx,
      keyring,
      now: () => hub.now,
      me: () => this.id,
      members: () => (this.extraMember ? [...hub.members(), this.extraMember] : hub.members()),
      highest: () => this.highest,
      header,
      send: (h, b) => hub.route(this, h, b),
      adopt: (e) => this.adopted.push(e),
      rejoin: () => {
        this.rejoined += 1;
      },
      status: (s) => this.statuses.push(s),
      snapshotSoon: () => {},
    });
  }
}

async function makePeer(hub: Hub, highest = true, identity?: Identity): Promise<Peer> {
  const id = new Uint8Array(16).fill(nextSeq);
  const seq = nextSeq++;
  const ident = identity ?? (await generateIdentity());
  const kx = await generateKx();
  const kxSig = await signPayload(ident, kxStatement(ROOM, kx.publicKeyRaw));
  const content = await crypto.subtle.importKey("raw", new Uint8Array(32).fill(42), { name: "AES-GCM" }, false, ["encrypt", "decrypt"]);
  const chain = await deriveChainKey(new Uint8Array(32).fill(43), new Uint8Array(16).fill(44));
  const ring = await Keyring.fromRoot(0, content, chain);
  const p = new Peer(hub, id, seq, ident, kx, kxSig, ring, highest);
  return p;
}

async function room(n: number, highest = true): Promise<{ hub: Hub; peers: Peer[] }> {
  const hub = new Hub();
  const peers: Peer[] = [];
  for (let i = 0; i < n; i++) {
    const p = await makePeer(hub, highest);
    hub.peers.push(p);
    peers.push(p);
  }
  for (const p of peers) await p.coord.joined(0);
  return { hub, peers };
}

function leave(hub: Hub, gone: Peer): void {
  const view = hub.members().find((m) => m.peerId === gone.id)!;
  hub.peers = hub.peers.filter((p) => p !== gone);
  for (const p of hub.peers) p.coord.memberLeft(view);
}

function arrive(hub: Hub, p: Peer): void {
  hub.peers.push(p);
  const view = hub.members().find((m) => m.peerId === p.id)!;
  for (const q of hub.peers) if (q !== p) q.coord.memberJoined(view);
}

async function tickAll(hub: Hub, peers = hub.peers): Promise<void> {
  for (const p of peers) await p.coord.tick();
  await hub.flush();
}

describe("EpochCoordinator", () => {
  it("rotates a Highest room once someone has been gone 60 s, and the leaver cannot follow", async () => {
    const { hub, peers } = await room(3);
    const [a, b, c] = peers;
    leave(hub, c);
    hub.now += LEAVE_GRACE_MS - 1_000;
    await tickAll(hub);
    expect(hub.epoch).toBe(0);
    hub.now += 1_000;
    await tickAll(hub);
    expect(hub.epoch).toBe(1);
    expect(a.keyring.current.epoch).toBe(1);
    expect(b.keyring.current.epoch).toBe(1);
    expect(await sameKey(a.keyring.keyFor(1)!, b.keyring.keyFor(1)!)).toBe(true);
    expect(c.keyring.current.epoch).toBe(0);
    expect(a.adopted).toEqual([1]);
    expect(b.adopted).toEqual([1]);
    expect(b.statuses.at(-1)).toBe("ok");
  });

  it("does not rotate an everyday room when someone leaves", async () => {
    const { hub, peers } = await room(3, false);
    leave(hub, peers[2]);
    hub.now += LEAVE_GRACE_MS * 2;
    await tickAll(hub);
    expect(hub.epoch).toBe(0);
  });

  it("does not rotate when the same signing key comes back in time", async () => {
    const { hub, peers } = await room(3);
    const [, , c] = peers;
    leave(hub, c);
    hub.now += 30_000;
    const back = await makePeer(hub, true, c.identity);
    hub.peers.push(back);
    const view = hub.members().find((m) => m.peerId === back.id)!;
    for (const p of hub.peers) if (p !== back) p.coord.memberJoined(view);
    hub.now += LEAVE_GRACE_MS;
    await tickAll(hub);
    expect(hub.epoch).toBe(0);
  });

  it("falls back to the next member when the first stays silent", async () => {
    const { hub, peers } = await room(3);
    const [, b, c] = peers;
    leave(hub, c);
    hub.now += LEAVE_GRACE_MS;
    await tickAll(hub, [b]);
    expect(hub.epoch).toBe(0);
    hub.now += ROTATOR_FALLBACK_MS;
    await tickAll(hub, [b]);
    expect(hub.epoch).toBe(1);
  });

  it("hands a newcomer the keys after a rotation", async () => {
    const { hub, peers } = await room(3);
    const [a, , c] = peers;
    leave(hub, c);
    hub.now += LEAVE_GRACE_MS;
    await tickAll(hub);
    const d = await makePeer(hub);
    hub.peers.push(d);
    const view = hub.members().find((m) => m.peerId === d.id)!;
    for (const p of hub.peers) if (p !== d) p.coord.memberJoined(view);
    await d.coord.joined(1);
    expect(d.statuses.at(-1)).toBe("waiting");
    await tickAll(hub);
    expect(d.keyring.current.epoch).toBe(1);
    expect(await sameKey(a.keyring.keyFor(1)!, d.keyring.keyFor(1)!)).toBe(true);
    expect(d.adopted).toEqual([1]);
    expect(d.statuses.at(-1)).toBe("ok");
  });

  it("says a room is unreadable when nobody who holds its key is there", async () => {
    const hub = new Hub();
    const d = await makePeer(hub);
    hub.peers.push(d);
    await d.coord.joined(2);
    expect(d.statuses.at(-1)).toBe("unreadable");
  });

  it("refuses a step whose confirmation does not match", async () => {
    const { hub, peers } = await room(2);
    const [a, b] = peers;
    const h = header(1);
    const secret = randomEpochSecret();
    const key = await wrapKey(a.kx, b.kx.publicKeyRaw, ROOM, 1, a.id, b.id);
    const { iv, ct } = await sealWrap(key, h, secret);
    const body = await encodeEpochKey(
      h,
      { kind: "step", from: 0, to: 1, root: 0, sender: a.id, roster: new Uint8Array(32), confirm: new Uint8Array(16), wraps: [{ p: b.id, iv, ct }] },
      a.identity,
    );
    hub.epoch = 1;
    await b.coord.receive(h, 1, a.id, body);
    expect(b.keyring.current.epoch).toBe(0);
    expect(b.statuses.at(-1)).toBe("refused");
  });

  it("accepts the same hand-made step when its confirmation matches", async () => {
    const { hub, peers } = await room(2);
    const [a, b] = peers;
    const h = header(1);
    const secret = randomEpochSecret();
    const next = await stepKeys(a.keyring.current, secret);
    const key = await wrapKey(a.kx, b.kx.publicKeyRaw, ROOM, 1, a.id, b.id);
    const { iv, ct } = await sealWrap(key, h, secret);
    const body = await encodeEpochKey(
      h,
      { kind: "step", from: 0, to: 1, root: 0, sender: a.id, roster: new Uint8Array(32), confirm: next.confirm, wraps: [{ p: b.id, iv, ct }] },
      a.identity,
    );
    hub.epoch = 1;
    await b.coord.receive(h, 1, a.id, body);
    expect(b.keyring.current.epoch).toBe(1);
    expect(await sameKey(next.contentKey, b.keyring.keyFor(1)!)).toBe(true);
    expect(b.adopted).toEqual([1]);
    expect(b.statuses).not.toContain("refused");
  });

  it("shows a roster mismatch but still follows the step", async () => {
    const { hub, peers } = await room(3);
    const [, b, c] = peers;
    b.extraMember = { peerId: new Uint8Array(16).fill(99), joinedAtSeq: 999 };
    leave(hub, c);
    hub.now += LEAVE_GRACE_MS;
    await tickAll(hub);
    expect(b.keyring.current.epoch).toBe(1);
    expect(b.statuses.at(-1)).toBe("roster-mismatch");
  });

  it("rejoins when a step leaves it out, to be handed the key as a newcomer", async () => {
    // b's key-agreement signature is broken before anyone checks it, so the
    // rotator cannot wrap for b.
    const hub = new Hub();
    const a = await makePeer(hub);
    const b = await makePeer(hub);
    const c = await makePeer(hub);
    b.kxSig = new Uint8Array(64);
    hub.peers.push(a, b, c);
    for (const p of hub.peers) await p.coord.joined(0);
    leave(hub, c);
    hub.now += LEAVE_GRACE_MS;
    await tickAll(hub);
    expect(a.keyring.current.epoch).toBe(1);
    expect(b.keyring.current.epoch).toBe(0);
    expect(b.rejoined).toBe(1);
    expect(b.statuses.at(-1)).toBe("waiting");
  });
  it("an everyday room still follows a valid step from another member", async () => {
    const { hub, peers } = await room(3, false);
    const [a, b, c] = peers;
    a.highest = true;
    leave(hub, c);
    hub.now += LEAVE_GRACE_MS;
    await tickAll(hub);
    expect(hub.epoch).toBe(1);
    expect(b.keyring.current.epoch).toBe(1);
    expect(await sameKey(a.keyring.keyFor(1)!, b.keyring.keyFor(1)!)).toBe(true);
    expect(b.adopted).toEqual([1]);
    expect(b.statuses).not.toContain("refused");
  });

  it("a member with a signed but off-curve key-agreement key does not stop the others rotating", async () => {
    const hub = new Hub();
    const [a, b, c, d] = [await makePeer(hub), await makePeer(hub), await makePeer(hub), await makePeer(hub)];
    // b's key keeps its 0x04 prefix and a valid signature, but is not a point
    // on the curve, so no one can agree a key with it.
    b.kx.publicKeyRaw[64] ^= 1;
    b.kxSig = await signPayload(b.identity, kxStatement(ROOM, b.kx.publicKeyRaw));
    hub.peers.push(a, b, c, d);
    for (const p of hub.peers) await p.coord.joined(0);
    leave(hub, c);
    hub.now += LEAVE_GRACE_MS;
    for (const p of hub.peers) await expect(p.coord.tick()).resolves.toBeUndefined();
    await hub.flush();
    expect(hub.epoch).toBe(1);
    expect(a.keyring.current.epoch).toBe(1);
    expect(d.keyring.current.epoch).toBe(1);
    expect(await sameKey(a.keyring.keyFor(1)!, d.keyring.keyFor(1)!)).toBe(true);
    expect(b.keyring.current.epoch).toBe(0);
    expect(b.rejoined).toBe(1);
  });

  it("a newcomer with an off-curve key-agreement key does not stop another newcomer's handover", async () => {
    const { hub, peers } = await room(3);
    const [a, , c] = peers;
    leave(hub, c);
    hub.now += LEAVE_GRACE_MS;
    await tickAll(hub);
    expect(hub.epoch).toBe(1);
    const bad = await makePeer(hub);
    bad.kx.publicKeyRaw[64] ^= 1;
    bad.kxSig = await signPayload(bad.identity, kxStatement(ROOM, bad.kx.publicKeyRaw));
    arrive(hub, bad);
    const d = await makePeer(hub);
    arrive(hub, d);
    await d.coord.joined(1);
    for (const p of hub.peers) await expect(p.coord.tick()).resolves.toBeUndefined();
    await hub.flush();
    expect(d.keyring.current.epoch).toBe(1);
    expect(await sameKey(a.keyring.keyFor(1)!, d.keyring.keyFor(1)!)).toBe(true);
  });

  for (const winnerFirst of [true, false]) {
    it(`a member that gets the winning step and a losing one together ends on the winner (${winnerFirst ? "a" : "b"} wins)`, async () => {
      const { hub, peers } = await room(4);
      const [a, b, m, c] = peers;
      leave(hub, c);
      // b notes the deadline first and waits its turn; a, which should have
      // gone first, is late, so both send a step for epoch 1.
      hub.now += LEAVE_GRACE_MS;
      await b.coord.tick();
      hub.now += ROTATOR_FALLBACK_MS;
      hub.captured = [];
      await a.coord.tick();
      await b.coord.tick();
      const [fa, fb] = hub.captured;
      hub.captured = null;
      expect(fa.from).toBe(a);
      expect(fb.from).toBe(b);
      const [win, lose] = winnerFirst ? [fa, fb] : [fb, fa];
      // The winner applies its own echo, so its keyring holds the room's key.
      await win.from.coord.receive(win.h, 1, win.from.id, win.body);
      expect(win.from.keyring.current.epoch).toBe(1);
      // The server relays the winner first, then the loser like a handover.
      await Promise.all([
        m.coord.receive(win.h, 1, win.from.id, win.body),
        m.coord.receive(lose.h, 1, lose.from.id, lose.body),
      ]);
      expect(m.keyring.current.epoch).toBe(1);
      expect(await sameKey(win.from.keyring.keyFor(1)!, m.keyring.keyFor(1)!)).toBe(true);
      expect(m.statuses).not.toContain("refused");
      expect(m.adopted).toEqual([1]);
      // The loser follows the winner too.
      await lose.from.coord.receive(win.h, 1, win.from.id, win.body);
      expect(await sameKey(win.from.keyring.keyFor(1)!, lose.from.keyring.keyFor(1)!)).toBe(true);
      expect(lose.from.statuses).not.toContain("refused");
    });
  }

  it("never starts a step once the room turns out not to be Highest", async () => {
    const { hub, peers } = await room(3);
    leave(hub, peers[2]);
    // The sealed config has now opened and says everyday.
    for (const p of hub.peers) p.highest = false;
    hub.now += LEAVE_GRACE_MS * 2;
    await tickAll(hub);
    expect(hub.epoch).toBe(0);
  });

  it("forgets a deadline whose departure came back before its turn", async () => {
    const { hub, peers } = await room(3);
    const [, b, c] = peers;
    leave(hub, c);
    hub.now += LEAVE_GRACE_MS;
    await tickAll(hub, [b]); // b notes the deadline, but it is not b's turn yet
    arrive(hub, await makePeer(hub, true, c.identity));
    hub.now += ROTATOR_FALLBACK_MS;
    await tickAll(hub, [b]);
    expect(hub.epoch).toBe(0);
  });

  it("rejoins when its own step comes back after it gave up on it", async () => {
    const { hub, peers } = await room(3);
    const [a, , c] = peers;
    leave(hub, c);
    hub.now += LEAVE_GRACE_MS;
    hub.captured = [];
    await a.coord.tick();
    expect(hub.captured).toHaveLength(1);
    // The departure came back, and a gave up on its step before the echo.
    arrive(hub, await makePeer(hub, true, c.identity));
    hub.now += ROTATOR_FALLBACK_MS + 1;
    await a.coord.tick();
    const [echo] = hub.captured;
    hub.captured = null;
    await a.coord.receive(echo.h, 1, a.id, echo.body);
    expect(a.keyring.current.epoch).toBe(0);
    expect(a.adopted).toEqual([]);
    expect(a.statuses.at(-1)).toBe("waiting");
    expect(a.statuses).not.toContain("refused");
    expect(a.rejoined).toBe(1);
  });

  it("rejoins when its own echo is an earlier step than the one it holds a secret for", async () => {
    const { hub, peers } = await room(3);
    const [a, , c] = peers;
    leave(hub, c);
    hub.now += LEAVE_GRACE_MS;
    hub.captured = [];
    await a.coord.tick();
    hub.now += ROTATOR_FALLBACK_MS + 1;
    await a.coord.tick(); // gives up on the first and sends a second for the same epoch
    expect(hub.captured).toHaveLength(2);
    const [first] = hub.captured;
    hub.captured = null;
    await a.coord.receive(first.h, 1, a.id, first.body);
    expect(a.keyring.current.epoch).toBe(0);
    expect(a.statuses).not.toContain("refused");
    expect(a.statuses.at(-1)).toBe("waiting");
    expect(a.rejoined).toBe(1);
  });

  it("sends neither steps nor handovers while it is waiting for keys itself", async () => {
    const { hub, peers } = await room(4);
    const [a, b, , c] = peers;
    leave(hub, c);
    hub.now += LEAVE_GRACE_MS;
    await tickAll(hub);
    expect(hub.epoch).toBe(1);
    // a now believes the room has moved past what it holds.
    await a.coord.joined(2);
    expect(a.statuses.at(-1)).toBe("waiting");
    hub.captured = [];
    arrive(hub, await makePeer(hub));
    leave(hub, b);
    hub.now += LEAVE_GRACE_MS;
    await a.coord.tick();
    expect(hub.captured).toEqual([]);
  });
});
