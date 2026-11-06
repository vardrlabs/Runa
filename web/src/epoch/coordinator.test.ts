import { describe, expect, it } from "vitest";
import { decryptWithExplicitNonce, encryptWithExplicitNonce } from "../crypto/aead";
import { deriveChainKey, randomEpochSecret } from "../crypto/epoch";
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

  route(from: Peer, h: Uint8Array, body: Uint8Array): boolean {
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
    highest: boolean,
  ) {
    this.coord = new EpochCoordinator({
      roomId: ROOM,
      identity,
      kx,
      keyring,
      now: () => hub.now,
      me: () => this.id,
      members: () => (this.extraMember ? [...hub.members(), this.extraMember] : hub.members()),
      highest: () => highest,
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
});
