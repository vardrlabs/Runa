import * as Y from "yjs";
import { afterEach, describe, expect, it, vi } from "vitest";
import { generateIdentity, signPayload, type Identity } from "./crypto/identity";
import { generateKx, kxStatement } from "./crypto/kx";
import { wrapWithLengthAndPad } from "./doc/ydoc";
import type { EvictDeps } from "./evict/coordinator";
import { deriveReRoot, newLinkWayIn, newPassWayIn, type WayIn } from "./evict/reroot";
import type { Keyring } from "./epoch/keyring";
import { EPOCH_OVERLAP_MS, LEAVE_GRACE_MS, ROTATOR_FALLBACK_MS } from "./epoch/rotation";
import { KEY_STATUS_TEXT, Session, type SessionEvents } from "./session";
import { FT } from "./transport/frame";
import { toB64, type JoinAck, type SocketEvents } from "./transport/socket";

/// What Session.create hands the socket, and what the session asks of it.
/// Everything else Session.create builds is real: the epoch coordinator, the
/// evict coordinator, the keyring, the document and the shred machine.
interface FakeSocket {
  events: SocketEvents;
  opts: { authKey: Uint8Array; roomId: Uint8Array };
  calls: string[];
  evictSent: number[];
  epochKeys: Uint8Array[];
}

const fake = vi.hoisted(() => ({ last: null as unknown }));

vi.mock("./transport/socket", async (importOriginal) => {
  const real = await importOriginal<typeof import("./transport/socket")>();
  const frame = await import("./transport/frame");
  class RunaSocket {
    events: SocketEvents;
    calls: string[] = [];
    evictSent: number[] = [];
    epochKeys: Uint8Array[] = [];
    isAwaitingKeys = false;
    constructor(readonly opts: { authKey: Uint8Array; roomId: Uint8Array; events: SocketEvents }) {
      this.events = opts.events;
      fake.last = this;
    }
    connect = () => Promise.resolve();
    stopReconnecting = () => void this.calls.push("stopReconnecting");
    close = () => void this.calls.push("close");
    dropKeys = () => void this.calls.push("dropKeys");
    replaceAuthKey = (k: Uint8Array) => {
      this.calls.push("replaceAuthKey");
      this.opts.authKey = k;
    };
    adoptEpoch = (e: number) => void this.calls.push(`adoptEpoch ${e}`);
    reconnectNow = () => void this.calls.push("reconnectNow");
    resume = () => void this.calls.push("resume");
    heldRestartTicket = () => null;
    dropRestartTicket = () => {};
    sendSyncRequest = () => {};
    sendUpdate = async () => {};
    sendSnapshot = async () => {};
    sendAwareness = async () => {};
    sendShredFrame = async () => {};
    sendEvictFrame = async (ft: number) => {
      this.evictSent.push(ft);
      return true;
    };
    sendSigned = () => true;
    sendEpochKey = (h: Uint8Array) => {
      this.epochKeys.push(h);
      return true;
    };
    frameHeader = (frameType: number, epoch: number) =>
      frame.encodeHeader({ version: frame.PROTOCOL_VERSION, frameType, roomId: this.opts.roomId, epoch, nonceSess: new Uint8Array(4), flags: 0 });
    epochKeyHeader = (epoch: number) => this.frameHeader(frame.FT.EPOCH_KEY, epoch);
    readyForSnapshot = () => false;
    replaceBacklogWith = () => {};
    sendPurgeAck = () => {};
    sendTtlExtend = () => {};
  }
  return { ...real, RunaSocket };
});

// Argon2id, held where a test needs to act while it runs.
vi.mock("./evict/reroot", async (importOriginal) => {
  const real = await importOriginal<typeof import("./evict/reroot")>();
  return { ...real, newPassWayIn: vi.fn(real.newPassWayIn) };
});

const ROOM_HEX = "07".repeat(16);
const ROOM = new Uint8Array(16).fill(7);
const ME = new Uint8Array(16).fill(0x11);

interface Member {
  peerId: Uint8Array;
  identity: Identity;
  kxPub: Uint8Array;
  kxSig: Uint8Array;
  seq: number;
}

async function member(n: number, seq: number): Promise<Member> {
  const identity = await generateIdentity();
  const kx = await generateKx();
  const kxSig = await signPayload(identity, kxStatement(ROOM, kx.publicKeyRaw));
  return { peerId: new Uint8Array(16).fill(n), identity, kxPub: kx.publicKeyRaw, kxSig, seq };
}

function wire(m: Member) {
  return {
    peer_id: toB64(m.peerId),
    pubkey: toB64(m.identity.publicKeyRaw),
    kx_pubkey: toB64(m.kxPub),
    kx_sig: toB64(m.kxSig),
    joined_at_seq: m.seq,
  };
}

function recorder() {
  const seen = {
    removed: 0,
    tempers: [] as string[],
    ignored: [] as string[],
    states: [] as [string, string | undefined][],
    keyStatus: [] as [string | null, boolean][],
    leftOut: 0,
    order: [] as string[],
  };
  const events: SessionEvents = {
    onJoinAck: () => {},
    onPeersChanged: () => {},
    onTemper: (t) => void seen.tempers.push(t),
    onShredPrompt: () => {},
    onShredState: () => {},
    onPurge: () => {},
    onCountdown: () => {},
    onTtlMismatch: () => {},
    onShredRejected: () => {},
    onHistoryPressure: () => {},
    onDivergence: () => {},
    onRoomUnavailable: () => {},
    onServerRestart: () => {},
    onConnectionRefused: () => {},
    onKeyStatus: (m, a) => void seen.keyStatus.push([m, a]),
    onEvictState: (st, reason) => {
      seen.states.push([st, reason]);
      seen.order.push(`state ${st}`);
    },
    onLeftOut: () => {
      seen.leftOut += 1;
      seen.order.push("leftOut");
    },
    onEvictIgnored: (r) => void seen.ignored.push(r),
    onRemoved: () => {
      seen.removed += 1;
    },
  };
  return { events, seen };
}

const sessions: Session[] = [];

afterEach(() => {
  for (const s of sessions.splice(0)) s.destroySession();
  vi.useRealTimers();
});

/// A session joined to a room of this tab (seq 1), `a` (seq 2) and `b` (seq 3).
async function joined(opts: { wayKind?: "link" | "pass" } = {}) {
  const contentKey = await crypto.subtle.importKey("raw", new Uint8Array(32).fill(9), { name: "AES-GCM" }, false, ["encrypt", "decrypt"]);
  const chainKey = await crypto.subtle.importKey("raw", new Uint8Array(32).fill(8), "HKDF", false, ["deriveBits", "deriveKey"]);
  const { events, seen } = recorder();
  const session = await Session.create(
    { url: "wss://relay.invalid/socket", roomIdHex: ROOM_HEX, authKey: new Uint8Array(32).fill(1), contentKey, chainKey, wayKind: opts.wayKind ?? "link" },
    events,
  );
  sessions.push(session);
  const socket = fake.last as FakeSocket;
  const a = await member(0x22, 2);
  const b = await member(0x33, 3);
  const me = { peer_id: toB64(ME), pubkey: toB64(session.identity.publicKeyRaw), joined_at_seq: 1 };
  const ack = (roster: unknown[]) =>
    ({
      peer_id: toB64(ME),
      epoch: 0,
      root_epoch: 0,
      log_len: 0,
      base_index: 0,
      has_snapshot: false,
      ttl: { kind: "none", secs: 0 },
      ceiling_optout: false,
      roster,
      indexed: true,
      log_id: "log-1",
    }) as unknown as JoinAck;
  const join = (roster: unknown[]) => (socket.events.onJoinAck as unknown as (a: JoinAck) => Promise<void>)(ack(roster));
  await join([me, wire(a), wire(b)]);
  const evictDeps = (session.evict as unknown as { d: EvictDeps }).d;
  const keyring = (session as unknown as { keyring: Keyring }).keyring;
  return { session, socket, seen, a, b, me, join, evictDeps, keyring };
}

/// Re-roots the real keyring to `root` on the epoch queue, as a commit does.
async function reRoot(session: Session, keyring: Keyring, evictDeps: EvictDeps, root = 1): Promise<void> {
  const way = newLinkWayIn();
  const keys = await deriveReRoot(way);
  await session.coordinator.exclusive(async () => {
    const ok = await keyring.reroot(root, keys.contentKey, keys.chainKey);
    if (!ok) throw new Error("re-root refused");
    evictDeps.applyReRoot({ root, way, keys, target: null, targetKey: null });
  });
}

const waitFor = (check: () => void) => vi.waitFor(check, { timeout: 3000, interval: 5 });

/// A wrapped Yjs update, as a snapshot carries one.
const snapshotBlob = () => wrapWithLengthAndPad(Y.encodeStateAsUpdate(new Y.Doc()));

describe("Session.create wiring: removal (amendment K)", () => {
  it("ends the tab on ERROR 4014: it stops reconnecting and says so once, with no other warning", async () => {
    const { socket, seen } = await joined();
    socket.events.onError(4014);
    socket.events.onError(4014);
    expect(seen.removed).toBe(1);
    expect(socket.calls.filter((c) => c === "stopReconnecting")).toHaveLength(1);
    expect(seen.tempers).not.toContain("WATCH");
  });

  it("ends the tab the same way when the evict coordinator finds this tab named in a commit", async () => {
    const { socket, seen, evictDeps } = await joined();
    evictDeps.removed();
    socket.events.onError(4014);
    expect(seen.removed).toBe(1);
    expect(socket.calls.filter((c) => c === "stopReconnecting")).toHaveLength(1);
  });

  it("does not ask the room after Argon2id when the tab was removed while it ran", async () => {
    const { session, socket } = await joined({ wayKind: "pass" });
    let finish: (w: WayIn) => void = () => {};
    vi.mocked(newPassWayIn).mockImplementationOnce(() => new Promise<WayIn>((res) => (finish = res)));
    const proposing = session.proposeEviction(null, "violet harbour copper lantern quartz ninety");
    await Promise.resolve();
    socket.events.onError(4014);
    const way = { ...newLinkWayIn(), kind: "pass" as const, phrase: "violet harbour copper lantern quartz ninety" };
    finish(way);
    expect(await proposing).toBe("failed");
    expect(socket.evictSent).toEqual([]);
    expect(way.secret.every((x) => x === 0)).toBe(true);
  });
});

describe("Session.create wiring: eviction frames and votes", () => {
  it("hands EVICT frames to the evict coordinator, which passes a refusal on as a request ignored", async () => {
    const { socket, seen, a } = await joined();
    socket.events.onEvictFrame?.(FT.EVICT_REQUEST, a.peerId, new Uint8Array([1, 2, 3]));
    await waitFor(() => expect(seen.ignored).toEqual(["malformed"]));
  });

  it("hands EVICT_COMMIT frames to the evict coordinator, which shows a bad one as a refused key change", async () => {
    const { socket, seen, a } = await joined();
    socket.events.onEvictCommit?.(new Uint8Array(3), 0, a.peerId, new Uint8Array(3));
    await waitFor(() => expect(seen.keyStatus).toContainEqual([KEY_STATUS_TEXT.refused, true]));
  });

  it("fails an open vote as voter-left when a voter leaves", async () => {
    const { session, socket, seen, a } = await joined();
    expect(await session.proposeEviction(null)).toBeNull();
    expect(session.evict.isOpen()).toBe(true);
    socket.events.onPeerLeave(a.peerId);
    await waitFor(() => expect(seen.states).toContainEqual(["FAILED", "voter-left"]));
  });

  it("fails an open vote as voter-left when a voter left while this tab was away", async () => {
    const { session, seen, me, b, join } = await joined();
    expect(await session.proposeEviction(null)).toBeNull();
    // Back after a reconnect: `a` is gone, and no PEER_LEAVE said so.
    await join([me, wire(b)]);
    await waitFor(() => expect(seen.states).toContainEqual(["FAILED", "voter-left"]));
  });

  it("holds a due key step while a vote is open, and sends it once the vote has ended without a commit", async () => {
    vi.useFakeTimers({ toFake: ["Date"] });
    const { session, socket, b } = await joined();
    // `b` leaves before the vote, so the vote stays open while the step falls due.
    socket.events.onPeerLeave(b.peerId);
    expect(await session.proposeEviction(null)).toBeNull();
    vi.setSystemTime(Date.now() + LEAVE_GRACE_MS + ROTATOR_FALLBACK_MS * 3);
    await session.coordinator.tick();
    await session.coordinator.tick();
    expect(socket.epochKeys).toHaveLength(0);
    await session.cancelEviction();
    expect(session.evict.isOpen()).toBe(false);
    await session.coordinator.tick();
    await waitFor(() => expect(socket.epochKeys).toHaveLength(1));
  });

  it("says in a shared room that its passphrase changed when the tab was left out", async () => {
    const { seen, evictDeps } = await joined({ wayKind: "pass" });
    evictDeps.leftOut();
    const [text, alarming] = seen.keyStatus.at(-1)!;
    expect(text).toMatch(/passphrase changed/);
    expect(text).not.toMatch(/\blink\b/);
    expect(alarming).toBe(false);
  });
});

describe("Session.create wiring: a tab left out of a re-root (amendment K)", () => {
  // The evict coordinator has two routes to "left out", and the page must
  // hear the same thing from both.
  it("tells the page once when a member's commit names an epoch this tab has not reached", async () => {
    const { seen, evictDeps } = await joined();
    // The later-epoch route calls only the leftOut dep.
    evictDeps.leftOut();
    evictDeps.leftOut();
    expect(seen.leftOut).toBe(1);
    expect(seen.states).toEqual([]);
    expect(seen.keyStatus.at(-1)?.[0]).toMatch(/link changed, and this tab was not given the new one/);
  });

  it("tells the page once when this tab holds no wrap it can use in a commit it can place", async () => {
    const { seen, evictDeps } = await joined();
    // The route through leftOutOfCommit: FAILED with left-out, then leftOut.
    evictDeps.state("FAILED", "left-out");
    evictDeps.leftOut();
    expect(seen.leftOut).toBe(1);
    expect(seen.order).toEqual(["state FAILED", "leftOut"]);
  });

  it("tells the page on a FAILED left-out alone, and not for any other failure", async () => {
    const { seen, evictDeps } = await joined();
    evictDeps.state("FAILED", "epoch-moved");
    expect(seen.leftOut).toBe(0);
    evictDeps.state("FAILED", "left-out");
    expect(seen.leftOut).toBe(1);
  });

  it("tells the page again when a later re-root it was let into is followed by one it was left out of", async () => {
    const { session, seen, evictDeps, keyring } = await joined();
    evictDeps.leftOut();
    await reRoot(session, keyring, evictDeps);
    evictDeps.leftOut();
    expect(seen.leftOut).toBe(2);
  });

  it("does not stop telling the page when the page's callback throws", async () => {
    const { session, evictDeps } = await joined();
    let calls = 0;
    (session as unknown as { events: SessionEvents }).events.onLeftOut = () => {
      calls += 1;
      throw new Error("page callback threw");
    };
    expect(() => evictDeps.leftOut()).not.toThrow();
    expect(() => evictDeps.state("FAILED", "left-out")).not.toThrow();
    expect(calls).toBe(1);
  });
});

describe("Session.create wiring: the end of the evict coordinator", () => {
  it("is ended when the keys are dropped: an open vote's way in goes, and no frame is taken after", async () => {
    const { session, socket, seen, a } = await joined();
    expect(await session.proposeEviction(null)).toBeNull();
    session.dropKeys();
    expect(session.evict.isOpen()).toBe(false);
    socket.events.onEvictFrame?.(FT.EVICT_REQUEST, a.peerId, new Uint8Array([1]));
    await new Promise((r) => setTimeout(r, 50));
    expect(seen.ignored).toEqual([]);
  });

  it("is ended when the session is destroyed", async () => {
    const { session, socket, seen, a } = await joined();
    expect(await session.proposeEviction(null)).toBeNull();
    session.destroySession();
    expect(session.evict.isOpen()).toBe(false);
    socket.events.onEvictFrame?.(FT.EVICT_REQUEST, a.peerId, new Uint8Array([1]));
    await new Promise((r) => setTimeout(r, 50));
    expect(seen.ignored).toEqual([]);
  });
});

describe("Session.create wiring: forgetting the keys from before a re-root (amendment K)", () => {
  const forget = (session: Session) => (session as unknown as { forgetOldRoot(): Promise<void> }).forgetOldRoot();

  it("does not count a snapshot sealed under the old root and delivered after the re-root, however long the overlap has passed", async () => {
    vi.useFakeTimers({ toFake: ["Date"] });
    const { session, socket, keyring, evictDeps, a } = await joined();
    await reRoot(session, keyring, evictDeps);
    expect(keyring.has(0)).toBe(true);
    socket.events.onSnapshot(a.peerId, 1n, snapshotBlob(), 0);
    vi.setSystemTime(Date.now() + EPOCH_OVERLAP_MS * 10);
    await forget(session);
    expect(keyring.has(0)).toBe(true);
  });

  it("forgets them once a snapshot under the new root has landed and the overlap has passed", async () => {
    vi.useFakeTimers({ toFake: ["Date"] });
    const { session, socket, keyring, evictDeps, a } = await joined();
    await reRoot(session, keyring, evictDeps);
    socket.events.onSnapshot(a.peerId, 1n, snapshotBlob(), 1);
    await forget(session);
    expect(keyring.has(0)).toBe(true);
    vi.setSystemTime(Date.now() + EPOCH_OVERLAP_MS);
    await forget(session);
    expect(keyring.has(0)).toBe(false);
  });
});
