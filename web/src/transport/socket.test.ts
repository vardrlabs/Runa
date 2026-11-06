import * as Y from "yjs";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { FrameCipher, decryptEnvelope } from "../crypto/aead";
import { randomEpochSecret, stepKeys } from "../crypto/epoch";
import { Keyring } from "../epoch/keyring";
import type { Identity } from "../crypto/identity";
import { mergeWrapped, unwrapLengthPrefix, wrapWithLengthAndPad } from "../doc/ydoc";
import { FT, HEADER_LEN, PROTOCOL_VERSION, buildJsonFrame, concatBytes, encodeHeader } from "./frame";
import { PART_MARKER, RunaSocket, readPart, splitIntoParts, toB64, type SocketEvents } from "./socket";

/// Stands in for the browser's WebSocket. `dead` models a connection that has
/// died without the browser noticing: it stays OPEN, sends vanish, and nothing
/// arrives — which is what a laptop waking or a phone changing networks does.
class FakeWebSocket {
  static readonly CONNECTING = 0;
  static readonly OPEN = 1;
  static readonly CLOSING = 2;
  static readonly CLOSED = 3;
  static all: FakeWebSocket[] = [];
  readyState = FakeWebSocket.CONNECTING;
  binaryType = "blob";
  sent: Uint8Array[] = [];
  dead = false;
  onopen: (() => void) | null = null;
  onmessage: ((ev: { data: ArrayBuffer }) => void) | null = null;
  onclose: ((ev?: { code: number }) => void) | null = null;
  onerror: (() => void) | null = null;
  constructor(readonly url: string) {
    FakeWebSocket.all.push(this);
  }
  send(bytes: Uint8Array): void {
    if (this.readyState !== FakeWebSocket.OPEN) throw new Error("send on a socket that is not open");
    if (!this.dead) this.sent.push(bytes.slice());
  }
  close(code?: number): void {
    if (this.readyState === FakeWebSocket.CLOSED) return;
    this.readyState = FakeWebSocket.CLOSED;
    this.onclose?.(code === undefined ? undefined : { code });
  }
  open(): void {
    this.readyState = FakeWebSocket.OPEN;
    this.onopen?.();
  }
  deliver(frame: Uint8Array): void {
    if (this.dead) return;
    this.onmessage?.({ data: frame.slice().buffer });
  }
}

const ROOM = new Uint8Array(16).fill(7);
const PEER = new Uint8Array(16).fill(0x42);
const realWebSocket = globalThis.WebSocket;
let sockets: RunaSocket[] = [];

beforeEach(() => {
  FakeWebSocket.all = [];
  (globalThis as { WebSocket: unknown }).WebSocket = FakeWebSocket;
});

afterEach(() => {
  for (const s of sockets) s.close();
  sockets = [];
  (globalThis as { WebSocket: unknown }).WebSocket = realWebSocket;
});

const noop = () => {};

async function makeSocket(
  opts: {
    events?: Partial<SocketEvents>;
    ackTimeoutMs?: number;
    heartbeatMs?: number;
    compact?: (w: Uint8Array[]) => Uint8Array[];
    epochOverlapMs?: number;
  } = {},
) {
  const key = await crypto.subtle.importKey("raw", new Uint8Array(32).fill(9), { name: "AES-GCM" }, false, [
    "encrypt",
    "decrypt",
  ]);
  const chain = await crypto.subtle.importKey("raw", new Uint8Array(32).fill(8), "HKDF", false, [
    "deriveBits",
    "deriveKey",
  ]);
  const keyring = await Keyring.fromRoot(0, key, chain);
  const socket = new RunaSocket({
    url: "ws://127.0.0.1:1/socket/test",
    roomId: ROOM,
    authKey: new Uint8Array(32).fill(1),
    identity: { publicKeyRaw: new Uint8Array(32).fill(5) } as unknown as Identity,
    keyring,
    kx: { publicKeyRaw: new Uint8Array(65).fill(4), sig: new Uint8Array(64).fill(6) },
    epochOverlapMs: opts.epochOverlapMs,
    insecureAllowed: true,
    ackTimeoutMs: opts.ackTimeoutMs,
    heartbeatMs: opts.heartbeatMs,
    compactUpdates: opts.compact,
    events: {
      onJoinAck: noop,
      onDocUpdate: noop,
      onSnapshot: noop,
      onAwareness: noop,
      onShredFrame: noop,
      onPeerJoin: noop,
      onPeerLeave: noop,
      onPurge: noop,
      onTtlExtended: noop,
      onError: noop,
      onSnapshotTooLarge: noop,
      onEpochStale: noop,
      onDisconnected: noop,
      ...opts.events,
    },
  });
  sockets.push(socket);
  await socket.connect();
  return { socket, key, keyring };
}

const latest = () => FakeWebSocket.all[FakeWebSocket.all.length - 1];

const LIMITS = { max_frame_bytes: 1024 * 1024, frames_per_sec: 1000, bytes_per_sec: 64 * 1024 * 1024 };

function joinAck(extra: Record<string, unknown> = {}): Uint8Array {
  return buildJsonFrame(FT.JOIN_ACK, ROOM, 0, {
    peer_id: toB64(PEER),
    epoch: 0,
    log_len: 0,
    base_index: 0,
    has_snapshot: false,
    ttl: { kind: "none", secs: 0 },
    ceiling_optout: false,
    kdf: { alg: "argon2id", m_kib: 65536, t: 3, p: 1, salt: "" },
    roster: [],
    acks: true,
    limits: LIMITS,
    ...extra,
  });
}

const docAck = (ok = true) => buildJsonFrame(FT.DOC_ACK, ROOM, 0, ok ? { ok, index: 0 } : { ok });
const docFrames = (ws: FakeWebSocket) => ws.sent.filter((f) => f[3] === FT.DOC_UPDATE);
const text = (s: string) => wrapWithLengthAndPad(new TextEncoder().encode(s));
const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

/// Opens a frame the way a receiving peer would: against the peer id the
/// server assigned, not the key the sender started with.
function readAsPeer(frame: Uint8Array, key: CryptoKey): Promise<Uint8Array> {
  return decryptEnvelope(key, frame.slice(0, HEADER_LEN), PEER, frame.slice(HEADER_LEN));
}

const OTHER = new Uint8Array(16).fill(0x24);

/// A frame as the relay delivers it: header, sender envelope, then the
/// envelope the sender's cipher produced under `key`.
async function incoming(ft: number, epoch: number, key: CryptoKey, plaintext: Uint8Array): Promise<Uint8Array> {
  const header = encodeHeader({ version: PROTOCOL_VERSION, frameType: ft, roomId: ROOM, epoch, nonceSess: new Uint8Array(4), flags: 0 });
  const env = await new FrameCipher(key, OTHER).encrypt(header, plaintext);
  return concatBytes(header, OTHER, env);
}

async function stepRing(ring: Keyring): Promise<void> {
  const s = randomEpochSecret();
  const next = await stepKeys(ring.current, s);
  await ring.applyStep(next.epoch, s, next.confirm);
}

async function waitFor(check: () => boolean, ms = 3000): Promise<void> {
  const end = Date.now() + ms;
  while (!check()) {
    if (Date.now() > end) throw new Error("timed out waiting");
    await sleep(10);
  }
}

describe("a document update is kept until the room has stored it", () => {
  it("sends nothing encrypted before the join is confirmed, then sends what was typed so peers can read it", async () => {
    const { socket, key } = await makeSocket();
    const ws = latest();
    ws.open();
    const typed = text("typed while the join was still in flight");
    await socket.sendUpdate(typed.slice());
    await socket.sendAwareness(text("cursor"));
    await expect(socket.sendSnapshot(text("state"), 0n)).rejects.toThrow();
    await sleep(30);
    expect(ws.sent.map((f) => f[3])).toEqual([FT.JOIN]);

    ws.deliver(joinAck());
    await waitFor(() => docFrames(ws).length === 1);
    expect(await readAsPeer(docFrames(ws)[0], key)).toEqual(typed);
  });

  it("resends an update the server never acknowledged on the next connection, and only that one", async () => {
    const { socket, key } = await makeSocket();
    const first = latest();
    first.open();
    first.deliver(joinAck());
    const stored = text("stored");
    const lost = text("lost with the connection");
    await socket.sendUpdate(stored.slice());
    await waitFor(() => docFrames(first).length === 1);
    first.deliver(docAck());
    await socket.sendUpdate(lost.slice());
    await waitFor(() => docFrames(first).length === 2);
    first.close();

    await waitFor(() => FakeWebSocket.all.length === 2);
    const second = latest();
    second.open();
    second.deliver(joinAck());
    await waitFor(() => docFrames(second).length === 1);
    await sleep(50);
    expect(docFrames(second)).toHaveLength(1);
    expect(await readAsPeer(docFrames(second)[0], key)).toEqual(lost);
  });

  it("abandons a connection that stops acknowledging, and resends on a new one", async () => {
    const { socket, key } = await makeSocket({ ackTimeoutMs: 150 });
    const first = latest();
    first.open();
    first.deliver(joinAck());
    first.dead = true;
    const typed = text("typed into a connection that had already died");
    await socket.sendUpdate(typed.slice());

    await waitFor(() => FakeWebSocket.all.length === 2);
    const second = latest();
    second.open();
    second.deliver(joinAck());
    await waitFor(() => docFrames(second).length === 1);
    expect(await readAsPeer(docFrames(second)[0], key)).toEqual(typed);
  });

  it("does not resend an update the room refused to store", async () => {
    const { socket } = await makeSocket();
    const first = latest();
    first.open();
    first.deliver(joinAck());
    await socket.sendUpdate(text("the log is full"));
    await waitFor(() => docFrames(first).length === 1);
    first.deliver(docAck(false));
    first.close();

    await waitFor(() => FakeWebSocket.all.length === 2);
    const second = latest();
    second.open();
    second.deliver(joinAck());
    await sleep(100);
    expect(docFrames(second)).toHaveLength(0);
  });

  it("against a server without acks, sends each update once and never resends it", async () => {
    const { socket } = await makeSocket();
    const first = latest();
    first.open();
    first.deliver(joinAck({ acks: undefined, limits: undefined }));
    await socket.sendUpdate(text("fire and forget"));
    await waitFor(() => docFrames(first).length === 1);
    first.close();

    await waitFor(() => FakeWebSocket.all.length === 2);
    const second = latest();
    second.open();
    second.deliver(joinAck({ acks: undefined, limits: undefined }));
    await sleep(100);
    expect(docFrames(second)).toHaveLength(0);
  });
});

describe("resending a backlog", () => {
  it("paces it under the rate the server advertised instead of tripping the limit", async () => {
    const { socket } = await makeSocket();
    const ws = latest();
    ws.open();
    for (let i = 0; i < 40; i++) await socket.sendUpdate(wrapWithLengthAndPad(new Uint8Array([i])));
    ws.deliver(joinAck({ limits: { ...LIMITS, frames_per_sec: 10 } }));
    await sleep(400);
    const sent = docFrames(ws).length;
    expect(sent).toBeGreaterThan(0);
    // A burst of the bucket's ten, plus five a second after it.
    expect(sent).toBeLessThanOrEqual(12);
  });

  it("merges updates queued while offline into one that applies the same", async () => {
    const { socket, key } = await makeSocket({ compact: mergeWrapped });
    const ws = latest();
    ws.open();
    const author = new Y.Doc();
    const updates: Uint8Array[] = [];
    author.on("update", (u: Uint8Array) => updates.push(u));
    const t = author.getText("content");
    for (let i = 0; i < 20; i++) t.insert(t.length, `line ${i}\n`);
    for (const u of updates) await socket.sendUpdate(wrapWithLengthAndPad(u));

    ws.deliver(joinAck());
    await waitFor(() => docFrames(ws).length >= 1);
    await sleep(50);
    expect(docFrames(ws)).toHaveLength(1);
    const reader = new Y.Doc();
    Y.applyUpdate(reader, unwrapLengthPrefix(await readAsPeer(docFrames(ws)[0], key)));
    expect(reader.getText("content").toString()).toBe(t.toString());
  });
});

describe("an update larger than a frame", () => {
  it("is split so no frame exceeds the limit, and a receiving peer puts it back together", async () => {
    const limit = 64 * 1024;
    const { socket } = await makeSocket();
    const ws = latest();
    ws.open();
    ws.deliver(joinAck({ limits: { ...LIMITS, max_frame_bytes: limit } }));
    const big = new Uint8Array(300 * 1024);
    for (let i = 0; i < big.length; i++) big[i] = (i * 31) & 0xff;
    const wrapped = wrapWithLengthAndPad(big);
    await socket.sendUpdate(wrapped.slice());

    // Acknowledge each frame as it goes out, until what has been sent adds up
    // to at least the whole update.
    let acked = 0;
    await waitFor(() => {
      const sent = docFrames(ws);
      while (acked < sent.length) {
        ws.deliver(docAck());
        acked++;
      }
      return sent.reduce((n, f) => n + f.length, 0) >= wrapped.length;
    }, 5000);
    const frames = docFrames(ws);
    expect(frames.length).toBeGreaterThan(1);
    for (const f of frames) expect(f.length).toBeLessThanOrEqual(limit);
    await waitFor(() => socket.readyForSnapshot(), 2000);

    const received: Uint8Array[] = [];
    await makeSocket({ events: { onDocUpdate: (_s, pt) => received.push(pt) } });
    const rws = latest();
    rws.open();
    rws.deliver(joinAck());
    // What the server relays: the frame with the sender's peer id spliced in.
    for (const f of frames) rws.deliver(concatBytes(f.slice(0, HEADER_LEN), PEER, f.slice(HEADER_LEN)));
    await waitFor(() => received.length === 1);
    expect(received[0]).toEqual(wrapped);
  });

  it("marks its parts so a client that predates them drops a part rather than applying it", () => {
    const wrapped = wrapWithLengthAndPad(new Uint8Array(5000).fill(3));
    const parts = splitIntoParts(wrapped, 1500, new Uint8Array(8).fill(1));
    expect(parts.length).toBeGreaterThan(1);
    for (const p of parts) {
      expect(new DataView(p.buffer).getUint32(0)).toBe(PART_MARKER);
      expect(() => unwrapLengthPrefix(p)).toThrow();
      expect(p.length % 256).toBe(0);
    }
    expect(concatBytes(...parts.map((p) => readPart(p)!.data))).toEqual(wrapped);
  });
});

describe("the server explaining itself", () => {
  it("passes on a restart the server announces", async () => {
    const seen: number[] = [];
    await makeSocket({ events: { onRestartNotice: (s) => seen.push(s) } });
    const ws = latest();
    ws.open();
    ws.deliver(joinAck());
    ws.deliver(buildJsonFrame(FT.RESTART_NOTICE, ROOM, 0, { in_secs: 60 }));
    await waitFor(() => seen.length === 1);
    expect(seen).toEqual([60]);
  });

  it("says why a connection was refused, and keeps trying", async () => {
    const refused: number[] = [];
    await makeSocket({ events: { onRefused: (c) => refused.push(c) } });
    const first = latest();
    first.open();
    first.close(4007);
    expect(refused).toEqual([4007]);
    await waitFor(() => FakeWebSocket.all.length === 2);
  });
});

/// What the server relays to a connection that asked for indexes: the sender
/// envelope, then the entry's log index, then the body.
function relayIndexed(frame: Uint8Array, index: number): Uint8Array {
  const i = new Uint8Array(8);
  new DataView(i.buffer).setBigUint64(0, BigInt(index), false);
  return concatBytes(frame.slice(0, HEADER_LEN), PEER, i, frame.slice(HEADER_LEN));
}

describe("a connection nobody is typing into", () => {
  it("is pinged, and abandoned when the ping goes unanswered, without waiting for a keystroke", async () => {
    await makeSocket({ heartbeatMs: 60, ackTimeoutMs: 150 });
    const first = latest();
    first.open();
    first.deliver(joinAck({ heartbeat: true }));
    first.dead = true;
    await waitFor(() => FakeWebSocket.all.length === 2, 2000);
  });

  it("stays up while its pings are answered, and hands on the roster each answer carries", async () => {
    const rosters: unknown[] = [];
    await makeSocket({ heartbeatMs: 40, ackTimeoutMs: 150, events: { onRoster: (r) => rosters.push(r) } });
    const ws = latest();
    ws.open();
    ws.deliver(joinAck({ heartbeat: true }));
    const roster = [{ peer_id: toB64(PEER), joined_at_seq: 1 }];
    let answered = 0;
    const end = Date.now() + 600;
    while (Date.now() < end) {
      const pings = ws.sent.filter((f) => f[3] === FT.PING).length;
      while (answered < pings) {
        ws.deliver(buildJsonFrame(FT.PONG, ROOM, 0, { roster }));
        answered++;
      }
      await sleep(10);
    }
    expect(answered).toBeGreaterThan(3);
    expect(FakeWebSocket.all).toHaveLength(1);
    expect(rosters[0]).toEqual(roster);
  });

  it("is never pinged by a server that did not offer it", async () => {
    await makeSocket({ heartbeatMs: 20, ackTimeoutMs: 100 });
    const ws = latest();
    ws.open();
    ws.deliver(joinAck());
    await sleep(200);
    expect(ws.sent.filter((f) => f[3] === FT.PING)).toHaveLength(0);
    expect(FakeWebSocket.all).toHaveLength(1);
  });
});

describe("the log index of every entry", () => {
  it("is reported once the entry is in the document, and a split update's only once it is whole", async () => {
    const limit = 16 * 1024;
    const { socket: sender } = await makeSocket();
    const sws = latest();
    sws.open();
    sws.deliver(joinAck({ limits: { ...LIMITS, max_frame_bytes: limit } }));
    await sender.sendUpdate(wrapWithLengthAndPad(new Uint8Array(40 * 1024).fill(4)));
    let acked = 0;
    await waitFor(() => {
      const sent = docFrames(sws);
      while (acked < sent.length) {
        sws.deliver(docAck());
        acked++;
      }
      return sender.readyForSnapshot();
    });
    const parts = docFrames(sws);
    expect(parts.length).toBeGreaterThan(2);

    const taken: number[] = [];
    const applied: Uint8Array[] = [];
    await makeSocket({
      events: { onEntriesTaken: (i) => taken.push(...i), onDocUpdate: (_s, pt) => applied.push(pt) },
    });
    const rws = latest();
    rws.open();
    rws.deliver(joinAck({ indexed: true }));
    // The last part is held back: the update is not in the document yet.
    parts.slice(0, -1).forEach((f, i) => rws.deliver(relayIndexed(f, 10 + i)));
    await sleep(80);
    expect(taken).toEqual([]);
    rws.deliver(relayIndexed(parts[parts.length - 1], 10 + parts.length - 1));
    await waitFor(() => applied.length === 1);
    expect([...taken].sort((a, b) => a - b)).toEqual(parts.map((_, i) => 10 + i));

    // A part sent again after the update was whole — its first ack was lost —
    // is taken at once rather than starting an assembly that never ends.
    rws.deliver(relayIndexed(parts[0], 50));
    await waitFor(() => taken.includes(50));
    expect(applied).toHaveLength(1);

    // An entry nobody can read holds nothing back either.
    const garbage = concatBytes(parts[0].slice(0, HEADER_LEN), new Uint8Array(64).fill(1));
    rws.deliver(relayIndexed(garbage, 51));
    await waitFor(() => taken.includes(51));
  });

  it("of our own update is the one its ack names", async () => {
    const taken: number[] = [];
    const { socket } = await makeSocket({ events: { onEntriesTaken: (i) => taken.push(...i) } });
    const ws = latest();
    ws.open();
    ws.deliver(joinAck({ indexed: true }));
    await socket.sendUpdate(text("mine"));
    await waitFor(() => docFrames(ws).length === 1);
    ws.deliver(buildJsonFrame(FT.DOC_ACK, ROOM, 0, { ok: true, index: 7 }));
    await waitFor(() => taken.length === 1);
    expect(taken).toEqual([7]);
  });
});

describe("a restart that hands the room over", () => {
  it("passes on the ticket, and joins again once the room is back although the refusal stopped retries", async () => {
    const tickets: string[] = [];
    const errors: number[] = [];
    const { socket, key } = await makeSocket({
      events: { onRestartTicket: (t) => tickets.push(t), onError: (c) => errors.push(c) },
    });
    const first = latest();
    first.open();
    first.deliver(joinAck());
    first.deliver(buildJsonFrame(FT.RESTART_TICKET, ROOM, 0, { ticket: "abc.def" }));
    first.close(1012);
    expect(tickets).toEqual(["abc.def"]);

    // Typed while the server was away: queued, and kept through the refusal.
    const typed = text("typed across the restart");
    await socket.sendUpdate(typed.slice());
    await waitFor(() => FakeWebSocket.all.length === 2);
    const refused = latest();
    refused.open();
    refused.deliver(buildJsonFrame(FT.ERROR, ROOM, 0, { code: 4001 }));
    await waitFor(() => errors.includes(4001));
    await sleep(600);
    expect(FakeWebSocket.all).toHaveLength(2);

    socket.resume();
    expect(FakeWebSocket.all).toHaveLength(3);
    const back = latest();
    back.open();
    back.deliver(joinAck());
    await waitFor(() => docFrames(back).length === 1);
    expect(await readAsPeer(docFrames(back)[0], key)).toEqual(typed);
  });

  it("forgets the ticket once a join succeeds, so it cannot bring the room back a second time", async () => {
    const { socket } = await makeSocket();
    const first = latest();
    first.open();
    first.deliver(joinAck());
    first.deliver(buildJsonFrame(FT.RESTART_TICKET, ROOM, 0, { ticket: "abc.def" }));
    first.close(1012);
    expect(socket.heldRestartTicket()?.ticket).toBe("abc.def");

    await waitFor(() => FakeWebSocket.all.length === 2);
    const back = latest();
    back.open();
    back.deliver(joinAck());
    await waitFor(() => socket.heldRestartTicket() === null);
  });

  it("can replace the whole backlog with one update, for a room whose log is new", async () => {
    const { socket, key } = await makeSocket();
    const ws = latest();
    ws.open();
    await socket.sendUpdate(text("one"));
    await socket.sendUpdate(text("two"));
    const whole = text("everything");
    socket.replaceBacklogWith(whole.slice());
    ws.deliver(joinAck());
    await waitFor(() => docFrames(ws).length === 1);
    await sleep(50);
    expect(docFrames(ws)).toHaveLength(1);
    expect(await readAsPeer(docFrames(ws)[0], key)).toEqual(whole);
  });
});

describe("epochs (amendment J)", () => {
  it("sends its key-agreement key and signature in JOIN", async () => {
    await makeSocket();
    const ws = latest();
    ws.open();
    await sleep(0);
    const body = JSON.parse(new TextDecoder().decode(ws.sent[0].slice(HEADER_LEN)));
    expect(body.kx_pubkey).toBe(toB64(new Uint8Array(65).fill(4)));
    expect(body.kx_sig).toBe(toB64(new Uint8Array(64).fill(6)));
  });

  it("holds document frames while the room is at an epoch it has no key for", async () => {
    const { socket, keyring } = await makeSocket();
    const ws = latest();
    ws.open();
    ws.deliver(joinAck({ epoch: 1 }));
    await sleep(0);
    expect(socket.isAwaitingKeys).toBe(true);
    await socket.sendUpdate(text("held"));
    await sleep(20);
    expect(docFrames(ws)).toHaveLength(0);
    await stepRing(keyring);
    socket.adoptEpoch(1);
    await sleep(20);
    const frames = docFrames(ws);
    expect(frames).toHaveLength(1);
    expect(new DataView(frames[0].buffer, frames[0].byteOffset).getUint32(20, false)).toBe(1);
    expect(await readAsPeer(frames[0], keyring.current.contentKey)).toEqual(text("held"));
  });

  it("reads a stored entry under the epoch it was written in", async () => {
    const onDocUpdate = vi.fn();
    const { socket, key, keyring } = await makeSocket({ events: { onDocUpdate } });
    const ws = latest();
    ws.open();
    ws.deliver(joinAck());
    await sleep(0);
    await stepRing(keyring);
    socket.adoptEpoch(1);
    ws.deliver(await incoming(FT.DOC_UPDATE, 0, key, text("from epoch zero")));
    await sleep(20);
    expect(onDocUpdate).toHaveBeenCalledTimes(1);
  });

  it("drops presence from before the overlap, with the stale warning", async () => {
    const onAwareness = vi.fn();
    const onEpochStale = vi.fn();
    const { socket, key, keyring } = await makeSocket({ epochOverlapMs: 0, events: { onAwareness, onEpochStale } });
    const ws = latest();
    ws.open();
    ws.deliver(joinAck());
    await sleep(0);
    await stepRing(keyring);
    socket.adoptEpoch(1);
    await sleep(5);
    ws.deliver(await incoming(FT.AWARENESS, 0, key, text("{}")));
    await sleep(20);
    expect(onAwareness).not.toHaveBeenCalled();
    expect(onEpochStale).toHaveBeenCalledWith(0);
  });

  it("keeps presence from the epoch just left inside the overlap", async () => {
    const onAwareness = vi.fn();
    const { socket, key, keyring } = await makeSocket({ epochOverlapMs: 60_000, events: { onAwareness } });
    const ws = latest();
    ws.open();
    ws.deliver(joinAck());
    await sleep(0);
    await stepRing(keyring);
    socket.adoptEpoch(1);
    ws.deliver(await incoming(FT.AWARENESS, 0, key, text("{}")));
    await sleep(20);
    expect(onAwareness).toHaveBeenCalledTimes(1);
  });

  it("drops a frame from an epoch it does not hold, without a warning", async () => {
    const onAwareness = vi.fn();
    const onEpochStale = vi.fn();
    const { key } = await makeSocket({ events: { onAwareness, onEpochStale } });
    const ws = latest();
    ws.open();
    ws.deliver(joinAck());
    await sleep(0);
    ws.deliver(await incoming(FT.AWARENESS, 5, key, text("{}")));
    await sleep(20);
    expect(onAwareness).not.toHaveBeenCalled();
    expect(onEpochStale).not.toHaveBeenCalled();
  });

  it("reconnects when the server refuses an update for its epoch, and resends it", async () => {
    const { socket } = await makeSocket();
    const ws = latest();
    ws.open();
    ws.deliver(joinAck());
    await sleep(0);
    await socket.sendUpdate(text("late"));
    await sleep(20);
    const before = FakeWebSocket.all.length;
    ws.deliver(buildJsonFrame(FT.DOC_ACK, ROOM, 0, { ok: false, epoch: 1 }));
    await waitFor(() => FakeWebSocket.all.length > before, 2000);
    const ws2 = latest();
    ws2.open();
    ws2.deliver(joinAck());
    await waitFor(() => docFrames(ws2).length === 1);
  });

  it("resends under the epoch it adopted, as a peer can read it, after a reconnect", async () => {
    const { socket, keyring } = await makeSocket();
    const ws = latest();
    ws.open();
    ws.deliver(joinAck());
    await sleep(0);
    await stepRing(keyring);
    socket.adoptEpoch(1);
    await socket.sendUpdate(text("after rotation"));
    await sleep(20);
    expect(docFrames(ws)).toHaveLength(1);
    const before = FakeWebSocket.all.length;
    ws.close();
    await waitFor(() => FakeWebSocket.all.length > before, 2000);
    const ws2 = latest();
    ws2.open();
    ws2.deliver(joinAck({ epoch: 1 }));
    await waitFor(() => docFrames(ws2).length === 1);
    const frame = docFrames(ws2)[0];
    expect(new DataView(frame.buffer, frame.byteOffset).getUint32(20, false)).toBe(1);
    expect(await readAsPeer(frame, keyring.current.contentKey)).toEqual(text("after rotation"));
  });

  it("labels a snapshot with the epoch it was sealed under even if the epoch changes while it seals", async () => {
    const { socket, key, keyring } = await makeSocket();
    const ws = latest();
    ws.open();
    ws.deliver(joinAck());
    await sleep(0);
    await stepRing(keyring);
    const sealing = socket.sendSnapshot(text("state"), 5n);
    socket.adoptEpoch(1);
    await sealing;
    const frame = ws.sent.filter((f) => f[3] === FT.SNAPSHOT)[0];
    const epoch = new DataView(frame.buffer, frame.byteOffset).getUint32(20, false);
    const opener = epoch === 0 ? key : keyring.current.contentKey;
    const header = frame.slice(0, HEADER_LEN);
    const envelope = frame.slice(HEADER_LEN + 8);
    expect(await decryptEnvelope(opener, header, PEER, envelope, 5n)).toEqual(text("state"));
    expect(header.slice(24, 28)).toEqual(envelope.slice(0, 4));
  });

  it("does not warn for a live frame from an epoch ahead of the one it sends under", async () => {
    const onAwareness = vi.fn();
    const onEpochStale = vi.fn();
    const { key, keyring } = await makeSocket({ epochOverlapMs: 0, events: { onAwareness, onEpochStale } });
    const ws = latest();
    ws.open();
    ws.deliver(joinAck());
    await sleep(0);
    await stepRing(keyring);
    ws.deliver(await incoming(FT.AWARENESS, 1, keyring.current.contentKey, text("{}")));
    await sleep(20);
    expect(onEpochStale).not.toHaveBeenCalled();
    expect(key).toBeTruthy();
  });

  it("holds sends when the keyring advanced but the socket has not adopted the epoch", async () => {
    const { socket, keyring } = await makeSocket();
    const ws = latest();
    ws.open();
    await stepRing(keyring);
    ws.deliver(joinAck({ epoch: 1 }));
    await sleep(0);
    expect(socket.isAwaitingKeys).toBe(true);
    await socket.sendUpdate(text("must wait"));
    await sleep(20);
    expect(docFrames(ws)).toHaveLength(0);
    socket.adoptEpoch(1);
    await waitFor(() => docFrames(ws).length === 1);
  });

  it("labels a cipher adopted before the join with the public key, so receivers refuse anything sent early", async () => {
    const { socket, keyring } = await makeSocket();
    const ws = latest();
    ws.open();
    await stepRing(keyring);
    socket.adoptEpoch(1);
    const ownKey = new Uint8Array(32).fill(5);
    // Sealed under the epoch-1 key with the cipher's own sender label.
    const header = encodeHeader({ version: PROTOCOL_VERSION, frameType: FT.AWARENESS, roomId: ROOM, epoch: 1, nonceSess: socket.sessionId, flags: 0 });
    const probe = (socket as unknown as { cipher: FrameCipher }).cipher;
    const env = await probe.encrypt(header, text("x"));
    await expect(decryptEnvelope(keyring.current.contentKey, header, PEER, env)).rejects.toThrow();
    await expect(decryptEnvelope(keyring.current.contentKey, header, ownKey, env)).resolves.toBeDefined();
  });

  it("reconnects on ERROR 4006", async () => {
    await makeSocket();
    const ws = latest();
    ws.open();
    ws.deliver(joinAck());
    await sleep(0);
    const before = FakeWebSocket.all.length;
    ws.deliver(buildJsonFrame(FT.ERROR, ROOM, 0, { code: 4006 }));
    await sleep(700);
    expect(FakeWebSocket.all.length).toBeGreaterThan(before);
  });

  it("passes EPOCH_KEY frames through unopened", async () => {
    const onEpochKey = vi.fn();
    await makeSocket({ events: { onEpochKey } });
    const ws = latest();
    ws.open();
    ws.deliver(joinAck());
    await sleep(0);
    const header = encodeHeader({ version: PROTOCOL_VERSION, frameType: FT.EPOCH_KEY, roomId: ROOM, epoch: 1, nonceSess: new Uint8Array(4), flags: 0 });
    const body = new Uint8Array([1, 2, 3, 4]);
    ws.deliver(concatBytes(header, OTHER, body));
    await sleep(10);
    expect(onEpochKey).toHaveBeenCalledTimes(1);
    const [h, e, sender, b] = onEpochKey.mock.calls[0];
    expect(h).toEqual(header);
    expect(e).toBe(1);
    expect(sender).toEqual(OTHER);
    expect(b).toEqual(body);
  });

  it("carries key-agreement keys from PEER_JOIN", async () => {
    const onPeerJoin = vi.fn();
    await makeSocket({ events: { onPeerJoin } });
    const ws = latest();
    ws.open();
    ws.deliver(joinAck());
    await sleep(0);
    const kx = new Uint8Array(65).fill(4);
    const sig = new Uint8Array(64).fill(3);
    ws.deliver(buildJsonFrame(FT.PEER_JOIN, ROOM, 0, { peer_id: toB64(OTHER), pubkey: toB64(new Uint8Array(32)), joined_at_seq: 2, kx_pubkey: toB64(kx), kx_sig: toB64(sig) }));
    await sleep(0);
    expect(onPeerJoin.mock.calls[0][0].kxPub).toEqual(kx);
    expect(onPeerJoin.mock.calls[0][0].kxSig).toEqual(sig);
  });
});
