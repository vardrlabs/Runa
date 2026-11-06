import { FrameCipher, decryptEnvelope } from "../crypto/aead";
import type { Identity } from "../crypto/identity";
import type { Keyring } from "../epoch/keyring";
import { EPOCH_OVERLAP_MS } from "../epoch/rotation";
import {
  concatBytes,
  encodeHeader,
  FT,
  HEADER_LEN,
  PROTOCOL_VERSION,
  buildFrame,
  buildJsonFrame,
  parseFrame,
  stripEnvelope,
  type EnvelopedFrame,
  type FrameHeader,
} from "./frame";

export interface RosterEntry {
  peerId: Uint8Array;
  pubkey?: Uint8Array;
  joinedAtSeq: number;
  /// The peer's ECDH P-256 key and its signature over it (amendment J), as
  /// the server relayed them. Unverified here; the coordinator checks them.
  kxPub?: Uint8Array;
  kxSig?: Uint8Array;
}

export type WireRoster = {
  peer_id: string;
  pubkey?: string;
  joined_at_seq: number;
  kx_pubkey?: string | null;
  kx_sig?: string | null;
}[];

export interface JoinAck {
  peer_id: string;
  epoch: number;
  log_len: number;
  base_index: number;
  has_snapshot: boolean;
  ttl: { kind: string; secs: number };
  /// How long the room has been alive. For an absolute TTL `ttl.secs` is the
  /// time remaining, so this is what makes the original duration recoverable.
  /// Optional because a server that predates it simply will not send one.
  elapsed_secs?: number;
  ceiling_optout: boolean;
  kdf: { alg: string; m_kib: number; t: number; p: number; salt: string };
  config_blob?: string;
  roster: WireRoster;
  /// True when the server acknowledges every DOC_UPDATE it stores. A server
  /// that predates acks omits it, and its updates are sent once and trusted.
  acks?: boolean;
  /// What this connection is held to, so a resend can be paced under it.
  limits?: { max_frame_bytes: number; frames_per_sec: number; bytes_per_sec: number };
  /// Relayed updates carry their log index (amendment H).
  indexed?: boolean;
  /// PING is answered with PONG (amendment G).
  heartbeat?: boolean;
  /// Which log the room has. It changes only when the room was brought back
  /// after a restart with a new, empty one (amendment I).
  log_id?: string;
  /// The epoch of the room's current root (amendment J). Absent from a
  /// server that predates it, which means 0.
  root_epoch?: number;
}

export interface SocketEvents {
  onJoinAck(ack: JoinAck): void;
  onDocUpdate(sender: Uint8Array, envelope: Uint8Array): void;
  onSnapshot(sender: Uint8Array, covers: bigint, envelope: Uint8Array): void;
  onAwareness(sender: Uint8Array, plaintext: Uint8Array): void;
  onShredFrame(frameType: number, sender: Uint8Array, plaintext: Uint8Array): void;
  onPeerJoin(entry: RosterEntry): void;
  onPeerLeave(peerId: Uint8Array, reason?: number): void;
  onPurge(reason: string): void;
  onTtlExtended(addSecs: number, effectiveSecs: number, addedBy: string): void;
  onError(code: number): void;
  /// The document has outgrown a single snapshot frame, so its edit history
  /// can no longer be compacted.
  onSnapshotTooLarge(bytes: number): void;
  onEpochStale(epoch: number): void;
  /// An EPOCH_KEY, unopened: the coordinator verifies and applies it.
  onEpochKey?(header: Uint8Array, headerEpoch: number, sender: Uint8Array, body: Uint8Array): void;
  onDisconnected(): void;
  /// This many of our document frames are now in the room log — or, against
  /// a server without acks, have been sent. The snapshot index is estimated
  /// from it.
  onUpdatesStored?(count: number): void;
  /// These log entries are now in the document, or can never be: applied,
  /// ours and stored, or unreadable. Reported only against a server that
  /// sends indexes.
  onEntriesTaken?(indexes: number[]): void;
  /// The server stops in this many seconds. `handover` says whether it will
  /// hand out tickets that bring the room back on the next process.
  onRestartNotice?(inSecs: number, handover: boolean): void;
  /// The ticket that brings this room back after the restart (amendment I).
  onRestartTicket?(ticket: string): void;
  /// The server's current roster, sent with every PONG.
  onRoster?(roster: WireRoster): void;
  /// The server turned this connection away: 4007 when this address holds as
  /// many connections as one address may, 4008 when the server is full.
  onRefused?(code: number): void;
}

export interface SocketOptions {
  url: string;
  roomId: Uint8Array;
  authKey: Uint8Array;
  identity: Identity;
  /// Every epoch key this member holds (amendment J). The socket encrypts
  /// under the epoch it last adopted and reads each frame under the key of
  /// the epoch in that frame's header.
  keyring: Keyring;
  /// This session's key-agreement key and the session's signature over it,
  /// sent in JOIN.
  kx: { publicKeyRaw: Uint8Array; sig: Uint8Array };
  /// How long frames from the epoch just left are still read. Tests shorten it.
  epochOverlapMs?: number;
  events: SocketEvents;
  insecureAllowed?: boolean;
  maxBackoffMs?: number;
  /// Merge queued updates before a backlog is resent. Takes and returns
  /// wrapped payloads; without it every queued update goes out on its own.
  compactUpdates?: (wrapped: Uint8Array[]) => Uint8Array[];
  /// How long a sent update may go unacknowledged before the connection it
  /// went out on is treated as dead. Also how long a PING may go unanswered.
  ackTimeoutMs?: number;
  /// How often a quiet connection is asked to prove it is alive.
  heartbeatMs?: number;
}

const textDecoder = new TextDecoder();

interface Limits {
  maxFrameBytes: number;
  framesPerSec: number;
  bytesPerSec: number;
}

/// The server's defaults. Used until a JOIN_ACK says otherwise, and against a
/// server that predates advertising its limits.
const DEFAULT_LIMITS: Limits = {
  maxFrameBytes: 1024 * 1024,
  framesPerSec: 100,
  bytesPerSec: 1024 * 1024,
};

/// What encryption adds to a DOC_UPDATE plaintext on the wire: the header,
/// the nonce session and counter, and the GCM tag.
const DOC_FRAME_OVERHEAD = HEADER_LEN + 4 + 8 + 16;

/// An update unacknowledged for this long means the connection it went out on
/// has died without the browser noticing. A browser keeps such a socket OPEN
/// until TCP gives up, which takes minutes, and everything sent into it in
/// that time is lost.
const ACK_TIMEOUT_MS = 10_000;

/// How often a connection is pinged. Acks only cover a connection something
/// is being sent on, so one that died while nobody typed was noticed at the
/// next keystroke — and until then the page said it was connected while
/// everyone else's edits went nowhere.
const HEARTBEAT_MS = 15_000;

/// Split updates this client has finished assembling, remembered so that a
/// part arriving again afterwards — a resend of one whose ack was lost — is
/// recognised instead of starting an assembly that can never complete.
const COMPLETED_PARTS_REMEMBERED = 256;

/// Updates queued while disconnected are merged once there are this many,
/// rather than holding one entry per keystroke for the whole outage.
const COMPACT_WHILE_OFFLINE_AT = 256;

const REASSEMBLY_MAX_BYTES = 64 * 1024 * 1024;
const REASSEMBLY_MAX_GROUPS = 32;
/// A message whose parts stop arriving is abandoned after this long. Parts
/// can be orphaned legitimately — a sender whose connection died mid-message,
/// or a snapshot that compacted away the first parts of one already applied.
const REASSEMBLY_STALE_MS = 120_000;

/// A DOC_UPDATE too large for one frame travels as parts. Each part's
/// plaintext opens with a length no real payload can have, so a client that
/// predates parts reads one as a corrupt update and drops it rather than
/// applying half of something:
///
///   u32 0xFFFFFFFF ‖ message id (8 B) ‖ index u16 ‖ total u16 ‖ data length u32 ‖ data ‖ zero pad
///
/// The id is random and stays with the message across reconnects, so a part
/// that is sent twice is recognised as the same part.
export const PART_MARKER = 0xffffffff;
export const PART_HEADER_LEN = 20;

export function splitIntoParts(wrapped: Uint8Array, maxData: number, id: Uint8Array): Uint8Array[] {
  if (id.length !== 8) throw new Error("part id must be 8 bytes");
  const size = Math.max(1, Math.floor(maxData));
  const total = Math.ceil(wrapped.length / size);
  if (total < 2) throw new Error("an update that fits in one frame is not split");
  if (total > 0xffff) throw new Error("update too large to split");
  const parts: Uint8Array[] = [];
  for (let i = 0; i < total; i++) {
    const data = wrapped.subarray(i * size, Math.min(wrapped.length, (i + 1) * size));
    const unpadded = PART_HEADER_LEN + data.length;
    const rem = unpadded % 256;
    const out = new Uint8Array(unpadded + (rem === 0 ? 0 : 256 - rem));
    const view = new DataView(out.buffer);
    view.setUint32(0, PART_MARKER, false);
    out.set(id, 4);
    view.setUint16(12, i, false);
    view.setUint16(14, total, false);
    view.setUint32(16, data.length, false);
    out.set(data, PART_HEADER_LEN);
    parts.push(out);
  }
  return parts;
}

export interface Part {
  id: string;
  index: number;
  total: number;
  data: Uint8Array;
}

function isPart(plaintext: Uint8Array): boolean {
  return (
    plaintext.length >= 4 &&
    new DataView(plaintext.buffer, plaintext.byteOffset, plaintext.byteLength).getUint32(0, false) ===
      PART_MARKER
  );
}

/// Null for anything that is not a well-formed part.
export function readPart(plaintext: Uint8Array): Part | null {
  if (plaintext.length < PART_HEADER_LEN || !isPart(plaintext)) return null;
  const view = new DataView(plaintext.buffer, plaintext.byteOffset, plaintext.byteLength);
  const index = view.getUint16(12, false);
  const total = view.getUint16(14, false);
  const len = view.getUint32(16, false);
  if (total < 2 || index >= total || PART_HEADER_LEN + len > plaintext.length) return null;
  let id = "";
  for (let i = 4; i < 12; i++) id += plaintext[i].toString(16).padStart(2, "0");
  return { id, index, total, data: plaintext.slice(PART_HEADER_LEN, PART_HEADER_LEN + len) };
}

/// One update this client has written, held until the room has stored it.
interface Pending {
  wrapped: Uint8Array;
  /// Built the first time the update is found too large for one frame.
  parts: Uint8Array[] | null;
  /// Frames the server has confirmed storing.
  acked: number;
  /// Frames sent on the current connection, acknowledged or not.
  sent: number;
  /// The log refused it. Resending cannot help.
  refused: boolean;
}

interface Group {
  total: number;
  parts: (Uint8Array | undefined)[];
  have: number;
  bytes: number;
  at: number;
  /// Log indexes of the entries that carried these parts, reported once the
  /// whole update has been applied.
  indexes: number[];
}

function limitsFrom(raw: JoinAck["limits"]): Limits {
  const pick = (v: unknown, fallback: number, lo: number, hi: number) =>
    typeof v === "number" && Number.isFinite(v) ? Math.min(hi, Math.max(lo, Math.floor(v))) : fallback;
  return {
    maxFrameBytes: pick(raw?.max_frame_bytes, DEFAULT_LIMITS.maxFrameBytes, 4096, 8 * 1024 * 1024),
    framesPerSec: pick(raw?.frames_per_sec, DEFAULT_LIMITS.framesPerSec, 2, 1_000_000),
    bytesPerSec: pick(raw?.bytes_per_sec, DEFAULT_LIMITS.bytesPerSec, 4096, 2 ** 31),
  };
}

export class RunaSocket {
  private ws: WebSocket | null = null;
  private cipher: FrameCipher;
  private backoffMs = 250;
  private maxBackoffMs: number;
  private closedByUs = false;
  private epoch = 0;
  /// The room's epoch, from JOIN_ACK and from every step adopted since.
  private roomEpoch = 0;
  /// When this socket started sending under its current epoch.
  private switchedAt = 0;
  /// The room is at an epoch this member holds no key for, or the server has
  /// fallen behind this member. Nothing encrypted is sent until a step or a
  /// handover settles it (amendment J).
  private awaitingKeys = false;
  private peerId: Uint8Array = new Uint8Array(16);
  private joined = false;
  private reconnectTimer: ReturnType<typeof setTimeout> | null = null;
  readonly events: SocketEvents;

  /// Bumped whenever a connection starts or is lost, so work that awaited
  /// across the change can tell it is stale.
  private generation = 0;
  private acksEnabled = false;
  private limits: Limits = DEFAULT_LIMITS;
  private outbox: Pending[] = [];
  /// One entry per frame sent on the current connection and not yet
  /// acknowledged, in send order. The server acknowledges in the order it
  /// reads, so the head is always the frame an ack refers to.
  private inflight: { item: Pending; sentAt: number }[] = [];
  private pumping = false;
  private bucket = { frames: 0, bytes: 0, at: 0 };
  private livenessTimer: ReturnType<typeof setInterval> | null = null;
  private reassembly = new Map<string, Group>();
  private reassemblyBytes = 0;
  private completedParts: string[] = [];
  private completedPartsSet = new Set<string>();
  private indexed = false;
  private heartbeat = false;
  private pingSentAt: number | null = null;
  private lastPingAt = 0;
  /// The ticket the last process handed over as it stopped, until a join
  /// succeeds. Kept past that, a room shredded after coming back could be
  /// brought back again by a second restart inside the ticket's lifetime.
  private restartTicket: { ticket: string; at: number } | null = null;

  constructor(private opts: SocketOptions) {
    this.maxBackoffMs = opts.maxBackoffMs ?? 15_000;
    this.cipher = new FrameCipher(opts.keyring.current.contentKey, opts.identity.publicKeyRaw);
    this.epoch = opts.keyring.current.epoch;
    this.events = opts.events;
  }

  get sessionId(): Uint8Array {
    return this.cipher.sess;
  }

  get currentEpoch(): number {
    return this.epoch;
  }

  get serverEpoch(): number {
    return this.roomEpoch;
  }

  get isAwaitingKeys(): boolean {
    return this.awaitingKeys;
  }

  /// Start encrypting under `epoch`, which the keyring now holds as current.
  /// A new key gets a new cipher, so its nonce stream starts fresh; a cipher
  /// is never rebuilt for a key it has already used, which would repeat nonces.
  adoptEpoch(epoch: number): void {
    const keys = this.opts.keyring.current;
    if (keys.epoch !== epoch || epoch === this.epoch) return;
    this.cipher = new FrameCipher(keys.contentKey, this.peerId);
    this.epoch = epoch;
    this.switchedAt = performance.now();
    if (epoch >= this.roomEpoch) {
      this.roomEpoch = epoch;
      this.awaitingKeys = false;
    }
    void this.pump();
  }

  epochKeyHeader(epoch: number): Uint8Array {
    return encodeHeader({
      version: PROTOCOL_VERSION,
      frameType: FT.EPOCH_KEY,
      roomId: this.opts.roomId,
      epoch,
      nonceSess: new Uint8Array(4),
      flags: 0,
    });
  }

  /// Returns whether it went out.
  sendEpochKey(header: Uint8Array, body: Uint8Array): boolean {
    if (!this.joined) return false;
    return this.rawSend(concatBytes(header, body));
  }

  /// Drop this connection and join again, to be handed the room's keys as a
  /// newcomer. For a member that saw the room move to an epoch it cannot follow.
  reconnectNow(): void {
    this.abandonConnection();
  }

  private isStale(frameEpoch: number): boolean {
    if (frameEpoch === this.epoch) return false;
    const overlap = this.opts.epochOverlapMs ?? EPOCH_OVERLAP_MS;
    return !(frameEpoch === this.epoch - 1 && performance.now() - this.switchedAt < overlap);
  }

  async connect(): Promise<void> {
    if (this.closedByUs) return;
    const url = this.opts.url;
    if (url.startsWith("ws://") && !this.opts.insecureAllowed) {
      throw new Error("insecure ws:// refused; RUNA_ALLOW_INSECURE=1 required");
    }
    const ws = new WebSocket(url);
    this.ws = ws;
    ws.binaryType = "arraybuffer";
    this.joined = false;
    this.generation += 1;
    ws.onopen = () => {
      void this.sendJoin();
    };
    ws.onmessage = (ev) => {
      void this.handleMessage(new Uint8Array(ev.data as ArrayBuffer));
    };
    ws.onclose = (ev) => {
      if (this.ws === ws) this.connectionLost();
      const code = (ev as CloseEvent | undefined)?.code;
      if (code === 4007 || code === 4008) this.events.onRefused?.(code);
      this.events.onDisconnected();
      if (!this.closedByUs) this.scheduleReconnect();
    };
    ws.onerror = () => {};
  }

  private scheduleReconnect(): void {
    if (this.closedByUs || this.reconnectTimer) return;
    const jitterBytes = new Uint32Array(1);
    crypto.getRandomValues(jitterBytes);
    // `% 0` is NaN, and setTimeout(NaN) fires immediately — a hot reconnect
    // loop for any backoff under ~4 ms.
    const spread = Math.max(1, Math.floor(this.backoffMs * 0.3));
    const jitter = jitterBytes[0] % spread;
    this.reconnectTimer = setTimeout(() => {
      this.reconnectTimer = null;
      this.backoffMs = Math.min(this.backoffMs * 2, this.maxBackoffMs);
      this.cipher = new FrameCipher(this.opts.keyring.current.contentKey, this.opts.identity.publicKeyRaw);
      this.epoch = this.opts.keyring.current.epoch;
      void this.connect().catch(() => this.scheduleReconnect());
    }, this.backoffMs + jitter);
  }

  /// Everything a connection held that dies with it. Queued updates survive:
  /// they are resent on the next connection.
  private connectionLost(): void {
    this.joined = false;
    this.generation += 1;
    this.inflight = [];
    this.stopLiveness();
  }

  /// Give up on a connection that has stopped acknowledging, without waiting
  /// for the browser to agree that it is dead. Closing it asks for a closing
  /// handshake the other end will never answer, and browsers wait up to a
  /// minute for that before reporting the close, so its handlers are detached
  /// and the reconnect starts now.
  private abandonConnection(): void {
    const ws = this.ws;
    if (!ws) return;
    this.ws = null;
    ws.onopen = null;
    ws.onmessage = null;
    ws.onclose = null;
    ws.onerror = null;
    try {
      ws.close();
    } catch {
      /* already closing */
    }
    this.connectionLost();
    this.events.onDisconnected();
    this.scheduleReconnect();
  }

  /// Forget everything queued or half-received. For when the room is gone or
  /// being wiped: there is nowhere left to send it, and it is document text.
  private discardQueues(): void {
    for (const item of this.outbox) {
      item.wrapped.fill(0);
      for (const p of item.parts ?? []) p.fill(0);
    }
    this.outbox = [];
    this.inflight = [];
    for (const g of this.reassembly.values()) for (const p of g.parts) p?.fill(0);
    this.reassembly.clear();
    this.reassemblyBytes = 0;
    this.stopLiveness();
  }

  /// The restart ticket held since the last process stopped, if no join has
  /// succeeded since.
  heldRestartTicket(): { ticket: string; at: number } | null {
    return this.restartTicket;
  }

  dropRestartTicket(): void {
    this.restartTicket = null;
  }

  /// Start again after the room was brought back on a new process: the join
  /// that found it missing stopped the retries, and nothing queued was
  /// discarded (amendment I).
  resume(): void {
    const old = this.ws;
    if (old) {
      // The refused connection, closed or about to be. Its handlers must not
      // fire into the new one's state.
      this.ws = null;
      old.onopen = null;
      old.onmessage = null;
      old.onclose = null;
      old.onerror = null;
      try {
        old.close();
      } catch {
        /* already closed */
      }
    }
    this.closedByUs = false;
    this.backoffMs = 250;
    if (this.reconnectTimer) {
      clearTimeout(this.reconnectTimer);
      this.reconnectTimer = null;
    }
    this.cipher = new FrameCipher(this.opts.keyring.current.contentKey, this.opts.identity.publicKeyRaw);
    this.epoch = this.opts.keyring.current.epoch;
    void this.connect().catch(() => this.scheduleReconnect());
  }

  /// Replace everything queued with one update: this client's whole document,
  /// for a room whose log is new. It contains every queued update already, and
  /// the new log has none of what was sent to the old one.
  replaceBacklogWith(wrapped: Uint8Array): void {
    for (const item of this.outbox) {
      item.wrapped.fill(0);
      for (const p of item.parts ?? []) p.fill(0);
    }
    this.outbox = [{ wrapped, parts: null, acked: 0, sent: 0, refused: false }];
    this.inflight = [];
  }

  /// Stop retrying without tearing down keys — used when the server says the
  /// room is gone, where reconnecting can only ever fail again.
  stopReconnecting(): void {
    this.closedByUs = true;
    if (this.reconnectTimer) {
      clearTimeout(this.reconnectTimer);
      this.reconnectTimer = null;
    }
    this.discardQueues();
    try {
      this.ws?.close();
    } catch {
      /* already closing */
    }
    this.ws = null;
  }

  close(): void {
    this.closedByUs = true;
    this.joined = false;
    if (this.reconnectTimer) clearTimeout(this.reconnectTimer);
    this.reconnectTimer = null;
    this.discardQueues();
    this.ws?.close();
    this.ws = null;
    // Final teardown is the only point at which the auth key may be wiped.
    this.opts.authKey.fill(0);
  }

  /// Release this socket's handle on the content key during a wipe. The
  /// session clearing its own copy did not reach this one.
  ///
  /// Best-effort by nature: the cipher object keeps its own reference, and
  /// nulling that would leave every send path dereferencing null. What
  /// actually ends the key's life is the navigation to the tombstone that
  /// follows immediately — the keys are non-extractable `CryptoKey` handles,
  /// so they cannot leave the tab in the first place, and tearing down the
  /// realm takes them with it.
  dropKeys(): void {
    this.closedByUs = true;
    this.discardQueues();
    this.opts.keyring.wipe();
  }

  private async sendJoin(): Promise<void> {
    // Copy the key into the frame; the original must survive reconnects
    // (every reconnect re-runs the JOIN handshake). Zero the copy only.
    const keyCopy = this.opts.authKey.slice();
    const body = {
      auth_key: toB64(keyCopy),
      pubkey: toB64(this.opts.identity.publicKeyRaw),
      client_version: "runa/1.0",
      acks: true,
      indexed: true,
      heartbeat: true,
      kx_pubkey: toB64(this.opts.kx.publicKeyRaw),
      kx_sig: toB64(this.opts.kx.sig),
    };
    keyCopy.fill(0);
    const frame = buildJsonFrame(FT.JOIN, this.opts.roomId, this.epoch, body);
    this.ws?.send(frame);
  }

  private async handleMessage(bytes: Uint8Array): Promise<void> {
    const parsed = parseFrame(bytes);
    if (!parsed) return;
    const { header } = parsed;
    if (header.version !== PROTOCOL_VERSION) {
      this.events.onError(4005);
      return;
    }
    // Server-authored event frames carry epoch 0 by construction, so they
    // must be exempt from the staleness check or every one of them would be
    // dropped the moment the room's epoch advanced.
    const isServerEvent =
      header.frameType === FT.JOIN_ACK ||
      header.frameType === FT.ERROR ||
      header.frameType === FT.PEER_JOIN ||
      header.frameType === FT.PEER_LEAVE ||
      header.frameType === FT.PURGE ||
      header.frameType === FT.TTL_EXTEND ||
      header.frameType === FT.DOC_ACK ||
      header.frameType === FT.RESTART_NOTICE ||
      header.frameType === FT.RESTART_TICKET ||
      header.frameType === FT.PONG;
    // Presence and shred traffic is live-only, so a copy from before the
    // overlap is stale and said so. Stored entries are not checked here: a
    // replayed log spans epochs, and each is read under its own key below.
    const liveOnly =
      header.frameType === FT.AWARENESS ||
      header.frameType === FT.SHRED_REQUEST ||
      header.frameType === FT.SHRED_VOTE ||
      header.frameType === FT.SHRED_CANCEL;
    if (!isServerEvent && liveOnly && this.opts.keyring.has(header.epoch) && this.isStale(header.epoch)) {
      this.events.onEpochStale(header.epoch);
      return;
    }
    if (header.frameType === FT.JOIN_ACK) {
      // Exactly one JOIN_ACK per connection. A relay that replays it could
      // otherwise rewind this connection's nonce stream, and nonce reuse
      // under a shared AES-GCM key hands the relay the plaintext.
      if (this.joined) return;
      let ack: JoinAck;
      try {
        ack = JSON.parse(textDecoder.decode(parsed.body)) as JoinAck;
      } catch {
        return;
      }
      this.joined = true;
      this.restartTicket = null;
      // Ahead of this member: a member must hand it the key. Behind: the
      // server has lost track of the room's rotations, and sending under an
      // older key would hand new writing to whoever left. Either way, hold.
      this.roomEpoch = typeof ack.epoch === "number" ? ack.epoch : 0;
      this.awaitingKeys = this.roomEpoch !== this.opts.keyring.current.epoch;
      // The AEAD sender component must be the server-assigned 16-byte peer id
      // (what receivers read from the envelope), not our public key. Re-label
      // in place: the nonce stream must never restart.
      this.peerId = fromB64(ack.peer_id);
      this.cipher.bindPeerId(this.peerId);
      // A successful join is what ends a run of failed attempts. The backoff
      // used to only ever grow, so a session that had reconnected a handful
      // of times waited fifteen seconds on every reconnect after that.
      this.backoffMs = 250;
      this.acksEnabled = ack.acks === true;
      this.indexed = ack.indexed === true;
      this.heartbeat = ack.heartbeat === true;
      this.limits = limitsFrom(ack.limits);
      this.bucket = { frames: this.limits.framesPerSec, bytes: this.limits.bytesPerSec, at: performance.now() };
      for (const item of this.outbox) item.sent = item.acked;
      this.compactOutbox();
      if (this.acksEnabled || this.heartbeat) this.startLiveness();
      this.events.onJoinAck(ack);
      void this.pump();
      return;
    }
    if (header.frameType === FT.DOC_ACK) {
      this.handleAck(parsed.body);
      return;
    }
    if (header.frameType === FT.RESTART_NOTICE) {
      try {
        const { in_secs, handover } = JSON.parse(textDecoder.decode(parsed.body)) as {
          in_secs: unknown;
          handover?: unknown;
        };
        if (typeof in_secs === "number" && Number.isFinite(in_secs) && in_secs >= 0) {
          this.events.onRestartNotice?.(Math.min(in_secs, 3600), handover === true);
        }
      } catch {
        return;
      }
      return;
    }
    if (header.frameType === FT.RESTART_TICKET) {
      try {
        const { ticket } = JSON.parse(textDecoder.decode(parsed.body)) as { ticket: unknown };
        if (typeof ticket === "string" && ticket.length > 0 && ticket.length <= 64 * 1024) {
          this.restartTicket = { ticket, at: Date.now() };
          this.events.onRestartTicket?.(ticket);
        }
      } catch {
        return;
      }
      return;
    }
    if (header.frameType === FT.PONG) {
      this.pingSentAt = null;
      try {
        const { roster } = JSON.parse(textDecoder.decode(parsed.body)) as { roster: unknown };
        if (Array.isArray(roster)) this.events.onRoster?.(roster as WireRoster);
      } catch {
        return;
      }
      return;
    }
    if (header.frameType === FT.ERROR) {
      let code = 4005;
      try {
        ({ code } = JSON.parse(textDecoder.decode(parsed.body)) as { code: number });
      } catch {
        /* malformed error frame: treat as a protocol error */
      }
      if (code === 4006) {
        // A frame of ours was refused for its epoch: this tab is more than the
        // overlap behind. Joining again resends everything not yet stored, and
        // waits for a handover if the room has moved on (amendment J).
        this.abandonConnection();
        return;
      }
      // 4001 covers "wrong key" and "no such room" — both are terminal. Left
      // to reconnect, a purged room turned every open tab into a client that
      // hammered the server every 15 seconds indefinitely.
      if (code === 4001 || code === 4010 || code === 4011) {
        this.closedByUs = true;
        if (this.reconnectTimer) clearTimeout(this.reconnectTimer);
      }
      this.events.onError(code);
      return;
    }
    if (header.frameType === FT.TTL_EXTEND) {
      try {
        const j = JSON.parse(textDecoder.decode(parsed.body)) as {
          add_secs: number;
          effective_secs: number;
          remaining_secs?: number;
          added_by: string;
        };
        // The server clamps extensions at a ceiling, so re-anchor on the
        // value it computed rather than adding our own request locally.
        this.events.onTtlExtended(j.remaining_secs ?? j.effective_secs, j.effective_secs, j.added_by);
      } catch {
        return;
      }
      return;
    }
    if (header.frameType === FT.PURGE) {
      try {
        const { reason } = JSON.parse(textDecoder.decode(parsed.body)) as { reason: string };
        this.closedByUs = true;
        if (this.reconnectTimer) clearTimeout(this.reconnectTimer);
        this.events.onPurge(reason);
      } catch {
        return;
      }
      return;
    }
    if (header.frameType === FT.PEER_JOIN) {
      try {
        const j = JSON.parse(textDecoder.decode(parsed.body)) as {
          peer_id: string;
          pubkey?: string;
          joined_at_seq: number;
          kx_pubkey?: string | null;
          kx_sig?: string | null;
        };
        this.events.onPeerJoin({
          peerId: fromB64(j.peer_id),
          pubkey: j.pubkey ? fromB64(j.pubkey) : undefined,
          joinedAtSeq: j.joined_at_seq,
          kxPub: j.kx_pubkey ? fromB64(j.kx_pubkey) : undefined,
          kxSig: j.kx_sig ? fromB64(j.kx_sig) : undefined,
        });
      } catch {
        return;
      }
      return;
    }
    if (header.frameType === FT.PEER_LEAVE) {
      try {
        const j = JSON.parse(textDecoder.decode(parsed.body)) as { peer_id: string; reason?: number };
        this.events.onPeerLeave(fromB64(j.peer_id), j.reason);
      } catch {
        return;
      }
      return;
    }

    let env: EnvelopedFrame | null;
    try {
      env = stripEnvelope(bytes);
    } catch {
      return;
    }
    if (!env) return;
    const { senderId } = env;

    if (header.frameType === FT.EPOCH_KEY) {
      this.events.onEpochKey?.(bytes.slice(0, HEADER_LEN), header.epoch, senderId, env.body);
      return;
    }
    // An epoch this member holds no key for is read from the log later, once
    // a member hands the key over; it is not counted as taken meanwhile.
    const key = this.opts.keyring.keyFor(header.epoch);
    if (!key) return;

    switch (header.frameType) {
      case FT.DOC_UPDATE: {
        // Against a server sending indexes, the entry's log index sits
        // between the sender envelope and the body (amendment H).
        let index: number | null = null;
        let body = env.body;
        if (this.indexed) {
          if (body.length < 8) return;
          const i = new DataView(body.buffer, body.byteOffset, 8).getBigUint64(0, false);
          if (i > BigInt(Number.MAX_SAFE_INTEGER)) return;
          index = Number(i);
          body = body.slice(8);
        }
        let taken: number[];
        try {
          const pt = await decryptEnvelope(key, bytes.slice(0, HEADER_LEN), senderId, body);
          const accepted = this.acceptPlaintext(pt, index);
          if (accepted.whole) this.events.onDocUpdate(senderId, accepted.whole);
          taken = accepted.taken;
        } catch {
          // Nothing will ever read this entry, here or anywhere: it can be
          // covered without losing anything, and must not hold back every
          // snapshot after it.
          taken = index === null ? [] : [index];
        }
        if (taken.length) this.events.onEntriesTaken?.(taken);
        return;
      }
      case FT.SNAPSHOT: {
        if (env.body.length < 8) return;
        const covers = snapshotCoversOf(env.body);
        try {
          const pt = await decryptEnvelope(
            key,
            bytes.slice(0, HEADER_LEN),
            senderId,
            env.body.slice(8),
            snapshotCoversOf(env.body),
          );
          this.events.onSnapshot(senderId, covers, pt);
        } catch {
          return;
        }
        return;
      }
      case FT.AWARENESS: {
        try {
          const pt = await decryptEnvelope(
            key,
            bytes.slice(0, HEADER_LEN),
            senderId,
            env.body,
          );
          this.events.onAwareness(senderId, pt);
        } catch {
          return;
        }
        return;
      }
      case FT.SHRED_REQUEST:
      case FT.SHRED_VOTE:
      case FT.SHRED_CANCEL: {
        try {
          const pt = await decryptEnvelope(
            key,
            bytes.slice(0, HEADER_LEN),
            senderId,
            env.body,
          );
          this.events.onShredFrame(header.frameType, senderId, pt);
        } catch {
          return;
        }
        return;
      }
      default:
        return;
    }
  }

  private handleAck(body: Uint8Array): void {
    let parsed: { ok?: unknown; index?: unknown; epoch?: unknown };
    try {
      parsed = JSON.parse(textDecoder.decode(body)) as { ok?: unknown; index?: unknown; epoch?: unknown };
    } catch {
      return;
    }
    const ok = parsed.ok === true;
    if (!ok && typeof parsed.epoch === "number") {
      // Refused for its epoch, not because the log is full. See ERROR 4006.
      this.abandonConnection();
      return;
    }
    const index = parsed.index;
    // Our own update is in our own document already, so its entry is taken
    // in the moment the server says where it went.
    if (ok && this.indexed && typeof index === "number") this.events.onEntriesTaken?.([index]);
    const entry = this.inflight.shift();
    if (!entry) return;
    const { item } = entry;
    if (item.refused) return;
    if (!ok) {
      // The log is full. Resending cannot help, and the ERROR sent alongside
      // this has already told the person their edits did not reach anyone.
      item.refused = true;
      this.removeFromOutbox(item);
      return;
    }
    item.acked += 1;
    this.events.onUpdatesStored?.(1);
    if (item.acked >= this.framesFor(item).length) this.removeFromOutbox(item);
  }

  /// Receive one DOC_UPDATE plaintext, with its log index when the server
  /// sends them. Returns a whole update to apply, or null while a split one is
  /// still arriving, and the log indexes that are taken in once it is applied.
  ///
  /// An incomplete split update holds back its indexes, and so every snapshot
  /// from its first part on, for as long as it stays incomplete. That is the
  /// price of never claiming to cover half of something.
  private acceptPlaintext(pt: Uint8Array, index: number | null): { whole: Uint8Array | null; taken: number[] } {
    const own = index === null ? [] : [index];
    if (!isPart(pt)) return { whole: pt, taken: own };
    const part = readPart(pt);
    if (!part) return { whole: null, taken: own };
    if (this.completedPartsSet.has(part.id)) return { whole: null, taken: own };
    this.pruneReassembly();
    let group = this.reassembly.get(part.id);
    if (group && group.total !== part.total) return { whole: null, taken: own };
    if (!group) {
      group = { total: part.total, parts: new Array(part.total), have: 0, bytes: 0, at: performance.now(), indexes: [] };
      this.reassembly.set(part.id, group);
    }
    group.indexes.push(...own);
    if (group.parts[part.index]) return { whole: null, taken: [] };
    group.parts[part.index] = part.data;
    group.have += 1;
    group.bytes += part.data.length;
    group.at = performance.now();
    this.reassemblyBytes += part.data.length;
    if (group.have < group.total) {
      this.enforceReassemblyBounds(part.id);
      return { whole: null, taken: [] };
    }
    this.dropGroup(part.id, group);
    this.completedParts.push(part.id);
    this.completedPartsSet.add(part.id);
    while (this.completedParts.length > COMPLETED_PARTS_REMEMBERED) {
      this.completedPartsSet.delete(this.completedParts.shift() as string);
    }
    return { whole: concatBytes(...(group.parts as Uint8Array[])), taken: group.indexes };
  }

  private dropGroup(id: string, group: Group): void {
    this.reassembly.delete(id);
    this.reassemblyBytes -= group.bytes;
  }

  private pruneReassembly(): void {
    const now = performance.now();
    for (const [id, g] of this.reassembly) {
      if (now - g.at > REASSEMBLY_STALE_MS) this.dropGroup(id, g);
    }
  }

  private enforceReassemblyBounds(current: string): void {
    while (this.reassembly.size > REASSEMBLY_MAX_GROUPS || this.reassemblyBytes > REASSEMBLY_MAX_BYTES) {
      let oldest: [string, Group] | null = null;
      for (const e of this.reassembly) {
        if (e[0] !== current && (!oldest || e[1].at < oldest[1].at)) oldest = e;
      }
      if (!oldest) {
        const g = this.reassembly.get(current);
        if (g) this.dropGroup(current, g);
        return;
      }
      this.dropGroup(oldest[0], oldest[1]);
    }
  }

  private ownHeader(frameType: number): Uint8Array {
    return encodeHeader({
      version: PROTOCOL_VERSION,
      frameType,
      roomId: this.opts.roomId,
      epoch: this.epoch,
      nonceSess: this.cipher.sess,
      flags: 0,
    });
  }

  /// Nothing encrypted may leave before JOIN_ACK. Until then the cipher is
  /// labelled with this client's public key instead of the peer id receivers
  /// will check it against, so every receiver rejects the frame — while the
  /// server, which cannot tell, stores a document update in the log for good
  /// and would compact history under a snapshot nobody can read.
  private canSendDocuments(): boolean {
    return this.joined && !this.awaitingKeys && this.ws?.readyState === WebSocket.OPEN;
  }

  /// Queue an update for the room. It is sent once the connection is joined,
  /// and kept — across reconnects — until the server says it stored it.
  async sendUpdate(plaintext: Uint8Array): Promise<void> {
    if (this.closedByUs) return;
    this.outbox.push({ wrapped: plaintext, parts: null, acked: 0, sent: 0, refused: false });
    if (!this.joined && this.outbox.length >= COMPACT_WHILE_OFFLINE_AT) this.compactOutbox();
    void this.pump();
  }

  /// Whether a snapshot taken now would cover what it claims to: joined, with
  /// nothing of ours still unstored and nothing of anyone's half-received.
  readyForSnapshot(): boolean {
    this.pruneReassembly();
    return (
      this.canSendDocuments() &&
      this.outbox.length === 0 &&
      this.inflight.length === 0 &&
      this.reassembly.size === 0
    );
  }

  private framesFor(item: Pending): Uint8Array[] {
    if (item.parts) return item.parts;
    if (item.wrapped.length + DOC_FRAME_OVERHEAD <= this.limits.maxFrameBytes) return [item.wrapped];
    const id = new Uint8Array(8);
    crypto.getRandomValues(id);
    const room = this.limits.maxFrameBytes - DOC_FRAME_OVERHEAD - PART_HEADER_LEN - 255;
    item.parts = splitIntoParts(item.wrapped, Math.max(1024, Math.min(room, Math.floor(this.limits.bytesPerSec / 2))), id);
    return item.parts;
  }

  private removeFromOutbox(item: Pending): void {
    const i = this.outbox.indexOf(item);
    if (i >= 0) this.outbox.splice(i, 1);
  }

  /// Merge updates that have not been partly stored into fewer. A backlog of
  /// keystrokes resent one frame each is slow at a paced rate, and a split
  /// update keeps its parts so a resend completes the message it started.
  private compactOutbox(): void {
    const compact = this.opts.compactUpdates;
    if (!compact) return;
    const loose = this.outbox.filter((i) => i.acked === 0 && !i.parts && !i.refused);
    if (loose.length < 2) return;
    let merged: Uint8Array[];
    try {
      merged = compact(loose.map((i) => i.wrapped));
    } catch {
      return;
    }
    const looseSet = new Set(loose);
    this.outbox = [
      ...this.outbox.filter((i) => !looseSet.has(i)),
      ...merged.map((wrapped) => ({ wrapped, parts: null, acked: 0, sent: 0, refused: false })),
    ];
  }

  /// Send queued frames, one at a time and in order, for as long as the
  /// connection is joined. Order matters twice over: acks are matched to
  /// frames by position, and a part must not overtake the parts before it.
  private async pump(): Promise<void> {
    if (this.pumping) return;
    this.pumping = true;
    try {
      while (this.canSendDocuments()) {
        const item = this.outbox.find((i) => !i.refused && i.sent < this.framesFor(i).length);
        if (!item) return;
        const plaintext = this.framesFor(item)[item.sent];
        const gen = this.generation;
        await this.pace(plaintext.length + DOC_FRAME_OVERHEAD);
        if (gen !== this.generation || item.refused || !this.outbox.includes(item)) continue;
        if (!this.canSendDocuments()) return;
        const header = this.ownHeader(FT.DOC_UPDATE);
        const envelope = await this.cipher.encrypt(header, plaintext);
        if (gen !== this.generation) continue;
        if (!this.rawSend(concatBytes(header, envelope))) return;
        item.sent += 1;
        if (this.acksEnabled) {
          this.inflight.push({ item, sentAt: performance.now() });
        } else {
          item.acked = item.sent;
          this.events.onUpdatesStored?.(1);
          if (item.acked >= this.framesFor(item).length) this.removeFromOutbox(item);
        }
      }
    } finally {
      this.pumping = false;
    }
  }

  /// Hold to half of the rate the server enforces. The rest is headroom for
  /// presence, shred frames and sync requests, which share the same limit.
  private async pace(bytes: number): Promise<void> {
    const frameRate = this.limits.framesPerSec / 2;
    const byteRate = this.limits.bytesPerSec / 2;
    const frameCap = this.limits.framesPerSec;
    const byteCap = Math.max(bytes, this.limits.bytesPerSec);
    for (;;) {
      const now = performance.now();
      const dt = Math.max(0, now - this.bucket.at) / 1000;
      this.bucket.at = now;
      this.bucket.frames = Math.min(frameCap, this.bucket.frames + dt * frameRate);
      this.bucket.bytes = Math.min(byteCap, this.bucket.bytes + dt * byteRate);
      if (this.bucket.frames >= 1 && this.bucket.bytes >= bytes) {
        this.bucket.frames -= 1;
        this.bucket.bytes -= bytes;
        return;
      }
      const waitFrames = this.bucket.frames >= 1 ? 0 : (1 - this.bucket.frames) / frameRate;
      const waitBytes = this.bucket.bytes >= bytes ? 0 : (bytes - this.bucket.bytes) / byteRate;
      await new Promise((r) => setTimeout(r, Math.max(1, Math.ceil(Math.max(waitFrames, waitBytes) * 1000))));
    }
  }

  private startLiveness(): void {
    this.stopLiveness();
    const timeout = this.opts.ackTimeoutMs ?? ACK_TIMEOUT_MS;
    const beat = this.opts.heartbeatMs ?? HEARTBEAT_MS;
    const gen = this.generation;
    this.pingSentAt = null;
    this.lastPingAt = performance.now();
    this.livenessTimer = setInterval(() => {
      if (gen !== this.generation) {
        this.stopLiveness();
        return;
      }
      const now = performance.now();
      const oldest = this.inflight[0];
      if (oldest && now - oldest.sentAt > timeout) {
        this.abandonConnection();
        return;
      }
      if (!this.heartbeat) return;
      if (this.pingSentAt !== null) {
        if (now - this.pingSentAt > timeout) this.abandonConnection();
        return;
      }
      if (now - this.lastPingAt >= beat) {
        this.lastPingAt = now;
        if (this.rawSend(buildJsonFrame(FT.PING, this.opts.roomId, this.epoch, {}))) this.pingSentAt = now;
      }
    }, Math.max(25, Math.min(1000, Math.floor(Math.min(timeout, beat) / 4))));
  }

  private stopLiveness(): void {
    if (this.livenessTimer) clearInterval(this.livenessTimer);
    this.livenessTimer = null;
  }

  async sendAwareness(plaintext: Uint8Array): Promise<void> {
    if (!this.canSendDocuments()) return;
    const header = this.ownHeader(FT.AWARENESS);
    const envelope = await this.cipher.encrypt(header, plaintext);
    this.rawSend(concatBytes(header, envelope));
  }

  async sendShredFrame(frameType: number, plaintext: Uint8Array): Promise<void> {
    if (!this.canSendDocuments()) return;
    const header = this.ownHeader(frameType);
    const envelope = await this.cipher.encrypt(header, plaintext);
    this.rawSend(concatBytes(header, envelope));
  }

  /// Throws when nothing was sent, so the caller does not move its sync index
  /// past history the server still holds.
  async sendSnapshot(plaintext: Uint8Array, covers: bigint): Promise<void> {
    if (!this.canSendDocuments()) throw new Error("not joined");
    // The truncation index rides outside the ciphertext but inside the AEAD:
    // a relay that rewrites it breaks authentication (amendment B).
    const header = this.ownHeader(FT.SNAPSHOT);
    const envelope = await this.cipher.encrypt(header, plaintext, covers);
    const body = new Uint8Array(8 + envelope.length);
    new DataView(body.buffer).setBigUint64(0, covers, false);
    body.set(envelope, 8);
    const frame = buildFrame(FT.SNAPSHOT, this.opts.roomId, this.epoch, this.cipher.sess, body);
    if (frame.length > this.limits.maxFrameBytes) {
      // Skipping leaves the log uncompacted, which is a slow problem.
      // Sending it closes the connection, which is an immediate one.
      this.events.onSnapshotTooLarge(frame.length);
      throw new Error("snapshot too large");
    }
    if (!this.rawSend(frame)) throw new Error("snapshot not sent");
  }

  sendSyncRequest(fromIndex: number): void {
    this.rawSend(
      buildJsonFrame(FT.DOC_SYNC_REQ, this.opts.roomId, this.epoch, { from_index: fromIndex }),
    );
  }

  sendTtlExtend(addSecs: number): void {
    this.rawSend(buildJsonFrame(FT.TTL_EXTEND, this.opts.roomId, this.epoch, { add_secs: addSecs }));
  }

  sendPurgeAck(requestId: string): void {
    this.rawSend(buildJsonFrame(FT.PURGE_ACK, this.opts.roomId, this.epoch, { request_id: requestId }));
  }

  /// Returns whether the bytes actually went out.
  private rawSend(bytes: Uint8Array): boolean {
    if (this.ws?.readyState === WebSocket.OPEN) {
      this.ws.send(bytes);
      return true;
    }
    return false;
  }
}

function snapshotCoversOf(envelope: Uint8Array): bigint {
  let c = 0n;
  for (let i = 0; i < 8; i++) c = (c << 8n) | BigInt(envelope[i]);
  return c;
}

export function toB64(bytes: Uint8Array): string {
  let s = "";
  for (const b of bytes) s += String.fromCharCode(b);
  return btoa(s);
}

export function fromB64(s: string): Uint8Array {
  const bin = atob(s);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

export type { FrameHeader };
export { HEADER_LEN };
