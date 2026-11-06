import * as cbor2 from "cbor2";
import * as Y from "yjs";
import { RunaSocket, fromB64, type JoinAck, type WireRoster } from "./transport/socket";
import { FT } from "./transport/frame";
import { RunaDoc, wrapWithLengthAndPad, mergeWrapped } from "./doc/ydoc";
import { bindMonaco, type Binding } from "./doc/binding";
import { AwarenessHub, handleFromPubkey } from "./doc/awareness";
import { generateIdentity, signPayload, type Identity } from "./crypto/identity";
import { generateKx, kxStatement } from "./crypto/kx";
import { EpochCoordinator, type KeyStatus } from "./epoch/coordinator";
import { Keyring } from "./epoch/keyring";
import {
  ShredMachine,
  cancelApplies,
  type Policy,
  type ShredRequest,
} from "./shred/machine";
import type { RosterEntry } from "./shred/roster";
import { executeWipe } from "./shred/wipe";
import { parseSecurityLevel, securityLevelOf, type SecurityLevel } from "./security-level";

/// A divergence warning is only meaningful once the document has stopped
/// moving. Two peers mid-keystroke legitimately hold different states.
const DIVERGENCE_QUIET_MS = 5_000;

/// How long a repair is given to work before the disagreement is called real.
/// Long enough for the server's replay to arrive and apply — the presence
/// heartbeat that re-evaluates this runs every ten seconds.
const DIVERGENCE_REPAIR_SETTLE_MS = 15_000;

export type DivergenceAction = "none" | "repair" | "warn" | "clear";

/// What to do about a disagreement, given what has already been tried.
///
/// The warning used to be the whole response: it appeared and sat there, and
/// the only thing that actually fixed a stale copy was reloading the page.
/// But the relay can already repair this — `tail_from(0)` returns the snapshot
/// and the entire tail, and applying it twice is harmless because Yjs is
/// idempotent — so the first response to a disagreement should be to fix it,
/// and the warning should be what happens when fixing it did not work.
///
/// Pulled out of the heartbeat so the policy can be tested without a socket, a
/// server, or two browsers.
export function divergenceAction(input: {
  diverged: boolean;
  reported: boolean;
  repairAttemptedAt: number;
  now: number;
  settleMs?: number;
}): DivergenceAction {
  const settleMs = input.settleMs ?? DIVERGENCE_REPAIR_SETTLE_MS;
  if (!input.diverged) return input.reported ? "clear" : "none";
  // Nothing tried yet: repair silently rather than announcing a problem the
  // client is about to solve on its own.
  if (input.repairAttemptedAt === 0) return "repair";
  // A repair is in flight. Saying nothing here is deliberate; a warning that
  // appears and disappears on its own is worse than one that waits.
  if (input.now - input.repairAttemptedAt < settleMs) return "none";
  return input.reported ? "none" : "warn";
}

/// Has the server shortened an absolute TTL behind the encrypted config?
///
/// `reported.secs` is the time *remaining*, which for a 24-hour room is
/// necessarily less than the 86 400 the config blob records — so comparing the
/// two directly reported every such room as tampered with, seconds after it
/// was made. A warning that is always on is worse than none: it teaches people
/// to dismiss the one banner that should stop them.
///
/// The total the server is claiming is `remaining + elapsed`, and elapsed
/// comes from the server rather than the local clock so that a disagreement
/// between the two cannot look like tampering. A room may legitimately be
/// *extended* — effective_ttl_secs is the configured value plus any
/// extensions — so only a claim shorter than the configured duration is a
/// contradiction.
///
/// Without `elapsedSecs` the shortening cannot be checked at all, and this
/// says so by returning false rather than guessing. A kind mismatch is checked
/// separately and still catches the cruder substitutions.
export function absoluteTtlShortened(
  cfg: { kind: string; secs: number },
  reported: { kind: string; secs: number },
  elapsedSecs: number | undefined,
): boolean {
  if (cfg.kind !== "absolute" || reported.kind !== "absolute") return false;
  if (typeof elapsedSecs !== "number" || !Number.isFinite(elapsedSecs) || elapsedSecs < 0) {
    return false;
  }
  const claimedTotal = reported.secs + elapsedSecs;
  return claimedTotal < cfg.secs - 1;
}

/// Replace a roster with the server's authoritative one.
///
/// This existed inline as a loop that only ever called `set`, so a JOIN_ACK
/// was merged into whatever the client already held. A peer id is minted per
/// connection, so every reconnect left the previous connection's id behind for
/// good: switching tabs twice left four entries where two people were.
///
/// The roster is not decoration. It is the consensus denominator — a shred
/// then asked three of four to approve with two people present — and its hash
/// travels inside a shred request, so an inflated roster hashed differently
/// from everybody else's and every receiver rejected the request as
/// `roster-mismatch` and never showed the prompt. Reloading the page appeared
/// to cure it because a reload builds a fresh session around an empty map.
///
/// Entries the server no longer lists are gone: they left while this client
/// was disconnected, so no PEER_LEAVE could be delivered.
export function replaceRoster(
  target: Map<string, RosterEntry>,
  authoritative: WireRoster,
): void {
  target.clear();
  for (const r of authoritative) {
    target.set(r.peer_id, {
      peerId: fromB64(r.peer_id),
      pubkey: r.pubkey ? fromB64(r.pubkey) : undefined,
      kxPub: r.kx_pubkey ? fromB64(r.kx_pubkey) : undefined,
      kxSig: r.kx_sig ? fromB64(r.kx_sig) : undefined,
      joinedAtSeq: r.joined_at_seq,
    });
  }
}

/// Who is gone from the roster, by signing key. A peer id is minted per
/// connection, so a member that reconnected is not a departure; its signing
/// key, which lives as long as its tab, is how it is recognised.
export function departedMembers(before: RosterEntry[], after: RosterEntry[]): RosterEntry[] {
  const still = new Set(after.filter((r) => r.pubkey).map((r) => toB64(r.pubkey!)));
  return before.filter((r) => r.pubkey && !still.has(toB64(r.pubkey)));
}

export const KEY_STATUS_TEXT: Record<KeyStatus, string | null> = {
  ok: null,
  waiting: "Waiting for someone in this room to give this tab the room's current key.",
  unreadable:
    "This room's key changed after the last people left, so what was written since can't be opened here.",
  refused:
    "A key change in this room failed its checks and was refused. Someone may be interfering with the room, so copy your work out.",
  "roster-mismatch":
    "The latest key change was made with a different list of people than this tab sees. Someone may be hidden from this room.",
  "server-behind":
    "The server has lost track of this room's key changes, so this tab has stopped sending. Copy your work out and reload.",
};

/// The log index a snapshot taken now may claim to cover, or null when there
/// is nothing new to cover.
///
/// Against a server that sends indexes this is exactly what the copy holds.
/// Without them it can only be this client's own stored updates on top of its
/// last snapshot — an undercount that falls further behind the more other
/// people type, and that the server refuses outright once it is below a
/// snapshot someone else made, since a snapshot may never move backwards. A
/// room whose oldest member mostly read therefore never compacted, and a long
/// session filled its log until edits were refused.
export function snapshotCover(s: {
  indexed: boolean;
  watermark: number;
  lastCovered: number;
  baseIndex: number;
  storedCount: number;
}): number | null {
  if (!s.indexed) return s.baseIndex + s.storedCount;
  return s.watermark > s.lastCovered ? s.watermark : null;
}

/// What has to change to turn `local` into the server's roster: who joined
/// and who left without this client being told. Applied through the same
/// handlers as PEER_JOIN and PEER_LEAVE, so a correction looks exactly like
/// the event that was missed.
///
/// JOIN_ACK was the only full roster a client ever received, so one that
/// missed an event stayed wrong until it next reconnected. Every PONG now
/// carries the server's roster (amendment G).
export function rosterChanges(
  local: Iterable<string>,
  authoritative: WireRoster,
): { joined: WireRoster; left: string[] } {
  const have = new Set(local);
  const want = new Set(authoritative.map((r) => r.peer_id));
  return {
    joined: authoritative.filter((r) => !have.has(r.peer_id)),
    left: [...have].filter((id) => !want.has(id)),
  };
}

/// How long a roster entry counts as present before it has to prove itself by
/// broadcasting. Must exceed the ten-second presence heartbeat.
const ROSTER_JOIN_GRACE_MS = 15_000;

export type LadderPhase =
  | { kind: "none" }
  | { kind: "normal"; remainingMs: number }
  | { kind: "watch"; remainingMs: number }
  | { kind: "armed"; remainingMs: number }
  | { kind: "burn"; remainingMs: number };

type ExpiryModel =
  | { kind: "none" }
  | { kind: "absolute"; deadlinePerfMs: number }
  | { kind: "idle"; windowMs: number; lastActivityPerfMs: number };

export interface SessionEvents {
  onJoinAck(ack: JoinAck): void;
  onPeersChanged(count: number): void;
  onTemper(temper: "COLD" | "SECURE" | "WATCH" | "ARMED" | "BURN"): void;
  onShredPrompt(request: ShredRequest): void;
  onShredState(state: string, waitingOnPeerId?: string): void;
  onPurge(reason: string): void;
  onCountdown(phase: LadderPhase): void;
  onTtlMismatch(): void;
  /// This client declined to take part in a shred vote, and why.
  onShredRejected(reason: string): void;
  /// Edits are no longer reaching other people, or soon will not be.
  onHistoryPressure(message: string): void;
  /// Raised with true when this copy is genuinely behind or ahead of an
  /// agreed-upon document, and with false when that resolves. It must be able
  /// to clear: a warning that latches on the first transient mismatch is
  /// indistinguishable from one that is always on.
  onDivergence(diverged: boolean): void;
  onRoomUnavailable(code: number): void;
  /// The server stops in this many seconds. With `handover`, the room comes
  /// back on the new process for anyone who keeps it open; without, it ends.
  onServerRestart(inSecs: number, handover: boolean): void;
  /// The room came back after a restart, and this copy is being sent to it.
  onRoomCarriedOver?(): void;
  /// Why the server is refusing this connection, or null once it is accepted.
  onConnectionRefused(message: string | null): void;
  /// How the room asks for its key to be kept, from its sealed config. Raised
  /// on every join.
  onSecurityLevel?(level: SecurityLevel): void;
  /// Where this tab stands with the room's key (amendment J), as a sentence
  /// to show, or null when there is nothing to say. `alarming` marks the
  /// states that may mean tampering.
  onKeyStatus?(message: string | null, alarming: boolean): void;
}

/// What the server said to a restart ticket: the room is back (whoever
/// brought it back), try again shortly, or it is not coming back.
export type RestoreResult = "restored" | "retry" | "gone" | "name-taken";

export interface SessionConfig {
  url: string;
  roomIdHex: string;
  authKey: Uint8Array;
  contentKey: CryptoKey;
  chainKey: CryptoKey;
  insecureAllowed?: boolean;
  /// Present a restart ticket to the new process. Without it, a room ends at
  /// a restart as it always did.
  restoreRoom?: (ticket: string) => Promise<RestoreResult>;
}

/// How long to keep presenting a ticket the server has not yet been able to
/// take — a new process still starting, say. The server stops honouring one
/// after ten minutes anyway.
const TICKET_PATIENCE_MS = 9 * 60_000;

/// How long a departed peer is still shown as "away" rather than gone. A
/// phone that locks its screen drops the websocket within seconds, so without
/// this the person simply vanishes and the rest of the room can reach quorum
/// without ever knowing they were excluded.
const AWAY_GRACE_MS = 10 * 60_000;

export interface AwayPeer {
  peerIdB64: string;
  /// The two-word handle their presence was broadcasting, so the shred
  /// dialog can say who is missing rather than "someone".
  handle: string;
  leftAt: number;
}

interface SocketInternals {
  ws?: WebSocket;
  roster: Map<string, RosterEntry>;
  away: Map<string, { handle: string; leftAt: number }>;
  myPeerId: string;
  myJoinedSeq: number;
  joinPerfMs: number;
}

export class Session {
  readonly doc: RunaDoc;
  readonly socket: RunaSocket;
  readonly identity: Identity;
  awareness: AwarenessHub | null = null;
  coordinator!: EpochCoordinator;
  securityLevel: SecurityLevel = "highest";
  private epochTimer: ReturnType<typeof setInterval> | null = null;
  /// A JOIN_ACK arrived while this tab held no key for the room's epoch, so
  /// the sync request waits for the handover.
  private syncDeferred = false;

  private binding: Binding | null = null;
  private heartbeatTimer: ReturnType<typeof setInterval> | null = null;
  private machine: ShredMachine;
  private internals: SocketInternals;
  private destroyed = false;
  wipeContext: WipeContext = {};
  private snapshotTimer: ReturnType<typeof setInterval> | null = null;
  private cursorTimerRef: (() => void) | null = null;
  private steadyTimer: ReturnType<typeof setInterval> | null = null;
  private ownHash = "";
  /// The log this client last joined, from JOIN_ACK.
  private logId: string | null = null;
  /// Relayed updates carry their log index, so snapshots cover exactly what
  /// this copy holds (amendment H).
  private indexed = false;
  /// The index the last snapshot this client saw or made covers.
  private lastCovered = 0;
  private carryingOver = false;

  private constructor(
    private cfg: SessionConfig,
    identity: Identity,
    doc: RunaDoc,
    socket: RunaSocket,
    machine: ShredMachine,
    internals: SocketInternals,
    private events: SessionEvents,
  ) {
    this.identity = identity;
    this.doc = doc;
    this.socket = socket;
    this.machine = machine;
    this.internals = internals;
  }

  static async create(cfg: SessionConfig, events: SessionEvents): Promise<Session> {
    const identity = await generateIdentity();
    const roomId = hexToBytes(cfg.roomIdHex);
    const kx = await generateKx();
    const kxSig = await signPayload(identity, kxStatement(roomId, kx.publicKeyRaw));
    const keyring = await Keyring.fromRoot(0, cfg.contentKey, cfg.chainKey);
    const roster = new Map<string, RosterEntry>();
    const away = new Map<string, { handle: string; leftAt: number }>();
    const internals: SocketInternals = { roster, away, myPeerId: "", myJoinedSeq: 0, joinPerfMs: 0 };
    let sessionRef: Session | null = null;

    const peerJoined = (entry: RosterEntry): void => {
      const id = toB64(entry.peerId);
      roster.set(id, entry);
      sessionRef?.coordinator?.memberJoined(entry);
      sessionRef?.noteRosterSeen(id);
      // Names come from the key the roster binds to this peer, never from
      // what the peer says its name is.
      if (entry.pubkey) {
        void handleFromPubkey(entry.pubkey).then((h) =>
          sessionRef?.awareness?.setHandle(id, h),
        );
      }
      // They are back; stop showing them as away.
      away.delete(id);
      // Say hello immediately. Presence is broadcast on the ten-second
      // heartbeat and on cursor movement, so without this a newcomer who
      // joins and sits still is invisible to everyone — and everyone is
      // invisible to them — for up to ten seconds. Measured at 10-12s
      // before this line existed.
      void sessionRef?.announcePresence();
      events.onPeersChanged(roster.size);
    };

    const peerLeft = (peerId: Uint8Array): void => {
      const id = toB64(peerId);
      const entry = roster.get(id);
      if (roster.delete(id)) {
        if (entry) sessionRef?.coordinator?.memberLeft(entry);
        // Remember them briefly, by name. A locked phone is
        // indistinguishable on the wire from someone closing the tab, and
        // the difference matters when a shred is about to be proposed.
        // The handle comes from their last presence broadcast; if they
        // never sent one, fall back to a short form of their peer id.
        // Derive from their roster key, captured before the entry goes.
        const pubkey = entry?.pubkey;
        away.set(id, { handle: id.slice(0, 6), leftAt: Date.now() });
        if (pubkey) {
          void handleFromPubkey(pubkey).then((h) => {
            const rec = away.get(id);
            if (rec) rec.handle = h;
          });
        }
      }
      events.onPeersChanged(roster.size);
    };

    const socket = new RunaSocket({
      url: cfg.url,
      roomId,
      authKey: cfg.authKey,
      identity,
      keyring,
      kx: { publicKeyRaw: kx.publicKeyRaw, sig: kxSig },
      insecureAllowed: cfg.insecureAllowed,
      compactUpdates: mergeWrapped,
      events: {
        onJoinAck: (ack) => sessionRef?.handleJoinAck(ack),
        onUpdatesStored: (count) => sessionRef?.noteUpdatesStored(count),
        onRestartNotice: (inSecs, handover) => {
          if (handover) sessionRef?.coordinator?.restartNotice(inSecs);
          events.onServerRestart(inSecs, handover);
        },
        onEpochKey: (header, epoch, sender, body) =>
          void sessionRef?.coordinator?.receive(header, epoch, sender, body),
        onEntriesTaken: (indexes) => {
          for (const i of indexes) sessionRef?.doc.cursor.note(i);
        },
        onRoster: (list) => {
          const { joined, left } = rosterChanges(roster.keys(), list);
          for (const id of left) peerLeft(fromB64(id));
          for (const r of joined) {
            peerJoined({
              peerId: fromB64(r.peer_id),
              pubkey: r.pubkey ? fromB64(r.pubkey) : undefined,
              kxPub: r.kx_pubkey ? fromB64(r.kx_pubkey) : undefined,
              kxSig: r.kx_sig ? fromB64(r.kx_sig) : undefined,
              joinedAtSeq: r.joined_at_seq,
            });
          }
        },
        onRefused: (code) =>
          events.onConnectionRefused(
            code === 4007
              ? "Your network already has as many connections to this server as one address may. Retrying…"
              : "This server is at its connection limit. Retrying…",
          ),
        onDocUpdate: (sender, envelope) =>
          sessionRef?.handleRemoteUpdate(envelope) ?? void sender,
        onSnapshot: (sender, covers, blob) => sessionRef?.handleSnapshot(sender, covers, blob),
        onAwareness: (sender, pt) => sessionRef?.awareness?.receive(sender, pt),
        onShredFrame: (ft, sender, pt) => void sessionRef?.handleShredFrame(ft, sender, pt),
        onPeerJoin: (entry) => peerJoined(entry),
        onPeerLeave: (peerId) => peerLeft(peerId),
        onPurge: (reason) => events.onPurge(reason),
        onTtlExtended: (remaining, effective, addedBy) =>
          sessionRef?.handleTtlExtended(remaining, effective, addedBy),
        onError: (code) => {
          // 4001 after a successful join means the room is gone, not that the
          // key is wrong. Discarding the code left the UI on "connecting"
          // while the socket retried forever.
          if (code === 4001 && sessionRef?.carryOver()) return;
          if (code === 4001 || code === 4010 || code === 4011) {
            socket.stopReconnecting();
            events.onRoomUnavailable(code);
            return;
          }
          if (code === 4004) {
            // The room's history is full, so this edit was neither stored nor
            // relayed. Nobody else saw it. A colour change is not enough
            // warning for silent data loss.
            events.onHistoryPressure(
              "This room is full and your latest edits did not reach anyone. " +
                "Copy your work out and start a new room.",
            );
          }
          events.onTemper("WATCH");
        },
        onEpochStale: () => events.onTemper("WATCH"),
        onSnapshotTooLarge: () => {
          events.onHistoryPressure(
            "This document has grown too large to compact its edit history. " +
              "Editing still works, but consider splitting it across rooms.",
          );
        },
        onDisconnected: () => events.onTemper("COLD"),
      },
    });

    const doc = new RunaDoc({
      transport: {
        sendUpdate: async (wrapped) => {
          sessionRef?.refreshActivity();
          await socket.sendUpdate(wrapped);
        },
        sendSnapshot: async (state, covers) => socket.sendSnapshot(state, covers),
        sendSyncRequest: (fromIndex) => socket.sendSyncRequest(fromIndex),
      },
    });

    const machine = new ShredMachine(identity, "", () => [...roster.values()], {
      // Record only. Wiping here would tear down the socket inside
      // castMyVote(), before respondToShred() has had a chance to transmit
      // the very ballot that produced the approval — so the last peer to
      // approve would destroy its own copy while everyone else sat one vote
      // short. The session flushes this once the wire is clear.
      onApproved: (requestId) => sessionRef?.markPurgeApproved(requestId),
      onRejected: () => events.onShredState("REJECTED"),
      onExpired: () => events.onShredState("EXPIRED"),
      onStalled: (_id, waiting) =>
        events.onShredState(waiting.length ? "STALLED" : "VOTING", waiting[0]),
      // Refusing to take part in a shred vote was discarded entirely: an empty
      // function, no log, no message. When a drifted roster made every peer
      // reject a request, the initiator sat in VOTING forever and nobody —
      // initiator or receiver — was told anything at all. A guard that fires
      // in silence cannot be diagnosed from the outside, which is exactly what
      // happened.
      onVoteRejectedByGuard: (reason) => {
        events.onShredRejected(reason);
      },
    });

    const session = new Session(cfg, identity, doc, socket, machine, internals, events);
    sessionRef = session;
    session.coordinator = new EpochCoordinator({
      roomId,
      identity,
      kx,
      keyring,
      now: () => Date.now(),
      me: () => (internals.myPeerId ? fromB64(internals.myPeerId) : null),
      members: () => [...roster.values()],
      highest: () => session.securityLevel === "highest",
      header: (epoch) => socket.epochKeyHeader(epoch),
      send: (header, body) => socket.sendEpochKey(header, body),
      adopt: (epoch) => session.keysAdopted(epoch),
      rejoin: () => socket.reconnectNow(),
      status: (st) => session.reportKeyStatus(st),
      snapshotSoon: () => session.snapshotSoon(),
    });
    session.epochTimer = setInterval(() => void session.coordinator.tick(), 1_000);
    void socket.connect().catch(() => {
      events.onTemper("COLD");
    });
    return session;
  }

  /// Count entries this client has actually added to the room log. The
  /// snapshot index is estimated from it, so it has to count what the server
  /// stored rather than what was typed: several queued edits can go out as one
  /// merged update, and one large edit as several parts.
  noteUpdatesStored(count: number): void {
    this.doc.storedCount += count;
  }

  /// A join refused as "no such room" while holding a restart ticket is the
  /// new process not knowing the room yet: present the ticket, then join
  /// again. Returns false when there is no ticket to present, and the refusal
  /// means what it always meant.
  ///
  /// Nothing queued is discarded while this runs. The first join after it
  /// sees a new log and sends this whole copy anyway.
  carryOver(): boolean {
    const held = this.socket.heldRestartTicket();
    const restore = this.cfg.restoreRoom;
    if (!held || !restore || this.destroyed) return false;
    if (this.carryingOver) return true;
    this.carryingOver = true;
    void (async () => {
      let wait = 1_000;
      try {
        while (!this.destroyed && Date.now() - held.at < TICKET_PATIENCE_MS) {
          let result: RestoreResult;
          try {
            result = await restore(held.ticket);
          } catch {
            result = "retry";
          }
          if (result === "restored") {
            this.socket.dropRestartTicket();
            this.socket.resume();
            return;
          }
          if (result !== "retry") break;
          await new Promise((r) => setTimeout(r, wait));
          wait = Math.min(wait * 2, 15_000);
        }
        this.socket.dropRestartTicket();
        if (this.destroyed) return;
        this.socket.stopReconnecting();
        this.events.onRoomUnavailable(4001);
      } finally {
        this.carryingOver = false;
      }
    })();
    return true;
  }

  private async handleJoinAck(ack: JoinAck): Promise<void> {
    this.events.onConnectionRefused(null);
    this.indexed = ack.indexed === true;
    // A new log under the same room id is a room brought back after a
    // restart (amendment I). It holds nothing yet — the server never had
    // anything it could read — so this copy is the room now, as much as
    // anyone's is: send all of it. Yjs merges it with everyone else's and
    // drops what repeats. Before any await, so it replaces the backlog before
    // the socket starts sending it.
    const newLog = this.logId !== null && ack.log_id !== undefined && ack.log_id !== this.logId;
    if (ack.log_id !== undefined) this.logId = ack.log_id;
    if (newLog) {
      this.doc.cursor.reset();
      this.doc.baseIndex = 0;
      this.doc.storedCount = 0;
      this.lastCovered = 0;
      this.socket.replaceBacklogWith(wrapWithLengthAndPad(Y.encodeStateAsUpdate(this.doc.ydoc)));
      this.events.onRoomCarriedOver?.();
    }
    this.internals.myPeerId = ack.peer_id;
    this.internals.myJoinedSeq = ack.roster.find((r) => r.peer_id === ack.peer_id)?.joined_at_seq ?? 0;
    this.internals.joinPerfMs = performance.now();
    this.machine.setMyPeerId(ack.peer_id);
    // JOIN_ACK carries the server's complete current roster, so it replaces
    // what this client holds rather than being merged into it. Extracted so
    // the replacement can be asserted directly: reproducing it through the
    // network needs a real socket close, and a brief offline blip does not
    // produce one, so an end-to-end test of it passes whether or not the fix
    // is present.
    //
    // Merging is what shipped, and every reconnect therefore left the previous
    // session's peer ids behind for good — a peer id is minted per connection,
    // so switching tabs twice left four entries where two people were. That
    // was not merely a wrong occupant count. The roster is the consensus
    // denominator, so a shred asked three of four to approve when two people
    // were present; and the roster hash travels inside a shred request, so an
    // inflated roster hashed differently from everyone else's and every
    // receiver rejected the request as `roster-mismatch` and never showed the
    // prompt. Reloading the page appeared to fix it because a reload builds a
    // fresh session around an empty map.
    //
    // Peers this client held that the server no longer lists are gone: they
    // left while it was disconnected and no PEER_LEAVE could be delivered.
    const rosterBefore = [...this.internals.roster.values()];
    replaceRoster(this.internals.roster, ack.roster);
    for (const r of ack.roster) this.noteRosterSeen(r.peer_id);
    this.events.onPeersChanged(this.internals.roster.size);

    // The AEAD-protected room config is authoritative over the cleartext
    // TTL the server reports (spec §5.9.3). A server that omits or garbles
    // the blob falls back to its clear value; a server that contradicts it
    // gets the mismatch banner AND loses the dispute.
    let effectiveTtl = ack.ttl;
    // How this room wants its key kept comes only from the sealed config. A
    // config that is missing or will not open is treated as the strictest
    // level, so a server cannot strip it to have a highest-security room's
    // key written into the tab's saved state.
    const cfg = ack.config_blob ? await this.decryptConfigBlob(ack.config_blob) : null;
    const level = securityLevelOf(cfg);
    if (ack.config_blob) {
      const cfgTtl = cfg?.ttl;
      if (cfgTtl) {
        const kindMismatch =
          cfgTtl.kind === "none" ? ack.ttl.kind !== "none" : cfgTtl.kind !== ack.ttl.kind;
        const shortenedAbsolute = absoluteTtlShortened(cfgTtl, ack.ttl, ack.elapsed_secs);
        if (kindMismatch || shortenedAbsolute) {
          this.events.onTtlMismatch();
          effectiveTtl =
            cfgTtl.kind === "none"
              ? { kind: "none", secs: 0 }
              : { kind: cfgTtl.kind as typeof ack.ttl.kind, secs: cfgTtl.secs };
        }
      } else {
        this.events.onTtlMismatch();
      }
    }
    this.events.onSecurityLevel?.(level);
    this.securityLevel = level;
    // Members who left while this tab was away count as departures, the same
    // as a PEER_LEAVE it saw (amendment J).
    for (const gone of departedMembers(rosterBefore, [...this.internals.roster.values()])) {
      this.coordinator.memberLeft(gone);
    }
    await this.coordinator.joined(typeof ack.epoch === "number" ? ack.epoch : 0);

    switch (effectiveTtl.kind) {
      case "none":
        this.armExpiryClock({ kind: "none" });
        break;
      case "absolute":
        this.armExpiryClock({
          kind: "absolute",
          deadlinePerfMs: performance.now() + effectiveTtl.secs * 1000,
        });
        break;
      default:
        this.armExpiryClock({
          kind: "idle",
          windowMs: effectiveTtl.secs * 1000,
          lastActivityPerfMs: performance.now(),
        });
        break;
    }

    this.events.onPeersChanged(this.internals.roster.size);
    this.events.onTemper("SECURE");
    this.events.onJoinAck(ack);
    // Resume rather than replay: asking from 0 on every reconnect pulls the
    // entire room log down again each time. With indexes, resume from exactly
    // what this copy holds.
    if (this.socket.isAwaitingKeys) {
      this.syncDeferred = true;
    } else {
      this.socket.sendSyncRequest(this.indexed ? this.doc.cursor.watermark : this.doc.syncFrom());
    }
    // Anything this client wrote that the room never stored is resent by the
    // socket itself, once it has confirmed the join.
  }

  /// A step or handover has given this tab the keys for `epoch`.
  keysAdopted(epoch: number): void {
    this.socket.adoptEpoch(epoch);
    if (this.syncDeferred && !this.socket.isAwaitingKeys) {
      this.syncDeferred = false;
      this.socket.sendSyncRequest(this.indexed ? this.doc.cursor.watermark : this.doc.syncFrom());
    }
  }

  reportKeyStatus(s: KeyStatus): void {
    const alarming = s === "refused" || s === "roster-mismatch" || s === "server-behind";
    this.events.onKeyStatus?.(KEY_STATUS_TEXT[s], alarming);
    if (alarming) this.events.onTemper("WATCH");
  }

  /// After a rotation the elected member snapshots straight away, so the log
  /// soon holds nothing under an older key.
  snapshotSoon(): void {
    setTimeout(() => this.trySnapshot(true), 1_000);
  }

  private async decryptConfigBlob(
    blobB64: string,
  ): Promise<{ ttl: { kind: string; secs: number }; level: SecurityLevel } | null> {
    try {
      const blob = fromB64(blobB64);
      const iv = blob.slice(0, 12);
      const ct = blob.slice(12);
      const pt = await crypto.subtle.decrypt(
        { name: "AES-GCM", iv },
        this.cfg.contentKey,
        ct,
      );
      const parsed = JSON.parse(new TextDecoder().decode(pt)) as {
        ttl: { kind: string; secs: number };
        level?: unknown;
      };
      return { ttl: parsed.ttl, level: parseSecurityLevel(parsed.level) };
    } catch {
      return null;
    }
  }

  private expiry: ExpiryModel = { kind: "none" };
  private expiryTimer: ReturnType<typeof setInterval> | null = null;
  private wiped = false;

  /// Absolute TTL anchors at join against the AEAD-protected config value
  /// when present. Idle TTL is an activity-driven window — any local edit,
  /// remote update or peer change refreshes it, so a tab never
  /// self-destructs mid-session while the server still considers the room
  /// alive.
  private visibilityHandler: (() => void) | null = null;

  private armExpiryClock(model: ExpiryModel): void {
    this.expiry = model;
    if (this.expiryTimer) clearInterval(this.expiryTimer);
    this.expiryTimer = null;
    // Re-armed on every JOIN_ACK, so every reconnect used to add another
    // listener that was never removed.
    if (this.visibilityHandler) {
      document.removeEventListener("visibilitychange", this.visibilityHandler);
      this.visibilityHandler = null;
    }
    if (model.kind === "none") return;
    this.expiryTimer = setInterval(() => this.tickExpiry(), 250);
    this.visibilityHandler = () => this.tickExpiry();
    document.addEventListener("visibilitychange", this.visibilityHandler);
    this.tickExpiry();
  }

  refreshActivity(): void {
    if (this.expiry.kind === "idle") {
      this.expiry.lastActivityPerfMs = performance.now();
    }
  }

  private tickExpiry(): void {
    if (this.wiped) return;
    let remaining: number;
    switch (this.expiry.kind) {
      case "none":
        return;
      case "absolute":
        remaining = this.expiry.deadlinePerfMs - performance.now();
        break;
      case "idle":
        remaining =
          this.expiry.lastActivityPerfMs + this.expiry.windowMs - performance.now();
        break;
    }
    if (remaining <= 0) {
      this.wiped = true;
      if (this.expiryTimer) clearInterval(this.expiryTimer);
      void this.purgeNow();
      return;
    }
    if (remaining <= 10_000) {
      this.events.onCountdown({ kind: "burn", remainingMs: remaining });
    } else if (remaining <= 60_000) {
      this.events.onCountdown({ kind: "armed", remainingMs: remaining });
    } else if (remaining <= 5 * 60_000) {
      this.events.onCountdown({ kind: "watch", remainingMs: remaining });
    } else {
      this.events.onCountdown({ kind: "normal", remainingMs: remaining });
    }
  }

  /// `remainingSecs` is what the server says is left, not what we asked for.
  /// The server clamps extensions at a ceiling, so adding our own request to
  /// the local clock would drift past the real deadline — and the extender
  /// used to count its own request twice, once locally and once from the
  /// broadcast it also receives.
  handleTtlExtended(remainingSecs: number, addSecs: number, addedBy: string): void {
    if (this.expiry.kind === "absolute" && remainingSecs > 0) {
      this.expiry.deadlinePerfMs = performance.now() + remainingSecs * 1000;
    } else if (this.expiry.kind === "idle") {
      if (remainingSecs > 0) this.expiry.windowMs = remainingSecs * 1000;
      this.refreshActivity();
    }
    this.wiped = false;
    this.events.onShredState(`EXTENDED +${Math.round(addSecs / 60)}m by ${addedBy.slice(0, 6)}…`);
  }

  extendExpiry(addSecs = 1800): void {
    // Fire and wait: the server echoes the authoritative deadline back to
    // every peer, this one included.
    this.socket.sendTtlExtend(addSecs);
  }

  tallySummary(): { approved: number; total: number; waitingOn?: string } {
    const t = this.machine.tally();
    const waiting = this.machine.waitingOn()[0];
    return { approved: t.approvals, total: t.total, waitingOn: waiting };
  }

  private handleRemoteUpdate(envelope: Uint8Array): void {
    if (envelope.length < 4) return;
    const len = new DataView(envelope.buffer, envelope.byteOffset, envelope.byteLength)
      .getUint32(0, false);
    if (len === 0) return;
    // A peer holding the room key can still send a malformed CRDT update.
    // These handlers run from an unawaited promise, so a throw here becomes
    // an unhandled rejection and silently stops the rest of the pipeline.
    try {
      this.doc.applyRemote(envelope);
    } catch {
      return;
    }
    this.refreshActivity();
    void this.refreshOwnHash();
  }

  private handleSnapshot(_sender: Uint8Array, covers: bigint, blobWithPrefix: Uint8Array): void {
    try {
      this.doc.applyRemote(blobWithPrefix);
    } catch {
      return;
    }
    const c = Number(covers);
    this.doc.cursor.noteBelow(c);
    if (Number.isSafeInteger(c)) this.lastCovered = Math.max(this.lastCovered, c);
    void this.refreshOwnHash();
  }

  /// Deterministic snapshot election (spec §5.8): the peer with the lowest
  /// (joined_at_seq, peer_id) snapshots when thresholds fire.
  private startSnapshotLoop(): void {
    if (this.snapshotTimer) return;
    this.snapshotTimer = setInterval(() => this.trySnapshot(false), 30_000);
  }

  private trySnapshot(force: boolean): void {
    if (performance.now() - this.internals.joinPerfMs < 60_000) return;
    // A snapshot claims to cover the log up to an index. Taken while this
    // client still has updates the room has not stored, or parts of one it is
    // still receiving, that claim would be wrong.
    if (!this.socket.readyForSnapshot()) return;
    const roster = [...this.internals.roster.values()];
    if (!roster.length) return;
    const me = toB64(hexToBytes(this.cfg.roomIdHex)) && this.internals.myPeerId;
    const elected = [...roster].sort((a, b) =>
      a.joinedAtSeq !== b.joinedAtSeq
        ? a.joinedAtSeq - b.joinedAtSeq
        : cmpBytes(a.peerId, b.peerId),
    )[0];
    if (toB64(elected.peerId) !== me) return;
    const covers = snapshotCover({
      indexed: this.indexed,
      watermark: this.doc.cursor.watermark,
      lastCovered: this.lastCovered,
      baseIndex: this.doc.baseIndex,
      storedCount: this.doc.storedCount,
    });
    if (covers === null) return;
    if (!force && !this.doc.shouldSnapshot(BigInt(Math.max(covers, 1)))) return;
    void this.doc.createSnapshot(BigInt(covers)).then((made) => {
      if (made) this.lastCovered = Math.max(this.lastCovered, covers);
    });
  }

  setSteadyTraffic(on: boolean, intervalMs = 400): void {
    if (this.steadyTimer) {
      clearInterval(this.steadyTimer);
      this.steadyTimer = null;
    }
    if (!on) return;
    this.steadyTimer = setInterval(() => {
      // Cover traffic goes out as AWARENESS, not DOC_UPDATE. The server
      // appends every DOC_UPDATE to the room log and cannot tell padded cover
      // frames from padded real edits — that is the point of the padding — so
      // sending it as an update quietly ate the room's log budget until real
      // edits started being refused. AWARENESS is relayed and never stored.
      void this.socket.sendAwareness(wrapWithLengthAndPad(new Uint8Array(0)));
    }, intervalMs);
  }

  /// When each roster entry was first seen by this client. Presence is
  /// broadcast on a heartbeat, so a peer who has just arrived and not yet
  /// spoken is genuinely absent from the awareness map — measured at 10-12
  /// seconds before a peer became visible by liveness alone. Counting them
  /// during that window is what stops a correct arrival looking like a
  /// disconnection.
  private rosterSeenAt = new Map<string, number>();
  private hashPending = false;
  private lastDocChangeAt = Date.now();
  private divergenceReported = false;

  private async refreshOwnHash(): Promise<void> {
    // Digesting the whole document on every remote update is O(doc) per
    // keystroke. One in flight at a time is enough for a divergence check.
    if (this.hashPending) return;
    this.hashPending = true;
    try {
      await this.computeOwnHash();
    } finally {
      this.hashPending = false;
    }
  }

  private async computeOwnHash(): Promise<void> {
    const text = this.doc.value;
    const digest = await crypto.subtle.digest(
      "SHA-256",
      new TextEncoder().encode(text) as BufferSource,
    );
    this.ownHash = Array.from(new Uint8Array(digest).slice(0, 8))
      .map((b) => b.toString(16).padStart(2, "0"))
      .join("");
  }

  /// Compared on the heartbeat rather than on every update, and only once the
  /// document has been still for a while.
  ///
  /// The previous version compared the local hash *at this instant* against
  /// hashes peers had broadcast up to a heartbeat earlier, on every single
  /// remote update. Two people typing are never at the same state at the same
  /// moment, so that fires constantly during ordinary editing — and because
  /// the banner latched and never cleared, one transient mismatch left it up
  /// for the rest of the session. Measured: two clients whose documents were
  /// byte-identical both showed the warning.
  ///
  /// Requiring agreement among a majority of reporters is kept: one peer
  /// broadcasting a made-up hash must not be able to tell everyone else they
  /// have diverged.
  private repairAttemptedAt = 0;

  private evaluateDivergence(): void {
    if (Date.now() - this.lastDocChangeAt < DIVERGENCE_QUIET_MS) return;
    const counts = this.awareness?.foreignHashCounts();
    const reporters = counts ? [...counts.values()].reduce((a, b) => a + b, 0) : 0;
    if (!counts || reporters === 0) return;
    const agreed = [...counts.entries()].sort((a, b) => b[1] - a[1])[0];
    const diverged = !!agreed && agreed[0] !== this.ownHash && agreed[1] * 2 > reporters;

    switch (
      divergenceAction({
        diverged,
        reported: this.divergenceReported,
        repairAttemptedAt: this.repairAttemptedAt,
        now: Date.now(),
      })
    ) {
      case "repair":
        this.repairAttemptedAt = Date.now();
        this.doc.resyncFromStart();
        break;
      case "warn":
        this.divergenceReported = true;
        this.events.onDivergence(true);
        break;
      case "clear":
        this.divergenceReported = false;
        this.repairAttemptedAt = 0;
        this.events.onDivergence(false);
        break;
      case "none":
        break;
    }
  }

  /// Ask the relay for everything again, on request.
  ///
  /// Returns nothing useful on purpose. The server allows one replay per
  /// connection at a time and drops the rest without a reply — correct, since
  /// otherwise a peer could make it clone the whole log at the frame rate —
  /// so a request that arrives during another replay simply does not happen,
  /// and there is no way from here to tell which occurred. The caller must say
  /// it asked, not that it worked.
  resyncNow(): void {
    this.repairAttemptedAt = Date.now();
    this.doc.resyncFromStart();
  }

  ownDocumentHash(): string {
    return this.ownHash;
  }

  private async handleShredFrame(frameType: number, sender: Uint8Array, plaintext: Uint8Array): Promise<void> {
    let decoded: Record<string, unknown>;
    try {
      decoded = cbor2.decode(plaintext) as Record<string, unknown>;
    } catch {
      return;
    }
    if (!decoded || typeof decoded !== "object") return;
    if (frameType === FT.SHRED_REQUEST) {
      const request = decoded as unknown as ShredRequest;
      if (request.initiatorPeerIdB64 === this.internals.myPeerId) return;
      const accepted = await this.machine.onRequestIncoming(request);
      if (accepted) this.events.onShredPrompt(request);
      return;
    }
    if (frameType === FT.SHRED_VOTE) {
      await this.machine.onVoteIncoming(decoded as never);
      await this.flushPendingPurge();
      return;
    }
    if (frameType === FT.SHRED_CANCEL) {
      if (!cancelApplies(this.machine.currentRequest(), decoded, toB64(sender))) {
        this.events.onShredRejected("cancel-not-from-initiator");
        return;
      }
      this.machine.reset();
      this.events.onShredState("IDLE");
    }
  }

  async attachEditor(
    monaco: typeof import("monaco-editor"),
    editor: import("monaco-editor").editor.IStandaloneCodeEditor,
  ): Promise<void> {
    const model = editor.getModel();
    if (!model) return;
    const seeded = this.doc.value;
    if (seeded && model.getValue() !== seeded) {
      model.setValue(seeded);
    }
    this.binding = bindMonaco(monaco, model, this.doc.ydoc, this.doc.text);
    // refreshOwnHash used to run only for remote updates, so after typing the
    // local hash described a document that no longer existed and compared
    // unequal against everyone else by construction. This covers both
    // directions, and gives the quiet window something to measure.
    this.doc.ydoc.on("update", () => {
      this.lastDocChangeAt = Date.now();
      void this.refreshOwnHash();
    });
    this.awareness = await AwarenessHub.create(
      (pt) => this.socket.sendAwareness(pt),
      this.identity.publicKeyRaw,
    );
    // Announce on arrival rather than waiting for the first heartbeat.
    void this.announcePresence();
    // Heartbeat is an awareness ping (not a sync request): it drives peer
    // liveness detection and divergence comparison without re-requesting
    // the entire log every 10 seconds (review R-3/R-7/R-8).
    const lastLine = 1;
    const lastCol = 1;
    this.heartbeatTimer = setInterval(() => {
      void this.awareness?.broadcastCursor(lastLine, lastCol, this.ownDocumentHash());
      const seen = new Set(
        (this.awareness?.snapshot() ?? []).map((s) => s.senderId),
      );
      const machine = this.machine;
      for (const peerIdB64 of this.internals.roster.keys()) {
        if (peerIdB64 === this.internals.myPeerId) continue;
        if (seen.has(peerIdB64)) machine.noteHeartbeat(peerIdB64);
        else machine.markUnreachable(peerIdB64);
      }
      void this.flushPendingPurge();
      this.evaluateDivergence();
    }, 10_000);

    this.startSnapshotLoop();
    // Every cursor movement used to mean an AEAD encrypt plus a websocket
    // frame — and typing moves the cursor on every keystroke, so the editor
    // was doing crypto per character. Coalesce to at most one frame per
    // 120 ms; presence does not need to be sharper than that.
    let cursorTimer: ReturnType<typeof setTimeout> | null = null;
    let latest: { line: number; column: number } | null = null;
    editor.onDidChangeCursorPosition((e) => {
      latest = { line: e.position.lineNumber, column: e.position.column };
      if (cursorTimer) return;
      cursorTimer = setTimeout(() => {
        cursorTimer = null;
        const p = latest;
        if (p) void this.awareness?.broadcastCursor(p.line, p.column, this.ownDocumentHash());
      }, 120);
    });
    this.cursorTimerRef = () => {
      if (cursorTimer) clearTimeout(cursorTimer);
    };
  }

  setWipeContext(ctx: WipeContext): void {
    this.wipeContext = ctx;
  }

  setInsecure(insecure: boolean): void {
    if (insecure) this.events.onTemper("WATCH");
  }

  dropKeys(): void {
    // CryptoKey references are dropped so the runtime can reclaim the last
    // handles; non-extractable keys cannot be serialised out of the tab.
    // The socket and its cipher hold their own references, so clearing only
    // the session's copy left the key reachable for the tab's lifetime.
    (this as unknown as { cfg: { contentKey: CryptoKey | null } }).cfg.contentKey = null;
    this.socket.dropKeys();
    this.coordinator?.wipe();
    if (this.epochTimer) clearInterval(this.epochTimer);
    this.awareness?.dispose();
    this.awareness = null;
  }

  noteRosterSeen(peerIdB64: string): void {
    if (!this.rosterSeenAt.has(peerIdB64)) this.rosterSeenAt.set(peerIdB64, Date.now());
  }

  /// One presence broadcast, used on arrival and whenever somebody else
  /// arrives. Cheap — it is the same frame the heartbeat sends — and it is
  /// what makes a liveness-derived count appear in about a second instead of
  /// on the next ten-second beat.
  async announcePresence(): Promise<void> {
    try {
      await this.awareness?.broadcastCursor(1, 1, this.ownDocumentHash());
    } catch {
      return;
    }
  }

  /// The roster size. This is the consensus denominator and must stay that
  /// way: a THRESHOLD request carries its bar inside the signed payload, and
  /// every receiver re-derives `supermajorityFor(ownRoster.length)` and
  /// rejects anything lower — so a proposal computed from a smaller number
  /// would be refused by everyone it was sent to.
  get peerCount(): number {
    return this.internals.roster.size;
  }

  /// Who is actually here, as opposed to who the roster still lists.
  ///
  /// The roster is a snapshot taken when this client joined, patched with the
  /// PEER_JOIN and PEER_LEAVE events it happened to receive afterwards. Miss
  /// one — during a disconnect, say — and it over-counts for the rest of the
  /// session with nothing to correct it. Four devices in one room reported 5,
  /// 3, 3 and 3 people at the same moment, all from the same server.
  ///
  /// Awareness state expires on its own after PRESENCE_TIMEOUT_MS, so counting
  /// live presence is self-healing and every client converges on the same
  /// number because they are all watching the same traffic. A device that
  /// reconnects stops broadcasting under its old identity and drops out
  /// without anything having to recognise that it is the same device — which
  /// is how this avoids introducing a linkable cross-session identifier into a
  /// tool that deliberately stores nothing.
  ///
  /// +1 for this client, which never appears in its own awareness map.
  get livePeerCount(): number {
    const live = new Set((this.awareness?.snapshot() ?? []).map((p) => p.senderId));
    const now = Date.now();
    let others = 0;
    for (const id of this.internals.roster.keys()) {
      if (id === this.internals.myPeerId) continue;
      // In the roster and speaking, or in the roster and new enough that it
      // has not had to speak yet. The grace must exceed the heartbeat, or a
      // peer who joins and sits still flickers out and back.
      const seen = this.rosterSeenAt.get(id) ?? 0;
      if (live.has(id) || now - seen < ROSTER_JOIN_GRACE_MS) others += 1;
    }
    return others + 1;
  }

  /// Peers who were here within the grace window and are not now. Shown to
  /// whoever is about to start a shred, so the choice to proceed without them
  /// is made deliberately rather than by accident of timing.
  awayPeers(): AwayPeer[] {
    const cutoff = Date.now() - AWAY_GRACE_MS;
    const out: AwayPeer[] = [];
    for (const [peerIdB64, rec] of this.internals.away) {
      if (rec.leftAt < cutoff) this.internals.away.delete(peerIdB64);
      else out.push({ peerIdB64, handle: rec.handle, leftAt: rec.leftAt });
    }
    return out;
  }

  /// Set when consensus is reached; acted on only once whatever frame
  /// produced it has actually been sent.
  private pendingPurge: string | null = null;

  markPurgeApproved(requestId: string): void {
    this.pendingPurge = requestId;
  }

  /// Safe to call anywhere; does nothing unless consensus was reached.
  private async flushPendingPurge(): Promise<void> {
    if (!this.pendingPurge) return;
    this.pendingPurge = null;
    await this.purgeNow();
  }

  async requestShred(policy: Policy, threshold: number | null, deadlineMs = 60_000): Promise<void> {
    const roomB64 = toB64(hexToBytes(this.cfg.roomIdHex));
    const request = await this.machine.createRequest(roomB64, 0, policy, threshold, deadlineMs);
    // INITIATOR reaches consensus the instant the request is created, so the
    // send has to happen before the purge or no other peer ever hears of it.
    await this.socket.sendShredFrame(FT.SHRED_REQUEST, cbor2.encode({ ...request }));
    await this.flushPendingPurge();
  }

  async respondToShred(request: ShredRequest, choice: "APPROVE" | "REJECT"): Promise<void> {
    const vote = await this.machine.castMyVote(request.requestId, choice);
    if (!vote) return;
    await this.socket.sendShredFrame(FT.SHRED_VOTE, cbor2.encode({ ...vote }));
    await this.flushPendingPurge();
  }

  cancelShred(): void {
    const current = this.machine.currentRequest();
    if (current) {
      void this.socket.sendShredFrame(
        FT.SHRED_CANCEL,
        cbor2.encode({ type: "SHRED_CANCEL", requestId: current.requestId }),
      );
    }
    this.machine.reset();
    this.events.onShredState("IDLE");
  }

  async purgeNow(): Promise<void> {
    this.machine.beginPurge();
    try {
      this.socket.sendPurgeAck("consensus");
    } catch {
      void 0;
    }
    await executeWipe(browserHost(this));
  }

  destroySession(): void {
    if (this.destroyed) return;
    this.destroyed = true;
    if (this.heartbeatTimer) clearInterval(this.heartbeatTimer);
    if (this.snapshotTimer) clearInterval(this.snapshotTimer);
    if (this.steadyTimer) clearInterval(this.steadyTimer);
    if (this.epochTimer) clearInterval(this.epochTimer);
    this.coordinator?.wipe();
    this.cursorTimerRef?.();
    this.binding?.dispose();
    this.doc.destroy();
    this.socket.close();
  }
}

interface WipeContext {
  editor?: import("monaco-editor").editor.IStandaloneCodeEditor | null;
  model?: import("monaco-editor").editor.ITextModel | null;
  previewEl?: HTMLElement | null;
}

export function browserHost(session: Session): import("./shred/wipe").WipeHost {
  const ctx: WipeContext = session.wipeContext ?? {};
  let keyboardBlocked = false;

  return {
    editorDetach() {
      try {
        ctx.editor?.updateOptions({ readOnly: true });
        ctx.model?.pushEOL("LF" as never);
      } catch {
        void 0;
      }
    },
    blockKeyboard() {
      if (keyboardBlocked) return;
      keyboardBlocked = true;
      document.addEventListener(
        "keydown",
        (e) => {
          e.preventDefault();
          e.stopPropagation();
        },
        { capture: true },
      );
      document.addEventListener(
        "beforeinput",
        (e) => {
          e.preventDefault();
          e.stopPropagation();
        },
        { capture: true },
      );
    },
    cancelNetwork() {
      try {
        session.socket.close();
      } catch {
        void 0;
      }
    },
    ydocDestroy() {
      session.destroySession();
    },
    modelDispose() {
      try {
        ctx.model?.dispose();
      } catch {
        void 0;
      }
    },
    editorDispose() {
      try {
        ctx.editor?.dispose();
      } catch {
        void 0;
      }
    },
    previewRootReplaceChildren() {
      ctx.previewEl?.replaceChildren();
    },
    dropKeys() {
      session.dropKeys();
    },
    socketClose() {
      try {
        session.socket.close();
      } catch {
        void 0;
      }
    },
    async clearCaches() {
      if ("caches" in window) {
        const keys = await caches.keys();
        await Promise.all(keys.map((k) => caches.delete(k)));
      }
      try {
        // The wipe sequence is the one legitimate use of storage clearing:
        // it removes anything a prior bug might have leaked (spec §7.8 step 7).
        // eslint-disable-next-line no-restricted-globals
        sessionStorage.clear();
        // eslint-disable-next-line no-restricted-globals
        localStorage?.clear?.();
      } catch {
        void 0;
      }
      const idb = (window as unknown as { indexedDB?: { databases(): Promise<unknown[]>; deleteDatabase(n: string): void } }).indexedDB;
      if (idb && typeof idb.databases === "function") {
        const dbs = (await idb.databases()) as { name?: string }[];
        for (const db of dbs) {
          if (db.name) idb.deleteDatabase(db.name);
        }
      }
    },
    async unregisterServiceWorkers() {
      const regs = navigator.serviceWorker ? await navigator.serviceWorker.getRegistrations() : [];
      await Promise.all(regs.map((r) => r.unregister()));
    },
    navigate(href: string) {
      window.location.replace(href);
    },
  };
}

function toB64(bytes: Uint8Array): string {
  let s = "";
  for (const b of bytes) s += String.fromCharCode(b);
  return btoa(s);
}

function hexToBytes(hex: string): Uint8Array {
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  return out;
}

function cmpBytes(a: Uint8Array, b: Uint8Array): number {
  for (let i = 0; i < Math.min(a.length, b.length); i++) {
    if (a[i] !== b[i]) return a[i] - b[i];
  }
  return a.length - b.length;
}
