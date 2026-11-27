import { confirmsEqual } from "../crypto/epoch";
import { signPayload, type Identity } from "../crypto/identity";
import { algForPubkey, openWrap, sealWrap, wrapKey, type KxPair } from "../crypto/kx";
import type { MemberView } from "../epoch/coordinator";
import type { Wrap } from "../epoch/frame";
import type { Keyring } from "../epoch/keyring";
import { encryptRoomConfig } from "../keys-session";
import type { SecurityLevel } from "../security-level";
import { canonicalRosterBytes } from "../shred/roster";
import { FT, HEADER_LEN } from "../transport/frame";
import {
  decodeCancel,
  decodeCommit,
  decodeRequest,
  decodeVote,
  encodeCancel,
  encodeCommit,
  encodeRequest,
  encodeVote,
  MAX_DEADLINE_MS,
  MAX_VOTES,
  verifyCommit,
  type DecodedCommit,
  type EvictRequest,
  type EvictVote,
} from "./frame";
import { COMMIT_WAIT_MS, EvictMachine, SeenRequests, type EvictState, type Guard, type Proposal } from "./machine";
import { decodeWayIn, deriveReRoot, encodeWayIn, wipeWayIn, type ReRootKeys, type WayIn } from "./reroot";
import { bytesEqual as eq, hexOf, keyDigest, rosterDigest, voteStatement } from "./statement";

/// Removing someone and changing the link, for one session (PROTOCOL.md
/// amendment K). Everything that touches the network, the clock or the rest
/// of the session comes in through `deps`, and every entry point runs on
/// `deps.exclusive`, the queue EPOCH_KEY frames are applied on.
///
/// That queue is not re-entrant and a task that never settles blocks every
/// key update in the room, so no task here calls `exclusive` again and none
/// waits for the network to answer. The wait for a commit's echo is a
/// deadline checked in `tick`.
///
/// Several votes can be open at once, each in its own `EvictMachine` with its
/// own frozen roster, deadline, approvals and commit wait. A vote, a cancel
/// and a commit find their vote by request id. The machines share one record
/// of the request ids seen under the root, so a request id is opened once by
/// this member, whichever vote it would have been. This member has at most
/// one request of its own open, so it holds at most one new way in.

export const DEFAULT_DEADLINE_MS = 60_000;
/// How long a proposer waits for its commit to come back from the server,
/// from the first time it sent it.
export const COMMIT_ECHO_MS = 10_000;
/// How many times a proposer builds its commit again for a new epoch, when a
/// key step lands after it sent the commit and before the commit came back.
/// The votes name the root, which a step does not move, so they still hold.
export const MAX_COMMIT_RESENDS = 3;
/// How long a VOTE or CANCEL that arrived before its REQUEST is held for it.
/// Frames reach the coordinator in the order their decrypts resolve, so the
/// request is usually a moment behind; anything older is let go.
export const EARLY_HOLD_MS = 5_000;
/// How many request ids early frames are held for at once. Each holds at
/// most `MAX_VOTES` votes, one per sender, and one cancel, and one sender has
/// frames held for one id at a time, so no sender can fill the buffer alone.
export const MAX_EARLY_IDS = 8;
/// How many removal requests a member holds open at once, its own included.
/// Each sender has at most one open here, and a request past either bound is
/// refused as "busy". So nobody can keep everyone else from asking by keeping
/// a request of their own open: theirs takes one place, not all of them.
export const MAX_OPEN_REQUESTS = 8;

export interface SealedConfig {
  ttl: { kind: string; secs: number };
  ceilingOptout: boolean;
  level: SecurityLevel;
}

/// A commit this member applied. Whoever receives it owns `way` and
/// `keys.authKey`, and wipes what it does not keep. It is handed over from
/// inside the queue task that re-rooted the keyring, so the receiver runs
/// `EpochCoordinator.reRooted` there.
export interface ReRooted {
  root: number;
  way: WayIn;
  keys: ReRootKeys;
  target: Uint8Array | null;
  targetKey: Uint8Array | null;
}

export interface EvictPrompt {
  requestId: Uint8Array;
  proposerKey: Uint8Array;
  target: Uint8Array | null;
  targetKey: Uint8Array | null;
}

/// Which vote a state is about: its request id, and whether it is this
/// member's own request.
export interface VoteRef {
  requestId: Uint8Array;
  mine: boolean;
}

export interface EvictDeps {
  roomId: Uint8Array;
  identity: Identity;
  kx: KxPair;
  keyring: Keyring;
  now(): number;
  me(): Uint8Array | null;
  members(): MemberView[];
  exclusive<T>(fn: () => Promise<T>): Promise<T>;
  kxOf(m: MemberView): Promise<Uint8Array | null>;
  header(frameType: number, epoch: number): Uint8Array;
  sendSealed(frameType: number, plaintext: Uint8Array): Promise<boolean>;
  sendSigned(header: Uint8Array, body: Uint8Array): boolean;
  sealedConfig(): SealedConfig;
  applyReRoot(r: ReRooted): void;
  prompt(p: EvictPrompt): void;
  /// `vote` is left out only when a commit left this member out and it had
  /// no vote open to end.
  state(s: EvictState, reason?: string, vote?: VoteRef): void;
  refused(reason: string): void;
  leftOut(): void;
  /// This tab holds the key a commit removed, and saw the commit anyway (a
  /// server that did not close it with 4014), so it says so itself.
  removed(): void;
}

interface Pending {
  requestId: Uint8Array;
  /// The root the request named.
  root: number;
  way: WayIn;
  keys: ReRootKeys;
  config: Uint8Array;
  /// When the commit was first sent. The give-up is measured from it, however
  /// often the commit is built again.
  sentAt: number | null;
  /// The header epoch of the last commit sent.
  sentEpoch: number | null;
  /// How many times the commit has been sent.
  sends: number;
}

/// One open vote: its machine, the last state handed to `deps.state` for it,
/// so a state the machine reached on its own (a vote that ran past its
/// deadline, say) is reported once, and whether it is this member's request.
interface Vote {
  id: Uint8Array;
  machine: EvictMachine;
  reported: EvictState;
  mine: boolean;
}

/// Frames for one request id that came before the request did.
interface Early {
  at: number;
  votes: { sender: Uint8Array; vote: EvictVote }[];
  cancel: Uint8Array | null;
}

function epochOfHeader(header: Uint8Array): number | null {
  if (header.length !== HEADER_LEN) return null;
  return new DataView(header.buffer, header.byteOffset, HEADER_LEN).getUint32(20, false);
}

export class EvictCoordinator {
  /// The open votes by request id (hex), in the order they opened. A vote is
  /// dropped once it has ended and its ending has been reported, and every
  /// vote ends when the root moves. A request being checked holds its place
  /// here, still IDLE, while its checks await.
  private votes = new Map<string, Vote>();
  /// Every request id seen under the root, shared by every vote's machine.
  private seen: SeenRequests;
  /// A machine that never opens a vote. It checks commits against the shared
  /// record, whether or not the vote they are for is still open.
  private checker: EvictMachine;
  /// The request a commit was applied for, so a vote or cancel for it still
  /// in flight is ignored.
  private doneId: Uint8Array | null = null;
  /// The request this member opened last, so a commit applied for it after
  /// its vote ended is still reported as DONE, as long as no newer request has
  /// opened since.
  private lastId: Uint8Array | null = null;
  /// The proposer's new way in, from its request until its commit is echoed
  /// or the vote ends.
  private pending: Pending | null = null;
  /// A commit whose echo did not come back in time. Its way in is closed to
  /// any new use and kept only so a late echo of that commit still applies,
  /// until members would also have stopped waiting for it or the root moves;
  /// then it is wiped.
  private late: Pending | null = null;
  /// VOTE and CANCEL frames held for a request not yet received, by request
  /// id, and the root they were held under.
  private early = new Map<string, Early>();
  private earlyRoot = -1;
  private dead = false;

  constructor(private d: EvictDeps) {
    this.seen = new SeenRequests(
      () => d.keyring.rootEpoch,
      (p) => this.holds(p),
    );
    this.checker = this.newMachine();
  }

  private newMachine(): EvictMachine {
    const d = this.d;
    return new EvictMachine({
      roomId: d.roomId,
      me: () => d.me(),
      myKey: () => d.identity.publicKeyRaw,
      members: () => d.members(),
      now: () => d.now(),
      root: () => d.keyring.rootEpoch,
      seen: this.seen,
    });
  }

  /// Whether an open vote, or this member's commit kept for a late echo,
  /// still needs this proposal: the shared record never lets go of one.
  private holds(p: Proposal): boolean {
    for (const v of this.votes.values()) if (v.machine.current() === p) return true;
    return this.late !== null && eq(this.late.requestId, p.request.id);
  }

  /// True while any vote is open or this member's commit is in flight. Steps
  /// wait meanwhile.
  isOpen(): boolean {
    for (const v of this.votes.values()) if (v.machine.isOpen()) return true;
    return this.pending !== null;
  }

  /// The ids of the votes open now, in the order they opened.
  openRequests(): Uint8Array[] {
    return [...this.votes.values()].filter((v) => v.machine.isOpen()).map((v) => v.id.slice());
  }

  /// Whether the vote on this request is open and still collecting answers.
  isVoting(requestId: Uint8Array): boolean {
    return this.votes.get(hexOf(requestId))?.machine.state === "VOTING";
  }

  /// The proposal this member froze for that request id under the current
  /// root, if it opened one and still holds it.
  requestFor(id: Uint8Array): Proposal | null {
    return this.seen.get(id);
  }

  /// This member's own vote, if it has one open.
  private ownVote(): Vote | null {
    for (const v of this.votes.values()) if (v.mine) return v;
    return null;
  }

  /// Whether a request from `sender` (this member, when it asks itself) is
  /// over the bounds: that sender already has one open here, or as many are
  /// open as a member holds. A request whose checks are still running counts.
  private overBounds(sender: Uint8Array): boolean {
    let n = 0;
    for (const v of this.votes.values()) {
      const m = v.machine;
      if (!m.isOpen() && m.state !== "IDLE") continue;
      n += 1;
      const p = m.current();
      if (p && eq(p.proposer, sender)) return true;
    }
    return n >= MAX_OPEN_REQUESTS;
  }

  /// No entry point rejects: a failure of any kind becomes `fallback`.
  private run<T>(fn: () => Promise<T>, fallback: T): Promise<T> {
    try {
      return this.d.exclusive(fn).catch(() => fallback);
    } catch {
      return Promise.resolve(fallback);
    }
  }

  private dropPending(): void {
    if (!this.pending) return;
    wipeWayIn(this.pending.way);
    this.pending.keys.authKey.fill(0);
    this.pending = null;
  }

  private dropLate(): void {
    if (!this.late) return;
    wipeWayIn(this.late.way);
    this.late.keys.authKey.fill(0);
    this.late = null;
  }

  /// The page's callbacks. One that throws changes nothing here: the state,
  /// the way in and the queue are this coordinator's, whatever the page does.
  private say(fn: () => void): void {
    try {
      fn();
    } catch {
      // Ignored on purpose.
    }
  }

  private refused(reason: string): void {
    this.say(() => this.d.refused(reason));
  }

  /// Tells `deps.state` about a vote's state if it moved, lets go of the new
  /// way in once this member's own vote is over without a commit, and drops
  /// a vote that has ended.
  private report(v: Vote, reason?: string): void {
    const m = v.machine;
    if (v.mine && !m.isOpen() && this.pending && eq(this.pending.requestId, v.id)) this.dropPending();
    const s = m.state;
    if (s !== v.reported) {
      v.reported = s;
      if (s !== "IDLE") this.say(() => this.d.state(s, reason, { requestId: v.id.slice(), mine: v.mine }));
    }
    const key = hexOf(v.id);
    if (!m.isOpen() && s !== "IDLE" && this.votes.get(key) === v) this.votes.delete(key);
  }

  /// Lets go of held frames that are too old or from under another root.
  private pruneEarly(): void {
    const root = this.d.keyring.rootEpoch;
    if (root !== this.earlyRoot) {
      this.early.clear();
      this.earlyRoot = root;
    }
    const now = this.d.now();
    for (const [key, e] of this.early) if (now - e.at >= EARLY_HOLD_MS) this.early.delete(key);
  }

  /// Holds a VOTE (or, with `vote` null, a CANCEL) for a request not yet
  /// received. Nothing held is trusted: the machine checks each one when the
  /// request opens. Past any bound the frame is dropped.
  private hold(id: Uint8Array, sender: Uint8Array, vote: EvictVote | null): void {
    this.pruneEarly();
    const key = hexOf(id);
    // A sender's newest frame replaces what it had held for any other id.
    for (const [k, x] of this.early) {
      if (k === key) continue;
      x.votes = x.votes.filter((v) => !eq(v.sender, sender));
      if (x.cancel && eq(x.cancel, sender)) x.cancel = null;
      if (x.votes.length === 0 && !x.cancel) this.early.delete(k);
    }
    let e = this.early.get(key);
    if (!e) {
      if (this.early.size >= MAX_EARLY_IDS) return;
      e = { at: this.d.now(), votes: [], cancel: null };
      this.early.set(key, e);
    }
    if (!vote) {
      if (!e.cancel) e.cancel = sender.slice();
      return;
    }
    if (e.votes.length >= MAX_VOTES || e.votes.some((x) => eq(x.sender, sender))) return;
    e.votes.push({ sender: sender.slice(), vote: { id: vote.id.slice(), vote: vote.vote, sig: vote.sig ? vote.sig.slice() : null } });
  }

  /// How many frames are held for requests not yet received.
  heldFrames(): number {
    let n = 0;
    for (const e of this.early.values()) n += e.votes.length + (e.cancel ? 1 : 0);
    return n;
  }

  /// Replays what was held for a request a vote's machine has just opened,
  /// in the same queue task, through the machine's own checks.
  private async replayEarly(v: Vote): Promise<void> {
    this.pruneEarly();
    const id = v.id;
    const key = hexOf(id);
    const e = this.early.get(key);
    if (!e) return;
    this.early.delete(key);
    if (e.cancel) {
      const guard = v.machine.onCancel(id, e.cancel);
      if (guard) this.refused(guard);
    }
    for (const { sender, vote } of e.votes) {
      if (this.dead || v.machine.state !== "VOTING") return;
      const guard = await v.machine.onVote(vote, sender);
      if (guard) this.refused(guard);
    }
  }

  /// Ends a vote that cannot go on, and lets go of the new way in if the vote
  /// is this member's own.
  private abandon(v: Vote, reason: string): void {
    if (v.mine) this.dropPending();
    v.machine.fail();
    this.report(v, reason);
  }

  /// Ends this member's own vote, the one its new way in belongs to.
  private abandonOwn(reason: string): void {
    const v = this.ownVote();
    if (v) this.abandon(v, reason);
    else this.dropPending();
  }

  /// Ask the room to remove `target`, or nobody (a link change), with `way`
  /// as the new way in. From here this owns `way`.
  propose(target: MemberView | null, way: WayIn, deadlineMs = DEFAULT_DEADLINE_MS): Promise<string | null> {
    return this.run(() => this.proposeNow(target, way, deadlineMs), "failed").then((r) => {
      // Whatever the answer other than null, the way in was never handed on,
      // including when the queue refused the task. A vote that holds it
      // still owns it, whatever went wrong after it opened.
      if (r !== null && this.pending?.way !== way && this.late?.way !== way) wipeWayIn(way);
      return r;
    });
  }

  private async proposeNow(target: MemberView | null, way: WayIn, deadlineMs: number): Promise<string | null> {
    let kept = false;
    let keys: ReRootKeys | null = null;
    try {
      if (this.dead) return "failed";
      const me = this.d.me()?.slice() ?? null;
      if (!me) return "not-joined";
      // One request of its own at a time, and none past the bound on open
      // requests; other members' open requests do not stop it asking.
      if (this.pending !== null || this.overBounds(me)) return "busy";
      if (!Number.isInteger(deadlineMs) || deadlineMs <= 0 || deadlineMs > MAX_DEADLINE_MS) return "failed";
      // The votes name the root, so a key step during the vote changes nothing.
      const root = this.d.keyring.rootEpoch;
      const members = this.d.members();
      let targetId: Uint8Array | null = null;
      let targetKey: Uint8Array | null = null;
      if (target) {
        const entry = members.find((m) => eq(m.peerId, target.peerId));
        const key = entry?.pubkey;
        if (!key || (target.pubkey && !eq(target.pubkey, key))) return "bad-target";
        if (eq(entry.peerId, me) || eq(key, this.d.identity.publicKeyRaw) || !algForPubkey(key)) return "bad-target";
        targetId = entry.peerId.slice();
        targetKey = key.slice();
      }
      keys = await deriveReRoot(way);
      const cfg = this.d.sealedConfig();
      const config = await encryptRoomConfig(keys.contentKey, cfg.ttl, cfg.ceilingOptout, cfg.level);
      const id = crypto.getRandomValues(new Uint8Array(16));
      // Every vote names the target's key by its digest, so the server knows
      // every connection holding it, not only the one named.
      const targetKeyDigest = targetKey ? await keyDigest(targetKey) : null;
      const sig = await signPayload(this.d.identity, voteStatement(this.d.roomId, id, root, targetId, targetKeyDigest, me, keys.verifier));
      const req: EvictRequest = {
        id,
        root,
        target: targetId,
        targetKey,
        verifier: keys.verifier,
        roster: await rosterDigest(members),
        policy: "UNANIMOUS",
        deadline: deadlineMs,
        sig,
      };
      const frame = encodeRequest(req);
      // Checked again after the last await: nothing above may have moved.
      const meNow = this.d.me();
      if (this.dead || !meNow || !eq(meNow, me)) return "failed";
      if (this.pending !== null || this.overBounds(me) || this.d.keyring.rootEpoch !== root) return "busy";
      // Someone joined or left meanwhile: every member would refuse the
      // request's roster digest, so it is not sent.
      if (!eq(canonicalRosterBytes(this.d.members()), canonicalRosterBytes(members))) return "roster-changed";
      const machine = this.newMachine();
      machine.start(req, me, members, targetKeyDigest);
      const v: Vote = { id: id.slice(), machine, reported: "IDLE", mine: true };
      this.votes.set(hexOf(id), v);
      this.lastId = id.slice();
      this.pending = { requestId: id, root, way, keys, config, sentAt: null, sentEpoch: null, sends: 0 };
      kept = true;
      let sent = false;
      try {
        sent = await this.d.sendSealed(FT.EVICT_REQUEST, frame);
      } catch {
        this.abandon(v, "send-failed");
        return "failed";
      }
      if (this.dead || this.pending?.requestId !== id) return "failed";
      if (!sent) {
        this.abandon(v, "not-sent");
        return "not-sent";
      }
      this.report(v);
      // A room of two: the proposer's approval is all there is.
      if (machine.state === "APPROVED") await this.commitNow();
      return null;
    } finally {
      if (!kept) {
        wipeWayIn(way);
        keys?.authKey.fill(0);
      }
    }
  }

  /// This member's answer to the request `requestId`. An answer to a vote
  /// that is not open here changes nothing.
  vote(requestId: Uint8Array, choice: "APPROVE" | "REJECT"): Promise<void> {
    return this.run(() => this.voteNow(requestId, choice), undefined);
  }

  private async voteNow(requestId: Uint8Array, choice: "APPROVE" | "REJECT"): Promise<void> {
    const key = hexOf(requestId);
    const v = this.votes.get(key);
    const p = v?.machine.current() ?? null;
    const me = this.d.me();
    if (this.dead || !v || !p || !me || v.machine.state !== "VOTING") return;
    // The target is not asked, and the proposer's request already is its vote.
    if (eq(p.proposer, me) || !p.policySet.some((r) => eq(r.peerId, me))) return;
    // Already approved, before a key step or not: its vote stands.
    if (v.machine.hasApproved(me)) return;
    const r = p.request;
    if (choice === "REJECT") {
      v.machine.rejectOwn();
      this.report(v);
      await this.d.sendSealed(FT.EVICT_VOTE, encodeVote({ id: r.id, vote: "REJECT", sig: null }));
      return;
    }
    // The digest the machine took from the request's `targetKey`, which it
    // checked against this member's roster before the vote opened.
    const sig = await signPayload(this.d.identity, voteStatement(this.d.roomId, r.id, r.root, r.target, p.targetKeyDigest, me, r.verifier));
    if (this.dead || this.votes.get(key) !== v || v.machine.current() !== p || v.machine.state !== "VOTING") return;
    v.machine.recordOwn(sig);
    this.report(v);
    if (v.machine.state !== "VOTING" && v.machine.state !== "APPROVED") return;
    let sent = false;
    try {
      sent = await this.d.sendSealed(FT.EVICT_VOTE, encodeVote({ id: r.id, vote: "APPROVE", sig }));
    } catch {
      // Handled below.
    }
    if (!sent && this.votes.get(key) === v && v.machine.current() === p && v.machine.isOpen()) this.abandon(v, "not-sent");
  }

  /// Withdraws this member's own request, the only one it can withdraw.
  cancel(): Promise<void> {
    return this.run(async () => {
      const v = this.ownVote();
      const p = v?.machine.current() ?? null;
      const me = this.d.me();
      if (this.dead || !v || !p || !me || !eq(p.proposer, me) || !v.machine.isOpen() || this.pending?.sentAt != null) return;
      // Whether it went out or not, the proposer ends its own vote; members
      // that never hear of it fail on their own deadline or commit wait.
      await this.d.sendSealed(FT.EVICT_CANCEL, encodeCancel({ id: p.request.id }));
      if (this.dead || this.votes.get(hexOf(v.id)) !== v || v.machine.current() !== p || !v.machine.isOpen()) return;
      v.machine.cancel();
      this.dropPending();
      this.report(v);
    }, undefined);
  }

  receiveFrame(frameType: number, sender: Uint8Array, plaintext: Uint8Array): Promise<void> {
    return this.run(() => this.receiveFrameNow(frameType, sender, plaintext), undefined);
  }

  private async receiveFrameNow(frameType: number, sender: Uint8Array, plaintext: Uint8Array): Promise<void> {
    const me = this.d.me();
    if (this.dead || !me || eq(sender, me)) return;
    if (frameType === FT.EVICT_REQUEST) {
      const req = decodeRequest(plaintext);
      if (!req) return this.refused("malformed");
      // A vote that ran out, or whose root moved, is reported as such, and
      // gives up its place, before a new request is counted against the
      // bounds. Only votes still collecting approvals: an approved one
      // waiting on its commit is the session timer's to end, since the
      // proposer's way in may still be kept for a late echo.
      for (const v of [...this.votes.values()]) if (v.machine.state === "VOTING") this.report(v, v.machine.tick(this.d.now())?.reason);
      // Another copy of a request this member already holds, open or settled,
      // asks nothing new.
      if (this.seen.has(req.id)) return;
      // One open request per sender, and a bound on all of them. Received,
      // so never judged later as a request this member did not see.
      if (this.overBounds(sender)) {
        this.seen.mark(req.id, null);
        return this.refused("busy");
      }
      const key = hexOf(req.id);
      const v: Vote = { id: req.id.slice(), machine: this.newMachine(), reported: "IDLE", mine: false };
      // It holds its place while its checks await, so the bounds above still
      // hold when it opens.
      this.votes.set(key, v);
      let guard: Guard | null = "malformed";
      try {
        guard = await v.machine.onRequest(req, sender);
      } finally {
        if (guard !== null && this.votes.get(key) === v) this.votes.delete(key);
      }
      if (guard) return this.refused(guard);
      this.lastId = req.id.slice();
      // Votes and a cancel that overtook the request count now, before
      // anyone is asked: a cancelled or refused request asks nobody.
      await this.replayEarly(v);
      if (this.dead) return;
      this.report(v);
      if (this.votes.get(key) !== v || v.machine.current()?.request !== req || v.machine.state !== "VOTING") return;
      // The person to be removed is not asked: the vote is about them. That
      // includes this tab under an earlier connection's peer id, which the
      // request names by its signing key.
      if (req.target && (eq(req.target, me) || (req.targetKey && eq(req.targetKey, this.d.identity.publicKeyRaw)))) return;
      const from = this.d.members().find((m) => eq(m.peerId, sender));
      const proposerKey = from?.pubkey;
      if (proposerKey) this.say(() => this.d.prompt({ requestId: req.id, proposerKey, target: req.target, targetKey: req.targetKey }));
      return;
    }
    if (frameType !== FT.EVICT_VOTE && frameType !== FT.EVICT_CANCEL) return;
    const v = frameType === FT.EVICT_VOTE ? decodeVote(plaintext) : null;
    const c = frameType === FT.EVICT_CANCEL ? decodeCancel(plaintext) : null;
    const id = v?.id ?? c?.id;
    if (!id) return this.refused("malformed");
    // A vote or cancel still in flight when the commit was applied.
    if (this.doneId && eq(this.doneId, id)) return;
    // One that overtook its request waits for it.
    if (!this.seen.has(id)) return this.hold(id, sender, v);
    // One for a request this member received but refused has nothing to
    // count toward, and is not shown as a refusal of its own.
    const placed = this.seen.get(id);
    if (!placed) return;
    const vote = this.votes.get(hexOf(id));
    // One for a vote that has ended here counts toward nothing.
    if (!vote) return this.refused(v || eq(placed.proposer, sender) ? "not-voting" : "cancel-not-from-proposer");
    if (v) {
      const guard = await vote.machine.onVote(v, sender);
      if (this.dead) return;
      this.report(vote);
      if (guard) return this.refused(guard);
      const pend = this.pending;
      if (vote.mine && vote.machine.state === "APPROVED" && pend && eq(pend.requestId, vote.id) && pend.sentEpoch === null) await this.commitNow();
      return;
    }
    const guard = vote.machine.onCancel(id, sender);
    this.report(vote);
    if (guard) return this.refused(guard);
  }

  /// The proposer, once every approval is in: seal the new way in to each
  /// member who approved, and send the commit. Never throws: a commit that
  /// cannot be built ends the vote.
  private async commitNow(): Promise<void> {
    try {
      await this.buildAndSend();
    } catch {
      this.abandonOwn("commit-failed");
    }
  }

  /// A key step landed after this member sent its commit and before the
  /// commit came back. The server takes a commit only at the room's current
  /// epoch, so the one sent can never be echoed: it is built again for the new
  /// epoch (a new header, tail root, wraps and signature) and sent again, at
  /// most `MAX_COMMIT_RESENDS` times for one vote. The votes are reused as
  /// they are, since they name the root. A commit that was never sent because
  /// the epoch moved while it was built is sent here too.
  private async resendIfStepped(): Promise<void> {
    const pend = this.pending;
    const own = pend ? this.votes.get(hexOf(pend.requestId)) : undefined;
    if (this.dead || !pend || own?.machine.state !== "APPROVED") return;
    if (pend.sentEpoch === this.d.keyring.current.epoch) return;
    if (pend.sentAt !== null && pend.sends > MAX_COMMIT_RESENDS) return;
    await this.commitNow();
  }

  /// Called after this member applied a key step, from inside the task that
  /// applied it: the work is queued behind that task, never run inside it.
  stepped(): Promise<void> {
    return this.run(() => this.resendIfStepped(), undefined);
  }

  private async buildAndSend(): Promise<void> {
    const pend = this.pending;
    const key = pend ? hexOf(pend.requestId) : "";
    const v = pend ? this.votes.get(key) : undefined;
    const p = v?.machine.current() ?? null;
    const me = this.d.me();
    if (this.dead || !pend || !v || !p || !me || v.machine.state !== "APPROVED") return;
    // The votes name the root: a re-root ended this vote, a step did not.
    if (this.d.keyring.rootEpoch !== p.request.root) return this.abandon(v, "root-moved");
    // The commit goes under the room's current epoch, and its tail names the
    // root one above it. Sent once at this epoch already: nothing to do.
    const epoch = this.d.keyring.current.epoch;
    if (pend.sentEpoch === epoch) return;
    const root = epoch + 1;
    const header = this.d.header(FT.EVICT_COMMIT, epoch);
    const wraps: Wrap[] = [];
    // Only the members who approved get the new way in: nobody who arrived
    // during the vote, and not the target or a connection holding its key.
    // Built again each time: the wrap key covers the root, and the header,
    // which names the epoch, is each wrap's associated data. The encoded way
    // in is zeroed after every build.
    const payload = encodeWayIn(pend.way);
    try {
      for (const m of p.policySet) {
        if (eq(m.peerId, me)) continue;
        // The member as it is listed now, holding the key it voted with.
        const view = this.d.members().find((x) => eq(x.peerId, m.peerId));
        if (!view?.pubkey || !m.pubkey || !eq(view.pubkey, m.pubkey)) continue;
        const kxPub = await this.d.kxOf(view);
        if (!kxPub) continue;
        try {
          const key = await wrapKey(this.d.kx, kxPub, this.d.roomId, root, me, m.peerId);
          // The ciphertext is exactly the encoded way in and the tag.
          const { iv, ct } = await sealWrap(key, header, payload);
          wraps.push({ p: m.peerId.slice(), iv, ct });
        } catch {
          // A key nobody can agree with: this member is left out and needs
          // the new way in from someone.
        }
      }
    } finally {
      payload.fill(0);
    }
    const body = await encodeCommit(
      header,
      {
        requestId: p.request.id,
        target: p.request.target,
        targetKeyDigest: p.targetKeyDigest,
        verifier: p.request.verifier,
        salt: pend.way.salt,
        config: pend.config,
        votes: v.machine.ballots(),
      },
      { root, sender: me.slice(), confirm: pend.keys.confirm, wraps },
      this.d.identity,
    );
    // Checked again after the awaits above.
    if (this.dead || this.pending !== pend || this.votes.get(key) !== v || v.machine.current() !== p || v.machine.state !== "APPROVED") return;
    if (this.d.keyring.rootEpoch !== p.request.root) return this.abandon(v, "root-moved");
    // A step landed while it was built: this one names an epoch the room has
    // left. The next look (`stepped`, or the timer) builds it again.
    if (this.d.keyring.current.epoch !== epoch) return;
    pend.sentAt ??= this.d.now();
    pend.sentEpoch = epoch;
    pend.sends += 1;
    if (!this.d.sendSigned(header, body)) this.abandon(v, "not-sent");
  }

  receiveCommit(header: Uint8Array, headerEpoch: number, sender: Uint8Array, body: Uint8Array): Promise<void> {
    return this.run(() => this.receiveCommitNow(header, headerEpoch, sender, body), undefined);
  }

  private async receiveCommitNow(header: Uint8Array, headerEpoch: number, sender: Uint8Array, body: Uint8Array): Promise<void> {
    const me = this.d.me()?.slice() ?? null;
    if (this.dead || !me) return;
    // The epoch is the one the signed header names; a separate one that
    // disagrees with it is refused rather than believed.
    const epoch = epochOfHeader(header);
    if (epoch === null || epoch !== headerEpoch) return this.refused("malformed-commit");
    const dec = decodeCommit(body);
    if (!dec) return this.refused("malformed-commit");
    const { clear, tail } = dec;
    const ring = this.d.keyring;
    // A commit for an epoch this member has left changes nothing.
    if (epoch < ring.current.epoch) return;
    // Checked before a commit can say anything, at this epoch or a later one:
    // a real member signed it, for the header it came under, and voted for it.
    if (tail.root !== epoch + 1 || !eq(tail.sender, sender)) return this.refused("malformed-commit");
    // Only someone who approved may send a commit, as the server also checks.
    if (!clear.votes.some((v) => eq(v.voter, sender))) return this.refused("commit-policy");
    const from = this.d.members().find((m) => eq(m.peerId, sender));
    const alg = from?.pubkey ? algForPubkey(from.pubkey) : null;
    if (!from?.pubkey || !alg || !(await verifyCommit(header, dec, alg, from.pubkey))) return this.refused("commit-signature");
    if (this.dead || ring.current.epoch > epoch) return;
    if (epoch > ring.current.epoch) {
      // The room moved where this member cannot follow without the new way
      // in: a member signed a commit for an epoch it has not reached. Every
      // vote it had open is over, and its own new way in, kept or not, goes.
      this.dropPending();
      this.dropLate();
      for (const v of [...this.votes.values()]) {
        if (!v.machine.isOpen()) continue;
        v.machine.fail();
        this.report(v, "left-out");
      }
      this.say(() => this.d.leftOut());
      return;
    }
    // The votes must name this member's own root. A commit whose votes name
    // a root the room has left fails their signatures here.
    const claim = {
      id: clear.requestId,
      root: ring.rootEpoch,
      target: clear.target,
      targetKeyDigest: clear.targetKeyDigest,
      verifier: clear.verifier,
      votes: clear.votes,
    };
    // The request this member saw for that id, if it still holds it. Only a
    // commit for one of these is ever applied: in an honest room everyone
    // wrapped for approved, so saw the request.
    const placed = this.seen.get(clear.requestId);
    // Also checks that the digest is SHA-256 of the key the request named
    // (or, for a request this member cannot place, of the named peer's roster
    // key).
    if (!(await this.checker.commitSatisfies(claim))) return this.refused("commit-policy");
    const holdsTargetKey = clear.targetKeyDigest !== null && eq(clear.targetKeyDigest, await keyDigest(this.d.identity.publicKeyRaw));

    // Everything above awaited: look again before acting on any of it.
    const meNow = this.d.me();
    if (this.dead || !meNow || !eq(meNow, me) || ring.current.epoch !== epoch) return;
    if (this.seen.get(clear.requestId) !== placed) return;

    // This connection is the one named, or this tab holds the key the votes
    // name (a connection opened again under a new peer id, say), so it was
    // removed whatever its peer id is now, and whatever it made of the
    // request. It says so only after the checks above, which hold the commit
    // to the request it saw or, if it cannot place one, to what a dishonest
    // commit can fail.
    // The server closes such a connection with 4014; if it sees the commit
    // anyway, it has no wrap, and says so itself.
    if (holdsTargetKey || (clear.target !== null && eq(clear.target, me))) {
      this.dropPending();
      this.dropLate();
      this.endVoteFor(clear.requestId);
      this.say(() => this.d.removed());
      return;
    }

    // A commit for a request this member never saw, refused, or no longer
    // holds: the checks a member that never saw it can make passed, so the
    // room's way in changed without it, whether or not the votes cover the
    // roster it sees now (people who joined during the vote, a voter that
    // left before this was read). No wrap is opened and the keyring is not
    // touched.
    if (!placed) return this.leftOutOfCommit();
    // A backstop to the request's own check: the votes were held to a policy
    // set that needed this member's approval under this tab's own key. One
    // that did not (a roster that left it out, or listed its peer id under
    // another key) says nothing about what this member agreed to, so its wrap
    // is never opened.
    const myKey = this.d.identity.publicKeyRaw;
    if (!placed.policySet.some((r) => eq(r.peerId, me) && r.pubkey !== undefined && eq(r.pubkey, myKey))) {
      return this.leftOutOfCommit();
    }

    const pend = this.pending;
    const late = this.late;
    const fromMe = eq(sender, me);
    const mine = fromMe && pend !== null && eq(pend.requestId, clear.requestId) ? pend : null;
    const mineLate = fromMe && !mine && late !== null && eq(late.requestId, clear.requestId) ? late : null;
    let way: WayIn | null = null;
    let keys: ReRootKeys | null = null;
    let handed = false;
    try {
      if (mine) {
        way = mine.way;
        keys = mine.keys;
        this.pending = null;
      } else if (mineLate) {
        // Its own commit, echoed after it gave up on it.
        way = mineLate.way;
        keys = mineLate.keys;
        this.late = null;
      } else {
        way = await this.unwrap(header, dec, from, me);
        if (!way) return this.leftOutOfCommit();
      }
      // A refusal of this member's own commit ends its vote, which nothing
      // else would, since its new way in is gone.
      const refuse = (reason: string): void => {
        if (mine) {
          const own = this.votes.get(hexOf(clear.requestId));
          if (own?.mine) this.abandon(own, reason);
        }
        this.refused(reason);
      };
      keys ??= await deriveReRoot(way);
      if (!eq(keys.verifier, clear.verifier) || !eq(way.salt, clear.salt) || !confirmsEqual(keys.confirm, tail.confirm)) {
        return refuse("commit-keys");
      }
      if (!(await this.configMatches(clear.config, keys.contentKey))) return refuse("commit-config");
      // The request named the target's key, and the commit's digest was
      // checked against it.
      const named = placed.request.targetKey;
      const targetKey = clear.targetKeyDigest && named ? named.slice() : null;
      // The last look before the keyring changes: nothing below awaits except
      // the re-root itself, which checks the epoch again.
      const meLast = this.d.me();
      if (this.dead || !meLast || !eq(meLast, me) || ring.current.epoch !== epoch) return;
      const root = await ring.reroot(tail.root, keys.contentKey, keys.chainKey);
      if (!root) return refuse("commit-stale");
      // From here on it is all synchronous.
      if (this.dead) return;
      // A different proposer's commit ended whatever this member had open,
      // and the epoch it was waiting at is gone.
      this.dropPending();
      this.dropLate();
      this.early.clear();
      this.endVoteFor(clear.requestId);
      this.d.applyReRoot({ root: tail.root, way, keys, target: clear.target, targetKey });
      handed = true;
    } finally {
      if (!handed) {
        if (way) wipeWayIn(way);
        keys?.authKey.fill(0);
      }
    }
  }

  /// A commit re-rooted the room. The vote it was for is done; every other
  /// vote still open here ends as one whose root moved, since it named the
  /// root the room has left. A vote for that request that already ended here
  /// is reported DONE too, if no newer request has opened since.
  private endVoteFor(requestId: Uint8Array): void {
    this.doneId = requestId.slice();
    const done = this.votes.get(hexOf(requestId));
    if (!done && this.lastId && eq(this.lastId, requestId)) {
      const mine = this.late !== null && eq(this.late.requestId, requestId);
      this.say(() => this.d.state("DONE", undefined, { requestId: requestId.slice(), mine }));
    }
    for (const v of [...this.votes.values()]) {
      if (v === done) {
        v.machine.finish();
        this.report(v);
      } else if (v.machine.isOpen()) {
        v.machine.fail();
        this.report(v, "root-moved");
      }
    }
  }

  /// The room's way in changed and this member holds no wrap it can use:
  /// every vote it had open is over, and it needs the new way in from
  /// someone who was there.
  private leftOutOfCommit(): void {
    this.dropPending();
    this.dropLate();
    let said = false;
    for (const v of [...this.votes.values()]) {
      v.machine.fail();
      v.reported = "IDLE";
      this.report(v, "left-out");
      said = true;
    }
    if (!said) this.say(() => this.d.state("FAILED", "left-out"));
    this.say(() => this.d.leftOut());
  }

  private async unwrap(header: Uint8Array, dec: DecodedCommit, from: MemberView, me: Uint8Array): Promise<WayIn | null> {
    const w = dec.tail.wraps.find((x) => eq(x.p, me));
    if (!w) return null;
    const kxPub = await this.d.kxOf(from);
    if (!kxPub) return null;
    let pt: Uint8Array | null = null;
    try {
      const key = await wrapKey(this.d.kx, kxPub, this.d.roomId, dec.tail.root, from.peerId, me);
      pt = await openWrap(key, header, w.iv, w.ct);
      return decodeWayIn(pt);
    } catch {
      return null;
    } finally {
      pt?.fill(0);
    }
  }

  /// The re-sealed config must open under the new content key and say what
  /// the room's config says now: a commit cannot change the room's expiry or
  /// lower its security level.
  private async configMatches(blob: Uint8Array, key: CryptoKey): Promise<boolean> {
    if (blob.length < 12 + 16) return false;
    try {
      const pt = await crypto.subtle.decrypt({ name: "AES-GCM", iv: blob.slice(0, 12) }, key, blob.slice(12));
      const parsed = JSON.parse(new TextDecoder().decode(pt)) as { ttl?: { kind?: unknown; secs?: unknown }; level?: unknown };
      const cur = this.d.sealedConfig();
      return parsed.level === cur.level && parsed.ttl?.kind === cur.ttl.kind && parsed.ttl?.secs === cur.ttl.secs;
    } catch {
      return false;
    }
  }

  memberLeft(m: MemberView): Promise<void> {
    return this.run(async () => {
      if (this.dead) return;
      for (const v of [...this.votes.values()]) {
        const reason = v.machine.memberLeft(m.peerId);
        if (reason) this.report(v, reason);
      }
    }, undefined);
  }

  /// This tab joined again under a new peer id. Everyone else has seen its
  /// previous connection leave, so a vote that needs it under that id, or
  /// that it asked under that id, has failed for them already; it ends here
  /// too, rather than holding this tab busy until its deadline.
  rejoined(previous: Uint8Array): Promise<void> {
    return this.run(async () => {
      if (this.dead) return;
      for (const v of [...this.votes.values()]) {
        const reason = v.machine.memberLeft(previous);
        if (reason) this.report(v, reason);
      }
    }, undefined);
  }

  /// Once a second, from the session's timer.
  tick(): Promise<void> {
    return this.run(async () => {
      if (this.dead) return;
      const now = this.d.now();
      this.pruneEarly();
      const late = this.late;
      if (late && (late.sentAt === null || now - late.sentAt >= COMMIT_WAIT_MS || this.d.keyring.rootEpoch !== late.root)) {
        this.dropLate();
      }
      const pend = this.pending;
      if (pend?.sentAt != null && now - pend.sentAt >= COMMIT_ECHO_MS) {
        // Given up and reported now, but its way in is kept, closed, in case
        // the echo is only late: members still wait for the commit.
        this.dropLate();
        this.late = pend;
        this.pending = null;
        const own = this.votes.get(hexOf(pend.requestId));
        if (own) {
          own.machine.fail();
          this.report(own, "no-echo");
        }
      }
      for (const v of [...this.votes.values()]) {
        const changed = v.machine.tick(now);
        this.report(v, changed?.reason);
      }
      // A step this member applied without `stepped` reaching here.
      await this.resendIfStepped();
    }, undefined);
  }

  /// Ends the session's use of this coordinator: nothing is accepted after.
  wipe(): void {
    this.dead = true;
    this.dropPending();
    this.dropLate();
    this.early.clear();
    for (const v of this.votes.values()) v.machine.reset();
    this.votes.clear();
  }
}
