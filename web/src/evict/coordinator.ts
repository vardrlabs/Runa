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
import { COMMIT_WAIT_MS, EvictMachine, type EvictState } from "./machine";
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

export const DEFAULT_DEADLINE_MS = 60_000;
/// How long a proposer waits for its commit to come back from the server.
export const COMMIT_ECHO_MS = 10_000;
/// How long a VOTE or CANCEL that arrived before its REQUEST is held for it.
/// Frames reach the coordinator in the order their decrypts resolve, so the
/// request is usually a moment behind; anything older is let go.
export const EARLY_HOLD_MS = 5_000;
/// How many request ids early frames are held for at once. Each holds at
/// most `MAX_VOTES` votes, one per sender, and one cancel.
export const MAX_EARLY_IDS = 8;

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
  state(s: EvictState, reason?: string): void;
  refused(reason: string): void;
  leftOut(): void;
  /// This tab holds the key a commit removed, and saw the commit anyway (a
  /// server that did not close it with 4014), so it says so itself.
  removed(): void;
}

interface Pending {
  requestId: Uint8Array;
  epoch: number;
  way: WayIn;
  keys: ReRootKeys;
  config: Uint8Array;
  sentAt: number | null;
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
  readonly machine: EvictMachine;
  /// The proposer's new way in, from its request until its commit is echoed
  /// or the vote ends.
  private pending: Pending | null = null;
  /// A commit whose echo did not come back in time. Its way in is closed to
  /// any new use and kept only so a late echo of that commit still applies,
  /// until members would also have stopped waiting for it or the epoch
  /// moves; then it is wiped.
  private late: Pending | null = null;
  /// VOTE and CANCEL frames held for a request not yet received, by request
  /// id, and the epoch they were held in.
  private early = new Map<string, Early>();
  private earlyEpoch = -1;
  /// The last state handed to `deps.state`, so a state the machine reached on
  /// its own (a vote that ran past its deadline, say) is reported once.
  private reported: EvictState = "IDLE";
  private dead = false;

  constructor(private d: EvictDeps) {
    this.machine = new EvictMachine({
      roomId: d.roomId,
      me: () => d.me(),
      members: () => d.members(),
      now: () => d.now(),
      epoch: () => d.keyring.current.epoch,
    });
  }

  /// True while a vote is open or this member's commit is in flight. Steps
  /// wait meanwhile.
  isOpen(): boolean {
    return this.machine.isOpen() || this.pending !== null;
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

  /// Tells `deps.state` about the machine's state if it moved, and lets go of
  /// the new way in once the vote is over without a commit.
  private report(reason?: string): void {
    if (!this.machine.isOpen() && this.pending) this.dropPending();
    const s = this.machine.state;
    if (s === this.reported) return;
    this.reported = s;
    if (s !== "IDLE") this.say(() => this.d.state(s, reason));
  }

  /// Lets go of held frames that are too old or from another epoch.
  private pruneEarly(): void {
    const epoch = this.d.keyring.current.epoch;
    if (epoch !== this.earlyEpoch) {
      this.early.clear();
      this.earlyEpoch = epoch;
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

  /// Replays what was held for a request the machine has just opened, in the
  /// same queue task, through the machine's own checks.
  private async replayEarly(id: Uint8Array): Promise<void> {
    this.pruneEarly();
    const key = hexOf(id);
    const e = this.early.get(key);
    if (!e) return;
    this.early.delete(key);
    if (e.cancel) {
      const guard = this.machine.onCancel(id, e.cancel);
      if (guard) this.refused(guard);
    }
    for (const { sender, vote } of e.votes) {
      if (this.dead || this.machine.state !== "VOTING") return;
      const guard = await this.machine.onVote(vote, sender);
      if (guard) this.refused(guard);
    }
  }

  private abandon(reason: string): void {
    this.dropPending();
    this.machine.fail();
    this.report(reason);
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
      if (this.isOpen()) return "busy";
      if (!Number.isInteger(deadlineMs) || deadlineMs <= 0 || deadlineMs > MAX_DEADLINE_MS) return "failed";
      const epoch = this.d.keyring.current.epoch;
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
      const sig = await signPayload(this.d.identity, voteStatement(this.d.roomId, id, epoch, targetId, targetKeyDigest, me, keys.verifier));
      const req: EvictRequest = {
        id,
        epoch,
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
      if (this.isOpen() || this.d.keyring.current.epoch !== epoch) return "busy";
      // Someone joined or left meanwhile: every member would refuse the
      // request's roster digest, so it is not sent.
      if (!eq(canonicalRosterBytes(this.d.members()), canonicalRosterBytes(members))) return "roster-changed";
      this.machine.start(req, me, members, targetKeyDigest);
      this.pending = { requestId: id, epoch, way, keys, config, sentAt: null };
      kept = true;
      this.reported = "IDLE";
      let sent = false;
      try {
        sent = await this.d.sendSealed(FT.EVICT_REQUEST, frame);
      } catch {
        this.abandon("send-failed");
        return "failed";
      }
      if (this.dead || this.pending?.requestId !== id) return "failed";
      if (!sent) {
        this.abandon("not-sent");
        return "not-sent";
      }
      this.report();
      // A room of two: the proposer's approval is all there is.
      if (this.machine.state === "APPROVED") await this.commitNow();
      return null;
    } finally {
      if (!kept) {
        wipeWayIn(way);
        keys?.authKey.fill(0);
      }
    }
  }

  vote(choice: "APPROVE" | "REJECT"): Promise<void> {
    return this.run(() => this.voteNow(choice), undefined);
  }

  private async voteNow(choice: "APPROVE" | "REJECT"): Promise<void> {
    const p = this.machine.current();
    const me = this.d.me();
    if (this.dead || !p || !me || this.machine.state !== "VOTING") return;
    // The target is not asked, and the proposer's request already is its vote.
    if (eq(p.proposer, me) || !p.policySet.some((r) => eq(r.peerId, me))) return;
    const r = p.request;
    if (choice === "REJECT") {
      this.machine.rejectOwn();
      this.report();
      await this.d.sendSealed(FT.EVICT_VOTE, encodeVote({ id: r.id, vote: "REJECT", sig: null }));
      return;
    }
    // The digest the machine took from the request's `targetKey`, which it
    // checked against this member's roster before the vote opened.
    const sig = await signPayload(this.d.identity, voteStatement(this.d.roomId, r.id, r.epoch, r.target, p.targetKeyDigest, me, r.verifier));
    if (this.dead || this.machine.current() !== p || this.machine.state !== "VOTING") return;
    this.machine.recordOwn(sig);
    this.report();
    if (this.machine.state !== "VOTING" && this.machine.state !== "APPROVED") return;
    let sent = false;
    try {
      sent = await this.d.sendSealed(FT.EVICT_VOTE, encodeVote({ id: r.id, vote: "APPROVE", sig }));
    } catch {
      // Handled below.
    }
    if (!sent && this.machine.current() === p && this.machine.isOpen()) this.abandon("not-sent");
  }

  cancel(): Promise<void> {
    return this.run(async () => {
      const p = this.machine.current();
      const me = this.d.me();
      if (this.dead || !p || !me || !eq(p.proposer, me) || !this.machine.isOpen() || this.pending?.sentAt != null) return;
      // Whether it went out or not, the proposer ends its own vote; members
      // that never hear of it fail on their own deadline or commit wait.
      await this.d.sendSealed(FT.EVICT_CANCEL, encodeCancel({ id: p.request.id }));
      if (this.dead || this.machine.current() !== p || !this.machine.isOpen()) return;
      this.machine.cancel();
      this.dropPending();
      this.report();
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
      const guard = await this.machine.onRequest(req, sender);
      if (guard) {
        this.report();
        return this.refused(guard);
      }
      // Votes and a cancel that overtook the request count now, before
      // anyone is asked: a cancelled or refused request asks nobody.
      await this.replayEarly(req.id);
      if (this.dead) return;
      this.reported = "IDLE";
      this.report();
      if (this.machine.current()?.request !== req || this.machine.state !== "VOTING") return;
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
    const cur = this.machine.current();
    if (cur && eq(cur.request.id, id) && this.machine.state === "DONE") return;
    // One that overtook its request waits for it.
    if (!this.machine.wasSeen(id)) return this.hold(id, sender, v);
    if (v) {
      const guard = await this.machine.onVote(v, sender);
      if (this.dead) return;
      this.report();
      if (guard) return this.refused(guard);
      if (this.machine.state === "APPROVED" && this.pending && this.pending.sentAt === null) await this.commitNow();
      return;
    }
    const guard = this.machine.onCancel(id, sender);
    this.report();
    if (guard) return this.refused(guard);
  }

  /// The proposer, once every approval is in: seal the new way in to each
  /// member who approved, and send the commit. Never throws: a commit that
  /// cannot be built ends the vote.
  private async commitNow(): Promise<void> {
    try {
      await this.buildAndSend();
    } catch {
      this.abandon("commit-failed");
    }
  }

  private async buildAndSend(): Promise<void> {
    const pend = this.pending;
    const p = this.machine.current();
    const me = this.d.me();
    if (this.dead || !pend || !p || !me || this.machine.state !== "APPROVED" || pend.sentAt !== null) return;
    const epoch = p.request.epoch;
    if (this.d.keyring.current.epoch !== epoch) return this.abandon("epoch-moved");
    const root = epoch + 1;
    const header = this.d.header(FT.EVICT_COMMIT, epoch);
    const wraps: Wrap[] = [];
    // Only the members who approved get the new way in: nobody who arrived
    // during the vote, and not the target or a connection holding its key.
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
        votes: this.machine.ballots(),
      },
      { root, sender: me.slice(), confirm: pend.keys.confirm, wraps },
      this.d.identity,
    );
    // Checked again after the awaits above.
    if (this.dead || this.pending !== pend || this.machine.current() !== p || this.machine.state !== "APPROVED") return;
    if (this.d.keyring.current.epoch !== epoch) return this.abandon("epoch-moved");
    pend.sentAt = this.d.now();
    if (!this.d.sendSigned(header, body)) this.abandon("not-sent");
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
      // in: a member signed a commit for an epoch it has not reached.
      this.say(() => this.d.leftOut());
      return;
    }
    const claim = {
      id: clear.requestId,
      epoch,
      target: clear.target,
      targetKeyDigest: clear.targetKeyDigest,
      verifier: clear.verifier,
      votes: clear.votes,
    };
    // Also checks that the digest is SHA-256 of the key the request named
    // (or, for a member that never saw it, of the named peer's roster key).
    if (!(await this.machine.commitSatisfies(claim))) return this.refused("commit-policy");
    const holdsTargetKey = clear.targetKeyDigest !== null && eq(clear.targetKeyDigest, await keyDigest(this.d.identity.publicKeyRaw));

    // Everything above awaited: look again before acting on any of it.
    const meNow = this.d.me();
    if (this.dead || !meNow || !eq(meNow, me) || ring.current.epoch !== epoch) return;

    // This connection is the one named, or this tab holds the key the votes
    // name (a connection opened again under a new peer id, say), so it was
    // removed whatever its peer id is now. The server closes such a
    // connection with 4014; if it sees the commit anyway, it has no wrap,
    // and says so itself.
    if (holdsTargetKey || (clear.target !== null && eq(clear.target, me))) {
      this.dropPending();
      this.dropLate();
      this.machine.finish();
      this.say(() => this.d.removed());
      return;
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
        if (!way) {
          this.machine.fail();
          this.reported = "IDLE";
          this.report("left-out");
          this.say(() => this.d.leftOut());
          return;
        }
      }
      // A refusal of this member's own commit ends its vote, which nothing
      // else would, since its new way in is gone.
      const refuse = (reason: string): void => {
        if (mine) this.abandon(reason);
        this.refused(reason);
      };
      keys ??= await deriveReRoot(way);
      if (!eq(keys.verifier, clear.verifier) || !eq(way.salt, clear.salt) || !confirmsEqual(keys.confirm, tail.confirm)) {
        return refuse("commit-keys");
      }
      if (!(await this.configMatches(clear.config, keys.contentKey))) return refuse("commit-config");
      // The request named the target's key; a member that never saw it finds
      // the roster entry whose key has the commit's digest, which is there
      // until the target's PEER_LEAVE arrives.
      const named = this.machine.requestFor(clear.requestId)?.request.targetKey ?? null;
      const targetKey = !clear.targetKeyDigest ? null : named ? named.slice() : await this.keyWithDigest(clear.targetKeyDigest);
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
      this.machine.finish();
      this.report();
      this.d.applyReRoot({ root: tail.root, way, keys, target: clear.target, targetKey });
      handed = true;
    } finally {
      if (!handed) {
        if (way) wipeWayIn(way);
        keys?.authKey.fill(0);
      }
    }
  }

  /// The signing key of a member whose key has this digest, if one is listed.
  private async keyWithDigest(digest: Uint8Array): Promise<Uint8Array | null> {
    for (const m of this.d.members()) {
      if (m.pubkey && eq(await keyDigest(m.pubkey), digest)) return m.pubkey.slice();
    }
    return null;
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
      const reason = this.machine.memberLeft(m.peerId);
      if (reason) this.report(reason);
    }, undefined);
  }

  /// Once a second, from the session's timer.
  tick(): Promise<void> {
    return this.run(async () => {
      if (this.dead) return;
      const now = this.d.now();
      this.pruneEarly();
      const late = this.late;
      if (late && (late.sentAt === null || now - late.sentAt >= COMMIT_WAIT_MS || this.d.keyring.current.epoch !== late.epoch)) {
        this.dropLate();
      }
      const pend = this.pending;
      if (pend?.sentAt != null && now - pend.sentAt >= COMMIT_ECHO_MS) {
        // Given up and reported now, but its way in is kept, closed, in case
        // the echo is only late: members still wait for the commit.
        this.dropLate();
        this.late = pend;
        this.pending = null;
        this.machine.fail();
        this.report("no-echo");
        return;
      }
      const changed = this.machine.tick(now);
      this.report(changed?.reason);
    }, undefined);
  }

  /// Ends the session's use of this coordinator: nothing is accepted after.
  wipe(): void {
    this.dead = true;
    this.dropPending();
    this.dropLate();
    this.early.clear();
    this.machine.reset();
    this.reported = "IDLE";
  }
}
