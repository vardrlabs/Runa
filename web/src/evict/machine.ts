import { verifyPayload } from "../crypto/identity";
import { algForPubkey } from "../crypto/kx";
import type { RosterEntry } from "../shred/roster";
import { MAX_DEADLINE_MS, type Ballot, type EvictRequest, type EvictVote } from "./frame";
import { bytesEqual as eq, hexOf, keyDigest, rosterDigest, voteStatement } from "./statement";

/// The vote to remove someone or change the link (PROTOCOL.md amendment K).
/// UNANIMOUS among everyone in the roster frozen at the request, the target
/// left out; any refusal ends it, and so do the deadline, a member it needs
/// leaving, and the room's epoch moving. No timers and no I/O: the caller
/// supplies the clock and calls `tick`.

export type EvictState = "IDLE" | "VOTING" | "APPROVED" | "REJECTED" | "EXPIRED" | "CANCELLED" | "FAILED" | "DONE";

export type Guard =
  | "busy"
  | "malformed"
  | "policy-not-permitted"
  | "wrong-epoch"
  | "unknown-proposer"
  | "proposer-is-target"
  | "unknown-target"
  | "target-key-mismatch"
  | "roster-mismatch"
  | "bad-signature"
  | "unknown-request"
  | "not-voting"
  | "not-in-policy-set"
  | "duplicate-vote"
  | "cancel-not-from-proposer";

/// Why a vote failed when someone left. The target leaving is not one of them:
/// the room re-roots anyway, and a connection the target opens again is never
/// in the policy set, so it is never wrapped (controller's decision 3).
export type LeaveReason = "proposer-left" | "voter-left";

/// How long members wait for the commit once every approval is in.
export const COMMIT_WAIT_MS = 15_000;

/// How many request ids one member remembers in one epoch. Past it the oldest
/// is let go, and from then until the epoch moves a commit for any id it
/// cannot place is refused rather than judged as one it never saw.
export const MAX_SEEN_REQUESTS = 64;

/// What a ballot signs. The eviction statement by default; Unit B (a room's
/// timer shortened by quorum) supplies its own and leaves `target` and
/// `targetKeyDigest` empty. `targetKeyDigest` is SHA-256 of the target's
/// signing key, so the server knows every connection holding it.
export interface Statement {
  id: Uint8Array;
  epoch: number;
  target: Uint8Array | null;
  targetKeyDigest: Uint8Array | null;
  verifier: Uint8Array;
}

/// The statement fields of a request: its `targetKey` is the whole key, and
/// a vote signs its digest.
export async function requestStatement(req: EvictRequest): Promise<Statement> {
  const targetKeyDigest = req.target && req.targetKey ? await keyDigest(req.targetKey) : null;
  return { id: req.id, epoch: req.epoch, target: req.target, targetKeyDigest, verifier: req.verifier };
}

export interface MachineDeps {
  roomId: Uint8Array;
  me(): Uint8Array | null;
  /// The roster, this member included.
  members(): RosterEntry[];
  now(): number;
  /// The epoch this member's keyring is at.
  epoch(): number;
  statement?(s: Statement, voter: Uint8Array): Uint8Array;
}

export interface Proposal {
  request: EvictRequest;
  /// SHA-256 of `request.targetKey`: what every vote on it signs.
  targetKeyDigest: Uint8Array | null;
  proposer: Uint8Array;
  /// Whose approval the policy needs: the roster when the request was made
  /// or received, without the target.
  policySet: RosterEntry[];
  deadlineAt: number;
  approvedAt: number | null;
}

const SETTLED: readonly EvictState[] = ["REJECTED", "EXPIRED", "CANCELLED", "FAILED", "DONE"];

async function signedBy(pubkey: Uint8Array, message: Uint8Array, sig: Uint8Array): Promise<boolean> {
  const alg = algForPubkey(pubkey);
  if (!alg || sig.length !== 64) return false;
  return verifyPayload(alg, pubkey, sig, message);
}

export class EvictMachine {
  state: EvictState = "IDLE";
  private p: Proposal | null = null;
  /// Approvals by voter (hex), with their signatures, for the commit.
  private approvals = new Map<string, Uint8Array>();
  /// Every request id this member received or made in the current epoch,
  /// with the proposal it froze, or null for one it refused. A commit for one
  /// of them is judged against that proposal and never as one this member
  /// did not see, even after a newer request replaced it here. Bounded by
  /// `MAX_SEEN_REQUESTS` and emptied when the epoch moves. It lives here, not
  /// in the coordinator, because `commitSatisfies` is what decides which set
  /// a commit is held to, and `open` is the one place a proposal is frozen.
  private seenEpoch = -1;
  private seenIds = new Map<string, Proposal | null>();
  private seenOverflowed = false;

  constructor(private d: MachineDeps) {}

  private seenTable(): Map<string, Proposal | null> {
    const epoch = this.d.epoch();
    if (epoch !== this.seenEpoch) {
      this.seenEpoch = epoch;
      this.seenIds.clear();
      this.seenOverflowed = false;
    }
    return this.seenIds;
  }

  private markSeen(id: Uint8Array, p: Proposal | null): void {
    const table = this.seenTable();
    const key = hexOf(id);
    if (!table.has(key) && table.size >= MAX_SEEN_REQUESTS) {
      const oldest = table.keys().next().value;
      if (oldest !== undefined) table.delete(oldest);
      this.seenOverflowed = true;
    }
    table.set(key, p);
  }

  /// Whether this member received or made a request with this id in the
  /// current epoch, whatever became of it.
  wasSeen(id: Uint8Array): boolean {
    return this.seenOverflowed || this.seenTable().has(hexOf(id));
  }

  /// The proposal this member froze for that id in the current epoch, if it
  /// opened one.
  requestFor(id: Uint8Array): Proposal | null {
    return this.seenTable().get(hexOf(id)) ?? null;
  }

  private statementFor(s: Statement, voter: Uint8Array): Uint8Array {
    return this.d.statement
      ? this.d.statement(s, voter)
      : voteStatement(this.d.roomId, s.id, s.epoch, s.target, s.targetKeyDigest, voter, s.verifier);
  }

  current(): Proposal | null {
    return this.p;
  }

  isOpen(): boolean {
    return this.state === "VOTING" || this.state === "APPROVED";
  }

  reset(): void {
    this.state = "IDLE";
    this.p = null;
    this.approvals.clear();
  }

  /// This member's own request. Its signature in the request is its approval.
  /// `targetKeyDigest` is the digest it signed: SHA-256 of `req.targetKey`.
  /// Throws while another vote is open: one sender's request never replaces
  /// another's. A vote that has finished may be started over.
  start(req: EvictRequest, me: Uint8Array, roster: RosterEntry[], targetKeyDigest: Uint8Array | null): void {
    // A vote past its deadline is over whether or not tick has run.
    this.pastDeadline();
    if (this.isOpen()) throw new Error("another vote is already open");
    this.reset();
    this.open(req, targetKeyDigest, me, roster);
  }

  private open(req: EvictRequest, targetKeyDigest: Uint8Array | null, proposer: Uint8Array, roster: RosterEntry[]): void {
    // The target, and any other connection holding its signing key (an
    // earlier connection of the same tab not yet gone), neither vote nor get
    // the new way in.
    const targetKey = req.target ? req.targetKey : null;
    this.p = {
      request: req,
      targetKeyDigest: targetKeyDigest ? targetKeyDigest.slice() : null,
      proposer: proposer.slice(),
      policySet: roster.filter(
        (r) => !(req.target && eq(r.peerId, req.target)) && !(targetKey && r.pubkey && eq(r.pubkey, targetKey)),
      ),
      deadlineAt: this.d.now() + req.deadline,
      approvedAt: null,
    };
    this.markSeen(req.id, this.p);
    this.approvals.set(hexOf(proposer), req.sig.slice());
    this.state = "VOTING";
    this.evaluate();
  }

  /// Whether the deadline has passed by the machine's own clock, whether or
  /// not `tick` has run. A vote past it fails and never counts another approval.
  private pastDeadline(): boolean {
    const p = this.p;
    if (!p || this.state !== "VOTING" || this.d.now() < p.deadlineAt) return false;
    this.state = "EXPIRED";
    return true;
  }

  private evaluate(): void {
    const p = this.p;
    if (!p || this.state !== "VOTING" || this.pastDeadline()) return;
    if (p.policySet.every((r) => this.approvals.has(hexOf(r.peerId)))) {
      this.state = "APPROVED";
      p.approvedAt = this.d.now();
    }
  }

  /// Every approval, in roster order, for the commit.
  ballots(): Ballot[] {
    const p = this.p;
    if (!p) return [];
    return p.policySet.flatMap((r) => {
      const sig = this.approvals.get(hexOf(r.peerId));
      return sig ? [{ voter: r.peerId.slice(), sig: sig.slice() }] : [];
    });
  }

  async onRequest(req: EvictRequest, sender: Uint8Array): Promise<Guard | null> {
    this.pastDeadline();
    // An id already received in this epoch is never opened again: a relayed
    // copy of a request this member refused would otherwise ask it again.
    if (this.seenTable().has(hexOf(req.id))) return "busy";
    if (SETTLED.includes(this.state)) this.reset();
    // Received, so never judged later as a request this member did not see.
    this.markSeen(req.id, null);
    if (this.state !== "IDLE") return "busy";
    if (req.policy !== "UNANIMOUS") return "policy-not-permitted";
    if (req.deadline <= 0 || req.deadline > MAX_DEADLINE_MS) return "malformed";
    if (req.epoch !== this.d.epoch()) return "wrong-epoch";
    const roster = this.d.members();
    const proposer = roster.find((r) => eq(r.peerId, sender));
    if (!proposer?.pubkey) return "unknown-proposer";
    if (req.target) {
      if (eq(req.target, sender)) return "proposer-is-target";
      const target = roster.find((r) => eq(r.peerId, req.target!));
      if (!target) return "unknown-target";
      if (!target.pubkey || !req.targetKey || !eq(target.pubkey, req.targetKey)) return "target-key-mismatch";
      if (eq(target.pubkey, proposer.pubkey)) return "proposer-is-target";
    }
    if (!eq(await rosterDigest(roster), req.roster)) return "roster-mismatch";
    // The proposer signed the digest of the key the roster shows for the
    // target (checked above to equal `req.targetKey`), so a commit carrying
    // its signature names that key to the server.
    const st = await requestStatement(req);
    let message: Uint8Array;
    try {
      message = this.statementFor(st, sender);
    } catch {
      return "malformed";
    }
    if (!(await signedBy(proposer.pubkey, message, req.sig))) return "bad-signature";
    // Re-checked after the awaits: another request may have opened meanwhile.
    if (this.state !== "IDLE") return "busy";
    this.open(req, st.targetKeyDigest, sender, roster);
    return null;
  }

  async onVote(v: EvictVote, sender: Uint8Array): Promise<Guard | null> {
    const p = this.p;
    if (!p || !eq(v.id, p.request.id)) return "unknown-request";
    if (this.state !== "VOTING" || this.pastDeadline()) return "not-voting";
    const member = p.policySet.find((r) => eq(r.peerId, sender));
    if (!member?.pubkey) return "not-in-policy-set";
    if (this.approvals.has(hexOf(sender))) return "duplicate-vote";
    if (v.vote === "REJECT") {
      this.state = "REJECTED";
      return null;
    }
    const st: Statement = { ...p.request, targetKeyDigest: p.targetKeyDigest };
    if (!v.sig || !(await signedBy(member.pubkey, this.statementFor(st, sender), v.sig))) return "bad-signature";
    if (this.p !== p || this.state !== "VOTING" || this.pastDeadline()) return "not-voting";
    if (this.approvals.has(hexOf(sender))) return "duplicate-vote";
    this.approvals.set(hexOf(sender), v.sig.slice());
    this.evaluate();
    return null;
  }

  /// This member's own approval, once it has signed.
  recordOwn(sig: Uint8Array): void {
    const me = this.d.me();
    const p = this.p;
    if (!me || !p || this.state !== "VOTING" || !p.policySet.some((r) => eq(r.peerId, me))) return;
    if (this.pastDeadline()) return;
    this.approvals.set(hexOf(me), sig.slice());
    this.evaluate();
  }

  rejectOwn(): void {
    if (this.state === "VOTING") this.state = "REJECTED";
  }

  onCancel(id: Uint8Array, sender: Uint8Array): Guard | null {
    const p = this.p;
    if (!p || !eq(p.request.id, id)) return "unknown-request";
    if (!eq(p.proposer, sender)) return "cancel-not-from-proposer";
    if (!this.isOpen()) return "not-voting";
    this.state = "CANCELLED";
    return null;
  }

  cancel(): void {
    if (this.isOpen()) this.state = "CANCELLED";
  }

  memberLeft(peerId: Uint8Array): LeaveReason | null {
    const p = this.p;
    if (!p || !this.isOpen()) return null;
    let reason: LeaveReason | null = null;
    if (eq(p.proposer, peerId)) reason = "proposer-left";
    else if (p.policySet.some((r) => eq(r.peerId, peerId))) reason = "voter-left";
    if (reason) this.state = "FAILED";
    return reason;
  }

  /// The argument is kept for callers but not read: the deadline and the
  /// commit wait are both measured on the injected clock, so the machine has
  /// one clock and a caller's `now` cannot drift from it.
  tick(_now: number): { state: EvictState; reason?: string } | null {
    const now = this.d.now();
    const p = this.p;
    if (!p || !this.isOpen()) return null;
    if (this.d.epoch() !== p.request.epoch) {
      this.state = "FAILED";
      return { state: this.state, reason: "epoch-moved" };
    }
    if (this.state === "VOTING" && now >= p.deadlineAt) {
      this.state = "EXPIRED";
      return { state: this.state };
    }
    if (this.state === "APPROVED" && p.approvedAt !== null && now - p.approvedAt >= COMMIT_WAIT_MS) {
      this.state = "FAILED";
      return { state: this.state, reason: "no-commit" };
    }
    return null;
  }

  fail(): void {
    if (this.state !== "DONE") this.state = "FAILED";
  }

  finish(): void {
    this.state = "DONE";
  }

  /// Whether a commit's votes are exactly what the policy needed: every
  /// member of the roster the request froze, without the target, each with a
  /// valid signature, and nobody else; and whether it names the target's key
  /// as the request did (SHA-256 of `request.targetKey`). That holds for any
  /// request this member opened in the current epoch, not only the one open
  /// now. A request it received but refused is never satisfied, and neither
  /// is an id it cannot place once its record has overflowed. A member that
  /// never saw the request requires the digest to be that of the key its
  /// roster shows for the named target, if it is still listed, and checks
  /// against its own roster without the named target, every entry whose key
  /// has the commit's digest, and itself.
  async commitSatisfies(c: Statement & { votes: Ballot[] }): Promise<boolean> {
    if ((c.target === null) !== (c.targetKeyDigest === null)) return false;
    const table = this.seenTable();
    const key = hexOf(c.id);
    if (table.has(key) ? table.get(key) === null : this.seenOverflowed) return false;
    const p = table.get(key) ?? null;
    let set: RosterEntry[];
    if (p) {
      const sameTarget = p.request.target === null ? c.target === null : c.target !== null && eq(p.request.target, c.target);
      const sameKey =
        p.targetKeyDigest === null ? c.targetKeyDigest === null : c.targetKeyDigest !== null && eq(p.targetKeyDigest, c.targetKeyDigest);
      if (!sameTarget || !sameKey || !eq(p.request.verifier, c.verifier) || p.request.epoch !== c.epoch) return false;
      set = p.policySet;
    } else {
      const me = this.d.me();
      const roster = this.d.members();
      const digests = await Promise.all(roster.map((r) => (r.pubkey ? keyDigest(r.pubkey) : Promise.resolve(null))));
      const holdsTargetKey = (i: number): boolean => {
        const d = digests[i];
        return c.targetKeyDigest !== null && d !== null && eq(d, c.targetKeyDigest);
      };
      const namedAt = c.target ? roster.findIndex((r) => eq(r.peerId, c.target!)) : -1;
      if (namedAt >= 0 && !holdsTargetKey(namedAt)) return false;
      set = roster.filter(
        (r, i) => !(c.target && eq(r.peerId, c.target)) && !holdsTargetKey(i) && !(me && eq(r.peerId, me)),
      );
    }
    if (set.length === 0 || c.votes.length !== set.length) return false;
    const seen = new Set<string>();
    for (const v of c.votes) {
      const m = set.find((r) => eq(r.peerId, v.voter));
      const key = hexOf(v.voter);
      if (!m?.pubkey || seen.has(key)) return false;
      seen.add(key);
      if (!(await signedBy(m.pubkey, this.statementFor(c, v.voter), v.sig))) return false;
    }
    return true;
  }
}
