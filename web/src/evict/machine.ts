import { verifyPayload } from "../crypto/identity";
import { algForPubkey } from "../crypto/kx";
import type { RosterEntry } from "../shred/roster";
import { MAX_DEADLINE_MS, type Ballot, type EvictRequest, type EvictVote } from "./frame";
import { bytesEqual as eq, hexOf, keyDigest, rosterDigest, voteStatement } from "./statement";

/// The vote to remove someone or change the link (PROTOCOL.md amendment K).
/// UNANIMOUS among everyone in the roster frozen at the request, the target
/// left out; any refusal ends it, and so do the deadline, a member it needs
/// leaving, and the room's root moving. Every vote names the root, not the
/// epoch, so an ordinary key step does not end it. No timers and no I/O: the
/// caller supplies the clock and calls `tick`.

export type EvictState = "IDLE" | "VOTING" | "APPROVED" | "REJECTED" | "EXPIRED" | "CANCELLED" | "FAILED" | "DONE";

export type Guard =
  | "busy"
  | "malformed"
  | "policy-not-permitted"
  | "wrong-root"
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

/// How many request ids one member remembers under one root. Past it one is let
/// go: a refused id before a settled proposal, the oldest first, and never the
/// proposal this member holds now. The record is best effort: a commit for an
/// id it has let go of is checked as one this member never saw, and is never
/// applied.
export const MAX_SEEN_REQUESTS = 64;

/// What a ballot signs. The eviction statement by default; Unit B (a room's
/// timer shortened by quorum) supplies its own and leaves `target` and
/// `targetKeyDigest` empty. `targetKeyDigest` is SHA-256 of the target's
/// signing key, so the server knows every connection holding it.
export interface Statement {
  id: Uint8Array;
  /// The room's root epoch the votes name.
  root: number;
  target: Uint8Array | null;
  targetKeyDigest: Uint8Array | null;
  verifier: Uint8Array;
}

/// The statement fields of a request: its `targetKey` is the whole key, and
/// a vote signs its digest.
export async function requestStatement(req: EvictRequest): Promise<Statement> {
  const targetKeyDigest = req.target && req.targetKey ? await keyDigest(req.targetKey) : null;
  return { id: req.id, root: req.root, target: req.target, targetKeyDigest, verifier: req.verifier };
}

export interface MachineDeps {
  roomId: Uint8Array;
  me(): Uint8Array | null;
  /// This tab's own signing key. Required, not optional: a request is only
  /// opened from a roster that lists `me` under this key, and a check that
  /// could be left out would let a dishonest server leave this member out of
  /// the policy set it freezes.
  myKey(): Uint8Array;
  /// The roster, this member included.
  members(): RosterEntry[];
  now(): number;
  /// The root epoch of this member's keyring: the epoch of its link or
  /// passphrase, or of the last re-root.
  root(): number;
  statement?(s: Statement, voter: Uint8Array): Uint8Array;
  /// The record of request ids seen under this root, when several machines
  /// share one: the coordinator runs one machine per open request, and a
  /// request id is seen once by the member, not once by each vote. Left out,
  /// the machine keeps its own.
  seen?: SeenRequests;
}

/// Request ids a member received or made under the current root, with the
/// proposal it froze for each, or null for one it refused. A commit for a
/// proposal here is judged against it, even after the vote ended; a commit
/// for any other id is one this member cannot place, and it never applies one
/// of those. Bounded by `MAX_SEEN_REQUESTS` and emptied when the root moves; a
/// key step leaves it as it is.
export class SeenRequests {
  private root = -1;
  private ids = new Map<string, Proposal | null>();

  /// `held` says whether a proposal belongs to a vote that is open now. Such
  /// a proposal is never let go to make room.
  constructor(
    private rootOf: () => number,
    private held: (p: Proposal) => boolean,
  ) {}

  private table(): Map<string, Proposal | null> {
    const root = this.rootOf();
    if (root !== this.root) {
      this.root = root;
      this.ids.clear();
    }
    return this.ids;
  }

  mark(id: Uint8Array, p: Proposal | null): void {
    const table = this.table();
    const key = hexOf(id);
    if (!table.has(key) && table.size >= MAX_SEEN_REQUESTS) this.letOneGo(table);
    table.set(key, p);
  }

  /// Lets go of the oldest refused id, or if there is none the oldest
  /// proposal that no open vote holds. Refused ids cost a sender nothing to
  /// make, so they never push a proposal out while one of them is left.
  private letOneGo(table: Map<string, Proposal | null>): void {
    let victim: string | null = null;
    for (const [k, v] of table) {
      if (v === null) {
        victim = k;
        break;
      }
      if (victim === null && !this.held(v)) victim = k;
    }
    if (victim !== null) table.delete(victim);
  }

  has(id: Uint8Array): boolean {
    return this.table().has(hexOf(id));
  }

  get(id: Uint8Array): Proposal | null {
    return this.table().get(hexOf(id)) ?? null;
  }
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
  /// The record of request ids seen under the current root (`SeenRequests`).
  /// It lives with the machines, not in the coordinator alone, because
  /// `commitSatisfies` is what decides which set a commit is held to, and
  /// `open` is the one place a proposal is frozen. A machine on its own keeps
  /// its own record, which never lets go of the proposal it holds now.
  private seen: SeenRequests;

  constructor(private d: MachineDeps) {
    this.seen = d.seen ?? new SeenRequests(() => d.root(), (p) => p === this.p);
  }

  private markSeen(id: Uint8Array, p: Proposal | null): void {
    this.seen.mark(id, p);
  }

  /// Whether this member still holds a record of a request with this id
  /// under the current root, whatever became of it.
  wasSeen(id: Uint8Array): boolean {
    return this.seen.has(id);
  }

  /// The proposal this member froze for that id under the current root, if
  /// it opened one and still holds it. Only a commit for one of these is ever
  /// applied.
  requestFor(id: Uint8Array): Proposal | null {
    return this.seen.get(id);
  }

  private statementFor(s: Statement, voter: Uint8Array): Uint8Array {
    return this.d.statement
      ? this.d.statement(s, voter)
      : voteStatement(this.d.roomId, s.id, s.root, s.target, s.targetKeyDigest, voter, s.verifier);
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
    // An id already received under this root is never opened again: a relayed
    // copy of a request this member refused would otherwise ask it again.
    if (this.seen.has(req.id)) return "busy";
    if (SETTLED.includes(this.state)) this.reset();
    // Received, so never judged later as a request this member did not see.
    this.markSeen(req.id, null);
    if (this.state !== "IDLE") return "busy";
    if (req.policy !== "UNANIMOUS") return "policy-not-permitted";
    if (req.deadline <= 0 || req.deadline > MAX_DEADLINE_MS) return "malformed";
    // The request names the root it was made at, and only this member's own
    // root is taken: a step since then changes nothing, a re-root does.
    if (req.root !== this.d.root()) return "wrong-root";
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
    // This member votes only on a roster that lists it under its own signing
    // key. Otherwise the policy set it freezes would not need its approval (a
    // roster without it), or would take another key's signature as its own,
    // and a commit it refused could still pass its checks.
    const me = this.d.me();
    const myKey = this.d.myKey();
    if (!me || !roster.some((r) => eq(r.peerId, me) && r.pubkey !== undefined && eq(r.pubkey, myKey))) return "roster-mismatch";
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

  /// Whether the open vote already holds an approval from this peer id. A
  /// member that approved does not vote again, a key step since included.
  hasApproved(peerId: Uint8Array): boolean {
    return this.p !== null && this.approvals.has(hexOf(peerId));
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
    if (this.d.root() !== p.request.root) {
      this.state = "FAILED";
      return { state: this.state, reason: "root-moved" };
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
  /// request this member opened under the current root, not only the one
  /// open now.
  ///
  /// For an id it cannot place (never received, refused, or let go of) it
  /// checks only what a dishonest commit can fail, since an honest roster
  /// drifts (people join during a vote, a voter leaves before the commit is
  /// read): if the named target is still listed, the digest is that of the
  /// key its roster shows for it; every voter still listed signed under the
  /// key its roster shows; no voter is the named target, holds the key the
  /// commit names, or is this member; and no voter appears twice. Whether the
  /// votes cover its own roster is not asked. The caller has checked that the
  /// sender signed the commit, is listed and is one of the voters. Passing
  /// tells such a member only that the room moved without it: `requestFor`
  /// returns null for that id, and the caller never applies the commit.
  async commitSatisfies(c: Statement & { votes: Ballot[] }): Promise<boolean> {
    if ((c.target === null) !== (c.targetKeyDigest === null)) return false;
    const p = this.requestFor(c.id);
    if (!p) return this.unplacedCommitSatisfies(c);
    const sameTarget = p.request.target === null ? c.target === null : c.target !== null && eq(p.request.target, c.target);
    const sameKey =
      p.targetKeyDigest === null ? c.targetKeyDigest === null : c.targetKeyDigest !== null && eq(p.targetKeyDigest, c.targetKeyDigest);
    if (!sameTarget || !sameKey || !eq(p.request.verifier, c.verifier) || p.request.root !== c.root) return false;
    const set = p.policySet;
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

  private async unplacedCommitSatisfies(c: Statement & { votes: Ballot[] }): Promise<boolean> {
    if (c.votes.length === 0) return false;
    const me = this.d.me();
    const roster = this.d.members();
    const digestOf = (r: RosterEntry): Promise<Uint8Array | null> => (r.pubkey ? keyDigest(r.pubkey) : Promise.resolve(null));
    const holdsTargetKey = (d: Uint8Array | null): boolean => c.targetKeyDigest !== null && d !== null && eq(d, c.targetKeyDigest);
    if (c.target) {
      const named = roster.find((r) => eq(r.peerId, c.target!));
      if (named && !holdsTargetKey(await digestOf(named))) return false;
    }
    const seen = new Set<string>();
    for (const v of c.votes) {
      const key = hexOf(v.voter);
      if (seen.has(key)) return false;
      seen.add(key);
      if ((me && eq(v.voter, me)) || (c.target && eq(v.voter, c.target))) return false;
      const m = roster.find((r) => eq(r.peerId, v.voter));
      // A voter no longer listed cannot be checked, and is not held against
      // the commit: it may have left after voting.
      if (!m) continue;
      if (!m.pubkey || holdsTargetKey(await digestOf(m))) return false;
      if (!(await signedBy(m.pubkey, this.statementFor(c, v.voter), v.sig))) return false;
    }
    return true;
  }
}
