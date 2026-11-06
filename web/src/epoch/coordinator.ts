import { confirmsEqual, randomEpochSecret, stepKeys } from "../crypto/epoch";
import { verifyPayload, type Identity } from "../crypto/identity";
import { algForPubkey, kxStatement, openWrap, sealWrap, wrapKey, type KxPair } from "../crypto/kx";
import { canonicalRosterBytes } from "../shred/roster";
import {
  decodeEpochKey,
  encodeEpochKey,
  MAX_HANDOVER_SECRETS,
  verifyEpochKey,
  type EpochKeyBody,
  type Wrap,
} from "./frame";
import type { Keyring } from "./keyring";
import {
  DepartureTracker,
  HANDOVER_FALLBACK_MS,
  rankOf,
  ROTATOR_FALLBACK_MS,
  turnHasCome,
} from "./rotation";

/// Rotation for one session (PROTOCOL.md amendment J): notices departures in
/// a Highest-security room, sends a step when it is this member's turn,
/// applies the steps the server echoes, and hands newcomers the secrets.
/// Everything that touches the network or the clock comes in through `deps`.

export interface MemberView {
  peerId: Uint8Array;
  pubkey?: Uint8Array;
  kxPub?: Uint8Array;
  kxSig?: Uint8Array;
  joinedAtSeq: number;
}

export type KeyStatus = "ok" | "waiting" | "unreadable" | "refused" | "roster-mismatch" | "server-behind";

export interface CoordinatorDeps {
  roomId: Uint8Array;
  identity: Identity;
  kx: KxPair;
  keyring: Keyring;
  now(): number;
  /// The server-assigned peer id, once joined.
  me(): Uint8Array | null;
  /// The roster, this member included.
  members(): MemberView[];
  /// Whether the room's sealed config says Highest security.
  highest(): boolean;
  header(epoch: number): Uint8Array;
  send(header: Uint8Array, body: Uint8Array): boolean;
  adopt(epoch: number): void;
  rejoin(): void;
  status(s: KeyStatus): void;
  snapshotSoon(): void;
}

const hex = (b: Uint8Array): string => Array.from(b, (x) => x.toString(16).padStart(2, "0")).join("");

function eq(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return false;
  return true;
}

async function rosterDigest(members: MemberView[]): Promise<Uint8Array> {
  const bytes = canonicalRosterBytes(members);
  return new Uint8Array(await crypto.subtle.digest("SHA-256", bytes as BufferSource));
}

export class EpochCoordinator {
  private tracker = new DepartureTracker();
  /// Signing key (hex) of each departed member, mapped to its peer id (hex).
  private departed = new Map<string, string>();
  private dueSince: number | null = null;
  private pendingStep: { to: number; secret: Uint8Array; confirm: Uint8Array; sentAt: number } | null = null;
  /// Newcomers waiting for a handover: peer id (hex) to when they arrived.
  private handovers = new Map<string, number>();
  /// Key-agreement keys whose signature checked out, by peer id (hex).
  private verifiedKx = new Map<string, Uint8Array>();
  private awaitingEpoch: number | null = null;
  private busy = false;
  /// EPOCH_KEY frames are handled one at a time, in the order they arrived,
  /// so two steps for the same epoch cannot both pass the epoch checks.
  private receiving: Promise<unknown> = Promise.resolve();

  constructor(private d: CoordinatorDeps) {}

  private async noteMember(m: MemberView): Promise<void> {
    const id = hex(m.peerId);
    if (this.verifiedKx.has(id) || !m.pubkey || !m.kxPub || !m.kxSig) return;
    const alg = algForPubkey(m.pubkey);
    if (!alg || m.kxPub.length !== 65 || m.kxPub[0] !== 0x04) return;
    try {
      if (await verifyPayload(alg, m.pubkey, m.kxSig, kxStatement(this.d.roomId, m.kxPub))) {
        this.verifiedKx.set(id, m.kxPub);
      }
    } catch {
      // Left unverified: no one wraps for this member, and it rejoins.
    }
  }

  /// Drop a step this member sent once the keyring has reached its epoch,
  /// whichever step got it there.
  private settlePending(reached: number): void {
    if (this.pendingStep && reached >= this.pendingStep.to) {
      this.pendingStep.secret.fill(0);
      this.pendingStep = null;
    }
  }

  private othersPresent(): boolean {
    const me = this.d.me();
    return this.d.members().some((m) => !me || !eq(m.peerId, me));
  }

  memberJoined(m: MemberView): void {
    this.noteMember(m).catch(() => undefined);
    if (m.pubkey) {
      const key = hex(m.pubkey);
      this.tracker.returned(key);
      this.departed.delete(key);
    }
    const me = this.d.me();
    if (me && !eq(m.peerId, me) && this.d.keyring.current.epoch > this.d.keyring.rootEpoch) {
      this.handovers.set(hex(m.peerId), this.d.now());
    }
  }

  memberLeft(m: MemberView): void {
    this.handovers.delete(hex(m.peerId));
    this.verifiedKx.delete(hex(m.peerId));
    if (this.d.highest() && m.pubkey) {
      const key = hex(m.pubkey);
      this.tracker.left(key, this.d.now());
      this.departed.set(key, hex(m.peerId));
    }
  }

  restartNotice(inSecs: number): void {
    this.tracker.noteRestartNotice(this.d.now(), inSecs);
  }

  /// After JOIN_ACK: check everyone's key-agreement key, and say whether this
  /// tab can read the room yet.
  async joined(roomEpoch: number): Promise<void> {
    await Promise.all(this.d.members().map((m) => this.noteMember(m)));
    // Anyone listed now is present, whatever this tab believed while it was
    // away: a departure that came back meanwhile must not cause a rotation.
    for (const m of this.d.members()) {
      if (!m.pubkey) continue;
      const key = hex(m.pubkey);
      this.tracker.returned(key);
      this.departed.delete(key);
    }
    const held = this.d.keyring.current.epoch;
    if (roomEpoch === held) {
      this.awaitingEpoch = null;
      this.d.status("ok");
    } else if (roomEpoch < held) {
      this.awaitingEpoch = null;
      this.d.status("server-behind");
    } else {
      this.awaitingEpoch = roomEpoch;
      this.d.status(this.othersPresent() ? "waiting" : "unreadable");
    }
  }

  /// Once a second.
  async tick(): Promise<void> {
    if (this.busy) return;
    this.busy = true;
    try {
      const now = this.d.now();
      // A departure that came back, or a rejoin, can clear the deadlines
      // after one fell due.
      if (!this.tracker.isDue(now)) this.dueSince = null;
      else if (this.dueSince === null) this.dueSince = now;
      if (this.awaitingEpoch !== null) this.d.status(this.othersPresent() ? "waiting" : "unreadable");
      const me = this.d.me();
      if (!me) return;
      if (this.pendingStep && now - this.pendingStep.sentAt > ROTATOR_FALLBACK_MS) {
        // Never echoed: another step won, or the server refused this one.
        this.pendingStep.secret.fill(0);
        this.pendingStep = null;
      }
      // A member still waiting for the room's key has nothing current to
      // step from or hand over.
      if (this.awaitingEpoch !== null) return;
      // Asked now, not only when the departure was noted: the level can be a
      // stale default until the sealed config has opened.
      if (this.dueSince !== null && !this.pendingStep && this.d.highest()) {
        const rank = rankOf(this.d.members(), me);
        if (turnHasCome(rank, now - this.dueSince, ROTATOR_FALLBACK_MS)) await this.sendStep(me);
      }
      for (const [peer, since] of [...this.handovers]) {
        const members = this.d.members();
        if (!members.some((m) => hex(m.peerId) === peer)) {
          this.handovers.delete(peer);
          continue;
        }
        const rank = rankOf(members.filter((m) => hex(m.peerId) !== peer), me);
        if (turnHasCome(rank, now - since, HANDOVER_FALLBACK_MS)) {
          this.handovers.delete(peer);
          await this.sendHandover(me, peer);
        }
      }
    } catch {
      // Whatever failed is tried again on the next tick.
    } finally {
      this.busy = false;
    }
  }

  private async sendStep(me: Uint8Array): Promise<void> {
    const ring = this.d.keyring;
    const cur = ring.current;
    const to = cur.epoch + 1;
    const header = this.d.header(to);
    const secret = randomEpochSecret();
    let kept = false;
    try {
      const next = await stepKeys(cur, secret);
      const wraps: Wrap[] = [];
      for (const m of this.d.members()) {
        if (eq(m.peerId, me)) continue;
        await this.noteMember(m);
        const kxPub = this.verifiedKx.get(hex(m.peerId));
        if (!kxPub) continue;
        try {
          const key = await wrapKey(this.d.kx, kxPub, this.d.roomId, to, me, m.peerId);
          const { iv, ct } = await sealWrap(key, header, secret);
          wraps.push({ p: m.peerId.slice(), iv, ct });
        } catch {
          // A key no one can agree with (off the curve, say). This member is
          // left out of the step and rejoins to be handed the key.
        }
      }
      const body = await encodeEpochKey(
        header,
        {
          kind: "step",
          from: cur.epoch,
          to,
          root: ring.rootEpoch,
          sender: me.slice(),
          roster: await rosterDigest(this.d.members()),
          confirm: next.confirm,
          wraps,
        },
        this.d.identity,
      );
      // Recorded before sending: the server echoes the step back, and the echo
      // must find the secret waiting.
      this.pendingStep = { to, secret, confirm: next.confirm, sentAt: this.d.now() };
      kept = true;
      if (!this.d.send(header, body)) {
        this.pendingStep = null;
        kept = false;
      }
    } finally {
      if (!kept) secret.fill(0);
    }
  }

  private async sendHandover(me: Uint8Array, peerHex: string): Promise<void> {
    const target = this.d.members().find((m) => hex(m.peerId) === peerHex);
    if (!target) return;
    await this.noteMember(target);
    const kxPub = this.verifiedKx.get(peerHex);
    if (!kxPub) return;
    const ring = this.d.keyring;
    const cur = ring.current;
    const blob = ring.secretsBlob();
    try {
      if (blob.length === 0 || blob.length / 32 > MAX_HANDOVER_SECRETS) return;
      const header = this.d.header(cur.epoch);
      const key = await wrapKey(this.d.kx, kxPub, this.d.roomId, cur.epoch, me, target.peerId);
      const { iv, ct } = await sealWrap(key, header, blob);
      const body = await encodeEpochKey(
        header,
        {
          kind: "handover",
          from: cur.epoch,
          to: cur.epoch,
          root: ring.rootEpoch,
          sender: me.slice(),
          roster: await rosterDigest(this.d.members()),
          confirm: cur.confirm,
          wraps: [{ p: target.peerId.slice(), iv, ct }],
        },
        this.d.identity,
      );
      this.d.send(header, body);
    } catch {
      // A newcomer whose key no one can agree with (off the curve, say) is
      // skipped, and the rest of the tick carries on.
    } finally {
      blob.fill(0);
    }
  }

  /// Handles one EPOCH_KEY after every earlier one has settled. Never rejects.
  receive(header: Uint8Array, headerEpoch: number, sender: Uint8Array, bytes: Uint8Array): Promise<void> {
    const fn = (): Promise<void> => this.receiveNow(header, headerEpoch, sender, bytes);
    const run = this.receiving.then(fn, fn);
    this.receiving = run.catch(() => undefined);
    return run.catch(() => undefined);
  }

  private async receiveNow(header: Uint8Array, headerEpoch: number, sender: Uint8Array, bytes: Uint8Array): Promise<void> {
    const decoded = decodeEpochKey(bytes);
    if (!decoded) return;
    const { body } = decoded;
    if (body.to !== headerEpoch || !eq(body.sender, sender)) return;
    const from = this.d.members().find((m) => eq(m.peerId, sender));
    if (!from?.pubkey) return;
    const alg = algForPubkey(from.pubkey);
    if (!alg || !(await verifyEpochKey(header, decoded, alg, from.pubkey))) {
      this.d.status("refused");
      return;
    }
    const me = this.d.me();
    if (!me) return;
    if (body.kind === "handover") await this.receiveHandover(header, body, from, me);
    else await this.receiveStep(header, body, from, me);
  }

  private async unwrapFrom(header: Uint8Array, body: EpochKeyBody, from: MemberView, me: Uint8Array): Promise<Uint8Array | null> {
    const wrap = body.wraps.find((w) => eq(w.p, me));
    if (!wrap) return null;
    await this.noteMember(from);
    const kxPub = this.verifiedKx.get(hex(from.peerId));
    if (!kxPub) return null;
    try {
      const key = await wrapKey(this.d.kx, kxPub, this.d.roomId, body.to, from.peerId, me);
      return await openWrap(key, header, wrap.iv, wrap.ct);
    } catch {
      return null;
    }
  }

  private async receiveStep(header: Uint8Array, body: EpochKeyBody, from: MemberView, me: Uint8Array): Promise<void> {
    const ring = this.d.keyring;
    if (body.to <= ring.current.epoch) return; // already held: a late duplicate
    const mine = eq(from.peerId, me);
    const pending = this.pendingStep;
    // Our own echo is only followable with the secret it was built from: a
    // step this tab gave up on, or an earlier one for the same epoch, is not.
    const ownSecret = mine && pending?.to === body.to && confirmsEqual(pending.confirm, body.confirm);
    if (body.to > ring.current.epoch + 1 || (mine && !ownSecret) || (!mine && !body.wraps.some((w) => eq(w.p, me)))) {
      // The room moved somewhere this member cannot follow. Join again and be
      // handed the keys as a newcomer.
      this.awaitingEpoch = body.to;
      this.d.status("waiting");
      this.d.rejoin();
      return;
    }
    let secret: Uint8Array | null;
    if (mine) {
      // Taken over from pendingStep here, and zeroed below whatever happens.
      secret = pending!.secret;
      this.pendingStep = null;
    } else {
      secret = await this.unwrapFrom(header, body, from, me);
      if (!secret) {
        this.d.status("refused");
        return;
      }
    }
    let applied;
    try {
      applied = await ring.applyStep(body.to, secret, body.confirm);
    } finally {
      secret.fill(0);
    }
    if (applied) this.settlePending(applied.epoch);
    if (!applied) {
      this.d.status("refused");
      return;
    }
    this.d.adopt(applied.epoch);
    // Departures this step cut out are settled. One that happened while it was
    // being built was wrapped for, and keeps its own deadline.
    const wrapped = new Set(body.wraps.map((w) => hex(w.p)));
    wrapped.add(hex(from.peerId));
    const covered = [...this.departed].filter(([, peer]) => !wrapped.has(peer)).map(([key]) => key);
    this.tracker.cover(covered);
    for (const k of covered) this.departed.delete(k);
    this.dueSince = null;
    this.awaitingEpoch = null;
    const digest = await rosterDigest(this.d.members());
    this.d.status(eq(digest, body.roster) ? "ok" : "roster-mismatch");
    this.d.snapshotSoon();
  }

  private async receiveHandover(header: Uint8Array, body: EpochKeyBody, from: MemberView, me: Uint8Array): Promise<void> {
    if (!body.wraps.some((w) => eq(w.p, me))) {
      // Someone has already looked after this newcomer.
      for (const w of body.wraps) this.handovers.delete(hex(w.p));
      return;
    }
    const ring = this.d.keyring;
    if (body.to <= ring.current.epoch || body.root !== ring.rootEpoch) return;
    const blob = await this.unwrapFrom(header, body, from, me);
    if (!blob) {
      this.d.status("refused");
      return;
    }
    let applied;
    try {
      applied = await ring.applyHandover(body.to, blob, body.confirm);
    } finally {
      blob.fill(0);
    }
    if (!applied) {
      this.d.status("refused");
      return;
    }
    this.settlePending(applied.epoch);
    this.awaitingEpoch = null;
    this.d.adopt(applied.epoch);
    this.d.status("ok");
  }

  wipe(): void {
    this.pendingStep?.secret.fill(0);
    this.pendingStep = null;
    this.handovers.clear();
    this.tracker.clear();
    this.departed.clear();
  }
}
