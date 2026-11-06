/// When a room rotates, and who does it (PROTOCOL.md amendment J). Pure: the
/// caller supplies the clock, so every rule here is tested without timers.

export const LEAVE_GRACE_MS = 60_000;
export const RESTART_GRACE_MS = 600_000;
export const ROTATOR_FALLBACK_MS = 15_000;
export const HANDOVER_FALLBACK_MS = 10_000;
export const EPOCH_OVERLAP_MS = 30_000;

/// Departures from a Highest-security room, keyed by the departed peer's
/// signing key, which lives as long as its tab. A dropped connection that
/// comes back with the same key is not a departure.
export class DepartureTracker {
  private deadlines = new Map<string, number>();
  private restartGraceUntil = 0;

  /// A restart that promises a handover gives everyone time to come back.
  noteRestartNotice(now: number, inSecs: number): void {
    if (!Number.isFinite(inSecs) || inSecs < 0) return;
    this.restartGraceUntil = Math.max(this.restartGraceUntil, now + inSecs * 1000 + RESTART_GRACE_MS);
  }

  left(signingKey: string, now: number): void {
    const grace = now < this.restartGraceUntil ? RESTART_GRACE_MS : LEAVE_GRACE_MS;
    this.deadlines.set(signingKey, now + grace);
  }

  returned(signingKey: string): void {
    this.deadlines.delete(signingKey);
  }

  /// True once any departure's grace has run out. The step that follows
  /// covers every departure still pending, so a burst makes one rotation.
  isDue(now: number): boolean {
    for (const d of this.deadlines.values()) if (d <= now) return true;
    return false;
  }

  /// Forget departures a step has cut out. One that happened while the step
  /// was being built was still wrapped for, and keeps its deadline.
  cover(keys: Iterable<string>): void {
    for (const k of keys) this.deadlines.delete(k);
  }

  pendingKeys(): string[] {
    return [...this.deadlines.keys()];
  }

  clear(): void {
    this.deadlines.clear();
  }
}

function cmpBytes(a: Uint8Array, b: Uint8Array): number {
  for (let i = 0; i < Math.min(a.length, b.length); i++) if (a[i] !== b[i]) return a[i] - b[i];
  return a.length - b.length;
}

/// A member's place in line: by join order, then peer id, the same order the
/// snapshot election uses. -1 when `me` is not in the roster.
export function rankOf(roster: { peerId: Uint8Array; joinedAtSeq: number }[], me: Uint8Array): number {
  const sorted = [...roster].sort((a, b) =>
    a.joinedAtSeq !== b.joinedAtSeq ? a.joinedAtSeq - b.joinedAtSeq : cmpBytes(a.peerId, b.peerId),
  );
  return sorted.findIndex((r) => cmpBytes(r.peerId, me) === 0);
}

/// Rank 0 acts at once; each later rank waits one fallback per rank ahead of
/// it, in case those members have gone quiet.
export function turnHasCome(rank: number, waitedMs: number, fallbackMs: number): boolean {
  return rank >= 0 && waitedMs >= rank * fallbackMs;
}
