import { afterEach, describe, expect, it, vi } from "vitest";
import { departedMembers, KEY_STATUS_TEXT, keyStatusReporter, Session } from "./session";
import { toB64 } from "./transport/socket";

const entry = (peer: number, key: number | null, seq: number) => ({
  peerId: new Uint8Array(16).fill(peer),
  pubkey: key === null ? undefined : new Uint8Array(32).fill(key),
  joinedAtSeq: seq,
});

describe("departedMembers", () => {
  it("names the signing keys that are gone, not the peer ids that changed", () => {
    const before = [entry(1, 10, 1), entry(2, 20, 2), entry(3, 30, 3)];
    // 1 reconnected under a new peer id with the same key; 3 is gone.
    const after = [entry(9, 10, 9), entry(2, 20, 2)];
    expect(departedMembers(before, after).map((e) => e.pubkey![0])).toEqual([30]);
  });

  it("ignores entries without a signing key", () => {
    expect(departedMembers([entry(1, null, 1)], [])).toEqual([]);
  });
});

describe("key status text", () => {
  it("has no em dashes and no 'we'", () => {
    for (const t of Object.values(KEY_STATUS_TEXT)) {
      if (t === null) continue;
      expect(t).not.toMatch(/—/);
      expect(t).not.toMatch(/\bwe\b/i);
    }
  });
});

describe("keyStatusReporter", () => {
  it("passes a status on only when it changes", () => {
    const shown: (string | null)[] = [];
    const tempers: string[] = [];
    const report = keyStatusReporter({
      onKeyStatus: (m) => shown.push(m),
      onTemper: (t) => tempers.push(t),
    });
    report("waiting");
    report("waiting");
    report("waiting");
    report("ok");
    report("ok");
    report("refused");
    report("refused");
    expect(shown).toEqual([KEY_STATUS_TEXT.waiting, null, KEY_STATUS_TEXT.refused]);
    expect(tempers).toEqual(["WATCH"]);
  });

  it("says whether the last status was alarming, so a later SECURE can be followed by WATCH", () => {
    const report = keyStatusReporter({ onKeyStatus: () => {}, onTemper: () => {} });
    expect(report.alarming()).toBe(false);
    report("server-behind");
    expect(report.alarming()).toBe(true);
    report("ok");
    expect(report.alarming()).toBe(false);
    report("roster-mismatch");
    expect(report.alarming()).toBe(true);
    report("waiting");
    expect(report.alarming()).toBe(false);
  });
});

describe("the snapshot a step asks for", () => {
  afterEach(() => {
    vi.useRealTimers();
  });

  /// A Session with only what the snapshot path reads, built without a
  /// network: this tab is the elected member, and its copy holds entries no
  /// snapshot covers yet.
  function fakeSession() {
    const me = new Uint8Array(16).fill(1);
    const made: bigint[] = [];
    const state = { ready: false, joinPerfMs: performance.now(), watermark: 10 };
    const s = Object.create(Session.prototype) as Record<string, unknown>;
    Object.assign(s, {
      internals: {
        get joinPerfMs() {
          return state.joinPerfMs;
        },
        roster: new Map([[toB64(me), { peerId: me, joinedAtSeq: 1 }]]),
        myPeerId: toB64(me),
      },
      socket: { readyForSnapshot: () => state.ready },
      cfg: { roomIdHex: "07".repeat(16) },
      indexed: true,
      lastCovered: 0,
      snapshotTimer: null,
      snapshotSoonTimer: null,
      snapshotAsked: 0,
      snapshotPaid: 0,
      doc: {
        cursor: {
          get watermark() {
            return state.watermark;
          },
        },
        baseIndex: 0,
        storedCount: 0,
        // The usual thresholds are not met: only a forced snapshot is taken.
        shouldSnapshot: () => false,
        createSnapshot: async (covers: bigint) => {
          made.push(covers);
          return true;
        },
      },
    });
    const session = s as unknown as { snapshotSoon(): void; startSnapshotLoop(): void };
    return { session, state, made };
  }

  it("is still taken by the regular loop when the first try came too early", async () => {
    vi.useFakeTimers();
    const { session, state, made } = fakeSession();
    session.startSnapshotLoop();
    session.snapshotSoon();
    // The quick try finds the member joined under a minute ago and not ready.
    await vi.advanceTimersByTimeAsync(1_000);
    expect(made).toEqual([]);
    state.joinPerfMs -= 120_000;
    state.ready = true;
    await vi.advanceTimersByTimeAsync(30_000);
    expect(made).toEqual([10n]);
    // Once one has been sent, the loop goes back to its usual thresholds.
    state.watermark = 20;
    await vi.advanceTimersByTimeAsync(60_000);
    expect(made).toEqual([10n]);
  });

  it("still makes the quick try when nothing holds it back", async () => {
    vi.useFakeTimers();
    const { session, state, made } = fakeSession();
    state.joinPerfMs -= 120_000;
    state.ready = true;
    session.snapshotSoon();
    await vi.advanceTimersByTimeAsync(1_000);
    expect(made).toEqual([10n]);
  });
});

describe("dropKeys", () => {
  it("drops the chain key along with the content key", () => {
    const cfg = { contentKey: {} as CryptoKey | null, chainKey: {} as CryptoKey | null };
    const s = Object.create(Session.prototype) as Record<string, unknown>;
    Object.assign(s, {
      cfg,
      socket: { dropKeys: () => {} },
      coordinator: { wipe: () => {} },
      epochTimer: null,
      snapshotSoonTimer: null,
      awareness: null,
    });
    (s as unknown as { dropKeys(): void }).dropKeys();
    expect(cfg.contentKey).toBeNull();
    expect(cfg.chainKey).toBeNull();
  });
});
