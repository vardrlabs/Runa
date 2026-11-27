import { afterEach, describe, expect, it, vi } from "vitest";
import { fingerprintWords } from "./crypto/fingerprint";
import { EPOCH_OVERLAP_MS } from "./epoch/rotation";
import { handleFromPubkey } from "./doc/awareness";
import type { ReRooted } from "./evict/coordinator";
import { KEY_STATUS_TEXT, keyStatusReporter, keyStatusText, Session } from "./session";
import { toB64 } from "./transport/socket";

/// What a Session's eviction wiring touches, built without a network. Each
/// collaborator records what was asked of it.
function fakeSession(opts: { throwingPage?: boolean; wayKind?: "link" | "pass" } = {}) {
  const calls: string[] = [];
  const shown: { reRooted: unknown[]; removed: number; ignored: string[]; prompts: unknown[]; keyStatus: (string | null)[] } = {
    reRooted: [],
    removed: 0,
    ignored: [],
    prompts: [],
    keyStatus: [],
  };
  const boom = (): never => {
    throw new Error("page callback threw");
  };
  const socket = {
    authKey: null as Uint8Array | null,
    replaceAuthKey(k: Uint8Array) {
      calls.push("replaceAuthKey");
      this.authKey = k;
    },
    adoptEpoch(e: number) {
      calls.push(`adoptEpoch ${e}`);
    },
    stopReconnecting() {
      calls.push("stopReconnecting");
    },
    close() {
      calls.push("close");
    },
    dropKeys() {
      calls.push("dropKeys");
    },
    readyForSnapshot: () => false,
  };
  const events = {
    onShredState: (s: string) => {
      calls.push(`onShredState ${s}`);
      if (opts.throwingPage) boom();
    },
    onReRooted: (r: unknown) => {
      shown.reRooted.push(r);
      if (opts.throwingPage) boom();
    },
    onRemoved: () => {
      shown.removed += 1;
      if (opts.throwingPage) boom();
    },
    onEvictIgnored: (reason: string) => shown.ignored.push(reason),
    onEvictPrompt: (p: unknown) => shown.prompts.push(p),
    onKeyStatus: (m: string | null) => {
      shown.keyStatus.push(m);
      if (opts.throwingPage) boom();
    },
    onTemper: () => {},
  };
  const keyring = {
    forgot: 0,
    forgetBeforeRoot() {
      this.forgot += 1;
    },
  };
  const s = Object.create(Session.prototype) as Record<string, unknown>;
  Object.assign(s, {
    cfg: { roomIdHex: "07".repeat(16), contentKey: "old-content", chainKey: "old-chain", wayKind: opts.wayKind ?? "link" },
    socket,
    events,
    keyring,
    keyStatus: keyStatusReporter(events),
    securityLevel: "highest",
    sealed: null,
    rerootAt: null,
    rerootSnapshotSeen: false,
    rerootGen: 0,
    removedSaid: false,
    destroyed: false,
    snapshotSoonTimer: null,
    snapshotAsked: 0,
    snapshotPaid: 0,
    machine: {
      reset: () => calls.push("shred reset"),
    },
    coordinator: {
      reRooted: (k: Uint8Array | null) => {
        calls.push(`reRooted ${k ? "key" : "null"}`);
        // As the real one does: it reports "ok" last.
        (s as unknown as { reportKeyStatus(x: string): void }).reportKeyStatus("ok");
      },
      exclusive: <T>(fn: () => Promise<T>) => fn(),
    },
    internals: { roster: new Map(), myPeerId: "" },
    doc: {
      destroy: () => calls.push("doc destroy"),
    },
  });
  return { s, session: s as unknown as SessionPrivates, socket, calls, shown, keyring };
}

interface SessionPrivates {
  applyReRoot(r: ReRooted): void;
  forgetOldRoot(): Promise<void>;
  removedFromRoom(): void;
  evictRefused(reason: string): void;
  evictStateChanged(state: string, reason?: string): void;
  raiseEvictPrompt(p: { requestId: Uint8Array; proposerKey: Uint8Array; target: Uint8Array | null; targetKey: Uint8Array | null }): Promise<void>;
  proposeEviction(target: Uint8Array | null, passphrase?: string): Promise<string | null>;
  sealedConfig(): { ttl: { kind: string; secs: number }; ceilingOptout: boolean; level: string };
  carryOver(): boolean;
}

function reRooted(kind: "link" | "pass", targetKey: Uint8Array | null): { r: ReRooted; authKey: Uint8Array; seedCopy: Uint8Array } {
  const authKey = new Uint8Array(32).fill(7);
  const fingerprintSeed = new Uint8Array(32).fill(9);
  const r: ReRooted = {
    root: 5,
    way: { kind, secret: new Uint8Array(32).fill(3), salt: new Uint8Array(16).fill(4), phrase: kind === "pass" ? "correct horse battery staple" : "" },
    keys: {
      authKey,
      verifier: new Uint8Array(32),
      contentKey: "new-content" as unknown as CryptoKey,
      chainKey: "new-chain" as unknown as CryptoKey,
      confirm: new Uint8Array(32),
      fingerprintSeed,
    },
    target: targetKey ? new Uint8Array(16).fill(2) : null,
    targetKey,
  };
  return { r, authKey, seedCopy: fingerprintSeed.slice() };
}

afterEach(() => {
  vi.useRealTimers();
});

describe("a re-root this tab applied", () => {
  it("hands the socket the new auth key, opens the room with the new keys, and ends any shred vote, all before it returns", () => {
    const { s, session, socket, calls } = fakeSession();
    const { r, authKey } = reRooted("link", null);
    session.applyReRoot(r);
    expect(calls.slice(0, 5)).toEqual(["replaceAuthKey", "adoptEpoch 5", "reRooted null", "shred reset", "onShredState IDLE"]);
    expect(socket.authKey).toBe(authKey);
    // The socket owns it now: nothing here zeroed it.
    expect(authKey.every((b) => b === 7)).toBe(true);
    const cfg = s.cfg as { contentKey: unknown; chainKey: unknown };
    expect(cfg.contentKey).toBe("new-content");
    expect(cfg.chainKey).toBe("new-chain");
  });

  it("wipes the way in and the fingerprint seed before it returns, and shows the new link and fingerprint once", async () => {
    const { session, shown } = fakeSession();
    const { r, seedCopy } = reRooted("link", null);
    session.applyReRoot(r);
    expect(r.way.secret.every((b) => b === 0)).toBe(true);
    expect(r.keys.fingerprintSeed.every((b) => b === 0)).toBe(true);
    await vi.waitFor(() => expect(shown.reRooted).toHaveLength(1));
    const got = shown.reRooted[0] as { fragment: string; passphrase: string | null; fingerprint: string; removed: string | null };
    expect(got.fragment).toMatch(/^#k=.+&s=.+$/);
    expect(got.passphrase).toBeNull();
    expect(got.removed).toBeNull();
    expect(got.fingerprint).toBe(fingerprintWords(seedCopy).join("-").toUpperCase());
  });

  it("shows a shared room's new passphrase, and names who was removed by their key", async () => {
    const { session, shown } = fakeSession({ wayKind: "pass" });
    const targetKey = new Uint8Array(32).fill(42);
    const { r } = reRooted("pass", targetKey);
    session.applyReRoot(r);
    expect(r.way.phrase).toBe("");
    await vi.waitFor(() => expect(shown.reRooted).toHaveLength(1));
    const got = shown.reRooted[0] as { fragment: string | null; passphrase: string | null; removed: string | null };
    expect(got.fragment).toBeNull();
    expect(got.passphrase).toBe("correct horse battery staple");
    expect(got.removed).toBe(await handleFromPubkey(targetKey));
  });

  it("never throws, and still finishes, when every page callback throws", async () => {
    const { session, socket, calls, shown } = fakeSession({ throwingPage: true });
    const { r, authKey } = reRooted("link", new Uint8Array(32).fill(1));
    expect(() => session.applyReRoot(r)).not.toThrow();
    expect(socket.authKey).toBe(authKey);
    expect(authKey.every((b) => b === 7)).toBe(true);
    expect(calls).toContain("reRooted key");
    expect(calls).toContain("shred reset");
    expect(r.way.secret.every((b) => b === 0)).toBe(true);
    expect(r.keys.fingerprintSeed.every((b) => b === 0)).toBe(true);
    await vi.waitFor(() => expect(shown.reRooted).toHaveLength(1));
  });
});

describe("a re-root this tab applied (fix wave 1)", () => {
  it("does not hide a failure to switch the send cipher: the socket stops, the secrets are wiped, and the throw reaches the coordinator", () => {
    const { session, socket, calls } = fakeSession();
    socket.adoptEpoch = () => {
      throw new Error("no cipher");
    };
    const { r } = reRooted("link", null);
    expect(() => session.applyReRoot(r)).toThrow("no cipher");
    expect(calls).toContain("stopReconnecting");
    expect(r.way.secret.every((b) => b === 0)).toBe(true);
    expect(r.keys.fingerprintSeed.every((b) => b === 0)).toBe(true);
  });

  it("keeps no reference to the old auth key, which the socket zeroed", () => {
    const { s, session } = fakeSession();
    const old = new Uint8Array(32).fill(1);
    (s.cfg as Record<string, unknown>).authKey = old;
    const { r, authKey } = reRooted("link", null);
    session.applyReRoot(r);
    expect((s.cfg as { authKey: Uint8Array }).authKey).toBe(authKey);
  });

  it("queues the forgetting of old keys at most once while the epoch queue is held up", async () => {
    vi.useFakeTimers();
    const { s, session, keyring } = fakeSession();
    let release: () => void = () => {};
    const blocker = new Promise<void>((res) => (release = res));
    let queued = 0;
    (s.coordinator as { exclusive: unknown }).exclusive = <T>(fn: () => Promise<T>): Promise<T> => {
      queued += 1;
      return blocker.then(fn);
    };
    session.applyReRoot(reRooted("link", null).r);
    s.rerootSnapshotSeen = true;
    vi.advanceTimersByTime(EPOCH_OVERLAP_MS);
    const runs = [session.forgetOldRoot(), session.forgetOldRoot(), session.forgetOldRoot()];
    expect(queued).toBe(1);
    release();
    await Promise.all(runs);
    expect(keyring.forgot).toBe(1);
  });

  it("says in a shared room that its passphrase changed, never its link", () => {
    const shown: (string | null)[] = [];
    const report = keyStatusReporter({ onKeyStatus: (m) => shown.push(m), onTemper: () => {} }, keyStatusText("pass"));
    report("left-out");
    expect(shown[0]).toMatch(/passphrase changed/);
    expect(shown[0]).not.toMatch(/\blink\b/);
    expect(keyStatusText("link")["left-out"]).toMatch(/link changed/);
    expect(keyStatusText("link")["left-out"]).not.toMatch(/passphrase/);
    for (const t of [...Object.values(keyStatusText("pass")), ...Object.values(keyStatusText("link"))]) {
      if (t === null) continue;
      expect(t).not.toMatch(/\u2014/);
      expect(t).not.toMatch(/\bwe\b/i);
    }
  });
});

describe("the keys from before a re-root", () => {
  it("are kept until a snapshot under the new root has landed and the overlap has passed", async () => {
    vi.useFakeTimers();
    const { s, session, keyring } = fakeSession();
    session.applyReRoot(reRooted("link", null).r);
    await session.forgetOldRoot();
    expect(keyring.forgot).toBe(0);
    // The overlap passes, but no snapshot under the new root has landed.
    vi.advanceTimersByTime(EPOCH_OVERLAP_MS);
    await session.forgetOldRoot();
    expect(keyring.forgot).toBe(0);
    // A snapshot lands.
    s.rerootSnapshotSeen = true;
    await session.forgetOldRoot();
    expect(keyring.forgot).toBe(1);
    // Once is enough.
    await session.forgetOldRoot();
    expect(keyring.forgot).toBe(1);
  });

  it("are kept while the overlap runs, even once a snapshot has landed", async () => {
    vi.useFakeTimers();
    const { s, session, keyring } = fakeSession();
    session.applyReRoot(reRooted("link", null).r);
    s.rerootSnapshotSeen = true;
    vi.advanceTimersByTime(EPOCH_OVERLAP_MS - 1);
    await session.forgetOldRoot();
    expect(keyring.forgot).toBe(0);
    vi.advanceTimersByTime(1);
    await session.forgetOldRoot();
    expect(keyring.forgot).toBe(1);
  });

  it("are not forgotten for a snapshot seen before the latest re-root", async () => {
    vi.useFakeTimers();
    const { s, session, keyring } = fakeSession();
    session.applyReRoot(reRooted("link", null).r);
    s.rerootSnapshotSeen = true;
    // A second re-root starts the wait again.
    session.applyReRoot(reRooted("link", null).r);
    vi.advanceTimersByTime(EPOCH_OVERLAP_MS);
    await session.forgetOldRoot();
    expect(keyring.forgot).toBe(0);
  });

  it("are not forgotten for this tab's own snapshot when it was begun before the re-root", async () => {
    vi.useFakeTimers();
    const { s, session } = fakeSession();
    const me = new Uint8Array(16).fill(1);
    let finish: (made: boolean) => void = () => {};
    Object.assign(s, {
      internals: { roster: new Map([[toB64(me), { peerId: me, joinedAtSeq: 1 }]]), myPeerId: toB64(me), joinPerfMs: performance.now() - 120_000 },
      indexed: true,
      lastCovered: 0,
      doc: {
        cursor: { watermark: 10 },
        baseIndex: 0,
        storedCount: 0,
        shouldSnapshot: () => true,
        createSnapshot: () => new Promise<boolean>((res) => (finish = res)),
      },
    });
    (s.socket as Record<string, unknown>).readyForSnapshot = () => true;
    const trySnapshot = (force: boolean) => (s as unknown as { trySnapshot(f: boolean): void }).trySnapshot(force);
    session.applyReRoot(reRooted("link", null).r);
    // Begun under the first new root, finished after a second re-root.
    trySnapshot(true);
    session.applyReRoot(reRooted("link", null).r);
    finish(true);
    await Promise.resolve();
    expect(s.rerootSnapshotSeen).toBe(false);
    // One begun and finished under the latest root counts.
    (s.doc as { cursor: { watermark: number } }).cursor.watermark = 20;
    trySnapshot(true);
    finish(true);
    await Promise.resolve();
    expect(s.rerootSnapshotSeen).toBe(true);
  });

  it("are forgotten on the epoch queue, after a task already queued there", async () => {
    vi.useFakeTimers();
    const { s, session, keyring } = fakeSession();
    let release: () => void = () => {};
    const blocker = new Promise<void>((res) => (release = res));
    let tail: Promise<unknown> = Promise.resolve();
    (s.coordinator as { exclusive: unknown }).exclusive = <T>(fn: () => Promise<T>): Promise<T> => {
      const run = tail.then(fn, fn);
      tail = run.catch(() => undefined);
      return run;
    };
    const queued = (s.coordinator as { exclusive<T>(fn: () => Promise<T>): Promise<T> }).exclusive(() => blocker);
    session.applyReRoot(reRooted("link", null).r);
    s.rerootSnapshotSeen = true;
    vi.advanceTimersByTime(EPOCH_OVERLAP_MS);
    const forgetting = session.forgetOldRoot();
    await Promise.resolve();
    expect(keyring.forgot).toBe(0);
    release();
    await queued;
    await forgetting;
    expect(keyring.forgot).toBe(1);
  });

  it("are kept when another re-root lands while the forgetting waits on the queue", async () => {
    vi.useFakeTimers();
    const { s, session, keyring } = fakeSession();
    let release: () => void = () => {};
    const blocker = new Promise<void>((res) => (release = res));
    let tail: Promise<unknown> = Promise.resolve();
    const exclusive = <T>(fn: () => Promise<T>): Promise<T> => {
      const run = tail.then(fn, fn);
      tail = run.catch(() => undefined);
      return run;
    };
    (s.coordinator as { exclusive: unknown }).exclusive = exclusive;
    const queued = exclusive(() => blocker);
    session.applyReRoot(reRooted("link", null).r);
    s.rerootSnapshotSeen = true;
    vi.advanceTimersByTime(EPOCH_OVERLAP_MS);
    // The next commit is applied by a task already queued when the timer
    // finds the old keys due.
    void exclusive(async () => session.applyReRoot(reRooted("link", null).r));
    const forgetting = session.forgetOldRoot();
    release();
    await queued;
    await forgetting;
    expect(keyring.forgot).toBe(0);
  });
});

describe("a tab the room removed", () => {
  it("stops reconnecting and says so once, whether 4014, a commit naming its key, or both reached it", () => {
    const { session, calls, shown } = fakeSession();
    session.removedFromRoom();
    session.removedFromRoom();
    expect(shown.removed).toBe(1);
    expect(calls.filter((c) => c === "stopReconnecting")).toHaveLength(1);
  });

  it("keeps the document it holds: nothing is destroyed, closed or wiped", () => {
    const { session, calls } = fakeSession();
    session.removedFromRoom();
    expect(calls).not.toContain("doc destroy");
    expect(calls).not.toContain("close");
    expect(calls).not.toContain("dropKeys");
  });

  it("does not throw when the page's callback does", () => {
    const { session } = fakeSession({ throwingPage: true });
    expect(() => session.removedFromRoom()).not.toThrow();
  });

  it("does not try to bring the room back after a restart", () => {
    const { s, session } = fakeSession();
    Object.assign(s.socket as object, { heldRestartTicket: () => ({ ticket: "t", at: Date.now() }) });
    (s.cfg as Record<string, unknown>).restoreRoom = async () => "restored";
    session.removedFromRoom();
    expect(session.carryOver()).toBe(false);
  });
});

describe("what the session says about eviction frames", () => {
  it("shows a commit that failed its checks as a refused key change", () => {
    const { session, shown } = fakeSession();
    session.evictRefused("commit-signature");
    expect(shown.keyStatus).toEqual([KEY_STATUS_TEXT.refused]);
    expect(shown.ignored).toEqual([]);
  });

  it("passes on any other refusal as a request ignored", () => {
    const { session, shown } = fakeSession();
    session.evictRefused("roster-mismatch");
    expect(shown.ignored).toEqual(["roster-mismatch"]);
    expect(shown.keyStatus).toEqual([]);
  });

  it("names who asked and who would be removed by their keys", async () => {
    const { session, shown } = fakeSession();
    const proposerKey = new Uint8Array(32).fill(5);
    const targetKey = new Uint8Array(32).fill(6);
    await session.raiseEvictPrompt({ requestId: new Uint8Array(16), proposerKey, target: new Uint8Array(16), targetKey });
    expect(shown.prompts).toEqual([{ by: await handleFromPubkey(proposerKey), who: await handleFromPubkey(targetKey) }]);
  });

  it("tells a tab left out of a re-root what happened without the tampering alarm", () => {
    // Controller's decision (fix wave 1, M4): the alarm means possible
    // tampering and sticks over a later SECURE. A member left out of a
    // re-root, or one that joined after the request, was not tampered with.
    const tempers: string[] = [];
    const shown: { m: string | null; alarming: boolean }[] = [];
    const report = keyStatusReporter({ onKeyStatus: (m, alarming) => shown.push({ m, alarming }), onTemper: (t) => tempers.push(t) });
    report("left-out");
    expect(report.alarming()).toBe(false);
    expect(tempers).toEqual([]);
    expect(shown).toEqual([{ m: KEY_STATUS_TEXT["left-out"], alarming: false }]);
  });

  it("does not raise the alarm for a commit that lost a race to another one", () => {
    const { session, shown } = fakeSession();
    session.evictRefused("commit-stale");
    expect(shown.keyStatus).toEqual([]);
    expect(shown.ignored).toEqual([]);
  });

  it("does not raise the alarm when this tab's own commit fails, and still does for anyone else's", async () => {
    const { session, shown } = fakeSession();
    // The coordinator ends this tab's vote, then refuses the commit, in one go.
    session.evictStateChanged("FAILED", "commit-keys");
    session.evictRefused("commit-keys");
    expect(shown.keyStatus).toEqual([]);
    // Someone else's commit with the same fault, straight after.
    session.evictRefused("commit-keys");
    expect(shown.keyStatus).toEqual([KEY_STATUS_TEXT.refused]);
  });

  it("forgets that its own commit failed once the coordinator's task is over", async () => {
    const { session, shown } = fakeSession();
    session.evictStateChanged("FAILED", "commit-config");
    await Promise.resolve();
    session.evictRefused("commit-config");
    expect(shown.keyStatus).toEqual([KEY_STATUS_TEXT.refused]);
  });

  it("raises no prompt for a vote that ended while the names were worked out", async () => {
    const { s, session, shown } = fakeSession();
    const requestId = new Uint8Array(16).fill(3);
    const machine = { state: "VOTING", current: () => ({ request: { id: requestId } }) };
    s.evict = { machine };
    const prompt = { requestId, proposerKey: new Uint8Array(32).fill(5), target: null, targetKey: null };
    const raising = session.raiseEvictPrompt(prompt);
    machine.state = "CANCELLED";
    await raising;
    expect(shown.prompts).toEqual([]);
    machine.state = "VOTING";
    await session.raiseEvictPrompt(prompt);
    expect(shown.prompts).toHaveLength(1);
    // A different request open now is not the one asked about.
    await session.raiseEvictPrompt({ ...prompt, requestId: new Uint8Array(16).fill(4) });
    expect(shown.prompts).toHaveLength(1);
  });
});

describe("asking the room", () => {
  it("holds a shared room's new passphrase to the create form's strength check before anyone is asked", async () => {
    const { s, session } = fakeSession({ wayKind: "pass" });
    const propose = vi.fn();
    s.evict = { propose };
    expect(await session.proposeEviction(null, "short")).toBe("weak-passphrase");
    expect(await session.proposeEviction(null)).toBe("weak-passphrase");
    expect(propose).not.toHaveBeenCalled();
  });

  it("says the person has left when they are no longer listed", async () => {
    const { s, session } = fakeSession();
    const propose = vi.fn();
    s.evict = { propose };
    expect(await session.proposeEviction(new Uint8Array(16).fill(8))).toBe("target-gone");
    expect(propose).not.toHaveBeenCalled();
  });

  it("hands a private room's new link to the coordinator with the listed member", async () => {
    const { s, session } = fakeSession();
    const target = { peerId: new Uint8Array(16).fill(8), pubkey: new Uint8Array(32).fill(1), joinedAtSeq: 2 };
    (s.internals as { roster: Map<string, unknown> }).roster.set(toB64(target.peerId), target);
    const propose = vi.fn(async () => null);
    s.evict = { propose };
    expect(await session.proposeEviction(target.peerId.slice())).toBeNull();
    expect(propose).toHaveBeenCalledTimes(1);
    const [victim, way] = propose.mock.calls[0] as unknown as [unknown, { kind: string; secret: Uint8Array }];
    expect(victim).toBe(target);
    expect(way.kind).toBe("link");
    expect(way.secret).toHaveLength(32);
  });

  it("seals the room's own config into a commit, or the strictest one when none opened", () => {
    const { s, session } = fakeSession();
    expect(session.sealedConfig()).toEqual({ ttl: { kind: "none", secs: 0 }, ceilingOptout: false, level: "highest" });
    s.sealed = { ttl: { kind: "absolute", secs: 86_400 }, ceilingOptout: true, level: "everyday" };
    expect(session.sealedConfig()).toEqual({ ttl: { kind: "absolute", secs: 86_400 }, ceilingOptout: true, level: "everyday" });
  });
});
