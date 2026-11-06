import { describe, expect, it } from "vitest";
import { departedMembers, KEY_STATUS_TEXT, keyStatusReporter } from "./session";

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
