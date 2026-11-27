import { describe, expect, it } from "vitest";
import {
  EVICT_COPY,
  evictCopy,
  evictStateText,
  fingerprintLine,
  ignoredText,
  proposeErrorText,
  removedLine,
  voteBody,
  voteTitle,
} from "./copy";

const FAIL_REASONS = [
  "proposer-left",
  "voter-left",
  "root-moved",
  "no-echo",
  "no-commit",
  "left-out",
  "not-sent",
  "send-failed",
  "commit-failed",
  "commit-keys",
  "other",
];
const PROPOSE_CODES = [
  "weak-passphrase",
  "kdf-unavailable",
  "target-gone",
  "bad-target",
  "roster-changed",
  "busy",
  "not-joined",
  "not-sent",
  "failed",
  "other",
];

function everyString(): string[] {
  const out: string[] = Object.values(EVICT_COPY);
  out.push(voteTitle("COPPER-LANTERN"), voteTitle(null), voteBody("TIN-HARBOUR", "COPPER-LANTERN"), voteBody("TIN-HARBOUR", null));
  out.push(removedLine("COPPER-LANTERN"), fingerprintLine("A-B-C-D-E-F"), ignoredText("busy"));
  for (const s of ["VOTING", "APPROVED", "REJECTED", "EXPIRED", "CANCELLED", "FAILED", "DONE"]) out.push(evictStateText(s));
  for (const r of FAIL_REASONS) out.push(evictStateText("FAILED", r));
  for (const c of PROPOSE_CODES) out.push(proposeErrorText(c));
  return out;
}

describe("the eviction flow's words", () => {
  it("have no em dashes and never say 'we'", () => {
    for (const t of everyString()) {
      expect(t).not.toMatch(/\u2014/);
      expect(t).not.toMatch(/\bwe\b/i);
    }
  });

  it("tell people to send the new way in on, and to compare the fingerprint again", () => {
    expect(EVICT_COPY.newWayBody).toMatch(/Send it to anyone who should still be here/);
    expect(fingerprintLine("X")).toMatch(/Compare it again/);
    expect(EVICT_COPY.removedBody).toMatch(/You were removed from this room/);
  });

  it("say something for every state a vote can end in, and every reason the session or the coordinator gives", () => {
    for (const s of ["VOTING", "APPROVED", "REJECTED", "EXPIRED", "CANCELLED", "FAILED"]) expect(evictStateText(s)).not.toBe("");
    for (const r of FAIL_REASONS) expect(evictStateText("FAILED", r)).not.toBe("");
    for (const c of PROPOSE_CODES) expect(proposeErrorText(c)).not.toBe("");
  });

  it("tell a tab that was left out of a link change that it needs the new one", () => {
    expect(evictStateText("FAILED", "left-out")).toMatch(/not given the new one/);
  });

  it("say that nothing changed when a request could not be sent", () => {
    expect(evictStateText("FAILED", "not-sent")).toMatch(/Nothing changed/);
    expect(proposeErrorText("roster-changed")).toMatch(/Try again/);
  });
});

/// Every reason the evict coordinator hands the session's `refused` dep that
/// the session passes on as a request ignored.
const IGNORED_REASONS = [
  "malformed",
  "busy",
  "policy-not-permitted",
  "wrong-root",
  "unknown-proposer",
  "proposer-is-target",
  "unknown-target",
  "target-key-mismatch",
  "roster-mismatch",
  "bad-signature",
  "unknown-request",
  "not-voting",
  "not-in-policy-set",
  "duplicate-vote",
  "cancel-not-from-proposer",
];

describe("the words a person reads (fix wave 1)", () => {
  it("say what was copied as a sentence with a subject", () => {
    expect(EVICT_COPY.copied).toMatch(/^The new link is copied\./);
    expect(EVICT_COPY.copiedPassphrase).toMatch(/^The new passphrase is copied\./);
  });

  it("never show a raw reason code for a request ignored, and say something plain for one not mapped", () => {
    const seen = new Set<string>();
    for (const r of [...IGNORED_REASONS, "something-new"]) {
      for (const way of [undefined, "link", "pass"] as const) {
        const t = ignoredText(r, way);
        expect(t).not.toContain(r);
        expect(t).not.toMatch(/[()]/);
        expect(t).toMatch(/^This tab ignored /);
        expect(t).not.toMatch(/\u2014/);
        expect(t).not.toMatch(/\bwe\b/i);
        if (way === "link") seen.add(t);
      }
    }
    // Each mapped reason says why in its own words.
    expect(seen.size).toBeGreaterThan(IGNORED_REASONS.length / 2);
    expect(ignoredText("something-new")).toBe(ignoredText("another-unmapped-code"));
  });

  it("tell a shared room about its passphrase and never about a link", () => {
    const pass = [
      evictCopy("pass").title,
      evictCopy("pass").relinkButton,
      evictCopy("pass").nobody,
      evictCopy("pass").removedBody,
      evictCopy("pass").gone,
      voteTitle(null, "pass"),
      voteBody("TIN-HARBOUR", null, "pass"),
      voteBody("TIN-HARBOUR", "COPPER-LANTERN", "pass"),
      evictStateText("FAILED", "left-out", "pass"),
      evictStateText("FAILED", "root-moved", "pass"),
      proposeErrorText("target-gone", "pass"),
      ...IGNORED_REASONS.map((r) => ignoredText(r, "pass")),
    ];
    for (const t of pass) expect(t).not.toMatch(/\blink\b/i);
    expect(evictCopy("pass").removedBody).toMatch(/The passphrase you used no longer opens it/);
    expect(voteTitle(null, "pass")).toBe("CHANGE THE PASSPHRASE?");
    expect(evictStateText("FAILED", "left-out", "pass")).toMatch(/passphrase changed, and this tab was not given the new one/);
  });

  it("tell a private room about its link, and keep today's words when the kind is not given", () => {
    expect(evictCopy("link")).toEqual(EVICT_COPY);
    expect(evictCopy()).toEqual(EVICT_COPY);
    expect(voteTitle(null)).toBe("CHANGE THE LINK?");
    expect(voteTitle(null, "link")).toBe("CHANGE THE LINK?");
    expect(evictStateText("FAILED", "left-out", "link")).toMatch(/link changed/);
    expect(evictStateText("FAILED", "left-out")).toBe(evictStateText("FAILED", "left-out", undefined));
    expect(voteBody("A", null)).toMatch(/link or passphrase/);
    expect(voteBody("A", null, "link")).not.toMatch(/passphrase/);
    expect(proposeErrorText("target-gone")).toMatch(/Change the link/);
  });

  it("have no em dashes and never say 'we' in a shared room's words either", () => {
    for (const t of [...Object.values(evictCopy("pass")), voteTitle(null, "pass"), voteBody("A", null, "pass"), evictStateText("FAILED", "left-out", "pass")]) {
      expect(t).not.toMatch(/\u2014/);
      expect(t).not.toMatch(/\bwe\b/i);
    }
  });
});
