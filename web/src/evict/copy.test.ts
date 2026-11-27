import { describe, expect, it } from "vitest";
import {
  EVICT_COPY,
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
  "epoch-moved",
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
