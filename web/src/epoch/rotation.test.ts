import { describe, expect, it } from "vitest";
import { DepartureTracker, LEAVE_GRACE_MS, RESTART_GRACE_MS, rankOf, turnHasCome } from "./rotation";

const id = (n: number) => new Uint8Array(16).fill(n);

describe("DepartureTracker", () => {
  it("is due once a departure has been gone the whole grace", () => {
    const t = new DepartureTracker();
    t.left("k1", 0);
    expect(t.isDue(LEAVE_GRACE_MS - 1)).toBe(false);
    expect(t.isDue(LEAVE_GRACE_MS)).toBe(true);
  });

  it("forgets a departure whose signing key comes back", () => {
    const t = new DepartureTracker();
    t.left("k1", 0);
    t.returned("k1");
    expect(t.isDue(LEAVE_GRACE_MS * 2)).toBe(false);
  });

  it("drops only the departures a step covered", () => {
    const t = new DepartureTracker();
    t.left("k1", 0);
    t.left("k2", 50_000);
    t.cover(["k1"]);
    expect(t.pendingKeys()).toEqual(["k2"]);
    expect(t.isDue(LEAVE_GRACE_MS)).toBe(false);
    expect(t.isDue(50_000 + LEAVE_GRACE_MS)).toBe(true);
  });

  it("gives departures during a restart handover the longer grace", () => {
    const t = new DepartureTracker();
    t.noteRestartNotice(0, 60);
    t.left("k1", 70_000);
    expect(t.isDue(70_000 + LEAVE_GRACE_MS)).toBe(false);
    expect(t.isDue(70_000 + RESTART_GRACE_MS)).toBe(true);
  });
});

describe("restart notice", () => {
  it("ignores a non-finite or negative lead time", () => {
    for (const n of [NaN, Infinity, -Infinity, -1]) {
      const t = new DepartureTracker();
      t.noteRestartNotice(0, n);
      t.left("k1", 1);
      expect(t.isDue(1 + LEAVE_GRACE_MS)).toBe(true);
    }
  });
});

describe("election", () => {
  const roster = [
    { peerId: id(3), joinedAtSeq: 7 },
    { peerId: id(1), joinedAtSeq: 2 },
    { peerId: id(2), joinedAtSeq: 2 },
  ];

  it("ranks by join order, then by peer id", () => {
    expect(rankOf(roster, id(1))).toBe(0);
    expect(rankOf(roster, id(2))).toBe(1);
    expect(rankOf(roster, id(3))).toBe(2);
    expect(rankOf(roster, id(9))).toBe(-1);
  });

  it("lets each rank act only after the ones before it had their chance", () => {
    expect(turnHasCome(0, 0, 15_000)).toBe(true);
    expect(turnHasCome(1, 14_999, 15_000)).toBe(false);
    expect(turnHasCome(1, 15_000, 15_000)).toBe(true);
    expect(turnHasCome(-1, 1e9, 15_000)).toBe(false);
  });
});
