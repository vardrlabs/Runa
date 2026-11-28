import { describe, expect, it } from "vitest";
import { MAX_OPEN_REQUESTS } from "./coordinator";
import { EMPTY_PROMPTS, MAX_ENDED_PROMPTS, promptAnswered, promptArrived, shownPrompt, voteEnded, type PromptQueue } from "./prompts";

const p = (id: string) => ({ id, by: `BY-${id}`, who: null });
const ids = (q: PromptQueue) => q.waiting.map((x) => x.id);

describe("the page's vote prompts (V1, rule 6)", () => {
  it("shows one prompt at a time, in the order the requests arrived, and answering shows the next", () => {
    let q = promptArrived(EMPTY_PROMPTS, p("a"));
    q = promptArrived(q, p("b"));
    q = promptArrived(q, p("c"));
    expect(shownPrompt(q, false)?.id).toBe("a");
    q = promptAnswered(q, "a");
    expect(shownPrompt(q, false)?.id).toBe("b");
    q = promptAnswered(q, "b");
    expect(shownPrompt(q, false)?.id).toBe("c");
    q = promptAnswered(q, "c");
    expect(shownPrompt(q, false)).toBeNull();
  });

  it("drops a waiting prompt whose vote ended without showing it, and closes the one shown when its vote ends", () => {
    let q = promptArrived(promptArrived(promptArrived(EMPTY_PROMPTS, p("a")), p("b")), p("c"));
    q = voteEnded(q, "b");
    expect(ids(q)).toEqual(["a", "c"]);
    q = voteEnded(q, "a");
    expect(shownPrompt(q, false)?.id).toBe("c");
  });

  it("never shows a prompt that arrives after its vote ended, or the same request twice", () => {
    let q = voteEnded(EMPTY_PROMPTS, "a");
    q = promptArrived(q, p("a"));
    expect(shownPrompt(q, false)).toBeNull();
    q = promptArrived(promptArrived(q, p("b")), p("b"));
    expect(ids(q)).toEqual(["b"]);
  });

  it("puts every prompt aside while the ask dialog is open, keeps one that arrives meanwhile, and shows the oldest after", () => {
    let q = promptArrived(EMPTY_PROMPTS, p("a"));
    expect(shownPrompt(q, true)).toBeNull();
    q = promptArrived(q, p("b"));
    expect(shownPrompt(q, true)).toBeNull();
    expect(ids(q)).toEqual(["a", "b"]);
    expect(shownPrompt(q, false)?.id).toBe("a");
  });

  it("holds at most as many prompts as a member holds open requests, and a bounded record of ended ones", () => {
    let q = EMPTY_PROMPTS;
    for (let i = 0; i < MAX_OPEN_REQUESTS + 3; i++) q = promptArrived(q, p(`r${i}`));
    expect(q.waiting).toHaveLength(MAX_OPEN_REQUESTS);
    for (let i = 0; i < MAX_ENDED_PROMPTS * 2; i++) q = voteEnded(q, `e${i}`);
    expect(q.ended).toHaveLength(MAX_ENDED_PROMPTS);
    expect(q.ended.at(-1)).toBe(`e${MAX_ENDED_PROMPTS * 2 - 1}`);
  });
});
