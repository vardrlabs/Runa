import { MAX_OPEN_REQUESTS } from "./coordinator";

/// The vote prompts a page has to show (PROTOCOL.md amendment K), one at a
/// time, in the order their requests arrived. Several votes can be open at
/// once, so the page keeps a queue: answering the prompt on screen shows the
/// next, a prompt whose vote has ended is dropped whether or not it was on
/// screen, and while the person has the ask dialog open no prompt is shown at
/// all. Nothing here ever stops the person asking the room themselves.
///
/// Plain values and functions, so a React state setter can hold them.

export interface PromptView {
  /// The request id, as the session names it.
  id: string;
  by: string;
  who: string | null;
}

export interface PromptQueue {
  /// Prompts not yet answered, oldest first.
  waiting: readonly PromptView[];
  /// Requests whose vote has ended here, newest last, so a prompt that comes
  /// after its own ending is never shown.
  ended: readonly string[];
}

/// How many ended requests a page remembers. A member holds at most
/// `MAX_OPEN_REQUESTS` open at once, so this covers several rounds of them.
export const MAX_ENDED_PROMPTS = 64;

export const EMPTY_PROMPTS: PromptQueue = { waiting: [], ended: [] };

/// A request asks this member. Ignored when its vote has already ended here,
/// when it is already waiting, or past the bound on open requests.
export function promptArrived(q: PromptQueue, p: PromptView): PromptQueue {
  if (q.ended.includes(p.id) || q.waiting.some((x) => x.id === p.id)) return q;
  if (q.waiting.length >= MAX_OPEN_REQUESTS) return q;
  return { ...q, waiting: [...q.waiting, p] };
}

/// The vote on a request ended: its prompt goes, shown or not.
export function voteEnded(q: PromptQueue, id: string): PromptQueue {
  const ended = q.ended.includes(id) ? q.ended : [...q.ended, id].slice(-MAX_ENDED_PROMPTS);
  return { waiting: q.waiting.filter((x) => x.id !== id), ended };
}

/// The person answered the prompt for this request.
export function promptAnswered(q: PromptQueue, id: string): PromptQueue {
  return { ...q, waiting: q.waiting.filter((x) => x.id !== id) };
}

/// The prompt on screen: the oldest waiting, unless the ask dialog is open,
/// which puts every prompt aside until it closes.
export function shownPrompt(q: PromptQueue, askOpen: boolean): PromptView | null {
  return askOpen ? null : (q.waiting[0] ?? null);
}
