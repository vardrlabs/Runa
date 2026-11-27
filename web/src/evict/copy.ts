/// Every sentence the eviction and link-change flow shows (PROTOCOL.md
/// amendment K), kept in one place so a test can hold them to the writing
/// rules: plain spoken sentences, no em dashes, never "we". Buttons, titles
/// and field labels stay terse.
///
/// A shared room is opened with a passphrase, and is never told about a link.
/// The functions below take the room's way-in kind as an optional last
/// argument; left out, they say what they said before it existed.

import type { WayKind } from "./reroot";

export const EVICT_COPY = {
  removeButton: "Remove someone",
  relinkButton: "Change link",
  title: "REMOVE SOMEONE OR CHANGE THE LINK",
  nobody: "Nobody, only the link changes",
  explainLink:
    "The room gets a new link and the old one stops working. Everyone else here has to agree, and any one of them can refuse. Anyone not connected right now will need the new link from someone who is.",
  explainPass:
    "The room gets a new passphrase and the old one stops working. Everyone else here has to agree, and any one of them can refuse. Anyone not connected right now will need the new passphrase from someone who is.",
  newPassphraseLabel: "NEW PASSPHRASE",
  propose: "Ask the room",
  deriving: "Deriving keys…",
  cancel: "Cancel",
  approve: "Agree",
  reject: "Refuse",
  done: "Done",
  copy: "Copy",
  newLinkTitle: "THIS ROOM HAS A NEW LINK",
  newPassTitle: "THIS ROOM HAS A NEW PASSPHRASE",
  newWayBody:
    "Send it to anyone who should still be here. The old one no longer opens the room, and this is the only time it is shown.",
  removedTitle: "REMOVED FROM THIS ROOM",
  removedBody: "You were removed from this room. The link you used no longer opens it.",
  copied: "The new link is copied. The part after the # is the key.",
  copiedPassphrase: "The new passphrase is copied. Send it separately from the room's address.",
  authFailed: "The passphrase is wrong, or this room no longer exists. If someone changed its passphrase, ask them for the new one.",
  gone: "It was shredded, it expired, the server restarted, or someone changed its link. If the link changed, ask someone who is still in the room for the new one. Rooms live only in memory, so there is no copy to recover.",
} as const;

/// The words of `EVICT_COPY` that name the way in, for a shared room.
const PASS_COPY = {
  title: "REMOVE SOMEONE OR CHANGE THE PASSPHRASE",
  relinkButton: "Change passphrase",
  nobody: "Nobody, only the passphrase changes",
  removedBody: "You were removed from this room. The passphrase you used no longer opens it.",
  gone: "It was shredded, it expired, the server restarted, or someone changed its passphrase. If the passphrase changed, ask someone who is still in the room for the new one. Rooms live only in memory, so there is no copy to recover.",
} as const;

/// `EVICT_COPY` for a room opened the way `way` says. A private room's is
/// `EVICT_COPY` itself.
export function evictCopy(way: WayKind = "link"): Record<keyof typeof EVICT_COPY, string> {
  return way === "pass" ? { ...EVICT_COPY, ...PASS_COPY } : EVICT_COPY;
}

/// What a sentence calls the way in. Without a kind, both, as before.
function wayWord(way: WayKind | undefined): string {
  if (way === "pass") return "passphrase";
  if (way === "link") return "link";
  return "link or passphrase";
}

export function voteTitle(who: string | null, way: WayKind = "link"): string {
  if (who) return `REMOVE ${who}?`;
  return way === "pass" ? "CHANGE THE PASSPHRASE?" : "CHANGE THE LINK?";
}

export function voteBody(by: string, who: string | null, way?: WayKind): string {
  const word = wayWord(way);
  return who
    ? `${by} asks to remove ${who} from this room. The room gets a new ${word}, and ${who} cannot come back with the old one. Any one person here can refuse.`
    : `${by} asks to change this room's ${word}. The old one stops working. Any one person here can refuse.`;
}

export function removedLine(who: string): string {
  return `${who} was removed from this room.`;
}

export function fingerprintLine(fp: string): string {
  return `The room's fingerprint is now ${fp}. Compare it again with the others.`;
}

/// What the page says about where a vote stands, for each state the evict
/// coordinator reports (and the reason it gives with FAILED).
export function evictStateText(state: string, reason?: string, way?: WayKind): string {
  switch (state) {
    case "VOTING":
      return "The request is waiting for everyone else to agree.";
    case "APPROVED":
      return "Everyone agreed, and the room's key is changing now.";
    case "REJECTED":
      return "Someone refused, so nothing changed.";
    case "EXPIRED":
      return "Not everyone answered in time, so nothing changed.";
    case "CANCELLED":
      return "The request was withdrawn, so nothing changed.";
    case "FAILED":
      return failText(reason, way);
    default:
      return "";
  }
}

function failText(reason: string | undefined, way: WayKind | undefined): string {
  switch (reason) {
    case "proposer-left":
      return "The person who asked left before the vote finished. Nothing changed.";
    case "voter-left":
      return "Someone left before the vote finished. Nothing changed.";
    case "epoch-moved":
      return "The room's key changed during the vote. Nothing changed, and you can ask again.";
    case "no-echo":
    case "no-commit":
      return "The server did not take the change, so nothing changed.";
    case "not-sent":
    case "send-failed":
      return "This tab could not send its part of the vote. Nothing changed.";
    case "left-out":
      return `The room's ${way === "pass" ? "passphrase" : "link"} changed, and this tab was not given the new one. Ask someone in the room for it.`;
    default:
      return "The request could not finish, so nothing changed.";
  }
}

/// Why a request to remove someone or change the link was not sent, for each
/// code `Session.proposeEviction` returns.
export function proposeErrorText(code: string, way?: WayKind): string {
  switch (code) {
    case "weak-passphrase":
      return "This room's passphrase is the only key protecting it. Use a longer one, or press Generate.";
    case "kdf-unavailable":
      return "This browser could not run Argon2, which protects a shared room's passphrase.";
    case "target-gone":
    case "bad-target":
      return `That person has already left. Change the ${way === "pass" ? "passphrase" : "link"} to keep them out.`;
    case "roster-changed":
      return "Someone joined or left while the request was being made. Try again.";
    case "busy":
      return "Another request is already open in this room.";
    case "not-joined":
    case "not-sent":
      return "This tab is not connected right now. Try again in a moment.";
    default:
      return "The request could not be sent.";
  }
}

/// What the page says about a request, vote or withdrawal this tab ignored,
/// for each reason the evict coordinator gives. A reason code is never shown:
/// one not listed here gets the plain fallback.
export function ignoredText(reason: string, way?: WayKind): string {
  const word = wayWord(way);
  const request = `This tab ignored a request to remove someone or change the ${word}`;
  switch (reason) {
    case "busy":
      return `${request}, because another one is already open.`;
    case "wrong-epoch":
      return `${request}, because it was made before the room's key last changed.`;
    case "roster-mismatch":
      return `${request}, because it was made with a different list of people than this tab sees.`;
    case "unknown-proposer":
      return `${request}, because the person who sent it is not in this tab's list of people.`;
    case "unknown-target":
      return `${request}, because the person it names is not in this tab's list of people.`;
    case "target-key-mismatch":
      return `${request}, because it names someone by a key that is not theirs.`;
    case "proposer-is-target":
      return `${request}, because the person who sent it named themselves.`;
    case "policy-not-permitted":
      return `${request}, because it did not ask for everyone to agree.`;
    case "bad-signature":
      return `This tab ignored a message about removing someone or changing the ${word}, because its signature did not check out. Someone may be interfering with the room.`;
    case "unknown-request":
    case "not-voting":
      return "This tab ignored an answer to a vote that is no longer open.";
    case "duplicate-vote":
      return "This tab ignored a second answer from the same person.";
    case "not-in-policy-set":
      return "This tab ignored an answer from someone who is not part of the vote.";
    case "cancel-not-from-proposer":
      return "This tab ignored a withdrawal sent by someone other than the person who asked.";
    case "malformed":
      return `This tab ignored a message about removing someone or changing the ${word}, because it could not be read.`;
    default:
      return `This tab ignored a message about removing someone or changing the ${word}.`;
  }
}
