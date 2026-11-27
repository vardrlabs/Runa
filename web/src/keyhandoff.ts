/// Where an unlisted room's key lives between "I have the link" and "the room
/// is open" — and, just as much, where it does not.
///
/// The key is the URL fragment (`#k=…&s=…`). A fragment never reaches the
/// server, which is why it was put there, but the browser does write the full
/// URL into its history, and a browser with sync on copies that history to its
/// vendor. So the address bar is the one place the key should not stay:
///
///   - Opening a room from inside RÚNA (creating one, or pasting a link into
///     Join a room) hands the key over in memory. It never enters the address
///     bar, so no history entry ever carries it.
///   - Arriving from a clicked link, the key is taken out of the address bar
///     as the page starts. The browser may already have recorded the address
///     it was opened with; nothing a page does can reach that entry, which is
///     why the README tells people at risk to paste links into Join instead.
///   - An everyday room then keeps the key in this tab's history *state*,
///     which is not the address, not shown in history, and not synced, so a
///     refresh still works. A highest-security room keeps it in memory only:
///     refresh, and the tab has forgotten it.

import type { SecurityLevel } from "./security-level";

/// The key of the room this page last opened, in memory only. Asking twice
/// (React's strict mode does; so does Back then Forward within the page) must
/// not turn into "this link is missing its key". Gone with the page: a
/// shred ends in a hard navigation, which destroys it.
let current: { roomIdHex: string; fragment: string } | null = null;

interface KeyState {
  runaRoom: string;
  runaKey: string;
}

function keyState(): KeyState | null {
  const s = history.state as Partial<KeyState> | null;
  return s && typeof s.runaRoom === "string" && typeof s.runaKey === "string"
    ? { runaRoom: s.runaRoom, runaKey: s.runaKey }
    : null;
}

/// The key for the room at `/r/<roomIdHex>`, from wherever it is: a handoff,
/// the address (which this then clears), or the tab's saved state. Undefined
/// if there is none — a highest-security room after a refresh, say.
export function takeRoomKey(roomIdHex: string): string | undefined {
  const hash = window.location.hash;
  if (hash.startsWith("#k=")) {
    // Out of the address bar before anything else runs. Whatever this tab
    // had saved is dropped too: the room has not said yet whether it may be
    // kept, and `applySecurityLevel` puts it back if so.
    history.replaceState(null, "", window.location.pathname + window.location.search);
    current = { roomIdHex, fragment: hash };
    return hash;
  }
  if (current && current.roomIdHex === roomIdHex) return current.fragment;
  const saved = keyState();
  if (saved && saved.runaRoom === roomIdHex) {
    current = { roomIdHex, fragment: saved.runaKey };
    return saved.runaKey;
  }
  return undefined;
}

/// Open an unlisted room from inside the app, with its key in memory only.
export function openUnlistedRoom(roomIdHex: string, fragment: string): void {
  current = { roomIdHex, fragment };
  history.pushState(null, "", `/r/${roomIdHex}`);
  window.dispatchEvent(new PopStateEvent("popstate", { state: null }));
}

/// Once the room's sealed config has said how it wants its key treated.
export function applySecurityLevel(
  roomIdHex: string,
  fragment: string,
  level: SecurityLevel,
): void {
  const here = window.location.pathname + window.location.search;
  if (level === "everyday") {
    history.replaceState({ runaRoom: roomIdHex, runaKey: fragment } satisfies KeyState, "", here);
  } else if (keyState()) {
    history.replaceState(null, "", here);
  }
}

/// The room's link changed (amendment K): the old key opens nothing now.
/// The new one replaces it in memory, and in an everyday room in the tab's
/// saved state too, so a refresh comes back in with it. A highest-security
/// room keeps it in memory only, and drops any key the tab had saved.
export function replaceRoomKey(roomIdHex: string, fragment: string, level: SecurityLevel): void {
  current = { roomIdHex, fragment };
  applySecurityLevel(roomIdHex, fragment, level);
}

/// The full shareable link, built from the key in memory rather than read
/// from an address bar that no longer holds it.
export function shareLink(roomIdHex: string, fragment: string): string {
  return `${window.location.origin}/r/${roomIdHex}${fragment}`;
}

/// A shared room opened from inside RÚNA (created on the front page, or typed
/// into Join a room). Its address would be its name, so it opens at `/` with
/// the name in memory, read once by the route, and only reaches the address
/// once the room says it may (`applyNamedSecurityLevel`).
let pendingNamed: string | null = null;

export function openNamedRoom(name: string): void {
  pendingNamed = name;
  history.pushState(null, "", "/");
  window.dispatchEvent(new PopStateEvent("popstate", { state: null }));
}

/// The name handed over by `openNamedRoom`, once. A second read, a refresh,
/// or Back to this entry gets nothing, and lands on the front page.
export function takePendingNamedRoom(): string | null {
  const name = pendingNamed;
  pendingNamed = null;
  return name;
}

/// An everyday shared room takes its usual address, `/<name>`, so it can be
/// refreshed and shared. A highest-security one keeps the name out: `/`.
export function applyNamedSecurityLevel(name: string, level: SecurityLevel): void {
  const target = level === "highest" ? "/" : `/${name}`;
  if (window.location.pathname !== target) history.replaceState(null, "", target);
}

