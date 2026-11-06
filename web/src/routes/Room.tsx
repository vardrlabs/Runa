import { KdfUnavailableError } from "../crypto/kdf";
import { useCallback, useEffect, useRef, useState } from "react";
import Editor, { loader } from "@monaco-editor/react";
import * as monacoModule from "monaco-editor";
import type { editor as MonacoEditor } from "monaco-editor";
import { clipboardReadAsksEveryTime, openBrowserMenuOnRightClick } from "../ui/contextmenu";

loader.config({ monaco: monacoModule });

self.MonacoEnvironment = {
  getWorker() {
    return new Worker(new URL("monaco-editor/esm/vs/editor/editor.worker.js", import.meta.url), { type: "module" });
  },
};
import { Session, type LadderPhase } from "../session";
import {
  deriveRoomKeys,
  parseFragment,
  passphraseMaterial,
} from "../keys-session";
import { Api } from "../api";
import { renderMarkdown, isExternalHref } from "../render/pipeline";
import { type TemperState } from "../ui/temper";
import { QuorumDial, useAccent } from "../ui/dial";
import { ShredModal } from "../ui/ShredModal";
import { supermajorityFor } from "../shred/machine";
import type { Policy } from "../shred/machine";
import type { ShredRequest } from "../shred/machine";
import { MissingKey } from "./MissingKey";
import { exportPdf, type ExportDensity } from "../export/paged";
import { exportMarkdown } from "../export/markdown";
import { TOOLBAR_ACTIONS, applyTool } from "../ui/toolbar";
import { useLineSync } from "../ui/linesync";
import { applyNamedSecurityLevel, applySecurityLevel, shareLink } from "../keyhandoff";
import { plainWebSocketAllowed } from "../transport/origin";

const api = new Api("");

export interface RoomProps {
  roomIdHex?: string;
  name?: string;
  fragment?: string;
}

type Phase =
  | { kind: "passphrase" }
  | { kind: "connecting" }
  | { kind: "missing-key" }
  | { kind: "auth-failed" }
  | { kind: "kdf-unavailable" }
  | { kind: "insecure-origin" }
  | { kind: "live"; session: Session; peerCount: number }
  | { kind: "purged" }
  | { kind: "unavailable" };

let extNoticeShown = false;
let highestNoticeShown = false;
let externalConfirmed = false;

export function Room(props: RoomProps) {
  if (props.roomIdHex && props.fragment === undefined) {
    return <MissingKey />;
  }
  return <JoinableRoom {...props} />;
}

function JoinableRoom(props: RoomProps) {
  const [phase, setPhase] = useState<Phase>({ kind: props.name ? "passphrase" : "connecting" });
  const sessionRef = useRef<Session | null>(null);
  const [markdown, setMarkdown] = useState("");
  const [html, setHtml] = useState("");
  const [peerCount, setPeerCount] = useState(0);
  // What the status bar shows. Kept separate from peerCount, which is the
  // roster size and feeds the shred consensus bar.
  const [livePeerCount, setLivePeerCount] = useState(1);
  const [temper, setTemper] = useState<TemperState>("COLD");
  const [shredOpen, setShredOpen] = useState(false);
  const [shredPrompt, setShredPrompt] = useState<ShredRequest | null>(null);
  const [shredLabel, setShredLabel] = useState("IDLE");
  const [shredPolicy, setShredPolicy] = useState<Policy>("UNANIMOUS");
  const [fingerprint, setFingerprint] = useState<string>("");
  const [mode, setMode] = useState<"split" | "editor" | "preview">("split");
  const [ladder, setLadder] = useState<LadderPhase>({ kind: "normal", remainingMs: 0 });
  const [ttlMismatch, setTtlMismatch] = useState(false);
  // A highest-security room keeps its key in this tab's memory only, so a
  // refresh forgets it. Said once, so nobody refreshes and is locked out.
  const [highestNotice, setHighestNotice] = useState(false);
  const [historyPressure, setHistoryPressure] = useState<string | null>(null);
  const [keyStatus, setKeyStatus] = useState<{ text: string; alarming: boolean } | null>(null);
  const [tally, setTally] = useState<{ approved: number; total: number; waitingOn?: string } | null>(null);
  const [diverged, setDiverged] = useState(false);
  // A restart the server has announced, as a deadline on this page's clock.
  const [restartAt, setRestartAt] = useState<number | null>(null);
  // Whether the server said the room will carry over to the new process.
  const [restartHandover, setRestartHandover] = useState(false);
  const [clock, setClock] = useState(() => performance.now());
  const [connRefused, setConnRefused] = useState<string | null>(null);
  const restartAnnouncedRef = useRef(false);
  const [showExtNotice, setShowExtNotice] = useState(() => !extNoticeShown);
  const editorRef = useRef<MonacoEditor.IStandaloneCodeEditor | null>(null);
  const editorAdapterRef = useRef<{
    scrollTop(line: number): void;
    getTopVisibleLine(): number;
    lineHeightPx: number;
    onScroll(fn: () => void): () => void;
  } | null>(null);
  const previewPaneRef = useRef<HTMLDivElement | null>(null);
  const [steady, setSteady] = useState(false);
  const [awayNames, setAwayNames] = useState<string[]>([]);
  const [menuOpen, setMenuOpen] = useState(false);
  const [exportOpen, setExportOpen] = useState(false);
  const menuRef = useRef<HTMLDivElement | null>(null);
  // Below the panes breakpoint the split mode renders identically to
  // editor-only — the stylesheet hides the preview — so offering it there is
  // offering a control that does nothing observable.
  const [isNarrow, setIsNarrow] = useState(
    () =>
      typeof window !== "undefined" &&
      typeof window.matchMedia === "function" &&
      window.matchMedia(NARROW_QUERY).matches,
  );

  useAccent(temper);

  useEffect(() => {
    if (restartAt === null) return;
    const id = setInterval(() => setClock(performance.now()), 500);
    return () => clearInterval(id);
  }, [restartAt]);

  // Presence expires on a timer rather than on an event, so it has to be
  // sampled: nobody sends a frame to say they have gone quiet.
  useEffect(() => {
    const t = setInterval(() => {
      setLivePeerCount(sessionRef.current?.livePeerCount ?? 1);
      setAwayNames(sessionRef.current?.awayPeers().map((p) => p.handle) ?? []);
    }, 2_000);
    return () => clearInterval(t);
  }, []);

  useEffect(() => {
    if (typeof window === "undefined" || typeof window.matchMedia !== "function") return;
    const mq = window.matchMedia(NARROW_QUERY);
    const sync = () => setIsNarrow(mq.matches);
    sync();
    mq.addEventListener("change", sync);
    return () => mq.removeEventListener("change", sync);
  }, []);

  // An overflow menu that cannot be dismissed without choosing something is a
  // trap on a phone, where there is no Escape key in reach and the panel
  // covers the editor.
  useEffect(() => {
    if (!menuOpen) return;
    const onDown = (e: PointerEvent) => {
      if (menuRef.current && !menuRef.current.contains(e.target as Node)) setMenuOpen(false);
    };
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") setMenuOpen(false);
    };
    document.addEventListener("pointerdown", onDown);
    document.addEventListener("keydown", onKey);
    return () => {
      document.removeEventListener("pointerdown", onDown);
      document.removeEventListener("keydown", onKey);
    };
  }, [menuOpen]);

  useEffect(() => {
    let cancelled = false;
    const boot = async () => {
      if (props.name) return;
      try {
        const keys = parseFragment(props.fragment ?? "");
        if (!keys || !props.roomIdHex) {
          if (!cancelled) setPhase({ kind: "missing-key" });
          return;
        }
        await startSession({
          roomIdHex: props.roomIdHex,
          passMaterial: null,
          linkSecret: keys.linkSecret,
          roomSalt: keys.roomSalt,
        });
      } catch (e) {
        if (cancelled) return;
        // The browser refuses ws:// from a non-loopback page, so an operator
        // who has not put TLS in front gets a hard failure here. Saying
        // "wrong passphrase" sends them looking in entirely the wrong place.
        setPhase(
          e instanceof Error && e.message === "INSECURE_ORIGIN"
            ? { kind: "insecure-origin" }
            : { kind: "auth-failed" },
        );
      }
    };
    void boot();
    return () => {
      cancelled = true;
    };
  }, []);

  const startSession = useCallback(
    async (args: {
      roomIdHex: string;
      passMaterial: Uint8Array | null;
      linkSecret: Uint8Array | null;
      roomSalt: Uint8Array;
    }) => {
      setPhase({ kind: "connecting" });
      const { authKey, contentKey, chainKey } = await deriveRoomKeys(
        args.passMaterial,
        args.linkSecret,
        args.roomSalt,
      );
      const wsInfo = websocketUrl(args.roomIdHex);
      const session = await Session.create(
        {
          url: wsInfo.url,
          roomIdHex: args.roomIdHex,
          authKey,
          contentKey,
          chainKey,
          insecureAllowed: plainWebSocketAllowed(window.location),
          restoreRoom: (ticket) => api.restoreRoom(ticket),
        },
        {
          onJoinAck: (_ack) => {
            setPhase((p) => (p.kind === "live" ? p : { kind: "live", session, peerCount }));
            void (async () => {
              try {
                const { fingerprintWords } = await import("../crypto/fingerprint");
                const { hkdfBits, INFO_FP } = await import("../crypto/keys");
                if (args.roomSalt && args.passMaterial) {
                  const seed = await hkdfBits(args.passMaterial, args.roomSalt, INFO_FP, 32);
                  setFingerprint(fingerprintWords(seed).join("-").toUpperCase());
                } else if (args.linkSecret && args.roomSalt) {
                  const seed = await hkdfBits(args.linkSecret, args.roomSalt, INFO_FP, 32);
                  setFingerprint(fingerprintWords(seed).join("-").toUpperCase());
                }
              } catch { void 0; }
            })();
          },
          onPeersChanged: (n) => {
            setPeerCount(n);
            setLivePeerCount(sessionRef.current?.livePeerCount ?? 1);
            setAwayNames(sessionRef.current?.awayPeers().map((p) => p.handle) ?? []);
          },
          onTemper: (t) => setTemper(t),
          onShredPrompt: (req) => {
            setShredPrompt(req);
            setShredOpen(true);
            setTemper("ARMED");
          },
          onShredState: (s) => {
            setShredLabel(s);
            const ses = sessionRef.current;
            if (ses) setTally(ses.tallySummary());
          },
          onCountdown: (phase) => {
            setLadder(phase);
            if (phase.kind === "burn") {
              editorRef.current?.updateOptions({ readOnly: true });
              setTemper("BURN");
            } else if (phase.kind === "armed") {
              setTemper("ARMED");
            } else if (phase.kind === "watch") {
              setTemper("WATCH");
            }
          },
          onTtlMismatch: () => setTtlMismatch(true),
          onSecurityLevel: (level) => {
            if (props.name) applyNamedSecurityLevel(props.name, level);
            else if (props.roomIdHex && props.fragment) applySecurityLevel(props.roomIdHex, props.fragment, level);
            else return;
            if (level === "highest" && !highestNoticeShown) setHighestNotice(true);
          },
          onShredRejected: (reason) => {
            // Say it out loud. A shred request that no peer will act on has to
            // be visible to somebody, or it looks exactly like a request that
            // was never sent.
            announce(
              reason === "roster-mismatch"
                ? "Ignored a shred request: this room's occupant list disagrees with the sender's."
                : reason === "cancel-not-from-initiator"
                  ? "Ignored an attempt to cancel the shred vote by someone who did not start it."
                  : `Ignored a shred request (${reason}).`,
            );
          },
          onHistoryPressure: (m) => setHistoryPressure(m),
          onKeyStatus: (m, alarming) => setKeyStatus(m ? { text: m, alarming } : null),
          onDivergence: (d) => setDiverged(d),
          onPurge: () => setPhase({ kind: "purged" }),
          onRoomUnavailable: () => setPhase({ kind: "unavailable" }),
          onServerRestart: (inSecs, handover) => {
            restartAnnouncedRef.current = true;
            setRestartHandover(handover);
            setClock(performance.now());
            setRestartAt(performance.now() + inSecs * 1000);
          },
          onRoomCarriedOver: () => {
            setRestartAt(null);
            announce("The server was updated, and this room carried over.");
          },
          onConnectionRefused: (message) => setConnRefused(message),
        },
      );
      sessionRef.current = session;
      // Was previously called on `sessionRef.current` before it was assigned,
      // so the plain-ws warning could never fire.
      session.setInsecure(wsInfo.insecure);
    },
    [],
  );

  useEffect(() => {
    return () => {
      sessionRef.current?.destroySession();
    };
  }, []);

  // Named rooms show the passphrase gate immediately and check existence in
  // parallel, so a live room is never delayed by the round trip while a
  // shredded one stops asking for a key it has no use for.
  useEffect(() => {
    const name = props.name;
    if (!name) return;
    let cancelled = false;
    void (async () => {
      const resolved = await api.resolveName(name).catch(() => null);
      if (cancelled || !resolved) return;
      if (!resolved.found) setPhase((p) => (p.kind === "passphrase" ? { kind: "unavailable" } : p));
    })();
    return () => {
      cancelled = true;
    };
  }, [props.name]);

  useEffect(() => {
    if (!markdown) {
      setHtml("");
      return;
    }
    let cancelled = false;
    const id = setTimeout(() => {
      void renderMarkdown(markdown).then(({ html }) => {
        if (!cancelled) setHtml(html);
      });
    }, 150);
    return () => {
      cancelled = true;
      clearTimeout(id);
    };
  }, [markdown]);

  const onEditorMount = useCallback(
    async (editor: MonacoEditor.IStandaloneCodeEditor) => {
      const model = editor.getModel();
      if (!model || !sessionRef.current) return;
      editorRef.current = editor;
      const monacoMod = await import("monaco-editor");
      sessionRef.current.setWipeContext({
        editor,
        model,
        previewEl: previewPaneRef.current,
      });
      editorAdapterRef.current = {
        scrollTop: (line) => editor.setScrollTop(Math.max(0, (line - 1) * editor.getOption(monacoMod.editor.EditorOption.lineHeight))),
        getTopVisibleLine: () => {
          const range = editor.getVisibleRanges()[0];
          return range ? range.startLineNumber : 1;
        },
        lineHeightPx: editor.getOption(monacoMod.editor.EditorOption.lineHeight),
        onScroll: (fn) => {
          const d = editor.onDidScrollChange(fn);
          return () => d.dispose();
        },
      };
      await sessionRef.current.attachEditor(monacoMod, editor);
      // Firefox and Safari make any Paste the page draws take two clicks, so
      // there right-click opens the browser's own menu, whose Paste is one.
      // Touch screens keep Monaco's: their menu comes from a long press, not
      // a mouse button, and never reaches the stand-in.
      if (clipboardReadAsksEveryTime(navigator.userAgent) && !COARSE_POINTER) {
        const undo = openBrowserMenuOnRightClick(editor);
        editor.onDidDispose(undo);
      }


      // Ctrl/Cmd+B and Ctrl/Cmd+I do nothing in Monaco on their own — bold and
      // italic are editor commands VS Code supplies for markdown, not part of
      // the standalone editor — so in a markdown editor they simply failed,
      // which reads as broken rather than absent. Bound to the same actions
      // the toolbar buttons use, so the two can never disagree about what
      // bold means.
      for (const [id, label, key] of [
        ["runa.bold", "Bold", monacoMod.KeyCode.KeyB],
        ["runa.italic", "Italic", monacoMod.KeyCode.KeyI],
      ] as const) {
        const action = TOOLBAR_ACTIONS.find((a) => a.title === label);
        if (!action) continue;
        editor.addAction({
          id,
          label,
          keybindings: [monacoMod.KeyMod.CtrlCmd | key],
          run: (ed) => applyTool(ed as MonacoEditor.IStandaloneCodeEditor, action),
        });
      }
      // getValue() copies the whole buffer; doing it per keystroke made
      // typing cost O(document). One read per idle pause is enough for a
      // preview that is itself debounced.
      let readTimer: ReturnType<typeof setTimeout> | null = null;
      model.onDidChangeContent(() => {
        if (readTimer) return;
        readTimer = setTimeout(() => {
          readTimer = null;
          setMarkdown(model.getValue());
        }, 90);
      });
      // Whatever the room already held arrived while the editor was being
      // attached, before there was a listener to hear it. Without this read
      // someone joining a room with text in it saw an empty preview until
      // somebody typed.
      setMarkdown(model.getValue());
    },
    [],
  );

  /// Opens the dialog. Deliberately does NOT propose anything: this used to
  /// fire the request immediately, which set the state to VOTING before the
  /// modal had rendered — leaving the policy selector and the away-peer
  /// warning, both of which only appear while IDLE, permanently invisible.
  /// The dialog is a confirmation step, so it has to exist before the thing
  /// it confirms.
  const startShred = useCallback(() => {
    setAwayNames(sessionRef.current?.awayPeers().map((p) => p.handle) ?? []);
    setShredLabel("IDLE");
    setShredOpen(true);
    setTemper("ARMED");
  }, []);

  /// The actual proposal, once someone has seen who is away and which policy
  /// applies and pressed Shred anyway.
  const confirmShred = useCallback((policy: Policy) => {
    setShredLabel("VOTING");
    void sessionRef.current
      ?.requestShred(
        policy,
        policy === "THRESHOLD" ? supermajorityFor(sessionRef.current?.peerCount ?? 0) : null,
      )
      .catch(() => {});
  }, []);

  // Ctrl+\ still cycles, but over the modes that are actually distinguishable
  // at this width. Including split on a phone spent a press on a change nobody
  // could see: the first press appeared to do nothing at all.
  const cycleMode = useCallback(() => {
    setMode((m) => {
      if (isNarrow) return m === "preview" ? "editor" : "preview";
      return m === "split" ? "editor" : m === "editor" ? "preview" : "split";
    });
  }, [isNarrow]);

  useLineSync(editorAdapterRef, previewPaneRef);

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if ((e.ctrlKey || e.metaKey) && e.key === "\\") {
        e.preventDefault();
        cycleMode();
      }
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [cycleMode]);

  const copyLink = useCallback(() => {
    // The address bar no longer holds the key, so the link is rebuilt from
    // the copy in memory. A shared room's address is the whole link: its
    // passphrase is never part of it.
    // A shared room's address is its name, which a highest-security room keeps
    // out of the address bar; its passphrase is never part of the link.
    const link =
      props.roomIdHex && props.fragment
        ? shareLink(props.roomIdHex, props.fragment)
        : props.name
          ? `${window.location.origin}/${props.name}`
          : window.location.href;
    void navigator.clipboard.writeText(link);
    announce(
      props.name
        ? "Copied the room's address. Send the passphrase separately, never alongside it."
        : "Copied. The part after the # is the key. Send the whole thing.",
    );
  }, [props.roomIdHex, props.fragment, props.name]);

  if (phase.kind === "missing-key") return <MissingKey />;

  if (phase.kind === "passphrase") {
    return (
      <>
        <PassphraseGate
        name={props.name!}
        onSubmit={async (passphrase) => {
          const resolved = await api.resolveName(props.name!).catch(() => null);
          if (!resolved?.found || !resolved.kdf || !resolved.room_id) {
            setPhase({ kind: "auth-failed" });
            return;
          }
          const roomSalt = b64ToBytes(resolved.kdf.salt);
          let derived: { material: Uint8Array | null };
          try {
            derived = await passphraseMaterial(passphrase, roomSalt);
          } catch (e) {
            if (e instanceof KdfUnavailableError) {
              setPhase({ kind: "kdf-unavailable" });
              return;
            }
            throw e;
          }
          if (!derived.material) return;
          const material = derived.material;
          await startSession({
            roomIdHex: resolved.room_id,
            passMaterial: material,
            linkSecret: null,
            roomSalt,
          });
        }}
        />
      </>
    );
  }

  if (phase.kind === "insecure-origin") {
    return (
      <main className="landing">
        <h1 className="mono">RÚNA</h1>
        <p className="micro-label tag">THIS PAGE IS NOT ON HTTPS</p>
        <div className="panel">
          <p>
            RÚNA will not open an unencrypted WebSocket from a page served over
            plain HTTP, so the editor cannot connect. This is a deployment
            problem, not a problem with your link.
          </p>
          <p style={{ marginBottom: 0 }}>
            Whoever runs this server needs to put HTTPS in front of it — see
            <code className="mono"> Deploying to the internet </code> in the
            README. <code className="mono">localhost</code> is exempt.
          </p>
        </div>
      </main>
    );
  }

  if (phase.kind === "unavailable") {
    return (
      <main className="landing">
        <h1 className="mono">RÚNA</h1>
        <p className="micro-label tag">THIS ROOM IS GONE</p>
        <div className="panel">
          <p>
            {restartAnnouncedRef.current && restartHandover
              ? "The server restarted for an update, and this room could not be brought back to the new version. Rooms live only in memory — there is no copy to recover, which is the point."
              : restartAnnouncedRef.current
              ? "The server restarted for an update, and this room ended with it. Rooms live only in memory — there is no copy to recover, which is the point."
              : "It was shredded, it expired, or the server restarted. Rooms live only in memory — there is no copy to recover, which is the point."}
          </p>
          <p style={{ marginBottom: 0 }}>
            <a href="/">← New room</a>
          </p>
        </div>
      </main>
    );
  }

  if (phase.kind === "kdf-unavailable") {
    return (
      <main className="landing">
        <h1 className="mono">RÚNA</h1>
        <div className="panel">
          <p>
            This browser could not run Argon2, the key derivation that turns
            the passphrase into this room's key. Nothing weaker can open the
            room, so it has not tried.
          </p>
          <p>Try an up-to-date browser, or close other tabs to free memory.</p>
          <a href="/">← Back</a>
        </div>
      </main>
    );
  }

  if (phase.kind === "auth-failed") {
    return (
      <main className="landing">
        <h1 className="mono">RÚNA</h1>
        <div className="panel">
          <p>Wrong passphrase, or this room no longer exists.</p>
          <a href="/">← Back</a>
        </div>
      </main>
    );
  }

  if (phase.kind === "purged") {
    return <Purged />;
  }

  if (phase.kind !== "live") {
    return (
      <main className="landing">
        <p className="micro-label">{phase.kind === "connecting" ? "CONNECTING…" : ""}</p>
        {connRefused && <p className="hint">{connRefused}</p>}
      </main>
    );
  }

  const panesClass = mode === "split" ? "panes" : mode === "editor" ? "panes editor-only" : "panes preview-only";
  // On a narrow screen split *is* editor-only on screen, so that is the tab
  // that should read as active — otherwise the highlight points at a mode the
  // reader cannot distinguish from the one they are looking at.
  const shownMode: ViewMode = isNarrow && mode === "split" ? "editor" : mode;

  const showLadderBanner = ladder.kind === "watch" || ladder.kind === "armed" || ladder.kind === "burn";

  return (
    <div className="room-shell">
      {showLadderBanner && (
        <div className="banner" role="status">
          <span className="mono">
            {ladder.kind === "burn"
              ? `This room is being destroyed in ${formatCountdown(ladder.remainingMs)}.`
              : ladder.kind === "armed"
                ? `This room expires in ${Math.ceil(ladder.remainingMs / 1000)} seconds.`
                : `This room expires in ${formatCountdown(ladder.remainingMs)}.`}
          </span>
          {ladder.kind !== "burn" && (
            <>
              <button onClick={() => sessionRef.current?.extendExpiry(1800)}>Extend +30m</button>
              <button onClick={() => void exportPdf()}>Export</button>
              <button className="danger" onClick={startShred}>
                Shred now
              </button>
            </>
          )}
        </div>
      )}
      {diverged && (
        <div className="banner" role="alert">
          <span>
            Your copy still differs from other peers after trying to resync.
          </span>
          <button
            onClick={() => {
              sessionRef.current?.resyncNow();
              // Says what it did, not what it achieved: the server allows one
              // replay per connection and drops the rest silently, so a
              // request made during another replay simply does not happen.
              announce("Asked the room for a full copy.");
            }}
          >
            Resync
          </button>
          <button onClick={() => setDiverged(false)}>Dismiss</button>
        </div>
      )}
      {restartAt !== null && (
        <div className="banner" role="alert">
          <span className={restartHandover ? undefined : "error-text"}>
            {restartMessage(restartAt - clock, restartHandover)}
          </span>
          <button onClick={() => setExportOpen(true)}>Export</button>
        </div>
      )}
      {connRefused && (
        <div className="banner" role="status">
          <span>{connRefused}</span>
        </div>
      )}
      {historyPressure && (
        <div className="banner" role="alert">
          <span className="error-text">{historyPressure}</span>
          <button onClick={() => setHistoryPressure(null)}>Dismiss</button>
        </div>
      )}
      {keyStatus && (
        <div className="banner" role={keyStatus.alarming ? "alert" : "status"}>
          <span className={keyStatus.alarming ? "error-text" : undefined}>{keyStatus.text}</span>
        </div>
      )}
      {ttlMismatch && (
        <div className="banner" role="alert">
          <span>The server reports a different expiry than this room was created with.</span>
          <button onClick={() => setTtlMismatch(false)}>Dismiss</button>
        </div>
      )}
      {highestNotice && (
        <div className="banner" role="note">
          <span>
            {props.name
              ? "Highest security: this room's name stays out of the address bar and browser history, and the passphrase is never stored. Refreshing or closing the tab leaves the room — to come back, type its name into Join a room. If your browser offers to save the passphrase, decline."
              : "Highest security: this tab holds the key in memory only. Refreshing or closing it forgets the key — to come back, paste the link into Join a room. Copy link first if you need it."}
          </span>
          <button
            onClick={() => {
              highestNoticeShown = true;
              setHighestNotice(false);
            }}
          >
            Got it
          </button>
        </div>
      )}
      <div className="statusbar">
        <span className="accent-dot" aria-hidden="true" />
        <span className="micro-label" style={{ color: "var(--accent)" }}>
          {props.name ?? "ROOM"}
        </span>
        {fingerprint && (
          <>
            <span className="sep micro-label" aria-hidden="true" />
            <span className="micro-label mono" style={{ letterSpacing: "0.08em" }} title="Room fingerprint — compare out of band">
              {fingerprint}
            </span>
          </>
        )}
        <span className="sep micro-label" aria-hidden="true" />
        <span className="micro-label" style={{ color: "var(--accent)" }}>{TEMBER_LABEL[temper]}</span>
        <span className="sep micro-label" aria-hidden="true" />
        <span className="sep micro-label" aria-hidden="true" />
        <span className="micro-label mono">
          {livePeerCount} {livePeerCount === 1 ? "PERSON" : "PEOPLE"}
        </span>
        {awayNames.length > 0 && (
          <span
            className="micro-label mono"
            style={{ color: "var(--text-faint)" }}
            title="Recently here, not connected now — a locked phone looks the same as a closed tab"
          >
            · {awayNames.length} AWAY
          </span>
        )}
        <span className="statusbar-spacer" style={{ flex: 1 }} />
        {ladder.kind !== "normal" && ladder.kind !== "none" && (
          <span className="micro-label mono" style={{ color: "var(--accent)" }}>
            {formatCountdown(ladder.remainingMs)}
          </span>
        )}
        {/* Wrapped so the actions can be given a row of their own on a phone.
            Left to plain flex-wrap they break at whatever point the room name
            happens to fill, which put Shred alone on a fourth row. */}
        <div className="statusbar-actions">
        <QuorumDial peers={[]} />
        <button onClick={copyLink}>Copy link</button>
        {/* Layout, Steady and Export fold behind ⋯ on a narrow screen. Copy
            link and Shred stay out because they are the two anyone reaches for
            under pressure, and burying Shred behind a menu would be the wrong
            thing to make slower. On a wide screen `display: contents` drops
            the wrapper entirely, so these lay out inline exactly as before and
            there is only ever one set of buttons to keep in sync. */}
        <div className={`tool-menu${menuOpen ? " is-open" : ""}`} ref={menuRef}>
          <button
            className="tool-menu-toggle"
            aria-expanded={menuOpen}
            aria-haspopup="menu"
            aria-label="More actions"
            onClick={() => setMenuOpen((o) => !o)}
          >
            ⋯
          </button>
          <div className="tool-menu-items">
            {/* Was a single button cycling split → editor → preview. Closing
                the preview and reopening it therefore cost two presses, and
                the control never said which mode was current. Every mode is
                now one press away and the active one is visible. */}
            <div className="mode-tabs" role="group" aria-label="Layout">
              {MODE_TABS.filter((t) => !(isNarrow && t.value === "split")).map((t) => (
                <button
                  key={t.value}
                  className="mode-tab"
                  aria-pressed={shownMode === t.value}
                  title={t.title}
                  onClick={() => {
                    setMenuOpen(false);
                    setMode(t.value);
                  }}
                >
                  {t.label}
                </button>
              ))}
            </div>
            <button
              aria-pressed={steady}
              title="Constant-rate transmission: closes the typing-cadence channel at a bandwidth cost"
              onClick={() => {
                const next = !steady;
                setSteady(next);
                sessionRef.current?.setSteadyTraffic(next);
              }}
            >
              Steady
              {steady && <span className="toggle-dot" aria-hidden="true" />}
            </button>
            <button
              onClick={() => {
                setMenuOpen(false);
                setExportOpen(true);
              }}
            >
              Export
            </button>
          </div>
        </div>
        <button className="danger" onClick={startShred}>
          Shred
        </button>
        </div>
      </div>

      {showExtNotice && (
        <div className="banner" role="note">
          <span>Extensions can read this page. Use a clean profile for anything that matters.</span>
          <button
            onClick={() => {
              extNoticeShown = true;
              setShowExtNotice(false);
            }}
          >
            Dismiss
          </button>
        </div>
      )}
      <div className={panesClass}>
        <div className="pane-editor">
          <div className="row" style={{ padding: "4px 8px", borderBottom: "1px solid var(--hairline)", flexWrap: "wrap" }}>
            {TOOLBAR_ACTIONS.map((a) => (
              <button
                key={a.title}
                title={a.title}
                className="mono"
                style={{ padding: "2px 8px", fontSize: 12 }}
                onClick={() => editorRef.current && applyTool(editorRef.current, a)}
              >
                {a.label}
              </button>
            ))}
          </div>
          <div
            spellCheck={false}
            autoCorrect="off"
            translate="no"
            data-gramm="false"
            // Takes what is left of the pane rather than all of it. With
            // height:100% the editor claimed the pane's full height and the
            // markdown ribbon above it added its own on top, so the room was
            // taller than the window by exactly one ribbon.
            style={{ flex: "1 1 auto", minHeight: 0, display: "flex", flexDirection: "column" }}
          >
            <Editor
              defaultLanguage="markdown"
              options={MONACO_OPTIONS}
              onMount={(editor) => void onEditorMount(editor)}
              theme="vs-dark"
            />
          </div>
        </div>
        <div
          className="pane-preview"
          ref={previewPaneRef}
          onClickCapture={(e) => {
            const anchor = (e.target as HTMLElement).closest("a");
            if (!anchor) return;
            const href = anchor.getAttribute("href") ?? "";
            if (!isExternalHref(href)) return;
            if (externalConfirmed) return;
            e.preventDefault();
            if (window.confirm("This leaves RÚNA and tells that site you were here.")) {
              externalConfirmed = true;
              window.open(href, "_blank", "noopener,noreferrer");
            }
          }}
        >
          <div
            className="preview-body"
            // Sanitised output only — pipeline.ts runs rehype-sanitize LAST.
            dangerouslySetInnerHTML={{ __html: html }}
          />
        </div>
      </div>

      <ShredModal
        open={shredOpen}
        awayNames={awayNames}
        peerCount={peerCount}
        policy={shredPolicy}
        onPolicyChange={(p) => setShredPolicy(p)}
        peers={
          tally
            ? Array.from({ length: tally.total }, (_, i) => ({
                peerIdB64: String(i),
                approved: i < tally.approved,
                unreachable: !!tally.waitingOn && i === tally.total - 1 && shredLabel === "STALLED",
              }))
            : []
        }
        state={shredLabel}
        onCancel={() => {
          setShredOpen(false);
          sessionRef.current?.cancelShred();
          setTemper("SECURE");
        }}
        onConfirm={confirmShred}
      />
      {exportOpen && (
        <ExportDialog
          onClose={() => setExportOpen(false)}
          onMarkdown={() => {
            setExportOpen(false);
            const source = editorRef.current?.getModel()?.getValue() ?? "";
            if (!exportMarkdown(source)) return;
            announce("Wrote an unencrypted copy to your downloads.");
          }}
          onPdf={(density) => {
            setExportOpen(false);
            void exportPdf(density);
          }}
        />
      )}
      {shredPrompt && (
        <ShredVotePrompt
          onDecide={(choice) => {
            const req = shredPrompt;
            setShredPrompt(null);
            setShredOpen(false);
            void sessionRef.current?.respondToShred(req, choice);
          }}
        />
      )}
      <ToastRegion />
    </div>
  );
}

const TEMBER_LABEL: Partial<Record<TemperState, string>> = {
  COLD: "COLD",
  SECURE: "SECURE",
  WATCH: "WATCH",
  ARMED: "ARMED",
  BURN: "BURN",
};

function Purged() {
  useEffect(() => {
    window.location.replace("/gone.html");
  }, []);
  return null;
}

/// Export offered PDF at one fixed size and nothing else, so a long document
/// became sixty-odd pages with no way to change it, and there was no way to
/// get the source back out at all.
///
/// A dialog rather than a nested dropdown: the toolbar's Export already lives
/// inside the overflow menu on a phone, and a menu inside a menu is miserable
/// to hit. It also leaves room to say what the sizes are for, which a row of
/// bare labels does not.
function ExportDialog({
  onClose,
  onMarkdown,
  onPdf,
}: {
  onClose(): void;
  onMarkdown(): void;
  onPdf(density: ExportDensity): void;
}) {
  const ref = useRef<HTMLDivElement | null>(null);
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") onClose();
    };
    document.addEventListener("keydown", onKey);
    return () => document.removeEventListener("keydown", onKey);
  }, [onClose]);
  return (
    <div className="modal-backdrop" onPointerDown={(e) => { if (e.target === e.currentTarget) onClose(); }}>
      <div className="modal" role="dialog" aria-modal="true" aria-labelledby="export-title" ref={ref}>
        <h2 id="export-title" className="micro-label">EXPORT</h2>
        <p className="hint">
          Both write an unencrypted file to this computer. RÚNA cannot shred that copy.
        </p>
        <div className="export-choice">
          <button onClick={onMarkdown}>Markdown (.md)</button>
          <p className="hint">The source as written, so it opens anywhere and comes back unchanged.</p>
        </div>
        <div className="export-choice">
          <span className="micro-label">PDF</span>
          <div className="row">
            <button onClick={() => onPdf("compact")}>Compact</button>
            <button onClick={() => onPdf("normal")}>Normal</button>
            <button onClick={() => onPdf("roomy")}>Large</button>
          </div>
          <p className="hint">Compact fits roughly twice as much on a page as Large.</p>
        </div>
        <div className="row" style={{ justifyContent: "flex-end", marginTop: 12 }}>
          <button onClick={onClose}>Cancel</button>
        </div>
      </div>
    </div>
  );
}

function ShredVotePrompt({ onDecide }: { onDecide(choice: "APPROVE" | "REJECT"): void }) {
  return (
    <div className="modal-backdrop">
      <div className="modal" role="alertdialog" aria-modal="true" aria-labelledby="vote-title">
        <h2 id="vote-title" className="micro-label">SHRED REQUESTED BY A PEER</h2>
        <p>{LIMIT_COPY}</p>
        <div className="row" style={{ justifyContent: "flex-end", marginTop: 12 }}>
          <button onClick={() => onDecide("REJECT")}>Reject</button>
          <button className="danger" onClick={() => onDecide("APPROVE")}>Approve</button>
        </div>
      </div>
    </div>
  );
}

const LIMIT_COPY =
  "This destroys the shared copy and the keys. It cannot reach copies other people already made.";

function PassphraseGate({ name, onSubmit }: { name: string; onSubmit(p: string): Promise<void> }) {
  const [value, setValue] = useState("");
  const [busy, setBusy] = useState(false);
  return (
    <main className="landing">
      <h1 className="mono">RÚNA</h1>
      <p className="micro-label tag">NAMED ROOM · {name.toUpperCase()}</p>
      <form
        className="panel"
        onSubmit={(e) => {
          e.preventDefault();
          if (busy) return;
          setBusy(true);
          // Without the reset the button stays stuck on "Deriving keys…" for
          // any path that returns without replacing this component.
          void onSubmit(value).finally(() => setBusy(false));
        }}
      >
        <div className="field">
          <label className="micro-label" htmlFor="pp">PASSPHRASE</label>
          {/* Not a real autocomplete token: browsers fall back to "on" and
              may offer to remember a passphrase for an ephemeral room. */}
          <input id="pp" type="password" autoComplete="off" value={value} onChange={(e) => setValue(e.target.value)} />
        </div>
        <button disabled={busy}>{busy ? "Deriving keys…" : "Enter room"}</button>
      </form>
    </main>
  );
}

let announcer: ((msg: string) => void) | null = null;
/// The restart warning, counting down. What it asks for depends on whether
/// the server hands rooms over to the next process: if it does, the thing
/// that keeps the room is keeping this tab open; if not, it is exporting.
function restartMessage(msLeft: number, handover: boolean): string {
  if (handover) {
    if (msLeft <= 0) return "The server is restarting now. Keep this tab open: your room comes back as soon as it does.";
    const total = Math.ceil(msLeft / 1000);
    const time = `${Math.floor(total / 60)}:${String(total % 60).padStart(2, "0")}`;
    return `This server restarts in ${time} to update. Keep this tab open and your room carries over to the new version. Export if you want your own copy.`;
  }
  if (msLeft <= 0) return "The server is restarting now. Anything not exported from this room is gone.";
  const total = Math.ceil(msLeft / 1000);
  const time = `${Math.floor(total / 60)}:${String(total % 60).padStart(2, "0")}`;
  return `This server restarts in ${time} to update. Rooms live only in memory, so this room and everything in it will be gone. Export your work now.`;
}

export function announce(msg: string): void {
  announcer?.(msg);
}

function ToastRegion() {
  const [toasts, setToasts] = useState<string[]>([]);
  useEffect(() => {
    announcer = (msg) => setToasts((t) => [...t, msg]);
    return () => {
      announcer = null;
    };
  }, []);
  useEffect(() => {
    if (!toasts.length) return;
    const id = setTimeout(() => setToasts((t) => t.slice(1)), 3500);
    return () => clearTimeout(id);
  }, [toasts]);
  return (
    <div className="toast-region" role="status" aria-live="polite">
      {toasts.map((t, i) => (
        <div key={i} className="toast">{t}</div>
      ))}
    </div>
  );
}

// iOS Safari zooms the page whenever focus lands on a control whose computed
// font-size is under 16px, and it does not undo that on blur — the shred
// dialog already moves focus to its Cancel button and the page stays zoomed
// regardless. A zoomed page then crops the dialog, which is position:fixed and
// so lays out against the layout viewport while the reader is looking at a
// smaller visual one. That was the reported symptom.
//
// The trigger is Monaco's hidden input, which computed to 12px. It cannot be
// reached from the stylesheet: Monaco writes the editor's font settings to
// that element as an inline style, which beats any rule short of !important,
// and fighting it there would leave Monaco's own measurements disagreeing with
// what is rendered. Setting the option instead keeps them in step.
//
// Keyed on pointer rather than width, because this is a property of touch
// input and not of how wide the window happens to be — a phone in landscape is
// past every width breakpoint here and still zooms. 16px is also simply easier
// to read on a phone than 12px.
//
// There is no supported way to reset page zoom once it has happened. The usual
// trick — swapping in a maximum-scale viewport — would take pinch-zoom away
// from everyone permanently to paper over one dialog, so removing the trigger
// is the whole fix.
const COARSE_POINTER =
  typeof window !== "undefined" &&
  typeof window.matchMedia === "function" &&
  window.matchMedia("(pointer: coarse)").matches;

export const TOUCH_FONT_SIZE = 16;

type ViewMode = "split" | "editor" | "preview";

const NARROW_QUERY = "(max-width: 1000px)";

const MODE_TABS: ReadonlyArray<{ value: ViewMode; label: string; title: string }> = [
  { value: "split", label: "Split", title: "Editor and preview side by side (Ctrl+\\)" },
  { value: "editor", label: "Editor", title: "Editor only (Ctrl+\\)" },
  { value: "preview", label: "Preview", title: "Preview only (Ctrl+\\)" },
];

export const MONACO_OPTIONS = {
  ...(COARSE_POINTER ? { fontSize: TOUCH_FONT_SIZE } : {}),
  language: "markdown",
  wordWrap: "on",
  tabSize: 2,
  insertSpaces: true,
  renderWhitespace: "selection",
  minimap: { enabled: false },
  // Off. Monaco enables this by default and it pins the header of the
  // enclosing foldable block to the top of the editor.
  //
  // Markdown has no folding provider in the standalone editor, so Monaco falls
  // back to folding by indentation — which in prose means lists, fenced code
  // and pasted terminal output, none of which are containers for what follows
  // them. So it pinned arbitrary lines: a row of dashes, a sentence that
  // happened to precede an indented paragraph. It also costs real height,
  // measured at 90px in Chromium when blocks nest, out of an editor around
  // 560px tall.
  //
  // Markdown does have real headings. They are not what this uses.
  stickyScroll: { enabled: false },
  // Without this Monaco never observes container resizes, so its cached
  // dimensions go stale and pointer coordinates map to the wrong glyph —
  // drag-selection and touch-selection silently stop working while
  // keyboard selection (ctrl/cmd+A) still behaves.
  automaticLayout: true,
  // Monaco's own menu, kept. Right-click is worth having, and with this off the
  // platform menu on Monaco's rendered text is a generic page menu — no Cut, no
  // Copy — because the visible glyphs are divs and the real input is hidden.
  //
  // In Firefox and Safari the right-click never reaches it, though. Its Paste
  // reads the clipboard from script, which those two answer with a Paste button
  // of their own that has to be clicked too — the "second Paste" reported from
  // both. There, right-click opens the browser's menu over a stand-in instead,
  // and its Paste is one click. See ui/contextmenu.ts.
  contextmenu: true,
  quickSuggestions: false,
  wordBasedSuggestions: "off",
  "semanticHighlighting.enabled": false,
  accessibilitySupport: "auto",
  spellcheck: false,
} as const;

function b64ToBytes(s: string): Uint8Array {
  const bin = atob(s);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

function websocketUrl(roomIdHex: string): { url: string; insecure: boolean } {
  const proto = window.location.protocol === "https:" ? "wss://" : "ws://";
  if (proto === "ws://" && !plainWebSocketAllowed(window.location)) {
    throw new Error("INSECURE_ORIGIN");
  }
  return { url: `${proto}${window.location.host}/socket/${roomIdHex}`, insecure: proto === "ws://" };
}

function formatCountdown(ms: number): string {
  const total = Math.ceil(ms / 1000);
  const h = Math.floor(total / 3600);
  const m = Math.floor((total % 3600) / 60);
  const sec = total % 60;
  const pad = (n: number) => String(n).padStart(2, "0");
  return `${pad(h)}:${pad(m)}:${pad(sec)}`;
}
