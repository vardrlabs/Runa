import { useEffect, useRef, useState, type RefObject } from "react";
import {
  EVICT_COPY,
  evictCopy,
  evictStateText,
  fingerprintLine,
  othersEndedLine,
  proposeErrorText,
  removedLine,
  voteBody,
  voteTitle,
} from "../evict/copy";
import { PassphraseField } from "./PassphraseField";
import type { WayKind } from "../evict/reroot";

export interface EvictCandidate {
  peerId: Uint8Array;
  handle: string;
}

/// The new way in, shown once. `link` is the whole shareable link for an
/// unlisted room and `passphrase` the new passphrase for a shared one; the
/// page holds this only while the notice is open.
export interface ReRootView {
  link: string | null;
  passphrase: string | null;
  fingerprint: string;
  removed: string | null;
  /// The commit also ended other requests this tab asked or was asked about.
  othersEnded?: boolean;
}

/// This tab's own request is out and not yet settled: it cannot ask again
/// meanwhile. Other people's requests never stop it asking.
export function evictInFlight(state: string): boolean {
  return state === "VOTING" || state === "APPROVED";
}

/// Where focus goes when a dialog closes and the control that opened it is
/// no longer on screen, such as a menu item in a menu that has folded away.
export type FocusFallback = () => HTMLElement | null;

const onScreen = (el: HTMLElement): boolean => el.isConnected && el.getClientRects().length > 0;

/// Moves focus into a dialog when it opens and gives it back to whatever had
/// it when the dialog closes, as the shred dialog does. When that control is
/// gone or hidden, focus goes to `fallback` instead of the page body.
function useDialogFocus(first: RefObject<HTMLElement | null>, fallback?: FocusFallback): void {
  const fallbackRef = useRef(fallback);
  fallbackRef.current = fallback;
  useEffect(() => {
    // The page body is where focus falls when nothing has it, such as after a
    // menu that opened the dialog folded away: it opened nothing.
    const active = document.activeElement;
    const back = active instanceof HTMLElement && active !== document.body ? active : null;
    first.current?.focus();
    return () => {
      if (back && onScreen(back)) {
        back.focus();
        return;
      }
      const other = fallbackRef.current?.();
      if (other && onScreen(other)) other.focus();
    };
  }, [first]);
}

/// Said while the new keys are made, when the dialog cannot be closed.
const BUSY_TEXT = "This tab is making the new keys. The dialog can be closed again once the request has gone out.";

/// The new way in could not be shown: the room has moved, and the person is
/// told so with nothing to copy.
function noWayText(way: WayKind): string {
  const word = way === "pass" ? "passphrase" : "link";
  return `This room's ${word} changed, and this tab could not show the new one. Ask someone who is still in the room for it.`;
}

/// The request to remove someone or change the link (amendment K). Nothing
/// is sent until "Ask the room"; for a shared room the new passphrase is
/// typed or generated here, with the create form's strength check.
///
/// Once this tab's own request is out, the dialog shows where it stands.
/// Close and Escape only close the dialog, so the person can answer someone
/// else's request meanwhile, and the bar opens it again; "Withdraw request"
/// is the one control that withdraws it, while it still collects answers.
export function EvictModal(props: {
  candidates: EvictCandidate[];
  /// Open with nobody chosen: a link change.
  relink: boolean;
  wayKind: WayKind;
  /// The state of this tab's own request, IDLE when it has none.
  state: string;
  stateReason?: string;
  returnFocus?: FocusFallback;
  onPropose(target: Uint8Array | null, passphrase: string): Promise<string | null>;
  /// Closes the dialog. An open request of this tab's stays open.
  onClose(): void;
  /// Withdraws this tab's own request, and closes the dialog.
  onWithdraw(): void;
}) {
  const words = evictCopy(props.wayKind);
  const [choice, setChoice] = useState<number>(props.relink || props.candidates.length === 0 ? -1 : 0);
  // Held here only while the dialog is open; closing it unmounts this
  // component and drops the string.
  const [passphrase, setPassphrase] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const cancelRef = useRef<HTMLButtonElement>(null);
  const mounted = useRef(true);

  useDialogFocus(cancelRef, props.returnFocus);

  useEffect(() => {
    mounted.current = true;
    return () => {
      mounted.current = false;
    };
  }, []);

  const inFlight = evictInFlight(props.state);
  const locked = busy || inFlight;
  // A request still collecting answers can be withdrawn. Once everyone has
  // agreed the commit is on its way, and nothing withdraws it.
  const canWithdraw = !busy && props.state === "VOTING";

  // Disabling the button that had focus drops focus to the page in some
  // browsers and leaves it on the disabled button in others; either way,
  // once the keys are made, or while a vote in flight locks the form, it
  // comes back to Cancel.
  useEffect(() => {
    if (busy) return;
    const active = document.activeElement;
    let disabled = false;
    try {
      disabled = active instanceof HTMLElement && active.matches(":disabled");
    } catch {
      disabled = active instanceof HTMLButtonElement && active.disabled;
    }
    if (!active || active === document.body || disabled) cancelRef.current?.focus();
  }, [busy, locked]);
  const submit = async () => {
    if (locked) return;
    setError(null);
    setBusy(true);
    const target = choice >= 0 ? (props.candidates[choice]?.peerId ?? null) : null;
    let code: string | null;
    try {
      code = await props.onPropose(target, passphrase);
    } catch {
      code = "failed";
    }
    // The page may have closed the dialog meanwhile, because the tab was
    // stranded or the room's way in changed; its state went with it.
    if (!mounted.current) return;
    setBusy(false);
    // The typed passphrase goes whatever the outcome: it was handed over,
    // and a refused one is typed or generated again.
    setPassphrase("");
    if (code) setError(proposeErrorText(code, props.wayKind));
  };

  // While the new keys are made, Cancel, Close and Escape do nothing: a
  // request that goes out behind a closed dialog is one the person thinks
  // they stopped. Escape belongs to this dialog only while focus is in it,
  // and it never withdraws anything.
  const close = () => {
    if (busy) return;
    setPassphrase("");
    props.onClose();
  };

  const withdraw = () => {
    if (!canWithdraw) return;
    setPassphrase("");
    props.onWithdraw();
  };

  const stateText = props.state !== "IDLE" ? evictStateText(props.state, props.stateReason, props.wayKind, true) : "";

  return (
    <div className="modal-backdrop">
      <div
        className="modal"
        role="dialog"
        aria-modal="true"
        aria-labelledby="evict-title"
        aria-busy={busy}
        onKeyDown={(e) => {
          if (e.key !== "Escape") return;
          e.stopPropagation();
          close();
        }}
      >
        <h2 id="evict-title" className="micro-label">
          {words.title}
        </h2>
        <p className="hint">{props.wayKind === "pass" ? EVICT_COPY.explainPass : EVICT_COPY.explainLink}</p>
        <fieldset disabled={locked} style={{ border: 0, padding: 0, margin: "14px 0" }}>
          <div role="radiogroup" aria-labelledby="evict-title">
            <label className="row checkbox-row">
              <input type="radio" name="evict-target" checked={choice === -1} onChange={() => setChoice(-1)} />
              <span>{words.nobody}</span>
            </label>
            {props.candidates.map((c, i) => (
              <label className="row checkbox-row" key={i}>
                <input type="radio" name="evict-target" checked={choice === i} onChange={() => setChoice(i)} />
                <span className="mono">{c.handle}</span>
              </label>
            ))}
          </div>
          {props.wayKind === "pass" && (
            <PassphraseField
              id="evict-passphrase"
              label={EVICT_COPY.newPassphraseLabel}
              value={passphrase}
              onChange={setPassphrase}
              autoComplete="off"
            />
          )}
        </fieldset>
        {busy && (
          <p className="hint" role="status">
            {BUSY_TEXT}
          </p>
        )}
        {stateText && (
          <p className="micro-label" role="status">
            {stateText}
          </p>
        )}
        {error && (
          <p className="error-text" role="alert">
            {error}
          </p>
        )}
        <div className="row" style={{ justifyContent: "flex-end" }}>
          <button ref={cancelRef} id={inFlight ? "evict-close" : undefined} disabled={busy} onClick={close}>
            {inFlight ? EVICT_COPY.close : EVICT_COPY.cancel}
          </button>
          {canWithdraw && (
            <button id="evict-withdraw" onClick={withdraw}>
              {EVICT_COPY.withdraw}
            </button>
          )}
          <button id="evict-propose" className="danger" disabled={locked} onClick={() => void submit()}>
            {busy ? EVICT_COPY.deriving : EVICT_COPY.propose}
          </button>
        </div>
      </div>
    </div>
  );
}

/// What everyone else is asked. The person to be removed is not asked. It
/// closes only by answering, like the shred vote, so Escape does nothing
/// here; focus starts on Refuse, the choice that changes nothing.
///
/// It never stops the person asking the room themselves: the prompt covers
/// the bar, so it offers the bar's two ways of asking as well. Either opens
/// the ask dialog, and the page puts this prompt aside until that closes.
export function EvictVotePrompt(props: {
  by: string;
  who: string | null;
  wayKind: WayKind;
  returnFocus?: FocusFallback;
  onDecide(choice: "APPROVE" | "REJECT"): void;
  onAsk?(relink: boolean): void;
}) {
  const words = evictCopy(props.wayKind);
  const rejectRef = useRef<HTMLButtonElement>(null);
  useDialogFocus(rejectRef, props.returnFocus);
  return (
    <div className="modal-backdrop">
      <div
        className="modal"
        role="alertdialog"
        aria-modal="true"
        aria-labelledby="evict-vote-title"
        aria-describedby="evict-vote-body"
      >
        <h2 id="evict-vote-title" className="micro-label">
          {voteTitle(props.who, props.wayKind)}
        </h2>
        <p id="evict-vote-body">{voteBody(props.by, props.who, props.wayKind)}</p>
        <div className="row" style={{ justifyContent: "flex-end", marginTop: 12 }}>
          <button id="evict-reject" ref={rejectRef} onClick={() => props.onDecide("REJECT")}>
            {EVICT_COPY.reject}
          </button>
          <button id="evict-approve" className="danger" onClick={() => props.onDecide("APPROVE")}>
            {EVICT_COPY.approve}
          </button>
        </div>
        {props.onAsk && (
          <div role="group" aria-labelledby="evict-vote-ask" data-evict-ask="" style={{ marginTop: 16 }}>
            <p id="evict-vote-ask" className="hint">
              {EVICT_COPY.askFirst}
            </p>
            <div className="row" style={{ justifyContent: "flex-end" }}>
              <button onClick={() => props.onAsk?.(false)}>{EVICT_COPY.removeButton}</button>
              <button onClick={() => props.onAsk?.(true)}>{words.relinkButton}</button>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}

/// The new link or passphrase, shown once to each member who stays. It is
/// the only time the page shows it, so only Done closes it: an Escape
/// pressed by habit would lose it for good. When the session could give
/// neither, the notice says the way in changed and offers nothing to copy.
export function ReRootNotice(props: {
  view: ReRootView;
  wayKind: WayKind;
  returnFocus?: FocusFallback;
  onCopy(text: string): void;
  onDone(): void;
}) {
  const { link, passphrase, fingerprint, removed, othersEnded } = props.view;
  const secret = link || passphrase || null;
  const copyRef = useRef<HTMLButtonElement>(null);
  const doneRef = useRef<HTMLButtonElement>(null);
  useDialogFocus(secret ? copyRef : doneRef, props.returnFocus);
  const isLink = link ? true : passphrase ? false : props.wayKind === "link";
  return (
    <div className="modal-backdrop">
      <div className="modal" role="dialog" aria-modal="true" aria-labelledby="reroot-title">
        <h2 id="reroot-title" className="micro-label">
          {isLink ? EVICT_COPY.newLinkTitle : EVICT_COPY.newPassTitle}
        </h2>
        {removed && <p>{removedLine(removed)}</p>}
        {secret ? <p>{EVICT_COPY.newWayBody}</p> : <p>{noWayText(props.wayKind)}</p>}
        {link ? (
          <code className="mono" data-new-link="" style={{ wordBreak: "break-all" }}>
            {link}
          </code>
        ) : passphrase ? (
          <code className="mono" data-new-passphrase="" style={{ wordBreak: "break-all" }}>
            {passphrase}
          </code>
        ) : null}
        {fingerprint && <p className="hint">{fingerprintLine(fingerprint)}</p>}
        {othersEnded && (
          <p className="hint" data-others-ended="">
            {othersEndedLine(props.wayKind)}
          </p>
        )}
        <div className="row" style={{ justifyContent: "flex-end", marginTop: 12 }}>
          {secret && (
            <button ref={copyRef} onClick={() => props.onCopy(secret)}>
              {EVICT_COPY.copy}
            </button>
          )}
          <button id="reroot-done" ref={doneRef} className="primary" onClick={props.onDone}>
            {EVICT_COPY.done}
          </button>
        </div>
      </div>
    </div>
  );
}
