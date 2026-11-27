import { useEffect, useRef, useState, type RefObject } from "react";
import {
  EVICT_COPY,
  evictStateText,
  fingerprintLine,
  proposeErrorText,
  removedLine,
  voteBody,
  voteTitle,
} from "../evict/copy";
import { PassphraseField } from "./PassphraseField";

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
}

/// A request is out and not yet settled: nothing new can be asked meanwhile.
export function evictInFlight(state: string): boolean {
  return state === "VOTING" || state === "APPROVED";
}

/// Moves focus into a dialog when it opens and gives it back to whatever had
/// it when the dialog closes, as the shred dialog does.
function useDialogFocus(first: RefObject<HTMLElement | null>): void {
  useEffect(() => {
    const back = document.activeElement instanceof HTMLElement ? document.activeElement : null;
    first.current?.focus();
    return () => {
      if (back && back.isConnected) back.focus();
    };
  }, [first]);
}

/// The request to remove someone or change the link (amendment K). Nothing
/// is sent until "Ask the room"; for a shared room the new passphrase is
/// typed or generated here, with the create form's strength check.
export function EvictModal(props: {
  candidates: EvictCandidate[];
  /// Open with nobody chosen: a link change.
  relink: boolean;
  wayKind: "link" | "pass";
  state: string;
  stateReason?: string;
  onPropose(target: Uint8Array | null, passphrase: string): Promise<string | null>;
  onCancel(): void;
}) {
  const [choice, setChoice] = useState<number>(props.relink || props.candidates.length === 0 ? -1 : 0);
  // Held here only while the dialog is open; closing it unmounts this
  // component and drops the string.
  const [passphrase, setPassphrase] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const cancelRef = useRef<HTMLButtonElement>(null);
  // In a ref so the key listener is added once: re-adding it on every render
  // is harmless, but the focus effect must not run again while someone types.
  const onCancelRef = useRef(props.onCancel);
  onCancelRef.current = props.onCancel;
  const mounted = useRef(true);

  useDialogFocus(cancelRef);

  useEffect(() => {
    mounted.current = true;
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") onCancelRef.current();
    };
    document.addEventListener("keydown", onKey);
    return () => {
      mounted.current = false;
      document.removeEventListener("keydown", onKey);
    };
  }, []);

  const locked = busy || evictInFlight(props.state);
  const submit = async () => {
    if (locked) return;
    setError(null);
    setBusy(true);
    const target = choice >= 0 ? (props.candidates[choice]?.peerId ?? null) : null;
    const code = await props.onPropose(target, passphrase);
    // Argon2id takes seconds, and the dialog may have closed meanwhile.
    if (!mounted.current) return;
    setBusy(false);
    if (code) setError(proposeErrorText(code));
    else setPassphrase("");
  };

  const stateText = props.state !== "IDLE" ? evictStateText(props.state, props.stateReason) : "";

  return (
    <div className="modal-backdrop">
      <div className="modal" role="dialog" aria-modal="true" aria-labelledby="evict-title">
        <h2 id="evict-title" className="micro-label">
          {EVICT_COPY.title}
        </h2>
        <p className="hint">{props.wayKind === "pass" ? EVICT_COPY.explainPass : EVICT_COPY.explainLink}</p>
        <fieldset disabled={locked} style={{ border: 0, padding: 0, margin: "14px 0" }}>
          <div role="radiogroup" aria-labelledby="evict-title">
            <label className="row checkbox-row">
              <input type="radio" name="evict-target" checked={choice === -1} onChange={() => setChoice(-1)} />
              <span>{EVICT_COPY.nobody}</span>
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
          <button ref={cancelRef} onClick={props.onCancel}>
            {EVICT_COPY.cancel}
          </button>
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
export function EvictVotePrompt(props: {
  by: string;
  who: string | null;
  onDecide(choice: "APPROVE" | "REJECT"): void;
}) {
  const rejectRef = useRef<HTMLButtonElement>(null);
  useDialogFocus(rejectRef);
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
          {voteTitle(props.who)}
        </h2>
        <p id="evict-vote-body">{voteBody(props.by, props.who)}</p>
        <div className="row" style={{ justifyContent: "flex-end", marginTop: 12 }}>
          <button id="evict-reject" ref={rejectRef} onClick={() => props.onDecide("REJECT")}>
            {EVICT_COPY.reject}
          </button>
          <button id="evict-approve" className="danger" onClick={() => props.onDecide("APPROVE")}>
            {EVICT_COPY.approve}
          </button>
        </div>
      </div>
    </div>
  );
}

/// The new link or passphrase, shown once to each member who stays. It is
/// the only time the page shows it, so only Done closes it: an Escape
/// pressed by habit would lose it for good.
export function ReRootNotice(props: { view: ReRootView; onCopy(text: string): void; onDone(): void }) {
  const { link, passphrase, fingerprint, removed } = props.view;
  const copyRef = useRef<HTMLButtonElement>(null);
  useDialogFocus(copyRef);
  return (
    <div className="modal-backdrop">
      <div className="modal" role="dialog" aria-modal="true" aria-labelledby="reroot-title">
        <h2 id="reroot-title" className="micro-label">
          {link ? EVICT_COPY.newLinkTitle : EVICT_COPY.newPassTitle}
        </h2>
        {removed && <p>{removedLine(removed)}</p>}
        <p>{EVICT_COPY.newWayBody}</p>
        {link ? (
          <code className="mono" data-new-link="" style={{ wordBreak: "break-all" }}>
            {link}
          </code>
        ) : (
          <code className="mono" data-new-passphrase="" style={{ wordBreak: "break-all" }}>
            {passphrase}
          </code>
        )}
        {fingerprint && <p className="hint">{fingerprintLine(fingerprint)}</p>}
        <div className="row" style={{ justifyContent: "flex-end", marginTop: 12 }}>
          <button ref={copyRef} onClick={() => props.onCopy(link ?? passphrase ?? "")}>
            {EVICT_COPY.copy}
          </button>
          <button id="reroot-done" className="primary" onClick={props.onDone}>
            {EVICT_COPY.done}
          </button>
        </div>
      </div>
    </div>
  );
}
