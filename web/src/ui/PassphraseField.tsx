import { generateDicewarePassphrase } from "../crypto/fingerprint";
import { estimatePassphrase } from "../crypto/passphrase";

/// The passphrase input with its strength check and Generate button. The
/// create form and the request to change a shared room's passphrase both use
/// this, so a new passphrase is held to the same bar either way.
export function PassphraseField(props: {
  id: string;
  label?: string;
  value: string;
  onChange(value: string): void;
  autoComplete: string;
}) {
  const verdict = props.value ? estimatePassphrase(props.value) : null;
  return (
    <div className="field">
      <label className="micro-label" htmlFor={props.id}>
        {props.label ?? "PASSPHRASE"}
      </label>
      <div className="row">
        <input
          id={props.id}
          type="password"
          autoComplete={props.autoComplete}
          value={props.value}
          onChange={(e) => props.onChange(e.target.value)}
        />
        <button type="button" onClick={() => props.onChange(generateDicewarePassphrase(5))}>
          Generate
        </button>
      </div>
      {verdict && !verdict.ok && (
        <p className="error-text">This is too easy to guess. Press Generate, or add more words.</p>
      )}
      {verdict?.ok && (
        <p className="hint">
          {verdict.dicewareWords > 0
            ? `${verdict.dicewareWords} random words make it strong, and easy to read aloud.`
            : "That is strong enough."}
        </p>
      )}
    </div>
  );
}
