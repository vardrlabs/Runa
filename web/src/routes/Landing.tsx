import { useState } from "react";
import { Api, type TtlBody } from "../api";
import {
  deriveRoomKeys,
  encryptRoomConfig,
  fragmentWithKey,
  passphraseMaterial,
  randomLinkSecret,
  randomSalt,
  verifierForAuthKey,
  type SecurityLevel,
} from "../keys-session";
import { openNamedRoom, openUnlistedRoom } from "../keyhandoff";
import {
  generateRoomName,
  randomHexSuffix,
} from "../crypto/fingerprint";
import { estimatePassphrase } from "../crypto/passphrase";
import { Field } from "../ui/Field";
import { PassphraseField } from "../ui/PassphraseField";
import { nameProblem } from "./name-rules";
import { readJoinTarget, type JoinTarget } from "./join";
import { navigateTo } from "./navigate";

type Class = "unlisted" | "named";

const TTL_PRESETS: { label: string; value: TtlBody }[] = [
  { label: "30 min after last activity", value: { kind: "idle-peers", secs: 1800 } },
  { label: "1 hour after last activity", value: { kind: "idle-peers", secs: 3600 } },
  { label: "8 hours after last activity", value: { kind: "idle-peers", secs: 28_800 } },
  { label: "24 hours from creation", value: { kind: "absolute", secs: 86_400 } },
];

export function Landing() {
  const [cls, setCls] = useState<Class>("unlisted");
  return (
    <main className="landing">
      <Field />
      <div className="masthead">
        <p className="micro-label eyebrow">Vardr Labs · ephemeral collaboration</p>
        <h1>RÚNA</h1>
        <p className="tagline">Shared, encrypted, and gone when you say so.</p>
      </div>

      {/* Two cards rather than a stacked list: the choice is binary, and side
          by side it costs one row instead of two. Only the selected card
          carries its explanation — the unselected one does not need to argue
          its case, and the height it saves is what keeps this on one screen. */}
      <div className="classes" role="radiogroup" aria-label="Room type">
        <label className={`class-card${cls === "unlisted" ? " is-on" : ""}`}>
          <input
            type="radio"
            name="cls"
            checked={cls === "unlisted"}
            onChange={() => setCls("unlisted")}
          />
          <span className="class-name">Private link</span>
          <span className="class-note">The link is the key</span>
        </label>
        <label className={`class-card${cls === "named" ? " is-on" : ""}`}>
          <input
            type="radio"
            name="cls"
            checked={cls === "named"}
            onChange={() => setCls("named")}
          />
          <span className="class-name">Shared name</span>
          <span className="class-note">A memorable address</span>
        </label>
      </div>

      <p className="class-detail">
        {cls === "unlisted" ? (
          <>Nobody can find it by guessing. Send the whole link — everything
          after the <span className="mono">#</span> is the key.</>
        ) : (
          <>Reachable at <span className="mono">{window.location.host}/copper-lantern</span>,
          so a passphrase is required. It is the only thing keeping the room
          private.</>
        )}
      </p>

      {cls === "unlisted" ? <UnlistedForm /> : <NamedForm />}

      <JoinForm />

      <footer className="landing-foot">
        <span className="micro-label">Apache-2.0 · no analytics · no cookies</span>
        <a
          className="source-link"
          href="https://github.com/vardrlabs/Runa"
          target="_blank"
          rel="noopener noreferrer"
        >
          {/* Inline rather than an <img>: the CSP is img-src 'self' data:,
              and an icon worth one request is not worth a network round trip
              on a page whose whole claim is that it fetches nothing. */}
          <svg viewBox="0 0 16 16" width="15" height="15" aria-hidden="true" fill="currentColor">
            <path d="M8 0C3.58 0 0 3.58 0 8c0 3.54 2.29 6.53 5.47 7.59.4.07.55-.17.55-.38
              0-.19-.01-.82-.01-1.49-2.01.37-2.53-.49-2.69-.94-.09-.23-.48-.94-.82-1.13-.28-.15-.68-.52-.01-.53.63-.01
              1.08.58 1.23.82.72 1.21 1.87.87 2.33.66.07-.52.28-.87.51-1.07-1.78-.2-3.64-.89-3.64-3.95
              0-.87.31-1.59.82-2.15-.08-.2-.36-1.02.08-2.12 0 0 .67-.21 2.2.82.64-.18 1.32-.27
              2-.27s1.36.09 2 .27c1.53-1.04 2.2-.82 2.2-.82.44 1.1.16 1.92.08 2.12.51.56.82
              1.27.82 2.15 0 3.07-1.87 3.75-3.65 3.95.29.25.54.73.54 1.48 0 1.07-.01 1.93-.01
              2.2 0 .21.15.46.55.38A8.01 8.01 0 0 0 16 8c0-4.42-3.58-8-8-8Z" />
          </svg>
          <span>Source on GitHub</span>
        </a>
      </footer>
    </main>
  );
}

/// Opening a room someone else made. A private room could only be reached by
/// its whole link and a shared one by typing its address into the browser's
/// bar; this takes either, however it was pasted, and says what it found
/// before anything is opened.
function JoinForm() {
  const [value, setValue] = useState("");
  const target = readJoinTarget(value, window.location.origin);
  const opens = target.kind === "private" || target.kind === "named";
  return (
    <form
      className="panel join"
      onSubmit={(e) => {
        e.preventDefault();
        if (target.kind === "private" && !target.elsewhere) {
          // The key is handed over in memory, so it never reaches the address
          // bar or the browser's history. A room on another server has to be
          // opened there, by its link.
          openUnlistedRoom(target.roomIdHex, target.fragment);
        } else if (target.kind === "named" && !target.elsewhere) {
          // Likewise the name: it reaches the address only once the room says
          // it is an everyday one.
          openNamedRoom(target.name);
        } else if (opens) {
          navigateTo(target.href);
        }
      }}
    >
      <div className="field">
        <label className="micro-label" htmlFor="join-room">JOIN A ROOM</label>
        <div className="row">
          <input
            id="join-room"
            type="text"
            inputMode="url"
            autoComplete="off"
            autoCapitalize="none"
            autoCorrect="off"
            spellCheck={false}
            placeholder="Paste a room link, or type a shared room’s name"
            value={value}
            onChange={(e) => setValue(e.target.value)}
          />
          <button type="submit" disabled={!opens}>Join</button>
        </div>
      </div>
      <p className={`join-hint${target.kind === "unrecognised" || target.kind === "private-no-key" ? " error-text" : ""}`} aria-live="polite">
        {joinHint(target)}
      </p>
    </form>
  );
}

function joinHint(t: JoinTarget): string {
  switch (t.kind) {
    case "nothing":
      return "The link someone sent you, or a shared room’s name like copper-lantern.";
    case "private":
      return t.elsewhere ? `A private room on ${t.elsewhere}, with its key.` : "A private room, with its key.";
    case "private-no-key":
      return t.damaged
        ? "The key after the # looks cut short. Copy the whole link again."
        : "That is a private room without its key — the part after the # in the link. Ask for the whole link.";
    case "named":
      return t.elsewhere
        ? `The shared room “${t.name}” on ${t.elsewhere}. You will need its passphrase.`
        : `The shared room “${t.name}”. You will need its passphrase.`;
    case "unrecognised":
      return t.reason;
  }
}

function ExpiryPicker({ onChange }: { onChange: (ttl: TtlBody) => void }) {
  return (
    <div className="field">
      <label className="micro-label" htmlFor="expiry">EXPIRY</label>
      <select id="expiry" defaultValue={JSON.stringify(TTL_PRESETS[1].value)} onChange={(e) => {
        const v = JSON.parse(e.target.value) as TtlBody;
        onChange(v);
      }}>
        {TTL_PRESETS.map((p) => (
          <option key={p.label} value={JSON.stringify(p.value)}>{p.label}</option>
        ))}
        <option value={JSON.stringify({ kind: "none", secs: 0 })}>
          No expiry — until shredded, or left empty and unedited for 12 hours
        </option>
      </select>
    </div>
  );
}

/// Chosen by whoever makes the room, sealed in its encrypted config, and so
/// applied for everyone who opens it — a source does not have to know the
/// setting exists to be covered by it.
function SecurityPicker({
  value,
  onChange,
  kind = "private",
}: {
  value: SecurityLevel;
  onChange: (l: SecurityLevel) => void;
  kind?: "private" | "shared";
}) {
  return (
    <div className="field">
      <label className="micro-label" htmlFor="security">SECURITY</label>
      <select id="security" value={value} onChange={(e) => onChange(e.target.value as SecurityLevel)}>
        <option value="everyday">Everyday — a refresh keeps you in the room</option>
        <option value="highest">Highest security — the key is never stored</option>
      </select>
      <p className="hint">
        {kind === "private"
          ? value === "everyday"
            ? "Either way the key never sits in the address bar or browser history. Everyday keeps it for this tab, so a refresh works."
            : "The key lives only in the open tab. Refreshing or closing it forgets the key; to come back, paste the link into Join a room. Choose this when someone could be harmed by being linked to this room."
          : value === "everyday"
            ? "The passphrase is never stored either way. Everyday gives the room its name as its address, so a refresh works and the address can be shared."
            : "The name never goes in the address bar or browser history, and the browser is asked not to save the passphrase. A refresh leaves the room; to come back, type its name into Join a room. Choose this when someone could be harmed by being linked to this room."}
      </p>
    </div>
  );
}

function UnlistedForm() {
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [ttl, setTtl] = useState<TtlBody>(TTL_PRESETS[1].value);
  const [level, setLevel] = useState<SecurityLevel>("everyday");

  const create = async () => {
    setBusy(true);
    setError(null);
    try {
      const salt = randomSalt();
      const linkSecret = randomLinkSecret();
      const { authKey, contentKey } = await deriveRoomKeys(null, linkSecret, salt);
      const verifierB64 = await verifierForAuthKey(authKey);
      // The id is assigned by the server: letting the client pick it made
      // creation into a probe for which rooms are live.
      const created = await new Api("").createUnlisted({
        verifierB64,
        kdf: { m_kib: 65536, t: 3, p: 1, salt: b64Of(salt) },
        ttl,
        ceilingOptout: ttl.kind === "none",
        configBlob: await encryptRoomConfig(contentKey, ttl, ttl.kind === "none", level),
      });
      openUnlistedRoom(created.room_id, fragmentWithKey(linkSecret, salt));
    } catch (e) {
      setError(describeError(e));
      setBusy(false);
    }
  };

  return (
    <div className="panel">
      <ExpiryPicker onChange={setTtl} />
      <SecurityPicker value={level} onChange={setLevel} />
      <button className="primary" onClick={create} disabled={busy}>
        {busy ? "Creating…" : "Create private room"}
      </button>
      {error && <p className="error-text mono">{error}</p>}
    </div>
  );
}

function NamedForm() {
  const [name, setName] = useState(generateRoomName(true));
  const [passphrase, setPassphrase] = useState("");
  const [suffixOn, setSuffixOn] = useState(true);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [refusal, setRefusal] = useState<string | null>(null);
  const [ttl, setTtl] = useState<TtlBody>(TTL_PRESETS[1].value);
  const [level, setLevel] = useState<SecurityLevel>("everyday");

  const nameIssue = name ? nameProblem(suffixOn ? name : name.replace(/-[0-9a-f]{4}$/, "")) : null;

  const create = async () => {
    setError(null);
    setRefusal(null);
    const finalNameCheck = nameProblem(suffixOn ? name : name.replace(/-[0-9a-f]{4}$/, ""));
    if (finalNameCheck) {
      setRefusal(finalNameCheck);
      return;
    }
    const v = estimatePassphrase(passphrase);
    // Was `!v.dicewareWords || !v.ok`, which refused every passphrase that
    // was not a run of lowercase words — including anything a password
    // manager generates, which is stronger than the diceware it insisted on.
    // Strength is the bar; the shape of it is not.
    if (!v.ok) {
      setRefusal(
        "This room's name is public, so the passphrase is the only key protecting it. Use a longer one, or press Generate for a five-word passphrase.",
      );
      return;
    }
    setBusy(true);
    try {
      const finalName = suffixOn ? name : name.replace(/-[0-9a-f]{4}$/, "");
      // Ask first. Creating the room is what finally checks the name, but the
      // key derivation in front of it is the slowest step on this page —
      // seconds on a phone — so a taken name used to cost that whole wait and
      // then an error about the passphrase. The server still decides: this
      // only saves the wait, and if the lookup itself fails, creation goes
      // ahead and the server refuses the name there.
      const existing = await new Api("").resolveName(finalName).catch(() => null);
      if (existing?.found) {
        setRefusal(`“${finalName}” is already taken. Pick a different name.`);
        setBusy(false);
        return;
      }
      const salt = randomSalt();
      const kdfResult = await passphraseMaterial(passphrase, salt);
      const material = kdfResult.material;
      if (!material) throw new Error("no material");
      const { authKey, contentKey } = await deriveRoomKeys(material, null, salt);
      const verifierB64 = await verifierForAuthKey(authKey);
      await new Api("").createNamed({
        name: finalName,
        suffix: false,
        verifierB64,
        kdf: { m_kib: 65536, t: 3, p: 1, salt: b64Of(salt) },
        ttl,
        ceilingOptout: ttl.kind === "none",
        configBlob: await encryptRoomConfig(contentKey, ttl, ttl.kind === "none", level),
      });
      if (level === "highest") openNamedRoom(finalName);
      else navigateTo(`/${finalName}`);
    } catch (e) {
      setError(describeError(e));
      setBusy(false);
    }
  };

  return (
    <div className="panel">
      <div className="field">
        <label className="micro-label" htmlFor="room-name">ROOM NAME</label>
        <div className="row">
          <input
            id="room-name"
            type="text"
            autoComplete="off"
            spellCheck={false}
            value={name}
            onChange={(e) => setName(e.target.value.toLowerCase())}
          />
          <button type="button" onClick={() => setName(generateRoomName(suffixOn))}>↻</button>
        </div>
        {nameIssue ? (
          <p className="error-text">{nameIssue}</p>
        ) : (
          <p className="hint">
            This becomes the address: <span className="mono">{window.location.host}/{suffixOn ? name : name.replace(/-[0-9a-f]{4}$/, "")}</span>
          </p>
        )}
      </div>
      <label className="row field checkbox-row">
        <input
          type="checkbox"
          checked={suffixOn}
          onChange={(e) => {
            // Add or remove the suffix on whatever is already in the box.
            // This used to regenerate the entire name, so unticking it after
            // typing something silently replaced your words with two random
            // ones.
            const on = e.target.checked;
            setSuffixOn(on);
            const base = name.replace(/-[0-9a-f]{4}$/, "");
            setName(on ? `${base}-${randomHexSuffix()}` : base);
          }}
        />
        <span className="hint">
          Add a few random characters to the end. Without them, someone could
          guess the address and see that a room exists — they still could not
          read it without the passphrase.
        </span>
      </label>
      {/* "new-password" invites the browser to save it, and a password
          manager with sync carries it off the device. A highest-security
          room asks it not to; browsers may still offer, which the hint
          below says. */}
      <PassphraseField
        id="passphrase"
        value={passphrase}
        onChange={setPassphrase}
        autoComplete={level === "highest" ? "off" : "new-password"}
      />
      <ExpiryPicker onChange={setTtl} />
      <SecurityPicker value={level} onChange={setLevel} kind="shared" />
      <button className="primary" onClick={create} disabled={busy}>
        {busy ? "Creating…" : "Create shared room"}
      </button>
      {refusal && <p className="error-text mono" role="alert">{refusal}</p>}
      {error && <p className="error-text mono">{error}</p>}
    </div>
  );
}

function describeError(e: unknown): string {
  const code = e instanceof Error ? e.message : String(e);
  switch (code) {
    case "NAME_TAKEN":
      return "That name is already taken. Pick a different name.";
    case "UNAVAILABLE":
      return "Could not reserve a room just now. Try again.";
    case "ARGON2_UNAVAILABLE":
      return "This browser could not run Argon2, which protects a shared room's passphrase. Try an up-to-date browser, or close other tabs to free memory.";
    case "NAME_INVALID":
      return "The server would not accept that name. Try another.";
    case "RATE_LIMITED":
      return "Too many rooms created from here just now. Wait a minute.";
    case "AT_CAPACITY":
      return "This server is at its room limit right now. Try again shortly.";
    case "RESTARTING":
      return "This server is restarting for an update. Try again in a minute.";
    default:
      return `Could not create the room (${code}).`;
  }
}

function b64Of(bytes: Uint8Array): string {
  let s = "";
  for (const b of bytes) s += String.fromCharCode(b);
  return btoa(s);
}
