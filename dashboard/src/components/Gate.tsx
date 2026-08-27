import { useState, type FormEvent } from "react";

interface Props {
  onUnlock: (passphrase: string, remember: boolean) => Promise<void>;
  error: string | null;
  busy: boolean;
}

export function Gate({ onUnlock, error, busy }: Props) {
  const [passphrase, setPassphrase] = useState("");
  const [remember, setRemember] = useState(true);

  /**
   * Trimmed at SUBMIT, not on change.
   *
   * Copying a passphrase out of a terminal, a password manager or a chat message
   * very often brings a trailing newline or space with it, and a passphrase field
   * is masked — so the stray character is invisible and the only feedback is
   * "Wrong passphrase", which sends you looking for the wrong problem.
   *
   * Trimming while typing would be worse than not trimming: it would silently
   * eat a space the moment you typed one, so a passphrase containing spaces
   * could never be entered at all. Interior whitespace is untouched here.
   *
   * Every other entry point (the collector, the CLI and all three /api/fleet
   * credential channels) trims identically, so the effective passphrase is the
   * same string everywhere. That agreement is the point: trimming HERE but not
   * where the snapshot is encrypted would lock the dashboard out of its own
   * payload.
   */
  const effective = passphrase.trim();

  function submit(e: FormEvent) {
    e.preventDefault();
    if (!effective || busy) return;
    void onUnlock(effective, remember);
  }

  return (
    <div className="gate">
      <form className="gate-card" onSubmit={submit}>
        <div className="gate-mark">rch · fleet</div>
        <h1>Locked</h1>
        <p className="gate-sub">
          This snapshot is encrypted. Enter the fleet passphrase to decrypt it in your browser.
        </p>

        <div className="field">
          <label htmlFor="pp">Passphrase</label>
          <input
            id="pp"
            type="password"
            value={passphrase}
            autoFocus
            autoComplete="current-password"
            spellCheck={false}
            placeholder="••••••••••••••••••••"
            onChange={(e) => setPassphrase(e.target.value)}
          />
        </div>

        <label
          style={{
            display: "flex", alignItems: "center", gap: 8,
            fontSize: 13, color: "var(--text-dim)", marginBottom: 16, cursor: "pointer",
          }}
        >
          <input type="checkbox" checked={remember} onChange={(e) => setRemember(e.target.checked)} />
          Stay unlocked on this device for 60 days
        </label>

        <button className="btn" type="submit" disabled={busy || !effective}>
          {busy ? "Deriving key…" : "Unlock"}
        </button>

        {error && <div className="gate-err" role="alert">{error}</div>}

        <p className="gate-note">
          The payload is AES-256-GCM ciphertext with a PBKDF2-SHA-256 (600k iteration) key.
          Decryption happens entirely in this tab — the passphrase is never sent anywhere and is
          never stored. "Stay unlocked" saves only the derived key, scoped to this site.
        </p>
      </form>
    </div>
  );
}
