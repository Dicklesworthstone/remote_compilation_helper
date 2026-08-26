import { useState, type FormEvent } from "react";

interface Props {
  onUnlock: (passphrase: string, remember: boolean) => Promise<void>;
  error: string | null;
  busy: boolean;
}

export function Gate({ onUnlock, error, busy }: Props) {
  const [passphrase, setPassphrase] = useState("");
  const [remember, setRemember] = useState(true);

  function submit(e: FormEvent) {
    e.preventDefault();
    if (!passphrase || busy) return;
    void onUnlock(passphrase, remember);
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

        <button className="btn" type="submit" disabled={busy || !passphrase}>
          {busy ? "Deriving key…" : "Unlock"}
        </button>

        {error && <div className="gate-err">{error}</div>}

        <p className="gate-note">
          The payload is AES-256-GCM ciphertext with a PBKDF2-SHA-256 (600k iteration) key.
          Decryption happens entirely in this tab — the passphrase is never sent anywhere and is
          never stored. "Stay unlocked" saves only the derived key, scoped to this site.
        </p>
      </form>
    </div>
  );
}
