import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import type { Envelope } from "./crypto";
import { clearKey, decryptEnvelope, deriveKey, loadPersistedKey, persistKey } from "./crypto";
import type { DispatcherView, HealthLevel, Snapshot, WorkerView } from "./types";
import {
  STALE_CRIT_SECONDS, STALE_WARN_SECONDS, classifyAll, classifyDispatcher,
  devRank, fmtAge, fmtGb, healthRank,
} from "./derive";
import { Gate } from "./components/Gate";
import { WorkerCard } from "./components/WorkerCard";
import { WorkerDrawer } from "./components/WorkerDrawer";
import { DevMachineCard } from "./components/DevMachineCard";
import { DevMachineDrawer } from "./components/DevMachineDrawer";
import { Sparkline } from "./components/Sparkline";

const DATA_URL = `${import.meta.env.BASE_URL}data/fleet.enc.json`;

type Sort = "health" | "name" | "speed" | "disk" | "load" | "slots";

function useTheme() {
  const [theme, setTheme] = useState<"dark" | "light">(() => {
    try {
      return (localStorage.getItem("rch_dash_theme") as "dark" | "light") ?? "dark";
    } catch {
      return "dark";
    }
  });
  useEffect(() => {
    document.documentElement.dataset.theme = theme;
    try {
      localStorage.setItem("rch_dash_theme", theme);
    } catch {
      /* private mode — the toggle still works for this session */
    }
  }, [theme]);
  return [theme, setTheme] as const;
}

export default function App() {
  const [envelope, setEnvelope] = useState<Envelope | null>(null);
  const [snap, setSnap] = useState<Snapshot | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [now, setNow] = useState(() => Date.now());
  const [theme, setTheme] = useTheme();

  // The live key is held in a ref, NOT only in the cookie. Without this,
  // Refresh silently did nothing whenever the operator unlocked without
  // ticking "stay unlocked", because there was no key to decrypt the reload.
  const keyRef = useRef<CryptoKey | null>(null);

  const [query, setQuery] = useState("");
  const [statusFilter, setStatusFilter] = useState<HealthLevel | "all">("all");
  const [sort, setSort] = useState<Sort>("health");
  const [openWorker, setOpenWorker] = useState<string | null>(null);
  const [openDev, setOpenDev] = useState<string | null>(null);

  useEffect(() => {
    const t = setInterval(() => setNow(Date.now()), 30_000);
    return () => clearInterval(t);
  }, []);

  const loadEnvelope = useCallback(async (): Promise<Envelope | null> => {
    try {
      const res = await fetch(`${DATA_URL}?t=${Date.now()}`, { cache: "no-store" });
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const env = (await res.json()) as Envelope;
      if (!env?.ciphertext || !env?.kdf?.salt) throw new Error("not an encrypted snapshot");
      setEnvelope(env);
      setNotice(null);
      return env;
    } catch (e) {
      setNotice(
        `Could not load the snapshot (${String((e as Error).message)}). ` +
          `Publish one with \`npm run snapshot\`.`,
      );
      return null;
    }
  }, []);

  useEffect(() => {
    void (async () => {
      const env = await loadEnvelope();
      if (!env) return;
      const key = await loadPersistedKey();
      if (!key) return;
      try {
        setSnap(JSON.parse(await decryptEnvelope(env, key)));
        keyRef.current = key;
      } catch {
        // Stale key (snapshot re-encrypted with a new salt, or passphrase
        // rotated). Drop it and fall back to the gate rather than looping.
        clearKey();
      }
    })();
  }, [loadEnvelope]);

  const unlock = useCallback(
    async (passphrase: string, remember: boolean) => {
      setBusy(true);
      setError(null);
      try {
        const env = envelope ?? (await loadEnvelope());
        if (!env) {
          setError("No snapshot to decrypt yet.");
          return;
        }
        const key = await deriveKey(passphrase, env);
        const plain = await decryptEnvelope(env, key); // throws on a wrong key
        setSnap(JSON.parse(plain));
        keyRef.current = key;
        if (remember) await persistKey(key);
      } catch {
        setError("Wrong passphrase.");
      } finally {
        setBusy(false);
      }
    },
    [envelope, loadEnvelope],
  );

  const refresh = useCallback(async () => {
    const env = await loadEnvelope();
    if (!env) return;
    const key = keyRef.current ?? (await loadPersistedKey());
    if (!key) {
      setNotice("Session key unavailable — unlock again to refresh.");
      setSnap(null);
      return;
    }
    try {
      setSnap(JSON.parse(await decryptEnvelope(env, key)));
      keyRef.current = key;
    } catch {
      // A new snapshot uses a fresh salt, so a key derived from the SAME
      // passphrase still decrypts it. Failure here means the passphrase itself
      // changed.
      setNotice("Snapshot was encrypted with a different passphrase — unlock again.");
      clearKey();
      keyRef.current = null;
      setSnap(null);
    }
  }, [loadEnvelope]);

  const lock = useCallback(() => {
    clearKey();
    keyRef.current = null;
    setSnap(null);
    setNotice(null);
  }, []);

  // classifyAll deliberately ignores the reader clock (worker staleness is
  // judged against snapshot time), so this must NOT depend on `now` — it
  // would recompute every tick for an identical result.
  const workers: WorkerView[] = useMemo(() => (snap ? classifyAll(snap) : []), [snap]);
  const devs: DispatcherView[] = useMemo(
    () => (snap ? snap.dispatchers.map(classifyDispatcher).sort((a, b) => devRank(a.level) - devRank(b.level) || a.id.localeCompare(b.id)) : []),
    [snap],
  );

  const counts = useMemo(() => {
    const c: Record<string, number> = {};
    for (const w of workers) c[w.health] = (c[w.health] ?? 0) + 1;
    return c;
  }, [workers]);

  const visible = useMemo(() => {
    const q = query.trim().toLowerCase();
    let list = workers;
    if (statusFilter !== "all") list = list.filter((w) => w.health === statusFilter);
    if (q) {
      list = list.filter(
        (w) =>
          w.id.toLowerCase().includes(q) ||
          (w.host ?? "").toLowerCase().includes(q) ||
          w.tags.some((t) => t.toLowerCase().includes(q)),
      );
    }
    const sorted = [...list];
    sorted.sort((a, b) => {
      switch (sort) {
        case "name": return a.id.localeCompare(b.id);
        case "speed": return (b.speed ?? -1) - (a.speed ?? -1);
        case "disk": return (b.diskUsedPct ?? -1) - (a.diskUsedPct ?? -1);
        case "load": return (b.loadPerCore ?? -1) - (a.loadPerCore ?? -1);
        case "slots": return (b.total_slots ?? -1) - (a.total_slots ?? -1);
        default: return healthRank(a.health) - healthRank(b.health) || a.id.localeCompare(b.id);
      }
    });
    return sorted;
  }, [workers, query, statusFilter, sort]);

  if (!snap) {
    return (
      <>
        {notice && (
          <div style={{ maxWidth: 460, margin: "18px auto 0", padding: "0 16px" }}>
            <div className="banner">{notice}</div>
          </div>
        )}
        <Gate onUnlock={unlock} error={error} busy={busy} />
      </>
    );
  }

  const t = snap.totals;
  const ageSec = (now - new Date(snap.generated_at).getTime()) / 1000;
  const dotClass = ageSec > STALE_CRIT_SECONDS ? "old" : ageSec > STALE_WARN_SECONDS ? "stale" : "live";
  const diskUsedPct =
    t.disk_total_gb > 0 ? ((t.disk_total_gb - t.disk_free_gb) / t.disk_total_gb) * 100 : 0;
  const attention = (counts.critical ?? 0) + (counts.warn ?? 0) + (counts.offline ?? 0);
  const devProblems = devs.filter((d) => d.level === "local-only" || d.level === "unreachable" || d.level === "degraded");
  const buildsCounted = t.builds_remote + t.builds_local;
  const remotePct = buildsCounted > 0 ? (t.builds_remote / buildsCounted) * 100 : null;

  return (
    <div className="shell">
      <header className="topbar">
        <div className="brand">
          <span className="brand-mark">rch</span>
          <span className="brand-label">{snap.label}</span>
        </div>
        <span className="spacer" />
        <div className="stamp">
          <span className={`dot ${dotClass}`} />
          snapshot {fmtAge(ageSec)}
        </div>
        <button className="icon-btn" onClick={() => void refresh()}>Refresh</button>
        <button className="icon-btn" onClick={() => setTheme(theme === "dark" ? "light" : "dark")}>
          {theme === "dark" ? "Light" : "Dark"}
        </button>
        <button className="icon-btn" onClick={lock}>Lock</button>
      </header>

      {notice && <div className="banner">{notice}</div>}

      {ageSec > STALE_CRIT_SECONDS && (
        <div className="banner">
          This snapshot is {fmtAge(ageSec)} old — it may no longer reflect the fleet.
          Re-run <code>npm run snapshot</code>.
        </div>
      )}

      {devProblems.length > 0 && (
        <div className="banner crit">
          {devProblems.length} dev machine{devProblems.length === 1 ? "" : "s"} not offloading normally:{" "}
          {devProblems.map((d) => d.id).join(", ")}. Builds there may be running locally.
        </div>
      )}

      <section className="kpis">
        <div className="kpi" style={{ ["--kpi-accent" as string]: "var(--accent)" }}>
          <div className="kpi-label">Workers</div>
          <div className="kpi-value">{t.workers}</div>
          <div className="kpi-sub">{counts.healthy ?? 0} healthy · {counts.busy ?? 0} busy</div>
        </div>
        <div className="kpi" style={{ ["--kpi-accent" as string]: attention > 0 ? "var(--warn)" : "var(--ok)" }}>
          <div className="kpi-label">Needs attention</div>
          <div className="kpi-value">{attention}</div>
          <div className="kpi-sub">
            {counts.critical ?? 0} critical · {counts.warn ?? 0} warn · {counts.offline ?? 0} offline
          </div>
        </div>
        <div className="kpi" style={{ ["--kpi-accent" as string]: "var(--busy)" }}>
          <div className="kpi-label">Build slots</div>
          <div className="kpi-value">{t.slots_used}<span className="unit">/ {t.slots}</span></div>
          <div className="kpi-sub">{t.active_builds} active build{t.active_builds === 1 ? "" : "s"}</div>
        </div>
        <div
          className="kpi"
          style={{ ["--kpi-accent" as string]: devProblems.length > 0 ? "var(--crit)" : "var(--ok)" }}
        >
          <div className="kpi-label">Dev machines</div>
          <div className="kpi-value">
            {t.dispatchers_remote_ready}<span className="unit">/ {t.dispatchers_reachable}</span>
          </div>
          <div className="kpi-sub">remote-ready of {t.dispatchers_total} configured</div>
        </div>
        <div
          className="kpi"
          style={{ ["--kpi-accent" as string]: remotePct != null && remotePct < 80 ? "var(--warn)" : "var(--ok)" }}
        >
          <div className="kpi-label">Builds offloaded</div>
          <div className="kpi-value">
            {remotePct != null ? `${remotePct.toFixed(0)}%` : "—"}
          </div>
          <div className="kpi-sub">{t.builds_remote} remote · {t.builds_local} local</div>
        </div>
        <div
          className="kpi"
          style={{ ["--kpi-accent" as string]: diskUsedPct >= 88 ? "var(--warn)" : "var(--ok)" }}
        >
          <div className="kpi-label">Disk free</div>
          <div className="kpi-value">{fmtGb(t.disk_free_gb)}</div>
          <div className="kpi-sub">{diskUsedPct.toFixed(0)}% of {fmtGb(t.disk_total_gb)} used</div>
        </div>
      </section>

      <section className="section">
        <div className="section-head">
          <h2>Dev machines</h2>
          <span className="count-pill">{devs.length}</span>
          <span className="spacer" />
          <span className="hint-inline">boxes that run rch and dispatch builds to the pool</span>
        </div>
        <div className="grid">
          {devs.map((d) => (
            <DevMachineCard key={d.id} d={d} onOpen={setOpenDev} />
          ))}
        </div>
      </section>

      {snap.history.length > 1 && (
        <section className="section">
          <div className="section-head">
            <h2>Trend</h2>
            <span className="count-pill">{snap.history.length} snapshots</span>
          </div>
          <div className="trend-grid">
            <div className="kpi" style={{ ["--kpi-accent" as string]: "var(--busy)" }}>
              <div className="kpi-label">Slots in use</div>
              <Sparkline values={snap.history.map((h) => h.slots_used)} stroke="var(--busy)" label="slots in use over time" />
            </div>
            <div className="kpi" style={{ ["--kpi-accent" as string]: "var(--ok)" }}>
              <div className="kpi-label">Disk free (GB)</div>
              <Sparkline values={snap.history.map((h) => h.disk_free_gb)} stroke="var(--ok)" label="fleet disk free over time" />
            </div>
            <div className="kpi" style={{ ["--kpi-accent" as string]: "var(--accent)" }}>
              <div className="kpi-label">Remote builds</div>
              <Sparkline values={snap.history.map((h) => h.builds_remote)} stroke="var(--accent)" label="remote builds over time" />
            </div>
          </div>
        </section>
      )}

      <section className="section">
        <div className="section-head">
          <h2>Workers</h2>
          <span className="count-pill">{visible.length} of {workers.length}</span>
          <span className="spacer" />
          <div className="filters">
            <input
              className="search"
              placeholder="Filter by name, host or tag…"
              value={query}
              onChange={(e) => setQuery(e.target.value)}
              aria-label="Filter workers"
            />
            {(["all", "critical", "warn", "offline", "busy", "healthy"] as const).map((s) => (
              <button
                key={s}
                className="chip"
                aria-pressed={statusFilter === s}
                onClick={() => setStatusFilter(s as HealthLevel | "all")}
              >
                {s}{s !== "all" && counts[s] ? ` ${counts[s]}` : ""}
              </button>
            ))}
            <select
              className="search"
              value={sort}
              onChange={(e) => setSort(e.target.value as Sort)}
              aria-label="Sort workers"
              style={{ minWidth: 0 }}
            >
              <option value="health">sort: health</option>
              <option value="name">sort: name</option>
              <option value="speed">sort: speed</option>
              <option value="slots">sort: slots</option>
              <option value="disk">sort: disk used</option>
              <option value="load">sort: load</option>
            </select>
          </div>
        </div>

        {visible.length === 0 ? (
          <div className="empty">No workers match this filter.</div>
        ) : (
          <div className="grid">
            {visible.map((w) => (
              <WorkerCard key={w.id} w={w} onOpen={setOpenWorker} />
            ))}
          </div>
        )}
      </section>

      <footer className="footer">
        <span>schema {snap.schema}</span>
        <span>generated {new Date(snap.generated_at).toLocaleString()}</span>
        <span>decrypted locally · AES-256-GCM</span>
      </footer>

      <WorkerDrawer w={workers.find((w) => w.id === openWorker) ?? null} onClose={() => setOpenWorker(null)} />
      <DevMachineDrawer d={devs.find((d) => d.id === openDev) ?? null} onClose={() => setOpenDev(null)} />
    </div>
  );
}
