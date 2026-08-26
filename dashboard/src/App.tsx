import { useCallback, useEffect, useMemo, useState } from "react";
import type { Envelope } from "./crypto";
import { clearKey, decryptEnvelope, deriveKey, loadPersistedKey, persistKey } from "./crypto";
import type { HealthLevel, Snapshot, WorkerView } from "./types";
import {
  STALE_CRIT_SECONDS, STALE_WARN_SECONDS, classifyAll, fmtAge, fmtGb, fmtUptime, healthRank,
} from "./derive";
import { Gate } from "./components/Gate";
import { WorkerCard } from "./components/WorkerCard";
import { WorkerDrawer } from "./components/WorkerDrawer";
import { Sparkline } from "./components/Sparkline";

const DATA_URL = `${import.meta.env.BASE_URL}data/fleet.enc.json`;

type Sort = "health" | "name" | "speed" | "disk" | "load";

function useTheme() {
  const [theme, setTheme] = useState<"dark" | "light">(
    () => (localStorage.getItem("rch_dash_theme") as "dark" | "light") ?? "dark",
  );
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
  const [fetchError, setFetchError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [now, setNow] = useState(() => Date.now());
  const [theme, setTheme] = useTheme();

  const [query, setQuery] = useState("");
  const [statusFilter, setStatusFilter] = useState<HealthLevel | "all">("all");
  const [sort, setSort] = useState<Sort>("health");
  const [openId, setOpenId] = useState<string | null>(null);

  // Keep relative timestamps honest without re-fetching.
  useEffect(() => {
    const t = setInterval(() => setNow(Date.now()), 30_000);
    return () => clearInterval(t);
  }, []);

  const loadEnvelope = useCallback(async (): Promise<Envelope | null> => {
    try {
      const res = await fetch(`${DATA_URL}?t=${Date.now()}`, { cache: "no-store" });
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const env = (await res.json()) as Envelope;
      setEnvelope(env);
      setFetchError(null);
      return env;
    } catch (e) {
      setFetchError(
        `Could not load the snapshot (${String((e as Error).message)}). ` +
          `Publish one with \`npm run snapshot\`.`,
      );
      return null;
    }
  }, []);

  // On mount: fetch the payload, and if a derived key is already stored, use it.
  useEffect(() => {
    void (async () => {
      const env = await loadEnvelope();
      if (!env) return;
      const key = await loadPersistedKey();
      if (!key) return;
      try {
        const plain = await decryptEnvelope(env, key);
        setSnap(JSON.parse(plain));
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
        const plain = await decryptEnvelope(env, key); // throws if wrong
        setSnap(JSON.parse(plain));
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
    const key = await loadPersistedKey();
    if (!key) return;
    try {
      setSnap(JSON.parse(await decryptEnvelope(env, key)));
    } catch {
      setFetchError("Snapshot was re-encrypted with a different passphrase — unlock again.");
      clearKey();
      setSnap(null);
    }
  }, [loadEnvelope]);

  const workers: WorkerView[] = useMemo(
    () => (snap ? classifyAll(snap, now) : []),
    [snap, now],
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
        default:
          return healthRank(a.health) - healthRank(b.health) || a.id.localeCompare(b.id);
      }
    });
    return sorted;
  }, [workers, query, statusFilter, sort]);

  if (!snap) {
    return (
      <>
        {fetchError && (
          <div style={{ maxWidth: 460, margin: "18px auto 0", padding: "0 16px" }}>
            <div className="banner">{fetchError}</div>
          </div>
        )}
        <Gate onUnlock={unlock} error={error} busy={busy} />
      </>
    );
  }

  const ageSec = (now - new Date(snap.generated_at).getTime()) / 1000;
  const dotClass = ageSec > STALE_CRIT_SECONDS ? "old" : ageSec > STALE_WARN_SECONDS ? "stale" : "live";

  // Slot capacity belongs to the WORKER, not to each dispatcher's view of it.
  // Summing `queue.slots_total` across dispatchers counts every worker once per
  // dispatcher — with 3 dispatchers each seeing the same 15 workers that
  // reported 198 slots for an 80-slot fleet. Use the deduplicated worker union.
  const slotsTotal = snap.totals.slots;
  const activeBuilds = workers.reduce((n, w) => n + w.active_builds, 0);
  const workersBusy = workers.filter((w) => w.active_builds > 0).length;
  const diskUsedPct =
    snap.totals.disk_total_gb > 0
      ? ((snap.totals.disk_total_gb - snap.totals.disk_free_gb) / snap.totals.disk_total_gb) * 100
      : 0;
  const attention = (counts.critical ?? 0) + (counts.warn ?? 0) + (counts.offline ?? 0);

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
        <button
          className="icon-btn"
          onClick={() => { clearKey(); setSnap(null); }}
        >
          Lock
        </button>
      </header>

      {ageSec > STALE_CRIT_SECONDS && (
        <div className="banner">
          This snapshot is {fmtAge(ageSec)} old — it may no longer reflect the fleet.
          Re-run <code>npm run snapshot</code> to refresh it.
        </div>
      )}

      <section className="kpis">
        <div className="kpi" style={{ ["--kpi-accent" as string]: "var(--accent)" }}>
          <div className="kpi-label">Workers</div>
          <div className="kpi-value">{snap.totals.workers}</div>
          <div className="kpi-sub">
            {counts.healthy ?? 0} healthy · {counts.busy ?? 0} busy
          </div>
        </div>
        <div
          className="kpi"
          style={{ ["--kpi-accent" as string]: attention > 0 ? "var(--warn)" : "var(--ok)" }}
        >
          <div className="kpi-label">Needs attention</div>
          <div className="kpi-value">{attention}</div>
          <div className="kpi-sub">
            {counts.critical ?? 0} critical · {counts.warn ?? 0} warn · {counts.offline ?? 0} offline
          </div>
        </div>
        <div className="kpi" style={{ ["--kpi-accent" as string]: "var(--busy)" }}>
          <div className="kpi-label">Build slots</div>
          <div className="kpi-value">{slotsTotal}</div>
          <div className="kpi-sub">
            {activeBuilds} active build{activeBuilds === 1 ? "" : "s"} on {workersBusy} worker
            {workersBusy === 1 ? "" : "s"}
          </div>
        </div>
        <div className="kpi" style={{ ["--kpi-accent" as string]: "var(--accent)" }}>
          <div className="kpi-label">Cores</div>
          <div className="kpi-value">{snap.totals.cores}</div>
          <div className="kpi-sub">{snap.totals.workers} machines</div>
        </div>
        <div
          className="kpi"
          style={{ ["--kpi-accent" as string]: diskUsedPct >= 88 ? "var(--warn)" : "var(--ok)" }}
        >
          <div className="kpi-label">Disk free</div>
          <div className="kpi-value">{fmtGb(snap.totals.disk_free_gb)}</div>
          <div className="kpi-sub">{diskUsedPct.toFixed(0)}% of {fmtGb(snap.totals.disk_total_gb)} used</div>
        </div>
        <div
          className="kpi"
          style={{
            ["--kpi-accent" as string]:
              snap.totals.dispatchers_reachable < snap.totals.dispatchers_total
                ? "var(--crit)" : "var(--ok)",
          }}
        >
          <div className="kpi-label">Dispatchers</div>
          <div className="kpi-value">
            {snap.totals.dispatchers_reachable}
            <span className="unit">/ {snap.totals.dispatchers_total}</span>
          </div>
          <div className="kpi-sub">reachable</div>
        </div>
      </section>

      {snap.history.length > 1 && (
        <section className="section">
          <div className="section-head">
            <h2>Free slots over time</h2>
            <span className="count-pill">{snap.history.length} snapshots</span>
          </div>
          <div className="kpi" style={{ ["--kpi-accent" as string]: "var(--busy)" }}>
            <Sparkline
              values={snap.history.map((h) => h.slots_available)}
              stroke="var(--busy)"
              label="free slots over time"
            />
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
                {s}
                {s !== "all" && counts[s] ? ` ${counts[s]}` : ""}
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
              <WorkerCard key={w.id} w={w} onOpen={setOpenId} />
            ))}
          </div>
        )}
      </section>

      <section className="section">
        <div className="section-head">
          <h2>Dispatchers</h2>
          <span className="count-pill">{snap.dispatchers.length}</span>
        </div>
        <div className="dgrid">
          {snap.dispatchers.map((d) => (
            <div className="dcard" key={d.id}>
              <div className="dcard-top">
                <span className={`dot ${d.reachable ? "live" : "old"}`} />
                <span className="dname">{d.id}</span>
                <span style={{ flex: 1 }} />
                <span className={`pill ${d.reachable ? "healthy" : "critical"}`}>
                  {d.reachable ? "up" : "unreachable"}
                </span>
              </div>
              <div className="dstat"><span>Daemon uptime</span><span>{fmtUptime(d.uptime_seconds)}</span></div>
              <div className="dstat"><span>Workers</span><span>{d.queue?.workers_available ?? "—"} / {d.queue?.workers_total ?? "—"}</span></div>
              <div className="dstat"><span>Slots free</span><span>{d.queue?.slots_available ?? "—"} / {d.queue?.slots_total ?? "—"}</span></div>
              <div className="dstat"><span>Queue depth</span><span>{d.queue?.queue_depth ?? "—"}</span></div>
              <div className="dstat"><span>Active builds</span><span>{d.queue?.active_builds.length ?? "—"}</span></div>
            </div>
          ))}
        </div>
      </section>

      <footer className="footer">
        <span>schema {snap.schema}</span>
        <span>generated {new Date(snap.generated_at).toLocaleString()}</span>
        <span>decrypted locally · AES-256-GCM</span>
      </footer>

      <WorkerDrawer w={workers.find((w) => w.id === openId) ?? null} onClose={() => setOpenId(null)} />
    </div>
  );
}
