import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import type { Envelope } from "./crypto";
import { clearKey, decryptEnvelope, deriveKey, loadPersistedKey, persistKey } from "./crypto";
import type { DispatcherView, HealthLevel, Snapshot, WorkerView } from "./types";
import {
  STALE_CRIT_SECONDS, classifyAll, classifyDispatcher,
  devRank, fmtAge, healthRank,
} from "./derive";
import { Gate } from "./components/Gate";
import { WorkerDrawer } from "./components/WorkerDrawer";
import { DevMachineCard } from "./components/DevMachineCard";
import { DevMachineDrawer } from "./components/DevMachineDrawer";
import { Overview } from "./components/Overview";
import { Topbar, WorkersSection, type Sort } from "./components/Topbar";


const DATA_URL = `${import.meta.env.BASE_URL}data/fleet.enc.json`;

/** Filter/sort state persists in the URL hash so views are shareable. */
function readViewPref(): { query: string; statusFilter: HealthLevel | "all"; sort: Sort } {
  const h = new URLSearchParams(location.hash.replace(/^#/, ""));
  const FILTERS = ["all", "critical", "warn", "offline", "busy", "healthy"];
  const SORTS = ["health", "name", "speed", "disk", "load", "slots"];
  const f = h.get("f");
  const s = h.get("s");
  return {
    query: h.get("q") ?? "",
    statusFilter: f && FILTERS.includes(f) ? (f as HealthLevel | "all") : "all",
    sort: s && SORTS.includes(s) ? (s as Sort) : "health",
  };
}

function useTheme() {
  const [theme, setTheme] = useState<"dark" | "light">(() => {
    try {
      const stored = localStorage.getItem("rch_dash_theme") as "dark" | "light" | null;
      if (stored) return stored;
      return window.matchMedia?.("(prefers-color-scheme: light)").matches ? "light" : "dark";
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
  // Only read inside callbacks — a ref, not state, so a fresh envelope never
  // triggers a pointless render.
  const envelopeRef = useRef<Envelope | null>(null);
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

  const [openWorker, setOpenWorker] = useState<string | null>(null);
  const [openDev, setOpenDev] = useState<string | null>(null);
  const [refreshing, setRefreshing] = useState(false);
  // Auto-reload the snapshot every 5 minutes — the collector's typical cron
  // cadence — so a wall-mounted tab tracks the fleet without a hand on Refresh.
  const [auto, setAuto] = useState<boolean>(() => {
    try {
      return localStorage.getItem("rch_dash_auto") !== "0";
    } catch {
      return true;
    }
  });
  const [query, setQuery] = useState(() => readViewPref().query);
  const [statusFilter, setStatusFilter] = useState<HealthLevel | "all">(() => readViewPref().statusFilter);
  const [sort, setSort] = useState<Sort>(() => readViewPref().sort);
  // When the current snapshot was decrypted — anchors the auto-refresh countdown.
  const [snapAt, setSnapAt] = useState<number | null>(null);

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
      envelopeRef.current = env;
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
        setSnapAt(Date.now());
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
        const env = envelopeRef.current ?? (await loadEnvelope());
        if (!env) {
          setError("No snapshot to decrypt yet.");
          return;
        }
        const key = await deriveKey(passphrase, env);
        let plain: string;
        try {
          plain = await decryptEnvelope(env, key);
        } catch (err) {
          // WebCrypto reports a GCM auth failure as OperationError — that is
          // the wrong passphrase. Any other throw (e.g. assertUsableEnvelope's
          // invalid-envelope errors) is a payload defect and deserves its real
          // message instead of a misleading accusation.
          setError(
            err instanceof Error && err.name === "OperationError"
              ? "Wrong passphrase."
              : `Could not decrypt this snapshot: ${err instanceof Error ? err.message : "unknown error"}`,
          );
          return;
        }
        setSnap(JSON.parse(plain));
        setSnapAt(Date.now());
        keyRef.current = key;
        if (remember) await persistKey(key);
      } catch (err) {
        setError((err as Error).message || "Failed to decrypt snapshot.");
      } finally {
        setBusy(false);
      }
    },
    [loadEnvelope],
  );

  const refresh = useCallback(async () => {
    setRefreshing(true);
    try {
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
        setSnapAt(Date.now());
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
    } finally {
      setRefreshing(false);
    }
  }, [loadEnvelope]);

  const toggleAuto = useCallback(() => {
    setAuto((prev) => !prev);
  }, []);

  // Persistence is an effect on the VALUE, not a side effect inside the
  // updater — updaters must stay pure (they run twice in StrictMode).
  useEffect(() => {
    try {
      localStorage.setItem("rch_dash_auto", auto ? "1" : "0");
    } catch {
      /* private mode — the toggle still applies to this session */
    }
  }, [auto]);

  // refresh lives in a ref so the interval does not re-subscribe (and drift)
  // every time a refresh lands a new snapshot. Written in an effect, never
  // during render (concurrent-unsafe).
  const refreshRef = useRef(refresh);
  useEffect(() => {
    refreshRef.current = refresh;
  }, [refresh]);

  // Persist filter/sort in the URL hash so an operator can share a link to a
  // filtered view. replaceState: no history spam per keystroke.
  useEffect(() => {
    const h = new URLSearchParams();
    if (query) h.set("q", query);
    if (statusFilter !== "all") h.set("f", statusFilter);
    if (sort !== "health") h.set("s", sort);
    const next = h.toString();
    history.replaceState(null, "", next ? `#${next}` : location.pathname + location.search);
  }, [query, statusFilter, sort]);
  const hasSnap = snap != null;
  useEffect(() => {
    if (!hasSnap || !auto) return;
    const id = setInterval(() => {
      if (document.visibilityState === "visible") void refreshRef.current();
    }, 5 * 60_000);
    return () => clearInterval(id);
  }, [hasSnap, auto]);

  const lock = useCallback(() => {
    clearKey();
    keyRef.current = null;
    setSnap(null);
    setSnapAt(null);
    setNotice(null);
  }, []);

  // Global operator shortcuts when unlocked and drawers are closed:
  // '/' -> focus worker search, 'r' -> refresh, 't' -> toggle theme, '1'-'6' -> status filters
  useEffect(() => {
    if (!snap) return;
    const handleKeyDown = (e: KeyboardEvent) => {
      if (e.metaKey || e.ctrlKey || e.altKey) return;
      const activeTag = (document.activeElement?.tagName ?? "").toLowerCase();
      const isInputActive = activeTag === "input" || activeTag === "textarea" || activeTag === "select";
      if (isInputActive) return;
      if (openWorker || openDev) return;

      if (e.key === "/") {
        e.preventDefault();
        const input = document.getElementById("worker-search-input");
        if (input) {
          (input as HTMLInputElement).focus();
          (input as HTMLInputElement).select();
        }
      } else if (e.key === "r" || e.key === "R") {
        e.preventDefault();
        void refreshRef.current();
      } else if (e.key === "t" || e.key === "T") {
        e.preventDefault();
        setTheme((prev) => (prev === "dark" ? "light" : "dark"));
      } else if (e.key === "1") {
        setStatusFilter("all");
      } else if (e.key === "2") {
        setStatusFilter("critical");
      } else if (e.key === "3") {
        setStatusFilter("warn");
      } else if (e.key === "4") {
        setStatusFilter("offline");
      } else if (e.key === "5") {
        setStatusFilter("busy");
      } else if (e.key === "6") {
        setStatusFilter("healthy");
      }
    };
    window.addEventListener("keydown", handleKeyDown);
    return () => window.removeEventListener("keydown", handleKeyDown);
  }, [snap, openWorker, openDev, setTheme]);

  // Cross-links: opening one entity closes the other drawer so the two native
  // dialogs never stack.
  const openWorkerFrom = useCallback((id: string) => {
    setOpenDev(null);
    setOpenWorker(id);
  }, []);
  const openDevFrom = useCallback((id: string) => {
    setOpenWorker(null);
    setOpenDev(id);
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

  // Worker ids for dev-drawer cross-links. Must live ABOVE the `if (!snap)`
  // early return — hooks cannot be conditional.
  const fleetWorkerIds = useMemo(() => new Set(workers.map((w) => w.id)), [workers]);

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

  const ageSec = (now - new Date(snap.generated_at).getTime()) / 1000;
  const hardProblems = devs.filter((d) => d.level === "local-only" || d.level === "unreachable");
  const degradedDevs = devs.filter((d) => d.level === "degraded");
  // Minutes until the next auto-refresh, for the header countdown. Anchored to
  // when the current snapshot was decrypted, so it survives re-unlocks.
  const autoInMin =
    auto && snapAt != null
      ? Math.max(0, Math.ceil((snapAt + 5 * 60_000 - now) / 60_000))
      : null;
  const snapshotMs = new Date(snap.generated_at).getTime();

  return (
    <div className="shell">
      <Topbar
        label={snap.label}
        ageSec={ageSec}
        refreshing={refreshing}
        onRefresh={() => void refresh()}
        auto={auto}
        autoInMin={autoInMin}
        onToggleAuto={toggleAuto}
        theme={theme}
        onToggleTheme={() => setTheme(theme === "dark" ? "light" : "dark")}
        onLock={lock}
      />

      {notice && <div className="banner">{notice}</div>}

      {ageSec > STALE_CRIT_SECONDS && (
        <div className="banner">
          This snapshot is {fmtAge(ageSec)} old — it may no longer reflect the fleet.
          Re-run <code>npm run snapshot</code>.
        </div>
      )}

      {hardProblems.length > 0 && (
        <div className="banner crit">
          {hardProblems.length} dev machine{hardProblems.length === 1 ? "" : "s"} not offloading:{" "}
          {hardProblems.map((d) => d.id).join(", ")}. Builds there are running locally, or the box
          cannot be reached.
        </div>
      )}

      {degradedDevs.length > 0 && (
        <div className="banner">
          {degradedDevs.length} dev machine{degradedDevs.length === 1 ? "" : "s"} in a degraded
          posture (partial remote capability — some workers pressure-blocked or unavailable):{" "}
          {degradedDevs.map((d) => d.id).join(", ")}.
        </div>
      )}

      <Overview snap={snap} counts={counts} hardProblems={hardProblems.length} />

      <section className="section">
        <div className="section-head">
          <h2>Dev machines</h2>
          <span className="count-pill">{devs.length}</span>
          <span className="spacer" />
          <span className="hint-inline">boxes that run rch and dispatch builds to the pool</span>
        </div>
        {devs.length === 0 ? (
          <div className="empty">No dev machines configured.</div>
        ) : (
          <div className="grid">
            {devs.map((d) => (
              <DevMachineCard key={d.id} d={d} onOpen={setOpenDev} />
            ))}
          </div>
        )}
      </section>

      <WorkersSection
        visible={visible}
        total={workers.length}
        counts={counts}
        query={query}
        onQuery={setQuery}
        statusFilter={statusFilter}
        onStatusFilter={setStatusFilter}
        sort={sort}
        onSort={setSort}
        onOpen={setOpenWorker}
      />

      <footer className="footer">
        <span>schema {snap.schema}</span>
        <span>generated {new Date(snap.generated_at).toLocaleString()}</span>
        <span>decrypted locally · AES-256-GCM</span>
      </footer>

      <WorkerDrawer
        w={workers.find((w) => w.id === openWorker) ?? null}
        onClose={() => setOpenWorker(null)}
        onOpenDev={openDevFrom}
      />
      <DevMachineDrawer
        d={devs.find((d) => d.id === openDev) ?? null}
        snapshotMs={snapshotMs}
        onClose={() => setOpenDev(null)}
        onOpenWorker={openWorkerFrom}
        fleetWorkerIds={fleetWorkerIds}
      />
    </div>
  );
}
