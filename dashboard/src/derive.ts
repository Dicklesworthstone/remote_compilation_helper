import type {
  ActiveBuild, ActiveBuildTuple, Alert, AlertTuple,
  BuildTuple, Dispatcher, DispatcherView, DispatcherWorkerSlots, DevLevel, HealthLevel,
  HintTuple, InternedString, Issue, IssueTuple, QueuedBuild, QueuedBuildTuple,
  RecentBuild, RemediationHint, Snapshot, Worker, WorkerSlotPair,
  WorkerView,
} from "./types";

/** Snapshots older than this are called out — stale data is worse than none. */
export const STALE_WARN_SECONDS = 15 * 60;
export const STALE_CRIT_SECONDS = 60 * 60;

export function fmtGb(gb: number | null | undefined, digits = 0): string {
  if (gb == null || !Number.isFinite(gb)) return "—";
  if (gb >= 1024) return `${(gb / 1024).toFixed(digits === 0 ? 1 : digits)} TB`;
  return `${gb.toFixed(digits)} GB`;
}

export function fmtAge(seconds: number | null): string {
  if (seconds == null || !Number.isFinite(seconds)) return "—";
  const s = Math.max(0, Math.round(seconds));
  if (s < 60) return `${s}s ago`;
  if (s < 3600) return `${Math.round(s / 60)}m ago`;
  if (s < 86400) return `${Math.round(s / 3600)}h ago`;
  return `${Math.round(s / 86400)}d ago`;
}

export function fmtUptime(seconds: number | null): string {
  if (seconds == null || !Number.isFinite(seconds)) return "—";
  const d = Math.floor(seconds / 86400);
  const h = Math.floor((seconds % 86400) / 3600);
  const m = Math.floor((seconds % 3600) / 60);
  if (d > 0) return `${d}d ${h}h`;
  if (h > 0) return `${h}h ${m}m`;
  return `${m}m`;
}

export function fmtDuration(ms: number | null): string {
  if (ms == null || !Number.isFinite(ms)) return "—";
  if (ms < 1000) return `${Math.round(ms)}ms`;
  if (ms < 60_000) return `${(ms / 1000).toFixed(1)}s`;
  return `${Math.round(ms / 60_000)}m`;
}

/**
 * Fold raw worker facts into one status.
 *
 * Order is deliberate. "We cannot reach it" outranks a stale disk reading,
 * because reachability is the more actionable fact. Disk outranks load: a full
 * disk takes a worker down hard, while high load is usually just work happening.
 */
/**
 * @param snapshotMs when the snapshot was TAKEN — not the reader's clock.
 *
 * Worker "last seen" must be judged against snapshot time. Using the browser's
 * clock made every worker in a two-hour-old snapshot report "offline", because
 * the snapshot's own age was being charged to each worker. Snapshot staleness
 * is surfaced separately by the header indicator and the stale banner.
 */
export function classify(w: Worker, snapshotMs: number): WorkerView {
  const p = w.pressure;
  const diskUsedPct =
    p.disk_total_gb && p.disk_free_gb != null && p.disk_total_gb > 0
      ? ((p.disk_total_gb - p.disk_free_gb) / p.disk_total_gb) * 100
      : null;
  const loadPerCore =
    w.caps.load_avg_1 != null && w.caps.num_cpus ? w.caps.load_avg_1 / w.caps.num_cpus : null;
  const staleSeconds = w.last_seen_unix != null ? snapshotMs / 1000 - w.last_seen_unix : null;
  const slotPct =
    w.total_slots && w.total_slots > 0 ? ((w.used_slots ?? 0) / w.total_slots) * 100 : null;

  const st = (w.status ?? "").toLowerCase();
  let health: HealthLevel = "healthy";
  let healthReason = "healthy";

  // A pressure event does not always carry a disk number (memory pressure, or a
  // telemetry gap). Falling back to the raw percentage unconditionally rendered
  // the literal string "disk undefined% full" on those workers.
  const pressureReason = (fallback: string) =>
    p.reason
      ? `pressure: ${p.reason}`
      : diskUsedPct != null
        ? `disk ${diskUsedPct.toFixed(0)}% full`
        : fallback;

  if (st === "disabled") {
    health = "disabled";
    healthReason = "manually disabled";
  } else if (st === "down" || st === "unreachable" || w.circuit_state === "open") {
    health = "offline";
    healthReason = w.circuit_state === "open" ? "circuit breaker open" : `worker ${st || "unreachable"}`;
  } else if (staleSeconds != null && staleSeconds > STALE_CRIT_SECONDS) {
    health = "offline";
    healthReason = `not seen for ${Math.round(staleSeconds / 60)}m`;
  } else if (p.state === "critical" || (diskUsedPct != null && diskUsedPct >= 95)) {
    health = "critical";
    healthReason = pressureReason("critical pressure");
  } else if (st === "draining") {
    health = "warn";
    healthReason = "draining (finishing current jobs)";
  } else if (st === "drained") {
    // Terminal state of a drain: idle and accepting nothing. It looks identical
    // to a healthy idle worker on every other surface, which is the trap.
    health = "warn";
    healthReason = "drained — accepting no new jobs";
  } else if (p.state === "warning" || (diskUsedPct != null && diskUsedPct >= 88)) {
    health = "warn";
    healthReason = pressureReason("pressure warning");
  } else if (p.state === "telemetry_gap") {
    // rch's own fourth pressure state. Treating it as healthy meant "I have no
    // idea how this worker is doing" rendered green.
    health = "warn";
    healthReason = p.reason ? `pressure: ${p.reason}` : "no pressure telemetry";
  } else if (st === "degraded") {
    health = "warn";
    healthReason = "worker responding slowly";
  } else if (w.consecutive_failures > 0) {
    health = "warn";
    healthReason = `${w.consecutive_failures} consecutive failure${w.consecutive_failures === 1 ? "" : "s"}`;
  } else if (loadPerCore != null && loadPerCore >= 2) {
    health = "warn";
    healthReason = `load ${loadPerCore.toFixed(1)}x cores`;
  } else if (w.circuit_state === "half_open") {
    health = "warn";
    healthReason = "circuit half-open (probing)";
  } else if (w.caps.projects_root_ok === false) {
    // Must precede the `busy` branch: a busy worker with a broken projects root
    // is still broken, and this check used to be unreachable whenever a build
    // was running — exactly when it matters.
    health = "warn";
    healthReason = "projects root unhealthy";
  } else if (p.telemetry_fresh === false) {
    // Everything above says healthy, but the readings behind that verdict are
    // stale. Report the uncertainty rather than the conclusion.
    health = "warn";
    healthReason =
      p.telemetry_age_secs != null
        ? `telemetry ${fmtAge(p.telemetry_age_secs).replace(" ago", "")} old`
        : "telemetry stale";
  } else if ((w.used_slots ?? 0) > 0) {
    health = "busy";
    healthReason = `${w.used_slots}/${w.total_slots} slots in use`;
  }

  return { ...w, health, healthReason, diskUsedPct, loadPerCore, staleSeconds, slotPct };
}

/**
 * Give each worker view its `seen_by` / `slots_by_dispatcher`, read off the
 * wire matrix by COLUMN.
 *
 * `Dispatcher.pool_slots` is one ROW of the (dispatcher x worker) derated-slot
 * matrix, aligned to `snap.workers`. These two per-worker fields are the same
 * matrix read the other way, and they used to be transmitted alongside the
 * rows — three encodings of one structure, ~50 bytes per cell to carry ~8 bytes
 * of fact, on the only thing in this snapshot whose size is the PRODUCT of both
 * fleet counts. `tools/scaling.mjs` measured that at 91% of a 500-machine
 * payload. See `projectDispatchers()` in tools/snapshot.mjs.
 *
 * ORDER IS THE CONTRACT, and it is preserved exactly. The collector built
 * `seen_by` by iterating dispatchers outermost; so does this, so the array
 * order and the object key order are what the old payload carried, element for
 * element.
 *
 * WHY `seen_by` IS EAGER AND `slots_by_dispatcher` IS NOT. Both are columns of
 * the same matrix, so building both costs one object per CELL: 75ms at 500
 * dispatchers, of which 66ms is `slots_by_dispatcher` alone. But every card on
 * screen reads `seen_by.length`, while `slots_by_dispatcher` is read by the
 * worker drawer, for the ONE worker that is open — usually none. So the array
 * is built for every worker and the record is built on first touch, cached in
 * place by replacing the accessor with the value. Enumerable and configurable,
 * so it survives a spread, `Object.keys`, `Object.entries` and
 * `JSON.stringify`: nothing downstream can tell it apart from a plain field.
 *
 * Mutates the VIEWS, never `snap`: `Snapshot` is React state, and a hook that
 * rewrites its own input is a re-render hazard. A snapshot that already carries
 * `seen_by` — one written before the matrix was de-duplicated — is left
 * completely alone, because its `worker_slots` are positional against a
 * DIFFERENT index space and deriving columns from them would attribute
 * readings to the wrong machines.
 */
function attachSlotColumns(snap: Snapshot, views: WorkerView[]): void {
  const dispatchers = snap?.dispatchers;
  if (!Array.isArray(dispatchers) || dispatchers.length === 0) return;
  if (views.some((v) => Array.isArray(v.seen_by))) return;

  const seenBy: (string[] | undefined)[] = new Array(views.length);
  for (const d of dispatchers) {
    const row = d?.pool_slots;
    if (!Array.isArray(row)) continue;
    const end = Math.min(row.length, views.length);
    for (let i = 0; i < end; i++) {
      // Only a real `[used, total]` counts as "seen". A null, a hole from a
      // trimmed row, or anything ragged means this machine said nothing about
      // this worker — which must never be read as a zero-slot reading, because
      // zero slots is the alarm this panel exists to raise.
      if (!Array.isArray(row[i])) continue;
      (seenBy[i] ??= []).push(d.id);
    }
  }

  for (let i = 0; i < views.length; i++) {
    const ids = seenBy[i];
    // No dispatcher reported this worker: leave both fields absent rather than
    // empty, so the card and the drawer hide their panels exactly as they did
    // when the collector omitted them.
    if (!ids) continue;
    const view = views[i];
    view.seen_by = ids;
    Object.defineProperty(view, "slots_by_dispatcher", {
      configurable: true,
      enumerable: true,
      get() {
        const built: Record<string, { used: number | null; total: number | null }> = {};
        for (const d of dispatchers) {
          const pair = d?.pool_slots?.[i];
          if (!Array.isArray(pair)) continue;
          built[d.id] = { used: pair[0] ?? null, total: pair[1] ?? null };
        }
        Object.defineProperty(view, "slots_by_dispatcher", {
          value: built, writable: true, configurable: true, enumerable: true,
        });
        return built;
      },
    });
  }
}

export function classifyAll(snap: Snapshot, _nowMs?: number): WorkerView[] {
  // Deliberately ignores the caller's clock — see classify().
  const snapshotMs = new Date(snap.generated_at).getTime();
  const views = snap.workers.map((w) => classify(w, snapshotMs));
  attachSlotColumns(snap, views);
  return views;
}

/**
 * Expand the wire form of a dev machine's derated slot view.
 *
 * The collector emits `[used, total]` pairs rather than a worker record per
 * dispatcher: at 142 pairs on a 10-machine fleet the duplicated records were
 * 54.6% of the whole snapshot and held nothing the merged `Snapshot.workers`
 * did not already carry. Only the slot readings are per-dispatcher, and the
 * dev-machine drawer only ever sums them and counts the zeroes.
 *
 * Two wire forms, and the difference is the INDEX SPACE, not the values:
 *   `pool_slots`   one row of the fleet matrix, aligned to `Snapshot.workers`,
 *                  with `null` where this machine does not have that worker.
 *   `worker_slots` the older dense form, positional against this dispatcher's
 *                  own worker order. Still read so an already-published
 *                  snapshot keeps its pool panel; never written any more.
 * Both collapse to the same records here, because the only consumer — the
 * dev-machine drawer — sums the pairs and counts the zeroes, and neither
 * answer depends on the order.
 *
 * A `null` is DROPPED, never expanded into `{used: null, total: null}`. "This
 * machine has no such worker" and "this machine has derated it to zero" are
 * opposite facts, and the second one is the alarm the drawer exists to raise.
 *
 * Tolerant of a missing or ragged array on purpose: a browser tab can be
 * holding a snapshot written by an older collector, and a dev machine with no
 * pool view must render as "0 workers seen", never crash the drawer.
 */
function expandWorkerSlots(d: Dispatcher | undefined): DispatcherWorkerSlots[] {
  const row: readonly (WorkerSlotPair | null)[] | undefined =
    (Array.isArray(d?.pool_slots) ? d.pool_slots : undefined) ??
    (Array.isArray(d?.worker_slots) ? d.worker_slots : undefined);
  if (!row) return [];
  const out: DispatcherWorkerSlots[] = [];
  for (const p of row) {
    if (!Array.isArray(p)) continue;
    out.push({
      // `?? null` and not `|| null`: 0 used slots and 0 total slots are the two
      // most interesting readings here — a worker derated to 0 is invisible to
      // this machine, which is the whole reason the drawer shows this.
      used_slots: p[0] ?? null,
      total_slots: p[1] ?? null,
    });
  }
  return out;
}

/**
 * Which tuple slots carry an interned string. THE schema of the string table —
 * mirrored by `INTERNED_BUILD_SLOTS`/`INTERNED_HINT_SLOTS` in
 * `tools/snapshot.mjs` and by the index constants in `tools/llm-view.mjs`.
 * `builds[2]` (location) and `hints[1]` (severity) are absent on purpose; see
 * the collector for why.
 */
const INTERNED_BUILD_SLOTS = [0, 1, 3] as const;
const INTERNED_HINT_SLOTS = [0, 2, 3, 4] as const;

/**
 * Resolve one possibly-interned wire slot against the snapshot's string table.
 *
 * A `number` is an index; anything else is already the value. That dispatch is
 * what makes the change safe in BOTH directions of version skew: a snapshot
 * written before the table existed carries plain strings in these slots and is
 * returned untouched, with no key rename and no data loss.
 *
 * `?? null` and never `|| null`, and an out-of-range index yields `null` rather
 * than `undefined`, so a truncated table degrades to "no message" instead of
 * rendering the string "undefined".
 */
function internedStr(v: InternedString | undefined, strings?: readonly string[]): string | null {
  if (typeof v === "number") return strings?.[v] ?? null;
  return v ?? null;
}

/**
 * Put the interned strings back into a decrypted snapshot, in place.
 *
 * Called at the transport boundary (`decryptEnvelope()` in src/crypto.ts)
 * rather than inside `classifyDispatcher()`, because the table is a property of
 * the SNAPSHOT and `classifyDispatcher()` is handed one dispatcher at a time —
 * `App.tsx` calls it as `snap.dispatchers.map(classifyDispatcher)`, so there is
 * no argument through which the table could reach it. Undoing the encoding once
 * where the payload arrives keeps every consumer downstream unaware of it.
 *
 * Idempotent: a second call finds strings where the indices were and leaves
 * them alone. A snapshot with no table is returned untouched.
 */
export function rehydrateStrings(snap: Snapshot): Snapshot {
  const strings = snap?.strings;
  if (!Array.isArray(strings) || strings.length === 0) return snap;
  const resolve = (v: InternedString): InternedString =>
    typeof v === "number" ? (strings[v] ?? null) : v;
  for (const d of snap.dispatchers ?? []) {
    if (Array.isArray(d?.builds)) {
      for (const b of d.builds) {
        if (!Array.isArray(b)) continue;
        for (const i of INTERNED_BUILD_SLOTS) b[i] = resolve(b[i]);
      }
    }
    if (Array.isArray(d?.hints)) {
      for (const h of d.hints) {
        if (!Array.isArray(h)) continue;
        for (const i of INTERNED_HINT_SLOTS) h[i] = resolve(h[i]);
      }
    }
  }
  return snap;
}

/**
 * Expand the wire form of a dev machine's recent builds.
 *
 * The collector ships `[project, command, location, worker_id, duration_ms,
 * exit_code, completed_at]` rather than an object per build: all seven values
 * are consumed, but at 121 records on a 10-machine fleet the repeated key names
 * alone were 10.2KB of a 92.3KB payload. Positions are the contract — keep this
 * in step with `tools/snapshot.mjs` and the mirror in `tools/llm-view.mjs`.
 *
 * Tolerant of a missing or ragged array on purpose: a browser tab can be holding
 * a snapshot written by an older collector, and a dev machine with no build
 * history must render "no builds recorded", never crash the drawer.
 */
export function expandBuilds(rows: BuildTuple[] | undefined, strings?: readonly string[]): RecentBuild[] {
  if (!Array.isArray(rows)) return [];
  return rows.map((b) => ({
    // `?? null` throughout, never `|| null`: `duration_ms: 0` and the
    // all-important `exit_code: 0` (the build SUCCEEDED) are real readings.
    // Slots 0, 1 and 3 go through `internedStr` — see INTERNED_BUILD_SLOTS.
    project: Array.isArray(b) ? internedStr(b[0], strings) : null,
    command: Array.isArray(b) ? internedStr(b[1], strings) : null,
    location: Array.isArray(b) ? (b[2] ?? null) : null,
    worker_id: Array.isArray(b) ? internedStr(b[3], strings) : null,
    duration_ms: Array.isArray(b) ? (b[4] ?? null) : null,
    exit_code: Array.isArray(b) ? (b[5] ?? null) : null,
    completed_at: Array.isArray(b) ? (b[6] ?? null) : null,
  }));
}

/**
 * Expand the wire form of a dev machine's remediation hints:
 * `[worker_id, severity, message, suggested_action, reason_code]`.
 * Same reasoning and the same legacy tolerance as `expandBuilds()`.
 */
export function expandHints(rows: HintTuple[] | undefined, strings?: readonly string[]): RemediationHint[] {
  if (!Array.isArray(rows)) return [];
  return rows.map((h) => ({
    // Everything but `severity` is interned — see INTERNED_HINT_SLOTS.
    worker_id: Array.isArray(h) ? internedStr(h[0], strings) : null,
    severity: Array.isArray(h) ? (h[1] ?? null) : null,
    message: Array.isArray(h) ? internedStr(h[2], strings) : null,
    suggested_action: Array.isArray(h) ? internedStr(h[3], strings) : null,
    reason_code: Array.isArray(h) ? internedStr(h[4], strings) : null,
  }));
}

/**
 * Expanders for the tuples re-added alongside `alerts`/`issues` and the
 * detailed active/queued build lists. None of these slots are interned. All
 * four tolerate a snapshot that predates them (`undefined` -> `[]`) and a
 * ragged row (`?? null`, never `|| null`, so `0` and `false` survive).
 * Mirrored in tools/llm-view.mjs; tests/parity.mjs compares the two.
 */
export function expandAlerts(rows: AlertTuple[] | undefined): Alert[] {
  if (!Array.isArray(rows)) return [];
  return rows.map((a) => ({
    kind: Array.isArray(a) ? (a[0] ?? null) : null,
    severity: Array.isArray(a) ? (a[1] ?? null) : null,
    worker_id: Array.isArray(a) ? (a[2] ?? null) : null,
    message: Array.isArray(a) ? (a[3] ?? null) : null,
    first_seen: Array.isArray(a) ? (a[4] ?? null) : null,
    last_seen: Array.isArray(a) ? (a[5] ?? null) : null,
    state: Array.isArray(a) ? (a[6] ?? null) : null,
  }));
}

export function expandIssues(rows: IssueTuple[] | undefined): Issue[] {
  if (!Array.isArray(rows)) return [];
  return rows.map((i) => ({
    severity: Array.isArray(i) ? (i[0] ?? null) : null,
    summary: Array.isArray(i) ? (i[1] ?? null) : null,
    remediation: Array.isArray(i) ? (i[2] ?? null) : null,
  }));
}

export function expandActive(rows: ActiveBuildTuple[] | undefined): ActiveBuild[] {
  if (!Array.isArray(rows)) return [];
  return rows.map((b) => ({
    id: Array.isArray(b) ? (b[0] ?? null) : null,
    project: Array.isArray(b) ? (b[1] ?? null) : null,
    worker_id: Array.isArray(b) ? (b[2] ?? null) : null,
    command: Array.isArray(b) ? (b[3] ?? null) : null,
    started_at: Array.isArray(b) ? (b[4] ?? null) : null,
    heartbeat_age_secs: Array.isArray(b) ? (b[5] ?? null) : null,
    progress_age_secs: Array.isArray(b) ? (b[6] ?? null) : null,
    phase: Array.isArray(b) ? (b[7] ?? null) : null,
    hook_alive: Array.isArray(b) ? (b[8] ?? null) : null,
    heartbeat_stale: Array.isArray(b) ? (b[9] ?? null) : null,
    progress_stale: Array.isArray(b) ? (b[10] ?? null) : null,
    confidence: Array.isArray(b) ? (b[11] ?? null) : null,
    slots: Array.isArray(b) ? (b[12] ?? null) : null,
    build_age_secs: Array.isArray(b) ? (b[13] ?? null) : null,
  }));
}

export function expandQueued(rows: QueuedBuildTuple[] | undefined): QueuedBuild[] {
  if (!Array.isArray(rows)) return [];
  return rows.map((q) => ({
    id: Array.isArray(q) ? (q[0] ?? null) : null,
    project: Array.isArray(q) ? (q[1] ?? null) : null,
    command: Array.isArray(q) ? (q[2] ?? null) : null,
    position: Array.isArray(q) ? (q[3] ?? null) : null,
    slots_needed: Array.isArray(q) ? (q[4] ?? null) : null,
    wait_time: Array.isArray(q) ? (q[5] ?? null) : null,
  }));
}

/**
 * Classify a DEV MACHINE by the question that actually matters: are its builds
 * going to the worker pool, or is it quietly compiling locally?
 *
 * `local-only` is the loud one, and it is why this dashboard exists: a
 * dispatcher whose workers all fall below its `build_slots` estimate silently
 * compiles everything on itself while `rch queue`, worker probes and every
 * other surface still report a healthy fleet.
 */
/**
 * @param strings the snapshot's string table, when the caller has one.
 *
 * Typed `unknown` and guarded rather than `string[]`, because the browser calls
 * this as `snap.dispatchers.map(classifyDispatcher)` — `Array.prototype.map`
 * passes the ELEMENT INDEX as the second argument, and a number quietly
 * standing in for the table would resolve every interned slot to null. The
 * browser path does not need it (src/crypto.ts rehydrates at the transport
 * boundary); direct callers such as tools and tests pass it explicitly.
 */
export function classifyDispatcher(d: Dispatcher, strings?: unknown): DispatcherView {
  const table: readonly string[] | undefined = Array.isArray(strings)
    ? (strings as readonly string[])
    : undefined;
  // `build_stats` is CUMULATIVE since the daemon started, so it is the wrong
  // basis for a "is this box offloading right now" verdict: a machine that did
  // 200 local builds last month stays branded local-only through a week of
  // perfect offloading, and one that broke this morning takes weeks to cross
  // the threshold. `builds` is the actual recent window, so prefer it and fall
  // back to the lifetime counters only when it is empty. Every build in the
  // window counts, not a display slice: the verdict must be measured over what
  // the collector observed.
  const s = d.build_stats;
  const recent = expandBuilds(d.builds, table);
  const recentCounted = recent.length;
  const recentRemote = recent.filter((b) => (b.location ?? "").toLowerCase() === "remote").length;

  const lifetimeCounted = s ? s.remote + s.local : 0;
  const basis: "recent" | "lifetime" | null =
    recentCounted > 0 ? "recent" : lifetimeCounted > 0 ? "lifetime" : null;

  const remotePct =
    basis === "recent"
      ? (recentRemote / recentCounted) * 100
      : basis === "lifetime"
        ? (s!.remote / lifetimeCounted) * 100
        : null;

  const window = basis === "recent" ? `last ${recentCounted} builds` : "all builds since daemon start";

  let level: DevLevel;
  let levelReason: string;

  if (!d.reachable) {
    level = "unreachable";
    // Say WHICH failure: an ssh refusal, a missing binary and a dead daemon
    // used to collapse into one string, and they have three different fixes.
    const first = Array.isArray(d.collection_errors) ? d.collection_errors[0] : undefined;
    levelReason = first ? `no response from rch — ${first}` : "no response from rch";
  } else if (d.posture && d.posture !== "remote_ready") {
    level = d.posture.includes("local") ? "local-only" : "degraded";
    levelReason = d.posture_description ?? d.posture;
  } else if (remotePct != null && remotePct < 50) {
    level = "local-only";
    levelReason = `only ${remotePct.toFixed(0)}% of the ${window} went remote`;
  } else if (basis === null) {
    level = "idle";
    levelReason = "no builds recorded yet";
  } else {
    level = "offloading";
    levelReason = `${remotePct!.toFixed(0)}% of the ${window} went to the pool`;
  }

  return {
    ...d,
    workers: expandWorkerSlots(d),
    // Expanded once here, not per component: the drawer renders these rows and
    // the card counts the hints, and both must see exactly the objects the
    // collector used to send.
    recent_builds: recent,
    remediation_hints: expandHints(d.hints, table),
    alert_records: expandAlerts(d.alerts),
    issue_records: expandIssues(d.issues),
    active_records: expandActive(d.active),
    queued_records: expandQueued(d.queued),
    level, levelReason, remotePct, remoteBasis: basis,
    remoteCounted: recentCounted || lifetimeCounted,
  };
}

/**
 * Sort order, most urgent first. `offline` outranks `warn`: a worker we cannot
 * reach at all is a bigger problem than one with a single transient probe
 * failure. `disabled` sorts last — it is an intended state, not a fault.
 */
export const HEALTH_ORDER: HealthLevel[] = ["critical", "offline", "warn", "busy", "healthy", "disabled"];

export function healthRank(h: HealthLevel): number {
  const i = HEALTH_ORDER.indexOf(h);
  return i === -1 ? HEALTH_ORDER.length : i;
}

export const DEV_ORDER: DevLevel[] = ["unreachable", "local-only", "degraded", "offloading", "idle"];
export function devRank(l: DevLevel): number {
  const i = DEV_ORDER.indexOf(l);
  return i === -1 ? DEV_ORDER.length : i;
}

/** Bar colour class for a 0-100 utilisation value. */
export function utilClass(pct: number | null): string {
  if (pct == null) return "off";
  if (pct >= 95) return "crit";
  if (pct >= 88) return "warn";
  return "ok";
}
