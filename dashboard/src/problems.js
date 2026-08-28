/**
 * Fleet problems, derived ONCE and consumed everywhere.
 *
 * Plain JavaScript on purpose: this file is imported by the browser bundle
 * (`src/App.tsx`, via the sibling `problems.d.ts`) AND by `tools/llm-view.mjs`
 * (the `/api/fleet` function and the `npm run llm` CLI). The health/posture
 * classifiers are still duplicated between `src/derive.ts` and
 * `tools/llm-view.mjs` for historical reasons and kept in step by
 * `tests/parity.mjs`; everything built ON TOP of those verdicts lives here so a
 * problem an agent is told about is, by construction, the same problem an
 * operator sees on screen.
 *
 * The shape is written for an agent that reads nothing else:
 *
 *   severity  critical | warn         critical = builds are (or will be) landing
 *                                     locally, or capacity is silently gone
 *   kind      dotted, stable          branch on it: `dev.*` is a dev machine
 *                                     problem, `worker.*` a worker problem,
 *                                     `build.*` a hung build, `fleet.*` a
 *                                     fleet-wide root cause, `snapshot.*` this
 *                                     feed itself
 *   target    machine / worker / build id
 *   detail    one line, human and machine readable
 *   since     ISO time the daemon first raised it, when known ("" otherwise)
 *   action    the command to run to fix or confirm it ("" when none)
 *   on        WHERE to run `action`: a dev machine id, "collector" (the box that
 *             runs the snapshot), or "" when the action is informational
 *
 * Every field is always present (strings, never null) so the TOON tabular
 * encoding stays a fixed-width table and a consumer can index by column.
 */

export const SEVERITY_RANK = { critical: 0, warn: 1, info: 2 };

/**
 * Catalogue of every `kind` this module can emit, with what it means and what
 * fixes it. Served verbatim by `/api/fleet?view=help` so an agent can learn the
 * vocabulary from the endpoint itself instead of from this file.
 */
export const PROBLEM_KINDS = {
  "snapshot.stale": {
    severity: "critical",
    meaning: "This feed is over an hour old; nothing below can be trusted as current.",
    fix: "Re-run the collector on the box that publishes the dashboard.",
  },
  "snapshot.timestamp_unreadable": {
    severity: "critical",
    meaning: "The snapshot's generated_at is not a valid timestamp; treat the feed as untrusted.",
    fix: "Inspect the collector output; republish.",
  },
  "fleet.degraded": {
    severity: "warn",
    meaning: "Two or more dev machines report partial remote capability for the SAME worker-side reason. One root cause, not N machine problems — fix the listed workers.",
    fix: "Act on the worker.* rows; the dev machines recover on their own.",
  },
  "dev.unreachable": {
    severity: "critical",
    meaning: "The collector could not get `rch status` from this dev machine (ssh failed, rch missing, or rchd down). Its builds may be running locally with nobody watching.",
    fix: "`ssh <id> true` if the transport failed; otherwise `rch daemon start` on the box.",
  },
  "dev.local-only": {
    severity: "critical",
    meaning: "This dev machine is compiling on itself: posture local_only, or under half of its recent builds went to the pool.",
    fix: "`rch doctor` on the box, then act on what it names.",
  },
  "dev.degraded": {
    severity: "warn",
    meaning: "This dev machine sees partial remote capability (some workers unavailable or pressure-blocked) for a reason not shared fleet-wide.",
    fix: "Read its remediation hints (`rch status --json` on the box).",
  },
  "dev.hook_missing": {
    severity: "critical",
    meaning: "Claude Code's PreToolUse hook is NOT installed on this dev machine, so nothing is intercepted and every agent build there runs locally.",
    fix: "`rch hook install` on the box.",
  },
  "dev.shim_missing": {
    severity: "warn",
    meaning: "The cargo shim is not installed, so builds started by scripts/Makefiles (not via a hooked tool call) run locally.",
    fix: "`rch shim install` on the box.",
  },
  "dev.shim_stale": {
    severity: "warn",
    meaning: "The cargo shim is installed but out of date or shadowed by another cargo on PATH.",
    fix: "`rch shim install` on the box (re-installs and re-orders PATH).",
  },
  "dev.unmanaged_local_builds": {
    severity: "critical",
    meaning: "Compiler processes are running on this dev machine RIGHT NOW with no rch ancestor — builds the hook/shim never saw. This is the 'silently burning local cores' failure.",
    fix: "`rch shim status --json` on the box to list them; check the hook and shim rows for the same machine.",
  },
  "dev.daemon_version_skew": {
    severity: "warn",
    meaning: "This dev machine runs a different rch version from the rest of the fleet.",
    fix: "`rch update` on the box (or `rch update --fleet` from any box).",
  },
  "dev.doctor_failed": {
    severity: "critical",
    meaning: "`rch doctor` reports FAILED checks on this dev machine (hook, daemon socket, config, SSH keys...).",
    fix: "`rch doctor --fix` when a failing check is fixable; otherwise `rch doctor` and read the message.",
  },
  "dev.doctor_warnings": {
    severity: "warn",
    meaning: "`rch doctor` reports warnings on this dev machine.",
    fix: "`rch doctor` on the box.",
  },
  "dev.collection_error": {
    severity: "warn",
    meaning: "The box answered `rch status` but one of the other probes failed (metrics endpoint, workers list, doctor, shim, hook). Some columns for this machine are UNKNOWN, not fine.",
    fix: "`rch doctor` on the box; the detail names the probe that failed.",
  },
  "worker.offline": {
    severity: "critical",
    meaning: "Worker unreachable, circuit breaker open, or not seen for over an hour. Its slots are gone from every dev machine.",
    fix: "`rch workers probe <id>` from a dev machine; the action column carries rch's own advice when it has one.",
  },
  "worker.critical": {
    severity: "critical",
    meaning: "Critical pressure (disk ≥95% or the daemon's pressure policy fired). Admission is refused; every dev machine derates it to 0 slots.",
    fix: "Free disk on the worker (`rch gc --workers <id>`, `rch cache clean --workers <id>`), then `rch workers capabilities --refresh`.",
  },
  "worker.warn": {
    severity: "warn",
    meaning: "Pressure warning, disk ≥88%, load ≥2× cores, recent failures, half-open circuit, drained, or stale telemetry.",
    fix: "See the action column; usually disk reclaim or wait for the next telemetry poll.",
  },
  "worker.convergence_drift": {
    severity: "warn",
    meaning: "This worker is missing repositories that a dev machine's builds depend on (repo convergence not ready).",
    fix: "`rch doctor --reliability` on the dev machine that reported it.",
  },
  "build.hook_dead": {
    severity: "critical",
    meaning: "An active build's dispatching hook process is gone. The build cannot complete and its slots stay reserved until cancelled.",
    fix: "`rch cancel <build id>` on the dev machine that owns it.",
  },
  "build.stalled": {
    severity: "warn",
    meaning: "An active build has stopped heartbeating and progressing, or has made no progress for 30+ minutes with the daemon's stall detector fairly confident.",
    fix: "`rch queue --json` on the owning dev machine to confirm; `rch cancel <build id>` if it is genuinely hung.",
  },
};

const s = (v) => (v == null ? "" : String(v));

function row(severity, kind, target, detail, extra = {}) {
  return {
    severity,
    kind,
    target: s(target),
    detail: s(detail),
    since: s(extra.since),
    action: s(extra.action),
    on: s(extra.on),
  };
}

function fmtSecs(sec) {
  if (sec == null || !Number.isFinite(sec)) return "?";
  const n = Math.max(0, Math.round(sec));
  if (n < 60) return `${n}s`;
  if (n < 3600) return `${Math.round(n / 60)}m`;
  return `${Math.round(n / 360) / 10}h`;
}

/** The most common daemon version among reachable dev machines, and who is off it. */
export function fleetVersion(devs) {
  const counts = new Map();
  for (const d of devs) {
    const v = d?.daemon?.version;
    if (d?.reachable && v) counts.set(v, (counts.get(v) ?? 0) + 1);
  }
  let modal = null;
  let best = -1;
  // Ties break on the LOWER version string so a half-rolled fleet flags the
  // machines that have NOT been updated yet, not the ones that have.
  for (const [v, n] of [...counts.entries()].sort((a, b) => b[1] - a[1] || (a[0] > b[0] ? 1 : -1))) {
    if (n > best) { modal = v; best = n; }
  }
  const off = devs
    .filter((d) => d?.reachable && d?.daemon?.version && d.daemon.version !== modal)
    .map((d) => `${d.id}@${d.daemon.version}`);
  return { version: modal, machines: best < 0 ? 0 : [...counts.values()].reduce((a, b) => a + b, 0), off_version: off };
}

/**
 * @param input.workers  merged workers, each carrying its classifier verdict
 *                       as `health` and `reason` (llm-view) or `healthReason`
 *                       (derive.ts)
 * @param input.devs     dispatchers, each carrying `level` and `reason` /
 *                       `levelReason`, plus the EXPANDED records the wire
 *                       tuples decode to: `remediation_hints`,
 *                       `alert_records`, `issue_records`, `active_records`
 * @param input.snapshotValid  false when generated_at was unparseable
 * @param input.ageSeconds     snapshot age from the caller's clock
 * @param input.staleAfter     seconds after which the snapshot is a problem
 */
export function buildProblems({ workers, devs, snapshotValid = true, ageSeconds = 0, staleAfter = 3600 }) {
  const problems = [];
  const reachable = devs.filter((d) => d.reachable);
  const wReason = (w) => w.reason ?? w.healthReason ?? "";
  const dReason = (d) => d.reason ?? d.levelReason ?? "";

  // --- what rch itself knows about each worker: advice, and since when ------
  // hints: worker -> {action, on}, most severe first, first reporter wins
  const HINT_RANK = { critical: 0, error: 0, warning: 1, warn: 1, info: 2 };
  const adviceFor = new Map();
  for (const d of reachable) {
    for (const h of d.remediation_hints ?? []) {
      if (!h?.worker_id || !h.suggested_action) continue;
      const rank = HINT_RANK[String(h.severity ?? "").toLowerCase()] ?? 3;
      const prev = adviceFor.get(h.worker_id);
      if (!prev || rank < prev.rank) adviceFor.set(h.worker_id, { rank, action: h.suggested_action, on: d.id });
    }
  }
  // issues: "Worker 'x' ..." + remediation, as a fallback source of advice
  for (const d of reachable) {
    for (const i of d.issue_records ?? []) {
      const m = /Worker '([^']+)'/.exec(i?.summary ?? "");
      if (!m || !i.remediation || adviceFor.has(m[1])) continue;
      adviceFor.set(m[1], { rank: 9, action: i.remediation, on: d.id });
    }
  }
  // alerts: worker -> earliest first_seen among ACTIVE alerts
  const sinceFor = new Map();
  for (const d of reachable) {
    for (const a of d.alert_records ?? []) {
      if (!a?.worker_id || !a.first_seen) continue;
      if (a.state && String(a.state).toLowerCase() !== "active") continue;
      const prev = sinceFor.get(a.worker_id);
      if (!prev || a.first_seen < prev) sinceFor.set(a.worker_id, a.first_seen);
    }
  }

  // --- snapshot itself ------------------------------------------------------
  if (!snapshotValid) {
    problems.push(row("critical", "snapshot.timestamp_unreadable", "snapshot",
      "generated_at is not a valid timestamp; treat this snapshot as untrusted",
      { action: "scripts/deploy-vercel.sh", on: "collector" }));
  } else if (ageSeconds > staleAfter) {
    problems.push(row("critical", "snapshot.stale", "snapshot",
      `snapshot is ${Math.round(ageSeconds / 60)}m old; re-run the collector`,
      { action: "scripts/deploy-vercel.sh", on: "collector" }));
  }

  // --- workers --------------------------------------------------------------
  const sickWorkers = workers.filter((w) => w.health === "critical" || w.health === "offline" || w.health === "warn");
  for (const w of workers) {
    if (w.health !== "critical" && w.health !== "offline" && w.health !== "warn") continue;
    const advice = adviceFor.get(w.id);
    let detail = wReason(w);
    if (w.recovery_in_secs != null && w.recovery_in_secs > 0) detail += ` — circuit retries in ${fmtSecs(w.recovery_in_secs)}`;
    if (w.bypass) detail += ` — bypass ${w.bypass}`;
    if (w.pressure?.confidence && w.pressure.confidence !== "high" && w.health !== "offline") {
      detail += ` (${w.pressure.confidence} confidence)`;
    }
    problems.push(row(
      w.health === "warn" ? "warn" : "critical",
      `worker.${w.health}`,
      w.id,
      detail,
      {
        since: sinceFor.get(w.id),
        action: advice?.action ?? (w.health === "offline" ? `rch workers probe ${w.id}` : ""),
        on: advice?.on ?? (reachable[0]?.id ?? ""),
      },
    ));
  }

  // --- dev machines ---------------------------------------------------------
  const degraded = reachable.filter((d) => d.level === "degraded");
  // One root cause, not N: when several machines are degraded and the pool
  // itself has sick workers, the machines are SYMPTOMS. Emit a single
  // fleet-level row naming the workers to fix, instead of one warning per
  // machine that all say the same thing.
  const collapseDegraded = degraded.length >= 2 && sickWorkers.length > 0;
  if (collapseDegraded) {
    problems.push(row("warn", "fleet.degraded", "fleet",
      `${degraded.length} of ${reachable.length} dev machines see partial remote capability; ` +
      `root cause is worker-side — fix ${sickWorkers.map((w) => w.id).join(", ")}`,
      { action: "", on: "" }));
  }

  for (const d of devs) {
    const errs = Array.isArray(d.collection_errors) ? d.collection_errors : [];
    if (d.level === "unreachable") {
      const first = errs[0] ?? "";
      const transport = /ssh|route to host|connection|timed out|permission denied/i.test(first);
      problems.push(row("critical", "dev.unreachable", d.id, dReason(d), {
        action: transport ? `ssh ${d.id} true` : "rch daemon start",
        on: transport ? "collector" : d.id,
      }));
      continue;
    }
    if (d.level === "local-only") {
      problems.push(row("critical", "dev.local-only", d.id, dReason(d), { action: "rch doctor", on: d.id }));
    } else if (d.level === "degraded" && !collapseDegraded) {
      problems.push(row("warn", "dev.degraded", d.id, dReason(d), { action: "rch status --json", on: d.id }));
    }

    if (d.hook && d.hook.claude_code === false) {
      problems.push(row("critical", "dev.hook_missing", d.id,
        "Claude Code PreToolUse hook is not installed — nothing is intercepted on this box",
        { action: "rch hook install", on: d.id }));
    }
    if (d.shim) {
      if (d.shim.installed === false) {
        problems.push(row("warn", "dev.shim_missing", d.id,
          "cargo shim not installed — script/Makefile builds run locally",
          { action: "rch shim install", on: d.id }));
      } else if (d.shim.installed === true && (d.shim.up_to_date === false || d.shim.on_path === false)) {
        const why = d.shim.up_to_date === false ? "out of date" : "shadowed by another cargo on PATH";
        problems.push(row("warn", "dev.shim_stale", d.id, `cargo shim ${why}`,
          { action: "rch shim install", on: d.id }));
      }
      if ((d.shim.local_builds_running ?? 0) > 0) {
        const n = d.shim.local_builds_running;
        problems.push(row("critical", "dev.unmanaged_local_builds", d.id,
          `${n} compiler process${n === 1 ? "" : "es"} running outside rch right now`,
          { action: "rch shim status --json", on: d.id }));
      }
    }
    if (d.doctor) {
      const failing = d.doctor.failing ?? [];
      const named = failing.slice(0, 3).map((c) => `${c[0]}: ${c[2] ?? c[1]}`).join("; ");
      const more = failing.length > 3 ? ` (+${failing.length - 3} more)` : "";
      const fixable = failing.some((c) => c[3] === true);
      if (d.doctor.failed > 0) {
        problems.push(row("critical", "dev.doctor_failed", d.id,
          `${d.doctor.failed} doctor check${d.doctor.failed === 1 ? "" : "s"} failed — ${named}${more}`,
          { action: fixable ? "rch doctor --fix" : "rch doctor", on: d.id }));
      } else if (d.doctor.warnings > 0) {
        problems.push(row("warn", "dev.doctor_warnings", d.id,
          `${d.doctor.warnings} doctor warning${d.doctor.warnings === 1 ? "" : "s"} — ${named}${more}`,
          { action: "rch doctor", on: d.id }));
      }
    }
    if (errs.length > 0) {
      problems.push(row("warn", "dev.collection_error", d.id,
        `probe failed: ${errs.slice(0, 3).join("; ")}${errs.length > 3 ? ` (+${errs.length - 3} more)` : ""} — those columns are unknown, not fine`,
        { action: "rch doctor", on: d.id }));
    }
    for (const b of d.active_records ?? []) {
      const who = `${b.project ?? "?"} on ${b.worker_id ?? "?"}`;
      const held = b.slots != null ? `${b.slots} slots held` : "slots held";
      if (b.hook_alive === false) {
        problems.push(row("critical", "build.hook_dead", `${d.id}:${b.id ?? b.project ?? "?"}`,
          `${who}: dispatching hook process is gone after ${fmtSecs(b.build_age_secs)}; ${held} until cancelled`,
          { since: b.started_at, action: b.id ? `rch cancel ${b.id}` : "rch queue --json", on: d.id }));
      } else if (
        (b.heartbeat_stale === true && b.progress_stale === true) ||
        (b.progress_stale === true && (b.build_age_secs ?? 0) > 1800 && (b.confidence ?? 0) >= 0.5)
      ) {
        problems.push(row("warn", "build.stalled", `${d.id}:${b.id ?? b.project ?? "?"}`,
          `${who}: no heartbeat for ${fmtSecs(b.heartbeat_age_secs)}, no progress for ${fmtSecs(b.progress_age_secs)}` +
          ` (phase ${b.phase ?? "?"}, age ${fmtSecs(b.build_age_secs)}); cancel with: rch cancel ${b.id ?? "<id>"}`,
          { since: b.started_at, action: "rch queue --json", on: d.id }));
      }
    }
  }

  // Version skew across the fleet.
  const fv = fleetVersion(devs);
  if (fv.version && fv.off_version.length > 0) {
    for (const d of reachable) {
      if (d.daemon?.version && d.daemon.version !== fv.version) {
        problems.push(row("warn", "dev.daemon_version_skew", d.id,
          `rch ${d.daemon.version}, fleet is on ${fv.version}`,
          { action: "rch update", on: d.id }));
      }
    }
  }

  // Convergence drift, deduped per worker (first reporting machine wins).
  const drifted = new Set();
  for (const d of reachable) {
    for (const cw of d.convergence?.workers ?? []) {
      const id = cw?.[0];
      if (!id || drifted.has(id)) continue;
      drifted.add(id);
      const state = cw[1] ?? "not ready";
      const missing = cw[2] ?? 0;
      problems.push(row("warn", "worker.convergence_drift", id,
        `${state}, ${missing} repo${missing === 1 ? "" : "s"} missing as seen from ${d.id}`,
        { action: "rch doctor --reliability", on: d.id }));
    }
  }

  problems.sort((a, b) =>
    (SEVERITY_RANK[a.severity] ?? 9) - (SEVERITY_RANK[b.severity] ?? 9) ||
    a.kind.localeCompare(b.kind) ||
    a.target.localeCompare(b.target));

  // --- what to run, grouped by where ---------------------------------------
  const byCmd = new Map();
  for (const p of problems) {
    if (!p.action) continue;
    const key = `${p.on} ${p.action}`;
    const prev = byCmd.get(key);
    if (prev) {
      if (!prev.fixes.includes(p.target)) prev.fixes.push(p.target);
      if ((SEVERITY_RANK[p.severity] ?? 9) < (SEVERITY_RANK[prev.severity] ?? 9)) prev.severity = p.severity;
    } else {
      byCmd.set(key, { severity: p.severity, on: p.on, run: p.action, fixes: [p.target] });
    }
  }
  const next_actions = [...byCmd.values()]
    .sort((a, b) => (SEVERITY_RANK[a.severity] ?? 9) - (SEVERITY_RANK[b.severity] ?? 9) || a.on.localeCompare(b.on))
    .map((a) => ({ ...a, fixes: a.fixes.join("|") }));

  return { problems, next_actions, fleet_version: fv };
}
