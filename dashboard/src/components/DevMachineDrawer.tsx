import { useMemo, useState } from "react";
import type { DispatcherView } from "../types";
import { fmtAge, fmtDuration, fmtUptime } from "../derive";
import { useDialog } from "./useDialog";

interface Props {
  d: DispatcherView | null;
  /** When the snapshot was taken — build ages are judged against it, never the reader's clock. */
  snapshotMs: number;
  onClose: () => void;
  /** Cross-links: ids resolve against the fleet-wide views held in App. */
  onOpenWorker: (id: string) => void;
  fleetWorkerIds: ReadonlySet<string>;
}

function Row({ k, v }: { k: string; v: React.ReactNode }) {
  return (
    <div className="kv">
      <dt>{k}</dt>
      <dd>{v ?? "—"}</dd>
    </div>
  );
}

export function DevMachineDrawer({ d, snapshotMs, onClose, onOpenWorker, fleetWorkerIds }: Props) {
  const { ref, onCancel, onClick, onKeyDown } = useDialog(d != null, onClose);
  const [copied, setCopied] = useState(false);

  // Deterministic, index-free list keys: an occurrence counter appended at
  // data-mapping time keeps identical hints/builds from colliding.
  const hintRows = useMemo(() => {
    const seen = new Map<string, number>();
    return (d?.remediation_hints ?? []).map((h) => {
      const base = `${h.worker_id ?? ""}|${h.reason_code ?? ""}|${h.message ?? ""}`;
      const n = (seen.get(base) ?? 0) + 1;
      seen.set(base, n);
      return { ...h, key: n === 1 ? base : `${base}|${n}` };
    });
  }, [d?.remediation_hints]);

  const buildRows = useMemo(() => {
    const seen = new Map<string, number>();
    return [...(d?.recent_builds ?? [])].reverse().map((b) => {
      const base = `${b.completed_at ?? ""}|${b.project ?? ""}|${b.worker_id ?? ""}|${b.duration_ms ?? ""}|${b.exit_code ?? ""}`;
      const n = (seen.get(base) ?? 0) + 1;
      seen.set(base, n);
      const completedMs = b.completed_at ? Date.parse(b.completed_at) : NaN;
      return {
        key: n === 1 ? base : `${base}|${n}`,
        remote: (b.location ?? "").toLowerCase() === "remote",
        project: b.project,
        command: b.command,
        worker_id: b.worker_id,
        knownWorker: b.worker_id != null && fleetWorkerIds.has(b.worker_id),
        duration_ms: b.duration_ms,
        // Judged against snapshot time so an old drawer never claims "0s ago".
        ago: Number.isFinite(completedMs) ? fmtAge((snapshotMs - completedMs) / 1000) : null,
        failed: b.exit_code != null && b.exit_code !== 0,
        exit: b.exit_code,
      };
    });
  }, [d?.recent_builds, fleetWorkerIds, snapshotMs]);

  // This dispatcher's OWN derated view of the pool — the thing no other
  // surface shows. rchd derates each worker from live telemetry independently
  // on every box, and a worker derated to 0 slots is invisible to any build,
  // which is how a machine silently goes local-only.
  const pool = useMemo(() => {
    const ws = d?.workers ?? [];
    const total = ws.reduce((n, w) => n + (w.total_slots ?? 0), 0);
    const used = ws.reduce((n, w) => n + (w.used_slots ?? 0), 0);
    const zero = ws.filter((w) => (w.total_slots ?? 0) === 0).length;
    return { count: ws.length, total, used, zero };
  }, [d?.workers]);

  const s = d?.build_stats;

  // Early return AFTER all hooks: a closed drawer must unmount its <dialog>.
  // A closed native dialog stays in the DOM (display:none), and tests plus the
  // padding-click guard assert on its removal — early return keeps them honest.
  if (!d) return null;

  return (
    <dialog
      ref={ref}
      className="drawer"
      aria-label={d ? `${d.id} dev machine details` : "Dev machine details"}
      onCancel={onCancel}
      onClick={onClick}
      onKeyDown={onKeyDown}
    >
          <div className="drawer-head">
            <h3>{d.id}</h3>
            <span className={`pill dev-${d.level}`}>{d.level}</span>
            <span style={{ flex: 1 }} />
            <button className="icon-btn" onClick={onClose}>Close</button>
          </div>
      <div className="drawer-host">
        <span>dev machine · dispatches builds to the pool</span>
        <button
          className="link"
          onClick={() => {
            navigator.clipboard
              ?.writeText("rch status")
              .then(() => setCopied(true))
              .catch(() => setCopied(false));
            setTimeout(() => setCopied(false), 1500);
          }}
          title="Copy the rch status command"
        >
          {copied ? "copied ✓" : "copy status cmd"}
        </button>
      </div>

      <div className="kv-group">
        <h4>Offload posture</h4>
        <dl style={{ margin: 0 }}>
          <Row k="Assessment" v={d.levelReason} />
          <Row
            k="Measured window"
            v={
              d.remoteBasis === "recent"
                ? `last ${d.remoteCounted} builds`
                : d.remoteBasis === "lifetime"
                  ? "since daemon start"
                  : "—"
            }
          />
          <Row k="rch posture" v={d.posture ?? "—"} />
          <Row k="Description" v={d.posture_description ?? "—"} />
          {(() => {
            // Counts must match the window the share was measured over.
            const recent = d.remoteBasis === "recent" ? (d.recent_builds ?? []) : [];
            const r = recent.length > 0
              ? recent.filter((b) => (b.location ?? "").toLowerCase() === "remote").length
              : (s?.remote ?? null);
            const l = recent.length > 0 ? recent.length - (r ?? 0) : (s?.local ?? null);
            return (
              <>
                <Row k="Builds remote" v={r ?? "—"} />
                <Row k="Builds local" v={l ?? "—"} />
              </>
            );
          })()}
          <Row k="Remote share" v={d.remotePct != null ? `${d.remotePct.toFixed(0)}%` : "—"} />
          <Row k="Avg build" v={fmtDuration(s?.avg_duration_ms ?? null)} />
          <Row k="Failures" v={s ? s.failure : "—"} />
        </dl>
      </div>

      <div className="kv-group">
        <h4>Daemon</h4>
        <dl style={{ margin: 0 }}>
          <Row k="Version" v={d.daemon?.version ?? "—"} />
          <Row k="Uptime" v={fmtUptime(d.daemon?.uptime_secs ?? null)} />
          <Row k="PID" v={d.daemon?.pid ?? "—"} />
          <Row k="Workers healthy" v={`${d.daemon?.workers_healthy ?? "—"} / ${d.daemon?.workers_total ?? "—"}`} />
          <Row k="Slots free" v={`${d.daemon?.slots_available ?? "—"} / ${d.daemon?.slots_total ?? "—"}`} />
          <Row k="Active / queued" v={`${d.active_builds} / ${d.queued_builds}`} />
        </dl>
      </div>

      <div className="kv-group">
        <h4>Interception on this box</h4>
        <p className="note">
          Three ways a dev machine quietly stops offloading while every worker looks fine: no
          hook, no shim, or compiles started outside both. <code>unknown</code> means the probe
          did not answer — not that it is fine.
        </p>
        <dl style={{ margin: 0 }}>
          <Row
            k="Claude Code hook"
            v={
              d.hook
                ? d.hook.claude_code === true
                  ? "installed"
                  : d.hook.claude_code === false
                    ? <span className="fail-mark">NOT INSTALLED — run rch hook install</span>
                    : "unknown"
                : "unknown (probe did not answer)"
            }
          />
          {d.hook && d.hook.agents.length > 0 && (
            <Row
              k="Other agents"
              v={d.hook.agents
                .filter(([a]) => a !== "ClaudeCode")
                .map(([a, ok]) => `${a}: ${ok ? "installed" : "missing"}`)
                .join(" · ")}
            />
          )}
          <Row
            k="cargo shim"
            v={
              d.shim
                ? d.shim.installed === false
                  ? <span className="fail-mark">not installed — run rch shim install</span>
                  : d.shim.installed === true
                    ? `installed${d.shim.up_to_date === false ? " · OUT OF DATE" : ""}${d.shim.on_path === false ? " · SHADOWED on PATH" : ""}` +
                      `${d.shim.interception ? ` · ${d.shim.interception}` : ""}` +
                      `${d.shim.toolchains_wrapped != null && d.shim.toolchains_total != null ? ` · ${d.shim.toolchains_wrapped}/${d.shim.toolchains_total} toolchains wrapped` : ""}`
                    : "unknown"
                : "unknown (probe did not answer)"
            }
          />
          <Row
            k="Compiles outside rch"
            v={
              d.shim?.local_builds_running == null
                ? "unknown"
                : d.shim.local_builds_running > 0
                  ? <span className="fail-mark">{d.shim.local_builds_running} running right now</span>
                  : "none"
            }
          />
          <Row
            k="rch doctor"
            v={
              d.doctor
                ? d.doctor.failed > 0
                  ? <span className="fail-mark">{d.doctor.failed} failed · {d.doctor.warnings} warnings · {d.doctor.passed}/{d.doctor.total} passed</span>
                  : d.doctor.warnings > 0
                    ? `${d.doctor.warnings} warning${d.doctor.warnings === 1 ? "" : "s"} · ${d.doctor.passed}/${d.doctor.total} passed`
                    : `${d.doctor.passed}/${d.doctor.total} passed`
                : "unknown (probe did not answer)"
            }
          />
          {d.doctor && d.doctor.failing.length > 0 && (
            <Row
              k="Doctor findings"
              v={
                <span>
                  {d.doctor.failing.map((c, i) => (
                    <span key={`${c[0]}|${i}`} style={{ display: "block" }}>
                      <span className={c[1] === "fail" ? "fail-mark" : undefined}>{c[0]}</span>
                      {c[2] ? ` — ${c[2]}` : ""}
                      {c[3] ? " (fixable: rch doctor --fix)" : ""}
                    </span>
                  ))}
                </span>
              }
            />
          )}
          {d.collection_errors.length > 0 && (
            <Row
              k="Probe errors"
              v={<span className="fail-mark">{d.collection_errors.join(" · ")}</span>}
            />
          )}
          {d.convergence && d.convergence.status && d.convergence.status !== "unknown" && (
            <Row
              k="Repo convergence"
              v={`${d.convergence.status} · ${d.convergence.ready} ready · ${d.convergence.drifting} drifting · ${d.convergence.failed} failed`}
            />
          )}
          {d.tests && d.tests.runs > 0 && (
            <Row k="Test runs (lifetime)" v={`${d.tests.runs} · ${d.tests.passed} passed · ${d.tests.failed} failed · ${d.tests.build_errors} build errors`} />
          )}
        </dl>
      </div>

      {(d.active_records.length > 0 || d.queued_records.length > 0) && (
        <div className="kv-group">
          <h4>Builds in flight ({d.active_records.length} active · {d.queued_records.length} queued)</h4>
          <div className="builds">
            {d.active_records.map((b, i) => {
              const stalled = b.hook_alive === false || (b.heartbeat_stale === true && b.progress_stale === true);
              return (
                <div key={`${b.id ?? ""}|${i}`} className="build-row" title={b.command ?? undefined}>
                  <span className={`pill ${b.hook_alive === false ? "critical" : stalled ? "warn" : "busy"}`}>
                    {b.hook_alive === false ? "hook dead" : stalled ? "stalled" : b.phase ?? "active"}
                  </span>
                  <span className="build-proj">{b.project ?? "—"}</span>
                  {b.worker_id && fleetWorkerIds.has(b.worker_id) ? (
                    <button className="link" onClick={() => onOpenWorker(b.worker_id as string)} title={`Open worker ${b.worker_id}`}>
                      {b.worker_id}
                    </button>
                  ) : (
                    <span className="metric-value">{b.worker_id ?? "—"}</span>
                  )}
                  <span className="metric-value" title="build age / since last progress (snapshot time)">
                    {b.build_age_secs != null ? fmtAge(b.build_age_secs).replace(" ago", "") : "—"}
                    {b.progress_age_secs != null && b.progress_age_secs > 120 && (
                      <span className="stall-mark"> · no progress {fmtAge(b.progress_age_secs).replace(" ago", "")}</span>
                    )}
                  </span>
                  <span className="metric-value">{b.slots != null ? `${b.slots} slots` : ""}{b.id ? ` · #${b.id}` : ""}</span>
                </div>
              );
            })}
            {d.queued_records.map((q, i) => (
              <div key={`q|${q.id ?? ""}|${i}`} className="build-row" title={q.command ?? undefined}>
                <span className="pill warn">queued #{q.position ?? "?"}</span>
                <span className="build-proj">{q.project ?? "—"}</span>
                <span className="metric-value">needs {q.slots_needed ?? "?"} slots</span>
                <span className="metric-value">waiting {q.wait_time ?? "—"}</span>
                <span className="metric-value">{q.id ? `#${q.id}` : ""}</span>
              </div>
            ))}
          </div>
        </div>
      )}

      {(d.alert_records.length > 0 || d.issue_records.length > 0) && (
        <div className="kv-group">
          <h4>Daemon alerts & issues ({d.alert_records.length + d.issue_records.length})</h4>
          {d.alert_records.map((a, i) => {
            const sinceMs = a.first_seen ? Date.parse(a.first_seen) : NaN;
            return (
              <div key={`a|${a.kind ?? ""}|${a.worker_id ?? ""}|${i}`} className="hint">
                <div className="hint-top">
                  <span className={`pill ${a.severity === "critical" || a.severity === "error" ? "critical" : "warn"}`}>
                    {a.kind ?? a.severity ?? "alert"}
                  </span>
                  {a.worker_id && fleetWorkerIds.has(a.worker_id) ? (
                    <button className="link" onClick={() => onOpenWorker(a.worker_id as string)}>{a.worker_id}</button>
                  ) : (
                    a.worker_id && <span className="metric-value">{a.worker_id}</span>
                  )}
                  <span className="metric-value">
                    {a.state ?? ""}{Number.isFinite(sinceMs) ? ` · since ${fmtAge((snapshotMs - sinceMs) / 1000)}` : ""}
                  </span>
                </div>
                <div className="hint-msg">{a.message}</div>
              </div>
            );
          })}
          {d.issue_records.map((it, i) => (
            <div key={`i|${it.summary ?? ""}|${i}`} className="hint">
              <div className="hint-top">
                <span className={`pill ${it.severity === "critical" || it.severity === "error" ? "critical" : "warn"}`}>
                  {it.severity ?? "issue"}
                </span>
              </div>
              <div className="hint-msg">{it.summary}</div>
              {it.remediation && <div className="hint-action">→ {it.remediation}</div>}
            </div>
          ))}
        </div>
      )}

      <div className="kv-group">
        <h4>This machine's view of the pool</h4>
        <p className="note">
          rchd derates every worker from live RAM/disk telemetry, independently on each
          dispatcher. A worker derated to <code>0</code> slots is invisible to any build — the
          root cause of a machine quietly going local.
        </p>
        <dl style={{ margin: 0 }}>
          <Row k="Workers seen" v={pool.count} />
          <Row k="Derated slots" v={`${pool.used} used / ${pool.total} total`} />
          <Row k="Zero-slot workers" v={pool.zero > 0 ? `${pool.zero} of ${pool.count}` : "none"} />
        </dl>
        {pool.zero > 0 && (
          <p className="warn-note">
            {pool.zero} worker{pool.zero === 1 ? "" : "s"} derated to 0 slots — invisible to any
            build from this box.
          </p>
        )}
      </div>

      {hintRows.length > 0 && (
        <div className="kv-group">
          <h4>Remediation hints ({hintRows.length})</h4>
          {hintRows.map((h) => (
            <div key={h.key} className="hint">
              <div className="hint-top">
                <span className={`pill ${h.severity === "critical" ? "critical" : "warn"}`}>
                  {h.severity ?? "info"}
                </span>
                {h.worker_id && <span className="metric-value">{h.worker_id}</span>}
              </div>
              <div className="hint-msg">{h.message}</div>
              {h.suggested_action && <div className="hint-action">→ {h.suggested_action}</div>}
            </div>
          ))}
        </div>
      )}

      <div className="kv-group">
        <h4>Recent builds ({buildRows.length})</h4>
        {buildRows.length === 0 ? (
          <div className="empty" style={{ padding: 16 }}>no builds recorded</div>
        ) : (
          <div className="builds">
            {buildRows.map((b) => (
              <div key={b.key} className="build-row">
                <span className={`pill ${b.remote ? "healthy" : "warn"}`}>{b.remote ? "remote" : "local"}</span>
                <span className="build-proj" title={b.command ?? undefined}>
                  {b.project ?? "—"}
                </span>
                {b.knownWorker ? (
                  <button
                    className="link"
                    onClick={() => onOpenWorker(b.worker_id as string)}
                    title={`Open worker ${b.worker_id}`}
                  >
                    {b.worker_id}
                  </button>
                ) : (
                  <span className="metric-value">{b.worker_id ?? (b.remote ? "?" : "—")}</span>
                )}
                <span className="metric-value" title="when the build finished (snapshot time)">{b.ago ?? "—"}</span>
                <span className="metric-value">
                  {fmtDuration(b.duration_ms)}
                  {b.failed && <span className="fail-mark"> · exit {b.exit}</span>}
                </span>
                </div>
              ))}
            </div>
          )}
        </div>
    </dialog>
  );
}
