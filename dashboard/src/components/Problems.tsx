import { useState } from "react";
import type { NextAction, Problem } from "../problems";
import { fmtAge } from "../derive";

interface Props {
  problems: Problem[];
  nextActions: NextAction[];
  /** When the snapshot was taken — `since` ages are judged against it, never the reader's clock. */
  snapshotMs: number;
  devIds: ReadonlySet<string>;
  workerIds: ReadonlySet<string>;
  onOpenDev: (id: string) => void;
  onOpenWorker: (id: string) => void;
}

function CopyButton({ text }: { text: string }) {
  const [state, setState] = useState<"idle" | "ok" | "fail">("idle");
  return (
    <button
      className="link"
      title="Copy command"
      onClick={(e) => {
        e.stopPropagation();
        navigator.clipboard
          ?.writeText(text)
          .then(() => setState("ok"))
          .catch(() => setState("fail"));
        setTimeout(() => setState("idle"), 1500);
      }}
    >
      {state === "ok" ? "copied ✓" : state === "fail" ? "copy failed" : "copy"}
    </button>
  );
}

/**
 * The problems panel: the SAME rows `/api/fleet?view=problems` hands an agent,
 * rendered for a human. Built by `src/problems.js`, so the two surfaces cannot
 * disagree about what is broken or what fixes it.
 *
 * Replaces the old pair of banners ("N dev machines not offloading", "N dev
 * machines degraded"), which repeated one worker-side root cause once per
 * machine and never said what to run.
 */
export function Problems({ problems, nextActions, snapshotMs, devIds, workerIds, onOpenDev, onOpenWorker }: Props) {
  const critical = problems.filter((p) => p.severity === "critical").length;

  const targetLink = (target: string) => {
    // Build targets are "<dev>:<build id>"; link the machine half.
    const base = target.includes(":") ? target.slice(0, target.indexOf(":")) : target;
    if (devIds.has(base)) {
      return (
        <button className="link" onClick={() => onOpenDev(base)} title={`Open dev machine ${base}`}>
          {target}
        </button>
      );
    }
    if (workerIds.has(base)) {
      return (
        <button className="link" onClick={() => onOpenWorker(base)} title={`Open worker ${base}`}>
          {target}
        </button>
      );
    }
    return <span>{target}</span>;
  };

  return (
    <section className="section" aria-label="Problems">
      <div className="section-head">
        <h2>Problems</h2>
        <span className={`count-pill ${critical > 0 ? "crit" : problems.length > 0 ? "warn" : "ok"}`}>
          {critical > 0
            ? `${critical} critical · ${problems.length - critical} warn`
            : problems.length > 0
              ? `${problems.length} warn`
              : "none"}
        </span>
        <span className="spacer" />
        <span className="hint-inline">
          same rows as <code>/api/fleet?view=problems</code> — action = what to run, on = where
        </span>
      </div>

      {problems.length === 0 ? (
        <div className="empty ok">No problems. Every reachable dev machine is offloading and every worker is admissible.</div>
      ) : (
        <div className="problems-scroll">
          <table className="problems">
            <thead>
              <tr>
                <th>sev</th>
                <th>kind</th>
                <th>target</th>
                <th>detail</th>
                <th>since</th>
                <th>action</th>
                <th>on</th>
              </tr>
            </thead>
            <tbody>
              {problems.map((p, i) => {
                const sinceMs = p.since ? Date.parse(p.since) : NaN;
                return (
                  <tr key={`${p.kind}|${p.target}|${i}`} className={`prob-${p.severity}`}>
                    <td>
                      <span className={`pill ${p.severity === "critical" ? "critical" : "warn"}`}>{p.severity}</span>
                    </td>
                    <td className="mono">{p.kind}</td>
                    <td className="mono">{targetLink(p.target)}</td>
                    <td className="prob-detail">{p.detail}</td>
                    <td className="mono" title={p.since || undefined}>
                      {Number.isFinite(sinceMs) ? fmtAge((snapshotMs - sinceMs) / 1000) : "—"}
                    </td>
                    <td className="prob-action">
                      {p.action ? (
                        <>
                          <code>{p.action}</code> <CopyButton text={p.action} />
                        </>
                      ) : (
                        "—"
                      )}
                    </td>
                    <td className="mono">{p.on ? (devIds.has(p.on) ? targetLink(p.on) : p.on) : "—"}</td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      )}

      {nextActions.length > 0 && (
        <details className="next-actions">
          <summary>
            Next actions — {nextActions.length} distinct command{nextActions.length === 1 ? "" : "s"}, grouped by machine
          </summary>
          <ul>
            {nextActions.map((a, i) => (
              <li key={`${a.on}|${a.run}|${i}`}>
                <span className={`pill ${a.severity === "critical" ? "critical" : "warn"}`}>{a.severity}</span>
                <span className="mono">{a.on || "—"}</span>
                <code>{a.run}</code>
                <CopyButton text={a.run} />
                <span className="hint-inline">fixes {a.fixes.split("|").join(", ")}</span>
              </li>
            ))}
          </ul>
        </details>
      )}
    </section>
  );
}
