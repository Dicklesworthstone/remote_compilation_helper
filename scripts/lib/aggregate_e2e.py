#!/usr/bin/env python3
"""Aggregate e2e artifacts into a single Markdown summary.

remote_compilation_helper-62u24.15.

Reads the artifact layout produced by ``scripts/run_all_e2e.sh`` (and uploaded
by ``.github/workflows/e2e.yml``):

    e2e_<slug>.status      one JSON line: {script, os, exit_code, status, duration_ms}
    e2e_<slug>*.jsonl      structured JSONL (any of the repo's e2e log schemas)

The ``.status`` file is authoritative for PASS/FAIL/SKIP — it records the e2e
script's exit code, which is what CI gates on. JSONL is parsed best-effort for a
per-scenario breakdown and a perf-budget table, tolerating the three logging
conventions in the tree (test_lib.sh, remediation_e2e.sh, RCH_E2E_LOG scripts)
and skipping any unparseable line.

Usage:
    aggregate_e2e.py --artifacts-dir <dir> [--output e2e_summary.md]
                     [--baseline-dir <dir>]

When ``--baseline-dir`` is given (e.g. artifacts from the merge base), any script
whose status regressed (pass -> fail) is highlighted. The aggregator never exits
non-zero on test failures: CI gates on the per-script run jobs, not on this
summary step.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from collections import defaultdict
from pathlib import Path

# A latency/perf metric event, e.g. "p50_ms", "p99_ms", "build_ms".
_PERF_KEY_RE = re.compile(r"^[a-z0-9_]*p?\d*_?ms$|^p\d+_ms$", re.IGNORECASE)
_NUM_RE = re.compile(r"-?\d+(?:\.\d+)?")

# JSONL "status" tokens that mean a scenario passed / failed / was skipped.
_PASS_TOKENS = {"pass", "passed", "ok", "success"}
_FAIL_TOKENS = {"fail", "failed", "error"}
_SKIP_TOKENS = {"skip", "skipped"}


def _load_statuses(root: Path) -> dict[str, dict]:
    """Map "<script>@<os>" -> status record from every *.status file under root."""
    out: dict[str, dict] = {}
    for path in sorted(root.rglob("*.status")):
        try:
            rec = json.loads(path.read_text(encoding="utf-8").strip() or "{}")
        except (OSError, json.JSONDecodeError):
            continue
        script = rec.get("script", path.stem)
        os_label = rec.get("os", "unknown")
        out[f"{script}@{os_label}"] = rec
    return out


def _first_number(value) -> float | None:
    if isinstance(value, (int, float)):
        return float(value)
    if isinstance(value, str):
        m = _NUM_RE.search(value)
        if m:
            try:
                return float(m.group(0))
            except ValueError:
                return None
    return None


def _scan_jsonl(root: Path):
    """Best-effort per-scenario tallies and perf points across all JSONL.

    Returns (scenarios, perf) where:
      scenarios: {script_slug: {"pass": n, "fail": n, "skip": n}}
      perf:      list of {script, metric, value}
    """
    scenarios: dict[str, dict[str, int]] = defaultdict(
        lambda: {"pass": 0, "fail": 0, "skip": 0}
    )
    perf: list[dict] = []

    for path in sorted(root.rglob("*.jsonl")):
        # Derive the owning script slug from the artifact filename:
        # "e2e_api_envelope.jsonl" or "e2e_api_envelope.e2e_api_envelope.jsonl".
        slug = path.name.split(".")[0]
        for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                continue
            if not isinstance(obj, dict):
                continue

            status = str(obj.get("status", "")).lower()
            if status in _PASS_TOKENS:
                scenarios[slug]["pass"] += 1
            elif status in _FAIL_TOKENS:
                scenarios[slug]["fail"] += 1
            elif status in _SKIP_TOKENS:
                scenarios[slug]["skip"] += 1

            # Perf events: event/phase token names a latency metric.
            metric = str(obj.get("event") or obj.get("phase") or "")
            if metric and _PERF_KEY_RE.match(metric):
                value = _first_number(
                    obj.get("detail")
                    if obj.get("detail") is not None
                    else obj.get("value", obj.get("message"))
                )
                if value is not None:
                    perf.append({"script": slug, "metric": metric, "value": value})

    return scenarios, perf


def _emoji(status: str) -> str:
    return {"pass": "✅", "fail": "❌", "skip": "⏭️"}.get(status, "❓")


def _render(statuses, scenarios, perf, baseline) -> tuple[str, dict]:
    totals = {"pass": 0, "fail": 0, "skip": 0}
    for rec in statuses.values():
        totals[rec.get("status", "fail")] = totals.get(rec.get("status", "fail"), 0) + 1

    lines: list[str] = []
    lines.append("## e2e summary")
    lines.append("")
    lines.append(
        f"**{totals['pass']} passed · {totals['fail']} failed · {totals['skip']} skipped** "
        f"({len(statuses)} job(s))"
    )
    lines.append("")

    # Per-script/os result table.
    lines.append("| script | os | result | exit | duration |")
    lines.append("|---|---|---|---|---|")
    regressions: list[str] = []
    for key in sorted(statuses):
        rec = statuses[key]
        status = rec.get("status", "fail")
        script = rec.get("script", key)
        os_label = rec.get("os", "?")
        dur = rec.get("duration_ms", 0)
        regressed = ""
        if baseline:
            base = baseline.get(key)
            if base and base.get("status") == "pass" and status == "fail":
                regressed = " ⚠️ REGRESSED"
                regressions.append(f"{script} ({os_label})")
        lines.append(
            f"| `{script}` | {os_label} | {_emoji(status)} {status}{regressed} "
            f"| {rec.get('exit_code', '?')} | {int(dur)}ms |"
        )
    lines.append("")

    if regressions:
        lines.append(
            "> ⚠️ **Regressions vs merge base:** " + ", ".join(sorted(set(regressions)))
        )
        lines.append("")

    # Per-scenario breakdown (only when any JSONL carried scenario statuses).
    scenario_rows = {s: c for s, c in scenarios.items() if any(c.values())}
    if scenario_rows:
        lines.append("### Scenario breakdown")
        lines.append("")
        lines.append("| script | pass | fail | skip |")
        lines.append("|---|---|---|---|")
        for slug in sorted(scenario_rows):
            c = scenario_rows[slug]
            lines.append(f"| `{slug}` | {c['pass']} | {c['fail']} | {c['skip']} |")
        lines.append("")

    # Perf-budget table (surfaced for review; never gates CI).
    if perf:
        lines.append("### Measured latency (informational — not gated)")
        lines.append("")
        lines.append("| script | metric | value (ms) |")
        lines.append("|---|---|---|")
        for row in sorted(perf, key=lambda r: (r["script"], r["metric"])):
            lines.append(
                f"| `{row['script']}` | {row['metric']} | {row['value']:g} |"
            )
        lines.append("")

    if not statuses:
        lines.append("_No e2e status artifacts found._")
        lines.append("")

    return "\n".join(lines) + "\n", totals


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description="Aggregate e2e artifacts.")
    parser.add_argument("--artifacts-dir", required=True, type=Path)
    parser.add_argument("--output", default="e2e_summary.md", type=Path)
    parser.add_argument("--baseline-dir", type=Path, default=None)
    args = parser.parse_args(argv)

    if not args.artifacts_dir.is_dir():
        print(f"artifacts dir not found: {args.artifacts_dir}", file=sys.stderr)
        return 2

    statuses = _load_statuses(args.artifacts_dir)
    scenarios, perf = _scan_jsonl(args.artifacts_dir)
    baseline = _load_statuses(args.baseline_dir) if args.baseline_dir else {}

    markdown, totals = _render(statuses, scenarios, perf, baseline)
    args.output.write_text(markdown, encoding="utf-8")

    # Echo a one-line summary for the CI log.
    print(
        f"e2e: {totals['pass']} pass, {totals['fail']} fail, {totals['skip']} skip "
        f"-> {args.output}"
    )
    # The aggregator is informational; CI gates on the per-script run jobs.
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
