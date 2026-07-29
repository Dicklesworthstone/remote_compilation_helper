#!/usr/bin/env python3
"""Verify benchmark results meet AGENTS.md performance budgets.

This is the CI/release benchmark gate for the hook hot path and the
session-history remediation hot paths (bd-session-history-remediation-ocv9i.16.7).

Performance requirements (from README/AGENTS.md):
- Non-compilation decision: < 1ms (1,000,000 ns)
- Compilation decision:     < 5ms (5,000,000 ns)
- Worker selection:         < 10ms

In practice these operations are microsecond-level; the budgets below are
conservative ceilings that still catch gross (multi-x) regressions without
flaking on shared CI runners.

The gate FAILS (exit 1) on any budget regression UNLESS an explicit, active
waiver is recorded in scripts/perf_budget_waivers.json with a rationale and an
owning bead. A waiver demotes a FAIL to a WAIVED warning; it never silences a
passing benchmark.

Matching: each `target/criterion/**/new/estimates.json` is matched to the
longest budget key that is a path-prefix of its criterion group path, so
slash-named groups (e.g. `classifier/tier0_reject`, `remediation/incident_append`)
gate correctly even though criterion nests them as directories.
"""
import datetime
import json
import sys
from pathlib import Path

# Performance budgets keyed by criterion group path (nanoseconds).
# A budget applies to every estimates.json whose group path starts with the key;
# the worst (max mean) measurement under a key is what gets gated.
BUDGETS = {
    # --- hook classification hot path -------------------------------------
    "classifier/tier0_reject": 100_000,        # 100µs (non-compilation reject)
    "classifier/structure_reject": 500_000,    # 500µs
    "classifier/compilation_match": 500_000,   # 500µs
    "classifier/never_intercept": 500_000,     # 500µs
    "classifier/complex": 1_000_000,           # 1ms
    "classifier/batch_100": 10_000_000,        # 10ms for 100 commands

    # --- remediation-program hot paths (bd-...16.7) -----------------------
    # Each is on or adjacent to the hook decision path; budgets derive from the
    # README/AGENTS non-compilation (<1ms) and compilation (<5ms) ceilings.
    "remediation/admit_preflight_compilation": 5_000_000,     # 5ms (comp path)
    "remediation/admit_preflight_noncompilation": 1_000_000,  # 1ms (non-comp)
    "remediation/output_mode_detect": 1_000_000,              # 1ms (every hook)
    "remediation/incident_append": 2_000_000,                 # 2ms (write path)
    "remediation/incident_read_warm": 5_000_000,              # 5ms (diagnostics)
    "remediation/incident_serialize": 500_000,                # 0.5ms
    "remediation/config_default": 500_000,                    # 0.5ms (cache-hit)
    "remediation/config_parse": 2_000_000,                    # 2ms (cache-miss)
    "remediation/rejection_aggregate": 500_000,               # 0.5ms
}

WAIVERS_FILE = Path("scripts/perf_budget_waivers.json")


def load_waivers(today: str) -> dict[str, dict]:
    """Load active (non-expired) waivers keyed by their benchmark prefix.

    A malformed or missing file yields no waivers (the gate stays strict).
    """
    if not WAIVERS_FILE.exists():
        return {}
    try:
        with open(WAIVERS_FILE) as f:
            data = json.load(f)
    except (json.JSONDecodeError, OSError) as e:
        print(f"Warning: could not parse {WAIVERS_FILE}: {e}", file=sys.stderr)
        return {}

    active: dict[str, dict] = {}
    for w in data.get("waivers", []):
        bench = w.get("benchmark", "")
        rationale = w.get("rationale", "")
        bead = w.get("bead_id", "")
        expires = w.get("expires", "")
        if not bench or not rationale or not bead or not expires:
            print(
                f"Warning: ignoring incomplete waiver (needs benchmark/rationale/"
                f"bead_id/expires): {w}",
                file=sys.stderr,
            )
            continue
        # ISO YYYY-MM-DD compares correctly as a string.
        if expires < today:
            print(
                f"Note: waiver for '{bench}' expired {expires} (bead {bead}); "
                f"budget is re-gated.",
                file=sys.stderr,
            )
            continue
        active[bench] = w
    return active


def find_waiver(group_key: str, waivers: dict[str, dict]) -> dict | None:
    """Find the longest-prefix active waiver covering a budget key."""
    best = None
    for bench, w in waivers.items():
        if group_key == bench or group_key.startswith(bench):
            if best is None or len(bench) > len(best[0]):
                best = (bench, w)
    return best[1] if best else None


def parse_estimates(estimates_file: Path) -> dict:
    """Parse a criterion estimates.json file."""
    try:
        with open(estimates_file) as f:
            data = json.load(f)
        return {
            "mean": data.get("mean", {}).get("point_estimate", 0),
            "median": data.get("median", {}).get("point_estimate", 0),
            "std_dev": data.get("std_dev", {}).get("point_estimate", 0),
        }
    except (json.JSONDecodeError, OSError) as e:
        print(f"Warning: Could not parse {estimates_file}: {e}")
        return {}


def longest_budget_key(group_path: str) -> str | None:
    """Return the longest BUDGETS key that is a path-prefix of group_path."""
    best = None
    for key in BUDGETS:
        if group_path == key or group_path.startswith(key + "/") or group_path.startswith(key):
            if best is None or len(key) > len(best):
                best = key
    return best


def collect_measurements(criterion_dir: Path) -> dict[str, float]:
    """Map each budget key to the worst (max) mean ns observed under it."""
    worst: dict[str, float] = {}
    for estimates_file in criterion_dir.glob("**/new/estimates.json"):
        rel = estimates_file.relative_to(criterion_dir)
        # Drop the trailing `new/estimates.json`; the rest is the group path.
        group_path = "/".join(rel.parts[:-2])
        key = longest_budget_key(group_path)
        if key is None:
            continue
        est = parse_estimates(estimates_file)
        if not est:
            continue
        mean_ns = est.get("mean", 0)
        if key not in worst or mean_ns > worst[key]:
            worst[key] = mean_ns
    return worst


def check_budgets(
    criterion_dir: Path, waivers: dict[str, dict]
) -> tuple[list[str], list[str], list[str]]:
    """Check measurements against budgets.

    Returns (passed, failed, waived) human-readable description lists.
    """
    passed: list[str] = []
    failed: list[str] = []
    waived: list[str] = []

    measurements = collect_measurements(criterion_dir)
    for key, mean_ns in sorted(measurements.items()):
        budget_ns = BUDGETS[key]
        desc = f"{key}: {mean_ns / 1e3:.2f}µs vs {budget_ns / 1e3:.2f}µs budget"
        if mean_ns <= budget_ns:
            passed.append(desc)
            continue
        waiver = find_waiver(key, waivers)
        if waiver is not None:
            waived.append(
                f"{desc} — WAIVED (bead {waiver['bead_id']}, expires "
                f"{waiver['expires']}): {waiver['rationale']}"
            )
        else:
            failed.append(desc)

    return passed, failed, waived


def write_summary(
    criterion_dir: Path,
    passed: list[str],
    failed: list[str],
    waived: list[str],
):
    """Write a summary file for CI reporting / PR comments."""
    summary_file = criterion_dir / "summary.txt"
    with open(summary_file, "w") as f:
        f.write("RCH Performance Budget Verification\n")
        f.write("=" * 40 + "\n\n")
        if passed:
            f.write("PASSED:\n")
            for p in passed:
                f.write(f"  OK: {p}\n")
            f.write("\n")
        if waived:
            f.write("WAIVED (tracked debt):\n")
            for w in waived:
                f.write(f"  WAIVED: {w}\n")
            f.write("\n")
        if failed:
            f.write("FAILED:\n")
            for fail in failed:
                f.write(f"  FAIL: {fail}\n")
            f.write("\n")
        f.write(
            f"\nTotal: {len(passed)} passed, {len(waived)} waived, "
            f"{len(failed)} failed\n"
        )


def main():
    """Main entry point."""
    criterion_dir = Path("target/criterion")
    if not criterion_dir.exists():
        print("Warning: target/criterion not found - skipping budget verification")
        print("Run 'cargo bench' first to generate benchmark results")
        sys.exit(0)

    today = datetime.date.today().isoformat()
    waivers = load_waivers(today)

    print("Checking performance budgets from AGENTS.md...")
    if waivers:
        print(f"Active waivers: {', '.join(sorted(waivers))}")
    print()

    passed, failed, waived = check_budgets(criterion_dir, waivers)

    if passed:
        print("PASSED:")
        for p in passed:
            print(f"  OK: {p}")
        print()
    if waived:
        print("WAIVED (tracked debt — recorded in perf_budget_waivers.json):")
        for w in waived:
            print(f"  WAIVED: {w}")
        print()
    if failed:
        print("FAILED:")
        for f in failed:
            print(f"  FAIL: {f}")
        print()

    write_summary(criterion_dir, passed, failed, waived)

    print(
        f"Total: {len(passed)} passed, {len(waived)} waived, {len(failed)} failed"
    )

    if failed:
        print("\nPERFORMANCE BUDGET VIOLATIONS DETECTED")
        print("See AGENTS.md for performance requirements.")
        print(
            "To temporarily accept a regression, add an explicit waiver with a "
            "rationale and owning bead to scripts/perf_budget_waivers.json."
        )
        sys.exit(1)

    if not passed and not waived:
        print("No benchmark results matched any budget patterns")
        print("This may be normal if benchmarks haven't been run yet")
    else:
        print("\nAll performance budgets met (waived items are tracked debt).")


if __name__ == "__main__":
    main()
