#!/usr/bin/env bash
#
# e2e_perf_budgets.sh — hot-path performance budget E2E runner for the
# session-history remediation program (bd-session-history-remediation-ocv9i.16.7).
#
# Drives the Rust budget suite (rch-common tests::remediation_hotpath_budget_e2e),
# which measures each remediation hot path with deterministic fixtures and emits
# one JSONL timing record per scenario. This runner then validates that emitted
# JSONL against the mandated program timing schema:
#
#   run_id, bead_id, scenario, event, status, command_fingerprint,
#   duration_ms, budget_ms, p95_ms, p99_ms, detail
#
# and re-emits each record (canonical field order) plus suite framing records to
# its own structured JSONL log, with human-readable progress on stderr.
#
# Exit codes (consumed by scripts/run_all_e2e.sh):
#   0  all scenarios within budget, schema valid
#   1  a scenario regressed past budget, or the JSONL schema was invalid
#   4  skipped (cargo or python3 unavailable — capability not present)
#   2  setup error
#
# Usage:
#   ./scripts/e2e_perf_budgets.sh [--run-id ID]

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
export PROJECT_ROOT

E2E_SKIP_EXIT=4

BEAD_ID="bd-session-history-remediation-ocv9i.16.7"
RUN_ID="run-$(date -u '+%Y%m%d%H%M%S')-$$-${RANDOM}"
for arg in "$@"; do
    case "$arg" in
        --run-id=*) RUN_ID="${arg#*=}" ;;
        --help|-h)
            sed -n '2,30p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'
            exit 0 ;;
    esac
done

# The Rust suite resolves its test-logs dir from CARGO_TARGET_DIR (falling back
# to the workspace target/); honor the same so we read the JSONL it actually
# wrote. Mirror the suite log into the workspace target/test-logs too, so
# run_all_e2e.sh collects it even when CARGO_TARGET_DIR points elsewhere.
TARGET_DIR="${CARGO_TARGET_DIR:-$PROJECT_ROOT/target}"
LOG_DIR="$TARGET_DIR/test-logs"
MIRROR_DIR="$PROJECT_ROOT/target/test-logs"
mkdir -p "$LOG_DIR" "$MIRROR_DIR"
SUITE_LOG="$LOG_DIR/e2e_perf_budgets.jsonl"
TEST_JSONL="$LOG_DIR/remediation_hotpath_budget.jsonl"
: > "$SUITE_LOG"

_ts() { date -u '+%Y-%m-%dT%H:%M:%S.%3NZ' 2>/dev/null || date -u '+%Y-%m-%dT%H:%M:%SZ'; }

# emit_suite <event> <status> <detail>
emit_suite() {
    printf '{"ts":"%s","run_id":"%s","bead_id":"%s","scenario":"_suite","event":"%s","status":"%s","detail":"%s"}\n' \
        "$(_ts)" "$RUN_ID" "$BEAD_ID" "$1" "$2" "$3" >> "$SUITE_LOG"
}

echo "Remediation hot-path budget E2E (run_id=$RUN_ID)"
emit_suite "suite.start" "info" "bead=$BEAD_ID"

# --- capability checks --------------------------------------------------------
if ! command -v cargo >/dev/null 2>&1; then
    echo "  ⊘ SKIP: cargo unavailable; cannot run the budget suite" >&2
    emit_suite "suite.skip" "skipped" "cargo unavailable"
    exit "$E2E_SKIP_EXIT"
fi
if ! command -v python3 >/dev/null 2>&1; then
    echo "  ⊘ SKIP: python3 unavailable; cannot validate JSONL schema" >&2
    emit_suite "suite.skip" "skipped" "python3 unavailable"
    exit "$E2E_SKIP_EXIT"
fi

# --- run the Rust budget suite ------------------------------------------------
# The emit test always lands the JSONL artifact before asserting budgets, so even
# a budget regression produces a record we can validate and report on.
echo "▶ running rch-common::remediation_hotpath_budget_e2e"
TEST_RC=0
(
    cd "$PROJECT_ROOT"
    cargo test -p rch-common --test remediation_hotpath_budget_e2e \
        -- --nocapture --test-threads=1
) || TEST_RC=$?

if [[ ! -f "$TEST_JSONL" ]]; then
    echo "  ✗ FAIL: expected timing JSONL not found at $TEST_JSONL" >&2
    emit_suite "suite.summary" "fail" "missing JSONL artifact (test rc=$TEST_RC)"
    exit 1
fi

# --- validate + normalize the emitted JSONL -----------------------------------
# Validates the mandated schema, then appends each record (canonical field order)
# to the suite log. Prints a per-scenario summary and exits nonzero on any
# missing field or any scenario whose recorded status is "fail".
echo "▶ validating timing JSONL schema: $TEST_JSONL"
VALIDATE_RC=0
python3 - "$TEST_JSONL" "$SUITE_LOG" "$RUN_ID" "$BEAD_ID" <<'PY' || VALIDATE_RC=$?
import json
import sys

test_jsonl, suite_log, run_id, bead_id = sys.argv[1:5]

REQUIRED = [
    "run_id", "bead_id", "scenario", "event", "status",
    "command_fingerprint", "duration_ms", "budget_ms", "p95_ms", "p99_ms",
    "detail",
]
NUMERIC = ["duration_ms", "budget_ms", "p95_ms", "p99_ms"]

records = []
with open(test_jsonl) as f:
    for ln, line in enumerate(f, 1):
        line = line.strip()
        if not line:
            continue
        try:
            records.append((ln, json.loads(line)))
        except json.JSONDecodeError as e:
            print(f"  ✗ line {ln} is not valid JSON: {e}", file=sys.stderr)
            sys.exit(1)

if not records:
    print("  ✗ no timing records emitted", file=sys.stderr)
    sys.exit(1)

problems = 0
regressions = 0
passes = 0
out = open(suite_log, "a")
for ln, rec in records:
    missing = [k for k in REQUIRED if k not in rec]
    if missing:
        print(f"  ✗ {rec.get('scenario','?')}: missing fields {missing}", file=sys.stderr)
        problems += 1
        continue
    bad_num = [k for k in NUMERIC if not isinstance(rec[k], (int, float))]
    if bad_num:
        print(f"  ✗ {rec['scenario']}: non-numeric {bad_num}", file=sys.stderr)
        problems += 1
        continue
    if rec["bead_id"] != bead_id:
        print(f"  ✗ {rec['scenario']}: bead_id {rec['bead_id']} != {bead_id}", file=sys.stderr)
        problems += 1
        continue
    status = rec["status"]
    if status not in ("pass", "fail"):
        print(f"  ✗ {rec['scenario']}: bad status '{status}'", file=sys.stderr)
        problems += 1
        continue

    # Canonical, ordered re-emit into the suite log.
    norm = {k: rec[k] for k in ("run_id", "bead_id", "scenario", "event", "status",
                                "command_fingerprint", "duration_ms", "budget_ms",
                                "p95_ms", "p99_ms", "detail")}
    out.write(json.dumps(norm) + "\n")

    if status == "fail":
        regressions += 1
        print(f"  ✗ REGRESSION {rec['scenario']}: p95={rec['p95_ms']}ms budget={rec['budget_ms']}ms",
              file=sys.stderr)
    else:
        passes += 1
        print(f"  ✓ {rec['scenario']}: p50={rec['duration_ms']}ms p95={rec['p95_ms']}ms "
              f"(budget {rec['budget_ms']}ms, {rec.get('cache_mode','n/a')}, "
              f"records={rec.get('record_count',0)})")
out.close()

print(f"\nschema: {len(records)} records, {problems} malformed; "
      f"budgets: {passes} pass, {regressions} regressed", file=sys.stderr)
if problems or regressions:
    sys.exit(1)
sys.exit(0)
PY

# --- summary ------------------------------------------------------------------
# Mirror the suite log to the workspace target/test-logs so run_all_e2e.sh and CI
# collect it even when CARGO_TARGET_DIR points outside the repo.
if [[ "$LOG_DIR" != "$MIRROR_DIR" ]]; then
    cp -f "$SUITE_LOG" "$MIRROR_DIR/e2e_perf_budgets.jsonl" 2>/dev/null || true
    cp -f "$TEST_JSONL" "$MIRROR_DIR/remediation_hotpath_budget.jsonl" 2>/dev/null || true
fi

if [[ $VALIDATE_RC -eq 0 && $TEST_RC -eq 0 ]]; then
    echo "  ✓ all remediation hot-path budgets within target; schema valid"
    emit_suite "suite.summary" "pass" "all budgets met; schema valid"
    echo "  JSONL: $SUITE_LOG"
    exit 0
fi

echo "  ✗ FAIL: budget regression or schema violation (test rc=$TEST_RC, validate rc=$VALIDATE_RC)" >&2
emit_suite "suite.summary" "fail" "test_rc=$TEST_RC validate_rc=$VALIDATE_RC"
echo "  JSONL: $SUITE_LOG" >&2
exit 1
