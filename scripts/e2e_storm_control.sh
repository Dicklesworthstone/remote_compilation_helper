#!/usr/bin/env bash
#
# e2e_storm_control.sh — multi-agent load fairness and storm-control E2E runner
# for the session-history remediation program
# (bd-session-history-remediation-ocv9i.10.4).
#
# Drives the deterministic mock-worker storm suite
# (rch-common tests::storm_control_e2e + the storm_control unit tests), which
# launches many concurrent build/test/check jobs against a simulated fleet and
# proves the scheduler/admission/queue/fallback stay coherent under contention:
#   - fairness / load spreading
#   - no duplicate remote job ids
#   - no unbounded local fallback storm
#   - no stuck wrapper without attach/cancel guidance
#   - no work to a bypassed / admin-disabled / capability-inadmissible worker
#
# The suite emits a SmokeProfileEvent JSONL trace (storm_control.jsonl) plus a
# _summary record; this runner validates that JSONL against the mandated program
# field set:
#
#   run_id, bead_id, scenario, event, status, duration_ms
#   + load fields: local_job_id, remote_job_id, queue_depth, selected_worker,
#                  fallback_decision, detail
#
# and re-frames the run into its own structured JSONL log, with human-readable
# progress on stderr.
#
# Exit codes (consumed by scripts/run_all_e2e.sh):
#   0  all invariants held, schema valid
#   1  an invariant failed, or the JSONL schema was invalid
#   4  skipped (cargo or python3 unavailable — capability not present)
#   2  setup error
#
# Usage:
#   ./scripts/e2e_storm_control.sh [--run-id=ID]

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
export PROJECT_ROOT

E2E_SKIP_EXIT=4

BEAD_ID="bd-session-history-remediation-ocv9i.10.4"
RUN_ID="run-$(date -u '+%Y%m%d%H%M%S')-$$-${RANDOM}"
for arg in "$@"; do
    case "$arg" in
        --run-id=*) RUN_ID="${arg#*=}" ;;
        --help|-h)
            sed -n '2,33p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'
            exit 0 ;;
    esac
done

# Honor CARGO_TARGET_DIR (the Rust suite writes its artifact there), falling back
# to the workspace target/. Mirror into the workspace target/test-logs too so
# run_all_e2e.sh collects it even when CARGO_TARGET_DIR points elsewhere.
TARGET_DIR="${CARGO_TARGET_DIR:-$PROJECT_ROOT/target}"
LOG_DIR="$TARGET_DIR/test-logs"
MIRROR_DIR="$PROJECT_ROOT/target/test-logs"
mkdir -p "$LOG_DIR" "$MIRROR_DIR"
SUITE_LOG="$LOG_DIR/e2e_storm_control.jsonl"
TEST_JSONL="$LOG_DIR/storm_control.jsonl"
: > "$SUITE_LOG"

_ts() { date -u '+%Y-%m-%dT%H:%M:%S.%3NZ' 2>/dev/null || date -u '+%Y-%m-%dT%H:%M:%SZ'; }

# emit_suite <event> <status> <detail>
emit_suite() {
    printf '{"ts":"%s","run_id":"%s","bead_id":"%s","scenario":"_suite","event":"%s","status":"%s","detail":"%s"}\n' \
        "$(_ts)" "$RUN_ID" "$BEAD_ID" "$1" "$2" "$3" >> "$SUITE_LOG"
}

echo "Multi-agent storm-control E2E (run_id=$RUN_ID)"
emit_suite "suite.start" "info" "bead=$BEAD_ID"

# --- capability checks --------------------------------------------------------
if ! command -v cargo >/dev/null 2>&1; then
    echo "  ⊘ SKIP: cargo unavailable; cannot run the storm suite" >&2
    emit_suite "suite.skip" "skipped" "cargo unavailable"
    exit "$E2E_SKIP_EXIT"
fi
if ! command -v python3 >/dev/null 2>&1; then
    echo "  ⊘ SKIP: python3 unavailable; cannot validate JSONL schema" >&2
    emit_suite "suite.skip" "skipped" "python3 unavailable"
    exit "$E2E_SKIP_EXIT"
fi

# --- run the Rust storm suite -------------------------------------------------
# The integration suite both asserts the invariants and (via
# e2e_storm_emit_jsonl_artifact) lands the JSONL trace before exiting, so even an
# invariant regression produces a record we can validate and report on.
echo "▶ running rch-common::storm_control_e2e + unit checkers"
TEST_RC=0
(
    cd "$PROJECT_ROOT"
    cargo test -p rch-common --test storm_control_e2e -- --nocapture --test-threads=1
    cargo test -p rch-common --lib storm_control:: -- --test-threads=1
) || TEST_RC=$?

if [[ "$TEST_RC" -ne 0 ]]; then
    echo "  ✗ FAIL: storm-control suite returned $TEST_RC" >&2
    emit_suite "suite.summary" "fail" "rust suite rc=$TEST_RC"
    exit 1
fi

if [[ ! -f "$TEST_JSONL" ]]; then
    echo "  ✗ FAIL: expected storm JSONL not found at $TEST_JSONL" >&2
    emit_suite "suite.summary" "fail" "missing JSONL artifact"
    exit 1
fi

# --- validate the emitted JSONL -----------------------------------------------
echo "▶ validating storm JSONL schema: $TEST_JSONL"
VALIDATE_RC=0
python3 - "$TEST_JSONL" "$SUITE_LOG" "$RUN_ID" "$BEAD_ID" <<'PY' || VALIDATE_RC=$?
import json
import sys

test_jsonl, suite_log, run_id, bead_id = sys.argv[1:5]

# Every event line carries these.
BASE = ["run_id", "bead_id", "scenario", "event", "status", "duration_ms"]
# These load fields must appear somewhere across the trace.
LOAD = ["local_job_id", "remote_job_id", "queue_depth", "selected_worker",
        "fallback_decision", "detail"]
# The summary record carries these statistics.
SUMMARY = ["total_jobs", "remote_successes", "local_fallbacks", "proof_refusals",
           "queue_timeouts", "cancellations", "p95_queue_wait_ms",
           "p95_end_to_end_ms"]

events = []
summary = None
with open(test_jsonl) as f:
    for ln, line in enumerate(f, 1):
        line = line.strip()
        if not line:
            continue
        try:
            rec = json.loads(line)
        except json.JSONDecodeError as e:
            print(f"  ✗ line {ln} is not valid JSON: {e}", file=sys.stderr)
            sys.exit(1)
        if rec.get("scenario") == "_summary":
            summary = rec
        else:
            events.append((ln, rec))

if not events:
    print("  ✗ no storm events emitted", file=sys.stderr)
    sys.exit(1)

problems = 0
seen_load = set()
for ln, rec in events:
    missing = [k for k in BASE if k not in rec]
    if missing:
        print(f"  ✗ line {ln} ({rec.get('event','?')}): missing base fields {missing}",
              file=sys.stderr)
        problems += 1
    if rec.get("scenario") != "load_storm_control":
        print(f"  ✗ line {ln}: unexpected scenario {rec.get('scenario')!r}", file=sys.stderr)
        problems += 1
    for k in LOAD:
        if k in rec:
            seen_load.add(k)

missing_load = [k for k in LOAD if k not in seen_load]
if missing_load:
    print(f"  ✗ load fields never appeared in the trace: {missing_load}", file=sys.stderr)
    problems += 1

if summary is None:
    print("  ✗ no _summary record emitted", file=sys.stderr)
    problems += 1
else:
    miss = [k for k in SUMMARY if k not in summary]
    if miss:
        print(f"  ✗ _summary missing statistics: {miss}", file=sys.stderr)
        problems += 1
    else:
        resolved = (summary["remote_successes"] + summary["local_fallbacks"]
                    + summary["proof_refusals"] + summary["cancellations"])
        if resolved != summary["total_jobs"]:
            print(f"  ✗ summary inconsistent: {resolved} resolved != "
                  f"{summary['total_jobs']} total", file=sys.stderr)
            problems += 1

with open(suite_log, "a") as out:
    status = "ok" if problems == 0 else "fail"
    out.write(json.dumps({
        "run_id": run_id, "bead_id": bead_id, "scenario": "_validate",
        "event": "schema.validate", "status": status,
        "event_lines": len(events),
        "summary": summary if summary else {},
    }) + "\n")

if problems:
    print(f"  ✗ {problems} schema problem(s)", file=sys.stderr)
    sys.exit(1)

s = summary or {}
print(f"  ✓ {len(events)} storm events, schema valid; "
      f"total={s.get('total_jobs')} remote={s.get('remote_successes')} "
      f"local_fallback={s.get('local_fallbacks')} proof_refused={s.get('proof_refusals')} "
      f"cancelled={s.get('cancellations')} p95_e2e={s.get('p95_end_to_end_ms')}ms")
PY

# Mirror artifacts so run_all_e2e.sh collects them regardless of target dir.
if [[ "$LOG_DIR" != "$MIRROR_DIR" ]]; then
    cp -f "$SUITE_LOG" "$MIRROR_DIR/" 2>/dev/null || true
    cp -f "$TEST_JSONL" "$MIRROR_DIR/" 2>/dev/null || true
fi

if [[ "$VALIDATE_RC" -ne 0 ]]; then
    emit_suite "suite.summary" "fail" "JSONL schema invalid"
    exit 1
fi

emit_suite "suite.summary" "ok" "all storm-control invariants held; JSONL schema valid"
echo "✓ storm-control E2E passed"
exit 0
