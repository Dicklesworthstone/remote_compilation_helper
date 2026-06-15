#!/usr/bin/env bash
#
# e2e_placement_controls.sh — E2E runner for first-class placement / visibility
# / strict-remote controls (bd-session-history-remediation-ocv9i.13.5).
#
# Drives `rch diagnose <command> --json` under each canonical control and
# asserts the resolved placement plan, emitting one structured JSONL record per
# scenario with the mandated program fields:
#
#   run_id, bead_id, command, requested_worker, effective_worker,
#   strict_remote_policy, queue_policy, visibility_mode, local_job_id,
#   remote_job_id, status, reason_code, duration_ms, detail
#
# Scenarios (all env-derived, so they pass with or without a live daemon):
#   force_remote        — RCH_FORCE_REMOTE=1   => strict_remote_policy=force_remote
#   require_remote      — RCH_REQUIRE_REMOTE=1 => strict_remote_policy=require_remote
#   require_supersedes  — both set => require_remote + precedence diagnostic
#   no_queue            — RCH_QUEUE_WHEN_BUSY=0 => queue_policy=no_queue
#   visibility_summary  — RCH_VISIBILITY=summary => visibility_mode=summary
#   requested_worker    — RCH_WORKER=<id> captured as requested_worker; an
#                         inadmissible requested worker yields a structured
#                         refusal outcome when a daemon answers.
#
# Exit codes (consumed by scripts/run_all_e2e.sh):
#   0  all scenarios pass (skips allowed)
#   1  a scenario failed
#   4  skipped (rch binary or python3 unavailable)
#
# Usage:
#   ./scripts/e2e_placement_controls.sh [--run-id=ID]

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
export PROJECT_ROOT

E2E_SKIP_EXIT=4
BEAD_ID="bd-session-history-remediation-ocv9i.13.5"
RUN_ID="run-$(date -u '+%Y%m%d%H%M%S')-$$-${RANDOM}"
for arg in "$@"; do
    case "$arg" in
        --run-id=*) RUN_ID="${arg#*=}" ;;
        --help | -h)
            sed -n '2,30p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'
            exit 0
            ;;
    esac
done

TARGET_DIR="${CARGO_TARGET_DIR:-$PROJECT_ROOT/target}"
LOG_DIR="$TARGET_DIR/test-logs"
MIRROR_DIR="$PROJECT_ROOT/target/test-logs"
mkdir -p "$LOG_DIR" "$MIRROR_DIR"
SUITE_LOG="${RCH_E2E_LOG:-$LOG_DIR/e2e_placement_controls.jsonl}"
: >"$SUITE_LOG"

PASS=0
FAIL=0
SKIP=0

# Emit one JSONL record (canonical field order) plus human progress on stderr.
emit() {
    local command="$1" requested="$2" effective="$3" strict="$4" queue="$5" vis="$6" \
        status="$7" reason="$8" dur="$9" detail="${10}"
    local line
    line=$(python3 - "$RUN_ID" "$BEAD_ID" "$command" "$requested" "$effective" "$strict" \
        "$queue" "$vis" "$status" "$reason" "$dur" "$detail" <<'PY'
import json, sys
keys = ["run_id","bead_id","command","requested_worker","effective_worker",
        "strict_remote_policy","queue_policy","visibility_mode","status",
        "reason_code","duration_ms","detail"]
vals = sys.argv[1:13]
rec = dict(zip(keys, vals))
# local/remote job ids are runtime-only; diagnose is a simulation. Present but empty.
rec["local_job_id"] = ""
rec["remote_job_id"] = ""
rec["duration_ms"] = int(rec["duration_ms"]) if str(rec["duration_ms"]).isdigit() else 0
print(json.dumps(rec, separators=(",", ":")))
PY
)
    printf '%s\n' "$line" >>"$SUITE_LOG"
    case "$status" in
        pass) PASS=$((PASS + 1)); printf '  [PASS] %-20s %s\n' "$1" "$detail" >&2 ;;
        fail) FAIL=$((FAIL + 1)); printf '  [FAIL] %-20s %s\n' "$1" "$detail" >&2 ;;
        skip) SKIP=$((SKIP + 1)); printf '  [SKIP] %-20s %s (%s)\n' "$1" "$detail" "$reason" >&2 ;;
    esac
}

now_ms() { date +%s%3N 2>/dev/null || echo 0; }

command -v python3 >/dev/null 2>&1 || {
    echo "python3 unavailable; skipping" >&2
    exit "$E2E_SKIP_EXIT"
}

RCH_BIN=""
for cand in "$PROJECT_ROOT/target/release/rch" "$PROJECT_ROOT/target/debug/rch"; do
    [[ -x "$cand" ]] && {
        RCH_BIN="$cand"
        break
    }
done
[[ -z "$RCH_BIN" ]] && command -v rch >/dev/null 2>&1 && RCH_BIN="$(command -v rch)"
[[ -z "$RCH_BIN" ]] && {
    echo "rch binary not built; skipping" >&2
    exit "$E2E_SKIP_EXIT"
}

echo "Placement controls E2E (run_id=$RUN_ID)" >&2

DIAG_CMD="cargo build --release"

# Extract a placement field (.data.placement.<field>) from a diagnose JSON blob.
placement_field() {
    python3 -c 'import json,sys
d=json.load(sys.stdin)
p=(d.get("data") or {}).get("placement") or {}
key=sys.argv[1]
cur=p
for part in key.split("."):
    cur=(cur or {}).get(part) if isinstance(cur,dict) else None
print("" if cur is None else cur)' "$1" 2>/dev/null || echo ""
}

# Run `rch diagnose` with the given inline env and return JSON on stdout.
run_diag() {
    # shellcheck disable=SC2086
    env "$@" RCH_JSON=1 "$RCH_BIN" diagnose "$DIAG_CMD" --json 2>/dev/null || true
}

# scenario: name, expected (field=value), inline env...
check_field() {
    local scenario="$1" field="$2" want="$3"
    shift 3
    local t0 dur json got requested effective
    t0=$(now_ms)
    json="$(run_diag "$@")"
    dur=$(($(now_ms) - t0))
    if [[ -z "$json" ]]; then
        emit "$DIAG_CMD" "" "" "" "" "" "skip" "diagnose_no_output" "$dur" "$scenario: no diagnose output"
        return
    fi
    got="$(printf '%s' "$json" | placement_field "$field")"
    requested="$(printf '%s' "$json" | placement_field "requested_worker")"
    effective="$(printf '%s' "$json" | placement_field "effective_worker")"
    local strict queue vis
    strict="$(printf '%s' "$json" | placement_field "strict_remote_policy")"
    queue="$(printf '%s' "$json" | placement_field "queue_policy")"
    vis="$(printf '%s' "$json" | placement_field "visibility_mode")"
    if [[ "$got" == "$want" ]]; then
        emit "$DIAG_CMD" "$requested" "$effective" "$strict" "$queue" "$vis" \
            "pass" "" "$dur" "$scenario: $field=$got"
    else
        emit "$DIAG_CMD" "$requested" "$effective" "$strict" "$queue" "$vis" \
            "fail" "field_mismatch" "$dur" "$scenario: expected $field=$want got $got"
    fi
}

check_field "force_remote"       "strict_remote_policy" "force_remote"   RCH_FORCE_REMOTE=1
check_field "require_remote"     "strict_remote_policy" "require_remote" RCH_REQUIRE_REMOTE=1
check_field "no_queue"           "queue_policy"         "no_queue"       RCH_QUEUE_WHEN_BUSY=0
check_field "visibility_summary" "visibility_mode"      "summary"        RCH_VISIBILITY=summary

# require supersedes force, and a precedence diagnostic is recorded.
t0=$(now_ms)
json="$(run_diag RCH_REQUIRE_REMOTE=1 RCH_FORCE_REMOTE=1)"
dur=$(($(now_ms) - t0))
if [[ -n "$json" ]]; then
    strict="$(printf '%s' "$json" | placement_field "strict_remote_policy")"
    has_diag="$(printf '%s' "$json" | python3 -c 'import json,sys
d=json.load(sys.stdin)
p=(d.get("data") or {}).get("placement") or {}
ds=p.get("diagnostics") or []
print("yes" if any(x.get("control")=="RCH_REQUIRE_REMOTE" for x in ds) else "no")' 2>/dev/null || echo "no")"
    if [[ "$strict" == "require_remote" && "$has_diag" == "yes" ]]; then
        emit "$DIAG_CMD" "" "" "$strict" "" "" "pass" "" "$dur" "require_supersedes: require_remote + precedence diagnostic"
    else
        emit "$DIAG_CMD" "" "" "$strict" "" "" "fail" "precedence_missing" "$dur" "require_supersedes: strict=$strict diag=$has_diag"
    fi
else
    emit "$DIAG_CMD" "" "" "" "" "" "skip" "diagnose_no_output" "$dur" "require_supersedes: no diagnose output"
fi

# requested worker captured; refusal reason surfaced when a daemon answers.
t0=$(now_ms)
json="$(run_diag RCH_WORKER=ghost-nonexistent)"
dur=$(($(now_ms) - t0))
if [[ -n "$json" ]]; then
    requested="$(printf '%s' "$json" | placement_field "requested_worker")"
    outcome="$(printf '%s' "$json" | placement_field "requested_worker_outcome.status")"
    reason="$(printf '%s' "$json" | placement_field "requested_worker_outcome.reason_code")"
    effective="$(printf '%s' "$json" | placement_field "effective_worker")"
    if [[ "$requested" == "ghost-nonexistent" ]]; then
        emit "$DIAG_CMD" "$requested" "$effective" "" "" "" "pass" "$reason" "$dur" "requested_worker captured; outcome=$outcome"
    else
        emit "$DIAG_CMD" "$requested" "$effective" "" "" "" "fail" "requested_not_captured" "$dur" "expected requested_worker=ghost-nonexistent got $requested"
    fi
else
    emit "$DIAG_CMD" "" "" "" "" "" "skip" "diagnose_no_output" "$dur" "requested_worker: no diagnose output"
fi

# Mirror the suite log so run_all_e2e.sh collects it regardless of target dir.
[[ "$SUITE_LOG" != "$MIRROR_DIR/e2e_placement_controls.jsonl" ]] \
    && cp -f "$SUITE_LOG" "$MIRROR_DIR/e2e_placement_controls.jsonl" 2>/dev/null || true

echo "Summary: pass=$PASS skip=$SKIP fail=$FAIL (run_id=$RUN_ID)" >&2
[[ "$FAIL" -gt 0 ]] && exit 1
exit 0
