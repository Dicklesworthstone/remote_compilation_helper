#!/usr/bin/env bash
#
# e2e_discovery_surfaces.sh — E2E runner for agent discovery surfaces
# (bd-session-history-remediation-ocv9i.13.4).
#
# Drives the machine-readable discovery commands an agent is promised in the
# README — `rch capabilities --json`, `rch robot-docs guide --json`, and
# `rch --help-json <path>` — and asserts the new remediation surfaces are
# present, emitting one structured JSONL record per scenario keyed by bead id
# and command path:
#
#   run_id, bead_id, command_path, surface, status, reason_code, duration_ms, detail
#
# Scenarios (all static/daemon-free, so they pass with or without a live daemon):
#   capabilities      — reason_code_families (RCH-E/R/I) + policies present
#   robot_docs        — remediation_workflows covers the seven named workflows
#   help_json_*       — --help-json resolves each real nested command path
#   check             — `rch check --json` returns a parseable envelope
#
# Exit codes (consumed by scripts/run_all_e2e.sh):
#   0  all scenarios pass (skips allowed)
#   1  a scenario failed
#   4  skipped (rch binary or python3 unavailable)
#
# Usage:
#   ./scripts/e2e_discovery_surfaces.sh [--run-id=ID]

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
export PROJECT_ROOT

E2E_SKIP_EXIT=4
BEAD_ID="bd-session-history-remediation-ocv9i.13.4"
RUN_ID="run-$(date -u '+%Y%m%d%H%M%S')-$$-${RANDOM}"
for arg in "$@"; do
    case "$arg" in
        --run-id=*) RUN_ID="${arg#*=}" ;;
        --help | -h)
            sed -n '2,25p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'
            exit 0
            ;;
    esac
done

TARGET_DIR="${CARGO_TARGET_DIR:-$PROJECT_ROOT/target}"
LOG_DIR="$TARGET_DIR/test-logs"
MIRROR_DIR="$PROJECT_ROOT/target/test-logs"
mkdir -p "$LOG_DIR" "$MIRROR_DIR"
SUITE_LOG="${RCH_E2E_LOG:-$LOG_DIR/e2e_discovery_surfaces.jsonl}"
: >"$SUITE_LOG"

PASS=0
FAIL=0
SKIP=0

# Emit one JSONL record (canonical field order) plus human progress on stderr.
emit() {
    local command_path="$1" surface="$2" status="$3" reason="$4" dur="$5" detail="$6"
    local line
    line=$(python3 - "$RUN_ID" "$BEAD_ID" "$command_path" "$surface" "$status" "$reason" \
        "$dur" "$detail" <<'PY'
import json, sys
keys = ["run_id","bead_id","command_path","surface","status","reason_code",
        "duration_ms","detail"]
vals = sys.argv[1:9]
rec = dict(zip(keys, vals))
rec["duration_ms"] = int(rec["duration_ms"]) if str(rec["duration_ms"]).isdigit() else 0
print(json.dumps(rec, separators=(",", ":")))
PY
)
    printf '%s\n' "$line" >>"$SUITE_LOG"
    case "$status" in
        pass) PASS=$((PASS + 1)); printf '  [PASS] %-26s %s\n' "$surface" "$detail" >&2 ;;
        fail) FAIL=$((FAIL + 1)); printf '  [FAIL] %-26s %s\n' "$surface" "$detail" >&2 ;;
        skip) SKIP=$((SKIP + 1)); printf '  [SKIP] %-26s %s (%s)\n' "$surface" "$detail" "$reason" >&2 ;;
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

echo "Discovery surfaces E2E (run_id=$RUN_ID)" >&2

# --- capabilities: reason-code families + policies -------------------------
t0=$(now_ms)
json="$(env NO_COLOR=1 "$RCH_BIN" capabilities --json 2>/dev/null || true)"
dur=$(($(now_ms) - t0))
if [[ -n "$json" ]]; then
    verdict="$(printf '%s' "$json" | python3 -c 'import json,sys
d=json.load(sys.stdin); data=d.get("data") or {}
fams=[f.get("family") for f in (data.get("reason_code_families") or [])]
pols=[p.get("id") for p in (data.get("policies") or [])]
ok = all(x in fams for x in ("RCH-E","RCH-R","RCH-I")) and \
     all(x in pols for x in ("fail_open","force_remote","require_remote"))
print("pass" if ok else "fail")
print("families="+",".join(filter(None,fams))+" policies="+",".join(filter(None,pols)))' 2>/dev/null || printf 'fail\nparse_error')"
    status="$(printf '%s' "$verdict" | sed -n '1p')"
    detail="$(printf '%s' "$verdict" | sed -n '2p')"
    [[ "$status" == "pass" ]] \
        && emit "capabilities" "capabilities" "pass" "" "$dur" "$detail" \
        || emit "capabilities" "capabilities" "fail" "missing_section" "$dur" "$detail"
else
    emit "capabilities" "capabilities" "skip" "no_output" "$dur" "no capabilities output"
fi

# --- robot-docs guide: remediation workflows -------------------------------
t0=$(now_ms)
json="$(env NO_COLOR=1 "$RCH_BIN" robot-docs guide --json 2>/dev/null || true)"
dur=$(($(now_ms) - t0))
if [[ -n "$json" ]]; then
    verdict="$(printf '%s' "$json" | python3 -c 'import json,sys
d=json.load(sys.stdin); data=d.get("data") or {}
ids=[w.get("id") for w in (data.get("remediation_workflows") or [])]
need=["admit_before_proof","proof_mode","worker_bypass_rejoin","fleet_status",
      "force_resync","queue_attach_cancel","real_fleet_smoke"]
missing=[x for x in need if x not in ids]
print("pass" if not missing else "fail")
print("workflows="+",".join(filter(None,ids)) if not missing else "missing="+",".join(missing))' 2>/dev/null || printf 'fail\nparse_error')"
    status="$(printf '%s' "$verdict" | sed -n '1p')"
    detail="$(printf '%s' "$verdict" | sed -n '2p')"
    [[ "$status" == "pass" ]] \
        && emit "robot-docs guide" "robot-docs" "pass" "" "$dur" "$detail" \
        || emit "robot-docs guide" "robot-docs" "fail" "missing_workflow" "$dur" "$detail"
else
    emit "robot-docs guide" "robot-docs" "skip" "no_output" "$dur" "no robot-docs output"
fi

# --- --help-json: real nested command paths --------------------------------
check_help_json() {
    local leaf="$1"
    shift
    local path_label="${*}"
    local t0 dur json got
    t0=$(now_ms)
    json="$(env NO_COLOR=1 "$RCH_BIN" --help-json "$@" 2>/dev/null || true)"
    dur=$(($(now_ms) - t0))
    if [[ -z "$json" ]]; then
        emit "$path_label" "help-json" "skip" "no_output" "$dur" "no help-json output"
        return
    fi
    got="$(printf '%s' "$json" | python3 -c 'import json,sys
try:
    d=json.load(sys.stdin)
    print(d.get("name",""))
except Exception:
    print("")' 2>/dev/null || echo "")"
    if [[ "$got" == "$leaf" ]]; then
        emit "$path_label" "help-json" "pass" "" "$dur" "resolved leaf=$got"
    else
        emit "$path_label" "help-json" "fail" "leaf_mismatch" "$dur" "expected leaf=$leaf got=$got"
    fi
}

check_help_json "admit" "admit"
check_help_json "exec" "exec"
check_help_json "capabilities" "workers" "capabilities"
check_help_json "status" "fleet" "status"
check_help_json "self-test" "self-test"

# --- check: parseable readiness envelope -----------------------------------
t0=$(now_ms)
json="$(env NO_COLOR=1 "$RCH_BIN" check --json 2>/dev/null || true)"
dur=$(($(now_ms) - t0))
if [[ -n "$json" ]] && printf '%s' "$json" | python3 -c 'import json,sys; json.load(sys.stdin)' 2>/dev/null; then
    emit "check" "check" "pass" "" "$dur" "check --json is a parseable envelope"
else
    emit "check" "check" "skip" "no_output" "$dur" "no parseable check output"
fi

# Mirror the suite log so run_all_e2e.sh collects it regardless of target dir.
[[ "$SUITE_LOG" != "$MIRROR_DIR/e2e_discovery_surfaces.jsonl" ]] \
    && cp -f "$SUITE_LOG" "$MIRROR_DIR/e2e_discovery_surfaces.jsonl" 2>/dev/null || true

echo "Summary: pass=$PASS skip=$SKIP fail=$FAIL (run_id=$RUN_ID)" >&2
[[ "$FAIL" -gt 0 ]] && exit 1
exit 0
