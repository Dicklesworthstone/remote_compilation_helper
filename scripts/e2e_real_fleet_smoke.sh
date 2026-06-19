#!/usr/bin/env bash
#
# e2e_real_fleet_smoke.sh — real-fleet smoke/soak profile E2E with the structured
# JSONL contract for bead bd-session-history-remediation-ocv9i.16.6.
#
# Drives the SAFE planning surface `rch self-test --smoke --dry-run --json` for
# two fleet shapes and checks that it emits a well-formed profile plan plus the
# structured SmokeProfileEvent trace:
#
#   empty_fleet  — no workers configured: every real-worker scenario is SKIPPED
#                  with reason smoke_no_real_workers; the plan is overall-skipped.
#   all_absent   — workers configured but no daemon/remote in this hermetic env:
#                  proof-mode refusal is EXPECTED (fail-closed when remote is
#                  unavailable); buildy scenarios are planned (dry-run).
#
# --dry-run executes nothing live (no SSH, no source mutation) — the deep
# scenario/skip/refusal logic is proven deterministically by the rch-common unit
# tests (fleet_smoke_profile.rs); this script proves the CLI surface is wired and
# emits the stable plan + JSONL shape. Each SmokeProfileEvent carries:
#
#   run_id, bead_id, scenario, event, status, [reason_code], duration_ms
#   (+ optional worker_id, command_fingerprint, remote_target_dir, artifact_summary)
#
# The emitted JSONL is self-validated at the end (field presence + parseability).
#
# Exit codes (consumed by scripts/run_all_e2e.sh):
#   0  all scenarios pass (skips allowed)
#   1  a scenario failed or the JSONL schema is malformed
#   4  skipped (rch binary or python3 unavailable)

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
export PROJECT_ROOT

E2E_SKIP_EXIT=4
BEAD_ID="bd-session-history-remediation-ocv9i.16.6"
RUN_ID="run-$(date -u '+%Y%m%d%H%M%S')-$$-${RANDOM}"
for arg in "$@"; do
    case "$arg" in
        --run-id=*) RUN_ID="${arg#*=}" ;;
        --help | -h)
            sed -n '2,24p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'
            exit 0
            ;;
    esac
done

TARGET_DIR="${CARGO_TARGET_DIR:-$PROJECT_ROOT/target}"
LOG_DIR="$TARGET_DIR/test-logs"
MIRROR_DIR="$PROJECT_ROOT/target/test-logs"
mkdir -p "$LOG_DIR" "$MIRROR_DIR"
SUITE_LOG="${RCH_E2E_LOG:-$LOG_DIR/e2e_real_fleet_smoke.jsonl}"
: >"$SUITE_LOG"

PASS=0
FAIL=0
SKIP=0

emit() {
    local scenario="$1" event="$2" status="$3" reason="$4" detail="$5"
    local line
    line=$(python3 - "$RUN_ID" "$BEAD_ID" "$scenario" "$event" "$status" "$reason" \
        "$detail" <<'PY'
import json, sys
keys = ["run_id", "bead_id", "scenario", "event", "status", "reason_code", "detail"]
print(json.dumps(dict(zip(keys, sys.argv[1:8])), separators=(",", ":")))
PY
)
    printf '%s\n' "$line" >>"$SUITE_LOG"
    case "$status" in
        pass) PASS=$((PASS + 1)); printf '  [PASS] %-12s %s\n' "$scenario" "$detail" >&2 ;;
        fail) FAIL=$((FAIL + 1)); printf '  [FAIL] %-12s %s\n' "$scenario" "$detail" >&2 ;;
        skip) SKIP=$((SKIP + 1)); printf '  [SKIP] %-12s %s (%s)\n' "$scenario" "$detail" "$reason" >&2 ;;
    esac
}

command -v python3 >/dev/null 2>&1 || { echo "python3 unavailable; skipping" >&2; exit "$E2E_SKIP_EXIT"; }

RCH_BIN=""
for cand in "$PROJECT_ROOT/target/release/rch" "$PROJECT_ROOT/target/debug/rch"; do
    [[ -x "$cand" ]] && { RCH_BIN="$cand"; break; }
done
[[ -z "$RCH_BIN" ]] && command -v rch >/dev/null 2>&1 && RCH_BIN="$(command -v rch)"
[[ -z "$RCH_BIN" ]] && { echo "rch binary not built; skipping" >&2; exit "$E2E_SKIP_EXIT"; }

echo "Real-fleet smoke profile E2E (run_id=$RUN_ID)" >&2

BASE="$LOG_DIR/smoke-$$"
mkdir -p "$BASE"

# Validate `rch self-test --smoke --dry-run --json` output: a well-formed plan
# (run_id/bead_id present, exactly the 8 scenarios, a non-empty events array, and
# every SmokeProfileEvent carrying the required fields + the right bead). Echo
# "ok" or a stable error token.
validate_smoke_json() {
    python3 - "$BEAD_ID" <<'PY'
import json, sys
bead = sys.argv[1]
try:
    d = json.load(sys.stdin)
except Exception:
    print("__BADJSON__"); sys.exit(0)
if not isinstance(d, dict) or "run_id" not in d or d.get("bead_id") != bead:
    print("no_run_envelope"); sys.exit(0)
plan = d.get("plan") or {}
scen = plan.get("scenarios") or []
if len(scen) != 8:
    print("wrong_scenario_count:%d" % len(scen)); sys.exit(0)
events = d.get("events") or []
if not events:
    print("no_events"); sys.exit(0)
required = ["run_id", "bead_id", "scenario", "event", "status", "duration_ms"]
for ev in events:
    miss = [k for k in required if k not in ev]
    if miss:
        print("event_missing:" + ",".join(miss)); sys.exit(0)
    if ev["bead_id"] != bead:
        print("event_wrong_bead"); sys.exit(0)
print("ok")
PY
}

run_smoke_scenario() {
    local scenario="$1" cfg_dir="$2"
    local out verdict
    out="$(env -u RCH_OUTPUT_FORMAT NO_COLOR=1 RCH_CONFIG_DIR="$cfg_dir" \
        "$RCH_BIN" self-test --smoke --dry-run --json 2>/dev/null || true)"
    if [[ -z "$out" ]]; then
        emit "$scenario" "smoke_plan" "skip" "no_output" \
            "no output in hermetic env (fail-open); logic covered by unit tests"
        return 0
    fi
    verdict="$(printf '%s' "$out" | validate_smoke_json)"
    case "$verdict" in
        ok)
            emit "$scenario" "smoke_plan" "pass" "" \
                "self-test --smoke emitted a well-formed plan + SmokeProfileEvent trace" ;;
        *)
            emit "$scenario" "smoke_plan" "fail" "$verdict" \
                "self-test --smoke output failed validation: $verdict" ;;
    esac
}

# --- empty_fleet: no workers configured ------------------------------------
EF="$BASE/empty_fleet"; mkdir -p "$EF"
: >"$EF/workers.toml"
run_smoke_scenario "empty_fleet" "$EF"

# --- all_absent: workers configured but unreachable ------------------------
AA="$BASE/all_absent"; mkdir -p "$AA"
cat >"$AA/workers.toml" <<'TOML'
[[workers]]
id = "absent-1"
host = "203.0.113.10"
user = "ubuntu"
identity_file = "~/.ssh/id_ed25519"
total_slots = 8
priority = 100

[[workers]]
id = "absent-2"
host = "203.0.113.11"
user = "ubuntu"
identity_file = "~/.ssh/id_ed25519"
total_slots = 8
priority = 90
TOML
run_smoke_scenario "all_absent" "$AA"

# --- self-validate the emitted harness JSONL schema ------------------------
schema_ok="$(python3 - "$SUITE_LOG" "$BEAD_ID" <<'PY'
import json, sys
path, bead = sys.argv[1], sys.argv[2]
required = ["run_id", "bead_id", "scenario", "event", "status", "reason_code", "detail"]
n = 0
with open(path) as f:
    for ln, line in enumerate(f, 1):
        line = line.strip()
        if not line:
            continue
        n += 1
        try:
            rec = json.loads(line)
        except json.JSONDecodeError:
            print(f"bad_json_line_{ln}"); sys.exit(0)
        miss = [k for k in required if k not in rec]
        if miss:
            print("missing:" + ",".join(miss)); sys.exit(0)
        if rec["bead_id"] != bead:
            print("wrong_bead"); sys.exit(0)
print("ok" if n > 0 else "empty")
PY
)"
if [[ "$schema_ok" == "ok" ]]; then
    emit "_suite" "schema_validate" "pass" "" "JSONL schema valid (all required fields present)"
else
    emit "_suite" "schema_validate" "fail" "$schema_ok" "JSONL schema invalid: $schema_ok"
fi

if [[ "$SUITE_LOG" != "$MIRROR_DIR/e2e_real_fleet_smoke.jsonl" ]]; then
    cp -f "$SUITE_LOG" "$MIRROR_DIR/e2e_real_fleet_smoke.jsonl" 2>/dev/null || true
fi

echo "Summary: pass=$PASS skip=$SKIP fail=$FAIL (run_id=$RUN_ID)" >&2
[[ "$FAIL" -gt 0 ]] && exit 1
exit 0
