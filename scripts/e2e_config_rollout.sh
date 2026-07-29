#!/usr/bin/env bash
#
# e2e_config_rollout.sh — E2E runner for remediation config rollout across the
# install/init/upgrade/doctor surfaces (bd-session-history-remediation-ocv9i.17.2).
#
# Crafts a config.toml carrying an invalid remediation knob plus a benign
# override, points the binary at it via RCH_CONFIG_DIR, and asserts that
# `rch config validate|lint|doctor|diff|export` and the top-level `rch doctor`
# surface / show / redact the [remediation] section. Emits one structured JSONL
# record per surface keyed by bead id:
#
#   run_id, bead_id, surface, command, status, reason_code, duration_ms, detail
#
# Exit codes (consumed by scripts/run_all_e2e.sh):
#   0  all scenarios pass (skips allowed)
#   1  a scenario failed
#   4  skipped (rch binary or python3 unavailable)
#
# Usage:
#   ./scripts/e2e_config_rollout.sh [--run-id=ID]

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
export PROJECT_ROOT

E2E_SKIP_EXIT=4
BEAD_ID="bd-session-history-remediation-ocv9i.17.2"
RUN_ID="run-$(date -u '+%Y%m%d%H%M%S')-$$-${RANDOM}"
for arg in "$@"; do
    case "$arg" in
        --run-id=*) RUN_ID="${arg#*=}" ;;
        --help | -h)
            sed -n '2,22p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'
            exit 0
            ;;
    esac
done

TARGET_DIR="${CARGO_TARGET_DIR:-$PROJECT_ROOT/target}"
LOG_DIR="$TARGET_DIR/test-logs"
MIRROR_DIR="$PROJECT_ROOT/target/test-logs"
mkdir -p "$LOG_DIR" "$MIRROR_DIR"
SUITE_LOG="${RCH_E2E_LOG:-$LOG_DIR/e2e_config_rollout.jsonl}"
: >"$SUITE_LOG"

PASS=0
FAIL=0
SKIP=0

emit() {
    local surface="$1" command="$2" status="$3" reason="$4" dur="$5" detail="$6"
    local line
    line=$(python3 - "$RUN_ID" "$BEAD_ID" "$surface" "$command" "$status" "$reason" \
        "$dur" "$detail" <<'PY'
import json, sys
keys = ["run_id","bead_id","surface","command","status","reason_code",
        "duration_ms","detail"]
vals = sys.argv[1:9]
rec = dict(zip(keys, vals))
rec["duration_ms"] = int(rec["duration_ms"]) if str(rec["duration_ms"]).isdigit() else 0
print(json.dumps(rec, separators=(",", ":")))
PY
)
    printf '%s\n' "$line" >>"$SUITE_LOG"
    case "$status" in
        pass) PASS=$((PASS + 1)); printf '  [PASS] %-16s %s\n' "$surface" "$detail" >&2 ;;
        fail) FAIL=$((FAIL + 1)); printf '  [FAIL] %-16s %s\n' "$surface" "$detail" >&2 ;;
        skip) SKIP=$((SKIP + 1)); printf '  [SKIP] %-16s %s (%s)\n' "$surface" "$detail" "$reason" >&2 ;;
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

# Craft a config dir with an invalid remediation knob + a benign override + an
# operator home path to exercise validate/lint/doctor (error) and diff/export
# (override + redaction).
CFG_DIR="$LOG_DIR/cfg-rollout-$$"
mkdir -p "$CFG_DIR"
cat >"$CFG_DIR/config.toml" <<'TOML'
[remediation.policy]
hook_exec_fail_open = false

[remediation.auto_rejoin]
check_interval_secs = 0

[remediation.incident_ledger]
path = "/home/alice/secret/ledger.jsonl"
TOML

run_rch() { env -u RCH_OUTPUT_FORMAT -u TOON_DEFAULT_FORMAT NO_COLOR=1 RCH_CONFIG_DIR="$CFG_DIR" "$RCH_BIN" "$@" 2>/dev/null || true; }

echo "Config rollout E2E (run_id=$RUN_ID)" >&2

# validate: must name the offending knob
t0=$(now_ms); out="$(run_rch config validate --json)"; dur=$(($(now_ms) - t0))
if printf '%s' "$out" | grep -q "check_interval_secs"; then
    emit "config-validate" "config validate --json" "pass" "" "$dur" "names invalid remediation knob"
else
    emit "config-validate" "config validate --json" "fail" "no_finding" "$dur" "validate did not surface remediation error"
fi

# lint: LINT-E101
t0=$(now_ms); out="$(run_rch config lint --json)"; dur=$(($(now_ms) - t0))
if printf '%s' "$out" | grep -q "LINT-E101"; then
    emit "config-lint" "config lint --json" "pass" "LINT-E101" "$dur" "lint surfaced remediation error"
else
    emit "config-lint" "config lint --json" "fail" "no_finding" "$dur" "lint missing LINT-E101"
fi

# config doctor: DOC-E100
t0=$(now_ms); out="$(run_rch config doctor --json)"; dur=$(($(now_ms) - t0))
if printf '%s' "$out" | grep -q "DOC-E100"; then
    emit "config-doctor" "config doctor --json" "pass" "DOC-E100" "$dur" "config doctor surfaced remediation error"
else
    emit "config-doctor" "config doctor --json" "fail" "no_finding" "$dur" "config doctor missing DOC-E100"
fi

# top-level doctor: remediation_config check present
t0=$(now_ms); out="$(run_rch doctor --json)"; dur=$(($(now_ms) - t0))
if printf '%s' "$out" | grep -q "remediation_config"; then
    emit "doctor" "doctor --json" "pass" "" "$dur" "top-level doctor includes remediation check"
else
    emit "doctor" "doctor --json" "fail" "no_check" "$dur" "top-level doctor missing remediation_config check"
fi

# diff: shows the override
t0=$(now_ms); out="$(run_rch config diff --json)"; dur=$(($(now_ms) - t0))
if printf '%s' "$out" | grep -q "remediation.policy.hook_exec_fail_open"; then
    emit "config-diff" "config diff --json" "pass" "" "$dur" "diff shows remediation override"
else
    emit "config-diff" "config diff --json" "fail" "no_entry" "$dur" "diff missing remediation override"
fi

# export: includes redacted remediation section
t0=$(now_ms); out="$(run_rch config export --format json)"; dur=$(($(now_ms) - t0))
redacted_ok="$(printf '%s' "$out" | python3 -c 'import json,sys
try:
    d=json.load(sys.stdin)
    p=(d.get("data") or {}).get("remediation",{}).get("incident_ledger",{}).get("path","")
    print("yes" if "/home/<redacted>/" in p and "/home/alice/" not in p else "no")
except Exception:
    print("err")' 2>/dev/null || echo "err")"
if [[ "$redacted_ok" == "yes" ]]; then
    emit "config-export" "config export --format json" "pass" "" "$dur" "export includes redacted remediation section"
else
    emit "config-export" "config export --format json" "fail" "not_redacted" "$dur" "export missing redacted remediation (got=$redacted_ok)"
fi

[[ "$SUITE_LOG" != "$MIRROR_DIR/e2e_config_rollout.jsonl" ]] \
    && cp -f "$SUITE_LOG" "$MIRROR_DIR/e2e_config_rollout.jsonl" 2>/dev/null || true

echo "Summary: pass=$PASS skip=$SKIP fail=$FAIL (run_id=$RUN_ID)" >&2
[[ "$FAIL" -gt 0 ]] && exit 1
exit 0
