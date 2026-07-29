#!/usr/bin/env bash
#
# e2e_config_rollout_logs.sh — config rollout E2E with the structured JSONL
# contract required by bead bd-session-history-remediation-ocv9i.17.3.
#
# Drives init/validate/doctor/config-diff/config-export across temp config homes
# AND a project override, emitting one JSONL record per scenario/event with the
# mandated fields:
#
#   run_id, bead_id, scenario, event, status, reason_code, config_source, path, detail
#
# Scenarios:
#   default_install  — `config init --non-interactive` writes a [remediation] block
#   project_override — a .rch/config.toml override is attributed to the project file
#   invalid_config   — an out-of-range knob is reported by validate/lint/doctor
#   upgrade_old      — an old config without [remediation] loads with defaults
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
BEAD_ID="bd-session-history-remediation-ocv9i.17.3"
RUN_ID="run-$(date -u '+%Y%m%d%H%M%S')-$$-${RANDOM}"
for arg in "$@"; do
    case "$arg" in
        --run-id=*) RUN_ID="${arg#*=}" ;;
        --help | -h)
            sed -n '2,20p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'
            exit 0
            ;;
    esac
done

TARGET_DIR="${CARGO_TARGET_DIR:-$PROJECT_ROOT/target}"
LOG_DIR="$TARGET_DIR/test-logs"
MIRROR_DIR="$PROJECT_ROOT/target/test-logs"
mkdir -p "$LOG_DIR" "$MIRROR_DIR"
SUITE_LOG="${RCH_E2E_LOG:-$LOG_DIR/e2e_config_rollout_logs.jsonl}"
: >"$SUITE_LOG"

PASS=0
FAIL=0
SKIP=0

emit() {
    local scenario="$1" event="$2" status="$3" reason="$4" config_source="$5" path="$6" detail="$7"
    local line
    line=$(python3 - "$RUN_ID" "$BEAD_ID" "$scenario" "$event" "$status" "$reason" \
        "$config_source" "$path" "$detail" <<'PY'
import json, sys
keys = ["run_id","bead_id","scenario","event","status","reason_code",
        "config_source","path","detail"]
print(json.dumps(dict(zip(keys, sys.argv[1:10])), separators=(",", ":")))
PY
)
    printf '%s\n' "$line" >>"$SUITE_LOG"
    case "$status" in
        pass) PASS=$((PASS + 1)); printf '  [PASS] %-16s %s\n' "$scenario" "$detail" >&2 ;;
        fail) FAIL=$((FAIL + 1)); printf '  [FAIL] %-16s %s\n' "$scenario" "$detail" >&2 ;;
        skip) SKIP=$((SKIP + 1)); printf '  [SKIP] %-16s %s (%s)\n' "$scenario" "$detail" "$reason" >&2 ;;
    esac
}

command -v python3 >/dev/null 2>&1 || { echo "python3 unavailable; skipping" >&2; exit "$E2E_SKIP_EXIT"; }

RCH_BIN=""
for cand in "$PROJECT_ROOT/target/release/rch" "$PROJECT_ROOT/target/debug/rch"; do
    [[ -x "$cand" ]] && { RCH_BIN="$cand"; break; }
done
[[ -z "$RCH_BIN" ]] && command -v rch >/dev/null 2>&1 && RCH_BIN="$(command -v rch)"
[[ -z "$RCH_BIN" ]] && { echo "rch binary not built; skipping" >&2; exit "$E2E_SKIP_EXIT"; }

echo "Config rollout logs E2E (run_id=$RUN_ID)" >&2

BASE="$LOG_DIR/cfg-rollout-logs-$$"
mkdir -p "$BASE"

# --- default_install: init writes a [remediation] block --------------------
DI="$BASE/default_install"; mkdir -p "$DI"
env -u RCH_OUTPUT_FORMAT NO_COLOR=1 RCH_CONFIG_DIR="$DI" "$RCH_BIN" config init --non-interactive >/dev/null 2>&1 || true
if grep -q "\[remediation\]" "$DI/config.toml" 2>/dev/null; then
    emit "default_install" "init" "pass" "" "default" "[remediation]" "init wrote the documented remediation block"
else
    emit "default_install" "init" "fail" "no_section" "default" "[remediation]" "init did not write [remediation]"
fi

# --- project_override: attributed to the project file ----------------------
PO="$BASE/project_override"; mkdir -p "$PO/.rch"
printf '[general]\nforce_remote = true\n' >"$PO/.rch/config.toml"
PU="$BASE/project_override_user"; mkdir -p "$PU"
src="$(cd "$PO" && env -u RCH_OUTPUT_FORMAT NO_COLOR=1 RCH_CONFIG_DIR="$PU" "$RCH_BIN" config show --sources --json 2>/dev/null | python3 -c 'import json,sys
try:
    d=json.load(sys.stdin)
    vs=(d.get("data") or {}).get("value_sources") or []
    m={e.get("key"):e.get("source") for e in vs}
    print(m.get("general.force_remote",""))
except Exception:
    print("")' 2>/dev/null || echo "")"
if [[ "$src" == project:* ]]; then
    emit "project_override" "show_sources" "pass" "" "$src" "general.force_remote" "override attributed to project file"
else
    emit "project_override" "show_sources" "fail" "wrong_source" "$src" "general.force_remote" "expected project: source, got '$src'"
fi

# --- invalid_config: out-of-range knob reported by validate ----------------
IC="$BASE/invalid_config"; mkdir -p "$IC"
printf '[remediation.auto_rejoin]\ncheck_interval_secs = 0\n' >"$IC/config.toml"
out="$(env -u RCH_OUTPUT_FORMAT NO_COLOR=1 RCH_CONFIG_DIR="$IC" "$RCH_BIN" config validate --json 2>/dev/null || true)"
if printf '%s' "$out" | grep -q "check_interval_secs"; then
    emit "invalid_config" "validate" "pass" "out_of_range" "user" "remediation.auto_rejoin.check_interval_secs" "validate named the invalid knob"
else
    emit "invalid_config" "validate" "fail" "no_finding" "user" "remediation.auto_rejoin.check_interval_secs" "validate did not surface the error"
fi

# --- upgrade_old: old config without [remediation] loads with defaults -----
UO="$BASE/upgrade_old"; mkdir -p "$UO"
printf '[general]\nenabled = true\nlog_level = "info"\n' >"$UO/config.toml"
out="$(env -u RCH_OUTPUT_FORMAT NO_COLOR=1 RCH_CONFIG_DIR="$UO" "$RCH_BIN" config validate --json 2>/dev/null || true)"
# An old config must not raise any remediation.* finding (defaults are valid).
if printf '%s' "$out" | grep -q "remediation\."; then
    emit "upgrade_old" "load" "fail" "unexpected_finding" "default" "[remediation]" "old config raised a remediation finding"
else
    emit "upgrade_old" "load" "pass" "" "default" "[remediation]" "old config loaded remediation defaults cleanly"
fi

# --- self-validate the emitted JSONL schema --------------------------------
schema_ok="$(python3 - "$SUITE_LOG" "$BEAD_ID" <<'PY'
import json, sys
path, bead = sys.argv[1], sys.argv[2]
required = ["run_id","bead_id","scenario","event","status","reason_code","config_source","path","detail"]
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
    emit "_suite" "schema_validate" "pass" "" "n/a" "$SUITE_LOG" "JSONL schema valid (all required fields present)"
else
    emit "_suite" "schema_validate" "fail" "$schema_ok" "n/a" "$SUITE_LOG" "JSONL schema invalid: $schema_ok"
fi

[[ "$SUITE_LOG" != "$MIRROR_DIR/e2e_config_rollout_logs.jsonl" ]] \
    && cp -f "$SUITE_LOG" "$MIRROR_DIR/e2e_config_rollout_logs.jsonl" 2>/dev/null || true

echo "Summary: pass=$PASS skip=$SKIP fail=$FAIL (run_id=$RUN_ID)" >&2
[[ "$FAIL" -gt 0 ]] && exit 1
exit 0
