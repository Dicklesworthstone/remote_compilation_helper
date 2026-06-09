#!/usr/bin/env bash
#
# remediation_e2e.sh — shared JSONL emit + scenario runner helpers for the
# session-history remediation E2E program (bd-session-history-remediation-ocv9i.16.3).
#
# Source this from a scenario runner. It provides:
#   - rem_init / rem_parse_args : run_id, filter, dry-run, mock-worker setup
#   - rem_emit                  : one structured JSONL line with the program schema
#   - rem_scenario_{begin,pass,fail,skip}
#   - rem_summary               : PASS/FAIL/SKIP totals + failed-scenario→bead→reason
#
# JSONL schema (one object per line):
#   run_id, bead_id, scenario, event, status, reason_code,
#   command_fingerprint, worker_id, duration_ms, detail, ts
#
# Design notes:
#   - No external JSON tooling required; strings are escaped in-shell.
#   - `--dry-run` exercises the runner/emitter/summary without invoking real
#     commands (so the framework is verifiable without a live daemon/fleet).
#   - Scenarios whose CLI surface does not exist yet record status=skipped with
#     a reason code and the owning bead, instead of failing the suite.

# shellcheck shell=bash

# --- state --------------------------------------------------------------------
REM_BEAD_ID="${REM_BEAD_ID:-bd-session-history-remediation-ocv9i.16.3}"
REM_RUN_ID=""
REM_LOG_FILE=""
REM_FILTER="*"
REM_DRY_RUN=0
REM_MOCK_WORKER=0
REM_PASS=0
REM_FAIL=0
REM_SKIP=0
REM_SCENARIO=""
REM_SCENARIO_START_MS=0
# Parallel arrays of failed scenarios -> (reason_code, detail) for the summary.
declare -a REM_FAILED_NAMES=()
declare -a REM_FAILED_REASONS=()
declare -a REM_FAILED_DETAILS=()

_rem_now_ms() { date -u '+%s%3N' 2>/dev/null || echo $(( $(date -u '+%s') * 1000 )); }
_rem_ts() { date -u '+%Y-%m-%dT%H:%M:%S.%3NZ' 2>/dev/null || date -u '+%Y-%m-%dT%H:%M:%SZ'; }

# Escape a string for embedding inside a JSON double-quoted value.
_rem_json_str() {
    local s="$1"
    s="${s//\\/\\\\}"   # backslash first
    s="${s//\"/\\\"}"   # double quote
    s="${s//$'\t'/\\t}"
    s="${s//$'\r'/\\r}"
    s="${s//$'\n'/\\n}"
    printf '%s' "$s"
}

# rem_init <suite_name> [run_id]
rem_init() {
    local suite="$1"
    REM_RUN_ID="${2:-${REM_RUN_ID:-run-$(date -u '+%Y%m%d%H%M%S')-$$-${RANDOM}}}"
    local log_dir="${PROJECT_ROOT:-$(pwd)}/target/test-logs"
    mkdir -p "$log_dir"
    REM_LOG_FILE="$log_dir/${suite}.jsonl"
    : > "$REM_LOG_FILE"
    rem_emit "_suite" "suite.start" "info" "none" "suite=$suite filter=$REM_FILTER dry_run=$REM_DRY_RUN mock=$REM_MOCK_WORKER" "" "" 0
}

# rem_parse_args "$@"  — handles --dry-run, --filter[=X], --mock-worker,
# --run-id[=X], --help; leaves unknown args for the caller in REM_REST.
declare -a REM_REST=()
rem_parse_args() {
    REM_REST=()
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --dry-run) REM_DRY_RUN=1 ;;
            --mock-worker|--mock) REM_MOCK_WORKER=1 ;;
            --filter) REM_FILTER="$2"; shift ;;
            --filter=*) REM_FILTER="${1#*=}" ;;
            --run-id) REM_RUN_ID="$2"; shift ;;
            --run-id=*) REM_RUN_ID="${1#*=}" ;;
            --help|-h)
                cat <<EOF
Usage: $(basename "${0:-runner}") [--dry-run] [--mock-worker] [--filter GLOB] [--run-id ID]
  --dry-run       Run the harness without invoking real rch commands
  --mock-worker   Use mock SSH / mock-worker mode (RCH_MOCK_SSH=1)
  --filter GLOB   Only run scenarios whose name matches GLOB (default: *)
  --run-id ID     Use a fixed run_id (default: generated)
JSONL logs: \${PROJECT_ROOT}/target/test-logs/<suite>.jsonl
EOF
                exit 0 ;;
            *) REM_REST+=("$1") ;;
        esac
        shift
    done
    if [[ $REM_MOCK_WORKER -eq 1 ]]; then
        export RCH_MOCK_SSH=1
    fi
    return 0
}

# rem_emit <scenario> <event> <status> <reason_code> <detail> [worker_id] [cmd_fingerprint] [duration_ms]
rem_emit() {
    local scenario="$1" event="$2" status="$3" reason_code="$4" detail="$5"
    local worker_id="${6:-}" cmd_fp="${7:-}" duration_ms="${8:-0}"
    local line
    line=$(printf '{"ts":"%s","run_id":"%s","bead_id":"%s","scenario":"%s","event":"%s","status":"%s","reason_code":"%s","command_fingerprint":"%s","worker_id":"%s","duration_ms":%s,"detail":"%s"}' \
        "$(_rem_ts)" \
        "$(_rem_json_str "$REM_RUN_ID")" \
        "$(_rem_json_str "$REM_BEAD_ID")" \
        "$(_rem_json_str "$scenario")" \
        "$(_rem_json_str "$event")" \
        "$(_rem_json_str "$status")" \
        "$(_rem_json_str "$reason_code")" \
        "$(_rem_json_str "$cmd_fp")" \
        "$(_rem_json_str "$worker_id")" \
        "${duration_ms:-0}" \
        "$(_rem_json_str "$detail")")
    [[ -n "$REM_LOG_FILE" ]] && printf '%s\n' "$line" >> "$REM_LOG_FILE"
}

# Should this scenario run, given --filter?
rem_selected() {
    # shellcheck disable=SC2053
    [[ "$1" == $REM_FILTER ]]
}

rem_scenario_begin() {
    REM_SCENARIO="$1"
    REM_SCENARIO_START_MS="$(_rem_now_ms)"
    echo "▶ scenario: $REM_SCENARIO"
    rem_emit "$REM_SCENARIO" "scenario.begin" "running" "none" "started"
}

_rem_scenario_dur() { echo $(( $(_rem_now_ms) - REM_SCENARIO_START_MS )); }

# rem_scenario_pass <reason_code> [detail] [worker_id] [cmd_fp]
rem_scenario_pass() {
    REM_PASS=$((REM_PASS + 1))
    rem_emit "$REM_SCENARIO" "scenario.end" "pass" "${1:-none}" "${2:-ok}" "${3:-}" "${4:-}" "$(_rem_scenario_dur)"
    echo "  ✓ PASS ($REM_SCENARIO)"
}

# rem_scenario_skip <reason_code> <detail> [owning_bead]
rem_scenario_skip() {
    REM_SKIP=$((REM_SKIP + 1))
    local detail="$2"
    [[ -n "${3:-}" ]] && detail="$detail (owner: $3)"
    rem_emit "$REM_SCENARIO" "scenario.end" "skipped" "${1:-surface_pending}" "$detail" "" "" "$(_rem_scenario_dur)"
    echo "  ⊘ SKIP ($REM_SCENARIO): $detail"
}

# rem_scenario_fail <reason_code> <detail> [worker_id] [cmd_fp]
rem_scenario_fail() {
    REM_FAIL=$((REM_FAIL + 1))
    REM_FAILED_NAMES+=("$REM_SCENARIO")
    REM_FAILED_REASONS+=("${1:-unknown}")
    REM_FAILED_DETAILS+=("${2:-}")
    rem_emit "$REM_SCENARIO" "scenario.end" "fail" "${1:-unknown}" "${2:-}" "${3:-}" "${4:-}" "$(_rem_scenario_dur)"
    echo "  ✗ FAIL ($REM_SCENARIO): ${2:-}"
}

# rem_summary — prints totals + failed-scenario→bead→reason; exits nonzero on fail.
rem_summary() {
    local total=$((REM_PASS + REM_FAIL + REM_SKIP))
    rem_emit "_suite" "suite.summary" \
        "$([[ $REM_FAIL -eq 0 ]] && echo pass || echo fail)" \
        "none" \
        "total=$total pass=$REM_PASS fail=$REM_FAIL skip=$REM_SKIP" "" "" 0
    echo ""
    echo "──────────────────────────────────────────────"
    echo "Remediation E2E summary  (run_id=$REM_RUN_ID)"
    echo "  total=$total  PASS=$REM_PASS  FAIL=$REM_FAIL  SKIP=$REM_SKIP"
    if [[ $REM_FAIL -gt 0 ]]; then
        echo "  Failed scenarios (scenario → bead → reason_code):"
        local i
        for i in "${!REM_FAILED_NAMES[@]}"; do
            echo "    - ${REM_FAILED_NAMES[$i]} → $REM_BEAD_ID → ${REM_FAILED_REASONS[$i]} : ${REM_FAILED_DETAILS[$i]}"
        done
    fi
    echo "  JSONL: $REM_LOG_FILE"
    echo "──────────────────────────────────────────────"
    [[ $REM_FAIL -eq 0 ]]
}
