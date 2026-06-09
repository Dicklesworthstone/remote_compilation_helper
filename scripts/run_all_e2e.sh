#!/usr/bin/env bash
#
# run_all_e2e.sh — local parity runner for the e2e suite
# (remote_compilation_helper-62u24.15).
#
# Runs every scripts/e2e_*.sh with the SAME env and artifact layout CI uses, so
# an operator can reproduce a CI e2e failure locally. CI invokes this script
# (one matrix job per e2e script via --filter) so there is exactly one code path
# for running an e2e, local or remote.
#
# Artifact layout (one set per script, in --out):
#   e2e_<slug>.jsonl       structured JSONL log (via RCH_E2E_LOG)
#   e2e_<slug>.build.log   combined stdout+stderr
#   e2e_<slug>.status      one JSON line: {script, os, exit_code, status, duration_ms}
#   e2e_<slug>.<name>.jsonl any target/test-logs JSONL the script emitted
#
# PASS/FAIL is the script's EXIT CODE — the authoritative signal CI gates on:
#   0            -> pass
#   4            -> skip   (E2E_SKIP_EXIT; capability/surface not present yet)
#   anything else -> fail
#
# Usage:
#   scripts/run_all_e2e.sh [--filter=<glob>] [--out=<dir>] [--list]
#
# Options:
#   --filter=<glob>  Only run scripts whose basename matches <glob> (default '*').
#                    Matched against the full basename, e.g. 'e2e_api_*.sh' or
#                    'e2e_self_test_full.sh'.
#   --out=<dir>      Artifact output directory (default target/e2e-artifacts).
#   --list           Print the scripts that would run, then exit.
#   --help           Show this help.
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
export PROJECT_ROOT

# shellcheck disable=SC1091
source "$SCRIPT_DIR/lib/e2e_common.sh"

FILTER='*'
OUT_DIR="$PROJECT_ROOT/target/e2e-artifacts"
LIST_ONLY=0

for arg in "$@"; do
    case "$arg" in
        --filter=*) FILTER="${arg#*=}" ;;
        --out=*)    OUT_DIR="${arg#*=}" ;;
        --list)     LIST_ONLY=1 ;;
        --help|-h)
            sed -n '2,40p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'
            exit 0
            ;;
        *)
            echo "run_all_e2e: unknown argument: $arg" >&2
            exit 2
            ;;
    esac
done

OS_LABEL="$(printf '%s' "${RUNNER_OS:-$(uname -s)}" | tr '[:upper:]' '[:lower:]')"
TEST_LOGS_DIR="$PROJECT_ROOT/target/test-logs"

# Discover e2e scripts (sorted, deterministic).
mapfile -t ALL_SCRIPTS < <(find "$PROJECT_ROOT/scripts" -maxdepth 1 -name 'e2e_*.sh' -printf '%f\n' | sort)

# Apply the filter (glob match on basename).
SELECTED=()
for s in "${ALL_SCRIPTS[@]}"; do
    # shellcheck disable=SC2053
    if [[ "$s" == $FILTER ]]; then
        SELECTED+=("$s")
    fi
done

if [[ ${#SELECTED[@]} -eq 0 ]]; then
    echo "run_all_e2e: no e2e scripts match filter '$FILTER'" >&2
    exit 2
fi

if [[ "$LIST_ONLY" -eq 1 ]]; then
    printf '%s\n' "${SELECTED[@]}"
    exit 0
fi

mkdir -p "$OUT_DIR" "$TEST_LOGS_DIR"

# JSON string escaper (small, dependency-free).
json_str() {
    local s="$1"
    s="${s//\\/\\\\}"
    s="${s//\"/\\\"}"
    printf '%s' "$s"
}

fail_count=0
pass_count=0
skip_count=0

for script in "${SELECTED[@]}"; do
    slug="${script%.sh}"
    log_jsonl="$OUT_DIR/${slug}.jsonl"
    build_log="$OUT_DIR/${slug}.build.log"
    status_file="$OUT_DIR/${slug}.status"

    e2e_log "running ${script} (os=${OS_LABEL})"

    # Marker so we can attribute target/test-logs JSONL produced by this run
    # (scripts using test_lib.sh / remediation_e2e.sh write there, not RCH_E2E_LOG).
    marker="$(mktemp)"

    start_ms="$(e2e_now_ms)"
    set +e
    (
        cd "$PROJECT_ROOT"
        RCH_E2E_LOG="$log_jsonl" RCH_E2E_VERBOSE="${RCH_E2E_VERBOSE:-0}" \
            bash "scripts/${script}"
    ) >"$build_log" 2>&1
    exit_code=$?
    set -e
    end_ms="$(e2e_now_ms)"
    duration_ms=$(( end_ms - start_ms ))

    # Gather any target/test-logs JSONL written during this run.
    if [[ -d "$TEST_LOGS_DIR" ]]; then
        while IFS= read -r -d '' produced; do
            cp -f "$produced" "$OUT_DIR/${slug}.$(basename "$produced")" 2>/dev/null || true
        done < <(find "$TEST_LOGS_DIR" -name '*.jsonl' -newer "$marker" -print0 2>/dev/null)
    fi
    rm -f "$marker"

    case "$exit_code" in
        0) status="pass"; pass_count=$(( pass_count + 1 )) ;;
        "$E2E_SKIP_EXIT") status="skip"; skip_count=$(( skip_count + 1 )) ;;
        *) status="fail"; fail_count=$(( fail_count + 1 )) ;;
    esac

    printf '{"script":"%s","os":"%s","exit_code":%d,"status":"%s","duration_ms":%d}\n' \
        "$(json_str "$script")" "$(json_str "$OS_LABEL")" "$exit_code" "$status" "$duration_ms" \
        >"$status_file"

    e2e_log "  -> ${status} (exit=${exit_code}, ${duration_ms}ms)"
done

echo
e2e_log "summary: ${pass_count} pass, ${fail_count} fail, ${skip_count} skip  (artifacts: ${OUT_DIR})"

# Non-zero exit iff a script genuinely failed (skips do not fail the suite).
[[ "$fail_count" -eq 0 ]]
