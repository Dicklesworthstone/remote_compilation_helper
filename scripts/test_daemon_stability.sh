#!/usr/bin/env bash
#
# test_daemon_stability.sh - Daemon stability test for rchd with rich_rust output
#
# This script validates:
# - Startup/shutdown cycles
# - Rich output does not block without a TTY
# - High volume hook processing
# - Memory stability under load
#
# Logging format: JSONL with required fields (ts, test, phase, worker, command,
# bytes_transferred, duration_ms, result, error)

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

# shellcheck source=lib/e2e_common.sh
source "$PROJECT_ROOT/scripts/lib/e2e_common.sh"

RUN_TS="$(date -u '+%Y%m%d_%H%M%S')"
LOG_FILE="/tmp/rch_daemon_stability_${RUN_TS}.jsonl"

RCH="$PROJECT_ROOT/target/release/rch"
RCHD="$PROJECT_ROOT/target/release/rchd"

STDOUT_FILE="/tmp/rch_daemon_stdout_${RUN_TS}.log"
STDERR_FILE="/tmp/rch_daemon_stderr_${RUN_TS}.log"

json_escape() {
    local s="$1"
    s=${s//\\/\\\\}
    s=${s//"/\\"}
    s=${s//$'\n'/\\n}
    s=${s//$'\r'/\\r}
    printf '%s' "$s"
}

log_json() {
    local level="$1"
    local test="$2"
    local phase="$3"
    local msg="$4"
    local worker="$5"
    local command="$6"
    local bytes_transferred="$7"
    local duration_ms="$8"
    local result="$9"
    local error="${10:-}"

    local ts
    ts="$(e2e_timestamp)"

    local msg_escaped
    msg_escaped="$(json_escape "$msg")"
    local worker_escaped
    worker_escaped="$(json_escape "$worker")"
    local command_escaped
    command_escaped="$(json_escape "$command")"

    if [[ -n "$error" ]]; then
        local error_escaped
        error_escaped="\"$(json_escape "$error")\""
        printf '{"ts":"%s","level":"%s","test":"%s","phase":"%s","msg":"%s","data":{"worker":"%s","command":"%s","bytes_transferred":%s,"duration_ms":%s,"result":"%s","error":%s}}\n' \
            "$ts" "$level" "$test" "$phase" "$msg_escaped" "$worker_escaped" "$command_escaped" \
            "$bytes_transferred" "$duration_ms" "$result" "$error_escaped" | tee -a "$LOG_FILE"
    else
        printf '{"ts":"%s","level":"%s","test":"%s","phase":"%s","msg":"%s","data":{"worker":"%s","command":"%s","bytes_transferred":%s,"duration_ms":%s,"result":"%s","error":null}}\n' \
            "$ts" "$level" "$test" "$phase" "$msg_escaped" "$worker_escaped" "$command_escaped" \
            "$bytes_transferred" "$duration_ms" "$result" | tee -a "$LOG_FILE"
    fi
}

fail() {
    log_json "ERROR" "$1" "error" "$2" "local" "" 0 0 "fail" "${3:-}" || true
    echo "FAIL: $2" >&2
    exit 1
}

cleanup() {
    if [[ -x "$RCH" ]]; then
        "$RCH" daemon stop >/dev/null 2>&1 || true
    fi
    if command -v pkill >/dev/null 2>&1; then
        pkill -f rchd >/dev/null 2>&1 || true
    fi
}
trap cleanup EXIT

log_json "INFO" "daemon_stability" "setup" "Building binaries" "local" "cargo build -p rch -p rchd --features rich-ui --release" 0 0 "start"
if ! cargo build -p rch -p rchd --features rich-ui --release >/dev/null; then
    fail "daemon_stability" "Build failed" "cargo build failed"
fi

if [[ ! -x "$RCH" || ! -x "$RCHD" ]]; then
    fail "daemon_stability" "Release binaries missing" "Expected $RCH and $RCHD"
fi

log_json "INFO" "daemon_stability" "setup" "Binaries built" "local" "cargo build" 0 0 "pass"

# =============================================================================
# TEST 1: Startup/Shutdown Cycle
# =============================================================================
log_json "INFO" "startup_shutdown" "test" "Starting startup/shutdown cycles" "local" "rch daemon start/stop" 0 0 "start"
for i in 1 2 3; do
    local_start="$(e2e_now_ms)"
    "$RCH" daemon start >/dev/null 2>&1 || fail "startup_shutdown" "Daemon failed to start on cycle $i"
    sleep 1
    if ! "$RCH" status >/dev/null 2>&1; then
        fail "startup_shutdown" "Daemon not responding on cycle $i"
    fi
    "$RCH" daemon stop >/dev/null 2>&1 || fail "startup_shutdown" "Daemon failed to stop on cycle $i"
    sleep 1
    local_end="$(e2e_now_ms)"
    duration_ms=$((local_end - local_start))
    log_json "INFO" "startup_shutdown" "verify" "Cycle $i passed" "local" "rch daemon start/stop" 0 "$duration_ms" "pass"
done
log_json "INFO" "startup_shutdown" "summary" "Startup/shutdown cycles passed" "local" "" 0 0 "pass"

# =============================================================================
# TEST 2: Rich Output Doesn't Block
# =============================================================================
log_json "INFO" "rich_output" "test" "Background daemon output (no TTY)" "local" "rch daemon start" 0 0 "start"

"$RCH" daemon start >"$STDOUT_FILE" 2>"$STDERR_FILE" || fail "rich_output" "Daemon failed to start"
sleep 2

pid="$(pgrep -n -f rchd || true)"
if [[ -z "$pid" ]]; then
    fail "rich_output" "Daemon process not found"
fi
if ! kill -0 "$pid" >/dev/null 2>&1; then
    fail "rich_output" "Daemon died unexpectedly" "pid $pid"
fi

"$RCH" status >/dev/null 2>&1 || fail "rich_output" "Daemon status failed"
"$RCH" workers list >/dev/null 2>&1 || true

if ! kill -0 "$pid" >/dev/null 2>&1; then
    fail "rich_output" "Daemon crashed during operations" "pid $pid"
fi

stderr_bytes=0
if [[ -s "$STDERR_FILE" ]]; then
    stderr_bytes=$(wc -c < "$STDERR_FILE" | tr -d ' ')
fi

"$RCH" daemon stop >/dev/null 2>&1 || fail "rich_output" "Daemon failed to stop"

log_json "INFO" "rich_output" "verify" "Background output passed" "local" "rch daemon start" "$stderr_bytes" 0 "pass"

# =============================================================================
# TEST 3: High Volume Hook Processing
# =============================================================================
log_json "INFO" "load_test" "test" "Load test (100 hook invocations)" "local" "rch (hook stdin)" 0 0 "start"

"$RCH" daemon start >/dev/null 2>&1 || fail "load_test" "Daemon failed to start"
sleep 2

HOOK_INPUT='{"tool_name":"Bash","tool_input":{"command":"echo test"}}'
start_ms="$(e2e_now_ms)"
for _ in $(seq 1 100); do
    echo "$HOOK_INPUT" | "$RCH" >/dev/null 2>&1 &
done
wait
end_ms="$(e2e_now_ms)"
duration_ms=$((end_ms - start_ms))

if ! "$RCH" status >/dev/null 2>&1; then
    fail "load_test" "Daemon unhealthy after load test"
fi

log_json "INFO" "load_test" "verify" "Load test passed" "local" "rch (hook stdin)" 0 "$duration_ms" "pass"

# =============================================================================
# TEST 4: Memory Stability (No Leaks)
# =============================================================================
log_json "INFO" "memory_stability" "test" "Memory stability under load" "local" "rch (hook stdin)" 0 0 "start"

pid="$(pgrep -n -f rchd || true)"
if [[ -z "$pid" ]]; then
    fail "memory_stability" "Daemon process not found"
fi

initial_mem=$(ps -o rss= -p "$pid" | tr -d ' ')

for _ in $(seq 1 1000); do
    echo "$HOOK_INPUT" | "$RCH" >/dev/null 2>&1 || true
done

final_mem=$(ps -o rss= -p "$pid" | tr -d ' ')
if [[ -z "$initial_mem" || -z "$final_mem" ]]; then
    fail "memory_stability" "Failed to read memory usage" "pid $pid"
fi

growth=$((final_mem - initial_mem))
log_json "INFO" "memory_stability" "verify" "Memory growth measured" "local" "ps rss" 0 0 "pass" "" || true

if (( growth > 50000 )); then
    fail "memory_stability" "Memory growth too high" "growth_kb=$growth"
fi

log_json "INFO" "memory_stability" "verify" "Memory growth within bounds" "local" "ps rss" 0 0 "pass"

"$RCH" daemon stop >/dev/null 2>&1 || true

log_json "INFO" "daemon_stability" "summary" "All daemon stability tests passed" "local" "" 0 0 "pass"

echo ""
echo "═══════════════════════════════════════════════════════════════"
echo "ALL DAEMON STABILITY TESTS PASSED"
echo "═══════════════════════════════════════════════════════════════"
