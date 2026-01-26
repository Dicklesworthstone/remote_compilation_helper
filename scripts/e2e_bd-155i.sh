#!/usr/bin/env bash
#
# e2e_bd-155i.sh - Worker capabilities report + mismatch warnings
#
# Verifies:
# - workers capabilities JSON includes local capabilities field
# - required runtime warnings appear when workers lack runtime
# - JSONL logging with required fields

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
LOG_FILE="${PROJECT_ROOT}/target/e2e_bd-155i.jsonl"

# shellcheck source=lib/e2e_common.sh
source "$SCRIPT_DIR/lib/e2e_common.sh"

passed_tests=0
failed_tests=0
run_start_ms="$(e2e_now_ms)"

daemon_pid=""
tmp_root=""

log_json() {
    local phase="$1"
    local message="$2"
    local worker="$3"
    local command="$4"
    local bytes="$5"
    local duration="$6"
    local result="$7"
    local error="${8:-}"
    local ts
    ts="$(e2e_timestamp)"
    printf '{"ts":"%s","test":"bd-155i","phase":"%s","worker":"%s","command":"%s","bytes_transferred":%s,"duration_ms":%s,"result":"%s","error":"%s","message":"%s"}\n' \
        "$ts" "$phase" "$worker" "$command" "$bytes" "$duration" "$result" "$error" "$message" | tee -a "$LOG_FILE"
}

record_pass() {
    passed_tests=$((passed_tests + 1))
}

record_fail() {
    failed_tests=$((failed_tests + 1))
}

cleanup() {
    if [[ -n "$daemon_pid" ]]; then
        kill "$daemon_pid" >/dev/null 2>&1 || true
        wait "$daemon_pid" >/dev/null 2>&1 || true
    fi
}
trap cleanup EXIT

check_dependencies() {
    log_json "setup" "Checking dependencies" "local" "dependency check" 0 0 "start"
    for cmd in cargo jq; do
        if ! command -v "$cmd" >/dev/null 2>&1; then
            log_json "setup" "Missing dependency" "local" "$cmd" 0 0 "fail" "missing $cmd"
            record_fail
            return 1
        fi
    done
    log_json "setup" "Dependencies ok" "local" "dependency check" 0 0 "pass"
    record_pass
}

build_binaries() {
    local rch_bin="${PROJECT_ROOT}/target/debug/rch"
    local rchd_bin="${PROJECT_ROOT}/target/debug/rchd"

    if [[ -x "$rch_bin" && -x "$rchd_bin" ]]; then
        log_json "setup" "Using existing rch/rchd binaries" "local" "cargo build" 0 0 "pass"
        record_pass
        echo "$rch_bin;$rchd_bin"
        return
    fi

    log_json "setup" "Building rch + rchd (debug)" "local" "cargo build -p rch -p rchd" 0 0 "start"
    if (cd "$PROJECT_ROOT" && cargo build -p rch -p rchd >/dev/null 2>&1); then
        log_json "setup" "Build completed" "local" "cargo build" 0 0 "pass"
        record_pass
    else
        log_json "setup" "Build failed" "local" "cargo build" 0 0 "fail" "cargo build failed"
        record_fail
        return 1
    fi

    echo "$rch_bin;$rchd_bin"
}

start_daemon() {
    tmp_root="$(mktemp -d "${TMPDIR:-/tmp}/rch-bd-155i-XXXXXX")"
    local workers_toml="$tmp_root/workers.toml"
    local socket_path="$tmp_root/rch.sock"

    cat > "$workers_toml" <<'WORKERS'
[[workers]]
id = "mock-1"
host = "127.0.0.1"
user = "test"
identity_file = "~/.ssh/id_rsa"
total_slots = 4
WORKERS

    log_json "setup" "Starting daemon (mock ssh)" "local" "rchd --socket" 0 0 "start"
    RCH_LOG_LEVEL=error RCH_TEST_MODE=1 RCH_MOCK_SSH=1 \
        "$rchd_bin" --socket "$socket_path" --workers-config "$workers_toml" --foreground \
        >"$tmp_root/rchd.log" 2>&1 &
    daemon_pid=$!

    for _ in {1..50}; do
        if [[ -S "$socket_path" ]]; then
            log_json "setup" "Daemon socket ready" "local" "$socket_path" 0 0 "pass"
            record_pass
            echo "$socket_path"
            return
        fi
        sleep 0.1
    done

    log_json "setup" "Daemon socket not ready" "local" "$socket_path" 0 0 "fail" "socket timeout"
    record_fail
    return 1
}

run_capabilities_check() {
    local socket_path="$1"
    local cap_cmd="rch workers capabilities --refresh --command bun test --json"

    log_json "classify" "Running workers capabilities" "local" "$cap_cmd" 0 0 "start"
    local start_ms
    start_ms="$(e2e_now_ms)"

    local output
    if ! output=$(RCH_DAEMON_SOCKET="$socket_path" RCH_TEST_MODE=1 RCH_MOCK_SSH=1 \
        "$rch_bin" workers capabilities --refresh --command "bun test" --json 2>/dev/null); then
        local duration_ms
        duration_ms=$(( $(e2e_now_ms) - start_ms ))
        log_json "exec" "Capabilities command failed" "local" "$cap_cmd" 0 "$duration_ms" "fail" "command failed"
        record_fail
        return 1
    fi

    local duration_ms
    duration_ms=$(( $(e2e_now_ms) - start_ms ))
    log_json "exec" "Capabilities command completed" "local" "$cap_cmd" 0 "$duration_ms" "pass"

    if ! echo "$output" | jq -e '.result.local' >/dev/null 2>&1; then
        log_json "verify" "Missing local capabilities field" "local" "$cap_cmd" 0 0 "fail" "local missing"
        record_fail
        return 1
    fi

    if ! echo "$output" | jq -r '.result.warnings[]?' | grep -q "required runtime bun"; then
        log_json "verify" "Missing required runtime warning" "local" "$cap_cmd" 0 0 "fail" "warning missing"
        record_fail
        return 1
    fi

    log_json "verify" "Capabilities warnings present" "local" "$cap_cmd" 0 0 "pass"
    record_pass
}

main() {
    mkdir -p "$(dirname "$LOG_FILE")"
    : > "$LOG_FILE"

    if ! check_dependencies; then
        return 1
    fi

    local bins
    if ! bins="$(build_binaries)"; then
        return 1
    fi
    rch_bin="${bins%;*}"
    rchd_bin="${bins#*;}"

    local socket_path
    if ! socket_path="$(start_daemon)"; then
        return 1
    fi

    if ! run_capabilities_check "$socket_path"; then
        return 1
    fi

    local elapsed_ms
    elapsed_ms=$(( $(e2e_now_ms) - run_start_ms ))
    local total_count
    total_count=$((passed_tests + failed_tests))
    log_json \
        "summary" \
        "bd-155i checks complete (pass=${passed_tests} fail=${failed_tests} total=${total_count})" \
        "local" \
        "summary" \
        0 \
        "$elapsed_ms" \
        "pass"
    return 0
}

main "$@"
