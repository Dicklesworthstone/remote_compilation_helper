#!/usr/bin/env bash
#
# e2e_test.sh - End-to-end pipeline test for Remote Compilation Helper (RCH)
#
# Usage:
#   ./scripts/e2e_test.sh [OPTIONS]
#
# Options:
#   --mock                 Run with mock SSH/rsync (default)
#   --real                 Run with real workers (requires env below)
#   --fail MODE            Inject failure: sync|exec|artifacts|worker-down|remote-exit|toolchain-install|no-rustup
#   --run-all              In mock mode, run success + failure scenarios
#   --unit                 Also run `cargo test --workspace`
#   --verbose              Enable verbose output
#   --help                 Show this help message
#
# Environment (real mode):
#   RCH_E2E_WORKERS_FILE    Path to workers.toml (preferred)
#   RCH_E2E_WORKER_HOST     Worker host
#   RCH_E2E_WORKER_USER     SSH user (default: ubuntu)
#   RCH_E2E_WORKER_KEY      SSH key path (default: ~/.ssh/id_rsa)
#   RCH_E2E_WORKER_ID       Worker id (default: e2e-worker)
#   RCH_E2E_WORKER_SLOTS    Total slots (default: 8)
#
# Notes:
# - Mock mode uses RCH_MOCK_SSH=1 and does NOT create real artifacts.
# - For mock runs we validate that the artifact phase executed via hook logs.
#

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
MODE="mock"
FAIL_MODE=""
RUN_ALL="0"
RUN_UNIT="0"
VERBOSE="${RCH_E2E_VERBOSE:-0}"

timestamp() { date -u '+%Y-%m-%dT%H:%M:%S.%3NZ'; }

log() {
    local level="$1" phase="$2"; shift 2
    local ts; ts="$(timestamp)"
    echo "[$ts] [$level] [$phase] $*"
}

die() { log "FAIL" "SETUP" "$*"; exit 2; }

usage() {
    sed -n '1,40p' "$0" | sed 's/^# \{0,1\}//'
}

parse_args() {
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --mock) MODE="mock"; shift ;;
            --real) MODE="real"; shift ;;
            --fail) FAIL_MODE="${2:-}"; shift 2 ;;
            --run-all) RUN_ALL="1"; shift ;;
            --unit) RUN_UNIT="1"; shift ;;
            --verbose|-v) VERBOSE="1"; shift ;;
            --help|-h) usage; exit 0 ;;
            *) log "FAIL" "ARGS" "Unknown option: $1"; exit 3 ;;
        esac
    done
    [[ "${RCH_MOCK_SSH:-}" == "1" ]] && MODE="mock" || true
    if [[ "$MODE" == "mock" && "$RUN_ALL" == "0" ]]; then
        RUN_ALL="1"
    fi
}

check_dependencies() {
    log "INFO" "SETUP" "Checking dependencies..."
    for cmd in cargo rustc; do
        command -v "$cmd" >/dev/null 2>&1 || die "Missing: $cmd"
    done
    log "INFO" "SETUP" "Dependencies OK"
}

build_binaries() {
    log "INFO" "BUILD" "Building rch + rchd (debug)..."
    cd "$PROJECT_ROOT"
    cargo build -p rch -p rchd >/dev/null 2>&1 || die "Build failed"
    [[ -x "$PROJECT_ROOT/target/debug/rch" ]] || die "Binary missing: rch"
    [[ -x "$PROJECT_ROOT/target/debug/rchd" ]] || die "Binary missing: rchd"
    log "INFO" "BUILD" "Build OK"
}

make_test_project() {
    TEST_ROOT="$(mktemp -d "${TMPDIR:-/tmp}/rch-e2e-XXXXXX")"
    PROJECT_DIR="$TEST_ROOT/project"
    LOG_DIR="$TEST_ROOT/logs"
    mkdir -p "$PROJECT_DIR/src" "$LOG_DIR"

    cat >"$PROJECT_DIR/Cargo.toml" <<'EOF'
[package]
name = "rch_e2e_app"
version = "0.1.0"
edition = "2024"

[dependencies]
EOF

    cat >"$PROJECT_DIR/src/main.rs" <<'EOF'
fn main() {
    println!("rch e2e ok");
}
EOF

    log "INFO" "SETUP" "Test project: $PROJECT_DIR"
    log "INFO" "SETUP" "Logs: $LOG_DIR"
}

write_workers_config() {
    WORKERS_FILE="$TEST_ROOT/workers.toml"

    if [[ "$MODE" == "mock" ]]; then
        cat >"$WORKERS_FILE" <<'EOF'
[[workers]]
id = "mock-worker"
host = "mock.host"
user = "mockuser"
identity_file = "~/.ssh/mock"
total_slots = 64
priority = 100
enabled = true
EOF
        return
    fi

    if [[ -n "${RCH_E2E_WORKERS_FILE:-}" ]]; then
        if [[ ! -f "$RCH_E2E_WORKERS_FILE" ]]; then
            die "RCH_E2E_WORKERS_FILE not found: $RCH_E2E_WORKERS_FILE"
        fi
        WORKERS_FILE="$RCH_E2E_WORKERS_FILE"
        return
    fi

    local host="${RCH_E2E_WORKER_HOST:-}"
    local user="${RCH_E2E_WORKER_USER:-ubuntu}"
    local key="${RCH_E2E_WORKER_KEY:-~/.ssh/id_rsa}"
    local wid="${RCH_E2E_WORKER_ID:-e2e-worker}"
    local slots="${RCH_E2E_WORKER_SLOTS:-8}"

    [[ -n "$host" ]] || die "RCH_E2E_WORKER_HOST is required for --real"

    cat >"$WORKERS_FILE" <<EOF
[[workers]]
id = "$wid"
host = "$host"
user = "$user"
identity_file = "$key"
total_slots = $slots
priority = 100
enabled = true
EOF
}

start_daemon() {
    SOCKET_PATH="$TEST_ROOT/rch.sock"
    DAEMON_LOG="$LOG_DIR/rchd.log"

    log "INFO" "DAEMON" "Starting rchd (socket: $SOCKET_PATH)"
    if [[ "$MODE" == "mock" ]]; then
        env RCH_MOCK_SSH=1 RCH_MOCK_SSH_STDOUT=health_check \
            "$PROJECT_ROOT/target/debug/rchd" \
            --socket "$SOCKET_PATH" \
            --workers-config "$WORKERS_FILE" \
            --foreground \
            >>"$DAEMON_LOG" 2>&1 &
    else
        "$PROJECT_ROOT/target/debug/rchd" \
            --socket "$SOCKET_PATH" \
            --workers-config "$WORKERS_FILE" \
            --foreground \
            >>"$DAEMON_LOG" 2>&1 &
    fi
    RCHD_PID=$!

    local waited=0
    while [[ ! -S "$SOCKET_PATH" && $waited -lt 50 ]]; do
        sleep 0.1
        waited=$((waited + 1))
    done

    if [[ ! -S "$SOCKET_PATH" ]]; then
        die "Daemon socket not found after startup (log: $DAEMON_LOG)"
    fi
    log "INFO" "DAEMON" "Daemon ready (pid: $RCHD_PID)"
}

stop_daemon() {
    if [[ -n "${RCHD_PID:-}" ]]; then
        log "INFO" "DAEMON" "Stopping rchd (pid: $RCHD_PID)"
        kill "$RCHD_PID" >/dev/null 2>&1 || true
    fi
}

hook_json() {
    cat <<'JSON'
{
  "tool_name": "Bash",
  "tool_input": {
    "command": "cargo build",
    "description": "rch e2e build"
  }
}
JSON
}

# Hook JSON with toolchain specification for toolchain sync tests
hook_json_with_toolchain() {
    local toolchain="${1:-nightly-2024-01-15}"
    cat <<JSON
{
  "tool_name": "Bash",
  "tool_input": {
    "command": "cargo build",
    "description": "rch e2e build with toolchain",
    "toolchain": "$toolchain"
  }
}
JSON
}

run_hook() {
    local scenario="$1"; shift
    local hook_out="$LOG_DIR/hook_${scenario}.out"
    local hook_err="$LOG_DIR/hook_${scenario}.err"
    local env_args=("$@")

    log "INFO" "HOOK" "Running hook ($scenario)" >&2
    (
        cd "$PROJECT_DIR"
        printf '%s\n' "$(hook_json)" | \
            env RCH_SOCKET_PATH="$SOCKET_PATH" "${env_args[@]}" \
            "$PROJECT_ROOT/target/debug/rch" >"$hook_out" 2>"$hook_err"
    )

    if /bin/grep -q '"permissionDecision":"deny"' "$hook_out"; then
        echo "deny"
    else
        echo "allow"
    fi
}

# Run hook with toolchain specification (for toolchain sync tests)
run_hook_with_toolchain() {
    local scenario="$1"
    local toolchain="$2"
    shift 2
    local hook_out="$LOG_DIR/hook_${scenario}.out"
    local hook_err="$LOG_DIR/hook_${scenario}.err"
    local env_args=("$@")

    log "INFO" "HOOK" "Running hook with toolchain ($scenario, tc=$toolchain)" >&2
    (
        cd "$PROJECT_DIR"
        printf '%s\n' "$(hook_json_with_toolchain "$toolchain")" | \
            env RCH_SOCKET_PATH="$SOCKET_PATH" "${env_args[@]}" \
            "$PROJECT_ROOT/target/debug/rch" >"$hook_out" 2>"$hook_err"
    )

    if /bin/grep -q '"permissionDecision":"deny"' "$hook_out"; then
        echo "deny"
    else
        echo "allow"
    fi
}

check_artifacts_real() {
    local bin_path="$PROJECT_DIR/target/debug/rch_e2e_app"
    [[ -x "$bin_path" ]]
}

check_artifacts_mock() {
    local hook_err="$1"
    local hook_out="${hook_err%.err}.out"
    /bin/grep -q "Artifacts retrieved" "$hook_err" || /bin/grep -q "Artifacts retrieved" "$hook_out"
}

check_artifacts_mock_failure() {
    local hook_err="$1"
    local hook_out="${hook_err%.err}.out"
    /bin/grep -q "Failed to retrieve artifacts" "$hook_err" || \
        /bin/grep -q "Failed to retrieve artifacts" "$hook_out"
}

# Check that toolchain failure was logged with decision path
check_toolchain_failure_logged() {
    local hook_err="$1"
    local hook_out="${hook_err%.err}.out"
    # Look for toolchain-related log messages
    /bin/grep -qi "toolchain" "$hook_err" || \
        /bin/grep -qi "toolchain" "$hook_out" || \
        /bin/grep -qi "rustup" "$hook_err" || \
        /bin/grep -qi "rustup" "$hook_out"
}

# Check that no-rustup fallback was logged
check_no_rustup_logged() {
    local hook_err="$1"
    local hook_out="${hook_err%.err}.out"
    /bin/grep -qi "rustup not available\|no rustup\|Continuing with default" "$hook_err" || \
        /bin/grep -qi "rustup not available\|no rustup\|Continuing with default" "$hook_out"
}

run_scenario() {
    local scenario="$1"
    local expect="$2"
    local fail="$3"
    local envs=()

    if [[ "$MODE" == "mock" ]]; then
        envs+=("RCH_MOCK_SSH=1")
    fi

    case "$fail" in
        sync) envs+=("RCH_MOCK_RSYNC_FAIL_SYNC=1") ;;
        exec) envs+=("RCH_MOCK_SSH_FAIL_EXECUTE=1") ;;
        artifacts) envs+=("RCH_MOCK_RSYNC_FAIL_ARTIFACTS=1") ;;
        worker-down) envs+=("RCH_MOCK_SSH_FAIL_CONNECT=1") ;;
        remote-exit) envs+=("RCH_MOCK_SSH_EXIT_CODE=2") ;;
        toolchain-install) envs+=("RCH_MOCK_TOOLCHAIN_INSTALL_FAIL=1") ;;
        no-rustup) envs+=("RCH_MOCK_NO_RUSTUP=1") ;;
        "") ;;
        *) die "Unknown failure mode: $fail" ;;
    esac

    local result
    result="$(run_hook "$scenario" "${envs[@]}")"

    if [[ "$result" != "$expect" ]]; then
        log "FAIL" "SCENARIO" "$scenario expected $expect, got $result"
        return 1
    fi

    if [[ "$MODE" == "real" && "$expect" == "deny" && "$fail" != "artifacts" ]]; then
        if check_artifacts_real; then
            log "INFO" "ARTIFACTS" "$scenario artifacts present"
        else
            log "FAIL" "ARTIFACTS" "$scenario artifacts missing"
            return 1
        fi
    fi

    if [[ "$MODE" == "mock" && "$expect" == "deny" && "$fail" != "sync" && "$fail" != "exec" && "$fail" != "worker-down" && "$fail" != "remote-exit" && "$fail" != "toolchain-install" && "$fail" != "no-rustup" ]]; then
        if [[ "$fail" == "artifacts" ]]; then
            if check_artifacts_mock_failure "$LOG_DIR/hook_${scenario}.err"; then
                log "INFO" "ARTIFACTS" "$scenario artifact failure logged"
            else
                log "FAIL" "ARTIFACTS" "$scenario artifact failure missing"
                return 1
            fi
        else
            if check_artifacts_mock "$LOG_DIR/hook_${scenario}.err"; then
                log "INFO" "ARTIFACTS" "$scenario artifact phase logged"
            else
                log "FAIL" "ARTIFACTS" "$scenario artifact phase missing"
                return 1
            fi
        fi
    fi

    # Toolchain-specific checks (allow fallback expected)
    if [[ "$MODE" == "mock" && "$fail" == "toolchain-install" ]]; then
        log "INFO" "TOOLCHAIN" "$scenario: toolchain install failure triggered local fallback"
    fi

    if [[ "$MODE" == "mock" && "$fail" == "no-rustup" ]]; then
        log "INFO" "TOOLCHAIN" "$scenario: no-rustup triggered local fallback"
    fi

    log "INFO" "SCENARIO" "$scenario OK"
}

# Run a scenario with explicit toolchain specification
run_toolchain_scenario() {
    local scenario="$1"
    local toolchain="$2"
    local expect="$3"
    local fail="$4"
    local envs=()

    if [[ "$MODE" == "mock" ]]; then
        envs+=("RCH_MOCK_SSH=1")
    fi

    case "$fail" in
        toolchain-install) envs+=("RCH_MOCK_TOOLCHAIN_INSTALL_FAIL=1") ;;
        no-rustup) envs+=("RCH_MOCK_NO_RUSTUP=1") ;;
        "") ;;
        *) die "Unknown toolchain failure mode: $fail" ;;
    esac

    local result
    result="$(run_hook_with_toolchain "$scenario" "$toolchain" "${envs[@]}")"

    if [[ "$result" != "$expect" ]]; then
        log "FAIL" "TOOLCHAIN" "$scenario expected $expect, got $result"
        return 1
    fi

    # Verify decision path logging
    local hook_err="$LOG_DIR/hook_${scenario}.err"
    local hook_out="$LOG_DIR/hook_${scenario}.out"

    if [[ "$fail" == "toolchain-install" ]]; then
        if check_toolchain_failure_logged "$hook_err"; then
            log "INFO" "TOOLCHAIN" "$scenario: toolchain failure properly logged"
        else
            log "WARN" "TOOLCHAIN" "$scenario: toolchain failure not explicitly logged (may be hidden)"
        fi
    fi

    if [[ "$fail" == "no-rustup" ]]; then
        if check_no_rustup_logged "$hook_err"; then
            log "INFO" "TOOLCHAIN" "$scenario: no-rustup properly logged"
        else
            log "WARN" "TOOLCHAIN" "$scenario: no-rustup not explicitly logged (may be hidden)"
        fi
    fi

    log "INFO" "TOOLCHAIN" "$scenario OK (tc=$toolchain)"
}

run_e2e() {
    log "INFO" "E2E" "Mode: $MODE"
    log "INFO" "E2E" "Scenario: ${FAIL_MODE:-success}"

    if [[ "$RUN_ALL" == "1" && "$MODE" == "mock" ]]; then
        run_scenario "success" "deny" ""
        run_scenario "sync_fail" "allow" "sync"
        run_scenario "exec_fail" "allow" "exec"
        run_scenario "worker_down" "allow" "worker-down"
        run_scenario "artifact_fail" "deny" "artifacts"
        run_scenario "remote_exit" "deny" "remote-exit"

        # Toolchain synchronization scenarios
        log "INFO" "E2E" "Running toolchain synchronization scenarios..."
        run_scenario "toolchain_install_fail" "allow" "toolchain-install"
        run_scenario "no_rustup" "allow" "no-rustup"
        log "INFO" "E2E" "Toolchain scenarios complete"
        return
    fi

    if [[ -n "$FAIL_MODE" ]]; then
        case "$FAIL_MODE" in
            sync|exec|worker-down|toolchain-install|no-rustup) run_scenario "$FAIL_MODE" "allow" "$FAIL_MODE" ;;
            artifacts|remote-exit) run_scenario "$FAIL_MODE" "deny" "$FAIL_MODE" ;;
            *) die "Unknown failure mode: $FAIL_MODE" ;;
        esac
    else
        run_scenario "success" "deny" ""
    fi
}

run_unit_tests() {
    log "INFO" "UNIT" "Running cargo test --workspace"
    cd "$PROJECT_ROOT"
    cargo test --workspace
}

main() {
    parse_args "$@"
    check_dependencies
    build_binaries
    make_test_project
    write_workers_config
    start_daemon

    trap stop_daemon EXIT

    if [[ "$MODE" == "mock" ]]; then
        export RUST_LOG="${RUST_LOG:-info}"
    fi

    run_e2e

    if [[ "$RUN_UNIT" == "1" ]]; then
        run_unit_tests
    fi

    log "INFO" "DONE" "E2E complete. Logs in $LOG_DIR"
    log "INFO" "DONE" "Temp project kept at $TEST_ROOT"
}

main "$@"
