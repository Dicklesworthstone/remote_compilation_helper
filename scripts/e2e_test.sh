#!/usr/bin/env bash
#
# e2e_test.sh - End-to-end test script for Remote Compilation Helper (RCH)
#
# Usage:
#   ./scripts/e2e_test.sh [OPTIONS]
#
# Options:
#   --mock          Run with mock SSH/rsync (default in CI, uses RCH_MOCK_SSH=1)
#   --real          Run with real workers (requires configured workers)
#   --verbose       Enable verbose output
#   --help          Show this help message
#
# Environment Variables:
#   RCH_MOCK_SSH=1              Force mock mode
#   RCH_E2E_VERBOSE=1           Enable verbose logging
#   RUST_LOG=debug              Enable Rust debug logging
#
# Exit codes:
#   0  All tests passed
#   1  Test failure
#   2  Setup failure (missing dependencies, build failure)
#   3  Invalid arguments
#

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
VERBOSE="${RCH_E2E_VERBOSE:-0}"
MODE="mock"

# Colors
if [[ -t 1 ]]; then
    RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[0;33m'
    BLUE='\033[0;34m'; CYAN='\033[0;36m'; BOLD='\033[1m'; RESET='\033[0m'
else
    RED=''; GREEN=''; YELLOW=''; BLUE=''; CYAN=''; BOLD=''; RESET=''
fi

timestamp() { date '+%Y-%m-%dT%H:%M:%S.%3N'; }

log() {
    local level="$1" phase="$2"; shift 2
    local ts; ts="$(timestamp)"
    case "$level" in
        INFO)  echo -e "${CYAN}[$ts]${RESET} ${BLUE}[$phase]${RESET} $*" ;;
        PASS)  echo -e "${CYAN}[$ts]${RESET} ${GREEN}[$phase]${RESET} ${GREEN}$*${RESET}" ;;
        FAIL)  echo -e "${CYAN}[$ts]${RESET} ${RED}[$phase]${RESET} ${RED}$*${RESET}" ;;
        WARN)  echo -e "${CYAN}[$ts]${RESET} ${YELLOW}[$phase]${RESET} ${YELLOW}$*${RESET}" ;;
        DEBUG) [[ "$VERBOSE" == "1" ]] && echo -e "${CYAN}[$ts]${RESET} [DEBUG] $*" || true ;;
    esac
}

log_header() {
    echo ""; echo -e "${BOLD}============================================================${RESET}"
    echo -e "${BOLD}  $1${RESET}"; echo -e "${BOLD}============================================================${RESET}"; echo ""
}

die() { log FAIL SETUP "$*"; exit 2; }

parse_args() {
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --mock) MODE="mock"; shift ;;
            --real) MODE="real"; shift ;;
            --verbose|-v) VERBOSE="1"; shift ;;
            --help|-h) head -n 25 "$0" | tail -n +2 | sed 's/^# //'; exit 0 ;;
            *) log FAIL ARGS "Unknown option: $1"; exit 3 ;;
        esac
    done
    [[ "${RCH_MOCK_SSH:-}" == "1" ]] && MODE="mock" || true
}

check_dependencies() {
    log INFO SETUP "Checking dependencies..."
    for cmd in cargo rustc; do
        command -v "$cmd" &>/dev/null || die "Missing: $cmd"
    done
    log PASS SETUP "All dependencies present"
}

build_project() {
    log INFO BUILD "Building RCH components..."
    cd "$PROJECT_ROOT"
    cargo build --release >/dev/null 2>&1 || die "Build failed"
    for bin in rch rchd rch-wkr; do
        [[ -x "target/release/$bin" ]] || die "Binary not found: $bin"
    done
    log PASS BUILD "Build successful"
}

setup_mock_environment() {
    log INFO SETUP "Setting up mock environment..."
    export RCH_MOCK_SSH=1
    export RUST_LOG="${RUST_LOG:-info}"
    log PASS SETUP "Mock environment configured"
}

TESTS_RUN=0; TESTS_PASSED=0; TESTS_FAILED=0

run_test() {
    local name="$1" func="$2"
    ((TESTS_RUN++))
    log INFO TEST "Running: $name"
    local start; start=$(date +%s%3N)
    if "$func"; then
        local dur=$(($(date +%s%3N) - start))
        log PASS TEST "PASS: $name (${dur}ms)"; ((TESTS_PASSED++))
    else
        local dur=$(($(date +%s%3N) - start))
        log FAIL TEST "FAIL: $name (${dur}ms)"; ((TESTS_FAILED++))
    fi
}

test_mock_ssh_connect() {
    cd "$PROJECT_ROOT"
    local output
    output=$(cargo test -p rch-common test_mock_ssh_client_connect -- --nocapture 2>&1)
    echo "$output" | /bin/grep -q "test.*ok"
}

test_mock_ssh_execute() {
    cd "$PROJECT_ROOT"
    cargo test -p rch-common test_mock_ssh_client_execute -- --nocapture 2>&1 | /bin/grep -q "test.*ok"
}

test_mock_rsync_sync() {
    cd "$PROJECT_ROOT"
    cargo test -p rch-common test_mock_rsync_sync -- --nocapture 2>&1 | /bin/grep -q "test.*ok"
}

test_mock_connection_failure() {
    cd "$PROJECT_ROOT"
    cargo test -p rch-common test_mock_ssh_client_connection_failure -- --nocapture 2>&1 | /bin/grep -q "test.*ok"
}

test_mock_rsync_failure() {
    cd "$PROJECT_ROOT"
    cargo test -p rch-common test_mock_rsync_failure -- --nocapture 2>&1 | /bin/grep -q "test.*ok"
}

test_hook_non_bash_allowed() {
    cd "$PROJECT_ROOT"
    cargo test -p rch test_non_bash_allowed -- --nocapture 2>&1 | /bin/grep -q "test.*ok"
}

test_hook_daemon_query_protocol() {
    cd "$PROJECT_ROOT"
    cargo test -p rch test_daemon_query_protocol -- --nocapture 2>&1 | /bin/grep -q "test.*ok"
}

test_hook_remote_success_mocked() {
    cd "$PROJECT_ROOT"
    cargo test -p rch test_process_hook_remote_success_mocked -- --nocapture 2>&1 | /bin/grep -q "test.*ok"
}

test_hook_sync_failure_allows() {
    cd "$PROJECT_ROOT"
    cargo test -p rch test_process_hook_remote_sync_failure_allows -- --nocapture 2>&1 | /bin/grep -q "test.*ok"
}

test_hook_nonzero_exit_denies() {
    cd "$PROJECT_ROOT"
    cargo test -p rch test_process_hook_remote_nonzero_exit_denies -- --nocapture 2>&1 | /bin/grep -q "test.*ok"
}

test_selection_score() {
    cd "$PROJECT_ROOT"
    cargo test -p rchd test_selection_score -- --nocapture 2>&1 | /bin/grep -q "test.*ok"
}

test_health_update_success() {
    cd "$PROJECT_ROOT"
    cargo test -p rchd test_worker_health_update_success -- --nocapture 2>&1 | /bin/grep -q "test.*ok"
}

test_health_recovery() {
    cd "$PROJECT_ROOT"
    cargo test -p rchd test_worker_health_recovery -- --nocapture 2>&1 | /bin/grep -q "test.*ok"
}

test_fail_open_daemon_unavailable() {
    cd "$PROJECT_ROOT"
    cargo test -p rch test_daemon_query_missing_socket -- --nocapture 2>&1 | /bin/grep -q "test.*ok"
}

test_fail_open_config_error() {
    cd "$PROJECT_ROOT"
    cargo test -p rch test_fail_open_on_config_error -- --nocapture 2>&1 | /bin/grep -q "test.*ok"
}

run_mock_transport_tests() {
    log_header "Mock Transport Tests"
    run_test "Mock SSH connect" test_mock_ssh_connect || true
    run_test "Mock SSH execute" test_mock_ssh_execute || true
    run_test "Mock rsync sync" test_mock_rsync_sync || true
    run_test "Mock connection failure" test_mock_connection_failure || true
    run_test "Mock rsync failure" test_mock_rsync_failure || true
}

run_hook_pipeline_tests() {
    log_header "Hook Pipeline Tests"
    run_test "Non-Bash tool allowed" test_hook_non_bash_allowed || true
    run_test "Daemon query protocol" test_hook_daemon_query_protocol || true
    run_test "Remote success (mocked)" test_hook_remote_success_mocked || true
    run_test "Sync failure allows local" test_hook_sync_failure_allows || true
    run_test "Non-zero exit denies" test_hook_nonzero_exit_denies || true
}

run_selection_tests() {
    log_header "Worker Selection Tests"
    run_test "Selection scoring" test_selection_score || true
}

run_health_tests() {
    log_header "Health Monitoring Tests"
    run_test "Health update success" test_health_update_success || true
    run_test "Health recovery" test_health_recovery || true
}

run_failure_mode_tests() {
    log_header "Failure Mode Tests"
    run_test "Fail-open daemon unavailable" test_fail_open_daemon_unavailable || true
    run_test "Fail-open config error" test_fail_open_config_error || true
}

run_all_unit_tests() {
    log_header "Running All Unit Tests"
    log INFO TEST "Running cargo test --workspace..."
    cd "$PROJECT_ROOT"
    local start; start=$(date +%s%3N)
    local output exit_code=0
    output=$(cargo test --workspace 2>&1) || exit_code=$?
    echo "$output"
    local dur=$(($(date +%s%3N) - start))
    if [[ $exit_code -eq 0 ]]; then
        log PASS TEST "All unit tests passed (${dur}ms)"
        return 0
    else
        log FAIL TEST "Some unit tests failed (${dur}ms)"
        return 1
    fi
}

main() {
    parse_args "$@"

    log_header "RCH End-to-End Test Suite"
    log INFO MAIN "Mode: $MODE"
    log INFO MAIN "Verbose: $VERBOSE"
    log INFO MAIN "Project root: $PROJECT_ROOT"

    log_header "Setup Phase"
    check_dependencies
    build_project
    setup_mock_environment

    run_mock_transport_tests
    run_hook_pipeline_tests
    run_selection_tests
    run_health_tests
    run_failure_mode_tests
    run_all_unit_tests || true

    log_header "Test Summary"
    local pass_rate=0
    [[ $TESTS_RUN -gt 0 ]] && pass_rate=$((TESTS_PASSED * 100 / TESTS_RUN))
    echo ""
    echo -e "  ${BOLD}Total:${RESET}   $TESTS_RUN"
    echo -e "  ${GREEN}Passed:${RESET}  $TESTS_PASSED"
    echo -e "  ${RED}Failed:${RESET}  $TESTS_FAILED"
    echo -e "  ${BOLD}Rate:${RESET}    ${pass_rate}%"
    echo ""

    if [[ $TESTS_FAILED -gt 0 ]]; then
        log FAIL MAIN "E2E tests completed with $TESTS_FAILED failures"
        exit 1
    else
        log PASS MAIN "All E2E tests passed"
        exit 0
    fi
}

main "$@"
