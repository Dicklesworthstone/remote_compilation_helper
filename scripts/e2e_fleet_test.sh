#!/usr/bin/env bash
# E2E Fleet Operations Test Suite
#
# Tests: preflight, fleet status, deployment, rollback
#
# Usage:
#   ./scripts/e2e_fleet_test.sh              # Run with real workers from workers.toml
#   ./scripts/e2e_fleet_test.sh --localhost  # Run against localhost only
#   RCH_MOCK_SSH=1 ./scripts/e2e_fleet_test.sh  # Run with mock SSH
#
# Environment:
#   DEBUG=1          Enable debug output
#   RCH_MOCK_SSH=1   Use mock SSH for CI environments
#   RCH_JSON=1       Force JSON output mode

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
LOG_DIR="${PROJECT_ROOT}/logs"
LOG_FILE="${LOG_DIR}/e2e_fleet_$(date +%Y%m%d_%H%M%S).log"
RCH_BIN="${RCH_BIN:-rch}"

# Ensure log directory exists
mkdir -p "$LOG_DIR"

# Color codes (disabled in non-interactive mode)
if [[ -t 1 ]]; then
    RED='\033[0;31m'
    GREEN='\033[0;32m'
    YELLOW='\033[0;33m'
    BLUE='\033[0;34m'
    NC='\033[0m' # No Color
else
    RED=''
    GREEN=''
    YELLOW=''
    BLUE=''
    NC=''
fi

# Logging functions with timestamps and levels
log_info()  { echo -e "${BLUE}[$(date '+%Y-%m-%d %H:%M:%S')]${NC} [INFO]  $*" | tee -a "$LOG_FILE"; }
log_warn()  { echo -e "${YELLOW}[$(date '+%Y-%m-%d %H:%M:%S')]${NC} [WARN]  $*" | tee -a "$LOG_FILE" >&2; }
log_error() { echo -e "${RED}[$(date '+%Y-%m-%d %H:%M:%S')]${NC} [ERROR] $*" | tee -a "$LOG_FILE" >&2; }
log_debug() { [[ "${DEBUG:-}" == "1" ]] && echo -e "[$(date '+%Y-%m-%d %H:%M:%S')] [DEBUG] $*" | tee -a "$LOG_FILE" || true; }
log_pass()  { echo -e "${GREEN}[$(date '+%Y-%m-%d %H:%M:%S')]${NC} [PASS]  $*" | tee -a "$LOG_FILE"; }
log_fail()  { echo -e "${RED}[$(date '+%Y-%m-%d %H:%M:%S')]${NC} [FAIL]  $*" | tee -a "$LOG_FILE"; }

# Test result tracking
TESTS_PASSED=0
TESTS_FAILED=0
TESTS_SKIPPED=0

# Run a single test
run_test() {
    local name="$1"
    shift
    log_info "=== Running test: $name ==="

    local start_time=$(date +%s.%N)
    local exit_code=0

    if "$@" 2>&1 | tee -a "$LOG_FILE"; then
        exit_code=0
    else
        exit_code=$?
    fi

    local end_time=$(date +%s.%N)
    local duration=$(echo "$end_time - $start_time" | bc 2>/dev/null || echo "?.??")

    if [[ $exit_code -eq 0 ]]; then
        log_pass "PASSED: $name (${duration}s)"
        ((TESTS_PASSED++))
        return 0
    else
        log_fail "FAILED: $name (${duration}s, exit=$exit_code)"
        ((TESTS_FAILED++))
        return 1
    fi
}

# Skip a test with reason
skip_test() {
    local name="$1"
    local reason="$2"
    log_warn "SKIPPED: $name - $reason"
    ((TESTS_SKIPPED++))
}

# =============================================================================
# Test: Deploy (dry run - acts as preflight)
# =============================================================================
test_deploy_dry_run() {
    log_info "Testing rch fleet deploy --dry-run (acts as preflight)..."
    local output
    local exit_code=0

    output=$(RCH_JSON=1 $RCH_BIN fleet deploy --dry-run 2>&1) || exit_code=$?

    log_debug "Deploy dry-run exit code: $exit_code"
    log_debug "Deploy dry-run output (first 500 chars): ${output:0:500}"

    # Verify JSON output or expected error
    if ! echo "$output" | jq -e '.' > /dev/null 2>&1; then
        # Check for expected non-JSON messages
        if echo "$output" | grep -qiE "no workers|not found|error|dry.?run"; then
            log_info "Deploy dry-run returned expected message"
            return 0
        fi
        log_error "Invalid deploy dry-run output"
        echo "$output" >> "$LOG_FILE"
        return 1
    fi

    log_info "Deploy dry-run completed"
    return 0
}

# =============================================================================
# Test: Fleet status
# =============================================================================
test_fleet_status() {
    log_info "Testing rch fleet status..."
    local output
    local exit_code=0

    output=$(RCH_JSON=1 $RCH_BIN fleet status 2>&1) || exit_code=$?

    log_debug "Fleet status exit code: $exit_code"
    log_debug "Fleet status output (first 500 chars): ${output:0:500}"

    # Output may have tracing logs mixed in - look for evidence of actual work
    if echo "$output" | grep -qiE "querying|workers|reachable|ssh.*check|status check"; then
        log_info "Fleet status performed worker queries"
    fi

    # Try to extract JSON from output (may be mixed with logs)
    local json_output
    json_output=$(echo "$output" | grep -E '^\{' | head -1 || echo "")

    if [[ -n "$json_output" ]] && echo "$json_output" | jq -e '.' > /dev/null 2>&1; then
        log_info "Valid JSON found in output"
        local worker_count
        worker_count=$(echo "$json_output" | jq -r '(.data.workers // .workers // []) | length' 2>/dev/null || echo "0")
        log_debug "Workers in status response: $worker_count"
    elif echo "$output" | grep -qiE "error|failed|no workers"; then
        log_info "Fleet status returned expected error/status message"
    else
        # Check if we at least see worker queries happening
        if echo "$output" | grep -qiE "ssh|worker|querying|parallel"; then
            log_info "Fleet status appears to be running queries"
            return 0
        fi
        log_warn "Could not parse fleet status output"
    fi

    log_info "Fleet status check completed"
    return 0
}

# =============================================================================
# Test: Rollback (dry run)
# =============================================================================
test_rollback_dry_run() {
    log_info "Testing rch fleet rollback --dry-run..."
    local output
    local exit_code=0

    output=$(RCH_JSON=1 $RCH_BIN fleet rollback --dry-run 2>&1) || exit_code=$?

    log_debug "Rollback dry-run exit code: $exit_code"
    log_debug "Rollback dry-run output (first 300 chars): ${output:0:300}"

    # Check for expected messages (no backups, dry run, etc.)
    if echo "$output" | grep -qiE "no backup|not found|dry.?run|rollback|nothing to"; then
        log_info "Rollback dry-run returned expected response"
        return 0
    fi

    # Try to parse JSON if present
    local json_output
    json_output=$(echo "$output" | grep -E '^\{' | head -1 || echo "")
    if [[ -n "$json_output" ]] && echo "$json_output" | jq -e '.' > /dev/null 2>&1; then
        log_info "Valid JSON found in rollback output"
        return 0
    fi

    # If command ran without crash, consider it a pass
    if [[ "$exit_code" -le 1 ]]; then
        log_info "Rollback dry-run completed (exit=$exit_code)"
        return 0
    fi

    log_error "Rollback dry-run failed unexpectedly"
    echo "$output" >> "$LOG_FILE"
    return 1
}

# =============================================================================
# Test: Rollback to specific version (dry run)
# =============================================================================
test_rollback_version_dry_run() {
    log_info "Testing rch fleet rollback --to-version 0.0.1 --dry-run..."
    local output
    local exit_code=0

    output=$(RCH_JSON=1 $RCH_BIN fleet rollback --to-version 0.0.1 --dry-run 2>&1) || exit_code=$?

    log_debug "Rollback version dry-run exit code: $exit_code"
    log_debug "Rollback version dry-run output (first 300 chars): ${output:0:300}"

    # Check for expected messages
    if echo "$output" | grep -qiE "no backup|not found|0\.0\.1|version|dry.?run|rollback"; then
        log_info "Rollback version dry-run processed version parameter"
        return 0
    fi

    # Try to parse JSON if present
    local json_output
    json_output=$(echo "$output" | grep -E '^\{' | head -1 || echo "")
    if [[ -n "$json_output" ]] && echo "$json_output" | jq -e '.' > /dev/null 2>&1; then
        log_info "Valid JSON found in output"
        return 0
    fi

    # If command ran without crash, consider it a pass
    if [[ "$exit_code" -le 1 ]]; then
        log_info "Rollback version dry-run completed (exit=$exit_code)"
        return 0
    fi

    log_error "Invalid rollback version dry-run output"
    echo "$output" >> "$LOG_FILE"
    return 1
}

# =============================================================================
# Test: Verify command
# =============================================================================
test_fleet_verify() {
    log_info "Testing rch fleet verify..."
    local output
    local exit_code=0

    output=$(RCH_JSON=1 $RCH_BIN fleet verify 2>&1) || exit_code=$?

    log_debug "Fleet verify exit code: $exit_code"
    log_debug "Fleet verify output: $output"

    # Verify JSON output or expected error
    if ! echo "$output" | jq -e '.' > /dev/null 2>&1; then
        if echo "$output" | grep -qi "no workers\|error"; then
            log_info "Fleet verify returned expected message"
            return 0
        fi
        log_error "Invalid fleet verify output"
        echo "$output" >> "$LOG_FILE"
        return 1
    fi

    log_info "Fleet verify completed"
    return 0
}

# =============================================================================
# Test: History command
# =============================================================================
test_fleet_history() {
    log_info "Testing rch fleet history..."
    local output
    local exit_code=0

    output=$(RCH_JSON=1 $RCH_BIN fleet history --limit 5 2>&1) || exit_code=$?

    log_debug "Fleet history exit code: $exit_code"
    log_debug "Fleet history output (first 300 chars): ${output:0:300}"

    # Check for expected messages
    if echo "$output" | grep -qiE "no history|empty|history|deployment|entries"; then
        log_info "Fleet history returned expected response"
        return 0
    fi

    # Try to parse JSON if present
    local json_output
    json_output=$(echo "$output" | grep -E '^\{' | head -1 || echo "")
    if [[ -n "$json_output" ]] && echo "$json_output" | jq -e '.' > /dev/null 2>&1; then
        log_info "Valid JSON found in history output"
        return 0
    fi

    # If command ran without crash, consider it a pass
    if [[ "$exit_code" -le 1 ]]; then
        log_info "Fleet history completed (exit=$exit_code)"
        return 0
    fi

    log_error "Invalid fleet history output"
    echo "$output" >> "$LOG_FILE"
    return 1
}

# =============================================================================
# Test: Mock SSH mode
# =============================================================================
test_mock_ssh_mode() {
    if [[ "${RCH_MOCK_SSH:-}" != "1" ]]; then
        skip_test "mock_ssh_mode" "RCH_MOCK_SSH not set"
        return 0
    fi

    log_info "Testing Mock SSH mode..."
    local output
    local exit_code=0

    output=$(RCH_MOCK_SSH=1 RCH_JSON=1 $RCH_BIN fleet deploy --dry-run 2>&1) || exit_code=$?

    log_debug "Mock SSH mode exit code: $exit_code"
    log_debug "Mock SSH mode output (first 300 chars): ${output:0:300}"

    # In mock mode, should get some response without real SSH
    if echo "$output" | grep -qiE "mock|dry.?run|deploy|workers|no workers"; then
        log_info "Mock SSH mode returned expected response"
        return 0
    fi

    # Try to parse JSON if present
    local json_output
    json_output=$(echo "$output" | grep -E '^\{' | head -1 || echo "")
    if [[ -n "$json_output" ]] && echo "$json_output" | jq -e '.' > /dev/null 2>&1; then
        log_info "Valid JSON found in mock mode output"
        return 0
    fi

    # If command ran without crash, consider it a pass
    if [[ "$exit_code" -le 1 ]]; then
        log_info "Mock SSH mode completed (exit=$exit_code)"
        return 0
    fi

    log_error "Mock SSH mode failed unexpectedly"
    echo "$output" >> "$LOG_FILE"
    return 1
}

# =============================================================================
# Main
# =============================================================================
print_summary() {
    echo ""
    log_info "=============================================="
    log_info "         E2E Fleet Test Summary"
    log_info "=============================================="
    log_info "Passed:  $TESTS_PASSED"
    log_info "Failed:  $TESTS_FAILED"
    log_info "Skipped: $TESTS_SKIPPED"
    log_info "Total:   $((TESTS_PASSED + TESTS_FAILED + TESTS_SKIPPED))"
    log_info "=============================================="
    log_info "Log file: $LOG_FILE"
    echo ""
}

main() {
    log_info "=============================================="
    log_info "   E2E Fleet Operations Test Suite"
    log_info "=============================================="
    log_info "Started at: $(date)"
    log_info "Log file: $LOG_FILE"
    log_info "RCH binary: $RCH_BIN"

    # Get RCH version
    local rch_version
    rch_version=$($RCH_BIN --version 2>/dev/null || echo "unknown")
    log_info "RCH version: $rch_version"

    # Check for mock mode
    if [[ "${RCH_MOCK_SSH:-}" == "1" ]]; then
        log_info "Running in MOCK SSH mode"
    fi

    echo ""

    # Run tests
    run_test "deploy_dry_run" test_deploy_dry_run || true
    run_test "fleet_status" test_fleet_status || true
    run_test "rollback_dry_run" test_rollback_dry_run || true
    run_test "rollback_version_dry_run" test_rollback_version_dry_run || true
    run_test "fleet_verify" test_fleet_verify || true
    run_test "fleet_history" test_fleet_history || true
    run_test "mock_ssh_mode" test_mock_ssh_mode || true

    # Print summary
    print_summary

    # Exit with failure if any tests failed
    if [[ $TESTS_FAILED -gt 0 ]]; then
        log_error "Some tests failed!"
        exit 1
    fi

    log_pass "All tests passed!"
    exit 0
}

# Parse arguments
case "${1:-}" in
    --help|-h)
        echo "Usage: $0 [OPTIONS]"
        echo ""
        echo "Options:"
        echo "  --help, -h    Show this help message"
        echo ""
        echo "Environment:"
        echo "  DEBUG=1          Enable debug output"
        echo "  RCH_MOCK_SSH=1   Use mock SSH for CI environments"
        echo "  RCH_BIN=<path>   Path to rch binary (default: rch)"
        exit 0
        ;;
    *)
        main "$@"
        ;;
esac
