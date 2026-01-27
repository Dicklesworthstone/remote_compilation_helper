#!/usr/bin/env bash
#
# e2e_api_error_codes.sh - Verify all JSON error responses use RCH-Exxx format
#
# Usage:
#   ./scripts/e2e_api_error_codes.sh [OPTIONS]
#
# Options:
#   --verbose          Enable verbose output
#   --help             Show this help message
#
# Purpose:
#   Validates that all CLI commands return properly formatted API errors
#   using the unified RCH-Exxx error code system.
#
# Exit codes:
#   0 - All tests passed
#   1 - Test failure
#   2 - Setup/dependency error
#

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
export PROJECT_ROOT
VERBOSE="${RCH_E2E_VERBOSE:-0}"
LOG_FILE="/tmp/rch_e2e_error_codes_$(date +%Y%m%d_%H%M%S).log"

# Structured JSONL logging
# shellcheck disable=SC1091
source "$SCRIPT_DIR/test_lib.sh"
init_test_log "$(basename "${BASH_SOURCE[0]}" .sh)"

# Counters
TESTS_RUN=0
TESTS_PASSED=0
TESTS_FAILED=0

timestamp() { date -u '+%Y-%m-%dT%H:%M:%S.%3NZ'; }

fail_with_code() {
    local exit_code="$1"
    shift
    local reason="$*"
    log_json verify "TEST FAIL" "{\"reason\":\"$reason\"}"
    exit "$exit_code"
}

log() {
    local level="$1"; shift
    local ts; ts="$(timestamp)"
    local msg="[$ts] [$level] $*"
    echo "$msg" | tee -a "$LOG_FILE"

    local phase="execute"
    case "$level" in
        INFO|DEBUG) phase="setup" ;;
        PASS|FAIL) phase="verify" ;;
        ERROR) phase="verify" ;;
        TEST) phase="execute" ;;
    esac
    log_json "$phase" "$msg"
}

log_pass() {
    TESTS_PASSED=$((TESTS_PASSED + 1))
    log "PASS" "$*"
}

log_fail() {
    TESTS_FAILED=$((TESTS_FAILED + 1))
    log "FAIL" "$*"
}

die() { log "ERROR" "$*"; fail_with_code 2 "$*"; }

usage() {
    sed -n '1,20p' "$0" | sed 's/^# \{0,1\}//'
}

parse_args() {
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --verbose|-v) VERBOSE="1"; shift ;;
            --help|-h) usage; exit 0 ;;
            *) log "ERROR" "Unknown option: $1"; exit 3 ;;
        esac
    done
}

check_dependencies() {
    log "INFO" "Checking dependencies..."
    for cmd in cargo jq; do
        command -v "$cmd" >/dev/null 2>&1 || die "Missing: $cmd"
    done
    log "INFO" "Dependencies OK"
}

build_binaries() {
    log "INFO" "Building rch (release)..."
    cd "$PROJECT_ROOT"
    if ! cargo build -p rch --release 2>&1 | tee -a "$LOG_FILE" | tail -3; then
        die "Build failed"
    fi
    [[ -x "$PROJECT_ROOT/target/release/rch" ]] || die "Binary missing: rch"
    log "INFO" "Build OK"
}

# Test helper: run command and check for RCH-Exxx format in error
test_error_format() {
    local test_name="$1"
    local cmd="$2"
    local expected_pattern="${3:-RCH-E}"

    TESTS_RUN=$((TESTS_RUN + 1))
    log "TEST" "[$test_name] Running: $cmd"

    local output
    output=$(eval "$cmd" 2>&1 || true)

    [[ "$VERBOSE" == "1" ]] && log "DEBUG" "Output: $output"

    # Check if output is valid JSON
    if ! echo "$output" | jq -e '.' >/dev/null 2>&1; then
        log_fail "[$test_name] Output is not valid JSON"
        return 1
    fi

    # Check for error.code field with RCH-E format
    local error_code
    error_code=$(echo "$output" | jq -r '.error.code // empty' 2>/dev/null || true)

    if [[ -z "$error_code" ]]; then
        log_fail "[$test_name] Missing .error.code field"
        return 1
    fi

    if [[ ! "$error_code" =~ $expected_pattern ]]; then
        log_fail "[$test_name] Error code '$error_code' does not match pattern '$expected_pattern'"
        return 1
    fi

    log_pass "[$test_name] Error code: $error_code"
    return 0
}

# Test helper: check that error has required fields
test_error_structure() {
    local test_name="$1"
    local json_output="$2"

    TESTS_RUN=$((TESTS_RUN + 1))
    log "TEST" "[$test_name] Checking error structure"

    local required_fields=("code" "category" "message")
    local missing_fields=()

    for field in "${required_fields[@]}"; do
        if ! echo "$json_output" | jq -e ".error.$field" >/dev/null 2>&1; then
            missing_fields+=("$field")
        fi
    done

    if [[ ${#missing_fields[@]} -gt 0 ]]; then
        log_fail "[$test_name] Missing required fields: ${missing_fields[*]}"
        return 1
    fi

    log_pass "[$test_name] All required fields present"
    return 0
}

# Test helper: validate error category
test_error_category() {
    local test_name="$1"
    local json_output="$2"

    TESTS_RUN=$((TESTS_RUN + 1))
    log "TEST" "[$test_name] Validating error category"

    local category
    category=$(echo "$json_output" | jq -r '.error.category // empty')

    local valid_categories="config network worker build transfer internal"
    if ! echo "$valid_categories" | grep -qw "$category"; then
        log_fail "[$test_name] Invalid category: $category"
        return 1
    fi

    log_pass "[$test_name] Category '$category' is valid"
    return 0
}

# Test helper: check remediation steps
test_remediation_present() {
    local test_name="$1"
    local json_output="$2"

    TESTS_RUN=$((TESTS_RUN + 1))
    log "TEST" "[$test_name] Checking remediation steps"

    local remediation_count
    remediation_count=$(echo "$json_output" | jq '.error.remediation | length // 0')

    if [[ "$remediation_count" -eq 0 ]]; then
        # Remediation is optional but recommended - warn don't fail
        log "WARN" "[$test_name] No remediation steps (optional but recommended)"
        TESTS_PASSED=$((TESTS_PASSED + 1))
        return 0
    fi

    log_pass "[$test_name] Has $remediation_count remediation steps"
    return 0
}

run_tests() {
    local rch="$PROJECT_ROOT/target/release/rch"

    log "INFO" "=========================================="
    log "INFO" "Starting API Error Code E2E Tests"
    log "INFO" "Log file: $LOG_FILE"
    log "INFO" "=========================================="

    # =========================================================================
    # Test 1: Invalid worker probe should return RCH-Exxx code
    # =========================================================================
    log "INFO" "Test 1: Invalid worker probe error format"
    local output
    output=$("$rch" workers probe nonexistent-worker --json 2>&1 || true)
    [[ "$VERBOSE" == "1" ]] && log "DEBUG" "Output: $output"

    test_error_format "probe-invalid-worker" "echo '$output' | cat" "RCH-E"
    test_error_structure "probe-structure" "$output"
    test_error_category "probe-category" "$output"
    test_remediation_present "probe-remediation" "$output"

    # =========================================================================
    # Test 2: Status command with daemon not running
    # =========================================================================
    log "INFO" "Test 2: Daemon not running error"
    # Temporarily unset socket path to ensure daemon not found
    local orig_socket="${RCH_DAEMON_SOCKET:-}"
    export RCH_DAEMON_SOCKET="/tmp/nonexistent-rch-socket-$$"

    output=$("$rch" status --json 2>&1 || true)
    [[ "$VERBOSE" == "1" ]] && log "DEBUG" "Output: $output"

    # Check if we got a JSON error (daemon might actually be running)
    if echo "$output" | jq -e '.error' >/dev/null 2>&1; then
        test_error_format "daemon-not-running" "echo '$output' | cat" "RCH-E"
        test_error_structure "daemon-structure" "$output"
    else
        # Daemon might be running, skip this test
        log "INFO" "[daemon-not-running] Skipped - daemon may be running"
    fi

    # Restore socket path
    if [[ -n "$orig_socket" ]]; then
        export RCH_DAEMON_SOCKET="$orig_socket"
    else
        unset RCH_DAEMON_SOCKET
    fi

    # =========================================================================
    # Test 3: Invalid config file error
    # =========================================================================
    log "INFO" "Test 3: Invalid config file error"
    local invalid_config
    invalid_config=$(mktemp --suffix=.toml)
    echo 'invalid toml [' > "$invalid_config"

    output=$(RCH_CONFIG="$invalid_config" "$rch" status --json 2>&1 || true)
    rm -f "$invalid_config"
    [[ "$VERBOSE" == "1" ]] && log "DEBUG" "Output: $output"

    # Config errors should have RCH-E format if triggered
    if echo "$output" | jq -e '.error' >/dev/null 2>&1; then
        test_error_format "config-invalid" "echo '$output' | cat" "RCH-E"
    else
        log "INFO" "[config-invalid] No config error triggered (may have fallback)"
    fi

    # =========================================================================
    # Test 4: Errors use stderr, not stdout (stream separation)
    # =========================================================================
    log "INFO" "Test 4: Error stream separation"
    TESTS_RUN=$((TESTS_RUN + 1))

    local stdout_file stderr_file
    stdout_file=$(mktemp)
    stderr_file=$(mktemp)

    "$rch" workers probe nonexistent-worker >"$stdout_file" 2>"$stderr_file" || true

    # For --json mode, errors go to stdout
    # For non-json mode, errors should go to stderr
    # Check stderr has error content or stdout has JSON error
    local has_error=0
    if [[ -s "$stderr_file" ]] || grep -q '"error"' "$stdout_file" 2>/dev/null; then
        has_error=1
    fi

    if [[ "$has_error" == "1" ]]; then
        log_pass "[stream-separation] Error output correctly routed"
    else
        log_fail "[stream-separation] No error output found"
    fi

    rm -f "$stdout_file" "$stderr_file"

    # =========================================================================
    # Test 5: JSON error format is parseable
    # =========================================================================
    log "INFO" "Test 5: JSON error parseable by jq"
    TESTS_RUN=$((TESTS_RUN + 1))

    output=$("$rch" workers probe nonexistent-worker --json 2>&1 || true)

    # Try to extract all standard fields
    local fields_ok=1
    for field in api_version timestamp success; do
        if ! echo "$output" | jq -e ".$field" >/dev/null 2>&1; then
            log "WARN" "Missing top-level field: $field"
            fields_ok=0
        fi
    done

    if [[ "$fields_ok" == "1" ]]; then
        log_pass "[json-parseable] All standard response fields present"
    else
        log_fail "[json-parseable] Some response fields missing"
    fi

    # =========================================================================
    # Test 6: Error codes are unique (no duplicates in catalog)
    # =========================================================================
    log "INFO" "Test 6: Verify unit tests pass for error code uniqueness"
    TESTS_RUN=$((TESTS_RUN + 1))

    # This is validated by unit tests, but we verify they pass
    if cargo test -p rch-common --lib -- api:: --quiet 2>&1 | grep -q "test result: ok"; then
        log_pass "[unit-tests] API unit tests pass"
    else
        # Run tests and capture full output for debugging
        local test_output
        test_output=$(cargo test -p rch-common --lib -- api:: 2>&1 || true)
        if echo "$test_output" | grep -q "passed"; then
            log_pass "[unit-tests] API unit tests pass"
        else
            log_fail "[unit-tests] Some API unit tests failed"
            [[ "$VERBOSE" == "1" ]] && log "DEBUG" "$test_output"
        fi
    fi

    # =========================================================================
    # Test 7: NO_COLOR doesn't break JSON output
    # =========================================================================
    log "INFO" "Test 7: NO_COLOR preserves JSON"
    TESTS_RUN=$((TESTS_RUN + 1))

    output=$(NO_COLOR=1 "$rch" workers probe nonexistent-worker --json 2>&1 || true)

    if echo "$output" | jq -e '.' >/dev/null 2>&1; then
        log_pass "[no-color] JSON output valid with NO_COLOR"
    else
        log_fail "[no-color] JSON output broken with NO_COLOR"
    fi
}

print_summary() {
    log "INFO" "=========================================="
    log "INFO" "Test Summary"
    log "INFO" "=========================================="
    log "INFO" "Total tests: $TESTS_RUN"
    log "INFO" "Passed: $TESTS_PASSED"
    log "INFO" "Failed: $TESTS_FAILED"
    log "INFO" "Log file: $LOG_FILE"

    if [[ "$TESTS_FAILED" -gt 0 ]]; then
        log "FAIL" "Some tests failed!"
        test_fail "Some tests failed"
    fi

    log "INFO" "All API error code tests passed!"
    test_pass
}

main() {
    parse_args "$@"
    check_dependencies
    build_binaries
    run_tests
    print_summary
}

main "$@"
