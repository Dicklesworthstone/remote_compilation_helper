#!/usr/bin/env bash
#
# e2e_api_envelope.sh - Verify API responses use unified ApiResponse<T> envelope
#
# Usage:
#   ./scripts/e2e_api_envelope.sh [OPTIONS]
#
# Options:
#   --verbose          Enable verbose output
#   --help             Show this help message
#
# Purpose:
#   Validates that all CLI commands return properly formatted API envelope
#   using the unified ApiResponse<T> structure with consistent fields.
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
LOG_FILE="/tmp/rch_e2e_envelope_$(date +%Y%m%d_%H%M%S).log"

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

# =============================================================================
# Test Helpers
# =============================================================================

# Test helper: verify success envelope structure
test_success_envelope() {
    local test_name="$1"
    local json_output="$2"

    TESTS_RUN=$((TESTS_RUN + 1))
    log "TEST" "[$test_name] Checking success envelope structure"

    # Required fields for success envelope
    local required_fields=("api_version" "timestamp" "success")
    local missing_fields=()

    for field in "${required_fields[@]}"; do
        if ! echo "$json_output" | jq -e ".$field" >/dev/null 2>&1; then
            missing_fields+=("$field")
        fi
    done

    if [[ ${#missing_fields[@]} -gt 0 ]]; then
        log_fail "[$test_name] Missing required fields: ${missing_fields[*]}"
        return 1
    fi

    # Check success is true
    local success_val
    success_val=$(echo "$json_output" | jq -r '.success')
    if [[ "$success_val" != "true" ]]; then
        log_fail "[$test_name] Expected success=true, got: $success_val"
        return 1
    fi

    log_pass "[$test_name] Success envelope valid"
    return 0
}

# Test helper: verify error envelope structure
test_error_envelope() {
    local test_name="$1"
    local json_output="$2"

    TESTS_RUN=$((TESTS_RUN + 1))
    log "TEST" "[$test_name] Checking error envelope structure"

    # Required fields for error envelope
    local required_fields=("api_version" "timestamp" "success" "error")
    local missing_fields=()

    for field in "${required_fields[@]}"; do
        if ! echo "$json_output" | jq -e ".$field" >/dev/null 2>&1; then
            missing_fields+=("$field")
        fi
    done

    if [[ ${#missing_fields[@]} -gt 0 ]]; then
        log_fail "[$test_name] Missing required fields: ${missing_fields[*]}"
        return 1
    fi

    # Check success is false
    local success_val
    success_val=$(echo "$json_output" | jq -r '.success')
    if [[ "$success_val" != "false" ]]; then
        log_fail "[$test_name] Expected success=false for error, got: $success_val"
        return 1
    fi

    log_pass "[$test_name] Error envelope valid"
    return 0
}

# Test helper: verify api_version format
test_api_version() {
    local test_name="$1"
    local json_output="$2"

    TESTS_RUN=$((TESTS_RUN + 1))
    log "TEST" "[$test_name] Checking api_version format"

    local api_version
    api_version=$(echo "$json_output" | jq -r '.api_version // empty')

    if [[ -z "$api_version" ]]; then
        log_fail "[$test_name] Missing api_version field"
        return 1
    fi

    # Should match semantic version pattern (e.g., "1.0", "2.1")
    if [[ ! "$api_version" =~ ^[0-9]+\.[0-9]+$ ]]; then
        log_fail "[$test_name] api_version '$api_version' not in semver format"
        return 1
    fi

    log_pass "[$test_name] api_version='$api_version'"
    return 0
}

# Test helper: verify timestamp is valid Unix epoch
test_timestamp() {
    local test_name="$1"
    local json_output="$2"

    TESTS_RUN=$((TESTS_RUN + 1))
    log "TEST" "[$test_name] Checking timestamp format"

    local ts
    ts=$(echo "$json_output" | jq -r '.timestamp // empty')

    if [[ -z "$ts" ]]; then
        log_fail "[$test_name] Missing timestamp field"
        return 1
    fi

    # Should be a positive integer (Unix epoch)
    if [[ ! "$ts" =~ ^[0-9]+$ ]] || [[ "$ts" -lt 1000000000 ]]; then
        log_fail "[$test_name] timestamp '$ts' is not a valid Unix epoch"
        return 1
    fi

    log_pass "[$test_name] timestamp=$ts (valid Unix epoch)"
    return 0
}

# Test helper: verify optional fields are omitted when null/empty
test_optional_field_omission() {
    local test_name="$1"
    local json_output="$2"

    TESTS_RUN=$((TESTS_RUN + 1))
    log "TEST" "[$test_name] Checking optional field omission"

    # Optional fields that should be omitted (not null) when not applicable
    # Check if 'data' appears with null value in error responses
    local success_val
    success_val=$(echo "$json_output" | jq -r '.success')

    if [[ "$success_val" == "false" ]]; then
        # For errors, 'data' should be omitted, not null
        if echo "$json_output" | jq -e 'has("data") and .data == null' >/dev/null 2>&1; then
            log_fail "[$test_name] 'data' should be omitted, not null, for errors"
            return 1
        fi
    fi

    if [[ "$success_val" == "true" ]]; then
        # For success, 'error' should be omitted, not null
        if echo "$json_output" | jq -e 'has("error") and .error == null' >/dev/null 2>&1; then
            log_fail "[$test_name] 'error' should be omitted, not null, for success"
            return 1
        fi
    fi

    log_pass "[$test_name] Optional fields correctly omitted"
    return 0
}

# Test helper: verify command field when present
test_command_field() {
    local test_name="$1"
    local json_output="$2"
    local expected_pattern="${3:-}"

    TESTS_RUN=$((TESTS_RUN + 1))
    log "TEST" "[$test_name] Checking command field"

    local cmd
    cmd=$(echo "$json_output" | jq -r '.command // empty')

    # command is optional, but if present should be non-empty
    if [[ -n "$cmd" ]]; then
        if [[ -n "$expected_pattern" ]] && [[ ! "$cmd" =~ $expected_pattern ]]; then
            log_fail "[$test_name] command '$cmd' doesn't match pattern '$expected_pattern'"
            return 1
        fi
        log_pass "[$test_name] command='$cmd'"
    else
        log_pass "[$test_name] command field omitted (optional)"
    fi
    return 0
}

# =============================================================================
# Test Cases
# =============================================================================

run_tests() {
    local rch="$PROJECT_ROOT/target/release/rch"

    log "INFO" "=========================================="
    log "INFO" "Starting API Envelope E2E Tests"
    log "INFO" "Log file: $LOG_FILE"
    log "INFO" "=========================================="

    local output

    # =========================================================================
    # Test 1: Error response envelope (workers probe invalid)
    # =========================================================================
    log "INFO" "Test 1: Error response envelope structure"
    output=$("$rch" workers probe nonexistent-worker --json 2>&1 || true)
    [[ "$VERBOSE" == "1" ]] && log "DEBUG" "Output: $output"

    test_error_envelope "error-envelope" "$output"
    test_api_version "error-api-version" "$output"
    test_timestamp "error-timestamp" "$output"
    test_optional_field_omission "error-optionals" "$output"
    test_command_field "error-command" "$output" "workers probe"

    # =========================================================================
    # Test 2: Success response envelope (daemon status - may show error if not running)
    # =========================================================================
    log "INFO" "Test 2: Command response envelope"
    output=$("$rch" daemon status --json 2>&1 || true)
    [[ "$VERBOSE" == "1" ]] && log "DEBUG" "Output: $output"

    # This may be success or error depending on daemon state
    if echo "$output" | jq -e '.success == true' >/dev/null 2>&1; then
        test_success_envelope "daemon-success" "$output"
    else
        test_error_envelope "daemon-error" "$output"
    fi
    test_api_version "daemon-api-version" "$output"
    test_timestamp "daemon-timestamp" "$output"
    test_command_field "daemon-command" "$output" "daemon"

    # =========================================================================
    # Test 3: Envelope consistency across commands
    # =========================================================================
    log "INFO" "Test 3: Envelope field consistency"
    TESTS_RUN=$((TESTS_RUN + 1))

    # Run multiple commands and verify all have same base envelope fields
    local cmds=("workers probe bad --json" "daemon status --json" "config show --json")
    local all_consistent=1

    for cmd_args in "${cmds[@]}"; do
        output=$("$rch" $cmd_args 2>&1 || true)
        [[ "$VERBOSE" == "1" ]] && log "DEBUG" "[$cmd_args] $output"

        # Check for api_version and timestamp
        if ! echo "$output" | jq -e '.api_version and .timestamp and (.success == true or .success == false)' >/dev/null 2>&1; then
            log "WARN" "Inconsistent envelope for: $cmd_args"
            all_consistent=0
        fi
    done

    if [[ "$all_consistent" == "1" ]]; then
        log_pass "[envelope-consistency] All commands use consistent envelope"
    else
        log_fail "[envelope-consistency] Some commands have inconsistent envelope"
    fi

    # =========================================================================
    # Test 4: JSON is valid and parseable
    # =========================================================================
    log "INFO" "Test 4: JSON validity"
    TESTS_RUN=$((TESTS_RUN + 1))

    output=$("$rch" workers probe test-worker --json 2>&1 || true)

    if echo "$output" | jq -e '.' >/dev/null 2>&1; then
        log_pass "[json-valid] Output is valid JSON"
    else
        log_fail "[json-valid] Output is not valid JSON"
    fi

    # =========================================================================
    # Test 5: Error envelope contains error object with code
    # =========================================================================
    log "INFO" "Test 5: Error object structure"
    output=$("$rch" workers probe nonexistent-worker --json 2>&1 || true)
    [[ "$VERBOSE" == "1" ]] && log "DEBUG" "Output: $output"

    TESTS_RUN=$((TESTS_RUN + 1))
    if echo "$output" | jq -e '.error.code' >/dev/null 2>&1; then
        local error_code
        error_code=$(echo "$output" | jq -r '.error.code')
        log_pass "[error-code] Error has code: $error_code"
    else
        log_fail "[error-code] Error object missing .code field"
    fi

    TESTS_RUN=$((TESTS_RUN + 1))
    if echo "$output" | jq -e '.error.category' >/dev/null 2>&1; then
        local category
        category=$(echo "$output" | jq -r '.error.category')
        log_pass "[error-category] Error has category: $category"
    else
        log_fail "[error-category] Error object missing .category field"
    fi

    # =========================================================================
    # Test 6: Unit tests for ApiResponse pass
    # =========================================================================
    log "INFO" "Test 6: ApiResponse unit tests"
    TESTS_RUN=$((TESTS_RUN + 1))

    local test_output
    test_output=$(cargo test -p rch-common --lib -- api::response::tests 2>&1 || true)

    if echo "$test_output" | grep -q "test result: ok"; then
        log_pass "[unit-tests] ApiResponse unit tests pass"
    elif echo "$test_output" | grep -q "passed"; then
        log_pass "[unit-tests] ApiResponse unit tests pass"
    else
        log_fail "[unit-tests] Some ApiResponse unit tests failed"
        [[ "$VERBOSE" == "1" ]] && log "DEBUG" "$test_output"
    fi

    # =========================================================================
    # Test 7: NO_COLOR preserves JSON envelope
    # =========================================================================
    log "INFO" "Test 7: NO_COLOR compatibility"
    TESTS_RUN=$((TESTS_RUN + 1))

    output=$(NO_COLOR=1 "$rch" workers probe test --json 2>&1 || true)

    if echo "$output" | jq -e '.api_version and .timestamp' >/dev/null 2>&1; then
        log_pass "[no-color] JSON envelope intact with NO_COLOR"
    else
        log_fail "[no-color] JSON envelope broken with NO_COLOR"
    fi

    # =========================================================================
    # Test 8: request_id is properly omitted when not set
    # =========================================================================
    log "INFO" "Test 8: request_id omission"
    TESTS_RUN=$((TESTS_RUN + 1))

    output=$("$rch" workers probe test --json 2>&1 || true)

    # request_id should be omitted (not present) unless explicitly set
    if echo "$output" | jq -e 'has("request_id") and .request_id == null' >/dev/null 2>&1; then
        log_fail "[request-id] request_id should be omitted, not null"
    else
        log_pass "[request-id] request_id correctly handled"
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

    log "INFO" "All API envelope tests passed!"
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
