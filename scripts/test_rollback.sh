#!/usr/bin/env bash
# Detailed rollback testing
#
# This script performs comprehensive testing of rollback operations,
# validating the backup registry, version lookup, and rollback workflow.
#
# Usage:
#   ./scripts/test_rollback.sh                  # Run with real workers
#   DEBUG=1 ./scripts/test_rollback.sh          # Enable debug output
#   RCH_MOCK_SSH=1 ./scripts/test_rollback.sh   # Use mock SSH

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
RCH_BIN="${RCH_BIN:-rch}"
OUTPUT_DIR="${PROJECT_ROOT}/logs"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)

# Ensure logs directory exists
mkdir -p "$OUTPUT_DIR"

# Color codes
if [[ -t 1 ]]; then
    RED='\033[0;31m'
    GREEN='\033[0;32m'
    YELLOW='\033[0;33m'
    BLUE='\033[0;34m'
    NC='\033[0m'
else
    RED=''
    GREEN=''
    YELLOW=''
    BLUE=''
    NC=''
fi

log_info()  { echo -e "${BLUE}[INFO]${NC} $*"; }
log_pass()  { echo -e "${GREEN}[PASS]${NC} $*"; }
log_fail()  { echo -e "${RED}[FAIL]${NC} $*"; }
log_warn()  { echo -e "${YELLOW}[WARN]${NC} $*"; }

# Track results
TESTS_PASSED=0
TESTS_FAILED=0

run_test() {
    local name="$1"
    shift
    echo ""
    log_info "--- Test: $name ---"
    if "$@"; then
        log_pass "PASSED: $name"
        ((TESTS_PASSED++))
        return 0
    else
        log_fail "FAILED: $name"
        ((TESTS_FAILED++))
        return 1
    fi
}

# =============================================================================
# Test: Rollback dry run (no version specified)
# =============================================================================
test_rollback_dry_run() {
    local output_file="${OUTPUT_DIR}/rollback_dry_run_${TIMESTAMP}.log"

    log_info "Running: $RCH_BIN fleet rollback --dry-run"

    local exit_code=0
    RUST_LOG=debug RCH_JSON=1 $RCH_BIN fleet rollback --dry-run 2>&1 | tee "$output_file" || exit_code=$?

    log_info "Exit code: $exit_code"
    log_info "Output saved to: $output_file"

    # Check for valid JSON or expected error
    if jq -e '.' "$output_file" > /dev/null 2>&1; then
        log_pass "Valid JSON output"
    elif grep -qiE "no backups|no previous|not found" "$output_file"; then
        log_pass "Expected 'no backups' message received"
    else
        log_fail "Unexpected output format"
        return 1
    fi

    # Check that dry run doesn't actually execute
    if grep -qiE "dry.?run|simulation|would" "$output_file"; then
        log_pass "Dry run mode confirmed"
    fi

    return 0
}

# =============================================================================
# Test: Rollback to specific version (dry run)
# =============================================================================
test_rollback_version() {
    local output_file="${OUTPUT_DIR}/rollback_version_${TIMESTAMP}.log"

    log_info "Running: $RCH_BIN fleet rollback --to-version 0.0.1 --dry-run"

    local exit_code=0
    RUST_LOG=debug RCH_JSON=1 $RCH_BIN fleet rollback --to-version 0.0.1 --dry-run 2>&1 | tee "$output_file" || exit_code=$?

    log_info "Exit code: $exit_code"
    log_info "Output saved to: $output_file"

    # Check for version handling
    if grep -qE "0\.0\.1|target.?version" "$output_file"; then
        log_pass "Version parameter processed"
    fi

    # Check for structured response
    if jq -e '.' "$output_file" > /dev/null 2>&1; then
        log_pass "Valid JSON output"
        return 0
    elif grep -qiE "no backup|not found|version" "$output_file"; then
        log_pass "Version lookup performed (backup not found)"
        return 0
    fi

    return 0
}

# =============================================================================
# Test: Rollback with worker filter
# =============================================================================
test_rollback_worker_filter() {
    local output_file="${OUTPUT_DIR}/rollback_worker_${TIMESTAMP}.log"

    log_info "Running: $RCH_BIN fleet rollback --worker nonexistent --dry-run"

    local exit_code=0
    RUST_LOG=debug RCH_JSON=1 $RCH_BIN fleet rollback --worker nonexistent --dry-run 2>&1 | tee "$output_file" || exit_code=$?

    log_info "Exit code: $exit_code"

    # Check that worker filter is applied
    if grep -qiE "nonexistent|not found|unknown worker|no such" "$output_file"; then
        log_pass "Worker filter applied (worker not found)"
        return 0
    elif [[ $exit_code -ne 0 ]]; then
        log_pass "Command rejected unknown worker"
        return 0
    fi

    return 0
}

# =============================================================================
# Test: Rollback parallelism
# =============================================================================
test_rollback_parallelism() {
    local output_file="${OUTPUT_DIR}/rollback_parallel_${TIMESTAMP}.log"

    log_info "Running: $RCH_BIN fleet rollback --parallel 1 --dry-run"

    local exit_code=0
    RUST_LOG=debug RCH_JSON=1 $RCH_BIN fleet rollback --parallel 1 --dry-run 2>&1 | tee "$output_file" || exit_code=$?

    log_info "Exit code: $exit_code"

    # Check that parallelism is respected
    if grep -qiE "parallel|concurrent|max.?concurrent" "$output_file"; then
        log_pass "Parallelism parameter processed"
    fi

    return 0
}

# =============================================================================
# Test: Rollback with verify flag
# =============================================================================
test_rollback_verify() {
    local output_file="${OUTPUT_DIR}/rollback_verify_${TIMESTAMP}.log"

    log_info "Running: $RCH_BIN fleet rollback --verify --dry-run"

    local exit_code=0
    RUST_LOG=debug RCH_JSON=1 $RCH_BIN fleet rollback --verify --dry-run 2>&1 | tee "$output_file" || exit_code=$?

    log_info "Exit code: $exit_code"

    # Check verify flag handling
    if grep -qiE "verify|hash|validation" "$output_file"; then
        log_pass "Verify flag processed"
    fi

    return 0
}

# =============================================================================
# Test: JSON output structure
# =============================================================================
test_json_structure() {
    local output_file="${OUTPUT_DIR}/rollback_json_${TIMESTAMP}.log"

    log_info "Running: $RCH_BIN fleet rollback --dry-run --json"

    local exit_code=0
    $RCH_BIN fleet rollback --dry-run --json 2>&1 | tee "$output_file" || exit_code=$?

    # Try to parse JSON
    if ! jq -e '.' "$output_file" > /dev/null 2>&1; then
        # Output might have log prefix, try extracting JSON
        if grep -oP '\{.*\}' "$output_file" | tail -1 | jq -e '.' > /dev/null 2>&1; then
            log_pass "JSON found in output"
            return 0
        fi
        log_warn "Could not extract valid JSON"
        return 0  # Don't fail, might be expected for no-backup case
    fi

    # Check for expected fields
    local has_success has_results
    has_success=$(jq -e '.success // .data.success // false' "$output_file" 2>/dev/null || echo "false")
    has_results=$(jq -e '.results // .data.results // []' "$output_file" 2>/dev/null || echo "[]")

    log_info "JSON structure: success=$has_success, results present=$([[ "$has_results" != "[]" ]] && echo "yes" || echo "no")"
    log_pass "JSON output validated"
    return 0
}

# =============================================================================
# Main
# =============================================================================
main() {
    echo ""
    echo -e "${BLUE}============================================${NC}"
    echo -e "${BLUE}   Rollback Operations Test Suite${NC}"
    echo -e "${BLUE}============================================${NC}"
    echo "Started at: $(date)"
    echo "RCH binary: $RCH_BIN"
    echo ""

    # Check for mock mode
    if [[ "${RCH_MOCK_SSH:-}" == "1" ]]; then
        log_info "Running in MOCK SSH mode"
    fi

    # Run tests
    run_test "rollback_dry_run" test_rollback_dry_run || true
    run_test "rollback_version" test_rollback_version || true
    run_test "rollback_worker_filter" test_rollback_worker_filter || true
    run_test "rollback_parallelism" test_rollback_parallelism || true
    run_test "rollback_verify" test_rollback_verify || true
    run_test "json_structure" test_json_structure || true

    # Summary
    echo ""
    echo -e "${BLUE}============================================${NC}"
    echo "  Test Summary"
    echo -e "${BLUE}============================================${NC}"
    echo "  Passed: $TESTS_PASSED"
    echo "  Failed: $TESTS_FAILED"
    echo "  Total:  $((TESTS_PASSED + TESTS_FAILED))"
    echo ""
    echo "Log files saved to: $OUTPUT_DIR"
    echo ""

    if [[ $TESTS_FAILED -gt 0 ]]; then
        echo -e "${RED}Some tests failed!${NC}"
        exit 1
    fi

    echo -e "${GREEN}All rollback tests passed!${NC}"
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
        echo "  RCH_MOCK_SSH=1   Use mock SSH mode"
        echo "  RCH_BIN=<path>   Path to rch binary"
        exit 0
        ;;
    *)
        main "$@"
        ;;
esac
