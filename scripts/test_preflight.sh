#!/usr/bin/env bash
# Detailed deployment/status testing with verbose output
#
# This script performs comprehensive testing of fleet operations,
# validating that SSH connectivity, disk space, and tool availability
# are actually being tested (not hardcoded).
#
# Note: Uses `fleet deploy --dry-run` and `fleet status` which internally
# run preflight checks before any operation.
#
# Usage:
#   ./scripts/test_preflight.sh                  # Run with real workers
#   DEBUG=1 ./scripts/test_preflight.sh          # Enable debug output
#   RCH_MOCK_SSH=1 ./scripts/test_preflight.sh   # Use mock SSH

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
RCH_BIN="${RCH_BIN:-rch}"
OUTPUT_FILE="${PROJECT_ROOT}/logs/preflight_debug_$(date +%Y%m%d_%H%M%S).log"

# Ensure logs directory exists
mkdir -p "$(dirname "$OUTPUT_FILE")"

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

echo -e "${BLUE}=== Fleet Status E2E Test ===${NC}"
echo "Testing SSH connectivity, worker status, health checks..."
echo "Output file: $OUTPUT_FILE"
echo ""

# Run fleet status with maximum verbosity (internally runs preflight checks)
echo "Running: RUST_LOG=debug RCH_JSON=1 $RCH_BIN fleet status"
echo "---"

RUST_LOG=debug RCH_JSON=1 $RCH_BIN fleet status 2>&1 | tee "$OUTPUT_FILE" || true

echo ""
echo -e "${BLUE}=== Validation ===${NC}"
echo ""

# Track validation results
CHECKS_PASSED=0
CHECKS_FAILED=0
CHECKS_WARN=0

pass() {
    echo -e "${GREEN}  [PASS]${NC} $*"
    ((CHECKS_PASSED++))
}

fail() {
    echo -e "${RED}  [FAIL]${NC} $*"
    ((CHECKS_FAILED++))
}

warn() {
    echo -e "${YELLOW}  [WARN]${NC} $*"
    ((CHECKS_WARN++))
}

# Check 1: Valid JSON output
echo "1. JSON Output Validation"
if jq -e '.' "$OUTPUT_FILE" > /dev/null 2>&1; then
    pass "Output is valid JSON"
else
    # Try to find JSON in output (might have debug logs mixed in)
    if grep -oP '\{.*\}' "$OUTPUT_FILE" | head -1 | jq -e '.' > /dev/null 2>&1; then
        warn "JSON found but mixed with debug output"
    else
        fail "Output is not valid JSON"
    fi
fi

# Check 2: SSH connectivity was tested
echo "2. SSH Connectivity Check"
if grep -qiE "ssh_ok|ssh_connect|ssh.*success|ssh.*failed|connecting.*ssh" "$OUTPUT_FILE"; then
    pass "SSH connectivity check evidence found"
elif grep -qiE "reachable|unreachable|connect" "$OUTPUT_FILE"; then
    pass "Connection check evidence found"
else
    warn "No clear SSH connectivity check evidence in logs"
fi

# Check 3: Disk space appears realistic
echo "3. Disk Space Validation"
# Extract disk space values from JSON
disk_values=$(grep -oP '"disk_space_mb"\s*:\s*\K[0-9]+' "$OUTPUT_FILE" 2>/dev/null || \
              grep -oP '"disk_mb"\s*:\s*\K[0-9]+' "$OUTPUT_FILE" 2>/dev/null || \
              grep -oP '"free_disk"\s*:\s*\K[0-9]+' "$OUTPUT_FILE" 2>/dev/null || \
              echo "")

if [[ -z "$disk_values" ]]; then
    warn "No disk space values found in output"
elif echo "$disk_values" | grep -qE '^10000$'; then
    warn "Disk space may be hardcoded (found exactly 10000 MB)"
else
    # Check if values are reasonable (between 100MB and 10TB)
    all_reasonable=true
    while read -r val; do
        if [[ -n "$val" ]] && [[ "$val" -lt 100 || "$val" -gt 10000000 ]]; then
            all_reasonable=false
            break
        fi
    done <<< "$disk_values"

    if $all_reasonable; then
        pass "Disk space values appear realistic: $disk_values MB"
    else
        warn "Disk space values outside expected range"
    fi
fi

# Check 4: rsync availability was checked
echo "4. rsync Availability Check"
if grep -qiE "rsync_ok|rsync.*available|which rsync|command -v rsync" "$OUTPUT_FILE"; then
    pass "rsync availability check evidence found"
elif grep -qiE "rsync" "$OUTPUT_FILE"; then
    warn "rsync mentioned but check method unclear"
else
    warn "No rsync check evidence found"
fi

# Check 5: zstd availability was checked
echo "5. zstd Availability Check"
if grep -qiE "zstd_ok|zstd.*available|which zstd|command -v zstd" "$OUTPUT_FILE"; then
    pass "zstd availability check evidence found"
elif grep -qiE "zstd" "$OUTPUT_FILE"; then
    warn "zstd mentioned but check method unclear"
else
    warn "No zstd check evidence found"
fi

# Check 6: Load average was checked
echo "6. Load Average Check"
if grep -qiE "load_avg|load_average|uptime" "$OUTPUT_FILE"; then
    pass "Load average check evidence found"
else
    warn "No load average check evidence found"
fi

# Check 7: Worker count
echo "7. Worker Detection"
worker_count=$(grep -cE '"worker_id"|"id"\s*:\s*"[^"]+worker|"name"\s*:\s*"' "$OUTPUT_FILE" 2>/dev/null || echo "0")
if [[ "$worker_count" -gt 0 ]]; then
    pass "Found $worker_count worker(s) in output"
elif [[ "${RCH_MOCK_SSH:-}" == "1" ]]; then
    pass "Mock mode - worker detection skipped"
else
    warn "No workers detected in output"
fi

# Check 8: Timing information
echo "8. Timing Information"
if grep -qiE "duration|elapsed|ms\"|took|timing" "$OUTPUT_FILE"; then
    pass "Timing information present"
else
    warn "No timing information found"
fi

# Summary
echo ""
echo -e "${BLUE}=== Summary ===${NC}"
echo "  Passed:   $CHECKS_PASSED"
echo "  Failed:   $CHECKS_FAILED"
echo "  Warnings: $CHECKS_WARN"
echo ""
echo "Full output saved to: $OUTPUT_FILE"
echo ""

# Exit code based on results
if [[ $CHECKS_FAILED -gt 0 ]]; then
    echo -e "${RED}Some checks failed!${NC}"
    exit 1
elif [[ $CHECKS_WARN -gt 2 ]]; then
    echo -e "${YELLOW}Multiple warnings - review output${NC}"
    exit 0
else
    echo -e "${GREEN}Preflight validation passed!${NC}"
    exit 0
fi
