#!/usr/bin/env bash
#
# analyze_test_logs.sh - Analyze RCH test logs and generate reports
#
# Parses JSONL test logs and generates summary statistics, failure analysis,
# and trend reports suitable for CI dashboards.
#
# Usage:
#   ./scripts/analyze_test_logs.sh [OPTIONS] [LOG_FILES...]
#
# Options:
#   --log-dir DIR        Directory containing .jsonl logs (default: target/test-logs)
#   --format FORMAT      Output format: text|json|markdown (default: text)
#   --failures-only      Only show failed tests
#   --slow-threshold MS  Report tests slower than MS milliseconds (default: 5000)
#   --output FILE        Write report to FILE (default: stdout)
#   --summary            Only show summary statistics
#   --ci                 CI-friendly output (no colors, machine-readable)
#   --help, -h           Show this help message
#
# Output:
#   Summary statistics, failure details, slow test warnings
#
# Exit Codes:
#   0 - Analysis complete, all tests passed
#   1 - Analysis complete, some tests failed
#   2 - Error during analysis
#

set -euo pipefail

# ============================================================================
# Configuration
# ============================================================================

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

LOG_DIR="${PROJECT_ROOT}/target/test-logs"
FORMAT="text"
FAILURES_ONLY=0
SLOW_THRESHOLD_MS=5000
OUTPUT_FILE=""
SUMMARY_ONLY=0
CI_MODE=0

# Statistics
TOTAL_TESTS=0
PASSED_TESTS=0
FAILED_TESTS=0
SKIPPED_TESTS=0
TOTAL_DURATION_MS=0

# Arrays for detailed info
declare -a FAILED_TEST_NAMES=()
declare -a FAILED_TEST_REASONS=()
declare -a SLOW_TEST_NAMES=()
declare -a SLOW_TEST_DURATIONS=()

# ============================================================================
# Helpers
# ============================================================================

# ANSI colors (disabled in CI mode)
setup_colors() {
    if [[ $CI_MODE -eq 1 ]] || [[ ! -t 1 ]]; then
        RED=""
        GREEN=""
        YELLOW=""
        BLUE=""
        BOLD=""
        NC=""
    else
        RED='\033[0;31m'
        GREEN='\033[0;32m'
        YELLOW='\033[0;33m'
        BLUE='\033[0;34m'
        BOLD='\033[1m'
        NC='\033[0m'
    fi
}

log_error() {
    echo -e "${RED}ERROR:${NC} $*" >&2
}

# ============================================================================
# Argument Parsing
# ============================================================================

parse_args() {
    local positional=()

    while [[ $# -gt 0 ]]; do
        case "$1" in
            --log-dir)
                LOG_DIR="$2"
                shift 2
                ;;
            --format)
                FORMAT="$2"
                shift 2
                ;;
            --failures-only)
                FAILURES_ONLY=1
                shift
                ;;
            --slow-threshold)
                SLOW_THRESHOLD_MS="$2"
                shift 2
                ;;
            --output)
                OUTPUT_FILE="$2"
                shift 2
                ;;
            --summary)
                SUMMARY_ONLY=1
                shift
                ;;
            --ci)
                CI_MODE=1
                shift
                ;;
            -h|--help)
                show_help
                exit 0
                ;;
            -*)
                log_error "Unknown option: $1"
                exit 2
                ;;
            *)
                positional+=("$1")
                shift
                ;;
        esac
    done

    # Remaining args are log files
    LOG_FILES=("${positional[@]:-}")
}

show_help() {
    head -35 "$0" | tail -30
}

# ============================================================================
# Log Parsing
# ============================================================================

# Parse a single JSONL log file
parse_log_file() {
    local log_file="$1"
    local test_name=""
    local test_passed=0
    local test_failed=0
    local test_skipped=0
    local test_duration=0
    local fail_reason=""

    while IFS= read -r line; do
        # Skip empty lines
        [[ -z "$line" ]] && continue

        # Extract fields using grep/sed (jq-free for portability)
        local message
        message=$(echo "$line" | grep -o '"message":"[^"]*"' | cut -d'"' -f4 || echo "")

        local duration_ms
        duration_ms=$(echo "$line" | grep -o '"duration_ms":[0-9]*' | cut -d':' -f2 || echo "0")

        local phase
        phase=$(echo "$line" | grep -o '"phase":"[^"]*"' | cut -d'"' -f4 || echo "")

        # Extract test name from log file name if not set
        if [[ -z "$test_name" ]]; then
            test_name=$(basename "$log_file" .jsonl)
        fi

        # Track test outcome
        case "$message" in
            "TEST PASS")
                test_passed=1
                test_duration=$duration_ms
                ;;
            "TEST FAIL")
                test_failed=1
                test_duration=$duration_ms
                fail_reason=$(echo "$line" | grep -o '"reason":"[^"]*"' | cut -d'"' -f4 || echo "Unknown")
                ;;
            "TEST SKIP")
                test_skipped=1
                ;;
        esac
    done < "$log_file"

    # Update global stats
    ((TOTAL_TESTS++)) || true

    if [[ $test_passed -eq 1 ]]; then
        ((PASSED_TESTS++)) || true
        TOTAL_DURATION_MS=$((TOTAL_DURATION_MS + test_duration))

        # Check for slow tests
        if [[ $test_duration -gt $SLOW_THRESHOLD_MS ]]; then
            SLOW_TEST_NAMES+=("$test_name")
            SLOW_TEST_DURATIONS+=("$test_duration")
        fi
    elif [[ $test_failed -eq 1 ]]; then
        ((FAILED_TESTS++)) || true
        TOTAL_DURATION_MS=$((TOTAL_DURATION_MS + test_duration))
        FAILED_TEST_NAMES+=("$test_name")
        FAILED_TEST_REASONS+=("$fail_reason")
    elif [[ $test_skipped -eq 1 ]]; then
        ((SKIPPED_TESTS++)) || true
    fi
}

# Parse all log files
parse_all_logs() {
    local files=()

    if [[ ${#LOG_FILES[@]} -gt 0 ]]; then
        files=("${LOG_FILES[@]}")
    elif [[ -d "$LOG_DIR" ]]; then
        while IFS= read -r -d '' file; do
            files+=("$file")
        done < <(find "$LOG_DIR" -name "*.jsonl" -print0 2>/dev/null)
    fi

    if [[ ${#files[@]} -eq 0 ]]; then
        log_error "No log files found"
        exit 2
    fi

    for file in "${files[@]}"; do
        parse_log_file "$file"
    done
}

# ============================================================================
# Report Generation
# ============================================================================

format_duration() {
    local ms="$1"
    if [[ $ms -ge 60000 ]]; then
        printf "%dm %ds" $((ms / 60000)) $(((ms % 60000) / 1000))
    elif [[ $ms -ge 1000 ]]; then
        printf "%.1fs" "$(echo "scale=1; $ms / 1000" | bc 2>/dev/null || echo "$((ms / 1000))")"
    else
        printf "%dms" "$ms"
    fi
}

generate_text_report() {
    echo ""
    echo -e "${BOLD}RCH Test Analysis Report${NC}"
    echo "========================"
    echo ""

    # Summary
    echo -e "${BOLD}Summary${NC}"
    echo "-------"
    printf "  Total:    %d tests\n" "$TOTAL_TESTS"
    printf "  Passed:   ${GREEN}%d${NC}\n" "$PASSED_TESTS"
    printf "  Failed:   ${RED}%d${NC}\n" "$FAILED_TESTS"
    printf "  Skipped:  ${YELLOW}%d${NC}\n" "$SKIPPED_TESTS"
    printf "  Duration: %s\n" "$(format_duration "$TOTAL_DURATION_MS")"
    echo ""

    # Pass rate
    if [[ $TOTAL_TESTS -gt 0 ]]; then
        local pass_rate=$((PASSED_TESTS * 100 / TOTAL_TESTS))
        echo -e "  Pass Rate: ${BOLD}${pass_rate}%${NC}"
        echo ""
    fi

    if [[ $SUMMARY_ONLY -eq 1 ]]; then
        return
    fi

    # Failed tests
    if [[ ${#FAILED_TEST_NAMES[@]} -gt 0 ]]; then
        echo -e "${RED}${BOLD}Failed Tests${NC}"
        echo "------------"
        for i in "${!FAILED_TEST_NAMES[@]}"; do
            echo -e "  ${RED}✗${NC} ${FAILED_TEST_NAMES[$i]}"
            echo "    Reason: ${FAILED_TEST_REASONS[$i]}"
        done
        echo ""
    fi

    # Slow tests
    if [[ ${#SLOW_TEST_NAMES[@]} -gt 0 && $FAILURES_ONLY -eq 0 ]]; then
        echo -e "${YELLOW}${BOLD}Slow Tests (>${SLOW_THRESHOLD_MS}ms)${NC}"
        echo "-------------------------"
        for i in "${!SLOW_TEST_NAMES[@]}"; do
            local duration_str
            duration_str=$(format_duration "${SLOW_TEST_DURATIONS[$i]}")
            echo "  ⚠ ${SLOW_TEST_NAMES[$i]} ($duration_str)"
        done
        echo ""
    fi
}

generate_json_report() {
    local failed_json="[]"
    local slow_json="[]"

    if [[ ${#FAILED_TEST_NAMES[@]} -gt 0 ]]; then
        failed_json="["
        for i in "${!FAILED_TEST_NAMES[@]}"; do
            [[ $i -gt 0 ]] && failed_json+=","
            failed_json+="{\"name\":\"${FAILED_TEST_NAMES[$i]}\",\"reason\":\"${FAILED_TEST_REASONS[$i]}\"}"
        done
        failed_json+="]"
    fi

    if [[ ${#SLOW_TEST_NAMES[@]} -gt 0 ]]; then
        slow_json="["
        for i in "${!SLOW_TEST_NAMES[@]}"; do
            [[ $i -gt 0 ]] && slow_json+=","
            slow_json+="{\"name\":\"${SLOW_TEST_NAMES[$i]}\",\"duration_ms\":${SLOW_TEST_DURATIONS[$i]}}"
        done
        slow_json+="]"
    fi

    cat <<EOF
{
  "summary": {
    "total": $TOTAL_TESTS,
    "passed": $PASSED_TESTS,
    "failed": $FAILED_TESTS,
    "skipped": $SKIPPED_TESTS,
    "duration_ms": $TOTAL_DURATION_MS,
    "pass_rate": $(( TOTAL_TESTS > 0 ? PASSED_TESTS * 100 / TOTAL_TESTS : 0 ))
  },
  "failed_tests": $failed_json,
  "slow_tests": $slow_json,
  "slow_threshold_ms": $SLOW_THRESHOLD_MS
}
EOF
}

generate_markdown_report() {
    echo "# RCH Test Analysis Report"
    echo ""
    echo "## Summary"
    echo ""
    echo "| Metric | Value |"
    echo "|--------|-------|"
    echo "| Total | $TOTAL_TESTS |"
    echo "| Passed | $PASSED_TESTS |"
    echo "| Failed | $FAILED_TESTS |"
    echo "| Skipped | $SKIPPED_TESTS |"
    echo "| Duration | $(format_duration "$TOTAL_DURATION_MS") |"

    if [[ $TOTAL_TESTS -gt 0 ]]; then
        local pass_rate=$((PASSED_TESTS * 100 / TOTAL_TESTS))
        echo "| Pass Rate | ${pass_rate}% |"
    fi
    echo ""

    if [[ $SUMMARY_ONLY -eq 1 ]]; then
        return
    fi

    if [[ ${#FAILED_TEST_NAMES[@]} -gt 0 ]]; then
        echo "## Failed Tests"
        echo ""
        for i in "${!FAILED_TEST_NAMES[@]}"; do
            echo "- **${FAILED_TEST_NAMES[$i]}**: ${FAILED_TEST_REASONS[$i]}"
        done
        echo ""
    fi

    if [[ ${#SLOW_TEST_NAMES[@]} -gt 0 && $FAILURES_ONLY -eq 0 ]]; then
        echo "## Slow Tests (>${SLOW_THRESHOLD_MS}ms)"
        echo ""
        for i in "${!SLOW_TEST_NAMES[@]}"; do
            echo "- ${SLOW_TEST_NAMES[$i]}: $(format_duration "${SLOW_TEST_DURATIONS[$i]}")"
        done
        echo ""
    fi
}

generate_report() {
    case "$FORMAT" in
        text)
            generate_text_report
            ;;
        json)
            generate_json_report
            ;;
        markdown|md)
            generate_markdown_report
            ;;
        *)
            log_error "Unknown format: $FORMAT"
            exit 2
            ;;
    esac
}

# ============================================================================
# Main
# ============================================================================

main() {
    parse_args "$@"
    setup_colors
    parse_all_logs

    if [[ -n "$OUTPUT_FILE" ]]; then
        generate_report > "$OUTPUT_FILE"
        echo "Report written to: $OUTPUT_FILE"
    else
        generate_report
    fi

    # Exit with failure if any tests failed
    if [[ $FAILED_TESTS -gt 0 ]]; then
        exit 1
    fi
    exit 0
}

main "$@"
