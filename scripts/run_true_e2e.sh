#!/usr/bin/env bash
#
# run_true_e2e.sh - Comprehensive test runner for RCH true E2E tests
#
# This script runs true end-to-end tests that execute against real worker
# machines over SSH, with comprehensive logging, reporting, and CI integration.
#
# Usage:
#   ./scripts/run_true_e2e.sh [OPTIONS]
#
# Options:
#   --filter PATTERN     Only run tests matching PATTERN
#   --verbose, -v        Enable verbose output
#   --ci                 CI mode: skip gracefully if no workers available
#   --junit FILE         Write JUnit XML report to FILE
#   --html FILE          Write HTML report to FILE
#   --no-cleanup         Don't clean up test artifacts after run
#   --timeout SECS       Test timeout in seconds (default: 600)
#   --workers-config F   Path to workers config file
#   --skip-preflight     Skip pre-flight checks (for debugging)
#   --help, -h           Show this help message
#
# Environment Variables:
#   RCH_E2E_WORKERS_CONFIG  Override workers config path
#   RCH_E2E_LOG_DIR         Override log directory
#   RCH_E2E_TIMEOUT_SECS    Override test timeout
#   RCH_E2E_SKIP_WORKER_CHECK  Skip worker availability check (1/true)
#
# Exit Codes:
#   0 - All tests passed
#   1 - Some tests failed
#   2 - Infrastructure error (no workers, daemon failed)
#   3 - Configuration error
#
# Examples:
#   # Run all true E2E tests
#   ./scripts/run_true_e2e.sh
#
#   # Run specific test with verbose output
#   ./scripts/run_true_e2e.sh --filter ssh_tests --verbose
#
#   # CI mode with JUnit output
#   ./scripts/run_true_e2e.sh --ci --junit test-results/junit.xml
#

set -euo pipefail

# ============================================================================
# Configuration
# ============================================================================

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

# Default settings
FILTER=""
VERBOSE=0
CI_MODE=0
JUNIT_FILE=""
HTML_FILE=""
NO_CLEANUP=0
TIMEOUT_SECS="${RCH_E2E_TIMEOUT_SECS:-600}"
WORKERS_CONFIG="${RCH_E2E_WORKERS_CONFIG:-$PROJECT_ROOT/tests/true_e2e/workers_test.toml}"
SKIP_PREFLIGHT=0

# Generated paths
RUN_TIMESTAMP=$(date -u '+%Y-%m-%d_%H%M%S')
RESULTS_DIR="${PROJECT_ROOT}/test-results/run_${RUN_TIMESTAMP}"
LOG_DIR="${RCH_E2E_LOG_DIR:-$RESULTS_DIR/logs}"

# Test results tracking
TESTS_RUN=0
TESTS_PASSED=0
TESTS_FAILED=0
TESTS_SKIPPED=0
START_TIME=""
END_TIME=""
TOTAL_DURATION_MS=0

# ============================================================================
# Logging Functions
# ============================================================================

# ANSI color codes
readonly RED='\033[0;31m'
readonly GREEN='\033[0;32m'
readonly YELLOW='\033[0;33m'
readonly BLUE='\033[0;34m'
readonly CYAN='\033[0;36m'
readonly DIM='\033[2m'
readonly BOLD='\033[1m'
readonly NC='\033[0m' # No Color

timestamp() {
    date -u '+%Y-%m-%dT%H:%M:%S.%3NZ' 2>/dev/null || date -u '+%Y-%m-%dT%H:%M:%SZ'
}

log_json() {
    local level="$1"
    local phase="$2"
    local msg="$3"
    local data="${4:-}"

    local ts
    ts=$(timestamp)

    if [[ -n "$data" ]]; then
        printf '{"ts":"%s","level":"%s","phase":"%s","msg":"%s","data":%s}\n' \
            "$ts" "$level" "$phase" "$msg" "$data"
    else
        printf '{"ts":"%s","level":"%s","phase":"%s","msg":"%s"}\n' \
            "$ts" "$level" "$phase" "$msg"
    fi
}

log() {
    local level="$1"
    local phase="$2"
    shift 2
    local msg="$*"
    local ts
    ts=$(timestamp)

    local color=""
    case "$level" in
        INFO)  color="$GREEN" ;;
        WARN)  color="$YELLOW" ;;
        ERROR) color="$RED" ;;
        DEBUG) color="$CYAN" ;;
        *)     color="$NC" ;;
    esac

    # Console output
    printf "%b[%s]%b %b[%-5s]%b %b[%s]%b %s\n" \
        "$DIM" "$ts" "$NC" \
        "$color" "$level" "$NC" \
        "$DIM" "$phase" "$NC" \
        "$msg" >&2

    # JSON log to file if log dir exists
    if [[ -d "$LOG_DIR" ]]; then
        log_json "$level" "$phase" "$msg" >> "$LOG_DIR/runner.jsonl"
    fi
}

die() {
    log "ERROR" "FATAL" "$*"
    exit 2
}

die_config() {
    log "ERROR" "CONFIG" "$*"
    exit 3
}

# ============================================================================
# Argument Parsing
# ============================================================================

usage() {
    sed -n '1,60p' "$0" | grep '^#' | sed 's/^# \?//'
}

parse_args() {
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --filter)
                FILTER="${2:-}"
                shift 2
                ;;
            --verbose|-v)
                VERBOSE=1
                shift
                ;;
            --ci)
                CI_MODE=1
                shift
                ;;
            --junit)
                JUNIT_FILE="${2:-}"
                shift 2
                ;;
            --html)
                HTML_FILE="${2:-}"
                shift 2
                ;;
            --no-cleanup)
                NO_CLEANUP=1
                shift
                ;;
            --timeout)
                TIMEOUT_SECS="${2:-600}"
                shift 2
                ;;
            --workers-config)
                WORKERS_CONFIG="${2:-}"
                shift 2
                ;;
            --skip-preflight)
                SKIP_PREFLIGHT=1
                shift
                ;;
            --help|-h)
                usage
                exit 0
                ;;
            *)
                log "ERROR" "ARGS" "Unknown option: $1"
                usage
                exit 3
                ;;
        esac
    done
}

# ============================================================================
# Pre-flight Checks
# ============================================================================

check_required_tools() {
    log "INFO" "PREFLIGHT" "Checking required tools..."

    local missing=()

    for cmd in cargo rustc ssh rsync; do
        if ! command -v "$cmd" &>/dev/null; then
            missing+=("$cmd")
        fi
    done

    if [[ ${#missing[@]} -gt 0 ]]; then
        die_config "Missing required tools: ${missing[*]}"
    fi

    log "INFO" "PREFLIGHT" "All required tools found"
}

check_rust_toolchain() {
    log "INFO" "PREFLIGHT" "Checking Rust toolchain..."

    local rust_version
    rust_version=$(rustc --version 2>/dev/null || echo "unknown")
    log "DEBUG" "PREFLIGHT" "Rust version: $rust_version"

    local cargo_version
    cargo_version=$(cargo --version 2>/dev/null || echo "unknown")
    log "DEBUG" "PREFLIGHT" "Cargo version: $cargo_version"

    # Check for nightly (required for true-e2e feature)
    if [[ ! "$rust_version" =~ nightly ]]; then
        log "WARN" "PREFLIGHT" "Non-nightly Rust detected. true-e2e tests may require nightly."
    fi
}

check_workers_config() {
    log "INFO" "PREFLIGHT" "Checking workers configuration..."

    if [[ ! -f "$WORKERS_CONFIG" ]]; then
        if [[ "$CI_MODE" == "1" ]]; then
            log "WARN" "PREFLIGHT" "Workers config not found: $WORKERS_CONFIG"
            log "INFO" "PREFLIGHT" "CI mode: skipping true E2E tests"
            TESTS_SKIPPED=$((TESTS_SKIPPED + 1))
            return 1
        else
            die_config "Workers config not found: $WORKERS_CONFIG"
        fi
    fi

    log "DEBUG" "PREFLIGHT" "Workers config: $WORKERS_CONFIG"

    # Parse workers config to count workers
    local worker_count
    worker_count=$(grep -c '^\[\[workers\]\]' "$WORKERS_CONFIG" 2>/dev/null || echo "0")
    log "INFO" "PREFLIGHT" "Found $worker_count worker(s) configured"

    if [[ "$worker_count" == "0" ]]; then
        if [[ "$CI_MODE" == "1" ]]; then
            log "WARN" "PREFLIGHT" "No workers configured"
            log "INFO" "PREFLIGHT" "CI mode: skipping true E2E tests"
            TESTS_SKIPPED=$((TESTS_SKIPPED + 1))
            return 1
        else
            die_config "No workers configured in $WORKERS_CONFIG"
        fi
    fi

    return 0
}

check_worker_connectivity() {
    log "INFO" "PREFLIGHT" "Checking worker connectivity..."

    # Skip if RCH_E2E_SKIP_WORKER_CHECK is set
    if [[ "${RCH_E2E_SKIP_WORKER_CHECK:-}" == "1" ]] || \
       [[ "${RCH_E2E_SKIP_WORKER_CHECK:-}" == "true" ]]; then
        log "INFO" "PREFLIGHT" "Worker connectivity check skipped (RCH_E2E_SKIP_WORKER_CHECK)"
        return 0
    fi

    # Extract first worker's connection info from TOML
    local host user identity_file
    host=$(grep -A10 '^\[\[workers\]\]' "$WORKERS_CONFIG" | grep 'host\s*=' | head -1 | sed 's/.*=\s*"\([^"]*\)".*/\1/')
    user=$(grep -A10 '^\[\[workers\]\]' "$WORKERS_CONFIG" | grep 'user\s*=' | head -1 | sed 's/.*=\s*"\([^"]*\)".*/\1/')
    identity_file=$(grep -A10 '^\[\[workers\]\]' "$WORKERS_CONFIG" | grep 'identity_file\s*=' | head -1 | sed 's/.*=\s*"\([^"]*\)".*/\1/')

    # Default user
    user="${user:-ubuntu}"
    identity_file="${identity_file:-~/.ssh/id_rsa}"

    # Expand tilde
    identity_file="${identity_file/#\~/$HOME}"

    if [[ -z "$host" ]]; then
        log "WARN" "PREFLIGHT" "Could not extract worker host from config"
        return 0
    fi

    log "DEBUG" "PREFLIGHT" "Testing connectivity to $user@$host"

    local ssh_opts=(-o BatchMode=yes -o ConnectTimeout=5 -o StrictHostKeyChecking=accept-new)
    if [[ -f "$identity_file" ]]; then
        ssh_opts+=(-i "$identity_file")
    fi

    if ssh "${ssh_opts[@]}" "$user@$host" "echo ok" &>/dev/null; then
        log "INFO" "PREFLIGHT" "Worker connectivity OK: $host"
    else
        if [[ "$CI_MODE" == "1" ]]; then
            log "WARN" "PREFLIGHT" "Cannot connect to worker: $host"
            log "INFO" "PREFLIGHT" "CI mode: skipping true E2E tests"
            TESTS_SKIPPED=$((TESTS_SKIPPED + 1))
            return 1
        else
            die "Cannot connect to worker: $host"
        fi
    fi

    return 0
}

run_preflight_checks() {
    log "INFO" "PREFLIGHT" "Starting pre-flight checks..."

    check_required_tools
    check_rust_toolchain

    if ! check_workers_config; then
        return 1
    fi

    if ! check_worker_connectivity; then
        return 1
    fi

    log "INFO" "PREFLIGHT" "Pre-flight checks completed successfully"
    return 0
}

# ============================================================================
# Test Execution
# ============================================================================

setup_test_environment() {
    log "INFO" "SETUP" "Setting up test environment..."

    # Create results directory
    mkdir -p "$RESULTS_DIR"
    mkdir -p "$LOG_DIR"

    log "INFO" "SETUP" "Results directory: $RESULTS_DIR"
    log "INFO" "SETUP" "Log directory: $LOG_DIR"

    # Export environment variables for tests
    export RCH_E2E_LOG_DIR="$LOG_DIR"
    export RCH_E2E_WORKERS_CONFIG="$WORKERS_CONFIG"
    export RCH_E2E_TIMEOUT_SECS="$TIMEOUT_SECS"

    if [[ "$VERBOSE" == "1" ]]; then
        export RUST_LOG="${RUST_LOG:-debug}"
        export RUST_BACKTRACE=1
    fi
}

build_project() {
    log "INFO" "BUILD" "Building project with true-e2e feature..."

    cd "$PROJECT_ROOT"

    local build_log="$LOG_DIR/build.log"

    if cargo build --features true-e2e --all-targets 2>&1 | tee "$build_log"; then
        log "INFO" "BUILD" "Build completed successfully"
    else
        log "ERROR" "BUILD" "Build failed. See $build_log"
        return 1
    fi
}

run_tests() {
    log "INFO" "TEST" "Running true E2E tests..."

    cd "$PROJECT_ROOT"

    local test_args=("--features" "true-e2e")
    test_args+=("--" "--test-threads=1")  # Run serially for E2E tests

    if [[ -n "$FILTER" ]]; then
        test_args+=("$FILTER")
    fi

    if [[ "$VERBOSE" == "1" ]]; then
        test_args+=("--nocapture")
    fi

    local test_log="$LOG_DIR/tests.log"
    local test_exit_code=0

    START_TIME=$(date +%s%3N)

    # Run tests and capture output
    if cargo test "${test_args[@]}" 2>&1 | tee "$test_log"; then
        test_exit_code=0
    else
        test_exit_code=$?
    fi

    END_TIME=$(date +%s%3N)
    TOTAL_DURATION_MS=$((END_TIME - START_TIME))

    # Parse test results from output
    parse_test_results "$test_log"

    return $test_exit_code
}

parse_test_results() {
    local log_file="$1"

    # Extract test counts from cargo test output
    # Format: "test result: ok. X passed; Y failed; Z ignored"
    local result_line
    result_line=$(grep "test result:" "$log_file" | tail -1 || echo "")

    if [[ -n "$result_line" ]]; then
        TESTS_PASSED=$(echo "$result_line" | grep -oP '\d+(?= passed)' || echo "0")
        TESTS_FAILED=$(echo "$result_line" | grep -oP '\d+(?= failed)' || echo "0")
        local ignored
        ignored=$(echo "$result_line" | grep -oP '\d+(?= ignored)' || echo "0")
        TESTS_SKIPPED=$((TESTS_SKIPPED + ignored))
        TESTS_RUN=$((TESTS_PASSED + TESTS_FAILED))
    fi

    log "INFO" "TEST" "Results: $TESTS_PASSED passed, $TESTS_FAILED failed, $TESTS_SKIPPED skipped"
}

# ============================================================================
# Report Generation
# ============================================================================

generate_summary_json() {
    local summary_file="$RESULTS_DIR/summary.json"

    log "INFO" "REPORT" "Generating summary JSON..."

    cat > "$summary_file" <<EOF
{
  "timestamp": "$(timestamp)",
  "run_id": "$RUN_TIMESTAMP",
  "duration_ms": $TOTAL_DURATION_MS,
  "tests": {
    "total": $((TESTS_RUN + TESTS_SKIPPED)),
    "passed": $TESTS_PASSED,
    "failed": $TESTS_FAILED,
    "skipped": $TESTS_SKIPPED
  },
  "configuration": {
    "workers_config": "$WORKERS_CONFIG",
    "timeout_secs": $TIMEOUT_SECS,
    "ci_mode": $CI_MODE,
    "verbose": $VERBOSE,
    "filter": "$FILTER"
  },
  "paths": {
    "results_dir": "$RESULTS_DIR",
    "log_dir": "$LOG_DIR"
  }
}
EOF

    log "INFO" "REPORT" "Summary written to: $summary_file"
}

generate_junit_xml() {
    local output_file="${1:-$RESULTS_DIR/junit.xml}"

    log "INFO" "REPORT" "Generating JUnit XML report..."

    # Ensure parent directory exists
    mkdir -p "$(dirname "$output_file")"

    local failures=$TESTS_FAILED
    local tests=$((TESTS_RUN + TESTS_SKIPPED))
    local time_secs
    time_secs=$(echo "scale=3; $TOTAL_DURATION_MS / 1000" | bc 2>/dev/null || echo "0")

    cat > "$output_file" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<testsuites name="RCH True E2E Tests" tests="$tests" failures="$failures" time="$time_secs">
  <testsuite name="true_e2e" tests="$tests" failures="$failures" time="$time_secs" timestamp="$(timestamp)">
    <properties>
      <property name="workers_config" value="$WORKERS_CONFIG"/>
      <property name="timeout_secs" value="$TIMEOUT_SECS"/>
      <property name="ci_mode" value="$CI_MODE"/>
    </properties>
EOF

    # Parse individual test results from log file
    local test_log="$LOG_DIR/tests.log"
    if [[ -f "$test_log" ]]; then
        # Extract test names and results
        # Format: "test module::test_name ... ok" or "test module::test_name ... FAILED"
        while IFS= read -r line; do
            if [[ "$line" =~ ^test\ ([a-zA-Z0-9_:]+)\ \.\.\.\ (.+)$ ]]; then
                local test_name="${BASH_REMATCH[1]}"
                local result="${BASH_REMATCH[2]}"

                case "$result" in
                    ok)
                        echo "    <testcase name=\"$test_name\" classname=\"true_e2e\"/>" >> "$output_file"
                        ;;
                    FAILED)
                        echo "    <testcase name=\"$test_name\" classname=\"true_e2e\">" >> "$output_file"
                        echo "      <failure message=\"Test failed\"/>" >> "$output_file"
                        echo "    </testcase>" >> "$output_file"
                        ;;
                    ignored)
                        echo "    <testcase name=\"$test_name\" classname=\"true_e2e\">" >> "$output_file"
                        echo "      <skipped/>" >> "$output_file"
                        echo "    </testcase>" >> "$output_file"
                        ;;
                esac
            fi
        done < "$test_log"
    fi

    cat >> "$output_file" <<EOF
  </testsuite>
</testsuites>
EOF

    log "INFO" "REPORT" "JUnit XML written to: $output_file"
}

generate_html_report() {
    local output_file="${1:-$RESULTS_DIR/report.html}"

    log "INFO" "REPORT" "Generating HTML report..."

    # Ensure parent directory exists
    mkdir -p "$(dirname "$output_file")"

    local status_color
    local status_text
    if [[ $TESTS_FAILED -eq 0 && $TESTS_RUN -gt 0 ]]; then
        status_color="#28a745"
        status_text="PASSED"
    elif [[ $TESTS_RUN -eq 0 ]]; then
        status_color="#6c757d"
        status_text="SKIPPED"
    else
        status_color="#dc3545"
        status_text="FAILED"
    fi

    local duration_display
    if [[ $TOTAL_DURATION_MS -gt 60000 ]]; then
        duration_display="$((TOTAL_DURATION_MS / 60000))m $((TOTAL_DURATION_MS % 60000 / 1000))s"
    else
        duration_display="$((TOTAL_DURATION_MS / 1000)).$((TOTAL_DURATION_MS % 1000))s"
    fi

    cat > "$output_file" <<EOF
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>RCH True E2E Test Report - $RUN_TIMESTAMP</title>
    <style>
        :root {
            --bg: #1a1a2e;
            --surface: #16213e;
            --text: #eee;
            --text-dim: #888;
            --pass: #28a745;
            --fail: #dc3545;
            --skip: #6c757d;
            --border: #333;
        }
        * { box-sizing: border-box; margin: 0; padding: 0; }
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background: var(--bg);
            color: var(--text);
            line-height: 1.6;
            padding: 2rem;
        }
        .container { max-width: 1200px; margin: 0 auto; }
        h1 {
            font-size: 1.8rem;
            margin-bottom: 1rem;
            border-bottom: 1px solid var(--border);
            padding-bottom: 0.5rem;
        }
        .status-badge {
            display: inline-block;
            padding: 0.25rem 0.75rem;
            border-radius: 4px;
            font-weight: bold;
            color: white;
            background: ${status_color};
        }
        .summary {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
            gap: 1rem;
            margin: 1.5rem 0;
        }
        .summary-card {
            background: var(--surface);
            padding: 1rem;
            border-radius: 8px;
            text-align: center;
        }
        .summary-card .value {
            font-size: 2rem;
            font-weight: bold;
        }
        .summary-card .label {
            color: var(--text-dim);
            font-size: 0.9rem;
        }
        .passed .value { color: var(--pass); }
        .failed .value { color: var(--fail); }
        .skipped .value { color: var(--skip); }
        .details {
            background: var(--surface);
            padding: 1rem;
            border-radius: 8px;
            margin-top: 1rem;
        }
        .details h2 {
            font-size: 1.2rem;
            margin-bottom: 0.5rem;
            color: var(--text-dim);
        }
        .details pre {
            background: var(--bg);
            padding: 0.75rem;
            border-radius: 4px;
            overflow-x: auto;
            font-size: 0.85rem;
        }
        .meta {
            color: var(--text-dim);
            font-size: 0.85rem;
            margin-top: 2rem;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>RCH True E2E Test Report <span class="status-badge">${status_text}</span></h1>

        <div class="summary">
            <div class="summary-card passed">
                <div class="value">${TESTS_PASSED}</div>
                <div class="label">Passed</div>
            </div>
            <div class="summary-card failed">
                <div class="value">${TESTS_FAILED}</div>
                <div class="label">Failed</div>
            </div>
            <div class="summary-card skipped">
                <div class="value">${TESTS_SKIPPED}</div>
                <div class="label">Skipped</div>
            </div>
            <div class="summary-card">
                <div class="value">${duration_display}</div>
                <div class="label">Duration</div>
            </div>
        </div>

        <div class="details">
            <h2>Configuration</h2>
            <pre>
Workers Config: ${WORKERS_CONFIG}
Timeout: ${TIMEOUT_SECS}s
CI Mode: ${CI_MODE}
Filter: ${FILTER:-"(none)"}
            </pre>
        </div>

        <div class="details">
            <h2>Paths</h2>
            <pre>
Results: ${RESULTS_DIR}
Logs: ${LOG_DIR}
            </pre>
        </div>

        <div class="meta">
            <p>Generated: $(timestamp)</p>
            <p>Run ID: ${RUN_TIMESTAMP}</p>
        </div>
    </div>
</body>
</html>
EOF

    log "INFO" "REPORT" "HTML report written to: $output_file"
}

generate_reports() {
    generate_summary_json

    if [[ -n "$JUNIT_FILE" ]]; then
        generate_junit_xml "$JUNIT_FILE"
    else
        generate_junit_xml
    fi

    if [[ -n "$HTML_FILE" ]]; then
        generate_html_report "$HTML_FILE"
    else
        generate_html_report
    fi
}

# ============================================================================
# Cleanup
# ============================================================================

cleanup() {
    log "INFO" "CLEANUP" "Cleaning up..."

    if [[ "$NO_CLEANUP" == "1" ]]; then
        log "INFO" "CLEANUP" "Cleanup skipped (--no-cleanup)"
        log "INFO" "CLEANUP" "Test artifacts preserved at: $RESULTS_DIR"
        return
    fi

    # Keep results directory but clean up any temporary files
    log "INFO" "CLEANUP" "Results preserved at: $RESULTS_DIR"
}

# ============================================================================
# Main
# ============================================================================

print_banner() {
    printf '%b' "$BOLD$CYAN"
    cat <<'EOF'
  ____   ____ _   _   _____                _____         _
 |  _ \ / ___| | | | |_   _| __ _   _  ___| ____|___| |_ ___
 | |_) | |   | |_| |   | || '__| | | |/ _ \  _| |_  / __/ __|
 |  _ <| |___|  _  |   | || |  | |_| |  __/ |___|/ /\__ \__ \
 |_| \_\\____|_| |_|   |_||_|   \__,_|\___|_____|___|___/___/

EOF
    printf '%b\n' "$NC"
    echo "True End-to-End Test Runner"
    echo "==========================================="
    echo ""
}

main() {
    parse_args "$@"

    print_banner

    log "INFO" "MAIN" "Starting test run: $RUN_TIMESTAMP"
    log "INFO" "MAIN" "Project root: $PROJECT_ROOT"

    # Setup
    setup_test_environment

    # Pre-flight checks
    if [[ "$SKIP_PREFLIGHT" == "0" ]]; then
        if ! run_preflight_checks; then
            if [[ "$CI_MODE" == "1" ]]; then
                log "INFO" "MAIN" "Exiting gracefully (CI mode, no workers)"
                generate_reports
                exit 0
            else
                exit 2
            fi
        fi
    else
        log "WARN" "MAIN" "Pre-flight checks skipped"
    fi

    # Build
    if ! build_project; then
        log "ERROR" "MAIN" "Build failed"
        exit 2
    fi

    # Run tests
    local test_exit=0
    if ! run_tests; then
        test_exit=1
    fi

    # Generate reports
    generate_reports

    # Cleanup
    cleanup

    # Print final summary
    echo ""
    echo "==========================================="
    printf "Test Run Complete: "
    if [[ $TESTS_FAILED -eq 0 && $TESTS_RUN -gt 0 ]]; then
        printf '%b%s%b\n' "$GREEN" "PASSED" "$NC"
    elif [[ $TESTS_RUN -eq 0 ]]; then
        printf '%b%s%b\n' "$YELLOW" "SKIPPED" "$NC"
    else
        printf '%b%s%b\n' "$RED" "FAILED" "$NC"
    fi
    echo "  Passed:  $TESTS_PASSED"
    echo "  Failed:  $TESTS_FAILED"
    echo "  Skipped: $TESTS_SKIPPED"
    echo "  Duration: $((TOTAL_DURATION_MS / 1000))s"
    echo ""
    echo "Results: $RESULTS_DIR"
    echo "==========================================="

    # Exit with appropriate code
    if [[ $TESTS_FAILED -gt 0 ]]; then
        exit 1
    else
        exit 0
    fi
}

# Run main if script is executed directly
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi
