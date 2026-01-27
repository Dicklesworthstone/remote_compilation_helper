#!/usr/bin/env bash
#
# e2e_test.sh - Master E2E test orchestration for RCH
#
# Usage:
#   ./scripts/e2e_test.sh [OPTIONS]
#
# Options:
#   --filter PATTERN     Run tests matching PATTERN (name or path)
#   --list               List discovered tests and exit
#   --junit FILE         Write JUnit XML to FILE (default: $LOG_DIR/junit.xml)
#   --log-dir DIR        Directory for per-test logs (default: /tmp/rch-e2e-logs)
#   --parallel N         Max parallel tests (default: auto)
#   --serial             Run all tests serially
#   --verbose, -v        Stream test output to stdout
#   --help, -h           Show this help message
#
# Legacy behavior:
#   If invoked with pipeline flags (--mock/--real/--fail/--run-all/--unit),
#   delegates to scripts/e2e_pipeline.sh to preserve old behavior.
#
# Exit codes:
#   0 - All tests passed
#   1 - Some tests failed
#   2 - Infrastructure error
#

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
export PROJECT_ROOT
LIB_PATH="$SCRIPT_DIR/lib/e2e_common.sh"
LEGACY_SCRIPT="$SCRIPT_DIR/e2e_pipeline.sh"

# Structured JSONL logging
# shellcheck disable=SC1091
source "$SCRIPT_DIR/test_lib.sh"
init_test_log "$(basename "${BASH_SOURCE[0]}" .sh)"

fail_with_code() {
    local exit_code="$1"
    shift
    local reason="$*"
    log_json verify "TEST FAIL" "{\"reason\":\"$reason\"}"
    exit "$exit_code"
}

if [[ ! -f "$LIB_PATH" ]]; then
    echo "[E2E] ERROR: Missing $LIB_PATH" >&2
    fail_with_code 2 "Missing $LIB_PATH"
fi

# shellcheck disable=SC1090
source "$LIB_PATH"

LOG_DIR="${E2E_LOG_DIR:-/tmp/rch-e2e-logs}"
VERBOSE="${E2E_VERBOSE:-0}"
FILTER="${E2E_FILTER:-}"
JUNIT_FILE="${E2E_JUNIT_FILE:-}"
PARALLELISM="${E2E_PARALLELISM:-}"
SERIAL_ONLY=0
LIST_ONLY=0

usage() {
    sed -n '1,40p' "$0" | sed 's/^# \{0,1\}//'
}

legacy_args_detected() {
    for arg in "$@"; do
        case "$arg" in
            --mock|--real|--fail|--run-all|--unit)
                return 0
                ;;
        esac
    done
    return 1
}

if legacy_args_detected "$@"; then
    if [[ ! -x "$LEGACY_SCRIPT" ]]; then
        echo "[E2E] ERROR: Missing legacy script $LEGACY_SCRIPT" >&2
        exit 2
    fi
    exec "$LEGACY_SCRIPT" "$@"
fi

parse_args() {
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --filter)
                FILTER="${2:-}"
                shift 2
                ;;
            --list)
                LIST_ONLY=1
                shift
                ;;
            --junit)
                JUNIT_FILE="${2:-}"
                shift 2
                ;;
            --log-dir)
                LOG_DIR="${2:-}"
                shift 2
                ;;
            --parallel)
                PARALLELISM="${2:-}"
                shift 2
                ;;
            --serial)
                SERIAL_ONLY=1
                shift
                ;;
            --verbose|-v)
                VERBOSE=1
                shift
                ;;
            --help|-h)
                usage
                exit 0
                ;;
            *)
                echo "[E2E] ERROR: Unknown option: $1" >&2
                usage
                fail_with_code 2 "Unknown option: $1"
                ;;
        esac
    done
}

test_name() {
    local file="$1"
    local name
    name="$(sed -n 's/^# E2E_NAME=//p' "$file" | head -n 1)"
    if [[ -z "$name" ]]; then
        name="$(basename "$file" .sh)"
    fi
    echo "$name"
}

test_serial() {
    local file="$1"
    /bin/grep -q '^# E2E_SERIAL=1' "$file"
}

test_args() {
    local file="$1"
    sed -n 's/^# E2E_ARGS=//p' "$file" | head -n 1
}

run_test() {
    local file="$1"
    local name="$2"
    local args_raw="$3"
    local slug="$4"
    local log_file="$LOG_DIR/${slug}.log"
    local result_file="$RESULTS_DIR/${slug}.result"
    local start_ms
    local end_ms
    local duration_ms
    local status

    start_ms="$(e2e_now_ms)"

    e2e_log "Running: $name"
    e2e_log "TEST START: $name"

    local -a args=()
    if [[ -n "$args_raw" ]]; then
        # shellcheck disable=SC2206
        args=($args_raw)
    fi

    set +e
    if [[ "$VERBOSE" == "1" ]]; then
        if [[ ${#args[@]} -gt 0 ]]; then
            "$file" "${args[@]}" 2>&1 | tee "$log_file"
        else
            "$file" 2>&1 | tee "$log_file"
        fi
        status=${PIPESTATUS[0]}
    else
        if [[ ${#args[@]} -gt 0 ]]; then
            "$file" "${args[@]}" >"$log_file" 2>&1
        else
            "$file" >"$log_file" 2>&1
        fi
        status=$?
    fi
    set -e

    end_ms="$(e2e_now_ms)"
    duration_ms=$((end_ms - start_ms))

    printf '%s|%s|%s|%s\n' "$name" "$status" "$duration_ms" "$log_file" > "$result_file"

    local duration_s
    duration_s=$(awk "BEGIN { printf \"%.2f\", ${duration_ms}/1000 }")

    if [[ "$status" -eq 0 ]]; then
        e2e_log "TEST PASS: $name (${duration_s}s)"
    elif [[ "$status" -eq "$E2E_SKIP_EXIT" ]]; then
        e2e_log "TEST SKIP: $name (${duration_s}s)"
    else
        e2e_log "TEST FAIL: $name (${duration_s}s)"
    fi
}

run_parallel_group() {
    local -a tests=("$@")
    local -a pids=()
    local pid
    local test_file

    for test_file in "${tests[@]}"; do
        local name
        local args
        local slug
        name="$(test_name "$test_file")"
        args="$(test_args "$test_file")"
        slug="$(e2e_slug "$name")"

        run_test "$test_file" "$name" "$args" "$slug" &
        pids+=("$!")

        if [[ ${#pids[@]} -ge "$PARALLELISM" ]]; then
            pid="${pids[0]}"
            wait "$pid" || true
            pids=("${pids[@]:1}")
        fi
    done

    for pid in "${pids[@]}"; do
        wait "$pid" || true
    done
}

run_serial_group() {
    local -a tests=("$@")
    local test_file
    for test_file in "${tests[@]}"; do
        local name
        local args
        local slug
        name="$(test_name "$test_file")"
        args="$(test_args "$test_file")"
        slug="$(e2e_slug "$name")"
        run_test "$test_file" "$name" "$args" "$slug"
    done
}

generate_junit() {
    local junit_path="$1"
    local total_tests="$2"
    local total_failures="$3"
    local total_skips="$4"
    local total_ms="$5"
    local total_seconds
    total_seconds=$(awk "BEGIN { printf \"%.3f\", ${total_ms}/1000 }")

    mkdir -p "$(dirname "$junit_path")"

    {
        echo '<?xml version="1.0" encoding="UTF-8"?>'
        echo "<testsuite name=\"rch-e2e\" tests=\"$total_tests\" failures=\"$total_failures\" skipped=\"$total_skips\" time=\"$total_seconds\">"

        local result_file
        for result_file in "$RESULTS_DIR"/*.result; do
            local name
            local status
            local duration_ms
            local log_file
            IFS='|' read -r name status duration_ms log_file < "$result_file"

            local case_seconds
            case_seconds=$(awk "BEGIN { printf \"%.3f\", ${duration_ms}/1000 }")

            local name_xml
            local log_xml
            name_xml="$(e2e_xml_escape "$name")"
            log_xml="$(e2e_xml_escape "$log_file")"

            echo "  <testcase classname=\"rch-e2e\" name=\"$name_xml\" time=\"$case_seconds\">"

            if [[ "$status" -eq "$E2E_SKIP_EXIT" ]]; then
                echo "    <skipped message=\"Skipped\"/>"
            elif [[ "$status" -ne 0 ]]; then
                echo "    <failure message=\"Exit $status\">Log: $log_xml</failure>"
            fi

            echo "    <system-out>Log: $log_xml</system-out>"
            echo "  </testcase>"
        done

        echo "</testsuite>"
    } > "$junit_path"
}

main() {
    parse_args "$@"

    if [[ -z "$PARALLELISM" ]]; then
        PARALLELISM="$(e2e_default_parallelism)"
    fi

    if [[ "$PARALLELISM" -lt 1 ]]; then
        PARALLELISM=1
    fi

    if [[ -z "$JUNIT_FILE" ]]; then
        JUNIT_FILE="$LOG_DIR/junit.xml"
    fi

    local test_dir="$PROJECT_ROOT/tests/e2e"
    if [[ ! -d "$test_dir" ]]; then
        e2e_log "ERROR: Missing tests/e2e directory"
        exit 2
    fi

    mkdir -p "$LOG_DIR"
    RESULTS_DIR="$LOG_DIR/results"
    mkdir -p "$RESULTS_DIR"

    local -a discovered=()
    local test_file
    while IFS= read -r test_file; do
        discovered+=("$test_file")
    done < <(find "$test_dir" -maxdepth 1 -type f -name '*.sh' | sort)

    if [[ ${#discovered[@]} -eq 0 ]]; then
        e2e_log "ERROR: No tests found in $test_dir"
        exit 2
    fi

    local -a selected=()
    local test_file
    for test_file in "${discovered[@]}"; do
        local name
        name="$(test_name "$test_file")"

        if [[ -n "$FILTER" ]]; then
            if [[ "$name" != *"$FILTER"* && "$test_file" != *"$FILTER"* ]]; then
                continue
            fi
        fi

        selected+=("$test_file")
    done

    if [[ ${#selected[@]} -eq 0 ]]; then
        e2e_log "ERROR: No tests matched filter '$FILTER'"
        exit 2
    fi

    if [[ "$LIST_ONLY" == "1" ]]; then
        for test_file in "${selected[@]}"; do
            echo "$(test_name "$test_file")"
        done
        exit 0
    fi

    e2e_log "====== TEST SUITE START ======"
    e2e_log "Discovered tests: ${#selected[@]}"
    e2e_log "Log dir: $LOG_DIR"
    log_json setup "Discovered tests: ${#selected[@]} (log_dir=$LOG_DIR)"

    local -a serial_tests=()
    local -a parallel_tests=()

    if [[ "$SERIAL_ONLY" == "1" || "$PARALLELISM" -le 1 ]]; then
        serial_tests=("${selected[@]}")
    else
        for test_file in "${selected[@]}"; do
            if test_serial "$test_file"; then
                serial_tests+=("$test_file")
            else
                parallel_tests+=("$test_file")
            fi
        done
    fi

    if [[ ${#parallel_tests[@]} -gt 0 ]]; then
        e2e_log "Running ${#parallel_tests[@]} parallel-safe test(s) with concurrency=$PARALLELISM"
        run_parallel_group "${parallel_tests[@]}"
    fi

    if [[ ${#serial_tests[@]} -gt 0 ]]; then
        e2e_log "Running ${#serial_tests[@]} serial test(s)"
        run_serial_group "${serial_tests[@]}"
    fi

    local total=0
    local passed=0
    local failed=0
    local skipped=0
    local infra=0
    local total_ms=0

    local result_file
    for result_file in "$RESULTS_DIR"/*.result; do
        local name
        local status
        local duration_ms
        local log_file

        IFS='|' read -r name status duration_ms log_file < "$result_file"
        total=$((total + 1))
        total_ms=$((total_ms + duration_ms))

        if [[ "$status" -eq 0 ]]; then
            passed=$((passed + 1))
        elif [[ "$status" -eq "$E2E_SKIP_EXIT" ]]; then
            skipped=$((skipped + 1))
        else
            failed=$((failed + 1))
            if [[ "$status" -eq 2 ]]; then
                infra=1
            fi
        fi
    done

    generate_junit "$JUNIT_FILE" "$total" "$failed" "$skipped" "$total_ms"

    e2e_log "====== SUMMARY ======"
    e2e_log "Passed: $passed, Failed: $failed, Skipped: $skipped"
    e2e_log "JUnit: $JUNIT_FILE"
    log_json verify "Summary: passed=$passed failed=$failed skipped=$skipped junit=$JUNIT_FILE"

    if [[ "$infra" -eq 1 ]]; then
        fail_with_code 2 "Infra failure"
    fi
    if [[ "$failed" -gt 0 ]]; then
        test_fail "Some E2E tests failed"
    fi
    test_pass
}

main "$@"
