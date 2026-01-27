#!/usr/bin/env bash
#
# e2e_bd-3ptd.sh - Machine-Readable API Specification tests
#
# Verifies:
# - rch schema list command outputs correct schemas
# - rch schema export generates valid JSON files
# - JSON Schema files can be parsed and validated
# - Error codes catalog contains all expected errors
# - JSON output mode works correctly

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
LOG_FILE="${PROJECT_ROOT}/target/e2e_bd-3ptd.jsonl"

# shellcheck source=lib/e2e_common.sh
source "$SCRIPT_DIR/lib/e2e_common.sh"

passed_tests=0
failed_tests=0
run_start_ms="$(e2e_now_ms)"

tmp_root=""
rch_bin=""

log_json() {
    local phase="$1"
    local message="$2"
    local worker="${3:-local}"
    local command="${4:-}"
    local bytes="${5:-0}"
    local duration="${6:-0}"
    local result="${7:-}"
    local error="${8:-}"
    local ts
    ts="$(e2e_timestamp)"
    printf '{"ts":"%s","test":"bd-3ptd","phase":"%s","worker":"%s","command":"%s","bytes_transferred":%s,"duration_ms":%s,"result":"%s","error":"%s","message":"%s"}\n' \
        "$ts" "$phase" "$worker" "$command" "$bytes" "$duration" "$result" "$error" "$message" | tee -a "$LOG_FILE"
}

record_pass() {
    passed_tests=$((passed_tests + 1))
}

record_fail() {
    failed_tests=$((failed_tests + 1))
}

cleanup() {
    if [[ -n "$tmp_root" && -d "$tmp_root" ]]; then
        rm -rf "$tmp_root"
    fi
}
trap cleanup EXIT

check_dependencies() {
    log_json "setup" "Checking dependencies" "local" "dependency check" 0 0 "start"
    for cmd in cargo jq; do
        if ! command -v "$cmd" >/dev/null 2>&1; then
            log_json "setup" "Missing dependency" "local" "$cmd" 0 0 "fail" "missing $cmd"
            record_fail
            return 1
        fi
    done
    log_json "setup" "Dependencies ok" "local" "dependency check" 0 0 "pass"
    record_pass
}

build_binaries() {
    local rch="${PROJECT_ROOT}/target/debug/rch"

    if [[ -x "$rch" ]]; then
        log_json "setup" "Using existing rch binary" "local" "cargo build" 0 0 "pass"
        record_pass
        rch_bin="$rch"
        return
    fi

    log_json "setup" "Building rch (debug)" "local" "cargo build -p rch" 0 0 "start"
    if (cd "$PROJECT_ROOT" && cargo build -p rch >/dev/null 2>&1); then
        log_json "setup" "Build completed" "local" "cargo build" 0 0 "pass"
        record_pass
        rch_bin="$rch"
    else
        log_json "setup" "Build failed" "local" "cargo build" 0 0 "fail" "cargo build failed"
        record_fail
        return 1
    fi
}

test_schema_list_text() {
    log_json "execute" "Testing schema list (text)" "local" "rch schema list" 0 0 "start"
    local output
    output=$("$rch_bin" schema list 2>/dev/null)

    if echo "$output" | grep -q "API Response" && \
       echo "$output" | grep -q "API Error" && \
       echo "$output" | grep -q "Error Codes"; then
        log_json "verify" "Schema list contains expected entries" "local" "rch schema list" 0 0 "pass"
        record_pass
        return 0
    else
        log_json "verify" "Schema list missing entries" "local" "rch schema list" 0 0 "fail" "missing schemas"
        record_fail
        return 1
    fi
}

test_schema_list_json() {
    log_json "execute" "Testing schema list (JSON)" "local" "rch schema list --json" 0 0 "start"
    local output
    output=$("$rch_bin" schema list --json 2>/dev/null)

    # Verify JSON structure
    local success count
    success=$(echo "$output" | jq -r '.success' 2>/dev/null || echo "null")
    count=$(echo "$output" | jq -r '.data.schemas | length' 2>/dev/null || echo "0")

    if [[ "$success" == "true" && "$count" == "3" ]]; then
        log_json "verify" "Schema list JSON correct" "local" "count=$count" 0 0 "pass"
        record_pass
        return 0
    else
        log_json "verify" "Schema list JSON invalid" "local" "success=$success count=$count" 0 0 "fail"
        record_fail
        return 1
    fi
}

test_schema_export() {
    log_json "execute" "Testing schema export" "local" "rch schema export" 0 0 "start"
    tmp_root="$(mktemp -d "${TMPDIR:-/tmp}/rch-bd-3ptd-XXXXXX")"
    local export_dir="$tmp_root/schemas"

    local output
    if ! output=$("$rch_bin" schema export --output "$export_dir" 2>/dev/null); then
        log_json "execute" "Schema export failed" "local" "rch schema export" 0 0 "fail"
        record_fail
        return 1
    fi

    # Verify files exist
    local files_ok=true
    for file in "api-response.schema.json" "api-error.schema.json" "error-codes.json"; do
        if [[ ! -f "$export_dir/$file" ]]; then
            log_json "verify" "Missing file" "local" "$file" 0 0 "fail"
            files_ok=false
        fi
    done

    if [[ "$files_ok" == "true" ]]; then
        log_json "verify" "All schema files exported" "local" "3 files" 0 0 "pass"
        record_pass
    else
        record_fail
        return 1
    fi
}

test_api_response_schema_valid() {
    log_json "execute" "Validating api-response schema" "local" "jq" 0 0 "start"
    local schema_file="$tmp_root/schemas/api-response.schema.json"

    # Check it's valid JSON and has expected structure using jq existence checks
    local has_api_version has_success has_timestamp
    has_api_version=$(jq -e '.properties.api_version' "$schema_file" >/dev/null 2>&1 && echo "1" || echo "0")
    has_success=$(jq -e '.properties.success.type' "$schema_file" >/dev/null 2>&1 && echo "1" || echo "0")
    has_timestamp=$(jq -e '.properties.timestamp' "$schema_file" >/dev/null 2>&1 && echo "1" || echo "0")

    if [[ "$has_api_version" == "1" && "$has_success" == "1" && "$has_timestamp" == "1" ]]; then
        log_json "verify" "API response schema valid" "local" "api-response.schema.json" 0 0 "pass"
        record_pass
        return 0
    else
        log_json "verify" "API response schema missing fields" "local" "av=$has_api_version s=$has_success ts=$has_timestamp" 0 0 "fail"
        record_fail
        return 1
    fi
}

test_api_error_schema_valid() {
    log_json "execute" "Validating api-error schema" "local" "jq" 0 0 "start"
    local schema_file="$tmp_root/schemas/api-error.schema.json"

    # Check it has expected fields using jq to check for property existence
    local has_code has_category has_message
    has_code=$(jq -e '.properties.code.type' "$schema_file" >/dev/null 2>&1 && echo "1" || echo "0")
    has_category=$(jq -e '.properties.category' "$schema_file" >/dev/null 2>&1 && echo "1" || echo "0")
    has_message=$(jq -e '.properties.message.type' "$schema_file" >/dev/null 2>&1 && echo "1" || echo "0")

    if [[ "$has_code" == "1" && "$has_category" == "1" && "$has_message" == "1" ]]; then
        log_json "verify" "API error schema valid" "local" "api-error.schema.json" 0 0 "pass"
        record_pass
        return 0
    else
        log_json "verify" "API error schema missing fields" "local" "code=$has_code cat=$has_category msg=$has_message" 0 0 "fail"
        record_fail
        return 1
    fi
}

test_error_codes_catalog() {
    log_json "execute" "Validating error-codes catalog" "local" "jq" 0 0 "start"
    local catalog_file="$tmp_root/schemas/error-codes.json"

    # Check structure
    local schema_version api_version categories_count errors_count
    schema_version=$(jq -r '.schema_version' "$catalog_file" 2>/dev/null || echo "")
    api_version=$(jq -r '.api_version' "$catalog_file" 2>/dev/null || echo "")
    categories_count=$(jq '.categories | length' "$catalog_file" 2>/dev/null || echo "0")
    errors_count=$(jq '.errors | length' "$catalog_file" 2>/dev/null || echo "0")

    if [[ "$schema_version" == "1.0" && "$api_version" == "1.0" && "$categories_count" == "6" && "$errors_count" -ge 50 ]]; then
        log_json "verify" "Error catalog valid" "local" "categories=$categories_count errors=$errors_count" 0 0 "pass"
        record_pass
    else
        log_json "verify" "Error catalog invalid" "local" "sv=$schema_version av=$api_version cat=$categories_count err=$errors_count" 0 0 "fail"
        record_fail
        return 1
    fi

    # Verify specific error codes exist
    local has_e001 has_e100 has_e500
    has_e001=$(jq '[.errors[] | select(.code == "RCH-E001")] | length' "$catalog_file" 2>/dev/null || echo "0")
    has_e100=$(jq '[.errors[] | select(.code == "RCH-E100")] | length' "$catalog_file" 2>/dev/null || echo "0")
    has_e500=$(jq '[.errors[] | select(.code == "RCH-E500")] | length' "$catalog_file" 2>/dev/null || echo "0")

    if [[ "$has_e001" == "1" && "$has_e100" == "1" && "$has_e500" == "1" ]]; then
        log_json "verify" "Key error codes present" "local" "E001,E100,E500" 0 0 "pass"
        record_pass
        return 0
    else
        log_json "verify" "Key error codes missing" "local" "E001=$has_e001 E100=$has_e100 E500=$has_e500" 0 0 "fail"
        record_fail
        return 1
    fi
}

test_schema_export_json() {
    log_json "execute" "Testing schema export (JSON output)" "local" "rch schema export --json" 0 0 "start"
    local export_dir="$tmp_root/schemas2"

    local output
    output=$("$rch_bin" schema export --output "$export_dir" --json 2>/dev/null)

    local success files_count
    success=$(echo "$output" | jq -r '.success' 2>/dev/null || echo "null")
    files_count=$(echo "$output" | jq -r '.data.files_generated' 2>/dev/null || echo "0")

    if [[ "$success" == "true" && "$files_count" == "3" ]]; then
        log_json "verify" "Export JSON output correct" "local" "files=$files_count" 0 0 "pass"
        record_pass
        return 0
    else
        log_json "verify" "Export JSON output invalid" "local" "success=$success files=$files_count" 0 0 "fail"
        record_fail
        return 1
    fi
}

main() {
    mkdir -p "$(dirname "$LOG_FILE")"
    : > "$LOG_FILE"

    if ! check_dependencies; then
        return 1
    fi

    if ! build_binaries; then
        return 1
    fi

    # Run tests
    test_schema_list_text || true
    test_schema_list_json || true
    test_schema_export || true
    test_api_response_schema_valid || true
    test_api_error_schema_valid || true
    test_error_codes_catalog || true
    test_schema_export_json || true

    # Summary
    local elapsed_ms
    elapsed_ms=$(( $(e2e_now_ms) - run_start_ms ))
    local total_count
    total_count=$((passed_tests + failed_tests))

    if [[ $failed_tests -eq 0 ]]; then
        log_json \
            "summary" \
            "bd-3ptd schema tests complete (pass=${passed_tests} fail=${failed_tests} total=${total_count})" \
            "local" \
            "summary" \
            0 \
            "$elapsed_ms" \
            "pass"
        return 0
    else
        log_json \
            "summary" \
            "bd-3ptd schema tests complete (pass=${passed_tests} fail=${failed_tests} total=${total_count})" \
            "local" \
            "summary" \
            0 \
            "$elapsed_ms" \
            "fail" \
            "$failed_tests tests failed"
        return 1
    fi
}

main "$@"
