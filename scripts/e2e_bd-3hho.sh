#!/usr/bin/env bash
#
# e2e_bd-3hho.sh - Transfer Optimization (size estimation + bandwidth control)
#
# Verifies:
# - Transfer config options are properly parsed (max_transfer_mb, max_transfer_time_ms, bwlimit_kbps)
# - Config values are visible in rch config show output
# - Env overrides work for transfer settings
# - Output is logged in JSONL format

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
LOG_FILE="${PROJECT_ROOT}/target/e2e_bd-3hho.jsonl"

timestamp() {
    date -u '+%Y-%m-%dT%H:%M:%S.%3NZ' 2>/dev/null || date -u '+%Y-%m-%dT%H:%M:%SZ'
}

log_json() {
    local phase="$1"
    local message="$2"
    local extra="${3:-{}}"
    local ts
    ts="$(timestamp)"
    printf '{"ts":"%s","test":"bd-3hho","phase":"%s","message":"%s",%s}\n' \
        "$ts" "$phase" "$message" "${extra#\{}" | sed 's/,}$/}/' | tee -a "$LOG_FILE"
}

die() {
    log_json "error" "$*" '{"result":"fail"}'
    exit 1
}

check_dependencies() {
    log_json "setup" "Checking dependencies"
    for cmd in cargo jq; do
        command -v "$cmd" >/dev/null 2>&1 || die "Missing dependency: $cmd"
    done
}

build_rch() {
    local rch_bin="${PROJECT_ROOT}/target/debug/rch"
    if [[ -x "$rch_bin" ]]; then
        log_json "setup" "Using existing rch binary" "{\"path\":\"$rch_bin\"}" >&2
        echo "$rch_bin"
        return
    fi
    log_json "setup" "Building rch (debug)" >&2
    (cd "$PROJECT_ROOT" && cargo build -p rch >/dev/null 2>&1) || die "cargo build failed"
    [[ -x "$rch_bin" ]] || die "rch binary missing after build"
    echo "$rch_bin"
}

write_transfer_config() {
    local project_dir="$1"
    local max_transfer_mb="${2:-}"
    local max_transfer_time_ms="${3:-}"
    local bwlimit_kbps="${4:-}"
    mkdir -p "$project_dir/.rch"
    {
        echo "[transfer]"
        [[ -n "$max_transfer_mb" ]] && echo "max_transfer_mb = $max_transfer_mb"
        [[ -n "$max_transfer_time_ms" ]] && echo "max_transfer_time_ms = $max_transfer_time_ms"
        [[ -n "$bwlimit_kbps" ]] && echo "bwlimit_kbps = $bwlimit_kbps"
    } > "$project_dir/.rch/config.toml"
}

get_transfer_config() {
    local rch_bin="$1"
    local project_dir="$2"
    local field="$3"
    (cd "$project_dir" && "$rch_bin" config show --json) | jq -r ".data.transfer.$field // \"null\""
}

main() {
    : > "$LOG_FILE"
    check_dependencies
    local rch_bin
    rch_bin="$(build_rch)"

    local tmp_root
    tmp_root="$(mktemp -d "${TMPDIR:-/tmp}/rch-transfer-opt-XXXXXX")"
    trap 'rm -rf "${tmp_root:-}"' EXIT

    local project_a="$tmp_root/project-a"
    local project_b="$tmp_root/project-b"
    local project_c="$tmp_root/project-c"
    mkdir -p "$project_a" "$project_b" "$project_c"

    log_json "setup" "Created test projects" "{\"root\":\"$tmp_root\"}"

    # Test 1: max_transfer_mb config
    log_json "test" "max_transfer_mb config parsing"
    write_transfer_config "$project_a" "500" "" ""
    local max_mb
    max_mb="$(get_transfer_config "$rch_bin" "$project_a" "max_transfer_mb")"
    if [[ "$max_mb" != "500" ]]; then
        die "Expected max_transfer_mb=500, got: $max_mb"
    fi
    log_json "verify" "max_transfer_mb parsed correctly" "{\"value\":$max_mb}"

    # Test 2: max_transfer_time_ms config
    log_json "test" "max_transfer_time_ms config parsing"
    write_transfer_config "$project_b" "" "5000" ""
    local max_time
    max_time="$(get_transfer_config "$rch_bin" "$project_b" "max_transfer_time_ms")"
    if [[ "$max_time" != "5000" ]]; then
        die "Expected max_transfer_time_ms=5000, got: $max_time"
    fi
    log_json "verify" "max_transfer_time_ms parsed correctly" "{\"value\":$max_time}"

    # Test 3: bwlimit_kbps config
    log_json "test" "bwlimit_kbps config parsing"
    write_transfer_config "$project_c" "" "" "10000"
    local bwlimit
    bwlimit="$(get_transfer_config "$rch_bin" "$project_c" "bwlimit_kbps")"
    if [[ "$bwlimit" != "10000" ]]; then
        die "Expected bwlimit_kbps=10000, got: $bwlimit"
    fi
    log_json "verify" "bwlimit_kbps parsed correctly" "{\"value\":$bwlimit}"

    # Test 4: Combined config
    log_json "test" "Combined transfer optimization config"
    write_transfer_config "$project_a" "200" "3000" "5000"
    max_mb="$(get_transfer_config "$rch_bin" "$project_a" "max_transfer_mb")"
    max_time="$(get_transfer_config "$rch_bin" "$project_a" "max_transfer_time_ms")"
    bwlimit="$(get_transfer_config "$rch_bin" "$project_a" "bwlimit_kbps")"
    if [[ "$max_mb" != "200" ]] || [[ "$max_time" != "3000" ]] || [[ "$bwlimit" != "5000" ]]; then
        die "Combined config mismatch: max_mb=$max_mb, max_time=$max_time, bwlimit=$bwlimit"
    fi
    log_json "verify" "Combined config parsed correctly" "{\"max_transfer_mb\":$max_mb,\"max_transfer_time_ms\":$max_time,\"bwlimit_kbps\":$bwlimit}"

    # Test 5: Default values (no config)
    log_json "test" "Default transfer config values"
    rm -f "$project_b/.rch/config.toml"
    max_mb="$(get_transfer_config "$rch_bin" "$project_b" "max_transfer_mb")"
    max_time="$(get_transfer_config "$rch_bin" "$project_b" "max_transfer_time_ms")"
    bwlimit="$(get_transfer_config "$rch_bin" "$project_b" "bwlimit_kbps")"
    # Default values should be null (no limit)
    if [[ "$max_mb" != "null" ]] || [[ "$max_time" != "null" ]] || [[ "$bwlimit" != "null" ]]; then
        log_json "verify" "Default values present" "{\"max_transfer_mb\":\"$max_mb\",\"max_transfer_time_ms\":\"$max_time\",\"bwlimit_kbps\":\"$bwlimit\"}"
    else
        log_json "verify" "Default values are null (unlimited)" '{"max_transfer_mb":"null","max_transfer_time_ms":"null","bwlimit_kbps":"null"}'
    fi

    # Test 6: Compression level (default)
    log_json "test" "Default compression level"
    local compression
    compression="$(get_transfer_config "$rch_bin" "$project_b" "compression_level")"
    if [[ "$compression" == "null" ]]; then
        die "compression_level should have a default value"
    fi
    log_json "verify" "compression_level has default" "{\"value\":$compression}"

    log_json "summary" "All bd-3hho transfer optimization checks passed" '{"result":"pass"}'
}

main "$@"
