#!/usr/bin/env bash
#
# e2e_bd-1i8n.sh - Env allowlist passthrough (config + env override)
#
# Verifies:
# - Project config allowlist is honored per-project
# - RCH_ENV_ALLOWLIST overrides project config
# - Output is logged in JSONL format

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
LOG_FILE="${PROJECT_ROOT}/target/e2e_bd-1i8n.jsonl"

timestamp() {
    date -u '+%Y-%m-%dT%H:%M:%S.%3NZ' 2>/dev/null || date -u '+%Y-%m-%dT%H:%M:%SZ'
}

log_json() {
    local phase="$1"
    local message="$2"
    local extra="${3:-{}}"
    local ts
    ts="$(timestamp)"
    printf '{"ts":"%s","test":"bd-1i8n","phase":"%s","message":"%s",%s}\n' \
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
        log_json "setup" "Using existing rch binary" "{\"path\":\"$rch_bin\"}"
        echo "$rch_bin"
        return
    fi
    log_json "setup" "Building rch (debug)"
    (cd "$PROJECT_ROOT" && cargo build -p rch >/dev/null 2>&1) || die "cargo build failed"
    [[ -x "$rch_bin" ]] || die "rch binary missing after build"
    echo "$rch_bin"
}

write_project_config() {
    local project_dir="$1"
    local allowlist="$2"
    mkdir -p "$project_dir/.rch"
    cat > "$project_dir/.rch/config.toml" <<EOF
[environment]
allowlist = [$allowlist]
EOF
}

read_allowlist() {
    local rch_bin="$1"
    local project_dir="$2"
    (cd "$project_dir" && "$rch_bin" config show --json) | jq -r '.result.environment.allowlist | join(",")'
}

main() {
    : > "$LOG_FILE"
    check_dependencies
    local rch_bin
    rch_bin="$(build_rch)"

    local tmp_root
    tmp_root="$(mktemp -d "${TMPDIR:-/tmp}/rch-env-allowlist-XXXXXX")"

    local project_a="$tmp_root/project-a"
    local project_b="$tmp_root/project-b"
    mkdir -p "$project_a" "$project_b"

    log_json "setup" "Writing project configs" "{\"root\":\"$tmp_root\"}"
    write_project_config "$project_a" "\"RUSTFLAGS\""
    write_project_config "$project_b" "\"CARGO_TARGET_DIR\""

    log_json "test" "Project config allowlist (project A)"
    local allowlist_a
    allowlist_a="$(read_allowlist "$rch_bin" "$project_a")"
    if [[ "$allowlist_a" != "RUSTFLAGS" ]]; then
        die "Expected allowlist RUSTFLAGS for project A, got: $allowlist_a"
    fi
    log_json "verify" "Project A allowlist ok" "{\"allowlist\":\"$allowlist_a\"}"

    log_json "test" "Project config allowlist (project B)"
    local allowlist_b
    allowlist_b="$(read_allowlist "$rch_bin" "$project_b")"
    if [[ "$allowlist_b" != "CARGO_TARGET_DIR" ]]; then
        die "Expected allowlist CARGO_TARGET_DIR for project B, got: $allowlist_b"
    fi
    log_json "verify" "Project B allowlist ok" "{\"allowlist\":\"$allowlist_b\"}"

    log_json "test" "Env override allowlist takes precedence"
    local allowlist_override
    allowlist_override="$(RCH_ENV_ALLOWLIST="RUSTFLAGS,CARGO_TARGET_DIR" read_allowlist "$rch_bin" "$project_a")"
    if [[ "$allowlist_override" != "RUSTFLAGS,CARGO_TARGET_DIR" ]]; then
        die "Expected override allowlist, got: $allowlist_override"
    fi
    log_json "verify" "Env override allowlist ok" "{\"allowlist\":\"$allowlist_override\"}"

    log_json "summary" "All bd-1i8n checks passed" '{"result":"pass"}'
}

main "$@"
