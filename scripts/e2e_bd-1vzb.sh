#!/usr/bin/env bash
#
# e2e_bd-1vzb.sh - Per-project force_local / force_remote overrides
#
# Verifies hook behavior with a real daemon in mock transport mode:
# 1) Baseline (no overrides) denies local execution (remote path taken)
# 2) force_local allows local execution even when remote would succeed
# 3) High confidence threshold allows local execution
# 4) force_remote bypasses confidence threshold and denies local execution
#
# Output is logged in JSONL format.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
LOG_FILE="${PROJECT_ROOT}/target/e2e_bd-1vzb.jsonl"

timestamp() {
    date -u '+%Y-%m-%dT%H:%M:%S.%3NZ' 2>/dev/null || date -u '+%Y-%m-%dT%H:%M:%SZ'
}

log_json() {
    local phase="$1"
    local message="$2"
    local extra="${3:-}"
    local ts
    ts="$(timestamp)"
    if [[ -z "$extra" || "$extra" == "{}" ]]; then
        printf '{"ts":"%s","test":"bd-1vzb","phase":"%s","message":"%s"}\n' \
            "$ts" "$phase" "$message" | tee -a "$LOG_FILE"
        return
    fi

    local payload="$extra"
    payload="${payload#\{}"
    payload="${payload%\}}"
    if [[ -z "$payload" ]]; then
        printf '{"ts":"%s","test":"bd-1vzb","phase":"%s","message":"%s"}\n' \
            "$ts" "$phase" "$message" | tee -a "$LOG_FILE"
        return
    fi

    printf '{"ts":"%s","test":"bd-1vzb","phase":"%s","message":"%s",%s}\n' \
        "$ts" "$phase" "$message" "$payload" | tee -a "$LOG_FILE"
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

build_binaries() {
    log_json "build" "Building rch + rchd (debug)"
    (cd "$PROJECT_ROOT" && cargo build -p rch -p rchd >/dev/null 2>&1) || die "cargo build failed"
    [[ -x "$PROJECT_ROOT/target/debug/rch" ]] || die "rch binary missing after build"
    [[ -x "$PROJECT_ROOT/target/debug/rchd" ]] || die "rchd binary missing after build"
}

make_test_project() {
    TEST_ROOT="$(mktemp -d "${TMPDIR:-/tmp}/rch-bd-1vzb-XXXXXX")"
    PROJECT_DIR="$TEST_ROOT/project"
    LOG_DIR="$TEST_ROOT/logs"
    mkdir -p "$PROJECT_DIR/src" "$LOG_DIR"

    cat >"$PROJECT_DIR/Cargo.toml" <<'EOF'
[package]
name = "rch_e2e_bd_1vzb"
version = "0.1.0"
edition = "2024"

[dependencies]
EOF

    cat >"$PROJECT_DIR/src/main.rs" <<'EOF'
fn main() {
    println!("rch bd-1vzb e2e ok");
}
EOF

    log_json "setup" "Created test project" "{\"root\":\"$TEST_ROOT\"}"
}

write_workers_config() {
    WORKERS_FILE="$TEST_ROOT/workers.toml"
    cat >"$WORKERS_FILE" <<'EOF'
[[workers]]
id = "mock-worker"
host = "mock.host"
user = "mockuser"
identity_file = "~/.ssh/mock"
total_slots = 64
priority = 100
enabled = true
EOF
}

start_daemon() {
    SOCKET_PATH="$TEST_ROOT/rch.sock"
    DAEMON_LOG="$LOG_DIR/rchd.log"

    log_json "daemon" "Starting rchd (mock transport)" "{\"socket\":\"$SOCKET_PATH\"}"
    env RCH_MOCK_SSH=1 RCH_MOCK_SSH_STDOUT=health_check \
        "$PROJECT_ROOT/target/debug/rchd" \
        --socket "$SOCKET_PATH" \
        --workers-config "$WORKERS_FILE" \
        --foreground \
        >>"$DAEMON_LOG" 2>&1 &
    RCHD_PID=$!

    local waited=0
    while [[ ! -S "$SOCKET_PATH" && $waited -lt 50 ]]; do
        sleep 0.1
        waited=$((waited + 1))
    done
    [[ -S "$SOCKET_PATH" ]] || die "Daemon socket not found after startup (log: $DAEMON_LOG)"
    log_json "daemon" "Daemon ready" "{\"pid\":$RCHD_PID}"
}

stop_daemon() {
    if [[ -n "${RCHD_PID:-}" ]]; then
        log_json "daemon" "Stopping daemon" "{\"pid\":$RCHD_PID}"
        kill "$RCHD_PID" >/dev/null 2>&1 || true
    fi
}

hook_json() {
    cat <<'JSON'
{
  "tool_name": "Bash",
  "tool_input": {
    "command": "cargo build",
    "description": "bd-1vzb e2e build"
  }
}
JSON
}

write_project_config() {
    local config_body="$1"
    mkdir -p "$PROJECT_DIR/.rch"
    cat >"$PROJECT_DIR/.rch/config.toml" <<EOF
$config_body
EOF
}

run_hook() {
    local scenario="$1"
    local hook_out="$LOG_DIR/hook_${scenario}.out"
    local hook_err="$LOG_DIR/hook_${scenario}.err"

    (
        cd "$PROJECT_DIR"
        printf '%s\n' "$(hook_json)" | env RCH_SOCKET_PATH="$SOCKET_PATH" RCH_MOCK_SSH=1 "$PROJECT_ROOT/target/debug/rch" \
            >"$hook_out" 2>"$hook_err"
    )

    if /bin/grep -q '"permissionDecision":"deny"' "$hook_out"; then
        echo "deny"
    else
        echo "allow"
    fi
}

expect_decision() {
    local scenario="$1"
    local expected="$2"
    local got
    got="$(run_hook "$scenario")"
    log_json "verify" "Hook decision" "{\"scenario\":\"$scenario\",\"expected\":\"$expected\",\"got\":\"$got\"}"
    [[ "$got" == "$expected" ]] || die "Scenario $scenario expected $expected, got $got"
}

main() {
    : > "$LOG_FILE"
    check_dependencies
    build_binaries
    make_test_project
    write_workers_config

    trap stop_daemon EXIT
    start_daemon

    log_json "test" "Baseline: remote available -> deny"
    write_project_config $'[general]\nenabled = true\n'
    expect_decision "baseline" "deny"

    log_json "test" "force_local: allow even when remote would succeed"
    write_project_config $'[general]\nenabled = true\nforce_local = true\n'
    expect_decision "force_local" "allow"

    log_json "test" "High confidence threshold: allow"
    write_project_config $'[general]\nenabled = true\n\n[compilation]\nconfidence_threshold = 1.0\n'
    expect_decision "high_threshold" "allow"

    log_json "test" "force_remote: deny even with high confidence threshold"
    write_project_config $'[general]\nenabled = true\nforce_remote = true\n\n[compilation]\nconfidence_threshold = 1.0\n'
    expect_decision "force_remote" "deny"

    log_json "summary" "All bd-1vzb checks passed" '{"result":"pass"}'
}

main "$@"
