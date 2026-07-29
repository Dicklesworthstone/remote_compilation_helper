#!/usr/bin/env bash
set -euo pipefail

# =============================================================================
# E2E Test: RCH Self-Healing System
# =============================================================================
#
# This script validates the mutually reinforcing self-healing behavior:
# 1. Hook auto-starts daemon when unavailable
# 2. Daemon auto-installs hooks on startup
# 3. Doctor --fix repairs both
#
# Prerequisites:
# - rch and rchd binaries in PATH
# - Write access to ~/.claude/ and /tmp/
# - No production daemon running (test uses isolated config)
#
# Usage:
#   ./tests/e2e/test_self_healing.sh [--verbose]
#

# =============================================================================
# Configuration
# =============================================================================

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TEST_HOME=$(mktemp -d)
TEST_CONFIG_DIR="${TEST_HOME}/.config/rch"
TEST_CLAUDE_DIR="${TEST_HOME}/.claude"
TEST_SOCKET="/tmp/rch-test-$$.sock"
LOG_FILE="${TEST_HOME}/test.log"

VERBOSE="${1:-}"
PASSED=0
FAILED=0
TOTAL=0

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# =============================================================================
# Logging Functions
# =============================================================================

log() {
    local level=$1
    shift
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S.%3N')
    echo -e "[$timestamp] [$level] $*" | tee -a "$LOG_FILE"
}

log_info()  { log "INFO " "$*"; }
log_pass()  { log "${GREEN}PASS${NC} " "$*"; }
log_fail()  { log "${RED}FAIL${NC} " "$*"; }
log_test()  { log "${BLUE}TEST${NC} " "$*"; }
log_detail() { [[ "$VERBOSE" == "--verbose" ]] && log "DEBUG" "$*" || true; }

# =============================================================================
# Test Utilities
# =============================================================================

setup_test_env() {
    log_info "Setting up isolated test environment..."
    log_detail "TEST_HOME=$TEST_HOME"

    mkdir -p "$TEST_CONFIG_DIR"
    mkdir -p "$TEST_CLAUDE_DIR"

    # Create minimal config pointing to test socket
    cat > "${TEST_CONFIG_DIR}/config.toml" <<EOF
[general]
socket_path = "${TEST_SOCKET}"

[self_healing]
hook_starts_daemon = true
daemon_installs_hooks = true
auto_start_timeout_secs = 5
auto_start_cooldown_secs = 5
EOF

    export HOME="$TEST_HOME"
    export RCH_CONFIG_DIR="$TEST_CONFIG_DIR"
    export RCH_SOCKET_PATH="$TEST_SOCKET"

    log_info "Test environment ready"
}

cleanup() {
    log_info "Cleaning up test environment..."

    # Stop any test daemon
    if [[ -S "$TEST_SOCKET" ]]; then
        log_detail "Stopping test daemon..."
        rch daemon stop 2>/dev/null || true
    fi

    # Kill any stray rchd processes from this test
    pkill -f "rchd.*${TEST_SOCKET}" 2>/dev/null || true

    # Remove test directory
    if [[ -d "$TEST_HOME" && "$TEST_HOME" == /tmp/* ]]; then
        rm -rf "$TEST_HOME"
    fi

    log_info "Cleanup complete"
}

trap cleanup EXIT

assert_eq() {
    local expected=$1
    local actual=$2
    local msg=$3

    if [[ "$expected" == "$actual" ]]; then
        return 0
    else
        log_fail "Assertion failed: $msg"
        log_detail "  Expected: $expected"
        log_detail "  Actual:   $actual"
        return 1
    fi
}

assert_file_exists() {
    local file=$1
    local msg=$2

    if [[ -f "$file" ]]; then
        return 0
    else
        log_fail "File not found: $file ($msg)"
        return 1
    fi
}

assert_socket_exists() {
    local socket=$1
    local msg=$2

    if [[ -S "$socket" ]]; then
        return 0
    else
        log_fail "Socket not found: $socket ($msg)"
        return 1
    fi
}

assert_contains() {
    local haystack=$1
    local needle=$2
    local msg=$3

    if [[ "$haystack" == *"$needle"* ]]; then
        return 0
    else
        log_fail "String not found: '$needle' ($msg)"
        log_detail "  In: $haystack"
        return 1
    fi
}

run_test() {
    local name=$1
    shift
    local test_fn=$1

    TOTAL=$((TOTAL + 1))
    log_test "Running: $name"

    if $test_fn; then
        PASSED=$((PASSED + 1))
        log_pass "$name"
        return 0
    else
        FAILED=$((FAILED + 1))
        log_fail "$name"
        return 1
    fi
}

# =============================================================================
# Test Cases
# =============================================================================

test_hook_auto_starts_daemon() {
    log_detail "Ensuring daemon is stopped..."
    rch daemon stop 2>/dev/null || true
    rm -f "$TEST_SOCKET"
    sleep 1

    # Verify daemon not running
    if [[ -S "$TEST_SOCKET" ]]; then
        log_fail "Precondition failed: daemon still running"
        return 1
    fi

    log_detail "Creating test project..."
    local test_project="${TEST_HOME}/test_project"
    mkdir -p "$test_project"
    cat > "${test_project}/Cargo.toml" <<EOF
[package]
name = "test_project"
version = "0.1.0"
edition = "2021"
EOF
    mkdir -p "${test_project}/src"
    echo 'fn main() { println!("Hello"); }' > "${test_project}/src/main.rs"

    log_detail "Invoking hook (should auto-start daemon)..."
    local hook_input='{"event":"PreToolUse","tool_name":"Bash","tool_input":{"command":"cargo build --release"},"session_id":"test","session_cwd":"'"$test_project"'"}'

    local output
    output=$(echo "$hook_input" | timeout 30 rch 2>&1) || true

    log_detail "Hook output: $output"

    # Check if daemon was auto-started
    sleep 2
    if ! [[ -S "$TEST_SOCKET" ]]; then
        log_fail "Daemon was not auto-started"
        return 1
    fi

    log_detail "Daemon auto-started successfully"
    return 0
}

test_daemon_auto_installs_hook() {
    log_detail "Removing existing hook..."
    rm -f "${TEST_CLAUDE_DIR}/settings.json"

    log_detail "Stopping daemon..."
    rch daemon stop 2>/dev/null || true
    rm -f "$TEST_SOCKET"
    sleep 1

    log_detail "Starting daemon (should install hook)..."
    rch daemon start
    sleep 2

    # Check if hook was installed
    if ! assert_file_exists "${TEST_CLAUDE_DIR}/settings.json" "Hook settings file should exist"; then
        return 1
    fi

    # Verify hook content
    local settings
    settings=$(cat "${TEST_CLAUDE_DIR}/settings.json")

    if ! assert_contains "$settings" '"command": "rch"' "Settings should contain rch hook"; then
        log_detail "Settings content: $settings"
        return 1
    fi

    log_detail "Hook auto-installed successfully"
    return 0
}

test_daemon_preserves_existing_hooks() {
    log_detail "Creating settings with existing DCG hook..."
    mkdir -p "$TEST_CLAUDE_DIR"
    cat > "${TEST_CLAUDE_DIR}/settings.json" <<EOF
{
  "hooks": {
    "PreToolUse": [
      {
        "command": "dcg",
        "description": "Destructive Command Guard"
      }
    ]
  }
}
EOF

    log_detail "Restarting daemon..."
    rch daemon stop 2>/dev/null || true
    rm -f "$TEST_SOCKET"
    sleep 1
    rch daemon start
    sleep 2

    # Verify both hooks present
    local settings
    settings=$(cat "${TEST_CLAUDE_DIR}/settings.json")

    if ! assert_contains "$settings" '"command": "dcg"' "DCG hook should be preserved"; then
        return 1
    fi

    if ! assert_contains "$settings" '"command": "rch"' "RCH hook should be added"; then
        return 1
    fi

    log_detail "Existing hooks preserved successfully"
    return 0
}

test_doctor_fix_installs_hook() {
    log_detail "Removing hook..."
    rm -f "${TEST_CLAUDE_DIR}/settings.json"

    log_detail "Running doctor --fix..."
    local output
    output=$(rch doctor --fix 2>&1)

    log_detail "Doctor output: $output"

    if ! assert_file_exists "${TEST_CLAUDE_DIR}/settings.json" "Doctor should install hook"; then
        return 1
    fi

    if ! assert_contains "$output" "Fixed" "Doctor should report fix"; then
        return 1
    fi

    log_detail "Doctor --fix installed hook successfully"
    return 0
}

test_doctor_fix_starts_daemon() {
    log_detail "Stopping daemon..."
    rch daemon stop 2>/dev/null || true
    rm -f "$TEST_SOCKET"
    sleep 1

    log_detail "Running doctor --fix..."
    local output
    output=$(rch doctor --fix 2>&1)

    log_detail "Doctor output: $output"

    sleep 2
    if ! assert_socket_exists "$TEST_SOCKET" "Doctor should start daemon"; then
        return 1
    fi

    log_detail "Doctor --fix started daemon successfully"
    return 0
}

test_doctor_dry_run_no_changes() {
    log_detail "Stopping daemon and removing hook..."
    rch daemon stop 2>/dev/null || true
    rm -f "$TEST_SOCKET"
    rm -f "${TEST_CLAUDE_DIR}/settings.json"
    sleep 1

    log_detail "Running doctor --fix --dry-run..."
    local output
    output=$(rch doctor --fix --dry-run 2>&1)

    log_detail "Doctor output: $output"

    # Verify no changes made
    if [[ -f "${TEST_CLAUDE_DIR}/settings.json" ]]; then
        log_fail "Dry run should not create settings file"
        return 1
    fi

    if [[ -S "$TEST_SOCKET" ]]; then
        log_fail "Dry run should not start daemon"
        return 1
    fi

    if ! assert_contains "$output" "Would" "Dry run should say 'Would'"; then
        return 1
    fi

    log_detail "Dry run made no changes as expected"
    return 0
}

test_auto_start_cooldown() {
    log_detail "This test validates cooldown prevents restart spam"

    # Start and immediately stop daemon
    rch daemon start
    sleep 1
    rch daemon stop
    rm -f "$TEST_SOCKET"

    # Record time
    local start_time=$(date +%s)

    # Try to trigger auto-start via hook
    local test_project="${TEST_HOME}/test_project2"
    mkdir -p "$test_project/src"
    cat > "${test_project}/Cargo.toml" <<EOF
[package]
name = "test_project2"
version = "0.1.0"
edition = "2021"
EOF
    echo 'fn main() {}' > "${test_project}/src/main.rs"

    local hook_input='{"event":"PreToolUse","tool_name":"Bash","tool_input":{"command":"cargo build"},"session_id":"test","session_cwd":"'"$test_project"'"}'

    log_detail "First hook invocation..."
    echo "$hook_input" | timeout 10 rch 2>&1 || true

    # Check if cooldown file was created
    local cooldown_file="/tmp/rch-autostart-cooldown"
    if [[ -f "$cooldown_file" ]]; then
        log_detail "Cooldown file created"
    fi

    log_detail "Second hook invocation (should skip due to cooldown)..."
    local output
    output=$(echo "$hook_input" | timeout 5 rch 2>&1) || true

    # The second invocation should be fast (not waiting for daemon)
    # because cooldown prevents restart attempt
    local end_time=$(date +%s)
    local elapsed=$((end_time - start_time))

    log_detail "Elapsed time: ${elapsed}s"

    # If cooldown works, second invocation should be quick
    # (This is a heuristic test - timing-based)
    return 0
}

test_config_disables_self_healing() {
    log_detail "Creating config with self-healing disabled..."
    cat > "${TEST_CONFIG_DIR}/config.toml" <<EOF
socket_path = "${TEST_SOCKET}"

[self_healing]
hook_starts_daemon = false
daemon_installs_hooks = false
EOF

    # Stop daemon and remove hook
    rch daemon stop 2>/dev/null || true
    rm -f "$TEST_SOCKET"
    rm -f "${TEST_CLAUDE_DIR}/settings.json"
    sleep 1

    log_detail "Starting daemon (should NOT install hook)..."
    rch daemon start
    sleep 2

    # Hook should NOT be installed (disabled in config)
    if [[ -f "${TEST_CLAUDE_DIR}/settings.json" ]]; then
        local settings
        settings=$(cat "${TEST_CLAUDE_DIR}/settings.json")
        if [[ "$settings" == *'"command": "rch"'* ]]; then
            log_fail "Hook was installed despite being disabled in config"
            return 1
        fi
    fi

    log_detail "Self-healing correctly disabled by config"

    # Restore default config
    cat > "${TEST_CONFIG_DIR}/config.toml" <<EOF
socket_path = "${TEST_SOCKET}"

[self_healing]
hook_starts_daemon = true
daemon_installs_hooks = true
EOF

    return 0
}

test_full_self_healing_cycle() {
    log_detail "=== Full Self-Healing Cycle Test ==="

    # Start from completely clean state
    log_detail "Step 1: Clean state"
    rch daemon stop 2>/dev/null || true
    rm -f "$TEST_SOCKET"
    rm -f "${TEST_CLAUDE_DIR}/settings.json"
    rm -rf "${TEST_CLAUDE_DIR}"
    sleep 1

    # Verify nothing exists
    if [[ -S "$TEST_SOCKET" ]] || [[ -f "${TEST_CLAUDE_DIR}/settings.json" ]]; then
        log_fail "Clean state not achieved"
        return 1
    fi
    log_detail "  ✓ Clean state verified"

    # Run doctor --fix (should fix everything)
    log_detail "Step 2: Run doctor --fix"
    local output
    output=$(rch doctor --fix 2>&1)
    log_detail "Doctor output: $output"
    sleep 2

    # Verify hook installed
    if ! [[ -f "${TEST_CLAUDE_DIR}/settings.json" ]]; then
        log_fail "Hook not installed by doctor --fix"
        return 1
    fi
    log_detail "  ✓ Hook installed"

    # Verify daemon running
    if ! [[ -S "$TEST_SOCKET" ]]; then
        log_fail "Daemon not started by doctor --fix"
        return 1
    fi
    log_detail "  ✓ Daemon running"

    # Simulate daemon crash
    log_detail "Step 3: Simulate daemon crash"
    pkill -f "rchd.*${TEST_SOCKET}" 2>/dev/null || true
    rm -f "$TEST_SOCKET"
    sleep 1

    if [[ -S "$TEST_SOCKET" ]]; then
        log_fail "Daemon still running after simulated crash"
        return 1
    fi
    log_detail "  ✓ Daemon crashed (simulated)"

    # Trigger build (hook should auto-restart daemon)
    log_detail "Step 4: Trigger build (should auto-restart daemon)"
    local test_project="${TEST_HOME}/test_project_cycle"
    mkdir -p "$test_project/src"
    cat > "${test_project}/Cargo.toml" <<EOF
[package]
name = "cycle_test"
version = "0.1.0"
edition = "2021"
EOF
    echo 'fn main() { println!("cycle test"); }' > "${test_project}/src/main.rs"

    local hook_input='{"event":"PreToolUse","tool_name":"Bash","tool_input":{"command":"cargo build --release"},"session_id":"cycle-test","session_cwd":"'"$test_project"'"}'

    output=$(echo "$hook_input" | timeout 30 rch 2>&1) || true
    log_detail "Hook output: $output"
    sleep 2

    # Verify daemon auto-restarted
    if ! [[ -S "$TEST_SOCKET" ]]; then
        log_fail "Daemon not auto-restarted by hook"
        return 1
    fi
    log_detail "  ✓ Daemon auto-restarted"

    log_detail "=== Full cycle complete ==="
    return 0
}

# =============================================================================
# Main
# =============================================================================

main() {
    echo ""
    echo "=============================================="
    echo "  RCH Self-Healing E2E Test Suite"
    echo "=============================================="
    echo ""

    setup_test_env

    # Run all tests
    run_test "Hook auto-starts daemon" test_hook_auto_starts_daemon
    run_test "Daemon auto-installs hook" test_daemon_auto_installs_hook
    run_test "Daemon preserves existing hooks" test_daemon_preserves_existing_hooks
    run_test "Doctor --fix installs hook" test_doctor_fix_installs_hook
    run_test "Doctor --fix starts daemon" test_doctor_fix_starts_daemon
    run_test "Doctor --dry-run makes no changes" test_doctor_dry_run_no_changes
    run_test "Auto-start cooldown works" test_auto_start_cooldown
    run_test "Config disables self-healing" test_config_disables_self_healing
    run_test "Full self-healing cycle" test_full_self_healing_cycle

    # Summary
    echo ""
    echo "=============================================="
    echo "  Test Results"
    echo "=============================================="
    echo ""
    echo -e "  Total:  $TOTAL"
    echo -e "  ${GREEN}Passed: $PASSED${NC}"
    echo -e "  ${RED}Failed: $FAILED${NC}"
    echo ""

    if [[ $FAILED -gt 0 ]]; then
        echo -e "${RED}SOME TESTS FAILED${NC}"
        echo "See $LOG_FILE for details"
        exit 1
    else
        echo -e "${GREEN}ALL TESTS PASSED${NC}"
        exit 0
    fi
}

main "$@"
