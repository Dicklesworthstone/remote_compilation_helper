#!/usr/bin/env bash
#
# test_framework.sh - Extended E2E test framework for RCH
#
# Extends test_lib.sh with TUI-specific testing utilities including
# pseudo-terminal handling, keystroke simulation, and screenshot capture.
#
# Usage:
#   source "$(dirname "$0")/lib/test_framework.sh"
#   init_test_log "my_tui_test"
#   tui_start "rch dashboard --mock-data"
#   tui_send_keys "j" "k" "q"
#   tui_expect_output "Workers"
#   tui_stop
#   test_pass
#
# Dependencies:
#   - test_lib.sh (sourced automatically)
#   - script (from util-linux, for pseudo-terminal)
#   - tmux (optional, for advanced TUI testing)
#

# Get script directory for sourcing dependencies
_FRAMEWORK_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Source base test library
# shellcheck disable=SC1091
source "$_FRAMEWORK_DIR/../test_lib.sh"

# ============================================================================
# Configuration
# ============================================================================

# TUI test settings
TUI_DEFAULT_TIMEOUT="${RCH_TUI_TIMEOUT:-5}"
TUI_SCREENSHOT_DIR="${RCH_SCREENSHOT_DIR:-${PROJECT_ROOT:-$(pwd)}/target/test-screenshots}"

# State tracking
_TUI_PID=""
_TUI_OUTPUT_FILE=""
_TUI_TMUX_SESSION=""

# ============================================================================
# TUI Testing Helpers
# ============================================================================

# Start a TUI command for testing using the built-in test mode.
#
# Args:
#   $1 - Command to run (e.g., "rch dashboard --mock-data")
#   $2 - Optional: output file path (default: temp file)
#
# Returns: 0 on success, 1 on failure
#
tui_start() {
    local cmd="$1"
    local output_file="${2:-}"

    if [[ -z "$output_file" ]]; then
        output_file=$(mktemp "${TMPDIR:-/tmp}/rch_tui_XXXXXX.log")
    fi
    _TUI_OUTPUT_FILE="$output_file"

    log_json execute "Starting TUI: $cmd" "{\"output_file\":\"$output_file\"}"

    # Use script command to create a pseudo-terminal
    # This allows capturing TUI output that would normally go to terminal
    if command -v script >/dev/null 2>&1; then
        # GNU script (Linux)
        if script --version 2>&1 | grep -q 'util-linux'; then
            script -q -c "$cmd" "$output_file" &
            _TUI_PID=$!
        # BSD script (macOS)
        else
            script -q "$output_file" bash -c "$cmd" &
            _TUI_PID=$!
        fi
    else
        # Fallback: run directly without pseudo-terminal
        log_json setup "Warning: script command not found, TUI output may be incomplete"
        $cmd > "$output_file" 2>&1 &
        _TUI_PID=$!
    fi

    # Wait briefly for TUI to initialize
    sleep 0.5

    if ! kill -0 "$_TUI_PID" 2>/dev/null; then
        log_json verify "TUI failed to start" "{\"pid\":$_TUI_PID}"
        return 1
    fi

    log_json execute "TUI started" "{\"pid\":$_TUI_PID}"
    return 0
}

# Start a TUI in tmux for more advanced testing.
#
# Args:
#   $1 - Command to run
#   $2 - Session name (default: auto-generated)
#
# Returns: 0 on success, 1 on failure
#
tui_start_tmux() {
    local cmd="$1"
    local session="${2:-rch_test_$$}"

    if ! command -v tmux >/dev/null 2>&1; then
        log_json setup "tmux not available, falling back to basic TUI start"
        tui_start "$cmd"
        return $?
    fi

    _TUI_TMUX_SESSION="$session"
    _TUI_OUTPUT_FILE=$(mktemp "${TMPDIR:-/tmp}/rch_tui_XXXXXX.log")

    log_json execute "Starting TUI in tmux: $cmd" "{\"session\":\"$session\"}"

    # Create detached tmux session
    tmux new-session -d -s "$session" -x 80 -y 24 "$cmd" \; \
        pipe-pane -o "cat >> $_TUI_OUTPUT_FILE"

    sleep 0.5

    if ! tmux has-session -t "$session" 2>/dev/null; then
        log_json verify "tmux session failed to start" "{\"session\":\"$session\"}"
        return 1
    fi

    log_json execute "tmux session started" "{\"session\":\"$session\"}"
    return 0
}

# Send keystrokes to the running TUI.
#
# Args:
#   $@ - Keys to send (e.g., "j" "k" "Enter" "q")
#
# Note: Each key is sent with a brief delay between them.
#
tui_send_keys() {
    local keys=("$@")

    for key in "${keys[@]}"; do
        log_json execute "Sending key: $key"

        if [[ -n "$_TUI_TMUX_SESSION" ]]; then
            # tmux mode - send keys to tmux pane
            tmux send-keys -t "$_TUI_TMUX_SESSION" "$key"
        elif [[ -n "$_TUI_PID" ]]; then
            # Direct mode - send via stdin if available
            # Note: This may not work for all TUI apps
            log_json execute "Warning: Direct key sending not fully supported"
        fi

        # Brief delay between keystrokes
        sleep 0.1
    done
}

# Check if TUI output contains expected text.
#
# Args:
#   $1 - Expected text pattern (grep pattern)
#   $2 - Optional: timeout in seconds (default: TUI_DEFAULT_TIMEOUT)
#
# Returns: 0 if found, 1 if not found within timeout
#
tui_expect_output() {
    local pattern="$1"
    local timeout="${2:-$TUI_DEFAULT_TIMEOUT}"
    local start_time
    start_time=$(date +%s)

    log_json verify "Expecting output: $pattern" "{\"timeout\":$timeout}"

    while true; do
        if [[ -f "$_TUI_OUTPUT_FILE" ]] && grep -q "$pattern" "$_TUI_OUTPUT_FILE" 2>/dev/null; then
            log_json verify "Found expected output: $pattern"
            return 0
        fi

        local elapsed
        elapsed=$(($(date +%s) - start_time))
        if [[ $elapsed -ge $timeout ]]; then
            log_json verify "Timeout waiting for: $pattern" "{\"elapsed\":$elapsed}"
            return 1
        fi

        sleep 0.2
    done
}

# Check that TUI output does NOT contain text.
#
# Args:
#   $1 - Unexpected text pattern (grep pattern)
#
# Returns: 0 if not found, 1 if found
#
tui_expect_not_output() {
    local pattern="$1"

    log_json verify "Expecting NO output matching: $pattern"

    if [[ -f "$_TUI_OUTPUT_FILE" ]] && grep -q "$pattern" "$_TUI_OUTPUT_FILE" 2>/dev/null; then
        log_json verify "Unexpectedly found: $pattern"
        return 1
    fi

    log_json verify "Correctly absent: $pattern"
    return 0
}

# Capture a screenshot of the current TUI state.
#
# Args:
#   $1 - Screenshot name (saved to TUI_SCREENSHOT_DIR)
#
# Returns: Path to screenshot file
#
tui_screenshot() {
    local name="$1"
    mkdir -p "$TUI_SCREENSHOT_DIR"

    local screenshot_file="$TUI_SCREENSHOT_DIR/${name}_$(date +%Y%m%d_%H%M%S).txt"

    log_json execute "Capturing screenshot: $name"

    if [[ -n "$_TUI_TMUX_SESSION" ]]; then
        # tmux mode - capture pane content
        tmux capture-pane -t "$_TUI_TMUX_SESSION" -p > "$screenshot_file"
    elif [[ -f "$_TUI_OUTPUT_FILE" ]]; then
        # Direct mode - copy current output
        cp "$_TUI_OUTPUT_FILE" "$screenshot_file"
    fi

    log_json execute "Screenshot saved" "{\"file\":\"$screenshot_file\"}"
    echo "$screenshot_file"
}

# Stop the TUI and capture final output.
#
# Args:
#   $1 - Optional: quit key sequence (default: "q")
#
tui_stop() {
    local quit_key="${1:-q}"

    log_json teardown "Stopping TUI"

    if [[ -n "$_TUI_TMUX_SESSION" ]]; then
        # Try graceful quit first
        tmux send-keys -t "$_TUI_TMUX_SESSION" "$quit_key" 2>/dev/null
        sleep 0.5

        # Kill session if still exists
        tmux kill-session -t "$_TUI_TMUX_SESSION" 2>/dev/null || true
        _TUI_TMUX_SESSION=""
    fi

    if [[ -n "$_TUI_PID" ]] && kill -0 "$_TUI_PID" 2>/dev/null; then
        kill "$_TUI_PID" 2>/dev/null || true
        wait "$_TUI_PID" 2>/dev/null || true
        _TUI_PID=""
    fi

    log_json teardown "TUI stopped"
}

# Get the captured TUI output.
#
# Returns: Output content (stdout)
#
tui_get_output() {
    if [[ -f "$_TUI_OUTPUT_FILE" ]]; then
        cat "$_TUI_OUTPUT_FILE"
    fi
}

# ============================================================================
# RCH-Specific Helpers
# ============================================================================

# Test RCH dashboard with mock data.
#
# Args:
#   $1 - Additional dashboard flags (optional)
#
rch_dashboard_test() {
    local extra_flags="${1:-}"

    # Use test mode for non-interactive snapshot
    local cmd="rch dashboard --test-mode --mock-data $extra_flags"
    log_json execute "Running: $cmd"

    local output
    output=$($cmd 2>&1)
    local exit_code=$?

    echo "$output"
    return $exit_code
}

# Test RCH dashboard state dump.
#
# Args:
#   $1 - Additional dashboard flags (optional)
#
rch_dashboard_state() {
    local extra_flags="${1:-}"

    local cmd="rch dashboard --dump-state --mock-data $extra_flags"
    log_json execute "Running: $cmd"

    $cmd 2>&1
}

# ============================================================================
# Assertion Helpers
# ============================================================================

# Assert that a condition is true.
#
# Args:
#   $1 - Condition to evaluate
#   $2 - Error message if false
#
assert_true() {
    if ! eval "$1"; then
        log_json verify "ASSERT FAILED: $2" "{\"condition\":\"$1\"}"
        return 1
    fi
    log_json verify "ASSERT PASS: $2"
    return 0
}

# Assert two values are equal.
#
# Args:
#   $1 - Expected value
#   $2 - Actual value
#   $3 - Error message (optional)
#
assert_eq() {
    local expected="$1"
    local actual="$2"
    local message="${3:-Values should be equal}"

    if [[ "$expected" != "$actual" ]]; then
        log_json verify "ASSERT FAILED: $message" "{\"expected\":\"$expected\",\"actual\":\"$actual\"}"
        return 1
    fi
    log_json verify "ASSERT PASS: $message"
    return 0
}

# Assert string contains substring.
#
# Args:
#   $1 - String to search in
#   $2 - Substring to find
#   $3 - Error message (optional)
#
assert_contains() {
    local haystack="$1"
    local needle="$2"
    local message="${3:-String should contain substring}"

    if [[ "$haystack" != *"$needle"* ]]; then
        log_json verify "ASSERT FAILED: $message" "{\"needle\":\"$needle\"}"
        return 1
    fi
    log_json verify "ASSERT PASS: $message"
    return 0
}

# Assert string does NOT contain substring.
#
# Args:
#   $1 - String to search in
#   $2 - Substring that should be absent
#   $3 - Error message (optional)
#
assert_not_contains() {
    local haystack="$1"
    local needle="$2"
    local message="${3:-String should not contain substring}"

    if [[ "$haystack" == *"$needle"* ]]; then
        log_json verify "ASSERT FAILED: $message" "{\"needle\":\"$needle\"}"
        return 1
    fi
    log_json verify "ASSERT PASS: $message"
    return 0
}

# Assert exit code matches expected.
#
# Args:
#   $1 - Expected exit code
#   $2 - Actual exit code
#   $3 - Error message (optional)
#
assert_exit_code() {
    local expected="$1"
    local actual="$2"
    local message="${3:-Exit code should match}"

    if [[ "$expected" != "$actual" ]]; then
        log_json verify "ASSERT FAILED: $message" "{\"expected_exit\":$expected,\"actual_exit\":$actual}"
        return 1
    fi
    log_json verify "ASSERT PASS: $message"
    return 0
}

# Assert file exists.
#
# Args:
#   $1 - File path
#   $2 - Error message (optional)
#
assert_file_exists() {
    local file="$1"
    local message="${2:-File should exist}"

    if [[ ! -f "$file" ]]; then
        log_json verify "ASSERT FAILED: $message" "{\"file\":\"$file\"}"
        return 1
    fi
    log_json verify "ASSERT PASS: $message"
    return 0
}

# Assert command succeeds.
#
# Args:
#   $@ - Command and arguments
#
assert_command_succeeds() {
    log_json execute "Running: $*"
    if "$@"; then
        log_json verify "Command succeeded: $*"
        return 0
    else
        log_json verify "Command failed: $*" "{\"exit_code\":$?}"
        return 1
    fi
}

# Assert command fails.
#
# Args:
#   $@ - Command and arguments
#
assert_command_fails() {
    log_json execute "Running (expecting failure): $*"
    if "$@"; then
        log_json verify "Command unexpectedly succeeded: $*"
        return 1
    else
        log_json verify "Command failed as expected: $*"
        return 0
    fi
}

# ============================================================================
# Cleanup
# ============================================================================

# Enhanced cleanup that handles TUI state
_test_framework_cleanup() {
    local exit_code=$?

    # Stop any running TUI
    if [[ -n "$_TUI_TMUX_SESSION" ]] || [[ -n "$_TUI_PID" ]]; then
        tui_stop 2>/dev/null || true
    fi

    # Call base library cleanup
    _test_lib_cleanup 2>/dev/null || true
}

trap _test_framework_cleanup EXIT
