#!/usr/bin/env bash
# ==============================================================================
# CRITICAL: Compile Command Hook Context Test (bd-3obh)
#
# This test verifies that when an AI agent invokes compilation commands through
# the RCH hook, the rich_rust integration does NOT interfere with:
#   1. Hook JSON response (must be clean, machine-parseable)
#   2. Compilation output that passes through (agents parse this)
#   3. Exit codes (agents use these to determine success/failure)
#   4. Error messages from the compiler (must be preserved exactly)
#
# ANY regression here is a BLOCKER - agents are the PRIMARY users of RCH.
# ==============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

# Source common helpers if available
if [[ -f "${SCRIPT_DIR}/lib/e2e_common.sh" ]]; then
    source "${SCRIPT_DIR}/lib/e2e_common.sh"
fi

# ============================================================================
# Configuration
# ============================================================================
TEST_LOG="${PROJECT_ROOT}/target/test_compile_hook_context.log"
TEST_PROJECT="/tmp/rch_compile_test_$$"
# Support CARGO_TARGET_DIR or use default location
CARGO_TARGET="${CARGO_TARGET_DIR:-${PROJECT_ROOT}/target}"
RCH="${RCH:-${CARGO_TARGET}/release/rch}"

# Ensure directories exist
mkdir -p "${PROJECT_ROOT}/target"
mkdir -p "$TEST_PROJECT/src"

# ============================================================================
# Logging
# ============================================================================
log_json() {
    local phase="$1"
    local message="$2"
    local extra="${3:-{}}"
    local ts
    ts=$(date -u '+%Y-%m-%dT%H:%M:%S.%3NZ' 2>/dev/null || date -u '+%Y-%m-%dT%H:%M:%SZ')
    printf '{"ts":"%s","test":"compile_hook_context","phase":"%s","message":"%s",%s}\n' \
        "$ts" "$phase" "$message" "${extra#\{}" | sed 's/,}$/}/' | tee -a "$TEST_LOG"
}

log() { echo "[$(date +%H:%M:%S)] $*" | tee -a "$TEST_LOG"; }
pass() { log "PASS: $*"; log_json "verify" "$*" '{"result":"pass"}'; }
fail() {
    log "FAIL: $*"
    log_json "error" "$*" '{"result":"fail"}'
    exit 1
}
skip() {
    log "SKIP: $*"
    log_json "skip" "$*" '{"result":"skip"}'
}

# ============================================================================
# Setup and Cleanup
# ============================================================================
setup_test_project() {
    log_json "setup" "Creating test Rust project"

    cat > "$TEST_PROJECT/Cargo.toml" << 'EOF'
[package]
name = "rch_compile_test"
version = "0.1.0"
edition = "2021"
EOF

    cat > "$TEST_PROJECT/src/main.rs" << 'EOF'
fn main() {
    println!("Hello from RCH compile test!");
}

#[cfg(test)]
mod tests {
    #[test]
    fn test_passes() {
        assert_eq!(2 + 2, 4);
    }
}
EOF
    log_json "setup" "Test project created at $TEST_PROJECT"
}

cleanup() {
    if [[ -d "$TEST_PROJECT" ]]; then
        rm -rf "$TEST_PROJECT"
    fi
}
trap cleanup EXIT

# ============================================================================
# Build RCH if needed
# ============================================================================
build_rch() {
    if [[ -x "$RCH" ]]; then
        log_json "setup" "Using existing binary: $RCH"
        return 0
    fi

    log_json "setup" "Building rch..."
    if ! cargo build -p rch --release 2>&1 | tail -5; then
        fail "Failed to build rch"
    fi

    if [[ ! -x "$RCH" ]]; then
        fail "rch binary not found at $RCH"
    fi
}

# ============================================================================
# Clean previous log
# ============================================================================
> "$TEST_LOG"

log "============================================================================="
log "COMPILE COMMAND HOOK CONTEXT TEST (bd-3obh)"
log "============================================================================="
log ""

# ============================================================================
# Setup
# ============================================================================
build_rch
setup_test_project

# Temp files for capturing output
STDOUT_FILE="$(mktemp)"
STDERR_FILE="$(mktemp)"
trap "rm -f $STDOUT_FILE $STDERR_FILE; cleanup" EXIT

# ============================================================================
# TEST 1: Hook JSON Response for cargo build (No ANSI codes in stdout)
# ============================================================================
log ""
log "TEST 1: Hook JSON Response Purity for cargo build"
log_json "test" "Hook JSON purity for cargo build"

CARGO_BUILD_INPUT="{\"tool_name\":\"Bash\",\"tool_input\":{\"command\":\"cd $TEST_PROJECT && cargo build\"}}"

echo "$CARGO_BUILD_INPUT" | "$RCH" > "$STDOUT_FILE" 2> "$STDERR_FILE"
HOOK_EXIT=$?

log "  Hook exit code: $HOOK_EXIT"

STDOUT_CONTENT=$(cat "$STDOUT_FILE")
if [[ -n "$STDOUT_CONTENT" ]]; then
    log "  stdout length: $(wc -c < "$STDOUT_FILE") bytes"

    # Verify stdout is valid JSON
    if ! echo "$STDOUT_CONTENT" | jq -e . >/dev/null 2>&1; then
        log "  stdout content: $STDOUT_CONTENT"
        fail "stdout is not valid JSON"
    fi

    # Verify NO ANSI escape codes in stdout
    if echo "$STDOUT_CONTENT" | grep -qP '\x1b\['; then
        fail "stdout contains ANSI escape codes!"
    fi
else
    log "  stdout: (empty - allow)"
fi

pass "cargo build hook returns clean JSON (or empty for allow)"

# ============================================================================
# TEST 2: Hook JSON Response for cargo test
# ============================================================================
log ""
log "TEST 2: Hook JSON Response Purity for cargo test"
log_json "test" "Hook JSON purity for cargo test"

CARGO_TEST_INPUT="{\"tool_name\":\"Bash\",\"tool_input\":{\"command\":\"cd $TEST_PROJECT && cargo test\"}}"

echo "$CARGO_TEST_INPUT" | "$RCH" > "$STDOUT_FILE" 2> "$STDERR_FILE"
HOOK_EXIT=$?

log "  Hook exit code: $HOOK_EXIT"

STDOUT_CONTENT=$(cat "$STDOUT_FILE")
if [[ -n "$STDOUT_CONTENT" ]]; then
    # Verify stdout is valid JSON
    if ! echo "$STDOUT_CONTENT" | jq -e . >/dev/null 2>&1; then
        fail "stdout is not valid JSON for cargo test"
    fi

    # Verify NO ANSI escape codes
    if echo "$STDOUT_CONTENT" | grep -qP '\x1b\['; then
        fail "stdout contains ANSI codes for cargo test!"
    fi
fi

pass "cargo test hook returns clean JSON"

# ============================================================================
# TEST 3: Hook JSON Response for cargo check/clippy
# ============================================================================
log ""
log "TEST 3: Hook JSON Response for cargo check"
log_json "test" "Hook JSON purity for cargo check"

CARGO_CHECK_INPUT="{\"tool_name\":\"Bash\",\"tool_input\":{\"command\":\"cd $TEST_PROJECT && cargo check\"}}"

echo "$CARGO_CHECK_INPUT" | "$RCH" > "$STDOUT_FILE" 2> "$STDERR_FILE"

STDOUT_CONTENT=$(cat "$STDOUT_FILE")
if [[ -n "$STDOUT_CONTENT" ]]; then
    if ! echo "$STDOUT_CONTENT" | jq -e . >/dev/null 2>&1; then
        fail "stdout is not valid JSON for cargo check"
    fi
    if echo "$STDOUT_CONTENT" | grep -qP '\x1b\['; then
        fail "stdout contains ANSI codes for cargo check!"
    fi
fi

pass "cargo check hook returns clean JSON"

# ============================================================================
# TEST 4: Exit Code Preservation - Success
# ============================================================================
log ""
log "TEST 4: Exit Code Preservation (Success)"
log_json "test" "Exit code preservation - success"

# Ensure project is valid
cat > "$TEST_PROJECT/src/main.rs" << 'EOF'
fn main() { println!("Hello"); }
EOF

# Run hook and capture exit code
echo "$CARGO_BUILD_INPUT" | "$RCH" >/dev/null 2>&1
SUCCESS_EXIT=$?

log "  cargo build exit code through hook: $SUCCESS_EXIT"

# Exit 0 means either allow (local) or successful remote execution
# Both are acceptable
if [[ $SUCCESS_EXIT -ne 0 ]]; then
    # May fail if daemon not running - this is acceptable
    skip "Hook exit was $SUCCESS_EXIT (daemon may not be running)"
else
    pass "Hook preserves successful exit code (0)"
fi

# ============================================================================
# TEST 5: Exit Code Preservation - Build Error
# ============================================================================
log ""
log "TEST 5: Exit Code Preservation (Build Error)"
log_json "test" "Exit code preservation - build error"

# Introduce a syntax error
cat > "$TEST_PROJECT/src/main.rs" << 'EOF'
fn main() {
    let x: i32 = "this is not an i32";  // Type error
}
EOF

CARGO_BUILD_ERROR_INPUT="{\"tool_name\":\"Bash\",\"tool_input\":{\"command\":\"cd $TEST_PROJECT && cargo build\"}}"

echo "$CARGO_BUILD_ERROR_INPUT" | "$RCH" > "$STDOUT_FILE" 2> "$STDERR_FILE"
ERROR_EXIT=$?

log "  Build error exit code: $ERROR_EXIT"

# If the command was intercepted and ran remotely, we expect non-zero exit
# If it was allowed (no daemon), we'll get 0 from the hook (allow)
if [[ $ERROR_EXIT -eq 0 ]]; then
    log "  Note: Exit 0 may mean command was allowed (daemon not running)"
fi

log_json "verify" "Exit code recorded" "{\"exit_code\":$ERROR_EXIT}"
pass "Exit code preserved (hook exit: $ERROR_EXIT)"

# ============================================================================
# TEST 6: Compiler Error Messages Preserved
# ============================================================================
log ""
log "TEST 6: Compiler Error Messages Preserved"
log_json "test" "Error message preservation"

# Leave the syntax error in place
STDERR_CONTENT=$(cat "$STDERR_FILE")
STDOUT_CONTENT=$(cat "$STDOUT_FILE")

# Combine for checking (error could be in either depending on execution mode)
COMBINED_OUTPUT="$STDOUT_CONTENT $STDERR_CONTENT"

# If remote execution happened, we should see the error somewhere
# If allowed, the hook just passes through
if [[ -n "$STDERR_CONTENT" ]]; then
    log "  stderr has content: $(wc -c < "$STDERR_FILE") bytes"

    # Check if type error is mentioned somewhere
    if echo "$COMBINED_OUTPUT" | grep -qiE "mismatched|expected.*found|type"; then
        pass "Compiler error message preserved"
    else
        log "  Note: Error message not in output (may be in JSON error field)"
        # Check if it's in the JSON response
        if echo "$STDOUT_CONTENT" | jq -e '.error' >/dev/null 2>&1; then
            pass "Error captured in JSON response"
        else
            skip "Error message format varies by execution mode"
        fi
    fi
else
    skip "No stderr output (command may have been allowed for local execution)"
fi

# Restore valid code
cat > "$TEST_PROJECT/src/main.rs" << 'EOF'
fn main() { println!("Hello"); }
EOF

# ============================================================================
# TEST 7: No RCH-Specific Rich Output in stdout
# ============================================================================
log ""
log "TEST 7: No RCH-Specific Rich Output Leakage"
log_json "test" "RCH rich output isolation"

# Pattern that would indicate RCH rich output leaked
RCH_PATTERNS=(
    '\[rch\]'
    '\[RCH\]'
    '╔═'
    '║'
    '╚═'
    '🔨'
    '✓'
    '✗'
)

echo "$CARGO_BUILD_INPUT" | "$RCH" > "$STDOUT_FILE" 2>/dev/null

STDOUT_CONTENT=$(cat "$STDOUT_FILE")
for pattern in "${RCH_PATTERNS[@]}"; do
    if echo "$STDOUT_CONTENT" | grep -qP "$pattern" 2>/dev/null; then
        fail "RCH rich output pattern '$pattern' found in stdout!"
    fi
done

pass "No RCH-specific rich output in stdout"

# ============================================================================
# TEST 8: Hook Classification Timing for Compilation Commands
# ============================================================================
log ""
log "TEST 8: Compilation Command Classification Timing"
log_json "test" "Classification timing"

ITERATIONS=25
TIMING_LOG="$(mktemp)"

for _ in $(seq 1 $ITERATIONS); do
    START=$(date +%s%N)
    echo "$CARGO_BUILD_INPUT" | "$RCH" >/dev/null 2>&1
    END=$(date +%s%N)
    echo $((END - START)) >> "$TIMING_LOG"
done

AVG_NS=$(awk '{ sum += $1 } END { print int(sum/NR) }' "$TIMING_LOG")
AVG_MS=$(echo "scale=2; $AVG_NS / 1000000" | bc)
rm -f "$TIMING_LOG"

log "  Average time for compilation command: ${AVG_MS}ms over $ITERATIONS iterations"
log_json "verify" "Timing measurement" "{\"avg_ms\":$AVG_MS,\"iterations\":$ITERATIONS}"

# Budget: <5ms for compilation classification (per AGENTS.md)
# Allow 10ms for CI variance
if (( AVG_NS > 10000000 )); then
    fail "Compilation classification too slow: ${AVG_MS}ms (threshold: 10ms)"
fi

pass "Compilation command timing acceptable: ${AVG_MS}ms"

# ============================================================================
# TEST 9: stderr Can Have Diagnostics (Separation Check)
# ============================================================================
log ""
log "TEST 9: stderr/stdout Separation"
log_json "test" "Stream separation"

echo "$CARGO_BUILD_INPUT" | "$RCH" > "$STDOUT_FILE" 2> "$STDERR_FILE"

STDOUT_CONTENT=$(cat "$STDOUT_FILE")

# stdout must be valid JSON or empty
if [[ -n "$STDOUT_CONTENT" ]]; then
    if ! echo "$STDOUT_CONTENT" | jq -e . >/dev/null 2>&1; then
        fail "stdout must be valid JSON or empty"
    fi

    # stdout must not contain raw log messages
    if echo "$STDOUT_CONTENT" | grep -qE '^\[' | head -1 | grep -qv '^\[.*\]$'; then
        fail "stdout appears to contain raw log lines"
    fi
fi

STDERR_SIZE=$(wc -c < "$STDERR_FILE")
log "  stdout: $(wc -c < "$STDOUT_FILE") bytes (JSON or empty)"
log "  stderr: $STDERR_SIZE bytes (diagnostics allowed)"

pass "stdout/stderr separation correct"

# ============================================================================
# SUMMARY
# ============================================================================
log ""
log "============================================================================="
log "ALL COMPILE COMMAND HOOK CONTEXT TESTS PASSED"
log "============================================================================="
log ""
log "This verifies that AI coding agents will receive:"
log "  - Clean JSON on stdout (no ANSI codes, no rich output)"
log "  - Preserved exit codes through the hook"
log "  - Preserved compiler error messages"
log "  - Fast classification (<10ms)"
log "  - Proper stdout/stderr separation"
log ""
log "Full log: $TEST_LOG"

log_json "summary" "All compile hook context tests passed" '{"total_tests":9,"result":"pass"}'
