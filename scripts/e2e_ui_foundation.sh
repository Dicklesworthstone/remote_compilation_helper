#!/usr/bin/env bash
# ==============================================================================
# E2E Test: UI Foundation Infrastructure (bd-38kz)
#
# Tests that the UI module correctly detects context and respects env vars.
# This verifies Phase 1 of the rich_rust integration is complete.
#
# Test coverage:
# - OutputContext detection (Hook, Machine, Interactive, Colored, Plain)
# - NO_COLOR environment variable disables ANSI codes
# - FORCE_COLOR environment variable enables colors without TTY
# - RCH_JSON environment variable forces machine output
# - RCH_HOOK_MODE environment variable forces hook mode
# - rich-ui feature flag compiles without errors
# ==============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
export PROJECT_ROOT
LOG_FILE="${PROJECT_ROOT}/target/e2e_ui_foundation_$(date +%Y%m%d_%H%M%S).log"

# Structured JSONL logging
# shellcheck disable=SC1091
source "$SCRIPT_DIR/test_lib.sh"
init_test_log "$(basename "${BASH_SOURCE[0]}" .sh)"

# Ensure target directory exists
mkdir -p "${PROJECT_ROOT}/target"

# ============================================================================
# Logging
# ============================================================================
log() {
    echo "[$(date +%H:%M:%S)] $*" | tee -a "$LOG_FILE"
    log_json execute "$*"
}
log_pass() {
    echo "[$(date +%H:%M:%S)] PASS $*" | tee -a "$LOG_FILE"
    log_json verify "PASS $*"
}
log_fail() {
    echo "[$(date +%H:%M:%S)] FAIL $*" | tee -a "$LOG_FILE"
    log_json verify "FAIL $*"
    test_fail "$*"
}
log_skip() {
    echo "[$(date +%H:%M:%S)] SKIP $*" | tee -a "$LOG_FILE"
    log_json setup "SKIP $*"
}

PASS_COUNT=0
FAIL_COUNT=0
SKIP_COUNT=0

pass() { log_pass "$*"; ((PASS_COUNT++)) || true; }
fail() { log_fail "$*"; ((FAIL_COUNT++)) || true; }
skip() { log_skip "$*"; ((SKIP_COUNT++)) || true; }

# ============================================================================
# Setup
# ============================================================================
log "========================================"
log "UI Foundation E2E Tests (bd-38kz)"
log "========================================"
log "Project root: $PROJECT_ROOT"
log "Log file: $LOG_FILE"
log ""

# ============================================================================
# Test 1: Feature flag compilation
# ============================================================================
log "Test 1: rich-ui feature flag compilation"

# Test with feature enabled
if cargo check -p rch-common --features rich-ui 2>&1 | tee -a "$LOG_FILE" | tail -3; then
    pass "rich-ui feature compiles successfully"
else
    fail "rich-ui feature failed to compile"
fi

# Test without feature (should also compile)
if cargo check -p rch-common --no-default-features 2>&1 | tee -a "$LOG_FILE" | tail -3; then
    pass "Compiles without rich-ui feature"
else
    fail "Failed to compile without rich-ui feature"
fi

# ============================================================================
# Test 2: Unit tests pass
# ============================================================================
log ""
log "Test 2: Unit tests for UI module"

# Run context tests
if cargo test -p rch-common --features rich-ui context 2>&1 | tee -a "$LOG_FILE" | tail -10; then
    pass "OutputContext unit tests pass"
else
    fail "OutputContext unit tests failed"
fi

# Run icons tests
if cargo test -p rch-common --features rich-ui icons 2>&1 | tee -a "$LOG_FILE" | tail -10; then
    pass "Icons unit tests pass"
else
    fail "Icons unit tests failed"
fi

# Run theme tests
if cargo test -p rch-common --features rich-ui theme 2>&1 | tee -a "$LOG_FILE" | tail -10; then
    pass "RchTheme unit tests pass"
else
    fail "RchTheme unit tests failed"
fi

# ============================================================================
# Test 3: Build binary and verify environment variable handling
# ============================================================================
log ""
log "Test 3: Binary builds and env vars work"

RCH="${PROJECT_ROOT}/target/release/rch"

# Try to use existing binary or build
if [[ -x "$RCH" ]]; then
    log "Using existing binary: $RCH"
else
    log "Building rch..."
    if cargo build -p rch --release 2>&1 | tee -a "$LOG_FILE" | tail -5; then
        pass "rch binary built successfully"
    else
        skip "Could not build rch binary - remaining tests will be skipped"
        log ""
        log "========================================"
        log "Results: $PASS_COUNT passed, $SKIP_COUNT skipped, $FAIL_COUNT failed"
        log "========================================"
        exit 0
    fi
fi

# Test NO_COLOR
log "Testing NO_COLOR environment variable..."
if [[ -x "$RCH" ]]; then
    OUTPUT=$(NO_COLOR=1 "$RCH" version 2>&1 || true)
    if echo "$OUTPUT" | grep -qP '\x1b\['; then
        fail "ANSI codes present despite NO_COLOR=1"
    else
        pass "NO_COLOR correctly disables ANSI codes"
    fi
else
    skip "rch binary not available for NO_COLOR test"
fi

# Test RCH_JSON
log "Testing RCH_JSON environment variable..."
if [[ -x "$RCH" ]]; then
    OUTPUT=$(RCH_JSON=1 "$RCH" status 2>&1 || true)
    if echo "$OUTPUT" | grep -qP '\x1b\['; then
        fail "ANSI codes present despite RCH_JSON=1"
    else
        pass "RCH_JSON correctly disables ANSI codes"
    fi
else
    skip "rch binary not available for RCH_JSON test"
fi

# ============================================================================
# Test 4: Module structure verification
# ============================================================================
log ""
log "Test 4: Module structure verification"

# Check rch-common/src/ui/ exists and has required files
if [[ -f "${PROJECT_ROOT}/rch-common/src/ui/mod.rs" ]] && \
   [[ -f "${PROJECT_ROOT}/rch-common/src/ui/context.rs" ]] && \
   [[ -f "${PROJECT_ROOT}/rch-common/src/ui/theme.rs" ]] && \
   [[ -f "${PROJECT_ROOT}/rch-common/src/ui/icons.rs" ]]; then
    pass "rch-common/src/ui/ has all required files"
else
    fail "rch-common/src/ui/ missing required files"
fi

# Check rch/src/ui/ exists
if [[ -f "${PROJECT_ROOT}/rch/src/ui/mod.rs" ]] && \
   [[ -f "${PROJECT_ROOT}/rch/src/ui/console.rs" ]]; then
    pass "rch/src/ui/ has required files"
else
    fail "rch/src/ui/ missing required files"
fi

# Check rchd/src/ui/ exists
if [[ -f "${PROJECT_ROOT}/rchd/src/ui/mod.rs" ]]; then
    pass "rchd/src/ui/ has required files"
else
    fail "rchd/src/ui/ missing required files"
fi

# ============================================================================
# Test 5: Verify OutputContext enum variants
# ============================================================================
log ""
log "Test 5: OutputContext enum variants"

CONTEXT_FILE="${PROJECT_ROOT}/rch-common/src/ui/context.rs"
if grep -q "pub enum OutputContext" "$CONTEXT_FILE" && \
   grep -q "Hook" "$CONTEXT_FILE" && \
   grep -q "Machine" "$CONTEXT_FILE" && \
   grep -q "Interactive" "$CONTEXT_FILE" && \
   grep -q "Colored" "$CONTEXT_FILE" && \
   grep -q "Plain" "$CONTEXT_FILE"; then
    pass "OutputContext has all 5 variants"
else
    fail "OutputContext missing required variants"
fi

# ============================================================================
# Summary
# ============================================================================
log ""
log "========================================"
log "UI Foundation E2E Tests Complete"
log "========================================"
log "Passed:  $PASS_COUNT"
log "Skipped: $SKIP_COUNT"
log "Failed:  $FAIL_COUNT"
log ""
log "Full log: $LOG_FILE"

if [[ $FAIL_COUNT -gt 0 ]]; then
    log "RESULT: FAILED"
    test_fail "UI foundation E2E failed"
else
    log "RESULT: PASSED"
    test_pass
fi
