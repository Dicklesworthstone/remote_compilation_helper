#!/usr/bin/env bash
# install_prompt_unit_test.sh - Unit-style tests for install.sh prompt logic
# Run from project root: ./scripts/install_prompt_unit_test.sh

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
export PROJECT_ROOT
TEST_DIR=$(mktemp -d)
LOG_FILE="$TEST_DIR/install_prompt_unit.log"

# Structured JSONL logging
# shellcheck disable=SC1091
source "$SCRIPT_DIR/test_lib.sh"
init_test_log "$(basename "${BASH_SOURCE[0]}" .sh)"

TESTS_RUN=0
TESTS_PASSED=0
TESTS_FAILED=0

log() {
    echo "[$(date -Iseconds)] $*" | tee -a "$LOG_FILE"
    log_json execute "$*"
}

pass() {
    TESTS_PASSED=$((TESTS_PASSED + 1))
    log "PASS: $1"
}

fail() {
    TESTS_FAILED=$((TESTS_FAILED + 1))
    log "FAIL: $1"
}

start_test() {
    TESTS_RUN=$((TESTS_RUN + 1))
    log "Test $TESTS_RUN: $1"
}

cleanup() {
    log "Cleaning up test directory: $TEST_DIR"
    rm -rf "$TEST_DIR"
}

trap '_test_lib_cleanup; cleanup' EXIT

log "=== RCH Installer Prompt Unit Tests ==="
log "Project root: $PROJECT_ROOT"
log "Test directory: $TEST_DIR"
log "Log file: $LOG_FILE"

if [[ ! -f "$PROJECT_ROOT/install.sh" ]]; then
    log "ERROR: install.sh not found at $PROJECT_ROOT/install.sh"
    test_fail "install.sh missing"
fi

# Source installer in library mode
export RCH_INSTALLER_LIB=1
# shellcheck disable=SC1090
source "$PROJECT_ROOT/install.sh"

# Override helpers to keep output deterministic
USE_GUM=false
USE_COLOR=false

CONFIRM_CALLED=false
CONFIRM_RESULT=0
INTERACTIVE=true
SERVICE_MANAGER="systemd"
SYSTEM_RCHD_ACTIVE=false

confirm() {
    CONFIRM_CALLED=true
    return "$CONFIRM_RESULT"
}

is_interactive() {
    if [[ "$INTERACTIVE" == "true" ]]; then
        return 0
    fi
    return 1
}

detect_service_manager() {
    if [[ -n "$SERVICE_MANAGER" ]]; then
        echo "$SERVICE_MANAGER"
        return 0
    fi
    return 1
}

systemctl() {
    if [[ "${1:-}" == "is-active" ]] && [[ "${2:-}" == "--quiet" ]] && [[ "${3:-}" == "rchd.service" ]]; then
        [[ "$SYSTEM_RCHD_ACTIVE" == "true" ]]
        return
    fi
    return 1
}

reset_env() {
    MODE="local"
    NO_SERVICE="false"
    EASY_MODE="false"
    YES="false"
    INSTALL_SERVICE="false"
    ENABLE_SERVICE=""
    CONFIRM_CALLED=false
    CONFIRM_RESULT=0
    INTERACTIVE=true
    SERVICE_MANAGER="systemd"
    SYSTEM_RCHD_ACTIVE=false
}

assert_eq() {
    local label="$1"
    local expected="$2"
    local actual="$3"
    if [[ "$expected" == "$actual" ]]; then
        pass "$label"
    else
        fail "$label (expected '$expected', got '$actual')"
    fi
}

assert_contains() {
    local label="$1"
    local haystack="$2"
    local needle="$3"
    if [[ "$haystack" == *"$needle"* ]]; then
        pass "$label"
    else
        fail "$label (missing '$needle')"
    fi
}

run_case() {
    local name="$1"
    local expect_enable="$2"
    local expect_confirm="$3"
    local expect_log="$4"

    start_test "$name"
    local output
    local output_file="$TEST_DIR/run_case_${TESTS_RUN}.output"
    maybe_prompt_service >"$output_file" 2>&1 || true
    output="$(<"$output_file")"

    assert_eq "$name enable" "$expect_enable" "$ENABLE_SERVICE"
    assert_eq "$name confirm_called" "$expect_confirm" "$CONFIRM_CALLED"

    if [[ -n "$expect_log" ]]; then
        assert_contains "$name log" "$output" "$expect_log"
    fi
}

# Case 1: worker mode
reset_env
MODE="worker"
run_case "worker_mode" "false" "false" ""

# Case 2: --no-service
reset_env
NO_SERVICE="true"
run_case "no_service_flag" "false" "false" ""

# Case 3: --install-service explicit opt-in
reset_env
INSTALL_SERVICE="true"
run_case "install_service_opt_in" "true" "false" ""

# Case 4: --install-service + --no-service (no-service wins)
reset_env
INSTALL_SERVICE="true"
NO_SERVICE="true"
run_case "install_service_overridden" "false" "false" ""

# Case 5: --yes
reset_env
YES="true"
run_case "yes_flag" "true" "false" ""

# Case 6: --easy-mode
reset_env
EASY_MODE="true"
run_case "easy_mode" "true" "false" ""

# Case 7: interactive decline
reset_env
CONFIRM_RESULT=1
run_case "interactive_decline" "false" "true" "Skipping background daemon setup"

# Case 8: non-interactive stdin default
reset_env
INTERACTIVE=false
run_case "non_interactive_default" "false" "false" "Non-interactive install without opt-in"

# Case 9: service manager missing
reset_env
SERVICE_MANAGER=""
run_case "no_service_manager" "false" "false" "No supported service manager detected"

# Case 10: service manager missing + explicit opt-in
reset_env
SERVICE_MANAGER=""
INSTALL_SERVICE="true"
run_case "no_service_manager_opt_in" "false" "false" "Background service requested but no supported service manager detected"

# Case 11: an active system-level daemon suppresses easy-mode user service setup
reset_env
EASY_MODE="true"
SYSTEM_RCHD_ACTIVE=true
run_case "system_daemon_suppresses_easy_mode" "false" "false" "System-level rchd.service is active"

# Case 12: easy-mode restart does not address a user daemon on a system-service host
start_test "system_daemon_suppresses_easy_mode_restart"
restart_guard_root="$TEST_DIR/restart-guard"
restart_guard_log="$restart_guard_root/rch.log"
mkdir -p "$restart_guard_root/bin"
cat > "$restart_guard_root/bin/rch" <<'EOF'
#!/usr/bin/env bash
printf '%s\n' "$*" >> "$RCH_STUB_LOG"
EOF
chmod +x "$restart_guard_root/bin/rch"
MODE="local"
INSTALL_DIR="$restart_guard_root/bin"
HOOK_BIN="rch"
SYSTEM_RCHD_ACTIVE=true
unset RCH_SKIP_DAEMON_RESTART
export RCH_STUB_LOG="$restart_guard_log"
restart_output=$(restart_daemon_if_needed 2>&1 || true)
assert_contains "system_daemon restart log" "$restart_output" "skipping user-daemon restart"
if [[ ! -e "$restart_guard_log" ]]; then
    pass "system_daemon avoids rch daemon restart"
else
    fail "system_daemon should not invoke rch daemon restart"
fi

# Case 13: default runtime directory collision
start_test "runtime_dir_collision_uses_private_directory"
runtime_collision_root="$TEST_DIR/runtime-collision"
mkdir -p "$runtime_collision_root"
printf 'occupied\n' > "$runtime_collision_root/rch"
INSTALL_DIR="$TEST_DIR/install-bin"
CONFIG_DIR="$TEST_DIR/config"
RUNTIME_DIR=""
unset RCH_RUNTIME_DIR
runtime_output_file="$TEST_DIR/runtime_collision.output"
TMPDIR="$runtime_collision_root" create_directories >"$runtime_output_file" 2>&1 || true
runtime_output="$(<"$runtime_output_file")"
if [[ -d "$RUNTIME_DIR" && "$RUNTIME_DIR" == "$runtime_collision_root"/rch-runtime.* ]]; then
    pass "runtime_dir_collision_uses_private_directory"
else
    fail "runtime_dir_collision_uses_private_directory (RUNTIME_DIR='$RUNTIME_DIR', output='$runtime_output')"
fi

log "=== Summary ==="
log "Tests run: $TESTS_RUN"
log "Passed:    $TESTS_PASSED"
log "Failed:    $TESTS_FAILED"
log "Log file:  $LOG_FILE"

if [[ $TESTS_FAILED -ne 0 ]]; then
    test_fail "One or more installer prompt unit tests failed"
fi

test_pass
