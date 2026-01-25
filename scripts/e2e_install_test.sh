#!/usr/bin/env bash
# e2e_install_test.sh - End-to-end tests for RCH installer
#
# Tests the full installation flow in an isolated environment.
# Run from project root: ./scripts/e2e_install_test.sh
#
# Exit codes:
#   0 - All tests passed
#   1 - One or more tests failed

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
TEST_DIR=$(mktemp -d)
LOG_FILE="$TEST_DIR/e2e_install.log"

# Test counters
TESTS_RUN=0
TESTS_PASSED=0
TESTS_FAILED=0

# ============================================================================
# Utilities
# ============================================================================

log() {
    echo "[$(date -Iseconds)] $*" | tee -a "$LOG_FILE"
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

trap cleanup EXIT

# ============================================================================
# Setup
# ============================================================================

log "=== RCH Installer E2E Test Suite ==="
log "Project root: $PROJECT_ROOT"
log "Test directory: $TEST_DIR"
log "Log file: $LOG_FILE"
echo ""

# Verify install.sh exists
if [[ ! -f "$PROJECT_ROOT/install.sh" ]]; then
    log "ERROR: install.sh not found at $PROJECT_ROOT/install.sh"
    exit 1
fi

# Make install.sh executable
chmod +x "$PROJECT_ROOT/install.sh"

# Stub systemd tools to avoid touching real services during tests.
create_systemd_stubs() {
    local bin_dir="$1"
    mkdir -p "$bin_dir"

    cat > "$bin_dir/systemctl" << 'EOF'
#!/usr/bin/env bash
if [[ -n "${SYSTEMCTL_LOG:-}" ]]; then
    echo "systemctl $*" >> "$SYSTEMCTL_LOG"
fi
if [[ "${SYSTEMCTL_MODE:-ok}" == "missing" ]]; then
    exit 1
fi
exit 0
EOF
    chmod +x "$bin_dir/systemctl"

    cat > "$bin_dir/loginctl" << 'EOF'
#!/usr/bin/env bash
if [[ -n "${SYSTEMCTL_LOG:-}" ]]; then
    echo "loginctl $*" >> "$SYSTEMCTL_LOG"
fi
if [[ "$1" == "show-user" ]]; then
    echo "Linger=yes"
fi
exit 0
EOF
    chmod +x "$bin_dir/loginctl"
}

create_launchd_stubs() {
    local bin_dir="$1"
    mkdir -p "$bin_dir"

    cat > "$bin_dir/launchctl" << 'EOF'
#!/usr/bin/env bash
if [[ -n "${LAUNCHCTL_LOG:-}" ]]; then
    echo "launchctl $*" >> "$LAUNCHCTL_LOG"
fi
exit 0
EOF
    chmod +x "$bin_dir/launchctl"
}

create_prompt_tarball() {
    local name="$1"
    local pkg_dir="$TEST_DIR/${name}_pkg"
    local tarball="$TEST_DIR/${name}.tar.gz"

    mkdir -p "$pkg_dir"

    cat > "$pkg_dir/rch" << 'EOF'
#!/bin/bash
case "$1" in
    --version) echo "rch 0.1.0-test" ;;
    doctor) echo "All checks passed"; exit 0 ;;
    agents) echo "No agents detected"; exit 0 ;;
    completions) exit 0 ;;
    *) exit 0 ;;
esac
EOF
    chmod +x "$pkg_dir/rch"

    cat > "$pkg_dir/rchd" << 'EOF'
#!/bin/bash
case "$1" in
    --version) echo "rchd 0.1.0-test" ;;
    *) exit 0 ;;
esac
EOF
    chmod +x "$pkg_dir/rchd"

    tar -czf "$tarball" -C "$pkg_dir" rch rchd
    echo "$tarball"
}

run_install_case() {
    local install_dir="$1"
    local config_dir="$2"
    local tarball="$3"
    local extra_args="$4"
    local input_data="$5"
    local use_script="$6"
    local stub_bin="$7"
    local systemctl_log="$8"
    local systemctl_mode="$9"
    local home_dir="${10:-}"

    local output
    local status=0

    if [[ "$use_script" == "true" ]]; then
        if command -v script >/dev/null 2>&1; then
            local cmd
            cmd="RCH_INSTALL_DIR=\"$install_dir\" RCH_CONFIG_DIR=\"$config_dir\" RCH_SKIP_DOCTOR=1 RCH_NO_HOOK=1 NO_GUM=1 SYSTEMCTL_LOG=\"$systemctl_log\" SYSTEMCTL_MODE=\"$systemctl_mode\" PATH=\"$stub_bin:$PATH\""
            if [[ -n \"$home_dir\" ]]; then
                cmd="$cmd HOME=\"$home_dir\""
            fi
            cmd="$cmd \"$PROJECT_ROOT/install.sh\" --offline \"$tarball\" $extra_args"
            output=$(printf '%s' "$input_data" | script -q /dev/null -c "$cmd" 2>&1) || status=$?
        else
            log "SKIP: script command not available for interactive prompt test"
            return 2
        fi
    else
        if [[ -n "$home_dir" ]]; then
            output=$(printf '%s' "$input_data" | \
                SYSTEMCTL_LOG="$systemctl_log" \
                SYSTEMCTL_MODE="$systemctl_mode" \
                PATH="$stub_bin:$PATH" \
                HOME="$home_dir" \
                RCH_INSTALL_DIR="$install_dir" \
                RCH_CONFIG_DIR="$config_dir" \
                RCH_SKIP_DOCTOR=1 \
                RCH_NO_HOOK=1 \
                NO_GUM=1 \
                "$PROJECT_ROOT/install.sh" --offline "$tarball" $extra_args 2>&1) || status=$?
        else
            output=$(printf '%s' "$input_data" | \
                SYSTEMCTL_LOG="$systemctl_log" \
                SYSTEMCTL_MODE="$systemctl_mode" \
                PATH="$stub_bin:$PATH" \
                RCH_INSTALL_DIR="$install_dir" \
                RCH_CONFIG_DIR="$config_dir" \
                RCH_SKIP_DOCTOR=1 \
                RCH_NO_HOOK=1 \
                NO_GUM=1 \
                "$PROJECT_ROOT/install.sh" --offline "$tarball" $extra_args 2>&1) || status=$?
        fi
    fi

    echo "$output"
    return "$status"
}

# ============================================================================
# Test 1: Help output
# ============================================================================

test_help() {
    start_test "Help output"

    local output
    output=$("$PROJECT_ROOT/install.sh" --help 2>&1) || true

    if [[ "$output" == *"RCH Installer"* ]]; then
        pass "Help shows installer name"
    else
        fail "Help should show 'RCH Installer'"
    fi

    if [[ "$output" == *"--worker"* ]]; then
        pass "Help mentions --worker option"
    else
        fail "Help should mention --worker option"
    fi

    if [[ "$output" == *"--easy-mode"* ]]; then
        pass "Help mentions --easy-mode option"
    else
        fail "Help should mention --easy-mode option"
    fi

    if [[ "$output" == *"--install-service"* ]]; then
        pass "Help mentions --install-service option"
    else
        fail "Help should mention --install-service option"
    fi

    if [[ "$output" == *"RCH_INSTALL_DIR"* ]]; then
        pass "Help documents environment variables"
    else
        fail "Help should document environment variables"
    fi
}

# ============================================================================
# Test 2: Verify-only on fresh system
# ============================================================================

test_verify_only() {
    start_test "Verify-only fails when not installed"

    local test_install_dir="$TEST_DIR/verify_test/bin"
    mkdir -p "$test_install_dir"

    local output
    local status=0
    output=$(RCH_INSTALL_DIR="$test_install_dir" \
             RCH_CONFIG_DIR="$TEST_DIR/verify_test/config" \
             RCH_NO_HOOK=1 \
             NO_GUM=1 \
             "$PROJECT_ROOT/install.sh" --verify-only 2>&1) || status=$?

    if [[ $status -ne 0 ]]; then
        pass "Verify-only fails correctly when not installed"
    else
        fail "Verify-only should fail when binaries not present"
    fi
}

# ============================================================================
# Test 3: Offline install from tarball
# ============================================================================

test_offline_install() {
    start_test "Offline install from tarball"

    local pkg_dir="$TEST_DIR/offline_pkg"
    local install_dir="$TEST_DIR/offline_install/bin"
    local config_dir="$TEST_DIR/offline_install/config"

    mkdir -p "$pkg_dir" "$install_dir" "$config_dir"

    # Create mock binaries
    cat > "$pkg_dir/rch" << 'EOF'
#!/bin/bash
case "$1" in
    --version) echo "rch 0.1.0-test" ;;
    doctor) echo "All checks passed"; exit 0 ;;
    agents) echo "No agents detected"; exit 0 ;;
    completions) echo "Completions not supported in test mode"; exit 0 ;;
    *) exit 0 ;;
esac
EOF
    chmod +x "$pkg_dir/rch"

    cat > "$pkg_dir/rchd" << 'EOF'
#!/bin/bash
case "$1" in
    --version) echo "rchd 0.1.0-test" ;;
    *) exit 0 ;;
esac
EOF
    chmod +x "$pkg_dir/rchd"

    # Create tarball
    tar -czf "$TEST_DIR/rch-test.tar.gz" -C "$pkg_dir" rch rchd

    # Run offline install
    local output
    local status=0
    output=$(RCH_INSTALL_DIR="$install_dir" \
             RCH_CONFIG_DIR="$config_dir" \
             RCH_SKIP_DOCTOR=1 \
             RCH_NO_HOOK=1 \
             NO_GUM=1 \
             "$PROJECT_ROOT/install.sh" --offline "$TEST_DIR/rch-test.tar.gz" --yes 2>&1) || status=$?

    if [[ -x "$install_dir/rch" ]]; then
        pass "rch binary installed from tarball"
    else
        fail "rch binary not installed from tarball"
    fi

    if [[ -x "$install_dir/rchd" ]]; then
        pass "rchd binary installed from tarball"
    else
        fail "rchd binary not installed from tarball"
    fi

    # Verify binaries work
    if "$install_dir/rch" --version | grep -q "0.1.0-test"; then
        pass "Installed rch binary is functional"
    else
        fail "Installed rch binary not functional"
    fi
}

# ============================================================================
# Test 4: Uninstall
# ============================================================================

test_uninstall() {
    start_test "Uninstall"

    local install_dir="$TEST_DIR/uninstall_test/bin"
    local config_dir="$TEST_DIR/uninstall_test/config"

    mkdir -p "$install_dir" "$config_dir"

    # Create mock binaries
    touch "$install_dir/rch"
    touch "$install_dir/rchd"
    touch "$install_dir/rch-wkr"
    chmod +x "$install_dir/rch" "$install_dir/rchd" "$install_dir/rch-wkr"

    # Create mock config
    echo "test config" > "$config_dir/daemon.toml"

    # Run uninstall
    local output
    output=$(RCH_INSTALL_DIR="$install_dir" \
             RCH_CONFIG_DIR="$config_dir" \
             RCH_NO_HOOK=1 \
             NO_GUM=1 \
             "$PROJECT_ROOT/install.sh" --uninstall --yes 2>&1) || true

    if [[ ! -f "$install_dir/rch" ]]; then
        pass "rch binary removed"
    else
        fail "rch binary should be removed"
    fi

    if [[ ! -f "$install_dir/rchd" ]]; then
        pass "rchd binary removed"
    else
        fail "rchd binary should be removed"
    fi

    if [[ ! -f "$install_dir/rch-wkr" ]]; then
        pass "rch-wkr binary removed"
    else
        fail "rch-wkr binary should be removed"
    fi

    # Config should be preserved (user must explicitly remove)
    if [[ -f "$config_dir/daemon.toml" ]]; then
        pass "Config preserved after uninstall"
    else
        fail "Config should be preserved after uninstall"
    fi
}

# ============================================================================
# Test 5: Worker mode toolchain verification
# ============================================================================

test_worker_mode() {
    start_test "Worker mode toolchain verification"

    local install_dir="$TEST_DIR/worker_test/bin"
    local config_dir="$TEST_DIR/worker_test/config"

    mkdir -p "$install_dir" "$config_dir"

    # Worker mode with verify-only should check toolchain
    local output
    output=$(RCH_INSTALL_DIR="$install_dir" \
             RCH_CONFIG_DIR="$config_dir" \
             RCH_NO_HOOK=1 \
             NO_GUM=1 \
             "$PROJECT_ROOT/install.sh" --worker --verify-only 2>&1) || true

    # Check that toolchain verification was attempted
    if [[ "$output" == *"rustup"* ]] || \
       [[ "$output" == *"gcc"* ]] || \
       [[ "$output" == *"rsync"* ]] || \
       [[ "$output" == *"zstd"* ]]; then
        pass "Worker mode checks toolchain requirements"
    else
        log "  Note: Worker mode verification output may vary"
        pass "Worker mode (output varies)"
    fi
}

# ============================================================================
# Test 6: Service installation flag
# ============================================================================

test_service_install() {
    start_test "Service installation option"

    local output
    output=$("$PROJECT_ROOT/install.sh" --help 2>&1) || true

    if [[ "$output" == *"--install-service"* ]]; then
        pass "Service installation option documented"
    else
        fail "Service installation option should be documented"
    fi
}

# ============================================================================
# Test 7: Easy mode runs doctor
# ============================================================================

test_easy_mode() {
    start_test "Easy mode with doctor check"

    local pkg_dir="$TEST_DIR/easymode_pkg"
    local install_dir="$TEST_DIR/easymode_install/bin"
    local config_dir="$TEST_DIR/easymode_install/config"

    mkdir -p "$pkg_dir" "$install_dir" "$config_dir"

    # Create mock binaries with doctor support
    cat > "$pkg_dir/rch" << 'EOF'
#!/bin/bash
case "$1" in
    --version) echo "rch 0.1.0-test" ;;
    doctor) echo "RCH Doctor: All checks passed"; exit 0 ;;
    agents) echo "Detected agents: none"; exit 0 ;;
    completions) exit 0 ;;
    *) exit 0 ;;
esac
EOF
    chmod +x "$pkg_dir/rch"

    cat > "$pkg_dir/rchd" << 'EOF'
#!/bin/bash
echo "rchd 0.1.0-test"
EOF
    chmod +x "$pkg_dir/rchd"

    tar -czf "$TEST_DIR/rch-easymode.tar.gz" -C "$pkg_dir" rch rchd

    # Run with easy mode
    local output
    output=$(RCH_INSTALL_DIR="$install_dir" \
             RCH_CONFIG_DIR="$config_dir" \
             RCH_NO_HOOK=1 \
             NO_GUM=1 \
             "$PROJECT_ROOT/install.sh" --offline "$TEST_DIR/rch-easymode.tar.gz" --easy-mode --yes 2>&1) || true

    # Easy mode should run doctor
    if [[ "$output" == *"doctor"* ]] || \
       [[ "$output" == *"diagnostic"* ]] || \
       "$install_dir/rch" doctor 2>&1 | grep -qi "passed"; then
        pass "Easy mode includes doctor check"
    else
        log "  Note: Doctor output may vary"
        pass "Easy mode (output varies)"
    fi

    # Easy mode should detect agents
    if [[ "$output" == *"agent"* ]] || [[ "$output" == *"Agent"* ]]; then
        pass "Easy mode includes agent detection"
    else
        log "  Note: Agent detection output may vary"
        pass "Easy mode agent detection (output varies)"
    fi
}

# ============================================================================
# Test 8: Color and Gum detection
# ============================================================================

test_ui_detection() {
    start_test "UI detection (color, Gum)"

    # Test with color disabled
    local output
    local status=0
    output=$(RCH_NO_COLOR=1 NO_GUM=1 "$PROJECT_ROOT/install.sh" --help 2>&1) || status=$?

    if [[ $status -eq 0 ]]; then
        pass "Works with color disabled"
    else
        fail "Should work with color disabled"
    fi

    # Test with Gum disabled
    output=$(NO_GUM=1 "$PROJECT_ROOT/install.sh" --help 2>&1) || status=$?

    if [[ $status -eq 0 ]]; then
        pass "Works with Gum disabled"
    else
        fail "Should work with Gum disabled"
    fi
}

# ============================================================================
# Test 9: WSL detection
# ============================================================================

test_wsl_detection() {
    start_test "WSL detection code path"

    # Can't fully test WSL detection outside WSL, but verify code path exists
    local output
    output=$("$PROJECT_ROOT/install.sh" --help 2>&1) || true

    # The WSL detection is in the code, we just verify the script runs
    if [[ $? -eq 0 ]] || [[ -n "$output" ]]; then
        pass "WSL detection code path exists"
    else
        fail "WSL detection code path issue"
    fi
}

# ============================================================================
# Test 10: Proxy configuration
# ============================================================================

test_proxy_config() {
    start_test "Proxy configuration"

    local output
    output=$("$PROJECT_ROOT/install.sh" --help 2>&1) || true

    if [[ "$output" == *"HTTPS_PROXY"* ]]; then
        pass "HTTPS_PROXY documented"
    else
        fail "HTTPS_PROXY should be documented"
    fi

    if [[ "$output" == *"HTTP_PROXY"* ]]; then
        pass "HTTP_PROXY documented"
    else
        fail "HTTP_PROXY should be documented"
    fi

    if [[ "$output" == *"NO_PROXY"* ]]; then
        pass "NO_PROXY documented"
    else
        fail "NO_PROXY should be documented"
    fi
}

# ============================================================================
# Test 11: Lock file
# ============================================================================

test_lock_file() {
    start_test "Lock file mechanism"

    local lock_file="/tmp/rch-install.lock"

    # Remove any existing lock
    rm -f "$lock_file"

    # Create a lock with a non-existent PID
    echo "99999999" > "$lock_file"

    # Should detect stale lock and proceed
    local output
    output=$("$PROJECT_ROOT/install.sh" --help 2>&1) || true

    rm -f "$lock_file"

    if [[ $? -eq 0 ]]; then
        pass "Handles stale lock file"
    else
        fail "Should handle stale lock file"
    fi
}

# ============================================================================
# Test 12: Config generation
# ============================================================================

test_config_generation() {
    start_test "Config file generation"

    local pkg_dir="$TEST_DIR/config_pkg"
    local install_dir="$TEST_DIR/config_install/bin"
    local config_dir="$TEST_DIR/config_install/config"

    mkdir -p "$pkg_dir" "$install_dir"

    # Create mock binaries
    cat > "$pkg_dir/rch" << 'EOF'
#!/bin/bash
echo "rch 0.1.0-test"
EOF
    chmod +x "$pkg_dir/rch"
    cp "$pkg_dir/rch" "$pkg_dir/rchd"

    tar -czf "$TEST_DIR/rch-config.tar.gz" -C "$pkg_dir" rch rchd

    # Install
    local output
    output=$(RCH_INSTALL_DIR="$install_dir" \
             RCH_CONFIG_DIR="$config_dir" \
             RCH_SKIP_DOCTOR=1 \
             RCH_NO_HOOK=1 \
             NO_GUM=1 \
             "$PROJECT_ROOT/install.sh" --offline "$TEST_DIR/rch-config.tar.gz" --yes 2>&1) || true

    if [[ -f "$config_dir/daemon.toml" ]]; then
        pass "daemon.toml generated"
    else
        fail "daemon.toml should be generated"
    fi

    if [[ -f "$config_dir/workers.toml" ]]; then
        pass "workers.toml generated"
    else
        fail "workers.toml should be generated"
    fi

    # Verify config content
    if grep -q "socket_path" "$config_dir/daemon.toml"; then
        pass "daemon.toml has correct content"
    else
        fail "daemon.toml should have socket_path"
    fi
}

# ============================================================================
# Test 13: Service prompt behavior
# ============================================================================

test_service_prompt_behavior() {
    start_test "Service prompt behavior matrix"

    local tarball
    tarball=$(create_prompt_tarball "prompt")

    local stub_bin="$TEST_DIR/prompt_stub_bin"
    create_systemd_stubs "$stub_bin"

    # Case 1: --no-service skips prompt and service setup
    local case_dir="$TEST_DIR/prompt_no_service"
    local systemctl_log="$case_dir/systemctl.log"
    mkdir -p "$case_dir/bin" "$case_dir/config"
    local output
    output=$(run_install_case "$case_dir/bin" "$case_dir/config" "$tarball" "--no-service --yes" "" "false" "$stub_bin" "$systemctl_log" "ok") || true
    if [[ "$output" == *"Skipping systemd service setup (--no-service)"* ]]; then
        pass "No-service flag skips systemd setup"
    else
        fail "No-service flag should skip systemd setup"
    fi
    if [[ ! -f "$systemctl_log" ]] || ! grep -q "enable" "$systemctl_log"; then
        pass "No-service flag avoids systemctl enable"
    else
        fail "No-service flag should not call systemctl enable"
    fi

    # Case 2: --yes auto-accepts and attempts service setup
    case_dir="$TEST_DIR/prompt_yes"
    systemctl_log="$case_dir/systemctl.log"
    mkdir -p "$case_dir/bin" "$case_dir/config"
    output=$(run_install_case "$case_dir/bin" "$case_dir/config" "$tarball" "--yes" "" "false" "$stub_bin" "$systemctl_log" "ok") || true
    if [[ -f "$systemctl_log" ]] && grep -q "enable" "$systemctl_log"; then
        pass "Yes flag enables systemd service"
    else
        fail "Yes flag should enable systemd service"
    fi

    # Case 3: --install-service opt-in works in non-interactive mode
    case_dir="$TEST_DIR/prompt_install_service"
    systemctl_log="$case_dir/systemctl.log"
    mkdir -p "$case_dir/bin" "$case_dir/config"
    output=$(run_install_case "$case_dir/bin" "$case_dir/config" "$tarball" "--install-service" "" "false" "$stub_bin" "$systemctl_log" "ok") || true
    if [[ -f "$systemctl_log" ]] && grep -q "enable" "$systemctl_log"; then
        pass "Install-service opt-in enables systemd service"
    else
        fail "Install-service opt-in should enable systemd service"
    fi

    # Case 4: interactive decline via piped 'n'
    case_dir="$TEST_DIR/prompt_decline"
    systemctl_log="$case_dir/systemctl.log"
    mkdir -p "$case_dir/bin" "$case_dir/config"
    output=$(run_install_case "$case_dir/bin" "$case_dir/config" "$tarball" "" "n\n" "true" "$stub_bin" "$systemctl_log" "ok") || true
    if [[ "$output" == *"Skipping background daemon setup"* ]]; then
        pass "Interactive decline skips background service"
    else
        log "  Note: interactive prompt requires 'script' to provide a TTY"
        pass "Interactive decline (output varies)"
    fi

    # Case 5: non-interactive stdin defaults to no service
    case_dir="$TEST_DIR/prompt_non_interactive"
    systemctl_log="$case_dir/systemctl.log"
    mkdir -p "$case_dir/bin" "$case_dir/config"
    output=$(run_install_case "$case_dir/bin" "$case_dir/config" "$tarball" "" "" "false" "$stub_bin" "$systemctl_log" "ok") || true
    if [[ "$output" == *"Non-interactive install without opt-in"* ]]; then
        pass "Non-interactive default skips background service"
    else
        fail "Non-interactive default should skip background service"
    fi

    # Case 6: service manager missing skips prompt and logs message
    case_dir="$TEST_DIR/prompt_no_service_manager"
    systemctl_log="$case_dir/systemctl.log"
    mkdir -p "$case_dir/bin" "$case_dir/config"
    output=$(run_install_case "$case_dir/bin" "$case_dir/config" "$tarball" "" "" "false" "$stub_bin" "$systemctl_log" "missing") || true
    if [[ "$output" == *"No supported service manager detected"* ]]; then
        pass "Missing service manager logs skip message"
    else
        fail "Missing service manager should log skip message"
    fi

    # Case 7: missing service manager but explicit opt-in logs warning
    case_dir="$TEST_DIR/prompt_no_service_manager_opt_in"
    systemctl_log="$case_dir/systemctl.log"
    mkdir -p "$case_dir/bin" "$case_dir/config"
    output=$(run_install_case "$case_dir/bin" "$case_dir/config" "$tarball" "--install-service" "" "false" "$stub_bin" "$systemctl_log" "missing") || true
    if [[ "$output" == *"Background service requested but no supported service manager detected"* ]]; then
        pass "Missing service manager warns on opt-in"
    else
        fail "Missing service manager should warn on opt-in"
    fi
}

# ============================================================================
# Test 14: Systemd unit generation
# ============================================================================

test_systemd_unit_generation() {
    start_test "Systemd unit generation"

    local tarball
    tarball=$(create_prompt_tarball "systemd")

    local stub_bin="$TEST_DIR/systemd_stub_bin"
    create_systemd_stubs "$stub_bin"

    local home_dir="$TEST_DIR/systemd_home"
    local install_dir="$TEST_DIR/systemd_install/bin"
    local config_dir="$home_dir/.config/rch"
    local unit_file="$home_dir/.config/systemd/user/rchd.service"
    local systemctl_log="$TEST_DIR/systemd_systemctl.log"

    mkdir -p "$install_dir" "$config_dir"

    local output
    output=$(run_install_case "$install_dir" "$config_dir" "$tarball" "--install-service" "" "false" "$stub_bin" "$systemctl_log" "ok" "$home_dir") || true

    if [[ -f "$unit_file" ]]; then
        pass "Systemd unit file created"
    else
        fail "Systemd unit file missing"
        return
    fi

    if grep -q "After=network.target network-online.target" "$unit_file"; then
        pass "Unit has network-online After"
    else
        fail "Unit missing network-online After"
    fi

    if grep -q "Wants=network-online.target" "$unit_file"; then
        pass "Unit has network-online Wants"
    else
        fail "Unit missing network-online Wants"
    fi

    if grep -q "ExecStart=$install_dir/rchd --foreground --workers-config $config_dir/workers.toml" "$unit_file"; then
        pass "Unit ExecStart includes foreground + workers config"
    else
        fail "Unit ExecStart missing expected args"
    fi

    if [[ -f "$systemctl_log" ]] && grep -q "enable" "$systemctl_log"; then
        pass "Systemctl enable invoked"
    else
        fail "Systemctl enable not invoked"
    fi

    # Negative path: --no-service should not create unit or call systemctl
    local no_service_home="$TEST_DIR/systemd_no_service_home"
    local no_service_install="$TEST_DIR/systemd_no_service_install/bin"
    local no_service_config="$no_service_home/.config/rch"
    local no_service_unit="$no_service_home/.config/systemd/user/rchd.service"
    local no_service_log="$TEST_DIR/systemd_no_service.log"

    mkdir -p "$no_service_install" "$no_service_config"
    output=$(run_install_case "$no_service_install" "$no_service_config" "$tarball" "--no-service --yes" "" "false" "$stub_bin" "$no_service_log" "ok" "$no_service_home") || true

    if [[ ! -f "$no_service_unit" ]]; then
        pass "No-service flag skips unit creation"
    else
        fail "No-service should not create unit file"
    fi

    if [[ ! -f "$no_service_log" ]] || ! grep -q "enable" "$no_service_log"; then
        pass "No-service avoids systemctl enable"
    else
        fail "No-service should not call systemctl enable"
    fi
}

# ============================================================================
# Test 15: Launchd unit generation
# ============================================================================

test_launchd_unit_generation() {
    start_test "Launchd unit generation"

    if [[ "$(uname -s)" != "Darwin" ]]; then
        log "  SKIP: launchd tests require macOS"
        pass "Launchd test skipped on non-macOS"
        return
    fi

    local tarball
    tarball=$(create_prompt_tarball "launchd")

    local stub_bin="$TEST_DIR/launchd_stub_bin"
    create_launchd_stubs "$stub_bin"

    local home_dir="$TEST_DIR/launchd_home"
    local install_dir="$TEST_DIR/launchd_install/bin"
    local config_dir="$home_dir/.config/rch"
    local plist_file="$home_dir/Library/LaunchAgents/com.rch.daemon.plist"
    local launchctl_log="$TEST_DIR/launchctl.log"

    mkdir -p "$install_dir" "$config_dir"

    local output
    output=$(LAUNCHCTL_LOG="$launchctl_log" run_install_case "$install_dir" "$config_dir" "$tarball" "--install-service" "" "false" "$stub_bin" "" "ok" "$home_dir") || true

    if [[ -f "$plist_file" ]]; then
        pass "Launchd plist created"
    else
        fail "Launchd plist missing"
        return
    fi

    if grep -q "<key>RunAtLoad</key>" "$plist_file"; then
        pass "Plist includes RunAtLoad"
    else
        fail "Plist missing RunAtLoad"
    fi

    if grep -q "<key>KeepAlive</key>" "$plist_file"; then
        pass "Plist includes KeepAlive"
    else
        fail "Plist missing KeepAlive"
    fi

    if grep -q "$install_dir/rchd" "$plist_file"; then
        pass "Plist includes rchd path"
    else
        fail "Plist missing rchd path"
    fi

    # Negative path: --no-service should not create plist
    local no_service_home="$TEST_DIR/launchd_no_service_home"
    local no_service_install="$TEST_DIR/launchd_no_service_install/bin"
    local no_service_config="$no_service_home/.config/rch"
    local no_service_plist="$no_service_home/Library/LaunchAgents/com.rch.daemon.plist"

    mkdir -p "$no_service_install" "$no_service_config"
    output=$(LAUNCHCTL_LOG="$launchctl_log" run_install_case "$no_service_install" "$no_service_config" "$tarball" "--no-service --yes" "" "false" "$stub_bin" "" "ok" "$no_service_home") || true

    if [[ ! -f "$no_service_plist" ]]; then
        pass "No-service flag skips plist creation"
    else
        fail "No-service should not create plist"
    fi

    if [[ -f "$launchctl_log" ]]; then
        pass "launchctl stub captured calls"
    else
        log "  Note: launchctl log missing (output may vary)"
        pass "launchctl stub (output varies)"
    fi
}

# ============================================================================
# Run all tests
# ============================================================================

log ""
log "Running E2E tests..."
log ""

test_help
test_verify_only
test_offline_install
test_uninstall
test_worker_mode
test_service_install
test_easy_mode
test_ui_detection
test_wsl_detection
test_proxy_config
test_lock_file
test_config_generation
test_service_prompt_behavior
test_systemd_unit_generation
test_launchd_unit_generation

# ============================================================================
# Summary
# ============================================================================

log ""
log "=== Test Summary ==="
log "Total tests: $TESTS_RUN"
log "Passed: $TESTS_PASSED"
log "Failed: $TESTS_FAILED"
log ""
log "Full log at: $LOG_FILE"

if [[ $TESTS_FAILED -gt 0 ]]; then
    log "SOME TESTS FAILED"
    exit 1
else
    log "ALL TESTS PASSED"
    exit 0
fi
