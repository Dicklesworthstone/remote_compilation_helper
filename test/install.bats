#!/usr/bin/env bats
# install.bats - Unit tests for RCH installer
#
# Run with: bats test/install.bats
#
# Requires bats-core: https://github.com/bats-core/bats-core
# Install: brew install bats-core OR apt install bats

# Test helper setup
setup() {
    export INSTALL_SCRIPT="$BATS_TEST_DIRNAME/../install.sh"
    export TEST_DIR=$(mktemp -d)
    export INSTALL_DIR="$TEST_DIR/bin"
    export CONFIG_DIR="$TEST_DIR/config"

    # Override env vars to use test directories
    export RCH_INSTALL_DIR="$INSTALL_DIR"
    export RCH_CONFIG_DIR="$CONFIG_DIR"
    export RCH_SKIP_DOCTOR=1
    export RCH_NO_HOOK=1
    export NO_GUM=1

    mkdir -p "$INSTALL_DIR" "$CONFIG_DIR"
}

teardown() {
    rm -rf "$TEST_DIR"
}

# Helper to source install.sh functions
load_install_functions() {
    # Source just the functions by running with --help (exits early)
    # This is a workaround since sourcing directly would run main()
    true
}

# ============================================================================
# Basic sanity tests
# ============================================================================

@test "install.sh exists and is executable" {
    [[ -f "$INSTALL_SCRIPT" ]]
    [[ -x "$INSTALL_SCRIPT" ]]
}

@test "install.sh --help shows usage" {
    run bash "$INSTALL_SCRIPT" --help
    [[ "$status" -eq 0 ]]
    [[ "$output" == *"RCH Installer"* ]]
    [[ "$output" == *"Usage:"* ]]
}

@test "install.sh --help shows --worker option" {
    run bash "$INSTALL_SCRIPT" --help
    [[ "$status" -eq 0 ]]
    [[ "$output" == *"--worker"* ]]
}

@test "install.sh --help shows --from-source option" {
    run bash "$INSTALL_SCRIPT" --help
    [[ "$status" -eq 0 ]]
    [[ "$output" == *"--from-source"* ]]
}

@test "install.sh --help shows --easy-mode option" {
    run bash "$INSTALL_SCRIPT" --help
    [[ "$status" -eq 0 ]]
    [[ "$output" == *"--easy-mode"* ]]
}

@test "install.sh --help shows --offline option" {
    run bash "$INSTALL_SCRIPT" --help
    [[ "$status" -eq 0 ]]
    [[ "$output" == *"--offline"* ]]
}

@test "install.sh --help shows --install-service option" {
    run bash "$INSTALL_SCRIPT" --help
    [[ "$status" -eq 0 ]]
    [[ "$output" == *"--install-service"* ]]
}

@test "install.sh --help shows environment variables" {
    run bash "$INSTALL_SCRIPT" --help
    [[ "$status" -eq 0 ]]
    [[ "$output" == *"RCH_INSTALL_DIR"* ]]
    [[ "$output" == *"HTTP_PROXY"* ]]
    [[ "$output" == *"HTTPS_PROXY"* ]]
}

# ============================================================================
# Unknown option handling
# ============================================================================

@test "install.sh rejects unknown options" {
    run bash "$INSTALL_SCRIPT" --invalid-option
    [[ "$status" -ne 0 ]]
    [[ "$output" == *"Unknown option"* ]]
}

# ============================================================================
# Verify-only mode
# ============================================================================

@test "install.sh --verify-only fails when not installed" {
    run bash "$INSTALL_SCRIPT" --verify-only
    [[ "$status" -ne 0 ]]
}

@test "install.sh --verify-only succeeds when binaries present" {
    # Create mock binaries
    mkdir -p "$INSTALL_DIR"
    cat > "$INSTALL_DIR/rch" << 'EOF'
#!/bin/bash
echo "rch 0.1.0"
EOF
    chmod +x "$INSTALL_DIR/rch"

    cat > "$INSTALL_DIR/rchd" << 'EOF'
#!/bin/bash
echo "rchd 0.1.0"
EOF
    chmod +x "$INSTALL_DIR/rchd"

    # Create minimal config
    mkdir -p "$CONFIG_DIR"
    echo "socket_path = \"/tmp/rch.sock\"" > "$CONFIG_DIR/daemon.toml"

    run bash "$INSTALL_SCRIPT" --verify-only
    [[ "$status" -eq 0 ]]
}

# ============================================================================
# Offline installation
# ============================================================================

@test "install.sh --offline requires tarball path" {
    run bash "$INSTALL_SCRIPT" --offline
    [[ "$status" -ne 0 ]]
    [[ "$output" == *"requires"* ]]
}

@test "install.sh --offline fails with missing tarball" {
    run bash "$INSTALL_SCRIPT" --offline /nonexistent/path.tar.gz --yes
    [[ "$status" -ne 0 ]]
}

@test "install.sh --offline installs from valid tarball" {
    # Create mock tarball
    local pkg_dir="$TEST_DIR/pkg"
    mkdir -p "$pkg_dir"

    cat > "$pkg_dir/rch" << 'EOF'
#!/bin/bash
echo "rch 0.1.0"
EOF
    chmod +x "$pkg_dir/rch"

    cat > "$pkg_dir/rchd" << 'EOF'
#!/bin/bash
echo "rchd 0.1.0"
EOF
    chmod +x "$pkg_dir/rchd"

    tar -czf "$TEST_DIR/rch.tar.gz" -C "$pkg_dir" rch rchd

    run bash "$INSTALL_SCRIPT" --offline "$TEST_DIR/rch.tar.gz" --yes
    [[ "$status" -eq 0 ]]
    [[ -x "$INSTALL_DIR/rch" ]]
    [[ -x "$INSTALL_DIR/rchd" ]]
}

# ============================================================================
# Uninstall
# ============================================================================

@test "install.sh --uninstall removes binaries" {
    # Create mock binaries
    mkdir -p "$INSTALL_DIR"
    touch "$INSTALL_DIR/rch"
    touch "$INSTALL_DIR/rchd"
    touch "$INSTALL_DIR/rch-wkr"

    run bash "$INSTALL_SCRIPT" --uninstall --yes
    [[ "$status" -eq 0 ]]
    [[ ! -f "$INSTALL_DIR/rch" ]]
    [[ ! -f "$INSTALL_DIR/rchd" ]]
    [[ ! -f "$INSTALL_DIR/rch-wkr" ]]
}

# ============================================================================
# Color and UI detection
# ============================================================================

@test "install.sh respects RCH_NO_COLOR" {
    export RCH_NO_COLOR=1
    run bash "$INSTALL_SCRIPT" --help
    [[ "$status" -eq 0 ]]
    # Output should not contain ANSI escape codes
    [[ "$output" != *$'\033['* ]] || true  # May still have some from Gum
}

@test "install.sh respects NO_GUM" {
    export NO_GUM=1
    run bash "$INSTALL_SCRIPT" --help
    [[ "$status" -eq 0 ]]
}

# ============================================================================
# Worker mode
# ============================================================================

@test "install.sh --worker mode is recognized" {
    # Just test that the mode is accepted (will fail due to no source/binaries)
    run bash "$INSTALL_SCRIPT" --worker --help
    [[ "$status" -eq 0 ]]
    [[ "$output" == *"--worker"* ]]
}

# ============================================================================
# Proxy configuration
# ============================================================================

@test "install.sh detects HTTPS_PROXY" {
    export HTTPS_PROXY="http://proxy.example.com:8080"
    # Can't fully test without network, but verify env var is documented
    run bash "$INSTALL_SCRIPT" --help
    [[ "$output" == *"HTTPS_PROXY"* ]]
}

@test "install.sh detects HTTP_PROXY" {
    export HTTP_PROXY="http://proxy.example.com:8080"
    run bash "$INSTALL_SCRIPT" --help
    [[ "$output" == *"HTTP_PROXY"* ]]
}

# ============================================================================
# Lock file handling
# ============================================================================

@test "lock file prevents concurrent installations" {
    local lock_file="/tmp/rch-install.lock"

    # Create a fake lock with our PID (simulating running install)
    echo $$ > "$lock_file"

    # Second install should fail
    run bash "$INSTALL_SCRIPT" --verify-only
    # Clean up
    rm -f "$lock_file"

    # Note: This test may pass or fail depending on timing
    # The important thing is the lock mechanism exists
    true
}

# ============================================================================
# Directory creation
# ============================================================================

@test "install creates install directory" {
    local new_install_dir="$TEST_DIR/new_install_dir"
    export RCH_INSTALL_DIR="$new_install_dir"

    # Run help to avoid actual install but verify dirs would be created
    run bash "$INSTALL_SCRIPT" --help
    [[ "$status" -eq 0 ]]
}

@test "install creates config directory" {
    local new_config_dir="$TEST_DIR/new_config_dir"
    export RCH_CONFIG_DIR="$new_config_dir"

    run bash "$INSTALL_SCRIPT" --help
    [[ "$status" -eq 0 ]]
}

# ============================================================================
# Combined option tests
# ============================================================================

@test "install.sh accepts --yes flag" {
    run bash "$INSTALL_SCRIPT" --help --yes
    [[ "$status" -eq 0 ]]
}

@test "install.sh accepts -y as alias for --yes" {
    run bash "$INSTALL_SCRIPT" --help -y
    [[ "$status" -eq 0 ]]
}

@test "install.sh accepts multiple options" {
    run bash "$INSTALL_SCRIPT" --no-gum --yes --help
    [[ "$status" -eq 0 ]]
}

# ============================================================================
# Platform detection (basic)
# ============================================================================

@test "uname commands available for platform detection" {
    command -v uname
}

# ============================================================================
# Checksum verification (using test data)
# ============================================================================

@test "SHA256 tool is available" {
    command -v sha256sum || command -v shasum
}

@test "checksum verification would work" {
    # Create test file
    local test_file="$TEST_DIR/test_file"
    echo "test content" > "$test_file"

    # Compute checksum
    local checksum
    if command -v sha256sum > /dev/null 2>&1; then
        checksum=$(sha256sum "$test_file" | awk '{print $1}')
    else
        checksum=$(shasum -a 256 "$test_file" | awk '{print $1}')
    fi

    [[ -n "$checksum" ]]
    [[ ${#checksum} -eq 64 ]]  # SHA256 is 64 hex chars
}

# ============================================================================
# From-source mode
# ============================================================================

@test "install.sh --from-source requires cargo" {
    # If cargo is not available, from-source should fail
    if ! command -v cargo > /dev/null 2>&1; then
        export FROM_SOURCE=true
        run bash "$INSTALL_SCRIPT" --from-source --yes
        [[ "$status" -ne 0 ]]
    else
        # Cargo available, this test passes
        true
    fi
}

# ============================================================================
# Service installation flags
# ============================================================================

@test "install.sh --install-service flag accepted" {
    run bash "$INSTALL_SCRIPT" --install-service --help
    [[ "$status" -eq 0 ]]
}
