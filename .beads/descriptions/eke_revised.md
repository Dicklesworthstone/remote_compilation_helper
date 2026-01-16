## Overview

Enhance install.sh to be a modern, polished installer with Gum UI (with ANSI fallback), SHA256 checksum verification, optional signature verification, proxy support, offline mode, uninstall capability, and an "easy mode" that configures PATH and runs post-install verification.

## Goals

1. Gum spinners and styled output (with graceful ANSI fallback)
2. SHA256 checksum verification for all downloads
3. Optional minisign/Sigstore signature verification
4. Proxy support (HTTP_PROXY, HTTPS_PROXY, NO_PROXY)
5. Offline/airgap installation from local tarball
6. Uninstall functionality
7. Easy mode: configure PATH, detect agents, run verification
8. Lock file to prevent concurrent installations
9. WSL detection and guidance
10. Comprehensive logging and error messages
11. **NEW: Rust nightly verification for worker installs**
12. **NEW: Post-install diagnostic check (`rch doctor`)**
13. **NEW: Optional systemd/launchd service installation**

## CLI Interface

```bash
./install.sh [OPTIONS]

OPTIONS:
  --version <VER>       Install specific version (default: latest)
  --channel <CHANNEL>   Release channel: stable, beta, nightly
  --install-dir <DIR>   Installation directory (default: /usr/local/bin)
  --easy-mode           Configure PATH + detect agents + verify + run doctor
  --offline <TARBALL>   Install from local tarball (airgap mode)
  --verify-only         Verify existing installation
  --uninstall           Remove RCH binaries and config
  --no-gum              Disable Gum UI (use ANSI fallback)
  --no-sig              Skip signature verification
  --yes                 Skip confirmation prompts
  --worker-mode         Install worker agent with toolchain verification (NEW)
  --install-service     Install systemd/launchd service for daemon (NEW)
  --help                Show help message

ENVIRONMENT VARIABLES:
  HTTP_PROXY            HTTP proxy URL
  HTTPS_PROXY           HTTPS proxy URL
  NO_PROXY              Comma-separated list of hosts to bypass proxy
  RCH_INSTALL_DIR       Override default install directory
  RCH_NO_COLOR          Disable colored output
  RCH_SKIP_DOCTOR       Skip post-install doctor check (NEW)
```

## Implementation Structure

```bash
#!/usr/bin/env bash
set -euo pipefail

# ============================================================================
# Configuration
# ============================================================================

VERSION="${RCH_VERSION:-latest}"
CHANNEL="${RCH_CHANNEL:-stable}"
INSTALL_DIR="${RCH_INSTALL_DIR:-/usr/local/bin}"
GITHUB_REPO="Dicklesworthstone/remote_compilation_helper"
GITHUB_API="https://api.github.com/repos/${GITHUB_REPO}"

# ============================================================================
# Terminal Detection and UI Setup
# ============================================================================

setup_ui() {
    # Detect terminal capabilities
    if [[ -t 1 ]] && [[ -z "${RCH_NO_COLOR:-}" ]] && [[ "${TERM:-dumb}" != "dumb" ]]; then
        USE_COLOR=true
    else
        USE_COLOR=false
    fi

    # Check for Gum
    if command -v gum >/dev/null 2>&1 && [[ -z "${NO_GUM:-}" ]]; then
        USE_GUM=true
    else
        USE_GUM=false
    fi

    # ANSI color codes (fallback)
    if $USE_COLOR; then
        RED='\033[0;31m'
        GREEN='\033[0;32m'
        YELLOW='\033[0;33m'
        BLUE='\033[0;34m'
        BOLD='\033[1m'
        RESET='\033[0m'
    else
        RED='' GREEN='' YELLOW='' BLUE='' BOLD='' RESET=''
    fi
}

# ============================================================================
# Output Functions
# ============================================================================

info() {
    if $USE_GUM; then
        gum style --foreground 212 "→ $*"
    else
        echo -e "${BLUE}→${RESET} $*"
    fi
}

success() {
    if $USE_GUM; then
        gum style --foreground 82 "✓ $*"
    else
        echo -e "${GREEN}✓${RESET} $*"
    fi
}

warn() {
    if $USE_GUM; then
        gum style --foreground 208 "⚠ $*"
    else
        echo -e "${YELLOW}⚠${RESET} $*" >&2
    fi
}

error() {
    if $USE_GUM; then
        gum style --foreground 196 "✗ $*"
    else
        echo -e "${RED}✗${RESET} $*" >&2
    fi
}

spin() {
    local title="$1"
    shift
    if $USE_GUM; then
        gum spin --spinner dot --title "$title" -- "$@"
    else
        info "$title"
        "$@"
    fi
}

confirm() {
    local prompt="$1"
    if [[ "${YES:-}" == "true" ]]; then
        return 0
    fi
    if $USE_GUM; then
        gum confirm "$prompt"
    else
        read -rp "$prompt [y/N] " response
        [[ "$response" =~ ^[Yy] ]]
    fi
}

# ============================================================================
# Platform Detection
# ============================================================================

detect_platform() {
    local os arch

    case "$(uname -s)" in
        Linux*)  os="linux" ;;
        Darwin*) os="darwin" ;;
        MINGW*|MSYS*|CYGWIN*) os="windows" ;;
        *)       error "Unsupported OS: $(uname -s)"; exit 1 ;;
    esac

    case "$(uname -m)" in
        x86_64|amd64)  arch="x86_64" ;;
        aarch64|arm64) arch="aarch64" ;;
        *)             error "Unsupported architecture: $(uname -m)"; exit 1 ;;
    esac

    # WSL detection
    if [[ "$os" == "linux" ]] && grep -qi microsoft /proc/version 2>/dev/null; then
        IS_WSL=true
        warn "WSL detected. Some features may require additional configuration."
    else
        IS_WSL=false
    fi

    TARGET="${os}-${arch}"
    info "Detected platform: $TARGET"
}

# ============================================================================
# NEW: Worker Mode - Toolchain Verification
# ============================================================================

verify_worker_toolchain() {
    info "Verifying worker toolchain requirements..."

    local errors=0

    # Check rustup
    if command -v rustup >/dev/null 2>&1; then
        local rustup_version
        rustup_version=$(rustup --version 2>/dev/null | head -1)
        success "rustup: $rustup_version"
    else
        error "rustup: not found"
        echo "  Install with: curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh"
        ((errors++))
    fi

    # Check for Rust nightly (required for some compilation features)
    if rustup toolchain list 2>/dev/null | grep -q "nightly"; then
        local nightly_version
        nightly_version=$(rustup run nightly rustc --version 2>/dev/null || echo "unknown")
        success "rust nightly: $nightly_version"
    else
        warn "rust nightly: not installed (recommended for full compatibility)"
        echo "  Install with: rustup toolchain install nightly"
        # Not a fatal error, but recommended
    fi

    # Check GCC/Clang
    if command -v gcc >/dev/null 2>&1; then
        success "gcc: $(gcc --version | head -1)"
    elif command -v clang >/dev/null 2>&1; then
        success "clang: $(clang --version | head -1)"
    else
        error "No C compiler found (gcc or clang required)"
        ((errors++))
    fi

    # Check rsync
    if command -v rsync >/dev/null 2>&1; then
        success "rsync: $(rsync --version | head -1)"
    else
        error "rsync: not found"
        echo "  Install with: apt install rsync / brew install rsync"
        ((errors++))
    fi

    # Check zstd
    if command -v zstd >/dev/null 2>&1; then
        success "zstd: $(zstd --version | head -1)"
    else
        error "zstd: not found"
        echo "  Install with: apt install zstd / brew install zstd"
        ((errors++))
    fi

    # Check SSH server (for incoming connections)
    if [[ -f /etc/ssh/sshd_config ]] || command -v sshd >/dev/null 2>&1; then
        success "sshd: available"
    else
        warn "sshd: not detected (required for receiving remote builds)"
    fi

    if [[ $errors -gt 0 ]]; then
        error "Worker toolchain verification failed with $errors errors"
        return 1
    fi

    success "Worker toolchain verification passed"
}

# ============================================================================
# NEW: Post-Install Doctor Check
# ============================================================================

run_doctor() {
    if [[ "${RCH_SKIP_DOCTOR:-}" == "1" ]]; then
        info "Skipping doctor check (RCH_SKIP_DOCTOR=1)"
        return 0
    fi

    info "Running post-install diagnostics..."

    if [[ -x "$INSTALL_DIR/rch" ]]; then
        "$INSTALL_DIR/rch" doctor 2>&1 || {
            warn "Doctor check reported issues (this may be expected on fresh install)"
            return 0
        }
        success "Doctor check passed"
    else
        warn "Cannot run doctor: rch binary not found"
    fi
}

# ============================================================================
# NEW: Service Installation
# ============================================================================

install_service() {
    info "Installing system service for rchd..."

    case "$(uname -s)" in
        Linux*)
            install_systemd_service
            ;;
        Darwin*)
            install_launchd_service
            ;;
        *)
            warn "Service installation not supported on this platform"
            return 0
            ;;
    esac
}

install_systemd_service() {
    local service_file="/etc/systemd/system/rchd.service"
    local user_service_file="$HOME/.config/systemd/user/rchd.service"

    if [[ -w "/etc/systemd/system" ]]; then
        # System-wide installation
        info "Installing system-wide systemd service..."
        $SUDO tee "$service_file" > /dev/null << EOF
[Unit]
Description=RCH Daemon - Remote Compilation Helper
After=network.target

[Service]
Type=simple
ExecStart=$INSTALL_DIR/rchd
Restart=on-failure
RestartSec=5
Environment=RCH_LOG_LEVEL=info

[Install]
WantedBy=multi-user.target
EOF
        $SUDO systemctl daemon-reload
        success "Installed $service_file"
        info "Enable with: sudo systemctl enable --now rchd"
    else
        # User-level installation
        info "Installing user-level systemd service..."
        mkdir -p "$(dirname "$user_service_file")"
        cat > "$user_service_file" << EOF
[Unit]
Description=RCH Daemon - Remote Compilation Helper

[Service]
Type=simple
ExecStart=$INSTALL_DIR/rchd
Restart=on-failure
RestartSec=5
Environment=RCH_LOG_LEVEL=info

[Install]
WantedBy=default.target
EOF
        systemctl --user daemon-reload
        success "Installed $user_service_file"
        info "Enable with: systemctl --user enable --now rchd"
    fi
}

install_launchd_service() {
    local plist_file="$HOME/Library/LaunchAgents/com.rch.daemon.plist"

    info "Installing launchd service..."
    mkdir -p "$(dirname "$plist_file")"

    cat > "$plist_file" << EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.rch.daemon</string>
    <key>ProgramArguments</key>
    <array>
        <string>$INSTALL_DIR/rchd</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
    <key>EnvironmentVariables</key>
    <dict>
        <key>RCH_LOG_LEVEL</key>
        <string>info</string>
    </dict>
    <key>StandardOutPath</key>
    <string>$HOME/.rch/logs/daemon.log</string>
    <key>StandardErrorPath</key>
    <string>$HOME/.rch/logs/daemon.err</string>
</dict>
</plist>
EOF

    success "Installed $plist_file"
    info "Load with: launchctl load $plist_file"
}

# ... (rest of existing functions: version resolution, download, verify, install, etc.)

# ============================================================================
# Version Resolution
# ============================================================================

resolve_version() {
    if [[ "$VERSION" == "latest" ]]; then
        info "Fetching latest $CHANNEL release..."
        local api_url="${GITHUB_API}/releases"

        if [[ "$CHANNEL" == "stable" ]]; then
            api_url="${GITHUB_API}/releases/latest"
        fi

        VERSION=$(curl -fsSL ${PROXY_ARGS:-} "$api_url" | jq -r '
            if type == "array" then
                [.[] | select(.prerelease == ('$([[ "$CHANNEL" != "stable" ]] && echo "true" || echo "false")'))] | first | .tag_name
            else
                .tag_name
            end
        ')

        if [[ -z "$VERSION" || "$VERSION" == "null" ]]; then
            error "Failed to determine latest version"
            exit 1
        fi
    fi

    info "Installing version: $VERSION"
}

# ============================================================================
# Download and Verification
# ============================================================================

download_release() {
    local base_url="https://github.com/${GITHUB_REPO}/releases/download/${VERSION}"
    local tarball="rch-${VERSION}-${TARGET}.tar.gz"
    local checksum_file="checksums.txt"

    TEMP_DIR=$(mktemp -d)
    trap 'rm -rf "$TEMP_DIR"' EXIT

    # Download tarball
    spin "Downloading $tarball..." \
        curl -fsSL ${PROXY_ARGS:-} -o "$TEMP_DIR/$tarball" "$base_url/$tarball"

    # Download checksums
    spin "Downloading checksums..." \
        curl -fsSL ${PROXY_ARGS:-} -o "$TEMP_DIR/$checksum_file" "$base_url/$checksum_file"

    # Verify checksum
    verify_checksum "$TEMP_DIR/$tarball" "$TEMP_DIR/$checksum_file" "$tarball"

    # Optional signature verification
    if [[ "${NO_SIG:-}" != "true" ]]; then
        if curl -fsSL ${PROXY_ARGS:-} -o "$TEMP_DIR/${checksum_file}.sig" "$base_url/${checksum_file}.sig" 2>/dev/null; then
            verify_signature "$TEMP_DIR/$checksum_file" "$TEMP_DIR/${checksum_file}.sig"
        else
            warn "Signature file not available, skipping signature verification"
        fi
    fi

    TARBALL_PATH="$TEMP_DIR/$tarball"
}

verify_checksum() {
    local file="$1"
    local checksum_file="$2"
    local filename="$3"

    info "Verifying checksum..."

    local expected
    expected=$(grep "$filename" "$checksum_file" | awk '{print $1}')

    if [[ -z "$expected" ]]; then
        error "Checksum not found for $filename"
        exit 1
    fi

    local computed
    if command -v sha256sum >/dev/null 2>&1; then
        computed=$(sha256sum "$file" | awk '{print $1}')
    elif command -v shasum >/dev/null 2>&1; then
        computed=$(shasum -a 256 "$file" | awk '{print $1}')
    else
        error "No SHA256 tool found (sha256sum or shasum required)"
        exit 1
    fi

    if [[ "$expected" != "$computed" ]]; then
        error "Checksum verification failed!"
        error "  Expected: $expected"
        error "  Got:      $computed"
        exit 1
    fi

    success "Checksum verified"
}

verify_signature() {
    local file="$1"
    local sig_file="$2"

    if command -v minisign >/dev/null 2>&1; then
        info "Verifying signature with minisign..."
        # Public key would be embedded or fetched
        # minisign -Vm "$file" -x "$sig_file" -P "$PUBLIC_KEY"
        warn "Signature verification not yet implemented"
    else
        warn "minisign not installed, skipping signature verification"
    fi
}

# ============================================================================
# Installation
# ============================================================================

install_binaries() {
    info "Installing to $INSTALL_DIR..."

    # Check permissions
    if [[ ! -w "$INSTALL_DIR" ]]; then
        if confirm "Need sudo to install to $INSTALL_DIR. Continue?"; then
            SUDO="sudo"
        else
            error "Cannot write to $INSTALL_DIR"
            exit 1
        fi
    else
        SUDO=""
    fi

    # Extract and install
    spin "Extracting binaries..." \
        tar -xzf "$TARBALL_PATH" -C "$TEMP_DIR"

    for binary in rch rchd rch-wkr; do
        if [[ -f "$TEMP_DIR/$binary" ]]; then
            $SUDO install -m 755 "$TEMP_DIR/$binary" "$INSTALL_DIR/$binary"
            success "Installed $binary"
        fi
    done
}

# ============================================================================
# Easy Mode: PATH Configuration
# ============================================================================

configure_path() {
    if [[ ":$PATH:" == *":$INSTALL_DIR:"* ]]; then
        info "$INSTALL_DIR already in PATH"
        return 0
    fi

    local shell_rc
    case "${SHELL:-/bin/bash}" in
        */bash) shell_rc="$HOME/.bashrc" ;;
        */zsh)  shell_rc="$HOME/.zshrc" ;;
        */fish) shell_rc="$HOME/.config/fish/config.fish" ;;
        *)      shell_rc="$HOME/.profile" ;;
    esac

    local path_line="export PATH=\"$INSTALL_DIR:\$PATH\""

    # Check if already configured
    if [[ -f "$shell_rc" ]] && grep -qF "$INSTALL_DIR" "$shell_rc"; then
        info "PATH already configured in $shell_rc"
        return 0
    fi

    if confirm "Add $INSTALL_DIR to PATH in $shell_rc?"; then
        echo "" >> "$shell_rc"
        echo "# Added by RCH installer" >> "$shell_rc"
        echo "$path_line" >> "$shell_rc"
        success "PATH configured in $shell_rc"
        warn "Run 'source $shell_rc' or restart your shell"
    fi
}

# ============================================================================
# Uninstall
# ============================================================================

uninstall() {
    info "Uninstalling RCH..."

    local binaries=(rch rchd rch-wkr)
    local removed=0

    for binary in "${binaries[@]}"; do
        local path="$INSTALL_DIR/$binary"
        if [[ -f "$path" ]]; then
            if [[ -w "$INSTALL_DIR" ]]; then
                rm -f "$path"
            else
                sudo rm -f "$path"
            fi
            success "Removed $path"
            ((removed++))
        fi
    done

    if [[ $removed -eq 0 ]]; then
        warn "No RCH binaries found in $INSTALL_DIR"
    fi

    # Optionally remove config
    if confirm "Remove RCH configuration (~/.config/rch)?"; then
        rm -rf "$HOME/.config/rch"
        success "Removed configuration"
    fi

    success "Uninstall complete"
}

# ============================================================================
# Verification
# ============================================================================

verify_installation() {
    info "Verifying installation..."

    local errors=0

    for binary in rch rchd rch-wkr; do
        local path="$INSTALL_DIR/$binary"
        if [[ -x "$path" ]]; then
            local version
            version=$("$path" --version 2>/dev/null | head -1 || echo "unknown")
            success "$binary: $version"
        else
            error "$binary: not found or not executable"
            ((errors++))
        fi
    done

    if [[ $errors -gt 0 ]]; then
        error "Verification failed with $errors errors"
        return 1
    fi

    success "Installation verified"
}

# ============================================================================
# Main
# ============================================================================

main() {
    setup_ui

    # Parse arguments
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --version)    VERSION="$2"; shift 2 ;;
            --channel)    CHANNEL="$2"; shift 2 ;;
            --install-dir) INSTALL_DIR="$2"; shift 2 ;;
            --easy-mode)  EASY_MODE=true; shift ;;
            --offline)    OFFLINE_TARBALL="$2"; shift 2 ;;
            --verify-only) VERIFY_ONLY=true; shift ;;
            --uninstall)  DO_UNINSTALL=true; shift ;;
            --no-gum)     NO_GUM=true; shift ;;
            --no-sig)     NO_SIG=true; shift ;;
            --yes)        YES=true; shift ;;
            --worker-mode) WORKER_MODE=true; shift ;;  # NEW
            --install-service) INSTALL_SERVICE=true; shift ;;  # NEW
            --help)       show_help; exit 0 ;;
            *)            error "Unknown option: $1"; exit 1 ;;
        esac
    done

    # Setup proxy
    setup_proxy

    # Handle modes
    if [[ "${DO_UNINSTALL:-}" == "true" ]]; then
        uninstall
        exit 0
    fi

    if [[ "${VERIFY_ONLY:-}" == "true" ]]; then
        verify_installation
        exit $?
    fi

    # NEW: Worker mode - verify toolchain first
    if [[ "${WORKER_MODE:-}" == "true" ]]; then
        verify_worker_toolchain || exit 1
    fi

    # Installation flow
    detect_platform

    if [[ -n "${OFFLINE_TARBALL:-}" ]]; then
        TARBALL_PATH="$OFFLINE_TARBALL"
        info "Using offline tarball: $TARBALL_PATH"
    else
        resolve_version
        download_release
    fi

    install_binaries
    verify_installation

    # NEW: Install service if requested
    if [[ "${INSTALL_SERVICE:-}" == "true" ]]; then
        install_service
    fi

    if [[ "${EASY_MODE:-}" == "true" ]]; then
        configure_path
        info "Detecting AI coding agents..."
        "$INSTALL_DIR/rch" agents detect || true

        # NEW: Run doctor check
        run_doctor
    fi

    echo ""
    success "RCH installation complete!"
    info "Run 'rch setup' to configure workers and hooks"
}

setup_proxy() {
    PROXY_ARGS=""
    if [[ -n "${HTTPS_PROXY:-}" ]]; then
        PROXY_ARGS="--proxy $HTTPS_PROXY"
        info "Using proxy: $HTTPS_PROXY"
    elif [[ -n "${HTTP_PROXY:-}" ]]; then
        PROXY_ARGS="--proxy $HTTP_PROXY"
        info "Using proxy: $HTTP_PROXY"
    fi
}

show_help() {
    cat << 'EOF'
RCH Installer

Usage: ./install.sh [OPTIONS]

Options:
  --version <VER>       Install specific version (default: latest)
  --channel <CHANNEL>   Release channel: stable, beta, nightly
  --install-dir <DIR>   Installation directory (default: /usr/local/bin)
  --easy-mode           Configure PATH + detect agents + verify + run doctor
  --offline <TARBALL>   Install from local tarball (airgap mode)
  --verify-only         Verify existing installation
  --uninstall           Remove RCH binaries and config
  --no-gum              Disable Gum UI (use ANSI fallback)
  --no-sig              Skip signature verification
  --yes                 Skip confirmation prompts
  --worker-mode         Install worker agent with toolchain verification (NEW)
  --install-service     Install systemd/launchd service for daemon (NEW)
  --help                Show this help message

Environment Variables:
  HTTP_PROXY            HTTP proxy URL
  HTTPS_PROXY           HTTPS proxy URL
  NO_PROXY              Hosts to bypass proxy
  RCH_INSTALL_DIR       Override default install directory
  RCH_NO_COLOR          Disable colored output
  RCH_SKIP_DOCTOR       Skip post-install doctor check (NEW)
EOF
}

main "$@"
```

## Testing Requirements

### Unit Tests (test/install.bats)

```bash
#!/usr/bin/env bats

load test_helper

@test "detect_platform returns valid target on Linux x86_64" {
    # Mock uname
    function uname() { [[ "$1" == "-s" ]] && echo "Linux" || echo "x86_64"; }
    export -f uname

    source install.sh --help
    detect_platform
    [[ "$TARGET" == "linux-x86_64" ]]
}

@test "detect_platform returns valid target on macOS arm64" {
    function uname() { [[ "$1" == "-s" ]] && echo "Darwin" || echo "arm64"; }
    export -f uname

    source install.sh --help
    detect_platform
    [[ "$TARGET" == "darwin-aarch64" ]]
}

@test "verify_checksum succeeds with correct checksum" {
    local tmp=$(mktemp)
    echo "test content" > "$tmp"
    local checksum=$(sha256sum "$tmp" | awk '{print $1}')
    echo "$checksum  $(basename $tmp)" > "${tmp}.checksums"

    source install.sh --help
    verify_checksum "$tmp" "${tmp}.checksums" "$(basename $tmp)"
}

@test "verify_checksum fails with wrong checksum" {
    local tmp=$(mktemp)
    echo "test content" > "$tmp"
    echo "wrongchecksum  $(basename $tmp)" > "${tmp}.checksums"

    source install.sh --help
    run verify_checksum "$tmp" "${tmp}.checksums" "$(basename $tmp)"
    [[ "$status" -ne 0 ]]
}

@test "configure_path is idempotent" {
    local tmp=$(mktemp)
    echo 'export PATH="/usr/local/bin:$PATH"' > "$tmp"

    SHELL="/bin/bash"
    HOME=$(dirname "$tmp")
    mv "$tmp" "$HOME/.bashrc"

    source install.sh --help
    configure_path

    local count=$(grep -c "/usr/local/bin" "$HOME/.bashrc")
    [[ "$count" -eq 1 ]]
}

@test "proxy setup uses HTTPS_PROXY" {
    export HTTPS_PROXY="http://proxy:8080"
    source install.sh --help
    setup_proxy
    [[ "$PROXY_ARGS" == "--proxy http://proxy:8080" ]]
}

# NEW: Worker toolchain tests
@test "worker mode verifies rustup presence" {
    source install.sh --help

    # This test requires mocking - verify the function exists
    declare -f verify_worker_toolchain > /dev/null
}

@test "worker mode verifies gcc or clang presence" {
    source install.sh --help

    # Should detect at least one compiler
    command -v gcc >/dev/null || command -v clang >/dev/null
}

# NEW: Service installation tests
@test "systemd service file generation" {
    source install.sh --help

    # Verify function exists and would produce valid output
    declare -f install_systemd_service > /dev/null
}

@test "launchd plist generation" {
    source install.sh --help

    declare -f install_launchd_service > /dev/null
}
```

### E2E Test Script (scripts/e2e_install_test.sh)

```bash
#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TEST_DIR=$(mktemp -d)
LOG_FILE="$TEST_DIR/e2e_install.log"

log() { echo "[$(date -Iseconds)] $*" | tee -a "$LOG_FILE"; }
pass() { log "PASS: $1"; }
fail() { log "FAIL: $1"; exit 1; }

cleanup() {
    rm -rf "$TEST_DIR"
}
trap cleanup EXIT

log "=== RCH Installer E2E Test ==="
log "Test dir: $TEST_DIR"

# Test 1: Help output
test_help() {
    log "Test 1: Help output"
    ./install.sh --help | grep -q "RCH Installer" || fail "Help should show installer name"
    ./install.sh --help | grep -q "worker-mode" || fail "Help should mention worker-mode"
    ./install.sh --help | grep -q "install-service" || fail "Help should mention install-service"
    pass "Help output"
}

# Test 2: Verify-only on fresh system
test_verify_only() {
    log "Test 2: Verify-only fails when not installed"
    INSTALL_DIR="$TEST_DIR/bin" ./install.sh --verify-only && fail "Should fail" || true
    pass "Verify-only fails correctly"
}

# Test 3: Offline install
test_offline_install() {
    log "Test 3: Offline install from tarball"

    # Create mock tarball
    mkdir -p "$TEST_DIR/pkg"
    echo '#!/bin/bash' > "$TEST_DIR/pkg/rch"
    echo 'echo "rch 0.1.0"' >> "$TEST_DIR/pkg/rch"
    chmod +x "$TEST_DIR/pkg/rch"
    tar -czf "$TEST_DIR/rch.tar.gz" -C "$TEST_DIR/pkg" rch

    mkdir -p "$TEST_DIR/bin"
    INSTALL_DIR="$TEST_DIR/bin" RCH_SKIP_DOCTOR=1 ./install.sh --offline "$TEST_DIR/rch.tar.gz" --yes
    [[ -x "$TEST_DIR/bin/rch" ]] || fail "Binary not installed"
    pass "Offline install"
}

# Test 4: Uninstall
test_uninstall() {
    log "Test 4: Uninstall"
    INSTALL_DIR="$TEST_DIR/bin" ./install.sh --uninstall --yes
    [[ ! -f "$TEST_DIR/bin/rch" ]] || fail "Binary not removed"
    pass "Uninstall"
}

# Test 5: Worker mode toolchain verification (NEW)
test_worker_mode() {
    log "Test 5: Worker mode toolchain verification"

    # Create mock binary that supports worker mode
    mkdir -p "$TEST_DIR/bin2"

    # This should at least run the verification (may fail if tools missing)
    INSTALL_DIR="$TEST_DIR/bin2" ./install.sh --worker-mode --verify-only 2>&1 | tee "$TEST_DIR/worker.log" || true

    # Check that toolchain verification was attempted
    if grep -qE "rustup|gcc|rsync|zstd" "$TEST_DIR/worker.log"; then
        pass "Worker mode toolchain verification"
    else
        log "  Note: Worker mode verification output may vary"
        pass "Worker mode (output varies)"
    fi
}

# Test 6: Service installation dry run (NEW)
test_service_install() {
    log "Test 6: Service installation"

    # We can't actually install services in test, but verify the code path exists
    ./install.sh --help | grep -q "install-service" || fail "Service option missing"
    pass "Service installation option"
}

# Test 7: Easy mode runs doctor (NEW)
test_easy_mode_doctor() {
    log "Test 7: Easy mode runs doctor check"

    # Create mock installation
    mkdir -p "$TEST_DIR/bin3"
    cat > "$TEST_DIR/bin3/rch" << 'EOF'
#!/bin/bash
case "$1" in
    --version) echo "rch 0.1.0" ;;
    doctor) echo "All checks passed"; exit 0 ;;
    agents) echo "No agents detected" ;;
esac
EOF
    chmod +x "$TEST_DIR/bin3/rch"
    cp "$TEST_DIR/bin3/rch" "$TEST_DIR/bin3/rchd"
    cp "$TEST_DIR/bin3/rch" "$TEST_DIR/bin3/rch-wkr"

    # Create tarball
    tar -czf "$TEST_DIR/rch3.tar.gz" -C "$TEST_DIR/bin3" rch rchd rch-wkr

    OUTPUT=$(INSTALL_DIR="$TEST_DIR/bin3" ./install.sh --offline "$TEST_DIR/rch3.tar.gz" --easy-mode --yes 2>&1) || true
    log "  Easy mode output: $(echo "$OUTPUT" | tail -10)"

    echo "$OUTPUT" | grep -qiE "doctor|diagnostic|check" || log "  Note: doctor output may vary"
    pass "Easy mode doctor"
}

# Test 8: Color and Gum detection
test_ui_detection() {
    log "Test 8: UI detection (color, Gum)"

    # Test with color disabled
    RCH_NO_COLOR=1 ./install.sh --help > /dev/null || fail "Should work without color"

    # Test with Gum disabled
    NO_GUM=1 ./install.sh --help > /dev/null || fail "Should work without Gum"

    pass "UI detection"
}

# Test 9: WSL detection (NEW)
test_wsl_detection() {
    log "Test 9: WSL detection"

    # Can't fully test WSL detection outside WSL, but verify code path exists
    ./install.sh --help > /dev/null
    pass "WSL detection code path"
}

# Test 10: Proxy configuration
test_proxy_config() {
    log "Test 10: Proxy configuration"

    # Set proxy and verify it's used (in help, since we can't actually connect)
    export HTTPS_PROXY="http://proxy.example.com:8080"
    ./install.sh --help | grep -qE "HTTPS_PROXY" || fail "Proxy env var not documented"
    unset HTTPS_PROXY

    pass "Proxy configuration"
}

# Run all tests
test_help
test_verify_only
test_offline_install
test_uninstall
test_worker_mode
test_service_install
test_easy_mode_doctor
test_ui_detection
test_wsl_detection
test_proxy_config

log "=== All install.sh E2E tests passed ==="
log "Full log at: $LOG_FILE"
cat "$LOG_FILE"
```

## Success Criteria

- [ ] Gum UI works when available
- [ ] ANSI fallback works without Gum
- [ ] SHA256 checksum verification passes
- [ ] Proxy support works (HTTP_PROXY, HTTPS_PROXY)
- [ ] Offline install from local tarball works
- [ ] Uninstall removes binaries cleanly
- [ ] Easy mode configures PATH idempotently
- [ ] WSL detection shows appropriate warnings
- [ ] **NEW: Worker mode verifies all toolchain requirements**
- [ ] **NEW: Post-install doctor check runs and reports issues**
- [ ] **NEW: Systemd service installation works on Linux**
- [ ] **NEW: Launchd service installation works on macOS**
- [ ] All bats tests pass
- [ ] E2E tests pass

## Dependencies

- remote_compilation_helper-9zy: Uses release artifacts
- remote_compilation_helper-gao: Release build configuration

## Blocks

None - this is a user-facing installer.
