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

## CLI Interface

```bash
./install.sh [OPTIONS]

OPTIONS:
  --version <VER>       Install specific version (default: latest)
  --channel <CHANNEL>   Release channel: stable, beta, nightly
  --install-dir <DIR>   Installation directory (default: /usr/local/bin)
  --easy-mode           Configure PATH + detect agents + verify
  --offline <TARBALL>   Install from local tarball (airgap mode)
  --verify-only         Verify existing installation
  --uninstall           Remove RCH binaries and config
  --no-gum              Disable Gum UI (use ANSI fallback)
  --no-sig              Skip signature verification
  --yes                 Skip confirmation prompts
  --help                Show help message

ENVIRONMENT VARIABLES:
  HTTP_PROXY            HTTP proxy URL
  HTTPS_PROXY           HTTPS proxy URL
  NO_PROXY              Comma-separated list of hosts to bypass proxy
  RCH_INSTALL_DIR       Override default install directory
  RCH_NO_COLOR          Disable colored output
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

    if [[ "${EASY_MODE:-}" == "true" ]]; then
        configure_path
        info "Detecting AI coding agents..."
        "$INSTALL_DIR/rch" agents detect || true
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
  --easy-mode           Configure PATH + detect agents + verify
  --offline <TARBALL>   Install from local tarball (airgap mode)
  --verify-only         Verify existing installation
  --uninstall           Remove RCH binaries and config
  --no-gum              Disable Gum UI (use ANSI fallback)
  --no-sig              Skip signature verification
  --yes                 Skip confirmation prompts
  --help                Show this help message

Environment Variables:
  HTTP_PROXY            HTTP proxy URL
  HTTPS_PROXY           HTTPS proxy URL
  NO_PROXY              Hosts to bypass proxy
  RCH_INSTALL_DIR       Override default install directory
  RCH_NO_COLOR          Disable colored output
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
```

### E2E Test Script (scripts/e2e_install_test.sh)

```bash
#!/usr/bin/env bash
set -euo pipefail

log() { echo "[$(date -Iseconds)] $*" >&2; }
pass() { log "✓ PASS: $*"; }
fail() { log "✗ FAIL: $*"; exit 1; }

TEST_DIR=$(mktemp -d)
trap 'rm -rf "$TEST_DIR"' EXIT

# Test 1: Help output
log "Test 1: Help output"
./install.sh --help | grep -q "RCH Installer" || fail "Help should show installer name"
pass "Help output"

# Test 2: Verify-only on fresh system
log "Test 2: Verify-only fails when not installed"
INSTALL_DIR="$TEST_DIR/bin" ./install.sh --verify-only && fail "Should fail" || true
pass "Verify-only fails correctly"

# Test 3: Offline install
log "Test 3: Offline install from tarball"
# Create mock tarball
mkdir -p "$TEST_DIR/pkg"
echo '#!/bin/bash' > "$TEST_DIR/pkg/rch"
echo 'echo "rch 0.1.0"' >> "$TEST_DIR/pkg/rch"
chmod +x "$TEST_DIR/pkg/rch"
tar -czf "$TEST_DIR/rch.tar.gz" -C "$TEST_DIR/pkg" rch

INSTALL_DIR="$TEST_DIR/bin" ./install.sh --offline "$TEST_DIR/rch.tar.gz" --yes
[[ -x "$TEST_DIR/bin/rch" ]] || fail "Binary not installed"
pass "Offline install"

# Test 4: Uninstall
log "Test 4: Uninstall"
INSTALL_DIR="$TEST_DIR/bin" ./install.sh --uninstall --yes
[[ ! -f "$TEST_DIR/bin/rch" ]] || fail "Binary not removed"
pass "Uninstall"

log "All install.sh E2E tests passed!"
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
- [ ] All bats tests pass
- [ ] E2E tests pass

## Dependencies

- remote_compilation_helper-9zy: Uses release artifacts
- remote_compilation_helper-gao: Release build configuration

## Blocks

None - this is a user-facing installer.
