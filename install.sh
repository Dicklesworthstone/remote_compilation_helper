#!/usr/bin/env bash
# install.sh - Remote Compilation Helper Installer
#
# A modern, polished installer with Gum UI (with ANSI fallback), checksum
# verification, proxy support, offline mode, and comprehensive toolchain verification.
#
# Installation modes:
#   1. Local:       Install rch + rchd on current machine (default)
#   2. Worker:      Install just rch-wkr on current machine
#
# Usage:
#   bash install.sh                      # Install + optionally enable background service
#   bash install.sh --local              # Same as above (default mode)
#   bash install.sh --worker             # Worker-only install (no daemon)
#   bash install.sh --from-source        # Build from source
#   bash install.sh --easy-mode          # Configure PATH + detect agents + run doctor
#   bash install.sh --no-service         # Install without system service
#   bash install.sh --offline <tarball>  # Install from local tarball
#   bash install.sh --uninstall          # Remove RCH
#
# Environment:
#   RCH_INSTALL_DIR     Where to install binaries (default: ~/.local/bin)
#   RCH_CONFIG_DIR      Where to store config (default: ~/.config/rch)
#   RCH_NO_HOOK         Skip Claude Code hook setup if set
#   RCH_NO_COLOR        Disable colored output
#   RCH_SKIP_DOCTOR     Skip post-install doctor check
#   HTTP_PROXY          HTTP proxy URL
#   HTTPS_PROXY         HTTPS proxy URL
#   NO_PROXY            Comma-separated list of hosts to bypass proxy

set -euo pipefail

# ============================================================================
# Configuration
# ============================================================================

INSTALLER_VERSION="1.0.2"
VERSION=""  # Set dynamically based on install mode
REPO_URL="https://github.com/Dicklesworthstone/remote_compilation_helper"
GITHUB_REPO="Dicklesworthstone/remote_compilation_helper"
GITHUB_API="https://api.github.com/repos/${GITHUB_REPO}"

INSTALL_DIR="${RCH_INSTALL_DIR:-$HOME/.local/bin}"
CONFIG_DIR="${RCH_CONFIG_DIR:-$HOME/.config/rch}"
SOCKET_PATH="/tmp/rch.sock"
LOCK_FILE="/tmp/rch-install.lock"

# Binaries
HOOK_BIN="rch"
DAEMON_BIN="rchd"
WORKER_BIN="rch-wkr"

# State variables
USE_COLOR=true
USE_GUM=false
IS_WSL=false
TEMP_DIR=""
TARBALL_PATH=""
PROXY_ARGS=""

# Default color values (set properly by setup_ui)
RED='' GREEN='' YELLOW='' BLUE='' MAGENTA='' CYAN='' BOLD='' DIM='' NC=''

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
        YELLOW='\033[1;33m'
        BLUE='\033[0;34m'
        MAGENTA='\033[0;35m'
        CYAN='\033[0;36m'
        BOLD='\033[1m'
        DIM='\033[2m'
        NC='\033[0m' # No Color
    else
        RED='' GREEN='' YELLOW='' BLUE='' MAGENTA='' CYAN='' BOLD='' DIM='' NC=''
    fi
}

# ============================================================================
# Output Functions (with Gum support)
# ============================================================================

info() {
    if $USE_GUM; then
        gum style --foreground 212 "→ $*"
    else
        echo -e "${BLUE}→${NC} $*"
    fi
}

success() {
    if $USE_GUM; then
        gum style --foreground 82 "✓ $*"
    else
        echo -e "${GREEN}✓${NC} $*"
    fi
}

warn() {
    if $USE_GUM; then
        gum style --foreground 208 "⚠ $*"
    else
        echo -e "${YELLOW}⚠${NC} $*" >&2
    fi
}

error() {
    if $USE_GUM; then
        gum style --foreground 196 "✗ $*"
    else
        echo -e "${RED}✗${NC} $*" >&2
    fi
}

die() {
    error "$@"
    cleanup_lock
    exit 1
}

# Spinner wrapper for long-running operations
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

# Confirmation prompt
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

# Draw a Unicode box with auto-calculated width (DCG-style)
# Usage: draw_box "color_code" "line1" "line2" ...
draw_box() {
    local color="$1"
    shift
    local lines=("$@")
    local max_len=0

    # Calculate maximum line length
    for line in "${lines[@]}"; do
        local len=${#line}
        [[ $len -gt $max_len ]] && max_len=$len
    done

    # Add padding
    local width=$((max_len + 4))
    local inner_width=$((width - 2))

    # Box characters
    local tl="╭" tr="╮" bl="╰" br="╯" h="─" v="│"

    # Top border
    local top_border="${tl}"
    for ((i=0; i<inner_width; i++)); do top_border+="${h}"; done
    top_border+="${tr}"

    # Bottom border
    local bottom_border="${bl}"
    for ((i=0; i<inner_width; i++)); do bottom_border+="${h}"; done
    bottom_border+="${br}"

    # Print box
    echo ""
    if $USE_COLOR; then
        echo -e "\033[${color}m${top_border}\033[0m"
        for line in "${lines[@]}"; do
            local padding=$((inner_width - ${#line} - 2))
            local pad_str=""
            for ((i=0; i<padding; i++)); do pad_str+=" "; done
            echo -e "\033[${color}m${v}\033[0m ${line}${pad_str} \033[${color}m${v}\033[0m"
        done
        echo -e "\033[${color}m${bottom_border}\033[0m"
    else
        echo "${top_border}"
        for line in "${lines[@]}"; do
            local padding=$((inner_width - ${#line} - 2))
            local pad_str=""
            for ((i=0; i<padding; i++)); do pad_str+=" "; done
            echo "${v} ${line}${pad_str} ${v}"
        done
        echo "${bottom_border}"
    fi
    echo ""
}

# Header display with full branding
show_header() {
    echo ""
    if $USE_GUM; then
        gum style \
            --border double \
            --border-foreground 212 \
            --padding "1 3" \
            --align center \
            "⚡ RCH Installer v$VERSION" \
            "" \
            "Remote Compilation Helper" \
            "Transparent compilation offloading for AI agents"
    else
        local header_color="1;35"  # Bold magenta
        echo -e "\033[${header_color}m"
        cat << 'BANNER'
    ██████╗  ██████╗██╗  ██╗
    ██╔══██╗██╔════╝██║  ██║
    ██████╔╝██║     ███████║
    ██╔══██╗██║     ██╔══██║
    ██║  ██║╚██████╗██║  ██║
    ╚═╝  ╚═╝ ╚═════╝╚═╝  ╚═╝
BANNER
        echo -e "\033[0m"
        draw_box "1;35" \
            "RCH Installer v$VERSION" \
            "Remote Compilation Helper" \
            "Transparent compilation offloading for AI agents"
    fi
}

command_exists() {
    command -v "$1" &> /dev/null
}

is_interactive() {
    [[ -t 0 ]]
}

systemd_user_available() {
    if ! command_exists systemctl; then
        return 1
    fi
    if systemctl --user show-environment >/dev/null 2>&1; then
        return 0
    fi
    if systemctl --user is-system-running >/dev/null 2>&1; then
        return 0
    fi
    return 1
}

detect_service_manager() {
    local os
    os="$(uname -s)"
    case "$os" in
        Linux*)
            if systemd_user_available; then
                echo "systemd"
                return 0
            fi
            ;;
        Darwin*)
            if command_exists launchctl; then
                echo "launchd"
                return 0
            fi
            ;;
        *)
            ;;
    esac
    return 1
}

ensure_command() {
    if ! command_exists "$1"; then
        die "Required command not found: $1. Please install it first."
    fi
}

# ============================================================================
# Lock File Management
# ============================================================================

acquire_lock() {
    if [[ -f "$LOCK_FILE" ]]; then
        local pid
        pid=$(cat "$LOCK_FILE" 2>/dev/null || echo "")
        if [[ -n "$pid" ]] && kill -0 "$pid" 2>/dev/null; then
            die "Another installation is in progress (PID: $pid). If this is incorrect, remove $LOCK_FILE"
        fi
        # Stale lock file, remove it
        rm -f "$LOCK_FILE"
    fi
    echo $$ > "$LOCK_FILE"
    trap cleanup_lock EXIT
}

cleanup_lock() {
    rm -f "$LOCK_FILE"
}

# ============================================================================
# Platform Detection
# ============================================================================

detect_platform() {
    info "Detecting platform..."

    local os arch

    case "$(uname -s)" in
        Linux*)  os="linux" ;;
        Darwin*) os="darwin" ;;
        MINGW*|MSYS*|CYGWIN*) os="windows" ;;
        *)       die "Unsupported OS: $(uname -s)" ;;
    esac

    case "$(uname -m)" in
        x86_64|amd64)  arch="x86_64" ;;
        aarch64|arm64) arch="aarch64" ;;
        *)             die "Unsupported architecture: $(uname -m)" ;;
    esac

    # WSL detection
    if [[ "$os" == "linux" ]] && grep -qi microsoft /proc/version 2>/dev/null; then
        IS_WSL=true
        warn "WSL detected. Some features may require additional configuration:"
        echo "  - SSH agent forwarding may need special setup"
        echo "  - File permissions between Windows/Linux may cause issues"
        echo "  - Consider using native Linux for best performance"
    fi

    TARGET="${os}-${arch}"
    success "Platform: $TARGET"
}

# ============================================================================
# Proxy Setup
# ============================================================================

setup_proxy() {
    PROXY_ARGS=""
    if [[ -n "${HTTPS_PROXY:-}" ]]; then
        PROXY_ARGS="--proxy $HTTPS_PROXY"
        info "Using HTTPS proxy: $HTTPS_PROXY"
    elif [[ -n "${HTTP_PROXY:-}" ]]; then
        PROXY_ARGS="--proxy $HTTP_PROXY"
        info "Using HTTP proxy: $HTTP_PROXY"
    fi
}

# ============================================================================
# Prerequisite Checks
# ============================================================================

check_prerequisites() {
    info "Checking prerequisites..."

    local errors=0

    # Required for building from source
    if [[ "${FROM_SOURCE:-false}" == "true" ]]; then
        if command_exists cargo; then
            success "cargo: $(cargo --version)"
        else
            error "cargo not found (required for source build)"
            ((errors++))
        fi

        if command_exists rustc; then
            local rustc_version
            rustc_version=$(rustc --version)
            if echo "$rustc_version" | grep -q nightly; then
                success "rustc: $rustc_version"
            else
                warn "rustc: $rustc_version (nightly recommended)"
            fi
        else
            error "rustc not found (required for source build)"
            ((errors++))
        fi
    fi

    # Required for operation
    if command_exists rsync; then
        success "rsync: available"
    else
        error "rsync not found"
        echo "  Install with: apt install rsync / brew install rsync"
        ((errors++))
    fi

    if command_exists ssh; then
        success "ssh: available"
    else
        error "ssh not found"
        ((errors++))
    fi

    # Optional but recommended
    if command_exists zstd; then
        success "zstd: available"
    else
        warn "zstd not found - compression will be slower"
    fi

    if [[ $errors -gt 0 ]]; then
        die "Prerequisites check failed with $errors errors"
    fi

    success "Prerequisites check passed"
}

# ============================================================================
# Worker Mode - Toolchain Verification
# ============================================================================

verify_worker_toolchain() {
    info "Verifying worker toolchain requirements..."

    local errors=0

    # Check rustup
    if command_exists rustup; then
        local rustup_version
        rustup_version=$(rustup --version 2>/dev/null | head -1)
        success "rustup: $rustup_version"
    else
        error "rustup: not found"
        echo "  Install with: curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh"
        ((errors++))
    fi

    # Check for Rust nightly
    if command_exists rustup && rustup toolchain list 2>/dev/null | grep -q "nightly"; then
        local nightly_version
        nightly_version=$(rustup run nightly rustc --version 2>/dev/null || echo "unknown")
        success "rust nightly: $nightly_version"
    else
        warn "rust nightly: not installed (recommended for full compatibility)"
        echo "  Install with: rustup toolchain install nightly"
    fi

    # Check GCC/Clang
    if command_exists gcc; then
        success "gcc: $(gcc --version | head -1)"
    elif command_exists clang; then
        success "clang: $(clang --version | head -1)"
    else
        error "No C compiler found (gcc or clang required)"
        ((errors++))
    fi

    # Check rsync
    if command_exists rsync; then
        success "rsync: $(rsync --version | head -1)"
    else
        error "rsync: not found"
        echo "  Install with: apt install rsync / brew install rsync"
        ((errors++))
    fi

    # Check zstd
    if command_exists zstd; then
        success "zstd: $(zstd --version 2>&1 | head -1)"
    else
        error "zstd: not found"
        echo "  Install with: apt install zstd / brew install zstd"
        ((errors++))
    fi

    # Check SSH server (for incoming connections)
    if [[ -f /etc/ssh/sshd_config ]] || command_exists sshd; then
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
# Installation Functions
# ============================================================================

create_directories() {
    info "Creating directories..."

    mkdir -p "$INSTALL_DIR"
    mkdir -p "$CONFIG_DIR"
    mkdir -p /tmp/rch

    success "Directories created"
}

build_from_source() {
    info "Building from source..."

    # Find project root
    local project_dir
    if [[ -f "Cargo.toml" ]] && grep -q "remote_compilation_helper" Cargo.toml 2>/dev/null; then
        project_dir="$(pwd)"
    elif [[ -f "$(dirname "${BASH_SOURCE[0]}")/Cargo.toml" ]]; then
        project_dir="$(dirname "${BASH_SOURCE[0]}")"
    else
        die "Cannot find RCH source directory. Run from project root or clone the repo first."
    fi

    cd "$project_dir"

    # Build release binaries
    if $USE_GUM; then
        spin "Building release binaries..." cargo +nightly build --release
    else
        info "Building release binaries (this may take a while)..."
        cargo +nightly build --release
    fi

    # Copy binaries - respect CARGO_TARGET_DIR if set
    local target_dir
    if [[ -n "${CARGO_TARGET_DIR:-}" ]]; then
        target_dir="$CARGO_TARGET_DIR/release"
    else
        target_dir="$project_dir/target/release"
    fi

    if [[ "$MODE" == "worker" ]]; then
        if [[ -f "$target_dir/$WORKER_BIN" ]]; then
            cp "$target_dir/$WORKER_BIN" "$INSTALL_DIR/"
            chmod +x "$INSTALL_DIR/$WORKER_BIN"
            success "Installed $WORKER_BIN"
        else
            die "Worker binary not found: $target_dir/$WORKER_BIN"
        fi
    else
        # Local mode: install hook and daemon
        for binary in "$HOOK_BIN" "$DAEMON_BIN"; do
            if [[ -f "$target_dir/$binary" ]]; then
                cp "$target_dir/$binary" "$INSTALL_DIR/"
                chmod +x "$INSTALL_DIR/$binary"
                success "Installed $binary"
            else
                die "Binary not found: $target_dir/$binary"
            fi
        done
    fi

    success "Build complete"
}

download_binaries() {
    # Try to download pre-built binaries first
    # If not available, automatically fall back to building from source

    info "Checking for pre-built binaries..."

    # Try to fetch the latest release
    local release_url="${GITHUB_API}/releases/latest"
    local release_info
    release_info=$(curl -sL --connect-timeout 10 $PROXY_ARGS "$release_url" 2>/dev/null || echo "")

    if [[ -z "$release_info" ]] || ! echo "$release_info" | grep -q '"tag_name"'; then
        warn "No pre-built binaries available yet"
        info "Falling back to building from source..."
        clone_and_build_from_source
        return
    fi

    # Check if there are assets for our platform
    local asset_name="rch-${TARGET}.tar.gz"
    if ! echo "$release_info" | grep -q "$asset_name"; then
        warn "No pre-built binary for $TARGET"
        info "Falling back to building from source..."
        clone_and_build_from_source
        return
    fi

    # Download and install the binary
    local tag_name
    tag_name=$(echo "$release_info" | sed -n 's/.*"tag_name": *"\([^"]*\)".*/\1/p' | head -1)
    local download_url="https://github.com/${GITHUB_REPO}/releases/download/${tag_name}/${asset_name}"

    TEMP_DIR=$(mktemp -d)
    trap 'rm -rf "$TEMP_DIR"; cleanup_lock' EXIT

    info "Downloading $asset_name..."
    if ! curl -fsSL $PROXY_ARGS "$download_url" -o "$TEMP_DIR/$asset_name" 2>/dev/null; then
        warn "Download failed"
        info "Falling back to building from source..."
        rm -rf "$TEMP_DIR"  # Clean up before fallback to avoid leak
        clone_and_build_from_source
        return
    fi

    # Extract and install
    info "Extracting binaries..."
    if ! tar -xzf "$TEMP_DIR/$asset_name" -C "$TEMP_DIR"; then
        warn "Failed to extract tarball"
        info "Falling back to building from source..."
        rm -rf "$TEMP_DIR"  # Clean up before fallback to avoid leak
        clone_and_build_from_source
        return
    fi

    if [[ "$MODE" == "worker" ]]; then
        if [[ -f "$TEMP_DIR/$WORKER_BIN" ]]; then
            install -m 755 "$TEMP_DIR/$WORKER_BIN" "$INSTALL_DIR/$WORKER_BIN"
            success "Installed $WORKER_BIN"
        else
            warn "Worker binary not in release"
            info "Falling back to building from source..."
            rm -rf "$TEMP_DIR"  # Clean up before fallback to avoid leak
            clone_and_build_from_source
            return
        fi
    else
        for binary in "$HOOK_BIN" "$DAEMON_BIN"; do
            if [[ -f "$TEMP_DIR/$binary" ]]; then
                install -m 755 "$TEMP_DIR/$binary" "$INSTALL_DIR/$binary"
                success "Installed $binary"
            else
                warn "$binary not in release"
                info "Falling back to building from source..."
                rm -rf "$TEMP_DIR"  # Clean up before fallback to avoid leak
                clone_and_build_from_source
                return
            fi
        done
    fi

    success "Binary installation complete"
}

clone_and_build_from_source() {
    # Clone the repository and build from source
    # This is the fallback when pre-built binaries aren't available

    ensure_command git

    # Check for Rust toolchain
    if ! command_exists cargo; then
        info "Rust toolchain not found. Installing via rustup..."
        if ! install_rust_toolchain; then
            die "Failed to install Rust. Please install manually: https://rustup.rs"
        fi
    fi

    TEMP_DIR=$(mktemp -d)
    trap 'rm -rf "$TEMP_DIR"; cleanup_lock' EXIT

    info "Cloning repository..."
    if $USE_GUM; then
        if ! spin "Cloning RCH repository..." git clone --depth 1 "$REPO_URL" "$TEMP_DIR/rch"; then
            die "Failed to clone repository from $REPO_URL"
        fi
    else
        if ! git clone --depth 1 "$REPO_URL" "$TEMP_DIR/rch"; then
            die "Failed to clone repository from $REPO_URL"
        fi
    fi

    cd "$TEMP_DIR/rch" || die "Failed to change to cloned repository directory"

    # Build release binaries
    if $USE_GUM; then
        if ! spin "Building release binaries (this may take a few minutes)..." cargo +nightly build --release; then
            die "Build failed. Check that Rust nightly is installed: rustup toolchain install nightly"
        fi
    else
        info "Building release binaries (this may take a few minutes)..."
        if ! cargo +nightly build --release; then
            die "Build failed. Check that Rust nightly is installed: rustup toolchain install nightly"
        fi
    fi

    # Install binaries - respect CARGO_TARGET_DIR if set
    local target_dir
    if [[ -n "${CARGO_TARGET_DIR:-}" ]]; then
        target_dir="$CARGO_TARGET_DIR/release"
    else
        target_dir="$TEMP_DIR/rch/target/release"
    fi

    if [[ "$MODE" == "worker" ]]; then
        if [[ -f "$target_dir/$WORKER_BIN" ]]; then
            install -m 755 "$target_dir/$WORKER_BIN" "$INSTALL_DIR/$WORKER_BIN"
            success "Installed $WORKER_BIN"
        else
            die "Worker binary not found after build"
        fi
    else
        for binary in "$HOOK_BIN" "$DAEMON_BIN"; do
            if [[ -f "$target_dir/$binary" ]]; then
                install -m 755 "$target_dir/$binary" "$INSTALL_DIR/$binary"
                success "Installed $binary"
            else
                die "Binary not found after build: $binary"
            fi
        done
    fi

    success "Build from source complete"
}

install_rust_toolchain() {
    # Install Rust via rustup if not present
    if command_exists rustup; then
        info "rustup found, ensuring nightly toolchain..."
        rustup toolchain install nightly 2>/dev/null || true
        return 0
    fi

    info "Installing Rust via rustup..."
    # Note: rustup respects HTTPS_PROXY/HTTP_PROXY environment variables automatically
    if curl --proto '=https' --tlsv1.2 -sSf $PROXY_ARGS https://sh.rustup.rs | sh -s -- -y --default-toolchain nightly; then
        # Source cargo env for current session
        if [[ -f "$HOME/.cargo/env" ]]; then
            source "$HOME/.cargo/env"
        fi
        success "Rust installed successfully"
        return 0
    else
        return 1
    fi
}

# ============================================================================
# Checksum Verification
# ============================================================================

verify_checksum() {
    local file="$1"
    local checksum_file="$2"
    local filename="$3"

    info "Verifying checksum..."

    local expected
    expected=$(grep "$filename" "$checksum_file" | awk '{print $1}')

    if [[ -z "$expected" ]]; then
        error "Checksum not found for $filename"
        return 1
    fi

    local computed
    if command_exists sha256sum; then
        computed=$(sha256sum "$file" | awk '{print $1}')
    elif command_exists shasum; then
        computed=$(shasum -a 256 "$file" | awk '{print $1}')
    else
        error "No SHA256 tool found (sha256sum or shasum required)"
        return 1
    fi

    if [[ "$expected" != "$computed" ]]; then
        error "Checksum verification failed!"
        error "  Expected: $expected"
        error "  Got:      $computed"
        return 1
    fi

    success "Checksum verified"
}

# ============================================================================
# Version Detection
# ============================================================================

detect_target_version() {
    # If VERSION already set (e.g., from environment), use it
    if [[ -n "${VERSION:-}" ]]; then
        return 0
    fi

    # If building from source, read from Cargo.toml
    if [[ "${FROM_SOURCE:-false}" == "true" ]] || \
       { [[ -f "Cargo.toml" ]] && grep -q "remote_compilation_helper" Cargo.toml 2>/dev/null; }; then
        local cargo_version=""

        # Check if this is a Cargo workspace (root Cargo.toml has [workspace])
        # In workspaces, version is often defined in [workspace.package] section
        if [[ -f "Cargo.toml" ]] && grep -q '^\[workspace\]' Cargo.toml 2>/dev/null; then
            # Extract version from [workspace.package] section using awk
            cargo_version=$(awk '
                /^\[workspace\.package\]/ { in_section=1; next }
                /^\[/ { in_section=0 }
                in_section && /^version[[:space:]]*=[[:space:]]*"/ {
                    gsub(/^version[[:space:]]*=[[:space:]]*"/, "")
                    gsub(/".*$/, "")
                    print
                    exit
                }
            ' Cargo.toml)
        fi

        # If workspace extraction failed or not a workspace, try direct extraction
        if [[ -z "$cargo_version" ]]; then
            if [[ -f "rch/Cargo.toml" ]]; then
                cargo_version=$(sed -n 's/^version = "\(.*\)"/\1/p' rch/Cargo.toml | head -1)
            fi
        fi

        # Last resort: try root Cargo.toml with simple pattern
        if [[ -z "$cargo_version" ]] && [[ -f "Cargo.toml" ]]; then
            cargo_version=$(sed -n 's/^version = "\(.*\)"/\1/p' Cargo.toml | head -1)
        fi

        if [[ -n "$cargo_version" ]]; then
            VERSION="$cargo_version"
            return 0
        fi
    fi

    # If offline tarball, try to extract from filename
    if [[ -n "${OFFLINE_TARBALL:-}" ]]; then
        local tarball_version
        tarball_version=$(echo "$OFFLINE_TARBALL" | sed -n 's/.*rch-v\?\([0-9][0-9.]*\).*/\1/p')
        if [[ -n "$tarball_version" ]]; then
            VERSION="$tarball_version"
            return 0
        fi
    fi

    # Try to fetch latest from GitHub (with timeout)
    local latest
    latest=$(curl -sL --connect-timeout 5 "${GITHUB_API}/releases/latest" 2>/dev/null | \
             sed -n 's/.*"tag_name": *"v\?\([^"]*\)".*/\1/p' | head -1)
    if [[ -n "$latest" ]]; then
        VERSION="$latest"
        return 0
    fi

    # Fallback to installer version
    VERSION="$INSTALLER_VERSION"
}

# ============================================================================
# Upgrade Detection
# ============================================================================

check_existing_install() {
    if [[ -x "$INSTALL_DIR/rch" ]]; then
        local current
        current=$("$INSTALL_DIR/rch" --version 2>/dev/null | head -1 | sed 's/rch //' || echo "")
        if [[ -n "$current" ]]; then
            EXISTING_VERSION="$current"
            if $USE_GUM; then
                gum style \
                    --border rounded \
                    --border-foreground 208 \
                    --padding "0 2" \
                    "Upgrading RCH" \
                    "Current: v$current" \
                    "Target:  v$VERSION"
            else
                draw_box "1;33" \
                    "Upgrading RCH" \
                    "Current: v$current" \
                    "Target:  v$VERSION"
            fi
            return 0
        fi
    fi
    EXISTING_VERSION=""
    return 1
}

# ============================================================================
# Sigstore Verification
# ============================================================================

verify_sigstore_bundle() {
    local file="$1"
    local artifact_url="$2"

    # Check if cosign is available
    if ! command_exists cosign; then
        warn "cosign not found; skipping Sigstore signature verification"
        info "Install cosign for enhanced security: https://docs.sigstore.dev/cosign/installation/"
        return 0
    fi

    local bundle_url="${artifact_url}.sigstore.json"
    local bundle_file="${file}.sigstore.json"

    info "Downloading Sigstore bundle..."
    if ! curl -fsSL $PROXY_ARGS "$bundle_url" -o "$bundle_file" 2>/dev/null; then
        warn "Could not download Sigstore bundle; skipping signature verification"
        return 0
    fi

    info "Verifying Sigstore signature..."
    if cosign verify-blob --bundle "$bundle_file" \
        --certificate-identity-regexp=".*" \
        --certificate-oidc-issuer-regexp=".*" \
        "$file" 2>/dev/null; then
        success "Sigstore signature verified"
        rm -f "$bundle_file"
        return 0
    else
        error "Sigstore signature verification failed!"
        rm -f "$bundle_file"
        return 1
    fi
}

# ============================================================================
# Skill Installation
# ============================================================================

install_skill() {
    local claude_dest="$HOME/.claude/skills/rch"
    local codex_dest="$HOME/.codex/skills/rch"
    local installed_claude=false
    local installed_codex=false

    info "Installing RCH skill for AI coding agents..."

    # Create both skill directories
    mkdir -p "$claude_dest/references"
    mkdir -p "$codex_dest/references"

    # Try to download skill from release assets
    local skill_url="https://github.com/${GITHUB_REPO}/releases/latest/download/skill.tar.gz"
    local skill_temp="${TEMP_DIR:-/tmp}/skill.tar.gz"

    if curl -fsSL $PROXY_ARGS "$skill_url" -o "$skill_temp" 2>/dev/null; then
        # Install to Claude skills folder
        if tar -xzf "$skill_temp" -C "$HOME/.claude/skills" 2>/dev/null; then
            installed_claude=true
        fi
        # Install to Codex skills folder
        if tar -xzf "$skill_temp" -C "$HOME/.codex/skills" 2>/dev/null; then
            installed_codex=true
        fi
        rm -f "$skill_temp"

        if $installed_claude || $installed_codex; then
            [[ $installed_claude == true ]] && success "Installed RCH skill to $claude_dest"
            [[ $installed_codex == true ]] && success "Installed RCH skill to $codex_dest"
            show_skill_info "$installed_claude" "$installed_codex"
            return 0
        fi
    fi

    # Fallback: create minimal skill inline
    info "Creating minimal skill (download failed)..."

    local skill_content
    skill_content=$(cat << 'SKILL_EOF'
---
name: rch
description: >-
  Remote compilation helper. Use when: rch doctor, workers.toml, "no workers",
  "compilation slow", fleet deploy, self-test, or offload cargo/gcc/bun.
---

# RCH — Remote Compilation Helper

Transparently offloads `cargo build`, `bun test`, `gcc` to remote workers. Same commands, faster builds.

<!-- TOC: Diagnosis | Quick Fixes | Worker Config | Install | Commands | Debug | References -->

## Diagnosis Loop

```bash
rch doctor              # What's broken?
rch doctor --fix        # Auto-fix common issues
rch doctor --verbose    # All checks passed? Ready to use
```

**If `--fix` can't solve it → see Quick Fixes or references.**

---

## Quick Fixes (Copy-Paste)

| Symptom | Command |
|---------|---------|
| SSH auth fails | `eval $(ssh-agent) && ssh-add ~/.ssh/your_key` |
| Daemon not running | `rm -f /tmp/rch.sock && rchd &` |
| Hook not installed | `rch hook install --force` |
| No workers available | `vim ~/.config/rch/workers.toml` (add workers) |
| Socket permission | `rm /tmp/rch.sock && rchd` |
| Stale socket | `lsof /tmp/rch.sock` → kill stale process |

---

## Worker Config (`~/.config/rch/workers.toml`)

```toml
[[workers]]
id = "builder"
host = "192.168.1.100"        # IP or hostname
user = "ubuntu"
identity_file = "~/.ssh/id_ed25519"
total_slots = 8               # ≈ CPU cores - 2
priority = 100                # Higher = preferred
tags = ["rust", "bun"]        # Optional capabilities
```

### Auto-Discover from SSH Config

```bash
rch workers discover --from-ssh-config --dry-run  # Preview
rch workers discover --from-ssh-config            # Add to config
```

### Verify Workers

```bash
rch workers probe --all         # Test all workers
rch workers probe worker1 -v    # Test single, verbose
rch workers list                # Show status
```

---

## Commands

- `rch doctor` - Diagnose issues
- `rch status` - Show daemon status
- `rch workers probe --all` - Test all workers
- `rch workers discover --from-ssh-config` - Auto-discover workers
- `rch fleet status` - Show all workers
- `rch self-test` - Full end-to-end verification

---

## Fleet Operations

```bash
rch fleet status             # Show all workers
rch fleet preflight --all    # Verify workers ready
rch fleet deploy --all       # Deploy rch-wkr to workers
rch self-test                # Full end-to-end verification
```

---

## Anti-Patterns

| Don't | Why | Do Instead |
|-------|-----|------------|
| Run daemon as root | Security risk | `systemctl --user start rchd` |
| Skip `rch doctor` | Miss config issues | Always verify first |
| Use `--force` blindly | May break hook | Check `rch hook status` first |
| Ignore transfer errors | Indicates network/disk issues | Check worker disk space, network |

---

## Debug

```bash
RCH_LOG=debug cargo build    # Show hook decisions
RCH_DRY_RUN=1 cargo check    # Test without remote execution
rch doctor --json > diag.json  # Export diagnostics
```

---

## Docs

Full documentation: https://github.com/Dicklesworthstone/remote_compilation_helper
SKILL_EOF
)

    # Write to both destinations
    echo "$skill_content" > "$claude_dest/SKILL.md"
    installed_claude=true
    echo "$skill_content" > "$codex_dest/SKILL.md"
    installed_codex=true

    success "Created RCH skill at $claude_dest"
    success "Created RCH skill at $codex_dest"
    show_skill_info "$installed_claude" "$installed_codex"
}

# Show info about the installed skill
show_skill_info() {
    local installed_claude="${1:-true}"
    local installed_codex="${2:-false}"

    echo ""

    # Build location lines based on what was installed
    local loc_lines=()
    [[ "$installed_claude" == "true" ]] && loc_lines+=("  📂 Claude Code:  ~/.claude/skills/rch/")
    [[ "$installed_codex" == "true" ]] && loc_lines+=("  📂 Codex CLI:    ~/.codex/skills/rch/")

    if $USE_GUM; then
        gum style \
            --border rounded \
            --border-foreground 141 \
            --padding "1 2" \
            --align left \
            "🤖 AI Agent Skills Installed" \
            "" \
            "The RCH skill is now available to AI coding agents." \
            "It provides setup guidance, troubleshooting, and quick fixes." \
            "" \
            "Installed to:" \
            "${loc_lines[@]}" \
            "" \
            "How Skills Work:" \
            "  When you describe an RCH problem to your AI agent," \
            "  the skill activates automatically. No slash commands" \
            "  needed—just describe the issue naturally:" \
            "" \
            "    \"rch doctor is showing errors\"" \
            "    \"no workers available\"" \
            "    \"how do I add a new worker?\"" \
            "" \
            "  The agent will use the skill's knowledge to help." \
            "" \
            "Trigger phrases: rch doctor, workers.toml, fleet deploy," \
            "                 no workers, compilation slow, self-test"
    else
        echo ""
        if $USE_COLOR; then
            echo -e "${BOLD}${CYAN}╭───────────────────────────────────────────────────────────╮${NC}"
            echo -e "${BOLD}${CYAN}│${NC}  ${BOLD}🤖 AI Agent Skills Installed${NC}                             ${BOLD}${CYAN}│${NC}"
            echo -e "${BOLD}${CYAN}╰───────────────────────────────────────────────────────────╯${NC}"
        else
            echo "╭───────────────────────────────────────────────────────────╮"
            echo "│  AI Agent Skills Installed                                │"
            echo "╰───────────────────────────────────────────────────────────╯"
        fi
        echo ""
        echo "  The RCH skill is now available to AI coding agents."
        echo "  It provides setup guidance, troubleshooting, and quick fixes."
        echo ""
        echo "  Installed to:"
        for line in "${loc_lines[@]}"; do
            echo "$line"
        done
        echo ""
        if $USE_COLOR; then
            echo -e "  ${BOLD}How Skills Work:${NC}"
        else
            echo "  How Skills Work:"
        fi
        echo "  ─────────────────"
        echo "  When you describe an RCH problem to your AI agent,"
        echo "  the skill activates automatically. No slash commands"
        echo "  needed—just describe the issue naturally:"
        echo ""
        if $USE_COLOR; then
            echo -e "    ${DIM}\"rch doctor is showing errors\"${NC}"
            echo -e "    ${DIM}\"no workers available\"${NC}"
            echo -e "    ${DIM}\"how do I add a new worker?\"${NC}"
        else
            echo "    \"rch doctor is showing errors\""
            echo "    \"no workers available\""
            echo "    \"how do I add a new worker?\""
        fi
        echo ""
        echo "  The agent will use the skill's knowledge to help."
        echo ""
        if $USE_COLOR; then
            echo -e "  ${BOLD}Trigger phrases:${NC} rch doctor, workers.toml, fleet deploy,"
        else
            echo "  Trigger phrases: rch doctor, workers.toml, fleet deploy,"
        fi
        echo "                   no workers, compilation slow, self-test"
    fi
}

# ============================================================================
# Offline Installation
# ============================================================================

install_from_tarball() {
    local tarball="$1"

    if [[ ! -f "$tarball" ]]; then
        die "Tarball not found: $tarball"
    fi

    info "Installing from offline tarball: $tarball"

    TEMP_DIR=$(mktemp -d)
    trap 'rm -rf "$TEMP_DIR"; cleanup_lock' EXIT

    # Extract tarball
    if $USE_GUM; then
        spin "Extracting tarball..." tar -xzf "$tarball" -C "$TEMP_DIR"
    else
        info "Extracting tarball..."
        tar -xzf "$tarball" -C "$TEMP_DIR"
    fi

    # Install binaries from tarball
    if [[ "$MODE" == "worker" ]]; then
        if [[ -f "$TEMP_DIR/$WORKER_BIN" ]]; then
            install -m 755 "$TEMP_DIR/$WORKER_BIN" "$INSTALL_DIR/$WORKER_BIN"
            success "Installed $WORKER_BIN"
        else
            die "Worker binary not found in tarball"
        fi
    else
        for binary in "$HOOK_BIN" "$DAEMON_BIN"; do
            if [[ -f "$TEMP_DIR/$binary" ]]; then
                install -m 755 "$TEMP_DIR/$binary" "$INSTALL_DIR/$binary"
                success "Installed $binary"
            else
                warn "$binary not found in tarball"
            fi
        done
    fi

    success "Offline installation complete"
}

install_binaries() {
    # Check for offline tarball first
    if [[ -n "${OFFLINE_TARBALL:-}" ]]; then
        install_from_tarball "$OFFLINE_TARBALL"
        return
    fi

    if [[ "${FROM_SOURCE:-false}" == "true" ]]; then
        build_from_source
    else
        # Try source first (if we're in the repo), otherwise download
        if [[ -f "Cargo.toml" ]] && grep -q "remote_compilation_helper" Cargo.toml 2>/dev/null; then
            info "Found source directory, building from source..."
            FROM_SOURCE=true
            build_from_source
        else
            # Try binary download (handles fallback to source build internally)
            download_binaries
        fi
    fi
}

# ============================================================================
# Configuration
# ============================================================================

generate_default_config() {
    local daemon_config="$CONFIG_DIR/daemon.toml"
    local workers_config="$CONFIG_DIR/workers.toml"

    if [[ ! -f "$daemon_config" ]]; then
        info "Generating default daemon configuration..."
        cat > "$daemon_config" << 'EOF'
# RCH Daemon Configuration
# See: https://github.com/Dicklesworthstone/remote_compilation_helper

# Unix socket path for hook communication.
# Default: $XDG_RUNTIME_DIR/rch.sock (if available), else ~/.cache/rch/rch.sock
# Uncomment to override:
# socket_path = "/tmp/rch.sock"

# Health check interval in seconds
health_check_interval_secs = 30

# Worker timeout before marking as unreachable (seconds)
worker_timeout_secs = 10

# Maximum concurrent jobs per worker slot
max_jobs_per_slot = 1

# Enable SSH connection pooling
connection_pooling = true

# Log level: trace, debug, info, warn, error
log_level = "info"
EOF
        success "Created $daemon_config"
    else
        info "Daemon config already exists: $daemon_config"
    fi

    if [[ ! -f "$workers_config" ]]; then
        info "Generating example workers configuration..."
        cat > "$workers_config" << 'EOF'
# RCH Workers Configuration
# Define your remote compilation workers here.
# Uncomment and modify the examples below.

# Example worker definition:
# [[workers]]
# id = "server1"
# host = "192.168.1.100"
# user = "ubuntu"
# identity_file = "~/.ssh/id_rsa"
# total_slots = 16
# priority = 100
# tags = ["rust", "fast"]
# enabled = true

# [[workers]]
# id = "server2"
# host = "192.168.1.101"
# user = "ubuntu"
# identity_file = "~/.ssh/id_rsa"
# total_slots = 8
# priority = 80
# tags = ["rust"]
# enabled = true
EOF
        success "Created $workers_config"
        warn "Edit $workers_config to add your workers"
    else
        info "Workers config already exists: $workers_config"
    fi
}

# ============================================================================
# Claude Code Hook Integration
# ============================================================================

get_claude_code_settings_path() {
    local paths=(
        "$HOME/.claude/settings.json"
        "$HOME/.config/claude/settings.json"
        "$HOME/Library/Application Support/Claude/settings.json"
    )

    for path in "${paths[@]}"; do
        if [[ -f "$path" ]]; then
            echo "$path"
            return 0
        fi
    done

    echo "$HOME/.claude/settings.json"
}

configure_claude_hook() {
    if [[ -n "${RCH_NO_HOOK:-}" ]]; then
        info "Skipping Claude Code hook setup (RCH_NO_HOOK set)"
        return
    fi

    info "Configuring Claude Code hook..."

    local settings_path
    settings_path=$(get_claude_code_settings_path)
    local settings_dir
    settings_dir=$(dirname "$settings_path")

    mkdir -p "$settings_dir"

    local hook_path="$INSTALL_DIR/$HOOK_BIN"

    if command_exists jq; then
        configure_hook_with_jq "$settings_path" "$hook_path"
    else
        configure_hook_manual "$settings_path" "$hook_path"
    fi
}

configure_hook_with_jq() {
    local settings_path="$1"
    local hook_path="$2"

    local hook_config
    hook_config=$(cat << EOF
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "Bash",
        "hooks": [
          {
            "type": "command",
            "command": "$hook_path"
          }
        ]
      }
    ]
  }
}
EOF
)

    if [[ -f "$settings_path" ]]; then
        local existing
        existing=$(cat "$settings_path")

        # Validate existing JSON; if empty or invalid, treat as new file
        if [[ -z "$existing" ]] || ! echo "$existing" | jq -e '.' &>/dev/null; then
            warn "Existing settings file is empty or invalid, creating fresh config"
            echo "$hook_config" | jq '.' > "$settings_path"
            success "Claude Code hook configured at $settings_path"
            return
        fi

        if echo "$existing" | jq -e '.hooks.PreToolUse' &>/dev/null; then
            # Check if rch hook already exists (look for rch in any command field)
            if echo "$existing" | jq -e '.hooks.PreToolUse[] | select(.hooks[]? | .command? | contains("rch"))' &>/dev/null; then
                info "RCH hook already configured"
                return
            fi

            local new_hook='{"matcher": "Bash", "hooks": [{"type": "command", "command": "'"$hook_path"'"}]}'
            echo "$existing" | jq ".hooks.PreToolUse += [$new_hook]" > "$settings_path"
        else
            # Use * for deep merge to preserve other hooks (e.g., PostToolUse)
            echo "$existing" | jq ". * $hook_config" > "$settings_path"
        fi
    else
        echo "$hook_config" | jq '.' > "$settings_path"
    fi

    success "Claude Code hook configured at $settings_path"
}

configure_hook_manual() {
    local settings_path="$1"
    local hook_path="$2"

    warn "jq not found - manual hook configuration required"

    echo ""
    echo -e "${BOLD}Add this to your Claude Code settings ($settings_path):${NC}"
    echo ""
    echo '{'
    echo '  "hooks": {'
    echo '    "PreToolUse": ['
    echo '      {'
    echo '        "matcher": "Bash",'
    echo '        "hooks": ['
    echo '          {'
    echo '            "type": "command",'
    echo "            \"command\": \"$hook_path\""
    echo '          }'
    echo '        ]'
    echo '      }'
    echo '    ]'
    echo '  }'
    echo '}'
    echo ""
}

# ============================================================================
# Service Opt-In Prompt
# ============================================================================

maybe_prompt_service() {
    if [[ "$MODE" == "worker" ]]; then
        ENABLE_SERVICE="false"
        return
    fi

    if [[ "${NO_SERVICE:-}" == "true" ]]; then
        ENABLE_SERVICE="false"
        return
    fi

    local service_manager=""
    service_manager="$(detect_service_manager 2>/dev/null || true)"
    if [[ -z "$service_manager" ]]; then
        ENABLE_SERVICE="false"
        if [[ "${EASY_MODE:-}" == "true" ]] || [[ "${YES:-}" == "true" ]] || [[ "${INSTALL_SERVICE:-}" == "true" ]]; then
            warn "Background service requested but no supported service manager detected; continuing without service."
        else
            info "No supported service manager detected - skipping background service setup"
        fi
        return
    fi

    if [[ "${INSTALL_SERVICE:-}" == "true" ]]; then
        ENABLE_SERVICE="true"
        return
    fi

    if [[ "${EASY_MODE:-}" == "true" ]] || [[ "${YES:-}" == "true" ]]; then
        ENABLE_SERVICE="true"
        return
    fi

    if ! is_interactive; then
        ENABLE_SERVICE="false"
        info "Non-interactive install without opt-in; skipping background daemon setup (use --install-service or --easy-mode)."
        return
    fi

    if confirm "Run rchd automatically in the background? (falls back to local if unavailable)"; then
        ENABLE_SERVICE="true"
    else
        ENABLE_SERVICE="false"
        info "Skipping background daemon setup (you can run 'rch daemon start' later)."
    fi
}

# ============================================================================
# Systemd/Launchd Service
# ============================================================================

setup_systemd_service() {
    if [[ "$MODE" == "worker" ]]; then
        return
    fi

    if ! systemd_user_available; then
        info "systemd user service unavailable - skipping service setup"
        return
    fi

    # Skip only if explicitly disabled
    if [[ "${NO_SERVICE:-}" == "true" ]]; then
        info "Skipping systemd service setup (--no-service)"
        return
    fi

    if [[ "${ENABLE_SERVICE:-true}" != "true" ]]; then
        info "Skipping systemd service setup (background daemon disabled)"
        return
    fi

    info "Setting up systemd service..."

    local service_file="$HOME/.config/systemd/user/rchd.service"
    mkdir -p "$(dirname "$service_file")"

    cat > "$service_file" << EOF
[Unit]
Description=RCH Remote Compilation Helper Daemon
After=network.target network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=$INSTALL_DIR/$DAEMON_BIN --foreground --workers-config $CONFIG_DIR/workers.toml
Restart=always
RestartSec=5
Environment=RUST_LOG=info

[Install]
WantedBy=default.target
EOF

    systemctl --user daemon-reload
    systemctl --user enable --now rchd.service || systemctl --user enable rchd.service

    success "Systemd service installed: rchd.service"

    # Enable lingering for reboot persistence (requires sudo)
    local current_user
    current_user=$(whoami)
    if command_exists loginctl; then
        if loginctl show-user "$current_user" 2>/dev/null | grep -q "Linger=yes"; then
            info "Lingering already enabled for $current_user"
        else
            info "Enabling lingering for $current_user (for reboot persistence)..."
            if sudo -n loginctl enable-linger "$current_user" 2>/dev/null; then
                success "Lingering enabled - service will start on boot"
            else
                warn "Could not enable lingering automatically"
                warn "Run: sudo loginctl enable-linger $current_user"
            fi
        fi
    fi

    # Start or restart the service if it is not already running
    if ! systemctl --user is-active rchd.service &>/dev/null; then
        info "Starting rchd service..."
        if systemctl --user start rchd.service; then
            success "rchd service started"
        else
            warn "Could not start rchd service automatically"
            info "Start manually with: systemctl --user start rchd"
        fi
    fi

    info "Check status: systemctl --user status rchd"
    info "Follow logs:  journalctl --user -u rchd -f"
}

setup_launchd_service() {
    if [[ "$MODE" == "worker" ]]; then
        return
    fi

    if [[ "$(uname -s)" != "Darwin" ]]; then
        return
    fi

    if ! command_exists launchctl; then
        info "launchctl not found - skipping service setup"
        return
    fi

    # Skip only if explicitly disabled
    if [[ "${NO_SERVICE:-}" == "true" ]]; then
        info "Skipping launchd service setup (--no-service)"
        return
    fi

    if [[ "${ENABLE_SERVICE:-true}" != "true" ]]; then
        info "Skipping launchd service setup (background daemon disabled)"
        return
    fi

    info "Setting up launchd service..."

    local plist_file="$HOME/Library/LaunchAgents/com.rch.daemon.plist"
    mkdir -p "$(dirname "$plist_file")"
    mkdir -p "$CONFIG_DIR/logs"

    # Unload existing service if present
    if launchctl list 2>/dev/null | grep -q "com.rch.daemon"; then
        info "Unloading existing service..."
        launchctl unload "$plist_file" 2>/dev/null || true
    fi

    cat > "$plist_file" << EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.rch.daemon</string>
    <key>ProgramArguments</key>
    <array>
        <string>$INSTALL_DIR/$DAEMON_BIN</string>
        <string>--foreground</string>
        <string>--workers-config</string>
        <string>$CONFIG_DIR/workers.toml</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
    <key>EnvironmentVariables</key>
    <dict>
        <key>RUST_LOG</key>
        <string>info</string>
    </dict>
    <key>StandardOutPath</key>
    <string>$CONFIG_DIR/logs/daemon.log</string>
    <key>StandardErrorPath</key>
    <string>$CONFIG_DIR/logs/daemon.err</string>
</dict>
</plist>
EOF

    success "Launchd service installed: $plist_file"

    # Load and start the service
    info "Loading launchd service..."
    if launchctl load "$plist_file" 2>/dev/null; then
        success "rchd service loaded and started"
        info "Service will start automatically on login"
    else
        warn "Could not load launchd service automatically"
        info "Load manually with: launchctl load $plist_file"
    fi

    info "Check status: launchctl list | grep rch"
}

# ============================================================================
# PATH Setup
# ============================================================================

setup_path() {
    if [[ ":$PATH:" == *":$INSTALL_DIR:"* ]]; then
        info "$INSTALL_DIR already in PATH"
        return 0
    fi

    warn "$INSTALL_DIR is not in PATH"

    local shell_rc=""
    case "${SHELL:-/bin/bash}" in
        */bash) shell_rc="$HOME/.bashrc" ;;
        */zsh)  shell_rc="$HOME/.zshrc" ;;
        */fish) shell_rc="$HOME/.config/fish/config.fish" ;;
        *)      shell_rc="$HOME/.profile" ;;
    esac

    local path_line="export PATH=\"$INSTALL_DIR:\$PATH\""

    if [[ -f "$shell_rc" ]] && grep -qF "$INSTALL_DIR" "$shell_rc"; then
        info "PATH already configured in $shell_rc"
        return 0
    fi

    if [[ "${EASY_MODE:-}" == "true" ]] || confirm "Add $INSTALL_DIR to PATH in $shell_rc?"; then
        echo "" >> "$shell_rc"
        echo "# RCH - Remote Compilation Helper" >> "$shell_rc"
        echo "$path_line" >> "$shell_rc"
        success "PATH configured in $shell_rc"
        warn "Run 'source $shell_rc' or restart your shell"
    fi
}

# ============================================================================
# Shell Completions
# ============================================================================

setup_shell_completions() {
    if [[ "$MODE" == "worker" ]]; then
        return
    fi

    info "Setting up shell completions..."

    local rch_bin="$INSTALL_DIR/$HOOK_BIN"
    if [[ ! -x "$rch_bin" ]]; then
        warn "RCH binary not found, skipping completion setup"
        return
    fi

    local current_shell
    current_shell=$(basename "${SHELL:-}")

    case "$current_shell" in
        bash)
            if "$rch_bin" completions install bash 2>/dev/null; then
                success "Installed bash completions"
            else
                warn "Could not install bash completions"
            fi
            ;;
        zsh)
            if "$rch_bin" completions install zsh 2>/dev/null; then
                success "Installed zsh completions"
            else
                warn "Could not install zsh completions"
            fi
            ;;
        fish)
            if "$rch_bin" completions install fish 2>/dev/null; then
                success "Installed fish completions"
            else
                warn "Could not install fish completions"
            fi
            ;;
        *)
            info "Unknown shell ($current_shell), skipping completion setup"
            info "Run 'rch completions install <shell>' manually to set up completions"
            ;;
    esac
}

# ============================================================================
# Post-Install Doctor Check
# ============================================================================

run_doctor() {
    if [[ "${RCH_SKIP_DOCTOR:-}" == "1" ]]; then
        info "Skipping doctor check (RCH_SKIP_DOCTOR=1)"
        return 0
    fi

    if [[ "$MODE" == "worker" ]]; then
        return 0
    fi

    info "Running post-install diagnostics..."

    local rch_bin="$INSTALL_DIR/$HOOK_BIN"
    if [[ -x "$rch_bin" ]]; then
        if "$rch_bin" doctor 2>&1; then
            success "Doctor check passed"
        else
            warn "Doctor check reported issues (this may be expected on fresh install)"
        fi
    else
        warn "Cannot run doctor: rch binary not found"
    fi
}

# ============================================================================
# Easy Mode: Agent Detection
# ============================================================================

detect_agents() {
    info "Detecting AI coding agents..."

    local rch_bin="$INSTALL_DIR/$HOOK_BIN"
    if [[ -x "$rch_bin" ]]; then
        "$rch_bin" agents detect 2>&1 || true
    else
        # Manual detection
        local agents_found=0

        if command_exists claude; then
            success "Claude Code: detected"
            ((agents_found++))
        fi

        if [[ -d "$HOME/.cursor" ]] || command_exists cursor; then
            success "Cursor: detected"
            ((agents_found++))
        fi

        if command_exists codex; then
            success "Codex CLI: detected"
            ((agents_found++))
        fi

        if [[ $agents_found -eq 0 ]]; then
            warn "No AI coding agents detected"
        fi
    fi
}

# ============================================================================
# Uninstall
# ============================================================================

uninstall() {
    info "Uninstalling RCH..."

    # Stop daemon if running via systemd
    if command_exists systemctl; then
        systemctl --user stop rchd.service 2>/dev/null || true
        systemctl --user disable rchd.service 2>/dev/null || true
        rm -f "$HOME/.config/systemd/user/rchd.service"
        systemctl --user daemon-reload 2>/dev/null || true
    fi

    # Stop launchd service on macOS
    if [[ "$(uname -s)" == "Darwin" ]]; then
        local plist_file="$HOME/Library/LaunchAgents/com.rch.daemon.plist"
        if [[ -f "$plist_file" ]]; then
            launchctl unload "$plist_file" 2>/dev/null || true
            rm -f "$plist_file"
        fi
    fi

    # Remove binaries
    rm -f "$INSTALL_DIR/$HOOK_BIN"
    rm -f "$INSTALL_DIR/$DAEMON_BIN"
    rm -f "$INSTALL_DIR/$WORKER_BIN"

    # Remove socket
    rm -f "$SOCKET_PATH"

    success "Binaries removed"

    echo ""
    echo -e "${YELLOW}Config files preserved at: $CONFIG_DIR${NC}"
    echo "To remove config: rm -rf $CONFIG_DIR"
    echo ""
    echo "To remove Claude Code hook, edit your settings and remove the RCH hook entry."
}

# ============================================================================
# Verification
# ============================================================================

verify_installation() {
    info "Verifying installation..."

    local failed=0

    if [[ "$MODE" == "worker" ]]; then
        if [[ -x "$INSTALL_DIR/$WORKER_BIN" ]]; then
            local version
            version=$("$INSTALL_DIR/$WORKER_BIN" --version 2>/dev/null | head -1 || echo "unknown")
            success "$WORKER_BIN: $version"
        else
            error "Worker binary not found or not executable"
            ((failed++))
        fi
    else
        for binary in "$HOOK_BIN" "$DAEMON_BIN"; do
            local path="$INSTALL_DIR/$binary"
            if [[ -x "$path" ]]; then
                local version
                version=$("$path" --version 2>/dev/null | head -1 || echo "unknown")
                success "$binary: $version"
            else
                error "$binary: not found or not executable"
                ((failed++))
            fi
        done

        if [[ ! -f "$CONFIG_DIR/daemon.toml" ]]; then
            error "Daemon config not found"
            ((failed++))
        fi
    fi

    if [[ $failed -gt 0 ]]; then
        die "Installation verification failed with $failed errors"
    fi

    success "Installation verified"
}

# ============================================================================
# Summary
# ============================================================================

print_summary() {
    echo ""
    if $USE_GUM; then
        gum style \
            --border double \
            --border-foreground 82 \
            --padding "1 3" \
            --align center \
            "✅ Installation Complete!"
    else
        draw_box "1;32" \
            "Installation Complete!" \
            "" \
            "RCH is ready to use"
    fi
    echo ""

    # Installation details
    if $USE_COLOR; then
        echo -e "${BOLD}Installation Details:${NC}"
    else
        echo "Installation Details:"
    fi
    echo ""
    echo "  📁 Binaries:    $INSTALL_DIR"
    echo "  ⚙️  Config:      $CONFIG_DIR"
    echo ""

    if [[ "$MODE" == "worker" ]]; then
        echo "  🔧 Worker binary: $INSTALL_DIR/$WORKER_BIN"
    else
        echo "  📦 Installed:"
        echo "      • rch     (hook CLI)"
        echo "      • rchd    (daemon)"
        echo ""

        if [[ "${ENABLE_SERVICE:-true}" == "true" ]] && [[ "${NO_SERVICE:-}" != "true" ]]; then
            if systemd_user_available; then
                # Check if daemon is actually running
                local daemon_status="unknown"
                if systemctl --user is-active rchd.service &>/dev/null; then
                    daemon_status="running"
                else
                    daemon_status="stopped"
                fi

                if [[ "$daemon_status" == "running" ]]; then
                    echo "  🔄 Service: rchd.service (systemd) - ✅ RUNNING"
                else
                    echo "  🔄 Service: rchd.service (systemd) - ⚠️ NOT RUNNING"
                fi
                echo ""
                if $USE_COLOR; then
                    echo -e "  ${DIM}Commands:${NC}"
                    echo -e "    ${CYAN}systemctl --user status rchd${NC}     # Check status"
                    echo -e "    ${CYAN}journalctl --user -u rchd -f${NC}     # Follow logs"
                    echo -e "    ${CYAN}systemctl --user restart rchd${NC}    # Restart"
                    echo -e "    ${CYAN}systemctl --user stop rchd${NC}       # Stop daemon"
                else
                    echo "  Commands:"
                    echo "    systemctl --user status rchd     # Check status"
                    echo "    journalctl --user -u rchd -f     # Follow logs"
                    echo "    systemctl --user restart rchd    # Restart"
                    echo "    systemctl --user stop rchd       # Stop daemon"
                fi
            elif [[ "$(uname -s)" == "Darwin" ]] && command_exists launchctl; then
                # Check if daemon is running on macOS
                local daemon_status="unknown"
                if launchctl list 2>/dev/null | grep -q "com.rch.daemon"; then
                    daemon_status="running"
                else
                    daemon_status="stopped"
                fi

                if [[ "$daemon_status" == "running" ]]; then
                    echo "  🔄 Service: com.rch.daemon (launchd) - ✅ RUNNING"
                else
                    echo "  🔄 Service: com.rch.daemon (launchd) - ⚠️ NOT RUNNING"
                fi
                echo ""
                if $USE_COLOR; then
                    echo -e "  ${DIM}Commands:${NC}"
                    echo -e "    ${CYAN}launchctl list | grep rch${NC}        # Check status"
                    echo -e "    ${CYAN}tail -f $CONFIG_DIR/logs/daemon.log${NC}"
                    echo -e "    ${CYAN}launchctl unload ~/Library/LaunchAgents/com.rch.daemon.plist${NC}  # Stop"
                else
                    echo "  Commands:"
                    echo "    launchctl list | grep rch        # Check status"
                    echo "    tail -f $CONFIG_DIR/logs/daemon.log"
                    echo "    launchctl unload ~/Library/LaunchAgents/com.rch.daemon.plist  # Stop"
                fi
            fi
            echo ""
        else
            echo "  🔄 Service: disabled"
            echo "     Run 'rch daemon start' when ready"
            echo ""
        fi

        # Next steps box
        if $USE_GUM; then
            gum style \
                --border rounded \
                --border-foreground 208 \
                --padding "0 2" \
                "Next Steps:" \
                "" \
                "1. Edit workers:   vim $CONFIG_DIR/workers.toml" \
                "2. Run diagnostics: rch doctor" \
                "3. Test workers:    rch workers probe --all"
        else
            draw_box "1;33" \
                "Next Steps:" \
                "" \
                "1. Edit workers:    vim $CONFIG_DIR/workers.toml" \
                "2. Run diagnostics: rch doctor" \
                "3. Test workers:    rch workers probe --all"
        fi
    fi
    echo ""

    # Supported commands section
    if [[ "$MODE" != "worker" ]]; then
        if $USE_COLOR; then
            echo -e "${BOLD}Supported Commands (auto-offloaded):${NC}"
        else
            echo "Supported Commands (auto-offloaded):"
        fi
        echo ""
        echo "  🦀 Rust:    cargo build, cargo test, cargo check, rustc"
        echo "  🍞 Bun:     bun test, bun typecheck"
        echo "  🔨 C/C++:   gcc, g++, clang, make, cmake, ninja"
        echo ""
        if $USE_COLOR; then
            echo -e "${DIM}Commands like 'cargo fmt', 'cargo install', 'ls' run locally.${NC}"
        else
            echo "Commands like 'cargo fmt', 'cargo install', 'ls' run locally."
        fi
        echo ""

        # AI Agent skill info
        local has_claude_skill=false
        local has_codex_skill=false
        [[ -f "$HOME/.claude/skills/rch/SKILL.md" ]] && has_claude_skill=true
        [[ -f "$HOME/.codex/skills/rch/SKILL.md" ]] && has_codex_skill=true

        if $has_claude_skill || $has_codex_skill; then
            local skill_locations=""
            $has_claude_skill && skill_locations+="Claude Code (~/.claude/skills/rch/)"
            if $has_codex_skill; then
                [[ -n "$skill_locations" ]] && skill_locations+=", "
                skill_locations+="Codex CLI (~/.codex/skills/rch/)"
            fi

            if $USE_GUM; then
                gum style \
                    --border rounded \
                    --border-foreground 141 \
                    --padding "0 2" \
                    "🤖 AI Agent Integration" \
                    "" \
                    "Skills installed for: $skill_locations" \
                    "" \
                    "Your AI coding agents now have RCH expertise built-in." \
                    "Just describe your issue naturally—no commands needed:" \
                    "" \
                    "  \"rch doctor is failing\"" \
                    "  \"no workers available\"" \
                    "  \"how do I configure a new worker?\"" \
                    "" \
                    "The agent's skill auto-activates on RCH topics."
            else
                draw_box "1;36" \
                    "AI Agent Integration" \
                    "" \
                    "Skills installed for:" \
                    "  $skill_locations" \
                    "" \
                    "Your AI coding agents now have RCH expertise built-in." \
                    "Just describe your issue naturally—no commands needed:" \
                    "" \
                    "  \"rch doctor is failing\"" \
                    "  \"no workers available\"" \
                    "  \"how do I configure a new worker?\"" \
                    "" \
                    "The agent's skill auto-activates on RCH topics."
            fi
            echo ""
        fi

        # Critical reminder about restarting Claude Code session
        if $USE_GUM; then
            gum style \
                --border double \
                --border-foreground 196 \
                --padding "1 3" \
                --align center \
                "⚠️  IMPORTANT: Restart Required  ⚠️" \
                "" \
                "You MUST start a NEW Claude Code session" \
                "for the RCH hook to be active." \
                "" \
                "Exit your current session and run 'claude' again."
        else
            echo ""
            if $USE_COLOR; then
                echo -e "${BOLD}${RED}╔══════════════════════════════════════════════════════════════╗${NC}"
                echo -e "${BOLD}${RED}║${NC}        ${BOLD}⚠️  IMPORTANT: Restart Required  ⚠️${NC}                  ${BOLD}${RED}║${NC}"
                echo -e "${BOLD}${RED}╠══════════════════════════════════════════════════════════════╣${NC}"
                echo -e "${BOLD}${RED}║${NC}                                                              ${BOLD}${RED}║${NC}"
                echo -e "${BOLD}${RED}║${NC}   You ${BOLD}MUST${NC} start a ${BOLD}NEW${NC} Claude Code session                  ${BOLD}${RED}║${NC}"
                echo -e "${BOLD}${RED}║${NC}   for the RCH hook to be active.                            ${BOLD}${RED}║${NC}"
                echo -e "${BOLD}${RED}║${NC}                                                              ${BOLD}${RED}║${NC}"
                echo -e "${BOLD}${RED}║${NC}   ${YELLOW}Exit your current session and run 'claude' again.${NC}        ${BOLD}${RED}║${NC}"
                echo -e "${BOLD}${RED}║${NC}                                                              ${BOLD}${RED}║${NC}"
                echo -e "${BOLD}${RED}╚══════════════════════════════════════════════════════════════╝${NC}"
            else
                echo "╔══════════════════════════════════════════════════════════════╗"
                echo "║        IMPORTANT: Restart Required                           ║"
                echo "╠══════════════════════════════════════════════════════════════╣"
                echo "║                                                              ║"
                echo "║   You MUST start a NEW Claude Code session                   ║"
                echo "║   for the RCH hook to be active.                             ║"
                echo "║                                                              ║"
                echo "║   Exit your current session and run 'claude' again.          ║"
                echo "║                                                              ║"
                echo "╚══════════════════════════════════════════════════════════════╝"
            fi
        fi
        echo ""
    fi
}

# ============================================================================
# Help
# ============================================================================

usage() {
    cat << EOF
RCH Installer v$VERSION

Usage: $0 [OPTIONS]

Options:
  --local              Install hook and daemon (default)
  --worker             Install worker agent only
  --from-source        Build from source (requires Rust)
  --offline <tarball>  Install from local tarball (airgap mode)
  --easy-mode          Configure PATH + detect agents + run doctor
  --verify-only        Verify existing installation
  --install-service    Enable background service without prompting
  --no-service         Skip systemd/launchd service setup
  --uninstall          Remove RCH installation
  --no-gum             Disable Gum UI (use ANSI fallback)
  --yes                Skip confirmation prompts
  --help, -h           Show this help

Environment:
  RCH_INSTALL_DIR      Installation directory (default: ~/.local/bin)
  RCH_CONFIG_DIR       Config directory (default: ~/.config/rch)
  RCH_NO_HOOK          Skip Claude Code hook setup if set
  RCH_NO_COLOR         Disable colored output
  RCH_SKIP_DOCTOR      Skip post-install doctor check
  HTTP_PROXY           HTTP proxy URL
  HTTPS_PROXY          HTTPS proxy URL
  NO_PROXY             Hosts to bypass proxy

Service Setup:
  On Linux:  systemd user service is offered during install (auto-accept in --easy-mode/--yes).
             Use --install-service to opt in without prompting.
             Lingering is enabled for reboot persistence when possible (requires sudo).
  On macOS:  launchd service is offered during install (auto-accept in --easy-mode/--yes).
             Use --install-service to opt in without prompting.
             Service starts on login when enabled.

Examples:
  ./install.sh                         # Install locally (auto-detects source)
  ./install.sh --from-source           # Force build from source
  ./install.sh --worker                # Install on a worker machine
  ./install.sh --easy-mode             # Full setup with PATH and detection
  ./install.sh --offline rch.tar.gz    # Install from local tarball
  ./install.sh --install-service       # Enable background service without prompt
  ./install.sh --no-service            # Install without system service
  ./install.sh --uninstall             # Remove installation

EOF
}

# ============================================================================
# Main
# ============================================================================

main() {
    # Parse arguments
    MODE="local"
    FROM_SOURCE="false"
    UNINSTALL="false"
    VERIFY_ONLY="false"
    EASY_MODE="false"
    NO_SERVICE="false"
    INSTALL_SERVICE="false"
    ENABLE_SERVICE="true"
    YES="false"
    OFFLINE_TARBALL=""

    while [[ $# -gt 0 ]]; do
        case "$1" in
            --local)
                MODE="local"
                shift
                ;;
            --worker|--worker-only)
                MODE="worker"
                shift
                ;;
            --from-source)
                FROM_SOURCE="true"
                shift
                ;;
            --offline)
                if [[ -n "${2:-}" ]]; then
                    OFFLINE_TARBALL="$2"
                    shift 2
                else
                    die "--offline requires a tarball path"
                fi
                ;;
            --easy-mode)
                EASY_MODE="true"
                shift
                ;;
            --verify-only)
                VERIFY_ONLY="true"
                shift
                ;;
            --install-service)
                INSTALL_SERVICE="true"
                shift
                ;;
            --no-service)
                NO_SERVICE="true"
                shift
                ;;
            --uninstall)
                UNINSTALL="true"
                shift
                ;;
            --no-gum)
                NO_GUM="true"
                shift
                ;;
            --yes|-y)
                YES="true"
                shift
                ;;
            --help|-h)
                usage
                exit 0
                ;;
            *)
                error "Unknown option: $1"
                usage
                exit 1
                ;;
        esac
    done

    # Setup UI
    setup_ui

    # Detect target version (needed for header and upgrade banner)
    detect_target_version

    show_header

    # Handle special modes
    if [[ "$UNINSTALL" == "true" ]]; then
        uninstall
        exit 0
    fi

    if [[ "$VERIFY_ONLY" == "true" ]]; then
        verify_installation
        exit $?
    fi

    # Acquire lock
    acquire_lock

    # Check for existing installation (shows upgrade banner)
    check_existing_install || true

    info "Installation mode: $MODE"
    echo ""

    # Setup proxy
    setup_proxy

    # Detect platform
    detect_platform

    # Worker mode toolchain verification
    if [[ "$MODE" == "worker" ]]; then
        verify_worker_toolchain || exit 1
    fi

    # Main installation
    check_prerequisites
    create_directories
    install_binaries
    generate_default_config

    if [[ "$MODE" == "local" ]]; then
        configure_claude_hook
        install_skill
        maybe_prompt_service
        setup_systemd_service
        setup_launchd_service
    fi

    setup_path
    setup_shell_completions
    verify_installation

    # Easy mode extras
    if [[ "$EASY_MODE" == "true" ]]; then
        detect_agents
        run_doctor
    fi

    print_summary
}

if [[ "${RCH_INSTALLER_LIB:-}" == "1" ]]; then
    return 0 2>/dev/null || exit 0
fi

main "$@"
