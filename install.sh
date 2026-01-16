#!/usr/bin/env bash
# install.sh - Remote Compilation Helper Installer
#
# Installation modes:
#   1. Local:       Install rch + rchd on current machine (default)
#   2. Worker:      Install just rch-wkr on current machine
#
# Usage:
#   bash install.sh                      # Interactive local install
#   bash install.sh --local              # Non-interactive local install
#   bash install.sh --worker             # Worker-only install
#   bash install.sh --from-source        # Build from source
#   bash install.sh --uninstall          # Remove RCH
#
# Environment:
#   RCH_INSTALL_DIR     Where to install binaries (default: ~/.local/bin)
#   RCH_CONFIG_DIR      Where to store config (default: ~/.config/rch)
#   RCH_NO_HOOK         Skip Claude Code hook setup if set

set -euo pipefail

# ============================================================================
# Configuration
# ============================================================================

VERSION="0.1.0"
REPO_URL="https://github.com/Dicklesworthstone/remote_compilation_helper"

INSTALL_DIR="${RCH_INSTALL_DIR:-$HOME/.local/bin}"
CONFIG_DIR="${RCH_CONFIG_DIR:-$HOME/.config/rch}"
SOCKET_PATH="/tmp/rch.sock"

# Binaries
HOOK_BIN="rch"
DAEMON_BIN="rchd"
WORKER_BIN="rch-wkr"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
BOLD='\033[1m'
NC='\033[0m' # No Color

# ============================================================================
# Utility Functions
# ============================================================================

info() {
    echo -e "${BLUE}[INFO]${NC} $*"
}

success() {
    echo -e "${GREEN}[OK]${NC} $*"
}

warn() {
    echo -e "${YELLOW}[WARN]${NC} $*"
}

error() {
    echo -e "${RED}[ERROR]${NC} $*" >&2
}

die() {
    error "$@"
    exit 1
}

command_exists() {
    command -v "$1" &> /dev/null
}

ensure_command() {
    if ! command_exists "$1"; then
        die "Required command not found: $1. Please install it first."
    fi
}

# ============================================================================
# Prerequisite Checks
# ============================================================================

check_prerequisites() {
    info "Checking prerequisites..."

    # Required for building from source
    if [[ "${FROM_SOURCE:-false}" == "true" ]]; then
        ensure_command cargo
        ensure_command rustc

        # Check Rust nightly
        if ! rustc --version | grep -q nightly; then
            warn "Rust nightly recommended. Current: $(rustc --version)"
        fi
    fi

    # Required for operation
    ensure_command rsync
    ensure_command ssh

    # Optional but recommended
    if ! command_exists zstd; then
        warn "zstd not found - compression will be slower"
    fi

    success "Prerequisites check passed"
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

    # Find project root (script location or current dir if Cargo.toml exists)
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
    info "Building release binaries (this may take a while)..."
    cargo build --release

    # Copy binaries
    local target_dir="$project_dir/target/release"

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
        if [[ -f "$target_dir/$HOOK_BIN" ]]; then
            cp "$target_dir/$HOOK_BIN" "$INSTALL_DIR/"
            chmod +x "$INSTALL_DIR/$HOOK_BIN"
            success "Installed $HOOK_BIN"
        else
            die "Hook binary not found: $target_dir/$HOOK_BIN"
        fi

        if [[ -f "$target_dir/$DAEMON_BIN" ]]; then
            cp "$target_dir/$DAEMON_BIN" "$INSTALL_DIR/"
            chmod +x "$INSTALL_DIR/$DAEMON_BIN"
            success "Installed $DAEMON_BIN"
        else
            die "Daemon binary not found: $target_dir/$DAEMON_BIN"
        fi
    fi

    success "Build complete"
}

download_binaries() {
    # For future: download pre-built binaries
    die "Binary downloads not yet available. Use --from-source to build from source."
}

install_binaries() {
    if [[ "${FROM_SOURCE:-false}" == "true" ]]; then
        build_from_source
    else
        # Try source first (if we're in the repo), otherwise download
        if [[ -f "Cargo.toml" ]] && grep -q "remote_compilation_helper" Cargo.toml 2>/dev/null; then
            info "Found source directory, building from source..."
            FROM_SOURCE=true
            build_from_source
        else
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

# Unix socket path for hook communication
socket_path = "/tmp/rch.sock"

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
    # Try common locations
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

    # Return default (may not exist yet)
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

    # Ensure directory exists
    mkdir -p "$settings_dir"

    local hook_path="$INSTALL_DIR/$HOOK_BIN"

    # Check if jq is available for JSON manipulation
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
        "hooks": ["$hook_path"]
      }
    ]
  }
}
EOF
)

    if [[ -f "$settings_path" ]]; then
        # Merge with existing settings
        local existing
        existing=$(cat "$settings_path")

        # Check if hooks already configured
        if echo "$existing" | jq -e '.hooks.PreToolUse' &>/dev/null; then
            # Check if RCH hook already present
            if echo "$existing" | jq -e '.hooks.PreToolUse[] | select(.hooks[] | contains("rch"))' &>/dev/null; then
                info "RCH hook already configured"
                return
            fi

            # Add to existing PreToolUse hooks
            local new_hook='{"matcher": "Bash", "hooks": ["'"$hook_path"'"]}'
            echo "$existing" | jq ".hooks.PreToolUse += [$new_hook]" > "$settings_path"
        else
            # Add hooks section
            echo "$existing" | jq ". + $hook_config" > "$settings_path"
        fi
    else
        # Create new settings file
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
    echo "        \"hooks\": [\"$hook_path\"]"
    echo '      }'
    echo '    ]'
    echo '  }'
    echo '}'
    echo ""
}

# ============================================================================
# Systemd Service
# ============================================================================

setup_systemd_service() {
    if [[ "$MODE" == "worker" ]]; then
        return  # Workers don't need systemd on the local side
    fi

    # Check if systemd is available
    if ! command_exists systemctl; then
        info "systemd not found - skipping service setup"
        return
    fi

    info "Setting up systemd service..."

    local service_file="$HOME/.config/systemd/user/rchd.service"
    mkdir -p "$(dirname "$service_file")"

    cat > "$service_file" << EOF
[Unit]
Description=Remote Compilation Helper Daemon
After=network.target

[Service]
Type=simple
ExecStart=$INSTALL_DIR/$DAEMON_BIN --workers-config $CONFIG_DIR/workers.toml
Restart=on-failure
RestartSec=5

[Install]
WantedBy=default.target
EOF

    # Reload and enable
    systemctl --user daemon-reload
    systemctl --user enable rchd.service

    success "Systemd service installed: rchd.service"
    info "Start with: systemctl --user start rchd"
    info "Check status: systemctl --user status rchd"
}

# ============================================================================
# PATH Setup
# ============================================================================

setup_path() {
    # Check if INSTALL_DIR is in PATH
    if [[ ":$PATH:" != *":$INSTALL_DIR:"* ]]; then
        warn "$INSTALL_DIR is not in PATH"

        local shell_rc=""
        if [[ -n "${BASH_VERSION:-}" ]]; then
            shell_rc="$HOME/.bashrc"
        elif [[ -n "${ZSH_VERSION:-}" ]]; then
            shell_rc="$HOME/.zshrc"
        fi

        if [[ -n "$shell_rc" ]] && [[ -f "$shell_rc" ]]; then
            local path_line="export PATH=\"\$PATH:$INSTALL_DIR\""
            if ! grep -q "$INSTALL_DIR" "$shell_rc"; then
                echo "" >> "$shell_rc"
                echo "# RCH - Remote Compilation Helper" >> "$shell_rc"
                echo "$path_line" >> "$shell_rc"
                success "Added $INSTALL_DIR to PATH in $shell_rc"
                warn "Run 'source $shell_rc' or restart your shell"
            fi
        else
            echo ""
            echo -e "${BOLD}Add to your shell profile:${NC}"
            echo "export PATH=\"\$PATH:$INSTALL_DIR\""
            echo ""
        fi
    fi
}

# ============================================================================
# Uninstall
# ============================================================================

uninstall() {
    info "Uninstalling RCH..."

    # Stop daemon if running
    if command_exists systemctl; then
        systemctl --user stop rchd.service 2>/dev/null || true
        systemctl --user disable rchd.service 2>/dev/null || true
        rm -f "$HOME/.config/systemd/user/rchd.service"
        systemctl --user daemon-reload 2>/dev/null || true
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
# Summary
# ============================================================================

print_summary() {
    echo ""
    echo -e "${GREEN}${BOLD}Installation Complete!${NC}"
    echo ""
    echo "Installed to: $INSTALL_DIR"
    echo "Config at:    $CONFIG_DIR"
    echo ""

    if [[ "$MODE" == "worker" ]]; then
        echo "Worker binary: $INSTALL_DIR/$WORKER_BIN"
    else
        echo "Binaries:"
        echo "  Hook:   $INSTALL_DIR/$HOOK_BIN"
        echo "  Daemon: $INSTALL_DIR/$DAEMON_BIN"
        echo ""
        echo -e "${BOLD}Next steps:${NC}"
        echo "1. Edit workers config: $CONFIG_DIR/workers.toml"
        echo "2. Start the daemon:    systemctl --user start rchd"
        echo "                   or:  $DAEMON_BIN --workers-config $CONFIG_DIR/workers.toml"
        echo "3. Test the hook:       rch hook test"
    fi
    echo ""
}

# ============================================================================
# Verify Installation
# ============================================================================

verify_installation() {
    info "Verifying installation..."

    local failed=0

    if [[ "$MODE" == "worker" ]]; then
        if [[ ! -x "$INSTALL_DIR/$WORKER_BIN" ]]; then
            error "Worker binary not found or not executable"
            failed=1
        fi
    else
        if [[ ! -x "$INSTALL_DIR/$HOOK_BIN" ]]; then
            error "Hook binary not found or not executable"
            failed=1
        fi
        if [[ ! -x "$INSTALL_DIR/$DAEMON_BIN" ]]; then
            error "Daemon binary not found or not executable"
            failed=1
        fi
        if [[ ! -f "$CONFIG_DIR/daemon.toml" ]]; then
            error "Daemon config not found"
            failed=1
        fi
    fi

    if [[ $failed -eq 0 ]]; then
        success "Installation verified"
    else
        die "Installation verification failed"
    fi
}

# ============================================================================
# Main
# ============================================================================

usage() {
    cat << EOF
RCH Installer v$VERSION

Usage: $0 [OPTIONS]

Options:
  --local           Install hook and daemon (default)
  --worker          Install worker agent only
  --from-source     Build from source (requires Rust)
  --uninstall       Remove RCH installation
  --help, -h        Show this help

Environment:
  RCH_INSTALL_DIR   Installation directory (default: ~/.local/bin)
  RCH_CONFIG_DIR    Config directory (default: ~/.config/rch)
  RCH_NO_HOOK       Skip Claude Code hook setup if set

Examples:
  ./install.sh                    # Install locally (auto-detects source)
  ./install.sh --from-source      # Force build from source
  ./install.sh --worker           # Install on a worker machine
  ./install.sh --uninstall        # Remove installation

EOF
}

main() {
    # Parse arguments
    MODE="local"
    FROM_SOURCE="false"
    UNINSTALL="false"

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
            --uninstall)
                UNINSTALL="true"
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

    echo ""
    echo -e "${BOLD}RCH Installer v$VERSION${NC}"
    echo ""

    if [[ "$UNINSTALL" == "true" ]]; then
        uninstall
        exit 0
    fi

    info "Installation mode: $MODE"
    echo ""

    check_prerequisites
    create_directories
    install_binaries
    generate_default_config

    if [[ "$MODE" == "local" ]]; then
        configure_claude_hook
        setup_systemd_service
    fi

    setup_path
    verify_installation
    print_summary
}

main "$@"
