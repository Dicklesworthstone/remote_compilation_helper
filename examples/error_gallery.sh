#!/bin/bash
#
# error_gallery.sh - Demonstrate all RCH error types and remediation suggestions
#
# Prerequisites:
#   - rch binary built and in PATH (cargo build --release)
#
# Usage:
#   ./examples/error_gallery.sh              # Show all error types
#   ./examples/error_gallery.sh --verbose    # Show with extra detail
#
# For asciinema recording:
#   asciinema rec -c "./examples/error_gallery.sh" error_gallery.cast
#
# shellcheck disable=SC2312

set -uo pipefail

# Colors for this script's output
RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[0;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
DIM='\033[2m'
NC='\033[0m' # No Color

VERBOSE=${1:-}

# Cleanup function
cleanup() {
    local exit_code=$?
    echo ""
    echo -e "${DIM}Error gallery demo completed (exit code: $exit_code)${NC}"
}
trap cleanup EXIT

# Print a section header
section() {
    echo ""
    echo -e "${BOLD}${RED}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${BOLD}${RED}  $1${NC}"
    echo -e "${BOLD}${RED}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo ""
    sleep 0.5
}

# Print an info message
info() {
    echo -e "${DIM}$1${NC}"
    sleep 0.3
}

# Print error category header
error_category() {
    echo ""
    echo -e "${YELLOW}▶ $1${NC}"
    echo ""
}

# Demo: Configuration Errors
demo_config_errors() {
    section "Configuration Errors"

    error_category "Missing configuration file"
    info "Attempting to use rch with no config..."
    # Use a non-existent config directory
    RCH_CONFIG_DIR=/nonexistent/path rch config show 2>&1 || true

    echo ""
    error_category "Invalid configuration syntax"
    info "Creating a config with syntax error..."
    local temp_config
    temp_config=$(mktemp -d)
    echo "invalid toml [[[" > "$temp_config/config.toml"
    RCH_CONFIG_DIR="$temp_config" rch config validate 2>&1 || true
    rm -rf "$temp_config"

    echo ""
    error_category "Missing required field"
    info "Config with missing required fields..."
    local temp_config2
    temp_config2=$(mktemp -d)
    echo "[daemon]" > "$temp_config2/config.toml"
    echo "# Missing required fields" >> "$temp_config2/config.toml"
    RCH_CONFIG_DIR="$temp_config2" rch config validate 2>&1 || true
    rm -rf "$temp_config2"
}

# Demo: Daemon Errors
demo_daemon_errors() {
    section "Daemon Errors"

    error_category "Daemon not running"
    info "Checking status when daemon is not running..."
    # Force socket to non-existent path
    RCH_SOCKET_PATH=/nonexistent/rch.sock rch daemon status 2>&1 || true

    echo ""
    error_category "Stale socket file"
    info "Attempting to connect to stale socket..."
    local temp_sock
    temp_sock=$(mktemp)
    # Create a regular file instead of socket
    RCH_SOCKET_PATH="$temp_sock" rch status 2>&1 || true
    rm -f "$temp_sock"
}

# Demo: Worker Errors
demo_worker_errors() {
    section "Worker Errors"

    error_category "Worker unreachable"
    info "Probing a non-existent worker..."
    rch workers probe nonexistent.example.com 2>&1 || true

    echo ""
    error_category "SSH authentication failure"
    info "Attempting connection with invalid key..."
    # This will timeout or fail gracefully
    timeout 5 rch workers probe badauth@localhost 2>&1 || true

    echo ""
    error_category "No workers configured"
    info "Running with empty workers config..."
    local temp_dir
    temp_dir=$(mktemp -d)
    echo "# Empty workers config" > "$temp_dir/workers.toml"
    RCH_WORKERS_CONFIG="$temp_dir/workers.toml" rch workers list 2>&1 || true
    rm -rf "$temp_dir"
}

# Demo: Hook Errors
demo_hook_errors() {
    section "Hook Errors"

    error_category "Hook not installed"
    info "Checking hook status when not installed..."
    rch hook status 2>&1 || true

    echo ""
    error_category "Invalid hook input"
    info "Passing malformed JSON to hook..."
    echo '{"invalid": "input"}' | rch 2>&1 || true
}

# Demo: Doctor Checks
demo_doctor_errors() {
    section "Doctor Diagnostics"

    error_category "Running doctor to detect issues"
    info "Doctor runs comprehensive checks and shows issues..."
    rch doctor 2>&1 || true

    if [[ "$VERBOSE" == "--verbose" ]]; then
        echo ""
        info "Running doctor with verbose output..."
        rch doctor -v 2>&1 || true
    fi
}

# Demo: --verbose flag differences
demo_verbose_differences() {
    section "Verbose Mode Comparison"

    error_category "Normal error output"
    info "Standard error message:"
    rch workers probe nonexistent.invalid 2>&1 || true

    echo ""
    error_category "Verbose error output (-v)"
    info "Error message with verbose flag:"
    rch workers probe nonexistent.invalid -v 2>&1 || true
}

# Main
main() {
    echo ""
    echo -e "${BOLD}${RED}"
    echo "   ███████╗██████╗ ██████╗  ██████╗ ██████╗"
    echo "   ██╔════╝██╔══██╗██╔══██╗██╔═══██╗██╔══██╗"
    echo "   █████╗  ██████╔╝██████╔╝██║   ██║██████╔╝"
    echo "   ██╔══╝  ██╔══██╗██╔══██╗██║   ██║██╔══██╗"
    echo "   ███████╗██║  ██║██║  ██║╚██████╔╝██║  ██║"
    echo "   ╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═╝"
    echo ""
    echo "   RCH Error Gallery - All Error Types & Remediation"
    echo -e "${NC}"

    info "This demo shows all error categories and their remediation suggestions."
    info "Each error includes context and actionable steps to fix the issue."
    echo ""

    demo_config_errors
    demo_daemon_errors
    demo_worker_errors
    demo_hook_errors
    demo_doctor_errors
    demo_verbose_differences

    section "Error Gallery Complete"
    echo -e "${GREEN}All error categories demonstrated.${NC}"
    echo ""
    echo -e "${DIM}Key takeaways:${NC}"
    echo -e "  ${CYAN}•${NC} Every error includes an error code (RCH-Exxx)"
    echo -e "  ${CYAN}•${NC} Context section shows relevant details"
    echo -e "  ${CYAN}•${NC} Suggestions provide actionable remediation steps"
    echo -e "  ${CYAN}•${NC} Use --verbose for additional debug information"
    echo -e "  ${CYAN}•${NC} Use --json for machine-readable error output"
}

main "$@"
