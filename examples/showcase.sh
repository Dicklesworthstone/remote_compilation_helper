#!/bin/bash
#
# showcase.sh - Display all RCH UI components
#
# Prerequisites:
#   - rch binary built and in PATH (cargo build --release)
#   - rchd daemon running (rch daemon start)
#   - At least one worker configured (or use RCH_MOCK_SSH=1 for demo)
#
# Usage:
#   ./examples/showcase.sh              # Normal demo
#   RCH_MOCK_SSH=1 ./examples/showcase.sh  # Demo without real workers
#
# For asciinema recording:
#   asciinema rec -c "./examples/showcase.sh" showcase.cast
#
# shellcheck disable=SC2312

set -euo pipefail

# Colors for this script's output
RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[0;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
DIM='\033[2m'
NC='\033[0m' # No Color

# Cleanup function
cleanup() {
    local exit_code=$?
    echo ""
    echo -e "${DIM}Demo completed (exit code: $exit_code)${NC}"
    exit $exit_code
}
trap cleanup EXIT

# Print a section header
section() {
    echo ""
    echo -e "${BOLD}${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${BOLD}${CYAN}  $1${NC}"
    echo -e "${BOLD}${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo ""
    sleep 0.5
}

# Print an info message
info() {
    echo -e "${DIM}$1${NC}"
    sleep 0.3
}

# Check prerequisites
check_prereqs() {
    section "Checking Prerequisites"

    if ! command -v rch &>/dev/null; then
        echo -e "${RED}Error: rch not found in PATH${NC}"
        echo -e "${DIM}Run: cargo build --release${NC}"
        exit 1
    fi

    echo -e "${GREEN}✓${NC} rch binary found: $(command -v rch)"

    # Check if daemon is running (don't fail if not)
    if rch daemon status &>/dev/null; then
        echo -e "${GREEN}✓${NC} rchd daemon is running"
    else
        echo -e "${YELLOW}!${NC} rchd daemon not running (some demos will be limited)"
    fi
}

# Demo: rch status
demo_status() {
    section "System Status Overview"

    info "Running: rch status"
    rch status || true

    echo ""
    info "Running: rch status --workers (include worker details)"
    rch status --workers || true
}

# Demo: rch workers list
demo_workers() {
    section "Worker Management"

    info "Running: rch workers list"
    rch workers list || true
}

# Demo: rch diagnose (command classification)
demo_diagnose() {
    section "Command Classification"

    info "Commands are classified through a 5-tier system (<1ms for 99% of commands)"
    echo ""

    # Commands that WILL be offloaded
    local offload_cmds=(
        "cargo build --release"
        "cargo test --workspace"
        "cargo check"
        "cargo clippy"
        "gcc -O2 main.c -o main"
        "make -j8"
    )

    info "Commands that WILL be offloaded:"
    for cmd in "${offload_cmds[@]}"; do
        echo ""
        echo -e "${DIM}> rch diagnose \"$cmd\"${NC}"
        rch diagnose "$cmd" || true
        sleep 0.2
    done

    echo ""
    echo ""

    # Commands that will NOT be offloaded
    local skip_cmds=(
        "ls -la"
        "cargo fmt"
        "git status"
        "echo hello"
        "cargo build | tee build.log"  # Piped
    )

    info "Commands that will NOT be offloaded:"
    for cmd in "${skip_cmds[@]}"; do
        echo ""
        echo -e "${DIM}> rch diagnose \"$cmd\"${NC}"
        rch diagnose "$cmd" || true
        sleep 0.2
    done
}

# Demo: rch config
demo_config() {
    section "Configuration Display"

    info "Running: rch config show"
    rch config show || true

    echo ""
    info "Running: rch config show --sources (show where values come from)"
    rch config show --sources || true
}

# Demo: rch doctor
demo_doctor() {
    section "System Health Check"

    info "Running: rch doctor"
    rch doctor || true
}

# Demo: Version and help
demo_help() {
    section "Help & Version"

    info "Running: rch --version"
    rch --version || true

    echo ""
    info "Running: rch --help"
    rch --help || true
}

# Main
main() {
    echo ""
    echo -e "${BOLD}${BLUE}"
    echo "   ██████╗  ██████╗██╗  ██╗"
    echo "   ██╔══██╗██╔════╝██║  ██║"
    echo "   ██████╔╝██║     ███████║"
    echo "   ██╔══██╗██║     ██╔══██║"
    echo "   ██║  ██║╚██████╗██║  ██║"
    echo "   ╚═╝  ╚═╝ ╚═════╝╚═╝  ╚═╝"
    echo ""
    echo "   Remote Compilation Helper - UI Showcase"
    echo -e "${NC}"

    check_prereqs
    demo_status
    demo_workers
    demo_diagnose
    demo_config
    demo_doctor
    demo_help

    section "Demo Complete"
    echo -e "${GREEN}All UI components demonstrated successfully.${NC}"
    echo ""
    echo -e "${DIM}For more information:${NC}"
    echo -e "  ${CYAN}rch --help${NC}              Show all commands"
    echo -e "  ${CYAN}rch <command> --help${NC}   Show command-specific help"
    echo -e "  ${CYAN}rch diagnose <cmd>${NC}     Explain classification for any command"
}

main "$@"
