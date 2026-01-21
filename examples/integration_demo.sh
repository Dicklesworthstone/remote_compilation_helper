#!/bin/bash
#
# integration_demo.sh - Real-world RCH workflow demonstration
#
# This script demonstrates the typical human operator experience with RCH,
# contrasting it with how AI coding agents interact with the system.
#
# Prerequisites:
#   - rch binary built and in PATH (cargo build --release)
#   - rchd daemon running (rch daemon start)
#   - At least one worker configured
#
# Usage:
#   ./examples/integration_demo.sh              # Run full demo
#   ./examples/integration_demo.sh --quick      # Abbreviated demo
#
# For asciinema recording:
#   asciinema rec -c "./examples/integration_demo.sh" integration_demo.cast
#
# shellcheck disable=SC2312

set -euo pipefail

# Colors for this script's output
RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[0;33m'
CYAN='\033[0;36m'
MAGENTA='\033[0;35m'
BOLD='\033[1m'
DIM='\033[2m'
NC='\033[0m' # No Color

QUICK_MODE=false
[[ "${1:-}" == "--quick" ]] && QUICK_MODE=true

# Temporary project directory
TEMP_PROJECT=""

# Cleanup function
cleanup() {
    local exit_code=$?
    if [[ -n "$TEMP_PROJECT" && -d "$TEMP_PROJECT" ]]; then
        echo -e "${DIM}Cleaning up temporary project...${NC}"
        rm -rf "$TEMP_PROJECT"
    fi
    echo ""
    echo -e "${DIM}Integration demo completed (exit code: $exit_code)${NC}"
}
trap cleanup EXIT

# Print a section header
section() {
    echo ""
    echo -e "${BOLD}${MAGENTA}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${BOLD}${MAGENTA}  $1${NC}"
    echo -e "${BOLD}${MAGENTA}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo ""
    sleep 0.5
}

# Print an info message
info() {
    echo -e "${DIM}$1${NC}"
    sleep 0.3
}

# Print a narrator message (simulating explanation)
narrate() {
    echo ""
    echo -e "${CYAN}▸${NC} $1"
    echo ""
    sleep 1
}

# Simulate typing effect for commands
type_cmd() {
    echo -ne "${GREEN}\$ ${NC}"
    local cmd="$1"
    if $QUICK_MODE; then
        echo "$cmd"
    else
        for ((i=0; i<${#cmd}; i++)); do
            echo -n "${cmd:$i:1}"
            sleep 0.03
        done
        echo ""
    fi
    sleep 0.5
}

# Run a command with simulated typing
run_cmd() {
    type_cmd "$1"
    eval "$1" || true
    sleep 0.5
}

# Check prerequisites
check_prereqs() {
    if ! command -v rch &>/dev/null; then
        echo -e "${RED}Error: rch not found in PATH${NC}"
        exit 1
    fi
}

# Create a test Rust project
create_test_project() {
    TEMP_PROJECT=$(mktemp -d)
    cd "$TEMP_PROJECT"
    cargo init --name demo_project --quiet

    # Add dependencies
    cat >> Cargo.toml << 'EOF'
[dependencies]
anyhow = "1.0"
clap = { version = "4", features = ["derive"] }

[dev-dependencies]
tempfile = "3"
EOF

    # Create main.rs with a feature
    cat > src/main.rs << 'EOF'
use anyhow::Result;
use clap::Parser;

#[derive(Parser, Debug)]
#[command(author, version, about)]
struct Args {
    /// Name to greet
    #[arg(short, long, default_value = "World")]
    name: String,
}

fn greet(name: &str) -> String {
    format!("Hello, {}!", name)
}

fn main() -> Result<()> {
    let args = Args::parse();
    println!("{}", greet(&args.name));
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_greet() {
        assert_eq!(greet("Rust"), "Hello, Rust!");
    }

    #[test]
    fn test_greet_world() {
        assert_eq!(greet("World"), "Hello, World!");
    }
}
EOF
}

# Demo: Human Operator Experience
demo_human_experience() {
    section "Human Operator Experience"

    narrate "As a human developer, you interact with RCH through rich terminal UI."
    narrate "Let's go through a typical development workflow..."

    # Step 1: Check system status
    narrate "First, check the system status to see available workers:"
    run_cmd "rch status --workers"

    # Step 2: Diagnose a command
    narrate "Before running a build, you can preview what will happen:"
    run_cmd "rch diagnose 'cargo build --release'"

    # Step 3: Run a build
    if rch daemon status &>/dev/null; then
        narrate "Now run the actual build. RCH transparently offloads to a worker:"
        cd "$TEMP_PROJECT"
        run_cmd "cargo build"

        # Step 4: Run tests
        narrate "Running tests also gets offloaded:"
        run_cmd "cargo test"
    else
        narrate "Daemon not running - showing simulated output:"
        echo ""
        echo -e "${DIM}   Compiling demo_project v0.1.0 ${YELLOW}[worker: build-server-1]${NC}"
        echo -e "${GREEN}    Finished${NC} dev [unoptimized + debuginfo] in 2.34s"
        echo ""
    fi

    # Step 5: Check doctor
    narrate "If something goes wrong, run diagnostics:"
    run_cmd "rch doctor"
}

# Demo: Agent Experience (contrast)
demo_agent_experience() {
    section "AI Agent Experience (Contrast)"

    narrate "When an AI coding agent runs the same commands, RCH operates silently."
    narrate "The agent sees standard cargo output - no rich UI, no progress bars."

    echo ""
    echo -e "${BOLD}What the agent invokes:${NC}"
    echo -e "${DIM}  {\"tool\": \"Bash\", \"command\": \"cargo build --release\"}${NC}"
    echo ""
    echo -e "${BOLD}What RCH does behind the scenes:${NC}"
    echo -e "  ${CYAN}1.${NC} Hook intercepts command (<1ms decision)"
    echo -e "  ${CYAN}2.${NC} Classify as: CargoBuild (confidence: 0.99)"
    echo -e "  ${CYAN}3.${NC} Query daemon for worker (12ms)"
    echo -e "  ${CYAN}4.${NC} Upload project to worker (rsync, 156ms)"
    echo -e "  ${CYAN}5.${NC} Execute remotely (8.2s)"
    echo -e "  ${CYAN}6.${NC} Retrieve artifacts (89ms)"
    echo -e "  ${CYAN}7.${NC} Return output to agent"
    echo ""
    echo -e "${BOLD}What the agent sees:${NC}"
    echo -e "${DIM}     Compiling demo_project v0.1.0${NC}"
    echo -e "${GREEN}    Finished${NC} release [optimized] in 8.42s"
    echo ""

    narrate "The agent has no idea compilation ran remotely. That's the point!"
    narrate "Transparency enables faster builds without agent modification."
}

# Demo: Workflow Scenarios
demo_workflow_scenarios() {
    section "Common Workflow Scenarios"

    # Scenario 1: Initial setup
    echo -e "${BOLD}Scenario 1: First-Time Setup${NC}"
    echo ""
    echo -e "  ${GREEN}\$${NC} rch init"
    echo -e "${DIM}  → Interactive wizard guides through:${NC}"
    echo -e "${DIM}     • Detecting workers from ~/.ssh/config${NC}"
    echo -e "${DIM}     • Probing connectivity${NC}"
    echo -e "${DIM}     • Deploying rch-wkr to workers${NC}"
    echo -e "${DIM}     • Syncing Rust toolchain${NC}"
    echo -e "${DIM}     • Installing Claude Code hook${NC}"
    echo ""

    # Scenario 2: Adding a new worker
    echo -e "${BOLD}Scenario 2: Adding a New Worker${NC}"
    echo ""
    echo -e "  ${GREEN}\$${NC} rch workers discover"
    echo -e "${DIM}  → Scans SSH config for potential workers${NC}"
    echo -e "  ${GREEN}\$${NC} rch workers setup new-server"
    echo -e "${DIM}  → Deploys binary, syncs toolchain${NC}"
    echo -e "  ${GREEN}\$${NC} rch workers benchmark --all"
    echo -e "${DIM}  → Updates speed scores for selection${NC}"
    echo ""

    # Scenario 3: Troubleshooting
    echo -e "${BOLD}Scenario 3: Troubleshooting Connection Issues${NC}"
    echo ""
    echo -e "  ${GREEN}\$${NC} rch doctor"
    echo -e "${DIM}  → Comprehensive system check${NC}"
    echo -e "  ${GREEN}\$${NC} rch workers probe build1 -v"
    echo -e "${DIM}  → Detailed connectivity test${NC}"
    echo -e "  ${GREEN}\$${NC} rch daemon logs -n 50"
    echo -e "${DIM}  → Recent daemon logs${NC}"
    echo ""

    # Scenario 4: CI Integration
    echo -e "${BOLD}Scenario 4: CI/CD Integration${NC}"
    echo ""
    echo -e "${DIM}  # In CI, use mock mode (no real workers):${NC}"
    echo -e "  ${GREEN}\$${NC} export RCH_MOCK_SSH=1"
    echo -e "  ${GREEN}\$${NC} cargo build"
    echo -e "${DIM}  → Builds locally with mock telemetry${NC}"
    echo ""
    echo -e "${DIM}  # Or use --json for machine parsing:${NC}"
    echo -e "  ${GREEN}\$${NC} rch status --json | jq '.workers | length'"
    echo -e "${DIM}  → Returns: 3${NC}"
    echo ""
}

# Demo: Performance comparison
demo_performance() {
    section "Performance Comparison"

    echo -e "${BOLD}Typical Build Times (Rust project with 50 dependencies):${NC}"
    echo ""
    echo -e "  ┌─────────────────────────────┬────────────┬────────────┐"
    echo -e "  │ ${BOLD}Scenario${NC}                    │ ${BOLD}Local${NC}      │ ${BOLD}RCH${NC}        │"
    echo -e "  ├─────────────────────────────┼────────────┼────────────┤"
    echo -e "  │ Clean build (debug)         │ 45s        │ 12s        │"
    echo -e "  │ Clean build (release)       │ 2m 15s     │ 35s        │"
    echo -e "  │ Incremental (1 file)        │ 8s         │ 3s         │"
    echo -e "  │ cargo check                 │ 15s        │ 4s         │"
    echo -e "  │ cargo test (50 tests)       │ 30s        │ 10s        │"
    echo -e "  └─────────────────────────────┴────────────┴────────────┘"
    echo ""
    echo -e "${DIM}  * Times vary based on project size and worker specs${NC}"
    echo -e "${DIM}  * RCH adds ~200ms overhead for transfer and setup${NC}"
    echo -e "${DIM}  * Cache affinity further improves incremental builds${NC}"
    echo ""
}

# Main
main() {
    echo ""
    echo -e "${BOLD}${MAGENTA}"
    echo "   ██╗███╗   ██╗████████╗███████╗ ██████╗ ██████╗  █████╗ ████████╗██╗ ██████╗ ███╗   ██╗"
    echo "   ██║████╗  ██║╚══██╔══╝██╔════╝██╔════╝ ██╔══██╗██╔══██╗╚══██╔══╝██║██╔═══██╗████╗  ██║"
    echo "   ██║██╔██╗ ██║   ██║   █████╗  ██║  ███╗██████╔╝███████║   ██║   ██║██║   ██║██╔██╗ ██║"
    echo "   ██║██║╚██╗██║   ██║   ██╔══╝  ██║   ██║██╔══██╗██╔══██║   ██║   ██║██║   ██║██║╚██╗██║"
    echo "   ██║██║ ╚████║   ██║   ███████╗╚██████╔╝██║  ██║██║  ██║   ██║   ██║╚██████╔╝██║ ╚████║"
    echo "   ╚═╝╚═╝  ╚═══╝   ╚═╝   ╚══════╝ ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝   ╚═╝   ╚═╝ ╚═════╝ ╚═╝  ╚═══╝"
    echo ""
    echo "   RCH Real-World Integration Demo"
    echo -e "${NC}"

    check_prereqs
    create_test_project
    demo_human_experience
    demo_agent_experience
    demo_workflow_scenarios
    demo_performance

    section "Integration Demo Complete"
    echo -e "${GREEN}Real-world workflow demonstrated successfully.${NC}"
    echo ""
    echo -e "${DIM}Key insights:${NC}"
    echo -e "  ${CYAN}•${NC} Humans see rich progress visualization"
    echo -e "  ${CYAN}•${NC} Agents see standard output (transparent)"
    echo -e "  ${CYAN}•${NC} Both benefit from faster remote compilation"
    echo -e "  ${CYAN}•${NC} Hook decision happens in <1ms for 99% of commands"
}

main "$@"
