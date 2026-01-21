#!/bin/bash
#
# progress_demo.sh - Demonstrate RCH progress bars and transfer visualization
#
# Prerequisites:
#   - rch binary built and in PATH (cargo build --release)
#   - rchd daemon running (rch daemon start)
#   - At least one worker configured
#
# Usage:
#   ./examples/progress_demo.sh              # Run progress demos
#   RCH_MOCK_SSH=1 ./examples/progress_demo.sh  # Demo with mock transport
#
# For asciinema recording:
#   asciinema rec -c "./examples/progress_demo.sh" progress_demo.cast
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
    echo -e "${DIM}Progress demo completed (exit code: $exit_code)${NC}"
}
trap cleanup EXIT

# Print a section header
section() {
    echo ""
    echo -e "${BOLD}${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${BOLD}${BLUE}  $1${NC}"
    echo -e "${BOLD}${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
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
    echo -e "${GREEN}✓${NC} rch binary found"

    if ! command -v cargo &>/dev/null; then
        echo -e "${RED}Error: cargo not found in PATH${NC}"
        exit 1
    fi
    echo -e "${GREEN}✓${NC} cargo found"

    # Check if daemon is running
    if rch daemon status &>/dev/null; then
        echo -e "${GREEN}✓${NC} rchd daemon is running"
    else
        echo -e "${YELLOW}!${NC} rchd daemon not running"
        echo -e "${DIM}  Starting daemon for demo...${NC}"
        rch daemon start || {
            echo -e "${YELLOW}!${NC} Could not start daemon. Progress may not be visible."
        }
    fi
}

# Create a test Rust project
create_test_project() {
    section "Creating Test Project"

    TEMP_PROJECT=$(mktemp -d)
    echo -e "${DIM}Creating project in: $TEMP_PROJECT${NC}"

    cd "$TEMP_PROJECT"
    cargo init --name progress_demo --quiet

    # Add some dependencies to make build take longer
    cat >> Cargo.toml << 'EOF'
[dependencies]
serde = { version = "1.0", features = ["derive"] }
serde_json = "1.0"
tokio = { version = "1", features = ["full"] }
regex = "1"
EOF

    # Create a more complex main.rs
    cat > src/main.rs << 'EOF'
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Serialize, Deserialize, Debug)]
struct Config {
    name: String,
    values: HashMap<String, i32>,
}

fn process_config(config: &Config) -> String {
    format!("Processing: {} with {} values", config.name, config.values.len())
}

fn main() {
    let config = Config {
        name: "progress_demo".to_string(),
        values: HashMap::from([
            ("alpha".to_string(), 1),
            ("beta".to_string(), 2),
            ("gamma".to_string(), 3),
        ]),
    };

    let result = process_config(&config);
    println!("{}", result);

    // Test regex
    let re = regex::Regex::new(r"\d+").unwrap();
    let count = re.find_iter(&result).count();
    println!("Found {} numbers", count);
}
EOF

    # Add a test file
    mkdir -p tests
    cat > tests/integration_test.rs << 'EOF'
#[test]
fn test_basic() {
    assert!(1 + 1 == 2);
}

#[test]
fn test_string() {
    let s = "hello".to_string();
    assert!(!s.is_empty());
}
EOF

    echo -e "${GREEN}✓${NC} Created test project with dependencies"
    echo -e "${DIM}  Dependencies: serde, serde_json, tokio, regex${NC}"
}

# Demo: Transfer Progress
demo_transfer_progress() {
    section "Transfer Progress Visualization"

    info "During file transfer to workers, you'll see progress like:"
    echo ""
    echo -e "${CYAN}  ┌─[UPLOAD]──────────────────────────────────────────────┐${NC}"
    echo -e "${CYAN}  │ ▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓░░░░░░░░░░ 75% │${NC}"
    echo -e "${CYAN}  │ 245 KB / 326 KB  •  12.4 MB/s  •  ETA: 0s           │${NC}"
    echo -e "${CYAN}  └───────────────────────────────────────────────────────┘${NC}"
    echo ""
    info "The progress bar shows:"
    echo -e "  ${CYAN}•${NC} Bytes transferred / Total bytes"
    echo -e "  ${CYAN}•${NC} Transfer speed"
    echo -e "  ${CYAN}•${NC} Estimated time remaining"
    echo ""
}

# Demo: Compilation Progress
demo_compilation_progress() {
    section "Compilation Progress Visualization"

    info "During compilation, you'll see live progress like:"
    echo ""
    echo -e "${GREEN}  [cargo build]${NC}"
    echo -e "${DIM}     Compiling serde v1.0.195${NC}"
    echo -e "${DIM}     Compiling tokio v1.35.1${NC}"
    echo -e "${DIM}     Compiling regex v1.10.2${NC}"
    echo -e "${GREEN}  ✓  Compiling progress_demo v0.1.0${NC}"
    echo -e "${GREEN}     Finished dev [unoptimized + debuginfo] in 12.34s${NC}"
    echo ""
    info "Features:"
    echo -e "  ${CYAN}•${NC} Real-time crate compilation status"
    echo -e "  ${CYAN}•${NC} Warning and error counts"
    echo -e "  ${CYAN}•${NC} Final timing summary"
    echo ""
}

# Demo: Pipeline Progress
demo_pipeline_progress() {
    section "Pipeline Progress (Multi-Stage)"

    info "Remote compilation follows a 5-stage pipeline:"
    echo ""
    echo -e "${GREEN}  ✓${NC} ${BOLD}Workspace Analysis${NC}    ${DIM}(12ms)${NC}"
    echo -e "${GREEN}  ✓${NC} ${BOLD}Upload${NC}                ${DIM}(156ms • 245 KB)${NC}"
    echo -e "${CYAN}  ●${NC} ${BOLD}Compilation${NC}           ${DIM}(in progress...)${NC}"
    echo -e "${DIM}  ○ Artifact Retrieval${NC}"
    echo -e "${DIM}  ○ Cache Update${NC}"
    echo ""
    info "Each stage shows:"
    echo -e "  ${CYAN}•${NC} Completion status (✓ done, ● active, ○ pending)"
    echo -e "  ${CYAN}•${NC} Timing information"
    echo -e "  ${CYAN}•${NC} Data transfer sizes"
    echo ""
}

# Demo: Real Build (if daemon available)
demo_real_build() {
    section "Live Build Demo"

    if ! rch daemon status &>/dev/null; then
        echo -e "${YELLOW}!${NC} Daemon not running - skipping live demo"
        echo -e "${DIM}  Start daemon with: rch daemon start${NC}"
        return 0
    fi

    cd "$TEMP_PROJECT"

    info "Running: cargo check (via RCH hook)"
    echo ""

    # This will go through the RCH pipeline if daemon is running
    cargo check 2>&1 || true

    echo ""
    info "Running: cargo build (via RCH hook)"
    echo ""

    cargo build 2>&1 || true

    echo ""
    info "Running: cargo test (via RCH hook)"
    echo ""

    cargo test 2>&1 || true
}

# Demo: Cache Hit Scenario
demo_cache_scenarios() {
    section "Cache Hit/Miss Scenarios"

    info "First build (cache miss):"
    echo ""
    echo -e "${DIM}  ┌─[PIPELINE]─────────────────────────────────────────────┐${NC}"
    echo -e "${DIM}  │ ${GREEN}✓${NC}${DIM} Workspace Analysis     12ms                       │${NC}"
    echo -e "${DIM}  │ ${GREEN}✓${NC}${DIM} Upload                 156ms  (245 KB)            │${NC}"
    echo -e "${DIM}  │ ${GREEN}✓${NC}${DIM} Compilation            12.4s  ${YELLOW}(cold)${NC}${DIM}             │${NC}"
    echo -e "${DIM}  │ ${GREEN}✓${NC}${DIM} Artifact Retrieval     89ms   (1.2 MB)            │${NC}"
    echo -e "${DIM}  │ ${GREEN}✓${NC}${DIM} Cache Update           23ms                       │${NC}"
    echo -e "${DIM}  └───────────────────────────────────────────────────────┘${NC}"
    echo ""

    info "Second build (incremental cache hit):"
    echo ""
    echo -e "${DIM}  ┌─[PIPELINE]─────────────────────────────────────────────┐${NC}"
    echo -e "${DIM}  │ ${GREEN}✓${NC}${DIM} Workspace Analysis     8ms                        │${NC}"
    echo -e "${DIM}  │ ${GREEN}✓${NC}${DIM} Upload                 45ms   (12 KB delta)       │${NC}"
    echo -e "${DIM}  │ ${GREEN}✓${NC}${DIM} Compilation            1.2s   ${GREEN}(warm)${NC}${DIM}              │${NC}"
    echo -e "${DIM}  │ ${GREEN}✓${NC}${DIM} Artifact Retrieval     34ms   (45 KB delta)       │${NC}"
    echo -e "${DIM}  │ ${CYAN}○${NC}${DIM} Cache Update           (skipped - no changes)     │${NC}"
    echo -e "${DIM}  └───────────────────────────────────────────────────────┘${NC}"
    echo ""

    info "Cache affinity optimizes worker selection for incremental builds."
}

# Main
main() {
    echo ""
    echo -e "${BOLD}${BLUE}"
    echo "   ██████╗ ██████╗  ██████╗  ██████╗ ██████╗ ███████╗███████╗███████╗"
    echo "   ██╔══██╗██╔══██╗██╔═══██╗██╔════╝ ██╔══██╗██╔════╝██╔════╝██╔════╝"
    echo "   ██████╔╝██████╔╝██║   ██║██║  ███╗██████╔╝█████╗  ███████╗███████╗"
    echo "   ██╔═══╝ ██╔══██╗██║   ██║██║   ██║██╔══██╗██╔══╝  ╚════██║╚════██║"
    echo "   ██║     ██║  ██║╚██████╔╝╚██████╔╝██║  ██║███████╗███████║███████║"
    echo "   ╚═╝     ╚═╝  ╚═╝ ╚═════╝  ╚═════╝ ╚═╝  ╚═╝╚══════╝╚══════╝╚══════╝"
    echo ""
    echo "   RCH Progress Visualization Demo"
    echo -e "${NC}"

    check_prereqs
    create_test_project
    demo_transfer_progress
    demo_compilation_progress
    demo_pipeline_progress
    demo_cache_scenarios
    demo_real_build

    section "Progress Demo Complete"
    echo -e "${GREEN}Progress visualization demonstrated successfully.${NC}"
    echo ""
    echo -e "${DIM}Progress is shown:${NC}"
    echo -e "  ${CYAN}•${NC} During file transfers (upload/download)"
    echo -e "  ${CYAN}•${NC} During remote compilation (crate-by-crate)"
    echo -e "  ${CYAN}•${NC} Across the 5-stage pipeline"
    echo -e "  ${CYAN}•${NC} With cache hit/miss indicators"
}

main "$@"
