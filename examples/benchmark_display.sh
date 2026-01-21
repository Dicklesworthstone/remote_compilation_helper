#!/bin/bash
#
# benchmark_display.sh - Run worker benchmarks with rich output display
#
# Prerequisites:
#   - rch binary built and in PATH (cargo build --release)
#   - rchd daemon running (rch daemon start)
#   - At least one worker configured
#
# Usage:
#   ./examples/benchmark_display.sh              # Run benchmarks
#   ./examples/benchmark_display.sh --mock       # Demo without real workers
#
# For asciinema recording:
#   asciinema rec -c "./examples/benchmark_display.sh" benchmark.cast
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

MOCK_MODE=false
[[ "${1:-}" == "--mock" ]] && MOCK_MODE=true

# Cleanup function
cleanup() {
    local exit_code=$?
    echo ""
    echo -e "${DIM}Benchmark demo completed (exit code: $exit_code)${NC}"
}
trap cleanup EXIT

# Print a section header
section() {
    echo ""
    echo -e "${BOLD}${YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${BOLD}${YELLOW}  $1${NC}"
    echo -e "${BOLD}${YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
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
        exit 1
    fi
    echo -e "${GREEN}✓${NC} rch binary found"

    if $MOCK_MODE; then
        echo -e "${YELLOW}!${NC} Running in mock mode (no real workers)"
        return 0
    fi

    if rch daemon status &>/dev/null; then
        echo -e "${GREEN}✓${NC} rchd daemon is running"
    else
        echo -e "${YELLOW}!${NC} Daemon not running - benchmarks will fail"
        echo -e "${DIM}  Start with: rch daemon start${NC}"
    fi
}

# Show current speed scores
show_speed_scores() {
    section "Current Speed Scores"

    info "SpeedScore represents relative worker performance (higher = faster)."
    echo ""

    if $MOCK_MODE; then
        # Simulated output
        echo -e "  ┌────────────────────────────────────────────────────────────────┐"
        echo -e "  │ ${BOLD}Worker${NC}          │ ${BOLD}SpeedScore${NC} │ ${BOLD}Cores${NC} │ ${BOLD}Status${NC}    │ ${BOLD}Last Run${NC}   │"
        echo -e "  ├────────────────────────────────────────────────────────────────┤"
        echo -e "  │ build-server-1  │ ${GREEN}1.45${NC}       │ 32    │ ${GREEN}Healthy${NC}   │ 2h ago     │"
        echo -e "  │ build-server-2  │ ${GREEN}1.32${NC}       │ 16    │ ${GREEN}Healthy${NC}   │ 4h ago     │"
        echo -e "  │ dev-laptop      │ ${YELLOW}0.78${NC}       │ 8     │ ${GREEN}Healthy${NC}   │ 1d ago     │"
        echo -e "  │ old-server      │ ${RED}0.42${NC}       │ 4     │ ${YELLOW}Degraded${NC}  │ 5d ago     │"
        echo -e "  └────────────────────────────────────────────────────────────────┘"
    else
        rch workers list 2>&1 || true
    fi

    echo ""
    info "SpeedScore interpretation:"
    echo -e "  ${GREEN}> 1.0${NC}  Faster than baseline"
    echo -e "  ${YELLOW}0.5-1.0${NC}  Around baseline performance"
    echo -e "  ${RED}< 0.5${NC}  Slower than baseline"
}

# Show benchmark history
show_benchmark_history() {
    section "Benchmark History"

    info "Recent benchmark runs for each worker:"
    echo ""

    if $MOCK_MODE; then
        # Simulated output
        echo -e "  ${BOLD}build-server-1${NC} (last 5 runs)"
        echo -e "  ┌───────────────┬────────────┬────────────┬──────────┐"
        echo -e "  │ ${BOLD}Timestamp${NC}     │ ${BOLD}Score${NC}      │ ${BOLD}Compile${NC}    │ ${BOLD}Transfer${NC} │"
        echo -e "  ├───────────────┼────────────┼────────────┼──────────┤"
        echo -e "  │ 2h ago        │ ${GREEN}1.45${NC}       │ 4.2s       │ 0.12s    │"
        echo -e "  │ 1d ago        │ ${GREEN}1.43${NC}       │ 4.3s       │ 0.11s    │"
        echo -e "  │ 2d ago        │ ${GREEN}1.42${NC}       │ 4.3s       │ 0.13s    │"
        echo -e "  │ 3d ago        │ ${GREEN}1.41${NC}       │ 4.4s       │ 0.12s    │"
        echo -e "  │ 5d ago        │ ${GREEN}1.40${NC}       │ 4.4s       │ 0.14s    │"
        echo -e "  └───────────────┴────────────┴────────────┴──────────┘"
        echo ""
        echo -e "  ${DIM}Trend: ${GREEN}↑ +0.05${NC} (3.5% improvement over 5 runs)${NC}"
    else
        rch workers speed-score history 2>&1 || echo -e "${YELLOW}No benchmark history available${NC}"
    fi
}

# Run actual benchmarks
run_benchmarks() {
    section "Running Benchmarks"

    if $MOCK_MODE; then
        info "Simulating benchmark run..."
        echo ""

        # Animated progress simulation
        local workers=("build-server-1" "build-server-2" "dev-laptop")
        for worker in "${workers[@]}"; do
            echo -ne "  ${CYAN}●${NC} Benchmarking ${BOLD}$worker${NC}... "
            for i in {1..3}; do
                echo -ne "▓"
                sleep 0.3
            done
            echo -e " ${GREEN}✓${NC} Done (SpeedScore: 1.${RANDOM:0:2})"
            sleep 0.2
        done

        echo ""
        echo -e "  ${GREEN}✓${NC} Benchmark complete for 3 workers"
        return 0
    fi

    info "This will run a standardized compilation test on each worker."
    info "Progress is shown as each worker is benchmarked."
    echo ""

    # Check if daemon is running
    if ! rch daemon status &>/dev/null; then
        echo -e "${YELLOW}!${NC} Daemon not running - cannot run benchmarks"
        return 0
    fi

    # Run the benchmark
    rch workers benchmark --all 2>&1 || true
}

# Show selection algorithm impact
show_selection_impact() {
    section "Selection Algorithm Impact"

    info "Worker selection uses SpeedScore and other factors:"
    echo ""
    echo -e "  ${BOLD}Selection Strategies:${NC}"
    echo ""
    echo -e "  ${CYAN}Priority${NC}       Select highest priority worker with available slots"
    echo -e "  ${CYAN}Fastest${NC}        Select worker with highest SpeedScore"
    echo -e "  ${CYAN}Balanced${NC}       Weight: 40% slots + 50% speed + 10% locality"
    echo -e "  ${CYAN}CacheAffinity${NC}  Prefer workers with recent builds for this project"
    echo -e "  ${CYAN}FairFastest${NC}    Weighted random favoring fast workers"
    echo ""

    info "Example selection decision:"
    echo ""
    echo -e "  ${BOLD}Request:${NC} cargo build --release (needs 8 slots)"
    echo ""
    echo -e "  ┌─────────────────┬────────┬────────┬─────────┬───────────┐"
    echo -e "  │ ${BOLD}Worker${NC}          │ ${BOLD}Avail${NC}  │ ${BOLD}Score${NC}  │ ${BOLD}Cache${NC}   │ ${BOLD}Decision${NC}  │"
    echo -e "  ├─────────────────┼────────┼────────┼─────────┼───────────┤"
    echo -e "  │ build-server-1  │ 24/32  │ 1.45   │ ${GREEN}warm${NC}    │ ${GREEN}Selected${NC}  │"
    echo -e "  │ build-server-2  │ 8/16   │ 1.32   │ cold    │ -         │"
    echo -e "  │ dev-laptop      │ 0/8    │ 0.78   │ cold    │ No slots  │"
    echo -e "  └─────────────────┴────────┴────────┴─────────┴───────────┘"
    echo ""
    echo -e "  ${DIM}Reason: CacheAffinity + HighestScore + AvailableSlots${NC}"
}

# Show benchmark configuration
show_benchmark_config() {
    section "Benchmark Configuration"

    info "Benchmarks use a standardized workload for fair comparison:"
    echo ""
    echo -e "  ${BOLD}Workload:${NC}"
    echo -e "    • Small Rust project with common dependencies"
    echo -e "    • Clean build (target deleted before each run)"
    echo -e "    • Release mode compilation"
    echo -e "    • Measures: transfer + compile + retrieve"
    echo ""
    echo -e "  ${BOLD}Normalization:${NC}"
    echo -e "    • Baseline: 64-core Linux server"
    echo -e "    • SpeedScore = baseline_time / worker_time"
    echo -e "    • Score > 1.0 means faster than baseline"
    echo ""
    echo -e "  ${BOLD}Configuration:${NC}"
    echo -e "    • Runs: 3 (median taken)"
    echo -e "    • Warmup: 1 run (discarded)"
    echo -e "    • Cooldown: 5s between runs"
}

# Main
main() {
    echo ""
    echo -e "${BOLD}${YELLOW}"
    echo "   ██████╗ ███████╗███╗   ██╗ ██████╗██╗  ██╗███╗   ███╗ █████╗ ██████╗ ██╗  ██╗"
    echo "   ██╔══██╗██╔════╝████╗  ██║██╔════╝██║  ██║████╗ ████║██╔══██╗██╔══██╗██║ ██╔╝"
    echo "   ██████╔╝█████╗  ██╔██╗ ██║██║     ███████║██╔████╔██║███████║██████╔╝█████╔╝"
    echo -e "   ██╔══██╗██╔══╝  ██║╚██╗██║██║     ██╔══██║██║╚██╔╝██║██╔══██║██╔══██╗██╔═██╗"
    echo "   ██████╔╝███████╗██║ ╚████║╚██████╗██║  ██║██║ ╚═╝ ██║██║  ██║██║  ██║██║  ██╗"
    echo "   ╚═════╝ ╚══════╝╚═╝  ╚═══╝ ╚═════╝╚═╝  ╚═╝╚═╝     ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝"
    echo ""
    echo "   RCH Worker Benchmark Display"
    echo -e "${NC}"

    check_prereqs
    show_speed_scores
    show_benchmark_history
    run_benchmarks
    show_selection_impact
    show_benchmark_config

    section "Benchmark Demo Complete"
    echo -e "${GREEN}Benchmark display demonstrated successfully.${NC}"
    echo ""
    echo -e "${DIM}Commands for benchmarking:${NC}"
    echo -e "  ${CYAN}rch workers benchmark --all${NC}     Run benchmarks on all workers"
    echo -e "  ${CYAN}rch workers benchmark <name>${NC}    Benchmark specific worker"
    echo -e "  ${CYAN}rch workers speed-score list${NC}    View current speed scores"
    echo -e "  ${CYAN}rch workers speed-score history${NC} View benchmark history"
}

main "$@"
