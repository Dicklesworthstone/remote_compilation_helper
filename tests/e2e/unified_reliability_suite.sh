#!/usr/bin/env bash
# E2E_NAME=unified_reliability_suite
# E2E_SERIAL=1
# E2E_ARGS=--ci
#
# Unified E2E reliability suite that orchestrates all scenario families:
#   - Path dependency closure (bd-vvmd.2.8)
#   - Repo convergence (bd-vvmd.3.6)
#   - Disk pressure prevention (bd-vvmd.4.6)
#   - Process triage detection (bd-vvmd.5.6)
#   - Reliability harness foundation (bd-vvmd.7.7)
#   - Reliability logging contract (bd-vvmd.7.3)
#
# Modes:
#   RCH_E2E_MODE=smoke   (default) - fast contract + unit + integration tests
#   RCH_E2E_MODE=nightly           - full suite including topology, soak, and regression
#
# Seed control:
#   RCH_E2E_SEED=<u64>   - deterministic seed for reproducible fixture generation
#
# Output:
#   Machine-readable JSONL phase logs and retained artifacts under target/e2e-suite/

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
LOG_PREFIX="[unified-e2e]"

E2E_MODE="${RCH_E2E_MODE:-smoke}"
E2E_SEED="${RCH_E2E_SEED:-}"
SUITE_DIR="${PROJECT_ROOT}/target/e2e-suite"
SUITE_LOG="${SUITE_DIR}/suite_run.jsonl"
SUITE_SUMMARY="${SUITE_DIR}/suite_summary.json"

PASS_COUNT=0
FAIL_COUNT=0
SKIP_COUNT=0
FAMILIES_RUN=()

# ---------------------------------------------------------------------------
# Logging helpers
# ---------------------------------------------------------------------------

log() {
  printf '%s %s\n' "$LOG_PREFIX" "$*"
}

fail() {
  printf '%s ERROR: %s\n' "$LOG_PREFIX" "$*" >&2
  exit 1
}

warn() {
  printf '%s WARN: %s\n' "$LOG_PREFIX" "$*" >&2
}

require_cmd() {
  command -v "$1" >/dev/null 2>&1 || fail "missing required command: $1"
}

emit_phase_event() {
  local family="$1" phase="$2" status="$3" duration_ms="${4:-0}"
  local ts
  ts="$(date -u +%Y-%m-%dT%H:%M:%S.%3NZ 2>/dev/null || date -u +%Y-%m-%dT%H:%M:%SZ)"
  printf '{"timestamp":"%s","family":"%s","phase":"%s","status":"%s","duration_ms":%d,"mode":"%s"}\n' \
    "$ts" "$family" "$phase" "$status" "$duration_ms" "$E2E_MODE" >> "$SUITE_LOG"
}

# ---------------------------------------------------------------------------
# Setup
# ---------------------------------------------------------------------------

setup_suite_dir() {
  mkdir -p "$SUITE_DIR"
  : > "$SUITE_LOG"
  log "suite output directory: $SUITE_DIR"
  log "mode=$E2E_MODE seed=${E2E_SEED:-<random>}"
}

# ---------------------------------------------------------------------------
# Scenario family runners
# ---------------------------------------------------------------------------

run_family() {
  local family="$1"
  shift
  local start_ms
  start_ms="$(date +%s%3N 2>/dev/null || echo 0)"

  log "--- $family ---"
  emit_phase_event "$family" "start" "running"

  if "$@" 2>&1 | tee -a "${SUITE_DIR}/${family}.log"; then
    local end_ms
    end_ms="$(date +%s%3N 2>/dev/null || echo 0)"
    local duration=$(( end_ms - start_ms ))
    emit_phase_event "$family" "done" "pass" "$duration"
    log "PASS: $family (${duration}ms)"
    PASS_COUNT=$(( PASS_COUNT + 1 ))
    FAMILIES_RUN+=("$family:pass")
  else
    local end_ms
    end_ms="$(date +%s%3N 2>/dev/null || echo 0)"
    local duration=$(( end_ms - start_ms ))
    emit_phase_event "$family" "done" "fail" "$duration"
    warn "FAIL: $family (${duration}ms)"
    FAIL_COUNT=$(( FAIL_COUNT + 1 ))
    FAMILIES_RUN+=("$family:fail")
  fi
}

skip_family() {
  local family="$1" reason="$2"
  log "SKIP: $family ($reason)"
  emit_phase_event "$family" "skip" "skipped"
  SKIP_COUNT=$(( SKIP_COUNT + 1 ))
  FAMILIES_RUN+=("$family:skip")
}

# ---------------------------------------------------------------------------
# Family: path dependency closure (bd-vvmd.2.8)
# ---------------------------------------------------------------------------

run_path_deps() {
  log "running cross-repo path dependency E2E scenarios"
  (
    cd "$PROJECT_ROOT"
    CARGO_TARGET_DIR=/data/tmp/cargo-target cargo test -p rch-common --test cross_repo_path_deps_e2e -- --nocapture
  )
}

# ---------------------------------------------------------------------------
# Family: repo convergence (bd-vvmd.3.6)
# ---------------------------------------------------------------------------

run_repo_convergence() {
  log "running repo convergence E2E scenarios"
  (
    cd "$PROJECT_ROOT"
    CARGO_TARGET_DIR=/data/tmp/cargo-target cargo test -p rch-common --test repo_convergence_e2e -- --nocapture
  )
}

# ---------------------------------------------------------------------------
# Family: process triage (bd-vvmd.5.6)
# ---------------------------------------------------------------------------

run_process_triage() {
  log "running process triage contract E2E scenarios"
  (
    cd "$PROJECT_ROOT"
    CARGO_TARGET_DIR=/data/tmp/cargo-target cargo test -p rch-common --test process_triage_e2e -- --nocapture
  )
}

# ---------------------------------------------------------------------------
# Family: disk pressure prevention (bd-vvmd.4.6)
# ---------------------------------------------------------------------------

run_disk_pressure() {
  log "running disk pressure policy unit tests"
  (
    cd "$PROJECT_ROOT"
    CARGO_TARGET_DIR=/data/tmp/cargo-target cargo test -p rchd -- disk_pressure --nocapture
  )
}

# ---------------------------------------------------------------------------
# Family: fault injection (bd-vvmd.7.6)
# ---------------------------------------------------------------------------

run_fault_injection() {
  log "running fault-injection E2E scenarios"
  (
    cd "$PROJECT_ROOT"
    CARGO_TARGET_DIR=/data/tmp/cargo-target cargo test -p rch-common --test fault_injection_e2e -- --nocapture
  )
}

# ---------------------------------------------------------------------------
# Family: reliability harness foundation (bd-vvmd.7.7)
# ---------------------------------------------------------------------------

run_reliability_harness() {
  log "running reliability harness foundation tests"
  (
    cd "$PROJECT_ROOT"
    CARGO_TARGET_DIR=/data/tmp/cargo-target cargo test -p rch-common -- e2e::tests --nocapture
  )
}

# ---------------------------------------------------------------------------
# Family: reliability logging contract (bd-vvmd.7.3)
# ---------------------------------------------------------------------------

run_reliability_logging() {
  log "running reliability logging schema contract tests"
  (
    cd "$PROJECT_ROOT"
    CARGO_TARGET_DIR=/data/tmp/cargo-target cargo test -p rch-common -- logging::tests --nocapture
  )
}

# ---------------------------------------------------------------------------
# Family: topology fixtures (bd-vvmd.7.1)
# ---------------------------------------------------------------------------

run_topology_fixtures() {
  log "running topology fixture smoke tests"
  if [[ ! -d /data/projects ]] || [[ ! -L /dp ]]; then
    skip_family "topology_fixtures" "missing /data/projects or /dp symlink"
    return 0
  fi
  (
    cd "$PROJECT_ROOT"
    CARGO_TARGET_DIR=/data/tmp/cargo-target cargo test -p rch-common -- multi_repo_fixture_ --nocapture
  )
}

# ---------------------------------------------------------------------------
# Family: command-classification regression (bd-vvmd.2.9)
# ---------------------------------------------------------------------------

run_classification_regression() {
  log "running command classification regression tests"
  (
    cd "$PROJECT_ROOT"
    CARGO_TARGET_DIR=/data/tmp/cargo-target cargo test -p rch-common -- classify --nocapture
  )
}

# ---------------------------------------------------------------------------
# Family: schema contract (bd-vvmd.6.8)
# ---------------------------------------------------------------------------

run_schema_contract() {
  log "running JSON/log schema contract tests"
  (
    cd "$PROJECT_ROOT"
    CARGO_TARGET_DIR=/data/tmp/cargo-target cargo test -p rch-common --test schema_contract_e2e -- --nocapture
  )
}

# ---------------------------------------------------------------------------
# Nightly-only families
# ---------------------------------------------------------------------------

run_nightly_topology_deep() {
  log "running nightly deep topology canonicalization tests"
  (
    cd "$PROJECT_ROOT"
    CARGO_TARGET_DIR=/data/tmp/cargo-target cargo test -p rch-common -- path_topology::tests --nocapture
  )
}

run_nightly_contract_schema_deep() {
  log "running nightly schema deep validation"
  (
    cd "$PROJECT_ROOT"
    CARGO_TARGET_DIR=/data/tmp/cargo-target cargo test -p rch-common -- repo_updater_contract::tests --nocapture
    CARGO_TARGET_DIR=/data/tmp/cargo-target cargo test -p rch-common -- process_triage::tests --nocapture
  )
}

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------

write_summary() {
  local total=$(( PASS_COUNT + FAIL_COUNT + SKIP_COUNT ))
  local families_json="["
  local first=true
  for entry in "${FAMILIES_RUN[@]}"; do
    local name="${entry%%:*}"
    local status="${entry##*:}"
    if [ "$first" = true ]; then
      first=false
    else
      families_json+=","
    fi
    families_json+="$(printf '{"name":"%s","status":"%s"}' "$name" "$status")"
  done
  families_json+="]"

  cat > "$SUITE_SUMMARY" <<EOJSON
{
  "mode": "$E2E_MODE",
  "seed": "${E2E_SEED:-null}",
  "total": $total,
  "pass": $PASS_COUNT,
  "fail": $FAIL_COUNT,
  "skip": $SKIP_COUNT,
  "families": $families_json
}
EOJSON

  log "=============================================="
  log "  Suite Summary: $PASS_COUNT pass / $FAIL_COUNT fail / $SKIP_COUNT skip ($total total)"
  log "  Mode: $E2E_MODE"
  log "  Artifacts: $SUITE_DIR"
  log "=============================================="
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

main() {
  require_cmd cargo

  setup_suite_dir

  # Export seed if set (for deterministic fixture generation)
  if [[ -n "$E2E_SEED" ]]; then
    export RCH_E2E_SEED="$E2E_SEED"
  fi

  # --- Smoke families (always run) ---
  run_family "path_deps"              run_path_deps
  run_family "repo_convergence"       run_repo_convergence
  run_family "process_triage"         run_process_triage
  run_family "disk_pressure"          run_disk_pressure
  run_family "reliability_harness"    run_reliability_harness
  run_family "reliability_logging"    run_reliability_logging
  run_family "topology_fixtures"      run_topology_fixtures
  run_family "fault_injection"           run_fault_injection
  run_family "classification_regression" run_classification_regression
  run_family "schema_contract"           run_schema_contract

  # --- Nightly families (only in nightly/full mode) ---
  case "$E2E_MODE" in
    smoke)
      log "skipping nightly-only families (set RCH_E2E_MODE=nightly for full suite)"
      ;;
    nightly|full)
      run_family "nightly_topology_deep"      run_nightly_topology_deep
      run_family "nightly_contract_schema"    run_nightly_contract_schema_deep
      ;;
    *)
      fail "unknown RCH_E2E_MODE=$E2E_MODE (expected smoke|nightly|full)"
      ;;
  esac

  write_summary

  if [[ $FAIL_COUNT -gt 0 ]]; then
    fail "$FAIL_COUNT scenario families failed"
  fi

  log "PASS: unified reliability suite completed successfully"
}

main "$@"
