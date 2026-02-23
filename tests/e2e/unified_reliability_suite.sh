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
# Family: cross-worker parity (bd-vvmd.7.10)
# ---------------------------------------------------------------------------

run_cross_worker_parity() {
  log "running cross-worker determinism/parity E2E scenarios"
  (
    cd "$PROJECT_ROOT"
    CARGO_TARGET_DIR=/data/tmp/cargo-target cargo test -p rch-common --test cross_worker_parity_e2e -- --nocapture
  )
}

# ---------------------------------------------------------------------------
# Family: soak concurrency (bd-vvmd.7.9)
# ---------------------------------------------------------------------------

run_soak_concurrency() {
  log "running soak concurrency E2E scenarios"
  (
    cd "$PROJECT_ROOT"
    CARGO_TARGET_DIR=/data/tmp/cargo-target cargo test -p rch-common --test soak_concurrency_e2e -- --nocapture
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
# Family: deterministic replay (bd-vvmd.7.12)
# ---------------------------------------------------------------------------

run_deterministic_replay() {
  log "running deterministic replay workflow E2E scenarios"
  (
    cd "$PROJECT_ROOT"
    CARGO_TARGET_DIR=/data/tmp/cargo-target cargo test -p rch-common --test deterministic_replay_e2e -- --nocapture
  )
}

# ---------------------------------------------------------------------------
# Family: performance budget (bd-vvmd.6.6)
# ---------------------------------------------------------------------------

run_performance_budget() {
  log "running performance budget assertion E2E scenarios"
  (
    cd "$PROJECT_ROOT"
    CARGO_TARGET_DIR=/data/tmp/cargo-target cargo test -p rch-common --test performance_budget_e2e -- --nocapture
  )
}

# ---------------------------------------------------------------------------
# Family: local-vs-remote parity (bd-vvmd.7.11)
# ---------------------------------------------------------------------------

run_local_remote_parity() {
  log "running local-vs-remote parity validation E2E scenarios"
  (
    cd "$PROJECT_ROOT"
    CARGO_TARGET_DIR=/data/tmp/cargo-target cargo test -p rch-common --test local_remote_parity_e2e -- --nocapture
  )
}

# ---------------------------------------------------------------------------
# Family: feature flags + rollout (bd-vvmd.6.7)
# ---------------------------------------------------------------------------

run_feature_flags_rollout() {
  log "running feature flags and staged rollout E2E scenarios"
  (
    cd "$PROJECT_ROOT"
    CARGO_TARGET_DIR=/data/tmp/cargo-target cargo test -p rch-common --test feature_flags_rollout_e2e -- --nocapture
  )
}

# ---------------------------------------------------------------------------
# Family: contract-drift compatibility (bd-vvmd.6.11)
# ---------------------------------------------------------------------------

run_contract_drift() {
  log "running cross-project helper contract-drift compatibility E2E scenarios"
  (
    cd "$PROJECT_ROOT"
    CARGO_TARGET_DIR=/data/tmp/cargo-target cargo test -p rch-common --test contract_drift_e2e -- --nocapture
  )
}

# ---------------------------------------------------------------------------
# Family: redaction + retention governance (bd-vvmd.6.10)
# ---------------------------------------------------------------------------

run_redaction_retention() {
  log "running redaction and retention governance E2E scenarios"
  (
    cd "$PROJECT_ROOT"
    CARGO_TARGET_DIR=/data/tmp/cargo-target cargo test -p rch-common --test redaction_retention_e2e -- --nocapture
  )
}

# ---------------------------------------------------------------------------
# Family: reliability doctor (bd-vvmd.6.9)
# ---------------------------------------------------------------------------

run_reliability_doctor() {
  log "running reliability doctor E2E scenarios"
  (
    cd "$PROJECT_ROOT"
    CARGO_TARGET_DIR=/data/tmp/cargo-target cargo test -p rch-common --test reliability_doctor_e2e -- --nocapture
  )
}

# ---------------------------------------------------------------------------
# Family: UX regression (bd-1qhj)
# ---------------------------------------------------------------------------

run_ux_regression() {
  log "running UX regression E2E scenarios"
  (
    cd "$PROJECT_ROOT"
    CARGO_TARGET_DIR=/data/tmp/cargo-target cargo test -p rch-common --test ux_regression_e2e -- --nocapture
  )
}

# ---------------------------------------------------------------------------
# Family: coverage matrix (bd-vvmd.7.8)
# ---------------------------------------------------------------------------

run_coverage_matrix() {
  log "running reliability coverage matrix staleness checks"
  (
    cd "$PROJECT_ROOT"
    CARGO_TARGET_DIR=/data/tmp/cargo-target cargo test -p rch-common --test reliability_coverage_matrix_e2e -- --nocapture
  )
}

# ---------------------------------------------------------------------------
# Family: CI test tiers (bd-vvmd.7.4)
# ---------------------------------------------------------------------------

run_ci_test_tiers() {
  log "running CI test tier definition validation"
  (
    cd "$PROJECT_ROOT"
    CARGO_TARGET_DIR=/data/tmp/cargo-target cargo test -p rch-common --test ci_test_tiers_e2e -- --nocapture
  )
}

# ---------------------------------------------------------------------------
# Family: SLO guardrails (bd-vvmd.6.5)
# ---------------------------------------------------------------------------

run_slo_guardrails() {
  log "running SLO guardrail regression checks"
  (
    cd "$PROJECT_ROOT"
    CARGO_TARGET_DIR=/data/tmp/cargo-target cargo test -p rch-common --test slo_guardrails_e2e -- --nocapture
  )
}

# ---------------------------------------------------------------------------
# Family: docs validation (bd-vvmd.6.4)
# ---------------------------------------------------------------------------

run_docs_validation() {
  log "running documentation validation checks"
  (
    cd "$PROJECT_ROOT"
    CARGO_TARGET_DIR=/data/tmp/cargo-target cargo test -p rch-common --test docs_validation_e2e -- --nocapture
  )
}

# ---------------------------------------------------------------------------
# Family: release gate sign-off (bd-vvmd.7.5)
# ---------------------------------------------------------------------------

run_release_gate_signoff() {
  log "running release gate sign-off checklist"
  (
    cd "$PROJECT_ROOT"
    CARGO_TARGET_DIR=/data/tmp/cargo-target cargo test -p rch-common --test release_gate_signoff_e2e -- --nocapture
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

run_nightly_reliability_benchmarks() {
  log "running nightly criterion benchmarks for reliability pipeline"
  (
    cd "$PROJECT_ROOT"
    CARGO_TARGET_DIR=/data/tmp/cargo-target cargo bench -p rch-common --bench reliability_bench -- --quick
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
  run_family "soak_concurrency"          run_soak_concurrency
  run_family "cross_worker_parity"       run_cross_worker_parity
  run_family "deterministic_replay"      run_deterministic_replay
  run_family "performance_budget"       run_performance_budget
  run_family "local_remote_parity"     run_local_remote_parity
  run_family "redaction_retention"     run_redaction_retention
  run_family "contract_drift"          run_contract_drift
  run_family "feature_flags_rollout"  run_feature_flags_rollout
  run_family "reliability_doctor"    run_reliability_doctor
  run_family "ux_regression"         run_ux_regression
  run_family "coverage_matrix"       run_coverage_matrix
  run_family "ci_test_tiers"        run_ci_test_tiers
  run_family "slo_guardrails"       run_slo_guardrails
  run_family "docs_validation"      run_docs_validation
  run_family "release_gate_signoff" run_release_gate_signoff

  # --- Nightly families (only in nightly/full mode) ---
  case "$E2E_MODE" in
    smoke)
      log "skipping nightly-only families (set RCH_E2E_MODE=nightly for full suite)"
      ;;
    nightly|full)
      run_family "nightly_topology_deep"      run_nightly_topology_deep
      run_family "nightly_contract_schema"    run_nightly_contract_schema_deep
      run_family "nightly_benchmarks"         run_nightly_reliability_benchmarks
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
