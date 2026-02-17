#!/usr/bin/env bash
# E2E_NAME=path_dependency_fixtures
# E2E_SERIAL=1
# E2E_ARGS=--ci

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
LOG_PREFIX="[path-dep-fixtures]"

log() {
  printf '%s %s\n' "$LOG_PREFIX" "$*"
}

fail() {
  printf '%s ERROR: %s\n' "$LOG_PREFIX" "$*" >&2
  exit 1
}

require_cmd() {
  command -v "$1" >/dev/null 2>&1 || fail "missing required command: $1"
}

assert_topology() {
  [[ -d /data/projects ]] || fail "expected canonical root /data/projects to exist"
  [[ -L /dp ]] || fail "expected /dp to be a symlink"

  local resolved
  resolved="$(readlink -f /dp)"
  [[ "$resolved" == "/data/projects" ]] || fail "/dp should resolve to /data/projects (got: $resolved)"
}

run_fixture_tests() {
  log "running deterministic multi-repo fixture unit tests"
  (
    cd "$PROJECT_ROOT"
    cargo test -p rch-common multi_repo_fixture_ -- --nocapture
  )
}

run_topology_smoke_tests() {
  log "running topology smoke tests (bootstrap + preflight gating)"
  (
    cd "$PROJECT_ROOT"
    cargo test -p rch topology_bootstrap_ -- --nocapture
    cargo test -p rchd topology_preflight_ -- --nocapture
    cargo test -p rch-wkr probe_projects_topology_ -- --nocapture
  )
}

run_topology_nightly_tests() {
  log "running topology nightly tests (deep canonicalization edge coverage)"
  (
    cd "$PROJECT_ROOT"
    cargo test -p rch-common path_topology::tests:: -- --nocapture
  )
}

main() {
  require_cmd cargo
  require_cmd readlink
  local topology_test_tier="${RCH_TOPOLOGY_TEST_TIER:-smoke}"

  log "validating canonical/alias topology invariants"
  assert_topology

  run_fixture_tests
  run_topology_smoke_tests

  case "$topology_test_tier" in
    smoke)
      log "topology tier=smoke (set RCH_TOPOLOGY_TEST_TIER=nightly for deep suite)"
      ;;
    nightly|full)
      run_topology_nightly_tests
      ;;
    *)
      fail "unknown RCH_TOPOLOGY_TEST_TIER=$topology_test_tier (expected smoke|nightly|full)"
      ;;
  esac

  log "PASS: path dependency fixture generation/reset checks are healthy"
}

main "$@"
