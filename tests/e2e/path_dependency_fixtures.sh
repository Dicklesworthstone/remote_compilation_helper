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

run_bootstrap_topology_tests() {
  log "running worker bootstrap topology enforcement tests"
  (
    cd "$PROJECT_ROOT"
    cargo test -p rch topology_bootstrap_ -- --nocapture
  )
}

main() {
  require_cmd cargo
  require_cmd readlink

  log "validating canonical/alias topology invariants"
  assert_topology

  run_fixture_tests
  run_bootstrap_topology_tests

  log "PASS: path dependency fixture generation/reset checks are healthy"
}

main "$@"
