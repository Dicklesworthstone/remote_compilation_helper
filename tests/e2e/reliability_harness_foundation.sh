#!/usr/bin/env bash
# E2E_NAME=reliability_harness_foundation
# E2E_SERIAL=1
# E2E_ARGS=--ci

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
LOG_PREFIX="[reliability-harness]"

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

run_foundation_tests() {
  log "running reliability harness foundation contract tests"
  (
    cd "$PROJECT_ROOT"
    cargo test -p rch-common reliability_harness_ -- --nocapture
  )
}

main() {
  require_cmd cargo
  run_foundation_tests
  log "PASS: reliability harness foundation tests succeeded"
}

main "$@"
