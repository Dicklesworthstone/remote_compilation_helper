#!/usr/bin/env bash
# E2E_NAME=reliability_logging_contract
# E2E_SERIAL=1
# E2E_ARGS=--ci

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
LOG_PREFIX="[reliability-logging]"

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

run_contract_tests() {
  log "running reliability schema + artifact contract tests"
  (
    cd "$PROJECT_ROOT"
    cargo test -p rch-common reliability -- --nocapture
  )
}

main() {
  require_cmd cargo
  run_contract_tests
  log "PASS: reliability logging contract tests succeeded"
}

main "$@"
