#!/usr/bin/env bash
# E2E_NAME=repo_updater_contract
# E2E_SERIAL=1
# E2E_ARGS=--ci

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
LOG_PREFIX="[repo-updater-contract]"
RU_BIN="${RU_BIN:-/data/projects/repo_updater/ru}"

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

run_contract_unit_tests() {
  log "running rch-common repo_updater contract unit tests"
  (
    cd "$PROJECT_ROOT"
    cargo test -p rch-common repo_updater_contract_ -- --nocapture
  )
}

run_ru_schema_probe() {
  if [[ ! -x "$RU_BIN" ]]; then
    log "skipping live ru schema probe: executable not found at $RU_BIN"
    return 0
  fi
  require_cmd jq
  log "probing ru robot-docs schema envelope at $RU_BIN"
  local probe_json
  probe_json="$("$RU_BIN" robot-docs schemas --json 2>/dev/null)"
  [[ -n "$probe_json" ]] || fail "ru schema probe returned empty output"
  echo "$probe_json" | jq -e '.data.content.envelope.required | index("data")' >/dev/null \
    || fail "ru schema envelope missing required data field"
  echo "$probe_json" | jq -e '.data.content.commands.sync.data_schema.properties.summary' >/dev/null \
    || fail "ru sync schema missing summary definition"
  log "ru schema probe checks passed"
}

main() {
  require_cmd cargo
  run_contract_unit_tests
  run_ru_schema_probe
  log "PASS: repo_updater adapter contract checks succeeded"
}

main "$@"
