#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
RCH_BIN="${RCH_BIN:-$ROOT/target/debug/rch}"

usage() {
  cat <<'USAGE'
Usage: scripts/test_verbose_flag.sh

Checks that --verbose adds human diagnostics without contaminating JSON output.

Environment:
  RCH_BIN    Path to the rch binary to test. Defaults to target/debug/rch.
  TMPDIR     Base directory for test artifacts. Defaults to /tmp.
USAGE
}

if [[ "${1:-}" == "--help" || "${1:-}" == "-h" ]]; then
  usage
  exit 0
fi

if [[ $# -gt 0 ]]; then
  usage >&2
  exit 2
fi

if [[ ! -x "$RCH_BIN" ]]; then
  echo "Building rch debug binary..."
  (cd "$ROOT" && cargo build -p rch)
fi

CONFIG_HOME="${TMPDIR:-/tmp}/rch-verbose-flag-$$"
mkdir -p "$CONFIG_HOME/rch"
cat > "$CONFIG_HOME/rch/workers.toml" <<'TOML'
[[workers]]
id = "builder-1"
host = "127.0.0.1"
user = "ubuntu"
identity_file = "~/.ssh/rch_verbose_test"
total_slots = 8
priority = 100
tags = ["rust", "test"]
TOML

NORMAL_OUT="$CONFIG_HOME/workers-normal.out"
VERBOSE_OUT="$CONFIG_HOME/workers-verbose.out"
JSON_OUT="$CONFIG_HOME/workers-verbose.json"
NORMAL_ERR="$CONFIG_HOME/workers-normal.err"
VERBOSE_ERR="$CONFIG_HOME/workers-verbose.err"
JSON_ERR="$CONFIG_HOME/workers-verbose-json.err"

run_capture() {
  local stdout_file="$1"
  local stderr_file="$2"
  shift 2

  if ! XDG_CONFIG_HOME="$CONFIG_HOME" "$RCH_BIN" "$@" > "$stdout_file" 2> "$stderr_file"; then
    echo "command failed: $RCH_BIN $*" >&2
    echo "stdout: $stdout_file" >&2
    echo "stderr: $stderr_file" >&2
    return 1
  fi
}

run_capture "$NORMAL_OUT" "$NORMAL_ERR" workers list
run_capture "$VERBOSE_OUT" "$VERBOSE_ERR" --verbose workers list
run_capture "$JSON_OUT" "$JSON_ERR" --verbose --json workers list

if grep -q "SSH Key" "$NORMAL_OUT"; then
  echo "normal workers list unexpectedly showed verbose SSH key detail" >&2
  exit 1
fi

grep -q "SSH Key" "$VERBOSE_OUT"
grep -q "Live status" "$VERBOSE_OUT"
grep -q "~/.ssh/rch_verbose_test" "$VERBOSE_OUT"

python3 - "$JSON_OUT" <<'PY'
import json
import sys

with open(sys.argv[1], "r", encoding="utf-8") as f:
    data = json.load(f)

assert data["success"] is True
assert data["data"]["count"] == 1
assert data["data"]["workers"][0]["id"] == "builder-1"
PY

echo "verbose flag checks passed"
echo "artifacts: $CONFIG_HOME"
