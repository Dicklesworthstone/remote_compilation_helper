#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
RCH_BIN="${RCH_BIN:-$ROOT/target/debug/rch}"

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

XDG_CONFIG_HOME="$CONFIG_HOME" "$RCH_BIN" workers list > "$NORMAL_OUT"
XDG_CONFIG_HOME="$CONFIG_HOME" "$RCH_BIN" --verbose workers list > "$VERBOSE_OUT"
XDG_CONFIG_HOME="$CONFIG_HOME" "$RCH_BIN" --verbose --json workers list > "$JSON_OUT"

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
