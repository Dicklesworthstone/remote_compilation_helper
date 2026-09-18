#!/usr/bin/env bash
# bd-ceewf: verified named-tool probes — worker-side end-to-end proof.
#
# The unit tests prove the DECISIONS (which declarations are accepted, which
# workers are admissible). They cannot prove that the real `rch-wkr` binary,
# built and run on a real worker, actually executes an operator-declared argv
# and reports the outcome in its capabilities JSON. That is what this checks:
#
#   1. builds rch-wkr on the worker,
#   2. runs `rch-wkr capabilities` with NO --tool-probe and asserts the JSON is
#      unchanged in shape (the compatibility property: a worker that declares
#      no tools behaves exactly as before),
#   3. runs it with declarations that must succeed, must fail, and cannot be
#      run at all, and asserts each lands in the right list,
#   4. asserts a malformed declaration is WARNED about and never counted as a
#      verified tool (the gate must not open on a broken payload).
#
# Run it on a worker, not the dispatcher:
#   rch exec --job --result-dir ceewf-proof -- ./scripts/e2e_bd-ceewf.sh
set -euo pipefail

OUT=${1:-ceewf-proof}
mkdir -p "$OUT"
log() { printf '%s\n' "$*" >&2; }

cargo build -q -p rch-wkr --bin rch-wkr
WKR=$(cargo metadata --no-deps --format-version 1 \
  | python3 -c 'import json,sys; print(json.load(sys.stdin)["target_directory"])')/debug/rch-wkr
[ -x "$WKR" ] || { log "rch-wkr not built at $WKR"; exit 2; }
log "worker binary: $WKR"

# ---- 1. no declarations: the tool fact lists must be absent entirely -------
"$WKR" capabilities >"$OUT/caps-bare.json" 2>"$OUT/caps-bare.stderr"
python3 - "$OUT/caps-bare.json" <<'PY'
import json, sys
caps = json.load(open(sys.argv[1]))
assert "tools_present" not in caps, f"unrequested probe reported tools_present: {caps.get('tools_present')}"
assert "tools_absent" not in caps, f"unrequested probe reported tools_absent: {caps.get('tools_absent')}"
assert caps.get("rustc_version"), "capabilities JSON lost its ordinary facts"
print("bare capabilities unchanged (no tool facts, ordinary facts intact)")
PY

# ---- 2. declarations: exit status decides ---------------------------------
# `true` succeeds and prints nothing; `false` exists and exits 1; the third
# binary does not exist. None of the three could be classified by its output.
"$WKR" capabilities --tool-probe '[
  {"name":"present","command":["true"]},
  {"name":"failing","command":["false"]},
  {"name":"missing","command":["rch-no-such-binary-9f3a"]}
]' >"$OUT/caps-tools.json" 2>"$OUT/caps-tools.stderr"
python3 - "$OUT/caps-tools.json" <<'PY'
import json, sys
caps = json.load(open(sys.argv[1]))
present, absent = caps.get("tools_present", []), caps.get("tools_absent", [])
assert present == ["present"], f"tools_present={present}"
assert absent == ["failing", "missing"], f"tools_absent={absent}"
assert caps.get("rustc_version"), "tool probing must not disturb the other facts"
print(f"verified={present} failed={absent}")
PY

# ---- 3. a malformed declaration warns and verifies nothing ----------------
"$WKR" capabilities --tool-probe '[{"name":"bad name","command":["true"]}]' \
  >"$OUT/caps-bad.json" 2>"$OUT/caps-bad.stderr"
python3 - "$OUT/caps-bad.json" <<'PY'
import json, sys
caps = json.load(open(sys.argv[1]))
assert not caps.get("tools_present"), "a malformed declaration must never verify a tool"
warnings = caps.get("probe_warnings", [])
assert any("ignored tool declaration" in w for w in warnings), f"no warning in {warnings}"
print(f"malformed declaration warned: {[w for w in warnings if 'ignored' in w]}")
PY

log "PASS: rch-wkr executes declared probes and reports them by exit status"
