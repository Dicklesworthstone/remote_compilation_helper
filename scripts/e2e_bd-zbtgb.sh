#!/usr/bin/env bash
# bd-zbtgb: `rch admit --job` preflight — CLI end-to-end proof.
#
# The unit tests prove the preflight DECISION. They cannot prove the CLI is
# wired to it: a `--job` flag that never reaches `as_job()`, or a
# `--require-tool` that is parsed and dropped, would leave every unit test
# green while the command answered the opposite of the truth. So this drives
# the real binary and reads its JSON envelope.
#
# It is read-only by construction — `rch admit` syncs nothing and reserves
# nothing — so it is safe to run against a live fleet.
#
#   rch exec --job --result-dir zbtgb-proof -- ./scripts/e2e_bd-zbtgb.sh
set -euo pipefail

OUT=${1:-zbtgb-proof}
mkdir -p "$OUT"
log() { printf '%s\n' "$*" >&2; }

cargo build -q -p rch --bin rch
RCH=$(cargo metadata --no-deps --format-version 1 \
  | python3 -c 'import json,sys; print(json.load(sys.stdin)["target_directory"])')/debug/rch
[ -x "$RCH" ] || { log "rch not built at $RCH"; exit 2; }
log "binary: $RCH"

run() { # label -- args...
  local label=$1; shift 2
  # `--json`, not RCH_JSON=1: the env var is documented as forcing machine
  # output but does not (bd-e92eh), and this script must test admit, not that
  # bug.
  "$RCH" admit --json "$@" >"$OUT/$label.json" 2>"$OUT/$label.stderr" || {
    log "FAIL: admit $* exited nonzero"; cat "$OUT/$label.stderr" >&2; exit 3;
  }
}

# A non-compilation workload: compilation preflight says local, job preflight
# must say offload. That difference IS the feature.
run compile-view -- -- ./run_shards.sh --shard 3
run job-view -- --job -- ./run_shards.sh --shard 3
run job-tools -- --job --require-tool clang --require-tool ld.lld -- ./run_shards.sh
run job-compile -- --job -- cargo test --workspace

python3 - "$OUT" <<'PY'
import json, sys, pathlib
out = pathlib.Path(sys.argv[1])
def data(name):
    payload = json.loads((out / f"{name}.json").read_text())
    assert payload.get("success") is True, f"{name}: {payload}"
    return payload["data"]

compile_view = data("compile-view")
assert compile_view["is_compilation"] is False, compile_view
assert compile_view["base_recommendation"] == "local", compile_view
assert not compile_view.get("job_mode"), compile_view
print(f"non-job view: recommendation={compile_view['base_recommendation']}")

job_view = data("job-view")
assert job_view["job_mode"] is True, job_view
assert job_view["base_recommendation"] == "offload", job_view
assert job_view["is_compilation"] is False, "classification facts must be kept"
print(f"job view: recommendation={job_view['base_recommendation']} (classifier bypassed)")

tools = data("job-tools")
assert tools["required"]["needs_tools"] == ["clang", "ld.lld"], tools["required"]
print(f"required tools reached the preflight: {tools['required']['needs_tools']}")

compiled = data("job-compile")
assert compiled["is_compilation"] is True and compiled["family"] == "cargo_test", compiled
assert compiled["base_recommendation"] == "offload", compiled
print("a compilation passed to --job keeps its family visible")
PY

log "PASS: rch admit --job is wired to the job-mode preflight"
