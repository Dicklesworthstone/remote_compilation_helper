#!/usr/bin/env bash
# E2E: verify bun install pre-execution hook caches correctly across runs.
#
# Each scenario is recorded as a JSONL line in $RCH_E2E_LOG with fields
# {ts, run_id, test, phase, event, status, detail}.
#
# Skips gracefully if `bun` is not installed.
set -euo pipefail

LOG_FILE=${RCH_E2E_LOG:-/tmp/rch_e2e_bun_prepare_$(date -u +%Y%m%dT%H%M%SZ).jsonl}
BUILD_LOG=${LOG_FILE%.jsonl}.build.log
RUN_ID=$(date -u +%Y%m%dT%H%M%SZ)-$$
PROJECT_ROOT=$(git rev-parse --show-toplevel)
RCHWKR=${RCHWKR_BIN:-${PROJECT_ROOT}/target/release/rch-wkr}
TMP=$(mktemp -d /tmp/rch_e2e_bun_XXXXXX)
# Quote $TMP at trap-set time only (single-quoted body ensures it's not
# re-expanded — it's already pinned to the safe mktemp path).
trap 'rm -rf "$TMP"' EXIT
PASS=0
FAIL=0

# Emit a JSONL event. Vars are passed via env to python so a `'` or
# newline in $detail can't corrupt the python source (no string interpolation).
emit() {
    local phase="$1" event="$2" status="$3" detail="${4:-}"
    EMIT_RUN_ID="$RUN_ID" EMIT_PHASE="$phase" EMIT_EVENT="$event" \
    EMIT_STATUS="$status" EMIT_DETAIL="$detail" \
    python3 -c '
import json, os, time
print(json.dumps({
  "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
  "run_id": os.environ.get("EMIT_RUN_ID", ""),
  "test": "e2e_bun_prepare",
  "phase": os.environ.get("EMIT_PHASE", ""),
  "event": os.environ.get("EMIT_EVENT", ""),
  "status": os.environ.get("EMIT_STATUS", ""),
  "detail": os.environ.get("EMIT_DETAIL", ""),
}))' >>"$LOG_FILE"
    echo "[$(date +%H:%M:%S)] [$status] $phase: $event ${detail:+— $detail}"
}

emit setup begin INFO "log=$LOG_FILE build_log=$BUILD_LOG tmp=$TMP rch_wkr=$RCHWKR"

# Build rch-wkr release if missing. Build output goes to a SEPARATE log
# file — we MUST NOT pollute the JSONL with cargo's free-form output, or
# any `jq -c` consumer would crash.
if [ ! -x "$RCHWKR" ]; then
    emit setup build_rch_wkr INFO
    (cd "$PROJECT_ROOT" && cargo build --release -p rch-wkr) >>"$BUILD_LOG" 2>&1
fi
[ -x "$RCHWKR" ] || { emit setup build_rch_wkr FAIL "$RCHWKR missing"; exit 2; }

# ---------- Scenario 0: rust runtime is no-op (no bun install) ----------
emit s0 begin INFO "rust_no_op"
mkdir -p "$TMP/rust_proj/src"
echo '[package]
name="x"
version="0.1.0"
edition="2021"' >"$TMP/rust_proj/Cargo.toml"
echo 'fn main(){}' >"$TMP/rust_proj/src/main.rs"
"$RCHWKR" prepare --project "$TMP/rust_proj" --runtime rust >"$TMP/rust_prep.json" 2>>"$BUILD_LOG"
ACTION_RUST=$(jq -r '.action' "$TMP/rust_prep.json" 2>/dev/null || echo "MISSING")
if [ "$ACTION_RUST" = "Skipped" ]; then
    PASS=$((PASS + 1))
    emit s0 rust_noop PASS
else
    FAIL=$((FAIL + 1))
    emit s0 rust_noop FAIL "action=$ACTION_RUST"
fi

# ---------- Scenario 5: bad manifest reports Failed (no bun needed) ----------
# This scenario validates the failure path even when bun isn't installed —
# we use an empty/corrupt package.json. compute_fingerprint succeeds (it just
# hashes the bytes) but the actual install attempt fails (or bun is absent
# and the spawn fails). Either is acceptable — we just need a failure mode
# that doesn't panic.
emit s5 begin INFO "bad_manifest_handled"
mkdir -p "$TMP/bad_proj"
echo '{ "broken json' >"$TMP/bad_proj/package.json"
"$RCHWKR" prepare --project "$TMP/bad_proj" --runtime bun >"$TMP/bad_prep.json" 2>>"$BUILD_LOG" || true
ACTION_BAD=$(jq -r '.action' "$TMP/bad_prep.json" 2>/dev/null || echo "EXIT_NONZERO")
# Allow Failed (when bun present + parse error) OR EXIT_NONZERO (when bun absent + spawn error)
if [ "$ACTION_BAD" = "Failed" ] || [ "$ACTION_BAD" = "EXIT_NONZERO" ]; then
    PASS=$((PASS + 1))
    emit s5 failure_handled PASS "result=$ACTION_BAD"
else
    FAIL=$((FAIL + 1))
    emit s5 failure_handled FAIL "expected Failed or EXIT_NONZERO got=$ACTION_BAD"
fi

# Skip the bun-specific tests if bun is not installed.
if ! command -v bun >/dev/null 2>&1; then
    emit setup bun_missing SKIP "bun not in PATH; skipping bun-install scenarios"
    emit summary done "INFO" "pass=$PASS fail=$FAIL (bun-specific scenarios skipped)"
    echo "==== TOTAL: PASS=$PASS FAIL=$FAIL (bun-specific scenarios skipped) ===="
    [ "$FAIL" -eq 0 ] || exit 1
    exit 0
fi

# ---------- Scenarios 1-4: bun-installed environments only ----------
PROJ="$TMP/bun_proj"
mkdir -p "$PROJ"
cat >"$PROJ/package.json" <<'JSON'
{
  "name": "rch_e2e_bun",
  "version": "0.0.1",
  "type": "module",
  "scripts": { "test": "bun test" },
  "dependencies": { "lodash": "4.17.21" }
}
JSON

# ---------- Scenario 1: First prepare must Install ----------
emit s1 begin INFO "first_install"
"$RCHWKR" prepare --project "$PROJ" --runtime bun >"$TMP/prep1.json" 2>>"$BUILD_LOG"
ACTION1=$(jq -r '.action' "$TMP/prep1.json")
TOOK1=$(jq -r '.took_ms' "$TMP/prep1.json")
if [ "$ACTION1" = "Installed" ] && [ -d "$PROJ/node_modules" ]; then
    PASS=$((PASS + 1))
    emit s1 install_succeeded PASS "took_ms=$TOOK1"
else
    FAIL=$((FAIL + 1))
    emit s1 install_succeeded FAIL "action=$ACTION1"
fi

# ---------- Scenario 2: Second prepare with no changes hits cache ----------
# We assert ACTION2==Skipped and that the cache-hit path didn't actually
# reinstall (took_ms is below an absolute install-cost threshold). We do
# NOT compare TOOK2 < TOOK1 — both can legitimately be 0ms when bun has a
# warm system cache, leading to false failures on `0 -lt 0`.
emit s2 begin INFO "cache_hit"
"$RCHWKR" prepare --project "$PROJ" --runtime bun >"$TMP/prep2.json" 2>>"$BUILD_LOG"
ACTION2=$(jq -r '.action' "$TMP/prep2.json")
TOOK2=$(jq -r '.took_ms' "$TMP/prep2.json")
# A real cache-hit completes in well under a second on any sane hardware
# even if the OS is loaded; an actual install of the lodash dep takes >5ms
# even on a warm cache. 200ms gives lots of headroom while still catching
# regressions where the cache check fired but the install also ran.
if [ "$ACTION2" = "Skipped" ] && [ "$TOOK2" -lt 200 ]; then
    PASS=$((PASS + 1))
    emit s2 cache_hit PASS "took_ms=$TOOK2 (first=$TOOK1, threshold=200)"
else
    FAIL=$((FAIL + 1))
    emit s2 cache_hit FAIL "action=$ACTION2 took=$TOOK2 first=$TOOK1 threshold=200"
fi

# ---------- Scenario 3: Modify package.json triggers reinstall ----------
# Change a field that doesn't affect dependency resolution (description),
# so the lockfile stays consistent. Fingerprint should still change.
emit s3 begin INFO "manifest_change"
# Pass $PROJ via env (not string interpolation) so a path with a `'` or
# `"` can't corrupt the python source.
PROJ_PATH="$PROJ" python3 -c '
import json, os
p = os.path.join(os.environ["PROJ_PATH"], "package.json")
with open(p) as f: d = json.load(f)
d["description"] = "Updated via e2e test"
with open(p, "w") as f: json.dump(d, f, indent=2)
'
"$RCHWKR" prepare --project "$PROJ" --runtime bun >"$TMP/prep3.json" 2>>"$BUILD_LOG"
ACTION3=$(jq -r '.action' "$TMP/prep3.json")
PREV_HASH=$(jq -r '.fingerprint_changed_from' "$TMP/prep3.json")
if [ "$ACTION3" = "Installed" ] && [ -n "$PREV_HASH" ] && [ "$PREV_HASH" != "null" ]; then
    PASS=$((PASS + 1))
    emit s3 reinstall_on_change PASS "prev_hash=${PREV_HASH:0:8}"
else
    FAIL=$((FAIL + 1))
    emit s3 reinstall_on_change FAIL "action=$ACTION3 prev=$PREV_HASH"
fi

# ---------- Scenario 4: Fingerprint file persists ----------
emit s4 begin INFO "fingerprint_persisted"
if [ -f "$PROJ/.rch_dep_fingerprint.json" ]; then
    PASS=$((PASS + 1))
    emit s4 fingerprint_file PASS
else
    FAIL=$((FAIL + 1))
    emit s4 fingerprint_file FAIL
fi

emit summary done "INFO" "pass=$PASS fail=$FAIL"
echo "==== TOTAL: PASS=$PASS FAIL=$FAIL ===="
[ "$FAIL" -eq 0 ] || exit 1
