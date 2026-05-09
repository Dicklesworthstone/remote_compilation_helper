#!/usr/bin/env bash
# test_update_signature_verification.sh — verify signature-verification
# test coverage matches bd-2bwc's 4 sub-criteria.
set -euo pipefail

case "${1:-}" in
  -h|--help)
    cat <<'HELP'
test_update_signature_verification.sh — verify update-system signature-test coverage.

Usage:
  scripts/test_update_signature_verification.sh [--help]

What it checks (each assertion → one PASS/FAIL line):
  run/cargo_test                          All update::verify::tests pass.
  coverage/valid                          ≥1 test covers valid-signature acceptance.
  coverage/invalid                        ≥1 test covers invalid-signature rejection.
  coverage/missing                        ≥1 test covers missing-signature handling.
  coverage/key_rotation                   ≥1 test covers key-rotation (regex anchor).
  anchor_check/pattern_starts_with_caret  RCH_RELEASE_IDENTITY_PATTERN starts with ^.
  anchor_check/pattern_ends_with_dollar   …and ends with .*\$ (substring-attack defense).

Environment:
  RCH_E2E_LOG  Override the JSONL log path.

Output:
  - Stdout: one human line per assertion + "==== TOTAL: PASS=N FAIL=M ===="
  - JSONL log: per-assertion {ts, run_id, test, phase, event, status, detail}.

Exit codes:
  0  all assertions passed
  1  one or more assertions failed

Filed under completion-debt bead remote_compilation_helper-6uuy2 (post-hoc verification of bd-2bwc).
HELP
    exit 0 ;;
esac

LOG_FILE=${RCH_E2E_LOG:-/tmp/rch_e2e_update_sig_$(date -u +%Y%m%dT%H%M%SZ).jsonl}
RUN_ID=$(date -u +%Y%m%dT%H%M%SZ)-$$
PROJECT_ROOT=$(git rev-parse --show-toplevel)
PASS=0
FAIL=0

emit() {
    local phase="$1" event="$2" status="$3" detail="${4:-}"
    python3 -c "
import json, time
print(json.dumps({
  'ts': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),
  'run_id': '$RUN_ID',
  'test': 'e2e_update_signature_verification',
  'phase': '$phase', 'event': '$event', 'status': '$status', 'detail': '$detail',
}))" >>"$LOG_FILE"
    echo "[$(date +%H:%M:%S)] [$status] $phase: $event ${detail:+— $detail}"
}

emit setup begin INFO "log=$LOG_FILE root=$PROJECT_ROOT"

# 1. Run the targeted unit tests for signature verification
emit run begin INFO "filter=update::verify::tests"
cd "$PROJECT_ROOT"
if cargo test -p rch --bin rch update::verify::tests -- --nocapture >>"$LOG_FILE" 2>&1; then
    PASS=$((PASS + 1))
    emit run cargo_test PASS
else
    FAIL=$((FAIL + 1))
    emit run cargo_test FAIL
fi

# 2. Verify each of the 4 sub-criteria has at least one named test
declare -A TEST_PATTERNS=(
    [valid]='integration_signature_verifies_with_real_cosign|test_rch_release_identity_pattern_accepts_canonical_url'
    [invalid]='test_signature_invalid_bundle_returns_err|test_rch_release_identity_pattern_rejects_substring_attacks'
    [missing]='test_signature_missing_bundle_yields_none'
    [key_rotation]='test_rch_release_identity_pattern_is_anchored|test_rch_release_identity_pattern_rejects_substring_attacks'
)

for sub in valid invalid missing key_rotation; do
    pattern="${TEST_PATTERNS[$sub]}"
    if rg -q "$pattern" "$PROJECT_ROOT/rch/src/update/verify.rs"; then
        PASS=$((PASS + 1))
        emit coverage "$sub" PASS "matched=$pattern"
    else
        FAIL=$((FAIL + 1))
        emit coverage "$sub" FAIL "no test matching: $pattern"
    fi
done

# 3. Verify the regex security anchor is correct (substring attacks must be rejected at runtime)
emit anchor_check begin INFO "regex anchored at ^...$"
if rg -q '"\^https://github\\.com' "$PROJECT_ROOT/rch/src/update/verify.rs"; then
    PASS=$((PASS + 1))
    emit anchor_check pattern_starts_with_caret PASS
else
    FAIL=$((FAIL + 1))
    emit anchor_check pattern_starts_with_caret FAIL
fi

if rg -qF '.*$"' "$PROJECT_ROOT/rch/src/update/verify.rs"; then
    PASS=$((PASS + 1))
    emit anchor_check pattern_ends_with_dollar PASS
else
    FAIL=$((FAIL + 1))
    emit anchor_check pattern_ends_with_dollar FAIL
fi

emit summary "done" "INFO" "pass=$PASS fail=$FAIL log=$LOG_FILE"
echo "==== TOTAL: PASS=$PASS FAIL=$FAIL ===="
[ "$FAIL" -eq 0 ] || exit 1
