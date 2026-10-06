#!/usr/bin/env bash
# test_update_signature_verification.sh - verify signature-verification
# test coverage matches bd-2bwc's 4 sub-criteria.
set -euo pipefail

case "${1:-}" in
  -h|--help)
    cat <<'HELP'
test_update_signature_verification.sh - verify update-system signature-test coverage.

Usage:
  scripts/test_update_signature_verification.sh [--help]

What it checks (each assertion -> one PASS/FAIL line):
  published_key/matches_updater           Published minisign key matches the updater's trust root.
  run/cargo_test                          All update::verify tests, including minisign, pass.
  run/install_authorization              Unsigned updates cannot reach installation by default.
  coverage/valid                          >=1 test covers valid-signature acceptance.
  coverage/invalid                        >=1 test covers invalid-signature rejection.
  coverage/missing                        >=1 test covers missing-signature handling.
  coverage/key_rotation                   >=1 test covers key-rotation (regex anchor).
  anchor_check/pattern_starts_with_caret  RCH_RELEASE_IDENTITY_PATTERN starts with ^.
  anchor_check/pattern_ends_with_dollar   ...and ends with .*$ (substring-attack defense).

Environment:
  RCH_E2E_LOG  Override the JSONL log path.

Output:
  - Stdout: one human line per assertion + "==== TOTAL: PASS=N FAIL=M ===="
  - JSONL log: per-assertion {ts, run_id, test, phase, event, status, detail}.
  - Test log: cargo output goes to <log>.cargo.log so the JSONL stays valid JSON.

Exit codes:
  0  all assertions passed
  1  one or more assertions failed

Filed under completion-debt bead remote_compilation_helper-6uuy2 (post-hoc verification of bd-2bwc).
HELP
    exit 0 ;;
esac

LOG_FILE=${RCH_E2E_LOG:-/tmp/rch_e2e_update_sig_$(date -u +%Y%m%dT%H%M%SZ).jsonl}
TEST_LOG=${LOG_FILE%.jsonl}.cargo.log
RUN_ID=$(date -u +%Y%m%dT%H%M%SZ)-$$
PROJECT_ROOT=$(git rev-parse --show-toplevel)
PASS=0
FAIL=0

emit() {
    local phase="$1" event="$2" status="$3" detail="${4:-}"
    EMIT_RUN_ID="$RUN_ID" EMIT_PHASE="$phase" EMIT_EVENT="$event" \
    EMIT_STATUS="$status" EMIT_DETAIL="$detail" \
    python3 -c '
import json, os, time
print(json.dumps({
  "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
  "run_id": os.environ.get("EMIT_RUN_ID", ""),
  "test": "e2e_update_signature_verification",
  "phase": os.environ.get("EMIT_PHASE", ""),
  "event": os.environ.get("EMIT_EVENT", ""),
  "status": os.environ.get("EMIT_STATUS", ""),
  "detail": os.environ.get("EMIT_DETAIL", ""),
}))' >>"$LOG_FILE"
    echo "[$(date +%H:%M:%S)] [$status] $phase: $event ${detail:+- $detail}"
}

emit setup begin INFO "log=$LOG_FILE test_log=$TEST_LOG root=$PROJECT_ROOT"

# The repository key is what external installers use; accepting it as a valid
# minisign key is insufficient if it differs from the updater's pinned signer.
# Check the exact payload and little-endian key id, not just its comment (#89).
if python3 - "$PROJECT_ROOT" <<'PY'
import base64
from pathlib import Path
import re
import sys

root = Path(sys.argv[1])

def require(condition, message):
    if not condition:
        raise SystemExit(message)

document = (root / ".github/rch-minisign.pub").read_text(encoding="utf-8").splitlines()
require(len(document) == 2, "published key must contain one comment and one key")
keys = re.findall(
    r'const\s+RELEASE_MINISIGN_PUBLIC_KEY\s*:\s*&str\s*=\s*"([A-Za-z0-9+/=]+)"\s*;',
    (root / "rch/src/update/verify.rs").read_text(encoding="utf-8"),
)
require(len(keys) == 1, "updater must pin one unambiguous release key")
published = base64.b64decode(document[1], validate=True)
pinned = base64.b64decode(keys[0], validate=True)
require(len(published) == 42 and published[:2] == b"Ed", "invalid minisign public key")
require(published == pinned, "published minisign key differs from updater trust root")
key_id = int.from_bytes(published[2:10], "little")
require(document[0] == f"untrusted comment: minisign public key {key_id:016X}", "published key id mismatch")
print(f"Published release key matches updater: {key_id:016X}")
PY
then
    PASS=$((PASS + 1))
    emit published_key matches_updater PASS
else
    FAIL=$((FAIL + 1))
    emit published_key matches_updater FAIL
fi

# 1. Run both signature implementations. The old ::tests filter silently
# excluded ::minisign_tests, which covers the actual release archive verifier.
emit run begin INFO "filter=update::verify::"
cd "$PROJECT_ROOT"
if cargo test -p rch --bin rch update::verify:: -- --nocapture >>"$TEST_LOG" 2>&1; then
    PASS=$((PASS + 1))
    emit run cargo_test PASS
else
    FAIL=$((FAIL + 1))
    emit run cargo_test FAIL
fi

# Missing signature metadata must not bypass a verifier by preventing it from
# running. Exercise the installation decision as well as cryptographic checks.
emit run begin INFO "filter=update::tests::update_verification_"
if cargo test -p rch --bin rch update::tests::update_verification_ -- --nocapture >>"$TEST_LOG" 2>&1; then
    PASS=$((PASS + 1))
    emit run install_authorization PASS
else
    FAIL=$((FAIL + 1))
    emit run install_authorization FAIL
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
