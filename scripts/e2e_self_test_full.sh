#!/usr/bin/env bash
# E2E: run the 5 self-test E2E scenarios and emit JSONL per-scenario results.
# Skips remote-worker scenarios when RCH_E2E_WORKER_HOST is unset (CI-friendly).
set -euo pipefail

LOG_FILE=${RCH_E2E_LOG:-/tmp/rch_e2e_self_test_full_$(date -u +%Y%m%dT%H%M%SZ).jsonl}
RUN_ID=$(date -u +%Y%m%dT%H%M%SZ)-$$
PROJECT_ROOT=$(git rev-parse --show-toplevel)
PASS=0
FAIL=0
SKIPPED=0

emit() {
    local phase="$1" event="$2" status="$3" detail="${4:-}"
    python3 -c "
import json, time
print(json.dumps({
  'ts': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),
  'run_id': '$RUN_ID',
  'test': 'e2e_self_test_full',
  'phase': '$phase', 'event': '$event', 'status': '$status', 'detail': '$detail',
}))" >>"$LOG_FILE"
    echo "[$(date +%H:%M:%S)] [$status] $phase: $event ${detail:+— $detail}"
}

emit setup begin INFO "log=$LOG_FILE"

if [ -z "${RCH_E2E_WORKER_HOST:-}" ]; then
    emit setup no_worker_env INFO "RCH_E2E_WORKER_HOST not set; remote scenarios will skip themselves"
fi

# Run each named scenario individually so per-test JSONL telemetry is captured.
SCENARIOS=(
    test_binary_hash_computation_e2e
    test_code_change_produces_different_hash
    test_remote_compilation_verification_e2e
    test_verify_compilation_on_worker_e2e
    test_complete_self_test_workflow_e2e
)

for scenario in "${SCENARIOS[@]}"; do
    emit "$scenario" begin INFO
    START_NS=$(date +%s%N)
    if (cd "$PROJECT_ROOT" && cargo test -p rchd --test e2e_self_test "$scenario" -- --exact --nocapture) >>"$LOG_FILE" 2>&1; then
        PASS=$((PASS + 1))
        # Detect SKIP from log (if test logged "SKIP: ...")
        if grep -q "SKIP:.*$scenario\|SKIP: RCH_E2E_WORKER_HOST" "$LOG_FILE" 2>/dev/null; then
            SKIPPED=$((SKIPPED + 1))
            emit "$scenario" finished SKIP "no real worker configured"
        else
            emit "$scenario" finished PASS
        fi
    else
        FAIL=$((FAIL + 1))
        emit "$scenario" finished FAIL
    fi
    END_NS=$(date +%s%N)
    DUR_MS=$(((END_NS - START_NS) / 1000000))
    emit "$scenario" duration INFO "ms=$DUR_MS"
done

emit summary done "INFO" "pass=$PASS fail=$FAIL skipped_subset=$SKIPPED"
echo "==== TOTAL: PASS=$PASS FAIL=$FAIL (subset SKIPPED for missing real worker: $SKIPPED) ===="
[ "$FAIL" -eq 0 ] || exit 1
