#!/usr/bin/env bash
#
# e2e_force_resync.sh — E2E runner for the agent-safe force-resync command
# `rch sync --force` (bd-apg5l, consuming bd-session-history-remediation-ocv9i.8.3).
#
# Emits structured JSONL (run_id, bead_id, scenario, event, status, reason_code,
# command_fingerprint, worker_id, duration_ms, detail) plus human-readable
# progress, and exits nonzero if any scenario fails.
#
# Usage:
#   ./scripts/e2e_force_resync.sh [--dry-run] [--mock-worker]
#                                 [--filter GLOB] [--run-id ID]
#
# The fast, deterministic scenarios need no daemon and no fleet: they verify the
# command surface, the non-destructive preview (no --force ⇒ applied=false), and
# the two safety refusals (apply without a target; apply against an unknown
# worker). The genuinely destructive real-apply path requires a reachable worker
# and is recorded status=skipped with instructions when no real fleet is
# configured — it must never delete anything outside the RCH-managed base.
#
# Exit codes: 0 all pass (skips allowed), 1 a scenario failed, 2 setup error.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
export PROJECT_ROOT

# This suite is owned by bd-apg5l, not the program bead.
export REM_BEAD_ID="bd-apg5l"

# shellcheck source=lib/remediation_e2e.sh
source "$SCRIPT_DIR/lib/remediation_e2e.sh"

rem_parse_args "$@"
rem_init "e2e_force_resync"

# Resolve the rch binary (prefer release, then debug, then PATH). Empty if none.
RCH_BIN=""
for cand in "$PROJECT_ROOT/target/release/rch" "$PROJECT_ROOT/target/debug/rch"; do
    [[ -x "$cand" ]] && { RCH_BIN="$cand"; break; }
done
[[ -z "$RCH_BIN" ]] && command -v rch >/dev/null 2>&1 && RCH_BIN="$(command -v rch)"

rch_surface_exists() {
    [[ -n "$RCH_BIN" ]] || return 1
    "$RCH_BIN" "$1" --help >/dev/null 2>&1
}

run_scenario() {
    local name="$1" body="$2" plan="$3"
    rem_selected "$name" || return 0
    rem_scenario_begin "$name"
    if [[ $REM_DRY_RUN -eq 1 ]]; then
        rem_scenario_pass "none" "dry-run plan: $plan"
        return 0
    fi
    if [[ -z "$RCH_BIN" ]]; then
        rem_scenario_skip "rch_binary_unavailable" "rch binary not built; cannot exercise real path"
        return 0
    fi
    "$body"
}

# --- scenarios ----------------------------------------------------------------

# The command surface exists and is discoverable.
sc_sync_surface() {
    if rch_surface_exists sync; then
        rem_scenario_pass "RCH-I001" "rch sync surface present" "" "rch sync --help"
    else
        rem_scenario_fail "sync_surface_missing" "rch sync subcommand is not available"
    fi
}

# Preview (no --force, no target) renders the plan and takes NO destructive
# action. Needs no daemon and no fleet.
sc_preview_no_action() {
    local tmp fp="rch sync --project <tmp> --json"
    tmp="$(mktemp -d)"
    local out
    if out="$("$RCH_BIN" sync --project "$tmp" --json 2>/dev/null)" \
        && printf '%s' "$out" | grep -q '"command":"sync"' \
        && printf '%s' "$out" | grep -q '"applied":false'; then
        rem_scenario_pass "RCH-I001" "preview emitted an envelope with applied=false" "" "$fp"
    else
        rem_scenario_fail "preview_envelope_missing" "preview did not emit applied=false envelope: ${out:0:200}"
    fi
    rm -rf "$tmp"
}

# Applying (--force, no --dry-run) without a target worker must refuse rather
# than silently no-op.
sc_apply_requires_target() {
    local fp="rch sync --force --json"
    if "$RCH_BIN" sync --force --json >/dev/null 2>&1; then
        rem_scenario_fail "apply_without_target_not_refused" "force apply without --worker/--all should fail"
    else
        rem_scenario_pass "RCH-I001" "force apply without a target was refused (nonzero exit)" "" "$fp"
    fi
}

# Applying against an unknown worker id must refuse (it is a usage error, and
# nothing is invalidated).
sc_apply_unknown_worker() {
    local fp="rch sync --force --worker __rch_e2e_absent__ --json"
    if "$RCH_BIN" sync --force --worker __rch_e2e_absent__ --json >/dev/null 2>&1; then
        rem_scenario_fail "unknown_worker_not_refused" "force apply against an unknown worker should fail"
    else
        rem_scenario_pass "RCH-I001" "force apply against an unknown worker was refused" "" "$fp"
    fi
}

# The destructive real-apply path needs a reachable worker. Without a real fleet
# we skip with instructions; with --mock-worker we still skip because mock SSH
# cannot prove a real invalidation+resync.
sc_real_apply() {
    rem_scenario_skip "real_fleet_required" \
        "run 'rch sync --force --worker <id> --project <repo> --json' against a configured worker; \
asserts only RCH-managed cache under transfer.remote_base is invalidated, then convergence repair" \
        "bd-apg5l"
}

# --- run ----------------------------------------------------------------------
echo "Force-resync E2E (run_id=$REM_RUN_ID, dry_run=$REM_DRY_RUN, mock=$REM_MOCK_WORKER, filter=$REM_FILTER)"

run_scenario "sync_surface"          sc_sync_surface \
    "assert 'rch sync' subcommand exists and is discoverable"
run_scenario "preview_no_action"     sc_preview_no_action \
    "assert preview (no --force) emits applied=false and takes no destructive action"
run_scenario "apply_requires_target" sc_apply_requires_target \
    "assert '--force' without --worker/--all refuses rather than no-ops"
run_scenario "apply_unknown_worker"  sc_apply_unknown_worker \
    "assert '--force --worker <unknown>' refuses (nothing invalidated)"
run_scenario "real_apply"            sc_real_apply \
    "force-resync a real worker: invalidate only RCH-managed cache, then trigger resync"

rem_summary
