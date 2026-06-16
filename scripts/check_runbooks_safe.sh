#!/usr/bin/env bash
#
# check_runbooks_safe.sh — regression guard for the RCH operational runbooks
# (remote_compilation_helper bd-...15.2).
#
# Ensures the safe automated-recovery guidance stays in the runbooks, and that
# stale or nonexistent commands (manual circuit reset, per-worker clean, force
# probe, etc.) cannot creep back in as recommendations — so old destructive or
# wrong guidance cannot silently return.
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
RUNBOOKS_DIR="$PROJECT_ROOT/docs/runbooks"

# The runbooks rewritten around safe automated recovery.
SAFE_RUNBOOKS=(
    "worker-recovery.md"
    "reliability-operations.md"
    "daemon-restart.md"
    "debugging-slow-builds.md"
    "configuration-troubleshooting.md"
)

fail=0

if [[ ! -d "$RUNBOOKS_DIR" ]]; then
    echo "runbooks dir not found: $RUNBOOKS_DIR" >&2
    exit 1
fi
for rb in "${SAFE_RUNBOOKS[@]}"; do
    if [[ ! -f "$RUNBOOKS_DIR/$rb" ]]; then
        echo "expected runbook missing: $RUNBOOKS_DIR/$rb" >&2
        fail=1
    fi
done

# --- 1. Stale / nonexistent commands must not appear in ANY runbook ----------
forbid() {
    local needle="$1"
    local hits
    hits="$(grep -rIlF -- "$needle" "$RUNBOOKS_DIR" 2>/dev/null || true)"
    if [[ -n "$hits" ]]; then
        echo "FORBIDDEN stale command returned ($needle):" >&2
        echo "    ${hits//$'\n'/$'\n'    }" >&2
        fail=1
    fi
}

# Commands that do not exist in the CLI (must never be recommended).
forbid "rch worker reset"
forbid "rch worker clean"
forbid "rch worker test"
forbid "rch status --circuits"
forbid "rch self-test --quick"
forbid "rch repo-convergence"
forbid "rch daemon restart --force"
forbid "rch config check"
forbid "rch classify"
forbid "rch sync "
forbid "rch debug-bundle"
forbid "workers probe --force"
forbid "daemon logs --tail"
forbid "--max-age-hours"
forbid "--max-parallel"
# Nonexistent / wrong env vars.
forbid "RCH_DRY_RUN"
forbid "RCH_LOG="
# Destructive manual recovery as a recommended fix.
forbid "rm -f /tmp/rch.sock && rchd"
forbid "rm /tmp/rch.sock && rchd"

# Backgrounding the daemon by hand (matches "rchd &" but NOT "rchd &>/dev/null").
bg_hits="$(grep -rIlnE 'rchd[[:space:]]+&([^>]|$)' "$RUNBOOKS_DIR" 2>/dev/null || true)"
if [[ -n "$bg_hits" ]]; then
    echo "FORBIDDEN: manual 'rchd &' backgrounding (use 'rch daemon start'):" >&2
    echo "    ${bg_hits//$'\n'/$'\n'    }" >&2
    fail=1
fi

# --- 2. Safe automated-recovery model must be documented ---------------------
# require_any: the needle must appear in at least one of the safe runbooks.
require_any() {
    local needle="$1"
    local f found=0
    for f in "${SAFE_RUNBOOKS[@]}"; do
        if grep -qF -- "$needle" "$RUNBOOKS_DIR/$f" 2>/dev/null; then
            found=1
            break
        fi
    done
    if [[ "$found" -eq 0 ]]; then
        echo "MISSING from runbooks (safe-recovery guidance): $needle" >&2
        fail=1
    fi
}

require_any "rch cache clean"                          # safe, dry-run-by-default reclaim
require_any "rch cancel"                               # cancel builds instead of pkill
require_any "rch daemon restart"                       # socket-safe restart, no manual rm
require_any "rch fleet doctor --reliability --scope"   # audited triage/convergence fix
require_any "temporary bypass"                         # self-healing lifecycle
require_any "auto-rejoin"
require_any "active-build"                             # active-build-protected reclaim
require_any "for transient"                            # the do-not-disable-for-transient rule
require_any "RCH_REQUIRE_REMOTE"                       # proof-mode handoff

# --- 3. The bead's required new topics must be present -----------------------
require_in() {
    local file="$1" needle="$2"
    if ! grep -qF -- "$needle" "$RUNBOOKS_DIR/$file" 2>/dev/null; then
        echo "MISSING from $file: $needle" >&2
        fail=1
    fi
}

require_in "reliability-operations.md" "Cloud / VMI Fleet Incidents"
require_in "reliability-operations.md" "Local Fallback Hazards Under Swarm Load"
require_in "reliability-operations.md" "Proof-Mode Handoff"
require_in "worker-recovery.md" "cloud / VMI fleet incident"

if [[ "$fail" -ne 0 ]]; then
    echo "runbook safe-recovery regression check FAILED" >&2
    exit 1
fi
echo "runbook safe-recovery regression check OK ($RUNBOOKS_DIR)"
