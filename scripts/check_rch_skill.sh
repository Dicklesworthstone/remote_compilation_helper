#!/usr/bin/env bash
#
# check_rch_skill.sh — regression guard for the canonical RCH skill
# (remote_compilation_helper bd-...15.1).
#
# Two jobs:
#   1. Assert the canonical skill (.claude/skills/rch/SKILL.md) still TEACHES the
#      safe operating model: temporary bypass / canary auto-rejoin, desired-state
#      reconciliation, the admission explainer, proof mode + the interim
#      proof-lane pattern, and where the structured evidence lives.
#   2. Assert the FORBIDDEN, destructive, or simply-wrong guidance never returns
#      to EITHER bundled skill (rch + remote-compilation-helper-setup): editing
#      workers.toml for transient illness, hand-deleting the socket, killing
#      "stale" processes, and stale/nonexistent command/env spellings.
#
# So old guidance cannot silently creep back via a future edit.
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
SKILLS_DIR="$PROJECT_ROOT/.claude/skills"
SKILL="$SKILLS_DIR/rch/SKILL.md"

fail=0

if [[ ! -f "$SKILL" ]]; then
    echo "canonical rch skill not found: $SKILL" >&2
    exit 1
fi

# --- 1. Required new-operating-model content (canonical SKILL.md) -------------
require() {
    local needle="$1"
    if ! grep -qF -- "$needle" "$SKILL"; then
        echo "MISSING from canonical rch skill: $needle" >&2
        fail=1
    fi
}

# Self-healing worker lifecycle.
require "temporary bypass"
require "canary"
require "auto-rejoin"
# The explicit rule the bead demands: do not fight transient illness by hand.
require "transient illness"
require "workers.toml"
# Desired-state reconciliation + admission explainer + remediation view.
require "rch status --fleet"
require "rch admit"
require "rch status --remediation"
require "RCH-I001"
# Proof mode + the exact interim proof-lane pattern.
require "RCH_REQUIRE_REMOTE"
require "RCH_REQUIRE_REMOTE=1 RCH_NO_SELF_HEALING=1 rch --no-self-healing exec --"
# Safe recovery primitives.
require "rch doctor --fix"
require "rch daemon restart"
# Where the structured evidence lives.
require "incidents.jsonl"
require "proofs.jsonl"
require "target/test-logs"
# Names the validation commands (validation-polish requirement).
require "cargo test -p rch-common"

# --- 2. Forbidden / stale guidance must be absent from BOTH skill trees -------
# Precise literal needles so legitimate anti-pattern ("Don't") cells and shell
# redirects (rchd &>/dev/null) are not flagged.
forbid() {
    local needle="$1"
    local hits
    hits="$(grep -rIlF -- "$needle" "$SKILLS_DIR" 2>/dev/null || true)"
    if [[ -n "$hits" ]]; then
        echo "FORBIDDEN guidance returned ($needle):" >&2
        echo "    ${hits//$'\n'/$'\n'    }" >&2
        fail=1
    fi
}

# Destructive manual recovery that races self-healing.
forbid "rm -f /tmp/rch.sock && rchd"
forbid "rm /tmp/rch.sock && rchd"
forbid "kill stale process"
# The anti-pattern the bead explicitly forbids: editing workers.toml for illness.
forbid "vim ~/.config/rch/workers.toml"
# Stale / nonexistent command + env spellings.
forbid "rch config check"
forbid "rch classify"
forbid "RCH_DRY_RUN"
forbid "RCH_LOG="
forbid "| rch hook"
forbid ".rch.toml"

# Backgrounding the daemon by hand (matches "rchd &" but NOT "rchd &>/dev/null").
bg_hits="$(grep -rIlnE 'rchd[[:space:]]+&([^>]|$)' "$SKILLS_DIR" 2>/dev/null || true)"
if [[ -n "$bg_hits" ]]; then
    echo "FORBIDDEN guidance returned (manual 'rchd &' backgrounding; use 'rch daemon start'):" >&2
    echo "    ${bg_hits//$'\n'/$'\n'    }" >&2
    fail=1
fi

if [[ "$fail" -ne 0 ]]; then
    echo "rch skill regression check FAILED" >&2
    exit 1
fi
echo "rch skill regression check OK ($SKILL + sibling setup skill)"
