#!/usr/bin/env bash
#
# check_postmortem_runbook.sh — regression guard for the RCH postmortem query
# pack runbook (remote_compilation_helper bd-...15.3).
#
# Fails if docs/runbooks/rch-postmortem-query-pack.md drops any required query
# term, the CASS source-state commands, or any raw-history fallback root — so
# old/incomplete guidance cannot silently return.
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
DOC="$PROJECT_ROOT/docs/runbooks/rch-postmortem-query-pack.md"

fail=0
require() {
    local needle="$1"
    if ! grep -qF -- "$needle" "$DOC"; then
        echo "MISSING from postmortem runbook: $needle" >&2
        fail=1
    fi
}

if [[ ! -f "$DOC" ]]; then
    echo "postmortem runbook not found: $DOC" >&2
    exit 1
fi

# The ten canonical query terms.
for term in \
    "local fallback" \
    "no admissible workers" \
    "RCH_REQUIRE_REMOTE" \
    "disk pressure" \
    "target dirs" \
    "Exec format error" \
    "rsync failed" \
    "wasm target" \
    "daemon logs" \
    "fleet update"; do
    require "$term"
done

# CASS source-state checks must be present.
require "cass sources list --json"
require "cass health --json"

# Bounded search (timeout) discipline must be present.
require "timeout 20s cass search"

# Raw-history fallback roots.
require ".claude/projects"
require ".codex/sessions"
require ".gemini/tmp"

# Where the structured records live (so the runbook keeps pointing at evidence).
require "incidents.jsonl"

if [[ "$fail" -ne 0 ]]; then
    echo "postmortem runbook regression check FAILED" >&2
    exit 1
fi
echo "postmortem runbook regression check OK ($DOC)"
