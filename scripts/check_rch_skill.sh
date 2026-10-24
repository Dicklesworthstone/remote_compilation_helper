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
# Byte semantics: under a UTF-8 locale grep -I treats a file with one invalid byte
# as binary and skips it, so a forbidden line in such a file would go unseen. The
# inherited locale is kept for the one regex check that needs Unicode spaces.
ORIG_LC_ALL="${LC_ALL-}"
export LC_ALL=C

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
#
# One exemption, fail-closed: the two pinned "Things That Do NOT Exist" blocks
# below name forbidden spellings only to say they do NOT exist, so agents stop
# inventing them. Each block must occur verbatim (heading and lead-in included)
# exactly once in its file, and a hit is allowed only on a line inside that
# occurrence. Renaming the heading, rewording the lead-in, editing the list, or
# copying a listed line anywhere else fails until the block here is updated.
PINNED_FILES=(
    "rch/references/COMMANDS.md"
    "rch/references/CONFIGURATION.md"
)
# Plain single-quoted strings (neither block contains a single quote), printed by
# the printf builtin. No heredoc: bash 5.3.9 was seen to hang on a heredoc whose
# stdout is a regular file. The backticks are literal Markdown, not expansions.
# shellcheck disable=SC2016
PINNED_BLOCK_0='## Things That Do NOT Exist

`rch workers add|remove` (use `workers init`, `workers discover --add`, or
`config edit --workers`) · `rch config check` · `rch hook install --force` ·
`rch fleet enable` · `rch status --stats` · `rch bypass`, `rch reconcile`,
`rch inventory`, `rch toolchain`, `rch wrapper` at top level · env vars
`RCH_DISABLED`, `RCH_BYPASS`, `RCH_FORCE_LOCAL`, `RCH_LOG`,
`RCH_DRY_RUN`, `RCH_NO_COLOR` (`RCH_DAEMON_SOCKET` is missing on 1.0.58 but is
an alias of `RCH_SOCKET_PATH` on 2.0.0) · config file `daemon.toml` **does** exist
(`rchd` reads `~/.config/rch/daemon.toml`) but `.rch.toml` does not (project
override is `.rch/config.toml`).'
# shellcheck disable=SC2016
PINNED_BLOCK_1='### Things That Do NOT Exist

These env vars are not read (never set them expecting an effect): `RCH_DISABLED`, `RCH_BYPASS`,
`RCH_FORCE_LOCAL`, `RCH_DAEMON_SOCKET`, `RCH_LOG`, `RCH_DRY_RUN`, `RCH_NO_COLOR`.'
pinned_block() {  # pinned_block <index>: the block's exact lines
    case "$1" in
        0) printf '%s\n' "$PINNED_BLOCK_0" ;;
        1) printf '%s\n' "$PINNED_BLOCK_1" ;;
    esac
}
block_range() {  # block_range <target file>, block on stdin: "first last" of its single verbatim occurrence
    awk 'NR == FNR { b[++n] = $0; next }
         { line[FNR] = $0; m = FNR }
         END {
             c = 0
             for (s = 1; s + n - 1 <= m; s++) {
                 ok = 1
                 for (k = 1; k <= n; k++) if (line[s + k - 1] != b[k]) { ok = 0; break }
                 if (ok) { c++; first = s }
             }
             if (c == 1) print first, first + n - 1
         }' - "$1"
}
PINNED_RANGES=()   # "<path> <first> <last>" for each block found exactly once
for i in 0 1; do
    if [[ -f "$SKILLS_DIR/${PINNED_FILES[$i]}" ]]; then
        r="$(pinned_block "$i" | block_range "$SKILLS_DIR/${PINNED_FILES[$i]}")"
        [[ -n "$r" ]] && PINNED_RANGES+=("${PINNED_FILES[$i]} $r")
    fi
done
forbid() {
    local needle="$1"
    local hits="" hit rel path lineno allowed pr pf pfirst plast out IFS=$'\n'
    out="$(grep -rInF -- "$needle" "$SKILLS_DIR" 2>/dev/null || true)"
    set -f                                            # hit text is data: no globbing while split on newlines
    for hit in $out; do                               # grep -n output: <file>:<line no>:<text>
        rel="${hit#"$SKILLS_DIR"/}"
        path="${rel%%:*}"
        lineno="${rel#*:}"; lineno="${lineno%%:*}"
        allowed=false
        for pr in ${PINNED_RANGES[@]+"${PINNED_RANGES[@]}"}; do
            pf="${pr%% *}"; pfirst="${pr#* }"; plast="${pfirst#* }"; pfirst="${pfirst%% *}"
            if [[ "$pf" == "$path" ]] && (( lineno >= pfirst && lineno <= plast )); then
                allowed=true; break
            fi
        done
        $allowed || hits+="${hits:+$'\n'}$path:${rel#*:}"
    done
    set +f
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

# Backgrounding the daemon by hand (matches "rchd &" but NOT "rchd &>/dev/null",
# and NOT "rchd && ...", which chains commands rather than backgrounding). Run
# under C (sees files with invalid bytes) AND the inherited locale (where
# [[:space:]] also matches no-break/em spaces), and report the union.
bg_pat='rchd[[:space:]]+&([^>&]|$)'
bg_hits="$( { grep -rIlnE "$bg_pat" "$SKILLS_DIR" 2>/dev/null || true
              ( if [[ -n "$ORIG_LC_ALL" ]]; then export LC_ALL="$ORIG_LC_ALL"; else unset LC_ALL; fi
                grep -rIlnE "$bg_pat" "$SKILLS_DIR" 2>/dev/null || true ); } | sort -u )"
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
