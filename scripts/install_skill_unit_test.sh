#!/usr/bin/env bash
# install_skill_unit_test.sh - Unit tests for install.sh skill-install safety.
#
# Regression cover for GH#45: the tarball/curl install path always fell back to
# the inline minimal stub (a stale `scripts/diagnose-rch.sh` entry 404'd and
# aborted the whole raw-tree fetch), and the stub then overwrote a full skill
# already on disk on every unattended re-run (nightly ACFS updater).
#
# These tests assert two invariants of the current code:
#   1. The raw-tree file list matches the files that actually exist in the repo
#      (no stale entries that would 404 and, historically, abort the install).
#   2. `_rch_skill_is_full` recognizes a real skill and the stub-write guard
#      refuses to downgrade it.
#
# Run from project root: ./scripts/install_skill_unit_test.sh

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
export PROJECT_ROOT
TEST_DIR=$(mktemp -d)

TESTS_RUN=0
TESTS_PASSED=0
TESTS_FAILED=0

log() { echo "[install_skill_unit] $*"; }
pass() { TESTS_PASSED=$((TESTS_PASSED + 1)); log "PASS: $1"; }
fail() { TESTS_FAILED=$((TESTS_FAILED + 1)); log "FAIL: $1"; }
start_test() { TESTS_RUN=$((TESTS_RUN + 1)); log "Test $TESTS_RUN: $1"; }
cleanup() { rm -rf "$TEST_DIR"; }
trap cleanup EXIT

log "=== RCH Installer Skill-Install Unit Tests ==="

if [[ ! -f "$PROJECT_ROOT/install.sh" ]]; then
    log "ERROR: install.sh not found at $PROJECT_ROOT/install.sh"
    exit 1
fi

export RCH_INSTALLER_LIB=1
# shellcheck disable=SC1090
source "$PROJECT_ROOT/install.sh"

# Silence advisory output during tests
warn() { :; }
info() { :; }
success() { :; }

# --- Test 1: skill_files entries all exist in the repo skill tree ------------
# install_skill declares skill_files as a local; re-declare the canonical list
# here and assert every entry resolves. A stale entry is exactly the GH#45 bug.
start_test "raw-tree companion list has no stale (404-prone) entries"
skill_tree="$PROJECT_ROOT/.claude/skills/rch"
# Keep this list identical to install_skill()'s skill_files.
companions=(
    "assets/workers-template.toml"
    "references/COMMANDS.md"
    "references/CONFIGURATION.md"
    "references/HOOKS.md"
    "references/OPERATIONS.md"
    "references/TROUBLESHOOTING.md"
    "references/WORKERS.md"
    "scripts/validate-setup.sh"
)
missing=""
for rel in "SKILL.md" "${companions[@]}"; do
    [[ -f "$skill_tree/$rel" ]] || missing="$missing $rel"
done
if [[ -z "$missing" ]]; then
    pass "all declared skill files exist in repo"
else
    fail "declared skill files missing from repo:$missing"
fi

# Guard against silent drift the other way: a companion present in the repo but
# absent from the installer list means fresh installs would ship an incomplete
# skill. (SKILL.md handled above; scripts/ and references/ and assets/ scanned.)
start_test "installer list covers every companion present in the repo"
uncovered=""
while IFS= read -r f; do
    rel="${f#"$skill_tree"/}"
    [[ "$rel" == "SKILL.md" ]] && continue
    covered=false
    for c in "${companions[@]}"; do
        [[ "$c" == "$rel" ]] && { covered=true; break; }
    done
    $covered || uncovered="$uncovered $rel"
done < <(find "$skill_tree" -type f | sort)
if [[ -z "$uncovered" ]]; then
    pass "installer list covers all repo companions"
else
    fail "repo files not in installer list:$uncovered"
fi

# --- Test 2: _rch_skill_is_full detection -----------------------------------
start_test "_rch_skill_is_full: stub-only dir is NOT full"
stub_dir="$TEST_DIR/stub"
mkdir -p "$stub_dir"
printf -- '---\nname: rch\n---\nstub\n' > "$stub_dir/SKILL.md"
if _rch_skill_is_full "$stub_dir"; then
    fail "stub-only dir wrongly classified as full"
else
    pass "stub-only dir correctly not full"
fi

start_test "_rch_skill_is_full: dir with references is full"
full_dir="$TEST_DIR/full"
mkdir -p "$full_dir/references"
printf 'full skill\n' > "$full_dir/SKILL.md"
printf 'ref\n' > "$full_dir/references/WORKERS.md"
if _rch_skill_is_full "$full_dir"; then
    pass "full dir correctly classified"
else
    fail "full dir wrongly classified as not full"
fi

start_test "_rch_skill_is_full: empty/missing dir is not full"
if _rch_skill_is_full "$TEST_DIR/does-not-exist"; then
    fail "missing dir wrongly classified as full"
else
    pass "missing dir correctly not full"
fi

# --- Test 3: stub guard preserves an existing full skill --------------------
# Exercise the exact guard logic install_skill uses for the inline stub write.
start_test "stub write does not clobber an existing full skill"
dest="$TEST_DIR/dest"
mkdir -p "$dest/references"
printf 'FULL REAL SKILL CONTENT\n' > "$dest/SKILL.md"
printf 'ref\n' > "$dest/references/WORKERS.md"
original="$(cat "$dest/SKILL.md")"
stub_content='STUB CONTENT'
if _rch_skill_is_full "$dest"; then
    :  # guard fires: do not overwrite
else
    echo "$stub_content" > "$dest/SKILL.md"
fi
if [[ "$(cat "$dest/SKILL.md")" == "$original" ]]; then
    pass "existing full skill preserved against stub downgrade"
else
    fail "full skill was downgraded to stub"
fi

start_test "stub write DOES populate an empty destination"
empty_dest="$TEST_DIR/empty_dest"
mkdir -p "$empty_dest"
if _rch_skill_is_full "$empty_dest"; then
    :
else
    echo "$stub_content" > "$empty_dest/SKILL.md"
fi
if [[ -f "$empty_dest/SKILL.md" && "$(cat "$empty_dest/SKILL.md")" == "$stub_content" ]]; then
    pass "empty destination received the stub"
else
    fail "empty destination was not populated"
fi

echo ""
log "=== Results: $TESTS_PASSED passed, $TESTS_FAILED failed, $TESTS_RUN run ==="
[[ $TESTS_FAILED -eq 0 ]]
