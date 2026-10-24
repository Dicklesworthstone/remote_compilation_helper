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
#   3. GH#93: the real `install_skill` leaves both skill trees untouched, and
#      downloads nothing, under RCH_SKIP_SKILL=1 / --skip-skill or when jsm
#      manages the rch skill, on every source path (repository copy, raw
#      tree, release tarball, inline stub); without those it still installs
#      and refreshes the RCH skill.
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
    "references/DISK_AND_PRESSURE.md"
    "references/ERROR_CODES.md"
    "references/EXEC_MODES.md"
    "references/FAIL_OPEN.md"
    "references/HOOKS.md"
    "references/MACHINE_INTROSPECTION.md"
    "references/MULTI_AGENT_CONTENTION.md"
    "references/OPERATIONS.md"
    "references/PATH_DEPENDENCIES.md"
    "references/RECOVERY_PLAYBOOKS.md"
    "references/SELF_HEALING.md"
    "references/SHIM.md"
    "references/SSH_KEY_RECOVERY.md"
    "references/SSH_TUNING.md"
    "references/TELEMETRY_RECOVERY.md"
    "references/TROUBLESHOOTING.md"
    "references/WORKERS.md"
    "scripts/auto_recover.sh"
    "scripts/diagnose-rch.sh"
    "scripts/mine_rch_history.sh"
    "scripts/multi_agent_safety.sh"
    "scripts/protocol_test.sh"
    "scripts/validate-setup.sh"
    "scripts/worker_disk_triage.sh"
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

# --- Test 4: the real install_skill() and skill ownership (GH#93) -----------
# Every case runs the actual install_skill() in a subshell with its own HOME,
# PATH (system dirs plus an optional fake jsm) and a curl stub that serves the
# repository's skill tree as the raw-tree or release-tarball source. Running
# a copy of install.sh that has no .claude/skills beside it forces the
# download paths instead of the repository-local copy.
SKILL_TREE="$PROJECT_ROOT/.claude/skills/rch"
REPO_INSTALLER="$PROJECT_ROOT/install.sh"
NOREPO_INSTALLER="$TEST_DIR/norepo/install.sh"
mkdir -p "$TEST_DIR/norepo"
cp "$REPO_INSTALLER" "$NOREPO_INSTALLER"
RELEASE_TARBALL="$TEST_DIR/skill.tar.gz"
tar -czf "$RELEASE_TARBALL" -C "$PROJECT_ROOT/.claude/skills" rch

make_jsm() {
    local dir="$TEST_DIR/bin-$1"
    mkdir -p "$dir"
    printf '#!/bin/sh\n%s\n' "$2" > "$dir/jsm"
    chmod +x "$dir/jsm"
    printf '%s\n' "$dir"
}
NO_JSM="$TEST_DIR/bin-none"
mkdir -p "$NO_JSM"
# The jsm that manages rch answers only when asked offline (JSM_OFFLINE=true),
# so the jsm-managed cases also prove the query stays off the network.
JSM_RCH=$(make_jsm rch "[ \"\${JSM_OFFLINE:-}\" = true ] || { echo 'jsm: network lookup attempted' >&2; exit 4; }
printf '%s\n' '{\"workspace\": \"default\", \"skills\": [{\"name\": \"cass\", \"version\": 3}, {\"name\": \"rch\", \"version\": 10}], \"count\": 2}'")
JSM_OTHER=$(make_jsm other "printf '%s\n' '{\"workspace\": \"default\", \"skills\": [{\"name\": \"rch-helper\", \"version\": 1}], \"count\": 1}'")
JSM_BROKEN=$(make_jsm broken "echo 'jsm: state unavailable' >&2; exit 3")
# A pretty-printed listing (jsm's format) of 401 skills, about 80 KB, with rch
# first. grep -q stops reading at the first matching line, so a reader of a
# listing larger than a pipe buffer must not lose that match to SIGPIPE.
JSM_RCH_LARGE=$(make_jsm rch-large "printf '{\n  \"workspace\": \"default\",\n  \"skills\": [\n    {\n      \"name\": \"rch\",\n      \"version\": 10\n    }'
i=0
while [ \"\$i\" -lt 400 ]; do
    printf ',\n    {\n      \"name\": \"skill-%d\",\n      \"version\": 1,\n      \"pinned\": false,\n      \"installed_at\": \"2026-08-26\",\n      \"status\": \"ok\",\n      \"update_available\": false,\n      \"latest_version\": null\n    }' \"\$i\"
    i=\$((i + 1))
done
printf '\n  ],\n  \"count\": 401\n}\n'")

# run_case DIR INSTALLER SOURCES PATH_PREFIX [NAME=VALUE...]
# SOURCES says which download answers (raw, release) or none (repo, none).
# TEMP_DIR and SKIP_SKILL are read, and the stub functions called, by the
# sourced installer's install_skill, which shellcheck does not follow.
# shellcheck disable=SC2034,SC2329
run_case() {
    local case_dir="$1" installer="$2" sources="$3" path_prefix="$4"
    shift 4
    mkdir -p "$case_dir/home" "$case_dir/tmp"
    (
        export HOME="$case_dir/home"
        export PATH="$path_prefix:/usr/bin:/bin"
        local kv
        for kv in "$@"; do export "${kv?}"; done
        export RCH_INSTALLER_LIB=1
        # shellcheck disable=SC1090
        source "$installer"
        TEMP_DIR="$case_dir/tmp"
        [[ -n "${CASE_SKIP_SKILL:-}" ]] && SKIP_SKILL="$CASE_SKIP_SKILL"
        warn() { printf '%s\n' "$*" >> "$case_dir/warn.log"; }
        info() { :; }
        success() { :; }
        show_skill_info() { :; }
        curl() {
            local url="" out=""
            while [[ $# -gt 0 ]]; do
                case "$1" in
                    -o) out="$2"; shift 2 ;;
                    -*) shift ;;
                    *) url="$1"; shift ;;
                esac
            done
            printf '%s\n' "$url" >> "$case_dir/downloads.log"
            case "$url" in
                https://raw.githubusercontent.com/*/main/.claude/skills/rch/*)
                    [[ "$sources" == raw ]] || return 22
                    cp "$SKILL_TREE/${url#*/main/.claude/skills/rch/}" "$out"
                    ;;
                */releases/latest/download/skill.tar.gz)
                    [[ "$sources" == release ]] || return 22
                    cp "$RELEASE_TARBALL" "$out"
                    ;;
                *) return 22 ;;
            esac
        }
        install_skill
    )
}

# A full package that RCH did not write: distinct SKILL.md and reference, plus
# a file RCH's tree does not have.
seed_external() {
    mkdir -p "$1/references"
    printf 'EXTERNAL-FIXTURE-SKILL\n' > "$1/SKILL.md"
    printf 'EXTERNAL-FIXTURE-WORKERS\n' > "$1/references/WORKERS.md"
    printf 'EXTERNAL-FIXTURE-ONLY\n' > "$1/foreign-only.md"
}

# Content snapshot of a tree: every path and every file's checksum.
snapshot() {
    (cd "$1" && find . | LC_ALL=C sort && find . -type f -exec cksum {} + | LC_ALL=C sort)
}

# untouched_case NAME INSTALLER SOURCES PATH_PREFIX [NAME=VALUE...]
# Claude's destination holds an external package and Codex's does not exist;
# the run must leave the first byte-for-byte as found, create nothing and
# download nothing.
untouched_case() {
    local name="$1"
    shift
    local case_dir="$TEST_DIR/case-$name"
    local claude="$case_dir/home/.claude/skills/rch"
    mkdir -p "$case_dir"
    seed_external "$claude"
    local before
    before=$(snapshot "$claude")
    start_test "$name: skill trees untouched, nothing downloaded"
    if ! run_case "$case_dir" "$@"; then
        fail "$name: install_skill failed"
    elif [[ "$(snapshot "$claude")" != "$before" ]]; then
        fail "$name: existing skill package was modified"
    elif [[ -e "$case_dir/home/.codex" ]]; then
        fail "$name: absent Codex skill destination was created"
    elif [[ -s "$case_dir/downloads.log" ]]; then
        fail "$name: download attempted: $(tr '\n' ' ' < "$case_dir/downloads.log")"
    else
        pass "$name: untouched"
    fi
}

# Every file of the repository skill tree is present, byte for byte.
matches_repo_tree() {
    local dest="$1" rel
    while IFS= read -r rel; do
        cmp -s "$SKILL_TREE/$rel" "$dest/$rel" || return 1
    done < <(cd "$SKILL_TREE" && find . -type f | sed 's|^\./||')
}

for sources in repo raw release none; do
    installer="$NOREPO_INSTALLER"
    [[ "$sources" == repo ]] && installer="$REPO_INSTALLER"
    untouched_case "optout-env-$sources" "$installer" "$sources" "$NO_JSM" RCH_SKIP_SKILL=1
done
untouched_case "optout-flag-repo" "$REPO_INSTALLER" repo "$NO_JSM" CASE_SKIP_SKILL=true
untouched_case "optout-flag-none" "$NOREPO_INSTALLER" none "$NO_JSM" CASE_SKIP_SKILL=true
untouched_case "jsm-managed-repo" "$REPO_INSTALLER" repo "$JSM_RCH"
untouched_case "jsm-managed-raw" "$NOREPO_INSTALLER" raw "$JSM_RCH"
untouched_case "jsm-managed-release" "$NOREPO_INSTALLER" release "$JSM_RCH"
untouched_case "jsm-managed-large-listing" "$REPO_INSTALLER" repo "$JSM_RCH_LARGE"

start_test "--skip-skill is an accepted installer option"
# RCH_INSTALLER_LIB is exported above; unset it so install.sh runs main().
if help_out=$(RCH_INSTALLER_LIB='' bash "$REPO_INSTALLER" --skip-skill --help 2>&1) && [[ "$help_out" == *"--skip-skill"* && "$help_out" == *"RCH_SKIP_SKILL"* ]]; then
    pass "--skip-skill parsed and documented"
else
    fail "--skip-skill rejected or undocumented"
fi

# installs_case NAME INSTALLER SOURCES PATH_PREFIX SEED
# SEED: "empty" (no destinations) or "old-rch" (an older RCH-owned package in
# both). Both destinations must end up holding the repository tree.
installs_case() {
    local name="$1" installer="$2" sources="$3" path_prefix="$4" seed="$5"
    local case_dir="$TEST_DIR/case-$name"
    local claude="$case_dir/home/.claude/skills/rch"
    local codex="$case_dir/home/.codex/skills/rch"
    mkdir -p "$case_dir"
    if [[ "$seed" == old-rch ]]; then
        local dest
        for dest in "$claude" "$codex"; do
            mkdir -p "$dest/references"
            printf -- '---\nname: rch\n---\nOLDER RCH SKILL\n' > "$dest/SKILL.md"
            printf 'OLDER WORKERS REFERENCE\n' > "$dest/references/WORKERS.md"
        done
    fi
    start_test "$name: installs the RCH skill"
    if ! run_case "$case_dir" "$installer" "$sources" "$path_prefix"; then
        fail "$name: install_skill failed"
    elif ! matches_repo_tree "$claude" || ! matches_repo_tree "$codex"; then
        fail "$name: destinations do not hold the repository skill tree"
    else
        pass "$name: both destinations hold the repository skill"
    fi
}

installs_case "nojsm-repo-empty" "$REPO_INSTALLER" repo "$NO_JSM" empty
installs_case "nojsm-repo-refresh" "$REPO_INSTALLER" repo "$NO_JSM" old-rch
installs_case "nojsm-raw-empty" "$NOREPO_INSTALLER" raw "$NO_JSM" empty
installs_case "nojsm-raw-refresh" "$NOREPO_INSTALLER" raw "$NO_JSM" old-rch
installs_case "nojsm-release-empty" "$NOREPO_INSTALLER" release "$NO_JSM" empty
installs_case "jsm-without-rch-repo" "$REPO_INSTALLER" repo "$JSM_OTHER" empty
installs_case "jsm-broken-repo" "$REPO_INSTALLER" repo "$JSM_BROKEN" old-rch

start_test "jsm that cannot list its packages is reported, not silently trusted"
if grep -q "jsm list --json" "$TEST_DIR/case-jsm-broken-repo/warn.log" 2>/dev/null; then
    pass "warning names the failed jsm query"
else
    fail "no warning for a failed jsm query"
fi

# GH#45 through the real function: every download fails, Claude holds a full
# external package and Codex has nothing.
start_test "stub fallback keeps a full package and fills an empty destination"
case_dir="$TEST_DIR/case-stub-fallback"
claude="$case_dir/home/.claude/skills/rch"
codex="$case_dir/home/.codex/skills/rch"
mkdir -p "$case_dir"
seed_external "$claude"
before=$(snapshot "$claude")
if ! run_case "$case_dir" "$NOREPO_INSTALLER" none "$NO_JSM"; then
    fail "install_skill failed on the stub path"
elif [[ "$(snapshot "$claude")" != "$before" ]]; then
    fail "full package was overwritten by the stub"
elif ! grep -q '^name: rch$' "$codex/SKILL.md" 2>/dev/null || cmp -s "$SKILL_TREE/SKILL.md" "$codex/SKILL.md"; then
    fail "empty destination did not receive the inline stub"
else
    pass "full package preserved; empty destination got the stub"
fi

echo ""
log "=== Results: $TESTS_PASSED passed, $TESTS_FAILED failed, $TESTS_RUN run ==="
[[ $TESTS_FAILED -eq 0 ]]
