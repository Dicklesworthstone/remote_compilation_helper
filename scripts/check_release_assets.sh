#!/usr/bin/env bash
#
# check_release_assets.sh — release-asset-completeness gate (rch#23 / #25 prevention).
#
# A release is only useful if it actually ships an archive for every platform the
# installer and self-updater know how to ask for. rch v1.0.43 shipped *only* the
# linux-x86_64-gnu archive while the installer requested -musl, so the tool became
# uninstallable on the most common platform (GitHub issue #23) — and the breakage
# was discovered by users, not by CI. The same failure mode is silent: a build job
# can go green while its artifact upload produces nothing, or a target can be
# dropped from `release.yml`'s `publish.needs` and nobody notices until a download
# 404s.
#
# This gate asserts that every REQUIRED target triple has both its archive AND its
# `.sha256` sidecar present, and warns (without failing) about OPTIONAL best-effort
# targets. Run it two ways:
#
#   1. Against the staged artifacts directory, BEFORE the GitHub Release is
#      created, so an incomplete release is never published:
#
#          scripts/check_release_assets.sh --dir artifacts --tag v1.2.3
#
#   2. Against the live published release (belt-and-suspenders — catches the
#      release-upload action itself dropping a file):
#
#          scripts/check_release_assets.sh --gh-release v1.2.3
#      (needs `gh` + GH_TOKEN/GITHUB_TOKEN; auto-detects the repo, or pass --repo)
#
# A `--self-test` mode fabricates synthetic fixtures and proves the gate actually
# fails on a missing archive / missing checksum (so it can be wired into ordinary
# CI without needing real release artifacts, and can never silently degrade into a
# no-op).
#
# The REQUIRED set mirrors release.yml's `publish.needs`. Keep them in sync: a
# target that `publish` hard-depends on belongs here; the intentionally
# best-effort targets (macos-x86_64, windows) are OPTIONAL. Override either set
# with the RCH_REQUIRED_TARGETS / RCH_OPTIONAL_TARGETS env vars (space-separated
# "<target-triple>:<archive-ext>" entries).
#
set -euo pipefail

# --- canonical target sets (each entry: "<target-triple>:<archive-ext>") ---------

DEFAULT_REQUIRED=(
    "x86_64-unknown-linux-gnu:tar.gz"
    "x86_64-unknown-linux-musl:tar.gz"
    "aarch64-unknown-linux-gnu:tar.gz"
    "aarch64-apple-darwin:tar.gz"
)
# Best-effort: built when a runner is available but not gated on (see the
# `publish.needs` comment in release.yml). Missing → warn, never fail.
DEFAULT_OPTIONAL=(
    "x86_64-apple-darwin:tar.gz"
    "x86_64-pc-windows-msvc:zip"
)

read_set() {
    # $1 = override env value (may be empty); $2.. = default entries.
    # Prints one "target:ext" per line.
    local override="$1"; shift
    if [[ -n "$override" ]]; then
        # space- or comma-separated (tr pads the shorter SET2, so both map to \n)
        tr ', ' '\n' <<<"$override" | while IFS= read -r e; do
            [[ -n "$e" ]] && printf '%s\n' "$e"
        done
    else
        printf '%s\n' "$@"
    fi
}

usage() {
    cat >&2 <<'EOF'
Usage:
  check_release_assets.sh --dir <artifacts-dir> --tag <tag>
  check_release_assets.sh --gh-release <tag> [--repo <owner/name>]
  check_release_assets.sh --self-test

Asserts every REQUIRED target triple has its archive + .sha256 in the release.
Exit 0 = complete; exit 1 = a required asset is missing (or bad usage).
EOF
}

# --- core check ------------------------------------------------------------------

# check_assets <tag> <have_fn>
#   <have_fn> is the name of a function taking an asset filename and returning 0
#   if that asset is present. Prints findings to stderr; returns 1 if any REQUIRED
#   asset is missing, else 0.
check_assets() {
    local tag="$1" have_fn="$2"
    local entry target ext archive checksum
    local -a missing=() warned=()

    while IFS= read -r entry; do
        [[ -z "$entry" ]] && continue
        target="${entry%%:*}"
        ext="${entry#*:}"
        archive="rch-${tag}-${target}.${ext}"
        checksum="${archive}.sha256"
        "$have_fn" "$archive"  || missing+=("$archive")
        "$have_fn" "$checksum" || missing+=("$checksum")
    done < <(read_set "${RCH_REQUIRED_TARGETS:-}" "${DEFAULT_REQUIRED[@]}")

    while IFS= read -r entry; do
        [[ -z "$entry" ]] && continue
        target="${entry%%:*}"
        ext="${entry#*:}"
        archive="rch-${tag}-${target}.${ext}"
        checksum="${archive}.sha256"
        "$have_fn" "$archive"  || warned+=("$archive")
        "$have_fn" "$checksum" || warned+=("$checksum")
    done < <(read_set "${RCH_OPTIONAL_TARGETS:-}" "${DEFAULT_OPTIONAL[@]}")

    if [[ ${#warned[@]} -gt 0 ]]; then
        echo "check_release_assets: NOTE — optional (best-effort) assets absent for ${tag}:" >&2
        printf '    - %s\n' "${warned[@]}" >&2
    fi

    if [[ ${#missing[@]} -gt 0 ]]; then
        echo "RCH-GATE-RELEASE-ASSETS: incomplete release ${tag} — missing REQUIRED asset(s):" >&2
        printf '    - %s\n' "${missing[@]}" >&2
        cat >&2 <<'EOF'

Every REQUIRED target triple must ship its archive AND its .sha256 sidecar, or the
installer/self-updater 404s on that platform for real users (this is exactly how
rch#23 happened). Fix by ensuring the corresponding build job ran and uploaded its
artifact, and that the target is wired into release.yml's `publish.needs`. The
REQUIRED set lives at the top of this script — keep it in sync with `publish.needs`.
EOF
        return 1
    fi
    return 0
}

# --- mode: directory -------------------------------------------------------------

run_dir_mode() {
    local dir="$1" tag="$2"
    [[ -d "$dir" ]] || { echo "check_release_assets: artifacts dir not found: $dir" >&2; exit 1; }
    _have_in_dir() { [[ -f "$dir/$1" ]]; }
    if check_assets "$tag" _have_in_dir; then
        echo "check_release_assets: OK — release ${tag} has every required archive + checksum in ${dir}/"
    else
        exit 1
    fi
}

# --- mode: live GitHub release ---------------------------------------------------

run_gh_mode() {
    local tag="$1" repo="${2:-}"
    command -v gh >/dev/null 2>&1 || { echo "check_release_assets: gh CLI not found (needed for --gh-release)" >&2; exit 1; }
    local -a gh_args=(release view "$tag" --json assets -q '.assets[].name')
    [[ -n "$repo" ]] && gh_args+=(--repo "$repo")
    local asset_list
    if ! asset_list="$(gh "${gh_args[@]}" 2>/dev/null)"; then
        echo "RCH-GATE-RELEASE-ASSETS: could not read GitHub release ${tag} (does it exist? is gh authed?)" >&2
        exit 1
    fi
    _have_in_release() { grep -Fxq -- "$1" <<<"$asset_list"; }
    if check_assets "$tag" _have_in_release; then
        echo "check_release_assets: OK — published release ${tag} contains every required archive + checksum"
    else
        exit 1
    fi
}

# --- mode: self-test -------------------------------------------------------------

run_self_test() {
    local tmp tag="v9.9.9-selftest"
    tmp="$(mktemp -d)"
    # shellcheck disable=SC2064
    trap "rm -rf '$tmp'" EXIT

    # Populate a complete set (required + optional) of archives + checksums.
    local entry target ext archive
    for entry in "${DEFAULT_REQUIRED[@]}" "${DEFAULT_OPTIONAL[@]}"; do
        target="${entry%%:*}"; ext="${entry#*:}"
        archive="rch-${tag}-${target}.${ext}"
        : >"$tmp/$archive"
        : >"$tmp/$archive.sha256"
    done

    local fails=0
    _st_have() { [[ -f "$tmp/$1" ]]; }

    # 1) complete set must PASS
    if check_assets "$tag" _st_have >/dev/null 2>&1; then
        echo "  self-test[1] complete set passes ......... OK"
    else
        echo "  self-test[1] complete set passes ......... FAIL" >&2; fails=1
    fi

    # 2) a missing REQUIRED archive must FAIL
    local req_target req_ext req_archive
    req_target="${DEFAULT_REQUIRED[0]%%:*}"; req_ext="${DEFAULT_REQUIRED[0]#*:}"
    req_archive="rch-${tag}-${req_target}.${req_ext}"
    rm -f "$tmp/$req_archive"
    if check_assets "$tag" _st_have >/dev/null 2>&1; then
        echo "  self-test[2] missing required archive fails  FAIL" >&2; fails=1
    else
        echo "  self-test[2] missing required archive fails  OK"
    fi
    : >"$tmp/$req_archive"  # restore

    # 3) a missing REQUIRED checksum must FAIL
    rm -f "$tmp/$req_archive.sha256"
    if check_assets "$tag" _st_have >/dev/null 2>&1; then
        echo "  self-test[3] missing required checksum fails FAIL" >&2; fails=1
    else
        echo "  self-test[3] missing required checksum fails OK"
    fi
    : >"$tmp/$req_archive.sha256"  # restore

    # 4) a missing OPTIONAL asset must still PASS (warn only)
    local opt_target opt_ext opt_archive
    opt_target="${DEFAULT_OPTIONAL[0]%%:*}"; opt_ext="${DEFAULT_OPTIONAL[0]#*:}"
    opt_archive="rch-${tag}-${opt_target}.${opt_ext}"
    rm -f "$tmp/$opt_archive"
    if check_assets "$tag" _st_have >/dev/null 2>&1; then
        echo "  self-test[4] missing optional asset passes . OK"
    else
        echo "  self-test[4] missing optional asset passes . FAIL" >&2; fails=1
    fi

    if [[ "$fails" -ne 0 ]]; then
        echo "check_release_assets --self-test: FAILED" >&2
        exit 1
    fi
    echo "check_release_assets --self-test: OK"
}

# --- arg parsing -----------------------------------------------------------------

main() {
    local mode="" dir="" tag="" repo=""
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --dir)        dir="${2:-}"; shift 2 ;;
            --tag)        tag="${2:-}"; shift 2 ;;
            --gh-release) mode="gh"; tag="${2:-}"; shift 2 ;;
            --repo)       repo="${2:-}"; shift 2 ;;
            --self-test)  mode="self-test"; shift ;;
            -h|--help)    usage; exit 0 ;;
            *) echo "check_release_assets: unknown argument: $1" >&2; usage; exit 1 ;;
        esac
    done

    if [[ "$mode" == "self-test" ]]; then
        run_self_test; return
    fi
    if [[ "$mode" == "gh" ]]; then
        [[ -n "$tag" ]] || { echo "check_release_assets: --gh-release requires a tag" >&2; usage; exit 1; }
        run_gh_mode "$tag" "$repo"; return
    fi
    # default: directory mode
    [[ -n "$dir" && -n "$tag" ]] || { echo "check_release_assets: --dir and --tag are required" >&2; usage; exit 1; }
    run_dir_mode "$dir" "$tag"
}

main "$@"
