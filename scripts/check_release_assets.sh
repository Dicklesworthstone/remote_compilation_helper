#!/usr/bin/env bash
#
# check_release_assets.sh — release-asset-completeness gate (rch#23 / #25 prevention).
#
# A release is only useful if a user on each supported platform can actually
# install/self-update from it. rch v1.0.43 became uninstallable on linux-x86_64
# because the published assets didn't include an archive the installer/updater
# could resolve for that platform (GitHub issue #23) — and the breakage was found
# by users, not CI. The failure mode is silent: a build/upload can drop a whole
# platform, or a release cut via the dsr fallback can omit one (see the
# "dsr drops linux archives" operational note), and nothing flags it.
#
# This gate is INSTALLABILITY-based, mirroring how the self-updater resolves an
# asset: `current_release_targets()` returns, per platform, an ORDERED list of
# accepted archive names (the canonical target triple AND short aliases), and the
# updater downloads the first one that exists. So a platform is "covered" when ANY
# of its accepted archive names is present together with a checksum the updater
# accepts — a per-archive `.sha256` sidecar OR a consolidated SHA256SUMS /
# checksums.txt (the checksum is enforced on download; see find_checksum_asset).
# Required platforms must be covered; optional ones only warn.
#
# Run it two ways:
#
#   1. Against the staged artifacts directory, BEFORE the GitHub Release is
#      created, so an incomplete release is never published:
#
#          scripts/check_release_assets.sh --dir artifacts --tag v1.2.3
#
#   2. Against the live published release (belt-and-suspenders — also works for
#      dsr-cut releases and catches the upload action dropping a file):
#
#          scripts/check_release_assets.sh --gh-release v1.2.3
#      (needs `gh` + GH_TOKEN/GITHUB_TOKEN; auto-detects the repo, or pass --repo)
#
# A `--self-test` mode fabricates synthetic fixtures and proves the gate fails on
# a fully-absent required platform / a missing checksum, accepts an alias-named
# archive as equivalent to the triple, and tolerates absent optional platforms —
# so it can run in ordinary CI and can never silently degrade into a no-op.
#
# Required platforms = where the tool MUST be installable (the worker fleet +
# common dev machines): linux-x86_64 and macos-aarch64. The accepted-name sets
# track current_release_targets() in rch/src/update/types.rs — keep them in sync.
# Override with RCH_REQUIRED_PLATFORMS / RCH_OPTIONAL_PLATFORMS (space-separated
# "<label>|<ext>|<name1>,<name2>,..." entries).
#
set -euo pipefail

# --- canonical platform sets -----------------------------------------------------
# Each entry: "<label>|<archive-ext>|<accepted-name-1>,<accepted-name-2>,...".
# A platform is covered if ANY accepted name has both <archive> and <archive>.sha256.

DEFAULT_REQUIRED_PLATFORMS=(
    "linux-x86_64|tar.gz|x86_64-unknown-linux-gnu,x86_64-unknown-linux-musl,linux-x86_64"
    "macos-aarch64|tar.gz|aarch64-apple-darwin,darwin-aarch64"
)
# Best-effort platforms (built when a runner is available; absence → warn, never fail).
DEFAULT_OPTIONAL_PLATFORMS=(
    "linux-aarch64|tar.gz|aarch64-unknown-linux-gnu,linux-aarch64"
    "macos-x86_64|tar.gz|x86_64-apple-darwin,darwin-x86_64"
    "windows-x86_64|zip|x86_64-pc-windows-msvc,windows-x86_64"
)

read_platforms() {
    # $1 = "1" if the override env var is SET (even to empty); $2 = its value;
    # $3.. = default entries. A set-but-empty override means "no platforms";
    # an unset override falls back to the defaults.
    local is_set="$1" override="$2"; shift 2
    if [[ "$is_set" == "1" ]]; then
        # entries separated by whitespace (newline-friendly via tr)
        tr ' ' '\n' <<<"$override" | while IFS= read -r e; do
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

Asserts every REQUIRED platform is installable from the release: some accepted
archive name (triple or alias) plus a checksum (its .sha256 or a consolidated
SHA256SUMS/checksums.txt) is present.
Exit 0 = covered; exit 1 = a required platform is missing (or bad usage).
EOF
}

# --- core check ------------------------------------------------------------------

# platform_covered <tag> <have_fn> <ext> <names_csv> <has_consolidated>
#   Returns 0 if ANY accepted name has its archive present together with a checksum
#   the updater would accept — either a per-archive "<archive>.sha256" sidecar or a
#   release-wide consolidated file (SHA256SUMS / checksums.txt; see
#   find_checksum_asset in download.rs). <has_consolidated> is 1 when such a
#   consolidated file is present in the release. Returns 1 otherwise.
platform_covered() {
    local tag="$1" have_fn="$2" ext="$3" names_csv="$4" has_consolidated="$5"
    local name archive
    local IFS=','
    for name in $names_csv; do
        [[ -z "$name" ]] && continue
        archive="rch-${tag}-${name}.${ext}"
        if "$have_fn" "$archive"; then
            if "$have_fn" "${archive}.sha256" || [[ "$has_consolidated" == "1" ]]; then
                return 0
            fi
        fi
    done
    return 1
}

# check_platforms <tag> <have_fn>
#   Prints findings to stderr; returns 1 if any REQUIRED platform is uncovered.
check_platforms() {
    local tag="$1" have_fn="$2"
    local entry label ext names
    local -a missing=() warned=()

    # A consolidated checksum file covers every archive in the release.
    local has_consolidated=0
    if "$have_fn" "SHA256SUMS" || "$have_fn" "checksums.txt"; then
        has_consolidated=1
    fi

    while IFS= read -r entry; do
        [[ -z "$entry" ]] && continue
        label="${entry%%|*}"; entry="${entry#*|}"
        ext="${entry%%|*}";   names="${entry#*|}"
        if ! platform_covered "$tag" "$have_fn" "$ext" "$names" "$has_consolidated"; then
            missing+=("${label} (looked for: $(fmt_names "$tag" "$ext" "$names"))")
        fi
    done < <(read_platforms "${RCH_REQUIRED_PLATFORMS+1}" "${RCH_REQUIRED_PLATFORMS:-}" "${DEFAULT_REQUIRED_PLATFORMS[@]}")

    while IFS= read -r entry; do
        [[ -z "$entry" ]] && continue
        label="${entry%%|*}"; entry="${entry#*|}"
        ext="${entry%%|*}";   names="${entry#*|}"
        if ! platform_covered "$tag" "$have_fn" "$ext" "$names" "$has_consolidated"; then
            warned+=("$label")
        fi
    done < <(read_platforms "${RCH_OPTIONAL_PLATFORMS+1}" "${RCH_OPTIONAL_PLATFORMS:-}" "${DEFAULT_OPTIONAL_PLATFORMS[@]}")

    if [[ ${#warned[@]} -gt 0 ]]; then
        echo "check_release_assets: NOTE — optional (best-effort) platform(s) not covered for ${tag}: ${warned[*]}" >&2
    fi

    if [[ ${#missing[@]} -gt 0 ]]; then
        echo "RCH-GATE-RELEASE-ASSETS: incomplete release ${tag} — REQUIRED platform(s) not installable:" >&2
        printf '    - %s\n' "${missing[@]}" >&2
        cat >&2 <<'EOF'

Each required platform needs at least one accepted archive name (canonical triple
OR short alias) PLUS a checksum the updater accepts (a per-archive .sha256 sidecar
or a consolidated SHA256SUMS / checksums.txt), or the installer/self-updater 404s
on that platform for real users (this is how rch#23 happened). Fix by ensuring the
platform's build ran and uploaded an archive + checksum. The accepted-name sets
live at the top of this script and track current_release_targets() in
rch/src/update/types.rs.
EOF
        return 1
    fi
    return 0
}

# fmt_names <tag> <ext> <names_csv> -> "a.tar.gz|b.tar.gz" (for diagnostics)
fmt_names() {
    local tag="$1" ext="$2" names_csv="$3" out="" name
    local IFS=','
    for name in $names_csv; do
        [[ -z "$name" ]] && continue
        out+="rch-${tag}-${name}.${ext} | "
    done
    printf '%s' "${out% | }"
}

# --- mode: directory -------------------------------------------------------------

run_dir_mode() {
    local dir="$1" tag="$2"
    [[ -d "$dir" ]] || { echo "check_release_assets: artifacts dir not found: $dir" >&2; exit 1; }
    _have_in_dir() { [[ -f "$dir/$1" ]]; }
    if check_platforms "$tag" _have_in_dir; then
        echo "check_release_assets: OK — release ${tag} is installable on every required platform (${dir}/)"
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
    if check_platforms "$tag" _have_in_release; then
        echo "check_release_assets: OK — published release ${tag} is installable on every required platform"
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

    local entry label ext names first_name
    _put() { : >"$tmp/rch-${tag}-$1.${2}"; : >"$tmp/rch-${tag}-$1.${2}.sha256"; }
    _rm()  { rm -f "$tmp/rch-${tag}-$1.${2}" "$tmp/rch-${tag}-$1.${2}.sha256"; }
    _st_have() { [[ -f "$tmp/$1" ]]; }

    # Populate the FIRST accepted name of every platform (required + optional).
    for entry in "${DEFAULT_REQUIRED_PLATFORMS[@]}" "${DEFAULT_OPTIONAL_PLATFORMS[@]}"; do
        label="${entry%%|*}"; entry="${entry#*|}"; ext="${entry%%|*}"; names="${entry#*|}"
        first_name="${names%%,*}"
        _put "$first_name" "$ext"
    done

    local fails=0
    # extract required platform[0] fields for targeted mutations
    local r0="${DEFAULT_REQUIRED_PLATFORMS[0]}"
    local r0_ext="${r0#*|}"; r0_ext="${r0_ext%%|*}"
    local r0_names="${r0##*|}"
    local r0_first="${r0_names%%,*}"
    local r0_alias="${r0_names##*,}"   # last accepted name (alias)

    # 1) full fixture must PASS
    if check_platforms "$tag" _st_have >/dev/null 2>&1; then
        echo "  self-test[1] full fixture passes ................. OK"
    else
        echo "  self-test[1] full fixture passes ................. FAIL" >&2; fails=1
    fi

    # 2) remove ALL accepted names of a required platform -> FAIL
    local n
    local IFS=','
    for n in $r0_names; do _rm "$n" "$r0_ext"; done
    unset IFS
    if check_platforms "$tag" _st_have >/dev/null 2>&1; then
        echo "  self-test[2] uncovered required platform fails ... FAIL" >&2; fails=1
    else
        echo "  self-test[2] uncovered required platform fails ... OK"
    fi

    # 3) cover that platform via a DIFFERENT accepted name (alias) -> PASS (equivalence)
    _put "$r0_alias" "$r0_ext"
    if check_platforms "$tag" _st_have >/dev/null 2>&1; then
        echo "  self-test[3] alias name satisfies platform ...... OK"
    else
        echo "  self-test[3] alias name satisfies platform ...... FAIL" >&2; fails=1
    fi

    # 4) remove just the alias's .sha256 (no consolidated file) -> FAIL
    rm -f "$tmp/rch-${tag}-${r0_alias}.${r0_ext}.sha256"
    if check_platforms "$tag" _st_have >/dev/null 2>&1; then
        echo "  self-test[4] archive without checksum fails ..... FAIL" >&2; fails=1
    else
        echo "  self-test[4] archive without checksum fails ..... OK"
    fi

    # 5) add a consolidated SHA256SUMS (alias archive still present, no sidecar) -> PASS
    : >"$tmp/SHA256SUMS"
    if check_platforms "$tag" _st_have >/dev/null 2>&1; then
        echo "  self-test[5] consolidated SHA256SUMS covers ..... OK"
    else
        echo "  self-test[5] consolidated SHA256SUMS covers ..... FAIL" >&2; fails=1
    fi
    rm -f "$tmp/SHA256SUMS"
    # restore required platform[0] for the next check
    _put "$r0_first" "$r0_ext"

    # 6) remove an OPTIONAL platform entirely -> still PASS (warn only)
    local o0="${DEFAULT_OPTIONAL_PLATFORMS[0]}"
    local o0_ext="${o0#*|}"; o0_ext="${o0_ext%%|*}"
    local o0_names="${o0##*|}"
    for n in ${o0_names//,/ }; do _rm "$n" "$o0_ext"; done
    if check_platforms "$tag" _st_have >/dev/null 2>&1; then
        echo "  self-test[6] absent optional platform passes .... OK"
    else
        echo "  self-test[6] absent optional platform passes .... FAIL" >&2; fails=1
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
    [[ -n "$dir" && -n "$tag" ]] || { echo "check_release_assets: --dir and --tag are required" >&2; usage; exit 1; }
    run_dir_mode "$dir" "$tag"
}

main "$@"
