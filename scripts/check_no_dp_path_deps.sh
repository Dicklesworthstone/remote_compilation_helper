#!/usr/bin/env bash
#
# check_no_dp_path_deps.sh — regression guard for rch#23.
#
# The workspace must build from a clean checkout on any machine. That breaks the
# moment a Cargo manifest depends on a crate by an ABSOLUTE filesystem path (e.g.
# `path = "/dp/frankentui/crates/ftui"`), because such a path only exists on the
# author's dev machine — a fresh `git clone && cargo build` (and the installer's
# source-build fallback) then aborts during manifest resolution with:
#
#     failed to read `/dp/frankentui/crates/ftui/Cargo.toml`: No such file ...
#
# That is exactly how rch v1.0.43 became uninstallable on linux-x86_64
# (GitHub issue #23). The durable fix was to depend on the published crates.io
# versions; this guard makes any regression back to an absolute-path dependency
# fail fast and legibly in CI instead of surfacing as an opaque cargo error.
#
# Relative path deps (`path = "rch-common"`, `path = "../foo"`) are fine and are
# NOT flagged — only absolute paths (a leading `/`) are rejected.
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$PROJECT_ROOT"

# Collect the manifests to scan. Prefer git's tracked-file list (skips target/,
# vendored trees, scratch dirs); fall back to a bounded find if not in a git repo.
manifests=()
if git rev-parse --is-inside-work-tree >/dev/null 2>&1; then
    while IFS= read -r f; do
        [[ -n "$f" ]] && manifests+=("$f")
    done < <(git ls-files -- 'Cargo.toml' '**/Cargo.toml')
else
    while IFS= read -r f; do
        manifests+=("$f")
    done < <(find . -name Cargo.toml -not -path '*/target/*' -print)
fi

if [[ ${#manifests[@]} -eq 0 ]]; then
    echo "check_no_dp_path_deps: no Cargo.toml manifests found under $PROJECT_ROOT" >&2
    exit 1
fi

# An absolute-path dependency: `path = "/..."` (any whitespace around `=`,
# optionally single-quoted). This catches [dependencies], [workspace.dependencies],
# [patch.*] and [build-dependencies] uniformly.
abs_path_re='path[[:space:]]*=[[:space:]]*["'\''"]/'

fail=0
for m in "${manifests[@]}"; do
    [[ -f "$m" ]] || continue
    # Match absolute-path deps but ignore full-line TOML comments — a commented-out
    # `# path = "/dp/old"` must not trip the guard. Inline-table deps like
    # `ftui = { path = "/dp/..." }` are mid-line (not comments) and still match.
    hits="$(grep -nE "$abs_path_re" -- "$m" 2>/dev/null | grep -vE '^[0-9]+:[[:space:]]*#' || true)"
    if [[ -n "$hits" ]]; then
        echo "RCH-GATE-DP-PATH: absolute-path dependency in $m (breaks clean-checkout build — rch#23):" >&2
        while IFS= read -r line; do
            echo "    $line" >&2
        done <<<"$hits"
        fail=1
    fi
done

if [[ "$fail" -ne 0 ]]; then
    cat >&2 <<'EOF'

Absolute-path dependencies do not exist on a clean checkout (CI, the installer's
source fallback, any other machine), so the workspace cannot build. Fix by
depending on the published crates.io version instead, e.g.:

    -ftui = { path = "/dp/frankentui/crates/ftui", version = "0.4.0" }
    +ftui = { version = "0.4" }

(or a workspace-relative `path = "..."` for an in-tree crate).
EOF
    exit 1
fi

echo "check_no_dp_path_deps: OK — no absolute-path dependencies in ${#manifests[@]} manifest(s)"
