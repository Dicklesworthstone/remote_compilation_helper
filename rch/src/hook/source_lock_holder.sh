set -eu
# Callers prepend rch_common::wkr_locate::WKR_LOCATE_SHELL. This holder
# transfers the inherited fd-3 plan/program, fd-4 claims and untouched stdin
# directly to the versioned native worker; an older deployment grants nothing.
rch_source_lock_unavailable() {
    case "${1-}" in
        --rch-finite-rpc) printf '%s\n' 'RCH_SOURCE_ACTIVITY_LIVENESS_UNAVAILABLE: rch-wkr source-lock v1 is required; no source activity acquired' >&2 ;;
        --rch-session) printf '%s\n' 'RCH_SOURCE_LOCK_LIVENESS_UNAVAILABLE: rch-wkr source-lock v1 is required; no source locks acquired' >&2 ;;
        *) printf '%s\n' 'RCH_SOURCE_LOCK_UNAVAILABLE: rch-wkr source-lock v1 is required; no source grant acquired' >&2 ;;
    esac
    exit 73
}
command -v rch_wkr_locate >/dev/null 2>&1 && rch_wkr_locate || rch_source_lock_unavailable "${1-}"
rch_source_lock_probe=$("$RCH_WKR" source-lock probe </dev/null) || rch_source_lock_unavailable "${1-}"
[ "$rch_source_lock_probe" = 'rch-wkr source-lock v1' ] || rch_source_lock_unavailable "${1-}"
exec "$RCH_WKR" source-lock "$@"
