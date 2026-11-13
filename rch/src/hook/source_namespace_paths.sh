# The registry holds its metadata mutex and checks source owners before create.
# The native worker observes or adds names without replacing existing paths.
# Callers prepend the shared worker locator before this adapter.
set -eu
if ! rch_wkr_locate; then
    printf '%s\n' 'RCH: source namespace: rch-wkr unavailable; deploy a current worker' >&2
    exit 73
fi
namespace_probe=$("$RCH_WKR" source-namespace-paths probe </dev/null 2>/dev/null) || namespace_probe=
if [ "$namespace_probe" != 'rch-wkr source-namespace-paths v1' ]; then
    printf '%s\n' 'RCH: source namespace: rch-wkr lacks source-namespace-paths v1; deploy a current worker' >&2
    exit 73
fi
exec "$RCH_WKR" source-namespace-paths "$@"
