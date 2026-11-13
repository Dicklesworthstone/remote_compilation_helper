# The caller prepends WKR_LOCATE_SHELL. Keep the uploaded namespace program on
# stdin; the native controller owns deadlines, process settlement and delivery.
set -eu
[ "$#" -le 1 ] || {
    printf '%s\n' 'RCH: invalid metadata control arguments' >&2
    exit 73
}
rch_control_contract=${1:-RCH_TOPOLOGY_OK}
case "$rch_control_contract" in
    RCH_TOPOLOGY_OK|RCH_SOURCE_CANCELLATION_SETTLED|\
    RCH_SOURCE_AUTHORITY_NAMESPACE|RCH_SOURCE_AUTHORITY_DISCOVERY|\
    RCH_SOURCE_INTENT_CANCEL|RCH_SOURCE_INTENT_RELEASED|\
    RCH_SOURCE_INTENT_CANCELLED|RCH_SOURCE_INTENT_CANCELLATION_STATE|\
    RCH_SOURCE_INTENT_FINISHED) ;;
    *) printf '%s\n' 'RCH: invalid metadata control result marker' >&2; exit 73 ;;
esac
if ! rch_wkr_locate; then
    printf '%s\n' 'RCH_SOURCE_NAMESPACE_OBSERVER_UNAVAILABLE: rch-wkr is not installed on this worker' >&2
    exit 73
fi
# Validate the protocol inside the process that owns execution supervision.
# An older worker rejects the unknown command before it can consume stdin;
# preserve that explicit refusal and every supervised program's exit status.
exec "$RCH_WKR" source-control --protocol v1 "$rch_control_contract"
