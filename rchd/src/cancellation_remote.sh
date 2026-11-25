# The caller prepends rch_common::REMOTE_PROCESS_IDENTITY_SCRIPT.
# A missing record still fails (42) but says so distinctly: the launcher
# writes the record before any workload runs and the worker cleanup deletes
# it only once the group is gone. Only the daemon, with durable no-launch
# evidence or the abandoned-build silence bound, may accept that absence.
if [ ! -e "$1" ] && [ ! -L "$1" ]; then
    # Failed shell tests are only a hint. An inaccessible record must retain
    # ownership just like any other unavailable process observation.
    rch_path_absent "$1" || exit 44
    printf 'RCH_REMOTE_RECORD_ABSENT_V1:%s\n' "$2"
    exit 42
fi
rch_remote_cancel "$1" "$2" term || exit $?
printf 'RCH_REMOTE_CANCELLED_V1:%s\n' "$2"
