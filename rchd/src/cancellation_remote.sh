# The caller prepends rch_common::REMOTE_PROCESS_IDENTITY_SCRIPT.
# A missing record still fails (42) but says so distinctly: the launcher
# writes the record before any workload runs and the worker cleanup deletes
# it only once the group is gone, so only the daemon, knowing the build was
# abandoned long ago, may treat absence as proof that nothing is running.
if [ ! -e "$1" ] && [ ! -L "$1" ]; then
    printf 'RCH_REMOTE_RECORD_ABSENT_V1:%s\n' "$2"
    exit 42
fi
rch_remote_cancel "$1" "$2" term || exit $?
printf 'RCH_REMOTE_CANCELLED_V1:%s\n' "$2"
