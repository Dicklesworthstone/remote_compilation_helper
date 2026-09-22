# The caller prepends rch_common::REMOTE_PROCESS_IDENTITY_SCRIPT.
rch_remote_cancel "$1" "$2" term || exit $?
printf 'RCH_REMOTE_CANCELLED_V1:%s\n' "$2"
