# This is the fixed command argument, not the namespace program. Keep that
# potentially large program on stdin. Its entire worker-side lifetime (input,
# mutex waits, retries, mutators AND pipe EOF) gets its own deadline, independent
# of the client's 20s exchange budget or a lost SSH connection. No source intent,
# pair lock, or workload exists at this boundary.
set -eu
if command -v gtimeout >/dev/null 2>&1; then
    rch_namespace_timer=gtimeout
elif command -v timeout >/dev/null 2>&1; then
    rch_namespace_timer=timeout
else
    printf '%s\n' 'RCH: namespace setup requires GNU timeout or gtimeout' >&2
    exit 73
fi
# Default timeout process-group semantics are essential: --foreground would
# leave a descendant holding the registry or output pipe. TERM gets one second
# to finish; KILL applies only to this private namespace-control group.
exec "$rch_namespace_timer" --kill-after=1 15 sh -c '
set -eu
umask 077
control=$(mktemp -d "${TMPDIR:-/tmp}/rch-namespace-control.XXXXXXXXXX") || exit 73
cleanup() {
    # These are fixed names in our freshly-created private directory, never
    # source, claim, recovery, alias, or caller-supplied paths.
    rm -f -- "$control/stdout.pipe" "$control/stderr.pipe" \
        "$control/stdout" "$control/stderr"
    rmdir -- "$control"
}
trap cleanup 0
# Do not let the monitored shell exit on TERM before the timer escalates to KILL:
# timeout stops monitoring when its direct child exits, even if a grandchild
# ignores TERM and still owns a pipe or mutex. Keep this group member alive.
trap "while :; do sleep 1; done" HUP INT TERM PIPE
mkfifo -- "$control/stdout.pipe" "$control/stderr.pipe" || exit 73
# Save input before spawning any asynchronous command. In dash, redirecting
# an asynchronous command from its own fd 0 still sees the implicit /dev/null.
exec 3<&0
# Read one byte beyond each bound, not merely a valid-looking prefix. Readers
# stay in this private group. Waiting for both detects grandchildren that keep
# a pipe open after the immediate program has already exited successfully.
head -c 4097 "$control/stdout.pipe" > "$control/stdout" 3<&- &
stdout_reader=$!
head -c 65537 "$control/stderr.pipe" > "$control/stderr" 3<&- &
stderr_reader=$!
set +e
# Launch with an explicit stdin binding: asynchronous POSIX commands otherwise
# read /dev/null. Redirect only the child, not this monitor while it waits.
# Dash can report a signalled foreground child through its redirected stderr;
# if that FIFO reader died too, SIGPIPE could kill the monitor before escalation.
sh -s <&3 3<&- > "$control/stdout.pipe" 2> "$control/stderr.pipe" &
program=$!
exec 3<&-
wait "$program"
status=$?
wait "$stdout_reader"
stdout_status=$?
wait "$stderr_reader"
stderr_status=$?
set -e
[ "$stdout_status" -eq 0 ] && [ "$stderr_status" -eq 0 ] || exit 73
stdout_bytes=$(wc -c < "$control/stdout") || exit 73
stderr_bytes=$(wc -c < "$control/stderr") || exit 73
if [ "$stdout_bytes" -gt 4096 ] || [ "$stderr_bytes" -gt 65536 ]; then
    printf "%s\n" "RCH: namespace control output exceeded its byte bound" >&2
    exit 73
fi
cat -- "$control/stderr" >&2 || exit 73
# Preserve refusal status, but never publish a premature readiness marker from
# a command that failed later. Exact byte comparison also rejects NUL, trailing
# noise and missing/extra newlines rather than repairing them into authority.
[ "$status" -eq 0 ] || exit "$status"
printf "RCH_TOPOLOGY_OK\n" | cmp -s - "$control/stdout" || {
    printf "%s\n" "RCH: namespace control returned invalid readiness" >&2
    exit 73
}
cat -- "$control/stdout"
'
