# Fixed command argument; the namespace program stays on stdin. This is only
# pre-intent namespace setup, never a source grant, pair lock or build workload.
set -eu
# GNU timeout kills its whole process group on --kill-after; uutils timeout
# (Ubuntu 25.10+ /usr/bin/timeout) kills only its direct child, leaving a
# TERM-resistant descendant holding the registry lock. Ubuntu keeps GNU's as
# gnutimeout; macOS Homebrew installs it as gtimeout.
if command -v gnutimeout >/dev/null 2>&1; then
    rch_namespace_timer=gnutimeout
elif command -v gtimeout >/dev/null 2>&1; then
    rch_namespace_timer=gtimeout
elif command -v timeout >/dev/null 2>&1 &&
    timeout --version 2>/dev/null | head -n 1 | grep -q 'GNU coreutils'; then
    rch_namespace_timer=timeout
else
    printf '%s\n' 'RCH: namespace setup requires GNU timeout (gnutimeout or gtimeout)' >&2
    exit 73
fi
umask 077
# The receipt directory belongs to the observer, OUTSIDE the execution group.
# Bound creation too: a blocked filesystem must not start an unobserved program.
control=$("$rch_namespace_timer" --kill-after=1 1 mktemp -d \
    "${TMPDIR:-/tmp}/rch-namespace-control.XXXXXXXXXX") || exit 73
cleanup() {
    # Fixed names in our private directory, never source/claim/recovery paths.
    # Cleanup is best effort and bounded; it cannot change the delivery result.
    "$rch_namespace_timer" --kill-after=1 1 sh -c '
        rm -f -- "$1/stdout.pipe" "$1/stderr.pipe" "$1/stdout" \
            "$1/stderr" "$1/result"
        rmdir -- "$1"
    ' rch-namespace-cleanup "$control" >/dev/null 2>&1 || :
}
trap cleanup 0
# Save the upload before starting a background command. POSIX shells otherwise
# substitute /dev/null for its stdin. The observer never consumes program bytes.
exec 3<&0
# GNU timeout creates a private process group. Do NOT use --foreground. The
# monitor's terminal action kills that exact, still-owned group (including the
# timer and itself); no remembered PID or process-table scan authorizes a kill.
# EOF is insufficient: a grandchild can close both pipes and retain a mutex or
# continue mutating the namespace after its parent exits. Always tear down the
# execution group, on success as well as failure, before forwarding readiness.
"$rch_namespace_timer" --kill-after=1 15 sh -c '
set -eu
control=$1
observer=$2
# Prove that the direct parent leads a private process group BEFORE
# installing a group-wide kill trap or reading any namespace program. A timer
# wrapper using --foreground must not turn "kill 0" into a kill of the observer,
# SSH session, or caller group. This inspects live ancestry, not a saved PID.
group_state=$(LC_ALL=C ps -o pid= -o ppid= -o pgid= -p "$$") || exit 73
set -f
set -- $group_state
[ "$#" -eq 3 ] || exit 73
case "$1:$2:$3" in *[!0-9:]*) exit 73 ;; esac
[ "$1" = "$$" ] && [ "$2" = "$3" ] && [ "$3" != "$$" ] &&
    [ "$3" != "$observer" ] || {
    printf "%s\n" "RCH: namespace timer did not establish a private process group" >&2
    exit 73
}
# Unexpected setup/validation errors must also retire the execution group.
# They leave no completion record, so the observer cannot report success.
trap "kill -KILL 0" 0
# Keep timeout monitoring until its KILL escalation, even if a descendant
# ignores TERM. A signalled monitor must not make the timer exit prematurely.
trap "while :; do sleep 1; done" HUP INT TERM PIPE
finish() {
    printf "%s\n" "$1" > "$control/result" || exit 73
    # The result is not acknowledged until the observer reaps this timer.
    # Only this pre-intent group is killed, not the observer or any build group.
    kill -KILL 0
    exit 73
}
mkfifo -- "$control/stdout.pipe" "$control/stderr.pipe" || exit 73
exec 3<&0
# One byte beyond each bound distinguishes complete evidence from truncation.
head -c 4097 "$control/stdout.pipe" > "$control/stdout" 3<&- &
stdout_reader=$!
head -c 65537 "$control/stderr.pipe" > "$control/stderr" 3<&- &
stderr_reader=$!
set +e
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
# An ordinary refusal may have printed readiness before failing. Preserve its
# exit but never publish that marker. Successful evidence must match bytewise.
[ "$status" -eq 0 ] || finish "$status"
printf "RCH_TOPOLOGY_OK\n" | cmp -s - "$control/stdout" || {
    printf "%s\n" "RCH: namespace control returned invalid readiness" >&2
    exit 73
}
finish 0
' rch-namespace-monitor "$control" "$$" <&3 3<&- &
monitor=$!
exec 3<&-
set +e
# Suppress the shell's diagnostic for the deliberate group kill, not the
# program's captured stderr or the monitor's validation diagnostics.
wait "$monitor" 2>/dev/null
monitor_status=$?
set -e
# A normal timer exit, an external interruption or a missing/partial record is
# not a teardown receipt. The monitor writes only a fully settled result, then
# kills its group; timeout escalation can finish that same teardown if needed.
[ "$monitor_status" -eq 137 ] && [ -f "$control/result" ] || {
    printf '%s\n' 'RCH: namespace control ended without settled group teardown' >&2
    exit 73
}
# Delivery has its own deadline, too. A stalled SSH reader must not leave the
# observer or its pipe writers alive. This group has no namespace mutators.
"$rch_namespace_timer" --kill-after=1 2 sh -c '
set -eu
control=$1
IFS= read -r status < "$control/result" || exit 73
case "$status" in ""|*[!0-9]*) exit 73 ;; esac
[ "${#status}" -le 3 ] && [ "$status" -le 255 ] || exit 73
printf "%s\n" "$status" | cmp -s - "$control/result" || exit 73
# Check the retained bytes again before releasing any readiness to the caller.
[ "$(wc -c < "$control/stdout")" -le 4096 ] || exit 73
[ "$(wc -c < "$control/stderr")" -le 65536 ] || exit 73
cat -- "$control/stderr" >&2 || exit 73
[ "$status" -eq 0 ] || exit "$status"
printf "RCH_TOPOLOGY_OK\n" | cmp -s - "$control/stdout" || exit 73
cat -- "$control/stdout"
' rch-namespace-delivery "$control"
