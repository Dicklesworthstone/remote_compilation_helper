# Fixed command argument; the namespace program stays on stdin. This is only
# namespace setup or finite source-ownership metadata, never a build workload.
# Every result requires settled descendant teardown, including empty replies.
set -eu
rch_control_ready=${1:-RCH_TOPOLOGY_OK}
rch_control_alternate=
rch_control_format='%s\n'
case "$rch_control_ready" in
    RCH_TOPOLOGY_OK|RCH_SOURCE_CANCELLATION_SETTLED) ;;
    RCH_SOURCE_AUTHORITY_NAMESPACE)
        rch_control_ready='RCH_SOURCE_AUTHORITY_NAMESPACE current'
        rch_control_alternate='RCH_SOURCE_AUTHORITY_NAMESPACE legacy' ;;
    RCH_SOURCE_INTENT_CANCEL)
        rch_control_ready=owned; rch_control_alternate=unowned; rch_control_format='%s' ;;
    RCH_SOURCE_INTENT_RELEASED)
        rch_control_ready=released; rch_control_alternate=pending; rch_control_format='%s' ;;
    RCH_SOURCE_INTENT_CANCELLED)
        rch_control_ready=cancelled; rch_control_alternate=pending; rch_control_format='%s' ;;
    RCH_SOURCE_INTENT_FINISHED)
        rch_control_ready=; rch_control_format='%s' ;;
    *) printf '%s\n' 'RCH: invalid metadata control result marker' >&2; exit 73 ;;
esac
# Native fallback for workers without GNU coreutils (including stock macOS).
# This implements only the fixed timer ABI below, not arbitrary timeout flags.
# The timer itself leads a new session/group and stays alive through escalation:
# its own membership, never a remembered/reaped child PID, authorizes killpg.
# fork/exec avoids Popen's synchronous exec-error pipe becoming an unbounded
# wait when launching a helper from a stalled filesystem. stdin and inherited
# authority descriptors pass through unchanged; no namespace bytes are read here.
# Call only in a substitution, background job or explicit subshell. exec must
# replace that shell so its caller observes the timer itself, not a shell that
# prints an extra "Killed" diagnostic while relaying the timer status.
rch_namespace_python_timer_program='
import os
import signal
import sys
import time

child = None
group = None
interrupted = 0

def interrupt(signum, _frame):
    global interrupted
    if not interrupted:
        interrupted = signum

def kill_owned_group():
    # This process never changes groups after setsid. Killing ourselves as
    # part of the group is intentional and yields the same 137 receipt as GNU.
    os.killpg(group, signal.SIGKILL)
    os._exit(73)

try:
    if (len(sys.argv) < 4 or sys.argv[1] != "--kill-after=1"
            or sys.argv[2] not in ("1", "2", "15")
            or sys.platform not in ("linux", "darwin")):
        os._exit(73)
    os.setsid()
    group = os.getpid()
    if os.getpgrp() != group:
        os._exit(73)
    for signum in (signal.SIGHUP, signal.SIGINT, signal.SIGTERM):
        signal.signal(signum, interrupt)
    signal.signal(signal.SIGCHLD, signal.SIG_DFL)
    # Ignore SIGPIPE only in the timer. A delivery helper still sees the
    # default disposition; a broken reader cannot strand the timer itself.
    signal.signal(signal.SIGPIPE, signal.SIG_IGN)
    deadline = time.monotonic() + int(sys.argv[2])
    child = os.fork()
    if child == 0:
        for signum in (signal.SIGHUP, signal.SIGINT, signal.SIGTERM, signal.SIGPIPE):
            signal.signal(signum, signal.SIG_DFL)
        try:
            os.execvp(sys.argv[3], sys.argv[3:])
        except OSError:
            os._exit(127)
    terminating = False
    while True:
        now = time.monotonic()
        if not terminating and (interrupted or now >= deadline):
            terminating = True
            deadline = now + 1
            # Our handler catches this too. Never exit on the direct child
            # after this boundary: TERM-resistant descendants need the KILL.
            os.killpg(group, interrupted or signal.SIGTERM)
        if terminating:
            if now >= deadline:
                kill_owned_group()
        else:
            waited, status = os.waitpid(child, os.WNOHANG)
            if waited:
                child = None
                if os.WIFEXITED(status):
                    os._exit(os.WEXITSTATUS(status))
                if os.WIFSIGNALED(status):
                    os._exit(128 + os.WTERMSIG(status))
                os._exit(73)
        time.sleep(min(0.02, max(0, deadline - time.monotonic())))
except BaseException:
    # A failed timer must not leave an already-started initializer behind.
    # Do not print to potentially blocked SSH pipes on this cleanup path.
    if child is not None and child != 0 and group is not None:
        kill_owned_group()
    os._exit(73)
'
rch_namespace_python_timer() {
    exec python3 -I -S -c "$rch_namespace_python_timer_program" "$@"
}
# A timer can itself be stopped or killed before its deadline. Observe its
# direct child without reaping it, then drain the still-owned group. A shell
# wait reaps too early: the timer can disappear while descendants keep the
# metadata mutex, and its remembered numeric PID is no longer kill authority.
# Both real timer backends establish a private group before starting helpers.
# The observer stays outside that group and never reads the uploaded program.
rch_namespace_observed_timer() {
    rch_timer_observation=$1
    shift
    case "$rch_timer_observation" in status|teardown) ;; *) exit 73 ;; esac
    case "$rch_namespace_timer" in
        rch_namespace_python_timer)
            set -- python3 -I -S -c "$rch_namespace_python_timer_program" "$@" ;;
        *) set -- "$rch_namespace_timer" "$@" ;;
    esac
    exec python3 -I -S -c '
import os
import signal
import sys

try:
    if not hasattr(signal, "pthread_sigmask") or not hasattr(signal, "sigwait"):
        raise ValueError("non-reaping child notification is unavailable")
    # Darwin can discard default-ignored SIGCHLD before sigwait sees it.
    # Catch explicitly, while blocked, and clear inherited auto-reap behavior.
    original_mask = signal.pthread_sigmask(signal.SIG_BLOCK, {signal.SIGCHLD})
    signal.signal(signal.SIGCHLD, lambda _signum, _frame: None)
    timer = os.fork()
except (OSError, ValueError) as error:
    try:
        os.set_blocking(2, False)
        os.write(2, ("RCH_SOURCE_NAMESPACE_OBSERVER_UNAVAILABLE " + str(error) + "\n").encode())
    except OSError:
        pass
    sys.exit(73)

if timer == 0:
    signal.signal(signal.SIGCHLD, signal.SIG_DFL)
    # Only the observer blocks child notifications. An inherited blocked
    # SIGCHLD must not leak into the timer or shells waiting on descendants.
    signal.pthread_sigmask(signal.SIG_SETMASK, original_mask - {signal.SIGCHLD})
    try:
        os.execvp(sys.argv[2], sys.argv[2:])
    except OSError:
        os._exit(127)

os.close(0)
failed = False
try:
    # Stop/continue and explicit notifications revoke this session too. They
    # are never treated as proof that a timer completed or a result is valid.
    signal.sigwait({signal.SIGCHLD})
except BaseException:
    failed = True
finally:
    # Kill the exact unreaped timer FIRST, including before group setup. Then
    # kill its group without a racy getpgid check. Fork guaranteed this PID
    # did not name an existing group, and non-reaping keeps it from reuse.
    try:
        os.kill(timer, signal.SIGKILL)
    except ProcessLookupError:
        pass
    try:
        os.killpg(timer, signal.SIGKILL)
    except ProcessLookupError:
        pass
    _, status = os.waitpid(timer, 0)

if not failed and sys.argv[1] == "teardown":
    # Zero is this observer acknowledging an actually killed and reaped
    # timer group. Observer SIGKILL must not mimic that acknowledgement:
    # its shell status is 137 even if a result was already written.
    # An ordinary timer exit(137) is not a group-teardown receipt either.
    if os.WIFSIGNALED(status) and os.WTERMSIG(status) == signal.SIGKILL:
        sys.exit(0)
    sys.exit(73)
if not failed:
    if os.WIFEXITED(status):
        sys.exit(os.WEXITSTATUS(status))
    if os.WIFSIGNALED(status):
        sys.exit(128 + os.WTERMSIG(status))
sys.exit(73)
' "$rch_timer_observation" "$@"
}
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
elif command -v python3 >/dev/null 2>&1; then
    rch_namespace_timer=rch_namespace_python_timer
else
    printf '%s\n' 'RCH: namespace setup requires GNU timeout (gnutimeout or gtimeout) or Python 3' >&2
    exit 73
fi
# The registry already requires Python for exact file/directory durability.
# GNU remains the timer when available; Python supplies portable non-reaping
# observation for both backends, including macOS Python before waitid existed.
command -v python3 >/dev/null 2>&1 || {
    printf '%s\n' 'RCH_SOURCE_NAMESPACE_OBSERVER_UNAVAILABLE Python 3 is required' >&2
    exit 73
}
umask 077
# The receipt directory belongs to the observer, OUTSIDE the execution group.
# Bound creation too: a blocked filesystem must not start an unobserved program.
control=$(rch_namespace_observed_timer status --kill-after=1 1 mktemp -d \
    "${TMPDIR:-/tmp}/rch-namespace-control.XXXXXXXXXX") || exit 73
cleanup() {
    # Fixed names in our private directory, never source/claim/recovery paths.
    # Cleanup is best effort and bounded; it cannot change the delivery result.
    (rch_namespace_observed_timer status --kill-after=1 1 sh -c '
        rm -f -- "$1/stdout.pipe" "$1/stderr.pipe" "$1/stdout" \
            "$1/stderr" "$1/result"
        rmdir -- "$1"
    ' rch-namespace-cleanup "$control") >/dev/null 2>&1 || :
}
trap cleanup 0
# Save the upload before starting a background command. POSIX shells otherwise
# substitute /dev/null for its stdin. The observer never consumes program bytes.
exec 3<&0
# Both timer backends create a private process group. Do NOT use --foreground. The
# monitor's terminal action kills that exact, still-owned group (including the
# timer and itself); no remembered PID or process-table scan authorizes a kill.
# EOF is insufficient: a grandchild can close both pipes and retain a mutex or
# continue mutating the namespace after its parent exits. Always tear down the
# execution group, on success as well as failure, before forwarding readiness.
rch_namespace_observed_timer teardown --kill-after=1 15 sh -c '
set -eu
control=$1
observer=$2
ready=$3
alternate=$4
reply_format=$5
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
if [ "$status" -ge 128 ]; then
    printf "RCH_SOURCE_NAMESPACE_PROCESS_TERMINATED status=%s signal=%s signal_origin=unknown\n" \
        "$status" "$((status - 128))" >&2
fi
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
if ! printf "$reply_format" "$ready" | cmp -s - "$control/stdout"; then
    [ -n "$alternate" ] && printf "$reply_format" "$alternate" | cmp -s - "$control/stdout" || {
        printf "%s\n" "RCH: namespace control returned invalid readiness" >&2
        exit 73
    }
fi
finish 0
' rch-namespace-monitor "$control" "$$" "$rch_control_ready" "$rch_control_alternate" "$rch_control_format" <&3 3<&- &
monitor=$!
exec 3<&-
set +e
# Suppress the shell's diagnostic for the deliberate group kill, not the
# program's captured stderr or the monitor's validation diagnostics.
wait "$monitor" 2>/dev/null
monitor_status=$?
set -e
# Only the observer can acknowledge that its actual timer was killed, the
# pinned group signalled, and the timer reaped. An externally killed observer
# returns 137 instead of zero, even if the inner monitor already wrote a result.
# A missing/partial result still cannot authorize successful publication.
[ "$monitor_status" -eq 0 ] && [ -f "$control/result" ] || {
    printf 'RCH_SOURCE_NAMESPACE_CONTROL_UNSETTLED status=%s cause=deadline-or-external-interruption\n' \
        "$monitor_status" >&2
    printf '%s\n' 'RCH: namespace control ended without settled group teardown' >&2
    exit 73
}
# Delivery has its own deadline, too. A stalled SSH reader must not leave the
# observer or its pipe writers alive. This group has no namespace mutators.
rch_namespace_observed_timer status --kill-after=1 2 sh -c '
set -eu
# Keep the timer alive until group KILL even when a pipe writer ignores TERM.
# Otherwise GNU timeout can reap this shell while that descendant is blocked.
trap "while :; do sleep 1; done" HUP INT TERM PIPE
control=$1
ready=$2
alternate=$3
reply_format=$4
IFS= read -r status < "$control/result" || exit 73
case "$status" in ""|*[!0-9]*) exit 73 ;; esac
[ "${#status}" -le 3 ] && [ "$status" -le 255 ] || exit 73
printf "%s\n" "$status" | cmp -s - "$control/result" || exit 73
# Check the retained bytes again before releasing any readiness to the caller.
[ "$(wc -c < "$control/stdout")" -le 4096 ] || exit 73
[ "$(wc -c < "$control/stderr")" -le 65536 ] || exit 73
cat -- "$control/stderr" >&2 || exit 73
[ "$status" -eq 0 ] || exit "$status"
if ! printf "$reply_format" "$ready" | cmp -s - "$control/stdout"; then
    [ -n "$alternate" ] && printf "$reply_format" "$alternate" | cmp -s - "$control/stdout" || exit 73
fi
cat -- "$control/stdout"
' rch-namespace-delivery "$control" "$rch_control_ready" "$rch_control_alternate" "$rch_control_format" </dev/null &
delivery=$!
set +e
# A foreground timer killed during delivery makes the observer shell print
# "Killed" to the same full stderr pipe, defeating the delivery deadline.
# Keep payload streams unchanged and silence only the observer's wait notice.
wait "$delivery" 2>/dev/null
delivery_status=$?
set -e
exit "$delivery_status"
