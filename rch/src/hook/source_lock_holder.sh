set -eu
# A source holder is a control session, never the compiler or rsync session.
# Keep its liveness independent of sshd/kernel TCP keepalive. The supervisor
# owns a private group from before lock acquisition through final teardown;
# expiry cannot touch a separately launched source activity and never edits a
# claim, cancellation marker, pair owner or receipt. Those durable records,
# plus the activity mutex, remain the authority for recovery after expiry.
if [ "${1-}" = --rch-session ]; then
    command -v python3 >/dev/null 2>&1 || {
        printf '%s\n' 'RCH_SOURCE_LOCK_LIVENESS_UNAVAILABLE: Python 3 is required; no source locks acquired' >&2
        exit 73
    }
    exec python3 -I -S -c '
import os
import select
import signal
import sys
import time

HEARTBEAT = b"RCH_SOURCE_LOCK_HEARTBEAT\n"
MAX_FRAME = 4096
MAX_PROGRAM = 32 * 1024 * 1024

def diagnostic(message):
    # Diagnostics must not prevent teardown when the SSH reader is gone or
    # its pipe is full. Called only on fatal paths, immediately before exit.
    try:
        os.set_blocking(2, False)
        os.write(2, (message + "\n").encode())
    except OSError:
        pass

try:
    idle = int(sys.argv[1])
    if len(sys.argv) != 2 or not 1 <= idle <= 3600:
        raise ValueError("invalid heartbeat deadline")
    if not hasattr(os, "waitid") or not hasattr(os, "WNOWAIT"):
        raise ValueError("non-reaping child observation is unavailable")
    with os.fdopen(3, "rb", closefd=True) as source:
        program = source.read(MAX_PROGRAM + 1)
    if not program or len(program) > MAX_PROGRAM or b"\x00" in program:
        raise ValueError("invalid bounded holder program")
    signal.signal(signal.SIGCHLD, signal.SIG_DFL)
    receipt_read, receipt_write = os.pipe()
    monitor = os.fork()
except (OSError, ValueError, IndexError) as error:
    diagnostic("RCH_SOURCE_LOCK_LIVENESS_UNAVAILABLE: " + str(error))
    sys.exit(73)

if monitor:
    # Fork before setsid: an ssh login shell can itself be a session leader.
    # This observer owns no source descriptors. Keep its direct child unreaped
    # while tearing down the group, including when the monitor itself is killed
    # externally. A zombie child pins its PID; no saved/reused PID is authority.
    os.close(receipt_write)
    os.close(0)
    os.waitid(os.P_PID, monitor, os.WEXITED | os.WNOWAIT)
    if os.getpgid(monitor) == monitor:
        try:
            os.killpg(monitor, signal.SIGKILL)
        except ProcessLookupError:
            pass
    _, status = os.waitpid(monitor, 0)
    receipt = os.read(receipt_read, 32)
    os.close(receipt_read)
    if (os.WIFSIGNALED(status) and os.WTERMSIG(status) == signal.SIGKILL
            and receipt.endswith(b"\n") and receipt[:-1].isdigit()
            and 0 <= int(receipt) <= 255):
        sys.exit(int(receipt))
    diagnostic("RCH_SOURCE_LOCK_SUPERVISOR_TERMINATED: no holder completion receipt; "
               + "durable ownership retained; status=" + str(status))
    sys.exit(73)

os.close(receipt_read)
group = None
interrupted = 0

def interrupt(signum, _frame):
    global interrupted
    if not interrupted:
        interrupted = signum

def finish(status, message=None):
    if message:
        diagnostic(message)
    # Our own live membership pins this group identity until SIGKILL. Never
    # reap a group leader and subsequently signal its possibly reused PID.
    if group != os.getpid() or os.getpgrp() != group:
        os._exit(73)
    try:
        os.write(receipt_write, (str(status) + "\n").encode())
        os.close(receipt_write)
    finally:
        # The observer may already have died with its SSH session. A broken
        # receipt pipe must never bypass teardown or strand inherited locks.
        os.killpg(group, signal.SIGKILL)
        os._exit(73)

try:
    os.setsid()
    group = os.getpid()
    if os.getpgrp() != group:
        raise ValueError("holder monitor has no private process group")
    for signum in (signal.SIGHUP, signal.SIGINT, signal.SIGTERM):
        signal.signal(signum, interrupt)
    signal.signal(signal.SIGCHLD, signal.SIG_DFL)
    signal.signal(signal.SIGPIPE, signal.SIG_IGN)
    child_read, child_write = os.pipe()
    child = os.fork()
    if child == 0:
        os.close(receipt_write)
        os.close(child_write)
        os.dup2(child_read, 0)
        os.close(child_read)
        for signum in (signal.SIGHUP, signal.SIGINT, signal.SIGTERM, signal.SIGPIPE):
            signal.signal(signum, signal.SIG_DFL)
        try:
            os.execvp("sh", ["sh", "-s"])
        except OSError:
            os._exit(127)
    os.close(child_read)
    os.set_blocking(child_write, False)
    os.set_blocking(0, False)
    # The full compound program is parsed before any release-stream reader.
    # The closure remains stdin data; it is never moved into a size-limited
    # exec argument. At most this bounded bootstrap and one frame are queued.
    pending = b"{\n" + program + b"\n}\n"
    buffered = b""
    released = False
    input_open = True
    deadline = time.monotonic() + idle
    while True:
        now = time.monotonic()
        if interrupted:
            finish(73, "RCH_SOURCE_LOCK_INTERRUPTED: signal=" + str(interrupted)
                   + "; durable ownership retained")
        if now >= deadline:
            reason = "RELEASE_TIMEOUT" if released else "HEARTBEAT_EXPIRED"
            finish(73, "RCH_SOURCE_LOCK_" + reason
                   + ": durable ownership retained; idle_seconds=" + str(idle))
        waited, status = os.waitpid(child, os.WNOHANG)
        if waited:
            if os.WIFEXITED(status):
                finish(os.WEXITSTATUS(status))
            if os.WIFSIGNALED(status):
                signum = os.WTERMSIG(status)
                finish(128 + signum, "RCH_SOURCE_LOCK_PROCESS_TERMINATED: signal="
                       + str(signum) + "; durable ownership retained")
            finish(73, "RCH_SOURCE_LOCK_PROCESS_TERMINATED: unknown child status")
        readable, writable, _ = select.select(
            [0] if input_open else [],
            [child_write] if child_write is not None and pending else [],
            [], min(0.05, max(0, deadline - now)))
        if readable:
            data = os.read(0, MAX_FRAME + 1 - len(buffered))
            if not data:
                if not released or buffered:
                    finish(73, "RCH_SOURCE_LOCK_DISCONNECTED: no complete release; durable ownership retained")
                input_open = False
            else:
                buffered += data
                while b"\n" in buffered:
                    frame, buffered = buffered.split(b"\n", 1)
                    frame += b"\n"
                    if released:
                        finish(73, "RCH_SOURCE_LOCK_PROTOCOL_ERROR: input after release")
                    if frame == HEARTBEAT:
                        # Partial or unknown input never refreshes liveness.
                        deadline = time.monotonic() + idle
                        continue
                    prefix, separator, token = frame[:-1].partition(b":")
                    if (separator != b":" or prefix not in
                            (b"RCH_SOURCE_AUTHORITY_RELEASE", b"RCH_SOURCE_PAIR_RELEASE")
                            or not 1 <= len(token) <= 128
                            or any(c not in b"0123456789abcdef-" for c in token)):
                        finish(73, "RCH_SOURCE_LOCK_PROTOCOL_ERROR: invalid release frame")
                    pending += frame
                    released = True
                    deadline = time.monotonic() + 15
                if len(buffered) >= MAX_FRAME:
                    finish(73, "RCH_SOURCE_LOCK_PROTOCOL_ERROR: frame exceeded byte bound")
        if writable:
            try:
                written = os.write(child_write, pending[:65536])
                pending = pending[written:]
            except BlockingIOError:
                pass
            except BrokenPipeError:
                os.close(child_write)
                child_write = None
        if released and not pending and child_write is not None:
            os.close(child_write)
            child_write = None
except BaseException as error:
    if group is not None:
        finish(73, "RCH_SOURCE_LOCK_LIVENESS_FAILED: " + str(error)
               + "; durable ownership retained")
    os._exit(73)
' "${2-}"
fi
# Probe the platform once. The internal marker pins the minimal GNU fallback
# rather than recursively selecting a backend; it grants no lock rights.
portable=no
gnu_cancellable=no
if [ "${1-}" = --rch-gnu-holder ]; then
    shift
else
    platform=$(uname -s)
    case "$platform" in
        Darwin) portable=yes ;;
        Linux)
            # Large closures otherwise exec flock AND sh once per lock. Reuse
            # the native single-process holder when Python is available. Keep
            # small plans on GNU: interpreter startup dominates their cost.
            # The recursive marker above pins the backend for the whole plan.
            if [ "${1-0}" -ge 32 ] && command -v python3 >/dev/null 2>&1; then
                portable=yes
            elif command -v bash >/dev/null 2>&1; then
                gnu_cancellable=yes
            fi
            ;;
    esac
fi
remaining=$1
shift
if [ "$remaining" -eq 0 ]; then
    exec 3<&-
    ready=$1
    shift
    if [ "$#" -gt 0 ]; then
        terminal=$1
        shift
        exec sh -c "$terminal" "$terminal" "$ready" "$@"
    fi
    printf '%s\n' "$ready"
    exec cat >/dev/null
fi
if [ "$portable" = yes ]; then
    # Darwin requires this backend; Linux large closures use it to avoid the
    # per-root exec chain. Acquire native flock(2) locks in ONE process; never
    # retry a failed native acquisition through GNU or replace these locks with
    # process-associated POSIX record locks or a shell/flock process per root.
    # Python is only a bootstrap: exec preserves PID and every acquired FD.
    # fd 3 is the plan, fd 4 (when present) is the durable claim input, and
    # stdin remains untouched for the release/disconnect protocol.
    command -v python3 >/dev/null 2>&1 || {
        printf 'RCH: %s source locking requires python3 with fcntl; no source grant acquired\n' "$platform" >&2
        exit 73
    }
    exec python3 -I -c '
import errno
import fcntl
import os
import select
import signal
import stat
import sys

try:
    count = int(sys.argv[1])
    ready = os.fsencode(sys.argv[2])
    if count < 1 or not ready or len(ready) >= 4096 or any(c in ready for c in (0, 10, 13)):
        raise ValueError("invalid source lock count or ready marker")
    # The requester sends no stdin bytes until the terminal announces ready.
    # Observe, never consume, stdin so the terminal still owns its exact
    # release protocol. EOF/early input before handoff grants nothing. Once
    # exec begins, the existing durable claim/cancellation protocol remains
    # authoritative, including a disconnect racing that final boundary.
    requester = select.poll()
    requester.register(0, select.POLLIN | select.POLLHUP | select.POLLERR)

    def requester_open(wait_ms=0):
        if requester.poll(wait_ms):
            raise ValueError("source lock requester ended or sent input before readiness")

    def verify_lock_path(path, identity):
        current = os.stat(path, follow_symlinks=False)
        if not stat.S_ISREG(current.st_mode) or identity != (current.st_dev, current.st_ino):
            raise ValueError("source lock path changed during acquisition")

    held = []
    seen = set()
    inodes = set()
    with os.fdopen(3, "rb", closefd=True) as plan:
        for _ in range(count):
            record = plan.readline(1024 * 1024 + 1)
            if (len(record) > 1024 * 1024 or not record.endswith(b"\n")
                    or record[:3] not in (b"x /", b"s /")
                    or b"\x00" in record or b"\r" in record):
                raise ValueError("invalid or incomplete source lock plan")
            path = record[2:-1]
            if path in seen:
                raise ValueError("duplicate source lock path")
            seen.add(path)
            # Preserve the canonical-root order supplied by Rust. Sorting the
            # hashed lock names here would deadlock against existing holders.
            requester_open()
            fd = os.open(path, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_NONBLOCK, 0o600)
            before = os.fstat(fd)
            if not stat.S_ISREG(before.st_mode):
                raise ValueError("source lock is not a regular file")
            identity = (before.st_dev, before.st_ino)
            # flock locks an open file description, not this process. Two
            # different names for one inode can self-deadlock through distinct
            # descriptors, or alias two supposedly independent shared roots.
            # Reject, never coalesce or upgrade, an ambiguous physical plan.
            if identity in inodes:
                raise ValueError("duplicate source lock inode")
            inodes.add(identity)
            mode = fcntl.LOCK_EX if record[:1] == b"x" else fcntl.LOCK_SH
            held.append((fd, path, identity, mode))
            verify_lock_path(path, identity)
        if plan.read(1):
            raise ValueError("source lock count does not match the plan")
    # Admission needs the whole closure, not a reserved prefix. A build
    # blocked on one busy dependency must not monopolize other source roots
    # throughout that build. Try in the supplied order; on contention release
    # EVERY acquired lock before waiting. No source access or ready marker is
    # allowed until the complete set is held. Existing blocking holders still
    # use the same inodes and lock modes, so mutual exclusion is unchanged.
    while True:
        acquired = []
        for fd, path, identity, mode in held:
            requester_open()
            verify_lock_path(path, identity)
            try:
                fcntl.flock(fd, mode | fcntl.LOCK_NB)
                acquired.append(fd)
            except OSError as error:
                if error.errno not in (errno.EACCES, errno.EAGAIN):
                    raise
                break
        else:
            break
        for fd in reversed(acquired):
            fcntl.flock(fd, fcntl.LOCK_UN)
        # Observe requester EOF/early input without consuming terminal input.
        # Only contention waits; the uncontended path does not sleep.
        requester_open(50)
    # An earlier pathname may change while a later lock is contended. Match
    # EVERY retained descriptor to its current regular pathname at handoff,
    # not merely when each lock was acquired. No path is recreated here.
    for fd, path, identity, _ in held:
        verify_lock_path(path, identity)
        # The terminal owns every lock until final exit. Python defaults new
        # descriptors to close-on-exec; transfer them only after full admission.
        os.set_inheritable(fd, True)
    requester_open()
    # Python ignores SIGPIPE by default; do not pass that policy to the
    # existing terminal shell. A lost reply must still terminate the holder.
    signal.signal(signal.SIGPIPE, signal.SIG_DFL)
    if len(sys.argv) > 3:
        terminal = sys.argv[3]
        os.execvp("sh", ["sh", "-c", terminal, terminal] + sys.argv[2:3] + sys.argv[4:])
    os.write(1, ready + b"\n")
    null = os.open(os.devnull, os.O_WRONLY)
    os.dup2(null, 1)
    os.close(null)
    os.execvp("cat", ["cat"])
except (OSError, ValueError, IndexError) as error:
    print("RCH: native source lock acquisition failed: {}".format(error), file=sys.stderr)
    sys.exit(73)
' "$remaining" "$@"
fi
if [ "$gnu_cancellable" = yes ]; then
    # Keep the GNU backend for small plans and workers without Python, but
    # own its descriptors in ONE shell instead of blocking in an exec chain.
    # flock(1) locks the inherited open file description, so its successful
    # exit does not release the parent's descriptor. A bounded contention
    # wait lets that parent notice requester EOF without a watchdog, signals,
    # PID races or a live process per root. Never retry tool errors.
    # -p ignores BASH_ENV, imported functions and inherited shell options;
    # this bootstrap must not execute a worker's interactive startup hooks.
    exec bash --noprofile --norc -p -c '
set -eu
holder_script=$1
shift
if (( BASH_VERSINFO[0] < 4 || (BASH_VERSINFO[0] == 4 && BASH_VERSINFO[1] < 1) )); then
    # Dynamic descriptors require Bash 4.1. Older/minimal workers retain
    # their existing GNU implementation; no new prerequisite is imposed.
    exec sh -c "$holder_script" "$holder_script" --rch-gnu-holder "$@"
fi
unset holder_script
refuse() {
    printf "RCH: GNU source lock acquisition failed: %s\n" "$1" >&2
    exit 73
}
requester_open() {
    # read -t 0 only tests readiness; it consumes NO bytes, including NUL.
    # A closed descriptor is not evidence of an idle, connected requester.
    [[ -e /dev/fd/0 ]] || refuse "source lock requester descriptor is unavailable"
    if IFS= read -r -t 0; then
        refuse "source lock requester ended or sent input before readiness"
    fi
}
requester_open
count=$1
ready=$2
shift 2
saved_lc_all=${LC_ALL-}
saved_lc_set=${LC_ALL+x}
export LC_ALL=C
newline="
"
cr=$(printf "\r")
case "$count" in ""|*[!0-9]*) refuse "invalid source lock count" ;; esac
[[ ${#count} -le 8 ]] || refuse "invalid source lock count"
count=$((10#$count))
[[ "$count" -gt 0 && -n "$ready" && ${#ready} -lt 4096 &&
   "$ready" != *"$newline"* && "$ready" != *"$cr"* ]] || refuse "invalid count or ready marker"
# Bound and NUL-check the data before line-oriented shell reads (which would
# otherwise discard NUL). fd 3 is already a complete caller-owned plan, not
# the release stream. Keep the final newline and require exact record count.
# Reopen only fd 3; fd 4 and every existing authority descriptor are untouched.
if IFS= read -r -d "" -n 33554433 plan <&3; then
    refuse "source lock plan contains NUL or exceeds the byte bound"
fi
[[ ${#plan} -le 33554432 && "$plan" == *"$newline" ]] || refuse "incomplete source lock plan"
exec 3<<<"${plan%$newline}"
unset plan
declare -A seen=()
paths=()
descriptors=()
modes=()
for ((i = 0; i < count; i++)); do
    IFS= read -r record <&3 || refuse "incomplete source lock plan"
    [[ ${#record} -lt 1048576 && "$record" != *"$cr"* ]] || refuse "invalid source lock record"
    case "$record" in
        "x /"*) mode=-x ;;
        "s /"*) mode=-s ;;
        *) refuse "invalid source lock record" ;;
    esac
    lock=${record:2}
    [[ ! ${seen["$lock"]+present} ]] || refuse "duplicate source lock path"
    seen["$lock"]=1
    requester_open
    [[ ! -L "$lock" && ( ! -e "$lock" || -f "$lock" ) ]] || refuse "source lock is not a regular file"
    if ! exec {lock_fd}<>"$lock"; then
        refuse "cannot open source lock descriptor"
    fi
    [[ -f /dev/fd/"$lock_fd" && ! -L "$lock" && "$lock" -ef /dev/fd/"$lock_fd" ]] || refuse "source lock path changed during open"
    # Compare retained descriptors, not pathnames that may have moved. Distinct
    # opens of one inode can self-deadlock or alias supposedly disjoint roots.
    # Reject every mode combination, including two shared locks, before flock.
    for ((j = 0; j < i; j++)); do
        [[ ! /dev/fd/"$lock_fd" -ef /dev/fd/"${descriptors[j]}" ]] || refuse "duplicate source lock inode"
    done
    paths+=("$lock")
    descriptors+=("$lock_fd")
    modes+=("$mode")
done
if IFS= read -r extra <&3 || [[ -n "$extra" ]]; then
    refuse "source lock count does not match the plan"
fi
exec 3<&-
# Like the native backend, validate the complete plan before acquiring any
# lock, and never wait while reserving only a prefix of the source closure.
# Keep the supplied order and the existing flock inodes/modes for mixed fleets.
while :; do
    for ((i = 0; i < count; i++)); do
        requester_open
        lock=${paths[i]}
        lock_fd=${descriptors[i]}
        [[ ! -L "$lock" && -f "$lock" && "$lock" -ef /dev/fd/"$lock_fd" ]] || refuse "source lock path changed during acquisition"
        if flock "${modes[i]}" -n -E 75 "$lock_fd"; then
            :
        else
            result=$?
            [[ "$result" -eq 75 ]] || refuse "flock failed without a contention verdict"
            break
        fi
    done
    [[ "$i" -lt "$count" ]] || break
    for ((j = i - 1; j >= 0; j--)); do
        flock -u "${descriptors[j]}" || refuse "cannot release partial source closure"
    done
    requester_open
    # Wait briefly on ONLY the contested root with no prefix held. If it
    # becomes available, drop this out-of-order lock before retrying the whole
    # plan. flock supplies the wait; no sleep binary or input consumption is
    # needed on minimal workers. Only the explicit contention code may retry.
    if flock "${modes[i]}" -w 0.05 -E 75 "${descriptors[i]}"; then
        flock -u "${descriptors[i]}" || refuse "cannot release contention wait lock"
    else
        result=$?
        [[ "$result" -eq 75 ]] || refuse "flock failed without a contention verdict"
    fi
done
# Revalidate the ENTIRE set after the final wait. Replacing an earlier lock
# pathname while a later root is busy must never leave a grant on old inodes.
for ((i = 0; i < count; i++)); do
    lock=${paths[i]}
    lock_fd=${descriptors[i]}
    [[ ! -L "$lock" && -f "$lock" && "$lock" -ef /dev/fd/"$lock_fd" ]] || refuse "source lock path changed during acquisition"
done
requester_open
if [[ "$saved_lc_set" ]]; then
    export LC_ALL="$saved_lc_all"
else
    unset LC_ALL
fi
if [[ "$#" -gt 0 ]]; then
    terminal=$1
    shift
    exec sh -c "$terminal" "$terminal" "$ready" "$@"
fi
printf "%s\n" "$ready"
exec cat >/dev/null
' rch-gnu-source-holder "$0" "$remaining" "$@"
fi
IFS= read -r record <&3 || exit 73
case "$record" in
    'x /'*) mode=-x ;;
    's /'*) mode=-s ;;
    *) exit 73 ;;
esac
lock=${record#??}
exec flock "$mode" --no-fork -- "$lock" sh -c "$0" "$0" --rch-gnu-holder "$((remaining - 1))" "$@"
