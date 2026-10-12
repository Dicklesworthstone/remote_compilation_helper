set -eu
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
            held.append((fd, path, identity))
            mode = fcntl.LOCK_EX if record[:1] == b"x" else fcntl.LOCK_SH
            while True:
                requester_open()
                try:
                    fcntl.flock(fd, mode | fcntl.LOCK_NB)
                    break
                except OSError as error:
                    if error.errno not in (errno.EACCES, errno.EAGAIN):
                        raise
                    # A blocking flock cannot notice requester EOF, and may
                    # hold earlier roots forever when SIGHUP is ignored.
                    # Only contention waits; uncontended plans do not sleep.
                    requester_open(50)
            verify_lock_path(path, identity)
            # Python defaults new descriptors to close-on-exec. Inheritance
            # is essential: the terminal protocol, not this bootstrap, owns
            # the locks until its final exit. Never reuse fd 3 or fd 4.
            os.set_inheritable(fd, True)
        if plan.read(1):
            raise ValueError("source lock count does not match the plan")
    # An earlier pathname may change while a later lock is contended. Match
    # EVERY retained descriptor to its current regular pathname at handoff,
    # not merely when each lock was acquired. No path is recreated here.
    for _, path, identity in held:
        verify_lock_path(path, identity)
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
    paths+=("$lock")
    descriptors+=("$lock_fd")
    [[ -f /dev/fd/"$lock_fd" && ! -L "$lock" && "$lock" -ef /dev/fd/"$lock_fd" ]] || refuse "source lock path changed during open"
    while :; do
        requester_open
        if flock "$mode" -w 0.05 -E 75 "$lock_fd"; then
            break
        else
            result=$?
            [[ "$result" -eq 75 ]] || refuse "flock failed without a contention verdict"
        fi
    done
done
if IFS= read -r extra <&3 || [[ -n "$extra" ]]; then
    refuse "source lock count does not match the plan"
fi
exec 3<&-
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
