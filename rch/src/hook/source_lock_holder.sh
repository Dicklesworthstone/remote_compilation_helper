set -eu
# Probe the platform once, not once per root in the exec-only GNU chain.
# The internal marker selects the existing GNU path; it grants no lock rights.
portable=no
if [ "${1-}" = --rch-gnu-holder ]; then
    shift
elif [ "$(uname -s)" = Darwin ]; then
    portable=yes
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
    # Darwin flock implementations need not provide GNU --no-fork. Acquire
    # native flock(2) locks in ONE process instead; do not replace them with
    # process-associated POSIX record locks or a shell/flock process per root.
    # Python is only a bootstrap: exec preserves PID and every acquired FD.
    # fd 3 is the plan, fd 4 (when present) is the durable claim input, and
    # stdin remains untouched for the release/disconnect protocol.
    command -v python3 >/dev/null 2>&1 || {
        printf '%s\n' 'RCH: Darwin source locking requires python3 with fcntl; no source grant acquired' >&2
        exit 73
    }
    exec python3 -I -c '
import fcntl
import os
import signal
import stat
import sys

try:
    count = int(sys.argv[1])
    ready = os.fsencode(sys.argv[2])
    if count < 1 or not ready or len(ready) >= 4096 or any(c in ready for c in (0, 10, 13)):
        raise ValueError("invalid source lock count or ready marker")
    held = []
    seen = set()
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
            fd = os.open(path, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_NONBLOCK, 0o600)
            held.append(fd)
            before = os.fstat(fd)
            if not stat.S_ISREG(before.st_mode):
                raise ValueError("source lock is not a regular file")
            fcntl.flock(fd, fcntl.LOCK_EX if record[:1] == b"x" else fcntl.LOCK_SH)
            after = os.stat(path, follow_symlinks=False)
            if not stat.S_ISREG(after.st_mode) or (before.st_dev, before.st_ino) != (after.st_dev, after.st_ino):
                raise ValueError("source lock path changed during acquisition")
            # Python defaults new descriptors to close-on-exec. Inheritance
            # is essential: the terminal protocol, not this bootstrap, owns
            # the locks until its final exit. Never reuse fd 3 or fd 4.
            os.set_inheritable(fd, True)
        if plan.read(1):
            raise ValueError("source lock count does not match the plan")
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
IFS= read -r record <&3 || exit 73
case "$record" in
    'x /'*) mode=-x ;;
    's /'*) mode=-s ;;
    *) exit 73 ;;
esac
lock=${record#??}
exec flock "$mode" --no-fork -- "$lock" sh -c "$0" "$0" --rch-gnu-holder "$((remaining - 1))" "$@"
