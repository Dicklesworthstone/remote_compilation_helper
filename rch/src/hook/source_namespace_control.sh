# Fixed command argument; the namespace program stays on stdin. This is only
# namespace setup or finite source-ownership metadata, never a build workload.
# Every result requires settled descendant teardown, including empty replies.
set -eu
# The client exports one validated timing policy to every fresh worker shell.
# Parse data, never shell arithmetic from the environment. Round upward to
# microseconds, then upward again only where timeout requires whole seconds.
rch_timing_micros=1000000
case "${RCH_TIMING_SCALE-1}" in
    1) ;;
    *)
        rch_timing_micros=$(LC_ALL=C awk '
            BEGIN {
                value = ENVIRON["RCH_TIMING_SCALE"]
                if (length(value) > 128 || value !~ /^[+-]?([0-9]+(\.[0-9]*)?|\.[0-9]+)([eE][+-]?[0-9]+)?$/) exit 1
                scale = value + 0
                if (!(scale >= 1 && scale <= 10)) exit 1
                units = int(scale * 1000000)
                if (units < scale * 1000000) units++
                printf "%.0f\n", units
            }
        ') || { printf "%s\n" "RCH: invalid RCH_TIMING_SCALE (expected finite 1..10)" >&2; exit 73; };;
esac
rch_timing_budget() {
    rch_timing_scaled=$((($1 * rch_timing_micros + 999999) / 1000000))
}
rch_control_ready=${1:-RCH_TOPOLOGY_OK}
rch_control_contract=$rch_control_ready
rch_control_alternate=
rch_control_third=
rch_control_format='%s\n'
case "$rch_control_ready" in
    RCH_TOPOLOGY_OK|RCH_SOURCE_CANCELLATION_SETTLED) ;;
    RCH_SOURCE_AUTHORITY_NAMESPACE)
        rch_control_ready='RCH_SOURCE_AUTHORITY_NAMESPACE current'
        rch_control_alternate='RCH_SOURCE_AUTHORITY_NAMESPACE legacy' ;;
    RCH_SOURCE_AUTHORITY_DISCOVERY)
        rch_control_ready='RCH_SOURCE_AUTHORITY_DISCOVERY current'
        rch_control_alternate='RCH_SOURCE_AUTHORITY_DISCOVERY legacy'
        rch_control_third='RCH_SOURCE_AUTHORITY_DISCOVERY absent' ;;
    RCH_SOURCE_INTENT_CANCEL)
        rch_control_ready=owned; rch_control_alternate=unowned; rch_control_format='%s' ;;
    RCH_SOURCE_INTENT_RELEASED)
        rch_control_ready=released; rch_control_alternate=pending; rch_control_format='%s' ;;
    RCH_SOURCE_INTENT_CANCELLED)
        rch_control_ready=cancelled; rch_control_alternate=pending; rch_control_format='%s' ;;
    RCH_SOURCE_INTENT_CANCELLATION_STATE)
        rch_control_ready=cancellation; rch_control_alternate=pending; rch_control_format='%s' ;;
    RCH_SOURCE_INTENT_FINISHED)
        rch_control_ready=; rch_control_format='%s' ;;
    *) printf '%s\n' 'RCH: invalid metadata control result marker' >&2; exit 73 ;;
esac
# Finite metadata must remain callable after a build fills the worker disk.
# Its transport owns no files: keep bounded replies in memory and leave all
# claim persistence/durability decisions to the uploaded registry transaction.
# Topology/bootstrap retains its existing controller below. Python already is
# required by metadata ownership and settlement, even on GNU-timeout workers.
if [ "$rch_control_contract" != RCH_TOPOLOGY_OK ]; then
    command -v python3 >/dev/null 2>&1 || {
        printf '%s\n' 'RCH_SOURCE_NAMESPACE_OBSERVER_UNAVAILABLE Python 3 is required' >&2
        exit 73
    }
    exec python3 -I -S -B -c '
import os
import select
import signal
import subprocess
import sys
import time

# The shell validated the transported finite scale before any child or file.
TIMING_SCALE = float(os.environ.get("RCH_TIMING_SCALE", "1"))
PROGRAM_DEADLINE = 15.0 * TIMING_SCALE
SETTLEMENT_DEADLINE = PROGRAM_DEADLINE + 1.0
DELIVERY_DEADLINE = 2.0 * TIMING_SCALE

# A guardian is the unreaped direct child and the private group leader. It
# stays alive after the program exits, independently enforcing the deadline
# and watching a pipe held ONLY by this observer. Observer death therefore
# cannot leave an unbounded lock waiter, even if all output pipes were closed.
# The guardian never passes its control/status descriptors to the program.
timer = None
changed = False
interrupted = 0

def child_changed(_signum, _frame):
    global changed
    changed = True

def interrupt(signum, _frame):
    global interrupted
    interrupted = interrupted or signum

def close(descriptor):
    try:
        os.close(descriptor)
    except OSError:
        pass

def guardian(owner, report, stdout, stderr, descriptors, started):
    owned = False
    try:
        os.setsid()
        owned = os.getpgrp() == os.getpid()
        if not owned:
            os._exit(73)
        for signum in (signal.SIGHUP, signal.SIGINT, signal.SIGTERM):
            signal.signal(signum, interrupt)
        signal.signal(signal.SIGCHLD, signal.SIG_DFL)
        signal.signal(signal.SIGPIPE, signal.SIG_IGN)
        for descriptor in descriptors:
            if descriptor not in (owner, report, stdout, stderr):
                close(descriptor)
        # Do not retain the SSH output pipes if its observer is killed.
        close(1)
        close(2)
        os.set_blocking(owner, False)
        os.set_blocking(report, False)
        # EOF before launch means the observer already disappeared.
        if select.select([owner], [], [], 0)[0]:
            os._exit(73)
        program = os.fork()
        if program == 0:
            for signum in (signal.SIGHUP, signal.SIGINT, signal.SIGTERM,
                           signal.SIGCHLD, signal.SIGPIPE):
                signal.signal(signum, signal.SIG_DFL)
            os.dup2(stdout, 1)
            os.dup2(stderr, 2)
            for descriptor in (owner, report, stdout, stderr):
                close(descriptor)
            try:
                # stdin is the actual uploaded program, not an unbounded
                # in-memory copy or a disk-backed temporary shell script.
                os.execvp("sh", ["sh", "-s"])
            except OSError:
                os._exit(127)
        close(0)
        close(stdout)
        close(stderr)
        deadline = started + PROGRAM_DEADLINE
        terminating = False
        while True:
            now = time.monotonic()
            if not terminating and (interrupted or now >= deadline):
                terminating = True
                deadline = min(now + 1, started + SETTLEMENT_DEADLINE)
                os.killpg(os.getpid(), signal.SIGTERM)
            if terminating:
                if now >= deadline:
                    os.killpg(os.getpid(), signal.SIGKILL)
            elif program is not None:
                waited, status = os.waitpid(program, os.WNOHANG)
                if waited:
                    program = None
                    if os.WIFEXITED(status):
                        code = os.WEXITSTATUS(status)
                    elif os.WIFSIGNALED(status):
                        code = 128 + os.WTERMSIG(status)
                    else:
                        raise ValueError("invalid program status")
                    if os.write(report, b"S" + bytes((code,))) != 2:
                        raise ValueError("incomplete program status")
            readable = select.select([owner], [], [], min(0.02, max(0, deadline - now)))[0]
            if readable:
                request = os.read(owner, 2)
                if (request == b"F" and program is None and not terminating
                        and not interrupted and time.monotonic() < deadline):
                    # This marker acknowledges an observer-requested stop,
                    # never an ordinary exit(137) or an external timer kill.
                    if os.write(report, b"D") != 1:
                        raise ValueError("incomplete teardown status")
                    os.killpg(os.getpid(), signal.SIGKILL)
                # Parent death, unexpected data and late finish requests all
                # revoke the session. No completion marker is produced.
                os.killpg(os.getpid(), signal.SIGKILL)
    except BaseException:
        if owned:
            os.killpg(os.getpid(), signal.SIGKILL)
        os._exit(73)

def linux_record(path):
    with open(path, "rb") as stream:
        raw = stream.read(8193)
    if len(raw) > 8192:
        raise ValueError("oversized process record")
    head, separator, tail = raw.rpartition(b") ")
    fields = tail.split()
    if (not separator or len(fields) < 20 or not head.split(b" ", 1)[0].isdigit()
            or fields[0] not in (b"R", b"S", b"D", b"T", b"t", b"K", b"W",
                                 b"P", b"I", b"X", b"Z", b"x")
            or not all(fields[index].isdigit() for index in (2, 3, 17, 19))):
        raise ValueError("invalid process record")
    record = (int(head.split(b" ", 1)[0]), fields[0], int(fields[2]),
              int(fields[3]), int(fields[17]), int(fields[19]))
    if record[0] <= 0 or record[4] <= 0:
        raise ValueError("invalid task identity or count")
    return record

def linux_view():
    with open("/proc/self/status", encoding="ascii") as stream:
        namespace = [line.split()[1:] for line in stream if line.startswith("NSpid:")]
    # A host-mounted procfs in a nested PID namespace cannot prove absence.
    # Never translate those foreign numeric IDs into signal authority.
    if namespace != [[str(os.getpid())]]:
        raise ValueError("unverified process namespace")
    observer = linux_record("/proc/self/stat")
    if (observer[0], observer[2], observer[3]) != (os.getpid(), os.getpgrp(), os.getsid(0)):
        raise ValueError("foreign process observation")

def session_empty(group):
    # The unreaped guardian pins its group/session identity during this whole
    # census. Metadata helpers stay in that private session; checking session
    # membership also refuses acknowledgement for a child which changed its
    # group: the original killpg does not clean up that escaped group. As with
    # the existing namespace boundary, this is not a sandbox for arbitrary
    # workloads which deliberately detach with setsid.
    seen_owner = False
    if sys.platform == "linux":
        linux_view()
        with os.scandir("/proc") as entries:
            for entry in entries:
                if not entry.name.isdecimal():
                    continue
                try:
                    record = linux_record(entry.path + "/stat")
                except (FileNotFoundError, ProcessLookupError):
                    continue
                if record[0] != int(entry.name):
                    raise ValueError("process census changed identity")
                if record[0] == group:
                    seen_owner = record[2:4] == (group, group)
                if record[2] != group and record[3] != group:
                    continue
                if record[1] not in (b"Z", b"X", b"x"):
                    return False
                # A zombie main thread may still have live siblings. Require
                # a complete, stable task census, not merely a dead leader.
                count = 0
                try:
                    with os.scandir(entry.path + "/task") as tasks:
                        for task in tasks:
                            if not task.name.isdecimal():
                                raise ValueError("invalid task census")
                            thread = linux_record(task.path + "/stat")
                            count += 1
                            if thread[0] != int(task.name) or thread[2:4] != record[2:4]:
                                raise ValueError("task census changed identity")
                            if thread[1] not in (b"Z", b"X", b"x"):
                                return False
                    if count != record[4] or linux_record(entry.path + "/stat") != record:
                        return False
                except (FileNotFoundError, ProcessLookupError):
                    return False
        linux_view()
    else:
        # Darwin has one PID view, and a zombie task has no executing sibling
        # threads. The checker has its own alarm and private group: a blocked
        # ps/exec or inherited pipe holder cannot outlive this census budget.
        process = subprocess.Popen(["ps", "-axo", "pid=,pgid=,stat="],
                                   stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        output = process.stdout.read(1048577)
        if len(output) > 1048576 or process.wait() != 0:
            raise ValueError("unavailable process census")
        seen_observer = False
        seen = set()
        for line in output.splitlines():
            fields = line.split()
            if (len(fields) != 3 or not fields[0].isdigit() or not fields[1].isdigit()
                    or not fields[2] or fields[2][:1] not in b"RSDTIUZE"):
                raise ValueError("invalid process census")
            pid, pgid, state = int(fields[0]), int(fields[1]), fields[2][:1]
            if pid in seen:
                raise ValueError("duplicate census entry")
            seen.add(pid)
            if pid == os.getpid():
                seen_observer = pgid == os.getpgrp() and pgid != group
            if pid == group:
                seen_owner = pgid == group
            if pid == process.pid:
                continue
            try:
                session = os.getsid(pid)
            except ProcessLookupError:
                continue
            if (pgid == group or session == group) and state != b"Z":
                return False
        if not seen_observer:
            raise ValueError("census omitted observer")
    return seen_owner

def quiescent(group, deadline):
    # Run procfs/ps reads outside the observer. Its own alarm survives observer
    # death; the observer also caps collection and kills the exact unreaped
    # checker group. Unavailable or incomplete evidence never becomes success.
    read_end, write_end = os.pipe()
    checker = None
    received = bytearray()
    try:
        checker = os.fork()
        if checker == 0:
            owned = False
            try:
                os.setsid()
                owned = os.getpgrp() == os.getpid()
                if not owned:
                    os._exit(73)
                def expire(_signum, _frame):
                    os.killpg(os.getpid(), signal.SIGKILL)
                for signum in (signal.SIGALRM, signal.SIGHUP, signal.SIGINT, signal.SIGTERM):
                    signal.signal(signum, expire)
                signal.signal(signal.SIGCHLD, signal.SIG_DFL)
                signal.pthread_sigmask(signal.SIG_UNBLOCK,
                                       {signal.SIGALRM, signal.SIGHUP, signal.SIGINT, signal.SIGTERM})
                signal.setitimer(signal.ITIMER_REAL, max(0.001, deadline - time.monotonic()))
                os.dup2(write_end, 3, inheritable=False)
                os.closerange(4, os.sysconf("SC_OPEN_MAX"))
                close(0)
                close(1)
                close(2)
                consecutive = 0
                while time.monotonic() < deadline:
                    consecutive = consecutive + 1 if session_empty(group) else 0
                    if consecutive == 2:
                        os.write(3, b"E")
                        os._exit(0)
                    time.sleep(0.01)
            except BaseException:
                pass
            if owned:
                os.killpg(os.getpid(), signal.SIGKILL)
            os._exit(73)
        close(write_end)
        os.set_blocking(read_end, False)
        while not interrupted and time.monotonic() < deadline:
            if not select.select([read_end], [], [], max(0, deadline - time.monotonic()))[0]:
                break
            chunk = os.read(read_end, 2 - len(received))
            if not chunk:
                break
            received.extend(chunk)
            if len(received) > 1:
                break
    finally:
        close(read_end)
        close(write_end)
        if checker is not None and checker > 0:
            # A normal exit is retained by waitpid even if our kill races its
            # last instruction. A killed/partial checker never grants absence.
            try:
                os.kill(checker, signal.SIGKILL)
            except ProcessLookupError:
                pass
            try:
                os.killpg(checker, signal.SIGKILL)
            except ProcessLookupError:
                pass
            except PermissionError:
                if sys.platform != "darwin":
                    raise
            _, status = os.waitpid(checker, 0)
    return (received == b"E" and os.WIFEXITED(status) and os.WEXITSTATUS(status) == 0
            and not interrupted and time.monotonic() < deadline)

def teardown(child, deadline=None):
    # Do not reap before signalling. Fork plus non-reaping pins this exact
    # group ID even if the guardian died or stopped before establishing it.
    try:
        os.kill(child, signal.SIGKILL)
    except ProcessLookupError:
        pass
    try:
        os.killpg(child, signal.SIGKILL)
    except ProcessLookupError:
        pass
    except PermissionError:
        # Darwin may return EPERM for a group containing only zombies.
        if sys.platform != "darwin":
            raise
    empty = False
    try:
        empty = deadline is None or quiescent(child, deadline)
    finally:
        _, status = os.waitpid(child, 0)
    return empty and os.WIFSIGNALED(status) and os.WTERMSIG(status) == signal.SIGKILL

def deliver(stderr, stdout, status):
    # No writers survive execution teardown. Nonblocking writes and one
    # shared delivery deadline prevent a stalled SSH reader from stranding
    # this observer; diagnostics must finish before any readiness is sent.
    deadline = time.monotonic() + DELIVERY_DEADLINE
    for descriptor, content in ((2, stderr), (1, stdout if status == 0 else b"")):
        if not content:
            continue
        os.set_blocking(descriptor, False)
        offset = 0
        while offset < len(content):
            remaining = deadline - time.monotonic()
            if interrupted or remaining <= 0:
                return 73
            if not select.select([], [descriptor], [], remaining)[1]:
                return 73
            try:
                count = os.write(descriptor, content[offset:])
            except BlockingIOError:
                continue
            if count <= 0:
                return 73
            offset += count
    return status if not interrupted else 73

descriptors = []
buffers = {}
finished = False
settled = False
failure = b"RCH_SOURCE_NAMESPACE_CONTROL_UNSETTLED cause=execution-or-process-settlement-unconfirmed\n"
code = 73
try:
    if sys.platform not in ("linux", "darwin") or not hasattr(signal, "pthread_sigmask"):
        raise ValueError("native process supervision is unavailable")
    # Clear inherited auto-reaping/blocked notifications. SIGCHLD is only an
    # interruption notice here; waitpid is reserved for final group teardown.
    signal.signal(signal.SIGCHLD, child_changed)
    for signum in (signal.SIGHUP, signal.SIGINT, signal.SIGTERM):
        signal.signal(signum, interrupt)
    signal.signal(signal.SIGPIPE, signal.SIG_IGN)
    signal.pthread_sigmask(signal.SIG_UNBLOCK, {signal.SIGCHLD, signal.SIGHUP,
                                             signal.SIGINT, signal.SIGTERM})
    replies = [sys.argv[1].encode()]
    if sys.argv[2]:
        replies.append(sys.argv[2].encode())
    if sys.argv[3]:
        replies.append(sys.argv[3].encode())
    if sys.argv[4] != "%s":
        replies = [reply + b"\n" for reply in replies]
    stdout_read, stdout_write = os.pipe()
    stderr_read, stderr_write = os.pipe()
    status_read, status_write = os.pipe()
    owner_read, owner_write = os.pipe()
    descriptors = [stdout_read, stdout_write, stderr_read, stderr_write,
                   status_read, status_write, owner_read, owner_write]
    started = time.monotonic()
    timer = os.fork()
    if timer == 0:
        guardian(owner_read, status_write, stdout_write, stderr_write, descriptors, started)
        os._exit(73)
    close(0)
    for descriptor in (stdout_write, stderr_write, status_write, owner_read):
        close(descriptor)
    os.set_blocking(owner_write, False)
    limits = {stdout_read: 4096, stderr_read: 65536, status_read: 3}
    buffers = {descriptor: bytearray() for descriptor in limits}
    opened = set(limits)
    for descriptor in opened:
        os.set_blocking(descriptor, False)
    while not changed and not interrupted and time.monotonic() < started + SETTLEMENT_DEADLINE:
        for descriptor in select.select(list(opened), [], [], 0.02)[0]:
            chunk = os.read(descriptor, min(8192, limits[descriptor] + 1 - len(buffers[descriptor])))
            if not chunk:
                opened.remove(descriptor)
            else:
                buffers[descriptor].extend(chunk)
                if len(buffers[descriptor]) > limits[descriptor]:
                    failure = b"RCH: namespace control output exceeded its byte bound\n"
                    raise ValueError("control output overflow")
        status = bytes(buffers[status_read])
        if status and (status[:1] != b"S" or (len(status) == 3 and status[2:] != b"D")):
            raise ValueError("invalid guardian response")
        if (not finished and len(status) >= 2
                and stdout_read not in opened and stderr_read not in opened):
            code = status[1]
            if code == 0 and bytes(buffers[stdout_read]) not in replies:
                failure = b"RCH: namespace control returned invalid readiness\n"
                raise ValueError("invalid metadata response")
            if os.write(owner_write, b"F") != 1:
                raise ValueError("incomplete teardown request")
            finished = True
    owned_timer = timer
    timer = None
    settled = teardown(owned_timer, started + SETTLEMENT_DEADLINE if finished else None)
    # The guardian writes at most three bytes before dying. Drain that pipe
    # after reaping too: SIGCHLD can arrive before select reports its last byte.
    while len(buffers[status_read]) <= 3:
        chunk = os.read(status_read, 4 - len(buffers[status_read]))
        if not chunk:
            break
        buffers[status_read].extend(chunk)
    settled = (settled and finished and not interrupted
               and time.monotonic() < started + SETTLEMENT_DEADLINE
               and bytes(buffers[status_read]) == b"S" + bytes((code,)) + b"D")
except BaseException:
    settled = False
finally:
    if timer is not None and timer > 0:
        owned_timer = timer
        timer = None
        try:
            teardown(owned_timer)
        except BaseException:
            settled = False
    for descriptor in descriptors:
        close(descriptor)

try:
    if not settled:
        os._exit(deliver(failure, b"", 73))
    stderr = bytes(buffers[stderr_read])
    if code >= 128:
        detail = ("RCH_SOURCE_NAMESPACE_PROCESS_TERMINATED status={} signal={} signal_origin=unknown\n"
                  .format(code, code - 128)).encode()
        if len(stderr) + len(detail) > 65536:
            os._exit(deliver(b"RCH: namespace control output exceeded its byte bound\n", b"", 73))
        stderr += detail
    os._exit(deliver(stderr, bytes(buffers[stdout_read]), code))
except BaseException:
    os._exit(73)
' "$rch_control_ready" "$rch_control_alternate" "$rch_control_third" "$rch_control_format"
fi
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
            or sys.argv[2] not in tuple(str(n) for n in range(1, 151))
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
    [ "${1:-}" = --kill-after=1 ] || exit 73
    case "${2:-}" in 1|2|15) ;; *) exit 73 ;; esac
    rch_timing_budget "$2"
    shift 2
    set -- --kill-after=1 "$rch_timing_scaled" "$@"
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
    except PermissionError:
        # Darwin answers EPERM once the group holds only zombies.
        if sys.platform != "darwin":
            raise
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
third=$6
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
    if { [ -n "$alternate" ] && printf "$reply_format" "$alternate" | cmp -s - "$control/stdout"; } ||
       { [ -n "$third" ] && printf "$reply_format" "$third" | cmp -s - "$control/stdout"; }; then
        :
    else
        printf "%s\n" "RCH: namespace control returned invalid readiness" >&2
        exit 73
    fi
fi
finish 0
' rch-namespace-monitor "$control" "$$" "$rch_control_ready" "$rch_control_alternate" "$rch_control_format" "$rch_control_third" <&3 3<&- &
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
third=$5
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
    if { [ -n "$alternate" ] && printf "$reply_format" "$alternate" | cmp -s - "$control/stdout"; } ||
       { [ -n "$third" ] && printf "$reply_format" "$third" | cmp -s - "$control/stdout"; }; then
        :
    else
        exit 73
    fi
fi
cat -- "$control/stdout"
' rch-namespace-delivery "$control" "$rch_control_ready" "$rch_control_alternate" "$rch_control_format" "$rch_control_third" </dev/null &
delivery=$!
set +e
# A foreground timer killed during delivery makes the observer shell print
# "Killed" to the same full stderr pipe, defeating the delivery deadline.
# Keep payload streams unchanged and silence only the observer's wait notice.
wait "$delivery" 2>/dev/null
delivery_status=$?
set -e
exit "$delivery_status"
