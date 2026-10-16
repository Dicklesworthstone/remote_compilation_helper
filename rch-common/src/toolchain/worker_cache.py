"""Worker-side environment preparation for RCH's opt-in local RABS profile.

Embedded by the existing Rust remote-command builder, after env controls.
Import the installed cargo-rabs preparation API without invoking its CLI or a
second Cargo. Neither this adapter nor readiness grants compiler-skip authority.
Preparation is isolated under an outer deadline; Cargo itself is exec'd once.

RCH_RABS_PREPARE_TIMEOUT_MS overrides the preparation budget (0 skips setup,
maximum 35000). The default is CARGO_RABS_STARTUP_MS plus 2000 ms, or 7000 ms
without a launcher override. Cleanup adds at most 250 ms of cooperative wait;
a kernel-blocked helper can retain pending SIGKILL. Cargo execution has no new
timeout. Existing/shared daemons are outside the preparer's process group.
Diagnostic replay has a separate 100 ms delivery budget and the same 250 ms
cleanup grace. A stalled stderr reader cannot hold Cargo before exec. Blocking
kernel operations can still outlive cooperative deadlines with SIGKILL pending.
"""

import ast
import json
import os
import selectors
import shutil
import signal
import socket
import stat
import sys
import time


ACTIVE = "RCH_RABS_WORKER_ACTIVE"
MAX_LAUNCHER_BYTES = 128 * 1024
MAX_PREPARE_BYTES = 1024 * 1024
MAX_PREPARE_LOG_BYTES = 16 * 1024
MAX_PREPARE_MS = 35_000
CLEANUP_SECONDS = 0.25
DIAGNOSTIC_SECONDS = 0.1
SETUP_SIGNALS = tuple(getattr(signal, name) for name in ("SIGINT", "SIGTERM", "SIGHUP")
                      if hasattr(signal, name))


class PreparationCancelled(BaseException):
    def __init__(self, number):
        self.number = number


def cancel_preparation(number, _frame):
    raise PreparationCancelled(number)


def load_prepare(launcher):
    # Inspect the version contract WITHOUT executing an older launcher's CLI.
    # Use the same captured source for inspection and execution; do not reopen
    # a path that an installation upgrade may have replaced in between.
    launcher = os.path.realpath(launcher)
    descriptor = os.open(launcher, os.O_RDONLY | os.O_NONBLOCK | os.O_CLOEXEC)
    with os.fdopen(descriptor, "rb") as source:
        if not stat.S_ISREG(os.fstat(source.fileno()).st_mode):
            raise RuntimeError("cargo-rabs is not a regular script")
        content = source.read(MAX_LAUNCHER_BYTES + 1)
    if len(content) > MAX_LAUNCHER_BYTES:
        raise RuntimeError("cargo-rabs exceeds the preparation source bound")
    tree = ast.parse(content, filename=launcher)
    versions = [node.value.value for node in tree.body
                if isinstance(node, ast.Assign) and len(node.targets) == 1
                and isinstance(node.targets[0], ast.Name)
                and node.targets[0].id == "RCH_WORKER_PREPARATION_API"
                and isinstance(node.value, ast.Constant)]
    if len(versions) != 1 or type(versions[0]) is not int or versions[0] != 1:
        raise RuntimeError("installed cargo-rabs lacks preparation API version 1")
    namespace = {"__name__": "rch_rabs_worker_launcher", "__file__": launcher}
    exec(compile(tree, launcher, "exec"), namespace)
    prepare = namespace.get("prepare")
    if not callable(prepare):
        raise RuntimeError("installed cargo-rabs lacks the preparation API")
    return prepare


def valid_environment(environment):
    # execve rejects NULs, empty names and '=' in names. Refuse during setup,
    # when stock Cargo is still safe, not at the final one-way exec boundary.
    return isinstance(environment, dict) and all(
        isinstance(key, str) and isinstance(value, str)
        and key and "=" not in key and "\0" not in key and "\0" not in value
        for key, value in environment.items()
    )


def prepared_environment(original):
    if sys.platform != "linux" or sys.version_info < (3, 9) or original.get(ACTIVE) == "1":
        return original
    launcher = shutil.which("cargo-rabs", path=original.get("PATH"))
    if launcher is None:
        print("rch: worker-local RABS unavailable: cargo-rabs is not installed; using stock Cargo",
              file=sys.stderr)
        return original
    try:
        # Installed scripts are worker-selected executable code, not uploaded
        # source or data. Incompatible installations refuse BEFORE execution.
        prepare = load_prepare(launcher)
        candidate = dict(original)
        candidate[ACTIVE] = "1"
        prepared = prepare(candidate, no_start=False)
        if not valid_environment(prepared):
            raise RuntimeError("installed cargo-rabs returned an invalid environment")
        return prepared
    except Exception as error:
        # Preparation only: no Cargo/rustc or output writer has started. Keep
        # the original environment, including explicit custom wrappers. Never
        # repeat a Cargo command after it has executed or exposed any output.
        print("rch: worker-local RABS setup unavailable: {}; using stock Cargo".format(error),
              file=sys.stderr)
        return original


def preparation_seconds(environment):
    def bounded_integer(name, default, maximum):
        try:
            value = int(environment.get(name, str(default)))
        except (TypeError, ValueError):
            return default
        return min(maximum, max(0, value))

    # Allow the launcher's own readiness deadline plus config/import overhead.
    # An explicit worker bound also covers source loading and blocking filesystem
    # operations that the in-process launcher's cooperative checks cannot stop.
    startup = bounded_integer("CARGO_RABS_STARTUP_MS", 5000, 30000)
    return bounded_integer("RCH_RABS_PREPARE_TIMEOUT_MS", startup + 2000,
                           MAX_PREPARE_MS) / 1000


def prepare_child(original, response, log_descriptor):
    # This is a fresh, single-threaded Python adapter, not a daemon runtime.
    # The parent retains Cargo's stdin, process identity and jobserver FDs.
    # Setup helpers must neither consume those tokens nor keep their pipes alive.
    os.setsid()
    for number in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP):
        signal.signal(number, signal.SIG_DFL)
    null = os.open(os.devnull, os.O_RDONLY | os.O_CLOEXEC)
    os.dup2(null, 0)
    os.dup2(log_descriptor, 1)
    os.dup2(log_descriptor, 2)
    keep = {0, 1, 2, response.fileno()}
    for entry in os.listdir("/proc/self/fd"):
        descriptor = int(entry)
        if descriptor not in keep:
            try:
                os.close(descriptor)
            except OSError:
                pass
    try:
        environment = prepared_environment(original)
        report = {"environment": environment}
    except KeyboardInterrupt:
        report = {"cancelled": True}
    except BaseException as error:
        # An installed launcher's sys.exit must not exit the Cargo adapter.
        report = {"error": "{}: {}".format(type(error).__name__, error)[:4096]}
    try:
        data = json.dumps(report, ensure_ascii=True, separators=(",", ":")).encode("ascii")
        if len(data) > MAX_PREPARE_BYTES:
            data = b'{"error":"RABS preparation environment exceeded its frame bound"}'
        # Never mix launcher output with the environment/control response.
        response.sendall(data)
        sys.stdout.flush()
        sys.stderr.flush()
    finally:
        response.close()


def cleanup_preparer(pid):
    # The direct child has NOT been reaped, even after observed exit. Its PID
    # therefore cannot have been recycled into an unrelated process/group.
    # cargo-rabs starts shared daemons in separate sessions; never kill them.
    previous = signal.pthread_sigmask(signal.SIG_BLOCK, SETUP_SIGNALS)
    try:
        for send in (lambda: os.killpg(pid, signal.SIGKILL),
                     lambda: os.kill(pid, signal.SIGKILL)):
            try:
                send()
            except ProcessLookupError:
                pass
        deadline = time.monotonic() + CLEANUP_SECONDS
        while True:
            try:
                child, _ = os.waitpid(pid, os.WNOHANG)
            except ChildProcessError:
                return True
            if child:
                return True
            if time.monotonic() >= deadline:
                # Report through bounded replay, never a blocking parent write.
                return False
            time.sleep(0.01)
    finally:
        # Deliver a pending cancellation only AFTER the owned child is reaped
        # or has pending SIGKILL; cancellation must not detach that child.
        signal.pthread_sigmask(signal.SIG_SETMASK, previous)


def replay_diagnostics(data):
    """Best-effort raw stderr under ownership, without changing Cargo's FDs.

    dup()/O_NONBLOCK would change the shared open-file description, leaking
    nonblocking I/O into Cargo or its caller. Instead only a short-lived relay
    may block in write. It owns no stdin, stdout, jobserver or control handles,
    runs no installed code, and is terminated/reaped before Cargo's exec.
    """
    if not data or signal.getsignal(signal.SIGCHLD) != signal.SIG_DFL:
        return
    data = bytes(data[:MAX_PREPARE_LOG_BYTES + 8192])
    pid = None
    # Close the fork-to-assignment cancellation window before taking ownership.
    previous = signal.pthread_sigmask(signal.SIG_BLOCK, SETUP_SIGNALS)
    try:
        pid = os.fork()
        if pid == 0:
            try:
                os.setsid()
                for number in SETUP_SIGNALS:
                    signal.signal(number, signal.SIG_DFL)
                signal.pthread_sigmask(signal.SIG_SETMASK, previous)
                for entry in os.listdir("/proc/self/fd"):
                    descriptor = int(entry)
                    if descriptor != 2:
                        try:
                            os.close(descriptor)
                        except OSError:
                            pass
                remaining = memoryview(data)
                while remaining:
                    written = os.write(2, remaining)
                    if written <= 0:
                        break
                    remaining = remaining[written:]
            except BaseException:
                pass
            os._exit(0)
        signal.pthread_sigmask(signal.SIG_SETMASK, previous)
        deadline = time.monotonic() + DIAGNOSTIC_SECONDS
        while True:
            try:
                exited = os.waitid(os.P_PID, pid, os.WEXITED | os.WNOHANG | os.WNOWAIT)
            except ChildProcessError:
                # An inherited auto-reap disposition relinquished this PID.
                # The fixed relay has no descendants: do not signal a reused ID.
                pid = None
                return
            if exited is not None or time.monotonic() >= deadline:
                return
            time.sleep(0.005)
    except OSError:
        # Exhausted process/FD resources or closed stderr cannot fail a build.
        # Never attempt to diagnose a relay failure with another stderr write.
        return
    finally:
        try:
            if pid:
                cleanup_preparer(pid)
        finally:
            signal.pthread_sigmask(signal.SIG_SETMASK, previous)


def bounded_prepared_environment(original):
    if sys.platform != "linux" or sys.version_info < (3, 9) or original.get(ACTIVE) == "1":
        return original
    # WNOWAIT cannot retain a PID under auto-reap or an external reaper. Refuse
    # setup before creating effects, rather than risk signaling a reused ID.
    # Preserve that original disposition for the eventual Cargo exec.
    if signal.getsignal(signal.SIGCHLD) != signal.SIG_DFL:
        return original
    budget = preparation_seconds(original)
    if budget == 0:
        return original
    deadline = time.monotonic() + budget
    parent = child = None
    log_read = log_write = None
    pid = None
    logs = bytearray()
    truncated = False
    failure = b""
    try:
        parent, child = socket.socketpair()
        log_read, log_write = os.pipe2(os.O_CLOEXEC)
        pid = os.fork()
        if pid == 0:
            try:
                parent.close()
                os.close(log_read)
                prepare_child(original, child, log_write)
            except BaseException:
                os._exit(1)
            os._exit(0)
        child.close()
        child = None
        os.close(log_write)
        log_write = None
        parent.setblocking(False)
        os.set_blocking(log_read, False)
        data = bytearray()
        eof = False
        log_eof = False
        with selectors.DefaultSelector() as selector:
            selector.register(parent, selectors.EVENT_READ, "response")
            selector.register(log_read, selectors.EVENT_READ, "log")
            while True:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise TimeoutError("RABS worker preparation deadline expired")
                # WNOWAIT observes exit without relinquishing the identity used
                # for cancellation and descendant cleanup in the finally block.
                exited = os.waitid(os.P_PID, pid, os.WEXITED | os.WNOHANG | os.WNOWAIT)
                if exited is not None and eof and log_eof:
                    if exited.si_code != os.CLD_EXITED or exited.si_status != 0:
                        raise RuntimeError("RABS preparation helper exited without success")
                    break
                for key, _ in selector.select(min(remaining, 0.05)):
                    if key.data == "response":
                        chunk = parent.recv(min(4096, MAX_PREPARE_BYTES + 1 - len(data)))
                        if not chunk:
                            eof = True
                            selector.unregister(parent)
                        else:
                            data.extend(chunk)
                            if len(data) > MAX_PREPARE_BYTES:
                                raise RuntimeError("RABS preparation response exceeded its frame bound")
                    else:
                        chunk = os.read(log_read, 4096)
                        if not chunk:
                            log_eof = True
                            selector.unregister(log_read)
                        else:
                            room = MAX_PREPARE_LOG_BYTES - len(logs)
                            logs.extend(chunk[:room])
                            truncated |= len(chunk) > room
        report = json.loads(data)
        if not isinstance(report, dict):
            raise RuntimeError("RABS preparation returned a non-object response")
        if report.get("cancelled") is True:
            raise KeyboardInterrupt
        if "error" in report:
            raise RuntimeError(str(report["error"])[:4096])
        environment = report.get("environment")
        if not valid_environment(environment):
            raise RuntimeError("RABS preparation returned an invalid environment")
        return environment
    except Exception as error:
        failure = ("rch: worker-local RABS setup unavailable: {}; using stock Cargo\n"
                   .format(str(error)[:4096])).encode("utf-8", errors="backslashreplace")
        return original
    finally:
        if pid and not cleanup_preparer(pid):
            failure += b"rch: RABS setup cleanup remains pending; acceleration not used\n"
        for stream in (parent, child):
            if stream is not None:
                stream.close()
        for descriptor in (log_read, log_write):
            if descriptor is not None:
                os.close(descriptor)
        if truncated:
            logs.extend(b"rch: RABS preparation diagnostics truncated\n")
        replay_diagnostics(failure + logs)


def main():
    argv = sys.argv[1:]
    if not argv:
        print("rch: worker-local RABS runner requires an executable", file=sys.stderr)
        return 127
    # Retain the complete original argv, including `rustup run TC cargo`.
    # `rustup run TC python ...` followed by a PATH lookup for Cargo is NOT
    # equivalent: it may select a different Cargo shim or lose custom-toolchain
    # fallback. Setup changes only the wrapper environment, never that choice.
    original = dict(os.environ)
    previous_handlers = {
        number: signal.signal(number, cancel_preparation)
        for number in (getattr(signal, name, None) for name in ("SIGTERM", "SIGHUP"))
        if number is not None
    }
    try:
        environment = bounded_prepared_environment(original)
    except KeyboardInterrupt:
        return 130
    except PreparationCancelled as cancelled:
        return 128 + cancelled.number
    finally:
        for number, handler in previous_handlers.items():
            signal.signal(number, handler)
    # Python ignores these signals for its own I/O. Restore the ordinary shell
    # defaults at the exec boundary rather than leaking Python's dispositions.
    for name in ("SIGPIPE", "SIGXFZ", "SIGXFSZ"):
        number = getattr(signal, name, None)
        if number is not None:
            signal.signal(number, signal.SIG_DFL)
    try:
        os.execvpe(argv[0], argv, environment)
    except OSError as error:
        print("rch: could not execute {}: {}".format(argv[0], error), file=sys.stderr)
        return 127 if isinstance(error, FileNotFoundError) else 126


if __name__ == "__main__":
    sys.exit(main())
