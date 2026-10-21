#!/usr/bin/env python3
"""Native lifetime tests of the embedded worker-cache adapter.

Only installed preparation/Cargo are fixtures. Processes, signals, pipe
ownership and locks are real. No daemon, SSH session or production worker is
started. PID handles pin every test cleanup target; fixture files are retained.
"""
import fcntl
import os
from pathlib import Path
import re
import select
import shutil
import signal
import subprocess
import sys
import tempfile
import time
import unittest

ROOT = Path(__file__).resolve().parents[1]
ADAPTER = Path(os.environ.get("RCH_TEST_WORKER_ADAPTER",
                             ROOT / "rch-common/src/toolchain/worker_cache.py"))
PYTHON = sys.executable
RUNNER_FILE = os.environ.get("RCH_TEST_WORKER_RUNNER")
RUNNER = (Path(RUNNER_FILE).read_text() if RUNNER_FILE else
          re.search(r'const PLATFORM_RUNNER: &str = r#"(.*?)"#;',
                    (ROOT / "rch-common/src/toolchain/worker_cache.rs").read_text(),
                    re.DOTALL).group(1))
SHELL = os.environ.get("RCH_TEST_SHELL", "/bin/sh")

PREPARATION = r'''RCH_WORKER_PREPARATION_API = 1
import fcntl, os, signal, time
from pathlib import Path
root = Path(os.environ["TEST_ROOT"])

def publish(name):
    temporary = root / (name + ".tmp")
    temporary.write_text(str(os.getpid()))
    temporary.rename(root / name)

def linger(name, lock_name):
    for number in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP):
        signal.signal(number, signal.SIG_IGN)
    lock = open(root / lock_name, "a")
    fcntl.flock(lock, fcntl.LOCK_EX)
    publish(name)
    while not (root / "release").exists():
        time.sleep(0.01)
    fcntl.flock(lock, fcntl.LOCK_UN)

publish("imported.pid")
if os.environ.get("TEST_MODE") == "import":
    linger("preparer.pid", "preparer.lock")

def prepare(env, no_start):
    mode = env.get("TEST_MODE", "success")
    if mode == "failure":
        raise RuntimeError("fixture preparation refusal")
    if mode == "cancel":
        raise KeyboardInterrupt
    if mode == "success":
        env["PREPARED"] = "yes"
        return env
    publish("preparer.pid")
    child = os.fork()
    if child == 0:
        try:
            if mode == "daemon":
                os.setsid()
            linger("descendant.pid", "descendant.lock")
        finally:
            os._exit(0)
    while not (root / "descendant.pid").exists():
        time.sleep(0.005)
    if mode == "returned":
        env["PREPARED"] = "yes"
        return env
    linger("ready.pid", "preparer.lock")
    os.waitpid(child, 0)
    env["PREPARED"] = "yes"
    return env
'''

CARGO = r'''#!/bin/sh
printf '%s\n' "$$" >> "$TEST_ROOT/cargo.calls"
printf '%s\0' "$@" > "$TEST_ROOT/arguments"
printf '%s\n' "${PREPARED-no}" > "$TEST_ROOT/prepared"
printf 'cargo stdout\n'
printf 'cargo stderr\n' >&2
if [ -n "${TEST_SIGNAL-}" ]; then kill -"$TEST_SIGNAL" "$$"; fi
exit "${TEST_STATUS-0}"
'''


@unittest.skipUnless(sys.platform == "linux" and hasattr(os, "pidfd_open"),
                     "requires Linux process handles and flock")
class WorkerLifetimeTests(unittest.TestCase):
    def setUp(self):
        self.root = Path(tempfile.mkdtemp(prefix="rch-preparer-lifetime-"))
        self.tools = self.root / "tools"
        self.tools.mkdir()
        (self.tools / "python3").symlink_to(PYTHON)
        (self.tools / "uname").symlink_to(shutil.which("uname"))
        self.env = {"PATH": str(self.tools), "HOME": str(self.root), "LC_ALL": "C",
                    "TEST_ROOT": str(self.root), "RCH_RABS_PREPARE_TIMEOUT_MS": "10000"}
        for name, source in (("cargo-rabs", PREPARATION), ("cargo", CARGO)):
            path = self.tools / name
            path.write_text(source)
            path.chmod(0o700)
        self.handles = []
        self.processes = []
        self.addCleanup(self.cleanup_owned)

    def cleanup_owned(self):
        for handle in self.handles:
            try:
                signal.pidfd_send_signal(handle, signal.SIGCONT)
                signal.pidfd_send_signal(handle, signal.SIGKILL)
            except ProcessLookupError:
                pass
            finally:
                os.close(handle)
        for process in self.processes:
            process.communicate(timeout=5)

    def start(self, mode="hang", args=("check",), code=None, pass_fds=()):
        self.env["TEST_MODE"] = mode
        command = [SHELL, "-c", RUNNER, "rch-rabs-worker",
                   code or ADAPTER.read_text(), "cargo", *args]
        process = subprocess.Popen(command, cwd=self.root, env=self.env,
                                   stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                   stderr=subprocess.PIPE, pass_fds=pass_fds)
        self.processes.append(process)
        handle = os.pidfd_open(process.pid)
        self.handles.append(handle)
        return process, handle

    def pin(self, name, process):
        deadline = time.monotonic() + 3
        while True:
            try:
                pid = int((self.root / name).read_text())
                handle = os.pidfd_open(pid)
                self.handles.append(handle)
                return pid, handle
            except (FileNotFoundError, ValueError):
                self.assertIsNone(process.poll(), "adapter exited before fixture readiness")
                self.assertLess(time.monotonic(), deadline, name)
                time.sleep(0.005)

    def stopped(self, handle, milliseconds=1500):
        poll = select.poll()
        poll.register(handle, select.POLLIN)
        return bool(poll.poll(milliseconds))

    def assert_free(self, name):
        with (self.root / name).open("a") as lock:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)

    def assert_cargo(self, process, expected=0, prepared=True):
        out, err = process.communicate(timeout=5)
        self.assertEqual(process.returncode, expected, err)
        self.assertEqual(out, b"cargo stdout\n")
        self.assertEqual((self.root / "cargo.calls").read_text(), str(process.pid) + "\n")
        self.assertEqual((self.root / "prepared").read_text(), "yes\n" if prepared else "no\n")
        self.assertTrue(err.endswith(b"cargo stderr\n"), err)

    def test_hard_killed_adapter_retires_preparer_and_lock_holding_descendant(self):
        process, owner = self.start()
        _, preparer = self.pin("ready.pid", process)
        _, descendant = self.pin("descendant.pid", process)
        signal.pidfd_send_signal(owner, signal.SIGKILL)
        process.wait(timeout=2)
        self.assertTrue(self.stopped(preparer), "preparer survived adapter SIGKILL")
        self.assertTrue(self.stopped(descendant), "descendant survived adapter SIGKILL")
        self.assert_free("preparer.lock")
        self.assert_free("descendant.lock")
        self.assertFalse((self.root / "cargo.calls").exists())

    def test_hard_killed_adapter_during_launcher_import_releases_lock(self):
        process, owner = self.start("import")
        _, preparer = self.pin("preparer.pid", process)
        signal.pidfd_send_signal(owner, signal.SIGKILL)
        process.wait(timeout=2)
        self.assertTrue(self.stopped(preparer), "launcher import survived owner death")
        self.assert_free("preparer.lock")
        self.assertFalse((self.root / "cargo.calls").exists())

    def test_deadline_still_retires_group_when_adapter_is_stopped(self):
        self.env["RCH_RABS_PREPARE_TIMEOUT_MS"] = "1500"
        process, owner = self.start()
        _, preparer = self.pin("ready.pid", process)
        _, descendant = self.pin("descendant.pid", process)
        signal.pidfd_send_signal(owner, signal.SIGSTOP)
        self.assertTrue(self.stopped(preparer, 3000), "stopped adapter disabled setup deadline")
        self.assertTrue(self.stopped(descendant), "deadline left a live descendant")
        self.assertFalse((self.root / "cargo.calls").exists())
        signal.pidfd_send_signal(owner, signal.SIGCONT)
        self.assert_cargo(process, prepared=False)
        self.assert_free("descendant.lock")

    def test_shared_daemon_session_is_not_owned_by_preparation_watchdog(self):
        process, owner = self.start("daemon")
        preparer_pid, preparer = self.pin("ready.pid", process)
        daemon_pid, daemon = self.pin("descendant.pid", process)
        self.assertNotEqual(os.getpgid(preparer_pid), os.getpgid(daemon_pid))
        signal.pidfd_send_signal(owner, signal.SIGKILL)
        process.wait(timeout=2)
        self.assertTrue(self.stopped(preparer), "preparer survived owner death")
        self.assertFalse(self.stopped(daemon, 100), "shared-daemon session was killed")
        self.assert_free("preparer.lock")

    def test_preparer_exit_cannot_disarm_descendant_cleanup(self):
        self.env["RCH_RABS_PREPARE_TIMEOUT_MS"] = "1500"
        process, _ = self.start("returned")
        _, descendant = self.pin("descendant.pid", process)
        self.assert_cargo(process, prepared=False)
        self.assertTrue(self.stopped(descendant))
        self.assert_free("descendant.lock")

    def test_owner_death_after_preparer_exit_still_retires_live_descendants(self):
        process, owner = self.start("returned")
        _, preparer = self.pin("preparer.pid", process)
        _, descendant = self.pin("descendant.pid", process)
        self.assertTrue(self.stopped(preparer), "preparer must exit before adapter death")
        self.assertFalse(self.stopped(descendant, 0))
        signal.pidfd_send_signal(owner, signal.SIGKILL)
        process.wait(timeout=2)
        self.assertTrue(self.stopped(descendant), "leader loss disarmed group cleanup")
        self.assert_free("descendant.lock")
        self.assertFalse((self.root / "cargo.calls").exists())

    def test_concurrent_preparations_have_independent_lifetimes(self):
        running = []
        for _ in range(4):
            fixture = WorkerLifetimeTests(methodName="runTest")
            fixture.setUp()
            self.addCleanup(fixture.cleanup_owned)
            process, owner = fixture.start()
            _, preparer = fixture.pin("ready.pid", process)
            _, descendant = fixture.pin("descendant.pid", process)
            running.append((fixture, process, owner, preparer, descendant))
        for fixture, process, owner, preparer, descendant in running[:2]:
            signal.pidfd_send_signal(owner, signal.SIGKILL)
            process.wait(timeout=2)
            self.assertTrue(fixture.stopped(preparer))
            self.assertTrue(fixture.stopped(descendant))
            fixture.assert_free("descendant.lock")
        for fixture, process, _, preparer, descendant in running[2:]:
            self.assertIsNone(process.poll())
            self.assertFalse(fixture.stopped(preparer, 0))
            self.assertFalse(fixture.stopped(descendant, 0))
            (fixture.root / "release").touch()
            fixture.assert_cargo(process)
            fixture.assert_free("descendant.lock")

    def test_success_retains_single_exec_and_opaque_arguments(self):
        arguments = ("+nightly", "test", "--", "", "a'b ; $HOME", "line\nbreak")
        process, _ = self.start("success", arguments)
        self.assert_cargo(process)
        self.assertEqual((self.root / "arguments").read_bytes(),
                         b"".join(os.fsencode(arg) + b"\0" for arg in arguments))

    def test_preparation_refusal_preserves_stock_cargo(self):
        process, _ = self.start("failure")
        self.assert_cargo(process, prepared=False)

    def test_preparation_cancellation_never_runs_cargo(self):
        process, _ = self.start("cancel")
        out, _ = process.communicate(timeout=5)
        self.assertEqual(process.returncode, 130)
        self.assertEqual(out, b"")
        self.assertFalse((self.root / "cargo.calls").exists())

    def injected(self, setup):
        # Only this fault-injection driver replaces a primitive. The production
        # adapter remains byte-for-byte intact, and executes as its real main.
        return ("import os, signal\nnamespace = {'__name__': 'adapter_under_test'}\n"
                "exec(compile(" + repr(ADAPTER.read_text()) +
                ", '<production-adapter>', 'exec'), namespace)\n" + setup +
                "\nraise SystemExit(namespace['main']())\n")

    def test_watchdog_fork_failure_refuses_before_installed_code(self):
        setup = ("fork = os.fork\ncalls = 0\n"
                 "def controlled_fork():\n"
                 "    global calls\n    calls += 1\n"
                 "    if calls == 2: raise OSError('watch fork refused')\n"
                 "    return fork()\n"
                 "os.fork = controlled_fork\n")
        process, _ = self.start("success", code=self.injected(setup))
        self.assert_cargo(process, prepared=False)
        self.assertFalse((self.root / "imported.pid").exists())

    def test_watchdog_readiness_failure_cannot_admit_preparation(self):
        setup = ("write = os.write\n"
                 "def controlled_write(fd, data):\n"
                 "    if data == b'1': raise OSError('ready write refused')\n"
                 "    return write(fd, data)\n"
                 "os.write = controlled_write\n")
        process, _ = self.start("success", code=self.injected(setup))
        self.assert_cargo(process, prepared=False)
        self.assertFalse((self.root / "imported.pid").exists())

    def test_parent_cancellation_retires_the_same_owned_group(self):
        for number in (signal.SIGTERM, signal.SIGHUP, signal.SIGINT):
            with self.subTest(signal=number):
                # Each process owns an independent fixture and cleanup handles.
                fixture = WorkerLifetimeTests(methodName="runTest")
                fixture.setUp()
                self.addCleanup(fixture.cleanup_owned)
                process, owner = fixture.start()
                _, preparer = fixture.pin("ready.pid", process)
                _, descendant = fixture.pin("descendant.pid", process)
                signal.pidfd_send_signal(owner, number)
                out, _ = process.communicate(timeout=5)
                self.assertEqual(process.returncode, 128 + number)
                self.assertEqual(out, b"")
                self.assertTrue(fixture.stopped(preparer))
                self.assertTrue(fixture.stopped(descendant))
                self.assertFalse((fixture.root / "cargo.calls").exists())

    def test_compiler_terminal_status_is_not_retried(self):
        for status, number in ((101, None), (0, signal.SIGTERM), (0, signal.SIGPIPE)):
            with self.subTest(status=status, signal=number):
                fixture = WorkerLifetimeTests(methodName="runTest")
                fixture.setUp()
                self.addCleanup(fixture.cleanup_owned)
                fixture.env["TEST_STATUS"] = str(status)
                if number is not None:
                    fixture.env["TEST_SIGNAL"] = str(number)
                process, _ = fixture.start("success")
                fixture.assert_cargo(process, -number if number else status)


if __name__ == "__main__":
    unittest.main(verbosity=2)
