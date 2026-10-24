#!/usr/bin/env python3
"""Exercise the production worker adapter's final execution gate.

Cargo and the installed preparation API are fixtures. Cleanup refusal/error and
an outside child reaper are explicit fault injections; no uninterruptible kernel
I/O or PID reuse is claimed. Forks, wait/reap, process groups, locks and output
backpressure are real. A separate control proves non-child PIDs are not signalled.
All files are retained, and test cleanup uses handles to test-owned processes.
"""
import fcntl
import json
import os
from pathlib import Path
import select
import shlex
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
PREPARE = '''RCH_WORKER_PREPARATION_API = 1
import fcntl, os, signal, time

def prepare(env, no_start):
    root = env["TEST_ROOT"]
    with open(root + "/prepared.pid", "w") as report:
        report.write(str(os.getpid()))
    mode = env.get("TEST_PREPARE", "success")
    if mode == "failure":
        raise RuntimeError("controlled preparation failure")
    if mode == "cancel":
        raise KeyboardInterrupt
    if mode == "hang":
        lock = open(root + "/preparation.lock", "a")
        fcntl.flock(lock, fcntl.LOCK_EX)
        with open(root + "/locked", "w") as marker:
            marker.write("held")
        time.sleep(30)
    env["PREPARED"] = "yes"
    return env
'''

# Load, do not rewrite, the exact production Python. All fault injection stays
# in this test driver. Calls from the preparer/watchdog have a different PID and
# are not confused with parent-side ownership decisions.
DRIVER = r'''
import errno, json, os, signal, sys, time
from pathlib import Path
source, executable = sys.argv[1:3]
arguments = sys.argv[3:]
namespace = {"__name__": "rch_cleanup_under_test", "__file__": source}
exec(compile(Path(source).read_bytes(), source, "exec"), namespace)
root = Path(os.environ["TEST_ROOT"])
parent = os.getpid()
fault = os.environ.get("TEST_FAULT", "none")
original_cleanup = namespace["cleanup_preparer"]
original_waitid = os.waitid
original_waitpid = os.waitpid
original_kill = os.kill
original_killpg = os.killpg
original_close = os.close
calls = 0
reaped = None
close_failed = False

def record(event, **values):
    if os.getpid() == parent:
        with (root / "events").open("a") as log:
            log.write(json.dumps({"event": event, **values}) + "\n")

def cleanup(pid):
    global calls
    calls += 1
    record("cleanup", pid=pid)
    if calls == 1 and fault == "no-cleanup":
        return False
    result = original_cleanup(pid)
    record("settled", pid=pid, result=result)
    if calls == 1 and fault == "pending":
        return False
    if calls == 1 and fault == "error":
        raise OSError(errno.EIO, "injected cleanup observation failure")
    if calls == 1 and fault == "unexpected-error":
        raise RuntimeError("injected cleanup implementation failure")
    return result

def waitid(which, pid, flags):
    global reaped
    if os.getpid() == parent and fault == "external-reap":
        if reaped == pid:
            raise ChildProcessError(errno.ECHILD, "child already reaped")
        result = original_waitid(which, pid, flags)
        if reaped is None and result is not None:
            # The kernel really relinquishes the child here. Its independently
            # armed watch remains in the group until the owner pipe is closed.
            original_waitpid(pid, 0)
            reaped = pid
            record("external-reap", pid=pid)
            raise ChildProcessError(errno.ECHILD, "child already reaped")
        return result
    return original_waitid(which, pid, flags)

def kill(pid, number):
    record("kill", pid=pid, number=number)
    return original_kill(pid, number)

def killpg(pid, number):
    record("killpg", pid=pid, number=number)
    return original_killpg(pid, number)

def close(descriptor):
    global close_failed
    if os.getpid() == parent and calls and fault == "close-error" and not close_failed:
        close_failed = True
        record("close-error", descriptor=descriptor)
        raise OSError(errno.EIO, "injected descriptor close failure")
    return original_close(descriptor)

namespace["cleanup_preparer"] = cleanup
os.waitid = waitid
os.kill = kill
os.killpg = killpg
os.close = close
sys.argv = [source, executable, *arguments]
raise SystemExit(namespace["main"]())
'''

HELPER = r'''
import json, os, sys, time
from pathlib import Path
source, mode, argument = sys.argv[1:]
namespace = {"__name__": "rch_cleanup_helper_test"}
exec(compile(Path(source).read_bytes(), source, "exec"), namespace)
if mode == "non-child":
    pid = int(argument)
else:
    ready_read, ready_write = os.pipe()
    pid = os.fork()
    if pid == 0:
        os.close(ready_read)
        os.setsid()
        os.write(ready_write, b"1")
        os.close(ready_write)
        if mode == "exited-child":
            os._exit(7)
        time.sleep(10)
        os._exit(0)
    os.close(ready_write)
    assert os.read(ready_read, 1) == b"1"
    os.close(ready_read)
    if mode == "exited-child":
        os.waitid(os.P_PID, pid, os.WEXITED | os.WNOWAIT)
result = namespace["cleanup_preparer"](pid)
Path(argument if mode != "non-child" else os.environ["REPORT"]).write_text(json.dumps(result))
'''


@unittest.skipUnless(sys.platform == "linux" and hasattr(os, "pidfd_open"),
                     "requires Linux process handles and flock")
class CleanupGateTests(unittest.TestCase):
    def setUp(self):
        self.root = Path(tempfile.mkdtemp(prefix="rch-cleanup-gate-"))
        self.tools = self.root / "tools"
        self.tools.mkdir()
        launcher = self.tools / "cargo-rabs"
        launcher.write_text(PREPARE)
        launcher.chmod(0o700)
        self.cargo = self.tools / "cargo"
        cat = shlex.quote(shutil.which("cat"))
        env = shlex.quote(shutil.which("env"))
        self.cargo.write_text(
            '#!/bin/sh\n'
            'printf "%s\\n" "$$" >> "$TEST_ROOT/cargo.calls"\n'
            'printf "%s\\0" "$@" > "$TEST_ROOT/arguments"\n'
            'printf "%s\\n" "${PREPARED-no}" > "$TEST_ROOT/prepared"\n'
            + cat + ' > "$TEST_ROOT/input"\n'
            + env + ' -0 > "$TEST_ROOT/environment"\n'
            'printf "cargo stdout\\n"\nprintf "cargo stderr\\n" >&2\n'
            'if [ -n "${TEST_SIGNAL-}" ]; then kill -"$TEST_SIGNAL" "$$"; fi\n'
            'exit "${TEST_STATUS-0}"\n')
        self.cargo.chmod(0o700)
        self.driver = self.root / "driver.py"
        self.driver.write_text(DRIVER)
        self.env = {"PATH": str(self.tools), "HOME": str(self.root), "LC_ALL": "C",
                    "TEST_ROOT": str(self.root), "RCH_RABS_PREPARE_TIMEOUT_MS": "1500"}

    def run_adapter(self, fault="none", mode="success", args=("check",), data=b""):
        env = dict(self.env, TEST_FAULT=fault, TEST_PREPARE=mode)
        if mode == "hang":
            env["RCH_RABS_PREPARE_TIMEOUT_MS"] = "300"
        return subprocess.run([PYTHON, "-I", "-S", str(self.driver), str(ADAPTER),
                               str(self.cargo), *args], env=env, input=data,
                              capture_output=True, timeout=6)

    def events(self):
        path = self.root / "events"
        return [json.loads(line) for line in path.read_text().splitlines()] if path.exists() else []

    def assert_refused(self, result):
        self.assertEqual(result.returncode, 255, result.stderr)
        self.assertEqual(result.stdout, b"")
        self.assertFalse((self.root / "cargo.calls").exists())
        self.assertIn(b"cleanup is unconfirmed; Cargo was not run", result.stderr)
        self.assertNotIn(b"Traceback", result.stderr)

    def test_successful_preparation_cannot_bypass_unconfirmed_cleanup(self):
        for fault in ("pending", "error", "unexpected-error", "close-error"):
            with self.subTest(fault=fault):
                self.setUp()
                result = self.run_adapter(fault)
                self.assertTrue((self.root / "prepared.pid").exists())
                self.assertTrue(any(event["event"] == "settled" and event["result"]
                                    for event in self.events()), "real child cleanup must run")
                self.assert_refused(result)

    def test_failed_or_cancelled_preparation_cannot_authorize_a_cleanup_fallback(self):
        for mode in ("failure", "cancel", "hang"):
            for fault in ("pending", "error"):
                with self.subTest(mode=mode, fault=fault):
                    self.setUp()
                    self.assert_refused(self.run_adapter(fault, mode))

    def test_lost_child_ownership_neither_signals_the_old_id_nor_executes_cargo(self):
        result = self.run_adapter("external-reap")
        reaped = [event["pid"] for event in self.events() if event["event"] == "external-reap"]
        self.assertEqual(len(reaped), 1, "the driver must actually reap the child")
        signals = [event for event in self.events()
                   if event["event"] in ("kill", "killpg") and event["pid"] == reaped[0]]
        self.assertEqual(signals, [], "loss of wait ownership is not signal authority")
        self.assert_refused(result)

    def test_owner_pipe_still_retires_preparation_when_parent_cleanup_cannot_confirm(self):
        result = self.run_adapter("no-cleanup", "hang")
        self.assertTrue((self.root / "locked").exists(), "fixture must really acquire its lock")
        # The production watchdog, not the injected cleanup function, releases
        # this lock after the parent closes its ownership descriptor.
        with (self.root / "preparation.lock").open("a") as lock:
            deadline = time.monotonic() + 2
            while True:
                try:
                    fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    break
                except BlockingIOError:
                    self.assertLess(time.monotonic(), deadline, "preparation lock survived")
                    time.sleep(0.01)
        self.assert_refused(result)

    def test_confirmed_success_and_stock_fallback_preserve_original_command(self):
        arguments = ("+nightly", "test", "--", "", "literal ; $HOME", "line\nbreak", "日本語")
        for mode in ("success", "failure", "hang"):
            with self.subTest(mode=mode):
                self.setUp()
                self.env["TEST_STATUS"] = "23"
                result = self.run_adapter(mode=mode, args=arguments, data=b"input\0\xff\n")
                self.assertEqual(result.returncode, 23, result.stderr)
                self.assertEqual(result.stdout, b"cargo stdout\n")
                self.assertEqual(len((self.root / "cargo.calls").read_text().splitlines()), 1)
                self.assertEqual((self.root / "prepared").read_text(),
                                 "yes\n" if mode == "success" else "no\n")
                self.assertEqual((self.root / "arguments").read_bytes(),
                                 b"".join(arg.encode() + b"\0" for arg in arguments))
                self.assertEqual((self.root / "input").read_bytes(), b"input\0\xff\n")

    def test_confirmed_cancellation_and_compiler_signal_are_not_retried(self):
        result = self.run_adapter(mode="cancel")
        self.assertEqual(result.returncode, 130, result.stderr)
        self.assertFalse((self.root / "cargo.calls").exists())
        self.env["TEST_SIGNAL"] = str(signal.SIGTERM)
        result = self.run_adapter()
        self.assertEqual(result.returncode, -signal.SIGTERM, result.stderr)
        self.assertEqual(len((self.root / "cargo.calls").read_text().splitlines()), 1)

    def test_non_child_kernel_identity_is_not_a_cleanup_target(self):
        outsider = subprocess.Popen([PYTHON, "-I", "-S", "-c", "import time; time.sleep(15)"],
                                    start_new_session=True)
        handle = os.pidfd_open(outsider.pid)
        report = self.root / "non-child-result"
        try:
            result = subprocess.run([PYTHON, "-I", "-S", "-c", HELPER, str(ADAPTER),
                                     "non-child", str(outsider.pid)],
                                    env=dict(os.environ, REPORT=str(report)),
                                    capture_output=True, timeout=3)
            self.assertEqual(result.returncode, 0, result.stderr)
            poll = select.poll()
            poll.register(handle, select.POLLIN)
            self.assertEqual(poll.poll(100), [], "a non-child process was signalled")
            self.assertFalse(json.loads(report.read_text()))
        finally:
            try:
                signal.pidfd_send_signal(handle, signal.SIGKILL)
            except ProcessLookupError:
                pass
            os.close(handle)
            outsider.wait(timeout=3)

    def test_kernel_owned_running_and_unreaped_exited_children_can_be_cleaned(self):
        for mode in ("running-child", "exited-child"):
            with self.subTest(mode=mode):
                report = self.root / mode
                result = subprocess.run([PYTHON, "-I", "-S", "-c", HELPER,
                                         str(ADAPTER), mode, str(report)],
                                        capture_output=True, timeout=3)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertTrue(json.loads(report.read_text()))

    def test_blocked_diagnostic_pipe_does_not_release_cargo_or_hold_the_refusal(self):
        read, write = os.pipe()
        fcntl.fcntl(write, fcntl.F_SETPIPE_SZ, 4096)
        os.write(write, b"x" * 4096)
        process = subprocess.Popen([PYTHON, "-I", "-S", str(self.driver), str(ADAPTER),
                                    str(self.cargo), "check"],
                                   env=dict(self.env, TEST_FAULT="pending"),
                                   stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=write)
        handle = os.pidfd_open(process.pid)
        os.close(write)
        try:
            process.wait(timeout=4)
            self.assertEqual(process.returncode, 255)
            self.assertFalse((self.root / "cargo.calls").exists())
            self.assertEqual(process.stdout.read(), b"")
            os.set_blocking(read, False)
            self.assertEqual(os.read(read, 8192), b"x" * 4096)
            self.assertEqual(os.read(read, 8192), b"", "diagnostic relay still owns the pipe")
        finally:
            try:
                signal.pidfd_send_signal(handle, signal.SIGKILL)
            except ProcessLookupError:
                pass
            os.close(handle)
            process.communicate(timeout=3)
            os.close(read)


if __name__ == "__main__":
    unittest.main(verbosity=2)
