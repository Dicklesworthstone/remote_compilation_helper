#!/usr/bin/env python3
"""Actual adapter/OS regressions; installed preparation and Cargo are doubles.

No Rust compilation, SSH, cache hit or fleet-performance claim. Filled pipes
have real blocked readers, not mocked write/select implementations.
"""

import errno
import fcntl
import importlib.util
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import time
import unittest
from unittest import mock


ADAPTER = Path(os.environ.get("RABS_TEST_WORKER_ADAPTER", str(
    Path(__file__).resolve().parents[1] / "rch-common/src/toolchain/worker_cache.py")))
CARGO = r'''
import fcntl, json, os, pathlib, signal, sys
root = pathlib.Path(os.environ["TEST_ROOT"])
try:
    children = os.waitpid(-1, os.WNOHANG)
except ChildProcessError:
    children = None
value = {"argv": sys.argv[1:], "pid": os.getpid(),
         "activated": os.environ.get("ACTIVATED"),
         "stderr_flags": fcntl.fcntl(2, fcntl.F_GETFL),
         "children": children}
if os.environ.get("TEST_STDIN"):
    value["stdin"] = sys.stdin.buffer.read().hex()
if os.environ.get("TEST_JOBSERVER"):
    value["jobserver"] = os.read(int(os.environ["TEST_JOBSERVER"]), 1).hex()
with open(root / "cargo-events", "a") as stream:
    stream.write(json.dumps(value) + "\n")
print(json.dumps(value), flush=True)
if os.environ.get("TEST_CARGO_SIGNAL"):
    os.kill(os.getpid(), int(os.environ["TEST_CARGO_SIGNAL"]))
sys.exit(int(os.environ.get("TEST_CARGO_STATUS", "0")))
'''
GOOD = '''
def prepare(env, no_start):
    import os
    print("prepared diagnostic", flush=True)
    env["ACTIVATED"] = "yes"
    return env
'''


@unittest.skipUnless(sys.platform == "linux", "Linux fork, WNOWAIT and descriptor custody")
class DiagnosticTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="rabs-diagnostics-")
        self.root = Path(self.temporary.name)
        self.launcher = self.root / "cargo-rabs"
        self.cargo = self.root / "cargo.py"
        self.cargo.write_text(CARGO)
        self.env = dict(os.environ, TEST_ROOT=str(self.root),
                        PATH=str(self.root) + os.pathsep + os.defpath,
                        RCH_RABS_WORKER_ACTIVE="0", RCH_RABS_PREPARE_TIMEOUT_MS="300")
        for name in ("ACTIVATED", "TEST_STDIN", "TEST_JOBSERVER", "TEST_CARGO_STATUS",
                     "TEST_CARGO_SIGNAL"):
            self.env.pop(name, None)
        self.children = []
        self.descriptors = []
        self.install(GOOD)

    def tearDown(self):
        for child in self.children:
            if child.poll() is None:
                child.terminate()
                try:
                    child.wait(timeout=1)
                except subprocess.TimeoutExpired:
                    child.kill()
                    child.wait(timeout=2)
            for stream in (child.stdout, child.stderr, child.stdin):
                if stream is not None:
                    stream.close()
        for descriptor in self.descriptors:
            os.close(descriptor)
        self.temporary.cleanup()

    def install(self, body):
        self.launcher.write_text("RCH_WORKER_PREPARATION_API = 1\n" + body)
        self.launcher.chmod(0o700)

    def filled_pipe(self):
        reader, writer = os.pipe()
        self.descriptors.extend((reader, writer))
        os.set_blocking(writer, False)
        while True:
            try:
                os.write(writer, b"x" * 4096)
            except BlockingIOError:
                break
        os.set_blocking(writer, True)
        return reader, writer

    def start(self, stderr=subprocess.PIPE, env=None, args=(), pass_fds=(), stdin=None, driver=False):
        entrypoint = ADAPTER
        if driver:
            # Observe actual fork results, without substituting fork, wait, I/O
            # or signal behavior. /proc task/children is not universal in Linux
            # sandboxes; a recorded unreaped child plus pidfd provides this cut.
            entrypoint = self.root / "driver.py"
            entrypoint.write_text('import importlib.util, os, sys\n'
                'spec = importlib.util.spec_from_file_location("adapter", ' + repr(str(ADAPTER)) + ')\n'
                'module = importlib.util.module_from_spec(spec)\nspec.loader.exec_module(module)\n'
                'native_fork = os.fork\ndef record_fork():\n    pid = native_fork()\n'
                '    if pid:\n        with open("fork-events", "a") as stream:\n'
                '            stream.write(str(pid) + "\\n")\n    return pid\n'
                'os.fork = record_fork\nsys.exit(module.main())\n')
        child = subprocess.Popen(
            [sys.executable, "-S", str(entrypoint), sys.executable, "-S", str(self.cargo)] + list(args),
            env=dict(self.env, **(env or {})), cwd=self.root, stdin=stdin,
            stdout=subprocess.PIPE, stderr=stderr, pass_fds=pass_fds,
        )
        self.children.append(child)
        return child

    def outcome(self, child, payload=None, status=0):
        output, errors = child.communicate(payload, timeout=3)
        self.assertEqual(child.returncode, status, errors)
        records = (self.root / "cargo-events").read_text().splitlines()
        self.assertEqual(len(records), 1, "exactly one Cargo execution")
        value = json.loads(records[0])
        self.assertEqual(value["pid"], child.pid, "exec preserves process identity")
        self.assertIsNone(value["children"], "no detached setup or logging child")
        self.assertEqual(json.loads(output), value, "setup cannot pollute Cargo JSON stdout")
        return value, errors

    def test_full_stderr_cannot_block_successful_preparation(self):
        _, writer = self.filled_pipe()
        flags = fcntl.fcntl(writer, fcntl.F_GETFL)
        value, _ = self.outcome(self.start(stderr=writer))
        self.assertEqual(value["activated"], "yes")
        self.assertEqual(value["stderr_flags"], flags)
        self.assertEqual(fcntl.fcntl(writer, fcntl.F_GETFL), flags)

    def test_full_stderr_cannot_block_failed_preparation(self):
        self.install('def prepare(env, no_start):\n    raise RuntimeError("refused")\n')
        _, writer = self.filled_pipe()
        value, _ = self.outcome(self.start(stderr=writer, env={"TEST_CARGO_STATUS": "101"}), status=101)
        self.assertIsNone(value["activated"])

    def test_full_stderr_cannot_block_outer_timeout(self):
        self.install('import time\nprint("import started", flush=True)\ntime.sleep(30)\n')
        _, writer = self.filled_pipe()
        value, _ = self.outcome(self.start(stderr=writer))
        self.assertIsNone(value["activated"])

    def test_full_stderr_cannot_block_system_exit_fallback(self):
        self.install('raise SystemExit(23)\n')
        _, writer = self.filled_pipe()
        value, _ = self.outcome(self.start(stderr=writer))
        self.assertIsNone(value["activated"])

    def test_broken_stderr_reader_does_not_fail_cargo(self):
        reader, writer = os.pipe()
        os.close(reader)
        self.descriptors.append(writer)
        self.assertEqual(self.outcome(self.start(stderr=writer))[0]["activated"], "yes")

    def test_raw_diagnostics_remain_byte_exact_and_off_stdout(self):
        self.install('def prepare(env, no_start):\n    import os\n'
                     '    os.write(1, b"out\\x00\\xff\\n")\n'
                     '    os.write(2, b"err\\xfe\\n")\n    return env\n')
        _, errors = self.outcome(self.start())
        self.assertEqual(errors, b"out\x00\xff\nerr\xfe\n")

    def test_log_flood_keeps_existing_capture_bound_and_truncation_notice(self):
        self.install('def prepare(env, no_start):\n    import os\n'
                     '    for _ in range(128):\n        os.write(2, b"x" * 4096)\n'
                     '    return env\n')
        _, errors = self.outcome(self.start(env={"RCH_RABS_PREPARE_TIMEOUT_MS": "1500"}))
        self.assertEqual(errors, b"x" * (16 * 1024) + b"rch: RABS preparation diagnostics truncated\n")

    def test_regular_stderr_preserves_existing_prefix_and_shared_offset(self):
        path = self.root / "diagnostics"
        with path.open("w+b") as stream:
            stream.write(b"previous log\n")
            stream.flush()
            self.outcome(self.start(stderr=stream))
            self.assertEqual(stream.tell(), len(b"previous log\nprepared diagnostic\n"))
        self.assertEqual(path.read_bytes(), b"previous log\nprepared diagnostic\n")

    def test_stalled_diagnostics_preserve_stdin_argv_and_jobserver(self):
        _, writer = self.filled_pipe()
        job_read, job_write = os.pipe()
        self.descriptors.extend((job_read, job_write))
        os.write(job_write, b"+")
        args = ["test", "--", "", "a b", "λ雪", "$(never run)"]
        payload = b"stdin\0\xff\n"
        value, _ = self.outcome(self.start(stderr=writer, args=args,
            env={"TEST_STDIN": "1", "TEST_JOBSERVER": str(job_read)},
            pass_fds=(job_read, job_write), stdin=subprocess.PIPE), payload)
        self.assertEqual(value["argv"], args)
        self.assertEqual(value["stdin"], payload.hex())
        self.assertEqual(value["jobserver"], b"+".hex())

    def test_cargo_signal_after_stalled_logging_is_not_retried(self):
        _, writer = self.filled_pipe()
        self.outcome(self.start(stderr=writer, env={"TEST_CARGO_SIGNAL": str(signal.SIGTERM)}),
                     status=-signal.SIGTERM)

    def cancel_during_relay(self, number):
        # Identify the relay by excluding the preparation child's recorded PID.
        # All process identities are this test's live descendants; no historical
        # PID is treated as signal authority.
        self.install('def prepare(env, no_start):\n    import os, pathlib\n'
                     '    pathlib.Path(env["TEST_ROOT"], "preparer").write_text(str(os.getpid()))\n'
                     '    print("ready", flush=True)\n    return env\n')
        _, writer = self.filled_pipe()
        child = self.start(stderr=writer, driver=True)
        deadline = time.monotonic() + 2
        relay = None
        while time.monotonic() < deadline and child.poll() is None:
            try:
                preparer = int((self.root / "preparer").read_text())
                children = (self.root / "fork-events").read_text()
                relay = next((int(pid) for pid in children.split() if int(pid) != preparer), None)
            except (FileNotFoundError, ValueError, ProcessLookupError):
                pass
            if relay is not None:
                break
            time.sleep(0.001)
        self.assertIsNotNone(relay, "must reach the real blocked relay cut")
        descriptor = os.pidfd_open(relay)
        try:
            child.send_signal(number)
            child.communicate(timeout=2)
            self.assertEqual(child.returncode, 128 + number)
            self.assertFalse((self.root / "cargo-events").exists())
            import select
            self.assertTrue(select.select([descriptor], [], [], 1)[0], "relay must exit")
        finally:
            os.close(descriptor)

    def test_term_during_relay_never_execs_cargo_or_leaves_a_child(self):
        self.cancel_during_relay(signal.SIGTERM)

    def test_int_during_relay_never_execs_cargo_or_leaves_a_child(self):
        self.cancel_during_relay(signal.SIGINT)

    def test_hup_during_relay_never_execs_cargo_or_leaves_a_child(self):
        self.cancel_during_relay(signal.SIGHUP)

    def test_relay_resource_failure_is_silent_and_restores_signal_mask(self):
        spec = importlib.util.spec_from_file_location("worker_diagnostic_test", ADAPTER)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        before = signal.pthread_sigmask(signal.SIG_BLOCK, [])
        with mock.patch.object(module.os, "fork", side_effect=OSError(errno.EAGAIN, "limit")):
            module.replay_diagnostics(b"cannot create a relay")
        self.assertEqual(signal.pthread_sigmask(signal.SIG_BLOCK, []), before)
        with mock.patch.object(module.os, "fork", side_effect=AssertionError("silent path forked")):
            module.replay_diagnostics(b"")

    def test_auto_reap_refuses_before_fork_and_preserves_original_environment(self):
        spec = importlib.util.spec_from_file_location("worker_reaper_test", ADAPTER)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        previous = signal.signal(signal.SIGCHLD, signal.SIG_IGN)
        try:
            with mock.patch.object(module.os, "fork", side_effect=AssertionError("unsafe fork")):
                original = dict(self.env)
                self.assertIs(module.bounded_prepared_environment(original), original)
                module.replay_diagnostics(b"not an owned reaper")
                self.assertEqual(signal.getsignal(signal.SIGCHLD), signal.SIG_IGN)
        finally:
            signal.signal(signal.SIGCHLD, previous)

    def test_custom_child_reaper_is_not_replaced_or_allowed_to_steal_ownership(self):
        spec = importlib.util.spec_from_file_location("worker_custom_reaper_test", ADAPTER)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        handler = lambda *_: None
        previous = signal.signal(signal.SIGCHLD, handler)
        try:
            with mock.patch.object(module.os, "fork", side_effect=AssertionError("unsafe fork")):
                original = dict(self.env)
                self.assertIs(module.bounded_prepared_environment(original), original)
                module.replay_diagnostics(b"not an owned reaper")
                self.assertIs(signal.getsignal(signal.SIGCHLD), handler)
        finally:
            signal.signal(signal.SIGCHLD, previous)


if __name__ == "__main__":
    unittest.main()
