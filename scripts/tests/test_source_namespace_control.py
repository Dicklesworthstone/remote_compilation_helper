#!/usr/bin/env python3
"""Real subprocess tests of the namespace control boundary, not live SSH.

The actual production shell runs GNU timeout and real flock/FIFO descriptors.
A PATH double shortens only the timer's duration (and checks the production
execution and observer phase policies); it does not substitute locking, signaling, or output handling.
Owned fixtures are retained for inspection. The Rust target supplies compiled
CONTROL bytes and otherwise runs these same tests.
"""
from pathlib import Path
import fcntl
import os
import shlex
import shutil
import select
import signal
import subprocess
import sys
import tempfile
import time
import unittest

REPO = Path(__file__).resolve().parents[2]
CONTROL = Path(os.environ.get("RCH_TEST_SOURCE_NAMESPACE_CONTROL",
                             REPO / "rch/src/hook/source_namespace_control.sh"))
SHELL = os.environ.get("RCH_TEST_SHELL", "/bin/sh")
# The real timer must be GNU: uutils timeout does not kill the whole group.
TIMEOUT = shutil.which("gnutimeout") or shutil.which("gtimeout") or shutil.which("timeout")
FLOCK = shutil.which("flock")


@unittest.skipUnless(sys.platform.startswith("linux") and TIMEOUT and FLOCK,
                     "requires Linux, GNU timeout, and flock")
class SourceNamespaceControlTests(unittest.TestCase):
    def setUp(self):
        self.root = Path(tempfile.mkdtemp(prefix="rch-namespace-control-test-"))
        self.tools = self.root / "tools"
        self.tools.mkdir()
        self.tmp = self.root / "tmp"
        self.tmp.mkdir()
        self.calls = self.root / "timer-calls"
        timer = ("#!/bin/sh\nset -eu\n"
                 '[ "$1" = --kill-after=1 ] || exit 96\n'
                 'case "$2:$3" in\n'
                 '  1:mktemp) ;;\n'
                 '  15:sh) [ "${6-}" = rch-namespace-monitor ] || exit 96 ;;\n'
                 '  2:sh) [ "${6-}" = rch-namespace-delivery ] || exit 96 ;;\n'
                 '  1:sh) [ "${6-}" = rch-namespace-cleanup ] || exit 96 ;;\n'
                 '  *) exit 96 ;;\nesac\n'
                 'printf "%s %s\\n" "$2" "$3" >> "$RCH_TIMER_CALLS"\nshift 2\n'
                 'exec ' + shlex.quote(TIMEOUT) + ' --kill-after=0.15 0.6 "$@"\n')
        for name in ("timeout", "gtimeout", "gnutimeout"):
            path = self.tools / name
            path.write_text(timer)
            path.chmod(0o700)
        # All nested `sh` invocations use the selected interpreter too, not
        # merely the outer shell while the substantive helper always uses dash.
        shell = self.tools / "sh"
        shell.write_text("#!/bin/sh\nexec " + shlex.quote(SHELL) + ' "$@"\n')
        shell.chmod(0o700)
        self.env = {**os.environ, "TMPDIR": str(self.tmp), "LC_ALL": "C",
                    "PATH": str(self.tools) + os.pathsep + os.environ["PATH"],
                    "RCH_TIMER_CALLS": str(self.calls)}
        self.script = CONTROL.read_text()

    def run_control(self, program):
        started = time.monotonic()
        result = subprocess.run([SHELL, "-c", self.script], input=program.encode(),
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                env=self.env, timeout=5, check=False)
        self.assertLess(time.monotonic() - started, 3, result.stderr)
        calls = self.calls.read_text().splitlines()
        self.assertEqual(calls[:2], ["1 mktemp", "15 sh"])
        self.assertEqual(calls[-1], "1 sh")
        self.assertIn(calls[2:-1], ([], ["2 sh"]))
        return result

    def assert_no_control_processes(self, root=None):
        # Test-owned children publish their PID. pidfds pin the cleanup target
        # so even a regression cannot signal an unrelated reused numeric PID.
        for pidfile in (root or self.root).glob("*.pid"):
            pid = int(pidfile.read_text())
            try:
                descriptor = os.pidfd_open(pid)
            except ProcessLookupError:
                continue
            try:
                # Group KILL and timeout's own exit are observed separately.
                # Wait on the pinned process, never rely on container init
                # promptly reaping a zombie or all CPUs scheduling together.
                exited = select.poll()
                exited.register(descriptor, select.POLLIN)
                alive = not exited.poll(1000)
                if alive:
                    signal.pidfd_send_signal(descriptor, signal.SIGKILL)
                self.assertFalse(alive, f"namespace child survived deadline: {pidfile}")
            except FileNotFoundError:
                pass
            finally:
                os.close(descriptor)

    def sleeper(self, stdout=True, stderr=True, lock=None):
        # This child stays in the namespace control group. No workload or
        # production owner is involved. It ignores TERM to require escalation.
        pidfile = self.root / "sleeper.pid"
        program = ("import os, signal, time, fcntl\n"
                   "signal.signal(signal.SIGTERM, signal.SIG_IGN)\n"
                   "signal.signal(signal.SIGHUP, signal.SIG_IGN)\n"
                   f"open({str(pidfile)!r}, 'w').write(str(os.getpid()))\n")
        if not stdout:
            program += "os.close(1)\n"
        if not stderr:
            program += "os.close(2)\n"
        if lock:
            program += (f"lock = open({str(lock)!r}, 'a')\n"
                        "fcntl.flock(lock, fcntl.LOCK_EX)\n"
                        f"open({str(self.root / 'lock-acquired')!r}, 'w').write('held')\n")
        program += "time.sleep(30)\n"
        self.addCleanup(self.assert_no_control_processes, self.root)
        return shlex.quote(sys.executable) + " -I -S -c " + shlex.quote(program)

    def test_success_is_byte_exact_and_normal_temporary_files_are_removed(self):
        result = self.run_control("printf 'diagnostic\\n' >&2\nprintf 'RCH_TOPOLOGY_OK\\n'\n")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, b"RCH_TOPOLOGY_OK\n")
        self.assertEqual(result.stderr, b"diagnostic\n")
        self.assertEqual(list(self.tmp.iterdir()), [])

    def test_large_bootstrap_stays_on_stdin(self):
        program = ("#" + "x" * 2048 + "\n") * 100 + "printf 'RCH_TOPOLOGY_OK\\n'\n"
        self.assertGreater(len(program), 131072)
        result = self.run_control(program)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, b"RCH_TOPOLOGY_OK\n")

    def test_missing_timer_refuses_before_the_program_runs(self):
        empty_path = self.root / "no-tools"
        empty_path.mkdir()
        mutation = self.root / "must-not-exist"
        result = subprocess.run([SHELL, "-c", self.script],
                                input=("echo wrote > " + shlex.quote(str(mutation))).encode(),
                                capture_output=True, timeout=3, check=False,
                                env={**self.env, "PATH": str(empty_path)})
        self.assertEqual(result.returncode, 73)
        self.assertEqual(result.stdout, b"")
        self.assertIn(b"requires GNU timeout", result.stderr)
        self.assertFalse(mutation.exists())

    def test_failed_program_cannot_publish_its_premature_ready_marker(self):
        result = self.run_control("printf 'RCH_TOPOLOGY_OK\\n'; printf refusal >&2; exit 75\n")
        self.assertEqual(result.returncode, 75, result.stderr)
        self.assertEqual(result.stdout, b"")
        self.assertEqual(result.stderr, b"refusal")

    def test_malformed_success_is_not_repaired_into_readiness(self):
        for text in (b"", b"RCH_TOPOLOGY_OK", b"RCH_TOPOLOGY_OK\n\n",
                     b"RCH_TOPOLOGY_OK\x00\n", b"noise\nRCH_TOPOLOGY_OK\n"):
            with self.subTest(text=text):
                # Each invocation has its own policy/call-count fixture.
                self.setUp()
                program = (shlex.quote(sys.executable) + " -I -S -c " +
                           shlex.quote(f"import os; os.write(1, {text!r})") + "\n")
                result = self.run_control(program)
                self.assertEqual(result.returncode, 73, result.stderr)
                self.assertEqual(result.stdout, b"")

    def test_output_limits_detect_overflow_not_only_a_valid_prefix(self):
        for descriptor, count in ((1, 4097), (2, 65537)):
            with self.subTest(descriptor=descriptor):
                self.setUp()
                code = (f"import os; os.write({descriptor}, b'x' * {count}); "
                        "os.write(1, b'RCH_TOPOLOGY_OK\\n')")
                result = self.run_control(shlex.quote(sys.executable) + " -I -S -c " + shlex.quote(code))
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(result.stdout, b"")
                self.assertLessEqual(len(result.stderr), 65536)

    def test_exact_stderr_bound_is_accepted_without_truncation(self):
        code = "import os; os.write(2, b'x' * 65536); os.write(1, b'RCH_TOPOLOGY_OK\\n')"
        result = self.run_control(shlex.quote(sys.executable) + " -I -S -c " + shlex.quote(code))
        self.assertEqual(result.returncode, 0, result.stderr[:100])
        self.assertEqual(result.stderr, b"x" * 65536)
        self.assertEqual(result.stdout, b"RCH_TOPOLOGY_OK\n")

    def test_term_resistant_mutator_is_killed_before_client_deadline(self):
        result = self.run_control(self.sleeper() + "\nprintf 'RCH_TOPOLOGY_OK\\n'\n")
        self.assertTrue((self.root / "sleeper.pid").exists(), "mutator must actually start")
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(result.stdout, b"")

    def test_successful_parent_does_not_leave_pipe_holding_descendants(self):
        for stdout, stderr in ((True, False), (False, True), (True, True)):
            with self.subTest(stdout=stdout, stderr=stderr):
                self.setUp()
                result = self.run_control(self.sleeper(stdout, stderr) +
                                          " &\nprintf 'RCH_TOPOLOGY_OK\\n'\n")
                self.assertTrue((self.root / "sleeper.pid").exists(), "descendant must actually start")
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(result.stdout, b"")
                self.assert_no_control_processes()

    def test_queued_initializer_cannot_mutate_after_timeout_and_lock_release(self):
        lock_path = self.root / "metadata.lock"
        created = self.root / "late-initialization"
        with lock_path.open("a") as held:
            fcntl.flock(held, fcntl.LOCK_EX)
            command = ("echo $$ > " + shlex.quote(str(self.root / "waiter.pid")) +
                       "\nexec " + FLOCK + " -x " + shlex.quote(str(lock_path)) + " sh -c " +
                       shlex.quote("mkdir " + shlex.quote(str(created)) +
                                   "; printf 'RCH_TOPOLOGY_OK\\n'"))
            result = self.run_control(command)
            self.assertNotEqual(result.returncode, 0)
            self.assertEqual(result.stdout, b"")
            self.assertTrue((self.root / "waiter.pid").exists())
            self.assert_no_control_processes()
            with lock_path.open("a") as probe:
                with self.assertRaises(BlockingIOError):
                    fcntl.flock(probe, fcntl.LOCK_EX | fcntl.LOCK_NB)
        # A leaked flock waiter would now acquire and execute its late mutator.
        time.sleep(0.2)
        self.assertFalse(created.exists())
        with lock_path.open("a") as probe:
            fcntl.flock(probe, fcntl.LOCK_EX | fcntl.LOCK_NB)

    def test_pipe_holding_child_releases_its_real_registry_lock_on_timeout(self):
        lock = self.root / "metadata.lock"
        result = self.run_control(self.sleeper(False, True, lock) +
                                  " &\nprintf 'RCH_TOPOLOGY_OK\\n'\n")
        self.assertTrue((self.root / "sleeper.pid").exists(), "lock holder must actually start")
        self.assertTrue((self.root / "lock-acquired").exists(), "child must actually hold the lock")
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(result.stdout, b"")
        self.assert_no_control_processes()
        with lock.open("a") as probe:
            fcntl.flock(probe, fcntl.LOCK_EX | fcntl.LOCK_NB)

    def test_deadline_includes_incomplete_stdin_program(self):
        child = subprocess.Popen([SHELL, "-c", self.script], stdin=subprocess.PIPE,
                                 stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=self.env)
        try:
            # Leave stdin OPEN with an incomplete compound command; the worker
            # must time out parsing it, not wait forever for the SSH transport.
            child.stdin.write(b"{\n")
            child.stdin.flush()
            child.wait(timeout=3)
            stdout = child.stdout.read()
            self.assertNotEqual(child.returncode, 0)
            self.assertEqual(stdout, b"")
        finally:
            child.stdin.close()
            if child.poll() is None:
                child.kill()
            child.wait(timeout=5)
            child.stdout.close()
            child.stderr.close()


if __name__ == "__main__":
    unittest.main(verbosity=2)
