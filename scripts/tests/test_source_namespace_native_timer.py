#!/usr/bin/env python3
"""Run the shipped namespace boundary without GNU timeout.

These are real POSIX processes, pipes and kernel locks; no replacement timeout
or fake signaling implementation is used. Fixtures are retained for inspection.
Linux-only pidfds make regression cleanup independent of numeric PID reuse.
"""
from pathlib import Path
import fcntl
import os
import select
import shlex
import shutil
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
PYTHON = sys.executable
READY = b"RCH_TOPOLOGY_OK\n"
# uutils cat (Ubuntu 25.10+ /usr/bin/cat) enlarges its output pipe for a splice
# fast path, so a pinned 4 KiB pipe never stalls it. The stalled-delivery test
# needs GNU cat, g-prefixed where uutils is the default.
GNU_CAT = next((path for path in map(shutil.which, ("gnucat", "gcat", "cat"))
                if path and b"GNU coreutils" in subprocess.run(
                    [path, "--version"], capture_output=True, timeout=3, check=False).stdout),
               None)


@unittest.skipUnless(sys.platform == "linux" and hasattr(os, "pidfd_open"),
                     "native Linux process/lock controls require pidfds")
class NativeTimerTests(unittest.TestCase):
    def setUp(self):
        self.root = Path(tempfile.mkdtemp(prefix="rch-native-namespace-"))
        self.tools = self.root / "tools"
        self.tools.mkdir()
        self.tmp = self.root / "tmp"
        self.tmp.mkdir()
        for name in ("mktemp", "ps", "head", "grep", "mkfifo", "wc", "cmp",
                     "cat", "mv", "rm", "rmdir", "sleep"):
            executable = shutil.which(name)
            self.assertIsNotNone(executable, name)
            (self.tools / name).symlink_to(executable)
        (self.tools / "sh").symlink_to(SHELL)
        (self.tools / "python3").symlink_to(PYTHON)
        # A non-GNU timeout must not be used merely because one exists.
        timeout = self.tools / "timeout"
        timeout.write_text("#!/bin/sh\n[ \"$1\" = --version ] || exit 97\nprintf 'timeout (uutils)\\n'\n")
        timeout.chmod(0o700)
        self.env = {"PATH": str(self.tools), "HOME": str(self.root),
                    "TMPDIR": str(self.tmp), "LC_ALL": "C"}
        self.script = CONTROL.read_text()
        self.pinned = []
        self.addCleanup(self.check_pinned_children)

    def run_control(self, program, **kwargs):
        return subprocess.run([SHELL, "-c", self.script], input=program,
                              capture_output=True, env=self.env, timeout=22, **kwargs)

    def python_command(self, code):
        return shlex.quote(PYTHON) + " -I -S -c " + shlex.quote(code)

    def pin_pidfile(self, path, process):
        deadline = time.monotonic() + 5
        while True:
            try:
                pid = int(path.read_text())
                descriptor = os.pidfd_open(pid)
                self.pinned.append((descriptor, path))
                return pid
            except (FileNotFoundError, ValueError):
                self.assertIsNone(process.poll(), "fixture exited before publishing its PID")
                self.assertLess(time.monotonic(), deadline, str(path))
                time.sleep(0.01)

    def check_pinned_children(self):
        survivors = []
        for descriptor, path in self.pinned:
            try:
                poll = select.poll()
                poll.register(descriptor, select.POLLIN)
                if not poll.poll(1500):
                    survivors.append(str(path))
                    signal.pidfd_send_signal(descriptor, signal.SIGKILL)
            finally:
                os.close(descriptor)
        self.pinned.clear()
        self.assertEqual(survivors, [], "native timer left an executing fixture")

    def group_fixture(self):
        # The direct child keeps TERM's default action. Its descendant ignores
        # TERM/HUP/INT, retains both pipes and owns a real flock until group KILL.
        descendant = self.python_command(
            "import fcntl, os, signal, time\n"
            "for s in (signal.SIGTERM, signal.SIGHUP, signal.SIGINT): signal.signal(s, signal.SIG_IGN)\n"
            f"lock = open({str(self.root / 'owned.lock')!r}, 'a')\n"
            "fcntl.flock(lock, fcntl.LOCK_EX)\n"
            f"open({str(self.root / 'descendant.pid')!r}, 'w').write(str(os.getpid()))\n"
            "time.sleep(30)\n")
        return descendant + " &\nwait\n"

    def start_timer(self, program, seconds="1"):
        # Execute the exact production function, not a Python model. Keep the
        # public-boundary tests below separate from this timer contract probe.
        prefix = self.script.split("# GNU timeout kills", 1)[0]
        command = (prefix + "\n(rch_namespace_python_timer --kill-after=1 " +
                   seconds + " sh -c " + shlex.quote(program) + ")")
        process = subprocess.Popen([SHELL, "-c", command], stdin=subprocess.DEVNULL,
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                   env=self.env)
        self.addCleanup(self.finish_process, process)
        return process

    @staticmethod
    def finish_process(process):
        if process.poll() is None:
            process.kill()
        process.communicate(timeout=5)

    def assert_lock_released(self):
        with (self.root / "owned.lock").open("a") as lock:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)

    def test_success_and_refusal_use_native_backend_without_changing_bytes(self):
        for status in (0, 7, 75, 125):
            with self.subTest(status=status):
                result = self.run_control(
                    b"printf 'diagnostic\\n' >&2\nprintf 'RCH_TOPOLOGY_OK\\n'\nexit " +
                    str(status).encode() + b"\n")
                self.assertEqual(result.returncode, status, result.stderr)
                self.assertEqual(result.stdout, READY if status == 0 else b"")
                self.assertEqual(result.stderr, b"diagnostic\n")
        self.assertEqual(list(self.tmp.iterdir()), [])

    def test_gnu_remains_preferred_without_starting_python(self):
        timer = shutil.which("gnutimeout") or shutil.which("gtimeout") or shutil.which("timeout")
        if not timer:
            self.skipTest("GNU preference control requires GNU timeout")
        version = subprocess.run([timer, "--version"], capture_output=True, timeout=3)
        if b"GNU coreutils" not in version.stdout:
            self.skipTest("the discovered timer is not GNU timeout")
        (self.tools / "gnutimeout").symlink_to(timer)
        (self.tools / "python3").rename(self.tools / "retained-python3")
        forbidden = self.root / "python-started"
        python = self.tools / "python3"
        python.write_text("#!/bin/sh\nprintf forbidden > " + shlex.quote(str(forbidden)) + "\nexit 99\n")
        python.chmod(0o700)
        result = self.run_control(b"printf 'RCH_TOPOLOGY_OK\\n'\n")
        self.assertEqual((result.returncode, result.stdout, result.stderr), (0, READY, b""))
        self.assertFalse(forbidden.exists())

    def test_fixed_timer_abi_refuses_unknown_options_before_execution(self):
        prefix = self.script.split("# GNU timeout kills", 1)[0]
        forbidden = self.root / "must-not-run"
        payload = ["sh", "-c", "printf forbidden > " + shlex.quote(str(forbidden))]
        for arguments in (["--foreground", "1"] + payload,
                          ["--kill-after=1", "0"] + payload,
                          ["--kill-after=1", "-1"] + payload,
                          ["--kill-after=1", "0.2"] + payload,
                          ["--kill-after=1", "1"]):
            with self.subTest(arguments=arguments[:2]):
                command = prefix + "\n(rch_namespace_python_timer " + shlex.join(arguments) + ")"
                result = subprocess.run([SHELL, "-c", command], capture_output=True,
                                        env=self.env, timeout=3)
                self.assertEqual(result.returncode, 73, result.stderr)
                self.assertFalse(forbidden.exists())
        command = prefix + "\n(rch_namespace_python_timer --kill-after=1 1 missing-rch-test-executable)"
        result = subprocess.run([SHELL, "-c", command], capture_output=True,
                                env=self.env, timeout=3)
        self.assertEqual((result.returncode, result.stdout, result.stderr), (127, b"", b""))

    def test_success_and_refusal_retire_quiet_descendants_before_reply(self):
        for status in (0, 75):
            with self.subTest(status=status):
                pidfile = self.root / f"quiet-{status}.pid"
                gate = self.root / f"reply-{status}.gate"
                descendant = self.python_command(
                    "import fcntl, os, signal, time\n"
                    "for s in (signal.SIGHUP, signal.SIGINT, signal.SIGTERM): signal.signal(s, signal.SIG_IGN)\n"
                    "os.close(1); os.close(2)\n"
                    f"lock = open({str(self.root / 'owned.lock')!r}, 'a')\n"
                    "fcntl.flock(lock, fcntl.LOCK_EX)\n"
                    f"open({str(pidfile)!r}, 'w').write(str(os.getpid()))\n"
                    "time.sleep(30)\n")
                program = (descendant + " &\nwhile [ ! -s " + shlex.quote(str(gate)) +
                           " ]; do sleep 0.01; done\nprintf 'RCH_TOPOLOGY_OK\\n'\n" +
                           f"exit {status}\n")
                process = subprocess.Popen([SHELL, "-c", self.script], stdin=subprocess.PIPE,
                                           stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                           env=self.env)
                self.addCleanup(self.finish_process, process)
                process.stdin.write(program.encode())
                process.stdin.close()
                process.stdin = None
                self.pin_pidfile(pidfile, process)
                with (self.root / "owned.lock").open("a") as lock:
                    with self.assertRaises(BlockingIOError):
                        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
                gate.write_text("release")
                stdout, stderr = process.communicate(timeout=5)
                self.assertEqual(process.returncode, status, stderr)
                self.assertEqual(stdout, READY if status == 0 else b"")
                self.assertEqual(stderr, b"")
                self.check_pinned_children()
                self.assert_lock_released()

    def test_large_script_and_inherited_authority_descriptor_are_preserved(self):
        authority = self.root / "authority"
        authority.write_bytes(b"authority-bytes\x00not-stdin")
        with authority.open("rb") as file:
            descriptor = fcntl.fcntl(file, fcntl.F_DUPFD, 10)
            try:
                code = (f"import os; assert os.read({descriptor}, 100) == b'authority-bytes\\x00not-stdin'; "
                        "os.write(1, b'RCH_TOPOLOGY_OK\\n')")
                program = ("#" + "x" * 2048 + "\n") * 130 + self.python_command(code)
                self.assertGreater(len(program), 262144)
                result = self.run_control(program.encode(), pass_fds=(descriptor,))
            finally:
                os.close(descriptor)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, READY)

    def test_malformed_and_overflow_output_never_become_readiness(self):
        cases = [(1, b""), (1, READY[:-1]), (1, READY + b"\n"),
                 (1, b"RCH_TOPOLOGY_OK\x00\n"), (1, b"x" * 4097),
                 (2, b"x" * 65537)]
        for descriptor, payload in cases:
            with self.subTest(descriptor=descriptor, size=len(payload)):
                code = f"import os; os.write({descriptor}, {payload!r})"
                if descriptor == 2:
                    code += "; os.write(1, b'RCH_TOPOLOGY_OK\\n')"
                result = self.run_control((self.python_command(code) + "\n").encode())
                self.assertNotEqual(result.returncode, 0, result.stderr[:200])
                self.assertEqual(result.stdout, b"")
        code = "import os; os.write(2, b'x' * 65536); os.write(1, b'RCH_TOPOLOGY_OK\\n')"
        result = self.run_control(self.python_command(code).encode())
        self.assertEqual(result.returncode, 0, result.stderr[:200])
        self.assertEqual(result.stdout, READY)
        self.assertEqual(result.stderr, b"x" * 65536)

    def test_deadline_kills_descendant_after_direct_child_dies_from_term(self):
        started = time.monotonic()
        process = self.start_timer(self.group_fixture())
        self.pin_pidfile(self.root / "descendant.pid", process)
        with (self.root / "owned.lock").open("a") as lock:
            with self.assertRaises(BlockingIOError):
                fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        process.communicate(timeout=5)
        self.assertEqual(process.returncode, 137)
        self.assertLess(time.monotonic() - started, 5)
        self.check_pinned_children()
        self.assert_lock_released()

    def test_external_signals_reach_timer_group_without_touching_caller(self):
        for signum in (signal.SIGHUP, signal.SIGINT, signal.SIGTERM):
            with self.subTest(signal=signum):
                # A fresh directory avoids interpreting an earlier PID file.
                if signum != signal.SIGHUP:
                    self.setUp()
                program = self.group_fixture()
                # exec the timer function's subshell through a new outer shell;
                # the descendant's live group names the timer, not its caller.
                process = self.start_timer(program, "15")
                pid = self.pin_pidfile(self.root / "descendant.pid", process)
                group = os.getpgid(pid)
                self.assertNotEqual(group, os.getpgrp())
                timer = os.pidfd_open(group)
                try:
                    signal.pidfd_send_signal(timer, signum)
                    process.communicate(timeout=5)
                finally:
                    os.close(timer)
                self.assertEqual(process.returncode, 137)
                self.check_pinned_children()
                self.assert_lock_released()

    def test_complete_boundary_times_out_unfinished_uploaded_program(self):
        started = time.monotonic()
        process = subprocess.Popen([SHELL, "-c", self.script], stdin=subprocess.PIPE,
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                   env=self.env)
        try:
            process.stdin.write(b"{\n")
            process.stdin.flush()
            process.wait(timeout=20)
            self.assertEqual(process.returncode, 73)
            self.assertEqual(process.stdout.read(), b"")
            self.assertLess(time.monotonic() - started, 20)
        finally:
            process.stdin.close()
            if process.poll() is None:
                process.kill()
            process.wait(timeout=5)
            process.stdout.close()
            process.stderr.close()

    def test_stalled_diagnostic_delivery_is_bounded_and_withholds_readiness(self):
        if GNU_CAT is None:
            self.skipTest("no GNU cat: uutils cat resizes the pipe instead of stalling")
        gnu_cat = self.tools / "cat.gnu"
        gnu_cat.symlink_to(GNU_CAT)
        os.replace(gnu_cat, self.tools / "cat")
        process = subprocess.Popen([SHELL, "-c", self.script], stdin=subprocess.PIPE,
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                   env=self.env)
        # Pin a small pipe capacity instead of assuming the host default.
        fcntl.fcntl(process.stderr.fileno(), fcntl.F_SETPIPE_SZ, 4096)
        code = "import os; os.write(2, b'x' * 65536); os.write(1, b'RCH_TOPOLOGY_OK\\n')"
        try:
            process.stdin.write(self.python_command(code).encode())
            process.stdin.close()
            process.wait(timeout=7)
            self.assertNotEqual(process.returncode, 0)
            self.assertEqual(process.stdout.read(), b"")
        finally:
            if process.poll() is None:
                process.kill()
            process.wait(timeout=5)
            process.stdout.close()
            process.stderr.close()

    def test_no_supported_timer_refuses_before_namespace_mutation(self):
        no_python = self.root / "no-python"
        no_python.mkdir()
        for name in ("timeout", "head", "grep"):
            (no_python / name).symlink_to(self.tools / name)
        mutation = self.root / "must-not-exist"
        result = subprocess.run([SHELL, "-c", self.script],
                                input=("echo forbidden > " + shlex.quote(str(mutation))).encode(),
                                capture_output=True, timeout=3,
                                env={**self.env, "PATH": str(no_python)})
        self.assertEqual(result.returncode, 73)
        self.assertEqual(result.stdout, b"")
        self.assertFalse(mutation.exists())


if __name__ == "__main__":
    unittest.main(verbosity=2)
