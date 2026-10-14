#!/usr/bin/env python3
"""Exercise the production namespace shell, including live process ownership.

Run on Linux with GNU timeout: python3 scripts/test_namespace_group_teardown.py
No Rust toolchain, worker, SSH connection, or production registry is needed.
"""
from __future__ import annotations

import fcntl
import os
from pathlib import Path
import shlex
import shutil
import signal
import subprocess
import tempfile
import time
import unittest

ROOT = Path(__file__).resolve().parents[1]
CONTROL = Path(os.environ.get("RCH_TEST_SOURCE_NAMESPACE_CONTROL",
                              ROOT / "rch/src/hook/source_namespace_control.sh"))
SHELL = os.environ.get("RCH_TEST_SHELL", "/bin/sh")
READY = b"RCH_TOPOLOGY_OK\n"


def running(pid: int) -> bool:
    try:
        # A zombie cannot retain a descriptor, run code, or mutate the registry.
        return Path(f"/proc/{pid}/stat").read_text().split(") ", 1)[1].split()[0] != "Z"
    except FileNotFoundError:
        return False


@unittest.skipUnless(Path("/proc/self/stat").exists() and shutil.which("timeout"),
                     "requires Linux process evidence and GNU timeout")
class NamespaceGroupTeardown(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory(prefix="rch-namespace-test-")
        self.addCleanup(self.temp.cleanup)
        self.directory = Path(self.temp.name)
        self.script = CONTROL.read_text()
        # Never let a failed regression leave a live test-owned process behind.
        self.children: list[int] = []
        self.addCleanup(self.stop_children)

    def stop_children(self) -> None:
        for pid in self.children:
            if running(pid):
                try:
                    os.kill(pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass

    def run_control(self, program: str, *, timeout: float = 6) -> subprocess.CompletedProcess:
        env = dict(os.environ, TMPDIR=str(self.directory))
        return subprocess.run([SHELL, "-c", self.script], input=program.encode(),
                              capture_output=True, timeout=timeout, env=env)

    def descendant_program(self, exit_code: int) -> tuple[str, Path, Path]:
        pidfile = self.directory / f"child-{exit_code}.pid"
        lockfile = self.directory / f"registry-{exit_code}.lock"
        # This descendant closes both protocol pipes, ignores graceful signals,
        # and retains the same kind of flock used by the source registry.
        child = (
            f"exec 9>{shlex.quote(str(lockfile))}; flock -x 9; "
            f"trap '' HUP INT TERM; echo $$ > {shlex.quote(str(pidfile))}; "
            "exec sleep 60"
        )
        program = (
            f"sh -c {shlex.quote(child)} </dev/null >/dev/null 2>&1 &\n"
            f"while [ ! -s {shlex.quote(str(pidfile))} ]; do :; done\n"
            f"printf 'RCH_TOPOLOGY_OK\\n'\nexit {exit_code}\n"
        )
        return program, pidfile, lockfile

    def assert_retired(self, pidfile: Path, lockfile: Path) -> None:
        pid = int(pidfile.read_text())
        self.children.append(pid)
        deadline = time.monotonic() + 2
        while running(pid) and time.monotonic() < deadline:
            time.sleep(0.01)
        self.assertFalse(running(pid), f"namespace descendant {pid} survived")
        with lockfile.open("rb") as lock:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            fcntl.flock(lock, fcntl.LOCK_UN)

    def test_success_retires_closed_pipe_descendant_and_registry_lock(self) -> None:
        program, pidfile, lockfile = self.descendant_program(0)
        result = self.run_control(program)
        self.assert_retired(pidfile, lockfile)
        self.assertEqual((result.returncode, result.stdout, result.stderr), (0, READY, b""))

    def test_refusal_retires_descendant_without_releasing_early_readiness(self) -> None:
        for code in (1, 73, 75, 137, 255):
            with self.subTest(exit_code=code):
                program, pidfile, lockfile = self.descendant_program(code)
                result = self.run_control(program)
                self.assert_retired(pidfile, lockfile)
                self.assertEqual(result.returncode, code)
                self.assertEqual(result.stdout, b"")

    def test_success_preserves_complete_diagnostics_and_cleans_private_files(self) -> None:
        result = self.run_control("printf 'diagnostic\\n' >&2\nprintf 'RCH_TOPOLOGY_OK\\n'\n")
        self.assertEqual((result.returncode, result.stdout, result.stderr),
                         (0, READY, b"diagnostic\n"))
        self.assertEqual(list(self.directory.iterdir()), [])

    def test_full_stderr_bound_is_delivered_without_truncation(self) -> None:
        result = self.run_control("head -c 65536 /dev/zero >&2\nprintf 'RCH_TOPOLOGY_OK\\n'\n")
        self.assertEqual(result.returncode, 0)
        self.assertEqual(result.stdout, READY)
        self.assertEqual(result.stderr, b"\0" * 65536)

    def test_refusal_preserves_original_diagnostics(self) -> None:
        result = self.run_control("printf 'busy owner\\n' >&2\nexit 75\n")
        self.assertEqual((result.returncode, result.stdout, result.stderr),
                         (75, b"", b"busy owner\n"))

    def test_invalid_and_incomplete_readiness_never_authorizes_success(self) -> None:
        for program in ("", "printf RCH_TOPOLOGY_OK", "printf 'RCH_TOPOLOGY_OK\\n\\n'",
                        "printf 'RCH_TOPOLOGY_OK\\000\\n'", "printf 'wrong\\n'"):
            with self.subTest(program=program):
                result = self.run_control(program)
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(result.stdout, b"")

    def test_excess_output_never_turns_a_valid_prefix_into_readiness(self) -> None:
        for program in ("printf 'RCH_TOPOLOGY_OK\\n'; head -c 5000 /dev/zero",
                        "head -c 65537 /dev/zero >&2; printf 'RCH_TOPOLOGY_OK\\n'"):
            with self.subTest(program=program):
                result = self.run_control(program)
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(result.stdout, b"")
                self.assertIn(b"byte bound", result.stderr)

    def test_malformed_shell_program_does_not_authorize_partial_success(self) -> None:
        result = self.run_control("printf 'RCH_TOPOLOGY_OK\\n'\nif\n")
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(result.stdout, b"")

    def test_repeated_success_never_kills_the_observer_or_test_group(self) -> None:
        for _ in range(10):
            result = self.run_control("printf 'RCH_TOPOLOGY_OK\\n'\n")
            self.assertEqual((result.returncode, result.stdout, result.stderr), (0, READY, b""))

    def test_open_pipe_descendant_is_bounded_and_readiness_is_withheld(self) -> None:
        # Shorten ONLY the execution deadline in this fault-injection test. The
        # production program and TERM-to-KILL behavior are otherwise unchanged.
        self.assertEqual(self.script.count('--kill-after=1 15 sh -c'), 1)
        self.script = self.script.replace('--kill-after=1 15 sh -c', '--kill-after=1 0.2 sh -c')
        pidfile = self.directory / "open-pipe.pid"
        child = f"trap '' HUP INT TERM; echo $$ > {shlex.quote(str(pidfile))}; exec sleep 60"
        program = (f"sh -c {shlex.quote(child)} &\n"
                   f"while [ ! -s {shlex.quote(str(pidfile))} ]; do :; done\n"
                   "printf 'RCH_TOPOLOGY_OK\\n'\n")
        result = self.run_control(program)
        pid = int(pidfile.read_text())
        self.children.append(pid)
        deadline = time.monotonic() + 2
        while running(pid) and time.monotonic() < deadline:
            time.sleep(0.01)
        self.assertFalse(running(pid))
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(result.stdout, b"")

    def test_foreground_timer_cannot_kill_observer_or_run_namespace_program(self) -> None:
        tools = self.directory / "tools"
        tools.mkdir()
        real = shutil.which("gnutimeout") or shutil.which("gtimeout") or shutil.which("timeout")
        for name in ("timeout", "gtimeout", "gnutimeout"):
            timer = tools / name
            timer.write_text("#!/bin/sh\nexec " + shlex.quote(real) +
                             ' --foreground "$@"\n')
            timer.chmod(0o700)
        mutation = self.directory / "must-not-exist"
        env = dict(os.environ, TMPDIR=str(self.directory),
                   PATH=str(tools) + os.pathsep + os.environ["PATH"])
        # The test itself stays outside the tested group, even on regression.
        result = subprocess.run([SHELL, "-c", self.script],
                                input=("touch " + shlex.quote(str(mutation)) +
                                       "\nprintf 'RCH_TOPOLOGY_OK\\n'\n").encode(),
                                capture_output=True, timeout=6, env=env,
                                start_new_session=True)
        self.assertEqual(result.returncode, 73, result.stderr)
        self.assertEqual(result.stdout, b"")
        self.assertFalse(mutation.exists())
        self.assertIn(b"private process group", result.stderr)

    def test_unverifiable_group_refuses_before_namespace_mutation(self) -> None:
        tools = self.directory / "tools"
        tools.mkdir()
        ps = tools / "ps"
        ps.write_text("#!/bin/sh\nprintf 'not a process identity\\n'\n")
        ps.chmod(0o700)
        mutation = self.directory / "must-not-exist"
        env = dict(os.environ, TMPDIR=str(self.directory),
                   PATH=str(tools) + os.pathsep + os.environ["PATH"])
        result = subprocess.run([SHELL, "-c", self.script],
                                input=("touch " + shlex.quote(str(mutation))).encode(),
                                capture_output=True, timeout=6, env=env,
                                start_new_session=True)
        self.assertEqual(result.returncode, 73)
        self.assertEqual(result.stdout, b"")
        self.assertFalse(mutation.exists())

    def test_deadline_before_program_completion_never_creates_success(self) -> None:
        self.script = self.script.replace('--kill-after=1 15 sh -c', '--kill-after=1 0.2 sh -c')
        result = self.run_control("printf 'RCH_TOPOLOGY_OK\\n'\nsleep 60\n")
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(result.stdout, b"")


if __name__ == "__main__":
    unittest.main(verbosity=2)
