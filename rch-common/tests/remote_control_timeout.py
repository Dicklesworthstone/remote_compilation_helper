#!/usr/bin/env python3
"""Real bounded control exchanges with no timeout executable on PATH.

Run after building rch-wkr on macOS. The helper identities and shell lifecycle
are not mocked. Run just ControlTimeout when testing the extracted control
functions independently of the complete repository.
"""
import os
from pathlib import Path
import shlex
import shutil
import signal
import subprocess
import sys
import tempfile
import time
import unittest

ROOT = Path(__file__).resolve().parents[2]
CORE = (ROOT / "rch-common/src/remote_process.sh").read_text()
SHELL = os.environ.get("RCH_TEST_SHELL", "/bin/sh")
# Deliberately exclude timeout, gtimeout and gnutimeout. Symlink real utilities;
# changing uname or returning fake identity observations would hide this bug.
TOOLS = (
    "awk", "cat", "chmod", "cmp", "cut", "date", "id", "kill", "mkdir",
    "mkfifo", "mktemp", "mv", "ps", "python3", "rch-wkr", "rm", "rmdir",
    "sh", "sleep", "stat", "tr", "uname", "wc",
)


class WithoutTimeout(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="rch-no-timeout-")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.bin = self.root / "bin"
        self.bin.mkdir()
        for name in TOOLS:
            executable = shutil.which(name)
            if executable:
                (self.bin / name).symlink_to(executable)
        self.env = dict(os.environ, PATH=str(self.bin), TMPDIR=str(self.root))

    def run_protocol(self, body, timeout=8):
        return subprocess.run(
            [SHELL, "-c", CORE + "\n" + body], env=self.env, text=True,
            capture_output=True, start_new_session=True, timeout=timeout,
        )

    def assert_no_capture_files(self):
        self.assertEqual(list(self.root.glob("rch-control-output.*")), [])


class ControlTimeout(WithoutTimeout):
    def test_real_timeout_executables_are_absent(self):
        result = self.run_protocol(
            "command -v python3 >/dev/null || exit 1; "
            "for tool in timeout gtimeout gnutimeout; do "
            "if command -v \"$tool\" >/dev/null; then exit 2; fi; done"
        )
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_success_preserves_complete_output(self):
        result = self.run_protocol("rch_control_capture 1s /bin/sh -c 'printf \"first\\nlast\\n\"'")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, "first\nlast\n")
        self.assert_no_capture_files()

    def test_nonzero_exit_never_publishes_authority_on_stdout(self):
        result = self.run_protocol(
            "rch_control_capture 1s /bin/sh -c 'printf diagnostic; exit 7'"
        )
        self.assertEqual(result.returncode, 7, result.stderr)
        self.assertEqual(result.stdout, "")
        self.assertIn("diagnostic", result.stderr)
        self.assert_no_capture_files()

    def test_missing_command_fails_closed(self):
        result = self.run_protocol("rch_control_capture 1s /rch/no-such-program")
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(result.stdout, "")
        self.assert_no_capture_files()

    def test_missing_python_fails_closed_before_execution(self):
        (self.bin / "python3").unlink()
        marker = self.root / "unsafe-launch"
        result = self.run_protocol(
            "rch_control_capture 1s /bin/sh -c "
            + shlex.quote("echo unsafe > " + shlex.quote(str(marker)))
        )
        self.assertEqual(result.returncode, 125, result.stderr)
        self.assertFalse(marker.exists())
        self.assertEqual(result.stdout, "")
        self.assert_no_capture_files()

    def test_invalid_timeout_arguments_cannot_spawn(self):
        marker = self.root / "unsafe-launch"
        command = "/bin/sh -c " + shlex.quote("echo unsafe > " + shlex.quote(str(marker)))
        for options in ("--signal=TERM 1s", "--signal=KILL 0s", "--signal=KILL NaN", "--signal=KILL 60s"):
            with self.subTest(options=options):
                result = self.run_protocol("rch_group_timeout " + options + " " + command)
                self.assertEqual(result.returncode, 125, result.stderr)
                self.assertFalse(marker.exists())

    def test_five_second_control_budget_is_supported(self):
        result = self.run_protocol("rch_control_capture 5s /bin/sh -c 'printf valid'")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, "valid")

    def test_monitor_owns_a_separate_kernel_session_and_group(self):
        code = "import os; print(os.getpid(), os.getppid(), os.getpgrp(), os.getsid(0))"
        result = self.run_protocol(
            'printf "%s\\n" "$$"; rch_group_timeout --signal=KILL 1s python3 -I -c '
            + shlex.quote(code)
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        caller, child, monitor, group, session = map(int, result.stdout.split())
        self.assertNotEqual(caller, monitor)
        self.assertNotEqual(child, monitor)
        self.assertEqual(monitor, group)
        self.assertEqual(monitor, session)

    def test_killed_command_preserves_signal_exit_status(self):
        result = self.run_protocol(
            "rch_group_timeout --signal=KILL 1s /bin/sh -c 'kill -TERM $$'"
        )
        self.assertEqual(result.returncode, 128 + signal.SIGTERM, result.stderr)

    def test_interrupted_monitor_cleans_its_group(self):
        for signum in (signal.SIGHUP, signal.SIGINT, signal.SIGTERM):
            with self.subTest(signal=signum):
                # This child signals its still-live parent, the session monitor.
                code = (
                    "import os, signal, time; "
                    f"os.kill(os.getppid(), {int(signum)}); time.sleep(30)"
                )
                start = time.monotonic()
                result = self.run_protocol(
                    "rch_group_timeout --signal=KILL 5s python3 -I -c " + shlex.quote(code)
                )
                self.assertEqual(result.returncode, 128 + signal.SIGKILL, result.stderr)
                self.assertLess(time.monotonic() - start, 4.0)

    def test_timeout_rejects_partial_success_and_keeps_other_group_alive(self):
        # Retain an unreaped direct child; never kill a PID taken from a record.
        sentinel = subprocess.Popen(["/bin/sleep", "30"], start_new_session=True)
        try:
            start = time.monotonic()
            result = self.run_protocol(
                "rch_control_capture 1s /bin/sh -c 'printf plausible_identity; sleep 30'"
            )
            elapsed = time.monotonic() - start
            self.assertNotEqual(result.returncode, 0)
            self.assertEqual(result.stdout, "")
            self.assertLess(elapsed, 4.0)
            self.assertIsNone(sentinel.poll(), "unrelated process group was signalled")
            self.assert_no_capture_files()
        finally:
            if sentinel.poll() is None:
                sentinel.kill()
            sentinel.wait(timeout=5)

    def test_exited_command_with_pipe_holding_descendant_is_bounded(self):
        marker = self.root / "descendant-survived"
        # A surviving descendant would create marker after the control deadline.
        payload = "(sleep 2; printf survived > " + shlex.quote(str(marker)) + ") & exit 0"
        start = time.monotonic()
        result = self.run_protocol("rch_control_capture 1s /bin/sh -c " + shlex.quote(payload))
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(result.stdout, "")
        self.assertLess(time.monotonic() - start, 4.0)
        time.sleep(1.3)
        self.assertFalse(marker.exists(), "pipe holder survived group cleanup")
        self.assert_no_capture_files()

    def test_invalid_bytes_and_oversize_output_are_refused(self):
        for payload in ('print("x" * 65537)', 'import sys; sys.stdout.buffer.write(b"ok\\0bad")'):
            with self.subTest(payload=payload):
                result = self.run_protocol(
                    "rch_control_capture 1s python3 -I -c " + shlex.quote(payload)
                )
                self.assertEqual(result.returncode, 125, result.stderr)
                self.assertEqual(result.stdout, "")
                self.assert_no_capture_files()


class NativeLifecycleWithoutTimeout(WithoutTimeout):
    def test_all_existing_lifecycle_operations_without_coreutils(self):
        # On macOS the workflow supplies the candidate native rch-wkr. This
        # invokes all existing real launch, watchdog, cancellation and recovery
        # tests unchanged, but with every GNU timeout alias absent from PATH.
        result = subprocess.run(
            [sys.executable, str(ROOT / "rch-common/tests/remote_process_platform.py"), "-v"],
            env=self.env, text=True, capture_output=True, timeout=120,
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertRegex(result.stderr, r"Ran [1-9][0-9]* tests")
        self.assertNotIn("skipped", result.stderr)


if __name__ == "__main__":
    unittest.main()
