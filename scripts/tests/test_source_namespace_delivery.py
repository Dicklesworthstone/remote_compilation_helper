#!/usr/bin/env python3
"""Exercise the production namespace observer under real output backpressure.

The actual GNU timer and OS pipes are used, with the shipped deadlines intact.
No daemon, SSH connection, source tree, or installed worker is touched. Retain
fixture directories so a failed process test leaves evidence for inspection.
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
GNU_TIMEOUT = shutil.which("gnutimeout") or shutil.which("gtimeout") or shutil.which("timeout")
READY = b"RCH_TOPOLOGY_OK\n"


@unittest.skipUnless(sys.platform == "linux" and GNU_TIMEOUT,
                     "requires Linux pipe sizing and GNU timeout")
class NamespaceDeliveryTests(unittest.TestCase):
    def setUp(self):
        version = subprocess.run([GNU_TIMEOUT, "--version"], capture_output=True,
                                 timeout=3, check=False)
        if b"GNU coreutils" not in version.stdout:
            self.skipTest("the discovered timer is not GNU timeout")
        self.root = Path(tempfile.mkdtemp(prefix="rch-namespace-delivery-"))
        self.tools = self.root / "tools"
        self.tools.mkdir()
        (self.tools / "gnutimeout").symlink_to(GNU_TIMEOUT)
        (self.tools / "sh").symlink_to(SHELL)
        self.tmp = self.root / "tmp"
        self.tmp.mkdir()
        self.env = {**os.environ, "PATH": str(self.tools) + os.pathsep + os.environ["PATH"],
                    "TMPDIR": str(self.tmp), "LC_ALL": "C"}
        self.script = CONTROL.read_text()

    def term_resistant_delivery(self):
        # Keep the real cat/pipe behavior but model an inherited TERM-ignore
        # disposition. The timer must escalate, not merely reap a TERM exit.
        cat = self.tools / "cat"
        self.writer_pid = self.root / "delivery.pid"
        self.env["RCH_TEST_DELIVERY_PID"] = str(self.writer_pid)
        cat.write_text("#!/bin/sh\ntrap '' TERM\nprintf '%s\\n' \"$$\" > \"$RCH_TEST_DELIVERY_PID\"\nexec " +
                       shlex.quote(shutil.which("cat")) + ' "$@"\n')
        cat.chmod(0o700)

    def test_stalled_stderr_does_not_block_observer_after_timer_exit(self):
        self.term_resistant_delivery()
        process = subprocess.Popen([SHELL, "-c", self.script], stdin=subprocess.PIPE,
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                   env=self.env)
        fcntl.fcntl(process.stderr.fileno(), fcntl.F_SETPIPE_SZ, 4096)
        code = "import os; os.write(2, b'x' * 65536); os.write(1, b'RCH_TOPOLOGY_OK\\n')"
        program = shlex.quote(sys.executable) + " -I -S -c " + shlex.quote(code)
        writer = None
        try:
            process.stdin.write(program.encode())
            process.stdin.close()
            deadline = time.monotonic() + 5
            while writer is None:
                try:
                    writer = os.pidfd_open(int(self.writer_pid.read_text()))
                except (FileNotFoundError, ValueError):
                    self.assertLess(time.monotonic(), deadline, "delivery writer did not start")
                    time.sleep(0.01)
            # Do NOT drain stderr until after exit: the delivery child must
            # hit its actual two-second deadline against a saturated pipe.
            process.wait(timeout=7)
            self.assertNotEqual(process.returncode, 0)
            self.assertEqual(process.stdout.read(), b"")
            exited = select.poll()
            exited.register(writer, select.POLLIN)
            # Keep stderr OPEN and unread during this check. Closing it would
            # kill the leaked writer by SIGPIPE and hide the original defect.
            self.assertTrue(exited.poll(1000), "delivery writer survived the control deadline")
        finally:
            if writer is not None:
                exited = select.poll()
                exited.register(writer, select.POLLIN)
                if not exited.poll(0):
                    signal.pidfd_send_signal(writer, signal.SIGKILL)
                os.close(writer)
            if process.poll() is None:
                process.kill()
            process.wait(timeout=5)
            process.stdout.close()
            process.stderr.close()

    def test_stalled_stdout_cannot_publish_readiness_or_hang_observer(self):
        reader, writer = os.pipe()
        fcntl.fcntl(writer, fcntl.F_SETPIPE_SZ, 4096)
        filler = b"p" * 4096
        self.assertEqual(os.write(writer, filler), len(filler))
        process = subprocess.Popen([SHELL, "-c", self.script], stdin=subprocess.PIPE,
                                   stdout=writer, stderr=subprocess.PIPE, env=self.env)
        os.close(writer)
        try:
            process.stdin.write(b"printf 'RCH_TOPOLOGY_OK\\n'\n")
            process.stdin.close()
            process.wait(timeout=7)
            self.assertNotEqual(process.returncode, 0)
            # Never block test cleanup on an inherited write descriptor.
            os.set_blocking(reader, False)
            self.assertEqual(os.read(reader, 8192), filler)
            self.assertEqual(os.read(reader, 8192), b"")
        finally:
            if process.poll() is None:
                process.kill()
            process.wait(timeout=5)
            process.stderr.close()
            os.close(reader)

    def test_success_and_refusal_keep_exact_output_and_exit_status(self):
        for status in (0, 7, 75, 125):
            with self.subTest(status=status):
                result = subprocess.run([SHELL, "-c", self.script],
                                        input=("printf 'diagnostic\\n' >&2\n"
                                               "printf 'RCH_TOPOLOGY_OK\\n'\n"
                                               f"exit {status}\n").encode(),
                                        capture_output=True, env=self.env, timeout=5)
                self.assertEqual(result.returncode, status, result.stderr)
                self.assertEqual(result.stdout, READY if status == 0 else b"")
                self.assertEqual(result.stderr, b"diagnostic\n")
        self.assertEqual(list(self.tmp.iterdir()), [])


if __name__ == "__main__":
    unittest.main(verbosity=2)
