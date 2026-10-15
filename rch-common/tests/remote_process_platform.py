#!/usr/bin/env python3
"""Real kernel identity, watchdog, cancellation and recovery on Linux/Darwin.

Darwin requires the candidate rch-wkr on PATH and GNU timeout (Homebrew
coreutils). No identity observation is mocked. Receipts are altered only to
exercise stale/reused birth and previous-boot recovery fences.
"""
import os
from pathlib import Path
import shlex
import signal
import subprocess
import tempfile
import time
import unittest

ROOT = Path(__file__).resolve().parents[2]
CORE = (ROOT / "rch-common/src/remote_process.sh").read_text()
TRANSFER = (ROOT / "rch/src/transfer.rs").read_text()
WATCHDOG = "rch_remote_record" + TRANSFER.split('r#"rch_remote_record', 1)[1].split('"#,', 1)[0]
SHELL = os.environ.get("RCH_TEST_SHELL", "/bin/sh")


class PlatformIdentity(unittest.TestCase):
    def setUp(self):
        self.root = Path(tempfile.mkdtemp(prefix="rch-platform-identity-"))
        self.receipt = self.root / "receipt"
        self.ready = self.root / "ready"
        self.children = []
        self.addCleanup(self.stop_owned)

    def stop_owned(self):
        for child in self.children:
            # These session IDs came from our own unreaped direct children.
            if child.poll() is None:
                os.killpg(child.pid, signal.SIGKILL)
            child.wait(timeout=10)

    def run_protocol(self, body):
        return subprocess.run([SHELL, "-c", CORE + "\n" + body],
                              text=True, capture_output=True, timeout=20)

    def assert_protocol(self, body):
        result = self.run_protocol(body)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def launch(self, seconds=0, payload=None):
        if payload is None:
            payload = "trap '' TERM; echo ready > " + shlex.quote(str(self.ready)) + "; exec sleep 60"
        child = subprocess.Popen(
            [SHELL, "-c", CORE + "\nexec 3>&2\n" + WATCHDOG, "rch-platform-test",
             str(self.receipt), str(seconds), "RCH_PLATFORM_DEADLINE", "115",
             SHELL, "-c", payload], start_new_session=True,
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        self.children.append(child)
        for _ in range(500):
            if self.receipt.exists() and (self.ready.exists() or payload == "exit 7"):
                return child
            self.assertIsNone(child.poll(), "identity setup refused before workload")
            time.sleep(.01)
        self.fail("workload did not start")

    def cancel(self, mode="term"):
        return self.run_protocol(
            f"rch_remote_cancel {shlex.quote(str(self.receipt))} 115 {mode}")

    def test_initial_execution_preserves_exit_status(self):
        child = self.launch(payload="exit 7")
        self.assertEqual(child.wait(timeout=10), 7)
        self.assertTrue(self.receipt.read_text().startswith("RCH_REMOTE_PROCESS_V1:115:"))

    def test_watchdog_and_timeout_recovery(self):
        child = self.launch(seconds=2)
        self.assertEqual(child.wait(timeout=12), -signal.SIGKILL)
        result = self.cancel("kill")
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_cancellation_escalates_and_recovery_confirms_empty(self):
        child = self.launch()
        result = self.cancel()
        self.assertEqual(result.returncode, 0, result.stderr)
        child.wait(timeout=10)
        self.assertEqual(self.cancel("kill").returncode, 0)

    def test_reused_birth_cannot_signal_live_group(self):
        child = self.launch()
        fields = self.receipt.read_text().strip().split(":")
        fields[-1] = str(int(fields[-1]) + 1)
        self.receipt.write_text(":".join(fields) + "\n")
        result = self.cancel()
        self.assertEqual(result.returncode, 43, result.stderr)
        self.assertIsNone(child.poll())

    def test_previous_boot_retires_only_old_execution(self):
        child = self.launch()
        fields = self.receipt.read_text().strip().split(":")
        fields[2] = "13572468-1234-4abc-8def-135724681357"
        self.receipt.write_text(":".join(fields) + "\n")
        result = self.cancel()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIsNone(child.poll())

    def test_actual_process_and_subshell_identity(self):
        self.assert_protocol(r'''
sleep 60 & member=$!
trap 'kill "$member"; wait "$member" 2>/dev/null' 0
rch_pgid=$(ps -o pgid= -p "$member" | tr -d ' ')
rch_read_process "$member" || exit 1
saved=$rch_observed_start
( rch_read_process "$member" && [ "$rch_observed_start" = "$saved" ] ) || exit 2
rch_pgid=2147483647
if rch_read_process "$member"; then exit 3; fi
''')


if __name__ == "__main__":
    unittest.main()
