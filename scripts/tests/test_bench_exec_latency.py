#!/usr/bin/env python3
"""Native subprocess cleanup checks for the paired latency benchmark.

These tests exercise real owned Python children and fixture teardown failures.
They do not run RCH, substitute a worker, or establish benchmark speedups.
All temporary evidence is retained.
"""

from contextlib import redirect_stderr
import importlib.util
import io
import json
from pathlib import Path
import select
import signal
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest


SCRIPT = Path(__file__).resolve().parents[1] / "bench_exec_latency.py"
spec = importlib.util.spec_from_file_location("bench_exec_latency", SCRIPT)
benchmark = importlib.util.module_from_spec(spec)
spec.loader.exec_module(benchmark)


def ready(child):
    if not select.select([child.stdout], [], [], 10)[0]:
        raise AssertionError("owned test child did not become ready")
    if child.stdout.readline() != b"ready\n":
        raise AssertionError("owned test child did not publish readiness")


class CleanupTests(unittest.TestCase):
    def test_keyboard_interrupt_stops_and_reaps_detached_launcher(self):
        with self.assertRaisesRegex(KeyboardInterrupt, "test interruption"):
            with benchmark.owned_process(
                [sys.executable, "-c", "import time; print('ready', flush=True); time.sleep(60)"],
                stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, start_new_session=True,
            ) as child:
                ready(child)
                raise KeyboardInterrupt("test interruption")
        self.assertIsNotNone(child.returncode)
        self.assertIsNotNone(child.poll())
        child.stdout.close()

    def test_stubborn_owned_child_is_killed_and_reaped(self):
        child = subprocess.Popen(
            [sys.executable, "-c", "import signal,time; "
             "signal.signal(signal.SIGINT, signal.SIG_IGN); "
             "signal.signal(signal.SIGTERM, signal.SIG_IGN); "
             "print('ready', flush=True); time.sleep(60)"],
            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, start_new_session=True,
        )
        try:
            ready(child)
            code = benchmark.stop_owned_child(child, interrupt_timeout=0.05, terminate_timeout=0.05)
            self.assertEqual(code, -signal.SIGKILL)
            self.assertEqual(child.returncode, -signal.SIGKILL)
        finally:
            if child.poll() is None:
                child.kill()
                child.wait(timeout=5)
            child.stdout.close()

    def test_failed_cleanup_does_not_skip_the_other_fixture(self):
        calls = []

        def stop(label, fails=False):
            calls.append(label)
            if fails:
                raise RuntimeError("retained recovery evidence")

        fixtures = [
            SimpleNamespace(label="baseline", stop=lambda: stop("baseline")),
            SimpleNamespace(label="candidate", stop=lambda: stop("candidate", True)),
        ]
        with redirect_stderr(io.StringIO()) as stderr:
            failures = benchmark.stop_fixtures(fixtures)
        self.assertEqual(calls, ["candidate", "baseline"])
        self.assertEqual(failures, [{"variant": "candidate", "error": "retained recovery evidence"}])
        self.assertIn("candidate cleanup failed", stderr.getvalue())

    def test_corrupt_recovery_journal_still_stops_private_daemon(self):
        root = Path(tempfile.mkdtemp(prefix="rch-bench-cleanup-"))
        fixture = benchmark.Fixture.__new__(benchmark.Fixture)
        fixture.journals = root / "journals"
        fixture.journals.mkdir()
        journal = fixture.journals / "broken.json"
        journal.write_text("retained malformed evidence")
        fixture.socket = root / "missing.sock"
        fixture.log = (root / "daemon.log").open("xb")
        fixture.process = subprocess.Popen(
            [sys.executable, "-c", "import time; print('ready', flush=True); time.sleep(60)"],
            stdout=subprocess.PIPE, stderr=fixture.log, start_new_session=True,
        )
        try:
            ready(fixture.process)
            with self.assertRaises(json.JSONDecodeError):
                fixture.stop()
            self.assertIsNotNone(fixture.process.returncode)
            self.assertTrue(fixture.log.closed)
            self.assertEqual(journal.read_text(), "retained malformed evidence")
        finally:
            if fixture.process.poll() is None:
                fixture.process.kill()
                fixture.process.wait(timeout=5)
            fixture.process.stdout.close()
            fixture.log.close()


if __name__ == "__main__":
    unittest.main()
