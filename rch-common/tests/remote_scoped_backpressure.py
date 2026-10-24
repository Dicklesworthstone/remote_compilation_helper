#!/usr/bin/env python3
"""Run the production Linux supervisor with an abandoned, full diagnostic pipe.

Only policy discovery is redirected; launch, process identity, cancellation,
status, one-shot claims and file-descriptor lifetime are real. No live SSH,
systemd or daemon is used. Fixtures are retained. Never drain stderr to make
completion pass: the consumer remains alive and unread through process exit.
"""
from __future__ import annotations

import fcntl
import json
import os
from pathlib import Path
import re
import select
import signal
import subprocess
import sys
import tempfile
import time
import unittest

SOURCE = Path(__file__).resolve().parents[1] / "src"
SHELL = os.environ.get("RCH_TEST_SHELL", "/bin/sh")


def protocol():
    expression = (SOURCE / "remote_scoped_launch.rs").read_text().split(
        "= concat!(\n", 1)[1].split("\n);", 1)[0]
    parts = []
    for line in expression.splitlines():
        item = line.strip().removesuffix(",")
        include = re.fullmatch(r'include_str!\(("[^"\n]+")\)', item)
        parts.append((SOURCE / json.loads(include[1])).read_text()
                     if include else json.loads(item))
    source = "".join(parts)
    supplied = os.environ.get("RCH_TEST_PROTOCOL_SCRIPT")
    if supplied and Path(supplied).read_text() != source:
        raise AssertionError("source expansion does not match the compiled protocol")
    core = (SOURCE / "remote_process.sh").read_text()
    if source.count(core) != 1:
        raise AssertionError("expected one shared identity implementation")
    return source.replace(core, core + '\nrch_policy_select_file() { rch_policy_file=; }\n')


PAYLOAD = '''
import os, sys, time
from pathlib import Path
root = Path(sys.argv[1])
(root/'ready').write_text(str(os.getpid()))
while not (root/'release').exists(): time.sleep(.01)
(root/'artifact').write_bytes(b'completed-output')
sys.exit(int(sys.argv[2]))
'''


@unittest.skipUnless(sys.platform == "linux" and hasattr(os, "pidfd_open"),
                     "Linux procfs and pidfd test cleanup")
class DiagnosticBackpressure(unittest.TestCase):
    def setUp(self):
        self.root = Path(tempfile.mkdtemp(prefix="rch-diagnostic-backpressure-"))
        self.children = []
        self.fds = []
        self.handles = []
        self.record = self.root / "41.pgid"
        self.claim = Path(str(self.record) + ".supervisor.v1")
        self.script = protocol()

    def tearDown(self):
        # These handles were opened while the fixture children were live.
        for fd in self.handles:
            try:
                signal.pidfd_send_signal(fd, signal.SIGKILL)
            except ProcessLookupError:
                pass
            os.close(fd)
        for child in self.children:
            if child.poll() is None:
                child.kill()
            child.wait(timeout=5)
            if child.stdout is not None:
                child.stdout.close()
        # Pipe consumers remain open through all status and ownership checks.
        for fd in self.fds:
            os.close(fd)

    def full_pipe(self):
        read, write = os.pipe()
        self.fds.extend((read, write))
        os.set_blocking(write, False)
        total = 0
        try:
            while True:
                total += os.write(write, b"x" * 4096)
        except BlockingIOError:
            pass
        os.set_blocking(write, True)
        self.assertGreater(total, 0)
        return read, write, total

    def start(self, *, full=True, code=7, script=None, disconnected=False,
              payload=PAYLOAD, stdout=subprocess.DEVNULL):
        read, write, filled = self.full_pipe() if full else (*os.pipe(), 0)
        if not full:
            self.fds.extend((read, write))
        if disconnected:
            os.close(read)
            self.fds.remove(read)
            read = None
        # Model the source-holder's inherited open-file-description lock. The
        # parent closes its duplicate immediately: only this launch may keep
        # it locked. Ending the payload alone must not count as releasing it.
        lock_path = self.root / f"source-{len(self.children)}.lock"
        lock = os.open(lock_path, os.O_RDWR | os.O_CREAT, 0o600)
        fcntl.flock(lock, fcntl.LOCK_EX)
        try:
            child = subprocess.Popen(
                [SHELL, "-c", "exec 3>&2\n" + (self.script if script is None else script),
                 "rch-build", str(self.record), "10", "RCH_TEST", "41",
                 sys.executable, "-I", "-S", "-c", payload, str(self.root), str(code)],
                stdin=subprocess.DEVNULL, stdout=stdout, stderr=write,
                start_new_session=True, pass_fds=(lock,),
            )
        finally:
            os.close(lock)
        self.children.append(child)
        self.handles.append(os.pidfd_open(child.pid))
        return child, read, filled, lock_path

    def finish(self, launch, expected):
        child, read, filled, lock_path = launch
        try:
            code = child.wait(timeout=4)
        except subprocess.TimeoutExpired:
            with lock_path.open("r+b") as lock:
                try:
                    fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
                except BlockingIOError:
                    raise AssertionError(
                        "terminal diagnostic blocked the supervisor AND its inherited lock"
                    ) from None
            raise AssertionError("supervisor remains blocked on terminal diagnostics") from None
        self.assertEqual(code, expected)
        with lock_path.open("r+b") as lock:
            try:
                fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                self.fail("an exited launch left an inherited ownership descriptor held")
        # Only inspect diagnostics AFTER exit and release have been asserted.
        if read is None:
            return b""
        os.set_blocking(read, False)
        received = bytearray()
        while True:
            try:
                chunk = os.read(read, 65536)
            except BlockingIOError:
                break
            if not chunk:
                break
            received.extend(chunk)
        self.assertGreaterEqual(len(received), filled)
        return bytes(received[filled:])

    def admitted(self, launch):
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            if (self.root / "ready").exists() and (self.root / "ready").stat().st_size:
                pid = int((self.root / "ready").read_text())
                handle = os.pidfd_open(pid)
                self.handles.append(handle)
                return handle
            self.assertIsNone(launch[0].poll(), "workload did not pass admission")
            time.sleep(.01)
        self.fail("workload did not start")

    def assert_dead(self, handle):
        poll = select.poll()
        poll.register(handle, select.POLLIN)
        self.assertTrue(poll.poll(1000), "payload survived terminal return")

    def test_existing_record_refuses_and_releases_inherited_lock_with_full_stderr(self):
        self.record.write_bytes(b"retained-execution\n")
        before = self.record.read_bytes()
        self.finish(self.start(), 255)
        self.assertEqual(self.record.read_bytes(), before)
        self.assertFalse((self.root / "ready").exists())

    def test_existing_claim_refuses_without_blocking_on_mkdir_diagnostic(self):
        self.claim.mkdir()
        sentinel = self.claim / "retained"
        sentinel.write_bytes(b"original owner")
        self.finish(self.start(), 255)
        self.assertEqual(sentinel.read_bytes(), b"original owner")
        self.assertFalse(self.record.exists())
        self.assertFalse((self.root / "ready").exists())

    def test_missing_receipt_stops_payload_and_returns_unconfirmed_without_a_reader(self):
        launch = self.start()
        handle = self.admitted(launch)
        original = self.record.read_bytes()
        self.record.rename(self.root / "retained-record")
        (self.root / "release").touch()
        self.finish(launch, 255)
        self.assert_dead(handle)
        self.assertEqual((self.root / "artifact").read_bytes(), b"completed-output")
        self.assertEqual((self.root / "retained-record").read_bytes(), original)
        self.assertTrue(self.claim.exists())

    def test_invalid_result_does_not_turn_into_success_or_hold_source_ownership(self):
        launch = self.start()
        handle = self.admitted(launch)
        # Publish an invalid report while the payload is still running. The
        # actual supervisor must stop it, then preserve the unknown outcome.
        result = self.claim / "result"
        result.write_text("wrong execution identity\n")
        result.chmod(0o600)
        self.finish(launch, 255)
        self.assert_dead(handle)
        self.assertFalse((self.root / "artifact").exists())
        self.assertTrue(self.record.exists())

    def test_available_reader_still_receives_exact_duplicate_refusal(self):
        self.record.write_text("retained\n")
        diagnostic = self.finish(self.start(full=False), 255)
        self.assertEqual(diagnostic, b"RCH_SCOPED_LAUNCH_ALREADY_OWNED\n")

    def test_normal_nonzero_workload_status_and_output_are_unchanged(self):
        launch = self.start(code=23)
        handle = self.admitted(launch)
        (self.root / "release").touch()
        self.finish(launch, 23)
        self.assert_dead(handle)
        self.assertEqual((self.root / "artifact").read_bytes(), b"completed-output")

    def test_missing_claim_parent_refuses_setup_without_an_output_consumer(self):
        self.record = self.root / "missing-parent" / "41.pgid"
        self.finish(self.start(), 125)
        self.assertFalse(self.record.exists())
        self.assertFalse((self.root / "ready").exists())

    def test_readable_setup_refusal_retains_its_exact_marker(self):
        self.record = self.root / "missing-parent" / "41.pgid"
        diagnostic = self.finish(self.start(full=False), 125)
        self.assertEqual(diagnostic, b"\nRCH_TEST_IDENTITY_UNAVAILABLE\n")
        self.assertFalse((self.root / "ready").exists())

    def test_disconnected_consumer_cannot_replace_refusal_with_sigpipe(self):
        self.record.write_text("retained\n")
        self.finish(self.start(full=False, disconnected=True), 255)
        self.assertEqual(self.record.read_text(), "retained\n")
        self.assertFalse((self.root / "ready").exists())

    def test_concurrent_unrelated_job_keeps_running_through_report_timeout(self):
        beats = self.root / "other-job"
        other = subprocess.Popen(
            [sys.executable, "-I", "-S", "-c",
             "import sys,time\nwhile True:\n"
             "    with open(sys.argv[1],'ab') as out: out.write(b'tick\\n')\n"
             "    time.sleep(.01)\n", str(beats)],
            stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
        self.children.append(other)
        self.handles.append(os.pidfd_open(other.pid))
        end = time.monotonic() + 3
        while not beats.exists() and time.monotonic() < end:
            time.sleep(.01)
        self.assertTrue(beats.exists())
        before = beats.stat().st_size
        self.record.write_text("retained\n")
        self.finish(self.start(), 255)
        self.assertIsNone(other.poll())
        self.assertGreater(beats.stat().st_size, before)

    def test_payload_stdout_stderr_and_nonzero_exit_remain_byte_exact(self):
        payload = ("import os,sys; os.write(1,bytes(range(256))*2); "
                   "os.write(2,b'payload-stderr:\\x00\\xff\\n'); sys.exit(23)")
        launch = self.start(full=False, payload=payload, stdout=subprocess.PIPE)
        diagnostic = self.finish(launch, 23)
        self.assertEqual(launch[0].stdout.read(), bytes(range(256)) * 2)
        self.assertEqual(diagnostic, b"payload-stderr:\x00\xff\n")

    def test_closed_stderr_remains_closed_in_the_workload(self):
        payload = ("import errno,os,sys\ntry: os.fstat(2)\n"
                   "except OSError as error: assert error.errno==errno.EBADF\n"
                   "else: raise AssertionError('stderr silently reopened')\n"
                   "os.write(1,b'closed-stderr'); sys.exit(23)\n")
        launch = self.start(script="exec 2>&-\n" + self.script,
                            payload=payload, stdout=subprocess.PIPE)
        self.finish(launch, 23)
        self.assertEqual(launch[0].stdout.read(), b"closed-stderr")


if __name__ == "__main__":
    unittest.main(verbosity=2)
