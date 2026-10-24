#!/usr/bin/env python3
"""Exercise worker launch stdin through the actual owned-group supervisor.

Only policy-file discovery is redirected to a private fixture. Process identity,
record publication, admission, workload execution, output, deadlines, group
census and cancellation all use the production shell. No live SSH, daemon or
systemd is involved. Fixtures are retained; cleanup signals only test-owned
processes, never an unbound historical PID. Cargo can supply compiled protocol
bytes and the standalone expansion must match them exactly.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
import re
import shlex
import signal
import socket
import string
import subprocess
import sys
import tempfile
import time
import unittest

SOURCE = Path(__file__).resolve().parents[1] / "src"
SHELL = os.environ.get("RCH_TEST_SHELL", "/bin/sh")


def _neutral_scheduling():
    # cargo under ananicy runs at nice 19 in SCHED_IDLE and its tests inherit
    # both, which starves the one-second deadlines here. Start from the
    # defaults when the host allows it.
    if sys.platform != "linux":
        return
    try:
        if os.sched_getscheduler(0) == os.SCHED_IDLE:
            os.sched_setscheduler(0, os.SCHED_OTHER, os.sched_param(0))
        if os.getpriority(os.PRIO_PROCESS, 0) > 0:
            os.setpriority(os.PRIO_PROCESS, 0, 0)
    except OSError:
        pass


_neutral_scheduling()
SELECT = '''
rch_policy_select_file() {
    rch_policy_file=${RCH_STDIN_POLICY-}
    rch_policy_owner=$(id -u)
}
'''


def assemble_protocol() -> str:
    rust = (SOURCE / "remote_scoped_launch.rs").read_text()
    expression = rust.split("= concat!(\n", 1)[1].split("\n);", 1)[0]
    parts = []
    for line in expression.splitlines():
        item = line.strip().removesuffix(",")
        include = re.fullmatch(r'include_str!\(("[^"\n]+")\)', item)
        parts.append((SOURCE / json.loads(include[1])).read_text()
                     if include else json.loads(item))
    expanded = "".join(parts)
    compiled = os.environ.get("RCH_TEST_PROTOCOL_SCRIPT")
    if compiled and Path(compiled).read_text() != expanded:
        raise AssertionError("compiled protocol differs from its exact source expansion")
    return expanded


def protocol() -> str:
    expanded = assemble_protocol()
    core = (SOURCE / "remote_process.sh").read_text()
    if expanded.count(core) != 1:
        raise AssertionError("expected one identity implementation shared by parent and child")
    return expanded.replace(core, core + SELECT)


def process(pid: int):
    try:
        fields = Path(f"/proc/{pid}/stat").read_text().rsplit(") ", 1)[1].split()
        return fields[0], int(fields[2]), int(fields[19])
    except FileNotFoundError:
        return None


def quote_transport(value: str) -> str:
    safe = string.ascii_letters + string.digits + "-_=/,.+"
    if value and all(char in safe for char in value):
        return value
    return "'" + "".join("'\\" + c + "'" if c in "'!" else c for c in value) + "'"


@unittest.skipUnless(sys.platform == "linux", "Linux worker supervision")
class WorkloadStdin(unittest.TestCase):
    def setUp(self):
        self.root = Path(tempfile.mkdtemp(prefix="rch-workload-stdin-"))
        self.record = self.root / "42.pgid"
        self.children = []
        self.env = {**os.environ, "RCH_STDIN_POLICY": "", "RCH_STDIN_ROOT": str(self.root)}

    def tearDown(self):
        # A failed assertion must not leave the fixture's watchdog running.
        # Bind the signal to the exact fresh record and still-pinned group.
        if self.record.exists():
            fields = self.record.read_text().strip().split(":")
            if len(fields) >= 5 and fields[1] == "42":
                pid, birth = int(fields[3]), int(fields[4])
                observed = process(pid)
                if observed and observed[1:] == (pid, birth):
                    try:
                        os.killpg(pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
        for child in self.children:
            if child.poll() is None:
                child.kill()
            child.communicate(timeout=5)
            for stream in (child.stdin, child.stdout, child.stderr):
                if stream is not None and not stream.closed:
                    stream.close()

    def start(self, code, *args, stdin=subprocess.PIPE, prefix="", limit=8, layers=0):
        body = prefix + "\nexec 3>&2\n" + protocol()
        for _ in range(layers):
            body = f'exec {shlex.quote(SHELL)} -c {quote_transport(body)} rch-build "$@"'
        child = subprocess.Popen(
            [SHELL, "-c", body, "rch-build", str(self.record), str(limit),
             "RCH_STDIN_DEADLINE", "42", sys.executable, "-I", "-S", "-c", code, *args],
            stdin=stdin, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=self.env,
        )
        self.children.append(child)
        return child

    def result(self, child, data=None, expected=0):
        stdout, stderr = child.communicate(data, timeout=15)
        self.assertEqual(child.returncode, expected, stderr.decode(errors="replace"))
        self.assertNotIn(b"COMPLETION_UNCONFIRMED", stderr)
        return stdout, stderr

    def test_binary_pipe_crosses_both_launches_and_preserves_nonzero_status(self):
        data = bytes(range(256)) * 2048 + b"\x00tail\xff"
        child = self.start("import sys; sys.stdout.buffer.write(sys.stdin.buffer.read()); "
                           "sys.stderr.write('diagnostic\\n'); sys.exit(7)")
        stdout, stderr = self.result(child, data, expected=7)
        self.assertEqual(stdout, data)
        self.assertIn(b"diagnostic\n", stderr)

    def test_regular_file_keeps_type_and_shared_current_offset(self):
        path = self.root / "input"
        data = b"already consumed" + bytes(range(256)) * 1024
        path.write_bytes(data)
        with path.open("rb", buffering=0) as source:
            source.seek(16)
            child = self.start("import os, stat, sys; assert stat.S_ISREG(os.fstat(0).st_mode); "
                               "sys.stdout.buffer.write(sys.stdin.buffer.read())", stdin=source)
            stdout, _ = self.result(child)
            self.assertEqual(stdout, data[16:])
            self.assertEqual(source.tell(), len(data))
        self.assertEqual(path.read_bytes(), data)

    def test_payload_arguments_remain_literal_through_descriptor_eval(self):
        arguments = ["", "quote'!\\", "$(touch INJECTED)", "\nend; false", "é"]
        code = "import json,sys; print(json.dumps(sys.argv[1:]), flush=True); " \
               "sys.stdout.buffer.write(sys.stdin.buffer.read())"
        stdout, _ = self.result(self.start(code, *arguments), b"payload")
        line, rest = stdout.split(b"\n", 1)
        self.assertEqual(json.loads(line), arguments)
        self.assertEqual(rest, b"payload")

    def test_existing_control_descriptors_are_not_replaced_or_closed(self):
        (self.root / "four").write_bytes(b"four")
        (self.root / "nine").write_bytes(b"nine")
        prefix = 'exec 4<"$RCH_STDIN_ROOT/four" 9<"$RCH_STDIN_ROOT/nine"'
        code = "import os,sys; assert os.read(4,4)==b'four'; assert os.read(9,4)==b'nine'; " \
               "sys.stdout.buffer.write(sys.stdin.buffer.read())"
        stdout, _ = self.result(self.start(code, prefix=prefix), b"stdin")
        self.assertEqual(stdout, b"stdin")

    def test_closed_stdin_stays_closed_without_borrowing_a_descriptor(self):
        prefix = "exec 0<&- 4</dev/null 5</dev/null 6</dev/null 7</dev/null 8</dev/null 9</dev/null"
        code = "import errno,os\ntry: os.read(0,1)\nexcept OSError as e: assert e.errno==errno.EBADF\n" \
               "else: raise AssertionError('stdin silently reopened')\nos.write(1,b'closed')"
        stdout, _ = self.result(self.start(code, prefix=prefix))
        self.assertEqual(stdout, b"closed")

    def test_each_borrowed_descriptor_is_closed_without_touching_existing_ones(self):
        for available in range(4, 10):
            with self.subTest(available=available):
                # Each invocation has its own immutable process record.
                self.record = self.root / f"borrow-{available}.pgid"
                prefix = "exec " + " ".join(f"{fd}</dev/null" for fd in range(4, 10)
                                           if fd != available)
                code = "import errno,os,sys\n" \
                       "for fd in range(3,10):\n" \
                       f"    if fd in (3,{available}):\n" \
                       "        try: os.fstat(fd)\n" \
                       "        except OSError as e: assert e.errno==errno.EBADF\n" \
                       "        else: raise AssertionError('internal descriptor leaked')\n" \
                       "    else: assert os.read(fd,1)==b''\n" \
                       "sys.stdout.buffer.write(sys.stdin.buffer.read())"
                stdout, _ = self.result(self.start(code, prefix=prefix), b"descriptor input")
                self.assertEqual(stdout, b"descriptor input")

    def test_descriptor_exhaustion_refuses_before_workload_or_record(self):
        prefix = "exec 4</dev/null 5</dev/null 6</dev/null 7</dev/null 8</dev/null 9</dev/null"
        child = self.start("import os; open(os.environ['RCH_STDIN_ROOT']+'/ran','w').write('ran')",
                           prefix=prefix)
        self.result(child, b"input", expected=125)
        self.assertFalse((self.root / "ran").exists())
        self.assertFalse(self.record.exists())

    def wait_ready(self, child):
        deadline = time.monotonic() + 5
        path = self.root / "ready"
        while time.monotonic() < deadline:
            if path.exists() and path.stat().st_size:
                pid = int(path.read_text())
                return os.pidfd_open(pid)
            self.assertIsNone(child.poll(), "workload exited before blocking on stdin")
            time.sleep(.01)
        self.fail("workload did not reach the actual input read")

    def assert_exited(self, descriptor):
        import select
        poll = select.poll()
        poll.register(descriptor, select.POLLIN)
        self.assertTrue(poll.poll(1500), "owned workload survived terminal result")

    def blocked_reader(self, limit=8):
        return self.start("import os; open(os.environ['RCH_STDIN_ROOT']+'/ready','w').write(str(os.getpid())); "
                          "os.read(0,1)", limit=limit)

    def test_deadline_still_terminates_a_workload_blocked_on_open_stdin(self):
        child = self.blocked_reader(limit=1)
        descriptor = self.wait_ready(child)
        try:
            child.wait(timeout=8)  # Do not close stdin to help it finish.
            self.result(child, expected=137)
            self.assert_exited(descriptor)
        finally:
            try:
                signal.pidfd_send_signal(descriptor, signal.SIGKILL)
            except ProcessLookupError:
                pass
            os.close(descriptor)

    def test_cancellation_still_terminates_a_workload_blocked_on_open_stdin(self):
        child = self.blocked_reader()
        descriptor = self.wait_ready(child)
        try:
            child.terminate()
            child.wait(timeout=8)
            self.result(child, expected=143)
            self.assert_exited(descriptor)
        finally:
            try:
                signal.pidfd_send_signal(descriptor, signal.SIGKILL)
            except ProcessLookupError:
                pass
            os.close(descriptor)

    def test_nice_policy_and_input_are_both_enforced(self):
        policy = self.root / "policy"
        policy.write_text("version=1\nnice=10\n")
        policy.chmod(0o600)
        self.env["RCH_STDIN_POLICY"] = str(policy)
        code = "import os,sys; assert os.getpriority(os.PRIO_PROCESS,0)==10; " \
               "sys.stdout.buffer.write(sys.stdin.buffer.read())"
        stdout, stderr = self.result(self.start(code), b"configured input")
        self.assertEqual(stdout, b"configured input")
        self.assertIn(b"RCH_WORKER_EXECUTION_POLICY:nice=10", stderr)

    def test_socket_stdin_is_not_replaced_with_a_pipe_or_waited_to_eof(self):
        source, peer = socket.socketpair()
        try:
            code = "import os,stat; assert stat.S_ISSOCK(os.fstat(0).st_mode); os.write(1,os.read(0,5))"
            child = self.start(code, stdin=source)
            source.close()
            peer.sendall(b"hello")
            stdout, _ = self.result(child)  # Peer stays OPEN throughout completion.
            self.assertEqual(stdout, b"hello")
        finally:
            source.close()
            peer.close()

    def test_four_transport_layers_retain_payload_and_argument_headroom(self):
        body = assemble_protocol()
        for _ in range(4):
            body = f"exec /bin/sh -c {quote_transport(body)} rch-transport"
        self.assertLess(len(body.encode()), 110_000)
        stdout, _ = self.result(self.start("import sys; sys.stdout.buffer.write(sys.stdin.buffer.read())",
                                          layers=4), b"nested input\0")
        self.assertEqual(stdout, b"nested input\0")


if __name__ == "__main__":
    unittest.main(verbosity=2)
