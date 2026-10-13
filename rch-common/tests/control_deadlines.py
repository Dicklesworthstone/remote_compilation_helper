#!/usr/bin/env python3
"""Real subprocess regressions for the production worker-control exchanges.

Only systemctl/busctl are test executables. GNU timeout, pipe inheritance,
process groups, signals, the policy gate and the snapshot parser are real.
This suite does not claim a live systemd, cgroup or SSH fleet qualification.
The Rust integration target supplies the compiled protocol; direct Python
runs use the checked-out production shell file. Test evidence is retained.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
import select
import signal
import subprocess
import sys
import tempfile
import time
import unittest

PROTOCOL = Path(os.environ.get(
    "RCH_CONTROL_TEST_PROTOCOL",
    str(Path(__file__).resolve().parents[1] / "src" / "remote_process.sh"),
)).read_text()
SHELL = os.environ.get("RCH_CONTROL_TEST_SHELL", "/bin/sh")
SNAPSHOT = "LoadState=loaded\nActiveState=active\nInvocationID=1234567890abcdef1234567890abcdef\nControlGroup=/jobs.slice/test.scope\n"
SNAPSHOT_CALL = 'rch_scope_manager=user; rch_scope_unit=test.scope; rch_scope_snapshot'


@unittest.skipUnless(sys.platform == "linux" and hasattr(os, "pidfd_open"),
                     "requires Linux pidfd handles and GNU timeout")
class ControlDeadlines(unittest.TestCase):
    def setUp(self) -> None:
        self.root = Path(tempfile.mkdtemp(prefix="rch-control-deadlines-"))
        self.env = {**os.environ, "PATH": f"{self.root}:/usr/bin:/bin",
                    "RCH_CONTROL_TEST_ROOT": str(self.root)}

    def helper(self, name: str, body: str) -> None:
        path = self.root / name
        path.write_text(f"#!{sys.executable}\n" +
                        "import json, os, signal, sys, time\nfrom pathlib import Path\n" +
                        "root = Path(os.environ['RCH_CONTROL_TEST_ROOT'])\n" + body)
        path.chmod(0o700)

    def run_shell(self, body: str, *args: str, stdin: bytes = b"",
                  stalled: bool = False, budget: float = 4) -> subprocess.CompletedProcess[bytes]:
        process = subprocess.Popen([SHELL, "-c", PROTOCOL + "\n" + body,
                                    "rch-control-test", *args], env=self.env,
                                   stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                   stderr=subprocess.PIPE, start_new_session=True)
        handles: list[int] = []
        try:
            if stalled:
                ready = self.root / "ready.json"
                deadline = time.monotonic() + 3
                while not ready.exists() and process.poll() is None and time.monotonic() < deadline:
                    time.sleep(0.01)
                self.assertTrue(ready.exists(), "test helper did not reach the intended wait")
                identities = json.loads(ready.read_text())
                # The test executable publishes its own PID and timeout's PGID.
                # Bind handles BEFORE waiting for completion, never signal a
                # stale numeric PID on timeout or after a successful test.
                for pid in dict.fromkeys(identities):
                    try:
                        handles.append(os.pidfd_open(pid))
                    except ProcessLookupError:
                        pass  # The old timeout can exit before its pipe holder.
                self.assertTrue(handles, "no live test-owned wait witness")
            try:
                out, err = process.communicate(input=stdin, timeout=budget)
            except subprocess.TimeoutExpired:
                self.fail(f"control exchange exceeded outer {budget}s test deadline")
            if stalled:
                poll = select.poll()
                for fd in handles:
                    poll.register(fd, select.POLLIN)
                remaining = set(handles)
                deadline = time.monotonic() + 2
                while remaining and time.monotonic() < deadline:
                    remaining.difference_update(fd for fd, _ in poll.poll(50))
                self.assertFalse(remaining, "timed-out helper or pipe holder is still alive")
            return subprocess.CompletedProcess(process.args, process.returncode, out, err)
        finally:
            for fd in handles:
                try:
                    signal.pidfd_send_signal(fd, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                os.close(fd)
            if process.poll() is None:
                process.kill()
            process.communicate(timeout=3)

    def stalled_helper(self, name: str, kind: str) -> None:
        self.helper(name, f'''
kind = {kind!r}
if kind != "client":
    if os.fork():
        print({SNAPSHOT!r}, end="", flush=True)
        sys.exit(0)
    if kind == "stderr":
        os.dup2(os.open(os.devnull, os.O_WRONLY), 1)
signal.signal(signal.SIGTERM, signal.SIG_IGN)
ready = root / "ready.tmp"
ready.write_text(json.dumps([os.getpid(), os.getpgrp()]))
ready.rename(root / "ready.json")
if kind == "client":
    print({SNAPSHOT!r}, end="", flush=True)
time.sleep(20)
''')

    def test_snapshot_deadline_stops_a_term_resistant_client(self) -> None:
        self.stalled_helper("systemctl", "client")
        result = self.run_shell(SNAPSHOT_CALL, stalled=True)
        self.assertEqual(result.returncode, 2, result.stderr)
        self.assertEqual(result.stdout, b"")

    def test_snapshot_deadline_includes_inherited_stdout_after_client_exit(self) -> None:
        self.stalled_helper("systemctl", "stdout")
        result = self.run_shell(SNAPSHOT_CALL, stalled=True)
        self.assertEqual(result.returncode, 2, result.stderr)
        self.assertEqual(result.stdout, b"")

    def test_snapshot_deadline_includes_inherited_stderr_after_client_exit(self) -> None:
        self.stalled_helper("systemctl", "stderr")
        result = self.run_shell(SNAPSHOT_CALL, stalled=True)
        self.assertEqual(result.returncode, 2, result.stderr)
        self.assertEqual(result.stdout, b"")

    def test_scope_creation_has_an_external_hard_deadline_and_no_admission(self) -> None:
        self.helper("systemctl", '''
if "--property=ActiveState" in sys.argv: print("active")
elif "--property=ControlGroup" in sys.argv: print("/jobs.slice")
else: sys.exit(19)
''')
        self.stalled_helper("busctl", "client")
        result = self.run_shell('''
rch_policy_manager=user; rch_policy_slice=jobs.slice
rch_boot=12345678-1234-1234-1234-123456789abc; rch_pgid=$$; rch_start=1
rch_policy_enter_scope || exit $?
printf payload-admitted
''', stalled=True, budget=8)
        self.assertEqual(result.returncode, 125, result.stderr)
        self.assertIn(b"RCH_WORKER_POLICY_REFUSED:scope_creation", result.stderr)
        self.assertEqual(result.stdout, b"")

    def test_failed_response_is_not_published_as_a_successful_value(self) -> None:
        self.helper("systemctl", 'print("active"); print("manager failed", file=sys.stderr); sys.exit(17)\n')
        result = self.run_shell('rch_policy_manager=user; rch_policy_systemctl show')
        self.assertEqual(result.returncode, 17)
        self.assertEqual(result.stdout, b"")
        self.assertIn(b"active", result.stderr)
        self.assertIn(b"manager failed", result.stderr)
        # Several existing policy checks compare a substitution's value. An
        # error printing "active" must never satisfy those checks.
        gate = self.run_shell('rch_policy_manager=user; [ "$(rch_policy_systemctl show)" = active ]')
        self.assertNotEqual(gate.returncode, 0)

    def test_control_exchange_does_not_consume_the_callers_stdin(self) -> None:
        self.helper("systemctl", '''
(root / "stdin").write_bytes(sys.stdin.buffer.read())
print("active")
''')
        result = self.run_shell('''
rch_policy_manager=user
rch_policy_systemctl show >/dev/null || exit $?
IFS= read -r pending || exit 81
printf '%s\n' "$pending"
''', stdin=b"next-bootstrap-command\n")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, b"next-bootstrap-command\n")
        self.assertEqual((self.root / "stdin").read_bytes(), b"")

    def test_success_keeps_argv_literal_and_does_not_change_caller_authority(self) -> None:
        self.helper("systemctl", '''
(root / "args.json").write_text(json.dumps(sys.argv[1:]))
print("active")
''')
        literal = "a b:'$(touch not-a-command)'*[x]"
        result = self.run_shell('''
rch_policy_manager=system; rch_pgid=123; rch_start=456; rch_scope_bound=1
value=$(rch_policy_systemctl show --value --property=ActiveState -- "$1") || exit $?
[ "$rch_pgid:$rch_start:$rch_scope_bound:$rch_policy_manager" = 123:456:1:system ] || exit 82
printf '%s\n' "$value"
''', literal)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, b"active\n")
        self.assertEqual(json.loads((self.root / "args.json").read_text()),
                         ["--system", "--no-pager", "--no-ask-password", "show",
                          "--value", "--property=ActiveState", "--", literal])

    def test_complete_snapshot_required_and_warnings_do_not_authorize_state(self) -> None:
        self.helper("systemctl", f'print({SNAPSHOT!r}, end="")\n')
        self.assertEqual(self.run_shell(SNAPSHOT_CALL).returncode, 0)
        for value in ("", SNAPSHOT + "ActiveState=inactive\n",
                      SNAPSHOT.replace("LoadState=loaded\n", ""),
                      SNAPSHOT.replace("ActiveState=active", "ActiveState=activating")):
            with self.subTest(response=value):
                self.helper("systemctl", f'print({value!r}, end="")\n')
                self.assertEqual(self.run_shell(SNAPSHOT_CALL).returncode, 2)
        self.helper("systemctl", f'print({SNAPSHOT!r}, end=""); print("unverified warning", file=sys.stderr)\n')
        self.assertEqual(self.run_shell(SNAPSHOT_CALL).returncode, 2)


if __name__ == "__main__":
    unittest.main(verbosity=2)
