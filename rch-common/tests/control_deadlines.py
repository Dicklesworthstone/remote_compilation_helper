#!/usr/bin/env python3
"""Real subprocess regressions for the production worker-control exchanges.

Manager clients and selected ps failures are test executables. GNU timeout,
pipes, process groups, signals, the policy gate and snapshot parsers are real.
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

    def test_process_census_deadline_stops_a_term_resistant_ps(self) -> None:
        self.stalled_helper("ps", "client")
        result = self.run_shell(
            "rch_pgid=424242; rch_scope_bound=0; rch_group_state",
            stalled=True,
        )
        self.assertEqual(result.returncode, 2, result.stderr)
        self.assertEqual(result.stdout, b"")

    def test_process_census_deadline_includes_inherited_stdout_after_ps_exit(self) -> None:
        self.stalled_helper("ps", "stdout")
        result = self.run_shell(
            "rch_pgid=424242; rch_scope_bound=0; rch_group_state",
            stalled=True,
        )
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


@unittest.skipUnless(sys.platform == "linux" and hasattr(os, "pidfd_open"),
                     "requires Linux process identities and pidfd test cleanup")
class ProcessCensusRecovery(unittest.TestCase):
    """The process census is faulted; record/identity/signal/lock code is real."""

    def setUp(self) -> None:
        self.root = Path(tempfile.mkdtemp(prefix="rch-census-recovery-"))
        self.env = {**os.environ, "PATH": f"{self.root}:/usr/bin:/bin",
                    "RCH_CENSUS_ROOT": str(self.root), "LC_ALL": "C"}
        self.children = []
        self.handles = []
        self.addCleanup(self.stop_owned)
        self.count = self.root / "count"
        self.trace = self.root / "signals"
        self.count.write_text("0")
        ps = self.root / "ps"
        ps.write_text(f"#!{sys.executable}\n" + '''
import os, sys
from pathlib import Path
root = Path(os.environ["RCH_CENSUS_ROOT"])
counter = root / "count"
number = int(counter.read_text()) + 1
counter.write_text(str(number))
fault = os.environ.get("RCH_CENSUS_FAULT", "none")
bad = (fault in ("failed", "malformed") and number == 1
       or fault == "persistent"
       or fault == "after-term" and number == 2
       or fault == "persistent-after-term" and number >= 2)
if bad:
    if fault == "malformed":
        print("not a process census")
        sys.exit(0)
    sys.exit(19)
os.execv("/usr/bin/ps", ["ps", *sys.argv[1:]])
''')
        ps.chmod(0o700)
        # The control channel records actual signals, never substitutes success.
        self.observe = '''
kill() { printf '%s\\n' "$*" >> "$RCH_CENSUS_ROOT/signals"; command kill "$@"; }
'''
        self.other = self.group()

    def stop_owned(self) -> None:
        for descriptor in self.handles:
            try:
                signal.pidfd_send_signal(descriptor, signal.SIGKILL)
            except ProcessLookupError:
                pass
        for child in self.children:
            if child.poll() is None:
                child.kill()
            child.wait(timeout=5)
        for descriptor in self.handles:
            os.close(descriptor)

    def group(self):
        root = self.root / f"group-{len(self.children)}"
        root.mkdir()
        record = root / "record"
        worker_code = '''
import fcntl, os, signal, sys, time
from pathlib import Path
root = Path(sys.argv[1])
signal.signal(signal.SIGTERM, signal.SIG_IGN)
lock = (root / "held.lock").open("a")
fcntl.flock(lock, fcntl.LOCK_EX)
(root / "worker").write_text(str(os.getpid()))
while True:
    with (root / "beats").open("ab") as out: out.write(b"tick\\n")
    time.sleep(.02)
'''
        leader_code = '''
import os, subprocess, sys, time
from pathlib import Path
root = Path(sys.argv[1])
worker = subprocess.Popen([sys.executable, "-I", "-S", "-c", sys.argv[2], str(root)])
while not (root / "beats").exists(): time.sleep(.01)
(root / "ready.tmp").write_text(str(worker.pid))
(root / "ready.tmp").rename(root / "ready")
time.sleep(60)
'''
        # No watchdog can mask a failed stop: this is exactly one recorded
        # leader and one TERM-resistant child holding a real file lock.
        body = PROTOCOL + '''
rch_apply_configured_worker_policy() { return 0; }
rch_remote_record "$1" 41 || exit 90
shift
exec "$@"
'''
        child = subprocess.Popen([SHELL, "-c", body, "rch-census-fixture", str(record),
                                  sys.executable, "-I", "-S", "-c", leader_code,
                                  str(root), worker_code], start_new_session=True,
                                 stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                                 stderr=subprocess.DEVNULL)
        self.children.append(child)
        leader = os.pidfd_open(child.pid)
        self.handles.append(leader)
        deadline = time.monotonic() + 5
        while not (root / "ready").exists() and time.monotonic() < deadline:
            self.assertIsNone(child.poll(), "recorded fixture did not start")
            time.sleep(.01)
        self.assertTrue((root / "ready").exists(), "fixture did not acquire its lock")
        worker = os.pidfd_open(int((root / "ready").read_text()))
        self.handles.append(worker)
        return child, record, leader, worker

    def recover(self, group, fault="none", mode="kill", extra="", body=None):
        _, record, _, _ = group
        before = (record.lstat().st_ino, record.read_bytes())
        command = body or 'rch_remote_cancel "$1" 41 "$2"'
        result = subprocess.run([SHELL, "-c", PROTOCOL + "\n" + self.observe + extra
                                 + "\n" + command, "rch-census-test", str(record), mode],
                                capture_output=True, timeout=8, start_new_session=True,
                                env={**self.env, "RCH_CENSUS_FAULT": fault})
        self.assertEqual((record.lstat().st_ino, record.read_bytes()), before)
        self.assert_alive(self.other)
        return result

    @staticmethod
    def exited(descriptor, wait=0):
        poll = select.poll()
        poll.register(descriptor, select.POLLIN)
        return bool(poll.poll(wait))

    def assert_alive(self, group):
        self.assertFalse(self.exited(group[2]), "unrelated leader was stopped")
        self.assertFalse(self.exited(group[3]), "unrelated worker was stopped")
        beats = group[1].parent / "beats"
        before = beats.stat().st_size
        deadline = time.monotonic() + 1
        while beats.stat().st_size == before and time.monotonic() < deadline:
            time.sleep(.01)
        self.assertGreater(beats.stat().st_size, before, "live job stopped making progress")

    def assert_stopped(self, group):
        self.assertTrue(self.exited(group[2], 1500), "recorded leader survived cancellation")
        self.assertTrue(self.exited(group[3], 1500), "TERM-resistant descendant survived")
        import fcntl
        with (group[1].parent / "held.lock").open("a") as lock:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)

    def signals(self):
        return self.trace.read_text().splitlines() if self.trace.exists() else []

    def test_failed_initial_census_stops_the_authenticated_group(self):
        for mode in ("kill", "term"):
            with self.subTest(mode=mode):
                self.count.write_text("0")
                group = self.group()
                result = self.recover(group, "failed", mode)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assert_stopped(group)
                self.assertEqual(self.signals()[-1], f"-KILL -{group[0].pid}")

    def test_malformed_successful_census_does_not_strand_an_owned_group(self):
        group = self.group()
        result = self.recover(group, "malformed")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assert_stopped(group)

    def test_persistent_census_failure_stops_work_but_cannot_confirm_cleanup(self):
        group = self.group()
        result = self.recover(group, "persistent")
        self.assertEqual(result.returncode, 44, result.stderr)
        self.assert_stopped(group)
        # Only a later genuine census establishes the release postcondition.
        self.assertEqual(self.recover(group).returncode, 0)

    def test_census_failure_after_term_keeps_this_calls_live_escalation_witness(self):
        group = self.group()
        result = self.recover(group, "after-term", "term")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(group[0].wait(timeout=3), -signal.SIGTERM)
        self.assert_stopped(group)
        self.assertEqual(self.signals(), [f"-TERM -{group[0].pid}", f"-KILL -{group[0].pid}"])

    def test_persistent_failure_after_term_still_escalates_without_claiming_completion(self):
        group = self.group()
        result = self.recover(group, "persistent-after-term", "term")
        self.assertEqual(result.returncode, 44, result.stderr)
        self.assert_stopped(group)
        self.assertEqual(self.recover(group).returncode, 0)

    def test_wrong_leader_birth_never_authorizes_a_signal(self):
        group = self.group()
        fields = group[1].read_text().strip().split(":")
        fields[4] = str(int(fields[4]) + 1)
        group[1].write_text(":".join(fields) + "\n")
        result = self.recover(group, "failed")
        self.assertNotEqual(result.returncode, 0)
        self.assert_alive(group)
        self.assertEqual(self.signals(), [])

    def test_legacy_pid_never_borrows_an_authenticated_identity(self):
        group = self.group()
        group[1].write_text(str(group[0].pid) + "\n")
        result = self.recover(group, "failed", extra="rch_identified=1\nrch_term_sent=1\n")
        self.assertNotEqual(result.returncode, 0)
        self.assert_alive(group)
        self.assertEqual(self.signals(), [])

    def test_preexisting_orphan_is_not_adopted_as_a_new_escalation_witness(self):
        group = self.group()
        group[0].terminate()
        group[0].wait(timeout=3)
        result = self.recover(group, "failed", "term")
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(self.exited(group[3]))
        self.assertEqual(self.signals(), [])

    def test_unknown_namespace_cannot_authorize_cleanup(self):
        group = self.group()
        result = self.recover(group, "failed", extra="rch_check_procfs_namespace() { return 1; }\n")
        self.assertEqual(result.returncode, 44, result.stderr)
        self.assert_alive(group)
        self.assertEqual(self.signals(), [])

    def test_signal_path_independently_refuses_the_observers_own_group(self):
        # All processes in this session are test-owned, so a missing guard is
        # observable as signal death without threatening the harness's group.
        for invocation in ('rch_signal_group KILL', '(rch_signal_group KILL)'):
            with self.subTest(invocation=invocation):
                body = '''
rch_apply_configured_worker_policy() { return 0; }
rch_remote_record "$1" 41 || exit 90
rch_read_record "$1" 41 || exit 91
''' + invocation + '''
status=$?
[ "$status" -ne 0 ] || exit 92
printf survived
'''
                result = subprocess.run([SHELL, "-c", PROTOCOL + "\n" + self.observe + body,
                                         "rch-census-self", str(self.root / "self-record")],
                                        capture_output=True, timeout=5, start_new_session=True,
                                        env=self.env)
                self.assertEqual((result.returncode, result.stdout), (0, b"survived"), result.stderr)
                self.assertEqual(self.signals(), [])


if __name__ == "__main__":
    unittest.main(verbosity=2)
