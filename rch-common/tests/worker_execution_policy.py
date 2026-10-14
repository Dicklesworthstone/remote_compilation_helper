#!/usr/bin/env python3
"""Linux protocol integration tests for the actual embedded launch/cancel shell.

No SSH server or Rust build is claimed by these tests. Policy-file discovery is
injected for isolation; parsing, niceness, /proc identity and signal escalation
are real. systemd failure tests use explicit command doubles, never a fake cgroup
observation. Set RCH_TEST_SYSTEMD_SLICE to an already active user slice to opt in
to the real systemd placement test on a disposable Linux test worker.
"""
from __future__ import annotations

import os
from pathlib import Path
import shutil
import signal
import subprocess
import sys
import tempfile
import time
import unittest

SOURCE = Path(__file__).resolve().parents[1] / "src" / "remote_process.sh"
SCRIPT = SOURCE.read_text()
SELECT_FIXTURE = r'''
rch_policy_select_file() {
    rch_policy_file=$RCH_TEST_POLICY_FILE
    rch_policy_owner=$(id -u)
}
'''


def _neutral_python() -> str:
    """The interpreter under a name no ananicy rule matches.

    ananicy-cpp re-nices processes by name on the build fleet (``python3`` ->
    nice 5), after the launcher has set the niceness these suites assert, so
    the assertions failed run to run on those hosts. A symlink is the same
    binary; only the process name (``comm``) differs, and child interpreters
    inherit it through ``sys.executable``.
    """
    if sys.platform != "linux" or Path(sys.executable).name == "rchtestpy":
        return sys.executable
    alias = Path(tempfile.mkdtemp(prefix="rch-test-interp-")) / "rchtestpy"
    alias.symlink_to(sys.executable)
    return str(alias)


def _neutral_scheduling():
    # cargo under ananicy runs at nice 19 in SCHED_IDLE and its tests inherit
    # both: deadlines starve and requested priorities cannot be applied. Start
    # from the defaults when the host allows it.
    if sys.platform != "linux":
        return
    try:
        if os.sched_getscheduler(0) == os.SCHED_IDLE:
            os.sched_setscheduler(0, os.SCHED_OTHER, os.sched_param(0))
        if os.getpriority(os.PRIO_PROCESS, 0) > 0:
            os.setpriority(os.PRIO_PROCESS, 0, 0)
    except OSError:
        pass


PYTHON = _neutral_python()
if PYTHON != sys.executable:
    _neutral_scheduling()
    # Re-run this harness under the alias too: a child forked from a process
    # named `python3` carries that name until it execs, and an ananicy pass
    # landing in that window re-nices it for good.
    os.execv(PYTHON, [PYTHON, *sys.argv])


def setUpModule() -> None:
    # ananicy-cpp rules on the build fleet put `cargo` and everything it spawns
    # in SCHED_IDLE, where procps prints NI as "-" and niceness cannot be
    # observed. Production launchers start from sshd in the normal class.
    # Leaving SCHED_IDLE for SCHED_OTHER at the same niceness is unprivileged.
    if sys.platform == "linux" and os.sched_getscheduler(0) not in (os.SCHED_OTHER, os.SCHED_BATCH):
        os.sched_setscheduler(0, os.SCHED_OTHER, os.sched_param(0))


@unittest.skipUnless(sys.platform == "linux", "Linux process identity backend")
class WorkerExecutionPolicy(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory(prefix="rch-worker-policy-test-")
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.policy = self.root / "policy.conf"
        self.record = self.root / "42.pgid"
        self.payload = self.root / "payload"
        self.env = {**os.environ, "RCH_TEST_POLICY_FILE": str(self.policy)}
        self.env.pop("RCH_TEST_SYSTEMD_SLICE", None)
        self.processes: list[subprocess.Popen[str]] = []
        self.addCleanup(self.reap_owned_processes)

    def reap_owned_processes(self) -> None:
        for proc in self.processes:
            # Every recorded process was created with start_new_session=True.
            if proc.poll() is None:
                try:
                    os.killpg(proc.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
            proc.wait(timeout=5)
            for pipe in (proc.stdin, proc.stdout, proc.stderr):
                if pipe is not None:
                    pipe.close()

    def write_policy(self, content: str | bytes = "version=1\nnice=10\n") -> None:
        self.policy.write_bytes(content.encode() if isinstance(content, str) else content)
        self.policy.chmod(0o600)

    def run_shell(self, body: str, *args: object, env: dict[str, str] | None = None,
                  session: bool = True, timeout: float = 12) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            ["/bin/sh", "-c", SCRIPT + SELECT_FIXTURE + body, "rch-policy-test", *map(str, args)],
            env=self.env if env is None else env, text=True, capture_output=True,
            start_new_session=session, timeout=timeout, check=False,
        )

    def parse(self) -> subprocess.CompletedProcess[str]:
        return self.run_shell(r'''
rch_policy_read_file "$1" "$(id -u)" || exit $?
printf '%s:%s:%s\n' "$rch_policy_nice" "$rch_policy_slice" "$rch_policy_manager"
''', self.policy)

    def launch(self, prefix: str = "", env: dict[str, str] | None = None) -> subprocess.CompletedProcess[str]:
        return self.run_shell(prefix + r'''
rch_remote_record "$1" 42 || exit $?
printf 'payload\n' > "$2"
ps -o ni= -p "$$"
''', self.record, self.payload, env=env)

    def fake(self, name: str, body: str) -> None:
        directory = self.root / "bin"
        directory.mkdir(exist_ok=True)
        path = directory / name
        path.write_text("#!/bin/sh\n" + body + "\n")
        path.chmod(0o700)
        self.env["PATH"] = str(directory) + ":/usr/bin:/bin"

    def start_live(self, build: int = 42) -> tuple[subprocess.Popen[str], Path, Path]:
        record = self.root / f"{build}.pgid"
        ready = self.root / f"{build}.ready"
        # An independently configured child ignores TERM, exercising witnessed
        # KILL escalation after the original group leader has been terminated.
        child = (
            "import os,signal,sys,time; "
            "signal.signal(signal.SIGTERM, signal.SIG_IGN); "
            "open(sys.argv[1], 'w').write(str(os.getpid())); time.sleep(60)"
        )
        body = r'''
rch_remote_record "$1" "$2" || exit $?
"$4" -c "$5" "$3" &
wait
'''
        proc = subprocess.Popen(
            ["/bin/sh", "-c", SCRIPT + SELECT_FIXTURE + body, "rch-policy-test",
             str(record), str(build), str(ready), PYTHON, child],
            env=self.env, text=True, stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True,
        )
        self.processes.append(proc)
        deadline = time.monotonic() + 5
        while not ready.exists() and proc.poll() is None and time.monotonic() < deadline:
            time.sleep(0.02)
        self.assertTrue(ready.exists(), f"build {build} did not become ready")
        return proc, record, ready

    def cancel(self, record: Path, build: int = 42, mode: str = "term") -> subprocess.CompletedProcess[str]:
        return self.run_shell(r'''rch_remote_cancel "$1" "$2" "$3"''', record, build, mode)

    def test_nice_grammar_boundaries(self) -> None:
        for nice in ("-20", "-19", "-1", "0", "1", "10", "19"):
            with self.subTest(nice=nice):
                self.write_policy(f"version=1\nnice={nice}\n")
                result = self.parse()
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(result.stdout, f"{nice}::user\n")
        for nice in ("-21", "20", "100", "+1", "01", "-0", "1.0", " 1", "1 ", "$(id)", "1;id", ""):
            with self.subTest(nice=nice):
                self.write_policy(f"version=1\nnice={nice}\n")
                self.assertEqual(self.parse().returncode, 125)

    def test_slice_and_manager_grammar(self) -> None:
        for slice_name in ("jobs.slice", "jobs-low.slice", "build_2.slice"):
            self.write_policy(f"version=1\nsystemd_slice={slice_name}\nsystemd_manager=system\n")
            result = self.parse()
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(result.stdout, f":{slice_name}:system\n")
        for slice_name in ("-.slice", "jobs.service", "../jobs.slice", "foo--bar.slice",
                           "jobs.slice --scope", ".slice", "x" * 201 + ".slice", "$(id).slice"):
            with self.subTest(slice=slice_name):
                self.write_policy(f"version=1\nsystemd_slice={slice_name}\n")
                self.assertEqual(self.parse().returncode, 125)
        self.write_policy("version=1\nsystemd_slice=jobs.slice\nsystemd_manager=auto\n")
        self.assertEqual(self.parse().returncode, 125)

    def test_invalid_config_never_launches(self) -> None:
        for content in (
            "nice=10\n", "version=2\nnice=10\n", "version=1\n", "version=1\nnice=10\nnice=19\n",
            "version=1\nnice=10\nrequired=false\n", "version=1\nnice=10\nsystemd_manager=user\n",
            "version=1\nnice=10\nsystemd_slice=jobs.slice\nexec=echo unsafe\n",
            "version=1\n nice = 10\n", "# comment only\n", "version=1\nnice=10\nversion=1\n",
        ):
            with self.subTest(content=content):
                self.write_policy(content)
                result = self.launch()
                self.assertEqual(result.returncode, 125, result.stderr)
                self.assertFalse(self.payload.exists())
                self.assertFalse(self.record.exists())

    def test_binary_and_oversized_policy_refused(self) -> None:
        for content in (b"version=1\nnice=1\x000\n", b"version=1\nnice=10\r\n",
                        b"version=1\n#\xff\nnice=10\n", b"#" * 8193):
            with self.subTest(content=repr(content[:40])):
                self.write_policy(content)
                self.assertEqual(self.parse().returncode, 125)

    def test_comments_and_final_line_without_newline(self) -> None:
        self.write_policy("# receiver configuration\n\nversion=1\nnice=10")
        self.assertEqual(self.parse().returncode, 0)

    def test_writable_file_refused(self) -> None:
        self.write_policy()
        for mode in (0o620, 0o602, 0o666):
            self.policy.chmod(mode)
            self.assertEqual(self.parse().returncode, 125)

    def test_symlink_and_hardlink_refused(self) -> None:
        self.write_policy()
        original = self.root / "original"
        self.policy.rename(original)
        self.policy.symlink_to(original)
        self.assertEqual(self.parse().returncode, 125)
        self.policy.unlink()
        os.link(original, self.policy)
        self.assertEqual(self.parse().returncode, 125)

    def test_missing_or_directory_policy_refused_when_selected(self) -> None:
        self.assertEqual(self.parse().returncode, 125)
        self.policy.mkdir()
        self.assertEqual(self.parse().returncode, 125)

    def test_no_policy_preserves_legacy_launch(self) -> None:
        env = {**self.env, "RCH_TEST_POLICY_FILE": ""}
        result = self.launch(env=env)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(int(result.stdout), os.getpriority(os.PRIO_PROCESS, 0))
        self.assertTrue(self.payload.exists())
        self.assertTrue(self.record.read_text().startswith("RCH_REMOTE_PROCESS_V1:42:"))
        self.assertNotIn("RCH_WORKER_EXECUTION_POLICY", result.stderr)

    def test_real_priority_applied_before_record_and_payload(self) -> None:
        nice = max(10, os.getpriority(os.PRIO_PROCESS, 0))
        self.write_policy(f"version=1\nnice={nice}\n")
        result = self.launch()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(int(result.stdout), nice)
        self.assertTrue(self.record.exists())
        self.assertTrue(self.payload.exists())
        self.assertIn(f"RCH_WORKER_EXECUTION_POLICY:nice={nice}", result.stderr)

    def test_posixly_correct_cannot_turn_priority_into_increment(self) -> None:
        if os.getpriority(os.PRIO_PROCESS, 0) > 4:
            self.skipTest("fixture needs initial niceness at most 4")
        self.write_policy()
        result = self.launch(
            '(unset POSIXLY_CORRECT; renice -n 4 -p "$$") >/dev/null || exit 120\n',
            env={**self.env, "POSIXLY_CORRECT": "1"},
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(int(result.stdout), 10)

    def test_renice_failure_does_not_launch(self) -> None:
        self.write_policy()
        self.fake("renice", "exit 1")
        result = self.launch()
        self.assertEqual(result.returncode, 125)
        self.assertIn("priority_change", result.stderr)
        self.assertFalse(self.payload.exists())
        self.assertFalse(self.record.exists())

    def test_successful_renice_without_effect_does_not_launch(self) -> None:
        nice = 19 if os.getpriority(os.PRIO_PROCESS, 0) != 19 else 18
        self.write_policy(f"version=1\nnice={nice}\n")
        self.fake("renice", "exit 0")
        result = self.launch()
        self.assertEqual(result.returncode, 125)
        self.assertIn("priority_not_enforced", result.stderr)
        self.assertFalse(self.payload.exists())
        self.assertFalse(self.record.exists())

    def test_priority_observation_failure_does_not_launch(self) -> None:
        self.write_policy(f"version=1\nnice={max(10, os.getpriority(os.PRIO_PROCESS, 0))}\n")
        self.fake("ps", "exit 1")
        result = self.launch()
        self.assertEqual(result.returncode, 125)
        self.assertIn("priority_observation", result.stderr)
        self.assertFalse(self.payload.exists())

    def test_missing_systemd_tool_does_not_launch(self) -> None:
        self.write_policy("version=1\nsystemd_slice=jobs.slice\n")
        directory = self.root / "minimal-bin"
        directory.mkdir()
        for name in ("id", "stat", "tr", "cmp", "cat", "uname", "timeout", "systemctl"):
            path = shutil.which(name)
            if path is not None:
                (directory / name).symlink_to(path)
        result = self.launch(env={**self.env, "PATH": str(directory)})
        self.assertEqual(result.returncode, 125)
        self.assertIn("systemd_tools", result.stderr)
        self.assertFalse(self.payload.exists())

    def test_missing_user_manager_or_inactive_slice_does_not_launch(self) -> None:
        self.write_policy("version=1\nsystemd_slice=jobs.slice\n")
        for body in ("exit 1", "echo inactive", "echo failed"):
            with self.subTest(body=body):
                self.fake("systemctl", body)
                result = self.launch()
                self.assertEqual(result.returncode, 125)
                self.assertIn("slice_not_active", result.stderr)
                self.assertFalse(self.payload.exists())
                self.assertFalse(self.record.exists())

    def test_control_capture_rejects_binary_and_oversized_success(self) -> None:
        self.env["TMPDIR"] = str(self.root)
        for body in (
            r"""printf 'active\000junk\n'""",
            r"""i=0; while [ "$i" -lt 7000 ]; do printf 0123456789; i=$((i + 1)); done""",
        ):
            with self.subTest(body=body):
                self.fake("systemctl", body)
                result = self.run_shell(r"""rch_control_capture 1s systemctl probe""")
                self.assertEqual(result.returncode, 125, result.stderr)
                self.assertEqual(result.stdout, "")
                self.assertEqual(list(self.root.glob("rch-control-output.*")), [])

    def test_control_capture_preserves_failure_status_and_cleans_timeout(self) -> None:
        self.env["TMPDIR"] = str(self.root)
        self.fake("systemctl", "printf 'inactive\\n' >&2; exit 7")
        failed = self.run_shell(r"""rch_control_capture 1s systemctl probe""")
        self.assertEqual(failed.returncode, 7)
        self.assertEqual(failed.stdout, "")
        self.assertEqual(failed.stderr, "inactive\n")
        self.assertEqual(list(self.root.glob("rch-control-output.*")), [])

        self.fake("systemctl", "printf prefix; sleep 5")
        started = time.monotonic()
        timed = self.run_shell(r"""rch_control_capture 1s systemctl probe""", timeout=4)
        self.assertLess(time.monotonic() - started, 3)
        self.assertNotEqual(timed.returncode, 0)
        self.assertEqual(timed.stdout, "")
        self.assertEqual(list(self.root.glob("rch-control-output.*")), [])

    def mock_active_slice(self) -> None:
        self.fake("systemctl", r'''
case " $* " in
    *--property=ActiveState*) echo active;;
    *--property=ControlGroup*) echo /user.slice/jobs.slice;;
    *) exit 1;;
esac
''')

    def test_scope_permission_failure_does_not_launch(self) -> None:
        self.write_policy("version=1\nsystemd_slice=jobs.slice\n")
        self.mock_active_slice()
        self.fake("busctl", "exit 1")
        result = self.launch()
        self.assertEqual(result.returncode, 125)
        self.assertIn("scope_creation", result.stderr)
        self.assertFalse(self.payload.exists())

    def test_queued_scope_without_actual_cgroup_move_does_not_launch(self) -> None:
        self.write_policy("version=1\nsystemd_slice=jobs.slice\n")
        self.mock_active_slice()
        self.fake("busctl", "exit 0")
        self.fake("sleep", "exit 0")  # exercise every bounded observation without waiting 5s
        result = self.launch()
        self.assertEqual(result.returncode, 125)
        self.assertIn("scope_not_enforced", result.stderr)
        self.assertFalse(self.payload.exists())
        self.assertFalse(self.record.exists())

    def test_real_term_escalation_reaps_priority_bound_descendant(self) -> None:
        nice = max(10, os.getpriority(os.PRIO_PROCESS, 0))
        self.write_policy(f"version=1\nnice={nice}\n")
        proc, record, ready = self.start_live()
        child_pid = int(ready.read_text())
        self.assertEqual(os.getpriority(os.PRIO_PROCESS, proc.pid), nice)
        self.assertEqual(os.getpriority(os.PRIO_PROCESS, child_pid), nice)
        result = self.cancel(record)
        self.assertEqual(result.returncode, 0, result.stderr)
        proc.wait(timeout=3)
        # The production verifier excludes zombies, not just PID existence.
        verify = self.run_shell(r'''rch_read_record "$1" 42 && rch_group_state''', record)
        self.assertEqual(verify.returncode, 0, verify.stderr)

    def test_fresh_channel_kill_mode_after_original_pipes_close(self) -> None:
        self.write_policy(f"version=1\nnice={max(10, os.getpriority(os.PRIO_PROCESS, 0))}\n")
        proc, record, _ = self.start_live()
        assert proc.stdout is not None and proc.stderr is not None
        proc.stdout.close()
        proc.stderr.close()
        self.assertIsNone(proc.poll())
        result = self.cancel(record, mode="kill")
        self.assertEqual(result.returncode, 0, result.stderr)
        proc.wait(timeout=3)
        # Repeat recovery is idempotent after the identity's group is gone.
        self.assertEqual(self.cancel(record, mode="kill").returncode, 0)

    def test_recovery_rejects_mismatched_identity_without_signalling(self) -> None:
        self.write_policy(f"version=1\nnice={max(10, os.getpriority(os.PRIO_PROCESS, 0))}\n")
        proc, record, _ = self.start_live()
        self.assertEqual(self.cancel(record, build=43).returncode, 43)
        self.assertIsNone(proc.poll())
        self.assertEqual(self.cancel(record).returncode, 0)

    def test_concurrent_builds_keep_independent_process_authority(self) -> None:
        self.write_policy(f"version=1\nnice={max(10, os.getpriority(os.PRIO_PROCESS, 0))}\n")
        first, record1, _ = self.start_live(42)
        second, record2, _ = self.start_live(43)
        self.assertNotEqual(first.pid, second.pid)
        evidence2 = record2.read_bytes()
        self.assertEqual(self.cancel(record1, 42).returncode, 0)
        self.assertIsNone(second.poll())
        self.assertEqual(record2.read_bytes(), evidence2)
        self.assertEqual(self.cancel(record2, 43).returncode, 0)

    @unittest.skipUnless(os.environ.get("RCH_TEST_SYSTEMD_SLICE"), "opt-in real systemd user slice")
    def test_real_systemd_placement(self) -> None:
        self.write_policy(
            "version=1\nsystemd_manager=user\n"
            f"systemd_slice={os.environ['RCH_TEST_SYSTEMD_SLICE']}\n"
        )
        result = self.launch()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("scope=rch-", result.stderr)
        self.assertTrue(self.payload.exists())


if __name__ == "__main__":
    unittest.main(verbosity=2)
