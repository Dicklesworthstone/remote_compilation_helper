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
CORE = Path(os.environ.get("RCH_CONTROL_TEST_PROTOCOL",
                           str(ROOT / "rch-common/src/remote_process.sh"))).read_text()
SHELL = os.environ.get("RCH_TEST_SHELL", "/bin/sh")
# Deliberately exclude timeout, gtimeout and gnutimeout. Symlink real utilities;
# changing uname or returning fake identity observations would hide this bug.
TOOLS = (
    "awk", "cat", "chmod", "cmp", "cut", "date", "id", "kill", "mkdir",
    "mkfifo", "mktemp", "mv", "ps", "python3", "rch-wkr", "rm", "rmdir",
    "setsid", "sh", "sleep", "stat", "tr", "uname", "wc",
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
        # The native monitor receives an already-scaled cap: 8s * 10 = 80s.
        # It must still refuse zero, unsupported signals and out-of-range data.
        for options in (
            "--signal=TERM 1s", "--signal=KILL 0s", "--signal=KILL NaN",
            "--signal=KILL 81s", "--signal=KILL 999999999999999999999999s",
        ):
            with self.subTest(options=options):
                result = self.run_protocol("rch_group_timeout " + options + " " + command)
                self.assertEqual(result.returncode, 125, result.stderr)
                self.assertFalse(marker.exists())

    def test_five_second_control_budget_is_supported(self):
        result = self.run_protocol("rch_control_capture 5s /bin/sh -c 'printf valid'")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, "valid")

    def test_adaptive_deadlines_keep_the_native_monitor_available(self):
        for seconds in range(2, 9):
            with self.subTest(seconds=seconds):
                result = self.run_protocol(
                    f"rch_group_timeout --signal=KILL {seconds}s /bin/sh -c 'printf valid'"
                )
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(result.stdout, "valid")

    def test_scaled_native_monitor_accepts_maximum_effective_deadline(self):
        self.env["RCH_TIMING_SCALE"] = "10"
        for seconds in (60, 80):
            with self.subTest(seconds=seconds):
                result = self.run_protocol(
                    f"rch_group_timeout --signal=KILL {seconds}s /bin/sh -c 'printf valid'"
                )
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(result.stdout, "valid")
        result = self.run_protocol("rch_control_capture 8s /bin/sh -c 'printf valid'")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, "valid")
        self.assert_no_capture_files()

    def test_scale_does_not_widen_unscaled_capture_argument_domain(self):
        self.env["RCH_TIMING_SCALE"] = "10"
        marker = self.root / "unsafe-scaled-launch"
        command = "/bin/sh -c " + shlex.quote("echo unsafe > " + shlex.quote(str(marker)))
        for cap in ("9s", "80s", "999999999999999999999999s"):
            with self.subTest(cap=cap):
                result = self.run_protocol("rch_control_capture " + cap + " " + command)
                self.assertEqual(result.returncode, 125, result.stderr)
                self.assertFalse(marker.exists())
                self.assertEqual(result.stdout, "")
                self.assert_no_capture_files()

    def test_remaining_recovery_budget_bounds_the_fallback_and_its_pipe_holder(self):
        marker = self.root / "descendant-survived-shared-budget"
        # The eight-second per-call allowance would let this descendant write.
        # A two-second remaining budget must stop the real monitor group first.
        payload = "(sleep 3; printf survived > " + shlex.quote(str(marker)) + ") & exit 0"
        started = time.monotonic()
        result = self.run_protocol('''
rch_observation_clock() { rch_observation_now=100; }
rch_observation_last_clock=100; rch_observation_deadline=300
rch_control_capture 8s /bin/sh -c ''' + shlex.quote(payload))
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(result.stdout, "")
        self.assertLess(time.monotonic() - started, 4.0)
        time.sleep(1.3)
        self.assertFalse(marker.exists(), "shared deadline did not stop the pipe holder")
        self.assert_no_capture_files()

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


class DisklessControlCapture(ControlTimeout):
    """Run the same byte/deadline contract without a writable scratch path.

    A regular file used as TMPDIR makes storage genuinely unavailable to the
    old capture helper, without filling a filesystem or changing permissions.
    This is a storage-failure regression, not a live ENOSPC/fleet acceptance.
    """

    def setUp(self):
        super().setUp()
        self.unavailable = self.root / "unavailable-scratch"
        self.unavailable.write_bytes(b"scratch must remain unchanged\n")
        self.env["TMPDIR"] = str(self.unavailable)

    def run_protocol(self, body, timeout=8):
        result = super().run_protocol("rch_control_diskless=1\n" + body, timeout)
        self.assertEqual(self.unavailable.read_bytes(), b"scratch must remain unchanged\n")
        self.assert_no_capture_files()
        return result

    def run_complete_protocol(self, body, **environment):
        from remote_process_platform import PROTOCOL

        result = subprocess.run(
            [SHELL, "-c", PROTOCOL + "\n" + body, "rch-observer"],
            env={key: value for key, value in {**self.env, **environment}.items()
                 if value is not None}, text=True, capture_output=True,
            start_new_session=True, timeout=8,
        )
        self.assertEqual(self.unavailable.read_bytes(), b"scratch must remain unchanged\n")
        self.assert_no_capture_files()
        return result

    def test_preserves_empty_output_tabs_and_every_trailing_newline(self):
        for output in ("", "\n", "\nfirst\tlast\n\n", "trailing.", ".\n\n"):
            with self.subTest(output=output):
                payload = "import sys; sys.stdout.write(" + repr(output) + ")"
                result = self.run_protocol(
                    "rch_control_capture 2s python3 -I -S -B -c " + shlex.quote(payload)
                )
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(result.stdout, output)

    def test_normal_and_census_limits_keep_the_original_boundaries(self):
        for census, limit in ((False, 65536), (True, 1048576)):
            for size in (limit, limit + 1):
                with self.subTest(census=census, size=size):
                    payload = f"import sys; sys.stdout.write('x' * {size})"
                    command = "python3 -I -S -B -c " + shlex.quote(payload)
                    if census:
                        # The actual production census has this argv shape.
                        # Only its output producer is a boundary fixture here.
                        command = "/bin/sh -c " + shlex.quote("exec " + command) + " rch-group-census"
                    result = self.run_protocol("rch_control_capture 2s " + command)
                    if size == limit:
                        self.assertEqual(result.returncode, 0, result.stderr)
                        self.assertTrue(result.stdout == "x" * size, "bounded bytes changed")
                    else:
                        self.assertEqual(result.returncode, 125, result.stderr)
                        self.assertEqual(result.stdout, "")

    def test_raw_control_and_non_ascii_bytes_are_never_published(self):
        for invalid in (b"\x00", b"\r", b"\x1b", b"\x7f", b"\xff"):
            with self.subTest(invalid=invalid):
                payload = "import sys; sys.stdout.buffer.write(" + repr(b"valid" + invalid + b"suffix") + ")"
                result = self.run_protocol(
                    "rch_control_capture 2s python3 -I -S -B -c " + shlex.quote(payload)
                )
                self.assertEqual(result.returncode, 125, result.stderr)
                self.assertEqual(result.stdout, "")

    def test_failed_command_preserves_exact_diagnostics_and_signal_status(self):
        for payload, status, diagnostic in (
            ("printf 'first\\n\\n'; printf 'last\\tline\\n\\n' >&2; exit 7", 7,
             "first\n\nlast\tline\n\n"),
            ("printf 'interrupted\\n'; kill -TERM $$", 128 + signal.SIGTERM,
             "interrupted\n"),
        ):
            with self.subTest(status=status):
                result = self.run_protocol("rch_control_capture 2s /bin/sh -c " + shlex.quote(payload))
                self.assertEqual(result.returncode, status, result.stderr)
                self.assertEqual(result.stdout, "")
                self.assertEqual(result.stderr, diagnostic)

    def test_invalid_output_still_waits_for_inherited_pipe_holders(self):
        for use_native in (False, True):
            if use_native:
                native = next((name for name in ("gnutimeout", "gtimeout", "timeout")
                               if shutil.which(name)), None)
                if native is None:
                    continue
                (self.bin / native).symlink_to(shutil.which(native))
            for kind, first in (("nul", "printf '\\000'"),
                                ("oversize", "python3 -I -S -B -c 'print(\"x\" * 65537)'")):
                with self.subTest(native=use_native, kind=kind):
                    marker = self.root / f"invalid-pipe-holder-survived-{use_native}-{kind}"
                    ready = self.root / f"invalid-pipe-holder-started-{use_native}-{kind}"
                    payload = ("printf ready > " + shlex.quote(str(ready)) + "; " + first
                               + "; (sleep 2; printf survived > " + shlex.quote(str(marker)) + ") & exit 0")
                    started = time.monotonic()
                    result = self.run_protocol("rch_control_capture 1s /bin/sh -c " + shlex.quote(payload))
                    self.assertNotEqual(result.returncode, 0)
                    self.assertEqual(result.stdout, "")
                    self.assertLess(time.monotonic() - started, 4.0)
                    self.assertTrue(ready.exists(), "fixture command never started")
                    time.sleep(2.3)
                    self.assertFalse(marker.exists(), "rejected output detached a live pipe holder")

    def test_eof_does_not_replace_child_exit(self):
        marker = self.root / "closed-stream-child-survived"
        ready = self.root / "closed-stream-child-started"
        payload = ("printf ready > " + shlex.quote(str(ready))
                   + "; exec 1>&- 2>&-; sleep 2; printf survived > " + shlex.quote(str(marker)))
        result = self.run_protocol("rch_control_capture 1s /bin/sh -c " + shlex.quote(payload))
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(result.stdout, "")
        self.assertTrue(ready.exists(), "fixture command never started")
        time.sleep(2.3)
        self.assertFalse(marker.exists(), "capture treated EOF as process completion")

    def test_interrupted_collector_cannot_abandon_its_command(self):
        # Signal the new inner collector, not the outer timeout monitor tested
        # above. Exiting that collector early would disarm the group timeout.
        for name in ("HUP", "INT", "TERM"):
            with self.subTest(signal=name):
                marker = self.root / ("interrupted-collector-survived-" + name)
                ready = self.root / ("interrupted-collector-started-" + name)
                payload = ("printf ready > " + shlex.quote(str(ready))
                           + f'; kill -{name} "$PPID"; sleep 2; printf survived > '
                           + shlex.quote(str(marker)))
                started = time.monotonic()
                result = self.run_protocol("rch_control_capture 1s /bin/sh -c " + shlex.quote(payload))
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(result.stdout, "")
                self.assertLess(time.monotonic() - started, 4.0)
                self.assertTrue(ready.exists(), "fixture command never started")
                time.sleep(2.3)
                self.assertFalse(marker.exists(), "collector interruption detached its command")

    def test_interrupted_collector_retains_signal_status_after_child_exit(self):
        for name, signum in (("HUP", signal.SIGHUP), ("INT", signal.SIGINT),
                             ("TERM", signal.SIGTERM)):
            with self.subTest(signal=name):
                completed = self.root / ("interrupted-command-completed-" + name)
                payload = (f'kill -{name} "$PPID"; printf not_authority; printf complete > '
                           + shlex.quote(str(completed)) + "; exit 0")
                result = self.run_protocol("rch_control_capture 2s /bin/sh -c " + shlex.quote(payload))
                self.assertEqual(result.returncode, 128 + signum, result.stderr)
                self.assertEqual(result.stdout, "")
                self.assertTrue(completed.exists(), "fixture command did not complete")

    def test_complete_protocol_bootstraps_with_unavailable_tmpdir(self):
        # Exercise the exact Rust concat! composition, including its heredoc,
        # rather than only evaluating the standalone function definitions.
        result = self.run_complete_protocol(
            "rch_control_diskless=1\n"
            "rch_control_capture 2s /bin/printf 'complete protocol\\n\\n'"
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, "complete protocol\n\n")

    def test_cancellation_exports_mode_to_nested_observer_without_leaking(self):
        # This is an explicit unavailable-census double, not native process
        # proof. Its nested shell really evaluates the production functions and
        # captures bytes without scratch before reporting unavailable evidence.
        result = self.run_complete_protocol(r'''
[ "${rch_control_diskless+x}" != x ] || exit 90
rch_control_diskless=0
rch_group_state() {
    observed=$(/bin/sh -c '
        command eval "$1" || exit 125
        rch_control_capture 2s /bin/printf nested-capture
    ' rch-nested "$rch_launch_source") || return 99
    [ "$observed" = nested-capture ] || return 99
    printf 'nested capture completed\n' >&2
    return 2
}
rch_identified=0
rch_scope_bound=0
rch_remote_cancel_loaded term
status=$?
[ "$rch_control_diskless" = 0 ] || exit 91
/bin/sh -c '[ "${rch_control_diskless+x}" != x ]' || exit 92
exit "$status"
''', rch_control_diskless=None)
        self.assertEqual(result.returncode, 43, result.stderr)
        self.assertEqual(result.stdout, "")
        self.assertEqual(result.stderr, "nested capture completed\n")

    def test_recovery_exports_mode_but_unknown_namespace_still_refuses(self):
        # Native namespace observation is deliberately unavailable. A completed
        # diskless helper is never itself execution-absence authority.
        result = self.run_complete_protocol(r'''
[ "${rch_control_diskless+x}" != x ] || exit 90
rch_control_diskless=0
rch_check_procfs_namespace() {
    observed=$(/bin/sh -c '
        command eval "$1" || exit 125
        rch_control_capture 2s /bin/printf nested-capture
    ' rch-nested "$rch_launch_source") || return 1
    [ "$observed" = nested-capture ] || return 1
    printf 'nested capture completed\n' >&2
    return 1
}
rch_identified=1
rch_recovery_boot_state
status=$?
[ "$rch_control_diskless" = 0 ] || exit 91
/bin/sh -c '[ "${rch_control_diskless+x}" != x ]' || exit 92
exit "$status"
''', rch_control_diskless=None)
        self.assertEqual(result.returncode, 2, result.stderr)
        self.assertEqual(result.stdout, "")
        self.assertEqual(result.stderr, "nested capture completed\n")


@unittest.skipUnless(sys.platform == "linux", "Linux birth-bound cancellation protocol")
class DisklessCancellation(WithoutTimeout):
    """Real kernel identity and cancellation; no census or signal doubles."""

    def setUp(self):
        super().setUp()
        self.unavailable = self.root / "unavailable-scratch"
        self.unavailable.write_bytes(b"scratch must remain unchanged\n")
        self.env["TMPDIR"] = str(self.unavailable)
        self.children = []
        self.addCleanup(self.stop_owned)

    def stop_owned(self):
        for child in self.children:
            if child.poll() is None:
                # The unreaped direct child pins the session/group identity.
                os.killpg(child.pid, signal.SIGKILL)
            child.wait(timeout=5)

    def group(self):
        child = subprocess.Popen(["/bin/sleep", "60"], start_new_session=True,
                                 stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                                 stderr=subprocess.DEVNULL)
        self.children.append(child)
        self.assertEqual(os.getpgid(child.pid), child.pid)
        return child

    def record(self, child):
        boot = Path("/proc/sys/kernel/random/boot_id").read_text().strip()
        birth = Path(f"/proc/{child.pid}/stat").read_bytes().rsplit(b") ", 1)[1].split()[19].decode()
        path = self.root / "receipt"
        path.write_text(f"RCH_REMOTE_PROCESS_V1:115:{boot}:{child.pid}:{birth}\n")
        path.chmod(0o600)
        return path

    def cancel(self, path, build=115):
        from remote_process_platform import PROTOCOL

        # Do not set rch_control_diskless here: real cancellation must select
        # its own storage-independent observation route.
        result = subprocess.run(
            [SHELL, "-c", PROTOCOL + '\nrch_remote_cancel "$1" "$2" kill\n',
             "rch-cancel", str(path), str(build)],
            env=self.env, text=True, capture_output=True, start_new_session=True, timeout=35,
        )
        self.assertEqual(self.unavailable.read_bytes(), b"scratch must remain unchanged\n")
        self.assert_no_capture_files()
        return result

    def test_real_birth_bound_group_can_be_cancelled_without_scratch(self):
        child = self.group()
        path = self.record(child)
        receipt = path.read_bytes()
        result = self.cancel(path)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(child.wait(timeout=5), -signal.SIGKILL)
        self.assertEqual(path.read_bytes(), receipt)
        # Repeat with the original receipt after the exact group has exited.
        result = self.cancel(path)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(path.read_bytes(), receipt)

    def test_missing_record_cannot_confirm_or_signal_under_storage_failure(self):
        child = self.group()
        result = self.cancel(self.root / "not-published")
        self.assertEqual(result.returncode, 42, result.stderr)
        self.assertEqual(result.stdout, "")
        self.assertIsNone(child.poll())

    def test_wrong_build_cannot_signal_under_storage_failure(self):
        child = self.group()
        path = self.record(child)
        result = self.cancel(path, build=116)
        self.assertEqual(result.returncode, 43, result.stderr)
        self.assertEqual(result.stdout, "")
        self.assertIsNone(child.poll())


class NativeLifecycleWithoutTimeout(WithoutTimeout):
    def test_all_existing_lifecycle_operations_without_coreutils(self):
        # On macOS the workflow supplies the candidate native rch-wkr. This
        # invokes the original launch, watchdog, cancellation, recovery and
        # portable boundary tests unchanged, with GNU timeout absent from PATH.
        # LinuxBusyCensus and the opt-in dedicated-host stress suite run
        # independently; their platform/opt-in skips are not lifecycle failures.
        result = subprocess.run(
            [sys.executable, str(ROOT / "rch-common/tests/remote_process_platform.py"),
             "PlatformIdentity", "DarwinCensusBoundary", "-v"],
            env=self.env, text=True, capture_output=True, timeout=120,
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertRegex(result.stderr, r"Ran [1-9][0-9]* tests")
        self.assertNotIn("skipped", result.stderr)


if __name__ == "__main__":
    unittest.main()
