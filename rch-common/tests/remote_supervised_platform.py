#!/usr/bin/env python3
"""Run the exact embedded rch-build supervisor, not the legacy watchdog tail.

SupervisedPlatform uses native Linux/macOS identities without platform mocks.
DarwinPrimitives selects Darwin's portable syscall adapters explicitly, also
on Linux; those tests are not native libproc or macOS qualification. Darwin
needs the candidate rch-wkr and Python 3.7+ (the harness needs Python 3.9+).
RCH_TEST_NO_TIMEOUT=1 removes GNU timeout aliases from PATH on either OS.
"""
import json
import os
from pathlib import Path
import re
import shlex
import shutil
import signal
import subprocess
import sys
import tempfile
import time
import unittest
import venv

SOURCE = Path(__file__).resolve().parents[1] / "src"
SHELL = os.environ.get("RCH_TEST_SHELL", "/bin/sh")
CORE = (SOURCE / "remote_process.sh").read_text()


def assemble_protocol():
    rust = (SOURCE / "remote_scoped_launch.rs").read_text()
    expression = rust.split("= concat!(\n", 1)[1].split("\n);", 1)[0]
    parts = []
    for line in expression.splitlines():
        item = line.strip().removesuffix(",")
        include = re.fullmatch(r'include_str!\(("[^"\n]+")\)', item)
        parts.append((SOURCE / json.loads(include[1])).read_text()
                     if include else json.loads(item))
    return "".join(parts)


PROTOCOL = assemble_protocol()


class SupervisedPlatform(unittest.TestCase):
    def setUp(self):
        # Retain failure receipts for diagnosis. Only our direct supervisor
        # children are signalled during cleanup; their own watchdog owns work.
        self.root = Path(tempfile.mkdtemp(prefix="rch-supervised-platform-"))
        self.receipt = self.root / "receipt"
        self.ready = self.root / "ready"
        self.release = self.root / "release"
        self.children = []
        self.env = dict(os.environ, HOME=str(self.root), TMPDIR=str(self.root))
        if os.environ.get("RCH_TEST_NO_TIMEOUT") == "1":
            binaries = self.root / "bin"
            binaries.mkdir()
            for tool in ("awk", "cat", "cmp", "id", "mkdir", "mkfifo", "mktemp",
                         "mv", "ps", "python3", "rch-wkr", "rm", "rmdir", "setsid",
                         "sh", "sleep", "stat", "tr", "uname", "wc"):
                resolved = shutil.which(tool)
                if resolved:
                    (binaries / tool).symlink_to(resolved)
            self.env["PATH"] = str(binaries)
            for tool in ("timeout", "gtimeout", "gnutimeout"):
                self.assertIsNone(shutil.which(tool, path=self.env["PATH"]))
        self.addCleanup(self.cleanup_owned)

    def cleanup_owned(self):
        for child in self.children:
            if child.poll() is None:
                child.kill()
            child.wait(timeout=15)
        if self.receipt.exists():
            # An exact fresh-channel recovery, never a blind killpg(record).
            self.cancel("kill")

    def start(self, payload, seconds=0, prefix="", stdin=subprocess.DEVNULL,
              protocol=PROTOCOL, diagnostic=None):
        out = open(self.root / f"out-{len(self.children)}", "w+b")
        err = open(self.root / f"err-{len(self.children)}", "w+b")
        self.addCleanup(out.close)
        self.addCleanup(err.close)
        child = subprocess.Popen(
            [SHELL, "-c", "exec 3>&2\n" + prefix + "\n" + protocol + "\nexit 79\n",
             "rch-build", str(self.receipt), str(seconds), "RCH_TEST_DEADLINE",
             "115", SHELL, "-c", payload],
            env=self.env, stdin=stdin, stdout=out, stderr=err if diagnostic is None else diagnostic,
            start_new_session=True,
        )
        self.children.append(child)
        return child, out, err

    def contents(self, file):
        file.flush()
        file.seek(0)
        return file.read()

    def finish(self, run, status=0):
        child, out, err = run
        actual = child.wait(timeout=20)
        self.assertEqual(actual, status, self.contents(err).decode(errors="replace"))
        return self.contents(out), self.contents(err)

    def wait_ready(self, child):
        until = time.monotonic() + 15
        while not self.ready.exists():
            self.assertIsNone(child.poll(), f"setup failed; fixtures: {self.root}")
            self.assertLess(time.monotonic(), until, f"setup stalled: {self.root}")
            time.sleep(.02)
        self.assertTrue(self.receipt.exists())
        self.assertTrue(Path(str(self.receipt) + ".supervisor.v1/go").exists())

    def blocking_payload(self):
        return (f"printf ready > {shlex.quote(str(self.ready))}; "
                f"while [ ! -f {shlex.quote(str(self.release))} ]; do sleep .1; done")

    def observe(self, body):
        return subprocess.run([SHELL, "-c", PROTOCOL + "\n" + body], env=self.env,
                              capture_output=True, timeout=30)

    def cancel(self, mode="term"):
        return self.observe(f"rch_remote_cancel {shlex.quote(str(self.receipt))} 115 {mode}")

    def assert_empty(self):
        result = self.observe(
            f"rch_read_record {shlex.quote(str(self.receipt))} 115 || exit $?; rch_group_state")
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_status_and_binary_stdin_survive_supervision(self):
        data = b"original\x00input\nlast\xff"
        with tempfile.TemporaryFile() as source:
            source.write(b"consumed:" + data)
            source.seek(len(b"consumed:"))
            out, err = self.finish(self.start("cat; printf diagnostic >&2; exit 7", stdin=source), 7)
        self.assertEqual(out, data)
        self.assertEqual(err, b"diagnostic")
        self.assert_empty()

    def test_completion_stops_background_members_before_success(self):
        late = self.root / "late-write"
        payload = (f"(trap '' TERM; sleep 2; printf leaked > {shlex.quote(str(late))}) "
                   "</dev/null >/dev/null 2>&1 & exit 0")
        self.finish(self.start(payload))
        self.assert_empty()
        time.sleep(2.1)
        self.assertFalse(late.exists(), "compiler descendant wrote after terminal success")

    def test_parent_sigkill_is_cleaned_by_in_group_watchdog(self):
        run = self.start(self.blocking_payload())
        self.wait_ready(run[0])
        run[0].kill()
        run[0].wait(timeout=5)
        until = time.monotonic() + 15
        while True:
            result = self.observe(
                f"rch_read_record {shlex.quote(str(self.receipt))} 115 || exit $?; rch_group_state")
            if result.returncode == 0:
                break
            self.assertLess(time.monotonic(), until, result.stderr)
            time.sleep(.05)

    def test_leader_crash_without_deadline_is_cleaned_by_surviving_watchdog(self):
        # A test-only last-resort guard prevents the broken incumbent from
        # leaving a permanent orphan. It signals only its own live group.
        # The real watchdog must prove cleanup long BEFORE this guard fires.
        payload = "(sleep 12; kill -KILL 0) & " + self.blocking_payload()
        run = self.start(payload, seconds=0)
        self.wait_ready(run[0])
        result = self.observe(
            f"rch_read_record {shlex.quote(str(self.receipt))} 115 || exit $?; "
            'rch_remote_leader_matches || exit 43; kill -KILL "$rch_pgid"')
        self.assertEqual(result.returncode, 0, result.stderr)
        started = time.monotonic()
        self.assertNotEqual(run[0].wait(timeout=8), 0)
        self.assert_empty()
        self.assertLess(time.monotonic() - started, 8)

    def test_deadline_stops_group_and_emits_marker(self):
        run = self.start(self.blocking_payload(), seconds=2)
        self.wait_ready(run[0])
        _, err = self.finish(run, 137)
        self.assertIn(b"RCH_TEST_DEADLINE\n", err)
        self.assert_empty()
        self.assertEqual(self.cancel("kill").returncode, 0)

    def test_supervisor_term_cleans_group(self):
        run = self.start(self.blocking_payload())
        self.wait_ready(run[0])
        run[0].send_signal(signal.SIGTERM)
        self.finish(run, 143)
        self.assert_empty()

    def test_fresh_channel_cancellation_cannot_be_success(self):
        run = self.start(self.blocking_payload())
        self.wait_ready(run[0])
        result = self.cancel()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertNotEqual(run[0].wait(timeout=15), 0)
        self.assert_empty()

    def cancel_with_probe(self, probe):
        # Fault injection is confined to the cancelling channel. Launch,
        # leader identity, actual signals and the final census remain native.
        # Put it in the literal shared source so a bounded collector sees the
        # same observation backend as its parent, not a special test path.
        core = CORE.replace("rch_read_process() {", "rch_real_read_process() {")
        core += "\n" + probe
        trace = self.root / "signals"
        core = core.replace("rch_signal_group() {", "rch_real_signal_group() {")
        core += ("\nrch_signal_group() { printf '%s\\n' \"$1\" >> "
                 + shlex.quote(str(trace)) + '; rch_real_signal_group "$@"; }\n')
        script = PROTOCOL.replace(CORE, core) + (
            f"\nrch_remote_cancel {shlex.quote(str(self.receipt))} 115 term")
        started = time.monotonic()
        result = subprocess.run([SHELL, "-c", script], env=self.env,
                                capture_output=True, timeout=25)
        elapsed = time.monotonic() - started
        return result, elapsed, trace.read_text() if trace.exists() else ""

    def test_stalled_member_probe_cannot_starve_cancellation(self):
        run = self.start(
            f"trap '' TERM; echo $$ > {shlex.quote(str(self.ready))}; "
            "while :; do sleep 1; done")
        self.wait_ready(run[0])
        member = int(self.ready.read_text())
        result, elapsed, signals = self.cancel_with_probe(f'''
rch_read_process() {{
    if [ "$1" = {member} ]; then sleep 15; fi
    rch_real_read_process "$1"
}}
''')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertLess(elapsed, 10, "member observation consumed the recovery budget")
        self.assertEqual(signals, "KILL\n", "partial collection must not authorize TERM")
        self.assert_empty()
        self.assertNotEqual(run[0].wait(timeout=10), 0)

    def test_large_group_has_one_collection_budget_not_one_per_member(self):
        run = self.start(
            "trap '' TERM; i=0; while [ \"$i\" -lt 32 ]; do sleep 60 & i=$((i+1)); done; "
            + self.blocking_payload())
        self.wait_ready(run[0])
        result, elapsed, signals = self.cancel_with_probe('''
rch_read_process() {
    if [ "$1" != "$rch_pgid" ]; then sleep .4; fi
    rch_real_read_process "$1"
}
''')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertLess(elapsed, 10, "per-member limits accumulated without a global limit")
        self.assertEqual(signals, "KILL\n")
        self.assert_empty()
        self.assertNotEqual(run[0].wait(timeout=10), 0)

    def test_complete_collection_retains_graceful_term(self):
        run = self.start(self.blocking_payload())
        self.wait_ready(run[0])
        result, _, signals = self.cancel_with_probe('''
rch_read_process() { rch_real_read_process "$1"; }
''')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue(signals.startswith("TERM\n"), signals)
        self.assert_empty()
        self.assertNotEqual(run[0].wait(timeout=10), 0)

    def test_witness_revalidation_has_a_shared_deadline(self):
        run = self.start(
            f"echo $$ > {shlex.quote(str(self.ready))}; while :; do sleep 1; done")
        self.wait_ready(run[0])
        member = int(self.ready.read_text())
        setup = f"rch_read_record {shlex.quote(str(self.receipt))} 115 || exit $?; "
        observed = self.observe(setup + f'rch_read_process {member} || exit 90; '
                                'printf "%s" "$rch_observed_start"')
        self.assertEqual(observed.returncode, 0, observed.stderr)
        birth = int(observed.stdout)
        core = CORE.replace("rch_read_process() {", "rch_real_read_process() {")
        core += f'''
rch_read_process() {{ sleep 15; rch_real_read_process "$1"; }}
'''
        script = PROTOCOL.replace(CORE, core) + "\n" + setup + f'''
rch_witness_identity="$rch_boot:$rch_pgid:$rch_start"
rch_witnesses={member}:{birth}
rch_remote_witness_matches
'''
        started = time.monotonic()
        result = subprocess.run([SHELL, "-c", script], env=self.env,
                                capture_output=True, timeout=25)
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertLess(time.monotonic() - started, 10)
        self.assertIsNone(run[0].poll(), "failed witness probe signalled the workload")
        self.assertEqual(self.cancel("kill").returncode, 0)

    def test_partial_and_malformed_collection_never_leaks_witnesses(self):
        run = self.start(self.blocking_payload())
        self.wait_ready(run[0])
        for output, code in (("123:456", 7), ("", 0), ("123", 0),
                             ("123:0", 0), ("1:456", 0), ("123:456:789", 0)):
            with self.subTest(output=output, status=code):
                result = self.observe(f'''
rch_read_record {shlex.quote(str(self.receipt))} 115 || exit 80
rch_group_state; [ "$?" = 1 ] || exit 81
rch_control_capture() {{ printf '%s\\n' {shlex.quote(output)}; return {code}; }}
rch_witnesses=stale; rch_witness_identity=stale
rch_capture_group_witnesses
[ "$?" = 46 ] && [ -z "$rch_witnesses$rch_witness_identity" ] || exit 82
''')
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertIsNone(run[0].poll())
        self.assertEqual(self.cancel("kill").returncode, 0)

    def test_collection_failure_does_not_bypass_live_birth_check(self):
        run = self.start(self.blocking_payload())
        self.wait_ready(run[0])
        # Model a changed identity between collection and the signal boundary.
        # Even the immediate-KILL fallback must refuse this still-live group.
        result = self.observe(f'''
rch_capture_group_witnesses() {{ rch_start=$((rch_start + 1)); return 46; }}
rch_remote_cancel {shlex.quote(str(self.receipt))} 115 term
''')
        self.assertEqual(result.returncode, 43, result.stderr)
        self.assertIsNone(run[0].poll())
        self.assertEqual(self.cancel("kill").returncode, 0)

    def test_bounded_witness_match_preserves_birth_and_exchange_fences(self):
        run = self.start(self.blocking_payload())
        self.wait_ready(run[0])
        result = self.observe(f'''
rch_read_record {shlex.quote(str(self.receipt))} 115 || exit 80
rch_group_state; [ "$?" = 1 ] || exit 81
rch_capture_group_witnesses || exit 82
rch_remote_witness_matches || exit 83
rch_witnesses="$rch_pgid:$((rch_start + 1))"
if rch_remote_witness_matches; then exit 84; fi
rch_control_capture() {{ printf 'RCH_WITNESS_MATCH_V1\\n'; return 7; }}
if rch_remote_witness_matches; then exit 85; fi
rch_control_capture() {{ printf 'RCH_WITNESS_MATCH_V1 contaminated\\n'; }}
if rch_remote_witness_matches; then exit 86; fi
rch_witness_identity=stale
rch_control_capture() {{ exit 87; }}
if rch_remote_witness_matches; then exit 88; fi
''')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIsNone(run[0].poll())
        self.assertEqual(self.cancel("kill").returncode, 0)

    def test_duplicate_admission_cannot_replace_live_receipt(self):
        first = self.start(self.blocking_payload())
        self.wait_ready(first[0])
        receipt = self.receipt.read_bytes()
        second = self.start("printf DUPLICATE")
        out, err = self.finish(second, 255)
        self.assertEqual(out, b"")
        self.assertIn(b"RCH_SCOPED_LAUNCH_ALREADY_OWNED", err)
        self.assertEqual(self.receipt.read_bytes(), receipt)
        self.assertIsNone(first[0].poll())
        self.release.touch()
        self.finish(first)
        self.assert_empty()

    def test_inherited_descriptor_and_closed_stdin(self):
        authority = self.root / "authority"
        authority.write_bytes(b"owned descriptor")
        prefix = f"exec 4<{shlex.quote(str(authority))}; exec 0<&-"
        code = ('import errno, os; '
                'print(os.read(4, 100).decode()); '
                'os.fstat(0)')
        out, err = self.finish(self.start("python3 -I -c " + shlex.quote(code), prefix=prefix), 1)
        self.assertEqual(out, b"owned descriptor\n")
        self.assertIn(b"Bad file descriptor", err)
        self.assert_empty()

    def test_all_borrowable_fds_occupied_refuses_before_payload(self):
        prefix = "; ".join(f"exec {fd}</dev/null" for fd in range(4, 10))
        out, err = self.finish(self.start("printf MUST_NOT_RUN", prefix=prefix), 125)
        self.assertEqual(out, b"")
        self.assertIn(b"IDENTITY_UNAVAILABLE", err)
        self.assertFalse(self.receipt.exists())

    def test_child_refusal_before_record_is_retryable_setup_failure(self):
        # Explicit setup failure, before any record or admission gate. Neither
        # the requested command nor an unconfirmed-execution verdict is valid.
        needle = "rch_scope_launch_child() {\n"
        self.assertEqual(PROTOCOL.count(needle), 1)
        refused = PROTOCOL.replace(needle, needle + "    exit 125\n")
        out, err = self.finish(self.start("printf MUST_NOT_RUN", protocol=refused), 125)
        self.assertEqual(out, b"")
        self.assertIn(b"IDENTITY_UNAVAILABLE", err)
        self.assertNotIn(b"COMPLETION_UNCONFIRMED", err)
        self.assertFalse(self.receipt.exists())
        self.assertFalse(Path(str(self.receipt) + ".supervisor.v1/go").exists())

    def test_fast_result_disarms_long_watchdog(self):
        started = time.monotonic()
        self.finish(self.start("exit 7", seconds=120), 7)
        self.assertLess(time.monotonic() - started, 10)
        self.assert_empty()

    def test_corrupted_receipt_cannot_redirect_owned_cleanup(self):
        run = self.start(self.blocking_payload())
        self.wait_ready(run[0])
        original = self.root / "original-receipt"
        original.write_bytes(self.receipt.read_bytes())
        self.receipt.write_bytes(b"corrupted receipt\n")
        self.release.touch()
        _, err = self.finish(run, 255)
        self.assertIn(b"RCH_SCOPED_COMPLETION_UNCONFIRMED", err)
        result = self.observe(f"rch_read_record {shlex.quote(str(original))} 115 || exit $?; rch_group_state")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.receipt.read_bytes(), b"corrupted receipt\n")

    def test_invalid_command_result_cannot_publish_success(self):
        run = self.start(self.blocking_payload())
        self.wait_ready(run[0])
        result = Path(str(self.receipt) + ".supervisor.v1/result")
        result.write_bytes(b"not an authenticated command result\n")
        result.chmod(0o600)
        self.finish(run, 255)
        self.assert_empty()

    def test_post_admission_census_loss_retains_uncertainty(self):
        loss = self.root / "census-unavailable"
        self.env["RCH_TEST_CENSUS_LOSS"] = str(loss)
        # Explicit failure AFTER native launch and admission. No fake positive
        # identity/death evidence is supplied. Fresh recovery uses real census.
        needle = "rch_group_state() {\n"
        self.assertEqual(PROTOCOL.count(needle), 1)
        fault = PROTOCOL.replace(needle, needle + '    [ ! -f "$RCH_TEST_CENSUS_LOSS" ] || return 2\n')
        run = self.start(self.blocking_payload(), protocol=fault)
        self.wait_ready(run[0])
        loss.touch()
        self.release.touch()
        _, err = self.finish(run, 255)
        self.assertIn(b"RCH_SCOPED_COMPLETION_UNCONFIRMED", err)
        self.assert_empty()
        self.assertEqual(self.cancel("kill").returncode, 0)

    def test_full_diagnostic_pipe_cannot_prevent_deadline_cleanup(self):
        read_end, write_end = os.pipe()
        try:
            os.set_blocking(write_end, False)
            while True:
                try:
                    os.write(write_end, b"x" * 4096)
                except BlockingIOError:
                    break
            os.set_blocking(write_end, True)
            run = self.start(self.blocking_payload(), seconds=2, diagnostic=write_end)
            self.wait_ready(run[0])
            started = time.monotonic()
            self.finish(run, 137)
            self.assertLess(time.monotonic() - started, 10)
            # The consumer deliberately never read a byte from the full pipe.
            self.assert_empty()
        finally:
            os.close(write_end)
            os.close(read_end)

    def test_closed_stderr_stays_closed_in_the_payload(self):
        code = "import os\ntry:\n os.fstat(2)\nexcept OSError:\n print('closed')\nelse:\n raise SystemExit(9)"
        out, err = self.finish(self.start("python3 -I -c " + shlex.quote(code), prefix="exec 2>&-"))
        self.assertEqual(out, b"closed\n")
        self.assertEqual(err, b"")
        self.assert_empty()


class DarwinPrimitives(unittest.TestCase):
    def run_adapter(self, body, data=None, boot_probe=None, env=None):
        source = CORE.replace("rch_control_capture() {", "rch_native_control_capture() {")
        source += (SOURCE / "remote_scoped_launch.sh").read_text()
        if boot_probe is not None:
            # Replace only the external sysctl executable. The production
            # capture, boot parser and recovery decision remain unchanged.
            self.assertEqual(source.count("/usr/sbin/sysctl"), 1)
            source = source.replace("/usr/sbin/sysctl", shlex.quote(str(boot_probe)))
        # Exercise these real portable syscalls without pretending Linux has
        # libproc/BSD stat. Native lifecycle selection is tested separately.
        source += ("\nuname() { printf 'Darwin\\n'; }\n"
                   # Keep the real host's file metadata for bounded capture;
                   # only the launch syscall adapter is selected as Darwin.
                   "rch_control_capture() ( unset -f uname; rch_native_control_capture \"$@\"; )\n"
                   + body)
        return subprocess.run([SHELL, "-c", source], input=data, env=env,
                              capture_output=True, start_new_session=True, timeout=10)

    def site_environment(self):
        # A real isolated venv, not a fake python executable. -I still loads
        # its .pth hooks; every RCH-owned helper must also request -S.
        temporary = tempfile.TemporaryDirectory(prefix="rch-site-hook-")
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name)
        virtual = root / "venv"
        venv.EnvBuilder(with_pip=False, symlinks=True).create(virtual)
        python = virtual / "bin/python3"
        site = Path(subprocess.check_output(
            [str(python), "-I", "-c", "import sysconfig; print(sysconfig.get_path('purelib'))"],
            text=True, timeout=10).strip())
        marker = root / "site-ran"
        (site / "rch_fixture_site_hook.py").write_text(
            f"with open({str(marker)!r}, 'a') as out: out.write('site loaded\\n')\n"
            "raise SystemExit(91)\n")
        (site / "rch_fixture.pth").write_text("import rch_fixture_site_hook\n")
        binaries = root / "bin"
        binaries.mkdir()
        for tool in ("awk", "cat", "cmp", "id", "mkdir", "mkfifo", "mktemp",
                     "mv", "ps", "rm", "rmdir", "sh", "sleep", "stat", "tr", "uname", "wc"):
            resolved = shutil.which(tool)
            if resolved:
                (binaries / tool).symlink_to(resolved)
        env = dict(os.environ, PATH=f"{virtual / 'bin'}:{binaries}", TMPDIR=str(root))
        baseline = subprocess.run(["python3", "-I", "-c", "pass"], env=env,
                                  capture_output=True, timeout=10)
        self.assertNotEqual(baseline.returncode, 0)
        self.assertEqual(marker.read_text(), "site loaded\n")
        return env, marker

    def test_control_monitor_does_not_load_site_hooks(self):
        env, marker = self.site_environment()
        result = self.run_adapter("rch_control_capture 1s /bin/sh -c 'printf observed'", env=env)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, b"observed")
        self.assertEqual(marker.read_text(), "site loaded\n")

    def test_darwin_lifecycle_helpers_do_not_load_site_hooks(self):
        env, marker = self.site_environment()
        child = subprocess.Popen(["/bin/sh", "-c", "exit 0"])
        child.wait(timeout=5)
        result = self.run_adapter(f'''
rch_scope_launch_fds || exit 1
rch_scope_launch_clock || exit 2
rch_darwin_process() {{ return 1; }}
rch_scope_launch_process {child.pid}
[ "$?" = 1 ] || exit 3
rch_scope_launch_exec /bin/sh -c 'printf launched' &
wait "$!" || exit 4
''', env=env)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, b"launched")
        result = self.run_adapter(
            "rch_scope_bound=0; rch_pgid=$$; rch_scope_launch_kill_self", env=env)
        self.assertEqual(result.returncode, -signal.SIGKILL, result.stderr)
        self.assertEqual(marker.read_text(), "site loaded\n")

    def test_session_exec_does_not_change_payload_python_startup(self):
        env, marker = self.site_environment()
        result = self.run_adapter(
            "rch_scope_launch_exec python3 -I -c 'pass' & wait \"$!\"", env=env)
        # The helper ignores site, but the requested payload must NOT: its
        # original argv/environment still select the failing Python site hook.
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(marker.read_text(), "site loaded\nsite loaded\n")

    def boot_observation(self, provider, body):
        with tempfile.TemporaryDirectory(prefix="rch-boot-probe-") as directory:
            probe = Path(directory) / "sysctl"
            probe.write_text("#!/bin/sh\n" + provider)
            probe.chmod(0o700)
            return self.run_adapter(body, boot_probe=probe)

    def test_failed_boot_probe_cannot_retire_execution(self):
        result = self.boot_observation(
            "printf '%s\\n' '13572468-1234-4ABC-8DEF-135724681357'; exit 7\n",
            r'''
rch_identified=1
rch_boot=24681357-1234-4abc-8def-246813572468
rch_recovery_boot_state
[ "$?" = 2 ] || exit 1
''')
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_boot_probe_preserves_same_and_confirmed_previous_boot(self):
        result = self.boot_observation(
            "printf '%s\\n' '13572468-1234-4ABC-8DEF-135724681357'\n",
            r'''
rch_identified=1
rch_boot=13572468-1234-4abc-8def-135724681357
rch_recovery_boot_state
[ "$?" = 0 ] || exit 1
rch_boot=24681357-1234-4abc-8def-246813572468
rch_recovery_boot_state
[ "$?" = 1 ] || exit 2
''')
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_boot_discontinuity_requires_two_successful_probes(self):
        result = self.boot_observation(r'''
printf '%s\n' '13572468-1234-4abc-8def-135724681357'
if [ -f "$0.seen" ]; then exit 7; fi
: > "$0.seen"
''', r'''
rch_identified=1
rch_boot=24681357-1234-4abc-8def-246813572468
rch_recovery_boot_state
[ "$?" = 2 ] || exit 1
''')
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_changing_boot_probe_is_not_confirmed_discontinuity(self):
        result = self.boot_observation(r'''
if [ -f "$0.seen" ]; then
    printf '%s\n' 'abcdef01-1234-4abc-8def-abcdefabcdef'
else
    printf '%s\n' '13572468-1234-4abc-8def-135724681357'
    : > "$0.seen"
fi
''', r'''
rch_identified=1
rch_boot=24681357-1234-4abc-8def-246813572468
rch_recovery_boot_state
[ "$?" = 2 ] || exit 1
''')
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_stalled_boot_probe_is_bounded_and_cannot_retire_execution(self):
        started = time.monotonic()
        result = self.boot_observation(
            "printf '%s\\n' '13572468-1234-4abc-8def-135724681357'; sleep 6\n",
            r'''
rch_identified=1
rch_boot=24681357-1234-4abc-8def-246813572468
rch_recovery_boot_state
[ "$?" = 2 ] || exit 1
''')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertLess(time.monotonic() - started, 4)

    def test_invalid_boot_bytes_never_become_recovery_authority(self):
        for provider in (
            "printf '13572468-1234-4abc-8def-135724681357\\000\\n'\n",
            "printf '%s\\n' '13572468-1234-4abc-8def-135724681357'; printf warning >&2\n",
            "printf '%s\\n' '00000000-0000-0000-0000-000000000000'\n",
            "printf '%s\\n' '13572468-1234-4abc-8def-135724681357' 'extra'\n",
            "exit 0\n",
        ):
            with self.subTest(provider=provider):
                result = self.boot_observation(provider, r'''
rch_identified=1
rch_boot=24681357-1234-4abc-8def-246813572468
rch_recovery_boot_state
[ "$?" = 2 ] || exit 1
''')
                self.assertEqual(result.returncode, 0, result.stderr)

    def test_failed_boot_read_publishes_no_stdout(self):
        result = self.boot_observation(
            "printf '%s\\n' '13572468-1234-4abc-8def-135724681357'; exit 7\n",
            "rch_read_boot")
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(result.stdout, b"")

    def test_reaped_process_is_absent_without_a_birth_witness(self):
        child = subprocess.Popen(["/bin/sh", "-c", "exit 0"])
        child.wait(timeout=5)
        result = self.run_adapter(f'''
rch_darwin_process() {{ return 1; }}
rch_scope_launch_process {child.pid}
[ "$?" = 1 ] || exit 1
[ -z "$rch_launch_birth$rch_launch_group" ] || exit 2
''')
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_live_process_without_birth_remains_unknown_and_unsignalled(self):
        child = subprocess.Popen(["/bin/sleep", "30"], start_new_session=True)
        try:
            result = self.run_adapter(f'''
rch_darwin_process() {{ return 1; }}
rch_launch_birth=stale
rch_launch_group=stale
rch_scope_launch_process {child.pid}
[ "$?" = 2 ] || exit 1
[ -z "$rch_launch_birth$rch_launch_group" ] || exit 2
''')
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIsNone(child.poll())
        finally:
            if child.poll() is None:
                child.kill()
            child.wait(timeout=5)

    def test_absence_probe_requires_exact_successful_evidence(self):
        for exchange in (
            "return 1",
            "printf 'RCH_PROCESS_ABSENT_V1:123'; return 7",
            "printf 'RCH_PROCESS_ABSENT_V1:456'",
            "printf 'RCH_PROCESS_ABSENT_V1:123\\nextra'",
            "printf ''",
        ):
            with self.subTest(exchange=exchange):
                result = self.run_adapter(f'''
rch_darwin_process() {{ return 1; }}
rch_control_capture() {{ {exchange}; }}
rch_scope_launch_process 123
[ "$?" = 2 ] || exit 1
''')
                self.assertEqual(result.returncode, 0, result.stderr)

    def test_invalid_pid_never_reaches_absence_probe(self):
        result = self.run_adapter(r'''
rch_darwin_process() { exit 90; }
rch_control_capture() { exit 91; }
for pid in 0 1 -1 invalid 2147483648; do
    rch_scope_launch_process "$pid"
    [ "$?" = 2 ] || exit 1
done
''')
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_fstat_preserves_occupied_slots_and_current_input(self):
        result = self.run_adapter(r'''
exec 4</dev/null 5>/dev/null
rch_scope_launch_save_input || exit 1
[ "$__sl_input" = 6 ] || exit 2
eval 'cat '"$__sl_input_redirect"' &'
wait "$!"
''', b"bytes\x00through pipe\xff")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, b"bytes\x00through pipe\xff")

    def test_fstat_observes_closed_input_and_stderr(self):
        result = self.run_adapter(r'''
exec 0<&- 2>&-
rch_scope_launch_save_input || exit 1
[ "$__sl_input_redirect" = '0<&-' ] || exit 2
if rch_scope_launch_fd_open 2; then exit 3; fi
''')
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_session_exec_keeps_child_pid_and_inherited_fd(self):
        result = self.run_adapter(r'''
exec 4</dev/null
rch_scope_launch_exec python3 -I -c 'import os; os.fstat(4); print(os.getpid(), os.getpgrp(), os.getsid(0))' &
child=$!
wait "$child" || exit 1
printf '%s\n' "$child"
''')
        self.assertEqual(result.returncode, 0, result.stderr)
        pid, group, session, child = map(int, result.stdout.split())
        self.assertEqual((pid, group, session), (child, child, child))

    def test_self_group_signal_refuses_an_unrelated_live_group(self):
        other = subprocess.Popen(["/bin/sleep", "20"], start_new_session=True)
        try:
            result = self.run_adapter(f"rch_scope_bound=0; rch_pgid={other.pid}; rch_scope_launch_kill_self")
            self.assertNotEqual(result.returncode, 0)
            self.assertIsNone(other.poll())
            result = self.run_adapter("rch_scope_bound=0; rch_pgid=$$; rch_scope_launch_kill_self")
            self.assertEqual(result.returncode, -signal.SIGKILL)
            self.assertIsNone(other.poll())
        finally:
            if other.poll() is None:
                other.kill()
            other.wait(timeout=5)

    def test_continuous_clock_is_positive_and_advances(self):
        result = self.run_adapter(r'''
rch_scope_launch_clock || exit 1
before=$rch_launch_now
sleep .1
rch_scope_launch_clock || exit 2
[ "$rch_launch_now" -gt "$before" ] || exit 3
''')
        self.assertEqual(result.returncode, 0, result.stderr)


if __name__ == "__main__":
    unittest.main()
