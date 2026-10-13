#!/usr/bin/env python3
"""Execute the production rch-build supervisor with real process trees.

Fast tests double ONLY policy discovery and systemd/cgroup operations. Actual
shell launch, niceness, V2 records, gates, result parsing, deadlines, process
identity, streams and cancellation/recovery are exercised. These are not live
cgroup or SSH/daemon tests. RCH_TEST_SYSTEMD_SLICE opts into real systemd tests.
Cargo passes the compiled protocol; standalone execution expands the exact
literal concat! expression and rejects any unknown Rust syntax.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
import re
import shlex
import signal
import string
import subprocess
import sys
import tempfile
import time
import unittest

SOURCE = Path(__file__).resolve().parents[1] / "src"
THIS = Path(__file__).resolve()
SHELL = os.environ.get("RCH_TEST_SHELL", "/bin/sh")


def assemble_protocol() -> str:
    rust = (SOURCE / "remote_scoped_launch.rs").read_text()
    expression = rust.split("= concat!(\n", 1)[1].split("\n);", 1)[0]
    parts = []
    for line in expression.splitlines():
        item = line.strip().removesuffix(",")
        include = re.fullmatch(r'include_str!\(("[^"\n]+")\)', item)
        if include:
            parts.append((SOURCE / json.loads(include[1])).read_text())
        else:
            parts.append(json.loads(item))
    return "".join(parts)


SELECT = r'''
rch_policy_select_file() {
    rch_policy_file=$RCH_TEST_POLICY_FILE
    rch_policy_owner=$(id -u)
}
'''

# No production launcher functions are replaced. This explicit fake resource
# backend tracks real, birth-bound groups and registered detached fixture PIDs.
MOCK_RESOURCE_BACKEND = r'''
rch_policy_enter_scope() {
    if [ "${RCH_TEST_ADMISSION_WAIT:-0}" = 1 ]; then
        printf '%s\n' "$rch_pgid" > "$RCH_TEST_ROOT/admission"
        sleep 30
    fi
    if [ "${RCH_TEST_CHANGE_POLICY:-0}" = 1 ]; then
        printf 'version=1\nnice=19\n' > "$RCH_TEST_POLICY_FILE"
    fi
    rch_scope_uid=$(id -u)
    rch_scope_manager=$rch_policy_manager
    rch_scope_invocation=0123456789abcdef0123456789abcdef
    rch_scope_namespace=1
    rch_scope_root_id=1.1
    rch_scope_node_id=1.$rch_pgid
    rch_scope_unit="rch-$rch_boot-$rch_pgid-$rch_start.scope"
    rch_scope_cgroup="/fixture/$rch_scope_unit"
    rch_scope_bound=1
    RCH_TEST_SCOPE_KEY=$rch_pgid; export RCH_TEST_SCOPE_KEY
    "$RCH_TEST_PYTHON" "$RCH_TEST_DRIVER" --backend bind "$RCH_TEST_ROOT" "$rch_pgid" "$rch_start"
}
rch_scope_operation() {
    "$RCH_TEST_PYTHON" "$RCH_TEST_DRIVER" --backend "$1" "$RCH_TEST_ROOT" "$rch_pgid" "$rch_start"
}
'''


def stat_process(pid: int) -> tuple[str, int, int] | None:
    try:
        fields = Path(f"/proc/{pid}/stat").read_text().rsplit(") ", 1)[1].split()
        return fields[0], int(fields[2]), int(fields[19])
    except FileNotFoundError:
        return None


def alive(pid: int, birth: int | None = None) -> bool:
    state = stat_process(pid)
    return state is not None and state[0] not in "ZXx" and (birth is None or state[2] == birth)


def resource_backend(operation: str, root: Path, pgid: int, start: int) -> int:
    directory = root / str(pgid)
    if operation == "bind":
        directory.mkdir()
        (directory / "owner").write_text(str(start))
        return 0
    if not (directory / "owner").is_file() or (directory / "owner").read_text() != str(start):
        return 3
    owner = stat_process(pgid)
    if owner is not None and owner[2] != start:
        return 3
    members = []
    registered = directory / "members"
    if registered.exists():
        for line in registered.read_text().splitlines():
            pid, birth = map(int, line.split(":"))
            if alive(pid, birth):
                members.append((pid, birth))
    if operation == "state":
        group_live = False
        for entry in Path("/proc").iterdir():
            if entry.name.isdecimal():
                state = stat_process(int(entry.name))
                if state is not None and state[1] == pgid and state[0] not in "ZXx":
                    group_live = True
        return int(group_live or bool(members))
    if operation == "probe":
        return 0
    if operation != "kill" or (root / "refuse-kill").exists():
        return 2
    # Record backend activity BEFORE killing: this helper may itself be in the
    # target group when called by the production in-scope watchdog.
    with (directory / "kills").open("a") as out:
        out.write(f"{os.getpid()}\n")
    for pid, birth in members:
        if alive(pid, birth):
            try:
                os.kill(pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
    try:
        os.killpg(pgid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    return 0


def protocol(instrument: bool = True, fixture: bool = True) -> str:
    expanded = assemble_protocol()
    compiled_path = os.environ.get("RCH_TEST_PROTOCOL_SCRIPT")
    if compiled_path:
        compiled = Path(compiled_path).read_text()
        if compiled != expanded:
            raise AssertionError("standalone expansion differs from compiled production protocol")
        expanded = compiled
    if not instrument:
        return expanded
    core = (SOURCE / "remote_process.sh").read_text()
    if expanded.count(core) != 1:
        raise AssertionError("expected one literal source shared by parent and child")
    return expanded.replace(core, core + SELECT + (MOCK_RESOURCE_BACKEND if fixture else ""))


def transport_quote(value: str) -> str:
    # shell-escape 0.1.5's Unix encoding, including its treatment of '!'.
    # The Rust unit test applies that crate directly; here we must exercise
    # real exec even when no Rust toolchain is installed on the test host.
    safe = string.ascii_letters + string.digits + "-_=/,.+"
    if value and all(char in safe for char in value):
        return value
    return "'" + "".join("'\\" + char + "'" if char in "'!" else char for char in value) + "'"


def nest_transport(script: str, layers: int) -> str:
    for _ in range(layers):
        script = f'exec {shlex.quote(SHELL)} -c {transport_quote(script)} rch-transport "$@"'
    return script


class ScriptTransport(unittest.TestCase):
    def invoke(self, script, *args, **options):
        return subprocess.run([SHELL, "-c", script, "rch-observer", *args],
                              capture_output=True, timeout=10, **options)

    def test_one_literal_hydrates_the_exact_child_program(self):
        source = protocol(instrument=False)
        core = (SOURCE / "remote_process.sh").read_text()
        launch = (SOURCE / "remote_scoped_launch.sh").read_text()
        self.assertEqual(source.count(core), 1)
        self.assertEqual(source.count(launch), 1)
        expected = (core + "\n" + launch).rstrip("\n").encode()
        result = self.invoke(source + '\nprintf "%s" "$rch_launch_source"\n')
        self.assertEqual((result.returncode, result.stdout, result.stderr), (0, expected, b""))

    def test_hydration_preserves_binary_stdin_and_literal_arguments(self):
        arguments = ["", "quote'!\\", "$(printf INJECTED)", "line\nRCH_SCOPED_LAUNCH_SOURCE_104\nend"]
        body = protocol(instrument=False) + '\nprintf "%s\\0" "$@"; command cat\n'
        payload = bytes(range(256)) * 64
        result = self.invoke(body, *arguments, input=payload,
                             env={**os.environ, "rch_launch_source": "printf INJECTED >&2; exit 99"})
        expected = b"".join(arg.encode() + b"\0" for arg in arguments) + payload
        self.assertEqual((result.returncode, result.stdout, result.stderr), (0, expected, b""))

    def test_four_quoted_transports_reach_the_protocol(self):
        body = protocol(instrument=False) + '\nrch_valid_pgid 42 || exit 90; printf "%s" "$1"\n'
        command = nest_transport(body, 4)
        # Retain the original 110 KB headroom, now after the enclosing layers.
        self.assertLess(len(command.encode()), 110_000)
        result = self.invoke(command, "reached'!$()\\")
        self.assertEqual((result.returncode, result.stdout, result.stderr),
                         (0, b"reached'!$()\\", b""))

    def test_failed_source_capture_does_not_evaluate_partial_output(self):
        with tempfile.TemporaryDirectory(prefix="rch-source-capture-") as name:
            program = Path(name) / "cat"
            program.write_text("#!/bin/sh\nprintf 'printf INJECTED; exit 0\\n'\nexit 1\n")
            program.chmod(0o700)
            result = self.invoke(protocol(instrument=False) + '\nprintf AFTER\n',
                                 env={**os.environ, "PATH": name})
            self.assertEqual((result.returncode, result.stdout, result.stderr), (125, b"", b""))


# Workload fixture: detached descendants ignore TERM and keep writing after the
# command exits unless the supervisor really cleans the whole resource group.
WORKLOAD = r'''
import json, os, signal, subprocess, sys, time
from pathlib import Path
root = Path(sys.argv[1]); mode = sys.argv[2]; code = int(sys.argv[3])
child_code = """
import os, signal, sys, time
from pathlib import Path
signal.signal(signal.SIGTERM, signal.SIG_IGN)
pid = os.getpid()
birth = Path(f'/proc/{pid}/stat').read_text().rsplit(') ', 1)[1].split()[19]
Path(sys.argv[1]).write_text(f'{pid}:{birth}')
while True:
    with open(sys.argv[2], 'a') as out: out.write('tick\\n')
    time.sleep(.05)
"""
child = subprocess.Popen([sys.executable, '-c', child_code, str(root/'child'), str(root/'beats')],
                         start_new_session=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
while not (root/'child').exists(): time.sleep(.01)
key = os.environ.get('RCH_TEST_SCOPE_KEY')
if key:
    with (Path(os.environ['RCH_TEST_ROOT'])/key/'members').open('a') as out:
        out.write((root/'child').read_text() + '\n')
(root/'observation').write_text(json.dumps({'nice': os.getpriority(os.PRIO_PROCESS, 0),
    'cwd': os.getcwd(), 'cgroup': Path('/proc/self/cgroup').read_text()}))
(root/'ready').write_text('ready')
print('streamed-stdout', flush=True); print('streamed-stderr', file=sys.stderr, flush=True)
if mode == 'hold':
    while not (root/'release').exists(): time.sleep(.05)
(root/'artifact').write_text('artifact-evidence')
sys.exit(code)
'''


@unittest.skipUnless(sys.platform == "linux", "Linux scope protocol")
class ScopedLaunch(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory(prefix="rch-scoped-launch-")
        self.root = Path(self.tmp.name)
        self.addCleanup(self.tmp.cleanup)
        self.processes: list[subprocess.Popen] = []
        self.streams = []
        self.addCleanup(self.cleanup_owned)
        self.policy = self.root / "policy"
        self.policy.write_text(f"version=1\nnice={max(10, os.getpriority(os.PRIO_PROCESS, 0))}\nsystemd_slice=jobs.slice\n")
        self.policy.chmod(0o600)
        self.env = {**os.environ, "RCH_TEST_POLICY_FILE": str(self.policy),
                    "RCH_TEST_ROOT": str(self.root), "RCH_TEST_PYTHON": sys.executable,
                    "RCH_TEST_DRIVER": str(THIS)}

    def cleanup_owned(self) -> None:
        for child in self.root.glob("*/child"):
            pid, birth = map(int, child.read_text().split(":"))
            if alive(pid, birth):
                os.kill(pid, signal.SIGKILL)
        for owner in self.root.glob("*/owner"):
            try:
                resource_backend("kill", self.root, int(owner.parent.name), int(owner.read_text()))
            except (OSError, ValueError):
                pass
        for proc in self.processes:
            if proc.poll() is None:
                proc.kill()
            proc.wait(timeout=5)
        for stream in self.streams:
            stream.close()

    def wait_for(self, predicate, seconds: float = 5) -> None:
        end = time.monotonic() + seconds
        while time.monotonic() < end:
            if predicate():
                return
            time.sleep(.02)
        self.assertTrue(predicate(), "condition did not become true")

    def start(self, name="42", mode="exit", code=0, limit=10, *, fixture=True,
              env=None, script=None, transport_layers=0) -> tuple[subprocess.Popen, Path, Path]:
        job = self.root / f"job-{name}"
        job.mkdir()
        record = self.root / f"{name}.pgid"
        out = (job / "stdout").open("w+")
        err = (job / "stderr").open("w+")
        self.streams += [out, err]
        body = protocol(fixture=fixture) if script is None else script
        # fd 3 and argv match TransferPipeline's tracked rch-build entry.
        command = f"exec {shlex.quote(SHELL)} -c {transport_quote(body + chr(10) + 'echo UNCONFINED; exit 97')} rch-build \"$@\" 3>&2"
        command = nest_transport(command, transport_layers)
        proc = subprocess.Popen(["/bin/sh", "-c", command, "scope-fixture", str(record), str(limit),
            "RCH_TEST_DEADLINE", name, sys.executable, "-c", WORKLOAD, str(job), mode, str(code)],
            cwd=job, env=env or self.env, stdin=subprocess.DEVNULL,
            stdout=out, stderr=err, start_new_session=True)
        self.processes.append(proc)
        return proc, job, record

    def finish(self, proc, job, expected=0) -> None:
        self.assertEqual(proc.wait(timeout=15), expected, (job / "stderr").read_text())
        self.assertNotIn("UNCONFINED", (job / "stdout").read_text())
        if (job / "child").exists():
            pid, birth = map(int, (job / "child").read_text().split(":"))
            self.assertFalse(alive(pid, birth), "detached descendant survived reported completion")
            before = (job / "beats").read_bytes()
            time.sleep(.12)
            self.assertEqual((job / "beats").read_bytes(), before)

    def recover(self, record: Path) -> subprocess.CompletedProcess:
        script = protocol() + '\nrch_remote_cancel "$1" "$2" "$3"\n'
        return subprocess.run([SHELL, "-c", script, "rch-recover", str(record), record.stem, "kill"],
                              env=self.env, text=True, capture_output=True, timeout=12)

    def test_normal_status_waits_for_detached_descendants(self) -> None:
        for code in (0, 23, 125):
            with self.subTest(code=code):
                proc, job, record = self.start(str(code + 1), code=code)
                self.finish(proc, job, code)
                self.assertEqual((job / "artifact").read_text(), "artifact-evidence")
                self.assertTrue(record.read_text().startswith("RCH_REMOTE_PROCESS_V2:"))
                self.assertNotIn("IDENTITY_UNAVAILABLE", (job / "stderr").read_text())

    def test_streams_working_directory_and_priority(self) -> None:
        proc, job, _ = self.start(mode="hold")
        self.wait_for(lambda: (job / "ready").exists())
        self.wait_for(lambda: "streamed-stdout" in (job / "stdout").read_text())
        self.assertIsNone(proc.poll(), "stdout must arrive before completion")
        obs = json.loads((job / "observation").read_text())
        self.assertEqual(obs["cwd"], str(job))
        self.assertEqual(obs["nice"], max(10, os.getpriority(os.PRIO_PROCESS, 0)))
        (job / "release").touch()
        self.finish(proc, job)
        self.assertIn("streamed-stderr", (job / "stderr").read_text())

    def test_nested_transport_keeps_scoped_cleanup_and_status(self) -> None:
        # One rch-build quote above plus three surrounding transport layers.
        # This formerly failed at exec before any workload could be launched.
        proc, job, record = self.start(code=23, transport_layers=3)
        self.finish(proc, job, 23)
        self.assertTrue(record.read_text().startswith("RCH_REMOTE_PROCESS_V2:"))
        self.assertEqual((job / "artifact").read_text(), "artifact-evidence")

    def test_deadline_reaps_scope_and_reports_marker(self) -> None:
        proc, job, _ = self.start(mode="hold", limit=1)
        self.finish(proc, job, 137)
        self.assertIn("RCH_TEST_DEADLINE", (job / "stderr").read_text())

    def test_supervisor_cancellation_reaps_scope(self) -> None:
        proc, job, _ = self.start(mode="hold")
        self.wait_for(lambda: (job / "ready").exists())
        proc.terminate()
        self.finish(proc, job, 143)

    def test_concurrent_jobs_do_not_cancel_each_other(self) -> None:
        one, first, _ = self.start("41", mode="hold")
        two, second, _ = self.start("42", mode="hold", code=17)
        self.wait_for(lambda: (first / "ready").exists() and (second / "ready").exists())
        one.terminate()
        self.finish(one, first, 143)
        self.assertIsNone(two.poll())
        (second / "release").touch()
        self.finish(two, second, 17)

    def test_fresh_channel_cancellation_and_repeated_recovery(self) -> None:
        proc, job, record = self.start(mode="hold")
        self.wait_for(lambda: (job / "ready").exists())
        before = record.read_bytes()
        result = self.recover(record)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.finish(proc, job, 137)
        self.assertEqual(record.read_bytes(), before)
        self.assertEqual(self.recover(record).returncode, 0)

    def test_supervisor_sigkill_cannot_strand_workload_with_no_deadline(self) -> None:
        proc, job, _ = self.start(mode="hold", limit=0)
        self.wait_for(lambda: (job / "ready").exists())
        proc.kill(); proc.wait(timeout=3)
        pid, birth = map(int, (job / "child").read_text().split(":"))
        self.wait_for(lambda: not alive(pid, birth))

    def test_unconfirmed_cleanup_retains_receipt_for_recovery(self) -> None:
        proc, job, record = self.start(mode="hold", limit=0)
        self.wait_for(lambda: (job / "ready").exists())
        (self.root / "refuse-kill").touch()
        (job / "release").touch()
        self.assertEqual(proc.wait(timeout=8), 255)
        self.assertIn("RCH_SCOPED_COMPLETION_UNCONFIRMED", (job / "stderr").read_text())
        before = record.read_bytes()
        (self.root / "refuse-kill").rename(self.root / "refusal-resolved")
        self.assertEqual(self.recover(record).returncode, 0)
        self.assertEqual(record.read_bytes(), before)

    def test_policy_snapshot_cannot_be_downgraded_during_launch(self) -> None:
        proc, job, record = self.start(env={**self.env, "RCH_TEST_CHANGE_POLICY": "1"})
        self.finish(proc, job)
        self.assertNotIn("systemd_slice", self.policy.read_text())
        self.assertTrue(record.read_text().startswith("RCH_REMOTE_PROCESS_V2:"))
        self.assertEqual(json.loads((job / "observation").read_text())["nice"], max(10, os.getpriority(os.PRIO_PROCESS, 0)))

    def test_cancellation_during_admission_starts_no_workload(self) -> None:
        proc, job, record = self.start(env={**self.env, "RCH_TEST_ADMISSION_WAIT": "1"})
        self.wait_for(lambda: (self.root / "admission").exists())
        proc.terminate()
        self.finish(proc, job, 143)
        self.assertFalse((job / "ready").exists())
        self.assertFalse(record.exists())

    def test_invalid_result_is_not_reported_as_compiler_success(self) -> None:
        proc, job, record = self.start(mode="hold", limit=0)
        self.wait_for(lambda: (job / "ready").exists())
        proc.send_signal(signal.SIGSTOP)
        (job / "release").touch()
        self.wait_for(lambda: bool(list(self.root.glob("*.supervisor.*/result"))))
        report = next(self.root.glob("*.supervisor.*/result"))
        report.write_text("RCH_SCOPED_RESULT_V1:wrong:0:0:0\n")
        proc.send_signal(signal.SIGCONT)
        self.finish(proc, job, 255)
        self.assertEqual(self.recover(record).returncode, 0)

    def test_missing_real_systemd_prerequisites_never_fall_through(self) -> None:
        # No systemd/cgroup double here. A definitely absent slice must refuse.
        self.policy.write_text("version=1\nsystemd_slice=rch-test-definitely-missing-104.slice\n")
        proc, job, record = self.start(fixture=False)
        self.finish(proc, job, 125)
        self.assertFalse((job / "ready").exists())
        self.assertFalse(record.exists())
        self.assertIn("RCH_WORKER_POLICY_REFUSED", (job / "stderr").read_text())

    def test_no_policy_and_nice_only_keep_legacy_entry(self) -> None:
        for scope_policy in ("", "version=1\nnice=10\n"):
            self.policy.write_text(scope_policy)
            env = {**self.env, "RCH_TEST_POLICY_FILE": str(self.policy) if scope_policy else ""}
            proc, job, _ = self.start(str(80 + len(scope_policy)), env=env)
            self.assertEqual(proc.wait(timeout=5), 97)
            self.assertIn("UNCONFINED", (job / "stdout").read_text())

    def test_recovery_entry_does_not_parse_current_policy(self) -> None:
        self.policy.write_text("invalid current policy")
        result = subprocess.run([SHELL, "-c", protocol() + '\nprintf loaded', "rch-recover"],
                                env=self.env, text=True, capture_output=True, timeout=3)
        self.assertEqual((result.returncode, result.stdout), (0, "loaded"))

    @unittest.skipUnless(os.environ.get("RCH_TEST_SYSTEMD_SLICE"), "opt-in live systemd user slice")
    def test_live_systemd_completion_timeout_cancellation_and_supervisor_loss(self) -> None:
        self.policy.write_text(f"version=1\nnice=10\nsystemd_slice={os.environ['RCH_TEST_SYSTEMD_SLICE']}\n")
        for index, mode in enumerate(("normal", "deadline", "cancel", "lost-parent")):
            with self.subTest(mode=mode):
                proc, job, _ = self.start(str(200 + index), mode="exit" if mode == "normal" else "hold",
                                           limit=1 if mode == "deadline" else 0, fixture=False)
                self.wait_for(lambda: (job / "ready").exists())
                observation = json.loads((job / "observation").read_text())
                self.assertIn(os.environ["RCH_TEST_SYSTEMD_SLICE"], observation["cgroup"])
                self.assertEqual(observation["nice"], 10)
                if mode == "lost-parent":
                    proc.kill(); proc.wait(timeout=3)
                    pid, birth = map(int, (job / "child").read_text().split(":"))
                    self.wait_for(lambda: not alive(pid, birth), 12)
                else:
                    if mode == "cancel": proc.terminate()
                    self.finish(proc, job, {"normal": 0, "deadline": 137, "cancel": 143}[mode])


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "--backend":
        sys.exit(resource_backend(sys.argv[2], Path(sys.argv[3]), int(sys.argv[4]), int(sys.argv[5])))
    unittest.main(verbosity=2)
