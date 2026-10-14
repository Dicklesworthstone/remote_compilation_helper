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
import fcntl
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


def _neutral_shell(shell: str) -> str:
    """``shell`` under a name no ananicy rule matches (``bash`` -> nice -4 on
    the fleet, inherited by everything it launches). Plain ``sh`` keeps its
    name: a bash that runs as ``sh`` switches to POSIX mode by argv[0]."""
    if sys.platform != "linux" or Path(shell).name == "sh":
        return shell
    alias = Path(tempfile.mkdtemp(prefix="rch-test-shell-")) / f"rchtest{Path(shell).name}"
    alias.symlink_to(shell)
    return str(alias)


SHELL = _neutral_shell(SHELL)



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


def check_admitted_receipt_change(test, mutation: str, index: int) -> None:
    """The original workload must stop, without trusting the replacement record.

    Pause its whole private group, including the backup watchdog. This isolates
    the outside supervisor's cleanup responsibility: a later parent-death timer
    must not conceal a failed cancellation. V1 uses real process observations
    and signals; the V2 cases retain the suite's explicit resource backend.
    """
    proc, job, record = test.start(str(600 + index), mode="hold", limit=0)
    other, other_job, other_record = test.start(str(700 + index), mode="hold", limit=0)
    test.wait_for(lambda: (job / "ready").exists() and (other_job / "ready").exists())
    original = record.read_bytes()
    other_original = other_record.read_bytes()
    fields = original.decode().strip().split(":")
    leader, birth = int(fields[3]), int(fields[4])

    def stop_owned_group(pid, started):
        # Only the exact private fixture group, never a receipt changed below.
        if alive(pid, started):
            try:
                os.killpg(pid, signal.SIGKILL)
            except ProcessLookupError:
                pass

    for bound in (fields, other_original.decode().strip().split(":")):
        test.addCleanup(stop_owned_group, int(bound[3]), int(bound[4]))
    test.assertTrue(alive(leader, birth))
    os.killpg(leader, signal.SIGSTOP)
    test.wait_for(lambda: (state := stat_process(leader)) is not None and state[0] == "T")
    retained = record.with_suffix(".before")
    record.rename(retained)
    changed = list(fields)
    if mutation == "missing":
        pass
    elif mutation == "symlink":
        record.symlink_to(other_record)
    else:
        if mutation == "truncated":
            replacement = original[:-1]
        elif mutation == "foreign":
            replacement = other_original
        else:
            if mutation == "build":
                changed[1] = "another-build"
            elif mutation == "birth":
                changed[4] = str(birth + 1)
            elif mutation == "boot":
                changed[2] = "11111111-1111-1111-1111-111111111111"
            elif mutation == "manager":
                changed[6] = "system"
            elif mutation == "invocation":
                changed[7] = "abcdef0123456789abcdef0123456789"
            elif mutation == "inode":
                changed[10] = "1.999999"
            elif mutation == "downgrade":
                changed = ["RCH_REMOTE_PROCESS_V1", *fields[1:5]]
            else:
                raise AssertionError(f"unknown mutation {mutation}")
            replacement = (":".join(changed) + "\n").encode()
        record.write_bytes(replacement)
        record.chmod(0o600)
    proc.terminate()
    test.finish(proc, job, 255)
    test.assertIn(b"RCH_SCOPED_COMPLETION_UNCONFIRMED", (job / "stderr").read_bytes())
    test.assertNotIn(b"IDENTITY_UNAVAILABLE", (job / "stderr").read_bytes())
    test.assertEqual(retained.read_bytes(), original)
    test.assertEqual(other_record.read_bytes(), other_original)
    if mutation == "missing":
        test.assertFalse(record.exists())
    elif mutation == "symlink":
        test.assertEqual(record.readlink(), other_record)
    else:
        test.assertEqual(record.read_bytes(), replacement)
    # Both the unrelated leader and its actual writer must remain live.
    test.assertIsNone(other.poll())
    sibling_pid, sibling_birth = map(int, (other_job / "child").read_text().split(":"))
    test.assertTrue(alive(sibling_pid, sibling_birth))
    before = (other_job / "beats").stat().st_size
    test.wait_for(lambda: (other_job / "beats").stat().st_size > before)
    (other_job / "release").touch()
    test.finish(other, other_job)


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
                    "RCH_TEST_ROOT": str(self.root), "RCH_TEST_PYTHON": PYTHON,
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
              env=None, script=None, transport_layers=0, workload=WORKLOAD) -> tuple[subprocess.Popen, Path, Path]:
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
            "RCH_TEST_DEADLINE", name, PYTHON, "-c", workload, str(job), mode, str(code)],
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

    def test_admitted_scope_cleanup_survives_receipt_loss_and_replacement(self) -> None:
        for index, mutation in enumerate(("missing", "truncated", "foreign", "symlink", "build", "birth", "boot")):
            with self.subTest(mutation=mutation):
                check_admitted_receipt_change(self, mutation, index)

    def test_admitted_scope_binding_cannot_change_or_downgrade(self) -> None:
        for index, mutation in enumerate(("manager", "invocation", "inode", "downgrade")):
            with self.subTest(mutation=mutation):
                check_admitted_receipt_change(self, mutation, index)

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

    def test_requested_scope_cannot_accept_a_v1_receipt(self) -> None:
        proc, job, record = self.start(mode="hold", limit=0)
        self.wait_for(lambda: (job / "ready").exists())
        # V1 and V2 both exist in mixed fleets, but a requested scope must
        # never silently adopt the weaker class on readback or recovery.
        original = record.read_text()
        record.write_text(":".join(original.strip().split(":")[:5]).replace(
            "RCH_REMOTE_PROCESS_V2:", "RCH_REMOTE_PROCESS_V1:") + "\n")
        (job / "release").touch()
        self.assertEqual(proc.wait(timeout=8), 255)
        self.assertIn("RCH_SCOPED_COMPLETION_UNCONFIRMED", (job / "stderr").read_text())
        record.write_text(original)
        self.assertEqual(self.recover(record).returncode, 0)

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


# V1 proves only its process group, not descendants which deliberately setsid.
# Unlike the V2 tests above, this lane doubles NO resource/identity/signal APIs.
GROUP_WORKLOAD = r'''
import json, os, subprocess, sys, time
from pathlib import Path
root = Path(sys.argv[1]); mode = sys.argv[2]; code = int(sys.argv[3])
child_code = """
import fcntl, os, signal, sys, time
from pathlib import Path
root = Path(sys.argv[1])
signal.signal(signal.SIGTERM, signal.SIG_IGN)
lock = (root/'held.lock').open('a')
fcntl.flock(lock, fcntl.LOCK_EX)
for fd in (0, 1, 2): os.close(fd)
pid = os.getpid()
birth = Path(f'/proc/{pid}/stat').read_text().rsplit(') ', 1)[1].split()[19]
(root/'child').write_text(f'{pid}:{birth}')
while True:
    with (root/'beats').open('a') as out: out.write('tick\\n')
    time.sleep(.02)
"""
child = subprocess.Popen([sys.executable, '-c', child_code, str(root)])
while not (root/'child').exists() or not (root/'beats').exists(): time.sleep(.01)
(root/'observation').write_text(json.dumps({'nice': os.getpriority(os.PRIO_PROCESS, 0),
    'cwd': os.getcwd(), 'group': os.getpgrp()}))
os.write(1, b'bytes-stdout:\x00\xff\n')
os.write(2, b'bytes-stderr:\x00\xfe\n')
(root/'ready').write_text('ready')
if mode == 'hold':
    while not (root/'release').exists(): time.sleep(.02)
(root/'artifact').write_text('artifact-evidence')
sys.exit(code)
'''


@unittest.skipUnless(sys.platform == "linux", "Linux process-group protocol")
class ProcessGroupLaunch(unittest.TestCase):
    setUp = ScopedLaunch.setUp
    cleanup_owned = ScopedLaunch.cleanup_owned
    wait_for = ScopedLaunch.wait_for

    def start(self, name="42", **options):
        options.setdefault("env", {**self.env, "RCH_TEST_POLICY_FILE": ""})
        return ScopedLaunch.start(self, name, fixture=False, workload=GROUP_WORKLOAD, **options)

    def finish(self, proc, job, expected=0):
        self.assertEqual(proc.wait(timeout=15), expected, (job / "stderr").read_bytes())
        self.assertNotIn(b"UNCONFINED", (job / "stdout").read_bytes())
        pid, birth = map(int, (job / "child").read_text().split(":"))
        self.assertFalse(alive(pid, birth), "live descendant after terminal return")
        before = (job / "beats").read_bytes()
        time.sleep(.1)
        self.assertEqual((job / "beats").read_bytes(), before)
        with (job / "held.lock").open("a") as lock:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)

    def recover(self, record):
        script = protocol(fixture=False) + '\nrch_remote_cancel "$1" "$2" "$3"\n'
        return subprocess.run([SHELL, "-c", script, "rch-recover", str(record), record.stem, "kill"],
                              env=self.env, capture_output=True, timeout=12)

    def test_no_policy_reaps_closed_pipe_descendants_before_preserving_status(self):
        for code in (0, 23, 125):
            with self.subTest(code=code):
                proc, job, record = self.start(str(code + 1), code=code)
                self.finish(proc, job, code)
                self.assertTrue(record.read_bytes().startswith(b"RCH_REMOTE_PROCESS_V1:"))
                self.assertEqual((job / "artifact").read_text(), "artifact-evidence")
                self.assertEqual((job / "stdout").read_bytes(), b"bytes-stdout:\x00\xff\n")
                self.assertIn(b"bytes-stderr:\x00\xfe\n", (job / "stderr").read_bytes())
                self.assertNotIn(b"IDENTITY_UNAVAILABLE", (job / "stderr").read_bytes())

    def test_nice_only_enforces_priority_without_requiring_systemd(self):
        nice = max(10, os.getpriority(os.PRIO_PROCESS, 0))
        self.policy.write_text(f"version=1\nnice={nice}\n")
        proc, job, record = self.start(env=self.env)
        self.finish(proc, job)
        observation = json.loads((job / "observation").read_text())
        self.assertEqual(observation["nice"], nice)
        self.assertEqual(observation["cwd"], str(job))
        self.assertTrue(record.read_bytes().startswith(b"RCH_REMOTE_PROCESS_V1:"))

    def test_deadline_stops_group_and_keeps_deadline_evidence(self):
        started = time.monotonic()
        proc, job, _ = self.start(mode="hold", limit=1)
        self.finish(proc, job, 137)
        self.assertGreaterEqual(time.monotonic() - started, 1)
        self.assertIn(b"RCH_TEST_DEADLINE", (job / "stderr").read_bytes())

    def test_supervisor_term_stops_group_with_unlimited_runtime(self):
        proc, job, _ = self.start(mode="hold", limit=0)
        self.wait_for(lambda: (job / "ready").exists())
        self.assertIsNone(proc.poll())
        self.assertEqual((job / "stdout").read_bytes(), b"bytes-stdout:\x00\xff\n")
        proc.terminate()
        self.finish(proc, job, 143)

    def test_admitted_group_cleanup_survives_receipt_loss_and_replacement(self):
        for index, mutation in enumerate(("missing", "truncated", "foreign", "symlink", "build", "birth", "boot")):
            with self.subTest(mutation=mutation):
                check_admitted_receipt_change(self, mutation, index)

    def test_supervisor_sigkill_triggers_birth_fenced_in_group_watchdog(self):
        proc, job, record = self.start(mode="hold", limit=0)
        self.wait_for(lambda: (job / "ready").exists())
        proc.kill(); proc.wait(timeout=3)
        pid, birth = map(int, (job / "child").read_text().split(":"))
        self.wait_for(lambda: not alive(pid, birth))
        self.assertEqual(self.recover(record).returncode, 0)

    def test_concurrent_groups_remain_independent(self):
        one, first, _ = self.start("41", mode="hold", limit=0)
        two, second, _ = self.start("42", mode="hold", code=17, limit=0)
        self.wait_for(lambda: (first / "ready").exists() and (second / "ready").exists())
        one.terminate()
        self.finish(one, first, 143)
        self.assertIsNone(two.poll())
        (second / "release").touch()
        self.finish(two, second, 17)

    def test_fresh_channel_cancellation_and_repeated_recovery_preserve_record(self):
        proc, job, record = self.start(mode="hold", limit=0)
        self.wait_for(lambda: (job / "ready").exists())
        before = record.read_bytes()
        result = self.recover(record)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.finish(proc, job, 137)
        self.assertEqual(self.recover(record).returncode, 0)
        self.assertEqual(record.read_bytes(), before)

    def test_nested_transport_keeps_group_ownership(self):
        proc, job, _ = self.start(code=23, transport_layers=3)
        self.finish(proc, job, 23)


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "--backend":
        sys.exit(resource_backend(sys.argv[2], Path(sys.argv[3]), int(sys.argv[4]), int(sys.argv[5])))
    unittest.main(verbosity=2)
