#!/usr/bin/env python3
"""Native one-shot admission tests for the production Linux worker supervisor.

Only policy discovery and explicit scheduling/failure injection are adapted.
The production mkdir, child launch, records, payload, watchdog and cancellation
run on real processes/files. This does not qualify live SSH, mixed-version
writers, power-loss durability, or systemd containment. Fixtures are retained.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import re
import shlex
import signal
import subprocess
import sys
import tempfile
import time
import unittest

SOURCE = Path(__file__).resolve().parents[1] / "src"
SHELL = os.environ.get("RCH_TEST_SHELL", "/bin/sh")


def assemble() -> str:
    rust = (SOURCE / "remote_scoped_launch.rs").read_text()
    expression = rust.split("= concat!(\n", 1)[1].split("\n);", 1)[0]
    parts = []
    for line in expression.splitlines():
        item = line.strip().removesuffix(",")
        include = re.fullmatch(r'include_str!\(("[^"\n]+")\)', item)
        parts.append((SOURCE / json.loads(include[1])).read_text() if include else json.loads(item))
    source = "".join(parts)
    compiled = os.environ.get("RCH_TEST_PROTOCOL_SCRIPT")
    if compiled and Path(compiled).read_text() != source:
        raise AssertionError("literal source expansion differs from compiled protocol")
    return source


def protocol(*, slow_parent=False, pause_before_child=False, extra="") -> str:
    source = assemble()
    core = (SOURCE / "remote_process.sh").read_text()
    launch = (SOURCE / "remote_scoped_launch.sh").read_text()
    if source.count(core) != 1 or source.count(launch) != 1:
        raise AssertionError("expected exactly one shared copy of each production source")
    # No host configuration or service is changed. Use the existing V1 lane.
    source = source.replace(core, core + '\nrch_policy_select_file() { rch_policy_file=; }\n')
    adapted = launch
    if slow_parent:
        # Delegate the original clock unchanged; delay only the observer so
        # record publication races are deterministic on the unmodified source.
        if adapted.count("rch_scope_launch_clock() {") != 1:
            raise AssertionError("clock fixture no longer matches production")
        adapted = adapted.replace("rch_scope_launch_clock() {", "rch_fixture_clock() {")
        adapted += r'''
rch_scope_launch_clock() {
    if [ "$0" = rch-build ]; then sleep 0.15; fi
    rch_fixture_clock
}
'''
    if pause_before_child:
        if adapted.count("rch_scope_launch_save_input() {") != 1:
            raise AssertionError("input fixture no longer matches production")
        adapted = adapted.replace("rch_scope_launch_save_input() {", "rch_fixture_save_input() {")
        adapted += r'''
rch_scope_launch_save_input() {
    if [ "$0" = rch-build ]; then
        printf '%s\n' "$$" > "$RCH_BEFORE_CHILD"
        while :; do sleep 0.01; done
    fi
    rch_fixture_save_input
}
'''
    source = source.replace(launch, adapted + extra)
    return source


PAYLOAD = r'''
import os, sys, time
from pathlib import Path
root = Path(sys.argv[1]); mode = sys.argv[2]; status = int(sys.argv[3])
with (root/'executions').open('ab', buffering=0) as output:
    output.write((str(os.getpid())+'\n').encode())
(root/'started').write_text('started')
if mode == 'hold':
    while not (root/'release').exists(): time.sleep(.01)
(root/'artifact').write_bytes(b'verified-fixture-output')
sys.exit(status)
'''


def process(pid):
    try:
        fields = Path(f"/proc/{pid}/stat").read_bytes().rsplit(b") ", 1)[1].split()
        return fields[0], int(fields[2]), int(fields[19])
    except FileNotFoundError:
        return None


@unittest.skipUnless(sys.platform == "linux", "Linux owned supervisor")
class LaunchOnce(unittest.TestCase):
    def setUp(self):
        self.root = Path(tempfile.mkdtemp(prefix="rch-launch-once-"))
        self.record = self.root / "41.pgid"
        self.children = []
        self.handles = []
        self.addCleanup(self.stop_owned)

    def stop_owned(self):
        for child, _, _ in self.children:
            if child.poll() is None:
                child.kill()
            child.wait(timeout=5)
        # The production watchdog gets a chance to observe its lost parent.
        # Only a still-birth-matching test-owned record is a cleanup target.
        for record in self.root.glob("*.pgid"):
            if not record.is_file() or record.is_symlink():
                continue
            fields = record.read_text().strip().split(":")
            if len(fields) != 5 or fields[0] != "RCH_REMOTE_PROCESS_V1":
                continue
            pid, birth = int(fields[3]), int(fields[4])
            deadline = time.monotonic() + 3
            while (state := process(pid)) and state[0] not in (b"Z", b"X", b"x") and state[2] == birth:
                if time.monotonic() >= deadline:
                    os.killpg(pid, signal.SIGKILL)
                    break
                time.sleep(.02)
        for handle in self.handles:
            handle.close()

    def start(self, *, record=None, job=None, mode="done", status=7, build="41", script=None, env=None, gate=None):
        record = self.record if record is None else record
        job = self.root if job is None else job
        index = len(self.children)
        out, err = self.root / f"out-{index}", self.root / f"err-{index}"
        handles = out.open("wb"), err.open("wb")
        self.handles.extend(handles)
        program = protocol() if script is None else script
        if gate:
            program = ('printf "%s\\n" "$$" >> "$RCH_GATE_READY"\n'
                       'while [ ! -e "$RCH_LAUNCH_GATE" ]; do sleep .01; done\n' + program)
        child = subprocess.Popen([SHELL, "-c", program, "rch-build", str(record), "10", "RCH_TEST", build,
                                  sys.executable, "-I", "-c", PAYLOAD, str(job), mode, str(status)],
                                 stdin=subprocess.DEVNULL, stdout=handles[0], stderr=handles[1],
                                 start_new_session=True, env={**os.environ, "LC_ALL": "C", **(env or {})})
        entry = child, out, err
        self.children.append(entry)
        return entry

    def finish(self, entry):
        child, out, err = entry
        code = child.wait(timeout=15)
        return code, out.read_bytes(), err.read_bytes()

    def wait_for(self, predicate):
        deadline = time.monotonic() + 10
        while not predicate():
            if time.monotonic() >= deadline:
                self.fail("native launch did not reach the expected boundary")
            time.sleep(.01)

    def count(self, root=None):
        path = (root or self.root) / "executions"
        return len(path.read_bytes().splitlines()) if path.exists() else 0

    def retained(self):
        result = {}
        for path in self.root.glob("41.pgid*"):
            paths = [path, *path.rglob("*")] if path.is_dir() and not path.is_symlink() else [path]
            for item in paths:
                stat = item.lstat()
                data = item.read_bytes() if item.is_file() and not item.is_symlink() else b""
                result[str(item.relative_to(self.root))] = (stat.st_ino, stat.st_mode, hashlib.sha256(data).hexdigest())
        return result

    def refused(self, entry):
        code, out, err = self.finish(entry)
        self.assertEqual(code, 255, (err, {"workload_executions": self.count()}))
        self.assertEqual(out, b"")
        self.assertIn(b"RCH_SCOPED_LAUNCH_ALREADY_OWNED", err)
        self.assertNotIn(b"IDENTITY_UNAVAILABLE", err, "a duplicate must not authorize setup fallback")

    def test_completed_job_is_not_reexecuted_or_overwritten(self):
        scripted = protocol(slow_parent=True)
        self.assertEqual(self.finish(self.start(script=scripted))[0], 7)
        before = self.retained()
        self.refused(self.start(script=scripted))
        self.assertEqual(self.count(), 1)
        self.assertEqual(self.retained(), before)

    def test_changed_policy_cannot_turn_a_duplicate_into_safe_fallback(self):
        self.assertEqual(self.finish(self.start())[0], 7)
        before = self.retained()
        self.refused(self.start(script=protocol(extra='\nrch_policy_select_file() { return 1; }\n')))
        self.assertEqual(self.count(), 1)
        self.assertEqual(self.retained(), before)

    def test_fresh_policy_refusal_starts_no_workload_and_keeps_its_claim(self):
        refusal = protocol(extra='\nrch_policy_select_file() { return 1; }\n')
        code, out, err = self.finish(self.start(script=refusal))
        self.assertEqual(code, 125, err)
        self.assertEqual(out, b'')
        self.assertIn(b'IDENTITY_UNAVAILABLE', err)
        self.assertFalse(self.record.exists())
        self.refused(self.start())
        self.assertEqual(self.count(), 0)

    def test_simultaneous_supervisors_start_exactly_one_workload(self):
        gate, ready = self.root / "gate", self.root / "gate-ready"
        env = {"RCH_LAUNCH_GATE": str(gate), "RCH_GATE_READY": str(ready)}
        attempts = [self.start(gate=True, env=env) for _ in range(12)]
        self.wait_for(lambda: ready.exists() and len(ready.read_text().splitlines()) == 12)
        gate.touch()
        results = [self.finish(attempt) for attempt in attempts]
        self.assertEqual(sorted(code for code, _, _ in results), [7] + [255] * 11)
        self.assertEqual(self.count(), 1)
        self.assertEqual(len(list(self.root.glob("*.supervisor.*"))), 1)
        self.assertTrue(self.record.read_text().startswith("RCH_REMOTE_PROCESS_V1:41:"))

    def test_active_owner_and_its_record_survive_a_duplicate(self):
        first = self.start(mode="hold")
        self.wait_for(lambda: (self.root / "started").exists())
        before = self.record.read_bytes()
        leader = int(before.split(b":")[3])
        self.refused(self.start())
        self.assertIsNone(first[0].poll())
        self.assertNotIn(process(leader)[0], (b"Z", b"X", b"x"))
        self.assertEqual(self.record.read_bytes(), before)
        self.assertEqual(self.count(), 1)
        (self.root / "release").touch()
        self.assertEqual(self.finish(first)[0], 7)

    def test_retired_record_does_not_erase_the_retained_launch_claim(self):
        self.assertEqual(self.finish(self.start())[0], 7)
        retained = self.root / "retired-record"
        self.record.rename(retained)
        before = self.retained()
        self.refused(self.start())
        self.assertEqual(self.count(), 1)
        self.assertFalse(self.record.exists())
        self.assertEqual(self.retained(), before)
        self.assertTrue(retained.read_text().startswith("RCH_REMOTE_PROCESS_V1:41:"))

    def test_lost_supervisor_before_record_publication_cannot_be_replayed(self):
        paused = self.root / "before-child"
        first = self.start(script=protocol(pause_before_child=True), env={"RCH_BEFORE_CHILD": str(paused)})
        self.wait_for(paused.exists)
        self.assertFalse(self.record.exists())
        first[0].kill()
        self.assertEqual(self.finish(first)[0], -9)
        before = self.retained()
        self.refused(self.start())
        self.assertEqual(self.count(), 0)
        self.assertEqual(self.retained(), before)

    def test_lost_supervisor_after_start_is_not_permission_for_another_attempt(self):
        first = self.start(mode="hold")
        self.wait_for(lambda: (self.root / "started").exists())
        fields = self.record.read_text().strip().split(":")
        leader, birth = int(fields[3]), int(fields[4])
        first[0].kill()
        self.assertEqual(self.finish(first)[0], -9)
        self.refused(self.start())
        self.assertEqual(self.count(), 1)
        self.wait_for(lambda: (state := process(leader)) is None or state[0] in (b"Z", b"X", b"x") or state[2] != birth)

    def test_legacy_record_is_preserved_without_creating_a_new_control_directory(self):
        self.record.write_text("retained legacy ownership\n")
        before = self.retained()
        self.refused(self.start())
        self.assertEqual(self.retained(), before)
        self.assertEqual(self.count(), 0)
        self.assertEqual(list(self.root.glob("*.supervisor.*")), [])

    def test_symlink_directory_and_fifo_records_refuse_without_following(self):
        target = self.root / "target"
        target.write_text("untouched")
        for index, kind in enumerate(("symlink", "dangling", "directory", "fifo")):
            path = self.root / f"{index}.pgid"
            if kind in ("symlink", "dangling"):
                path.symlink_to(target if kind == "symlink" else self.root / "absent")
            elif kind == "directory":
                path.mkdir()
            else:
                os.mkfifo(path)
            before = path.lstat()
            self.refused(self.start(record=path))
            self.assertEqual(path.lstat().st_ino, before.st_ino)
            self.assertFalse(Path(str(path) + ".supervisor.v1").exists())
        self.assertEqual(target.read_text(), "untouched")
        self.assertFalse((self.root / "absent").exists())
        self.assertEqual(self.count(), 0)

    def test_existing_control_directory_file_or_alias_is_never_adopted(self):
        target = self.root / "foreign-control"
        target.mkdir()
        sentinel = target / "sentinel"
        sentinel.write_text("untouched")
        for index, kind in enumerate(("directory", "file", "symlink", "dangling")):
            path = self.root / f"control-{index}.pgid"
            control = Path(str(path) + ".supervisor.v1")
            if kind == "directory": control.mkdir()
            elif kind == "file": control.write_text("foreign file")
            else: control.symlink_to(target if kind == "symlink" else self.root / "absent")
            before = control.lstat()
            self.refused(self.start(record=path))
            self.assertEqual(control.lstat().st_ino, before.st_ino)
            self.assertFalse(path.exists())
        self.assertEqual(sentinel.read_text(), "untouched")
        self.assertEqual(self.count(), 0)

    def test_distinct_record_identities_can_run_independently(self):
        jobs = [self.root / name for name in ("one", "two")]
        for job in jobs: job.mkdir()
        entries = [self.start(record=self.root / f"distinct-{i}.pgid", job=job, mode="hold", build=str(41 + i))
                   for i, job in enumerate(jobs)]
        self.wait_for(lambda: all((job / "started").exists() for job in jobs))
        self.assertTrue(all(entry[0].poll() is None for entry in entries))
        for job in jobs: (job / "release").touch()
        self.assertEqual([self.finish(entry)[0] for entry in entries], [7, 7])
        self.assertEqual([self.count(job) for job in jobs], [1, 1])

    def test_legacy_record_arriving_during_claim_creation_refuses_before_child(self):
        extra = r'''
mkdir() {
    command mkdir "$@" || return $?
    printf '%s\n' late-owner > "$RCH_LATE_RECORD"
}
'''
        self.refused(self.start(script=protocol(extra=extra), env={"RCH_LATE_RECORD": str(self.record)}))
        self.assertEqual(self.record.read_text(), "late-owner\n")
        self.assertEqual(self.count(), 0)

    def test_ambiguous_claim_creation_is_retained_and_never_retried(self):
        extra = r'''
mkdir() { command mkdir "$@" || return $?; return 1; }
'''
        self.refused(self.start(script=protocol(extra=extra)))
        before = self.retained()
        self.refused(self.start())
        self.assertEqual(self.retained(), before)
        self.assertEqual(self.count(), 0)


if __name__ == "__main__":
    unittest.main(verbosity=2)
