"""Deterministic GiB scenarios plus small real-process disk guard regressions.

Run: PYTHONDONTWRITEBYTECODE=1 python3 rch-common/tests/build_disk_monitor_test.py
Fixtures are retained for inspection; these tests never fill a filesystem.
"""

import importlib.util
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import time
import unittest
from types import SimpleNamespace
from unittest.mock import patch

SOURCE = Path(__file__).resolve().parents[1] / "build_disk_monitor.py"
SPEC = importlib.util.spec_from_file_location("build_disk_monitor", SOURCE)
monitor = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(monitor)
GIB = 1 << 30
MIB = 1 << 20
MARKER = "RCH_TEST_ATTEMPT_DISK_BUDGET:"


class DiskMonitorTests(unittest.TestCase):
    def setUp(self):
        self.root = Path(tempfile.mkdtemp(prefix="rch-disk-test-"))
        self.target = self.root / "target"
        self.target.mkdir()
        self.registry = self.root / "registry"
        self.processes = []

    def tearDown(self):
        for process in self.processes:
            # The Popen child is still ours until reaped; its private session
            # cannot have been reused. Never signal a stale arbitrary PID.
            if process.poll() is None:
                if os.getpgid(process.pid) == process.pid:
                    os.killpg(process.pid, signal.SIGKILL)
                else:
                    process.kill()
            process.communicate(timeout=3)

    def spawn(self, payload, *, budget=8 * MIB, floor=MIB, inject="", mode="standalone", outputs=None, target=None, timeout_seconds=0, receipt_initial=None, probe_paths=None):
        number = len(self.processes)
        receipt = self.root / ("receipt-" + str(number))
        target = target or self.target
        outputs = outputs or [target]
        probes = probe_paths if probe_paths is not None else [target] + outputs
        plan = {"probe": [str(path) for path in probes],
                "output": [str(path) for path in outputs], "receipt": str(receipt),
                "timeout_seconds": timeout_seconds, "receipt_initialized": receipt_initial is not None}
        if receipt_initial is not None:
            receipt.write_text(receipt_initial, encoding="utf-8")
            receipt.chmod(0o600)
        driver = (
            "import importlib.util,sys,os,time,pathlib,signal\n"
            f"s=importlib.util.spec_from_file_location('m',{str(SOURCE)!r}); m=importlib.util.module_from_spec(s); s.loader.exec_module(m)\n"
            f"OriginalRegistry=m.Registry; m.Registry=lambda: OriginalRegistry({str(self.registry)!r})\n"
            + inject + "\n"
            + f"os._exit(m.main({[str(budget), str(floor), MARKER, str(target), json.dumps(plan), mode, sys.executable, '-c', payload]!r}))\n"
        )
        process = subprocess.Popen(
            [sys.executable, "-I", "-S", "-c", driver], stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, start_new_session=mode == "tracked",
        )
        self.processes.append(process)
        return process, receipt

    def wait_file(self, path, timeout=5):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if path.exists() and path.stat().st_size:
                return path.read_text()
            time.sleep(0.025)
        self.fail("expected file did not appear: " + str(path))

    def complete(self, process, timeout=8):
        stdout, stderr = process.communicate(timeout=timeout)
        return process.returncode, stdout.decode(errors="replace"), stderr.decode(errors="replace")

    def failure(self, receipt):
        for line in receipt.read_text().splitlines():
            if line.startswith(MARKER):
                return json.loads(line[len(MARKER):])
        self.fail("missing typed failure receipt: " + receipt.read_text())

    def synthetic_monitor(self, budget=40 * GIB, floor=10 * GIB):
        value = monitor.Monitor.__new__(monitor.Monitor)
        value.budget, value.floor, value.devices = budget, floor, {1}
        value.baseline, value.peak_output, value.peak_growth = 0, 0, 0
        value.floors, value.free = {1: floor}, {1: 33 * GIB}
        value.previous = (0, dict(value.free))
        return value

    def test_reported_21_gib_growth_stops_before_filesystem_floor(self):
        value = self.synthetic_monitor()
        value.observe_output(21 * GIB)
        with self.assertRaises(monitor.BudgetFailure) as caught:
            value.observe_free({1: 12 * GIB}, 10)
        self.assertEqual(caught.exception.reason, "free_floor")
        self.assertEqual(caught.exception.growth, 21 * GIB)
        self.assertGreater(caught.exception.free, value.floor)

    def test_small_build_with_same_33_gib_headroom_is_allowed(self):
        value = self.synthetic_monitor(budget=4 * GIB)
        value.observe_output(2 * GIB)
        value.observe_free({1: 31 * GIB}, 10)
        self.assertEqual(value.peak_growth, 2 * GIB)

    def test_flat_slot_allowance_cannot_admit_cold_test_budget(self):
        registry = monitor.Registry(str(self.registry))
        value = SimpleNamespace(boot=monitor.boot_identity(), group=os.getpgrp(), start="test",
                                budget=30 * GIB, floor=10 * GIB, devices={1}, sample=lambda: {1: 33 * GIB})
        with self.assertRaises(monitor.BudgetFailure) as caught:
            registry.admit(value)
        self.assertEqual(caught.exception.reason, "admission")
        value.budget = 4 * GIB
        free, floors = registry.admit(value)
        self.assertEqual((free, floors), ({1: 33 * GIB}, {1: 10 * GIB}))

    def test_reservation_retirement_requires_dead_group_or_new_boot(self):
        record = {"boot": "boot-a", "group": 42, "leader_start": "old"}
        self.assertTrue(monitor.reservation_alive(record, "boot-a", {42}))
        self.assertFalse(monitor.reservation_alive(record, "boot-a", set()))
        self.assertFalse(monitor.reservation_alive(record, "boot-b", {42}))
        # Leader absence/reuse deliberately does not appear in the decision:
        # living group members keep the entire reservation.

    def test_free_bytes_use_unprivileged_available_blocks(self):
        with patch.object(monitor.os, "fstatvfs", return_value=SimpleNamespace(f_bavail=7, f_bfree=99, f_frsize=4096)):
            self.assertEqual(list(monitor.filesystem_sample([str(self.target)]).values()), [7 * 4096])

    def test_telemetry_errors_and_filesystem_changes_fail_closed(self):
        with patch.object(monitor.os, "fstatvfs", side_effect=PermissionError("probe unavailable")):
            with self.assertRaises(PermissionError):
                monitor.filesystem_sample([str(self.target)])
        value = self.synthetic_monitor()
        with self.assertRaises(monitor.BudgetFailure):
            value.observe_free({2: 100 * GIB}, 1)

    def test_nested_roots_and_hardlinks_are_counted_once(self):
        nested = self.target / "nested"
        nested.mkdir()
        output = nested / "output"
        output.write_bytes(b"x" * 8192)
        os.link(output, self.target / "same-inode")
        self.assertEqual(monitor.measure_outputs([str(self.target)]),
                         monitor.measure_outputs([str(self.target), str(nested)]))

    def test_success_preserves_output_and_warm_total_highwater(self):
        (self.target / "warm-cache").write_bytes(b"w" * 3 * MIB)
        process, receipt = self.spawn(f"from pathlib import Path; Path({str(self.target / 'new')!r}).write_bytes(b'x'*4096); print('small-build-ok')", mode="tracked")
        status, stdout, stderr = self.complete(process)
        self.assertEqual(status, 0, stderr)
        self.assertIn("small-build-ok", stdout)
        usage = json.loads(receipt.read_text().split("_DISK_USAGE:", 1)[1])
        self.assertTrue(usage["complete"])
        self.assertEqual(usage["exit_code"], 0)
        self.assertGreaterEqual(usage["peak_output_bytes"], 3 * MIB + 4096)
        self.assertLess(usage["peak_growth_bytes"], MIB)

    def test_nonzero_foreground_exit_has_complete_final_measurement(self):
        process, receipt = self.spawn("print('compiler-error'); raise SystemExit(101)")
        status, stdout, stderr = self.complete(process)
        self.assertEqual(status, 101, stderr)
        self.assertIn("compiler-error", stdout)
        usage = json.loads(receipt.read_text().split("_DISK_USAGE:", 1)[1])
        self.assertTrue(usage["complete"])
        self.assertEqual(usage["exit_code"], 101)

    def check_terminal_sample(self, condition, reason):
        # Real execution and final output scanning, with a telemetry transition
        # AFTER the old completion path's last free-space observation. This is
        # synchronized by the observer/scan calls, not by a scheduling sleep.
        for mode in ("standalone", "tracked"):
            with self.subTest(mode=mode, condition=condition):
                witness = self.root / ("terminal-sample-" + mode)
                artifact = self.target / ("retained-" + mode)
                inject = f"""original_finish=m.finish_descendants
original_observe=m.Monitor.observe_free
original_scan=m.Monitor.scan
original_sample=m.Monitor.sample
def finish(value, heartbeat):
    original_finish(value, heartbeat)
    value.finalizing=True
def observe(value, samples, now):
    original_observe(value, samples, now)
    if getattr(value, 'finalizing', False):
        value.final_free_observed=True
def scan(value):
    total=original_scan(value)
    if getattr(value, 'final_free_observed', False):
        value.terminal_scan_done=True
    return total
def sample(value):
    samples=original_sample(value)
    if getattr(value, 'terminal_scan_done', False):
        pathlib.Path({str(witness)!r}).write_text('sampled after final scan')
        condition={condition!r}
        if condition == 'floor':
            return {{device: value.floor for device in samples}}
        if condition == 'error':
            raise OSError('terminal filesystem probe failed')
        if condition == 'identity':
            return {{max(samples) + 1: min(samples.values())}}
        if condition == 'timeout':
            time.sleep(5)
    return samples
m.finish_descendants=finish
m.Monitor.observe_free=observe
m.Monitor.scan=scan
m.Monitor.sample=sample"""
                payload = f"from pathlib import Path; Path({str(artifact)!r}).write_text('keep'); print('foreground-finished')"
                process, receipt = self.spawn(payload, inject=inject, mode=mode)
                status, stdout, stderr = self.complete(process)
                self.assertNotEqual(status, 0, stderr)
                self.assertIn("foreground-finished", stdout)
                failure = self.failure(receipt)
                self.assertEqual(failure["reason"], reason)
                self.assertTrue(failure["started"])
                usage = json.loads(receipt.read_text().split("_DISK_USAGE:", 1)[1])
                self.assertFalse(usage["complete"])
                self.assertIsNone(usage["exit_code"])
                self.assertTrue(witness.exists())
                self.assertEqual(artifact.read_text(), "keep")

    def test_completion_rechecks_floor_after_final_scan(self):
        self.check_terminal_sample("floor", "free_floor")

    def test_completion_refuses_failed_terminal_probe(self):
        self.check_terminal_sample("error", "monitor_unavailable")

    def test_completion_refuses_changed_terminal_filesystem(self):
        self.check_terminal_sample("identity", "monitor_unavailable")

    def test_completion_bounds_terminal_probe(self):
        self.check_terminal_sample("timeout", "monitor_unavailable")

    def test_complete_receipt_binds_original_status_before_guardian_ack(self):
        inject = """original_supervise=m.supervise
def killed_after_receipt(*args):
    original_supervise(*args)
    os.kill(os.getpid(), signal.SIGKILL)
m.supervise=killed_after_receipt"""
        process, receipt = self.spawn("print('completed-zero')", inject=inject)
        status, stdout, _ = self.complete(process)
        self.assertNotEqual(status, 0)
        self.assertIn("completed-zero", stdout)
        usage = json.loads(receipt.read_text().split("_DISK_USAGE:", 1)[1])
        self.assertTrue(usage["complete"])
        # Callers must reject the surviving success receipt paired with the
        # guardian's killed status, never classify it as a retryable job signal.
        self.assertEqual(usage["exit_code"], 0)

    def test_zero_configured_floor_is_valid_and_persists_in_ledger(self):
        process, _ = self.spawn("print('zero-floor-ok')", floor=0)
        status, stdout, stderr = self.complete(process)
        self.assertEqual(status, 0, stderr)
        self.assertIn("zero-floor-ok", stdout)
        entries = monitor.Registry(str(self.registry)).read()
        self.assertEqual([entry["floor"] for entry in entries], [0])

    def test_exact_outer_receipt_initialization_is_consumed(self):
        process, receipt = self.spawn("print('claimed-attempt-ok')", receipt_initial=MARKER + "\n")
        status, stdout, stderr = self.complete(process)
        self.assertEqual(status, 0, stderr)
        self.assertIn("claimed-attempt-ok", stdout)
        self.assertIn("_DISK_USAGE:", receipt.read_text())

    def test_existing_receipt_cannot_be_reused_as_a_new_attempt(self):
        stale = MARKER + '{"started":true,"reason":"growth"}\n'
        process, receipt = self.spawn("print('must-not-start')", receipt_initial=stale)
        status, stdout, stderr = self.complete(process)
        self.assertEqual(status, monitor.EXIT_BUDGET)
        self.assertNotIn("must-not-start", stdout)
        self.assertEqual(receipt.read_text(), stale)
        self.assertIn('"started":false', stderr)
        self.assertIn("initialization does not match", stderr)

    def test_oversized_output_is_killed_and_artifacts_are_retained(self):
        output = self.target / "large"
        process, receipt = self.spawn(f"from pathlib import Path; import time; Path({str(output)!r}).write_bytes(b'x'*{4*MIB}); time.sleep(20)", budget=2 * MIB)
        status, _, stderr = self.complete(process)
        self.assertNotEqual(status, 0, stderr)
        failure = self.failure(receipt)
        self.assertEqual(failure["reason"], "growth")
        self.assertTrue(failure["started"])
        self.assertGreaterEqual(failure["growth_bytes"], 4 * MIB)
        self.assertEqual(output.stat().st_size, 4 * MIB)

    def test_managed_temporary_output_outside_target_is_charged(self):
        temporary = self.root / "managed-tmp"
        temporary.mkdir()
        output = temporary / "linker-output"
        process, receipt = self.spawn(f"from pathlib import Path; import time; Path({str(output)!r}).write_bytes(b'x'*{4*MIB}); time.sleep(20)", budget=2 * MIB, outputs=[self.target, temporary])
        self.complete(process)
        self.assertEqual(self.failure(receipt)["reason"], "growth")
        self.assertTrue(output.exists())

    def secondary_volume(self):
        shared = Path("/dev/shm")
        if not shared.is_dir() or not os.access(shared, os.W_OK):
            self.skipTest("a writable second filesystem is required")
        if shared.stat().st_dev == self.target.stat().st_dev:
            self.skipTest("fixture directories must be on distinct filesystems")
        return Path(tempfile.mkdtemp(prefix="rch-disk-test-", dir=str(shared)))

    def secondary_capacity(self, secondary, free):
        return f"""original_sample=m.filesystem_sample
def sample(paths):
    result=original_sample(paths)
    device=os.stat({str(secondary)!r}).st_dev
    if device in result:
        result[device]={free}
    return result
m.filesystem_sample=sample"""

    def test_unlisted_output_volume_refuses_before_workload_when_full(self):
        secondary = self.secondary_volume()
        process, receipt = self.spawn(
            "print('must-not-start')", outputs=[self.target, secondary],
            probe_paths=[self.target], inject=self.secondary_capacity(secondary, MIB),
        )
        status, stdout, _ = self.complete(process)
        self.assertEqual(status, monitor.EXIT_BUDGET)
        self.assertNotIn("must-not-start", stdout)
        failure = self.failure(receipt)
        self.assertEqual(failure["reason"], "admission")
        self.assertFalse(failure["started"])

    def test_unlisted_healthy_output_volume_is_reserved_and_allowed(self):
        secondary = self.secondary_volume()
        output = secondary / "output"
        process, receipt = self.spawn(
            f"from pathlib import Path; Path({str(output)!r}).write_bytes(b'x'*4096)",
            outputs=[self.target, secondary, secondary], probe_paths=[self.target],
            inject=self.secondary_capacity(secondary, 24 * MIB),
        )
        status, _, stderr = self.complete(process)
        self.assertEqual(status, 0, stderr)
        self.assertEqual(output.stat().st_size, 4096)
        entries = monitor.Registry(str(self.registry)).read()
        self.assertEqual(len(entries), 1)
        self.assertEqual(entries[0]["devices"],
                         sorted([self.target.stat().st_dev, secondary.stat().st_dev]))
        self.assertTrue(json.loads(receipt.read_text().split("_DISK_USAGE:", 1)[1])["complete"])

    def test_unlisted_output_volume_floor_stops_running_workload(self):
        secondary = self.secondary_volume()
        ready = secondary / "writer"
        free = f"({MIB} if pathlib.Path({str(ready)!r}).exists() else {24*MIB})"
        payload = f"from pathlib import Path; import os,time; Path({str(ready)!r}).write_text(str(os.getpid())); time.sleep(2)"
        process, receipt = self.spawn(
            payload, outputs=[self.target, secondary], probe_paths=[self.target],
            inject=self.secondary_capacity(secondary, free),
        )
        status, _, _ = self.complete(process)
        self.assertNotEqual(status, 0)
        failure = self.failure(receipt)
        self.assertEqual(failure["reason"], "free_floor")
        self.assertTrue(failure["started"])
        record = monitor.process_snapshot().get(int(ready.read_text()))
        self.assertTrue(record is None or record["state"] in ("Z", "X"))

    def test_capacity_and_device_are_bound_to_the_same_open_directory(self):
        secondary = self.secondary_volume()
        link = self.root / "probe-link"
        link.symlink_to(self.target, target_is_directory=True)
        original_stat, original_open = os.stat, os.open
        device = self.target.stat().st_dev
        switched = False

        def switch():
            nonlocal switched
            if not switched:
                link.rename(self.root / "original-probe-link")
                link.symlink_to(secondary, target_is_directory=True)
                switched = True

        def changing_stat(path, *args, **kwargs):
            value = original_stat(path, *args, **kwargs)
            if path == str(link):
                switch()
            return value

        def changing_open(path, *args, **kwargs):
            descriptor = original_open(path, *args, **kwargs)
            if path == str(link):
                switch()
            return descriptor

        def capacity(dev):
            return SimpleNamespace(f_bavail=7 if dev == device else 99, f_frsize=4096)

        with patch.object(monitor.os, "stat", side_effect=changing_stat), \
             patch.object(monitor.os, "open", side_effect=changing_open), \
             patch.object(monitor.os, "statvfs", side_effect=lambda path: capacity(original_stat(path).st_dev)), \
             patch.object(monitor.os, "fstatvfs", side_effect=lambda fd: capacity(os.fstat(fd).st_dev)):
            samples = monitor.filesystem_sample([str(link)])
        self.assertTrue(switched, "the fixture must actually replace the path")
        self.assertEqual(samples, {device: 7 * 4096})

    def test_output_replacement_during_admission_probe_never_starts_workload(self):
        inject = f"""original_sample=m.filesystem_sample
samples=0
def sample(paths):
    global samples
    result=original_sample(paths)
    samples+=1
    if samples == 2:
        os.rename({str(self.target)!r}, {str(self.root / 'original-target')!r})
        os.mkdir({str(self.target)!r})
    return result
m.filesystem_sample=sample"""
        process, receipt = self.spawn("print('must-not-start')", inject=inject)
        status, stdout, _ = self.complete(process)
        self.assertEqual(status, monitor.EXIT_BUDGET)
        self.assertNotIn("must-not-start", stdout)
        failure = self.failure(receipt)
        self.assertEqual(failure["reason"], "monitor_unavailable")
        self.assertFalse(failure["started"])
        self.assertEqual(monitor.Registry(str(self.registry)).read(), [])

    def test_corrupt_ledger_refuses_before_workload(self):
        registry = monitor.Registry(str(self.registry))
        (Path(registry.root) / "ledger.json").write_text("corrupt", encoding="utf-8")
        os.chmod(Path(registry.root) / "ledger.json", 0o600)
        output = self.target / "started"
        process, receipt = self.spawn(f"from pathlib import Path; Path({str(output)!r}).write_text('started')")
        status, _, _ = self.complete(process)
        self.assertEqual(status, monitor.EXIT_BUDGET)
        self.assertFalse(self.failure(receipt)["started"])
        self.assertFalse(output.exists())

    def test_concurrent_reservations_are_retained_until_group_stops_then_retry(self):
        inject = f"m.filesystem_sample=lambda paths: {{os.stat(paths[0]).st_dev: {12*MIB}}}"
        ready = self.target / "ready"
        payload = f"from pathlib import Path; import time; Path({str(ready)!r}).write_text('ready'); time.sleep(20)"
        first, _ = self.spawn(payload, budget=7 * MIB, inject=inject)
        self.wait_file(ready)
        second, receipt = self.spawn("print('must-not-start')", budget=7 * MIB, inject=inject)
        status, stdout, _ = self.complete(second)
        self.assertEqual(status, monitor.EXIT_BUDGET)
        self.assertNotIn("must-not-start", stdout)
        self.assertFalse(self.failure(receipt)["started"])
        os.kill(first.pid, signal.SIGTERM)
        self.complete(first)
        third, _ = self.spawn("print('retry-ok')", budget=7 * MIB, inject=inject)
        status, stdout, stderr = self.complete(third)
        self.assertEqual(status, 0, stderr)
        self.assertIn("retry-ok", stdout)

    def test_free_floor_crossing_kills_live_writer(self):
        ready = self.target / "writer"
        inject = f"m.filesystem_sample=lambda paths: {{os.stat(paths[0]).st_dev: ({MIB} if pathlib.Path({str(ready)!r}).exists() else {20*MIB})}}"
        process, receipt = self.spawn(f"from pathlib import Path; import os,time; Path({str(ready)!r}).write_text(str(os.getpid())); time.sleep(20)", inject=inject)
        self.complete(process)
        self.assertEqual(self.failure(receipt)["reason"], "free_floor")
        record = monitor.process_snapshot().get(int(ready.read_text()))
        self.assertTrue(record is None or record["state"] in ("Z", "X"))

    def test_spawn_interruption_is_started_and_kills_unreturned_child(self):
        ready = self.target / "writer"
        inject = f"""original_popen=m.subprocess.Popen
def interrupted_spawn(*args, **kwargs):
    child=original_popen(*args, **kwargs)
    deadline=time.monotonic()+5
    while not pathlib.Path({str(ready)!r}).exists():
        if child.poll() is not None or time.monotonic() >= deadline:
            raise RuntimeError('spawn fixture did not publish its writer identity')
        time.sleep(0.01)
    raise m.BudgetFailure('interrupted', detail='signal after OS spawn')
m.subprocess.Popen=interrupted_spawn"""
        process, receipt = self.spawn(f"from pathlib import Path; import os,time; Path({str(ready)!r}).write_text(str(os.getpid())); time.sleep(20)", inject=inject)
        self.complete(process)
        self.assertTrue(self.failure(receipt)["started"])
        self.assertEqual(self.failure(receipt)["reason"], "interrupted")
        pid = int(ready.read_text())
        record = monitor.process_snapshot().get(pid)
        self.assertTrue(record is None or record["state"] in ("Z", "X"))

    def test_symlink_output_root_is_refused_before_workload(self):
        link = self.root / "linked-target"
        link.symlink_to(self.target, target_is_directory=True)
        process, receipt = self.spawn("print('must-not-start')", target=link)
        status, stdout, _ = self.complete(process)
        self.assertEqual(status, monitor.EXIT_BUDGET)
        self.assertFalse(self.failure(receipt)["started"])
        self.assertNotIn("must-not-start", stdout)

    def test_output_root_replacement_stops_running_build(self):
        process, receipt = self.spawn(f"import os,time; os.rename({str(self.target)!r},{str(self.root / 'old-target')!r}); os.mkdir({str(self.target)!r}); time.sleep(20)")
        self.complete(process)
        self.assertEqual(self.failure(receipt)["reason"], "monitor_unavailable")
        self.assertTrue(self.failure(receipt)["started"])

    def test_blocked_statvfs_has_deadline(self):
        ready = self.target / "ready"
        inject = f"""original_sample=m.filesystem_sample
def blocked_sample(paths):
    if pathlib.Path({str(ready)!r}).exists():
        time.sleep(20)
    return original_sample(paths)
m.filesystem_sample=blocked_sample"""
        process, receipt = self.spawn(f"from pathlib import Path; import time; Path({str(ready)!r}).write_text('ready'); time.sleep(20)", inject=inject)
        self.complete(process)
        self.assertEqual(self.failure(receipt)["reason"], "monitor_unavailable")
        self.assertIn("telemetry deadline", self.failure(receipt)["detail"])

    def test_backpressured_stderr_preserves_durable_budget_reason(self):
        output = self.target / "large"
        payload = f"""import os,time
from pathlib import Path
if os.fork() == 0:
    time.sleep(0.3)
    Path({str(output)!r}).write_bytes(b'x'*{4*MIB})
    time.sleep(20)
else:
    os.write(2,b'n'*{2*MIB})
    time.sleep(20)
"""
        process, receipt = self.spawn(payload, budget=2 * MIB)
        self.wait_file(receipt)
        self.assertEqual(self.failure(receipt)["reason"], "growth")
        self.complete(process)

    def test_guardian_kills_writers_when_supervisor_is_killed(self):
        ready = self.target / "writer"
        process, receipt = self.spawn(f"from pathlib import Path; import os,signal,time; Path({str(ready)!r}).write_text(str(os.getpid())); os.kill(os.getppid(),signal.SIGKILL); time.sleep(20)")
        status, _, _ = self.complete(process)
        self.assertNotEqual(status, 0)
        self.assertEqual(receipt.read_text(), "")
        record = monitor.process_snapshot().get(int(ready.read_text()))
        self.assertTrue(record is None or record["state"] in ("Z", "X"))

    def test_lost_group_leader_cannot_strand_workload(self):
        ready = self.target / "writer"
        process, receipt = self.spawn(f"from pathlib import Path; import os,signal,time; Path({str(ready)!r}).write_text(str(os.getpid())); os.kill(os.getpgrp(),signal.SIGKILL); time.sleep(20)", mode="tracked")
        self.complete(process)
        record = monitor.process_snapshot().get(int(ready.read_text()))
        self.assertTrue(record is None or record["state"] in ("Z", "X"))

    def test_background_writer_is_stopped_after_foreground_success(self):
        ready = self.target / "writer"
        payload = f"""import os,time
from pathlib import Path
if os.fork() == 0:
    Path({str(ready)!r}).write_text(str(os.getpid()))
    time.sleep(20)
else:
    time.sleep(0.15)
    print('foreground-ok')
"""
        process, _ = self.spawn(payload)
        status, stdout, stderr = self.complete(process)
        self.assertEqual(status, 0, stderr)
        self.assertIn("foreground-ok", stdout)
        record = monitor.process_snapshot().get(int(ready.read_text()))
        self.assertTrue(record is None or record["state"] in ("Z", "X"))

    def test_execution_deadline_uses_existing_marker_and_stops_group(self):
        ready = self.target / "writer"
        process, receipt = self.spawn(f"from pathlib import Path; import os,time; Path({str(ready)!r}).write_text(str(os.getpid())); time.sleep(20)", timeout_seconds=1)
        self.complete(process)
        lines = receipt.read_text().splitlines()
        self.assertIn(MARKER.removesuffix("_DISK_BUDGET:"), lines)
        self.assertFalse(any(line.startswith(MARKER) for line in lines))
        record = monitor.process_snapshot().get(int(ready.read_text()))
        self.assertTrue(record is None or record["state"] in ("Z", "X"))

    def test_guardian_stops_writers_when_failure_receipt_write_hangs(self):
        inject = "m.persist_receipts=lambda *args: time.sleep(20)"
        ready = self.target / "writer"
        output = self.target / "large"
        process, receipt = self.spawn(f"from pathlib import Path; import os,time; Path({str(ready)!r}).write_text(str(os.getpid())); Path({str(output)!r}).write_bytes(b'x'*{4*MIB}); time.sleep(20)", budget=2 * MIB, inject=inject)
        self.complete(process)
        self.assertEqual(receipt.read_text(), "")
        record = monitor.process_snapshot().get(int(ready.read_text()))
        self.assertTrue(record is None or record["state"] in ("Z", "X"))

    def test_receipt_serializer_exception_cannot_skip_group_cleanup(self):
        inject = """def broken_receipt(*args):
    raise RuntimeError('receipt serialization failed')
m.receipts_for_failure=broken_receipt"""
        ready = self.target / "writer"
        output = self.target / "large"
        process, receipt = self.spawn(f"from pathlib import Path; import os,time; Path({str(ready)!r}).write_text(str(os.getpid())); Path({str(output)!r}).write_bytes(b'x'*{4*MIB}); time.sleep(20)", budget=2 * MIB, inject=inject)
        self.complete(process)
        self.assertEqual(receipt.read_text(), "")
        record = monitor.process_snapshot().get(int(ready.read_text()))
        self.assertTrue(record is None or record["state"] in ("Z", "X"))

    def test_recycled_numeric_pid_never_receives_cleanup_signal(self):
        if not hasattr(os, "pidfd_open"):
            self.skipTest("pidfd requires Linux with Python 3.9 or later")
        record = {"pid": 123, "group": 456, "state": "S", "start": "original"}
        value = SimpleNamespace(group=456, controls=set(), check_owner=lambda: None)
        with patch.object(monitor, "process_snapshot", side_effect=[{123: record}, {}]), \
             patch.object(monitor.os, "pidfd_open", return_value=789) as opened, \
             patch.object(monitor.os, "getpgid", return_value=456), \
             patch.object(monitor.signal, "pidfd_send_signal") as sent, \
             patch.object(monitor.os, "close"), \
             patch.object(monitor.os, "kill") as numeric_kill:
            monitor.finish_descendants(value, lambda: None)
        opened.assert_called_once_with(123)
        sent.assert_called_once_with(789, signal.SIGKILL)
        numeric_kill.assert_not_called()


if __name__ == "__main__":
    unittest.main()
