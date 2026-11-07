"""Deterministic GiB scenarios plus small real-process disk guard regressions.

Run: PYTHONDONTWRITEBYTECODE=1 python3 rch-common/tests/build_disk_monitor_test.py
Fixtures are retained for inspection; these tests never fill a filesystem.
"""

import gc
import importlib.util
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import time
import tracemalloc
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


class TimingScaleTests(unittest.TestCase):
    def test_transported_scale_scales_caps_without_changing_poll_cadence(self):
        driver = (
            "import importlib.util,json\n"
            f"s=importlib.util.spec_from_file_location('m',{str(SOURCE)!r})\n"
            "m=importlib.util.module_from_spec(s); s.loader.exec_module(m)\n"
            "print(json.dumps([m.TIMING_SCALE,m.FREE_SAMPLE_DEADLINE,"
            "m.SCAN_DEADLINE,m.HEARTBEAT_DEADLINE,m.RESERVATION_LOCK_DEADLINE,"
            "m.ADMISSION_DEADLINE,m.FINALIZATION_DEADLINE,m.BOOTSTRAP_ALLOWANCE,"
            "m.POLL_SECONDS,m.SCAN_INTERVAL]))\n"
        )
        for value, scale in ((None, 1), ("1", 1), ("2", 2), ("1.25", 1.25), ("10", 10)):
            with self.subTest(value=value):
                env = dict(os.environ)
                env.pop("RCH_TIMING_SCALE", None)
                if value is not None:
                    env["RCH_TIMING_SCALE"] = value
                result = subprocess.run([sys.executable, "-I", "-S", "-c", driver],
                                        capture_output=True, env=env, timeout=5)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(json.loads(result.stdout),
                                 [scale, scale, 30 * scale, 3 * scale, 2 * scale,
                                  5 * scale, 2 * scale, 10 * scale, 0.25, 2])

    def test_invalid_and_nonfinite_policy_is_rejected(self):
        for value in ("", "0", "-1", "0.999", "10.01", "nan", "NaN", "inf",
                      "-inf", "1e9999", "1e-9999", " 2", "2 ", "1_0",
                      "1;printf injected", "$(printf injected)", "2" * 129):
            with self.subTest(value=value), self.assertRaises(ValueError):
                monitor.parse_timing_scale(value)


class DiskMonitorTests(unittest.TestCase):
    @unittest.skipUnless(sys.platform.startswith("linux"), "Linux procfs exit race")
    def test_census_tolerates_real_procfs_exit_but_preserves_live_process(self):
        child = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(30)"])
        self.processes.append(child)
        original = monitor.linux_process
        with open(f"/proc/{child.pid}/stat", encoding="utf-8") as stale:
            child.terminate()
            child.wait(timeout=3)
            # A retained procfs descriptor reproduces ESRCH from the kernel.
            with self.assertRaises(ProcessLookupError):
                stale.read()
            injected = False
            def read_record(path):
                nonlocal injected
                if not injected and path != f"/proc/{os.getpid()}/stat":
                    injected = True
                    stale.read()
                return original(path)
            with patch.object(monitor, "linux_process", side_effect=read_record):
                snapshot = monitor.process_snapshot()
            self.assertTrue(injected)
            self.assertIn(os.getpid(), snapshot)
            self.assertNotIn(child.pid, snapshot)

    @unittest.skipUnless(sys.platform.startswith("linux"), "Linux owner exit race")
    def test_owner_esrch_interrupts_and_permission_errors_remain_fail_closed(self):
        value = monitor.Monitor.__new__(monitor.Monitor)
        value.parent, value.group, value.start = os.getppid(), os.getpid(), "old"
        with patch.object(monitor, "linux_process", side_effect=ProcessLookupError(3, "gone")):
            with self.assertRaises(monitor.BudgetFailure) as failure:
                value.check_owner()
            self.assertEqual(failure.exception.reason, "interrupted")
        with patch.object(monitor, "linux_process", side_effect=PermissionError(13, "denied")):
            with self.assertRaises(PermissionError):
                monitor.process_snapshot()

    @unittest.skipUnless(sys.platform == "darwin", "Darwin native identity")
    def test_darwin_owner_rejects_live_nonleader(self):
        child = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(30)"])
        self.processes.append(child)
        self.assertNotEqual(os.getpgid(child.pid), child.pid)
        with self.assertRaises(monitor.BudgetFailure):
            monitor.darwin_leader_start(child.pid, monitor.boot_identity())

    @unittest.skipUnless(sys.platform == "darwin", "Darwin native identity")
    def test_darwin_owner_native_identity_survives_census_failure(self):
        child = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(30)"], start_new_session=True)
        self.processes.append(child)
        value = monitor.Monitor.__new__(monitor.Monitor)
        value.parent, value.group, value.boot = os.getppid(), child.pid, monitor.boot_identity()
        value.start = monitor.darwin_leader_start(value.group, value.boot)
        with patch.object(monitor, "process_snapshot", side_effect=AssertionError("unrelated census")):
            value.check_owner()
            value.start = str(int(value.start) + 1)
            with self.assertRaises(monitor.BudgetFailure):
                value.check_owner()
            value.start = monitor.darwin_leader_start(value.group, value.boot)
            value.boot = "00000000-0000-0000-0000-000000000000"
            with self.assertRaises(monitor.BudgetFailure):
                value.check_owner()
            value.boot = monitor.boot_identity()
            child.terminate()
            child.wait(timeout=3)
            with self.assertRaises(subprocess.CalledProcessError):
                value.check_owner()

    @unittest.skipUnless(sys.platform == "darwin", "Darwin process census")
    def test_darwin_census_omits_reaped_probe_but_keeps_live_child(self):
        child = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(30)"])
        self.processes.append(child)
        snapshot = monitor.process_snapshot()
        self.assertIn(child.pid, snapshot)
        direct_children = {record["pid"] for record in snapshot.values()
                           if record["parent"] == os.getpid()}
        self.assertEqual(direct_children, {child.pid})

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

    def spawn(self, payload, *, budget=8 * MIB, floor=MIB, inject="", mode="standalone", outputs=None, target=None, timeout_seconds=0, receipt_initial=None, probe_paths=None, warm_policy=None, require_incremental_tracking=False, timing_scale=None):
        number = len(self.processes)
        receipt = self.root / ("receipt-" + str(number))
        target = target or self.target
        outputs = outputs or [target]
        probes = probe_paths if probe_paths is not None else [target] + outputs
        plan = {"probe": [str(path) for path in probes],
                "output": [str(path) for path in outputs], "receipt": str(receipt),
                "timeout_seconds": timeout_seconds, "receipt_initialized": receipt_initial is not None,
                "warm_policy": warm_policy, "require_incremental_tracking": require_incremental_tracking}
        if receipt_initial is not None:
            receipt.write_text(receipt_initial, encoding="utf-8")
            receipt.chmod(0o600)
        driver = (
            "import importlib.util,sys,os,time,pathlib,signal\n"
            "sys.dont_write_bytecode=True\n"
            f"s=importlib.util.spec_from_file_location('m',{str(SOURCE)!r}); m=importlib.util.module_from_spec(s); s.loader.exec_module(m)\n"
            f"OriginalRegistry=m.Registry; m.Registry=lambda: OriginalRegistry({str(self.registry)!r})\n"
            + inject + "\n"
            + f"os._exit(m.main({[str(budget), str(floor), MARKER, str(target), json.dumps(plan), mode, sys.executable, '-c', payload]!r}))\n"
        )
        env = dict(os.environ)
        env.pop("RCH_TIMING_SCALE", None)
        if timing_scale is not None:
            env["RCH_TIMING_SCALE"] = timing_scale
        process = subprocess.Popen(
            [sys.executable, "-I", "-S", "-c", driver], stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, start_new_session=mode == "tracked", env=env,
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
        value.baseline_records, value.incremental_reliable = None, False
        value.pool_identity, value.peak_added, value.unproven_baseline = [1] * 32, 0, 0
        value.strict_tracking = False
        value.baseline_pool = value.final_pool = value.admitted_pool = None
        value.floors, value.free = {1: floor}, {1: 33 * GIB}
        value.free_start = dict(value.free)
        value.free_min = dict(value.free)
        value.previous = (0, dict(value.free))
        return value

    def measured_monitor(self, budget=8 * MIB, outputs=None):
        value = self.synthetic_monitor(budget=budget, floor=MIB)
        outputs = [str(path) for path in outputs or [self.target]]
        initial = monitor.measure_outputs(outputs, str(self.target))
        value.baseline = value.peak_output = initial.total
        value.baseline_records = initial.records
        value.baseline_pool = value.final_pool = value.pool_observation(initial)
        value.incremental_reliable = initial.records is not None and value.baseline_pool is not None
        return value

    def measured_policy(self, value):
        return {"cold_growth_bytes": value.budget * 2,
                "pools": [value.baseline_pool] + [None] * 7}

    def cargo_cache_roots(self, additional_home=None):
        base = self.root / "worker cache base"
        base.mkdir(exist_ok=True)
        plan = {"name": "rch-cargo-cache-worker", "additional_home": additional_home,
                "verified": True}
        with patch.dict(os.environ, {"RCH_CH_BASE": str(base)}):
            roots, aliases = monitor.prepare_cargo_cache_roots(plan)
        return base / plan["name"], roots, aliases

    def test_cargo_cache_growth_is_charged_when_cleanup_masks_total_growth(self):
        retained = self.target / "retained"
        retained.write_bytes(os.urandom(4 * MIB))
        cache, cache_roots, _ = self.cargo_cache_roots()
        roots = [str(self.target)] + cache_roots
        value = self.measured_monitor(budget=MIB, outputs=roots)
        value.require_warm_pool(self.measured_policy(value))
        retained.write_bytes(b"")
        (cache / "registry" / "download").write_bytes(os.urandom(2 * MIB))
        scan = monitor.measure_outputs(roots, str(self.target), value.baseline_records)
        self.assertLess(scan.total, value.baseline)
        with self.assertRaises(monitor.BudgetFailure) as caught:
            value.observe_output(scan)
        self.assertEqual(caught.exception.reason, "growth")
        self.assertGreaterEqual(value.peak_added, 2 * MIB)
        self.assertGreater(value.peak_growth, value.budget)

    def test_cargo_cache_retained_bytes_never_borrow_target_pool_credit(self):
        (self.target / "retained").write_bytes(os.urandom(4 * MIB))
        cache, cache_roots, _ = self.cargo_cache_roots()
        (cache / "registry" / "retained").write_bytes(os.urandom(5 * MIB))
        value = self.measured_monitor(budget=4 * MIB, outputs=[str(self.target)] + cache_roots)
        with self.assertRaises(monitor.BudgetFailure) as caught:
            value.require_warm_pool(self.measured_policy(value))
        self.assertEqual(caught.exception.reason, "cold_required")
        self.assertEqual(caught.exception.growth, 0)
        self.assertIsNone(value.admitted_pool)
        self.assertGreaterEqual(value.baseline - value.baseline_pool["retained_bytes"], 5 * MIB)

    def test_cargo_cache_cold_growth_and_complete_footprint_include_cache(self):
        (self.target / "retained").write_bytes(os.urandom(MIB))
        cache, cache_roots, _ = self.cargo_cache_roots()
        (cache / "registry" / "retained").write_bytes(os.urandom(5 * MIB))
        roots = [str(self.target)] + cache_roots
        value = self.measured_monitor(budget=4 * MIB, outputs=roots)
        (cache / "git" / "new-pack").write_bytes(os.urandom(MIB))
        value.observe_output(monitor.measure_outputs(roots, str(self.target), value.baseline_records))
        self.assertGreaterEqual(value.peak_added, MIB)
        self.assertLess(value.peak_growth, 2 * MIB)
        self.assertGreaterEqual(value.peak_output, 7 * MIB)

    def test_cargo_cache_warm_small_download_retains_target_credit_only(self):
        (self.target / "retained").write_bytes(os.urandom(4 * MIB))
        cache, cache_roots, _ = self.cargo_cache_roots()
        (cache / "registry" / "retained").write_bytes(os.urandom(MIB))
        roots = [str(self.target)] + cache_roots
        value = self.measured_monitor(budget=4 * MIB, outputs=roots)
        value.require_warm_pool(self.measured_policy(value))
        (cache / "registry" / "download").write_bytes(os.urandom(MIB))
        value.observe_output(monitor.measure_outputs(roots, str(self.target), value.baseline_records))
        self.assertGreaterEqual(value.unproven_baseline, MIB)
        self.assertGreaterEqual(value.peak_growth, 2 * MIB)
        self.assertLess(value.peak_growth, 3 * MIB)
        self.assertIsNotNone(value.admitted_pool)

    def cargo_cache_monitor(self, budget):
        base = self.root / "worker cache base"
        plan = {"name": "rch-cargo-cache-worker", "additional_home": None, "verified": True}
        with patch.dict(os.environ, {"RCH_CH_BASE": str(base)}):
            return monitor.Monitor(budget, MIB, str(self.target), [str(self.target)], cargo_cache=plan)

    def test_cargo_cache_beyond_the_walk_bound_is_protected_but_not_walked(self):
        (self.target / "retained").write_bytes(os.urandom(4 * MIB))
        cache, roots, _ = self.cargo_cache_roots()
        for index in range(6):
            (cache / "registry" / str(index)).write_bytes(os.urandom(MIB))
        with patch.object(monitor, "MAX_WALKED_CACHE_ENTRIES", 5):
            value = self.cargo_cache_monitor(4 * MIB)
        self.assertEqual(value.outputs, [str(self.target)])
        self.assertLessEqual(set(roots), set(value.paths))
        self.assertLess(value.baseline, 5 * MIB)
        # Walked, these 6 MiB would force cold readmission of a 4 MiB budget.
        value.require_warm_pool(self.measured_policy(value))
        self.assertIsNotNone(value.admitted_pool)

    def test_cargo_cache_within_the_walk_bound_is_charged_to_the_build(self):
        (self.target / "retained").write_bytes(os.urandom(4 * MIB))
        cache, roots, _ = self.cargo_cache_roots()
        (cache / "registry" / "retained").write_bytes(os.urandom(5 * MIB))
        value = self.cargo_cache_monitor(4 * MIB)
        self.assertLessEqual(set(roots), set(value.outputs))
        self.assertGreaterEqual(value.baseline, 5 * MIB)
        with self.assertRaises(monitor.BudgetFailure) as caught:
            value.require_warm_pool(self.measured_policy(value))
        self.assertEqual(caught.exception.reason, "cold_required")

    def test_cargo_cache_walk_bound_counts_entries_under_nested_roots_once(self):
        cache, roots, _ = self.cargo_cache_roots()
        for index in range(3):
            (cache / "registry" / str(index)).write_bytes(b"x")
        # registry, git, and three files, although three roots overlap.
        with patch.object(monitor, "MAX_WALKED_CACHE_ENTRIES", 5):
            self.assertTrue(monitor.cache_walk_is_bounded(roots))
        with patch.object(monitor, "MAX_WALKED_CACHE_ENTRIES", 4):
            self.assertFalse(monitor.cache_walk_is_bounded(roots))

    def test_cargo_cache_explicit_home_and_registry_git_redirects_are_bound(self):
        base = self.root / "worker cache base"
        cache = base / "rch-cargo-cache-worker"
        cache.mkdir(parents=True)
        registry, git, explicit = (self.root / name for name in ("registry-store", "git-store", "explicit-home"))
        registry.mkdir()
        git.mkdir()
        (cache / "registry").symlink_to(registry)
        (cache / "git").symlink_to(git)
        _, roots, aliases = self.cargo_cache_roots(str(explicit))
        self.assertIn(str(registry), roots)
        self.assertIn(str(git), roots)
        self.assertIn(str(explicit), roots)
        self.assertEqual(aliases[str(cache / "registry")], str(registry))
        monitor.verify_cargo_cache_bindings(aliases)
        (cache / "registry").rename(cache / "registry-retained-link")
        (cache / "registry").symlink_to(git)
        with self.assertRaises(monitor.BudgetFailure) as caught:
            monitor.verify_cargo_cache_bindings(aliases)
        self.assertEqual(caught.exception.reason, "monitor_unavailable")

    def test_cargo_cache_dangling_known_redirect_prepares_only_one_directory(self):
        base = self.root / "worker cache base"
        cache = base / "rch-cargo-cache-worker"
        cache.mkdir(parents=True)
        registry = self.root / "new-registry"
        (cache / "registry").symlink_to(registry)
        _, roots, _ = self.cargo_cache_roots()
        self.assertTrue(registry.is_dir())
        self.assertIn(str(registry), roots)
        with self.assertRaises(monitor.BudgetFailure) as caught:
            self.cargo_cache_roots(str(self.root / "absent-parent" / "home"))
        self.assertIn("parent must already exist", caught.exception.detail)
        self.assertFalse((self.root / "absent-parent").exists())

    def test_cargo_cache_unknown_scope_and_client_base_fail_closed(self):
        plan = {"name": "rch-cargo-cache-worker", "additional_home": None, "verified": False}
        with self.assertRaises(monitor.BudgetFailure) as caught:
            monitor.validate_cargo_cache_plan(plan, True)
        self.assertIn("literal absolute CARGO_HOME", caught.exception.detail)
        with self.assertRaises(monitor.BudgetFailure):
            monitor.validate_cargo_cache_plan(None, True)
        plan["verified"] = True
        for base in ("${TMPDIR}", "relative-client-base", str(self.root / "absent")):
            with self.subTest(base=base), patch.dict(os.environ, {"RCH_CH_BASE": base}):
                with self.assertRaises(monitor.BudgetFailure):
                    monitor.prepare_cargo_cache_roots(plan)
        for name in ("../outside", "rch-cargo-cache-a/b", "rch-cargo-cache-$(id)"):
            with self.subTest(name=name), self.assertRaises(monitor.BudgetFailure):
                monitor.validate_cargo_cache_plan({**plan, "name": name})

    @unittest.skipUnless(os.path.isdir("/dev/shm"), "requires an available second filesystem")
    def test_cargo_cache_distinct_filesystem_is_sampled_and_floor_protected(self):
        external = Path(tempfile.mkdtemp(prefix="rch-cargo-cache-volume-", dir="/dev/shm"))
        if external.stat().st_dev == self.target.stat().st_dev:
            self.skipTest("/dev/shm is not a distinct filesystem")
        _, cache_roots, _ = self.cargo_cache_roots(str(external))
        roots = [str(self.target)] + cache_roots
        samples = monitor.filesystem_sample(roots)
        device = external.stat().st_dev
        self.assertIn(device, samples)
        value = self.measured_monitor(outputs=roots)
        value.devices = set(samples)
        value.free_start, value.free_min = dict(samples), dict(samples)
        value.floors = {key: 0 for key in samples}
        # Actual statvfs availability violates this configured cache-volume
        # floor; the test never fills a real filesystem or fabricates free space.
        value.floors[device] = samples[device] + 1
        value.previous = None
        with self.assertRaises(monitor.BudgetFailure) as caught:
            value.observe_free(samples, 1)
        self.assertEqual(caught.exception.reason, "free_floor")
        self.assertEqual(caught.exception.free, samples[device])

    def usage(self, receipt):
        return json.loads(receipt.read_text().split("_DISK_USAGE:", 1)[1])

    def warm_policy(self):
        process, receipt = self.spawn("print('establish-pool')")
        status, _, stderr = self.complete(process)
        self.assertEqual(status, 0, stderr)
        pool = self.usage(receipt)["incremental"]["final_pool"]
        return {"cold_growth_bytes": 16 * MIB, "pools": [pool] + [None] * 7}

    def test_reported_21_gib_growth_stops_before_filesystem_floor(self):
        value = self.synthetic_monitor()
        value.observe_output(monitor.OutputScan(21 * GIB))
        with self.assertRaises(monitor.BudgetFailure) as caught:
            value.observe_free({1: 12 * GIB}, 10)
        self.assertEqual(caught.exception.reason, "free_floor")
        self.assertEqual(caught.exception.growth, 21 * GIB)
        self.assertGreater(caught.exception.free, value.floor)

    def test_small_build_with_same_33_gib_headroom_is_allowed(self):
        value = self.synthetic_monitor(budget=4 * GIB)
        value.observe_output(monitor.OutputScan(2 * GIB))
        value.observe_free({1: 31 * GIB}, 10)
        self.assertEqual(value.peak_growth, 2 * GIB)

    def test_admission_preserves_probe_time_across_delayed_ledger_publication(self):
        value = self.synthetic_monitor(budget=8 * MIB, floor=MIB)
        device = self.target.stat().st_dev
        value.devices, value.paths = {device}, [str(self.target)]
        value.bindings = monitor.output_bindings(value.paths)
        value.cargo_cache_bindings = {}
        value.boot, value.group, value.start = monitor.boot_identity(), os.getpgrp(), "probe-time"
        registry = monitor.Registry(str(self.registry))
        clock = [1.0]
        original_atomic_json = monitor.atomic_json

        def publish(path, payload):
            original_atomic_json(path, payload)
            # The actual reservation is durable, but publishing it consumed
            # time after the free-space probe returned.
            clock[0] = 9.0

        with patch.object(monitor, "filesystem_sample", return_value={device: GIB}), \
                patch.object(monitor.time, "monotonic", side_effect=lambda: clock[0]), \
                patch.object(monitor, "atomic_json", side_effect=publish), \
                patch.object(monitor, "Registry", return_value=registry):
            value.admit()
        self.assertEqual(value.previous, (1.0, {device: GIB}))
        self.assertEqual(value.free_start, {device: GIB})
        self.assertEqual(value.free_min, {device: GIB})
        self.assertEqual(registry.read(), [{
            "boot": value.boot, "group": value.group, "leader_start": value.start,
            "devices": [device], "budget": value.budget, "floor": value.floor,
        }])
        value.observe_free({device: 3 * GIB // 4}, 9.1)
        self.assertEqual(value.free_start[device] - value.free_min[device], GIB // 4)
        self.assertEqual(value.peak_growth, 0)

    def test_sample_timestamp_precedes_delayed_post_probe_validation(self):
        value = self.synthetic_monitor(budget=8 * MIB, floor=MIB)
        device = self.target.stat().st_dev
        value.devices, value.paths = {device}, [str(self.target)]
        value.bindings = monitor.output_bindings(value.paths)
        value.cargo_cache_bindings = {}
        clock, checks = [1.0], [0]
        original_verify = monitor.verify_output_bindings

        def verify(bindings):
            original_verify(bindings)
            checks[0] += 1
            if checks[0] == 2:
                clock[0] = 9.0

        with patch.object(monitor, "filesystem_sample", return_value={device: GIB}), \
                patch.object(monitor.time, "monotonic", side_effect=lambda: clock[0]), \
                patch.object(monitor, "verify_output_bindings", side_effect=verify):
            sampled = value.sample()
        self.assertEqual(checks[0], 2)
        self.assertEqual(sampled, ({device: GIB}, 1.0))

    def test_probe_time_preserves_slow_drop_but_refuses_real_burst_and_floor(self):
        for later_time, rejected in ((9.0, False), (1.25, True)):
            with self.subTest(later_time=later_time):
                value = self.synthetic_monitor(budget=8 * MIB, floor=MIB)
                device = self.target.stat().st_dev
                value.devices, value.paths = {device}, [str(self.target)]
                value.bindings = monitor.output_bindings(value.paths)
                value.cargo_cache_bindings = {}
                value.floors, value.free = {device: MIB}, {device: GIB}
                value.free_start, value.free_min = dict(value.free), dict(value.free)
                value.previous = (0.0, dict(value.free))
                with patch.object(monitor, "filesystem_sample",
                                  side_effect=[{device: GIB}, {device: 3 * GIB // 4}]), \
                        patch.object(monitor.time, "monotonic", side_effect=[1.0, later_time]):
                    old_probe, fresh_probe = value.sample(), value.sample()
                # Consumption occurs long after both real probes. That delay
                # must neither invent a burst nor erase one that was measured.
                with patch.object(monitor.time, "monotonic", return_value=1000.0):
                    value.observe_free(*old_probe)
                    if rejected:
                        with self.assertRaises(monitor.BudgetFailure) as caught:
                            value.observe_free(*fresh_probe)
                        self.assertEqual(caught.exception.reason, "free_floor")
                    else:
                        value.observe_free(*fresh_probe)
                        self.assertEqual(value.previous, (later_time, {device: 3 * GIB // 4}))
                self.assertEqual(value.free_start[device] - value.free_min[device], GIB // 4)
                self.assertEqual(value.peak_growth, 0)
        value = self.synthetic_monitor(budget=8 * MIB, floor=MIB)
        value.previous = None
        with self.assertRaises(monitor.BudgetFailure) as caught:
            value.observe_free({1: MIB}, 1000.0)
        self.assertEqual(caught.exception.reason, "free_floor")

    def test_delayed_terminal_consumption_keeps_true_free_drop_and_completes(self):
        # The fixture changes only logical statvfs availability; it allocates
        # no large files. Native bindings, census, guardian, and receipts run.
        inject = f"""import threading
original_filesystem_sample=m.filesystem_sample
original_sample=m.Monitor.sample
original_admit=m.Monitor.admit
original_finish=m.finish_descendants
admitted=False
after_delay=False
runtime_probe_seen=threading.Event()
def filesystem_sample(paths):
    samples=original_filesystem_sample(paths)
    available={GIB} - ({GIB // 4} if after_delay else 0)
    return {{device: available for device in samples}}
def sample(value):
    result=original_sample(value)
    if admitted:
        runtime_probe_seen.set()
    return result
def admit(value):
    global admitted
    result=original_admit(value)
    admitted=True
    return result
def finish(value, heartbeat):
    global after_delay
    if not runtime_probe_seen.wait(1):
        raise AssertionError('runtime free-space probe did not finish')
    original_finish(value, heartbeat)
    for _ in range(8):
        heartbeat()
        time.sleep(0.25)
    after_delay=True
m.filesystem_sample=filesystem_sample
m.Monitor.sample=sample
m.Monitor.admit=admit
m.finish_descendants=finish"""
        process, receipt = self.spawn("print('foreground-finished')", inject=inject)
        status, stdout, stderr = self.complete(process)
        self.assertEqual(status, 0, stderr)
        self.assertIn("foreground-finished", stdout)
        usage = self.usage(receipt)
        self.assertTrue(usage["complete"])
        self.assertEqual(usage["exit_code"], 0)
        self.assertEqual(usage["peak_growth_bytes"], 0)
        self.assertIsNotNone(usage["incremental"])
        self.assertEqual(usage["incremental"]["peak_free_drop_bytes"], GIB // 4)

    def test_flat_slot_allowance_cannot_admit_cold_test_budget(self):
        registry = monitor.Registry(str(self.registry))
        value = SimpleNamespace(boot=monitor.boot_identity(), group=os.getpgrp(), start="test",
                                budget=30 * GIB, floor=10 * GIB, devices={1}, sample=lambda: ({1: 33 * GIB}, time.monotonic()))
        with self.assertRaises(monitor.BudgetFailure) as caught:
            registry.admit(value)
        self.assertEqual(caught.exception.reason, "admission")
        value.budget = 4 * GIB
        free, floors, _sampled_at = registry.admit(value)
        self.assertEqual((free, floors), ({1: 33 * GIB}, {1: 10 * GIB}))

    def test_reservation_retirement_requires_dead_group_or_new_boot(self):
        record = {"boot": "boot-a", "group": 42, "leader_start": "old"}
        self.assertTrue(monitor.reservation_alive(record, "boot-a", {42}))
        self.assertFalse(monitor.reservation_alive(record, "boot-a", set()))
        self.assertFalse(monitor.reservation_alive(record, "boot-b", {42}))
        # Leader absence/reuse deliberately does not appear in the decision:
        # living group members keep the entire reservation.

    def test_admission_keeps_all_records_when_capacity_covers_them(self):
        registry = monitor.Registry(str(self.registry))
        record = dict(boot=monitor.boot_identity(), group=os.getpgrp(),
                      leader_start="retained", devices=[1], budget=7 * GIB, floor=10 * GIB)
        monitor.atomic_json(str(self.registry / "ledger.json"), {"version": 1, "entries": [record]})
        value = SimpleNamespace(boot=monitor.boot_identity(), group=os.getpgrp(), start="new",
                                budget=4 * GIB, floor=2 * GIB, devices={1}, sample=lambda: ({1: 21 * GIB}, time.monotonic()))
        with patch.object(monitor, "process_snapshot", side_effect=AssertionError("unnecessary census")):
            free, floors, _sampled_at = registry.admit(value)
        self.assertEqual((free, floors), ({1: 21 * GIB}, {1: 10 * GIB}))
        self.assertEqual(registry.read()[0], record)
        self.assertEqual(len(registry.read()), 2)

    def test_admission_fallback_resamples_after_real_census(self):
        registry = monitor.Registry(str(self.registry))
        value = SimpleNamespace(boot=monitor.boot_identity(), group=os.getpgrp(), start="new",
                                budget=4 * GIB, floor=2 * GIB, devices={1})
        samples = iter(({1: 5 * GIB}, {2: 20 * GIB}))
        value.sample = lambda: (next(samples), time.monotonic())
        with self.assertRaises(monitor.BudgetFailure) as caught:
            registry.admit(value)
        self.assertEqual(caught.exception.reason, "monitor_unavailable")
        self.assertEqual(registry.read(), [])

    def test_full_live_ledger_does_not_publish_unreadable_extra_record(self):
        registry = monitor.Registry(str(self.registry))
        record = dict(boot=monitor.boot_identity(), group=os.getpgrp(),
                      leader_start="retained", devices=[1], budget=1, floor=0)
        monitor.atomic_json(str(self.registry / "ledger.json"), {"version": 1, "entries": [record] * 4096})
        value = SimpleNamespace(boot=monitor.boot_identity(), group=os.getpgrp(), start="new",
                                budget=1, floor=0, devices={1}, sample=lambda: ({1: GIB}, time.monotonic()))
        with self.assertRaises(monitor.BudgetFailure) as caught:
            registry.admit(value)
        self.assertEqual(caught.exception.reason, "monitor_unavailable")
        self.assertEqual(len(registry.read()), 4096)

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
        self.assertEqual(monitor.measure_outputs([str(self.target)]).total,
                         monitor.measure_outputs([str(self.target), str(nested)]).total)

    def test_completed_scans_release_inode_tables_without_cyclic_collection(self):
        for number in range(512):
            (self.target / str(number)).touch()
        expected = monitor.measure_outputs([str(self.target)]).total
        # A long-running guardian must release each completed scan's metadata,
        # even when the cyclic collector has not revisited its generation yet.
        gc.collect()
        enabled = gc.isenabled()
        gc.disable()
        tracemalloc.start()
        try:
            for _ in range(64):
                self.assertEqual(monitor.measure_outputs([str(self.target)]).total, expected)
            retained, _ = tracemalloc.get_traced_memory()
            self.assertLess(retained, MIB, "completed scans retained inode tables")
        finally:
            tracemalloc.stop()
            gc.collect()
            if enabled:
                gc.enable()

    def test_success_preserves_output_and_warm_total_highwater(self):
        # Assert allocated-byte accounting even on compressed filesystems.
        (self.target / "warm-cache").write_bytes(os.urandom(3 * MIB))
        process, receipt = self.spawn(f"from pathlib import Path; import os; Path({str(self.target / 'new')!r}).write_bytes(os.urandom(4096)); print('small-build-ok')", mode="tracked")
        status, stdout, stderr = self.complete(process)
        self.assertEqual(status, 0, stderr)
        self.assertIn("small-build-ok", stdout)
        usage = json.loads(receipt.read_text().split("_DISK_USAGE:", 1)[1])
        self.assertTrue(usage["complete"])
        self.assertEqual(usage["exit_code"], 0)
        self.assertGreaterEqual(usage["peak_output_bytes"], 3 * MIB + 4096)
        self.assertLess(usage["peak_growth_bytes"], MIB)
        observation = usage["incremental"]
        self.assertEqual(observation["version"], 1)
        self.assertGreaterEqual(observation["baseline_output_bytes"], 3 * MIB)
        self.assertGreaterEqual(observation["peak_added_output_bytes"], 4096)
        self.assertLess(observation["peak_added_output_bytes"], MIB)
        self.assertEqual(observation["baseline_pool"]["identity"], observation["final_pool"]["identity"])
        self.assertNotEqual(observation["baseline_pool"]["state"], observation["final_pool"]["state"])

    def test_cold_output_is_fully_charged(self):
        process, receipt = self.spawn(
            f"from pathlib import Path; import os; Path({str(self.target / 'cold-output')!r}).write_bytes(os.urandom({2 * MIB}))"
        )
        status, _, stderr = self.complete(process)
        self.assertEqual(status, 0, stderr)
        observation = self.usage(receipt)["incremental"]
        self.assertLess(observation["baseline_output_bytes"], MIB)
        self.assertGreaterEqual(observation["peak_added_output_bytes"], 2 * MIB)
        self.assertIsNone(self.usage(receipt)["admitted_pool"])

    def test_cleanup_cannot_offset_additional_output(self):
        retained = self.target / "old-cache"
        retained.write_bytes(os.urandom(4 * MIB))
        value = self.measured_monitor()
        # Moving old artifacts outside the monitored tree has the same
        # accounting effect as cleanup while preserving the test fixture.
        retained.rename(self.root / "removed-cache")
        (self.target / "new-output").write_bytes(os.urandom(MIB))
        final = monitor.measure_outputs([str(self.target)], str(self.target))
        self.assertLess(final.total, value.baseline)
        value.observe_output(final)
        self.assertGreaterEqual(value.peak_added, MIB)
        self.assertGreaterEqual(value.peak_growth, MIB)

    def test_modified_baseline_inode_cannot_keep_retained_credit(self):
        retained = self.target / "old-cache"
        retained.write_bytes(os.urandom(2 * MIB))
        inode = retained.stat().st_ino
        value = self.measured_monitor()
        retained.write_bytes(os.urandom(2 * MIB))
        self.assertEqual(retained.stat().st_ino, inode)
        value.observe_output(monitor.measure_outputs([str(self.target)], str(self.target)))
        self.assertGreaterEqual(value.peak_added, 2 * MIB)
        self.assertNotEqual(value.baseline_pool["state"], value.final_pool["state"])

    def test_incremental_hardlinks_are_deduplicated_across_roots(self):
        source = self.root / "source"
        source.mkdir()
        (self.target / "retained").write_bytes(os.urandom(3 * MIB))
        value = self.measured_monitor(outputs=[source, self.target])
        added = self.target / "new-output"
        added.write_bytes(os.urandom(MIB))
        os.link(added, source / "linked-output")
        final = monitor.measure_outputs([str(source), str(self.target)], str(self.target))
        reversed_roots = monitor.measure_outputs([str(self.target), str(source)], str(self.target))
        value.observe_output(final)
        self.assertGreaterEqual(value.peak_added, MIB)
        self.assertLess(value.peak_added, 2 * MIB)
        self.assertEqual(final.pool_state, reversed_roots.pool_state)
        self.assertEqual(final.pool_bytes, reversed_roots.pool_bytes)

    def test_peak_free_drop_survives_concurrent_cleanup(self):
        value = self.measured_monitor()
        value.observe_free({1: 27 * GIB}, 10)
        value.observe_free({1: 35 * GIB}, 20)
        _, usage = monitor.usage_receipt(MARKER, value, True, 0)
        self.assertEqual(usage["incremental"]["peak_free_drop_bytes"], 6 * GIB)
        self.assertEqual(value.free, {1: 35 * GIB})

    def test_warm_unproven_source_and_cache_baselines_are_charged(self):
        source, cache = self.root / "source", self.root / "cache"
        source.mkdir()
        cache.mkdir()
        (self.target / "retained").write_bytes(os.urandom(4 * MIB))
        (source / "input").write_bytes(os.urandom(3 * MIB))
        (cache / "unattested").write_bytes(os.urandom(2 * MIB))
        roots = [str(source), str(cache), str(self.target)]
        value = self.measured_monitor(outputs=roots)
        policy = self.measured_policy(value)
        value.require_warm_pool(policy)
        unproven = value.baseline - value.baseline_pool["retained_bytes"]
        self.assertGreaterEqual(unproven, 5 * MIB)
        self.assertEqual(value.peak_growth, unproven)
        value.observe_output(monitor.measure_outputs(roots, str(self.target)))
        self.assertEqual(value.peak_added, 0)
        self.assertEqual(value.peak_growth, unproven)
        _, usage = monitor.usage_receipt(MARKER, value, True, 0)
        self.assertEqual(usage["admitted_pool"], policy["pools"][0])
        self.assertEqual(usage["peak_growth_bytes"], unproven)

    def test_larger_source_baseline_requires_cold_before_warm_admission(self):
        source = self.root / "source"
        source.mkdir()
        (self.target / "retained").write_bytes(os.urandom(3 * MIB))
        source_file = source / "input"
        source_file.write_bytes(os.urandom(MIB))
        previous = self.measured_monitor(outputs=[source, self.target])
        policy = self.measured_policy(previous)
        previous.require_warm_pool(policy)
        source_file.write_bytes(os.urandom(9 * MIB))
        current = self.measured_monitor(outputs=[source, self.target])
        self.assertEqual(previous.baseline_pool, current.baseline_pool)
        with self.assertRaises(monitor.BudgetFailure) as caught:
            current.require_warm_pool(policy)
        self.assertEqual(caught.exception.reason, "cold_required")
        self.assertEqual(caught.exception.required_growth_bytes, 16 * MIB)
        self.assertEqual(caught.exception.growth, 0)
        self.assertIn(str(current.baseline - current.baseline_pool["retained_bytes"]), caught.exception.detail)
        self.assertIsNone(current.admitted_pool)
        self.assertEqual(current.unproven_baseline, 0)

    def test_nested_sibling_pool_requires_its_own_funded_allowance(self):
        source = self.root / "source"
        source.mkdir()
        self.target = source / ".rch-target-selected-pool-current"
        self.target.mkdir()
        sibling = source / ".rch-target-other-pool-retained"
        sibling.mkdir()
        (self.target / "artifact").write_bytes(os.urandom(4 * MIB))
        sibling_artifact = sibling / "artifact"
        sibling_artifact.write_bytes(os.urandom(2 * MIB))
        roots = [str(source), str(self.target)]
        value = self.measured_monitor(outputs=roots)
        policy = self.measured_policy(value)
        value.require_warm_pool(policy)
        self.assertGreaterEqual(value.unproven_baseline, 2 * MIB)
        self.assertLess(value.unproven_baseline, 3 * MIB)
        value.observe_output(monitor.measure_outputs(roots, str(self.target), value.baseline_records))
        self.assertEqual(value.peak_added, 0)
        self.assertEqual(value.peak_growth, value.unproven_baseline)

        # A familiar pool name is not an admission proof. Only the selected
        # target snapshot is attested, even when both pools share the source.
        sibling_artifact.write_bytes(os.urandom(9 * MIB))
        larger = self.measured_monitor(outputs=roots)
        self.assertEqual(larger.baseline_pool, value.baseline_pool)
        with self.assertRaises(monitor.BudgetFailure) as caught:
            larger.require_warm_pool(policy)
        self.assertEqual(caught.exception.reason, "cold_required")
        self.assertEqual(caught.exception.growth, 0)
        self.assertEqual(caught.exception.required_growth_bytes, 16 * MIB)
        self.assertIsNone(larger.admitted_pool)

    def test_warm_baseline_must_leave_a_strict_growth_buffer(self):
        (self.target / "retained").write_bytes(os.urandom(4096))
        value = self.measured_monitor()
        policy = self.measured_policy(value)
        boundary = value.budget - monitor.growth_buffer(value.budget)
        # Exact numerical boundary independent of filesystem block sizes.
        value.baseline = value.baseline_pool["retained_bytes"] + boundary
        with self.assertRaises(monitor.BudgetFailure) as caught:
            value.require_warm_pool(policy)
        self.assertEqual(caught.exception.reason, "cold_required")
        self.assertIsNone(value.admitted_pool)
        value.baseline -= 1
        value.require_warm_pool(policy)
        self.assertEqual(value.unproven_baseline, boundary - 1)

    def test_cleanup_cannot_remove_unproven_baseline_runtime_charge(self):
        source = self.root / "source"
        source.mkdir()
        (self.target / "retained").write_bytes(os.urandom(4 * MIB))
        source_file = source / "input"
        source_file.write_bytes(os.urandom(5 * MIB))
        roots = [str(source), str(self.target)]
        value = self.measured_monitor(outputs=roots)
        value.require_warm_pool(self.measured_policy(value))
        source_file.rename(self.root / "removed-source")
        (self.target / "new").write_bytes(os.urandom(4 * MIB))
        final = monitor.measure_outputs(roots, str(self.target))
        self.assertLess(final.total, value.baseline)
        with self.assertRaises(monitor.BudgetFailure) as caught:
            value.observe_output(final)
        self.assertEqual(caught.exception.reason, "growth")
        self.assertGreaterEqual(value.peak_growth, 9 * MIB)
        self.assertEqual(value.peak_growth, value.unproven_baseline + value.peak_added)

    def test_rewritten_unproven_inode_keeps_honest_aggregate_charge(self):
        source = self.root / "source"
        source.mkdir()
        (self.target / "retained").write_bytes(os.urandom(MIB))
        source_file = source / "input"
        source_file.write_bytes(os.urandom(3 * MIB))
        roots = [str(source), str(self.target)]
        value = self.measured_monitor(outputs=roots)
        value.require_warm_pool(self.measured_policy(value))
        inode = source_file.stat().st_ino
        source_file.write_bytes(os.urandom(3 * MIB))
        self.assertEqual(source_file.stat().st_ino, inode)
        value.observe_output(monitor.measure_outputs(roots, str(self.target)))
        self.assertGreater(value.peak_growth, value.peak_output)
        self.assertLessEqual(value.peak_growth, 2 * value.peak_output)
        self.assertEqual(value.peak_growth, value.unproven_baseline + value.peak_added)
        _, usage = monitor.usage_receipt(MARKER, value, True, 0)
        self.assertTrue(usage["complete"])
        self.assertEqual(usage["peak_growth_bytes"], value.peak_growth)

    def test_lost_learning_keeps_unproven_baseline_charge(self):
        source = self.root / "source"
        source.mkdir()
        (self.target / "retained").write_bytes(os.urandom(4 * MIB))
        (source / "input").write_bytes(os.urandom(3 * MIB))
        roots = [str(source), str(self.target)]
        value = self.measured_monitor(outputs=roots)
        policy = self.measured_policy(value)
        value.require_warm_pool(policy)
        (self.target / "new").write_bytes(os.urandom(MIB))
        with patch.object(monitor, "MAX_INCREMENTAL_ENTRIES", 1):
            final = monitor.measure_outputs(roots, str(self.target), value.baseline_records)
        value.observe_output(final)
        self.assertGreaterEqual(value.peak_growth, value.unproven_baseline + MIB)
        _, usage = monitor.usage_receipt(MARKER, value, True, 0)
        self.assertTrue(usage["complete"])
        self.assertEqual(usage["admitted_pool"], policy["pools"][0])
        self.assertIsNone(usage["incremental"])

    def test_source_hardlink_to_attested_pool_is_not_charged_twice(self):
        source = self.root / "source"
        source.mkdir()
        retained = self.target / "retained"
        retained.write_bytes(os.urandom(4 * MIB))
        os.link(retained, source / "alias")
        (source / "input").write_bytes(os.urandom(MIB))
        value = self.measured_monitor(outputs=[source, self.target])
        value.require_warm_pool(self.measured_policy(value))
        self.assertGreaterEqual(value.unproven_baseline, MIB)
        self.assertLess(value.unproven_baseline, 2 * MIB)

    def test_bounded_snapshot_still_counts_additions_after_cleanup(self):
        retained = self.target / "retained"
        retained.write_bytes(os.urandom(4 * MIB))
        value = self.measured_monitor()
        policy = self.measured_policy(value)
        value.require_warm_pool(policy)
        retained.rename(self.root / "removed-retained")
        (self.target / "new").write_bytes(os.urandom(MIB))
        with patch.object(monitor, "MAX_INCREMENTAL_ENTRIES", 1):
            final = monitor.measure_outputs([str(self.target)], str(self.target), value.baseline_records)
        self.assertLess(final.total, value.baseline)
        self.assertIsNone(final.records)
        self.assertGreaterEqual(final.added, MIB)
        value.observe_output(final)
        self.assertGreaterEqual(value.peak_growth, MIB)
        self.assertLess(value.peak_growth, 2 * MIB)
        _, usage = monitor.usage_receipt(MARKER, value, True, 0)
        self.assertTrue(usage["complete"])
        self.assertEqual(usage["admitted_pool"], policy["pools"][0])
        self.assertIsNone(usage["incremental"])

    def test_capped_snapshot_cannot_hide_warm_runtime_budget_violation(self):
        retained = self.target / "retained"
        retained.write_bytes(os.urandom(4 * MIB))
        value = self.measured_monitor(budget=2 * MIB)
        value.require_warm_pool(self.measured_policy(value))
        retained.rename(self.root / "removed-retained")
        (self.target / "new").write_bytes(os.urandom(3 * MIB))
        with patch.object(monitor, "MAX_INCREMENTAL_ENTRIES", 1):
            final = monitor.measure_outputs([str(self.target)], str(self.target), value.baseline_records)
        self.assertLess(final.total, value.baseline)
        self.assertIsNone(final.records)
        with self.assertRaises(monitor.BudgetFailure) as caught:
            value.observe_output(final)
        self.assertEqual(caught.exception.reason, "growth")
        self.assertGreaterEqual(caught.exception.growth, 3 * MIB)
        self.assertFalse(value.incremental_reliable)

    def test_directory_churn_disables_learning_without_erasing_streamed_additions(self):
        retained = self.target / "retained"
        retained.write_bytes(os.urandom(4 * MIB))
        value = self.measured_monitor()
        value.require_warm_pool(self.measured_policy(value))
        retained.rename(self.root / "removed-retained")
        (self.target / "new").write_bytes(os.urandom(MIB))
        original = monitor.os.scandir

        def changed_directory(descriptor):
            entries = original(descriptor)
            # Change the directory after its opening stamp. The real scan
            # must suppress its pool proof but retain observed new allocations.
            (self.target / "concurrent-entry").write_bytes(b"")
            return entries

        with patch.object(monitor.os, "scandir", side_effect=changed_directory):
            final = monitor.measure_outputs([str(self.target)], str(self.target), value.baseline_records)
        self.assertIsNone(final.records)
        self.assertIsNone(final.pool_state)
        self.assertGreaterEqual(final.added, MIB)
        value.observe_output(final)
        self.assertGreaterEqual(value.peak_growth, MIB)
        self.assertFalse(value.incremental_reliable)

    def test_capped_runtime_counter_still_deduplicates_hardlinks(self):
        source = self.root / "source"
        source.mkdir()
        (self.target / "retained").write_bytes(os.urandom(3 * MIB))
        roots = [str(source), str(self.target)]
        value = self.measured_monitor(outputs=roots)
        value.require_warm_pool(self.measured_policy(value))
        added = self.target / "new"
        added.write_bytes(os.urandom(MIB))
        os.link(added, source / "new-alias")
        with patch.object(monitor, "MAX_INCREMENTAL_ENTRIES", 1):
            final = monitor.measure_outputs(roots, str(self.target), value.baseline_records)
        self.assertIsNone(final.records)
        value.observe_output(final)
        self.assertGreaterEqual(value.peak_added, MIB)
        self.assertLess(value.peak_added, 2 * MIB)

    def test_unknown_warm_runtime_attribution_uses_conservative_total(self):
        (self.target / "retained").write_bytes(os.urandom(4 * MIB))
        value = self.measured_monitor(budget=2 * MIB)
        value.require_warm_pool(self.measured_policy(value))
        # An adapter that cannot supply either the streaming counter or
        # current inode records may not fall back to zero net growth.
        with self.assertRaises(monitor.BudgetFailure) as caught:
            value.observe_output(monitor.OutputScan(3 * MIB))
        self.assertEqual(caught.exception.reason, "growth")
        self.assertEqual(caught.exception.growth, 3 * MIB)
        self.assertFalse(value.incremental_reliable)

    def test_conservative_tracking_fallback_can_still_confirm_completion(self):
        (self.target / "retained").write_bytes(os.urandom(MIB))
        value = self.measured_monitor()
        policy = self.measured_policy(value)
        value.require_warm_pool(policy)
        value.observe_output(monitor.OutputScan(2 * MIB))
        _, usage = monitor.usage_receipt(MARKER, value, True, 0)
        self.assertEqual(usage["peak_growth_bytes"], 2 * MIB)
        self.assertTrue(usage["complete"])
        self.assertEqual(usage["admitted_pool"], policy["pools"][0])
        self.assertIsNone(usage["incremental"])

    def test_required_source_tracking_refuses_incomplete_initial_snapshot(self):
        (self.target / "source-input").write_bytes(os.urandom(MIB))
        with patch.object(monitor, "MAX_INCREMENTAL_ENTRIES", 1):
            value = self.measured_monitor()
        self.assertIsNone(value.baseline_records)
        with self.assertRaises(monitor.BudgetFailure) as caught:
            value.require_runtime_tracking(True)
        self.assertEqual(caught.exception.reason, "monitor_unavailable")
        self.assertIn("initial output tracking", caught.exception.detail)
        self.assertFalse(value.strict_tracking)
        # The internal upload requirement does not change ordinary cold mode.
        value.require_runtime_tracking(False)
        self.assertFalse(value.strict_tracking)

    def test_required_source_tracking_preserves_budget_without_pool_policy(self):
        retained = self.target / "source-input"
        retained.write_bytes(os.urandom(4 * MIB))
        value = self.measured_monitor(budget=2 * MIB)
        value.require_runtime_tracking(True)
        self.assertIsNone(value.admitted_pool)
        retained.rename(self.root / "removed-source")
        (self.target / "incoming").write_bytes(os.urandom(3 * MIB))
        with patch.object(monitor, "MAX_INCREMENTAL_ENTRIES", 1):
            final = monitor.measure_outputs([str(self.target)], str(self.target), value.baseline_records)
        self.assertLess(final.total, value.baseline)
        with self.assertRaises(monitor.BudgetFailure) as caught:
            value.observe_output(final)
        self.assertEqual(caught.exception.reason, "growth")
        self.assertGreaterEqual(caught.exception.growth, 3 * MIB)

    def test_required_tracking_plan_rejects_non_boolean_flags_before_guardian(self):
        for required in (None, "true", 1, []):
            with self.subTest(required=required):
                plan = {"probe": [str(self.target)], "output": [str(self.target)],
                        "require_incremental_tracking": required}
                argv = [str(8 * MIB), str(MIB), MARKER, str(self.target), json.dumps(plan), "standalone", "true"]
                with patch.object(monitor, "run_guarded") as guarded:
                    with self.assertRaises(ValueError):
                        monitor.main(argv)
                guarded.assert_not_called()

    def test_required_initial_tracking_refuses_before_receiver_launch(self):
        (self.target / "source-input").write_bytes(os.urandom(MIB))
        process, receipt = self.spawn(
            "print('receiver-must-not-start')", require_incremental_tracking=True,
            inject="m.MAX_INCREMENTAL_ENTRIES=1",
        )
        status, stdout, _ = self.complete(process)
        self.assertEqual(status, monitor.EXIT_BUDGET)
        self.assertNotIn("receiver-must-not-start", stdout)
        failure = self.failure(receipt)
        self.assertEqual(failure["reason"], "monitor_unavailable")
        self.assertFalse(failure["started"])

    def test_snapshot_bound_preserves_completion_but_disables_small_learning(self):
        (self.target / "retained").write_bytes(os.urandom(4096))
        process, receipt = self.spawn("print('bounded-completion')", inject="m.MAX_INCREMENTAL_ENTRIES=1")
        status, stdout, stderr = self.complete(process)
        self.assertEqual(status, 0, stderr)
        self.assertIn("bounded-completion", stdout)
        usage = self.usage(receipt)
        self.assertTrue(usage["complete"])
        self.assertIsNone(usage["incremental"])
        self.assertGreaterEqual(usage["peak_output_bytes"], 4096)

    def test_exact_warm_pool_proof_allows_small_reservation(self):
        (self.target / "retained").write_bytes(os.urandom(3 * MIB))
        policy = self.warm_policy()
        process, receipt = self.spawn("print('warm-admitted')", warm_policy=policy)
        status, stdout, stderr = self.complete(process)
        self.assertEqual(status, 0, stderr)
        self.assertIn("warm-admitted", stdout)
        self.assertEqual(self.usage(receipt)["admitted_pool"], policy["pools"][0])

    def test_source_sync_does_not_change_target_pool_proof(self):
        source = self.root / "source"
        source.mkdir()
        (source / "input").write_text("before-sync")
        (self.target / "retained").write_bytes(os.urandom(MIB))
        policy = self.warm_policy()
        (source / "input").write_text("new source contents after sync")
        process, receipt = self.spawn("print('source-sync-admitted')", outputs=[source, self.target], warm_policy=policy)
        status, stdout, stderr = self.complete(process)
        self.assertEqual(status, 0, stderr)
        self.assertIn("source-sync-admitted", stdout)
        self.assertEqual(self.usage(receipt)["admitted_pool"], policy["pools"][0])

    def test_repopulated_same_inode_pool_requires_cold_readmission(self):
        retained = self.target / "old-cache"
        retained.write_bytes(os.urandom(3 * MIB))
        policy = self.warm_policy()
        root_inode = self.target.stat().st_ino
        retained.rename(self.root / "removed-cache")
        (self.target / "new-cache").write_bytes(os.urandom(3 * MIB))
        self.assertEqual(self.target.stat().st_ino, root_inode)
        ledger_before = monitor.Registry(str(self.registry)).read()
        process, receipt = self.spawn("print('must-not-start')", warm_policy=policy)
        status, stdout, _ = self.complete(process)
        self.assertEqual(status, monitor.EXIT_BUDGET)
        self.assertNotIn("must-not-start", stdout)
        failure = self.failure(receipt)
        self.assertEqual(failure["reason"], "cold_required")
        self.assertEqual(failure["required_growth_bytes"], 16 * MIB)
        self.assertFalse(failure["started"])
        self.assertEqual(monitor.Registry(str(self.registry)).read(), ledger_before)

    def test_unavailable_bounded_pool_proof_requires_cold_readmission(self):
        (self.target / "retained").write_bytes(os.urandom(MIB))
        policy = self.warm_policy()
        process, receipt = self.spawn("print('must-not-start')", warm_policy=policy,
                                      inject="m.MAX_INCREMENTAL_ENTRIES=1")
        status, stdout, _ = self.complete(process)
        self.assertEqual(status, monitor.EXIT_BUDGET)
        self.assertNotIn("must-not-start", stdout)
        failure = self.failure(receipt)
        self.assertEqual(failure["reason"], "cold_required")
        self.assertFalse(failure["started"])

    def test_lost_learning_metadata_preserves_warm_admission_and_completion(self):
        (self.target / "retained").write_bytes(os.urandom(MIB))
        policy = self.warm_policy()
        # Initial root + retained file fit. New output exceeds the evidence
        # cap after admission without making the process outcome uncertain.
        process, receipt = self.spawn(
            f"from pathlib import Path; Path({str(self.target / 'new')!r}).write_bytes(b'x' * 4096)",
            warm_policy=policy, inject="m.MAX_INCREMENTAL_ENTRIES=2",
        )
        status, _, stderr = self.complete(process)
        self.assertEqual(status, 0, stderr)
        usage = self.usage(receipt)
        self.assertTrue(usage["complete"])
        self.assertEqual(usage["admitted_pool"], policy["pools"][0])
        self.assertIsNone(usage["incremental"])

    def test_malformed_warm_policy_fails_closed_before_launch(self):
        (self.target / "retained").write_bytes(os.urandom(4096))
        valid = self.warm_policy()
        wrong_digest = dict(valid["pools"][0], state=[True] * 32)
        for policy in (
            {},
            dict(valid, cold_growth_bytes=8 * MIB),
            dict(valid, pools=[]),
            dict(valid, pools=[None] * 8),
            dict(valid, pools=[wrong_digest] + [None] * 7),
            dict(valid, pools=[dict(valid["pools"][0], state=[0] * 32)] + [None] * 7),
            dict(valid, pools=[dict(valid["pools"][0], identity=[0] * 32)] + [None] * 7),
            dict(valid, pools=[dict(valid["pools"][0], retained_bytes=0)] + [None] * 7),
            dict(valid, pools=[valid["pools"][0]] * 2 + [None] * 6),
        ):
            with self.subTest(policy=policy):
                process, receipt = self.spawn("print('must-not-start')", warm_policy=policy)
                status, stdout, _ = self.complete(process)
                self.assertEqual(status, monitor.EXIT_BUDGET)
                self.assertNotIn("must-not-start", stdout)
                failure = self.failure(receipt)
                self.assertEqual(failure["reason"], "monitor_unavailable")
                self.assertFalse(failure["started"])
                self.assertNotIn("required_growth_bytes", failure)

    def test_cleanup_does_not_hide_runtime_budget_violation(self):
        retained = self.target / "old-cache"
        retained.write_bytes(os.urandom(4 * MIB))
        policy = self.warm_policy()
        payload = (
            "from pathlib import Path; import os,time; "
            f"Path({str(retained)!r}).rename({str(self.root / 'removed-cache')!r}); "
            f"Path({str(self.target / 'new')!r}).write_bytes(os.urandom({3 * MIB})); time.sleep(20)"
        )
        process, receipt = self.spawn(payload, budget=2 * MIB, warm_policy=policy)
        self.complete(process)
        failure = self.failure(receipt)
        self.assertEqual(failure["reason"], "growth")
        self.assertGreaterEqual(failure["growth_bytes"], 3 * MIB)
        self.assertTrue(failure["started"])
        self.assertFalse(self.usage(receipt)["complete"])

    def test_overlapping_builds_conservatively_observe_shared_additions(self):
        (self.target / "retained").write_bytes(os.urandom(3 * MIB))
        policy = self.warm_policy()
        gate = self.root / "release-writers"
        tasks = []
        # Both baselines and first scans finish before either writer starts.
        # Both writers finish before either monitor completes. This exercises
        # shared additions deterministically without assigning them to a PID.
        for index in range(2):
            scanned = self.root / ("scanned-" + str(index))
            done = self.root / ("done-" + str(index))
            peer_done = self.root / ("done-" + str(1 - index))
            inject = f"""original_observe=m.Monitor.observe_output
def observed(value, scan):
    original_observe(value, scan)
    pathlib.Path({str(scanned)!r}).write_text('scanned')
m.Monitor.observe_output=observed"""
            payload = (
                "from pathlib import Path\nimport os,time\n"
                f"while not Path({str(gate)!r}).exists(): time.sleep(0.01)\n"
                f"Path({str(self.target / ('new-' + str(index)))!r}).write_bytes(os.urandom({MIB}))\n"
                f"Path({str(done)!r}).write_text('done')\n"
                f"while not Path({str(peer_done)!r}).exists(): time.sleep(0.01)\n"
            )
            tasks.append((*self.spawn(payload, warm_policy=policy, inject=inject), scanned))
        for _, _, scanned in tasks:
            self.wait_file(scanned)
        gate.write_text("go")
        for process, receipt, _ in tasks:
            status, _, stderr = self.complete(process)
            self.assertEqual(status, 0, stderr)
            usage = self.usage(receipt)
            self.assertEqual(usage["admitted_pool"], policy["pools"][0])
            self.assertGreaterEqual(usage["incremental"]["peak_added_output_bytes"], 2 * MIB)

    def test_warm_cancellation_keeps_admission_proof_but_not_completion(self):
        (self.target / "retained").write_bytes(os.urandom(MIB))
        policy = self.warm_policy()
        ready = self.root / "writer-ready"
        process, receipt = self.spawn(
            f"from pathlib import Path; import time; Path({str(ready)!r}).write_text('ready'); time.sleep(20)",
            warm_policy=policy,
        )
        self.wait_file(ready)
        # Cancellation signals the group. The guardian alone never reaches the
        # supervisor that writes this receipt, and only fences the group.
        os.killpg(process.pid, signal.SIGTERM)
        status, _, _ = self.complete(process)
        self.assertNotEqual(status, 0)
        self.assertTrue(self.failure(receipt)["started"])
        usage = self.usage(receipt)
        self.assertEqual(usage["admitted_pool"], policy["pools"][0])
        self.assertFalse(usage["complete"])
        self.assertIsNone(usage["exit_code"])

    def test_reading_retained_artifacts_does_not_invalidate_pool_proof(self):
        retained = self.target / "retained"
        retained.write_bytes(os.urandom(MIB))
        policy = self.warm_policy()
        retained.read_bytes()
        process, receipt = self.spawn("print('retained-read-admitted')", warm_policy=policy)
        status, _, stderr = self.complete(process)
        self.assertEqual(status, 0, stderr)
        self.assertEqual(self.usage(receipt)["admitted_pool"], policy["pools"][0])

    def test_warm_proof_does_not_transfer_to_another_target(self):
        (self.target / "retained").write_bytes(os.urandom(MIB))
        policy = self.warm_policy()
        other = self.root / "other-target"
        other.mkdir()
        (other / "retained").write_bytes((self.target / "retained").read_bytes())
        process, receipt = self.spawn("print('must-not-start')", target=other, warm_policy=policy)
        status, stdout, _ = self.complete(process)
        self.assertEqual(status, monitor.EXIT_BUDGET)
        self.assertNotIn("must-not-start", stdout)
        self.assertEqual(self.failure(receipt)["reason"], "cold_required")
        self.assertFalse(self.failure(receipt)["started"])

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
    samples, sampled_at=original_sample(value)
    if getattr(value, 'terminal_scan_done', False):
        pathlib.Path({str(witness)!r}).write_text('sampled after final scan')
        condition={condition!r}
        if condition == 'floor':
            return {{device: value.floor for device in samples}}, sampled_at
        if condition == 'error':
            raise OSError('terminal filesystem probe failed')
        if condition == 'identity':
            return {{max(samples) + 1: min(samples.values())}}, sampled_at
        if condition == 'timeout':
            time.sleep(5)
    return samples, sampled_at
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

    def test_complete_ack_retries_share_one_scaled_deadline(self):
        for scale, ready_after, succeeds in (
                (1, 0, True), (1, 3.6, False), (2, 3.6, True),
                (10, float("inf"), False)):
            with self.subTest(scale=scale, ready_after=ready_after):
                clock, attempts = [10.0], []
                deadline = 10.0 + 3.0 * scale

                def write(descriptor, data):
                    attempts.append(clock[0])
                    self.assertEqual((descriptor, data), (71, b"C"))
                    if clock[0] - 10.0 < ready_after:
                        raise BlockingIOError()
                    return len(data)

                def sleep(delay):
                    self.assertGreaterEqual(delay, 0)
                    self.assertLessEqual(delay, 0.025)
                    clock[0] += delay

                with patch.object(monitor, "HEARTBEAT_DEADLINE", 3.0 * scale), \
                        patch.object(monitor.time, "monotonic", side_effect=lambda: clock[0]), \
                        patch.object(monitor.time, "sleep", side_effect=sleep), \
                        patch.object(monitor.os, "getppid", return_value=73), \
                        patch.object(monitor.os, "write", side_effect=write):
                    if succeeds:
                        monitor.acknowledge_completion(71, 73)
                    else:
                        with self.assertRaises(monitor.BudgetFailure) as caught:
                            monitor.acknowledge_completion(71, 73)
                        self.assertIn("deadline", caught.exception.detail)
                self.assertTrue(attempts)
                self.assertTrue(all(attempt < deadline for attempt in attempts))
                if succeeds:
                    self.assertGreaterEqual(clock[0] - 10.0, ready_after)
                    self.assertLess(clock[0], deadline)
                else:
                    self.assertAlmostEqual(clock[0], deadline)

    def test_complete_ack_refuses_lost_parent_and_late_or_short_writes(self):
        for failure in ("parent_before", "parent_after", "equal_deadline",
                        "late_deadline", "short_write"):
            with self.subTest(failure=failure):
                clock, parent = [1.0], [73]
                if failure == "parent_before":
                    parent[0] = 74

                def write(descriptor, data):
                    if failure == "parent_after":
                        parent[0] = 74
                    elif failure == "equal_deadline":
                        clock[0] = 4.0
                    elif failure == "late_deadline":
                        clock[0] = 4.001
                    return 0 if failure == "short_write" else len(data)

                with patch.object(monitor, "HEARTBEAT_DEADLINE", 3.0), \
                        patch.object(monitor.time, "monotonic", side_effect=lambda: clock[0]), \
                        patch.object(monitor.os, "getppid", side_effect=lambda: parent[0]), \
                        patch.object(monitor.os, "write", side_effect=write) as writes:
                    with self.assertRaises(monitor.BudgetFailure):
                        monitor.acknowledge_completion(71, 73)
                self.assertEqual(writes.call_count, 0 if failure == "parent_before" else 1)

    def test_complete_ack_late_delivery_never_authorizes_normal_exit(self):
        # The native C write succeeds, but a scheduling delay crosses its
        # delivery deadline before confirmation. Even with C queued, the owned
        # group must fail closed instead of returning a normal exception code.
        inject = """native_write=os.write
native_monotonic=time.monotonic
def write(descriptor, data):
    written=native_write(descriptor, data)
    if data == b'C':
        native_write(2, b'RCH_TEST_COMPLETION_ACK_WAS_WRITTEN\\n')
        m.time.monotonic=lambda: native_monotonic()+m.HEARTBEAT_DEADLINE
    return written
m.os.write=write"""
        for scale in ("1", "10"):
            with self.subTest(scale=scale):
                process, receipt = self.spawn(
                    "print('completed-zero')", inject=inject, timing_scale=scale)
                status, stdout, stderr = self.complete(process)
                self.assertIn("RCH_TEST_COMPLETION_ACK_WAS_WRITTEN", stderr)
                self.assertIn("completed-zero", stdout)
                self.assertTrue(self.usage(receipt)["complete"])
                self.assertEqual(self.usage(receipt)["exit_code"], 0)
                self.assertEqual(status, -signal.SIGKILL, stderr)

    @unittest.skipUnless(sys.platform.startswith("linux") and hasattr(os, "pidfd_open")
                         and hasattr(signal, "pidfd_send_signal"), "Linux pinned guardian")
    def test_complete_ack_survives_real_heartbeat_pipe_pressure(self):
        # Pause only this attempt's pinned guardian. Fill its real nonblocking
        # heartbeat pipe so the first completion write receives native EAGAIN.
        # The finally block resumes that same guardian before a retry can run.
        inject = """import fcntl
native_write=os.write
pressured=False
def write(descriptor, data):
    global pressured
    if data != b'C' or pressured:
        return native_write(descriptor, data)
    pressured=True
    guardian=os.getppid()
    guardian_fd=os.pidfd_open(guardian)
    try:
        if os.getppid() != guardian or os.getpgid(guardian) != os.getpgrp():
            raise AssertionError('guardian no longer belongs to this attempt')
        signal.pidfd_send_signal(guardian_fd, signal.SIGSTOP)
        try:
            stopped_by=time.monotonic()+1
            while m.linux_process('/proc/'+str(guardian)+'/stat')['state'] not in ('T', 't'):
                if time.monotonic() >= stopped_by:
                    raise AssertionError('owned guardian did not stop')
                time.sleep(0.005)
            capacity=fcntl.fcntl(descriptor, fcntl.F_GETPIPE_SZ)
            for size in (4096, 1):
                for _ in range(capacity//size+1):
                    try:
                        native_write(descriptor, b'H'*size)
                    except BlockingIOError:
                        break
                else:
                    raise AssertionError('native heartbeat pipe did not fill')
            try:
                return native_write(descriptor, data)
            except BlockingIOError:
                native_write(2, b'RCH_TEST_COMPLETION_PIPE_SATURATED\\n')
                raise
        finally:
            signal.pidfd_send_signal(guardian_fd, signal.SIGCONT)
    finally:
        os.close(guardian_fd)
m.os.write=write"""
        process, receipt = self.spawn("print('completed-zero')", inject=inject)
        status, stdout, stderr = self.complete(process)
        self.assertIn("RCH_TEST_COMPLETION_PIPE_SATURATED", stderr)
        self.assertIn("completed-zero", stdout)
        usage = self.usage(receipt)
        self.assertTrue(usage["complete"])
        self.assertEqual(usage["exit_code"], 0)
        self.assertEqual(status, 0, stderr)

    @unittest.skipUnless(sys.platform.startswith("linux") and hasattr(os, "pidfd_open")
                         and hasattr(signal, "pidfd_send_signal"), "Linux pinned guardian")
    def test_complete_ack_is_drained_after_supervisor_exit(self):
        # This race needs more queued bytes than the guardian's two original
        # reads. Resume the owned guardian only after its child is a zombie:
        # the acknowledgment is already in the pipe, with no remaining writer.
        read_fd, write_fd = os.pipe()
        try:
            capacity = monitor.fcntl.fcntl(write_fd, monitor.fcntl.F_GETPIPE_SZ)
        finally:
            os.close(read_fd)
            os.close(write_fd)
        if capacity < 16384:
            self.skipTest("native pipe cannot hold the completion backlog")
        queued = self.root / "completion-queued"
        inject = f"""native_write=os.write
def write(descriptor, data):
    if data != b'C':
        return native_write(descriptor, data)
    guardian=os.getppid()
    guardian_fd=os.pidfd_open(guardian)
    try:
        if os.getppid() != guardian or os.getpgid(guardian) != os.getpgrp():
            raise AssertionError('guardian no longer belongs to this attempt')
        signal.pidfd_send_signal(guardian_fd, signal.SIGSTOP)
        stopped_by=time.monotonic()+1
        while m.linux_process('/proc/'+str(guardian)+'/stat')['state'] not in ('T', 't'):
            if time.monotonic() >= stopped_by:
                raise AssertionError('owned guardian did not stop')
            time.sleep(0.005)
        backlog=b'H'*8192+data
        if native_write(descriptor, backlog) != len(backlog):
            raise AssertionError('native completion backlog was truncated')
        pathlib.Path({str(queued)!r}).write_text(str(os.getpid()))
        return len(data)
    except BaseException:
        signal.pidfd_send_signal(guardian_fd, signal.SIGCONT)
        raise
    finally:
        os.close(guardian_fd)
m.os.write=write"""
        process, receipt = self.spawn("print('completed-zero')", inject=inject)
        guardian_fd = os.pidfd_open(process.pid)
        try:
            supervisor = int(self.wait_file(queued))
            deadline = time.monotonic() + 3
            while True:
                record = monitor.linux_process(f"/proc/{supervisor}/stat")
                self.assertEqual(record["parent"], process.pid)
                self.assertEqual(record["group"], process.pid)
                if record["state"] == "Z":
                    break
                self.assertLess(time.monotonic(), deadline, "supervisor did not exit")
                time.sleep(0.005)
        finally:
            try:
                signal.pidfd_send_signal(guardian_fd, signal.SIGCONT)
            except ProcessLookupError:
                pass
            os.close(guardian_fd)
        status, stdout, stderr = self.complete(process)
        self.assertIn("completed-zero", stdout)
        self.assertTrue(self.usage(receipt)["complete"])
        self.assertEqual(self.usage(receipt)["exit_code"], 0)
        self.assertEqual(status, 0, stderr)

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
        process, receipt = self.spawn(f"from pathlib import Path; import os,time; Path({str(output)!r}).write_bytes(os.urandom({4*MIB})); time.sleep(20)", budget=2 * MIB)
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
        process, receipt = self.spawn(f"from pathlib import Path; import os,time; Path({str(output)!r}).write_bytes(os.urandom({4*MIB})); time.sleep(20)", budget=2 * MIB, outputs=[self.target, temporary])
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
    if os.path.realpath(args[0][0]) != os.path.realpath(sys.executable):
        return child
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

    def test_invalid_timing_policy_never_starts_payload(self):
        mutation = self.root / "invalid-scale-payload"
        for value in ("nan", "inf", "0", "11", ""):
            with self.subTest(value=value):
                process, _ = self.spawn(
                    f"from pathlib import Path; Path({str(mutation)!r}).touch()",
                    timing_scale=value)
                status, _, stderr = self.complete(process)
                self.assertNotEqual(status, 0)
                self.assertIn("RCH_TIMING_SCALE", stderr)
                self.assertFalse(mutation.exists())

    def test_scaled_heartbeat_accepts_late_progress_beyond_default_deadline(self):
        inject = """original_finish=m.finish_descendants
def delayed_finish(value, heartbeat):
    time.sleep(3.6)
    return original_finish(value, heartbeat)
m.finish_descendants=delayed_finish"""
        for scale, succeeds in (("1", False), ("2", True)):
            with self.subTest(scale=scale):
                process, receipt = self.spawn(
                    "print('foreground-finished')",
                    inject=inject, timing_scale=scale)
                status, stdout, stderr = self.complete(process, timeout=10)
                self.assertIn("foreground-finished", stdout)
                if succeeds:
                    self.assertEqual(status, 0, stderr)
                    usage = json.loads(receipt.read_text().split("_DISK_USAGE:", 1)[1])
                    self.assertTrue(usage["complete"])
                    self.assertEqual(usage["exit_code"], 0)
                else:
                    self.assertNotEqual(status, 0, stderr)
                    self.assertEqual(receipt.read_text(), "")
                    diagnostic = json.loads(stderr.split("_DISK_GUARDIAN:", 1)[1])
                    self.assertEqual(diagnostic["reason"], "heartbeat_timeout")
                    self.assertTrue(diagnostic["started"])

    def test_scaled_heartbeat_stall_remains_bounded_and_unconfirmed(self):
        inject = """original_finish=m.finish_descendants
def stalled_finish(value, heartbeat):
    time.sleep(20)
    return original_finish(value, heartbeat)
m.finish_descendants=stalled_finish"""
        started = time.monotonic()
        process, receipt = self.spawn(
            "print('foreground-finished')", inject=inject, timing_scale="2")
        status, stdout, stderr = self.complete(process, timeout=10)
        self.assertNotEqual(status, 0, stderr)
        self.assertIn("foreground-finished", stdout)
        self.assertLess(time.monotonic() - started, 9)
        self.assertEqual(receipt.read_text(), "")
        diagnostic = json.loads(stderr.split("_DISK_GUARDIAN:", 1)[1])
        self.assertEqual(diagnostic["reason"], "heartbeat_timeout")
        self.assertTrue(diagnostic["started"])

    def test_scaled_free_sample_deadline_allows_delayed_success(self):
        for value, succeeds in (("1", False), ("2", True)):
            with self.subTest(scale=value):
                ready = self.target / ("delayed-sample-" + value)
                inject = f"""original_sample=m.filesystem_sample
def delayed_sample(paths):
    if pathlib.Path({str(ready)!r}).exists():
        time.sleep(1.3)
    return original_sample(paths)
m.filesystem_sample=delayed_sample"""
                payload = ("from pathlib import Path; import time; "
                           f"Path({str(ready)!r}).write_text('ready'); time.sleep(2.5)")
                process, receipt = self.spawn(payload, inject=inject, timing_scale=value)
                status, _, stderr = self.complete(process, timeout=10)
                if succeeds:
                    self.assertEqual(status, 0, stderr)
                else:
                    self.assertNotEqual(status, 0)
                    self.assertIn("telemetry deadline", self.failure(receipt)["detail"])

    def test_scaled_blocked_statvfs_is_still_bounded(self):
        ready = self.target / "scaled-blocked-sample"
        inject = f"""original_sample=m.filesystem_sample
def blocked_sample(paths):
    if pathlib.Path({str(ready)!r}).exists():
        time.sleep(20)
    return original_sample(paths)
m.filesystem_sample=blocked_sample"""
        started = time.monotonic()
        process, receipt = self.spawn(
            "from pathlib import Path; import time; "
            f"Path({str(ready)!r}).write_text('ready'); time.sleep(20)",
            inject=inject, timing_scale="2")
        self.complete(process, timeout=10)
        self.assertLess(time.monotonic() - started, 8)
        self.assertIn("telemetry deadline", self.failure(receipt)["detail"])

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
    Path({str(output)!r}).write_bytes(os.urandom({4*MIB}))
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
        for scale in ("1", "10"):
            with self.subTest(scale=scale):
                ready = self.target / ("writer-" + scale)
                payload = (
                    "from pathlib import Path; import os,signal,time; "
                    f"Path({str(ready)!r}).write_text(str(os.getpid())); "
                    "os.kill(os.getppid(),signal.SIGKILL); time.sleep(20)"
                )
                process, receipt = self.spawn(payload, timing_scale=scale)
                status, _, stderr = self.complete(process)
                self.assertNotEqual(status, 0)
                self.assertEqual(receipt.read_text(), "")
                diagnostic = json.loads(stderr.split("_DISK_GUARDIAN:", 1)[1])
                self.assertEqual(diagnostic["reason"], "supervisor_exit_unconfirmed")
                self.assertEqual(diagnostic["wait_status"], signal.SIGKILL)
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
        process, receipt = self.spawn(payload)
        status, stdout, stderr = self.complete(process)
        usage = json.loads(receipt.read_text().split("_DISK_USAGE:", 1)[1])
        if hasattr(os, "pidfd_open") and hasattr(signal, "pidfd_send_signal"):
            self.assertEqual(status, 0, stderr)
            self.assertTrue(usage["complete"])
        else:
            # Without a pinned process handle, the existing safety contract
            # cancels the owned group rather than risk a recycled PID.
            self.assertEqual(status, -signal.SIGKILL, stderr)
            self.assertEqual(self.failure(receipt)["reason"], "monitor_unavailable")
            self.assertFalse(usage["complete"])
        self.assertIn("foreground-ok", stdout)
        record = monitor.process_snapshot().get(int(ready.read_text()))
        self.assertTrue(record is None or record["state"] in ("Z", "X"))

    def test_execution_deadline_uses_existing_marker_and_stops_group(self):
        for scale in ("1", "10"):
            with self.subTest(scale=scale):
                ready = self.target / ("writer-" + scale)
                payload = (
                    "from pathlib import Path; import os,time; "
                    f"Path({str(ready)!r}).write_text(str(os.getpid())); time.sleep(20)"
                )
                process, receipt = self.spawn(
                    payload, timeout_seconds=1, timing_scale=scale)
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
        process, receipt = self.spawn(f"from pathlib import Path; import os,time; Path({str(ready)!r}).write_text(str(os.getpid())); Path({str(output)!r}).write_bytes(os.urandom({4*MIB})); time.sleep(20)", budget=2 * MIB, inject=inject)
        status, _, stderr = self.complete(process)
        self.assertNotEqual(status, 0)
        failures = [json.loads(line[len(MARKER):]) for line in stderr.splitlines()
                    if line.startswith(MARKER)]
        self.assertEqual(len(failures), 1, stderr)
        self.assertEqual(failures[0]["reason"], "growth")
        self.assertTrue(failures[0]["started"])
        self.assertEqual(receipt.read_text(), "")
        record = monitor.process_snapshot().get(int(ready.read_text()))
        self.assertTrue(record is None or record["state"] in ("Z", "X"))

    def test_receipt_serializer_exception_cannot_skip_group_cleanup(self):
        inject = """def broken_receipt(*args):
    raise RuntimeError('receipt serialization failed')
m.receipts_for_failure=broken_receipt"""
        ready = self.target / "writer"
        output = self.target / "large"
        process, receipt = self.spawn(f"from pathlib import Path; import os,time; Path({str(ready)!r}).write_text(str(os.getpid())); Path({str(output)!r}).write_bytes(os.urandom({4*MIB})); time.sleep(20)", budget=2 * MIB, inject=inject)
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

    def test_terminal_census_progress_keeps_guardian_live(self):
        # Delay real procfs records only during finalization. The whole census
        # takes longer than the heartbeat deadline, but each read progresses.
        # Keep the real namespace, membership, writer cleanup and receipts.
        inject = """original_finish=m.finish_descendants
original_process=m.linux_process
remaining=0
def process(path):
    global remaining
    result=original_process(path)
    if remaining:
        remaining-=1
        time.sleep(0.6)
    return result
def finish(value, heartbeat):
    global remaining
    remaining=7
    return original_finish(value, heartbeat)
m.linux_process=process
m.finish_descendants=finish"""
        if not sys.platform.startswith("linux"):
            self.skipTest("procfs record scheduling probe")
        process, receipt = self.spawn("print('foreground-finished')", inject=inject)
        status, stdout, stderr = self.complete(process, timeout=15)
        self.assertEqual(status, 0, stderr)
        self.assertIn("foreground-finished", stdout)
        usage = json.loads(receipt.read_text().split("_DISK_USAGE:", 1)[1])
        self.assertTrue(usage["complete"])
        self.assertEqual(usage["exit_code"], 0)

    def test_slow_terminal_census_still_verifies_killed_background_writer(self):
        if not sys.platform.startswith("linux"):
            self.skipTest("procfs record scheduling probe")
        inject = """original_finish=m.finish_descendants
original_snapshot=m.process_snapshot
def finish(value, heartbeat):
    first=True
    def slow_snapshot(beat=lambda: None):
        nonlocal first
        result=original_snapshot(beat)
        if first:
            first=False
            for _ in range(12):
                beat()
                time.sleep(0.2)
        return result
    m.process_snapshot=slow_snapshot
    return original_finish(value, heartbeat)
m.finish_descendants=finish"""
        process, receipt = self.spawn(
            "import subprocess,sys; subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(30)']); print('foreground-finished')",
            inject=inject)
        status, stdout, stderr = self.complete(process, timeout=20)
        self.assertEqual(status, 0, stderr)
        self.assertIn("foreground-finished", stdout)
        usage = json.loads(receipt.read_text().split("_DISK_USAGE:", 1)[1])
        self.assertTrue(usage["complete"])
        self.assertEqual(usage["exit_code"], 0)

    def test_terminal_census_stalled_read_still_stops_group(self):
        inject = """original_finish=m.finish_descendants
original_process=m.linux_process
def finish(value, heartbeat):
    def stalled(path):
        time.sleep(20)
        return original_process(path)
    m.linux_process=stalled
    return original_finish(value, heartbeat)
m.finish_descendants=finish"""
        if not sys.platform.startswith("linux"):
            self.skipTest("procfs record scheduling probe")
        process, receipt = self.spawn("print('foreground-finished')", inject=inject)
        status, stdout, stderr = self.complete(process, timeout=8)
        self.assertNotEqual(status, 0, stderr)
        self.assertIn("foreground-finished", stdout)
        self.assertEqual(receipt.read_text(), "")
        diagnostic = json.loads(stderr.split("_DISK_GUARDIAN:", 1)[1])
        self.assertEqual(diagnostic["reason"], "heartbeat_timeout")
        self.assertTrue(diagnostic["started"])


if __name__ == "__main__":
    unittest.main()
