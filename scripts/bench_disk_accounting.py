#!/usr/bin/env python3
"""Pair original and candidate production disk accounting on real local files.

Example:
    python3 scripts/bench_disk_accounting.py \
      --baseline-monitor /path/to/original/build_disk_monitor.py \
      --candidate-monitor rch-common/build_disk_monitor.py \
      --work-dir /path/to/writable/filesystem --output /path/to/results.json

This imports the supplied monitor sources without modifying them. It exercises
scan/accounting methods with a synthetic observer identity, never bypassing
process-namespace verification to launch a guarded build. It does not qualify
SSH, durable worker reservations, source transfer, or live remote Cargo builds.
Fixtures are retained; the benchmark does not fill or clean a filesystem.
"""

import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import resource
import statistics
import subprocess
import sys
import tempfile
import time

MIB = 1 << 20
MARKER = "RCH_BENCH_DISK_BUDGET:"
modules = {}


def scan(name, target, outputs=None, baseline_records=None):
    module = modules[name]
    paths = [str(path) for path in outputs or [target]]
    if name == "baseline":
        return module.measure_outputs(paths)
    return module.measure_outputs(paths, str(target), baseline_records)


def size(name, value):
    return value if name == "baseline" else value.total


def observer(name, target, budget=128 * MIB, outputs=None):
    module = modules[name]
    value = module.Monitor.__new__(module.Monitor)
    initial = scan(name, target, outputs)
    value.budget, value.floor = budget, MIB
    value.baseline = value.peak_output = size(name, initial)
    value.peak_growth = 0
    free = module.filesystem_sample([str(target)])
    value.devices = set(free)
    value.floors = {device: MIB for device in free}
    value.free, value.previous = dict(free), None
    if name == "candidate":
        # This identity cannot authorize a worker or attest its process group.
        value.pool_identity = [1] * 32
        value.baseline_records, value.incremental_reliable = initial.records, True
        value.baseline_pool = value.final_pool = value.pool_observation(initial)
        value.admitted_pool = None
        value.peak_added = 0
        value.unproven_baseline = 0
        value.strict_tracking = False
        value.free_start, value.free_min = dict(free), dict(free)
    return value


def allocate(path, count):
    block = b"x" * MIB
    with path.open("wb") as stream:
        for _ in range(count // MIB):
            stream.write(block)
        stream.write(block[:count % MIB])
        stream.flush()
        os.fsync(stream.fileno())


def observe(value, name, target):
    value.observe_output(scan(name, target, baseline_records=getattr(value, "baseline_records", None)))
    value.observe_free(modules[name].filesystem_sample([str(target)]), time.monotonic())


def metrics(name, value):
    result = {
        "starting_allocated_bytes": value.baseline,
        "peak_total_output_bytes": value.peak_output,
        "peak_growth_bytes": value.peak_growth,
    }
    if name == "candidate":
        _, usage = modules[name].usage_receipt(MARKER, value, True, 0)
        result.update(
            peak_added_output_bytes=value.peak_added,
            peak_free_drop_bytes=sum(
                max(0, start - value.free_min[device])
                for device, start in value.free_start.items()
            ),
            incremental_receipt_available=usage["incremental"] is not None,
        )
    return result


def benchmark(root, sources, pressure_probe):
    provenance = {}
    for name, source in sources.items():
        data = source.read_bytes()
        spec = importlib.util.spec_from_file_location(name, source)
        module = importlib.util.module_from_spec(spec)
        exec(compile(data, str(source), "exec"), module.__dict__)
        modules[name] = module
        provenance[name] = {
            "path": str(source), "sha256": hashlib.sha256(data).hexdigest()
        }
    results = {
        "scope": "Executed original/candidate accounting and scan microbenchmark on local files. Production functions loaded unmodified from captured source bytes. Observer identity is synthetic; this does not qualify process supervision, durable worker admission, SSH, or live remote Cargo admission.",
        "sources": provenance,
        "fixture_root": str(root),
        "cases": {},
    }
    for case in ["warm", "cold", "cleanup", "overlap", "retained_modified"]:
        target = root / case / "target"
        target.mkdir(parents=True)
        if case != "cold":
            allocate(target / "retained", 16 * MIB)
        values = {name: observer(name, target) for name in sources}
        free_before = modules["candidate"].filesystem_sample([str(target)])
        if case == "cleanup":
            # Truncate only our fixture, really freeing its allocated blocks.
            allocate(target / "retained", 0)
        if case == "retained_modified":
            allocate(target / "retained", 16 * MIB)
        elif case == "overlap":
            gate = target.parent / "start"
            children = []
            for index in range(3):
                program = (
                    "from pathlib import Path; import os,time\n"
                    f"gate=Path({str(gate)!r})\n"
                    "while not gate.exists(): time.sleep(0.005)\n"
                    f"with open({str(target / ('new-' + str(index)))!r},'wb') as f:\n"
                    " f.write(b'x'*(1<<20)); f.flush(); os.fsync(f.fileno())\n"
                    "time.sleep(0.15)\n"
                )
                children.append(subprocess.Popen([sys.executable, "-I", "-S", "-c", program]))
            gate.write_text("start", encoding="ascii")
            while any(child.poll() is None for child in children):
                for name, value in values.items():
                    observe(value, name, target)
                time.sleep(0.01)
            assert all(child.wait() == 0 for child in children)
        else:
            allocate(target / "new-output", MIB)
        for name, value in values.items():
            observe(value, name, target)
        free_after = modules["candidate"].filesystem_sample([str(target)])
        results["cases"][case] = {
            name: metrics(name, value) for name, value in values.items()
        }
        results["cases"][case]["measured_free_delta_bytes"] = sum(
            free_before[d] - free_after[d] for d in free_before
        )
        results["cases"][case]["scope"] = (
            "Three real child writers with overlapping lifetimes write to one shared target. Both observers cover all writers; no per-writer attribution claim."
            if case == "overlap" else "Allocated files and actual statvfs samples."
        )

    # Alternate call order against the identical tree in this invocation.
    target = root / "scan-performance" / "target"
    target.mkdir(parents=True)
    for number in range(2048):
        allocate(target / f"artifact-{number:05}", 4096)
    raw = {"baseline": [], "candidate": []}
    for repeat in range(15):
        order = ["baseline", "candidate"] if repeat % 2 == 0 else ["candidate", "baseline"]
        for name in order:
            start = time.perf_counter_ns()
            sample = scan(name, target)
            elapsed = (time.perf_counter_ns() - start) / 1e6
            raw[name].append(elapsed)
            assert size(name, sample) >= 2048 * 4096
    results["scan_performance"] = {
        "files": 2048,
        "runs_per_variant": 15,
        "raw_ms": raw,
        "median_ms": {name: statistics.median(values) for name, values in raw.items()},
        "scope": "One complete output scan including candidate signatures and hash. No end-to-end performance claim.",
    }

    # Only the proven target receives credit; source/cache roots stay charged.
    target = root / "unpooled-baseline" / "target"
    source = root / "unpooled-baseline" / "other-output"
    target.mkdir(parents=True)
    source.mkdir()
    allocate(target / "retained", 16 * MIB)
    allocate(source / "unproven-retained", 4 * MIB)
    values = {name: observer(name, target, outputs=[source, target]) for name in sources}
    candidate = values["candidate"]
    candidate.require_warm_pool({
        "cold_growth_bytes": 256 * MIB,
        "pools": [candidate.baseline_pool] + [None] * 7,
    })
    allocate(target / "new-output", MIB)
    for name, value in values.items():
        value.observe_output(scan(name, target, [source, target], getattr(value, "baseline_records", None)))
        value.observe_free(
            modules[name].filesystem_sample([str(target), str(source)]), time.monotonic()
        )
    results["cases"]["unpooled_baseline"] = {
        name: metrics(name, value) for name, value in values.items()
    }
    results["cases"]["unpooled_baseline"].update(
        proven_target_retained_bytes=candidate.baseline_pool["retained_bytes"],
        unproven_baseline_bytes=candidate.unproven_baseline,
        scope="Real target 16 MiB plus separate output root 4 MiB, then 1 MiB added. Production require_warm_pool uses a synthetic observer identity: this is an accounting proof fixture, not verified worker admission.",
    )

    # The original transfer plan omitted the worker's durable Cargo home.
    # Bind it through the candidate's actual worker-side resolver and compare
    # both accounting paths on the same cleanup and cache-write sequence.
    if hasattr(modules["candidate"], "prepare_cargo_cache_roots"):
        target = root / "cargo-cache-cleanup" / "target"
        base = target.parent / "worker-cache-base"
        target.mkdir(parents=True)
        base.mkdir()
        plan = {"name": "rch-cargo-cache-benchmark", "additional_home": None,
                "verified": True}
        previous_base = os.environ.get("RCH_CH_BASE")
        try:
            os.environ["RCH_CH_BASE"] = str(base)
            cache_roots, aliases = modules["candidate"].prepare_cargo_cache_roots(plan)
        finally:
            if previous_base is None:
                os.environ.pop("RCH_CH_BASE", None)
            else:
                os.environ["RCH_CH_BASE"] = previous_base
        allocate(target / "retained", 16 * MIB)
        outputs = {"baseline": [target], "candidate": [target] + cache_roots}
        values = {name: observer(name, target, 4 * MIB, outputs[name]) for name in sources}
        candidate = values["candidate"]
        candidate.require_warm_pool({
            "cold_growth_bytes": 32 * MIB,
            "pools": [candidate.baseline_pool] + [None] * 7,
        })
        free_before = modules["candidate"].filesystem_sample(outputs["candidate"])
        allocate(target / "retained", 0)
        allocate(base / plan["name"] / "registry" / "download", 8 * MIB)
        modules["candidate"].verify_cargo_cache_bindings(aliases)
        decisions = {}
        for name, value in values.items():
            try:
                value.observe_output(scan(name, target, outputs[name], getattr(value, "baseline_records", None)))
                decisions[name] = "allowed"
            except modules[name].BudgetFailure as error:
                decisions[name] = error.reason
        free_after = modules["candidate"].filesystem_sample(outputs["candidate"])
        results["cases"]["cargo_cache_cleanup"] = {
            name: dict(metrics(name, value), output_guard_result=decisions[name])
            for name, value in values.items()
        }
        results["cases"]["cargo_cache_cleanup"].update(
            budget_bytes=4 * MIB,
            cache_write_bytes=8 * MIB,
            final_actual_allocated_bytes=scan("candidate", target, outputs["candidate"]).total,
            measured_free_delta_bytes=sum(free_before[d] - free_after[d] for d in free_before),
            cache_roots=cache_roots,
            scope="Actual 16 MiB retained target is truncated and 8 MiB is written into a separate durable Cargo home under a 4 MiB budget. Original target-only accounting and candidate cache-root accounting observe the same files. Production cache resolver and output guard execute; observer identity remains synthetic and no guarded workload is launched.",
        )

    # Observe the requested volume without writing to or filling it.
    actual = modules["candidate"].filesystem_sample([str(pressure_probe)])
    value = observer("candidate", root / "cold" / "target")
    value.devices, value.floors, value.previous = set(actual), {d: MIB for d in actual}, None
    value.free_min, value.free_start = dict(actual), dict(actual)
    try:
        value.observe_free(actual, time.monotonic())
        reason = "allowed"
    except modules["candidate"].BudgetFailure as error:
        reason = error.reason
    results["actual_disk_pressure"] = {
        "probe": str(pressure_probe),
        "available_bytes_by_device": {str(k): v for k, v in actual.items()},
        "floor_bytes": MIB,
        "observed_guard_result": reason,
        "scope": "Production floor observation with actual statvfs; process launch excluded.",
    }
    for name, module in modules.items():
        try:
            module.boot_identity()
            status = "verified"
        except Exception as error:
            status = type(error).__name__ + ": " + str(error)
        results.setdefault("process_facility", {})[name] = status
    return results


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--baseline-monitor", type=Path, required=True)
    parser.add_argument("--candidate-monitor", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--work-dir", type=Path, help="Parent for retained benchmark fixtures; defaults to the system temporary directory")
    parser.add_argument("--pressure-probe", type=Path, help="Read-only statvfs probe; defaults to the baseline monitor's directory")
    args = parser.parse_args()
    resource.setrlimit(resource.RLIMIT_AS, (256 << 20, 256 << 20))
    sys.dont_write_bytecode = True
    sources = {
        "baseline": args.baseline_monitor.resolve(strict=True),
        "candidate": args.candidate_monitor.resolve(strict=True),
    }
    root = Path(tempfile.mkdtemp(prefix="rch-accounting-bench-", dir=args.work_dir)).resolve()
    pressure = (args.pressure_probe or sources["baseline"].parent).resolve(strict=True)
    results = benchmark(root, sources, pressure)
    output = args.output.resolve()
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(results, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"output": str(output), "fixture_root": str(root),
                      "scan_median_ms": results["scan_performance"]["median_ms"]}))


if __name__ == "__main__":
    main()
