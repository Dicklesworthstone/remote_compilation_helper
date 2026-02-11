#!/usr/bin/env python3
"""Test performance regression detection.

Parses JSONL test logs from target/test-logs/, extracts test durations,
compares against stored baselines, and reports regressions.

This script implements bd-2ee4: Create test performance regression detection.

Usage:
    # Check for regressions against stored baseline
    python3 scripts/check_test_regression.py

    # Update the baseline with current results
    python3 scripts/check_test_regression.py --update-baseline

    # Show verbose output
    python3 scripts/check_test_regression.py --verbose

    # Set custom regression threshold (default: 20%)
    python3 scripts/check_test_regression.py --threshold 1.25

Exit codes:
    0 - No regressions detected (or baseline updated)
    1 - Regressions detected
    2 - Error (e.g., no logs found)
"""
import argparse
import json
import sys
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from statistics import mean, median, stdev


# Configuration
DEFAULT_LOG_DIR = Path("target/test-logs")
BASELINE_FILE = Path(".baselines/test_performance_baseline.json")
DEFAULT_THRESHOLD = 1.20  # 20% regression threshold
MIN_SAMPLES_FOR_BASELINE = 3  # Minimum samples to consider for baseline
OUTLIER_PERCENTILE = 95  # Use p95 for comparison to ignore outliers


@dataclass
class TestTiming:
    """Timing data for a single test execution."""
    test_name: str
    duration_ms: int
    timestamp: str
    platform: str = ""


@dataclass
class TestBaseline:
    """Historical baseline for a test."""
    test_name: str
    mean_ms: float
    median_ms: float
    p95_ms: float
    stddev_ms: float
    sample_count: int
    last_updated: str
    platform: str = ""


@dataclass
class RegressionReport:
    """Report of detected regressions."""
    regressions: list[dict] = field(default_factory=list)
    improvements: list[dict] = field(default_factory=list)
    new_tests: list[dict] = field(default_factory=list)
    total_tests: int = 0
    passed: int = 0
    failed: int = 0


def detect_platform() -> str:
    """Detect the current platform."""
    import platform as plat
    system = plat.system().lower()
    machine = plat.machine().lower()

    # Normalize architecture
    if machine in ("x86_64", "amd64"):
        arch = "x64"
    elif machine in ("aarch64", "arm64"):
        arch = "arm64"
    else:
        arch = machine

    return f"{system}-{arch}"


def parse_jsonl_logs(log_dir: Path) -> list[TestTiming]:
    """Parse all JSONL log files and extract test timings."""
    timings = []
    platform = detect_platform()

    if not log_dir.exists():
        return timings

    for log_file in log_dir.glob("*.jsonl"):
        try:
            with open(log_file, "r") as f:
                entries = [json.loads(line) for line in f if line.strip()]

            # Extract test name from filename (format: test_name_YYYYMMDD_HHMMSS.jsonl)
            filename = log_file.stem
            # Remove timestamp suffix if present
            parts = filename.rsplit("_", 2)
            if len(parts) >= 3 and len(parts[-1]) == 6 and len(parts[-2]) == 8:
                # Has timestamp suffix
                test_name = "_".join(parts[:-2])
            else:
                test_name = filename

            # Find the max duration in the log (represents total test time)
            max_duration_ms = 0
            timestamp = ""

            for entry in entries:
                # Handle both E2E logger format and global test logger format
                duration = entry.get("duration_ms") or entry.get("elapsed_ms") or 0
                if duration > max_duration_ms:
                    max_duration_ms = duration
                    timestamp = entry.get("timestamp", "")

                # Also check for TestResult format with explicit duration
                if "test_name" in entry and entry.get("duration_ms"):
                    test_name = entry["test_name"]

            if max_duration_ms > 0:
                timings.append(TestTiming(
                    test_name=test_name,
                    duration_ms=max_duration_ms,
                    timestamp=timestamp,
                    platform=platform,
                ))

        except (json.JSONDecodeError, IOError) as e:
            print(f"Warning: Could not parse {log_file}: {e}", file=sys.stderr)

    return timings


def aggregate_timings(timings: list[TestTiming]) -> dict[str, list[int]]:
    """Aggregate timings by test name."""
    aggregated: dict[str, list[int]] = defaultdict(list)
    for timing in timings:
        aggregated[timing.test_name].append(timing.duration_ms)
    return dict(aggregated)


def calculate_percentile(values: list[int], percentile: float) -> float:
    """Calculate a percentile value."""
    if not values:
        return 0.0
    sorted_values = sorted(values)
    k = (len(sorted_values) - 1) * (percentile / 100.0)
    f = int(k)
    c = f + 1 if f + 1 < len(sorted_values) else f
    return sorted_values[f] + (k - f) * (sorted_values[c] - sorted_values[f])


def load_baseline(baseline_file: Path) -> dict[str, TestBaseline]:
    """Load baseline from JSON file."""
    baselines = {}

    if not baseline_file.exists():
        return baselines

    try:
        with open(baseline_file, "r") as f:
            data = json.load(f)

        for name, values in data.get("tests", {}).items():
            baselines[name] = TestBaseline(
                test_name=name,
                mean_ms=values.get("mean_ms", 0),
                median_ms=values.get("median_ms", 0),
                p95_ms=values.get("p95_ms", 0),
                stddev_ms=values.get("stddev_ms", 0),
                sample_count=values.get("sample_count", 0),
                last_updated=values.get("last_updated", ""),
                platform=values.get("platform", ""),
            )
    except (json.JSONDecodeError, IOError) as e:
        print(f"Warning: Could not load baseline: {e}", file=sys.stderr)

    return baselines


def save_baseline(baseline_file: Path, timings: list[TestTiming]) -> None:
    """Save current timings as the new baseline."""
    baseline_file.parent.mkdir(parents=True, exist_ok=True)

    aggregated = aggregate_timings(timings)
    now = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    platform = detect_platform()

    tests = {}
    for name, durations in aggregated.items():
        if len(durations) < MIN_SAMPLES_FOR_BASELINE:
            # Not enough samples, use the durations we have
            pass

        tests[name] = {
            "mean_ms": round(mean(durations), 2) if durations else 0,
            "median_ms": round(median(durations), 2) if durations else 0,
            "p95_ms": round(calculate_percentile(durations, OUTLIER_PERCENTILE), 2),
            "stddev_ms": round(stdev(durations), 2) if len(durations) > 1 else 0,
            "sample_count": len(durations),
            "last_updated": now,
            "platform": platform,
        }

    data = {
        "version": "1.0",
        "generated_at": now,
        "platform": platform,
        "threshold": DEFAULT_THRESHOLD,
        "tests": tests,
    }

    with open(baseline_file, "w") as f:
        json.dump(data, f, indent=2)
        f.write("\n")

    print(f"Baseline saved to {baseline_file}")
    print(f"  Tests: {len(tests)}")
    print(f"  Platform: {platform}")


def check_regressions(
    timings: list[TestTiming],
    baselines: dict[str, TestBaseline],
    threshold: float,
) -> RegressionReport:
    """Check current timings against baselines for regressions."""
    report = RegressionReport()
    aggregated = aggregate_timings(timings)
    platform = detect_platform()

    report.total_tests = len(aggregated)

    for test_name, durations in aggregated.items():
        current_p95 = calculate_percentile(durations, OUTLIER_PERCENTILE)
        current_mean = mean(durations) if durations else 0

        if test_name not in baselines:
            # New test, no baseline to compare
            report.new_tests.append({
                "test_name": test_name,
                "current_p95_ms": round(current_p95, 2),
                "current_mean_ms": round(current_mean, 2),
                "samples": len(durations),
            })
            continue

        baseline = baselines[test_name]

        # Check platform compatibility
        if baseline.platform and baseline.platform != platform:
            # Different platform, skip comparison
            report.new_tests.append({
                "test_name": test_name,
                "current_p95_ms": round(current_p95, 2),
                "reason": f"platform mismatch (baseline: {baseline.platform}, current: {platform})",
            })
            continue

        # Compare p95 against baseline p95
        if baseline.p95_ms > 0:
            ratio = current_p95 / baseline.p95_ms

            if ratio > threshold:
                # Regression detected
                report.failed += 1
                report.regressions.append({
                    "test_name": test_name,
                    "baseline_p95_ms": baseline.p95_ms,
                    "current_p95_ms": round(current_p95, 2),
                    "ratio": round(ratio, 2),
                    "threshold": threshold,
                    "regression_pct": round((ratio - 1) * 100, 1),
                })
            elif ratio < (1 / threshold):
                # Improvement detected
                report.passed += 1
                report.improvements.append({
                    "test_name": test_name,
                    "baseline_p95_ms": baseline.p95_ms,
                    "current_p95_ms": round(current_p95, 2),
                    "ratio": round(ratio, 2),
                    "improvement_pct": round((1 - ratio) * 100, 1),
                })
            else:
                # Within threshold
                report.passed += 1
        else:
            # No valid baseline p95
            report.new_tests.append({
                "test_name": test_name,
                "current_p95_ms": round(current_p95, 2),
                "reason": "no baseline p95",
            })

    return report


def print_report(report: RegressionReport, verbose: bool = False) -> None:
    """Print the regression report."""
    print("\n" + "=" * 60)
    print("Test Performance Regression Report")
    print("=" * 60 + "\n")

    # Summary
    print(f"Total tests analyzed: {report.total_tests}")
    print(f"  Passed: {report.passed}")
    print(f"  Failed: {report.failed}")
    print(f"  New (no baseline): {len(report.new_tests)}")
    print()

    # Regressions (always shown)
    if report.regressions:
        print("REGRESSIONS DETECTED:")
        for reg in sorted(report.regressions, key=lambda x: x["ratio"], reverse=True):
            print(f"  FAIL: {reg['test_name']}")
            print(f"        baseline p95: {reg['baseline_p95_ms']:.1f}ms")
            print(f"        current p95:  {reg['current_p95_ms']:.1f}ms")
            print(f"        regression:   +{reg['regression_pct']:.1f}%")
            print()
    else:
        print("No regressions detected.")
        print()

    # Improvements (verbose)
    if verbose and report.improvements:
        print("\nIMPROVEMENTS:")
        for imp in sorted(report.improvements, key=lambda x: x["ratio"]):
            print(f"  OK: {imp['test_name']}")
            print(f"      baseline p95: {imp['baseline_p95_ms']:.1f}ms")
            print(f"      current p95:  {imp['current_p95_ms']:.1f}ms")
            print(f"      improvement:  -{imp['improvement_pct']:.1f}%")
        print()

    # New tests (verbose)
    if verbose and report.new_tests:
        print("\nNEW TESTS (no baseline):")
        for new in report.new_tests:
            print(f"  NEW: {new['test_name']}")
            print(f"       current p95: {new.get('current_p95_ms', 'N/A')}ms")
            if "reason" in new:
                print(f"       reason: {new['reason']}")
        print()


def write_json_report(report: RegressionReport, output_file: Path) -> None:
    """Write the report in JSON format."""
    data = {
        "generated_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "platform": detect_platform(),
        "summary": {
            "total_tests": report.total_tests,
            "passed": report.passed,
            "failed": report.failed,
            "new_tests": len(report.new_tests),
        },
        "regressions": report.regressions,
        "improvements": report.improvements,
        "new_tests": report.new_tests,
    }

    output_file.parent.mkdir(parents=True, exist_ok=True)
    with open(output_file, "w") as f:
        json.dump(data, f, indent=2)
        f.write("\n")

    print(f"JSON report written to {output_file}")


def main() -> int:
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description="Test performance regression detection",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument(
        "--log-dir",
        type=Path,
        default=DEFAULT_LOG_DIR,
        help=f"Directory containing JSONL test logs (default: {DEFAULT_LOG_DIR})",
    )
    parser.add_argument(
        "--baseline",
        type=Path,
        default=BASELINE_FILE,
        help=f"Baseline file path (default: {BASELINE_FILE})",
    )
    parser.add_argument(
        "--threshold",
        type=float,
        default=DEFAULT_THRESHOLD,
        help=f"Regression threshold as ratio (default: {DEFAULT_THRESHOLD} = {(DEFAULT_THRESHOLD-1)*100:.0f}%% slower)",
    )
    parser.add_argument(
        "--update-baseline",
        action="store_true",
        help="Update the baseline with current results",
    )
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Show detailed output including improvements and new tests",
    )
    parser.add_argument(
        "--json-output",
        type=Path,
        help="Write JSON report to this file",
    )
    parser.add_argument(
        "--ci",
        action="store_true",
        help="CI mode: fail on any regression",
    )

    args = parser.parse_args()

    # Parse test logs
    print(f"Parsing test logs from {args.log_dir}...")
    timings = parse_jsonl_logs(args.log_dir)

    if not timings:
        print(f"Warning: No test logs found in {args.log_dir}")
        if args.ci:
            # In CI, missing logs is an error
            return 2
        return 0

    print(f"Found {len(timings)} test timing(s)")

    # Update baseline mode
    if args.update_baseline:
        save_baseline(args.baseline, timings)
        return 0

    # Load baseline and check for regressions
    print(f"Loading baseline from {args.baseline}...")
    baselines = load_baseline(args.baseline)

    if not baselines:
        print("No baseline found. Run with --update-baseline to create one.")
        if args.ci:
            return 2
        return 0

    print(f"Loaded {len(baselines)} baseline(s)")

    # Check for regressions
    report = check_regressions(timings, baselines, args.threshold)

    # Print report
    print_report(report, verbose=args.verbose)

    # Write JSON report if requested
    if args.json_output:
        write_json_report(report, args.json_output)

    # Exit code
    if report.failed > 0:
        print(f"\nPERFORMANCE REGRESSION DETECTED: {report.failed} test(s) exceeded threshold")
        return 1

    print("\nAll performance checks passed!")
    return 0


if __name__ == "__main__":
    sys.exit(main())
