#!/usr/bin/env python3
"""Verify benchmark results meet AGENTS.md performance budgets.

Performance requirements:
- Non-compilation decision: < 1ms (1,000,000 ns)
- Compilation decision: < 5ms (5,000,000 ns)

In practice, classify_command should be in microsecond range.
"""
import json
import sys
from pathlib import Path


# Performance budgets from AGENTS.md (in nanoseconds)
# These are conservative budgets; actual performance should be much better
BUDGETS = {
    # Non-compilation commands should be very fast
    "classifier/tier0_reject": 100_000,        # 100µs (conservative)
    "classifier/structure_reject": 500_000,    # 500µs

    # Compilation matching can take slightly longer
    "classifier/compilation_match": 500_000,   # 500µs
    "classifier/never_intercept": 500_000,     # 500µs
    "classifier/complex": 1_000_000,           # 1ms

    # Batch throughput (100 commands)
    "classifier/batch_100": 10_000_000,        # 10ms for 100 commands = 100µs/cmd
}


def find_criterion_results(base_dir: Path) -> dict[str, dict]:
    """Find and parse criterion benchmark results."""
    results = {}

    for bench_dir in base_dir.glob("**/new/estimates.json"):
        # Extract benchmark name from path
        # Path structure: target/criterion/<group>/<benchmark>/new/estimates.json
        parts = bench_dir.relative_to(base_dir).parts
        if len(parts) >= 3:
            group_name = parts[0]
            results[group_name] = parse_estimates(bench_dir)

    return results


def parse_estimates(estimates_file: Path) -> dict:
    """Parse criterion estimates.json file."""
    try:
        with open(estimates_file) as f:
            data = json.load(f)
        return {
            "mean": data.get("mean", {}).get("point_estimate", 0),
            "median": data.get("median", {}).get("point_estimate", 0),
            "std_dev": data.get("std_dev", {}).get("point_estimate", 0),
        }
    except (json.JSONDecodeError, FileNotFoundError) as e:
        print(f"Warning: Could not parse {estimates_file}: {e}")
        return {}


def check_budgets(criterion_dir: Path) -> tuple[list[str], list[str]]:
    """Check benchmark results against budgets.

    Returns (passed, failed) lists of benchmark descriptions.
    """
    passed = []
    failed = []

    # Find all benchmark group directories
    for group_path in criterion_dir.iterdir():
        if not group_path.is_dir():
            continue

        group_name = group_path.name

        # Check if this group has any budgets
        matching_budgets = [(name, budget) for name, budget in BUDGETS.items()
                          if group_name.startswith(name) or name == group_name]

        if not matching_budgets:
            continue

        # Find estimates for this group
        estimates_file = group_path / "new" / "estimates.json"
        if not estimates_file.exists():
            # Try to find in subdirectories (for parameterized benchmarks)
            for sub in group_path.iterdir():
                if sub.is_dir():
                    sub_estimates = sub / "new" / "estimates.json"
                    if sub_estimates.exists():
                        estimates_file = sub_estimates
                        break

        if not estimates_file.exists():
            print(f"Warning: No estimates found for {group_name}")
            continue

        estimates = parse_estimates(estimates_file)
        if not estimates:
            continue

        mean_ns = estimates.get("mean", 0)

        for budget_name, budget_ns in matching_budgets:
            if budget_name == group_name or group_name.startswith(budget_name):
                if mean_ns <= budget_ns:
                    passed.append(
                        f"{group_name}: {mean_ns/1e3:.2f}µs <= {budget_ns/1e3:.2f}µs budget"
                    )
                else:
                    failed.append(
                        f"{group_name}: {mean_ns/1e3:.2f}µs > {budget_ns/1e3:.2f}µs budget"
                    )
                break

    return passed, failed


def write_summary(criterion_dir: Path, passed: list[str], failed: list[str]):
    """Write a summary file for CI reporting."""
    summary_file = criterion_dir / "summary.txt"

    with open(summary_file, "w") as f:
        f.write("RCH Performance Budget Verification\n")
        f.write("=" * 40 + "\n\n")

        if passed:
            f.write("PASSED:\n")
            for p in passed:
                f.write(f"  OK: {p}\n")
            f.write("\n")

        if failed:
            f.write("FAILED:\n")
            for fail in failed:
                f.write(f"  FAIL: {fail}\n")
            f.write("\n")

        f.write(f"\nTotal: {len(passed)} passed, {len(failed)} failed\n")


def main():
    """Main entry point."""
    # Find criterion results directory
    criterion_dir = Path("target/criterion")

    if not criterion_dir.exists():
        print("Warning: target/criterion not found - skipping budget verification")
        print("Run 'cargo bench' first to generate benchmark results")
        sys.exit(0)

    print("Checking performance budgets from AGENTS.md...")
    print()

    passed, failed = check_budgets(criterion_dir)

    if passed:
        print("PASSED:")
        for p in passed:
            print(f"  OK: {p}")
        print()

    if failed:
        print("FAILED:")
        for f in failed:
            print(f"  FAIL: {f}")
        print()

    # Write summary for CI
    write_summary(criterion_dir, passed, failed)

    print(f"Total: {len(passed)} passed, {len(failed)} failed")

    if failed:
        print("\nPERFORMANCE BUDGET VIOLATIONS DETECTED")
        print("See AGENTS.md for performance requirements")
        sys.exit(1)

    if not passed and not failed:
        print("No benchmark results matched any budget patterns")
        print("This may be normal if benchmarks haven't been run yet")
    else:
        print("\nAll performance budgets met!")


if __name__ == "__main__":
    main()
