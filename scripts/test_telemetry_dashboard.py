#!/usr/bin/env python3
"""
Test Telemetry Dashboard - Parses JSONL test outputs and displays summary statistics.

Usage:
    ./scripts/test_telemetry_dashboard.py [--dir PATH] [--format {text,json,summary}]

This tool parses JSONL log files from test runs and provides:
- Log level distribution (DEBUG, INFO, WARN, ERROR)
- Test pass/fail counts
- Timing statistics
- Alert summaries
- Per-test breakdown
"""

import argparse
import json
import sys
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional


@dataclass
class TestResult:
    """Represents a single test's results."""
    name: str
    passed: bool = False
    start_time: Optional[datetime] = None
    end_time: Optional[datetime] = None
    duration_ms: Optional[float] = None
    log_count: int = 0
    error_count: int = 0
    warn_count: int = 0


@dataclass
class TelemetrySummary:
    """Aggregated telemetry summary."""
    total_logs: int = 0
    level_counts: Dict[str, int] = field(default_factory=lambda: defaultdict(int))
    source_counts: Dict[str, int] = field(default_factory=lambda: defaultdict(int))
    target_counts: Dict[str, int] = field(default_factory=lambda: defaultdict(int))
    alert_kinds: Dict[str, int] = field(default_factory=lambda: defaultdict(int))
    alert_severities: Dict[str, int] = field(default_factory=lambda: defaultdict(int))
    tests: Dict[str, TestResult] = field(default_factory=dict)
    earliest_timestamp: Optional[datetime] = None
    latest_timestamp: Optional[datetime] = None
    files_processed: List[str] = field(default_factory=list)


def parse_timestamp(ts_str: str) -> Optional[datetime]:
    """Parse ISO 8601 timestamp from JSONL."""
    if not ts_str:
        return None
    try:
        # Handle timestamps with varying precision
        ts_str = ts_str.rstrip('Z')
        if '.' in ts_str:
            # Truncate nanoseconds to microseconds
            main, frac = ts_str.split('.')
            frac = frac[:6]  # Keep only 6 decimal places
            ts_str = f"{main}.{frac}"
        return datetime.fromisoformat(ts_str)
    except (ValueError, TypeError):
        return None


def parse_individual_test_log(entry: dict, summary: TelemetrySummary) -> None:
    """Parse an entry from individual test log format (test_guard! output)."""
    summary.total_logs += 1

    # Level counts
    level = entry.get('level', 'unknown')
    if isinstance(level, str):
        level = level.upper()
    else:
        level = str(level).upper()
    summary.level_counts[level] += 1

    # Source counts
    source = entry.get('source', 'unknown')
    if isinstance(source, dict):
        # Handle structured source like {'custom': 'smoke'}
        source = json.dumps(source, sort_keys=True)
    elif not isinstance(source, str):
        source = str(source)
    summary.source_counts[source] += 1

    # Timestamp tracking
    ts = parse_timestamp(entry.get('timestamp', ''))
    if ts:
        if summary.earliest_timestamp is None or ts < summary.earliest_timestamp:
            summary.earliest_timestamp = ts
        if summary.latest_timestamp is None or ts > summary.latest_timestamp:
            summary.latest_timestamp = ts


def parse_aggregated_log(entry: dict, summary: TelemetrySummary) -> None:
    """Parse an entry from aggregated log format (tracing output)."""
    summary.total_logs += 1

    # Level counts
    level = entry.get('level', 'UNKNOWN').upper()
    summary.level_counts[level] += 1

    # Target (module path) counts
    target = entry.get('target', 'unknown')
    summary.target_counts[target] += 1

    # Extract fields
    fields = entry.get('fields', {})
    message = fields.get('message', '')

    # Check for alerts
    if 'ALERT:' in message or 'alert_kind' in fields:
        alert_kind = fields.get('alert_kind', 'unknown')
        severity = fields.get('severity', 'unknown')
        summary.alert_kinds[alert_kind] += 1
        summary.alert_severities[severity] += 1

    # Check for test markers
    if message.startswith('TEST START:'):
        test_name = message.replace('TEST START:', '').strip()
        if test_name not in summary.tests:
            summary.tests[test_name] = TestResult(name=test_name)
        summary.tests[test_name].start_time = parse_timestamp(entry.get('timestamp', ''))
        summary.tests[test_name].log_count += 1
    elif message.startswith('TEST PASS:'):
        test_name = message.replace('TEST PASS:', '').strip()
        if test_name not in summary.tests:
            summary.tests[test_name] = TestResult(name=test_name)
        summary.tests[test_name].passed = True
        summary.tests[test_name].end_time = parse_timestamp(entry.get('timestamp', ''))
        summary.tests[test_name].log_count += 1
    elif message.startswith('TEST FAIL:'):
        test_name = message.replace('TEST FAIL:', '').strip()
        if test_name not in summary.tests:
            summary.tests[test_name] = TestResult(name=test_name)
        summary.tests[test_name].passed = False
        summary.tests[test_name].end_time = parse_timestamp(entry.get('timestamp', ''))
        summary.tests[test_name].error_count += 1
        summary.tests[test_name].log_count += 1

    # Track errors/warnings for any test context
    entry.get('threadId', '')
    if level == 'ERROR':
        # Try to attribute to a test if we can
        for test in summary.tests.values():
            test.error_count += 1
            break  # Just increment once
    elif level == 'WARN':
        for test in summary.tests.values():
            test.warn_count += 1
            break

    # Timestamp tracking
    ts = parse_timestamp(entry.get('timestamp', ''))
    if ts:
        if summary.earliest_timestamp is None or ts < summary.earliest_timestamp:
            summary.earliest_timestamp = ts
        if summary.latest_timestamp is None or ts > summary.latest_timestamp:
            summary.latest_timestamp = ts


def parse_jsonl_file(path: Path, summary: TelemetrySummary) -> int:
    """Parse a JSONL file and update the summary. Returns number of entries parsed."""
    count = 0
    try:
        with open(path, 'r') as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    entry = json.loads(line)
                    # Detect format by presence of 'fields' key (aggregated) vs 'source' (individual)
                    if 'fields' in entry:
                        parse_aggregated_log(entry, summary)
                    else:
                        parse_individual_test_log(entry, summary)
                    count += 1
                except json.JSONDecodeError as e:
                    print(f"Warning: Invalid JSON in {path}: {e}", file=sys.stderr)
        summary.files_processed.append(str(path))
    except IOError as e:
        print(f"Warning: Could not read {path}: {e}", file=sys.stderr)
    return count


def format_duration(start: Optional[datetime], end: Optional[datetime]) -> str:
    """Format duration between two timestamps."""
    if start and end:
        delta = end - start
        ms = delta.total_seconds() * 1000
        return f"{ms:.2f}ms"
    return "N/A"


def print_text_report(summary: TelemetrySummary) -> None:
    """Print a human-readable text report."""
    print("=" * 70)
    print("                    TEST TELEMETRY DASHBOARD")
    print("=" * 70)
    print()

    # Overview
    print("OVERVIEW")
    print("-" * 40)
    print(f"  Total log entries:    {summary.total_logs:,}")
    print(f"  Files processed:      {len(summary.files_processed)}")
    if summary.earliest_timestamp and summary.latest_timestamp:
        duration = summary.latest_timestamp - summary.earliest_timestamp
        print(f"  Time span:            {duration.total_seconds():.3f}s")
        print(f"  Start:                {summary.earliest_timestamp.isoformat()}")
        print(f"  End:                  {summary.latest_timestamp.isoformat()}")
    print()

    # Log level distribution
    print("LOG LEVEL DISTRIBUTION")
    print("-" * 40)
    total = sum(summary.level_counts.values()) or 1
    for level in ['DEBUG', 'INFO', 'WARN', 'ERROR', 'TRACE']:
        count = summary.level_counts.get(level, 0)
        pct = (count / total) * 100
        bar_len = int(pct / 2)
        bar = "█" * bar_len
        print(f"  {level:8s} {count:6,} ({pct:5.1f}%) {bar}")
    # Any other levels
    for level, count in sorted(summary.level_counts.items()):
        if level not in ['DEBUG', 'INFO', 'WARN', 'ERROR', 'TRACE']:
            pct = (count / total) * 100
            print(f"  {level:8s} {count:6,} ({pct:5.1f}%)")
    print()

    # Test results
    if summary.tests:
        print("TEST RESULTS")
        print("-" * 40)
        passed = sum(1 for t in summary.tests.values() if t.passed)
        failed = sum(1 for t in summary.tests.values() if not t.passed and t.end_time)
        in_progress = sum(1 for t in summary.tests.values() if t.start_time and not t.end_time)
        print(f"  Passed:       {passed:4}")
        print(f"  Failed:       {failed:4}")
        print(f"  In Progress:  {in_progress:4}")
        print(f"  Total:        {len(summary.tests):4}")

        # Show failed tests if any
        failed_tests = [t for t in summary.tests.values() if not t.passed and t.end_time]
        if failed_tests:
            print()
            print("  Failed Tests:")
            for t in failed_tests[:10]:  # Limit to 10
                print(f"    - {t.name}")
            if len(failed_tests) > 10:
                print(f"    ... and {len(failed_tests) - 10} more")
        print()

    # Alert summary
    if summary.alert_kinds:
        print("ALERT SUMMARY")
        print("-" * 40)
        print("  By Kind:")
        for kind, count in sorted(summary.alert_kinds.items(), key=lambda x: -x[1]):
            print(f"    {kind:25s} {count:5}")
        print()
        print("  By Severity:")
        for sev, count in sorted(summary.alert_severities.items(), key=lambda x: -x[1]):
            print(f"    {sev:15s} {count:5}")
        print()

    # Top sources/targets
    if summary.source_counts:
        print("TOP LOG SOURCES")
        print("-" * 40)
        for source, count in sorted(summary.source_counts.items(), key=lambda x: -x[1])[:10]:
            print(f"  {source:30s} {count:6}")
        print()

    if summary.target_counts:
        print("TOP LOG TARGETS")
        print("-" * 40)
        for target, count in sorted(summary.target_counts.items(), key=lambda x: -x[1])[:10]:
            print(f"  {target:45s} {count:6}")
        print()

    print("=" * 70)


def print_summary_report(summary: TelemetrySummary) -> None:
    """Print a brief one-line summary."""
    passed = sum(1 for t in summary.tests.values() if t.passed)
    failed = sum(1 for t in summary.tests.values() if not t.passed and t.end_time)
    errors = summary.level_counts.get('ERROR', 0)
    warns = summary.level_counts.get('WARN', 0)

    status = "PASS" if failed == 0 and errors == 0 else "FAIL"
    print(f"[{status}] {summary.total_logs:,} logs | "
          f"{passed} passed, {failed} failed | "
          f"{errors} errors, {warns} warnings | "
          f"{len(summary.files_processed)} files")


def print_json_report(summary: TelemetrySummary) -> None:
    """Print a JSON report."""
    report = {
        "total_logs": summary.total_logs,
        "files_processed": len(summary.files_processed),
        "level_counts": dict(summary.level_counts),
        "source_counts": dict(summary.source_counts),
        "target_counts": dict(summary.target_counts),
        "alert_kinds": dict(summary.alert_kinds),
        "alert_severities": dict(summary.alert_severities),
        "tests": {
            "total": len(summary.tests),
            "passed": sum(1 for t in summary.tests.values() if t.passed),
            "failed": sum(1 for t in summary.tests.values() if not t.passed and t.end_time),
            "in_progress": sum(1 for t in summary.tests.values() if t.start_time and not t.end_time),
        },
        "timestamps": {
            "earliest": summary.earliest_timestamp.isoformat() if summary.earliest_timestamp else None,
            "latest": summary.latest_timestamp.isoformat() if summary.latest_timestamp else None,
        },
    }
    print(json.dumps(report, indent=2))


def main():
    parser = argparse.ArgumentParser(
        description="Test Telemetry Dashboard - Parse JSONL test outputs",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s                              # Process default directory
  %(prog)s --dir ./custom-logs          # Process custom directory
  %(prog)s --format json                # Output as JSON
  %(prog)s --format summary             # One-line summary
  %(prog)s --file specific.jsonl        # Process single file
        """
    )
    parser.add_argument(
        '--dir', '-d',
        default='target/test-logs',
        help='Directory containing JSONL files (default: target/test-logs)'
    )
    parser.add_argument(
        '--file', '-f',
        help='Process a single JSONL file instead of a directory'
    )
    parser.add_argument(
        '--format', '-o',
        choices=['text', 'json', 'summary'],
        default='text',
        help='Output format (default: text)'
    )
    parser.add_argument(
        '--all-tests-only',
        action='store_true',
        help='Only process all_tests.jsonl if present'
    )

    args = parser.parse_args()

    summary = TelemetrySummary()

    if args.file:
        # Process single file
        path = Path(args.file)
        if not path.exists():
            print(f"Error: File not found: {path}", file=sys.stderr)
            sys.exit(1)
        parse_jsonl_file(path, summary)
    else:
        # Process directory
        log_dir = Path(args.dir)
        if not log_dir.exists():
            print(f"Error: Directory not found: {log_dir}", file=sys.stderr)
            print("Hint: Run tests first to generate JSONL logs.", file=sys.stderr)
            sys.exit(1)

        if args.all_tests_only:
            all_tests = log_dir / 'all_tests.jsonl'
            if all_tests.exists():
                parse_jsonl_file(all_tests, summary)
            else:
                print(f"Error: all_tests.jsonl not found in {log_dir}", file=sys.stderr)
                sys.exit(1)
        else:
            # Process all JSONL files
            jsonl_files = sorted(log_dir.glob('*.jsonl'))
            if not jsonl_files:
                print(f"Error: No JSONL files found in {log_dir}", file=sys.stderr)
                sys.exit(1)

            for path in jsonl_files:
                parse_jsonl_file(path, summary)

    # Output
    if args.format == 'json':
        print_json_report(summary)
    elif args.format == 'summary':
        print_summary_report(summary)
    else:
        print_text_report(summary)

    # Exit code based on failures
    failed = sum(1 for t in summary.tests.values() if not t.passed and t.end_time)
    errors = summary.level_counts.get('ERROR', 0)
    sys.exit(1 if failed > 0 or errors > 0 else 0)


if __name__ == '__main__':
    main()
