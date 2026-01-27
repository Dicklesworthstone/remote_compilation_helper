# Test Performance Baselines

This directory contains performance baselines for test regression detection.

## Files

- `test_performance_baseline.json` - Test duration baselines per platform

## Usage

```bash
# Check for regressions against baseline
python3 scripts/check_test_regression.py

# Update baseline with current results (after accepting new timings)
python3 scripts/check_test_regression.py --update-baseline

# Verbose output
python3 scripts/check_test_regression.py --verbose

# Custom threshold (default: 20% regression)
python3 scripts/check_test_regression.py --threshold 1.25
```

## How It Works

1. The regression detection script parses JSONL test logs from `target/test-logs/`
2. Extracts test durations (p95 percentile to ignore outliers)
3. Compares against stored baselines
4. Flags regressions when p95 exceeds threshold (default: 20% slower)

## Updating Baselines

Baselines should be updated when:
- Adding new tests
- Accepting intentional performance changes
- After significant code refactoring

Run `python3 scripts/check_test_regression.py --update-baseline` and commit the changes.

## CI Integration

The regression check runs in CI after tests complete. Regressions cause the build to fail.
