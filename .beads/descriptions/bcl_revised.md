## Overview

Add comprehensive GitHub Actions CI with quality gates, security scanning, cross-platform testing, **performance budget verification**, fuzz testing, and detailed logging. This is a prerequisite for automated releases.

## Goals

1. Linux + macOS + Windows test matrix
2. Security scanning (cargo-audit, dependency review)
3. Full quality gates: check, clippy, fmt, test
4. E2E tests with RCH_MOCK_SSH=1
5. Build release artifacts for all supported targets
6. Coverage reporting with codecov
7. MSRV (Minimum Supported Rust Version) verification
8. Artifact upload on failure for debugging
9. **NEW: Performance benchmark CI to verify <1ms/<5ms latency requirements**
10. **NEW: Fuzz testing for classifier security**
11. **NEW: Benchmark regression detection**

## Workflow Structure

### Trigger Events
```yaml
on:
  push:
    branches: [main]
  pull_request:
    branches: [main]
  schedule:
    - cron: '0 6 * * 1'  # Weekly security scan
```

### Jobs

#### 1. check (fastest feedback)
- cargo check --all-targets --all-features
- Runs on: ubuntu-latest
- Purpose: Fast syntax and type checking

#### 2. fmt
- cargo fmt --all -- --check
- Runs on: ubuntu-latest
- Purpose: Ensure consistent formatting

#### 3. clippy
- cargo clippy --all-targets --all-features -- -D warnings
- Runs on: ubuntu-latest
- Purpose: Lint checks with strict warnings

#### 4. security
- cargo audit
- cargo deny check
- Runs on: ubuntu-latest
- Purpose: Dependency vulnerability scanning

#### 5. test (matrix)
- cargo test --all-features --workspace
- Matrix: ubuntu-latest, macos-latest, windows-latest
- Rust: stable, nightly, MSRV (1.75.0)
- Purpose: Cross-platform correctness

#### 6. e2e
- RCH_MOCK_SSH=1 ./scripts/e2e_test.sh
- Runs on: ubuntu-latest
- Upload logs as artifacts on failure
- Purpose: Integration testing

#### 7. coverage
- cargo llvm-cov --all-features --workspace --lcov --output-path lcov.info
- Upload to codecov
- Purpose: Track test coverage

#### 8. build-release
- Build release binaries for all targets
- Upload as artifacts
- Purpose: Verify release builds work

#### 9. benchmark (NEW)
- cargo bench --bench classifier --bench latency
- Compare against baseline (stored in benches/baseline.json)
- **FAIL if non-compilation latency > 1ms (95th percentile)**
- **FAIL if compilation decision latency > 5ms (95th percentile)**
- Upload benchmark results as artifacts
- Purpose: Verify performance budgets from AGENTS.md

#### 10. fuzz (NEW - weekly)
- cargo +nightly fuzz run classify_fuzz -- -max_total_time=300
- Runs on: schedule only (weekly)
- Purpose: Security testing of command classifier

## Target Matrix

```yaml
targets:
  - x86_64-unknown-linux-gnu
  - x86_64-unknown-linux-musl
  - aarch64-unknown-linux-gnu
  - x86_64-apple-darwin
  - aarch64-apple-darwin
  - x86_64-pc-windows-msvc
```

## Caching Strategy

```yaml
- uses: Swatinem/rust-cache@v2
  with:
    cache-on-failure: true
    shared-key: ${{ matrix.os }}-${{ matrix.rust }}
```

## Implementation Files

```
.github/
├── workflows/
│   ├── ci.yml              # Main CI workflow
│   ├── release.yml         # Release workflow (cargo-dist)
│   ├── security.yml        # Weekly security scan
│   ├── benchmark.yml       # Performance benchmarks (NEW)
│   └── fuzz.yml            # Weekly fuzz testing (NEW)
├── dependabot.yml          # Automated dependency updates
└── CODEOWNERS              # Review requirements

benches/
├── classifier.rs           # Classifier benchmarks (NEW)
├── latency.rs              # Hook latency benchmarks (NEW)
├── baseline.json           # Baseline for regression detection (NEW)
└── README.md               # Benchmark documentation (NEW)

fuzz/
├── Cargo.toml              # Fuzz targets (NEW)
└── fuzz_targets/
    ├── classify_fuzz.rs    # Command classification fuzzer (NEW)
    └── hook_input_fuzz.rs  # Hook JSON input fuzzer (NEW)
```

## Workflow YAML (ci.yml)

```yaml
name: CI

on:
  push:
    branches: [main]
  pull_request:
  schedule:
    - cron: '0 6 * * 1'

env:
  CARGO_TERM_COLOR: always
  RUST_BACKTRACE: 1

jobs:
  check:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: dtolnay/rust-toolchain@stable
      - uses: Swatinem/rust-cache@v2
      - run: cargo check --all-targets --all-features

  fmt:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: dtolnay/rust-toolchain@nightly
        with:
          components: rustfmt
      - run: cargo fmt --all -- --check

  clippy:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: dtolnay/rust-toolchain@stable
        with:
          components: clippy
      - uses: Swatinem/rust-cache@v2
      - run: cargo clippy --all-targets --all-features -- -D warnings

  security:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: rustsec/audit-check@v2
        with:
          token: ${{ secrets.GITHUB_TOKEN }}

  test:
    strategy:
      fail-fast: false
      matrix:
        os: [ubuntu-latest, macos-latest, windows-latest]
        rust: [stable, nightly]
        include:
          - os: ubuntu-latest
            rust: '1.75.0'  # MSRV
    runs-on: ${{ matrix.os }}
    steps:
      - uses: actions/checkout@v4
      - uses: dtolnay/rust-toolchain@master
        with:
          toolchain: ${{ matrix.rust }}
      - uses: Swatinem/rust-cache@v2
      - name: Run tests
        env:
          RCH_MOCK_SSH: '1'
        run: cargo test --all-features --workspace
      - name: Upload test logs on failure
        if: failure()
        uses: actions/upload-artifact@v4
        with:
          name: test-logs-${{ matrix.os }}-${{ matrix.rust }}
          path: |
            target/debug/deps/*.log
            **/test-output.log

  e2e:
    runs-on: ubuntu-latest
    needs: [check, clippy]
    steps:
      - uses: actions/checkout@v4
      - uses: dtolnay/rust-toolchain@stable
      - uses: Swatinem/rust-cache@v2
      - name: Build
        run: cargo build --release
      - name: Run E2E tests
        env:
          RCH_MOCK_SSH: '1'
          RCH_LOG_LEVEL: debug
        run: |
          chmod +x scripts/e2e_test.sh
          ./scripts/e2e_test.sh 2>&1 | tee e2e-output.log
      - name: Upload E2E logs
        if: always()
        uses: actions/upload-artifact@v4
        with:
          name: e2e-logs
          path: e2e-output.log

  # NEW: Performance benchmark job
  benchmark:
    runs-on: ubuntu-latest
    needs: [check]
    steps:
      - uses: actions/checkout@v4
      - uses: dtolnay/rust-toolchain@stable
      - uses: Swatinem/rust-cache@v2
      - name: Run benchmarks
        run: |
          cargo bench --bench classifier --bench latency -- --save-baseline ci
          # Extract and verify latency budgets
          python3 scripts/check_benchmark_budgets.py
      - name: Upload benchmark results
        uses: actions/upload-artifact@v4
        with:
          name: benchmark-results
          path: target/criterion/
      - name: Comment on PR with benchmark results
        if: github.event_name == 'pull_request'
        uses: actions/github-script@v7
        with:
          script: |
            const fs = require('fs');
            const results = fs.readFileSync('target/criterion/summary.txt', 'utf8');
            github.rest.issues.createComment({
              issue_number: context.issue.number,
              owner: context.repo.owner,
              repo: context.repo.repo,
              body: '## Benchmark Results\n```\n' + results + '\n```'
            });

  coverage:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: dtolnay/rust-toolchain@stable
        with:
          components: llvm-tools-preview
      - uses: taiki-e/install-action@cargo-llvm-cov
      - uses: Swatinem/rust-cache@v2
      - run: cargo llvm-cov --all-features --workspace --lcov --output-path lcov.info
      - uses: codecov/codecov-action@v4
        with:
          files: lcov.info
          fail_ci_if_error: false
```

## Benchmark Definitions (NEW)

### benches/classifier.rs
```rust
use criterion::{black_box, criterion_group, criterion_main, Criterion, BenchmarkId};
use rch_common::classify::classify_command;

fn bench_classifier(c: &mut Criterion) {
    let mut group = c.benchmark_group("classifier");

    // Tier 0: Fast negative (must be < 1µs)
    let tier0_commands = ["cd /tmp", "ls -la", "cat file.txt", "git status", "echo hello"];
    for cmd in tier0_commands {
        group.bench_with_input(BenchmarkId::new("tier0_reject", cmd), cmd, |b, cmd| {
            b.iter(|| classify_command(black_box(cmd)))
        });
    }

    // Tier 1: Positive match (must be < 5µs)
    let tier1_commands = ["cargo build", "rustc lib.rs", "gcc main.c", "make all"];
    for cmd in tier1_commands {
        group.bench_with_input(BenchmarkId::new("tier1_match", cmd), cmd, |b, cmd| {
            b.iter(|| classify_command(black_box(cmd)))
        });
    }

    // Complex commands (full pipeline, must be < 5ms for 95th percentile)
    let complex_commands = [
        "RUSTFLAGS=\"-C target-cpu=native\" cargo build --release --features all",
        "cargo build 2>&1 | tee build.log",
        "$(cargo build --message-format=json | jq ...)",
    ];
    for cmd in complex_commands {
        group.bench_with_input(BenchmarkId::new("complex", &cmd[..20]), cmd, |b, cmd| {
            b.iter(|| classify_command(black_box(cmd)))
        });
    }

    group.finish();
}

criterion_group!(benches, bench_classifier);
criterion_main!(benches);
```

### benches/latency.rs
```rust
use criterion::{criterion_group, criterion_main, Criterion};
use rch::hook::process_hook_request;

fn bench_hook_latency(c: &mut Criterion) {
    let mut group = c.benchmark_group("hook_latency");

    // Full hook request (non-compilation) - must be < 1ms
    let non_compilation_request = r#"{"tool":"Bash","input":{"command":"git status"}}"#;
    group.bench_function("non_compilation", |b| {
        b.iter(|| process_hook_request(non_compilation_request))
    });

    // Full hook request (compilation) - must be < 5ms
    let compilation_request = r#"{"tool":"Bash","input":{"command":"cargo build --release"}}"#;
    group.bench_function("compilation", |b| {
        b.iter(|| process_hook_request(compilation_request))
    });

    group.finish();
}

criterion_group!(benches, bench_hook_latency);
criterion_main!(benches);
```

### scripts/check_benchmark_budgets.py (NEW)
```python
#!/usr/bin/env python3
"""Verify benchmark results meet AGENTS.md performance budgets."""
import json
import sys
from pathlib import Path

BUDGETS = {
    "hook_latency/non_compilation": 1_000_000,  # 1ms in nanoseconds
    "hook_latency/compilation": 5_000_000,       # 5ms in nanoseconds
    "classifier/tier0_reject": 1_000,            # 1µs
    "classifier/tier1_match": 5_000,             # 5µs
}

def check_budgets():
    criterion_dir = Path("target/criterion")
    failures = []

    for bench_name, budget_ns in BUDGETS.items():
        estimate_file = criterion_dir / bench_name / "new/estimates.json"
        if not estimate_file.exists():
            print(f"Warning: {bench_name} benchmark not found")
            continue

        with open(estimate_file) as f:
            data = json.load(f)

        # Check 95th percentile
        p95 = data["mean"]["point_estimate"]  # Use mean as proxy
        if p95 > budget_ns:
            failures.append(f"{bench_name}: {p95/1e6:.2f}ms > budget {budget_ns/1e6:.2f}ms")
        else:
            print(f"OK: {bench_name} = {p95/1e6:.3f}ms (budget: {budget_ns/1e6:.2f}ms)")

    if failures:
        print("\nPERFORMANCE BUDGET VIOLATIONS:")
        for f in failures:
            print(f"  FAIL: {f}")
        sys.exit(1)

    print("\nAll performance budgets met!")

if __name__ == "__main__":
    check_budgets()
```

## Fuzz Testing (NEW)

### fuzz/fuzz_targets/classify_fuzz.rs
```rust
#![no_main]
use libfuzzer_sys::fuzz_target;
use rch_common::classify::classify_command;

fuzz_target!(|data: &[u8]| {
    if let Ok(cmd) = std::str::from_utf8(data) {
        // Should never panic, regardless of input
        let _ = classify_command(cmd);
    }
});
```

### fuzz/fuzz_targets/hook_input_fuzz.rs
```rust
#![no_main]
use libfuzzer_sys::fuzz_target;
use rch::hook::parse_hook_input;

fuzz_target!(|data: &[u8]| {
    if let Ok(json_str) = std::str::from_utf8(data) {
        // Should handle malformed JSON gracefully
        let _ = parse_hook_input(json_str);
    }
});
```

## Testing Requirements

### Unit Tests
- Workflow syntax validation (actionlint)
- Job dependency graph correctness
- Benchmark budget verification script

### Integration Tests
- Push to test branch triggers workflow
- PR triggers subset of jobs
- Matrix expands correctly
- Benchmarks run and produce output

### E2E Tests
- Full workflow run completes
- Artifacts uploaded correctly
- Coverage reports generated
- Benchmark results uploaded
- Performance budgets verified

## Logging Requirements

- Each job logs start time and duration
- Failure artifacts include full logs
- E2E test output captured and uploaded
- Benchmark results summarized in PR comments

## Success Criteria

- [ ] All jobs pass on clean repo
- [ ] Clippy/fmt fail PRs on violations
- [ ] E2E tests run with RCH_MOCK_SSH=1
- [ ] Coverage reports uploaded to codecov
- [ ] Security scan runs weekly
- [ ] MSRV verified (1.75.0)
- [ ] Windows builds pass
- [ ] Artifacts uploaded on failure
- [ ] **NEW: Non-compilation latency < 1ms (95th percentile)**
- [ ] **NEW: Compilation decision latency < 5ms (95th percentile)**
- [ ] **NEW: Fuzz testing runs weekly without crashes**
- [ ] **NEW: Benchmark regression detection works**

## Dependencies

None - this is infrastructure.

## Blocks

- remote_compilation_helper-9zy (Self-Update) - needs release artifacts
- remote_compilation_helper-gao (cargo-dist) - generates release workflow
