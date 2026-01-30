## Overview

Add comprehensive GitHub Actions CI with quality gates, security scanning, cross-platform testing, and detailed logging. This is a prerequisite for automated releases.

## Goals

1. Linux + macOS + Windows test matrix
2. Security scanning (cargo-audit, dependency review)
3. Full quality gates: check, clippy, fmt, test
4. E2E tests with RCH_MOCK_SSH=1
5. Build release artifacts for all supported targets
6. Coverage reporting with codecov
7. MSRV (Minimum Supported Rust Version) verification
8. Artifact upload on failure for debugging

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
│   └── security.yml        # Weekly security scan
├── dependabot.yml          # Automated dependency updates
└── CODEOWNERS              # Review requirements
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
      - run: cargo test --all-features --workspace
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

## Testing Requirements

### Unit Tests
- Workflow syntax validation (actionlint)
- Job dependency graph correctness

### Integration Tests
- Push to test branch triggers workflow
- PR triggers subset of jobs
- Matrix expands correctly

### E2E Tests
- Full workflow run completes
- Artifacts uploaded correctly
- Coverage reports generated

## Logging Requirements

- Each job logs start time and duration
- Failure artifacts include full logs
- E2E test output captured and uploaded

## Success Criteria

- [ ] All jobs pass on clean repo
- [ ] Clippy/fmt fail PRs on violations
- [ ] E2E tests run with mock SSH
- [ ] Coverage reports uploaded to codecov
- [ ] Security scan runs weekly
- [ ] MSRV verified (1.75.0)
- [ ] Windows builds pass
- [ ] Artifacts uploaded on failure

## Dependencies

None - this is infrastructure.

## Blocks

- remote_compilation_helper-9zy (Self-Update) - needs release artifacts
- remote_compilation_helper-gao (cargo-dist) - generates release workflow
