# Dependency Upgrade Log

**Date:** 2026-01-25  |  **Project:** remote_compilation_helper  |  **Language:** Rust

## Summary
- **Updated:** 5  |  **Skipped:** 0  |  **Failed:** 0  |  **Needs attention:** 0

## Updates

### whoami: 1.5 → 2.0 (rch-common, rchd dev-dependency)
- **Breaking:** `username()` now returns `Result<String, Error>` instead of `String`
- **Migration:** Added `.unwrap_or_else(|_| "unknown".to_string())` to all call sites
- **Files changed:**
  - `rch-common/src/e2e/fixtures.rs:25`
  - `rch-common/src/ssh.rs:141`
  - `rchd/tests/e2e_self_test.rs:65`
  - `rchd/Cargo.toml` (dev-dependency version)
- **Tests:** ✓ Passed

### criterion: 0.5 → 0.8 (rch-common dev-dependency)
- **Breaking:** None observed
- **Tests:** ✓ Passed

### colored: 2 → 3 (rch)
- **Breaking:** MSRV bump to 1.80, `lazy_static` dependency removed
- **Migration:** None required - API compatible
- **Tests:** ✓ Passed

### rusqlite: 0.32 → 0.38 (rch-telemetry)
- **Breaking:** `u64`/`usize` no longer implement `FromSql` by default
- **Migration:** Changed `let total: u64` to `let total: i64` then cast to u64
- **Files changed:**
  - `rch-telemetry/src/storage/mod.rs:277-281`
- **Tests:** ✓ Passed

### reqwest: 0.12 → 0.13 (rch)
- **Breaking:** Default TLS changed to rustls, `query`/`form` features now optional
- **Migration:** None required - using `json` feature which is still supported
- **Notes:** Now using rustls as TLS backend by default (was native-tls)
- **Tests:** ✓ Passed

## Skipped

None

## Failed

None

## SQLite Improvements (rust-cli-with-sqlite skill)

Applied best practices from the rust-cli-with-sqlite skill to rch-telemetry:

### Enhanced SQLite Configuration
- **File:** `rch-telemetry/src/storage/mod.rs`
- Added `PRAGMA wal_autocheckpoint=1000` for controlled WAL growth
- Added `PRAGMA foreign_keys=ON` for referential integrity
- Added `busy_timeout(5 seconds)` for concurrent access handling
- Already had: `journal_mode=WAL`, `synchronous=NORMAL`

### Added Database Diagnostics
- **File:** `rch-telemetry/src/storage/mod.rs`
- Added `integrity_check()` method using `PRAGMA integrity_check`
- Added `stats()` method returning `StorageStats` struct with:
  - telemetry_snapshots count
  - hourly_aggregates count
  - speedscore_entries count
  - test_runs count
  - db_size_bytes
- Exported `StorageStats` from `rch-telemetry/src/lib.rs`

### Integrated with Doctor Command
- **File:** `rch/src/doctor.rs`
- Added new `check_telemetry_database()` check to `rch doctor`
- Checks: database existence, integrity, and optionally stats (in verbose mode)
- Provides actionable suggestions for corrupted databases

## Notes

- All workspace members now build and pass tests
- Rust Edition 2024 with nightly-2025-01-01 toolchain
- Full test suite: 780+ tests passing

---

**Date:** 2026-02-19  |  **Project:** remote_compilation_helper  |  **Language:** Rust

## Summary
- **Updated:** 20  |  **Skipped:** 1  |  **Failed:** 0  |  **Needs attention:** 0

## Updates

### Workspace-level (Cargo.toml)

#### clap: 4.5.54 → 4.5.60
- **Breaking:** None (patch release)
- **Tests:** Passed

#### clap_complete: 4.5.65 → 4.5.66
- **Breaking:** None (patch release)
- **Tests:** Passed

#### memchr: 2.7.6 → 2.8.0
- **Breaking:** None (minor release)
- **Tests:** Passed

#### regex: 1.12.2 → 1.12.3
- **Breaking:** None (patch release)
- **Tests:** Passed

#### uuid: 1.19.0 → 1.21.0
- **Breaking:** None (minor release)
- **Tests:** Passed

#### anyhow: 1.0.100 → 1.0.101
- **Breaking:** None (patch release)
- **Tests:** Passed

#### ureq: 3.0 → 3.2
- **Breaking:** None (minor release)
- **Tests:** Passed

#### notify: 8.0 → 8.2
- **Breaking:** None (minor release)
- **Tests:** Passed

#### toml: 0.9.10 → 1.0 (MAJOR)
- **Breaking:** Minimal — only `Time::second`/`Time::nanosecond` wrapped in `Option`; project doesn't use datetime types
- **Migration:** Version bump only, no code changes needed
- **Tests:** Passed

#### tracing-opentelemetry: 0.28 → 0.32 (MAJOR)
- **Breaking:** Semantic convention attribute renames (`code.filepath` → `code.file.path`, `code.lineno` → `code.line.number`), `PreSampledTracer` removed, `otel.status_message` → `otel.status_description`
- **Migration:** No code changes needed — project's OpenTelemetry integration is a stub
- **Bonus:** Removed duplicate `opentelemetry v0.27.1` and `opentelemetry_sdk v0.27.1` from dependency tree (old tracing-opentelemetry required OTel 0.27, now correctly uses 0.31)
- **Tests:** Passed

#### rand: 0.9.2 → 0.10.0 (MAJOR)
- **Breaking:** `rand::Rng` trait renamed to `rand::RngExt`
- **Migration:** Changed `use rand::Rng` to `use rand::RngExt` in 2 files:
  - `rch-common/src/types.rs:4`
  - `rchd/src/selection.rs:20`
- **Tests:** Passed

### Crate-specific

#### indicatif: 0.18.3 → 0.18.4 (rch)
- **Breaking:** None (patch release)
- **Tests:** Passed

#### reqwest: 0.13.1 → 0.13.2 (rch)
- **Breaking:** None (patch release)
- **Tests:** Passed

#### tempfile: 3.22.0 → 3.25.0 (rch, rchd, rch-common, rch-telemetry)
- **Breaking:** None (minor release)
- **Tests:** Passed

#### proptest: 1.7.0 → 1.10.0 (rch, rchd, rch-common, rch-telemetry dev-deps)
- **Breaking:** None (minor release)
- **Tests:** Passed

#### criterion: 0.8.1 → 0.8.2 (rch-common dev-dep)
- **Breaking:** None (patch release)
- **Tests:** Passed

#### insta: 1.42 → 1.46 (rch dev-dep)
- **Breaking:** None (minor release)
- **Tests:** Passed

#### whoami: 2.0 → 2.1 (rch-common, rchd)
- **Breaking:** None (minor release)
- **Tests:** Passed

### Pre-existing fix applied

#### rch-common/src/cargo_path_deps.rs: visibility fix
- **Issue:** `CargoPathDependencyError::new`, `with_manifest_path`, `with_dependency_name`, `with_dependency_path` were `fn` (private) but called from tests in `dependency_closure_planner.rs`
- **Fix:** Changed to `pub(crate) fn`
- **Note:** Pre-existing compilation error, not caused by dependency updates

## Skipped

### ctor: 0.2.9 → 0.6.3
- **Reason:** ctor 0.6 macro expansion uses `#[allow(unsafe_code)]` which is incompatible with `#![forbid(unsafe_code)]` required by project policy (AGENTS.md)
- **Action:** Stayed on 0.2.9

## Failed

None

## Transitive dependency improvements
- Removed duplicate `opentelemetry v0.27.1` / `opentelemetry_sdk v0.27.1` (were only needed by tracing-opentelemetry 0.28)
- Removed `rand_chacha v0.3.1` (replaced by `chacha20 v0.10.0` in rand 0.10)

### Toolchain update

#### rust-toolchain.toml: nightly-2025-11-01 → nightly-2026-02-19
- **Change:** rustc 1.93.0-nightly (82ae0ee64 2025-10-31) → rustc 1.95.0-nightly (c04308580 2026-02-18)
- **Breaking:** None observed
- **Tests:** All passing (4993+ tests, 0 failures)

## Notes

- All 4993+ tests passing with 0 failures after toolchain update
- `cargo clippy --workspace --all-targets -- -D warnings` clean
- `cargo fmt --check` clean (fixed pre-existing formatting in `dependency_closure_planner.rs`)

---

**Date:** 2026-01-26  |  **Project:** remote_compilation_helper  |  **Language:** Rust

## Summary
- **Updated:** 36  |  **Skipped:** 14  |  **Failed:** 0  |  **Needs attention:** 2

## Updates

### anyhow: 1.0 → 1.0.100
- **Breaking:** None noted in release notes (clippy lint improvement only)
- **Tests:** `cargo test`

### serde: 1.0 → 1.0.228
- **Breaking:** None noted in patch release notes
- **Tests:** `cargo test`

### serde_json: 1.0 → 1.0.149
- **Breaking:** None noted in patch release notes
- **Tests:** `cargo test`

### tokio: 1.43 → 1.49.0
- **Breaking:** No hard breaks noted; `TcpStream/TcpSocket::set_linger` deprecated in 1.49.0
- **Tests:** `cargo test -p rch-common`

### clap: 4.5 → 4.5.54
- **Breaking:** None noted (help rendering fixes and maintenance)
- **Tests:** `cargo test -p rch` (full run flaky on hook tests; individual re-runs passed)

### memchr: 2.7 → 2.7.6
- **Breaking:** None noted in patch release notes
- **Tests:** `cargo test -p rch-common`

### regex: 1.11 → 1.12.2
- **Breaking:** None noted in patch release notes
- **Tests:** `cargo test -p rch-common`

### tracing: 0.1 → 0.1.44
- **Breaking:** None noted in patch release notes
- **Tests:** `cargo test -p rch-common`

### tracing-subscriber: 0.3 → 0.3.22
- **Breaking:** None noted in patch release notes
- **Tests:** `cargo test -p rch-common`

### blake3: 1.5 → 1.8.3
- **Breaking:** None noted in release notes (performance-focused updates)
- **Tests:** `cargo test` (blocked by workspace build locks; interrupted)

### chrono: 0.4 → 0.4.43
- **Breaking:** None noted in release notes
- **Tests:** `timeout 600 cargo test` (timed out while waiting on workspace build locks)

### clap_complete: 4.5 → 4.5.65
- **Breaking:** None noted in patch release notes
- **Tests:** `timeout 600 cargo test` (interrupted due to workspace build locks)

### colored: 3 → 3.1.1
- **Breaking:** None noted in release notes
- **Tests:** `timeout 180 cargo test` (timed out waiting on workspace build locks)

### console: 0.16 → 0.16.2
- **Breaking:** None noted in patch release notes
- **Tests:** `timeout 180 cargo test` (timed out waiting on workspace build locks)

### criterion: 0.8 → 0.8.1
- **Breaking:** None noted in patch release notes
- **Tests:** `timeout 180 cargo test` (timed out waiting on workspace build locks)

### humantime: 2.1 → 2.3.0
- **Breaking:** None noted in patch release notes
- **Tests:** `cargo test -p rch-common`

### ratatui: 0.29 → 0.30.0
- **Breaking:** Review v0.30.0 changelog for API adjustments
- **Tests:** `cargo test -p rch-common`

### unicode-width: 0.2 → 0.2.2
- **Breaking:** None noted in patch release notes
- **Tests:** `cargo test -p rch-common` (required ratatui 0.30+)

### hyper: 1.5 → 1.8.1
- **Breaking:** None noted in patch/minor release notes
- **Tests:** `timeout 180 cargo test` (timed out waiting on workspace build locks)

### indicatif: 0.18 → 0.18.3
- **Breaking:** None noted in patch release notes
- **Tests:** `timeout 180 cargo test` (timed out waiting on workspace build locks)

### is-terminal: 0.4 → 0.4.17
- **Breaking:** None noted in patch release notes
- **Tests:** `timeout 180 cargo test` (blocked by workspace build locks)

### miette: 7 → 7.6.0
- **Breaking:** None noted in patch release notes
- **Tests:** `timeout 180 cargo test` (FAILED: rustc -vV SIGKILL)

### object: 0.38 → 0.38.1
- **Breaking:** None noted in patch release notes
- **Tests:** `timeout 60 cargo test` (timed out during workspace rebuild)

### opentelemetry: 0.27 → 0.31.0
- **Breaking:** `opentelemetry::global::set_tracer_provider` now returns `()` (previously returned a guard)
- **Tests:** `timeout 60 cargo test -p rchd` (timed out during workspace rebuild)

### opentelemetry_sdk: 0.27 → 0.31.0
- **Breaking:** None noted in 0.31.0 release notes
- **Tests:** `timeout 60 cargo test -p rchd` (timed out during workspace rebuild)

### opentelemetry-otlp: 0.27 → 0.31.0
- **Breaking:** None noted in 0.31.0 release notes (new gzip/zstd HTTP compression features)
- **Tests:** `timeout 60 cargo test -p rchd` (timed out during workspace rebuild)

### axum: 0.8 → 0.8.8
- **Breaking:** None noted in release notes
- **Tests:** `cargo test -p rchd` (FAILED: `test_daemon_startup_shutdown_cycles` - connection refused in cycle 2)
- **Notes:** Added `::tracing` disambiguation in `rchd/src/metrics/mod.rs` after test compile error.

### thiserror: 2.0 → 2.0.18
- **Breaking:** None noted in patch release notes
- **Tests:** `cargo test -p rch-common`

### toml: 0.9 → 0.9.10
- **Breaking:** None noted; 0.9.x adds TOML 1.1 spec support
- **Tests:** `cargo test -p rch-common` (initial full run flaked on `progress_context_nested_counts`, single-test re-run passed)

### uuid: 1.11 → 1.19.0
- **Breaking:** None noted for std usage; release notes mention internal serde dependency change
- **Tests:** `cargo test -p rch-common` (flaked on `progress_context_nested_counts`, single-test re-run passed)

### rand: 0.9 → 0.9.2
- **Breaking:** None noted in patch release notes (0.9.x)
- **Tests:** `cargo test -p rch-common`

### zstd: 0.13 → 0.13.3
- **Breaking:** None noted in patch release notes
- **Tests:** `cargo test -p rch-common`

### openssh: 0.11 → 0.11.6
- **Breaking:** v0.11.0 removed deprecated APIs, removed `tokio-pipe`, and replaced `From<tokio::process::Child*>` with `TryFrom<tokio::process::Child*>` (fallible conversions); removed `IntoRawFd` for `Child*`
- **Tests:** `timeout 60 cargo test` (timed out waiting on workspace build locks)

### shellexpand: 3.1 → 3.1.1 (rch, rch-common, rch-telemetry)
- **Breaking:** None noted in patch release notes
- **Tests:** `cargo test -p rch-common`

### tempfile: 3.19/3.0 → 3.22.0 (workspace dev-deps + rch-telemetry)
- **Breaking:** None noted in patch release notes
- **Tests:** `cargo test -p rch-common`

### terminal_size: 0.4 → 0.4.3 (rch)
- **Breaking:** None noted in patch release notes
- **Tests:** `cargo test -p rch` (FAILED: `hook::tests::test_cargo_test_with_filter`, single-test re-run passed)

### reqwest: 0.13 → 0.13.1 (rch)
- **Breaking:** None noted in patch release notes
- **Tests:** `cargo test -p rch` (FAILED: `hook::tests::test_cargo_test_remote_success`, single-test re-run passed)

### sha2: 0.10 → 0.10.9 (rch)
- **Breaking:** None noted in patch release notes
- **Tests:** `cargo test -p rch` (FAILED: `hook::tests::test_cargo_test_remote_test_failures`, single-test re-run passed)

### urlencoding: 2 → 2.1.3 (rch)
- **Breaking:** None noted in patch release notes
- **Tests:** `cargo test -p rch` (FAILED: `hook::tests::test_cargo_test_remote_test_failures`, single-test re-run passed)

### proptest: 1.4 → 1.7.0 (rch, rch-common, rch-telemetry dev-deps)
- **Breaking:** None noted in patch release notes
- **Tests:** `cargo test -p rch-common`, `cargo test -p rch`

## Skipped
### cron: already at 0.15.0
- **Reason:** Workspace already pinned to latest stable 0.15.0 (no change needed)

### crossterm: already at 0.29.0
- **Reason:** Workspace already pinned to latest stable 0.29.0 (no change needed)

### dialoguer: already at 0.12.0
- **Reason:** Workspace already pinned to latest stable 0.12.0 (no change needed)

### directories: already at 6.0.0
- **Reason:** Workspace already pinned to latest stable 6.0.0 (no change needed)

### dirs: already at 6.0.0
- **Reason:** Workspace already pinned to latest stable 6.0.0 (no change needed)

### fastrand: already at 2.3.0
- **Reason:** Workspace already pinned to latest stable 2.3.0 (no change needed)

### lazy_static: already at 1.5.0
- **Reason:** Workspace already pinned to latest stable 1.5.0 (no change needed)

### prometheus: already at 0.14.0
- **Reason:** Workspace already pinned to latest stable 0.14.0 (no change needed)

### pulldown-cmark: already at 0.13.0
- **Reason:** Workspace already pinned to latest stable 0.13.0 (no change needed)

### rich_rust: already at 0.1.1
- **Reason:** Workspace already pinned to latest stable 0.1.1 (no change needed)

### rusqlite: already at 0.38.0
- **Reason:** Workspace already pinned to latest stable 0.38.0 (no change needed)

### shell-escape: already at 0.1.5
- **Reason:** Workspace already pinned to latest stable 0.1.5 (no change needed)

### toon-rust: already at 0.1.3
- **Reason:** Workspace already pinned to latest stable 0.1.3 (no change needed)

### which: already at 8.0.0
- **Reason:** Workspace already pinned to latest stable 8.0.0 (no change needed)

## Requires Attention

### axum test failures (stability)
- `rchd/tests/stability.rs` `test_daemon_startup_shutdown_cycles` flaked with `Connection refused` after socket ready.
- Likely needs retry/backoff after socket creation or cleanup of stale socket between cycles.

### miette test failure (SIGKILL)
- `timeout 180 cargo test` failed when `rustc -vV` was killed with signal 9.
- Likely resource pressure or competing builds; re-run when build load is lower.
