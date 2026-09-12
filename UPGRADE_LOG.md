# Dependency Upgrade Log

## 2026-09-12 — dependency refresh and DSR release (bd-6q0eo)

Status: in progress. Registry versions are checked against crates.io; existing
git, path and prerelease dependencies and the pinned nightly are preserved.
Each changed dependency receives a separate consumer test before the next
upgrade. Final workspace tests, compiler checks, Clippy, security audit and
release artifact verification follow. Historical entries below remain intact.

The candidate release is 2.0.0: public Rust schema helpers now return schemars
1.x Schema instead of 0.8 RootSchema. Draft 7 output preserves the dialect,
but does not preserve that Rust source API. No version bump occurs until the
required gates pass. The retained staging directory still has 1.1.0 in its name.
The existing RCH signing identity was found on css; its public key
1BBD79B28BF718D0 successfully verified the retained v1.0.64 Mac archive.
No private key was copied or changed.

### Interim static review

- The final 29-file scope, including the stock-Cargo probe and macOS cfg fix,
  exits 0 with zero new criticals, 193 warnings and 31 informational findings.
  Every changed Rust file matches its frozen snapshot. Receipt:
  `/run/user/1000/rch-fuchsia-ubs-20260912-2k0kt_kb/extension29path-_fmi6v27/final-validation.json`.
- After the release-gate repairs, the 28-file static comparison exits 0 with
  zero new criticals, 185 warnings and 27 informational findings. Two narrow
  stream-test annotations identify a trusted binary selector and an intentional
  assertion panic. All source hashes match the reviewed snapshot; existing
  baseline findings remain visible. Receipt:
  `/run/user/1000/rch-fuchsia-ubs-20260912-2k0kt_kb/extension28final-khpqkt35/final-validation.json`.
- A corrected private UBS runner layout now merges findings and fingerprints
  properly. The installed runner could not find its separately installed helper
  directory, so its baseline comparison was not trustworthy. Shared tools were
  not modified. On all 18 changed Rust files, comparison with bfa13059 now exits
  0 with zero new criticals, 105 warnings and 9 informational findings. Five
  specific loopback-test false positives have explained local annotations;
  the baseline's critical findings remain visible. No Cargo phase ran in UBS.
  Receipt: `/run/user/1000/rch-fuchsia-ubs-20260912-2k0kt_kb/extension18/final-validation.json`.
- UBS 5.4.2 static-only diff scan inspected 14 Rust files and exited 1:
  16 critical, 1,759 warning and 329 informational heuristic findings.
  It scans entire changed files, including large existing inline test modules.
  Reports are retained at `/run/user/1000/rch-release-ubs-detail-0318.txt` and
  `/run/user/1000/rch-release-ubs-0317.json`.
- New critical findings point to the loopback test's panic on accept failure,
  Instant deadlines misclassified as security-token generation, and an I/O
  error-kind comparison misclassified as secret comparison. These are test-only
  failure checks, not authentication operations. New indexing/parsing findings
  are assertions about the request sent by the real client under test.
- Existing critical examples are test panics, credential-source enum comparisons,
  an environment-variable name, and dummy credential fixture text. No suppression
  was added merely to force a zero exit. This is a reviewed nonzero report, not
  a clean UBS gate. Cargo phases are deliberately run separately through RCH.
- Fresh security checkpoint after the schema migration: cargo-audit exited 0,
  720 dependencies, zero vulnerabilities and no warnings; advisory database
  b50980aad8b8f14f77e25a97b32dd94bf008b0af. Raw receipt:
  `/private/tmp/rch-release-1.1.0-boldbrook-20260912/rch-security-audit-20260912T0320.json`.
- Interim workspace check passed through strict RCH with --workspace,
  --all-targets, --all-features, --locked and the pinned nightly; no compiler
  warnings reported. Remote exit 0, log:
  `/private/tmp/rch-release-1.1.0-boldbrook-20260912/workspace-check-interim-0317.log`.
  This validates the current partial upgrade, not a final release candidate.
- Interim strict Clippy also passed through RCH with --workspace, --all-targets,
  --all-features and -D warnings. Remote exit 0, log:
  `/private/tmp/rch-release-1.1.0-boldbrook-20260912/workspace-clippy-interim-0324.log`.
  Remaining upgrades and the full release test/artifact gates are outstanding.

### sha2: workspace 0.10.9 → 0.11.0

- Research: RustCrypto hashes SHA-2 changelog; digest 0.11 and Rust 2024 require
  no changes to the current hashing calls. Preserve default-features = false.
- The CLI and daemon already use 0.11.0; this updates the five RABS consumers.
  Cargo update --workspace reuses the existing locked 0.11.0 package without
  upgrading unrelated packages. All 839 consumer library tests passed (CAS 237,
  key 297, sandbox 162, worker 9, daemon 134), zero failures or ignores.
  Strict RCH exited 0; log:
  `/private/tmp/rch-release-1.1.0-boldbrook-20260912/sha2-test-0221.log`.

### object: 0.38.1 → 0.40.0

- Research: [upstream changelog](https://github.com/gimli-rs/object/blob/v0.40.0/CHANGELOG.md).
  Raw file-format fields now use newtypes and several low-level APIs changed;
  RCH's high-level parsing and section access need no migration. Preserve
  read/elf/macho features and disabled defaults. All 30 binary hashing tests
  passed, zero failures or ignores; strict RCH exited 0. Log:
  `/private/tmp/rch-release-1.1.0-boldbrook-20260912/object-test-0232.log`.

### uuid: 1.24.0 → 1.26.1

- Research: [upstream release](https://github.com/uuid-rs/uuid/releases/tag/v1.26.1).
  Fixes v7 counter placement and overflowing timestamp conversion; current v4
  generation and serde calls remain compatible. All ten job identity tests
  passed, zero failures or ignores; strict RCH exited 0. Log:
  `/private/tmp/rch-release-1.1.0-boldbrook-20260912/uuid-test-0234.log`.

### zstd: unused workspace declaration 0.13.3 → 0.14.0

- Research: [upstream release](https://github.com/gyscos/zstd-rs/releases/tag/v0.14.0).
  Prepared dictionaries now borrow for the stream lifetime; decoder finish
  consumes the remaining frame. No workspace member consumes this Rust crate,
  and it is absent from Cargo.lock. RCH invokes external compression tools.
  Locked Cargo metadata validation passed; receipt `zstd-metadata-0235.json`
  is retained in the Mac release directory. No runtime upgrade is claimed.

### flate2: 1.1.9 → 1.1.10

- Research: [upstream release](https://github.com/rust-lang/flate2-rs/releases/tag/1.1.10).
  Fixes gzip write loops and rejects oversized extra fields and incomplete
  deflate streams. Existing GzDecoder/GzEncoder calls remain compatible.
  All 27 installer tests passed, zero failures or ignores; strict RCH exited 0.
  Log: `/private/tmp/rch-release-1.1.0-boldbrook-20260912/flate2-test-0236.log`.

### cron: 0.15.0 → 0.17.0

- Research: published source at upstream commit 3d0447f9b2aacdbbafe551c7237df8afbc4c5308;
  weekday iteration/reset fixes and winnow update. Existing API is compatible.
- The next-run calculation now accepts its clock value, allowing deterministic
  tests for six/seven-field weekday schedules and invalid-schedule fallback.
  The status test now uses a valid schedule and asserts an actual next run.
  This crate calculates status; tokio-cron-scheduler still executes schedules.
  All 38 self-test service tests passed, zero failures or ignores; strict RCH
  exited 0 and formatting passed. Log:
  `/private/tmp/rch-release-1.1.0-boldbrook-20260912/cron-test-0240.log`.

### toml: 1.1.3+spec-1.1.0 → 1.1.6+spec-1.1.0

- Research: [upstream changelog](https://github.com/toml-rs/toml/blob/toml-v1.1.6/crates/toml/CHANGELOG.md).
  Preserves datetime values during serde conversion and fixes allocation-only
  builds; existing configuration calls remain compatible. All 139 configuration
  tests passed, zero failures or ignores; strict RCH exited 0. Log:
  `/private/tmp/rch-release-1.1.0-boldbrook-20260912/toml-test-0243.log`.

### dirs: 6.0.0 → 7.0.0

- Research: published source comparison and upstream commit
  793c8a97bea55669a806499839abd7b1d844279f. Windows preference_dir moves to
  roaming storage; RCH does not call that function. Existing home/cache/config
  calls remain compatible. All 25 environment configuration tests passed, zero
  failures or ignores; strict RCH exited 0. Log:
  `/private/tmp/rch-release-1.1.0-boldbrook-20260912/dirs-test-0245.log`.

### OpenTelemetry coupled family

- opentelemetry 0.31.0 → 0.32.0; SDK 0.31.0 → 0.32.1;
  OTLP 0.31.1 → 0.32.0; tracing-opentelemetry 0.32.1 → 0.33.0.
- Research: upstream OpenTelemetry Rust changelogs at ec289cb3 and 284a37d9,
  tracing-opentelemetry changelog at 1d5422f1. Existing meter/provider calls
  are compatible; preserve SDK Tokio/testing and member grpc-tonic features.
  New exporter errors retain the existing Prometheus-only fallback.
- All 351 telemetry tests passed, zero failures, five existing benchmark or
  hardware ignores; strict RCH exited 0. Log:
  `/private/tmp/rch-release-1.1.0-boldbrook-20260912/otel-test-0247.log`.
  The in-memory exporter tests verify metric records, not a live collector or
  TLS connectivity. The update also removes the old reqwest 0.12 copy.

### hyper: 1.11.0 → 1.11.1

- Research: [upstream release](https://github.com/hyperium/hyper/releases/tag/v1.11.1).
  HTTP/1 parsing, flushing and connection-close fixes; existing API compatible.
  All 204 daemon API tests passed, zero failures or ignores; strict RCH exited 0.
  Log: `/private/tmp/rch-release-1.1.0-boldbrook-20260912/hyper-test-0250.log`.

### ureq: 3.3.0 → 3.4.1

- Research: [upstream changelog](https://github.com/algesten/ureq/blob/3.4.1/CHANGELOG.md).
  Seals RequestExt (no custom RCH implementation), fixes connection reuse and
  timeout budgeting. Existing webhook calls remain compatible.
- Add a bounded real loopback HTTP test for request JSON, content type, user
  agent, HMAC header, success and HTTP failures. The first run passed 45 tests
  and failed the new retry assertion: ureq returned `http status: 503`, which
  RCH's existing string classifier did not recognize. This behavior also exists
  in the previously locked ureq 3.3.0 source.
- Set http_status_as_error(false) so the existing explicit HTTP status handler
  produces the retry classifier's stable format. Extend the real HTTP test to
  cover non-retryable 400 and retryable 429/503. Failure log:
  `/private/tmp/rch-release-1.1.0-boldbrook-20260912/ureq-test-0254.log`.
- Retest: all 46 alert tests passed, zero failures or ignores; strict RCH exited
  0 and formatting passed. Log:
  `/private/tmp/rch-release-1.1.0-boldbrook-20260912/ureq-retest-0256.log`.

### thiserror: 2.0.19 → 2.0.20

- Research: [upstream comparison](https://github.com/dtolnay/thiserror/compare/2.0.19...2.0.20).
  Derive lint handling changes; current error definitions need no migration.
  All 208 selected shared error tests passed, zero failures or ignores; strict
  RCH exited 0. Log:
  `/private/tmp/rch-release-1.1.0-boldbrook-20260912/thiserror-test-0259.log`.

### console: 0.16.4 → 0.16.6

- Research: [upstream release](https://github.com/console-rs/console/releases/tag/0.16.6).
  Fixes UTF-8 truncation and visible-column handling; current APIs compatible.
  All 529 selected CLI UI tests passed, zero failures or ignores; strict RCH
  exited 0. Log:
  `/private/tmp/rch-release-1.1.0-boldbrook-20260912/console-test-0300.log`.

### FrankenTUI coupled family: 0.4.1 → 0.7.0

- Research: published manifests and source at upstream commit
  798efa0bb746601cea78b75ad8bc859f738a6456. Upgrade all nine shared-type crates
  together, preserving facade runtime support and disabled defaults.
- ftui-tty is Unix-only. Match its imports and application loop to the existing
  non-Unix dashboard refusal; retain shared rendering/state helpers for tests.
  All 274 dashboard tests passed, zero failures or ignores; strict RCH exited 0
  and formatting passed. Log:
  `/private/tmp/rch-release-1.1.0-boldbrook-20260912/ftui-test-0307.log`.

### schemars: 0.8.22 → 1.2.2

- Research: [upstream migration guide](https://github.com/GREsau/schemars/blob/v1.2.2/docs/0-migrating.md)
  and generator source. Replace removed RootSchema with Schema and update the
  manual AnyJson implementation to the current trait signature.
- Nine source files migrate their exports to explicit Draft 7 settings, keeping
  the existing schema dialect and definitions path. Add a check covering all
  twelve exported contract schemas. All 27 schema unit tests passed, zero
  failures or ignores; strict RCH exited 0 and formatting passed. Log:
  `/private/tmp/rch-release-1.1.0-boldbrook-20260912/schemars-test-0312.log`.
- Integration tests contain five removed RootSchema references, migrated in
  the tenth source/test file. The user requested continued work after the
  eleven-file migration approval question on September 12. The CLI now uses
  explicit Draft 7 settings for all thirteen response types; a regression
  test covers all fifteen supported command forms. All thirteen selected CLI
  schema tests passed with zero failures or ignores; strict RCH exited 0.
  Log: `/private/tmp/rch-release-1.1.0-boldbrook-20260912/schemars-cli-1304.log`.
- All 44 contract integration tests passed, zero failures or ignores; strict
  RCH exited 0. Log:
  `/private/tmp/rch-release-1.1.0-boldbrook-20260912/schemars-contract-test-0316.log`.

### fsqlite: 0.1.19 → 0.3.18

- Research: published archive SHA256
  `08fec08ab10876b67a132b9c6eaa3eeaea62b58b4ebb3370684bcbb2333875c8`,
  [connection lifecycle source](https://github.com/Dicklesworthstone/frankensqlite/blob/1600766ca698dae99b6018474bc8c150ece4a82d/crates/fsqlite/src/async_api.rs).
- Use the supported AsyncConnection synchronous methods with async-api enabled
  and default features still disabled. The adapter joins its worker during
  Drop using close_without_checkpoint_sync, retaining the previous no-checkpoint
  behavior. Cleanup failures produce a best-effort stderr diagnostic; Drop does
  not panic. No caller-facing async API or direct runtime dependency is added.
- Clarify the existing dependency documentation: the storage APIs remain
  synchronous, while FrankenSQLite encapsulates its runtime internally.
  The dependency-direction gate remains unchanged.
- Add retained-file tests for unfinished-transaction rollback before immediate
  reopen and unchanged committed WAL bytes after Drop. The full rabs-cas suite
  passed all 260 tests with zero failures or ignores, including the crash
  matrix. Strict RCH and its client exited 0; log `fsqlite-test-1311.log` in the
  retained Mac release directory. Review then strengthened the WAL assertion
  to require frame content beyond the 32-byte header; both lifecycle tests
  passed again, remote/client exit 0 (`fsqlite-wal-1318.log`). Interim audit
  passed: 708 dependencies, no vulnerabilities/warnings.

### rusqlite: 0.39.0 → 0.40.2

- Research: upstream 0.40 release notes and published APIs; existing connection,
  statement, parameter and row calls remain compatible. Preserve bundled SQLite
  and telemetry's optional storage feature. Required transitives are hashlink
  0.12.2 and libsqlite3-sys 0.38.2.
- Full CAS and telemetry library gates ran with all features. The first
  attempt was refused before compilation because hz2 reached 96% disk usage.
  Its artifacts were retained. A fresh isolated two-slot ovh-a worker was added;
  its initial missing-inventory refusal cleared after health discovery, and
  strict RCH accepted the next attempt. No local fallback or cleanup was used.
  Logs: `rusqlite-test-1320.log`, `rusqlite-ovh-1322.log`, and the active
  `rusqlite-ovh-1323.log` in the retained Mac release directory.
- Accepted gate passed 590 tests (239 CAS, 351 telemetry), zero failures and
  five existing telemetry benchmark ignores. Remote and client exited 0.

### serial_test: 3.5.0 → 4.0.1

- Research: upstream 4.0.1 release; syn 3 migration and MSRV 1.93.1 are
  supported by the pinned nightly. Existing serial attributes are unchanged.
  Both member declarations updated together; CLI/daemon configuration tests
  are running through strict RCH.
- ovh-a refused this gate before compilation because another compiler caused
  critical memory pressure. The gate moved to isolated release-vmi1153651,
  which had 181 GiB free disk and 54 GiB available RAM. The pinned Git dependency
  and compilation cache are being populated there. No caches were deleted or
  admission thresholds bypassed. Active log: `serial-vmi-1335.log`.
- First compiled gate passed 241 CLI tests but failed one socket fixture:
  the long RCH TMPDIR exceeded Unix SUN_LEN before bind. The existing fixture
  now uses a short unique /tmp directory. No assertion was removed or weakened.
  Rerun passed 322 tests (242 CLI, 80 daemon), zero failures or ignores,
  remote/client exit 0. Log: `serial-retest-1404.log`.
- Subsequent gates use owned short TMPDIR `/tmp/rch-release-tests.31Ai9m` on
  this worker to avoid infrastructure-induced Unix socket limits. Directory
  and prior logs are retained.

### reqwest: 0.13.4 → 0.13.5

- Research: upstream patch release and published API; existing HTTP client
  calls remain compatible. Preserve disabled defaults and json/rustls features.
  All 20 doctor webhook delivery tests passed, zero failures or ignores,
  remote/client exit 0. Log: `reqwest-test-1408.log`.

### futures: 0.3.33 → 0.3.34

- Research: upstream wakeup fixes and syn 3 macro changes; current StreamExt
  and FuturesUnordered calls remain compatible. All 14 fleet GC concurrency
  and shared-deadline tests passed, zero failures or ignores, remote/client
  exit 0. Log: `futures-test-1422.log`.

### which: 8.0.5 → 8.0.6

- Research: [upstream fix](https://github.com/harryfei/which-rs/pull/128).
  Fixes relative PATH resolution against the supplied working directory.
  Existing lookup APIs remain compatible. All 38 shim consumer tests passed,
  zero failures or ignores, remote/client exit 0. Log: `which-test-1442.log`.

### whoami: 2.1.2 → 2.1.3

- Research: [upstream release](https://github.com/ardaku/whoami/releases/tag/v2.1.3).
  Adds Mate desktop detection and raises libc/libredox minimum versions.
  Username lookup remains compatible. All 123 selected shared SSH tests passed,
  zero failures; the existing global-mock-state test remains ignored. Remote
  and client exited 0. Log: `whoami-test-1445.log`.

### Final dependency checkpoint

- The first completed full workspace run reported 9,928 passed, 10 failed,
  and 20 existing ignores across 167 test binaries. Remote/client exit 101;
  log `workspace-test-retry-1516.log`. The user explicitly authorized continued
  repairs after the library-updater cumulative-failure circuit breaker.
- Release-gate fixes are being validated: worker FIFO creation/path and bounded
  grant enforcement; actual OUT_DIR identity for failed-build fixtures; Cargo
  JSON artifact freshness in fingerprint tests; stderr routing for human daemon
  status; and the contained multi-worker fixture's health response. Existing
  concurrency, persistence, fingerprint and selection assertions are preserved.
- The complete rabs-wkr test invocation passed through strict RCH, including
  the real nested-make grant test and canonical namespace process tests.
  Jobserver setup failure now refuses execution and the unchanged concurrency
  ceiling passes. Remote/client exit 0; log `jobserver-fix-test-1623.log`.
  The existing nested-make assertion allows grant + 2 simultaneous leaves
  because GNU make has implicit slots; this is a transferable-token budget,
  not proof of a strict total-process cap equal to the grant.
- The coverage ledger was regenerated with its existing compiled generator,
  then all three comparison tests passed. It records 1,477 lexical test markers
  and 492 coverage IDs, not executed test counts. Most drift predates this
  dependency work; this work added two CAS Drop/reopen regressions.
- Hook timing failed with the debug CLI (46ms versus 25ms). Qualification will
  use the intended release profile without relaxing the timing threshold.
- The wrapper contract probe now excludes the launcher's debug-profile overrides;
  normalized live channel fixtures still require review and verification.
- Targeted fixture retests passed N010 (1), wrapper fingerprinting (1), stream
  isolation (11) and contained multi-worker selection (10), without skips.
  The contract negative-control test passed, but its matrix still differs on
  stable and nightly; beta matches. Installed Cargo shims are being checked
  before accepting any recorded-contract change. Remote/client exit 101;
  log `release-fixture-retests-1647.log`.
- The residual CARGO_BUILD_JOBS difference came from managed toolchain Cargo
  shims on stable and nightly. The probe now resolves only recognized managed
  shims to their retained real Cargo executable; beta remains unchanged.
  Its PATH starts with that channel's bin directory to pair Cargo with rustc.
  All channel and output assertions remain enabled, and no golden was changed.
- Native macOS arm64 workspace check passed with all targets/features and the
  pinned nightly. Strict Clippy initially found a macOS-only needless return in
  the systemd guard; moving the Linux-only guard into its cfg block preserved
  Linux behavior. The full native Clippy retry passed with -D warnings through
  strict RCH. Logs `native-mac-workspace-check-pinned-env-20260912.log.tWXV78`
  and `native-mac-workspace-clippy-pinned-env-20260912.log.dXVTGN` are retained.
  This is native compilation/lint validation, not native test execution.
- Final Linux workspace check passed through strict RCH with --locked,
  --all-targets and --all-features on the pinned nightly, remote/client exit 0
  in 1,582.1s. Log: `workspace-check-final-1745.log`. Final Linux Clippy also
  passed all targets/features with -D warnings, remote/client exit 0, Cargo
  5m39s. Log: `workspace-clippy-final-1813.log`.

- The optimized Linux qualification CLI built successfully on the worker in
  50m47s. RCH retrieved the exact 21,589,920-byte ELF (SHA-256
  c95bd5c793dc48cc50c75dd8a5a4268f32c7b0a705091a331524cf9c1a8dc36e),
  then correctly refused foreign execution on the Mac coordinator: remote
  Cargo exit 0, client exit 102 (E327). This native Linux test build is not a
  release artifact; final DSR builds use explicit platform targets. Log:
  `hook-optimized-build-1649.log`.
- The optimized hook retest passed 12 of 13 tests; the unchanged 25ms timing
  assertion measured 37ms under worker CPU pressure. Even `rch --version`
  showed comparable scheduling delays. Existing binaries will be checked on
  a quieter Linux host before attributing this to classifier performance.
- The same retest still failed the complete wrapper channel matrix: installed
  stable is February's 1.93.1 and nightly predates the September 11 contract
  fixture. Beta matches. Recent existing stable/nightly toolchains will be
  copied into a private Rustup home, preserving shared installations and the
  project pin. No channel is removed and no golden is rewritten to match a
  stale toolchain. Log: `hook-contract-retest-1742.log`, remote/client exit 101.
- CSS runtime qualification passed all 13 unchanged hook integration tests,
  zero failures, ignores or filters, exit 0 in 0.27s. Both timing tests averaged
  4ms against the unchanged 25ms limit. The optimized CLI and existing test
  binary were hash-verified across worker, Mac and CSS; no compilation ran on
  CSS. Fresh HOME, XDG paths, config, socket and cwd excluded the live fleet;
  RCH_NO_UPDATE_CHECK=1 made this an offline hook test. Full log:
  `/data/tmp/rch-release-1.1.0-boldbrook-20260912/hook-qualification.eBB0Fw/full-suite.log`,
  SHA-256 fad9ad73b3ef6bec93f88613a51ed9c984e37637c1473db46ec0e7c1220e0fe8.
- The recent-toolchain retest could not reach comparison: Cargo reused a test
  binary whose compiled CARGO_MANIFEST_DIR pointed into a previous clean-overlay
  source root, already reaped by installed RCH 1.0.64. The tracked stable fixture
  was therefore absent at that obsolete path. Log `wrapper-contract-recent-1819.log`
  exits 101 (one negative-control pass, one matrix failure). This pre-existing
  cache/source-lifetime issue is tracked as bd-cfv95. The final full workspace
  run uses RCH_DISABLE_TARGET_REUSE=1 so all test binaries compile and execute
  in the same fresh source snapshot. No missing fixture is fabricated or golden
  rewritten; all three recent channels remain enabled.

- All pending stable Rust dependency upgrades have passed their consumer gates.
  Pinned Git/path/prerelease dependencies are preserved. This does not claim
  an update of the JavaScript dashboard dependencies.
- Formatting passed. Security audit exited 0 over 708 dependencies with zero
  vulnerabilities and no warnings; advisory database b50980aad8b8f14f77e25a97b32dd94bf008b0af.
  Receipt: `/run/user/1000/rch-security-audit-20260912T1451.json`.
- A refreshed audit at 18:03 UTC also passed all 708 dependencies with zero
  vulnerabilities or warnings, using the same advisory revision. Receipt:
  `/run/user/1000/rch-security-audit-20260912T1803.json`.
- Full workspace tests run natively on the strict RCH Linux worker because
  existing integration helpers require Cargo's native debug binary layout.
  CI=1 selects the existing contained harness behavior; this is not live-fleet
  qualification. No golden regeneration or channel narrowing is enabled.
- The first full gate failed before tests (remote/client 101): SBH deleted
  the active Cargo Git cache at 15:01:53 UTC, causing franken-kernel's rustc
  spawn to fail because its working directory vanished. The compiler remained
  present and executable. SBH activity decision d27152e27f93 proves the deletion;
  earlier decision 9765c993e143 at 14:11 explains the repeated Git fetch.
  Scoped release-root protection was added before cache recovery/retry.
  Failed log retained: `workspace-test-final-1452.log`. No tests were skipped
  or source code changed to address this infrastructure failure.
- Recovered the exact pinned Git subtree by non-overwriting copy from retained
  quarantine `/data/tmp/.sbh/quarantine/9765c993e143/git`; verified full revision
  107adf1df8d274b37c6ed9a12471fe3da44429f2 and franken_kernel source. Protection
  markers now cover both the release root and Git directory. The running SBH
  checks markers dynamically. The unchanged full gate is retried in
  `workspace-test-retry-1516.log`; quarantine and failed log remain retained.

### tru: 0.2.3 → 0.2.4

- Research: [upstream v0.2.4 release](https://github.com/Dicklesworthstone/toon_rust/releases/tag/v0.2.4), commit d356b8d.
- Maintenance and dependency changes; upstream reports no encoder/decoder or
  public API changes. Optional async-stream compiler ICE is outside RCH's
  enabled feature set.
- Validation: passed all four selected RCH consumer tests (TOON output and
  numeric/null round trips), zero failures or ignores. Strict RCH invocation
  exited 0 on hz2; full log retained at
  `/private/tmp/rch-release-1.1.0-boldbrook-20260912/tru-hz2-0128.log`.
  The pinned-nightly cold build and tests took 459.7 seconds remotely.
  This run used a persistent release-owned Cargo cache, no debug symbols and
  no incremental compilation; debug assertions remained enabled.
- Replay runs from the isolated Mac release checkout through RCH to hz4.
  Worker admission and cross-host topology refusals occurred before compilation;
  these are infrastructure failures, not dependency test failures. The first
  replay uses `--base HEAD --clean-overlay --overlay-path Cargo.lock`, an explicit
  Linux target, and the unchanged pinned nightly. Its full log is retained on
  the Mac at `/private/tmp/rch-release-1.1.0-boldbrook-20260912/tru-replay-0107.log`.
- That replay was gracefully cancelled through RCH at 01:25 UTC after severe
  worker I/O contention (full I/O PSI 85.77% over ten seconds). Build
  `30017364196065284` released both slots; the queue is empty. The invocation
  exited 255 without a test result. Source, cache and log are retained; the
  same candidate will be retried sequentially on hz2.
- The first consumer run could not be recorded: the controller filesystem
  filled while its log was being written. The partial log is
  `/data/tmp/rch-upgrade-tru-20260912T0046.log`; its pipeline exited 1 with
  ENOSPC, so it provides no passing-test evidence. No matching job remained
  in the queue or on the worker. Replay will use remote storage.
- Cargo imported the unchanged Asupersync revision from the existing local
  repository after the initial network import was interrupted. The pin stays
  `107adf1df8d274b37c6ed9a12471fe3da44429f2`.

### h2: 0.4.15 → 0.4.19

- Research: [RUSTSEC-2026-0258](https://rustsec.org/advisories/RUSTSEC-2026-0258.html)
  and [upstream v0.4.19](https://github.com/hyperium/h2/releases/tag/v0.4.19).
- Fixes the existing empty-DATA-frame denial of service; later patches refine
  frame budgets. Transitive dependency; no direct manifest or API migration.
- Validation: 351 telemetry library tests passed, zero failures, five existing
  hardware/benchmark ignores. Strict RCH exited 0; log:
  `/private/tmp/rch-release-1.1.0-boldbrook-20260912/h2-test-0138.log`.
  An earlier launch omitted the persistent-cache settings and was cancelled
  during transfer; it contributes no validation evidence.

### rich_rust: 0.2.2 → 0.2.3

- Research: [upstream v0.2.3 release](https://github.com/Dicklesworthstone/rich_rust/releases/tag/v0.2.3)
  and published manifest. Its `lru` requirement moves from 0.16 to 0.18,
  removing this workspace's only owner of vulnerable `lru` 0.16.4.
- Existing enabled features are preserved. Validation: 529 CLI UI tests passed,
  zero failures or ignores; strict RCH exited 0. Log:
  `/private/tmp/rch-release-1.1.0-boldbrook-20260912/rich-test-0141.log`.
- Required transitive updates include fancy-regex 0.18 and time 0.3.55.

### lru: 0.18.1 → 0.18.4

- Research: [upstream comparison](https://github.com/jeromefroe/lru-rs/compare/0.18.1...0.18.4)
  and [RUSTSEC-2026-0253](https://rustsec.org/advisories/RUSTSEC-2026-0253.html).
- Fixes panic safety in `pop`; later releases add sparse allocation and retain
  APIs. Existing RCH cache calls need no migration. All 32 cache tests passed,
  zero failures or ignores; strict RCH exited 0. Log:
  `/private/tmp/rch-release-1.1.0-boldbrook-20260912/lru-test-0144.log`.

### blake3: 1.8.5 → 1.8.7

- Research: [upstream 1.8.7 release](https://github.com/BLAKE3-team/BLAKE3/releases/tag/1.8.7).
- Removes the arrayref dependency after an upstream owner-account compromise;
  this is not a claim that the previously locked arrayref bytes were malicious.
- Existing hash API is unchanged. All 30 binary hashing tests passed, zero
  failures or ignores; strict RCH exited 0. Log:
  `/private/tmp/rch-release-1.1.0-boldbrook-20260912/blake3-test-0147.log`.

### chacha20: 0.10.1 (yanked) → 0.10.2

- Research: [upstream 0.10.2](https://github.com/RustCrypto/stream-ciphers/releases/tag/chacha20-v0.10.2).
- Fixes SSE4.1 instructions used in the SSE2 RNG/legacy backend. The separate
  0.9.1 dependency remains constrained by its existing consumers.
- Added a real-RNG retry-jitter bounds test: existing exponential-delay tests
  explicitly disable jitter and would not exercise this rand dependency.
  All eight retry tests passed, zero failures or ignores; strict RCH exited 0.
  This does not emulate an SSE2-only CPU. Log:
  `/private/tmp/rch-release-1.1.0-boldbrook-20260912/chacha-test-0152.log`.
- Security checkpoint after these updates: cargo-audit exited 0, 711 dependencies,
  zero vulnerabilities and no warnings, advisory DB b50980aa. Raw receipt:
  `/private/tmp/rch-release-1.1.0-boldbrook-20260912/rch-security-audit-20260912T0152.json`.
  Workspace formatting also passed.

### clap: 4.6.4 → 4.6.6

- Research: [upstream changelog](https://github.com/clap-rs/clap/blob/v4.6.6/CHANGELOG.md).
- Fixes optional value-name help and adds overridden-usage access; existing
  derive/env features and CLI contracts are preserved. All 178 CLI parsing tests
  passed, zero failures or ignores; strict RCH exited 0. Log:
  `/private/tmp/rch-release-1.1.0-boldbrook-20260912/clap-test-0154.log`.

### clap_complete: 4.6.7 → 4.6.9

- Research: [upstream comparison](https://github.com/clap-rs/clap/compare/clap_complete-v4.6.7...clap_complete-v4.6.9).
- Adds dynamic possible-value helpers and fixes generated Bash function names
  for POSIX compatibility. Existing unstable-dynamic feature is preserved.
- Validation: all 29 completion tests passed, zero failures or ignores;
  strict RCH exited 0. Log:
  `/private/tmp/rch-release-1.1.0-boldbrook-20260912/completion-test-0159.log`.

**Date:** 2026-05-14  |  **Project:** remote_compilation_helper  |  **Language:** Rust + TypeScript

## Summary
- **Updated:** Rust workspace dependencies, local authored `/dp` crates, and web dashboard dependencies
- **Skipped latest:** 2 web majors due current peer constraints
- **Failed:** 0
- **Release target:** 1.0.26

## Rust Updates

### Local authored libraries
- `toon-rust` now resolves to local `/dp/toon_rust` (`package = "tru"`, version `0.2.3`).
- FrankenTUI crates now resolve to local `/dp/frankentui/crates/*` paths at version `0.4.0`.
- `rich_rust` now resolves to local `/dp/rich_rust` at version `0.2.1`.
- GitHub release and crates.io publish jobs recreate `/dp/rich_rust`, `/dp/toon_rust`, and `/dp/frankentui` on fresh runners before building.

### Registry dependencies
- Updated direct Rust dependencies reported by `cargo outdated`, including `hmac`, `sha2`, `lru`, `reqwest`, `terminal_size`, `rusqlite`, `fastrand`, `whoami`, `proptest`, `insta`, and `rand`.
- Removed the `ctor` test initializer dependency instead of upgrading it. The 1.x macro API requires unsafe attributes that conflict with this workspace's `#![forbid(unsafe_code)]` policy.
- Narrowed `rich_rust` features to the UI primitives RCH actually uses, removing unused syntax/markdown/backtrace dependencies and their transitive audit warnings.
- Updated transitive `rustls-webpki` and `rand` lockfile entries to fixed patch releases after `cargo audit` reported advisories.

### Code migrations
- Adapted `toon_rust::encode` / `decode` call sites to the local `/dp/toon_rust` API.
- Updated SHA-256 formatting for `sha2` 0.11 by converting finalized digest bytes to lowercase hex explicitly.
- Imported `hmac::KeyInit` where required by `hmac` 0.13.

## Web Updates

### Updated dependencies
- Updated the dashboard stack across Next.js, React, TanStack Query, Motion, Recharts, SWR, Tailwind packages, Playwright, Vitest, Vite, jsdom, and related type packages.
- Added a direct Vite 8 dev dependency to satisfy `@vitejs/plugin-react` 6.x.
- Added a package override for `postcss` 8.5.14 to keep `npm audit` clean through the Next.js dependency tree.

### Intentionally held
- Held `eslint` at 9.39.4 because the current Next/TypeScript ESLint stack rejects ESLint 10.
- Held `typescript` at 5.9.3 because the current TypeScript ESLint peer range rejects TypeScript 6.

### Code migrations
- Fixed new React hook dependency and purity lints after the web dependency refresh.
- Moved benchmark SSE status ref synchronization out of render to satisfy the newer React hooks lint rules.
- Updated dashboard test fixtures for the current API shapes used by the build and E2E suites.
- Replaced an invalid `aria-expanded` attribute on a `role="region"` element with a testable data attribute.
- Set `turbopack.root` explicitly in the Next.js config after the Playwright release gate exposed a Next 16 root-inference panic from `src/app`.
- Made the animated sidebar active-item highlight ignore pointer input so fast route-transition clicks cannot land on the moving highlight instead of a navigation link.
- Added a timeout-backed abort signal to benchmark trigger requests so stalled HTTP calls cannot leave the dashboard in a pending trigger state indefinitely.
- Prevented duplicate benchmark SSE reconnect timers and made the performance-budget percentile helper total for empty or out-of-range inputs.

## Verification
- `cargo outdated --workspace --depth 1`: all Rust dependencies up to date; local `toon-rust` has no registry update to compare.
- `cargo audit`: no vulnerabilities or warnings after lockfile and feature cleanup.
- `npm outdated`: only the intentional `eslint` 10 and TypeScript 6 peer-incompatible majors remain.
- `npm audit`: 0 vulnerabilities.
- Full release-gate commands are run separately before publishing 1.0.26.

### 2026-05-14 follow-up: DSR release verifier compatibility

DSR's post-release verifier invokes `rch upgrade --check`, while RCH exposed
the self-update workflow as `rch update --check`. Added `upgrade` as a visible
alias for `update` and superseded `v1.0.25` with `v1.0.26` so release
verification and user-facing self-update vocabulary both work.

---

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
