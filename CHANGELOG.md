# Changelog

All notable changes to **rch** (Remote Compilation Helper) are documented here.

Changes are organized by version and grouped by landed capability rather than raw diff order. Tags that correspond to actual [GitHub Releases](https://github.com/Dicklesworthstone/remote_compilation_helper/releases) are marked with **(release)**; other versions are git-tag-only.

Repository: <https://github.com/Dicklesworthstone/remote_compilation_helper>

---

## [Unreleased] (since v1.0.14)

No unreleased changes yet.

---

## [v1.0.14] -- 2026-03-23 **(release)**

### Worker scheduling safety

- Prevent concurrent builds for the same project from landing on the same worker checkout. The daemon now excludes workers already active for that project and uses an atomic active-build claim after slot reservation to close the last same-project race in worker selection. ([fbea95f](https://github.com/Dicklesworthstone/remote_compilation_helper/commit/fbea95f7b65903859a3e81f7f01d9ced28ac7ee2))

### Dependency maintenance

- Update dependencies to resolve security advisories. ([1548842](https://github.com/Dicklesworthstone/remote_compilation_helper/commit/154884291146b73177c122e1856c0d287767ef50))

### Configurable path topology

- New `[path_topology]` config section allows operators to define custom project root directories instead of hardcoded `/data/projects` and `/dp` conventions. All project-hash call sites now respect the configured policy. ([87b8bc6](https://github.com/Dicklesworthstone/remote_compilation_helper/commit/87b8bc6cdce9036b3f61877c9bffdb2b4e413eaa), [a04737f](https://github.com/Dicklesworthstone/remote_compilation_helper/commit/a04737f7a1a78c0eafe76feb0bfcf386d9dc34aa))

### Hook system expansion

- Major expansion of the hook lifecycle: additional compilation event handling, improved orchestration, and expanded compilation config types in the transfer pipeline. ([698422c](https://github.com/Dicklesworthstone/remote_compilation_helper/commit/698422cbe71ab0a2fcaf9720e6abe6b0ab3a532e), [a92c452](https://github.com/Dicklesworthstone/remote_compilation_helper/commit/a92c4528d730d24765d009db3e6f59f0c0987b02), [eb516a4](https://github.com/Dicklesworthstone/remote_compilation_helper/commit/eb516a4a299ce772c3f0c19b6e02a13f52c1d203), [aed2477](https://github.com/Dicklesworthstone/remote_compilation_helper/commit/aed247792bda9e83c33d8f75a5ccba8181b5635c), [e713602](https://github.com/Dicklesworthstone/remote_compilation_helper/commit/e7136026e69cfe85905dc189d87dc2bb97f3ff86))

---

## [v1.0.13] -- 2026-03-18 **(release)**

Metadata-only release bumping the release tag to match v1.0.12 content.

- Release v1.0.13 ([e69e0e2](https://github.com/Dicklesworthstone/remote_compilation_helper/commit/e69e0e2c921961046a787cf21013f76e772c3a98))

---

## [v1.0.12] -- 2026-03-18 **(release)**

### Worker selection and scheduling

- Priority-based worker selection with cache affinity and speed-score tiebreakers; improved cache tracker to better reflect per-project build locality. ([9b2106b](https://github.com/Dicklesworthstone/remote_compilation_helper/commit/9b2106be68c57b9d4064850bc341393e8954caa9))

### Remote process lifecycle

- Remote process group cleanup via PGID file so orphan build processes on workers are reliably reaped. Cancellation and history refinements accompany the change. ([ea86c25](https://github.com/Dicklesworthstone/remote_compilation_helper/commit/ea86c2573e322c961fc4972e6f473d6710bdc4d8))

### Compilation configuration

- Exposed compilation slot and timeout config fields (`build_slots`, `test_slots`, `check_slots`, `build_timeout_sec`, `test_timeout_sec`, `bun_timeout_sec`) and wired them through the remote execution pipeline so operators can tune concurrency per build type. ([3a65c86](https://github.com/Dicklesworthstone/remote_compilation_helper/commit/3a65c86c4c35d27aed96f5f36d315095a3bf9306))

---

## [v1.0.11] -- 2026-03-17 **(release)**

Large release spanning the full reliability subsystem, TUI migration, and many operational improvements.

### Reliability subsystem (bd-vvmd epic)

#### Repo convergence service

- New `RepoConvergence` service tracks which repositories each worker has, detects drift from the required dependency graph, and provides operator commands (`status`, `dry-run`, `repair`). A background periodic convergence loop alerts on drift automatically. Convergence checks are integrated into worker selection so builds avoid workers missing required repos. ([b51d1ed](https://github.com/Dicklesworthstone/remote_compilation_helper/commit/b51d1ed769c8c91a1c56128c45e9c2194016fcfd), [a876f0c](https://github.com/Dicklesworthstone/remote_compilation_helper/commit/a876f0c7b560959ac7755cba31b8809c25a5f1b9), [db0728d](https://github.com/Dicklesworthstone/remote_compilation_helper/commit/db0728d160ac8022d60c6c2837045f80cd7af5f5), [c8fe9bf](https://github.com/Dicklesworthstone/remote_compilation_helper/commit/c8fe9bf7443f1906b31ce0f8e50c058fbaf01418))

#### Disk pressure resilience

- Disk pressure module scores worker storage health, integrates into daemon lifecycle, worker selection, and status reporting. Predictive headroom estimator and reservation model prevent scheduling builds that would fill a disk. Safe reclaim module protects active builds while reclaiming space with bounded budgets. Scheduler admission control rejects builds when pressure is too high. 32 integration tests cover disk-full prevention and recovery. ([660e7a4](https://github.com/Dicklesworthstone/remote_compilation_helper/commit/660e7a406973a07023786e4b85d0536c6f07a633), [ea3ba1a](https://github.com/Dicklesworthstone/remote_compilation_helper/commit/ea3ba1a120a24fb6c2b421d530bfb6d5d72eb791), [320780d](https://github.com/Dicklesworthstone/remote_compilation_helper/commit/320780d0f59520dfdd9b8326e3d161eb740774a8), [6bae14b](https://github.com/Dicklesworthstone/remote_compilation_helper/commit/6bae14b6d09dbd319c02c77f5a691045938c2233), [fcfe4e8](https://github.com/Dicklesworthstone/remote_compilation_helper/commit/fcfe4e82f01ea66ea79561b03e67780f8b3e13ec))

#### Process triage and remediation

- Bounded remediation pipeline with TERM/KILL escalation and full audit trail. Periodic triage loop and on-demand triage command for operator intervention. ([b70e4e7](https://github.com/Dicklesworthstone/remote_compilation_helper/commit/b70e4e7bc643fd1d4a78cfc1a3108a531e3ec49d), [a770153](https://github.com/Dicklesworthstone/remote_compilation_helper/commit/a770153cecdd2d1e7f86b29c853af19cca8f8c1b))

#### Unified reliability model

- Multi-signal reliability model unifies health, convergence, pressure, and triage data into a single worker health score used by the scheduler. ([3c55240](https://github.com/Dicklesworthstone/remote_compilation_helper/commit/3c55240cec81e30bded7196ba7fa7cfd91293a0a))

#### Cancellation orchestration

- `CancellationOrchestrator` with deterministic state machine and bounded escalation. Cancellation metadata wired into build history, daemon status API, doctor, TUI, and status display. E2E cancellation test scripts added. ([38260cd](https://github.com/Dicklesworthstone/remote_compilation_helper/commit/38260cd359789c50fe2bf528cd848f0a1b4c52d2), [882545e](https://github.com/Dicklesworthstone/remote_compilation_helper/commit/882545ea6d2a08455b2eea3b9826100d428d7387), [1b54521](https://github.com/Dicklesworthstone/remote_compilation_helper/commit/1b54521f56a0899e9cd3d692753bfdd0688cbb3d))

#### Dependency closure planner

- Builds can now include required repository closure (transitive path dependencies) rather than syncing a single root. Cargo metadata timeout and binary hash hardening also added. ([8363b75](https://github.com/Dicklesworthstone/remote_compilation_helper/commit/8363b75ed0a2c10b9876943c1b281bd09b2d97be), [2815b6d](https://github.com/Dicklesworthstone/remote_compilation_helper/commit/2815b6d19f593880db031a3cb1198c75d6fc4b6e), [d6590d1](https://github.com/Dicklesworthstone/remote_compilation_helper/commit/d6590d16ec0272834c1951bd79abbcaf244dfa38))

### Unified status and posture

- Unified status overview surfaces system posture, convergence state, pressure, and actionable remediation hints in a single view. Error code taxonomy extended with 28 new codes for path-deps, closure, storage, and process-triage. ([ddd0bec](https://github.com/Dicklesworthstone/remote_compilation_helper/commit/ddd0becbef253ed938439381439a38c39ca04063), [b571053](https://github.com/Dicklesworthstone/remote_compilation_helper/commit/b571053b44a6f60bb67ed9f791ebe5edd3f6aa56))

### TUI migration to FrankenTUI

- Terminal UI layer migrated from ratatui/crossterm to FrankenTUI native stack, including workspace dependency updates. Buffer rendering fix for empty cells and frame rect origin normalization. ([365f607](https://github.com/Dicklesworthstone/remote_compilation_helper/commit/365f6072e16c72d487d3b1c833b8dd5d187b1d75), [e68db7d](https://github.com/Dicklesworthstone/remote_compilation_helper/commit/e68db7d27f25f389d8a6979db67dfcf99f0a57be), [86cd921](https://github.com/Dicklesworthstone/remote_compilation_helper/commit/86cd921b41755091039ec3a1a004e061eeeacd74))

### Command classification and shell safety

- Shell-aware command tokenizer, classification regression tests, and timing budget assertions ensure the 5-tier classifier remains fast and accurate. Output truncation with SIGPIPE prevention added for large build outputs. ([1b867f1](https://github.com/Dicklesworthstone/remote_compilation_helper/commit/1b867f12d88c3e9196c88c2f813781a22262064d), [2ff8c3c](https://github.com/Dicklesworthstone/remote_compilation_helper/commit/2ff8c3c2c9007e45f2a72e7ea0e6cf85f171aefd), [78d2f9f](https://github.com/Dicklesworthstone/remote_compilation_helper/commit/78d2f9fcc96edc7577bf0626c3e2e5443ff10070))

### Hook and daemon improvements

- Dynamic daemon timeout with queue-aware behavior. Hook skips `repo_updater` pre-sync when local sync roots are dirty. Worker disk space probed from project root instead of `/tmp`. Concurrent agent updates to hook timeout logic handled safely. ([202a3d9](https://github.com/Dicklesworthstone/remote_compilation_helper/commit/202a3d9fa86001f573de32857ecb233ec39bdd9c), [720f980](https://github.com/Dicklesworthstone/remote_compilation_helper/commit/720f9804aa06ad0959009984955ab371e7e8233b), [4f4f01e](https://github.com/Dicklesworthstone/remote_compilation_helper/commit/4f4f01ea8bea7e6522bb108326989f9d76b58002))

### SSH and transfer

- SSH ControlMaster defaulted to off with fallback retry, fixing alias-based path topology issues. Broken pipe errors from protocol deadlock eliminated. Portable builds enabled by replacing local frankentui path deps with git deps. ([464a25b](https://github.com/Dicklesworthstone/remote_compilation_helper/commit/464a25bef50df62e8ef324b946b7585b0499ed11), [fdcab48](https://github.com/Dicklesworthstone/remote_compilation_helper/commit/fdcab4834114e35a508d7206b9102906a1e2ee77), [ef566dd](https://github.com/Dicklesworthstone/remote_compilation_helper/commit/ef566ddc86b62e241aba0a09da73dc0d6894b6b2))

### Worker tooling

- `rch-wkr benchmark` now supports `--json` and `--format` output flags. ([a2ac6b3](https://github.com/Dicklesworthstone/remote_compilation_helper/commit/a2ac6b30acefb3963380dd71d4eef4f078be8b2e))

### Cargo path dependency detection

- Hook detects cargo path dependencies and expands the transfer set accordingly. Common-library logic simplified. ([286b138](https://github.com/Dicklesworthstone/remote_compilation_helper/commit/286b138c4d76c4af74815e492ea6b0983df3d925), [68f6434](https://github.com/Dicklesworthstone/remote_compilation_helper/commit/68f6434c168015e99a3daafbde56190e16c7ae52))

### Build lifecycle hooks

- Pre/post build lifecycle callbacks in the hook system and false toolchain fallback avoidance. ([d91d967](https://github.com/Dicklesworthstone/remote_compilation_helper/commit/d91d96759d9c03a3766e97c389c0c0cfdb2be9fa), [9996a37](https://github.com/Dicklesworthstone/remote_compilation_helper/commit/9996a37b8db5eb328b1926f2bc3048434ece123c))

### Security and correctness

- Sensitive value masking handles quoted strings. User-isolated cache directory. 24-hour hard timeout for stuck builds. Epoch-based build IDs for uniqueness. Double slot release prevention. ([3fb98ce](https://github.com/Dicklesworthstone/remote_compilation_helper/commit/3fb98ce393a146629dcef938e12f629b833d7546), [4cc9f7e](https://github.com/Dicklesworthstone/remote_compilation_helper/commit/4cc9f7e6f719a72d31f8e11abf2294893cde8738), [08ae6e7](https://github.com/Dicklesworthstone/remote_compilation_helper/commit/08ae6e7202bc10872f06f1dac68e209ea8be1bec))

### Testing

- 15-file comprehensive reliability E2E test suite, schema contract E2E tests, Criterion microbenchmarks for the reliability pipeline, and operator runbook. Test suites for path deps, convergence, triage, and fault injection. ([77074ba](https://github.com/Dicklesworthstone/remote_compilation_helper/commit/77074ba7a6da582a4198b407e1572c610c8ee1a2), [7aefab2](https://github.com/Dicklesworthstone/remote_compilation_helper/commit/7aefab26551a915d8bd6861c2547e53e33b628bc), [95c8e80](https://github.com/Dicklesworthstone/remote_compilation_helper/commit/95c8e808446aa070e40ca08748f69184d7585f69), [2498cb9](https://github.com/Dicklesworthstone/remote_compilation_helper/commit/2498cb9a826e7794a68d064a5de417df1e579c1a))

---

## [v1.0.10] -- 2026-02-14 **(release)**

### Daemon and test hardening

- Refactored daemon command dispatch, expanded SSH utility patterns, and hardened audit E2E tests. Integration tests now respect `CARGO_TARGET_DIR`. ([7cd10f6](https://github.com/Dicklesworthstone/remote_compilation_helper/commit/7cd10f6e7fdc812563c8dc41a03c7d1a5b5e8c86), [a5c5928](https://github.com/Dicklesworthstone/remote_compilation_helper/commit/a5c59280654ab87775fd3155eebe93d0efd31b10))

---

## [v1.0.9] -- 2026-02-14 (tag only)

Version bump and workspace alignment. Same functional content as v1.0.10 preparation.

- Bump workspace version to 1.0.9. ([0830c22](https://github.com/Dicklesworthstone/remote_compilation_helper/commit/0830c22ba52f2a8f35da469193cc717023c807ef))

---

## [v1.0.8] -- 2026-02-05 **(release)**

### Command classification fix

- Fixed classification of commands with `2>&1` stderr-redirect patterns that were being incorrectly rejected. Flaky compound-command classification tests removed in favor of deterministic coverage. ([ef5481b](https://github.com/Dicklesworthstone/remote_compilation_helper/commit/ef5481b46776a5e65807e907375adf1fb14f1807), [95b37c0](https://github.com/Dicklesworthstone/remote_compilation_helper/commit/95b37c0f21b50ab571553631b7f8843546c789cc))

---

## [v1.0.7] -- 2026-02-05 **(release)**

### Installer robustness overhaul

- Installer downloads versioned release artifacts instead of unversioned URLs. Asset retry logic with API fallback. Agent detection no longer fails the install when subcommands are missing. Reliable `$(whoami)` instead of `$USER`. Installer banner alignment and Unicode box width fixes. ([c0ab548](https://github.com/Dicklesworthstone/remote_compilation_helper/commit/c0ab5488cec0b21c85a49d2fc6576a039f150a6b), [58cc779](https://github.com/Dicklesworthstone/remote_compilation_helper/commit/58cc7790a20c0b99a08911c77de08e20fb735b96), [d46b97c](https://github.com/Dicklesworthstone/remote_compilation_helper/commit/d46b97c4036d169523425f9af314ce95f8e1bd6d), [a94c362](https://github.com/Dicklesworthstone/remote_compilation_helper/commit/a94c3623bc7ade3a81ddca069f02cc09fe415480))

### Fleet and worker deployment

- Installer auto-syncs workers after easy-mode install. `rch-wkr` is now installed for local fleet deploy. Fleet sync commands fixed. ([325a3c5](https://github.com/Dicklesworthstone/remote_compilation_helper/commit/325a3c5a8d8cccaba11f1738150f1ae05a87c817), [7a47261](https://github.com/Dicklesworthstone/remote_compilation_helper/commit/7a47261580a371a027754ba559e4e1ff57593c37), [85be397](https://github.com/Dicklesworthstone/remote_compilation_helper/commit/85be397b09be3f139eaa26033bfb22eddccb93fb))

### SSH path handling

- Tilde paths (`~/.ssh/...`) properly resolved for SCP uploads and remote operations. ([c31f60c](https://github.com/Dicklesworthstone/remote_compilation_helper/commit/c31f60cd855a336dc10ce9fad1d012abded4d6aa), [c4a5912](https://github.com/Dicklesworthstone/remote_compilation_helper/commit/c4a591248b62a94440632ef3867ff6f02e523b18))

### Hook infrastructure

- Comprehensive git hook infrastructure with pattern-based file matching. Externalized shell installer and PowerShell checksum fix. ([ef0f90b](https://github.com/Dicklesworthstone/remote_compilation_helper/commit/ef0f90b7155e49d929e74fa02cf42c7b78626157))

### Platform compatibility

- Windows `run_exec` stub added. ([3a1d098](https://github.com/Dicklesworthstone/remote_compilation_helper/commit/3a1d098bef15d04cb74b94c772673a4cb20515f5))

---

## [v1.0.6] -- 2026-02-02 **(release)**

### CI and release workflow fixes

- Fixed release workflow build failures: removed unused linker env var causing ARM64 build failure, excluded `rchd` from Windows release package. ([9b256df](https://github.com/Dicklesworthstone/remote_compilation_helper/commit/9b256df7bd019479c84531f2e403565c826c921c), [9fd29a5](https://github.com/Dicklesworthstone/remote_compilation_helper/commit/9fd29a5919dd54bc73bd8fc391d1e1e528f57a88), [3feefb2](https://github.com/Dicklesworthstone/remote_compilation_helper/commit/3feefb2a231595bb17bd8c7956c1d50562868fcc))

---

## [v1.0.5] -- 2026-02-02 (tag only)

### Hook safety

- Hook installation now performs safe merge instead of replacing existing hooks, preventing loss of user-configured hooks. Installer restart-box alignment fix. ([2897b96](https://github.com/Dicklesworthstone/remote_compilation_helper/commit/2897b9674bcbde783e58bd3c451bfc8600e531c3), [2424694](https://github.com/Dicklesworthstone/remote_compilation_helper/commit/242469d433462e4a490f408950a1b5cad7540264))

---

## [v1.0.4] -- 2026-02-02 **(release)**

Version bump. Functional content matches v1.0.3 + v1.0.5 preparation.

- Bump version to 1.0.4. ([6fc2285](https://github.com/Dicklesworthstone/remote_compilation_helper/commit/6fc2285299bd00a7dab658fcaa220c9a35867601))

---

## [v1.0.3] -- 2026-02-02 **(release)**

Version bump. Released to lock in v1.0.2 content for distribution.

- Bump version to 1.0.3. ([5116d9f](https://github.com/Dicklesworthstone/remote_compilation_helper/commit/5116d9fb9e0a921cd073e408097514e8e6c9e85c))

---

## [v1.0.2] -- 2026-02-02 **(release)**

### Transparent command interception

- `AllowWithModifiedCommand` hook response enables transparent interception: the hook rewrites the command the agent sees so remote execution is invisible to the caller. ([cfdb411](https://github.com/Dicklesworthstone/remote_compilation_helper/commit/cfdb4115bf327827312f649027a291360db26f4f))

### Adaptive transfer compression

- Transfer pipeline now estimates payload size and selects compression level automatically. Size-threshold tuning included. ([0dbe0e5](https://github.com/Dicklesworthstone/remote_compilation_helper/commit/0dbe0e5d7831026144dcc1f9556693ad9d9f7c11), [5292845](https://github.com/Dicklesworthstone/remote_compilation_helper/commit/52928453cde3130f5ea7648cda95760f7b225fea))

### Security and reliability

- SSH disconnect on timeout to prevent leaked remote processes. Panicking `expect`/`unwrap` calls replaced with proper error handling. SSH pool TOCTOU race fixed. SSH socket security hardened with `StrictHostKeyChecking=accept-new`. Queue timeout with graceful fallback to local build. `whoami` crate replaced with env var lookup. ([4a76a2f](https://github.com/Dicklesworthstone/remote_compilation_helper/commit/4a76a2f2396b7a620b24b216279507ca56eb11d1), [b03131f](https://github.com/Dicklesworthstone/remote_compilation_helper/commit/b03131f07c1556338dd0bb87ca2c06e6edb1cd6b), [dcf2059](https://github.com/Dicklesworthstone/remote_compilation_helper/commit/dcf20590ad84f25c760042fe51b22792b976cec4), [a8ed079](https://github.com/Dicklesworthstone/remote_compilation_helper/commit/a8ed079242bb4c4b0c59fa3c175ebc81074d9c74), [412a875](https://github.com/Dicklesworthstone/remote_compilation_helper/commit/412a87548b59e27be4877e41869cf28b11e0fe15))

### Hook performance

- Config load deferred in the hook fast-path so non-compilation commands pay zero config overhead. ([014ae51](https://github.com/Dicklesworthstone/remote_compilation_helper/commit/014ae5139ddde56a04812935b4ee0cdd03d7edf5))

### Installer

- Installer respects `CARGO_TARGET_DIR` when building from source. Prominent restart reminder after hook installation. ([8057caf](https://github.com/Dicklesworthstone/remote_compilation_helper/commit/8057cafa477a5af8a65ccce0858087445df9e724), [c567338](https://github.com/Dicklesworthstone/remote_compilation_helper/commit/c56733bbd032608be4fbc1503e6bba28985231c6))

---

## [v1.0.1] -- 2026-02-01 **(release)**

### Daemon robustness

- Improved daemon robustness with timeouts, logging, and cache bounds. Timeouts and body size limits added to hook-daemon communication. Robust drift detection in benchmark scheduler. ([14d955a](https://github.com/Dicklesworthstone/remote_compilation_helper/commit/14d955a80bc1eb19e53e3279fc9504e83eaaa188), [8141d20](https://github.com/Dicklesworthstone/remote_compilation_helper/commit/8141d20523c238ebb14585490ee315995e5fff33), [c7a4e45](https://github.com/Dicklesworthstone/remote_compilation_helper/commit/c7a4e45e876481376916be6a70f5d2657866995e))

### Cross-platform compatibility

- SSH, Unix socket, and rich-UI code gated behind `cfg(unix)` for Windows/macOS cross-compilation. Platform-specific process detection for macOS lock handling. CI matrix refined for platform-appropriate crate exclusions. ([0b15482](https://github.com/Dicklesworthstone/remote_compilation_helper/commit/0b154821ad860a496933859cd458c0d68bd76f84), [adad172](https://github.com/Dicklesworthstone/remote_compilation_helper/commit/adad172eb44489e4fdf80fd3a23027fb16e1e9ef), [410713c](https://github.com/Dicklesworthstone/remote_compilation_helper/commit/410713c082ea44db49e4f50cad392aee1d8fa4e6))

### Refactoring and code quality

- Worker handler functions extracted from `api.rs` to `workers.rs`. Dead code from old multi-pass classifier removed (replaced by single-pass state machine). Deep audit fixes for security, reliability, and performance. Strict Sigstore certificate verification enforced for updates. `bail!()` calls converted to structured error types throughout. ([b579b20](https://github.com/Dicklesworthstone/remote_compilation_helper/commit/b579b20cc49e608a20ea9d4befc9bb064fd4e556), [a806111](https://github.com/Dicklesworthstone/remote_compilation_helper/commit/a806111ece977aab5c6912c403899d2ebf63bea6), [2886ce1](https://github.com/Dicklesworthstone/remote_compilation_helper/commit/2886ce1de6110ad8ad0255558767cff0d9e1cf3b), [a6ea157](https://github.com/Dicklesworthstone/remote_compilation_helper/commit/a6ea157a2c9f1ab3c22e5604d263a6fcfff2f7d3))

### Test stability

- Pipe buffer blocking fix in E2E test harness. Race condition removed from mock transport test. E2E multi-worker retry tolerance increased. All test harnesses respect `CARGO_TARGET_DIR`. ([6a83859](https://github.com/Dicklesworthstone/remote_compilation_helper/commit/6a83859f6b128bccacefe64fafcffc3beb19bd12), [21f01b3](https://github.com/Dicklesworthstone/remote_compilation_helper/commit/21f01b3aac3d675245ff247c6d859383569c1e44), [20bc2e5](https://github.com/Dicklesworthstone/remote_compilation_helper/commit/20bc2e58b778cf8e24692630ae625ef28eb05b45))

---

## [v1.0.0] -- 2026-01-29 **(release)**

First stable release. Massive expansion from the v0.1.x series, spanning fleet management, security hardening, CLI modularization, and install resilience.

### Fleet management

- Full fleet deployment: `rch update --fleet` and `rch fleet deploy|rollback|status|verify|drain|history`. Parallel rollback operations with graceful worker lifecycle. `SshExecutor` for shared fleet SSH infrastructure. Fleet status probes with async telemetry. Comprehensive E2E fleet test scripts. ([54fde73](https://github.com/Dicklesworthstone/remote_compilation_helper/commit/54fde7334a0f52539683ebbf55913d2708cbda3c), [77174578](https://github.com/Dicklesworthstone/remote_compilation_helper/commit/77174578d9477654e1c544129f2c212fc4ef7d7e), [8ce42a3](https://github.com/Dicklesworthstone/remote_compilation_helper/commit/8ce42a342d94fc3ccbae2bef0962fb686b7e3f13), [ab7a83c](https://github.com/Dicklesworthstone/remote_compilation_helper/commit/ab7a83c5e47dccb905ead7657ece48bd11706969))

### Installer resilience

- Installer auto-fallbacks to source build when prebuilt binaries are unavailable. Installer uses `cargo +nightly` instead of assuming default toolchain. TEMP_DIR leak fixed. Config doctor and config edit commands added. ([c7ffb48](https://github.com/Dicklesworthstone/remote_compilation_helper/commit/c7ffb48b92b4615ed6805a794b147f998a0f2c10), [76a82c8](https://github.com/Dicklesworthstone/remote_compilation_helper/commit/76a82c8e7e848f14171f8bd3d322e7fa303395b9), [0a5637b](https://github.com/Dicklesworthstone/remote_compilation_helper/commit/0a5637b5a99c73e187435e26b33e7542337f6f7d))

### CLI modularization

- `commands.rs` split into module directory with dedicated files for daemon, config, workers, queue, agents, and speedscore commands. Command helpers consolidated. `-y`/`--yes` flags for non-interactive use. `config get` and `config set` commands implemented. ([dd9b366](https://github.com/Dicklesworthstone/remote_compilation_helper/commit/dd9b366bbfcfd54eb9b890d6707891c52dd5d131), [943fedd](https://github.com/Dicklesworthstone/remote_compilation_helper/commit/943fedd809d01edfdc5456f80e92c89694f60f17), [5fff22f](https://github.com/Dicklesworthstone/remote_compilation_helper/commit/5fff22f7ee9cfcc0c647c0b5747df68bb57334e2), [0f09429](https://github.com/Dicklesworthstone/remote_compilation_helper/commit/0f694298f6fca460aac22b311af8a9dda129ccbc))

### Security

- Command injection prevention: commands with embedded newlines rejected. Update checksum verification enforced. Hook/daemon input limits hardened. Concurrent backup registry access protected with locks. ([553c064](https://github.com/Dicklesworthstone/remote_compilation_helper/commit/553c06421e497b89f2065b70726d3085c6976a5f), [2caa631](https://github.com/Dicklesworthstone/remote_compilation_helper/commit/2caa6311aea71aee01302319b24cbc54ee055ca0), [2f9de73](https://github.com/Dicklesworthstone/remote_compilation_helper/commit/2f9de73c94f97c1aa82b29df20e1a3188075ea1d), [c92f867](https://github.com/Dicklesworthstone/remote_compilation_helper/commit/c92f867499684bdcb6471c94b8340b9093997f3a))

### Performance

- `Classification` strings switched to `Cow<'static, str>` for zero-allocation hot paths. Timing estimation moved to `spawn_blocking`. Blocking IO moved off async thread in the hook. In-memory cache for `TimingHistory`. ([30503fe](https://github.com/Dicklesworthstone/remote_compilation_helper/commit/30503fe5c38c6e403ee550a4d9c056f3860db952), [071f3d5](https://github.com/Dicklesworthstone/remote_compilation_helper/commit/071f3d5bbd90097f2464c6102039020af724deac), [90752e5](https://github.com/Dicklesworthstone/remote_compilation_helper/commit/90752e570a6343c658621f4d4ac7439189ccd827), [c4ebdbb](https://github.com/Dicklesworthstone/remote_compilation_helper/commit/c4ebdbb905140dffb93f0f77e80958019da74231))

### TUI

- Detail bar showing full content of selected item. Config init wizard flag simplification. ([8e399bc](https://github.com/Dicklesworthstone/remote_compilation_helper/commit/8e399bcc676c5e49597d06d6cd9b3b091cf12f68))

### Update system

- Changelog diff computation for multi-version update jumps so users see aggregated changes. ([27a7e78](https://github.com/Dicklesworthstone/remote_compilation_helper/commit/27a7e7877798aec58d90fd5327a3816a4f7805f9), [6e014ee](https://github.com/Dicklesworthstone/remote_compilation_helper/commit/6e014eeb86d08b494d1039e8bb9f34988a1e37e9))

### Worker improvements

- Worker selection, health checks, and API robustness refined. Cache affinity uniqueness improved via path hash. Cache age overflow prevented with `saturating_mul`. Preflight checks and transfer handling refined. ([d830790](https://github.com/Dicklesworthstone/remote_compilation_helper/commit/d8307901f36e0f25c291692436693334ddd7b672), [16b7de3](https://github.com/Dicklesworthstone/remote_compilation_helper/commit/16b7de3f2a6e822d6e974e2e8f5f721a0250e005), [bd34757](https://github.com/Dicklesworthstone/remote_compilation_helper/commit/bd34757aa89442a35f926094586edaccabada8c7))

---

## [v0.1.64] -- 2026-02-01 (tag only)

Anomalous tag pointing to the same commit as the v1.0.1 version-bump. Likely created as a legacy reference; no unique content beyond what v1.0.1 covers.

---

## [v0.1.3] -- 2026-01-28 **(release)** -- "TUI Enhancements & Fleet Deployment"

### TUI enhancements

- Build history panel supports column sorting. Worker drain/enable controls and state selection API added. Help overlay expanded with drain/enable shortcuts. Emoji icons replaced with Unicode symbols for terminal compatibility. Confirmation dialogs restored for destructive worker actions. ([5ccf11a](https://github.com/Dicklesworthstone/remote_compilation_helper/commit/5ccf11aed530833919676f68748dbe354b34dcc8), [fc94b0a](https://github.com/Dicklesworthstone/remote_compilation_helper/commit/fc94b0a85229bd316abef5125ee90f2e15dc3647), [3a3e2be](https://github.com/Dicklesworthstone/remote_compilation_helper/commit/3a3e2befc403be9884238b6aec59816cc50f287c), [093ec90](https://github.com/Dicklesworthstone/remote_compilation_helper/commit/093ec9072431b5a177464297ee330d1558348d62))

### Fleet deployment progress

- `FleetProgress` struct for parallel deployment tracking, integrated into `FleetExecutor`. Fleet-wide worker binary deployment with Sigstore signature verification. ([126124](https://github.com/Dicklesworthstone/remote_compilation_helper/commit/126124392d04bd8b366baa8619c60f8fed8fbece), [92cc5eb](https://github.com/Dicklesworthstone/remote_compilation_helper/commit/92cc5ebb40b4a67fb1f9bf5fbb6fa0e5a0522834), [54fde73](https://github.com/Dicklesworthstone/remote_compilation_helper/commit/54fde7334a0f52539683ebbf55913d2708cbda3c), [34f5332](https://github.com/Dicklesworthstone/remote_compilation_helper/commit/34f5332787d835b6d46f67cf39836255d891b419))

### Health check command

- New `rch check` command for quick health verification. ([c964f66](https://github.com/Dicklesworthstone/remote_compilation_helper/commit/c964f667e62fcd66cda3dea7523bc411b5561731), [0bbf258](https://github.com/Dicklesworthstone/remote_compilation_helper/commit/0bbf2588c9f89babeacc42729019bacc95c826e5))

### CLI polish

- Verbose mode with live daemon status for `workers list`. Confirmation prompts for daemon stop/restart. Short flags (`-a` for `--all`, etc.). Drained worker status integrated across all UI layers. Parallel progress display for worker benchmarks. ([6e8ba9b](https://github.com/Dicklesworthstone/remote_compilation_helper/commit/6e8ba9bcc7e71b56c685dd22367cfbb655bc4612), [0b0b1fc](https://github.com/Dicklesworthstone/remote_compilation_helper/commit/0b0b1fc487347a60f68d13264e8ff4b85be2986a), [894ecd8](https://github.com/Dicklesworthstone/remote_compilation_helper/commit/894ecd8309d068503d4d6a4e9d1972cf13331729), [b951c64](https://github.com/Dicklesworthstone/remote_compilation_helper/commit/b951c647dfbb06ca1eeef54691979462de68a892), [d1d5ff6](https://github.com/Dicklesworthstone/remote_compilation_helper/commit/d1d5ff6672598a345fa032e7947d15e860905892))

### Error system

- Comprehensive error code system with structured diagnostics. SSH key path validation with comprehensive checks. ([17d6d2b](https://github.com/Dicklesworthstone/remote_compilation_helper/commit/17d6d2b74b15cb73e1d9095a0daf5ae713a9ac18), [280e835](https://github.com/Dicklesworthstone/remote_compilation_helper/commit/280e835b11b8ebf049928906b00e99eb38a447cf))

### Config validation

- Comprehensive validation for paths, SSH keys, and rsync patterns. ([8f074c5](https://github.com/Dicklesworthstone/remote_compilation_helper/commit/8f074c53da7023caa2d64cb42a83d2b6a3f6feac))

---

## [v0.1.2] -- 2026-01-27 **(release)** -- "Test Coverage & Stability Improvements"

### Test coverage expansion

- 2000+ lines of new unit tests across all components. Comprehensive proptest fuzz testing for SSH command escaping, config parsing, and command classification. Test coverage added for alerts, telemetry, health checks, self-healing modules, icon system (Unicode/ASCII fallback), and storage. Test performance regression detection infrastructure. Test guard instrumentation across daemon unit tests. ([595c715](https://github.com/Dicklesworthstone/remote_compilation_helper/commit/595c7152058caefd38de1e1603064313434f5ea5), [39be0a5](https://github.com/Dicklesworthstone/remote_compilation_helper/commit/39be0a55bb165323ad335c30eaad7f05b29abe28), [fc3ce1a](https://github.com/Dicklesworthstone/remote_compilation_helper/commit/fc3ce1af47245efa87b7c5c71b5f2945123375ca), [59d0a75](https://github.com/Dicklesworthstone/remote_compilation_helper/commit/59d0a75dc6cb21b8c00b594ea8d78904990462b2))

### Dashboard and monitoring

- Dashboard non-interactive modes for CI/monitoring environments. Web interface queued builds display and API updates. SpeedScore breakdown passed to badge. Saved-time summary verification script. ([8708a08](https://github.com/Dicklesworthstone/remote_compilation_helper/commit/8708a08db5599ab2fc711df96656bdccad16c3c1), [af71615](https://github.com/Dicklesworthstone/remote_compilation_helper/commit/af716151091d40f5eb065bc6de910b97f08dffbf), [0c05d1c](https://github.com/Dicklesworthstone/remote_compilation_helper/commit/0c05d1c5f5ed0524c1fa03ccb452a527375fa7b3))

### Build intelligence

- Build timing history for intelligent offload gating decisions. Wait-for-worker queueing and timing breakdown support. Remote speedup threshold documented and configurable. ([6aa1f2a](https://github.com/Dicklesworthstone/remote_compilation_helper/commit/6aa1f2aedd44e873b1933129d8379e0aae2a41f9), [19028fd](https://github.com/Dicklesworthstone/remote_compilation_helper/commit/19028fd8ced9b43e2a5b667b47b6fb3783895041), [8a68ff7](https://github.com/Dicklesworthstone/remote_compilation_helper/commit/8a68ff7e2fe5410ded27aefc6eeb9b8572ac2a70))

### Worker health and selection

- Worker health metrics in preflight checks. Cache affinity tracking expanded. Diagnose dry-run, transfer limits, and selection audit log. ([688baeb](https://github.com/Dicklesworthstone/remote_compilation_helper/commit/688baebad4b7f4426bd426d9eae151b3e4c391a8), [2d68fcc](https://github.com/Dicklesworthstone/remote_compilation_helper/commit/2d68fccebce45baaded48060544635fd89ab3353), [81a9430](https://github.com/Dicklesworthstone/remote_compilation_helper/commit/81a94302824951e601518503be68fcff84c2c453))

### Alert system

- Webhook dispatch for external notifications (async HTTP client). Daemon alerts surfaced and configurable. ([d16ff8a](https://github.com/Dicklesworthstone/remote_compilation_helper/commit/d16ff8a7db64268b85936d8e6fe929f07f033bdd), [fd64d1a](https://github.com/Dicklesworthstone/remote_compilation_helper/commit/fd64d1acbd85787f8e71d37cc4344294b07999be))

### Agent coordination

- `agents_list` and `agents_status` commands for multi-agent coordination. Queued builds exposed in daemon status API. Build queue management in `BuildHistory`. ([fc3ce1a](https://github.com/Dicklesworthstone/remote_compilation_helper/commit/23dffa45ff048e851fba342bc999d8e4cb0ee034), [8910de9](https://github.com/Dicklesworthstone/remote_compilation_helper/commit/8910de9bb2164e50c4b93dde2b6f24c7fe7795f2), [dbb6b17](https://github.com/Dicklesworthstone/remote_compilation_helper/commit/dbb6b17b2416c58d1f4e22596effcc6b5897e0e2))

### Self-healing

- Self-healing hook install hardened. Claude hook creation no longer makes `.claude` directory for non-Claude users. Self-healing cooldown logic tested. ([3909c89](https://github.com/Dicklesworthstone/remote_compilation_helper/commit/3909c890e10df4161a5e221e5200c85a3c5710de), [b1a129a](https://github.com/Dicklesworthstone/remote_compilation_helper/commit/b1a129abc83a1803ae87f98c0a8e83d1386e57c6))

### Miscellaneous

- `.rchignore` support with diagnose reporting. Cache cleanup scheduler. `--help-json` and `--capabilities` CLI flags. Transfer `remote_base` configuration option. SSH keepalive/ControlPersist. Classification cache. C/C++ true-E2E tests. Force-local/force-remote overrides. Retryable transport errors. Doctor auto-starts daemon on `--fix`. ([10140577](https://github.com/Dicklesworthstone/remote_compilation_helper/commit/10140577c17cc98aa16ee392b477a2409e4fd8a1), [d4b7432](https://github.com/Dicklesworthstone/remote_compilation_helper/commit/d4b7432e490e344c66682a214e30d0c6368d51b7), [bdb54e6](https://github.com/Dicklesworthstone/remote_compilation_helper/commit/bdb54e62558b4f8db8c0eaf4cd6a7ee019cac88b), [03c0827](https://github.com/Dicklesworthstone/remote_compilation_helper/commit/03c0827a70cd23c41c4dddcfb4d617f33a2cd5ce), [b93c96e](https://github.com/Dicklesworthstone/remote_compilation_helper/commit/b93c96e47efb10edb2cdb432561972e7848b1290), [a9c1a1a](https://github.com/Dicklesworthstone/remote_compilation_helper/commit/a9c1a1a8e107839dbf06784b52d237daedbc9876))

---

## [v0.1.1] -- 2026-01-26 (tag only)

### Daemon and API

- Enhanced daemon with improved health monitoring, hot-reload support (SIGHUP signal handling), and improved selection logic. GET `/status` API endpoint added. Daemon reload command and JSON response handling. ([5b8e8fb](https://github.com/Dicklesworthstone/remote_compilation_helper/commit/5b8e8fb1781886a4bdc541dac79ec2967b2e3873), [120b802](https://github.com/Dicklesworthstone/remote_compilation_helper/commit/120b802d214a68ccc71fcdc74c40ceeed5427af6), [433dbc4](https://github.com/Dicklesworthstone/remote_compilation_helper/commit/433dbc450d256f8941ccbea501019ee501bbd3cb), [2da910a](https://github.com/Dicklesworthstone/remote_compilation_helper/commit/2da910a1f4912a1725026f8af31c2dc0d9cec00b))

### Update system and verification

- Self-update verification and type definitions. Version check caching and improved backup management. Sigstore signing integration. ([54cb30a](https://github.com/Dicklesworthstone/remote_compilation_helper/commit/54cb30afc05380cbc1f77d84e556b6f865dc21bc), [c67499a](https://github.com/Dicklesworthstone/remote_compilation_helper/commit/c67499a2f7c039e9c26c40ebc236928a3bd74adc), [66c2601](https://github.com/Dicklesworthstone/remote_compilation_helper/commit/66c2601c58757c881d5c4f70bd3415d87c82b61c))

### Hook and agent integration

- Celebration UI for successful builds integrated into hook. Profile detection for environment-aware behavior. Hooks module added to `rch-common` for agent integration. Test command classification and structural checks. ([615bbfb](https://github.com/Dicklesworthstone/remote_compilation_helper/commit/615bbfbe42f9e92945df40acdfa8baff9e1c01d9), [5bb56f7](https://github.com/Dicklesworthstone/remote_compilation_helper/commit/5bb56f722661d9c3b7ad864d665e7be9c6361515), [059a66c](https://github.com/Dicklesworthstone/remote_compilation_helper/commit/059a66c7d6075cb9b3a1fc9bbe496943c34cf83e), [e6e07fb](https://github.com/Dicklesworthstone/remote_compilation_helper/commit/e6e07fb351aa164613af74e8c5f8ee4141ef43b9))

### CLI and TUI

- Queue command and doctor `--dry-run` option. TUI improvements and download reliability. State locking and transfer reliability improved. Doctor diagnostics enhanced. Worker capabilities command and API endpoint. ([4b5fa6e](https://github.com/Dicklesworthstone/remote_compilation_helper/commit/4b5fa6ed90c1c5bb02bff7bd7366956c3e77fb75), [3361adf](https://github.com/Dicklesworthstone/remote_compilation_helper/commit/3361adf52c71383c71560d84026e463a58cb58ef), [da2c3d9](https://github.com/Dicklesworthstone/remote_compilation_helper/commit/da2c3d96f4b695b75504dcf1bfb8b98eec90a4c9), [08f19c4](https://github.com/Dicklesworthstone/remote_compilation_helper/commit/08f19c424b7154e771fb18a9eb10d8a2e6099bab), [c4506a9](https://github.com/Dicklesworthstone/remote_compilation_helper/commit/c4506a9872b441bd02d0069e15bb72421a629f4f))

### Worker and benchmark

- Local capability probing and version mismatch detection. Benchmark queue and enhanced metrics system. Worker cache and executor improvements. ([acc840a](https://github.com/Dicklesworthstone/remote_compilation_helper/commit/acc840a559a04d93a794453959d6c371643e8b96), [6f9847a](https://github.com/Dicklesworthstone/remote_compilation_helper/commit/6f9847a4dd04125e274661066637a72351f34f87), [8879c05](https://github.com/Dicklesworthstone/remote_compilation_helper/commit/8879c0585da2b024c0b7122e069115b6d5896cc4))

### Testing

- E2E test scripts for API validation and self-healing. Telemetry test coverage for protocol and schema. Comprehensive hook pipeline tests. ([40a203c](https://github.com/Dicklesworthstone/remote_compilation_helper/commit/40a203ce410b62e0c84bc6a17dbc6c2fb125728d), [0e855cb](https://github.com/Dicklesworthstone/remote_compilation_helper/commit/0e855cb8b10343973ba025a94cec4544f88fd2da), [a61578b](https://github.com/Dicklesworthstone/remote_compilation_helper/commit/a61578b798ff718b99ea626fc1671e6a8b740d7a))

### Doctor

- Telemetry database integrity checks in doctor. ([eae104e](https://github.com/Dicklesworthstone/remote_compilation_helper/commit/eae104e96a84bd9a987c2ffe10a99f9c992d60a0))

### Installer

- Installer prompt tests, service manager detection, non-interactive mode skip, opt-in service and README quick install, systemd unit checks. ([82f53f3](https://github.com/Dicklesworthstone/remote_compilation_helper/commit/82f53f3954cf9cece6eee77150068c43f17f8d15), [de88252](https://github.com/Dicklesworthstone/remote_compilation_helper/commit/de88252e5b8490f4839eee8ba7ad00952acc4abf), [0b4c772](https://github.com/Dicklesworthstone/remote_compilation_helper/commit/0b4c7727ddecc2edb3a8534ae04d96ff5d4de5ea))

---

## [v0.1.0] -- 2026-01-25 (tag only)

First tagged version. Marks the project's initial functional milestone after 9 days of development from the initial commit (2026-01-16).

### Core architecture

- Complete Cargo workspace scaffold with five crates: `rch` (hook + CLI), `rchd` (daemon), `rch-wkr` (worker agent), `rch-common` (shared types/protocol), `rch-telemetry` (observability). ([4bfef2d](https://github.com/Dicklesworthstone/remote_compilation_helper/commit/4bfef2db4e4ab4b6c15a55eee219691bfc0da562))

### SSH execution pipeline

- SSH execution and transfer pipeline with rsync-based file synchronization between local and remote workers. ([2da910a](https://github.com/Dicklesworthstone/remote_compilation_helper/commit/2da910a1f4912a1725026f8af31c2dc0d9cec00b))

### Daemon

- Unix socket API for hook-daemon communication. Worker health monitoring with heartbeats. ([85ef478](https://github.com/Dicklesworthstone/remote_compilation_helper/commit/85ef4784ae5d7e7563dafc5f3608250caf8aff20), [0ea92b1](https://github.com/Dicklesworthstone/remote_compilation_helper/commit/0ea92b119fafd4d7d3f76f707f2c2434cf550690))

### Hook system

- PreToolUse hook integration for Claude Code. Remote transfer pipeline for compilation offloading. 5-tier classification pipeline for fast non-compilation rejection. ([8d28e81](https://github.com/Dicklesworthstone/remote_compilation_helper/commit/8d28e8185e3917acc6241539a527dc038a215225))

### Worker configuration

- Worker configuration system with TOML-based worker definitions. ([0d73015](https://github.com/Dicklesworthstone/remote_compilation_helper/commit/0d73015765a481aa15bd472d9b0dbb3699318220))

### CLI

- All CLI subcommand handlers implemented: daemon management, worker operations, status, queue, cancel, hook install/uninstall, diagnose, exec, config, doctor, self-test, update, speedscore, dashboard, completions, schema. ([26a27ac](https://github.com/Dicklesworthstone/remote_compilation_helper/commit/26a27ac2c5f31c7349b400172a30f9de716b836a))

### UI foundations

- UI output abstraction layer with adaptive color system. Structured `SelectionResponse` with graceful local fallback when no worker is available. Circuit breaker types and configuration for fault isolation. Toolchain detection, verification, and auto-installation on workers. ([38a6f80](https://github.com/Dicklesworthstone/remote_compilation_helper/commit/38a6f80ad83e006e60af53bf295a62d3c0c8c64c), [fdc871e](https://github.com/Dicklesworthstone/remote_compilation_helper/commit/fdc871e7c74467e78b82f2be5cad0c50d6ec8b00), [f7cd942](https://github.com/Dicklesworthstone/remote_compilation_helper/commit/f7cd942ac3fed09f9ad38f7f218af5e1e9a82ac9), [b010111](https://github.com/Dicklesworthstone/remote_compilation_helper/commit/b010111a82dfcc11e38bf18b96bd14e0e2fc023c))

### Security

- Security hardening for command classification. SSH command execution timeout. ([dcaf422](https://github.com/Dicklesworthstone/remote_compilation_helper/commit/dcaf422c0c7b5984f71c5bb6c2afb7a2ae08fa50), [2fdec3e](https://github.com/Dicklesworthstone/remote_compilation_helper/commit/2fdec3e543821c20de62b8ce32b8e3bffe5ae04c))

### Installation

- `install.sh` script for local setup with `--easy-mode` support. ([5893fae](https://github.com/Dicklesworthstone/remote_compilation_helper/commit/5893faea165c9d0d55e69106c14057ad80e1bfbc))

### Design constraint

- Fail-open architecture: if remote execution is not safe or possible, commands run locally with no blocking or stalling.

---

## Initial Development -- 2026-01-16

- Initial commit: project scaffold, README, and architecture design. ([294d89a](https://github.com/Dicklesworthstone/remote_compilation_helper/commit/294d89af219328d429cbb6370fb7f2b448d87300))

---

[Unreleased]: https://github.com/Dicklesworthstone/remote_compilation_helper/compare/v1.0.14...HEAD
[v1.0.14]: https://github.com/Dicklesworthstone/remote_compilation_helper/compare/v1.0.13...v1.0.14
[v1.0.13]: https://github.com/Dicklesworthstone/remote_compilation_helper/compare/v1.0.12...v1.0.13
[v1.0.12]: https://github.com/Dicklesworthstone/remote_compilation_helper/compare/v1.0.11...v1.0.12
[v1.0.11]: https://github.com/Dicklesworthstone/remote_compilation_helper/compare/v1.0.10...v1.0.11
[v1.0.10]: https://github.com/Dicklesworthstone/remote_compilation_helper/compare/v1.0.9...v1.0.10
[v1.0.9]: https://github.com/Dicklesworthstone/remote_compilation_helper/compare/v1.0.8...v1.0.9
[v1.0.8]: https://github.com/Dicklesworthstone/remote_compilation_helper/compare/v1.0.7...v1.0.8
[v1.0.7]: https://github.com/Dicklesworthstone/remote_compilation_helper/compare/v1.0.6...v1.0.7
[v1.0.6]: https://github.com/Dicklesworthstone/remote_compilation_helper/compare/v1.0.5...v1.0.6
[v1.0.5]: https://github.com/Dicklesworthstone/remote_compilation_helper/compare/v1.0.4...v1.0.5
[v1.0.4]: https://github.com/Dicklesworthstone/remote_compilation_helper/compare/v1.0.3...v1.0.4
[v1.0.3]: https://github.com/Dicklesworthstone/remote_compilation_helper/compare/v1.0.2...v1.0.3
[v1.0.2]: https://github.com/Dicklesworthstone/remote_compilation_helper/compare/v1.0.1...v1.0.2
[v1.0.1]: https://github.com/Dicklesworthstone/remote_compilation_helper/compare/v1.0.0...v1.0.1
[v1.0.0]: https://github.com/Dicklesworthstone/remote_compilation_helper/compare/v0.1.3...v1.0.0
[v0.1.64]: https://github.com/Dicklesworthstone/remote_compilation_helper/compare/v1.0.0...v0.1.64
[v0.1.3]: https://github.com/Dicklesworthstone/remote_compilation_helper/compare/v0.1.2...v0.1.3
[v0.1.2]: https://github.com/Dicklesworthstone/remote_compilation_helper/compare/v0.1.1...v0.1.2
[v0.1.1]: https://github.com/Dicklesworthstone/remote_compilation_helper/compare/v0.1.0...v0.1.1
[v0.1.0]: https://github.com/Dicklesworthstone/remote_compilation_helper/compare/294d89af219328d429cbb6370fb7f2b448d87300...v0.1.0
