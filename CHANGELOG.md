# Changelog

All notable changes to **rch** (Remote Compilation Helper) are documented here.

This changelog is organized by version, with each version grouping changes by landed capability rather than raw diff order. Tags that correspond to actual [GitHub Releases](https://github.com/Dicklesworthstone/remote_compilation_helper/releases) are marked with **(release)**; other versions are git-tag-only.

Repository: <https://github.com/Dicklesworthstone/remote_compilation_helper>

---

## [Unreleased] (since v1.0.13)

7 commits on `main` since v1.0.13, as of 2026-03-20.

### Configurable path topology

- New `[path_topology]` config section allows operators to define custom project root directories instead of hardcoded `/data/projects` and `/dp` conventions. All project-hash call sites now respect the configured policy. ([87b8bc6](https://github.com/Dicklesworthstone/remote_compilation_helper/commit/87b8bc6cdce9036b3f61877c9bffdb2b4e413eaa), [a04737f](https://github.com/Dicklesworthstone/remote_compilation_helper/commit/a04737f7a1a78c0eafe76feb0bfcf386d9dc34aa))

### Hook system expansion

- Major expansion of hook lifecycle management: additional compilation event callbacks, improved orchestration flow, and expanded compilation config types and transfer pipeline wiring. ([698422c](https://github.com/Dicklesworthstone/remote_compilation_helper/commit/698422cbe71ab0a2fcaf9720e6abe6b0ab3a532e), [a92c452](https://github.com/Dicklesworthstone/remote_compilation_helper/commit/a92c4528d730d24765d009db3e6f59f0c0987b02), [eb516a4](https://github.com/Dicklesworthstone/remote_compilation_helper/commit/eb516a4a299ce772c3f0c19b6e02a13f52c1d203), [aed2477](https://github.com/Dicklesworthstone/remote_compilation_helper/commit/aed247792bda9e83c33d8f75a5ccba8181b5635c), [e713602](https://github.com/Dicklesworthstone/remote_compilation_helper/commit/e7136026e69cfe85905dc189d87dc2bb97f3ff86))

---

## [v1.0.13] -- 2026-03-19 **(release)**

Empty bump release on top of v1.0.12 content. ([e69e0e2](https://github.com/Dicklesworthstone/remote_compilation_helper/commit/e69e0e2c921961046a787cf21013f76e772c3a98))

---

## [v1.0.12] -- 2026-03-19 **(release)**

### Worker selection improvements

- Priority-based worker selection with cache-hit and speed tiebreakers; cache tracker accuracy improvements. ([9b2106b](https://github.com/Dicklesworthstone/remote_compilation_helper/commit/9b2106be68c57b9d4064850bc341393e8954caa9))

### Remote process lifecycle

- Remote process group cleanup via PGID file, ensuring orphan processes on workers are reaped after cancellation or timeout. Cancellation and build history refinements. ([ea86c25](https://github.com/Dicklesworthstone/remote_compilation_helper/commit/ea86c2573e322c961fc4972e6f473d6710bdc4d8))

### Compilation config exposure

- Compilation slot counts (`build_slots`, `test_slots`, `check_slots`) and timeout fields (`build_timeout_sec`, `test_timeout_sec`, `bun_timeout_sec`) are now fully exposed and wired through the remote execution pipeline. ([3a65c86](https://github.com/Dicklesworthstone/remote_compilation_helper/commit/3a65c86c4c35d27aed96f5f36d315095a3bf9306))

---

## [v1.0.11] -- 2026-03-17 **(release)**

71 commits since v1.0.10. This is the largest single release, landing the full deterministic reliability platform and FrankenTUI migration.

### Deterministic multi-repo reliability platform

A complete reliability stack for multi-repo remote builds, including policy, control loops, remediation, and validation.

- **Canonical topology enforcement**: Workers are normalized around `/data/projects` and `/dp` conventions during setup. ([c1bd5cb](https://github.com/Dicklesworthstone/remote_compilation_helper/commit/c1bd5cbef5a2c402d8660a64d77c0491ab9cecb1))
- **Path-dependency closure planner**: Builds can include the full repository closure rather than a single root, with cargo metadata timeout and edge-case hardening. ([8363b75](https://github.com/Dicklesworthstone/remote_compilation_helper/commit/8363b75ed0a2c10b9876943c1b281bd09b2d97be), [286b138](https://github.com/Dicklesworthstone/remote_compilation_helper/commit/286b138c4d76c4af74815e492ea6b0983df3d925))
- **Repo convergence service**: Tracks worker drift vs required repos; periodic convergence loop with drift alerting; operator commands for status, dry-run, and repair. ([b51d1ed](https://github.com/Dicklesworthstone/remote_compilation_helper/commit/b51d1ed769c8c91a1c56128c45e9c2194016fcfd), [db0728d](https://github.com/Dicklesworthstone/remote_compilation_helper/commit/db0728d7e9bec1dadd424db75b4aef8f9ad3b73f))
- **Disk pressure resilience**: Pressure scoring, predictive disk headroom estimator, admission control in scheduler, safe reclaim with active-build protection and bounded budgets. ([660e7a4](https://github.com/Dicklesworthstone/remote_compilation_helper/commit/660e7a406973a07023786e4b85d0536c6f07a633), [fcfe4e8](https://github.com/Dicklesworthstone/remote_compilation_helper/commit/fcfe4e82f01ea66ea79561b03e67780f8b3e13ec), [320780d](https://github.com/Dicklesworthstone/remote_compilation_helper/commit/320780d0f59520dfdd9b8326e3d161eb740774a8), [6bae14b](https://github.com/Dicklesworthstone/remote_compilation_helper/commit/6bae14b6d09dbd319c02c77f5a691045938c2233), [ea3ba1a](https://github.com/Dicklesworthstone/remote_compilation_helper/commit/ea3ba1a120a24fb6c2b421d530bfb6d5d72eb791))
- **Process triage and remediation**: Bounded TERM/KILL escalation pipeline with audit trail; periodic triage loop and on-demand triage command. ([b70e4e7](https://github.com/Dicklesworthstone/remote_compilation_helper/commit/b70e4e7bc643fd1d4a78cfc1a3108a531e3ec49d), [a770153](https://github.com/Dicklesworthstone/remote_compilation_helper/commit/a770153cecdd2d1e7f86b29c853af19cca8f8c1b))
- **Unified multi-signal reliability model**: Worker health decisions use a combined signal model rather than individual thresholds. ([3c55240](https://github.com/Dicklesworthstone/remote_compilation_helper/commit/3c55240cec81e30bded7196ba7fa7cfd91293a0a))
- **Cancellation orchestration**: Deterministic state machine with bounded escalation, metadata propagation into build history, health signals surfaced in status/doctor/TUI. ([38260cd](https://github.com/Dicklesworthstone/remote_compilation_helper/commit/38260cd359789c50fe2bf528cd848f0a1b4c52d2), [1b54521](https://github.com/Dicklesworthstone/remote_compilation_helper/commit/1b54521f56a0899e9cd3d692753bfdd0688cbb3d))
- **Unified posture and remediation**: Status output now includes system posture, convergence state, pressure, and actionable remediation hints. ([ddd0bec](https://github.com/Dicklesworthstone/remote_compilation_helper/commit/ddd0becbef253ed938439381439a38c39ca04063))

### FrankenTUI migration

- TUI layer migrated from `ratatui/crossterm` to FrankenTUI native `ftui-*` stack. Updated dependencies, rendering, and test harness. ([365f607](https://github.com/Dicklesworthstone/remote_compilation_helper/commit/365f6072e16c72d487d3b1c833b8dd5d187b1d75), [e68db7d](https://github.com/Dicklesworthstone/remote_compilation_helper/commit/e68db7d27f25f389d8a6979db67dfcf99f0a57be))
- Fix for empty cells in buffer rendering and normalized frame rect origin. ([86cd921](https://github.com/Dicklesworthstone/remote_compilation_helper/commit/86cd921b41755091039ec3a1a004e061eeeacd74))

### Hook and execution pipeline

- Dynamic daemon timeout with queue-aware behavior. ([202a3d9](https://github.com/Dicklesworthstone/remote_compilation_helper/commit/202a3d9fa86001f573de32857ecb233ec39bdd9c))
- Pre/post build lifecycle callbacks added to hook system. ([d91d967](https://github.com/Dicklesworthstone/remote_compilation_helper/commit/d91d96759d9c03a3766e97c389c0c0cfdb2be9fa))
- Skip `repo_updater` pre-sync when local sync roots are dirty. ([720f980](https://github.com/Dicklesworthstone/remote_compilation_helper/commit/720f9804aa06ad0959009984955ab371e7e8233b))
- Shell-aware command tokenizer, build ID propagation for remote cancellation, async concurrency fixes. ([1b867f1](https://github.com/Dicklesworthstone/remote_compilation_helper/commit/1b867f12d88c3e9196c88c2f813781a22262064d))

### SSH and transport

- Replace `libssh-rs` `SshClient` with native `ssh` subprocess for command execution. ([9df00fa](https://github.com/Dicklesworthstone/remote_compilation_helper/commit/9df00fa68b965380a49f12c3ce6cb0d90a24fab6))
- Default `ControlMaster` off, add fallback retry, fix alias-based path topology. ([464a25b](https://github.com/Dicklesworthstone/remote_compilation_helper/commit/464a25bef50df62e8ef324b946b7585b0499ed11))
- Replace local FrankenTUI path deps with git deps for portable builds. ([ef566dd](https://github.com/Dicklesworthstone/remote_compilation_helper/commit/ef566ddc86b62e241aba0a09da73dc0d6894b6b2))

### Fixes

- Eliminate broken pipe errors from protocol deadlock. ([fdcab48](https://github.com/Dicklesworthstone/remote_compilation_helper/commit/fdcab4834114e35a508d7206b9102906a1e2ee77))
- Avoid false toolchain fallback. ([9996a37](https://github.com/Dicklesworthstone/remote_compilation_helper/commit/9996a37b8db5eb328b1926f2bc3048434ece123c))
- Probe disk space from project root instead of `/tmp`. ([4f4f01e](https://github.com/Dicklesworthstone/remote_compilation_helper/commit/4f4f01ea8bea7e6522bb108326989f9d76b58002))
- Prevent double slot release, window-based debt decay. ([08ae6e7](https://github.com/Dicklesworthstone/remote_compilation_helper/commit/08ae6e73d1318b1f434e62b2fb9b6e0a8e0e5fd8))
- Fix command classification, output truncation with SIGPIPE prevention, reduce SSH pool lock contention, improve build queue concurrency, graceful shutdown. ([78d2f9f](https://github.com/Dicklesworthstone/remote_compilation_helper/commit/78d2f9fcc96edc7577bf0626c3e2e5443ff10070))
- Sensitive value masking handles quoted strings. ([3fb98ce](https://github.com/Dicklesworthstone/remote_compilation_helper/commit/3fb98ce393a146629dcef938e12f629b833d7546))
- Move cache directory to user-isolated path, add 24h hard timeout for stuck builds, epoch-based build IDs. ([4cc9f7e](https://github.com/Dicklesworthstone/remote_compilation_helper/commit/4cc9f7e6f719a72d31f8e11abf2294893cde8738))

### Worker tooling

- `--json` and `--format` flags added to `rch-wkr benchmark` subcommand. ([a2ac6b3](https://github.com/Dicklesworthstone/remote_compilation_helper/commit/a2ac6b30acefb3963380dd71d4eef4f078be8b2e))

### Test infrastructure

- 15-file comprehensive reliability E2E test suite. ([77074ba](https://github.com/Dicklesworthstone/remote_compilation_helper/commit/77074ba7a6da582a4198b407e1572c610c8ee1a2))
- E2E suites for path deps, convergence, triage, and fault injection. ([95c8e80](https://github.com/Dicklesworthstone/remote_compilation_helper/commit/95c8e808446aa070e40ca08748f69184d7585f69))
- Schema contract E2E tests. ([7aefab2](https://github.com/Dicklesworthstone/remote_compilation_helper/commit/7aefab26551a915d8bd6861c2547e53e33b628bc))
- Criterion microbenchmarks for the reliability pipeline. ([2498cb9](https://github.com/Dicklesworthstone/remote_compilation_helper/commit/2498cb96a7cba9e2605a5d85b7a8f62ed94df93d))
- Operator runbook for reliability operations. ([261a4c7](https://github.com/Dicklesworthstone/remote_compilation_helper/commit/261a4c72ce3e4b3e82bdb24f94f9e63a16e1b5ce))

---

## [v1.0.10] -- 2026-02-14 **(release)**

Rolled up from v1.0.9 (tag-only, no release). Changes since v1.0.8.

### Daemon and test improvements

- Refactored daemon command dispatch and expanded SSH utility patterns. ([7cd10f6](https://github.com/Dicklesworthstone/remote_compilation_helper/commit/7cd10f6))
- Hardened audit E2E tests.
- Integration tests now respect `CARGO_TARGET_DIR`.

---

## [v1.0.9] -- 2026-02-14 (tag only)

Internal version bump consumed by v1.0.10 release.

---

## [v1.0.8] -- 2026-02-05 **(release)**

### Command classification fix

- Fixed `2>&1` redirect classification that was incorrectly triggering interception. ([ef5481b](https://github.com/Dicklesworthstone/remote_compilation_helper/commit/ef5481b46776a5e65807e907375adf1fb14f1807), [95b37c0](https://github.com/Dicklesworthstone/remote_compilation_helper/commit/95b37c0f21b50ab571553631b7f8843546c789cc))
- Removed flaky compound command classification tests.

---

## [v1.0.7] -- 2026-02-05 **(release)**

19 commits since v1.0.6. Major installer hardening release.

### Installer robustness

- Fixed version resolution, proxy argument passing, and asset download paths. Multiple fallback strategies: versioned asset download, API fallback, source build fallback. ([58cc779](https://github.com/Dicklesworthstone/remote_compilation_helper/commit/58cc779), [7d5ca96](https://github.com/Dicklesworthstone/remote_compilation_helper/commit/7d5ca96), [d97ac3c](https://github.com/Dicklesworthstone/remote_compilation_helper/commit/d97ac3c), [6a0c909](https://github.com/Dicklesworthstone/remote_compilation_helper/commit/6a0c909), [b088039](https://github.com/Dicklesworthstone/remote_compilation_helper/commit/b088039))
- Agent detection no longer fails the install if subcommands are missing.
- Externalized shell installer; fixed PowerShell checksum handling. ([91dee50](https://github.com/Dicklesworthstone/remote_compilation_helper/commit/91dee50))
- Auto-sync workers after easy-mode install. ([325a3c5](https://github.com/Dicklesworthstone/remote_compilation_helper/commit/325a3c5))

### Git hook infrastructure

- Comprehensive pattern-based file matching for git hooks. ([ef0f90b](https://github.com/Dicklesworthstone/remote_compilation_helper/commit/ef0f90b))

### Cross-platform

- Windows `run_exec` stub added. ([3a1d098](https://github.com/Dicklesworthstone/remote_compilation_helper/commit/3a1d098))
- Fix installer box width for Unicode characters. ([a94c362](https://github.com/Dicklesworthstone/remote_compilation_helper/commit/a94c3623bc7ade3a81ddca069f02cc09fe415480))
- Resolve tilde paths for SCP uploads and remote operations. ([c31f60c](https://github.com/Dicklesworthstone/remote_compilation_helper/commit/c31f60c), [c4a5912](https://github.com/Dicklesworthstone/remote_compilation_helper/commit/c4a5912))

---

## [v1.0.6] -- 2026-02-03 **(release)**

### CI fixes

- Exclude `rchd` from Windows release package. ([3feefb2](https://github.com/Dicklesworthstone/remote_compilation_helper/commit/3feefb2a231595bb17bd8c7956c1d50562868fcc))
- Remove unused linker env var causing ARM64 build failure.
- Fix release workflow build failures.

---

## [v1.0.5] -- 2026-02-02 (tag only)

### Hook safety

- Hook installation now safely merges into existing hook configurations instead of replacing them. ([2897b96](https://github.com/Dicklesworthstone/remote_compilation_helper/commit/2897b9674bcbde783e58bd3c451bfc8600e531c3))
- Fix restart box alignment.

---

## [v1.0.4] -- 2026-02-02 **(release)**

Version bump. No functional changes beyond v1.0.3.

---

## [v1.0.3] -- 2026-02-02 **(release)**

Version bump. No functional changes beyond v1.0.2.

---

## [v1.0.2] -- 2026-02-02 **(release)**

20 commits since v1.0.1. Focused on security hardening, hook execution, and transport reliability.

### Transparent command interception

- `AllowWithModifiedCommand` hook response enables transparent command rewriting for the Claude Code hook protocol. ([cfdb411](https://github.com/Dicklesworthstone/remote_compilation_helper/commit/cfdb4115bf327827312f649027a291360db26f4f))

### Security and SSH hardening

- `StrictHostKeyChecking=accept-new` replaces `no` for SSH connections. ([a8ed079](https://github.com/Dicklesworthstone/remote_compilation_helper/commit/a8ed079242bb4c4b0c59fa3c175ebc81074d9c74))
- SSH socket security hardened; lock handling improved. ([cb4ba31](https://github.com/Dicklesworthstone/remote_compilation_helper/commit/cb4ba31f63563642f90bb69dacf67e8407bc207a))
- Artifact verification and worker selection portability fixes. ([4ffe5b6](https://github.com/Dicklesworthstone/remote_compilation_helper/commit/4ffe5b6))

### Transport and execution reliability

- Adaptive compression based on transfer size estimation. ([0dbe0e5](https://github.com/Dicklesworthstone/remote_compilation_helper/commit/0dbe0e5))
- SSH disconnect on timeout to prevent leaked remote processes. ([4a76a2f](https://github.com/Dicklesworthstone/remote_compilation_helper/commit/4a76a2f))
- SSH pool TOCTOU race fix and optimized hook command parsing. ([dcf2059](https://github.com/Dicklesworthstone/remote_compilation_helper/commit/dcf2059))
- Queue timeout with graceful fallback to local build. ([412a875](https://github.com/Dicklesworthstone/remote_compilation_helper/commit/412a87548b59e27be4877e41869cf28b11e0fe15))

### Daemon and config

- Config load deferred in hook fast-path for lower latency. ([014ae51](https://github.com/Dicklesworthstone/remote_compilation_helper/commit/014ae51))
- Queue timeout configuration added to `DaemonContext`.
- Replaced `whoami` crate with env var lookup.
- Prominent restart reminder after hook installation. ([c56733b](https://github.com/Dicklesworthstone/remote_compilation_helper/commit/c56733b))

---

## [v1.0.1] -- 2026-02-01 **(release)**

88 commits since v1.0.0. Major stabilization and modularization release.

### Cross-platform compatibility

- SSH and Unix-only code gated behind `cfg(unix)` for Windows/macOS builds. Rich UI modules gated for Unix only. ([0b15482](https://github.com/Dicklesworthstone/remote_compilation_helper/commit/0b15482), [a37a15c](https://github.com/Dicklesworthstone/remote_compilation_helper/commit/a37a15c), [f7ce265](https://github.com/Dicklesworthstone/remote_compilation_helper/commit/f7ce265))
- Platform-specific process detection for lock files on macOS. ([adad172](https://github.com/Dicklesworthstone/remote_compilation_helper/commit/adad172))
- macOS read-only root filesystem handling for CI builds.
- CI matrix expanded and refined for Linux, macOS, and Windows.

### Daemon robustness

- Timeouts, logging improvements, and cache bounds for daemon operations. ([14d955a](https://github.com/Dicklesworthstone/remote_compilation_helper/commit/14d955a80bc1eb19e53e3279fc9504e83eaaa188))
- Body size limits added to daemon communication. ([8141d20](https://github.com/Dicklesworthstone/remote_compilation_helper/commit/8141d20523c238ebb14585490ee315995e5fff33))
- Robust drift detection in benchmark scheduler. ([c7a4e45](https://github.com/Dicklesworthstone/remote_compilation_helper/commit/c7a4e45))

### Codebase modularization

- `commands.rs` split into module directory with dedicated files for daemon, queue, config, agents, workers, speedscore commands. ([dd9b366](https://github.com/Dicklesworthstone/remote_compilation_helper/commit/dd9b366), [8591e01](https://github.com/Dicklesworthstone/remote_compilation_helper/commit/8591e01), [943fedd](https://github.com/Dicklesworthstone/remote_compilation_helper/commit/943fedd), [cd71972](https://github.com/Dicklesworthstone/remote_compilation_helper/commit/cd71972))
- Worker handler functions moved from `api.rs` to `workers.rs`. ([b579b20](https://github.com/Dicklesworthstone/remote_compilation_helper/commit/b579b20))
- `bail!()` macros replaced with structured error types throughout. ([bd36dbd](https://github.com/Dicklesworthstone/remote_compilation_helper/commit/bd36dbd), [bc077f3](https://github.com/Dicklesworthstone/remote_compilation_helper/commit/bc077f3))

### New commands

- `config doctor` and `config edit` commands. ([a08d565](https://github.com/Dicklesworthstone/remote_compilation_helper/commit/a08d565))
- `config get` command. ([5fff22f](https://github.com/Dicklesworthstone/remote_compilation_helper/commit/5fff22f))
- `-y`/`--yes` flags for non-interactive confirmation.

### Fleet operations (stub elimination)

- Real rollback with artifact/version handling and concurrent write protection. ([7717457](https://github.com/Dicklesworthstone/remote_compilation_helper/commit/77174578d9477654e1c544129f2c212fc4ef7d7e))
- Parallel fleet operations with bounded concurrency.
- `CommandRunner` trait extracted for testable backup operations.
- E2E fleet test scripts.

### Security

- Deep audit fixes for security, reliability, and performance. ([2886ce1](https://github.com/Dicklesworthstone/remote_compilation_helper/commit/2886ce1de6110ad8ad0255558767cff0d9e1cf3b))
- Strict Sigstore certificate verification for updates. ([a6ea157](https://github.com/Dicklesworthstone/remote_compilation_helper/commit/a6ea157a2c9f1ab3c22e5604d263a6fcfff2f7d3))
- Command injection prevention: reject commands with embedded newlines. ([553c064](https://github.com/Dicklesworthstone/remote_compilation_helper/commit/553c06421e497b89f2065b70726d3085c6976a5f))

---

## [v1.0.0] -- 2026-01-29 **(release)**

36 commits since v0.1.3. The 1.0 milestone.

### Performance

- In-memory cache for `TimingHistory` on the hook fast-path. ([c4ebdbb](https://github.com/Dicklesworthstone/remote_compilation_helper/commit/c4ebdbb))
- `Classification` strings switched to `Cow<'static, str>` for zero-allocation hot paths. ([30503fe](https://github.com/Dicklesworthstone/remote_compilation_helper/commit/30503fe))
- Timing estimation moved to `spawn_blocking` to avoid blocking the async runtime. ([071f3d5](https://github.com/Dicklesworthstone/remote_compilation_helper/commit/071f3d5))

### TUI enhancements

- Detail bar showing full content of selected item. ([8e399bc](https://github.com/Dicklesworthstone/remote_compilation_helper/commit/8e399bc))

### Installer improvements

- Auto-fallback to source build when prebuilt binaries are unavailable. ([c7ffb48](https://github.com/Dicklesworthstone/remote_compilation_helper/commit/c7ffb48), [76a82c8](https://github.com/Dicklesworthstone/remote_compilation_helper/commit/76a82c8))
- Consolidated duplicate `clone_and_build` functions.

### Daemon refinements

- Improved worker selection, health checks, and API robustness. ([d830790](https://github.com/Dicklesworthstone/remote_compilation_helper/commit/d830790))
- Blocking IO moved off the async thread in hook path. ([90752e5](https://github.com/Dicklesworthstone/remote_compilation_helper/commit/90752e5))

### Security

- Security, reliability, and correctness fixes from deep audit. ([fbaeaab](https://github.com/Dicklesworthstone/remote_compilation_helper/commit/fbaeaabb155414d60a9eaf21630ff2c1b6b23eca))

### Test infrastructure

- Comprehensive audit E2E integration tests.
- Zero-allocation reject path tests and cache error handling hardening.

---

## [v0.1.3] -- 2026-01-28 **(release)**

68 commits since v0.1.2. Last pre-1.0 release.

### New features

- **`rch check` command**: Quick health status verification. ([c964f66](https://github.com/Dicklesworthstone/remote_compilation_helper/commit/c964f667e62fcd66cda3dea7523bc411b5561731), [0bbf258](https://github.com/Dicklesworthstone/remote_compilation_helper/commit/0bbf2588c9f89babeacc42729019bacc95c826e5))
- **TUI sort controls**: Build history panel supports column sorting. ([5ccf11a](https://github.com/Dicklesworthstone/remote_compilation_helper/commit/5ccf11aed530833919676f68748dbe354b34dcc8))
- **Fleet progress tracking**: Real-time parallel deployment progress with `FleetProgress` struct. ([92cc5eb](https://github.com/Dicklesworthstone/remote_compilation_helper/commit/92cc5eb), [1261243](https://github.com/Dicklesworthstone/remote_compilation_helper/commit/1261243))
- **Worker drain lifecycle**: `Drained` worker status with full UI integration. ([63be3da](https://github.com/Dicklesworthstone/remote_compilation_helper/commit/63be3da), [b951c64](https://github.com/Dicklesworthstone/remote_compilation_helper/commit/b951c64))
- **TUI drain/enable controls**: Worker state management from the dashboard. ([fc94b0a](https://github.com/Dicklesworthstone/remote_compilation_helper/commit/fc94b0a85229bd316abef5125ee90f2e15dc3647))
- **Fleet-wide binary deployment**: `rch update --fleet` deploys worker binaries. ([34f5332](https://github.com/Dicklesworthstone/remote_compilation_helper/commit/34f5332787d835b6d46f67cf39836255d891b419))
- **Sigstore verification**: Release artifacts verified via Sigstore signatures. ([34f5332](https://github.com/Dicklesworthstone/remote_compilation_helper/commit/34f5332787d835b6d46f67cf39836255d891b419))

### CLI improvements

- Short flags for common options (`-a` for `--all`, etc.). Confirmation prompts for destructive daemon operations. Verbose mode with live daemon status for `workers list`. ([2894ecd](https://github.com/Dicklesworthstone/remote_compilation_helper/commit/2894ecd), [0b0b1fc](https://github.com/Dicklesworthstone/remote_compilation_helper/commit/0b0b1fc), [6ead204](https://github.com/Dicklesworthstone/remote_compilation_helper/commit/6ead204))
- Dry-run support for `cancel` command. ([2df63f2](https://github.com/Dicklesworthstone/remote_compilation_helper/commit/2df63f2))
- Parallel progress display for worker benchmarks. ([d1d5ff6](https://github.com/Dicklesworthstone/remote_compilation_helper/commit/d1d5ff6))

### Error system

- Comprehensive error code system with structured diagnostics and remediation hints. ([17d6d2b](https://github.com/Dicklesworthstone/remote_compilation_helper/commit/17d6d2b))

### Config validation

- Comprehensive validation for paths, SSH keys, and rsync patterns. ([8f074c5](https://github.com/Dicklesworthstone/remote_compilation_helper/commit/8f074c5))

### TUI

- Help overlay with drain/enable shortcuts. Emoji icons replaced with Unicode symbols for terminal compatibility. TUI unit tests (+482 lines). ([0519e9b](https://github.com/Dicklesworthstone/remote_compilation_helper/commit/0519e9bf661324ee94568c318d3d251dd3ebc0ed))

---

## [v0.1.2] -- 2026-01-27 **(release)**

82 commits since v0.1.1.

### Test coverage expansion (+2000 lines)

- Proptest fuzz testing for SSH command escaping and config parsing. ([39be0a5](https://github.com/Dicklesworthstone/remote_compilation_helper/commit/39be0a5), [cbcedbd](https://github.com/Dicklesworthstone/remote_compilation_helper/commit/cbcedbd))
- Coverage for alerts, telemetry, health checks, self-healing, icon system, storage module.
- 54 unit tests added in a single pass. ([25ee8d6](https://github.com/Dicklesworthstone/remote_compilation_helper/commit/25ee8d6))
- Test performance regression detection infrastructure.

### New features

- **Dashboard non-interactive modes** for CI/monitoring environments. ([8708a08](https://github.com/Dicklesworthstone/remote_compilation_helper/commit/8708a08))
- **Agent commands**: `agents_list` and `agents_status` for multi-agent coordination. ([23dffa4](https://github.com/Dicklesworthstone/remote_compilation_helper/commit/23dffa4))
- **Build timing history**: Intelligent offload gating based on historical build times. ([6aa1f2a](https://github.com/Dicklesworthstone/remote_compilation_helper/commit/6aa1f2aedd44e873b1933129d8379e0aae2a41f9))
- **Queued builds display**: Visible in web interface, API, and status. ([13381e7](https://github.com/Dicklesworthstone/remote_compilation_helper/commit/13381e7), [af71615](https://github.com/Dicklesworthstone/remote_compilation_helper/commit/af71615))
- **Worker health metrics** in preflight checks. ([688baeb](https://github.com/Dicklesworthstone/remote_compilation_helper/commit/688baeb))
- **Webhook dispatch**: Async HTTP client for external alert notifications. ([d16ff8a](https://github.com/Dicklesworthstone/remote_compilation_helper/commit/d16ff8a), [6159fc1](https://github.com/Dicklesworthstone/remote_compilation_helper/commit/6159fc1))
- **Worker display improvements**: Visual slot bars and speed indicators. ([023313a](https://github.com/Dicklesworthstone/remote_compilation_helper/commit/023313a))

### Improvements

- `urlencoding_encode` optimized to avoid allocations. ([4282e60](https://github.com/Dicklesworthstone/remote_compilation_helper/commit/4282e60))
- Cache cleanup scheduler reliability improved.
- Dependabot automerge workflow with failure notification.

---

## [v0.1.1] -- 2026-01-26 (tag only)

82 commits since v0.1.0. Daemon maturation and operational surface expansion.

### Daemon capabilities

- Hot-reload support for daemon configuration via SIGHUP. ([120b802](https://github.com/Dicklesworthstone/remote_compilation_helper/commit/120b802d214a68ccc71fcdc74c40ceeed5427af6), [433dbc4](https://github.com/Dicklesworthstone/remote_compilation_helper/commit/433dbc450d256f8941ccbea501019ee501bbd3cb))
- Improved health checks, history tracking, and budget metrics. ([8b4f512](https://github.com/Dicklesworthstone/remote_compilation_helper/commit/8b4f512))
- Expanded API and worker selection logic. ([f5ae9b0](https://github.com/Dicklesworthstone/remote_compilation_helper/commit/f5ae9b0))

### Worker improvements

- Worker capabilities command and API endpoint. ([c4506a9](https://github.com/Dicklesworthstone/remote_compilation_helper/commit/c4506a9))
- Improved worker cache and executor. ([8879c05](https://github.com/Dicklesworthstone/remote_compilation_helper/commit/8879c05))

### Hook and agent integration

- Hooks module for agent integration added to `rch-common`. ([059a66c](https://github.com/Dicklesworthstone/remote_compilation_helper/commit/059a66c))
- Celebration UI for successful builds integrated into hook flow. ([615bbfb](https://github.com/Dicklesworthstone/remote_compilation_helper/commit/615bbfbe42f9e92945df40acdfa8baff9e1c01d9), [5bb56f7](https://github.com/Dicklesworthstone/remote_compilation_helper/commit/5bb56f722661d9c3b7ad864d665e7be9c6361515))
- Self-update verification and type definitions. ([54cb30a](https://github.com/Dicklesworthstone/remote_compilation_helper/commit/54cb30a))

### Queue and doctor commands

- `rch queue` command and `rch doctor --dry-run` option. ([4b5fa6e](https://github.com/Dicklesworthstone/remote_compilation_helper/commit/4b5fa6e))
- Telemetry database integrity checks in doctor. ([eae104e](https://github.com/Dicklesworthstone/remote_compilation_helper/commit/eae104e))

### UI framework

- `RchTheme` with brand colors and semantic styles. ([8620e62](https://github.com/Dicklesworthstone/remote_compilation_helper/commit/8620e62cd085eebed4955879aab61a9dad8cb684))
- `RchConsole` wrapper for context-aware rich output. ([a14f195](https://github.com/Dicklesworthstone/remote_compilation_helper/commit/a14f195b068acf7ece9528a959d657d0b5cc2d1f))
- Rich display components: `StatusTable`, `WorkerTable`, `BenchmarkTable`, `ConfigDisplay`. ([123149a](https://github.com/Dicklesworthstone/remote_compilation_helper/commit/123149a5c7ff99efbfb530ee95158d8402cfa2a7), [b95c8d0](https://github.com/Dicklesworthstone/remote_compilation_helper/commit/b95c8d04b7539a74790cbc485e6698de97e6e633))
- Pipeline progress visualization. ([ef1c70f](https://github.com/Dicklesworthstone/remote_compilation_helper/commit/ef1c70ff80a57d15fdd265a08f0d116329a1ce6a))

---

## [v0.1.0] -- 2026-01-25 (tag only)

462 commits. Initial public release. Built the complete foundation from initial commit (2026-01-16) to functional remote compilation system in 9 days.

### Core architecture

- Cargo workspace with 5 crates: `rch` (hook + CLI), `rchd` (daemon), `rch-wkr` (worker agent), `rch-common` (shared protocol/types), `rch-telemetry` (observability). ([4bfef2d](https://github.com/Dicklesworthstone/remote_compilation_helper/commit/4bfef2db4e4ab4b6c15a55eee219691bfc0da562))
- SSH execution and transfer pipeline. ([2da910a](https://github.com/Dicklesworthstone/remote_compilation_helper/commit/2da910a1f4912a1725026f8af31c2dc0d9cec00b))
- Unix socket API for hook-daemon communication. ([85ef478](https://github.com/Dicklesworthstone/remote_compilation_helper/commit/85ef4784ae5d7e7563dafc5f3608250caf8aff20))
- Worker configuration system and health monitoring with heartbeats. ([0ea92b1](https://github.com/Dicklesworthstone/remote_compilation_helper/commit/0ea92b119fafd4d7d3f76f707f2c2434cf550690), [5893fae](https://github.com/Dicklesworthstone/remote_compilation_helper/commit/5893faea165c9d0d55e69106c14057ad80e1bfbc))

### Command classification

- 5-tier classification pipeline: fast reject, pattern matching, confidence scoring, timing estimation, and final decision. Supports Rust (cargo build/check/clippy/doc/test/nextest/bench), Bun (test/typecheck), C/C++ (gcc/g++/clang/clang++), and build systems (make/cmake/ninja/meson).
- Explicit non-intercept for package management, interactive, watch, piped, and redirected commands.
- `.rchignore` support for project-specific exclusions. ([1014057](https://github.com/Dicklesworthstone/remote_compilation_helper/commit/1014057))

### CLI surface

- Full subcommand set: `daemon`, `workers`, `status`, `check`, `queue`, `cancel`, `hook`, `agents`, `diagnose`, `exec`, `config`, `doctor`, `self-test`, `update`, `fleet`, `speedscore`, `dashboard`/`tui`, `web`, `schema`, `completions`.
- `--help-json` and `--capabilities` for machine-readable introspection. ([bdb54e6](https://github.com/Dicklesworthstone/remote_compilation_helper/commit/bdb54e6))
- Global flags: `-v`, `-q`, `-j`, `-F`, `--color`.

### Worker selection and scheduling

- Balanced strategy blending speed, load, health, and cache affinity.
- Cache affinity tracking and project-aware worker routing.
- SSH keepalive and ControlPersist optimization. ([b93c96e](https://github.com/Dicklesworthstone/remote_compilation_helper/commit/b93c96e47efb10edb2cdb432561972e7848b1290))

### Observability

- Prometheus metrics collection.
- OpenTelemetry tracing integration.
- SpeedScore system with telemetry-backed history.
- Web status proxy and dashboard.

### Installation and deployment

- `curl | bash` installer with easy-mode, service manager integration (systemd/launchd), and agent detection. ([0b4c772](https://github.com/Dicklesworthstone/remote_compilation_helper/commit/0b4c7727ddecc2edb3a8534ae04d96ff5d4de5ea))
- Claude Code skill and release automation workflow. ([6e26a8f](https://github.com/Dicklesworthstone/remote_compilation_helper/commit/6e26a8f0e1bc3d85808de0c2d128219d1c5843d5))
- Sigstore signing and skill bundling. ([66c2601](https://github.com/Dicklesworthstone/remote_compilation_helper/commit/66c2601c58757c881d5c4f70bd3415d87c82b61c))

### Error system

- Error catalog with codes and remediation steps. ([088a6a6](https://github.com/Dicklesworthstone/remote_compilation_helper/commit/088a6a6faecd551043aeb53a45b2d3e67b991bd1))

### Test infrastructure

- True E2E tests for cargo builds, fail-open behavior, exit code preservation, stream isolation, hook non-interference. ([bd0ef1a](https://github.com/Dicklesworthstone/remote_compilation_helper/commit/bd0ef1a6a32e78d790f942ce3033b18028153f4e), [b12f0c8](https://github.com/Dicklesworthstone/remote_compilation_helper/commit/b12f0c8406ed1a1a26b46e26fce5f406452754e0), [51e2b9d](https://github.com/Dicklesworthstone/remote_compilation_helper/commit/51e2b9d923625a39d3b4c2a5e0c3e18bc1b2ee63), [f6cdbf7](https://github.com/Dicklesworthstone/remote_compilation_helper/commit/f6cdbf797ff5a58ac2e6336376da0e9ffeb97096), [966d657](https://github.com/Dicklesworthstone/remote_compilation_helper/commit/966d657156533c98d5b4f6d48947073761202cd8))

### License

- MIT License. ([82f6808](https://github.com/Dicklesworthstone/remote_compilation_helper/commit/82f680850ed239a15cb3554b0024f95feec36f99))

---

## Version index

| Version | Date | Type | Commits |
|---------|------|------|---------|
| [Unreleased] | -- | -- | 7 |
| [v1.0.13] | 2026-03-19 | Release | 1 |
| [v1.0.12] | 2026-03-19 | Release | 3 |
| [v1.0.11] | 2026-03-17 | Release | 71 |
| [v1.0.10] | 2026-02-14 | Release | 7 |
| [v1.0.9] | 2026-02-14 | Tag only | -- |
| [v1.0.8] | 2026-02-05 | Release | 5 |
| [v1.0.7] | 2026-02-05 | Release | 19 |
| [v1.0.6] | 2026-02-03 | Release | 4 |
| [v1.0.5] | 2026-02-02 | Tag only | 2 |
| [v1.0.4] | 2026-02-02 | Release | 1 |
| [v1.0.3] | 2026-02-02 | Release | 1 |
| [v1.0.2] | 2026-02-02 | Release | 20 |
| [v1.0.1] | 2026-02-01 | Release | 88 |
| [v1.0.0] | 2026-01-29 | Release | 36 |
| [v0.1.3] | 2026-01-28 | Release | 68 |
| [v0.1.2] | 2026-01-27 | Release | 82 |
| [v0.1.1] | 2026-01-26 | Tag only | 82 |
| [v0.1.0] | 2026-01-25 | Tag only | 462 |

[Unreleased]: https://github.com/Dicklesworthstone/remote_compilation_helper/compare/v1.0.13...HEAD
[v1.0.13]: https://github.com/Dicklesworthstone/remote_compilation_helper/compare/v1.0.12...v1.0.13
[v1.0.12]: https://github.com/Dicklesworthstone/remote_compilation_helper/compare/v1.0.11...v1.0.12
[v1.0.11]: https://github.com/Dicklesworthstone/remote_compilation_helper/compare/v1.0.10...v1.0.11
[v1.0.10]: https://github.com/Dicklesworthstone/remote_compilation_helper/compare/v1.0.8...v1.0.10
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
[v0.1.3]: https://github.com/Dicklesworthstone/remote_compilation_helper/compare/v0.1.2...v0.1.3
[v0.1.2]: https://github.com/Dicklesworthstone/remote_compilation_helper/compare/v0.1.1...v0.1.2
[v0.1.1]: https://github.com/Dicklesworthstone/remote_compilation_helper/compare/v0.1.0...v0.1.1
[v0.1.0]: https://github.com/Dicklesworthstone/remote_compilation_helper/commits/v0.1.0
