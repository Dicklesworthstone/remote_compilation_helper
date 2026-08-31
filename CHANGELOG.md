# Changelog

This is a synthesized, agent-facing changelog for the full history of **rch** (Remote
Compilation Helper): the PreToolUse hook + CLI (`rch`), the local daemon (`rchd`), the
worker agent (`rch-wkr`), the RABS build sidecar (`rabs-*`, `rabsd`), and the fleet
dashboard (`dashboard/`).

Scope window: project inception (`v0.1.0`, 2026-01-25) through `v1.0.61` (2026-08-29).

This document was rebuilt from git history (`git log --no-merges` per tag range, `git show`
on representative commits), version tags (`git for-each-ref`), GitHub release metadata
(`gh release list`/`view` — a **release** is a published GitHub Release; **tag only** means
no release was ever published for the tag; one **draft** was never published), and the
checked-in issue tracker (`.beads/issues.jsonl`, queried with `jq`). Where sources
disagreed, git history won. Two tags have no successor number (`v1.0.32`, `v1.0.48` were
never cut) and one orphan tag (`rch-local-superseded-20260710`) lives only on local backup
branches.

This document is intentionally organized by landed capabilities, not raw diff order: each
version has a short narrative, the capabilities it delivered, the tracker workstreams it
closed, and the commits an agent should inspect first. Commit links go to the GitHub commit
page; workstream links go to the tracker file (search it for the id).

Sections for `v1.0.16` and earlier are inherited from the previous changelog and were
re-checked against the tag spine; nine of their commit links (in the `v1.0.16`, `v1.0.2` and
`v1.0.1` sections) point at commits that no longer exist in this repository's rewritten
history. They are kept as-is because the descriptions were verified against the tag ranges,
but those particular links will 404.

Repository: <https://github.com/Dicklesworthstone/remote_compilation_helper>

## Version Timeline

`Kind` distinguishes a published GitHub Release from a plain git tag. Dates are tag dates.

| Version | Kind | Date | Summary |
|---------|------|------|---------|
| [`v1.0.62`](https://github.com/Dicklesworthstone/remote_compilation_helper/releases/tag/v1.0.62) | Release | 2026-08-29 | Convergence over the tailnet API: `GET /repo-convergence/status` token-gated on `:9101`; the dashboard collector folds it in so `worker.convergence_drift` fires on API-collected boxes |
| [`v1.0.61`](https://github.com/Dicklesworthstone/remote_compilation_helper/releases/tag/v1.0.61) | Release | 2026-08-29 | rchd tailnet status API (`[api]`); dashboard publishes 2-min snapshots to Vercel Blob over that API; problems/diagnose agent views; `web/` retired |
| [`v1.0.60`](https://github.com/Dicklesworthstone/remote_compilation_helper/releases/tag/v1.0.60) | Release | 2026-08-28 | Shim v3: every local shim fallback capped via `CARGO_BUILD_JOBS`; Windows CIM telemetry; socket reload honours `--workers-config` |
| [`v1.0.59`](https://github.com/Dicklesworthstone/remote_compilation_helper/releases/tag/v1.0.59) | Release | 2026-08-27 | Shim v2: `--message-format` no longer forces local; `cargo-clippy` shimmed; `RUSTC_WORKSPACE_WRAPPER` guard |
| [`v1.0.58`](https://github.com/Dicklesworthstone/remote_compilation_helper/tree/v1.0.58) | Tag | 2026-08-26 | RABS lands in full; job mode (`rch exec --job`); `remote_build_jobs` cap (#49) — no GitHub Release |
| [`v1.0.57`](https://github.com/Dicklesworthstone/remote_compilation_helper/releases/tag/v1.0.57) | Release | 2026-08-15 | 547 commits: RABS born (10 crates, 513-bead plan) and hits a live shadow-mode spine; fleet role policy, durable disables, SIGILL quarantine, macOS telemetry (#39–#43) |
| [`v1.0.56`](https://github.com/Dicklesworthstone/remote_compilation_helper/releases/tag/v1.0.56) | Release | 2026-08-05 | Configurable canonical project root (GH #38) and related fixes |
| [`v1.0.55`](https://github.com/Dicklesworthstone/remote_compilation_helper/tree/v1.0.55) | Tag | 2026-08-02 | Concurrent stderr drain fixes a latent Windows-transfer deadlock; Windows-worker docs genericized |
| [`v1.0.54`](https://github.com/Dicklesworthstone/remote_compilation_helper/tree/v1.0.54) | Tag | 2026-08-02 | First Windows worker platform: tar-over-ssh transport, `C:/rch`, `declared_os` wire field |
| [`v1.0.53`](https://github.com/Dicklesworthstone/remote_compilation_helper/releases/tag/v1.0.53) | Release | 2026-08-02 | Host-OS worker admission gate (`os` in workers.toml); local fix branch reconciled; refusal legibility (#30–#35); component-level capability probing |
| [`v1.0.52`](https://github.com/Dicklesworthstone/remote_compilation_helper/releases/tag/v1.0.52) | Release | 2026-07-23 | `rch shim install\|status\|uninstall` — the canonical cargo offload wrapper |
| [`v1.0.51`](https://github.com/Dicklesworthstone/remote_compilation_helper/releases/tag/v1.0.51) | Release | 2026-07-22 | Bypass↔telemetry stranding deadlock that silently dropped the whole fleet |
| [`v1.0.50`](https://github.com/Dicklesworthstone/remote_compilation_helper/tree/v1.0.50) | Draft | 2026-07-17 | Fail-closed clean-overlay remote proofs for shared working trees — release drafted, never published |
| [`v1.0.49`](https://github.com/Dicklesworthstone/remote_compilation_helper/releases/tag/v1.0.49) | Release | 2026-07-15 | Go/TypeScript/Nix build offload (#26, #29); `RCH-E415` fail-closed cargo path-dep materialization |
| [`v1.0.47`](https://github.com/Dicklesworthstone/remote_compilation_helper/releases/tag/v1.0.47) | Release | 2026-07-02 | Shared `SshPool` + unified circuit breaker end false worker DOWN flaps; artifacts default to `/data/tmp/rch` |
| [`v1.0.46`](https://github.com/Dicklesworthstone/remote_compilation_helper/releases/tag/v1.0.46) | Release | 2026-06-25 | Release-asset-completeness CI gate made installability-based; cosign-tolerance fix validated |
| [`v1.0.45`](https://github.com/Dicklesworthstone/remote_compilation_helper/releases/tag/v1.0.45) | Release | 2026-06-25 | Session-history-remediation program closes (epics 7/10/16); piped/backgrounded cargo offloads (#24); hook.rs de-monolithized |
| [`v1.0.44`](https://github.com/Dicklesworthstone/remote_compilation_helper/releases/tag/v1.0.44) | Release | 2026-06-24 | Local fleet hotfix: cosign-tolerant self-update for the cosign-less worker fleet |
| [`v1.0.43`](https://github.com/Dicklesworthstone/remote_compilation_helper/releases/tag/v1.0.43) | Release | 2026-06-19 | Per-project `preferred_workers` routing via `.rch/config.toml` |
| [`v1.0.42`](https://github.com/Dicklesworthstone/remote_compilation_helper/releases/tag/v1.0.42) | Release | 2026-06-18 | 190 commits: remediation program launches (bypass/socket recovery, placement controls, redaction); circuit window + priority (#21); target-dir reuse (#19) |
| [`v1.0.41`](https://github.com/Dicklesworthstone/remote_compilation_helper/releases/tag/v1.0.41) | Release | 2026-06-08 | Autonomous worker-side stale-target reaper (default off) |
| [`v1.0.40`](https://github.com/Dicklesworthstone/remote_compilation_helper/releases/tag/v1.0.40) | Release | 2026-06-08 | `rch exec` reaps the whole test process group at the runtime cap |
| [`v1.0.39`](https://github.com/Dicklesworthstone/remote_compilation_helper/releases/tag/v1.0.39) | Release | 2026-06-08 | Stale-target reaper works when the canonical root is a symlink |
| [`v1.0.38`](https://github.com/Dicklesworthstone/remote_compilation_helper/releases/tag/v1.0.38) | Release | 2026-06-08 | Stale-target reaper sweeps every project under the canonical root |
| [`v1.0.37`](https://github.com/Dicklesworthstone/remote_compilation_helper/releases/tag/v1.0.37) | Release | 2026-06-02 | rchd single-instance enforcement via systemd cgroup detection |
| [`v1.0.36`](https://github.com/Dicklesworthstone/remote_compilation_helper/releases/tag/v1.0.36) | Release | 2026-06-02 | Finite SSH `ControlPersist` stops control-master leaks |
| [`v1.0.35`](https://github.com/Dicklesworthstone/remote_compilation_helper/releases/tag/v1.0.35) | Release | 2026-05-30 | Stale-target reaper no longer reaps a just-created sibling |
| [`v1.0.34`](https://github.com/Dicklesworthstone/remote_compilation_helper/releases/tag/v1.0.34) | Release | 2026-05-30 | Reap abandoned per-job remote target directories (worker disk hygiene) |
| [`v1.0.33`](https://github.com/Dicklesworthstone/remote_compilation_helper/releases/tag/v1.0.33) | Release | 2026-05-29 | Kills the systemd restart storm + log flood; unblocks a release pipeline broken since v1.0.29 |
| [`v1.0.31`](https://github.com/Dicklesworthstone/remote_compilation_helper/releases/tag/v1.0.31) | Release | 2026-05-26 | Telemetry re-poll cadence tuned (`skip_after` 60→30 s) to close the last freshness flap |
| [`v1.0.30`](https://github.com/Dicklesworthstone/remote_compilation_helper/releases/tag/v1.0.30) | Release | 2026-05-26 | Telemetry poller retry + timeout + INFO summary; 8/8 workers, 0 failures |
| [`v1.0.29`](https://github.com/Dicklesworthstone/remote_compilation_helper/releases/tag/v1.0.29) | Release | 2026-05-26 | Fixes permit starvation from v1.0.28's semaphore that collapsed telemetry to 1/9 workers |
| [`v1.0.28`](https://github.com/Dicklesworthstone/remote_compilation_helper/releases/tag/v1.0.28) | Release | 2026-05-26 | Telemetry poller drops its long-held config lock; bounded concurrent SSH polls |
| [`v1.0.27`](https://github.com/Dicklesworthstone/remote_compilation_helper/releases/tag/v1.0.27) | Release | 2026-05-25 | 57 commits: worker-topology aliasing, reliability pipeline, `RCH_*_INJECT_*` registry, `doctor --runbook`, `workers benchmark/compare` |
| [`v1.0.26`](https://github.com/Dicklesworthstone/remote_compilation_helper/releases/tag/v1.0.26) | Release | 2026-05-14 | `upgrade` alias for the release helper |
| [`v1.0.25`](https://github.com/Dicklesworthstone/remote_compilation_helper/releases/tag/v1.0.25) | Release | 2026-05-14 | Dependency and release maintenance (FrankenTUI/rich_rust/TOON from current checkouts) |
| [`v1.0.24`](https://github.com/Dicklesworthstone/remote_compilation_helper/releases/tag/v1.0.24) | Release | 2026-04-29 | `rch fleet deploy` prefers the installed `rch-wkr` over stale dev-target builds |
| [`v1.0.23`](https://github.com/Dicklesworthstone/remote_compilation_helper/releases/tag/v1.0.23) | Release | 2026-04-29 | Atomic replace everywhere: doctor survives broken pipes; fleet SCP and install.sh stage-then-rename |
| [`v1.0.22`](https://github.com/Dicklesworthstone/remote_compilation_helper/releases/tag/v1.0.22) | Release | 2026-04-29 | Daemon socket requests get connect/IO timeouts + half-close; release CI concurrency per-tag |
| [`v1.0.21`](https://github.com/Dicklesworthstone/remote_compilation_helper/releases/tag/v1.0.21) | Release | 2026-04-29 | Streaming artifact retrieval regains rsync `--safe-links` |
| [`v1.0.20`](https://github.com/Dicklesworthstone/remote_compilation_helper/releases/tag/v1.0.20) | Release | 2026-04-29 | `CARGO_TARGET_DIR` round-trips through remote exec; `[path_topology]` TOML/CLI wiring (#10); installer survives `/tmp/rch` collisions |
| [`v1.0.19`](https://github.com/Dicklesworthstone/remote_compilation_helper/releases/tag/v1.0.19) | Release | 2026-04-23 | 40-commit audit sweep: fleet lock, alert lifecycle, config diagnostics, self-test timeout, probe error codes, ~25 concurrency/safety fixes |
| [`v1.0.18`](https://github.com/Dicklesworthstone/remote_compilation_helper/tree/v1.0.18) | Tag | 2026-04-16 | Diagnose + path-topology bug fixes |
| [`v1.0.17`](https://github.com/Dicklesworthstone/remote_compilation_helper/releases/tag/v1.0.17) | Release | 2026-04-01 | Maintenance |
| [`v1.0.16`](https://github.com/Dicklesworthstone/remote_compilation_helper/releases/tag/v1.0.16) | Release | 2026-03-24 | Worker scheduling safety; configurable path topology; hook system expansion |
| [`v1.0.15`](https://github.com/Dicklesworthstone/remote_compilation_helper/tree/v1.0.15) | Tag | 2026-03-24 | Version bump |
| [`v1.0.14`](https://github.com/Dicklesworthstone/remote_compilation_helper/tree/v1.0.14) | Tag | 2026-03-24 | Pre-v1.0.16 maintenance |
| [`v1.0.13`](https://github.com/Dicklesworthstone/remote_compilation_helper/releases/tag/v1.0.13) | Release | 2026-03-18 | Release bump |
| [`v1.0.12`](https://github.com/Dicklesworthstone/remote_compilation_helper/releases/tag/v1.0.12) | Release | 2026-03-18 | Worker selection/scheduling, remote process lifecycle, compilation config |
| [`v1.0.11`](https://github.com/Dicklesworthstone/remote_compilation_helper/releases/tag/v1.0.11) | Release | 2026-03-17 | 99 commits: reliability subsystem (bd-vvmd), unified status/posture, FrankenTUI migration, classification + shell safety |
| [`v1.0.10`](https://github.com/Dicklesworthstone/remote_compilation_helper/releases/tag/v1.0.10) | Release | 2026-02-14 | Daemon and test hardening |
| [`v1.0.9`](https://github.com/Dicklesworthstone/remote_compilation_helper/tree/v1.0.9) | Tag | 2026-02-14 | Version bump |
| [`v1.0.8`](https://github.com/Dicklesworthstone/remote_compilation_helper/releases/tag/v1.0.8) | Release | 2026-02-05 | Command classification fix |
| [`v1.0.7`](https://github.com/Dicklesworthstone/remote_compilation_helper/releases/tag/v1.0.7) | Release | 2026-02-04 | Installer robustness overhaul; fleet/worker deployment; SSH path handling |
| [`v1.0.6`](https://github.com/Dicklesworthstone/remote_compilation_helper/releases/tag/v1.0.6) | Release | 2026-02-02 | CI and release workflow fixes |
| [`v1.0.5`](https://github.com/Dicklesworthstone/remote_compilation_helper/tree/v1.0.5) | Tag | 2026-02-02 | Hook safety: safe-merge hook installation |
| [`v1.0.4`](https://github.com/Dicklesworthstone/remote_compilation_helper/releases/tag/v1.0.4) | Release | 2026-02-02 | Version bump |
| [`v1.0.3`](https://github.com/Dicklesworthstone/remote_compilation_helper/releases/tag/v1.0.3) | Release | 2026-02-02 | Version bump |
| [`v1.0.2`](https://github.com/Dicklesworthstone/remote_compilation_helper/releases/tag/v1.0.2) | Release | 2026-02-02 | Transparent command interception; adaptive transfer compression; hook performance |
| [`v1.0.1`](https://github.com/Dicklesworthstone/remote_compilation_helper/releases/tag/v1.0.1) | Release | 2026-02-01 | Daemon robustness; cross-platform compatibility; refactoring |
| [`v1.0.0`](https://github.com/Dicklesworthstone/remote_compilation_helper/releases/tag/v1.0.0) | Release | 2026-01-29 | 1.0: fleet management, installer resilience, CLI modularization, update system |
| [`v0.1.64`](https://github.com/Dicklesworthstone/remote_compilation_helper/tree/v0.1.64) | Tag | 2026-02-01 | Pre-1.0 tag on the same history as v1.0.1 |
| [`v0.1.3`](https://github.com/Dicklesworthstone/remote_compilation_helper/releases/tag/v0.1.3) | Release | 2026-01-28 | TUI enhancements & fleet deployment |
| [`v0.1.2`](https://github.com/Dicklesworthstone/remote_compilation_helper/releases/tag/v0.1.2) | Release | 2026-01-27 | Test coverage & stability improvements |
| [`v0.1.1`](https://github.com/Dicklesworthstone/remote_compilation_helper/tree/v0.1.1) | Tag | 2026-01-26 | Daemon health monitoring, hot reload, selection logic, `/status` API |
| [`v0.1.0`](https://github.com/Dicklesworthstone/remote_compilation_helper/tree/v0.1.0) | Tag | 2026-01-25 | Workspace scaffold: `rch`, `rchd`, `rch-wkr`, `rch-common`, `rch-telemetry` |

---

## [Unreleased]


### Shim v4: `RCH_SHIM_LOCAL_IDE=1` resolves a WORKING real cargo (tiered), fixing nightly-renamed-cargo hosts

The documented local-build escape hatch was dead exactly when it was needed. On a
host whose active toolchain cargo was renamed to `cargo-rch-real` (rch toolchain
wrapping, or a rustup update over it), the rustup proxy at `~/.cargo/bin/cargo`
cannot dispatch — rustup answers `the 'cargo' binary, normally provided by the
'cargo' component, is not applicable to the '<toolchain>' toolchain` — and the
shim's local fallback hardcoded exactly that proxy. So when remote offload
failed and the operator asked for a local build (`RCH_SHIM_LOCAL_IDE=1 cargo
build --release -p rch`), the escape hatch itself died (2026-08-30 fleet rollout
of `943b8e29` on a nightly-default dispatcher; the working manual workaround was
`RCH_CARGO_WRAPPER_BYPASS=1 ~/.rustup/toolchains/<tc>/bin/cargo-rch-real` with
the toolchain bin prepended to PATH — which is precisely what the shim now does
by itself). Bead
[`bd-73gdn`](https://github.com/Dicklesworthstone/remote_compilation_helper/blob/main/.beads/issues.jsonl):
- **Tiered real-cargo resolution** in every local path of the cargo shim
  (`RCH_SHIM_LOCAL_IDE=1`, wrapper bypass, IDE diagnostics, the catch-all arm),
  first executable wins: `$RCH_REAL_CARGO` (new explicit operator override) →
  `$RCH_SHIM_REAL_CARGO` (the toolchain-wrapper handoff, preserving toolchain
  identity) → `<active-toolchain>/bin/cargo-rch-real` where the active toolchain
  is discovered via `rustc --print sysroot` (honors `RUSTUP_TOOLCHAIN` and
  `rust-toolchain.toml`, i.e. the toolchain the build would actually use) → the
  stock `~/.cargo/bin/cargo` proxy, correct wherever nothing was renamed.
- **Toolchain-bin PATH prepend**: when the resolved real cargo is a renamed
  `cargo-rch-real`, its directory is prepended to `PATH` so the build's rustc /
  clippy-driver resolve from the SAME toolchain — a repo `.cargo/config.toml`
  with `-Z` flags (e.g. `-Z threads=4`) needs nightly rustc even when the rustup
  default is stable. The rch toolchain wrapper's own local fallback gets the same
  prepend (wrap version 3).
- **Loud failure with a named fix**: when every tier comes up empty the shim now
  exits 127 listing what it tried and naming `RCH_REAL_CARGO` and
  `rch shim uninstall` as the remedies, instead of exec'ing a proxy that errors.
- **Agent-facing docs**: the tier order is now printed by `rch shim install`,
  carried in `rch shim --help`, and embedded as a comment block in the generated
  shim itself, so an agent hitting a broken local fallback can debug it in place.
- Everything else is preserved verbatim: offload routing, the fail-open /
  loop-break contract, the local `CARGO_BUILD_JOBS` cap, rust-analyzer handling.
  Hosts where nothing was renamed resolve tier 4 exactly as v3 did.

### Windows workers: pooled SSH never uses ControlMaster (wsurf permanently "unreachable")

The daemon's SSH pools (shared build/telemetry pool AND the dedicated health
pool) forced ControlMaster multiplexing for every worker — but Windows
OpenSSH has no ControlMaster support. On the Windows worker (`os = "windows"`)
a pooled session appears to connect and then every command over it hangs and
dies at the command stage, so each pooled health probe failed
deterministically with `Failed to wait for command completion` and the daemon
marked the worker permanently unreachable — while fresh one-shot SSH to the
same host worked fine (`rch workers probe` healthy, `rch check` degraded
15/16; 2026-08-30 incident on worker `wsurf`). Linux workers only ever hit
the same signature transiently and recovered via retries/circuit. Bead
[`bd-wgbx9`](https://github.com/Dicklesworthstone/remote_compilation_helper/blob/main/.beads/issues.jsonl):

- **Pool-layer override** in `rch_common::SshPool`: a single helper
  (`pooled_client_options`) derives each pooled client's options and forces
  `control_master = false` whenever the worker's declared OS is `windows`
  (the reserved `os:windows` tag from `os = "windows"` in `workers.toml`,
  case-normalized). Both per-worker client construction sites in
  `get_or_create_client_entry` route through it, so every pool consumer
  (health, telemetry, cache cleanup, reclaim, stale-target reap, toolchain
  preflight) is fixed at once. `SshClient::connect`'s existing
  ControlMaster-failure retry could not catch this class — the mux connect
  succeeds; the commands hang.
- **`control_persist_idle` is NOT separately neutralized**: it is consulted
  only when `control_master` is true (`control_persist_mode`), so it is inert
  once mux is off and is left verbatim. Non-Windows workers keep the pool's
  options verbatim in full — warm-master reuse for the rest of the fleet is
  unchanged.
- Unit tests cover windows/linux × pool-mux/pool-non-mux at both the helper
  and the pool-entry layer (plus `os = "Windows"` case normalization).

### Windows workers: command execution dispatches to the system `ssh` binary

The Windows ControlMaster fix above stopped pooled Windows clients from
spending a warm master on a slave that never replies, but the underlying
command-execute path was still broken: the `openssh` crate 0.11.6 cannot
execute commands on Windows OpenSSH at all. The connect step uses a
different channel and works; the execute step does not — the slave never
completes the command channel, so every command hangs at the
`Failed to wait for command completion` boundary regardless of mux,
keepalive, or persist settings (2026-08-30 fleet diagnostic, 6/6 option
combinations all 12-second timeouts; see
`/Users/jemanuel/projects/wsurf-openssh-diag/FINDINGS.md`). The pool-side
override (`bd-wgbx9`) is correct but the daemon never gets there for
Windows workers — `Failed to wait for command completion` fires first.
The worker `wsurf` (the only Windows box) has been permanently marked
unreachable ever since, hidden by the persistent bypass state. Bead
[`bd-nfusx`](https://github.com/Dicklesworthstone/remote_compilation_helper/blob/main/.beads/issues.jsonl):

- **System-ssh fallback at execute time** in `rch_common::ssh`: three
  helpers (`prefers_system_ssh`, `system_ssh_argv`, `system_ssh_execute`)
  plus a dispatch at the top of `SshClient::execute_with_timeout`. When
  `declared_os(&config.tags) == Some("windows")`, the dispatch spawns the
  system `ssh` binary directly via `tokio::process::Command` with
  `BatchMode=yes`, `ConnectTimeout=8`, `StrictHostKeyChecking=accept-new`,
  `-i <identity_file>`, the configured `ServerAliveInterval` (omitted at
  `0`), and `kill_on_drop(true)` so a timeout cannot leak an ssh child.
  Output is read concurrently off stdout / stderr with the same
  `MAX_OUTPUT_SIZE` cap the openssh-crate path enforces, and the result
  is a `CommandResult` with the same shape callers already consume.
  Linux / unlabelled workers keep the openssh-crate path verbatim —
  the dispatch key is identical to the one `pooled_client_options` uses,
  so the two Windows fallbacks cannot diverge on which workers they
  apply to.
- **Argv builder** is pure and testable. Identity file is tilde-expanded
  via `shellexpand::tilde` (the same call site as the openssh crate
  path), `WorkerConfig` has no port field so the argv has no `-p` flag
  (non-default ports travel as `host:port`), and the destination is
  `user@host`. The argv is `ssh -i <key> -o BatchMode=yes -o
  ConnectTimeout=8 -o StrictHostKeyChecking=accept-new [-o
  ServerAliveInterval=N] user@host command` — the same proven
  fleet-preflight arg set used by `rch/src/fleet/ssh.rs::SshExecutor`.
- **Unit tests** cover the dispatch key for `os:windows`, `os:Windows`
  (case normalization), `os:linux`, and an unlabelled worker; the argv
  builder for default keepalive, zero keepalive (omitted flag), long
  keepalive preserved verbatim, and tilde-expanded identity file; and a
  lockstep check that the dispatch key matches `pooled_client_options`.
- **Persistent bypass state is doing its job** (avoiding wasted probes
  on a known-bad worker) but will hide this fix until reset. After
  rolling out the new build, run `rch status --json | jq '.bypass'` and
  clear the wsurf bypass entry so the daemon re-evaluates against the
  new execute path.

### Custom cargo profiles sync their outputs; silent zero-output sync-backs fail loudly

Remote builds that write to a CUSTOM cargo profile directory (`cargo build --profile
release-perf` → `target/release-perf/`) reported success while syncing back only the
loose target-root metadata files (`.rustc_info.json`, `CACHEDIR.TAG`) — the actual
binary stayed on the worker and the LOCAL artifact silently remained the previous
build's. Observed across a 30-pass optimization session on franken_markdown
(`--profile release-perf --example fmd_perf_harness`: "4 files, 660 bytes" retrieved,
stale binary benchmarked unknowingly; every session had to md5-verify freshness or
fall back to `RCH_SHIM_LOCAL_IDE=1`). Two layers fix it (bead
[`bd-mpbav`](https://github.com/Dicklesworthstone/remote_compilation_helper/blob/main/.beads/issues.jsonl)):

- **Profile-aware artifact patterns.** `--profile <name>` is extracted from the cargo
  command during pattern selection; custom profile names (whose output dir is
  `target/<name>/`, unlike `dev`/`test`→`debug` and `release`/`bench`→`release`)
  now add `target/<name>/**` plus the `--target <triple>` form
  `target/*/<name>/**` to the default-root sync, and the rebased
  `<name>/**` / `*/<name>/**` includes plus plain and triple-nested cache excludes
  to the custom-`CARGO_TARGET_DIR` sync.
- **Zero-build-output detection (RCH-E326).** Artifact retrievals now itemize every
  matched regular file (`--info=name2 --out-format='%i %n'`, transferred AND
  verified-up-to-date). For kinds with an enumerable output contract
  (`cargo build`/`doc`/`zigbuild`), a sync-back that succeeded yet matched zero
  build outputs — every matched file loose metadata or cache state — fails the
  build with `RCH-E326` (exit 102) naming the stale-local-artifact hazard and the
  expected output dirs, instead of surfacing the remote's exit 0. Up-to-date
  no-op rebuilds are recognized (their outputs appear as verified-current
  manifest entries) and never fire; evidence-incomplete manifests (older worker
  rsyncs, mock/Windows transports) fail open.

## [v1.0.62] -- 2026-08-29 (release)

The one route the tailnet API was still missing. `rch status --json` folds repo-convergence
into its output, but a dashboard collector asking over HTTP got `/status` without it — so
API-collected machines could never raise `worker.convergence_drift`, and a worker quietly
missing repos looked healthy from the fleet view (bead
[`bd-ngln7`](https://github.com/Dicklesworthstone/remote_compilation_helper/blob/main/.beads/issues.jsonl)).

**Delivered capability**

- `GET /repo-convergence/status[?worker=<id>]` on the rchd tailnet API (`[api]` listener,
  `:9101`), token-gated like `/status`, serving the exact body the Unix socket serves.
- The dashboard collector (`dashboard/tools/snapshot.mjs`) issues it as a fifth GET and folds
  the answer into the synthesized status section, so `worker.convergence_drift` problem rows
  fire identically on API-collected and ssh-collected machines. An rchd too old to serve the
  route (404) leaves the convergence column UNKNOWN with a named `repo-convergence: HTTP 404`
  collection error — never a silent "no drift".

**Closed workstreams**

- [`bd-ngln7`](https://github.com/Dicklesworthstone/remote_compilation_helper/blob/main/.beads/issues.jsonl)
  — serve `/repo-convergence/status` on the rchd tailnet API.

**Representative commits**

- [`af2e77a9`](https://github.com/Dicklesworthstone/remote_compilation_helper/commit/af2e77a963a170374058a5df47599075da3fa496)
  — the route, its token gate, and the router tests.
- [`2418b69d`](https://github.com/Dicklesworthstone/remote_compilation_helper/commit/2418b69dd1317fd9e9239d81440f2584e01d6a45)
  — the collector's fifth GET with the 404-means-unknown fallback and tests.
- [`5c2ac121`](https://github.com/Dicklesworthstone/remote_compilation_helper/commit/5c2ac1210649bae27fcf8b286554487fa2a9372e)
  — compile fix and route documentation.

## [v1.0.61] -- 2026-08-29 (release)

### Tailnet status API, 2-minute fleet snapshots, `web/` retired

Three changes that turn the fleet dashboard from a 20-minute-old picture into a
live one and let agents on any tailnet machine ask a dispatcher what is wrong
right now.

- **`rchd` tailnet status API** (`[api]` in `config.toml`, bd-2f5ms). The daemon's
  full `/status` JSON — the same body the `0600` Unix socket serves — plus
  `/workers/capabilities` and a new `/workers/config` (static tags/priority/slots)
  over TCP, bearer-token gated (`Authorization: Bearer` or `X-Rch-Token`,
  constant-time compare). `bind = "tailscale"` resolves the machine's Tailscale
  IPv4 at startup (port 9101); the bind address must be loopback or inside
  Tailscale's ranges (`100.64.0.0/10`, `fd7a:115c:a1e0::/48`) unless
  `allow_any_addr = true`, and the daemon refuses to start the API without a token
  unless `no_token = true` is explicit. `/health`, `/ready`, `/metrics`, `/budget`
  stay open on that listener too. A bad `[api]` section is logged with its fix and
  the daemon runs on without the API. CLI: `rchd --api-bind`, `--api-token-file`;
  `rch config set|get|show` know `api.*` (the token value is never echoed).
- **Collector over the API** (`dashboard/tools/snapshot.mjs`, bd-04ifk). A
  dispatcher written `name=100.x.y.z:9101` is asked over HTTP (four GETs, ~1 s for
  the whole fleet) instead of ssh; posture is derived by the CLI's exact rule and
  hints come from the daemon's `issues[]`. The dev-machine-local self-checks
  (`rch doctor`, `shim status`, `hook status`) still go over ssh, but only every 15
  minutes, cached. An API that does not answer falls back to the full ssh probe
  for that machine and says so. Dev-machine rows carry `via: api|ssh`.
- **Publish without a deploy.** `dashboard/scripts/publish-snapshot.sh` collects and
  uploads only the ciphertext to a Vercel Blob store every 120 s
  (`packaging/launchd/com.local.rch-dashboard-publish.plist`); the app and
  `/api/fleet` fetch it at runtime (`RCH_DASH_DATA_URL` / `VITE_RCH_DASH_DATA_URL`)
  and fall back to the deploy-time copy **saying so** (banner;
  `X-Rch-Snapshot-Source` header). `deploy-vercel.sh` now only ships code, hourly.
  The `/api/fleet` KDF cache no longer binds the ciphertext IV, so it survives the
  snapshot rotating under the same salt. Measured: fleet change → visible in ≤3 min
  (was 20–40).
- **`web/` retired** (bd-oxdl1). `rch web` no longer spawns a Next.js dev server
  nobody's installed `rch` could find; it opens `[dashboard] url` (or `--url`,
  `RCH_DASHBOARD_URL`) and prints the agent endpoint. `RCH-E900/E901` now mean "no
  dashboard URL configured" / "not an http(s) URL". Dependabot watches
  `/dashboard` instead of `/web`; the remediation e2e checks the dashboard's
  problems module. The `web/` directory is removed from the tree.

### Fleet dashboard: problems with actions, agent diagnose views, dev-machine self-checks

The `dashboard/` fleet console (Vite/React, encrypted static snapshot, deployed to
Vercel; first landed 2026-08-26 in [`6865d09`](https://github.com/Dicklesworthstone/remote_compilation_helper/commit/6865d09)…[`e8ec3a7`](https://github.com/Dicklesworthstone/remote_compilation_helper/commit/e8ec3a7) without a changelog entry)
now leverages what the daemon already knew and collects three things it did not:

- **Collector** (`dashboard/tools/snapshot.mjs`): three new probe sections on the same
  single ssh connection — `rch doctor --json`, `rch shim status --json`,
  `rch hook status --json` — so a dev machine with **no Claude Code hook**, a stale or
  shadowed cargo shim, or **compiler processes running outside rch right now** is a
  named problem instead of a grey "idle" card. `daemon.alerts[]` and `daemon.issues[]`
  are kept again (they had been dropped as unread), along with active builds **with the
  daemon's stall detectors**, queued builds, repo convergence, test counters, and
  per-worker pressure confidence / policy rule / circuit recovery / bypass code.
  Remediation hints are capped worst-first, not daemon-order-first. An unreachable
  machine's detail is the ssh/rch error line, not the 2 KB probe script.
- **Problems** (`dashboard/src/problems.js`): one module derives the problem list for the
  page and for `/api/fleet`, so they cannot disagree. Every row carries `action` (the
  command), `on` (where to run it) and `since` (from the daemon's alert lifecycle);
  `next_actions[]` folds them into distinct commands per machine. N identical
  "dev machine degraded" rows caused by the same sick workers collapse into one
  `fleet.degraded` row naming the workers. New kinds: `dev.hook_missing`,
  `dev.unmanaged_local_builds`, `dev.shim_missing/stale`, `dev.doctor_failed/warnings`,
  `dev.daemon_version_skew`, `dev.collection_error`, `worker.convergence_drift`,
  `build.hook_dead`, `build.stalled`.
- **Agent endpoint** (`GET /api/fleet`, `npm run llm`): schema `rch.fleet.llm.v2`;
  `view=problems` (cheapest poll), `view=diagnose&target=<machine|worker>` (everything
  about one entity, incl. its per-dev-machine derated slot readings and what every other
  box says about it), `view=help` (the contract and problem-kind catalogue, no key
  needed), `target=` filtering on every view, `404` listing the known ids, `400`s that
  point at `?view=help`. Dev-machine rows now say `offload_pct`+`basis`, `hook`, `shim`,
  `doctor`, `local_now`; the summary carries `verdict`, `hooks_missing`,
  `local_builds_running`, `daemon_version`, `version_skew`.
- **Page**: a Problems panel (same rows, copyable actions, cross-links) replaces the two
  banners; dev-machine cards flag hook/shim/local-compile/doctor/stalled-build state and
  the drawer shows interception state, builds in flight with stall flags, and daemon
  alerts/issues.
- **Tests**: probe fixtures cover all seven sections and each failing alone; parity now
  proves the browser and endpoint paths emit byte-identical problem rows; endpoint tests
  cover help/problems/diagnose/target/404 and **fail** rather than silently passing two
  assertions when the passphrase is absent; four hardcoded-`true` checks in e2e/prod are
  real assertions; prod-check also hits `/api/fleet` and compares its problem count to
  the page's.
- **Ops**: the launchd refresh agent is checked in at `packaging/launchd/` with the real
  cadence (20 min, bounded by Vercel's deploy quota) documented instead of the README's
  10-minute crontab. Follow-ups filed: `bd-04ifk` (publish the blob without a deploy),
  `bd-2f5ms` (authenticated remote rchd API for live cross-machine diagnosis),
  `bd-oxdl1` (retire or wire in `web/`).

## [v1.0.60] -- 2026-08-28 (release)

### Local shim fallbacks capped (shim v3)

- Every local-exec path in the generated shims (`cargo`, `cargo-clippy`, the toolchain
  wrapper) now routes through `exec_local`, which sets `CARGO_BUILD_JOBS` when it is not
  already set — the one lever that outranks a repo's own `.cargo/config.toml`. A committed
  `jobs = -1` on a 128-thread box had meant 127 concurrent `rustc`, each forking a ~1 GB
  `rust-lld`, exhausting RAM and swap while `rch shim status` reported every toolchain
  wrapped. Default cap 8; `RCH_LOCAL_MAX_JOBS` overrides; an explicit `CARGO_BUILD_JOBS`
  always wins; the offload path stays uncapped (workers do their own slot accounting).
  `SHIM_VERSION` 2 → 3, `TOOLCHAIN_WRAP_VERSION` 1 → 2 — run `rch shim install` after
  upgrading.
- Disk-pressure policy adapts to small tmpfs mounts.
- Windows worker telemetry parses CIM samples for CPU/memory; `rch-wkr` resolves
  rustup/tool binaries with the `.exe` suffix (bd-jdcxd).
- Socket `reload` honours the launch-time `--workers-config` path (bd-xqg58).

## [v1.0.59] -- 2026-08-27 (release)

### Shim offload leaks fixed (shim v2)

- The cargo shim no longer sends every `--message-format` build local — only
  rust-analyzer's rendered-diagnostic formats stay local — and `cargo-clippy` is shimmed so
  direct invocations offload. A `RUSTC_WORKSPACE_WRAPPER` guard keeps `cargo clippy`
  producing lints. `SHIM_VERSION` → 2; run `rch shim install` after upgrading.

## [v1.0.58] -- 2026-08-26 (tag only)

No GitHub Release exists for this tag: the installer and the fleet's nightly updater kept
serving v1.0.57 until v1.0.59 was published. The tag is dated 2026-08-26 (this section was
originally headed 2026-08-24, the date the notes were written).

278 commits since v1.0.57. Two themes: **RABS**, a new build-sidecar subsystem that lands
in full, and **job mode**, which opens rch's remote-execution rails to work that is not a
compilation.

### Worker-side rustc cap per job (#49)

- **`compilation.remote_build_jobs`** (default `auto`) exports `CARGO_BUILD_JOBS` in the
  remote build session so one offloaded cargo job no longer forks `nproc` rustc on the
  worker. `total_slots` bounds concurrent *jobs*; this bounds parallelism *within* a job,
  which is the axis that was actually exhausting RAM. `auto` is computed on the worker
  from its live cores and memory as `clamp(ram_gib / 8, 2, min(nproc, 8))`; `off`
  restores the old behavior; an integer pins a fixed count. Explicit intent always wins:
  a `CARGO_BUILD_JOBS` already in the worker session (e.g. `/etc/environment`), forwarded
  through the env allowlist, written inline in the command, a `-j` flag, or a project
  `.cargo/config.toml` `[build] jobs` are all left untouched. Windows workers are skipped.
  (Commit [`cf040af0`](https://github.com/Dicklesworthstone/remote_compilation_helper/commit/cf040af0), in the v1.0.58 tag; previously mis-filed under Unreleased.)

(v1.0.57 shipped as a GitHub release on 2026-08-15 without a changelog entry; this section
covers v1.0.57..v1.0.58 only.)

### Job mode — remote execution for non-compilation work

- **`rch exec --job`** admits a command that the classifier would otherwise reject. The
  transparent shell hook's compilation-only admission is unchanged; this is an explicit,
  opt-in path for work that is deliberately remote.

  ```
  rch exec --job --result-dir fuzz/corpus --result-dir crashes -- ./fuzz_target.sh
  ```

- **`--result-dir`** declares directories to bring back, repeatable and order-preserving.
  It is refused without `--job`, so it cannot quietly widen sync-back for ordinary builds.
- **Job-mode admissions queue on active-project exclusion** rather than being refused
  outright. Previously the queue activated only for `AllWorkersBusy`, so a sharded caller
  hit `NoAdmissibleWorkers` and got no wait at all.
- **Exactly one structured result envelope per invocation**, emitted at every terminal
  path, with stdout kept envelope-only while remote command output streams to stderr. This
  is what lets a caller distinguish "the remote command exited non-zero", "rch fell back
  locally and *that* exited non-zero", and "rch itself failed" — a distinction numeric exit
  status cannot carry, since `RCH-Ennn` values are diagnostic identifiers rather than a
  disjoint exit namespace.

  Addresses the proposal in GH#27.

### RABS — Asupersync-native Accelerated Build Sidecar

A new subsystem across `rabs-cas`, `rabs-protocol`, `rabs-key`, `rabs-scheduler`,
`rabs-sandbox`, `rabs-action`, `rabs-replay`, `rabs-wrap`, `rabs-asupersync`, `rabs-wkr`
and `rabsd`. All RABS crates are `publish = false`.

- **Content-addressed store** with ownership-safe provisional recovery, a native-child
  gate, worker reconcile, and cache inventory.
- **Cacheability gating** that refuses to cache a build script whose output depends on an
  imported clock, with suffix-tolerant clock detection and a zero-divergence gate plus
  cacheability report.
- **Scheduler** with permit-chain total ordering, cross-edge single-flight, plane grants,
  and bounded lineage waiters.
- **Durable coordinator fencing** over protocol primitives, with worker fences and
  coordinator lease tracking.
- **Sandbox** network-isolation policy contracts and brokered-fetch lease validation, with
  canonical mounts and a namespace spec.
- **Edge cargo resolution** contract and snapshot validation.

### rch / rchd / rch-wkr

- **Worker-state hygiene**: multi-base GC, reconcile and inventory CLI, plus a
  mirror-ownership probe.
- **Honest disk-pressure reporting** and expanded probe diagnostics in worker selection.

### Fixed

- 26 fixes across the workspace, concentrated in `rch` and the RABS crates.

---

## [v1.0.57] -- 2026-08-15 (release)

547 non-merge commits, 2026-08-05 → 2026-08-15 (release published 2026-08-15, tagged commit
[`7013f4cf`](https://github.com/Dicklesworthstone/remote_compilation_helper/commit/7013f4cf)).
Two stories run in this window and they barely touch: (1) **RABS is born** — every crate in
the "Remote Artifact Build Sidecar" workspace (`rabs-protocol`, `rabs-key`, `rabs-cas`,
`rabs-sandbox`, `rabs-scheduler`, `rabs-asupersync`, `rabs-action`, `rabs-replay`, `rabs-wrap`,
`rabs-wkr`, `rabsd`) has zero commits before this range and a working shadow-mode spine by
the end of it; (2) **rch/rchd keep shipping independently** — fleet-role policy, durable
admin-disable state, CPU-capability quarantine, target-dir bloat reaping, and a batch of
release-blocking fixes landed the same week, none of it RABS. The GitHub Release notes for
v1.0.57 mention only the second story: RABS was still shadow-only. (v1.0.58, 278 commits
later, is where RABS lands in full.)

### RABS genesis — the master plan becomes a 513-bead epic graph and ten crates

Before 2026-08-06 the repo has no `rabs-*` crate; `COMPREHENSIVE_MASTER_PLAN_FOR_RABS_ASUPERSYNC_NATIVE.md`
(v1.6) is checked in the same day the workspace is scaffolded and immediately turned into a
full bead graph — Epics A through T (`remote_compilation_helper-rabs-root-4pidu.19` through
`.38`), 510 beads in one commit, corrected by a same-day "fresh-eyes audit." The next three
days (~330 commits) build the epics as pure libraries with no daemon wiring yet.

#### Delivered capability

- Ten new crates in the Cargo workspace plus the `rabsd` daemon binary, none of which existed at v1.0.56.
- `rabs-protocol`: five schema-version registries, a 23-family stable reason-code registry, a shared redaction/data-classification library, byte-preserving path/argv/env wire types, and requested→resolved snapshot-lineage sealing.
- `rabs-key`: declared-invocation-output derivation, a Layer-0 configuration pack with exact toolchain/capability detection, and the first `rch why`/DAG-browser explainability scaffolding.
- `rabs-cas`: schema-v13 durable content store with provisional-ancestor closures, adoption-edge tracking, ZSTD compression-policy tiers, and commit-ack gating on CAS + metadata durability.
- `rabs-sandbox`: canonical pseudo-file/locale/timezone/device allowlists, immutable read-only source-snapshot mounts, and deterministic OUT_DIR/incremental/temp/home path remapping validated by a cross-worktree acceptance harness.

#### Closed workstreams

- [`remote_compilation_helper-rabs-root-4pidu.19`](https://github.com/Dicklesworthstone/remote_compilation_helper/blob/main/.beads/issues.jsonl) RABS Epic A: repository and architecture foundation
- [`remote_compilation_helper-rabs-root-4pidu.22`](https://github.com/Dicklesworthstone/remote_compilation_helper/blob/main/.beads/issues.jsonl) RABS Epic D: canonical execroot and path handling (65 commits, the busiest epic in the range)
- [`remote_compilation_helper-rabs-root-4pidu.26`](https://github.com/Dicklesworthstone/remote_compilation_helper/blob/main/.beads/issues.jsonl) RABS Epic H: durable CAS and metadata

#### Representative commits

- [`9ff533b9`](https://github.com/Dicklesworthstone/remote_compilation_helper/commit/9ff533b9) scaffolds rabs-protocol, rabs-key, rabs-action, and rabs-cas in one commit — the birth of the workspace
- [`0d0e2546`](https://github.com/Dicklesworthstone/remote_compilation_helper/commit/0d0e2546) writes 510 beads in a single commit, turning the master plan into a tracked epic graph
- [`b12a8de6`](https://github.com/Dicklesworthstone/remote_compilation_helper/commit/b12a8de6) adds the RABS Asupersync-native accelerated build sidecar master plan
- [`fea5d926`](https://github.com/Dicklesworthstone/remote_compilation_helper/commit/fea5d926) rabs-sandbox D009: a deterministic epoch makes Cargo's mtime-based fingerprint worktree-invariant, root-caused live via `cargo -vv` on hz2

### The bridge-plan pivot and the S1–S8 spine — RABS goes live in shadow mode

By 2026-08-10 the epic-by-epic build was producing correct libraries but no running system.
`RABS_BRIDGE_PLAN.md` records a same-day "reality check" and replaces epic-order execution
with a spine-first plan: get one real, live, end-to-end path working before finishing any
more epics. Milestones S1 through S8 landed in under 36 hours (08-10 to 08-11).

#### Delivered capability

- S1: `rabsd` boots a real `rabs-asupersync` runtime island (not a mock) on csd and hz2.
- S2: `rabs-wrap`, a tiny `RUSTC_WRAPPER` binary with a breaker-gated daemon consult, meeting an enforced 8.4 ms end-to-end p95 overhead gate.
- S3: a live UDS server in the rabsd edge region (with a same-day fix for concurrent daemons colliding on the default socket path).
- S4: a shadow decision plane over real production build traffic — computes real Epic-F action keys and emits pass-through "would-have-hit" evidence without altering any build output.
- S5: `rabs-wkr` worker session with orchestrated canonical execution, proven live on hz2.
- S6: the coordinator role boots in-process with leases/arbiter/singleflight mounted and leader/follower degraded-mode acceptance.
- S7: `rabsd doctor`, capability-gated fleet deploy scripts, and packaging/CI.
- S8: fault-injection chaos slice plus a compressed 24-hour shadow soak, both green.
- Post-spine hardening (08-12): rabsd refuses a cache hit whose materialized outputs differ from the caller's real work.

#### Closed workstreams

- [`bd-c7331`](https://github.com/Dicklesworthstone/remote_compilation_helper/blob/main/.beads/issues.jsonl) S1: rabsd binary + real Asupersync runtime island (M2 keystone)
- [`bd-gj6vd`](https://github.com/Dicklesworthstone/remote_compilation_helper/blob/main/.beads/issues.jsonl) S2: rabs-wrap tiny wrapper binary (real RUSTC_WRAPPER)
- [`bd-vyhr0`](https://github.com/Dicklesworthstone/remote_compilation_helper/blob/main/.beads/issues.jsonl) S3: UDS server in the rabsd edge region
- [`bd-w94g8`](https://github.com/Dicklesworthstone/remote_compilation_helper/blob/main/.beads/issues.jsonl) S4: shadow decision plane over production traffic
- [`bd-085cm`](https://github.com/Dicklesworthstone/remote_compilation_helper/blob/main/.beads/issues.jsonl) S5: rabs-wkr skeleton — real ATP session + orchestrated canonical execution
- [`bd-z360j`](https://github.com/Dicklesworthstone/remote_compilation_helper/blob/main/.beads/issues.jsonl) S6: coordinator role boots in-process
- [`bd-n8qt3`](https://github.com/Dicklesworthstone/remote_compilation_helper/blob/main/.beads/issues.jsonl) S7: packaging + fleet provisioning of rabs binaries
- [`bd-rb754`](https://github.com/Dicklesworthstone/remote_compilation_helper/blob/main/.beads/issues.jsonl) S8: spine chaos slice — fault injection + 24h shadow soak

#### Representative commits

- [`28ea3f8a`](https://github.com/Dicklesworthstone/remote_compilation_helper/commit/28ea3f8a) RABS bridge plan: spine-first gap closure from the 2026-08-10 reality check
- [`151ad102`](https://github.com/Dicklesworthstone/remote_compilation_helper/commit/151ad102) S1 — rabsd boots the real asupersync runtime island
- [`aae09051`](https://github.com/Dicklesworthstone/remote_compilation_helper/commit/aae09051) S2 — the tiny RUSTC_WRAPPER binary with breaker-gated daemon consult
- [`8047e569`](https://github.com/Dicklesworthstone/remote_compilation_helper/commit/8047e569) S3 — UDS edge server goes live
- [`15ea763b`](https://github.com/Dicklesworthstone/remote_compilation_helper/commit/15ea763b) S4 — shadow decision plane over live traffic
- [`42b50f31`](https://github.com/Dicklesworthstone/remote_compilation_helper/commit/42b50f31) rabsd refuses a cache hit whose outputs differ from the caller's actual work

### Fleet reliability hardening — role policy, durable disable state, and target-dir bloat

Running in parallel with the early RABS scaffolding (08-06 to 08-09), rch/rchd picked up a
batch of operational fixes aimed at the worker fleet, independent of RABS entirely.

#### Delivered capability

- `general.role = dispatcher|worker|hybrid`: box-level fail-closed queueing policy replaces the old per-call `RCH_REQUIRE_REMOTE` env var.
- `AdminDisableStore` persists worker admin-disable state across `rchd` restarts (a restart used to silently re-enable a worker an operator had disabled).
- CPU-capability (SIGILL) fault detection: workers that fault on unsupported instructions are auto-quarantined instead of surfacing as false build failures; `rch-wkr` probes and reports the x86-64 microarch level (v1..v4) with a soft pre-v3 selection penalty.
- `rch cache status` and `rch gc [--dry-run]`: agent-facing on-demand reap surfaces, backed by an optional per-worker byte-cap LRU eviction policy and a long-TTL pooled-dir reaper for "immortal pool corpses" — the fix for target-dir bloat silently consuming worker disk.
- `rchd`'s restart-admission barrier no longer wedges permanently when a dead wrapper process holds a lease.
- macOS: `rch`/`rchd` prefer an existing `~/.config/rch/config.toml` over the `ProjectDirs`-derived `~/Library/Application Support/...` path.

#### Closed workstreams

- [`bd-wywsj`](https://github.com/Dicklesworthstone/remote_compilation_helper/blob/main/.beads/issues.jsonl) general.role = dispatcher|worker|hybrid — box-level fail-closed/queue policy
- [`bd-8zxz7`](https://github.com/Dicklesworthstone/remote_compilation_helper/blob/main/.beads/issues.jsonl) cpu-capability-fault quarantine not durable across rchd restarts (ovh-b incident)
- [`bd-68hon`](https://github.com/Dicklesworthstone/remote_compilation_helper/blob/main/.beads/issues.jsonl) auto-detect & handle worker CPU-capability (SIGILL) faults
- [`bd-9fgeu`](https://github.com/Dicklesworthstone/remote_compilation_helper/blob/main/.beads/issues.jsonl) macOS: rch+rchd silently ignore the documented ~/.config/rch/config.toml
- [`bd-8e1mx`](https://github.com/Dicklesworthstone/remote_compilation_helper/blob/main/.beads/issues.jsonl) rchd restart-admission barrier permanently wedged by dead-wrapper job leases

#### Representative commits

- [`89a26e1a`](https://github.com/Dicklesworthstone/remote_compilation_helper/commit/89a26e1a) `BoxRole` dispatcher/worker/hybrid for fleet machine identity
- [`2ae4a338`](https://github.com/Dicklesworthstone/remote_compilation_helper/commit/2ae4a338) durable `AdminDisableStore`, rehydrated across rchd restarts
- [`a89ee345`](https://github.com/Dicklesworthstone/remote_compilation_helper/commit/a89ee345) optional per-worker byte-cap LRU for stale target reaping
- [`ab5befee`](https://github.com/Dicklesworthstone/remote_compilation_helper/commit/ab5befee) prefer existing XDG `~/.config/rch` over ProjectDirs on macOS
- [`310f8b8d`](https://github.com/Dicklesworthstone/remote_compilation_helper/commit/310f8b8d) unwedge the restart-admission barrier from dead-wrapper leases

### Release-week fix batch — the issues named in the v1.0.57 release notes

Every "Added"/"Fixed" line in the GitHub Release comes from a concentrated 2026-08-14 push,
three days after the RABS spine was declared complete and shadow-only.

#### Delivered capability

- macOS-native telemetry (GH #39): `rch-telemetry` collects real CPU/memory via `host_processor_info`/`vm_stat`/`sysctl` instead of returning zeros from a missing `/proc`.
- SpeedScore persistence (GH #40): `rchd` persists a worker's SpeedScore before marking its benchmark done, so a crash/restart mid-cycle no longer discards a fresh benchmark; unknown telemetry age logs as `-1` instead of `u64::MAX`.
- Durable per-worker cargo git-dep cache (GH #42): the hook keeps a per-worker `CARGO_HOME` across jobs so git dependencies are fetched once per worker, not once per job.
- Stable-toolchain pin fix (GH #43): `rch` no longer stamps a stable rustc commit date onto rustup as if it were a nightly.
- `min_free_gb` probe timeout fails closed: capability probes on loaded hosts get a 25 s budget so a timed-out disk-floor probe can no longer silently admit jobs below the configured floor.

#### Representative commits

- [`d64190db`](https://github.com/Dicklesworthstone/remote_compilation_helper/commit/d64190db) collect real CPU/memory on macOS without /proc (#39)
- [`cddbcae1`](https://github.com/Dicklesworthstone/remote_compilation_helper/commit/cddbcae1) persist SpeedScore before treating a benchmark as done (#40)
- [`9f985350`](https://github.com/Dicklesworthstone/remote_compilation_helper/commit/9f985350) keep a durable per-worker CARGO_HOME across jobs (#42)
- [`c5a237a1`](https://github.com/Dicklesworthstone/remote_compilation_helper/commit/c5a237a1) never stamp a stable rustc commit date onto rustup (#43)
- [`b23cecad`](https://github.com/Dicklesworthstone/remote_compilation_helper/commit/b23cecad) give loaded-host capability probes a 25 s budget

## [v1.0.56] -- 2026-08-04 (release)

First published release since v1.0.53; v1.0.54 and v1.0.55 were git-tag-only
(GitHub Actions could not run the release pipeline), so their changes ship
here as binaries for the first time.

### Added

- **GH #38 — the canonical project root is configurable.** `path_topology`
  roots (`canonical_project_root`, `extra_project_roots`) are wired into the
  `rch config set` / `rch config reset` arms with validation, so fleets that
  do not keep code under `/data/projects` can point rch at their real layout
  without hand-editing config files.
- **Clean-overlay execution receipts and admission.** Successful clean-overlay
  runs emit receipts; concurrent overlay roots are guarded, root identity is
  bound, and isolated clean-overlay jobs are admitted correctly.
- **Durable client job leases and daemon restart admission guards**
  (bd-6xhh9.2/.3/.4), including retention of missing-worker bypass records.

### Fixed

- **SpeedScore benchmarks compile and emit finite, parseable output**: the
  compilation benchmark actually compiles, JSON scores are finite, and pretty
  `Score` lines parse; worker probes no longer report NaN/garbage SpeedScores.
- **Windows worker transfers** (v1.0.54/v1.0.55 content): tar/ssh stderr is
  drained concurrently (no more deadlocked transfers), retrieval can no longer
  clobber the source, and transfers are bounded by a timeout.
- Lockfile pruned of unused entries; benchmark/test formatting cleaned up.

---

## [v1.0.55] -- 2026-08-02 (tag only)

Two-commit follow-up to the just-shipped Windows worker platform. The Windows tar-over-ssh
transport piped the mirror process's stderr (local `tar` on sync, remote `ssh` on retrieve)
but never drained it — a chatty `tar` (concurrent writes, locked files, permission noise)
could fill the ~64 KB pipe, block the process, starve the stdout pump, and hang the whole
transfer; it is now drained concurrently via a spawned sink task. Paired with a docs pass
that generalizes the Windows-worker setup guide (`C:/rch` tar-over-ssh transport, v1
limitations) for use outside the original fleet.

- [`d629beee`](https://github.com/Dicklesworthstone/remote_compilation_helper/commit/d629beee) fixes a latent deadlock in Windows transfers — rare in practice, but a hang with no timeout
- [`3c26f428`](https://github.com/Dicklesworthstone/remote_compilation_helper/commit/3c26f428) genericizes the Windows-worker skill docs for other fleets

## [v1.0.54] -- 2026-08-02 (tag only)

Ships the first Windows worker platform. Remote compilation had assumed a POSIX worker
everywhere (rsync, `/data/tmp/rch`, `timeout(1)`); this threads a
`WorkerPlatform::{Posix, Windows}` through the transfer pipeline without touching POSIX
defaults. `SelectedWorker.declared_os` (serde-default) carries the operator-declared OS from
the daemon so old hooks stay compatible; Windows workers sync/retrieve via tar-over-ssh under
`C:/rch` (accepting both `C:/` and `C:\` as absolute overrides), skip the POSIX `timeout(1)`
wrapper and the `setsid`/pgid watchdog (which would otherwise hang SSH until timeout on a
successful Windows build), and disable streaming progress.

- [`27d95e5b`](https://github.com/Dicklesworthstone/remote_compilation_helper/commit/27d95e5b) the platform threading itself — wire field, transfer pipeline, orchestration
- [`277848f6`](https://github.com/Dicklesworthstone/remote_compilation_helper/commit/277848f6) locks drive-path parsing and the pgid-watchdog skip so the Windows path can't regress to Unix assumptions
- [`d1dc306a`](https://github.com/Dicklesworthstone/remote_compilation_helper/commit/d1dc306a) fills the new `declared_os` fixture field so the suite compiles under the wire change

## [v1.0.53] -- 2026-08-02 (release)

21 commits, but not a single linear line of work: the merge commit [`9f52da57`](https://github.com/Dicklesworthstone/remote_compilation_helper/commit/9f52da57) ("integrate
origin/main with local RCH fixes as remote supersets") reconciled two histories that had
independently diverged from v1.0.52 — an 11-commit local fix branch dated 2026-05-15 →
2026-07-25, and 5 commits that origin/main had advanced in the same window — and the OS-gate
feature landed on top of that reconciliation. Author dates on 11 of the 21 commits therefore
predate the nominal window; they only reached `main` on 2026-07-29.

### Host-OS worker admission gate

Cross-platform fleets had no way to keep a command that needs a specific host OS (a
`*-pc-windows-msvc` build needing the MSVC toolchain, `*-apple-*` needing the macOS SDK)
from being routed to a worker structurally incapable of producing that artifact.

#### Delivered capability

- Opt-in `os` field in `workers.toml` (`linux | darwin | windows`) that makes a worker **exclusive**: admissible only for commands requiring that OS; a worker declaring nothing admits exactly as before.
- Requirement derived from the command's `--target` triple (`*-pc-windows-msvc` → windows, `*-apple-*` → darwin; `*-pc-windows-gnu`/wasm stay unconstrained), reusing the existing `SelectionRequest::command` field so the gate holds across mixed `rch`/`rchd` versions in one fleet.
- Gate enforced in three independent places (`WorkerSelector::get_eligible_workers`, `try_fallback`, `build_selection_diagnostics`) so `rch status` reports the exclusion as `os.declared_mismatch` instead of disagreeing with the scheduler; no admissible worker falls back to local rather than dispatching to a host that can't build it.
- Corrected `WORKERS.md`/`workers-template.toml`, which had documented a `required_tags` gate that never existed in source (tags are descriptive only).
- Repaired a `main` compile break the merge reconciliation had introduced (`ErrorCode::BuildCargoWorkspaceInheritance` missing a `description()` arm; a dead closure in `status.rs`).

#### Representative commits

- [`974ac383`](https://github.com/Dicklesworthstone/remote_compilation_helper/commit/974ac383) the OS-gate feature itself, gated in three places for consistency
- [`08b2fcf9`](https://github.com/Dicklesworthstone/remote_compilation_helper/commit/08b2fcf9) restores workspace-inheritance error handling the merge reconciliation had dropped
- [`a4f7e8bc`](https://github.com/Dicklesworthstone/remote_compilation_helper/commit/a4f7e8bc) repairs the resulting `main` compile break
- [`ef21509c`](https://github.com/Dicklesworthstone/remote_compilation_helper/commit/ef21509c) documents the gate and retracts the phantom `required_tags` claim

### Local fixes branch reconciled: path-topology, worker pins, fleet pressure, transfer stalls

An 11-commit local branch (2026-05-15 → 2026-07-25) covering path-dependency workspace
sync, worker-pin selection, fleet-pressure visibility, and transfer-stall bounding had
drifted from `origin/main` by roughly 488 upstream commits before [`9f52da57`](https://github.com/Dicklesworthstone/remote_compilation_helper/commit/9f52da57) reconciled the
two "best of both," explicitly keeping local intent where remote had not yet absorbed it.

#### Delivered capability

- Policy-normalized absolute path dependencies allowed through path-topology; path-dependency workspace sync roots isolated per project; synced-manifest path attributes rewritten and workspace-inherited path dependencies synced.
- `rch status` surfaces pressure-blocked fleet state instead of hiding it.
- `preferred_workers` is an authoritative pin — both `WorkerSelector` and the legacy selection path return `NoMatchingWorkers` rather than silently substituting a different eligible worker.
- Artifact transfer stalls bounded; the remote-required non-compilation refusal gets its own error code.
- Remote sync topology and manifest rewriting driven from `PathTopologyPolicy`/config instead of hardcoded `/dp → /data/projects` and `/tmp/rch-sync` constants; a `replace_sources()` pass that had been corrupting non-path manifest metadata was dropped for the targeted rewriter; floating rust channels (`stable`/`beta`/`nightly`) matched by family instead of exact version, so a plain-`nightly` project stops being refused by every worker on a different nightly date.

#### Representative commits

- [`4f7931e0`](https://github.com/Dicklesworthstone/remote_compilation_helper/commit/4f7931e0) isolates path-dependency workspace sync roots
- [`6fea0b34`](https://github.com/Dicklesworthstone/remote_compilation_helper/commit/6fea0b34) makes worker pins authoritative instead of a soft hint
- [`ac84dd29`](https://github.com/Dicklesworthstone/remote_compilation_helper/commit/ac84dd29) bounds artifact transfer stalls
- [`e3bbabdb`](https://github.com/Dicklesworthstone/remote_compilation_helper/commit/e3bbabdb) drives remote sync from configuration, drops the corrupting source-rewrite pass
- [`8daea511`](https://github.com/Dicklesworthstone/remote_compilation_helper/commit/8daea511) matches floating rust channels by family, not exact date/version

Three of these commits carry bracketed tracker refs (`[br-bd-3bhcb]`, `[br-bd-17c65.10.19]`,
`[br-bd-17c65.10.17.1.3]`) that do not resolve to any record in the current
`.beads/issues.jsonl`; they are quoted from the commit messages, not linked.

### Upstream fleet-refusal legibility and capability probing

While the local branch above was in flight, `origin/main` independently shipped a self-audit
batch fix (issues #30–#35) for refusal legibility plus per-toolchain capability probing,
merged into the same reconciliation.

#### Delivered capability

- Refusals route through `summary_critical()` (always-on stderr) instead of the default-silent `summary()`, so an `rc=1` refusal is no longer indistinguishable from a crashed toolchain; retryable refusals get exit code 103 versus exit 1 for permanent ones.
- Stale worker-side `target/` residue is no longer re-pulled onto the local project root when a custom `CARGO_TARGET_DIR` is in play (previously a spurious E309 on otherwise-complete builds).
- The capability probe records installed rustup **components** per toolchain, not just toolchains/targets — a worker missing `clippy`/`rustfmt` for the pinned nightly used to report healthy and get routed lint work it silently failed.

#### Closed workstreams

- [`bd-vc61a`](https://github.com/Dicklesworthstone/remote_compilation_helper/blob/main/.beads/issues.jsonl) Capability probe records toolchains/targets but not COMPONENTS
- [`bd-u9mo8`](https://github.com/Dicklesworthstone/remote_compilation_helper/blob/main/.beads/issues.jsonl) `rch shim install|status|uninstall` (canonical cargo wrapper) — closure recorded; the feature shipped in v1.0.52

#### Representative commits

- [`10198772`](https://github.com/Dicklesworthstone/remote_compilation_helper/commit/10198772) refusal-legibility and stale-target-pull batch fix (rch#30–35)
- [`85398183`](https://github.com/Dicklesworthstone/remote_compilation_helper/commit/85398183) per-toolchain COMPONENTS probing (bd-vc61a)
- [`9318f5c7`](https://github.com/Dicklesworthstone/remote_compilation_helper/commit/9318f5c7) files bd-68hon (worker CPU-capability SIGILL auto-handling), root-caused live against the Ivy Bridge `ovh-b` worker; closed later, in v1.0.57

## [v1.0.52] -- 2026-07-23 (release)

### Added

- **`rch shim install|status|uninstall` — the canonical cargo offload wrapper.**
  rch only auto-intercepts builds via the Claude Code PreToolUse hook, so Codex,
  plain shells, scripts, and CI — which invoke `cargo` directly with no hook — were
  compiling **locally** on orchestrator boxes, defeating the point of rch. rch already
  honored a cargo-wrapper contract (it sets `RCH_CARGO_WRAPPER_BYPASS=1` on local
  fallback) but never shipped the wrapper, so every box hand-rolled one or had none.
  This ships the ONE canonical wrapper as a first-class command:
  - harness-agnostic — every agent that runs `cargo` via `PATH` now offloads;
  - loop-safe (honors `RCH_CARGO_WRAPPER_BYPASS`), fails open if `rch` is absent, and
    leaves rust-analyzer (`--message-format`) builds local;
  - offloads only `build|test|check|clippy|bench|doc|nextest`; everything else is local;
  - installs to a dedicated `~/.rch/shims/` (not `~/.local/bin`, which acfs manages);
  - `--allow-local-fallback` toggles fail-open; default is fail-closed (queue for a
    worker, never build locally) — appropriate for a dispatcher box;
  - `rch shim status` reports version drift, `PATH` order, and any local builds running.

  Install **only** on dispatcher boxes (that offload OUT); never on a worker box (a
  worker runs cargo via `rch-wkr` and the shim would re-offload/loop). Part of a larger
  effort tracked as an epic (dispatcher `general.role`, a loud local-build alarm, and
  install/watchdog durability to follow).

### Fixed

- Tidied two nightly-clippy findings (`collapsible_if`, `manual_contains`) in the
  linked-git-worktree upload path so the tree is clean under `-D warnings`.

---

## [v1.0.51] -- 2026-07-22 (release)

### Fixed

- **The bypass↔telemetry stranding deadlock that silently dropped the whole fleet
  to local builds.** A circuit trip quarantined a worker and persisted a
  `BypassRecord`; the telemetry poller then skipped quarantined workers, but the
  bypass recovery gate requires *fresh telemetry* before promoting a worker — so a
  quarantined worker could never produce the evidence needed for its own recovery.
  Restarting `rchd` did not help, because `reconcile_on_start` re-applied the
  persisted record. Meanwhile every offload fell back to local execution with no
  fleet-level signal (root cause of the 2026-07-16 offload meltdown).
  `should_poll_worker` now gates on the **admin** axis (`AdminIntent::Drained |
  Disabled`) instead of `WorkerStatus`, which collapses every quarantine state into
  `Unreachable`.
- **`rch workers enable` is now durable.** The enable handler deletes the persisted
  bypass record (mirroring `rejoin`), so an operator re-enable survives a daemon
  restart instead of being re-quarantined from disk on the next start.
- **Health probes no longer cascade into fleet-wide quarantine.** Health checks get
  their own SSH ControlMaster pool, separate from the shared build/telemetry pool.
  The health probe is what opens the circuit that quarantines a worker, so a single
  wedged control socket could previously false-fail every probe at once.
- **`cargo zigbuild` is no longer dispatched to workers that cannot run it.**
  `CargoZigbuild` mapped to `RequiredRuntime::Rust`, and the finer `needs_zig` check
  is only enforced by `assess_admissibility`, which the daemon's selection path never
  calls — so any rustc-capable worker was admitted. On a worker without
  cargo-zigbuild the build fails with `error: no such command: 'zigbuild'`, which
  matches neither `is_toolchain_failure` nor `detect_worker_system_dependency_failure`,
  so the nonzero exit reached the user verbatim instead of falling open to local.

### Added

- **`cargo zigbuild` cross-compile offload.** New `CompilationKind::CargoZigbuild`
  covering both `cargo zigbuild ...` and the standalone `cargo-zigbuild` binary
  (build forms only). Artifact retrieval is triple-aware — cargo-zigbuild always
  builds for an explicit `--target`, so output lands under
  `target/<triple>/<profile>/`, which the ordinary Rust globs miss entirely — with
  triple-nested cache excludes on the custom-`CARGO_TARGET_DIR` path.
- **`RequiredRuntime::Zig`**, gated on `WorkerCapabilities::has_zig()`, which requires
  **both** `zig` and `cargo-zigbuild`: zig alone cannot run the subcommand, and
  cargo-zigbuild alone cannot link (it shells out to `zig cc`). `rch-wkr` probes both.
- **Fleet-degraded alarm.** `rchd` now emits an edge-triggered warning when ≥75% of
  the last 20 selections returned no worker (clearing at ≤40%), so a fleet-wide silent
  local fallback is visible in the daemon journal instead of only in per-hook output.

### Upgrade notes

- **Upgrade `rch-wkr` on workers, not just the orchestrators.** Worker selection reads
  capabilities from `rch-wkr capabilities` JSON. Until the new `rch-wkr` is deployed,
  `zig_version`/`cargo_zigbuild_version` are absent, `has_zig()` is false, and
  zigbuilds run locally rather than offloading — the safe direction, and it
  self-resolves on worker upgrade.
- `RequiredRuntime` gained a `Zig` variant, which appears in the `SelectionRequest`
  wire format. Keep `rch` and `rchd` at the same version, as with the Go/TypeScript
  offload in 1.0.48.

---

## [v1.0.50] -- 2026-07-17 (draft release — never published)

`gh release view v1.0.50` reports `isDraft: true` with no publish date: the tag exists and
the notes below describe what it carries, but nothing was ever served from it; installers
skipped from v1.0.49 to v1.0.51.

### Added

- **Fail-closed clean-overlay remote proofs for shared working trees.** `rch
  exec` now accepts an immutable `--base <commit>` plus `--clean-overlay` and
  explicit `--overlay-path` selections (or `--no-overlay`). The remote source
  tree is built from `git archive` and only the selected, validated paths are
  overlaid, so unrelated local dirt cannot enter a proof build. The pipeline
  rejects deletions, type changes, symlink or submodule surfaces, ambiguous
  spellings, export-affecting attributes, source mutation during capture, and
  post-transfer fingerprint drift. Clean-overlay execution is remote-only and
  never falls back to the ambient local tree.

### Fixed

- **Shell suffix classification is byte-faithful and fail-closed.** Benign
  pipes, redirects, and backgrounding remain offloadable without rewriting
  file-descriptor adjacency, while embedded newlines and carriage returns are
  rejected before a command can be re-emitted.
- **Release gates remain deterministic inside isolated overlays.** Doctor
  startup probes now honor explicit test binaries, generated Cargo fixtures
  declare standalone workspaces, and compact harness directory identifiers keep
  Unix-domain socket paths below the platform limit.

---

## [v1.0.49] -- 2026-07-15 (release)

### Polyglot offload: Go, TypeScript, and Nix join the fleet

Through v1.0.47, rch only offloaded Cargo/rustc (plus gcc/bun/node). Agent swarms running
`go build`, `go test`, `tsc`, or `nix build` got zero interception — every one of those ran
locally, so a dispatch box could carry a load average over 100 while dozens of Rust-only
worker slots sat idle. This wave adds real classification and worker capability gating for
three more toolchains, plus a correctness fix for cross-repo Cargo path dependencies that
could otherwise silently desync a remote build. Landed via PR #29.

#### Delivered capability

- New `CompilationKind::{GoBuild, GoTest, GoVet, Tsc}` — the `workers.toml` `tags = ["bun","go","rust"]` entries had implied Go/TS offload worked since day one; `required_tags` was never read anywhere, so it never did.
- Nix build/test routing: `nix build`, legacy `nix-build`, `nix flake check`, and non-interactive `nix develop -c` / `nix shell -c` are classified and routed only to workers that probe a real `nix` binary with a populated `/nix/store`; interactive/mutating Nix subcommands fall back to local.
- `node_modules` is provisioned worker-side for `tsc` instead of rsynced (macOS-native `.node` binaries would be unusable on a Linux worker).
- The PreToolUse hook stopped attaching an ambient rustup toolchain to non-Rust dispatches (a `go build` was carrying `nightly-2026-07-11` along for the ride).
- `fix(cargo): materialize every local path closure` — derives a manifest-only materialization closure (normal/build/dev/target/optional/workspace-inherited/patch/transitive path deps) separate from the active cargo-metadata execution DAG, and fails closed with a new `RCH-E415` (with actionable evidence) instead of silently syncing only the primary root.
- Installer: an active system-level `rchd.service` is treated as authoritative on worker hosts, so Easy Mode no longer installs a redundant user-level daemon that nightly updates could resurrect alongside root's (issue #28).

#### Representative commits

- [`1213f4ef`](https://github.com/Dicklesworthstone/remote_compilation_helper/commit/1213f4ef) `feat(classifier): offload Go and TypeScript builds` — new compilation kinds + capability gating
- [`c6fe8dee`](https://github.com/Dicklesworthstone/remote_compilation_helper/commit/c6fe8dee) `feat(offload): route Nix builds to nix-capable workers` (#26)
- [`325a7503`](https://github.com/Dicklesworthstone/remote_compilation_helper/commit/325a7503) probe + require a real nix (binary + populated /nix/store)
- [`167d5117`](https://github.com/Dicklesworthstone/remote_compilation_helper/commit/167d5117) materialize every local path closure — new `RCH-E415` fail-closed path
- [`a17ec093`](https://github.com/Dicklesworthstone/remote_compilation_helper/commit/a17ec093) installer avoids a duplicate user daemon on worker hosts (#28)

There is no `v1.0.48` tag: the sequence goes straight from v1.0.47 to v1.0.49.

## [v1.0.47] -- 2026-07-02 (release)

Two-commit release shipping one large, deliberately atomic fix:
[`facb7b2d`](https://github.com/Dicklesworthstone/remote_compilation_helper/commit/facb7b2d)
`feat(rchd): self-healing worker circuits + SSH connection reuse; managed build-artifact dirs`.
A fleet audit found the periodic daemon subsystems (health, telemetry, capability probe,
cache-cleanup, stale-target-reap, reclaim, toolchain probe) each opening fresh SSH sessions,
and the resulting handshake flood (~72/min) was itself making healthy workers look
unreachable and tripping their circuit breakers. The fix threads one shared `SshPool` (warm
`ControlMaster`, bounded `ControlPersist`) through every subsystem, collapsing that to ~12
warm masters; unifies the two circuit-breaker stores into one source of truth via
`CircuitStats::apply_health_outcome` so `enable()` and a successful benchmark actually
reset/promote state, half-open recovery needs exactly `success_threshold` clean probes, and a
transient half-open failure no longer reopens the circuit; and defaults the remote
build-artifact prefix (`CARGO_TARGET_DIR`/`TMPDIR`/Go caches) to the managed `/data/tmp/rch`
zone instead of leaking into unscanned paths (root cause of a 241 GB `/root/cass-ft-target`
filling a worker). The second commit
([`0c22f427`](https://github.com/Dicklesworthstone/remote_compilation_helper/commit/0c22f427))
files the Nix-offload design bead that lands in v1.0.49.

The orphan tag `rch-local-superseded-20260710` (2026-07-09) sits only on local backup
branches and is not an ancestor of any release: an abandoned parallel-agent branch that
reimplemented the same SSH-pool + circuit-breaker idea already shipped in [`facb7b2d`](https://github.com/Dicklesworthstone/remote_compilation_helper/commit/facb7b2d).

## [v1.0.46] -- 2026-06-25 (release)

Small CI-hardening release closing the trailing edge of the session-history-remediation
program. [`bfa76f3b`](https://github.com/Dicklesworthstone/remote_compilation_helper/commit/bfa76f3b)
and [`71727d57`](https://github.com/Dicklesworthstone/remote_compilation_helper/commit/71727d57)
add a release-asset-completeness gate plus a linux-musl row to the test-release matrix, then
rework the gate to be installability/platform-based rather than a brittle file-count check
(`bd-qb0if`). [`90ff452a`](https://github.com/Dicklesworthstone/remote_compilation_helper/commit/90ff452a)
closes `bd-o0lxa`, confirming the cosign-tolerance self-update fix (PR #25) was
independently validated.

## [v1.0.45] -- 2026-06-25 (release)

### Session-history-remediation program: closeout (epics 7, 10, 16 + root)

`bd-session-history-remediation-ocv9i` — "RCH session-history remediation program from
complete history analysis" — was the dominant epic across v1.0.42 and v1.0.45, built from a
full audit of real agent session logs. This release closes its remaining P0/P1 sub-epics:
OS/arch-aware fleet update with release-provenance verification (epic 7), capacity-queue
semantics under multi-agent load (epic 10), and cross-cutting fault-injection/release gates
via a real-fleet smoke/soak profile (epic 16) — then closes the root program itself.

#### Delivered capability

- Release-provenance verification + deploy audit: a fleet-deploy enforcement gate, so a worker binary that doesn't match the expected release provenance is refused rather than silently deployed.
- `rch self-test --smoke --load` real-fleet profile: `DesiredVsLiveFleet`, `ProofModeRefusal`, `cargo_canary`/`artifact_retrieval`/`queue_attach_cancel`, disk/inode admission, and capabilities smoke scenarios — each built against a mock-SSH executor and then proven live against the real fleet, fixing two daemon canary bugs only the live run surfaced.
- Multi-agent storm-control E2E foundation, proven live on a 12-worker fleet (epic 10.4) — validates queue-when-busy and job-reattach semantics under real concurrent load.
- A CI/release validation-matrix gate with close-reason evidence audit (epic 16.5).
- rch#23 fleet-packaging fixes: workspace deps switched from absolute `/dp` paths to crates.io, a linux-x86_64 prebuilt fallback (musl → gnu) for the installer, and a clean-checkout CI guard.
- Cosign-tolerant signature verification lands on `main` via PR #25 — the same fix v1.0.44 had already fleet-deployed off a divergent branch.
- Hook classifier: cargo/rustc wrapped in a benign pipe, redirect, background `&`, or `bash -c "..."` was previously rejected by the Tier-1 structural filter and run locally — since those are the dominant agent invocation forms, `force_remote=true` orchestrators were silently defeated, producing exactly the local rustc storms rch exists to prevent (issue #24). `classify_command` now handles both safely at depth 0.
- `zcecy.14` (hook hot-path de-monolithization) closes: `hook.rs` down to 1992 lines via five submodule extractions.

#### Closed workstreams

- [`bd-session-history-remediation-ocv9i`](https://github.com/Dicklesworthstone/remote_compilation_helper/blob/main/.beads/issues.jsonl) RCH session-history remediation program — root closed COMPLETE
- [`bd-session-history-remediation-ocv9i.7`](https://github.com/Dicklesworthstone/remote_compilation_helper/blob/main/.beads/issues.jsonl) P0: OS/arch-aware fleet update and worker binary validation
- [`bd-session-history-remediation-ocv9i.10`](https://github.com/Dicklesworthstone/remote_compilation_helper/blob/main/.beads/issues.jsonl) P1: Capacity queue semantics and job reattach
- [`bd-session-history-remediation-ocv9i.16`](https://github.com/Dicklesworthstone/remote_compilation_helper/blob/main/.beads/issues.jsonl) P0: Cross-cutting validation fault injection and release gates
- [`remote_compilation_helper-zcecy`](https://github.com/Dicklesworthstone/remote_compilation_helper/blob/main/.beads/issues.jsonl) Epic: rch hook hot-path — performance + reliability hardening

#### Representative commits

- [`06aad61c`](https://github.com/Dicklesworthstone/remote_compilation_helper/commit/06aad61c) closes epics 7/16 and the root program
- [`c4ed7bba`](https://github.com/Dicklesworthstone/remote_compilation_helper/commit/c4ed7bba) enforce release-provenance gate + deploy audit in fleet deploy
- [`a1c6ec38`](https://github.com/Dicklesworthstone/remote_compilation_helper/commit/a1c6ec38) wire `rch self-test --smoke --load` live storm-control
- [`8d6e3fe1`](https://github.com/Dicklesworthstone/remote_compilation_helper/commit/8d6e3fe1) use crates.io deps instead of absolute /dp paths (rch#23)
- [`a5757a48`](https://github.com/Dicklesworthstone/remote_compilation_helper/commit/a5757a48) closes `zcecy.14` — hook.rs de-monolithized to 1992 lines
- [`8ceeb066`](https://github.com/Dicklesworthstone/remote_compilation_helper/commit/8ceeb066) offload cargo/rustc when wrapped in benign pipe/redirect/bg/bash -c (#24)

## [v1.0.44] -- 2026-06-24 (release)

Fleet hotfix built off v1.0.43 (the deployed baseline) plus two cherry-picked `main` fixes,
built locally because GitHub Actions was gridlocked (50+ hour queue). Headline: `rch update`
no longer hard-fails on hosts without `cosign`
([`d67e6022`](https://github.com/Dicklesworthstone/remote_compilation_helper/commit/d67e6022)) —
signature verification degrades to a warning (checksum stays enforced) when a release ships
a sigstore bundle but `cosign` isn't installed, unblocking self-update across the cosign-less
worker fleet. Also cherry-picks a stalled-Cargo-git-fetch classifier
([`41405976`](https://github.com/Dicklesworthstone/remote_compilation_helper/commit/41405976))
and a bound on piggyback telemetry collection so a finished build's optional telemetry run
can no longer keep it looking "active." Only aarch64-darwin and x86_64-linux-gnu assets were
built; the same cosign fix later landed formally on `main` via PR #25 in v1.0.45.

## [v1.0.43] -- 2026-06-19 (release)

Single-commit release:
[`141ae56b`](https://github.com/Dicklesworthstone/remote_compilation_helper/commit/141ae56b)
`feat(routing): source preferred_workers from project .rch/config.toml` — per-project
worker-preference routing, built directly on v1.0.42.

## [v1.0.42] -- 2026-06-18 (release)

The largest release in this span — 190 commits over ten days (2026-06-08 → 2026-06-18),
dominated by two epics: the session-history-remediation program's opening wave, and a
parallel hook-hot-path de-monolithization effort.

### Session-history-remediation program: launch (epics 1, 3, 5, 17)

The epic `bd-session-history-remediation-ocv9i` was scoped directly from a review of real
agent session logs, targeting the failure modes showing up in the wild: workers stuck in a
manual-recovery bypass state, hooks that couldn't self-heal a dead daemon socket,
silently-ignored placement env vars, and unredacted secrets in proof output.

#### Delivered capability

- Bypass recovery service: a probe/backoff/canary auto-rejoin loop so a worker temporarily bypassed for a failure no longer needs a manual `rch workers enable` to recover (epic 1.3).
- Hook socket-failure recovery: structured incidents plus autostart hardening when the daemon socket is unreachable (epic 3.1).
- Agent-facing proof handoff output format (epic 5.4), and a canonical placement-controls registry (`rch-common/src/placement.rs`) resolving `RCH_WORKER`, `RCH_FORCE_REMOTE`/`RCH_REQUIRE_REMOTE`, `RCH_QUEUE_WHEN_BUSY`, `RCH_VISIBILITY` and their aliases into a `PlacementPlan` that never silently drops an unrecognized or superseded knob — fixing a previously **silently-ignored `RCH_FORCE_REMOTE`** (epic 13.5).
- Central remediation config schema + default policy, wired into `init`/`doctor`/`lint`/`diff`/`export` rollout, with E2E golden-test coverage (epic 17.1–17.3).
- `redact_secrets` wired into every remediation output surface plus shell E2E leak guards (`bd-53ga7`).
- `rch sync --force` — an agent-safe force-resync command (`bd-apg5l`).
- `rch capabilities` webhook notifications fire on reliability-verdict transitions.

#### Closed workstreams

- [`bd-session-history-remediation-ocv9i.1`](https://github.com/Dicklesworthstone/remote_compilation_helper/blob/main/.beads/issues.jsonl) P0: Temporary bypass and auto-rejoin worker lifecycle
- [`bd-session-history-remediation-ocv9i.3`](https://github.com/Dicklesworthstone/remote_compilation_helper/blob/main/.beads/issues.jsonl) P0: Hook daemon doctor mutual self-healing
- [`bd-session-history-remediation-ocv9i.5`](https://github.com/Dicklesworthstone/remote_compilation_helper/blob/main/.beads/issues.jsonl) P0: Proof mode and deferred proof queue
- [`bd-session-history-remediation-ocv9i.13.5`](https://github.com/Dicklesworthstone/remote_compilation_helper/blob/main/.beads/issues.jsonl) First-class placement queue and visibility controls for agents
- [`bd-session-history-remediation-ocv9i.17`](https://github.com/Dicklesworthstone/remote_compilation_helper/blob/main/.beads/issues.jsonl) P1: Config defaults installer and upgrade rollout

#### Representative commits

- [`e333c8fe`](https://github.com/Dicklesworthstone/remote_compilation_helper/commit/e333c8fe) bypass recovery service — probe/backoff/canary auto-rejoin loop
- [`0320b32d`](https://github.com/Dicklesworthstone/remote_compilation_helper/commit/0320b32d) hook socket-failure recovery incidents + autostart hardening
- [`9b332c31`](https://github.com/Dicklesworthstone/remote_compilation_helper/commit/9b332c31) central remediation config schema + default policy
- [`d3c6272b`](https://github.com/Dicklesworthstone/remote_compilation_helper/commit/d3c6272b) redact secrets at free-text output surfaces
- [`70ac75a2`](https://github.com/Dicklesworthstone/remote_compilation_helper/commit/70ac75a2) wire remediation config into init/doctor/lint/diff/export rollout

### Hook hot-path de-monolithization (epic zcecy.14)

`remote_compilation_helper-zcecy` began carving `rch/src/hook.rs` into focused submodules
(29 commits reference `zcecy` in this range). This release extracts the SSH command runner,
command-parsing, formatting, and repo-updater pre-sync subsystems; the effort completes in
v1.0.45.

#### Representative commits

- [`3d9c24d5`](https://github.com/Dicklesworthstone/remote_compilation_helper/commit/3d9c24d5) extract hook::ssh submodule + rename to run_offload_ssh_command
- [`2b880d07`](https://github.com/Dicklesworthstone/remote_compilation_helper/commit/2b880d07) extract hook::command_parsing submodule
- [`5b4fcb04`](https://github.com/Dicklesworthstone/remote_compilation_helper/commit/5b4fcb04) extract hook::formatting submodule — hook.rs now ≤ 2000 lines
- [`9dff82aa`](https://github.com/Dicklesworthstone/remote_compilation_helper/commit/9dff82aa) extract repo_updater pre-sync subsystem from hook.rs

### Fleet reliability and scheduler correctness

A cluster of independent fixes targeting worker dispatch and connection health, several from
a dedicated fleet audit.

#### Delivered capability

- Self-healing circuit window + first-class worker priority (#21): `CircuitStats::error_rate()` computes over a bounded recent-results window instead of unbounded lifetime counters, and `close()` clears `recent_results` — fixes long-uptime daemons silently dropping healthy workers from dispatch (the recurring "not enough free build slots" flapping). Priority becomes a first-class selection input.
- `SshPool` validates connection liveness on borrow instead of trusting a possibly-dead pooled connection.
- Remote target-dir reuse + narrowed sync-back (#19): the remote cargo target-dir name is a stable key derived from `(project_root, toolchain, target)` instead of unique-per-invocation, so builds stop cold-recompiling the full dependency graph and leaving GBs of throwaway per-job target dirs; sync-back fails loud on missing artifacts.
- Watchdog stdio detach (#20): a successful build releases its SSH session immediately instead of holding it open.
- Fleet deploy guards against OS/arch binary mismatch, so a mismatched worker binary is refused rather than bricking the target.
- `cache_gc` staging walk never follows symlinks; `rch-wkr` status messages use a non-panicking stderr write.
- Hot-path performance budgets + regression suite (epic 16.7).
- CI nightly toolchain pin bumped 2025-11-01 → 2026-06-06 (#22), fixing an `ftui-widgets` E0658 that had blocked all builds/releases off `main`.

#### Representative commits

- [`11877499`](https://github.com/Dicklesworthstone/remote_compilation_helper/commit/11877499) self-healing circuit window + first-class worker priority (#21)
- [`48488480`](https://github.com/Dicklesworthstone/remote_compilation_helper/commit/48488480) reuse remote target dirs, narrow sync-back, fail loud on missing artifacts (#19)
- [`8fdff510`](https://github.com/Dicklesworthstone/remote_compilation_helper/commit/8fdff510) detach watchdog timer stdio so successful builds release the SSH session (#20)
- [`2f74d98f`](https://github.com/Dicklesworthstone/remote_compilation_helper/commit/2f74d98f) SshPool validates connection liveness on borrow
- [`69a7ac24`](https://github.com/Dicklesworthstone/remote_compilation_helper/commit/69a7ac24) bump pinned nightly 2025-11-01 → 2026-06-06 (#22)

## [v1.0.41] -- 2026-06-08 (release)

### Added

- **Autonomous worker-side stale-target reaper (default-OFF).** `rchd` gains an
  optional periodic background sweep that SSHes each healthy worker every
  `interval_mins` (default 120) and reaps abandoned per-job `.rch-target-*-job-*`
  / `.rch-target-*-pid-*` dirs idle >`idle_hours` (default 12h) across **all**
  repos under the worker's canonical project root — closing the gap where the
  orchestrator hook only ever reaps the single repo currently being built (the
  ~1.6 TB-across-the-fleet accumulation). Shares one predicate with the hook
  reaper (`rch_common::stale_target_reap`) so the two cannot drift. Depth-robust
  (`find -maxdepth 8 -prune`, catches nested workspace members), canonicalizes a
  symlinked base, and re-asserts a ≥2-path-segment guard on the resolved root.
  **Ships default-OFF** (this is an autonomous periodic deleter targeting
  `/data/projects`); enable per-host with `RCH_WORKER_REAP_ENABLE=1` or
  `[stale_target_reap] enabled = true`, disable with `RCH_WORKER_REAP_DISABLE=1`.

### Changed

- **Orchestrator hook reaper reverted to cheap current-project-only.** With the
  daemon now handling cross-repo GC, the hook reaper no longer does a full
  `find` over the canonical root on every build dispatch (the v1.0.38/39
  behavior) — it again sweeps only the just-built repo's sibling per-job dirs via
  a `cd`-based glob (which also follows a symlinked project dir natively). This
  removes the per-dispatch full-tree walk.

### Fixes

- **`rch daemon restart` now cycles a systemd-managed rchd.** On hosts where
  rchd runs as a systemd `--user` (or system) unit, the old socket-shutdown +
  spawn path could not restart the unit (systemd respawned the old on-disk
  image; the manual spawn deferred to systemd and exited), leaving a stale
  binary running. `rch daemon restart` now detects a systemd-managed rchd and
  restarts via `systemctl [--user] restart rchd`, falling back to the manual
  path for user-launched daemons and macOS launchd.
- **`rch update` retries transient download/checksum failures.** GitHub
  `502/503/504`/`429` and request timeouts on the release asset or its `.sha256`
  sidecar are now retried with bounded backoff (4 attempts, 2s/5s/15s) instead
  of aborting (the "Checksum not found" symptom was a 504 on the sidecar). A
  genuine checksum **mismatch** (corruption) and a `404` (asset absent) remain
  hard failures.

---

## [v1.0.40] -- 2026-06-08 (release)

### Fixes

- **`rch exec` reaps the whole test process group at the runtime cap.** Killing
  only the direct child left grandchildren (test servers, fixtures) orphaned —
  observed as 20-45h orphan trees pinning worker resources. The cap now reaps the
  entire process group. (Also tightens `rchd` cache-cleanup and cancellation
  handling.)

---

## [v1.0.39] -- 2026-06-08 (release)

### Fixes

- **Stale-target reaper now works when the canonical root is a symlink on the
  worker.** v1.0.38 rooted the sweep at the orchestrator's `canonical_root`, but
  on a real worker that path is frequently a symlink (the macOS orchestrator
  passes `/Users/<u>/projects`, which is a symlink to `/data/projects` on the
  worker) and `find <symlink>` does not descend the target without `-L`. The
  reaper was therefore a silent no-op for builds dispatched from such an
  orchestrator (found by live canary testing). The generated reap script now
  canonicalizes the root and the live-dir path at runtime (`cd … && pwd -P`)
  before walking, so `find` traverses the real tree and the live-dir exclusion
  still matches the physical paths `find` emits. `-L` is deliberately *not* used
  (following arbitrary in-tree symlinks during a root-owned delete sweep is
  unsafe). A defense-in-depth check re-asserts the ≥2-path-segment invariant on
  the *resolved* root before any `find`/`rm`.

---

## [v1.0.38] -- 2026-06-08 (release)

### Fixes

- **Stale-target reaper now sweeps every project under the canonical root.**
  The reaper (added in v1.0.34) only ever swept the *current* build's project
  directory, so once a project stopped dispatching builds its abandoned per-job
  `.rch-target-<host>-job-*` dirs were never revisited and accumulated forever
  (observed: 72 dirs / 332G on a single worker). It now roots its sweep at the
  same `canonical_root` (`/data/projects`) where per-job dirs are actually
  created, using a depth-robust `find -maxdepth 8 -type d -name
  '.rch-target-*-job-*' -o -name '.rch-target-*-pid-*' -prune` that matches
  top-level repos, canonical `<id>/<hash>` layouts, and nested workspace members
  alike (the old fixed-depth `*/*/` glob silently missed both 1-level and
  3+-level dirs). The `is_safe_reap_path` guard, the >12h newest-descendant idle
  check (no `-type f`, so a freshly `mkdir`'d concurrent build survives — the
  v1.0.35 race fix), and full-path exclusion of the live job dir are all
  preserved; the live dir is excluded by exact path and a fresh project's dirs
  are protected by the idle check.

- **Isolated CARGO_HOME staging honors `TMPDIR`.** Per-job cargo-home dirs were
  hardcoded under `/tmp` (`/tmp/rch-cargo-home-*`), which eats RAM on workers
  with a tmpfs `/tmp`. The base is now resolved on the worker at execution time
  to `$TMPDIR` (if a real directory) → `/data/tmp` (if present) → `/tmp`. The
  `rch-cargo-home-` basename prefix is unchanged so external cleanup (sbh) still
  matches, and the resolution is done in shell with all values double-quoted, so
  a hostile `$TMPDIR` cannot inject. (rchd under systemd does not inherit PAM's
  `/etc/environment`, so the resolution is explicit rather than relying on the
  daemon's inherited env.)

---

## [v1.0.37] -- 2026-06-02 (release)

### Fixes

- **rchd: enforce a single instance via systemd cgroup detection** to stop
  orphan/duplicate daemons (no-op on macOS / non-unit hosts).

---

## [v1.0.36] -- 2026-06-02 (release)

### Fixes

- **rch-common: pin a finite ControlPersist** to stop the SSH control-master
  leak (leaked masters + telemetry gap). Corrects the `control_persist_idle`
  documentation accordingly.

---

## [v1.0.35] -- 2026-05-30 (release)

### Fixes

- **Stale-target reaper: don't reap a just-created sibling.** The reaper's
  recency check used `find -type f`, which finds nothing in a per-job dir that
  a *concurrent* build has just `mkdir`'d but not yet written a file into — so it
  could delete an active build's target dir (the build then fails and must
  retry). The check now considers the directory itself and any descendant
  (`find <dir> -mmin -N`), so a freshly-created dir is kept by its own recent
  mtime while genuinely-abandoned dirs are still reaped. Also corrected the
  reaper's doc comments (it does not assert per-job dirs are "reused", and the
  call awaits a quick SSH dispatch rather than adding zero latency).

---

## [v1.0.34] -- 2026-05-30 (release)

### Worker disk hygiene

- **Reap abandoned per-job remote target directories.** Forwarded-`CARGO_TARGET_DIR`
  builds get a per-job target dir on the worker
  (`.rch-target-<worker>-job-<id>-<ts>-<seq>`) that rch previously never cleaned
  up, so they accumulated until worker disks filled (observed on a worker whose
  single btrfs root hit 100% from ~600G of stale per-job dirs). After each sync,
  rch now opportunistically removes sibling per-job dirs on the chosen worker
  whose **newest file is older than an idle threshold** (default **12h**,
  overridable via `RCH_STALE_TARGET_REAP_HOURS`, floored at 1h). Because per-job
  dirs are *reused* across an agent's edit-compile-fix loop, the reaper keys on
  recent file activity so an in-progress incremental cache is always preserved —
  it never clips a live build or races a concurrent build on the same project,
  even with multiple agents building it on the same worker. The removal is
  detached on the worker and best-effort, so it adds no latency to the build.
  Inputs are charset-guarded before being embedded in the remote reap script.

---

## [v1.0.33] -- 2026-05-29 (release)

### Restart-storm eradication and release-pipeline unblocking

A systemd interaction bug had been silently restart-storming rchd on four Linux controllers
(28k–34k restarts observed) while flooding the Mac controller's log capture at 2.1 GB/day,
and in parallel the GitHub Actions release workflow had been failing for three consecutive
tag attempts (v1.0.29–v1.0.31 all 24h-timed-out). This version fixes both the daemon-level
bug and the CI pipeline that ships it.

#### Delivered capability

- `rchd::bind_daemon_socket` waits for the current socket owner to free it under systemd (`INVOCATION_ID` set) instead of exiting 1 and triggering `Restart=always` storms; standalone invocations keep fail-fast behavior.
- `rch::doctor::spawn_rchd` self-heal prefers `systemctl --user start rchd.service` (idempotent) over nohup-spawning a competing detached daemon that could permanently seize the socket.
- Telemetry poller's per-worker SSH connect/disconnect lines demoted from INFO to `debug!`, plus a log retention cap (`RCH_LOG_MAX_FILES`, default 7) — ends the 8.3M-line/day log flood.
- `sd_notify` (`Type=notify` readiness, `READY=1` + `STATUS=`) so `systemctl status` shows why a waiting rchd looks idle; `wait_for_socket` probes for a live listener instead of stat-ing the path.
- CI: pinned `RUSTUP_TOOLCHAIN` (the "can't find crate for `core`" failure that had silently broken every release build since v1.0.29), patched `/dp/` path deps on SIP-protected macOS runners, and dropped the broken Windows build and the runner-starved macOS x86_64 job from `publish.needs`.

#### Representative commits

- [`23c2e40e`](https://github.com/Dicklesworthstone/remote_compilation_helper/commit/23c2e40e) systemd wait-for-owner + prefer `systemctl start` over nohup-spawn; INFO→debug log demotion + retention cap
- [`96aeb2cb`](https://github.com/Dicklesworthstone/remote_compilation_helper/commit/96aeb2cb) retry on transient bind errors; testable `bind_daemon_socket_with_mode` split
- [`31ab11e3`](https://github.com/Dicklesworthstone/remote_compilation_helper/commit/31ab11e3) `sd_notify` readiness + `wait_for_socket` probes a live listener
- [`9349e275`](https://github.com/Dicklesworthstone/remote_compilation_helper/commit/9349e275) pin `RUSTUP_TOOLCHAIN` — fixes the stdlib-shadowing bug behind three timed-out releases
- [`e3b45d4d`](https://github.com/Dicklesworthstone/remote_compilation_helper/commit/e3b45d4d) drop the broken Windows build and runner-starved macOS x86_64 from `publish.needs`

There is no `v1.0.32` tag.

## [v1.0.31] -- 2026-05-26 (release)

One-commit tuning fix closing the telemetry-poller saga (see v1.0.28–v1.0.30): v1.0.30 made
every poll cycle refresh all workers, but freshness reads still dipped because
`skip_after=60s` plus a 30 s tick pushed the effective re-poll interval to ~90 s — exactly
the pressure layer's telemetry-stale threshold, so workers raced in and out of "fresh".
[`848e0539`](https://github.com/Dicklesworthstone/remote_compilation_helper/commit/848e0539)
drops `skip_after` to 30 s (effective ~60 s re-poll).

## [v1.0.30] -- 2026-05-26 (release)

One-commit fix making the telemetry poller resilient to SSH contention: fleet telemetry
freshness fluctuated because concurrent SSH load from other daemon subsystems caused
intermittent re-poll failures.
[`3e483741`](https://github.com/Dicklesworthstone/remote_compilation_helper/commit/3e483741)
adds a one-shot retry with backoff per poll attempt, a per-cycle INFO-level "refreshed N/M"
summary, and `MissedTickBehavior::Skip` so a long cycle cannot fire a burst of back-to-back
cycles. Validated 8/8 workers refreshed with 0 failures over ~4.5 minutes.

## [v1.0.29] -- 2026-05-26 (release)

One-commit fix for permit starvation introduced by v1.0.28's semaphore: a poll whose SSH
hung past the (not-always-honored) `ssh_timeout` held its concurrency permit indefinitely;
on a 9-worker fleet ~4 stuck polls exhausted all 4 permits and silently collapsed freshness
to 1/9 workers.
[`f1d07625`](https://github.com/Dicklesworthstone/remote_compilation_helper/commit/f1d07625)
wraps each poll in a hard `tokio::time::timeout(ssh_timeout + 5s)` and raises
`MAX_CONCURRENT_TELEMETRY_POLLS` 4 → 16.

## [v1.0.28] -- 2026-05-26 (release)

One-commit fix for the telemetry poller starving worker selection: the poller held a
`worker.config` read-lock across the entire SSH round-trip and fanned out one unbounded poll
per worker per tick, producing multi-second "worker_selection latency exceeded panic
threshold" stalls (5–20 s against a 50 ms budget).
[`ab23b1ef`](https://github.com/Dicklesworthstone/remote_compilation_helper/commit/ab23b1ef)
snapshots the worker config and releases the lock before SSH work, and bounds concurrent SSH
polls with a 4-permit semaphore.

## [v1.0.27] -- 2026-05-25 (release)

### Fleet-reliability hardening and worker-topology correctness

57 commits (2026-05-15 → 05-19) closing three parallel workstreams: canonical
worker-filesystem-topology validation, the reliability/telemetry reporting pipeline that
later fed the v1.0.28–v1.0.31 poller fixes, and a security-hardening pass across
shell-command construction sites. Also delivers the `RCH_*_INJECT_*` test-fixture registry
and two new `rch doctor`/`rch workers` subcommands.

#### Delivered capability

- `path_topology` alias verification widened to accept `AliasSubtreeSymlinkVerified` (alias points at a subtree of the canonical root) and `AliasDirectoryEntryVerified` (alias is a real directory containing symlinks into the canonical root), plus hook fail-closed behavior and a worker-probe refactor.
- `rch doctor --runbook <code>` and `--runbook-list`: static Markdown incident runbooks per `RCH-Rnnn` reliability code.
- `rch workers benchmark [WORKER_ID] [--all] [--force]` and `rch workers compare`, completing the SpeedScore display/management commands.
- `RCH_*_INJECT_*` env-var registry (`rch-common/src/testing/injection.rs`): one source of truth for debug/test injection variables, so a typo becomes a compile error instead of a silent no-op.
- Reliability-pipeline correctness: admission verdicts wired into pressure debt, side-effect-free reliability scoring, command exits excluded from worker circuit health, selector-rejection diagnostics surfaced, affinity fallback requires slots, rchd reports only assignable free slots.
- Remediation-reporting fixes: correct `telemetry_gap` fix strings across `rch check`/`rch status`/RCH-R104 (issue #16 — none of the three prior directives actually refreshed telemetry).
- Security hardening across worker-deploy shell commands, hook settings mutation, queue-display/test-log paths, topology/transfer/selector diagnostics quoting, rsync filter escaping, and catch-all-artifact source guards.
- Update/lock hardening: tokenized lock-file parsing; the lock file is only removed on `Drop` if its body still matches what the guard wrote.
- Docs: `SKILL.md`/`HOOKS.md`/`TROUBLESHOOTING.md`/`WORKERS.md` rewritten around `rch doctor` as the entry point; `diagnose-rch.sh` removed.

#### Closed workstreams

- [`remote_compilation_helper-62u24.13`](https://github.com/Dicklesworthstone/remote_compilation_helper/blob/main/.beads/issues.jsonl) Test fixtures foundation: `RCH_*_INJECT_*` registry + `rch debug` + request_id propagation
- [`remote_compilation_helper-62u24.20`](https://github.com/Dicklesworthstone/remote_compilation_helper/blob/main/.beads/issues.jsonl) `rch doctor --runbook <code>`: Markdown runbook generation
- [`remote_compilation_helper-ifq7s`](https://github.com/Dicklesworthstone/remote_compilation_helper/blob/main/.beads/issues.jsonl) `rch workers benchmark <id>` + `rch workers compare`
- [`remote_compilation_helper-28o9b`](https://github.com/Dicklesworthstone/remote_compilation_helper/blob/main/.beads/issues.jsonl) Hook topology preflight diagnostics name exact alias paths

#### Representative commits

- [`c98b0afd`](https://github.com/Dicklesworthstone/remote_compilation_helper/commit/c98b0afd) path-topology alias-subtree/alias-directory verification + hook fail-closed
- [`a934d75e`](https://github.com/Dicklesworthstone/remote_compilation_helper/commit/a934d75e) `RCH_*_INJECT_*` env-var registry
- [`e7eaa647`](https://github.com/Dicklesworthstone/remote_compilation_helper/commit/e7eaa647) `rch doctor --runbook`/`--runbook-list`
- [`078ae817`](https://github.com/Dicklesworthstone/remote_compilation_helper/commit/078ae817) `rch workers benchmark`/`compare`
- [`9e298bf7`](https://github.com/Dicklesworthstone/remote_compilation_helper/commit/9e298bf7) fix `telemetry_gap` remediation strings (#16)
- [`aaa8a6cd`](https://github.com/Dicklesworthstone/remote_compilation_helper/commit/aaa8a6cd) skill docs rewritten around `rch doctor`

## [v1.0.26] -- 2026-05-14 (release)

Same-day one-commit follow-up to v1.0.25:
[`25848a02`](https://github.com/Dicklesworthstone/remote_compilation_helper/commit/25848a02)
adds an `upgrade` alias for the release/upgrade helper.

## [v1.0.25] -- 2026-05-14 (release)

### Dependency and release maintenance

- Switched local-owner libraries to the current `/dp` checkouts: FrankenTUI
  crates now resolve from `/dp/frankentui`, TOON resolves from
  `/dp/toon_rust`, and `rich_rust` resolves from `/dp/rich_rust`.
- Refreshed Rust direct dependencies and lockfile, including `reqwest`,
  `sha2`, `hmac`, `rusqlite`, `proptest`, `insta`, `terminal_size`,
  `whoami`, `fastrand`, and security-sensitive transitive TLS crates.
- Removed the `rich_rust/full` feature from RCH's default rich UI path,
  dropping unmaintained `syntect` transitive dependencies that were not
  needed by the codebase.
- Updated the web dashboard dependency stack to current compatible releases
  and added a `postcss` override so `npm audit` remains clean while Next.js
  ships its pinned nested dependency.
- Hardened the release workflow so all release and publish jobs recreate the
  `/dp` local dependency layout, including Windows builds and crates.io dry
  runs.

---

## [v1.0.24] -- 2026-04-29 (release)

Single-commit release.
[`ce4b0029`](https://github.com/Dicklesworthstone/remote_compilation_helper/commit/ce4b0029)
fixes `find_local_binary()` in `rch/src/fleet/mod.rs` so `rch fleet deploy` prefers a
properly installed `rch-wkr` (resolved via `which`, home dir, or the current-exe directory)
over whatever happens to sit in a dev `target/{release,debug}` or `CARGO_TARGET_DIR`, so a
stale or mismatched dev build no longer gets pushed to fleet workers. The commit also
carries an incidental `.beads/issues.jsonl` id-format normalization — a tracker-sync side
effect, not a product change.

## [v1.0.23] -- 2026-04-29 (release)

Three-commit release closing out the day's deploy-hardening push.

- [`8fdd6d06`](https://github.com/Dicklesworthstone/remote_compilation_helper/commit/8fdd6d06) `rch doctor` no longer panics on a broken pipe: stdout writes go through a `write_stdout` wrapper so piping the report into `head` is normal Unix behavior instead of a crash.
- [`72bcbfd3`](https://github.com/Dicklesworthstone/remote_compilation_helper/commit/72bcbfd3) `copy_binary_via_scp` uploads to a per-deploy staging path and renames into place instead of SCP-ing straight onto `~/.local/bin/rch-wkr` — a direct overwrite could fail or corrupt the binary while the worker was executing it.
- [`bca70f48`](https://github.com/Dicklesworthstone/remote_compilation_helper/commit/bca70f48) `install.sh` installs binaries via `install -m 755` into `${dest}.tmp.$$` then `mv -f`, so re-running the installer against a live `rchd`/`rch-wkr` doesn't `ETXTBSY` or truncate a running executable.

## [v1.0.22] -- 2026-04-29 (release)

- [`83606e72`](https://github.com/Dicklesworthstone/remote_compilation_helper/commit/83606e72) `send_daemon_command` gains a 3 s connect timeout and 10 s I/O timeout plus explicit half-close around the daemon Unix-socket protocol, so a CLI invocation can no longer hang indefinitely if `rchd` never responds.
- [`17eaeacc`](https://github.com/Dicklesworthstone/remote_compilation_helper/commit/17eaeacc) release workflow concurrency group scoped per-tag instead of one global `release` group (a stale queued run for one tag could block every subsequent release); the `cargo publish -p rch-common` step checks crates.io directly for an already-published version.
- [`8a036ead`](https://github.com/Dicklesworthstone/remote_compilation_helper/commit/8a036ead) version bump.

## [v1.0.21] -- 2026-04-29 (release)

Two commits: a version bump plus
[`f71aa7d3`](https://github.com/Dicklesworthstone/remote_compilation_helper/commit/f71aa7d3),
which adds `--safe-links` to the new `build_retrieve_streaming_command()` rsync invocation so
streamed artifact retrieval preserves the symlink-safety semantics the streaming path had
dropped relative to the non-streaming command.

## [v1.0.20] -- 2026-04-29 (release)

### CARGO_TARGET_DIR round-tripping and installer resilience

Two problems surfaced from real remote-build usage: `rch exec` silently dropped custom Cargo
target directories when running builds on a worker, and the installer had a hardcoded
`/tmp/rch` runtime directory that could collide with a stale non-directory left behind by
another tool.

#### Delivered capability

- `rch exec` maps a local `--target-dir`/`CARGO_TARGET_DIR` to a worker-scoped `.rch-target`, strips the local target-dir setting before shipping the command remotely, and syncs `.rch-target` back to the requested local path on completion — so two projects with different target dirs no longer clobber each other's artifacts on the same worker.
- `[path_topology]` TOML config is wired end-to-end: `PartialRchConfig` gained the field (serde had silently dropped the whole section), `apply_layer` merges it, and `rch config get/show/validate` recognize the keys (closes #10). Two follow-ups make empty-string handling consistent (`RCH_CANONICAL_PROJECT_ROOT=""` is "unset" in `rch config get/show` and in `merge_config`).
- `install.sh` accepts a custom runtime directory and recovers instead of aborting when `/tmp/rch` already exists as a non-directory.

#### Representative commits

- [`13bc7498`](https://github.com/Dicklesworthstone/remote_compilation_helper/commit/13bc7498) CARGO_TARGET_DIR sync: worker-scoped `.rch-target` mapping, strip-then-restore around remote exec
- [`41eb319c`](https://github.com/Dicklesworthstone/remote_compilation_helper/commit/41eb319c) gates the target-dir sync on cargo command kind
- [`62a823d2`](https://github.com/Dicklesworthstone/remote_compilation_helper/commit/62a823d2) wires `path_topology` through the TOML parser and `rch config` (closes #10)
- [`ada30198`](https://github.com/Dicklesworthstone/remote_compilation_helper/commit/ada30198) / [`87ed33a4`](https://github.com/Dicklesworthstone/remote_compilation_helper/commit/87ed33a4) empty-string audit gap on the CLI-read and config-merge sides
- [`be12fde1`](https://github.com/Dicklesworthstone/remote_compilation_helper/commit/be12fde1) installer survives a `/tmp/rch` path collision

## [v1.0.19] -- 2026-04-23 (release)

### Audit-pass hardening sweep

40 commits, almost entirely from a self-directed correctness/safety audit plus five
new-capability beads closed the same evening (2026-04-22). The audit fixes share a pattern —
subtle concurrency races, unsafe string/byte slicing, permissive matchers, and resource
leaks that had shipped quietly and would only surface under load or on specific platforms.
The fleet-lock bug was traced to "Worker self-test failed" errors recurring across 30+
concurrent-agent sessions.

#### Delivered capability

- Structured error codes on worker probes: `WorkerProbeResult` gained `error_code` mapped from the RCH-Exxx catalog, plumbed through the probe path and surfaced in summaries, plus an interactive-TTY hint when `rch` is invoked bare.
- Per-fleet cooperative lock: `rch fleet {deploy,rollback,drain}` take a per-fleet lock, closing a race where two concurrent invocations (e.g. separate agent panes) could interleave systemd unit writes, binary swaps, and drain/undrain sequencing.
- Alert lifecycle + cleared-retention window: circuit-breaker alerts that self-heal no longer stay pinned on `rch status` indefinitely.
- Config diagnostics + `identity_file` env expansion: `rch workers list`/config validation aggregate missing-key diagnostics and expand env vars in `identity_file`, so a typo'd key path is caught at config time instead of at first probe failure.
- Self-test outer timeout budget: `rch self-test --all` enforces a real per-worker total timeout; previously a worker failing 3 retries could consume `3 × timeout + 2 × retry_delay` before being classified as timed out.
- Concurrency and resource-leak fixes: atomic rate-limit check+insert in `BenchmarkQueue::enqueue`; `kill_on_drop` + concurrent pipe drain on every timeout-wrapped subprocess spawn (fixing a >64 KB `cargo metadata` deadlock and a leaked-child bug); single `write_all` per line for concurrent O_APPEND JSONL writers; `O_CREAT|O_EXCL` lock acquisition for the update lock; `saturating_duration_since` replacing `Instant::now() - window` to stop a fresh-boot panic.
- Safety/correctness: shell-safe argv reassembly via `shell_words::join` for `rch exec -- …`; reject unsafe worker IDs and shell-escape IDs in remote commands; refuse slot reservations on draining/drained/disabled workers; clamp Rolling `batch_size`/AllAtOnce parallelism to avoid divide-by-zero; anchored/basename matchers replace three permissive substring matchers; no byte-indexed string slicing in display/parse paths; anchored `cleanup_old_backups` prefix matching; whole-disk vs partition classification across Linux naming schemes; true-median on even-length latency samples and a benchmark-score scaling no-op.

#### Closed workstreams

- [`remote_compilation_helper-5z2wa`](https://github.com/Dicklesworthstone/remote_compilation_helper/blob/main/.beads/issues.jsonl) rch fleet deploy: per-fleet cooperative lock
- [`remote_compilation_helper-3ogaz`](https://github.com/Dicklesworthstone/remote_compilation_helper/blob/main/.beads/issues.jsonl) rch status: auto-clear or grey-out stale circuit-breaker alerts
- [`remote_compilation_helper-hke4t`](https://github.com/Dicklesworthstone/remote_compilation_helper/blob/main/.beads/issues.jsonl) rch config validate: check identity_file existence + permissions
- [`remote_compilation_helper-nhrjr`](https://github.com/Dicklesworthstone/remote_compilation_helper/blob/main/.beads/issues.jsonl) RCH-E100 doesn't distinguish key-missing from host-down from auth-refused
- [`remote_compilation_helper-nuuqt`](https://github.com/Dicklesworthstone/remote_compilation_helper/blob/main/.beads/issues.jsonl) rch self-test: enforce upper-bound timeout per worker

#### Representative commits

- [`894d13fd`](https://github.com/Dicklesworthstone/remote_compilation_helper/commit/894d13fd) per-fleet cooperative lock for deploy/rollback/drain
- [`9cb7f6d6`](https://github.com/Dicklesworthstone/remote_compilation_helper/commit/9cb7f6d6) alert lifecycle states + cleared-retention window
- [`1ae6af4f`](https://github.com/Dicklesworthstone/remote_compilation_helper/commit/1ae6af4f) structured RCH-Exxx `error_code` on worker probes
- [`3087a4e4`](https://github.com/Dicklesworthstone/remote_compilation_helper/commit/3087a4e4) `rch self-test --all` gets a real outer per-worker timeout
- [`81467ba8`](https://github.com/Dicklesworthstone/remote_compilation_helper/commit/81467ba8) `kill_on_drop` + concurrent pipe drain on every timeout-wrapped subprocess spawn
- [`dfefbfeb`](https://github.com/Dicklesworthstone/remote_compilation_helper/commit/dfefbfeb) anchored/basename equality replaces three permissive substring matchers

## [v1.0.18] -- 2026-04-16 (tag only)

### Diagnose + path topology bug fixes

- `rch diagnose` and the `rch exec` post-hook entry point now honor the
  configured `[path_topology]` section when normalizing the project path.
  Previously both call sites used the compiled-in `/data/projects` + `/dp`
  defaults even when operators had set `canonical_root` / `alias_root` in
  `config.toml`, producing a spurious warning:
  `Project path normalization failed for ...: canonical root is missing
  (input: ..., detail: missing root /data/projects)`. Closes
  [#9](https://github.com/Dicklesworthstone/remote_compilation_helper/issues/9).
  ([24580cd](https://github.com/Dicklesworthstone/remote_compilation_helper/commit/24580cdf))

---

## [v1.0.17] -- 2026-04-01 (release)

Nightly toolchain verification release. Unpins the nightly toolchain to the
rolling latest, forwards `CARGO_TARGET_DIR` through delegated commands,
expands path-dependency resolution to enclosing workspace roots, and switches
documentation examples to `${TMPDIR:-/tmp}` instead of hardcoded `/tmp`.

---

## [v1.0.16] -- 2026-03-23 **(release)**

### Worker scheduling safety

- Prevent concurrent builds for the same project from landing on the same worker checkout. The daemon now excludes workers already active for that project and uses an atomic active-build claim after slot reservation to close the last same-project race in worker selection. ([fbea95f](https://github.com/Dicklesworthstone/remote_compilation_helper/commit/fbea95f7b65903859a3e81f7f01d9ced28ac7ee2))

### Dependency maintenance

- Update dependencies to resolve security advisories. ([1548842](https://github.com/Dicklesworthstone/remote_compilation_helper/commit/154884291146b73177c122e1856c0d287767ef50))

### Configurable path topology

- New `[path_topology]` config section allows operators to define custom project root directories instead of hardcoded `/data/projects` and `/dp` conventions. All project-hash call sites now respect the configured policy. ([87b8bc6](https://github.com/Dicklesworthstone/remote_compilation_helper/commit/87b8bc6cdce9036b3f61877c9bffdb2b4e413eaa), [a04737f](https://github.com/Dicklesworthstone/remote_compilation_helper/commit/a04737f7a1a78c0eafe76feb0bfcf386d9dc34aa))

### Hook system expansion

- Major expansion of the hook lifecycle: additional compilation event handling, improved orchestration, and expanded compilation config types in the transfer pipeline. ([698422c](https://github.com/Dicklesworthstone/remote_compilation_helper/commit/698422cbe71ab0a2fcaf9720e6abe6b0ab3a532e), [a92c452](https://github.com/Dicklesworthstone/remote_compilation_helper/commit/a92c4528d730d24765d009db3e6f59f0c0987b02), [eb516a4](https://github.com/Dicklesworthstone/remote_compilation_helper/commit/eb516a4a299ce772c3f0c19b6e02a13f52c1d203), [aed2477](https://github.com/Dicklesworthstone/remote_compilation_helper/commit/aed247792bda9e83c33d8f75a5ccba8181b5635c), [e713602](https://github.com/Dicklesworthstone/remote_compilation_helper/commit/e7136026e69cfe85905dc189d87dc2bb97f3ff86))

---

## [v1.0.15] -- 2026-03-23

Superseded tag-only version bump. `v1.0.16` carries the same release content with the corrected lockfile version metadata.

---

## [v1.0.14] -- 2026-03-23

Superseded tag-only version bump. `v1.0.15` carries the same release content with the corrected lockfile version metadata.

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

## Notes for Agents

- Start with the [Version Timeline](#version-timeline) for chronology and the release-vs-tag
  distinction; the installer and the fleet's nightly updater only ever serve **Releases**.
- Jump into a version section for what actually landed: `Delivered capability` names the
  behavior, `Closed workstreams` gives the intent (search `.beads/issues.jsonl` for the id),
  `Representative commits` are the diffs to read first.
- The two subsystems most worth knowing before touching code: the reliability/remediation
  stack (`v1.0.11` → `v1.0.45`, epics `bd-vvmd` and `bd-session-history-remediation-ocv9i`)
  and RABS (`v1.0.57` → `v1.0.58`, epics `remote_compilation_helper-rabs-root-4pidu.*`).
- Shim versions matter operationally: shim v2 (`v1.0.59`) and v3 (`v1.0.60`) both require
  `rch shim install` after upgrading; `rch shim status` reports staleness.
- Three tags are not what they look like: `v1.0.50` is an unpublished draft, `v1.0.58` has no
  release at all, and `v1.0.32`/`v1.0.48` were never cut.
- Everything below `v1.0.16` in the reference block uses compare links; newer versions link
  straight to their release or tag page in the timeline.

[Unreleased]: https://github.com/Dicklesworthstone/remote_compilation_helper/compare/v1.0.62...HEAD
[v1.0.62]: https://github.com/Dicklesworthstone/remote_compilation_helper/compare/v1.0.61...v1.0.62
[v1.0.16]: https://github.com/Dicklesworthstone/remote_compilation_helper/compare/v1.0.15...v1.0.16
[v1.0.15]: https://github.com/Dicklesworthstone/remote_compilation_helper/compare/v1.0.14...v1.0.15
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
[v1.0.17]: https://github.com/Dicklesworthstone/remote_compilation_helper/compare/v1.0.16...v1.0.17
[v1.0.18]: https://github.com/Dicklesworthstone/remote_compilation_helper/compare/v1.0.17...v1.0.18
[v1.0.19]: https://github.com/Dicklesworthstone/remote_compilation_helper/compare/v1.0.18...v1.0.19
[v1.0.20]: https://github.com/Dicklesworthstone/remote_compilation_helper/compare/v1.0.19...v1.0.20
[v1.0.21]: https://github.com/Dicklesworthstone/remote_compilation_helper/compare/v1.0.20...v1.0.21
[v1.0.22]: https://github.com/Dicklesworthstone/remote_compilation_helper/compare/v1.0.21...v1.0.22
[v1.0.23]: https://github.com/Dicklesworthstone/remote_compilation_helper/compare/v1.0.22...v1.0.23
[v1.0.24]: https://github.com/Dicklesworthstone/remote_compilation_helper/compare/v1.0.23...v1.0.24
[v1.0.25]: https://github.com/Dicklesworthstone/remote_compilation_helper/compare/v1.0.24...v1.0.25
[v1.0.26]: https://github.com/Dicklesworthstone/remote_compilation_helper/compare/v1.0.25...v1.0.26
[v1.0.27]: https://github.com/Dicklesworthstone/remote_compilation_helper/compare/v1.0.26...v1.0.27
[v1.0.28]: https://github.com/Dicklesworthstone/remote_compilation_helper/compare/v1.0.27...v1.0.28
[v1.0.29]: https://github.com/Dicklesworthstone/remote_compilation_helper/compare/v1.0.28...v1.0.29
[v1.0.30]: https://github.com/Dicklesworthstone/remote_compilation_helper/compare/v1.0.29...v1.0.30
[v1.0.31]: https://github.com/Dicklesworthstone/remote_compilation_helper/compare/v1.0.30...v1.0.31
[v1.0.33]: https://github.com/Dicklesworthstone/remote_compilation_helper/compare/v1.0.31...v1.0.33
[v1.0.34]: https://github.com/Dicklesworthstone/remote_compilation_helper/compare/v1.0.33...v1.0.34
[v1.0.35]: https://github.com/Dicklesworthstone/remote_compilation_helper/compare/v1.0.34...v1.0.35
[v1.0.36]: https://github.com/Dicklesworthstone/remote_compilation_helper/compare/v1.0.35...v1.0.36
[v1.0.37]: https://github.com/Dicklesworthstone/remote_compilation_helper/compare/v1.0.36...v1.0.37
[v1.0.38]: https://github.com/Dicklesworthstone/remote_compilation_helper/compare/v1.0.37...v1.0.38
[v1.0.39]: https://github.com/Dicklesworthstone/remote_compilation_helper/compare/v1.0.38...v1.0.39
[v1.0.40]: https://github.com/Dicklesworthstone/remote_compilation_helper/compare/v1.0.39...v1.0.40
[v1.0.41]: https://github.com/Dicklesworthstone/remote_compilation_helper/compare/v1.0.40...v1.0.41
[v1.0.42]: https://github.com/Dicklesworthstone/remote_compilation_helper/compare/v1.0.41...v1.0.42
[v1.0.43]: https://github.com/Dicklesworthstone/remote_compilation_helper/compare/v1.0.42...v1.0.43
[v1.0.44]: https://github.com/Dicklesworthstone/remote_compilation_helper/compare/v1.0.43...v1.0.44
[v1.0.45]: https://github.com/Dicklesworthstone/remote_compilation_helper/compare/v1.0.44...v1.0.45
[v1.0.46]: https://github.com/Dicklesworthstone/remote_compilation_helper/compare/v1.0.45...v1.0.46
[v1.0.47]: https://github.com/Dicklesworthstone/remote_compilation_helper/compare/v1.0.46...v1.0.47
[v1.0.49]: https://github.com/Dicklesworthstone/remote_compilation_helper/compare/v1.0.47...v1.0.49
[v1.0.50]: https://github.com/Dicklesworthstone/remote_compilation_helper/compare/v1.0.49...v1.0.50
[v1.0.51]: https://github.com/Dicklesworthstone/remote_compilation_helper/compare/v1.0.50...v1.0.51
[v1.0.52]: https://github.com/Dicklesworthstone/remote_compilation_helper/compare/v1.0.51...v1.0.52
[v1.0.53]: https://github.com/Dicklesworthstone/remote_compilation_helper/compare/v1.0.52...v1.0.53
[v1.0.54]: https://github.com/Dicklesworthstone/remote_compilation_helper/compare/v1.0.53...v1.0.54
[v1.0.55]: https://github.com/Dicklesworthstone/remote_compilation_helper/compare/v1.0.54...v1.0.55
[v1.0.56]: https://github.com/Dicklesworthstone/remote_compilation_helper/compare/v1.0.55...v1.0.56
[v1.0.57]: https://github.com/Dicklesworthstone/remote_compilation_helper/compare/v1.0.56...v1.0.57
[v1.0.58]: https://github.com/Dicklesworthstone/remote_compilation_helper/compare/v1.0.57...v1.0.58
[v1.0.59]: https://github.com/Dicklesworthstone/remote_compilation_helper/compare/v1.0.58...v1.0.59
[v1.0.60]: https://github.com/Dicklesworthstone/remote_compilation_helper/compare/v1.0.59...v1.0.60
[v1.0.61]: https://github.com/Dicklesworthstone/remote_compilation_helper/compare/v1.0.60...v1.0.61
