# Comprehensive Issues and Problems with RCH Based on Complete Session History Analysis

Date: 2026-06-08

Repository: `/data/projects/remote_compilation_helper`

Primary task: mine the local and remote agent session history for RCH failures, confusing behavior, infrastructure failure modes, and actual RCH design flaws. Findings are grouped by the machine whose agent session history or operational history produced the evidence.

## Scope

This pass used:

- Local `cass` session history from `/data/projects`.
- Remote `cass` and shell probes over SSH aliases `ts1`, `ts2`, `css`, `csd`.
- Tailscale SSH aliases `mac-mini-max` and `mac-mini-old`.
- The current RCH repo docs and code.
- The canonical private `$rch` skill under `/dp/je_private_skills_repo/.claude/skills/rch`.
- The `$cass`, `$sc`, and `$operationalizing-expertise` skills, mainly for the broad-query, evidence-bank, and operationalization workflow.
- Open Beads in this repo.

Important caveat: several session indexes were stale or partially unreachable. I did not treat that as a reason to skip the machine. I recorded it as an operational finding, because a stale or unreachable session index is itself relevant to debugging and fleet recovery work.

## Directly Inspected Evidence Trail

This report is mostly based on broad `cass` query matrices, but the following specific artifacts were inspected directly and shaped the conclusions:

- Local session `/home/ubuntu/.claude/projects/-data-projects/e355f62c-ae7f-4c97-bd85-fd22fb0bfc60.jsonl`: hook could not connect to daemon, local execution was allowed, daemon restart restored remote compilation, and the session reasoned toward hook/daemon/doctor self-healing.
- Local session `/home/ubuntu/.claude/projects/-data-projects-beads-rust/eccf9525-f722-40de-971e-15294cf3a464.jsonl`: socket path mismatch, local fallback, worker selected without `rustup`, manual drain/remove/re-enable flow.
- Local session `/home/ubuntu/.claude/projects/-data-projects-mcp-agent-mail-rust/effe792c-7e54-4b7b-bb21-c932be888ccf.jsonl`: stale path dependency roots, unclear force-sync path, `rsync` failure, and queue/slot ambiguity.
- Local session `/home/ubuntu/.claude/projects/-data-projects-storage-ballast-helper/9fe26b30-ae3f-4e59-a034-73ae6ab454aa.jsonl`: rewritten `CARGO_TARGET_DIR` to `.rch-target` while artifact collection searched `target/release/**`.
- mac-mini-max session `/Users/jemanuel/.claude/projects/-Users-jemanuel/6808415d-2854-4409-914c-7ed9c1513bcb.jsonl`: remote cleanup pressure, destructive-command guard intervention, expensive target-dir scans, and fleet/process remediation context.
- RCH source files: `rch-common/src/types.rs`, `rchd/src/workers.rs`, `rchd/src/config.rs`, `rchd/src/stale_target_reap.rs`, `rchd/src/selection.rs`.
- RCH docs: `docs/design/pooled-target-dirs.md`, `docs/runbooks/worker-recovery.md`, `docs/runbooks/debugging-slow-builds.md`.
- Canonical skill package: `/dp/je_private_skills_repo/.claude/skills/rch/SKILL.md` and its referenced worker, disk pressure, contention, self-healing, fail-open, and operations references.
- Open Beads in this repo, especially the P0 Darwin-controller/Linux-worker deploy issue and P1 doctor/hook reliability issues.

The broad query matrices were run locally and on every requested reachable machine. `ts2` and `mac-mini-old` could not be fully mined because SSH or `cass` access timed out.

## Executive Summary

RCH is failing in two broad classes of situations.

The first class is external fleet trouble: workers run out of disk, get overloaded, lose SSH, miss toolchains, or disappear because VMI/Contabo machines are paused or unreachable. RCH cannot prevent every one of those failures.

The second class is RCH behavior that makes those ordinary fleet failures worse. The session history repeatedly shows agents reacting to transient worker illness by draining, disabling, editing `workers.toml`, or otherwise shrinking the worker pool. Later, when the workers recover, they remain absent from the available pool until a human or agent manually remembers to re-add them. That is the core design flaw the user called out, and the history strongly confirms it.

The main RCH product gaps are:

1. RCH needs a first-class temporary bypass or quarantine state, separate from permanent admin disable.
2. RCH needs automatic diagnostic polling and auto-rejoin for temporarily bypassed workers.
3. RCH needs desired-state reconciliation: the configured fleet, live daemon state, and actually reachable workers should not silently drift apart.
4. Hook, daemon, and doctor need bidirectional self-healing instead of silent local fallback.
5. Local fallback must become loud, structured, and actionable; agents currently miss or tolerate it too easily.
6. Worker capability checks are incomplete: missing `rustup`, missing runtimes, stale worker binaries, wrong OS/arch artifacts, stale path dependencies, and wrong users/paths all appear repeatedly.
7. Disk pressure and target-dir cleanup are systemic, not incidental. RCH needs pooled target dirs, safe remote reaping, default-on stale cleanup, and artifact collection that follows the actual target dir.
8. Queue and capacity semantics are confusing: the history includes cases where a remote job appears to keep running after the CLI reports failure or "0 slots".
9. Fleet incidents such as VMI/Contabo pauses need explicit diagnosis and routing behavior, not just degraded health scores.
10. The canonical `$rch` skill and repo runbooks should be updated to teach the desired behavior and stop recommending manual permanent pool shrinkage for transient problems.

## Cross-Machine Issue Taxonomy

### P0: Worker Lifecycle Uses the Wrong Primitive

Current behavior observed in history:

- A worker fails preflight, is overloaded, lacks a toolchain, runs out of disk, or misses SSH.
- Agents drain it, disable it, or remove it from `workers.toml`.
- The immediate failure is avoided.
- The worker later recovers.
- RCH does not automatically re-admit it.
- The fleet stays smaller, causing contention, "all workers at capacity", "no workers passed health", or local fallback.

The code reinforces this. `WorkerStatus` has `Healthy`, `Degraded`, `Unreachable`, `Draining`, `Drained`, and `Disabled`. Health application preserves `Draining`, `Drained`, and `Disabled`, and reservation skips them. That is correct for permanent admin actions, but it is the wrong default response to transient failure.

Required design:

- `AdminDisabled`: explicit, persistent, human-intended removal.
- `Draining`: explicit, persistent or bounded operational drain.
- `TemporaryBypass` or `Quarantined`: automatic, reasoned, TTL/backoff based, and eligible for remote diagnostics.
- `RecoveredPendingCanary`: worker appears fixed but must pass a canary build/probe.
- `Healthy`: admitted for real work.

Temporary bypass records should include:

- Worker id and host.
- Failure class: SSH, daemon, worker binary, runtime/toolchain, disk pressure, load, path dependency sync, artifact collection, OS/arch mismatch, telemetry stale, preflight failure, or circuit breaker.
- First failure time and last failure time.
- Next probe time.
- Probe backoff.
- Consecutive pass/fail counts.
- Last diagnostic summary.
- Auto-rejoin criteria.

Auto-rejoin should require several consecutive passes, not one lucky SSH response. A good default is:

- SSH and remote shell work.
- `rch-wkr --version` matches expected protocol/version.
- Rust runtime/toolchain checks pass for the requested runtime.
- Disk and inode free thresholds pass on `/`, `/tmp`, configured cargo home, target dir root, and any RCH work root.
- Load/process pressure is below policy threshold.
- Worker telemetry is fresh.
- A small canary command succeeds through the same path real builds use.
- For Rust, a tiny cargo check or cached noop build confirms target dir and cargo home are usable.

### P0: Silent Local Fallback Lets Agents Think Work Is Verified Remotely

Local history repeatedly shows `[RCH] local` with reasons such as daemon unavailable, all workers busy, all workers failed preflight, no workers passed health, no admissible workers, and all circuits open.

Local fallback is sometimes useful, but it is currently too easy for agents to miss. In several sessions agents continued as if they had used remote compilation when the build actually ran locally.

Required behavior:

- Every fallback must print a one-line structured reason with an error code, affected workers, and one next action.
- `RCH_REQUIRE_REMOTE=1` should be recommended in skills and used by agents for proof builds.
- Hook-triggered local fallback should be obvious in the transcript and machine-readable.
- RCH should preserve exact daemon selection reason strings for unknown future reasons.
- Fallback should distinguish "all workers busy, wait/queue" from "no configured workers" from "all failed preflight" from "workers exist but are bypassed".

### P0: Hook, Daemon, and Doctor Are Not Mutually Self-Healing Enough

Local evidence shows a hook attempted to query the daemon, got `Connection refused`, and allowed local execution. The same session concluded that:

- The daemon was not running.
- The hook did not start the daemon or retry.
- `doctor --fix` did not repair hooks.
- The daemon did not verify or install hooks on start.

Required behavior:

- The hook should try to start the daemon when the daemon socket is missing or refused.
- The daemon should verify hook installation and socket path consistency on startup.
- `rch doctor --fix` must actually run remediations, not just describe them.
- `rch doctor` should verify the active shell/editor/agent hook path, daemon path, socket path, and current user.
- Socket path mismatches should be a named diagnosis, not a vague daemon failure.

### P0: Fleet Desired State Drifts Away From Live Pool

The session history shows a recurring pattern: workers are removed or bypassed during incidents, then the pool remains smaller even after the worker fleet is healthy. Remote history also has repeated "fleet restored" messages after all workers became healthy again. RCH should not require agents to remember the original desired pool.

Required behavior:

- Keep a desired-state inventory separate from the live eligible set.
- Periodically compare configured workers, daemon worker state, remote reachability, and last good check.
- Alert when a configured worker is missing from live eligibility for longer than a policy window.
- Auto-rejoin temporary bypass workers after diagnostics pass.
- Refuse to let transient failure handling mutate the permanent desired inventory unless the operator explicitly requests permanent disable.

### P0: Darwin Controller Can Push Darwin Worker Binary to Linux Workers

Open Beads include a P0 issue: `rch update --fleet` from a Darwin controller can push a Darwin `rch-wkr` binary to Linux workers, causing `Exec format error`.

Required behavior:

- Fleet update must be OS/arch aware.
- The controller must build or fetch per-target artifacts.
- Each remote deploy should verify `file`, `uname`, executable startup, and protocol handshake.
- Mixed Darwin/Linux fleets should be a first-class test case.

### P1: Path Dependency and Repo Convergence Sync Is Fragile

Local session evidence from `mcp_agent_mail_rust` shows remote workers with stale path dependencies. The local checkout had a method such as `clear_idle`, while remote dependency roots did not. Attempts to force sync were unclear, and the pipeline reported syncing roots without detecting the changed crate correctly.

Required behavior:

- RCH must identify the full path-dependency closure, not only the top-level repo.
- The worker should receive path dependencies in a deterministic, inspectable way.
- There should be a `rch sync --explain` or `rch doctor sync` command that lists every root, local revision/content hash, remote revision/content hash, and why a root will or will not sync.
- A transient SSH or rsync failure should not kill the entire convergence mechanism without retry.
- "All workers failed convergence" should show the concrete first failing path and remote command.

### P1: Artifact Retrieval Does Not Track Actual Target Directory

Session evidence from `storage_ballast_helper` shows an artifact pattern like `target/release/**`, while RCH rewrote `CARGO_TARGET_DIR` to the remote `.rch-target`. The binary was produced under `.rch-target`, but artifact collection still looked under `target/release/**`.

Required behavior:

- Artifact collection must follow the actual target directory used by the remote command.
- If RCH rewrites `CARGO_TARGET_DIR`, artifact patterns must be rewritten or expanded accordingly.
- Artifact diagnostics should print the remote target dir, patterns searched, files found, and reason no artifact matched.

### P1: Queue and Capacity Semantics Can Lose Output or Mislead Agents

Local evidence shows a case where an agent selected a known-good worker but saw `0 slots`; the job appeared already queued or running, while the CLI returned early. This creates a bad state: remote work may be consuming capacity, but the agent has no output and believes the command failed.

Required behavior:

- If a command enters a queue, the CLI should return a job id and either wait, stream, or explicitly say it did not start.
- `rch status` should show queued, running, and abandoned jobs.
- If reservation fails after a queue admission, RCH must cancel or reattach cleanly.
- Agents should never be left with "maybe running somewhere" uncertainty.

### P1: Disk Pressure Handling Is Too Reactive

The session corpus is full of disk-pressure and target-dir evidence:

- "No space left on device" appears across multiple projects.
- `target_rch` and `.rch-target` directories accumulate.
- Historical design notes mention 0.5 GB to 11 GB per target dir and around 1.6 TB of manual cleanup.
- Stale target reaping exists but is disabled by default in config.
- The daemon-side stale-target reaper only sweeps workers that are Healthy with closed circuits, so the machines most likely to need cleanup may be skipped.

Required behavior:

- Pooled target dirs should be the default for Rust builds, keyed by repo identity and toolchain.
- Stale-target reaping should be default-on with conservative policy.
- RCH should be able to diagnose disk pressure on unhealthy workers without admitting them for builds.
- Cleanup should be safe, auditable, and policy-driven; agents should not need to run ad hoc deletes.
- `rch doctor` should show remote disk, inode, target-dir, cargo-home, and `/tmp` pressure per worker.
- Worker bypass reasons should include disk and inode pressure separately.

### P1: Worker Capability Inventory Is Incomplete

The history includes:

- A worker selected for Rust but missing `rustup`.
- Workers with stale worker binaries.
- Workers with missing runtime capability.
- Workers reachable over SSH but failing preflight.
- Workers that have different remote users in SSH config versus `workers.toml`.
- A macOS build needing a mac worker while RCH only had Linux workers available.

Required behavior:

- Maintain an explicit capability inventory per worker:
  - OS, arch, libc, shell, remote user, home, temp root.
  - Installed Rust toolchains and cargo path.
  - Supported runtimes.
  - `rch-wkr` version and protocol.
  - Disk roots and capacity.
  - Whether the worker can build Darwin artifacts, Linux artifacts, or both.
- Selection should fail with "no workers with runtime/capability X" rather than routing to a worker that will fail later.
- `workers.toml` should be validated against SSH config and live host facts.

### P1: Telemetry Freshness and Health Thresholds Are Too Brittle

mac-mini-max history showed worker telemetry freshness fluctuating: only part of the fleet was fresh after restart, some VMI workers had `telemetry_gap age=None`, and SSH poll times ranged from sub-second to around 7 seconds. Tight retention and long cross-region SSH delays can make workers appear stale between successful polls.

Required behavior:

- Health thresholds should account for poll interval, timeout, concurrency, and host distance.
- Telemetry age should not collapse to `None` without a clear cause.
- A worker should not be evicted from eligibility merely because the observer loop is overloaded.
- `rch status --why-unhealthy` should explain telemetry age, last probe result, and next probe schedule.

### P1: Logging Can Become Its Own Disk Problem

mac-mini-max history showed very large daemon logs, including a multi-GB `daemon.log` and large `daemon.err`.

Required behavior:

- RCH should rotate daemon logs by default.
- `rch doctor` should report log sizes and stale logs.
- Debug logging should have retention controls.
- Logs should be structured enough to support postmortems without becoming a disk-pressure source.

### P1: Runbooks and Skills Teach Too Much Manual Surgery

The current repo runbooks and old skill material contain recovery patterns that are too manual and sometimes conflict with the current AGENTS rules. For example, old runbooks include destructive cleanup examples and direct process killing patterns. The canonical private `$rch` skill is much better, but it still should be enhanced with the temporary-bypass and auto-rejoin model.

Required behavior:

- Update the canonical `$rch` skill with:
  - "Do not permanently remove workers for transient illness."
  - "Use temporary bypass/quarantine and auto-rejoin."
  - Broad `cass` query packs for RCH postmortem mining.
  - Remote machine checklist for `ts1`, `ts2`, `css`, `csd`, `mac-mini-max`, `mac-mini-old`.
  - `RCH_REQUIRE_REMOTE=1` proof-build guidance.
  - Disk-pressure and target-dir artifact guidance.
- Update repo runbooks to avoid destructive examples and align with current safe operational style.

### P2: CASS Itself Is Part of the Operational Surface

Local and remote `cass` were useful, but also showed operational friction:

- Local `cass index --json` hung at indexing phase with `current=0 total=13`, so stale indexes had to be used.
- `cass status --json` can hang under contention.
- Remote indexes were stale on several machines.
- Some stale search result paths on `css` and `ts1` no longer existed.
- `csd` returned a fresh index with zero RCH-related query hits, which may mean either little session history there or missing ingestion.

Required behavior:

- RCH postmortem workflows should use bounded `cass` commands with timeouts.
- The `$rch` skill should include a "stale index fallback" method.
- Session history mining should record index freshness and path-resolution failures.

## Evidence by Machine

## Local VPS: `/data/projects`

Local session history is by far the richest source. The local `cass` index is stale but broad enough to expose many RCH incidents.

Representative local query totals:

| Query | Total hits | Notable workspaces |
| --- | ---: | --- |
| `rch` | 1000 | `skills_for_12_west` 731, `remote_compilation_helper` 249 |
| `remote compilation` | 1000 | `remote_compilation_helper` 849 |
| `rch exec` | 1000 | `skills_for_12_west` 996 |
| `rchd` | 1000 | `remote_compilation_helper` 826 |
| `rch-wkr` | 1000 | `remote_compilation_helper` 928 |
| `workers.toml` | 1000 | `remote_compilation_helper` 731 |
| `RCH_REQUIRE_REMOTE` | 1000 | `remote_compilation_helper` 599 |
| `[RCH] local` | 1000 | `remote_compilation_helper` 340, `/data/projects` 175 |
| `local compilation despite rch` | 118 | `remote_compilation_helper` 28 |
| `daemon unavailable` | 619 | `remote_compilation_helper` 191 |
| `all workers at capacity` | 693 | `remote_compilation_helper` 154, `frankensqlite` 114 |
| `all workers unreachable` | 580 | `remote_compilation_helper` 436 |
| `all worker circuits open` | 258 | `remote_compilation_helper` 237 |
| `no workers configured` | 589 | `remote_compilation_helper` 211 |
| `no workers passed health` | 326 | `remote_compilation_helper` 121 |
| `all workers failed preflight` | 131 | `remote_compilation_helper` 51 |
| `all workers failed convergence` | 110 | `remote_compilation_helper` 47 |
| `no admissible workers` | 7 | `beads_rust`, `frankensqlite` |
| `NoWorkersWithRuntime` | 171 | `remote_compilation_helper` 168 |
| `worker starvation` | 233 | `frankensqlite` 115 |
| `rch workers disable` | 335 | `remote_compilation_helper` 219 |
| `re-enable worker` | 46 | `remote_compilation_helper` 15 |
| `disk pressure` | 1000 | `frankensqlite` 588, `remote_compilation_helper` 111 |
| `no space left on device` | 805 | Many repos |
| `CARGO_TARGET_DIR` | 1000 | `frankensqlite` 220, `mcp_agent_mail_rust` 114 |
| `.rch-target` | 62 | `/data/projects` 26, `remote_compilation_helper` 14 |
| `stale target` | 1000 | Broad |
| `ssh timeout` | 1000 | `remote_compilation_helper` 455 |
| `connection refused rch` | 117 | `frankensqlite` 29, `remote_compilation_helper` 25 |
| `Darwin linux workers rch` | 60 | Cross-platform failure evidence |
| `rch update fleet` | 1000 | Fleet-deploy evidence |
| `failed convergence rch` | 658 | `ntm` 518, `remote_compilation_helper` 61 |

Concrete local findings:

1. Hook/daemon self-healing failure:
   - A session saw the hook fail to query the daemon with `Connection refused` and allow local execution.
   - Restarting the daemon made remote build work on `csd`.
   - The session explicitly concluded that the hook should start the daemon and the daemon should verify hooks.

2. Worker temporary failure became permanent pool shrinkage:
   - In `beads_rust`, worker `fmd` was selected even though `rustup` was missing.
   - The agent drained it.
   - The drain did not take effect until daemon restart.
   - The drain did not persist as expected after restart.
   - The agent edited `workers.toml` to remove `fmd`.
   - After Rust was installed on `fmd`, it had to be manually re-enabled.
   - This is exactly the workflow RCH should make unnecessary.

3. Socket path mismatch caused silent local builds:
   - One session saw config using `/run/user/1000/rch.sock` while daemon used `/tmp/rch.sock`.
   - Cargo ran locally instead of being offloaded.
   - This should be diagnosed by doctor and repaired by hook/daemon self-healing.

4. Path dependency sync failure:
   - `mcp_agent_mail_rust` sessions showed remote workers with stale path dependency roots.
   - Local source contained newer APIs not present remotely.
   - The agent could not find a clear force-sync path.
   - `rsync failed` and dependency-root sync failure blocked verification.

5. Queue/capacity ambiguity:
   - A session selected a known-good worker but saw `0 slots`.
   - The job appeared already queued/running, but the CLI returned early.
   - RCH needs job identity and reattach/cancel semantics.

6. Artifact path mismatch:
   - `storage_ballast_helper` sessions showed remote target-dir rewriting to `.rch-target` while artifact collection still searched `target/release/**`.
   - This can produce a successful remote build with missing local artifacts.

7. Disk and target-dir pressure:
   - `target_rch`, `.rch-target`, and stale cargo target directories appear across local history.
   - Repo design docs already identify per-job target dirs as a major cause of unbounded accumulation and cold caches.

8. RCH code confirms sticky disabled/drained states:
   - `apply_health_status` preserves `Draining`, `Drained`, and `Disabled`.
   - `reserve_slots` refuses those states.
   - Manual enable is required to clear disabled state.
   - This is appropriate for admin disable but wrong for transient failure handling.

9. Current open Beads align with history:
   - P0 Darwin controller pushing Darwin `rch-wkr` to Linux workers.
   - P1 `doctor --fix` must execute remediations.
   - P1 hook hot-path reliability.
   - P1 doctor reliability completeness.

## ts1: `thinkstation1`

Status:

- SSH reachable.
- `cass` available, version 0.6.9.
- Index reported stale.

Representative query totals:

| Query | Total hits |
| --- | ---: |
| `[RCH] local` | 125 |
| `all workers at capacity` | 51 |
| `all workers unreachable` | 4 |
| `daemon unavailable` | 6 |
| `disk pressure` | 86 |
| `rch workers disable` | 2 |
| `rch workers enable` | 36 |
| `Contabo` | 36 |
| `vmi` | 16 |
| `target_rch` | 2273 |
| `worker starvation` | 25 |

Findings from ts1 history:

1. `target_rch` is a very large theme on this machine. Even if many hits are not direct failures, the volume supports the conclusion that remote target dirs and build artifacts are a recurring operational load.

2. `all workers at capacity` appears enough to support a backpressure problem: agents need queue visibility, wait guidance, and a clean "try later or require remote" mode.

3. The presence of both disable and enable hits indicates manual pool repair activity. That supports the need for automatic temporary bypass and auto-rejoin.

4. Some hit paths from the stale index no longer resolved during direct inspection. That limits exact quote extraction but is itself a session-history reliability issue.

## ts2: `thinkstation2`

Status:

- Initially reachable enough to identify the host and `cass` version 0.6.10.
- `cass status` timed out.
- Later SSH timed out during banner exchange to the LAN address.

Findings from ts2 history and access behavior:

1. ts2 itself is an example of a worker or analysis host that can move between reachable, slow, and unreachable states.

2. RCH should model this as temporary bypass with polling, not permanent removal.

3. Session-history mining on ts2 is incomplete because the machine could not be queried reliably. Any "complete history" workflow needs an explicit unreachable-host ledger with retry timestamps.

4. If ts2 is part of the worker pool, daemon health should distinguish:
   - SSH banner timeout.
   - SSH authentication failure.
   - Shell command timeout.
   - `rch-wkr` unreachable.
   - Worker busy but healthy.

## css: `superserver`

Status:

- SSH reachable.
- `cass` available, version 0.4.2.
- Index stale.
- Some stale result paths did not resolve when inspected directly.

Representative query totals:

| Query | Total hits |
| --- | ---: |
| `all workers unreachable` | 79 |
| `all worker circuits open` | 21 |
| `daemon unavailable` | 183 |
| `disk pressure` | 407 |
| `rch workers disable` | 431 |
| `rch workers enable` | 1100 |
| `Contabo` | 517 |
| `vmi` | 172 |
| `target_rch` | 4653 |
| `worker starvation` | 350 |

Findings from css history:

1. css has the strongest signal that RCH worker-pool mutation is common. The disable/enable counts are high enough that manual lifecycle management is not an edge case.

2. The Contabo and VMI counts are high. This supports the user-observed pattern where cloud fleet machines disappear or get paused and all work routes to a smaller local pool.

3. `target_rch` is extremely high. css should be considered a prime source for target-dir reaper and pooled-target-dir validation.

4. The combination of `all workers unreachable`, `all worker circuits open`, and `daemon unavailable` indicates that users and agents frequently see degraded remote build state rather than a single isolated host issue.

5. Stale result paths again show that session-history tooling needs bounded refresh and path validation in postmortem workflows.

## csd: `sensedemobox`

Status:

- SSH reachable.
- `cass` available, version 0.4.1.
- Index reported not stale.
- The RCH query pack returned zero hits for the selected terms.

Findings from csd history:

1. csd did not contribute much direct session-history evidence in this pass.

2. csd still appears in local histories as a worker that can successfully run remote builds after daemon/hook recovery.

3. Because csd has a fresh index and zero RCH hits, it may be under-indexed for relevant agent sessions or simply not used as an agent-session host for RCH work.

4. csd is useful as a known-good worker comparison target. RCH diagnostics should make it easy to compare a failing worker against a known-good worker: toolchain, paths, disk, version, user, SSH latency, and canary result.

## mac-mini-max

Status:

- SSH reachable over Tailscale.
- `cass` available, version 0.4.1.
- Index stale.

Representative query totals:

| Query | Total hits |
| --- | ---: |
| `[RCH] local` | 355 |
| `all workers at capacity` | 2 |
| `all workers unreachable` | 37 |
| `all worker circuits open` | 4 |
| `daemon unavailable` | 23 |
| `disk pressure` | 300 |
| `rch workers disable` | 6 |
| `rch workers enable` | 34 |
| `Contabo` | 310 |
| `vmi` | 1188 |
| `target_rch` | 727 |
| `worker starvation` | 16 |

Concrete findings from mac-mini-max history:

1. Telemetry freshness problems:
   - A session showed only part of the worker fleet fresh after restart.
   - Some VMI workers had no telemetry age.
   - SSH poll times varied enough that tight freshness thresholds can falsely classify workers as stale.

2. Health-threshold local fallback:
   - A mac-mini-max session observed local execution because no workers passed health thresholds.

3. VMI/Contabo fleet signals are strong:
   - The `vmi` hit count is especially high.
   - This supports adding cloud/fleet desired-state awareness to RCH diagnostics.

4. Log growth is a real operational problem:
   - mac-mini-max history included very large daemon logs.
   - RCH should rotate logs and report log pressure.

5. Disk cleanup pressure can become unsafe:
   - A mac-mini-max session showed attempted cleanup of remote build targets and destructive-command guard intervention.
   - RCH should provide safe, policy-driven cleanup so agents do not invent ad hoc cleanup commands.

6. Cross-platform selection matters:
   - Local history from mac contexts showed macOS builds needing a mac worker while RCH had only Linux workers available.
   - RCH needs runtime and platform-aware selection, not just "reachable worker".

## mac-mini-old

Status:

- SSH timed out to the Tailscale address.

Findings from mac-mini-old access behavior:

1. This is another example of fleet hosts becoming temporarily unreachable.

2. The correct RCH response is temporary bypass with scheduled diagnostics, not permanent removal.

3. A complete RCH doctor or fleet report should include "expected but unreachable" hosts with last-seen, last-successful-probe, and next retry.

## RCH Repo and Skill Findings

### Current Code

The current status model has the ingredients for explicit lifecycle states, but not the right transient recovery path.

Observed code-level facts:

- Worker status includes Healthy, Degraded, Unreachable, Draining, Drained, and Disabled.
- Health application preserves Draining, Drained, and Disabled.
- Slot reservation rejects Draining, Drained, and Disabled.
- Manual enable clears disabled fields.
- Stale target reaper is present but disabled by default.
- Stale target sweeping only targets healthy workers with closed circuits.

Interpretation:

- Permanent admin states are sticky by design.
- Transient incidents are being handled with sticky states or config edits.
- The missing abstraction is temporary bypass with automatic re-probe and rejoin.

### Current Docs

Relevant docs already recognize several problems:

- Pooled target dir design notes explain why per-job `.rch-target-*` dirs accumulate and destroy cache efficiency.
- Worker recovery runbooks cover manual intervention.
- Slow-build runbooks cover disk and process cleanup.

Docs gap:

- They need to be rewritten around safe, automated, policy-driven RCH primitives.
- They should stop normalizing manual permanent removal as a transient recovery path.
- They should align with the current AGENTS rule set and avoid destructive examples.

### Canonical `$rch` Skill

The canonical skill is useful and already contains:

- Worker checks.
- Disk-pressure guidance.
- Multi-agent contention guidance.
- Fail-open and self-healing guidance.
- Recovery playbooks.

Needed additions:

- A temporary bypass / auto-rejoin operating model.
- A "do not edit workers.toml to solve transient illness" rule.
- A fleet desired-state reconciliation section.
- A remote session-history query pack.
- Artifact retrieval guidance for rewritten target dirs.
- A proof-build mode that sets `RCH_REQUIRE_REMOTE=1`.
- A cross-platform fleet update warning for Darwin/Linux.

## Proposed Implementation Backlog

### P0. Temporary Bypass and Auto-Rejoin

Add a worker lifecycle state for transient automatic removal from selection.

Acceptance criteria:

- Transient failures move workers to `TemporaryBypass`, not `Disabled`.
- Bypass reasons are stored and shown in status.
- Bypassed workers are still probed.
- Workers auto-rejoin after consecutive successful diagnostics.
- Admin disabled workers do not auto-rejoin.
- `workers.toml` is not mutated for transient failures.

### P0. Desired-State Fleet Reconciler

Add a reconciler that compares configured workers, live daemon state, and actual reachable workers.

Acceptance criteria:

- `rch status --fleet` shows desired, eligible, bypassed, disabled, unreachable, and missing.
- RCH warns when expected workers have been absent longer than a threshold.
- RCH reports whether capacity collapse is due to cloud fleet disappearance, local pool overload, or admin disable.

### P0. Hook/Daemon/Doctor Self-Healing

Make the daemon, hook, and doctor repair each other.

Acceptance criteria:

- Hook starts daemon on missing/refused socket and retries once.
- Daemon verifies hook install and socket path on startup.
- Doctor detects and fixes stale hook, missing hook, wrong socket path, and daemon not running.
- `doctor --fix` performs concrete remediations.

### P0. OS/Arch-Aware Fleet Update

Fix the Darwin-controller to Linux-worker deploy bug.

Acceptance criteria:

- `rch update --fleet` never deploys a controller-native binary to incompatible workers.
- Each worker gets the correct OS/arch artifact.
- Post-deploy remote startup verifies executable format and protocol handshake.

### P1. Path Dependency Convergence

Make dependency sync explainable and robust.

Acceptance criteria:

- `rch sync --explain` lists all path roots and hashes.
- Convergence retries transient SSH/rsync failures.
- Stale dependency roots produce a named error with local and remote details.
- Agents have a supported force-resync path.

### P1. Capacity, Queue, and Job Reattach

Fix ambiguous queue behavior.

Acceptance criteria:

- Queued jobs have job ids.
- CLI either waits, streams, or says no job started.
- `rch status` shows queued/running/abandoned jobs.
- Failed reservation cannot leave hidden remote work running without an attach/cancel path.

### P1. Disk-Pressure and Target-Dir Program

Turn target-dir cleanup into a first-class RCH feature.

Acceptance criteria:

- Pooled target dirs are default.
- Stale reaper is enabled by default with safe policy.
- Reaper can diagnose unhealthy workers without scheduling builds on them.
- Doctor shows per-worker disk, inode, cargo-home, target-root, and log pressure.
- Artifact retrieval follows the actual remote target dir.

### P1. Capability Inventory

Selection should be based on explicit capabilities.

Acceptance criteria:

- Worker facts include OS, arch, runtime, Rust toolchain, user, paths, worker version, and capacity.
- Selection explains missing capability versus unhealthy worker versus busy worker.
- `workers.toml` validation catches SSH user/path drift.

### P1. Telemetry and Log Retention

Make observability reliable under load.

Acceptance criteria:

- Telemetry freshness threshold accounts for poll duration and timeout.
- `age=None` has a concrete explanation.
- Daemon logs rotate by default.
- Doctor reports excessive daemon logs.

### P2. Skill and Runbook Refresh

Update operational guidance.

Acceptance criteria:

- Canonical `$rch` skill teaches temporary bypass and auto-rejoin.
- Runbooks remove unsafe cleanup defaults.
- Skills include a standard remote CASS query pack.
- Skills teach `RCH_REQUIRE_REMOTE=1` for proof runs.

## Standard Query Pack Used

The following queries were useful and should be added to the `$rch` skill:

```text
rch
remote compilation
remote_compilation_helper
rch exec
rchd
rch-wkr
workers.toml
RCH_REQUIRE_REMOTE
[RCH] local
local compilation despite rch
local fallback
daemon unavailable
all workers at capacity
all workers unreachable
all worker circuits open
no workers configured
no workers passed health
all workers failed preflight
all workers failed convergence
no admissible workers
NoWorkersWithRuntime
worker starvation
worker pool
rch workers disable
rch workers enable
drain worker
unhealthy worker
re-enable worker
vmi
Contabo
disk pressure
no space left on device
disk full
/tmp
CARGO_TARGET_DIR
target_rch
.rch-target
stale target
ssh timeout
connection refused rch
Darwin linux workers rch
rch update fleet
rch doctor reliability
RCH-E210
RCH-E211
RCH-E204
RCH-E305
repo convergence rch
failed convergence rch
preflight rch
```

## Final Diagnosis

The most important issue is not that individual workers fail. Workers will fail. Cloud machines will pause. Disk will fill. SSH will time out. The real RCH bug is that transient failures are allowed to mutate or shrink the effective worker pool in ways that do not automatically heal.

RCH should treat the worker pool as desired state plus live eligibility. Temporary failure should affect only live eligibility. Permanent disable should require an explicit permanent action. Recovery should be automatic, diagnostic, and visible.

If RCH implements temporary bypass, auto-rejoin, desired-state reconciliation, loud fallback, hook/daemon/doctor self-healing, robust dependency sync, and target-dir/disk pressure management, most of the repeated agent-session failures would turn from "agents get stuck and give up" into "RCH explains the problem, routes around it, and repairs the pool when the worker recovers."
