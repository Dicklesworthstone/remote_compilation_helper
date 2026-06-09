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

Important caveat: every machine had some indexing, access, or corpus-shape complication. I did not treat that as a reason to skip the machine. I recorded it as an operational finding, because a stale, absent, or misleading session index is itself relevant to debugging and fleet recovery work. The first pass over-relied on capped `cass` searches. The second pass went directly to the raw `.jsonl` stores with bounded `rg` scans. The third pass checked CASS source configuration, counted RCH-explicit candidate files, and sampled direct raw session/tool-output evidence from the live and backup stores.

## Directly Inspected Evidence Trail

This report is based on broad `cass` query matrices, direct raw-session scans, and targeted JSONL snippets. The following specific artifacts were inspected directly and shaped the conclusions:

- Local session `/home/ubuntu/.claude/projects/-data-projects/e355f62c-ae7f-4c97-bd85-fd22fb0bfc60.jsonl`: hook could not connect to daemon, local execution was allowed, daemon restart restored remote compilation, and the session reasoned toward hook/daemon/doctor self-healing.
- Local session `/home/ubuntu/.claude/projects/-data-projects-beads-rust/eccf9525-f722-40de-971e-15294cf3a464.jsonl`: socket path mismatch, local fallback, worker selected without `rustup`, manual drain/remove/re-enable flow.
- Local session `/home/ubuntu/.claude/projects/-data-projects-mcp-agent-mail-rust/effe792c-7e54-4b7b-bb21-c932be888ccf.jsonl`: stale path dependency roots, unclear force-sync path, `rsync` failure, and queue/slot ambiguity.
- Local session `/home/ubuntu/.claude/projects/-data-projects-storage-ballast-helper/9fe26b30-ae3f-4e59-a034-73ae6ab454aa.jsonl`: rewritten `CARGO_TARGET_DIR` to `.rch-target` while artifact collection searched `target/release/**`.
- mac-mini-max session `/Users/jemanuel/.claude/projects/-Users-jemanuel/6808415d-2854-4409-914c-7ed9c1513bcb.jsonl`: remote cleanup pressure, destructive-command guard intervention, expensive target-dir scans, and fleet/process remediation context.
- RCH source files: `rch-common/src/types.rs`, `rchd/src/workers.rs`, `rchd/src/config.rs`, `rchd/src/stale_target_reap.rs`, `rchd/src/selection.rs`.
- RCH docs: `docs/design/pooled-target-dirs.md`, `docs/runbooks/worker-recovery.md`, `docs/runbooks/debugging-slow-builds.md`.
- Canonical skill package: `/dp/je_private_skills_repo/.claude/skills/rch/SKILL.md` and its referenced worker, disk pressure, contention, self-healing, fail-open, and operations references.
- Open Beads in this repo, especially the P0 Darwin-controller/Linux-worker deploy issue and P1 doctor/hook reliability issues.
- Local RCH project stores `/home/ubuntu/.claude/projects/-data-projects-remote-compilation-helper`, `/home/ubuntu/.claude/projects/-data-projects-remote_compilation_helper`, and `/data/agent_config_folder_backups/.claude/projects/-data-projects-remote-compilation-helper`, including `doctor.reliability.watch` output and product-history beads around multi-repo sync, disk pressure, worker self-healing, and hook/UX gaps.
- `ts1` raw sessions including `/home/ubuntu/.codex/sessions/2026/05/10/rollout-2026-05-10T01-09-44-019e104a-9799-7ca3-a309-b02f0f8f2eab.jsonl`, which showed local fallback after failed preflight, local cargo lock contention, later successful SSH probes to VMI workers, daemon connection refusal, and daemon logs reconnecting workers.
- `css` raw sessions including `/home/ubuntu/.codex/sessions/2026/04/25/rollout-2026-04-25T11-23-30-019dc53d-2000-7f10-909f-0eedc03c0437.jsonl` and `/home/ubuntu/.codex/sessions/2026/05/08/rollout-2026-05-08T01-18-38-019e0606-04ca-72c1-adb3-3721583f55a0.jsonl`, which showed non-compilation `rch exec` confusion, missing `wasm32-unknown-unknown`, `rsync failed` on vanished `.git/index.lock`, and multi-agent proof lanes routing through RCH.
- `mac-mini-max` raw session `/Users/jemanuel/.claude/projects/-Users-jemanuel/6808415d-2854-4409-914c-7ed9c1513bcb.jsonl`, which confirmed a Darwin controller pushing a Darwin `rch-wkr` binary to Linux workers, causing `Exec format error` and breaking telemetry/offload.
- mac-mini-max raw sessions under `/Users/jemanuel/.claude/projects/-Users-jemanuel-projects/6991adb6-d686-4d70-8bed-bcc569877b63/`, which include VMI build-worker sweeps, active `rsync`/`.rch-target-vmi...` paths, `/tmp/rch-cargo-home-vmi...` cargo homes, and safe-cleanup pressure during active builds.

The broad query matrices were run locally and on every requested reachable machine. `mac-mini-old` could not be mined because SSH to the Tailscale address timed out. `ts2` was slow but reachable during the second pass and was raw-mined directly.

## Second-Pass Raw Corpus Coverage

The first pass used capped `cass` totals and therefore undercounted the real surface area. The second pass treated the raw session files as the ground truth. The counts below are raw matching lines, not unique incidents; they overcount repeated prompts, tool output, and skill bodies, but they are still valuable because they show which machines have large clusters worth direct inspection. When a term is enormous, the count is best read as "this problem class is common enough to require product support", not as a precise incident count.

### Raw Source Inventory

| Machine | Reachability and index state | Raw files inspected or counted |
| --- | --- | ---: |
| Local VPS `/data/projects` | Reachable; `cass` unhealthy/stale, last indexed 2026-06-05, 133 quarantined conversations | 3,982 Claude + 11,909 Codex + 66 rollout summaries |
| `ts1` / `thinkstation1` | Reachable; `cass 0.6.13`; index 88 days stale | 1,756 Claude + 2,166 Codex + 256 rollout summaries |
| `ts2` / `thinkstation2` | Reachable but slow; `cass 0.6.10`; index 10 days stale | 1,912 Claude + 645 Codex + 104 rollout summaries |
| `css` / `superserver` | Reachable; `cass 0.6.13`; index 48 days stale | 653 Claude + 334 Codex + 49 rollout summaries |
| `csd` / `sensedemobox` | Reachable; `cass 0.4.1`; index not found | 1,069 Claude + 453 Codex + 3 rollout summaries |
| `mac-mini-max` | Reachable over Tailscale; `cass 0.4.1`; index 3 days stale | 2,948 Claude + 1,647 Codex + 15 rollout summaries |
| `mac-mini-old` | SSH timed out | Not mined |

### Raw Hit Matrix

These are raw matching-line counts from the bounded second-pass scan:

| Term | Local | ts1 | ts2 | css | csd | mac-mini-max |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| `[RCH] local` | 2,167 | 25,405 | 10,963 | 12,987 | 6,940 | 26,225 |
| `rch exec` | 427,376 | 806,450 | 342,984 | 844,878 | 471,272 | 984,755 |
| `RCH_REQUIRE_REMOTE` | 2,599 | 33,317 | 25,898 | 34,054 | 7,606 | 65,928 |
| `all workers at capacity` | 210 | 557 | 614 | 157 | 609 | 501 |
| `all workers unreachable` | 128 | 215 | 385 | 95 | 78 | 2,176 |
| `all worker circuits open` | 102 | 171 | 137 | 102 | 68 | 153 |
| `no workers passed health` | 81 | 43 | 239 | 147 | 1 | 8,557 |
| `all workers failed preflight` | 304 | 569 | 196 | 68 | 655 | 2,756 |
| `all workers failed convergence` | 40 | 0 | 0 | 0 | 0 | 0 |
| `no admissible workers` | 2,118 | 8,178 | 8,622 | 4,654 | 293 | 14,649 |
| `rch workers disable` | 444 | 2,829 | 1,769 | 577 | 1,508 | 1,549 |
| `rch workers enable` | 304 | 672 | 639 | 186 | 528 | 947 |
| `workers.toml` | 16,448 | 6,137 | 3,566 | 1,195 | 3,438 | 69,660 |
| `No space left on device` | 5,241 | 6,810 | 2,920 | 4,156 | 12,309 | 46,380 |
| `Contabo` | 36,778 | 36,454 | 10,261 | 12,346 | 12,391 | 137,821 |
| `vmi` | 336,052 | 1,158,377 | 38,821 | 328,776 | 283,731 | 1,758,479 |
| `Exec format error` | 116 | 53 | 5 | 1 | 20 | 189 |
| `rch update --fleet` | 75 | 57 | 32 | 14 | 18 | 77 |
| `wasm32-unknown-unknown` | 4,992 | 262 | 7,607 | 5,349 | 24 | 3,419 |
| `rsync failed` | 1,106 | 3,382 | 137 | 462 | 251 | 2,159 |
| `CARGO_TARGET_DIR` | 98,674 | 450,075 | 296,342 | 343,873 | 190,980 | 455,058 |
| `target_rch` | 817 | 15,044 | 50,307 | 8,679 | 46,187 | 17,158 |
| `.rch-target` | 53,915 | 257,844 | 218,478 | 64,946 | 95,523 | 165,518 |
| `connection refused` | 1,883 | 2,567 | 818 | 1,498 | 270 | 4,909 |

Immediate conclusions from the raw matrix:

1. The previous "zero hits" or low-count readings for some machines were artifacts of stale or missing indexes. `csd` has no usable `cass` index, yet raw history has thousands of RCH lines.
2. `rch exec`, `CARGO_TARGET_DIR`, `.rch-target`, and VMI terms are enormous on every active host. RCH is not a niche helper; it is core build infrastructure for the whole agent fleet.
3. Manual lifecycle mutation is not rare. `rch workers disable` and `rch workers enable` appear hundreds to thousands of times across the hosts, which supports replacing manual pool shrinkage with temporary bypass and automatic rejoin.
4. Disk and artifact pressure are fleet-wide. `No space left on device`, `.rch-target`, `target_rch`, and `CARGO_TARGET_DIR` appear strongly on all reachable machines.
5. Cloud/fleet disruptions are central, not peripheral. `Contabo` and `vmi` dominate mac, ts1, css, and local histories.
6. Wrong-architecture deployment is not hypothetical. `Exec format error` and `rch update --fleet` co-occur across the local, mac, ts1, ts2, css, and csd corpora, with mac-mini-max providing the clearest direct narrative.
7. WebAssembly target friction and `rsync` failure are recurring capability/convergence classes. They need first-class capability inventory and sync diagnostics, not one-off agent workarounds.

## Third-Pass Expanded Raw-Session Evidence

A deeper pass corrected the earlier undercount. The first indexed `cass` pass and even the second raw-count pass did not adequately show how much session history exists outside the indexed happy path. The third pass therefore widened the method in three ways:

1. It checked the CASS source configuration and CASS health on every reachable host.
2. It counted RCH-explicit candidate files before sampling category evidence.
3. It prioritized direct raw session files and tool-output sidecars over `cass search` output.

Important CASS-source findings:

| Machine | CASS source state observed in this pass | Implication |
| --- | --- | --- |
| Local VPS `/data/projects` | `cass 0.6.13`; `sources.toml` contains only local backup stores under `/data/agent_config_folder_backups`; `cass health` was unhealthy/stale with 133 quarantined conversations | Local indexed search is not a complete view of live history; raw live stores and backup stores both matter |
| `ts1` | `cass 0.6.13`; `cass sources list` returned zero configured sources | Use raw `~/.claude`, `~/.codex`, and `~/.gemini` stores directly |
| `ts2` | `cass 0.6.10`; `cass sources list` returned zero configured sources | Same; indexed evidence undercounts by construction |
| `css` | `cass 0.6.13`; `cass sources list` returned zero configured sources | Same |
| `csd` | `cass 0.4.1`; `cass sources list` returned zero configured sources | Same, and older CASS makes the index less trustworthy |
| `mac-mini-max` | `cass 0.4.1`; configured SSH sources for `css`, `csd`, `trj`, `yto`, and `fmd`; index stale | Mac has the broadest configured cross-machine CASS map, but it is stale and older |
| `mac-mini-old` | SSH timed out at `100.101.242.107:22` | Not mined |

RCH-explicit candidate-file counts from the third-pass prefilter:

| Machine/root group | RCH-relevant candidate files |
| --- | ---: |
| Local live stores (`~/.claude`, `~/.codex`, `~/.gemini`, rollout summaries) | 14,475 |
| Local backup Claude store | 21,294 |
| Local backup Codex store | 626 |
| Local backup Gemini store | 523 |
| `ts1` live stores | 3,836 |
| `ts2` live stores | 3,277 |
| `css` live stores | 884 |
| `csd` live stores | 1,105 |
| `mac-mini-max` live stores | 5,619 |

These are file counts after filtering for explicit RCH markers such as `rch`, `remote compilation`, `remote_compilation_helper`, `target_rch`, `workers.toml`, `/tmp/rch`, `rchd`, `NoWorkers`, `telemetry_gap`, and `RCH_`. They are not line counts or incident counts. The important point is scale: the complete history surface is tens of thousands of files even before interpreting individual incidents.

Third-pass evidence sharpened the diagnosis in these specific ways:

1. CASS is useful but insufficient for RCH postmortems. Stale indexes, absent sources, and quarantined sessions are normal enough that the `$rch` skill should include a raw-history fallback query pack.
2. RCH has no durable incident ledger that agents can query directly. Agents are reconstructing fleet state from session logs, `rch status`, `rch doctor`, `journalctl`, and ad hoc grep. RCH should write its own compact, append-only incident log with reason codes, worker eligibility transitions, selection refusals, fallback decisions, and recovery events.
3. The "remote_ready but no admissible workers" state appears repeatedly. The product should not advertise readiness at one layer while selection refuses every worker at another layer without a single decisive explanation.
4. `RCH_REQUIRE_REMOTE=1` and `RCH_FORCE_REMOTE=1` have become folk remedies. They help distinguish proof runs from convenience runs, but they do not solve the underlying need for reliable admission, queueing, and self-healing.
5. The session history distinguishes host problems from RCH problems. Disk pressure, swap saturation, stuck `rustc`, and paused/unreachable VMIs are host/fleet issues; silent fallback, sticky pool shrinkage, poor eligibility explanation, target-dir sprawl, and missing auto-rejoin are RCH issues.

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

Remote raw sessions add another convergence class: `rsync` failed because a volatile file such as `.git/index.lock` vanished during transfer in a busy shared repo. That is not a source-code failure and should not collapse the whole build without a clear retry or ignore policy.

Required behavior:

- RCH must identify the full path-dependency closure, not only the top-level repo.
- The worker should receive path dependencies in a deterministic, inspectable way.
- There should be a `rch sync --explain` or `rch doctor sync` command that lists every root, local revision/content hash, remote revision/content hash, and why a root will or will not sync.
- A transient SSH or rsync failure should not kill the entire convergence mechanism without retry.
- "All workers failed convergence" should show the concrete first failing path and remote command.
- Transfer excludes should cover volatile lock files and known ephemeral stores.
- Vanished files should be classified separately from real transfer corruption.

### P1: Artifact Retrieval Does Not Track Actual Target Directory

Session evidence from `storage_ballast_helper` shows an artifact pattern like `target/release/**`, while RCH rewrote `CARGO_TARGET_DIR` to the remote `.rch-target`. The binary was produced under `.rch-target`, but artifact collection still looked under `target/release/**`.

Required behavior:

- Artifact collection must follow the actual target directory used by the remote command.
- If RCH rewrites `CARGO_TARGET_DIR`, artifact patterns must be rewritten or expanded accordingly.
- Artifact diagnostics should print the remote target dir, patterns searched, files found, and reason no artifact matched.

### P1: Artifact Retrieval Cost Model Ignores File Count

ts1 raw evidence showed a remote retrieval of 55,823 files totaling only 914,945 bytes taking about 109.5 seconds. That is a metadata and small-file problem, not a byte-volume problem. The current operational guidance tends to talk about transfer size, but raw sessions show file count can dominate wall time.

Required behavior:

- Status and logs should report files transferred, bytes transferred, file count per second, and wall-clock phase timings.
- Artifact collection should avoid returning broad target trees when a narrower artifact pattern is sufficient.
- RCH should warn when an artifact pattern expands to tens of thousands of files.
- The planner should prefer manifest-based artifact retrieval over recursive wildcard retrieval for large target dirs.

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
- Workers missing `wasm32-unknown-unknown` despite receiving wasm proof lanes.
- The same host having a valid `rch-wkr` for one user/path and a broken wrong-arch `rch-wkr` for the exact user/path RCH invokes.

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
- Capability checks must run as the actual configured remote user and resolve the exact executable path that the worker will use.

### P1: Explicit `rch exec` UX Is Too Easy To Misuse

Raw mac and css sessions showed two separate UX problems:

- `rch exec "cargo check --all-targets"` was interpreted as one executable name instead of a shell command, then the agent had to discover the required `rch exec -- cargo check --all-targets` form.
- `rch exec -- env CARGO_TARGET_DIR=... cargo fmt --check --all` warned that the command was non-compilation, while the operator had intentionally invoked `rch exec`.

Required behavior:

- Detect the common quoted-command form and print the corrected invocation.
- In explicit `rch exec` mode, distinguish "I will not offload this because it is non-compilation" from "I will run it remotely because the operator explicitly requested `rch exec`."
- Machine output should include `selected_worker`, `local_or_remote`, `classification`, and `reason` so agents do not have to infer execution location from logs.

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
- `csd` had no usable index; raw scans found thousands of RCH matches that indexed search did not expose.
- Raw history can live in tool-output sidecars or unindexed JSONL fields, so `cass` must be paired with raw `rg` for RCH postmortems.

Required behavior:

- RCH postmortem workflows should use bounded `cass` commands with timeouts.
- The `$rch` skill should include a "stale index fallback" method.
- Session history mining should record index freshness and path-resolution failures.
- The fallback method should include raw root inventory and a standard bounded `rg` term matrix.

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

Second-pass local raw-session additions:

10. The local raw corpus is much broader than the first capped `cass` matrix showed:
    - 427,376 raw `rch exec` matching lines across 2,087 files.
    - 98,674 `CARGO_TARGET_DIR` matching lines across 725 files.
    - 53,915 `.rch-target` matching lines across 125 files.
    - 36,778 `Contabo` and 336,052 `vmi` matching lines.
    - 1,106 `rsync failed`, 5,241 `No space left on device`, and 116 `Exec format error` lines.

11. The top local RCH failure cluster on 2026-06-08 contains all major categories in one place: `[RCH] local`, all workers at capacity, all workers unreachable, all worker circuits open, no workers passed health, all workers failed preflight, all workers failed convergence, `rch workers disable`, `rch workers enable`, `rch update --fleet`, `Exec format error`, `rsync failed`, and connection refusal. That clustering suggests RCH needs a single fleet incident mode instead of disjoint per-symptom messages.

12. Local memory and raw sessions independently show that agents have learned to use `RCH_REQUIRE_REMOTE=1` for proof runs, but the system still frequently falls back or blocks. That means "teach agents to require remote" is necessary but not sufficient; RCH itself must make remote unavailability explainable and recoverable.

Third-pass local raw-session additions:

13. The dedicated local RCH Claude stores (`-data-projects-remote-compilation-helper` and `-data-projects-remote_compilation_helper`) contain direct product-history evidence, not just downstream-user complaints. A `doctor.reliability.watch` tool output from session `77ba25db-...` reported 9 configured workers, 8 healthy workers, and 52/70 available slots while the overall verdict remained `Degraded`. That shows RCH can have many healthy-looking workers and still be in a degraded operational state that agents need to understand.

14. The same RCH project history contains the already-closed epic "Deterministic Multi-Repo Remote Builds + Worker Self-Healing". Its description names the recurring field problems directly: local path dependencies fail on workers, workers accumulate disk pressure, and remote stuck processes degrade capacity. This is independent confirmation that the issues in this report are not isolated to one recent incident.

15. Local RCH code-reading sessions repeatedly surfaced fail-open behavior in the hook: parse errors and other hook failures allow local execution. Fail-open is appropriate as a safety default, but session history shows it becomes harmful when agents treat local success as remote proof. RCH needs a separate "proof mode" where local fallback is impossible or at least unmistakably non-compliant.

16. Local RCH documentation/bead history explicitly calls out user confusion around "why isn't this working?", hook silence, circuit breaker behavior, and understanding when commands are not offloaded. That UX problem is a product defect because the main consumers are agents that will otherwise keep working under a false assumption.

## ts1: `thinkstation1`

Status:

- SSH reachable.
- `cass` available, version 0.6.13.
- Index reported 88 days stale during the second pass.

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

Second-pass ts1 raw-session additions:

5. `ts1` is one of the strongest RCH signal hosts:
   - 25,405 raw `[RCH] local` lines.
   - 806,450 raw `rch exec` lines.
   - 8,178 `no admissible workers` lines.
   - 2,829 `rch workers disable` lines and 672 `rch workers enable` lines.
   - 1,158,377 `vmi` lines, showing that VMI fleet behavior dominates this host's RCH context.

6. A May 10 raw session showed two `rch exec` commands falling back locally with `[RCH] local (all workers failed preflight checks)`. The local cargo runs then blocked on package/build directory locks. This is the clearest evidence that fail-open can directly create local compilation storms and lock contention.

7. The same May 10 session later probed VMI workers successfully over SSH after the preflight failure. That means "reachable over SSH" and "eligible for a build" diverged, and RCH needs to expose the exact reason for the failed preflight, not just let agents infer from reachability.

8. The same session had a daemon query return `Connection refused (os error 111)` and later `journalctl --user -u rchd` showed VMI worker connect/disconnect churn. This supports the hook/daemon/doctor self-healing backlog item.

9. `ts1` raw output also showed remote artifact retrieval of 55,823 files and only 914,945 bytes taking about 109.5 seconds. RCH's artifact cost model must account for file count and metadata overhead, not just byte volume.

Third-pass ts1 raw-session additions:

10. `ts1` rollout summaries include a stale `rch check` warning about `ts1` disk pressure while `rch status --workers --jobs` still reported remote-ready. This is another form of split-brain readiness: one surface says ready, another surface says pressured.

11. `ts1` histories include a benchmark that silently fell back locally because RCH reported `no admissible workers`; a retry with `RCH_FORCE_REMOTE=1` produced the actual remote profile artifact. This shows why perf and proof workflows cannot trust default fail-open behavior.

12. `ts1` histories also mention `no admissible workers: insufficient_slots=3,hard_preflight=4` and concurrent Cargo build-lock waits. That connects RCH admission failure directly to local lock contention.

13. Several `ts1` proof lanes use `RCH_WORKER=ts1`, `RCH_VISIBILITY=summary`, and worker-scoped `CARGO_TARGET_DIR` values. That indicates users are compensating for selection uncertainty manually; RCH should expose the same intent as first-class CLI options and diagnostics.

## ts2: `thinkstation2`

Status:

- Reachable in the second pass, but slow enough that earlier attempts timed out.
- `cass` available, version 0.6.10.
- `cass` index was 10 days stale.
- Raw stores counted: 1,912 Claude files, 645 Codex files, and 104 rollout summaries.

Findings from ts2 history and access behavior:

1. ts2 itself is an example of a worker or analysis host that can move between reachable, slow, and temporarily unreachable states.

2. The raw second-pass scan found substantial RCH history:
   - 10,963 `[RCH] local` lines.
   - 342,984 `rch exec` lines.
   - 614 `all workers at capacity` lines.
   - 385 `all workers unreachable` lines.
   - 239 `no workers passed health` lines.
   - 8,622 `no admissible workers` lines.
   - 1,769 `rch workers disable` lines and 639 `rch workers enable` lines.
   - 50,307 `target_rch` lines and 218,478 `.rch-target` lines.

3. The top ts2 target-dir clusters are not abstract. A raw session showed an active `rch exec` process with a worker-scoped target dir such as `.rch-target-ts2-job-...` and a temporary cargo home under `/tmp/rch-cargo-home-ts2-...`. This is the expected isolation pattern, but the hit volume shows it needs lifecycle management and reaping.

4. ts2 has strong WebAssembly target friction: 7,607 `wasm32-unknown-unknown` lines. The selection layer needs to know whether a worker has that target installed before accepting wasm lanes.

5. RCH should model ts2-style reachability changes as temporary bypass with polling, not permanent removal.

6. If ts2 is part of the worker pool, daemon health should distinguish:
   - SSH banner timeout.
   - SSH authentication failure.
   - Shell command timeout.
   - `rch-wkr` unreachable.
   - Worker busy but healthy.
   - Worker reachable but missing the requested crate path, toolchain, target, or runtime.

Third-pass ts2 raw-session additions:

7. `ts2` session summaries contain repeated strict remote-only attempts that failed before test output because both workers were reachable but rejected by critical disk pressure. The exact recurring shape is `no admissible workers: critical_pressure=2`.

8. A `ts2` audit session states that capability refresh changed the pressure reason text but did not restore admissible workers. This means "refresh capabilities" is not enough; RCH needs an explicit repair or bypass path for admission pressure.

9. Another `ts2` session reports `remote_ready` while both workers still had critical disk pressure or stale telemetry. This should be impossible as an unqualified status. RCH status should separate "daemon reachable" from "at least one worker admissible for this command".

10. `ts2` histories show the correct agent behavior under strict proof requirements: record the refusal and avoid local fallback. RCH should make that the easy path by returning structured proof-failure output with the exact reason, not by depending on agent discipline.

## css: `superserver`

Status:

- SSH reachable.
- `cass` available, version 0.6.13.
- Index reported 48 days stale during the second pass.
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

Second-pass css raw-session additions:

6. The stale indexed totals substantially undercounted css. Raw counts include:
   - 12,987 `[RCH] local` lines.
   - 844,878 `rch exec` lines.
   - 34,054 `RCH_REQUIRE_REMOTE` lines.
   - 4,654 `no admissible workers` lines.
   - 577 `rch workers disable` lines and 186 `rch workers enable` lines.
   - 4,156 `No space left on device` lines.
   - 343,873 `CARGO_TARGET_DIR` lines and 64,946 `.rch-target` lines.

7. css raw sessions show `rch exec -- env CARGO_TARGET_DIR=... cargo fmt --check --all` warning that the command was non-compilation, then local blocking on package cache. RCH's explicit `exec` UX should be clearer about when it will actually use a worker, especially when the user explicitly typed `rch exec`.

8. css raw sessions show a worker lacking `wasm32-unknown-unknown`. That should be a capability-inventory failure before selection, not a late proof-lane surprise.

9. css raw sessions show `rsync failed: file has vanished` on `.git/index.lock` during sync. RCH should exclude volatile lock files and treat vanished files as retryable or ignorable when safe.

10. css sessions also showed a degraded fleet status with 5/9 workers healthy, 86/102 slots available, low success rate, a degraded `ts2`, VMI telemetry unavailable, and advice to refresh capabilities. That is exactly the kind of state that needs a unified fleet-incident diagnosis.

Third-pass css raw-session additions:

11. css histories include strict remote proof commands using `RCH_REQUIRE_REMOTE=1`, `RCH_QUEUE_WHEN_BUSY=1`, and extended daemon wait timeouts. Agents are explicitly trying to use queue semantics, but the report surface still often collapses to "no admissible workers" or local fallback.

12. css histories show `active_project_exclusion=2` as a selection blocker. RCH should distinguish "all workers globally bad" from "this project is excluded or saturated on otherwise healthy workers".

13. css histories include fail-opened local lanes on registry/target-availability problems. That shows another class of non-worker host issue that RCH should preserve as a structured local-fallback reason instead of burying in cargo output.

14. css histories use dedicated `CARGO_TARGET_DIR` paths under `/tmp/rch_target_*`, which validates the current best practice but also reinforces the need for RCH-managed target-dir lifecycle and cleanup.

## csd: `sensedemobox`

Status:

- SSH reachable.
- `cass` available, version 0.4.1.
- `cass` index was not found; the earlier zero-hit reading was an index artifact, not evidence absence.
- Raw stores counted: 1,069 Claude files, 453 Codex files, and 3 rollout summaries.

Findings from csd history:

1. csd did contribute direct raw-session evidence once the scan bypassed `cass`:
   - 6,940 `[RCH] local` lines.
   - 471,272 `rch exec` lines.
   - 609 `all workers at capacity` lines.
   - 655 `all workers failed preflight` lines.
   - 1,508 `rch workers disable` lines and 528 `rch workers enable` lines.
   - 12,309 `No space left on device` lines.
   - 283,731 `vmi` lines.
   - 95,523 `.rch-target` lines.

2. The first-pass conclusion that csd had little direct history was wrong. The correct conclusion is that csd's indexed search surface was unusable for this task.

3. csd still appears in local histories as a worker that can successfully run remote builds after daemon/hook recovery. That makes it useful as a known-good comparison target.

4. RCH diagnostics should make it easy to compare a failing worker against a known-good worker such as csd: toolchain, paths, disk, version, user, SSH latency, telemetry freshness, preflight result, and canary result.

5. csd's combination of raw local fallback, preflight failures, disk errors, VMI references, and manual disable/enable commands reinforces the same fleet-lifecycle issue seen everywhere else.

Third-pass csd raw-session additions:

6. csd histories include a `franken_node` one-bead workflow where the source work was complete but "remote proof is still the blocker." That is exactly the operational failure mode RCH should make actionable: the code may be ready, but proof cannot land until RCH explains and resolves admission.

7. csd histories show agents reading the `$rch` skill specifically because commands were running locally, workers were unhealthy, hooks were silent, sync failed, disk was pressured, or SSH/daemon/telemetry recovery was needed. That means the operational skill is already the de facto front door for RCH failures.

8. csd histories include panes blocked on `rch exec -- env RUSTUP_TOOLCHAIN=nightly cargo check ...`; the visible user-facing state was "blocked", not "RCH is repairing or queueing this". RCH should offer durable job IDs and reattachable status so panes do not become opaque blocked terminals.

9. csd histories also show quoted explicit-exec misuse, such as `rch exec "cargo test --test ..."` inside spawned shells. The CLI should detect single-string command invocations and print the corrected `rch exec -- cargo test --test ...` form.

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

Second-pass mac-mini-max raw-session additions:

7. mac-mini-max has the largest combined fleet signal in this pass:
   - 26,225 `[RCH] local` lines.
   - 984,755 `rch exec` lines.
   - 65,928 `RCH_REQUIRE_REMOTE` lines.
   - 2,176 `all workers unreachable` lines.
   - 8,557 `no workers passed health` lines.
   - 14,649 `no admissible workers` lines.
   - 46,380 `No space left on device` lines.
   - 137,821 `Contabo` lines and 1,758,479 `vmi` lines.
   - 455,058 `CARGO_TARGET_DIR` lines and 165,518 `.rch-target` lines.

8. The mac session directly confirmed the wrong-architecture fleet update: an interrupted `rch update --fleet` from macOS pushed a Darwin `rch-wkr` binary to Linux workers. The result was `Exec format error` on worker telemetry and offload paths. The same session confirmed root's worker binary could be a valid Linux ELF while the `ubuntu` user's `~/.local/bin/rch-wkr` was broken, so checks must verify the exact remote user/path RCH will execute.

9. The same mac session showed telemetry poll failures, disk-pressure policy decisions with `telemetry_gap`, and missing disk metrics. RCH must distinguish "no telemetry because polling is broken" from "host has bad disk pressure" and from "host is healthy but metrics are stale".

10. mac raw sessions show `rch exec "cargo check --all-targets"` being interpreted as a single binary name, followed by a correction to `rch exec -- cargo check --all-targets`. That is a CLI ergonomics problem; RCH should detect and explain quoted single-command misuse.

11. mac raw sessions also show long multi-root syncs, worker-scoped `.rch-target-*` paths, and successful remote proof lanes. That matters because some RCH paths work; the design goal is not to abandon RCH, but to make the failing paths recover the same way the healthy remote paths do.

Third-pass mac-mini-max raw-session additions:

12. mac-mini-max has direct fleet-sweep sessions for the VMI build workers. One session tasked agents to inspect `vmi1149989`, `vmi1152480`, `vmi1153651`, and `vmi1156319`; another targeted `vmi1167313`, `vmi1227854`, `vmi1264463`, and `vmi1293453`. The sweep instructions explicitly called these "RCH build workers", collected disk/swap/PSI/version/service data, and warned that `rustc`/`cargo` on those hosts is normal. This confirms the VMI fleet is the real production worker layer, not background noise in the logs.

13. mac-mini-max system-performance sessions show the host side of the same issue: local mac health reports included 95.3% swap usage, 98% root filesystem usage, and critical `/tmp`/cargo target cleanup pressure. When RCH fails open to a local machine in that condition, it can turn a remote-worker issue into local machine overload.

14. mac-mini-max sessions show `ts2` described as wedged rather than merely busy: LAN ping worked, Tailscale ping had multi-second latency, and SSH banner exchange timed out because the userspace host could not fork a session handler. This is exactly the kind of state that should become temporary bypass plus periodic recovery probe, not sticky removal.

15. mac-mini-max sessions show active remote build processes and `rsync` transfers against VMI workers, including `.rch-target-vmi...` paths and `/tmp/rch-cargo-home-vmi...` cargo homes. That supports both sides of the target-dir conclusion: per-job isolation is real and useful, but it must be managed because it creates cleanup and artifact-retrieval pressure.

16. mac-mini-max sessions show cleanup of `rch-cargo-home` and build artifacts freeing space while active builds simultaneously consume more. RCH should account for active jobs before cleanup, reserve cleanup budgets, and expose "safe to reap" state rather than leaving agents to infer it from `lsof`, `ps`, and path names.

17. mac-mini-max histories contain a wrong-architecture packaging example (`Mach-O 64-bit executable arm64`) alongside the earlier RCH worker `Exec format error` story. Fleet update tooling must verify the binary format on the remote host and for the exact remote user before switching worker binaries.

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

### P0. Incident Ledger and Readiness Split

RCH should record its own compact incident evidence instead of forcing agents to reconstruct incidents from stale CASS indexes and raw session logs.

Acceptance criteria:

- Append an incident event whenever a worker changes live eligibility, a selection run rejects all workers, a command falls back locally, a daemon/socket check fails, telemetry goes stale, a capability refresh changes a worker, or artifact retrieval misses expected outputs.
- Every event includes a stable reason code, command fingerprint, worker id if applicable, project id, selected mode, and whether local fallback was allowed.
- `rch status` separates daemon reachability, configured desired workers, live healthy workers, and command-admissible workers.
- `remote_ready` is never shown without also stating whether at least one worker is admissible for the requested command shape.
- `rch diagnose --json -- <command>` can replay the last relevant incident chain for that command and explain the decisive blocker.

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
- Volatile files such as `.git/index.lock` are excluded or handled as retryable vanished files.

### P1. Artifact Retrieval Cost and Precision

Make artifact retrieval follow the actual target dir and avoid pathological small-file returns.

Acceptance criteria:

- Retrieval diagnostics include phase timings, file count, byte count, and selected artifact patterns.
- RCH warns when a pattern expands to tens of thousands of files.
- Artifact collection can use a manifest or explicit artifact list instead of broad recursive target globs.
- Rewritten `CARGO_TARGET_DIR` paths are reflected in artifact search patterns.

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
- Capabilities include installed Rust targets such as `wasm32-unknown-unknown`.
- `rch-wkr` validation runs as the configured remote user and checks the exact executable path.

### P1. Explicit Exec Ergonomics

Make `rch exec` failures self-explanatory for agents.

Acceptance criteria:

- Detect `rch exec "cargo check --all-targets"` style misuse and print the corrected `rch exec -- cargo check --all-targets` form.
- In explicit `rch exec` mode, output whether the command ran remotely, ran locally, or was rejected as non-compilation.
- JSON output includes `local_or_remote`, `selected_worker`, `classification`, `reason_code`, and remediation.

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
- Skills teach raw-session fallback when `cass` is stale, absent, or misses tool output.
- Skills teach the CASS source-state check: `cass sources list --json`, `cass health --json`, then raw `rg` over `~/.claude/projects`, `~/.codex/sessions`, `~/.gemini/tmp`, and backup stores when indexes are absent or stale.
- Skills document wrong-architecture fleet update risk, wasm target checks, and volatile sync-file handling.

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
wasm32-unknown-unknown
Exec format error
rsync failed
file has vanished
daemon.log
daemon.err
```

## Final Diagnosis

The most important issue is not that individual workers fail. Workers will fail. Cloud machines will pause. Disk will fill. SSH will time out. The real RCH bug is that transient failures are allowed to mutate or shrink the effective worker pool in ways that do not automatically heal.

RCH should treat the worker pool as desired state plus live eligibility. Temporary failure should affect only live eligibility. Permanent disable should require an explicit permanent action. Recovery should be automatic, diagnostic, and visible.

If RCH implements temporary bypass, auto-rejoin, desired-state reconciliation, loud fallback, hook/daemon/doctor self-healing, robust dependency sync, and target-dir/disk pressure management, most of the repeated agent-session failures would turn from "agents get stuck and give up" into "RCH explains the problem, routes around it, and repairs the pool when the worker recovers."
