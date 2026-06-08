# Design: Tier-1 Pooled Target Directories

**Status:** Draft / Proposal
**Author:** (research agent)
**Date:** 2026-06-01
**Scope:** `rch` orchestrator + `rch-wkr`/`rchd` worker side. Design only — no implementation.

---

## 1. Problem statement

### 1.1 What rch does today

When a delegated build forwards `CARGO_TARGET_DIR` (or rch decides to do
target-sync), rch gives **every job its own private remote target directory** on
the worker. The directory name is constructed in
[`rch/src/hook.rs:3255-3287`](../../rch/src/hook.rs):

```rust
// rch/src/hook.rs:3286
format!(".rch-target-{safe_worker_id}-{job_id}-{timestamp}-{sequence}")
```

where:

- `safe_worker_id` is the sanitized worker id,
- `job_id` is `job-<build_id>` or, lacking a build id, `pid-<pid>`
  ([`hook.rs:3276-3278`](../../rch/src/hook.rs)),
- `timestamp` is `SystemTime::now()` nanoseconds
  ([`hook.rs:3279-3282`](../../rch/src/hook.rs)),
- `sequence` is a process-global monotonic `AtomicU64`
  ([`hook.rs:3256-3257`, `3283-3284`](../../rch/src/hook.rs)).

This name is generated once per build in
[`hook.rs:6032-6034`](../../rch/src/hook.rs) (only when
`forwarded_cargo_target_dir.is_some()`), and threaded into the primary transfer
pipeline via `with_remote_cargo_target_dir_name(...)`
([`hook.rs:6073-6075`](../../rch/src/hook.rs)). The pipeline then forces the
worker build's `CARGO_TARGET_DIR` to `<remote_path>/<that-name>`.

The remote project path itself is `<remote_base>/<project_id>/<project_hash>`,
or an explicit topology override like `/data/projects/<repo>`
([`rch/src/transfer.rs:926-931`, `583-608`](../../rch/src/transfer.rs)). So in
practice the on-disk layout per worker is:

```text
/data/projects/<repo>/
  .rch-target-css-job-29863360510034113-1780109474952075077-0/
  .rch-target-css-job-29863360510034114-1780109480001120033-1/
  .rch-target-css-job-29863360510034115-1780109511778231044-2/
  ... one per job, forever ...
```

### 1.2 Why this hurts

Two compounding failures:

1. **Unbounded accumulation.** The name is unique per job by construction
   (`job_id` + `timestamp` + `sequence`), so N jobs produce N directories with
   **no GC at creation or completion**. Each per-repo target dir is observed at
   **0.5-11 GB** (an active dir was seen accumulating ~11.5h of artifacts —
   [`transfer.rs:2229`](../../rch/src/transfer.rs)), with **dozens per repo per
   worker**. Across the 13-host fleet this reached **~1.6 TB** that had to be
   hand-reclaimed, and repeatedly drives workers to disk-full / offline.

2. **Cold incremental cache every job.** Because each job gets a *fresh* target
   dir, cargo's incremental compilation cache, fingerprint database, and
   dependency `.rlib`s start **empty on every build**. An edit-fix loop that
   should be near-instant recompiles the world each time: slower builds *and*
   more disk (each cold build re-materializes the full dependency graph).

These are the two halves of the same root cause: **per-job isolation buys
collision-freedom and trivially-correct cleanup semantics at the cost of all
cache reuse and all disk bounds.**

### 1.3 Why per-job isolation exists (the constraint we must preserve)

Per-job dirs solve real problems that any replacement must still solve:

- **Concurrent-job collision.** Multiple agents (or one agent's parallel jobs)
  can build the *same repo* on the *same worker* simultaneously. Two
  `cargo build` invocations sharing one target dir must not corrupt each
  other's fingerprints or partial artifacts.
- **Trivially-correct cleanup.** A per-job dir is conceptually owned by one job,
  so reasoning about when it is safe to delete *seems* simple (it is not — see
  the reaper below).
- **Isolation across incompatible toolchains.** Different builds of the same
  repo may use different `rustc` versions; their incremental caches are
  mutually incompatible and must not share a directory.

The pooled design below must preserve all three guarantees while bounding disk
and restoring cache reuse.

---

## 2. Proposed design

### 2.1 Core idea

Replace the per-**job** key with a per-**(repo, toolchain)** key. All jobs for
the same repo using the same toolchain share **one** target directory and
therefore one warm incremental cache:

```text
/data/projects/<repo>/.rch-target-<toolchain-key>
```

Example layout (contrast with section 1.1):

```text
/data/projects/<repo>/
  .rch-target-nightly-2026-05-01-a1b2c3/   # all nightly-2026-05-01 jobs
  .rch-target-stable-1.87.0-d4e5f6/        # all stable jobs
```

N jobs on one toolchain -> **1** directory. The number of pooled dirs per repo is
bounded by the number of *distinct toolchains* actually used (typically 1, rarely
more than 2-3), not by job count.

### 2.2 Keying scheme

```text
pool_name = ".rch-target-" + toolchain_key
toolchain_key = sanitize(toolchain.rustup_toolchain()) + "-" + short_hash(toolchain.full_version)
```

The toolchain identity already exists in rch:
[`ToolchainInfo`](../../rch-common/src/toolchain.rs) carries `channel`, optional
`date`, and `full_version`
([`rch-common/src/toolchain.rs:16-24`](../../rch-common/src/toolchain.rs));
`rustup_toolchain()` ([`toolchain.rs:43-48`](../../rch-common/src/toolchain.rs))
yields the canonical `stable` / `nightly-2026-05-01` / `1.87.0` string that is
*already* used to wrap the remote command as `rustup run <toolchain>`
([`rch-common/src/toolchain.rs:76-87`](../../rch-common/src/toolchain.rs), via
[`transfer.rs:959-974`, `1554-1556`](../../rch/src/transfer.rs)). The toolchain
is detected per build from `rust-toolchain.toml` / legacy `rust-toolchain` /
`rustc --version` ([`rch/src/hook.rs:429-432`](../../rch/src/hook.rs) ->
[`rch/src/toolchain.rs:36-55`](../../rch/src/toolchain.rs)).

**Why toolchain MUST be in the key:** cargo's incremental cache, fingerprints,
and proc-macro/`.rlib` artifacts are keyed to a specific `rustc`. Sharing one
target dir across two `rustc` versions does not merely miss the cache — it forces
cargo to invalidate and rebuild on every toolchain switch, and (worse) risks
stale artifacts being picked up. `full_version` is folded into the hash so that
`nightly` (which floats) is distinguished by the actual resolved compiler, not
just the channel label.

> **Edge case — floating `nightly`.** Bare `nightly` with no pinned date floats
> day to day. If only `channel`+`date` were keyed, two different *actual*
> nightlies would collide in one pool. Including a `full_version` hash gives a
> distinct pool per real compiler; old nightly pools then age out via the
> eviction/reaper policy (sections 4.3 and 5).

The remaining unique tokens from the old scheme (`job_id`, `timestamp`,
`sequence`) are **dropped from the directory name** — that is precisely the
change that collapses N -> 1.

### 2.3 What stays the same

- Remote project path derivation (`remote_path()`,
  [`transfer.rs:926-931`](../../rch/src/transfer.rs)) is unchanged; only the
  child target-dir name changes.
- `CARGO_TARGET_DIR` is still force-injected to the rch-chosen dir
  ([`hook.rs:3245-3253`](../../rch/src/hook.rs),
  [`hook.rs:6070-6075`](../../rch/src/hook.rs)); local target-dir flags are still
  stripped from the command ([`hook.rs:3306-3347`](../../rch/src/hook.rs)).
- Artifact sync-back of the custom target dir
  ([`hook.rs:6515-6598`](../../rch/src/hook.rs)) is unchanged in mechanism.

---

## 3. Concurrency safety

### 3.1 The new hazard

Per-job dirs made concurrent same-repo builds trivially safe (disjoint dirs).
Pooling reintroduces **concurrent writers to one target dir**. We must decide how
two simultaneous `cargo build`s against `.rch-target-<toolchain-key>` coordinate.

### 3.2 Option A — rely on cargo's own lock

Cargo takes an advisory lock on the target directory (`.cargo-lock` /
package-cache lock). A second `cargo` invocation against the same target dir
**blocks** until the first releases, then proceeds (and benefits from the now-warm
cache). This is already battle-tested: it is exactly how two terminals building
one local project behave.

- **Pros:** zero new rch coordination code; correctness delegated to cargo;
  serialized builds share a warm cache (the second build is often near-instant).
- **Cons:** a second job *waits* for the whole first build (no parallelism for
  same-repo+toolchain jobs). A hung/very long build (the ~11.5h dir from
  [`transfer.rs:2229`](../../rch/src/transfer.rs)) can stall queued jobs. Cargo's
  lock is process-level on the worker; rch must ensure it does not itself impose
  a *shorter* command timeout that kills a job merely waiting on the lock.

### 3.3 Option B — rch-level coordination

rch maintains its own per-`(repo, toolchain)` coordination so it controls
queueing/timeouts rather than discovering contention only when cargo blocks:

- **B1 — strict serialization:** an rch-held async mutex keyed by
  `(worker, repo, toolchain)`; jobs queue in rch with rch-controlled timeouts and
  observability. Equivalent throughput to Option A but with rch-visible queue
  depth and the ability to fall back to a private dir if the wait exceeds a
  threshold.
- **B2 — small bounded pool:** keep a *small* fixed number `k` (e.g. 2) of pooled
  dirs per `(repo, toolchain)`, round-robined. Restores limited parallelism
  (`k`-way) while keeping disk bounded at `k` dirs instead of N. Each of the `k`
  still serializes internally via cargo's lock.

rch currently has **no** build-level mutex or semaphore around target dirs (the
only "lock" tokens in `transfer.rs` are `Cargo.lock`/lockfile *filenames* for
sync, e.g. [`transfer.rs:36-42`](../../rch/src/transfer.rs) — not concurrency
primitives). So Option B is net-new machinery.

### 3.4 Throughput trade-off

| Model | Disk per repo | Same-repo parallelism | Cache reuse | New code |
|---|---|---|---|---|
| **Per-job (today)** | N dirs (unbounded) | N-way (max) | none (always cold) | — |
| **A: pooled + cargo lock** | 1 dir | 1 (serialized) | max (warm) | minimal |
| **B1: pooled + rch serialize** | 1 dir | 1 (serialized) | max (warm) | medium |
| **B2: pooled, pool of k** | k dirs | k-way | high | medium |

### 3.5 Recommendation

**Default to Option A (pooled, one dir per `(repo, toolchain)`, rely on cargo's
lock), with B2 (`k`-way pool) available as an opt-in escape valve for
high-contention repos.**

Rationale: Option A is the smallest, lowest-risk change that delivers ~all the
disk win (N -> 1) and ~all the cache win. The headline cost — loss of same-repo
parallelism — is mostly illusory: in the dominant rch workload (one agent doing
an edit-fix-build loop on one repo), builds are *already* effectively serial, and
serialization onto a warm cache is **faster end-to-end** than N cold parallel
builds. We must, however, ensure rch's command timeout does not kill a job that
is merely *waiting* on cargo's lock (treat lock-wait time as non-build time, or
size the timeout accordingly — see section 7). For the rare genuinely-parallel
same-repo workload, an operator sets `pool_width = k` to recover `k`-way
concurrency at `k` times the (still bounded) disk.

---

## 4. Disk & performance impact

### 4.1 Disk reduction

- **Count:** per repo, dirs drop from *job-count* (dozens) to *toolchain-count*
  (approximately 1). The ~1.6 TB fleet figure was dominated by dozens of
  0.5-11 GB stale per-job dirs per hot repo; pooling removes the multiplier
  outright.
- **Size:** one pooled dir is roughly the size of a single warm target dir for
  that repo+toolchain (it does *not* grow per job — it is reused in place). It
  still grows over time within itself (stale incremental artifacts), bounded by
  the eviction policy below.

### 4.2 Performance

- Warm incremental cache across the edit-fix loop: subsequent builds recompile
  only changed crates instead of the full graph — the central reason cargo has
  incremental compilation at all.
- Less I/O churn: dependency `.rlib`s are materialized once per toolchain, not
  once per job.

### 4.3 Sizing & eviction policy

Pooled dirs are *long-lived*, so they need their own bound:

1. **Per-pool soft cap (size-triggered prune).** When a pool exceeds a size cap
   (e.g. configurable, default a few GB above the project's typical warm size),
   run `cargo` housekeeping or prune stale incremental fragments — *never* a blind
   `rm` of the whole dir during active use.
2. **Per-repo LRU across toolchains.** Keep at most the M most-recently-used
   toolchain pools per repo (default M small, e.g. 2); evict the
   least-recently-used whole pool when a new toolchain appears. This naturally
   ages out floating-nightly pools (section 2.2).
3. **Whole-repo abandonment** is handled by the Tier-2 reaper / Tier-3 sbh as a
   backstop (section 6), not by Tier-1 itself.

---

## 5. Migration path

### 5.1 Feature flag & coexistence

- Introduce a config/env flag, e.g. `RCH_TARGET_POOLING=off|pooled|pool:<k>`
  (default `off` initially, flipping to `pooled` after soak). When `off`, the
  existing per-job name from [`hook.rs:6032-6034`](../../rch/src/hook.rs) is used
  unchanged.
- The decision lives at the single call site that builds
  `remote_cargo_target_dir_name_override`
  ([`hook.rs:6032-6034`](../../rch/src/hook.rs)): in pooled mode it calls a new
  `pooled_cargo_target_dir_name(&toolchain)` instead of
  `remote_cargo_target_dir_name(build_id, worker_id)`. Everything downstream
  (`with_remote_cargo_target_dir_name`, env injection, sync-back) is agnostic to
  how the name was chosen.

### 5.2 Not breaking in-flight jobs

- Per-job and pooled dirs have **disjoint name shapes** (per-job:
  `.rch-target-<worker>-job-<id>-...`; pooled: `.rch-target-<toolchain-key>`), so
  a flag flip never reuses or clobbers a directory an in-flight job is writing.
- Old per-job dirs left over from before the flip are simply abandoned and aged
  out by the reaper (they match `REAP_GLOBS`; pooled dirs do **not** — see
  section 6).
- Rollback is a flag flip back to `off`; no on-disk migration needed.

### 5.3 Worker (Tier-2) reaper changes — see section 6.

---

## 6. Interaction with Tier-2 (reaper) and Tier-3 (sbh)

### 6.1 Today's two reapers (both target *per-job* dirs)

- **Orchestrator-side:** `TransferPipeline::reap_stale_sibling_per_job_target_dirs`
  ([`transfer.rs:2247-...`](../../rch/src/transfer.rs)), which removes sibling
  per-job dirs idle for `idle_hours` (default 12h), never the current job's dir,
  using the shared predicate in
  [`rch-common/src/stale_target_reap.rs`](../../rch-common/src/stale_target_reap.rs).
- **Worker-side (Tier-2, new):** the periodic `rchd` background sweep in
  [`rchd/src/stale_target_reap.rs`](../../rchd/src/stale_target_reap.rs), which
  every `interval_mins` SSHes each worker and applies the **same** idle predicate
  under `remote_base` (default `/data/projects`).

Both match **`REAP_GLOBS = [".rch-target-*-job-*", ".rch-target-*-pid-*"]`**
([`rch-common/src/stale_target_reap.rs:34`](../../rch-common/src/stale_target_reap.rs)).
By design these globs match **only the per-job shape** and would **not** match a
pooled `.rch-target-<toolchain-key>` dir.

### 6.2 How pooling reduces the reaper's job

The per-job reapers exist *because* per-job dirs accumulate without bound. Pooling
removes that accumulation at the source (Tier-1), so the reapers' role shrinks
from "GC the constant stream of dead per-job dirs" to "backstop for whole-repo
abandonment." Concretely:

- The per-job globs keep running to mop up **legacy** per-job dirs and any
  residual `off`-mode jobs — they remain correct and harmless.
- A **new pooled-dir reaper rule** is added: reap a pooled dir
  (`.rch-target-<toolchain-key>`) only when the **entire repo** has been idle for
  a long window (a multiple of the per-job idle threshold — a pool is *meant* to
  persist between jobs, so its idle threshold must be much longer than a per-job
  dir's). The same descendant-mtime staleness test applies
  ([`transfer.rs:2237-2245`](../../rch/src/transfer.rs)): never reap a pool with
  recent deep file activity.

### 6.3 Tier-3 (sbh)

sbh was *wrongly* relied upon as the cleanup mechanism for rch's per-job sprawl
(per project memory: "rch leaves `.rch-target-*` dirs with NO GC — sbh is the only
cleanup mechanism"). This coupling is dangerous: sbh's heuristics have repeatedly
mis-deleted source dirs under `/data/projects`. **Tier-1 pooling shrinks the
problem sbh was expected to solve to near-zero**, letting sbh return to its proper
role as a last-resort disk-pressure ballast rather than rch's de-facto GC.

---

## 7. Risks & mitigations

| # | Risk | Mitigation |
|---|---|---|
| 1 | **Cache poisoning across jobs** — one job's bad/partial artifacts corrupt a shared cache and break a later job. | cargo's fingerprinting normally isolates this; on a detected build failure of a kind consistent with cache corruption, fall back to a one-shot private dir and optionally mark the pool for a clean rebuild. Keep a per-pool "last good toolchain hash" marker; mismatch -> wipe-and-rebuild that pool. |
| 2 | **Lock contention / starvation** — many same-repo jobs queue on cargo's lock; a long build starves the rest. | Default Option A serializes (acceptable for the edit-loop workload). Provide `pool:<k>` for parallel workloads. Ensure rch's command timeout does **not** count lock-wait as build time (else a queued job is killed for the crime of waiting). Surface queue depth in status. |
| 3 | **Stale incremental artifacts -> miscompile** — reused fingerprints mask a needed rebuild. | This is a cargo correctness property, not introduced by pooling (local devs share one target dir routinely). Mitigate residual risk with the size-cap prune (section 4.3) and a manual `--fresh`/pool-reset escape hatch; key the pool on `full_version` so a compiler change always lands in a different pool. |
| 4 | **Toolchain drift** — floating `nightly` resolves to a new compiler; old pool becomes incompatible/abandoned. | `full_version` in the key forces a new pool per real compiler (section 2.2). LRU-evict old toolchain pools per repo (section 4.3 item 2). |
| 5 | **Disk-fill of a single hot pooled dir** — one very active repo's pool grows large. | Per-pool soft size cap with prune (section 4.3 item 1); Tier-2/Tier-3 backstops; the *count* is already bounded (1 per toolchain), so worst case is bounded by one warm target, not N. |
| 6 | **Concurrent flag-flip / mixed-mode races.** | Disjoint name shapes (section 5.2) make pooled and per-job dirs non-overlapping; reaper globs are shape-specific, so neither mode reaps the other's live dirs. |

---

## 8. Open questions for the human

1. **Default concurrency model:** accept the recommended Option A (serialize via
   cargo's lock) as the shipping default, or start with `pool:2` to preserve some
   same-repo parallelism out of the box?
2. **Pool idle threshold for the new Tier-2 rule:** what multiple of the 12h
   per-job idle threshold is right for whole-pool reaping (24h? 72h? a week)? A
   pool is supposed to survive between work sessions, so this must be generous.
3. **Per-repo toolchain-pool LRU `M`:** is `M=2` enough, or do real repos
   regularly juggle >2 toolchains (stable + pinned nightly + MSRV check)?
4. **Timeout accounting:** confirm the desired semantics for command timeout vs.
   cargo lock-wait (don't kill a job that is merely queued). Does rch currently
   distinguish "waiting" from "building"? (No build-level mutex exists today —
   section 3.3.)
5. **`full_version` availability/cost:** `detect_toolchain` falls back to
   `rustc --version` ([`rch/src/toolchain.rs:53-54`](../../rch/src/toolchain.rs));
   is `full_version` reliably populated for the pinned-file cases, and is the
   extra `rustc` invocation per build acceptable, or should the toolchain key be
   cached per repo?
6. **Rollout ordering:** flip the flag fleet-wide at once, or canary on the
   highest-churn hosts (ts2/trj) first given the disk-fill history?
7. **Cache-poisoning detection signal:** is there a reliable stderr/exit-code
   signature for cache corruption we can hook (mirroring the existing
   `is_toolchain_failure` fallback at [`hook.rs:585-589`](../../rch/src/hook.rs))?
