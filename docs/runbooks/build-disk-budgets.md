# Runbook: Build Disk Budgets

RCH assigns a disk growth budget to recognized compilation commands and explicit
job requests, checks that budget during worker admission, and supervises the
remote command while it runs. This supplements the existing disk allowance per
CPU slot. A slot alone does not establish that a particular build will fit.

[Issue #121](https://github.com/Dicklesworthstone/remote_compilation_helper/issues/121)
reported a FrankenNumPy workspace test placed on `hz3` with approximately 33 GiB
free, or 3.7% of its filesystem. Its target directory reached approximately
21 GiB before the shared worker exhausted its disk. That failed partial output
is evidence of a large build; it does not prove that 21 GiB would complete it.

## How RCH estimates a build

The daemon combines the project identity, requested command, and recorded build
history. The exact history key includes command options and the validated Cargo
profile environment bound into the command before selection. A successful small
package check cannot establish the requirement for a different workspace test.

Without usable history, Rust commands start with these conservative estimates:

| Command family | Ordinary command | Command with a broad build flag |
| --- | ---: | ---: |
| Cargo test, nextest, bench | 24 GiB | 32 GiB |
| Cargo build, zigbuild | 8 GiB | 16 GiB |
| Cargo check, clippy | 2 GiB | 8 GiB |
| Cargo doc | 8 GiB | 8 GiB |

The broad flags are `--workspace`, `--all`, `--all-targets`, and `--all-features`.
These are command-based estimates, not a dependency graph or a prediction of
each crate's output. Other recognized command families have their own defaults;
an explicit job without a recognized compilation command starts at 16 GiB.

RCH reserves additional growth using this formula, rounded up to whole GiB:

```text
growth budget = ceil(estimated footprint + max(25% of that footprint, 2 GiB))
```

A request's explicit `disk_headroom_gib` can raise this minimum. It cannot lower
the budget below the estimate. The worker's free-space floor is added separately.

History uses the largest unexpired measurement, preserving high-water samples
within a bounded window of eight samples per key and a 30-day age limit. The
footprint book is stored beside the history log as `history.footprints.json`.
A missing, expired, or unreadable book falls back to the conservative defaults.

Only a successful, attributed measurement of **total peak allocated output**
for the exact project and command can establish an estimate below its default.
Warm target directories are included in that total, so a near-zero incremental
rebuild does not erase the size of the existing output pool. Failed builds,
broader command-family evidence, and legacy changes in filesystem free space
can raise estimates but cannot independently establish a smaller complete build.
Cancelled builds do not teach a complete footprint. Free-space changes on a
worker shared by simultaneous jobs are not attributed to one job as output.

### The 21 GiB incident and smaller controls

With the default 10 GiB floor and no other active reservations:

| Available evidence | Growth budget | Required free space | Disk-budget decision with 33 GiB free |
| --- | ---: | ---: | --- |
| No history for `cargo test` | 30 GiB | 40 GiB | Refuse this worker |
| Workspace test with only a failed 21 GiB partial output | 40 GiB | 50 GiB | Refuse this worker; retain the 32 GiB workspace estimate |
| Hypothetical successful exact-command measurement of 21 GiB | 27 GiB | 37 GiB | Refuse this worker |
| Successful exact-command measurement of 2 GiB | 4 GiB | 14 GiB | Admit if the other worker guards pass |
| Cold ordinary `cargo check` | 4 GiB | 14 GiB | Admit if the other worker guards pass |

The small control does not require pretending the reported failed build
succeeded. It uses separate, successful output evidence. These rows describe the
per-build admission calculation; slot availability, health, capabilities, and
the existing disk-pressure policy still apply. In particular, 3.7% free also
crosses the default 5% critical ratio rule, independently of this calculation.

## Reservations and fresh capacity

Admission requires all of the following:

- A valid build-filesystem free and total capacity sample. Generic `/tmp` disk
  telemetry alone is insufficient when the actual build storage differs.
- A current worker endpoint and probe generation, with a sample no older than
  90 seconds. CPU telemetry and pressure reevaluation do not refresh disk age.
- Enough free space for the new growth budget, every active growth reservation
  on that worker, and the largest applicable free-space floor, counted once.
- Working durable ownership accounting. An accounting failure prevents new
  guarded admission.

Selection previews and the authoritative admission check use the same budget.
The authoritative check and reservation update share the ownership lock, so
concurrent selections cannot independently spend the same available headroom.
Active reservations stay whole even after their output consumes disk space.
This deliberately conservative accounting can reduce concurrency on a busy
worker; observed growth is not credit for another job.

Completing a job releases its reservation once, but does not claim its artifacts
have been deleted. Before the released allowance can fund another admission,
a new capacity probe must start strictly after completion. A probe already in
flight at completion is insufficient. Interrupted or unconfirmed ownership
remains reserved through retries and recovery; elapsed time or a reused PID is
not evidence that the old work stopped.

The worker checks capacity again immediately before launching the command. Its
private, locked ledger at `/var/tmp/rch-build-disk-<uid>` coordinates guarded
jobs using the same Unix account, including jobs from different dispatchers.
It charges the full budget on each involved filesystem and preserves the
largest active floor. Entries are retired when the recorded boot has changed
or the process group has no executing members, not by a timeout or a partial
directory scan. Do not remove this ledger to manufacture free capacity.

## Runtime enforcement and failure handling

The supervisor measures allocated blocks in the remote workspace and the managed
Cargo target, temporary, and Go output/cache directories supplied by the
execution plan. It checks available space on every filesystem containing those
roots. Both SSH and direct `rch-wkr execute` supervision include the working
directory in the output scan. Physical directory identities are verified;
symlink output roots, replacement roots, scan failures, and unaccounted
filesystem changes cannot silently become zero usage. Hard links and nested
output roots are deduplicated within a scan.

The initial output size is the baseline. The job budget limits additional
allocated growth above it, while the receipt records the total peak output for
future estimates. Runtime checks currently use a 250 ms control interval,
approximately two-second output scans, a one-second free-space probe deadline,
and a 30-second output-scan deadline. Scans run separately from free-space
sampling. An independent guardian stops the owned process group if supervision
or its heartbeat is lost.

A complete usage receipt certifies that execution ended, remaining writers
stopped, and the final output scan passed. It also binds the original exit
status. Completion does not imply a successful build: ordinary nonzero compiler
or test exits are preserved, and only exit zero may establish a smaller learned
footprint. A missing or mismatched status follows uncertain-execution recovery.

The free-space stop threshold includes the configured floor and an extra buffer:
at least the smaller of 256 MiB and one-sixteenth of the growth budget, with a
one-byte minimum, raised when the observed aggregate write rate requires more
room. The rate component reserves roughly two seconds of the measured decline
in free space. Reaching this threshold or exceeding the growth budget stops the
owned build group and preserves its output for diagnosis and recovery.

Typed failures use **`RCH-E330`** (`BuildDiskBudgetExceeded`):

| Evidence | Recovery behavior |
| --- | --- |
| Confirmed refusal before command launch (`started: false`) | After the daemon acknowledges release, RCH may select another eligible worker while excluding the refusing worker. Exhausting alternatives reports E330. |
| Command started, or spawning it may have started it (`started: true`) | Stop the owned group and report the failure. Do not automatically replay the command locally or on another worker. |
| Missing or invalid receipt, unknown execution state, or unacknowledged release | Retain uncertain ownership and use the existing no-replay recovery path. A transport error does not prove a safe pre-start refusal. |

The detailed reason distinguishes `admission`, `growth`, `free_floor`,
`monitor_unavailable`, and `interrupted`. A confirmed `free_floor` failure also
feeds the existing worker disk-pressure recovery path. Exceeding one project's
growth budget does not by itself prove the entire disk is full.

## Worker requirements

Use Python 3.8 or newer with its standard library. The embedded supervisor runs
through `python3 -I -S`; no Python package installation is needed. The minimum
version describes the implementation's API requirements, not a claim that every
Python version or worker platform has been tested.

Linux requires procfs in the active PID namespace, readable kernel boot and
process-start identities, and `setsid` for the tracked SSH launch. macOS uses
Python's `setsid` syscall and the updated `rch-wkr process-identity` helper on
the remote PATH, together with native boot-session and process information.
The accounting directory and receipt locations must support the required Unix
permissions, locking, and atomic replacement operations.

Missing Python, unsupported platforms such as Windows, or unverifiable process
identity refuse guarded execution before the workload starts. If monitoring
becomes unavailable after launch, the job is stopped and cannot be replayed
automatically. Linux uses pidfds where available to terminate surviving
background descendants safely; older Python/kernel combinations and macOS fail
closed when such descendants require cleanup without a safe individual-process
signal mechanism. Ordinary foreground completion does not require that fallback.
See [worker recovery](worker-recovery.md) for ownership and cancellation recovery.

## Configuration and diagnosis

The existing selection settings remain independent controls:

```toml
[selection]
min_free_gb = 10.0
disk_gb_per_slot = 10.0
```

Despite the legacy `gb` names, these capacity calculations use GiB.
`min_free_gb` defines the per-build protected floor and is rounded up to whole
GiB for the budget sent to the worker. Omitting it retains the 10 GiB default.
An explicit `min_free_gb = 0.0`, or `None` in a programmatic `SelectionConfig`,
opts out of that configured floor. It does not disable growth budgets, shared
reservations, runtime write-rate buffers, per-slot derating, or the separate
critical disk-pressure rules. Invalid negative or non-finite floors cannot
silently remove protection.

`disk_gb_per_slot` remains a positive allowance for deriving effective slot
capacity; changing it does not override a particular project's growth budget.
The separate `disk_critical_free_ratio` and optional
`disk_critical_ratio_cap_gb` still control the ratio-based critical rule. Restart
the daemon after selection-policy changes. Update the dispatcher, daemon, and
worker together: a new dispatcher talking to an older daemon uses a conservative
cold command budget and a 10 GiB floor, without the new daemon history policy.

To investigate a refusal, inspect the selected worker and the daemon's capacity
observations:

```bash
rch workers probe hz3 --verbose
rch workers list --verbose
rch status --remediation
```

`disk_headroom_unknown` means a valid build-storage sample or durable accounting
is unavailable. `disk_headroom_stale` requires a current daemon probe, including
the probe-after-completion rule. `disk_headroom_insufficient` reports the free
and required GiB, including active reservations and the floor. Inspect space on
the actual remote build and target filesystems, and allow confirmed completion
and a fresh probe to update capacity before diagnosing a retained reservation
as a leak. Use the [worker recovery runbook](worker-recovery.md) for uncertain
process ownership; do not kill a process using only an old numeric PID.

Callers can reduce artifact size with validated Cargo profile settings such as
`CARGO_PROFILE_TEST_DEBUG=0` and `CARGO_PROFILE_TEST_INCREMENTAL=false`.
See [forwarding Cargo artifact-size settings](configuration-troubleshooting.md#forward-cargo-artifact-size-settings)
for accepted settings, custom profiles, shell precedence, and the operator
opt-out. Changing profile settings creates different command evidence; RCH does
not assume an unmeasured profile change has already made a build small.

## Limits of this protection

This is admission control and polling, not a filesystem quota. A sufficiently
fast write burst can consume the buffer before the next observation or process
termination. Byte budgets do not reserve inodes or replace filesystem quota
accounting. Large trees can exceed the scan deadline and be refused or stopped.

The worker ledger coordinates one Unix account. Other users and external
writers are visible through falling free space, but do not participate in that
ledger's reservations. A command that writes outside the declared roots is not
fully charged as job output; writes to an unobserved filesystem are outside the
monitor. Source uploads happen before the runtime baseline and retain their
existing transfer protections. Concurrent changes to a shared output pool can
also make one job's measured footprint conservatively include another's output.

Process groups do not contain children that deliberately start another session.
Use worker service or cgroup containment when stronger process isolation is
required. The monitor does not delete artifacts or make an interrupted command
safe to rerun. Diagnose the retained output and establish terminal ownership
before choosing an explicit retry.

## Implementation references

- [Budget defaults and arithmetic](../../rch-common/src/types.rs)
- [Footprint provenance and retention](../../rchd/src/headroom.rs)
- [Ownership and admission accounting](../../rchd/src/history.rs)
- [Capacity freshness and pressure policy](../../rchd/src/disk_pressure.rs)
- [Worker disk supervisor](../../rch-common/build_disk_monitor.py)
- [SSH supervision and receipts](../../rch/src/transfer.rs)
