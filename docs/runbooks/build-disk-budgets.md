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

Cold history continues to use **total peak allocated output**. A successful,
attributed measurement for the exact project and command can establish a cold
estimate below its default. Failed builds, broader command-family evidence,
and legacy changes in filesystem free space can raise estimates but cannot
independently establish a smaller complete build. Cancelled builds do not teach
a complete footprint. Legacy totals are never reinterpreted as incremental
measurements, and a small warm rebuild cannot erase a larger cold requirement.

### Retained Cargo pools and incremental admission

[Issue #132](https://github.com/Dicklesworthstone/remote_compilation_helper/issues/132)
reported 81–95 GB retained target pools charged repeatedly against approximately
220 GB free, although each incremental check added only hundreds of megabytes.
The daemon now maintains separate, versioned incremental observations for the
exact project, command, and worker endpoint. The book retains at most eight
pools per key and eight samples per pool, with the same 30-day expiry and
high-water policy as cold history.

A successful observation first establishes a pool anchor. A subsequent
successful observation must begin at that exact anchor before its additional
space can qualify a smaller reservation. The worker binds a pool to its physical
target path, boot, device, inode, and a fingerprint of the tree's names and
allocation metadata. Equal directory sizes do not prove equal retained state.
Reading files does not invalidate the fingerprint; changing or replacing them
does. Metadata collection is capped at 100,000 entries. Incomplete, changing,
oversized, or expired evidence cannot authorize a smaller reservation.

Incremental observations conservatively charge:

```text
unproven baseline = total starting output - verified starting target pool
measured requirement = unproven baseline
                     + max(peak new/modified output, peak free-space decline)
```

Only the verified target pool receives retained allocation credit. Source trees
and other cache/output roots remain charged. New or modified inodes are counted
without subtracting old artifacts that disappeared concurrently. Rewriting an
existing inode can charge its entire current allocation, even when its final
size is unchanged. Other writers can inflate the free-space decline; RCH never
divides shared usage into unsupported per-job estimates. The minimum measured
footprint remains 1 GiB, followed by the ordinary growth margin and protected
floor.

The proof covers the selected target, not every directory with a cache-like
name. Large sibling target pools inside the scanned source tree remain part of
the unproven baseline and can limit the reduction. They are not deleted or
silently excluded. This is a conservative scope limit when several retained
pools share one source mirror.

The smaller reservation carries its qualifying pool proofs and the cold
fallback requirement in durable ownership. The worker verifies a matching pool
before admission and launch. A mismatch or an unfunded current source/cache
baseline requires a **new cold reservation**; the worker cannot enlarge its
allowance independently. After confirmed release, `rch exec` refreshes capacity
and permits one cold reselection. A failed refresh does not waive freshness.
An ordinary positive client headroom request remains a minimum and permits
verified warm-pool credit. The client marks the cold retry explicitly and omits
warm capability on that request, so concurrently learned cold requirements
cannot turn the retry into another conditional reservation. Admission previews
use the same minimum and warm capability as ordinary durable execution.

New ownership snapshots use format version 3 so an older daemon cannot silently
discard the warm condition and restore a discounted reservation as unconditional.
The current daemon accepts legacy versions 1 and 2 only for cold reservations;
conditional reservations require the complete, validated version 3 state.

If the cold retry must queue, its durable row binds the exact previous remote
attempt's completion receipt. An older receipt cannot stand in for the new
waiter during cancellation, remove it on an unrelated ownership write, or
release another active attempt. Recovery verifies the same wrapper, project,
command, and predecessor ID; ambiguous legacy queued/terminal overlaps still
refuse recovery. The predecessor receipt is retained while that waiter needs
it. Older readers reject this additional queue field instead of discarding the
retry relationship.

Warm execution is currently limited to durable `rch exec` with ordinary,
single-root Cargo source synchronization. Its rsync receiver runs under the
same disk supervisor, using the selected reservation throughout upload; compiler
execution then verifies the exact target pool and takes a fresh capacity sample.
Canonical repository convergence is skipped on this path. Clean overlays,
source-content receipts, and multiple-root materializers request cold admission
before uploading. Legacy hook clients keep cold admission. A started command or
uncertain source cancellation never authorizes replay.
If the source receiver cannot establish its bounded initial allocation map, it
refuses before rsync rather than proceeding with only a net-size measurement.
That preparation failure retains the existing cancellation/recovery path; it
does not manufacture a compiler completion or a retryable pool receipt.

Failed, cancelled, incomplete, or unreliable observations remove warm eligibility
without erasing larger measured bounds. Recovery must establish and match a new
successful anchor. Old installations therefore need two qualifying successes
before receiving a warm allowance; a worker that cannot fit even one cold
reservation remains conservatively refused. Deleting or manually shrinking
history is not a substitute for trustworthy observations.

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
the disk-pressure policy still apply. With 33 GiB free at 3.7%, the disk
thresholds produce Warning under the default 25 GiB cap. The larger growth
budgets in the table are still refused.

## Reservations and fresh capacity

Admission requires all of the following:

- A valid build-filesystem free and total capacity sample. Generic `/tmp` disk
  telemetry alone is insufficient when the actual build storage differs.
- A current worker endpoint, probe generation, and transport generation, with
  a sample no older than 90 seconds. CPU telemetry and pressure reevaluation
  do not refresh disk age.
- Enough free space for the new growth budget, every active growth reservation
  on that worker, and the largest applicable free-space floor, counted once.
- Working durable ownership accounting. An accounting failure prevents new
  guarded admission.

If active disk-budget ownership cannot be restored safely at startup, the
daemon stops and retains the original snapshot. Invalid or mislabeled snapshots
must not shed their reservations, protected floors, or conditional allowances
through legacy quarantine recovery. Restore verified ownership before retrying;
clearing the ledger does not establish that the old work stopped.

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

When fresh capacity proves that a request fits by itself but competing owned
reservations prevent admission, selection reports the worker as busy. With
queueing enabled, the request enters the same durable wait queue as a request
waiting for CPU slots. It retains the original deadline and cancellation
identity and does not hold CPU slots while waiting for disk. Other suitability
checks still apply; Critical pressure, insufficient capacity for a single
request, missing observations, and expired or superseded evidence remain
refusals.

An existing queued request can bridge the short interval between a competing
owner's confirmed completion and the next capacity probe. This permits waiting
only: the old observation cannot fund admission, and its ordinary age and
generation limits still apply. New requests retain the normal stale-capacity
refresh/refusal behavior. A post-completion probe must prove enough current
space, including retained artifacts and remaining owners, before the waiter
receives a reservation.

A connection loss invalidates earlier capacity measurements, including copies
already held by an admission attempt. Reconnecting or re-enabling a worker
does not restore those measurements or clear its reservations. Guarded
admission requires a fresh capability probe; successful health recovery
already schedules that probe. A probe started before the connection loss
cannot establish recovered capacity.

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

Dispatcher-managed Cargo execution also includes the worker's durable
`rch-cargo-cache-<worker>` home, an explicit literal absolute `CARGO_HOME`
override, and physical destinations of their `registry` and `git` redirects.
The client captures the original command before shell wrapping; the monitor
resolves the default cache from the worker's canonical `RCH_CH_BASE`, before
client environment forwarding or a change of working directory. Redirects and
physical directory identities are rechecked during scans and free-space
sampling. Every resulting filesystem participates in reservation and floor
checks.

Existing Cargo cache bytes receive no target-pool credit. They remain an
unproven baseline, and an unfunded cache requires cold readmission before the
workload starts. New cache allocations count even if target cleanup masks
their filesystem free-space change. A dynamic, relative, removed, or otherwise
unresolved Cargo home refuses before launch with `monitor_unavailable` and no
learning receipt; a larger cold allowance cannot resolve an unknown output
scope. Cache preparation creates only the bounded home/registry/git
directories; their parent trees must already exist.

Each build walks its outputs every two seconds, and a walk that outlives its
30-second deadline stops the build. A shared cache past 25,000 entries is
therefore left out of that walk: one holding 600,000 entries took 30 seconds to
walk cold on an idle worker. Such a cache still participates in reservation and
floor checks, and its redirects are still verified, but its bytes are neither
charged to the build nor held against a warm admission. New downloads into it
are bounded by the free-space floor rather than by the growth budget, and a
usage receipt's peak growth omits them.

Direct `rch-wkr execute` remains cold-only and rejects conditional warm
budgets. Its existing inherited Cargo/Rustup home probes protect filesystem
floors, but do not provide the dispatcher's cache-output attribution or resolve
command-local home overrides. Arbitrary build-script destinations remain
outside the declared output scope.

The initial output size is the baseline. Runtime accounting tracks new and
modified allocation as well as positive net growth, so concurrent cleanup cannot
erase observed new output. A conditional warm execution also charges its
unproven baseline. Receipts retain total peak output for cold history and carry
optional incremental evidence separately from confirmed completion. Runtime
checks currently use a 250 ms control interval,
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
| Exact `cold_required` refusal before compiler launch | After acknowledged release, `rch exec` permits one fresh cold selection. Unsupported source modes make this decision before any source-content receipt or upload. |
| Confirmed refusal before command launch (`started: false`) | After the daemon acknowledges release, RCH may select another eligible worker while excluding the refusing worker. Exhausting alternatives reports E330. |
| Command started, or spawning it may have started it (`started: true`) | Stop the owned group and report the failure. Do not automatically replay the command locally or on another worker. |
| Missing or invalid receipt, unknown execution state, or unacknowledged release | Retain uncertain ownership and use the existing no-replay recovery path. A transport error does not prove a safe pre-start refusal. |

The detailed reason distinguishes `cold_required`, `admission`, `growth`, `free_floor`,
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
disk_critical_free_ratio = 0.05
disk_critical_ratio_cap_gb = 25.0
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
The separate critical ratio rule requires both free ratio at or below
`disk_critical_free_ratio` and free GiB at or below `disk_critical_ratio_cap_gb`.
The defaults are 5% and 25 GiB, including on a dispatcher without a config file.
Thus a 900 GiB disk with 30 GiB free can retain slots, while the same disk at
8 GiB free still triggers the independent 10 GiB critical floor. Existing
small-filesystem and `/tmp` rules still apply. Stale or unavailable build
storage telemetry, outstanding reservations, and an authorized budget that
cannot fit still refuse admission regardless of the cap.

An explicit numeric cap remains authoritative; `disk_critical_ratio_cap_gb =
"uncapped"` retains an unconditional ratio rule. Programmatic `None` and JSON
`null` have the same meaning and serialize as `"uncapped"` so configuration
edits cannot silently reinstate the default cap. `rch config get
selection.disk_critical_ratio_cap_gb --sources` reports the value and its source;
`rch config set selection.disk_critical_ratio_cap_gb uncapped` selects the
stricter mode. Numeric caps must be finite and at least 10 GiB. The CLI rejects
invalid values before writing; invalid numeric file settings make the daemon
use the stricter uncapped rule and log the reason.

Restart the daemon after selection-policy changes; the startup log records the
effective critical thresholds, protected floor and per-slot budget. Update the
dispatcher, daemon, and worker together: a new dispatcher talking to an older
daemon uses a conservative cold command budget and a 10 GiB floor, without the
new daemon history policy.

To investigate a refusal, inspect the selected worker and the daemon's capacity
observations:

```bash
rch workers probe hz3 --verbose
rch workers list --verbose
rch status --remediation
```

`disk_headroom_unknown` means a valid build-storage sample or durable accounting
is unavailable. `disk_headroom_stale` requires a current daemon probe, including
the probe-after-connection-change and probe-after-completion rules.
`disk_headroom_insufficient` reports the free
and required GiB, including active reservations and the floor. Inspect space on
the actual remote build and target filesystems, and allow confirmed completion
and a fresh probe to update capacity before diagnosing a retained reservation
as a leak. Use the [worker recovery runbook](worker-recovery.md) for uncertain
process ownership; do not kill a process using only an old numeric PID.

`disk_headroom_reserved` identifies a request that fits alone and can wait for
competing reservations. `disk_headroom_awaiting_probe` identifies an existing
waiter awaiting a post-completion sample. Neither diagnostic waives disk
admission or reserves CPU capacity.

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
