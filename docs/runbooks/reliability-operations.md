# Runbook: Reliability Operations

## Architecture Overview

RCH's reliability architecture is built around five pillars:

1. **Repo Convergence** — Ensures remote workers have correct repository state
2. **Storage Pressure** — Detects and responds to disk pressure on workers
3. **Process Triage** — Identifies and manages stuck/zombie build processes
4. **Circuit Breakers** — Isolates failing workers to prevent cascade failures
5. **Fail-Open Semantics** — Falls back to local builds when remote is unavailable

All five are **self-healing**: workers are temporarily bypassed and auto-rejoined,
breakers open and re-close on their own, stale remote dirs are reaped with
active-build protection, and stuck processes are escalated TERM → KILL with an
audit trail. Operator action is for genuine, lasting problems — and should use
the reversible, audited primitives below, never blind `pkill`/`rm -rf`.

### System Posture

| Posture | Meaning |
|---------|---------|
| `remote-ready` | All workers healthy, remote compilation available |
| `degraded` | Some workers unhealthy, partial remote capability |
| `local-only` | No workers available, builds run locally (fail-open) |

Check current posture:
```bash
rch status --json | jq '.posture'
rch status --remediation            # human bands: fleet, admissibility, proof queue, pressure, telemetry, incidents
```

## Quick Diagnosis

```bash
rch check                           # quick yes/no health (exit 0=ready, 1=degraded, 2=not ready)
rch status --fleet                  # desired vs live, dominant problem class, absence alerts
rch status --json                   # machine-readable for scripting
rch doctor                          # diagnostics + remediation plan (read-only)
rch doctor --reliability            # reliability-focused probes (topology/convergence/pressure/triage/…)
```

## Error Taxonomy

Error codes follow `RCH-Exxx`; admission/incident reason codes use `RCH-Innn`;
operator runbooks for remediation codes use `RCH-Rnnn` (see
`rch doctor --runbook-list`).

| Range | Category | Examples |
|-------|----------|---------|
| `RCH-E0xx` | Configuration | Missing workers.toml, invalid config |
| `RCH-E1xx` | Transfer/sync | File transfer failures, hash mismatches |
| `RCH-E2xx` | Build execution | Compilation failures, timeout |
| `RCH-E3xx` | Convergence | Repo sync failures, drift detected |
| `RCH-E4xx` | Daemon/service | Daemon unreachable, timeout, socket errors |
| `RCH-E5xx` | Storage/disk | Pressure critical, cleanup failed |

## Failure Modes and Remediation

### Worker Unreachable

**Symptoms:** Status shows worker "unreachable"/"bypassed", circuit breaker "open"

**Reason codes:** `circuit_open`, `worker_unreachable`

**Diagnosis:**
```bash
rch status --fleet
rch workers probe <worker-id> --verbose
ssh <user>@<host> 'echo ok'
```

**Remediation:** fix the underlying SSH/network/agent issue (see the
[worker-recovery runbook](worker-recovery.md)), then let the breaker self-heal.
There is no manual circuit reset and no `--force` probe; a successful scheduled
probe moves the breaker open → half-open → closed and a canary build auto-rejoins
the worker.
```bash
rch workers probe <worker-id> --verbose   # observe; daemon clears the breaker after a good probe
rch status --fleet                        # confirm it returned to the live pool
```
Do **not** `rch workers disable` for a transient outage — that blocks auto-rejoin.

**Risk:** `rch workers disable` is a permanent decommission, not a transient
pause: it suppresses auto-rejoin until you explicitly `rch workers enable`, so a
worker disabled for a momentary blip stays out of the pool. Prefer observing the
self-healing breaker (open → half-open → closed) over any manual intervention.

### Source namespace and terminal cancellation recovery (#111)

**Symptoms:** source namespace initialization refuses with status 73, an
overlapping source owner remains unavailable, or an SSH control session retains
source locks after its dispatcher has disappeared. A lease can already report
`state=finished` and `terminal_acknowledged=true` while an older cancellation
still needs worker metadata reconciliation.

Start with the original wrapper on the dispatcher that retains its journal:

```bash
rch jobs
rch jobs recover <wrapper-id> --timeout-secs 300
rch jobs attach <wrapper-id> --timeout-secs 300
```

Recovery keeps the recorded worker, build, token and source closure. For an
already acknowledged cancellation, it acquires exclusive journal ownership and
validates the failed delivery result and complete source, tree and pair
retirement. It then reconciles worker metadata, without reopening source paths,
replaying compilation or repeating completed daemon accounting. Ordinary
acknowledged deliveries do not require this cancellation operation.

New cancellations persist `source_cancellation_settled=false` before contacting
the worker. Only an exact worker settlement reply allows the journal to record
`true`; a failed journal publication remains retryable. A new terminal
acknowledgement or readmission cannot discard an unresolved cancellation.
Recovery also resumes settlement if source retirement reached the journal but
the dispatcher stopped before recording the failed returned result. Persisted
resource retirement does not bypass an outstanding cancellation obligation.
Older preparation cancellations without this field also enter reconciliation.
The daemon's existing recovery service considers eligible acknowledged
cancellations normally after a 15-minute scheduling grace, retaining its
per-worker concurrency limits and failure backoff. It excludes live or unverified owners.
Elapsed time selects a recovery attempt; it never proves source ownership has
ended.

#### Evidence required on the worker

The worker acquires the token's activity locks before registry metadata locks.
This drains previously admitted transfers, execution and cleanup. Future normal
activity must reject the cancellation fence; cleanup must still possess an
active claim. Locks are checked against their current inodes, and records must
match the exact requested token and source-closure digest. The transaction
confirms file and containing-directory durability before acknowledging a change.

The following outcomes additionally require the complete, owned local recovery
evidence described above:

| Worker evidence | Settlement result |
|---|---|
| Exact active claim plus cancellation marker | Move the existing claim into `cancelled/` and retain the marker. |
| Exact cancellation marker with no remaining grant | Publish a cancellation receipt and retain the marker; no source tree is inspected or changed. |
| Exact completed cancellation receipt | Reconfirm durability and retain or create the matching marker. Repeated recovery is idempotent. |
| Active claim without a cancellation fence, incomplete pending state, quarantine without a completed cancellation receipt, missing evidence, mismatched roots, contradictory terminal state, or ambiguous registry histories | Refuse settlement and retain the evidence. |

**A remaining `.cancelling` file is not a failed cleanup verdict.** It protects
against delayed acquire/recover requests for that identity even after retention
GC removes an old cancellation receipt. New identities are excluded by active
or complete pending claims, not by an unrelated terminal marker. A successfully
settled old token must remain refused while a new token can acquire the released
closure.

Unowned cancellation retains its durable fence before independently publishing
the completed receipt or returning `unowned`. It does not depend on the
dispatcher reaching a later settlement call. Replaying `cancel`, `finish-cancel`
or `settle-cancel` against an exact historical receipt-only cancellation restores
and confirms its fence before acknowledging success.

Cancellation-receipt retention requires a complete, byte-identical durable fence
and no conflicting records for that token. Receipt-only, malformed, symlinked,
quarantined or contradictory evidence is preserved. In particular, an incomplete
hard-linked quarantine fence cannot replace the complete receipt needed for
later recovery. Failed fence or registry durability barriers preserve both
records. Released receipts are retained even when they are old and unambiguous:
they are the only durable restart proof if release succeeded on the worker but
its reply or the dispatcher's local checkpoint was lost. Age cannot prove that
the dispatcher acknowledged release. Removing that receipt also permits an old
initial acquisition request to reuse the identity. Retaining the original
receipt preserves both proofs without rewriting its bytes or inode.
Each cancellation-receipt collection pass validates at most 16 candidates;
this bounds the added checks, not directory enumeration or filesystem latency.
Unresolved early candidates can defer later collection. Activity lock files are
not collected. Released-receipt and activity-lock growth remain unresolved;
safe collection needs a durable acknowledgement and identity-fencing protocol,
not an age threshold.

All dispatchers sharing a registry must run the corrected embedded transaction,
or their old sessions must be quiesced. An older dispatcher can still collect
released receipts needed by a newer one. This correction cannot reconstruct a
receipt already collected: missing worker evidence remains unconfirmed.

Preserve the original journal, cancellation records and lock files when
diagnosing a refusal. Neither a terminal lease alone, an empty process listing,
a free metadata lock, nor record age authorizes deleting them. Unlinking an
apparently stale `*.activity.lock` can leave an existing holder on the old inode
while a new caller locks a different inode. The settlement operation does not
reap activity lock files or infer cleanup authority from current source bytes.

#### Distinguishing refusals

Use the diagnostic token and its operation/stage fields, rather than status 73
or the word `Killed` alone:

| Diagnostic | Meaning and next observation |
|---|---|
| `RCH_SOURCE_NAMESPACE_METADATA_LOCK_BUSY` | The initializer exhausted its five-second metadata-lock wait; `elapsed_ms` and `lock` identify that wait. This uses status 76 and admits no source grant. |
| `RCH_SOURCE_NAMESPACE_PRE_ADMISSION_FAILED` | The named topology or initialization stage failed before source or execution intent. The exact admitted journal recorded the phase; retry still requires acknowledged daemon release and its exact terminal receipt. |
| `RCH_SOURCE_SETTLEMENT_LOCK_BUSY` | Recovery could not drain the named activity or metadata lock within its bounded wait. Retain the journal and retry after the owning activity resolves. |
| `RCH_SOURCE_CANCELLATION_FENCE` | An explicit same-token fence or an overlapping active cancelling owner caused refusal. Use the reported identity/record to find its owning journal. |
| `RCH_SOURCE_REGISTRY_PUBLICATION_UNCONFIRMED` | A record transition or durability confirmation did not complete. A visible rename is insufficient acknowledgement; retry the same identity. |
| `RCH_SOURCE_REGISTRY_INTERRUPTED` | A registry step exited unexpectedly; retain its `operation`, `stage`, `status` and identity. |
| `RCH_SOURCE_PAIR_PUBLICATION_UNCONFIRMED` | A pair owner or exact release receipt could not complete publication or durability confirmation. Preserve its records and retry the owning lease; a visible record does not by itself acknowledge release. |
| `RCH_SOURCE_PAIR_OWNERSHIP_UNCONFIRMED` | Pair custody is missing, malformed, changed or inconsistent with the requested identity. A free lock or an old receipt cannot replace conflicting owner evidence. |
| `RCH_SOURCE_NAMESPACE_PROCESS_TERMINATED`, `RCH_SOURCE_NAMESPACE_CONTROL_UNSETTLED`, or `RCH_SOURCE_NAMESPACE_INTERRUPTED` | The program terminated, teardown was not confirmed, or the worker supplied no diagnostic. These do not establish whether the cause was an external signal, a deadline, OOM, or another infrastructure fault. |
| `RCH_SOURCE_LOCK_HEARTBEAT_EXPIRED`, `RCH_SOURCE_LOCK_DISCONNECTED`, or `RCH_SOURCE_LOCK_RELEASE_TIMEOUT` | The control session expired or lost its release protocol. Durable ownership remains for recovery. |
| `RCH_SOURCE_LOCK_PROCESS_TERMINATED` or `RCH_SOURCE_LOCK_SUPERVISOR_TERMINATED` | The holder or its supervisor terminated. A process exit alone does not authorize retiring the durable claim. |
| `RCH_SOURCE_CANCELLATION_UNSETTLED` | Worker evidence or its lock namespace could not be verified. The accompanying reason identifies what must be resolved before retrying. |
| `RCH_SOURCE_CLAIM_RETENTION_DEFERRED` | Receipt collection could not confirm the retained cancellation fence's durability. Both records remain; this does not grant cleanup authority. |
| `RCH_GC_LEGACY_SOURCE_OWNERSHIP_UNKNOWN` | A legacy active claim is malformed or unsafe to read. GC cannot prove the candidate unowned and preserves both the record and source tree. |

#### Namespace failure, daemon completion and readmission

The topology probe and namespace initialization run before the recovery intent,
source or pair acquisition, transfer and execution. A failure at either boundary
can receive the typed preflight diagnostic only after the exact admitted journal
durably records its failed phase. Its schema, wrapper, worker, build and
nonpending selection must match, with no source recovery, observed outcome or
terminal acknowledgement. The phase is diagnostic, never recovery authority;
later finalize or release-uncertain heartbeats may replace it. The outcome stays
unset until daemon completion is verified.

For this path, an acknowledged release is followed by a bounded read-only
completion query on the same configured daemon socket. The wrapper, worker and
build must match the exact terminal record. An ordinary failed result permits
the existing retry policy. A completed cancellation with exit `130`, the exact
cancellation operation ID and successful cleanup/history evidence instead
publishes terminal acknowledgement and exits without selecting another worker.
A release ACK alone cannot choose between those results: an idempotent release
may acknowledge cancellation that already won the race.

The journal rechecks admission identity, absent source recovery and outcome
agreement under its mutex after the query. A failed or oversized reply,
contradictory receipt, changed admission or failed journal publication remains
unconfirmed; it cannot authorize another selection. Any
`RemoteExecutionUnconfirmed` in the original error chain still takes precedence.
Generic later SSH timeouts remain fail closed, while original source-contention
evidence remains available to the worker-selection policy.

If the dispatcher stops before release or before receiving that terminal
receipt, the journal has no invented exit code to conflict with a later daemon
cancellation. Existing owner-verified restart recovery can adopt the exact
daemon completion after the wrapper is absent. This neither fabricates daemon
completion from a phase nor relaxes conflicting outcomes in older journals.

#### Journal custody during readmission

Readmission that supersedes source recovery must preserve the preceding journal
under its exclusive ownership gate. Current journals written with a normal
umask, including modes `0640` and `0644`, can supply that evidence when they are
regular files owned by the current user, have one link and are not writable by
group or others. Retained snapshots and publication temporaries remain private
(`0600`). Exact bytes and named inode are verified before and after publication;
changed, symlinked, hard-linked or externally writable evidence is refused. The
original journal is not chmodded or otherwise changed to satisfy snapshot
validation.

#### Interrupted source-pair publication and cancellation

Clean-overlay source pairs have their own durable owner and per-identity
release receipt, in addition to the source registry. Earlier pair operations
wrote these final names in place. A failed write could truncate the owner to
an empty file and make every later acquisition refuse the pool. Pair operations
now write complete private temporary records, sync them, recheck the expected
old inode and bytes, atomically publish the new record and confirm the file and
parent-directory barriers before replying. All publishers retain the same pair
lock; first acquisition also retains the registry metadata lock and checks its
cancellation fences.

The exact release receipt becomes durable before the owner changes to
`released`. A retry can finish that interrupted transition when the old owner
still matches and its source root is absent. An existing release receipt is
immutable: its exact token is confirmed without rewriting it, and that token
cannot acquire the pair again. Historical receipt confirmation preserves a
different valid current owner and never inspects that successor's source tree.
Owned regular records with one link and no group/other write permission are
accepted, including safe legacy `0640`/`0644` records; new records use `0600`.
Partial, symlinked, hard-linked, writable or contradictory records remain
refused. The correction prevents new partial final records; it does not erase
or guess the contents of malformed records already on a worker.

Detached recovery also handles cancellation interrupted after pair release,
both before and after worker `finish-cancel`. With exclusive verified journal
ownership, it requires the exact bound recipe, a durable tree-retirement
checkpoint, and either durable pair retirement or the exact worker pair-release
receipt. It additionally requires a recorded cancellation obligation or an
exact durable worker cancellation marker or receipt for a legacy recipe. The
read-only `cancellation-state` probe distinguishes existing cancellation intent
from the `cancelled` probe's completed receipt. It refuses incomplete pending,
quarantined, unknown or contradictory same-identity evidence without repairing
it. A positive intent probe is not source access or completed cleanup. Those facts
authorize only cancellation metadata reconciliation and failed-job retirement.
They authorize no new source or pair grant, source-content reads or tree
mutation. Existing cancellation validation can inspect physical path topology.
The worker still drains activity, checks the exact source closure and preserves
the old-token cancellation fence. Journal changes, missing pair proof and
conflicting worker records remain failures with the evidence retained.

For a non-paired legacy job with an exact execution-completion receipt, recovery
also recognizes a cancellation marker left before `finish-cancel` or after
receipt collection. It checkpoints the observed command exit and cancellation
obligation before invoking the existing activity-drained cancellation cleanup.
The observation does not itself mark sources released, return a result, retire
the journal or acknowledge the daemon. A lost cleanup reply leaves a durable
obligation for the next recovery owner. Missing or conflicting intent remains
unconfirmed. A legacy paired job without its required retirement proof remains
refused rather than borrowing another owner's source pair.

When cancellation started before tree or pair retirement completed, an exact
execution-completion or execution-lost proof resumes the existing cancellation
cleanup path. An unretired paired tree requires the exact live cleanup pair
guard. Recovery cannot substitute a free kernel lock, a terminal daemon lease
or another owner's current source for that authority. A restarted operation
then completes the existing worker and daemon acknowledgements without
replaying the command.

#### Bounded POSIX control-session liveness

New POSIX source and source-pair lock sessions carry complete heartbeats every
10 seconds. A worker supervisor uses a monotonic 90-second idle deadline during
bootstrap, acquisition and holding. Partial or invalid frames do not renew it.
An explicit release has a separate 15-second completion budget. The supervisor
owns a private process group and tears down its holders and inheriting helpers;
the observer kills that group before reaping its direct child or accepting a
completion receipt. Missing required Python process/locking capabilities fail
before a source grant is acquired.
The observer uses blocked `SIGCHLD` with `pthread_sigmask` and `sigwait`; it
does not require the [`os.waitid`](https://docs.python.org/3.13/library/os.html#os.waitid)
interface missing from older macOS Python.
Child notifications trigger teardown of the still-owned session, and only its
completion receipt can establish a successful result.
The child session unblocks `SIGCHLD` even when the invoking environment had it
blocked; only the observer retains its blocked notification mask. Timer death
is observed before reaping, so descendants cannot retain metadata locks after
an acknowledged controller teardown. An exit code of 137 alone is not a
teardown acknowledgement.

Finite cancellation, cancellation-finish and release/receipt RPCs, including
pair reconciliation, run inside the same bounded metadata controller as
namespace initialization. Its worker-side execution budget is 15 seconds with
one-second escalation; output delivery has its own two-second budget. A local
SSH timeout alone is insufficient: a queued worker `flock` must not wake after
the caller disappears and publish a late cancellation. Only the exact expected
reply, including an empty finish reply, is accepted after confirmed teardown.

Expiry releases control-session descriptors while retaining active claims,
cancellation fences, pair ownership and receipts. Separately launched compiler
or rsync sessions are not part of this group. Their activity locks and durable
claims remain the evidence recovery must drain and validate. The bound assumes
the worker supervisor can run and its processes can be terminated; a stopped
supervisor or uninterruptible kernel I/O cannot be promised a hard 90-second
lock-release time. Native Windows retains its existing transport and has no
equivalent qualified heartbeat supervisor in this change.

This policy applies to newly launched sessions. It does not change `sshd`
configuration or retrofit watchdogs into old sessions. Dispatcher binaries
generate the SSH programs, so updating only a worker binary does not replace
an older dispatcher's control-session behavior.

#### Legacy registries and remaining acceptance

New journals persist `source_authority_namespace=current` before acquisition.
An older journal without this field first locates exact evidence in the current
`/var/tmp/rch-source-authority-locks/claims-v1` and legacy
`/tmp/rch-source-authority-locks/claims-v1` registries. Discovery takes the
identity's activity locks before both metadata locks, validates and reconfirms
the records, and grants no source access. Recovery checkpoints the discovered
`current` or `legacy` binding under exclusive journal ownership before issuing
cancellation, cleanup, pair recovery or release probes. The binding cannot
change on a later retry. Source and pair hierarchy locks, activity checks and
retention-prefix checks all use the recorded namespace.

Discovery does not initialize an absent registry to manufacture ownership
evidence. A matching identity in both registries, an incomplete pending write,
missing evidence or changed binding is retained and refused. Legacy cleanup
transactions take current metadata before legacy metadata and check competing
lexical and physical claims before authorizing cleanup; the valid legacy active
claim remains until cleanup finishes. Creating empty current lock-directory
plumbing for this ordering does not create a claim or cancellation receipt.
A legacy pair-only intent without a source-registry record remains refused:
its namespace cannot be guessed from the present layout.

Old executed-but-lost
cancellations that recorded neither `preparation_cancelled` nor the new
settlement field cannot safely be identified from their exit code alone.

The registry migration also changed hierarchy-lock paths. A read-only legacy
scan does not prove safe admission across simultaneously active old and new
dispatchers. Quiesce pre-migration dispatchers and account for their outstanding
sessions and leases during rollout; do not treat this terminal-recovery change
as qualification of mixed-version admission.

**Native-worker acceptance remains required.** The
[October 29 report](https://github.com/Dicklesworthstone/remote_compilation_helper/issues/111#issuecomment-6484520860)
correlates a persistent project-specific namespace failure with terminal
cancellation records. Both current source and the reported `ff152a046086`
implementation exclude other identities through `.claim`/`.pending` records;
the two reported terminal records alone do not explain a fresh identity's
namespace refusal. Preserve that distinction when evaluating the repair.
The separate retrieval-staging work tracked by `bd-ra5aw` does not resolve this
incident by itself.

The October 30 isolated Linux qualification at `5b1eee2` passed 235 regressions: 76 source
registry/legacy-GC cases, 31 earlier registry cases, 65 holder cases, 28 control
cases, 11 native-timer cases, three delivery cases, 13 process-group cases and
eight real loopback OpenSSH cases. The SSH suite uses fixture-owned keys and
strict host verification; heartbeat fault cases select a two-second idle lease,
while queued cancellation uses the shipped 15-second execution deadline. It
checks retained claim bytes/inodes, independent activity and absence of late
publication after unlocking. Run it with
`python3 scripts/tests/test_source_ownership_ssh.py` on an isolated Linux host
where the test user may start `sshd`.

The cancellation-retention repairs through `7ae3f5f` passed 90 comprehensive
registry cases, 31 earlier registry cases and eight loopback SSH cases. Those
historical results covered missing fences, lost durability acknowledgements,
conflicting receipts and old-token refusal. The current registry and SSH
qualification below supersedes those counts. These tests exercise actual
processes, locks and transport with injected durability failures; tmpfs does
not establish physical power-loss recovery or installed-worker acceptance.

The subsequent source-pair publication qualification reproduced the previous
failure with actual pair/metadata locks and a kernel file-size write limit:
both `sh` and `bash`, with either an absent or previously released owner, left
an empty owner that the next admission refused. Seven focused native tests of
the new production custody program passed, covering interrupted writes and
publication barriers, exact receipt replay, concurrent dispatchers, changed
owners, readable legacy records, malformed evidence and successor preservation.
The final frozen-source holder suite passed all 72 cases: 65 existing holder
cases and these seven pair-custody cases, with no skips.
The expanded real loopback OpenSSH suite passed all ten cases, including loss
of the SSH client after pair release commits, and a restart between pair
release and source cancellation completion. Repeated old-token reconciliation
preserved the successor's owner, active claim and source bytes and inodes.
Both new pair SSH cases also passed again after the final missing-owner
refusal was added.
These execute worker programs and real kernel locks; they do not compile the
Rust command builders or execute the new Rust journal-recovery integration.

The following legacy-cancellation and released-proof corrections reproduced
the aged-release failure against the unchanged `358f0c6` registry under both
`sh` and `bash`, and independently over real loopback SSH. After a lost release
reply, another admission collected the aged receipt and the original release
query incorrectly returned `pending`. Marker-only cancellation also left the
completed-receipt query at `pending` while normal recovery remained refused.
The corrected native registry suite passed all 98 cases, and the earlier
registry/admission suite passed all 31. The expanded controller suite passed
31 cases, the native fallback timer passed 11, and real pipe
backpressure delivery passed three. All 12 loopback SSH cases passed, including
lost release replies across retention, cancellation intent while independent
activity remains live, and restart between pair release and `finish-cancel`.
The probe preserved live claims and source bytes; successor admission and
repeated old-token reconciliation remained safe. No skips occurred in these
suites. The earlier holder/pair-custody results remain scoped to their prior
revision; this correction did not change those programs.

The journal-custody correction passed 25 job-identity and journal tests in the
actual default-feature `rch-common` crate using the pinned nightly toolchain.
Default-feature `rch-common` Clippy with `--lib --tests -- -D warnings` also
passed.
An isolated unchanged-code build ran the readable-original regression and
reproduced the reported `retained journal file identity, permissions or exact
bytes changed` error on an owned `0644` original. The correction accepts `0640`
and `0644` originals while still refusing writable or hard-linked originals,
changed evidence and nonprivate retained snapshots. This qualification does not
substitute for compilation and execution of the full RCH retry integration.

Pinned workspace `cargo fmt --all -- --check` passed with the admission and
source-pair corrections. Eight focused `namespace_preflight_` tests were added for
phase publication, exact terminal receipts over real Unix sockets, cancellation
winning a release race, invalid/oversized replies, source-busy propagation,
journal reload and concurrent completion. These new RCH tests were **not
executed** in this environment.

Four additional `paired_cancellation_recovery_` Rust tests exercise exact journal
ownership, daemon outcome reconciliation, durable reload, lost cancellation and
settlement replies, missing/conflicting pair evidence and failed journal
publication. They were independently source-reviewed but were also **not
compiled or executed** here. The native worker-program results above do not
replace this integration gate.

Two `completed_source_cancellation_` Rust tests were added for the later legacy
intent correction, and the four paired tests were strengthened. They exercise
actual journal ownership and disk reload with injected worker observations,
including a crash before cleanup, conflicting command outcomes and changed
custody. All six remain **uncompiled and unexecuted** here. Native worker tests
validate the registry observations separately from this dispatcher integration.

The latest locked, default-feature `cargo check -p rch --all-targets` attempt
again received SIGKILL while compiling the unchanged `asupersync 0.5.0`
dependency, before reaching RCH. It used one Cargo job, one rustc thread, no
debug info and no incremental compilation under the 8 GiB memory limit; the
cgroup OOM-kill counter increased during that failure. The earlier full locked
workspace check at `5b1eee2` encountered the same dependency failure. These
attempts establish no compiler verdict for the changed RCH integration. Full
workspace check/Clippy and execution of the RCH recovery, lease and retry
regressions remain required before release acceptance. Successful common-crate
Clippy and Linux process/SSH qualifications do not replace those gates or the
original affected worker's acceptance. After the legacy-intent correction,
both the backing filesystem and temporary filesystem had no free space; the
heavy Rust gates were not repeated under the unchanged memory constraint.

On a native host with sufficient build capacity, include these Rust gates with
the worker acceptance cases below:

```bash
cargo check --locked --workspace --all-targets
cargo clippy --locked --workspace --all-targets -- -D warnings
cargo test --locked -p rch --bin rch namespace_preflight_ -- --test-threads=1
cargo test --locked -p rch --bin rch paired_cancellation_recovery_ -- --test-threads=1
cargo test --locked -p rch --bin rch completed_source_cancellation_ -- --test-threads=1
cargo test --locked -p rch --bin rch source_pair_ -- --test-threads=1
cargo test --locked -p rch --bin rch retry_selection_ -- --test-threads=1
cargo test --locked -p rch --bin rch retry_custody_ -- --test-threads=1
```

Before calling the incident resolved on the fleet, record the exact dispatcher
and worker revisions and complete these acceptance cases on isolated native
worker fixtures:

1. Run the required Rust workspace checks and the recovery/lease/SSH regression
   targets, plus the Linux registry, holder and namespace-controller suites.
   Record any blocked gate explicitly; source review is not compilation.
2. Reproduce interrupted initialization and cancellation over real SSH,
   including a lost settlement reply and restart between worker publication and
   local journal acknowledgement. Retrying the original wrapper must settle
   once, preserve the old-token fence and admit a new overlapping job safely.
   Interrupt preflight before daemon release and race release against daemon
   cancellation. Exact failure receipts may retry; completed cancellation must
   remain terminal, with no replay and no invented conflicting local exit.
   Include legacy marker-only journals and lost release replies aged past
   retention, with all shared-registry dispatchers using the updated policy.
3. Exercise concurrent dispatchers and a still-running activity. Recovery must
   refuse while that activity owns its lock; an unrelated project must continue
   making progress. Corrupt, changed, absent and conflicting evidence must
   remain refused without source-tree mutation.
4. Exercise a half-open/multiplexed SSH session and a stopped or dead client.
   Verify control locks are released after heartbeat loss under the stated
   scheduling assumptions, durable records remain, and separate build/transfer
   activity is not killed. Include observer and supervisor termination, a
   stopped supervisor and an explicit `SIGCHLD` sent to its observer.
5. Qualify the deployed Linux toolchain, including GNU/uutils differences, and
   native Darwin process/locking behavior where used, using the `python3` found
   on the worker's noninteractive SSH `PATH`. Exercise an inherited ignored
   `SIGCHLD` disposition and an inherited blocked mask. Linux subprocess tests,
   including tests that remove `os.waitid`, do not qualify Darwin or Windows.
6. Revisit the affected project and worker with the new diagnostics and original
   lease evidence. Establish the cause of the historical namespace refusal and
   verify repeated admissions after recovery. A passing isolated reproduction
   does not establish that the production failure has been eliminated.

### Disk Pressure Critical

**Symptoms:** Worker pressure state "critical", builds deferred

**Reason code:** `pressure_critical`

**Diagnosis:**
```bash
rch doctor --reliability --scope pressure
rch status --json | jq '.daemon.workers[] | select(.pressure_state == "critical")'
ssh <user>@<host> 'df -h / /tmp'
```

**Remediation:** reclaim safely. The daemon's stale-target reaper removes only
idle remote dirs (active builds are always kept); local staging trees are reaped
via `rch cache clean`, which is **dry-run by default**:
```bash
rch cache clean --older 1h                 # preview reclaimable local staging trees
rch cache clean --older 1h --execute       # reclaim idle trees
# Reclaim incremental build state without nuking a whole target tree:
ssh <user>@<host> 'cargo clean --manifest-path /tmp/rch/<project>/Cargo.toml'
# Manual removal is a last resort — verify the candidate is inactive FIRST:
ssh <user>@<host> 'sudo lsof +D /tmp/rch_target_<name>'   # empty ⇒ inactive
ssh <user>@<host> 'rm -rf /tmp/rch_target_<name>'         # only if lsof was empty
```

**Risk:** Reclaim removes cached build artifacts; subsequent builds are slower
until caches rebuild. Blind `rm -rf` of an active dir can corrupt a live build —
hence the lsof guard and active-build-protected reaper.

### Repo Convergence Failed

**Symptoms:** Worker convergence state "failed"/"drifting", missing repos

**Reason codes:** `convergence_failed`, `convergence_drifting` (RCH-R3xx)

**Diagnosis:**
```bash
rch doctor --reliability --scope convergence
rch status --json | jq '.convergence.workers[] | select(.drift_state != "ready")'
```

**Remediation:** the daemon converges drift automatically; to force a repair,
use the operator-confirmed fleet doctor fix (preview first):
```bash
rch fleet doctor --reliability --scope convergence                                   # diagnose
rch fleet doctor --reliability --scope convergence --fix --fleet-confirm --workers <id>   # apply on one worker
```

The `--fix` path triggers the daemon's `repo-convergence repair` for the targeted
worker (the same operation as the `POST /repo-convergence/repair` admin endpoint):
it resets the convergence budget so the next cycle re-syncs the missing repos.

**Risk:** Convergence repair may re-sync/re-clone repositories, discarding any
worker-side local changes. `--fleet-confirm` is the required safety gate before
`--fix` touches workers; scope to specific `--workers` rather than the whole fleet
when in doubt.

### All Workers Down (Fail-Open)

**Symptoms:** Posture `local-only`, all builds running locally

**Reason:** No healthy workers available — often a cloud/VMI fleet incident or a
self-induced swarm-load collapse (see the dedicated sections below)

**Diagnosis:**
```bash
rch status --fleet
rch doctor
```

**Remediation:** fail-open is working as designed — builds are not blocked. Fix
the systemic cause (network, DNS, SSH keys, cloud outage), then workers
auto-rejoin. Do **not** `rch workers disable` or delete absent workers to "clean
up"; they are part of desired state and rejoin on recovery.

### Schema/Contract Mismatch

**Symptoms:** Adapter version warnings, unexpected response formats

**Reason code:** `schema_mismatch`

**Diagnosis:**
```bash
rch doctor --reliability --check-schemas
```

**Remediation:** redeploy the affected adapter binary to workers with an
atomic, verified deploy (do not hand-patch a worker binary):
```bash
rch fleet deploy --worker <id> --force --verify
rch status --json | jq '.schema_version'
```

If the mismatch is a genuine schema-version bump rather than a stale binary,
follow the schema migration steps for the affected component before redeploying:
a migration may be required when the persisted on-disk format changed, and a blind
redeploy would not reconcile already-written records.

## Cloud / VMI Fleet Incidents

When the whole fleet (or a region) disappears at once — provider outage, VMI
image roll, network partition — RCH treats it as a desired-vs-live gap, not a
config problem:

```bash
rch status --fleet            # dominant problem class = absent/unreachable across many workers
rch status --remediation      # posture local-only/degraded, fallback flagged intentional
```

- **Fail-open carries you:** builds run locally; nothing is blocked.
- **Do not mutate desired state to react.** Editing `workers.toml` or
  `rch workers disable`-ing the absent nodes forces a manual re-add and defeats
  auto-rejoin when the cloud recovers.
- **When the fleet returns,** workers are re-probed and auto-rejoined (canary
  before full traffic). Confirm with `rch status --fleet`.
- **Genuinely dead node?** Decommission explicitly:
  `rch workers disable <id> --reason "decommissioned" --drain -y`.

## Local Fallback Hazards Under Swarm Load

Many agents building at once can starve the worker pool. The danger is a
feedback loop: builds fall back to local, local CPU saturates, everything slows,
and operators "fix" it with destructive manual cleanup that removes capacity.

Safer handling:

```bash
rch status --fleet            # is it real shortage, overload, or pressure?
rch queue                     # depth + which builds are running/waiting
rch admit "cargo build"       # RCH-I003 insufficient slots? RCH-I011 local fallback?
```

- **Prefer queueing over fallback** under contention — `RCH_QUEUE_WHEN_BUSY=1`
  (default) waits for a busy worker instead of piling onto local CPU.
- **Shed load by cancelling, not killing:** `rch cancel <id>` / `rch cancel --all -y`
  reclaims slots with tracked cleanup.
- **Do not add/remove workers reflexively** or `pkill` local cargo — that masks
  the signal and can worsen the loop. Watch the fallback rate against the SLO.

## Proof-Mode Handoff

When a result must be *proven* to have run remotely (no silent local fallback),
hand off through proof mode rather than trusting logs:

```bash
# Interim proof lane — fail-closed, self-healing disabled so nothing auto-starts underneath:
RCH_REQUIRE_REMOTE=1 RCH_NO_SELF_HEALING=1 rch --no-self-healing exec -- cargo test --workspace
```

- `RCH_REQUIRE_REMOTE=1` refuses local fallback (`RCH-I012` / `RCH-E301`) instead
  of running locally. Keep the build command as **direct argv** after `--`;
  shell-wrapped (`bash -lc "..."`) commands classify as non-compilation and are
  refused under strict mode.
- A refusal records a durable **proof intent** in the proof store
  (`<state>/proofs.jsonl`), which the daemon replays when capacity returns; the
  matching incident lands in `<state>/incidents.jsonl`
  (`<state>` = `RCH_STATE_HOME`, else `XDG_STATE_HOME/rch`, else
  `~/.local/state/rch`, else `/tmp/rch`).
- Inspect the handoff with `rch status --remediation --json` (proof-queue band)
  and `rch admit "<cmd>" --json` rather than scraping output.

## Feature Flags and Rollout

| State | Meaning |
|-------|---------|
| `disabled` | Feature completely off |
| `dry_run` | Feature runs but takes no action; logs what would happen |
| `canary` | Feature active on subset of workers |
| `enabled` | Feature fully active |

```bash
rch status --json | jq '.feature_flags'
```

## SLO Guardrails

| Metric | P50 Budget | P99 Budget | Release Blocking |
|--------|-----------|-----------|-----------------|
| Hook decision latency | 1ms | 5ms | Yes |
| Convergence check | 100ms | 500ms | P99 only |
| Triage overhead | 2ms | — | Yes |
| Fallback rate | <10% | — | Yes |
| Cancellation cleanup | — | 10s | Yes |

## Incident Triage Flowchart

1. **Check posture:** `rch status --fleet` / `rch status --json | jq '.posture'`
2. **If `local-only`:** all workers → network → SSH → daemon; suspect a cloud/VMI
   incident or swarm-load collapse (sections above). Fail-open is correct; fix the
   cause, don't disable desired state.
3. **If `degraded`:** inspect failing workers → `rch doctor --reliability`
4. **If `remote-ready` but slow:** pressure → convergence → build/queue stats
5. **Escalation:** collect `rch status --remediation --json` and
   `rch doctor --reliability --json`; the incident ledger already has the
   reason-coded chain.

## Safe vs Destructive Operations

All diagnostics are read-only and **safe to run** in production:

```bash
rch check                                 # read-only
rch status / rch status --fleet           # read-only
rch doctor / rch doctor --reliability     # read-only diagnostics
rch self-test                             # creates temp files, cleans up
rch cache clean --older <dur>             # DRY-RUN unless --execute is added
```

Operations that change state require operator intent — preview, then confirm:

```bash
rch cache clean --older <dur> --execute                                   # reclaims idle staging trees
rch fleet doctor --reliability --scope convergence --fix --fleet-confirm  # may re-sync repos
rch fleet deploy --worker <id> --force --verify                           # atomic, rollback-safe
rch workers disable <id> --reason "..." --drain -y                        # PERMANENT decommission only
```

Never: `pkill -9` a build/agent, `rm -rf` a worker's RCH tree, or `rm` the daemon
socket. Use `rch cancel`, the audited triage fix, the active-build-protected
reaper, and `rch daemon restart` instead.

## Validation

The behaviors in this runbook are backed by tests; the runbook itself is guarded
against stale guidance returning:

```bash
# Runbook regression guard (forbidden/stale guidance cannot return; wired into CI):
./scripts/check_runbooks_safe.sh
# Reliability traceability matrix + convergence + pressure/triage behaviors:
cargo test -p rch-common --test reliability_coverage_matrix_e2e
cargo test -p rch-common --test repo_convergence_e2e
# Admission reason-code vocabulary + proof-mode + incident ledger:
cargo test -p rch-common --test admission_goldens_e2e
cargo test -p rch-common --lib proof incident telemetry_explain
```

Structured records live under `<state>` (`RCH_STATE_HOME`, else
`XDG_STATE_HOME/rch`, else `~/.local/state/rch`, else `/tmp/rch`):
`incidents.jsonl` (reason-coded incidents) and `proofs.jsonl` (proof intents +
replay state). E2E scenario logs are written as JSONL under `target/test-logs/`.
Read live state via `rch status --remediation --json`, `rch diagnose "<cmd>"
--json`, and `rch admit "<cmd>" --json`.
