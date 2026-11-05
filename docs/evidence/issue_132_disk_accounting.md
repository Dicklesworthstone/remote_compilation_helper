# Issue #132: pooled-target disk accounting and executed measurements

Date: November 5, 2026.

This report accompanies the correction to the disk-accounting portion of
[issue #132](https://github.com/Dicklesworthstone/remote_compilation_helper/issues/132).
Its consumers are maintainers reviewing additional-space admission and operators
qualifying that behavior on their workers. It records executed local evidence,
the deliberately modeled capacity replay, and remaining integration limits.
It may be retired when an equivalent live-worker qualification supersedes it.

Implementation commit:
[`d8f2a060e8b4573d989759e4f213fa8bed35d087`](https://github.com/Dicklesworthstone/remote_compilation_helper/commit/d8f2a060e8b4573d989759e4f213fa8bed35d087).
The parent is `543cd2ced10aadee8af597046bbf553eb39d7cdd`. Concurrent upstream
critical-ratio policy changes and RABS work were preserved.

## What changed

Cold estimates still use total peak allocated output. Warm estimates have a
separate, bounded history keyed by exact project, command, and worker endpoint.
A successful receipt establishes an anchor; another successful receipt must
start at that exact retained pool before a smaller allowance is eligible.
Legacy total-output samples are never converted to incremental samples.

The worker binds the selected target to its physical path, boot, device/inode,
and a deterministic tree-state fingerprint. It measures new or modified inode
allocations without subtracting concurrent cleanup. The learned requirement is:

```text
unproven baseline = starting output - verified starting target pool
additional requirement = unproven baseline
                       + max(peak new/modified output, peak free-space decline)
```

Only the selected pool receives retained credit. Other source/cache allocations,
including sibling target pools inside the source tree, remain charged. Shared
free-space changes can increase the estimate; they are never divided into
unsupported per-writer estimates. The existing minimum footprint, growth
margin, protected floor, capacity freshness, and full concurrent reservations
still apply.

Conditional allowances persist through ownership and recovery. New ownership
snapshots use format version 3, which old loaders reject before they can discard
the warm condition. The new loader accepts legacy versions 1 and 2 only for
cold reservations. Failed, cancelled, partial, or invalid observations remove
warm eligibility without erasing larger observed bounds.

Ordinary single-root Cargo source upload under durable `rch exec` now runs its
rsync receiver under the disk supervisor. Unsupported preparation modes require
cold admission before writing. An exact prelaunch pool refusal can request one
fresh cold reservation only after acknowledged ownership release. Started or
uncertain execution is never automatically replayed. Optional learning evidence
is separate from a confirmed execution receipt.

The implementation and regression changes are in the shared protocol and
monitor, daemon history/selection/admission, client execution/transfer, worker
entry points, and [the operating runbook](../runbooks/build-disk-budgets.md).
No SSH-persistence optimization is included.

## Executed native admission replay: modeled 220 GiB capacity

An isolated Rust test compiled the production footprint book, budget validation,
growth calculation, and disk-admission methods. Both original and candidate
accounting ran in the same test invocation. The fixture supplied 220 GiB free,
a 10 GiB protected floor, total cold-output observations of 81/84/95 GiB, and
matching successful warm receipts observing 300 MiB additional space per build.

| Accounting | Reservations for the three requests | Disk decisions | False refusals in this fixture |
| --- | --- | --- | --- |
| Original retained-pool learning | 102, 105, 119 GiB | Admit, admit, refuse | 1 of 3 |
| Qualified incremental learning | 3, 3, 3 GiB | Admit, admit, admit | 0 of 3 |

The cold estimates remain 81/84/95 GiB. Stale observations, exhausted capacity,
protected floors, and the requirement for a new capacity sample after completion
remain enforced in the executed admission-method tests.

These are executed decisions over **modeled capacity and receipts**, not an
allocation of 220 GiB or a live scheduler/worker run. This harness does not
exercise the full daemon ownership lock, API dispatch, source upload, process
launch, or the reporter's worker. The false-refusal denominator is exactly these
three modeled requests; it is not a fleet failure rate.

## Executed filesystem benchmark

The reusable [benchmark](../../scripts/bench_disk_accounting.py) imports the two
supplied production monitor files without changing their source. It allocates
real files and calls their actual scan/accounting methods, using a synthetic
observer identity that cannot authorize a worker. Source bytes are hashed before
execution. [The JSON result](issue_132_disk_accounting.json) contains the raw
measurements, all scan timings, provenance, and scope statements.

| Case | Starting allocated output | Largest observed total output | Candidate new/modified allocation counter | Actual free-space decline |
| --- | ---: | ---: | ---: | ---: |
| Warm retained target plus new output | 16 MiB | 17 MiB | 1 MiB | 1 MiB |
| Cold target | 0 | 1 MiB | 1 MiB | 1 MiB |
| Cleanup of retained output plus a new file | 16 MiB | 16 MiB | 1 MiB | -15 MiB |
| Three overlapping child writers | 16 MiB | 19 MiB | 3 MiB | 3 MiB + 4 KiB |
| Rewrite of a retained inode | 16 MiB | 16 MiB | 16 MiB | 0 |
| Selected target plus unproven source/cache baseline | 20 MiB | 21 MiB | 1 MiB | 1 MiB |

The last row contains 16 MiB of proven target and 4 MiB of other retained output.
Its actual warm aggregate charge is **5 MiB**: the 4 MiB unproven baseline plus
the new 1 MiB. In the overlap case, a 4 KiB start-gate file outside the target
also appears in the filesystem free-space decline. That independent lower bound
can raise learning above the 3 MiB attributed output counter.

Cleanup is the decisive difference from final-minus-initial sizing: the old net
growth counter reads zero after 16 MiB is freed and 1 MiB is written, while the
candidate still observes and charges the 1 MiB allocation. Rewriting an existing
16 MiB inode charges its current allocation conservatively even when free space
does not change. Three real child processes had overlapping lifetimes; both
observers saw the shared target. This does not claim exact per-writer attribution.

The warm row demonstrates a 1 MiB incremental observation despite a 17 MiB total
output peak. Original learning uses that total peak; corrected warm learning
uses the qualified additional-space observation. These small physical fixtures
are not measurements of the reporter's 81–95 GB directories.

### Actual pressure observation

The existing overlay filesystem reported **0 available bytes** through the
production `statvfs` sampling function. With a 1 MiB floor, the production
free-space observer returned `free_floor`. The benchmark did not fill that
filesystem or delete anything. This executes the pressure observation and
refusal method, not guarded process termination on a live worker.

### Accounting cost

The same invocation scanned the same 2,048-file tree 15 times per variant,
alternating original/candidate order. The candidate scan includes inode-version
signatures and the retained-tree fingerprint.

| Variant | Median complete scan |
| --- | ---: |
| Original | 4.800489 ms |
| Candidate | 14.377503 ms |
| Increase | 9.577014 ms, approximately 3.0x total scan time |

This is a measured cost increase on a shared executor. It is not a performance
win, an SSH benchmark, or an end-to-end remote-build latency measurement. The
reporter's 73–78 second and 31–32 second remote checks were not reproduced here.

## Validation status

| Check | Executed result | Qualification scope |
| --- | --- | --- |
| Focused Python accounting/filesystem tests | 27 passed in 1.445 s | Actual production scan/accounting methods, including cleanup, hardlinks, capped/changing metadata, conservative fallback, source tracking, and pressure predicates |
| Nested sibling-pool regression | 1 passed in 0.143 s | Actual nested source/selected-target/sibling layout; unfunded sibling growth requires cold admission |
| Native accounting/admission and ownership-gate harness | 19 passed, 0 failed | Exact production fragments in isolated scaffolding, including original/candidate replay and two ownership-version/policy tests; not full daemon integration |
| Native upload-construction harness | 2 passed, 0 failed in 0.09 s | Exact production command builders/tests and source-authority factories; binary streams, literal argv, fence ordering, and bounded command length |
| `cargo check --locked -p rch-common --lib` | Passed after final upstream policy integration; exit 0, 20.22 s | Real final common crate; does not establish whole-workspace compilation |
| `cargo fmt --all -- --check` | Passed after upstream integration | Workspace Rust formatting/parsing |
| `git diff --check` | Passed | Changed-file whitespace |
| Full daemon compilation | Incomplete; compiler terminated by `SIGKILL`, exit 101 | No full daemon check or test success is claimed |
| `cargo check --locked --workspace --all-targets` | Attempted once; resource wrapper exit 125 | Interrupted during dependency preparation when retained private files exceeded the 768 MiB ceiling; no pass claimed |
| `cargo clippy --locked --workspace --all-targets -- -D warnings` | Attempted once; resource wrapper exit 125 | Cargo started, then the same file-budget guard interrupted it before source diagnostics; no pass claimed |
| Native guardian/process and live-worker runs | Unavailable in this execution facility | Both original and candidate reject the foreign process namespace |

The upload harness uses test receivers and transport/config scaffolding. It
does not validate a real SSH transport, guardian, source-lease lifetime, or
worker reservation ledger. The complete daemon regression bodies for ownership,
cancellation, API admission, and recovery are included in the implementation,
but their full-crate execution is not established by the isolated results.
The two executed ownership-gate tests copy the actual old/new version match,
warm-policy predicate, writer version, and relevant production types. They check
downgrade rejection, legacy cold queue acceptance, and conditional-budget
validation; they do not execute the complete loader or file migration.

An earlier full Python process-suite attempt ran 68 tests with 42 failures,
9 errors, and 3 skips. Both baseline and candidate monitors refuse this
executor's foreign procfs before launch. The failures were not individually
resolved or classified, and no full process-suite pass is claimed. An attempted
private procfs namespace was denied by the facility; ownership checks were not
weakened to obtain a passing result.

Builds used the pinned nightly Rust 1.100 toolchain, one Cargo job, disabled
incremental/debug output, and bounded process memory. The facility has an
8 GiB cgroup limit as well as a full overlay filesystem. No live RCH worker or
DSR launcher was available in this workspace. GitHub Actions were not dispatched.
The final common check, isolated tests, workspace attempt, and Clippy attempt
used a cgroup-aware guard as well as the retained runner's file-budget guard.
The cgroup OOM-kill counter remained unchanged during those final attempts.
Wrapper exit 125 denotes a resource interruption, not a Cargo source diagnostic.
The workspace attempt left 840,171,520 bytes of retained private files and the
Clippy attempt observed 840,110,080 bytes, both above the 768 MiB ceiling. Caches
were preserved; the limits were not raised to force a passing gate.

## Reproduction and remaining qualification

The benchmark accepts explicit source and output paths and retains its fixtures:

```bash
RCH_DISK_BENCH_DIR=$(mktemp -d)
git show 543cd2ced10aadee8af597046bbf553eb39d7cdd:./rch-common/build_disk_monitor.py > "$RCH_DISK_BENCH_DIR/original.py"
python3 scripts/bench_disk_accounting.py \
  --baseline-monitor "$RCH_DISK_BENCH_DIR/original.py" \
  --candidate-monitor rch-common/build_disk_monitor.py \
  --work-dir "$RCH_DISK_BENCH_DIR" \
  --pressure-probe "$RCH_DISK_BENCH_DIR" \
  --output "$RCH_DISK_BENCH_DIR/results.json"
```

The pressure result depends on the chosen filesystem's actual capacity; an
ordinary healthy volume should be allowed. No command fills the disk to force
the observed refusal. Repeated timings will vary with filesystem and host load.

Original monitor SHA-256:
`c2058c9f06c7f268c288f7d389f0d352c3252c7e3c238b583d08285ce2a94bb8`.
Candidate monitor SHA-256:
`ef184fb890c782d8a433cc0c3b8ec551ca4d10f6002ef8710724b1523e94b7ec`.
The original bytes match both the initial inspected checkout and the final
implementation parent; subsequent upstream policy changes did not alter them.

Before claiming live-worker qualification, run the complete workspace compiler,
strict Clippy, daemon/client recovery regressions, and process-monitor suite on
a supported host; then repeat the three-build scenario with actual retained
targets while recording decisions, ownership, capacity samples, and peak output.
That live qualification and SSH performance work remain open.

Conservative operating limits remain intentional: two qualifying successes are
needed to bootstrap a warm pool; missing initial source evidence refuses before
upload; large unproven sibling pools stay charged; changed inputs can exceed a
warm allowance and stop without replay; and sampling does not provide filesystem
quota containment between observations.
