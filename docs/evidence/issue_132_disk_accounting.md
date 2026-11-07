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

## Follow-up: queue continuity, explicit retry intent, and Cargo cache coverage

Implementation and regression commit:
[`6943790888290c2a16e1de19bba0d1782e8393f3`](https://github.com/Dicklesworthstone/remote_compilation_helper/commit/6943790888290c2a16e1de19bba0d1782e8393f3),
directly on `main`, based on `4d7927d327ca190c32b31127b4d0134b7f9b237a`.
Concurrent source-ownership, RABS, and stale-capacity refresh changes were
preserved.

The follow-up extends the same issue correction in three places. Fresh
capacity that proves a request fits alone now permits a durable wait behind
competing reservations. It does not admit the request, discount another owner,
or waive the post-completion probe. Existing waiters retain their original
deadline across that probe gap; expired, missing, or superseded observations,
genuine pressure, and requests that do not fit alone remain refusals.

A positive configured headroom is now solely a minimum. Ordinary durable
execution and preview can still use verified target credit. The exact
prelaunch cold retry has separate client intent and omits warm capability even
if concurrent learning increases the cold requirement. A later queued attempt
binds its predecessor's completion receipt, so an old completed attempt no
longer prevents a legitimate cold retry from waiting. Recovery, cancellation,
receipt retention, and unrelated ownership publication preserve that binding.

Dispatcher-managed Cargo execution now scans the worker-resolved durable Cargo
home, supported literal absolute overrides, and physical destinations of known
registry/Git redirects. It reserves and samples every resulting filesystem.
Existing cache allocations remain unproven baseline; only the selected target
has retained credit. Unknown cache scope refuses before execution and cannot
produce a misleading complete learning sample. Non-Cargo commands retain their
original classification through shell wrapping. Direct `rch-wkr execute`
remains cold-only with its existing cache-volume probes; it has not gained the
dispatcher's output attribution for cache allocations or command-local home
overrides.

### Executed paired follow-up benchmark

The same reusable benchmark was extended with the actual worker-side cache
resolver and rerun against the original monitor and final follow-up monitor.
The existing raw JSON preserves the first run and stores this run under
`followup_2026_11_05`. Candidate SHA-256:
`ce914cd4dff8440850ffe23e76d064ccacc0e137afa090a0e8e37278120fb00a`.

The new case starts with a 16 MiB target, frees that retained file, and then
writes 8 MiB into the separate durable Cargo cache under a 4 MiB budget. These
are real allocated files. Free space increased by 8 MiB, so net filesystem size
could not expose the write. The fixture's largest observed combined allocation
was 16,793,600 bytes including directory blocks; final allocation was 8,404,992
bytes. The guard results were:

| Accounting and declared roots | Observed growth charge | Output guard result |
| --- | ---: | --- |
| Original target-only accounting | 0 bytes | Allowed |
| Corrected target and durable-cache accounting | 8,404,992 bytes | `growth` |

The corrected new/modified allocation counter was 8,392,704 bytes; 12,288 bytes
of unproven cache-directory baseline supplied the remaining charge. This
executes the actual resolver and accounting methods with a synthetic observer
identity. It does not launch or terminate a guarded remote build.

The other physical cases also executed again: warm and cold output, cleanup,
three overlapping child writers, a rewritten retained inode, and an unproven
source/cache baseline. Small directory allocations differ from the first
filesystem's results and are retained exactly in the JSON.

| Same-invocation 2,048-file scan, 15 alternating runs | Median |
| --- | ---: |
| Original monitor | 6.710740 ms |
| Follow-up monitor | 16.179687 ms |
| Increase | 9.468947 ms, approximately 2.41x total scan time |

This scan-only comparison measures the combined accounting correction against
the original monitor. It does not isolate the cache resolver's incremental
cost, and it establishes no end-to-end latency improvement. The available
filesystem now had 22,658,437,120 bytes free and the 1 MiB floor probe correctly
allowed it; unlike the first run, this was not an exhausted-volume condition.
The separate cache regression executes a real distinct-device `statvfs` sample
against a configured floor above its available bytes without filling the disk.
Both monitors still rejected this facility's foreign process namespace, so
live guardian/process qualification remains unavailable here.

Eight focused Python cache regressions passed in 0.163 seconds. They cover
cleanup-hidden growth, uncredited retained cache, cold footprint coverage,
small warm downloads, explicit and redirected cache identities, bounded
directory preparation, unresolved scope, and distinct-filesystem floor
protection. Full daemon/client compilation and new Rust regression execution
remain unestablished by these local Python and filesystem results.

### Follow-up native validation status

The pinned `nightly-2026-08-31` toolchain was installed and verified. A shallow
fetch verified the exact locked asupersync commit
`78b64636e99fea4ea2d868096576021dd3b8e519`; a subsequent ordinary
`cargo fetch --locked --target x86_64-unknown-linux-gnu` completed in 9.283 seconds.
Neither the manifest nor lockfile was changed to make the build easier.

| Final check | Executed result |
| --- | --- |
| Focused Python cache regressions | 8 passed, 0 skipped, 0.163 s |
| Paired production filesystem/accounting benchmark | Completed, including the new cache-growth case and all prior physical cases |
| Changed Rust files, pinned formatting | Passed through targeted formatter checks; not a workspace Cargo-format pass |
| `git diff --check` | Passed |
| `cargo check --locked -p rch-common --lib` | Resource guard interrupted dependency compilation at Tokio after 49.588 s; changed crate source was not checked |
| `cargo check --locked --workspace --all-targets` | Resource preflight blocked before Cargo, exit 125; 24,563,712 bytes estimated headroom |
| `cargo clippy --locked --workspace --all-targets -- -D warnings` | Resource preflight blocked before Cargo, exit 125; 873,316,352 bytes estimated headroom |
| `cargo fmt --all --check` | Resource preflight blocked before Cargo, exit 125; 761,552,896 bytes estimated headroom |
| New/expanded Rust regression filters | Not executed |
| Live worker, full process guardian, and SSH latency qualification | Unavailable |

The resource guard used one Cargo job, one compiler frontend thread, disabled
incremental/debug output, a task-exclusive cache, and a 768 MiB stop threshold
within the shared 8 GiB cgroup. Unrelated jobs repeatedly consumed the available
memory. The final wrapper failures are resource refusals, not compiler
diagnostics. No completed native source check or native regression pass is
claimed for this follow-up. The complete recorded command statuses and source
hashes are preserved under `followup_native_validation` in the JSON evidence.
The prior native results earlier in this report belong to the first
implementation and do not qualify this follow-up.

The unexecuted Rust coverage includes the `disk_contention_` and
`queued_retry_predecessor_` filters for admission, endpoint epochs, pressure,
completion probes, queued cold retries, restart, cancellation, receipt pruning,
and stale releases. Client regressions cover ordinary positive minima versus
explicit cold retries and preview capability. The `cargo_disk_cache` filter
covers original-command parsing, wrapper option values, preserved non-Cargo
scope, and typed prestart refusal without a learning sample. These remain
required host-side qualification before treating the changes as fully tested.
