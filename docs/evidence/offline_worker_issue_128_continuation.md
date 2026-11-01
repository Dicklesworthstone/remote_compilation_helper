# Issue #128 continuation: disablement and recovery ownership

## Scope and source identity

This November 1, 2026 continuation records additional failures found after the
[current-main follow-up](offline_worker_issue_128.md). It preserves that earlier
evidence and tests the remaining lifecycle, persistence, and artifact-retrieval
paths. The [companion JSON](offline_worker_issue_128_continuation.json) retains
exact source blobs, binary identities, baseline observations, and log hashes.

The baseline is `dceec4f39021c5fb0be3b43276f83063c0d7fe75`. Three functional
corrections were published directly to main:

| Correction | Commit |
|---|---|
| Retain recovery records when durable enable fails | [`2c77f402`](https://github.com/Dicklesworthstone/remote_compilation_helper/commit/2c77f402407a2c27fdbbefb2a38ac68f2f924772) |
| Preserve disablement through inventory removal and return | [`9f267909`](https://github.com/Dicklesworthstone/remote_compilation_helper/commit/9f267909cba71ede3b23dfae74f83987d7b2dc33) |
| Retain source ownership during custom-target retrieval | [`33e68124`](https://github.com/Dicklesworthstone/remote_compilation_helper/commit/33e681245dec8a66580e4a5141d119c81a25f8c0) |

The measured daemon was built after upstream `5163bfb6`. Subsequent publication
preserved incoming upstream `4885980a`, with identical owned worker, reload,
and fixture blobs. The combined CLI incorporates that upstream's disk-budget
change and the retrieval correction; its tested code commit is `33e68124`.
Exact commit parents, source blobs, and binary identities are in the JSON.

Validation is complete for the scopes recorded below. The unit suites, focused
process checks, full OpenSSH fixture, CLI/retrieval tests, lifecycle integration,
and formatting passed. Full-workspace check and strict Clippy also passed. The
seven-file supporting correction and its selected runtime tests were validated
on the exact source published as
[`3b69bf58`](https://github.com/Dicklesworthstone/remote_compilation_helper/commit/3b69bf587fd8cc66fd16e8e0872996e2f27a86e4),
whose parent is `33e68124`. Ignored tests and the limits of these scopes are
identified below.

## Failures and corrections

### Failed durable enable lost the recovery record

`BypassRecordStore::remove` removed its live record before attempting the durable
write. When that write failed, a manual enable returned an error while deleting
the row needed by automatic recovery. The worker remained quarantined, and the
recovery scanner could no longer find its retained failure state.

The baseline store regression and daemon manual-enable regression both fail
because the expected record becomes `None`. The correction persists a proposed
map before replacing the live map. Failed retirement therefore retains the
record and its retry path. Tests cover repeated persistence failures, automatic
rejoin, manual retry, restart, an unaffected peer, and preservation of three
owned slots and their active-build history.

### Configuration removal cleared explicit disablement

Removing a busy worker from configuration changed its administrative state from
`Disabled` to `Draining`. The active build prevented immediate removal, leaving
a worker whose background SSH permission had reopened. This is observable
through the actual daemon API and transport processes:

| Baseline transport | New SSH dials | Observation window | Dial spacing | Owned slots |
|---|---:|---:|---:|---:|
| Instrumented SSH subprocess | 2 | 3.2396s | 0.2112s | 3 |
| Real local OpenSSH | 2 | 3.2456s | 0.2701s | 3 |

Both runs warmed the two SSH pools, reserved three slots, explicitly disabled
the worker, removed it through `POST /reload`, and observed `draining` with the
original active build still present. Both fail on the new-dial assertion. The
preserved daemon SHA-256 is
`d92ac5721f892808108c1fb059bcce630131d781b0d5ca113a2ec866963cbe22`.
Partial phase JSON, transport events, and daemon logs were retained before each
failed assertion. Cleanup left no live transport with a recorded process identity.

The correction separates configuration absence from operator intent. A disabled
worker remains disabled while its existing work drains; a pending disable also
retains its completion action. Reintroducing an identical configuration clears
only the removal request. The process regression additionally requires silence
after re-addition and restart, rejects scheduling after enable while connectivity
is still unproven, and restores scheduling after a successful recovery probe.
Only explicit release may relinquish the original three-slot reservation.

Both focused candidate runs passed with zero new SSH dials during removal,
identical re-addition, and restart. Each retained all three original slots until
explicit release. Enabling against a refused endpoint produced two bounded
probe dials; after the endpoint recovered, successful probing restored service
in 3.475s with OpenSSH and 3.493s with the subprocess fixture. The daemon binary
SHA-256 remained
`16b2b0419e9402808c11839ab448b1e1ee0f275a00f2df53718e99c365c6d8b6`
before and after both runs.

Returning an enabled worker to inventory also wakes waiting monitors without
resetting its next-probe deadline. A paused-clock regression verifies the normal
30-second health deadline and a 900-second offline recovery deadline exactly.

### Custom-target retrieval lacked the execution grant

The custom `CARGO_TARGET_DIR` retrieval path constructed a fresh transfer
pipeline without the original source-authority identity. Its artifact size and
header probes and rsync sender consequently lacked the invocation's activity
lock and cancellation fence.

The correction attaches the existing identity before creating the staging
pipeline, so ordinary collection and recovery retries retain the same grant.
The process regression uses real rsync and flock behind an isolated SSH command
fixture: a missing exact grant must refuse, a held activity lock must queue the
read, another valid grant must still retrieve its own bytes, and cancellation
while queued must prevent the first reader from accessing the target pool.
This regression passed in the 67-test combined-source CLI suite, alongside the
incoming disk-budget regression. Baseline attempts stopped during compilation,
so this defect has source evidence and a passing combined-source regression
without an observed failing baseline execution. The JSON identifies corrected
fixture errors and incomplete attempts separately from accepted results.

### Supporting corrections for workspace validation

The workspace gates exposed narrow compatibility and lint defects in existing
RABS paths. The supporting corrections preserve their contracts:

- The corruption test holds the store lock, opens its fixture database through
  the existing SQL engine, and asserts that exactly one committed publication
  is corrupted. The production metadata store keeps its encapsulated API.
- Named callback aliases retain borrowed mutable callbacks, their lifetimes,
  and their existing result types.
- Large payloads in private enums are boxed and moved into their original
  consuming operations, preserving single ownership and control flow.
- A mutable local counter exercises the same archive-member limit, and borrowed
  slice comparisons retain the same materialization assertions without clones.

These changes were published unchanged as `3b69bf58`. The targeted runtime run
passed six `rabs-cas` tests and fifty-eight `rabsd` tests, including both sticky
metadata-corruption tests and the recursive submodule-limit test. These checks
support existing paths; they do not establish new RABS qualification.

## Validation results

| Gate | Observed result |
|---|---|
| Fresh common unit suite | **2,498 passed, 8 ignored, 0 failed**, 24.06s |
| Fresh daemon unit suite | **1,929 passed, 0 ignored, 0 failed**, 132.15s |
| Six new daemon regressions | All passed within the full daemon suite |
| Baseline removal process scenario | Failed on actual new dials in both transport modes |
| Candidate removal process scenario | Passed with zero disabled-worker dials in both modes |
| Full OpenSSH process fixture | Passed against measured daemon `16b2b041`; binary hash unchanged |
| Combined-source CLI selected suite | **67 passed, 0 failed**, 0.80s |
| Combined-source CLI all-target strict Clippy | Passed, 1m 10s |
| Common/daemon all-target strict Clippy | Passed, 1m 35s |
| Final CLI executable build | Passed, 1m 05s |
| Final daemon lifecycle integration | **17 passed, 0 failed**, including the full synthetic offline-worker fixture, 133.56s |
| Final jobs lifecycle integration | **8 passed, 0 failed**, 6.23s |
| Final formatting | Passed |
| Full-workspace strict Clippy | Passed on the published supporting snapshot, 58.40s |
| Full-workspace check | Passed on the same snapshot, 18.13s |
| Workspace-correction formatting | Passed |
| Selected `rabs-cas` runtime tests | **6 passed, 0 failed, 0 ignored**, 0.26s |
| Selected `rabsd` runtime tests | **58 passed, 0 failed, 1 ignored**, 0.67s |

The selected RABS test build completed in 7m 18s. Its existing ignored test,
`toolchain_capture_requires_real_reflink_and_retains_independent_bytes`, requires
`RABS_REFLINK_TEST_ROOT` on a real reflink-capable filesystem. The exact selected
test invocation, filters, build controls, four-test-thread setting, per-test
outcomes, and workspace commands are retained in the JSON. These selected
runtime results are not a full-workspace runtime test run.
The common suite's eight existing ignored tests use global mock state and
request serial execution; their exact names and reasons are also retained in
the JSON.

The accepted logs show compilation from the actual candidate repository root,
and the JSON binds executable hashes and source blobs separately. The 67-test
CLI run preceded restoration of a misplaced existing lint annotation; runtime
code was unchanged, and strict Clippy passed on the final published blob.
Stale artifacts, fixture mistakes, failed compilation, and the corrected lint
integration failure remain documented in the JSON rather than counted as
accepted validation.

The first full-workspace check and strict Clippy attempt each exited 101. They
exposed an existing RABS corruption-test API mismatch, a mutable-constant
warning, and type-size/complexity lint errors. The logs show compile and lint
failures rather than a resource kill. Narrow corrections preserve the corruption
assertions, callback contracts, and materialization comparisons. Strict
full-workspace Clippy, the same-source check, formatting, and selected runtime
tests subsequently passed. The JSON retains the first failures, intermediate
findings, and the exact accepted and published source snapshot.

Final lifecycle tests rebuilt the published `33e68124` source and used CLI
SHA-256 `c331c6d0d76b70850d85654b668241fc1ef43128e937622699394719768a1431`
and daemon SHA-256
`b7a0785e3b59a05fc725d2b023ebdb86ff5cd7b9395da812135ad1aabc13d934`.
The final synthetic fixture therefore validates the combined published source.
The earlier OpenSSH rate measurements retain their separate `16b2b041` daemon
identity and are not relabeled as measurements of the rebuilt executable.

The full OpenSSH fixture recorded three recovery dials over 9.206 seconds, with
a minimum spacing of 3.058 seconds at a configured three-second recovery
interval. Twelve concurrent capability refresh requests added no offline-worker
dials. Freezing two already authenticated transports produced one dial over
6.232 seconds while allowing twelve admissions to a healthy peer and retaining
the original three-slot reservation. With fourteen blackholed workers, live
blackhole transports peaked at twelve while twenty-four healthy admissions and
two health heartbeats completed. These short configured test intervals exercise
the bounded behavior; they are not production outage-rate measurements.

Post-run checks found no identity-matching live transport among the twenty-two
dial events from the focused runs or the seventy-seven dial events from the
full OpenSSH run. The checks compared recorded PID birth ticks in the same PID
namespace and did not signal processes.

These tests do not reproduce the reporter's original RCH 1.x/Tailscale rates.
The OpenSSH fixture performs real local authentication but supplies deterministic
worker replies and does not run a remote build. Reserved slots exercise daemon
ownership and restart semantics, without claiming that a compiler was executing.
No RABS qualification, fleet deployment, or performance improvement is claimed.
