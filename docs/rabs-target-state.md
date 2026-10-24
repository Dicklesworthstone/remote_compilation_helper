# Worker-local Cargo target state

The canonical worker can retain Cargo target trees after successful builds or
ordinary completed compile, lint or test failures, then seed later builds with
independently owned copies. Cargo or Clippy executes on every request and
decides which compilation steps are fresh. This accelerates repeated commands,
ordinary build/check/test transitions, changes to package or target selection,
and Clippy runs across local source and data edits. Every request still executes
its current command and verifies its current result.

## Enable it on a worker

Add a byte limit to the worker's existing authenticated coordinator command:

```sh
rabs-wkr --coordinator 10.0.0.1:7091 --worker-id builder \
  --target-cache-bytes 1073741824
```

Keep the worker's existing TLS and durable admission configuration. The default
is `0`, which disables target retention. The maximum configured limit is 8 GiB.
The pool admits at most eight retained or pending seeds, and each complete target
tree must also fit the existing 1 GiB tree inventory limit. Pending captures count
against the pool before copying begins; old unused seeds are evicted when needed.
The byte limit counts target file payload. Durable metadata has a separate
16 MiB cap per generation; directory and filesystem allocation overhead also
remain subject to the existing file and directory count limits.

`RABS_WORKER_TARGET_CACHE_BYTES` also sets this limit; an explicit CLI value
takes precedence. Without a runtime epoch the pool belongs to the worker process
and survives coordinator reconnects, but a worker restart drops its seeds.

For a worker whose host runtime is kept stable, also select an operator-managed
epoch to retain completed seeds across restarts:

```sh
RABS_WORKER_TARGET_CACHE_BYTES=1073741824 \
RABS_WORKER_TARGET_CACHE_EPOCH=worker-image-2026-01 \
  rabs-wkr --coordinator 10.0.0.1:7091 --worker-id builder
```

The equivalent CLI option is `--target-cache-epoch worker-image-2026-01`.
The epoch is a version label supplied by the operator, not an automatically
measured host identity. It must contain 1–128 ASCII letters, digits, dots,
underscores or hyphens and start with a letter or digit. An absent or explicitly
empty epoch selects process-only retention. CLI values override the environment.

Keep the epoch unchanged only while all host tools, system libraries, headers,
configuration and other runtime inputs visible to builds remain unchanged.
Before updating those inputs, stop the worker and its builds, change to a new
epoch, then restart the worker on the updated runtime. An epoch change starts
with cold target state. Do not reuse an earlier epoch label for a later runtime
change. Captured toolchains and source still have their own exact identities;
the epoch does not replace those checks.

Durable seeds live beneath `target-cache` in the worker's existing private
journal directory. The store has an independent lifetime lock and admits one
local owner. Only the final completion fence can publish a durable seed;
staged, cancelled or interrupted captures cannot become hits after restart.
Startup verifies persisted metadata and target bytes before admitting a seed,
and each execution receives an independently verified private copy. Epoch
changes and byte-limit reductions use the same bounded store instead of leaving
an unbounded directory per epoch. Neither durable nor process-only mode shares
writable target files between workers or executions.

Managed deployments accept the same two environment settings through
`scripts/rabs_fleet_deploy.sh`. Omitted values retain the active managed settings
during an upgrade. An explicit zero byte limit disables retention; an explicit
empty epoch restores process-only retention. A disabled store is dormant until
enabled again, when the supplied epoch and quota are checked.

No new Cargo profile field is needed for ordinary target retention. Both the
direct and durable daemon modes of [canonical Cargo](rabs-canonical-cargo.md)
can use an enabled worker. Requests
must have a verified uploaded workspace, captured toolchain, and an explicit
Cargo artifact-report contract. Dependency-only execution and generic artifact
requests keep their existing behavior.

### Retain private rustc incremental state

Set `"incremental": true` in the canonical Cargo profile to run with
`CARGO_INCREMENTAL=1`. This explicitly overrides Cargo's per-profile incremental
setting. The default and `false` keep `CARGO_INCREMENTAL=0`. Both values enter
the actual command environment and select different target families; changing
the toolchain, compilation profile or other keyed controls still starts cold.

The explicit `cargo-private-incremental-json-v1` and
`cargo-private-incremental-test-json-v1` output contracts keep compiler state
under the selected profile's `incremental` directory on the worker. An explicit
target triple also selects that target's profile directory. The worker and
coordinator derive these exact paths independently. A similarly named binary,
custom profile, or generated output is not omitted. Every Cargo-reported output
must still appear in the delivered artifact manifest. Older output contracts
continue to return their complete regular-file trees.

The retained seed contains the complete target, including rustc's dep-graph,
query-cache and work products. A new execution receives its own writable copy;
the retained seed and concurrent attempts share no writable inodes. Cargo and
rustc validate that state during the current command. Normal edits can reuse
it, and persistent mode can retain it across worker restarts under the same
runtime epoch. Tests always execute again.

Only delivered artifacts consume transport payload bytes. The complete tree,
including omitted compiler state and internal hardlink aliases, still counts
toward the existing 1 GiB, 4,096-file and 16,384-entry inventory limits and the
configured target-pool quota. Its full namespace receives the same symlink,
hardlink, special-file and mutation checks before any artifact is offered.
Without worker target retention, an incremental build still runs with fresh
private storage, but the next operation has no retained seed to reuse. This
mode does not transfer incremental snapshots to other workers or authorize
fine-grained action-cache serving.

## What can reuse a seed

An exact match binds the complete captured source manifest, dependency projection,
toolchain, compilation arguments, final command environment, working directory,
canonical namespace policy, output location and required files, and effective
worker job grant.
The pool also separates worker identities, coordinator endpoints, and
authenticated coordinator certificate keys.

Changing a captured dependency, environment value, feature flag, toolchain,
output location or required files, or effective job grant starts with a fresh
target. The restricted local input edit family below is the only exception
to exact source bytes. An identical invocation can reuse its prior target while Cargo
still runs the requested command, including test executables for `cargo test`.

An exact invocation match is preferred. Otherwise, ordinary `build`, `check`,
`test --no-run`, and `test` commands may select the most recent compatible
target. Compilation settings and non-editable captured inputs remain exact. The
command name, test execution switch, test filter, failure policy, and arguments
after the test harness separator do not fragment this optional target pool.
Package selectors (`--package`/`-p`, `--workspace`/`--all`, `--exclude`) and target
selectors (`--lib`, `--bin`, `--example`, `--test`, `--bench`, their plural forms,
and `--all-targets`) may also change. Cargo still receives every original
argument and checks the selected units' own fingerprints. Feature, profile,
target triple, compiler, environment, and other compilation settings stay exact.
Unknown argument forms keep exact-invocation reuse only.

For example, `cargo build` followed by `cargo test --no-run` can reuse compiled
dependencies while building the new test targets. A subsequent `cargo test`
can reuse those compiled targets and still executes the tests. Check and build
may require different compiler outputs, which Cargo creates as necessary. A
restored target therefore does not imply that every compiler artifact is fresh.
Every invocation reports and verifies its own diagnostics, exit status and
cancellation outcome. Successful invocations also require their current
artifact report.

Selecting one workspace library and later selecting a binary or example can
therefore reuse their shared dependencies while compiling the newly requested
target. Switching to a different package never serves the earlier package's
artifact report. A selected test still runs its harness and returns its current
failure even when all compilation steps are fresh.

Canonical Clippy has its own compatibility family. Repeated Clippy invocations
and the eligible source/data edits below can reuse a previous Clippy target. The
captured `cargo-clippy`, Cargo and rustc bindings, all package/target selectors,
`--no-deps`, and every argument after Clippy's lint separator remain exact,
including their order. Clippy can otherwise consider a previously unlinted
dependency fresh when that package becomes a selected lint target. Keeping its
selectors exact ensures the newly selected package actually receives its lints.
Changing an allow/deny level also starts with a fresh target; the current Clippy
process must recheck affected units and report any current lint failure. Cargo
build/check/test targets and Clippy targets use separate families.

The worker gives each eligible execution a fresh HOME and a captured or empty
Cargo home. Its jobserver has a stable canonical FIFO name but a new private
FIFO and independent token budget for each execution. The final environment,
including that actual grant, participates in the match.

### Reuse after local source and data edits

For a workspace with local/path packages, a compatible target can survive edits,
additions, removals and renames of ordinary non-executable source and data files.
This includes `.rs` files and `build.rs`, text and binary assets consumed through
`include_str!` or `include_bytes!`, and schemas, templates, headers or other
inputs tracked by build scripts. Cargo applies its usual dep-info and
`rerun-if-changed` rules to the current bytes and restored target. Build scripts
remain responsible for declaring the inputs they read.

`Cargo.toml`, `Cargo.lock`, `rust-toolchain`, `rust-toolchain.toml`, `clippy.toml`,
`.clippy.toml`, all `.cargo` and `.git` descendants, `.gitignore`, `.gitattributes`,
`.gitmodules`, executable inputs, and all files underneath a
`.cargo-checksum.json` package root remain
exact in content, membership and executable mode. Those controls and immutable
dependencies still select a fresh target when changed. Unknown commands and
arguments retain exact-invocation reuse only.

This also applies to isolated `cargo_home_source` projections, including captured
registry archives and locked Git databases. The worker retains the admitted
projection's complete transport identity and its separate cache/workspace
manifests. Source edits may change only the eligible workspace files: every
cache member's path, bytes, size and executable bit, along with the projection
version and transport prefix, must remain exact. Adding, removing, renaming or
changing a cache file starts with a fresh target, even if that file ends in `.rs`.
The worker verifies that both partitions belong to the current admitted source
before selecting a compatible seed or replacing the workspace mount.

The legacy `registry-cargo-home-v1` contract, which leaves the transport prefix
visible in the workspace, retains exact-source compatibility only. Vendored
packages also remain exact because Cargo does not track registry/Git source
mtimes. Input capture and planning still validate the complete current source.

The worker compares the previous and current manifests, never incoming mtimes,
to identify edits and membership changes. It copies only the current source
tree: removed modules and directories are not restored from an older workspace.
Unchanged files receive their retained timestamps in the new private workspace.
Edited or added files and all surviving parent directories of changed, added,
removed or renamed files receive the current worker time. On membership changes,
ancestor `Cargo.toml` files also receive that time, without changing their bytes,
so default package-scanning build scripts cannot miss a deletion with no changed
file left behind. Unrelated packages retain their previous timestamps.

The current worker time must be strictly later than every retained source and
target timestamp, including Cargo's fingerprint and build-script records.
The worker reads back the complete timestamp plan and re-verifies current bytes.
A regressed clock or inadequate filesystem timestamp precision refuses optional
restoration and builds cold; output timestamps are never changed to force a hit.
Directory mode changes and empty-directory changes unrelated to the admitted
source/data membership changes also refuse optional restoration.

Cargo or Clippy still runs and decides which local units/dependents to rebuild
or relint. Tests run again even when their compiled state can be reused. The
exact invocation key, current source manifest, output checks and final completion
fence remain unchanged. This is not a cross-source action-cache hit or cached
test outcome.

### Reuse after a failed compile, lint or test

A normally exited Cargo or Clippy command with status 1–127 can leave useful
completed dependencies even when another crate does not compile, a lint is denied
or a test fails. The worker can retain that complete private target tree and
restore it for the next command. Cargo reads its own fingerprints, rebuilds
unfinished or changed units, and executes the requested tests again. A repeated
failing test command still returns its nonzero status and current diagnostics;
fixing the source can reuse completed dependencies without treating the earlier
failure as a successful result.

Failure seeds have no successful artifact offer. Missing final outputs are
never invented, and no failed target tree is delivered as a completed build.
The snapshot must pass the same byte, file-count, path, internal-hard-link and
mutation checks as other private target state. Its source bytes and timestamps
are verified before and after capture. Empty or unsafe partial trees simply
do not produce a seed.

## How ownership and freshness work

The worker first validates the original sealed source and its namespace. Cold
and contended lookups keep that existing read-only workspace; they do not copy
it just to discover that no target seed is available. Cold attempts still
revalidate the complete source before staging a target seed.

Only a matching target seed triggers creation and verification of a separate
runtime workspace. Only that private copy may receive retained timestamps or
the source-edit timestamp plan; the original captured source and seal stay untouched.
The source and target mounts are replaced together after both original backing
identities match, and the final namespace is validated again. The execution
attempt retains its private source owner through process cleanup and capture.
A failed optional restore exposes neither a partial target nor a partial source
copy to the compiler.

A seed is copied into a fresh execution target, preserving bytes, ordinary
permissions, original modification times, empty directories, and verified
internal hard-link relationships. Each copy owns its inodes independently of
the seed, other attempts, and shared storage. Output timestamps are preserved,
not advanced to make Cargo consider an output fresh. The namespace mounts only
the execution's private target writable.

Normal process completion, zero residual descendants, verified diagnostics,
source validation and the final cancellation check are required before a
pending seed enters the pool. The seed must match the observed native exit
status. A zero exit additionally requires the complete validated successful
artifact offer; an ordinary nonzero Cargo exit may retain private state without
such an offer. Signal termination of the native launcher and exit statuses
128–255, which namespace launchers may use to report an inner signal, cannot
publish seeds. Cancellation, deadlines, lost execution leases, uncertain cleanup
and invalid captures also prevent publication. A later result-delivery or
retention failure can leave valid local target state; that
state does not authorize serving or replaying a compiler result.

Corrupt, changed, oversized, or unavailable seeds are refused. Directories must
retain owner read, write, and search permission so cancellation and eviction can
clean up their private copies; unusual directory modes bypass optional seeding.
An optional target-state failure leaves the command with fresh target storage, subject to
its ordinary execution deadline and cancellation. A busy pool also permits a
cold execution without waiting for another build's copy.

## Observe reuse

Worker stderr includes structured events:

- `worker-target-state` reports `cold`, `restored`, `restored-compatible`, `restored-edited`,
  `cold-after-refusal`, or `cold-pool-busy`, together with the request ID and
  matching-key digest.
- `worker-target-state-refused` explains an optional capture or restore failure.
- `worker-target-state-published` reports the accepted seed size, retained byte
  total, and entry count.
- `worker-target-state-recovered` reports the seeds and payload bytes admitted
  after reopening a durable store. Recovery or persistence refusal events explain
  rejected generations; `worker-target-state-storage-disabled` means uncertain
  reclamation has stopped further durable writes until successful recovery.

`restored`, `restored-compatible`, or `restored-edited` means a verified private target was provided
to Cargo. Cargo's own artifact JSON `fresh` fields show whether compilation was
skipped. The build's
diagnostics, exit status, artifact verification, and delivery acknowledgments
still come from the current execution.

This is ordinary Cargo hot state, not RABS action-cache publication or proof of
a complete action input closure. Build scripts retain Cargo's normal input
tracking obligations. Host tools and system libraries visible in its canonical
runtime are not all captured by the toolchain identity. After changing those
inputs, process-only mode requires a worker restart and durable mode requires
the new runtime epoch described above. The separate gates for observation, recipes, closed
views, and verified action serving remain in force.
