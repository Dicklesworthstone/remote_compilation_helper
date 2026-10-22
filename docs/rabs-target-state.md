# Worker-local Cargo target state

The canonical worker can retain successful Cargo target trees and seed later
builds with independently owned copies. Cargo executes on every request and
decides which compilation steps are fresh. This accelerates repeated commands
and ordinary build/check/test transitions, including bounded local Rust-source
edits, without serving a stored compiler result.

## Enable it on a worker

Add a byte limit to the worker's existing authenticated coordinator command:

```sh
rabs-wkr --coordinator 10.0.0.1:7091 --worker-id builder \
  --target-cache-bytes 1073741824
```

Keep the worker's existing TLS and durable admission configuration. The default
is `0`, which disables target retention. The maximum configured limit is 8 GiB.
The pool admits at most eight retained or pending seeds, and each target tree
must also fit the existing 1 GiB artifact transport limit. Pending captures count
against the pool before copying begins; old unused seeds are evicted when needed.

The worker process owns this pool across coordinator reconnects. It does not
persist seeds across worker restarts or share them with another worker process.
Run a reconnecting worker to benefit across separate canonical builds; a worker
started with `--once` exits after its one session and drops the pool.

No new Cargo profile field is needed. Both the direct and durable daemon modes
of [canonical Cargo](rabs-canonical-cargo.md) can use an enabled worker. Requests
must have a verified uploaded workspace, captured toolchain, and an explicit
Cargo artifact-report contract. Dependency-only execution and generic artifact
requests keep their existing behavior.

## What can reuse a seed

An exact match binds the complete captured source manifest, dependency projection,
toolchain, compilation arguments, final command environment, working directory,
canonical namespace policy, output location and required files, and effective
worker job grant.
The pool also separates worker identities, coordinator endpoints, and
authenticated coordinator certificate keys.

Changing a captured dependency, environment value, feature flag, toolchain,
output location or required files, or effective job grant starts with a fresh
target. The restricted local Rust-source edit family below is the only exception
to exact source bytes. An identical invocation can reuse its prior target while Cargo
still runs the requested command, including test executables for `cargo test`.

An exact invocation match is preferred. Otherwise, ordinary `build`, `check`,
`test --no-run`, and `test` commands may select the most recent compatible
target. Compilation settings and non-editable captured inputs remain exact. The
command name, test execution switch, test filter, failure policy, and arguments
after the test harness separator do not fragment this optional target pool;
the current Cargo process still receives every original argument. Compiler and
target-selection options retain their exact spelling and order. Unknown
argument forms and Clippy keep exact-invocation reuse only.

For example, `cargo build` followed by `cargo test --no-run` can reuse compiled
dependencies while building the new test targets. A subsequent `cargo test`
can reuse those compiled targets and still executes the tests. Check and build
may require different compiler outputs, which Cargo creates as necessary. A
restored target therefore does not imply that every compiler artifact is fresh.
Every invocation produces and verifies its own artifact report, diagnostics,
exit status, and cancellation outcome.

The worker gives each eligible execution a fresh HOME and a captured or empty
Cargo home. Its jobserver has a stable canonical FIFO name but a new private
FIFO and independent token budget for each execution. The final environment,
including that actual grant, participates in the match.

### Reuse after local Rust-source edits

For a workspace with local/path packages, a compatible target can survive edits,
additions, removals and renames of non-executable `.rs` files, including `build.rs`.
Non-Rust files (including manifests, lockfiles, Cargo configuration and data read
by build scripts), executable inputs, and all files underneath a
`.cargo-checksum.json` package root remain exact in content, membership and
executable mode. Changing those inputs still selects a fresh target. Unknown
commands and arguments retain exact-invocation reuse only.

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
Rust membership changes also refuse optional restoration.

Cargo still runs and decides which local units/dependents to rebuild. Tests run
again even when their compiled state can be reused. The exact invocation key,
current source manifest, output checks and success-only seed publication remain
unchanged. This is not a cross-source action-cache hit or cached test outcome.

## How ownership and freshness work

The worker first validates the original sealed source and its namespace. Cold
and contended lookups keep that existing read-only workspace; they do not copy
it just to discover that no target seed is available. Cold attempts still
revalidate the complete source before staging a successful target seed.

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

Successful execution, process cleanup, diagnostic verification, artifact
capture, and the final cancellation check must all succeed before a pending
seed enters the pool. Failed or interrupted commands cannot publish a seed.
A later result-delivery or retention failure can leave valid local target state;
that state does not authorize serving or replaying a compiler result.

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

`restored`, `restored-compatible`, or `restored-edited` means a verified private target was provided
to Cargo. Cargo's own artifact JSON `fresh` fields show whether compilation was
skipped. The build's
diagnostics, exit status, artifact verification, and delivery acknowledgments
still come from the current execution.

This is ordinary Cargo hot state, not RABS action-cache publication or proof of
a complete action input closure. Build scripts retain Cargo's normal input
tracking obligations. Restart the worker after changing host tools or system
libraries visible in its canonical runtime, since those are not all captured by
the toolchain identity. The separate gates for observation, recipes, closed
views, and verified action serving remain in force.
