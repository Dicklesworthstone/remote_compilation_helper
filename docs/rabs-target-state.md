# Worker-local Cargo target state

The canonical worker can retain successful Cargo target trees and seed later
builds with independently owned copies. Cargo executes on every request and
decides which compilation steps are fresh. This accelerates repeated commands
with identical captured inputs without serving a stored compiler result.

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

A match binds the complete captured source manifest, dependency projection,
toolchain, command and arguments, final command environment, working directory,
canonical namespace policy, output contract, and effective worker job grant.
The pool also separates worker identities, coordinator endpoints, and
authenticated coordinator certificate keys.

Changing a source file, build script, captured dependency, environment value,
feature flag, toolchain, output contract, or effective job grant starts with a
fresh target. This first implementation does not reuse incremental state across
source edits. An identical invocation can reuse its prior target while Cargo
still runs the requested command, including test executables for `cargo test`.

The worker gives each eligible execution a fresh HOME and a captured or empty
Cargo home. Its jobserver has a stable canonical FIFO name but a new private
FIFO and independent token budget for each execution. The final environment,
including that actual grant, participates in the match.

## How ownership and freshness work

The worker first validates the original sealed source and its namespace. It
then creates and verifies a separate runtime workspace. Only this private copy
may receive the timestamps from a prior identical workspace; the original
captured source and its seal remain untouched.

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

- `worker-target-state` reports `cold`, `restored`, `cold-after-refusal`, or
  `cold-pool-busy`, together with the request ID and matching-key digest.
- `worker-target-state-refused` explains an optional capture or restore failure.
- `worker-target-state-published` reports the accepted seed size, retained byte
  total, and entry count.

`restored` means a verified private target was provided to Cargo. Cargo's own
artifact JSON `fresh` fields show whether compilation was skipped. The build's
diagnostics, exit status, artifact verification, and delivery acknowledgments
still come from the current execution.

This is ordinary Cargo hot state, not RABS action-cache publication or proof of
a complete action input closure. Build scripts retain Cargo's normal input
tracking obligations. Restart the worker after changing host tools or system
libraries visible in its canonical runtime, since those are not all captured by
the toolchain identity. The separate gates for observation, recipes, closed
views, and verified action serving remain in force.
