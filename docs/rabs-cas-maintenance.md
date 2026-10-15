# Recurring CAS maintenance and physical raw-blob reclamation

`rabsd`'s janitor now runs recurring usage scans on one joined maintenance
thread. The default remains **non-deleting**. A quota breach is advisory; it
never enables physical deletion, releases a pin, or evicts a published result.
The previous startup GC audit remains available in this default mode.

## Explicitly enable physical reclamation

Set these in the daemon's environment before starting a new process:

```sh
RABS_GC_RECLAIM=1 \
RABS_GC_INTERVAL_SECS=60 \
RABS_GC_GRACE_SECS=300 \
RABS_GC_MAX_LOCATIONS=64 \
rabsd
```

This is an operator opt-in to deleting eligible cache **files**, not just
retiring their metadata. Qualify the Rust tests and a controlled deployment
before enabling it on a valuable store. Installing the code does not enable
reclamation or restart any running daemon.

`RABS_GC_RECLAIM` accepts `1/true/on` and `0/false/off` (default off).
The interval and grace each accept 1–86,400 seconds (defaults 60 and 300).
The location limit accepts 1–1,024 (default 64). Invalid, zero, overflowed,
or non-UTF-8 settings refuse maintenance startup and emit
`janitor-gc-config-refused`; they do not silently disable a requested safeguard.
`RABS_QUOTA_BYTES` keeps its existing advisory meaning.

The worker waits one interval **after finishing** a pass. Slow I/O cannot queue
catch-up sweeps. Shutdown wakes that wait, stops further passes and joins an
already-started pass before releasing the store. Kernel filesystem calls and
metadata transactions are not claimed interruptible; joining slow I/O can
therefore delay shutdown. Steady-state scans and sweeps do not run on the
Asupersync control reactor, and no nested runtime is started.

## What can be reclaimed

The first physical collector supports only recorded, unpinned `raw-v1` blobs
at the exact digest-derived path under this mount's `blobs/objects` namespace.
It uses the existing GC planner and pin-reachability closure. Every unreleased
pin remains a root, including an expired pin that has not passed the separate
explicit reconciliation/release flow.

A file needs two matching inode/version observations separated by positive
monotonic grace. Replacement restarts grace. Restart forgets the in-memory
observations and starts grace again; old tombstones or a wall-clock change
cannot shorten it. Newly pinned or reachable candidates are rescued.

Collection defers when the metadata lock is busy, coordinator authority is
absent, startup reconciliation refused serving, or any action generation is
still open. Any recorded quarantine, quarantined replica, or divergence
incident also defers physical collection. These deliberately broad holds
favor evidence retention over disk recovery in the initial implementation.

The collector requires a private CAS root and the original held mount-lock
inode, owned real parent directories, and a regular single-link file. It
refuses symlinked parents, hardlinked blobs, external replica paths, unsupported
encodings, and noncanonical digest/path spellings. It never walks or deletes
staging or quarantine trees, unregistered files, publication rows, object/edge
records, pins, or packed representations.

The exclusive mount and CAS mutex serialize this operation with participating
writers, new action admissions, materialization and pin updates. This is **not**
a security boundary against another malicious process with the same UID.

## Crash behavior and evidence

An exact-location unlink intent is durable before any file is removed. The
containing shard directory is synced before its location metadata is retired.
An interrupted unlink retains recovery state. A later pass may roll forward
an absent location only when the matching intent exists and the current
protection checks still permit it. Absence without an intent belongs to startup
reconciliation, not to an invented successful collection.

`janitor-physical-gc` reports actual `unlinked_files`, their logical
`unlinked_bytes`, `recovered_locations`, observations and retained candidates.
Recovery of already-missing files is not counted as another unlink. Logical
bytes are not freed-block measurements: an open descriptor can retain blocks.
A late failure explicitly reports the already-unlinked prefix and leaves
remaining recovery state rather than claiming nothing happened.

Usage scans do not follow stable symlinks or count hardlinked files twice. They
are observational samples, not coherent snapshots. A failed, cancelled, or
oversized traversal reports `janitor-store-usage-unavailable`; partial data is
not published as zero usage. The traversal is capped at one million entries.

## Limits and qualification

The per-pass limit bounds physical operations and retained grace observations,
**not** the GC planner's full-index metadata snapshot and sorting. Large-store
planning can still hold the metadata mutex long enough to delay a compiler
consultation; this needs real-store latency qualification. Continuous active
builds or retained incident evidence can defer collection indefinitely.

This does not implement LRU eviction of pinned published actions, automatic pin
expiry/release, a hard quota guarantee, packed-object collection, or cleanup of
unregistered filesystem orphans. It does not add remote Cargo dispatch.

```sh
rch exec -- cargo test -p rabsd --lib janitor --locked
rch exec -- cargo test -p rabsd --test janitor_gc_live --test janitor_reclaim_live --locked
```

The unit tests use real CAS/filesystem APIs with synthetic objects and clock
injection. The integration tests use the actual prebuilt `rabsd` binary, verify
that files disappear only in opt-in mode, retain a pinned blob, require repeated
passes, and reopen the mount after child shutdown. No nested Cargo build runs.
Adding these tests is not evidence that they have passed: Rust compilation,
runtime qualification and fleet behavior remain unverified in the authoring
environment, which has no Rust toolchain. Native SQLite/filesystem model checks
are separate supporting evidence, not substitutes for the Rust tests.
