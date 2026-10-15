# Compiler capture custody after a daemon restart

The live dependency lane pins compiler outputs while it captures immutable
bytes, waits for the wrapper's acknowledgment, and offers the result for
coordinator publication. Successful publication creates independent durable
roots; normal capture cleanup releases only its own temporary custody. A daemon
crash cannot run that cleanup, so the capture pins survive in the metadata store.

New captures already record a versioned attempt/lease/worker/object witness in
the same transaction as the pin. Recovery now consumes those witnesses on the
existing live handoff path, after normal `CapturePins::drop` cleanup. It holds
the same exclusively mounted CAS metadata lock throughout validation and release.

## What authorizes recovery

The caller must hold the currently active full coordinator authority. A capture
from a different authority in the same cluster can be retired only after its old
authority is durably released and its generation is durably tombstoned. The
witness must reproduce the exact capture owner, pin ID and root. Its coordinator,
action, generation, ordinal, attempt, worker boot/incarnation and execution lease
must match the normalized database bindings in both directions.

Lease expiry, elapsed wall-clock time and a missing acknowledgment are not
abandonment proofs. Current-authority captures, legacy pins without witnesses,
malformed or oversized witnesses, inconsistent bindings and other pin classes
retain protection. Recovery uses the existing authority-scoped release API. It
does not delete files, locations, witnesses or publications, and it cannot release
an independent publication or incident pin. Removing a capture root merely allows
the separate garbage collector to assess otherwise unprotected objects later.

## Bounded progress and its limits

Each nonempty capture cleanup examines at most 32 eligible rows. Progress is an
append-only `rabs-capture-recovery-cursor-v1` decision receipt keyed by the full
current authority. The checkpoint follows confirmed releases and uses the last
pin ID, not an offset into a shrinking result set. Interruption repeats safe
reads; it does not skip unconfirmed releases. A completed cursor stops additional
scans and checkpoint writes until a new authority starts. There is no new schema,
background executor or configuration switch.

This is demand-driven recovery, not an idle boot sweep: an idle daemon or a
workload producing no new captures does not advance it. Thirty-two returned rows
is not a hard wall-clock bound; SQL/index traversal and durable writes can still
block on the backend. Malformed progress records retain remaining roots. Repairs
to previously retained witnesses are not automatically rescanned under a completed
cursor; a new coordinator authority opens a fresh scan. Legacy records without
sufficient evidence are never guessed safe.

## Validation

```sh
cargo test --release -p rabsd --lib capture_pins --locked
python3 tests/test_rabs_capture_recovery.py -v
```

The Rust selection retains the existing capture and journal tests and adds ten
recovery regressions. They cover the actual cleanup hook after mounted-CAS reopen,
independent publication protection, 17 forged witness fields, full-width identities
on both metadata backends, stale authority, missing fences, pagination, interrupted
checkpoints and reopening the metadata connection between pages.

The 18 Python checks execute the literal production SQL against a schema slice and
an explicit cursor model: 24 binding-column mutations, 33 interruption cuts,
file-backed SQLite reopen, oversized projections and 50 seeded histories. They
passed during implementation, but do not execute Rust, serde, RABS identity hashing,
the scoped-release implementation or full migrations. Rust tooling was unavailable,
so the Rust tests, compilation, formatting, CI execution and live-fleet behavior
remain unverified by that implementation run. No build-speedup claim follows from
these tests.
