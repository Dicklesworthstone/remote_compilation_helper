# Bounded backpressure for parallel Cargo cache lookups

The live edge has a bounded decision lane. Previously, filling its slots made
additional compiler requests immediately pass through to local compilation,
even when a briefly delayed lookup could reuse a cached result or join an
existing action. Decision-capacity backpressure keeps those requests eligible
for the normal lookup path without adding a daemon work queue.

The daemon sends this response only when the existing lane refused admission
with `Saturated`, before its decision closure ran, and the request included
Boolean `wait_for_inflight: true`:

```json
{"kind":"rustc-decision","decision":"pass-through","reason":"edge-capacity","retry":"decision-capacity-v1","compiler_skip_authorized":false,"materialization_started":false}
```

This is not a cache hit, action identity, reserved attempt, or output writer.
No decision permit is retained while the wrapper waits. The existing connection
limit and per-connection request quota remain in force. A `capacity-wait` event
records the refusal without pretending that input facts were observed.

New wrappers recognize only that versioned hint with explicit non-owning flags
and no action key, attempt, or environment grant. They sleep under their existing
backoff and resubmit the original request bytes. Old wrappers understand the
ordinary `pass-through` decision and simply compile normally; old daemons do not
produce the hint. A bare `edge-capacity` reason is not retryable, because older
daemons also used it for errors from work that had already started.

Capacity, cold input preparation, and keyed singleflight waiting share one
absolute deadline and retry count. A first capacity refusal selects the existing
cold-preparation budget once. Later capacity gaps cannot restart a deadline or
erase an already bound action key: the next hit or admitted execution must still
match it. The existing wait-budget environment controls, including zero to
suppress the relevant waiting phase, retain their meaning. Connection rollover
continues to use the existing bounded negotiation path and does not reset the
logical consultation's limits.

No retry hint is emitted for an admitted panic, thread-start failure, compiler
completion, or accepted-hit installation. Once the wrapper has accepted a hit,
a capacity-style reply is still uncertain delivery and fails closed; it cannot
restart lookup or authorize local compilation over a possibly changing tree.
Original-caller cancellation also stops waiting without authorizing fallback.
All key construction, input validation, sampling, quarantine, publication,
installation, and capture-acknowledgment gates remain unchanged.

This addresses decision-slot pressure on an already admitted live connection.
It does not guarantee fairness, avoid fallback after a deadline, increase the
connection limit, recover a failed completion, reserve installation capacity,
or dispatch Cargo actions to canonical remote workers. No running daemon or
production configuration is changed by installing the code. There is no measured
Cargo or fleet speedup from this increment.

## Qualification

Nine wrapper tests use the production decision loop with socket-pair peers to
exercise transitions, shared quotas/deadlines, malformed hints, changed keys,
legacy behavior, cancellation and post-acceptance uncertainty. Four daemon tests
exercise the actual capacity lane, its admitted-panic path, strict negotiation,
and the real connection handler with all decision permits held. The connection
test checks status responsiveness, then releases capacity and requires the same
request to take its normal observation path exactly once. Its compiler request
is a probe fixture, not a real compiled/cache-served action.

The existing wrapper unit and `edge::server` CI selections include these tests:

```sh
rch exec -- cargo test -p rabs-wrap --bin rabs-wrap --locked
rch exec -- cargo test -p rabsd --lib edge::server --locked
```

The authoring environment has no Cargo, rustc, or rustfmt. The Rust tests and
compilation have not been run here; source-contract checks are supporting checks,
not substitutes for executing the runtime tests or a real parallel Cargo build.

## Completion capacity survives the capture handoff

Compiler completion now acquires its capacity slot once, before capture, and
retains that non-clone reservation until publication or cleanup finishes.
Previously, capture released the slot before requesting the wrapper's
acknowledgment. A fresh burst could consume all slots in that gap and prevent
the already-captured, acknowledged candidate from reaching publication.

The capture worker is joined before the receipt is sent. Acknowledgment retains
only the capacity reservation and immutable candidate, not a worker thread or CAS
mutex. Its existing read/write deadlines are unchanged. Publication consumes the
same reservation instead of requesting another slot. No second compiler run,
retry queue, increased thread limit or new protocol permission is introduced.

This changes what the completion limit bounds: it now includes handoffs waiting
for acknowledgment, as well as active capture/publication workers. A slow peer
can hold a slot until its bounded exchange ends, so initial overload can still
refuse a new completion. The benefit is that newly arriving work cannot displace
an already-admitted captured result at the publication boundary. This is not a
promise that every captured result commits: missing or mismatched consent, OS
thread-start failures, I/O errors and all existing publication gates still apply.

Six ownership tests cover reservations, joined workers, cancellation, panics and
payload cleanup order. Four Linux tests drive the actual completion function,
coordinator/CAS and Unix-socket acknowledgment while all other slots are held.
They require successful publication for matching consent, non-publication and
settlement for wrong consent/disconnection, and no receipt or extra CAS locations
on initial saturation. Toolchain probes and compiler-output bytes in these tests
are explicit fixtures, not real compiler executions. The existing `edge::server`
CI test selection includes them. These added Rust tests have not run in the
authoring environment, which lacks Cargo and rustc.
