# Receiver-side verified worker delivery

`rabsd --worker-exec-loopback` is an explicit operator path that sends one
canonical request to a connecting worker and receives its complete diagnostics
and declared compiled files. It uses the production `coord::worker_delivery`
receiver, not the test coordinator from the worker acceptance tests.

This command is **plaintext and literal-loopback only**. It does not replace the
native authenticated ATP transport, enroll a worker, mount the daemon's CAS,
publish an action-cache entry, or make the Cargo wrapper skip compilation.
Loopback limits reachability; it does not authenticate another local process.
Use it only with trusted local users. `expected-worker` checks a claimed label,
not a certificate. The receipt explicitly records `transport_authenticated:false`
and `publication_authorized:false`. Failed TLS configurations must not be cleared
or downgraded to make a fleet connection use this operator lane.

## Run one delivery

Build the receiver and worker using the repository's pinned Rust toolchain:

```sh
cargo build -p rabsd -p rabs-wkr
```

Prepare a request using the `files-v1` declaration in
[rabs-worker-artifacts.md](rabs-worker-artifacts.md). Toolchain and workspace
backing paths refer to the worker host. The compiler's output paths must target
the declared `/__rabs/out/<unit>` mount. The receiver sends the request unchanged;
it does not derive Cargo arguments, alter source paths, or stage source inputs.

Start the receiver with an existing absolute parent and a NEW delivery directory:

```sh
rabsd --worker-exec-loopback 127.0.0.1:7091 local-worker \
  /absolute/request.json /absolute/results/delivery-42
```

In another terminal on the same trusted host, start the worker:

```sh
rabs-wkr --coordinator 127.0.0.1:7091 --worker-id local-worker --once
```

The receiver writes its listening address to stderr, accepts exactly one worker,
negotiates `ranges-v1`, `request-journal-v1`, and `files-v1` when artifacts are
requested, then sends exactly one execution request. Existing delivery paths,
including empty directories and symlinks, are refused without overwriting them.
There is no automatic reconnect, command retransmission, or local compile fallback.
The existing worker journal still owns admission. The requested ID must exceed
the worker/endpoint's durable high-water; an older or equal ID is refused before
execution. A newer ID can also be refused by the worker if prior work is uncertain.
Never delete/reset the journal, change endpoints, or increase an ID merely to
retry work whose outcome is unknown. Use outcome reconciliation first.

## What becomes available

A completed receiver directory contains:

```text
artifacts/<declared relative names>
diagnostics/stdout
diagnostics/stderr
delivery.json
```

The receiver independently verifies the exact requested names and unit, sorted
manifest, executable bits, lengths, manifest digest, request identity, offsets,
end-of-file indicators, per-chunk digests, and complete file digests. Arbitrary
binary bytes, including NUL and non-UTF-8 diagnostics, are preserved in files.
Executable artifacts receive mode 0700; other files receive 0600. The delivery
root is private. The receiver never writes these files into a Cargo target tree.

Each range is at most 65,536 raw bytes. Parsed wire frames and request files are
bounded to 1 MiB. A combined 1 GiB budget covers BOTH diagnostic streams AND all
artifacts; this receiver policy may be stricter than individual worker limits.
A peer advertising more is refused before ranges are requested. Network accept
and handshake each have a 60-second absolute budget. After dispatch, the exchange
has the effective execution budget (at most 30 minutes) plus five minutes for
transfer. Trickled bytes and telemetry cannot renew those deadlines. These are
network budgets, not a promise to interrupt an operating-system fsync that stalls.

All file hashes must match before any ACK is sent. The receiver syncs files,
directories, and parent ancestry, writes and syncs `delivery.pending`, renames it
to `delivery.json`, and syncs the directory again. Only then does it acknowledge
diagnostics and artifacts. This requires local storage with working file and
directory fsync semantics. Private receiver directories must not be concurrently
modified by another local process; this is not a race-proof shared-directory API.

## Failure and acknowledgment semantics

Compiler success and successful byte delivery are different facts. A failed or
interrupted compilation may produce a verified diagnostic delivery, but no
compiled-artifact bundle. The operator exits with the recorded nonzero compiler
or interruption status. Missing captures, malformed results, unresolved reported
descendants, corrupt bytes, and disk errors never become successful deliveries.

Before the local delivery frontier, failures produce `worker-delivery-error` on
stderr. Once any execution write is attempted, `execution_may_have_run` remains
true even when that write fails. No error response authorizes reexecution. Partial
staging is retained for inspection rather than silently deleted or reused. A
final directory-sync error can leave a receipt on disk whose durability is
uncertain; no release ACK is sent and the command does not report success.

After the frontier, a lost or mismatched ACK response does not invalidate the
verified local files. The command returns `worker-delivery` with
`acknowledgments_confirmed:false`, an acknowledgment error, and `reexecute:false`.
The verified receipt remains available. Losing the command's own stdout after
that point likewise is not permission to rerun the compiler. This is local byte
retention, not worker-side durable artifact resumption or cache publication.

## Qualification

Run the receiver unit, TCP transport, and real CLI tests:

```sh
cargo test -p rabsd worker_delivery
cargo test -p rabsd --bin rabsd worker_exec
cargo test -p rabsd --test worker_delivery_cli
```

The CLI test starts the actual receiver binary and a scripted TCP peer, delivering
binary artifacts and multi-range diagnostics through the production receiver.
It verifies that a complete local receipt exists before either ACK arrives.
It does not execute a real compiler or prove authenticated fleet behavior. The
separate worker `artifact_transfer_linux` test exercises real canonical compilation.
Tests added with this path still require execution on a supported Rust host;
their presence alone is not passing test or production-qualification evidence.
