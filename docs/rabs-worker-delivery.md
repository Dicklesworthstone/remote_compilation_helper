# Receiver-side verified worker delivery

`rabsd --worker-exec-tls` is the authenticated operator path that sends one
canonical request to a connecting worker and receives its complete diagnostics
and declared compiled files. It uses the production `coord::worker_delivery`
receiver through native Asupersync mutual TLS and ATP Control framing. The
separate `--worker-exec-loopback` fixture command uses the same verifier.

The loopback command is **plaintext and literal-loopback only**. It does not replace the
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
[rabs-worker-artifacts.md](rabs-worker-artifacts.md). For worker-local inputs,
toolchain and workspace backing paths refer to the worker host. The compiler's
output paths must target the declared `/__rabs/out/<unit>` mount. The receiver
sends the request unchanged; it does not derive Cargo arguments or alter source
paths. Explicit source manifests instead use `--source-root`; `--worker-prepare`
can retain selected inputs before execution. Neither capture nor upload is part
of result recovery or acknowledgment reconciliation.

### Replay registry inputs into a private Cargo home

Source-backed requests may include an explicit registry-cache projection:

```json
"cargo_home": {
  "version": "registry-cargo-home-v1",
  "prefix": "cache"
}
```

The prefix is a relative directory INSIDE the transferred source manifest, not
an absolute host path or permission to crawl a Cargo installation. All selected
files under that prefix must be beneath `registry/cache`, `registry/index` or
`registry/src`. Their exact paths, lengths, executable bits and hashes are part
of the same source manifest as the project. The selection is retained verbatim
in the original request and its durable fingerprint.

For preparation, select the required registry files using `source_files` or a
`source_roots` entry such as `cache: {path, files}` alongside the application
root. Root names become directory prefixes in the saved bundle. Select only the
approved files required by the target Cargo invocation; this does not discover
the dependency closure or import an entire `~/.cargo` directory. A local-registry
fixture, for example, can carry these inputs:

```text
app/Cargo.toml
app/Cargo.lock
app/.cargo/config.toml
app/src/main.rs
cache/registry/index/local/registry_dep-1.0.0.crate
cache/registry/index/local/index/re/gi/registry_dep
```

The application's explicitly selected `.cargo/config.toml` must name the local
registry beneath the canonical Cargo home, not the original host checkout.
Ordinary registry cache/index/source projections instead retain the layout and
configuration required by their pinned Cargo version. Cargo-home internals are
not a stable interchange format: qualify the selected inputs against the target
toolchain. The preparer does not rewrite manifests, source replacement settings,
lockfiles, arguments, environment or working directory. Use the original
command's `--frozen` requirement when both locked resolution and offline operation
are required; the sandbox's network isolation is unchanged in either case.

Cargo-home configuration and credentials, installed binaries, global metadata,
lock files and Git dependency state cannot be selected through this replay
field. Configuration needed by the build must be explicitly supplied as an
ordinary workspace input instead. This directory policy is not a secret scanner:
the caller remains responsible for approving the content of every selected file.

After transport/session admission, the worker must echo the exact version and
prefix in its initial `source-ready` before any source or registry bytes are sent.
The same echo is required at the final seal. A worker that ignores the extension,
an unsolicited selection, a changed prefix or a missing final confirmation
refuses without executing. A warm source-byte cache does not waive these checks.

The worker verifies the sealed projection, then copies it into a fresh private
Cargo home owned by that one execution. Files are independent writable copies
so Cargo can acquire locks, unpack archives and update its own cache metadata;
the transferred workspace remains read-only. No host Cargo-home configuration or
credentials are inherited, and runtime writes cannot alter the original source
or shared source-byte cache. Preparation shares the original bounded upload
phase and must finish before execution ownership is handed off. Source protocol
limits still apply: at most 4,096 files and 512 MiB across the complete projection.
The independent runtime copy requires additional space for the selected registry
bytes and for whatever Cargo subsequently unpacks.

Result resume and acceptance reconciliation carry the original request identity
but never reupload registry inputs or recreate an execution Cargo home. This is
explicit input delivery, not proof of package provenance, complete dependency
resolution, immutable action inputs, or permission to skip compilation.

### Build a prepared bundle and install its outputs

`--worker-build-tls` joins source upload, authenticated execution, durable byte
delivery, and complete output installation in one operator command. First prepare
a bundle containing `request.json` and `source/` with `--worker-prepare`. The
request must contain a source manifest and an artifact declaration; an explicit
`tree-files-v1` declaration receives the full output tree, including Cargo's
intermediate files. The compiler command still supplies its exact arguments,
canonical working directory, environment, and worker toolchain backing.

With the TLS environment described below, run:

```sh
rabsd --worker-build-tls 0.0.0.0:7091 fleet-worker <worker-spki-sha256> \
  /absolute/bundles/build-42 /absolute/deliveries/build-42 /absolute/outputs/build-42
```

Start `rabs-wkr --once` against that listener as shown in the authenticated
delivery instructions below. The three local directories must have existing
parents, be disjoint, and contain no symlink ancestors. For a new execution the
delivery and output directories must be absent. The bundle supplies the only
source upload; the original checkout is no longer needed. The command retains
the complete verified delivery before privately staging and atomically installing
every successful artifact. Installed files are independent copies, so modifying
them cannot change the retained delivery. Failed or interrupted compilation
retains diagnostics and its original exit status without installing partial outputs.

Repeating this exact command verifies the existing delivery and installed tree
offline. It can also finish installation after a previous installation failure.
No worker connection, TLS credentials, or source directory is needed for a
complete local delivery; keep the bundle's `request.json` to identify that
delivery. An existing differing output tree is refused without replacement.
An existing incomplete or corrupt delivery is also refused and never triggers
another execution.

If execution completed remotely but the delivery was lost, explicitly retrieve
the original result into a **new** delivery directory:

```sh
rabsd --worker-build-tls --resume 0.0.0.0:7091 fleet-worker <worker-spki-sha256> \
  /absolute/bundles/build-42 /absolute/deliveries/build-42-resumed /absolute/outputs/build-42
```

Resume sends only the retained-result request and byte reads; it neither uploads
source nor dispatches a compiler. An unavailable remote result remains an error.
The worker must still retain the requested result. A complete local delivery can
be installed even if a release acknowledgment was lost; acknowledgment
reconciliation remains the separate `--worker-exec-tls --acknowledge` operation
using the same bundle request and delivery directory.

Success prints one `worker-build` JSON object containing `delivery` and
`installed_outputs`; the latter reports whether a verified existing tree was
reused. A nonzero compiler exit produces a retained `delivery` and null
`installed_outputs`. Installation or protocol failure prints `worker-build-error`
with `execution_may_have_run` and `reexecute:false`. These commands do not publish
action-cache entries or install Cargo freshness authority. They provide explicit
build outputs for inspection and use in a new directory.

The equivalent trusted local fixture is `--worker-build-loopback`, with the same
arguments except for the omitted key pin. It accepts only literal loopback
addresses and retains the plaintext provenance described above.

### Authenticated delivery

Provision an explicit CA plus server and worker certificates with the appropriate
serverAuth/clientAuth uses. The worker verifies the server's configured DNS name;
both endpoints require the native `rabs-worker-atp/1` ALPN. Use existing trusted
credential provisioning; do not accept a certificate or key pin learned from an
untrusted worker connection.

Obtain the expected worker public-key pin from its independently trusted
certificate. This hashes DER SubjectPublicKeyInfo, not the whole certificate:

```sh
openssl x509 -in /credentials/worker.pem -pubkey -noout |
  openssl pkey -pubin -outform DER |
  openssl dgst -sha256
```

Use the resulting 64 lowercase hex digits as `<worker-spki-sha256>`. On the
receiver, all three TLS paths are required, nonempty and absolute:

```sh
RABS_COORD_TLS_CA=/credentials/ca.pem \
RABS_COORD_TLS_CERT=/credentials/coordinator.pem \
RABS_COORD_TLS_KEY=/credentials/coordinator.key \
rabsd --worker-exec-tls 0.0.0.0:7091 fleet-worker <worker-spki-sha256> \
  /absolute/request.json /absolute/results/delivery-42
```

On the worker host:

```sh
RABS_WORKER_TLS_CA=/credentials/ca.pem \
RABS_WORKER_TLS_CERT=/credentials/worker.pem \
RABS_WORKER_TLS_KEY=/credentials/worker.key \
RABS_WORKER_TLS_SERVER_NAME=coordinator.example.internal \
rabs-wkr --coordinator coordinator.example.internal:7091 --worker-id fleet-worker --once
```

The listener address is a literal IP:port and may be non-loopback only in TLS
mode. Bind it to the intended interface and apply the deployment's network
access policy. TLS mode never tries plaintext, even on loopback or after a
configuration error. The command accepts one connection; an invalid peer ends
this invocation without dispatch rather than starting an unbounded accept loop.

Admission checks the configured SPKI against the public key TLS authenticated,
then checks the hello's peer claim and versions through `CoordinatorSession`.
The worker answers a fresh session/operation/token challenge, then passes durable
boot-generation/incarnation admission before receiving the grant or uploading
source. The existing S5 `canonical-probes:<peer-id>` label is retained for
handshake compatibility, but the delivery adapter additionally permits only the
complete operator-selected execution or recovery request, exactly once. Unknown
operations, publication attempts and a changed request cannot pass that adapter.
The grant explicitly disables publication and arbitrary session resume. Sealed
result retrieval uses the separately negotiated `durable-result-v1` protocol on
a fresh authenticated connection, not continuation of the old session.

An authenticated receipt records `transport_authenticated:true`, the
`worker_spki_sha256`, `authenticated_session_id` and `identity_generation` before
release ACKs. These fields come from the adapter, not worker-supplied JSON.
Authentication establishes the sender, not correctness or determinism of its
execution; all byte and manifest checks still apply. Identity generation 1 here
describes the pinned key's worker role; key rotation is not implemented.

The operator persists each stable worker name's authenticated SPKI binding and
boot-generation/incarnation history beneath `$RABS_STATE_DIR/worker-admission`
(default `~/.cache/rch/rabs-state/worker-admission`). It reuses the coordinator's
exclusive store lock and durable S022 fence. Concurrent receivers for the same
worker name refuse; separate workers remain independent. A first failed TLS or
challenge exchange does not establish a key binding. Once authenticated, changing
the pin under the same name refuses before listening rather than creating fresh
boot history. Treat worker names and state roots as durable configuration; renaming
a worker or discarding its state is not an outcome-recovery operation.

Lower boot generations refuse across receiver restarts. Conflicting active
incarnations at the same generation persist a clone-ambiguity refusal; neither
contender can clear it by incrementing its boot number or supplying a JSON
re-enrollment claim. Clean completion releases the exact session while retaining
high-water history. A killed receiver leaves its session conservatively open.
This command does not provide a key-rotation/re-enrollment service, cross-host
clone adjudication, scheduling, or authoritative action-cache admission.

TLS mode has separate absolute network budgets: 60 seconds for accepting the
connection, the native transport's five-second TLS handshake limit, 10 seconds
for application admission, at most 30 minutes plus 60 seconds for execution and
cleanup, five minutes for verified transfer, and 10 seconds for both ACK replies.
Bytes, telemetry and repeated ranges do not reset a phase. Timeout poisons the
connection; partial writes are never retried. The native ATP payload limit is
1 MiB minus 64 bytes; larger requests are rejected before listening. Filesystem
operations, including sync, are not guaranteed interruptible by these budgets.

### Trusted local fixture

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
requested, then sends exactly one execution request. Existing delivery paths
are reverified offline when complete and matching. Incomplete directories,
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
artifacts/<accepted relative names>
diagnostics/stdout
diagnostics/stderr
delivery.json
```

The receiver independently verifies the requested names and unit, sorted
manifest, executable bits, lengths, manifest digest, request identity, offsets,
end-of-file indicators, per-chunk digests, and complete file digests. Exact-file
requests require equality with the declaration. Explicit `tree-files-v1`
requests require every named output and verify the complete bounded manifest,
including intermediate files. Arbitrary binary bytes, including NUL and non-UTF-8
diagnostics, are preserved in files. Executable artifacts receive mode 0700;
other files receive 0600. The delivery root is private. The receiver never writes
these files into a Cargo target tree or claims Cargo freshness from their presence.

Each range is at most 65,536 raw bytes. Loopback wire frames and request files are
bounded to 1 MiB. A combined 1 GiB budget covers BOTH diagnostic streams AND all
artifacts; this receiver policy may be stricter than individual worker limits.
A peer advertising more is refused before ranges are requested. Network accept
and handshake in loopback mode each have a 60-second absolute budget. After dispatch, the exchange
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
compiled-artifact bundle. The execution/delivery operator exits with the recorded
nonzero compiler or interruption status. Missing captures, malformed results,
unresolved reported descendants, corrupt bytes, and disk errors never become
successful deliveries.

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
that point likewise is not permission to rerun the compiler. Normal repetition
reverifies that local delivery offline and does not contact the worker. It cannot
confirm remote acceptance or release retained-result capacity by itself.

### Retrieve a missing local result without re-executing

`--resume` takes the ORIGINAL request and a new absolute delivery directory. It
sends only `result-resume`, verifies the retained bytes using the ordinary delivery
receiver, and acknowledges only after complete local durability. A complete
matching destination still recovers offline; an incomplete existing destination
is never repaired or overwritten. No source checkout or `--source-root` is needed.
Resume requires the worker's matching durable admission and retained result; an
unavailable result is an error, never permission to run the compiler again.

### Reconcile lost acknowledgments without downloading again

Use `--acknowledge` only when the complete local delivery already exists and its
receipt contains `result_retention:durable-result-v1` plus the retained-result
seal. This addresses the case where bytes are safely local but an acceptance ACK
was lost, so the worker still refuses new work while retaining the old result.
For the authenticated lane, reuse the established coordinator credentials and
original worker endpoint, identity and state directory:

```sh
RABS_COORD_TLS_CA=/credentials/ca.pem \
RABS_COORD_TLS_CERT=/credentials/coordinator.pem \
RABS_COORD_TLS_KEY=/credentials/coordinator.key \
rabsd --worker-exec-tls --acknowledge \
  0.0.0.0:7091 fleet-worker <worker-spki-sha256> \
  /absolute/request.json /absolute/results/delivery-42
```

The worker connects as in authenticated delivery above. The trusted-local fixture
also supports `rabsd --worker-exec-loopback --acknowledge` with its usual four
positionals. The flag may precede or follow the positionals, but cannot be mixed
with `--resume` or `--source-root`. A plaintext receipt cannot be acknowledged as
an authenticated one, and TLS failure never selects the loopback lane.

Before listening, acknowledgment recovery verifies the existing receipt, exact
request and historical transport policy, every diagnostic/artifact byte and mode,
and the complete file tree. It then authenticates the worker, resumes only the
original request, and requires the same retained-result seal, outcome, lengths,
diagnostic hashes and complete artifact manifest. It rechecks local bytes after
the network round trip, before sending either release ACK. It sends no source
bytes, range reads or compiler command and never replaces local files or rewrites
the historical receipt.

When both ACKs were already journaled but the final reply was lost, the worker may
refuse result resume because its copies have been released. The receiver then
queries `request-status` for the same admission. Only a matching terminal outcome
and exact seal marked `retained_result_released:true` confirm acceptance. A missing
spool, larger high-water mark, generic refusal or foreign result cannot confirm
it. If the worker has moved on and no longer retains that admission's metadata,
the operation refuses rather than guessing. The valid local delivery remains
usable independently of whether remote acceptance can still be confirmed.

Successful `--acknowledge` exits **zero**, reports
`acknowledgments_confirmed:true`, and keeps the original compiler exit code in the
receipt even when compilation failed. Reconciliation failure exits nonzero with
`execution_may_have_run:true` and `reexecute:false`; the local result is retained.
A new explicit invocation can retry reconciliation on a fresh connection. No
failure retries the same connection or authorizes execution. Prevent concurrent
same-user modification of the local delivery throughout this operation.

## Qualification

Run the receiver unit, TCP transport, and real CLI tests:

```sh
cargo test -p rabsd worker_delivery
cargo test -p rabsd delivery_ack
cargo test -p rabsd --bin rabsd worker_exec
cargo test -p rabsd --test worker_delivery_cli
cargo test -p rabsd --test worker_exec_tls
```

The CLI test starts the actual receiver binary and a scripted TCP peer, delivering
binary artifacts and multi-range diagnostics through the production receiver.
It verifies that a complete local receipt exists before either ACK arrives.
It does not execute a real compiler or prove authenticated fleet behavior. The
separate worker `artifact_transfer_linux` test exercises real canonical compilation.
The TLS tests generate temporary credentials with OpenSSL and connect a scripted
native mutual-TLS/ATP peer to the actual `rabsd --worker-exec-tls` process. They
exercise complete multi-range binary delivery, configured-key refusal despite a
valid CA, authentication before dispatch, corrupted data from an authenticated
peer, no plaintext downgrade, and pre-network configuration/path refusals.
Acknowledgment cases first obtain a delivery through that real receiver, then
exercise fresh TLS reconciliation, repeated lost replies, exact already-released
confirmation, changed-result refusal and local-evidence preservation with no
range reads or local inode replacement. OpenSSL is required; these security tests
do not silently skip its absence. The scripted peer does not execute a compiler
and is not a real fleet qualification. Tests added with this path still require
execution on a supported Rust host; their presence alone is not passing test or
production-qualification evidence.

Registry replay adds shared sandbox, worker and sender regression coverage:

```sh
cargo test -p rabs-sandbox cargo_home
cargo test -p rabs-wkr cargo_home
cargo test -p rabsd cargo_home
```

The controlled-host registry acceptance case is selected explicitly:

```sh
cargo test -p rabs-wkr --test cargo_tree_worker_linux registry_tests -- --ignored
```

It requires canonical-capable Linux, a complete Rust toolchain and linker, tar
and gzip. It generates a local registry package, uploads it to the actual worker,
compiles offline inside the canonical namespace, restarts after completion and
retrieves the original result without reupload or reexecution. It downloads and
checks every output before running the received executable. Its negative case
uploads transport-valid bytes with a wrong Cargo package checksum and requires
Cargo to reject them with no artifact offer. The client is a bounded loopback
fixture, not an authenticated fleet coordinator. Missing prerequisites fail when
this ignored test is explicitly selected; source presence is not a passing gate.
