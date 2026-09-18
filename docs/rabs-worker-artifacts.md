# Worker compiled-artifact transfer (`files-v1`)

The canonical worker can return an exact declared set of compiled files after
execution. It uses a fresh worker-owned output-unit mount, captures the files
into immutable bounded snapshots, and serves named ranges until acknowledgment.
This extends the existing worker session. It is **not** authenticated ATP, a
coordinator CAS publication, durable reconnect resumption, or automatic Cargo
cache serving. The wrapper's shadow keys are not artifact-reuse authority.

## Negotiate and declare

The worker advertises `"artifact_transfers":["files-v1"]` in `worker-hello`.
The coordinator selects `"artifact_transfer":"files-v1"` in `session-ok`.
This selection is independent of diagnostic `"output_transfer":"ranges-v1"`.
An artifact declaration without negotiation is refused **before execution**;
an unsupported selection refuses the handshake, never silently downgrades.
Negotiation refusal precedes durable admission as well as thread creation, so
it does not leave an unexecuted request recorded as uncertain work.

A canonical execution request may include:

```json
{
  "kind": "canonical-exec",
  "request_id": 42,
  "program": "/__rabs/toolchain/bin/rustc",
  "args": [
    "--crate-name", "example", "--crate-type=rlib",
    "/__rabs/workspace/lib.rs",
    "--emit=link=/__rabs/out/dep/libexample.rlib,metadata=/__rabs/out/dep/libexample.rmeta,dep-info=/__rabs/out/dep/example.d"
  ],
  "toolchain_backing": "/worker/toolchains/pinned",
  "workspace_backing": "/worker/workspaces/captured",
  "artifacts": {
    "unit": "dep",
    "files": ["libexample.rlib", "libexample.rmeta", "example.d"]
  }
}
```

The worker chooses fresh private physical backing for `/__rabs/out/dep` through
the existing canonical mount planner. `artifacts` accepts **only** `unit` and
`files`; the peer cannot choose its host backing. The driver must set compiler
output paths explicitly. The worker does not rewrite argv, derive Cargo output
names, or collect arbitrary files from the mutable workspace.

The declaration must contain 1–128 unique relative UTF-8 file names. Names may
not contain traversal or empty components, control characters, backslashes or
colons; they are limited to 1,024 bytes and 32 components. Unit names are limited
to 64 ASCII alphanumeric, dot, underscore or hyphen characters, excluding `.`
and `..`. A file cannot also be an ancestor directory of another declared file.

## Complete capture, never partial success

Only successful, uninterrupted execution with zero reported residual
process-group members can produce an artifact offer. Capture occurs after
process cleanup and diagnostic drain. The private output tree must contain
exactly the declared regular files and their parent directories. Missing or
extra files, undeclared directories, symlinks, special files, and Unix hard
links are refusals. A zero process exit with an incomplete artifact capture is
an execution-completion error, not a successful result. A failed or cancelled
compile never offers partially compiled artifacts; its captured diagnostics
can still be returned when diagnostic capture succeeds.

Capture snapshots at most 1 GiB **total artifact bytes** per execution, with
cancellation checks during copying. The walker also limits directory entries
to 4,096. These limits bound retained artifact snapshots, not all writes the
compiler could make before capture and not the existing diagnostic spill tier.
Filesystem safety assumes the private backing is quiescent after sandbox
cleanup; this is not a race-proof reader of arbitrary mutable host directories.

A successful `exec-result` adds `artifact_transfer`, `artifact_ack_required`, and
`artifact_manifest`. The manifest is sorted by relative file name and contains:

```json
{
  "unit": "dep",
  "files": [
    {"name": "example.d", "bytes": 123, "sha256": "<file digest>", "executable": false}
  ],
  "total_bytes": 123,
  "manifest_sha256": "<manifest digest>"
}
```

This example is schematic. Actual results contain the complete declared set.
File hashes are ordinary SHA-256 over the retained bytes. Executable bits are
recorded separately and bound into the manifest; a receiver must apply its own
safe installation policy rather than infer file modes from extensions.

## Retrieve and accept

Request a declared name, never a host path:

```json
{"kind":"artifact-read","request_id":42,"name":"libexample.rlib","offset":0,"max_bytes":65536}
```

`max_bytes` defaults to 65,536 and must be between 1 and 65,536. A response is an
`artifact-chunk` with the exact name/request identity, original and next offsets,
file length, whole-file SHA-256, executable bit, manifest digest, chunk SHA-256,
`data_hex` and `eof`. Hex preserves arbitrary binary data. Offset at EOF returns
an empty final chunk; offset beyond EOF is refused. Range retries are repeatable
and do not advance a shared protocol cursor. Replacing the original compiler
files cannot change snapshot reads.

The receiver must check identity, lengths, ranges, per-chunk hashes, the final
reconstructed file hashes, the exact expected output set and the manifest hash
before accepting the bundle. An acknowledgment carries:

```json
{"kind":"artifact-ack","request_id":42,"manifest_sha256":"<verified manifest digest>","total_bytes":123}
```

The ACK must match the retained execution, manifest and total length exactly.
A valid ACK releases that bundle and returns `artifact-acknowledged`. Retrying
the most recent accepted ACK returns `already_released:true` without releasing
a newer bundle. An ACK is the receiver's acceptance claim, not proof of byte
receipt, execution correctness, or coordinator publication authority.

There is at most one unacknowledged artifact bundle per session. New work cannot
evict it and is refused with `artifacts-unacknowledged` (or the existing
`output-unacknowledged` when diagnostics are also pending). Artifact and
diagnostic ACKs release their own owners independently. Negotiated `--once`
exits only after both owners have been acknowledged, in either order. Connection
loss releases scratch captures; a new session cannot retrieve them by guessing
old request IDs. Lost acknowledgments do not authorize rerunning an uncertain
execution. The worker's durable journal fingerprints the complete request,
including the artifact declaration, before launch and records bounded terminal
metadata before delivery. Request IDs must increase across restarts for that
worker/endpoint. `request-status` can reconcile the outcome but cannot restore
scratch bytes; `artifacts_available_in_this_session` only describes the current
connection. Reusing an admitted ID with a different artifact declaration is a
conflict, not a new execution. Never reset `RABS_WORKER_STATE_DIR` to retry work.
Durable artifact resumption remains a separate protocol responsibility.

## Manifest framing

`manifest_sha256` is SHA-256 of the following exact framing. `field(x)` is an
unsigned 64-bit big-endian byte length followed by `x`; integers below are not
length-prefixed unless marked `field`.

1. `field(UTF8("rabs.worker-artifact-manifest.v1"))`.
2. `field(UTF8(unit))`.
3. File count as unsigned 64-bit big-endian.
4. For every file in strictly increasing UTF-8 bytewise name order:
   `field(UTF8(name))`, executable as one byte (`0` or `1`), length as unsigned
   64-bit big-endian, then `field(ASCII(lowercase_hex_file_sha256))`.

This transport manifest is distinct from the canonical CAS artifact-bundle
root. No action-key or trust claim is implied by matching this digest.

## Tests and qualification

`artifacts` unit tests exercise validation, exact-set capture, file and mode
identity, cancellation, ranges and ACK ownership. Execution-owner tests prevent
missing captures or failed work from becoming successful artifact offers.
Production-driver tests retain artifacts and diagnostics through either ACK
order. `artifact_transfer_linux` starts the actual worker over TCP, compiles
rlib/rmeta/dep-info in the canonical sandbox, downloads and verifies all files,
and links a consumer against the downloaded rlib. Its compilation test explicitly
skips without canonical isolation; its negotiation-refusal test does not require
isolation. These tests need to be run with the repository's Rust toolchain; their
presence does not establish a successful run or fleet qualification.
