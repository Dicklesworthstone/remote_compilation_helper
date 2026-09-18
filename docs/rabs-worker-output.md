# Worker diagnostic output retrieval

The `rabs-wkr` prototype session supports complete, byte-exact stdout/stderr
retrieval **after execution and process/drain cleanup**. This is not live pipe
streaming, artifact publication, authenticated ATP, or durable reconnect resume.
The existing prototype transport must remain inside a trusted deployment.

## Negotiate before executing

`worker-hello` advertises `"output_transfers":["ranges-v1"]`. The coordinator
selects it in its acknowledgment:

```json
{"kind":"session-ok","output_transfer":"ranges-v1"}
```

An absent selection retains digest-only behavior. Unknown or malformed selections
refuse the handshake rather than silently downgrading. An executing worker in
`ranges-v1` mode snapshots the resident head **and** the spilled tail of each
stream into private anonymous files. It computes result digests from those same
bytes; capture failure produces an execution-completion error, not a successful
result with truncated output. Such an error may follow actual execution and
must not trigger an automatic rerun of an uncertain command.

## Retrieve and verify

The normal `exec-result` adds `output_transfer`, `stdout_bytes`, `stderr_bytes`,
and `output_ack_required`. Lengths refer to complete streams, not spill sizes.
A non-executed result can have no output capture and require no acknowledgment.

Request a range using only the session's execution identity and a stream name:

```json
{"kind":"output-read","request_id":42,"stream":"stdout","offset":0,"max_bytes":65536}
```

The response is an `output-chunk` with the same request ID, stream and offset,
plus `next_offset`, `total_bytes`, `eof`, `data_hex`, `sha256` (the full stream),
and `chunk_sha256` (this raw chunk). Hex preserves NUL and non-UTF-8 diagnostics.
Verify chunk hashes, placement and lengths; then independently hash the entire
reconstructed stream and compare with `exec-result`. Retry or out-of-order reads
return the same bytes. No worker filesystem path is accepted as a read target.

`max_bytes` defaults to 65,536 and must be in 1..=65,536. Offset at EOF returns an
empty final chunk; offset beyond EOF is an error. Each retained stream is capped
at 1 GiB; oversize capture refuses rather than truncating. This bounds additional
snapshot storage, **not** the preexisting drain's total spill volume. A session
holds at most one completed output pair and admits no new execution while its
output is unacknowledged (`output-unacknowledged`). Control pings still work.

## Acknowledge ownership release

After verifying both streams, echo their complete identity:

```json
{"kind":"output-ack","request_id":42,"stdout_bytes":18,"stderr_bytes":0,"stdout_sha256":"<verified full stdout SHA-256>","stderr_sha256":"<verified full stderr SHA-256>"}
```

The example lengths are illustrative: use the actual reconstructed lengths.
Only an exact match releases the held snapshots. The worker answers
`output-acknowledged`. Retrying the latest successful ACK is idempotent and cannot
release a newer execution's output. An ACK is the receiver's statement that it
accepted the bytes, not cryptographic proof that it read them or authority to
publish a build result.

In negotiated mode, `--once` waits for this ACK before exiting. Without negotiated
capture, it retains its existing exit-after-result behavior. Disconnect or session
failure releases the anonymous snapshots; a new session cannot retrieve old
request IDs. There is no retention timeout or cross-session resume in this lane.
Cancelled executions can still return their complete captured pre-kill diagnostics;
`stop_reason` remains authoritative and an interrupted zero exit is not success.

## Tests

Unit tests exercise range replay, binary/empty streams, bounds, real drain head +
spill reconstruction, spill replacement, capture/result mismatch, cancellation,
ACK binding and session isolation. `rabs-wkr/tests/output_transfer_linux.rs` drives
the actual worker binary over TCP through canonical `rustc --print sysroot`, reads
and hashes both streams, retries ranges, rejects a wrong ACK and verifies `--once`
exits only after the correct ACK. It explicitly skips when canonical isolation is
unavailable. These tests do not establish ATP authentication or fleet qualification.
