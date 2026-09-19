# Durable CAS archives of worker deliveries

`rabs-delivery-cas` closes the storage gap after worker delivery: verified
compiler artifacts and diagnostic bytes can be retained in the existing RABS
content-addressed store and restored without contacting a worker or rerunning a
compiler. This is explicit archival of one historical execution, **not** action
cache serving or proof that another execution may be skipped.

## Archive and restore

Build the operator binary with `cargo build -p rabsd --bin rabs-delivery-cas`.
A complete `delivery.json` and the original request JSON are prerequisites.

```sh
rabs-delivery-cas archive /private/rabs/cas /private/request.json \
  worker-a /private/delivery-42 loopback

# Set ARCHIVE_ROOT to the exact root field from the archive JSON response.
rabs-delivery-cas restore /private/rabs/cas "$ARCHIVE_ROOT" \
  /private/request.json worker-a /private/restored-42 loopback
```

For an authenticated historical delivery, replace `loopback` with
`spki:<64-lowercase-hex-worker-key-fingerprint>`. The trust mode is mandatory.
Recovery preserves and checks the original provenance; it performs no new TLS
handshake and does not upgrade an unauthenticated receipt.

The destination of `restore` must be absent and its parent must already exist.
An existing empty directory is also refused. Both commands emit JSON. Exit zero
means the archive/restore operation succeeded, not that the original compilation
succeeded; its original exit code and interruption remain in the receipt.

## Storage and retention

Every input delivery first passes the ordinary complete recovery verifier.
Each file is then independently hashed under both its raw SHA-256 identity and
native domain-separated CAS identity. The standard `put_if_absent` path hashes
the stored bytes again, enforces exact size, uses full durability, and deduplicates
identical content. Executable metadata and the original verified receipt are
bound into the archive index, not inferred from a file extension.

The index is itself a native CAS object. Its reachability edges are installed
before an unexpiring `delivery-archive` pin. Repeated archive operations produce
the same root and pin. A crash before pin creation can leave unreferenced blobs,
but cannot produce an action publication or a successful archive response. The
original delivery is never removed. Released archive pins are not silently
reactivated; restore requires the archive's active retention pin.

Pins protect the complete file closure from ordinary and emergency GC. Retention
is explicit and unexpiring: archiving consumes storage until the pin is released
through store administration. This command does not implement automatic pruning,
archive eviction, or a host-wide disk quota. Put limits cover at most 1 GiB of
combined diagnostics/artifacts and an additional 2 MiB archive index. Keep the
CAS root and its ancestors access-controlled for the sensitivity of the retained
build data.

## Restore frontier and failures

Restoration checks the root bytes, pin, metadata kind, exact request and worker,
file map, native object identities and raw file hashes. Corrupt physical replicas
are quarantined; another verified durable raw replica may satisfy a read. Logical
object quarantine blocks all copies. Unsupported storage encodings are refused
rather than interpreted as raw bytes.

Bytes first land in a private `.restore-staging` subtree of a newly reserved
destination. The ordinary delivery verifier checks the complete reconstructed
receipt, trust policy, expected file set and permissions before promotion.
`delivery.json` is published at the destination only after verified file trees
are moved into place and synchronized. Interrupted restores leave inspectable
partial state, never permission to reexecute. Use a different fresh destination
to restore again; this command never overwrites or deletes a failed restore.

Remote release acknowledgments are not replayed or inferred. A restored result
reports `acknowledgments_confirmed:false` even though its local bytes are verified.
No action entry, coordinator authority, execution lease, trust promotion, or
servable action-result pointer is created by archival.

## Exclusive mount and execution context

`mount_and_reconcile` now holds an OS lock for the entire `LiveCas` lifetime,
before SQLite initialization, reconciliation or coordinator authority acquisition.
The operator and a running daemon cannot independently mount the same store.
Stop the daemon first or use a separate CAS root; the command never takes over a
live owner. The `.mount.lock` inode is retained after unlock and must not be deleted
to bypass fencing. This is local-filesystem ownership, not cross-host election.

The library functions are blocking. They hold the metadata mutex while storing
or reading a complete closure, so call them from an operator/blocking thread, not
an asynchronous control reactor. File inputs and the private store must not be
concurrently modified outside these ownership boundaries. Content verification
is intentionally repeated at storage and recovery boundaries; no throughput or
cache-hit performance improvement is claimed without measurement.

## Verification

`cargo test -p rabsd --test delivery_archive` exercises real CAS puts, idempotence,
pin reachability, store reopen, binary/executable recovery, corruption and replica
fallback, quarantine, refusal of changed requests/existing destinations, and the
actual operator binary. Mount tests cover duplicate and aliased mounts, a separate
process, unsafe lock paths, last-owner release and failed startup. These tests
must run with the project toolchain; their presence alone is not a passing result.
