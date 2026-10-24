# Restart reuse of toolchain digests

The opt-in live Cargo dependency lane now retains verified compiler, runtime
library and sysroot file digests across **same-boot daemon restarts**. This avoids
rehashing unchanged toolchain bytes merely because `rabsd` restarted. It does not
make a cache hit authoritative and does not enable remote worker execution.

## Using it

The existing `scripts/cargo-rabs` launcher supplies an absolute `RABS_STATE_DIR`.
On qualified Linux x86-64 and AArch64 hosts, the first toolchain warm opens
`$RABS_STATE_DIR/toolchain-digests.v1`. The state directory must already exist,
be owned by the daemon's user, and not be writable by group or other users.
No directory or permission repair is performed by this optimization.

A manually started daemon can use the same optimization by setting its existing
`RABS_STATE_DIR` to an absolute, owner-controlled directory outside its toolchain.
Set `RABS_TOOLCHAIN_DIGEST_CACHE=0` (or `off`) on the daemon to disable persistence
without disabling the existing in-memory memo or changing serving policy.

The structured `rabsd-toolchain-digest-cache` event reports `ready` and the number
of retained entries loaded, or `cold` and the journal refusal reason. An entry
count is **not** a cache-hit count, proof of compiler skipping, or a speedup
measurement. The first warm still reads all uncached bytes.

## What remains mandatory

The daemon still probes the exact compiler and completely observes toolchain
membership. Every named file, including hardlinked aliases, is checked before
and after hashing. A retained digest is selected only by the exact device,
inode, byte length, modification timestamp and change timestamp already used by
the process-local memo. A changed file requires a fresh descriptor-verified read.
Directory observations and request guards are never loaded from the journal.

The journal additionally binds the Linux boot ID, mount namespace, user, digest
algorithm and typed object domain. It cannot be reused after a reboot or in
another mount namespace. Like the existing file-generation memo, it assumes a
trusted local filesystem whose change timestamps change on writes; filesystem
rollback and malicious same-user modification of private state are outside that
contract. Checksums detect corruption, not an authorized user's forgery.

No action key, publication, verification result, replay allowance, compiler
transcript or compiler-skip authorization is imported. Existing independent
verification, quarantine, output custody, materialization and serving gates
remain unchanged.

## Bounds and recovery

The owner-private journal holds at most 16,384 fixed-size records: 1,966,176
bytes including its header. Its lock never waits. A busy, foreign, linked,
permissively accessible, oversized or unsupported journal causes ordinary
verified reads instead. No shared endpoint, daemon or unrelated file is removed.

Records are appended only after a verified read and a fresh pathname check.
A torn final append contributes no hint; recovery retains only the complete,
checksummed prefix. A damaged known-format header, corrupt complete record or
contradictory digest discards all retained hints. Unknown formats are left
untouched. Persistence failure does not fail a successfully verified warm.

## Regression command

```sh
cargo test -p rabsd --lib edge::live_facts::toolchain_hashing --locked
```

The tests cover restart reuse through the production hashing path, changed
inputs, boot/namespace invalidation, corruption, contradictory records, torn
appends, private-file checks, lock ownership, capacity and typed encoding.
Running these tests is not a substitute for the real Cargo acceptance suite:

```sh
python3 scripts/test_rabs_live.py
```
