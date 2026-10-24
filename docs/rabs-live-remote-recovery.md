# Recover a retained live remote dependency result

`scripts/rabs-recover` connects the live remote lane's retained `recovery.json`
and `request.json` to the **existing native TLS result-recovery operator**. It
never sends a new compiler execution. Linux, Python 3.9+, procfs and Linux
sealed memory-file support are required. Use this repository script with an
updated `rabsd`; it is not yet added to the release installer payload.

## Inspect first

Use the directory printed by `rabs-remote-recovery-retained` or by the uncertain
execution error. Paths below are examples, not a directory to create manually.

```bash
recovery=/absolute/rabs-state/dependency-workers/result-EXAMPLE
python3 scripts/rabs-recover "$recovery"
```

Without an operation flag, this reads only bounded private intent metadata. It
checks the saved request digest and prints the request/action identity, selected
worker, listener and original admission-state directory. It does **not** verify
output bytes, infer that execution finished, acquire a worker, or print compiler
arguments/environment values. `outputs_verified` and `publication_authorized`
remain false.

Keep this directory and its original admission state exclusively owned during
recovery. Do not copy the record into a fresh state tree or replace a worker pin
in order to get past fencing. The driver rejects a changed state binding. It
does not stop the daemon, remove locks, cancel an active worker, or retire an
abandoned coordinator action. Wait for normal transport ownership release;
resolve busy ownership through the established operator workflow, not by deleting
its lock or ledger. The worker must reconnect outward to the recorded listener.

## Resume bytes, not execution

Supply the same coordinator TLS credentials used by the original deployment.
The driver checks that their paths are absolute; `rabsd` validates the credentials
and performs authentication. Select a matching binary with `--rabsd` or
`CARGO_RABS_DAEMON`. Otherwise a sibling binary or `rabsd` on PATH is used.

```bash
export RABS_COORD_TLS_CA=/absolute/credentials/ca.pem
export RABS_COORD_TLS_CERT=/absolute/credentials/coordinator.pem
export RABS_COORD_TLS_KEY=/absolute/credentials/coordinator.key

python3 scripts/rabs-recover "$recovery" \
  --rabsd /absolute/bin/rabsd \
  --resume-to /absolute/recovered/dependency-17
```

The destination's parent must already exist; the destination itself must not.
The native receiver creates and verifies the new delivery. Existing partial
files under `$recovery/delivery` are passed as **untrusted prefix hints**, then
reverified with the complete result digest by the same receiver used for normal
recovery. No original file is changed or removed. A missing partial directory
selects result-only resume without prefix hints. `--no-prefix` explicitly requests
fresh result download while retaining a damaged or unwanted old prefix.

If that recovery is interrupted too, keep its new partial directory and select
it explicitly on the next result-only attempt:

```bash
python3 scripts/rabs-recover "$recovery" \
  --prefix-from /absolute/recovered/dependency-17 \
  --resume-to /absolute/recovered/dependency-17-next
```

Every attempt still uses the original saved request, public-key pin, and
admission ledger. Selecting a prefix gives it no execution or result authority.
The new destination cannot overlap either the original recovery directory or
the selected prefix. An unavailable/retired worker result, invalid request,
corrupt bytes, or lost connection is a refusal, never a compiler retry.

## Reconcile a lost acknowledgment

When complete `delivery.json` exists but acknowledgment was unconfirmed, use:

```bash
python3 scripts/rabs-recover "$recovery" \
  --acknowledge "$recovery/delivery"
```

For a completed separate recovery, pass that recovered delivery directory
instead. The helper only checks structural privacy and the presence of an
ordinary bounded marker. **The native operator revalidates the exact request,
historical pinned provenance and every result byte before opening its listener
or sending acknowledgments.** A marker's mere existence is not proof. This mode
neither downloads artifacts nor dispatches execution; corrupted or partial
results cannot authorize an acknowledgment.

The helper hands off with `exec`, retaining the native operator's PID, signals,
terminal streams and exit status. A sealed inherited memory file supplies the
already-checked request bytes, so replacing `request.json` after handoff cannot
substitute a different command. No shell is used and no private request copy is
written to another disk location. The native operator remains responsible for
its absolute deadlines, worker-session fencing and complete output validation.

## Boundaries

These are result retrieval and acknowledgment operations, **not** automatic live
action reconciliation. A resumed receipt identifies its delivery session; it
does not invent the original execution incarnation. Recovery does not publish a
cache entry, install into Cargo's target tree, clear an abandoned actor, or
authorize skipping rustc. Successful retrieval is also distinct from the
historical compiler's exit status, which remains in the native receipt/output.

Request records can contain sensitive environment values. Keep the owner-only
permissions; do not attach whole recovery directories to public reports. Sealed
handoff prevents request-path substitution, but this is not a defense against a
malicious process sharing the operator's credentials and mutating its other
state. Retained and newly recovered directories consume disk until explicitly
handled; this command introduces no automatic cleanup policy.

The Python regression suite exercises actual file/descriptor/sealing/process
behavior with an explicit `rabsd` executable fixture. It is not a native TLS,
Rust compilation, real worker-result retrieval or Cargo performance result:

```bash
python3 -I -S scripts/tests/test_rabs_recover.py -v
```
