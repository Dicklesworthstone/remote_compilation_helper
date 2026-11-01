# Deploying the RABS toolset over SSH

`install-rabs --ssh HOST` transfers and installs `cargo-rabs`, `rabs-wrap`,
`rabsd`, `rabs-wkr`, and `rabs-cargo-root` together. Repeat `--ssh` for up to 32 distinct SSH
host aliases. This is the S7 tool-distribution path: it does **not** turn the
host-local dependency cache into fleet-wide canonical execution, start services,
reconfigure Cargo, or qualify a release to serve cached compiler outputs.

## Install a trusted release

Verify the release's publisher signature/checksum **before** selecting its
archive. The installer does not download releases or authenticate publishers;
its SHA-256 comparisons detect transfer/copy corruption, not provenance.

```sh
python3 scripts/install-rabs \
  --from-archive /absolute/path/to/authenticated-linux-release.tar.gz \
  --ssh worker-a --ssh worker-b
```

Omitting `--bin-dir` selects **each remote user's** `~/.local/bin`, not the
dispatcher's home. An explicit `--bin-dir` must be absolute and is applied on
every selected worker. Paths are framed data on stdin, never shell fragments.

Workers require Python 3 and Linux x86-64 or AArch64. Select the archive for
their architecture; use a separate invocation for the other architecture.
The dispatcher need not share the workers' architecture. The receiver checks
native ELF identity before switching the active generation. Already-running
RABS processes continue running their original generation: installation does
not restart or kill them. Existing daemon configuration is not changed.

An extracted, trusted bundle works with `--from-bundle`. Locally built tools
work with `--from-build /path/to/target/<target-triple>`, which selects
`wrapper-release/rabs-wrap`, `daemon-release/{rabsd,rabs-wkr,rabs-cargo-root}`, and the
checkout's `scripts/cargo-rabs`. No compiler runs on the deployment path.

## Transport and activation

SSH uses existing host aliases/configuration, batch authentication, and strict
host-key checking. Enroll host keys through the operator's normal trusted
process first. Agent forwarding and port forwarding are disabled; no project
source, Cargo environment, or credentials are included in the transfer.

The dispatcher captures one private transfer image containing the installer
and all five tools, checking source file identities before and after capture.
Every worker receives those same bytes. The receiver verifies the complete
inventory, exact sizes, SHA-256 digests, and stream termination before calling
the existing installer. All tools become current via one atomic generation
symlink switch. Previous generations and unmanaged installations are retained;
an unmanaged destination is refused rather than overwritten.

`--ssh-timeout SECONDS` bounds each SSH client's complete lifetime (default
600, range 1..3600), including transfer and the installation acknowledgment.
A short additional reap allowance follows a terminated client. Both output
streams share a 128 KiB limit. No per-byte timeout can extend the deadline.

`--ssh-reserve-mib MIB` requires capacity above the transfer and installation
payload (default 1024, range 64..65536). Checks cover local staging and both
remote staging and destination filesystems. This is a capacity **preflight**,
not a reservation against other users concurrently filling a filesystem.

## Outcomes and recovery

The command emits one JSON `rabs-deployed` result. Each worker has either
`state: "installed"`, with a receipt binding the sent file identities and
installed generation, or `state: "unconfirmed"`. Exit status is zero only
when every selected worker returns a valid complete receipt. A failed worker
does not prevent attempts on the other distinct, explicitly selected workers.

**An unconfirmed result is not proof that installation did not happen.** A
connection may fail after the active generation was switched. The command
never retries that worker automatically, invents a rollback, or starts an old
or new daemon to guess the outcome. Use the read-only verification command
below to check whether the intended toolset is now active before considering
another operator-directed installation.

The sender retains the `transfer_image` path reported in the JSON result.
Successful receipts also name the receiver's `staging_dir`. Incomplete remote
stages use private `rabs-deploy-recv-*` directories under that worker's temporary
directory. Staging and previous generations are not automatically deleted.
Retained stages therefore consume disk and require deliberate operator
retention management; the installer makes no garbage-collection claim.

### Verify an interrupted activation

Use the `transfer_image` path from the original deployment result and the same
SSH user/host. The image retains the exact bytes sent, even if the original
build directory has subsequently changed:

```sh
python3 scripts/install-rabs --verify \
  --from-image /absolute/path/to/rabs-deploy-send-IDENTITY/transfer.bin \
  --ssh worker-a
```

This checks the image's complete payload against its recorded hashes, then
asks the worker to inspect its current managed generation. It sends only the
current inspector and expected file identities, without retransmitting tools.
The receiver opens the existing installation lock for shared read access,
checks all public links and the active generation manifest, and hashes all
five actual executable files. It also checks native ELF identity, launcher
syntax, ownership and permissions, and rechecks file/link identities after
reading. A manifest alone cannot establish success. No installed executable
is run, no destination or lock is created, and no generation is activated,
replaced, repaired or removed. An installation already holding the lock
produces an unverified result instead of a partial observation.

The original image selects the original destination. If its `bin_dir` was
omitted, verification again uses the remote user's `~/.local/bin`. An explicit
`--bin-dir` that changes the image's destination is refused. For a mixed fleet,
select the corresponding image from the original result's `transfer_images`
map and verify that architecture's hosts together; a wrong-architecture
toolset cannot verify. Repeat `--ssh` and use `--ssh-jobs 1..8` to check several
hosts with the existing strict SSH policy, per-host deadline and output cap.

You can instead select an already authenticated release archive, an extracted
bundle, or matching local build outputs:

```sh
python3 scripts/install-rabs --verify \
  --from-archive /absolute/path/to/authenticated-linux-release.tar.gz \
  --ssh worker-a --ssh worker-b --ssh-jobs 2

python3 scripts/install-rabs --verify \
  --from-bundle /absolute/path/to/trusted-bundle \
  --bin-dir /absolute/path/to/installed/bin
```

Omitting `--ssh` checks the local installation. Verification accepts one
expected toolset per invocation; `--from-target` is an installation option.
Expected archives/images must already be trusted. Comparison hashes detect
changed bytes and bind the result to that selected toolset; they do not
authenticate its publisher or establish Rust build qualification.

An SSH result has `kind: "rabs-verified"`; each worker is `verified` or
`unverified`. A successful receipt names the observed generation and includes
all file hashes and `expected_toolset_sha256`. Local verification emits the
same per-installation receipt directly. Exit status is **zero only when every
requested installation currently matches the expected toolset**. Missing,
corrupt, mixed, unsafe, concurrently changing or unreachable installations
produce a nonzero result with a reason. No automatic retry or rollback follows.

A successful check resolves whether the desired files are active **now**.
The earlier lost acknowledgment remains unconfirmed as a historical event;
verification does not prove which deployment activated those bytes, which
generation a running process uses, or whether coordinator admission and Cargo
serving work. Existing services and Cargo configuration remain untouched.

## Regression coverage

```sh
python3 -m unittest discover -s tests -p 'test_install_rabs*.py' -v
```

The SSH regressions replace only the transport process with a local peer.
They execute the real bounded bootstrap, receiver, filesystem installer,
upgrade transaction, and receipt parser. They use native `true` binaries as
fixtures, not fabricated claims of RABS builds. Passing these tests does not
establish real-fleet SSH connectivity, Cargo cache correctness, distributed
singleflight, or production soak evidence. Rust serving, sampling, release
qualification, capture acknowledgment and quarantine gates are unchanged.
