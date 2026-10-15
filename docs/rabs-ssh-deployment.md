# Deploying the RABS toolset over SSH

`install-rabs --ssh HOST` transfers and installs `cargo-rabs`, `rabs-wrap`,
`rabsd`, and `rabs-wkr` together. Repeat `--ssh` for up to 32 distinct SSH
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
`wrapper-release/rabs-wrap`, `daemon-release/{rabsd,rabs-wkr}`, and the
checkout's `scripts/cargo-rabs`. No compiler runs on the deployment path.

## Transport and activation

SSH uses existing host aliases/configuration, batch authentication, and strict
host-key checking. Enroll host keys through the operator's normal trusted
process first. Agent forwarding and port forwarding are disabled; no project
source, Cargo environment, or credentials are included in the transfer.

The dispatcher captures one private transfer image containing the installer
and all four tools, checking source file identities before and after capture.
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
or new daemon to guess the outcome. Inspect the worker's `.rabs-current` link
and retained `.rabs-versions/<generation>/manifest.json` before another
operator-directed installation. Compare the current files' actual hashes
against the desired toolset; the manifest alone is not a fresh content check.

The sender retains the `transfer_image` path reported in the JSON result.
Successful receipts also name the receiver's `staging_dir`. Incomplete remote
stages use private `rabs-deploy-recv-*` directories under that worker's temporary
directory. Staging and previous generations are not automatically deleted.
Retained stages therefore consume disk and require deliberate operator
retention management; the installer makes no garbage-collection claim.

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
