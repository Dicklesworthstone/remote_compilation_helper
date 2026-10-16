# Canonical Cargo-driver builds through the installed toolset

`cargo rabs --rabs-canonical PROFILE.json -- build --bin app --release` connects
ordinary named-binary Cargo builds to RABS's existing canonical worker path:

1. The launcher validates explicit source, toolchain, worker and destination
   intent and creates a new private operation directory.
2. It execs the installed `rabsd --worker-build-tls --prepare-from ...` once.
3. The native driver calls the existing coherent source/optional vendor graph
   planner and complete toolchain capture. `request.json` is made durable only
   after the captured input bundle is ready.
4. The existing mutual-TLS worker exchange transfers the captured inputs, runs
   Cargo itself inside the worker's canonical namespace and receives the complete
   verified output tree. Successful results install into a new private directory.

This is the canonical **Cargo driver**, not a wrapper-only path rewrite. The
source remains `/__rabs/workspace`, the captured toolchain lives under
`/__rabs/toolchain`, and Cargo writes to `/__rabs/out/cargo` before any rustc unit
is planned. Existing worker output, cancellation, lease and recovery mechanisms
are reused. There is no second scheduler, transport, artifact installer or cache.

**This profile is execution-only.** It does not publish an action-cache result,
serve a cache hit, distribute individual rustc units, enable the local dependency
lane, or share a cache across workers. It does not make an unsandboxed local
cache key equivalent to a canonical execution. Those remain separate integration
and qualification tasks. Unlike `--rabs-remote`, this path does not invoke RCH.

## Profile and prerequisites

Linux is required on the preparing host and worker. Install matching `cargo-rabs`
and `rabsd` on the preparing host and `rabs-wkr` on the worker. The native toolchain
directory must contain ordinary executable `bin/cargo` and `bin/rustc` plus the
runtime/sysroot files required by the existing toolchain capture contract. Rustup
shims or symlinks are not a substitute for a complete toolchain dataset.

Create an operation parent outside the source/toolchain trees, owned by the user
and mode 0700. Existing directories are not silently chmodded. Use this profile:

```json
{
  "version": "canonical-cargo-v1",
  "listen": "192.0.2.10:45200",
  "worker": "worker-a",
  "worker_spki_sha256": "REPLACE_WITH_64_LOWERCASE_HEX_DIGITS",
  "source_root": "/data/projects/approved-anchor",
  "toolchain_root": "/opt/rust/native-linux-toolchain",
  "operation_root": "/data/rabs-operations",
  "manifest": "app/Cargo.toml",
  "vendor": "vendor"
}
```

`listen` is the **coordinator's local bind address**, not a worker address. Use
an actual local IP and a nonzero port. The separately configured, authenticated
worker must connect/reconnect to that address using its existing `--coordinator`
mode. Concurrent operations need distinct listen endpoints (or the existing
prepared-job service); this frontend does not allocate ports or start workers.

The existing native TLS adapter uses `RABS_COORD_TLS_CA`, `RABS_COORD_TLS_CERT`
and `RABS_COORD_TLS_KEY`. Configure the worker's matching trust separately.
The launcher does not create certificates, send private keys, downgrade to
plaintext, deploy services or guess an SSH command. `CARGO_RABS_DAEMON` can select
an explicit installed native driver. Missing or old tooling fails without local
compilation or retry through RCH.

`source_root` is explicit permission to capture/upload the **complete approved
anchor**, subject to existing capture policy. Keep credentials, unrelated files
and build outputs outside it. The launcher does not run `cargo vendor`, modify
Cargo configuration or fetch dependencies. `manifest` defaults to `Cargo.toml`.
`vendor` is optional: omit it for an entirely local graph, or name the existing
approved vendor tree. The shared planner validates its source-replacement config,
lockfile and checksum-covered package closure. Unsupported configuration, escaping
local dependencies and symlink sources refuse preparation; there is no fallback
that uploads a larger guessed set.

## Supported command contract

The first command must be `build`, with at least one explicit `--bin NAME` or
`--bin=NAME`. The required outputs are those **actual binaries**, never incidental
Cargo metadata used as an invented success marker. `tree-files-v1` also returns
the complete bounded regular-file output tree, including intermediate artifacts.

Supported options are `--package`/`-p`, `--features`/`-F`, `--all-features`,
`--no-default-features`, `--release`/`-r`, `--locked`, `--offline`, `--frozen`,
`--color`, `--verbose`/`-v`/`-vv`, `--quiet`/`-q`, and one optional `--target` from:
`x86_64-unknown-linux-gnu`, `aarch64-unknown-linux-gnu`,
`x86_64-unknown-linux-musl`, `aarch64-unknown-linux-musl`.
Value options accept a separate value or `=value`; compact `-pname`/`-Fname`
spellings are not supported. Required target libraries/linkers must already exist
in the captured toolchain or admitted worker environment; selecting a triple does
not install a cross-compiler. Cargo remains responsible for package/feature
resolution and may reject an otherwise syntactically supported request.

The profile owns `--manifest-path` and `--target-dir`. Custom profiles, target JSON,
`--config`, unstable flags, `+toolchain`, execution commands (`run`, tests), broad
implicit target selection and unknown options refuse rather than silently change
meaning. The selected toolchain also supplies local Cargo metadata probes; a
`cargo +nightly rabs` launcher selection does not override that explicit dataset.
Cargo is always locked/offline, without duplicating supplied flags.

The worker receives its existing clear-environment canonical base, with
`CARGO_INCREMENTAL=0`. **Ambient dispatcher RUSTFLAGS, Cargo configuration,
custom wrappers and other environment values are not copied into the worker
command.** This is an explicitly selected canonical build profile, not transparent
preservation of the dispatcher's execution environment. TLS credentials remain
local to the transport process. The worker retains ownership of its jobserver;
this frontend does not send the dispatcher's descriptor numbers to another host.

## Outputs, failure and recovery

Before handing off, the launcher prints the retained operation directory to
stderr. `spec.json` is preparation intent, not an input or result digest.
`operation.json` records the native prepared-build argv and request ID, not an
execution receipt. Source/toolchain capture and verified delivery stay with
`rabsd`; the launcher does not parse a success-looking stdout line into authority.

**stdout is the native worker-build JSON report, not a Cargo message stream.**
Compiler diagnostics are retained in the verified delivery directory. The native
driver's exit code and signals remain observable through exec. The launcher adds
no detached child, build retry, local fallback or shared-daemon startup.

Every invocation chooses a new exclusive operation directory. Failed or partial
state is retained. Do not rerun the frontend to recover an uncertain execution:
that would explicitly request a new operation. Inspect its existing bundle and
delivery, then use the existing prepared-build recovery interface without
`--prepare-from`. A complete delivery can be verified/reused offline; an incomplete
one refuses ordinary redispatch. Explicit `--resume` retrieves a retained worker
result into a new delivery directory and never executes again. Source-preparation
failures must be corrected before requesting another build; partial bundles are
never overwritten.

Existing transfer bounds still apply: a maximum 4096 regular tree files and the
worker delivery byte limit, currently 1 GiB including diagnostics. Filesystem and
source/toolchain preparation costs are included; kernel I/O is not claimed
interruptible. Nothing here demonstrates a speedup or establishes production
readiness.

## Validation and remaining work

The launcher regression suite executes the production Python entry point and
real exec, filesystem, pipes and signals with a clearly marked native-driver
**double**. It does not execute Rust, Cargo, TLS or bubblewrap. Python site startup
is omitted in subprocess fixtures so unrelated installed hooks do not own test
lifecycle. Separate Rust tests call the actual source preparation API and cover
exclusive paths, old-checkout independence, malformed specs and recovery refusal.

```sh
python3 -I -S scripts/tests/test_cargo_rabs_canonical.py -v
rch exec -- cargo test -p rabsd --bin rabsd worker_exec::prepared_build --locked
```

The authoring environment has no Rust toolchain. Rust compilation/tests and a
real native Cargo-to-authenticated-worker build remain unverified. Before rollout,
run that full path using one pinned revision and compare output bytes and compiler
failures to the explicit canonical baseline. Per-action admission/placement,
coordinator-only cache publication, cross-worker reuse, real compiler-skip evidence,
performance gates and the required canary/soak are not completed by this frontend.
