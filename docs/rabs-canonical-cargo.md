# Canonical Cargo-driver builds through the installed toolset

`cargo rabs --rabs-canonical PROFILE.json -- build --workspace` connects ordinary
Cargo workspace builds to RABS's existing canonical worker path. The same path
supports `check` and `test --no-run`, with Cargo selecting the requested libraries,
binaries, examples and test executables:

1. The launcher validates explicit source, toolchain, worker and destination
   intent and creates a new private operation directory.
2. It execs the installed `rabsd --worker-build-tls --prepare-from ...` once.
3. The native driver captures the source graph, approved vendor tree or locked
   registry cache, and complete toolchain. `request.json` is made durable only
   after the captured input bundle is ready.
4. The existing mutual-TLS worker exchange transfers the captured inputs and runs
   Cargo itself inside the worker's canonical namespace. Cargo's JSON reports
   identify its actual outputs; both peers verify those files against the complete
   captured output tree. Successful results install into a new private directory.

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

Worker capability probing executes a no-op inside the same canonical base
namespace used for builds, including private `/proc`, `/dev`, temporary storage
and isolated networking. An installed bubblewrap and a successful basic user/PID
namespace smoke test are insufficient. A host that cannot construct the complete
base namespace does not advertise canonical execution or receive those builds;
the worker does not substitute a broader mount view or weaker isolation.

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
For an entirely local graph, omit `vendor` and `cargo_home_source`. For a
pre-vendored graph, name the existing approved `vendor` tree. The shared planner
validates its source-replacement config, lockfile and checksum-covered package
closure. Unsupported configuration, escaping local dependencies and symlink
sources refuse preparation; there is no fallback that uploads a larger guessed
set.

### Use dependencies already cached by Cargo

For a locked crates.io graph, replace `vendor` with an explicit absolute
`cargo_home_source` in the profile:

```json
"cargo_home_source": "/home/builder/.cargo"
```

This selects the crates.io sparse registry cache. The native preparer reads
`Cargo.lock` from the captured workspace, selects the required `.crate` archives
and sparse index records, verifies archive SHA-256 values against that lockfile,
and checks archive paths and bounded unpacked contents before Cargo uses them.
It runs offline Cargo metadata against a fresh private Cargo home and verifies
the resolved graph against the retained inputs. The lockfile must remain
unchanged. Missing cache entries, checksum mismatches and unsupported registry
sources refuse preparation before remote execution.

The cache must contain the locked graph, including optional and target-specific
dependencies needed by the planner's `--all-features` metadata check. A successful
default-feature build alone may not populate it. Prepare that cache explicitly
with stock `cargo fetch --locked` before using this offline mode; the RABS
preparer does not perform that network operation for you.

The imported bytes become an ordinary part of the verified source bundle under
the reserved `rabs-cargo-home` prefix. The worker uses the explicit
`isolated-registry-cargo-home-v1` projection to reconstruct separate private
workspace and Cargo-home directories. The transport cache prefix is absent from
the workspace seen by Cargo and build scripts, preserving the original source
layout and wildcard workspace membership. Execution stays locked/offline.
The selected cache files are copied; the user's Cargo home is never used as a
writable planning or worker directory. User configuration,
credentials, Git checkouts and previously expanded `registry/src` trees are not
imported. This mode neither fetches missing dependencies nor runs `cargo vendor`.

`cargo_home_source` and `vendor` are mutually exclusive. The selected Cargo home
must have ordinary directory ancestors and be disjoint from the source,
toolchain and operation roots. The source anchor must not already contain the
reserved `rabs-cargo-home` directory. Git dependencies and alternate registries
still require the approved vendor route. Cache capture does not authorize action
cache publication or a compiler skip.

## Supported command contract

The first command must be `build`, `check`, or `test` with `--no-run`. For example:

```sh
cargo rabs --rabs-canonical PROFILE.json -- build --workspace
cargo rabs --rabs-canonical PROFILE.json -- check --workspace --all-targets
cargo rabs --rabs-canonical PROFILE.json -- test --workspace --no-run
cargo rabs --rabs-canonical PROFILE.json -- build -p app --bin app --release
```

Cargo owns package and target selection, including its normal defaults when no
selection option is supplied. Supported selectors are `--workspace`,
`--package`/`-p`, `--exclude` (with `--workspace`), `--lib`, `--bins`, `--examples`,
`--tests`, `--benches`, `--all-targets`, and literal `--bin NAME`, `--example NAME`,
`--test NAME` or `--bench NAME`. Test executables are compiled and returned;
this operation does not run them or claim that their tests passed.

Supported build options are `--features`/`-F`, `--all-features`,
`--no-default-features`, `--release`/`-r`, `--locked`, `--offline`, `--frozen`,
`--color`, `--verbose`/`-v`/`-vv`, `--quiet`/`-q`, and one optional `--target` from:
`x86_64-unknown-linux-gnu`, `aarch64-unknown-linux-gnu`,
`x86_64-unknown-linux-musl`, `aarch64-unknown-linux-musl`.
Value options accept a separate value or `=value`; compact `-pname`/`-Fname`
spellings are not supported. Required target libraries/linkers must already exist
in the captured toolchain or admitted worker environment; selecting a triple does
not install a cross-compiler. Cargo remains responsible for package/feature
resolution and may reject an otherwise syntactically supported request.

The profile owns `--manifest-path`, `--target-dir` and `--message-format=json`.
Custom profiles, target JSON, `--config`, unstable flags, `+toolchain`, execution
commands (`run`, `test` without `--no-run`), arguments after `--`, and unknown
options refuse before preparation. The selected toolchain also supplies local Cargo metadata probes; a
`cargo +nightly rabs` launcher selection does not override that explicit dataset.
Cargo is always locked/offline, without duplicating supplied flags.

The worker receives its existing clear-environment canonical base, with
`CARGO_INCREMENTAL=0`. **Ambient dispatcher RUSTFLAGS, Cargo configuration,
custom wrappers and other environment values are not copied into the worker
command.** This is an explicitly selected canonical build profile, not transparent
preservation of the dispatcher's execution environment. TLS credentials remain
local to the transport process. The worker retains ownership of its jobserver;
this frontend does not send the dispatcher's descriptor numbers to another host.

The optional profile field `jobserver_grant` requests an integer from 1 to 4096
worker execution slots. It becomes native request intent; the launcher does not
inject `NUM_JOBS`, `--jobs` or dispatcher jobserver handles. When a worker uses a
shared host budget, choose a grant no larger than that budget. For example, a
host with eight shared slots can admit four Cargo roots requesting two slots
each. Each root owns its implicit slot and receives at most one transferable
jobserver token. The worker keeps that grant through process-group cleanup.

## Outputs, failure and recovery

The explicit `artifacts.cargo = "cargo-json-v1"` contract augments
`tree-files-v1`. The launcher's `files` minimum is empty because it does not guess
hashed library, metadata, executable or target-triple paths. After Cargo exits
successfully and its writers have drained, the worker requires a complete
`compiler-artifact` / `build-finished` report with at least one ordinary target.
Every reported output must exist beneath `/__rabs/out/cargo`, and each reported
executable must retain executable mode. The worker captures the entire bounded
regular-file tree, including Cargo intermediates that are absent from the report.
Incidental files such as `.rustc_info.json`, or a success marker alone, cannot
satisfy the contract.

The coordinator independently checks the hash-verified report against the artifact
manifest before acknowledging delivery, then verifies every delivered file using
the existing protocol. Offline recovery repeats the report check after verifying
the retained bytes and modes. Missing outputs, truncated reports, failed builds
and malformed output paths refuse success. Old worker/driver versions reject the
new declaration; install matching binaries. Cargo's report supplies output names,
never cache authority or permission to skip a compiler.

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
worker delivery byte limit, currently 1 GiB including diagnostics. Cargo report
parsing also limits stdout to 64 MiB and each line to 1 MiB, before allocating an
unbounded record. Non-JSON procedural-macro stdout remains in diagnostics.
Filesystem and
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
rch exec -- cargo test -p rabsd --test cargo_vendor_prepare registry:: --locked
rch exec -- cargo test -p rabs-sandbox --lib cargo_home --locked
rch exec -- cargo test -p rabs-wkr --lib cargo_home --locked
rch exec -- cargo test -p rabs-sandbox --lib cargo_artifacts --locked
rch exec -- cargo test -p rabs-sandbox --test cargo_artifacts --locked
rch exec -- cargo test -p rabs-wkr --lib cargo_capture --locked
rch exec -- cargo test -p rabs-wkr --lib cargo_dynamic_outputs --locked
rch exec -- cargo test -p rabsd --lib coord::worker_delivery::tests --locked
```

The Cargo artifact integration fixture runs the real installed Cargo and rustc
against a two-package workspace with generated Rust. It builds, checks and
compiles tests, validates every report against the descriptor-anchored output
inventory, executes the produced application and integration-test binary, and
checks that a real compiler error cannot become a successful report. Worker
capture/completion tests preserve the original admitted declaration while
discovering dynamic outputs. Coordinator scripted-peer tests cover refusal before
acknowledgement and revalidation during offline recovery; they do not substitute
for authenticated worker execution.

The separate canonical namespace fixture uses the production mount and launch
builders, poisons the live checkout after source capture, and checks read-only
source enforcement plus all three compilation modes. It is explicitly opt-in;
an incapable host fails the requested test instead of recording a successful skip:

```sh
cargo test -p rabs-sandbox --test cargo_artifacts \
  canonical_namespace_build_check_and_test_compilation_capture_actual_outputs \
  -- --ignored --exact
```

The cached-registry integration fixture calls the production preparer and runs
real Cargo with transitive dependencies, a build dependency and generated Rust.
It poisons the original expanded registry sources and user configuration, retires
the original source/cache directories after preparation, and asserts that build
scripts see exactly the original workspace entries. Separate malformed-input
cases must refuse before publishing a prepared bundle.

The authenticated worker fixture is explicitly opt-in on a canonical-capable
Linux host with OpenSSL and matching built binaries:

```sh
RABS_TEST_WORKER_BIN="$PWD/target/debug/rabs-wkr" \
  cargo test -p rabsd --test cargo_vendor_prepare \
    registry::cached_crates_io_builds_over_native_tls_without_user_cache_and_replays_outputs_offline \
    -- --ignored --nocapture

RABS_TEST_WORKER_BIN="$PWD/target/debug/rabs-wkr" \
  cargo test -p rabsd --test cargo_vendor_prepare \
    registry::cargo_selected_workspace_outputs_survive_native_tls_and_offline_recovery \
    -- --ignored --nocapture
```

Before rollout, run that full path using one pinned revision and compare output
bytes and compiler failures to the explicit canonical baseline. Input preparation
and isolated filesystem tests alone do not prove the authenticated build.
Per-action admission/placement,
coordinator-only cache publication, cross-worker reuse, real compiler-skip evidence,
performance gates and the required canary/soak are not completed by this frontend.
