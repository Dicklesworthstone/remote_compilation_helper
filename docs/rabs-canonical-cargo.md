# Canonical Cargo-driver builds through the installed toolset

`cargo rabs --rabs-canonical PROFILE.json -- build --workspace` connects ordinary
Cargo workspace builds to RABS's existing canonical worker path. The same path
supports `check`, `clippy`, `test`, and `test --no-run`, with Cargo selecting the
requested libraries, binaries, examples and test executables. Ordinary `test` runs those
tests on the selected worker and returns Cargo's final exit status:

1. The launcher validates explicit source, toolchain, worker or worker pool, and destination
   intent and creates a new private operation directory.
2. It execs the installed native driver once: normally
   `rabsd --worker-build-tls --replay-diagnostics --prepare-from ...`, or
   `rabsd --job-build --prepare-from ...` when `daemon_socket` is selected.
3. The native driver captures the source graph, approved vendor tree or locked
   dependency cache, and complete toolchain. `request.json` is made durable only
   after the captured input bundle is ready. Daemon jobs retain allocation
   intent until the queue selects their execution owner.
4. The existing mutual-TLS worker exchange transfers the captured inputs and runs
   Cargo itself inside the worker's canonical namespace. Cargo's JSON reports
   identify its actual outputs; both peers verify those files against the complete
   captured output tree. Successful results install into a new private directory.
5. After complete verified delivery, the native driver replays the exact retained
   Cargo/test stdout and stderr. Native operation reports are written to stderr.
   A failing test keeps its nonzero status and diagnostics; it does not install a
   successful artifact result or retry locally.

This is the canonical **Cargo driver**, not a wrapper-only path rewrite. The
source remains `/__rabs/workspace`, the captured toolchain lives under
`/__rabs/toolchain`, and Cargo writes to `/__rabs/out/cargo` before any rustc unit
is planned. Existing worker output, cancellation, lease and recovery mechanisms
are reused. The existing scheduler, transport and artifact installer remain in
control of every operation.

**This profile is execution-only.** It does not publish an action-cache result,
serve a compiler or test-result cache hit, distribute individual rustc units, enable the local dependency
lane, or share a cache across workers. It does not make an unsandboxed local
cache key equivalent to a canonical execution. Those remain separate integration
and qualification tasks. Unlike `--rabs-remote`, this path does not invoke RCH.

## Profile and prerequisites

Linux is required on the preparing host and worker. Install matching `cargo-rabs`
and `rabsd` on the preparing host and `rabs-wkr` on the worker. The native toolchain
directory must contain ordinary executable `bin/cargo` and `bin/rustc` plus the
runtime/sysroot files required by the existing toolchain capture contract. Rustup
shims or symlinks are not a substitute for a complete toolchain dataset.
For `clippy`, that same captured dataset must also contain ordinary executable
`bin/cargo-clippy` and `bin/clippy-driver`. The launcher invokes the captured
Clippy program directly and binds its Cargo and rustc companions to the captured
absolute paths, so dispatcher or worker PATH entries cannot select a different
Clippy installation.

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
mode. Direct operations need distinct listen endpoints when they run concurrently.
The daemon mode below uses the existing prepared-job service to serialize jobs
for the same worker and endpoint. This frontend does not allocate ports or start
workers.

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

### Submit canonical builds to the running daemon

Add an explicit local socket to the same profile to use durable background job
ownership:

```json
"daemon_socket": "/home/builder/.cache/rch/rabsd.sock"
```

The socket must already exist, be private to the current user, and have ordinary
directory ancestors. Its immediate parent must be owned by that user and not
writable by others. Keep the endpoint outside the captured inputs. The launcher
attaches to this daemon; it does not start or reconfigure it. Configure the
daemon's own `RABS_STATE_DIR` and `RABS_COORD_TLS_CA`, `RABS_COORD_TLS_CERT`, and
`RABS_COORD_TLS_KEY` before starting it. The background daemon owns the worker's
TLS exchange and durable admission state.

The native client captures the approved workspace, dependencies and toolchain
once, submits that retained bundle under a new job ID, then waits for verified
delivery. Worker request IDs are allocated when the daemon claims a queued job,
while holding the selected worker's admission through dispatch. This prevents
concurrent callers from allocating IDs in one order and reaching the worker in
another. The queued template keeps explicit `request_id: "allocate"`; only the
durably bound daemon record carries the actual numeric execution identity.
No source recapture or new ID allocation occurs during result recovery.

The command returns Cargo's actual exit code and replays the complete verified
stdout and stderr. A lost client connection or an interrupted waiting client
leaves the same durable job available for inspection. It does not submit another
build or cancel the background job. `operation.json` in the printed operation
directory records `job_id`, `daemon_socket`, and the submit/status/wait/cancel commands.
For example, using that exact job ID:

```sh
RABS_SOCKET_PATH=/home/builder/.cache/rch/rabsd.sock rabsd --job-status JOB_ID
RABS_SOCKET_PATH=/home/builder/.cache/rch/rabsd.sock rabsd --job-wait JOB_ID
RABS_SOCKET_PATH=/home/builder/.cache/rch/rabsd.sock rabsd --job-cancel JOB_ID
```

The ordinary recovery frontend also recognizes a saved daemon operation:

```sh
cargo rabs --rabs-recover /home/builder/.cache/rch/operations/cargo-JOB_ID
```

It uses the saved job ID and private daemon socket to invoke `--job-wait` once.
The original profile, checkout, toolchain and captured bundle are not needed for
this read-only wait/replay path. It does not resubmit the job. For a daemon-owned
operation, `--status` and `--cancel` also address that same job. Result controls
`--resume-to NEW_DELIVERY [--prefix-from PREFIX]`, `--delivery DELIVERY`, and
`--acknowledge DELIVERY` hand off to the daemon's existing result-resume, local
recovery, and release commands. They preserve its selected worker and request
identity. Wait on the original job afterward to replay a verified compiler
result.

Waiting again is a read-only operation and replays a verified completed result.
If the initial submission response was lost, inspect the same job first. The
saved `job_submit_argv` invokes `--job-submit-allocated` with that exact ID,
placement and retained bundle. Repeating this admission is idempotent: an
existing job returns its original status and assigned worker ID; it does not
queue another execution. A changed bundle or destination is refused. This is
also the recovery route when capture completed but the first admission failed.
If a daemon or transport failure leaves execution uncertain, inspect and recover
that same job with the existing job recovery commands. A second invocation of
`cargo rabs` creates a new job; it is not a recovery operation. The service keeps
its existing bounded queue, per-worker ownership, cancellation, result-only
reconnection and local-delivery recovery behavior. This mode adds no compiler
cache or per-unit scheduling authority.

### Place canonical Cargo jobs across a worker pool

Replace the three singular `listen`, `worker`, and `worker_spki_sha256` fields
with an ordered `workers` array to let the daemon select a worker for each
whole Cargo job. Pool placement requires `daemon_socket`; it uses the same
durable job service as single-worker daemon builds:

```json
{
  "version": "canonical-cargo-v1",
  "daemon_socket": "/home/builder/.cache/rch/rabsd.sock",
  "workers": [
    {
      "listen": "192.0.2.10:45200",
      "worker": "worker-a",
      "worker_spki_sha256": "REPLACE_WITH_WORKER_A_64_LOWERCASE_HEX_DIGITS"
    },
    {
      "listen": "192.0.2.10:45201",
      "worker": "worker-b",
      "worker_spki_sha256": "REPLACE_WITH_WORKER_B_64_LOWERCASE_HEX_DIGITS"
    }
  ],
  "source_root": "/data/projects/approved-anchor",
  "toolchain_root": "/opt/rust/native-linux-toolchain",
  "operation_root": "/data/rabs-operations",
  "manifest": "app/Cargo.toml"
}
```

The array accepts 1–32 entries. Each entry names an already configured worker,
its nonzero lowercase certificate pin, and its coordinator bind endpoint.
Names, pins and normalized endpoints must be distinct. IPv6 endpoints use
`[address]:port`. The singular fields and `workers` cannot be combined. Each
worker must already reconnect to its own listed endpoint; this profile does
not provision workers or discover a fleet.

The daemon chooses an eligible worker using its durable job load, with the
listed order breaking equal-load ties. It excludes workers whose previous
execution remains unresolved. Selection and the original pool intent become
part of the durable job before dispatch, so concurrent submissions can spread
across available workers while retaining the existing queue and admission
limits. A selected job keeps that worker for execution, cancellation and
result-only recovery. An interrupted or uncertain attempt is never moved to
another worker. The pool supplies whole-Cargo placement, not per-rustc-unit
distribution or permission to reuse another worker's private target state.

The operation directory retains private, exclusively created `pool.json` along
with `spec.json` and `operation.json`. The pool file is a native JSON array of
`address`, `worker`, and `worker_spki_sha256` entries in the original order;
literal endpoints are normalized before saving. All three files are made
durable before the launcher hands off. `operation.json` retains `worker_pool`
as placement intent and the job's status command. The daemon's `--job-status`
response identifies the actual selected worker and, after admission, its bound
request ID; the launcher does not claim to know that choice in advance.

The saved submission command is
`rabsd --job-submit-pool JOB_ID POOL_FILE BUNDLE DELIVERY OUTPUTS`. Repeating
that exact admission after an uncertain submission response returns the same
durable job and selection. Changing its ordered pool, captured bundle or
destinations is refused. The ordinary `cargo rabs --rabs-recover OPERATION`
wait/status/cancel and result-recovery controls still address the original
daemon job. They do not need the original profile, `pool.json`, checkout or
toolchain and cannot submit or select a replacement worker.

### Reuse worker-local Cargo target state

A reconnecting worker can opt into bounded private target reuse with
`--target-cache-bytes 1073741824` for a 1 GiB pool. Identical captured inputs and
compilation settings may seed the next execution's private target directory,
allowing Cargo to skip compilation it considers fresh. An exact invocation is
preferred; compatible `build`, `check`, `test --no-run` and `test` commands can
share a target when their other compilation settings match. Cargo still executes
each current request, including its selected tests and harness arguments.
Source, build-script, environment, toolchain, feature, or effective job-grant
changes start with a fresh target.

This pool survives coordinator reconnects within one worker process; it is
disabled by default and does not persist across worker restarts. See
[worker-local Cargo target state](rabs-target-state.md) for ownership, limits,
runtime assumptions, and the worker events that report actual reuse.

### Reuse verified artifact bytes on the coordinator

Enable an optional coordinator byte cache to avoid downloading identical artifact
files from the same authenticated worker on later builds. This complements the
worker's private target pool: Cargo still executes the current command, and the
coordinator receives its current result, Cargo report and complete diagnostics.
Every reused file is copied into the new delivery and hashed against that
current result's manifest before the ordinary receipt and acknowledgment path.

Create a private cache parent once, outside captured source/toolchain trees and
operation directories, then enable it on the process that owns worker delivery:

```sh
mkdir -m 700 "$HOME/.cache/rabs-artifact-cache"
RABS_ARTIFACT_CACHE_DIR="$HOME/.cache/rabs-artifact-cache" \
RABS_ARTIFACT_CACHE_BYTES=1073741824 \
RABS_ARTIFACT_CACHE_ENTRIES=4096 \
  cargo rabs --rabs-canonical /absolute/profile.json -- build --workspace
```

The example applies to direct TLS builds. For a profile with `daemon_socket`,
set these variables in the **daemon's environment before starting it**; the
job-submitting client does not change the running daemon's environment. The same
configuration also covers authenticated live dependency delivery and explicit
result resume. It does not enable reuse for the plaintext loopback fixture.

`RABS_ARTIFACT_CACHE_DIR` must name an existing absolute directory owned by the
current user with no group/other permissions; symlink ancestors are refused.
The receiver manages only its `artifact-bytes-v1` child. It does not create or
chmod the configured parent. Byte and entry limits default to 1 GiB and 4096;
their allowed ranges are 1–17,179,869,184 bytes and 1–65,536 entries. Both limits
cover all worker scopes in that cache, including a pending object. Values must
be decimal integers. Supplying either limit without the directory, or supplying
malformed settings, refuses before execution dispatch. With all three variables
absent, the cache is disabled.

A missing or unsafe cache directory produces one
`artifact-byte-cache-unavailable` setup diagnostic and uses ordinary verified
transfer. Missing or corrupt objects also take the ordinary range path; local
copy cancellation, deadline expiry and delivery-write errors remain failures.
Objects may survive coordinator restarts, but every hit is independently checked
and isolated by authenticated worker key and worker name. Diagnostics and test
outcomes are never replayed from this cache. See
[artifact byte reuse](rabs-worker-delivery.md#reuse-artifact-bytes-across-authenticated-deliveries)
for ownership and recovery details.

### Use dependencies already cached by Cargo

For a locked crates.io or supported pinned-Git graph, replace `vendor` with an explicit absolute
`cargo_home_source` in the profile:

```json
"cargo_home_source": "/home/builder/.cargo"
```

For crates.io packages, this selects the sparse registry cache. The native preparer reads
`Cargo.lock` from the captured workspace, selects the required `.crate` archives
and sparse index records, verifies archive SHA-256 values against that lockfile,
and checks archive paths and bounded unpacked contents before Cargo uses them.
It runs offline Cargo metadata against a fresh private Cargo home and verifies
the resolved graph against the retained inputs. The lockfile must remain
unchanged. Missing cache entries, checksum mismatches and unsupported registry
sources refuse preparation before remote execution.

Git dependencies may use a full or abbreviated `rev`, an explicit `branch` or
`tag`, or Cargo's default branch, provided `Cargo.lock` records the full
40-character lowercase resolved commit. The manifest selector remains part of
the exact source identity; only that locked commit selects the captured object
closure. Preparation and execution stay locked/offline, so moved remote or
cached refs cannot update the selected source. Literal reference names retain
their exact identity across Cargo's lockfile and metadata encodings, including
names containing `+`, `%`, `#` or `&`.

The approved Cargo home must already contain the complete locked object data
under `git/db`; a checkout alone is insufficient. The Linux preparing host needs
Git and `prlimit` available as local executables. This does not require those
tools on the worker: captured Cargo reconstructs its own private checkouts.

The preparer opens ordinary object files through retained descriptors, without
reading the original repository configuration or executing its hooks. It packs
only the selected commits and their complete trees and blobs into fresh minimal
databases, marks those commits as shallow roots, and verifies each generated
pack with Git. Unselected ancestor commits and unrelated repository history are
not transferred. Native Git helpers have a 2 GiB address-space limit, bounded
output and process-group deadlines; expanded registry and Git sources share the
existing source byte and file limits. The metadata probe checks each resolved
Git package's full locked identity, contained manifest and target paths, and the
bytes and executable modes of its checkout against the selected objects.

Credential-bearing URLs, object alternates, partial clones, Git submodules and
symlinks are outside this cached Git profile. Missing or unsupported inputs
refuse before remote execution.
Manifests, lockfiles and captured project configuration retain their original
bytes; no source replacement is synthesized for this mode.

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

A bundle containing reconstructed Git databases negotiates
`isolated-registry-git-cargo-home-v1`. Each database contains only generated
fixed configuration, detached HEAD, bounded shallow roots, a fixed generated
ref, and one verified pack/index pair. Both peers validate this distinct shape;
the worker checks the retained control bytes before constructing either private
view. Older endpoints refuse the new version before source upload. Registry-only
bundles keep their existing version and behavior.

`cargo_home_source` and `vendor` are mutually exclusive. The selected Cargo home
must have ordinary directory ancestors and be disjoint from the source,
toolchain and operation roots. The source anchor must not already contain the
reserved `rabs-cargo-home` directory. Alternate registries and Git graphs outside
the locked-commit cache profile still require the supported approved vendor
route. Cache capture does not authorize action
cache publication or a compiler skip.

### Captured compiler configuration

Captured project `.cargo/config` and `.cargo/config.toml` files may retain these
bounded compiler settings:

- `[build]` `rustflags` and `rustdocflags`;
- `[target.<triple>]` and `[target.'cfg(...)']` `rustflags`;
- `[llvm-cov]` `exclude`, retained as configuration metadata.

String and array spellings retain Cargo's own tokenization and merge semantics;
the captured configuration bytes are not rewritten. Supported compiler controls
include `--cfg`, `--check-cfg`, lint levels, `-g`, `-O`, scalar codegen settings
(`opt-level`, `debuginfo`, `debug-assertions`, `overflow-checks`, `embed-bitcode`,
`force-frame-pointers`, `codegen-units`, `panic`, `lto`, `strip`) and explicit
bounded `-Z threads` counts. Vendor source replacements can appear alongside
these settings in the existing validated vendor configuration.

Compiler/wrapper overrides, `[env]`, linkers, runners, output-directory settings,
response files and other compiler flags require additional input or execution
contracts and remain unsupported in this profile. User Cargo-home configuration
is still excluded. Preparation checks the retained configuration before invoking
Cargo; no broader source capture or hidden local execution is substituted.

## Supported command contract

The first command must be `build`, `check`, `clippy`, or `test`. For example:

```sh
cargo rabs --rabs-canonical PROFILE.json -- build --workspace
cargo rabs --rabs-canonical PROFILE.json -- check --workspace --all-targets
cargo rabs --rabs-canonical PROFILE.json -- clippy --workspace --all-targets --all-features -- -D warnings
cargo rabs --rabs-canonical PROFILE.json -- test --workspace --no-run
cargo rabs --rabs-canonical PROFILE.json -- test --workspace --no-fail-fast
cargo rabs --rabs-canonical PROFILE.json -- test --test integration selected::case -- --exact --nocapture
cargo rabs --rabs-canonical PROFILE.json -- test --doc
cargo rabs --rabs-canonical PROFILE.json -- build -p app --bin app --release
```

Cargo owns package and target selection, including its normal defaults when no
selection option is supplied. Supported selectors are `--workspace`,
`--package`/`-p`, `--exclude` (with `--workspace`), `--lib`, `--bins`, `--examples`,
`--tests`, `--benches`, `--all-targets`, and literal `--bin NAME`, `--example NAME`,
`--test NAME` or `--bench NAME`. `test --no-run` compiles and returns test
executables without executing them. Ordinary `test` preserves a single Cargo
test-name filter, `--no-fail-fast`, `--doc`, and the exact test-harness arguments
after `--`, including `--nocapture`, `--exact` and `--test-threads=1`. These
arguments are not interpreted as Cargo flags; required Cargo controls are
inserted before the delimiter. Cargo remains responsible for selection,
doctests, ignored tests, list/help modes and the final process exit. The captured
toolchain must contain `rustdoc` when the selected command needs it.

`clippy` supports the same package, target and feature selections, plus
`--no-deps`. After its `--` delimiter, it accepts bounded lint controls: `-A`,
`-W`, `-D`, `-F`, `--allow`, `--warn`, `--deny`, `--forbid`, `--force-warn`, and
`--cap-lints`. Short lint flags accept attached or separate names, including
names such as `clippy::bool_comparison`; long flags accept separate or `=value`
forms. Required locked/offline, output and JSON controls are inserted before the
delimiter. Source-fixing mode, response files, output paths and arbitrary compiler
flags are not admitted through this lint-only argument contract. A denied lint
retains Clippy's nonzero exit and verified diagnostics and cannot produce a
successful artifact result.

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
Custom profiles, target JSON, `--config`, unstable Cargo flags, `+toolchain`, `run`,
test-harness arguments on compilation-only commands, arguments other than the
supported lint controls after Clippy's delimiter, and unknown Cargo options
refuse before preparation. The selected toolchain also supplies local Cargo metadata probes; a
`cargo +nightly rabs` launcher selection does not override that explicit dataset.
Cargo is always locked/offline, without duplicating supplied flags.

The worker receives its existing clear-environment canonical base, with
`CARGO_INCREMENTAL=0`. **Ambient dispatcher RUSTFLAGS, Cargo configuration,
custom wrappers and other environment values are not copied into the worker
command.** The supported captured project configuration described above still
applies. This is an explicitly selected canonical build profile, not transparent
preservation of the dispatcher's execution environment. TLS credentials remain
local to the transport process. The worker retains ownership of its jobserver;
this frontend does not send the dispatcher's descriptor numbers to another host.
Tests execute under the same isolated network and read-only source namespace as
the build; their writes must use admitted output/home/temporary paths. The
profile does not claim equivalence to tests relying on the dispatcher's network,
credentials, mutable checkout or other ambient state.

The optional profile field `jobserver_grant` requests an integer from 1 to 4096
worker execution slots. It becomes native request intent; the launcher does not
inject `NUM_JOBS`, `--jobs` or dispatcher jobserver handles. When a worker uses a
shared host budget, choose a grant no larger than that budget. For example, a
host with eight shared slots can admit four Cargo roots requesting two slots
each. Each root owns its implicit slot and receives at most one transferable
jobserver token. The worker keeps that grant through process-group cleanup.

## Outputs, failure and recovery

The explicit `artifacts.cargo = "cargo-json-v1"` compilation contract and
`artifacts.cargo = "cargo-test-json-v1"` test-execution contract augment
`tree-files-v1`. Old endpoints reject the new test contract rather than treating
tests as compilation-only work. The launcher's `files` minimum is empty because it does not guess
hashed library, metadata, executable or target-triple paths. After Cargo exits
successfully and its writers have drained, the worker requires a complete
`compiler-artifact` / `build-finished` report with at least one ordinary target.
For test execution, `build-finished` ends only Cargo's compilation report. Later
stdout belongs to the test programs and is retained byte-for-byte, including
JSON-shaped records, binary bytes and unterminated lines. It cannot add outputs
or change the compilation report. **Only the native final Cargo exit status can
make the complete operation successful.** A passing compilation followed by a
test failure retains the failure and diagnostics without offering successful
artifacts. There is no test-result cache or inferred test-pass count.

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

The canonical launcher selects native `--replay-diagnostics`. **stdout contains
the exact verified Cargo/test stdout**, and the matching stderr bytes are replayed
to stderr. Test execution therefore produces Cargo JSON followed by ordinary
test output; stdout is not promised to be a pure JSON stream. The native
worker-build result report and launcher operation-location message go to stderr.
Replay happens after complete verified delivery, including on compiler/test
failure; this is not live output streaming. Both streams are verified and
retained privately before any replay. Their individual byte order is preserved;
no historical ordering between independently captured stdout/stderr is invented.
The complete diagnostics also remain in the delivery directory for recovery.
The native driver's exit code and signals remain observable through exec. The launcher adds
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
parsing also limits stdout to 64 MiB and each compilation-report line to 1 MiB,
before allocating an unbounded record. Test output after `build-finished` is
consumed under the total byte bound without imposing a JSON line limit. Non-JSON
procedural-macro stdout remains in diagnostics.
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
checks that a real compiler error cannot become a successful report. Further
real Cargo tests execute a selected integration test, preserve deliberately
JSON-shaped harness output, return a failing test's exit 101 despite successful
compilation, and execute a documentation example with rustdoc. The real Clippy
fixture uses captured toolchain companions with Rust tools absent from PATH,
checks warning-only success and denied-lint exit 101, and then checks a clean
workspace with all targets, all features and warnings denied. Its successful
reports are verified against the complete captured output inventory. Worker
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

The mixed-cache integration fixture adds a parented pinned Git repository with
two packages and a build script alongside registry dependencies. It poisons the
original Git configuration, refs, hooks and checkout, prepares through the
production API, and retires both original roots before a frozen Cargo build
against the projected inputs. It checks that the original lockfile is unchanged,
the expected application output is produced, the parent commit is absent from
the reconstructed database, and object alternates refuse before publication:

```sh
cargo test -p rabsd --test cargo_vendor_prepare \
  registry::cached_git_and_registry_sources_rebuild_offline_without_original_history_or_configuration \
  --locked -- --exact --nocapture
```

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
