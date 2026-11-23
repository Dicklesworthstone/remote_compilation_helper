# Canonical Cargo-driver builds through the installed toolset

`rabs-cargo --worker PROFILE.json -- build --workspace` connects ordinary
Cargo workspace builds to RABS's existing canonical worker path. The same path
supports `check`, `clippy`, `doc`, `test`, `run`, and `bench`, with Cargo selecting the
requested libraries, binaries, examples and test or benchmark executables.
`test --no-run` and `bench --no-run` compile without running those executables.
Execution commands run on the selected worker and return Cargo's final exit status:

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
   Cargo/program stdout and stderr. Native operation reports are written to stderr.
   A failing program keeps its nonzero status and diagnostics; it does not install a
   successful artifact result or retry locally.

This is the canonical **Cargo driver**, not a wrapper-only path rewrite. The
source remains `/__rabs/workspace`, the captured toolchain lives under
`/__rabs/toolchain`, and Cargo writes to `/__rabs/out/cargo` before any rustc unit
is planned. Existing worker output, cancellation, lease and recovery mechanisms
are reused. The existing scheduler, transport and artifact installer remain in
control of every operation.

**This remote profile is execution-only.** It does not publish an action-cache result,
serve a compiler, program or benchmark-result cache hit, distribute individual rustc units, enable the local dependency
lane, or share a cache across workers. It does not make an unsandboxed local
cache key equivalent to a canonical execution. Those remain separate integration
and qualification tasks. Unlike `--rabs-remote`, this path does not invoke RCH.

A separate [local canonical compilation profile](#local-canonical-builds-and-checks-with-dependency-caching)
connects captured Cargo checks and builds to the external-dependency cache, with
isolated worker execution for eligible Rust archives. Its commands and narrower
graph requirements are described below.

For clients on separate hosts,
[`cargo rabs --rabs-canonical-remote`](#submit-from-separate-hosts-to-the-shared-coordinator)
uploads captured inputs to one pinned, mutually authenticated coordinator. Cargo
runs at that coordinator, and eligible dependency compilations from independent
clients share its existing worker pool and action ownership. Each client receives
its own verified output tree. The native `rabsd --canonical-compile-remote`
entrypoint remains available for explicit one-off profiles.

## Native Cargo subcommand

The `rabs-cli` crate also builds a native `cargo-rabs` executable. Cargo discovers
it as `cargo rabs` when its installation directory is on `PATH`. It uses the
same Rust execution and recovery owners as `rabs-cargo` and `rabs-recover`.

```sh
cargo install --locked --path rabs-cli --profile wrapper-release \
  --bin cargo-rabs --bin rabs-cargo --bin rabs-recover

cargo rabs check --workspace
cargo rabs --rabs-no-start --rabs-require-daemon -- test --no-run
cargo rabs --rabs-remote -- build --release
cargo rabs --rabs-canonical-local LOCAL.json -- check --workspace
cargo rabs --rabs-canonical-remote REMOTE.json -- build --workspace
cargo rabs --rabs-canonical WORKER.json -- build --bin application
cargo rabs --rabs-recover /absolute/cargo-OPERATION
```

For an installation alongside the legacy launcher, add a separate `--root`
to `cargo install` and put that root's `bin` directory first on `PATH`.
Cargo's `--force` option explicitly replaces an existing executable instead.

This source installation requires the matching native helpers. Ordinary local
Cargo uses `rch-wkr`, selected by `CARGO_RABS_WORKER`, physical sibling or `PATH`;
cache preparation uses matching `rabs-wrap` and `rabsd`. Remote RCH mode uses
`rch`; canonical and recovery modes use `rabsd`. Explicit helper overrides keep
their existing validation and never silently select another executable.

No arguments selects ordinary local `build`. Cargo's injected `rabs` argument
is consumed once. Launcher options precede Cargo arguments; a launcher `--`
ends that option parsing, and Cargo's later `--` preserves program/test arguments
literally. Local execution preserves non-UTF-8 Unix arguments, inherited stdin,
jobserver descriptors, exit status and signals through one native exec chain.

`--rabs-no-start` only attaches to an already ready, authenticated daemon. A
missing or stale endpoint is left untouched. `--rabs-require-daemon` refuses
before Cargo starts when preparation cannot verify readiness; it can combine
with `--rabs-no-start`. Without the strict option, confirmed setup failure uses
ordinary Cargo. Unconfirmed cleanup never starts Cargo. These local-daemon
options cannot combine with remote or canonical modes.

The canonical aliases retain their established no-command defaults: `check` for
local/shared-coordinator profiles and `build` for a direct worker profile.
`--rabs-recover` performs the existing result-only recovery/wait using the saved
operation identity. It never submits another build. The standalone
`rabs-recover` command continues to default to inspection.

`install.sh --with-rabs` and `scripts/install-rabs` install the native
`cargo-rabs` in the same atomic generation as the other RABS executables. Source
builds select it from `wrapper-release`; bundles must contain a native executable
matching the other tools' architecture. Source-verified packaging checks its
compiled build identity alongside every other native tool. The bundle installer
still requires its existing installation interpreter; running `cargo rabs` uses
only the Rust frontend and native helpers. Installing the frontend does not
establish a fleet rollout, compiler-cache hit or performance result.

## Native canonical Cargo entry point

`rabs-cargo` is the Rust command-line entry point for ordinary local Cargo,
RCH remote execution, canonical worker execution, the local canonical driver
and the shared remote coordinator.

| Mode | Profile | Execution owner |
|---|---|---|
| `--cache` | None | Local Cargo with native cache preparation |
| `--rch` | None | RCH with worker-local cache preparation |
| `--worker` | `canonical-cargo-v1` | A pinned worker, or the existing daemon's worker pool |
| `--local` | `canonical-compile-local-v1` | Local canonical driver or its selected service |
| `--remote` | `canonical-compile-remote-v1` | Shared pinned-TLS coordinator |

The canonical modes expose `build`, `check`, `clippy`, `doc`, `test`, `run`, and
`bench`. Local and remote canonical profiles also support `nextest run`, as
described below. The local and shared-coordinator modes support explicitly closed or
captured file input for executing `run`/`test`/`bench`. Worker execution uses
closed stdin.

Build it from the same checkout as the native driver:

```sh
cargo build --locked --profile wrapper-release -p rabs-cli --bin rabs-cargo

target/wrapper-release/rabs-cargo --worker WORKER.json \
  --rabsd /absolute/path/to/rabsd -- build --workspace

target/wrapper-release/rabs-cargo --worker WORKER.json \
  --rabsd /absolute/path/to/rabsd --stdin-file fixtures/request.bin \
  -- run --bin application

target/wrapper-release/rabs-cargo --remote REMOTE.json \
  --rabsd /absolute/path/to/rabsd --stdin closed -- run --bin application

target/wrapper-release/rabs-cargo --remote REMOTE.json \
  --rabsd /absolute/path/to/rabsd --stdin-file fixtures/request.json \
  -- run --bin application -- --mode batch

target/wrapper-release/rabs-cargo --local LOCAL.json \
  --rabsd /absolute/path/to/rabsd -- check --workspace --all-targets
```

Select one canonical mode and profile. Cargo selectors follow the optional `--`
separator. `--worker` requires an explicit Cargo command because its profile
contains placement and input settings. For `--local` and `--remote`, an explicit
Cargo command replaces the saved command and selection; with no command, the
profile's command and selection remain in effect. Arguments after Cargo's own
`--` remain program or test arguments and are validated by the shared canonical
command contract.

### Run nextest with captured inputs

`rabs-cargo --local` and `--remote` accept `nextest run`. The captured toolchain
must contain an ordinary executable `bin/cargo-nextest` alongside `bin/cargo`
and `bin/rustc`. The runner is included in the toolchain identity and is never
discovered through the ambient `PATH`. A local profile's persistent service and
the pinned remote canonical coordinator use the same execution path.

```sh
rabs-cargo --local LOCAL.json -- nextest run --workspace
rabs-cargo --remote REMOTE.json -- nextest run -p core \
  --cargo-profile release --profile ci --test-threads 1 \
  -E 'test(roundtrip)' -- --exact
rabs-cargo --local LOCAL.json -- nextest run --lib --no-run
```

Compilation and runner options remain distinct:

| Intent | Command-line option | Profile selection field |
|---|---|---|
| Cargo compilation profile | `--cargo-profile NAME` or `--release` | `profile` or `release` |
| Nextest configuration profile | `--profile NAME` | `runner_profile` |
| Explicit test concurrency | `--test-threads N`, `--jobs N`, or `-jN` | `test_threads` |
| Nextest filter expressions | Repeated `--filterset EXPR` or `-E EXPR` | `filtersets` |
| One optional test-name filter | Positional filter | `test_filter` |
| Emulated test-harness arguments | Arguments after `--` | `test_args` |

The profile's `jobs` supplies nextest's independent `--build-jobs`; it is never
passed as nextest's `--jobs`, which controls test concurrency. Omitting
`test_threads` preserves nextest's project configuration, including serial test
profiles. Explicit thread counts are bounded positive integers from 1 to 4096.
Package, feature and target-kind selectors retain the shared canonical command
bounds; nextest accepts at most one built-in compilation target. Doctests are
not part of this command: use the existing `test --doc` path for them.

The nonexecuting graph query uses captured Cargo `test --no-run` with the same
compilation selectors. Runner profiles, filters, thread counts and harness
arguments never narrow that graph or consume the driver's planning controls.
The actual operation then executes captured nextest with its normal output and
current exit status. It does not request Cargo's `--message-format=json` from
nextest or interpret nextest results as Cargo artifact announcements.

Every requested test run executes afresh, including after private target reuse.
Tests, setup scripts and test-pass results receive no action-cache authority;
the existing isolated dependency-compilation boundary still applies. The
complete captured source and toolchain, including nextest itself, remain part
of private target identity. `--no-run` compiles without running test bodies and
delivers the completed target tree. Nextest defaults to closed stdin; executing
tests may use the existing captured-input policy. Compilation-only requests
cannot inherit or capture stdin.

The direct `--worker` frontend rejects nextest before preparing an operation:
its separate Cargo JSON artifact-delivery contract does not yet support this
runner. Use `--local` or `--remote`. `nextest list`, arbitrary configuration
overrides, user-selected manifests/output roots and machine-output overrides
are outside this bounded frontend.

### Input and toolchain selection

`--stdin closed` selects EOF. `--stdin-file RELATIVE` selects an ordinary input
file within the approved `source_root`; the native driver captures it with the
source and delivers the captured bytes to the executing program or test harness.
A stdin override replaces either saved stdin policy. Remote operations and local
service submissions require explicit closed or captured file input for `run`
and executing `bench`; `test` defaults to EOF and also accepts captured input.
`--stdin inherit` is available for direct local `run`, executing `test`, and
executing `bench`, subject to the driver's noninteractive-input rules.
`--worker` defaults to EOF and also accepts `--stdin-file` for `run`, executing
`test`, and executing `bench`, with a **16 MiB** input limit. This works with a
direct worker, a daemon-owned worker, or an ordered worker pool. The file must be
an ordinary, nonsymlink member of the approved `source_root`; paths are relative
to that root even when the Cargo manifest is in a subdirectory. The worker
receives the exact snapshot bytes through an immutable descriptor, including
empty files and binary input. Worker capability `source-file-stdin-v1` is checked
before upload or execution; older workers refuse this request. Inherited input
and captured input for compilation-only commands or `--no-run` are refused.
Recovery retains the original source identity and input selection and never executes the
command again to reproduce its input or result.

The profile selects exactly one of an explicit physical `toolchain_root` or
`"toolchain": "rustup"`. The Rustup option resolves the installed compiler in the
caller's original working directory and environment, honoring `RUSTUP_TOOLCHAIN`
and Rustup's directory overrides and toolchain files. A leading `+toolchain`
before the Cargo command overrides that selection:

```sh
rabs-cargo --remote REMOTE.json -- +nightly-2026-08-31 build --workspace
```

The selector requires a `"toolchain": "rustup"` profile and a following Cargo
command; arguments such as `run -- +nightly` remain literal program arguments.
`CARGO_RABS_RUSTUP` may select the discovery executable, otherwise the caller's
`PATH` selects it. Discovery disables automatic installation, has a five-second
deadline and a bounded path response, and reaps its supervised child. Returned
toolchain ancestors must be ordinary directories, with ordinary executable
`bin/cargo` and `bin/rustc` files. Only the resolved `toolchain_root` reaches the
retained native profile; the backend does not rediscover Rustup. The existing
backend still performs source, toolchain, environment, namespace, authentication,
and output validation.

The command resolves `rabsd` beside its own physical executable, or uses an
explicit `--rabsd PATH` or `CARGO_RABS_DAEMON` setting. It retains a private
operation profile before handing off once to that driver. Cargo's exit status
and process signals pass through the handoff; an execution failure does not
start a local fallback or another build. Remote profiles may use a private
`output_root` to allocate a fresh, absent output destination for each invocation.
An explicit existing `output_destination` is refused.

This executable can also be installed independently with
`cargo install --locked --path rabs-cli --bin rabs-cargo`; select the matching
driver explicitly when it is installed elsewhere. This source-build command
does not establish that a published release bundle contains the executable.

### Direct workers and durable worker-pool jobs

The native `--worker` mode accepts the existing `canonical-cargo-v1` profile
described in [Profile and prerequisites](#profile-and-prerequisites). It supports
the same literal worker endpoint and certificate pin, source root, toolchain,
manifest, vendored or captured dependencies, source-selection policy,
`jobserver_grant`, explicit environment and private incremental setting. The
existing `cargo rabs --rabs-canonical` launcher accepts this profile as well.

With `daemon_socket`, the native frontend submits one durable job to the
existing daemon. An ordered `workers` array selects the existing pool placement
path and requires that socket. `live_stderr` is available for both daemon-owned
jobs and direct pinned TLS worker builds.
The frontend retains `spec.json`, `operation.json` and, for a pool, `pool.json`
under a fresh private operation directory. Allocation intent stays
`request_id: "allocate"` until the native execution owner assigns the request.
Client TLS credentials remain in the process environment; they are not copied
into the Cargo environment or retained submission records.

The frontend hands off once to `rabsd --worker-build-tls --prepare-from` or
`rabsd --job-build --prepare-from`. Source capture, worker admission, mutual TLS,
process supervision and verified output delivery remain in those native owners.
A failed or interrupted handoff retains its operation and never starts another
build. The reported operation directory can be passed directly to the native
recovery command. For a daemon-owned job:

```sh
rabs-recover /data/rabs-operations/cargo-JOB_ID
rabs-recover --status /data/rabs-operations/cargo-JOB_ID
rabs-recover --wait /data/rabs-operations/cargo-JOB_ID
```

Inspection and daemon job controls use the retained identity without the
original profile, source tree or toolchain. Direct worker recovery additionally
requires the prepared `bundle/request.json` and its original admission state;
allocation intent alone cannot authorize result retrieval. See
[Outputs, failure and recovery](#outputs-failure-and-recovery) for the result-only
resume and acknowledgment rules. Native process tests exercise the producer and
recovery records together with explicit driver fixtures; they do not establish
live worker execution, TLS interoperability or a performance improvement.

### Ordinary local Cargo with native cache preparation

The profile-free `--cache` mode uses the same bounded native preparation owner
as the RCH worker adapter:

```sh
rabs-cargo --cache -- check --workspace
rabs-cargo --cache -- +nightly test -- --nocapture
CARGO_RABS_WORKER=/absolute/rch-wkr rabs-cargo --cache -- build --release
```

This Linux mode requires matching `rch-wkr`, `rabs-wrap` and `rabsd` executables.
The frontend selects `rch-wkr` from `CARGO_RABS_WORKER`, its own physical sibling
directory, or PATH, in that order. It selects Cargo from the literal `CARGO`
override or PATH and preserves its final symlink spelling for Rustup proxies.
With no Cargo arguments it selects `build`. It creates no canonical profile,
changes no working directory, and preserves opaque Unix arguments, stdin,
environment, exit status, signals and inherited jobserver descriptors.

There is one handoff to `rch-wkr worker-cache --protocol v1 -- CARGO ...`.
That existing native owner prepares or attaches to the local daemon, verifies
its readiness and execs Cargo once. It honors `CARGO_RABS_WRAP`,
`CARGO_RABS_DAEMON`, state/socket/startup settings and explicit wrapper opt-outs.
A confirmed setup failure can run stock Cargo; an uncertain setup cleanup
cannot. Missing or incompatible `rch-wkr` refuses before Cargo starts. The
frontend never retries a compiler or silently selects a different helper after
an explicit executable override fails.

If `CARGO_RABS_ROOT_BUDGET_DIR`, `CARGO_RABS_ROOT_CAPACITY` and
`CARGO_RABS_ROOT_CGROUP` request local root admission, all three must be present
and no root may already be active. The execution chain includes the existing
`rabs-cargo-root` owner, selected by `CARGO_RABS_ROOT_HELPER` or sibling/PATH.
That owner validates the capacity, delegated cgroup and durable budget before
starting Cargo. Cache setup failure never bypasses requested admission.

Readiness does not authorize a cache hit: the existing wrapper, coordinator,
input closure, publication, sampling and serving rules still decide each
compiler action. This mode performs local builds and retains ordinary Cargo
paths. For RCH remote execution with worker-local preparation, use the separate
[`rabs-cargo --rch` mode](rabs-rch-worker-cache.md#direct-cargo-entry-point).
Native frontend tests exercise real process handoff with explicit helper
fixtures; compiler reuse and fleet performance require their own qualification.

## Profile and prerequisites

Linux is required on the preparing host and worker. Install matching `rabs-cargo`
and `rabsd` on the preparing host and `rabs-wkr` on the worker. The native toolchain
directory must contain ordinary executable `bin/cargo` and `bin/rustc` plus the
runtime/sysroot files required by the existing toolchain capture contract. Rustup
shims or symlinks are not a substitute for a complete toolchain dataset.
For `clippy`, that same captured dataset must also contain ordinary executable
`bin/cargo-clippy` and `bin/clippy-driver`. The launcher invokes the captured
Clippy program directly and binds its Cargo and rustc companions to the captured
absolute paths, so dispatcher or worker PATH entries cannot select a different
Clippy installation.
For `doc`, the captured dataset also requires ordinary executable `bin/rustdoc`.
Both `RUSTDOC` and `RUSTC` are bound to that dataset's canonical executables.

For an installed Rustup toolchain, any canonical **launcher** profile can
replace `"toolchain_root": "/absolute/toolchain"` with `"toolchain": "rustup"`.
Specify exactly one of these fields. `cargo rabs --rabs-canonical ...`,
`cargo rabs --rabs-canonical-local ...` and
`cargo rabs --rabs-canonical-remote ...` resolve `rustup which rustc` once in the
caller's original working directory and environment. This honors the selected
`RUSTUP_TOOLCHAIN`, including `cargo +nightly rabs`, and Rustup's directory
overrides and toolchain files at the invocation location. It does not select a
different toolchain from the profile directory or captured `source_root`.

With a `"toolchain": "rustup"` profile, a leading `+toolchain` before the Cargo
command selects that installed toolchain explicitly:

```sh
cargo rabs --rabs-canonical PROFILE.json -- +nightly-2026-08-31 build --workspace
cargo rabs --rabs-canonical-local LOCAL.json -- +nightly-2026-08-31 check --workspace
cargo rabs --rabs-canonical-remote REMOTE.json -- +nightly-2026-08-31 build --workspace
```

The launcher passes this selection to `rustup which --toolchain NAME rustc` in
the original working directory. It takes precedence over `RUSTUP_TOOLCHAIN`,
directory overrides and toolchain files without modifying the caller's
environment. The selector is consumed before the captured Cargo runs. Exactly
one nonempty UTF-8 selector of at most 1024 bytes is accepted, without whitespace
or control characters; Rustup validates the installed toolchain name. A selector
requires a following Cargo command and conflicts with an explicit
`toolchain_root` profile. Either conflict refuses before discovery or operation
creation. Arguments such as `run -- +nightly` remain literal program arguments.

Discovery uses `RUSTUP_AUTO_INSTALL=0`, has a five-second deadline and a bounded
path response, and requires an already installed toolchain with ordinary
`bin/cargo` and `bin/rustc` executables. Symlinked toolchain ancestors and
non-regular compiler paths are refused. `CARGO_RABS_RUSTUP` can name the installed
Rustup executable; otherwise it is found on the caller's `PATH`. The caller's environment is not
modified by discovery. The native driver then captures and verifies the full
physical toolchain through the existing preparation contract.

Only that resolved `toolchain_root` is retained in the native profile or request.
Queued work, execution and recovery do not rediscover Rustup. Direct native
`rabsd --canonical-compile-local` profiles still require `toolchain_root`; the
`toolchain` selector is a launcher input. The ordinary live wrapper and
`--rabs-remote` retain their existing toolchain behavior.

Worker capability probing executes a no-op inside the same canonical base
namespace used for builds, including private `/proc`, `/dev`, temporary storage
and isolated networking. An installed bubblewrap and a successful basic user/PID
namespace smoke test are insufficient. A host that cannot construct the complete
base namespace does not advertise canonical execution or receive those builds;
the worker does not substitute a broader mount view or weaker isolation.

ELF runtime discovery requires GNU Coreutils `timeout`. The probe prefers
`/usr/bin/gnutimeout` when installed, otherwise it checks `/usr/bin/timeout`;
a different implementation is refused explicitly. The independent watchdog
survives an abrupt owner death, while native supervision also bounds both
output streams and group cleanup. Capability discovery and loader execution
share the existing five-second budget. This does not change host utilities.

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

Preparation follows the selected workspace and its resolved local dependency
paths when validating Cargo control files. A repository can contain unrelated
workspaces, deliberately invalid manifest/lockfile fixtures, and inactive nested
Cargo configurations without those files preventing a build. They remain in the
complete captured source tree, byte for byte. Selecting one of those manifests
or reaching it through an active dependency makes its declarations subject to
the normal checks. Workspace inheritance, automatic path members, optional and
target-specific dependencies, and member development dependencies are included;
foreign workspaces contribute only the inheritance and dependencies Cargo uses.
Only the selected workspace's lockfile and configurations on the invocation's
ancestor chain govern preparation. Workspace globs followed by `..` are refused
because Cargo expands the glob before traversing the parent; ordinary contained
`../sibling` paths remain supported.

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

To see stderr progress while a canonical worker build runs, add this
Boolean field to its profile:

```json
"live_stderr": true
```

The launcher selects `rabsd --job-build --live-stderr --prepare-from ...` for
daemon-owned jobs, or `rabsd --worker-build-tls --replay-diagnostics --live-stderr
--prepare-from ...` for a direct worker. The native client displays a contiguous
stderr prefix in bounded chunks, then verifies the bytes already shown against
the final transcript before printing the remaining stderr. A gap in the live
preview stops early presentation; the verified result supplies the unseen
suffix. **Stdout remains behind verified completion and artifact installation**,
because Cargo's stdout can announce artifact readiness. Early diagnostics do not
establish build success or authorize another execution.

On Linux, waiting, following and replaying clients use bounded writes to pipes,
sockets and terminals without changing the caller's descriptor flags. Their
requested wait deadline also bounds live output. Once a terminal job is observed,
verification and final replay share at most five further minutes inside that
original deadline. A stalled consumer or partial write exits with an error and
never restarts the build; the durable job remains available under the same ID.
Failure reporting has its own short bound so a full stderr pipe cannot trap the
client a second time. Regular-file writes retain their original offset and
append semantics; kernel-blocked filesystem operations are not a hard real-time
deadline guarantee.

`live_stderr` accepts only `true` or `false`. Local canonical profiles refuse
this field before preparation. Omission or `false` retains ordinary
completed-result replay. The selected mode is presentation
intent in `operation.json`; it is not copied into the worker command, its
environment or the Cargo artifact contract. An older daemon without the native
whole-Cargo diagnostics capability refuses an explicit live request.

A direct live client owns its execution thread until completion. The transport
only updates fixed-size preview buffers; console writes cannot stall pipe
draining, lease renewal or result delivery. A signal, console failure or elapsed
presentation deadline requests cancellation and joins the normal authenticated
cleanup without launching another build. Its retained delivery remains available
for explicit recovery. Both direct and daemon clients verify the exact stderr
prefix before exposing final stdout or the remaining stderr.
Direct `--live-stderr` currently requires a Linux client for bounded console
writes and cancellation. Other client platforms refuse it before preparation
or dispatch; their ordinary completed-result mode remains available.

The ordinary recovery frontend also recognizes a saved daemon operation:

```sh
cargo rabs --rabs-recover /home/builder/.cache/rch/operations/cargo-JOB_ID
```

It uses the saved job ID and private daemon socket to invoke `--job-wait` once,
including `--live-stderr` when the retained operation requested it. Recovery
validates the saved mode against the fixed wait command and reconstructs the
invocation using the installed driver. Status, cancellation and result-control
commands keep their existing semantics and do not implicitly wait or show a
diagnostic stream.
The original profile, checkout, toolchain and captured bundle are not needed for
this read-only wait/replay path. It does not resubmit the job. For a daemon-owned
operation, `--status` and `--cancel` also address that same job. Result controls
`--resume-to NEW_DELIVERY [--prefix-from PREFIX]`, `--delivery DELIVERY`, and
`--acknowledge DELIVERY` hand off to the daemon's existing result-resume, local
recovery, and release commands. They preserve its selected worker and request
identity. Wait on the original job afterward to replay a verified compiler
result.

The installed native `rabs-recover` command also accepts these daemon-owned
operation directories. Its default is offline inspection of retained intent;
select `--wait` explicitly to contact the owner and replay a verified result:

```sh
rabs-recover /home/builder/.cache/rch/operations/cargo-JOB_ID
rabs-recover /home/builder/.cache/rch/operations/cargo-JOB_ID --status
rabs-recover /home/builder/.cache/rch/operations/cargo-JOB_ID --wait
rabs-recover /home/builder/.cache/rch/operations/cargo-JOB_ID --cancel
```

Native inspection reports that outputs have not been verified and does not
require a running daemon. Active controls use the job ID and private socket
retained in `operation.json`, including the saved live-stderr preference for
`--wait`. They reconstruct one invocation of the selected or installed sibling
`rabsd`; saved command strings are validated as intent and never executed. The
original source tree, profile, toolchain and bundle can be unavailable. Client
TLS credentials are unnecessary because the existing daemon owns the worker
connection and numeric request identity.

The native result controls are:

```sh
rabs-recover /home/builder/.cache/rch/operations/cargo-JOB_ID \
    --resume-to /home/builder/recovered-delivery
rabs-recover /home/builder/.cache/rch/operations/cargo-JOB_ID \
    --resume-to /home/builder/resumed-delivery --prefix-from /home/builder/partial-delivery
rabs-recover /home/builder/.cache/rch/operations/cargo-JOB_ID \
    --delivery /home/builder/complete-delivery
rabs-recover /home/builder/.cache/rch/operations/cargo-JOB_ID \
    --acknowledge /home/builder/complete-delivery
```

Choose one control or result destination per invocation. A daemon-job resume
uses a fresh destination and forwards partial bytes only when `--prefix-from`
is explicit; `--no-prefix` also selects a fresh download. The daemon remains
responsible for verifying every result and deciding whether a retained delivery
can be reconciled or acknowledged. Status, cancellation and result controls
return the native control status; use `--wait` afterward for the verified
compiler exit code and diagnostics. Cancellation admission does not prove that
worker teardown has finished. None of these commands submits a new job, reads
the allocation template as a numeric request, or retries execution after a lost
reply. Direct-worker recovery keeps its existing TLS, original admission-state
and partial-delivery requirements.

Each later explicit recovery or `rabsd --job-wait --live-stderr JOB_ID` starts a
new presentation cursor and may replay the whole retained diagnostic transcript.
There is no durable console-position checkpoint across client processes.
Within one waiting invocation, the native client retains its already displayed
stderr prefix through result-only recovery and prints the verified suffix once.
A lost or failed wait never causes the launcher to fall back to local compilation
or submit another execution.

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

The daemon runs up to four prepared jobs at once by default. Set
`[rabs] prepared_concurrency = 16` in its configuration, or start it with
`RABS_PREPARED_CONCURRENCY=16`, to use more independent workers concurrently.
The limit accepts 1–32 and takes effect on daemon restart. It governs executor
threads, job admission and local result recovery together. Per-worker ownership
and the bounded queue still apply; listing 32 workers does not itself allocate
32 executors. See [prepared builds in the running daemon](rabs-worker-delivery.md#prepared-builds-in-the-running-daemon)
for configuration and status details.

The daemon first chooses by durable job load. Among equally loaded workers it
prefers a worker that completed the exact captured Cargo request, then one that
completed a compatible command or source generation. Within each match class,
the most recently admitted matching job wins; the listed order breaks remaining
ties. A source edit can therefore return to a worker holding the preceding build's
private target and incremental state, while a less loaded worker still takes
priority.

Compatibility uses the same source and command planner as the worker's
[private target cache](rabs-target-state.md). Ordinary non-executable local
source and data edits, additions, removals and renames may retain affinity.
Cargo `build`, `check`, `test`, `run` and `bench` can share it across package
and target selections. Clippy remains a separate family with exact selectors
and lint controls. Cargo manifests, lockfiles, configuration, executable inputs,
vendored packages and captured Cargo-home cache contents remain exact, as do
the toolchain, environment, compilation profile, target, features, job grant,
output location, required artifacts, private-state projection and other request
controls. Unknown argument forms retain only
exact-request preference. Legacy visible-prefix Cargo-home projections retain
exact-source preference.

Profiles still partition that hint: an ordinary `build` and `run` use debug,
whereas ordinary `bench` uses release. `build --release` can prepare the release
family for a later `bench`; benchmark filters and program arguments do not change
compilation compatibility. Every requested program still executes. Pool affinity
does not establish comparable benchmark hardware or load; select a fixed worker
and control its runtime conditions when comparing measurements.

A hint requires the same configured endpoint, worker identity and certificate
pin. Resolved ordinary failures can also leave useful state; cancelled, stopped,
unresolved and never-dispatched jobs cannot supply a hint. History is limited
to the last 128 queue admissions in the bounded durable live record set; cold
archives do not contribute. Reloading those records after a coordinator restart
can preserve affinity. A worker restart, eviction, disabled target cache or
changed runtime epoch may still leave that worker cold. The worker independently
verifies its retained state and executes the original Cargo command, including
tests; placement alone never authorizes reuse or a compiler skip. The captured
request, source identity and recovery identity remain exact and unchanged.

Workers whose previous execution remains unresolved are excluded. Selection
and the original pool intent become
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
`--target-cache-bytes 1073741824` or `RABS_WORKER_TARGET_CACHE_BYTES=1073741824`
for a 1 GiB pool. Identical captured inputs and
compilation settings may seed the next execution's private target directory,
allowing Cargo to skip compilation it considers fresh. An exact invocation is
preferred; compatible `build`, `check`, `test`, `run` and `bench` commands can
share a target when their other compilation settings match. Cargo still executes
each current request, including its selected programs and runtime arguments.
Ordinary local source and data edits can retain compiler metadata from an
eligible check. The complete retained target must contain only metadata,
dep-info and recognized Cargo bookkeeping. Changed inputs and their surviving
ancestor directories receive timestamps newer than the retained target, and
Cargo applies its own freshness checks. A target containing archives, object
files, executables, generated outputs or incremental state requires the complete
source capture to remain identical. Procedural macros, build scripts and the
integrated assembler can read files that Cargo does not track; retiming those
files cannot make a previously compiled consumer stale. Compiler injection,
captured Cargo configuration and ambiguous manifest controls also disable
source-edit reuse. Manifests, lockfiles, immutable dependency sources,
environment, toolchain and effective job-grant changes select a different
target family. An older eligible metadata seed can still be selected when a
newer codegen seed cannot be reused after an edit.

A completed ordinary compiler, test, run or benchmark failure can also retain its private
target after verified process cleanup. The next request executes Cargo again
and returns its own outcome; a failing program is never converted into a cache hit
or a successful artifact delivery. Cancellation, uncertain cleanup, native
launcher signal termination and unsafe partial trees cannot publish reusable
target state.

The pool is disabled by default. With only a byte limit it survives coordinator
reconnects within one worker process. To preserve completed seeds across worker
restarts on a stable host runtime, also set `RABS_WORKER_TARGET_CACHE_EPOCH` or
`--target-cache-epoch` to an operator-managed version label. Stop the worker and
change this epoch before updating host tools, system libraries or other runtime
inputs; a restart alone does not invalidate durable seeds. Managed fleet
deployment accepts and preserves these settings. See
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

For a locked crates.io, public sparse alternate-registry or supported pinned-Git
graph, replace `vendor` with an explicit absolute `cargo_home_source` in the
profile:

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

Public alternate registries use the same archive and sparse-index capture path.
Keep each named registry declaration in the captured project configuration:

```toml
# .cargo/config.toml
[registries.company]
index = "sparse+https://registry.example/team/"
```

```toml
# Cargo.toml
[dependencies]
company-library = { version = "1.2", registry = "company" }
```

The index must use `sparse+http://` or `sparse+https://`, an ordinary lowercase
DNS or IPv4 host, an optional nonzero port and a trailing slash. Registry URLs
cannot contain credentials, queries, fragments, escapes or traversal. Each
`[registries.<name>]` table accepts only `index`; source replacement tables,
credential providers and tokens are not admitted by this cache mode. Index
`config.json` must describe public HTTP(S) download/API endpoints and cannot set
`auth-required = true`. Standard Cargo download URL templates are preserved.
At most eight matching sparse cache namespaces are captured per preparation.
Archive candidates are read and hashed once per cache path and share a 512 MiB
acquisition limit, including archives rejected by checksum comparison. Exceeding
that limit refuses preparation even if the selected archives would fit. The
retained source/cache bytes and decompressed archives keep their separate limits.

Registry source, package name, version and lockfile checksum remain separate
parts of the selection. Two registries on the same host may publish distinct
archives for the same name and version; preparation keeps both and offline
Cargo selects the exact URL-derived namespace. The resolved source, manifest
and target bytes must match their captured locked archive. A named registry is
never silently redirected to crates.io or a different alternate registry.

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

Pinned Git submodules are included recursively from the exact gitlinks and
committed `.gitmodules` blobs in the selected trees. The approved Cargo home
must contain every child commit in its Git databases; mutable checkouts, their
current revisions and local `.gitmodules` edits are not source inputs. Cargo
resolves each original absolute or relative submodule URL offline from the
captured databases, and the preparer verifies the complete nested checkout
against the selected blob hashes and executable modes. Changing a selected
submodule pin changes the captured source identity.

Submodule declarations require confined relative paths and ordinary URLs
without credentials. Configuration includes, command-valued updates and
settings that skip the pinned checkout are refused. Capture admits at most 64
selected databases and distinct commit revisions, with at most 16 nested
submodule levels; the expanded files also share the existing source limits.
Missing child objects fail preparation without fetching or using checkout
contents as a substitute.

Credential-bearing URLs, object alternates, partial clones and symlinks remain
outside this cached Git profile. Missing or unsupported inputs refuse before
remote execution.
Manifests, lockfiles and captured project configuration retain their original
bytes; no source replacement is synthesized for this mode.

By default, the cache must contain the locked graph, including optional and
target-specific dependencies needed by the planner's `--all-features` metadata
check. A successful
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
reserved `rabs-cargo-home` directory. Git-index alternate registries,
authentication-dependent indexes, source replacement configurations and Git
graphs outside the locked-commit cache profile still require the supported
approved vendor route. Cache capture does not authorize action
cache publication or a compiler skip.

### Prepare the selected Cargo dependency graph

For `build`, `check`, `clippy`, `doc`, `test`, `run` and `bench`, a `canonical-cargo-v1` launcher profile can opt into
command-specific dependency preparation with this field:

```json
"source_selection": "cargo-unit-graph-v1"
```

This mode accepts local source anchors and an approved `cargo_home_source`.
It cannot be combined with `vendor`; existing vendor profiles continue to use
the default preparer.

The launcher passes that local intent as `cargo_source.selection`. The native
preparer binds it to the actual validated Cargo request and asks the captured
Cargo for its nonexecuting `--unit-graph -Z unstable-options` plan. Package,
feature, target and profile selection must describe the command that the worker
will run. Planning includes selected host build dependencies and procedural
macros as well as target units; a target-filtered metadata result alone is not
the dependency closure.

Test and benchmark planning preserves the selected targets, name filter,
`--no-run`, `--doc` and `--no-fail-fast` where applicable. Harness and program
arguments after `--` stay in the original execution request and are never
passed to the graph query. Planning does not compile or run build scripts,
tests, benchmarks or the requested program. For `run`, captured Cargo metadata
and, when needed, `cargo pkgid` resolve the exact default binary; named binaries
and examples retain their explicit selectors. The preparer queries a build
graph for that one target because Cargo's run command may look for an executable
even during graph-only planning. The worker still receives the original `run`
command and its literal arguments. Ambiguous default binaries are refused.

Clippy planning runs the captured `cargo-clippy` with its captured `cargo` and
`rustc`, and requires the ordinary executable `clippy-driver` companion from
the same toolchain image. It preserves `--no-deps` and the validated lint-level
arguments after `--`; the preparer inserts every locked/offline and unit-graph
control before that lint tail. `--no-deps` changes linting, not dependency input
requirements: selected ordinary dependencies, build scripts and procedural
macros still need their complete sources. A missing companion or an unsupported
lint argument refuses preparation before Cargo planning. Neither graph planning
nor a selected source archive is permission to reuse a Clippy result.

Documentation planning preserves `--no-deps` and `--document-private-items` and
requires captured rustdoc and rustc. The selected roots must be Cargo `doc`
units; required dependency `check`/`build` units and project executors remain
in the graph. `--no-deps` omits dependency documentation, not the compiler
inputs needed to document the selected packages.

Planning and execution use the same validated literal application environment.
Overrides of Cargo, Rustup, compiler, loader, Git or RABS control variables are
refused, apart from the existing explicit `CARGO_INCREMENTAL` control and
Clippy's exact launcher-supplied canonical `CARGO`/`RUSTC` bindings and Doc's
canonical `RUSTDOC`/`RUSTC` bindings. These
are rebound only to their captured physical siblings during local planning;
profile environment settings cannot replace them. The canonical Cargo or Clippy
program and the selected manifest's parent working directory must agree with the
launcher request. Remote canonical requests sent directly to `rabsd` have the
same requirements. Captured compiler flags must also be independent of the planning
machine: `-C target-cpu=native` is refused in this mode because it can change
conditional dependency selection on a worker with different hardware. Explicit
CPU and target-feature settings remain supported.

With `cargo_home_source`, absent sparse-registry archives are permitted only
when Cargo does not select those packages. For example, a disabled optional
dependency or a Windows-only dependency need not be downloaded for a Linux
check that does not use it. Locked sparse-index records remain required, and
every selected package must resolve to retained, verified source bytes. A
missing selected archive, changed checksum, unsupported graph or unsupported
command refuses preparation. The preparer does not fetch missing inputs or
fall back to a different selection. Pinned Git capture retains its existing
complete locked-revision contract. Selected Git packages also require an
unambiguous source selector and one retained manifest for each package name in
the selected commit; duplicate same-name manifests are refused.

This option still captures the complete approved source anchor and retains its
original manifests, lockfile and configuration. It changes dependency
preparation, not the worker's artifact or cache-authority contract. Profiles
without `source_selection` keep the existing complete-graph preparation.
Clippy retains its full captured source identity and separate private target
families, including the ordered lint controls. This option does not relax its
freshness or cache-authority boundary.

### Captured compiler configuration

Captured project `.cargo/config` and `.cargo/config.toml` files may retain these
bounded compiler settings:

- `[build]` `rustflags` and `rustdocflags`;
- `[target.<triple>]` and `[target.'cfg(...)']` `rustflags`;
- `[profile.<name>]` scalar settings, inheritance, package overrides and build overrides;
- `[llvm-cov]` `exclude`, retained as configuration metadata.

String and array spellings retain Cargo's own tokenization and merge semantics;
the captured configuration bytes are not rewritten. Supported compiler controls
include `--cfg`, `--check-cfg`, lint levels, `-g`, `-O`, scalar codegen settings
(`opt-level`, `debuginfo`, `debug-assertions`, `overflow-checks`, `embed-bitcode`,
`force-frame-pointers`, `force-unwind-tables`, `codegen-units`, `panic`, `lto`,
`strip`, `split-debuginfo`, `code-model`, `relocation-model`, `target-cpu` and
signed `target-feature` lists) and explicit bounded `-Z threads` counts.
CPU and feature names are preserved literally; the worker's compiler decides
whether they are supported. `target-cpu=native` selects the executing worker's
CPU. This does not authorize a cross-machine action-cache hit. Vendor source
replacements can appear alongside these settings in the existing validated
vendor configuration.

Captured profiles support `inherits`, `opt-level`, `debug`, `split-debuginfo`,
`strip`, `debug-assertions`, `overflow-checks`, `lto`, `panic`, `codegen-units`,
`rpath`, and Boolean `incremental` settings. The launcher's explicit incremental
policy supplies `CARGO_INCREMENTAL`, which takes precedence over these captured
profile settings: the default is `0`, and the opt-in below selects `1`.
Package and build overrides support the applicable scalar settings; nested
overrides, inheritance within an override, and override `lto`, `panic` or `rpath`
are refused. Configuration accepts up to 64 profiles and 128 package selectors
per profile. Cargo owns inheritance, package matching, configuration precedence
and its normal errors for invalid combinations; the source planner retains the
exact project configuration bytes.

Captured `[env]` settings also retain their existing default, `force` and bounded
config-relative semantics; see [captured environment](rabs-canonical-environment.md).
Compiler/wrapper overrides, linkers, runners, output-directory settings,
response files and other compiler flags require additional input or execution
contracts and remain unsupported in this profile. User Cargo-home configuration
is still excluded. Preparation checks the retained configuration before invoking
Cargo; no broader source capture or hidden local execution is substituted.

### Private incremental compilation

To retain rustc's incremental work products between builds on the same worker,
add this Boolean field to the canonical JSON profile:

```json
"incremental": true
```

The launcher supplies `CARGO_INCREMENTAL=1` for `build`, `check`, `clippy`, `doc`, `test`,
`run`, and `bench`, including both `--no-run` forms. Omitting the field or setting it to `false`
keeps `CARGO_INCREMENTAL=0`. This is an explicit operation policy: it overrides
the incremental settings of captured Cargo profiles, including release and
custom profiles. Ambient dispatcher values and arbitrary `env` overrides cannot
change it. Cargo and rustc retain their normal handling of incompatible compiler
options; the launcher does not change optimization settings to enable reuse.

Enable [worker-local target retention](rabs-target-state.md) to keep useful state
between operations. Every execution still runs its requested Cargo command in a
private target tree. With identical captured source, a compatible seed can
contain the complete prior incremental state. A source edit starts a fresh
target when the retained inventory contains codegen or incremental products;
those products do not inherit the metadata-only source-edit policy.
Changing the explicit incremental policy, compiler, profile, target or
other keyed compilation controls selects a different target family. Without
target retention, the command uses fresh private incremental storage.

Ordinary Cargo feature selections may share a private target when the captured
dependency closure and other compilation controls remain unchanged. Cargo checks
the current feature fingerprints and build-script environment; unchanged
dependencies can remain fresh as features are enabled, disabled or selected
again. Clippy feature selections remain separate so lint coverage is rechecked.
Doc keeps exact command arguments and the complete captured source identity.
Its private incremental projection refuses a custom profile named `doc`, whose
`doc/incremental` state root would overlap documentation for a crate named
`incremental`; complete-tree Doc delivery has no such exclusion.

Incremental compiler state remains on the worker and is excluded from delivered
artifacts through the explicit contracts described below. It is never a shared
writable directory or a compiler-result cache hit. Exported artifacts retain
their 1 GiB, 4,096-file and 16,384-entry limits. The complete private target has
a separate bounded inventory of at most 8 GiB, 65,536 regular files and 131,072
entries, so a large incremental directory cannot exhaust the smaller transfer
quota. The worker validates the entire tree, including omitted state, and
charges every retained byte against its configured target-cache quota. Unsafe
private files still refuse capture. Persistent reuse follows the existing
runtime-epoch and complete-state verification rules. This does
not enable portable incremental snapshots, skip program execution, or authorize
broader dependency or workspace action-cache serving.

## Supported command contract

The first command must be `build`, `check`, `clippy`, `doc`, `test`, `run`, or `bench`. For example:

```sh
cargo rabs --rabs-canonical PROFILE.json -- build --workspace
cargo rabs --rabs-canonical PROFILE.json -- check --workspace --all-targets
cargo rabs --rabs-canonical PROFILE.json -- clippy --workspace --all-targets --all-features -- -D warnings
cargo rabs --rabs-canonical PROFILE.json -- doc --workspace --no-deps --document-private-items
cargo rabs --rabs-canonical PROFILE.json -- test --workspace --no-run
cargo rabs --rabs-canonical PROFILE.json -- test --workspace --no-fail-fast
cargo rabs --rabs-canonical PROFILE.json -- test --test integration selected::case -- --exact --nocapture
cargo rabs --rabs-canonical PROFILE.json -- test --doc
cargo rabs --rabs-canonical PROFILE.json -- build -p app --bin app --release
cargo rabs --rabs-canonical PROFILE.json -- build --workspace --profile production
cargo rabs --rabs-canonical PROFILE.json -- test --profile ci --no-run
cargo rabs --rabs-canonical PROFILE.json -- run --bin app -- 'argument with spaces'
cargo rabs --rabs-canonical PROFILE.json -- run --example demo --release -- --help
cargo rabs --rabs-canonical PROFILE.json -- bench --bench measured --no-run
cargo rabs --rabs-canonical PROFILE.json -- bench --bench measured selected -- --exact
```

`--profile NAME` and `--profile=NAME` select a captured manifest or configuration
profile for all seven supported commands. Supply one profile, without
`--release` or `-r`. Names are 1–64 ASCII letters, digits, underscores or hyphens,
starting with a letter or digit. The launcher preserves the exact arguments and
lets Cargo resolve the profile. Warm target reuse keeps debug, release and named
custom profile families separate. The built-in `dev`/`test` profiles share the
debug family; `release`/`bench` share the release family. Cargo rechecks each
unit's actual compilation settings, and captured configuration remains exact.
Clippy preserves its own profile selection in a separate lint family.
Doc preserves its exact invocation and complete source identity.
`bench` uses Cargo's bench/release profile by default. Cargo's benchmark command
does not accept `--release` or `-r`; use `--profile` for another profile.

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

`doc` generates HTML documentation with package/workspace/features/profile/target
selection and library, binary or example targets. It supports `--no-deps` and
`--document-private-items`. Tests, benches, `--all-targets`, browser launching,
alternate output formats and argument tails are refused. The complete verified
target tree includes source pages, search data and static assets beyond the
crate indexes reported by Cargo. The [documentation section](#generate-and-deliver-documentation)
describes both canonical execution paths.

`run` selects at most one package and one literal `--bin NAME` or `--example NAME`.
With no target selector, Cargo resolves the package's default executable. Program
arguments must follow `--` and are preserved exactly, including empty strings,
Unicode and values resembling launcher or Cargo options. Workspace-wide or plural
target selectors are not meaningful for this single-executable command and refuse.

`bench` accepts the package/target selectors, one benchmark-name filter,
`--no-fail-fast`, and the exact benchmark arguments after `--`. `bench --no-run`
uses the compilation contract and returns executables without running them;
runtime arguments and filters require execution. Cargo owns harness selection,
including `harness = false`, and the final exit status. Every benchmark invocation
executes again, even when all compilation units are fresh.

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
`--no-default-features`, `--release`/`-r`, `--profile`, `--locked`, `--offline`, `--frozen`,
`--color`, `--verbose`/`-v`/`-vv`, `--quiet`/`-q`, and one optional `--target` from:
`x86_64-unknown-linux-gnu`, `aarch64-unknown-linux-gnu`,
`x86_64-unknown-linux-musl`, `aarch64-unknown-linux-musl`.
Value options accept a separate value or `=value`; compact `-pname`/`-Fname`
spellings are not supported. Required target libraries/linkers must already exist
in the captured toolchain or admitted worker environment; selecting a triple does
not install a cross-compiler. Cargo remains responsible for package/feature
resolution and may reject an otherwise syntactically supported request.

The profile owns `--manifest-path`, `--target-dir` and `--message-format=json`.
Target JSON, `--config`, unstable Cargo flags,
test-harness arguments on compilation-only commands, arguments other than the
supported lint controls after Clippy's delimiter, and unknown Cargo options
refuse before preparation. The selected toolchain also supplies local Cargo metadata probes; a
`cargo +nightly rabs` launcher selection affects `"toolchain": "rustup"` profiles
but does not override an explicit `toolchain_root`. A leading `+toolchain` after
the profile's `--` delimiter is supported only with the Rustup selector described
above; it never reaches the captured Cargo binary.
Cargo is always locked/offline, without duplicating supplied flags.

The worker receives its existing clear-environment canonical base, with
`CARGO_INCREMENTAL=0` by default or `1` for the explicit incremental opt-in.
**Ambient dispatcher RUSTFLAGS, Cargo configuration,
custom wrappers and other environment values are not copied into the worker
command.** The supported captured project configuration described above still
applies. This is an explicitly selected canonical build profile, not transparent
preservation of the dispatcher's execution environment. TLS credentials remain
local to the transport process. The worker retains ownership of its jobserver;
this frontend does not send the dispatcher's descriptor numbers to another host.
Tests, programs and benchmarks execute with closed stdin under the same isolated
network and read-only source namespace as
the build; their writes must use admitted output/home/temporary paths. The
profile does not claim equivalence to programs relying on the dispatcher's network,
credentials, mutable checkout or other ambient state.

The optional profile field `jobserver_grant` requests an integer from 1 to 4096
worker execution slots. It becomes native request intent; the launcher does not
inject `NUM_JOBS`, `--jobs` or dispatcher jobserver handles. When a worker uses a
shared host budget, choose a grant no larger than that budget. For example, a
host with eight shared slots can admit four Cargo roots requesting two slots
each. Each root owns its implicit slot and receives at most one transferable
jobserver token. The worker keeps that grant through process-group cleanup.

## Outputs, failure and recovery

The explicit `artifacts.cargo` contract augments `tree-files-v1`:

| Operation | Ordinary contract | Private incremental contract |
|---|---|---|
| Build, check, lint, test/bench `--no-run` | `cargo-json-v1` | `cargo-private-incremental-json-v1` |
| Test | `cargo-test-json-v1` | `cargo-private-incremental-test-json-v1` |
| Run | `cargo-run-json-v1` | `cargo-private-incremental-run-json-v1` |
| Bench | `cargo-bench-json-v1` | `cargo-private-incremental-bench-json-v1` |

The launcher selects the private column for `incremental: true`. Each contract
requires matching native support; older endpoints refuse an unknown contract
before execution. The contract must match the actual Cargo command and its
execution or `--no-run` mode.
The launcher's `files` minimum is empty because it does not guess
hashed library, metadata, executable or target-triple paths. After Cargo exits
successfully and its writers have drained, the worker requires a complete
`compiler-artifact` / `build-finished` report with at least one ordinary target.
For test, run and bench execution, `build-finished` ends only Cargo's compilation report. Later
stdout belongs to the programs and is retained byte-for-byte, including
JSON-shaped records, binary bytes and unterminated lines. It cannot add outputs
or change the compilation report. **Only the native final Cargo exit status can
make the complete operation successful.** A passing compilation followed by a
program failure retains the failure and diagnostics without offering successful
artifacts. Run requires exactly one reported non-build-script executable; bench
requires at least one. There is no cached runtime outcome or inferred test-pass count.

Every reported output must exist beneath `/__rabs/out/cargo`, and each reported
executable must retain executable mode. The ordinary contracts capture the entire
bounded regular-file tree, including Cargo intermediates absent from the report.
The private-incremental contracts verify that same complete tree but omit only
`<profile-output>/incremental/**` and, when an explicit target triple is selected,
`<triple>/<profile-output>/incremental/**` from artifact delivery. `dev` and `test`
profiles use `debug`; `release` and `bench` use `release`; custom profiles use
their exact names. The host-profile root remains private during cross-compilation
as well. Other directories merely named `incremental` are still delivered.
Reported compiler outputs cannot be hidden by this projection. The worker's
retained seed includes the complete state, and the full-tree integrity and size
checks apply before projection, including to the files that remain private.
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
the exact verified Cargo/program stdout**, and the matching stderr bytes are replayed
to stderr. Execution therefore produces Cargo JSON followed by ordinary
program output; stdout is not promised to be a pure JSON stream. The native
worker-build result report and launcher operation-location message go to stderr.
Replay happens after complete verified delivery, including on compiler/program
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

The retained legacy launcher regression suite executes the script entry point and
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
compilation, and execute a documentation example with rustdoc. Native run and
benchmark fixtures cover custom runtime arguments, opaque binary/JSON-shaped
stdout, actual failure statuses, benchmark `--no-run`, release-profile output
discovery and private incremental state. The real Clippy
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

RABS_TEST_WORKER_BIN="$PWD/target/debug/rabs-wkr" \
  cargo test -p rabsd --test prepared_operation_live \
    actual_canonical_cargo_ --locked -- --ignored --nocapture
```

The run/bench authenticated fixtures compare each native exit and runtime output
with stock Cargo for cold compilation, a warm program failure, and successful
execution after a source edit. They restart the worker between phases and check
retained private incremental files, reuse of the unchanged path dependency,
recompilation of the edited source, and exclusion of private state from delivery.

Before rollout, run that full path using one pinned revision and compare output
bytes and compiler failures to the explicit canonical baseline. Input preparation
and isolated filesystem tests alone do not prove the authenticated build.
Per-action admission/placement,
coordinator-only cache publication, cross-worker reuse, real compiler-skip evidence,
performance gates and the required canary/soak are not completed by this frontend.

## Local canonical Cargo commands with dependency caching

`rabsd --canonical-compile-local PROFILE.json` runs the captured native Cargo as
`cargo check`, `cargo build`, `cargo clippy`, `cargo doc`, `cargo test`,
`cargo nextest run`, `cargo run` or `cargo bench`, always offline and locked,
with the selected packages, features and targets
inside the canonical namespace and connects
its rustc requests to an operation-owned coordinator. Eligible external registry,
locked Git and verified directory-source libraries use the existing metadata
cache or the isolated worker archive lane, including cold-result publication,
differential verification and compiler-skip gates. Successful builds retain their
completed target tree and report its usable host path. Documentation commands
retain their complete generated target tree too. `test --no-run` and
`bench --no-run` deliver their compiled harnesses the same way. Tests, doctests,
programs and benchmarks execute on every invocation and return their current
result. Cargo plans the units at `/__rabs/workspace` with the captured
compiler at `/__rabs/toolchain/bin/rustc` and target at `/__rabs/out/cargo`, so moving
the original checkout does not introduce a different host path into that unit's
arguments or metadata output.

The local profile asks the captured Cargo to plan the **actual selected build
units** with `--unit-graph -Z unstable-options` on the selected `check`, `build`,
`clippy`, `doc`, `test` or `bench`, using the same Cargo selection, captured configuration
and canonical paths as execution. For `run`, captured metadata and Cargo's own
package resolution identify the selected binary or executable example; the
driver plans that exact target with `cargo build --bin/--example`. This avoids
the pinned Cargo's unsupported `run --unit-graph` path while retaining the
original `cargo run` command for execution. Program and harness arguments after
`--` are supplied only to the actual execution. Clippy's
validated lint arguments are retained for both planning and execution, after
the driver's Cargo options. Planning
does not compile or run project units, and finishes before a wrapper or cache
endpoint is exposed. Selected build scripts and procedural macros execute under
Cargo. A build-script run must name its matching compiled producer, and the
complete graph retains a coordinator-owned requirement that dependency caching
use isolated workers. Inactive optional dependencies, development targets and
other workspace members do not enable that requirement unless Cargo selects
their executors. `build --tests`, `build --benches` and `build --all-targets`
may compile harnesses; they never run tests or benchmarks. `test` admits the
selected test and library-doctest units and always requires isolated-worker
authority for dependency caching, including when `--no-run` is selected. `run`
and `bench` also always require that isolated-worker authority, including
`bench --no-run`. Run graphs must select one executable build root; benchmark
graphs admit their selected build/test units without admitting doctests. Cargo
can emit the same unit graph with or without `--no-run`; the retained command
selection determines whether the harnesses execute. Unknown graph versions, modes, target kinds, malformed edges,
cycles, unreachable units and sources outside the retained inputs also refuse.
This requires a nightly Cargo supporting the unit-graph interface; an unsupported
toolchain does not fall back to a guessed package graph.
Doc also always requires isolated-worker dependency authority. Its `doc` units
remain outside rustc result admission; ordinary dependency build/check units
retain their independently qualified compiler paths.

The default source preparation still captures the complete approved anchor and
uses locked all-features metadata to validate its dependency closure. Selecting
fewer compilation units does not reduce the authorized upload/capture scope or make
missing locked dependencies available offline. The explicit `source_selection`
option described above is also available on `canonical-compile-local-v1`
profiles for `build`, `check`, `clippy`, `doc`, `test`, `run` and `bench`. It changes the preparation
graph without narrowing the approved source anchor or granting compiler-result
authority.
Workspace members and primary packages use the separately qualified workspace
worker profiles described below; unsupported requests compile normally inside
the namespace. Their results never enter the external-dependency cache class.
External dependency `metadata` plus `dep-info` may execute locally or on an
explicitly configured authenticated dependency worker. Pure Rust `lib`/`rlib`
archive actions with `dep-info` and `link`, optionally also `metadata`, require
the worker's separately admitted closed archive namespace before they can publish
or replay a cache result. With no suitable worker, Cargo still builds those
archives in its own namespace, without granting those local archive results cache
authority. Test, Clippy, Doc, Run and Bench commands and graphs containing active build scripts or procedural macros also
require that isolated worker lane for metadata cache publication and replay.
Project executors can access the operation's wrapper socket; they cannot turn a
claimed local completion into trusted cache evidence. The retained graph policy
therefore blocks local lookup, capture and publication even when a worker is
missing, busy or refuses the action. Without a suitable worker the current
compilation proceeds through Cargo with no local action-cache authority.

Build-script producers, proc-macro producers/consumers and native-link inputs
retain their per-action cache restrictions and compile normally. Workspace and
primary packages have a separate, narrow closed-library cache class; other
accepted workspace units remain fresh executions. Eligible external libraries that consume a completed build script's
`OUT_DIR` can use the isolated worker metadata or archive cache with the complete
generated tree captured as an input. The build script itself still runs under
Cargo. Eligible independent pure dependencies may also use the isolated worker
cache. Dynamic-library candidates in a
dependency search directory still conservatively prevent that directory's
admission; this change does not claim complete per-unit acceleration for every
macro-heavy graph. Build-script failure and generated-source errors preserve
Cargo's failure status. No script, macro, test or program result cache is added.

### Pipelined metadata delivery for committed dependency hits

Matching `rabsd` and `rabs-wrap` binaries negotiate metadata delivery on an
accepted dependency cache hit. For results containing separately emitted
`.rmeta` and its recorded compiler artifact notification, the coordinator
validates the complete output selection and reserves every destination, then
stages and installs the metadata and derived dep-info before staging the
remaining `.rlib` outputs. Cargo can receive its original metadata-ready notification
while those larger outputs are still being prepared.

The wrapper forwards and flushes the exact continuous stderr prefix through
the metadata notification, including preceding dep-info notifications and diagnostics, before
acknowledging the action and committed manifest. Final success replays only
the remaining suffix. Notification order, diagnostic bytes and line endings
are preserved. A result without an eligible notification uses complete-result
delivery. Existing peers without the negotiated protocol keep that behavior.

Both phases retain one destination reservation and spend one durable replay
allowance. The coordinator checks original input observations before exposing
metadata, and rechecks the current authority, manifest, serving/release gates,
selected replicas and the exact spent receipt before installing the tail.
The last permitted replay can finish its tail without obtaining a second
allowance. A disconnect, expired deadline, corrupt tail or revoked authority
after metadata exposure fails the build; it cannot start a second local rustc
over the partially delivered outputs. The socket exchange and stderr-prefix
delivery use bounded waits, including when Cargo stops reading its pipe.

This delivery path uses already committed, qualified results.
Unfinished worker output does not gain publication or replay authority. Workspace
results require their own closed-library qualification described below; the
broader workspace execution profile remains private. Native
Cargo qualification and build-time measurements remain necessary to establish
the effect on a particular workload.

### Create and run the local profile

Install matching native `rabsd` and `rabs-wrap` binaries. The explicit nightly toolchain
root must contain its real `bin/cargo`, `bin/rustc`, libraries and native sysroot.
Documentation and selected doctests additionally require an ordinary executable
`bin/rustdoc` in that captured toolchain. Doc and Test invocations bind `RUSTDOC` to
`/__rabs/toolchain/bin/rustdoc`; ambient PATH or configuration cannot select a
different documentation compiler.
The preparing host must pass the full production bubblewrap namespace probe,
including private `/proc`, `/dev`, temporary storage and network isolation.
Unsupported hosts return an error before compilation; there is no weaker local
execution mode behind this command.

Create two private directories outside the captured source and toolchain. Keep
the operation parent short enough for a Unix socket pathname; `/tmp/rabs-compile-ops`
is an example. The driver checks existing permissions instead of repairing them:

```sh
mkdir -m 700 /home/builder/rabs-compile-state /tmp/rabs-compile-ops
```

For an already vendored project, save this profile with your actual absolute paths:

```json
{
  "version": "canonical-compile-local-v1",
  "command": "check",
  "source_root": "/data/projects/approved-anchor",
  "toolchain_root": "/opt/rust/native-linux-toolchain",
  "state_root": "/home/builder/rabs-compile-state",
  "operation_root": "/tmp/rabs-compile-ops",
  "wrapper": "/usr/local/bin/rabs-wrap",
  "manifest": "app/Cargo.toml",
  "vendor": "vendor",
  "jobs": 1,
  "timeout_seconds": 1800
}
```

```sh
rabsd --canonical-compile-local ./canonical-compile.json
```

`command` is `check` by default, `build`, `clippy`, `doc`, `test`, `run` or `bench`.
The profile and native entry point
replace `canonical-check-local-v1` and `--canonical-check-local`; install matching
tools and update saved local profiles. `manifest` defaults to `Cargo.toml`, `jobs`
to 1 and `timeout_seconds` to 1800.
Omitting `selection` for `check` retains the library-only `check --lib` behavior;
omitting it for `build`, `clippy`, `doc`, `test`, `run` or `bench` uses Cargo's ordinary
default members and targets. Setting
`"selection": {}` uses Cargo's ordinary default members and targets. A selection
can specify `workspace`, `packages`, `exclude`, `features`, `all_features`,
`no_default_features`, `lib`, `bins`, `tests`, `examples`, `benches`, `all_targets`,
the named-target arrays `bin`, `test`, `example`, `bench`, the compilation-target
array `target`, and either `release` or the optional profile-name string `profile`.
For `test` and `bench`, it also accepts `no_run`, `no_fail_fast`, an optional
`test_filter` string and the literal `test_args` array. `doc` is accepted only
for `test`. These harness fields cannot change another command. Bench uses
Cargo's optimized benchmark profile by default and accepts `profile`, but
rejects `release`, matching Cargo's `bench` options.
For the `doc` command, selection also accepts `no_deps` and
`document_private_items`, while test/benchmark targets and harness fields are refused.
For `run`, the selection accepts one package, one compilation target, and at
most one named binary or example, with no workspace or plural target selectors.
The literal `run_args` array supplies the program's arguments after `--`;
it cannot change another command. If no binary or example is named, Cargo's
selected default members and `default-run` choose the target, with ambiguity
reported before execution. For `clippy`, the selection
also accepts `no_deps` and a `lint_args` array containing bounded lint controls;
these fields cannot change another command.
An empty `target` and absent or null `profile` retain Cargo's defaults. Exclusions
require workspace selection. For example:

```json
"selection": {
  "packages": ["core", "app"],
  "features": ["app/fast"],
  "no_default_features": true,
  "lib": true
}
```

Cargo resolves package/feature names and target availability itself. These fields
cannot supply another command, compiler, environment, configuration file,
manifest, output directory or arbitrary unstable option. A test target selection
type-checks tests under `check` and compiles their executable harnesses under
`build`; neither command executes them. Compilation targets and
profile names contain only ASCII letters, digits, hyphens and underscores, start
with a letter or digit, and are at most 1,024 bytes. JSON target specifications
and paths are not admitted. `host-tuple` selects the captured Cargo's host target;
required target libraries must already exist in the captured toolchain. Cargo
validates profile existence and inheritance in the captured workspace.

The job count accepts 1–4096 and each canonical graph/compilation timeout accepts 1–7200
seconds. A purely local graph omits `vendor`. A registry/Git cache profile uses
`"cargo_home_source": "/home/builder/.cargo"` instead of `vendor`; the existing
locked offline planner captures the required package archives and Git objects
into a private Cargo home. It does not inherit that cache's user configuration,
credentials or unrelated expanded sources. The source, toolchain, state,
operation and optional Cargo-cache roots must be disjoint ordinary absolute
directories. The wrapper must be an ordinary executable outside the captured
source and mutable state/operation roots. Commands other than `check`, `build`,
`clippy`, `doc`, `test`, `run` and `bench` and arbitrary mount declarations are not
profile fields.

An optional `env` object supplies literal application inputs, for example
`"env": {"APP_VERSION": "2026.10", "SQLX_OFFLINE": "true"}`. The driver gives
canonical Cargo planning and execution the same values, including build scripts,
`env!`, tests and launched programs. It never imports the submitting client's or
service's ambient application environment. The exact values also participate in
private target-state and compiler-action identities, so a changed value cannot
reuse the old environment's result. Cargo retains its usual `[env]` default and
`force = true` precedence. Namespace, toolchain, jobserver and
coordinator controls remain reserved. See [environment inputs](rabs-canonical-environment.md)
for names, byte bounds and the direct/shared-service contract.

Preparation captures the selected toolchain before its Cargo metadata planning
and uses those captured Cargo/rustc binaries with a controlled environment.
The actual graph proof and compilation then run in the canonical namespace. The source
workspace and HOME are read-only there. HOME contains the retained wrapper and
the fresh operation socket; private Cargo state and the target are writable.
Tests, programs and benchmarks use the same view. Write temporary files through
`TMPDIR` (`/__rabs/tmp`) or the private target selected by `CARGO_TARGET_DIR`;
executed code that writes into the source checkout or HOME will fail. Networking
is isolated, so these commands cannot rely on external services. These runtime
constraints apply to doctests too, and
failures retain Cargo's status rather than retrying outside the namespace.
The build sees neither the persistent CAS nor the ordinary daemon endpoint.
Its scoped endpoint accepts rustc requests only and refuses status, generic
serving, prepared-job and administrative messages. Logical compiler paths are
translated to backing files only through the coordinator's retained mount
capability; a wrapper-supplied path or environment flag cannot construct one.

### Select native source preparation

For a native profile using an approved Cargo cache, replace `vendor` with these
fields to prepare dependencies for the command you actually select:

```json
"cargo_home_source": "/home/builder/.cargo",
"source_selection": "cargo-unit-graph-v1"
```

A purely local graph needs only `source_selection`. Both the native entry point
and `cargo rabs --rabs-canonical-local` support this mode for `check`, `build`,
`clippy`, `doc`, `test`, `run` and `bench`. The captured Cargo plans the actual package, feature,
target and profile selection, including host build dependencies and procedural
macros. The driver's fixed compiler paths, output directory and job count remain
bound to that execution. The [selected preparation constraints](#prepare-the-selected-cargo-dependency-graph)
apply; `vendor` cannot use this opt-in mode.

For Clippy, preparation invokes the captured `cargo-clippy` and requires its
ordinary executable `clippy-driver` companion. Its exact `CARGO` and `RUSTC`
bindings resolve inside the captured toolchain during planning, while retained
requests keep their canonical paths. Ordered lint controls follow Cargo's
nonexecuting graph flags. Preparation neither compiles nor executes project code;
the subsequent Clippy command still runs its current lint selection, without
claiming a cached lint result.

Final delivery includes only registry archives belonging to the validated
selected units. The complete locked sparse-index records, registry configuration,
lockfile and approved source anchor remain retained, and Git capture keeps its
complete locked-revision contract. An inactive optional dependency, or an external
dependency used only by an unselected workspace member, can lack its archive.
Selecting that package requires its verified archive and fails if it is missing.

Available locked archives are still captured and verified before Cargo selects
the graph. Pruning reduces the final delivery and retained cache inputs; it does
not reduce the initial capture work or its resource limits. This input-preparation
option leaves compiler-cache admission and publication rules unchanged.

### Send canonical dependency compilations to workers

The local Cargo driver also accepts the existing pinned dependency-worker
configuration from its operator environment. With no worker configuration it
keeps the local metadata lane only for compiler-only check/build graphs without
project executors. Test, Clippy, Doc, Run and Bench commands and graphs with build scripts or procedural
macros compile without local action-cache authority.
To use workers, install matching `rabsd`, `rabs-wrap` and
`rabs-wkr` binaries and provision the mutual-TLS credentials described in
[live dependency worker setup](rabs-worker-delivery.md#run-the-live-cargo-dependency-worker).
Run the worker's normal outward reconnect loop against the configured listener,
then launch the same canonical profile:

```sh
RABS_COORD_TLS_CA=/credentials/ca.pem \
RABS_COORD_TLS_CERT=/credentials/coordinator.pem \
RABS_COORD_TLS_KEY=/credentials/coordinator.key \
RABS_DEPENDENCY_WORKER_LISTEN=192.0.2.10:7092 \
RABS_DEPENDENCY_WORKER_ID=leaf-worker \
RABS_DEPENDENCY_WORKER_SPKI_SHA256=REPLACE_WITH_WORKER_SPKI_SHA256 \
  cargo rabs --rabs-canonical-local ./canonical-compile.json -- build --lib
```

Replace the address, paths and pin with the deployment's actual values. The
listener belongs to the coordinator; the worker connects to it. A configured
pool uses `RABS_DEPENDENCY_WORKERS_JSON` instead of the three singleton fields,
with the same existing 1–32 worker bound and per-worker certificate pins. Partial,
mixed or invalid explicit settings refuse startup. Credentials and transport
state remain outside the Cargo namespace; no normal daemon needs to be started
for this operation-owned coordinator.

The dependency-worker pool binds each configured endpoint when the pool is
created and keeps it bound through the pool's lifetime. Matching workers that
advertise `worker-standby-v2` can stay connected between compiler requests. A
direct invocation owns these listeners until its coordinator finishes; the
shared service described below keeps them available between Cargo commands.
Workers can therefore reconnect and become ready while the coordinator has no
compiler request waiting.

Dependency placement also checks the compiler's execution host before granting
work or transferring inputs. Workers advertise their native Linux ISA in
`dependency_execution_hosts` (`linux-x86_64-v1` or `linux-aarch64-v1`); the
coordinator selects it from the captured compiler's host triple, independently
of the compilation's output `--target`. A missing or incompatible advertisement
cannot admit a new dependency execution. GNU and musl compiler hosts use the
same ISA eligibility check; the existing exact runtime-cohort verification
still checks the retained loader and libraries. The worker independently
rechecks the selected host before acquiring durable execution ownership.

The worker must explicitly advertise `canonical-dependency-exec-v4` and support
the selected `metadata` or `rlib` execution mode. Both peers retain that exact version and mode through
authenticated admission. An older worker cannot silently reinterpret the request
as ordinary-path dependency execution, and metadata support does not authorize an
archive action. The worker receives only the retained
package, complete generated input trees, exact dependency candidates and
captured toolchain. It retains its own
runtime and verifies it against the keyed runtime cohort, then creates private
output and HOME trees. The outer Cargo workspace, Cargo home,
control socket and persistent CAS are not exposed to that compiler.

The worker can reuse one of four process-owned runtime images instead of
copying the same ELF libraries for every compilation. A lease binds the verified
toolchain, ordered loader paths, runtime cohort and current output filesystem;
active images cannot be evicted. Reuse still verifies the retained bytes and
independently remeasures the host before and after execution. The
`worker-runtime-acquired` event distinguishes captured, reused and private images.
See [runtime ownership and limits](rabs-worker-delivery.md#reuse-retained-compiler-runtimes).

For a library with `OUT_DIR`, the coordinator requires Cargo's completed
`root-output` record to name that exact canonical path and captures its byte-exact
persisted stdout alongside every file and directory in the generated tree.
Directory-only trees and empty subdirectories are retained, keyed and rebuilt
under an explicit private owner. The path must be below
`/__rabs/out/cargo`, disjoint from compiler outputs and dependency search roots;
the worker mounts it read-only at the original logical name. The action key
binds the complete generated contents and directory listings, the persisted Cargo directives and the
presented environment. Source and record generations are checked again before
publication and installation. A changed generated file or directory therefore cannot reuse
the earlier consumer result even when its package source and build script are
unchanged. These inputs authorize only an independently supervised compiler
execution; they do not authorize local result capture or cache the script's
execution, filesystem observations or side effects.

Canonical metadata checks can also consume static native libraries generated in
captured Cargo `OUT_DIR` trees. Each `-L native=...` search directory must belong to a
captured tree, and every unmodified `-l static=NAME` must resolve to a retained
`libNAME.a`. The coordinator binds archive bytes, search ordering, directory
listings and Cargo directives into the key. The worker independently verifies
the named archives in both the announced manifest and the sealed source tree;
successful metadata compilation alone is insufficient because rustc need not
open a static archive while checking types. Eligible dependency results earn
replay through the existing sampling and release gates. No linker runs and only
metadata plus dep-info are returned.

This extension requires the worker's explicit
`canonical-generated-static-metadata-v1` capability in `dependency_native_inputs`.
An older worker refuses before source upload or compiler dispatch. Native
metadata has a distinct isolation-policy identity; existing pure-Rust metadata
and archive identities are unchanged. Dynamic/system libraries and native library
modifiers retain their existing refusals. Without the isolated worker path, these
checks run under Cargo without local dependency-cache authority.

Cargo propagates a dependency build script's native search paths to downstream
libraries and workspace targets. Those consumers can now execute through the
same isolated worker path even when they have no build script, `OUT_DIR` or
direct `-l` option of their own. For each foreign `-L native=...` root, the
coordinator captures the producer's complete generated tree, persisted build-script
stdout and `root-output` record through the canonical driver's retained target
mount. The worker restores each tree read-only at its original logical path.
Native search order, every retained file, empty directory and producer record
participate in the consumer's identity; an unchanged Rust package or `.rmeta`
cannot hide changed propagated native inputs. The worker never receives the
whole mutable Cargo target directory.

Requests carrying these additional generated roots require the explicit
`canonical-generated-native-roots-v1` entry in `dependency_native_inputs`,
alongside the existing output-mode and native-metadata capability checks.
Update coordinator and worker together; an older worker refuses before input
upload or execution. This does not admit arbitrary host search paths: each
additional root must be a retained canonical Cargo generated tree with matching
completed producer records. A missing record, unsupported native option or
changed retained input prevents that invocation from acquiring cache authority.

The capture binding comes from the driver's retained mount capability, not from
a canonical-path flag in a compiler plan. It binds both the physical tree and
Cargo's recorded logical name through background capture and memo reuse. A
request whose worker context names another generated root is refused before
dispatch, and generated-input requests cannot recover local publication authority
by bypassing the edge's ordinary admission path.

Archive execution also excludes process information and entropy devices from
the compiler's filesystem view. Its only null device is an independently checked
real `/dev/null` character device. The action key covers the complete retained
package and generated inputs, exact dependency artifacts, compiler, runtime and
presented environment.
Assembler `.incbin` reads can therefore consume keyed package bytes even when
rustc omits those files from dep-info; host-only paths, `/proc` content and
`/dev/urandom` cannot become invisible archive inputs. This is a closed per-action
view, separate from the larger namespace where Cargo plans and builds workspace
targets. Canonical local metadata evidence cannot promote an archive, and canonical
remote metadata and archive policies have distinct action identities.

Cargo's `/__rabs/...` names remain unchanged in compiler arguments, environment,
dep-info, output declarations and action keys. Only coordinator file observation
and final output installation use retained physical backing paths. Runtime and
complete-toolchain checks are repeated through publication and installation, and
the ordinary worker runtime-compatibility requirements still apply. This
canonical remote class has a separate key policy from both ordinary remote work
and local canonical execution; existing local samples do not promote remote hits.

Cold results use the existing private execution and verified delivery path, then
require the wrapper's manifest-specific acceptance before installation. Repeated
eligible requests earn cache replay through the existing differential-sampling
and release-authorization gates. `remote-offer`, `rabsd-remote-dependency-admitted`
and the worker's durable receipts distinguish real dispatch from local fallback.
An incompatible worker or a refused action does not gain publication authority;
fallback after dispatch still requires verified completion of remote execution.
Selected project executors never authorize local dependency cache capture
or replay, even after a worker refusal.

### Execute selected workspace compilations remotely

The same configured worker pool can execute the project's own compilation
units, including primary packages and local path dependencies. Canonical
`build` and the library-compilation portions of `test` support ordinary Rust
libraries. Canonical `check` additionally supports binaries, examples,
integration tests, library and binary test harnesses, and benchmark targets.
Custom `harness = false` tests and benchmarks use Cargo's actual `--cfg test`
arguments without inventing a crate type or adding `--test`:

```sh
cargo rabs --rabs-canonical-local ./canonical-compile.json -- check --workspace --all-targets
```

The coordinator matches each request to Cargo's retained selected unit graph:
package, source, crate name/type, compilation mode, target and features must
agree. Cargo can serialize ordinary and test-harness graph rows identically,
so graph membership alone does not attest an exact harness mode. Harness checks
also bind the trusted command's target selection and selected root units;
custom harnesses require selected integration-test or benchmark roots. The
actual compiler arguments are independently bound into each execution identity.
Ordinary wrapper requests cannot enable this path by supplying canonical-looking
names.

This uses the separately negotiated `canonical-workspace-exec-v3` context.
Workers must advertise that version and the requested `metadata` or `rlib`
mode; update both coordinator and worker binaries together. Matching binaries
and the worker setup above are sufficient; there is no new cache-enablement
switch. Unsupported units continue through Cargo's
ordinary compiler path. Binary and harness checks require exactly metadata and
dep-info outputs. Their legitimate empty `.rmeta` files are retained and
installed; no executable is linked, and no test or benchmark body runs during
these checks. Final binary/test linking, native linking, procedural-macro
consumers and incremental compiler state remain outside this per-unit worker
profile; build scripts execute through the existing canonical Cargo driver.

Workspace library builds can also bundle static native archives produced in
their own build-script `OUT_DIR`. The coordinator captures that complete tree,
including empty subdirectories and the Cargo output record, and requires each
declared native search directory and `libNAME.a` to occur in the retained
evidence. The native inputs use unmodified `-l static=NAME` arguments whose
`-L native=...` paths stay within that exact
`OUT_DIR`. Rustc bundles the captured archive inside the closed archive view;
this step invokes no external linker. Selected workspace metadata checks accept
the same exact static inputs when the worker advertises
`canonical-generated-static-metadata-v1`. Their returned outputs remain metadata
and dep-info; they do not link a library, executable or test harness. Archive
bytes participate in the fresh execution identity even though rustc's dep-info
does not list them and a metadata check may not read them.

Workspace units can also receive native search paths propagated through dependency
libraries. They use the same completed-record capture and
`canonical-generated-native-roots-v1` capability described above, including
consumers with no own `OUT_DIR`. The root's full retained files and directory
listings remain part of each workspace execution identity. Only supported static
native options and retained Cargo paths are eligible; dynamic, system and
framework inputs remain excluded.
Inputs cannot be acquired by spelling an unretained host path in rustc argv.

Ordinary workspace library metadata checks with propagated native inputs can
also earn action-cache reuse through the distinct
`canonical-workspace-propagated-native-dag-metadata-v1` class (key epoch 36).
Every loadable Rust dependency must have an operation-owned installation backed
by an exact committed producer and complete transitive ancestry. Every foreign
native tree, its directory listings and completed Cargo records remain keyed;
an optional own `OUT_DIR` is retained in full as well. The coordinator checks
these generations again before publication and delivery. The class requires
its own successful verification samples and quarantine checks, so earlier
pure-Rust or own-`OUT_DIR` metadata evidence cannot enable its replay.

This metadata path uses the closed metadata sandbox and publishes only metadata,
dep-info and diagnostics. It supplies no archive, final-link, harness or
build-script execution authority.

Ordinary workspace library builds with inherited native search roots can also
qualify through the separate
`canonical-workspace-propagated-native-dag-rlib-v1` class (key epoch 37).
This closes the archive-reuse gap for a native dependency feeding one or more
workspace libraries, including consumers without their own build script:

```sh
cargo rabs --rabs-canonical-local ./canonical-compile.json -- build --workspace --lib
```

The archive class uses the existing isolated `Rlib` worker context. It retains
every foreign native tree and completed Cargo record, any own generated tree,
the whole captured workspace, exact compiler environment, ordered Rust
candidate inventory, and current committed producer ancestry. Archive consumers
require archive-capable producers; metadata-only publications cannot qualify
them. Every returned archive must pass the existing native-member closure
validation before publication or delivery.

Archive and metadata results have distinct action identities, verification
samples and class quarantine. An archive hit restores its verified `.rlib`,
metadata, dep-info and diagnostics through the existing delivery owner. A
changed native object, directory listing, Cargo record, compiler environment or
producer witness requires a new key or refuses reuse. A previously qualified
consumer still rechecks its transitive producers before serving.

These classes cache consuming Rust library actions. Final executable linking,
test execution and build-script execution keep their existing execution paths.
Unsupported or unqualified requests retain fresh execution; build scripts still
execute under Cargo. The broader native compiler and exact-link caching
milestones remain separate.

The general workspace execution profile executes each accepted request afresh.
Its identity binds the entire
retained workspace, including sibling files and empty directories, generated
`OUT_DIR` contents and Cargo run records, exact Rust dependency artifacts,
toolchain, runtime and original compiler environment. Relative source arguments,
the workspace working directory, `CARGO_PRIMARY_PACKAGE` and the project's lint
settings remain intact. Cargo's entirely empty `LD_LIBRARY_PATH` is preserved
and modeled as zero search entries. Empty components in nonempty colon-separated
lists still refuse because they can introduce current-directory lookup.
The worker reconstructs an independent read-only source
tree at `/__rabs/workspace`; generated files retain their separate read-only
mount. It never receives the coordinator socket, Cargo home or mutable CAS.

A complete authenticated result remains owned by that one request. After
compiler/descendant drain, the coordinator verifies its output manifest and
input generations, waits for the wrapper to acknowledge that exact manifest,
then installs only the declared outputs. Canonical dep-info bytes stay unchanged;
validation and freshness checks resolve their logical paths through the driver's
retained backing mappings. Source, dependency, toolchain or coordinator changes
refuse installation. A repeated request needs another fresh execution, and
uncertain execution cannot authorize concurrent local fallback.

For a completed workspace result with nonempty declared metadata and a valid
compiler notification prefix, the matching wrapper receives metadata before
the archive tail. The coordinator installs and verifies the metadata and
dep-info, sends the original compiler prefix, and waits for its exact
acknowledgment before staging the remaining outputs. One reservation covers
every destination, and the original result pins and input guards remain owned
through both phases. Input or coordinator changes during the acknowledgment
prevent tail installation. Any failure after head exposure prevents local
fallback. Successful checks whose metadata is intentionally empty retain
complete-result delivery.

This permits downstream Cargo work to overlap archive installation after the
workspace compiler has completed. It does not grant cache authority or expose
an unfinished producer's metadata.

These execution-only workspace results do not create an action-cache publication,
serving entry, differential sample or replayable transcript index. A separate
closed-library class can qualify for reuse under the narrower rules below.
Cargo still owns command execution and freshness; the optional private target
reuse described below has its existing independent rules and limits.

### Cache closed workspace leaf-library builds and checks

Workspace leaf action caching admits selected ordinary Rust `lib` or `rlib` units in
two independently qualified classes: builds with archive output, and checks with
metadata and dep-info output only. Both require a retained Cargo unit graph with
no project executors, no explicit external crates or implicit Rust artifact
candidates, no generated inputs or native libraries, and no incremental state.
The captured Rust standard library remains available through the retained
toolchain. Libraries consuming other workspace artifacts may qualify for the
separate committed-producer build and check classes below. Test harnesses, binaries,
procedural macros, external dependency consumers and generated/native workspace
units retain their existing fresh-execution or ordinary Cargo paths.

Each class keys the **complete captured workspace**, including sibling files,
every directory listing and empty directories. It also binds the exact compiler
arguments, working directory, environment, toolchain and measured runtime. An
unrelated workspace edit can therefore invalidate the result. These initial
classes retain complete inputs; they do not establish a discovered minimal source
closure or cache arbitrary workspace compilations.

The coordinator independently matches the request to the driver's retained
selected library unit, its build/check mode and its graph. Archive builds require
the worker's existing `canonical-workspace-exec-v3` context in closed `rlib` mode.
Metadata checks require the separately negotiated
`canonical-workspace-closed-metadata-v1` context in `closed-metadata` mode. Both
strict namespaces omit the process filesystem and entropy devices and expose
only the checked null device. The worker measures each mode independently;
support for ordinary metadata execution does not authorize closed metadata.

The distinct `canonical-workspace-closed-rlib-v1` and
`canonical-workspace-closed-metadata-v1` policies and versioned action identities
separate archive and check results from each other, execution-only workspace
results and external dependency results. Existing archive identities remain
unchanged. A workspace descriptor, canonical-looking path or local wrapper
completion cannot confer this authority. Dispatch, completed result capture and
cache replay each revalidate the selected class and its execution policy.

Eligible cold results still require authenticated remote execution, compiler and
descendant drain, complete output/transcript capture, unchanged retained inputs,
and the wrapper's exact manifest acknowledgment before private installation.
Publication and subsequent reuse pass the existing independent differential
sampling, release authorization and serving gates. Metadata and archive results
earn separate samples, and divergence quarantines the affected class independently.
Execution-only workspace results cannot train these gates or become replayable by
changing a profile flag. Both classes use the existing fixed sampling policy; the optional
dependency-only SPRT promotion policy does not authorize workspace replay.

Once qualified, a hit restores the declared archive and metadata when emitted,
or the check's metadata, together with dep-info and compiler diagnostics through
the verified installer. Cargo can use the restored `.rmeta` in subsequent
consumer compilations; those consumers still qualify independently for their own
execution or reuse paths. Source, environment or workspace-directory changes
require a different action identity. Missing, unsupported or changed evidence
preserves the existing refusal and fallback rules, including the prohibition on
a second compilation while a remote execution is uncertain.

### Cache workspace library builds with committed dependencies

Ordinary pure Rust workspace library builds can also qualify when they consume
other workspace libraries. This supports chains and branching graphs through
the same canonical local profile:

```sh
cargo rabs --rabs-canonical-local ./canonical-compile.json -- build --workspace --lib
```

Every retained `.rmeta` or `.rlib` candidate in every compiler search directory
must have been installed from an already committed closed-workspace **archive
build** in the same retained Cargo operation. This includes transitive and
unnamed candidates, not only explicit `--extern` arguments. The coordinator
records the exact producer action, descriptor, canonical result manifest,
logical output and object identity together with the installed file generation.
The reusable key includes those stable identities and the entire retained
artifact bytes; physical backing paths and file generations remain private to
the operation so a different checkout can reuse the same canonical action.

Verified metadata from a completed, committed producer can qualify a consumer
before that producer's archive finishes installing. The metadata witness is
registered only after the actual head is verified and before Cargo receives
the compiler notification. An archive receives its own witness only after
successful complete installation. A manifest declaration, ordinary local
compiler completion or fresh request-owned result does not grant a witness.
Replacing a candidate with identical bytes still invalidates the old file
generation until another verified installation establishes its provenance.

The existing worker candidate projection remains unchanged: non-explicit
archives shadowed by nonempty metadata are omitted from the retained namespace.
An explicit archive is retained in full and needs its own witness even when a
same-name metadata file exists. Cargo's later creation of a primary archive
hard link can change that archive's recorded generation; an explicit consumer
then conservatively executes afresh. Unknown or unattributed candidates also
keep the consumer on its existing fresh-execution path. Cacheable metadata-only checks,
external dependency producers, generated/native inputs, procedural macros,
incremental state and final links do not qualify for this initial dependent
archive class. The selected graph must still contain no project executors.

The separate `canonical-workspace-committed-rlib-v1` policy uses key epoch 6 and
its own serving class and verification evidence. Like the leaf classes, it
retains the complete captured workspace, all directory listings, exact compiler
environment and arguments, complete toolchain and measured runtime. It uses the
existing closed `rlib` worker context. This remains a conservative complete-input
cache; it does not establish minimal source discovery or general provisional
metadata reuse.

Publication records the exact committed producer references in the existing
durable ancestry graph. The coordinator rechecks their transitive closure under
the publication lock and again during cache lookup, metadata installation and
archive-tail installation. Missing publications, changed objects, adoption,
cycles, expired serving validity, quarantine and adverse producer evidence
refuse reuse. A consumer must still earn its own independent comparisons and
pass release, class and replay gates; its producers' samples do not count for it.
After metadata exposure, a later revocation or delivery failure remains a
terminal delivery error and cannot authorize local fallback.

### Cache workspace library checks with committed dependencies

Pure Rust workspace `lib`/`rlib` checks can qualify through the independent
`canonical-workspace-committed-metadata-v1` class, using key epoch 7:

```sh
cargo rabs --rabs-canonical-local ./canonical-compile.json -- check --workspace --lib
```

The class requires the strict `closed-metadata` worker context and retains the
complete captured workspace, directory listings, exact compiler environment,
arguments, toolchain and runtime. It keys every explicit extern and every
loadable implicit candidate, together with the exact committed producer action,
descriptor, manifest, logical output and entire artifact identity. Producers
must be closed workspace metadata or archive actions whose outputs were
verified and installed by the same retained Cargo operation. External dependency
producers, unknown target seeds, local fallback and uncommitted metadata cannot
supply this authority; those consumers keep their existing fresh execution.

The operation-owned input capability binds its consumer class as well as the
original files and generations. A metadata capability cannot qualify an archive
consumer. Recursive lineage checks also retain each intermediate producer's own
policy, preserving the archive class's existing producer scope and epoch-6
identity. Changed or quarantined transitive producers block both new publication
and replay even when the consumer already has passing comparisons.

Metadata results earn their own independent samples and persistent class
quarantine. A qualified hit restores `.rmeta`, dep-info and diagnostics through
the existing verified installer. A chain of ordinary library checks can therefore
reuse committed metadata. Eligible final binary and test checks use the separate
terminal metadata classes below. Generated/native inputs, project executors, harness
outputs, incremental state and archive output remain outside this metadata
class. The selected Cargo graph must still contain no project executors.

### Cache binary, example and harness metadata checks

Canonical `check` requests can qualify selected binary, example, standard test
and benchmark harnesses, and custom `harness=false` test/benchmark roots for
terminal metadata caching:

```sh
cargo rabs --rabs-canonical-local ./canonical-compile.json -- check --bin app
cargo rabs --rabs-canonical-local ./canonical-compile.json -- check --example demo
cargo rabs --rabs-canonical-local ./canonical-compile.json -- check --test integration
```

These actions cache compiler metadata, dep-info and diagnostics. They require
the retained Cargo-selected source, crate type, target, features and exact
harness invocation. The selected compiler action runs in the independently
enforced `ClosedMetadata` namespace. Other units may execute project code
without granting local completion authority. Keys retain the complete captured
workspace and directory listings, exact compiler environment and arguments,
output declarations, toolchain and measured runtime. Executable linking, test
execution, generated/native inputs and incremental state remain outside these
pure-input classes.

Two independent policies distinguish the source of input authority:

| Terminal class | Key epoch | Required input proof |
| --- | --- | --- |
| `rustc-workspace-terminal-leaf-metadata-v2` | 24 | Every retained candidate directory is observed and empty; durable producer ancestry stays empty. |
| `rustc-workspace-terminal-metadata-v2` | 25 | Every loadable Rust candidate has an exact committed installation witness; the complete nonempty workspace/immutable dependency ancestry remains valid. Exact empty search metadata remains keyed and materialized without producer authority. |

Each class earns its own independent comparison samples and retains separate
quarantine and serving gates. Library samples cannot qualify a terminal action.
A missing, changed or quarantined producer blocks the committed terminal class;
missing ancestry cannot turn it into the dependency-free class.

Rustc ordinarily emits an empty `.rmeta` for these terminal checks. Both worker
completion and a qualified cache hit install that exact declared file through
complete-result delivery and replay the validated compiler transcript. Terminal
results never grant early metadata readiness or become reusable dependency
producers, including when a compiler emits nonempty terminal metadata. Existing
library and producer-witness nonempty checks are unchanged.

Warm private targets retain terminal completion validity separately from
dependency-producer authority. Restoring Cargo's terminal fingerprints therefore
rechecks the original terminal publication and its quarantine before Cargo can
treat the unit as Fresh.

Broad selections such as `check --all-targets` can leave earlier terminal
outputs visible in later units' search directories. Exact empty metadata stays
in the keyed and materialized input inventory without becoming a producer.
The committed terminal class can retain those files alongside its independently
verified loadable dependencies; explicit empty externs still refuse. The leaf
class requires literally empty candidate directories, so a terminal root with
only earlier empty candidates continues with fresh execution. Selecting an
individual terminal root allows its independently qualified leaf action to
replay in a fresh Cargo target.

#### Generated-code terminal checks

Selected binaries, examples, standard test/benchmark harnesses and
`harness=false` roots can also qualify when their own package has a completed
Cargo build script and generated `OUT_DIR` inputs. These actions use two
additional classes:

| Generated terminal class | Key epoch | Required input proof |
| --- | --- | --- |
| `rustc-workspace-generated-terminal-leaf-metadata-v1` | 34 | Complete own generated inputs and build-script record; every retained Rust candidate directory is empty. |
| `rustc-workspace-generated-terminal-metadata-v1` | 35 | The same complete generated inputs plus exact committed provenance for every loadable Rust candidate and current transitive producer standing. |

The key binds the whole captured workspace, every generated file and directory
listing (including empty directories), the completed build-script stdout
record, exact presented environment and matching `rustc-env` directives. It
also retains the selected terminal invocation, output contract, toolchain,
runtime and complete dependency inventory. A changed generated byte, directory,
record, environment value or committed producer requires a different key or
refuses reuse. Original input generations are checked again through delivery.

These classes use the existing closed metadata worker context. Native search
roots and library directives, procedural macros, incremental state, linking
and target execution remain excluded. Build scripts still run for the current
cold Cargo operation; this feature caches their consuming compiler checks,
and does not add build-script execution caching.

Generated terminal actions earn independent comparison samples and class
quarantine. Pure terminal or generated-library evidence cannot qualify them.
Both fresh completion and a qualified hit install exact metadata (including
empty files), dep-info and verified diagnostics before replay. Even nonempty
terminal metadata never grants downstream producer authority. Retained target
seeds preserve the generated terminal policy and recheck publication, action,
class, output and producer standing before restoring Cargo freshness.

Controlled-host regressions cover both generated terminal classes across all
six binary/example/standard-harness/custom-harness shapes, with stock compiler
bytes and diagnostics, independent samples, cold-target and relocated-checkout
reuse, generated-input and environment invalidation, and a current type error:

```sh
cargo test -p rabsd --test canonical_check_local \
    canonical_generated_terminal_metadata_leaves_earn_hits_without_running_targets \
    -- --ignored --exact --test-threads=1
cargo test -p rabsd --test canonical_check_local \
    canonical_generated_terminal_metadata_consumers_earn_hits_from_committed_ancestry \
    -- --ignored --exact --test-threads=1
```

These tests require the matching native wrapper and worker, OpenSSL and full
Linux bubblewrap isolation described in the validation section. Pure key and
coordinator unit tests do not replace those compiler/worker integration gates.

### Cache workspace libraries using qualified immutable dependency leaves

The canonical driver can also cache an ordinary workspace library whose retained
inputs include a verified immutable registry, Git or checksummed directory-source
dependency leaf. This supports a plain external dependency feeding one or more
workspace libraries with the same commands:

```sh
cargo rabs --rabs-canonical-local ./canonical-compile.json -- build --workspace --lib
cargo rabs --rabs-canonical-local ./canonical-compile.json -- check --workspace --lib
```

The external producer must have run through the canonical remote lane, have a
successful committed result, and have its actual output verified and installed
by this Cargo operation. It must have no explicit externs, no loadable Rust
candidates (including unnamed alternatives), no generated or native inputs, and
no recorded producer ancestry. An ordinary dependency-cache entry, a local
compiler result, a copied artifact, a raw fallback or a request-owned result
cannot establish this qualification.

Qualification binds the producer's action, descriptor, published manifest and
execution mode. The operation separately retains each installed file generation.
Every later publication and delivery rechecks the exact objects, qualification,
current serving validity, quarantine and transitive ancestry. An external leaf
with newly discovered ancestry is refused. Each intermediate workspace producer
keeps its own producer restrictions, even when its consumer permits a broader
input class. Revocation after metadata delivery remains a terminal delivery
error, including metadata-only results with no archive tail.

The existing workspace-only classes remain the first choice. When their narrower
producer policy cannot admit the inputs, eligible requests use separate
`canonical-workspace-committed-mixed-rlib-v1` (epoch 8) or
`canonical-workspace-committed-mixed-metadata-v1` (epoch 9) identities. They earn
their own comparison evidence and class safety holds. Archive consumers require
archive-class producers; metadata consumers can use metadata or archive
producers, with complete explicit archive bytes retained. Metadata producers
authorize only `.rmeta` outputs. Checks still explicitly negotiate
`ClosedMetadata`; builds retain the existing closed archive worker context.

These epoch 8/9 profiles deliberately admit immutable leaves only. External
crates with their own committed dependencies require the separately keyed DAG
profiles below. An unqualified retained candidate or a workspace Cargo graph
containing build scripts or procedural macros still keeps the workspace
consumer on its existing fresh-execution path.

### Cache through committed immutable dependency chains

Canonical builds and checks can also cache a chain of immutable external
dependencies before those outputs reach workspace libraries. For example,
registry or vendored A can feed immutable B, which feeds workspace C and D.
The commands and retained canonical mount layout remain the same.

Each non-leaf external compiler request must bind every loadable Rust candidate
to an exact producer installed by this Cargo operation. This includes candidates
not named by an explicit `--extern`. The descriptor hashes the producer action,
descriptor, committed manifest, output role and whole object identity together
with the existing source, invocation, environment, toolchain and runtime inputs.
The published result retains that same ancestry. Historical generic dependency
entries, source labels or a path containing equal bytes cannot supply it.

The new policies earn independent comparison evidence and class safety holds:

| Consumer | Archive policy / key epoch | Metadata policy / key epoch |
|---|---|---|
| Immutable dependency DAG | `canonical-immutable-committed-dag-rlib-v1` / 10 | `canonical-immutable-committed-dag-metadata-v1` / 11 |
| Workspace consuming immutable DAGs | `canonical-workspace-committed-dag-rlib-v1` / 12 | `canonical-workspace-committed-dag-metadata-v1` / 13 |

An immutable DAG producer can consume qualified immutable leaves and other
immutable DAG producers. Workspace DAG consumers can additionally consume the
existing narrower workspace classes. Every intermediate producer keeps its own
policy, including when a shared ancestor was already checked under a broader
consumer. Archive consumers require archive-class producers; metadata consumers
may use metadata or whole archives. Immutable metadata retains the existing
dependency `Metadata` execution view, while workspace checks explicitly retain
`ClosedMetadata`. No worker namespace or execution capability is broadened.

Publication, cached replay and fresh-result installation recheck the complete
transitive graph against current publication, class, object and quarantine
state. A local-fallback middle crate cannot qualify its descendants. Revocation
after metadata delivery remains terminal even for metadata-only results.

This support remains limited to ordinary pure libraries without generated,
native, proc-macro or incremental inputs, and workspace consumers retain the
executor-free Cargo graph requirement. Complete package/workspace contents and
directory inventories remain keyed. Minimal observed read closures, general
build-script replay and arbitrary external-input graphs remain separate work.

### Local Clippy with reusable dependency compilation

The same local profile can lint its selected Cargo units:

```sh
cargo rabs --rabs-canonical-local ./canonical-compile.json -- clippy --workspace --all-targets --no-deps -- -D warnings
```

The captured toolchain must contain ordinary executable `bin/cargo-clippy` and
`bin/clippy-driver`, alongside Cargo and rustc. Both the graph query and the
actual command invoke that captured `cargo-clippy`, with `CARGO` and `RUSTC`
bound to the captured canonical binaries. Toolchain capture identifies their
bytes; an ambient rustup proxy or another PATH entry cannot select the driver.

`--no-deps` limits lint coverage as it does in ordinary Clippy. The tail after
`--` accepts `-A`, `-W`, `-D`, `-F`, `--allow`, `--warn`, `--force-warn`, `--deny`,
`--forbid` and `--cap-lints`. Short flags accept separate or attached lint names;
long flags accept separate values or `=value`. Lint names are bounded lowercase
identifiers, including names such as `clippy::needless_return`. Lint caps are
`allow`, `warn`, `deny` or `forbid`. Their order is preserved, because later
lint levels can change the result. Compiler flags, response files, paths and
arbitrary Clippy arguments are refused. A direct native profile expresses the
same selection as `"command":"clippy"` with
`"selection":{"no_deps":true,"lint_args":["-D","warnings"]}`.

Clippy driver invocations pass through the wrapper and never acquire a rustc
cache key, publication capability or compiler-skip reply. The entire operation
disables local dependency-result authority. Ordinary rustc dependency requests
may use the existing isolated-worker lane when its admission and replay gates
are satisfied; without an admitted worker they compile normally. Cargo still
owns lint freshness and the current command's diagnostics and exit status.
Clippy-driver wrapper chains also remain outside fresh workspace offload; a
selected library record cannot substitute ordinary rustc for its lint execution.

Optional private target reuse keeps Clippy in its own families, binding its
exact selection, ordered lint controls, captured driver and complete source
snapshot. A warm `check` cannot supply Clippy lint coverage. Changing lint
levels or captured configuration starts a different family, including changes
that rustc dep-info would not observe. An identical Clippy request can restore
verified private Cargo state; it still starts the selected Cargo/Clippy command.
Lint outcomes are never shared action-cache results or delivered build artifacts.

### Generate and deliver documentation

Both canonical profiles support HTML documentation generation:

```sh
cargo rabs --rabs-canonical-local ./canonical-compile.json -- doc --workspace --no-deps
cargo rabs --rabs-canonical-local ./canonical-compile.json -- doc -p core --lib --document-private-items
cargo rabs --rabs-canonical ./canonical-worker.json -- doc --workspace --no-deps --document-private-items
```

The captured toolchain must contain ordinary executable Cargo, rustc and rustdoc.
Planning and execution bind both compilers to their captured canonical paths.
A native local profile can express the same command as `"command":"doc"` and
`"selection":{"no_deps":true,"document_private_items":true}`. Complete and
selected source preparation both support Doc.

The returned target directory contains `doc/<crate>/index.html`; an explicit
compilation target uses `<target>/doc/<crate>/index.html`. The whole verified
tree is delivered or retained, including private-item pages when selected,
source views, search indexes, JavaScript, fonts and CSS. Cargo's JSON index
filenames establish the required minimum, so they never filter out supporting
files. Existing tree path, byte, file-count, mutation and writer-drain limits apply.

Doc supports library, binary and example selectors, with the profile's existing
package, feature, target and compilation-profile controls. It rejects test and
benchmark targets, `--all-targets`, `--open`, custom output formats, arbitrary
rustdoc arguments and compiler-environment overrides. `cargo test --doc` retains
its separate doctest execution behavior.

Every invocation starts the original Cargo documentation command and returns its
current status and diagnostics. Cargo owns rustdoc freshness.
Rustdoc units do not become rustc cache entries. Eligible dependency compilations
retain the existing isolated-worker requirements. Optional private target reuse
binds the full source, captured toolchain, exact arguments and environment;
different documentation selections cannot borrow a Build/Check compatibility family.

### Run programs and benchmarks with reusable compilation

The local profile also runs a selected binary or executable example and Cargo's
benchmark harnesses. Eligible library compilations can use isolated workers;
the final links and requested program or benchmark bodies execute in the local
canonical namespace.

```sh
cargo rabs --rabs-canonical-local ./canonical-compile.json -- run --bin analyze \
  -- --format=json < input.json
cargo rabs --rabs-canonical-local ./canonical-compile.json -- bench --bench throughput \
  selected -- --exact </dev/null
cargo rabs --rabs-canonical-local ./canonical-compile.json -- bench --bench throughput --no-run
```

Run's `run_args` and Bench's `test_filter`/`test_args` are literal runtime values.
Empty arguments, Unicode and option-looking program arguments survive the
handoff. They never enter graph planning as Cargo options. `harness = false`
benchmark targets retain Cargo's custom-harness behavior. Bench defaults to
Cargo's optimized benchmark profile; use `--profile NAME` for another profile.

This is a **noninteractive execution profile**. Executing Run and Bench commands
inherit pipe, file or null stdin. A terminal stdin is rejected before source
capture or coordinator startup because the managed Cargo process group does not
own terminal foreground control. Redirect input, use `</dev/null`, or deliver a
binary with `build` and run it outside this profile when it needs an interactive
terminal. `bench --no-run` does not consume stdin or require this redirection.
Check, Build, Clippy and Doc retain closed stdin. Test also defaults to closed
stdin, but an executing Test can explicitly inherit nonterminal input or use a
captured file as described below. The source workspace and HOME remain read-only,
temporary and target directories are
private and writable, and external networking remains unavailable.

Optional private target reuse can restore compiled artifacts across changes to
program arguments or benchmark filters. Every invocation still starts the
original Cargo command and reruns the requested body. A normally exited failing
program or benchmark may retain its compiled state, but Cargo's current numeric
exit status is preserved and the execution result is never cached. The driver's execution
records report `run_execution` or `benchmark_execution` and explicitly keep
program/benchmark result caching disabled. `bench --no-run` delivers the complete
compiled target tree through the same retained-artifact contract as Build and
`test --no-run`.

#### Run without input through a shared or remote service

Native profiles can explicitly select `"stdin": "closed"`. Cargo and the
requested program or benchmark receive EOF without reading the client's or
daemon's input. This admits noninteractive Run and executing Bench commands
through both persistent local and pinned-TLS remote canonical services.
Omitting the field preserves the existing command-specific defaults: Run and
executing Bench inherit nonterminal input in standalone mode and refuse service
submission. An explicit `"stdin": "inherit"` also remains standalone-only and
is available for executing Test as well. Test defaults to EOF; compilation-only
commands, including `test --no-run` and `bench --no-run`, reject inherited input.

For a native local profile, add `"stdin": "closed"` beside `"command": "run"`
and submit with `rabsd --canonical-compile-local PROFILE.json`. The same profile
can name `service_socket` to use the persistent local coordinator.

For a remote profile, replace its `settings` object with, for example:

```json
{
  "command": "run",
  "stdin": "closed",
  "manifest": "app/Cargo.toml",
  "selection": {
    "bin": ["analyze"],
    "run_args": ["--format=json"]
  },
  "jobs": 2,
  "timeout_seconds": 1800
}
```

Submit it with `rabsd --canonical-compile-remote PROFILE.json`. Executing Bench
uses `"command": "bench"`, `"stdin": "closed"`, and the existing `bench`,
`test_filter` and `test_args` selectors. Standard output, standard error,
numeric exit status, cancellation, execution deadlines and accepted-operation
recovery keep their ordinary service behavior. The program or benchmark runs
once for each newly admitted operation; its outcome is not cached. Run and
executing Bench return diagnostics and status without publishing an artifact
destination. Planning still uses closed stdin independently of execution.

Use these native `rabsd` entry points for the explicit stdin policy. The legacy
`cargo rabs` launcher retains its existing profile whitelist and remote Run/Bench
restriction. No live stdin stream is forwarded by the remote protocol.

#### Run with a captured input file

Native local, shared and remote profiles can instead select
`"stdin_file": "inputs/request.bin"` for Run, executing Test, or executing Bench. The name is
relative to the approved `source_root`, independently of the selected manifest's
directory. For a remote profile, put it in `settings`:

```json
{
  "command": "run",
  "stdin_file": "inputs/request.bin",
  "manifest": "app/Cargo.toml",
  "selection": {"bin": ["analyze"]},
  "jobs": 2,
  "timeout_seconds": 1800
}
```

Use `rabsd --canonical-compile-local PROFILE.json` or
`rabsd --canonical-compile-remote PROFILE.json`; a local profile may also name
`service_socket`. Omit `stdin` when selecting `stdin_file`: combining the two
is an error. Check, Build, Clippy, Doc, `test --no-run` and `bench --no-run` do not
accept this field. Their existing EOF behavior is unchanged.

For a test harness that reads standard input, select `"command": "test"` and,
for example, `"selection": {"test": ["parser"], "test_args": ["--nocapture"]}`.
Captured input is supported for both ordinary libtest and `harness = false`
targets; select arguments that the chosen harness supports. The native frontend
exposes this directly:

```sh
rabs-cargo --remote REMOTE.json --stdin-file fixtures/request.bin \
  -- test --test parser -- --nocapture
rabs-cargo --local LOCAL.json --stdin inherit \
  -- test --test parser -- --nocapture < fixtures/request.bin
```

Input is shared with Cargo descendants using Cargo's ordinary descriptor
inheritance; it is not duplicated independently for every selected harness.
A literal `--no-run` after the harness separator remains a harness argument and
does not turn an executing selection into compilation-only work.

The selected file must already belong to the captured compiler-visible
workspace. Absolute paths, traversal, symlinks, missing files and isolated
Cargo-home transport members cannot become input. Existing source capture
exclusions, file counts and the 512 MiB aggregate source limit still apply;
`stdin_file` cannot request an extra client or coordinator pathname. The bytes
travel through the ordinary verified source upload, including its existing
whole-file and prefix reuse.

After source sealing, the operation copies this exact member into private
descriptor custody, verifies its checksum, and gives Cargo one read-only regular
file at offset zero. Cargo decides which descendants inherit it, as with an
ordinary redirected Cargo invocation. Planning receives EOF and never consumes
the file. File bytes, identity and ownership are checked again before spawn and
after the process group drains. Client or service stdin is not read. Empty files
produce EOF, binary data is preserved, and a new admitted command starts from
offset zero even when its compiled targets are fresh.

The original operation retains this input across a connection interruption;
reattachment cannot reopen a host pathname, rewind the running command or execute
it again. Test, Run and Bench outcomes remain uncached. The native Cargo/namespace
fixture `canonical_captured_stdin_run_test_and_bench_execute_current_bytes_locally_and_in_service`
checks current file contents, client-input isolation and repeated execution on
a capable host; its presence does not establish native or fleet qualification.

### Share a canonical coordinator across concurrent commands

An optional persistent service keeps one coordinator authority, CAS and dependency
worker pool alive across local canonical commands. Each admitted command still
captures its own inputs, runs its own Cargo process and uses private workspace,
target, temporary and wrapper-endpoint directories. The service shares immutable
results and the existing action ownership machinery; it does not share a writable
Cargo target or make fresh-only workspace actions cacheable.

Create the same private state directory used by the command profiles, then save
this service configuration with your actual paths:

```json
{
  "version": "canonical-compile-service-v1",
  "state_root": "/home/builder/rabs-compile-state",
  "socket": "/home/builder/rabs-compile-state/compile.sock",
  "max_roots": 4,
  "max_queued_roots": 16,
  "jobs_per_root": 2
}
```

Start the installed native service:

```sh
rabsd --canonical-compile-service ./canonical-service.json
```

Configure the service process's dependency-worker pool and mutual-TLS environment
before startup, using the worker settings above. The service reads that operator
configuration once. A submitting client's worker environment cannot replace the
service's pool or credentials.

Service startup binds every configured dependency-worker endpoint before
announcing readiness. Each configured worker has one listener owner thread,
at most one authenticated idle connection, and at most one pending or active
transport assignment. The existing 1–32 worker limit bounds these owners. A
failed endpoint bind refuses startup and closes the endpoints already started.
The service's existing request queue continues to own work waiting for a slot.

Standby first verifies the worker's TLS public-key pin, configured name and
TLS-derived peer identity, then selects the explicitly advertised
`worker-standby-v2` exchange. The coordinator sends a heartbeat every 15 seconds;
each ping and matching pong share a 10-second budget. The worker allows at most
45 seconds for the next complete idle record. A failed heartbeat closes that
connection so the worker's outward loop can reconnect to the same listener.
Confirmed readiness also wakes queued placement and clears the endpoint's
connection cooldown.

Workers include their measured one-minute CPU load in the authenticated hello
and refresh it in idle heartbeat replies. Among compatible ready workers, the
pool prefers lower load per advertised CPU. Equal scores retain round-robin
order. Unknown measurements and samples older than 30 seconds at the coordinator
keep their round-robin positions; load never excludes a worker or grants another
slot. A disconnected or replaced connection loses its pressure hint together
with its readiness. Capability checks and ordinary execution admission still run
after placement.

An assigned request starts ordinary session admission with a fresh 10-second
challenge budget. An outstanding heartbeat must finish before this transition.
The durable worker incarnation checks, request identity, live-action admission
and execution lease are established for that request; idle heartbeats allocate
none of them and leave the worker's execution journal unchanged. Each connection
still carries one operation. After verified completion, the worker reconnects
and can wait for the next command. A peer without standby support can use
ordinary admission when an assignment is already waiting, but is not retained
as an idle peer.

Shutdown stops new worker reservations, wakes idle acceptance and heartbeat
waits, and cancels pending assignments. Active operations retain their existing
cancellation, cleanup and verified-delivery ownership. The service joins each
listener owner before releasing its coordinator authority and state lock;
restarting the service can bind the same configured endpoints while the workers
continue their outward reconnect loops. A possible execution remains subject
to the existing recovery restrictions throughout this drain.

Add the existing socket to each local canonical profile, keeping its `state_root`
equal to the service's state root:

```json
"service_socket": "/home/builder/rabs-compile-state/compile.sock"
```

Both `cargo rabs --rabs-canonical-local PROFILE.json -- ...` and the native
`rabsd --canonical-compile-local PROFILE.json` entry point then submit to that
service. Neither starts another coordinator nor silently falls back to direct
execution when the service is unavailable. The socket must already exist, be
owned by the current user and private, and have ordinary directory ancestors.
It must be outside captured source, toolchain, optional Cargo-cache and operation
roots. A socket inside the private state root is supported and never enters a
build namespace.

`max_roots` bounds simultaneous admitted operations. Set `max_queued_roots` to
0–128 to retain a bounded number of additional callers; its default is zero,
which preserves immediate busy refusal. Validated waiting requests enter a FIFO
queue before any source/toolchain capture or Cargo process begins. Each waits
at most its profile's `timeout_seconds`. Disconnect, cancellation, service
shutdown and expiry remove only that caller, including the queue's head, so
later callers can advance. The service reports `canonical-service-queued` with
an admission ticket on its diagnostic stream. Once active and waiting slots
are full, further clients receive a busy refusal before capture. Handshakes and
result delivery also count against the bounded connection capacity.
Each profile's `jobs` must be at most `jobs_per_root`, and a root retains its
admission through process and stream drain. Independent roots can compile
concurrently while sharing the same coordinator generation. Eligible identical
dependency actions use the existing singleflight, sampling and replay gates.
With isolated dependency workers configured, acknowledged dependency and
workspace requests enter the same bounded service-owned queue when the pool is
busy or cooling down. Identical dependency requests join one queued or active
execution. Each workspace request instead gets its own queue identity and
executes afresh, even when its inputs match another caller's. Waiting requests
retain their captured inputs without occupying a worker, creating a compiler
lease or starting a waiting producer thread. The dispatcher wakes on admission,
worker or action-key release, cancellation and connection-cooldown deadlines.

Workspace requests for the same action retain FIFO order. A request waiting for
an earlier execution of that key does not prevent unrelated ready actions from
using idle workers. Cancelling a workspace caller removes only its own queued
or running work. For a shared dependency execution, cancelling one subscriber
removes only that subscriber's interest; the final departure requests
cancellation. The service retains each started transport until verified
completion or an explicitly uncertain outcome with retained recovery state.
Service shutdown cancels and joins these owners before releasing coordinator
authority.

An actual transport interruption before the coordinator starts writing the
compiler execution request can now move that same producer to an available
alternate worker. Placement permits at most two alternate attempts and never
returns to a previously tried worker. Its immutable inputs, subscribers, action
generation and dispatch claim stay together. An admitted retry receives a fresh
attempt and execution lease only after the prior attempt's exact lease and
worker session have been checked released. Late messages from that prior
attempt cannot advance or complete its replacement. Each worker receives a
fresh durable request ID and its own recovery directory.

This failover is limited to transport failures with explicit evidence that no
execution request may have reached the worker. Compiler failures, malformed
inputs, authentication refusals and caller cancellation do not trigger it. If
no untried worker is immediately available, the producer settles the confirmed
pre-execution failure instead of holding a thread waiting for another slot.
Once any execution-frame write may have occurred, the same failure remains
uncertain: its recovery record is retained and it cannot authorize another
worker execution or local fallback. The admitted and failover events report
the participating workers; admission events also report the actual generation,
attempt and lease identities for diagnosis.

Each subscriber retains its own input observations and target mapping.
Compilation never writes a target by itself: each caller must acknowledge the
exact completed manifest before its own bounded installer runs and revalidates
its inputs. New dependency callers cannot join a completed execution; they pass
the ordinary cache and verification gates. A workspace result remains owned by
one request and can be consumed only once. Queuing does not publish it, add
verification evidence, authorize replay or make workspace actions cacheable.

The service bounds active producers by the configured worker count and retains
at most 256 requests across both dependency and workspace classes. This combined
limit includes offers awaiting acknowledgment, queued requests, active work and
completed results awaiting installation; identical workspace keys still count
as separate requests. The service reports `queued-request-owned` and a distinct
`queue_request_id` for accepted workspace demand. This identifier is local to
the service and identifies queue ownership, not a compiler attempt or worker
request.

Queued work has a five-minute admission budget. Expiry before dispatch returns
an action-bound failure confirming that execution did not begin, allowing the
caller to compile locally. Cancelling a queued workspace request or losing the
final queued dependency subscriber promptly releases that demand and its
retained inputs without waiting for a busy worker. Execution uncertainty after
dispatch retains the existing recovery and fallback restrictions.

Remote actions also reuse verified dependency input bytes across overlapping
artifact inventories. The coordinator retains immutable bytes for the exact
file generation and content digest, checks each caller's descriptor and complete
inventory, and reuses the existing transfer digest. The process-wide byte cache
retains at most 512 MiB and 4,096 entries, including captures in progress and
objects held by active uploads. Active uploads prevent eviction. If the cache
is full, ordinary verified capture proceeds within the existing per-upload
bounds. Cancellation releases unfinished captures; worker-side verification of
received bytes remains mandatory.

Workers reuse verified source and dependency objects when negotiating the exact
missing-file list. A warm object is first captured into an independent verified
file, then imported as a whole manifest member. The import tries the existing
filesystem-tested copy-on-write clone and otherwise copies with bounded buffers;
it does not repeat transport chunk encoding and hashing for bytes already on
the worker. Both paths check the complete file digest and keep a distinct private
inode. The final source-tree seal still verifies every declared member before
execution. Upload cancellation reaches cache reads, imports, final sealing and
Cargo-home preparation between bounded chunks; the worker joins its input task
before releasing that task's custody. Once verified source custody passes to
execution, dropping the upload task cannot revoke the executing source.

Preparation's Cargo metadata, package selection, rustup and Git subprocesses use
the same root broker, so preliminary work cannot exceed the configured process
root limit. Source capture, cache expansion, hashing, materialization and final
source sealing observe operation cancellation between bounded chunks.

The service captures each selected toolchain once and retains that exact image
across operations. Concurrent requests for the same original toolchain share one
capture; subsequent requests check the original source and retained filesystem
generations without recopying or rehashing the complete toolchain. A changed
source selects a fresh image. Active operations keep their earlier immutable
image until planning, execution and any worker upload have finished. Remote
dependency execution uploads from this same retained owner, avoiding a second
coordinator-side toolchain copy.

Retention is bounded to four images, including preparation and old generations
still held by active operations. An image with an outstanding lease cannot be
evicted. Each image also obeys the existing toolchain entry/byte limits; this is
not a filesystem free-space quota. One capture runs at a time, and a caller
waiting for capacity observes its timeout and cancellation. Cancelling a client
does not cancel another client's shared preparation. The service owns that
preparation with an independent 120-second cooperative deadline and cancels and
joins it during shutdown. Images are private to this service lifetime; restart
captures them again.

The service supports `check`, `build`, `clippy`, `doc`, `test`, `test --no-run` and
`bench --no-run`. Native profiles also support `run` and executing `bench` with
explicit `"stdin": "closed"` or a captured `"stdin_file"`. Executing `test` can
also select captured input while retaining EOF by default. The service never
forwards inherited input.
Profiles retaining inherited stdin refuse before capture. Test, program and
benchmark bodies still run on each newly admitted operation and retain their
actual failure status.

Compiler stdout and stderr stream to the client while Cargo is running. Private
bounded files separate process-pipe drainage from a slow socket consumer, and
independent read cursors preserve each stream's exact bytes without changing the
writer's offset or inventing cross-stream ordering. Completion drains the last
tail once; already visible prefixes are not replayed. Combined
Cargo output is bounded at 64 MiB, with a separate 128 MiB protocol limit including
planning and driver diagnostics. Disconnecting the client or exceeding an output
bound cancels and drains that operation; this interface does not create a detached
recoverable background job. Service shutdown stops admission, cancels and joins
its active operations and shared remote executions, then releases coordinator
authority.

### Submit from separate hosts to the shared coordinator

The installed native commands expose the shared canonical runtime to explicitly
enrolled clients over pinned mutual TLS:

```sh
rabsd --canonical-compile-remote-service ./remote-service.json
rabsd --canonical-compile-remote ./remote-build.json
```

Run the first command on the coordinator and the second on a client. Each client
captures its approved source/dependency closure and complete toolchain, then
uploads the exact bytes requested by the coordinator's verified input plan. The
coordinator allocates private input and operation directories and runs the
existing canonical Cargo driver. Cargo plans at the
same stable paths used by local canonical operations. Eligible concurrent
dependency requests from different clients can join one shared execution, while
each operation keeps its own source observations, Cargo process, target,
wrapper endpoint and cancellation owner. Results are installed independently at
each client's explicit output destination.

Install matching `rabsd` builds on the clients and coordinator, and a matching
`rabs-wrap` on the coordinator. Both sides require Linux. The coordinator must
pass the complete production namespace probe, and the captured toolchain must
support nightly Cargo unit-graph planning and run on that coordinator. The
existing source, dependency, environment and execution-host restrictions still
apply. Configure dependency workers on the coordinator using
[the existing pinned worker setup](#send-canonical-dependency-compilations-to-workers)
to share eligible remote metadata and archive compilations. Worker identities,
credentials and listeners are selected by the service operator.

#### Enroll client and coordinator certificates

Provision a trusted CA, a coordinator server certificate, and a separate client
certificate/key for each enrolled edge host. The coordinator certificate must
cover the client's configured `server_name`. Certificate-chain validation and
explicit SPKI SHA-256 pins are both required: the client pins the coordinator,
and the service accepts only its enrolled client keys.

Obtain each pin from the corresponding trusted certificate:

```sh
openssl x509 -in /credentials/coordinator.pem -pubkey -noout |
  openssl pkey -pubin -outform DER |
  openssl dgst -sha256

openssl x509 -in /credentials/edge-a.pem -pubkey -noout |
  openssl pkey -pubin -outform DER |
  openssl dgst -sha256
```

Copy only the resulting 64 lowercase hexadecimal characters, without the
OpenSSL label, into the appropriate profile. Replace all example addresses,
paths and pin placeholders below. Keep certificate private keys outside captured
source and toolchain roots. The profile's `tls` fields configure this dedicated
client-to-coordinator transport; dependency-worker TLS remains separately
configured through `RABS_COORD_TLS_CA`, `RABS_COORD_TLS_CERT` and
`RABS_COORD_TLS_KEY` on the coordinator.

#### Start the coordinator

Create three pairwise disjoint, owned private directories. Existing directories
must already have mode 0700; the service does not repair their permissions.
Keep the operation root short enough for its operation-scoped Unix sockets:

```sh
mkdir -m 700 /home/builder/rabs-remote-state \
  /home/builder/rabs-remote-inputs /tmp/rabs-remote-ops
```

Save the complete service profile as `remote-service.json`:

```json
{
  "version": "canonical-compile-remote-service-v1",
  "listen": "192.0.2.10:45300",
  "state_root": "/home/builder/rabs-remote-state",
  "input_root": "/home/builder/rabs-remote-inputs",
  "operation_root": "/tmp/rabs-remote-ops",
  "wrapper": "/usr/local/bin/rabs-wrap",
  "tls": {
    "ca": "/credentials/ca.pem",
    "certificate": "/credentials/coordinator.pem",
    "private_key": "/credentials/coordinator.key"
  },
  "allowed_edge_pins": [
    "REPLACE_WITH_EDGE_A_64_LOWERCASE_HEX_DIGITS"
  ],
  "max_roots": 4,
  "max_queued_roots": 16,
  "queue_timeout_seconds": 300,
  "source_cache_bytes": 536870912,
  "toolchain_cache_bytes": 8589934592,
  "toolchain_cache_entries": 4,
  "toolchain_file_cache_bytes": 8589934592,
  "target_cache": {
    "runtime_epoch": "builder-image-2026.10",
    "max_bytes": 1073741824,
    "max_families": 8
  },
  "jobs_per_root": 2
}
```

`listen` is an IP address and port bound on the coordinator. The three storage
roots must have ordinary absolute paths and no symlink ancestry. The wrapper
must be an ordinary executable outside those mutable roots. `allowed_edge_pins`
accepts 1–256 distinct nonzero client-key pins. `max_roots` accepts 1–32 and
`jobs_per_root` accepts 1–4096, with at most 4096 aggregate jobs. Each admitted
operation holds its root slot across input transfer, execution and final
delivery, bounding simultaneous work even while inputs are uploading.

`max_queued_roots` accepts 0–128 and defaults to 0. Set it above zero to let
authenticated clients wait when the active roots are occupied. Requests keep
FIFO order within each authenticated client key; the coordinator schedules fair
turns between keys. The example admits four operations and bounds additional
waiting requests at sixteen.

Each enrolled client also has a fixed waiting allowance: divide
`max_queued_roots` by the number of `allowed_edge_pins`, round down, and use at
least one slot when queuing is enabled. With four waiting slots and three
clients, each client can retain one waiting request. The remaining slot stays
unassigned so earlier clients cannot consume a later client's share. A single
enrolled client retains the entire configured queue. The existing service-ready
event reports the computed `max_queued_roots_per_peer`.

Available active-root capacity remains usable by any client. When there is no
backlog, enqueue grants that capacity atomically; concurrent callers cannot
claim the same idle slot. An unclaimed grant releases its capacity when its
owner is dropped. Once work is queued, new arrivals cannot bypass its existing
fair turn. Cancelling a waiting request removes only that request and frees
its peer's allowance; starting it moves the capacity into the active-root bound.

When the queue can hold at least one request per enrolled client, one peer
cannot exhaust another peer's waiting allowance. Rounding down leaves at most
`enrolled_clients - 1` waiting slots unassigned; active-root capacity remains
available.
If the configured queue is smaller than the enrollment, the global queue bound
still applies and all clients cannot hold waiting requests simultaneously.
These quotas apply after authentication and request validation; they do not
reserve listener connections or TLS-handshake capacity.

At the coordinator, a queued request retains only its connection and bounded
declaration. It receives no input tree or compiler tokens and cannot start
uploading or execute Cargo until admitted. The client keeps its already
captured inputs while waiting.

`queue_timeout_seconds` accepts 1–1800 and defaults to 300. The queue deadline
is fixed when a validated request enters admission; progress polls do not renew
it. The same fixed deadline bounds SDK selection, verification and source-cache
prefill before Ready, including any wait for another admitted operation's cold
SDK upload. Acquiring a root slot does not reset that deadline. Client
cancellation, disconnection, timeout or
service shutdown releases that caller's waiting state without cancelling another
caller. The Cargo frontend waits on the same authenticated connection and starts
uploading only after Ready grants its input phase. It does not resubmit the
operation. Ready starts a fresh, fixed 35-minute input-transfer budget; cached
source preparation does not consume it. If all connection slots are occupied,
the service still closes excess connections before
authentication, without a plaintext response.

Simultaneous admitted operations with the same authenticated client key and
complete SDK identity share one cold upload. One caller uploads; existing
followers receive Queued/Poll replies until its SDK is completely sealed and
verified, then receive Ready with SDK reuse. Followers retain their operation
permits but create no source or SDK input trees while waiting. If the uploader
disappears, a surviving follower may become the uploader before Ready, within
its original deadline. This never retries a Cargo execution.

Cold upload sharing also works when persistent SDK caching is disabled or full.
The pending registry contains at most 32 weak entries, independently of retained
cache capacity. A completed flight is removed from that registry before existing
followers receive its exact lease; later requests must use the ordinary cache or
start a new upload. Only active admitted operations retain an uncached shared SDK.
The registry cannot prolong its lifetime, and neither source trees nor command
results are shared. Root-queue capacity and this waiting state are separate:
`max_queued_roots: 0` still allows an already admitted operation to wait for a
matching SDK upload.

The service can retain already uploaded SDKs for subsequent operations.
`toolchain_cache_bytes` defaults to 0 (disabled) and accepts at most 64 GiB;
`toolchain_cache_entries` defaults to 4 and accepts 1–32. The example enables
an 8 GiB, four-image cache. Both limits apply to retained SDKs, including images
still leased by operations or downstream uploads. Idle images may be evicted;
a full or disabled cache still admits a normal private upload. These are
logical retained-byte and image-count limits, separate from active operation
input limits and filesystem free-space admission.

Reuse requires the same enrolled TLS client key and complete toolchain dataset
identity. The service verifies the cached image again before selecting reuse.
Concurrent requests for the same retained image can share one in-progress byte
scan; each caller independently checks its owner and complete retained generation
before and after that scan. Completed checks are never memoized, and cancelling
one caller does not cancel another caller's wait or authorize partial results.
The client then transfers the requested source bytes without SDK entries or SDK
chunks. Every operation keeps its own source, runtime and output directories; a cached
SDK retains only its dedicated compiler directory. Changes to the retained SDK
or its ownership invalidate that generation and refuse the affected operation.
A cache failure never causes a second execution, reconnection or local fallback.

This cache lasts for the service process. A service restart requires a new SDK
upload; no directory is adopted from a pathname or an old on-disk marker. The
client still captures and validates its local SDK on each invocation. Reuse
removes repeated SDK network transfer and reconstruction; it does not eliminate
local capture or verification, and no end-to-end speedup is claimed here.

`toolchain_file_cache_bytes` independently enables completed-file and partial-file
SDK reuse. It defaults to 0 (disabled) and accepts at most 64 GiB. The example
retains up to 8 GiB of SDK byte objects in addition to its complete-image cache.
All authenticated clients share that one byte budget, object-count limit and
nonblocking writer lock. Content names are partitioned by the TLS client key;
one client cannot discover or reuse another client's retained file or prefix.
These byte objects carry no SDK identity or execution authority. Like the
complete-image cache, this optional storage lasts for the service process.

Complete-image reuse takes precedence. On a cold SDK upload with file caching
enabled, Ready selects `upload-files`. After the source window is acknowledged,
the client declares regular SDK members in ordered pages of at most 64 files
and 256 KiB. The service returns complete-file hits and bounded prefix offers
from private snapshots. The client independently hashes each offered prefix
from its retained SDK before choosing that offset; a mismatched prefix selects
zero. Every directory, symlink and regular-file entry still travels, with an
explicit file cursor, and the usual four-frame window carries missing bytes.
The service verifies each imported range and seals the complete reconstructed
SDK against the original dataset identity before admitting execution.

An interrupted upload can therefore leave completed files and a bounded current
prefix for a later request by the same authenticated client. Changed SDK images
can reuse unchanged member bytes while still proving their own complete image.
An interrupted input upload is not automatically resubmitted. This cache provides
input-byte recovery for a later deliberate request; accepted-operation recovery
uses the separate live ownership mechanism described below. The original fixed
35-minute input budget includes negotiation,
snapshot import, network transfer and final verification, with cancellation
checks between bounded copies.

Cache contention, missing objects or optional checkpoint storage failures leave
ordinary upload available. Once a range has been selected, a corrupt snapshot,
unknown cursor, altered entry or invalid source cannot silently become a miss.
A valid SDK whose extra file inventory would exceed the existing 64 MiB metadata
limit explicitly declines optional file negotiation before its first page and
uses the ordinary upload path. The final SDK limits and seal are unchanged.
Temporary hit snapshots remain bounded by the smaller of the SDK size and cache
capacity, separately from retained bytes and each operation's fresh input tree.

The optional `source_cache_bytes` setting retains verified source-file bytes for
later requests. It defaults to 0 (disabled), accepts at most 8 GiB, and uses one
aggregate budget of at most 4096 objects across all enrolled clients. The example
enables 512 MiB. Objects are scoped by the client key authenticated by TLS and
their content digest; another client key cannot reuse those bytes. The service
owns a private pool for its process lifetime. A restart starts a fresh pool and
does not adopt old cache directories. This budget is separate from SDK retention,
Cargo target state and active operations' private input trees.

Every request still sends its complete `SourceManifest`. Ready includes a
`SourcePlan` binding that manifest's digest to a strictly increasing list of
missing nonempty-file indices in canonical manifest order. The coordinator
imports verified cache hits into a fresh private receiver before sending Ready.
The client validates the plan, checks **every captured source member**, including
omitted and empty files, and uploads only the requested members. Each operation
still requires a complete fresh server-side seal before execution; imported bytes
and mutable execution files never share writable inodes. Source chunks outside
the frozen missing-file plan are terminal protocol errors.

Completed files and bounded partial-file checkpoints can seed later transfers
even if an upload stops before the complete tree is sealed. Ready may offer an
incomplete file's index, byte offset and SHA-256, with at most 256 KiB of prefix
metadata. Offers refer to one frozen private snapshot bounded by the declared
source bytes and the existing cache budget. They are byte-reuse hints, never
execution or action-cache authority.

The client hashes the offered range from its independently verified local source
checkpoint. A match sends only the missing tail; a mismatch starts the ordinary
upload at zero. The first source chunk's offset selects exactly that frozen
offer or zero. No extra round trip is added, and the existing four-frame upload
window remains unchanged. The coordinator imports a selected prefix only once,
checks the complete file and still requires the final complete-tree seal. This
also applies to declared Cargo-home registry inputs. Wire version
`canonical-compile-remote-v12` and the exact tool build identity must match before
the service admits inputs; update the client and service together.

The preparation budget bounds snapshot capture. Readiness grants the existing
separate fixed input budget to both the receiver and its frozen snapshots;
chunks, retries and prefix selection cannot renew it. Cancellation is checked
between bounded copies. Missing, evicted or unavailable cache objects request
ordinary upload. Once an import has started, a verification or cancellation
failure cannot become a cache miss in that receiver. Optional cache-write
contention or storage failure can skip retention, but cannot hide invalid source
bytes or authorize a partial tree. Accepted partial bytes share the same object
quota and byte budget as complete files, and failed replacement preserves the
previous acknowledged checkpoint.

The optional server `target_cache` object retains Cargo's private compilation
state across remote operations and service restarts. It uses the existing
[persistent target cache](#persistent-reuse-and-command-results), including its
required host `runtime_epoch`, exact compatibility checks, private copies,
transaction recovery and producer verification. Omit the object to start every
remote operation with a cold Cargo target. Its default retention is 1 GiB and
eight families; the limits are 8 GiB and 32 families. These are one aggregate
budget for the service, shared across enrolled clients, independently of the
SDK cache and active operation storage.

Remote target families also bind the client key authenticated by TLS. A
different client key or a local canonical command cannot restore another
client's target, even when source and compiler identities match. The client
cannot provide this scope, a cache directory, or target-cache policy through its
remote settings. Every operation still declares its complete source, seals a
fresh input tree, uses an independent runtime workspace and target, and executes
the selected Cargo command. Timestamp restoration only touches that runtime copy; the original
received source remains available for final verification. Compiler-only checks
retain the existing eligible source-edit behavior; codegen, Clippy and graphs
with project executors keep the complete captured source identity.

Successful restore can let Cargo report existing units as Fresh. Current
coordinator publication, qualification and producer ancestry are rechecked
before execution and completion. Stored target bytes never become a cached
command result or bypass final artifact delivery verification. Changing the
host tools or libraries visible through `/usr` requires a new `runtime_epoch`.

Set the coordinator's dependency-worker environment before starting the service.
For example, a single worker uses its own listener, separate from the remote
client listener above:

```sh
RABS_COORD_TLS_CA=/credentials/worker-ca.pem \
RABS_COORD_TLS_CERT=/credentials/worker-coordinator.pem \
RABS_COORD_TLS_KEY=/credentials/worker-coordinator.key \
RABS_DEPENDENCY_WORKER_LISTEN=192.0.2.10:7092 \
RABS_DEPENDENCY_WORKER_ID=leaf-worker \
RABS_DEPENDENCY_WORKER_SPKI_SHA256=REPLACE_WITH_WORKER_64_LOWERCASE_HEX_DIGITS \
  rabsd --canonical-compile-remote-service ./remote-service.json
```

The worker must run its normal outward connection loop against the dependency
listener. A pool uses `RABS_DEPENDENCY_WORKERS_JSON` in place of the three
singleton worker fields. The service owns that configuration and its shared
coordinator authority for its whole lifetime. Client requests cannot choose
worker endpoints, coordinator storage paths, wrapper executables or mount rules.

#### Submit a captured client operation

On the client, create a private staging root and a separate private output
parent outside the source, toolchain and optional Cargo-cache roots. The final
output destination must be absent; do not create it in advance:

```sh
mkdir -m 700 /home/dev/rabs-remote-staging /home/dev/rabs-remote-results
```

Save this complete client profile as `remote-build.json`:

```json
{
  "version": "canonical-compile-remote-v1",
  "coordinator": "192.0.2.10:45300",
  "server_name": "rabs-coordinator.internal",
  "coordinator_pin": "REPLACE_WITH_COORDINATOR_64_LOWERCASE_HEX_DIGITS",
  "tls": {
    "ca": "/home/dev/credentials/ca.pem",
    "certificate": "/home/dev/credentials/edge-a.pem",
    "private_key": "/home/dev/credentials/edge-a.key"
  },
  "source_root": "/home/dev/projects/approved-anchor",
  "toolchain_root": "/opt/rust/native-nightly-toolchain",
  "staging_root": "/home/dev/rabs-remote-staging",
  "output_destination": "/home/dev/rabs-remote-results/build-001",
  "cargo_home_source": "/home/dev/.cargo",
  "settings": {
    "command": "build",
    "manifest": "app/Cargo.toml",
    "source_selection": "cargo-unit-graph-v1",
    "selection": {
      "workspace": true
    },
    "jobs": 2,
    "timeout_seconds": 1800,
    "env": {
      "APP_VERSION": "2026.11"
    }
  }
}
```

Invoke the installed client:

```sh
rabsd --canonical-compile-remote ./remote-build.json
```

`coordinator` selects the remote host and port. `server_name` is checked against
the coordinator certificate even when connecting by IP. All filesystem paths
in the client profile are absolute and refer to that client. The captured source
and toolchain are admitted as sealed datasets; the coordinator does not need
access to those original host paths. With SDK retention enabled, a verified
same-client cache hit transfers only the source dataset. The required `output_destination` names a
new directory whose immediate parent is owned and private.

`settings` uses the same logical command, manifest, selection and literal
environment contract as the canonical local profile. Defaults are `check`,
`Cargo.toml`, one job and 1800 seconds. Jobs must fit the service's per-root
grant. Omitting `selection` for Check retains its library-only default; an
explicit empty selection uses Cargo's ordinary default members and targets.
The remote service accepts Check, Build, Clippy, Doc, Test and benchmark
compilation with `"no_run": true`. Native settings also admit Run and executing
Bench with explicit `"stdin": "closed"` or a captured `"stdin_file"`; executing
Test also accepts captured input and otherwise defaults to EOF. Any inherited
stdin remains unsupported even when the client redirects its input: the service
does not forward that stream. Test, program and benchmark bodies still execute
for each newly admitted operation and retain their actual exit status.

For a vendored source graph, omit `cargo_home_source` and `source_selection`,
then add `"vendor": "vendor"` inside `settings`. For an entirely local graph,
omit both dependency-source choices. The
[selected source-preparation rules](#select-native-source-preparation) apply
when `source_selection` is enabled. The entire approved source anchor remains
the capture boundary. Client application environment is supplied only through
`settings.env`; worker, loader and canonical execution controls remain reserved.

#### Submit through Cargo with a reusable remote profile

The Cargo frontend accepts the native client profile above. For repeated
invocations, replace `output_destination` with `output_root`, an owned private
parent for fresh results. The launcher also accepts `"toolchain": "rustup"`
instead of `toolchain_root`, using the caller's selected installed toolchain.
For example, save this launcher profile as `remote-cargo.json`:

```json
{
  "version": "canonical-compile-remote-v1",
  "coordinator": "192.0.2.10:45300",
  "server_name": "rabs-coordinator.internal",
  "coordinator_pin": "REPLACE_WITH_COORDINATOR_64_LOWERCASE_HEX_DIGITS",
  "tls": {
    "ca": "/home/dev/credentials/ca.pem",
    "certificate": "/home/dev/credentials/edge-a.pem",
    "private_key": "/home/dev/credentials/edge-a.key"
  },
  "source_root": "/home/dev/projects/approved-anchor",
  "toolchain": "rustup",
  "staging_root": "/home/dev/rabs-remote-staging",
  "output_root": "/home/dev/rabs-remote-results",
  "cargo_home_source": "/home/dev/.cargo",
  "settings": {
    "manifest": "app/Cargo.toml",
    "source_selection": "cargo-unit-graph-v1",
    "jobs": 2,
    "timeout_seconds": 1800,
    "env": {
      "APP_VERSION": "2026.11"
    }
  }
}
```

Use the same client prerequisites, credentials and private parent directories
described above. The private key must remain outside the captured source,
toolchain and optional Cargo-home roots. Invoke the installed Cargo launcher:

```sh
cargo rabs --rabs-canonical-remote ./remote-cargo.json -- check --workspace
cargo rabs --rabs-canonical-remote ./remote-cargo.json -- build -p app --release
cargo rabs --rabs-canonical-remote ./remote-cargo.json -- test -p app -- --test-threads=1
cargo rabs --rabs-canonical-remote ./remote-cargo.json -- bench --no-run
```

Check, Build, Clippy, Doc, Test and nonexecuting Bench use the canonical Cargo
selection parser, including package, target, feature and profile choices.
Clippy requires the captured Clippy tools; Doc and executing doctests require
the captured rustdoc executable. The legacy Cargo frontend still refuses Run and
Bench without `--no-run` before dispatch. Use the native profile entry point with
explicit closed stdin for those commands.

The command line replaces any saved `settings.command` and
`settings.selection`; other settings remain in effect. With no Cargo command,
the launcher selects `check` with an explicit empty selection, so Cargo chooses
its ordinary default members and targets. It does not inherit application
environment variables into `settings.env`.

Each invocation retains a mode-0600 native `profile.json` inside a new
mode-0700 `staging_root/<command>-<token>` directory. Its capture directory is
private, and its output destination is the absent
`output_root/<command>-<token>` path. The launcher reports the retained profile
on stderr and invokes `rabsd --canonical-compile-remote` exactly once, preserving
the native client's output streams and exit status. It leaves the reusable
profile unchanged. Launcher-only `output_root` and `toolchain` fields are
resolved before the native client reads the retained profile.

Alternatively, retain an explicit `output_destination` for a one-off operation;
it must be absent, and it cannot be combined with `output_root`. The launcher
does not clear an earlier result. The selected launcher profile remains available
for inspection after failure or interruption. The surviving native client can
reattach to its accepted operation within the running service, as described below.
A failure does not trigger a local fallback or automatic resubmission.

#### Reuse previously downloaded artifact bytes

Repeated builds often return many unchanged dependency artifacts. To reuse
those local bytes when downloading a new result, explicitly select a previous
output directory:

```sh
RABS_REMOTE_ARTIFACT_REUSE_ROOT=/home/dev/rabs-remote-results/build-001 \
  cargo rabs --rabs-canonical-remote ./remote-cargo.json -- build --workspace
```

The native client reads this variable directly; the Cargo launcher passes it
through without adding it to `settings.env` or the compiled program's environment.
For a direct `rabsd --canonical-compile-remote` invocation, the native client
profile can instead contain `"artifact_reuse_root": "/home/dev/rabs-remote-results/build-001"`.
That field is a native-client option; use the environment variable with the
Cargo launcher. If both select different paths, preparation refuses. An empty
variable also refuses instead of selecting an implicit default.

The selected root must already exist, belong to the caller, and be private,
with ordinary directory ancestors. It must be disjoint from captured source,
toolchain, Cargo home, staging and the new output destination, and must not
contain the client's private TLS key. A previous output can share the new
output's parent. Existing outputs are never changed or merged into place.

After receiving the complete new artifact manifest, the client examines only
its declared file names in the selected root. A complete regular file with the
expected length and SHA-256 is copied or reflinked into fresh private staging
and verified again. Missing, unreadable or mismatching complete files are
downloaded normally. Symlinks and external hardlinks cannot supply reusable
bytes. The new manifest supplies each file's executable mode. Unrelated old
files are not copied, and no writable inode is shared with the previous result.
Cancellation or a mutation during an accepted import terminates the receive
operation; the client does not guess that a partial import succeeded.

For a shorter ordinary file, the client can freeze its current bytes into one
private anonymous snapshot and offer the file's index, prefix length and SHA-256.
The offers are bounded to 256 KiB of metadata, and snapshot bytes cannot exceed
the complete new manifest's artifact-byte budget. An unavailable snapshot or a
full offer budget leaves that file on the ordinary download path.

The service hashes the same range from its independently captured artifact. A
match sends only the remaining tail; a mismatch sends that file from offset zero.
The first actual payload chunk selects one of those two choices, so no extra
round trip is needed. The client imports a selected prefix from its frozen
snapshot exactly once before appending the tail. It never advances a receive
cursor without installing the actual bytes. An unexpected first offset, modified
snapshot, interrupted import, or final file-hash mismatch refuses publication.
Changes to the old file after capture cannot alter the frozen prefix.

The client requests only the sorted manifest indexes still needing payloads.
The service validates that request, retains the existing bounded transfer
windows, and verifies its entire captured target and original producer authority
before authorizing publication. The client still seals and hashes the complete
new tree and waits for the coordinator's exact commit before atomic installation.
An all-reused result goes through these same checks and acknowledgments.
Reuse work shares the original delivery deadline; it cannot extend that budget.

With reuse selected, stderr reports `canonical-remote-artifact-reuse` after the
complete local tree seal. `reused_files` and `reused_bytes` count complete files
imported locally. `offered_prefix_files` counts prefix hints, while `resumed_files`
and `resumed_bytes` count only prefixes the sender selected and the client
actually imported. `transfer_files` and `transfer_bytes` count received artifact
payloads. These counts exclude framing overhead and do not assert final commit
authorization, completed delivery or a measured build speedup.
The same explicit mechanism accepts a retained `.rabs-target-staging-*` directory
as hints for a deliberately submitted new operation, reusing complete files and
matching partial prefixes. It does not reconnect to a lost operation, suppress a
compiler invocation, or grant action-cache or Cargo freshness authority. Preserve and
inspect any uncertain prior result before deciding to submit new work.

#### Results, ownership and current limits

The client preserves Cargo's numeric exit status and separate stdout/stderr
streams. By default, stdout remains byte-exact. The client retains it in a
bounded private file while receiving progress.
Stdout is replayed once only after the authenticated terminal completion agrees
with Cargo's exit status and any returned target has been installed and verified.
This keeps Cargo's artifact announcements behind verified delivery. Stderr remains
live. An incomplete or invalid delivery does not expose retained stdout; a completed
failed command still publishes its diagnostics and preserves its nonzero exit.
A successful Build or Doc, or Test/Bench with `no_run`, transfers the
completed ordinary-file target tree and installs it at `output_destination`.
Successful Check, Clippy and executing Test return their status and diagnostics
without materializing that destination. The destination field remains required
for every profile, and an existing destination refuses instead of being merged
or overwritten. Choose a fresh destination for each intentional new operation.

#### Subscriber paths in remote Cargo JSON

The native remote client and `rabs-cargo --remote` accept an optional top-level
`stdout_presentation` field in the client profile. It is independent of
`settings`; it never enters the remote request, compilation identity or cache
key. Omitting it selects `"raw"`.

| Value | Published stdout |
| --- | --- |
| `raw` | Original Cargo and program bytes. |
| `cargo-json-source-paths-v1` | Translate recognized source and diagnostic paths to this client's source, toolchain and optional Cargo-home roots. Preserve artifact filenames, executable paths and complete build-script output records. This variant also works for failed commands and commands that do not install a target tree. |
| `cargo-json-subscriber-v1` | Translate recognized source paths and returned artifact paths. Every translated output file must belong to the verified installed manifest; output directories must be represented by installed descendants. A missing output mapping refuses the translated presentation. |

For example, add this field beside `source_root` in a native remote profile:

```json
"stdout_presentation": "cargo-json-source-paths-v1"
```

Source paths map from `/__rabs/workspace`, `/__rabs/toolchain`, and
`/__rabs/cargo-home` to the corresponding explicit client roots. Full subscriber
presentation also maps `/__rabs/out/cargo` to `output_destination`, subject to
verified manifest membership. Cargo's `package_id` remains its original identity.
Diagnostic messages, source snippets, labels, suggestions, build-script values,
and unknown records retain their meaning. Rendered diagnostic location headers
change only when their original path, line and column match structured spans.
Rustc's internal artifact notifications retain their original bytes.

The client validates the entire retained stream privately before publishing any
translated prefix, then verifies installed output custody again. An unsupported
record, unmapped path, unavailable output, ambiguous rendered location or exceeded
presentation bound selects the original **whole stream** instead. Stderr then
reports `canonical-remote-presentation-bypassed` with `requested`, `using: "raw"`,
and a content-free `reason`. It does not expose source text or client paths in
that status record, alter the compiler's exit status, or submit another execution.
Transport reattachment still uses raw byte offsets from the retained transcript.

JSON records are limited to 1 MiB before translation and 4 MiB after translation;
total presented bytes are limited to four times the existing retained-output
budget. Plain output streams in bounded chunks. After Cargo's valid
`build-finished` record, all remaining program bytes stay byte-exact, including
JSON-looking or binary output. Cancellation and the existing delivery deadline
remain active during validation and publication.

Relative rustc span paths remain unchanged: their base can be a workspace root
different from the selected manifest's directory, so the client does not guess
an absolute location. Source links identify the original captured roots; they
do not assert that the live checkout still contains the captured bytes. Select
the source-path variant when dependency artifacts are not returned; the full
subscriber variant must fall back to raw output if any requested artifact is
absent from the installed tree.

#### Delivery bounds and ownership

Source input remains limited to **512 MiB and 4096 regular files**. Source and
artifact manifests transfer in bounded pages, so a complete declaration may
exceed one 1 MiB ATP record without enlarging individual records or file limits.
The service verifies the complete source declaration before admitting input
bytes or reserving compilation work.

Artifact delivery is limited to **8 GiB and 16,384 regular files**, with at most
8 MiB of canonical manifest metadata. The complete
file set, lengths, executable identities and hashes are verified before atomic
publication. Symlinks, special files, external hardlinks, ambiguous paths and
oversized trees refuse delivery; the service never substitutes a successful
partial tree. Internal hardlink aliases become independent files. Files arrive
read-only, with mode 0444 or 0555 according to their executable bit, inside a
private 0700 target root. Empty directories, timestamps and hardlink topology
are not transported. These are detached build artifacts; this format does not
grant reusable Cargo target-state or action-cache authority on the client.

Explicit cancellation, terminal local/protocol failure, recovery expiry, and
service shutdown cancel and drain the original operation. Cancellation removes
only that operation's interest in a shared dependency execution; another client's
retained subscription can continue. Losing the last subscriber cancels the shared
producer through the existing ownership path. Service shutdown stops admission
and joins attached and detached operations and shared executions before releasing
coordinator authority. The service verifies the same installed build identity as
the client and cannot downgrade a client's required release-authorization policy.
Install matching client and coordinator binaries: paged source and artifact
manifests, source-file and partial-prefix negotiation, SDK file/prefix and image
reuse, artifact missing-file/prefix selection and operation reattachment use wire
version `canonical-compile-remote-v12`, while existing client and service JSON
profile versions remain unchanged. Older wire versions refuse before upload or
execution.

#### Recover an interrupted accepted operation

After input readiness, the client retains a random operation credential bound
to its authenticated TLS key and the coordinator's current authority incarnation.
The credential is issued before `InputsDone`, so a lost acceptance response can
be reconciled without guessing whether execution began. The original input owner
is the only path that can start Cargo. A resume request can take ownership of an
existing operation or wait briefly for its original connection; it cannot upload
inputs, reserve another build, select another coordinator, or start compilation.

When an accepted connection encounters a transport error, the surviving client
automatically reconnects to the same pinned coordinator for at most **60 seconds
per outage**. The service retains the existing operation for at most 60 seconds
while detached, within its original deadline. Execution and result delivery have
fixed deadlines; reattachment does not renew them. Every retained operation keeps
its admission permit, so active plus detached operations stay within `max_roots`.
The service allows bounded connection headroom for reattachment while an old
connection is still noticing a failure, without admitting extra builds.

The client reports the last complete record it successfully retained for stdout
and wrote for stderr. The same private stdout file survives transport reattachment;
wire offsets count the original received bytes, independently of later replay.
The server accepts only a previously acknowledged or actually offered complete
record boundary. It resumes diagnostics there, without silently skipping bytes
or printing an already exposed record again. A local spool or output write failure
is a terminal error, not a reason to reconnect or replay partially printed
diagnostics.

The native remote client writes to caller pipes and sockets using bounded
nonblocking output. Cancellation or the current operation/delivery deadline can
stop blocked live stderr or final verified stdout publication and cancel the
original operation without replaying output. Regular-file writes still depend
on filesystem and kernel latency; this does not make every filesystem call
interruptible or introduce an interactive terminal/PTY protocol.

During artifact transfer, the same private receiver stays alive across
connections. After verifying the identical replayed manifest, the client sends
its original missing-file/prefix selection and first incomplete file/byte cursor.
Completed local imports and downloaded files stay in that receiver. A previously
selected prefix is not imported again, and an accepted nonzero cursor takes
precedence over an original prefix offer. Untouched files can still select their
frozen prefix hints; reconnect never reads changed hints from the old tree. Every final
tree still passes the complete manifest, byte, mode and namespace seal before
the original coordinator authorizes publication.

If the client has already atomically installed the output, it retains an
`InstalledTarget` receipt with the original inventory, file and directory
identities, and parent/ancestor descriptors. Reattachment verifies that exact
tree and reconciles the original publication acknowledgment, without renaming or
overwriting the destination again. The service accepts this path only after it
authorized the original commit and rechecks its captured target and producer
provenance before returning completion. The client verifies the installed tree
again before reporting success. A final `Delivered` acknowledgment releases
retained service custody; losing that acknowledgment does not invalidate a
completion the client has already verified.

Cancellation first uses a usable attachment and can also use a short, separately
authenticated cancellation connection for the same token if the original wire
has failed. It cannot become a new execution. If the coordinator is unreachable,
the fixed detachment/execution deadlines provide the remaining cleanup bound.

This recovery requires the **same surviving client process and the same running
service incarnation**. Tokens and receiver/publication custody are not persisted
for client or service restart, failover, detached-job lookup, or later CLI resume.
Malformed protocol data, changed output, invalid credentials, cancellation and
authority changes refuse recovery. A failure outside the retained window can
still leave an installed output with an uncertain command result; preserve it
for inspection instead of automatically submitting another operation. Failed
receive staging remains private and retained.

Cargo and each operation's rustc endpoint run at the coordinator. The client
does not run an independent local Cargo driver against a distributed action
coordinator. This route extends the existing shared dependency runtime across
authenticated client hosts; complete M6 fleet scheduling, a measured multi-host
build storm and its performance targets still require their own qualification.
The Cargo frontend submits through this same native protocol and inherits its
live reattachment behavior. It does not add restart recovery or change the
service's admission and artifact delivery limits.

### Persistent reuse and command results

The direct driver or persistent service exclusively owns
`state_root/canonical-compile-v1`, including its CAS and state lock. Direct
invocations sharing an active state root return a busy error instead of
superseding its coordinator term; use `service_socket` for concurrent commands.
This separate namespace also keeps canonical compilation independent of a normal
daemon's CAS. Retain the state parent across commands; each command gets fresh
private target and source capture under `operation_root`. Direct invocations
also capture their toolchain there; the service instead holds its bounded shared
toolchain images under the locked state root.

To retain Cargo's own private target state between local canonical commands,
add this optional object to the same profile. Remote canonical services accept
the same object in their server profile:

```json
"target_cache": {
  "runtime_epoch": "builder-image-2026.10",
  "max_bytes": 1073741824,
  "max_families": 8
}
```

`runtime_epoch` is an operator-selected identifier for this host's tools and
libraries. Change it whenever host compiler/linker/runtime files visible through
the namespace's read-only `/usr` view change. Captured Rust toolchain bytes,
wrapper bytes, driver build identity, canonical environment and namespace,
Cargo target/profile and immutable source controls are bound automatically.
An epoch is required because a captured Rust toolchain alone does not identify
the host linker and system libraries. It accepts 1–256 ASCII letters, digits,
dots, underscores and hyphens. Omit `target_cache` to retain the original cold
target behavior, including when exercising dependency-cache sampling.

The default `max_bytes` is 1 GiB; the maximum is 8 GiB of retained snapshot
bytes across all target families. `max_families` defaults to 8 and accepts 1–32. Each family
retains one committed generation, so switching between compilation profiles,
toolchains, runtime epochs or source-control configurations can return to a
previous compatible target instead of always starting cold. A verified restore
or successful capture refreshes that family's recency. When either budget is
exceeded, the least recently used families are removed while preserving the
newly committed family. Setting `max_families` to 1 selects single-family
retention.

A replacement is fully captured before other healthy families are evicted to
make room for it. Startup also enforces newly lowered retention limits, giving
the selected family preference when its snapshot fits the new byte budget.
Atomic publication may temporarily retain the old aggregate plus one replacement
of at most `max_bytes`, with bounded metadata. Recovery handles each family's
pending/previous/committed transaction separately; pending data never becomes a
usable seed. The earlier single-family store is validated and moved into the
new family layout without copying its target files. Unknown entries or unsafe
filesystem aliases refuse optional cache use instead of becoming cleanup targets.

Every invocation still starts Cargo and admits its actual selected unit graph.
A usable seed is verified and copied or reflinked into a new private target;
its stored files are never mounted writable. Unchanged captured source files
receive their previous timestamps in a separate runtime workspace. Eligible
local source/data edits are stamped after every retained fingerprint; removed
or renamed inputs also dirty their surviving parent directories and manifests.
Cargo then decides which units rebuild. Compiler-only checks can retain this
source-edit family. Identical captured inputs can also reuse compatible build,
package and feature selections; toolchain, target/profile,
runtime epoch, lockfile, manifest, configuration and captured dependency changes
separate the seed family. Immutable registry/Git/vendor inputs remain exact.
This allows workspace crates to stay fresh without granting them action-cache
publication or skipping Cargo's current command.

Retained targets can also carry the provenance of qualified committed dependency
outputs that the driver actually verified and installed. That inventory is
covered by the target seed's integrity seal. After a complete independent target
restore and coordinator startup, the driver verifies the artifact bytes, current
publication and class eligibility, and complete producer ancestry, including
immutable-leaf qualification and quarantine. It then grants fresh installation
witnesses bound to this operation's files and coordinator. An eligible
metadata-check consumer can therefore use its committed-dependency cache after
a source edit while unchanged parents remain Cargo-Fresh, subject to the usual
sampling and input checks.

Verified terminal metadata completions have a separate inventory under the same
seed integrity seal. Each entry binds the terminal policy, action, descriptor,
manifest and installed metadata bytes. Restore verifies its own action, class
and output-object standing, together with any required producer ancestry, before
Cargo starts. Terminal entries never create dependency installation witnesses or
early metadata readiness, even when their metadata is nonempty. Both producer
and terminal completion standing are checked again before accepting the current
command's completion, including when optional target capture fails.

Completion-aware target seeds use payload version 2. An integrity-valid version
1 seed remains available for existing inventory and recovery bookkeeping but
produces a cold restore: it cannot prove whether a terminal fingerprint came
from a revoked cached result. A later successful capture replaces it through
the existing verified publication transaction. A failed or cancelled capture
does not discard the old seed.

Ordinary `check --workspace --lib --bins` and check-mode harnesses can leave
empty `.rmeta` files in those same dependency directories. Rust's crate locator
skips their metadata; RABS still hashes their exact paths and bytes, copies them
into the worker's read-only input view, and rechecks their original file
generations before upload and installation. These files require no committed
producer witness and never become producer ancestry. Empty metadata explicitly
named by `--extern`, an empty archive, an unqualified nonempty candidate, a
symlink, or a previously known producer truncated to empty still refuses cache
qualification. Removing or adding even an empty file changes the action key.
The first cold compile and the first warm compile with a new binary placeholder
therefore qualify separately under the existing comparison requirements.

Restoring target bytes alone never grants committed authority. Ordinary local
and request-owned results, unknown files and older seeds without recorded
provenance add no installation witnesses. This does not narrow the
complete-workspace action keys or relax the source-exact target families required
for code-generating graphs. If restored producer witnesses fail current
provenance checks, the operation fails before Cargo starts. Known producers are
checked again at the end of a retainable run, before accepting completion or
delivering retained build artifacts, so newly quarantined ancestry cannot become
an optional save failure.

The native tests
`canonical_warm_workspace_metadata_with_bins_preserves_committed_provenance_across_restarts`
and
`canonical_warm_mixed_metadata_with_bins_preserves_committed_provenance_across_restarts`
exercise this path with real Cargo, isolated workers and a separate stock
control. They alternate two source variants, restart the coordinator for every
operation, retain Cargo-Fresh parents, and earn library and terminal replay from
actual comparisons. They also quarantine a retained producer and require
rejection before Cargo starts. They require the
same full Linux namespace capability and matching binaries as the other native
cache fixtures; their presence is not evidence that they have run.

The same-family terminal regressions first earn a terminal cache hit, retain it,
and prove that an unchanged command can use Cargo Fresh. They then quarantine
that terminal action or a distinct real action in the same terminal class and
require refusal before Cargo starts, without changing the retained seed or
dispatching another worker request. These also require the full native fixture
environment.

The persistent service serializes target-cache I/O around open/restore and around
completed capture, releasing that lock while Cargo runs. Waiting for this lock,
scanning and hashing inputs, and copying target state observe the requesting
operation's cancellation. A disconnected or cancelled caller stops this work
and releases its admission; an interrupted restore cannot start a cold compiler.
An interrupted capture leaves the previous committed seed usable and the partial
candidate unpublished for ordinary recovery. A cancellation arriving after the
short atomic publication preserves that completed seed and stops output delivery.
A command may continue
from its independent target even if another command replaces or evicts the seed
it restored. Each successful save reopens its current compatibility family and
recalculates aggregate retention before publication; the last successful completed
save supplies that family's next seed. A failed candidate capture does not displace
a newer healthy generation. If another profile expanded retained state beyond an
older command's smaller cache limits, that older command skips its optional save
rather than discarding the newer families or exceeding its temporary byte bound.
Cargo's completed result remains unchanged.

Code-generating builds, all Test, Clippy, Doc, Run and Bench commands, and selected graphs with build scripts
or procedural macros use the **complete captured source identity** for private target reuse. An unchanged capture can
reuse its verified target, but any captured file edit starts that graph with a
cold target. Procedural macros may read data through ordinary filesystem calls
that do not appear in rustc's dependency information; changing only such a file
must invalidate the prior expansion even when Cargo would otherwise report the
consumer as fresh. Pure Rust codegen has a similar gap: LLVM assembler
`.incbin` reads can embed data without reporting it in rustc's dep-info.
Changing only that data must not return an old archive or executable. The more
selective source-edit reuse above remains available to compiler-only checks.
With multiple families retained, returning to an earlier exact source snapshot
can recover its own target state even after an intervening source edit or
build selected a different family.

The `canonical-compilation-started` stderr record reports
`private_target_state` as `disabled`, `cold` or `restored`, and
`restored_committed_outputs` counts the installation witnesses re-established
for this operation. A failed optional snapshot restore keeps its partial copy
unmounted and runs the current command cold, unless the operation was cancelled;
an optional storage failure during save preserves Cargo's actual result. Both
report a `canonical-target-state-unavailable` diagnostic. A new seed is saved only after
complete compiler/session/coordinator drain and a normal Cargo exit below 128.
An ordinary compiler or lint error can therefore retain successfully compiled
dependencies, and a failing test, program or benchmark can retain its compiled
artifacts. The next invocation still runs Cargo and reports the current outcome;
failed units and requested program or test bodies execute again. No command
failure becomes a cache result or successful build delivery. Retained committed
producers still require current valid publication authority before saving and
before a later Cargo invocation can use them as fresh inputs.
That same successful cold command can replace a seed after a failed restore.
An ineligible source edit or a failed private destination preserves a healthy
committed seed until that replacement succeeds.
Cancelled commands, direct signal termination, exits of 128 or higher, and
incomplete process-group cleanup cannot replace a seed. A failed optional
capture preserves the previous healthy generation. Successful build delivery still owns separate files,
so editing or running a previously delivered binary cannot alter the seed or
another invocation's outputs.

The ordinary fixed sampling policy requires an initial successful compiler
result and two matching real compiler comparisons before a subsequent eligible
request can skip rustc. Repeating the same eligible command four times against the same
state root exercises that progression. Adaptive sampling or a configured release
authorization policy can require additional evidence. This command loads the
same `[rabs]` configuration and environment overrides for build identity and
release authorization as the normal daemon. `required` remains enforced; the
profile grants no release verdict or preverified cache entry.

The stderr decision trail records `rabsd-live-dependency` events such as
`execute`, `hit`, `served`, and the specific reason for a fallback. A `hit` is an
offer; `served` follows the accepted, verified installation. Workspace crates
continue through the compiler even on a warm dependency action cache unless
Cargo itself finds them fresh in an explicitly enabled private target. Editing a
dependency's captured source or changing its exact upstream artifact inventory
changes the key or refuses reuse. Unsupported actions preserve ordinary rustc
execution rather than borrowing the external dependency class's evidence.

The actual compilation inherits stdout and stderr, delivering Cargo JSON and compiler
diagnostics as they are written with exact bytes and ordinary terminal/pipe
behavior. There is no delayed replay or retained copy of these streams. A slow
consumer backpressures Cargo while the process supervisor still enforces the
execution deadline and cancellation. Graph planning remains a bounded capture.
The command returns Cargo's actual status; a timeout, cancellation or incomplete
process-group cleanup is an error, including a child that exits zero while
handling cancellation.
Input/toolchain capture and the first graph proof precede the scoped daemon's
signal listener; they retain the existing bounded preparation behavior and the
namespace's die-with-parent boundary. Compiler execution after admission uses
the owned process group and coordinated shutdown path.
The coordinator drains its sessions and output writers before the private
operation directory is released. After Cargo's process group exits, admission
to the scoped endpoint is sealed and the coordinator retains authority while
acknowledged captures finish publication. This drain has a 60-second deadline;
expiration is reported as an error rather than silently losing the last unit's
publication or verification sample. A check returns diagnostics and success/failure;
its temporary target is released after optional private state capture. Persistent reusable dependency results remain
in the profile's CAS.

A successful `build`, `test --no-run` or `bench --no-run` moves its complete target tree, after that clean drain, to
a fresh private `operation_root/rabs-build-<random>/target` directory. The move
preserves the actual artifacts, executable permissions and inodes without a second
copy. Captured source, toolchain, Cargo home and control sockets stay in the
temporary operation and are released separately. Existing delivery directories
are never overwritten, and failed, cancelled or incompletely drained operations
do not expose a successful build delivery.

The native driver prints a `canonical-build-completed` JSON record on stderr
with the selected `command`, `tests_executed: false`,
`canonical_target: "/__rabs/out/cargo"` and the real `target_directory`.
Cargo's stdout and artifact paths retain their original canonical spelling; use
the reported target directory for the same relative output path. For example,
`/__rabs/out/cargo/release/server` is available as
`<target_directory>/release/server`; an explicit target triple adds its usual
subdirectory. A retained binary may be run directly when its normal target and
runtime requirements are met. RABS does not run it as part of `build`,
`test --no-run` or `bench --no-run`. Test and benchmark harnesses retain Cargo's
ordinary names under `debug/deps`, `release/deps` or the selected target/profile
directory. Each delivered command
has its own retained outputs; this is artifact delivery, not a shared writable
target cache or a request to skip Cargo's current command.

### Validate the real bridge

The ordinary native tests cover strict profile parsing, command-specific unit-graph admission,
read-only control/source mounts, retained state and output ownership, and the real scoped
socket's refusal of generic daemon capabilities while joining an open session:

```sh
cargo test -p rabsd --lib coord::canonical_local --locked
cargo test -p rabsd --test canonical_check_local --locked
cargo test -p rabs-sandbox --lib cargo_check --locked
cargo test -p rabs-sandbox --test cargo_check --locked -- --nocapture
```

The sandbox Cargo tests invoke the actual installed nightly Cargo, rustc and Clippy.
They check selected feature/target/profile graphs, real check metadata, build
archives, generated Rust from a build script, a functioning procedural macro,
a linked binary and compiled test harnesses. Build and no-run cases require
execution markers to remain absent. Test cases then verify filtering, repeated
execution when Cargo reports a fresh harness, doctest execution and the current
failure exit status. Clippy cases plan without compiling, then prove that lint
failures remain visible after a successful check and changes to lint levels.
Run cases resolve a default binary while excluding an invalid unrelated binary,
preserve literal arguments and binary input, and execute again when Cargo reports
fresh artifacts. Bench cases exercise custom harnesses, optimized and explicit
profiles, no-run compilation, repeated current execution and failures.
A wrong-profile negative control must fail compilation. These
cases validate command selection and its real Cargo outputs; they do not substitute
for the isolated worker/cache fixtures below.

The local canonical test fixtures require the full namespace and matching native
driver/wrapper binaries:

```sh
RABS_CANONICAL_TEST_WRAPPER="$PWD/target/debug/rabs-wrap" \
  cargo test -p rabsd --test canonical_check_local --locked \
    canonical_cargo_tests_deliver_no_run_artifacts_and_execute_each_current_run \
    -- --ignored --exact --nocapture

RABS_CANONICAL_TEST_WRAPPER="$PWD/target/debug/rabs-wrap" \
  cargo test -p rabsd --test canonical_check_local --locked \
    canonical_cargo_doctests_execute_with_captured_rustdoc_and_preserve_failures \
    -- --ignored --exact --nocapture

RABS_CANONICAL_TEST_WRAPPER="$PWD/target/debug/rabs-wrap" \
  cargo test -p rabsd --test canonical_check_local --locked \
    canonical_clippy_preserves_current_lints_and_separates_private_target_families \
    -- --ignored --exact --nocapture

RABS_CANONICAL_TEST_WRAPPER="$PWD/target/debug/rabs-wrap" \
  cargo test -p rabsd --test canonical_check_local --locked \
    canonical_cargo_run_preserves_default_target_input_arguments_and_every_current_exit \
    -- --ignored --exact --nocapture

RABS_CANONICAL_TEST_WRAPPER="$PWD/target/debug/rabs-wrap" \
  cargo test -p rabsd --test canonical_check_local --locked \
    canonical_cargo_bench_delivers_no_run_then_executes_each_current_custom_harness \
    -- --ignored --exact --nocapture
```

These cases check delivered no-run harnesses, execution of each current test
request, the captured rustdoc, failure propagation and refusal of local cache
authority from test code. The Clippy fixture checks cold/warm target reuse,
current lint failures after a warm check, lint-level and configuration changes,
and refusal of local rustc cache authority. It also requires the captured Clippy
components. Run checks a real stdin pipe and current success/failure after
restored private state; Bench checks retained no-run output and current harness
execution after restore. The ordinary unignored CLI tests also use a real PTY to
verify terminal refusal happens before profile-root access. These tests must
actually execute on a supported host; an
ignored fixture or a namespace-capability refusal is not passing evidence.

The closed workspace leaf-library cache has a separate native acceptance fixture:

```sh
RABS_CANONICAL_TEST_WRAPPER="$PWD/target/debug/rabs-wrap" \
RABS_TEST_WORKER_BIN="$PWD/target/debug/rabs-wkr" \
  cargo test -p rabsd --test canonical_check_local --locked \
    canonical_cargo_workspace_leaf_archives_earn_hits_with_complete_source_closure \
    -- --ignored --exact --nocapture

RABS_CANONICAL_TEST_WRAPPER="$PWD/target/debug/rabs-wrap" \
RABS_TEST_WORKER_BIN="$PWD/target/debug/rabs-wkr" \
  cargo test -p rabsd --test canonical_check_local --locked \
    canonical_workspace_leaf_denied_input_falls_back_only_after_worker_settlement \
    -- --ignored --exact --nocapture
```

The first fixture requires an actual publication and two independent remote
comparisons before a hit. It compares delivered archive, metadata, dep-info and
diagnostic bytes; the hit must leave the worker journal unchanged. It then
changes source outside the member, an assembler input absent from dep-info,
the compiler environment and a directory member, and requires new execution
identities. Adding a build script must restore the private execution-only path.
The second fixture checks that a denied process-filesystem read completes and
drains on the worker before ordinary Cargo fallback, without earning publication
or verification evidence. These fixtures require the same full native namespace
capabilities as the dependency fixtures; adding them does not establish that they
have passed on a deployment host.

The committed-dependency class has two additional native acceptance cases:

```sh
RABS_CANONICAL_TEST_WRAPPER="$PWD/target/debug/rabs-wrap" \
RABS_TEST_WORKER_BIN="$PWD/target/debug/rabs-wkr" \
  cargo test -p rabsd --test canonical_check_local --locked \
    canonical_workspace_committed_dag_earns_transitive_replay_across_worktrees \
    -- --ignored --exact --nocapture

RABS_CANONICAL_TEST_WRAPPER="$PWD/target/debug/rabs-wrap" \
RABS_TEST_WORKER_BIN="$PWD/target/debug/rabs-wkr" \
  cargo test -p rabsd --test canonical_check_local --locked \
    canonical_workspace_dag_refuses_cache_authority_from_a_local_fallback_producer \
    -- --ignored --exact --nocapture
```

The first builds a real A-to-B-to-C library chain with transitive type lookup,
requires initial publication and two independent comparisons per unit, and
matches durable ancestor identities to the delivered artifacts. Unchanged and
relocated builds must replay exact outputs and diagnostics without advancing
the worker journal. The second requires a producer's denied process-filesystem
read to settle on the worker before local fallback; successful downstream remote
compilations must remain fresh and acquire no cache publication or samples.
These cases must run on a host with the complete native namespace capability;
their presence or an ignored-test result is not execution evidence.

The full compiler-skip test is explicitly opt-in because it needs the complete
Linux namespace capability and an installed native wrapper. Build the binaries
from the same revision, then run:

```sh
cargo build -p rabsd -p rabs-wrap --locked
RABS_CANONICAL_TEST_WRAPPER="$PWD/target/debug/rabs-wrap" \
  cargo test -p rabsd --test canonical_check_local --locked \
    canonical_cargo_earns_cross_worktree_dependency_hits_and_invalidates_changed_source \
    -- --ignored --exact --nocapture
```

That test runs real Cargo and rustc against two vendored dependency libraries.
It requires three actual cold/sample compiles with identical action identities,
then requires verified hits in a different checkout and fresh target after a
workspace source edit. Unused optional build-script and development proc-macro
dependencies are present throughout those checks. A subsequent dependency edit
must compile. Explicitly selecting either executor must execute its real code
and validate the generated result without borrowing the earlier local cache
authority. The script also connects to the wrapper socket and attempts to claim
local capture; the retained operation policy must refuse that claim. The test
does not inject publication rows or verification samples. An ignored test or a
namespace-support refusal is not end-to-end success evidence; run this test on a
capable host before enabling the profile operationally.

The remote bridge has a separate opt-in fixture using the actual native worker,
mutual TLS, captured Cargo/rustc and durable worker request receipts:

```sh
cargo build -p rabsd -p rabs-wrap -p rabs-wkr --locked
RABS_CANONICAL_TEST_WRAPPER="$PWD/target/debug/rabs-wrap" \
RABS_TEST_WORKER_BIN="$PWD/target/debug/rabs-wkr" \
  cargo test -p rabsd --test canonical_check_local --locked \
    canonical_cargo_offloads_real_dependency_samples_then_replays_across_worktrees \
    -- --ignored --exact --nocapture
```

This requires OpenSSL and full canonical namespace support. It requires three
completed remote compilations of each of two dependencies, then verifies that a
relocated check serves both from cache without advancing the worker's execution
receipts. A changed dependency must produce the changed metadata consumed by a
compile-time check in the root package. Selecting the fixture's deliberately
failing build script must execute it and retain Cargo's failure, without falling
back to local cache capture. It does not inject
cache rows, samples or delivery receipts. Merely adding or ignoring this fixture
is not native execution evidence; run it on a capable host to qualify the new
canonical remote metadata path. Neither metadata bridge test establishes workspace
caching, archive execution or a performance improvement.

The canonical build fixture exercises the separate archive path and final artifact
delivery using the same complete Linux namespace and matching binaries:

```sh
RABS_CANONICAL_TEST_WRAPPER="$PWD/target/debug/rabs-wrap" \
RABS_TEST_WORKER_BIN="$PWD/target/debug/rabs-wkr" \
  cargo test -p rabsd --test canonical_check_local --locked \
    canonical_cargo_build_offloads_archives_replays_and_delivers_a_working_binary \
    -- --ignored --exact --nocapture

RABS_TEST_TOOLCHAIN_ROOT="$(rustc --print sysroot)" \
  cargo test -p rabs-sandbox --lib \
    dependency_context::tests::real_canonical_rustc_archive_view_closes_assembler_inputs_missing_from_dep_info \
    --locked -- --ignored --exact --nocapture

RABS_TEST_TOOLCHAIN_ROOT="$(rustc --print sysroot)" \
  cargo test -p rabs-sandbox --lib real_canonical_archive_bundles_ \
    --locked -- --ignored --nocapture
```

The build fixture requires three real remote archive executions for each of two
dependencies, then verifies a relocated warm build without additional worker
executions. It compares delivered `.rlib` bytes and executes the final linked
binary, edits a dependency and requires new keys and changed outputs, and checks
that the failing build script cannot create a completed build delivery. The
archive checks require one exact metadata-prefix acknowledgment per dependency
before the daemon records complete installation, both for the first three
published remote productions and for later warm replay. The producer path
requires completed worker execution and H011 publication; it spends no cache
replay receipt and does not manufacture a passing verification sample. Only
the dep-info and nonempty metadata head is installed before acknowledgment,
under the same complete destination reservation used by the archive tail.
Every negotiated frame binds the action, manifest and exact remote capture.
Failures after exposing the head prevent local fallback. Completed request-owned
workspace results use the same metadata acknowledgment with their original
private result custody instead of publication or replay authority. The fixture
also requires their metadata acknowledgment before complete installation.
Older wrappers and valid empty-metadata results retain complete-result delivery.

This permits downstream Cargo work to overlap local archive materialization.
Separately, matching workers can prefetch up to 8 MiB of exact declared metadata
in 64 KiB chunks while the compiler is still running. These bytes remain private
until the independently validated terminal manifest selects them; a complete
match avoids the final metadata range requests. Partial or changed candidates
use ordinary delivery. This overlaps metadata transfer with code generation,
but Cargo notification still requires producer completion and does not authorize
provisional descendants. See the [prefetch protocol](rabs-worker-delivery.md#prefetch-metadata-while-the-worker-compiles).
Separate real
Unix-socket/wrapper subprocess tests in `rabs-wrap/tests/metadata_protocol.rs`
hold back the final answer until the prefix is observed on both cached and
produced-result delivery, check exact transcript reassembly, and exercise
failure after exposure and blocked stderr. Those
protocol fixtures do not substitute for this actual Cargo/worker acceptance.
The sandbox fixture separately compiles an actual `.incbin` payload whose bytes appear
in the archive but not rustc's dep-info, then verifies that unkeyed host/process/
entropy inputs are inaccessible. The native-archive fixtures compile and link real
C objects through both an own generated tree and two propagated native trees,
including a downstream unit with no `OUT_DIR`. They verify that a thin archive
cannot read an original object outside the retained trees. These are runnable acceptance tests, not a
claim that an incapable host has passed them. Full native execution, build
qualification and performance evidence must be established on a capable host.

The generated-input variants run the same Cargo, wrapper, TLS worker and cache
path for both output modes:

```sh
RABS_CANONICAL_TEST_WRAPPER="$PWD/target/debug/rabs-wrap" \
RABS_TEST_WORKER_BIN="$PWD/target/debug/rabs-wkr" \
  cargo test -p rabsd --test canonical_check_local --locked \
    canonical_cargo_offloads_generated_metadata_replays_and_invalidates_changed_out_dir \
    -- --ignored --exact --nocapture

RABS_CANONICAL_TEST_WRAPPER="$PWD/target/debug/rabs-wrap" \
RABS_TEST_WORKER_BIN="$PWD/target/debug/rabs-wkr" \
  cargo test -p rabsd --test canonical_check_local --locked \
    canonical_cargo_build_offloads_generated_archives_and_delivers_changed_output \
    -- --ignored --exact --nocapture
```

Their vendored dependency's build script reads a captured workspace file outside
its package and writes generated Rust. After three real remote samples, a
relocated build must replay both dependency results. Changing only that workspace
input then leaves the dependency package bytes unchanged: the independent leaf
must still replay, while the generated-input consumer needs a different key and
an actual remote compile. A compile-time assertion checks the new metadata;
the build variant also compares the archives and executes the delivered binary.
The worker boundary tests separately compare native rustc outputs with sealed
generated input transfer, including a modified original tree, and ownership
tests cover empty trees and writable-alias refusal. The workflow runs the exact
native selectors above; adding them does not establish that an unsupported host
has passed the full path.

Two complementary cases place the generator in the leaf dependency itself:

```sh
RABS_CANONICAL_TEST_WRAPPER="$PWD/target/debug/rabs-wrap" \
RABS_TEST_WORKER_BIN="$PWD/target/debug/rabs-wkr" \
  cargo test -p rabsd --test canonical_check_local --locked \
    canonical_cargo_offloads_generated_dependency_metadata_and_invalidates_generated_bytes \
    -- --ignored --exact --nocapture

RABS_CANONICAL_TEST_WRAPPER="$PWD/target/debug/rabs-wrap" \
RABS_TEST_WORKER_BIN="$PWD/target/debug/rabs-wkr" \
  cargo test -p rabsd --test canonical_check_local --locked \
    canonical_cargo_build_offloads_generated_archives_and_delivers_current_generated_code \
    -- --ignored --exact --nocapture
```

Only the script's workspace input changes; package source, exact stdout and
`rustc-env` remain fixed. Both the generated leaf and its dependent must acquire
new keys and execute remotely. This checks propagation through the dependency
graph alongside the unchanged-leaf replay case above. The build case requires
the delivered executable to use the new generated value.

The propagated-native-root cases place a static native archive in a leaf
dependency's `OUT_DIR`. Cargo carries its `-L native=...` path through a pure
Rust middle dependency into workspace library and binary checks. Neither
downstream package has its own build script or generated directory:

```sh
RABS_CANONICAL_TEST_WRAPPER="$PWD/target/debug/rabs-wrap" \
RABS_TEST_WORKER_BIN="$PWD/target/debug/rabs-wkr" \
  cargo test -p rabsd --test canonical_check_local --locked \
    canonical_cargo_build_offloads_propagated_native_archives_and_invalidates_transitive_consumers \
    -- --ignored --exact --nocapture

RABS_CANONICAL_TEST_WRAPPER="$PWD/target/debug/rabs-wrap" \
RABS_TEST_WORKER_BIN="$PWD/target/debug/rabs-wkr" \
  cargo test -p rabsd --test canonical_check_local --locked \
    canonical_cargo_check_offloads_propagated_native_roots_and_invalidates_transitive_consumers \
    -- --ignored --exact --nocapture
```

Both cases require full Linux namespaces, OpenSSL, `cc`, `ar` and matching native
binaries. They require actual remote offers and completions for the leaf,
middle and eligible workspace units, earn dependency hits through three real
samples, and replay those dependencies after relocating the checkout while
workspace requests execute afresh. Changing only the generated archive must
invalidate the leaf and middle keys even for metadata checks. A separate empty
directory mutation must also invalidate both consumers while preserving
the build case's archive bytes and executable result. The existing own-native
dependency fixtures now likewise require their downstream workspace units to
execute remotely. These are native acceptance tests to run on a capable host;
their presence does not establish a completed native qualification or speedup.

The propagated-native workspace archive cache has an additional acceptance case:

```sh
RABS_CANONICAL_TEST_WRAPPER="$PWD/target/debug/rabs-wrap" \
RABS_TEST_WORKER_BIN="$PWD/target/debug/rabs-wkr" \
  cargo test -p rabsd --test canonical_check_local --locked \
    canonical_cargo_build_replays_propagated_native_workspace_archives \
    -- --ignored --exact --nocapture
```

It compiles a real C archive, bundles it in a workspace provider library, and
builds a downstream workspace library that inherits the native search root.
Three independent worker executions must match the stock compiler before the
downstream epoch-37 action can replay from a relocated checkout. The fixture
checks exact archives, dep-info and diagnostics, committed ancestry and the
returned executable's value. Changing only the native source must invalidate
both library actions and change that executable's result; the changed action
must earn fresh samples before replay. It requires the complete namespace and
worker prerequisites above. Adding or compiling this test does not establish
that native execution, cache reuse or a performance target has been qualified.

### Select local Cargo units from the Cargo command line

The installed `cargo-rabs` launcher accepts the same local profile and turns
ordinary Build, Check, Clippy, Doc, Test, Run and Bench selectors into the native
driver's typed command and selection:

```sh
cargo rabs --rabs-canonical-local ./canonical-compile.json -- check
cargo rabs --rabs-canonical-local ./canonical-compile.json -- check --workspace --all-targets
cargo rabs --rabs-canonical-local ./canonical-compile.json -- check -p app --bin server \
  --no-default-features --features app/http --release
cargo rabs --rabs-canonical-local ./canonical-compile.json -- check -p core --lib \
  --target wasm32-unknown-unknown --target host-tuple --profile dev
cargo rabs --rabs-canonical-local ./canonical-compile.json -- build -p app --bin server --release
cargo rabs --rabs-canonical-local ./canonical-compile.json -- build --workspace --all-targets
cargo rabs --rabs-canonical-local ./canonical-compile.json -- build -p core --tests --profile test
cargo rabs --rabs-canonical-local ./canonical-compile.json -- clippy --workspace --all-targets --no-deps -- -D warnings
cargo rabs --rabs-canonical-local ./canonical-compile.json -- clippy -p core --lib -- -Aclippy::needless_return
cargo rabs --rabs-canonical-local ./canonical-compile.json -- doc --workspace --no-deps --document-private-items
cargo rabs --rabs-canonical-local ./canonical-compile.json -- test --workspace
cargo rabs --rabs-canonical-local ./canonical-compile.json -- test -p core --no-run
cargo rabs --rabs-canonical-local ./canonical-compile.json -- test -p core --doc
cargo rabs --rabs-canonical-local ./canonical-compile.json -- test -p core roundtrip \
  --no-fail-fast -- --exact --nocapture --test-threads=1
cargo rabs --rabs-canonical-local ./canonical-compile.json -- run -p app --bin server \
  -- --input=sample.json </dev/null
cargo rabs --rabs-canonical-local ./canonical-compile.json -- bench -p core --bench throughput \
  -- --test </dev/null
cargo rabs --rabs-canonical-local ./canonical-compile.json -- bench -p core --no-run
```

Omitting the Cargo arguments selects `check`. Explicit command-line selection
replaces the profile's `command` and entire `selection` object; it never merges with saved
features or targets. An empty selection uses Cargo's ordinary default members
and targets. Directly invoking `rabsd` with a check profile that omits `selection`
retains the library-only `--lib` behavior; Build, Clippy, Doc, Test, Run and Bench
profiles use Cargo's defaults.
The profile still selects the manifest,
source and toolchain roots, job budget, timeout, state directory and wrapper.

| Selection | Accepted options |
|---|---|
| Packages | `-p` / `--package`, `--workspace`, `--exclude` with `--workspace` |
| Features | `-F` / `--features`, `--all-features`, `--no-default-features` |
| Target kinds | `--lib`, `--bins`, `--tests`, `--examples`, `--benches`, `--all-targets` |
| Named targets | `--bin`, `--test`, `--example`, `--bench` |
| Compilation targets | Repeated `--target` with built-in target names or `host-tuple` |
| Compilation profile | `--release` / `-r`, or one `--profile NAME`; `bench` accepts only the latter and defaults to optimized compilation |
| Test/benchmark execution | `test` and `bench`: `--no-run`, `--no-fail-fast`, one optional name filter; `--doc` is Test-only |
| Test/benchmark harness | `test` and `bench`: literal arguments after `--`, such as `--exact`, `--nocapture`, `--ignored` or `--test-threads=1` |
| Program execution | `run`: at most one package, one compilation target, and one named `--bin` or `--example`; literal program arguments after `--` |
| Clippy lint selection | `clippy` only: `--no-deps`, and the bounded lint controls after `--` described above |
| Documentation | `doc`: `--no-deps`, `--document-private-items`, library/binary/example selectors; test/bench/all-target selectors are refused |

Value options accept separate arguments and `--option=value`; `-pPACKAGE` and
`-FFEATURES` are also accepted. Repeated array-valued options retain every literal
value in order. `--profile` occurs at most once and cannot be combined with
`--release` or `-r`. Target and profile names use the same restricted name syntax
as the native profile above; neither can select a JSON target specification or
another file. Run excludes workspace and plural target selection. All array
entries, the optional profile, the test/benchmark filter, lint controls, program
arguments and harness arguments together share the
128-value limit and the selected command arguments' 16 KiB byte budget, including
option names. Each individual value is limited to 1,024 UTF-8 bytes.
Cargo interprets package specifications and comma/space-separated feature lists.
The native driver constructs its nonexecuting unit-graph query and subsequent
compilation from the same selection. Run resolves its one executable target
through captured Cargo metadata/package identity and plans that target as a
Build, then invokes the original Run command. It requires a captured nightly
Cargo with unit-graph support and derives the worker-only cache policy from the
Test, Clippy, Doc, Run or Bench command or required build-script/procedural-macro units
before exposing the cache endpoint. Selecting
a different target or feature set can therefore retain local metadata caching
when those executors are inactive. Source
preparation still captures the locked graph; these selectors do not narrow the
approved source boundary or replace the isolated generated-input admission checks.

This mode accepts `check`, `build`, `clippy`, `test`, `run` and `bench`. Arbitrary
subcommands are not admitted. `build --tests` and `build --benches` compile only;
`test --no-run` and `bench --no-run` also compile without executing their harnesses.
Ordinary Test, doctest, Run and Bench bodies run on every request, even when their
compiled inputs are fresh. Program arguments, filters and harness arguments are
retained as separate typed fields; the driver appends the runtime tail after
its own Cargo options. No argument after
that separator can become a Cargo configuration or planning option.
The native driver supplies locked/offline
mode, canonical compiler and output locations, and JSON diagnostics. Arguments
that would override them, including `--config`, `--manifest-path`, `--target-dir`,
`--message-format` and `-Z`, are refused as Cargo options. Arguments after `--`
are program arguments for Run and harness arguments for Test or Bench; Clippy
accepts its validated lint controls there.
Set `jobs` and `manifest` in the profile. Launcher modes and
local root-admission settings cannot be combined with this mode.

Before the single native handoff, the launcher saves the resolved profile as
`operation_root/<command>-<random>/profile.json` with mode 0600 in a mode 0700
directory. It prints that retained pathname on stderr, preserves the source
profile, then replaces its own process with
`rabsd --canonical-compile-local <retained-profile>`. Native exit status, signals,
stdin and stdout/stderr pass through that handoff. `CARGO_RABS_DAEMON` may select
the matching installed `rabsd`; the selected compiler and wrapper still come
from the profile. Release-policy configuration remains native and mandatory.
No ordinary daemon is started, and a setup/native failure does not retry through
Cargo, RCH or a weaker namespace.

`scripts/tests/test_cargo_rabs_local.py` exercises this launcher handoff with an
explicit executable driver fixture, including literal selections, retained
permissions, process identity, raw streams, exit signals and refusal paths.
Those tests establish the frontend contract. The real Cargo/compiler/cache
qualification still requires the native integration tests above.
