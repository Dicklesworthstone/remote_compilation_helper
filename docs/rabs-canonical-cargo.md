# Canonical Cargo-driver builds through the installed toolset

`cargo rabs --rabs-canonical PROFILE.json -- build --workspace` connects ordinary
Cargo workspace builds to RABS's existing canonical worker path. The same path
supports `check`, `clippy`, `test`, `run`, and `bench`, with Cargo selecting the
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

A separate [local canonical check profile](#local-canonical-checks-with-dependency-caching)
connects captured Cargo execution to the existing external-dependency metadata
cache. Its explicit command and narrower graph requirements are described below.

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
Ordinary local source and data edits can retain compiled dependencies: changed
inputs and their surviving ancestor directories receive timestamps newer than
the retained target, and Cargo applies its own freshness checks. Embedded text
or binary assets and declared build-script inputs follow the same path. Cargo
manifests, lockfiles, configuration, executable inputs, immutable dependency
sources, environment, toolchain, feature, or effective job-grant changes still
start with a fresh target.

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
reserved `rabs-cargo-home` directory. Git-index alternate registries,
authentication-dependent indexes, source replacement configurations and Git
graphs outside the locked-commit cache profile still require the supported
approved vendor route. Cache capture does not authorize action
cache publication or a compiler skip.

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

The launcher supplies `CARGO_INCREMENTAL=1` for `build`, `check`, `clippy`, `test`,
`run`, and `bench`, including both `--no-run` forms. Omitting the field or setting it to `false`
keeps `CARGO_INCREMENTAL=0`. This is an explicit operation policy: it overrides
the incremental settings of captured Cargo profiles, including release and
custom profiles. Ambient dispatcher values and arbitrary `env` overrides cannot
change it. Cargo and rustc retain their normal handling of incompatible compiler
options; the launcher does not change optimization settings to enable reuse.

Enable [worker-local target retention](rabs-target-state.md) to keep useful state
between operations. Every execution still runs its requested Cargo command in a
private target tree. A compatible seed can contain the complete prior incremental
state, and rustc decides which work products remain usable after source edits.
Changing the explicit incremental policy, compiler, profile, target or
other keyed compilation controls selects a different target family. Without
target retention, the command uses fresh private incremental storage.

Ordinary Cargo feature selections may share a private target when the captured
dependency closure and other compilation controls remain unchanged. Cargo checks
the current feature fingerprints and build-script environment; unchanged
dependencies can remain fresh as features are enabled, disabled or selected
again. Clippy feature selections remain separate so lint coverage is rechecked.

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

The first command must be `build`, `check`, `clippy`, `test`, `run`, or `bench`. For example:

```sh
cargo rabs --rabs-canonical PROFILE.json -- build --workspace
cargo rabs --rabs-canonical PROFILE.json -- check --workspace --all-targets
cargo rabs --rabs-canonical PROFILE.json -- clippy --workspace --all-targets --all-features -- -D warnings
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
profile for all six supported commands. Supply one profile, without
`--release` or `-r`. Names are 1–64 ASCII letters, digits, underscores or hyphens,
starting with a letter or digit. The launcher preserves the exact arguments and
lets Cargo resolve the profile. Warm target reuse keeps debug, release and named
custom profile families separate. The built-in `dev`/`test` profiles share the
debug family; `release`/`bench` share the release family. Cargo rechecks each
unit's actual compilation settings, and captured configuration remains exact.
Clippy preserves its own profile selection in a separate lint family.
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
Target JSON, `--config`, unstable Cargo flags, `+toolchain`,
test-harness arguments on compilation-only commands, arguments other than the
supported lint controls after Clippy's delimiter, and unknown Cargo options
refuse before preparation. The selected toolchain also supplies local Cargo metadata probes; a
`cargo +nightly rabs` launcher selection does not override that explicit dataset.
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

## Local canonical checks with dependency caching

`rabsd --canonical-check-local PROFILE.json` runs the captured native Cargo as
`cargo check --offline --locked` with the selected packages, features and targets
inside the canonical namespace and connects
its rustc requests to an operation-owned coordinator. Eligible external registry,
locked Git and verified directory-source libraries use the existing metadata
cache, including its cold-result publication, differential verification and
compiler-skip gates. Cargo plans the units at `/__rabs/workspace` with the captured
compiler at `/__rabs/toolchain/bin/rustc` and target at `/__rabs/out/cargo`, so moving
the original checkout does not introduce a different host path into that unit's
arguments or metadata output.

The local profile asks the captured Cargo to plan the **actual selected build
units** with `check --unit-graph -Z unstable-options`, using the same command
arguments, captured configuration and canonical paths as execution. Planning
does not compile or run project units, and finishes before a wrapper or cache
endpoint is exposed. A selected build script or procedural macro refuses the
operation. Inactive optional dependencies, development targets and other
workspace members containing those executors no longer prevent a safe library
or package check. Unknown graph versions, modes, target kinds, malformed edges,
cycles, unreachable units and sources outside the retained inputs also refuse.
This requires a nightly Cargo supporting the unit-graph interface; an unsupported
toolchain does not fall back to a guessed package graph.

The earlier source preparation still captures the complete approved anchor and
uses locked all-features metadata to validate its dependency closure. Selecting
fewer check units does not reduce the authorized upload/capture scope or make
missing locked dependencies available offline.
Workspace members, primary packages and unsupported compiler requests compile
normally inside the namespace. Their results do not enter the dependency cache.
The supported cache class remains external dependency `metadata` plus `dep-info`;
workspace publication, generated inputs, archive/codegen caching and per-rustc
remote dispatch require their own admission and qualification work.

### Create and run the local profile

Install matching native `rabsd` and `rabs-wrap` binaries. The explicit nightly toolchain
root must contain its real `bin/cargo`, `bin/rustc`, libraries and native sysroot.
The preparing host must pass the full production bubblewrap namespace probe,
including private `/proc`, `/dev`, temporary storage and network isolation.
Unsupported hosts return an error before compilation; there is no weaker local
execution mode behind this command.

Create two private directories outside the captured source and toolchain. Keep
the operation parent short enough for a Unix socket pathname; `/tmp/rabs-check-ops`
is an example. The driver checks existing permissions instead of repairing them:

```sh
mkdir -m 700 /home/builder/rabs-check-state /tmp/rabs-check-ops
```

For an already vendored project, save this profile with your actual absolute paths:

```json
{
  "version": "canonical-check-local-v1",
  "source_root": "/data/projects/approved-anchor",
  "toolchain_root": "/opt/rust/native-linux-toolchain",
  "state_root": "/home/builder/rabs-check-state",
  "operation_root": "/tmp/rabs-check-ops",
  "wrapper": "/usr/local/bin/rabs-wrap",
  "manifest": "app/Cargo.toml",
  "vendor": "vendor",
  "jobs": 1,
  "timeout_seconds": 1800
}
```

```sh
rabsd --canonical-check-local ./canonical-check.json
```

`manifest` defaults to `Cargo.toml`, `jobs` to 1 and `timeout_seconds` to 1800.
Omitting `selection` retains the original `check --lib` behavior. Setting
`"selection": {}` uses Cargo's ordinary default members and targets. A selection
can specify `workspace`, `packages`, `exclude`, `features`, `all_features`,
`no_default_features`, `lib`, `bins`, `tests`, `examples`, `benches`, `all_targets`,
the named-target arrays `bin`, `test`, `example`, `bench`, and `release`.
Exclusions require workspace selection. For example:

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
type-checks tests; it does not execute their harnesses.

The job count accepts 1–4096 and the canonical graph/check timeout accepts 1–7200
seconds. A purely local graph omits `vendor`. A registry/Git cache profile uses
`"cargo_home_source": "/home/builder/.cargo"` instead of `vendor`; the existing
locked offline planner captures the required package archives and Git objects
into a private Cargo home. It does not inherit that cache's user configuration,
credentials or unrelated expanded sources. The source, toolchain, state,
operation and optional Cargo-cache roots must be disjoint ordinary absolute
directories. The wrapper must be an ordinary executable outside the captured
source and mutable state/operation roots. Arbitrary commands, mount declarations
and environment overrides are not profile fields.

Preparation captures the selected toolchain before its Cargo metadata planning
and uses those captured Cargo/rustc binaries with a controlled environment.
The actual graph proof and check then run in the canonical namespace. The source
workspace and HOME are read-only there. HOME contains the retained wrapper and
the fresh operation socket; private Cargo state and the target are writable.
The build sees neither the persistent CAS nor the ordinary daemon endpoint.
Its scoped endpoint accepts rustc requests only and refuses status, generic
serving, prepared-job and administrative messages. Logical compiler paths are
translated to backing files only through the coordinator's retained mount
capability; a wrapper-supplied path or environment flag cannot construct one.

### Persistent reuse and command results

The driver owns `state_root/canonical-check-v1`, including its CAS and exclusive
state lock. Concurrent invocations using the same state root return a busy error
instead of superseding an active coordinator term. This separate namespace also
keeps the local profile's lifecycle independent of a normal daemon's CAS. Use a
dedicated state parent and retain it across checks; each command gets a fresh
private target and source/toolchain capture under `operation_root`.

The ordinary fixed sampling policy requires an initial successful compiler
result and two matching real compiler comparisons before a subsequent eligible
request can skip rustc. Repeating the same check four times against the same
state root exercises that progression. Adaptive sampling or a configured release
authorization policy can require additional evidence. This command loads the
same `[rabs]` configuration and environment overrides for build identity and
release authorization as the normal daemon. `required` remains enforced; the
profile grants no release verdict or preverified cache entry.

The stderr decision trail records `rabsd-live-dependency` events such as
`execute`, `hit`, `served`, and the specific reason for a fallback. A `hit` is an
offer; `served` follows the accepted, verified installation. Workspace crates
continue through the compiler even on a warm dependency cache. Editing a
dependency's captured source or changing its exact upstream artifact inventory
changes the key or refuses reuse. Unsupported actions preserve ordinary rustc
execution rather than borrowing the external dependency class's evidence.

The actual check inherits stdout and stderr, delivering Cargo JSON and compiler
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
publication or verification sample. Output paths in Cargo's JSON refer to that
canonical operation; this check interface returns diagnostics and success/failure,
while persistent reusable dependency results remain in the profile's CAS.

### Validate the real bridge

The ordinary native tests cover strict profile parsing, selected unit-graph admission,
read-only control/source mounts, retained state ownership, and the real scoped
socket's refusal of generic daemon capabilities while joining an open session:

```sh
cargo test -p rabsd --lib coord::canonical_local --locked
cargo test -p rabsd --test canonical_check_local --locked
```

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
must compile, while explicitly selecting either executor must refuse the graph
before the cache endpoint is exposed. The test
does not inject publication rows or verification samples. An ignored test or a
namespace-support refusal is not end-to-end success evidence; run this test on a
capable host before enabling the profile operationally. This bounded local bridge
does not complete the remote worker, workspace-cache or performance qualification
tasks described above.

### Select local Cargo units from the Cargo command line

The installed `cargo-rabs` launcher accepts the same local profile and turns
ordinary check selectors into the native driver's typed selection:

```sh
cargo rabs --rabs-canonical-local ./canonical-check.json -- check
cargo rabs --rabs-canonical-local ./canonical-check.json -- check --workspace --all-targets
cargo rabs --rabs-canonical-local ./canonical-check.json -- check -p app --bin server \
  --no-default-features --features app/http --release
```

Omitting the Cargo arguments selects `check`. Explicit command-line selection
replaces the profile's entire `selection` object; it never merges with saved
features or targets. An empty selection uses Cargo's ordinary default members
and targets. Directly invoking `rabsd` with a profile that omits `selection`
retains the older `--lib` behavior. The profile still selects the manifest,
source and toolchain roots, job budget, timeout, state directory and wrapper.

| Selection | Accepted options |
|---|---|
| Packages | `-p` / `--package`, `--workspace`, `--exclude` with `--workspace` |
| Features | `-F` / `--features`, `--all-features`, `--no-default-features` |
| Target kinds | `--lib`, `--bins`, `--tests`, `--examples`, `--benches`, `--all-targets` |
| Named targets | `--bin`, `--test`, `--example`, `--bench` |
| Compilation profile | `--release` / `-r` |

Value options accept separate arguments and `--option=value`; `-pPACKAGE` and
`-FFEATURES` are also accepted. Repeated value options retain every literal value.
Cargo interprets package specifications and comma/space-separated feature lists.
The native driver constructs both its nonexecuting unit-graph query and the
subsequent check from the same selection. It requires a captured nightly Cargo
with unit-graph support and refuses required build-script/procedural-macro units
before exposing the cache endpoint. Selecting a different target or feature set
can therefore admit a check whose unused targets need those executors. Source
preparation still captures the locked graph; these selectors do not narrow the
approved source boundary or authorize generated-input caching.

This command accepts `check` only. The native driver supplies locked/offline
mode, canonical compiler and output locations, and JSON diagnostics. Arguments
that would override them, including `--config`, `--manifest-path`, `--target-dir`,
`--message-format`, `-Z`, `--target`, `--profile`, or arguments after a second
`--`, are refused. Set `jobs` and `manifest` in the profile. Launcher modes and
local root-admission settings cannot be combined with this mode.

Before the single native handoff, the launcher saves the resolved profile as
`operation_root/check-<random>/profile.json` with mode 0600 in a mode 0700
directory. It prints that retained pathname on stderr, preserves the source
profile, then replaces its own process with
`rabsd --canonical-check-local <retained-profile>`. Native exit status, signals,
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
