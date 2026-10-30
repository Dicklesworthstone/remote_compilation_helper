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

A separate [local canonical compilation profile](#local-canonical-builds-and-checks-with-dependency-caching)
connects captured Cargo checks and builds to the external-dependency cache, with
isolated worker execution for eligible Rust archives. Its commands and narrower
graph requirements are described below.

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

## Local canonical Cargo commands with dependency caching

`rabsd --canonical-compile-local PROFILE.json` runs the captured native Cargo as
`cargo check`, `cargo build`, `cargo clippy`, `cargo test`, `cargo run` or
`cargo bench`, always offline and locked, with the selected packages, features and targets
inside the canonical namespace and connects
its rustc requests to an operation-owned coordinator. Eligible external registry,
locked Git and verified directory-source libraries use the existing metadata
cache or the isolated worker archive lane, including cold-result publication,
differential verification and compiler-skip gates. Successful builds retain their
completed target tree and report its usable host path. `test --no-run` and
`bench --no-run` deliver their compiled harnesses the same way. Tests, doctests,
programs and benchmarks execute on every invocation and return their current
result. Cargo plans the units at `/__rabs/workspace` with the captured
compiler at `/__rabs/toolchain/bin/rustc` and target at `/__rabs/out/cargo`, so moving
the original checkout does not introduce a different host path into that unit's
arguments or metadata output.

The local profile asks the captured Cargo to plan the **actual selected build
units** with `--unit-graph -Z unstable-options` on the selected `check`, `build`,
`clippy`, `test` or `bench`, using the same Cargo selection, captured configuration
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

The earlier source preparation still captures the complete approved anchor and
uses locked all-features metadata to validate its dependency closure. Selecting
fewer compilation units does not reduce the authorized upload/capture scope or make
missing locked dependencies available offline.
Workspace members, primary packages and unsupported compiler requests compile
normally inside the namespace. Their results do not enter the dependency cache.
External dependency `metadata` plus `dep-info` may execute locally or on an
explicitly configured authenticated dependency worker. Pure Rust `lib`/`rlib`
archive actions with `dep-info` and `link`, optionally also `metadata`, require
the worker's separately admitted closed archive namespace before they can publish
or replay a cache result. With no suitable worker, Cargo still builds those
archives in its own namespace, without granting those local archive results cache
authority. Test, Run and Bench commands and graphs containing active build scripts or procedural macros also
require that isolated worker lane for metadata cache publication and replay.
Project executors can access the operation's wrapper socket; they cannot turn a
claimed local completion into trusted cache evidence. The retained graph policy
therefore blocks local lookup, capture and publication even when a worker is
missing, busy or refuses the action. Without a suitable worker the current
compilation proceeds through Cargo with no local action-cache authority.

Build-script producers, proc-macro producers/consumers, workspace/primary packages
and native-link inputs retain their per-action cache restrictions and compile
normally. Eligible external libraries that consume a completed build script's
`OUT_DIR` can use the isolated worker metadata or archive cache with the complete
generated tree captured as an input. The build script itself still runs under
Cargo. Eligible independent pure dependencies may also use the isolated worker
cache. Dynamic-library candidates in a
dependency search directory still conservatively prevent that directory's
admission; this change does not claim complete per-unit acceleration for every
macro-heavy graph. Build-script failure and generated-source errors preserve
Cargo's failure status. No script, macro, test or program result cache is added.

### Create and run the local profile

Install matching native `rabsd` and `rabs-wrap` binaries. The explicit nightly toolchain
root must contain its real `bin/cargo`, `bin/rustc`, libraries and native sysroot.
Selected doctests additionally require an ordinary executable `bin/rustdoc` in
that captured toolchain. Test invocations bind `RUSTDOC` to
`/__rabs/toolchain/bin/rustdoc`; ambient PATH or configuration cannot select a
different documentation-test compiler.
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

`command` is `check` by default, `build`, `clippy`, `test`, `run` or `bench`.
The profile and native entry point
replace `canonical-check-local-v1` and `--canonical-check-local`; install matching
tools and update saved local profiles. `manifest` defaults to `Cargo.toml`, `jobs`
to 1 and `timeout_seconds` to 1800.
Omitting `selection` for `check` retains the library-only `check --lib` behavior;
omitting it for `build`, `clippy`, `test`, `run` or `bench` uses Cargo's ordinary
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
`clippy`, `test`, `run` and `bench`, mount declarations
and environment overrides are not profile fields.

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

### Send canonical dependency compilations to workers

The local Cargo driver also accepts the existing pinned dependency-worker
configuration from its operator environment. With no worker configuration it
keeps the local metadata lane only for compiler-only check/build graphs without
project executors. Test, Clippy, Run and Bench commands and graphs with build scripts or procedural
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
listings remain part of each fresh workspace execution identity. This scope
still excludes dynamic/system libraries and native library modifiers.
Inputs cannot be acquired by spelling an unretained host path in rustc argv.
Workspace native results remain request-owned and are never published or
replayed through the dependency action cache.

Each accepted workspace request executes afresh. Its identity binds the entire
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

Workspace results do not create an action-cache publication, serving entry,
differential sample or replayable transcript index. This adds remote execution
for eligible workspace compilations without granting workspace action-cache reuse.
Cargo still owns command execution and freshness; the optional private target
reuse described below has its existing independent rules and limits.

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
Existing Check, Build, Clippy and Test commands retain closed stdin. The source
workspace and HOME remain read-only, temporary and target directories are
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

### Persistent reuse and command results

The driver owns `state_root/canonical-compile-v1`, including its CAS and exclusive
state lock. Concurrent invocations using the same state root return a busy error
instead of superseding an active coordinator term. This separate namespace also
keeps the local profile's lifecycle independent of a normal daemon's CAS. Use a
dedicated state parent and retain it across commands; each command gets a fresh
private target and source/toolchain capture under `operation_root`.

To retain Cargo's own private target state between local canonical commands,
add this optional object to the same profile:

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

Code-generating builds, all Test, Clippy, Run and Bench commands, and selected graphs with build scripts
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
`private_target_state` as `disabled`, `cold` or `restored`. A failed optional
restore keeps its partial copy unmounted and runs the current command cold;
a failed save preserves Cargo's actual result. Both report a
`canonical-target-state-unavailable` diagnostic. A new seed is saved only after
complete compiler/session/coordinator drain and either successful Cargo execution
or a normally exited Test, Run or Bench command. A failing test, program or
benchmark may therefore retain its compiled artifacts for the next invocation;
its body still executes again, and the previous success or failure is never
served as the current command's result.
That same successful cold command can replace a seed after a failed restore.
An ineligible source edit or a failed private destination preserves a healthy
committed seed until that replacement succeeds.
Failed check/build commands, cancelled commands and incomplete process-group
cleanup cannot replace a successful seed. Checks can also
retain reusable state too. Successful build delivery still owns separate files,
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
sandbox fixture separately compiles an actual `.incbin` payload whose bytes appear
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

### Select local Cargo units from the Cargo command line

The installed `cargo-rabs` launcher accepts the same local profile and turns
ordinary Build, Check, Clippy, Test, Run and Bench selectors into the native
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
retains the library-only `--lib` behavior; Build, Clippy, Test, Run and Bench
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
Test, Clippy, Run or Bench command or required build-script/procedural-macro units
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
