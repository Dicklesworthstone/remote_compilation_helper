# Receiver-side verified worker delivery

`rabsd --worker-exec-tls` is the authenticated operator path that sends one
canonical request to a connecting worker and receives its complete diagnostics
and declared compiled files. It uses the production `coord::worker_delivery`
receiver through native Asupersync mutual TLS and ATP Control framing. The
separate `--worker-exec-loopback` fixture command uses the same verifier.

The loopback command is **plaintext and literal-loopback only**. It does not replace the
native authenticated ATP transport, enroll a worker, mount the daemon's CAS,
publish an action-cache entry, or make the Cargo wrapper skip compilation.
Loopback limits reachability; it does not authenticate another local process.
Use it only with trusted local users. `expected-worker` checks a claimed label,
not a certificate. The receipt explicitly records `transport_authenticated:false`
and `publication_authorized:false`. Failed TLS configurations must not be cleared
or downgraded to make a fleet connection use this operator lane.

## Run the live Cargo dependency worker

The normal Cargo wrapper can send an eligible dependency compilation directly
to an authenticated worker, publish its verified result, and install that
current result after the wrapper acknowledges the exact output manifest. Build
matching binaries from this checkout:

```sh
cargo build -p rabsd -p rabs-wkr -p rabs-wrap
```

Provision a mutual-TLS CA, a coordinator certificate valid for the worker's
configured server name, and a worker client certificate. Obtain the worker's
SPKI SHA-256 from that trusted certificate:

```sh
openssl x509 -in /credentials/worker.pem -pubkey -noout |
  openssl pkey -pubin -outform DER |
  openssl dgst -sha256
```

Start the normal daemon with the following environment. Replace the private
listen address, credential paths and pin with your deployment values; the pin
is exactly 64 lowercase hexadecimal characters, without the OpenSSL label.
Use this socket and state directory for the Cargo launcher too.

```sh
install -d -m 700 "$HOME/.cache/rabs-leaf"
RABS_STATE_DIR="$HOME/.cache/rabs-leaf" \
RABS_SOCKET_PATH="$HOME/.cache/rabs-leaf/rabs.sock" \
RABS_LIVE_DEPENDENCY=1 \
RABS_COORD_TLS_CA=/credentials/ca.pem \
RABS_COORD_TLS_CERT=/credentials/coordinator.pem \
RABS_COORD_TLS_KEY=/credentials/coordinator.key \
RABS_DEPENDENCY_WORKER_LISTEN=192.0.2.10:7092 \
RABS_DEPENDENCY_WORKER_ID=leaf-worker \
RABS_DEPENDENCY_WORKER_SPKI_SHA256=REPLACE_WITH_WORKER_SPKI_SHA256 \
  ./target/debug/rabsd
```

On the worker host, run the matching worker continuously. The address must
reach the coordinator's configured listener, and the TLS server name must
match its certificate:

```sh
RABS_WORKER_TLS_CA=/credentials/ca.pem \
RABS_WORKER_TLS_CERT=/credentials/worker.pem \
RABS_WORKER_TLS_KEY=/credentials/worker.key \
RABS_WORKER_TLS_SERVER_NAME=coordinator.example.internal \
RABS_WORKER_STATE_DIR="$HOME/.cache/rabs-leaf-worker" \
  ./target/debug/rabs-wkr \
    --coordinator coordinator.example.internal:7092 --worker-id leaf-worker
```

The daemon binds this listener when an eligible wrapper request has accepted
remote execution. Keep the worker's reconnect loop running without `--once`;
there is no idle connection queue on the listener. Preserve its
durable state across reconnects and restarts.

For a systemd worker, the fleet deployment script can install those same
identity and journal settings alongside the worker's TLS credentials:

```sh
RABS_WORKER_TLS_CA=/local/credentials/ca.pem \
RABS_WORKER_TLS_CERT=/local/credentials/worker.pem \
RABS_WORKER_TLS_KEY=/local/credentials/worker.key \
RABS_WORKER_TLS_SERVER_NAME=coordinator.example.internal \
RABS_WORKER_ID=leaf-worker \
RABS_WORKER_STATE_DIR=/var/lib/rabs/leaf-worker \
  ./scripts/rabs_fleet_deploy.sh worker-ssh-alias \
    coordinator.example.internal:7092 ./target/daemon-release/rabs-wkr
```

The three PEM paths are **local**; the state directory is on the **remote**
worker. The worker ID must match `RABS_DEPENDENCY_WORKER_ID` above. After
activation, the script prints the public certificate SPKI SHA-256 to use for
`RABS_DEPENDENCY_WORKER_SPKI_SHA256`. Successful service startup does not prove
that the coordinator has accepted a worker session.

Deployment requires the complete canonical namespace by default. For an
archive worker on a Linux host that cannot mount private procfs, set
`RABS_DEPLOY_CAPABILITY=dependency-rlib` on the deployment command above.
The selector accepts only `canonical` or `dependency-rlib`; an empty or unknown
value refuses locally before contacting SSH. The archive probe measures the
same user, PID, IPC, UTS and network isolation as native archive execution,
with a cleared environment, private `/tmp` and `/__rabs/tmp`, and only the
nonsymlink Linux null character device (major 1, minor 3). It checks the device
before and after the no-op and never mounts procfs or a general device tree.
Trusted read-only host runtime files allow the probe's `/usr/bin/true` to run;
real dependency compilation still requires the separately retained keyed
runtime and complete captured inputs.

A successful archive probe reports `dependency-rlib-ok`. It does not claim
canonical or metadata execution support. Probe failures refuse before any
credential, binary, service or journal changes. The selector applies only to
that deployment and is not saved in the managed service: an upgrade without
it requires canonical capability again. The installed worker independently
measures and advertises its execution modes, and the coordinator still must
negotiate the requested mode before admitting a compiler invocation.

`RABS_WORKER_ID` and `RABS_WORKER_STATE_DIR` are optional. On a fresh install,
omitting them preserves the worker's short-hostname identity and default
durable state layout. During an upgrade, omitted values are copied from the
active managed service while holding the deployment lock. Supplied values
replace only their respective settings. IDs use 1–128 ASCII letters, digits,
dots, underscores or hyphens and start with a letter or digit. The state path
must be absolute, printable ASCII and at most 4096 characters; spaces and
shell punctuation are transferred literally. Keep an existing worker's state
path and identity stable. Changing its journal directory to retry a build
abandons the history that prevents a completed or uncertain request from
executing twice. Missing prior settings refuse an upgrade before replacing
the binary or restarting the service.

For canonical whole-Cargo jobs, managed deployments also accept
`RABS_WORKER_TARGET_CACHE_BYTES` (0–8589934592) and
`RABS_WORKER_TARGET_CACHE_EPOCH`. A positive byte limit enables private target
reuse. A nonempty epoch additionally retains completed seeds across worker
restarts on an unchanged host runtime. The epoch is an operator-managed label:
stop the worker and change the label before updating host tools, libraries or
other runtime inputs. An omitted setting preserves its active managed value
during upgrades; explicit `0` bytes disables reuse, and an explicitly empty
epoch selects process-only retention. See [Cargo target state](rabs-target-state.md)
for limits, ownership, and the runtime stability requirement.

In another coordinator-side terminal, run ordinary Cargo through the live
wrapper. Repeat the same worker selection here so launcher readiness verifies
that the attached daemon has the requested remote capability:

```sh
RABS_STATE_DIR="$HOME/.cache/rabs-leaf" \
RABS_SOCKET_PATH="$HOME/.cache/rabs-leaf/rabs.sock" \
RABS_LIVE_DEPENDENCY=1 \
RABS_DEPENDENCY_WORKER_LISTEN=192.0.2.10:7092 \
RABS_DEPENDENCY_WORKER_ID=leaf-worker \
RABS_DEPENDENCY_WORKER_SPKI_SHA256=REPLACE_WITH_WORKER_SPKI_SHA256 \
CARGO_RABS_DAEMON="$PWD/target/debug/rabsd" \
CARGO_RABS_WRAP="$PWD/target/debug/rabs-wrap" \
  ./scripts/cargo-rabs --rabs-no-start --rabs-require-daemon \
    check --locked --manifest-path /absolute/project/Cargo.toml
```

The first eligible request starts a complete toolchain capture in the
background. A waiting wrapper receives `remote-toolchain-pending` and retries
the same invocation within its existing preparation deadline; it can then
execute remotely on that first build. Preparation grants no execution or
installation authority. Callers that disable waiting, exhaust their wait
budget or encounter a capture failure retain the existing local path before
remote acceptance. Later requests use the retained compiler and sysroot only
while their complete source witness still matches. Worker execution also
requires the measured kernel, CPU, external loader libraries, loader cache,
loader symlink topology and filesystem profile to match the coordinator.
Both hosts need the supported Linux isolation environment; the worker needs
working bubblewrap and user namespaces.

The worker captures the selected external ELF libraries into an independently
owned runtime snapshot before launching a dependency compiler. The namespace
mounts a sparse read-only `/usr`, the captured `/etc/ld.so.cache` when present,
and the exact observed loader aliases. Other host `/usr` contents and
`/etc/alternatives` are absent. Snapshot ownership lasts through process-group
cleanup and diagnostic drains, and the retained bytes are verified before
execution and after cleanup. Writable output and HOME mounts cannot alias
the runtime backing. The complete loader-cache bytes participate in the v2
runtime identity, so even an unrelated host package change can conservatively
require matching worker images or a new runtime observation.

This narrows the metadata dependency execution environment; it does not admit
arbitrary workspace code generation or build-script replay. Private proc and
device views still exist, and arbitrary later dynamic loading, locale/NSS
data, time and randomness are not a complete discovered input closure.

The remote classes accept metadata-only dependency actions
(`--emit=dep-info,metadata`) and pure Rust `lib`/`rlib` archive actions
(`--emit=dep-info,link` with optional `metadata`), including explicit `--extern name=/path/lib*.rmeta`
and `--extern name=/path/lib*.rlib` inputs. The key covers each direct extern
and the complete candidate inventories of every dependency search directory,
including metadata or archives rustc can discover through transitive
dependencies. Changing any candidate's bytes or the directory membership
invalidates that identity. The daemon captures and verifies those exact bytes
after the wrapper accepts private execution, then retains them throughout
transfer without reopening mutable target paths.

A populated dependency search directory may be disjoint from the action's
output directory or may be that same directory. In the shared case, the worker
places each retained dependency file above its private writable output mount
as a separate read-only bind. Bare toolchain externs, proc macros and
executable/shared-library linker output remain local. Ordinary dependency
execution also refuses native library inputs; the canonical Cargo archive
extension below admits a bounded generated-static-library case. Build scripts
themselves continue to run locally.
These limits apply to each compiler action; they do not prevent Cargo from
continuing with other units.

Both dependency classes may consume a previously completed Cargo build
script's generated `OUT_DIR` tree. Admission binds the exact captured Cargo
build-script output record, the original `OUT_DIR` path and every generated
file, including an explicitly captured empty tree. The transfer also retains
every generated directory, including empty subdirectories.
Generated file contents, directory membership and empty-directory topology
select a different key. The
captured `rustc-env` directives must agree with the compiler environment. Every
source or generated path reported by dep-info must belong to the captured
input closure. This does not cache or replay
the build script's execution.

**Generated native static archives in canonical Cargo builds.** A canonical
remote external-dependency `lib`/`rlib` compilation may use `-L native=PATH` when every native search
directory is the current package's captured `OUT_DIR` or one of its declared
subdirectories. Explicit library arguments must have exactly `-l static=NAME`
form, and a matching `libNAME.a` must appear in the captured generated files
under one of those search directories. Source `#[link]` attributes may use the
same closed search view. The complete generated tree, native search order,
library arguments and Cargo build-script record all participate in the key;
native actions also have a distinct isolation policy. Pure Rust action keys
retain their existing policy.

The worker independently validates the native argument shape and directory
topology before execution. Rustc bundles the retained native objects into its
returned rlib inside the existing closed archive namespace, with no external
linker, general host filesystem, procfs or entropy devices. Thin-archive members
must also resolve within retained inputs; a reference to an unmounted host
object fails the private compile. The existing verified-drain fallback handles
that failure before output installation. This uses the existing canonical v4
context and generated-tree transfer; older workers that reject native arguments
continue through that same fallback boundary.

This extension is automatic for eligible canonical dependency workers during
`cargo rabs --rabs-canonical-local PROFILE.json -- build ...`. It does not add
local native-result capture. Metadata-only checks, system or dynamic library
searches, library modifiers/renaming, and native search paths belonging to a
different package's `OUT_DIR` continue locally. In particular, a native search
path propagated through a larger dependency graph is not implicitly included
in the current package's captured generated tree. Fresh workspace library
execution can bundle archives from its own captured `OUT_DIR` under the
separately negotiated `canonical-workspace-exec-v3` contract. It validates the
same complete generated-file and directory evidence, retains exact arguments,
and grants no action-cache publication or replay authority. A workspace unit
consuming a native path from another package's generated tree remains local.

The worker keeps the original source, generated-input, output and toolchain
path spellings and full compiler environment inside private mounts. The
`dependency-exec-v8` context binds an explicit list of populated dependency
roots to their first-use directory indices. A single sealed source transfer contains
`package/<source-path>`, optional `generated/<generated-path>` and
`dependencies/NNNN/<artifact-basename>`; only the declared package, generated
and retained candidate files may appear. The worker verifies that inventory
and mounts the generated tree and each disjoint populated dependency root
read-only. The context carries every generated subdirectory, including empty
ones, separately from the file-byte manifest. The worker reconstructs the exact
tree in an exclusive backing without modifying the sealed transfer bundle or
sharing file inodes with it. This preserves compiler path traversal such as
`empty/../value.rs`; removing or replacing an empty directory also invalidates
the retained input guard. A truly empty generated root has the same explicit
ownership. The generated root must match the original `OUT_DIR` environment
value and cannot overlap source, output, dependency or toolchain roots.
Generated input files never become returned compiler artifacts.
For a shared input/output root, it rechecks the sealed input bytes and creates
exclusive, empty mountpoint files in its owned output backing. A dependency
name that collides with a declared output is refused before execution. The
worker retains descriptors for both the inputs and their mountpoint files,
verifies their ownership and identity before launch and after output capture,
and excludes only those verified mountpoint files from the returned artifacts.
Replacing or modifying them prevents successful capture. Empty dependency
roots and loader parents receive private empty backings with only declared
child mountpoints. The original target tree is never mounted.

Cargo's `target/debug/deps` and `target/debug` loader search paths still require
fresh bounded checks excluding loadable files, symlinks and hardware-capability
subdirectories. A loader directory cannot be the generated root or lie inside
it. Unsupported loader paths or changing source, generated input, build-script
record, artifact, toolchain or runtime observations refuse remote admission
or installation.
The context also requires an explicit `execution_mode`: `metadata` retains the
existing proc/device view, while `rlib` removes procfs and general devices and
exposes only `/dev/null`. This closes assembler file reads that rustc dep-info
does not record, including `.incbin`. Source, generated, dependency, toolchain
and selected runtime files remain captured and read-only; output and temporary
trees remain private. Archive keys bind exact original paths and environment
instead of inheriting metadata-only layout projections. Native inputs,
proc macros and unmodeled codegen outputs cannot enter this archive class.
This profile does not establish arbitrary workspace or plugin hermeticity.

Workers measure these profiles separately. Their hello advertises
`dependency_execution_modes` containing only the supported `metadata` and/or
`rlib` modes; the authenticated session grant selects the exact
`dependency_execution_mode` in the request. Missing, unknown or mismatched
modes refuse before admission, input upload or execution. The archive probe
uses the same namespace setup as archive execution, including user, PID, IPC,
UTS and network isolation, private temporary filesystems and `/dev/null`.
The null device must be the Linux character device 1:3; a symlink, regular
file or different device refuses both probing and namespace construction.
A host that cannot mount procfs can still execute the measured archive profile.
Metadata and whole-Cargo execution retain their full canonical isolation checks.
Sealed-result recovery requires the original request fingerprint and retained
bytes, without requiring the restarted host to support new execution.

The launcher requires a daemon advertising `dependency-exec-v8`; old execution
contexts cannot admit new work. Already sealed results from older contexts can
still resume against their exact saved request fingerprint.

A successful remote primary producer does not run a duplicate local compile.
Publication and installation still check the exact request, outputs, current
authority, release policy and negative verification/class holds. Subsequent
cache replays retain the existing qualification and periodic sampling rules.
Transport uncertainty cannot authorize a concurrent local retry.

### Run independent dependency compilations on a worker pool

Set `RABS_DEPENDENCY_WORKERS_JSON` to configure 1–32 individually pinned workers.
Each entry has exactly `listen`, `worker_id` and `worker_spki_sha256` fields.
Every listener, worker ID and certificate pin must be unique. The launcher
accepts literal coordinator-side IPv4 or unscoped bracketed IPv6 addresses with
fixed nonzero ports; each worker connects to its assigned coordinator port. The
JSON is limited to 128 KiB. Worker IDs are nonempty UTF-8 strings of at most 1024 bytes
without control characters; the fleet installer has the narrower ID rules
documented above. Pins retain the 64 lowercase hexadecimal, nonzero format.
Unknown or duplicate JSON fields, duplicate identities, and mixtures of pool
and singleton settings are refused, including empty singleton variables.

On the coordinator, prepare a separate state directory and export the pool
selection. The two pins below are **examples**: replace them with the SPKI
SHA-256 values obtained from each worker's trusted certificate using the
OpenSSL command above. Replace the example listen address with the coordinator's
actual private address.

```sh
unset RABS_DEPENDENCY_WORKER_LISTEN RABS_DEPENDENCY_WORKER_ID RABS_DEPENDENCY_WORKER_SPKI_SHA256
install -d -m 700 "$HOME/.cache/rabs-pool"
export RABS_STATE_DIR="$HOME/.cache/rabs-pool"
export RABS_SOCKET_PATH="$HOME/.cache/rabs-pool/rabs.sock"
export RABS_DEPENDENCY_WORKERS_JSON='[
  {"listen":"192.0.2.10:7092","worker_id":"leaf-a","worker_spki_sha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},
  {"listen":"192.0.2.10:7093","worker_id":"leaf-b","worker_spki_sha256":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"}
]'
```

Run the matching worker on each worker host with its own certificate and durable
journal directory. For `leaf-a`, use:

```sh
RABS_WORKER_TLS_CA=/credentials/ca.pem \
RABS_WORKER_TLS_CERT=/credentials/leaf-a.pem \
RABS_WORKER_TLS_KEY=/credentials/leaf-a.key \
RABS_WORKER_TLS_SERVER_NAME=coordinator.example.internal \
RABS_WORKER_STATE_DIR="$HOME/.cache/rabs-leaf-a" \
RABS_WORKER_TOOLCHAIN_CACHE_BYTES=8589934592 \
  ./target/debug/rabs-wkr \
    --coordinator coordinator.example.internal:7092 --worker-id leaf-a
```

For `leaf-b`, use its certificate, key and journal directory and connect to the
second port:

```sh
RABS_WORKER_TLS_CA=/credentials/ca.pem \
RABS_WORKER_TLS_CERT=/credentials/leaf-b.pem \
RABS_WORKER_TLS_KEY=/credentials/leaf-b.key \
RABS_WORKER_TLS_SERVER_NAME=coordinator.example.internal \
RABS_WORKER_STATE_DIR="$HOME/.cache/rabs-leaf-b" \
RABS_WORKER_TOOLCHAIN_CACHE_BYTES=8589934592 \
  ./target/debug/rabs-wkr \
    --coordinator coordinator.example.internal:7093 --worker-id leaf-b
```

Each example allows up to 8 GiB of verified toolchain retention per worker,
separate from source staging and private execution copies. Select a byte budget
that fits the host's disk capacity. The first execution captures the toolchain;
later jobs in the same worker process can reuse its verified bytes and avoid
retransmission. Absence or zero disables this retention. See the
[toolchain transfer and cache guide](#send-the-selected-toolchain-with-a-prepared-build)
for size limits, cache validation and worker-restart behavior.

Keep both worker reconnect loops running. In the coordinator shell with the
exported pool configuration, start an ordinary Cargo check:

```sh
RABS_COORD_TLS_CA=/credentials/ca.pem \
RABS_COORD_TLS_CERT=/credentials/coordinator.pem \
RABS_COORD_TLS_KEY=/credentials/coordinator.key \
CARGO_RABS_DAEMON="$PWD/target/debug/rabsd" \
CARGO_RABS_WRAP="$PWD/target/debug/rabs-wrap" \
  ./scripts/cargo-rabs --rabs-require-daemon \
    check --locked --manifest-path /absolute/project/Cargo.toml
```

This starts a live daemon if needed. Subsequent invocations retain the exported
pool selection so the launcher checks the attached daemon's exact normalized
configuration, including worker order, remote protocol 1 and
`dependency-exec-v8`. The advertised `remote_dependency` object contains these
protocol fields and a `workers` array in configured order. A singleton daemon
does not satisfy a pool request, even when the pool contains that one worker.
An existing daemon is never reconfigured or restarted to fit a new request;
use a separate socket and state directory when changing the selection.

Use `build --locked` in the same launcher command to accelerate eligible
dependency archives during an ordinary Cargo build. Cargo continues to run
the final executable link and unsupported compiler actions locally.

Independent eligible metadata or archive actions can execute concurrently, with at most
one admitted action per worker. Selection rotates across available slots, and
each reservation remains held through execution, result capture and publication.
Two requests for the same action cannot consume separate workers while the
first dispatch is pending. When every slot is busy, the existing bounded
wrapper wait and local path before remote acceptance still apply. A transport
failure or uncertain result after dispatch never causes an automatic retry on
another worker. Durable recovery remains bound to the selected worker's identity.

The pool retains all source, toolchain, isolation and output checks described
above. It expands concurrency for the supported metadata and closed archive classes;
other codegen actions, native linking, proc macros and build-script
execution retain their existing local path. `--rabs-require-daemon` guarantees
matching daemon setup, not remote execution of every Cargo action. The original
three-variable singleton configuration and its status fields remain supported.

### Reuse uploaded sources and dependency archives

Workers retain a digest-verified input cache across sessions and restarts by
default. Its objects live in `source-files-v1` below the worker's existing
private journal directory and have a 512 MiB aggregate allowance. Source files,
generated inputs and Rust dependency archives share this cache; objects larger
than 4 MiB are reusable too, up to the existing 512 MiB source-projection limit.
Every hit is fully hashed into a private snapshot before populating a fresh
execution receiver. Hashing and copying use 64 KiB buffers, and the final source
seal remains required even when no file bytes need uploading.

For a directly launched worker, `--source-cache-bytes N` overrides
`RABS_WORKER_SOURCE_CACHE_BYTES`. Both accept 0–8589934592 bytes; `0` disables
input reuse. For example:

```sh
rabs-wkr --coordinator 192.0.2.10:7092 --worker-id leaf-worker --source-cache-bytes 1073741824
```

`RABS_SOURCE_CACHE_DIR` optionally selects another existing absolute private
directory instead of the journal directory. Reducing the allowance trims older
retained objects when the next source upload seals. Cache corruption or eviction costs
another upload; retained readers have independent snapshots, and execution
never shares writable inodes with cached objects. Capacity bounds retained
objects; transfer staging and one in-flight verification snapshot require
additional temporary space. Lookup, copy and cache population use the original
input deadline. This cache saves input transport; compilation, result
publication and Cargo target-state policies retain their existing checks.

### Share a CPU budget between workers on the same host

Separate worker processes can serve different coordinators or worker-pool slots
while sharing one local execution budget. Configure every participating worker
with the same private directory and fixed capacity:

```sh
install -d -m 700 "$HOME/.cache/rabs-host-budget"
export RABS_WORKER_HOST_BUDGET_DIR="$HOME/.cache/rabs-host-budget"
export RABS_WORKER_HOST_SLOTS=8
```

Start each worker with its own existing identity and state directory. The shared
budget directory must be on a local filesystem with working OS file locks, have
ordinary directory ancestors, and remain stable for the domain's lifetime.
Both variables are required together. Capacity is an integer from 1 to 4096 and
is persisted with the domain; another worker cannot reopen the same directory
with a different capacity. Omitting both variables keeps the existing behavior.

A request for `C` execution slots acquires all `C` shared credits immediately
before spawning, after input and toolchain preparation. Cargo owns one implicit
slot and its private FIFO receives only `C - 1` transferable tokens. Contention
does not silently shrink the grant or change `NUM_JOBS`. Waiting remains bounded
by the request deadline and observes cancellation. Transfers and source capture
do not hold CPU credits. Live metadata-only rustc requests use a one-slot action
grant and preserve their original keyed `NUM_JOBS` value.

Canonical whole-Cargo requests can set `jobserver_grant` explicitly in their
native request specification. For example, `"jobserver_grant": 2` under the
eight-slot domain permits at most four such
Cargo roots at once. A grant larger than the host capacity refuses. When omitted,
the worker's existing machine-sized default still applies, so choose an explicit
grant when the shared budget is smaller than the worker's reported capacity.

Credits remain owned through process-group termination and diagnostic-stream
draining. A normal completion or cancellation releases them only after cleanup
proves no descendants remain. Each credit is durably marked before execution;
worker crashes or uncertain cleanup leave those credits quarantined even after
the OS unlocks the files. A missing PID is not evidence that descendants stopped.
The initial implementation does not automatically clear quarantine: inspect and
drain the affected execution before operator repair, and do not replace or reset
the budget directory while any participating worker or descendant may remain.

This bounds admitted cooperative execution across participating processes on
one host. It is not a kernel CPU limit, cluster-wide fairness, or admission for
workers configured with another directory or no shared budget.

### Run the native wrapper-to-worker oracle

After the build above, run the explicit integration fixture on a host with
Linux isolation and OpenSSL:

```sh
RABS_TEST_WORKER_BIN="$PWD/target/debug/rabs-wkr" \
RABS_TEST_WRAP_BIN="$PWD/target/debug/rabs-wrap" \
  cargo test -p rabsd --test prepared_operation_live \
    live_wrapper_remote_leaf_matches_stock_and_samples_replay \
    -- --ignored --nocapture
```

The fixture starts the real wrapper, daemon, TLS worker and rustc. It compares
every result's metadata, dep-info and diagnostics with stock rustc under the
same Cargo-shaped invocation, uses durable worker receipts to distinguish
remote production from cache replay, and checks later sampling and an
environment-driven key change. Its first wrapper invocation must wait for the
cold toolchain capture and finish on the worker; repeated local warmup builds
do not satisfy the fixture.

A second fixture lets actual Cargo choose the compiler arguments, working
directory, jobserver and loader environment. It builds an entirely offline
vendored registry graph: leaf, middle, top, then the primary consumer. Top
depends directly only on middle but constructs a type defined in leaf and
re-exported by middle, requiring rustc to resolve transitive metadata:

```sh
RABS_TEST_WORKER_BIN="$PWD/target/debug/rabs-wkr" \
RABS_TEST_WRAP_BIN="$PWD/target/debug/rabs-wrap" \
  cargo test -p rabsd --test prepared_operation_live \
    actual_offline_cargo_check_uses_remote_dependency_dag_then_replays \
    -- --ignored --nocapture
```

That case compares all eight metadata and dep-info outputs with stock Cargo at
the same paths and follows Cargo's artifact messages to locate each result.
It tracks each dependency's distinct action key, requires three actual remote
qualification observations per dependency, and then requires a complete Cargo
run serving all three from cache without advancing the worker's durable
receipt. Terminal events are associated with the crate that admitted their
action key; one crate's successful execution cannot stand in for another's.
Toolchain warmup may let different nodes start qualification on different runs.

With `dependency-exec-v8`, this DAG oracle can use shared or disjoint dependency
and output directories. It performs no compiler-argument rewriting and never
treats local fallback as evidence of remote admission. It selects the installed
Cargo and its matching compiler explicitly; ordinary rustup-based Cargo use
can select that compiler itself. Both integration fixtures are ignored by
default and must be run on the supported host to establish execution evidence.
Their presence alone does not assert a successful RABS remote run.

The corresponding `cargo build` fixture exercises code generation and final
linking with the same offline graph:

```sh
RABS_TEST_WORKER_BIN="$PWD/target/debug/rabs-wkr" \
RABS_TEST_WRAP_BIN="$PWD/target/debug/rabs-wrap" \
  cargo test -p rabsd --test prepared_operation_live \
    actual_offline_cargo_build_uses_remote_archives_then_links_and_replays \
    -- --ignored --nocapture
```

It compares ten Cargo-selected archive, metadata and dep-info outputs with the
stock build, links and executes the consumer (which must print `146`), requires
three actual remote archive productions for each dependency, and verifies a
later build uses all three cached dependencies without another worker receipt.
It requires the measured archive profile, matching binaries and OpenSSL. Local
fallback or the stock baseline alone cannot satisfy the remote assertions.

A worker-level native fixture explicitly exercises a populated shared directory
with both metadata and archive direct externs, transitive metadata resolution,
and exact output capture:

```sh
cargo test -p rabs-wkr --test process_tree_linux \
  real_dependency_rustc_reads_shared_output_metadata_dag -- --nocapture
```

That fixture compares the real worker rustc result with stock rustc using the
same paths, arguments and complete dependency inventory. It also checks that
retained inputs and mountpoint files do not become output artifacts. It needs
the supported Linux isolation environment, including a private `/proc` mount;
an unsupported-host skip does not establish remote execution evidence.

A related native fixture adds generated Rust input under Cargo's loader
parent while retaining the shared metadata and archive dependency directory:

```sh
cargo test -p rabs-wkr --test process_tree_linux \
  real_dependency_rustc_reads_generated_out_dir_with_shared_metadata_dag \
  -- --nocapture
```

It compares stock rustc and worker metadata, dep-info and JSON diagnostics at
the same paths, and checks that generated input files are not returned as
outputs. This fixture has not yet been run on the supported isolation host;
the new test alone does not establish execution evidence.

The archive variant runs the same shared dependency and generated-input shape
through the worker's closed archive profile and compares all three outputs with
stock rustc:

```sh
cargo test -p rabs-wkr --test process_tree_linux \
  real_dependency_rustc_builds_archive_with_generated_inputs_and_shared_dag \
  -- --nocapture
```

The sandbox-level native regression separately exercises assembler inputs that
do not appear in dep-info. It requires successful archive isolation rather than
silently skipping on an unsupported host:

```sh
RABS_TEST_TOOLCHAIN_ROOT="$(rustc --print sysroot)" \
  cargo test -p rabs-sandbox --lib \
    real_rustc_archive_view_closes_assembler_inputs_missing_from_dep_info \
    -- --ignored --nocapture
```

It compiles an archive containing captured `.incbin` bytes and refuses attempts
to read host-only files, procfs or `/dev/urandom`. This proves the production
sandbox boundary; the worker and live Cargo fixtures establish the broader
remote execution and replay behavior when run successfully.

The generated-native sandbox regression uses that same production archive
view, links and executes the returned rlib, and requires a thin archive's
attempt to read an unmounted original host object to fail:

```sh
RABS_TEST_TOOLCHAIN_ROOT="$(rustc --print sysroot)" \
  cargo test -p rabs-sandbox --lib \
    real_canonical_archive_bundles_retained_native_inputs_and_denies_thin_escape \
    -- --ignored --nocapture
```

It also needs `cc` and GNU `ar`. The lightweight compiler conformance test
`bundled_static_archive_changes_executable_without_changing_dep_info` in
`rabs-key/tests/live_dependency_out_dir_conformance.rs` proves that native
archive edits change the executable even though rustc's dep-info is unchanged.
It requires no namespaces and makes no claim about remote serving.

For the complete Cargo, authenticated-worker, cache and artifact-delivery path:

```sh
RABS_CANONICAL_TEST_WRAPPER="$PWD/target/debug/rabs-wrap" \
RABS_TEST_WORKER_BIN="$PWD/target/debug/rabs-wkr" \
  cargo test -p rabsd --test canonical_check_local \
    canonical_cargo_build_bundles_generated_native_archives_replays_and_invalidates_them \
    -- --ignored --nocapture
```

This fixture requires the full Cargo namespace and OpenSSL as well. It demands
actual remote cold samples, subsequent cache replay across worktrees, a working
delivered executable, and a new remote result when only the native generator's
workspace input changes. The independent Rust dependency must remain a hit.
The workspace consumer must stay local and uncached while its two external
dependencies offload or replay; the delivered binary exercises the native code.
An ignored test or an unsupported-host result is not execution evidence.

## Run one delivery

Build the receiver and worker using the repository's pinned Rust toolchain:

```sh
cargo build -p rabsd -p rabs-wkr
```

Prepare a request using the `files-v1` declaration in
[rabs-worker-artifacts.md](rabs-worker-artifacts.md). For worker-local inputs,
toolchain and workspace backing paths refer to the worker host. The compiler's
output paths must target the declared `/__rabs/out/<unit>` mount. The receiver
sends the request unchanged; it does not derive Cargo arguments or alter source
paths. Explicit source manifests instead use `--source-root`; `--worker-prepare`
can retain selected inputs before execution. Neither capture nor upload is part
of result recovery or acknowledgment reconciliation.

### Prepare a local Cargo workspace without enumerating files

Use `cargo_source` to prepare a locked Cargo workspace and its local path
dependencies. The source root is an explicit approved directory containing all
of those packages. The example below assumes `app/Cargo.toml` beneath that root;
its sibling packages retain the same relative paths on the worker:

```json
{
  "kind": "canonical-exec",
  "request_id": 42,
  "program": "cargo",
  "args": ["build", "--frozen", "--jobs=1"],
  "toolchain_backing": "/worker/rust-toolchain",
  "command_context": {
    "version": "env-cwd-v1",
    "cwd": "/__rabs/workspace/app",
    "env": {"CARGO_TARGET_DIR": "/__rabs/out/build"}
  },
  "cargo_source": {"manifest": "app/Cargo.toml"},
  "artifacts": {
    "unit": "build",
    "tree": "tree-files-v1",
    "files": ["debug/my_app"]
  }
}
```

Set the executable filename and worker toolchain path for the actual project,
save the specification, and prepare it:

```sh
rabsd --worker-prepare /absolute/project-parent /absolute/spec.json /absolute/bundles/build-42
```

Preparation first captures a coherent source image, then runs local
`cargo metadata --locked --offline --all-features` against a private copy of that
image. It checks package, workspace, target and dependency paths against the
approved tree. The resulting bundle includes every captured regular source file,
including build scripts, build-script data and inactive local dependencies. The
existing capture exclusions still apply to secrets, generated build output and
repository metadata. Choose the narrowest source root that includes the required
workspace and sibling packages.

The executable request contains the verified source manifest; `cargo_source` is
consumed locally. Cargo arguments and command context are preserved exactly.
Source discovery uses all features conservatively, even when the eventual
command enables fewer features. A virtual workspace is supported by selecting
its `Cargo.toml` and setting the corresponding canonical working directory.

Automatic preparation requires a captured workspace `Cargo.lock`. Without an
explicit `vendor` selection it supports local packages only and refuses Cargo
configuration, registry/git dependencies, symlinks and escaping manifest paths.
The opt-in vendor mode below adds checked crates.io, alternate-registry and locked Git directory
sources without network fetching or arbitrary configuration replay. Use explicit `source_files` or
`source_roots` for other supported projections; those selectors are mutually
exclusive with `cargo_source`. Explicit registry Cargo-home replay remains a
separate input-delivery mode.

Cargo metadata may run installed compiler probes; it does not build packages or
run their build scripts. Discovery has a 30-second process budget and an 8 MiB
limit per output stream, plus the existing source-transfer file and byte limits.
Failure retains no ready bundle and never dispatches a worker execution.

### Prepare a workspace with vendored registry and Git dependencies

When the approved source anchor already contains a vendor directory, automatic
preparation can resolve registry dependencies without enumerating their files:

```json
"cargo_source": {
  "manifest": "Cargo.toml",
  "vendor": "vendor"
}
```

Both paths are relative to the approved anchor passed to `--worker-prepare`.
For this example, the anchor's existing `.cargo/config.toml` must contain only:

```toml
[source.crates-io]
replace-with = "vendored-sources"

[source.vendored-sources]
directory = "vendor"
```

The replacement source name may differ. Its relative directory is resolved from
the directory containing `.cargo`, as Cargo defines configuration-file paths.
For an `app/.cargo/config.toml` and a sibling vendor directory, use `../vendor`
in that configuration and `vendor` in the preparation selection. The preparer
requires those paths to identify the same contained directory. It copies the
original configuration unchanged; it neither generates it nor runs `cargo vendor`.
See Cargo's [source replacement reference](https://doc.rust-lang.org/cargo/reference/source-replacement.html)
and [configuration path rules](https://doc.rust-lang.org/cargo/reference/config.html#config-relative-paths).

Each vendor package must have a complete `.cargo-checksum.json` and explicit
package name/version. Preparation rehashes the retained file bytes and requires
exact checksum coverage: missing, extra, changed and duplicate entries refuse.
The registry package checksums must match the actual resolved workspace's captured
`Cargo.lock`, not a neighboring lockfile. Git packages use Cargo's null archive
checksum and retain the same exact per-file verification. Cargo still owns dependency resolution;
its resolved package identities, source directories and target paths are checked
against the verified vendor tree and lock. Local path packages can coexist with
registry packages, including transitive and build dependencies. Checksummed nested
manifest/config fixtures within vendor packages remain ordinary package data.

The same selected directory can contain locked Git packages, either alongside
crates.io packages or by themselves. Preserve the source replacement tables
generated by `cargo vendor`; for example, a pinned Git dependency adds:

```toml
[source."git+https://example.org/team/dependency?rev=<revision>"]
git = "https://example.org/team/dependency"
rev = "<revision>"
replace-with = "vendored-sources"
```

The table name may be an alias. Its Git URL and optional `rev`, `branch` or `tag`
must match the original dependency selection, and the captured lockfile must
contain a canonical full 40-digit commit. A full hexadecimal `rev` must agree
with that locked commit. Resolution is checked against the complete package name,
version and source identity. Git workspace sibling dependencies are supported
through Cargo's directory-source semantics. Local dependency or workspace
selections that enter the vendor directory refuse before Cargo runs, preventing
those packages from being reinterpreted as unrestricted local path packages.

Alternate registries can use the same checked directory. Declare the registry's
name and exact index URL alongside its direct source replacement in the single
captured `.cargo/config.toml`:

```toml
[registries.private]
index = "sparse+https://registry.example.org/index/"

[source.private-index]
registry = "sparse+https://registry.example.org/index/"
replace-with = "vendored-sources"

[source.vendored-sources]
directory = "vendor"
```

The workspace may then declare
`dependency = { version = "1.2.3", registry = "private" }`. The registry name
must resolve through that captured index declaration; the source table name
may differ. Published dependency manifests with `registry-index` are also
supported, so transitive and build dependencies retain their exact source
selection. Every registry index must have a direct replacement to the approved
directory, and every resolved package must match the captured lock's complete
name/version/source identity and archive checksum. The same name/version from
different sources is refused as ambiguous in this bounded vendor layout.

Both Git-index HTTP(S) URLs and `sparse+http(s)` URLs are supported. Use the
canonical index spelling recorded by Cargo: a Git index appears as
`registry+https://…` in `Cargo.lock`, while a sparse index retains `sparse+https://…`
and its required trailing slash. Source identities are compared exactly; an
index with a different path or protocol cannot borrow another index's verified
packages. Credential-bearing URLs, registry tokens and credential-provider
configuration are not accepted. See Cargo's
[alternate registry reference](https://doc.rust-lang.org/cargo/reference/registries.html#using-an-alternate-registry).

Use the same `cargo_source` selection above and prepare the existing captured
layout with the normal command:

```bash
rabsd --worker-prepare /absolute/approved-anchor /absolute/specification.json /absolute/new-bundle
```

This bounded mode accepts one directory replacement, optional crates.io,
explicit alternate-registry indexes, and explicit Git source replacements.
It accepts no other Cargo configuration layers.
Replacement chains, arbitrary build/credential configuration,
symlinks and escaping local paths refuse. Directory sources must already be complete; no registry, broker, fetch,
archive download or user Cargo home is consulted. The existing 4,096-file and
512 MiB source bounds include the whole approved anchor and vendor tree.

The resulting ordinary source bundle works with `--worker-build-tls` below;
no special worker vendor protocol or `cargo_home` projection is required. The
worker sees the same source replacement and dependency layout in its read-only
workspace. Build-script generated files belong in the declared output tree. The
selected execution arguments and environment remain unchanged, including any
user-supplied offline/locked requirements; planning flags are not injected into
the later compilation command.

These checks establish consistency among supplied source bytes, checksum metadata
and the lockfile. They do not authenticate the original registry archive or Git
origin, prove
full E025 resolution provenance, or authorize an action-cache hit. The operator
must approve the captured content and target toolchain before transmission.

### Replay registry inputs into a private Cargo home

Source-backed requests may include an explicit registry-cache projection:

```json
"cargo_home": {
  "version": "registry-cargo-home-v1",
  "prefix": "cache"
}
```

The prefix is a relative directory INSIDE the transferred source manifest, not
an absolute host path or permission to crawl a Cargo installation. All selected
files under that prefix must be beneath `registry/cache`, `registry/index` or
`registry/src`. Their exact paths, lengths, executable bits and hashes are part
of the same source manifest as the project. The selection is retained verbatim
in the original request and its durable fingerprint.

For preparation, select the required registry files using `source_files` or a
`source_roots` entry such as `cache: {path, files}` alongside the application
root. Root names become directory prefixes in the saved bundle. Select only the
approved files required by the target Cargo invocation; this does not discover
the dependency closure or import an entire `~/.cargo` directory. A local-registry
fixture, for example, can carry these inputs:

```text
app/Cargo.toml
app/Cargo.lock
app/.cargo/config.toml
app/src/main.rs
cache/registry/index/local/registry_dep-1.0.0.crate
cache/registry/index/local/index/re/gi/registry_dep
```

The application's explicitly selected `.cargo/config.toml` must name the local
registry beneath the canonical Cargo home, not the original host checkout.
Ordinary registry cache/index/source projections instead retain the layout and
configuration required by their pinned Cargo version. Cargo-home internals are
not a stable interchange format: qualify the selected inputs against the target
toolchain. The preparer does not rewrite manifests, source replacement settings,
lockfiles, arguments, environment or working directory. Use the original
command's `--frozen` requirement when both locked resolution and offline operation
are required; the sandbox's network isolation is unchanged in either case.

Cargo-home configuration and credentials, installed binaries, global metadata,
lock files and Git dependency state cannot be selected through this replay
field. Configuration needed by the build must be explicitly supplied as an
ordinary workspace input instead. This directory policy is not a secret scanner:
the caller remains responsible for approving the content of every selected file.

After transport/session admission, the worker must echo the exact version and
prefix in its initial `source-ready` before any source or registry bytes are sent.
The same echo is required at the final seal. A worker that ignores the extension,
an unsolicited selection, a changed prefix or a missing final confirmation
refuses without executing. A warm source-byte cache does not waive these checks.

The worker verifies the sealed projection, then copies it into a fresh private
Cargo home owned by that one execution. Files are independent writable copies
so Cargo can acquire locks, unpack archives and update its own cache metadata;
the transferred workspace remains read-only. No host Cargo-home configuration or
credentials are inherited, and runtime writes cannot alter the original source
or shared source-byte cache. Preparation shares the original bounded upload
phase and must finish before execution ownership is handed off. Source protocol
limits still apply: at most 4,096 files and 512 MiB across the complete projection.
The independent runtime copy requires additional space for the selected registry
bytes and for whatever Cargo subsequently unpacks.

Result resume and acceptance reconciliation carry the original request identity
but never reupload registry inputs or recreate an execution Cargo home. This is
explicit input delivery, not proof of package provenance, complete dependency
resolution, immutable action inputs, or permission to skip compilation.

### Send the selected toolchain with a prepared build

Prepared TLS builds can deliver their compiler installation along with their
source. The worker does not need that installation at a matching local path.
The uploaded tree is verified, independently captured for execution, and mounted
at `/__rabs/toolchain`. Its owner remains alive through process cleanup and
diagnostic capture; verification before launch and after cleanup rejects changes
to the retained backing before successful artifacts can be offered.

To include a toolchain during source preparation, add the complete local
installation path to the specification:

```json
"toolchain_source": "/absolute/local/rust-toolchain"
```

`--worker-prepare` retains an independent copy in `bundle/toolchain/`, alongside
`source/`. It removes `toolchain_source` and `toolchain_backing` from the
executable request, selects `toolchain_transfer: "toolchain-tree-v1"`, and saves a
`toolchain_identity` object containing `version: "toolchain-dataset-v1"`, a
lowercase SHA-256 digest, and unsigned `files` and `bytes` counts. If a
specification also supplies an identity, preparation checks it against the
captured tree instead of replacing it. The complete retained input precedes the
bundle's `request.json` readiness marker. Preparation reads the toolchain without
running its binaries.

Use the resulting bundle with `--worker-build-tls` or `--job-submit`. New
execution validates the retained toolchain before contacting the worker. It
uploads source first, then offers the toolchain over the same authenticated
connection. A negotiated verified worker cache hit avoids retransmitting the
tree; a miss streams it normally. The saved command is dispatched only after
both inputs are sealed.
The original local installation is no longer needed. A missing or changed
retained tree fails before dispatch; it cannot select a worker-local compiler.
Direct `--worker-exec-tls --source-root` does not infer toolchain upload permission
from neighboring directories. Plaintext loopback execution does not accept the
toolchain transfer selection.

The identity covers relative paths, directory layout including empty directories,
regular-file bytes, executable bits, and exact contained relative symlink targets.
Hard links become independent copies. Absolute, dangling, escaping or cyclic
symlinks, special files, nested mounts, incoherent reads and limit violations
refuse. The Linux implementation uses descriptor-relative `openat2` traversal.
Defaults allow 8 GiB, 100,000 entries and 64 levels of depth. There are no implicit
exclusions for documentation or other toolchain files: select a complete approved
runtime tree when a full installation is unnecessarily large. The transfer sends
bounded entry records and chunks rather than loading the complete tree into
memory. Symlinks are created after file delivery and validated against the
complete tree. Partial, out-of-order, altered or incomplete input cannot become
an execution root. Capture and repeated verification read the full selected tree;
allow disk space for the retained bundle and the worker's staging and private
execution copies.

To retain toolchains across jobs and worker reconnects, set
`RABS_WORKER_TOOLCHAIN_CACHE_BYTES` to the worker-local byte budget before
starting the worker. Absence or zero disables retention; the pool is bounded by
64 GiB and eight datasets. The first actual execution captures the verified
toolchain into that pool. A later connection may select `toolchain-reuse-v1`
when the worker advertises it alongside toolchain transfer. On an exact hit,
the worker revalidates the retained dataset on its filesystem thread and replies
to the initial toolchain offer with `sealed:true`; the coordinator sends no
toolchain entries, chunks or seal frame. The original request is unchanged.

Lookup uses the full dataset identity and verifies the declared entry count.
It never opens a sender-supplied worker path, captures a missing installation,
or waits for another capture. A disabled pool, missing dataset, oversized dataset
or capture still in progress uses ordinary upload. Corrupt retained bytes refuse
the current operation; they do not become a successful hit. A lease keeps the
verified tree alive through admission, execution and process drain, even if its
cache entry is retired. Cancellation and the fixed input deadline still apply
to lookup and acknowledgment. Without explicit reuse negotiation, an unsolicited
`sealed:true` begin reply is rejected.

This pool is process-local. Worker process restart discards it, while reconnects
within the same worker process can retain it. Prepared bundles still contain
their own complete compiler tree and are verified locally before networking;
cache reuse does not make a missing or corrupted local bundle executable.

The receiver requires the worker's explicit `toolchain-tree-v1` transfer and
`toolchain-dataset-v1` verification capabilities before sending input bytes.
A missing capability refuses; a content mismatch on the worker refuses before
compiler spawn. The original request remains the journal, lease and delivery
identity: private worker paths are never written into it. Result resume and
complete local delivery recovery use that original identity and do not upload or
recapture a toolchain, or require the restarted worker to retain execution
capability.

Requests that explicitly select an existing worker `toolchain_backing` can still
use the local capture path. A supplied `toolchain_identity` requires an exact
match; an omitted identity permits an unpinned private capture. Malformed
identities and simultaneous transfer/backing selections refuse.

This binds the selected tree's bytes. It does not identify host `/usr`, linker,
dynamic-loader configuration or other runtime inputs outside that tree, and does
not authorize cache publication or compiler skipping. Private ownership and a
read-only sandbox mount remain required: file modes and before/after verification
do not protect against a hostile process with the worker owner's credentials.

### Build a prepared bundle and install its outputs

`--worker-build-tls` joins source upload, authenticated execution, durable byte
delivery, and complete output installation in one operator command. First prepare
a bundle containing `request.json`, `source/`, and, when selected, `toolchain/`
with `--worker-prepare`. The
request must contain a source manifest and an artifact declaration; an explicit
`tree-files-v1` declaration receives the full output tree, including Cargo's
intermediate files. The compiler command still supplies its exact arguments,
canonical working directory, environment, and explicit toolchain selection.

Canonical Cargo requests can additionally declare `"cargo":"cargo-json-v1"`
inside `artifacts`, with `"unit":"cargo"`, `"tree":"tree-files-v1"` and an
empty `files` minimum. This explicit contract requires the native Cargo program,
`--message-format=json`, `/__rabs/out/cargo` as the target directory, and a
compilation command (`build`, `check`, or `test --no-run`). Cargo's completed
artifact report supplies the actual required filenames and executable modes.
The worker validates them while capturing the complete tree; the coordinator
checks them independently before acknowledgement and again during offline
recovery. A success-looking marker without compiler artifacts is insufficient.
The contract does not run tests, publish cache entries or change request identity.
See [canonical Cargo](rabs-canonical-cargo.md) for supported frontend selections
and report bounds. Endpoints without this contract reject the new field.

With the TLS environment described below, run:

```sh
rabsd --worker-build-tls 0.0.0.0:7091 fleet-worker <worker-spki-sha256> \
  /absolute/bundles/build-42 /absolute/deliveries/build-42 /absolute/outputs/build-42
```

Start `rabs-wkr --once` against that listener as shown in the authenticated
delivery instructions below. The three local directories must have existing
parents, be disjoint, and contain no symlink ancestors. For a new execution the
delivery and output directories must be absent. The bundle supplies the only
source upload; the original checkout is no longer needed. The command retains
the complete verified delivery before privately staging and atomically installing
every successful artifact. Installed files are independent copies, so modifying
them cannot change the retained delivery. Failed or interrupted compilation
retains diagnostics and its original exit status without installing partial outputs.

Repeating this exact command verifies the existing delivery and installed tree
offline. It can also finish installation after a previous installation failure.
No worker connection, TLS credentials, or source directory is needed for a
complete local delivery; keep the bundle's `request.json` to identify that
delivery. An existing differing output tree is refused without replacement.
An existing incomplete or corrupt delivery is also refused and never triggers
another execution.

If execution completed remotely but the delivery was lost, explicitly retrieve
the original result into a **new** delivery directory:

```sh
rabsd --worker-build-tls --resume 0.0.0.0:7091 fleet-worker <worker-spki-sha256> \
  /absolute/bundles/build-42 /absolute/deliveries/build-42-resumed /absolute/outputs/build-42
```

Resume sends only the retained-result request and byte reads; it neither uploads
source nor dispatches a compiler. An unavailable remote result remains an error.
The worker must still retain the requested result. A complete local delivery can
be installed even if a release acknowledgment was lost; acknowledgment
reconciliation remains the separate `--worker-exec-tls --acknowledge` operation
using the same bundle request and delivery directory.

To reuse an interrupted download's local prefixes, replace `--resume` with
`--resume-from /absolute/deliveries/interrupted`. The new delivery and output
paths remain separate; see the prefix-recovery section below.

Success prints one `worker-build` JSON object containing `delivery` and
`installed_outputs`; the latter reports whether a verified existing tree was
reused. A nonzero compiler exit produces a retained `delivery` and null
`installed_outputs`. Installation or protocol failure prints `worker-build-error`
with `execution_may_have_run` and `reexecute:false`. These commands do not publish
action-cache entries or install Cargo freshness authority. They provide explicit
build outputs for inspection and use in a new directory.

The trusted local fixture is `--worker-build-loopback`, with the same arguments
except for the omitted key pin. It requires a worker-local toolchain selection,
accepts only literal loopback addresses, and retains the plaintext provenance
described above.

### Prepared builds in the running daemon

The running `rabsd` can durably queue prepared builds, execute jobs on independent
workers, install verified outputs, and retain their status across client
disconnects and daemon restarts. Four jobs may run at once by default. Configure
`prepared_concurrency` in the daemon's `[rabs]` table to use a larger worker pool:

```toml
[rabs]
prepared_concurrency = 16
```

The supported range is 1–32. `RABS_PREPARED_CONCURRENCY=16` overrides the file
setting for the daemon process. Restart the daemon to apply a change;
`rabsd --check-config` reports the resolved setting. One validated limit controls
the owned executor threads, active-job admission, local result recovery and
retained live previews. Raising it allows independent workers to run more jobs
at once; jobs that share a worker, key pin, listener or conflicting paths still
serialize. The existing queue and retained-byte limits also apply. Choose a
value that fits the coordinator's memory, transfer bandwidth and available
workers.

`rabsd --coord-status` reports the running service's `prepared_jobs` object:
`available`, `concurrency`, `active`, `queued`, `accepting`, and
`persistence_uncertain`. Active ownership includes cancellation and local result
recovery until that owner finishes. Queued counts include jobs waiting for a
result-recovery retry, so neither count promises that a specific worker is free.
A busy or poisoned queue lock returns `available:false` with the configured
limit and a detail instead of blocking status behind a filesystem transaction.
An unavailable prepared-job service is reported as `null`.

Set `RABS_COORD_TLS_CA`,
`RABS_COORD_TLS_CERT`, and `RABS_COORD_TLS_KEY` on the daemon process before
starting it. These are the same authenticated transport credentials described
below. The job commands connect to that daemon through `RABS_SOCKET_PATH` (or
the configured socket); setting credentials only on a submitting client does
not configure the daemon.

Prepare a bundle with selected source files and `toolchain_source` first. Daemon
jobs require both the captured source manifest and a required toolchain identity;
requests that depend on an unspecified worker toolchain are refused. Choose and
retain a 32-character lowercase hexadecimal job ID **before** submitting:

```sh
rabsd --job-submit 0123456789abcdef0123456789abcdef \
  0.0.0.0:7091 fleet-worker <worker-spki-sha256> \
  /absolute/bundles/build-42 /absolute/deliveries/build-42 /absolute/outputs/build-42
rabsd --job-status 0123456789abcdef0123456789abcdef
```

The submission saves the exact prepared request, worker identity, key pin, and
paths before replying. Repeating an identical submission with the same ID returns
its status; changing its request or destination is refused. After a lost response,
inspect that ID instead of creating another job. The job ID identifies the durable
submission; the bundle's `request_id` remains the worker journal's execution
identity. A new execution needs a fresh request ID above that worker journal's
high-water mark. Submitting the same bundle under a different job ID does not
allocate a new worker attempt.

Wait until `listen_address` is present, then connect the authenticated worker to
the coordinator's reachable hostname or IP at the reported port, using the worker
command below. A wildcard bind address such as `0.0.0.0` is not the worker's remote
destination. For repeated jobs, use a fixed
listener port and omit the worker's `--once` option so its existing reconnect loop
can service later jobs. A listener submitted with port `0` reports its actual port
and retains that first bound endpoint for recovery. Keep the worker's configured
coordinator address, including its DNS spelling, unchanged for that journal;
changing it also changes the journal identity. Jobs sharing a worker name, key
pin, listener endpoint, or conflicting paths cannot execute concurrently.

After a short connection delivers a normally completed result and both output
owners acknowledge it, the worker reconnects with 125–250 ms of jitter. Its
`worker-reconnect-scheduled` record reports `completed_delivery: true` only when
that connection advances the durable request/release state. A fully delivered
compiler error also counts as useful work. Completing retained-result recovery
resets the delay once; repeated acknowledgments do not. Empty sessions, partial
delivery, cancelled execution and unresolved results keep the existing
exponential outage backoff, capped at 15–30 seconds of jitter. This prevents a
sequence of successful short compilations from accumulating outage delays;
an idle worker whose listener is absent still backs off normally.

Status reports `queued`, `running`, `cancelling`, `completed`, `cancelled`,
`failed_before_start`, or `uncertain`. Check `succeeded`, `exit_code`, `stop_reason`,
and `outputs_installed` to distinguish a successful installed build from a
completed compiler failure. `outputs_installed` records a verified installation;
it does not continuously monitor later user edits.

After a native socket interruption during execution or result delivery, the
daemon automatically tries to recover the original retained result up to three
times, with 1, 2, and 4 second backoffs.
These attempts use only result resume or acknowledgment messages: they do not
upload source or execute the compiler again. Status exposes
`automatic_recoveries`, `recovery_pending`, and the current `mode`. Each resumed
download gets a fresh `rabs-recovery-<job-id>-<number>` directory beside the
original delivery, checked against live and archived ownership. A lost release
acknowledgment uses the already verified delivery and preserves the known build
outcome even if its cleanup retries run out.

The worker stays reserved throughout recovery. A durably queued retry survives
a daemon restart and starts a fresh conservative backoff; an owner that crashes
during an active attempt still leaves an uncertain job for explicit recovery.
Cancellation and daemon shutdown suppress further automatic recovery. Invalid
protocol messages, authentication failures, corrupt data, and local filesystem
errors do not trigger these retries. After the budget is exhausted or recovery
cannot be safely scheduled, the explicit commands below remain available.
Source or toolchain upload failures before compiler dispatch remain
`failed_before_start`; automatic recovery never retries execution.

Cancellation is durable:

```sh
rabsd --job-cancel 0123456789abcdef0123456789abcdef
```

A queued execution can be cancelled before dispatch. An active cancellation
interrupts admission or sends the exact in-flight request's cancel, then retains
and verifies its terminal result when the connection permits. If the daemon dies
while a job is active, restart marks it `uncertain`; it never automatically sends
another compiler execution. The worker stays reserved until the original result
is reconciled. Retrieve a retained result into a new directory with:

```sh
rabsd --job-resume 0123456789abcdef0123456789abcdef \
  /absolute/deliveries/build-42-resumed /absolute/deliveries/build-42
```

The final prefix directory is optional. Resume uses the saved request and original
worker, uploads no source, and never starts a compiler. It can verify and reuse an
already installed, identical output tree. An unavailable remote result remains
uncertain and does not release the worker for unrelated execution.

If delivery completed but acknowledgment confirmation was lost, reconcile the
original verified delivery instead of downloading it again:

```sh
rabsd --job-acknowledge 0123456789abcdef0123456789abcdef \
  /absolute/deliveries/build-42
```

Acknowledgment accepts only a delivery directory already owned by this job. It
verifies the saved bytes and exact authenticated result, including the worker's
durable released-result status when remote spools are already gone. It neither
executes nor uploads source nor modifies installed outputs. Confirmed release
clears the worker reservation. Recovery uses the saved request even if the
original bundle is no longer available.

The daemon bounds live operation accounting to 1,024 records and 64 MiB. When a
new submission needs room, it automatically archives the oldest fully resolved
records. Eligible records are jobs that failed before dispatch, executions
cancelled before dispatch, and completed or cancelled executions whose worker
release acknowledgments are confirmed. Queued, active, uncertain, and
acknowledgment-pending work continues to consume live capacity; unresolved work
can still cause admission to refuse.

Archival preserves the complete saved record on disk. Historical job IDs,
requests, and reserved paths remain checked, so archival cannot make an old ID
or output destination available to another execution. Status, verified completion
replay, and explicit local recovery continue to work for archived jobs. Local
recovery first restores the record to live accounting and never queues another
compiler execution. Archive moves are durable and verified again at startup;
conflicting or corrupt history refuses admission. Full-history checks run on the
filesystem admission lane without holding the operation-state mutex, so they do
not block cancellation behind the entire scan. Archived records are retained
indefinitely: resident accounting stays bounded while disk history and admission
scan time grow with the number of jobs.

The store permits at most 1,024 retained jobs, a 64 MiB admission budget including
reserved record space, and 16 recovery destinations per job. Full stores refuse
new admissions; completed records are not silently erased. These jobs provide
authenticated execution and explicit output installation. They do not grant
semantic action-cache publication or Cargo freshness authority.

### Follow live diagnostic previews from a daemon job

Use `--job-follow` to inspect a running prepared job without waiting for its
complete diagnostic transcript:

```sh
rabsd --job-follow 0123456789abcdef0123456789abcdef 3600 > job-events.ndjson
```

Live previews use the worker's optional `tail-v1` capability. The daemon polls
the existing authenticated execution connection every 500 milliseconds, with
cancellation and lease renewal taking priority. A worker without preview support
still provides ordinary verified completion; its live preview is unavailable.

The optional timeout defaults to 3,600 seconds and accepts decimal seconds from
1 through 86,400. Stdout contains newline-delimited JSON. Each `prepared-preview`
event identifies the operation, its saved request fingerprint, and its durable
`attempt`. Segments name `stdout` or `stderr`, carry binary-safe lowercase
`data_hex`, and describe `offset`, `next_offset`, `skipped_bytes`, and
`observed_bytes`. Each response contains at most 8 KiB per stream. A gap is
explicit: `skipped_bytes` counts bytes between the client's previous cursor and
the returned segment. Only `next_offset` advances that cursor; `observed_bytes`
does not mean the client received those bytes.

Previews are a bounded, temporary view and always have `complete:false`.
Clients read independently without consuming another client's diagnostics.
Late attachment, output faster than preview capture, and slow readers can leave
gaps. Missing or closed preview state, daemon restart, and recovery attempts
produce `available:false` with `reason:"unavailable"`; transient contention uses
`reason:"busy"`. These responses contain no segments. Repeated identical preview
responses are omitted from the CLI output. The command follows the original
queued job into its first claimed attempt, then stops if that attempt or request
identity changes outside its bounded automatic recovery sequence. Automatic
result and acknowledgment recovery retain the same request and can be followed
through to verified completion; live preview reads stop during those recovery
attempts. A manually changed attempt still requires another explicit follow
invocation.

At terminal delivery, the client requests verified completion metadata, checks
the local receipt, and snapshots and hashes both complete diagnostic streams
using the same verification as `--job-wait`. It rereads status to ensure recovery
has not changed the attempt during verification. It then emits one
`prepared-follow-completion` event containing `completion_verified:true`, the
verified completion metadata, and the compiler's original exit code, and exits
with that code. The event retains `preview_complete:false`: verification does
not fill gaps or print the full diagnostics a second time. A cancellation before
dispatch returns 130 with `completion:null` and `completion_verified:false`,
without reading delivery files.

Following is read-only. A timeout, uncertain outcome, lost daemon connection,
changed attempt, failed verification, or partial output write stops the client
without retrying output or submitting, cancelling, resuming, or acknowledging
the job. Errors are structured JSON on stderr and report whether preview output
may already have been exposed. Interrupting this client leaves the daemon-owned
job running. Final verification uses temporary disk space bounded by the complete
diagnostic size; filesystem and console writes are not promised interruptible.
Use `--job-wait` when you need the complete binary stdout and stderr streams.
Neither command grants cache publication or Cargo freshness authority.

### Wait for a daemon job and replay its compiler diagnostics

After submitting a prepared job, a shell or CI caller can wait for that exact
job and receive its original compiler exit status and binary diagnostics:

```sh
rabsd --job-wait 0123456789abcdef0123456789abcdef 3600
```

The timeout is optional (default 3,600 seconds), must be a positive decimal
number of seconds, and cannot exceed 86,400. Waiting is read-only: it polls
status and asks the local daemon to verify a terminal delivery. It never submits,
resumes, acknowledges, cancels, or dispatches worker execution. An uncertain
job, unavailable daemon, changed identity, or failed verification stops the
client; none triggers compilation or an automatic reconciliation attempt.
Interrupting the client leaves the daemon-owned job alone. Use `--job-cancel`
explicitly to cancel work, and the existing resume/acknowledge commands when
the job requires outcome reconciliation.

For a delivered result, the daemon checks the entire retained artifact and
diagnostic tree against its saved original request and worker key. It releases
the operation-store mutex while hashing and runs this work on the bounded
filesystem lane, not the cancellation/status lane. It rejects a recovery/state
change observed during verification. The reply contains only bounded completion
metadata, not the full saved request, command environment, or bulk file bytes.
This works after daemon restart without the original bundle or worker credentials.

The local client checks that metadata against the job it followed, verifies the
receipt, and copies BOTH diagnostic streams into independent private temporary
files while rehashing every byte. Neither stream is printed until both copies
verify. It then emits raw stdout to stdout and raw stderr to stderr and exits
with the original compiler code. Failed compilation is not converted to exit
zero. Cancellation before dispatch returns 130 with no diagnostic-file access.
A successful job must have recorded a verified output installation; this is a
historical installation fact, not continuous monitoring of later user edits.

This is terminal diagnostic replay, not live streaming during compilation.
Per-stream byte order is preserved; historical cross-stream interleaving cannot
be reconstructed. Each explicit invocation may print the diagnostics again.
Failed/partial console writes stop without automatic replay, and typed client
errors distinguish possible diagnostic exposure. No status JSON is mixed into
successful compiler stdout or stderr. The client uses temporary disk space up
to the combined diagnostic size (bounded by the existing 1 GiB delivery limit).
Network calls share the overall wait deadline with per-exchange caps; copies
check that deadline between chunks. Blocking filesystem operations and console
writes are not promised interruptible. Both state and delivery paths remain
operator-owned; this is not a hostile same-user filesystem API.

Qualification: `cargo test -p rabsd prepared_operation::completion`,
`cargo test -p rabsd --bin rabsd prepared_jobs::wait`, and
`cargo test -p rabsd --test prepared_job_wait`. The process test runs the actual
daemon and client over UDS after production receiver/store setup with a scripted
transport-admitted peer. It does not run a compiler, TLS session, or fleet gate.

### Authenticated delivery

Provision an explicit CA plus server and worker certificates with the appropriate
serverAuth/clientAuth uses. The worker verifies the server's configured DNS name;
both endpoints require the native `rabs-worker-atp/1` ALPN. Use existing trusted
credential provisioning; do not accept a certificate or key pin learned from an
untrusted worker connection.

Obtain the expected worker public-key pin from its independently trusted
certificate. This hashes DER SubjectPublicKeyInfo, not the whole certificate:

```sh
openssl x509 -in /credentials/worker.pem -pubkey -noout |
  openssl pkey -pubin -outform DER |
  openssl dgst -sha256
```

Use the resulting 64 lowercase hex digits as `<worker-spki-sha256>`. On the
receiver, all three TLS paths are required, nonempty and absolute:

```sh
RABS_COORD_TLS_CA=/credentials/ca.pem \
RABS_COORD_TLS_CERT=/credentials/coordinator.pem \
RABS_COORD_TLS_KEY=/credentials/coordinator.key \
rabsd --worker-exec-tls 0.0.0.0:7091 fleet-worker <worker-spki-sha256> \
  /absolute/request.json /absolute/results/delivery-42
```

On the worker host:

```sh
RABS_WORKER_TLS_CA=/credentials/ca.pem \
RABS_WORKER_TLS_CERT=/credentials/worker.pem \
RABS_WORKER_TLS_KEY=/credentials/worker.key \
RABS_WORKER_TLS_SERVER_NAME=coordinator.example.internal \
rabs-wkr --coordinator coordinator.example.internal:7091 --worker-id fleet-worker --once
```

The listener address is a literal IP:port and may be non-loopback only in TLS
mode. Bind it to the intended interface and apply the deployment's network
access policy. TLS mode never tries plaintext, even on loopback or after a
configuration error. The command accepts one connection; an invalid peer ends
this invocation without dispatch rather than starting an unbounded accept loop.

Admission checks the configured SPKI against the public key TLS authenticated,
then checks the hello's peer claim and versions through `CoordinatorSession`.
The worker answers a fresh session/operation/token challenge, then passes durable
boot-generation/incarnation admission before receiving the grant or uploading
source. The existing S5 `canonical-probes:<peer-id>` label is retained for
handshake compatibility, but the delivery adapter additionally permits only the
complete operator-selected execution or recovery request, exactly once. Unknown
operations, publication attempts and a changed request cannot pass that adapter.
The grant explicitly disables publication and arbitrary session resume. Sealed
result retrieval uses the separately negotiated `durable-result-v1` protocol on
a fresh authenticated connection, not continuation of the old session.

An authenticated receipt records `transport_authenticated:true`, the
`worker_spki_sha256`, `authenticated_session_id` and `identity_generation` before
release ACKs. These fields come from the adapter, not worker-supplied JSON.
Authentication establishes the sender, not correctness or determinism of its
execution; all byte and manifest checks still apply. Identity generation 1 here
describes the pinned key's worker role; key rotation is not implemented.

The operator persists each stable worker name's authenticated SPKI binding and
boot-generation/incarnation history beneath `$RABS_STATE_DIR/worker-admission`
(default `~/.cache/rch/rabs-state/worker-admission`). It reuses the coordinator's
exclusive store lock and durable S022 fence. Concurrent receivers for the same
worker name refuse; separate workers remain independent. A first failed TLS or
challenge exchange does not establish a key binding. Once authenticated, changing
the pin under the same name refuses before listening rather than creating fresh
boot history. Treat worker names and state roots as durable configuration; renaming
a worker or discarding its state is not an outcome-recovery operation.

Lower boot generations refuse across receiver restarts. Conflicting active
incarnations at the same generation persist a clone-ambiguity refusal; neither
contender can clear it by incrementing its boot number or supplying a JSON
re-enrollment claim. Clean completion releases the exact session while retaining
high-water history. A killed receiver leaves its session conservatively open.
This command does not provide a key-rotation/re-enrollment service, cross-host
clone adjudication, scheduling, or authoritative action-cache admission.

TLS mode has separate absolute network budgets: 60 seconds for accepting the
connection, the native transport's five-second TLS handshake limit, 10 seconds
for application admission, five minutes for source upload, and an additional
30 minutes when uploading a selected toolchain. Toolchain chunks are pipelined
in bounded batches of four. The worker independently enforces the input budgets
described below. Execution still has at most 30 minutes plus 60 seconds for cleanup,
followed by five minutes for verified result transfer and 10 seconds for both
ACK replies.
Bytes, telemetry and repeated ranges do not reset a phase. Timeout poisons the
connection; partial writes are never retried. The native ATP payload limit is
1 MiB minus 64 bytes; larger requests are rejected before listening. Filesystem
operations, including sync, are not guaranteed interruptible by these budgets.

### Worker input deadlines release abandoned uploads

The worker starts its own monotonic input clock when it accepts the first source
upload for a request. Source upload has five minutes. A matching toolchain upload
may begin only after source sealing; it then has at most 30 minutes, with a fixed
35-minute limit measured from the original source start. Repeated begin frames,
chunks, heartbeats and refused requests do not renew either limit. Fully sealed
inputs remain subject to the deadline until their matching execution takes
ownership.

The session driver races input reads, filesystem-task completions and reply
writes against the same deadline. A connected client that sends nothing, sends
only heartbeats, or stops reading an upload acknowledgment therefore cannot keep
the staging reservation indefinitely. Expiry closes the session with
`input-upload-deadline-exceeded`, revokes both source and toolchain readiness,
and drains accepted filesystem work before dropping the staged trees. If a write
has already emitted part of a frame, the worker abandons the connection without
appending another frame or retrying the partial write.

While staged inputs belong to a request, an unrelated execution or result-resume
request is refused before durable admission. Successful handoff of the matching
inputs ends the upload clock; the execution's own hard timeout and renewable
lease then govern its lifetime. Ordinary result recovery starts without staged
inputs and does not acquire an upload deadline. As with execution cleanup, an
operating-system filesystem call that stalls can delay the final joined cleanup.

If expiry or an input-ownership failure is discovered after durable admission
but before invoking the launcher, the worker records a resolved error receipt
with `executed:false` and `execution_may_have_run:false`. The failed request ID
remains reserved across restart, while later request IDs can proceed. A failure
to persist that receipt keeps the journal closed to further admission.

### Execution leases stop abandoned compilations

Authenticated execution requires the worker to advertise `request-renewal-v1`.
The coordinator selects a 30-second execution lease during session admission and
renews it every 10 seconds while waiting for the execution result. An older
worker that does not advertise this protocol is refused before source upload or
dispatch. Upgrade the coordinator and worker together. Result resume and release
acknowledgment reconciliation remain available without an execution lease.

The grant binds the authenticated session, a fresh lease ID, worker boot and
incarnation, request ID, and SHA-256 of the complete original JSON request. It
travels in `session-ok`; the saved request and durable journal fingerprint remain
unchanged. Source upload does not consume execution time: the worker arms its
local monotonic timer only after the exact request is admitted and before its
execution owner starts. The request's independent hard timeout still applies.

The worker checks expiry in its execution owner, including the managed process
drain loop. An open but silent connection, or a blocked renewal-acknowledgment
write, cannot keep a compiler alive. On observed expiry, the worker stops and
drains its process group, records exit 125 with `stop_reason:lease-expired`, and
retains complete captured diagnostics through the ordinary verified delivery and
recovery path. An expired execution cannot supply successful build artifacts.
Filesystem operations blocked inside the operating system remain subject to the
existing cleanup limitations; the lease is not a guarantee of interruptible I/O.

Renewals must name the exact session, lease and active request, with a strictly
newer sequence. The coordinator permits only one unacknowledged renewal and
measures its own deadline from sending it, so delayed acknowledgments cannot
grant extra time. Expiry, cancellation and completion permanently stop renewals.
One exact outstanding acknowledgment may be drained after the terminal result;
it cannot revive execution. A partial renewal write poisons the connection and
is never retried. Local expiry reduces the remaining result-drain budget to at
most 60 seconds without claiming that remote cleanup has already completed.

This lease controls execution liveness on the existing prepared-request path.
It does not establish the full action-generation authority or semantic input
identity required for action-cache publication. The explicit plaintext loopback
fixture remains an unleased test path.

### Interrupt an authenticated build without losing its outcome

During an online `--worker-exec-tls` or `--worker-build-tls` operation, Ctrl+C
(SIGINT) or SIGTERM can request cancellation of the exact dispatched execution.
No new command flag is needed. The receiver's signal adapter is installed after
TLS connection establishment. A stop observed before execution dispatch closes
the connection without starting work; during source staging the worker's normal
session-loss path retains ownership until accepted filesystem work drains.

While awaiting an execution result, the first observed signal sends exactly one
`cancel` for that request ID over the existing authenticated connection. It then
waits for the actual terminal result, not merely `cancel-accepted`. The remaining
execution/cleanup deadline is reduced to at most 60 seconds from that signal,
never extended past the original deadline. Heartbeats and cancellation replies
do not refresh it. A complete result then uses the ordinary bounded transfer
phase: every diagnostic and successful artifact is verified and made locally
durable before release acknowledgments, exactly as for uninterrupted delivery.

When cancellation wins, the worker ordinarily reports exit 130 and
`stop_reason:cancelled`; complete diagnostics remain recoverable and no failed
build artifacts are installed. When completion wins the race, the receiver
preserves the actual result and original exit status, including successful
artifacts. Sending a cancel is not evidence that the command was cancelled.
One matching late cancellation response may follow a completed result without
being mistaken for a byte-range response or authorizing another execution.

A second observed signal abandons the connection without repeating cancellation
or acknowledging incomplete output. An interrupt during result resume, byte
transfer or acknowledgment reconciliation likewise abandons that operation; it
never obtains permission to cancel or execute another request. A failed or
partial cancel write is terminal for the connection. None of these paths retries
execution, clears worker history, or falls back to a local compiler.

Keep the original request and delivery directory after interruption. A complete
verified receipt still supports ordinary offline recovery. An incomplete delivery
remains inspection state; explicit `--resume` may retrieve a retained original
result into a new directory. A cancellation acknowledgment, EOF, or deadline
expiry alone does not prove remote cleanup or make reexecution safe.

Signal handling is not a claim of interruptible filesystem I/O: capture, hashing,
fsync, and output installation can still block in the operating system. Signals
are observed while reading network records and before new writes; writes already
in progress retain the native transport's existing deadlines. Before the TLS
adapter is installed, and in the separate plaintext loopback fixture, existing
process-signal behavior is unchanged. SIGKILL cannot perform graceful recovery.

### Trusted local fixture

Start the receiver with an existing absolute parent and a NEW delivery directory:

```sh
rabsd --worker-exec-loopback 127.0.0.1:7091 local-worker \
  /absolute/request.json /absolute/results/delivery-42
```

In another terminal on the same trusted host, start the worker:

```sh
rabs-wkr --coordinator 127.0.0.1:7091 --worker-id local-worker --once
```

The receiver writes its listening address to stderr, accepts exactly one worker,
negotiates `ranges-v1`, `request-journal-v1`, and `files-v1` when artifacts are
requested, then sends exactly one execution request. Existing delivery paths
are reverified offline when complete and matching. Incomplete directories,
including empty directories and symlinks, are refused without overwriting them.
There is no automatic reconnect, command retransmission, or local compile fallback.
The existing worker journal still owns admission. The requested ID must exceed
the worker/endpoint's durable high-water; an older or equal ID is refused before
execution. A newer ID can also be refused by the worker if prior work is uncertain.
Never delete/reset the journal, change endpoints, or increase an ID merely to
retry work whose outcome is unknown. Use outcome reconciliation first.

## What becomes available

A completed receiver directory contains:

```text
artifacts/<accepted relative names>
diagnostics/stdout
diagnostics/stderr
delivery.json
```

The receiver independently verifies the requested names and unit, sorted
manifest, executable bits, lengths, manifest digest, request identity, offsets,
end-of-file indicators, per-chunk digests, and complete file digests. Exact-file
requests require equality with the declaration. Explicit `tree-files-v1`
requests require every named output and verify the complete bounded manifest,
including intermediate files. Arbitrary binary bytes, including NUL and non-UTF-8
diagnostics, are preserved in files. Executable artifacts receive mode 0700;
other files receive 0600. The delivery root is private. The receiver never writes
these files into a Cargo target tree or claims Cargo freshness from their presence.

Each range is at most 65,536 raw bytes. Loopback wire frames and request files are
bounded to 1 MiB. A combined 1 GiB budget covers BOTH diagnostic streams AND all
artifacts; this receiver policy may be stricter than individual worker limits.
A peer advertising more is refused before ranges are requested. Network accept
and handshake in loopback mode each have a 60-second absolute budget. After dispatch, the exchange
has the effective execution budget (at most 30 minutes) plus five minutes for
transfer. Trickled bytes and telemetry cannot renew those deadlines. These are
network budgets, not a promise to interrupt an operating-system fsync that stalls.

Source uploads batch up to four ordinary `source-chunk` messages, including
chunks from different selected files, before draining their ordered acknowledgments.
The final source seal still waits for every acknowledgment. Diagnostic and artifact
downloads similarly queue at most four ordinary range requests for one file, then
verify every response before starting another batch. This removes the mandatory
one-response wait after each individual chunk without increasing a chunk's size,
relaxing any hash or identity check, or renewing the phase deadline. Malformed
responses and failed writes stop the operation without retrying a batch. Existing
missing-file hints and unaligned local resume prefixes retain their usual meaning;
no new CLI flag, wire version or cache-publication authority is introduced.

All file hashes must match before any ACK is sent. The receiver syncs files,
directories, and parent ancestry, writes and syncs `delivery.pending`, renames it
to `delivery.json`, and syncs the directory again. Only then does it acknowledge
diagnostics and artifacts. This requires local storage with working file and
directory fsync semantics. Private receiver directories must not be concurrently
modified by another local process; this is not a race-proof shared-directory API.

### Reuse artifact bytes across authenticated deliveries

An optional coordinator-local artifact cache can satisfy complete artifact files
from earlier deliveries from the same authenticated worker. A new execution still
runs, and the receiver still validates the current terminal result, request,
artifact manifest, Cargo report and diagnostics. The cache supplies file bytes;
it does not supply a result, compilation outcome or permission to publish.

Configure the process that owns the authenticated connection:

| Variable | Default | Contract |
|----------|---------|----------|
| `RABS_ARTIFACT_CACHE_DIR` | Disabled | Existing absolute parent directory, owned by the current user, with no group/other permissions or symlink ancestors |
| `RABS_ARTIFACT_CACHE_BYTES` | `1073741824` | Decimal integer from `1` through `17179869184`; aggregate logical object and pending-copy bytes |
| `RABS_ARTIFACT_CACHE_ENTRIES` | `4096` | Decimal integer from `1` through `65536`; aggregate objects and pending-copy entry |

Only the dedicated `artifact-bytes-v1` child is managed. Create the parent
explicitly outside captured inputs, retained bundles, deliveries and installed
outputs. The application never creates or chmods that parent. For example,
after configuring the existing coordinator TLS credentials:

```sh
mkdir -m 700 /absolute/rabs-artifact-cache
RABS_ARTIFACT_CACHE_DIR=/absolute/rabs-artifact-cache \
  rabsd --worker-build-tls 0.0.0.0:7091 fleet-worker <worker-spki-sha256> \
    /absolute/bundles/build-42 /absolute/deliveries/build-42 /absolute/outputs/build-42
```

The same environment settings apply to `--worker-exec-tls`, source-backed
prepared TLS builds and explicit result resume. `--resume-from` takes precedence
and disables the byte cache for that operation, preserving its existing refusal
of corrupt local prefixes. For daemon prepared jobs and
live dependency execution, configure the daemon before startup; setting the
variables only on a submitting client cannot reconfigure that running process.
Acknowledgment-only reconciliation does not open the cache. Plaintext loopback
delivery cannot consume or seed it.

All three variables absent disables the cache. An empty/relative/traversing
directory, malformed or out-of-range limit, or a limit supplied without the
directory produces a configuration error before session grant, source upload or
execution dispatch. A syntactically valid configuration whose storage cannot be
opened privately emits one `artifact-byte-cache-unavailable` JSON setup
diagnostic on stderr and continues through ordinary verified transfer.

Cache identity includes the authenticated SPKI and worker name, then the
artifact's complete SHA-256 and byte length. A new request or session can reuse
matching bytes; a changed worker name or key cannot. The current manifest owns
the destination path and executable mode. Cached objects are ordinary private
files, and delivery copies receive independent inodes. Writes to an installed
artifact therefore cannot alter the retained cache object.

Every hit is copied and completely rehashed before the file is accepted. A
corrupt, missing or inaccessible object is a miss, and the receiver downloads
that file through its normal bounded range pipeline. Current diagnostics are
always received and verified. Newly verified artifact bytes can populate the
cache under the aggregate byte and entry bounds; an optional cache-storage
failure can skip population without turning a successful delivery
into a failure. Cache objects may survive restarts, but their presence alone is
never trusted.

Warm readers share a nonblocking read lease that prevents their objects from
being evicted; an active exclusive writer can force a cold read or skip optional
population. The limits cover logical payload bytes and entries, including
incoming copies and retained readers; filesystem blocks and metadata consume
additional space. Before optional population, free-space and inode checks reserve
room for the remaining current artifacts and delivery receipt, accounting for
filesystem allocation rounding, but cannot guarantee capacity against unrelated
concurrent disk writers.

The local copy and population loops check the same operation deadline and
interruption state at each 64 KiB boundary. A cancellation, expired phase budget,
or failed write to the actual delivery is propagated instead of being retried as
a cache miss. Daemon cancellation after an observed terminal result retains its
existing verified-delivery drain; explicit operator signals retain their existing
abandon behavior. All required file checks, directory syncs, the current
`delivery.json`, and worker acknowledgments still occur.

The byte-cache tests run the real receiver and filesystem with controlled
protocol peers. They check warm range elision, scope separation, corrupt-cache
fallback, independent copies, bounded storage and interrupted copying. They do
not constitute a native TLS/compiler performance measurement:

```sh
cargo test -p rabsd --lib coord::worker_delivery --locked
cargo test -p rabsd --lib coord::secure_worker_delivery --locked
```

## Failure and acknowledgment semantics

Compiler success and successful byte delivery are different facts. A failed or
interrupted compilation may produce a verified diagnostic delivery, but no
compiled-artifact bundle. The execution/delivery operator exits with the recorded
nonzero compiler or interruption status. Missing captures, malformed results,
unresolved reported descendants, corrupt bytes, and disk errors never become
successful deliveries.

Before the local delivery frontier, failures produce `worker-delivery-error` on
stderr. Once any execution write is attempted, `execution_may_have_run` remains
true even when that write fails. No error response authorizes reexecution. Partial
staging is retained for inspection rather than silently deleted or reused. A
final directory-sync error can leave a receipt on disk whose durability is
uncertain; no release ACK is sent and the command does not report success.

After the frontier, a lost or mismatched ACK response does not invalidate the
verified local files. The command returns `worker-delivery` with
`acknowledgments_confirmed:false`, an acknowledgment error, and `reexecute:false`.
The verified receipt remains available. Losing the command's own stdout after
that point likewise is not permission to rerun the compiler. Normal repetition
reverifies that local delivery offline and does not contact the worker. It cannot
confirm remote acceptance or release retained-result capacity by itself.

### Retrieve a missing local result without re-executing

`--resume` takes the ORIGINAL request and a new absolute delivery directory. It
sends only `result-resume`, verifies the retained bytes using the ordinary delivery
receiver, and acknowledges only after complete local durability. A complete
matching destination still recovers offline; an incomplete existing destination
is never repaired or overwritten. No source checkout or `--source-root` is needed.
Resume requires the worker's matching durable admission and retained result; an
unavailable result is an error, never permission to run the compiler again.

### Resume an interrupted download using local prefixes

`--resume-from` selects an old delivery directory as a source of candidate bytes,
while recovering the original retained result into a **new** directory:

```sh
rabsd --worker-exec-tls --resume-from /absolute/deliveries/interrupted \
  0.0.0.0:7091 fleet-worker <worker-spki-sha256> \
  /absolute/request.json /absolute/deliveries/recovered
```

It implies result resume and cannot be combined with `--resume`, `--acknowledge`
or `--source-root`. The flag and its absolute path may precede or follow all
positionals. Both `--worker-build-tls` and the corresponding loopback commands
accept the same flag. The ordinary loopback reachability/provenance restrictions
remain unchanged; prefix availability never selects a different transport.

The worker must still authenticate under the selected policy and return its
matching retained result. The receiver then copies ordinary local file prefixes
into new independent files and downloads only their remaining ranges. A complete
nonempty local file can avoid range reads, but every copied byte still enters
the same complete-file SHA-256 check as downloaded bytes. A prefix need not end
on a protocol chunk boundary. Missing local members use normal full downloads;
this is contiguous-prefix recovery, not sparse out-of-order chunk recovery.

The previous directory is never repaired, truncated, linked into the new output,
or promoted to a verified delivery. Its markers, file lengths and timestamps
cannot supply result identity, transport authentication or release authority.
The new receipt describes the current delivery session and retains the original
request fingerprint. All manifest, aggregate-budget, durability and release-ACK
checks remain in place. No source upload or compiler dispatch is permitted.

Nonregular members, symlink parents/files, additional hard links, oversized files
and detected changes refuse. A corrupt local prefix plus a valid remote tail
fails the complete-file hash and sends no release acknowledgment; it does not
silently retry, repair the old directory or install a partial build. A subsequent
explicit ordinary `--resume` into another new directory can omit those candidates
without reexecuting the compiler, provided the worker still retains the result.

Old and new roots must be disjoint, with ordinary directory ancestors and an
existing parent for the new destination. Prepared builds additionally keep the
prefix source separate from their bundle and installation directory. Local root
preflight precedes credentials/listening, but a complete matching local delivery
still recovers offline even if the old prefix source no longer exists. Keep both
trees exclusively operator-owned during online recovery: filesystem checks are
not a hostile same-user race-proof API. The old data remains on disk, so plan for
a full new delivery's storage as well as the retained partial copy. Filesystem
copy/hash/sync work is not promised interruptible; transport deadlines are not
renewed by prefix reuse.

### Reconcile lost acknowledgments without downloading again

Use `--acknowledge` only when the complete local delivery already exists and its
receipt contains `result_retention:durable-result-v1` plus the retained-result
seal. This addresses the case where bytes are safely local but an acceptance ACK
was lost, so the worker still refuses new work while retaining the old result.
For the authenticated lane, reuse the established coordinator credentials and
original worker endpoint, identity and state directory:

```sh
RABS_COORD_TLS_CA=/credentials/ca.pem \
RABS_COORD_TLS_CERT=/credentials/coordinator.pem \
RABS_COORD_TLS_KEY=/credentials/coordinator.key \
rabsd --worker-exec-tls --acknowledge \
  0.0.0.0:7091 fleet-worker <worker-spki-sha256> \
  /absolute/request.json /absolute/results/delivery-42
```

The worker connects as in authenticated delivery above. The trusted-local fixture
also supports `rabsd --worker-exec-loopback --acknowledge` with its usual four
positionals. The flag may precede or follow the positionals, but cannot be mixed
with `--resume`, `--resume-from` or `--source-root`. A plaintext receipt cannot be acknowledged as
an authenticated one, and TLS failure never selects the loopback lane.

Before listening, acknowledgment recovery verifies the existing receipt, exact
request and historical transport policy, every diagnostic/artifact byte and mode,
and the complete file tree. It then authenticates the worker, resumes only the
original request, and requires the same retained-result seal, outcome, lengths,
diagnostic hashes and complete artifact manifest. It rechecks local bytes after
the network round trip, before sending either release ACK. It sends no source
bytes, range reads or compiler command and never replaces local files or rewrites
the historical receipt.

When both ACKs were already journaled but the final reply was lost, the worker may
refuse result resume because its copies have been released. The receiver then
queries `request-status` for the same admission. Only a matching terminal outcome
and exact seal marked `retained_result_released:true` confirm acceptance. A missing
spool, larger high-water mark, generic refusal or foreign result cannot confirm
it. If the worker has moved on and no longer retains that admission's metadata,
the operation refuses rather than guessing. The valid local delivery remains
usable independently of whether remote acceptance can still be confirmed.

Successful `--acknowledge` exits **zero**, reports
`acknowledgments_confirmed:true`, and keeps the original compiler exit code in the
receipt even when compilation failed. Reconciliation failure exits nonzero with
`execution_may_have_run:true` and `reexecute:false`; the local result is retained.
A new explicit invocation can retry reconciliation on a fresh connection. No
failure retries the same connection or authorizes execution. Prevent concurrent
same-user modification of the local delivery throughout this operation.

## Qualification

Run the receiver unit, TCP transport, and real CLI tests:

```sh
cargo test -p rabsd worker_delivery
cargo test -p rabsd delivery_ack
cargo test -p rabsd --bin rabsd worker_exec
cargo test -p rabsd --test worker_delivery_cli
cargo test -p rabsd --test worker_exec_tls
cargo test -p rabsd coord::secure_worker_delivery::interrupt
cargo test -p rabsd --test worker_interrupt_tls
cargo test -p rabsd worker_delivery::reuse
cargo test -p rabsd --test worker_resume_tls
```

The prefix-recovery tests interrupt an actual receiver's native TLS download,
then launch a fresh receiver/build command using its partial files. They require
only the remaining artifact ranges, complete local hash verification before ACKs,
independent installed outputs, and offline replay without the old prefix source
or configured credentials. Corrupt prefixes and a different CA-valid worker key
must refuse. The peer is scripted; these tests do not execute a compiler or
establish real-worker spool/fleet proof. They remain coverage awaiting execution,
not measured network-performance or passing acceptance evidence.

The interruption tests send real SIGINT/SIGTERM to the actual receiver process
while communicating through native mutual TLS. Their scripted peer exercises
cancel-once, complete binary diagnostics, completion races, pre-dispatch and
resume interruption, second-signal abandonment, foreign cancellation replies,
and offline recovery of a cancelled delivery. They do not execute a compiler or
prove worker descendant cleanup. The unit tests additionally cover partial-frame
preservation, failed writes, and absolute cancellation-drain deadlines. All new
interruption tests still require execution on a supported Rust host; source
coverage alone is not a passing cancellation or fleet-qualification result.

The CLI test starts the actual receiver binary and a scripted TCP peer, delivering
binary artifacts and multi-range diagnostics through the production receiver.
It verifies that a complete local receipt exists before either ACK arrives.
It does not execute a real compiler or prove authenticated fleet behavior. The
separate worker `artifact_transfer_linux` test exercises real canonical compilation.
The TLS tests generate temporary credentials with OpenSSL and connect a scripted
native mutual-TLS/ATP peer to the actual `rabsd --worker-exec-tls` process. They
exercise complete multi-range binary delivery, configured-key refusal despite a
valid CA, authentication before dispatch, corrupted data from an authenticated
peer, no plaintext downgrade, and pre-network configuration/path refusals.
Acknowledgment cases first obtain a delivery through that real receiver, then
exercise fresh TLS reconciliation, repeated lost replies, exact already-released
confirmation, changed-result refusal and local-evidence preservation with no
range reads or local inode replacement. OpenSSL is required; these security tests
do not silently skip its absence. The scripted peer does not execute a compiler
and is not a real fleet qualification. Tests added with this path still require
execution on a supported Rust host; their presence alone is not passing test or
production-qualification evidence.

Registry replay adds shared sandbox, worker and sender regression coverage:

```sh
cargo test -p rabs-sandbox cargo_home
cargo test -p rabs-wkr cargo_home
cargo test -p rabsd cargo_home
```

The controlled-host registry acceptance case is selected explicitly:

```sh
cargo test -p rabs-wkr --test cargo_tree_worker_linux registry_tests -- --ignored
```

It requires canonical-capable Linux, a complete Rust toolchain and linker, tar
and gzip. It generates a local registry package, uploads it to the actual worker,
compiles offline inside the canonical namespace, restarts after completion and
retrieves the original result without reupload or reexecution. It downloads and
checks every output before running the received executable. Its negative case
uploads transport-valid bytes with a wrong Cargo package checksum and requires
Cargo to reject them with no artifact offer. The client is a bounded loopback
fixture, not an authenticated fleet coordinator. Missing prerequisites fail when
this ignored test is explicitly selected; source presence is not a passing gate.


Vendored automatic preparation adds seven filesystem/metadata regressions and
three normal process-level tests. They run the actual preparation CLI and a
frozen local Cargo build from retained inputs after the original checkout changes,
including transitive dependencies, a build script and its included data:

```sh
cargo test -p rabsd coord::source_delivery::preparation::cargo::vendor
cargo test -p rabsd --test cargo_vendor_prepare
```

The separate native-TLS end-to-end case is intentionally ignored by default. On
a canonical-capable Linux host with OpenSSL and a complete Rust toolchain, build
the matching worker from the same revision and explicitly select it:

```sh
cargo build -p rabs-wkr
RABS_TEST_WORKER_BIN=/absolute/path/to/target/debug/rabs-wkr \
  cargo test -p rabsd --test cargo_vendor_prepare \
  automatic_vendored_bundle_builds_over_native_tls_and_replays_installed_outputs_offline \
  -- --ignored --exact
```

That case launches both real binaries, creates temporary TLS credentials, prepares
a dependency-backed bundle, compiles through the worker's canonical namespace,
verifies and installs the complete output, and runs the installed executable.
It then removes access to source and credentials and repeats the command offline,
requiring unchanged receipt/request identities and no worker connection. Missing
prerequisites fail when the test is selected. These tests are implementation
coverage awaiting execution, not a reported passing fleet or performance gate.

Toolchain delivery adds filesystem receiver/export tests, worker session-driver
tests, and preparation plus native TLS sender tests:

```sh
cargo test -p rabs-sandbox toolchain_transfer
cargo test -p rabs-sandbox --test toolchain_dataset_realfs
cargo test -p rabs-wkr toolchain_upload_session_tests
cargo test -p rabsd --test toolchain_binding
cargo test -p rabsd --test worker_exec_tls toolchain
```

Input deadline regressions drive the production worker session on the native
current-thread runtime with short injected budgets. They cover idle uploads,
blocked acknowledgments, traffic that cannot renew a deadline, and execution
handoff. The transport peer is a fixture; these tests do not establish native TLS
or canonical compiler coverage:

```sh
cargo test -p rabs-wkr --bin rabs-wkr input_deadline
```

The TLS sender tests use a scripted peer and the actual filesystem receiver;
they do not prove that a compiler ran. A separate explicitly selected case runs
both binaries, uploads the full selected compiler tree, builds the vendored
workspace, runs the installed executable, and repeats delivery recovery with
both retained input directories unavailable:

```sh
RABS_TEST_WORKER_BIN=/absolute/path/to/target/debug/rabs-wkr \
  cargo test -p rabsd --test cargo_vendor_prepare \
  uploaded_toolchain_builds_vendored_workspace_over_native_tls_and_recovers_offline \
  -- --ignored --exact
```

That case requires the same canonical Linux and TLS prerequisites, plus disk
space and transfer time for the selected complete toolchain. Its request carries
no worker-local toolchain path. It retains the ordinary compiler timeout; its
larger setup and transfer allowance covers the newly uploaded compiler data.
