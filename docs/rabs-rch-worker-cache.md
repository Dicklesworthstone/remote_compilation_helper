# RCH-dispatched Cargo with worker-local RABS

This is the master plan's section 3.7 execution profile: RCH still selects a
worker, transfers source, runs Cargo there and returns artifacts. An opt-in
adapter prepares the existing RABS dependency cache on that worker before
executing the original command. It is not fleet-wide per-action scheduling,
cross-worker cache sharing, or automatic `rabs-wkr` action dispatch.

## Enable for a build

Use a rebuilt RCH containing this adapter, and install the complete matching
RABS toolset on each selected Linux worker. The worker's execution PATH must
resolve `cargo-rabs`; that installed launcher must advertise preparation API
version 1. Python 3.9+ is required. Existing installation instructions are in
[rabs-ssh-deployment.md](rabs-ssh-deployment.md).

```sh
RCH_RABS_WORKER_CACHE=1 rch exec -- cargo build --release
RCH_RABS_WORKER_CACHE=1 rch exec -- cargo check
```

The switch belongs to the process constructing the remote command, usually
RCH on the dispatcher. It is not a path to a dispatcher-side wrapper, and it
need not be forwarded to the worker. Only the exact value `1` enables it.
Unset the variable to restore the previous command builder unchanged; this
does not stop shared daemons or delete cached state. Installation alone never
enables the profile.

Ordinary literal `cargo` commands are recognized after the existing inline
environment or `env` prefix. Non-Cargo commands, quoted or expanded executable
names, absolute executable paths and nested shell commands keep their old
behavior. Existing RCH command normalization and eligibility rules still apply.
The adapter does not expand aliases or rewrite a compound command's later
commands. Darwin and Windows workers execute the original command without
loading the Linux-only preparation path.

## Execution and fallback

### Direct Cargo entry point

The launcher can select this remote profile directly, without preparing RABS
or starting a local build on the dispatcher:

```sh
cargo rabs --rabs-remote build --release
cargo +nightly rabs --rabs-remote check
RCH_WORKER=worker-a cargo rabs --rabs-remote test --no-run
```

This requires the updated `cargo-rabs` launcher, a matching rebuilt RCH client,
and the worker installation described above. `CARGO_RABS_RCH` selects an explicit
RCH executable; otherwise the launcher uses its normal sibling/PATH/release
search. Linux and macOS dispatchers are supported. It does not need a local
RABS installation. RCH may still perform its own metadata and toolchain probes.

The launcher execs `rch exec --source-content-receipt -- cargo ...` with
`RCH_REQUIRE_REMOTE=1` and `RCH_RABS_WORKER_CACHE=1`. Source receipts request
RCH's existing owned source/target path. They do not authorize caching an
arbitrary whole-Cargo result. RCH retains source-policy enforcement, worker
selection, toolchain resolution, target isolation, publication and delivery.
RCH's supported POSIX source-receipt transport is required; unsupported worker
or command combinations refuse rather than falling back to a local build.

Cargo arguments are passed as separate, unquoted argv elements. The executable
on the worker is literal `cargo`, not the dispatcher's `CARGO` path. Existing
`RUSTUP_TOOLCHAIN`, explicit Cargo `+toolchain` arguments and RCH routing settings
reach RCH unchanged. No custom local Cargo executable is transported or inferred
from its pathname. Non-UTF-8 arguments refuse remote dispatch without replacement;
the existing local launcher continues to support opaque Unix argv.

Once RCH is execed, the launcher cannot retry a failed/uncertain build or start
a local compiler. RCH owns its own admitted attempts and recovery policy. Its
statuses, output contracts and recovery instructions apply, including its
restrictions on Cargo JSON stdout; this is not a claim that every Cargo command
has stock-Cargo stdout behavior through the current RCH backend. Worker cache
setup remains best effort: remote-required is not cache-hit-required.

`--rabs-remote` cannot be combined with `--rabs-no-start` or
`--rabs-require-daemon`, which refer to local daemon setup. Options after the
first Cargo argument or an explicit `--` are never interpreted by the launcher.
`CARGO_RABS_REMOTE_ACTIVE=1` marks the RCH process tree so re-entering remote mode
refuses; an existing `RCH_RABS_WORKER_ACTIVE=1` similarly prevents second-hop
dispatch. These are recursion controls, not authentication or publication rights.
Normal local mode and the version-1 imported `prepare()` API are unchanged.

### Worker-side preparation

RCH's existing environment controls run before preparation. The adapter then
loads the worker-installed launcher's versioned `prepare` API without running
its CLI, and finally execs the unchanged `rustup run <toolchain> cargo ...`
(or original unpinned Cargo) argv. This ordering preserves Rustup's direct
Cargo selection and custom-toolchain fallback; resolving Cargo from PATH after
running Python inside `rustup run` would not be equivalent.

The launcher remains the only owner of bounded daemon startup, dual lifetime
locks, ownership checks and crash recovery. It resolves its existing
`RABS_CONFIG`, `RABS_SOCKET_PATH`, `RABS_STATE_DIR`, `CARGO_RABS_DAEMON`,
`CARGO_RABS_WRAP` and `CARGO_RABS_STARTUP_MS` settings in the worker environment.
A running daemon is neither reconfigured nor stopped. Explicit custom or
disabled wrapper environment settings retain the launcher's stock-Cargo
fallback. As with direct `cargo rabs`, successful setup explicitly selects
`rabs-wrap`, overriding Cargo's `build.rustc-wrapper` configuration.

Missing Python/launcher, unsupported preparation API or a setup failure does
not fail or repeat the compilation: the original command runs once. Setup
failures emit a worker-stderr explanation. After exec there is no retry branch.
Arguments, cwd, target directory, selected toolchain, inherited jobserver
handles and the command's exit status remain under their existing owners.
`RCH_RABS_WORKER_ACTIVE=1` prevents repeated preparation in an already-prepared
process tree; it is not cache-hit or compiler-skip authority.

Preparation runs in an owned helper under `RCH_RABS_PREPARE_TIMEOUT_MS`
(0 skips setup, maximum 35000 ms; default `CARGO_RABS_STARTUP_MS` plus 2000 ms,
or 7000 ms without that override). Cargo retains its original descriptors.
Captured setup diagnostics are replayed by a separate, short-lived process
with only stderr, not by a potentially blocking write in the Cargo parent.
Replay has a 100 ms delivery budget and up to 250 ms of cooperative cleanup;
the existing preparation cleanup has its own 250 ms grace. A full stderr pipe
therefore cannot indefinitely prevent the final Cargo exec. No extra relay
is created for silent setup. Cargo's own output is never passed through this
bounded setup logger, and no inherited open-file-description flags are changed.

Readable setup logs retain their raw bytes up to the existing 16 KiB capture
bound. Slow, closed or unavailable diagnostic sinks can lose a suffix or the
whole setup diagnostic; this is not a durable logging contract. Cancellation
during replay terminates the owned relay and does not start Cargo. SIGCHLD
auto-reap or a custom child reaper bypasses setup before any helper is forked,
because those contexts cannot provide the retained PID ownership required for
safe cleanup. The original child-reaping disposition is not overwritten.
Kernel-blocked operations can outlive cooperative deadlines with SIGKILL
pending; this does not assert a hard wall-clock filesystem or process bound.

RABS still checks exact input keys, output custody, publication, trust,
sampling and materialization. Readiness is not a hit. Unsupported units and
required verification executions compile normally. The worker-cache profile
defaults a newly started daemon to `RABS_REUSE_CARGO_LAYOUT=1`, using the
existing tracked-read-safe projection for `CARGO_TARGET_DIR`,
`CARGO_BUILD_TARGET_DIR`, and `CARGO_BUILD_BUILD_DIR`. An explicit
`RABS_REUSE_CARGO_LAYOUT` value is preserved instead. When the adapter supplies
the default itself, it removes that variable again before Cargo is execed, so
the optimization does not create a new Cargo/build-script environment input.
An already-running daemon is never reconfigured. The projection keeps Cargo's
real paths and retains its policy identity and tracked-read publication veto.

No serving policy, target ownership rule or RCH artifact-delivery path is
relaxed. Separate workers retain separate caches; reuse is limited by the
existing live dependency class and its path/input contracts.

## Validation boundaries

`tests/test_rabs_worker_cache.py` executes the exact embedded shell and Python
adapter with the real launcher and real Linux processes, Unix sockets, locks
and jobserver pipes. Its 23 tests include concurrent startup, managed crash
recovery, refusal of incompatible launchers before source execution, opaque
argv, exec-once exit/signal behavior and a PATH-shim sensitivity control.
Cargo, Rustup and the daemon in these tests are fixture executables. The
original launcher behavior remains covered by its 50 regressions. Five additional
Rust unit tests exercise command construction and opt-out parity.

Eighteen additional tests in `scripts/tests/test_cargo_rabs.py` exercise the
remote entry point with real exec, signals, streams, cwd and jobserver handles.
They cover missing or recursive RCH executables, local-option conflicts,
unsupported argument encoding, routing/toolchain/argument preservation,
status propagation and the absence of launcher retries or local setup. The
RCH program in these tests is an explicit fixture. Three tests continue through
the production `worker_cache.py` and imported preparation API, proving
shared fixture-daemon setup, worker-side cache refusal and jobserver custody.
They still do not run the Rust RCH backend, SSH, real remote Cargo, source receipts
or cache hits. Run this whole test file through DSR with the other native suites.
Native macOS and full fleet acceptance remain separate checks.

`tests/test_rabs_worker_cache_diagnostics.py` adds sixteen adapter regressions
with real filled/broken pipes, raw diagnostic bytes, regular-file offsets,
jobserver descriptors, and relay cancellation under INT/TERM/HUP. Cargo and
installed preparation code are explicit doubles; one cancellation driver records
real fork results, and resource-failure tests inject fork refusal. Successful and
timed-out setup both wedge against the exact prior adapter when stderr is full;
the repaired adapter passes the same tests without draining that pipe. All 68
launcher tests and all 16 diagnostic tests passed during this integration.

CI and release qualification use DSR exclusively. The original fixture-suite
results above establish their stated process and adapter behavior.

Real Linux qualification on November 5, 2026 also passed the original four-round
public cache ladder through RCH/SSH: execute and commit, two verification
executions, then a served hit with no compiler execution for that dependency.
A full `cargo check --locked -j1 -p rabs-key` run repeated this for all eight
eligible registry dependencies. Every invocation used a fresh Cargo target;
all eleven Cargo compiler units reported `fresh=false`, all eight registry
metadata outputs matched stock bytes, and all six remote jobs had terminal
acknowledgements and complete source/target release records.

That full-project test was functionally correct but slower: ordinary RCH took
22.75 and 22.80 seconds, while the warm RABS run took 27.98 seconds. Cache
population and the two verification runs took 96.80, 121.28 and 105.63 seconds.
These results use the qualified e019 Rust build and 3f launcher identified in
[the execution plan](../RABS_BRIDGE_PLAN.md). Their qualification includes
751 Rust tests and 340 launcher/adapter tests, zero ignored/skipped, formatting,
full workspace checks and strict Clippy. A newly built metadata installation
optimization is still being qualified; these older results do not establish its
performance.

The metadata installation build also passed all four original native Linux
scenarios: CHECK with replay, edits, relocation and an expected compiler failure;
BUILD with archive replay and a working delivered binary; three fresh requests
through a persistent worker across coordinator restart; and the same service
with an explicitly prewarmed, complete SDK. These are real compiler runs over
authenticated loopback TLS on one host. Source, tool and full SDK byte audits
matched afterward, with no observed owned test processes remaining. The
source-bound receipts are in [the execution plan](../RABS_BRIDGE_PLAN.md).
This functional result does not establish a speed benefit. A subsequent worker
reconnect repair still requires its own build and native qualification.
Multi-host acceleration and native macOS dispatch remain open.

Before claiming fleet acceleration, qualify rebuilt binaries with actual Cargo
and daemon execution: confirm served decisions correspond to skipped compilers,
compare returned artifact bytes to stock builds, test private target isolation,
record cold/warm/refusal rates and include setup cost in elapsed-time results.
No speedup or production deployment is established by the fixture suite.
