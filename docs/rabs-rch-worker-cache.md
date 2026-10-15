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

RABS still checks exact input keys, output custody, publication, trust,
sampling and materialization. Readiness is not a hit. Unsupported units and
required verification executions compile normally. No serving policy, default
projection, target ownership rule or RCH artifact-delivery path is relaxed.
Separate workers retain separate caches; reuse is limited by the existing
live dependency class and its path/input contracts.

## Validation boundaries

`tests/test_rabs_worker_cache.py` executes the exact embedded shell and Python
adapter with the real launcher and real Linux processes, Unix sockets, locks
and jobserver pipes. Its 23 tests include concurrent startup, managed crash
recovery, refusal of incompatible launchers before source execution, opaque
argv, exec-once exit/signal behavior and a PATH-shim sensitivity control.
Cargo, Rustup and the daemon in these tests are fixture executables. The
existing 50 launcher tests remain unchanged. Five additional Rust unit tests
exercise command construction and opt-out parity.

Both native suites passed during implementation. Rust compilation, those Rust
unit tests, Clippy, formatting, real Cargo cache-hit parity and fleet acceptance
were not run in the implementation environment because Cargo/Rust tooling was
unavailable. The RABS Binaries workflow now includes the native suites on its
x86-64 and AArch64 runners and the Rust assembly tests, retaining all previous
runtime gates. Workflow configuration is not a passing CI result.

Before claiming fleet acceleration, qualify rebuilt binaries with actual Cargo
and daemon execution: confirm served decisions correspond to skipped compilers,
compare returned artifact bytes to stock builds, test private target isolation,
record cold/warm/refusal rates and include setup cost in elapsed-time results.
No speedup or production deployment is established by the fixture suite.
