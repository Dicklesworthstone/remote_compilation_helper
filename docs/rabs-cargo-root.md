# Explicit local Cargo root admission

`cargo-rabs` can hand local builds to the native `rabs-cargo-root` helper.
Every participating invocation reserves one root credit from the same durable
host-local budget. The credit covers the complete Cargo process tree, including
children which create a new session or process group. The helper releases it
only after Cargo is reaped and the kernel reports that its cgroup is empty.

This is a **count of simultaneous local Cargo trees**, not a CPU-slot grant or
a coordinator/fleet lease. Cargo's jobserver, `-j` flags and configuration keep
their existing meanings. A root capacity of four admits four trees; it does not
limit those trees to four total compiler processes. Worker CPU admission remains
the separate `RABS_WORKER_HOST_BUDGET_DIR` / `RABS_WORKER_HOST_SLOTS` mechanism.

## Enable it

Install a matching RABS bundle, including `rabs-cargo-root`. Both source builds
and the Linux GNU release archives include the helper. Set all three variables:

```sh
export CARGO_RABS_ROOT_BUDGET_DIR=/absolute/private/local/rabs-root-budget
export CARGO_RABS_ROOT_CAPACITY=4
export CARGO_RABS_ROOT_CGROUP=/sys/fs/cgroup/your-delegated-domain
cargo rabs build --workspace
```

The budget directory must be private local state owned by the invoking user;
all participating launches must use the same path and capacity. Keep it separate
from worker CPU budgets: the two domains count different resources. The helper
creates the directory and its immutable capacity manifest when first opened.
Their immutable manifest versions differ, so a worker and a root helper refuse
to open one another's budget directories even when the capacities match.
It never reinitializes existing state to change capacity or recover a crash.

The cgroup path must already be an explicitly delegated, writable cgroup-v2
domain below `/sys/fs/cgroup`. The host administrator or user service manager
must provide that delegation. The helper creates only its own child cgroups;
it does not enable controllers, modify ancestor resource limits, move another
process, or request system administration privileges. A read-only mount,
ordinary directory, symlinked path, threaded cgroup or missing control file
refuses before Cargo runs. The kernel must support `cgroup.kill` and pidfds.

`CARGO_RABS_ROOT_HELPER` can select a particular native executable. Normal
discovery searches installed siblings, `PATH`, then the checkout's release
directory, as with the other RABS tools. Partial or malformed configuration
refuses instead of silently dropping admission. These local settings cannot
combine with `--rabs-remote` or `--rabs-canonical`.

## Cargo behavior and lifetime

The Python launcher makes one `exec` handoff to the native helper. The helper
spawns a self-exec trampoline, which joins and verifies the exact new cgroup
before executing Cargo. This closes the usual spawn-then-attach race: Cargo
cannot fork a compiler before attachment. No unsafe `pre_exec` hook is used.

The original Cargo argument bytes, working directory, environment, inherited
jobserver descriptors, stdin/stdout/stderr and process group are retained.
The optional normal RABS wrapper setup still adds `RUSTC_WRAPPER` as before.
The helper adds `CARGO_RABS_ROOT_ACTIVE` to identify an already managed tree.
Nested ordinary Cargo and build-script subprocesses stay inside that tree;
nested `cargo-rabs` root admission refuses to avoid waiting on its own credit.

The helper forwards INT, TERM, HUP and QUIT to current cgroup members using
pidfds. The existing terminal process group is retained. After a two-second
grace period it uses `cgroup.kill` for the whole descendant tree, including
new sessions and nested cgroups. When Cargo exits normally, any remaining
descendants are also stopped before the root credit is returned. Cleanup has
a bounded wait; timeout or uncertain cgroup identity leaves the credit held
in durable quarantine. Successful commands preserve Cargo's exit status;
signal termination is replayed as a native signal after cleanup.
In this explicitly supervised mode those four signals mean cancellation,
including when the invoking shell previously ignored one of them. The helper
does not promise to preserve inherited ignored-signal dispositions.

If ordinary cache-daemon setup falls back to stock Cargo, explicitly requested
root admission remains in force. A native helper failure never retries the
build outside the gate. With no root-admission settings, the original direct
Cargo `exec` path is unchanged.

The delegation and budget are trusted same-user local state. Deliberately
migrating a workload to another cgroup or modifying budget state with the same
credentials is outside this cooperative admission contract. `setsid` and
ordinary process-group changes do not leave a cgroup.

## Crash quarantine

Before any spawn, the shared HostBudget substrate durably arms the root credit.
If the helper is killed or loses cleanup proof, closing its file descriptors
does not return that credit. Later invocations refuse or wait according to the
remaining capacity. A vanished PID, a restarted helper, a timeout or an empty
new cgroup does not prove that an old tree stopped.

There is no automated quarantine-repair command in this slice. Preserve the
budget state and affected cgroups for operator recovery. Do not delete, copy,
replace or edit a budget to force admission. Recovery requires fencing every
prior owner and proving its affected trees are empty before establishing new
admission authority. This local mechanism does not complete the plan's global
Cargo-root/frontier broker or distributed fairness work.

## Validation

Production-module tests cover strict configuration, actual-cgroup filesystem
checks, complete `populated` parsing and pidfd signals to an owned real child.
The shared HostBudget tests cover weighted contention, durable crash quarantine
and immutable state identity. Python tests exercise the launcher's handoff,
byte-preserving arguments, inherited jobserver FDs, refusal and installation;
their native-helper double is not cgroup evidence.

The controlled integration fixture requires a real writable delegation and a
matching built helper:

```sh
RABS_TEST_ROOT_CGROUP=/sys/fs/cgroup/your-delegated-domain \
  cargo test -p rabs-wkr --test cargo_root_linux -- --ignored --test-threads=1
```

It runs real Cargo, checks that a second root waits for the only credit, and
proves cleanup of a `setsid` descendant. A second case kills the owner while
Cargo is live and verifies quarantine before and after explicit test-owned
cgroup cleanup. A filesystem fixture cannot substitute for those kernel tests.
