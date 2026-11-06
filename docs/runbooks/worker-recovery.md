# Runbook: Worker Recovery

## First principle: most worker illness self-heals

A worker that fails health/probe is moved by the daemon to a **temporary bypass**
(quarantine) with **probe backoff**. When probes recover, it enters
**recovered-pending-canary**, runs the configured **canary** command, and on success is
**auto-rejoined** to the healthy pool. Circuit breakers follow the same arc
(open → half-open → closed) automatically.

The default canary is `rustc --version`. Rejoining proves that recovery checks
and that command passed; validate the project's native build and tests separately.

So the default action for a transiently-sick worker is **nothing** — watch it
rejoin. Reserve operator action for *genuine, lasting* problems, and always
prefer reversible, audited primitives.

> **Never** edit `workers.toml` or `rch workers disable` a worker for transient
> illness (slow, briefly unreachable, failing a few probes). That converts a
> self-healing, temporary condition into permanent capacity loss and blocks
> auto-rejoin. `disable` is for genuine decommission/maintenance only.

## Symptoms

- Worker shows as "unreachable" / "bypassed" in status
- Circuit breaker is "open" for a worker
- Builds not being routed to a specific worker
- SSH connection failures in logs

## Quick Diagnosis

```bash
rch status --fleet                     # desired vs live; absent/disabled/unreachable + absence alerts
rch status --remediation               # operator bands incl. circuit/telemetry/pressure
rch workers probe <worker-id> -v       # probe one worker, verbose
rch workers list --verbose             # per-worker circuit + health state
ssh -i ~/.ssh/rch_key user@worker-host "echo OK"
```

Circuit-breaker state is shown by `rch workers list --verbose`, `rch queue`, and
the `rch status --remediation` view — there is no separate `--circuits` flag and
no manual circuit reset; the breaker heals itself once probes succeed.

## Step-by-Step Recovery

### 1. Identify the problem

```bash
rch workers probe <worker-id> --verbose
```

Possible issues: SSH refused (service down), SSH timeout (network/firewall), SSH
auth failed (key), `rch-wkr` not responding, disk full, out of memory.

### 2. SSH connection issues

**Connection refused:**
```bash
ssh user@worker "systemctl status sshd" 2>/dev/null || echo "Cannot connect - SSH may be down"
# With console access, restart SSH on the worker:
sudo systemctl restart sshd
```

**Connection timeout:**
```bash
ping worker-host
nc -zv worker-host 22
ssh user@worker "sudo ufw status"          # firewall (on worker)
```

**Authentication failed:**
```bash
ssh -vvv -i ~/.ssh/rch_key user@worker-host "echo OK"
ls -la ~/.ssh/rch_key                      # want -rw------- (600); `rch doctor --fix` corrects loose perms
ssh user@worker "cat ~/.ssh/authorized_keys"
```

### 3. Worker agent (`rch-wkr`) issues

**Check the agent:**
```bash
ssh worker "~/.rch/bin/rch-wkr health"     # expect: OK
ssh worker "~/.rch/bin/rch-wkr --version"
```

**If `rch-wkr` is missing or wrong version → redeploy (atomic, rollback-safe):**
```bash
rch fleet deploy --worker <worker-id> --force --verify
```

The deploy installs to a staging path and atomically switches the symlink, so a
failed deploy rolls back rather than leaving a half-installed agent. Do **not**
hand-remove the install for a version/health problem — let the atomic deploy
replace it.

**If `rch-wkr` is stuck/zombie:** drain the worker first so no new builds route
to it, then let the daemon's bounded process triage (TERM → KILL with audit)
clean it up, or run the operator-confirmed triage fix:
```bash
rch workers drain <worker-id> -y                                   # reversible; stops new routing
rch fleet doctor --reliability --scope triage --workers <worker-id>            # diagnose stuck/zombie procs
rch fleet doctor --reliability --scope triage --fix --fleet-confirm --workers <worker-id>  # bounded TERM->KILL, audited
rch workers enable <worker-id>                                     # bring it back when healthy
```
Manual `ssh worker "pkill -9 rch-wkr"` is a last resort: drain first, get
operator confirmation, and prefer the audited triage path above — a blind
`pkill -9` can kill an in-flight build with no record.

### 4. Resource issues

**Disk full** — reclaim safely; never blanket-`rm -rf` a worker's RCH tree (you
can delete an in-flight build):
```bash
ssh worker "df -h / /tmp"
rch cache clean --older 1h                 # DRY-RUN: shows reclaimable local staging trees
rch cache clean --older 1h --execute       # actually reclaim (idle trees only)
rch doctor --reliability --scope pressure  # disk-pressure diagnosis for the fleet
```
Remote worker target dirs are reaped automatically by the daemon's
**stale-target reaper**, which only removes dirs idle past the threshold
(active builds touch their dir continuously and are always kept). If you must
clean a worker dir by hand, verify it is inactive first and only then remove it:
```bash
ssh worker "sudo lsof +D /tmp/rch_target_<name>"   # empty output ⇒ inactive
# only if empty, and with operator intent:
ssh worker "rm -rf /tmp/rch_target_<name>"
```

**Memory exhausted / runaway builds** — cancel through RCH so cleanup is tracked,
rather than `pkill`:
```bash
ssh worker "free -m"
rch queue                                  # find the runaway build id(s)
rch cancel <build-id>                      # graceful (SIGTERM)
rch cancel <build-id> --force              # SIGKILL if it ignores TERM
rch cancel --all -y                        # last resort: cancel everything
```
For stuck OS processes that are not tracked builds, use the audited triage fix in
§3 rather than `pkill -9 cargo`.

**Jobs still waiting for a worker:** inspect `rch queue` or `rch jobs`, then cancel
the queued ID or its durable wrapper identity:

```bash
rch cancel <queue-id>
rch jobs cancel <wrapper-id>
```

The daemon records cancellation before acknowledging it and prevents that wrapper
from later receiving a worker reservation. The waiting wrapper exits with code
130 and does not fall back to a local build. If admission has already won, the
same request follows the existing cancellation path for the exact active build.
If the job has already left the queue for timeout or local fallback, cancellation
reports that it is no longer queued instead of claiming it prevented a start.

If the connection fails after a queue-enabled selection request may have reached
the daemon, the wrapper retains its lease as `selection_unconfirmed` and stops.
It does not retry selection or run locally while the original waiter or an
accepted cancellation remains unresolved. Inspect the original job identity with
`rch jobs`; use that same identity for targeted cancellation when the daemon is
available. Failures before a connection is established retain ordinary daemon
recovery behavior.

Queue IDs have a separate, durably allocated namespace and are not reused after
a daemon restart. Repeating cancellation by wrapper identity is supported after
restart. Legacy queued requests without a durable wrapper identity refuse this
operation. Cancellation intents are bounded at 100,000 identities; exhaustion or
a persistence failure refuses acknowledgment instead of forgetting a cancelled
job and allowing it to run later.

**Active jobs recovered after a daemon restart:** inspect `rch queue`, then use
`rch cancel <build-id>` for the specific job you want to stop. Cancellation can
now finish when the original local wrapper has exited, including when its PID
belongs to a different process. The daemon preserves the originally observed
wrapper identity; delayed heartbeats cannot adopt that replacement process.
Local signals use Linux pidfds after verifying the recorded boot and process
start identity.

For tracked Linux and macOS worker jobs launched by this version, the remote record binds
the build ID, worker boot UUID, process-group leader and its start time. The
daemon checks this identity before each remote signal and verifies that the
group has no executing members. It then persists the terminal cancellation and
releases the job's reservation once. Repeated or concurrent cancellation does
not release extra slots. Recovery does not rerun the command or infer that its
artifacts were successfully produced.

If SSH is unavailable, identity cannot be verified, or a live group survives
after its recorded leader exits, the job and reservation remain active for
retry. `--force` does not bypass these checks. Older numeric-only PGID records
can confirm an already empty group, but cannot authorize killing a live group.
Linux requires procfs mounted in the active PID namespace and retains its
complete thread census. macOS uses the updated `rch-wkr process-identity <pid>`
helper on the remote PATH, kernel boot-session UUIDs, and libproc start times
at microsecond precision. Update `rch-wkr` on macOS workers together with the
dispatcher. A missing or older helper refuses setup before starting work.
Bounded control observations use GNU timeout when available, or Python 3
otherwise. The existing `setsid` launch capability is still required. Missing
both bounded helpers fails closed. BSD stat and the native process census are
used on macOS; no Linux procfs is required.
Windows jobs and unsupported worker launch capabilities do not gain that
guarantee. Do not remove the retained ownership record to make capacity appear
free while execution remains uncertain.

### Busy Linux worker: process observation unavailable (issue #129)

`RCH_SCOPED_COMPLETION_UNCONFIRMED` / SSH exit 255 means the dispatcher cannot
prove that the owned remote execution stopped. This can happen **before the
payload starts**, during scope admission, as well as during final cleanup.
Payload output, an SSH heartbeat, free slots, or a successful compiler exit do
not replace the completion proof. The job retains its source ownership and
reservation; automatic local execution or another remote attempt remains unsafe.

Linux census cost now scales with process leaders and the threads of the target
group. It reads one validated leader snapshot and skips the second `ps` call
when every target process has one thread. Multithreaded targets, including a
zombie leader with live sibling threads, still require a targeted LWP snapshot.
It never enumerates unrelated threads. Invalid output, an inaccessible PID
namespace, incomplete terminal thread counts, or a live-to-terminal race between
snapshots remains unknown. Positive liveness does not require a stable thread
count. Census output is bounded at 1 MiB, with byte validation before parsing.

The observer uses the task count and one-minute load from `/proc/loadavg` as
cheap scheduling hints. Its budget is
`min(8, 3 + floor(tasks / 2048) + floor(load / 16))` seconds, or five seconds
when those hints are unavailable or malformed. These hints affect waiting time
only; they never establish process presence, absence, identity, or health.
For the reported approximately 4,800 tasks and load 47 this gives seven seconds,
providing headroom above the reported 0.7–1.2-second census and helper startup.
There is no host-wide process enumeration merely to choose a timeout.

The relevant deadline hierarchy is:

| Operation | Budget and retry rule |
| --- | --- |
| Linux process identity before admission | Targeted `/proc/<pid>/stat` reads with namespace, boot and start-time fencing; no full census |
| Census and scope manager snapshots | 3–8 seconds on Linux; five-second fallback; clipped to the enclosing monotonic deadline |
| Priority enforcement before admission | Five seconds for `renice`, adaptive observation budget for priority verification; both consume the setup deadline |
| Policy slice checks and scope creation | Five seconds per control exchange; scope creation is not automatically replayed |
| Scope binding before receipt publication | At most three unavailable observations within 30 seconds and the overall setup deadline |
| Supervisor admission | At most three unavailable scope observations within the same 60-second setup deadline; gate stays closed and child/receipt identity is rechecked |
| Cancellation and completion verification | One 30-second monotonic observer budget shared by census, witnesses, scope operations and retries; stop after three consecutive unknown post-kill observations |
| Fresh SSH cleanup | 45 seconds including connection and response draining |
| Daemon cancellation | 60 seconds for all termination stages; default remote command allowance is 45 seconds |
| Cancellation CLI response | 75 seconds; large bulk cancellations may continue in their daemon-owned task after client timeout |
| Process-observation recovery | Dedicated supervised no-op: 60-second setup, five-second payload, shared cleanup budget, 120-second total SSH allowance |
| Recovery capability inventory | At least 25 seconds each for connection and inventory when process-observation recovery is required; the enclosing recovery deadline includes both plus the 120-second lifecycle allowance |
| Final recovery canary | At least 25 seconds each for connection and command, within a separate 50-second default allowance; telemetry freshness is checked after the lifecycle probe |
| Diagnostic/deadline marker delivery | One second, best effort; delivery never grants completion authority |

These are bounded control and transport budgets, not a promise that an
unresponsive kernel schedules a shell at an exact instant. Expiry retains
unknown state. Retrying an observation does not restart its enclosing deadline,
relaunch the payload, or reissue a side-effecting scope-creation request.

An unconfirmed Linux/macOS execution now reports a separate, owner-bound
`process_observation` failure to the daemon. The daemon immediately excludes
that endpoint from scheduling and persists temporary bypass, without changing
administrator intent, marking the build complete, or releasing its slots.
Reports for the same incident are deduplicated; new failures retain recovery
backoff. A late report for a replaced worker endpoint is rejected.

A verified refusal before payload admission also reports process-observation
failure before releasing its proven unstarted job. That safe release does not
clear the worker bypass. Failed standalone cancellation reports the same health
condition when remote termination is unconfirmed; a local wrapper-cleanup error
after authenticated remote termination does not misclassify the worker.

Ordinary heartbeat, storage and telemetry success cannot clear this bypass.
Recovery must run a real supervised no-op using the current receiver policy,
pass admission and the full census/cleanup proof, and then satisfy the existing
recovery/canary policy. The process-observation requirement survives daemon
restart and later SSH or disk-failure classifications. Recovery of worker
eligibility does **not** settle previously retained jobs: inspect and recover
each original job identity separately. Failed recovery probes retain their
private `rch-process-health.*` receipt directories for diagnosis.

Regression commands (Linux, with procfs mounted in the active PID namespace):

```bash
python3 rch-common/tests/remote_scoped_launch.py -v
python3 rch-common/tests/remote_process_platform.py -v
python3 rch-common/tests/control_deadlines.py -v
cargo test -p rch-common --test remote_process_threads --test remote_process_escalation
cargo test -p rchd process_observation
cargo test -p rchd census_quarantine
```

The platform suite includes deterministic large-census fixtures and injected
timeout failures. Its opt-in native stress fixture creates 2,350 sleeping
processes with approximately 4,800 threads; run it only where that process and
memory headroom is available:

```bash
RCH_TEST_PROCESS_STRESS=1 RCH_TEST_STRESS_PROCESSES=2350 \
  python3 rch-common/tests/remote_process_platform.py NativeProcessStress -v
```

**CPU overloaded:** drain the worker so it stops taking new work; it rejoins on
`enable`. Do not kill processes blindly.
```bash
ssh worker "uptime"
rch workers drain <worker-id> -y
rch workers enable <worker-id>             # when load subsides
```

### 5. Circuit breaker / bypass recovery (it heals itself)

Once the underlying issue is fixed, the breaker reopens to half-open on the next
scheduled probe and closes after a successful canary — no manual reset exists or
is needed. To observe and nudge:

```bash
rch workers list --verbose                 # current circuit/bypass state
rch workers probe <worker-id> -v           # run a probe now
rch status --fleet                         # confirm it returned to the live pool
```

**Filesystems without a fixed inode pool:** btrfs allocates inodes on demand,
so `df -i` reports 0 total and 0 free inodes; Git Bash on NTFS reports `-`.
Recovery checks only free disk bytes on such roots, and on every Windows
worker. Roots with a fixed inode pool (ext4 and similar) must clear both the
byte floor and the inode floor (`min_disk_inodes`). An older daemon refuses
`disk` recovery on btrfs or Windows despite plenty of free bytes; the fix for
that is a daemon upgrade, not disk cleanup.

The recovery inventory also queries every installed Rust toolchain. A manual
worker probe can succeed while the daemon's shorter recovery probe times out.
If logs show that timeout, measure the complete inventory and give it enough
time to finish in the local daemon's configuration, for example:

```toml
[remediation.auto_rejoin]
probe_timeout_secs = 60
```

This changes the recovery probe budget; build/test deadlines and worker health
checks have separate budgets. Apply it with `rch daemon restart --yes --drain`,
then verify daemon status and the worker's actual recovery state. A successful
manual probe alone does not clear a persisted bypass or prove auto-rejoin.

### 6. Verify recovery

```bash
rch self-test --worker <worker-id>         # full end-to-end build on that worker
rch fleet verify --worker <worker-id>      # post-deploy/health verification
```

### Native Windows build failures after recovery

Git Bash can put its Unix `link.exe` ahead of Microsoft's linker. If an MSVC
build invokes the wrong executable, select the installed Microsoft linker in
the worker's Cargo configuration. `C:/rch/.cargo/config.toml` applies to RCH
projects beneath `C:/rch`; preserve any existing configuration before editing.
For example, this toolset was verified on `wsurf` on September 9, 2026:

```toml
[target.x86_64-pc-windows-msvc]
linker = 'C:/BuildTools/VC/Tools/MSVC/14.44.35207/bin/HostX64/x64/link.exe'
```

Verify the installed path on the worker instead of assuming that version exists.
Then retry the same project command and confirm that its tests actually execute.

An SSH command timeout currently does **not** terminate a Windows build's
process tree: the transfer code records no Windows process-group identifier and
reports `remote cleanup not attempted`. Inspect native `cargo`, `rustc`, `cl`,
and `link` processes, including their parents and creation times, before retrying.
Wait for an active owned build to finish or use a targeted, reviewed cancellation;
do not kill unrelated compiler processes. Retain the failed log and target cache.
A retry can reuse completed dependencies, but the timed-out attempt is not a test
pass and its absence from the dispatcher queue does not prove remote termination.

### Inspecting Windows build and Cargo caches

For a worker declared as Windows, both commands inspect the tar transport's
`C:/rch` build base and the worker's resolved temporary/cache base:

```bash
rch cache status --workers wsurf
rch gc --dry-run --workers wsurf --json
```

Additional Windows roots can be configured through `gc_extra_roots` or passed
to GC with, for example, `--root 'D:/build cache'`. The report lists rejected
roots and missing build roots; a missing `C:/rch` does not hide Cargo caches
in the worker's temporary directory. Directory sizes use apparent bytes,
rounded up to KiB. An incomplete directory or metadata scan fails the worker
report instead of reporting a complete inventory with missing entries.

Windows inventory is read-only: native process/handle ownership cannot yet be
established by the Git POSIX shell. Every directory class is kept, including
old per-job trees, and neither age nor a byte cap authorizes deletion.
`rch gc --apply` reports that Windows collection is unavailable and retains
the inventory; it does not invoke POSIX claim cleanup or retained-source scans.
A Windows-only `--apply` invocation exits unsuccessfully. Use the inventory
to diagnose space usage, and establish native ownership before any manual
cleanup. Local shell regression tests do not constitute native Windows
qualification.

## Recovery procedures by scenario

### Scenario: worker VM rebooted

```bash
ping worker-host
ssh worker "echo OK"
rch workers probe <worker-id> -v           # daemon auto-clears the breaker after a good probe
rch status --fleet
```

### Scenario: network partition resolved

```bash
nc -zv worker-host 22
rch workers probe --all                    # breakers self-heal; no manual reset
```

### Scenario: worker disk filled up

```bash
rch cache clean --older 1h --execute       # reclaim idle local staging trees
# remote: the stale-target reaper handles idle dirs; for manual cleanup, lsof-guard first (see §4)
ssh worker "df -h / /tmp"
rch fleet verify --worker <worker-id>
```

### Scenario: worker agent corrupted

```bash
rch workers drain <worker-id> -y           # stop routing to it first
rch fleet deploy --worker <worker-id> --force --verify   # atomic, rollback-safe reinstall
rch workers enable <worker-id>
```
Only if a redeploy genuinely cannot repair the install should you remove the
on-worker tree by hand — and then with explicit operator intent, after draining:
`ssh worker "rm -rf ~/.rch"` followed by `rch fleet deploy --worker <id> --force`.

### Scenario: cloud / VMI fleet incident (many workers absent at once)

A provider outage, VMI image roll, or network event can make most of the fleet
disappear together. This is expected and **fail-open** handles it — builds run
locally until workers return.

```bash
rch status --fleet                         # dominant problem class = absent/unreachable across the fleet
rch status --remediation                   # confirms posture and that fallback is intentional
```
Do **not** `rch workers disable` or delete the absent workers from `workers.toml`
to "clean up" — they are part of desired state and will **auto-rejoin** when the
cloud recovers. Editing them out forces a manual re-add and defeats reconciliation.
If a node is genuinely gone for good, decommission it explicitly with
`rch workers disable <id> --reason "decommissioned" --drain -y`.

## Prevention

```bash
# Periodic health check (alert on failure)
*/5 * * * * rch workers probe --all --quiet || notify-admin
```

```toml
# ~/.config/rch/config.toml — alert on degradation
[alerts]
enabled = true
webhook_url = "https://hooks.slack.com/..."
```

```bash
# Weekly local staging cleanup (dry-run first, then --execute)
rch cache clean --older 7d
rch cache clean --older 7d --execute
# Periodic fleet verification
rch fleet verify
```

## Escalation

If a worker cannot be recovered:

1. **Temporary (reversible):** drain so nothing routes to it — it rejoins on
   `enable`:
   ```bash
   rch workers drain <worker-id> -y     # or: rch fleet drain <worker-id>
   ```
2. **Investigate:** access the worker console or contact the infra team.
3. **Decommission (permanent, operator intent):** only for genuinely dead nodes:
   ```bash
   rch workers disable <worker-id> --reason "decommissioned" --drain -y
   ```
4. **Document:** the incident ledger records reason-coded events automatically;
   add operator context to the incident report.
