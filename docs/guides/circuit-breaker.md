# Circuit Breaker Guide

RCH uses a circuit breaker per worker to stop routing builds to a flaky machine
and prevent cascading failures. When a worker repeatedly fails health checks or
remote commands, its circuit opens, and the daemon temporarily skips it.

Think of this like an electrical breaker: it trips to protect the system, then
resets after a cooldown to test whether the worker recovered.

## How It Works in RCH

- **Per worker**: Each worker has its own circuit state.
- **Fail-open philosophy**: If something is wrong, RCH avoids that worker and
  falls back to other workers or local execution.
- **Automatic recovery**: After a cooldown, RCH probes the worker before using
  it normally again.

## Circuit States

**Closed**
- Normal operation.
- Worker accepts jobs.

**Open**
- Worker is excluded after repeated failures.
- Cooldown timer runs before probing.

**Half-open**
- Limited probe requests test recovery.
- Success closes the circuit; any failure reopens it.

## State Transitions (Defaults)

```
CLOSED --(3 failures OR >=50% error rate in 60s)--> OPEN
OPEN   --(cooldown 30s elapsed)------------------> HALF-OPEN
HALF   --(2 consecutive successes)--------------> CLOSED
HALF   --(any failure)--------------------------> OPEN
```

## Configuration

Circuit breaker settings live in your config:

- User-level: `~/.config/rch/config.toml`
- Project-level: `.rch/config.toml`

```toml
[circuit]
failure_threshold = 3        # consecutive failures to open
success_threshold = 2        # consecutive successes to close
error_rate_threshold = 0.5   # error rate to open within window
window_secs = 60             # rolling window size
open_cooldown_secs = 30      # cooldown before half-open
half_open_max_probes = 1     # concurrent probes allowed
command_failure_threshold = 2 # command failures are tracked separately
open_cooldown_max_secs = 480   # cap for repeated circuit reopens
recovery_probe_interval_secs = 300 # offline-worker SSH probe cadence
```

Notes:
- If you lower thresholds too far, brief network blips can open circuits.
- If you raise thresholds too high, failing workers will be retried too often.
- `down_after_failures` is an alias for `failure_threshold`; use one spelling
  in a TOML file.
- All circuit settings are supported by `rch config set/get/reset`. For example,
  `rch config set circuit.open_cooldown_secs 900` makes offline probes wait at
  least 15 minutes. Restart the daemon after changing these settings.

## Offline workers and administrative disablement

Connection failure and operator disablement have separate lifecycles. After
`failure_threshold` consecutive connection failures, a worker is temporarily
offline and cannot receive builds. The health monitor owns recovery. After each
failed recovery probe it waits at least `max(recovery_probe_interval_secs,
open_cooldown_secs)` seconds before starting another bounded health probe.
Telemetry and maintenance do not independently
reconnect while the worker is offline. Concurrent health requests share the same
per-worker probe admission. A failed VPN or powered-off host therefore remains
quiet between probes, even when the daemon has no queued builds.
Build admission and other background traffic already pause after the first
connection failure; the consecutive-failure threshold controls when health
checks switch to the slower recovery cadence.

The first successful recovery probe clears the transport outage immediately;
normal telemetry and build eligibility checks can then run again. Recovery does
not bypass incompatible toolchains, storage problems, or independent quarantine
requirements. A worker that comes back between probes is normally detected
within one configured interval plus the time needed for that probe. An ongoing
failed attempt or a large fleet outage can add a wait for a recovery probe slot;
healthy workers have separate
probe capacity. Lower the interval when faster detection matters more than idle
connection traffic.

`rch workers disable <id>` stops daemon background connections and cancels
queued or in-flight probes, in addition to rejecting new compilation jobs. The
existing administrative state store preserves that choice across daemon restarts
and worker configuration reloads. Only `rch workers enable <id>` clears this
administrative disablement; a successful health result cannot re-enable it.
An unreadable or invalid administrative state file prevents daemon startup
instead of being treated as an empty list. Failed persistence is returned as an
error: a failed disable still stops live traffic, and a failed enable leaves the
worker disabled.

## Verifying offline handling

The Linux process regression uses actual daemon processes, Unix sockets, and an
instrumented SSH executable. It checks sustained outages, blackholed connections,
concurrent admissions and capability refreshes, healthy-peer progress, recovery,
warm-session cancellation, disabled restarts, and pooling disabled:

```bash
cargo test -p rchd --test daemon_lifecycle offline_worker_process_recovery -- --nocapture
```

For real OpenSSH handshakes and a before/after measurement, build both revisions
with the same compiler/profile and preserve each daemon binary, then run:

```bash
python3 scripts/test_offline_worker_recovery.py \
  --binary /path/to/updated/rchd \
  --before /path/to/baseline/rchd \
  --openssh --measure-seconds 65 \
  --output /tmp/rch-offline-comparison
```

This mode requires local `ssh`, `ssh-keygen`, and `sshd`; root-run OpenSSH also
requires its normal `/run/sshd` directory. The fixture isolates its keys, state,
and sockets and records connection counts, spacing, process concurrency, daemon
CPU/RSS, log volume, recovery latency, and selection latency. The remote command
protocol is deterministic: this is an SSH/daemon integration test, not a remote
compilation or a measurement of a real VPN's routing traffic. Resource accounting
requires `/proc` to describe the same PID namespace as the test processes.

The complementary `cargo test -p rchd --bin rchd offline_worker` suite exercises
an entire day of recovery scheduling with Tokio's virtual clock, a 900-second
cooldown, extreme interval values, concurrent probe exclusion, and durable-state
failure cases.

## What To Do When a Circuit Opens

1. **Wait for auto-recovery**
   - The circuit's default cooldown is 30 seconds; a worker with repeated
     connection failures receives one recovery attempt every 5 minutes by default.

2. **Check the reason**

```bash
rch status --circuits
rch daemon logs | grep -i circuit
rch workers history my-worker
```

3. **Fix the underlying issue**
   - SSH connectivity: `ssh -v -i ~/.ssh/key user@host "echo OK"`
   - Worker load: check CPU/memory/disk
   - Disk space: `df -h` on the worker

4. **Manually reset after a fix**

```bash
rch workers reset my-worker
rch workers probe my-worker
```

## Related Docs

- Troubleshooting: `docs/TROUBLESHOOTING.md` (Circuit Breaker Open)
- Worker recovery runbook: `docs/runbooks/worker-recovery.md`
- Monitoring guide: `docs/guides/monitoring.md`
