# Runbook: Daemon Restart

## When to Restart

Restart the daemon when:

- Configuration changes require reload
- Daemon is unresponsive
- Memory usage is unexpectedly high
- After RCH upgrade
- Clearing stale state

## Quick Restart

```bash
# Graceful restart (closes admission and waits for active work)
rch daemon restart --drain

# Non-interactive graceful restart (up to 300 seconds)
rch daemon restart --drain --drain-timeout 300 -y

# Check status
rch daemon status
```

Restart requires a responsive daemon so the CLI can verify its process identity,
acquire a maintenance fence, and confirm shutdown. An unreachable or refused
socket is not proof that its original daemon exited. For that condition, use
the [supervisor recovery procedure](#recover-through-the-matching-supervisor).

## Step-by-Step Procedures

### Graceful Restart

Use this for configuration changes or routine maintenance.

```bash
# 1. Check current status
rch daemon status

# 2. See active builds
rch status --jobs

# 3. Graceful restart (waits up to 300s for builds)
rch daemon restart --drain --drain-timeout 300

# 4. Verify restart
rch daemon status
rch status --workers
```

### Restart After Cancelling Stuck Work

Cancel the specific stuck builds through the tracked cancellation path, verify
their cleanup, then request a graceful drain. This keeps build identity and
cleanup evidence available when deciding whether the daemon can restart.

```bash
# 1. Inspect admission and identify the stuck builds
rch daemon admission status
rch status --jobs

# 2. Cancel the intended build and verify that its cleanup settles
rch cancel <build-id>
rch queue

# 3. Drain remaining work before restarting
rch daemon restart --drain --drain-timeout 300 -y

# 4. Confirm the new incarnation and open admission
rch daemon status
rch daemon admission status --json
```

`-y` only skips an interactive prompt; it does not authorize interrupting builds.
The maintenance `--force` flag explicitly authorizes interruption, but still
requires verified daemon identity, maintenance ownership, and an acknowledged
shutdown. It cannot bypass another owner or a durable ownership fault. A failed
or unconfirmed shutdown returns a nonzero status and does not proceed to a
replacement daemon blindly.
For a daemon that cannot complete the protocol, follow the supervisor recovery
procedure below. Removing its socket or signaling processes by name cannot
establish that the original daemon stopped safely.

### Debug Mode Restart

For troubleshooting issues:

```bash
# 1. Stop daemon
rch daemon stop

# 2. Start in foreground with debug logging
RCH_LOG_LEVEL=debug rchd

# 3. In another terminal, test operations
rch status
cargo build  # In a project

# 4. Review logs in the foreground terminal
# Ctrl+C to stop when done

# 5. Restart in background
rch daemon start
```

## Restart Scenarios

### After Configuration Change

```bash
# Edit configuration
vim ~/.config/rch/config.toml

# Validate before applying
rch config validate

# Apply without a full restart (preferred for config-only changes)
rch daemon reload

# Verify new config is loaded
rch config show --sources
```

### After Adding/Removing Workers

Editing `workers.toml` is correct for a **genuine, lasting** fleet change (adding
a real new host, decommissioning a dead one). It is **not** the way to handle a
worker that is transiently slow/unreachable — that self-heals via temporary
bypass + canary auto-rejoin, and editing it out blocks the rejoin. See the
[worker-recovery runbook](worker-recovery.md).

```bash
# Edit workers file for a real add/remove
vim ~/.config/rch/workers.toml

# Apply (reload picks up worker changes without a restart)
rch daemon reload

# Verify workers
rch workers list
rch workers probe --all
```

### After RCH Upgrade

```bash
# Update RCH
rch update

# Restart daemon with new binary
rch daemon restart

# Verify version
rch --version
rch daemon status
```

### Memory Issues

```bash
# Check daemon memory usage
ps aux | grep rchd

# If memory is high, restart
rch daemon restart

# Consider adjusting config to limit history
vim ~/.config/rch/config.toml
# [history]
# max_entries = 1000
```

### Stuck Builds

```bash
# Check for stuck builds
rch status --jobs
rch queue

# Cancel the stuck build(s) with tracked cleanup before touching the daemon
rch cancel <build-id>            # graceful (SIGTERM)
rch cancel <build-id> --force    # SIGKILL if it ignores TERM
rch cancel --all -y              # last resort

# Restart after cancellation has settled and the daemon is responding
rch daemon restart --drain -y

# Verify clean state
rch status --jobs
```

## Troubleshooting Restart Failures

### Build Admission Remains Closed

Inspect the daemon's actual state before retrying maintenance:

```bash
rch daemon admission status
rch daemon admission status --json
rch status --json
rch doctor --json
```

`rch daemon admission status --json` returns the complete snapshot in `data`.
The top-level `success` means the inspection completed; `data.admission_closed`
is the field that says whether new builds can start. `rch status --json` includes
the admission ownership state in `data.daemon.admission` and reports posture
`admission_closed` when the barrier is closed, even if every worker is healthy.
Doctor includes an `admission` object and a `daemon_admission` check; reliability
doctor reports `RCH-R015` for a closed barrier.

The admission snapshot nested in `/status`, also used by reliability doctor,
reports ownership without scanning durable client leases. Its empty
`client_lease_ids` array does not establish that no leases block restart, and
`restart_permitted` remains false in that snapshot. Use
`rch daemon admission status --json` for the full bounded lease inspection.

The status and doctor payloads now advertise `data.schema_version: "1.1.0"`.
This minor schema change adds the admission object and the `admission_closed`
status posture. Consumers that enumerate posture values must handle that value
and inspect the admission object before declaring remote builds available.
An absent admission object in an older saved response means unknown admission
state. The common `ApiResponse` envelope remains at `api_version: "1.0"`;
the new `daemon admission` commands use that envelope and return the complete
fenced snapshot in `data`.

Important fields:

| Field | Meaning |
| --- | --- |
| `daemon_incarnation` | Unique identity of this daemon lifetime; old credentials cannot control a replacement. |
| `maintenance_closed` | A maintenance operation currently owns the barrier. |
| `maintenance_owner` | Owner PID, kernel process birth identity, purpose, token, and generation. |
| `maintenance_owner.owner_presence` | `live`, `absent`, or `unknown`, using birth identity rather than PID existence. |
| `maintenance_owner.remaining_ms` | Remaining renewable maintenance lease; enforced by the daemon's monotonic clock until shutdown is committed. |
| `maintenance_owner.deadline_unix_ms` | Informational wall-clock deadline; committed shutdown no longer expires. |
| `last_recovery` | Most recent recovered owner, reason, and time. |
| `ownership_failed` / `ownership_error` | A durable ownership storage failure, such as ENOSPC; independent of maintenance. |
| `shutdown_committed` | Shutdown has passed its fencing check and is in progress. |
| `client_lease_ids` / `client_lease_scan_error` | Durable build owners still blocking restart, or a failure to inspect them. |

An active maintenance operation renews a bounded lease. The daemon recovers it
when the original process is proven absent or the lease expires, including when
process inspection remains uncertain. Status requests and build admission apply
the same recovery rule. Cancellation and drain errors attempt an owner-validated
release and verify the resulting state. If the client or daemon crashes, a
replacement daemon uses a fresh incarnation; old release requests cannot reopen
a new owner's barrier.

To request safe recovery and verify that builds can be admitted again:

```bash
rch daemon admission recover
rch daemon admission recover --json
```

Recovery targets the exact observed incarnation and owner token. The daemon
refuses to steal a live, unexpired maintenance lease, and the CLI checks a fresh
snapshot before reporting admission open. A new concurrent maintenance owner,
an unreadable response, a durable ownership failure, or committed shutdown makes
recovery return an error instead of claiming success. There is no unfenced
administrative release or `--force` recovery option.

If `ownership_failed` is true, inspect `ownership_error` and the daemon logs,
then repair the reported storage problem. The fault is latched for that daemon's
entire lifetime: repair alone, maintenance recovery, and the maintenance
interruption flag cannot clear it. The daemon requests shutdown after
two consecutive fault checks, which run every 30 seconds. Once shutdown begins,
the process watchdog enforces a further 30-second exit deadline. Whether a
replacement starts automatically depends on the supervisor's restart policy.
Follow the supervisor recovery procedure if it does not return with open
admission. For `shutdown_committed`, wait for exit/restart and verify the new
daemon incarnation's admission state.

Durable **job** leases have a separate conservative rule: a stale lease stops
blocking restart only when its original owner is proven absent, including a
recycled PID or old boot identity. A live wrapper still blocks restart despite
an old heartbeat; uncertain identity remains blocking. A refused or timed-out
maintenance operation releases its own admission barrier so this uncertainty
does not indefinitely prevent unrelated builds. Pre-admission wrappers waiting
for maintenance do not count as work to drain unless they retain remote or
source ownership. No lease file is deleted merely to make a restart pass.

New builds wait up to `RCH_RESTART_ADMISSION_WAIT_SECS` (default 600 seconds) for
admission after the initial status probe. Once a closed barrier is observed,
subsequent probes share the remaining wait budget, including when a daemon
stops replying. A zero value refuses after the first closed observation. A proven
no-start refusal retires the wrapper's lease without inventing a remote exit code.

### Recover Through the Matching Supervisor

Use this after repairing a durable ownership storage fault, or when the daemon
cannot answer enough of the maintenance protocol to confirm a CLI restart.
An enabled `rchd.service` may serve a different socket. Match the service to the
affected daemon before changing it, and retain any available original PID,
start time, socket path, and incarnation for the recovery check.

```bash
# Inspect the configured endpoint and capture its current identity, if reachable
rch daemon status --json
rch status --json | jq '.data.daemon | {daemon, admission}'

# Inspect each possible systemd scope without changing it
systemctl --user show rchd.service -p MainPID -p ActiveState -p SubState -p Restart -p ExecStart
systemctl show rchd.service -p MainPID -p ActiveState -p SubState -p Restart -p ExecStart
```

For a reachable endpoint, the owning service's current `MainPID` must match
`data.daemon.daemon.pid` from `rch status --json`; also check its `ExecStart` and
configured socket. If the endpoint is already unreachable, use previously
recorded identity and the supervisor's process and journal evidence. A matching
service name alone does not establish ownership.

After storage repair, allow the faulted daemon's automatic shutdown to finish.
Inspect the matched unit again. If it already has a replacement PID and the
endpoint reports a new incarnation with `admission_closed: false`, recovery is
complete; preserve that replacement because it may have admitted new work.
If the matched unit has exited (`MainPID=0`, with an inactive or failed state),
start that unit and verify the endpoint:

```bash
# User-scope example; use the verified scope and service name
systemctl --user start rchd.service
rch daemon status --json
rch daemon admission status --json
```

If the original daemon remains unresponsive and you explicitly choose to
interrupt its remaining work, first recheck that the unit still owns that
original process, then stop only that matched unit with
`systemctl --user stop rchd.service`. Verify `MainPID=0` and an inactive or failed
state before the start step. For a system-scope unit, use the corresponding
system-scope commands with the required administrative permissions. A stop of
a live supervised daemon can interrupt builds; it is not a verified drain.
If a different process appeared during inspection, diagnose its admission state
before deciding whether any stop is still needed.

For launchd or another supervisor, perform the same identity and service-state
checks using that supervisor. For a manually launched daemon, observe its
original process exit through its owning terminal or launcher, then run
`rch daemon start` and verify admission. Preserve the durable job journals and
socket ownership evidence throughout recovery; do not bypass an unconfirmed
shutdown by deleting leases or unlinking the endpoint.

### Socket File Already Exists

```
Error: Address already in use
```

Inspect the configured endpoint and its service owner:

```bash
rch daemon status --json
rch daemon admission status --json
```

An unreachable socket can still belong to a live daemon. `rch daemon restart`
refuses when it cannot verify that daemon; it does not reclaim the socket.
After the matching supervisor or original launcher confirms process exit,
`rch daemon start` delegates any stale endpoint cleanup to the daemon's startup
checks. Verify open admission afterward. If startup still refuses the endpoint,
inspect its ownership and configuration using the supervisor procedure above.

### Permission Denied

```
Error: Permission denied: <socket path>
```

Inspect the resolved socket and the account that owns the corresponding service:

```bash
rch daemon status --json
rch config show --sources
rch doctor --json
```

Correct the configured endpoint, service account, or runtime-directory
permissions after identifying the actual owner. A permission error does not
prove a socket is stale. Restart does not remove foreign-owned endpoints or
take over a different user's daemon. Follow the matching supervisor procedure
if the intended service needs to stop before permissions are repaired.

### Config Parse Error

```
Error: Failed to parse config
```

**Solution:**
```bash
# Validate config
rch config validate

# Fix any errors shown
vim ~/.config/rch/config.toml

# Then restart
rch daemon start
```

### Workers Config Not Found

```
Warning: No workers configured
```

**Solution:**
```bash
# Create workers config
rch workers discover --add

# Or manually create
vim ~/.config/rch/workers.toml
```

## Health Checks After Restart

```bash
# 1. Verify daemon is running and admission is open
rch daemon status
rch daemon admission status --json

# 2. Check worker connectivity
rch workers probe --all

# 3. Verify the daemon API is responding (resolves the socket path for you)
rch --json daemon status | jq

# 4. Test a build end-to-end
rch self-test --all
```

## Automated Restart (systemd)

For production setups, use systemd to manage the daemon:

```bash
# Create service file
cat > ~/.config/systemd/user/rchd.service << 'EOF'
[Unit]
Description=RCH Daemon
After=network.target

[Service]
Type=simple
ExecStart=%h/.local/bin/rchd
Restart=on-failure
RestartSec=5

[Install]
WantedBy=default.target
EOF

# Enable and start
systemctl --user daemon-reload
systemctl --user enable rchd
systemctl --user start rchd

# Routine restart uses the maintenance fence and drains active work
rch daemon restart --drain

# View logs
journalctl --user -u rchd -f
```

## State Preservation

On restart:

- The daemon gets a new incarnation; credentials from earlier maintenance cannot control it.
- Worker health states reset to "unknown" (re-probed on first use)
- Circuit breakers reset to "closed"
- Build history is preserved (if persisted)
- Graceful maintenance waits for active work to finish; `--force` explicitly allows interruption.
- Durable ownership and client job leases remain evidence for outstanding work and recovery. Inspect `rch jobs` after an interrupted operation; do not delete that evidence to make a restart pass.
