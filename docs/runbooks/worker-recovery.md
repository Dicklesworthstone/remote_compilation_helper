# Runbook: Worker Recovery

## First principle: most worker illness self-heals

A worker that fails health/probe is moved by the daemon to a **temporary bypass**
(quarantine) with **probe backoff**. When probes recover, it enters
**recovered-pending-canary**, gets one **canary** build, and on success is
**auto-rejoined** to the healthy pool. Circuit breakers follow the same arc
(open → half-open → closed) automatically.

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

### 6. Verify recovery

```bash
rch self-test --worker <worker-id>         # full end-to-end build on that worker
rch fleet verify --worker <worker-id>      # post-deploy/health verification
```

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
