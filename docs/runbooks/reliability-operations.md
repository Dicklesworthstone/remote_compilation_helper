# Runbook: Reliability Operations

## Architecture Overview

RCH's reliability architecture is built around five pillars:

1. **Repo Convergence** — Ensures remote workers have correct repository state
2. **Storage Pressure** — Detects and responds to disk pressure on workers
3. **Process Triage** — Identifies and manages stuck/zombie build processes
4. **Circuit Breakers** — Isolates failing workers to prevent cascade failures
5. **Fail-Open Semantics** — Falls back to local builds when remote is unavailable

### System Posture

The system reports one of three postures:

| Posture | Meaning |
|---------|---------|
| `remote-ready` | All workers healthy, remote compilation available |
| `degraded` | Some workers unhealthy, partial remote capability |
| `local-only` | No workers available, builds run locally (fail-open) |

Check current posture:
```bash
rch status --json | jq '.posture'
```

## Quick Diagnosis

```bash
# Full status overview with remediation hints
rch status

# JSON output for scripting
rch status --json

# Doctor diagnostics with remediation plan
rch doctor

# System self-test
rch self-test --quick
```

## Error Taxonomy

Error codes follow the pattern `RCH-Exxx`:

| Range | Category | Examples |
|-------|----------|---------|
| `RCH-E0xx` | Configuration | Missing workers.toml, invalid config |
| `RCH-E1xx` | Transfer/sync | File transfer failures, hash mismatches |
| `RCH-E2xx` | Build execution | Compilation failures, timeout |
| `RCH-E3xx` | Convergence | Repo sync failures, drift detected |
| `RCH-E4xx` | Daemon/service | Daemon unreachable, timeout, socket errors |
| `RCH-E5xx` | Storage/disk | Pressure critical, cleanup failed |

## Failure Modes and Remediation

### Worker Unreachable

**Symptoms:** Status shows worker as "unreachable", circuit breaker "open"

**Reason codes:** `circuit_open`, `worker_unreachable`

**Diagnosis:**
```bash
rch status --workers
rch workers probe <worker-id> --verbose
ssh <user>@<host> 'echo ok'
```

**Remediation:**
```bash
# Force-probe to reset circuit breaker
rch workers probe <worker-id> --force

# Verify recovery
rch status --workers
```

**Risk:** Force-probing resets the circuit breaker cooldown timer. If the worker is genuinely down, the circuit will re-open after the next failure.

### Disk Pressure Critical

**Symptoms:** Worker shows pressure state "critical", builds deferred

**Reason code:** `pressure_critical`

**Diagnosis:**
```bash
rch status --json | jq '.daemon.workers[] | select(.pressure_state == "critical")'
ssh <user>@<host> 'df -h /'
```

**Remediation:**
```bash
# Check cache sizes
ssh <user>@<host> 'du -sh /tmp/rch-*'

# Clean build artifacts (destructive)
ssh <user>@<host> 'cargo clean'

# Verify recovery
rch workers probe <worker-id>
```

**Risk:** Disk cleanup removes cached build artifacts. Subsequent builds will be slower until caches are rebuilt.

### Repo Convergence Failed

**Symptoms:** Worker convergence state "failed" or "drifting", missing repos

**Reason codes:** `convergence_failed`, `convergence_drifting`

**Diagnosis:**
```bash
rch status --json | jq '.convergence.workers[] | select(.drift_state != "ready")'
```

**Remediation:**
```bash
# Soft repair (non-destructive)
rch repo-convergence repair --worker <worker-id>

# Force repair (may re-clone repos, destructive)
rch repo-convergence repair --worker <worker-id> --force

# Dry-run check
rch repo-convergence dry-run --worker <worker-id>
```

**Risk:** Force repair may re-clone repositories, discarding any local worker-side changes.

### All Workers Down (Fail-Open)

**Symptoms:** Posture is "local-only", all builds running locally

**Reason:** No healthy workers available

**Diagnosis:**
```bash
rch status
rch doctor
```

**Remediation:**
1. Check network connectivity to all workers
2. Verify worker daemon processes are running
3. Force-probe each worker: `rch workers probe <id> --force`
4. Check for systemic issues (DNS, firewall, SSH keys)

### Schema/Contract Mismatch

**Symptoms:** Adapter version warnings, unexpected response formats

**Reason code:** `schema_mismatch`

**Diagnosis:**
```bash
rch doctor --reliability --check-schemas
```

**Remediation:**
1. Update the affected adapter binary on workers
2. Verify schema version match: `rch status --json | jq '.schema_version'`

**Risk:** Major version mismatches may require migration steps. Check release notes before updating.

## Feature Flags and Rollout

Reliability features use staged rollout:

| State | Meaning |
|-------|---------|
| `disabled` | Feature completely off |
| `dry_run` | Feature runs but takes no action; logs what would happen |
| `canary` | Feature active on subset of workers |
| `enabled` | Feature fully active |

**Check rollout status:**
```bash
rch status --json | jq '.feature_flags'
```

## SLO Guardrails

Key performance budgets:

| Metric | P50 Budget | P99 Budget | Release Blocking |
|--------|-----------|-----------|-----------------|
| Hook decision latency | 1ms | 5ms | Yes |
| Convergence check | 100ms | 500ms | P99 only |
| Triage overhead | 2ms | — | Yes |
| Fallback rate | <10% | — | Yes |
| Cancellation cleanup | — | 10s | Yes |

## Incident Triage Flowchart

1. **Check posture:** `rch status --json | jq '.posture'`
2. **If `local-only`:** Check all workers → network → SSH → daemon
3. **If `degraded`:** Check specific failing workers → `rch doctor`
4. **If `remote-ready` but slow:** Check pressure states → convergence → build stats
5. **Escalation:** If unable to resolve, collect `rch status --json` and `rch doctor` output for incident report

## Dry-Run Operations

All diagnostic commands are safe to run in production:

```bash
rch status          # read-only
rch doctor          # read-only diagnostics
rch self-test       # creates temp files, cleans up
```

Repair commands with `--force` are destructive and should be confirmed:

```bash
rch workers probe <id> --force           # resets circuit breaker
rch repo-convergence repair <id> --force # may re-clone repos
```
