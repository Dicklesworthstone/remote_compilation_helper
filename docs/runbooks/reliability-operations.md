# Runbook: Reliability Operations

## Architecture Overview

RCH's reliability architecture is built around five pillars:

1. **Repo Convergence** — Ensures remote workers have correct repository state
2. **Storage Pressure** — Detects and responds to disk pressure on workers
3. **Process Triage** — Identifies and manages stuck/zombie build processes
4. **Circuit Breakers** — Isolates failing workers to prevent cascade failures
5. **Fail-Open Semantics** — Falls back to local builds when remote is unavailable

All five are **self-healing**: workers are temporarily bypassed and auto-rejoined,
breakers open and re-close on their own, stale remote dirs are reaped with
active-build protection, and stuck processes are escalated TERM → KILL with an
audit trail. Operator action is for genuine, lasting problems — and should use
the reversible, audited primitives below, never blind `pkill`/`rm -rf`.

### System Posture

| Posture | Meaning |
|---------|---------|
| `remote-ready` | All workers healthy, remote compilation available |
| `degraded` | Some workers unhealthy, partial remote capability |
| `local-only` | No workers available, builds run locally (fail-open) |

Check current posture:
```bash
rch status --json | jq '.posture'
rch status --remediation            # human bands: fleet, admissibility, proof queue, pressure, telemetry, incidents
```

## Quick Diagnosis

```bash
rch check                           # quick yes/no health (exit 0=ready, 1=degraded, 2=not ready)
rch status --fleet                  # desired vs live, dominant problem class, absence alerts
rch status --json                   # machine-readable for scripting
rch doctor                          # diagnostics + remediation plan (read-only)
rch doctor --reliability            # reliability-focused probes (topology/convergence/pressure/triage/…)
```

## Error Taxonomy

Error codes follow `RCH-Exxx`; admission/incident reason codes use `RCH-Innn`;
operator runbooks for remediation codes use `RCH-Rnnn` (see
`rch doctor --runbook-list`).

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

**Symptoms:** Status shows worker "unreachable"/"bypassed", circuit breaker "open"

**Reason codes:** `circuit_open`, `worker_unreachable`

**Diagnosis:**
```bash
rch status --fleet
rch workers probe <worker-id> --verbose
ssh <user>@<host> 'echo ok'
```

**Remediation:** fix the underlying SSH/network/agent issue (see the
[worker-recovery runbook](worker-recovery.md)), then let the breaker self-heal.
There is no manual circuit reset and no `--force` probe; a successful scheduled
probe moves the breaker open → half-open → closed and a canary build auto-rejoins
the worker.
```bash
rch workers probe <worker-id> --verbose   # observe; daemon clears the breaker after a good probe
rch status --fleet                        # confirm it returned to the live pool
```
Do **not** `rch workers disable` for a transient outage — that blocks auto-rejoin.

### Disk Pressure Critical

**Symptoms:** Worker pressure state "critical", builds deferred

**Reason code:** `pressure_critical`

**Diagnosis:**
```bash
rch doctor --reliability --scope pressure
rch status --json | jq '.daemon.workers[] | select(.pressure_state == "critical")'
ssh <user>@<host> 'df -h / /tmp'
```

**Remediation:** reclaim safely. The daemon's stale-target reaper removes only
idle remote dirs (active builds are always kept); local staging trees are reaped
via `rch cache clean`, which is **dry-run by default**:
```bash
rch cache clean --older 1h                 # preview reclaimable local staging trees
rch cache clean --older 1h --execute       # reclaim idle trees
# Reclaim incremental build state without nuking a whole target tree:
ssh <user>@<host> 'cargo clean --manifest-path /tmp/rch/<project>/Cargo.toml'
# Manual removal is a last resort — verify the candidate is inactive FIRST:
ssh <user>@<host> 'sudo lsof +D /tmp/rch_target_<name>'   # empty ⇒ inactive
ssh <user>@<host> 'rm -rf /tmp/rch_target_<name>'         # only if lsof was empty
```

**Risk:** Reclaim removes cached build artifacts; subsequent builds are slower
until caches rebuild. Blind `rm -rf` of an active dir can corrupt a live build —
hence the lsof guard and active-build-protected reaper.

### Repo Convergence Failed

**Symptoms:** Worker convergence state "failed"/"drifting", missing repos

**Reason codes:** `convergence_failed`, `convergence_drifting` (RCH-R3xx)

**Diagnosis:**
```bash
rch doctor --reliability --scope convergence
rch status --json | jq '.convergence.workers[] | select(.drift_state != "ready")'
```

**Remediation:** the daemon converges drift automatically; to force a repair,
use the operator-confirmed fleet doctor fix (preview first):
```bash
rch fleet doctor --reliability --scope convergence                                   # diagnose
rch fleet doctor --reliability --scope convergence --fix --fleet-confirm --workers <id>   # apply on one worker
```

**Risk:** Convergence repair may re-sync/re-clone repositories, discarding any
worker-side local changes. `--fleet-confirm` is the required safety gate before
`--fix` touches workers; scope to specific `--workers` rather than the whole fleet
when in doubt.

### All Workers Down (Fail-Open)

**Symptoms:** Posture `local-only`, all builds running locally

**Reason:** No healthy workers available — often a cloud/VMI fleet incident or a
self-induced swarm-load collapse (see the dedicated sections below)

**Diagnosis:**
```bash
rch status --fleet
rch doctor
```

**Remediation:** fail-open is working as designed — builds are not blocked. Fix
the systemic cause (network, DNS, SSH keys, cloud outage), then workers
auto-rejoin. Do **not** `rch workers disable` or delete absent workers to "clean
up"; they are part of desired state and rejoin on recovery.

### Schema/Contract Mismatch

**Symptoms:** Adapter version warnings, unexpected response formats

**Reason code:** `schema_mismatch`

**Diagnosis:**
```bash
rch doctor --reliability --check-schemas
```

**Remediation:** redeploy the affected adapter binary to workers with an
atomic, verified deploy (do not hand-patch a worker binary):
```bash
rch fleet deploy --worker <id> --force --verify
rch status --json | jq '.schema_version'
```

## Cloud / VMI Fleet Incidents

When the whole fleet (or a region) disappears at once — provider outage, VMI
image roll, network partition — RCH treats it as a desired-vs-live gap, not a
config problem:

```bash
rch status --fleet            # dominant problem class = absent/unreachable across many workers
rch status --remediation      # posture local-only/degraded, fallback flagged intentional
```

- **Fail-open carries you:** builds run locally; nothing is blocked.
- **Do not mutate desired state to react.** Editing `workers.toml` or
  `rch workers disable`-ing the absent nodes forces a manual re-add and defeats
  auto-rejoin when the cloud recovers.
- **When the fleet returns,** workers are re-probed and auto-rejoined (canary
  before full traffic). Confirm with `rch status --fleet`.
- **Genuinely dead node?** Decommission explicitly:
  `rch workers disable <id> --reason "decommissioned" --drain -y`.

## Local Fallback Hazards Under Swarm Load

Many agents building at once can starve the worker pool. The danger is a
feedback loop: builds fall back to local, local CPU saturates, everything slows,
and operators "fix" it with destructive manual cleanup that removes capacity.

Safer handling:

```bash
rch status --fleet            # is it real shortage, overload, or pressure?
rch queue                     # depth + which builds are running/waiting
rch admit "cargo build"       # RCH-I003 insufficient slots? RCH-I011 local fallback?
```

- **Prefer queueing over fallback** under contention — `RCH_QUEUE_WHEN_BUSY=1`
  (default) waits for a busy worker instead of piling onto local CPU.
- **Shed load by cancelling, not killing:** `rch cancel <id>` / `rch cancel --all -y`
  reclaims slots with tracked cleanup.
- **Do not add/remove workers reflexively** or `pkill` local cargo — that masks
  the signal and can worsen the loop. Watch the fallback rate against the SLO.

## Proof-Mode Handoff

When a result must be *proven* to have run remotely (no silent local fallback),
hand off through proof mode rather than trusting logs:

```bash
# Interim proof lane — fail-closed, self-healing disabled so nothing auto-starts underneath:
RCH_REQUIRE_REMOTE=1 RCH_NO_SELF_HEALING=1 rch --no-self-healing exec -- cargo test --workspace
```

- `RCH_REQUIRE_REMOTE=1` refuses local fallback (`RCH-I012` / `RCH-E301`) instead
  of running locally. Keep the build command as **direct argv** after `--`;
  shell-wrapped (`bash -lc "..."`) commands classify as non-compilation and are
  refused under strict mode.
- A refusal records a durable **proof intent** in the proof store
  (`<state>/proofs.jsonl`), which the daemon replays when capacity returns; the
  matching incident lands in `<state>/incidents.jsonl`
  (`<state>` = `RCH_STATE_HOME`, else `XDG_STATE_HOME/rch`, else
  `~/.local/state/rch`, else `/tmp/rch`).
- Inspect the handoff with `rch status --remediation --json` (proof-queue band)
  and `rch admit "<cmd>" --json` rather than scraping output.

## Feature Flags and Rollout

| State | Meaning |
|-------|---------|
| `disabled` | Feature completely off |
| `dry_run` | Feature runs but takes no action; logs what would happen |
| `canary` | Feature active on subset of workers |
| `enabled` | Feature fully active |

```bash
rch status --json | jq '.feature_flags'
```

## SLO Guardrails

| Metric | P50 Budget | P99 Budget | Release Blocking |
|--------|-----------|-----------|-----------------|
| Hook decision latency | 1ms | 5ms | Yes |
| Convergence check | 100ms | 500ms | P99 only |
| Triage overhead | 2ms | — | Yes |
| Fallback rate | <10% | — | Yes |
| Cancellation cleanup | — | 10s | Yes |

## Incident Triage Flowchart

1. **Check posture:** `rch status --fleet` / `rch status --json | jq '.posture'`
2. **If `local-only`:** all workers → network → SSH → daemon; suspect a cloud/VMI
   incident or swarm-load collapse (sections above). Fail-open is correct; fix the
   cause, don't disable desired state.
3. **If `degraded`:** inspect failing workers → `rch doctor --reliability`
4. **If `remote-ready` but slow:** pressure → convergence → build/queue stats
5. **Escalation:** collect `rch status --remediation --json` and
   `rch doctor --reliability --json`; the incident ledger already has the
   reason-coded chain.

## Safe vs Destructive Operations

All diagnostics are read-only and safe in production:

```bash
rch check                                 # read-only
rch status / rch status --fleet           # read-only
rch doctor / rch doctor --reliability     # read-only diagnostics
rch self-test                             # creates temp files, cleans up
rch cache clean --older <dur>             # DRY-RUN unless --execute is added
```

Operations that change state require operator intent — preview, then confirm:

```bash
rch cache clean --older <dur> --execute                                   # reclaims idle staging trees
rch fleet doctor --reliability --scope convergence --fix --fleet-confirm  # may re-sync repos
rch fleet deploy --worker <id> --force --verify                           # atomic, rollback-safe
rch workers disable <id> --reason "..." --drain -y                        # PERMANENT decommission only
```

Never: `pkill -9` a build/agent, `rm -rf` a worker's RCH tree, or `rm` the daemon
socket. Use `rch cancel`, the audited triage fix, the active-build-protected
reaper, and `rch daemon restart` instead.

## Validation

The behaviors in this runbook are backed by tests; the runbook itself is guarded
against stale guidance returning:

```bash
# Runbook regression guard (forbidden/stale guidance cannot return; wired into CI):
./scripts/check_runbooks_safe.sh
# Reliability traceability matrix + convergence + pressure/triage behaviors:
cargo test -p rch-common --test reliability_coverage_matrix_e2e
cargo test -p rch-common --test repo_convergence_e2e
# Admission reason-code vocabulary + proof-mode + incident ledger:
cargo test -p rch-common --test admission_goldens_e2e
cargo test -p rch-common --lib proof incident telemetry_explain
```

Structured records live under `<state>` (`RCH_STATE_HOME`, else
`XDG_STATE_HOME/rch`, else `~/.local/state/rch`, else `/tmp/rch`):
`incidents.jsonl` (reason-coded incidents) and `proofs.jsonl` (proof intents +
replay state). E2E scenario logs are written as JSONL under `target/test-logs/`.
Read live state via `rch status --remediation --json`, `rch diagnose "<cmd>"
--json`, and `rch admit "<cmd>" --json`.
