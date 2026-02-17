# Migration Guide

This guide helps you transition from local compilation to RCH remote compilation.

## Overview

Migrating to RCH involves:
1. Setting up the infrastructure (workers, daemon)
2. Installing hooks for your AI coding agent
3. Validating behavior matches local compilation
4. Tuning for optimal performance

The goal is **transparent** operation - your workflow shouldn't change.

## Pre-Migration Checklist

Before starting:

- [ ] Identify worker machines (existing servers, cloud VMs, spare desktops)
- [ ] Ensure SSH access to workers
- [ ] Verify workers have sufficient resources (CPU, RAM, disk)
- [ ] Document current build times as baseline

## Step 1: Infrastructure Setup

### Install RCH on Workstation

```bash
# From source
git clone https://github.com/Dicklesworthstone/remote_compilation_helper.git
cd remote_compilation_helper
cargo build --release
cp target/release/rch target/release/rchd ~/.local/bin/

# Or via cargo
cargo install --git https://github.com/Dicklesworthstone/remote_compilation_helper.git
```

### Configure Workers

```bash
mkdir -p ~/.config/rch

cat > ~/.config/rch/workers.toml << 'EOF'
[[workers]]
id = "worker1"
host = "your-worker-ip"
user = "your-username"
identity_file = "~/.ssh/id_rsa"
total_slots = 8
priority = 100
EOF
```

### Deploy to Workers

```bash
# Install RCH on workers
rch fleet deploy

# Verify
rch fleet verify
```

### Start the Daemon

```bash
rch daemon start
```

## Step 2: Install Hooks

### Claude Code

```bash
rch hook install --agent=claude-code
```

This adds RCH to Claude Code's PreToolUse hooks.

### Verify Hook Installation

```bash
rch hook status
```

Should show the hook is active.

## Step 3: Validation

### Test Classification

Verify commands are classified correctly:

```bash
# Should be REMOTE
rch classify "cargo build --release"
rch classify "cargo test"
rch classify "cargo check"

# Should be LOCAL
rch classify "cargo fmt"
rch classify "cargo install foo"
rch classify "cargo clean"
rch classify "git status"
```

### Test End-to-End

Run a build with verbose output:

```bash
cd /path/to/rust/project
RCH_VERBOSE=1 cargo build
```

You should see:
1. Command classification
2. Worker selection
3. Transfer to worker
4. Remote execution
5. Artifact retrieval

### Verify Artifacts

After remote build:

```bash
# Check artifacts are present
ls -la target/release/

# Run the binary
./target/release/your-app --version
```

## Step 4: Canonical Topology Rollout Plan (`/data/projects` + `/dp`)

This phase is specifically for migrating existing workers to the canonical
filesystem topology required by reliability workstreams:

- `/data/projects` must exist as a directory
- `/dp` must be a symlink resolving to `/data/projects`
- workers failing topology preflight must be excluded from remote scheduling

### Phase 0: Fleet Inventory and Segmentation

1. Capture a baseline before making any changes:
```bash
rch workers list
rch workers probe --all
rch status --workers
```
2. Segment workers into rollout cohorts (for example by region or host group):
- `canary` (5-15% of fleet)
- `batch-a` (next 30-40%)
- `batch-b` (remainder)
3. Record cohort membership in your operations notes before execution.

### Phase 1: Canary Cohort

Run migration only on canary workers first:

```bash
# Run bootstrap/enforcement for a single canary worker or a small set.
rch workers setup --worker <canary-id>

# Re-verify health and topology eligibility.
rch workers probe <canary-id>
rch status --workers
```

Go/no-go rule for Phase 1:
- Proceed only if all canary workers are healthy or have explicit, understood,
  non-topology issues unrelated to migration.

### Phase 2: Rolling Batch Migration

Migrate the remaining cohorts in bounded batches. After each batch:

1. Run worker setup for that cohort.
2. Re-check worker probe + status.
3. Stop immediately on repeated topology integrity failures.

### Phase 3: Full-Fleet Validation and Stabilization

After all cohorts are migrated:

- Run full worker health checks.
- Run representative compile/test workloads.
- Confirm no persistent preflight exclusion for topology reasons.

## Mixed-State Worker Handling (Critical)

During migration, mixed states are expected temporarily. Treat them explicitly:

| State Detected | Meaning | Required Action |
|---|---|---|
| `projects_root_ok=true` | Topology healthy | Keep worker eligible |
| `alias_missing` | `/dp` missing | Re-run setup, verify symlink creation |
| `alias_wrong_target:*` | `/dp` points elsewhere | Repoint alias, re-run probe |
| `alias_not_symlink` | `/dp` exists but wrong type | Manual repair (safe remove/recreate symlink) |
| `canonical_not_directory` | `/data/projects` exists but invalid type | Manual integrity remediation before retry |
| `canonical_missing` | canonical root absent | Re-run setup, confirm directory creation |

Workers with topology failures must remain excluded from remote scheduling until
explicit revalidation confirms recovery.

## Validation Checklist (Per Phase Gate)

Use this checklist before promoting to the next phase:

- [ ] `rch workers probe` succeeds for target cohort
- [ ] No unresolved topology-preflight failure reasons in `rch status --workers`
- [ ] At least one representative `cargo build` and `cargo test` run succeeds
- [ ] No unexpected fail-open spikes during the phase window
- [ ] Operator notes include worker IDs, timestamps, and remediation actions

## Dry-Run Procedure + Evidence Template

Before each production phase, run and archive a dry-run evidence bundle:

```bash
# Example evidence capture commands
date -Iseconds
rch workers list
rch workers probe --all
rch status --workers
```

Evidence template (store in your rollout notes):

```text
Phase: <canary|batch-a|batch-b|final>
Timestamp: <ISO8601>
Cohort Workers: <comma-separated ids>
Preflight Summary: <healthy/degraded counts>
Topology Failures: <none | list of worker->reason>
Actions Taken: <commands + remediation>
Go/No-Go Decision: <go|no-go>
Approved By: <operator>
```

## Step 5: Performance Tuning

### Baseline Comparison

Compare build times:

```bash
# Local build (RCH disabled)
RCH_ENABLED=false time cargo build --release

# Remote build
RCH_ENABLED=true time cargo build --release
```

### Initial Sync

First sync to a worker is slow (full project transfer). Subsequent syncs are incremental.

Tips to minimize initial sync:
- Ensure `.gitignore` includes `target/`
- Add large data directories to excludes
- Consider pre-warming worker caches

### Optimize Excludes

```toml
# ~/.config/rch/config.toml
[transfer]
exclude_patterns = [
    "target/",
    ".git/objects/",
    "node_modules/",
    "benches/data/",
    "test_fixtures/large/",
]
```

### Adjust Compression

For different network conditions:

```toml
# Fast local network (100Mbps+)
compression_level = 1

# Moderate network (10-100Mbps)
compression_level = 3

# Slow network (<10Mbps)
compression_level = 9
```

## Common Migration Issues

### "Build runs locally instead of remote"

1. Check daemon is running: `rch daemon status`
2. Check hook is installed: `rch hook status`
3. Check command classification: `rch classify "your command"`
4. Check confidence threshold: lower if needed

### "Build slower than local"

Expected for:
- Small projects (overhead exceeds benefit)
- First build (initial sync is slow)
- Poor network to workers

Solutions:
- Increase `min_local_time_ms` to skip small builds
- Add more workers
- Improve network connectivity

### "Build fails remotely but works locally"

Common causes:
1. Missing tools on worker (install via `rch fleet deploy`)
2. Different Rust version (sync toolchains)
3. Platform-specific code (workers must be same platform)
4. Missing environment variables

Debug with:
```bash
RCH_LOG_LEVEL=debug cargo build 2>&1 | tee build.log
```

### "Artifacts missing after build"

Check transfer patterns include your artifacts:

```toml
# .rch/config.toml
[transfer]
include_artifacts = [
    "target/release/*",
    "target/debug/*",
]
```

## Rollback Plan

If migration causes instability or inconsistent topology states, roll back in
reverse cohort order.

### Rollback Triggers

Initiate rollback when any of the following are true:

- sustained topology preflight failures after remediation attempts
- repeated `alias_wrong_target` / `alias_not_symlink` reoccurrence in the same cohort
- materially elevated fail-open rate attributable to topology drift
- operator cannot prove canonical invariants for current rollout segment

### Rollback Steps

1. Freeze rollout immediately (no new cohorts).
2. Remove affected workers from routing (drain/disable) until repaired:
```bash
rch workers drain <worker-id>
```
3. Restore previously known-good worker topology configuration for the affected cohort.
4. Re-run probe/status validation:
```bash
rch workers probe <worker-id>
rch status --workers
```
5. Re-enable workers only after explicit verification:
```bash
rch workers enable <worker-id>
```
6. If fleet-wide instability persists, temporarily disable RCH for local fallback:
```bash
export RCH_ENABLED=false
```

### Rollback Completion Criteria

- All affected workers are either healthy and revalidated, or intentionally drained.
- No unknown topology-preflight failures remain.
- Incident notes include root cause, corrective action, and follow-up owner.

## Post-Migration

### Document the Setup

Record:
- Worker configurations
- Tuning decisions made
- Known issues and workarounds

### Set Up Monitoring

- Add health checks (see Monitoring Guide)
- Configure alerts for daemon/worker issues
- Track build performance over time

### Team Onboarding

Share with team:
1. RCH overview and benefits
2. How to check if RCH is working
3. How to bypass RCH if needed
4. Who to contact for issues

## Comparison: Before vs After

| Aspect | Before (Local) | After (RCH) |
|--------|---------------|-------------|
| Build CPU | Workstation | Workers |
| Build parallelism | Limited by local cores | Limited by fleet cores |
| Concurrent agents | ~2-3 before throttling | Many (worker-limited) |
| Workstation responsiveness | Degraded during builds | Maintained |
| Setup complexity | None | Moderate (one-time) |
| Dependencies | Local tools | Tools on workers |

## Success Criteria

Migration is successful when:
- [ ] Builds complete successfully via RCH
- [ ] Build times are acceptable (≤ 15% overhead typical)
- [ ] Multiple agents can build concurrently
- [ ] Workstation remains responsive during builds
- [ ] Team is trained on RCH operation
- [ ] Monitoring and alerts are in place
