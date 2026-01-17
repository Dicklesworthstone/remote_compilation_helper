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

## Step 4: Phased Rollout

### Phase 1: Single Project

Start with one project to gain confidence:

```bash
# Enable only for specific project
cd /path/to/project
mkdir .rch
echo 'enabled = true' > .rch/config.toml
```

### Phase 2: Gradual Expansion

After validation:
- Remove project-specific configs
- Let RCH handle all projects

### Phase 3: Full Production

- Enable for all AI agent sessions
- Monitor for issues
- Tune as needed

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

If issues arise, disable RCH temporarily:

```bash
# Immediate disable (environment)
export RCH_ENABLED=false

# Or stop daemon
rch daemon stop

# Or uninstall hook
rch hook uninstall
```

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
