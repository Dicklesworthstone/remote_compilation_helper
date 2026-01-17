# RCH Troubleshooting Guide

## Quick Diagnostics

Run the doctor command for automated diagnostics:

```bash
rch doctor
```

This checks:
- Daemon status and connectivity
- Worker SSH connectivity
- Hook installation
- Configuration validity
- Recent build history

---

## Common Issues

### 1. Builds Run Locally Instead of Remote

**Symptoms:**
- No visible difference in build behavior
- Build times same as before RCH
- `rch status --jobs` shows no active jobs

**Diagnosis:**

```bash
# Check if hook is installed
rch hook status

# Test classification manually
rch classify "cargo build --release"

# Check if daemon is running
rch daemon status
```

**Solutions:**

| Cause | Fix |
|-------|-----|
| Hooks not installed | `rch hook install` |
| Daemon not running | `rchd` or `rch daemon start` |
| Command not recognized | Check classifier output - may need pattern update |
| All workers down | `rch workers probe --all` |
| Confidence below threshold | Adjust `confidence_threshold` in config |

### 2. "Connection Refused" or "Daemon Not Running"

**Symptoms:**
- Commands hang or fail immediately
- Error: "Could not connect to daemon"
- Socket file missing

**Diagnosis:**

```bash
# Check if daemon process is running
pgrep -x rchd

# Check socket file
ls -la "${XDG_RUNTIME_DIR:-$HOME/.cache/rch}/rch.sock"

# Check daemon logs
rch daemon logs --tail 50
```

**Solutions:**

```bash
# Start the daemon
rchd

# Or as a background service (Linux)
systemctl --user start rchd

# macOS with launchd
launchctl load ~/Library/LaunchAgents/com.rch.daemon.plist
```

### 3. SSH Connection Failures

**Symptoms:**
- "Permission denied"
- "Connection timed out"
- Worker shows as "unreachable" in status

**Diagnosis:**

```bash
# Test SSH directly
ssh -i ~/.ssh/your_key user@worker-host "echo OK"

# Check RCH's SSH configuration
cat ~/.config/rch/workers.toml

# Verbose SSH test
ssh -v -i ~/.ssh/your_key user@worker-host "echo OK"
```

**Solutions:**

| Cause | Fix |
|-------|-----|
| Wrong SSH key | Update `identity_file` in workers.toml |
| SSH agent not running | `eval $(ssh-agent) && ssh-add` |
| Firewall blocking | Check port 22 or custom SSH port |
| Host key changed | `ssh-keygen -R worker-host` |
| Known hosts issue | Add `StrictHostKeyChecking=no` for first connection |

### 4. Slow Sync / First Build Very Slow

**Symptoms:**
- First build takes much longer than local
- "Syncing..." step takes minutes
- High bandwidth usage

**Understanding:**
- First sync transfers entire project (excluding `target/`, `.git/objects/`)
- Subsequent syncs are incremental (only changed files)
- Large projects with many files take longer

**Diagnosis:**

```bash
# See what's being synced
RCH_VERBOSE=1 cargo build 2>&1 | grep -i sync

# Check project size
du -sh . --exclude=target --exclude=.git
```

**Solutions:**

```bash
# Ensure exclusions are configured
cat ~/.config/rch/config.toml | grep exclude

# Add additional exclusions for your project
# In ~/.config/rch/config.toml:
[transfer]
exclude_patterns = [
    "target/",
    ".git/objects/",
    "node_modules/",
    "*.rlib",
    "*.rmeta",
    "vendor/",           # Add project-specific
    "test_data/large/",  # Add project-specific
]
```

### 5. Build Succeeds on Worker but Fails Locally

**Symptoms:**
- Remote build succeeds
- Local verification fails
- Missing artifacts after build

**Diagnosis:**

```bash
# Check what was synced back
ls -la target/release/

# Enable verbose mode
RCH_VERBOSE=1 cargo build

# Check transfer settings
rch config show | grep -A5 "\[transfer\]"
```

**Solutions:**
- Ensure `target/` is synced back (default behavior)
- Check for platform-specific artifacts (cross-compilation issues)
- Verify both machines have same Rust toolchain

### 6. Circuit Breaker Open (Worker Unavailable)

**Symptoms:**
- Worker shows "circuit: open" in status
- Builds going to other workers or running locally
- Recent failures logged

**Understanding:**

RCH uses a per-worker circuit breaker to prevent cascading failures. Think of it
like an electrical breaker: after repeated failures, it "opens" and stops
routing builds to that worker until the cooldown expires.

**States:**
- **Closed**: Normal operation (worker accepts jobs)
- **Open**: Worker excluded after failures; cooldown running
- **Half-open**: Limited probes to test recovery

**Transitions (defaults):**
- **Closed → Open**: 3 consecutive failures or high error rate (>= 50% in 60s)
- **Open → Half-open**: cooldown elapsed (30s)
- **Half-open → Closed**: 2 consecutive successes
- **Half-open → Open**: any failure

**Diagnosis:**

```bash
# Check circuit state (summary)
rch status --workers

# Detailed circuit status
rch status --circuits

# Failure history and recent events
rch workers history my-worker
rch daemon logs | grep -i circuit
```

**Solutions:**

```bash
# Wait for automatic recovery (half-open probes after cooldown)

# Manually reset once the worker is fixed
rch workers reset my-worker

# Force re-probe
rch workers probe my-worker
```

**Configuration (config.toml):**

```toml
[circuit]
failure_threshold = 3        # consecutive failures to open
success_threshold = 2        # consecutive successes to close
error_rate_threshold = 0.5   # error rate to open within window
window_secs = 60             # rolling window size
open_cooldown_secs = 30      # cooldown before half-open
half_open_max_probes = 1     # concurrent probes allowed
```

See the full guide: `docs/guides/circuit-breaker.md`.

### 7. Classification Wrong (Non-build Commands Offloaded)

**Symptoms:**
- Non-build commands sent to worker
- Unexpected behavior for certain commands

**Diagnosis:**

```bash
# Test specific command
rch classify "your command here"

# See classification with debug output
RCH_LOG_LEVEL=debug rch classify "command"
```

**Solutions:**
- Report false positives as bugs
- Use `--local` flag for specific commands: `RCH_LOCAL_ONLY=1 command`
- Add patterns to never-intercept list (requires code change)

### 8. Memory/Disk Issues on Worker

**Symptoms:**
- Builds fail with OOM (Out of Memory)
- "No space left on device" errors
- Worker becomes slow/unresponsive

**Diagnosis:**

```bash
# Check worker resources via SSH
ssh user@worker "df -h && free -m"

# Check RCH temp directory usage
ssh user@worker "du -sh /tmp/rch/"
```

**Solutions:**

```bash
# Clean worker disk
rch workers clean my-worker

# Or manually clean old builds
ssh user@worker "rm -rf /tmp/rch/*"

# Add more workers to distribute load
```

### 9. Toolchain Mismatch

**Symptoms:**
- Compilation errors about unstable features
- Different behavior on worker vs local
- "error[E0554]: `#![feature]` may not be used on the stable release channel"

**Diagnosis:**

```bash
# Check local toolchain
rustc --version
rustup show

# Check worker toolchain
ssh user@worker "rustc --version && rustup show"
```

**Solutions:**

```bash
# Sync toolchain to worker
ssh user@worker "rustup default nightly-2024-01-15"

# Or use rustup override in project
echo "nightly-2024-01-15" > rust-toolchain.toml
```

---

## Diagnostic Commands Reference

| Command | Purpose |
|---------|---------|
| `rch doctor` | Full diagnostic check |
| `rch status` | Daemon and worker overview |
| `rch status --workers` | Detailed worker status |
| `rch status --jobs` | Active and recent compilations |
| `rch workers probe --all` | Test all worker connections |
| `rch workers probe <id>` | Test specific worker |
| `rch hook status` | Check hook installation |
| `rch classify "cmd"` | Test command classification |
| `rch config show` | Display current configuration |
| `rch daemon logs` | View daemon logs |

---

## Collecting Debug Information

For bug reports, collect:

```bash
# Generate debug bundle
{
  echo "=== RCH Version ==="
  rch --version 2>&1

  echo -e "\n=== Doctor Output ==="
  rch doctor 2>&1

  echo -e "\n=== Status ==="
  rch status 2>&1

  echo -e "\n=== Workers ==="
  rch status --workers 2>&1

  echo -e "\n=== Config ==="
  rch config show 2>&1

  echo -e "\n=== Hook Status ==="
  rch hook status 2>&1

  echo -e "\n=== Rust Version ==="
  rustc --version 2>&1

  echo -e "\n=== OS Info ==="
  uname -a 2>&1
} > rch-debug.txt

echo "Debug info saved to rch-debug.txt"
```

---

## Getting Help

- **GitHub Issues**: [Report a bug](https://github.com/Dicklesworthstone/remote_compilation_helper/issues)
- **Discussions**: [Ask questions](https://github.com/Dicklesworthstone/remote_compilation_helper/discussions)
- **README**: [Full documentation](https://github.com/Dicklesworthstone/remote_compilation_helper#readme)

When reporting issues, please include:
1. RCH version (`rch --version`)
2. Operating system and version
3. Output of `rch doctor`
4. Steps to reproduce
5. Expected vs actual behavior
