# Runbook: Debugging Slow Builds

## Symptoms

- Build takes significantly longer than expected
- `rch status` shows high latency to workers
- Builds appear to be queuing or waiting

## Quick Diagnosis

```bash
# Check overall system health
rch doctor

# View worker status
rch status --workers

# See active builds
rch status --jobs
```

## Step-by-Step Investigation

### 1. Check Worker Health

```bash
rch status --workers
```

**Look for:**
- Workers marked as "degraded" or "unreachable"
- High latency values (> 100ms round-trip)
- Low available slots (all cores in use)
- Open circuit breakers

**Example output analysis:**
```
Worker 'css' (32 slots):
  Status: degraded          <-- Problem: Worker is slow
  Latency: 250ms            <-- Problem: High latency
  Available: 2/32           <-- OK: Slots available
  Circuit: closed           <-- OK: Not tripped

Worker 'fra' (16 slots):
  Status: unreachable       <-- Problem: Can't connect
  Circuit: open             <-- Expected: Circuit tripped
```

### 2. Check Circuit Breaker States

```bash
rch status --circuits
```

**If circuits are open:**
- Worker is experiencing repeated failures
- RCH stopped routing to protect system
- Wait for half-open state (30s default) or investigate worker

**Resolution options:**
```bash
# Manual reset (if you know worker is fixed)
rch worker reset <worker-id>

# Or wait for automatic recovery
# Check logs for failure reason
rch daemon logs | grep <worker-id>
```

### 3. Check Transfer Performance

Enable debug logging to see transfer times:

```bash
RCH_LOG_LEVEL=debug cargo build 2>&1 | grep -i transfer
```

**Look for:**
- Transfer times > 5s for small projects (< 10MB)
- Low compression ratios (< 2x)
- Rsync errors or retries

**If transfers are slow:**

```bash
# Test raw network speed
ssh worker "dd if=/dev/zero bs=1M count=100" | dd of=/dev/null

# Check what's being transferred
rch sync --dry-run

# Verify excludes are working
cat .rch/config.toml  # Check exclude patterns
```

### 4. Check Command Classification

Verify the command is being classified correctly:

```bash
rch classify "your command here"
```

**Expected output:**
```
Command: cargo build --release
Classification: Remote (CargoBuild)
Confidence: 0.95
Decision: INTERCEPT (threshold: 0.85)
```

**If classification is wrong:**
- Report as bug if legitimate compilation command not intercepted
- Use `--local` flag for specific commands that shouldn't be remoted

### 5. Check Worker Resources

SSH to worker and check resources:

```bash
# Check disk space
ssh worker "df -h /tmp"

# Check memory
ssh worker "free -m"

# Check CPU load
ssh worker "uptime"

# Check for zombie processes
ssh worker "ps aux | grep -E 'cargo|rustc' | head -20"
```

### 6. Check Project Cache

```bash
# View cache usage on worker
ssh worker "du -sh /tmp/rch/*"

# Clean old caches
rch worker clean <worker-id> --max-age-hours=24
```

## Common Solutions

| Issue | Solution |
|-------|----------|
| All circuits open | Check worker connectivity, restart workers |
| High transfer time | Check network, adjust compression level |
| Worker degraded | Investigate worker load, add more workers |
| Slots exhausted | Reduce parallel agents or add workers |
| Wrong classification | Report bug, use `--local` flag |
| Cache too large | Clean worker caches |
| First build slow | Normal - initial sync is full transfer |

## Performance Tuning

### Adjust Compression Level

```toml
# ~/.config/rch/config.toml
[transfer]
compression_level = 3  # Default: 3 (1-19, lower = faster)
```

- Level 1-3: Fast compression, larger transfer
- Level 3-6: Balanced (recommended)
- Level 7+: Slower compression, smaller transfer (only for slow networks)

### Optimize Excludes

```toml
# ~/.config/rch/config.toml
[transfer]
exclude_patterns = [
    "target/",
    ".git/objects/",
    "node_modules/",
    "*.rlib",
    "*.rmeta",
    "benches/data/",  # Add project-specific excludes
]
```

### Increase Parallelism

```bash
# If workers have capacity
rch daemon restart --max-parallel=8
```

## Escalation

If the issue persists after following this runbook:

1. Collect diagnostic information:
   ```bash
   rch debug-bundle > rch-debug-$(date +%Y%m%d).txt
   ```

2. Check recent changes:
   - New workers added?
   - Network changes?
   - Large project changes?

3. Review daemon logs:
   ```bash
   rch daemon logs --tail 100
   ```

4. File an issue with the debug bundle attached.
