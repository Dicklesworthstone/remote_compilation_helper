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
rch workers list --verbose     # per-worker circuit + health state
rch queue                      # circuit states alongside running/queued builds
rch status --remediation       # operator bands incl. circuit/telemetry
```

**If circuits are open:**
- Worker is experiencing repeated failures
- RCH stopped routing to protect the system
- The breaker recovers itself: open → half-open (probe window) → closed after a
  successful canary. There is no manual reset (and no `--circuits` flag).

**Resolution options:**
```bash
# Fix the underlying worker issue, then observe the breaker self-heal:
rch workers probe <worker-id> -v
rch daemon logs -n 200 | grep <worker-id>
rch status --fleet             # confirm it returned to the live pool
```
Do not `rch workers disable` a worker whose breaker is open for a transient
failure — it auto-rejoins once probes succeed.

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

# Inspect the resolved transfer/offload plan (no side effects)
rch diagnose "cargo build --release" --dry-run --json

# Verify excludes are working
cat .rch/config.toml  # Check exclude patterns
```

### 4. Check Command Classification

Verify the command is being classified correctly:

```bash
rch diagnose "your command here"
rch admit "your command here"        # offload recommendation + RCH-Innn reason code
```

**Expected output:**
```
Command: cargo build --release
Classification: Remote (CargoBuild)
Confidence: 0.95
Decision: INTERCEPT (threshold: 0.85)
```

**If classification is wrong:**
- Report as a bug if a legitimate compilation command is not intercepted
- Force a command to stay local via config: `general.force_local = true` in a
  project `.rch/config.toml` (or `RCH_FORCE_REMOTE=1` to force the opposite)

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

# Reclaim idle local staging trees (dry-run first, then --execute).
# Remote worker dirs are reaped automatically with active-build protection.
rch cache clean --older 24h
rch cache clean --older 24h --execute
```

## Common Solutions

| Issue | Solution |
|-------|----------|
| All circuits open | Check worker connectivity, restart workers |
| High transfer time | Check network, adjust compression level |
| Worker degraded | Investigate worker load, add more workers |
| Slots exhausted | Reduce parallel agents or add workers |
| Wrong classification | Report bug; pin with `general.force_local` in `.rch/config.toml` |
| Cache too large | `rch cache clean --older <dur> --execute` (reaper handles remote) |
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
    ".git/",
    "node_modules/",
    "*.rlib",
    "*.rmeta",
    "benches/data/",  # Add project-specific excludes
]
```

### Increase Parallelism

Slot counts are config-driven; edit them and reload (no restart needed):

```toml
# ~/.config/rch/config.toml
[compilation]
build_slots = 4
test_slots = 8
check_slots = 2
```

```bash
rch daemon reload
```

## Escalation

If the issue persists after following this runbook:

1. Collect diagnostic information:
   ```bash
   rch doctor --json > rch-doctor.json
   rch status --remediation --json > rch-remediation.json
   ```

2. Check recent changes:
   - New workers added?
   - Network changes?
   - Large project changes?

3. Review daemon logs:
   ```bash
   rch daemon logs -n 100
   ```

4. File an issue with the debug bundle attached.
