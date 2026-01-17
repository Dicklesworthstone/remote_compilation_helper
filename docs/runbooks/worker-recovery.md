# Runbook: Worker Recovery

## Symptoms

- Worker shows as "unreachable" in status
- Circuit breaker is "open" for worker
- Builds not being routed to specific worker
- SSH connection failures in logs

## Quick Diagnosis

```bash
# Check worker status
rch status --workers

# Check specific worker
rch workers probe <worker-id> --verbose

# Test SSH directly
ssh -i ~/.ssh/rch_key user@worker-host "echo OK"
```

## Step-by-Step Recovery

### 1. Identify the Problem

```bash
# Check worker status
rch workers probe <worker-id> --verbose
```

**Possible issues:**
- SSH connection refused (service down)
- SSH timeout (network issue or firewall)
- SSH authentication failed (key issue)
- Worker agent not responding (rch-wkr down)
- Disk full
- Out of memory

### 2. SSH Connection Issues

**Connection refused:**
```bash
# Check if SSH service is running on worker
ssh user@worker "systemctl status sshd" 2>/dev/null || \
    echo "Cannot connect - SSH may be down"

# If you have console access, restart SSH:
sudo systemctl restart sshd
```

**Connection timeout:**
```bash
# Check network connectivity
ping worker-host

# Check if port 22 is open
nc -zv worker-host 22

# Check firewall rules (on worker)
sudo ufw status
sudo iptables -L -n | grep 22
```

**Authentication failed:**
```bash
# Test SSH with verbose output
ssh -vvv -i ~/.ssh/rch_key user@worker-host "echo OK"

# Check key permissions
ls -la ~/.ssh/rch_key
# Should be: -rw------- (600)

# Check authorized_keys on worker
ssh user@worker "cat ~/.ssh/authorized_keys"
```

### 3. Worker Agent Issues

**Check if rch-wkr is installed and working:**
```bash
# Test worker agent
ssh worker "~/.rch/bin/rch-wkr health"
# Should output: OK

# Check version
ssh worker "~/.rch/bin/rch-wkr --version"
```

**If rch-wkr is not found:**
```bash
# Redeploy to worker
rch fleet deploy --worker <worker-id> --force
```

**If rch-wkr is not responding:**
```bash
# Check for zombie processes
ssh worker "ps aux | grep rch-wkr"

# Kill stale processes
ssh worker "pkill -9 rch-wkr"
```

### 4. Resource Issues

**Disk full:**
```bash
# Check disk space
ssh worker "df -h"

# Clean RCH cache
ssh worker "rm -rf /tmp/rch/*/hash_*"

# Or use built-in cleanup
rch worker clean <worker-id> --max-age-hours=1
```

**Memory exhausted:**
```bash
# Check memory
ssh worker "free -m"

# Find memory hogs
ssh worker "ps aux --sort=-%mem | head -10"

# Kill runaway cargo processes
ssh worker "pkill -9 cargo"
```

**CPU overloaded:**
```bash
# Check load
ssh worker "uptime"

# If load > 2x CPU count, wait or kill processes
ssh worker "ps aux --sort=-%cpu | head -10"
```

### 5. Reset Circuit Breaker

Once the underlying issue is fixed:

```bash
# Check current circuit state
rch status --circuits

# Manual reset (forces immediate probe)
rch worker reset <worker-id>

# Verify recovery
rch workers probe <worker-id>
```

### 6. Verify Recovery

```bash
# Full verification
rch fleet verify --worker <worker-id>

# Test with a build
rch worker test <worker-id> --project /path/to/test/project
```

## Recovery Procedures by Scenario

### Scenario: Worker VM Rebooted

```bash
# 1. Wait for VM to come back (check with ping)
ping worker-host

# 2. Test SSH
ssh worker "echo OK"

# 3. Reset circuit breaker
rch worker reset <worker-id>

# 4. Verify
rch workers probe <worker-id>
```

### Scenario: Network Partition Resolved

```bash
# 1. Verify connectivity
nc -zv worker-host 22

# 2. Reset circuit breaker
rch worker reset <worker-id>

# 3. Run health check
rch workers probe --all
```

### Scenario: Worker Disk Filled Up

```bash
# 1. Clean caches
ssh worker "rm -rf /tmp/rch/*"

# 2. Verify disk space
ssh worker "df -h"

# 3. Reset and verify
rch worker reset <worker-id>
rch fleet verify --worker <worker-id>
```

### Scenario: Worker Agent Corrupted

```bash
# 1. Remove old installation
ssh worker "rm -rf ~/.rch"

# 2. Redeploy
rch fleet deploy --worker <worker-id> --force

# 3. Verify
rch fleet verify --worker <worker-id>
```

## Prevention

### Set Up Monitoring

```bash
# Add to crontab for regular checks
*/5 * * * * rch workers probe --all --quiet || notify-admin
```

### Configure Alerts

```toml
# ~/.config/rch/config.toml
[alerts]
webhook_url = "https://hooks.slack.com/..."
alert_on_circuit_open = true
alert_on_worker_degraded = true
```

### Regular Maintenance

```bash
# Weekly cache cleanup
rch worker clean --all --max-age-hours=168

# Monthly worker verification
rch fleet verify
```

## Escalation

If worker cannot be recovered:

1. **Temporary:** Drain the worker to prevent routing:
   ```bash
   rch fleet drain <worker-id>
   ```

2. **Investigate:** Access worker console or contact infrastructure team

3. **Replace:** If hardware/VM issue, provision new worker and add to fleet

4. **Document:** Record incident and resolution for future reference
