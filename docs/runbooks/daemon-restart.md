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
# Graceful restart (prompts if builds are active, then waits for them)
rch daemon restart

# Non-interactive restart (skips the active-build prompt; terminates them)
rch daemon restart -y

# Check status
rch daemon status
```

`rch daemon restart` reclaims and replaces a stale/refused socket itself — you
never need to `rm` the socket or `pkill` the daemon by hand.

## Step-by-Step Procedures

### Graceful Restart

Use this for configuration changes or routine maintenance.

```bash
# 1. Check current status
rch daemon status

# 2. See active builds
rch status --jobs

# 3. Graceful restart (waits up to 120s for builds)
rch daemon restart

# 4. Verify restart
rch daemon status
rch status --workers
```

### Force Restart

Use this when the daemon is hung or unresponsive.

```bash
# 1. Try graceful first
rch daemon restart

# 2. If builds are wedged, restart non-interactively (replaces a stale socket for you)
rch daemon restart -y

# 3. If the managed restart cannot bind, stop then start (still socket-safe)
rch daemon stop -y
rch daemon start

# 4. Confirm
rch daemon status
```

`rch daemon start` / `restart` detect and replace a stale socket, so manual
`pkill -9 rchd` + `rm <socket>` is a genuine last resort only if the managed
commands fail — and it terminates whatever the daemon was doing with no audit.
If you must, get operator confirmation, then `rch daemon stop -y` first.

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

# Only if the daemon itself is wedged:
rch daemon restart -y

# Verify clean state
rch status --jobs
```

## Troubleshooting Restart Failures

### Socket File Already Exists

```
Error: Address already in use
```

**Solution:** `rch daemon start`/`restart` detects the stale socket and replaces
it — let it, rather than `rm`-ing the socket yourself.
```bash
rch daemon status     # confirms whether a daemon is actually live
rch daemon restart    # reclaims and replaces the stale socket, then starts clean
```

### Permission Denied

```
Error: Permission denied: <socket path>
```

**Solution:** this usually means a socket left by another user/run. Let the
managed restart reclaim it, and use `rch doctor --fix` for permission issues:
```bash
rch --json daemon status    # shows the resolved socket path (do not hardcode it)
rch daemon restart          # reclaims/replaces the socket safely
rch doctor --fix            # corrects fixable permission problems
```
Only if a foreign-owned socket truly blocks startup, and with operator intent,
remove that specific path after confirming no live daemon owns it.

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
# 1. Verify daemon is running
rch daemon status

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

# Restart via systemd
systemctl --user restart rchd

# View logs
journalctl --user -u rchd -f
```

## State Preservation

The daemon maintains state in memory. On restart:
- Worker health states reset to "unknown" (re-probed on first use)
- Circuit breakers reset to "closed"
- Build history is preserved (if persisted)
- Active builds are terminated (graceful) or killed (force)

To preserve state across restarts:
```toml
# ~/.config/rch/config.toml
[daemon]
persist_state = true
state_file = "/tmp/rch.state"
```
