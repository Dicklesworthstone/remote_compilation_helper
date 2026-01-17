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
# Graceful restart (waits for active builds)
rch daemon restart

# Force restart (kills active builds)
rch daemon restart --force

# Check status
rch daemon status
```

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

Use this when daemon is hung or unresponsive.

```bash
# 1. Try graceful first
rch daemon restart

# 2. If that fails, force restart
rch daemon restart --force

# 3. If still stuck, kill manually
pkill -9 rchd
rm /tmp/rch.sock  # Clean up socket file

# 4. Start fresh
rchd &
# Or
rch daemon start
```

### Debug Mode Restart

For troubleshooting issues:

```bash
# 1. Stop daemon
rch daemon stop

# 2. Start in foreground with debug logging
RUST_LOG=debug rchd

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

# Restart to apply
rch daemon restart

# Verify new config is loaded
rch config show
```

### After Adding/Removing Workers

```bash
# Edit workers file
vim ~/.config/rch/workers.toml

# Restart daemon
rch daemon restart

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

# If builds are stuck
rch daemon restart --force

# Verify clean state
rch status --jobs
```

## Troubleshooting Restart Failures

### Socket File Already Exists

```
Error: Address already in use
```

**Solution:**
```bash
# Check if daemon is actually running
pgrep rchd

# If not running, remove stale socket
rm /tmp/rch.sock

# Start daemon
rch daemon start
```

### Permission Denied

```
Error: Permission denied: /tmp/rch.sock
```

**Solution:**
```bash
# Check socket ownership
ls -la /tmp/rch.sock

# Remove if owned by different user
sudo rm /tmp/rch.sock

# Start as your user
rch daemon start
```

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

# 3. Verify API is responding
curl -s --unix-socket /tmp/rch.sock http://localhost/status | jq

# 4. Test a build
cd /path/to/test/project
cargo check
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
