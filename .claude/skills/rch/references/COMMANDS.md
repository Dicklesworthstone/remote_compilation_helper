# Command Reference

## Core Commands

| Command | Purpose | Common Flags |
|---------|---------|--------------|
| `rch doctor` | Diagnose + safe auto-fix | `--fix`, `--dry-run`, `--verbose`, `--reliability`, `--json` |
| `rch check` | Quick yes/no health (exit 0/1/2) | `--json` |
| `rch status` | System status overview | `--workers`, `--jobs`, `--fleet`, `--remediation`, `--json` |
| `rch admit "<cmd>"` | Will this command offload? + reason code | `--json` |
| `rch diagnose "<cmd>"` | Classify + offload decision + daemon health | `--dry-run`, `--json` |
| `rch exec -- <cmd>` | Explicitly offload one build command | (env: `RCH_REQUIRE_REMOTE`, `RCH_FORCE_REMOTE`) |
| `rch self-test` | Full end-to-end verification | `--worker <id>`, `--all` |
| `rch workers probe` | Test workers | `--all`, `-v`, `worker_id` |
| `rch workers list` | List workers | `--capabilities`, `--json` |
| `rch workers discover` | Auto-find workers | `--from-ssh-config`, `--dry-run` |
| `rch workers drain` / `enable` / `disable` | Worker lifecycle (drain reversible; disable permanent) | `-y`, `--reason`, `--drain` |
| `rch hook install` | Setup Claude hook | `--force` |
| `rch hook status` / `test` | Check / self-test the hook | — |
| `rch config show` | Show config | `--sources` |
| `rch config validate` / `lint` / `doctor` | Validate config | `--json` |

## Daemon Commands

Use the managed lifecycle — it cleans up the socket and self-heals with the hook.
Never `rm` the socket or `kill` "stale" processes by hand.

```bash
# Lifecycle
rch daemon start                 # Start (resolves + cleans the socket for you)
rch daemon stop                  # Stop (prompts if builds are active)
rch daemon restart               # Stale/refused socket → restart, don't rm
rch daemon status                # Is it up? (add --json for the resolved socket path)
rch daemon reload                # Reload config without restart

# OS service managers (optional)
systemctl --user start rchd      # Systemd (Linux)
launchctl load ~/Library/LaunchAgents/com.rch.daemon.plist  # macOS

# Logs (rotated by default)
rch daemon logs -n 200
journalctl --user -u rchd -f     # Linux service logs
```

## Debug Commands

```bash
# Verbose diagnostics
rch doctor --verbose

# Export diagnostics
rch doctor --json > diagnostic.json

# Test the hook
rch hook test

# Dry run (shows the decision without remote execution)
rch diagnose "cargo check" --dry-run

# Debug logging
RCH_LOG_LEVEL=debug rch diagnose "cargo build"
RCH_LOG_LEVEL=trace rch diagnose "cargo build"  # Maximum detail
```

## Worker Probe Output

```bash
rch workers probe worker1 --verbose
```

Shows:
- SSH connectivity (port 22)
- Detected toolchains (rustc, cargo, bun, gcc, clang)
- Disk space (/tmp)
- System load

## Environment Variables

| Variable | Purpose | Example |
|----------|---------|---------|
| `RCH_LOG_LEVEL` | Log level | `debug`, `trace`, `info` |
| `RCH_REQUIRE_REMOTE` | Proof mode: fail-closed, refuse local fallback | `1` |
| `RCH_FORCE_REMOTE` | Always attempt offload, still fail-open | `1` |
| `RCH_NO_SELF_HEALING` | Disable hook/daemon self-healing for this run | `1` |
| `RCH_QUEUE_WHEN_BUSY` | Wait for a busy worker instead of local fallback | `1` (default) |
| `RCH_STATE_HOME` | Incident/proof state dir | `~/.local/state/rch` |
| `RCH_CONFIG_DIR` | Config location | `~/.config/rch` |
| `NO_COLOR` / `FORCE_COLOR` | ANSI color behavior | `1` |

## Config Files

| File | Purpose |
|------|---------|
| `~/.config/rch/workers.toml` | Worker definitions |
| `~/.config/rch/config.toml` | User config (general/compilation/transfer/selection/self_healing) |
| `.rch/config.toml` (project) | Per-project overrides |
| `.rchignore` (project) | Optional transfer excludes |
