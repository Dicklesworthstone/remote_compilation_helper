# Troubleshooting

**First step**: `rch doctor --verbose`

## Symptom Index

| Error Message | Jump To |
|---------------|---------|
| "Permission denied (publickey)" | [SSH Issues](#ssh-issues) |
| "Connection refused" | [SSH Issues](#ssh-issues) |
| "Host key verification failed" | [SSH Issues](#ssh-issues) |
| "No config file" / "Config not found" | [Configuration](#configuration) |
| "Invalid TOML" | [Configuration](#configuration) |
| "Daemon not running" / socket errors | [Daemon](#daemon) |
| "Hook not triggering" | [Hook Issues](#hook-issues) |
| "No workers available" | [Worker Issues](#worker-issues) |
| "Transfer failed" | [Worker Issues](#worker-issues) |
| Compilation slower than local | [Performance](#performance) |

---

## Installation

```bash
# Rust nightly not installed
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
rustup install nightly && rustup default nightly

# Edition 2024 error → need recent nightly
rustup update nightly
rustc +nightly --version  # Need 1.82+

# Missing rsync/zstd
sudo apt install rsync zstd      # Debian/Ubuntu
brew install rsync zstd          # macOS
sudo dnf install rsync zstd      # Fedora
```

---

## SSH Issues

| Symptom | Diagnose | Fix |
|---------|----------|-----|
| Permission denied | `ssh -vvv -i key user@host` | `chmod 600 ~/.ssh/*`; check key path |
| Connection refused | `nc -zv host 22` | Check firewall (`ssh worker "sudo ufw status"`), SSH service |
| Host key failed | — | `ssh-keyscan host >> ~/.ssh/known_hosts` |
| Agent not running | `echo $SSH_AUTH_SOCK` | `eval $(ssh-agent) && ssh-add` |
| Key not found | `ls -la ~/.ssh/` | Verify key file exists at configured path |

**Full SSH debug**: `ssh -vvv -i ~/.ssh/key user@host "echo ok"`

---

## Configuration

```bash
# No config directory
mkdir -p ~/.config/rch

# Create minimal config
cat > ~/.config/rch/workers.toml << 'EOF'
[[workers]]
id = "worker1"
host = "192.168.1.100"
user = "ubuntu"
identity_file = "~/.ssh/id_ed25519"
total_slots = 8
priority = 100
EOF

# Or use interactive wizard
rch init

# Validate syntax
rch config check
```

**Common TOML mistakes**:
- Missing quotes around string values
- `[workers]` instead of `[[workers]]`
- Typos in field names

---

## Daemon

| Symptom | Check | Fix |
|---------|-------|-----|
| Not running | `pgrep rchd` | `rchd &` or `systemctl --user start rchd` |
| Socket missing | `ls /tmp/rch.sock` | Start daemon |
| Socket stale | Socket exists but daemon dead | `rm /tmp/rch.sock && rchd` |
| Permission denied | `ls -la /tmp/rch.sock` | Check socket permissions |
| Crashes | `rchd --foreground --verbose` | Check logs for error |

**Daemon logs**: `journalctl --user -u rchd -f`

**Deep debug**: `rchd --foreground --log-level=debug`

---

## Hook Issues

| Symptom | Check | Fix |
|---------|-------|-----|
| Not registered | `cat ~/.claude/settings.json \| jq '.hooks.PreToolUse'` | `rch hook install` |
| Binary not found | `which rch` | Ensure rch is in PATH |
| Returns error | `echo '{"tool":"Bash","input":{"command":"cargo check"}}' \| rch hook` | Reinstall rch |
| Not intercepting | `rch classify "cargo build"` | Verify command is supported |

**Commands never intercepted** (by design):
- `bun install/add/remove` (package management)
- `bun run/dev/build` (local execution)
- Piped: `cargo build | tee log`
- Background: `cargo build &`

**Test hook directly**:
```bash
echo '{"tool":"Bash","input":{"command":"cargo build"}}' | rch hook
# Expect: {"allow":true,"output":"..."}

RCH_DRY_RUN=1 cargo check  # Logs decision without remote execution
```

---

## Worker Issues

| Symptom | Check | Fix |
|---------|-------|-----|
| No workers | `rch workers status` | Add workers to config |
| No slots | `rch workers list --verbose` | Wait or add more workers |
| Can't connect | `ssh -i key user@host "echo ok"` | Fix SSH (see above) |
| Missing toolchain | `ssh worker "which rustc bun"` | Install on worker |
| Transfer fails | `rsync -avz --dry-run ./src/ worker:/tmp/t/` | Check disk space, rsync version |

**Install Rust on worker**: `ssh worker "curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh"`

**Check worker disk**: `ssh worker "df -h /tmp"`

**Check rsync compatibility**: `rsync --version` and `ssh worker "rsync --version"`

---

## Performance

| Symptom | Likely Cause | Fix |
|---------|--------------|-----|
| Slower than local | Project too small (<2s compile) | RCH overhead ~100-500ms; only helps for longer builds |
| High transfer time | Large project / slow network | Check `.rchignore` excludes `target/`, `node_modules/` |
| Worker slow | High load | `ssh worker "uptime; top -bn1 \| head -20"` → try different worker |

**Profile transfer**: `time rsync -avz ./src/ worker:/tmp/test/`

**Check network**: `ping -c 5 worker`

**Debug transfer**: `RCH_LOG=debug cargo build 2>&1 | grep transfer`

---

## Debug Mode

```bash
export RCH_LOG=debug    # or trace for maximum detail
cargo build             # Logs show hook decisions

# Levels: error, warn, info, debug, trace
```

---

## Getting Help

```bash
rch --version              # Show version
rch --help                 # General help
rch doctor --help          # Doctor subcommand help
rch workers --help         # Workers subcommand help
```

## Generate Diagnostic Report

```bash
rch doctor --json > diagnostic.json
```
