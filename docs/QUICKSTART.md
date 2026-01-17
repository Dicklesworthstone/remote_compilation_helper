# RCH Quick Start Guide

Get remote compilation working in 5 minutes.

## Prerequisites

- macOS or Linux workstation
- SSH access to a build server (cloud VM, powerful desktop, etc.)
- Rust toolchain installed on both machines
- Claude Code or another supported AI coding agent

Need help setting up SSH? See the [SSH setup guide](./guides/ssh-setup.md).

## 1. Install RCH (30 seconds)

**From Source (Recommended):**

```bash
git clone https://github.com/Dicklesworthstone/remote_compilation_helper.git
cd remote_compilation_helper
cargo build --release
cp target/release/rch target/release/rchd ~/.local/bin/
```

**Or with the installer:**

```bash
curl -fsSL https://raw.githubusercontent.com/Dicklesworthstone/remote_compilation_helper/main/install.sh | bash
```

**Or with Cargo:**

```bash
cargo install --git https://github.com/Dicklesworthstone/remote_compilation_helper.git
```

## 2. Add a Worker (60 seconds)

Create the worker configuration:

```bash
mkdir -p ~/.config/rch
cat > ~/.config/rch/workers.toml << 'EOF'
[[workers]]
id = "my-server"
host = "your-server-ip-or-hostname"
user = "your-username"
identity_file = "~/.ssh/id_rsa"
total_slots = 16  # Number of CPU cores available
priority = 100
EOF
```

Test the connection:

```bash
# Verify SSH works
ssh -i ~/.ssh/id_rsa your-username@your-server-ip-or-hostname "echo OK"

# Install RCH on the worker
rch workers install my-server
```

## 3. Install Claude Code Hook (30 seconds)

```bash
# Auto-detect and install hooks
rch hook install

# Or manually for Claude Code
rch hook install --agent=claude-code
```

Verify the hook is installed:

```bash
rch hook status
```

## 4. Start the Daemon (10 seconds)

```bash
# Start in foreground (see logs)
rchd

# Or start in background
rch daemon start

# Check status
rch daemon status
```

## 5. Build Something!

```bash
# In any Rust project with Claude Code:
claude

# Inside Claude Code session:
> cargo build --release     # Automatically offloaded!
> cargo test               # Tests run on worker
> bun test                 # Bun tests on worker too
```

## What Just Happened?

1. You typed `cargo build`
2. RCH's hook intercepted the command
3. The 5-tier classifier detected it's a compilation command (< 1ms)
4. Your code was synced to the worker via rsync + zstd
5. The build ran on the fast worker machine
6. Results were synced back to your local `target/` directory
7. Output appeared in your terminal as if it ran locally

The agent never knew compilation ran remotely!

## Verify It's Working

```bash
# Check worker connectivity
rch workers probe --all

# See active compilations
rch status --jobs

# View worker health
rch status --workers
```

## Next Steps

- [Configure multiple workers](./guides/workers.md)
- [Customize classification rules](./architecture/classifier.md)
- [Set up monitoring](./guides/monitoring.md)
- [Troubleshoot issues](./TROUBLESHOOTING.md)

## Performance Tips

| Tip | Why It Matters |
|-----|----------------|
| Use SSD workers | Build artifact I/O is fast |
| Low-latency network | Matters more than bandwidth for small syncs |
| More cores = faster | Rust parallelizes well |
| First sync is slow | Initial full copy; subsequent syncs are incremental |

## Common Issues (Quick Reference)

| Issue | Quick Fix |
|-------|-----------|
| "Connection refused" | Start daemon: `rchd` |
| "No workers available" | Add worker in `~/.config/rch/workers.toml` |
| Build runs locally | Check hooks: `rch hook status` |
| Slow first build | Normal - initial sync transfers entire project |
| SSH permission denied | Check SSH key: `ssh -i ~/.ssh/key user@host` |

For detailed troubleshooting, see [TROUBLESHOOTING.md](./TROUBLESHOOTING.md).

## Environment Variables

| Variable | Purpose | Default |
|----------|---------|---------|
| `RCH_ENABLED` | Enable/disable RCH | `true` |
| `RCH_LOCAL_ONLY` | Force local execution | `false` |
| `RCH_VERBOSE` | Enable verbose logging | `false` |
| `RCH_WORKER` | Force specific worker | (auto-select) |

## Uninstall

```bash
rch hook uninstall
rch daemon stop
rm ~/.local/bin/rch ~/.local/bin/rchd
rm -rf ~/.config/rch
```
