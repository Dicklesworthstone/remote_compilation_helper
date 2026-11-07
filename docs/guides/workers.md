# Worker Setup Guide

This guide covers setting up and managing worker machines for RCH.
If you are new to the concept, start with `docs/guides/worker-infrastructure.md`.

## Prerequisites

Workers need:
- Linux (Ubuntu 22.04+ recommended, or any modern distro)
- SSH access with key-based authentication
- Sufficient CPU cores (8+ recommended)
- Sufficient RAM (16GB+ recommended)
- Fast storage (NVMe SSD recommended)
- Network connectivity to workstation

## Adding Your First Worker

### 1. Prepare the Worker Machine

On the worker machine:

```bash
# Ensure SSH is running
sudo systemctl enable ssh
sudo systemctl start ssh

# Create a dedicated user (optional but recommended)
sudo useradd -m -s /bin/bash rch-worker
sudo mkdir -p /home/rch-worker/.ssh
sudo chmod 700 /home/rch-worker/.ssh
```

### 2. Set Up SSH Key Access

On your workstation:

```bash
# Generate a dedicated key (if you don't have one)
ssh-keygen -t ed25519 -f ~/.ssh/rch_worker -C "rch-worker-access"

# Copy to worker
ssh-copy-id -i ~/.ssh/rch_worker.pub user@worker-host

# Test connection
ssh -i ~/.ssh/rch_worker user@worker-host "echo OK"
```

### 3. Configure in RCH

```bash
# Create workers config
mkdir -p ~/.config/rch
cat >> ~/.config/rch/workers.toml << 'EOF'
[[workers]]
id = "my-first-worker"
host = "worker-host-or-ip"
user = "your-username"
identity_file = "~/.ssh/rch_worker"
total_slots = 8  # Adjust to your CPU core count
priority = 100
EOF
```

### 4. Deploy RCH to Worker

```bash
# Install rch-wkr on the worker
rch fleet deploy --worker my-first-worker

# Verify installation
rch fleet verify --worker my-first-worker
```

### 5. Verify Operation

```bash
# Test connectivity
rch workers probe my-first-worker

# Run a test build
cd /path/to/rust/project
cargo build
```

## Worker Configuration Options

### Basic Configuration

```toml
[[workers]]
id = "worker1"           # Unique identifier
host = "10.0.1.10"       # Hostname or IP address
user = "builder"         # SSH username
identity_file = "~/.ssh/rch_key"  # SSH private key
total_slots = 16         # Number of parallel build slots
priority = 100           # Selection priority (higher = preferred)
```

### Advanced Configuration

```toml
[[workers]]
id = "worker1"
host = "worker1.internal"
user = "builder"
identity_file = "~/.ssh/rch_key"
total_slots = 32
priority = 100

# Optional settings
port = 22                # SSH port (default: 22)
tags = ["fast", "ssd"]   # Tags for filtering
enabled = true           # Enable/disable without removing

# Environment overrides on this worker
[workers.environment]
CARGO_BUILD_JOBS = "16"
RUSTFLAGS = "-C target-cpu=native"
```

### SSH via Bastion/Jump Host

If workers are behind a bastion host, configure in `~/.ssh/config`:

```
# ~/.ssh/config
Host rch-bastion
    HostName bastion.example.com
    User admin
    IdentityFile ~/.ssh/bastion_key

Host rch-worker-*
    ProxyJump rch-bastion
    User builder
    IdentityFile ~/.ssh/rch_key

Host rch-worker-1
    HostName 10.0.1.10

Host rch-worker-2
    HostName 10.0.1.11
```

Then in workers.toml:
```toml
[[workers]]
id = "worker1"
host = "rch-worker-1"  # SSH config alias
total_slots = 16
```

## Installing Required Tools on Workers

Workers need these tools installed:

```bash
# On each worker (run via SSH or directly)

# Install Rust (nightly)
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
rustup default nightly
rustup update

# Install build tools
sudo apt update
sudo apt install -y build-essential rsync zstd

# For C/C++ projects
sudo apt install -y gcc g++ clang

# For Bun/TypeScript projects
curl -fsSL https://bun.sh/install | bash
```

`rch fleet deploy` automates the RCH side of this: it installs `rch-wkr` and
syncs the Rust toolchain (pass `--no-toolchain` to skip that). It does not
install system packages, so run the commands above yourself.
```bash
rch fleet deploy --worker my-worker
```

## Managing Multiple Workers

### Discovery

Find potential workers from SSH config:

```bash
# Discover from ~/.ssh/config
rch workers discover

# Add discovered workers
rch workers discover --add
```

### Listing Workers

```bash
# List all configured workers
rch workers list

# Show detailed status
rch workers list --verbose
```

### Probing Workers

```bash
# Test all workers
rch workers probe --all

# Test specific worker
rch workers probe worker1 --verbose
```

### Cargo on Dual-Role Workers

A worker can also run its own agents with `rch shim install` enabled. Once RCH
has placed a command on that worker, its child environment supplies both
`RCH_CARGO_WRAPPER_BYPASS=1` and `RCH_CARGO_WRAPPER_ORIGIN=rch`. This applies to
SSH jobs, nested scripts and `rch-wkr execute`, including disk-supervised jobs.
The shim continues to reject a caller-set bypass without the managed origin
when remote execution is required.

An explicit Cargo selector such as `cargo +nightly build` takes precedence over
leading `RUSTUP_TOOLCHAIN` assignments. RCH consumes that selector when it
constructs the selected Rustup runner, preserving the remaining Cargo arguments
so direct toolchain Cargo does not receive a proxy-only `+nightly` argument.
Cargo Zig builds use the same Rust toolchain admission checks. If environment
files, split strings or nested command wrappers make the toolchain unresolved,
RCH refuses Rust admission instead of choosing an ambient toolchain. Clearing
`RUSTUP_TOOLCHAIN` also requires a later explicit pin for this admission path.

Refresh the worker execution checks before sending builds:

```bash
rch --json workers capabilities --refresh --command 'cargo test'
```

On the worker, `rch-wkr capabilities` runs `cargo --version` through PATH and,
when rustup is available, directly invokes the Cargo reported by
`rustup which cargo`. Both use the same managed child environment as worker
execution. The checks share a five-second deadline and a 16 KiB output limit.
A failed check clears the Rust capability and reports its cause in
`probe_warnings`; other runtimes and worker connectivity remain independently
usable. Pinned-toolchain admission also checks both Cargo entry points.

Selection and slot reservation use the same execution requirements. Before
creating a build owner, the daemon rechecks runtime availability, required
named tools, exact Node/Bun versions, Rust components and toolchain versions
against the current capability snapshot. A requested toolchain also requires
a fresh successful preflight. A refresh that invalidates one of these facts
causes selection to retry before it spends slots; existing builds retain their
ownership, and jobs without the failed requirement remain eligible.

Completed toolchain checks belong to the worker connection and lifecycle that
produced them. Disabling a worker, replacing its endpoint or losing its shared
transport invalidates both successful and failed checks. After recovery, RCH
checks the requested toolchain again before reserving slots; reconnecting alone
cannot reuse a pre-outage success or keep a repaired toolchain excluded.

For `worker Cargo execution check failed`, inspect the reported PATH or
toolchain failure, update the dispatcher and worker binaries together, and
repair the worker's Cargo/shim installation as needed. Re-run the capability
refresh afterward. Do not export bypass markers globally in an agent shell.

### Updating Workers

```bash
# Update all workers
rch fleet deploy

# Update specific worker
rch fleet deploy --worker worker1

# Force reinstall
rch fleet deploy --worker worker1 --force
```

## Worker Maintenance

### Draining a Worker

Before maintenance, drain the worker to stop new builds:

```bash
# Start draining (waits for active builds)
rch fleet drain worker1

# Check drain status
rch status --workers

# After maintenance, re-enable
rch workers enable worker1
```

### Cleaning Worker Cache

```bash
# Clean old project caches
rch worker clean worker1 --max-age-hours=24

# Clean all workers
rch worker clean --all --max-age-hours=168
```

### Removing a Worker

```bash
# Disable first
rch workers disable worker1

# Remove from config
vim ~/.config/rch/workers.toml
# Delete the [[workers]] block

# Restart daemon
rch daemon restart
```

## Performance Tuning

### Slot Calculation

```
Recommended: total_slots = CPU_cores × 0.8
```

This leaves headroom for system processes and rsync.

### Network Optimization

For workers on slow networks:

```toml
[[workers]]
id = "remote-worker"
# ... other config ...

# Increase timeouts
[workers.ssh]
connect_timeout_secs = 30
command_timeout_secs = 600

# Higher compression for slow links
[workers.transfer]
compression_level = 9
```

### SSD vs HDD

Workers with SSDs are significantly faster. Mark them with tags:

```toml
[[workers]]
id = "fast-worker"
tags = ["ssd", "nvme"]

[[workers]]
id = "slow-worker"
tags = ["hdd"]
```

Then prefer SSD workers:
```toml
# ~/.config/rch/config.toml
[selection]
preferred_tags = ["ssd"]
```

## Monitoring Workers

### Health Checks

The daemon automatically checks worker health every 30 seconds.

```bash
# View health status
rch status --workers

# View circuit breaker states
rch status --circuits
```

### Logs

```bash
# View daemon logs (includes worker events)
rch daemon logs

# Filter to specific worker
rch daemon logs | grep worker1
```

### Statistics

```bash
# View build statistics per worker
rch status --stats

# Detailed worker stats
rch workers stats worker1
```

## Troubleshooting

### Worker Not Accepting Builds

```bash
# Check status
rch status --workers

# If circuit is open
rch worker reset worker1

# If degraded, check latency
rch workers probe worker1 --verbose
```

### SSH Connection Failures

```bash
# Test SSH directly
ssh -v -i ~/.ssh/rch_key user@worker "echo OK"

# Check known_hosts
ssh-keygen -R worker-host
ssh -i ~/.ssh/rch_key user@worker "echo OK"
```

### Disk Space Issues

```bash
# Check worker disk
ssh worker "df -h"

# Clean cache
rch worker clean worker1 --max-age-hours=1
```

See [Worker Recovery Runbook](../runbooks/worker-recovery.md) for detailed troubleshooting.
