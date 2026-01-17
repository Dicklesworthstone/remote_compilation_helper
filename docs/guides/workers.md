# Worker Setup Guide

This guide covers setting up and managing worker machines for RCH.

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

You can automate this with:
```bash
rch fleet deploy --worker my-worker --install-deps
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
