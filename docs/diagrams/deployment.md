# Deployment Topology Diagram

## Production Deployment

Typical deployment with multiple AI agents and remote workers:

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                        WORKSTATION (macOS/Linux)                            │
│                                                                             │
│  ┌───────────────────────────────────────────────────────────────────────┐  │
│  │                      AI Coding Agents                                 │  │
│  │                                                                       │  │
│  │  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐                │  │
│  │  │ Claude Code  │  │ Claude Code  │  │ Claude Code  │  ...           │  │
│  │  │  Session 1   │  │  Session 2   │  │  Session N   │                │  │
│  │  │              │  │              │  │              │                │  │
│  │  │ Project A    │  │ Project B    │  │ Project A    │                │  │
│  │  │ tmux:0       │  │ tmux:1       │  │ tmux:2       │                │  │
│  │  └──────┬───────┘  └──────┬───────┘  └──────┬───────┘                │  │
│  │         │                 │                 │                         │  │
│  └─────────┼─────────────────┼─────────────────┼─────────────────────────┘  │
│            │                 │                 │                            │
│            │    PreToolUse   │    PreToolUse   │    PreToolUse              │
│            │    hook         │    hook         │    hook                    │
│            ▼                 ▼                 ▼                            │
│  ┌───────────────────────────────────────────────────────────────────────┐  │
│  │                         rch (Hook Binary)                             │  │
│  │                                                                       │  │
│  │  • Receives JSON from stdin                                           │  │
│  │  • 5-tier command classification                                      │  │
│  │  • Communicates with daemon via Unix socket                           │  │
│  │  • Orchestrates rsync transfers                                       │  │
│  │                                                                       │  │
│  └───────────────────────────────┬───────────────────────────────────────┘  │
│                                  │                                          │
│                                  │ Unix Socket                              │
│                                  │ /tmp/rch.sock                            │
│                                  ▼                                          │
│  ┌───────────────────────────────────────────────────────────────────────┐  │
│  │                        rchd (Local Daemon)                            │  │
│  │                                                                       │  │
│  │  • Worker pool management                  • Build deduplication      │  │
│  │  • Selection algorithm                     • Statistics tracking      │  │
│  │  • Health monitoring (30s heartbeat)       • API server               │  │
│  │  • Circuit breaker per worker              • SSH connection pool      │  │
│  │                                                                       │  │
│  │  Config: ~/.config/rch/config.toml                                    │  │
│  │  Workers: ~/.config/rch/workers.toml                                  │  │
│  │  State: /tmp/rch.state                                                │  │
│  │                                                                       │  │
│  └───────────────────────────────────────────────────────────────────────┘  │
│                                                                             │
│  Ports: None (local Unix socket only)                                       │
│  User: Current user                                                         │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
                                    │
                                    │ SSH (port 22)
                                    │ ControlMaster multiplexing
                                    │
              ┌─────────────────────┼─────────────────────┐
              │                     │                     │
              ▼                     ▼                     ▼
┌─────────────────────┐  ┌─────────────────────┐  ┌─────────────────────┐
│   Worker 1 (css)    │  │   Worker 2 (fra)    │  │   Worker N (...)    │
│                     │  │                     │  │                     │
│ Cloud: AWS/GCP/...  │  │ Cloud: Hetzner/...  │  │ On-prem / Desktop   │
│ Region: us-east-1   │  │ Region: eu-central  │  │ Location: Office    │
│                     │  │                     │  │                     │
│ ┌─────────────────┐ │  │ ┌─────────────────┐ │  │ ┌─────────────────┐ │
│ │    rch-wkr      │ │  │ │    rch-wkr      │ │  │ │    rch-wkr      │ │
│ │                 │ │  │ │                 │ │  │ │                 │ │
│ │ • Executor      │ │  │ │ • Executor      │ │  │ │ • Executor      │ │
│ │ • Cache manager │ │  │ │ • Cache manager │ │  │ │ • Cache manager │ │
│ │ • Health report │ │  │ │ • Health report │ │  │ │ • Health report │ │
│ └─────────────────┘ │  │ └─────────────────┘ │  │ └─────────────────┘ │
│                     │  │                     │  │                     │
│ Specs:              │  │ Specs:              │  │ Specs:              │
│ • 32 cores          │  │ • 16 cores          │  │ • 8 cores           │
│ • 64GB RAM          │  │ • 32GB RAM          │  │ • 32GB RAM          │
│ • NVMe SSD          │  │ • NVMe SSD          │  │ • NVMe SSD          │
│                     │  │                     │  │                     │
│ Toolchains:         │  │ Toolchains:         │  │ Toolchains:         │
│ • Rust nightly      │  │ • Rust nightly      │  │ • Rust nightly      │
│ • GCC 13            │  │ • GCC 13            │  │ • GCC 13            │
│ • Clang 17          │  │ • Clang 17          │  │ • Clang 17          │
│ • Bun 1.x           │  │ • Bun 1.x           │  │ • Bun 1.x           │
│                     │  │                     │  │                     │
│ Cache:              │  │ Cache:              │  │ Cache:              │
│ /tmp/rch/           │  │ /tmp/rch/           │  │ /tmp/rch/           │
│  └─ proj_abc123/    │  │  └─ proj_def456/    │  │  └─ proj_abc123/    │
│                     │  │                     │  │                     │
│ Ports: 22 (SSH)     │  │ Ports: 22 (SSH)     │  │ Ports: 22 (SSH)     │
│                     │  │                     │  │                     │
└─────────────────────┘  └─────────────────────┘  └─────────────────────┘
```

## Configuration Files

### Workstation Configuration

```
~/.config/rch/
├── config.toml         # Global RCH settings
└── workers.toml        # Worker fleet definition

~/.claude/              # Claude Code installation
├── settings.json       # May contain hook configuration
└── hooks/
    └── PreToolUse.bash # RCH hook script
```

### Worker File Layout

```
~/.rch/
├── bin/
│   └── rch-wkr         # Worker binary
├── config.toml         # Worker-local settings (if any)
└── backups/            # Previous versions for rollback
    ├── 20260115_120000/
    └── 20260114_090000/

/tmp/rch/               # Build cache (ephemeral)
├── project_abc/
│   └── hash_123456/    # Project snapshot
│       ├── Cargo.toml
│       ├── src/
│       └── target/     # Build artifacts
└── project_def/
    └── hash_789012/
```

## Network Requirements

### Outbound from Workstation

| Destination | Port | Protocol | Purpose |
|-------------|------|----------|---------|
| Workers | 22 | SSH | Command execution, rsync |
| GitHub | 443 | HTTPS | Self-update checks (optional) |

### Inbound to Workers

| Source | Port | Protocol | Purpose |
|--------|------|----------|---------|
| Workstation | 22 | SSH | All RCH communication |

### Firewall Rules

```bash
# On workstation (usually not needed, outbound allowed)
# (No changes required)

# On workers
sudo ufw allow from <workstation-ip> to any port 22
```

## Scaling Considerations

### Horizontal Scaling

Add more workers to increase total compilation capacity:

```toml
# ~/.config/rch/workers.toml

[[workers]]
id = "worker-1"
host = "10.0.1.10"
total_slots = 16

[[workers]]
id = "worker-2"
host = "10.0.1.11"
total_slots = 32

[[workers]]
id = "worker-3"
host = "10.0.1.12"
total_slots = 16

# Total capacity: 64 slots
```

### Slot Calculation

```
Recommended slots = CPU cores × 0.8
```

This leaves headroom for system processes and rsync transfers.

### Geographic Distribution

For global teams, deploy workers in multiple regions:

```
┌─────────────────┐
│  US Developer   │─────────▶ US-East Worker (low latency)
└─────────────────┘           │
                              │ fallback
                              ▼
┌─────────────────┐           EU Worker (higher latency)
│  EU Developer   │───────────▶
└─────────────────┘
```

Configure worker priority to prefer local workers:

```toml
[[workers]]
id = "us-east"
host = "..."
priority = 100  # High priority for US developers

[[workers]]
id = "eu-central"
host = "..."
priority = 50   # Lower priority (fallback)
```

## Security Considerations

### SSH Key Management

- Use dedicated SSH keys for RCH (separate from personal keys)
- Consider ed25519 keys for better security and performance
- Deploy keys via `rch fleet deploy` or configuration management

```bash
# Generate dedicated key
ssh-keygen -t ed25519 -f ~/.ssh/rch_worker -C "rch-worker-access"

# Configure in workers.toml
[[workers]]
identity_file = "~/.ssh/rch_worker"
```

### Network Security

- Workers should not be publicly accessible
- Use VPN or private network for production
- SSH bastion/jump host supported via `~/.ssh/config`

```
# ~/.ssh/config
Host rch-worker-*
    ProxyJump bastion.example.com
```

### Code Security

- Source code is transferred to workers
- Workers should be trusted infrastructure
- Consider: worker isolation, audit logging, encryption at rest
