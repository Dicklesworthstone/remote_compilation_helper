# Worker Configuration

## Schema

```toml
[[workers]]
id = "unique-name"           # Required
host = "192.168.1.100"       # Required: IP or hostname
user = "ubuntu"              # Required: SSH user
identity_file = "~/.ssh/key" # Required: SSH key path
total_slots = 16             # Required: max concurrent jobs (≈ CPU cores - 2)
priority = 100               # Optional: selection weight (default: 50, higher = preferred)
tags = ["rust", "fast"]      # Optional: capability tags
enabled = true               # Optional: set false to disable (default: true)
```

## Selection Algorithm

```
score = available_slots × priority × locality_bonus
```

1. **Available slots**: `total_slots - active_jobs`
2. **Priority**: tiebreaker when slots equal
3. **Locality**: bonus for workers with cached project data
4. **Tags**: project can require specific tags via `.rch.toml`

## Multi-Worker Example

```toml
# Primary (fast, high priority)
[[workers]]
id = "fast-builder"
host = "build-server.local"
user = "build"
identity_file = "~/.ssh/build_key"
total_slots = 48
priority = 100
tags = ["fast", "rust", "bun"]

# Secondary (fallback when primary busy)
[[workers]]
id = "backup"
host = "192.168.1.50"
user = "ubuntu"
identity_file = "~/.ssh/id_ed25519"
total_slots = 8
priority = 50
tags = ["rust"]

# Specialized TypeScript worker
[[workers]]
id = "ts-builder"
host = "ts.internal"
user = "node"
identity_file = "~/.ssh/ts_key"
total_slots = 16
priority = 75
tags = ["bun", "typescript"]
```

## SSH Config Discovery

```bash
rch workers discover --from-ssh-config --dry-run   # Preview
rch workers discover --from-ssh-config             # Add to config
rch workers discover --from-ssh-config --filter "build*"  # Filter by pattern
```

**Required SSH config fields**: `Host`, `HostName`, `User`, `IdentityFile`

**Optional RCH hints** (in SSH config comments):
```
Host build-server
    HostName 192.168.1.100
    User ubuntu
    IdentityFile ~/.ssh/build_key
    # rch-slots: 16
    # rch-priority: 90
    # rch-tags: rust,bun
```

## Probing & Monitoring

```bash
rch workers probe worker1 --verbose  # Test connectivity + detect toolchains
rch workers probe --all              # Probe all workers
rch workers status                   # Current state
rch workers status --json            # For monitoring tools
watch -n 5 'rch workers status'      # Continuous monitoring
```

Probe output shows: SSH connectivity, detected toolchains (rustc, cargo, bun, gcc), disk space, load.

## Tags

Workers declare capabilities:
```toml
[[workers]]
id = "polyglot"
tags = ["rust", "bun", "cpp"]
```

Projects require tags:
```toml
# .rch.toml in project root
required_tags = ["rust", "fast"]
```

## Slot Sizing

```bash
ssh worker1 "nproc"  # Check cores
# Rule: total_slots = cores - 2 (leave headroom for system)
```

## Disable/Enable

```toml
[[workers]]
id = "under-maintenance"
enabled = false  # Won't be selected
```
