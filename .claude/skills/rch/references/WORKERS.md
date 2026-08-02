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
tags = ["rust", "fast"]      # Optional: descriptive labels (NOT a scheduling gate)
os = "windows"               # Optional: hard gate — see "Cross-Platform Workers"
enabled = true               # Optional: set false to disable (default: true)
```

## Selection Algorithm

```
score = available_slots × priority × locality_bonus
```

1. **Available slots**: `total_slots - active_jobs`
2. **Priority**: tiebreaker when slots equal
3. **Locality**: bonus for workers with cached project data
4. **Runtime capability**: probed per worker (rust/go/bun/node/nix/zig); a
   command is only scheduled onto a worker that has the runtime it needs
5. **Host OS**: a worker declaring `os` is admissible *only* for commands
   requiring that OS — see below

Tags take no part in selection.

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

## Cross-Platform Workers (`os =`)

A worker whose host OS differs from the rest of the fleet declares it:

```toml
[[workers]]
id = "windows-builder"
host = "192.168.1.127"
user = "builder"
identity_file = "~/.ssh/windows_key"
total_slots = 4
os = "windows"      # linux | darwin | windows
```

`os` is a **hard admission gate** and makes the worker **exclusive**: it accepts
only commands that require that OS. A plain `cargo check` dispatched from a Linux
or macOS machine will never be scheduled there, so it cannot hand back
wrong-platform artifacts. A worker with no `os` set remains a candidate for
anything — the default, and the behaviour of every worker that predates this.

The requirement comes from the command's `--target` triple:

| Triple | Requires | Why |
|---|---|---|
| `*-pc-windows-msvc` | `os = "windows"` | links against the MSVC toolchain |
| `*-apple-*` (darwin/ios/tvos/watchos) | `os = "darwin"` | needs the macOS SDK |
| `*-pc-windows-gnu`, `wasm32-*`, others | nothing | cross-compiles fine from Linux |

If a command requires an OS no worker declares, nothing is admissible and the
build **falls back to local** — which is correct, and better than shipping it to
a host that cannot produce the artifact. `rch status` diagnostics report the
exclusion with reason code `os.declared_mismatch`.

> **Upgrade before you configure.** `WorkerEntry` does not set
> `#[serde(deny_unknown_fields)]`, so an rchd predating this feature parses
> `os = "windows"`, discards it, and treats the worker as unfenced. Roll out the
> daemon first, then add the worker.

## Tags

Workers may carry descriptive labels:
```toml
[[workers]]
id = "polyglot"
tags = ["rust", "bun", "cpp"]
```

**Tags do not affect scheduling.** Nothing in rch matches on them — they exist
for operator bookkeeping (`rch workers list`). Runtime capability is *probed*
per worker rather than declared, and host OS is gated by `os` above.

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
