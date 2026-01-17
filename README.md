# rch — Remote Compilation Helper

<div align="center">

**Transparent compilation offloading for AI coding agents**

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Rust](https://img.shields.io/badge/rust-nightly%202024-orange.svg)](https://www.rust-lang.org/)

</div>

<div align="center">
<h3>Quick Install</h3>

```bash
cargo install --git https://github.com/Dicklesworthstone/remote_compilation_helper.git
```

</div>

---

## TL;DR

**The Problem**: Running 15+ AI coding agents (Claude Code, Codex CLI) simultaneously causes compilation storms—100% CPU, kernel contention, thermal throttling, and unresponsive shells. Your workstation becomes unusable.

**The Solution**: RCH intercepts compilation commands via Claude Code hooks, transparently routes them to a fleet of remote worker machines, and returns artifacts as if nothing happened. Agents never know compilation ran remotely.

### Why Use RCH?

| Feature | What It Does |
|---------|--------------|
| **Transparent Interception** | Hooks into Claude Code's PreToolUse—agents think compilation ran locally |
| **Smart Classification** | 5-tier system classifies commands in <1ms; surgical precision avoids false positives |
| **Fleet Management** | Load-balance across 4+ workers with 48-80 total cores |
| **Project Affinity** | Routes to workers with cached project copies—incremental builds stay fast |
| **Deduplication** | Multiple agents compiling same project share results via broadcast |

---

## Quick Example

```bash
# Start the daemon
rch daemon start

# Verify worker connectivity
rch workers probe --all

# Now use Claude Code normally—RCH intercepts automatically
claude

# Inside Claude Code session, compilations are transparently offloaded:
> cargo build --release     # Runs on remote worker, artifacts returned
> cargo test               # Same—tests run remotely, output streams back
> bun test                 # Bun tests offloaded to worker
> bun typecheck            # TypeScript type checking on worker
> cargo fmt                # NOT intercepted (modifies local source)
> bun install              # NOT intercepted (modifies local node_modules)
> cargo --version          # NOT intercepted (too quick to benefit)

# Check what's happening
rch status --jobs          # Active compilations
rch status --workers       # Worker health and slots
```

---

## Design Philosophy

### 1. Transparency Above All

Agents must not know compilation ran remotely. The hook returns silently on success with artifacts in place. Only failures surface—and they look like normal compilation errors.

### 2. Fail-Open, Never Block

On any error—worker unreachable, transfer timeout, daemon down—RCH allows local execution rather than blocking the agent. A slow local build beats a stuck agent.

### 3. Precision Over Recall

False positives are catastrophic (intercepting `cargo fmt` breaks source files). False negatives are acceptable (missing an offload opportunity just means local compilation). The 5-tier classifier prioritizes precision.

### 4. Sub-Millisecond Decisions

99% of commands are non-compilation. The hook must reject them in <0.1ms. Only actual compilation commands pay the full classification cost (<5ms).

### 5. Stateless Hook, Stateful Daemon

The `rch` hook is a pure function—all state lives in `rchd`. This makes the hook fast and debuggable.

---

## How RCH Compares

| Capability | RCH | distcc | icecc | Local |
|------------|-----|--------|-------|-------|
| **Transparent to agents** | ✅ Full | ❌ Requires wrapper | ❌ Requires wrapper | ✅ |
| **Full Rust support** | ✅ cargo, rustc | ❌ C/C++ only | ❌ C/C++ only | ✅ |
| **Bun/TypeScript support** | ✅ test, typecheck | ❌ | ❌ | ✅ |
| **Automatic load balancing** | ✅ Slot-aware | ⚠️ Manual | ✅ | N/A |
| **Project caching** | ✅ Affinity routing | ❌ | ❌ | ✅ |
| **Multi-agent dedup** | ✅ Broadcast channels | ❌ | ❌ | ❌ |
| **Setup complexity** | ⚠️ Moderate | ✅ Simple | ⚠️ Moderate | ✅ None |

**When to use RCH:**
- Running multiple AI coding agents simultaneously
- Your workstation CPU is the bottleneck
- You have SSH access to remote machines with spare capacity
- Your projects are Rust-heavy (best support), TypeScript/Bun (good support), or C/C++ (good support)

**When RCH might not be ideal:**
- Single-agent workflows (local is usually fast enough)
- Projects with unusual build systems (Bazel, Buck)
- Air-gapped environments without SSH access to workers

---

## Installation

### From Source (Recommended)

```bash
git clone https://github.com/Dicklesworthstone/remote_compilation_helper.git
cd remote_compilation_helper
cargo build --release

# Install binaries
cp target/release/rch ~/.local/bin/
cp target/release/rchd ~/.local/bin/
```

### With Cargo

```bash
cargo install --git https://github.com/Dicklesworthstone/remote_compilation_helper.git
```

### Setup Workers

```bash
# Configure worker fleet
mkdir -p ~/.config/rch
cat > ~/.config/rch/workers.toml << 'EOF'
[[workers]]
id = "worker1"
host = "203.0.113.10"
user = "ubuntu"
identity_file = "~/.ssh/id_rsa"
total_slots = 16
priority = 100

[[workers]]
id = "worker2"
host = "203.0.113.11"
user = "ubuntu"
identity_file = "~/.ssh/id_rsa"
total_slots = 32
priority = 100
EOF

# Install RCH on workers
rch install --fleet

# Register the Claude Code hook
rch hook install
```

---

## Quick Start

### 1. Start the Daemon

```bash
rchd                           # Foreground (logs visible)
rch daemon start              # Background (systemd/launchd)
```

### 2. Verify Workers

```bash
rch workers list              # Show configured workers
rch workers probe --all       # Test SSH connectivity and detect capabilities
rch workers benchmark         # Measure worker speeds
```

Worker probing automatically detects installed toolchains (Rust, Bun, Node.js). For Bun/TypeScript projects, verify workers have Bun installed:

```bash
# Check capabilities on a specific worker
ssh worker1 "bun --version"   # Should show Bun version

# Or probe via RCH (requires rch-wkr installed on worker)
rch workers probe worker1 --verbose   # Shows detected capabilities
```

### 3. Use Claude Code Normally

```bash
claude                        # Start Claude Code session
# All cargo build/test/check commands are now offloaded
```

### 4. Monitor Activity

```bash
rch status                    # Daemon status
rch status --workers          # Worker health
rch status --jobs             # Active compilations
```

---

## Commands

Global flags available on all commands:

```bash
--verbose       # Increase logging
--quiet         # Suppress non-error output
--format json   # Machine-readable output
```

### `rch daemon`

Control the local daemon.

```bash
rch daemon start              # Start in background
rch daemon stop               # Stop daemon
rch daemon restart            # Restart daemon
rch daemon status             # Check if running
rch daemon logs               # Tail daemon logs
```

### `rch workers`

Manage the worker fleet.

```bash
rch workers list              # List configured workers
rch workers probe --all       # Test connectivity
rch workers probe worker1     # Test specific worker
rch workers benchmark         # Run speed benchmarks
rch workers drain worker1     # Stop routing to worker
rch workers enable worker1    # Resume routing to worker
```

### `rch status`

Show system status.

```bash
rch status                    # Overview
rch status --workers          # Worker details (slots, health, latency)
rch status --jobs             # Active and recent compilations
rch status --stats            # Aggregate statistics
```

### `rch config`

Manage configuration.

```bash
rch config show               # Show effective config
rch config init               # Create project .rch/config.toml
rch config validate           # Validate TOML syntax
rch config set key value      # Set config value
```

### `rch hook`

Manage the Claude Code hook.

```bash
rch hook install              # Register PreToolUse hook
rch hook uninstall            # Remove hook
rch hook test                 # Simulate hook invocation
```

---

## Configuration

For full configuration precedence and reference, see `docs/guides/configuration.md`.

### User Config (`~/.config/rch/config.toml`)

```toml
# Global settings
[general]
enabled = true
log_level = "info"
socket_path = "~/.cache/rch/rch.sock"

# Compilation settings
[compilation]
confidence_threshold = 0.85      # Min confidence to intercept (0.0-1.0)
min_local_time_ms = 2000         # Skip if local <2s
remote_speedup_threshold = 1.2   # Require 20% speedup for remote

# Transfer settings
[transfer]
compression_level = 3            # zstd level (1-19)
exclude_patterns = [
    "target/",
    ".git/objects/",
    "node_modules/",
    "*.rlib",
    "*.rmeta",
]

# Output settings
[output]
stream_mode = "realtime"         # realtime, buffered, summary
preserve_colors = true
max_latency_ms = 50
```

### Workers Config (`~/.config/rch/workers.toml`)

```toml
[[workers]]
id = "css"                       # Unique identifier
host = "203.0.113.20"           # SSH hostname or IP (example)
user = "ubuntu"                  # SSH user
identity_file = "~/.ssh/key.pem" # SSH private key
total_slots = 32                 # CPU cores available
priority = 100                   # Higher = preferred
tags = ["fast", "ssd"]          # Optional tags for filtering

[[workers]]
id = "fra"
host = "worker2.example.com"
user = "builder"
identity_file = "~/.ssh/id_rsa"
total_slots = 16
priority = 50
```

### Project Config (`.rch/config.toml` in project root)

```toml
# Disable RCH for this project
enabled = false

# Or customize behavior
[general]
enabled = true
preferred_workers = ["css"]     # Always try these first

[transfer]
include_patterns = [            # Force-include files
    "src/generated/*.rs",
]
exclude_patterns = [            # Additional excludes
    "benches/data/",
]

[environment]
RUSTFLAGS = "-C target-cpu=native"
CARGO_BUILD_JOBS = "16"
```

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `RCH_ENABLED` | Enable/disable RCH | `true` |
| `RCH_WORKER` | Force specific worker | unset |
| `RCH_WORKERS` | Limit worker pool (comma-separated) | all |
| `RCH_COMPRESSION` | Override compression level | `3` |
| `RCH_DRY_RUN` | Show what would happen | `false` |
| `RCH_LOCAL_ONLY` | Force local execution | `false` |
| `RCH_BYPASS` | Disable RCH entirely | `false` |
| `RCH_VERBOSE` | Enable verbose logging | `false` |

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                            AGENT WORKSTATION                                 │
│                                                                             │
│  ┌──────────────┐     ┌────────────────────────────────────────────────┐   │
│  │ Claude Code  │────▶│ rch (PreToolUse Hook)                          │   │
│  │ Agent 1..N   │     │ • Parse hook JSON                              │   │
│  └──────────────┘     │ • 5-tier command classification (<1ms)         │   │
│        │              │ • Query daemon for worker selection            │   │
│        │              └──────────────────────────┬─────────────────────┘   │
│        │                                         │                          │
│        │              ┌──────────────────────────▼─────────────────────┐   │
│        │              │ rchd (Local Daemon)                            │   │
│        │              │ • Worker health monitoring (30s heartbeat)      │   │
│        │              │ • Slot tracking (atomic, lock-free)            │   │
│        │              │ • Speed scoring & load balancing               │   │
│        │              │ • SSH connection pool (multiplexing)           │   │
│        │              │ • Compilation deduplication (broadcast)        │   │
│        │              └──────────────────────────┬─────────────────────┘   │
│        │                                         │                          │
└────────┼─────────────────────────────────────────┼──────────────────────────┘
         │                                         │ SSH
         │                                         ▼
┌────────┼─────────────────────────────────────────────────────────────────────┐
│        │              WORKER FLEET (4+ machines, 48-80 cores)               │
│        │                                                                     │
│        │         ┌─────────────┐   ┌─────────────┐   ┌─────────────┐        │
│        │         │ Worker 1    │   │ Worker 2    │   │ Worker N    │        │
│        │         │ 16 slots    │   │ 32 slots    │   │ 16 slots    │        │
│        │         │             │   │             │   │             │        │
│        │         │ rch-wkr     │   │ rch-wkr     │   │ rch-wkr     │        │
│        │         │ • Execute   │   │ • Execute   │   │ • Execute   │        │
│        │         │ • Cache     │   │ • Cache     │   │ • Cache     │        │
│        │         │ • Cleanup   │   │ • Cleanup   │   │ • Cleanup   │        │
│        │         └─────────────┘   └─────────────┘   └─────────────┘        │
│        │                                                                     │
└────────┼─────────────────────────────────────────────────────────────────────┘
         │
         ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                              DATA FLOW                                       │
│                                                                             │
│  1. Agent runs `cargo build`                                                │
│  2. Hook classifies → compilation (0.92 confidence)                         │
│  3. Daemon selects worker (slots available, project cached)                 │
│  4. rsync project → worker (zstd, exclude target/)                          │
│  5. Execute `cargo build` on worker                                         │
│  6. Stream output back in real-time (colors preserved)                      │
│  7. rsync artifacts ← worker (target/release/)                              │
│  8. Hook returns silently → agent continues                                 │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

### Command Classification (5-Tier System)

```
Command: "cargo build --release"

Tier 0: Instant Reject (<0.01ms)
├─ Is Bash tool? ✅
├─ Has content? ✅
└─ Pass → continue

Tier 1: Structure Analysis (<0.1ms)
├─ Piped? ❌
├─ Backgrounded? ❌
├─ Redirected? ❌
└─ Pass → continue

Tier 2: SIMD Keyword Filter (<0.2ms)
├─ Contains "cargo"? ✅
└─ Pass → continue

Tier 3: Negative Pattern Check (<0.5ms)
├─ "cargo install"? ❌
├─ "cargo fmt"? ❌
├─ "cargo clean"? ❌
└─ Pass → continue

Tier 4: Full Classification (<5ms)
├─ Pattern match: cargo build
├─ Confidence: 0.95
├─ Threshold: 0.85
└─ INTERCEPT ✅
```

---

## Troubleshooting

### "Connection refused to worker"

```bash
# Check SSH connectivity
ssh -i ~/.ssh/key.pem ubuntu@worker-host echo "OK"

# Verify worker is configured
rch workers list

# Test specific worker
rch workers probe worker1 --verbose
```

### "Compilation slower than local"

```bash
# Check if project caching is working
rch status --jobs --verbose

# Force benchmark update
rch workers benchmark

# Verify network latency
rch workers probe --all --latency
```

### "Output not showing during compilation"

```bash
# Check stream mode
rch config show | grep stream_mode

# Force realtime streaming
export RCH_STREAM_MODE=realtime
cargo build
```

### "Some commands not being intercepted"

```bash
# Test classification
echo '{"tool":"Bash","input":{"command":"cargo build"}}' | rch hook test

# Check confidence threshold
rch config show | grep confidence_threshold

# Run with verbose to see decisions
RCH_VERBOSE=1 cargo build
```

### "Daemon not running"

```bash
# Check daemon status
rch daemon status

# View logs for errors
rch daemon logs --tail 50

# Restart daemon
rch daemon restart
```

---

## Limitations

### What RCH Doesn't Handle (Yet)

- **Bazel/Buck builds**: Complex build systems with custom execution models
- **Cross-compilation**: Target architecture must match worker architecture
- **Build caching servers**: No integration with sccache servers (local sccache works)
- **Windows workers**: Linux workers only (WSL2 might work, untested)

### Known Constraints

| Constraint | Impact | Workaround |
|------------|--------|------------|
| SSH required | No HTTP/gRPC transport | Use SSH tunnels if needed |
| Rust nightly | Workers need matching toolchain | `rch install --fleet` syncs toolchains |
| Large artifacts | Slow return for 500MB+ binaries | Use `--release` profile, strip symbols |
| Workspace deps | All workspace members transferred | Use `.rch/config.toml` excludes |

---

## FAQ

### Why "RCH"?

**R**emote **C**ompilation **H**elper. Short, typeable, memorable.

### Is my code sent over the network?

Yes—source files are transferred via rsync over SSH. If this is a concern:
- Use workers you control (not shared infrastructure)
- Workers should be on a trusted network
- SSH provides encryption in transit
- Consider VPN for additional security

### Does RCH work with non-Rust projects?

Yes, with good support for multiple ecosystems:
- **Bun/TypeScript**: `bun test` and `bun typecheck` are offloaded. Package management (`bun install`, `bun add`) and dev servers (`bun dev`) run locally.
- **C/C++**: Compilation via `gcc`, `clang`, `make`, `cmake`, `ninja` is supported.
- **Not supported**: Go, Python, and npm/yarn/pnpm commands are not intercepted.

### What if a worker goes down mid-compilation?

RCH detects the failure and falls back to local compilation. The agent sees a brief delay, then compilation proceeds locally.

### Can I use RCH without Claude Code?

The hook is designed for Claude Code's PreToolUse mechanism. For standalone use, you'd need to wrap your shell to call `rch` for every command—possible but not officially supported.

### How do I add more workers?

```bash
# Edit workers.toml
vim ~/.config/rch/workers.toml

# Add new worker block
[[workers]]
id = "new-worker"
host = "203.0.113.12"
...

# Install on new worker
rch install --worker new-worker

# Probe to verify
rch workers probe new-worker
```

### Why are some fast commands not intercepted?

RCH skips commands estimated to complete locally in <2 seconds. The overhead of transfer + remote execution isn't worth it for quick operations like `cargo check` on a small crate.

---

## Contributing

### Development Setup

```bash
git clone https://github.com/Dicklesworthstone/remote_compilation_helper.git
cd remote_compilation_helper

# Build all components
cargo build

# Run tests
cargo test

# Run with verbose logging
RUST_LOG=debug cargo run --bin rch -- status
```

### Project Structure

```
remote_compilation_helper/
├── rch/           # Hook CLI binary
├── rchd/          # Local daemon
├── rch-wkr/       # Worker agent
├── rch-common/    # Shared library
├── config/        # Example configs
├── scripts/       # Setup scripts
└── tests/         # Integration tests
```

---

## License

MIT License. See [LICENSE](LICENSE) for details.

---

## Acknowledgments

Built with:
- [Rust](https://www.rust-lang.org/) — Systems programming language
- [tokio](https://tokio.rs/) — Async runtime
- [ssh2](https://docs.rs/ssh2) — SSH connectivity
- [memchr](https://docs.rs/memchr) — SIMD string search
- [zstd](https://facebook.github.io/zstd/) — Fast compression

Inspired by:
- [distcc](https://distcc.github.io/) — Distributed C/C++ compilation
- [icecc](https://github.com/icecc/icecream) — Distributed compiler
- [Claude Code](https://claude.ai/code) — AI coding assistant with hooks
