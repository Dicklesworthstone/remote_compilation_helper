# rch — Remote Compilation Helper

<div align="center">
  <img src="rch_illustration.webp" alt="rch - Remote Compilation Helper for AI coding agents">
</div>

<div align="center">
<h3>Quick Install</h3>

```bash
curl -fsSL "https://raw.githubusercontent.com/Dicklesworthstone/remote_compilation_helper/main/install.sh?$(date +%s)" | bash -s -- --easy-mode
```

<p><em>Installs rch + rchd, configures the hook, and can optionally enable the background daemon. If rchd or workers are unavailable, RCH fails open to local builds.</em></p>
</div>

<div align="center">
  <img src="rch_diagram.webp" alt="rch architecture diagram">
</div>

<div align="center">

**Transparent compilation offloading for AI coding agents**

[![CI](https://github.com/Dicklesworthstone/remote_compilation_helper/actions/workflows/ci.yml/badge.svg)](https://github.com/Dicklesworthstone/remote_compilation_helper/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Rust](https://img.shields.io/badge/rust-nightly%202024-orange.svg)](https://www.rust-lang.org/)
[![codecov](https://codecov.io/gh/Dicklesworthstone/remote_compilation_helper/graph/badge.svg)](https://codecov.io/gh/Dicklesworthstone/remote_compilation_helper)

</div>

---

## TL;DR

**The Problem**: Running 15+ AI coding agents (Claude Code, Codex CLI) simultaneously creates compilation storms—100% CPU, kernel contention, thermal throttling, and unresponsive shells. Your workstation becomes unusable while agents wait for builds.

**The Solution**: RCH intercepts compilation commands via Claude Code's PreToolUse hook, transparently routes them to a fleet of remote worker machines, and returns artifacts as if compilation ran locally. Agents never know the difference.

### Why Use RCH?

| Feature | What It Does |
|---------|--------------|
| **Transparent Interception** | Hooks into Claude Code's PreToolUse—agents think compilation ran locally |
| **Sub-Millisecond Decisions** | 5-tier classifier rejects 99% of commands in <0.1ms, compilation decisions in <1ms |
| **Smart Worker Selection** | Load-balances across workers using speed scores, available slots, and project locality |
| **Project Affinity** | Routes to workers with cached project copies—incremental builds stay fast |
| **Multi-Agent Dedup** | Multiple agents compiling same project share results via broadcast channels |
| **Fail-Open Design** | Any error falls back to local execution—never blocks an agent |

---

## Quick Example

```bash
# 1. Start the daemon
$ rchd &
[rchd] Listening on /tmp/rch.sock
[rchd] 3 workers online (72 total slots)

# 2. Configure a worker (one-time)
$ cat >> ~/.config/rch/workers.toml << 'EOF'
[[workers]]
id = "build-server"
host = "203.0.113.10"
user = "ubuntu"
identity_file = "~/.ssh/id_rsa"
total_slots = 32
EOF

# 3. Verify connectivity
$ rch workers probe --all
build-server: OK (latency: 12ms, 32 slots, rust 1.87-nightly, bun 1.2.0)

# 4. Install the hook into Claude Code
$ rch hook install
Hook installed at ~/.claude/hooks/pre-tool-use.sh

# 5. Use Claude Code normally—RCH intercepts automatically
$ claude
> cargo build --release     # → Runs on build-server, artifacts returned
> cargo test               # → Tests run remotely, output streams back
> bun test                 # → Bun tests offloaded to worker
> cargo fmt                # → NOT intercepted (modifies source)
> ls -la                   # → NOT intercepted (not compilation)

# 6. Monitor what's happening
$ rch status --jobs
ACTIVE JOBS:
  project-x/cargo build --release  →  build-server (14s elapsed)

$ rch status --workers
WORKERS:
  build-server   ████████░░░░  (8/32 slots)  speed: 94.2
```

---

## Beautiful Terminal Output (rich_rust)

RCH ships with rich terminal output for human use (tables, panels, progress). It automatically falls back to plain ASCII when a terminal is not available or machine output is requested. Rich output goes to stderr so stdout remains clean for JSON/machine consumption.

### UI Features Overview

- Colored status output with consistent icons
- Progress visualization for sync and execution phases
- Rich error panels with remediation hints
- Worker status tables (status, slots, speed, latency)

### Controlling Output

Use these flags and environment variables to force the desired output mode:

- `--json` or `--format json|toon` -> machine output on stdout, no rich UI
- `--color=never` or `NO_COLOR=1` -> plain ASCII output (no ANSI)
- `--color=always` or `CLICOLOR_FORCE=1` / `FORCE_COLOR=1` -> force color output
- `TERM=dumb` -> plain ASCII fallback
- `-q/--quiet` -> errors only
- `-v/--verbose` -> extra details (timings, diagnostics)

See [docs/RICH_OUTPUT_MIGRATION.md](docs/RICH_OUTPUT_MIGRATION.md) for a detailed migration guide and compatibility info.

### Before / After (Plain vs Rich)

Plain fallback (no colors, no tables):

```text
$ rch status
Daemon: running (pid 4123)
Workers: 3 total, 3 healthy, 72 slots
Active jobs: 1
Recent builds: 5
```

Rich output (conceptual layout):

```text
$ rch status
[Status]  Daemon: healthy  |  Workers: 3  |  Slots: 72 (12 used)
---------------------------------------------------------------
WORKERS
  id    status    slots    speed   latency
  css   healthy   8/32     94.2    12ms
  csd   healthy   2/16     88.1    18ms
  cse   healthy   2/24     91.0    15ms
```

### Screenshots Gallery (Text Previews)

Status overview:

```text
$ rch status --workers
WORKERS
  css  healthy  8/32  speed 94.2  latency 12ms
  csd  healthy  2/16  speed 88.1  latency 18ms
```

Worker probe results:

```text
$ rch workers probe --all
css: OK   (latency 12ms, rust 1.87-nightly, bun 1.2.0)
csd: OK   (latency 18ms, rust 1.87-nightly, bun 1.2.0)
```

Compilation progress:

```text
Syncing project...  182 MB / 182 MB  (1.2s)
Compiling...        cargo build --release
Returning artifacts...  14 files  (0.6s)
```

Error display:

```text
ERROR: Worker 'css' unreachable
Suggested fix: rch workers probe css
```

### Accessibility

- Colors are optional; plain ASCII is always available.
- Output avoids emoji-only signals and includes text labels.
- Rich UI renders to stderr, keeping stdout available for tooling.
- Use `--color=never` or `NO_COLOR=1` for screen reader friendliness.

---

## Design Philosophy

### 1. Transparency Above All

Agents must not know compilation ran remotely. The hook returns silently on success with artifacts in place. Only failures surface—and they look like normal compilation errors.

### 2. Fail-Open, Never Block

On any error—worker unreachable, transfer timeout, daemon down—RCH allows local execution rather than blocking the agent. A slow local build beats a stuck agent.

### 3. Precision Over Recall

False positives are catastrophic (intercepting `cargo fmt` corrupts source files). False negatives are acceptable (missing an offload just means local compilation). The 5-tier classifier prioritizes precision.

### 4. Sub-Millisecond Non-Compilation Decisions

99% of commands are non-compilation. The hook must reject them in <0.1ms. Only actual compilation commands pay the full classification cost (<5ms).

### 5. Stateless Hook, Stateful Daemon

The `rch` hook is a pure function—all state lives in `rchd`. This makes the hook fast, debuggable, and crash-resistant.

---

## How RCH Compares

| Capability | RCH | distcc | icecc | Local |
|------------|-----|--------|-------|-------|
| **Transparent to agents** | ✅ Full | ❌ Wrapper required | ❌ Wrapper required | ✅ |
| **Full Rust support** | ✅ cargo, rustc | ❌ C/C++ only | ❌ C/C++ only | ✅ |
| **Bun/TypeScript** | ✅ test, typecheck | ❌ | ❌ | ✅ |
| **C/C++ support** | ✅ gcc, clang, make | ✅ | ✅ | ✅ |
| **Automatic load balancing** | ✅ Slot-aware | ⚠️ Manual | ✅ | N/A |
| **Project caching** | ✅ Affinity routing | ❌ | ❌ | ✅ |
| **Multi-agent dedup** | ✅ Broadcast | ❌ | ❌ | ❌ |
| **Setup complexity** | ⚠️ Moderate | ✅ Simple | ⚠️ Moderate | ✅ None |

**When to use RCH:**
- Running multiple AI coding agents simultaneously
- Your workstation CPU is the bottleneck
- You have SSH access to remote machines with spare capacity
- Projects are Rust-heavy (best support), TypeScript/Bun (good), or C/C++ (good)

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
# Create config directory
mkdir -p ~/.config/rch

# Configure your worker fleet
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

# Install RCH on workers (copies rch-wkr binary)
rch install --fleet

# Register the Claude Code hook
rch hook install
```

---

## Quick Start

### 1. Start the Daemon

```bash
rchd                          # Foreground (see logs)
rch daemon start              # Background (systemd/launchd)
```

### 2. Verify Workers

```bash
rch workers list              # Show configured workers
rch workers probe --all       # Test SSH connectivity
rch workers benchmark         # Measure worker speeds (optional)
```

### 3. Use Claude Code Normally

```bash
claude                        # Start Claude Code session
# All cargo build/test/check commands are now offloaded
```

### 4. Monitor Activity

```bash
rch status                    # Daemon status
rch status --workers          # Worker health and slots
rch status --jobs             # Active compilations
```

---

## Commands

Global flags available on all commands:

```bash
--verbose       # Increase logging
--quiet         # Suppress non-error output
--json          # Machine-readable JSON output (legacy)
--format json|toon   # Machine output format (json or toon)
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
rch workers probe --all       # Test connectivity and detect capabilities
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

### `rch dashboard` (alias: `rch tui`)

Interactive TUI dashboard for real-time monitoring in your terminal.

```bash
rch dashboard                          # Launch interactive dashboard
rch dashboard --refresh 500            # Faster refresh (ms)
rch dashboard --no-mouse               # Disable mouse support
rch dashboard --high-contrast          # Accessibility: high contrast mode
rch dashboard --color-blind tritanopia # Accessibility: color blind palette

# Non-interactive modes (do not manipulate the terminal)
rch dashboard --test-mode --mock-data  # Render once and exit (CI-friendly)
rch dashboard --dump-state --mock-data # Print JSON state and exit (automation)
```

Controls: `q`/Esc quit, ↑/↓ navigate, Tab switch panels, `r` refresh, `?` help.

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
# Optional SSH stability knobs (useful on flaky networks)
ssh_server_alive_interval_secs = 30  # ssh -o ServerAliveInterval
ssh_control_persist_secs = 60        # ssh -o ControlPersist=60s (0 disables)

# Optional: project-local excludes
#
# If a project root contains a `.rchignore` file, its patterns are appended to
# the effective exclude list (defaults + config). Format:
# - one pattern per line
# - `#` comments and blank lines ignored
# - leading/trailing whitespace trimmed
# - negation (`!pattern`) is NOT supported (treated as literal)

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
host = "203.0.113.20"           # SSH hostname or IP
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
force_local = false           # Never offload for this project (mutually exclusive with force_remote)
force_remote = false          # Always attempt offload for this project (still respects safety gates)
preferred_workers = ["css"]     # Always try these first

[transfer]
include_patterns = [            # Force-include files
    "src/generated/*.rs",
]
exclude_patterns = [            # Additional excludes
    "benches/data/",
]

# Alternatively (or additionally), add a `.rchignore` file in the project root.
# Its patterns are merged deterministically into the transfer excludes.

[environment]
allowlist = ["RUSTFLAGS", "CARGO_TARGET_DIR"]
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
| `RCH_ENV_ALLOWLIST` | Comma-separated env vars to forward | unset |
| `RCH_SSH_SERVER_ALIVE_INTERVAL_SECS` | SSH keepalive interval (ServerAliveInterval) | unset |
| `RCH_SSH_CONTROL_PERSIST_SECS` | SSH ControlPersist idle seconds (0 disables) | unset |
| `RCH_VERBOSE` | Enable verbose logging | `false` |
| `RCH_PRIORITY` | Per-command selection hint: `low|normal|high` | unset |
| `RCH_OUTPUT_FORMAT` | Machine output format: `json` or `toon` | unset |
| `TOON_DEFAULT_FORMAT` | Default machine format when `--json` is set | unset |

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

### Display issues (colors, glyphs, or rich tables missing)

- Rich UI renders to stderr; ensure stderr is a TTY when testing locally.
- Force color output with `--color=always`, `CLICOLOR_FORCE=1`, or `FORCE_COLOR=1`.
- Disable styling with `--color=never` or `NO_COLOR=1`.
- For automation, prefer `--json` or `--format json|toon` to avoid ANSI output.
- If your terminal is mis-detected, set `TERM=dumb` to force plain output.

### "Connection refused to worker"

```bash
# Check SSH connectivity directly
ssh -i ~/.ssh/key.pem ubuntu@worker-host echo "OK"

# Verify worker is configured
rch workers list

# Test specific worker with verbose output
rch workers probe worker1 --verbose
```

### "Compilation slower than local"

```bash
# Check if project caching is working
rch status --jobs --verbose

# Force benchmark update to recalculate speed scores
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
# Test classification manually
echo '{"tool":"Bash","input":{"command":"cargo build"}}' | rch hook test

# Check confidence threshold (default 0.85)
rch config show | grep confidence_threshold

# Run with verbose to see classification decisions
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

## Test Execution

RCH fully supports `cargo test` and streams test output back to your agent in real-time.

### Supported Test Commands

| Command | Offloaded | Notes |
|---------|-----------|-------|
| `cargo test` | ✅ Yes | Basic test execution |
| `cargo test --release` | ✅ Yes | Release mode tests |
| `cargo test specific_test` | ✅ Yes | Run specific test by name |
| `cargo test -- --nocapture` | ✅ Yes | Shows test stdout |
| `cargo test --workspace` | ✅ Yes | Tests all workspace packages |
| `cargo test -p crate_name` | ✅ Yes | Test specific package |
| `cargo t` | ✅ Yes | Short alias for cargo test |
| `cargo test --lib` | ✅ Yes | Library tests only |
| `cargo test --bins` | ✅ Yes | Binary tests only |
| `cargo test --doc` | ✅ Yes | Documentation tests |
| `RUST_BACKTRACE=1 cargo test` | ✅ Yes | Environment variables preserved |

### Exit Code Handling

RCH correctly handles cargo test's specific exit codes:

| Exit Code | Meaning | RCH Behavior |
|-----------|---------|--------------|
| 0 | All tests passed | Deny local execution (success) |
| 1 | Build/compilation error | Deny local execution (error) |
| 101 | Tests ran but some failed | Deny local execution (test failure) |
| 128+N | Killed by signal N | Deny local execution (resource issue) |

**Why deny local after failure?** Re-running tests locally won't help—the agent already saw the failure output. This prevents redundant execution.

### Output Streaming

Test output streams back in real-time as tests execute:
- Pass/fail results appear as they complete
- `--nocapture` output is visible immediately
- Compilation errors show before tests run

### Example Usage

```bash
# Run all tests on remote worker
$ cargo test
   Compiling my-crate v0.1.0
    Finished test [unoptimized + debuginfo]
     Running unittests src/lib.rs
running 42 tests
test module::test_feature ... ok
test module::test_edge_case ... ok
...
test result: ok. 42 passed; 0 failed; 0 ignored

# Run specific tests with output capture disabled
$ cargo test my_function -- --nocapture
running 1 test
test my_function ... [debug output here] ok
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

Yes, with varying levels of support:

| Ecosystem | Offloaded Commands | Local Commands |
|-----------|-------------------|----------------|
| **Rust** | `cargo build`, `cargo test`, `cargo check`, `cargo run`, `rustc` | `cargo fmt`, `cargo clean`, `cargo install` |
| **Bun/TypeScript** | `bun test`, `bun typecheck` | `bun install`, `bun dev`, `bun run` |
| **C/C++** | `gcc`, `g++`, `clang`, `make`, `cmake`, `ninja` | — |
| **Not supported** | — | Go, Python, npm, yarn, pnpm |

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
user = "ubuntu"
identity_file = "~/.ssh/id_rsa"
total_slots = 24
priority = 100

# Install rch-wkr on the new worker
rch install --worker new-worker

# Verify connectivity
rch workers probe new-worker
```

### Why are some fast commands not intercepted?

RCH skips commands estimated to complete locally in <2 seconds. The overhead of transfer + remote execution isn't worth it for quick operations like `cargo check` on a small crate.

---

## About Contributions

Please don't take this the wrong way, but I do not accept outside contributions for any of my projects. I simply don't have the mental bandwidth to review anything, and it's my name on the thing, so I'm responsible for any problems it causes; thus, the risk-reward is highly asymmetric from my perspective. I'd also have to worry about other "stakeholders," which seems unwise for tools I mostly make for myself for free. Feel free to submit issues, and even PRs if you want to illustrate a proposed fix, but know I won't merge them directly. Instead, I'll have Claude or Codex review submissions via `gh` and independently decide whether and how to address them. Bug reports in particular are welcome. Sorry if this offends, but I want to avoid wasted time and hurt feelings. I understand this isn't in sync with the prevailing open-source ethos that seeks community contributions, but it's the only way I can move at this velocity and keep my sanity.

---

## License

MIT License. See [LICENSE](LICENSE) for details.

---

---

## Self-Update System

RCH includes a built-in update mechanism that handles version checking, downloading, verification, and installation—all without requiring manual intervention.

### Checking for Updates

```bash
# Check if an update is available
rch update --check

# Show detailed version information
rch update --check --verbose
```

The update checker uses intelligent caching:
- Version checks are cached for 24 hours to avoid hammering GitHub's API
- Background threads warm the cache on startup without blocking your workflow
- Set `RCH_NO_UPDATE_CHECK=1` to disable automatic checks entirely

### Performing Updates

```bash
# Update to latest stable release
rch update

# Update to a specific version
rch update --version 0.2.0

# Update from beta/nightly channel
rch update --channel beta
```

### Backup and Rollback

Every update creates a backup of the current installation:

```bash
# List available backups
rch update --list-backups

# Rollback to previous version
rch update --rollback

# Rollback to specific version
rch update --rollback --version 0.1.0
```

Backups are stored in `~/.local/share/rch/backups/` with JSON metadata files. Only the 3 most recent backups are retained to conserve disk space.

### Update Verification

Downloaded releases are verified using multiple mechanisms:
- **SHA256 checksums**: Every release artifact has a corresponding `.sha256` file
- **Sigstore signatures**: Artifacts are signed using keyless Sigstore/cosign
- **SLSA provenance**: Level 3 supply chain attestation via GitHub Actions

```bash
# Verify a downloaded artifact manually
cosign verify-blob --bundle rch-v0.2.0-linux.tar.gz.sigstore.json \
  --certificate-identity-regexp=".*" \
  --certificate-oidc-issuer-regexp=".*" \
  rch-v0.2.0-linux.tar.gz
```

---

## Algorithms and Design Principles

### Worker Selection Algorithm

When a compilation command is intercepted, RCH must quickly select the optimal worker. The selection algorithm considers multiple factors:

```
Score(worker) = SpeedScore × AvailabilityFactor × AffinityBonus × PriorityWeight

Where:
  SpeedScore        = Benchmark-derived CPU performance (0-100)
  AvailabilityFactor = AvailableSlots / TotalSlots (0-1)
  AffinityBonus     = 1.5 if worker has project cached, else 1.0
  PriorityWeight    = ConfiguredPriority / 100 (0-1)
```

The daemon maintains real-time slot counts using atomic operations—no locks required. When a job starts, slots are decremented; when it completes, they're incremented back. This lock-free design allows concurrent worker selection without contention.

### Transfer Optimization

File transfers use rsync with carefully tuned parameters:

```bash
rsync -az --compress-level=3 \
  --exclude='target/' \
  --exclude='.git/objects/' \
  --exclude='node_modules/' \
  --partial --inplace \
  --timeout=300 \
  source/ worker:dest/
```

Key optimizations:
- **zstd compression (level 3)**: Balances speed vs ratio—level 3 is ~400MB/s encoding
- **Exclusion patterns**: Skip derived artifacts that will be regenerated
- **Partial transfers**: Resume interrupted transfers instead of restarting
- **In-place updates**: Modify files directly to reduce I/O operations

For incremental builds (where worker already has an old project copy), rsync's delta algorithm transfers only changed blocks—typically <1% of total file size.

### Connection Pooling

SSH connections are expensive to establish (~200-500ms for handshake). RCH maintains a connection pool per worker:

```
ConnectionPool {
  worker_id -> [Connection; max_connections]

  get_connection():
    if pool has idle connection:
      return idle connection (reuse)
    if pool.size < max_connections:
      establish new connection
      return new connection
    else:
      wait for connection to become available
}
```

With SSH multiplexing enabled (`ControlMaster`), additional connections over an existing master are near-instant (~5ms).

### Compilation Deduplication

Multiple agents working in the same project may trigger identical builds simultaneously. RCH deduplicates these using broadcast channels:

```
InFlightCompilations {
  key: (project_path, command_hash) -> broadcast::Sender<Result>
}

on_compilation_request(project, command):
  key = (project, hash(command))

  if key in in_flight:
    # Another agent already running this exact build
    return in_flight[key].subscribe().await

  # First request—execute compilation
  sender = broadcast::channel()
  in_flight[key] = sender

  result = execute_on_worker(project, command)
  sender.send(result)

  remove in_flight[key]
  return result
```

When Agent A triggers `cargo build --release` and Agent B triggers the same command 2 seconds later, Agent B subscribes to A's result channel instead of starting a duplicate build. Both agents receive the same output and artifacts.

### Output Streaming Architecture

Compilation output streams back to agents in real-time via a buffered channel architecture:

```
Worker Process → SSH stdout → Daemon → Unix Socket → Hook → Agent

Buffering strategy:
  - 64KB buffer between SSH and daemon (high throughput)
  - Line-buffered between daemon and hook (low latency)
  - Hook outputs lines immediately to agent (no buffering)
```

The daemon performs ANSI color code translation on-the-fly to ensure terminal colors display correctly regardless of the SSH pseudo-terminal settings.

---

## Performance Characteristics

### Latency Budget

RCH is designed around strict latency budgets to remain imperceptible during normal development:

| Operation | Budget | Typical |
|-----------|--------|---------|
| Hook invocation (non-compilation) | <1ms | 0.1ms |
| Command classification | <5ms | 0.8ms |
| Worker selection | <10ms | 2ms |
| Connection (pooled) | <50ms | 5ms |
| File sync (incremental, <100 files changed) | <2s | 500ms |
| File sync (full project, 10K files) | <30s | 8s |

### When Remote Wins vs Local

Remote compilation provides speedup when:

```
T_local > T_transfer + T_remote + T_return

Where:
  T_local    = Local compilation time
  T_transfer = Time to sync files to worker
  T_remote   = Remote compilation time (faster due to more cores)
  T_return   = Time to sync artifacts back
```

**Sweet spot**: Projects with >30s local compile time, where workers have 2x+ core count advantage.

**Break-even point**: ~5-10 second local builds. Below this, overhead dominates.

RCH automatically estimates `T_local` based on project size and historical data, skipping remote execution when it's unlikely to help.

### Memory Usage

| Component | Idle | Active |
|-----------|------|--------|
| Hook (`rch`) | N/A (exits after check) | ~8MB peak |
| Daemon (`rchd`) | ~15MB | ~50MB (scales with concurrent jobs) |
| Worker (`rch-wkr`) | ~10MB | ~20MB + compilation process |

The daemon uses memory-mapped I/O for large file transfers, keeping resident memory low regardless of artifact size.

---

## Security Model

### Trust Boundaries

```
┌─────────────────────────────────────────────────────────────────┐
│                    AGENT WORKSTATION (trusted)                   │
│  ┌──────────┐     ┌─────────┐     ┌──────────┐                  │
│  │  Agent   │────▶│   rch   │────▶│   rchd   │                  │
│  │(Claude)  │     │ (hook)  │     │ (daemon) │                  │
│  └──────────┘     └─────────┘     └──────────┘                  │
│                                        │                         │
└────────────────────────────────────────┼─────────────────────────┘
                                         │ SSH (encrypted)
                                         ▼
┌─────────────────────────────────────────────────────────────────┐
│                    WORKER MACHINES (semi-trusted)                │
│  • Has read access to source code during compilation             │
│  • Returns artifacts (binaries, test results)                    │
│  • No persistent storage of source (cleaned after job)           │
│  • Isolated per-job directories                                  │
└─────────────────────────────────────────────────────────────────┘
```

### Recommendations

1. **Use workers you control**: Don't use shared infrastructure for proprietary code
2. **Network isolation**: Workers should be on a trusted network or VPN
3. **SSH key management**: Use dedicated keys for RCH with limited permissions
4. **Audit logging**: Enable `RCH_LOG_LEVEL=debug` for full command tracing

### What RCH Does NOT Do

- Store source code persistently on workers (cleaned after each job)
- Transmit credentials or secrets (excluded from sync by default)
- Execute arbitrary commands (only classified compilation commands)
- Modify source files (write-protected during remote execution)

---

## Integration with AI Coding Agents

RCH is specifically designed for multi-agent AI coding workflows. Here's how it integrates with popular tools:

### Claude Code

Claude Code's PreToolUse hook mechanism is RCH's primary integration point:

```json
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "Bash",
        "hooks": [
          {
            "type": "command",
            "command": "/home/user/.local/bin/rch"
          }
        ]
      }
    ]
  }
}
```

When Claude Code is about to execute a Bash command:
1. It calls `rch` with the command as JSON on stdin
2. `rch` classifies the command (<1ms for most commands)
3. If compilation: `rch` executes remotely and returns output
4. If not compilation: `rch` exits with code 0, letting Claude Code proceed normally

The agent never knows compilation happened remotely—artifacts appear in the expected locations.

### Multiple Simultaneous Agents

RCH shines when running 5, 10, or 15+ agents simultaneously:

| Agents | Without RCH | With RCH (4 workers, 64 total slots) |
|--------|-------------|--------------------------------------|
| 1 | Normal | ~Same (overhead not worth it) |
| 3 | CPU contention begins | Distributed across workers |
| 5 | Severe slowdown | Still responsive |
| 10 | System unusable | Workers at 50% capacity |
| 15+ | Crashes likely | Workers handling load |

The key insight: your workstation's CPU becomes a bottleneck far before your workers' combined capacity is exhausted.

### Agent-Aware Features

- **Deduplication**: Agents compiling the same project share results
- **Priority hints**: Mark urgent agent work with `RCH_PRIORITY=high`
- **Isolation**: Each agent's jobs are tracked separately for debugging
- **Fail-open**: If RCH has issues, agents continue with local builds

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
