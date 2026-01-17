# Component Architecture Diagram

## Overview

RCH consists of three main components that work together to transparently offload compilation:

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                            AGENT WORKSTATION                                 │
│                                                                              │
│  ┌──────────────┐     ┌────────────────────────────────────────────────┐    │
│  │ Claude Code  │────▶│ rch (PreToolUse Hook)                          │    │
│  │ Agent 1..N   │     │                                                │    │
│  │              │     │  ┌──────────────────────────────────────────┐  │    │
│  │ AI coding    │     │  │         5-Tier Classifier                │  │    │
│  │ assistants   │     │  │                                          │  │    │
│  │ executing    │     │  │ T0: Instant reject (SIMD keywords)       │  │    │
│  │ Bash cmds    │     │  │ T1: Structure analysis (pipes, bg)       │  │    │
│  └──────────────┘     │  │ T2: Positive keyword match               │  │    │
│        │              │  │ T3: Negative pattern check               │  │    │
│        │              │  │ T4: Full classification + confidence     │  │    │
│        │              │  └──────────────────────────────────────────┘  │    │
│        │              │                    │                           │    │
│        │              │                    ▼                           │    │
│        │              │  ┌──────────────────────────────────────────┐  │    │
│        │              │  │         Transfer Pipeline                │  │    │
│        │              │  │                                          │  │    │
│        │              │  │ • rsync project → worker                 │  │    │
│        │              │  │ • zstd compression (level 3)             │  │    │
│        │              │  │ • Exclude target/, .git/, node_modules/  │  │    │
│        │              │  │ • rsync artifacts ← worker               │  │    │
│        │              │  └──────────────────────────────────────────┘  │    │
│        │              └───────────────────────┬────────────────────────┘    │
│        │                                      │                             │
│        │                                      │ Unix Socket                 │
│        │                                      │ ~/.cache/rch/rch.sock       │
│        │                                      ▼                             │
│        │              ┌───────────────────────────────────────────────────┐ │
│        │              │              rchd (Local Daemon)                  │ │
│        │              │                                                   │ │
│        │              │  ┌─────────────────┐  ┌─────────────────────────┐ │ │
│        │              │  │  Worker Pool    │  │    Selection Engine     │ │ │
│        │              │  │                 │  │                         │ │ │
│        │              │  │ • Health state  │  │ • Weighted scoring      │ │ │
│        │              │  │ • Slot tracking │  │ • Project affinity      │ │ │
│        │              │  │ • Circuit state │  │ • Load balancing        │ │ │
│        │              │  └─────────────────┘  └─────────────────────────┘ │ │
│        │              │                                                   │ │
│        │              │  ┌─────────────────┐  ┌─────────────────────────┐ │ │
│        │              │  │  SSH Pool       │  │    Build History        │ │ │
│        │              │  │                 │  │                         │ │ │
│        │              │  │ • Multiplexing  │  │ • Project records       │ │ │
│        │              │  │ • Conn reuse    │  │ • Performance stats     │ │ │
│        │              │  │ • Health check  │  │ • Deduplication         │ │ │
│        │              │  └─────────────────┘  └─────────────────────────┘ │ │
│        │              └───────────────────────────────────────────────────┘ │
│        │                                      │                             │
└────────┼──────────────────────────────────────┼─────────────────────────────┘
         │                                      │
         │                                      │ SSH (port 22)
         │                                      │ ControlMaster multiplexing
         │                                      ▼
┌────────┼────────────────────────────────────────────────────────────────────┐
│        │              WORKER FLEET (4+ machines, 48-80+ cores)              │
│        │                                                                    │
│        │   ┌─────────────────┐  ┌─────────────────┐  ┌─────────────────┐   │
│        │   │ Worker 1 (css)  │  │ Worker 2 (fra)  │  │ Worker N        │   │
│        │   │ 32 slots        │  │ 16 slots        │  │ 16 slots        │   │
│        │   │                 │  │                 │  │                 │   │
│        │   │ ┌─────────────┐ │  │ ┌─────────────┐ │  │ ┌─────────────┐ │   │
│        │   │ │  rch-wkr    │ │  │ │  rch-wkr    │ │  │ │  rch-wkr    │ │   │
│        │   │ │             │ │  │ │             │ │  │ │             │ │   │
│        │   │ │ • executor  │ │  │ │ • executor  │ │  │ │ • executor  │ │   │
│        │   │ │ • cache mgr │ │  │ │ • cache mgr │ │  │ │ • cache mgr │ │   │
│        │   │ │ • toolchain │ │  │ │ • toolchain │ │  │ │ • toolchain │ │   │
│        │   │ └─────────────┘ │  │ └─────────────┘ │  │ └─────────────┘ │   │
│        │   │                 │  │                 │  │                 │   │
│        │   │ Toolchains:     │  │ Toolchains:     │  │ Toolchains:     │   │
│        │   │ • rust nightly  │  │ • rust nightly  │  │ • rust nightly  │   │
│        │   │ • gcc/clang     │  │ • gcc/clang     │  │ • gcc/clang     │   │
│        │   │ • bun           │  │ • bun           │  │ • bun           │   │
│        │   └─────────────────┘  └─────────────────┘  └─────────────────┘   │
│        │                                                                    │
│        │   Project Caches:                                                  │
│        │   /tmp/rch/<project_id>/<hash>/                                    │
│        │                                                                    │
└────────┼────────────────────────────────────────────────────────────────────┘
         │
         ▼
    Agent receives
    output + artifacts
    as if local build
```

## Component Details

### rch (Hook CLI)

The hook binary that intercepts commands from AI coding agents.

| Module | Purpose | Key Files |
|--------|---------|-----------|
| `hook.rs` | Claude Code hook protocol handling | Parse JSON, emit response |
| `classify.rs` | Command classification | 5-tier system |
| `transfer.rs` | Project sync pipeline | rsync orchestration |
| `config.rs` | Configuration loading | TOML parsing, precedence |
| `fleet/` | Fleet deployment commands | Deploy, rollback, status |
| `ui/` | Output formatting | Themes, progress, adaptive |

### rchd (Local Daemon)

Long-running daemon that manages worker state and selection.

| Module | Purpose | Key Files |
|--------|---------|-----------|
| `workers.rs` | Worker pool management | State, slots, health |
| `selection.rs` | Worker selection algorithm | Scoring, affinity |
| `api.rs` | Unix socket API handler | Request routing |
| `health.rs` | Health monitoring | Heartbeats, circuit breaker |
| `history.rs` | Build history tracking | Stats, deduplication |

### rch-wkr (Worker Agent)

Agent running on remote workers to execute compilations.

| Module | Purpose | Key Files |
|--------|---------|-----------|
| `executor.rs` | Command execution | Streaming output |
| `cache.rs` | Project cache management | Cleanup, pruning |
| `toolchain.rs` | Rust toolchain management | Version detection |

### rch-common (Shared Library)

Shared types and utilities used by all components.

| Module | Purpose | Key Types |
|--------|---------|-----------|
| `types.rs` | Core domain types | WorkerId, BuildRecord |
| `protocol.rs` | Hook protocol types | HookInput, HookOutput |
| `patterns.rs` | Command classification | CompilationKind, keywords |
| `ssh.rs` | SSH client wrapper | SshClient, SshOptions |
| `config/` | Configuration system | Profiles, validation |

## Data Flow

1. **Hook Input**: Agent executes Bash command → hook receives JSON
2. **Classification**: 5-tier system determines if compilation
3. **Selection**: Daemon selects best available worker
4. **Transfer Out**: rsync syncs project to worker
5. **Execution**: Worker runs compilation command
6. **Transfer Back**: rsync returns artifacts
7. **Response**: Hook returns to agent silently

## Configuration Hierarchy

```
CLI flags
    ↓ overrides
Environment variables (RCH_*)
    ↓ overrides
Profile defaults (dev/prod/test)
    ↓ overrides
.env file
    ↓ overrides
Project config (.rch/config.toml)
    ↓ overrides
User config (~/.config/rch/config.toml)
    ↓ overrides
Built-in defaults
```

## Communication Protocols

### Hook ↔ Daemon (Unix Socket)

Simple HTTP-like protocol:

```
GET /select-worker?project=X&cores=N&toolchain=JSON&runtime=RUNTIME
→ {"worker": "css", "slots": 12, "speed": 87.3, "reason": "Success"}

POST /release-worker?worker=css&slots=4
→ {"released": true}

GET /status
→ {"workers": [...], "active_builds": 5, "uptime": 3600}
```

### Daemon ↔ Worker (SSH)

Command execution over SSH with connection multiplexing:

```bash
# Health check
ssh worker "rch-wkr health"
→ "OK"

# Capability detection
ssh worker "rch-wkr capabilities"
→ {"rustc": "1.80.0-nightly", "bun": "1.0.0", ...}

# Command execution
ssh worker "rch-wkr execute --workdir=/tmp/rch/proj_abc123 --command='cargo build'"
→ (streamed stdout/stderr)
```
