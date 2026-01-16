# AGENTS.md — Remote Compilation Helper (RCH)

> Guidelines for AI coding agents working in this Rust codebase.

---

## RULE NUMBER 1: NO FILE DELETION

**YOU ARE NEVER ALLOWED TO DELETE A FILE WITHOUT EXPRESS PERMISSION.** Even a new file that you yourself created, such as a test code file. You have a horrible track record of deleting critically important files or otherwise throwing away tons of expensive work. As a result, you have permanently lost any and all rights to determine that a file or folder should be deleted.

**YOU MUST ALWAYS ASK AND RECEIVE CLEAR, WRITTEN PERMISSION BEFORE EVER DELETING A FILE OR FOLDER OF ANY KIND.**

---

## Project Overview

**Remote Compilation Helper (RCH)** is a transparent compilation offloading system that intercepts compilation commands from AI coding agents and executes them on remote worker machines. It integrates with Claude Code's PreToolUse hook system, similar to [Destructive Command Guard (DCG)](https://github.com/Dicklesworthstone/destructive_command_guard).

### Key Differences from DCG

| Aspect | DCG | RCH |
|--------|-----|-----|
| Purpose | Block dangerous commands | Redirect compilation commands |
| Hook behavior | Deny and explain | Intercept, execute remotely, return artifacts |
| Agent awareness | Agent knows command was blocked | Agent is unaware of remote execution |
| Output | JSON denial + colorful warning | Silent (artifacts appear locally) |

### Architecture

```
Claude Code → PreToolUse Hook → RCH
                                 ↓
                            Is compilation?
                           /           \
                          No            Yes
                          ↓              ↓
                      Pass through   Select worker
                                         ↓
                                   Transfer code (rsync + zstd)
                                         ↓
                                   Execute remotely
                                         ↓
                                   Return artifacts
                                         ↓
                                   Silent success
```

---

## Irreversible Git & Filesystem Actions — DO NOT EVER BREAK GLASS

1. **Absolutely forbidden commands:** `git reset --hard`, `git clean -fd`, `rm -rf`, or any command that can delete or overwrite code/data must never be run unless the user explicitly provides the exact command and states, in the same message, that they understand and want the irreversible consequences.
2. **No guessing:** If there is any uncertainty about what a command might delete or overwrite, stop immediately and ask the user for specific approval. "I think it's safe" is never acceptable.
3. **Safer alternatives first:** When cleanup or rollbacks are needed, request permission to use non-destructive options (`git status`, `git diff`, `git stash`, copying to backups) before ever considering a destructive command.
4. **Mandatory explicit plan:** Even after explicit user authorization, restate the command verbatim, list exactly what will be affected, and wait for a confirmation that your understanding is correct. Only then may you execute it—if anything remains ambiguous, refuse and escalate.
5. **Document the confirmation:** When running any approved destructive command, record (in the session notes / final response) the exact user text that authorized it, the command actually run, and the execution time. If that record is absent, the operation did not happen.

---

## Toolchain: Rust & Cargo

We only use **Cargo** in this project, NEVER any other package manager.

- **Edition:** Rust 2024 (nightly required — see `rust-toolchain.toml`)
- **Dependency versions:** Explicit versions for stability
- **Configuration:** Cargo.toml only
- **Unsafe code:** Forbidden (`#![forbid(unsafe_code)]`)

### Key Dependencies

| Crate | Purpose |
|-------|---------|
| `serde` + `serde_json` | JSON parsing for Claude Code hook protocol |
| `tokio` | Async runtime for concurrent operations |
| `ssh2` or `openssh` | SSH connections to remote workers |
| `memchr` | SIMD-accelerated substring search for command classification |
| `regex` | Command pattern matching |
| `blake3` | Fast hashing for project cache keys |
| `tracing` | Structured logging |
| `clap` | CLI argument parsing |

### Workspace Structure

```
remote_compilation_helper/
├── Cargo.toml              # Workspace manifest
├── rch/                    # Hook CLI binary
├── rchd/                   # Local daemon
├── rch-wkr/                # Worker agent
└── rch-common/             # Shared library
```

### Release Profile

```toml
[profile.release]
opt-level = "z"     # Optimize for size (lean binary for distribution)
lto = true          # Link-time optimization
codegen-units = 1   # Single codegen unit for better optimization
panic = "abort"     # Smaller binary, no unwinding overhead
strip = true        # Remove debug symbols
```

---

## Code Editing Discipline

### No Script-Based Changes

**NEVER** run a script that processes/changes code files in this repo. Brittle regex-based transformations create far more problems than they solve.

- **Always make code changes manually**, even when there are many instances
- For many simple changes: use parallel subagents
- For subtle/complex changes: do them methodically yourself

### No File Proliferation

If you want to change something or add a feature, **revise existing code files in place**.

**NEVER** create variations like:
- `mainV2.rs`
- `main_improved.rs`
- `main_enhanced.rs`

New files are reserved for **genuinely new functionality** that makes zero sense to include in any existing file. The bar for creating new files is **incredibly high**.

---

## Backwards Compatibility

We do not care about backwards compatibility—we're in early development with no users. We want to do things the **RIGHT** way with **NO TECH DEBT**.

- Never create "compatibility shims"
- Never create wrapper functions for deprecated APIs
- Just fix the code directly

---

## Core Concepts

### 1. Command Classification

RCH must identify compilation commands with high precision:

**Supported Commands:**
- Rust: `cargo build`, `cargo test`, `cargo run`, `cargo check`, `rustc`
- C/C++: `gcc`, `g++`, `clang`, `clang++`
- Build systems: `make`, `cmake --build`, `ninja`

**Pattern Matching Strategy:**
1. Quick keyword filter (SIMD-accelerated)
2. Full regex classification
3. Context extraction (working dir, project root, flags)

### 2. Worker Fleet Management

Workers are remote Linux machines with:
- Passwordless SSH access via key
- Rust nightly toolchain
- GCC/Clang installed
- rsync and zstd available

**Worker Selection Algorithm:**
- Available slots (CPU cores not in use)
- Speed score (from benchmarking)
- Cached project locality

### 3. Transfer Pipeline

```
Local Project → rsync + zstd → Remote /tmp/rch/{project}_{hash}/
                                         ↓
                               Execute compilation
                                         ↓
                               tar + zstd → Local target/
```

**Excluded from transfer:**
- `target/`
- `.git/objects/`
- `node_modules/`
- Build artifacts (`.rlib`, `.rmeta`, `.o`)

### 4. Daemon Communication

The hook (`rch`) communicates with daemon (`rchd`) via Unix socket:

```
rch → /tmp/rch.sock → rchd
      ↓
      GET /select-worker?project=X&cores=4
      ←
      { "worker": "css", "slots": 12, "speed": 87.3 }
```

---

## Performance Requirements

Every Bash command passes through this hook. Performance is critical:

| Operation | Budget | Panic Threshold |
|-----------|--------|-----------------|
| Hook decision (non-compilation) | <1ms | 5ms |
| Hook decision (compilation) | <5ms | 10ms |
| Worker selection | <10ms | 50ms |
| Full pipeline | <15% overhead | 50% overhead |

**Fail-open philosophy:** If anything times out or errors, allow local execution rather than blocking.

---

## Compiler Checks (CRITICAL)

**After any substantive code changes, you MUST verify no errors were introduced:**

```bash
# Check for compiler errors and warnings
cargo check --all-targets

# Check for clippy lints
cargo clippy --all-targets -- -D warnings

# Verify formatting
cargo fmt --check
```

If you see errors, **carefully understand and resolve each issue**. Read sufficient context to fix them the RIGHT way.

---

## Testing

### Unit Tests

```bash
# Run all tests
cargo test

# Run with output
cargo test -- --nocapture

# Run specific workspace member
cargo test -p rch
cargo test -p rchd
cargo test -p rch-common
```

### Integration Tests

```bash
# Test command classification
cargo test -p rch classify

# Test worker selection
cargo test -p rchd selection
```

### End-to-End Testing

```bash
# With real workers
./scripts/e2e_test.sh

# With mock SSH (faster)
RCH_MOCK_SSH=1 ./scripts/e2e_test.sh
```

---

## Module Ownership

When making changes, respect these module boundaries:

| Module | Purpose | Key Files |
|--------|---------|-----------|
| `rch` | Hook CLI | `hook.rs`, `classify.rs`, `transfer.rs` |
| `rchd` | Daemon | `workers.rs`, `selection.rs`, `ssh_pool.rs` |
| `rch-wkr` | Worker agent | `executor.rs`, `cache.rs` |
| `rch-common` | Shared types | `types.rs`, `protocol.rs`, `patterns.rs` |

---

## Adding New Compilation Patterns

1. Add keyword to quick filter in `rch-common/src/patterns.rs`
2. Add regex pattern in same file
3. Add classifier case in `rch/src/classify.rs`
4. Add tests for all variants
5. Run `cargo test` to verify

Example:

```rust
// In patterns.rs
pub static COMPILATION_KEYWORDS: &[&str] = &[
    "cargo", "rustc",
    "gcc", "g++", "clang",
    "make", "cmake", "ninja",
    "meson",  // ← Add new keyword
];

// In classify.rs
pub fn classify_command(cmd: &str) -> Classification {
    // ...
    if cmd.starts_with("meson compile") {
        return Classification::BuildSystem(BuildSystemKind::Meson);
    }
}
```

---

## Third-Party Library Usage

If you aren't 100% sure how to use a third-party library, **SEARCH ONLINE** to find the latest documentation and best practices.

---

## MCP Agent Mail — Multi-Agent Coordination

See the MCP Agent Mail section in the DCG AGENTS.md for full details. Key points:

- Register identity with `ensure_project` + `register_agent`
- Reserve files with `file_reservation_paths` before editing
- Communicate via `send_message` with thread IDs
- Always `acknowledge_message` when `ack_required=true`

---

## Beads (bd) — Issue Tracking

This project uses beads for lightweight issue tracking:

```bash
bd ready              # Show issues ready to work
bd list --status=open # All open issues
bd create --title="..." --type=task --priority=2
bd update <id> --status=in_progress
bd close <id>
bd sync               # Persist changes
```

---

## Session Completion Protocol

**When ending a work session**, you MUST complete ALL steps below:

1. **Run quality gates** (if code changed):
   ```bash
   cargo check --all-targets
   cargo clippy --all-targets -- -D warnings
   cargo test
   ```

2. **Update beads**:
   ```bash
   bd sync --flush-only
   ```

3. **Commit and push** (if applicable):
   ```bash
   git add .
   git commit -m "..."
   git push
   ```

**CRITICAL:** Work is NOT complete until changes are synced. NEVER leave uncommitted work.

---

## Key Files Reference

| File | Purpose |
|------|---------|
| `PLAN_TO_MAKE_REMOTE_COMPILATION_HELPER.md` | Comprehensive implementation plan |
| `install.sh` | Main installer script |
| `rch/src/main.rs` | Hook entry point |
| `rch/src/hook.rs` | Claude Code hook protocol |
| `rch/src/classify.rs` | Command classification |
| `rchd/src/main.rs` | Daemon entry point |
| `rchd/src/workers.rs` | Worker state management |
| `~/.config/rch/config.toml` | User configuration |
| `~/.config/rch/workers.toml` | Worker definitions |

## Landing the Plane (Session Completion)

**When ending a work session**, you MUST complete ALL steps below. Work is NOT complete until `git push` succeeds.

**MANDATORY WORKFLOW:**

1. **File issues for remaining work** - Create issues for anything that needs follow-up
2. **Run quality gates** (if code changed) - Tests, linters, builds
3. **Update issue status** - Close finished work, update in-progress items
4. **PUSH TO REMOTE** - This is MANDATORY:
   ```bash
   git pull --rebase
   bd sync
   git push
   git status  # MUST show "up to date with origin"
   ```
5. **Clean up** - Clear stashes, prune remote branches
6. **Verify** - All changes committed AND pushed
7. **Hand off** - Provide context for next session

**CRITICAL RULES:**
- Work is NOT complete until `git push` succeeds
- NEVER stop before pushing - that leaves work stranded locally
- NEVER say "ready to push when you are" - YOU must push
- If push fails, resolve and retry until it succeeds
