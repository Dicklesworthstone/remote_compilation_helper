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
- Bun/TypeScript: `bun test`, `bun typecheck`
- C/C++: `gcc`, `g++`, `clang`, `clang++`
- Build systems: `make`, `cmake --build`, `ninja`

**Commands NOT Intercepted (run locally):**
- Bun package management: `bun install`, `bun add`, `bun remove`, `bun link`
- Bun execution: `bun run`, `bun build`, `bun dev`, `bun repl`
- Bun package runner: `bun x` / `bunx` (like npx)
- Watch modes: `bun test --watch`, `bun typecheck --watch`
- Piped/redirected/backgrounded commands

**Rationale for Bun Interception:**
Bun's `test` and `typecheck` commands are CPU-intensive operations (running tests, type-checking large codebases) that benefit from remote execution, similar to `cargo test` and `cargo check`. Package management and dev servers must run locally because they modify `node_modules/` or bind to local ports.

**Pattern Matching Strategy:**
1. Quick keyword filter (SIMD-accelerated)
2. Full regex classification
3. Context extraction (working dir, project root, flags)

### Classification Details: cargo test

`cargo test` is fully supported with these characteristics:

| Property | Value |
|----------|-------|
| **CompilationKind** | `CargoTest` |
| **Confidence** | 0.95 |
| **RequiredRuntime** | `Rust` |
| **Artifact Patterns** | `target/debug/**`, `target/release/**` |

**Supported Variants (all classified as CargoTest):**
- `cargo test` — Basic test execution
- `cargo test --release` — Release mode tests
- `cargo test filter` — Run tests matching filter
- `cargo test -- --nocapture` — Show stdout during tests
- `cargo test --workspace` — Test all workspace packages
- `cargo test -p package` — Test specific package
- `cargo t` — Short alias for cargo test
- `cargo test --lib`, `--bins`, `--doc` — Target-specific tests
- `RUST_BACKTRACE=1 cargo test` — Environment variable wrappers

**Exit Code Semantics:**
```rust
const EXIT_SUCCESS: i32 = 0;        // All tests passed
const EXIT_BUILD_ERROR: i32 = 1;    // Build/compilation error
const EXIT_TEST_FAILURES: i32 = 101; // Tests ran but some failed
const EXIT_SIGNAL_BASE: i32 = 128;   // Process killed by signal N (exit = 128+N)
```

All non-zero exits deny local re-execution (correct behavior—re-running won't help).

### 2. Worker Fleet Management

Workers are remote Linux machines with:
- Passwordless SSH access via key
- Rust nightly toolchain
- GCC/Clang installed
- Bun runtime (for TypeScript/Bun projects)
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

## Beads (br) — Dependency-Aware Issue Tracking

Beads provides a lightweight, dependency-aware issue database and CLI (`br` / beads_rust) for selecting "ready work," setting priorities, and tracking status.

**Note:** `br` is non-invasive and never executes git commands. You must manually add, commit, and push `.beads/` changes.

**SQLite/WAL Caution:** br uses SQLite with WAL mode. Always run `br sync --flush-only` before git operations to ensure `.beads/` files are consistent.

### Quick Start

```bash
br ready --json                                    # Show issues ready to work (no blockers)
br create "Issue title" -t bug|feature|task -p 0-4 --json
br update br-42 --status in_progress --json
br close br-42 --reason "Completed" --json
br sync --flush-only                               # Export to JSONL
git add .beads/ && git commit -m "Sync beads" && git push
```

### Issue Types

- `bug` - Something broken
- `feature` - New functionality
- `task` - Work item (tests, docs, refactoring)
- `epic` - Large feature with subtasks
- `chore` - Maintenance (dependencies, tooling)

### Priorities

- `0` - Critical (security, data loss, broken builds)
- `1` - High (major features, important bugs)
- `2` - Medium (default, nice-to-have)
- `3` - Low (polish, optimization)
- `4` - Backlog (future ideas)

---

## bv — Graph-Aware Triage Engine

bv is a graph-aware triage engine for Beads projects (`.beads/beads.jsonl`). It computes PageRank, betweenness, critical path, cycles, HITS, eigenvector, and k-core metrics deterministically.

**CRITICAL: Use ONLY `--robot-*` flags. Bare `bv` launches an interactive TUI that blocks your session.**

### The Workflow: Start With Triage

**`bv --robot-triage` is your single entry point.** It returns:
- `quick_ref`: at-a-glance counts + top 3 picks
- `recommendations`: ranked actionable items with scores, reasons, unblock info
- `quick_wins`: low-effort high-impact items
- `blockers_to_clear`: items that unblock the most downstream work
- `project_health`: status/type/priority distributions, graph metrics
- `commands`: copy-paste shell commands for next steps

```bash
bv --robot-triage        # THE MEGA-COMMAND: start here
bv --robot-next          # Minimal: just the single top pick + claim command
```

### Command Reference

**Planning:**
| Command | Returns |
|---------|---------|
| `--robot-plan` | Parallel execution tracks with `unblocks` lists |
| `--robot-priority` | Priority misalignment detection with confidence |

**Graph Analysis:**
| Command | Returns |
|---------|---------|
| `--robot-insights` | Full metrics: PageRank, betweenness, HITS, eigenvector, critical path, cycles, k-core |
| `--robot-label-health` | Per-label health: `health_level`, `velocity_score`, `staleness`, `blocked_count` |

### jq Quick Reference

```bash
bv --robot-triage | jq '.quick_ref'                        # At-a-glance summary
bv --robot-triage | jq '.recommendations[0]'               # Top recommendation
bv --robot-plan | jq '.plan.summary.highest_impact'        # Best unblock target
bv --robot-insights | jq '.Cycles'                         # Circular deps (must fix!)
```

---

## UBS — Ultimate Bug Scanner

**Golden Rule:** `ubs <changed-files>` before every commit. Exit 0 = safe. Exit >0 = fix & re-run.

### Commands

```bash
ubs file.rs file2.rs                    # Specific files (< 1s) — USE THIS
ubs $(git diff --name-only --cached)    # Staged files — before commit
ubs --only=rust,toml src/               # Language filter (3-5x faster)
ubs .                                   # Whole project
```

### Output Format

```
Warning  Category (N errors)
    file.rs:42:5 - Issue description
    Suggested fix
Exit code: 1
```

Parse: `file:line:col` -> location | Suggested fix -> how to fix | Exit 0/1 -> pass/fail

### Bug Severity

- **Critical (always fix):** Memory safety, use-after-free, data races, SQL injection
- **Important (production):** Unwrap panics, resource leaks, overflow checks
- **Contextual (judgment):** TODO/FIXME, println! debugging

---

## ast-grep vs ripgrep

**Use `ast-grep` when structure matters.** It parses code and matches AST nodes, ignoring comments/strings, and can **safely rewrite** code.

- Refactors/codemods: rename APIs, change patterns
- Policy checks: enforce patterns across a repo

**Use `ripgrep` when text is enough.** Fastest way to grep literals/regex.

- Recon: find strings, TODOs, log lines, config values
- Pre-filter: narrow candidate files before ast-grep

### Rule of Thumb

- Need correctness or **applying changes** -> `ast-grep`
- Need raw speed or **hunting text** -> `rg`
- Often combine: `rg` to shortlist files, then `ast-grep` to match/modify

### Rust Examples

```bash
# Find structured code (ignores comments)
ast-grep run -l Rust -p 'fn $NAME($$$ARGS) -> $RET { $$$BODY }'

# Find all unwrap() calls
ast-grep run -l Rust -p '$EXPR.unwrap()'

# Quick textual hunt
rg -n 'println!' -t rust

# Combine speed + precision
rg -l -t rust 'unwrap\(' | xargs ast-grep run -l Rust -p '$X.unwrap()' --json
```

---

## Morph Warp Grep — AI-Powered Code Search

**Use `mcp__morph-mcp__warp_grep` for exploratory "how does X work?" questions.** An AI agent expands your query, greps the codebase, reads relevant files, and returns precise line ranges with full context.

**Use `ripgrep` for targeted searches.** When you know exactly what you're looking for.

### When to Use What

| Scenario | Tool | Why |
|----------|------|-----|
| "How is command classification implemented?" | `warp_grep` | Exploratory; don't know where to start |
| "Where is the worker selection algorithm?" | `warp_grep` | Need to understand architecture |
| "Find all uses of `Classification`" | `ripgrep` | Targeted literal search |
| "Replace all `unwrap()` with `expect()`" | `ast-grep` | Structural refactor |

### warp_grep Usage

```
mcp__morph-mcp__warp_grep(
  repoPath: "/path/to/rch",
  query: "How does the transfer pipeline work?"
)
```

### Anti-Patterns

- **Don't** use `warp_grep` to find a specific function name -> use `ripgrep`
- **Don't** use `ripgrep` to understand "how does X work" -> wastes time with manual reads

---

## cass — Cross-Agent Session Search

`cass` indexes prior agent conversations (Claude Code, Codex, Cursor, Gemini, ChatGPT, etc.) so we can reuse solved problems.

**Rules:** Never run bare `cass` (TUI). Always use `--robot` or `--json`.

### Examples

```bash
cass health
cass search "remote compilation" --robot --limit 5
cass view /path/to/session.jsonl -n 42 --json
cass expand /path/to/session.jsonl -n 42 -C 3 --json
cass capabilities --json
cass robot-docs guide
```

### Tips

- Use `--fields minimal` for lean output
- Filter by agent with `--agent`
- Use `--days N` to limit to recent history

stdout is data-only, stderr is diagnostics; exit code 0 means success.

Treat cass as a way to avoid re-solving problems other agents already handled.

<!-- bv-agent-instructions-v1 -->

---

## Beads Workflow Integration

This project uses [beads_rust](https://github.com/Dicklesworthstone/beads_rust) for issue tracking. Issues are stored in `.beads/` and tracked in git.

**Note:** `br` is non-invasive and never executes git commands. You must manually add, commit, and push `.beads/` changes.

**SQLite/WAL Caution:** br uses SQLite with WAL mode. Always run `br sync --flush-only` before git operations to ensure `.beads/` files are consistent.

### Essential Commands

```bash
# CLI commands for agents
br ready              # Show issues ready to work (no blockers)
br list --status=open # All open issues
br show <id>          # Full issue details with dependencies
br create --title="..." --type=task --priority=2
br update <id> --status=in_progress
br close <id> --reason="Completed"
br close <id1> <id2>  # Close multiple issues at once
br sync --flush-only  # Export to JSONL (then manually git add/commit/push)
```

### Workflow Pattern

1. **Start**: Run `br ready` to find actionable work
2. **Claim**: Use `br update <id> --status=in_progress`
3. **Work**: Implement the task
4. **Complete**: Use `br close <id>`
5. **Sync**: Always run sync workflow at session end:
   ```bash
   br sync --flush-only
   git add .beads/
   git commit -m "Sync beads"
   git push
   ```

### Key Concepts

- **Dependencies**: Issues can block other issues. `br ready` shows only unblocked work.
- **Priority**: P0=critical, P1=high, P2=medium, P3=low, P4=backlog (use numbers, not words)
- **Types**: task, bug, feature, epic, question, docs

<!-- end-bv-agent-instructions -->

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
   br sync --flush-only
   git add .beads/
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
   br sync --flush-only
   git add .beads/
   git commit -m "Sync beads"
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

---

## Note for Codex/GPT-5.2

You constantly bother me and stop working with concerned questions that look similar to this:

```
Unexpected changes (need guidance)

- Working tree still shows edits I did not make in Cargo.toml, Cargo.lock, rch/src/classify.rs, rchd/src/workers.rs. Please advise whether to keep/commit/revert these before any further work. I did not touch them.

Next steps (pick one)

1. Decide how to handle the unrelated modified files above so we can resume cleanly.
```

NEVER EVER DO THAT AGAIN. The answer is literally ALWAYS the same: those are changes created by the potentially dozen of other agents working on the project at the same time. This is not only a common occurence, it happens multiple times PER MINUTE. The way to deal with it is simple: you NEVER, under ANY CIRCUMSTANCE, stash, revert, overwrite, or otherwise disturb in ANY way the work of other agents. Just treat those changes identically to changes that you yourself made. Just fool yourself into thinking YOU made the changes and simply don't recall it for some reason.
