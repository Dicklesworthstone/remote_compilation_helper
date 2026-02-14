# AGENTS.md — Remote Compilation Helper (RCH)

> Guidelines for AI coding agents working in this Rust codebase.

---

## RULE 0 - THE FUNDAMENTAL OVERRIDE PREROGATIVE

If I tell you to do something, even if it goes against what follows below, YOU MUST LISTEN TO ME. I AM IN CHARGE, NOT YOU.

---

## RULE NUMBER 1: NO FILE DELETION

**YOU ARE NEVER ALLOWED TO DELETE A FILE WITHOUT EXPRESS PERMISSION.** Even a new file that you yourself created, such as a test code file. You have a horrible track record of deleting critically important files or otherwise throwing away tons of expensive work. As a result, you have permanently lost any and all rights to determine that a file or folder should be deleted.

**YOU MUST ALWAYS ASK AND RECEIVE CLEAR, WRITTEN PERMISSION BEFORE EVER DELETING A FILE OR FOLDER OF ANY KIND.**

---

## Irreversible Git & Filesystem Actions — DO NOT EVER BREAK GLASS

1. **Absolutely forbidden commands:** `git reset --hard`, `git clean -fd`, `rm -rf`, or any command that can delete or overwrite code/data must never be run unless the user explicitly provides the exact command and states, in the same message, that they understand and want the irreversible consequences.
2. **No guessing:** If there is any uncertainty about what a command might delete or overwrite, stop immediately and ask the user for specific approval. "I think it's safe" is never acceptable.
3. **Safer alternatives first:** When cleanup or rollbacks are needed, request permission to use non-destructive options (`git status`, `git diff`, `git stash`, copying to backups) before ever considering a destructive command.
4. **Mandatory explicit plan:** Even after explicit user authorization, restate the command verbatim, list exactly what will be affected, and wait for a confirmation that your understanding is correct. Only then may you execute it—if anything remains ambiguous, refuse and escalate.
5. **Document the confirmation:** When running any approved destructive command, record (in the session notes / final response) the exact user text that authorized it, the command actually run, and the execution time. If that record is absent, the operation did not happen.

---

## Git Branch: ONLY Use `main`, NEVER `master`

**The default branch is `main`. The `master` branch exists only for legacy URL compatibility.**

- **All work happens on `main`** — commits, PRs, feature branches all merge to `main`
- **Never reference `master` in code or docs** — if you see `master` anywhere, it's a bug that needs fixing
- **The `master` branch must stay synchronized with `main`** — after pushing to `main`, also push to `master`:
  ```bash
  git push origin main:master
  ```

**If you see `master` referenced anywhere:**
1. Update it to `main`
2. Ensure `master` is synchronized: `git push origin main:master`

---

## Toolchain: Rust & Cargo

We only use **Cargo** in this project, NEVER any other package manager.

- **Edition:** Rust 2024 (nightly required — see `rust-toolchain.toml`)
- **Dependency versions:** Explicit versions for stability
- **Configuration:** Cargo.toml workspace with `workspace = true` pattern
- **Unsafe code:** Forbidden (`#![forbid(unsafe_code)]`)

### Key Dependencies

| Crate | Purpose |
|-------|---------|
| `serde` + `serde_json` | JSON parsing for Claude Code hook protocol |
| `tokio` | Async runtime for concurrent operations |
| `openssh` | SSH connections to remote workers |
| `memchr` | SIMD-accelerated substring search for command classification |
| `regex` | Command pattern matching |
| `blake3` | Fast hashing for project cache keys |
| `clap` | CLI argument parsing |
| `tracing` + `tracing-subscriber` + `tracing-appender` | Structured logging and diagnostics |
| `zstd` | Compression for transfer pipeline |
| `toml` + `directories` | Configuration loading |
| `thiserror` + `anyhow` + `miette` | Error handling with rich diagnostics |
| `axum` + `tower` + `hyper` | HTTP server for metrics endpoint |
| `ureq` | HTTP client for webhook dispatch |
| `opentelemetry` + `opentelemetry-otlp` | OpenTelemetry observability |
| `prometheus` | Metrics collection |
| `ratatui` + `crossterm` | TUI interface |
| `rich_rust` | Rich terminal output |
| `notify` | File watching for hot-reload |
| `uuid` | UUID generation |
| `chrono` | Time formatting |
| `toon-rust` | Serialization |

### Release Profile

The release build optimizes for size (lean binary for distribution):

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

## Compiler Checks (CRITICAL)

**After any substantive code changes, you MUST verify no errors were introduced:**

```bash
# Check for compiler errors and warnings (workspace-wide)
cargo check --workspace --all-targets

# Check for clippy lints (pedantic + nursery are enabled)
cargo clippy --workspace --all-targets -- -D warnings

# Verify formatting
cargo fmt --check
```

If you see errors, **carefully understand and resolve each issue**. Read sufficient context to fix them the RIGHT way.

---

## Testing

### Testing Policy

Every component crate includes inline `#[cfg(test)]` unit tests alongside the implementation. Tests must cover:
- Happy path
- Edge cases (empty input, max values, boundary conditions)
- Error conditions

Cross-component integration tests live in the workspace `tests/` directory.

### Unit Tests

```bash
# Run all tests across the workspace
cargo test --workspace

# Run with output
cargo test --workspace -- --nocapture

# Run tests for a specific crate
cargo test -p rch
cargo test -p rchd
cargo test -p rch-common
cargo test -p rch-wkr
cargo test -p rch-telemetry

# Run tests with all features enabled
cargo test --workspace --all-features
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

### Test Categories

| Crate | Focus Areas |
|-------|-------------|
| `rch` | Hook protocol, command classification, transfer pipeline, exit code handling |
| `rchd` | Worker state management, selection algorithm, SSH pool, daemon communication |
| `rch-wkr` | Remote executor, cache management |
| `rch-common` | Shared types, protocol parsing, pattern matching, UI components |
| `rch-telemetry` | OpenTelemetry integration, metrics collection |
| `tests/` (workspace) | True end-to-end tests with fixtures (hello_world, rust_workspace, failing_tests, etc.) |

---

## Third-Party Library Usage

If you aren't 100% sure how to use a third-party library, **SEARCH ONLINE** to find the latest documentation and current best practices.

---

## Remote Compilation Helper — This Project

**This is the project you're working on.** RCH is a transparent compilation offloading system that intercepts compilation commands from AI coding agents and executes them on remote worker machines. It integrates with Claude Code's PreToolUse hook system, similar to [Destructive Command Guard (DCG)](https://github.com/Dicklesworthstone/destructive_command_guard).

### What It Does

Intercepts compilation commands (cargo build/test/clippy, gcc, clang, bun test/typecheck, make, etc.) and transparently offloads them to a fleet of 8 remote Contabo VPS workers. This prevents compilation storms from overwhelming the local machine when many agents run simultaneously.

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

### Workspace Structure

```
remote_compilation_helper/
├── Cargo.toml              # Workspace root
├── rch/                    # Hook CLI binary
├── rchd/                   # Local daemon
├── rch-wkr/                # Worker agent
├── rch-common/             # Shared library
├── rch-telemetry/          # OpenTelemetry integration
├── tests/                  # True E2E tests with fixtures
├── examples/               # Usage examples
├── docs/                   # Documentation
├── scripts/                # Build/test scripts
└── install.sh              # Main installer script
```

### Key Files by Crate

| Crate | Key Files | Purpose |
|-------|-----------|---------|
| `rch` | `src/main.rs` | Hook entry point |
| `rch` | `src/hook.rs` | Claude Code hook protocol integration |
| `rch` | `src/classify.rs` | Command classification (compilation detection) |
| `rch` | `src/transfer.rs` | Code transfer pipeline (rsync + zstd) |
| `rchd` | `src/main.rs` | Daemon entry point |
| `rchd` | `src/workers.rs` | Worker state management |
| `rchd` | `src/selection.rs` | Worker selection algorithm |
| `rchd` | `src/ssh_pool.rs` | SSH connection pooling |
| `rch-wkr` | `src/executor.rs` | Remote command executor |
| `rch-wkr` | `src/cache.rs` | Project cache management |
| `rch-common` | `src/types.rs` | Shared types and protocol |
| `rch-common` | `src/protocol.rs` | Hook communication protocol |
| `rch-common` | `src/patterns.rs` | Compilation keyword/regex patterns |
| `rch-common` | `src/ui/` | UI module (context, display, error, icons, theme, progress) |
| `rch-telemetry` | `src/` | OpenTelemetry + Prometheus metrics |
| `~/.config/rch/config.toml` | User configuration |
| `~/.config/rch/workers.toml` | Worker definitions |

### Core Concepts

#### 1. Command Classification

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

#### Classification Details: cargo test

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

#### 2. Worker Fleet Management

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

#### 3. Transfer Pipeline

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

#### 4. Daemon Communication

The hook (`rch`) communicates with daemon (`rchd`) via Unix socket:

```
rch → /tmp/rch.sock → rchd
      ↓
      GET /select-worker?project=X&cores=4
      ←
      { "worker": "css", "slots": 12, "speed": 87.3 }
```

### Adding New Compilation Patterns

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

### Performance Requirements

Every Bash command passes through this hook. Performance is critical:

| Operation | Budget | Panic Threshold |
|-----------|--------|-----------------|
| Hook decision (non-compilation) | <1ms | 5ms |
| Hook decision (compilation) | <5ms | 10ms |
| Worker selection | <10ms | 50ms |
| Full pipeline | <15% overhead | 50% overhead |

**Fail-open philosophy:** If anything times out or errors, allow local execution rather than blocking.

### UI Design Principles for AI Agents

RCH uses context-aware output to work correctly with both humans and AI agents.

#### Output Mode Detection

RCH automatically detects the appropriate output mode:

| Context | Mode | Detected When | Output |
|---------|------|---------------|--------|
| Hook mode | `hook` | Called as Claude Code hook (stdin is JSON) | Pure JSON on stdout |
| Machine mode | `machine` | `RCH_JSON=1` or `--json` flag | Structured JSON |
| Interactive | `interactive` | stderr is TTY, human at terminal | Rich panels, colors |
| Colored | `colored` | `FORCE_COLOR=1` but no TTY | ANSI colors, no panels |
| Plain | `plain` | `NO_COLOR=1` or no TTY | Plain text only |

**Detection priority (first match wins):**
1. `RCH_JSON=1` → Machine mode
2. Hook invocation detected → Hook mode
3. `NO_COLOR` set → Plain mode
4. `FORCE_COLOR=0` → Plain mode
5. stderr is TTY → Interactive mode
6. `FORCE_COLOR` set → Colored mode
7. Default → Plain mode

#### Stream Separation (Critical!)

RCH follows Unix conventions:
- **stdout** is for DATA (JSON, compilation output, artifacts)
- **stderr** is for DIAGNOSTICS (status, progress, errors)

This means:
- Agents can reliably parse stdout without noise
- `rch status | jq` works correctly
- Compilation output passthrough is unaffected

#### Environment Variables

| Variable | Effect |
|----------|--------|
| `RCH_JSON=1` | Force JSON output mode |
| `RCH_HOOK_MODE=1` | Force hook mode (pure JSON) |
| `NO_COLOR=1` | Disable all ANSI colors |
| `FORCE_COLOR=1` | Enable colors even without TTY |
| `FORCE_COLOR=0` | Disable colors explicitly |

#### JSON Response Format

All JSON responses follow a standard envelope:

```json
{
  "api_version": "1.0",
  "timestamp": 1706000000,
  "command": "workers list",
  "success": true,
  "data": { ... },
  "error": null
}
```

On error:

```json
{
  "api_version": "1.0",
  "timestamp": 1706000000,
  "command": "workers probe",
  "success": false,
  "data": null,
  "error": {
    "code": "RCH-E100",
    "message": "SSH connection failed",
    "category": "network",
    "context": { "worker": "builder-1", "host": "192.168.1.100" },
    "remediation": [
      "Verify the worker host is reachable: ping 192.168.1.100",
      "Check that SSH service is running on the worker",
      "Try connecting manually: ssh user@192.168.1.100"
    ]
  }
}
```

#### Error Code Reference

Error codes follow the pattern `RCH-Ennn`:

| Range | Category | Examples |
|-------|----------|----------|
| E001-E099 | Configuration | `ConfigNotFound`, `ConfigParseError` |
| E100-E199 | Network/SSH | `SshConnectionFailed`, `SshAuthFailed` |
| E200-E299 | Worker | `WorkerUnreachable`, `WorkerBusy` |
| E300-E399 | Build | `BuildFailed`, `TransferError` |
| E400-E499 | Daemon | `DaemonNotRunning`, `SocketError` |
| E500-E599 | Internal | `InternalError` (unexpected errors) |

#### Exit Code Semantics

| Exit Code | Meaning |
|-----------|---------|
| 0 | Success |
| 1 | General error (configuration, etc.) |
| 2 | Command usage error |
| 100 | Network/SSH error |
| 101 | Worker error |
| 102 | Build failed (remote compilation) |
| 128+N | Process killed by signal N |

#### UI Module Structure

The UI module is located in `rch-common/src/ui/` with these components:

| Module | Purpose |
|--------|---------|
| `context.rs` | Output mode detection (`OutputContext`) |
| `display.rs` | Error display utilities (`display_error`, `error_to_panel`) |
| `error.rs` | `ErrorPanel` component for rich error display |
| `icons.rs` | Unicode icons with ASCII fallbacks |
| `theme.rs` | `RchTheme` colors and styling |
| `progress.rs` | Progress bars, spinners, build status |

Key principles:
- All rich output goes to stderr
- Every error includes an error code
- Always provide remediation steps
- Support graceful degradation to plain text

### Dependabot — Update + Automerge Policy

Dependabot is configured in `.github/dependabot.yml` to open weekly update PRs for:
- GitHub Actions (grouped)
- Cargo workspace dependencies (grouped; core deps like `tokio*`, `serde*`, `hyper*` are separated)
- npm dependencies under `/web` (grouped dev vs prod)

Automerge is handled by `.github/workflows/dependabot-automerge.yml`:
- **Auto-merge GitHub Actions PRs** (after CI passes)
- **Auto-merge semver patch PRs** (after CI passes)
- Minor/major updates are **not** auto-merged and require review.

Agent guidance:
- Treat Dependabot PRs like normal code: fix CI failures rather than merging around them.
- If you change deps manually, keep `Cargo.lock` changes in the same commit.

### Key Design Decisions

- **Fail-open philosophy** — if anything times out or errors, allow local execution rather than blocking
- **SIMD-accelerated keyword filter** using `memchr` for sub-millisecond command classification
- **Two-phase classification** — quick keyword filter first, then full regex only for candidates
- **Unix socket daemon communication** — minimal latency for hook → daemon IPC
- **rsync + zstd transfer pipeline** — incremental sync with compression for fast code transfer
- **Structured tracing** throughout — every operation emits spans with latency and context
- **Context-aware output** — automatic detection of hook/machine/interactive/plain modes
- **Stream separation** — stdout for data, stderr for diagnostics (Unix convention)
- **Size-optimized release builds** — `opt-level = "z"` + `panic = "abort"` for lean distribution binary

---

## MCP Agent Mail — Multi-Agent Coordination

A mail-like layer that lets coding agents coordinate asynchronously via MCP tools and resources. Provides identities, inbox/outbox, searchable threads, and advisory file reservations with human-auditable artifacts in Git.

### Why It's Useful

- **Prevents conflicts:** Explicit file reservations (leases) for files/globs
- **Token-efficient:** Messages stored in per-project archive, not in context
- **Quick reads:** `resource://inbox/...`, `resource://thread/...`

### Same Repository Workflow

1. **Register identity:**
   ```
   ensure_project(project_key=<abs-path>)
   register_agent(project_key, program, model)
   ```

2. **Reserve files before editing:**
   ```
   file_reservation_paths(project_key, agent_name, ["src/**"], ttl_seconds=3600, exclusive=true)
   ```

3. **Communicate with threads:**
   ```
   send_message(..., thread_id="FEAT-123")
   fetch_inbox(project_key, agent_name)
   acknowledge_message(project_key, agent_name, message_id)
   ```

4. **Quick reads:**
   ```
   resource://inbox/{Agent}?project=<abs-path>&limit=20
   resource://thread/{id}?project=<abs-path>&include_bodies=true
   ```

### Macros vs Granular Tools

- **Prefer macros for speed:** `macro_start_session`, `macro_prepare_thread`, `macro_file_reservation_cycle`, `macro_contact_handshake`
- **Use granular tools for control:** `register_agent`, `file_reservation_paths`, `send_message`, `fetch_inbox`, `acknowledge_message`

### Common Pitfalls

- `"from_agent not registered"`: Always `register_agent` in the correct `project_key` first
- `"FILE_RESERVATION_CONFLICT"`: Adjust patterns, wait for expiry, or use non-exclusive reservation
- **Auth errors:** If JWT+JWKS enabled, include bearer token with matching `kid`

---

## Beads (br) — Dependency-Aware Issue Tracking

Beads provides a lightweight, dependency-aware issue database and CLI (`br` - beads_rust) for selecting "ready work," setting priorities, and tracking status. It complements MCP Agent Mail's messaging and file reservations.

**Important:** `br` is non-invasive—it NEVER runs git commands automatically. You must manually commit changes after `br sync --flush-only`.

### Conventions

- **Single source of truth:** Beads for task status/priority/dependencies; Agent Mail for conversation and audit
- **Shared identifiers:** Use Beads issue ID (e.g., `br-123`) as Mail `thread_id` and prefix subjects with `[br-123]`
- **Reservations:** When starting a task, call `file_reservation_paths()` with the issue ID in `reason`

### Typical Agent Flow

1. **Pick ready work (Beads):**
   ```bash
   br ready --json  # Choose highest priority, no blockers
   ```

2. **Reserve edit surface (Mail):**
   ```
   file_reservation_paths(project_key, agent_name, ["src/**"], ttl_seconds=3600, exclusive=true, reason="br-123")
   ```

3. **Announce start (Mail):**
   ```
   send_message(..., thread_id="br-123", subject="[br-123] Start: <title>", ack_required=true)
   ```

4. **Work and update:** Reply in-thread with progress

5. **Complete and release:**
   ```bash
   br close 123 --reason "Completed"
   br sync --flush-only  # Export to JSONL (no git operations)
   ```
   ```
   release_file_reservations(project_key, agent_name, paths=["src/**"])
   ```
   Final Mail reply: `[br-123] Completed` with summary

### Mapping Cheat Sheet

| Concept | Value |
|---------|-------|
| Mail `thread_id` | `br-###` |
| Mail subject | `[br-###] ...` |
| File reservation `reason` | `br-###` |
| Commit messages | Include `br-###` for traceability |

---

## bv — Graph-Aware Triage Engine

bv is a graph-aware triage engine for Beads projects (`.beads/beads.jsonl`). It computes PageRank, betweenness, critical path, cycles, HITS, eigenvector, and k-core metrics deterministically.

**Scope boundary:** bv handles *what to work on* (triage, priority, planning). For agent-to-agent coordination (messaging, work claiming, file reservations), use MCP Agent Mail.

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
| `--robot-insights` | Full metrics: PageRank, betweenness, HITS, eigenvector, critical path, cycles, k-core, articulation points, slack |
| `--robot-label-health` | Per-label health: `health_level`, `velocity_score`, `staleness`, `blocked_count` |
| `--robot-label-flow` | Cross-label dependency: `flow_matrix`, `dependencies`, `bottleneck_labels` |
| `--robot-label-attention [--attention-limit=N]` | Attention-ranked labels |

**History & Change Tracking:**
| Command | Returns |
|---------|---------|
| `--robot-history` | Bead-to-commit correlations |
| `--robot-diff --diff-since <ref>` | Changes since ref: new/closed/modified issues, cycles |

**Other:**
| Command | Returns |
|---------|---------|
| `--robot-burndown <sprint>` | Sprint burndown, scope changes, at-risk items |
| `--robot-forecast <id\|all>` | ETA predictions with dependency-aware scheduling |
| `--robot-alerts` | Stale issues, blocking cascades, priority mismatches |
| `--robot-suggest` | Hygiene: duplicates, missing deps, label suggestions |
| `--robot-graph [--graph-format=json\|dot\|mermaid]` | Dependency graph export |
| `--export-graph <file.html>` | Interactive HTML visualization |

### Scoping & Filtering

```bash
bv --robot-plan --label backend              # Scope to label's subgraph
bv --robot-insights --as-of HEAD~30          # Historical point-in-time
bv --recipe actionable --robot-plan          # Pre-filter: ready to work
bv --recipe high-impact --robot-triage       # Pre-filter: top PageRank
bv --robot-triage --robot-triage-by-track    # Group by parallel work streams
bv --robot-triage --robot-triage-by-label    # Group by domain
```

### Understanding Robot Output

**All robot JSON includes:**
- `data_hash` — Fingerprint of source beads.jsonl
- `status` — Per-metric state: `computed|approx|timeout|skipped` + elapsed ms
- `as_of` / `as_of_commit` — Present when using `--as-of`

**Two-phase analysis:**
- **Phase 1 (instant):** degree, topo sort, density
- **Phase 2 (async, 500ms timeout):** PageRank, betweenness, HITS, eigenvector, cycles

### jq Quick Reference

```bash
bv --robot-triage | jq '.quick_ref'                        # At-a-glance summary
bv --robot-triage | jq '.recommendations[0]'               # Top recommendation
bv --robot-plan | jq '.plan.summary.highest_impact'        # Best unblock target
bv --robot-insights | jq '.status'                         # Check metric readiness
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
ubs --ci --fail-on-warning .            # CI mode — before PR
ubs .                                   # Whole project (ignores target/, Cargo.lock)
```

### Output Format

```
⚠️  Category (N errors)
    file.rs:42:5 – Issue description
    💡 Suggested fix
Exit code: 1
```

Parse: `file:line:col` → location | 💡 → how to fix | Exit 0/1 → pass/fail

### Fix Workflow

1. Read finding → category + fix suggestion
2. Navigate `file:line:col` → view context
3. Verify real issue (not false positive)
4. Fix root cause (not symptom)
5. Re-run `ubs <file>` → exit 0
6. Commit

### Bug Severity

- **Critical (always fix):** Memory safety, use-after-free, data races, SQL injection
- **Important (production):** Unwrap panics, resource leaks, overflow checks
- **Contextual (judgment):** TODO/FIXME, println! debugging

---

## RCH — Remote Compilation Helper

RCH offloads `cargo build`, `cargo test`, `cargo clippy`, and other compilation commands to a fleet of 8 remote Contabo VPS workers instead of building locally. This prevents compilation storms from overwhelming csd when many agents run simultaneously.

**RCH is installed at `~/.local/bin/rch` and is hooked into Claude Code's PreToolUse automatically.** Most of the time you don't need to do anything if you are Claude Code — builds are intercepted and offloaded transparently.

To manually offload a build:
```bash
rch exec -- cargo build --release
rch exec -- cargo test
rch exec -- cargo clippy
```

Quick commands:
```bash
rch doctor                    # Health check
rch workers probe --all       # Test connectivity to all 8 workers
rch status                    # Overview of current state
rch queue                     # See active/waiting builds
```

If rch or its workers are unavailable, it fails open — builds run locally as normal.

**Note for Codex/GPT-5.2:** Codex does not have the automatic PreToolUse hook, but you can (and should) still manually offload compute-intensive compilation commands using `rch exec -- <command>`. This avoids local resource contention when multiple agents are building simultaneously.

---

## ast-grep vs ripgrep

**Use `ast-grep` when structure matters.** It parses code and matches AST nodes, ignoring comments/strings, and can **safely rewrite** code.

- Refactors/codemods: rename APIs, change import forms
- Policy checks: enforce patterns across a repo
- Editor/automation: LSP mode, `--json` output

**Use `ripgrep` when text is enough.** Fastest way to grep literals/regex.

- Recon: find strings, TODOs, log lines, config values
- Pre-filter: narrow candidate files before ast-grep

### Rule of Thumb

- Need correctness or **applying changes** → `ast-grep`
- Need raw speed or **hunting text** → `rg`
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

**Use `ast-grep` for structural patterns.** When you need AST precision for matching/rewriting.

### When to Use What

| Scenario | Tool | Why |
|----------|------|-----|
| "How is command classification implemented?" | `warp_grep` | Exploratory; don't know where to start |
| "Where is the worker selection algorithm?" | `warp_grep` | Need to understand architecture |
| "Find all uses of `Classification`" | `ripgrep` | Targeted literal search |
| "Find files with `println!`" | `ripgrep` | Simple pattern |
| "Replace all `unwrap()` with `expect()`" | `ast-grep` | Structural refactor |

### warp_grep Usage

```
mcp__morph-mcp__warp_grep(
  repoPath: "/dp/remote_compilation_helper",
  query: "How does the transfer pipeline work?"
)
```

Returns structured results with file paths, line ranges, and extracted code snippets.

### Anti-Patterns

- **Don't** use `warp_grep` to find a specific function name → use `ripgrep`
- **Don't** use `ripgrep` to understand "how does X work" → wastes time with manual reads
- **Don't** use `ripgrep` for codemods → risks collateral edits

<!-- bv-agent-instructions-v1 -->

---

## Beads Workflow Integration

This project uses [beads_rust](https://github.com/Dicklesworthstone/beads_rust) (`br`) for issue tracking. Issues are stored in `.beads/` and tracked in git.

**Important:** `br` is non-invasive—it NEVER executes git commands. After `br sync --flush-only`, you must manually run `git add .beads/ && git commit`.

### Essential Commands

```bash
# View issues (launches TUI - avoid in automated sessions)
bv

# CLI commands for agents (use these instead)
br ready              # Show issues ready to work (no blockers)
br list --status=open # All open issues
br show <id>          # Full issue details with dependencies
br create --title="..." --type=task --priority=2
br update <id> --status=in_progress
br close <id> --reason "Completed"
br close <id1> <id2>  # Close multiple issues at once
br sync --flush-only  # Export to JSONL (NO git operations)
```

### Workflow Pattern

1. **Start**: Run `br ready` to find actionable work
2. **Claim**: Use `br update <id> --status=in_progress`
3. **Work**: Implement the task
4. **Complete**: Use `br close <id>`
5. **Sync**: Run `br sync --flush-only` then manually commit

### Key Concepts

- **Dependencies**: Issues can block other issues. `br ready` shows only unblocked work.
- **Priority**: P0=critical, P1=high, P2=medium, P3=low, P4=backlog (use numbers, not words)
- **Types**: task, bug, feature, epic, question, docs
- **Blocking**: `br dep add <issue> <depends-on>` to add dependencies

### Session Protocol

**Before ending any session, run this checklist:**

```bash
git status              # Check what changed
git add <files>         # Stage code changes
br sync --flush-only    # Export beads to JSONL
git add .beads/         # Stage beads changes
git commit -m "..."     # Commit everything together
git push                # Push to remote
```

### Best Practices

- Check `br ready` at session start to find available work
- Update status as you work (in_progress → closed)
- Create new issues with `br create` when you discover tasks
- Use descriptive titles and set appropriate priority/type
- Always `br sync --flush-only && git add .beads/` before ending session

<!-- end-bv-agent-instructions -->

## Landing the Plane (Session Completion)

**When ending a work session**, you MUST complete ALL steps below.

**MANDATORY WORKFLOW:**

1. **File issues for remaining work** - Create issues for anything that needs follow-up
2. **Run quality gates** (if code changed) - Tests, linters, builds
3. **Update issue status** - Close finished work, update in-progress items
4. **Sync beads** - `br sync --flush-only` to export to JSONL
5. **Hand off** - Provide context for next session


---

Note for Codex/GPT-5.2:

You constantly bother me and stop working with concerned questions that look similar to this:

```
Unexpected changes (need guidance)

- Working tree still shows edits I did not make in Cargo.toml, Cargo.lock, rch/src/classify.rs, rchd/src/workers.rs. Please advise whether to keep/commit/revert these before any further work. I did not touch them.

Next steps (pick one)

1. Decide how to handle the unrelated modified files above so we can resume cleanly.
```

NEVER EVER DO THAT AGAIN. The answer is literally ALWAYS the same: those are changes created by the potentially dozen of other agents working on the project at the same time. This is not only a common occurence, it happens multiple times PER MINUTE. The way to deal with it is simple: you NEVER, under ANY CIRCUMSTANCE, stash, revert, overwrite, or otherwise disturb in ANY way the work of other agents. Just treat those changes identically to changes that you yourself made. Just fool yourself into thinking YOU made the changes and simply don't recall it for some reason.

---

## Note on Built-in TODO Functionality

Also, if I ask you to explicitly use your built-in TODO functionality, don't complain about this and say you need to use beads. You can use built-in TODOs if I tell you specifically to do so. Always comply with such orders.
