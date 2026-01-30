# Changelog

All notable changes to the Remote Compilation Helper (RCH) project.

## [1.0.0] - 2026-01-30

The 1.0.0 release marks RCH as feature-complete for production use. This release represents approximately 3 weeks of intensive development with 827 commits, building the entire system from initial scaffold to a fully functional transparent compilation offloading system.

---

### Core Hook System

**Transparent Compilation Interception** - RCH integrates with Claude Code's PreToolUse hook system to intercept compilation commands transparently. The agent is unaware of remote execution; artifacts simply appear locally.

- **5-Tier Classification System** - High-precision command classification with sub-millisecond performance:
  - Tier 0: Instant reject (empty commands, non-Bash tools)
  - Tier 1: Structure analysis (pipes, redirects, backgrounding)
  - Tier 2: SIMD keyword filter (memchr-accelerated)
  - Tier 3: Negative pattern check (never-intercept commands)
  - Tier 4: Full classification with confidence scoring

- **Supported Compilation Commands**:
  - Rust: `cargo build`, `cargo test`, `cargo check`, `cargo clippy`, `cargo doc`, `cargo bench`, `cargo nextest run`
  - Bun/TypeScript: `bun test`, `bun typecheck`
  - C/C++: `gcc`, `g++`, `clang`, `clang++`
  - Build systems: `make`, `cmake --build`, `ninja`, `meson compile`

- **Smart Multi-Command Classification** - Commands chained with `&&`, `||`, or `;` are split and classified independently. If any sub-command is compilation, it triggers remote execution.

- **Zero-Allocation Hot Paths** - Classification strings use `Cow<'static, str>` to avoid heap allocations on the critical path.

---

### Worker Fleet Management

**Intelligent Worker Selection** - Multiple selection strategies optimize for different workloads:

- **Priority Strategy** - Respects configured worker priorities for preferred routing
- **Fastest Strategy** - Routes to workers with highest SpeedScore
- **Balanced Strategy** - Distributes load evenly across workers
- **CacheAffinity Strategy** - Routes projects to workers with warm caches
- **FairFastest Strategy** - Balances speed and fair distribution

**Health Monitoring & Circuit Breakers**:
- Automatic health probing with configurable intervals
- Circuit breaker pattern (Closed → Open → HalfOpen) for fault tolerance
- Consecutive failure tracking with configurable thresholds
- Automatic recovery with exponential backoff

**Worker Lifecycle Management**:
- `Healthy`, `Degraded`, `Unhealthy`, `Unknown`, `Draining`, `Drained`, `Disabled` statuses
- Graceful drain: stop new jobs, let existing jobs complete
- Manual enable/disable with optional reasons

**Slot-Based Concurrency** - Each worker declares total slots (typically CPU cores). The daemon tracks slot usage and never overcommits.

---

### Transfer Pipeline

**High-Performance File Synchronization**:
- rsync with zstd compression for efficient transfers
- Incremental sync (only changed files)
- Configurable exclusion patterns
- `.rchignore` support (similar to `.gitignore`)

**Artifact Retrieval**:
- Automatic retrieval of `target/` build artifacts
- Checksum verification for integrity
- Retry logic with exponential backoff for transient failures

**SSH Transport Hardening**:
- Configurable ServerAliveInterval and ControlPersist
- Connection pooling with ControlMaster
- Timeout handling for hung connections
- Identity file validation

---

### Daemon (rchd)

**Unix Socket API** - HTTP-like protocol over Unix socket for hook-daemon communication:

| Endpoint | Purpose |
|----------|---------|
| `GET /select-worker` | Request a worker for compilation |
| `POST /release-worker` | Release a reserved worker |
| `GET /status` | Full system status |
| `GET /health` | Kubernetes-style health check |
| `GET /ready` | Kubernetes-style readiness check |
| `GET /metrics` | Prometheus-format metrics |
| `GET /events` | Server-Sent Events stream |
| `POST /reload` | Hot-reload configuration |
| `POST /shutdown` | Graceful shutdown |

**Build Queue Management**:
- Wait-for-worker queueing when all workers busy
- FIFO queue with priority support
- Queue position tracking and ETA estimation

**Configuration Hot-Reload**:
- `rch daemon reload` or `SIGHUP` signal
- Add/remove/update workers without restart
- Validation before applying changes

**Event Bus**:
- Real-time event streaming for monitoring
- Events: `worker:selected`, `worker:released`, `build:started`, `build:completed`, `health:changed`

---

### CLI Commands

**Comprehensive Command Suite**:

```
rch status              # System overview with worker health
rch workers list        # List workers with slot usage
rch workers probe       # Test worker connectivity
rch workers deploy      # Deploy rch-wkr binary to workers
rch workers enable/disable/drain  # Lifecycle management
rch fleet deploy        # Parallel deployment to all workers
rch daemon start/stop/restart/reload  # Daemon control
rch config show/set/init  # Configuration management
rch doctor              # Diagnose and fix issues
rch check               # Quick health verification
rch update check/install/rollback  # Self-update system
```

**Rich Output Modes**:
- Interactive mode with colors and panels (TTY)
- JSON mode for programmatic access (`--json` or `RCH_JSON=1`)
- Plain text for non-TTY environments

**Short Flags** - Common options have short forms:
- `-a` for `--all`
- `-v` for `--verbose`
- `-f` for `--force`

**Confirmation Prompts** - Destructive actions require confirmation (can skip with `--yes`).

---

### Terminal UI (TUI)

**Interactive Dashboard** (`rch tui`):

- **Workers Panel** - Real-time worker status with health indicators
- **Build History Panel** - Recent builds with timing and outcomes
- **Detail Bar** - Full content preview of selected items
- **Help Overlay** - Keyboard shortcut reference (`?` to toggle)

**Keyboard Controls**:
- `Tab` / `Shift+Tab` - Navigate panels
- `j/k` or arrows - Navigate items
- `d` - Drain selected worker
- `e` - Enable selected worker
- `/` - Filter mode
- `q` - Quit

**Visual Indicators**:
- Unicode symbols for cross-terminal compatibility (no emoji)
- Color-coded status (green=healthy, yellow=degraded, red=unhealthy)
- Slot usage bars with percentage

**Sort Controls** - Build history sortable by time, duration, or worker.

---

### Self-Test System

**Remote Compilation Verification** - Proves the pipeline works end-to-end:

1. Applies unique test marker to source code
2. Builds locally for reference hash
3. Syncs source to worker
4. Builds on worker
5. Retrieves artifacts
6. Compares binary hashes

**Scheduled Self-Tests**:
- Configurable cron schedule
- History retention and reporting
- Alert on repeated failures

---

### Update System

**Self-Updating Capability**:
- `rch update check` - Check for new releases
- `rch update install` - Download and install update
- `rch update rollback` - Revert to previous version

**Security Features**:
- SHA256 checksum verification
- Sigstore signature verification (when bundle available)
- Backup of current binary before update

**Fleet Deployment** (`rch fleet deploy`):
- Parallel deployment to all workers
- Progress tracking per worker
- Version verification after install

---

### Telemetry & SpeedScore

**Worker Telemetry Collection**:
- CPU usage (overall, per-core, load average)
- Memory usage (used, available, swap)
- Disk I/O metrics
- Network throughput

**SpeedScore System** - Composite performance score (0-100) based on:
- CPU benchmark results
- Memory bandwidth
- Disk I/O speed
- Network latency

**Benchmark Scheduler**:
- Automatic re-benchmark on score staleness
- Drift detection triggers re-benchmark
- Manual trigger via API

---

### Configuration & Validation

**Configuration Files**:
- `~/.config/rch/config.toml` - User settings
- `~/.config/rch/workers.toml` - Worker definitions

**Setup Wizard** (`rch config init`):
- Interactive worker configuration
- SSH key validation
- Connectivity testing

**Comprehensive Validation**:
- SSH identity file existence and permissions
- rsync exclude pattern syntax
- Network address resolution
- Remote directory accessibility

---

### Error Handling & Diagnostics

**Structured Error Codes** - All errors have unique codes (RCH-Exxx):

| Range | Category |
|-------|----------|
| E001-E099 | Configuration errors |
| E100-E199 | Network/SSH errors |
| E200-E299 | Worker errors |
| E300-E399 | Build errors |
| E400-E499 | Daemon errors |
| E500-E599 | Internal errors |

**Rich Error Display**:
- Color-coded severity
- Contextual information (worker, host, command)
- Remediation suggestions
- Related documentation links

**Fail-Open Philosophy** - If anything fails, allow local execution rather than blocking the agent.

---

### Installation System

**One-Line Install**:
```bash
curl -fsSL https://raw.githubusercontent.com/Dicklesworthstone/remote_compilation_helper/main/install.sh | bash
```

**Installation Features**:
- Automatic binary download for platform
- Fallback to source build if binaries unavailable
- Claude Code hook integration
- Systemd/launchd service setup (optional)
- Shell completions (bash, zsh, fish)

**Agent Integration**:
- Automatic Claude Code `.claude.json` configuration
- Hook registration in `~/.claude/settings.json`

---

### Testing Infrastructure

**Comprehensive Test Coverage**:
- Unit tests with TestLogger (JSONL output)
- Integration tests for subsystems
- True end-to-end tests with real workers
- Property-based tests (proptest) for edge cases

**Test Categories**:
- Command classification tests
- Worker selection tests
- Transfer pipeline tests
- Fail-open behavior tests
- Exit code propagation tests
- Artifact integrity tests

**CI/CD Integration**:
- GitHub Actions workflows
- Dependabot automerge for patches
- Performance regression detection

---

### Performance Characteristics

| Operation | Target | Panic Threshold |
|-----------|--------|-----------------|
| Hook decision (non-compilation) | <1ms | 5ms |
| Hook decision (compilation) | <5ms | 10ms |
| Worker selection | <10ms | 50ms |
| Full pipeline overhead | <15% | 50% |

**Optimizations**:
- SIMD-accelerated keyword search (memchr)
- Zero-allocation classification paths
- In-memory timing history cache
- Connection pooling

---

### Security

- **No unsafe code** - `#![forbid(unsafe_code)]` enforced
- **Shell escaping** - All user input properly escaped
- **SSH key validation** - Permissions checked before use
- **Checksum verification** - All downloads verified
- **No secrets in config** - Identity files referenced by path

---

### Known Limitations

- Benchmark execution stub (placeholder for rch-benchmark integration)
- Changelog diff computation in update check (TODO)
- Rollback simulation (SSH restore not yet implemented)

---

## Contributors

Built with assistance from Claude Code AI agents using the Beads issue tracking system.

---

## License

MIT License - See LICENSE file for details.
