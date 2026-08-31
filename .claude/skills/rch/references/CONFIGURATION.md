# RCH Configuration Reference

## Contents

- [Precedence and File Locations](#precedence-and-file-locations)
- [Main Config (`~/.config/rch/config.toml`)](#main-config-configrchconfigtoml)
- [Workers Config (`~/.config/rch/workers.toml`)](#workers-config-configrchworkerstoml)
- [Project Overrides and `.rchignore`](#project-overrides-and-rchignore)
- [Daemon Config (`~/.config/rch/daemon.toml`)](#daemon-config-configrchdaemontoml)
- [Environment Variables](#environment-variables)
- [Hook Configuration (Claude Code)](#hook-configuration-claude-code)
- [Validation and Diagnostics](#validation-and-diagnostics)
- [Runtime Data Paths](#runtime-data-paths)

Values below are the code defaults in `rch-common/src/types.rs` /
`rchd/src/config.rs` as of main 2026-08-25 (v1.0.58). Verify live with
`rch config show --sources` and `rch --json config get <key>`.

## Precedence and File Locations

Highest to lowest (`rch --help`):

1. CLI flags (`--json`, `--no-self-healing`, …)
2. Environment variables (`RCH_*`)
3. Profile defaults (`RCH_PROFILE`) — only fill vars not already set
4. `.rch.env` (all keys) then `.env` (**only `RCH_`-prefixed keys**); never override existing process env
5. Project config `.rch/config.toml` (deep-merged over user config)
6. User config `~/.config/rch/config.toml`
7. Built-in defaults

Config directory resolution (`rch/src/config.rs`): `RCH_CONFIG_DIR` → an
**existing** `$XDG_CONFIG_HOME/rch` / `~/.config/rch` → an existing legacy
platform dir (macOS `~/Library/Application Support/com.rch.rch`) → fresh
install uses XDG. **macOS hazard:** on a box where only the legacy dir exists,
the CLI reads it while a launchd daemon may be pointed (`--workers-config`) at
`~/.config/rch/workers.toml` — two drifting worker lists. If both dirs exist,
XDG wins for the CLI. Keep one, and confirm with
`rch --json config show --sources`.

Primary files:

- User config: `~/.config/rch/config.toml`
- Worker list: `~/.config/rch/workers.toml`
- Daemon settings: `~/.config/rch/daemon.toml`
- Project override: `.rch/config.toml`
- Transfer excludes: `.rchignore`

## Main Config (`~/.config/rch/config.toml`)

Sections (all optional): `[general] [compilation] [transfer] [environment]
[circuit] [output] [self_healing] [self_test] [selection] [execution] [alerts]
[fleet] [path_topology] [doctor] [remediation] [layer0]`.

```toml
[general]
enabled = true
role = "hybrid"            # dispatcher | worker | hybrid. dispatcher ⇒ rch exec defaults to strict remote;
                           # worker ⇒ `rch shim install` refuses
force_local = false
force_remote = false
log_level = "info"         # trace, debug, info, warn, error, off
socket_path = ""           # default derives from $XDG_RUNTIME_DIR; macOS: ~/Library/Caches/rch/rch.sock

[compilation]
confidence_threshold = 0.85
min_local_time_ms = 2000
remote_speedup_threshold = 1.2
build_slots = 4
test_slots = 8
check_slots = 2
build_timeout_sec = 300     # everything not listed below
test_timeout_sec = 1800     # cargo test/nextest, nix build, go test
bun_timeout_sec = 600
external_timeout_enabled = true
allow_local_fallback = true # false ⇒ every local fallback is refused (fail-closed box)

[transfer]
compression_level = 3       # env RCH_COMPRESSION_LEVEL
remote_base = "/data/tmp/rch"   # staging base on workers (older docs said /tmp/rch)
# sync_timeout_ms = 120000  # per-attempt source upload; unset = 30s + 1s/MiB, capped 1h (1000..=3600000)
# ssh_server_alive_interval_secs = 15 # optional; unset by default (recommend 15 for long builds)
# ssh_control_persist_secs = 60       # opt-in ControlMaster; 0 disables
adaptive_compression = false          # tiers: <10MB→1, <200MB→3, else 7, clamped to min/max
min_compression_level = 1
max_compression_level = 9
verify_artifacts = false
verify_max_size_bytes = 104857600
# max_transfer_mb / max_transfer_time_ms / bwlimit_kbps / estimated_bandwidth_bps — all unset by default
exclude_patterns = ["target/", "*.rlib", "*.rmeta", ".git/", "node_modules/", ".beads/", ".doctor/", ".env", ".env.*", "*.pem", "*.key", "credentials.json", "secrets.json", "secrets.yaml", "dist/", "build/", ".next/", "coverage/"]  # abbreviated default list

[transfer.retry]
max_attempts = 3
base_delay_ms = 100
max_delay_ms = 5000
jitter_factor = 0.1
total_timeout_ms = 30000

[environment]
allowlist = []              # env RCH_ENV_ALLOWLIST (comma/space separated). CARGO_TARGET_DIR, TMPDIR/TMP/TEMP,
                            # GOCACHE/GOMODCACHE/GOPATH are ALWAYS rewritten to worker-scoped paths regardless

[execution]
allowlist = ["cargo","rustc","nextest","gcc","g++","clang","clang++","cc","c++","make","cmake","ninja","meson","bun","nix","go","tsc"]

[selection]
strategy = "balanced"       # priority | fastest | balanced | cache_affinity | fair_fastest
min_success_rate = 0.8
max_load_per_core = 2.0
min_free_gb = 10.0
[selection.weights]         # speedscore 0.5, slots 0.4, health 0.3, cache 0.2, network 0.1, priority 0.5, half_open_penalty 0.5
[selection.fairness]        # lookback_secs 300, max_consecutive_selections 3
[selection.affinity]        # enabled true, pin_minutes 60, enable_last_success_fallback true, fallback_min_success_rate 0.5

[circuit]
failure_threshold = 3
success_threshold = 2
error_rate_threshold = 0.5
window_secs = 60
open_cooldown_secs = 30
half_open_max_probes = 1

[output]
visibility = "none"         # none|silent|quiet, summary|short, verbose|debug. Refusal lines print regardless
first_run_complete = false
color_mode = "always"       # always|auto|never

[self_healing]
hook_starts_daemon = true
daemon_installs_hooks = true
auto_start_cooldown_secs = 30   # alias: auto_start_cooldown
auto_start_timeout_secs = 3     # aliases: daemon_start_timeout, auto_start_timeout
self_healing_log_level = "info"

[self_test]
enabled = false
# schedule / interval / workers = "all" | ["id", ...] / on_failure = alert|disable_worker|alert_and_disable
retry_count = 3
retry_delay = "5m"

[alerts]
enabled = true
suppress_duplicates_secs = 300
cleared_retention_secs = 300
# [alerts.webhook] url, secret, timeout_secs = 5, retry_count = 3, events = []

[fleet]
ssh_connect_timeout_secs = 10
ssh_command_timeout_secs = 30
min_disk_space_mb = 500
max_load_average = 10.0
max_concurrent_workers = 10
retry_count = 2
retry_delay_ms = 1000

[path_topology]
canonical_root = "/data/projects"   # env RCH_CANONICAL_PROJECT_ROOT; "" = unset; ~ expands
alias_root = "/dp"                  # env RCH_ALIAS_PROJECT_ROOT; set equal to canonical_root if you have no alias

[layer0]                    # Cargo profile pack forced onto remote release builds; hook path never injects
enabled = false
release_lto_thin = false
release_codegen_units_1 = false

[remediation.pooled_target]
pooling_enabled = true
reaper_enabled = false      # autonomous periodic reap ships OFF (prior fleet-wide deletion incident); rch gc runs it on demand
reaper_idle_hours = 12
reaper_interval_mins = 120
remote_base = "/data/projects"
reaper_pooled_idle_hours = 168   # 0 disables the pooled pass; 1..24 rejected
reaper_max_cache_gb = 0          # byte-cap LRU, 0 = off
# other [remediation.*]: policy (hook_exec_fail_open=true, proof_mode_fail_closed=true),
# temporary_bypass (backoff 30s..900s), auto_rejoin (required_consecutive_passes=2, canary_required=true,
# check_interval_secs=30, min_disk_free_gb=5.0, canary_command="rustc --version"),
# telemetry_freshness (max_age_secs=120), disk_pressure (warning_avail_pct=15, critical_avail_pct=5),
# incident_ledger (max_entries=5000, 4 MiB), reconciliation (max_attempts=3, time_budget_secs=120,
# state_hysteresis_ms=5000, staleness_threshold_secs=300), proof (store_path, stale-source policy),
# log_retention, build_root, smoke
```

`rch config show --sources` attributes `general, compilation, transfer,
environment, circuit, output, self_healing, self_test, path_topology, layer0`
plus the five env-settable `remediation.*` keys; `selection`, `execution`,
`alerts`, `fleet`, `doctor` and `transfer.retry.*` load but are not attributed.

## Workers Config (`~/.config/rch/workers.toml`)

```toml
[[workers]]
id = "worker-name"                      # required
host = "203.0.113.20"                   # required (hostname, IP, or ~/.ssh/config alias)
user = "ubuntu"                         # default "ubuntu"
identity_file = "~/.ssh/id_ed25519"     # default: first of ~/.ssh/{id_ed25519,id_rsa,id_ecdsa} that exists
total_slots = 16                        # default 8
priority = 100                          # default 100
tags = ["rust", "bun"]                  # default []; DESCRIPTIVE ONLY
# os = "windows"                        # optional hard gate; see below
enabled = true
```

| Field | Gates admission? | Notes |
|---|---|---|
| `total_slots` | yes (capacity) | Derive from a persisted SpeedScore + cores; see `SKILL.md` |
| `priority` | no (ordering) | Higher wins among equally eligible workers |
| `tags` | **no** | Purely descriptive. Nothing in rch matches on them; runtimes (rust/go/bun/nix) are *probed* |
| `os` | **yes (hard)** | `linux`/`darwin`/`windows`. Makes the worker exclusive to commands requiring that OS (`--target` triple). Normalized to a reserved `os:<name>` tag on load |
| `enabled` | yes | `false` removes it from the pool (admin-disabled) |

There is **no** `port`, `arch`, or `capabilities` field. A writer that omits
`os` silently un-fences the worker on the next write — edit with
`rch config edit --workers` or a full-file rewrite, never a partial regenerate.
Full `os` semantics and the Windows worker recipe: `WORKERS.md`.

## Project Overrides and `.rchignore`

`.rch/config.toml` uses the same schema and is deep-merged over the user
config (loaded from the literal relative path, so run from the project root).
Typical use: `[general] force_local = true` for a project that must build on
this host, or per-kind timeouts.

`.rchignore`: one pattern per line, `#` comments, whitespace trimmed,
**no `!` negation** (treated literally). Patterns are *additive* to
`transfer.exclude_patterns`.

## Daemon Config (`~/.config/rch/daemon.toml`)

```toml
socket_path = ""                     # default as above
health_check_interval_secs = 30
worker_timeout_secs = 10
max_jobs_per_slot = 1
connection_pooling = true
log_level = "info"

[queue]
enabled = false                      # daemon-side queue; hook-side RCH_QUEUE_WHEN_BUSY is what agents see
max_depth = 100                      # 0 = unlimited
timeout_secs = 300

[cache_cleanup]
enabled = true
interval_secs = 3600
max_cache_age_hours = 72
min_free_gb = 10
idle_threshold_secs = 60
remote_base = "/data/tmp/rch"

[stale_target_reap]                  # mirrors [remediation.pooled_target]; a drift-guard test keeps them equal
enabled = false
interval_mins = 120
idle_hours = 12
remote_base = "/data/projects"
pooled_idle_hours = 168
max_cache_gb = 0
```

Env overrides for the reaper: `RCH_WORKER_REAP_ENABLE`, `RCH_WORKER_REAP_DISABLE`
(disable always wins), `RCH_WORKER_REAP_INTERVAL_MINS`, `RCH_STALE_TARGET_REAP_HOURS`
(floored at 1h, default 12).

## Environment Variables

Loader-consumed (`rch config export` emits these names):

| Variable | Sets | Notes |
|---|---|---|
| `RCH_ENABLED` | `general.enabled` | `0/false/no/off` disables. Must be in the **process env** of the hook/`rch exec`; an inline prefix inside an agent's Bash command does not bypass the hook |
| `RCH_LOG_LEVEL` | `general.log_level` | `trace..off`; `RUST_LOG` (if set) overrides the whole filter |
| `RCH_FORCE_REMOTE` / `RCH_REQUIRE_REMOTE` | `general.force_remote` | REQUIRE also fails closed; wins over FORCE |
| `RCH_SOCKET_PATH` | `general.socket_path` | (`RCH_DAEMON_SOCKET` is **not** read by any code) |
| `RCH_CONFIDENCE_THRESHOLD`, `RCH_MIN_LOCAL_TIME_MS`, `RCH_REMOTE_SPEEDUP_THRESHOLD`, `RCH_BUILD_SLOTS`, `RCH_TEST_SLOTS`, `RCH_CHECK_SLOTS`, `RCH_BUILD_TIMEOUT_SEC`, `RCH_TEST_TIMEOUT_SEC`, `RCH_BUN_TIMEOUT_SEC`, `RCH_EXTERNAL_TIMEOUT_ENABLED` | `[compilation]` | |
| `RCH_COMPRESSION_LEVEL` (legacy alias `RCH_COMPRESSION`) | `transfer.compression_level` | `RCH_TRANSFER_ZSTD_LEVEL` only triggers a validator warning — it does nothing |
| `RCH_SYNC_TIMEOUT_MS` | `transfer.sync_timeout_ms` | per-attempt; 1000..=3600000 |
| `RCH_SSH_SERVER_ALIVE_INTERVAL_SECS`, `RCH_SSH_CONTROL_PERSIST_SECS` | `[transfer]` | |
| `RCH_ENV_ALLOWLIST` | `environment.allowlist` | comma and/or whitespace separated |
| `RCH_VISIBILITY` (`RCH_QUIET` > `RCH_VISIBILITY` > `RCH_VERBOSE`) | `output.visibility` | `none\|summary\|verbose` |
| `RCH_NO_SELF_HEALING` | master kill switch | when truthy the four below are ignored |
| `RCH_HOOK_STARTS_DAEMON`, `RCH_DAEMON_INSTALLS_HOOKS`, `RCH_AUTO_START_COOLDOWN_SECS`, `RCH_AUTO_START_TIMEOUT_SECS` | `[self_healing]` | |
| `RCH_CANONICAL_PROJECT_ROOT`, `RCH_ALIAS_PROJECT_ROOT` | `[path_topology]` | |
| `RCH_REMEDIATION_HOOK_EXEC_FAIL_OPEN`, `RCH_REMEDIATION_PROOF_FAIL_CLOSED`, `RCH_REMEDIATION_INCIDENT_MAX_ENTRIES`, `RCH_REMEDIATION_BYPASS_CHECK_INTERVAL_SECS`, `RCH_REMEDIATION_TELEMETRY_MAX_AGE_SECS` | `[remediation]` | |

Placement controls (resolved per command; visible in `rch diagnose --json` → `.data.placement`):

| Variable | Values | Effect |
|---|---|---|
| `RCH_WORKER` (alias `RCH_WORKERS`; both set ⇒ merged) | `id[,id…]` | request worker(s); an inadmissible requested worker is **refused** with an `RCH-Innn` code, never silently swapped |
| `RCH_PRESET` | profile name | recorded as `requested_profile` |
| `RCH_REQUIRE_REMOTE` / `RCH_FORCE_REMOTE` | `0\|1` | strict (fail-closed) vs. force (fail-open) |
| `RCH_QUEUE_WHEN_BUSY` | `0\|1` (default `1`) | wait for a slot instead of local fallback; unrecognized ⇒ warning, treated as 1 |
| `RCH_DAEMON_WAIT_RESPONSE_TIMEOUT_SECS` (alias `RCH_DAEMON_RESPONSE_TIMEOUT_SECS`) | secs > 0 | max wait for a queued worker |
| `RCH_DISABLE_TARGET_REUSE` | `0\|1` | legacy per-job remote target dir instead of pooled |

Hook/exec-side knobs that are **not** part of the placement plan (read directly
in `rch/src/hook.rs`): `RCH_PRIORITY` (`low|normal|high`, default `normal`;
invalid ⇒ `normal`), `RCH_MAX_REMOTE_ATTEMPTS` (u32 ≥ 1, default 3). The
queued-wait default behind `RCH_DAEMON_WAIT_RESPONSE_TIMEOUT_SECS` (and its
alias) is **330 s**; the non-queued daemon IPC default is 30 s and is not
env-tunable.

Other runtime: `RCH_CONFIG_DIR`, `RCH_STATE_HOME` (default `$XDG_STATE_HOME/rch`
→ `~/.local/state/rch`), `RCH_PROFILE` (`dev|prod|test`), `RCH_LOG_FORMAT`
(`pretty|json|compact`), `RCH_LOG_FILE`, `RCH_LOG_TARGETS`, `RCH_LOG_MAX_FILES` (7),
`RCH_JSON`, `RCH_HOOK_MODE`, `RCH_OUTPUT_FORMAT`, `TOON_DEFAULT_FORMAT`,
`NO_COLOR`/`FORCE_COLOR`/`CLICOLOR_FORCE`, `RCH_NO_UPDATE_CHECK`,
`RCH_CARGO_WRAPPER_BYPASS` (shim loop-break / bypass), `RCH_OTEL_*`,
`RCH_DISABLE_CONFIG_CACHE`, `RCH_MOCK_SSH` (tests).

Worker-side: `RCH_WORKER_ID` (falls back to `HOSTNAME`), `RCH_WKR_CANONICAL_ROOT`,
`RCH_WKR_ALIAS_ROOT`, `RCH_PREPARE_INSTALL_TIMEOUT_SECS`.

Validation-only names (appear in `rch --help`/validators but are **not read as
overrides**): `RCH_DAEMON_TIMEOUT_MS`, `RCH_SSH_KEY`, `RCH_TRANSFER_ZSTD_LEVEL`.
Non-existent: `RCH_DISABLED`, `RCH_BYPASS`, `RCH_FORCE_LOCAL`, `RCH_DAEMON_SOCKET`,
`RCH_LOG`, `RCH_DRY_RUN`, `RCH_NO_COLOR`.

Boolean parsing: loader accepts `1|true|yes|on` / `0|false|no|off|""`; the
placement resolver additionally accepts `enabled|disabled`.

## Hook Configuration (Claude Code)

`~/.claude/settings.json`:

```json
{ "hooks": { "PreToolUse": [ { "matcher": "Bash",
    "hooks": [ { "type": "command", "command": "/absolute/path/to/rch" } ] } ] } }
```

Gemini CLI: `~/.gemini/settings.json`; Codex CLI: `~/.codex/config.toml`
(`rch agents install-hook gemini-cli|codex-cli`). Manage with
`rch hook install|status|uninstall` (Claude Code) and `rch agents …`.
Non-hook agents/shells/CI get offload from the cargo shim — `SHIM.md`.

## Validation and Diagnostics

```bash
rch config show --sources
rch config validate            # TOML + value validation
rch config lint
rch config doctor              # semantic: missing identity_file keys, bad [[workers]] blocks, ...
rch config diff                # delta from defaults
rch check
```

## Runtime Data Paths

| Path | Purpose |
|---|---|
| `~/.local/share/rch/telemetry/telemetry.db` | telemetry / SpeedScore persistence (host running rchd) |
| `~/.local/share/rch/fleet_history/` | fleet deployment history |
| `~/.local/state/rch/` (`RCH_STATE_HOME`) | job leases, incident ledger, bypass records |
| `~/.cache/rch/` | cache; L2 project cache; `rabs-state/cas` |
| `${XDG_RUNTIME_DIR:-/tmp}/rch/hook_autostart.{lock,cooldown}` | hook autostart coordination |
| `~/.rch/shims/cargo` | managed cargo shim |
| `/data/tmp/rch` (worker) | default `transfer.remote_base` staging |
| `<remote project>/.rch-target-*`, `.rch-tmp/`, `.rch-go/` | managed per-project worker dirs (pooled target dirs, scratch, Go caches) |
| `/tmp/rch-source-authority-locks/` (worker) | source-authority flock files |
