# Configuration Guide

This guide consolidates how RCH configuration works, where files live, and how
values are resolved when multiple layers exist.

## Overview

RCH has three primary configuration surfaces:

1. **Hook/CLI config** (`config.toml`) for interception, transfer, and circuit
   breaker behavior.
2. **Worker definitions** (`workers.toml`) for daemon-managed worker inventory.
3. **Daemon settings** (`daemon.toml`) for health checks and socket behavior.

## Precedence (Hook/CLI Config)

For `rch` (the hook/CLI), the effective configuration is resolved in this order
(lowest to highest):

1. Built-in defaults
2. User config: `~/.config/rch/config.toml`
3. Project config: `.rch/config.toml`
4. Environment variables (RCH_*)
5. Command-line flags (when a command supports them)

Tip: use `rch config show --sources` to see where each value came from.

Note: the config library includes support for `.env` / `.rch.env` files and
profile presets (via `RCH_PROFILE`), but the current `rch` loader only applies
user/project config + env overrides. Verify your effective values with
`rch config show --sources`.

## Hook/CLI Config File (`config.toml`)

Location:
- User: `~/.config/rch/config.toml`
- Project: `.rch/config.toml`

Sections and fields:

### `[general]`
- `enabled` (bool, default `true`) — Master on/off switch for the hook.
- `log_level` (string, default `"info"`) — `trace|debug|info|warn|error`.
- `socket_path` (string, default `"/tmp/rch.sock"`) — Unix socket path used to
  communicate with the daemon.

### `[compilation]`
- `confidence_threshold` (float, default `0.85`) — Minimum classifier confidence
  to intercept a command.
- `min_local_time_ms` (u64, default `2000`) — Skip interception if the estimated
  local runtime is shorter than this.

### `[transfer]`
- `compression_level` (u32, default `3`) — zstd compression level.
- `exclude_patterns` (list) — Patterns excluded from transfer. Defaults include:
  `target/`, `.git/objects/`, `node_modules/`, common build caches, and
  coverage output. Use `rch config show` to see the full effective list.

### `[circuit]`
- `failure_threshold` (u32, default `3`) — Consecutive failures to open.
- `success_threshold` (u32, default `2`) — Consecutive successes to close.
- `error_rate_threshold` (float, default `0.5`) — Error rate to open in window.
- `window_secs` (u64, default `60`) — Rolling error window size.
- `open_cooldown_secs` (u64, default `30`) — Cooldown before half-open.
- `half_open_max_probes` (u32, default `1`) — Concurrent probes allowed.

Example:

```toml
[general]
enabled = true
log_level = "info"
socket_path = "/tmp/rch.sock"

[compilation]
confidence_threshold = 0.85
min_local_time_ms = 2000

[transfer]
compression_level = 3
exclude_patterns = ["target/", "node_modules/"]

[circuit]
failure_threshold = 3
success_threshold = 2
error_rate_threshold = 0.5
window_secs = 60
open_cooldown_secs = 30
half_open_max_probes = 1
```

## Workers Config (`workers.toml`)

Location: `~/.config/rch/workers.toml`

Each worker entry:
- `id` (string, required) — Unique identifier.
- `host` (string, required) — Hostname or IP.
- `user` (string, default `"ubuntu"`) — SSH user.
- `identity_file` (string, default `"~/.ssh/id_rsa"`) — SSH key path.
- `total_slots` (u32, default `8`) — CPU slots available.
- `priority` (u32, default `100`) — Higher = preferred.
- `tags` (list, default `[]`) — Optional selection tags.
- `enabled` (bool, default `true`) — Skip worker if false.

Example:

```toml
[[workers]]
id = "worker-1"
host = "203.0.113.20"
user = "ubuntu"
identity_file = "~/.ssh/id_rsa"
total_slots = 16
priority = 100
tags = ["ssd", "fast"]
enabled = true
```

## Daemon Config (`daemon.toml`)

Location: `~/.config/rch/daemon.toml`

Fields:
- `socket_path` (default `/tmp/rch.sock`) — Unix socket path.
- `health_check_interval_secs` (default `30`) — Health check cadence.
- `worker_timeout_secs` (default `10`) — Mark worker unreachable after timeout.
- `max_jobs_per_slot` (default `1`) — Max concurrent jobs per slot.
- `connection_pooling` (default `true`) — Reuse SSH connections.
- `log_level` (default `"info"`) — Daemon logging level.

## Environment Variables (RCH_*)

RCH uses environment variables for overrides, tooling, and testing. The list
below groups variables by intent. If you are unsure whether a variable is
applied in your version, verify with `rch config show --sources` or `rch --help`.

### Core runtime overrides (hook/CLI)
These are read by the hook configuration loader:

- `RCH_ENABLED`
- `RCH_LOG_LEVEL`
- `RCH_SOCKET_PATH`
- `RCH_CONFIDENCE_THRESHOLD`
- `RCH_COMPRESSION`

### CLI/daemon options (documented in `rch --help` / validators)

- `RCH_PROFILE`
- `RCH_LOG_FORMAT`
- `RCH_DAEMON_SOCKET`
- `RCH_DAEMON_TIMEOUT_MS`
- `RCH_SSH_KEY`
- `RCH_TRANSFER_ZSTD_LEVEL`
- `RCH_ENABLE_METRICS`
- `RCH_TEST_MODE`

### Hook integration variables
Used by hook integration scripts (see `docs/extending/integration-hooks.md`):

- `RCH_COMMAND`
- `RCH_PROJECT`
- `RCH_ESTIMATED_CORES`
- `RCH_WORKER`
- `RCH_LAST_BUILD_WORKER`
- `RCH_BUILD_SUCCESS`
- `RCH_BUILD_ERROR`
- `RCH_AVAILABLE_WORKERS`
- `RCH_TEST_HOOK`

### Web dashboard

- `RCH_API_URL`

### Installer / setup helpers

- `RCH_CONFIG_DIR`
- `RCH_INSTALL_DIR`
- `RCH_NO_COLOR`
- `RCH_NO_HOOK`
- `RCH_SKIP_DOCTOR`
- `RCH_INIT_HOST`
- `RCH_VERBOSE`

### Mocking, test, and CI helpers

- `RCH_MOCK_SSH`
- `RCH_MOCK_CIRCUIT_OPEN`
- `RCH_MOCK_NO_RUSTUP`
- `RCH_MOCK_RSYNC_BYTES`
- `RCH_MOCK_RSYNC_FAIL_ARTIFACTS`
- `RCH_MOCK_RSYNC_FAIL_SYNC`
- `RCH_MOCK_RSYNC_FILES`
- `RCH_MOCK_SSH_DELAY_MS`
- `RCH_MOCK_SSH_EXIT_CODE`
- `RCH_MOCK_SSH_FAIL_CONNECT`
- `RCH_MOCK_SSH_FAIL_EXECUTE`
- `RCH_MOCK_SSH_STDERR`
- `RCH_MOCK_SSH_STDOUT`
- `RCH_MOCK_TOOLCHAIN_INSTALL_FAIL`
- `RCH_E2E_VERBOSE`
- `RCH_E2E_WORKERS_FILE`
- `RCH_E2E_WORKER_HOST`
- `RCH_E2E_WORKER_ID`
- `RCH_E2E_WORKER_KEY`
- `RCH_E2E_WORKER_SLOTS`
- `RCH_E2E_WORKER_USER`
- `RCH_CIRCUIT_FAILURE_THRESHOLD`
- `RCH_CIRCUIT_RESET_TIMEOUT_SEC`
- `RCH_DAEMON_TIMEOUT_MS`
- `RCH_OTEL_ENABLED`
- `RCH_PRESET`
- `RCH_BAD_BOOL`
- `RCH_TEST_`
- `RCH_TEST_1`
- `RCH_TEST_123`
- `RCH_TEST_12345`
- `RCH_TEST_99999`
- `RCH_TEST_BOOL_FALSE`
- `RCH_TEST_BOOL_TRUE`
- `RCH_TEST_LIST`
- `RCH_TEST_MARKER_UNIQUE_12345_XYZ`
- `RCH_TEST_OK`
- `RCH_TEST_OPT`
- `RCH_TEST_SRC`
- `RCH_TEST_U64`
- `RCH_TEST_U64_OOR`
- `RCH_TEST_WORKER_HOST`
- `RCH_TEST_WORKER_KEY`
- `RCH_TEST_WORKER_USER`

### Documented but not yet wired in code

These appear in docs/README but are not currently used by the config loader:

- `RCH_BYPASS`
- `RCH_DRY_RUN`
- `RCH_LOCAL_ONLY`
- `RCH_STREAM_MODE`
- `RCH_WORKERS`
- `RCH_NO_CACHE`

## Per-Project Configuration

Use `.rch/config.toml` when you need project-specific behavior (e.g. disable
RCH for a repo or change thresholds). Only the sections above are recognized;
unknown keys are ignored.

## Debugging Configuration

- `rch config show` — Show effective config
- `rch config show --sources` — Show value origins
- `rch config export` — Export config to shell/.env format
- `rch doctor` — Diagnose common misconfigurations

## Related Docs

- `docs/QUICKSTART.md`
- `docs/TROUBLESHOOTING.md`
- `docs/runbooks/configuration-troubleshooting.md`
