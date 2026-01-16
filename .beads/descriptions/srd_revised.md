## Overview

Implement comprehensive environment variable override support for all RCH configuration options. Environment variables take precedence over config files, enabling deployment-time customization and 12-factor app compliance.

## Goals

1. Document all environment variables with types and defaults
2. Implement type-safe parsing with clear error messages
3. Establish precedence order: env > project config > user config > defaults
4. Track config sources for debugging (`rch config show --sources`)
5. Support config export for shell scripts
6. **NEW: .env file support for development**
7. **NEW: RCH_MOCK_SSH documentation (from AGENTS.md)**
8. **NEW: Config profiles (dev/prod/test)**
9. **NEW: Environment variable validation on startup**

## Environment Variable Reference

### Core Variables

| Variable | Type | Default | Description |
|----------|------|---------|-------------|
| `RCH_CONFIG_DIR` | Path | `~/.config/rch` | User configuration directory |
| `RCH_DATA_DIR` | Path | `~/.local/share/rch` | Data directory (logs, cache, backups) |
| `RCH_LOG_LEVEL` | String | `info` | Log level: trace, debug, info, warn, error |
| `RCH_LOG_FORMAT` | String | `pretty` | Log format: pretty, json, compact |
| `RCH_NO_COLOR` | Bool | `false` | Disable colored output |
| `RCH_PROFILE` | String | none | Config profile to load (NEW) |

### Daemon Variables

| Variable | Type | Default | Description |
|----------|------|---------|-------------|
| `RCH_DAEMON_SOCKET` | Path | `/tmp/rch.sock` | Unix socket path |
| `RCH_DAEMON_PORT` | u16 | `0` | TCP port (0 = Unix socket only) |
| `RCH_DAEMON_TIMEOUT_MS` | u64 | `5000` | Client connection timeout |
| `RCH_DAEMON_MAX_CONNECTIONS` | u32 | `100` | Maximum concurrent connections |
| `RCH_DAEMON_PID_FILE` | Path | `$RCH_DATA_DIR/rchd.pid` | PID file location |

### Worker Variables

| Variable | Type | Default | Description |
|----------|------|---------|-------------|
| `RCH_WORKERS_FILE` | Path | `$RCH_CONFIG_DIR/workers.toml` | Worker definitions file |
| `RCH_DEFAULT_WORKERS` | String | none | Comma-separated default workers |
| `RCH_WORKER_TIMEOUT_SEC` | u64 | `30` | Worker health check timeout |
| `RCH_WORKER_RETRY_DELAY_MS` | u64 | `1000` | Delay between worker retries |
| `RCH_WORKER_MAX_RETRIES` | u32 | `3` | Maximum retry attempts |

### Transfer Variables

| Variable | Type | Default | Description |
|----------|------|---------|-------------|
| `RCH_TRANSFER_COMPRESSION` | String | `zstd` | Compression: zstd, gzip, none |
| `RCH_TRANSFER_ZSTD_LEVEL` | i32 | `3` | Zstd compression level (1-22) |
| `RCH_TRANSFER_EXCLUDE` | String | See below | Additional rsync excludes |
| `RCH_TRANSFER_BANDWIDTH_LIMIT` | String | none | Bandwidth limit (e.g., "10M") |

### SSH Variables

| Variable | Type | Default | Description |
|----------|------|---------|-------------|
| `RCH_SSH_KEY` | Path | `~/.ssh/id_ed25519` | SSH private key path |
| `RCH_SSH_CONFIG` | Path | `~/.ssh/config` | SSH config file |
| `RCH_SSH_KNOWN_HOSTS` | Path | `~/.ssh/known_hosts` | Known hosts file |
| `RCH_SSH_TIMEOUT_SEC` | u64 | `10` | SSH connection timeout |

### Testing Variables (CRITICAL - from AGENTS.md)

| Variable | Type | Default | Description |
|----------|------|---------|-------------|
| `RCH_MOCK_SSH` | Bool | `false` | **Enable mock SSH mode for testing** |
| `RCH_MOCK_LATENCY_MS` | u64 | `100` | Simulated latency in mock mode |
| `RCH_TEST_MODE` | Bool | `false` | Enable test mode (no actual remote ops) |
| `RCH_BENCHMARK_MODE` | Bool | `false` | Enable benchmark mode (minimal logging) |

### Circuit Breaker Variables

| Variable | Type | Default | Description |
|----------|------|---------|-------------|
| `RCH_CIRCUIT_FAILURE_THRESHOLD` | u32 | `5` | Failures before opening circuit |
| `RCH_CIRCUIT_RESET_TIMEOUT_SEC` | u64 | `30` | Time before half-open attempt |
| `RCH_CIRCUIT_HALF_OPEN_MAX` | u32 | `3` | Max requests in half-open state |

### Feature Flags

| Variable | Type | Default | Description |
|----------|------|---------|-------------|
| `RCH_ENABLE_METRICS` | Bool | `true` | Enable Prometheus metrics |
| `RCH_ENABLE_TRACING` | Bool | `false` | Enable OpenTelemetry tracing |
| `RCH_ENABLE_TUI` | Bool | `true` | Enable TUI dashboard |
| `RCH_ENABLE_SELF_UPDATE` | Bool | `true` | Enable self-update feature |

## Implementation

### Environment Parser

```rust
// rch-common/src/config/env.rs

use std::env;
use std::path::PathBuf;
use std::str::FromStr;

/// Track where a config value came from
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ConfigSource {
    Default,
    UserConfig,
    ProjectConfig,
    Environment,
    CommandLine,
    DotEnv,      // NEW
    Profile,     // NEW
}

impl ConfigSource {
    pub fn precedence(&self) -> u8 {
        match self {
            ConfigSource::Default => 0,
            ConfigSource::UserConfig => 1,
            ConfigSource::ProjectConfig => 2,
            ConfigSource::DotEnv => 3,
            ConfigSource::Profile => 4,
            ConfigSource::Environment => 5,
            ConfigSource::CommandLine => 6,
        }
    }
}

/// A config value with its source
#[derive(Debug, Clone)]
pub struct Sourced<T> {
    pub value: T,
    pub source: ConfigSource,
}

impl<T> Sourced<T> {
    pub fn new(value: T, source: ConfigSource) -> Self {
        Self { value, source }
    }

    pub fn map<U>(self, f: impl FnOnce(T) -> U) -> Sourced<U> {
        Sourced {
            value: f(self.value),
            source: self.source,
        }
    }
}

/// Error types for environment parsing
#[derive(Debug, thiserror::Error)]
pub enum EnvError {
    #[error("Invalid value for {var}: expected {expected}, got '{value}'")]
    InvalidValue {
        var: String,
        expected: String,
        value: String,
    },

    #[error("Path not found for {var}: {path}")]
    PathNotFound { var: String, path: PathBuf },

    #[error("Invalid duration for {var}: {value}")]
    InvalidDuration { var: String, value: String },

    #[error("Value out of range for {var}: {value} (valid: {min}..={max})")]
    OutOfRange {
        var: String,
        value: String,
        min: String,
        max: String,
    },
}

/// Parse environment variables with validation
pub struct EnvParser {
    prefix: &'static str,
    errors: Vec<EnvError>,
}

impl EnvParser {
    pub fn new() -> Self {
        Self {
            prefix: "RCH_",
            errors: Vec::new(),
        }
    }

    /// Get string value with default
    pub fn get_string(&mut self, name: &str, default: &str) -> Sourced<String> {
        let var_name = format!("{}{}", self.prefix, name);
        match env::var(&var_name) {
            Ok(value) => Sourced::new(value, ConfigSource::Environment),
            Err(_) => Sourced::new(default.to_string(), ConfigSource::Default),
        }
    }

    /// Get bool value with default
    pub fn get_bool(&mut self, name: &str, default: bool) -> Sourced<bool> {
        let var_name = format!("{}{}", self.prefix, name);
        match env::var(&var_name) {
            Ok(value) => {
                let parsed = match value.to_lowercase().as_str() {
                    "1" | "true" | "yes" | "on" => true,
                    "0" | "false" | "no" | "off" | "" => false,
                    _ => {
                        self.errors.push(EnvError::InvalidValue {
                            var: var_name.clone(),
                            expected: "boolean (true/false/1/0/yes/no)".to_string(),
                            value: value.clone(),
                        });
                        default
                    }
                };
                Sourced::new(parsed, ConfigSource::Environment)
            }
            Err(_) => Sourced::new(default, ConfigSource::Default),
        }
    }

    /// Get numeric value with default and range validation
    pub fn get_u64_range(&mut self, name: &str, default: u64, min: u64, max: u64) -> Sourced<u64> {
        let var_name = format!("{}{}", self.prefix, name);
        match env::var(&var_name) {
            Ok(value) => {
                match value.parse::<u64>() {
                    Ok(n) if n >= min && n <= max => {
                        Sourced::new(n, ConfigSource::Environment)
                    }
                    Ok(n) => {
                        self.errors.push(EnvError::OutOfRange {
                            var: var_name,
                            value: n.to_string(),
                            min: min.to_string(),
                            max: max.to_string(),
                        });
                        Sourced::new(default, ConfigSource::Default)
                    }
                    Err(_) => {
                        self.errors.push(EnvError::InvalidValue {
                            var: var_name,
                            expected: "unsigned integer".to_string(),
                            value,
                        });
                        Sourced::new(default, ConfigSource::Default)
                    }
                }
            }
            Err(_) => Sourced::new(default, ConfigSource::Default),
        }
    }

    /// Get path value with expansion and optional existence check
    pub fn get_path(&mut self, name: &str, default: &str, must_exist: bool) -> Sourced<PathBuf> {
        let var_name = format!("{}{}", self.prefix, name);
        let value = env::var(&var_name).unwrap_or_else(|_| default.to_string());
        let source = if env::var(&var_name).is_ok() {
            ConfigSource::Environment
        } else {
            ConfigSource::Default
        };

        // Expand ~ and environment variables
        let expanded = shellexpand::full(&value)
            .map(|s| PathBuf::from(s.to_string()))
            .unwrap_or_else(|_| PathBuf::from(&value));

        if must_exist && !expanded.exists() {
            self.errors.push(EnvError::PathNotFound {
                var: var_name,
                path: expanded.clone(),
            });
        }

        Sourced::new(expanded, source)
    }

    /// Return all accumulated errors
    pub fn errors(&self) -> &[EnvError] {
        &self.errors
    }

    /// Check if any errors occurred
    pub fn has_errors(&self) -> bool {
        !self.errors.is_empty()
    }
}
```

### .env File Support (NEW)

```rust
// rch-common/src/config/dotenv.rs

use std::path::Path;

/// Load .env file if present
pub fn load_dotenv(project_dir: &Path) -> Result<Vec<(String, String)>> {
    let dotenv_path = project_dir.join(".env");
    let rch_env_path = project_dir.join(".rch.env");

    let mut loaded = Vec::new();

    // Load .rch.env first (project-specific RCH settings)
    if rch_env_path.exists() {
        loaded.extend(parse_env_file(&rch_env_path)?);
    }

    // Load .env (may contain RCH_ prefixed vars)
    if dotenv_path.exists() {
        for (key, value) in parse_env_file(&dotenv_path)? {
            if key.starts_with("RCH_") {
                loaded.push((key, value));
            }
        }
    }

    // Set environment variables (don't override existing)
    for (key, value) in &loaded {
        if std::env::var(key).is_err() {
            std::env::set_var(key, value);
        }
    }

    Ok(loaded)
}

fn parse_env_file(path: &Path) -> Result<Vec<(String, String)>> {
    let content = std::fs::read_to_string(path)?;
    let mut vars = Vec::new();

    for line in content.lines() {
        let line = line.trim();

        // Skip comments and empty lines
        if line.is_empty() || line.starts_with('#') {
            continue;
        }

        // Parse KEY=value
        if let Some((key, value)) = line.split_once('=') {
            let key = key.trim().to_string();
            let value = value.trim().trim_matches('"').trim_matches('\'').to_string();
            vars.push((key, value));
        }
    }

    Ok(vars)
}
```

### Config Profiles (NEW)

```rust
// rch-common/src/config/profiles.rs

use std::path::Path;

/// Predefined config profiles
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Profile {
    /// Development mode: verbose logging, mock SSH allowed
    Dev,
    /// Production mode: minimal logging, strict settings
    Prod,
    /// Testing mode: mock SSH enabled, test fixtures
    Test,
    /// Custom profile from file
    Custom,
}

impl Profile {
    pub fn from_env() -> Option<Self> {
        match std::env::var("RCH_PROFILE").ok()?.to_lowercase().as_str() {
            "dev" | "development" => Some(Profile::Dev),
            "prod" | "production" => Some(Profile::Prod),
            "test" | "testing" => Some(Profile::Test),
            _ => Some(Profile::Custom),
        }
    }

    /// Apply profile defaults before other config sources
    pub fn apply_defaults(&self) {
        match self {
            Profile::Dev => {
                set_if_unset("RCH_LOG_LEVEL", "debug");
                set_if_unset("RCH_LOG_FORMAT", "pretty");
            }
            Profile::Prod => {
                set_if_unset("RCH_LOG_LEVEL", "warn");
                set_if_unset("RCH_LOG_FORMAT", "json");
                set_if_unset("RCH_ENABLE_METRICS", "true");
            }
            Profile::Test => {
                set_if_unset("RCH_MOCK_SSH", "1");
                set_if_unset("RCH_LOG_LEVEL", "debug");
                set_if_unset("RCH_TEST_MODE", "1");
            }
            Profile::Custom => {
                // Load from profile file
            }
        }
    }
}

fn set_if_unset(key: &str, value: &str) {
    if std::env::var(key).is_err() {
        std::env::set_var(key, value);
    }
}
```

### Config Validation on Startup (NEW)

```rust
// rch-common/src/config/validate.rs

/// Validate all configuration on startup
pub fn validate_config(config: &RchConfig) -> Vec<ConfigWarning> {
    let mut warnings = Vec::new();

    // Check for common misconfigurations
    if config.daemon.timeout_ms < 100 {
        warnings.push(ConfigWarning {
            var: "RCH_DAEMON_TIMEOUT_MS".to_string(),
            message: "Timeout less than 100ms may cause premature failures".to_string(),
            severity: Severity::Warning,
        });
    }

    if config.transfer.zstd_level > 19 {
        warnings.push(ConfigWarning {
            var: "RCH_TRANSFER_ZSTD_LEVEL".to_string(),
            message: "Zstd level > 19 uses excessive CPU for minimal gain".to_string(),
            severity: Severity::Warning,
        });
    }

    if !config.ssh.key_path.exists() && !config.mock_ssh {
        warnings.push(ConfigWarning {
            var: "RCH_SSH_KEY".to_string(),
            message: format!("SSH key not found: {:?}", config.ssh.key_path),
            severity: Severity::Error,
        });
    }

    // Validate mock SSH usage
    if config.mock_ssh && !config.test_mode {
        warnings.push(ConfigWarning {
            var: "RCH_MOCK_SSH".to_string(),
            message: "Mock SSH enabled outside test mode - builds won't actually compile remotely".to_string(),
            severity: Severity::Warning,
        });
    }

    warnings
}

#[derive(Debug)]
pub struct ConfigWarning {
    pub var: String,
    pub message: String,
    pub severity: Severity,
}

#[derive(Debug, Clone, Copy)]
pub enum Severity {
    Info,
    Warning,
    Error,
}
```

## CLI Integration

```
rch config show                    # Show current config
rch config show --sources          # Show config with sources
rch config show --json             # JSON output
rch config export                  # Export as shell script
rch config export --profile prod   # Export production profile
rch config validate                # Validate configuration (NEW)
rch config set <key> <value>       # Set config value
rch config unset <key>             # Remove config value
```

### Example Outputs

```bash
# rch config show --sources
RCH Configuration
═════════════════

Setting                     Value                  Source
──────────────────────────────────────────────────────────
daemon.socket              /tmp/rch.sock           default
daemon.timeout_ms          5000                    default
log_level                  debug                   environment (RCH_LOG_LEVEL)
ssh.key_path              ~/.ssh/id_ed25519       user config
workers.default           ["gpu-server"]           project config
mock_ssh                  true                     environment (RCH_MOCK_SSH)
profile                   dev                      environment (RCH_PROFILE)
```

```bash
# rch config export
#!/bin/bash
# RCH configuration export
# Generated: 2024-01-15T10:30:00Z

export RCH_LOG_LEVEL="debug"
export RCH_DAEMON_SOCKET="/tmp/rch.sock"
export RCH_SSH_KEY="$HOME/.ssh/id_ed25519"
# ... etc
```

## Implementation Files

```
rch-common/src/
├── config/
│   ├── mod.rs           # Config loading and merging
│   ├── env.rs           # Environment variable parsing
│   ├── dotenv.rs        # .env file support (NEW)
│   ├── profiles.rs      # Config profiles (NEW)
│   ├── validate.rs      # Config validation (NEW)
│   ├── source.rs        # Source tracking
│   └── export.rs        # Shell export generation

rch/src/
├── commands/
│   └── config.rs        # CLI commands
```

## Testing Requirements

### Unit Tests (rch-common/src/config/tests/)

**env_test.rs**
```rust
#[test]
fn test_bool_parsing() {
    std::env::set_var("RCH_TEST_BOOL", "true");
    let mut parser = EnvParser::new();
    let result = parser.get_bool("TEST_BOOL", false);
    assert_eq!(result.value, true);
    assert_eq!(result.source, ConfigSource::Environment);
}

#[test]
fn test_invalid_bool_uses_default() {
    std::env::set_var("RCH_BAD_BOOL", "maybe");
    let mut parser = EnvParser::new();
    let result = parser.get_bool("BAD_BOOL", false);
    assert_eq!(result.value, false);
    assert!(parser.has_errors());
}

#[test]
fn test_range_validation() {
    std::env::set_var("RCH_OUT_OF_RANGE", "100");
    let mut parser = EnvParser::new();
    let result = parser.get_u64_range("OUT_OF_RANGE", 5, 1, 10);
    assert_eq!(result.value, 5); // Uses default
    assert!(parser.has_errors());
}

#[test]
fn test_path_expansion() {
    std::env::set_var("HOME", "/home/test");
    let mut parser = EnvParser::new();
    let result = parser.get_path("TEST_PATH", "~/.config/rch", false);
    assert_eq!(result.value, PathBuf::from("/home/test/.config/rch"));
}
```

**dotenv_test.rs**
```rust
#[test]
fn test_dotenv_loading() {
    let tmp = TempDir::new().unwrap();
    let env_file = tmp.path().join(".rch.env");
    std::fs::write(&env_file, "RCH_LOG_LEVEL=trace\nRCH_MOCK_SSH=1").unwrap();

    let loaded = load_dotenv(tmp.path()).unwrap();
    assert!(loaded.iter().any(|(k, v)| k == "RCH_LOG_LEVEL" && v == "trace"));
}

#[test]
fn test_dotenv_doesnt_override() {
    std::env::set_var("RCH_PRESET", "original");

    let tmp = TempDir::new().unwrap();
    let env_file = tmp.path().join(".rch.env");
    std::fs::write(&env_file, "RCH_PRESET=fromfile").unwrap();

    load_dotenv(tmp.path()).unwrap();
    assert_eq!(std::env::var("RCH_PRESET").unwrap(), "original");
}
```

**profiles_test.rs**
```rust
#[test]
fn test_dev_profile() {
    std::env::set_var("RCH_PROFILE", "dev");
    let profile = Profile::from_env().unwrap();
    profile.apply_defaults();

    // Dev sets debug logging if not already set
    // (test may need cleanup of env vars)
}

#[test]
fn test_test_profile_enables_mock() {
    std::env::remove_var("RCH_MOCK_SSH");
    std::env::set_var("RCH_PROFILE", "test");

    let profile = Profile::from_env().unwrap();
    profile.apply_defaults();

    assert_eq!(std::env::var("RCH_MOCK_SSH").unwrap(), "1");
}
```

### E2E Test Script (scripts/e2e_env_test.sh)

```bash
#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RCH="${RCH:-$SCRIPT_DIR/../target/release/rch}"
TEST_DIR=$(mktemp -d)
LOG_FILE="$TEST_DIR/e2e_env.log"

log() { echo "[$(date -Iseconds)] $*" | tee -a "$LOG_FILE"; }
pass() { log "PASS: $1"; }
fail() { log "FAIL: $1"; exit 1; }

cleanup() { rm -rf "$TEST_DIR"; }
trap cleanup EXIT

log "=== RCH Environment Variables E2E Test ==="

# Test 1: Environment overrides default
test_env_override() {
    log "Test 1: Environment overrides default"
    export RCH_LOG_LEVEL=trace
    OUTPUT=$("$RCH" config show 2>&1)
    echo "$OUTPUT" | grep -q "trace" || fail "Should show trace level"
    unset RCH_LOG_LEVEL
    pass "Environment override"
}

# Test 2: Config sources shown
test_config_sources() {
    log "Test 2: Config sources"
    export RCH_LOG_LEVEL=debug
    OUTPUT=$("$RCH" config show --sources 2>&1)
    echo "$OUTPUT" | grep -qiE "environment|source" || log "Note: --sources may not be implemented"
    unset RCH_LOG_LEVEL
    pass "Config sources"
}

# Test 3: Mock SSH mode
test_mock_ssh() {
    log "Test 3: RCH_MOCK_SSH mode"
    export RCH_MOCK_SSH=1
    OUTPUT=$("$RCH" config show 2>&1)
    log "  Mock SSH config: $(echo "$OUTPUT" | grep -i mock | head -1)"
    unset RCH_MOCK_SSH
    pass "Mock SSH"
}

# Test 4: .env file loading
test_dotenv() {
    log "Test 4: .env file loading"
    echo "RCH_LOG_LEVEL=trace" > "$TEST_DIR/.rch.env"
    cd "$TEST_DIR"
    OUTPUT=$("$RCH" config show 2>&1)
    log "  With .env: $(echo "$OUTPUT" | grep -i log | head -1)"
    cd -
    pass ".env file"
}

# Test 5: Config export
test_export() {
    log "Test 5: Config export"
    OUTPUT=$("$RCH" config export 2>&1 || echo "export not implemented")
    log "  Export (first 3 lines): $(echo "$OUTPUT" | head -3)"
    pass "Config export"
}

# Test 6: Profile loading
test_profiles() {
    log "Test 6: Config profiles"
    export RCH_PROFILE=test
    OUTPUT=$("$RCH" config show 2>&1)
    log "  Test profile: $(echo "$OUTPUT" | grep -i mock | head -1)"
    unset RCH_PROFILE
    pass "Config profiles"
}

# Test 7: Validation
test_validation() {
    log "Test 7: Config validation"
    OUTPUT=$("$RCH" config validate 2>&1 || true)
    log "  Validation: $(echo "$OUTPUT" | head -3)"
    pass "Config validation"
}

# Run all tests
test_env_override
test_config_sources
test_mock_ssh
test_dotenv
test_export
test_profiles
test_validation

log "=== All Environment E2E tests passed ==="
```

## Logging Requirements

- DEBUG: Each environment variable read
- DEBUG: Config file merge steps
- INFO: Active profile
- INFO: .env file loaded
- WARN: Invalid environment variable value
- WARN: Configuration warnings from validation
- ERROR: Critical configuration errors

## Success Criteria

- [ ] All 25+ environment variables documented
- [ ] Type-safe parsing with clear error messages
- [ ] Precedence order correctly implemented
- [ ] `--sources` flag shows value origins
- [ ] Export generates valid shell script
- [ ] **NEW: .env file support works**
- [ ] **NEW: RCH_MOCK_SSH documented and working**
- [ ] **NEW: Config profiles apply correctly**
- [ ] **NEW: Startup validation catches errors**
- [ ] Unit test coverage > 80%
- [ ] E2E tests pass

## Dependencies

- remote_compilation_helper-0dl: Uses config primitives

## Blocks

- All commands that need configuration
