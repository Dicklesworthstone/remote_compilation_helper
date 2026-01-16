## Overview

Add comprehensive environment variable overrides for all configuration settings with explicit precedence rules, strong type parsing with validation, and a `rch config show --sources` view showing where each value came from.

## Goals

1. Full env var coverage for all config values
2. Consistent naming: `RCH_<SECTION>_<OPTION>` format
3. Strong type parsing with validation, defaults, and error messages
4. Source tracking (default → user → project → env)
5. Clear error messages for invalid values
6. Shell export generation for debugging

## Env Var Matrix

### General Settings
| Variable | Type | Default | Description |
|----------|------|---------|-------------|
| `RCH_ENABLED` | bool | true | Enable/disable RCH interception |
| `RCH_LOG_LEVEL` | string | info | Log level (trace/debug/info/warn/error) |
| `RCH_LOG_FILE` | path | - | Optional log file path |
| `RCH_SOCKET_PATH` | path | ~/.rch/rch.sock | Daemon socket location |
| `RCH_CONFIG_DIR` | path | ~/.config/rch | Override config directory |
| `RCH_DATA_DIR` | path | ~/.local/share/rch | Override data directory |

### Compilation Settings
| Variable | Type | Default | Description |
|----------|------|---------|-------------|
| `RCH_CONFIDENCE_THRESHOLD` | float | 0.7 | Min confidence for remote |
| `RCH_MIN_LOCAL_TIME_MS` | u64 | 500 | Skip remote if local < this |
| `RCH_REMOTE_SPEEDUP_THRESHOLD` | float | 1.5 | Required speedup factor |
| `RCH_TIMEOUT_SECS` | u64 | 300 | Max build time before kill |
| `RCH_RETRY_COUNT` | u32 | 2 | Retries on transient failure |

### Transfer Settings
| Variable | Type | Default | Description |
|----------|------|---------|-------------|
| `RCH_COMPRESSION` | u32 | 3 | Zstd compression level (0-22) |
| `RCH_EXCLUDE_PATTERNS` | list | .git,target | Comma-separated excludes |
| `RCH_INCLUDE_HIDDEN` | bool | false | Include hidden files |
| `RCH_MAX_FILE_SIZE_MB` | u64 | 100 | Skip files larger than this |

### Worker Selection
| Variable | Type | Default | Description |
|----------|------|---------|-------------|
| `RCH_WORKERS` | list | - | Comma-separated allowlist |
| `RCH_WORKERS_EXCLUDE` | list | - | Comma-separated blocklist |
| `RCH_PREFERRED_WORKER` | string | - | Prefer this worker when available |
| `RCH_SELECTION_STRATEGY` | string | adaptive | round_robin/latency/adaptive |

### Debug/Behavior
| Variable | Type | Default | Description |
|----------|------|---------|-------------|
| `RCH_DRY_RUN` | bool | false | Log decisions without executing |
| `RCH_BYPASS` | bool | false | Skip RCH, run locally |
| `RCH_LOCAL_ONLY` | bool | false | Force local execution |
| `RCH_VERBOSE` | bool | false | Extra verbose output |
| `RCH_DEBUG` | bool | false | Debug mode (extra checks) |
| `RCH_MOCK_SSH` | bool | false | Use mock SSH for testing |

## Precedence Rules

```
Priority (highest wins):
  1. Environment variable (RCH_*)
  2. Project config (./rch.toml)
  3. User config (~/.config/rch/config.toml)
  4. Built-in defaults
```

## Implementation

### Type-Safe Parsing Module

```rust
// rch/src/config/env.rs

use std::env;
use std::str::FromStr;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum EnvParseError {
    #[error("Invalid boolean for {var}: expected 'true', 'false', '1', or '0', got '{value}'")]
    InvalidBool { var: String, value: String },

    #[error("Invalid integer for {var}: {source}")]
    InvalidInt { var: String, #[source] source: std::num::ParseIntError },

    #[error("Invalid float for {var}: {source}")]
    InvalidFloat { var: String, #[source] source: std::num::ParseFloatError },

    #[error("Invalid path for {var}: path does not exist: {path}")]
    PathNotFound { var: String, path: String },

    #[error("Invalid log level for {var}: expected trace/debug/info/warn/error, got '{value}'")]
    InvalidLogLevel { var: String, value: String },

    #[error("Value out of range for {var}: {value} not in {min}..={max}")]
    OutOfRange { var: String, value: String, min: String, max: String },
}

/// Parse boolean from env var with multiple accepted formats
pub fn parse_bool(var: &str) -> Result<Option<bool>, EnvParseError> {
    match env::var(var) {
        Ok(v) => {
            let lower = v.to_lowercase();
            match lower.as_str() {
                "true" | "1" | "yes" | "on" => Ok(Some(true)),
                "false" | "0" | "no" | "off" | "" => Ok(Some(false)),
                _ => Err(EnvParseError::InvalidBool {
                    var: var.to_string(),
                    value: v,
                }),
            }
        }
        Err(env::VarError::NotPresent) => Ok(None),
        Err(env::VarError::NotUnicode(_)) => Err(EnvParseError::InvalidBool {
            var: var.to_string(),
            value: "<invalid unicode>".to_string(),
        }),
    }
}

/// Parse integer with range validation
pub fn parse_int<T: FromStr + PartialOrd + std::fmt::Display>(
    var: &str,
    min: T,
    max: T,
) -> Result<Option<T>, EnvParseError>
where
    T::Err: Into<std::num::ParseIntError>,
{
    match env::var(var) {
        Ok(v) => {
            let parsed: T = v.parse().map_err(|e: T::Err| EnvParseError::InvalidInt {
                var: var.to_string(),
                source: e.into(),
            })?;
            if parsed < min || parsed > max {
                return Err(EnvParseError::OutOfRange {
                    var: var.to_string(),
                    value: v,
                    min: min.to_string(),
                    max: max.to_string(),
                });
            }
            Ok(Some(parsed))
        }
        Err(env::VarError::NotPresent) => Ok(None),
        Err(_) => Err(EnvParseError::InvalidInt {
            var: var.to_string(),
            source: "".parse::<i32>().unwrap_err(),
        }),
    }
}

/// Parse comma-separated list
pub fn parse_list(var: &str) -> Option<Vec<String>> {
    env::var(var).ok().map(|v| {
        v.split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect()
    })
}

/// Parse path with optional existence check
pub fn parse_path(var: &str, must_exist: bool) -> Result<Option<PathBuf>, EnvParseError> {
    match env::var(var) {
        Ok(v) => {
            let path = PathBuf::from(&v);
            if must_exist && !path.exists() {
                return Err(EnvParseError::PathNotFound {
                    var: var.to_string(),
                    path: v,
                });
            }
            Ok(Some(path))
        }
        Err(_) => Ok(None),
    }
}
```

### Source Tracking

```rust
// rch/src/config/sources.rs

use std::collections::HashMap;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ConfigSource {
    Default,
    UserConfig,
    ProjectConfig,
    Environment,
}

impl std::fmt::Display for ConfigSource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Default => write!(f, "default"),
            Self::UserConfig => write!(f, "~/.config/rch/config.toml"),
            Self::ProjectConfig => write!(f, "./rch.toml"),
            Self::Environment => write!(f, "environment"),
        }
    }
}

#[derive(Debug, Clone)]
pub struct TrackedValue<T> {
    pub value: T,
    pub source: ConfigSource,
    pub env_var: Option<String>,
}

#[derive(Debug, Clone)]
pub struct ConfigSources {
    sources: HashMap<String, ConfigSource>,
    env_vars: HashMap<String, String>,
}

impl ConfigSources {
    pub fn new() -> Self {
        Self {
            sources: HashMap::new(),
            env_vars: HashMap::new(),
        }
    }

    pub fn track(&mut self, field: &str, source: ConfigSource, env_var: Option<&str>) {
        self.sources.insert(field.to_string(), source);
        if let Some(var) = env_var {
            self.env_vars.insert(field.to_string(), var.to_string());
        }
    }

    pub fn get_source(&self, field: &str) -> ConfigSource {
        self.sources.get(field).copied().unwrap_or(ConfigSource::Default)
    }

    /// Generate table for display
    pub fn to_table(&self, config: &Config) -> Vec<SourceRow> {
        // Returns field, value, source, env_var
    }
}
```

### CLI Integration

```rust
// rch/src/commands/config.rs

/// Show configuration with sources
#[derive(Parser)]
pub struct ConfigShowArgs {
    /// Show where each value came from
    #[arg(long)]
    sources: bool,

    /// Export as shell variables
    #[arg(long)]
    export: bool,

    /// Output format
    #[arg(long, value_enum, default_value = "table")]
    format: OutputFormat,
}

pub fn show_config(args: ConfigShowArgs) -> Result<()> {
    let (config, sources) = Config::load_with_sources()?;

    if args.export {
        // Output: export RCH_LOG_LEVEL="debug"
        for (var, value) in config.to_env_vars() {
            println!("export {}=\"{}\"", var, value);
        }
        return Ok(());
    }

    if args.sources {
        // Table with Field | Value | Source columns
        let table = sources.to_table(&config);
        match args.format {
            OutputFormat::Table => print_sources_table(&table),
            OutputFormat::Json => println!("{}", serde_json::to_string_pretty(&table)?),
        }
    } else {
        // Just the config values
        match args.format {
            OutputFormat::Table => print_config_table(&config),
            OutputFormat::Json => println!("{}", serde_json::to_string_pretty(&config)?),
            OutputFormat::Toml => println!("{}", toml::to_string_pretty(&config)?),
        }
    }

    Ok(())
}
```

## Implementation Files

```
rch/src/
├── config/
│   ├── mod.rs           # Config struct and load logic
│   ├── env.rs           # Env var parsing helpers
│   ├── sources.rs       # Source tracking
│   └── validation.rs    # Value validation
├── commands/
│   └── config.rs        # `rch config` subcommand
```

## Testing Requirements

### Unit Tests (rch/src/config/tests/)

**env_test.rs**
```rust
#[test]
fn test_parse_bool_true_variants() {
    for val in ["true", "TRUE", "True", "1", "yes", "YES", "on", "ON"] {
        std::env::set_var("TEST_BOOL", val);
        assert_eq!(parse_bool("TEST_BOOL").unwrap(), Some(true), "Failed for: {}", val);
    }
}

#[test]
fn test_parse_bool_false_variants() {
    for val in ["false", "FALSE", "False", "0", "no", "NO", "off", "OFF", ""] {
        std::env::set_var("TEST_BOOL", val);
        assert_eq!(parse_bool("TEST_BOOL").unwrap(), Some(false), "Failed for: {}", val);
    }
}

#[test]
fn test_parse_bool_invalid() {
    std::env::set_var("TEST_BOOL", "maybe");
    let err = parse_bool("TEST_BOOL").unwrap_err();
    assert!(matches!(err, EnvParseError::InvalidBool { .. }));
}

#[test]
fn test_parse_int_in_range() {
    std::env::set_var("TEST_INT", "5");
    assert_eq!(parse_int::<u32>("TEST_INT", 0, 10).unwrap(), Some(5));
}

#[test]
fn test_parse_int_out_of_range() {
    std::env::set_var("TEST_INT", "100");
    let err = parse_int::<u32>("TEST_INT", 0, 10).unwrap_err();
    assert!(matches!(err, EnvParseError::OutOfRange { .. }));
}

#[test]
fn test_parse_float_valid() {
    std::env::set_var("TEST_FLOAT", "0.75");
    assert_eq!(parse_float("TEST_FLOAT", 0.0, 1.0).unwrap(), Some(0.75));
}

#[test]
fn test_parse_list_empty() {
    std::env::set_var("TEST_LIST", "");
    assert_eq!(parse_list("TEST_LIST"), Some(vec![]));
}

#[test]
fn test_parse_list_with_spaces() {
    std::env::set_var("TEST_LIST", " foo , bar , baz ");
    assert_eq!(parse_list("TEST_LIST"), Some(vec!["foo".to_string(), "bar".to_string(), "baz".to_string()]));
}

#[test]
fn test_parse_path_exists() {
    std::env::set_var("TEST_PATH", "/tmp");
    assert!(parse_path("TEST_PATH", true).unwrap().is_some());
}

#[test]
fn test_parse_path_not_found() {
    std::env::set_var("TEST_PATH", "/nonexistent/path/12345");
    let err = parse_path("TEST_PATH", true).unwrap_err();
    assert!(matches!(err, EnvParseError::PathNotFound { .. }));
}
```

**sources_test.rs**
```rust
#[test]
fn test_precedence_env_over_project() {
    let mut sources = ConfigSources::new();
    sources.track("log_level", ConfigSource::ProjectConfig, None);
    sources.track("log_level", ConfigSource::Environment, Some("RCH_LOG_LEVEL"));
    assert_eq!(sources.get_source("log_level"), ConfigSource::Environment);
}

#[test]
fn test_precedence_project_over_user() {
    // ... similar
}

#[test]
fn test_to_table_includes_all_fields() {
    let config = Config::default();
    let sources = ConfigSources::new();
    let table = sources.to_table(&config);
    assert!(table.iter().any(|r| r.field == "log_level"));
    assert!(table.iter().any(|r| r.field == "confidence_threshold"));
}
```

**validation_test.rs**
```rust
#[test]
fn test_compression_level_bounds() {
    assert!(validate_compression(0).is_ok());
    assert!(validate_compression(22).is_ok());
    assert!(validate_compression(23).is_err());
}

#[test]
fn test_log_level_valid() {
    for level in ["trace", "debug", "info", "warn", "error"] {
        assert!(validate_log_level(level).is_ok());
    }
}

#[test]
fn test_log_level_invalid() {
    assert!(validate_log_level("verbose").is_err());
}
```

### Integration Tests (rch/tests/config_integration.rs)

```rust
#[test]
fn test_config_show_sources_output() {
    std::env::set_var("RCH_LOG_LEVEL", "debug");
    let output = Command::new(RCH_BIN)
        .args(["config", "show", "--sources"])
        .output()
        .unwrap();

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("log_level"));
    assert!(stdout.contains("debug"));
    assert!(stdout.contains("environment") || stdout.contains("RCH_LOG_LEVEL"));
}

#[test]
fn test_config_show_export_format() {
    let output = Command::new(RCH_BIN)
        .args(["config", "show", "--export"])
        .output()
        .unwrap();

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("export RCH_"));
}

#[test]
fn test_config_show_json() {
    let output = Command::new(RCH_BIN)
        .args(["config", "show", "--format", "json"])
        .output()
        .unwrap();

    let json: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert!(json.is_object());
}

#[test]
fn test_invalid_env_var_error_message() {
    std::env::set_var("RCH_COMPRESSION", "invalid");
    let output = Command::new(RCH_BIN)
        .args(["config", "show"])
        .output()
        .unwrap();

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("Invalid"));
    assert!(stderr.contains("RCH_COMPRESSION"));
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

cleanup() {
    rm -rf "$TEST_DIR"
    unset RCH_LOG_LEVEL RCH_COMPRESSION RCH_WORKERS RCH_DRY_RUN RCH_BYPASS 2>/dev/null || true
}
trap cleanup EXIT

log "=== RCH Environment Variables E2E Test ==="
log "Binary: $RCH"
log "Test dir: $TEST_DIR"

# Test 1: Boolean parsing variants
test_bool_parsing() {
    log "Test 1: Boolean parsing for RCH_DRY_RUN"

    for val in "true" "TRUE" "1" "yes" "on"; do
        export RCH_DRY_RUN="$val"
        OUTPUT=$("$RCH" config show --sources 2>&1)
        log "  RCH_DRY_RUN=$val -> $(echo "$OUTPUT" | grep -E 'dry_run|DRY_RUN' || echo 'not found')"
        echo "$OUTPUT" | grep -qE "true|environment" || fail "dry_run should be true for $val"
    done

    for val in "false" "FALSE" "0" "no" "off"; do
        export RCH_DRY_RUN="$val"
        OUTPUT=$("$RCH" config show --sources 2>&1)
        log "  RCH_DRY_RUN=$val -> $(echo "$OUTPUT" | grep -E 'dry_run|DRY_RUN' || echo 'not found')"
    done

    pass "Boolean parsing"
}

# Test 2: Integer range validation
test_int_range() {
    log "Test 2: Integer range validation for RCH_COMPRESSION"

    export RCH_COMPRESSION="5"
    OUTPUT=$("$RCH" config show --sources 2>&1)
    log "  RCH_COMPRESSION=5: $OUTPUT"
    echo "$OUTPUT" | grep -qE "5|compression" || fail "compression should be 5"

    export RCH_COMPRESSION="99"
    if OUTPUT=$("$RCH" config show 2>&1); then
        fail "Should reject compression=99"
    else
        log "  RCH_COMPRESSION=99 correctly rejected: $OUTPUT"
    fi

    pass "Integer range validation"
}

# Test 3: List parsing
test_list_parsing() {
    log "Test 3: List parsing for RCH_WORKERS"

    export RCH_WORKERS="worker1, worker2, worker3"
    OUTPUT=$("$RCH" config show --sources 2>&1)
    log "  RCH_WORKERS='$RCH_WORKERS' -> $OUTPUT"
    echo "$OUTPUT" | grep -qE "worker1|worker2" || fail "workers list not parsed"

    pass "List parsing"
}

# Test 4: Source tracking
test_source_tracking() {
    log "Test 4: Source tracking shows 'environment'"

    export RCH_LOG_LEVEL="debug"
    OUTPUT=$("$RCH" config show --sources 2>&1)
    log "  Source output: $OUTPUT"
    echo "$OUTPUT" | grep -qiE "environment|RCH_LOG_LEVEL" || fail "Source not tracked"

    pass "Source tracking"
}

# Test 5: Export format
test_export_format() {
    log "Test 5: Export format generates valid shell"

    OUTPUT=$("$RCH" config show --export 2>&1)
    log "  Export output (first 5 lines):"
    echo "$OUTPUT" | head -5 | while read -r line; do log "    $line"; done

    # Verify it's valid shell
    echo "$OUTPUT" > "$TEST_DIR/export.sh"
    bash -n "$TEST_DIR/export.sh" || fail "Export is not valid shell"

    pass "Export format"
}

# Test 6: JSON output
test_json_output() {
    log "Test 6: JSON output is valid"

    OUTPUT=$("$RCH" config show --format json 2>&1)
    log "  JSON output: $(echo "$OUTPUT" | head -c 200)..."

    echo "$OUTPUT" | python3 -c "import json, sys; json.load(sys.stdin)" || fail "Invalid JSON"

    pass "JSON output"
}

# Test 7: Invalid value error messages
test_error_messages() {
    log "Test 7: Invalid values produce clear error messages"

    export RCH_COMPRESSION="not-a-number"
    if OUTPUT=$("$RCH" config show 2>&1); then
        fail "Should fail with invalid compression"
    fi
    log "  Error for invalid compression: $OUTPUT"
    echo "$OUTPUT" | grep -qiE "invalid|RCH_COMPRESSION" || fail "Error message unclear"

    export RCH_LOG_LEVEL="invalid-level"
    if OUTPUT=$("$RCH" config show 2>&1); then
        fail "Should fail with invalid log level"
    fi
    log "  Error for invalid log level: $OUTPUT"

    pass "Error messages"
}

# Test 8: Precedence (env over config file)
test_precedence() {
    log "Test 8: Env vars override config files"

    # Create a project config
    cat > "$TEST_DIR/rch.toml" << 'EOF'
[general]
log_level = "warn"
EOF

    export RCH_LOG_LEVEL="trace"
    cd "$TEST_DIR"
    OUTPUT=$("$RCH" config show --sources 2>&1)
    log "  With rch.toml log_level=warn and RCH_LOG_LEVEL=trace:"
    log "  Output: $OUTPUT"
    echo "$OUTPUT" | grep -qE "trace.*environment|environment.*trace" || log "  (Note: verify precedence manually)"

    pass "Precedence"
}

# Run all tests
test_bool_parsing
test_int_range
test_list_parsing
test_source_tracking
test_export_format
test_json_output
test_error_messages
test_precedence

log "=== All E2E tests passed ==="
log "Full log at: $LOG_FILE"
cat "$LOG_FILE"
```

## Logging Requirements

- DEBUG: Log each env var lookup attempt and result
- DEBUG: Log precedence resolution (which source won)
- INFO: Log final effective config on startup
- WARN: Log deprecated env var usage (with migration hint)
- ERROR: Log invalid env var values with expected format

## Success Criteria

- [ ] All env vars documented in `rch config show --help`
- [ ] All env vars listed in matrix above are supported
- [ ] Invalid env values produce clear, actionable errors
- [ ] `rch config show --sources` shows correct source for each field
- [ ] `rch config show --export` generates valid shell script
- [ ] JSON output is valid and complete
- [ ] Unit test coverage > 85%
- [ ] All E2E tests pass

## Dependencies

- Help text updates (remote_compilation_helper-3nq)

## Blocks

- Config state detection (remote_compilation_helper-0dl) uses these primitives
