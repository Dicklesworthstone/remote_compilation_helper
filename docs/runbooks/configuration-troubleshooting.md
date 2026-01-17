# Runbook: Configuration Troubleshooting

## Symptoms

- RCH not intercepting commands
- Wrong workers being selected
- Configuration changes not taking effect
- Unexpected behavior

## Quick Diagnosis

```bash
# Show effective configuration
rch config show

# Validate configuration syntax
rch config validate

# Check which config files are loaded
rch config show --sources
```

## Configuration Hierarchy

Configuration is loaded in this order (later overrides earlier):

```
1. Built-in defaults
2. User config: ~/.config/rch/config.toml
3. Project config: .rch/config.toml (in project directory)
4. .env file: .rch/.env or .env
5. Profile: via RCH_PROFILE=dev|prod|test
6. Environment variables: RCH_*
7. CLI flags
```

## Common Issues

### Commands Not Being Intercepted

**Check hook installation:**
```bash
# Verify hook is installed
rch hook status

# Test classification manually
rch classify "cargo build --release"
```

**If hook not installed:**
```bash
rch hook install
```

**If classification is LOCAL:**
```bash
# Check confidence threshold
rch config show | grep confidence

# Lower threshold if needed
rch config set compilation.confidence_threshold 0.80
```

**If daemon not running:**
```bash
rch daemon status
rch daemon start
```

### Wrong Worker Selection

**Check workers configuration:**
```bash
rch workers list
```

**Check selection weights:**
```bash
rch config show | grep -A5 "\[selection\]"
```

**Test selection:**
```bash
# See why a worker was chosen
RCH_LOG_LEVEL=debug cargo build 2>&1 | grep -i select
```

**Adjust priorities:**
```toml
# ~/.config/rch/workers.toml
[[workers]]
id = "preferred"
priority = 100  # Higher = more preferred

[[workers]]
id = "fallback"
priority = 50
```

### Configuration Changes Not Taking Effect

**Restart daemon:**
```bash
rch daemon restart
```

**Verify config was loaded:**
```bash
# Check effective config
rch config show

# Compare with file
cat ~/.config/rch/config.toml
```

**Check for syntax errors:**
```bash
rch config validate
```

**Check precedence:**
```bash
# Show which file each setting came from
rch config show --sources
```

### Environment Variable Issues

**Check environment:**
```bash
env | grep RCH
```

**Common variables:**
| Variable | Purpose |
|----------|---------|
| `RCH_ENABLED` | Enable/disable (true/false) |
| `RCH_LOCAL_ONLY` | Force local execution |
| `RCH_WORKER` | Force specific worker |
| `RCH_BYPASS` | Skip RCH entirely |
| `RCH_VERBOSE` | Enable verbose logging |
| `RCH_CONFIG_DIR` | Override config directory |

**Clear conflicting variables:**
```bash
unset RCH_LOCAL_ONLY
unset RCH_BYPASS
```

### Profile Issues

**Check current profile:**
```bash
echo $RCH_PROFILE
rch config show | head -5
```

**Available profiles:**
- `dev`: Relaxed settings, verbose logging
- `prod`: Optimized settings, minimal logging
- `test`: Mock SSH, fast timeouts

**Switch profiles:**
```bash
export RCH_PROFILE=dev
rch daemon restart
```

## Configuration Reference

### Main Config (`~/.config/rch/config.toml`)

```toml
[general]
enabled = true
log_level = "info"

[compilation]
confidence_threshold = 0.85  # 0.0-1.0
min_local_time_ms = 2000     # Skip if local < 2s

[transfer]
compression_level = 3        # zstd level 1-19
exclude_patterns = [
    "target/",
    ".git/objects/",
    "node_modules/",
]

[selection]
slot_weight = 0.4
speed_weight = 0.5
cache_weight = 0.1

[daemon]
socket_path = "~/.cache/rch/rch.sock"
health_interval_secs = 30
```

### Workers Config (`~/.config/rch/workers.toml`)

```toml
[[workers]]
id = "worker1"
host = "10.0.1.10"
user = "builder"
identity_file = "~/.ssh/rch_key"
total_slots = 16
priority = 100
tags = ["fast", "ssd"]
```

### Project Config (`.rch/config.toml`)

```toml
# Override settings for this project
[general]
enabled = true
preferred_workers = ["worker1"]

[transfer]
exclude_patterns = [
    "benches/data/",
    "test_fixtures/",
]

[environment]
RUSTFLAGS = "-C target-cpu=native"
```

## Validation Steps

### 1. Syntax Validation

```bash
rch config validate
```

Should output: `Configuration is valid`

### 2. Worker Connectivity

```bash
rch workers probe --all
```

All workers should show `OK`

### 3. Hook Integration

```bash
# Test hook protocol
echo '{"tool":"Bash","input":{"command":"cargo build"}}' | rch hook test
```

Should show classification result

### 4. End-to-End Test

```bash
# In a Rust project
RCH_VERBOSE=1 cargo check 2>&1 | head -20
```

Should show remote execution logs

## Resetting Configuration

### Reset to Defaults

```bash
# Backup current config
cp ~/.config/rch/config.toml ~/.config/rch/config.toml.bak

# Remove user config
rm ~/.config/rch/config.toml

# Restart daemon with defaults
rch daemon restart
```

### Generate Fresh Config

```bash
rch config init

# Or with specific profile
rch config init --profile prod
```

## Debug Mode

For detailed configuration debugging:

```bash
# Show all config sources
RCH_LOG_LEVEL=debug rch config show --sources

# Watch config loading
RCH_LOG_LEVEL=debug rch daemon start 2>&1 | grep -i config
```

## Export/Import Configuration

```bash
# Export effective config
rch config export > rch-config-backup.toml

# Import on another machine
rch config import rch-config-backup.toml
```
