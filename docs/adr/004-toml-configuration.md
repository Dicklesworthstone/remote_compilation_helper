# ADR-004: TOML Configuration Format

## Status

Accepted

## Context

RCH needs configuration for:
- Global settings (socket path, log level, thresholds)
- Worker definitions (hosts, SSH credentials, slots)
- Per-project overrides (exclude patterns, preferred workers)

Options considered:
1. **TOML** (chosen)
2. JSON
3. YAML
4. Environment variables only
5. INI format

## Decision

Use TOML for all configuration files.

**Configuration hierarchy:**

```
~/.config/rch/config.toml      # Global settings
~/.config/rch/workers.toml     # Worker fleet definition
.rch/config.toml               # Per-project overrides
```

**Precedence (highest to lowest):**
1. Environment variables (`RCH_*`)
2. Per-project config (`.rch/config.toml`)
3. User config (`~/.config/rch/config.toml`)
4. Compiled defaults

## Configuration Files

### Global Config (~/.config/rch/config.toml)

```toml
[general]
enabled = true
log_level = "info"
socket_path = "~/.cache/rch/rch.sock"

[compilation]
confidence_threshold = 0.85
min_local_time_ms = 2000

[transfer]
compression_level = 3
exclude_patterns = [
    "target/",
    ".git/objects/",
    "node_modules/",
]

[output]
stream_mode = "realtime"
preserve_colors = true
```

### Workers Config (~/.config/rch/workers.toml)

```toml
[[workers]]
id = "fast-server"
host = "build.example.com"
user = "builder"
identity_file = "~/.ssh/build_key"
total_slots = 32
priority = 100
tags = ["fast", "ssd"]

[[workers]]
id = "backup"
host = "192.168.1.50"
user = "ubuntu"
identity_file = "~/.ssh/id_rsa"
total_slots = 8
priority = 50
```

### Project Config (.rch/config.toml)

```toml
[general]
enabled = true
preferred_workers = ["fast-server"]

[transfer]
exclude_patterns = ["benches/data/"]
include_patterns = ["generated/*.rs"]
```

## Consequences

### Positive

- **Human readable**: Easy to edit and review
- **Comments**: Can document configuration inline
- **Type safety**: Explicit types, no implicit conversions
- **Rust ecosystem**: First-class serde support via `toml` crate
- **Structured**: Tables and arrays for complex configs
- **Familiar**: Similar to Cargo.toml

### Negative

- **Less common than JSON/YAML**: Some users unfamiliar
- **No schema validation**: Must validate in code
- **Multiline strings**: Less elegant than YAML

### Mitigations

- Provide `rch config init` to generate starter config
- `rch config validate` to check syntax and semantics
- Comprehensive error messages on parse failures

## Alternatives Considered

### JSON

- **Pro**: Universal, machine-friendly
- **Con**: No comments (dealbreaker for config files)
- **Con**: Verbose for simple configs

### YAML

- **Pro**: Very readable, flexible
- **Con**: Indentation-sensitive (error-prone)
- **Con**: Complex specification, edge cases
- **Con**: Security concerns (arbitrary code execution in some parsers)

### Environment Variables Only

- **Pro**: Simple, 12-factor app compatible
- **Con**: Poor for structured data (worker lists)
- **Con**: Hard to maintain many variables

### INI Format

- **Pro**: Simple, familiar
- **Con**: No nested structures
- **Con**: No arrays

## Validation

All configuration is validated at load time:

```rust
pub fn validate_config(config: &Config) -> Result<(), ConfigError> {
    if config.compilation.confidence_threshold < 0.0
        || config.compilation.confidence_threshold > 1.0
    {
        return Err(ConfigError::InvalidThreshold);
    }
    // ... more validations
    Ok(())
}
```

## References

- `rch-common/src/config.rs` - Configuration types and loading
- [TOML Specification](https://toml.io/)
- [serde_toml crate](https://docs.rs/toml/)
