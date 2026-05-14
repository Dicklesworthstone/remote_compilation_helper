# Hook Integration

## Flow

```
Claude Code → PreToolUse Hook → rch
                                 │
                    ┌────────────┴────────────┐
                    │ Bash tool?              │
                    │   └─ Compilation cmd?   │
                    │       └─ Yes → Remote   │
                    │       └─ No → Local     │
                    │   └─ No → Pass through  │
                    └─────────────────────────┘
```

## Installation

```bash
rch hook install      # Modifies ~/.claude/settings.json
rch hook status       # Verify
rch hook uninstall    # Remove
```

Adds to settings:
```json
{"hooks":{"PreToolUse":[{"matcher":"Bash","command":"/path/to/rch hook"}]}}
```

## Protocol

**Input** (stdin):
```json
{"tool":"Bash","input":{"command":"cargo build --release"}}
```

**Output** (stdout):

| Response | JSON | Meaning |
|----------|------|---------|
| Pass through | `{"allow":true}` | Run locally |
| Intercept | `{"allow":true,"output":"..."}` | Return captured output |
| Block | `{"allow":false,"reason":"..."}` | Prevent execution |

## Classification (5-tier, <5ms total)

| Tier | Time | Check |
|------|------|-------|
| 1 | <100μs | Keyword bloom filter |
| 2 | <200μs | Quick regex scan |
| 3 | <500μs | Full command parse |
| 4 | <1ms | Context extraction |
| 5 | <5ms | Worker selection |

### Intercepted

```
cargo build/test/check/run, rustc
bun test, bun typecheck
gcc, g++, clang, clang++, cc
make, cmake --build, ninja, meson compile
```

### Never Intercepted

```
bun install/add/remove     # Modifies node_modules
bun run/dev/build          # Needs local ports
cargo build | tee log      # Piped
cargo build > output.txt   # Redirected
cargo build &              # Background
```

## Testing

```bash
# Test classification
echo '{"tool":"Bash","input":{"command":"cargo build"}}' | rch hook
# → {"allow":true,"output":"..."}

echo '{"tool":"Bash","input":{"command":"ls -la"}}' | rch hook
# → {"allow":true}

# Dry run with file input
RCH_DRY_RUN=1 rch hook < test-input.json

# Dry run (logs but no remote execution)
RCH_DRY_RUN=1 cargo check

# Debug logging
RCH_LOG=debug cargo build
RCH_LOG=trace cargo build  # Maximum detail

# Verify hook is running
ps aux | grep rch
```

## Configuration

`~/.config/rch/config.toml`:
```toml
[hook]
classify_timeout_ms = 5      # Classification budget
pipeline_timeout_s = 300     # Full pipeline timeout
fail_open = true             # On error → allow local execution

local_patterns = [           # Force local execution
    "cargo fmt",
    "cargo doc"
]
```

## Uninstalling

```bash
rch hook uninstall  # Removes hook from ~/.claude/settings.json

# Manual removal: edit ~/.claude/settings.json and remove the PreToolUse entry
```

## Security

- Runs with user permissions
- SSH keys via ssh-agent (recommended)
- Workers should be trusted machines
- Never modifies source code
- Artifacts transferred via secure rsync
