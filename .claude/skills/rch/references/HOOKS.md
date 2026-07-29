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
# Built-in hook self-test (preferred)
rch hook test

# Raw protocol: the hook is the bare `rch` binary reading JSON on stdin in
# hook mode (RCH_HOOK_MODE=1 forces it; Claude Code invokes the binary directly).
echo '{"tool":"Bash","input":{"command":"cargo build"}}' | RCH_HOOK_MODE=1 rch
# → strict JSON decision on stdout

echo '{"tool":"Bash","input":{"command":"ls -la"}}' | RCH_HOOK_MODE=1 rch

# Show the decision without remote execution
rch diagnose "cargo check" --dry-run

# Debug logging
RCH_LOG_LEVEL=debug rch diagnose "cargo build"
RCH_LOG_LEVEL=trace rch diagnose "cargo build"  # Maximum detail

# Verify hook registration
rch hook status
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
