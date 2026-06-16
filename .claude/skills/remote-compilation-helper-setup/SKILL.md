---
name: remote-compilation-helper-setup
description: >-
  Configure RCH workers, install hooks, fix SSH/daemon issues. Use when setting up
  remote compilation, adding build machines, troubleshooting rch doctor, or "no workers available".
---

# RCH Setup

Offloads `cargo build`, `bun test`, `gcc` to remote workers. Transparent—same commands, faster builds.

## Workflow

```
1. rch doctor           # What's broken?
2. rch doctor --fix     # Auto-fix common issues
3. rch doctor           # All green? Done.
```

If `--fix` can't solve it, continue below.

## Setup Checklist

- [ ] **Prerequisites**: `which rustup rsync zstd` (install missing)
- [ ] **Install**: `cargo install --path rch` (or `--path .` from repo root)
- [ ] **Configure**: Create `~/.config/rch/workers.toml` (see below)
- [ ] **Hook**: `rch hook install`
- [ ] **Daemon**: `rch daemon start` (or `systemctl --user start rchd`)
- [ ] **Validate**: `rch doctor` → all checks pass, then `rch self-test`

## Worker Config

```toml
# ~/.config/rch/workers.toml
[[workers]]
id = "worker1"
host = "192.168.1.100"
user = "ubuntu"
identity_file = "~/.ssh/id_ed25519"
total_slots = 8    # ≈ CPU cores - 2
priority = 100     # Higher = preferred
tags = ["rust"]    # Optional capability tags
```

**Discover from SSH config**:
```bash
rch workers discover --from-ssh-config --dry-run  # Preview
rch workers discover --from-ssh-config            # Add to config
```

**Verify workers**:
```bash
rch workers probe worker1 --verbose  # Test single
rch workers probe --all              # Test all
rch workers list --capabilities      # Show detected toolchains
```

## Quick Fixes

| Symptom | Fix |
|---------|-----|
| SSH fails | `eval $(ssh-agent) && ssh-add ~/.ssh/your_key` |
| Daemon down / stale socket | `rch daemon restart` — never `rm` the socket by hand |
| Hook missing | `rch hook install` (`--force` only after `rch hook status`) |
| No workers | `rch status --fleet` + `rch admit "cargo build"` — find the real cause; **do not** edit `workers.toml` for transient illness |

**Test the hook**:
```bash
rch hook test
```

## Validation

```bash
rch doctor --verbose   # Full diagnostics
rch doctor --json      # Machine-readable
rch diagnose "cargo check" --dry-run  # Show the decision without remote execution
```

⚠️ **All `rch doctor` checks must pass before use.**

## References

| Topic | Reference |
|-------|-----------|
| Worker schema, selection algorithm, tags | [WORKERS.md](references/WORKERS.md) |
| All error messages & detailed fixes | [TROUBLESHOOTING.md](references/TROUBLESHOOTING.md) |
| Hook protocol, 5-tier classification | [HOOKS.md](references/HOOKS.md) |
