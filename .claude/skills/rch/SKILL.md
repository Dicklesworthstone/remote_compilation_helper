---
name: rch
description: >-
  Offload cargo/gcc/bun builds to remote workers. Use when compilation is slow,
  workers are unhealthy, hook routing is unclear, or remote sync/execution is
  failing.
---

# RCH — Remote Compilation Helper

Use this skill for remote compilation offload, worker fleet health checks, and hook incident recovery.

## Quick Start

```bash
rch check
rch status --workers --jobs
rch workers probe --all
rch hook status
rch diagnose --dry-run "cargo check --workspace --all-targets"
rch exec -- env CARGO_TARGET_DIR=/tmp/rch_target_<name> cargo check --workspace --all-targets
```

If `rch exec -- ...` succeeds, remote offload is healthy and remaining failures are likely project/toolchain specific.

If `rch status` shows storage pressure, always check both `/` and `/tmp` on the worker before deciding what to fix:

```bash
ssh ubuntu@<host> 'df -h / /tmp && free -h && cat /proc/pressure/memory && cat /proc/pressure/io'
```

---

## Fast Triage Order

Run in this order and stop at the first failing stage:

1. **Availability**
```bash
rch check
rch status --workers --jobs
rch workers probe --all
rch queue
```

2. **Config + socket consistency**
```bash
rch config show --sources
rch --json config get general.socket_path
rch --json daemon status
```

3. **Hook integration**
```bash
rch hook status
rch agents status
rch hook install
```

4. **Command classification + path closure**
```bash
rch diagnose "cargo build --release"
rch diagnose --dry-run "cargo test --workspace"
```

5. **Remote compile proof**
```bash
rch exec -- env CARGO_TARGET_DIR=/tmp/rch_target_<name> cargo check --workspace --all-targets
```

6. **If sync fails or storage looks bad, inspect the worker directly**
```bash
ssh ubuntu@<host> 'df -h / /tmp'
ssh ubuntu@<host> 'du -sh /tmp/rch-* /tmp/rch_target_* 2>/dev/null | sort -h'
ssh ubuntu@<host> 'find /data/projects -maxdepth 2 -type d \\( -name "target_rch_*" -o -name "target_*" -o -name "target-*" -o -name target \\) -exec du -sh {} + 2>/dev/null | sort -h | tail'
```

---

## Quick Fixes

| Symptom | Command |
|---------|---------|
| Hook not installed | `rch hook install && rch hook status` |
| Daemon not running | `rch daemon start` |
| Socket mismatch / stale daemon state | `rch daemon restart -y` then `rch --json daemon status` |
| No workers configured | `rch workers discover --add --yes && rch workers setup --all` |
| Workers unreachable | `rch workers probe --all` then fix SSH key/host reachability |
| Transfer churn under target dirs | Add excludes in `~/.config/rch/config.toml`, then `rch daemon reload` |
| Path dependency missing remotely | Ensure required sibling repos exist on workers under canonical project roots, then retry `rch exec -- ...` |
| Sync fails with `Permission denied` in `/data/projects/<repo>` | Fix remote mirror ownership: `ssh ubuntu@<host> 'sudo chown -R ubuntu:ubuntu /data/projects/<repo> && sudo chmod 775 /data/projects/<repo>'` |
| Worker shows pressure warning | Check `/` and `/tmp` separately, then inspect stale `rch_target_*`, `rch-*`, and `target_rch_*` dirs before broader cleanup |
| Need full environment diagnosis | `rch doctor` and `rch config doctor` |

---

## Reference Index

Use these files for full depth:

- **Runbooks + operational playbooks**: `references/OPERATIONS.md`
- **Troubleshooting flow + failure signatures**: `references/TROUBLESHOOTING.md`
- **Worker lifecycle operations**: `references/WORKERS.md`
- **Config hierarchy + environment controls**: `references/CONFIGURATION.md`
- **PreToolUse hook protocol and behavior**: `references/HOOKS.md`
- **Workers config template**: `assets/workers-template.toml`
- **Project docs**: https://github.com/Dicklesworthstone/remote_compilation_helper
