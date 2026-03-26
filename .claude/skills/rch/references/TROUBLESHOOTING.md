# RCH Troubleshooting

## Diagnostic Flow

```text
Compilation running locally instead of remotely?
│
├─ Quick health gate:
│  $ rch check
│  │
│  ├─ Not ready/degraded?
│  │   ├─ Check daemon:
│  │   │  $ rch --json daemon status
│  │   │
│  │   ├─ Check workers:
│  │   │  $ rch workers probe --all
│  │   │
│  │   └─ Check hook install:
│  │      $ rch hook status
│  │
│  └─ Ready?
│      continue below
│
└─ Ready but behavior is wrong?
   ├─ Socket alignment:
   │  $ rch --json config get general.socket_path
   │  $ rch --json daemon status
   │
   ├─ Explain routing decision:
   │  $ rch diagnose "cargo build --release"
   │
   ├─ Validate hook protocol path:
   │  $ rch hook test
   │
   └─ Force direct offload proof:
      $ rch exec -- cargo check --workspace --all-targets
```

---

## Common Errors

### Daemon not running / `check` says not ready

**Cause:** daemon process absent or startup failure.

```bash
rch daemon start
rch --json daemon status
rch daemon logs -n 200
```

### Socket mismatch between config and daemon

**Cause:** `general.socket_path` differs from active daemon socket.

```bash
rch --json config get general.socket_path
rch --json daemon status
# then align and restart:
rch daemon restart -y
```

### "No workers available" / probe failures

**Cause:** no workers configured, SSH/auth failures, or workers are disabled/drained.

```bash
rch workers list
rch workers probe --all
rch workers discover --probe
rch workers discover --add --yes
rch workers setup --all
```

### "rustup: not found" / "cargo: not found" on worker

**Cause:** missing toolchain on one or more workers.

```bash
rch workers sync-toolchain --all
rch workers capabilities --refresh
```

If still failing, SSH to the specific worker and validate `rustup`, `cargo`, and PATH.

### Hook not intercepting

**Cause:** hook missing, wrong binary path, or command classified as local.

```bash
rch hook status
rch hook install
rch hook test
rch diagnose "cargo build --release"
```

### Sync/transfer fails under active target churn

**Cause:** build artifacts changing during rsync.

```bash
# Add target-like excludes in ~/.config/rch/config.toml [transfer].exclude_patterns
rch daemon reload
rch config show --sources
```

Also inspect the worker directly:

```bash
ssh ubuntu@<host> 'df -h / /tmp'
ssh ubuntu@<host> 'du -sh /tmp/rch-* /tmp/rch_target_* 2>/dev/null | sort -h'
```

If cleanup is needed, verify inactivity first:

```bash
ssh ubuntu@<host> 'sudo lsof +D /tmp/rch_target_<name>'
```

If the directory is inactive, prefer targeted stale-artifact cleanup over broad cache deletion.

### Sync fails with `Permission denied` or `Operation not permitted` inside `/data/projects/<repo>`

**Cause:** the canonical mirror on the worker is not writable by the SSH user. This commonly happens when a repo under `/data/projects` was created or updated as `root`.

Check:

```bash
ssh ubuntu@<host> "stat -c '%U:%G %a %n' /data/projects/<repo>"
```

Fix:

```bash
ssh ubuntu@<host> 'sudo chown -R ubuntu:ubuntu /data/projects/<repo> && sudo chmod 775 /data/projects/<repo>'
```

Then retry:

```bash
rch exec -- cargo check --workspace --all-targets
```

### `rch exec` fails open for workdirs outside `/data/projects`

**Cause:** canonical-root normalization rejects workdirs outside the configured project root.

Symptoms include errors mentioning `input resolves outside canonical root`.

Fix:

```bash
pwd
rch diagnose --dry-run "cargo build --release"
```

Then run the build from a workspace under `/data/projects`. If you need a clean copy for testing, stage it under `/data/projects/<temp-repo>` instead of `/tmp/<temp-repo>`.

### Worker shows storage pressure even after cleanup

**Cause:** telemetry lag, large ballast allocation, or active live build churn.

Check:

```bash
rch status --workers --jobs
ssh ubuntu@<host> 'df -h / /tmp && free -h'
ssh ubuntu@<host> 'journalctl -u sbh -n 50 --no-pager'
```

Interpretation:

- If `df` is healthy but `rch status` still warns, give telemetry a minute and refresh.
- If `/tmp` is healthy but `/` is still low, inspect large project `target_*` trees under `/data/projects`.
- If `sbh` is active but repeatedly logging `scan channel saturated` or `scan timed out`, inspect stale build artifacts and verify the host is running the current `sbh` binary and the narrowed worker config.

### Path dependency missing remotely (`../.../Cargo.toml`)

**Cause:** required sibling repositories are not available in worker topology.

```bash
rch diagnose --dry-run "cargo test --workspace"
rch exec -- env CARGO_TARGET_DIR=/tmp/rch_target_<name> cargo check --workspace --all-targets
```

Then ensure sibling repos exist on workers under canonical roots and retry.

---

## Debug Mode

```bash
RCH_LOG_LEVEL=debug rch check
RCH_LOG_LEVEL=debug rch diagnose "cargo test --workspace"
RCH_LOG_LEVEL=debug rch exec -- cargo check --workspace --all-targets
```

Protocol-level hook test:

```bash
RCH_LOG_LEVEL=debug printf '%s\n' \
  '{"tool_name":"Bash","tool_input":{"command":"cargo check"}}' | rch
```

---

## Safe Reset Sequence

```bash
rch daemon restart -y
rch config validate
rch config doctor
rch workers probe --all
rch hook status
rch hook test
rch check
```

If still failing, capture artifacts for escalation:

```bash
rch doctor --json > /tmp/rch-doctor.json
rch --json daemon status > /tmp/rch-daemon-status.json
rch --json workers probe --all > /tmp/rch-workers-probe.json
```
