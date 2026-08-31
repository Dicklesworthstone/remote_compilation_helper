# RCH Troubleshooting

## Contents

- [Diagnostic Flow](#diagnostic-flow)
- [Common Errors](#common-errors)
- [Debug Mode](#debug-mode)
- [Safe Reset Sequence](#safe-reset-sequence)
- [Reading `rch status` Output Correctly](#reading-rch-status-output-correctly)
- [Daemon Version Drift After Upgrade](#daemon-version-drift-after-upgrade)
- [Telemetry Corruption](#telemetry-corruption)
- ["Why did my command run locally?" (Silent Fail-Open)](#why-did-my-command-run-locally-silent-fail-open)
- [See Also](#see-also)

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
│  │   └─ Check interception (hook + shim):
│  │      $ rch hook status && rch shim status
│  │
│  └─ Ready?
│      continue below
│
└─ Ready but behavior is wrong?
   ├─ Socket alignment:
   │  $ rch --json config get general.socket_path
   │  $ rch --json daemon status
   │
   ├─ Explain routing + admission:
   │  $ rch diagnose --dry-run "cargo build --release"
   │  $ rch admit "cargo build --release"
   │
   ├─ Validate hook protocol path:
   │  $ rch hook test
   │
   ├─ Fleet posture in one screen:
   │  $ rch status --remediation
   │
   └─ Force direct offload proof (loud on failure):
      $ RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=verbose rch exec -- cargo check --workspace --all-targets
```

For any reason code you see, `rch error explain <RCH-Exxx|RCH-Innn>` and
`rch doctor --runbook <RCH-Rnnn>` are faster than this file.

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

### Builds compile locally although the fleet has free slots

**Cause:** the build didn't come through the hook — Codex/scripts/Makefiles
call `cargo` directly, or an absolute-path `~/.rustup/toolchains/*/bin/cargo`
bypassed PATH. The cargo shim is the fix; `rch shim status` shows
`local_builds_running` and whether the shim is ahead on PATH.

```bash
rch shim status                 # installed? interception direct|delegated|none? N/M toolchains wrapped?
rch shim install                # dispatcher boxes only; re-run after every `rustup toolchain install`
ps -eo pid,args | grep -E '[r]ustc|[c]argo'
```

Full guide: `SHIM.md`.

### `[RCH-E301]` — shell-wrapped cargo refused

**Cause:** `rch exec -- bash -lc "cargo test -p a && cargo test -p b"` (or
`sh -c`). rch can't bind the output path, so it refuses before remote *and*
local execution (exit 1, empty stdout). Run separate direct invocations:

```bash
RCH_REQUIRE_REMOTE=1 rch exec -- cargo test -p a
RCH_REQUIRE_REMOTE=1 rch exec -- cargo test -p b
```

### Exit 103 — `remote required; refusing local fallback (...) — retryable`

**Cause:** strict remote (`RCH_REQUIRE_REMOTE=1`, the shim's fail-closed
default, `general.role = "dispatcher"`, clean-overlay/receipt modes) and no
worker was assignable *right now*. Nothing ran. Fix the fleet, then retry:

```bash
rch status --remediation
rch admit "<the command>"         # per-candidate rejection reasons
```

Exit 1 with `(non-compilation command)` / `(config unavailable)` is permanent —
use `rch exec --job` for non-compilation work.

### Build appears stuck at `waiting for N remote source-authority lock(s)`

**Cause:** another invocation holds a shared path-dependency root on that
worker until its Cargo exits. Not a hang; wait, or check `rch queue` for the
peer build. `MULTI_AGENT_CONTENTION.md`.

### Job mode exits 102 with `RCH-E309`

**Cause:** a declared `--result-dir` was missing or only partially transferable
on the worker — the job itself may have passed (its exit is in the `--json`
envelope's `remote_exit_code`). Make the directory repo-relative and ensure the
job creates it. `EXEC_MODES.md`.

### Sync/transfer fails under active target churn

**Cause:** build artifacts changing during rsync.

```bash
# Add target-like excludes in ~/.config/rch/config.toml [transfer].exclude_patterns
rch daemon reload
rch config show --sources
```

`transfer skipped` in the summary line means the payload exceeded
`[transfer] max_transfer_mb` / `max_transfer_time_ms`; `RCH-E401` means the
per-attempt upload budget (`RCH_SYNC_TIMEOUT_MS`, payload-aware default) ran out.

Also inspect the worker, letting rch enumerate what it owns first:

```bash
rch cache status --workers <id>            # pooled/per-job target dirs with verdicts
rch gc --dry-run --workers <id>            # what the reaper would remove
ssh ubuntu@<host> 'df -h / /data /tmp 2>/dev/null'
```

Prefer `rch gc --workers <id>` over any manual `rm`; see `DISK_AND_PRESSURE.md`.

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
RCH_REQUIRE_REMOTE=1 rch exec -- cargo check --workspace --all-targets
```

On main, `rch doctor --reliability --scope ownership` detects root-owned
entries in the mirror tree fleet-wide (detection only; reason codes
`RCH-R70x`). The 1.0.58 release has no such probe under any scope — check per
worker with the `stat` command above.

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

- If `df` is healthy but `rch status` still warns, give telemetry a minute and refresh (`[remediation.telemetry_freshness] max_age_secs = 120`).
- The worker probe reports the **worst-case** free space across project roots and `/tmp` — a full tmpfs `/tmp` alone is enough to flag the worker.
- If `/tmp` is healthy but `/` is still low, inspect pooled `.rch-target-*` trees under `/data/projects` with `rch cache status --workers <id>`.
- If `sbh` is active but repeatedly logging `scan channel saturated` or `scan timed out`, inspect stale build artifacts and verify the host is running the current `sbh` binary and the narrowed worker config.

### Path dependency missing remotely (`../.../Cargo.toml`)

**Cause:** required sibling repositories are not available in worker topology.

```bash
rch diagnose --dry-run "cargo test --workspace"
rch sync --project . --all                 # preview stale worker-cache resync; --force applies (RCH-E411)
RCH_REQUIRE_REMOTE=1 rch exec -- cargo check --workspace --all-targets
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

---

## Reading `rch status` Output Correctly

`rch status` (and `rch check`) can simultaneously show `✓ RCH is ready (9/9 workers healthy)` AND a list of `[warning] Circuit opened for worker '<id>'` alerts. **The alerts are informational** — circuit breakers are self-healing once the worker is healthy and the half-open probe succeeds. Don't over-react.

**Wrong:** "I see warnings — better restart the daemon and reload the config."

**Right:** `rch workers probe --all && rch status --workers --jobs` — the alert clears within the next status refresh.

If a circuit doesn't auto-clear after the cooldown (`[circuit] open_cooldown_secs = 30`, one half-open probe at a time, `success_threshold = 2` consecutive successes to close) and the underlying probe is healthy, there's a real bug; capture `rch --json status --workers | jq '.data.daemon.workers[] | {id, circuit_state, consecutive_failures, last_error, recovery_in_secs}'` and `rch daemon logs -n 100`.

Likewise `rch status --fleet` showing workers **bypassed** is the daemon's
temporary-bypass quarantine, which auto-rejoins after consecutive healthy probes
plus a canary build — not something to restart the daemon over
(`SELF_HEALING.md`).

---

## Daemon Version Drift After Upgrade

**Symptom:** New rch CLI features behave inconsistently; `rch --version` differs from the daemon's reported version.

**Self-fix (this is safe — never ask first):**

The daemon's running version is reported by `rch --json status` at `.data.daemon.daemon.version` (the `rch --json daemon status` endpoint deliberately returns only running/socket/uptime — not version). Compare:

```bash
rch --version | awk '{print $2}'
rch --json status | jq -r '.data.daemon.daemon.version'
# If they differ:
rch daemon restart -y                                    # only when `rch queue` shows 0 active builds — restart interrupts them
rch --json status | jq -r '.data.daemon.daemon.version'  # confirm equal
```

`rch daemon restart -y` is the upgrade path, but it does **not** drain: the interactive prompt says "N active build(s) will be interrupted", `-y` skips exactly that prompt, and the daemon itself may answer `shutdown_blocked` (with the active/queued build ids) while builds run. Check `rch --json queue | jq '.data.active_builds|length'` is 0 first, or `rch cancel` deliberately.

If a worker shows mismatched binary version after a host upgrade:

```bash
rch fleet status              # human-readable per-worker status
rch fleet verify              # compare installed vs expected
rch fleet deploy --canary 25 --canary-wait 60 --verify
rch fleet deploy --verify
```

---

## Telemetry Corruption

**Symptom:** Recurring `RCH-E507`, `Telemetry database integrity check failed`, empty `rch speedscore --history`, daemon log lines mentioning `database disk image is malformed`.

**Self-fix:** See `references/TELEMETRY_RECOVERY.md`. Short version: wait for `rch queue` to be empty, stop the daemon, move `telemetry.db*` aside (Linux `~/.local/share/rch/telemetry/`, macOS `~/Library/Application Support/com.rch.rch/telemetry/`), restart. Telemetry is derived data; you lose history but nothing operational.

---

## "Why did my command run locally?" (Silent Fail-Open)

**Symptom:** `rch hook status` says installed; `rch exec` works in isolation; but a particular `cargo build` invocation runs locally without the rch wrapper. No `[RCH] local (...)` line appears because `RCH_VISIBILITY=none` is set, or because the hook never engaged at all.

**Self-fix:**

1. Force visibility: `RCH_VISIBILITY=verbose <your-command>`. If you now see `[RCH] local (...)`, follow `references/FAIL_OPEN.md` to map the reason to a fix.
2. If still no `[RCH]` line, the hook never fired. Probe the protocol directly:
   ```bash
   .claude/skills/rch/scripts/protocol_test.sh "<your-command>"
   ```
   If stdout is empty, the classifier is rejecting your command. Common causes: shell-wrapped (`bash -lc "cargo …"`), backgrounded with `&`, watch modes, `cargo fmt`, or a `go`/`nix` command with no worker advertising that runtime. (Plain pipes like `cargo build | tee log` and `cd x && cargo check` *are* rewritten.) Restructure or use `rch exec -- <cmd>` directly.
3. If the hook fires but the command still runs locally, the rewrite isn't being honored — check that `~/.claude/settings.json` has the right hook command path (`rch hook install` re-resolves it), and that the Claude Code session was started after the install.
4. If the build came from Codex, a script, or an absolute-path toolchain cargo, the hook was never in the loop — `rch shim status`.

See `references/FAIL_OPEN.md` for the full taxonomy.

---

## See Also

- `references/FAIL_OPEN.md` — the canonical guide for `[RCH] local (...)` reasons and refusal lines
- `references/ERROR_CODES.md` — RCH-Exxx catalog, RCH-Innn refusal codes, RCH-Rnnn runbooks, exit codes
- `references/SHIM.md` — cargo shim, toolchain wrapping, building locally on purpose
- `references/EXEC_MODES.md` — strict remote, job mode, clean overlay, receipts, exec envelope
- `references/PATH_DEPENDENCIES.md` — multi-repo workspace problems
- `references/MULTI_AGENT_CONTENTION.md` — TOCTOU, fleet deploy races, autostart cooldown
- `references/DISK_AND_PRESSURE.md` — RCH-E210..217 + sbh handoff
- `references/SELF_HEALING.md` — autostart cooldown, daemon supervision
- `references/SSH_KEY_RECOVERY.md` — host-doesn't-have-the-key recovery
- `references/SSH_TUNING.md` — ControlMaster, keepalives, retry semantics
- `references/TELEMETRY_RECOVERY.md` — corrupt telemetry.db recovery
- `references/MACHINE_INTROSPECTION.md` — JSON/schema/capability surfaces
- `references/RECOVERY_PLAYBOOKS.md` — symptom→fix in ≤90s
- `scripts/auto_recover.sh` — heuristic, dry-run-by-default recovery
- `scripts/worker_disk_triage.sh` — read-only disk report per worker
- `scripts/protocol_test.sh` — probe the hook protocol directly
- `scripts/multi_agent_safety.sh` — flock wrapper for fleet ops
- `scripts/mine_rch_history.sh` — search prior incidents in agent session history
