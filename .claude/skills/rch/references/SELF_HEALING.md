# Self-Healing: Daemon Autostart, Cooldown, Hook Bootstrap

## Contents

- [What's in `[self_healing]`](#whats-in-self_healing)
- [What `try_auto_start_daemon` Actually Does](#what-try_auto_start_daemon-actually-does)
- [Symptoms and What They Mean](#symptoms-and-what-they-mean)
- [Hook Re-installation (`daemon_installs_hooks`)](#hook-re-installation-daemon_installs_hooks)
- [Worker Temporary Bypass and Auto-Rejoin](#worker-temporary-bypass-and-auto-rejoin)
- [Self-Test as Continuous Verification](#self-test-as-continuous-verification)
- [Auto-Start Knobs You Can Tune](#auto-start-knobs-you-can-tune)
- [Agent Operating Rules](#agent-operating-rules)

RCH ships a self-healing layer so the hook can recover from a crashed daemon without operator intervention. Understanding how it works lets agents avoid step-on-step interactions and lets you diagnose when self-healing is masking a real bug.

---

## What's in `[self_healing]`

```toml
[self_healing]
hook_starts_daemon = true       # Hook will spawn rchd if socket is unreachable
daemon_installs_hooks = true    # Daemon will reinstall missing PreToolUse hooks
auto_start_timeout_secs = 3     # How long to wait for the socket after spawn (default: 3)
auto_start_cooldown_secs = 30   # Minimum gap between consecutive autostart attempts (default: 30)
self_healing_log_level = "info" # debug|info|warn|error for self-healing log lines
```

(Field names match `rch_common::SelfHealingConfig` in `rch-common/src/types.rs`,
which also accepts the alias `daemon_start_timeout`; the CLI-side loader in
`rch/src/config.rs` additionally canonicalizes `auto_start_timeout` and
`auto_start_cooldown` to the `_secs` names.)

Per-invocation overrides, highest precedence first: CLI `--no-self-healing`
(everything off) / `--no-hook-auto-start` (just the daemon spawn); env
`RCH_NO_SELF_HEALING=1` (master kill switch — when set, the four granular vars
below are ignored); `RCH_HOOK_STARTS_DAEMON`, `RCH_DAEMON_INSTALLS_HOOKS`,
`RCH_AUTO_START_COOLDOWN_SECS`, `RCH_AUTO_START_TIMEOUT_SECS`.

If `hook_starts_daemon = false`, you're back to manual: every `rch exec` that finds the socket missing falls open with `[RCH] local (daemon unavailable)` (or refuses with exit 103 under strict remote).

---

## What `try_auto_start_daemon` Actually Does

Code path: `rch/src/hook/auto_start.rs::try_auto_start_daemon`. Step-by-step:

1. **Bail if disabled.** `Err(AutoStartError::Disabled)` if `hook_starts_daemon = false`.
2. **Acquire the cross-process lock first.** Create-new on `${XDG_RUNTIME_DIR:-/tmp}/rch/hook_autostart.lock`; a same-host lock older than **60 s** is treated as stale and replaced, otherwise `Err(AutoStartError::LockHeld)`. (The lock moved ahead of the socket probe to close a race where a second hook deleted a socket the first had just verified.)
3. **Probe the existing socket under the lock.** Short `connect + ping`: healthy → `Ok(())`; unhealthy/stale → remove the *confirmed* stale socket and continue (`UnhealthySocket` / `StaleSocket` variants exist for the odd cases).
4. **Check cooldown.** Read `hook_autostart.cooldown`; if less than `auto_start_cooldown_secs` since the last attempt, bail with `Err(AutoStartError::CooldownActive(elapsed, required))`.
5. **Write cooldown stamp.** Persist current epoch seconds.
6. **Find the binary.** `which_rchd_path()` checks the directory of the current `rch` executable first, then PATH. Fail with `BinaryNotFound` if absent.
7. **Spawn.** `nohup <rchd>` with stdio nulled. Hand off to background.
8. **Wait for socket.** Up to `auto_start_timeout_secs`, polling. On timeout: `Err(AutoStartError::Timeout)`.
9. **Drop the lock** (RAII via `AutoStartLock`). Cooldown stamp persists.

So, in steady state, only **one** agent at a time gets to spawn the daemon, and after either success or failure no agent retries for `auto_start_cooldown_secs`.

---

## Symptoms and What They Mean

### Many agents see `[RCH] local (daemon unavailable)` simultaneously

Either:
- The daemon crashed and one agent is currently in the cooldown/lock window, holding off the others — wait `auto_start_cooldown_secs` and try again
- `rchd` binary is missing or not in PATH — `which rchd && rchd --version`

Diagnose:

```bash
ls -la "${XDG_RUNTIME_DIR:-/tmp}/rch/"
cat "${XDG_RUNTIME_DIR:-/tmp}/rch/hook_autostart.cooldown" 2>/dev/null   # epoch seconds
date +%s                                                                 # compare
which rchd
```

### Repeated cooldown-active errors but daemon never starts

`rchd` is failing to come up at all (broken binary, port in use, OOM at startup, missing $HOME for state, etc.). The cooldown is hiding the real spawn failure. Bypass the autostart path:

```bash
rch daemon start                 # foreground spawn — surfaces the real error
# or
rchd --foreground                # depending on rchd flags
journalctl --user -u rch.daemon -n 100 2>/dev/null    # if running as systemd user unit
rch daemon logs -n 200
```

### `LockHeld` perpetually

A previous `rch` invocation crashed while holding the lock. The lock file is `${XDG_RUNTIME_DIR:-/tmp}/rch/hook_autostart.lock`. If no process exists for it (`fuser` returns nothing), it's safe to remove. Prefer asking the user before doing so — it's a cleanup operation, not strictly an "rch" command. If authorized:

```bash
fuser "${XDG_RUNTIME_DIR:-/tmp}/rch/hook_autostart.lock" 2>/dev/null && echo "still held" || rm "${XDG_RUNTIME_DIR:-/tmp}/rch/hook_autostart.lock"
```

### Socket exists but `rch check` says not ready

A previous `rchd` died without cleanup. `try_auto_start_daemon` will detect a stale socket on next run and remove it. To force the issue:

```bash
rch daemon restart -y
rch --json daemon status | jq '.'
```

---

## Hook Re-installation (`daemon_installs_hooks`)

When `daemon_installs_hooks = true`, the daemon notices on startup whether the PreToolUse hook is registered for any detected agent (Claude Code, Codex, Gemini, etc.). If it's missing for the agent that owns the user session, it will reinstall.

This is mostly invisible. To inspect what the daemon thinks:

```bash
rch agents list --json
rch agents status
rch hook status --json
```

If you've explicitly uninstalled the hook (`rch hook uninstall`), set `daemon_installs_hooks = false` to avoid re-install on next daemon start.

Daemon startup also verifies hook ↔ socket consistency and `rch doctor --fix`
carries remediations for hook/daemon/socket drift. Version skew between the
CLI and a running `rchd` is only detectable manually (`rch --version` vs
`rch --json status | jq -r '.data.daemon.daemon.version'`).

---

## Worker Temporary Bypass and Auto-Rejoin

The second self-healing loop lives in the daemon (`rchd/src/bypass_recovery_service.rs`,
policy in `rch-common/src/bypass_recovery.rs`). A worker that fails transiently
is moved to **temporary bypass** (durable record under `RCH_STATE_HOME`),
distinct from operator **admin-disable** (`rch workers disable`, never probed).

- Probe backoff 30 s → 900 s (`[remediation.temporary_bypass]`).
- Rejoin requires `required_consecutive_passes = 2` fully-healthy probes across
  `ssh_ok, worker_binary_ok, protocol_ok, toolchain_ok, disk_ok (≥ 5 GB),
  load_ok, telemetry_ok`, then a passing canary (`canary_command = "rustc --version"`
  through the real build path). One failing dimension resets the streak.
- `reconcile_on_start` re-derives state from persisted records on daemon start,
  so a restart cannot silently un-bypass. `rch workers enable <id>` deletes the
  record so an operator re-enable survives restart.
- Observe: `rch status --fleet` (`bypassed N`), `rch status --remediation`
  ("Live Eligibility … temporarily bypassed (auto-rejoin)"), requested-worker
  refusals `RCH-I009`.

The historical wedge this replaced: persistent "all workers unreachable" with
`consec-fail never recovers` (bug `87z23`, closed) that forced fleet-wide local
fallback. If you see the fleet stuck bypassed with green probes, capture
`rch doctor --reliability --scope topology --json` before restarting anything.

---

## Self-Test as Continuous Verification

`rch self-test` runs the full classifier → daemon → worker → transfer → exec → result loop end-to-end. Schedule it (or just run it before believing the system is healthy):

```bash
rch self-test --all                               # one round on every worker
rch self-test --worker <worker-id>                # single worker
rch self-test --worker <worker-id> --debug --timeout 600  # debug build, longer timeout
rch self-test --scheduled                         # use scheduled config
rch self-test --smoke [--dry-run]                 # real-fleet smoke profile (planner + JSONL trace)
rch self-test --soak / --load                     # soak; bounded concurrent canary swarm with storm-control invariants
rch self-test status                              # last run + schedule
rch self-test history --limit 10
```

If `rch self-test --all` ever **hangs indefinitely**, that's the symptom of a known prior bug (`remote_compilation_helper-w5r9`, closed 2026-01-30) — kill it and capture `rch doctor --json`. Current versions are timeout-bounded; if you reproduce on 1.0.58+, escalate.

---

## Auto-Start Knobs You Can Tune

For test rigs or environments where you want autostart off:

```toml
[self_healing]
hook_starts_daemon = false
```

For environments where the autostart cooldown is too aggressive (rare):

```toml
[self_healing]
auto_start_cooldown_secs = 2
auto_start_timeout_secs = 5
```

Verify after editing:

```bash
rch config show --sources | grep -A6 self_healing
rch daemon reload
```

---

## Agent Operating Rules

- **Do** trust the autostart path on first failure. Re-issue the original `rch exec` once after `auto_start_cooldown_secs`.
- **Do** check `which rchd` if autostart never recovers.
- **Don't** delete `hook_autostart.cooldown` in a tight loop — that's defeating a safety. Either wait or use `rch daemon start` directly (which doesn't go through the cooldown path).
- **Don't** kill or restart rchd while builds are active. On 1.0.58 `rch daemon restart -y` interrupts them (it does not drain; `-y` only skips the warning); on 2.0.0 it refuses unless `--drain` or `--force`. Use it only after confirming `rch queue` shows no active builds.
- **Don't** ask the human "should I restart the daemon?" — the daemon's own self-healing is the right answer for transient failures. Only escalate after `rch doctor --json` plus `rch daemon logs -n 200` show an actionable upstream problem.
