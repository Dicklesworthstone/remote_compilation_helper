# Multi-Agent Contention

## Contents

- [Same Project on Same Worker (TOCTOU)](#same-project-on-same-worker-toctou)
- [All Workers Busy / Backlog Pressure](#all-workers-busy--backlog-pressure)
- [Daemon Stop / Restart Coordination](#daemon-stop--restart-coordination)
- [Worker Setup Storms](#worker-setup-storms)
- [Concurrent Edits in the Project Tree During Sync](#concurrent-edits-in-the-project-tree-during-sync)
- [Shared Path Dependencies: Source-Authority Locks](#shared-path-dependencies-source-authority-locks)
- [Stale Daemon Across rch CLI Upgrade](#stale-daemon-across-rch-cli-upgrade)
- [Auto-Start Cooldown](#auto-start-cooldown)
- [SSH ControlMaster Poisoning](#ssh-controlmaster-poisoning)
- [Cancellation Storms](#cancellation-storms)
- [Coordination Stack Cheat Sheet](#coordination-stack-cheat-sheet)

When 22 Claude Max accounts and 11 GPT Pro accounts are all driving rch on the same machine and into the same worker fleet, the failure modes are no longer about correctness — they're about contention. This file catalogs the patterns and the cooperation rules.

---

## Same Project on Same Worker (TOCTOU)

**Symptom:** Two agents kick off `cargo build` for the same project at almost the same time. One succeeds; the other gets `RCH-E305 Remote working directory error` or sees the rsync target locked.

**Root cause:** Two builds racing in the same `target/` checkout on the worker.

**Status:** Largely fixed in v1.0.16 (commit `fbea95f`, then `dbf9682` for the final TOCTOU-race close on the daemon API side). The daemon now:
- Excludes workers already running an active build for the same project from selection
- Atomically claims the active-build slot after slot reservation

**What you can still do wrong:** bypass the daemon. If you `ssh worker 'cd /data/projects/foo && cargo build'` outside `rch exec`, you defeat the guard. Always go through `rch exec` (or let the hook route the command).

**If you see the symptom anyway:**

1. Confirm both agents are routing through the daemon, not direct SSH. Active builds live in `rch --json queue`, not `daemon status`:
   ```bash
   rch --json queue | jq -r '.data.active_builds[]? | "\(.id) \(.worker_id) \(.project_id)"'
   ```
2. Look for the same `project_id` repeated across active builds.
3. If reproducible, capture `rch doctor --json` and `rch daemon logs -n 200`; this is an upstream regression worth filing.

---

## All Workers Busy / Backlog Pressure

**Symptom:** `[RCH] local (all workers at capacity)` or `[RCH] local (all worker circuits open)` start showing up under heavy swarm load. (Snake-case tags in JSON output: `all_workers_busy`, `all_circuits_open`.)

**Self-fix (per-agent, no human needed):**

Queue-when-busy is **on by default** in current rch — agents already wait for a slot rather than falling open immediately. The env var `RCH_QUEUE_WHEN_BUSY` exists primarily to *disable* this (set `=0`) for benchmarking. If you still see `[RCH] local (all workers at capacity)`, the wait timed out — bump it:

```bash
export RCH_DAEMON_WAIT_RESPONSE_TIMEOUT_SECS=900   # default is 330 s — setting 120 would SHORTEN the wait
```

This buys more time for slots to free up before falling back. For queue-or-die behavior, combine with `RCH_REQUIRE_REMOTE=1` (refuse local fallback, exit 103 when the wait expires) and a high timeout.

**Fleet-wide tuning:**

```bash
rch queue --watch                                                          # see backlog live
rch --json status --workers --jobs | jq '.data.daemon.workers[] | {id, used: .used_slots, total: .total_slots}'
rch workers list --speedscore                                              # spread across workers
```

If aggregate slot capacity is the bottleneck, raise `total_slots` on the fastest workers (`~/.config/rch/workers.toml`) and `rch daemon reload`. A reasonable starting point is `2x physical cores`.

If a single worker is hot and others are cold, check runtime gates (`bun`/`go`/`nix` probed capabilities, the `os =` gate) or affinity pinning (`[selection.affinity] pin_minutes = 60`) funneling everyone to one worker — tags never gate.

**Job mode is different.** `rch exec --job` requests that lose every worker to active-same-project exclusion are *queued*, not refused: an N-shard burst larger than the fleet spreads one shard per worker and waits for the rest (affinity fallback is suppressed so a queued shard cannot land on a busy worker). Compilation requests still get immediate `no admissible workers`.

---

## Daemon Stop / Restart Coordination

**Risk:** One agent runs `rch daemon restart -y` while five others have active builds against the daemon. The restart drops their connections.

**Cooperation rule:**

- Never `rch daemon stop` or `rch daemon restart` while builds are active: they **interrupt** builds, they do not drain. The CLI prompts ("N active build(s) will be interrupted"); `-y` skips that prompt, and the daemon may refuse with `shutdown_blocked` (the CLI does not surface that clearly). That is 1.0.58; on 2.0.0 both commands refuse while builds are in flight, `--drain` waits for them and `--force` interrupts them.
- Before any restart, check:
  ```bash
  rch --json queue | jq '.data.active_builds | length'
  ```
  If the active list isn't empty, drain first or wait.

If you must restart (e.g., new binary deploy), use:

```bash
rch fleet drain --all -y          # gracefully stop accepting new jobs fleet-wide (workers, not local)
rch daemon restart -y             # local daemon
for w in $(rch --json workers list | jq -r '.data.workers[].id'); do rch workers enable "$w"; done   # there is no `rch fleet enable`
```

Right after a daemon restart, selections can briefly fail with
`selection error: restart_admission_barrier_active` — the daemon is
re-deriving job leases and bypass records; retry, don't restart again.

Use Agent Mail file reservations on `~/.config/rch/{config.toml,workers.toml}` and the daemon socket path before destructive ops.

---

## Worker Setup Storms

**Symptom:** Six agents all hit `rch workers setup --all` at once. They step on each other deploying `rch-wkr` binaries and toolchains; one or more workers end up half-installed.

**Cooperation rule:**

`rch workers setup` and `rch fleet deploy` are idempotent but not multi-writer safe under heavy concurrency. Wrap them with a host-local flock so only one runs at a time. The skill ships `scripts/multi_agent_safety.sh` as a wrapper:

```bash
.claude/skills/rch/scripts/multi_agent_safety.sh rch workers setup --all
```

Or use Agent Mail file reservations:

```text
file_reservation_paths(project_key, agent_name,
  paths=["~/.config/rch/workers.toml", "~/.config/rch/config.toml"],
  ttl_seconds=600, exclusive=true,
  reason="rch fleet deploy")
```

---

## Concurrent Edits in the Project Tree During Sync

**Symptom:** rsync error mid-transfer — file changed/disappeared mid-stream. Or `RCH-E406 Transfer checksum mismatch`.

**Root cause:** Another agent is editing files while your build is being shipped to the worker.

**Mitigations:**

- Add `target_*/`, `target-*/`, and other artifact-shaped patterns to `[transfer] exclude_patterns` so build outputs don't get picked up by the upload (cf. recent split between upload and retrieval excludes in `transfer.rs`).
- For multi-agent projects, take an Agent Mail reservation on the source files before you touch them, so other agents stage their work elsewhere.
- Use **clean-overlay mode** instead of stashing: `RCH_REQUIRE_REMOTE=1 rch exec --base HEAD --clean-overlay --overlay-path <your files> -- cargo test` ships the committed tree plus only your explicit paths, and refuses if an overlay changes mid-transfer (`EXEC_MODES.md`). Never `git stash` other agents' work.
- `RCH-E402` / `RCH-I013` (rsync vanished file) is the same story from the transport side.

---

## Shared Path Dependencies: Source-Authority Locks

When two agents build projects that share a path dependency (sibling repo under
the canonical root), rch holds an exclusive `flock` on every mutable closure
root on the worker from before the first rsync until **Cargo exits**
(`/tmp/rch-source-authority-locks/<blake3>.lock`, one persistent SSH session
per invocation). A sync-only lock was insufficient: another invocation could
replace a manifest while rustc was still reading the closure.

Verbose lines: `[RCH] waiting for N remote source-authority lock(s) on <worker>`
→ `acquired` → `released … after Cargo exit`. A build "stuck" there is waiting
for a peer's Cargo, not hung. Lock loss is fail-closed (the run errors rather
than proceeding without authority). Clean-overlay and receipt runs use isolated
roots and don't take these locks.

---

## Stale Daemon Across rch CLI Upgrade

**Symptom:** You ran `rch update` (or installed a new build) and now CLI features behave oddly while the daemon is still running the old version.

**Self-fix:**

```bash
rch --version
rch --json status | jq -r '.data.daemon.daemon.version'   # `daemon status` has no version field
# If they don't match (this manual comparison is the only version check — `rch check` has no version field):
rch daemon restart -y
rch --json status | jq -r '.data.daemon.daemon.version'   # Confirm equal
```

`rch fleet verify` checks worker binary hashes too:

```bash
rch fleet verify
```

If a worker is on an old `rch-wkr`, deploy:

```bash
rch fleet deploy --canary 25 --canary-wait 60 --verify
# or for a single worker:
rch fleet deploy --worker <id> --verify
```

To update both the local rch CLI and the fleet binaries in one shot: `rch update --fleet`.

---

## Auto-Start Cooldown

`try_auto_start_daemon` in `rch/src/hook/auto_start.rs` writes a cooldown timestamp to `${XDG_RUNTIME_DIR:-/tmp}/rch/hook_autostart.cooldown` after each spawn attempt. Subsequent invocations within `[self_healing] auto_start_cooldown_secs` (default **30s**) get `AutoStartError::CooldownActive` and fall open.

**Implication for swarms:** Right after a daemon crash, only the first agent gets to restart it. Everyone else falls open until the cooldown expires (30 seconds by default — that's a long time for a swarm; lower it via `[self_healing] auto_start_cooldown_secs = 5` if you accept the trade-off of more spawn churn on a flapping daemon).

**What to do:** Don't manually delete the cooldown file in a tight loop. Let the 30 s cooldown expire, or `rch daemon start` explicitly (which doesn't go through the hook autostart path).

If something is genuinely wedged and the cooldown is hiding a real failure to spawn:

```bash
ls -la "${XDG_RUNTIME_DIR:-/tmp}/rch/"     # see lock + cooldown
cat "${XDG_RUNTIME_DIR:-/tmp}/rch/hook_autostart.cooldown"
rch daemon start                           # bypasses hook cooldown
```

If `rch daemon start` itself fails, you have a real problem — check `rch daemon logs -n 200` and `which rchd`.

---

## SSH ControlMaster Poisoning

`SshOptions::default().control_master = false` since the recent fix (commit `464a25b`). Stale local control sockets had been poisoning otherwise healthy connections.

If you (or another agent) explicitly opted into ControlMaster via `RCH_SSH_CONTROL_PERSIST_SECS` and you start seeing intermittent `RCH-E100`/`RCH-E105` errors:

```bash
ls ~/.ssh/control-* ~/.ssh/cm-* /run/user/$(id -u)/openssh-* "${TMPDIR:-/tmp}"/ssh-* 2>/dev/null   # /run/user is Linux-only
# If stale sockets exist, remove them (with user authorization for /run path)
ssh -O check ubuntu@<host> 2>&1 || true
ssh -O exit ubuntu@<host> 2>&1 || true
```

Then unset `RCH_SSH_CONTROL_PERSIST_SECS` for the next swarm run. See `SSH_TUNING.md`.

---

## Cancellation Storms

If a parent agent issues `rch cancel --all --yes` while sub-agents are mid-build, expect:

- `RCH-E320` graceful cancel signal dispatched
- `RCH-E321` escalated to forced kill after timeout (if the sub-agent's command ignored SIGTERM)
- `RCH-E323` post-cancel cleanup errors (rare; usually file-handle related)
- `RCH-E324` slots not released after cancel (rare; daemon log will show it)

Best practice in swarms:

- Prefer `rch cancel <build-id>` over `--all`. Sub-agents tell you their build IDs in the summary line.
- If you must `--all`, broadcast it via Agent Mail first so sub-agents know to expect failures.

---

## Coordination Stack Cheat Sheet

| Concern | Mechanism |
|---|---|
| Mutual exclusion on rch config edits | Agent Mail `file_reservation_paths` + `flock` wrapper |
| Awareness of others' active builds | `rch --json queue \| jq '.data.active_builds[]? \| {id, worker_id, project_id}'` |
| Awareness of disk pressure on workers | `rch --json status --workers \| jq '.data.daemon.workers[] \| {id, pressure_state, pressure_reason_code}'` |
| Avoiding hot-restart of daemon under load | check `rch queue` before `rch daemon restart` |
| Avoiding worker setup races | `multi_agent_safety.sh` flock + Agent Mail reservation |
| Building only your own edits on a shared tree | `rch exec --base HEAD --clean-overlay --overlay-path …` |
| Sharded/fuzz work across the fleet | `rch exec --job --result-dir …` (queues per worker instead of refusing) |
| Quiet failure detection in long swarms | grep `[RCH] local` in stderr captures, or `rch --json exec` envelopes (see `FAIL_OPEN.md`) |
| Where every fail-open went | `rch status --remediation` ("Recent Incidents"), incident ledger under `RCH_STATE_HOME` |
