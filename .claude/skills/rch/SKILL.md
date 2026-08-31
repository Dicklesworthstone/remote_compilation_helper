---
name: rch
description: >-
  Offload cargo/gcc/bun builds to remote workers. Use when compilation slow,
  "[RCH] local" in stderr, workers unhealthy, hook silent, sync fails, disk
  pressure, or SSH/daemon/telemetry recovery.
---

# RCH — Remote Compilation Helper

`rch` transparently offloads compilation commands to remote workers via a Claude Code PreToolUse hook (and, for every other agent/shell, via the managed cargo shim). The daemon picks a healthy worker, rsync's the workspace, runs the build, syncs artifacts back, and exits with the worker's exit code.

This skill is the operational layer agents use when that pipeline isn't working — and the much more common case where it *thinks* it's working but is silently building locally. Single principle: **self-resolve before asking the human.** Every recovery path here is one the agent can run alone.

Harmonized against `remote_compilation_helper` main @ `b5c0566` (2026-08-25), workspace **v1.0.58**. The released 1.0.58 binary predates the post-release shim toolchain-wrapper commits; where that matters it is called out.

---

## Read This First

When a build feels slow, run **one** thing:

```bash
RCH_VISIBILITY=verbose <your-command> 2>&1 | grep -E '^\[RCH\]'
```

The summary line is a contract:

| Pattern | What to do |
|---|---|
| `[RCH] remote <worker> (...)` | Healthy. Done. |
| `[RCH] remote <worker> failed (exit N)` / `failed [RCH-Exxx] ...` | Real build/env failure. `rch error explain RCH-Exxx`; `references/ERROR_CODES.md`. |
| `[RCH] local (<reason>)` | **Fail-open.** `references/FAIL_OPEN.md`; look the reason up verbatim. |
| `[RCH] remote required; refusing local fallback (<reason>)` | **Fail-closed** (strict remote / shim / dispatcher role). Exit 103 = retry after fixing the fleet; exit 1 = permanent. |
| _no `[RCH]` line at all_ | Hook didn't fire, or the shim isn't ahead on PATH. `scripts/protocol_test.sh "<cmd>"` then `rch shim status`. |

If you can't see why offload isn't happening, **prove the path in isolation, loudly**:

```bash
RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=verbose rch exec -- cargo check --workspace --all-targets
```

`[RCH] remote <worker> (...)` ⇒ the offload pipeline is healthy and the problem is upstream (hook classifier, PATH/shim order, the invocation form). A refusal line names exactly what's missing. Then `references/RECOVERY_PLAYBOOKS.md`.

---

## Quick Start

```bash
rch check                                   # exit 0 ready / 1 degraded / 2 not ready
rch status --workers --jobs                 # full status
rch status --remediation                    # bands: operator-action vs self-healing vs normal fail-open
rch status --fleet                          # desired vs live workers: bypassed / disabled / unreachable / missing
rch workers probe --all                     # connectivity + component matrix + probe_warnings
rch hook status && rch agents status        # which agents are wrapped
rch shim status                             # cargo shim: PATH order, local builds running, toolchains wrapped
rch admit "cargo test -p foo"               # read-only admission preflight
rch diagnose --dry-run "cargo check --workspace --all-targets"
RCH_REQUIRE_REMOTE=1 rch exec -- cargo check --workspace --all-targets
rch self-test --all                         # end-to-end verify
rch doctor --reliability --scope topology,pressure   # (`ownership` scope is post-1.0.58)
rch doctor --fix --dry-run                  # what doctor would auto-fix
rch --robot-triage --json                   # agent mega-command
```

If `rch status` shows storage pressure, check both `/` and `/tmp` on the worker before deciding what to fix:

```bash
ssh <user>@<host> 'df -h / /tmp /data 2>/dev/null; free -h; cat /proc/pressure/memory /proc/pressure/io'
```

---

## Fast Triage Order

Run in order; stop at the first failing stage.

1. **Availability** — `rch check`, `rch status --workers --jobs`, `rch status --fleet`, `rch workers probe --all`, `rch queue`
2. **Config + socket consistency** — `rch config show --sources`, `rch --json config get general.socket_path`, `rch --json daemon status` (version is in `rch --json status` → `.data.daemon.daemon.version`)
3. **Interception** — `rch hook status`, `rch agents status`, `rch shim status`, `rch hook install` (idempotent)
4. **Classification + admission + closure** — `rch diagnose --dry-run "<cmd>"`, `rch admit "<cmd>"`
5. **Remote compile proof** — `RCH_REQUIRE_REMOTE=1 rch exec -- cargo check --workspace --all-targets`
6. **If sync fails or storage looks bad** — `rch cache status --workers <id>`, `rch gc --dry-run --workers <id>`, then `references/DISK_AND_PRESSURE.md`

---

## Quick Fixes

| Symptom | Command |
|---------|---------|
| Hook not installed | `rch hook install && rch hook status` (Gemini/Codex: `rch agents install-hook gemini-cli\|codex-cli`) |
| Codex / scripts / CI build locally | `rch shim install` on the dispatcher — `references/SHIM.md` |
| `rch shim status` shows local rustc running | fix PATH order (`~/.rch/shims` first) or re-run `rch shim install` after a `rustup toolchain install` |
| Daemon not running | `rch daemon start` |
| Daemon version drift after upgrade | `rch daemon restart -y` — after `rch --json queue \| jq '.data.active_builds\|length'` is 0: restart **interrupts** active builds (`-y` only skips the warning prompt) |
| Socket mismatch / stale daemon state | `rch daemon restart -y` then `rch --json daemon status` |
| No workers configured | `rch workers discover --add --yes && rch workers setup --all` (or `rch workers init`) |
| Workers unreachable | `rch workers probe --all`; keys → `references/SSH_KEY_RECOVERY.md` |
| "all workers unreachable" persists though probes pass | workers are in **temporary bypass**: `rch status --fleet`; they auto-rejoin after N healthy probes + a canary build; `rch workers enable <id>` clears the record |
| All workers busy | queueing is default (waits 330 s); raise it — `RCH_DAEMON_WAIT_RESPONSE_TIMEOUT_SECS=900 <cmd>` — or raise `total_slots` |
| `no admissible workers` | `rch admit "<cmd>"` — per-candidate rejection reasons + next action |
| Requested worker refused (`RCH_WORKER=x`) | the `[RCH-Innn]` line carries a `next_action`; do it — rch never silently swaps workers |
| Shell-wrapped cargo refused `[RCH-E301]` | never `rch exec -- bash -lc "cargo … && cargo …"`; run separate `rch exec -- cargo …` |
| Job exits 102 with `RCH-E309` | a declared `--result-dir` was missing/partial on the worker; fix the path, the job itself may have passed |
| Need a per-command priority bump | `RCH_PRIORITY=high <cmd>` |
| Want `RUSTFLAGS`/`RUST_LOG` forwarded | `RCH_ENV_ALLOWLIST=RUSTFLAGS,RUST_LOG <cmd>` (`CARGO_TARGET_DIR`/`TMPDIR` are always rewritten on the worker) |
| Transfer churn / payload too large (`transfer skipped`) | `.rchignore` or `[transfer] exclude_patterns`, then `rch daemon reload` |
| Path dependency missing remotely | `references/PATH_DEPENDENCIES.md` (`[path_topology]`; `rch sync --force` for stale worker caches) |
| Sync `Permission denied` under `/data/projects/<repo>` | `ssh <user>@<host> "stat -c '%U:%G %a %n' /data/projects/<repo>"` then fix: `ssh <user>@<host> 'sudo chown -R <user>:<user> /data/projects/<repo> && sudo chmod 775 /data/projects/<repo>'` (a fleet-wide `rch doctor --reliability --scope ownership` probe exists on main only) |
| Worker disk pressure (RCH-E210/211…) | `rch cache status`, `rch gc --dry-run`, then `references/DISK_AND_PRESSURE.md` / `sbh` |
| Telemetry / SpeedScore broken | `references/TELEMETRY_RECOVERY.md` |
| Hook says installed but isn't intercepting | `scripts/protocol_test.sh "<cmd>"` |
| Multiple agents racing on fleet ops | `scripts/multi_agent_safety.sh <cmd>` + Agent Mail reservations |
| `--target *-pc-windows-msvc` / `*-apple-*` won't offload | needs a worker declaring `os = "windows"` / `"darwin"` — `references/WORKERS.md`; without one it correctly runs local |
| Cross-platform worker taking the wrong jobs | it has no `os =` set; add it, and roll rchd out first (older builds ignore the key silently) |
| Build must run **locally on purpose** (release binary for this host) | `.rch/config.toml` → `[general] force_local = true`, plus `RCH_CARGO_WRAPPER_BYPASS=1` if the shim is installed; inline `RCH_ENABLED=0` does **not** bypass the hook |
| Need a runbook, not a guess | `rch doctor --runbook-list`; `rch doctor --runbook RCH-R006` |
| Need full environment diagnosis | `rch doctor --json`, `rch config doctor` |

---

## Worker Priority and Slots Are **Measured**, Never Guessed

**Rule: never hand-set `priority` or `slots` in `workers.toml` from intuition, core count, or price tier. Derive them from a persisted SpeedScore. If no score exists, fixing that comes first — it is a bug, not a reason to guess.**

Hand-tuned priorities silently invert. A real example from this fleet: the two highest-priority workers (`110`) had the *fewest* slots (4 and 5) while ten-slot workers sat at `100`, so the scheduler preferentially routed to the smallest, most disk-constrained boxes — which is exactly why those two filled to 96–98% first.

### The correct sequence

```bash
rch workers benchmark --all --force     # measure
rch workers list --speedscore           # confirm scores persisted and DIFFER
rch workers compare <id> <id> <id>      # side-by-side
rch speedscore <worker>                 # per-worker detail + components
# only now: set priority ∝ measured score, slots ∝ cores
```

### Verify the score is real before you trust it

| Check | Bad sign | Meaning |
|---|---|---|
| Spread across workers | every worker scores the same (esp. exactly `100.0`) | scoring is saturated/clamped — worthless for ranking |
| Correlation with hardware | a 6-core box outscores a 16-core box | benchmark is single-threaded or measuring current *load* |
| Persistence | `rch speedscore <w>` says "not benchmarked yet" right after a successful benchmark | score isn't being stored; the scheduler will re-benchmark forever |

That third one has a loud tell: `daemon.log` fills with alternating `Benchmark completed successfully ... score: 100.0` and `Enqueued benchmark request ... reason: new_worker` for the same worker. That is an infinite re-benchmark loop and will grow the log to hundreds of MB. (A persisted score is now treated as "already benchmarked" — if you still see the loop, the store is broken.)

`rch workers benchmark` (the CLI probe) times an SSH round-trip around a hello-world compile. It is **not** a capability measurement and must never be used to rank workers. The authoritative number is the daemon's SpeedScore (CPU 30 / disk 20 / compilation 20 / memory 15 / network 15 via `rch-telemetry`).

### Before recommending more hardware

```bash
rch queue        # → "● N available  ● M busy  ● 0 offline / X / Y slots free"
```

If slots are free and nothing is queued, **more machines will not help** — say so. Look for the real constraint in this order: **disk pressure** (workers >90% degrade and fail builds long before slots run out; `rch status --remediation` shows the tightest free-disk ratio), then stale/inverted priorities, then slot counts that don't match core counts. Only recommend buying when `rch queue` shows sustained zero free slots under real load.

---

## Anti-Asking Rules

These are the questions agents historically ask the human that they should *just answer themselves*. **Do not ask. Do.**

- "Can I restart the daemon?" — Yes, once `rch --json queue | jq '.data.active_builds|length'` is 0. `rch daemon restart -y` does **not** drain: `-y` skips the "N active build(s) will be interrupted" prompt, and the daemon may refuse (`shutdown_blocked`) while builds run. Wait or `rch cancel` first.
- "Can I install the hook / the shim?" — Yes on a dispatcher box (`rch hook install`, `rch shim install`). The shim refuses on a `role = "worker"` box by itself.
- "The autostart cooldown is blocking me — can I delete the cooldown file?" — Don't; wait `auto_start_cooldown_secs` (30 s) or run `rch daemon start`, which isn't gated by the hook cooldown.
- "Can I drop the corrupt telemetry db?" — Yes. `references/TELEMETRY_RECOVERY.md`. Telemetry is derived data.
- "Should I recover SSH keys from a sibling host?" — If the keys are missing here but reachable on another host, yes. `references/SSH_KEY_RECOVERY.md` Step 3.
- "Should I run the benchmarks before setting priorities?" — Yes, always. Priorities without a persisted SpeedScore are guesses.
- "Every worker scored the same — can I rank them by core count?" — No. An identical score across the fleet means scoring is broken; fix the score.
- "Should we buy more workers?" — Answer from `rch queue` and `rch status --remediation`, not intuition. Free slots + empty queue = no. Check disk pressure first.
- "The worker is at 97% disk — should I delete the rch build pool?" — Run `rch cache status --workers <id>` then `rch gc --dry-run --workers <id>`; let the reaper's verdicts (`REAPABLE` vs `pooled (kept)` vs `active/recent (kept)`) decide. Never `rm -rf` a `.rch-target-*` dir by hand while `rch queue` shows that project active.
- "A shimmed build exited 103 — should I uninstall the shim?" — No. 103 means the *fleet* had nothing admissible; `rch status --remediation`, fix that, retry.
- "It's waiting on a source-authority lock — is it hung?" — No. Another invocation holds a shared path-dependency root on that worker; it releases when that Cargo exits.

When in genuine doubt, capture the escalation packet (end of `references/RECOVERY_PLAYBOOKS.md`) and surface that — not a wall of text — to the human.

---

## `rch exec` Modes You Should Know (details: `references/EXEC_MODES.md`)

| Need | Form |
|---|---|
| Proof it ran remotely | `RCH_REQUIRE_REMOTE=1 rch exec -- cargo test --workspace` (refuses fallback; exit 103 retryable / 1 permanent) |
| Machine-readable outcome | `rch --json exec -- cargo test -p foo` → one NDJSON envelope: `outcome` (delivery) + `location` + `remote_exit_code` |
| Non-compilation remote work (shards, fuzz, bench) | `rch exec --job --result-dir crashes -- ./fuzz.sh` (result dirs come back even on failure; missing dir ⇒ exit 102 `RCH-E309`) |
| Build the committed tree, ignore others' edits | `rch exec --base HEAD --clean-overlay --overlay-path src/lib.rs -- cargo test` (remote-only by construction) |
| Byte-exact source receipt | `rch exec --source-content-receipt -- cargo test --locked` → `rch.source_content_receipt.v1` |
| Several cargo commands | separate invocations — a shell-wrapped chain is refused (`RCH-E301`) |

---

## Knobs Worth Knowing (Env Vars)

Every name below is read by 1.0.58 code (`references/CONFIGURATION.md` has the full list and the ones that are *not* read).

| Variable | Use |
|---|---|
| `RCH_VISIBILITY=summary\|verbose\|none` | `[RCH] ...` summary line per offloaded build. Code default is `none` — set `summary` in your harness env. Refusals print regardless. |
| `RCH_REQUIRE_REMOTE=1` | Fail closed instead of building locally (proof mode). Wins over `RCH_FORCE_REMOTE`. |
| `RCH_FORCE_REMOTE=1` | Skip local-time/speedup gating, still fail open. |
| `RCH_QUEUE_WHEN_BUSY` | Wait for a slot instead of local fallback. **Default `1`.** `0` to opt out (benchmarking). |
| `RCH_DAEMON_WAIT_RESPONSE_TIMEOUT_SECS` (alias `RCH_DAEMON_RESPONSE_TIMEOUT_SECS`) | Max seconds to wait for a queued worker. **Default 330** — set it higher, not lower, to wait longer. |
| `RCH_WORKER=id[,id]` (alias `RCH_WORKERS`, merged) | Request specific worker(s); inadmissible ⇒ refused with `RCH-Innn` + next action. |
| `RCH_PRIORITY=low\|normal\|high` | Scheduler hint. |
| `RCH_ENV_ALLOWLIST=K1,K2` | Forward env vars to the remote build (`RUSTFLAGS`, `RUST_LOG`, …). |
| `RCH_MAX_REMOTE_ATTEMPTS` | Remote retry budget (default 3). |
| `RCH_DISABLE_TARGET_REUSE=1` | Legacy per-job remote target dir instead of the pooled `.rch-target-*-pool-*`. |
| `RCH_SYNC_TIMEOUT_MS` | Per-attempt source-upload timeout (1000..=3600000); default is payload-aware. |
| `RCH_COMPRESSION_LEVEL` | Transfer compression (default 3). (`RCH_TRANSFER_ZSTD_LEVEL` is *not* read.) |
| `RCH_SSH_SERVER_ALIVE_INTERVAL_SECS` / `RCH_SSH_CONTROL_PERSIST_SECS` | Keepalive (recommend 15) / opt-in ControlMaster (default OFF). |
| `RCH_LOG_LEVEL=debug` | Diagnostics on stderr; surfaces which fail-open path was taken. |
| `RCH_SOCKET_PATH` | Daemon socket override. (`RCH_DAEMON_SOCKET` is *not* read.) |
| `RCH_NO_SELF_HEALING=1` / `--no-self-healing` / `--no-hook-auto-start` | Disable autostart/hook re-install for one invocation. |
| `RCH_ENABLED=0` | Disable rch — only effective in the **process env** of the hook/`rch exec`, not as an inline prefix inside an agent's command. |
| `RCH_CARGO_WRAPPER_BYPASS=1` | Shim/toolchain-wrapper bypass → real cargo. |
| `RCH_OUTPUT_FORMAT=json\|toon`, `RCH_JSON=1` | Machine output. |
| `RCH_CANONICAL_PROJECT_ROOT` / `RCH_ALIAS_PROJECT_ROOT` | Override `[path_topology]` roots. |

---

## RABS (Asupersync-native Accelerated Build Sidecar) — What To Tell Agents

RABS is a new build-caching sidecar inside the rch workspace (11 crates — 10 `rabs-*` plus `rabsd` — all `publish = false`; binaries `rabsd`, `rabs-wrap` as a `RUSTC_WRAPPER`, `rabs-wkr`). As of 2026-08-25 it is **opt-in and shadow-only**: `rabs-wrap` computes a canonical action key, consults the daemon, records a `would_have_hit` receipt, then execs the real rustc unconditionally — **it does not serve cache hits yet** (bead `bd-k52xe` open). Nothing wires `RUSTC_WRAPPER` automatically; `install.sh` builds the spine best-effort and `scripts/rabs_fleet_deploy.sh` deploys it only to bwrap-capable hosts. It is fail-open by design (`rabsd --doctor` treats a dead daemon as WARN).

Operator surface: `rch rabs gc plan|run|history`, `rch rabs worker reconcile <W>` (proposals only), `rch rabs doctor`, `rch rabs inventory`. These act on the RABS CAS (`~/.cache/rch/rabs-state/cas`), **not** on worker target dirs — don't reach for them for disk pressure. If an agent asks "is RABS making my builds faster?" the honest answer today is no; the win is still rch offload itself.

---

## Reference Index

**Recognising what's wrong:**
- `references/FAIL_OPEN.md` — every `[RCH] local (...)` reason and refusal line mapped to a self-fix
- `references/ERROR_CODES.md` — `RCH-Ennn` catalog, `RCH-Innn` refusal codes, `RCH-Rnnn` runbooks, the three exit-code schemes
- `references/TROUBLESHOOTING.md` — diagnostic flow + common errors

**Solving specific failure classes:**
- `references/RECOVERY_PLAYBOOKS.md` — symptom → fix in ≤90 s, lettered playbooks A–P
- `references/SHIM.md` — cargo shim, toolchain wrapping, local-build alarm, building locally on purpose
- `references/EXEC_MODES.md` — strict remote, job mode, clean overlay, receipts, exec envelope, source-authority locks
- `references/SSH_KEY_RECOVERY.md` — when workers.toml references keys this host doesn't have
- `references/PATH_DEPENDENCIES.md` — multi-repo workspaces, closure planner, `[path_topology]`
- `references/DISK_AND_PRESSURE.md` — pooled target dirs, `rch gc` / `rch cache`, reaper config, RCH-E210..217, `sbh` handoff
- `references/TELEMETRY_RECOVERY.md` — corrupt `~/.local/share/rch/telemetry/telemetry.db`
- `references/SELF_HEALING.md` — autostart cooldown, temporary bypass + auto-rejoin, `[self_healing]`
- `references/SSH_TUNING.md` — ControlMaster, keepalives, retry classification

**Operating in fleets and swarms:**
- `references/MULTI_AGENT_CONTENTION.md` — TOCTOU, source-authority locks, fleet deploy races, autostart cooldown sharing
- `references/OPERATIONS.md` — runbook + worker fleet lifecycle
- `references/WORKERS.md` — worker config, lifecycle states, `os =` gate, Windows workers, fleet commands
- `references/CONFIGURATION.md` — every config section/key/default, env vars (incl. the ones that don't exist), runtime paths
- `references/HOOKS.md` — hook protocol, per-agent install, what is/isn't intercepted
- `references/MACHINE_INTROSPECTION.md` — `--json` shapes, envelope, verified jq recipes
- `references/COMMANDS.md` — full command/flag reference (quoted from clap)

**Automation scripts (in `scripts/`):**
- `auto_recover.sh` — heuristic, dry-run-by-default fleet recovery
- `worker_disk_triage.sh` — read-only mount-aware disk report per worker
- `protocol_test.sh` — probe the hook protocol with synthetic input
- `multi_agent_safety.sh` — flock wrapper for fleet/setup operations
- `mine_rch_history.sh` — find prior agent sessions that hit a given failure
- `diagnose-rch.sh` — end-to-end diagnostic (health, socket, workers, hook, shim, protocol)
- `validate-setup.sh` — verify prerequisites/config/daemon/hook before use

**Templates and project docs:**
- `assets/workers-template.toml`
- Source: <https://github.com/Dicklesworthstone/remote_compilation_helper> — `README.md`, `CHANGELOG.md`, `docs/runbooks/*`

---

## Adjacent Skills

- **`sbh`** — disk-pressure defense for AI coding workloads. Use when `RCH-E210/211/215/216` fires and `rch gc` isn't enough.
- **`agent-mail`** — file reservations and messaging between agents. Use before `rch fleet deploy` or any worker config edit in a swarm.
- **`ntm`** / **`vibing-with-ntm`** — multi-agent tmux orchestration; common parent context for agents that hit rch failures.
- **`cass`** — search prior agent sessions; `scripts/mine_rch_history.sh` is the fallback when the cass index has dead pointers.
- **`provision-new-machine`** — provisioning a cloud VPS as an rch worker (root env, `TMPDIR`-only, no global `CARGO_TARGET_DIR`).

---

## Reading Output: TUI vs Hook

`rch` with **no subcommand** is the PreToolUse hook (JSON in, JSON out) — don't run bare `rch` expecting help; use `rch --help`. `rch dashboard` (alias `rch tui`) and `rch web` are interactive and block your session; `rch dashboard --dump-state` / `--test-mode` are the non-interactive escapes.
