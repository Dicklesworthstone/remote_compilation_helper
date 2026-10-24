# Recovery Playbooks (Symptom → Fix in ≤ 90 Seconds)

## Contents

- [Playbook A: "My build feels slow"](#playbook-a-my-build-feels-slow)
- [Playbook B: "Daemon unavailable"](#playbook-b-daemon-unavailable)
- [Playbook C: "All workers unreachable"](#playbook-c-all-workers-unreachable)
- [Playbook D: "All workers at capacity"](#playbook-d-all-workers-at-capacity)
- [Playbook E: "All workers failed preflight"](#playbook-e-all-workers-failed-preflight)
- [Playbook F: "Permission denied" during sync](#playbook-f-permission-denied-during-sync)
- [Playbook G: Worker disk pressure](#playbook-g-worker-disk-pressure)
- [Playbook H: Hook isn't being called](#playbook-h-hook-isnt-being-called)
- [Playbook I: Hook timeout / slow classification](#playbook-i-hook-timeout--slow-classification)
- [Playbook J: Worker version drift after upgrade](#playbook-j-worker-version-drift-after-upgrade)
- [Playbook K: `rch self-test` won't finish](#playbook-k-rch-self-test-wont-finish)
- [Playbook L: TOML/config edit broke things](#playbook-l-tomlconfig-edit-broke-things)
- [Playbook M: Local builds although the fleet is free (shim)](#playbook-m-local-builds-although-the-fleet-is-free-shim)
- [Playbook N: `[RCH-E301]` shell-wrapped cargo refused](#playbook-n-rch-e301-shell-wrapped-cargo-refused)
- [Playbook O: Exit 103 — strict remote refused](#playbook-o-exit-103--strict-remote-refused)
- [Playbook P: Job mode exit 102 / `RCH-E309`](#playbook-p-job-mode-exit-102--rch-e309)
- [When the Playbook Doesn't Apply](#when-the-playbook-doesnt-apply)

Each playbook is structured as: **observed signal → one-shot diagnostic → ordered fix attempts → verification**. Run them in order. Don't skip the diagnostic. Don't ask the human if the fix is in the playbook.

For unknown symptoms or a stuck loop, fall through to the bottom of this file ("When the Playbook Doesn't Apply") for the escalation packet.

---

## Playbook A: "My build feels slow"

**Signal:** Build wall time is much higher than expected; you suspect rch fell back to local.

```bash
# Diagnostic
RCH_VISIBILITY=verbose cargo check 2>&1 | grep -E '^\[RCH\]'
```

**Fix attempts:**

1. If you see `[RCH] local (...)` — open `references/FAIL_OPEN.md` and look up the parenthetical reason. Apply the matching self-fix.
2. If you see `[RCH] remote required; refusing local fallback (...)` — Playbook O.
3. If you see no `[RCH]` line at all — the hook isn't intercepting (`rch hook status`, `rch hook install`, `rch hook test`), or the build never went through the hook (Codex/script/absolute-path cargo) — Playbook M.
4. If you see `[RCH] remote ...` — RCH is doing what it can; the slowness is real. Inspect `rch speedscore --all`, `rch queue`, and whether the pooled target dir is warm (`rch cache status --workers <id>`).

**Verify:**

```bash
RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=verbose rch exec -- cargo check --workspace --all-targets 2>&1 | tail -5
```

The summary line should say `[RCH] remote <worker> (...)`; a refusal names what is missing.

---

## Playbook B: "Daemon unavailable"

**Signal:** `[RCH] local (daemon unavailable)` or `RCH-E500 / RCH-E502`.

```bash
# Diagnostic
rch --json daemon status 2>&1 | head -20
ls -la "${XDG_RUNTIME_DIR:-/tmp}/rch/" 2>&1
```

**Fix attempts:**

1. If `which rchd` is empty → daemon binary missing. Install rch (see project README).
2. If autostart cooldown is recent → wait out `auto_start_cooldown_secs` (30 s) and retry the original command, or run `rch daemon start` (not gated by the cooldown).
3. If autostart lock is held by no process → it's stale. Ask user authorization, then `rm "${XDG_RUNTIME_DIR:-/tmp}/rch/hook_autostart.lock"`.
4. Foreground spawn to surface the real error: `rch daemon start`. Read its stderr.
5. If `rch daemon start` succeeds but the hook still doesn't see the daemon, check socket consistency: `rch --json config get general.socket_path` and `rch --json daemon status | jq '.data.socket_path'` must match. If they don't: `rch daemon restart -y`.

**Verify:** `rch check` returns `ready`.

---

## Playbook C: "All workers unreachable"

**Signal:** `[RCH] local (all workers unreachable)` (JSON tag `all_workers_unreachable`) or `RCH-E100 / RCH-E101 / RCH-E108`.

```bash
# Diagnostic
rch --json workers probe --all | jq '.data.results[] | {id, status, error_code, error}'
rch status --fleet                     # probes green but "unreachable"? → workers are temporarily BYPASSED
```

**Fix attempts (per failing worker):**

0. If probes are green but the daemon still says unreachable, the workers are in temporary bypass and will auto-rejoin after 2 healthy probes + a canary build; `rch workers enable <id>` forces it. Don't restart the daemon for this.
1. SSH directly: `ssh -v -i <identity_file> ubuntu@<host> 'echo OK'`. The first error you see is the real one.
2. Auth error → check `identity_file` permissions (`chmod 600`), key on agent (`ssh-add -l`), and authorized_keys on the worker.
3. Connection refused → `sshd` not running on worker, or wrong port.
4. DNS / network unreachable → host moved or networking broken.
5. Host key changed → with explicit user authorization, refresh the entry. Compare fingerprints first.

**Verify:** `rch workers probe <id>` returns ok.

---

## Playbook D: "All workers at capacity"

**Signal:** `[RCH] local (all workers at capacity)` (snake-case tag in JSON: `all_workers_busy`) or `RCH-E204` repeatedly.

**Fix attempts (in order, escalating):**

1. **Verify queueing is on** — `RCH_QUEUE_WHEN_BUSY` is **already enabled by default** in current rch (only set `=0` to disable). If you still see `all workers at capacity`, queueing didn't help — the wait timed out.
2. Raise the wait timeout above its **330 s default** for the next invocation: `RCH_DAEMON_WAIT_RESPONSE_TIMEOUT_SECS=900 <your-command>` (a value like 120 would shorten it).
3. Check whether one worker is hot and others are cold (uneven distribution): `rch --json status --workers | jq '.data.daemon.workers[] | {id, used: .used_slots, total: .total_slots}'`.
4. If aggregate capacity is the problem, raise `total_slots` on top workers in `~/.config/rch/workers.toml`, then `rch daemon reload`.
5. Watch the backlog drain: `rch queue --watch` (this is an interactive polling view, not a TUI — Ctrl-C exits cleanly).
6. `no admissible workers: …` instead of "at capacity" means every candidate was rejected for a *reason* — `rch admit "<cmd>"` lists them (critical pressure, missing runtime, active-project exclusion, `os` gate). For sharded non-compilation work use `rch exec --job`, which queues on active-project exclusion instead of refusing.

**Verify:** Next `rch exec` lands `[RCH] remote <worker> (...)`.

---

## Playbook E: "All workers failed preflight"

**Signal:** `[RCH] local (all workers failed preflight checks)` (snake-case tag: `all_workers_failed_preflight`) or `RCH-E013..024 / RCH-E205 / RCH-E305 / RCH-E410..414`.

```bash
# Diagnostic
rch diagnose --dry-run "<the command>" 2>&1 | head -50
rch admit "<the command>"
RCH_LOG_LEVEL=debug RCH_REQUIRE_REMOTE=1 rch exec -- cargo check 2>&1 | tail -40
```

**Fix attempts:**

1. If a path-dep error (RCH-E013..016) → see `PATH_DEPENDENCIES.md` for the exact code.
2. If `RCH_TOPOLOGY_ERR_CANONICAL_NOT_DIRECTORY` or `_ALIAS_NOT_SYMLINK` in worker stderr → fix the topology on the worker (`/data/projects` should be a directory; `/dp` should be a symlink to it).
3. If `RCH-E205 Worker missing toolchain` → `rch workers sync-toolchain --all`. If **every** worker reports `missing clippy, rustfmt` while cargo works over SSH, the worker `rch-wkr` predates the PATH-fallback fix — `rch fleet deploy --verify`.
4. If `RCH-E305 Remote working dir error` → typically mirror perms broken; see Playbook F.
5. If `RCH-E411 dependency preflight stale` → `rch sync --force --worker <id> --project .`.

**Verify:** `rch diagnose --dry-run "<command>"` reports `Ready` for the closure plan.

---

## Playbook F: "Permission denied" during sync

**Signal:** `[RCH] local (remote pipeline failed)` (or `RCH-E405`) with stderr lines mentioning `Permission denied` or `Operation not permitted` under `/data/projects/<repo>`.

```bash
# Diagnostic
# (the fleet-wide mirror-ownership doctor probe, `--scope ownership`, exists from 2.0.0; on 1.0.58 check per worker:)
ssh ubuntu@<worker> "stat -c '%U:%G %a %n' /data/projects/<repo>"
```

**Fix:**

```bash
ssh ubuntu@<worker> 'sudo chown -R ubuntu:ubuntu /data/projects/<repo> && sudo chmod 775 /data/projects/<repo>'
RCH_REQUIRE_REMOTE=1 rch exec -- cargo check
```

If you see this on multiple repos, audit who's doing `sudo git clone` or running things as root in `/data/projects`.

---

## Playbook G: Worker disk pressure

**Signal:** `[RCH] remote <worker> failed [RCH-E210]` (or `E211/E215/E216/E217`); or `rch status` calls out a worker as critical.

See the dedicated `DISK_AND_PRESSURE.md`. TL;DR:

```bash
rch status --remediation                     # tightest free-disk ratio, which workers
rch --json status --workers | jq '.data.daemon.workers[] | select(.pressure_state != "healthy") | {id, pressure_state, pressure_reason_code, pressure_disk_free_gb}'
rch cache status --workers <id>              # what rch owns there
rch gc --dry-run --workers <id> && rch gc --workers <id>    # reap stale pooled/per-job target dirs
ssh ubuntu@<worker> 'df -h / /data /tmp 2>/dev/null; free -h; cat /proc/pressure/memory'
ssh ubuntu@<worker> 'sbh status --json'      # still hot → let sbh handle it
```

If `sbh` isn't installed on the worker: install it, or escalate. Don't `rm -rf` build artifacts blindly — other agents might be mid-build; `rch gc` only removes dirs idle past their window.

---

## Playbook H: Hook isn't being called

**Signal:** Builds run locally; `[RCH]` summary lines never appear; the hook seems silent.

```bash
# Diagnostic
rch hook status --json
rch agents status --json
which rch
cat ~/.claude/settings.json 2>/dev/null | jq '.hooks.PreToolUse'
```

**Fix attempts:**

1. Hook not installed → `rch hook install` (or `rch agents install-hook claude-code`).
2. Hook command path is wrong → `rch hook install` re-resolves to the current absolute path.
3. The Claude Code session predates the hook install → restart Claude Code (the harness only loads hooks on startup).
4. Hook installed but fires for a different agent → confirm `rch agents list --json` includes the agent you're running under.

**Verify:**

```bash
rch hook test
printf '%s\n' '{"tool_name":"Bash","tool_input":{"command":"cargo check"}}' | rch
```

The second should produce a JSON `updatedInput` rewriting to `rch exec -- cargo check`.

---

## Playbook I: Hook timeout / slow classification

**Signal:** Claude Code reports the hook timed out, or the hook is logging classification budget warnings.

```bash
# Diagnostic
RCH_LOG_LEVEL=debug printf '%s\n' '{"tool_name":"Bash","tool_input":{"command":"cargo build"}}' | rch 2>&1 | grep -iE 'budget|classif'
```

**Likely causes:**

- Massive `Cargo.toml`/`metadata` and the closure preflight is slow → the config/classification cache should warm; test with `RCH_DISABLE_CONFIG_CACHE=1` to see whether a stale cache is the difference before touching anything under `~/.cache/rch/` (deletion needs explicit user authorization).
- A misbehaving CI invocation is running rch in a loop and starving the daemon.
- Hook-side daemon auto-start is spawning `rchd` on every call (cooldown 30 s) — `rch daemon start` explicitly, or `--no-hook-auto-start` to measure without it.

If the hook's compilation decision exceeds 5ms, that's a budget regression worth filing.

---

## Playbook J: Worker version drift after upgrade

**Signal:** New rch features behave inconsistently across workers; `rch fleet status` shows mixed versions.

```bash
rch fleet status --json    # exact JSON shape varies by version; inspect first
rch fleet verify           # human-readable comparison of installed binaries
```

**Fix:**

```bash
rch fleet deploy --canary 25 --canary-wait 60 --verify
# observe output, then
rch fleet deploy --verify           # full rollout
rch fleet verify                    # confirm uniform
```

If rollback is needed: `rch fleet rollback --verify`.

For a single worker, `rch fleet deploy --worker <id> --verify` (deploy, single host).

---

## Playbook K: `rch self-test` won't finish

**Signal:** `rch self-test --all` runs forever or returns no output for minutes.

```bash
# Diagnostic
rch self-test --worker <id> --timeout 120 --debug 2>&1 | tail -30
rch self-test history --limit 5 --json
```

**Fix attempts:**

1. Try a single worker with `--timeout 120 --debug`. If that works, the `--all` mode is hitting a slow worker — narrow down with `rch speedscore --all`.
2. If self-test hangs against any single worker, that worker has a deeper problem. `rch workers probe <id>`, then drain it (`rch workers drain <id>`) and continue without it.
3. Capture a full doctor report: `rch doctor --json > /tmp/rch-doctor.json`. The old hang bug (`remote_compilation_helper-w5r9`, closed 2026-01-30) is fixed; if you reproduce on current rch, escalate with the doctor output.

---

## Playbook L: TOML/config edit broke things

**Signal:** Things were working; you edited `~/.config/rch/config.toml` or `workers.toml`; now nothing works.

```bash
rch config validate
rch config doctor
rch config show --sources
rch config diff                      # what differs from defaults
```

If `rch config validate` flags an issue, fix the indicated line and `rch daemon reload`. If you can't see what's wrong, `git diff` of the config (if you keep it under version control) is your friend. Otherwise `rch config init` writes a clean baseline you can compare against.

Two silent config traps: a `[[workers]]` rewrite that drops `os = "..."` un-fences a cross-platform worker; and on a macOS box with no `~/.config/rch/`, the CLI reads the legacy `~/Library/Application Support/com.rch.rch/` dir while a launchd daemon may be pointed at `~/.config/rch/workers.toml` (when both exist, XDG wins — `CONFIGURATION.md`).

---

## Playbook M: Local builds although the fleet is free (shim)

**Signal:** `rch queue` shows free slots, yet this box is compiling (`rch shim status` → `N local rustc running`; load average high; no `[RCH]` lines).

```bash
# Diagnostic
rch shim status --json
ps -eo pid,args | grep -E '[r]ustc|[c]argo' | head
```

**Fix attempts:**

1. Shim not installed → `rch shim install` (dispatcher boxes only; it refuses on `role = "worker"`).
2. `interception: none` → `~/.rch/shims` is not first on PATH for the shell the agent harness was launched from. Prepend it in that rc file and restart the harness.
3. Absolute-path `~/.rustup/toolchains/<tc>/bin/cargo` in `ps` output, or `N/M toolchains wrapped` → `rch shim install` again (new toolchains land unwrapped after `rustup toolchain install` / `acfs update`).
4. `--message-format` builds are rust-analyzer — expected local, ignore.
5. `bash -lc "cargo …"` builds resolving to a *real* cargo → same PATH problem as 2.

**Verify:** `rch shim status` reports 0 local builds and `direct`/`delegated` interception; the next shimmed `cargo check` prints `[RCH] remote …` (or a refusal, Playbook O — never a local build). Details: `SHIM.md`.

---

## Playbook N: `[RCH-E301]` shell-wrapped cargo refused

**Signal:** `rch exec -- bash -lc "cargo test -p a && cargo test -p b"` exits 1 with `[RCH-E301]` and empty stdout; envelope `fallback_reason: "shell-wrapped cargo command"`.

**Fix:** split into direct invocations — `RCH_REQUIRE_REMOTE=1 rch exec -- cargo test -p a`, then `-p b`. Non-compilation scripts that must run remotely use `rch exec --job -- ./script.sh`. This is a permanent refusal (not exit 103); retrying the same shape never helps.

---

## Playbook O: Exit 103 — strict remote refused

**Signal:** `[RCH] remote required; refusing local fallback (<reason>) — retryable`, exit 103. Sources of strictness: `RCH_REQUIRE_REMOTE=1`, the shim's fail-closed default, `general.role = "dispatcher"`, `--clean-overlay`, `--source-content-receipt`, `compilation.allow_local_fallback = false`.

```bash
# Diagnostic
rch status --remediation
rch admit "<the command>"
rch --json daemon status
```

**Fix attempts:**

1. `daemon unavailable` → Playbook B.
2. `no admissible workers: …` / `all workers …` → the fleet: Playbooks C, D, E, G by reason.
3. `<requested-worker refusal>` (`RCH_WORKER=x` set) → do the `next_action` in the line, or unset `RCH_WORKER`.
4. If a local build is genuinely acceptable *right now*: run without the strict source (`RCH_REQUIRE_REMOTE=0 rch exec -- …` when the strictness came from the shim/env), knowing it builds on this box.

Exit **1** with `(non-compilation command)` / `(config unavailable)` / `[RCH-E301]` is permanent — fix the command shape, not the fleet.

**Verify:** the next invocation prints `[RCH] remote <worker> (...)`.

---

## Playbook P: Job mode exit 102 / `RCH-E309`

**Signal:** `rch exec --job --result-dir <d> -- …` exits 102; envelope `outcome: "collection_error"` or `result_dirs[].status` ∈ `missing|transfer_failed`.

**Fix attempts:**

1. The job itself may have passed — read `remote_exit_code` in `rch --json exec …` output before re-running.
2. `missing` → the job never created `<d>` on the worker, or the path isn't repo-relative (absolute/traversing paths are refused up front with exit 2 / `RCH-E001`). Make the job `mkdir -p` it.
3. `transfer_failed` → worker disk (Playbook G) or transport (Playbook C); `rch daemon logs -n 200`.
4. `no admissible workers` for many shards → expected queueing: job requests wait on active-project exclusion (`RCH_QUEUE_WHEN_BUSY`, default on); raise `RCH_DAEMON_WAIT_RESPONSE_TIMEOUT_SECS` for long shard waits.

---

## When the Playbook Doesn't Apply

Capture the escalation packet before pinging the human:

```bash
mkdir -p /tmp/rch-escalation && cd /tmp/rch-escalation
rch doctor --json                         > doctor.json 2>&1 || true
rch --json daemon status                  > daemon-status.json 2>&1 || true
rch --json workers probe --all            > workers-probe.json 2>&1 || true
rch --json status --workers --jobs        > status.json 2>&1 || true
rch --json status --fleet                 > fleet.json 2>&1 || true
rch status --remediation                  > remediation.txt 2>&1 || true
rch --json doctor --reliability --scope all > reliability.json 2>&1 || true
rch --json queue                          > queue.json 2>&1 || true
rch --json config show --sources          > config.json 2>&1 || true
rch --json hook status                    > hook-status.json 2>&1 || true
rch --json agents status                  > agents-status.json 2>&1 || true
rch shim status --json                    > shim-status.json 2>&1 || true
rch --json self-test --all --timeout 120  > selftest.json 2>&1 || true
rch daemon logs -n 500                    > daemon.log 2>&1 || true
{ echo "rch=$(rch --version)"; echo "rchd=$(rchd --version 2>/dev/null || true)"; \
  echo "daemon-reported-version=$(rch --json status 2>/dev/null | jq -r '.data.daemon.daemon.version // ""')"; } > versions.txt
ls -lah
```

Then surface a one-paragraph synthesis to the human: what symptom you saw, what you tried (with playbook letter), where the packet lives. Don't ship a wall of text; the packet is the data, your message is the signal.
