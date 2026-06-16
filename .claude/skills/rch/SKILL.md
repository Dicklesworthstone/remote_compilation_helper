---
name: rch
description: >-
  Remote compilation helper. Use when: rch doctor, workers.toml, "no workers",
  "compilation slow", admission/why-not-offloaded, proof mode, fleet deploy,
  self-test, or offload cargo/gcc/bun.
---

# RCH — Remote Compilation Helper

Transparently offloads `cargo build`, `cargo test`, `bun test`, `gcc` to remote
workers. Same commands, faster builds. **Fail-open**: if remote execution is not
possible, commands run locally — RCH never blocks your build.

<!-- TOC: Operating Model | Diagnose | Will it offload? | Fleet | Worker illness | Quick Fixes | Worker Config | Install | Commands | Proof mode | Evidence | Debug | Validate | Anti-Patterns | References -->

## Operating Model — read this first

RCH self-heals. Most "broken RCH" symptoms are **transient** and recover on their
own; the failure mode in practice is operators making *permanent* changes to fix a
*temporary* problem, which converts self-healing capacity loss into real capacity
loss.

**Golden rules (do NOT break these):**

1. **Never edit `workers.toml` to fix transient illness.** A worker that is slow,
   briefly unreachable, or failing probes is handled automatically (see
   [Worker illness](#worker-illness--let-it-self-heal)). Editing the config or
   removing the worker defeats auto-rejoin.
2. **Never `rch workers disable` for transient illness.** `disable` is a
   **permanent, operator-intent** action for genuine decommission/maintenance —
   not for a worker that is temporarily unhealthy.
3. **Never `rm` the daemon socket or `kill` "stale" processes by hand.** Use
   `rch daemon restart` / `rch doctor --fix`; the daemon and hook self-heal each
   other.
4. **Prefer `rch doctor --fix` and the explainer commands over manual surgery.**
   Start with diagnosis, not SSH.

---

## Diagnose

```bash
rch doctor                # What's broken? (read-only)
rch doctor --fix          # Safe, idempotent auto-fix (backs up before mutating)
rch doctor --dry-run      # Show what --fix would do, change nothing
rch check                 # Quick yes/no: is RCH working right now? (exit 0/1/2)
rch status --remediation  # Operator view: fleet, admissibility, proof queue,
                          #   disk pressure, telemetry freshness, recent incidents
                          #   — each band tagged operator-action / self-healing / fail-open
```

`rch doctor --reliability [--check-schemas] [--json]` adds fleet/reliability
posture. **If `--fix` cannot solve it → see [Quick Fixes](#quick-fixes-safe-copy-paste)
or the [references](#references).**

---

## Will it offload? — admission explainer

When a build ran locally and you expected remote, ask RCH directly instead of
guessing from logs:

```bash
rch admit "cargo build --release"      # Recommendation: Offload | Local | Queue | Defer + reason
rch admit "cargo build --release" --json
rch diagnose "cargo test --workspace"  # Classification + offload decision + daemon health
rch diagnose "cargo test --workspace" --dry-run --json
```

`rch admit` reports the required capabilities, the proof policy, and — when a
command won't offload — a stable `RCH-Innn` reason code and next action. Common
reason codes:

| Code | Meaning | Typical next action |
|------|---------|---------------------|
| `RCH-I001` | No admissible workers | `rch status --fleet` — is the fleet absent vs overloaded vs missing capability? |
| `RCH-I003` | Insufficient slots | Queue or wait (`RCH_QUEUE_WHEN_BUSY=1`); don't add workers reflexively |
| `RCH-I006` | Missing runtime/toolchain/target | `rch workers capabilities --refresh`; install toolchain/target on worker |
| `RCH-I008` | Telemetry stale | `rch status --remediation` (telemetry band) — usually self-heals |
| `RCH-I011` | Local fallback | Expected when remote not worth it; force with `RCH_FORCE_REMOTE=1` |
| `RCH-I012` | Proof refusal | Strict mode refused local fallback — see [Proof mode](#proof-mode-interim-proof-lane) |
| `RCH-I017` | Wrong user/path worker binary | Re-run fleet deploy/validate; do not hand-patch the worker |

`rch --robot-triage --json`, `rch capabilities --json`, and `rch robot-docs guide`
give the full machine-readable surface — no README lookup needed.

---

## Fleet — desired vs live

```bash
rch status --fleet          # desired / live / absent / disabled / unreachable / healthy
rch status --fleet --json   # + dominant problem class + absence alerts
```

This answers *why capacity collapsed*: cloud-fleet disappearance, local pool
overload, admin disable, pressure, missing capability, or daemon/config drift —
**without** treating a transient bypass as a permanent desired-state edit.

---

## Worker illness — let it self-heal

A worker that fails health/probe is moved to a **temporary bypass** (quarantine)
by the daemon, with **probe backoff**. When probes recover, the worker enters
**recovered-pending-canary**, gets one **canary** build, and on success is
**auto-rejoined** to the healthy pool. You do not need to do anything.

| Situation | Do | Do NOT |
|-----------|-----|--------|
| Worker slow / flaky / briefly unreachable | Nothing — or `rch status --fleet` to watch it rejoin | Edit `workers.toml`; `rch workers disable` |
| Worker overloaded | `rch workers drain <id> -y` (reversible), then `rch workers enable <id>` | Permanently remove it |
| Genuine decommission / hardware maintenance | `rch workers disable <id> --reason "..." --drain -y` | Leave it silently absent (`--fleet` will alert) |
| Bring a drained/disabled worker back | `rch workers enable <id>` | — |

`disable` and config edits are **permanent operator intent**; reserve them for
lasting changes and always pair with a reason so the incident ledger records why.

---

## Quick Fixes (safe, copy-paste)

| Symptom | Safe fix |
|---------|----------|
| Anything looks wrong | `rch doctor --fix` (idempotent, backs up first) |
| SSH auth fails | `eval $(ssh-agent) && ssh-add ~/.ssh/your_key` |
| Daemon not running | `rch daemon start` (or `rch daemon restart`) |
| Socket stale / refused | `rch daemon restart` — never `rm` the socket by hand |
| Hook not installed | `rch hook install` (`--force` only after `rch hook status`) |
| "No workers available" | `rch status --fleet` to find the real cause — **do not** edit `workers.toml` for transient illness |
| Command ran locally unexpectedly | `rch admit "<command>"` to see the reason code |

The default socket path resolves to `$XDG_RUNTIME_DIR/rch.sock`, then
`~/.cache/rch/rch.sock`, then `/tmp/rch.sock`. **Never hardcode it** — query with
`rch --json daemon status`.

---

## Worker Config (`~/.config/rch/workers.toml`)

```toml
[[workers]]
id = "builder"
host = "192.168.1.100"        # IP or hostname
user = "ubuntu"
identity_file = "~/.ssh/id_ed25519"
total_slots = 8               # ≈ CPU cores - 2
priority = 100                # Higher = preferred (selection still gates on health/capability)
tags = ["rust", "bun"]        # Optional capabilities
```

### Auto-Discover from SSH Config

```bash
rch workers discover --from-ssh-config --dry-run  # Preview
rch workers discover --from-ssh-config            # Add to config
```

### Verify Workers

```bash
rch workers probe --all              # Test all workers
rch workers probe worker1 -v         # Test single, verbose
rch workers list --capabilities      # Show status + detected toolchains/targets
rch workers capabilities --refresh   # Re-probe exact user/path facts
```

---

## Fresh Install Checklist

- [ ] Prerequisites: `which rsync zstd ssh` (install missing)
- [ ] Config: `rch init` (wizard), or create `~/.config/rch/workers.toml` (see above)
- [ ] Daemon: `rch daemon start`
- [ ] Hook: `rch hook install`
- [ ] Validate: `rch doctor` → all green, then `rch self-test`

---

## Supported Commands (Auto-Offloaded)

| Category | Commands |
|----------|----------|
| Rust | `cargo build`, `cargo check`, `cargo clippy`, `cargo doc`, `cargo test`, `cargo nextest run`, `cargo bench`, `rustc` |
| Bun | `bun test`, `bun typecheck` |
| C/C++/Build | `gcc`, `g++`, `clang`, `make`, `cmake --build`, `ninja`, `meson compile` |

**Never offloaded** (run locally by design): `cargo install`, `cargo clean`,
`cargo fmt`, `bun install`/`add`/`remove`, `bun run`/`dev`/`build`, `bunx`,
watch modes, and piped/redirected/backgrounded commands.

---

## Proof mode (interim proof-lane)

To *prove* a build ran remotely (no silent local fallback), use strict mode.
`RCH_REQUIRE_REMOTE=1` is **fail-closed**: if remote can't proceed it refuses with
`RCH-I012` / `RCH-E301` instead of running locally. The interim proof-lane
pattern, with self-healing disabled so nothing is auto-started underneath you:

```bash
RCH_REQUIRE_REMOTE=1 RCH_NO_SELF_HEALING=1 rch --no-self-healing exec -- cargo test --workspace
RCH_REQUIRE_REMOTE=1 RCH_NO_SELF_HEALING=1 rch --no-self-healing exec -- cargo clippy --workspace --all-targets -- -D warnings
```

Rules:
- Keep the build command as **direct argv** after `--`. Do **not** wrap several
  cargo commands in `bash -lc "... && ..."` — shell-wrapped commands classify as
  non-compilation and strict mode refuses them (`RCH-E301`). Run separate
  `rch exec` invocations instead.
- `RCH_FORCE_REMOTE=1` is the **fail-open** cousin: always attempt offload but
  still fall back to local. `RCH_REQUIRE_REMOTE` takes precedence.
- This is the **interim** proof lane. For durable proof, the daemon records a
  deferred **proof intent** and replays it (see [Evidence](#where-the-evidence-lives)).

---

## Where the evidence lives

Structured records back every decision — point postmortems and validation at
these, not at scraped logs. Paths resolve under `RCH_STATE_HOME`, else
`$XDG_STATE_HOME/rch`, else `~/.local/state/rch`, else `/tmp/rch`:

| Record | Path | Holds |
|--------|------|-------|
| Incident ledger | `<state>/incidents.jsonl` | Append-only reason-coded incidents (`RCH-Innn`) with context |
| Proof intents | `<state>/proofs.jsonl` (or `[remediation.proof] store_path`) | Deferred proof-mode intents + replay state |
| E2E test logs | `target/test-logs/*.jsonl` (`RCH_TEST_LOG_FILE` to override) | Structured `run_id`/`bead_id`/`scenario`/`reason_code` events |
| Daemon logs | `rch daemon logs -n 200` (rotated by default; `RCH_LOG_FILE`) | Daemon activity |

Read them via `rch status --remediation --json`, `rch diagnose "<cmd>" --json`,
and `rch admit "<cmd>" --json` — all carry the same reason-code vocabulary.

---

## Debug

```bash
RCH_LOG_LEVEL=debug rch diagnose "cargo build --release"   # Show the offload decision
RCH_LOG_LEVEL=debug rch check
rch diagnose "cargo check" --dry-run                       # Full pipeline, no side effects
rch doctor --json > diag.json                              # Export diagnostics
rch daemon logs -n 200                                     # Recent daemon log
```

---

## Validate (this skill's behavior is tested)

```bash
# Telemetry freshness / why-unhealthy explanations:
cargo test -p rch-common --lib telemetry_explain
# Incident ledger + reason-code registry:
cargo test -p rch-common --lib incident
# Proof mode + deferred proof replay:
cargo test -p rch-common --lib proof
# Admission explainer goldens + reason-code vocabulary:
cargo test -p rch-common --test admission_goldens_e2e
# Command classification (the hook's offload decision):
cargo test -p rch -- classify
# Golden agent/operator output stability:
cargo test -p rch-common --test golden_schemas_e2e
# Skill regression guard (forbidden/destructive guidance cannot return):
./scripts/check_rch_skill.sh
```

---

## Anti-Patterns

| Don't | Why | Do Instead |
|-------|-----|------------|
| Edit `workers.toml` for a slow/flaky worker | Defeats auto-rejoin; permanent loss for a transient problem | Let temporary bypass + canary rejoin it; watch `rch status --fleet` |
| `rch workers disable` for transient illness | `disable` is permanent operator intent | `rch workers drain -y` (reversible) or do nothing |
| `rm /tmp/rch.sock` / `kill` stale rchd | Races the self-healing daemon/hook | `rch daemon restart`, `rch doctor --fix` |
| Hardcode `/tmp/rch.sock` | Real socket may be runtime/cache path | `rch --json daemon status` |
| Assume remote failure == local failure | Often a worker/topology issue | `rch diagnose` + `rch exec -- ...` |
| Infer execution location from noisy logs | Logs are not the contract | `rch admit "<cmd>" --json` (`local_or_remote`, `reason_code`) |
| Run daemon as root | Security risk | `systemctl --user start rchd` / `rch daemon start` |

---

## References

| Topic | File |
|-------|------|
| Operations runbook (incidents, fleet, queue, transfer) | [OPERATIONS.md](references/OPERATIONS.md) |
| Config schema, precedence, runtime data paths | [CONFIGURATION.md](references/CONFIGURATION.md) |
| Worker schema, selection algorithm, SSH discovery | [WORKERS.md](references/WORKERS.md) |
| Error/reason codes, symptom→fix table | [TROUBLESHOOTING.md](references/TROUBLESHOOTING.md) |
| Hook protocol, 5-tier classification, security | [HOOKS.md](references/HOOKS.md) |
| Command reference | [COMMANDS.md](references/COMMANDS.md) |
