# Detecting and Responding to RCH Fail-Open

## Contents

- [Golden Rule](#golden-rule)
- [The Summary-Line Surface](#the-summary-line-surface)
- [Fail-Open Reasons (and What To Do)](#fail-open-reasons-and-what-to-do)
- [Fail-Closed Refusals (Not Fail-Open)](#fail-closed-refusals-not-fail-open)
- [Detection Snippets](#detection-snippets)
- [Force the Issue](#force-the-issue)
- ["Don't Ask the Human" Rules](#dont-ask-the-human-rules)

RCH's most expensive failure mode for agents is **silent fall-back to local
execution**: the build "succeeded" but ran locally, slowly, while the fleet sat
idle. This file is how to *see* a fail-open, what each reason means, and what
to do before asking anyone.

## Golden Rule

**Never say "build done" until you've checked stderr for `[RCH] local (...)`.**
Or use `rch --json exec` and assert `location == "remote"` (`EXEC_MODES.md`).

## The Summary-Line Surface

`rch exec` and the hook print one summary line on stderr per routed
compilation, controlled by `[output] visibility = none|summary|verbose` (default
**`none`** in code — set `RCH_VISIBILITY=summary` in your harness env or config).

| Pattern | Meaning |
|---|---|
| `[RCH] remote <worker> (<duration>)` (`412ms` / `8.1s`) | successful remote build |
| `[RCH] remote <worker> failed (exit <N>)` | ran remotely; the build itself failed — a normal compiler/test error |
| `[RCH] remote <worker> failed [RCH-Exxx] <summary>` | build-environment failure on the worker; `ERROR_CODES.md` |
| `[RCH] local (<reason>)` | **fail-open** — compilation ran locally; read the reason |
| `[RCH] remote required; refusing local fallback (<reason>)[ — retryable]` | **fail-closed refusal** (strict remote); nothing ran; exit 103 (retryable) or 1 |
| `[RCH] remote required; refusing local fallback [RCH-E301] (non-compilation command)` | fail-closed, permanent (exit 1): `RCH-E301` (`BuildUnknownCommand`) is the code for both this strict-remote non-compilation refusal and the shell-wrapped-cargo refusal — for a real non-compilation job use `rch exec --job`; for `bash -lc "cargo …"` split into direct `rch exec -- cargo …` calls |
| `[RCH] refusing local fallback (compilation.allow_local_fallback=false; <reason>)` | box-level fail-closed |
| `[RCH] waiting for N remote source-authority lock(s) on <worker>` | verbose: contending with another invocation on a shared path dep — not hung |
| _(no line)_ | visibility `none`, or RCH never engaged — re-run with `RCH_VISIBILITY=verbose` |

Refusal lines are emitted via `summary_critical` and show even at visibility
`none`.

## Fail-Open Reasons (and What To Do)

Reasons come from three places: hook decision points (`rch/src/hook.rs`),
the daemon's `SelectionReason` (`rch-common/src/types.rs`, human `Display`
form in the summary, snake_case tag in JSON), and requested-worker refusals
(`rch-common/src/placement.rs`).

### Hook-decision fail-opens

| Reason text | Triggered when | Self-fix |
|---|---|---|
| `daemon unavailable` | socket unreachable and auto-start failed / disabled / in cooldown | `rch daemon start && rch --json daemon status`; `SELF_HEALING.md` |
| `force_local` **(hook path only)** | `[general] force_local = true` (often a project `.rch/config.toml`). `rch exec`/the shim never consult `force_local` | intentional; `rch config get general.force_local --sources` shows where |
| `invalid config: force_local+force_remote` **(hook path only)** | both set (e.g. project `force_local` + `RCH_REQUIRE_REMOTE` in the harness env) | unset one; `rch daemon reload` |
| `confidence below threshold` **(hook path only)** | classifier weak match (threshold `[compilation] confidence_threshold` 0.85) | `rch diagnose "<cmd>"`; restructure the command or `force_remote` in `.rch/config.toml` |
| `command '<base>' not in allowlist` **(hook path only)** | `[execution] allowlist` excludes the command base | `rch --json config get execution.allowlist`; add it |
| `non-compilation command` | `rch exec` given a non-compilation command (exit 1 under strict remote) | use `rch exec --job` if it must run remotely |
| `config unavailable` | config failed to load | `rch config validate` |
| `dependency preflight <RCH-Exxx>: <remediation>; evidence: <summary>` / `dependency preflight failed: <summary>` | closure planner refused (cycle, missing manifest, off-root path dep, stale worker cache) | follow the remediation; `PATH_DEPENDENCIES.md`; `rch sync --force` for stale caches |
| `transfer skipped` (+ sub-reason) | payload exceeds `[transfer] max_transfer_mb` / `max_transfer_time_ms` | tighten excludes / `.rchignore`, or raise the caps |
| `toolchain missing on <worker>` | remote rustup/cargo/component absent | `rch workers sync-toolchain --all`; `rch workers capabilities --refresh` |
| `remote execution failed` (the `rch exec` path) / `remote pipeline failed` (legacy in-hook execution path) | generic transfer/exec failure | `RCH_LOG_LEVEL=debug rch exec -- <cmd>`; `rch daemon logs -n 200` |
| `<reason>; remote retries exhausted` | `RCH_MAX_REMOTE_ATTEMPTS` (default 3) used up | fix the underlying reason; raise the budget only if failures are transient |
| `[RCH-I001] daemon selected unrequested worker '<id>' for requested set […]` | `RCH_WORKER` asked for workers the daemon could not honor | `rch admit "<cmd>"`; fix the requested worker or drop `RCH_WORKER` |
| `<requested-worker refusal summary>` (`RCH-I001`–`I007`, `I009`) | requested worker inadmissible: unknown id, admin-disabled, draining, temporarily bypassed, wrong platform, missing runtime, project-excluded, no free/total slots, critical pressure, hard preflight | every refusal carries a `next_action`; do that |

### Daemon-decision fail-opens (`SelectionReason`)

| JSON tag | Human form in `local (...)` | Self-fix |
|---|---|---|
| `no_workers_configured` | `no workers configured` | `rch workers discover --add --yes && rch workers setup --all` |
| `all_workers_unreachable` | `all workers unreachable` | `rch workers probe --all`; `SSH_TUNING.md` / `SSH_KEY_RECOVERY.md`. If it *persists* with probes green, see `rch status --fleet` for **temporary bypass** state |
| `all_circuits_open` | `all worker circuits open` | inspect `rch --json status --workers \| jq '.data.daemon.workers[] \| {id, circuit_state, last_error, recovery_in_secs}'`; auto-closes after cooldown |
| `all_workers_busy` | `all workers at capacity` | queueing is on by default (wait default **330 s**), so this means the wait timed out: raise it, e.g. `RCH_DAEMON_WAIT_RESPONSE_TIMEOUT_SECS=900` (120 would *shorten* it), or raise `total_slots`; `rch queue --watch` |
| `no_workers_passed_health` | `no workers passed health thresholds` | `[selection] min_success_rate / max_load_per_core / min_free_gb` exclude everyone; `rch status --remediation` |
| `all_workers_failed_preflight` | `all workers failed preflight checks` | `rch diagnose --dry-run "<cmd>"`; E013–E024, E205, E305, E410–E414 |
| `all_workers_failed_convergence` | `all workers failed repo convergence checks` | sibling repos missing/unwritable on workers; `PATH_DEPENDENCIES.md` |
| `no_admissible_workers` | `no admissible workers: <summary>` | `rch admit "<cmd>"` lists per-candidate rejections (`critical_pressure`, `insufficient_slots`, `circuit_open`, `telemetry_stale`, `hard_preflight`, `missing_runtime`, `missing_toolchain`, `missing_rust_target`, `os_arch_mismatch`, `active_project_exclusion`, …) |
| `no_matching_workers` | `no matching workers found` | an explicit `RCH_WORKER`/preferred set matched no configured worker; check ids with `rch workers list`. (The `os` gate surfaces as `no admissible workers: os_gate_excluded=… required_os=…` instead) |
| `no_workers_with_runtime` | `no workers with Bun installed` (capitalized: `Bun`, `Go`, `Nix`, `Node`, `Rust`, `Zig`) | install the runtime on a worker, `rch workers capabilities --refresh` |
| `selection_error` | `selection error: <msg>` — payloads seen: `restart_admission_barrier_active` (daemon just restarted; retry), `queue_timeout`, `hook_exited` | retry; if persistent capture `rch doctor --json` + `rch daemon logs -n 200` |

`affinity_pinned` / `affinity_fallback` are success paths and never appear in
`local (...)`.

### "Build" succeeded but nothing went remote

```
   Compiling foo v0.1.0
    Finished `dev` profile in 38.41s
[RCH] local (all workers at capacity)
```

That is a 38-second build that should have taken 2 seconds remotely. Fix the
reason, don't move on.

## Fail-Closed Refusals (Not Fail-Open)

Under `RCH_REQUIRE_REMOTE=1`, the shim's default body, `general.role =
"dispatcher"`, `--clean-overlay`, `--source-content-receipt`, or
`compilation.allow_local_fallback = false`, RCH **refuses** instead of building
locally. Exit **103** = retryable (no worker assignable now, daemon momentarily
unavailable); exit **1** = permanent (`non-compilation command`, `config
unavailable`, shell-wrapped cargo `RCH-E301`). Retry 103 after fixing the fleet
(`rch status --remediation`); don't loop on 1.

## Detection Snippets

```bash
# Wrapper that runs a build and asserts remote
out=$(RCH_VISIBILITY=summary cargo check 2>&1)
if grep -qE '^\[RCH\] (local|remote required|refusing)' <<<"$out"; then
  echo "RCH DID NOT RUN THIS REMOTELY:" >&2; grep -E '^\[RCH\]' <<<"$out" >&2; exit 99
fi

# JSON-mode proof (scripted agents)
rch --json exec -- cargo check --workspace 2>/dev/null \
  | jq -e '.location=="remote" and .outcome=="completed"' >/dev/null || echo "not remote"

# Where did every fail-open go? (incident ledger via status)
rch --json status | jq '.data.daemon.remediation, .data.remediation_hints'
```

## Force the Issue

To know whether the offload path works at all, bypass the hook and forbid
fallback:

```bash
RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=verbose rch exec -- cargo check --workspace --all-targets
```

`[RCH] remote <worker> (...)` ⇒ the pipeline is healthy and the problem is
upstream (hook, classifier, PATH/shim, the agent's invocation form). A refusal
line names exactly what is missing. Don't wrap the command in `env
CARGO_TARGET_DIR=…` any more — target dirs are rewritten on the worker
regardless (pooled `.rch-target-*`).

## "Don't Ask the Human" Rules

- **`daemon unavailable`** → `rch daemon start`. If the auto-start cooldown is active, wait it out; `rch daemon start` bypasses the cooldown.
- **`all workers unreachable`** → `rch workers probe --all`; fix keys/hosts; check `rch status --fleet` for bypassed workers.
- **`all workers at capacity`** → raise the wait above its 330 s default (`RCH_DAEMON_WAIT_RESPONSE_TIMEOUT_SECS=900`), or `total_slots`.
- **`toolchain missing on X`** → `rch workers sync-toolchain --all`.
- **`no admissible workers`** → `rch admit "<cmd>"`, then fix what it names.
- **Stale unix socket** → auto-start already handles it; just retry.
- **`Permission denied` under `/data/projects/<repo>`** → `ssh <user>@<host> 'sudo chown -R <user>:<user> /data/projects/<repo> && sudo chmod 775 /data/projects/<repo>'`; (a fleet-wide mirror-ownership doctor probe, `--scope ownership`, exists from 2.0.0; on 1.0.58 use the per-worker `stat`/`chown` recipe in `OPERATIONS.md`).
- **Exit 103 from a shimmed cargo** → the fleet, not the shim: `rch status --remediation`.

When in genuine doubt, collect `rch doctor --json`, `rch --json status --workers
--jobs`, `rch --json workers probe --all`, the failing command's stderr, and
`rch daemon logs -n 200` (Playbook end of `RECOVERY_PLAYBOOKS.md`).
