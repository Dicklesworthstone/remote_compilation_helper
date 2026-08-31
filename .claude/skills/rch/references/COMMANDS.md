# Command Reference (rch main @ 2026-08-25, workspace v1.0.58)

Every flag below is quoted from the clap definitions in
`rch/src/main.rs` (and `rch/src/commands/{rabs_gc,why}.rs`). Prefer
`rch --help-json <path>` at runtime; this table is the offline copy.

## Contents

- [Global Flags](#global-flags)
- [Health, Status, Queue](#health-status-queue)
- [Execution: `exec`, `diagnose`, `admit`, `why`](#execution-exec-diagnose-admit-why)
- [Daemon](#daemon)
- [Workers](#workers)
- [Hook, Agents, Shim](#hook-agents-shim)
- [Config](#config)
- [Doctor, Self-Test, Error Catalog](#doctor-self-test-error-catalog)
- [Storage: `gc`, `cache`, `sync`, `rabs`](#storage-gc-cache-sync-rabs)
- [Fleet, Update, SpeedScore](#fleet-update-speedscore)
- [UI and Discovery](#ui-and-discovery)
- [Things That Do NOT Exist](#things-that-do-not-exist)
- [Other Binaries](#other-binaries)

## Global Flags

| Flag | Effect |
|---|---|
| `-v, --verbose` / `-q, --quiet` | verbosity |
| `-j, --json` | machine JSON (standard envelope) |
| `-F, --format json\|toon` | machine format; env `RCH_OUTPUT_FORMAT` |
| `--color auto\|always\|never`, `--no-color` | ANSI control |
| `--no-self-healing` | disable all self-healing for this invocation (== `RCH_NO_SELF_HEALING=1`) |
| `--no-hook-auto-start` | disable hook-side daemon auto-start for this invocation |
| `--robot-triage` | agent mega-command: quick_ref + recommended commands + health probes |
| `--schema <cmd path>` | JSON Schema for a command's output |
| `--help-json [cmd path]` | help tree as JSON (intercepted before clap) |
| `--capabilities` | root-level only (not accepted after a subcommand): legacy raw-JSON capability dump; prefer `rch capabilities --json` |

No subcommand ⇒ **PreToolUse hook mode** (JSON on stdin). Don't run bare `rch`
from a terminal expecting help.

## Health, Status, Queue

```bash
rch check                              # exit 0 ready / 1 degraded / 2 not ready; --json → .data.status ready|degraded|not_ready
rch status [-w|--workers] [-J|--jobs]
rch status --fleet                     # desired vs live worker grouping, dominant problem class, absence alerts
rch status --remediation               # bands tagged operator-action / self-healing / normal fail-open
rch queue [-w|--watch] [-f|--follow]   # follow = stream build events (tail -f)
rch cancel [<build_id>] [-a|--all] [-f|--force] [-y|--yes] [-n|--dry-run]
```

## Execution: `exec`, `diagnose`, `admit`, `why`

```bash
rch exec [--base <COMMIT> --clean-overlay (--overlay-path <P>... | --no-overlay)]
         [--source-content-receipt] [--job [--result-dir <DIR>...]] -- <command...>
rch diagnose [-n|--dry-run] <command...>    # full offload pipeline explanation; --json → .data.placement etc.
rch admit <command...>                       # read-only admission preflight: recommendation, family, required caps
rch why miss --prior <JSON|-> --current <JSON>            # explain a cache/plan miss between two breakdowns
rch why refusal --outcome first-seen|serving-blocked|trust-refused|materialization-unavailable
```

Full semantics of every `exec` mode: `EXEC_MODES.md`.

## Daemon

```bash
rch daemon start | stop [-y] | restart [-y] | status | logs [-n <LINES>=50] | reload
```

`rch --json daemon status` returns only `{running, socket_path, uptime_seconds}`.
The daemon's **version** is at `rch --json status` → `.data.daemon.daemon.version`.

`rchd` itself: `-s/--socket`, `-w/--workers-config`, `--history-file`,
`--history-capacity` (100), `-f/--foreground`, `--metrics-port` (9100),
`--metrics-reset-interval` (300), `--debug-routing`, `--no-hot-reload`, `-v`.

## Workers

```bash
rch workers list [--speedscore]
rch workers capabilities [--refresh] [--command <CMD>]
rch workers probe [<worker>] [-a|--all]            # prints probe_warnings next to the component matrix
rch workers benchmark [<WORKER_ID> | --all] [--force]
rch workers compare <WORKER_ID> <WORKER_ID>...      # side-by-side SpeedScore data
rch workers drain <worker> [-y]
rch workers enable <worker>                         # also clears a persisted temporary-bypass record
rch workers disable <worker> [--reason <R>] [--drain] [-y]
rch workers deploy-binary [<worker>] [--all] [--force] [--dry-run]
rch workers discover [--probe] [--add] [--yes]      # long --yes only, no -y
rch workers sync-toolchain [<worker>] [--all] [--dry-run]
rch workers setup [<worker>] [--all] [--dry-run] [--skip-binary] [--skip-toolchain]
rch workers init [-y]                               # write workers.toml from detected defaults
```

States: HEALTHY / DRAINING / DRAINED / DISABLED (admin), plus daemon-side
**temporary bypass** (auto-rejoin after N healthy probes + a canary build).

## Hook, Agents, Shim

```bash
rch hook install | uninstall [-y] | test | status         # Claude Code only
rch agents list [--all] | status [<agent>] | install-hook <agent> [--dry-run] | uninstall-hook <agent> [--dry-run]
   # agent ids (kebab): claude-code gemini-cli codex-cli cursor continue-dev windsurf aider cline
rch shim install [--allow-local-fallback] [--no-toolchains] | status | uninstall     # see SHIM.md
```

## Config

```bash
rch config show [--sources] | get <key> [--sources] | set <key> <value> | reset <key>
rch config init [--wizard] [--non-interactive] | validate | lint | doctor | diff
rch config edit [--project | --user | --workers]
rch config export [--format shell|env]
rch completions generate <shell> | install [<shell>] [--dry-run] | uninstall <shell> [--dry-run] | status
```

There is no `rch config check`; it is `validate` (syntax) / `lint` / `doctor`
(semantic, incl. missing `identity_file` keys).

## Doctor, Self-Test, Error Catalog

```bash
rch doctor [--fix] [--dry-run] [--install-deps]
rch doctor --reliability [--check-schemas] [--strict|--lenient] [--scope all|topology,convergence,pressure,triage,helpers,rollout,schema]   # main adds `ownership` (mirror-ownership probe); 1.0.58 rejects it and has no such probe
rch doctor --reliability --watch [--watch-interval <S>=5] [--transitions-only] [--watch-snapshot <PATH>]
rch doctor --runbook <RCH-Rnnn>          # render an authored runbook as Markdown, no probes
rch doctor --runbook-list                # 10 authored runbooks on 1.0.58 (11 on main)
rch self-test [status | history [--limit N]] [--worker <W>] [--all] [--project <P>] [--timeout <S>=300] [--debug]
              [--scheduled] [--smoke] [--soak] [--load] [--dry-run]
rch error explain <RCH-Ennn|RCH-Innn> [--json]
rch error list [--category <snake_case>] [--json]     # 166 known codes on 1.0.58 (E + I + R namespaces)
```

Note: `rch doctor --help` currently prints no description (the doc comment is
attached to `rch error` in source) — the flags above are correct regardless.

## Storage: `gc`, `cache`, `sync`, `rabs`

Three distinct surfaces — do not conflate:

```bash
rch gc [-n|--dry-run] [--workers <ID>...]        # reap stale remote target dirs NOW (same sweep as the daemon's periodic one)
rch cache status [--workers <ID>...]              # read-only: per-dir path/size/idle/verdict incl. pooled dirs
rch cache clean [--older 24h] [--project <NAME>] [--execute] [--base <PATH>...]   # local staging trees; dry-run unless --execute
rch cache warm [--workers <ID>...] [--project <PATH>]
rch sync [--force] [-w <WORKER>] [-a|--all] [-p <PROJECT>] [-n]   # force-resync stale worker caches for a closure (preview unless --force)
rch rabs gc plan|run|history [--cas-root DIR] [--mode normal|emergency] [--protect KEY]... [--budget N] [--reconciled] [--max-listed N]
rch rabs worker reconcile <WORKER> [--cas-root DIR]   # proposals only, never auto-applied
rch rabs doctor [--cas-root DIR] [--min-seq-lag N=1000]
rch rabs inventory [--cas-root DIR] [--l2-root DIR] [--allow-namespace NS]...
```

`rch rabs …` operates on the RABS content-addressed store (`~/.cache/rch/rabs-state/cas`
or `$RABS_STATE_DIR/cas`), **not** on worker target dirs. See `DISK_AND_PRESSURE.md`.

## Fleet, Update, SpeedScore

```bash
rch fleet deploy [--worker <ID[,ID]>] [--parallel 4] [--canary <PCT>] [--canary-wait 60] [--no-toolchain] [--force]
                 [--verify] [--drain-first] [--drain-timeout 120] [--dry-run] [--resume] [--version <V>] [--audit-log <P>] [-y]
rch fleet rollback [--worker <ID>] [--to-version <V>] [--parallel 4] [--verify] [--dry-run] [-y]
rch fleet status [--worker <ID>] [--watch]
rch fleet verify [--worker <ID>]
rch fleet drain [<worker>] [--all] [--timeout 120] [-y]
rch fleet history [--limit 10] [--worker <ID>]
rch fleet doctor --reliability [--scope a,b] [--fix --fleet-confirm] [--continue-on-failure] [--workers <ID,ID>] [--worker-timeout 10]
rch update|upgrade [--check] [--version <V>] [--channel stable|beta|nightly] [--fleet] [--rollback] [--verify|--skip-verify]
                   [-y] [--dry-run] [--no-restart] [--drain-timeout 60] [--show-changelog]
rch speedscore [<worker>] [--all] [--history] [--days 30] [--limit 20]
```

There is **no** `rch fleet enable`; re-enable workers with `rch workers enable <id>`.

## UI and Discovery

```bash
rch dashboard|tui [--refresh 1000] [--no-mouse] [--test-mode] [--mock-data] [--dump-state] [--high-contrast] [--color-blind <mode>]
rch web [--port 3000] [--no-open] [--prod]
rch init|setup [-y] [--skip-test]
rch capabilities                  # with --json: commands, env_vars, exit_codes, policies, reason_code_families, ...
rch robot-docs guide
rch schema export [-o DIR] | list
```

`rch dashboard` / `rch tui` / `rch web` block the session — never from automation
(`--dump-state` / `--test-mode` are the non-interactive escapes).

## Things That Do NOT Exist

`rch workers add|remove` (use `workers init`, `workers discover --add`, or
`config edit --workers`) · `rch config check` · `rch hook install --force` ·
`rch fleet enable` · `rch status --stats` · `rch bypass`, `rch reconcile`,
`rch inventory`, `rch toolchain`, `rch wrapper` at top level · env vars
`RCH_DISABLED`, `RCH_BYPASS`, `RCH_FORCE_LOCAL`, `RCH_DAEMON_SOCKET`, `RCH_LOG`,
`RCH_DRY_RUN`, `RCH_NO_COLOR` · config file `daemon.toml` **does** exist
(`rchd` reads `~/.config/rch/daemon.toml`) but `.rch.toml` does not (project
override is `.rch/config.toml`).

## Other Binaries

| Binary | Role |
|---|---|
| `rchd` | local daemon: worker state, selection, queue, reliability subsystems, Unix-socket API |
| `rch-wkr` | worker agent on remote hosts: `execute`, `health`, `info`, `capabilities`, `cleanup [--max-age-hours 168]`, `telemetry`, `benchmark`, `prepare` |
| `rch-telemetry` | `collect` — telemetry CLI used on workers |
| `rabsd`, `rabs-wrap`, `rabs-wkr` | RABS spine (edge/coordinator daemon, tiny `RUSTC_WRAPPER`, trusted worker). Opt-in, shadow-only today — see `SKILL.md` § RABS |
