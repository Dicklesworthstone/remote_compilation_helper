# The Cargo Shim (`rch shim`) — Offload for Every Agent, Not Just Claude Code

## Contents

- [Why It Exists](#why-it-exists)
- [What `rch shim install` Does](#what-rch-shim-install-does)
- [Fail-Closed by Default](#fail-closed-by-default)
- [Toolchain Wrapping (rustup `bin/cargo`)](#toolchain-wrapping-rustup-bincargo)
- [`rch shim status`](#rch-shim-status)
- [The Local-Builds Alarm](#the-local-builds-alarm)
- [Building Locally On Purpose](#building-locally-on-purpose)
- [Rules](#rules)
- [Failure Modes](#failure-modes)

## Why It Exists

rch only auto-intercepts builds through the Claude Code PreToolUse hook. Codex,
Gemini CLI without the hook, plain shells, scripts, Makefiles and CI all invoke
`cargo` directly — and on a dispatcher box those builds were compiling
**locally**, defeating the point of rch. `rch shim` (shipped v1.0.52) is the one
canonical cargo wrapper, managed as a first-class command instead of a
hand-rolled script per box.

## What `rch shim install` Does

```bash
rch shim install                        # fail-closed (default): queue for a worker, never build locally
rch shim install --allow-local-fallback # fail-open: offload, fall back to local under load
rch shim install --no-toolchains        # leave rustup toolchain cargo binaries untouched
rch shim status                         # install state, version, PATH order, local builds
rch shim uninstall                      # remove the shim and restore wrapped toolchains
```

- Writes a managed `#!/bin/sh` script to **`~/.rch/shims/cargo`** (deliberately
  not `~/.local/bin`) carrying a `# rch-shim-version:` marker, and expects that
  directory to precede `~/.cargo/bin` on PATH.
- The shim offloads only `build|b|test|t|check|c|clippy|bench|doc|nextest`;
  everything else (`cargo fmt`, `cargo install`, `cargo metadata`, …) goes to
  the real cargo untouched.
- Any `--message-format*` argument (rust-analyzer / IDE tooling) runs locally.
- Loop-safe: rch sets `RCH_CARGO_WRAPPER_BYPASS=1` on its own local-fallback
  re-exec, and the shim honors it → real cargo. If `rch` is not on PATH the
  shim also passes through (never blocks a build).
- Refuses to install on a box whose config says `general.role = "worker"` — a
  worker *is* the compute; wrapping its cargo would recurse into the fleet.

## Fail-Closed by Default

The default shim body bakes in `RCH_REQUIRE_REMOTE=1 RCH_QUEUE_WHEN_BUSY=1`, so a
shimmed `cargo build` waits for a worker and **never compiles locally**. That is
what a dispatcher wants: local rustc on an orchestrator box is the incident,
not a fallback. A refusal surfaces as

```
[RCH] remote required; refusing local fallback (<reason>) — retryable
```

with exit **103** (retryable: no worker assignable right now / daemon momentarily
unavailable) or exit **1** for permanent refusals (`non-compilation command`,
`config unavailable`, and the shell-wrapped-cargo `RCH-E301` case). These lines
are emitted through `summary_critical`, so they show even with
`output.visibility = "none"`.

Related: with `general.role = "dispatcher"` in `config.toml`, *every* `rch exec`
on the box defaults to fail-closed (`RequireRemote`) unless `RCH_REQUIRE_REMOTE`
or `RCH_FORCE_REMOTE` is explicitly present in the environment — presence, even
`=0`, is treated as an explicit override.

## Toolchain Wrapping (rustup `bin/cargo`)

Since main @ `73dd330` (2026-08-25, after the v1.0.58 release), `rch shim install`
also wraps **every installed rustup toolchain's** `<toolchain>/bin/cargo`:

- The original binary is preserved as a **hardlink** named `cargo-rch-real`
  beside it; the wrapper script is swapped in with an atomic rename.
- The wrapper exports `RCH_SHIM_REAL_CARGO` so a local fallback still uses the
  caller's exact toolchain (`cargo +nightly …`, absolute-path invocations).
- Marker `# rch-toolchain-wrap-version:`; `RUSTUP_HOME` is honored; Unix only.
- Why: absolute-path calls (`~/.rustup/toolchains/<tc>/bin/cargo`, Makefiles,
  `cargo +tc` re-exec) bypass PATH entirely. The motivating incident: a
  dispatcher running 42 local rustc processes while the fleet sat at 76/86 free
  slots.

**Operator rule that follows:** `rustup toolchain install …` (and `acfs update`)
lands *new, unwrapped* toolchains. `rch shim status` warns `N/M wrapped`.
**Re-run `rch shim install` after any toolchain install.**

Safety properties (from `rch/src/commands/shim.rs`):

- `rch shim uninstall` refuses to remove a wrapper whose `cargo-rch-real` is
  missing (`refusing to remove wrapper at …: … is missing (no real cargo to
  restore)`). A re-wrap that finds a wrapper with its real binary gone tells
  you to `rustup toolchain install --force <tc>` first.
- If rustup replaced a toolchain since the last wrap, the stale `cargo-rch-real`
  is dropped and the *new* binary is preserved.
- A concurrent-wrap race is detected and refused rather than preserving a
  wrapper as "the real cargo".

## `rch shim status`

Human form:

```
✓ cargo shim installed at ~/.rch/shims/cargo
  version: 1 (current)
  ● PATH resolves the shim ahead of ~/.cargo/bin
  ⚠ 2 local rustc running — builds are compiling on this box (check PATH order / unwrapped toolchains above)
```

(The 1.0.58 release wording is "… (check PATH order / absolute-path
`.rustup/.../bin/cargo` invocations)".)

`rch shim status --json` fields (main): `installed`, `path`, `version`,
`embedded_version`, `up_to_date`, `on_path_ahead_of_cargo` (kept for
compatibility), `interception` (`direct` | `delegated` | `none`),
`local_builds_running`, `toolchains_wrapped`, `toolchains_total`,
`toolchain_errors[]` (only populated by install/uninstall). The released 1.0.58
binary emits only `on_path_ahead_of_cargo` (no `interception`, no toolchain
fields) — check `rch --version` before scripting against these; the skill
scripts accept both.

`interception = delegated` means a *delegating* cargo sits earlier on PATH
(e.g. a `~/.local/bin/cargo` that execs the shim). Older builds reported that
as "not intercepted" — it is fine.

## The Local-Builds Alarm

`local_builds_running > 0` on a dispatcher is the signal to act on. In order:

1. `rch shim status` — is the shim ahead of `~/.cargo/bin` on PATH for the
   shell the builds came from? (`interception = none` → fix PATH, e.g. the
   agent harness was launched from a shell whose rc doesn't prepend
   `~/.rch/shims`.)
2. `ps -eo pid,args | grep -E '[r]ustc|[c]argo'` — absolute-path
   `.rustup/toolchains/*/bin/cargo` invocations mean toolchain wrapping is
   missing or stale → `rch shim install`.
3. `--message-format` builds (rust-analyzer) are *expected* local and harmless.
4. A `cargo` wrapped in `bash -lc '…'` (login-shell form) is not intercepted by
   the hook (`sh -c`/`bash -c` forms *are* unwrapped and rewritten), but the
   **shim still catches it** when the inner `cargo` resolves through PATH — so
   if it is building locally, PATH order is wrong.

## Building Locally On Purpose

Inline env prefixes inside an agent's Bash command do **not** bypass the hook —
`RCH_ENABLED=0 cargo build` is rewritten to `rch exec -- RCH_ENABLED=0 cargo
build` (verified against 1.0.58). The hook reads its *own* process environment
and the config files, not the command text. Two independent interceptors have to be told separately, because
`general.force_local` is honored **only by the hook path** (`process_hook`) —
`rch exec`, which is what the shim invokes, never reads it:

```toml
# .rch/config.toml (project-scoped; remove afterwards) — stops the HOOK from rewriting
[general]
force_local = true
```

```bash
# the inline var stops the SHIM (and rustup toolchain wrappers) — they exec the real cargo
RCH_CARGO_WRAPPER_BYPASS=1 cargo build --release
file target/release/<binary>          # confirm it is a binary for THIS host, not a Linux ELF synced back
```

No `[RCH]` line is printed in this case (the shim bypass never runs rch, and
the hook's own `[RCH] local (force_local)` line only appears when the harness
env/config sets `output.visibility`), so verify with `file`/`--version` on the
artifact or `rch shim status` (`local_builds_running`) rather than by grepping.

Outside an agent harness (plain shell, CI), `export RCH_ENABLED=false` in the
process environment disables the hook/`rch exec` for that shell;
`RCH_CARGO_WRAPPER_BYPASS=1` still needs to be set for the shim. `RCH_DISABLED`,
`RCH_BYPASS` and `RCH_FORCE_LOCAL` do not exist.

## Rules

- Install **only** on dispatcher/orchestrator boxes. Never on a worker.
- Re-run `rch shim install` after every `rustup toolchain install` / `acfs update`.
- Don't hand-roll a cargo wrapper; the skill and rch both assume the managed one.
- Don't "fix" a local-build alarm by uninstalling the shim; fix PATH or wrapping.

## Failure Modes

| Symptom | Cause | Fix |
|---|---|---|
| `rch shim install` refuses: role is worker | `general.role = "worker"` | Correct — leave it. Set `role = "dispatcher"` only on orchestrators |
| `N/M toolchains wrapped` warning | new toolchain since last install | `rch shim install` |
| shim installed but `interception: none` | `~/.rch/shims` not first on PATH in *that* shell | prepend in the rc file the agent harness sources; restart the harness |
| every shimmed build exits 103 | fleet has no admissible worker | `rch status --remediation`, `rch admit "<cmd>"`; fix the fleet, or temporarily `rch shim install --allow-local-fallback` |
| "refuses to remove wrapper: cargo-rch-real missing" | hardlink lost | `rustup toolchain install --force <tc>` then `rch shim install` |
| `rch shim status --json` lacks `interception` | binary is the 1.0.58 release, wrapper fields are post-release | upgrade (`rch update`) or read `on_path_ahead_of_cargo` |

Open upstream work as of 2026-08-25: shim/role durability (watchdog re-assert,
installer, doctor integration) is bead `bd-ousos` (open); a loud local-build
alarm in `rch status`/`doctor` is `bd-sb836` (in progress).
