# Hook Integration

## Contents

- [Execution Flow](#execution-flow)
- [Installation and Status (per agent)](#installation-and-status-per-agent)
- [Hook Protocol](#hook-protocol)
- [What Gets Intercepted](#what-gets-intercepted)
- [What the Hook Never Does](#what-the-hook-never-does)
- [Quick Hook Tests](#quick-hook-tests)
- [Performance, Safety, Self-Healing](#performance-safety-self-healing)

## Execution Flow

```text
Agent PreToolUse (Bash) -> rch (no subcommand = hook mode, JSON on stdin)
        |
        +-- non-Bash tool / non-compilation -> empty stdout (allow unchanged)
        +-- compilation -> allow with rewritten command: "rch exec -- <original>"
                            (a leading `cd X &&` is preserved: "cd X && rch exec -- cargo check")
        |
        v
rch exec runs: daemon selection -> sync -> remote execute -> artifacts back -> exit code
        (fail-open to local on any pre-execution failure unless strict remote)
```

The hook only *classifies* (sub-ms for non-compilation, low-ms for
compilation); the remote work happens in the rewritten `rch exec` process.
Agents without a PreToolUse hook (Codex CLI in some modes, scripts, CI) are
covered by the cargo shim instead — `SHIM.md`.

## Installation and Status (per agent)

```bash
rch hook install | status | test | uninstall      # Claude Code (~/.claude/settings.json)
rch agents list [--all]                            # detected agents + hook support level
rch agents status [<agent>]
rch agents install-hook claude-code|gemini-cli|codex-cli [--dry-run]
rch agents uninstall-hook <agent> [--dry-run]
```

| Agent (kebab id for `install-hook`) | `kind` / `agent` in JSON | Config path | Hook support |
|---|---|---|---|
| `claude-code` | `ClaudeCode` | `~/.claude/settings.json` | Full (PreToolUse) |
| `gemini-cli` | `GeminiCli` | `~/.gemini/settings.json` | Full |
| `codex-cli` | `CodexCli` | `~/.codex/config.toml` | Full |
| `continue-dev` | `ContinueDev` | `~/.continue/config.json` | Partial (installable) |
| `cursor`, `windsurf`, `aider`, `cline` | … | detection only / none | cannot install; use the shim |

(`agents status` / `hook status` JSON print the PascalCase `Debug` name on
both 1.0.58 and main, even though `AgentKind`'s serde rename is kebab-case; the
kebab ids are what the CLI *accepts*.)

Installed Claude Code entry:

```json
{ "hooks": { "PreToolUse": [ { "matcher": "Bash",
    "hooks": [ { "type": "command", "command": "/absolute/path/to/rch" } ] } ] } }
```

`rch hook install` re-resolves the absolute path; re-run it after moving the
binary. Claude Code loads hooks at startup — restart the session after
installing. With `[self_healing] daemon_installs_hooks = true` (default) the
daemon re-installs a missing hook on start.

## Hook Protocol

Input on stdin:

```json
{"tool_name":"Bash","tool_input":{"command":"cargo build --release","description":"..."},"session_id":"optional"}
```

Output on stdout — one of:

1. **empty** → allow unchanged
2. rewrite:
   ```json
   {"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"allow",
     "updatedInput":{"command":"rch exec -- cargo build --release"}}}
   ```
3. deny (rare, policy-level):
   ```json
   {"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"deny","permissionDecisionReason":"..."}}
   ```

Hook stdout is protocol-clean by construction: the exec result envelope is
never emitted on the hook path, and diagnostics go to stderr.

## What Gets Intercepted

Observed against 1.0.58 (`scripts/protocol_test.sh` reproduces):

| Command | Result |
|---|---|
| `cargo build\|check\|clippy\|doc\|test\|nextest run\|bench\|run`, `rustc` | rewritten (`cargo run` included) |
| `RUST_BACKTRACE=1 cargo test`, `env X=1 cargo build` | rewritten with the env prefix preserved *inside* the command |
| `cd /data/projects/x && cargo check` | `cd … && rch exec -- cargo check` |
| `cargo build --release 2>&1 \| tee build.log`, `cargo build \| wc -l` | rewritten — a single pipe stage whose consumer is a benign pager (`tee head cat grep less more tail wc rg`); any other consumer, a second stage, `;`, `\|\|`, input redirects or subshells → not intercepted (verified: `cargo build ; cargo test` and `cargo build \|\| echo failed` stay local) |
| `cargo build &` | rewritten (`rch exec -- cargo build &`) — backgrounding is *not* an exclusion |
| `cargo build && cargo test` | **only the last `&&` segment is offloaded** (`cargo build && rch exec -- cargo test`); everything before it runs locally — use separate commands |
| `gcc/g++/clang/clang++`; `make`, `cmake --build`, `ninja`, `meson compile` | rewritten (no runtime requirement) |
| `bun test`, `bun typecheck`, `tsc` | rewritten; require a worker with Bun / Node — otherwise `rch exec` falls open with `[RCH] local (no workers with Bun installed)` |
| `go build\|test\|vet`, `nix build\|nix-build\|nix flake check\|nix develop -c …\|nix shell -c …` | classified as compilation (`rch diagnose` says so), but on 1.0.58 the hook left them **unchanged** on this fleet — even with `go.mod`/`flake.nix` present and none of our workers advertising Go/Nix. Verify with `scripts/protocol_test.sh` in your project; if rewritten, the runtime gate applies inside `rch exec` (`no workers with Go installed`) |
| `cargo fmt --check` | not compilation (local); admitted only via `rch exec --clean-overlay` |
| `cargo install\|clean\|metadata`, `bun install\|add\|remove\|run\|build\|dev\|x`, `nix run\|repl\|profile\|flake update\|store gc`, `nix-env`, `nix-shell` | never intercepted |
| `sh -c 'cargo …'`, `bash -c "cargo …"` | the inner command is classified and the shell wrapper is **dropped**: rewritten to `rch exec -- cargo …` |
| `bash -lc "cargo …"` (any extra flag before `-c`) | not compilation at the hook; the **shim** still catches the inner `cargo` when it resolves via PATH; a direct `rch exec -- bash -lc "cargo …"` is refused (`RCH-E301`) |
| `bun test --watch` and other watch forms | never intercepted |

Inline `RCH_*=…` prefixes are **part of the command text**, not the hook's
environment — `RCH_ENABLED=0 cargo build` is rewritten like any other build.
To keep a build local from inside an agent, use `.rch/config.toml`
`[general] force_local = true` (plus `RCH_CARGO_WRAPPER_BYPASS=1` for the shim).

## What the Hook Never Does

- Sets `--job`, `--clean-overlay`, `--source-content-receipt`, or `--json` on
  the rewritten `rch exec` — those are explicit operator/agent choices.
- Injects `[layer0]` Cargo profile settings (exec-only).
- Blocks a build: any classification/config/daemon failure allows local execution
  (unless the box/env is strict remote — then `rch exec` refuses, not the hook).

## Quick Hook Tests

```bash
printf '%s\n' '{"tool_name":"Bash","tool_input":{"command":"cargo build --release"}}' | rch
printf '%s\n' '{"tool_name":"Bash","tool_input":{"command":"ls -la"}}' | rch      # empty stdout expected
rch hook test                                                                      # built-in integration test
scripts/protocol_test.sh "cd /data/projects/x && cargo check" "go test ./..."
RCH_LOG_LEVEL=debug rch hook test
RCH_LOG_LEVEL=debug rch diagnose "cargo test --workspace"
```

## Performance, Safety, Self-Healing

- Budgets: non-compilation decision < 1 ms, compilation decision < 5 ms
  (log warnings when exceeded).
- Hook-side daemon auto-start (`[self_healing] hook_starts_daemon`, cooldown
  30 s, lock at `${XDG_RUNTIME_DIR:-/tmp}/rch/hook_autostart.*`); disable per
  invocation with `--no-hook-auto-start` or `RCH_NO_SELF_HEALING=1`.
- Every fail-open is recorded in the incident ledger (`RCH_STATE_HOME`) and
  summarized in `rch status --remediation`.
