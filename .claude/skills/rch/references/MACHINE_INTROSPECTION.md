# Machine-Readable Surfaces (For Agents)

## Contents

- [Discovery Ladder](#discovery-ladder)
- [Per-Command JSON Mode](#per-command-json-mode)
- [Unified Response Envelope](#unified-response-envelope)
- [The `rch exec` Result Envelope](#the-rch-exec-result-envelope)
- [Output Format Modes](#output-format-modes)
- [Useful jq Recipes (verified against 1.0.58)](#useful-jq-recipes-verified-against-1058)
- [Wire-Level Hook Protocol](#wire-level-hook-protocol)
- [Where Agents Trip Up](#where-agents-trip-up)

`rch` is built for agents: every command returns structured output, exposes its
schema, and the CLI tree is queryable as JSON. Use these surfaces instead of
guessing.

## Discovery Ladder

```bash
rch --robot-triage --json      # quick_ref + recommended commands + health probes — START HERE
rch capabilities --json        # commands, env_vars, exit_codes, policies, reason_code_families,
                               # recommended_commands, runtimes, hook_formats, output_formats, features
rch robot-docs guide           # in-tool operating guide
rch --help-json                # entire CLI tree as JSON
rch --help-json workers probe  # one subtree
rch --schema workers list      # JSON Schema for a command's output
rch schema list                # available schemas
rch schema export -o ./schemas # api-response / api-error / error-codes to disk
rch error list [--category X] [--json]   # 166 codes on 1.0.58, 177 on 2.0.0 (RCH-Ennn + RCH-Innn + RCH-Rnnn)
rch error explain RCH-I001               # description + remediation for one code
rch doctor --runbook-list                # authored RCH-Rnnn runbooks
```

The legacy `rch --capabilities` flag is a raw JSON shortcut; `rch capabilities
--json` is the enveloped form.

## Per-Command JSON Mode

`--json` / `-F json|toon` are **global** flags and may go before or after the
subcommand:

```bash
rch --json check                          # .data.status ready|degraded|not_ready, .data.exit_code, .data.issues[]
rch --json daemon status                  # {running, socket_path, uptime_seconds} — no version here
rch --json status --workers --jobs        # daemon + workers + posture + remediation_hints
rch --json status --fleet                 # desired vs live worker grouping
rch --json workers list                   # .data.count, .data.workers[]{id,host,user,total_slots,priority,tags} (no identity_file)
rch --json workers probe --all            # .data.results[]{id,host,status,latency_ms?,error?,error_code?} + .data.summary{total,healthy,unhealthy,failed,by_error_code}
rch --json queue                          # active_builds, queued_builds, queue_depth, slots_*, workers_*
rch --json hook status                    # .data.agents[]{agent, status}
rch --json agents status                  # .data.agents[]{name, kind, detected, version, config_path, hook_support, hook_status, can_install_hook}
rch --json admit "cargo test -p foo"      # base_recommendation, family, is_compilation, required, proof_policy, compound, detail
rch --json diagnose --dry-run "<cmd>"     # classification, decision, placement{...}, worker_selection, tiers, ...
rch --json self-test --all
rch --json speedscore --all
rch --json fleet status
rch --json doctor
rch --json doctor --reliability --scope topology,pressure   # `ownership` scope exists from 2.0.0 (1.0.58 rejects it)
rch --json config show --sources
rch --json config get general.socket_path # .data.{key, value}
rch --json gc --dry-run --workers <id>    # per-dir verdicts + RCH_REAP_RM audit events
rch --json cache status
rch shim status --json
```

**stdout is data-only.** Diagnostics go to stderr. Exit 0 = success.

## Unified Response Envelope

```json
{
  "api_version": "1.0",
  "timestamp": 1787696414,
  "command": "workers list",
  "success": true,
  "data": { ... },
  "error": null
}
```

On failure `success: false` and `error: {code, message, category, context,
remediation[]}`. `error.code` is the stable handle (`RCH-Exxx`). Older skill
text describing a `{kind, elapsed_ms, request_id, version}` envelope was wrong —
the shape above is what 1.0.58 emits.

`rch schema export -o ./schemas` writes `api-response.schema.json`,
`api-error.schema.json`, and `error-codes.json` (the catalog: 100 `RCH-Ennn`
entries on 1.0.58, 6 categories; `rch schema list` prints the live count).

## The `rch exec` Result Envelope

`rch --json exec -- <cmd>` prints exactly one NDJSON line on stdout at the
terminal path (`api_version, command, outcome, location, fallback_reason?,
worker_id?, remote_exit_code?, duration_ms?, timing?, result_dirs?,
error_code?`). `outcome` is about **delivery** (`completed|refused|
transport_error|collection_error`), not build success. Full contract:
`EXEC_MODES.md`.

## Output Format Modes

```bash
RCH_OUTPUT_FORMAT=json rch status          # implies --json
RCH_OUTPUT_FORMAT=toon rch status          # TOON
TOON_DEFAULT_FORMAT=toon rch --json status # switch JSON-flagged calls to TOON
RCH_JSON=1 rch status                      # machine JSON, colors off
```

`NO_COLOR=1`, `FORCE_COLOR=1`, `CLICOLOR_FORCE=1` behave as expected.
Mode detection order: `RCH_JSON` → hook stdin → `NO_COLOR` → `FORCE_COLOR=0` →
TTY → `FORCE_COLOR` → plain.

## Useful jq Recipes (verified against 1.0.58)

```bash
# Quick health
rch --json check | jq -r '.data.status'                           # ready | degraded | not_ready
rch --json check | jq -r '.data.issues[]?'

# Daemon version lives in `status`, NOT `daemon status`
rch --json status | jq -r '.data.daemon.daemon.version'
rch --json daemon status | jq -r '.data.socket_path'

# Reachable worker ids (probe returns .data.results[] plus a .data.summary)
rch --json workers probe --all | jq -r '.data.results[] | select(.status=="ok") | .id'
rch --json workers probe --all | jq -r '.data.results[] | select(.status!="ok") | "\(.id) [\(.status)] \(.error_code // "") \(.error // "")"'
rch --json workers probe --all | jq '.data.summary'               # {total, healthy, unhealthy, failed, by_error_code}
# status values: ok | capability_missing | capability_unknown | unhealthy | error | connection_failed; branch on .error_code, not .error text

# Per-worker daemon view: circuit, slots, pressure (fields are FLAT on each worker)
rch --json status --workers | jq -r '.data.daemon.workers[]
  | "\(.id)\t\(.status)\t\(.used_slots)/\(.total_slots)\t\(.circuit_state)\t\(.pressure_state)\t\(.pressure_reason_code)"'

# Workers under pressure
rch --json status --workers | jq -r '.data.daemon.workers[] | select(.pressure_state!="healthy") | "\(.id) \(.pressure_state) free=\(.pressure_disk_free_gb)GB"'

# Posture + operator hints
rch --json status | jq -r '.data.posture, .data.remediation_hints[]?'

# Queue
rch --json queue | jq '{depth:.data.queue_depth, free:.data.slots_available, total:.data.slots_total, busy:.data.workers_busy}'
rch --json queue | jq -r '.data.active_builds[]? | "\(.id) \(.worker_id) \(.project_id)"'

# Configured workers
rch --json workers list | jq -r '.data.workers[] | "\(.id)\t\(.host)\t\(.total_slots)\t\(.priority)\t\(.tags|join(","))"'

# Hook / agents
rch --json hook status | jq -r '.data.agents[] | "\(.agent)\t\(.status)"'          # ClaudeCode  Installed
rch --json agents status | jq -r '.data.agents[] | select(.can_install_hook) | "\(.kind)\t\(.hook_status)"'

# Placement plan for a command
rch --json diagnose --dry-run "cargo test -p foo" | jq '.data.placement'
rch --json diagnose --dry-run "cargo test -p foo" | jq '.data | {decision, classification, worker_selection}'

# Admission preflight
rch --json admit "cargo test -p foo" | jq '{rec:.data.base_recommendation, family:.data.family, need:.data.required}'

# Scripted proof that a build ran remotely and passed
rch --json exec -- cargo test -p foo 2>/dev/null | jq -e '.outcome=="completed" and .location=="remote" and .remote_exit_code==0'

# Error catalog lookups
rch error explain RCH-E309 --json | jq '{code:.data.code, remediation:.data.remediation}'
jq -r '.errors[] | select(.category=="transfer") | "\(.code)\t\(.message)"' schemas/error-codes.json
```

## Wire-Level Hook Protocol

`rch` with no subcommand is the Claude Code PreToolUse hook:

```bash
printf '%s\n' '{"tool_name":"Bash","tool_input":{"command":"cargo build --release"}}' | rch
```

Responses: empty stdout (allow unchanged) ·
`{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"allow","updatedInput":{"command":"rch exec -- cargo build --release"}}}` ·
`{"hookSpecificOutput":{"permissionDecision":"deny","permissionDecisionReason":"..."}}`.
`scripts/protocol_test.sh` drives a battery. Details: `HOOKS.md`.

## Where Agents Trip Up

- **Forgetting `--json`** and grepping human output. Field names are stable; use jq.
- **Conflating exit 0 with "ran remotely."** Use `RCH_VISIBILITY=verbose`, or the exec envelope. See `FAIL_OPEN.md`.
- **Looking for the daemon version in `daemon status`.** It's in `rch --json status`.
- **Expecting `.data.workers` (or a flat `.data[]`) from `workers probe`.** Probe is `.data.results[]` + `.data.summary`; `workers list` is `.data.workers[]`.
- **Bare `rch dashboard` / `rch tui` / `rch web`.** All interactive; they block. (`rch tui` *is* a valid alias of `dashboard` now.)
- **Assuming inline `RCH_*=` prefixes affect the hook.** They are part of the command text, not the hook's environment.
