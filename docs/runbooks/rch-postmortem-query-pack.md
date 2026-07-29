# Runbook: RCH Postmortem Query Pack & Raw-History Fallback

Standard workflow for reconstructing "what did RCH actually do?" after an
incident — first via [CASS](https://github.com/Dicklesworthstone/cass) session
search, then via a bounded raw-history `rg` fallback when CASS is stale or its
paths don't resolve. Use this when an agent reports a confusing RCH outcome
(ran local unexpectedly, "no admissible workers", a proof refusal, an artifact
miss) and you need the evidence chain, not prose.

## Symptoms

- "RCH ran my build locally and I don't know why"
- "no admissible workers" with no further detail
- A proof-mode refusal or `Exec format error` in an agent transcript
- Disk-pressure / target-dir / rsync failures you need to correlate across sessions

## Where the structured records live (check these FIRST)

RCH already persists machine-readable records — prefer them over transcript prose:

| Record | Location | Schema |
|---|---|---|
| Incident ledger (selection/admission/fallback/proof/artifact) | `${RCH_STATE_HOME}/incidents.jsonl`, else `${XDG_STATE_HOME}/rch/incidents.jsonl`, else `~/.local/state/rch/incidents.jsonl`, else `/tmp/rch/incidents.jsonl` | `IncidentEvent` (stable `RCH-Innn` reason codes; see `rch-common/src/incident.rs`) |
| Durable proof intents | `${RCH_STATE_HOME}/proof_intents/` (see `rch-common/src/proof_intent.rs`) | `ProofIntent` |
| e2e structured logs | `target/test-logs/*.jsonl` and CI `e2e-*` artifacts | per-script JSONL (see `scripts/lib/aggregate_e2e.py`) |
| Daemon logs | `daemon.log` / `daemon.err` in the daemon state dir (rotated; see `rch-common/src/log_retention.rs`) | text |

Query the ledger directly before reaching for session history:

```bash
# Most-recent incidents (corruption-tolerant reader; one JSON object per line)
tail -n 50 "${RCH_STATE_HOME:-$HOME/.local/state/rch}/incidents.jsonl" | jq -c '{ts:.occurred_at_unix_ms, code:.reason_code, type:.event_type, worker:.worker_id}'

# Filter to one reason class (e.g. missing capability = RCH-I006)
jq -c 'select(.reason_code=="RCH-I006")' "${RCH_STATE_HOME:-$HOME/.local/state/rch}/incidents.jsonl"
```

`rch diagnose --json -- <command>` combines classification, admission, the
recent incident-chain, and the decisive blocker; `rch admit --json -- <command>`
gives a read-only preflight (offload/local/queue/defer + required capabilities)
before re-running.

## Step 1 — CASS source-state check (don't trust a stale index)

```bash
# Are the session sources resolvable and fresh?
cass sources list --json
cass health --json
```

Record any **freshness** or **path-resolution** failures from these two commands
(a stale `last_indexed` timestamp, a source whose `path` no longer exists). If
either is unhealthy, skip straight to the **raw-history fallback** (Step 3) —
a stale CASS index will silently under-report.

## Step 2 — Bounded CASS searches (always with a timeout)

Run each query term from the postmortem pack as a **bounded** search so a hung
index can't stall the postmortem:

```bash
# 20s ceiling per query; --json for machine-readable hits.
for term in \
  "local fallback" \
  "no admissible workers" \
  "RCH_REQUIRE_REMOTE" \
  "disk pressure" \
  "target dirs" \
  "Exec format error" \
  "rsync failed" \
  "wasm target" \
  "daemon logs" \
  "fleet update"; do
  echo "### $term"
  timeout 20s cass search --json "$term" || echo "  (cass search timed out or failed for: $term — use raw fallback)"
done
```

If any term times out or errors, fall through to Step 3 for that term.

## Step 3 — Raw-history `rg` fallback (match-only, bounded)

When CASS is unavailable, stale, or a term timed out, grep the raw session
stores directly. Use `rg -l` / `rg --count` (match-only) first so you don't
dump megabytes of transcript; open specific files only after locating them.

```bash
RCH_HISTORY_ROOTS=(
  "$HOME/.claude/projects"
  "$HOME/.codex/sessions"
  "$HOME/.gemini/tmp"
)
# Also include rollout summaries and any backup stores you keep:
RCH_HISTORY_ROOTS+=( "$HOME/.claude/rollouts" "$HOME/.rch/session-backups" )

for term in \
  "local fallback" \
  "no admissible workers" \
  "RCH_REQUIRE_REMOTE" \
  "disk pressure" \
  "target dirs" \
  "Exec format error" \
  "rsync failed" \
  "wasm target" \
  "daemon logs" \
  "fleet update"; do
  echo "### $term"
  # -l = files-with-matches only; skip roots that don't exist.
  for root in "${RCH_HISTORY_ROOTS[@]}"; do
    [ -d "$root" ] || continue
    rg -l --no-messages -- "$term" "$root" 2>/dev/null
  done
done
```

Then open the located files (and the matching `incidents.jsonl` lines from the
table above) to assemble the evidence chain. Cross-reference each transcript hit
with its `RCH-Innn` reason code so the postmortem cites the stable code, not the
prose.

## The postmortem query terms (the canonical pack)

These ten terms are the standard pack — keep them in sync with the
session-history report's failure classes:

1. `local fallback`
2. `no admissible workers`
3. `RCH_REQUIRE_REMOTE`
4. `disk pressure`
5. `target dirs`
6. `Exec format error`
7. `rsync failed`
8. `wasm target`
9. `daemon logs`
10. `fleet update`

## Validation & regression guard

- **Doc regression check:** `scripts/check_postmortem_runbook.sh` asserts this
  runbook still contains every query term, the CASS source-state commands, and
  every raw-history root — run it (and wire it into doc CI) so old guidance that
  drops a term or a fallback path cannot silently return.
- **Incident schema:** `cargo test -p rch-common --lib incident` /
  `incident_ledger` validate the `RCH-Innn` reason codes and the
  corruption-tolerant JSONL reader this runbook relies on.
- **Readiness / admission surfaces:** `cargo test -p rch-common --lib readiness`,
  `admission_rejection`, `admission_recommendation`, `capability_probe` validate
  the diagnose/admit output this runbook points operators at.
