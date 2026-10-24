#!/usr/bin/env bash
# auto_recover.sh — heuristic, safe-by-default recovery loop for unhealthy rch fleets.
#
# Usage:
#   ./auto_recover.sh             # dry-run: print what would happen
#   ./auto_recover.sh --apply     # actually take action (still safe; no rm -rf)
#
# What it does, in order:
#   1. Probes daemon health → if dead and 'rchd' is in PATH, starts it
#   2. Probes hook install on every detected agent → installs if missing
#   3. Probes every worker → classifies failures (key missing, host down,
#      auth, telemetry stale, version drift, disk pressure)
#   4. For each classifiable failure, applies the safe recovery
#      (disable+drain unreachable workers, redeploy binary on version drift,
#      hand off to sbh skill on disk pressure, etc.)
#   5. Re-runs probes, prints a summary
#
# What it deliberately will NOT do without explicit user authorization:
#   - rm anything (target dirs, sockets, key files, daemon state, telemetry db)
#   - kill -9 any process
#   - chown /data/projects on a worker
#   - run sbh clean (just suggests the command)
#
# Adheres to AGENTS.md "no destructive defaults" rule.

set -euo pipefail

APPLY=0
[[ "${1:-}" == "--apply" ]] && APPLY=1
[[ "${1:-}" == "-h" || "${1:-}" == "--help" ]] && { sed -n '2,/^# Adheres/p' "$0" | sed -E 's/^# ?//'; exit 0; }

color() { [[ -t 1 ]] && printf '\033[%sm%s\033[0m' "$1" "$2" || printf '%s' "$2"; }
say()   { printf '%s %s\n' "$(color '1;34' '[plan]')" "$*"; }
ok()    { printf '%s %s\n' "$(color '1;32' '[ok]  ')" "$*"; }
warn()  { printf '%s %s\n' "$(color '1;33' '[warn]')" "$*" >&2; }
err()   { printf '%s %s\n' "$(color '1;31' '[fail]')" "$*" >&2; }

run() {
  if (( APPLY )); then
    "$@"
  else
    printf '       $ %s\n' "$*"
  fi
}

require() { command -v "$1" >/dev/null 2>&1 || { err "missing command: $1"; exit 127; }; }
require rch
require jq
(( BASH_VERSINFO[0] >= 4 )) || { err "bash 4+ required (mapfile, declare -A); macOS: brew install bash"; exit 1; }

# workers.toml location mirrors rch's own resolution: RCH_CONFIG_DIR > existing XDG dir > legacy macOS dir
_cfg_dir="${RCH_CONFIG_DIR:-${XDG_CONFIG_HOME:-$HOME/.config}/rch}"
[[ -d "$_cfg_dir" ]] || { [[ -d "$HOME/Library/Application Support/com.rch.rch" ]] && _cfg_dir="$HOME/Library/Application Support/com.rch.rch"; }
WORKERS_TOML="$_cfg_dir/workers.toml"
# GNU `timeout` is absent on stock macOS; fall back to running the command directly
if ! command -v timeout >/dev/null 2>&1; then
  if command -v gtimeout >/dev/null 2>&1; then timeout() { gtimeout "$@"; }; else timeout() { shift; "$@"; }; fi
fi

# ──────────────────────────────────────────────────────────────────────────────
# Phase 1: Daemon
# ──────────────────────────────────────────────────────────────────────────────
say "Phase 1: daemon health"
DAEMON_JSON="$(timeout 5 rch --json daemon status 2>/dev/null || true)"
DAEMON_RUNNING="$(printf '%s' "$DAEMON_JSON" | jq -r '.data.running // false' 2>/dev/null || echo false)"

if [[ "$DAEMON_RUNNING" != "true" ]]; then
  if command -v rchd >/dev/null 2>&1; then
    say "daemon not responding — running 'rch daemon start'"
    run rch daemon start || true
    sleep 2
  else
    err "rchd binary missing from PATH; install rch first"
    exit 1
  fi
else
  ok "daemon responsive"
fi

# Socket consistency
CFG_SOCK="$(timeout 5 rch --json config get general.socket_path 2>/dev/null | jq -r '.data.value // ""' || true)"
DMN_SOCK="$(printf '%s' "$DAEMON_JSON" | jq -r '.data.socket_path // ""')"
if [[ -n "$CFG_SOCK" && -n "$DMN_SOCK" && "$CFG_SOCK" != "$DMN_SOCK" ]]; then
  warn "socket mismatch: config=$CFG_SOCK daemon=$DMN_SOCK — restarting daemon"
  run rch daemon restart -y || true
fi

# ──────────────────────────────────────────────────────────────────────────────
# Phase 2: Hook installation per agent
# ──────────────────────────────────────────────────────────────────────────────
# `rch --json agents status` returns:
#   .data.agents[].{kind, name, hook_status, can_install_hook, ...}
# `kind` is PascalCase ("ClaudeCode"); install-hook expects kebab-case
# ("claude-code"). Convert by injecting hyphens before each upper-case run.
pascal_to_kebab() {
  printf '%s\n' "$1" | sed -E 's/([a-z0-9])([A-Z])/\1-\2/g; s/([A-Z]+)([A-Z][a-z])/\1-\2/g' \
    | tr '[:upper:]' '[:lower:]'
}

say "Phase 2: hook installation per agent"
AGENT_JSON="$(timeout 10 rch --json agents status 2>/dev/null || true)"
if [[ -n "$AGENT_JSON" ]]; then
  # Separator is US (0x1f), not TAB: `read` with IFS=tab collapses consecutive tabs, so an empty
  # middle field would shift every later column left.
  while IFS=$'\x1f' read -r kind name hook_status can_install detected; do
    [[ -z "$kind" ]] && continue
    [[ "$detected" == "false" ]] && continue
    [[ "$hook_status" == "Installed" ]] && continue
    if [[ "$can_install" != "true" ]]; then
      warn "$name ($kind): hook missing but agent reports can_install_hook=false — skipping"
      continue
    fi
    agent_arg="$(pascal_to_kebab "$kind")"
    warn "$name ($kind): hook is '${hook_status:-unknown}' — installing as '$agent_arg'"
    run rch agents install-hook "$agent_arg" || true
  done < <(printf '%s' "$AGENT_JSON" \
            | jq -r '.data.agents[]? | [(.kind // ""), (.name // ""), (.hook_status // ""), ((.can_install_hook // false)|tostring), ((.detected // true)|tostring)] | join("")')
else
  warn "could not query agents; skipping hook check"
fi

# ──────────────────────────────────────────────────────────────────────────────
# Phase 3: Worker probe + classification
# ──────────────────────────────────────────────────────────────────────────────
say "Phase 3: worker probes"
PROBE_JSON="$(timeout 60 rch --json workers probe --all 2>/dev/null || true)"
if [[ -z "$PROBE_JSON" ]]; then
  err "could not probe workers; daemon may still be starting — try again in 10s"
  exit 0
fi

# `rch --json workers probe --all` returns:
#   .data.results[] = {id, host, status, latency_ms?, error?, error_code?}  (+ .data.summary)
# status is one of: ok | capability_missing | capability_unknown | unhealthy | error | connection_failed.
# error_code (RCH-Exxx) is the stable handle; the human `error` text is matched only as a fallback.
# US (0x1f) separator: TAB is IFS whitespace and an empty error_code would shift the columns.
mapfile -t ROWS < <(
  printf '%s' "$PROBE_JSON" \
    | jq -r '.data.results[]? | [(.id // ""), (.host // ""), (.status // ""), (.error_code // ""), ((.error // "") | gsub("[\n]"; " "))] | join("")'
)

# id → ssh user, from workers.toml via `rch --json workers list` (workers are not all `ubuntu@`)
declare -A USER_BY_ID
while IFS=$'\t' read -r wid wuser; do
  [[ -n "$wid" ]] && USER_BY_ID["$wid"]="${wuser:-ubuntu}"
done < <(timeout 10 rch --json workers list 2>/dev/null | jq -r '.data.workers[]? | [.id, (.user // "ubuntu")] | @tsv' || true)

if [[ ${#ROWS[@]} -eq 0 ]]; then
  warn "no workers configured (probe returned empty array)"
  say "  rch workers discover --probe --add --yes && rch workers setup --all"
  exit 0
fi

UNHEALTHY=()
for row in "${ROWS[@]}"; do
  IFS=$'\x1f' read -r id host status code reason <<<"$row"
  if [[ "$status" == "ok" ]]; then
    ok "$id ($host)"
    continue
  fi
  UNHEALTHY+=("$id"$'\x1f'"$host"$'\x1f'"$code"$'\x1f'"$status"$'\x1f'"$reason")
done

if [[ ${#UNHEALTHY[@]} -eq 0 ]]; then
  ok "all ${#ROWS[@]} worker(s) healthy"
  exit 0
fi

say "Phase 4: classify ${#UNHEALTHY[@]} unhealthy worker(s)"
for entry in "${UNHEALTHY[@]}"; do
  IFS=$'\x1f' read -r id host code status reason <<<"$entry"
  suser="${USER_BY_ID[$id]:-ubuntu}"
  printf '\n  worker=%s host=%s status=%s code=%s\n  reason=%s\n' "$id" "$host" "$status" "${code:-n/a}" "$reason"

  # Branch on the stable error_code first (RCH-E100 connect, E101 auth, E102 key, E103 host key,
  # E205 toolchain, E210/E211 disk pressure, E212 telemetry), then on the probe status, then on
  # substrings of the human text. Subject layout: "<code>:<status>:<text>".
  # When the code is one this table handles, drop status/text from the subject
  # so a phrase in the human message (e.g. "timed out" inside an E212
  # telemetry error) can never route it to an earlier arm such as
  # disable+drain. Text matching is only the fallback for code-less errors.
  subject="$code:$status:$reason"
  case "$code" in
    RCH-E10[0-9]|RCH-E205|RCH-E21[0-7]) subject="$code::" ;;
  esac
  case "$subject" in
    RCH-E101:*|RCH-E102:*|*"Permission denied"*"publickey"*|*"identity_file"*|*"no such identity"*)
      warn "$id: SSH auth/key failure"
      # Find the identity_file for this worker by walking workers.toml.
      # Strategy: track the current [[workers]] block; remember when we
      # see id="<target>"; print identity_file when matched. Handles id
      # appearing either before or after identity_file within a block.
      KEY_PATH="$(awk -v target="$id" '
        function strval(s) { sub(/^[^"]*"/, "", s); sub(/".*$/, "", s); return s }
        /^[[:space:]]*\[\[workers\]\]/ { id_seen=""; ifile=""; matched=0; next }
        /^[[:space:]]*id[[:space:]]*=/ { id_seen=strval($0); if (id_seen==target) matched=1 }
        /^[[:space:]]*identity_file[[:space:]]*=/ { ifile=strval($0) }
        matched && ifile != "" { print ifile; exit }
      ' "$WORKERS_TOML" 2>/dev/null)"
      KEY_RESOLVED="${KEY_PATH/#~/$HOME}"
      if [[ -z "$KEY_PATH" ]]; then
        warn "could not find identity_file for '$id' in $WORKERS_TOML"
        say "manual check:  rch --json workers list | jq '.data.workers[] | select(.id==\"$id\")'"
      elif [[ -n "$KEY_RESOLVED" && ! -r "$KEY_RESOLVED" ]]; then
        warn "configured key '$KEY_RESOLVED' is not readable on this host"
        say "search for an alternate copy:  find ~/.ssh /etc/ssh /root/.ssh 2>/dev/null -name '$(basename "$KEY_RESOLVED")*'"
        say "or check ssh-agent:           ssh-add -l"
        say "or disable temporarily:       rch workers disable $id --reason 'missing key' --drain -y"
        say "full recovery playbook:       references/SSH_KEY_RECOVERY.md"
      else
        say "key looks present; check authorized_keys on $host:"
        say "  ssh -i '$KEY_RESOLVED' -v $suser@$host true"
      fi
      ;;
    RCH-E103:*|*"host key verification"*)
      warn "$id: host-key mismatch — needs explicit human authorization to refresh known_hosts"
      ;;
    RCH-E100:*|RCH-E10[4-9]:*|*:connection_failed:*|*"Connection refused"*|*"Connection timed out"*|*"No route to host"*|*"timed out"*)
      warn "$id: TCP unreachable"
      run rch workers disable "$id" --reason "host unreachable: $reason" --drain -y || true
      ;;
    *"self-test failed"*|*"binary version"*|*"outdated"*|*"protocol"*"mismatch"*)
      warn "$id: looks like binary/version drift"
      # rch workers deploy-binary doesn't have --verify; use rch fleet deploy with --worker.
      run rch fleet deploy --worker "$id" --verify || true
      ;;
    RCH-E21[0-7]:*|*"disk pressure"*|*"no space left"*|*"telemetry"*"stale"*|*"RCH-E21"*)
      warn "$id: disk/telemetry pressure — reap with rch first, then sbh"
      say "rch cache status --workers $id && rch gc --dry-run --workers $id"
      say "ssh $suser@$host 'df -h / /data /tmp 2>/dev/null; free -h; sbh status 2>/dev/null'"
      say "if sbh available:  ssh $suser@$host 'sbh scan && sbh clean --apply'"
      ;;
    RCH-E205:*|*:capability_missing:*|*"toolchain"*|*"rustup"*|*"cargo: command not found"*)
      warn "$id: toolchain/component missing on remote (or worker PATH lacks ~/.cargo/bin — see WORKERS.md)"
      run rch workers sync-toolchain "$id" || true
      ;;
    *)
      warn "$id: no automated rule matched. Investigate manually:"
      say "  ssh -v $suser@$host echo OK"
      say "  rch --json workers probe $id | jq '.data.results[]'"
      ;;
  esac
done

# ──────────────────────────────────────────────────────────────────────────────
# Phase 5: Re-verify
# ──────────────────────────────────────────────────────────────────────────────
echo
say "Phase 5: re-verify"
run rch check
echo
ok "done."
if (( ! APPLY )); then
  warn "this was a DRY RUN — re-run with --apply to execute the suggested actions"
fi
