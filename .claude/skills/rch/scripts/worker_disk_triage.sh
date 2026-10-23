#!/usr/bin/env bash
# worker_disk_triage.sh — read-only mount-aware disk report for every worker.
#
# Never deletes anything. Suggests the next safe step (usually "hand off to sbh").
#
# Usage:
#   ./worker_disk_triage.sh                   # all workers
#   ./worker_disk_triage.sh host-a host-d           # specific workers by id
#   ./worker_disk_triage.sh --json            # machine-readable

set -euo pipefail

JSON_OUT=0
WORKERS=()
for arg in "$@"; do
  case "$arg" in
    --json) JSON_OUT=1 ;;
    -h|--help)
      sed -n '2,/^# Usage/p' "$0" | sed -E 's/^# ?//'; exit 0 ;;
    *) WORKERS+=("$arg") ;;
  esac
done

require() { command -v "$1" >/dev/null 2>&1 || { echo "missing: $1" >&2; exit 127; }; }
require rch
require jq
require ssh
(( BASH_VERSINFO[0] >= 4 )) || { echo "bash 4+ required (mapfile, declare -A); macOS: brew install bash" >&2; exit 1; }

# `rch --json workers list` shape: .data.workers[].{id, host, user, total_slots, priority, tags}
if [[ ${#WORKERS[@]} -eq 0 ]]; then
  mapfile -t WORKERS < <(rch --json workers list 2>/dev/null \
    | jq -r '.data.workers[]?.id')
fi

if [[ ${#WORKERS[@]} -eq 0 ]]; then
  echo "no workers configured" >&2
  exit 1
fi

# Resolve id → host and id → ssh user (workers are not all `ubuntu@`; root-dispatch VPS workers are common)
declare -A HOST_BY_ID USER_BY_ID
while IFS=$'\x1f' read -r id host user; do
  [[ -n "$id" ]] || continue
  HOST_BY_ID["$id"]="$host"
  USER_BY_ID["$id"]="${user:-ubuntu}"
done < <(rch --json workers list 2>/dev/null \
  | jq -r '.data.workers[]? | [(.id // ""), (.host // ""), (.user // "ubuntu")] | join("\u001f")')

probe_one() {
  local id="$1"
  local host="${HOST_BY_ID[$id]:-$id}"
  local user="${USER_BY_ID[$id]:-ubuntu}"
  ssh -o ConnectTimeout=8 -o BatchMode=yes "$user@$host" '
    set +e
    printf "%s\n" "--- df / /data /tmp ---"
    df -h / /data /tmp 2>/dev/null
    printf "%s\n" "--- mem + pressure ---"
    free -h | awk "NR<=2"
    [ -r /proc/pressure/memory ] && cat /proc/pressure/memory
    [ -r /proc/pressure/io ]     && cat /proc/pressure/io
    printf "%s\n" "--- tmp-base rch artifacts: staging, pooled/per-job target dirs, legacy names (top 10) ---"
    du -sh /tmp/rch-* /tmp/rch_target_* /data/tmp/rch/* /data/tmp/.rch-target-* /tmp/.rch-target-* 2>/dev/null | sort -h | tail -10
    printf "%s\n" "--- /data/projects managed + foreign target dirs (top 10 by size) ---"
    find /data/projects -maxdepth 3 -type d \( -name ".rch-target-*" -o -name ".rch-tmp" -o -name "target_rch_*" -o -name "target_*" -o -name "target-*" -o -name target \) -exec du -sh {} + 2>/dev/null | sort -h | tail -10
    printf "%s\n" "--- sbh status (if installed) ---"
    if command -v sbh >/dev/null 2>&1; then sbh status 2>/dev/null | head -20; else echo "sbh not installed"; fi
    printf "%s\n" "--- top processes by RSS ---"
    ps -eo pid,user,rss,cmd --sort=-rss --no-headers 2>/dev/null | head -10
  ' 2>&1
}

if (( JSON_OUT )); then
  echo "{"
  first=1
  for id in "${WORKERS[@]}"; do
    host="${HOST_BY_ID[$id]:-$id}"
    rc=0
    raw="$(probe_one "$id" 2>&1)" || rc=$?    # ssh exit 255 = unreachable; keep the JSON valid
    [[ $first -eq 0 ]] && echo ","
    first=0
    printf '  "%s": {"host": %s, "ssh_exit": %d, "report": %s}' \
      "$id" "$(printf '%s' "$host" | jq -Rs .)" "$rc" "$(printf '%s' "$raw" | jq -Rs .)"
  done
  echo
  echo "}"
  exit 0
fi

for id in "${WORKERS[@]}"; do
  host="${HOST_BY_ID[$id]:-$id}"
  echo
  echo "=========================================="
  echo "  Worker: $id  ($host)"
  echo "=========================================="
  probe_one "$id" || echo "[ssh failed]"
done

cat <<'EOF'

──────────────────────────────────────────────────────────────────────────
Next steps (NEVER delete anything by hand yet):

  • Let rch reap what it owns first (.rch-target-*-pool-* / -job- / -pid- dirs,
    tmp-base strays); it only removes dirs idle past their window:
        rch cache status --workers <id>       # read-only verdicts (REAPABLE / pooled (kept) / active/recent (kept))
        rch gc --dry-run --workers <id>
        rch gc --apply --workers <id>         # rch 2.0.0 previews without --apply; on 1.0.58 omit --apply and always pass --workers (sweeping all can hang)

  • Prefer letting sbh handle the rest (if installed on the worker; use the
    worker's configured ssh user from `rch --json workers list`):
        ssh <user>@<host> 'sbh scan'
        ssh <user>@<host> 'sbh clean --apply'

  • Only legacy/foreign trees (rch_target_*, target_rch_*, a bare target/) are
    manual candidates, and only after:
      1. `sudo lsof +D <dir>` is empty,
      2. `rch --json queue | jq '.data.active_builds[].project_id'` does not reference that project,
      3. explicit user authorization for the rm.

  • If a worker has critical pressure that won't clear:
        rch workers drain <id> -y    # finish active builds, accept no new
        # ... investigate ...
        rch workers enable <id>
EOF
