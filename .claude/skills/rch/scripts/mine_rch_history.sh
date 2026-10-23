#!/usr/bin/env bash
# mine_rch_history.sh — find prior agent sessions that hit a given rch failure.
#
# When the local cass index is stale or has dead pointers, fall through to
# direct ripgrep over JSONL session files on this host (and optionally remote ones).
#
# Usage:
#   ./mine_rch_history.sh "RCH-E1[0-9][0-9]"
#   ./mine_rch_history.sh "All configured workers are unhealthy"
#   ./mine_rch_history.sh --remote <host> "Worker disk pressure"
#
# Default mode greps the local agent session caches under $HOME.

set -euo pipefail

if [[ $# -eq 0 || "${1:-}" == "-h" || "${1:-}" == "--help" ]]; then
  sed -n '2,/^# Default mode/p' "$0" | sed -E 's/^# ?//'; exit 0
fi

# portable mtime (GNU stat -c on Linux, BSD stat -f on macOS)
mtime_of() { stat -c %Y "$1" 2>/dev/null || stat -f %m "$1" 2>/dev/null || echo 0; }

REMOTE_HOST=""
if [[ "${1:-}" == "--remote" ]]; then
  shift; REMOTE_HOST="${1:?usage: --remote <host> <pattern>}"; shift
fi

PATTERN="${1:?usage: $(basename "$0") <pattern>}"

require() { command -v "$1" >/dev/null 2>&1 || { echo "missing: $1" >&2; exit 127; }; }
require rg

ROOTS=(
  "$HOME/.claude/projects"
  "$HOME/.codex/sessions"
  "$HOME/.gemini/tmp"
  "$HOME/.cursor/logs"
)

run_search_local() {
  for real in "${ROOTS[@]}"; do
    [[ -d "$real" ]] || continue
    printf '\n## %s\n' "$real"
    # `-e -- pattern` so a pattern starting with "-" is not parsed as a flag; `|| true` because
    # rg exits 1 on "no matches", which would otherwise abort the loop under pipefail.
    { rg --type-add 'jsonl:*.jsonl' --type jsonl --type json -l --no-messages -e "$PATTERN" -- "$real" 2>/dev/null || true; } \
      | while read -r f; do
          line=$(rg --type-add 'jsonl:*.jsonl' --type jsonl --type json -n -m1 --no-messages -e "$PATTERN" -- "$f" 2>/dev/null \
                  | cut -d: -f1 || true)
          age_d=$(( ($(date +%s) - $(mtime_of "$f")) / 86400 ))
          printf '  %4dd  %s:%s\n' "$age_d" "$f" "${line:-?}"
        done
  done
}

run_search_remote() {
  ssh -o ConnectTimeout=5 -o BatchMode=yes "$REMOTE_HOST" "
    PATTERN=$(printf '%q' "$PATTERN")
    for real in \"\$HOME/.claude/projects\" \"\$HOME/.codex/sessions\" \"\$HOME/.gemini/tmp\" \"\$HOME/.cursor/logs\"; do
      [ -d \"\$real\" ] || continue
      printf '\n## %s:%s\n' '$REMOTE_HOST' \"\$real\"
      { rg --type-add 'jsonl:*.jsonl' --type jsonl --type json -l --no-messages -e \"\$PATTERN\" -- \"\$real\" 2>/dev/null || true; } \
        | while read -r f; do
            line=\$(rg --type-add 'jsonl:*.jsonl' --type jsonl --type json -n -m1 --no-messages -e \"\$PATTERN\" -- \"\$f\" 2>/dev/null | cut -d: -f1 || true)
            mt=\$(stat -c %Y \"\$f\" 2>/dev/null || stat -f %m \"\$f\" 2>/dev/null || echo 0)
            age_d=\$(( (\$(date +%s) - mt) / 86400 ))
            printf '  %4dd  %s:%s\n' \"\$age_d\" \"\$f\" \"\${line:-?}\"
          done
    done
  "
}

if [[ -n "$REMOTE_HOST" ]]; then
  run_search_remote
else
  run_search_local
fi

cat <<EOF

──────────────────────────────────────────────────────────────────────────
To read context around a hit:
  rg --type-add 'jsonl:*.jsonl' --type jsonl -B 5 -A 30 "$PATTERN" <file>

For remote hosts:
  ssh <host> "rg --type-add 'jsonl:*.jsonl' --type jsonl -B 5 -A 30 \"$PATTERN\" <file>"

To turn into cass-style results (if local cass index is fresh):
  cass search "$PATTERN" --robot --limit 30
EOF
