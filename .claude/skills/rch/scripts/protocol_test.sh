#!/usr/bin/env bash
# protocol_test.sh — directly probe the rch hook protocol with synthetic inputs.
#
# Confirms what the hook will do for a given command without actually building.
# Useful when:
#   - hook seems installed but commands run locally
#   - you want to know whether a compound command (cd ... && cargo ...) will be wrapped
#   - you want to see the exact JSON the hook returns
#
# Usage:
#   ./protocol_test.sh                                   # default tests
#   ./protocol_test.sh "cargo build --release"           # one custom command
#   ./protocol_test.sh "cd /data/projects/x && cargo check"

set -euo pipefail

require() { command -v "$1" >/dev/null 2>&1 || { echo "missing: $1" >&2; exit 127; }; }
require rch
require jq

# Use mktemp so concurrent runs don't collide and we clean up on exit/interrupt.
STDERR_TMP="$(mktemp -t rch_proto_stderr.XXXXXX)"
trap 'rm -f "$STDERR_TMP"' EXIT INT TERM

run_one() {
  local cmd="$1"
  local input
  input=$(jq -nc --arg c "$cmd" '{tool_name:"Bash", tool_input:{command:$c}}')
  printf '\n--- INPUT ---\n%s\n' "$input"
  printf '\n--- STDOUT (the hook decision) ---\n'
  local out rc=0
  # don't let `set -e` abort the battery on a non-zero hook exit (e.g. exit 2 = deny)
  out=$(printf '%s\n' "$input" | RCH_LOG_LEVEL=info rch 2>"$STDERR_TMP") || rc=$?
  [[ $rc -ne 0 ]] && printf '(hook exit code: %d)\n' "$rc"
  if [[ -z "$out" ]]; then
    printf '(empty)  → ALLOW UNCHANGED (hook did not intercept)\n'
  else
    printf '%s\n' "$out" | jq . 2>/dev/null || printf '%s\n' "$out"
    if grep -q '"updatedInput"' <<<"$out"; then
      printf '\n  → hook will REWRITE to: %s\n' \
        "$(jq -r '.hookSpecificOutput.updatedInput.command' <<<"$out")"
    elif grep -q '"deny"' <<<"$out"; then
      printf '\n  → hook will DENY\n'
    fi
  fi
  printf '\n--- STDERR (diagnostics) ---\n'
  cat "$STDERR_TMP" || true
  : > "$STDERR_TMP"   # truncate for next run
  printf '\n=================================================================\n'
}

if [[ $# -gt 0 ]]; then
  for cmd in "$@"; do
    run_one "$cmd"
  done
  exit 0
fi

# Default battery
COMMANDS=(
  "cargo check"
  "cargo build --release"
  "cargo test --workspace"
  "cargo nextest run"
  "bun test"
  "bun typecheck"
  "ls -la"                               # should NOT be intercepted
  "cargo install ripgrep"                # should NOT be intercepted (mutating)
  "cargo fmt --check"                    # should NOT be intercepted (read-only; only admitted via --clean-overlay)
  "cd /data/projects/x && cargo check"   # compound: should preserve cd
  "cargo build --release 2>&1 | tee build.log"   # pipes are fine now
  "bash -lc 'cargo test'"                # shell-wrapped: NOT intercepted at the hook (shim may still catch it)
  "RCH_ENABLED=0 cargo build"            # inline env prefix does NOT bypass the hook
  "go test ./..."                        # classified as compilation, but left unchanged by the 1.0.58 hook on this fleet
  "nix build"                            # same — see references/HOOKS.md
)

for cmd in "${COMMANDS[@]}"; do
  run_one "$cmd"
done

cat <<'EOF'

──────────────────────────────────────────────────────────────────────────
Interpretation:
  • Empty stdout    → hook does nothing (command runs as-is, locally)
  • permissionDecision=allow + updatedInput → hook will rewrite to `rch exec -- ...`
  • permissionDecision=deny → policy or config blocks the command

If a compilation command (cargo build, cargo test, etc.) returns empty stdout:
  - Check 'rch hook status' to confirm the hook is installed for the right agent
  - Check '[general] enabled = true' in ~/.config/rch/config.toml (and RCH_ENABLED in the harness env)
  - Check '[general] force_local' isn't true (also in the project's .rch/config.toml)
  - Run 'rch diagnose "<command>"' to see classifier output
  - go/nix commands are classified as compilation but the 1.0.58 hook has been observed to leave them unchanged

Note: an inline RCH_*=... prefix is part of the command text, not the hook's
environment — it is rewritten like any other build. To keep a build local on
purpose use .rch/config.toml [general] force_local = true (see references/SHIM.md).
EOF
