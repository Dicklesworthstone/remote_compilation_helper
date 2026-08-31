#!/usr/bin/env bash
# RCH Setup Validation Script
# Checks that RCH is properly configured and ready to use (prereqs, config,
# daemon, hook, shim). Read-only. Asks rch for paths instead of hardcoding them.

set -euo pipefail

if [[ -t 1 ]]; then
    RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'
else
    RED=''; GREEN=''; YELLOW=''; NC=''
fi

ERRORS=0
WARNINGS=0

pass() { echo -e "${GREEN}[PASS]${NC} $1"; }
fail() { echo -e "${RED}[FAIL]${NC} $1"; ERRORS=$((ERRORS + 1)); }
warn() { echo -e "${YELLOW}[WARN]${NC} $1"; WARNINGS=$((WARNINGS + 1)); }
info() { echo -e "      $1"; }

HAS_JQ=0
command -v jq >/dev/null 2>&1 && HAS_JQ=1

# GNU `timeout` is absent on stock macOS; fall back to running the command directly
if ! command -v timeout >/dev/null 2>&1; then
    if command -v gtimeout >/dev/null 2>&1; then timeout() { gtimeout "$@"; }; else timeout() { shift; "$@"; }; fi
fi

echo "RCH Setup Validation"
echo "===================="
echo

# 1. Prerequisites
echo "Prerequisites:"

if command -v rch >/dev/null 2>&1; then
    pass "rch binary found: $(command -v rch) ($(rch --version 2>/dev/null | head -1))"
else
    fail "rch binary not found in PATH"
fi

if command -v rchd >/dev/null 2>&1; then
    pass "rchd binary found: $(command -v rchd)"
else
    fail "rchd binary not found in PATH (hook auto-start and 'rch daemon start' need it)"
fi

for tool in rsync zstd ssh; do
    if command -v "$tool" >/dev/null 2>&1; then
        pass "$tool installed"
    else
        fail "$tool not installed"
    fi
done

if [[ "$HAS_JQ" -eq 1 ]]; then
    pass "jq installed (needed by the skill scripts)"
else
    warn "jq not installed — skill scripts and --json recipes need it"
fi

if [[ -n "${SSH_AUTH_SOCK:-}" ]]; then
    pass "ssh-agent running"
else
    warn "ssh-agent not running (only matters for passphrase-protected identity files)"
fi

echo

# 2. Configuration
echo "Configuration:"

CONFIG_DIR="${RCH_CONFIG_DIR:-${XDG_CONFIG_HOME:-$HOME/.config}/rch}"
LEGACY_MAC_DIR="$HOME/Library/Application Support/com.rch.rch"
WORKERS_FILE="$CONFIG_DIR/workers.toml"

if [[ -d "$CONFIG_DIR" ]]; then
    pass "Config directory exists: $CONFIG_DIR"
else
    fail "Config directory missing: $CONFIG_DIR (run: rch init, or rch config init)"
fi

if [[ -d "$LEGACY_MAC_DIR" ]]; then
    if [[ -d "$CONFIG_DIR" ]]; then
        warn "Both $CONFIG_DIR (used by the CLI — XDG wins) and legacy $LEGACY_MAC_DIR exist; make sure the daemon's --workers-config points at the same workers.toml (drift hazard)"
    else
        warn "Only the legacy $LEGACY_MAC_DIR exists — the CLI reads it; a launchd daemon pointed at ~/.config/rch/workers.toml would see a different worker list"
        CONFIG_DIR="$LEGACY_MAC_DIR"
        WORKERS_FILE="$CONFIG_DIR/workers.toml"
    fi
fi

if [[ -f "$WORKERS_FILE" ]]; then
    pass "Workers config exists: $WORKERS_FILE"
    WORKER_COUNT=$(grep -c '^\[\[workers\]\]' "$WORKERS_FILE" 2>/dev/null || true)   # grep -c prints 0 AND exits 1 on no match
    [[ "${WORKER_COUNT:-0}" =~ ^[0-9]+$ ]] || WORKER_COUNT=0
    if [[ "$WORKER_COUNT" -gt 0 ]]; then
        pass "Found $WORKER_COUNT worker(s) configured"
    else
        fail "No workers defined in $WORKERS_FILE"
    fi
else
    fail "Workers config missing: $WORKERS_FILE (run: rch workers init, or rch workers discover --add --yes)"
fi

if command -v rch >/dev/null 2>&1; then
    if rch config validate >/dev/null 2>&1; then
        pass "rch config validate: ok"
    else
        fail "rch config validate reported problems (run it for details)"
    fi
fi

echo

# 3. Daemon
echo "Daemon:"

DAEMON_JSON=""
if command -v rch >/dev/null 2>&1; then
    DAEMON_JSON="$(timeout 10 rch --json daemon status 2>/dev/null || true)"
fi

if [[ -n "$DAEMON_JSON" && "$HAS_JQ" -eq 1 ]]; then
    RUNNING="$(printf '%s' "$DAEMON_JSON" | jq -r '.data.running // false')"
    SOCKET_PATH="$(printf '%s' "$DAEMON_JSON" | jq -r '.data.socket_path // ""')"
    CFG_SOCKET="$(timeout 10 rch --json config get general.socket_path 2>/dev/null | jq -r '.data.value // ""' || true)"
    if [[ "$RUNNING" == "true" ]]; then
        pass "rchd running (socket: ${SOCKET_PATH:-unknown})"
        DAEMON_VER="$(timeout 15 rch --json status 2>/dev/null | jq -r '.data.daemon.daemon.version // ""' || true)"
        CLI_VER="$(rch --version 2>/dev/null | awk '{print $2}')"
        if [[ -n "$DAEMON_VER" && -n "$CLI_VER" && "$DAEMON_VER" != "$CLI_VER" ]]; then
            warn "daemon version $DAEMON_VER != CLI version $CLI_VER (fix: rch daemon restart -y)"
        fi
    else
        warn "rchd not running (start with: rch daemon start — the hook also auto-starts it after a 30s cooldown)"
    fi
    if [[ -n "$SOCKET_PATH" && -n "$CFG_SOCKET" && "$SOCKET_PATH" != "$CFG_SOCKET" ]]; then
        fail "socket mismatch: daemon=$SOCKET_PATH config=$CFG_SOCKET (fix: rch daemon restart -y)"
    fi
elif [[ -n "$DAEMON_JSON" ]]; then
    if printf '%s' "$DAEMON_JSON" | grep -q '"running"[[:space:]]*:[[:space:]]*true'; then
        pass "rchd running"
    else
        warn "rchd not running (start with: rch daemon start)"
    fi
else
    if pgrep -x rchd >/dev/null 2>&1; then
        warn "rchd process exists but 'rch --json daemon status' returned nothing (socket path mismatch?)"
    else
        warn "rchd not running (start with: rch daemon start)"
    fi
fi

echo

# 4. Hooks (per agent)
echo "Agent hooks:"

AGENTS_JSON=""
if command -v rch >/dev/null 2>&1; then
    AGENTS_JSON="$(timeout 10 rch --json agents status 2>/dev/null || true)"
fi

if [[ -n "$AGENTS_JSON" && "$HAS_JQ" -eq 1 ]]; then
    # `kind` is the PascalCase Debug name ("ClaudeCode") on both 1.0.58 and main; accept kebab too, defensively
    CLAUDE_STATUS="$(printf '%s' "$AGENTS_JSON" | jq -r '.data.agents[]? | select((.kind // "") | test("^(ClaudeCode|claude-code)$")) | .hook_status // ""')"
    if [[ "$CLAUDE_STATUS" == "Installed" ]]; then
        pass "Claude Code PreToolUse hook installed"
    elif [[ -n "$CLAUDE_STATUS" ]]; then
        fail "Claude Code hook: $CLAUDE_STATUS (fix: rch hook install)"
    else
        warn "Claude Code not detected on this host"
    fi
    # process substitution (not a pipe) so pass/warn update the counters in this shell
    while IFS=$'\t' read -r name status; do
        [[ -z "$name" ]] && continue
        if [[ "$status" == "Installed" ]]; then
            pass "$name hook installed"
        else
            warn "$name detected, hook $status (optional: rch agents install-hook <agent>)"
        fi
    done < <(printf '%s' "$AGENTS_JSON" \
      | jq -r '.data.agents[]? | select(((.kind // "") | test("^(ClaudeCode|claude-code)$") | not) and .can_install_hook==true and (.detected // true)) | "\(.name)\t\(.hook_status // "unknown")"')
else
    SETTINGS_FILE="$HOME/.claude/settings.json"
    if [[ -f "$SETTINGS_FILE" ]] && grep -q "PreToolUse" "$SETTINGS_FILE" 2>/dev/null && grep -q "rch" "$SETTINGS_FILE" 2>/dev/null; then
        pass "RCH hook registered in Claude Code settings"
    else
        fail "Claude Code PreToolUse hook not registered (fix: rch hook install)"
    fi
fi

echo

# 5. Cargo shim (non-hook agents, scripts, CI)
echo "Cargo shim:"

SHIM_JSON=""
if command -v rch >/dev/null 2>&1; then
    SHIM_JSON="$(timeout 10 rch shim status --json 2>/dev/null || true)"
fi

if [[ -n "$SHIM_JSON" && "$HAS_JQ" -eq 1 ]]; then
    SHIM_INSTALLED="$(printf '%s' "$SHIM_JSON" | jq -r '(.data // .).installed // false')"
    SHIM_LOCAL="$(printf '%s' "$SHIM_JSON" | jq -r '(.data // .).local_builds_running // 0')"
    SHIM_INTERCEPT="$(printf '%s' "$SHIM_JSON" | jq -r '(.data // .) | (.interception // (if .on_path_ahead_of_cargo == true then "direct" elif .on_path_ahead_of_cargo == false then "none" else "unknown" end))')"
    SHIM_WRAPPED="$(printf '%s' "$SHIM_JSON" | jq -r '(.data // .).toolchains_wrapped // ""')"
    SHIM_TOTAL="$(printf '%s' "$SHIM_JSON" | jq -r '(.data // .).toolchains_total // ""')"
    if [[ "$SHIM_INSTALLED" == "true" ]]; then
        pass "cargo shim installed (~/.rch/shims/cargo), interception: $SHIM_INTERCEPT"
        [[ "$SHIM_INTERCEPT" == "none" ]] && fail "shim is not ahead of cargo on PATH (prepend ~/.rch/shims in the shell rc the agent harness uses)"
        if [[ -n "$SHIM_WRAPPED" && -n "$SHIM_TOTAL" && "$SHIM_WRAPPED" != "$SHIM_TOTAL" ]]; then
            warn "rustup toolchains wrapped: $SHIM_WRAPPED/$SHIM_TOTAL — re-run 'rch shim install'"
        fi
    else
        warn "cargo shim not installed — Codex/scripts/CI builds will compile locally (dispatcher boxes: rch shim install)"
    fi
    if [[ "$SHIM_LOCAL" =~ ^[0-9]+$ && "$SHIM_LOCAL" -gt 0 ]]; then
        warn "$SHIM_LOCAL local rustc/cargo build(s) running on this box right now"
    fi
else
    warn "could not query 'rch shim status --json' (older binary, or rch missing)"
fi

echo

# 6. Summary
echo "===================="
if [[ $ERRORS -eq 0 && $WARNINGS -eq 0 ]]; then
    echo -e "${GREEN}All checks passed! RCH is ready.${NC}"
    exit 0
elif [[ $ERRORS -eq 0 ]]; then
    echo -e "${YELLOW}$WARNINGS warning(s), no errors. RCH may work with limitations.${NC}"
    exit 0
else
    echo -e "${RED}$ERRORS error(s), $WARNINGS warning(s). Next: rch doctor --fix --dry-run, rch status --remediation.${NC}"
    exit 1
fi
