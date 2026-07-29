#!/usr/bin/env bash
# RCH Setup Validation Script
# Checks that RCH is properly configured and ready to use

set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

ERRORS=0
WARNINGS=0

pass() { echo -e "${GREEN}[PASS]${NC} $1"; }
fail() { echo -e "${RED}[FAIL]${NC} $1"; ((ERRORS++)); }
warn() { echo -e "${YELLOW}[WARN]${NC} $1"; ((WARNINGS++)); }
info() { echo -e "      $1"; }

echo "RCH Setup Validation"
echo "===================="
echo

# 1. Check prerequisites
echo "Prerequisites:"

if command -v rch &>/dev/null; then
    pass "rch binary found: $(which rch)"
else
    fail "rch binary not found in PATH"
fi

if command -v rsync &>/dev/null; then
    pass "rsync installed"
else
    fail "rsync not installed"
fi

if command -v zstd &>/dev/null; then
    pass "zstd installed"
else
    fail "zstd not installed"
fi

if [ -n "${SSH_AUTH_SOCK:-}" ]; then
    pass "ssh-agent running"
else
    warn "ssh-agent not running (may need: eval \$(ssh-agent) && ssh-add)"
fi

echo

# 2. Check configuration
echo "Configuration:"

CONFIG_DIR="${XDG_CONFIG_HOME:-$HOME/.config}/rch"
WORKERS_FILE="$CONFIG_DIR/workers.toml"

if [ -d "$CONFIG_DIR" ]; then
    pass "Config directory exists: $CONFIG_DIR"
else
    fail "Config directory missing: $CONFIG_DIR"
fi

if [ -f "$WORKERS_FILE" ]; then
    pass "Workers config exists: $WORKERS_FILE"

    # Count workers
    WORKER_COUNT=$(grep -c '^\[\[workers\]\]' "$WORKERS_FILE" 2>/dev/null || echo 0)
    if [ "$WORKER_COUNT" -gt 0 ]; then
        pass "Found $WORKER_COUNT worker(s) configured"
    else
        fail "No workers defined in $WORKERS_FILE"
    fi
else
    fail "Workers config missing: $WORKERS_FILE"
fi

echo

# 3. Check daemon
echo "Daemon:"

# The socket path is not fixed: it resolves to $XDG_RUNTIME_DIR/rch.sock, then
# ~/.cache/rch/rch.sock, then /tmp/rch.sock. Check each candidate (and let
# config override RCH_SOCKET_PATH/RCH_DAEMON_SOCKET win) rather than hardcoding.
SOCKET_FOUND=""
for candidate in \
    "${RCH_SOCKET_PATH:-}" \
    "${RCH_DAEMON_SOCKET:-}" \
    "${XDG_RUNTIME_DIR:-}/rch.sock" \
    "$HOME/.cache/rch/rch.sock" \
    "/tmp/rch.sock"; do
    [ -n "$candidate" ] || continue
    if [ -S "$candidate" ]; then
        SOCKET_FOUND="$candidate"
        break
    fi
done

if [ -n "$SOCKET_FOUND" ]; then
    pass "Daemon socket exists: $SOCKET_FOUND"
else
    warn "Daemon socket not found (run: rch daemon status)"
fi

if pgrep -x rchd &>/dev/null; then
    pass "rchd process running"
else
    warn "rchd not running (start with: rch daemon start)"
fi

echo

# 4. Check Claude Code hook
echo "Claude Code Hook:"

SETTINGS_FILE="$HOME/.claude/settings.json"

if [ -f "$SETTINGS_FILE" ]; then
    if grep -q "PreToolUse" "$SETTINGS_FILE" 2>/dev/null; then
        if grep -q "rch" "$SETTINGS_FILE" 2>/dev/null; then
            pass "RCH hook registered in Claude Code"
        else
            fail "PreToolUse exists but RCH not configured"
        fi
    else
        fail "No PreToolUse hook configured"
    fi
else
    fail "Claude Code settings not found: $SETTINGS_FILE"
fi

echo

# 5. Summary
echo "===================="
if [ $ERRORS -eq 0 ] && [ $WARNINGS -eq 0 ]; then
    echo -e "${GREEN}All checks passed! RCH is ready.${NC}"
    exit 0
elif [ $ERRORS -eq 0 ]; then
    echo -e "${YELLOW}$WARNINGS warning(s), no errors. RCH may work with limitations.${NC}"
    exit 0
else
    echo -e "${RED}$ERRORS error(s), $WARNINGS warning(s). Run 'rch doctor --fix' to resolve.${NC}"
    exit 1
fi
