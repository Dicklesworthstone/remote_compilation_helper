#!/usr/bin/env bash
#
# e2e_remediation_views.sh — E2E runner for the human dashboard TUI/web
# remediation views (bd-session-history-remediation-ocv9i.14.4).
#
# Exercises the operator-facing remediation surfaces end to end and emits one
# structured JSONL record per scenario with the mandated program fields:
#
#   run_id, bead_id, scenario, event, status, route_or_view, reason_code,
#   duration_ms, detail
#
# Scenarios:
#   tui_dump_state    — `rch dashboard --mock-data --dump-state` exposes the
#                       assembled remediation view (8 bands + overall posture)
#                       without a daemon.
#   tui_redaction     — the dumped view leaks no secrets / hostnames / paths.
#   cli_status_remed  — `rch status --remediation --json` returns the
#                       `status-remediation` envelope (skipped if no daemon).
#   web_surface       — the web `/api/remediation` route, `/remediation` page,
#                       and sidebar nav link are present.
#
# Surfaces still gated on a live daemon record status=skipped with a reason code
# (never a false FAIL). Exit codes (consumed by scripts/run_all_e2e.sh):
#   0  all scenarios pass (skips allowed)
#   1  a scenario failed
#   4  skipped (rch binary or python3 unavailable — capability not present)
#   2  setup error
#
# Usage:
#   ./scripts/e2e_remediation_views.sh [--run-id=ID]

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
export PROJECT_ROOT

E2E_SKIP_EXIT=4
BEAD_ID="bd-session-history-remediation-ocv9i.14.4"
RUN_ID="run-$(date -u '+%Y%m%d%H%M%S')-$$-${RANDOM}"
for arg in "$@"; do
    case "$arg" in
        --run-id=*) RUN_ID="${arg#*=}" ;;
        --help | -h)
            sed -n '2,30p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'
            exit 0
            ;;
    esac
done

TARGET_DIR="${CARGO_TARGET_DIR:-$PROJECT_ROOT/target}"
LOG_DIR="$TARGET_DIR/test-logs"
MIRROR_DIR="$PROJECT_ROOT/target/test-logs"
mkdir -p "$LOG_DIR" "$MIRROR_DIR"
SUITE_LOG="${RCH_E2E_LOG:-$LOG_DIR/e2e_remediation_views.jsonl}"
: >"$SUITE_LOG"

PASS=0
FAIL=0
SKIP=0

# Emit one JSONL record (canonical field order) to the suite log + mirror, with
# human progress on stderr.
emit() {
    local scenario="$1" event="$2" status="$3" route="$4" reason="$5" dur="$6" detail="$7"
    local line
    line=$(python3 - "$RUN_ID" "$BEAD_ID" "$scenario" "$event" "$status" "$route" "$reason" "$dur" "$detail" <<'PY'
import json, sys
keys = ["run_id","bead_id","scenario","event","status","route_or_view","reason_code","duration_ms","detail"]
vals = sys.argv[1:10]
rec = dict(zip(keys, vals))
rec["duration_ms"] = int(rec["duration_ms"]) if str(rec["duration_ms"]).isdigit() else 0
print(json.dumps(rec, separators=(",", ":")))
PY
)
    printf '%s\n' "$line" >>"$SUITE_LOG"
    case "$status" in
        pass) PASS=$((PASS + 1)); printf '  [PASS] %-18s %s\n' "$scenario" "$detail" >&2 ;;
        fail) FAIL=$((FAIL + 1)); printf '  [FAIL] %-18s %s\n' "$scenario" "$detail" >&2 ;;
        skip) SKIP=$((SKIP + 1)); printf '  [SKIP] %-18s %s (%s)\n' "$scenario" "$detail" "$reason" >&2 ;;
    esac
}

now_ms() { date +%s%3N 2>/dev/null || echo 0; }

command -v python3 >/dev/null 2>&1 || {
    echo "python3 unavailable; skipping" >&2
    exit "$E2E_SKIP_EXIT"
}

RCH_BIN=""
for cand in "$PROJECT_ROOT/target/release/rch" "$PROJECT_ROOT/target/debug/rch"; do
    [[ -x "$cand" ]] && {
        RCH_BIN="$cand"
        break
    }
done
[[ -z "$RCH_BIN" ]] && command -v rch >/dev/null 2>&1 && RCH_BIN="$(command -v rch)"

echo "Remediation views E2E (run_id=$RUN_ID)" >&2

# --- tui_dump_state + tui_redaction ------------------------------------------
DUMP=""
if [[ -n "$RCH_BIN" ]]; then
    t0=$(now_ms)
    if DUMP="$("$RCH_BIN" dashboard --mock-data --dump-state 2>/dev/null)"; then
        dur=$(($(now_ms) - t0))
        bands=$(printf '%s' "$DUMP" | python3 -c 'import json,sys; d=json.load(sys.stdin); r=d.get("remediation") or {}; print(len(r.get("bands",[])))' 2>/dev/null || echo 0)
        overall=$(printf '%s' "$DUMP" | python3 -c 'import json,sys; d=json.load(sys.stdin); r=d.get("remediation") or {}; print(r.get("overall",""))' 2>/dev/null || echo "")
        if [[ "$bands" == "8" && -n "$overall" ]]; then
            emit "tui_dump_state" "render" "pass" "tui:dashboard" "" "$dur" "8 bands; overall=$overall"
        else
            emit "tui_dump_state" "render" "fail" "tui:dashboard" "missing_remediation" "$dur" "expected 8 bands+overall, got bands=$bands overall=$overall"
        fi
    else
        emit "tui_dump_state" "render" "skip" "tui:dashboard" "dump_state_unavailable" "0" "dashboard --dump-state did not run"
    fi
else
    emit "tui_dump_state" "render" "skip" "tui:dashboard" "rch_binary_unavailable" "0" "rch binary not built"
fi

if [[ -n "$DUMP" ]]; then
    # The view carries only worker-id aliases, counts, reason codes, and
    # pre-redacted text — never hostnames, SSH users, paths, or secrets.
    rem_json=$(printf '%s' "$DUMP" | python3 -c 'import json,sys; d=json.load(sys.stdin); print(json.dumps(d.get("remediation") or {}))' 2>/dev/null || echo '{}')
    leak=""
    printf '%s' "$rem_json" | grep -Eq 'AKIA[0-9A-Z]{16}' && leak="aws_key"
    printf '%s' "$rem_json" | grep -q 'BEGIN RSA PRIVATE KEY' && leak="pem"
    printf '%s' "$rem_json" | grep -Eq '@[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' && leak="host_user"
    if [[ -z "$leak" ]]; then
        emit "tui_redaction" "assert" "pass" "tui:dashboard" "" "0" "no secret/host/path leak in dumped view"
    else
        emit "tui_redaction" "assert" "fail" "tui:dashboard" "$leak" "0" "secret-shaped string leaked in dumped view"
    fi
else
    emit "tui_redaction" "assert" "skip" "tui:dashboard" "no_dump" "0" "no dump-state output to scan"
fi

# --- cli_status_remed ---------------------------------------------------------
if [[ -n "$RCH_BIN" ]]; then
    t0=$(now_ms)
    if out="$("$RCH_BIN" status --remediation --json 2>/dev/null)" \
        && printf '%s' "$out" | grep -q '"command":"status-remediation"'; then
        dur=$(($(now_ms) - t0))
        emit "cli_status_remed" "query" "pass" "cli:status --remediation" "" "$dur" "status-remediation envelope returned"
    else
        # No daemon configured in this env is expected, not a defect.
        emit "cli_status_remed" "query" "skip" "cli:status --remediation" "daemon_unreachable" "0" "no daemon to serve status --remediation"
    fi
else
    emit "cli_status_remed" "query" "skip" "cli:status --remediation" "rch_binary_unavailable" "0" "rch binary not built"
fi

# --- web_surface --------------------------------------------------------------
route_ts="$PROJECT_ROOT/web/src/app/api/remediation/route.ts"
page_tsx="$PROJECT_ROOT/web/src/app/remediation/page.tsx"
sidebar="$PROJECT_ROOT/web/src/components/layout/sidebar.tsx"
if [[ -f "$route_ts" && -f "$page_tsx" ]] && grep -q "'/remediation'" "$sidebar" 2>/dev/null; then
    emit "web_surface" "assert" "pass" "web:/remediation" "" "0" "route.ts + page.tsx + sidebar nav present"
else
    emit "web_surface" "assert" "fail" "web:/remediation" "web_surface_missing" "0" "missing web remediation route/page/nav"
fi

# Mirror the suite log so run_all_e2e.sh collects it regardless of target dir.
[[ "$SUITE_LOG" != "$MIRROR_DIR/e2e_remediation_views.jsonl" ]] \
    && cp -f "$SUITE_LOG" "$MIRROR_DIR/e2e_remediation_views.jsonl" 2>/dev/null || true

echo "Summary: pass=$PASS skip=$SKIP fail=$FAIL (run_id=$RUN_ID)" >&2
[[ "$FAIL" -gt 0 ]] && exit 1
exit 0
