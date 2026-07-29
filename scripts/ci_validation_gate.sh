#!/usr/bin/env bash
#
# ci_validation_gate.sh — unified CI/release validation gate for the
# session-history remediation program (bd-session-history-remediation-ocv9i.16.5).
#
# Wires the program's validation matrix into a single gate that runs WITHOUT a
# live fleet. It runs (in order, recording per-stage status + reason code +
# owning remediation bead):
#
#   1. dep_cycles            br dep cycles must be empty            -> ...16.5
#   2. closed_bead_evidence  every closed program bead cites        -> ...16.5
#                            commands/log-artifacts in its close
#   3. matrix                reliability coverage matrix tests      -> ...16.1
#   4. schema_goldens        schema/golden regression tests         -> ...16.4
#   5. ci_tiers              CI test-tier definitions               -> ...16.1
#   6. e2e_mock              remediation E2E program (dry-run/mock)  -> ...16.3
#   7. perf_budgets          hot-path performance budgets            -> ...16.7
#   8. live_smoke            real-fleet smoke (OPT-IN: --live)        -> ...16.6
#
# Output: a concise Markdown + JSON summary with per-stage and per-bead status.
# A failed stage carries the exact reason code and the remediation bead id.
#
# Exit: 0 if no stage failed (skips allowed), 1 if any stage failed, 2 on setup
# error. Live-worker stages are SKIPPED by default; pass --live to include them.
#
# Usage:
#   scripts/ci_validation_gate.sh [--run-id ID] [--out-dir DIR] [--quick]
#                                 [--strict] [--live]
#     --quick   run only the fast checks (dep_cycles + closed_bead_evidence +
#               summary); skip the cargo/e2e compilation stages.
#     --strict  fail (not warn) when a closed bead cites a command XOR an
#               artifact but not both.
#     --live    additionally run real-fleet live-worker stages (needs a fleet).

set -uo pipefail
# shellcheck disable=SC2155
export PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$PROJECT_ROOT" || { echo "ci_validation_gate: cannot cd to $PROJECT_ROOT" >&2; exit 2; }

RUN_ID="gate-$$"
OUT_DIR="$PROJECT_ROOT/target/validation-gate"
QUICK=0
STRICT=0
RUN_LIVE=0
OFFLOAD=0

while [[ $# -gt 0 ]]; do
    case "$1" in
        --run-id) RUN_ID="$2"; shift ;;
        --run-id=*) RUN_ID="${1#*=}" ;;
        --out-dir) OUT_DIR="$2"; shift ;;
        --out-dir=*) OUT_DIR="${1#*=}" ;;
        --quick) QUICK=1 ;;
        --strict) STRICT=1 ;;
        --live) RUN_LIVE=1 ;;
        --offload) OFFLOAD=1 ;;
        -h|--help) sed -n '2,45p' "$0"; exit 0 ;;
        *) echo "ci_validation_gate: unknown arg: $1" >&2; exit 2 ;;
    esac
    shift
done

# python3 backs every stage record + the summary; fail fast with a clear message
# rather than silently writing nothing.
if ! command -v python3 >/dev/null 2>&1; then
    echo "ci_validation_gate: python3 is required" >&2
    exit 2
fi

mkdir -p "$OUT_DIR"
STAGES_LOG="$OUT_DIR/stages.jsonl"
AUDIT_JSON="$OUT_DIR/closed_bead_evidence.json"
SUMMARY_JSON="$OUT_DIR/summary.json"
SUMMARY_MD="$OUT_DIR/summary.md"
: > "$STAGES_LOG"
GATE_FAIL=0

# record_stage <name> <status> <exit_code> <reason_code> <remediation_bead> <detail>
record_stage() {
    python3 - "$1" "$2" "$3" "$4" "$5" "$6" >>"$STAGES_LOG" <<'PY'
import json, sys
n, s, ec, rc, rem, det = sys.argv[1:7]
print(json.dumps({"stage": n, "status": s, "exit_code": int(ec),
                  "reason_code": (rc or None), "remediation_bead": (rem or None),
                  "detail": det}))
PY
    [[ "$2" == "fail" ]] && GATE_FAIL=1
    printf '  [%-4s] %-22s %s\n' "$2" "$1" "$6" >&2
    return 0
}

# cargo_stage <name> <reason_code> <rembead> -- <cargo args...>
cargo_stage() {
    local name="$1" reason="$2" rem="$3"; shift 4  # drop the literal --
    if [[ $QUICK -eq 1 ]]; then
        record_stage "$name" "skip" 0 "" "$rem" "skipped (--quick)"; return 0
    fi
    if ! command -v cargo >/dev/null 2>&1; then
        record_stage "$name" "skip" 0 "" "$rem" "skipped (cargo unavailable)"; return 0
    fi
    # --offload routes the build/test through `rch exec` (remote worker) so the
    # gate does not saturate local CPU; falls back to local cargo if rch is
    # absent. Plain `cargo` otherwise keeps the gate portable for CI runners.
    local rc
    if [[ $OFFLOAD -eq 1 ]] && command -v rch >/dev/null 2>&1; then
        rch exec -- cargo "$@" >"$OUT_DIR/$name.log" 2>&1; rc=$?
    else
        cargo "$@" >"$OUT_DIR/$name.log" 2>&1; rc=$?
    fi
    if [[ $rc -eq 0 ]]; then
        record_stage "$name" "pass" 0 "" "$rem" "ok$([[ $OFFLOAD -eq 1 ]] && echo ' (offloaded)')"
    else
        record_stage "$name" "fail" "$rc" "$reason" "$rem" "see $OUT_DIR/$name.log"
    fi
}

echo "===== RCH validation gate (ocv9i.16.5) run_id=$RUN_ID =====" >&2

# --- 1. dependency cycles -----------------------------------------------------
# Capture br's full output FIRST, then grep a here-string. Piping `br` into
# `grep -q` is unsafe here: grep -q closes the pipe on first match and, under
# `set -o pipefail`, a SIGPIPE-killed `br` would make the pipeline non-zero and
# spuriously report "cycles". The here-string has no upstream process to signal.
if command -v br >/dev/null 2>&1; then
    cycles_out="$(br dep cycles 2>&1)"
    if grep -qiE "no (dependency )?cycles" <<<"$cycles_out"; then
        record_stage "dep_cycles" "pass" 0 "" "bd-session-history-remediation-ocv9i.16.5" "no cycles"
    else
        record_stage "dep_cycles" "fail" 1 "RCH-GATE-DEP-CYCLE" \
            "bd-session-history-remediation-ocv9i.16.5" "br dep cycles reported cycles"
    fi
else
    record_stage "dep_cycles" "skip" 0 "" "bd-session-history-remediation-ocv9i.16.5" "skipped (br unavailable)"
fi

# --- 2. closed-bead close-reason evidence audit -------------------------------
AUDIT_ARGS=(--beads "$PROJECT_ROOT/.beads/issues.jsonl" --out-json "$AUDIT_JSON")
[[ $STRICT -eq 1 ]] && AUDIT_ARGS+=(--strict)
if [[ -f "$PROJECT_ROOT/.beads/issues.jsonl" ]]; then
    if python3 "$PROJECT_ROOT/scripts/lib/audit_closed_beads.py" "${AUDIT_ARGS[@]}" >/dev/null 2>"$OUT_DIR/closed_bead_evidence.err"; then
        record_stage "closed_bead_evidence" "pass" 0 "" \
            "bd-session-history-remediation-ocv9i.16.5" "all closed program beads cite evidence"
    else
        record_stage "closed_bead_evidence" "fail" 1 "RCH-GATE-EVIDENCE-MISSING" \
            "bd-session-history-remediation-ocv9i.16.5" "see $AUDIT_JSON"
    fi
else
    record_stage "closed_bead_evidence" "skip" 0 "" \
        "bd-session-history-remediation-ocv9i.16.5" "skipped (no beads export)"
fi

# --- 3..7 cargo + e2e stages (mock-worker; no live fleet) ---------------------
cargo_stage "matrix" "RCH-GATE-MATRIX-GAP" "bd-session-history-remediation-ocv9i.16.1" -- \
    test -p rch-common --test reliability_coverage_matrix_e2e
cargo_stage "schema_goldens" "RCH-GATE-SCHEMA-DRIFT" "bd-session-history-remediation-ocv9i.16.4" -- \
    test -p rch-common --test golden_schemas_e2e
cargo_stage "ci_tiers" "RCH-GATE-TIER-DRIFT" "bd-session-history-remediation-ocv9i.16.1" -- \
    test -p rch-common --test ci_test_tiers_e2e

run_script_stage() {  # <name> <reason> <rembead> <script> <args...>
    local name="$1" reason="$2" rem="$3" script="$4"; shift 4
    if [[ $QUICK -eq 1 ]]; then
        record_stage "$name" "skip" 0 "" "$rem" "skipped (--quick)"; return 0
    fi
    if [[ ! -x "$PROJECT_ROOT/scripts/$script" ]]; then
        record_stage "$name" "skip" 0 "" "$rem" "skipped ($script missing)"; return 0
    fi
    bash "$PROJECT_ROOT/scripts/$script" "$@" >"$OUT_DIR/$name.log" 2>&1
    local rc=$?
    if [[ $rc -eq 0 ]]; then
        record_stage "$name" "pass" 0 "" "$rem" "ok"
    elif [[ $rc -eq 4 ]]; then
        record_stage "$name" "skip" 4 "" "$rem" "script self-skipped (exit 4)"
    else
        record_stage "$name" "fail" "$rc" "$reason" "$rem" "see $OUT_DIR/$name.log"
    fi
}

run_script_stage "e2e_mock" "RCH-GATE-E2E-FAIL" "bd-session-history-remediation-ocv9i.16.3" \
    e2e_remediation_program.sh --dry-run --mock-worker --run-id "$RUN_ID"
run_script_stage "perf_budgets" "RCH-GATE-PERF-REGRESSION" "bd-session-history-remediation-ocv9i.16.7" \
    e2e_perf_budgets.sh --run-id "$RUN_ID"

# --- 8. live-worker stages (opt-in only) --------------------------------------
if [[ $RUN_LIVE -eq 1 ]]; then
    run_script_stage "live_smoke" "RCH-GATE-LIVE-SMOKE-FAIL" "bd-session-history-remediation-ocv9i.16.6" \
        e2e_real_fleet_smoke.sh --run-id "$RUN_ID"
else
    record_stage "live_smoke" "skip" 0 "" "bd-session-history-remediation-ocv9i.16.6" \
        "live-worker stage skipped by default (pass --live to run)"
fi

# --- summary (Markdown + JSON, per-stage + per-bead) --------------------------
RUN_ID="$RUN_ID" OUT_DIR="$OUT_DIR" STAGES_LOG="$STAGES_LOG" AUDIT_JSON="$AUDIT_JSON" \
SUMMARY_JSON="$SUMMARY_JSON" SUMMARY_MD="$SUMMARY_MD" python3 <<'PY'
import json, os

stages = []
with open(os.environ["STAGES_LOG"]) as f:
    for line in f:
        line = line.strip()
        if line:
            stages.append(json.loads(line))

audit = {}
ap = os.environ["AUDIT_JSON"]
if os.path.exists(ap):
    with open(ap) as f:
        audit = json.load(f)

passed = [s for s in stages if s["status"] == "pass"]
failed = [s for s in stages if s["status"] == "fail"]
skipped = [s for s in stages if s["status"] == "skip"]

summary = {
    "gate": "ci_validation_gate",
    "remediation_bead": "bd-session-history-remediation-ocv9i.16.5",
    "run_id": os.environ["RUN_ID"],
    "ok": len(failed) == 0,
    "totals": {"stages": len(stages), "pass": len(passed), "fail": len(failed), "skip": len(skipped)},
    "stages": stages,
    "closed_bead_evidence": audit.get("totals", {}),
    "beads": audit.get("beads", []),
}
with open(os.environ["SUMMARY_JSON"], "w") as f:
    json.dump(summary, f, indent=2)

def row(cells):
    return "| " + " | ".join(cells) + " |"

md = []
verdict = "PASS ✅" if summary["ok"] else "FAIL ❌"
md.append(f"# RCH validation gate — {verdict}")
md.append("")
md.append(f"- Run: `{summary['run_id']}`  Remediation bead: `{summary['remediation_bead']}`")
t = summary["totals"]
md.append(f"- Stages: {t['pass']} pass / {t['fail']} fail / {t['skip']} skip")
ce = summary["closed_bead_evidence"]
if ce:
    md.append(f"- Closed-bead evidence: {ce.get('pass',0)} pass / {ce.get('warn',0)} warn / {ce.get('fail',0)} fail "
              f"(of {ce.get('audited',0)} program beads)")
md.append("")
md.append("## Stages")
md.append(row(["Stage", "Status", "Reason code", "Remediation bead", "Detail"]))
md.append(row(["---"] * 5))
for s in stages:
    md.append(row([s["stage"], s["status"], s.get("reason_code") or "—",
                   (s.get("remediation_bead") or "—").replace("bd-session-history-remediation-", "…"),
                   s["detail"]]))
if failed:
    md.append("")
    md.append("## Failed stages (action required)")
    for s in failed:
        md.append(f"- **{s['stage']}** — `{s.get('reason_code')}` → remediation `{s.get('remediation_bead')}` — {s['detail']}")
warns = [b for b in summary["beads"] if b["status"] == "WARN"]
efails = [b for b in summary["beads"] if b["status"] == "FAIL"]
if efails or warns:
    md.append("")
    md.append("## Closed-bead evidence flags")
    for b in efails:
        md.append(f"- ❌ `{b['id']}` — no close-reason evidence (len {b['reason_len']})")
    for b in warns:
        md.append(f"- ⚠️ `{b['id']}` — commit-only thin close (no test/command/artifact cited); review")
md.append("")
with open(os.environ["SUMMARY_MD"], "w") as f:
    f.write("\n".join(md) + "\n")

print("\n".join(md))
PY

echo "" >&2
echo "summary: $SUMMARY_MD  |  $SUMMARY_JSON" >&2
if [[ $GATE_FAIL -eq 1 ]]; then
    echo "VALIDATION GATE: FAIL" >&2
    exit 1
fi
echo "VALIDATION GATE: PASS" >&2
exit 0
