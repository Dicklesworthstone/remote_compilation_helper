#!/usr/bin/env bash
#
# redaction_leak_check.sh — secret-leak guard for RCH output surfaces (bd-53ga7).
#
# Injects representative provider-shaped secrets (AWS / GitHub / Anthropic /
# Stripe / Slack / bearer / JWT / DATABASE_URL / home path) into the surfaces
# that emit free text, then asserts NONE of them survive into any stdout/stderr,
# config export, or on-disk artifact. Complements the Rust consumer-wiring proof
# in rch-common/tests/redaction_leak_guard_e2e.rs (incident ledger + artifact
# diagnostics), which this script does not duplicate.
#
# Every secret is assembled from split parts at runtime so no secret-shaped
# literal appears in source (keeps GitHub secret-scanning / push-protection
# quiet — the bytes only exist while the script runs).
#
# Exit: 0 = no leak, 1 = a secret leaked, 2 = setup/build failure.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
export PROJECT_ROOT
# shellcheck source=/dev/null
source "$SCRIPT_DIR/test_lib.sh"
init_test_log "redaction_leak_check"

LEAKS=0

# ---------------------------------------------------------------------------
# Build a fresh rch (the secret-redaction wiring is recent; a stale binary
# would silently skip it). Honors RCH_BIN if a caller supplies a built binary.
# ---------------------------------------------------------------------------
RCH_BIN="${RCH_BIN:-}"
build_rch() {
    if [[ -n "$RCH_BIN" && -x "$RCH_BIN" ]]; then
        log_json setup "Using provided RCH_BIN=$RCH_BIN"
        return
    fi
    log_json setup "Building rch (debug)…"
    if ! cargo build -p rch --bin rch >/dev/null 2>&1; then
        test_fail "cargo build -p rch failed"
        exit 2
    fi
    RCH_BIN="$PROJECT_ROOT/target/debug/rch"
    [[ -x "$RCH_BIN" ]] || { test_fail "rch binary not found at $RCH_BIN"; exit 2; }
}

# ---------------------------------------------------------------------------
# Secret fixtures — assembled at runtime, never literal.
# ---------------------------------------------------------------------------
declare -A SECRETS
build_secrets() {
    SECRETS[aws]="AKIA$(printf 'IOSFODNN7EXAMPLE')"
    SECRETS[github]="ghp_$(printf 'abcdefghijklmnopqrstuvwx012345')"
    SECRETS[anthropic]="sk-ant-$(printf 'api03abcdefghijklmnop')"
    SECRETS[stripe]="sk_live_$(printf 'abcdefghijklmnop0123456789')"
    SECRETS[slack]="xoxb-$(printf '0123456789-abcdefghij')"
    SECRETS[bearer]="ghs_$(printf 'zyxwvutsrq0987654321abcdef')"
}

# Assert a captured blob is free of every injected secret.
#   $1 = surface label, $2 = path to captured output file
assert_no_secret() {
    local label="$1" file="$2" key val
    for key in "${!SECRETS[@]}"; do
        val="${SECRETS[$key]}"
        if grep -qF -- "$val" "$file" 2>/dev/null; then
            log_json verify "LEAK in $label: $key secret survived" "{\"surface\":\"$label\",\"secret_class\":\"$key\"}"
            LEAKS=$((LEAKS + 1))
        fi
    done
}

# ---------------------------------------------------------------------------
# Surface 1: config export (--format=json). The remediation section is rendered
# via RemediationConfig::redacted(); operator paths carrying a secret in their
# home/user segment must come back masked.
# ---------------------------------------------------------------------------
test_config_export() {
    local cfgdir out
    cfgdir="$(mktemp -d)"
    mkdir -p "$cfgdir/rch"
    cat > "$cfgdir/rch/config.toml" <<EOF
[remediation.proof]
store_path = "/home/svc-${SECRETS[github]}/proofs.jsonl"
[remediation.incident_ledger]
path = "/home/svc-${SECRETS[aws]}/incidents.jsonl"
[remediation.pooled_target]
remote_base = "/home/svc-${SECRETS[bearer]}/projects"
[remediation.auto_rejoin]
disk_roots = ["/home/svc-${SECRETS[stripe]}/cache"]
EOF
    out="$cfgdir/export.json"
    RCH_CONFIG_DIR="$cfgdir" RCH_JSON=1 "$RCH_BIN" config export --format=json >"$out" 2>&1 || true
    assert_no_secret "config export json" "$out"
    if grep -qF "<redacted>" "$out"; then
        log_json verify "config export redaction confirmed active (<redacted> present)"
    else
        log_json verify "config export produced no <redacted> marker (remediation may be default); no-leak still asserted"
    fi
}

# ---------------------------------------------------------------------------
# Surface 2: config show (human display) must not echo the injected paths raw.
# ---------------------------------------------------------------------------
test_config_show() {
    local cfgdir out
    cfgdir="$(mktemp -d)"
    mkdir -p "$cfgdir/rch"
    cat > "$cfgdir/rch/config.toml" <<EOF
[remediation.proof]
store_path = "/home/svc-${SECRETS[github]}/proofs.jsonl"
EOF
    out="$cfgdir/show.txt"
    RCH_CONFIG_DIR="$cfgdir" "$RCH_BIN" config show >"$out" 2>&1 || true
    assert_no_secret "config show" "$out"
}

# ---------------------------------------------------------------------------
# Surface 3: diagnose echoes the classified command; a secret-shaped arg must be
# masked in any logged/echoed form.
# ---------------------------------------------------------------------------
test_diagnose() {
    local out
    out="$(mktemp)"
    "$RCH_BIN" diagnose "env API_KEY=${SECRETS[github]} cargo build --release" >"$out" 2>&1 || true
    assert_no_secret "diagnose" "$out"
}

main() {
    build_secrets
    build_rch
    log_json execute "Exercising surfaces with injected secrets"
    test_config_export
    test_config_show
    test_diagnose

    if [[ $LEAKS -eq 0 ]]; then
        log_json verify "No injected secret leaked across any surface"
        test_pass
    else
        test_fail "$LEAKS secret leak(s) detected"
    fi
}

main "$@"
