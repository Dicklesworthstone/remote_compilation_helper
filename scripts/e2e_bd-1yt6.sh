#!/usr/bin/env bash
#
# e2e_bd-1yt6.sh - Cancellation reliability sweep
#
# Covers:
# - cancellation state-machine branch behavior (in-flight, post-completion race, repeated cancel)
# - cancellation status surfacing and remediation hints
# - integration signals for network jitter, worker unreachability, partial transfer failure
#
# NOTE: CPU-intensive test commands are offloaded via `rch exec -- ...`.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
LOG_FILE="${PROJECT_ROOT}/target/e2e_bd-1yt6.jsonl"
TARGET_DIR="/tmp/rch-bd-1yt6-target"

timestamp() {
    date -u '+%Y-%m-%dT%H:%M:%S.%3NZ' 2>/dev/null || date -u '+%Y-%m-%dT%H:%M:%SZ'
}

log_json() {
    local phase="$1"
    local message="$2"
    local extra="${3:-{}}"
    local ts
    ts="$(timestamp)"
    printf '{"ts":"%s","test":"bd-1yt6","phase":"%s","message":"%s",%s}\n' \
        "$ts" "$phase" "$message" "${extra#\{}" | sed 's/,}$/}/' | tee -a "$LOG_FILE"
}

die() {
    log_json "error" "$*" '{"result":"fail"}'
    exit 1
}

require_cmd() {
    command -v "$1" >/dev/null 2>&1 || die "Missing dependency: $1"
}

run_case() {
    local case_id="$1"
    shift
    log_json "start" "$case_id"
    if "$@"; then
        log_json "pass" "$case_id" '{"result":"pass"}'
    else
        die "Case failed: ${case_id}"
    fi
}

main() {
    : > "$LOG_FILE"
    require_cmd rch
    require_cmd cargo

    mkdir -p "${PROJECT_ROOT}/target"
    log_json "setup" "Starting cancellation reliability E2E sweep" "{\"target_dir\":\"${TARGET_DIR}\"}"

    cd "$PROJECT_ROOT"

    # Unit/daemon integration slices for cancellation lifecycle and status surfaces.
    run_case "cancel_inflight_metadata" \
        rch exec -- env CARGO_TARGET_DIR="$TARGET_DIR" cargo test -p rchd test_cancel_inflight_build_records_metadata -- --nocapture
    run_case "cancel_post_completion_race" \
        rch exec -- env CARGO_TARGET_DIR="$TARGET_DIR" cargo test -p rchd test_cancel_after_completion_returns_error_post_completion_race -- --nocapture
    run_case "cancel_repeated_deterministic" \
        rch exec -- env CARGO_TARGET_DIR="$TARGET_DIR" cargo test -p rchd test_repeated_cancel_after_completion_is_deterministic -- --nocapture
    run_case "status_cancellation_issues" \
        rch exec -- env CARGO_TARGET_DIR="$TARGET_DIR" cargo test -p rchd test_handle_status_emits_cancellation_cleanup_issue -- --nocapture

    # Integration reliability scenarios: jitter/unreachable/partial transfer states.
    run_case "worker_network_jitter_reconnect" \
        rch exec -- env CARGO_TARGET_DIR="$TARGET_DIR" cargo test -p rchd --test e2e_worker test_worker_reconnect_after_network_blip -- --nocapture
    run_case "pipeline_partial_transfer" \
        rch exec -- env CARGO_TARGET_DIR="$TARGET_DIR" cargo test -p rchd --test e2e_pipeline test_interrupted_transfer -- --nocapture
    run_case "failopen_unreachable_transfer_failure" \
        rch exec -- env CARGO_TARGET_DIR="$TARGET_DIR" cargo test -p rch --features true-e2e --test true_e2e test_failopen_transfer_failure -- --nocapture

    log_json "summary" "All bd-1yt6 cancellation reliability checks passed" '{"result":"pass"}'
}

main "$@"
