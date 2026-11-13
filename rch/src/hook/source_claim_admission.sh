# rch_source_attempt runs in a fresh subshell for EACH attempt. Its caller
# supplies the complete acquisition program, including fresh claim/lock input.
# The parent must own no source, activity, or metadata lock descriptors. Waiting
# inside an already-locked terminal would prevent recovery from retiring the
# previous owner. No caller command is part of this admission-only retry loop.
set -eu
# The caller supplies an unscaled retry window, not an attempt count. Namespace
# setup uses five seconds, preserving the five one-second waits in its former
# six-attempt policy. Operation cost now consumes the elapsed window.
# Validate and snapshot the one transported policy before any attempt. Starting
# the window only after the first validated conflict preserves a slow first
# operation which succeeds within its enclosing control deadline.
# These clock helpers own no execution authority. The enclosing controller
# still bounds each attempt and must settle its group before publishing output.
# The caller composes WKR_LOCATE_SHELL before this program. Resolve and verify
# the deployed native protocol before the first source transaction can mutate.
rch_wkr_locate || {
    printf '%s\n' 'RCH_SOURCE_ADMISSION_CLOCK_UNAVAILABLE rch-wkr is required' >&2
    exit 73
}
rch_admission_worker=$RCH_WKR
rch_admission_probe=$("$rch_admission_worker" source-admission probe </dev/null) || {
    printf '%s\n' 'RCH_SOURCE_ADMISSION_CLOCK_UNAVAILABLE upgrade rch-wkr' >&2
    exit 73
}
[ "$rch_admission_probe" = 'rch-wkr source-admission v1' ] || {
    printf '%s\n' 'RCH_SOURCE_ADMISSION_CLOCK_UNAVAILABLE unsupported rch-wkr' >&2
    exit 73
}
rch_admission_budget=$("$rch_admission_worker" source-admission budget \
    "${rch_admission_retry_seconds-}" </dev/null) || exit 73
rch_admission_deadline=
rch_admission_require_time() {
    set +e
    "$rch_admission_worker" source-admission "$1" "$rch_admission_deadline" </dev/null
    rch_admission_clock_status=$?
    set -e
    case "$rch_admission_clock_status" in
        0) ;;
        75)
            if [ "$2" = 73 ]; then
                # A successful attempt may already have mutated durable state.
                # Expiry cannot turn that result into retryable pre-grant busy.
                printf '%s\n' 'RCH_SOURCE_ADMISSION_UNCONFIRMED cause=deadline-after-success' >&2
            fi
            exit "$2" ;;
        *) exit 73 ;;
    esac
}
while :; do
    if [ -n "$rch_admission_deadline" ]; then
        rch_admission_require_time check 75
    fi
    # Do NOT call the function in an if/|| condition: POSIX shells then ignore
    # errexit even inside its subshell, bypassing failed registry setup guards.
    # Only the parent disables errexit to collect the result; each attempt's
    # fresh subshell starts with set -eu and stops on the first failed guard.
    set +e
    rch_source_attempt
    rch_admission_result=$?
    set -e
    case "$rch_admission_result" in
        0)
            if [ -n "$rch_admission_deadline" ]; then
                rch_admission_require_time check 73
            fi
            exit 0 ;;
        # Only a validated pre-grant ownership conflict is retryable. Unknown
        # ownership, corruption, cancellation and a failed release are terminal.
        75) ;;
        *) exit "$rch_admission_result" ;;
    esac
    if [ -z "$rch_admission_deadline" ]; then
        rch_admission_deadline=$("$rch_admission_worker" source-admission start \
            "$rch_admission_budget" </dev/null) || exit 73
    fi
    rch_admission_require_time wait 75
done
