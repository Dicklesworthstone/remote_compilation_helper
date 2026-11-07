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
rch_admission_clock='
import math
import os
import re
import sys
import time

MAX_BUDGET_NS = 600 * 1000000000
MAX_CLOCK_NS = (1 << 63) - 1

def number(text):
    if len(text) > 20 or re.fullmatch(r"[0-9]+", text) is None:
        raise ValueError("invalid clock argument")
    return int(text)

try:
    if len(sys.argv) != 3:
        raise ValueError("invalid clock invocation")
    operation, value = sys.argv[1], number(sys.argv[2])
    if operation == "budget":
        if not 1 <= value <= 60:
            raise ValueError("invalid retry window")
        text = os.environ.get("RCH_TIMING_SCALE", "1")
        if (len(text) > 128 or re.fullmatch(
                r"[+-]?(?:[0-9]+(?:\.[0-9]*)?|\.[0-9]+)(?:[eE][+-]?[0-9]+)?",
                text) is None):
            raise ValueError("invalid transported scale")
        scale = float(text)
        if not math.isfinite(scale) or not 1.0 <= scale <= 10.0:
            raise ValueError("invalid transported scale")
        budget = math.ceil(value * scale * 1000000000)
        if not 0 < budget <= MAX_BUDGET_NS:
            raise ValueError("invalid scaled window")
        print(budget)
    elif operation == "start":
        now = time.monotonic_ns()
        if not 0 < value <= MAX_BUDGET_NS or not 0 <= now <= MAX_CLOCK_NS - value:
            raise ValueError("invalid absolute deadline")
        print(now + value)
    elif operation in ("check", "wait"):
        now = time.monotonic_ns()
        if not 0 < value <= MAX_CLOCK_NS or value - now > MAX_BUDGET_NS:
            raise ValueError("invalid absolute deadline")
        if now >= value:
            sys.exit(75)
        if operation == "wait":
            # Preserve the ordinary retry cadence, including at scale ten.
            time.sleep(min(1.0, (value - now) / 1000000000))
        sys.exit(0 if time.monotonic_ns() < value else 75)
    else:
        raise ValueError("invalid clock operation")
except (OSError, OverflowError, ValueError):
    print("RCH_SOURCE_ADMISSION_CLOCK_UNAVAILABLE", file=sys.stderr)
    sys.exit(73)
'
rch_admission_budget=$(python3 -I -S -c "$rch_admission_clock" budget \
    "${rch_admission_retry_seconds-}" </dev/null) || exit 73
rch_admission_deadline=
rch_admission_require_time() {
    set +e
    python3 -I -S -c "$rch_admission_clock" "$1" "$rch_admission_deadline" </dev/null
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
        rch_admission_deadline=$(python3 -I -S -c "$rch_admission_clock" start \
            "$rch_admission_budget" </dev/null) || exit 73
    fi
    rch_admission_require_time wait 75
done
