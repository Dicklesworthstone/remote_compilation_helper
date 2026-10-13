# rch_source_attempt runs in a fresh subshell for EACH attempt. Its caller
# supplies the complete acquisition program, including fresh claim/lock input.
# The parent must own no source, activity, or metadata lock descriptors. Waiting
# inside an already-locked terminal would prevent recovery from retiring the
# previous owner. No caller command is part of this admission-only retry loop.
set -eu
case "$rch_admission_attempts" in ''|*[!0-9]*) exit 73 ;; esac
[ "$rch_admission_attempts" -gt 0 ] && [ "$rch_admission_attempts" -le 60 ] || exit 73
remaining=$rch_admission_attempts
while :; do
    # Do NOT call the function in an if/|| condition: POSIX shells then ignore
    # errexit even inside its subshell, bypassing failed registry setup guards.
    # Only the parent disables errexit to collect the result; each attempt's
    # fresh subshell starts with set -eu and stops on the first failed guard.
    set +e
    rch_source_attempt
    result=$?
    set -e
    [ "$result" -ne 0 ] || exit 0
    # 75 is reserved for a validated pre-grant ownership conflict. Unknown
    # ownership, corruption, cancellation and a failed release are terminal.
    [ "$result" -eq 75 ] || exit "$result"
    remaining=$((remaining - 1))
    [ "$remaining" -gt 0 ] || exit 75
    sleep 1 || exit 73
done
