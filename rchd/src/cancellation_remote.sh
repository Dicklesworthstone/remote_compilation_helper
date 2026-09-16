pgid_file=$1
build_id=$2
# Missing identity is not proof of absence, and must never trigger broad pkill.
case "$pgid_file" in /*) ;; *) exit 42;; esac
[ -f "$pgid_file" ] && [ ! -L "$pgid_file" ] && [ -r "$pgid_file" ] || exit 42
pgid=$(cat "$pgid_file" 2>/dev/null) || exit 42
# Never reinterpret 0, 1, negative, malformed, or overflowing IDs as signals.
case "$pgid" in ''|*[!0-9]*|0*|1) exit 42;; esac
[ "${#pgid}" -le 10 ] && [ "$pgid" -le 2147483647 ] || exit 42

# Exit 0: no executing members; 1: live members; 2: observation unavailable.
# kill -0 alone cannot distinguish ESRCH from EPERM. A successful, validated
# process-table snapshot also sees surviving children after the leader exits.
group_state() {
    snapshot=$(LC_ALL=C ps -e -o pid= -o pgid= -o stat=) || return 2
    printf '%s\n' "$snapshot" | LC_ALL=C awk -v group="$pgid" -v observer="$$" '
        NF != 3 || $1 !~ /^[0-9]+$/ || $2 !~ /^[0-9]+$/ || $3 !~ /^[A-Za-z][A-Za-z0-9+<>-]*$/ { bad = 1; next }
        $1 == observer { seen = 1; if ($2 == group) bad = 1 }
        $2 == group && $3 !~ /^[ZX]/ { live = 1 }
        END { if (bad || !seen) exit 2; if (live) exit 1; exit 0 }
    '
}
confirm_or_continue() {
    group_state
    case $? in
        0) printf 'RCH_REMOTE_CANCELLED_V1:%s\n' "$build_id"; exit 0;;
        1) return 0;;
        *) exit 44;;
    esac
}

# Idempotent retries can confirm an already-exited group without signalling.
confirm_or_continue
# Do not fall back to the positive PID: that could leave group members running.
kill -TERM -"$pgid" 2>/dev/null || :
sleep 1 || exit 44
confirm_or_continue
kill -KILL -"$pgid" 2>/dev/null || :
attempt=0
while [ "$attempt" -lt 20 ]; do
    confirm_or_continue
    attempt=$((attempt + 1))
    sleep 0.1 || exit 44
done
# Successful signal delivery is not a successful cancellation.
exit 45
