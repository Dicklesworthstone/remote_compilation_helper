# Linux process-group identity shared by launch, timeout cleanup, and recovery.
# A PID is not durable authority: bind it to the worker boot and leader start.
set -f

rch_valid_pgid() {
    case "$1" in ''|*[!0-9]*|0*|1) return 1;; esac
    [ "${#1}" -le 10 ] && [ "$1" -le 2147483647 ]
}

rch_valid_boot() {
    case "$1" in *[!0-9a-f-]*) return 1;; esac
    case "$1" in ????????-????-????-????-????????????) return 0;; esac
    return 1
}

# Read a member of the bound group, including comm with spaces or parentheses.
# Function positional arguments do not replace the launcher's command arguments.
rch_read_process() {
    rch_valid_pgid "$1" || return 1
    rch_proc_pid=$1
    rch_observed_boot=$(cat /proc/sys/kernel/random/boot_id 2>/dev/null) || return 1
    rch_valid_boot "$rch_observed_boot" || return 1
    rch_stat=$(cat "/proc/$rch_proc_pid/stat" 2>/dev/null) || return 1
    case "$rch_stat" in "$rch_proc_pid ("*") "*) ;; *) return 1;; esac
    rch_stat=${rch_stat##*) }
    set -- $rch_stat
    [ "$#" -ge 20 ] && [ "$3" = "$rch_pgid" ] || return 1
    case "$1" in Z|X) return 1;; esac
    shift 19
    rch_observed_start=$1
    case "$rch_observed_start" in ''|*[!0-9]*|0*) return 1;; esac
    [ "${#rch_observed_start}" -le 20 ]
}

rch_read_leader() {
    rch_read_process "$rch_pgid"
}

rch_remote_leader_matches() {
    rch_read_leader || return 1
    [ "$rch_observed_boot" = "$rch_boot" ] && [ "$rch_observed_start" = "$rch_start" ]
}

# Publish before starting any workload. A complete record appears in one rename.
# The caller must already be the session/process-group leader created by setsid.
rch_remote_record() {
    rch_pgid=$$
    rch_valid_pgid "$rch_pgid" && rch_read_leader || return 1
    rch_boot=$rch_observed_boot
    rch_start=$rch_observed_start
    rch_record_tmp="$1.$rch_pgid"
    (umask 077; set -C; printf 'RCH_REMOTE_PROCESS_V1:%s:%s:%s:%s\n' \
        "$2" "$rch_boot" "$rch_pgid" "$rch_start" > "$rch_record_tmp") || return 1
    mv -f "$rch_record_tmp" "$1"
}

rch_read_record() {
    case "$1" in /*) ;; *) return 42;; esac
    [ -f "$1" ] && [ ! -L "$1" ] && [ -r "$1" ] || return 42
    rch_record=$(cat "$1" 2>/dev/null) || return 42
    rch_identified=0
    case "$rch_record" in
        RCH_REMOTE_PROCESS_V1:*)
            rch_fields=${rch_record#RCH_REMOTE_PROCESS_V1:}
            rch_record_build=${rch_fields%%:*}
            [ "$rch_record_build" = "$2" ] || return 43
            rch_fields=${rch_fields#*:}
            rch_boot=${rch_fields%%:*}
            rch_fields=${rch_fields#*:}
            rch_pgid=${rch_fields%%:*}
            rch_start=${rch_fields#*:}
            rch_valid_boot "$rch_boot" || return 42
            case "$rch_start" in ''|*[!0-9]*|0*) return 42;; esac
            [ "${#rch_start}" -le 20 ] || return 42
            [ "$rch_record" = "RCH_REMOTE_PROCESS_V1:$2:$rch_boot:$rch_pgid:$rch_start" ] || return 42
            # Command substitution strips trailing newlines (and some shells
            # discard NULs). Require the original bytes to be one complete line.
            rch_record_bytes=$(LC_ALL=C wc -c < "$1") || return 42
            rch_record_lines=$(LC_ALL=C wc -l < "$1") || return 42
            [ "$rch_record_bytes" -eq "$((${#rch_record} + 1))" ] && \
                [ "$rch_record_lines" -eq 1 ] || return 42
            rch_identified=1
            ;;
        *) rch_pgid=$rch_record;;
    esac
    rch_valid_pgid "$rch_pgid" || return 42
}

# 0: no executing members; 1: live members; 2: observation unavailable.
# kill -0 cannot distinguish ESRCH from EPERM, or live processes from zombies.
rch_group_state() {
    rch_snapshot=$(LC_ALL=C ps -e -o pid= -o pgid= -o stat=) || return 2
    printf '%s\n' "$rch_snapshot" | LC_ALL=C awk -v group="$rch_pgid" -v observer="$$" '
        NF != 3 || $1 !~ /^[0-9]+$/ || $2 !~ /^[0-9]+$/ || $3 !~ /^[A-Za-z][A-Za-z0-9+<>-]*$/ { bad = 1; next }
        $1 == observer { seen = 1; if ($2 == group) bad = 1 }
        $2 == group && $3 !~ /^[ZX]/ { live = 1 }
        END { if (bad || !seen) exit 2; if (live) exit 1; exit 0 }
    '
}

# Return 43 for unknown/reused identity, including a live orphan group whose
# leader has exited. Never signal it based solely on a historical group number.
rch_signal_group() {
    [ "$rch_identified" -eq 1 ] && rch_remote_leader_matches || return 43
    # Revalidate immediately before EACH signal. dash requires no `--` here.
    kill -"$1" -"$rch_pgid" 2>/dev/null || :
}

rch_remote_cancel() {
    rch_read_record "$1" "$2" || return $?
    rch_mode=$3
    rch_group_state
    case $? in 0) return 0;; 1) ;; *) return 44;; esac
    if [ "$rch_mode" = term ]; then
        rch_signal_group TERM || return $?
        sleep 1 || return 44
        rch_group_state
        case $? in 0) return 0;; 1) ;; *) return 44;; esac
    fi
    rch_signal_group KILL || return $?
    rch_attempt=0
    while [ "$rch_attempt" -lt 20 ]; do
        rch_group_state
        case $? in 0) return 0;; 1) ;; *) return 44;; esac
        rch_attempt=$((rch_attempt + 1))
        sleep 0.1 || return 44
    done
    return 45
}
