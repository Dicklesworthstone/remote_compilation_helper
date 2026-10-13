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

# /proc can belong to an ancestor PID namespace while kill uses ours. Never
# interpret that foreign view as ownership, or as proof that a group is empty.
# NSpid lists IDs from procfs's namespace through our active namespace. Require
# exactly our own ID: equality with just the first ID can occur by coincidence.
# Use builtin read so /proc/self describes this shell, not a spawned reader.
# Missing namespace evidence (including older kernels) fails closed.
rch_check_procfs_namespace() {
    while IFS= read -r rch_status_line; do
        case "$rch_status_line" in
            NSpid:*)
                set -- ${rch_status_line#NSpid:}
                [ "$#" -eq 1 ] && [ "$1" = "$$" ]
                return $?;;
        esac
    done < /proc/self/status 2>/dev/null
    return 1
}

# Read a member of the bound group, including comm with spaces or parentheses.
# Function positional arguments do not replace the launcher's command arguments.
rch_read_process() {
    rch_valid_pgid "$1" && rch_check_procfs_namespace || return 1
    rch_proc_pid=$1
    rch_observed_boot=$(cat /proc/sys/kernel/random/boot_id 2>/dev/null) || return 1
    rch_valid_boot "$rch_observed_boot" || return 1
    rch_stat=$(cat "/proc/$rch_proc_pid/stat" 2>/dev/null) || return 1
    case "$rch_stat" in "$rch_proc_pid ("*") "*) ;; *) return 1;; esac
    rch_stat=${rch_stat##*) }
    set -- $rch_stat
    [ "$#" -ge 20 ] && [ "$3" = "$rch_pgid" ] || return 1
    # Keep the same conservative state grammar as process_identity.rs. An
    # unknown future state is not authority to signal a process group.
    case "$1" in R|S|D|T|t|K|W|P|I) ;; *) return 1;; esac
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
    rch_check_procfs_namespace || return 2
    rch_snapshot=$(LC_ALL=C ps -e -o pid= -o pgid= -o stat=) || return 2
    printf '%s\n' "$rch_snapshot" | LC_ALL=C awk -v group="$rch_pgid" -v observer="$$" '
        NF != 3 || $1 !~ /^[0-9]+$/ || $2 !~ /^[0-9]+$/ || $3 !~ /^[RSDTtKWPIXZx][A-Za-z0-9+<>-]*$/ { bad = 1; next }
        $1 == observer { seen = 1; if ($2 == group) bad = 1 }
        $2 == group && $3 !~ /^[ZXx]/ { live = 1 }
        END { if (bad || !seen) exit 2; if (live) exit 1; exit 0 }
    '
}

# Capture live members while the recorded leader still authenticates the group.
# TERM can kill that leader before a child that ignores TERM. A surviving
# member's birth identity lets THIS cancellation finish escalation without
# treating a historical PGID as authority. These witnesses are never persisted.
rch_capture_group_witnesses() {
    rch_witnesses=
    rch_witness_identity=
    [ "$rch_identified" -eq 1 ] && rch_remote_leader_matches || return 43
    # rch_group_state already validated this snapshot, including our observer.
    rch_member_pids=$(printf '%s\n' "$rch_snapshot" | LC_ALL=C awk -v group="$rch_pgid" '
        $2 == group && $3 !~ /^[ZXx]/ { print $1 }
    ') || return 44
    for rch_member_pid in $rch_member_pids; do
        if rch_read_process "$rch_member_pid" && [ "$rch_observed_boot" = "$rch_boot" ]; then
            rch_witnesses="$rch_witnesses $rch_member_pid:$rch_observed_start"
        fi
    done
    # Do not transfer authority across a leader exit/reuse during collection.
    rch_remote_leader_matches || { rch_witnesses=; return 43; }
    rch_witness_identity="$rch_boot:$rch_pgid:$rch_start"
}

rch_remote_witness_matches() {
    [ "${rch_witness_identity:-}" = "$rch_boot:$rch_pgid:$rch_start" ] || return 1
    for rch_witness in $rch_witnesses; do
        rch_witness_pid=${rch_witness%%:*}
        rch_witness_start=${rch_witness#*:}
        # rch_read_process also checks current group membership and liveness.
        if rch_read_process "$rch_witness_pid" &&
            [ "$rch_observed_boot" = "$rch_boot" ] &&
            [ "$rch_observed_start" = "$rch_witness_start" ]; then
            return 0
        fi
    done
    return 1
}

# Return 43 for unknown/reused identity. A pre-existing orphan is never adopted;
# only an authenticated TERM in this call can authorize witnessed escalation.
rch_signal_group() {
    [ "$rch_identified" -eq 1 ] || return 43
    if ! rch_remote_leader_matches; then
        [ "$1" = KILL ] && [ "${rch_term_sent:-0}" -eq 1 ] &&
            rch_remote_witness_matches || return 43
    fi
    # Revalidate immediately before EACH signal. dash requires no `--` here.
    kill -"$1" -"$rch_pgid" 2>/dev/null || :
}

rch_remote_cancel() {
    # No authority may leak between calls, even when parsing the next record fails.
    rch_witnesses=
    rch_witness_identity=
    rch_term_sent=0
    rch_read_record "$1" "$2" || return $?
    rch_mode=$3
    rch_group_state
    case $? in 0) return 0;; 1) ;; *) return 44;; esac
    if [ "$rch_mode" = term ]; then
        rch_capture_group_witnesses || return $?
        rch_signal_group TERM || return $?
        rch_term_sent=1
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
