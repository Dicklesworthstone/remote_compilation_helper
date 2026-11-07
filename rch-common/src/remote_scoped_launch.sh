# Owned supervisor: V1 covers the group; V2 also covers detached descendants.
# Completion requires proven cleanup. Keep comments compact: this source is
# quoted through four transport layers within the Linux argument-size limit.

# Preserve the open input description across dash asynchronous redirection.
# Borrow only a free FD; never reopen paths or overwrite inherited authority.
rch_scope_launch_fds() {
    __sl_open_fds=
    case "$(uname -s)" in
        Linux)
            rch_check_procfs_namespace || return 1
            __sl_fd_dir=/proc/$rch_self_pid/fd
            [ -r "$__sl_fd_dir" ] && [ -x "$__sl_fd_dir" ] || return 1
            for __sl_fd in 0 2 4 5 6 7 8 9; do
                if [ -e "$__sl_fd_dir/$__sl_fd" ] || [ -L "$__sl_fd_dir/$__sl_fd" ]; then
                    __sl_open_fds="$__sl_open_fds $__sl_fd"
                fi
            done;;
        Darwin)
            # No substitution: its pipe would change the FD set. Encode input,
            # stderr and a free slot in status 64..94, outside startup failures.
            __sl_fd_probe=0
            python3 -I -S -c '
import errno, os, sys
def opened(fd):
    try:
        os.fstat(fd)
        return True
    except OSError as error:
        if error.errno != errno.EBADF:
            raise
        return False
state = 64 + 8 * opened(0) + 16 * opened(2)
for fd in range(4, 10):
    if not opened(fd):
        state += fd - 3
        break
sys.exit(state)
' || __sl_fd_probe=$?
            [ "$__sl_fd_probe" -ge 64 ] && [ "$__sl_fd_probe" -le 94 ] || return 1
            __sl_free_fd=$((__sl_fd_probe & 7))
            [ "$__sl_free_fd" -le 6 ] || return 1
            [ "$((__sl_fd_probe & 8))" = 0 ] || __sl_open_fds=0
            [ "$((__sl_fd_probe & 16))" = 0 ] || __sl_open_fds="$__sl_open_fds 2"
            # Conservatively reserve all other slots; only one is borrowed.
            for __sl_fd in 4 5 6 7 8 9; do
                [ "$__sl_fd" = "$((__sl_free_fd + 3))" ] || __sl_open_fds="$__sl_open_fds $__sl_fd"
            done;;
        *) return 1;;
    esac
}

rch_scope_launch_fd_open() {
    case " $__sl_open_fds " in *" $1 "*) return 0;; esac
    return 1
}

rch_scope_launch_save_input() {
    __sl_input= __sl_input_redirect=
    rch_scope_launch_fds || return 1
    if ! rch_scope_launch_fd_open 0; then
        __sl_input_redirect='0<&-'
        return 0
    fi
    for __sl_input_candidate in 4 5 6 7 8 9; do
        if ! rch_scope_launch_fd_open "$__sl_input_candidate"; then
            __sl_input=$__sl_input_candidate
            # Only this validated single digit enters eval as program text.
            eval "exec $__sl_input<&0" || return 1
            __sl_input_redirect="0<&$__sl_input $__sl_input<&-"
            return 0
        fi
    done
    return 1
}

rch_scope_launch_close_input() {
    case "$__sl_input" in
        [4-9]) eval "exec $__sl_input<&-" || return 1;;
        '') return 0;;
        *) return 1;;
    esac
    __sl_input=
}

# Snapshot policy once; changes must not downgrade a requested scope to V1.
rch_scope_launch_select() {
    rch_launch_nice= rch_launch_slice= rch_launch_manager=user
    rch_policy_select_file || return 125
    if [ -n "$rch_policy_file" ]; then
        rch_policy_read_file "$rch_policy_file" "$rch_policy_owner" || return 125
        rch_launch_nice=$rch_policy_nice
        rch_launch_slice=$rch_policy_slice
        rch_launch_manager=$rch_policy_manager
    fi
    rch_apply_configured_worker_policy() {
        rch_policy_nice=$rch_launch_nice
        rch_policy_slice=$rch_launch_slice
        rch_policy_manager=$rch_launch_manager
        [ -n "$rch_policy_nice$rch_policy_slice" ] || return 0
        rch_policy_enforce
    }
}

# Cheap liveness of a direct child or the captured supervisor. The namespace is
# fenced once before launch. Birth identity is rechecked before EVERY signal.
# 0: live, 1: absent/dead, 2: unavailable. No kill -0 == dead inference.
rch_scope_launch_process() {
    rch_launch_group= rch_launch_birth=
    rch_valid_pgid "$1" || return 2
    if [ "$(uname -s)" = Darwin ]; then
        if ! rch_darwin_process "$1"; then
            # Only independent ESRCH proves this process absent after libproc
            # failure. This never proves group absence or authorizes signals.
            rch_observation_budget
            rch_launch_absence=$(rch_control_capture "${rch_observation_seconds}s" python3 -I -S -c '
import errno, os, sys
try:
    os.getpgid(int(sys.argv[1]))
except OSError as error:
    if error.errno == errno.ESRCH:
        print("RCH_PROCESS_ABSENT_V1:" + sys.argv[1])
        sys.exit(0)
    raise
sys.exit(1)
' "$1") || return 2
            [ "$rch_launch_absence" = "RCH_PROCESS_ABSENT_V1:$1" ] && return 1
            return 2
        fi
        rch_launch_group=$rch_observed_pgid
        rch_launch_birth=$rch_observed_start
        return 0
    fi
    [ -d "/proc/$1" ] || return 1
    IFS= read -r rch_launch_stat < "/proc/$1/stat" 2>/dev/null || return 2
    case "$rch_launch_stat" in "$1 ("*") "*) ;; *) return 2;; esac
    rch_launch_stat=${rch_launch_stat##*) }
    set -- $rch_launch_stat
    [ "$#" -ge 20 ] || return 2
    case "$1" in Z|X|x) return 1;; R|S|D|T|t|K|W|P|I) ;; *) return 2;; esac
    rch_launch_group=$3
    shift 19
    rch_launch_birth=$1
    rch_scope_uint "$rch_launch_birth" && [ "$rch_launch_birth" != 0 ] || return 2
}

# Linux uptime is monotonic, including suspend. Keep its hundredths so a cap
# does not expire early because its starting fractional second was discarded.
rch_scope_launch_clock() {
    if [ "$(uname -s)" = Darwin ]; then
        # Darwin continuous time includes suspend; Python monotonic does not.
        rch_observation_budget
        rch_launch_now=$(rch_control_capture "${rch_observation_seconds}s" python3 -I -S -c \
            'import time; print(time.clock_gettime_ns(time.CLOCK_MONOTONIC_RAW) // 10000000)') || return 1
        rch_scope_uint "$rch_launch_now" && [ "${#rch_launch_now}" -le 15 ]
        return $?
    fi
    read -r rch_launch_uptime rch_launch_idle < /proc/uptime || return 1
    case "$rch_launch_uptime" in *.*) ;; *) return 1;; esac
    rch_launch_secs=${rch_launch_uptime%%.*}
    rch_launch_frac=${rch_launch_uptime#*.}
    rch_scope_uint "$rch_launch_secs" && [ "${#rch_launch_secs}" -le 12 ] || return 1
    case "$rch_launch_frac" in [0-9][0-9]) ;; *) return 1;; esac
    rch_launch_now=$((rch_launch_secs * 100 + 1$rch_launch_frac - 100))
}

rch_scope_launch_parent_alive() {
    rch_scope_launch_process "$__sl_parent" && [ "$rch_launch_birth" = "$__sl_parent_start" ]
}

# Bound marker delivery. Map fd 3 before Python closes nonstandard descriptors.
rch_scope_launch_deadline_marker() {
    rch_timing_budget 1
    rch_group_timeout --signal=KILL "${rch_timing_scaled}s" /bin/sh -c 'printf "\n%s\n" "$1"' rch-deadline "$1" \
        >&3 2>/dev/null </dev/null
}

# Bound diagnostics without changing receipt, claim, status or cleanup verdict.
rch_scope_launch_message() (
    rch_timing_budget 1
    rch_group_timeout --signal=KILL "${rch_timing_scaled}s" /bin/sh -c '
        case "$2" in
            line) printf "%s\n" "$1";;
            setup) printf "\n%s_IDENTITY_UNAVAILABLE\n" "$1";;
            *) exit 125;;
        esac
    ' rch-launch-message "$1" "${2:-line}" </dev/null
) 2>/dev/null

# Policy selects the required authority class. Never accept a V1 downgrade of
# a requested scope, or silently assume that an ordinary group has V2 rights.
rch_scope_launch_binding_matches() {
    if [ -n "$rch_launch_slice" ]; then
        [ "$rch_scope_bound" = 1 ]
    else
        [ "$rch_scope_bound" = 0 ]
    fi
}

# In-session watchdog membership pins its own group even after leader death.
# Historical receipts still need outside birth-fenced cancellation and census.
rch_scope_launch_kill_self() {
    if [ "$rch_scope_bound" = 1 ]; then
        rch_scope_operation kill
    elif [ "$(uname -s)" = Darwin ]; then
        # Kernel membership grants this in-session authority, never a receipt.
        rch_valid_pgid "$rch_pgid" || return 1
        python3 -I -S -c '
import os, signal, sys
group = os.getpgrp()
if group <= 1 or group != int(sys.argv[1]):
    sys.exit(1)
os.killpg(group, signal.SIGKILL)
' "$rch_pgid"
    else
        rch_check_procfs_namespace && rch_read_process "$rch_self_pid" &&
            [ "$rch_observed_boot" = "$rch_boot" ] || return 1
        kill -KILL -"$rch_pgid"
    fi
}

# Called in a new setsid shell. No payload is allowed until the outside
# supervisor validates the selected record class and opens the private gate.
rch_scope_launch_child() {
    __sl_record=$1; __sl_control=$2; __sl_marker=$3; __sl_build=$4
    __sl_parent=$5; __sl_parent_start=$6; __sl_limit=$7
    rch_launch_nice=$8; rch_launch_slice=$9; shift 9
    rch_launch_manager=$1; shift
    [ -z "$rch_launch_nice" ] || rch_policy_valid_nice "$rch_launch_nice" || exit 125
    [ -z "$rch_launch_slice" ] || rch_policy_valid_slice "$rch_launch_slice" || exit 125
    case "$rch_launch_manager" in user|system) ;; *) exit 125;; esac
    rch_apply_configured_worker_policy() {
        rch_policy_nice=$rch_launch_nice
        rch_policy_slice=$rch_launch_slice
        rch_policy_manager=$rch_launch_manager
        [ -n "$rch_policy_nice$rch_policy_slice" ] || return 0
        rch_policy_enforce
    }
    rch_observation_clock_checked || exit 125
    rch_timing_budget 6000
    rch_observation_deadline=$((rch_observation_now + rch_timing_scaled))
    rch_remote_record "$__sl_record" "$__sl_build" || exit 125
    rch_scope_launch_binding_matches || exit 125
    unset rch_observation_deadline rch_observation_last_clock
    __sl_cancelled=0
    trap '__sl_cancelled=1' HUP INT TERM
    while [ ! -f "$__sl_control/go" ]; do
        if [ "$__sl_cancelled" = 1 ] || ! rch_scope_launch_parent_alive; then
            rch_scope_launch_kill_self
            exit 255
        fi
        sleep 0.1 || exit 255
    done
    rch_scope_launch_clock || exit 255
    __sl_started=$rch_launch_now
    # Watchdog survives supervisor loss and remains armed after payload exit
    # until proven cleanup. Only V2 covers detached descendants.
    (
        trap '' HUP INT TERM
        while :; do
            # This member must stop its pinned group after leader loss, even
            # with a live supervisor and no configured build deadline.
            if ! rch_scope_launch_parent_alive || ! rch_remote_leader_matches; then
                rch_scope_launch_kill_self
                exit 255
            fi
            if ! rch_scope_launch_clock; then
                rch_scope_launch_kill_self
                exit 255
            fi
            if [ "$__sl_limit" -gt 0 ] && [ "$((rch_launch_now - __sl_started))" -ge "$((__sl_limit * 100))" ]; then
                (umask 077; set -C; printf '%s\n' deadline > "$__sl_control/deadline") || :
                rch_scope_launch_deadline_marker "$__sl_marker"
                rch_scope_launch_kill_self
                exit 255
            fi
            sleep 0.2 3>&- || exit 255
        done
    ) >/dev/null 2>&1 </dev/null &
    # Watchdog must not inherit borrowed input. Post-admission failure is
    # uncertain execution, never a pre-workload refusal permitting fallback.
    rch_scope_launch_save_input || { rch_scope_launch_kill_self; exit 255; }
    eval '"$@" 3>&- '"$__sl_input_redirect"' &'
    __sl_payload=$!
    rch_scope_launch_close_input
    wait "$__sl_payload"; __sl_status=$?
    [ "$__sl_cancelled" != 1 ] || __sl_status=143
    # Payload status is NOT completion: the parent must prove tree cleanup.
    (umask 077; set -C; printf 'RCH_SCOPED_RESULT_V1:%s:%s:%s:%s\n' \
        "$__sl_build" "$rch_pgid" "$rch_start" "$__sl_status" > "$__sl_control/result.tmp") &&
        mv "$__sl_control/result.tmp" "$__sl_control/result" || exit 255
    while :; do sleep 1 3>&- || exit 255; done
}

rch_scope_launch_read_result() {
    [ -f "$__sl_control/result" ] && [ ! -L "$__sl_control/result" ] || return 1
    # Balance case-pattern parentheses for Darwin's bash 3.2 substitution parser.
    __sl_result_metadata=$(
        case "$(uname -s)" in
            (Darwin) stat -f '%u:%Lp:%l:%z' "$__sl_control/result";;
            (Linux) stat -c '%u:%a:%h:%s' -- "$__sl_control/result";;
            (*) exit 1;;
        esac
    ) || return 1
    case "$__sl_result_metadata" in "$__sl_uid:600:1:"*) ;; *) return 1;; esac
    __sl_result_size=${__sl_result_metadata##*:}
    rch_scope_uint "$__sl_result_size" && [ "$__sl_result_size" -le 256 ] || return 1
    __sl_result=$(cat "$__sl_control/result") || return 1
    __sl_prefix="RCH_SCOPED_RESULT_V1:$__sl_build:$__sl_child:$__sl_child_start:"
    case "$__sl_result" in "$__sl_prefix"*) ;; *) return 1;; esac
    __sl_status=${__sl_result#"$__sl_prefix"}
    rch_scope_uint "$__sl_status" && [ "${#__sl_status}" -le 3 ] && [ "$__sl_status" -le 255 ] || return 1
    [ "$__sl_result_size" -eq "$((${#__sl_result} + 1))" ] &&
        [ "$(wc -l < "$__sl_control/result")" -eq 1 ]
}

rch_scope_launch_read_owned_record() {
    rch_read_record "$__sl_record" "$__sl_build" &&
        rch_scope_launch_binding_matches && [ "$rch_pgid" = "$__sl_child" ] &&
        [ "$rch_start" = "$__sl_child_start" ]
}

# Only before admission: stop the exact setup child. V2 also needs scope cleanup.
rch_scope_launch_stop_setup() {
    rch_scope_launch_process "$__sl_child"
    case $? in 1) return 0;; 0) ;; *) return 1;; esac
    [ "$rch_launch_birth" = "$__sl_child_start" ] || return 1
    if [ "$rch_launch_group" = "$__sl_child" ]; then
        kill -KILL -"$__sl_child" 2>/dev/null || return 1
    else
        kill -KILL "$__sl_child" 2>/dev/null || return 1
    fi
}

# Preserve child PID and FDs. Darwin supplies setsid(2) through Python.
rch_scope_launch_exec() {
    case "$(uname -s)" in
        Linux) exec setsid "$@";;
        Darwin) exec python3 -I -S -c 'import os, sys; os.setsid(); os.execvp(sys.argv[1], sys.argv[1:])' "$@";;
        *) return 125;;
    esac
}

# Exit 255 retains ownership on unknown completion; it never permits fallback.
rch_scope_launch_supervise() {
    __sl_record=$1; __sl_limit=$2; __sl_marker=$3; __sl_build=$4; shift 4
    case "$__sl_record" in /*) ;; *) return 125;; esac
    # Atomic one-shot claim: neither lost publication nor retired receipt allows
    # a second execution. Outer durable execution/source grants remain required.
    if [ -e "$__sl_record" ] || [ -L "$__sl_record" ]; then
        rch_scope_launch_message RCH_SCOPED_LAUNCH_ALREADY_OWNED >&2
        return 255
    fi
    __sl_control="$__sl_record.supervisor.v1"
    (umask 077; mkdir -m 700 -- "$__sl_control") 2>/dev/null || {
        # Existing claims retain ownership; other mkdir errors started nothing.
        if [ -e "$__sl_control" ] || [ -L "$__sl_control" ]; then
            rch_scope_launch_message RCH_SCOPED_LAUNCH_ALREADY_OWNED >&2
            return 255
        fi
        rch_scope_launch_message "$__sl_marker" setup >&2
        return 125
    }
    # Recheck legacy writers; never remove or adopt their record or this fence.
    if [ -e "$__sl_record" ] || [ -L "$__sl_record" ]; then
        rch_scope_launch_message RCH_SCOPED_LAUNCH_ALREADY_OWNED >&2
        return 255
    fi
    # Claim first: changed policy must not grant fallback to a duplicate launch.
    rch_scope_launch_select || {
        rch_scope_launch_message "$__sl_marker" setup >&2
        return 125
    }
    rch_scope_uint "$__sl_limit" && [ "${#__sl_limit}" -le 10 ] &&
        [ "$__sl_limit" -le 2147483647 ] || return 125
    [ "$#" -gt 0 ] && rch_check_procfs_namespace || return 125
    case "$(uname -s)" in
        Linux) command -v setsid >/dev/null 2>&1 || return 125;;
        Darwin) command -v python3 >/dev/null 2>&1 || return 125;;
        *) return 125;;
    esac
    # Capture supervisor birth for the lost-parent watchdog before launch.
    rch_scope_launch_process "$$" && rch_scope_launch_clock || {
        rch_scope_launch_message "$__sl_marker" setup >&2
        return 125
    }
    __sl_parent_start=$rch_launch_birth
    __sl_uid=$(id -u) || return 125
    __sl_cancelled=0
    trap '__sl_cancelled=1' HUP INT TERM
    rch_scope_launch_save_input || {
        rch_scope_launch_message "$__sl_marker" setup >&2
        return 125
    }
    # Only the fixed FD redirection becomes eval syntax; data stays quoted.
    eval 'rch_scope_launch_exec /bin/sh -c "$rch_launch_source
rch_scope_launch_child \"\$@\"" rch-scoped-child \
        "$__sl_record" "$__sl_control" "$__sl_marker" "$__sl_build" \
        "$$" "$__sl_parent_start" "$__sl_limit" \
        "$rch_launch_nice" "$rch_launch_slice" "$rch_launch_manager" "$@" '"$__sl_input_redirect"' &'
    __sl_child=$!
    # Silence asynchronous shell notices after child stream inheritance. Route
    # bounded diagnostics via stdout to original stderr; preserve closed stderr.
    if rch_scope_launch_fd_open 2; then
        rch_scope_launch_finish 1>&2 2>/dev/null
    else
        rch_scope_launch_finish >/dev/null 2>&1
    fi
}

# Must remain in the supervising shell for birth binding and cancellation traps.
# stdout here is the original diagnostic stream, never payload stdout.
rch_scope_launch_finish() {
    rch_scope_launch_close_input
    __sl_child_start=; __sl_admitted=0; __sl_admission_record=; __sl_reason=setup
    __sl_admission_observations=0
    rch_scope_launch_clock || return 255
    __sl_setup_started=$rch_launch_now
    rch_timing_budget 6000
    __sl_setup_deadline=$((__sl_setup_started + rch_timing_scaled))
    __sl_last_clock=$((rch_launch_now - 1))
    while :; do
        rch_scope_launch_process "$__sl_child"
        __sl_live=$?
        if [ "$__sl_live" = 0 ]; then
            if [ -z "$__sl_child_start" ]; then __sl_child_start=$rch_launch_birth; fi
            [ "$rch_launch_birth" = "$__sl_child_start" ] || { __sl_reason=unknown; break; }
        elif [ "$__sl_live" = 1 ]; then
            __sl_reason=exited; break
        else
            __sl_reason=unknown; break
        fi
        if [ "$__sl_cancelled" = 1 ]; then __sl_reason=cancelled; break; fi
        rch_scope_launch_clock || { __sl_reason=unknown; break; }
        [ "$rch_launch_now" -gt "$__sl_last_clock" ] || { __sl_reason=unknown; break; }
        __sl_last_clock=$rch_launch_now
        if [ "$__sl_admitted" = 0 ]; then
            # One deadline covers publication and all admission observations.
            if [ "$rch_launch_now" -ge "$__sl_setup_deadline" ]; then
                [ "$__sl_admission_observations" = 0 ] || __sl_reason=unknown
                break
            fi
            if [ -e "$__sl_record" ] || [ -L "$__sl_record" ]; then
                if ! rch_scope_launch_read_owned_record; then
                    __sl_reason=unknown; break
                fi
                # Live birth proves presence; only cleanup needs a full census.
                rch_remote_leader_matches || { __sl_reason=unknown; break; }
                __sl_scope_state=1
                if [ $rch_scope_bound = 1 ]; then
                    __sl_admission_observations=$((__sl_admission_observations + 1))
                    rch_observation_deadline=$__sl_setup_deadline
                    rch_observation_last_clock=$rch_launch_now
                    rch_scope_operation state
                    __sl_scope_state=$?
                    unset rch_observation_deadline rch_observation_last_clock
                    case "$__sl_scope_state" in
                        1|2) ;;
                        *) __sl_reason=unknown; break;;
                    esac
                fi
                rch_scope_launch_clock || { __sl_reason=unknown; break; }
                [ "$rch_launch_now" -ge "$__sl_last_clock" ] || { __sl_reason=unknown; break; }
                __sl_last_clock=$rch_launch_now
                if [ "$rch_launch_now" -ge "$__sl_setup_deadline" ]; then
                    __sl_reason=unknown; break
                fi
                if [ "$__sl_cancelled" = 1 ]; then __sl_reason=cancelled; break; fi
                rch_remote_leader_matches || { __sl_reason=unknown; break; }
                if [ "$__sl_scope_state" = 2 ]; then
                    # Gate stays closed; recheck birth and the receipt next pass.
                    sleep 0.1 || { __sl_reason=unknown; break; }
                    continue
                fi
                __sl_started=$rch_launch_now
                # Mark admitted BEFORE gate write. Retain its binding in memory:
                # receipt loss/replacement cannot redirect or waive cleanup.
                __sl_admission_record=$rch_record
                __sl_admitted=1
                (umask 077; set -C; printf '%s\n' go > "$__sl_control/go") || {
                    __sl_reason=unknown; break;
                }
            fi
        else
            if [ -e "$__sl_control/result" ] || [ -L "$__sl_control/result" ]; then
                if rch_scope_launch_read_result; then __sl_reason=result; else __sl_reason=unknown; fi
                break
            fi
            if [ "$__sl_limit" -gt 0 ] && [ "$((rch_launch_now - __sl_started))" -ge "$((__sl_limit * 100))" ]; then
                __sl_reason=deadline; break
            fi
        fi
        sleep 0.1 || { __sl_reason=unknown; break; }
    done
    __sl_cleanup=0
    __sl_cleanup_status=0; __sl_record_status=0
    if [ "$__sl_admitted" = 1 ]; then
        # Revalidate signal authority and prove emptiness using admitted identity.
        rch_remote_cancel_loaded kill || {
            __sl_cleanup_status=$?; __sl_cleanup=1;
        }
        # Check record AFTER cleanup in a subshell; parsing cannot replace our
        # admitted identity. Record damage still forbids confirmed completion.
        (rch_scope_launch_read_owned_record &&
            [ "$rch_record" = "$__sl_admission_record" ]) || {
                __sl_record_status=$?; __sl_cleanup=1;
            }
    else
        rch_scope_launch_stop_setup || {
            __sl_cleanup_status=$?; __sl_cleanup=1;
        }
        # Reap before reading: setup publication cannot then race recovery.
        if [ "$__sl_cleanup" = 0 ]; then wait "$__sl_child"; __sl_wait=$?; fi
        if [ -e "$__sl_record" ] || [ -L "$__sl_record" ]; then
            if rch_scope_launch_read_owned_record; then
                rch_remote_cancel_loaded kill || {
                    __sl_cleanup_status=$?; __sl_cleanup=1;
                }
            else
                __sl_record_status=$?; __sl_cleanup=1
            fi
        fi
    fi
    if [ "$__sl_cleanup" != 0 ]; then
        rch_scope_launch_message "RCH_SCOPED_COMPLETION_UNCONFIRMED
RCH_SCOPED_COMPLETION_DETAIL:reason=$__sl_reason,admitted=$__sl_admitted,cleanup=$__sl_cleanup_status,record=$__sl_record_status"
        return 255
    fi
    if [ "$__sl_admitted" = 1 ]; then wait "$__sl_child"; __sl_wait=$?; fi
    # Deadline wins raced payload status. Retain evidence for recovery.
    if [ "$__sl_reason" = deadline ] || [ -f "$__sl_control/deadline" ]; then
        rch_scope_launch_deadline_marker "$__sl_marker"
        return 137
    fi
    [ "$__sl_cancelled" = 0 ] || return 143
    case "$__sl_reason" in
        result) return "$__sl_status";;
        unknown)
            rch_scope_launch_message "RCH_SCOPED_COMPLETION_UNCONFIRMED
RCH_SCOPED_COMPLETION_DETAIL:reason=unknown,admitted=$__sl_admitted,cleanup=0,record=0"
            return 255;;
        exited)
            if [ "$__sl_admitted" = 1 ]; then return "$__sl_wait"; fi;;
    esac
    rch_scope_launch_message "$__sl_marker" setup
    return 125
}

# Recovery probes actual policy/admission/execution/completion. Uncertainty
# retains evidence and emits no healthy sentinel. Caller cap:120s including SSH.
rch_process_health_probe() (
    rch_health_base=${TMPDIR:-/tmp}
    case "$rch_health_base" in /*) ;; *) exit 1;; esac
    rch_health_dir=$(umask 077; mktemp -d "$rch_health_base/rch-process-health.XXXXXXXXXX") || exit 1
    /bin/sh -c '
rch_launch_source=$1; shift
command eval "$rch_launch_source" || exit 125
exec 3>&2
rch_scope_launch_supervise "$@"
' rch-process-health "$rch_launch_source" \
        "$rch_health_dir/receipt" 5 RCH_PROCESS_HEALTH_DEADLINE 0 /bin/sh -c ':' || exit 1
    # Only a proven completed attempt can discard its private probe evidence.
    # There are no user paths or recursive deletions in this cleanup.
    rm -f -- "$rch_health_dir/receipt" \
        "$rch_health_dir/receipt.supervisor.v1/go" \
        "$rch_health_dir/receipt.supervisor.v1/result" || exit 1
    rmdir -- "$rch_health_dir/receipt.supervisor.v1" "$rch_health_dir" || exit 1
    printf '%s\n' RCH_PROCESS_HEALTH_V1
)
