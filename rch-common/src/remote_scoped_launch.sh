# Owned rch-build lifecycle. The supervisor stays OUTSIDE the workload group.
# The leader reports the command's status but remains alive until the supervisor
# has stopped the group (and configured scope). Only then may the outer durable
# execution wrapper publish completion and release source/output ownership.
# This is the existing rch-build argv ABI, not a new worker installation.
# V1 owns a process group; only configured V2 scopes cover setsid descendants.

# Dash redirects an asynchronous command's stdin to /dev/null BEFORE applying
# that command's redirections: <&0 alone cannot preserve the original input.
# Borrow an unused descriptor, duplicate the original open file description,
# then explicitly bind it back to fd 0 in the child. Never reopen a pathname
# (which resets file offsets), spool input, or overwrite inherited authority FDs.
# Procfs is already a launch prerequisite and the namespace check names THIS
# shell, including when a function is invoked from a subshell.
rch_scope_launch_save_input() {
    __sl_input= __sl_input_redirect=
    rch_check_procfs_namespace || return 1
    __sl_fd_dir=/proc/$rch_self_pid/fd
    [ -r "$__sl_fd_dir" ] && [ -x "$__sl_fd_dir" ] || return 1
    if [ ! -e "$__sl_fd_dir/0" ] && [ ! -L "$__sl_fd_dir/0" ]; then
        __sl_input_redirect='0<&-'
        return 0
    fi
    for __sl_input_candidate in 4 5 6 7 8 9; do
        if [ ! -e "$__sl_fd_dir/$__sl_input_candidate" ] &&
            [ ! -L "$__sl_fd_dir/$__sl_input_candidate" ]; then
            __sl_input=$__sl_input_candidate
            # Only this literal single-digit selection enters eval. No input,
            # path, argument or environment value becomes shell program text.
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

# Snapshot receiver policy once. Never let removal/change between route selection
# and child launch silently put a requested scope on the legacy PGID-only route.
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
    rch_valid_pgid "$1" || return 2
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

# Best-effort marker delivery must not delay hard cleanup behind a full pipe.
# GNU timeout bounds AND reaps the writer; its own output FDs are closed.
rch_scope_launch_deadline_marker() {
    timeout -k 1s 1s /bin/sh -c 'printf "\n%s\n" "$1" >&3' rch-deadline "$1" \
        >/dev/null 2>&1 </dev/null
}

# Policy selects the required authority class. Never accept a V1 downgrade of
# a requested scope, or silently assume that an ordinary group has V2 rights.
rch_scope_launch_binding_matches() {
    if [ -n "$rch_launch_slice" ]; then
        [ "$rch_scope_bound" = 1 ]
    else
        [ "$rch_scope_bound" = 0 ]
    fi
}

# Used ONLY by the still-executing leader/watchdog inside its own group. Its
# current membership pins that group even if the leader died. $$ in a watchdog
# subshell names the leader, so obtain the actual caller PID from the verified
# procfs view. This is not historical receipt authority or an orphan adopter;
# the outside supervisor must still use birth-fenced cancellation and census.
rch_scope_launch_kill_self() {
    if [ "$rch_scope_bound" = 1 ]; then
        rch_scope_operation kill
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
    rch_remote_record "$__sl_record" "$__sl_build" || exit 125
    rch_scope_launch_binding_matches || exit 125
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
    # This watchdog lives in the group and survives a SIGKILL of the outside
    # supervisor. It remains armed after the command reports its exit status,
    # until the supervisor stops the group/scope. V2 additionally covers
    # detached descendants; V1 makes no claim beyond its own process group.
    (
        trap '' HUP INT TERM
        while :; do
            if ! rch_scope_launch_parent_alive; then
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
    # Start the watchdog first so it never inherits the borrowed input FD.
    # Admission has already occurred: failure here is uncertain execution,
    # never the pre-workload capability refusal that permits fallback.
    rch_scope_launch_save_input || { rch_scope_launch_kill_self; exit 255; }
    eval '"$@" 3>&- '"$__sl_input_redirect"' &'
    __sl_payload=$!
    rch_scope_launch_close_input
    wait "$__sl_payload"; __sl_status=$?
    [ "$__sl_cancelled" != 1 ] || __sl_status=143
    # This is only a command-status report, NEVER a completion receipt. The
    # parent still has to prove the whole process/cgroup tree has stopped.
    (umask 077; set -C; printf 'RCH_SCOPED_RESULT_V1:%s:%s:%s:%s\n' \
        "$__sl_build" "$rch_pgid" "$rch_start" "$__sl_status" > "$__sl_control/result.tmp") &&
        mv "$__sl_control/result.tmp" "$__sl_control/result" || exit 255
    while :; do sleep 1 3>&- || exit 255; done
}

rch_scope_launch_read_result() {
    [ -f "$__sl_control/result" ] && [ ! -L "$__sl_control/result" ] || return 1
    [ "$(stat -c '%u:%a:%h' -- "$__sl_control/result")" = "$__sl_uid:600:1" ] || return 1
    __sl_result_size=$(stat -c '%s' -- "$__sl_control/result") || return 1
    [ "$__sl_result_size" -le 256 ] || return 1
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

# Before the gate opens, only trusted setup helpers can be running. Stop that
# exact child/group on admission failure; never use this PGID-only path once
# payload execution has been admitted. A V2 record still requires scope cleanup.
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

# Exit 255 on unconfirmed cleanup: transfer orchestration already treats it as
# unknown remote completion and retains recovery/source authority. Do not turn
# cleanup uncertainty into an ordinary compiler failure or a setup fallback.
rch_scope_launch_supervise() {
    __sl_record=$1; __sl_limit=$2; __sl_marker=$3; __sl_build=$4; shift 4
    case "$__sl_record" in /*) ;; *) return 125;; esac
    # The record names ONE admitted execution, not permission to launch it
    # again. Keep the control directory as a one-shot claim, even if a lost
    # caller never reached record publication or the record is later retired.
    # mkdir is the atomic arbiter for simultaneous supervisors; a randomized
    # control directory admitted both and let the second overwrite the record.
    # Existing legacy records also refuse before any child or mutation starts.
    # Outer durable execution/source grants remain required: an older writer
    # that ignores this directory does not participate in its arbitration.
    if [ -e "$__sl_record" ] || [ -L "$__sl_record" ]; then
        printf '%s\n' RCH_SCOPED_LAUNCH_ALREADY_OWNED >&2
        return 255
    fi
    __sl_control="$__sl_record.supervisor.v1"
    (umask 077; mkdir -m 700 -- "$__sl_control") || {
        # Only an existing claim means another launch owns this record. Any
        # other failure (missing parent, EDQUOT, ENOSPC) claimed and started
        # nothing: report the pre-workload refusal the caller may retry.
        if [ -e "$__sl_control" ] || [ -L "$__sl_control" ]; then
            printf '%s\n' RCH_SCOPED_LAUNCH_ALREADY_OWNED >&2
            return 255
        fi
        printf '\n%s_IDENTITY_UNAVAILABLE\n' "$__sl_marker" >&2
        return 125
    }
    # Recheck after acquisition for an older launcher which has no claim.
    # Do not remove/adopt either its record or this invocation's new fence.
    if [ -e "$__sl_record" ] || [ -L "$__sl_record" ]; then
        printf '%s\n' RCH_SCOPED_LAUNCH_ALREADY_OWNED >&2
        return 255
    fi
    # Claim before policy selection: a policy changed since an earlier run
    # must not turn its duplicate into a pre-workload fallback permission.
    rch_scope_launch_select || {
        printf '\n%s_IDENTITY_UNAVAILABLE\n' "$__sl_marker" >&2
        return 125
    }
    rch_scope_uint "$__sl_limit" && [ "${#__sl_limit}" -le 10 ] &&
        [ "$__sl_limit" -le 2147483647 ] || return 125
    [ "$#" -gt 0 ] && rch_check_procfs_namespace && command -v setsid >/dev/null 2>&1 || return 125
    # No observer may share the new child's group or cgroup. Capture this
    # supervisor's birth before launch for the child's lost-parent watchdog.
    rch_scope_launch_process "$$" || return 125
    __sl_parent_start=$rch_launch_birth
    __sl_uid=$(id -u) || return 125
    __sl_cancelled=0
    trap '__sl_cancelled=1' HUP INT TERM
    rch_scope_launch_save_input || {
        printf '\n%s_IDENTITY_UNAVAILABLE\n' "$__sl_marker" >&2
        return 125
    }
    # Arguments and the literal source expand as QUOTED argument values inside
    # eval; only the fixed descriptor redirection is assembled as syntax.
    eval 'setsid /bin/sh -c "$rch_launch_source
rch_scope_launch_child \"\$@\"" rch-scoped-child \
        "$__sl_record" "$__sl_control" "$__sl_marker" "$__sl_build" \
        "$$" "$__sl_parent_start" "$__sl_limit" \
        "$rch_launch_nice" "$rch_launch_slice" "$rch_launch_manager" "$@" '"$__sl_input_redirect"' &'
    __sl_child=$!
    rch_scope_launch_close_input
    __sl_child_start=; __sl_admitted=0; __sl_admission_record=; __sl_reason=setup
    rch_scope_launch_clock || return 255
    __sl_setup_started=$rch_launch_now
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
        if [ "$__sl_admitted" = 0 ]; then
            if [ -e "$__sl_record" ] || [ -L "$__sl_record" ]; then
                if ! rch_scope_launch_read_owned_record; then
                    __sl_reason=unknown; break
                fi
                rch_group_state
                [ "$?" = 1 ] || { __sl_reason=unknown; break; }
                rch_scope_launch_clock || { __sl_reason=unknown; break; }
                __sl_started=$rch_launch_now
                # Mark admitted before publication: an uncertain gate write
                # cannot authorize the pre-payload group-only cleanup path.
                # Keep the complete admitted binding in memory. Receipt loss or
                # replacement must neither redirect cleanup nor erase our duty
                # to stop this already-authorized workload.
                __sl_admission_record=$rch_record
                __sl_admitted=1
                (umask 077; set -C; printf '%s\n' go > "$__sl_control/go") || {
                    __sl_reason=unknown; break;
                }
            elif [ "$((rch_launch_now - __sl_setup_started))" -ge 6000 ]; then
                __sl_reason=setup; break
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
    if [ "$__sl_admitted" = 1 ]; then
        # Nothing after admission reloads the identity fields. The cancellation
        # primitive revalidates their live process/scope authority before every
        # signal and still requires the full post-kill emptiness proof.
        rch_remote_cancel_loaded kill || __sl_cleanup=1
        # A damaged durable record still forbids reporting confirmed completion.
        # Read it ONLY in a subshell, after attempting owned cleanup: otherwise
        # even a failed parse can replace the binding used for cancellation.
        (rch_scope_launch_read_owned_record &&
            [ "$rch_record" = "$__sl_admission_record" ]) || __sl_cleanup=1
    else
        rch_scope_launch_stop_setup || __sl_cleanup=1
        # Wait before inspecting the receipt: publication cannot race recovery
        # once this setup child has stopped. No payload passed the private gate.
        if [ "$__sl_cleanup" = 0 ]; then wait "$__sl_child"; __sl_wait=$?; fi
        if [ -e "$__sl_record" ] || [ -L "$__sl_record" ]; then
            if rch_scope_launch_read_owned_record; then
                rch_remote_cancel_loaded kill || __sl_cleanup=1
            else
                __sl_cleanup=1
            fi
        fi
    fi
    if [ "$__sl_cleanup" != 0 ]; then
        printf '%s\n' RCH_SCOPED_COMPLETION_UNCONFIRMED >&2
        return 255
    fi
    if [ "$__sl_admitted" = 1 ]; then wait "$__sl_child"; __sl_wait=$?; fi
    # Deadline evidence wins a raced compiler report, exactly as the existing
    # stream marker does. Retain the marker/status/control files for recovery.
    if [ "$__sl_reason" = deadline ] || [ -f "$__sl_control/deadline" ]; then
        rch_scope_launch_deadline_marker "$__sl_marker"
        return 137
    fi
    [ "$__sl_cancelled" = 0 ] || return 143
    case "$__sl_reason" in
        result) return "$__sl_status";;
        unknown) printf '%s\n' RCH_SCOPED_COMPLETION_UNCONFIRMED >&2; return 255;;
        exited)
            if [ "$__sl_admitted" = 1 ]; then return "$__sl_wait"; fi;;
    esac
    printf '\n%s_IDENTITY_UNAVAILABLE\n' "$__sl_marker" >&2
    return 125
}
