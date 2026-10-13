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
# Inside ( ... ) $$ still names the invoking shell while /proc/self is this
# subshell (the watchdog's timer is one), so compare with this process's own
# ID: a command exec'd from a substitution reports it as its parent.
rch_check_procfs_namespace() {
    rch_self_pid=$(exec sh -c 'echo "$PPID"') || return 1
    while IFS= read -r rch_status_line; do
        case "$rch_status_line" in
            NSpid:*)
                set -- ${rch_status_line#NSpid:}
                [ "$#" -eq 1 ] && [ "$1" = "$rch_self_pid" ]
                return $?;;
        esac
    done < /proc/self/status 2>/dev/null
    return 1
}

# Read a member of the bound group, including comm with spaces or parentheses.
# A member may be a non-leader TID: /proc/<tid>/stat has the same birth/group
# fields. This preserves escalation when a process leader is already a zombie
# but another thread of that process is still running.
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
    # Refuse before publishing execution authority or spawning the payload.
    # Scope placement moves this leader, not the workload into a separate tree.
    rch_apply_configured_worker_policy || return 125
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
# A zombie process leader does not prove its other threads have exited. Enumerate
# LWPs, retaining their own IDs for live escalation witnesses. A terminal-only
# snapshot must account for every reported thread; unsupported/incomplete thread
# enumeration is unknown, never a fallback to a process-only empty-group claim.
rch_group_state() {
    rch_check_procfs_namespace || return 2
    rch_task_snapshot=$(LC_ALL=C ps -e -L -o pid= -o lwp= -o pgid= -o stat= -o nlwp=) || return 2
    rch_snapshot=$(printf '%s\n' "$rch_task_snapshot" | LC_ALL=C awk -v group="$rch_pgid" -v observer="$$" '
        NF != 5 || $1 !~ /^[1-9][0-9]*$/ || $2 !~ /^[1-9][0-9]*$/ || $3 !~ /^[0-9]+$/ || $4 !~ /^[RSDTtKWPIXZx][A-Za-z0-9+<>-]*$/ || $5 !~ /^[1-9][0-9]*$/ { bad = 1; next }
        seen_task[$2]++ { bad = 1 }
        $2 == observer { seen = 1; if ($3 == group) bad = 1 }
        $3 == group {
            members[$1]++
            if ($1 in expected && expected[$1] != $5) uncertain = 1
            expected[$1] = $5
            if ($4 !~ /^[ZXx]/) live = 1
        }
        { print $2, $3, $4 }
        END {
            if (bad || !seen) exit 2
            # Positive liveness needs no complete census. Requiring a stable
            # thread count here would prevent cancelling a busy compiler.
            if (live) exit 1
            for (pid in members) if (members[pid] != expected[pid]) uncertain = 1
            if (uncertain) exit 2
            exit 0
        }
    ')
    return $?
}

# Capture live members while the recorded leader still authenticates the group.
# TERM can kill that leader before a child that ignores TERM. A surviving
# member's birth identity lets THIS cancellation finish escalation without
# treating a historical PGID as authority. These witnesses are never persisted.
rch_capture_group_witnesses() {
    rch_witnesses=
    rch_witness_identity=
    [ "$rch_identified" -eq 1 ] && rch_remote_leader_matches || return 43
    # rch_group_state normalized the validated LWP census to ID/group/state.
    # Retain live TIDs, not just process leaders, with the same birth fencing.
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

# Optional receiver-side execution policy for tracked Linux build payloads.
# These functions travel with the launch protocol; no worker launcher is needed.
# Sync, pre-launch package bootstrap, and untracked execution are NOT confined
# here. This is not by itself admission for a dual-role worker (GH #104).
#
# Configure ONE of /etc/rch/worker-execution.conf (root owned) or
# $HOME/.config/rch/worker-execution.conf (owned by the SSH user or root):
#   version=1
#   nice=10
#   systemd_slice=jobs.slice
#   systemd_manager=user
# All specified settings are required. Missing policy preserves legacy behavior.
# Unknown/duplicate keys, an unreadable file, or failed enforcement refuse setup.
# No policy contents are ever evaluated as shell code.

rch_policy_refuse() {
    printf 'RCH_WORKER_POLICY_REFUSED:%s\n' "$1" >&2
    return 125
}

rch_policy_valid_nice() {
    case "$1" in 0|[1-9]|1[0-9]|-[1-9]|-1[0-9]|-20) return 0;; esac
    return 1
}

rch_policy_valid_slice() {
    case "$1" in *.slice) rch_policy_slice_base=${1%.slice};; *) return 1;; esac
    [ -n "$rch_policy_slice_base" ] && [ "${#1}" -le 200 ] || return 1
    case "$rch_policy_slice_base" in
        -*|*-|*--*|*[!a-zA-Z0-9_-]*) return 1;;
    esac
}

rch_policy_select_file() {
    rch_policy_file=
    rch_policy_uid=$(id -u) || { rch_policy_refuse uid; return 125; }
    rch_policy_system=/etc/rch/worker-execution.conf
    rch_policy_user=
    case "${HOME:-}" in /*) rch_policy_user="$HOME/.config/rch/worker-execution.conf";; esac
    # An inaccessible containing directory is not evidence of absent policy.
    for rch_policy_dir in /etc/rch "${HOME:-/}/.config" "${HOME:-/}/.config/rch"; do
        if [ -d "$rch_policy_dir" ] && [ ! -x "$rch_policy_dir" ]; then
            rch_policy_refuse unreadable_directory; return 125
        fi
    done
    if [ -e "$rch_policy_system" ] || [ -L "$rch_policy_system" ]; then
        rch_policy_file=$rch_policy_system
        rch_policy_owner=0
    fi
    if [ -n "$rch_policy_user" ] && { [ -e "$rch_policy_user" ] || [ -L "$rch_policy_user" ]; }; then
        [ -z "$rch_policy_file" ] || { rch_policy_refuse multiple_policies; return 125; }
        rch_policy_file=$rch_policy_user
        rch_policy_owner=$rch_policy_uid
    fi
}

# Parse the entire bounded, ASCII data file before changing process attributes.
# owner is the expected uid; root-owned user policy is also accepted.
rch_policy_read_file() {
    rch_policy_nice=
    rch_policy_slice=
    rch_policy_manager=user
    rch_policy_seen=':'
    [ -f "$1" ] && [ ! -L "$1" ] && [ -r "$1" ] || {
        rch_policy_refuse unreadable_file; return 125;
    }
    rch_policy_stat=$(LC_ALL=C stat -c '%u:%a:%s:%h' -- "$1") || {
        rch_policy_refuse file_metadata; return 125;
    }
    rch_policy_file_uid=${rch_policy_stat%%:*}
    rch_policy_stat=${rch_policy_stat#*:}
    rch_policy_mode=${rch_policy_stat%%:*}
    rch_policy_stat=${rch_policy_stat#*:}
    rch_policy_size=${rch_policy_stat%%:*}
    rch_policy_links=${rch_policy_stat#*:}
    case "$rch_policy_mode" in [0-7][0-7][0-7]) ;; *) rch_policy_refuse file_mode; return 125;; esac
    [ "$rch_policy_file_uid" = "$2" ] || [ "$rch_policy_file_uid" = 0 ] || {
        rch_policy_refuse file_owner; return 125;
    }
    [ "$((0$rch_policy_mode & 022))" -eq 0 ] && [ "$rch_policy_links" = 1 ] || {
        rch_policy_refuse writable_or_linked_file; return 125;
    }
    [ "$rch_policy_size" -le 8192 ] || { rch_policy_refuse file_size; return 125; }
    # Shell read can discard NULs. Validate bytes before parsing, not afterwards.
    LC_ALL=C tr -cd '\11\12\40-\176' < "$1" | cmp -s - "$1" || {
        rch_policy_refuse file_encoding; return 125;
    }
    while IFS= read -r rch_policy_line || [ -n "$rch_policy_line" ]; do
        case "$rch_policy_line" in ''|'#'*) continue;; esac
        case "$rch_policy_line" in *=*) ;; *) rch_policy_refuse syntax; return 125;; esac
        rch_policy_key=${rch_policy_line%%=*}
        rch_policy_value=${rch_policy_line#*=}
        case "$rch_policy_seen" in *":$rch_policy_key:"*) rch_policy_refuse duplicate_key; return 125;; esac
        rch_policy_seen="$rch_policy_seen$rch_policy_key:"
        case "$rch_policy_key" in
            version) [ "$rch_policy_value" = 1 ] || { rch_policy_refuse version; return 125; };;
            nice)
                rch_policy_valid_nice "$rch_policy_value" || { rch_policy_refuse nice; return 125; }
                rch_policy_nice=$rch_policy_value;;
            systemd_slice)
                rch_policy_valid_slice "$rch_policy_value" || { rch_policy_refuse slice; return 125; }
                rch_policy_slice=$rch_policy_value;;
            systemd_manager)
                case "$rch_policy_value" in user|system) ;; *) rch_policy_refuse manager; return 125;; esac
                rch_policy_manager=$rch_policy_value;;
            *) rch_policy_refuse unknown_key; return 125;;
        esac
    done < "$1"
    case "$rch_policy_seen" in *:version:*) ;; *) rch_policy_refuse missing_version; return 125;; esac
    [ -n "$rch_policy_nice$rch_policy_slice" ] || { rch_policy_refuse empty_policy; return 125; }
    case "$rch_policy_seen" in
        *:systemd_manager:*)
            [ -n "$rch_policy_slice" ] || { rch_policy_refuse manager_without_slice; return 125; };;
    esac
}

rch_policy_systemctl() {
    timeout 5s systemctl "--$rch_policy_manager" --no-pager --no-ask-password "$@"
}

# Read the launcher's actual unified cgroup. A successful D-Bus job submission
# is not evidence that systemd moved it; cgroup v1/ambiguous evidence is refused.
rch_policy_current_cgroup() (
    rch_policy_cgroup_count=0
    rch_policy_cgroup_value=
    while IFS= read -r rch_policy_cgroup_line; do
        case "$rch_policy_cgroup_line" in
            0::/*)
                rch_policy_cgroup_count=$((rch_policy_cgroup_count + 1))
                rch_policy_cgroup_value=${rch_policy_cgroup_line#0::};;
        esac
    done < "/proc/$$/cgroup"
    [ "$rch_policy_cgroup_count" -eq 1 ] || exit 125
    printf '%s\n' "$rch_policy_cgroup_value"
)

rch_policy_enter_scope() {
    command -v busctl >/dev/null 2>&1 && command -v systemctl >/dev/null 2>&1 &&
        command -v timeout >/dev/null 2>&1 || { rch_policy_refuse systemd_tools; return 125; }
    # An operator must start/configure the selected slice. Do not synthesize a
    # missing slice and accidentally run without its intended resource limits.
    [ "$(rch_policy_systemctl show --value --property=ActiveState -- "$rch_policy_slice")" = active ] || {
        rch_policy_refuse slice_not_active; return 125;
    }
    rch_policy_slice_cgroup=$(rch_policy_systemctl show --value --property=ControlGroup -- "$rch_policy_slice") || {
        rch_policy_refuse slice_cgroup; return 125;
    }
    case "$rch_policy_slice_cgroup" in /*) ;; *) rch_policy_refuse slice_cgroup; return 125;; esac
    [ "$rch_policy_slice_cgroup" != / ] || { rch_policy_refuse root_slice; return 125; }
    rch_policy_scope="rch-$rch_boot-$rch_pgid-$rch_start.scope"
    # Attach the EXISTING setsid leader, rather than starting an independent
    # transient service. All subsequently spawned work keeps the same PGID and
    # stdio, so the existing watchdog, cancellation and recovery remain owners.
    busctl "--$rch_policy_manager" --timeout=5s --allow-interactive-authorization=no \
        call org.freedesktop.systemd1 /org/freedesktop/systemd1 \
        org.freedesktop.systemd1.Manager StartTransientUnit 'ssa(sv)a(sa(sv))' \
        "$rch_policy_scope" fail 3 PIDs au 1 "$rch_pgid" \
        Slice s "$rch_policy_slice" Description s 'RCH tracked build' 0 >/dev/null || {
        rch_policy_refuse scope_creation; return 125;
    }
    rch_policy_expected_cgroup="$rch_policy_slice_cgroup/$rch_policy_scope"
    rch_policy_poll=0
    while [ "$(rch_policy_current_cgroup)" != "$rch_policy_expected_cgroup" ]; do
        rch_policy_poll=$((rch_policy_poll + 1))
        [ "$rch_policy_poll" -lt 50 ] || { rch_policy_refuse scope_not_enforced; return 125; }
        sleep 0.1 || { rch_policy_refuse scope_wait; return 125; }
    done
    [ "$(rch_policy_systemctl show --value --property=ActiveState -- "$rch_policy_scope")" = active ] &&
        [ "$(rch_policy_systemctl show --value --property=Slice -- "$rch_policy_scope")" = "$rch_policy_slice" ] &&
        [ "$(rch_policy_systemctl show --value --property=ControlGroup -- "$rch_policy_scope")" = "$rch_policy_expected_cgroup" ] || {
        rch_policy_refuse scope_evidence; return 125;
    }
}

rch_policy_enforce() {
    [ "$(uname -s)" = Linux ] || { rch_policy_refuse platform; return 125; }
    rch_remote_leader_matches || { rch_policy_refuse process_identity; return 125; }
    if [ -n "$rch_policy_nice" ]; then
        # util-linux -n becomes relative with POSIXLY_CORRECT. Clear that flag
        # only in the helper process; never change the build's environment.
        (unset POSIXLY_CORRECT; renice -n "$rch_policy_nice" -p "$rch_pgid") >/dev/null || {
            rch_policy_refuse priority_change; return 125;
        }
        rch_policy_observed_nice=$(LC_ALL=C ps -o ni= -p "$rch_pgid") || {
            rch_policy_refuse priority_observation; return 125;
        }
        # ps pads the numeric field; splitting is safe after the numeric check.
        case "$rch_policy_observed_nice" in *[!\ 0-9-]*) rch_policy_refuse priority_observation; return 125;; esac
        set -- $rch_policy_observed_nice
        [ "$#" -eq 1 ] && [ "$1" = "$rch_policy_nice" ] || {
            rch_policy_refuse priority_not_enforced; return 125;
        }
    fi
    rch_policy_scope=
    if [ -n "$rch_policy_slice" ]; then
        rch_policy_enter_scope || return 125
    fi
    rch_remote_leader_matches || { rch_policy_refuse process_identity; return 125; }
    printf 'RCH_WORKER_EXECUTION_POLICY:nice=%s,slice=%s,manager=%s,scope=%s\n' \
        "${rch_policy_nice:-inherit}" "${rch_policy_slice:-none}" \
        "$rch_policy_manager" "${rch_policy_scope:-none}" >&2
}

rch_apply_configured_worker_policy() {
    rch_policy_select_file || return 125
    [ -n "$rch_policy_file" ] || return 0
    rch_policy_read_file "$rch_policy_file" "$rch_policy_owner" || return 125
    rch_policy_enforce
}
