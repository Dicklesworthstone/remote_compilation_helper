# Receiver-side guards for invocation-owned source staging. This is a filesystem
# safety boundary, not a sandbox against another process running as the same uid.
# No input is evaluated as shell code. Call prepare once, then verify before each
# receiver setup/upload; recovery verifies the existing owner and never adopts it.

rch_stage_refuse() {
    printf 'RCH_ISOLATED_STAGING_REFUSED:%s\n' "$1" >&2
    return 125
}

rch_stage_valid_path() {
    case "$1" in /*) ;; *) return 1;; esac
    case "$1" in /|*/|*//*|*/./*|*/../*|*/.|*/..) return 1;; esac
    # grep processes newline as a delimiter, not a character matched by
    # [:cntrl:]. Compare bytes after removing controls so LF is rejected too.
    clean=$(printf '%s' "$1" | LC_ALL=C tr -d '\000-\037\177') || return 1
    [ "$clean" = "$1" ]
}

rch_stage_valid_identity() {
    [ "${#1}" -eq 32 ] || return 1
    case "$1" in *[!0-9a-f]*) return 1;; esac
}

# Check every existing component, including dangling links. pwd -P provides an
# independent physical-path check. Never let mkdir -p traverse an unchecked link.
rch_stage_physical_path() (
    rch_stage_valid_path "$1" || exit 125
    path=$1
    while [ "$path" != / ]; do
        [ ! -L "$path" ] || exit 125
        if [ -e "$path" ]; then
            [ -d "$path" ] || exit 125
            physical=$(CDPATH= cd -- "$path" && pwd -P) || exit 125
            [ "$physical" = "$path" ] || exit 125
        fi
        path=${path%/*}
        [ -n "$path" ] || path=/
    done
)

# A staging base must not itself live in a developer repository. A .git file
# (linked worktree) and a dangling .git symlink are fences, not just directories.
rch_stage_base_is_safe() (
    rch_stage_physical_path "$1" || exit 125
    path=$1
    while :; do
        [ ! -e "$path/.git" ] && [ ! -L "$path/.git" ] || exit 125
        [ "$path" != / ] || break
        path=${path%/*}
        [ -n "$path" ] || path=/
    done
)

rch_stage_owner_matches() (
    job=$1
    identity=$2
    uid=$(id -u) || exit 125
    [ -d "$job" ] && [ ! -L "$job" ] || exit 125
    [ "$(LC_ALL=C stat -c '%u:%a' -- "$job")" = "$uid:700" ] || exit 125
    marker="$job/.rch-stage-owner"
    [ -f "$marker" ] && [ ! -L "$marker" ] || exit 125
    [ "$(LC_ALL=C stat -c '%u:%a:%h' -- "$marker")" = "$uid:600:1" ] || exit 125
    printf 'RCH_ISOLATED_STAGE_V1:%s\n' "$identity" | cmp -s - "$marker"
)

rch_stage_private_parent() (
    uid=$(id -u) || exit 125
    metadata=$(LC_ALL=C stat -c '%u:%a' -- "$1") || exit 125
    owner=${metadata%%:*}
    mode=${metadata#*:}
    case "$mode" in [0-7][0-7][0-7]|[0-7][0-7][0-7][0-7]) ;; *) exit 125;; esac
    [ "$owner" = "$uid" ] && [ "$((0$mode & 022))" -eq 0 ]
)

rch_stage_prepare() (
    [ "$#" -eq 2 ] || { rch_stage_refuse arguments; exit 125; }
    [ "$(uname -s)" = Linux ] || { rch_stage_refuse platform; exit 125; }
    base=$1
    identity=$2
    rch_stage_valid_identity "$identity" || { rch_stage_refuse identity; exit 125; }
    rch_stage_base_is_safe "$base" || { rch_stage_refuse unsafe_base; exit 125; }
    job="$base/invocations/$identity"
    # Check before any creation, including a pre-existing invocations alias.
    rch_stage_physical_path "$job" || { rch_stage_refuse unsafe_invocation; exit 125; }
    umask 077
    mkdir -p -- "$base/invocations" || { rch_stage_refuse mkdir_base; exit 125; }
    rch_stage_private_parent "$base" && rch_stage_private_parent "$base/invocations" || {
        rch_stage_refuse shared_parent; exit 125;
    }
    # Atomic claim: even a directory containing an apparently valid owner is
    # NOT adopted by prepare. Disconnected sessions use verify instead.
    mkdir -m 700 -- "$job" || { rch_stage_refuse invocation_exists; exit 125; }
    (set -C; printf 'RCH_ISOLATED_STAGE_V1:%s\n' "$identity" > "$job/.rch-stage-owner") || {
        rch_stage_refuse write_owner; exit 125;
    }
    mkdir -m 700 -- "$job/source" || { rch_stage_refuse mkdir_source; exit 125; }
    rch_stage_owner_matches "$job" "$identity" || { rch_stage_refuse owner; exit 125; }
    printf '%s\n' "$job"
)

rch_stage_verify() (
    [ "$#" -eq 3 ] || { rch_stage_refuse arguments; exit 125; }
    [ "$(uname -s)" = Linux ] || { rch_stage_refuse platform; exit 125; }
    base=$1
    identity=$2
    destination=$3
    rch_stage_valid_identity "$identity" || { rch_stage_refuse identity; exit 125; }
    rch_stage_base_is_safe "$base" || { rch_stage_refuse unsafe_base; exit 125; }
    job="$base/invocations/$identity"
    case "$destination" in "$job/source/"*) ;; *) rch_stage_refuse outside_source; exit 125;; esac
    rch_stage_base_is_safe "$destination" || { rch_stage_refuse unsafe_destination; exit 125; }
    rch_stage_private_parent "$base" && rch_stage_private_parent "$base/invocations" || {
        rch_stage_refuse shared_parent; exit 125;
    }
    rch_stage_owner_matches "$job" "$identity" || { rch_stage_refuse owner; exit 125; }
    if [ -d "$destination" ]; then
        # A checkout created after preparation is still a developer checkout.
        # Hardlinks can alias files outside the tree even without symlinks.
        unsafe=$(find -P "$destination" \( -name .git -o -type f -links +1 -o \
            -name .rch-partial -type l \) -print -quit) || {
            rch_stage_refuse inventory; exit 125;
        }
        [ -z "$unsafe" ] || { rch_stage_refuse protected_entry; exit 125; }
    fi
)

# Source-upload receiver for --rsync-path. The existing durable source grant
# must enclose this operation: possession of an invocation identity does not
# authorize replay while a disconnected build may still be running.
# Arguments: base, invocation identity, exact planned destination, server argv.
rch_stage_receive() (
    [ "$#" -ge 6 ] || { rch_stage_refuse receiver_arguments; exit 125; }
    base=$1
    identity=$2
    destination=$3
    shift 3
    [ "$1" = --server ] || { rch_stage_refuse not_receiver; exit 125; }
    partial_value=0
    for arg do
        if [ "$partial_value" -eq 1 ]; then
            [ "$arg" = .rch-partial ] || { rch_stage_refuse partial_directory; exit 125; }
            partial_value=0
            continue
        fi
        case "$arg" in
            --sender|--inplace*|--append*|--keep-dirlinks*|--copy-dirlinks*|--link-dest*|\
            --copy-dest*|--compare-dest*|--backup-dir*|--temp-dir*|--log-file*|\
            --write-batch*|--only-write-batch*|-?*K*|-?*H*|-K*|-H*)
                rch_stage_refuse unsafe_receiver_option; exit 125;;
            --partial-dir) partial_value=1;;
            --partial-dir=.rch-partial) ;;
            --partial-dir*) rch_stage_refuse partial_directory; exit 125;;
        esac
        last=$arg
    done
    [ "$partial_value" -eq 0 ] || { rch_stage_refuse partial_directory; exit 125; }
    [ "$last" = "$destination" ] || [ "$last" = "$destination/" ] || {
        rch_stage_refuse destination_mismatch; exit 125;
    }
    rch_stage_verify "$base" "$identity" "$destination" || exit 125
    umask 077
    mkdir -p -- "$destination" || { rch_stage_refuse mkdir_destination; exit 125; }
    CDPATH= cd -P -- "$destination" || { rch_stage_refuse cwd; exit 125; }
    [ "$(pwd -P)" = "$destination" ] || { rch_stage_refuse cwd_alias; exit 125; }
    # Rotate argv to remove ONLY its last operand, without eval or re-splitting.
    # The receiver uses the pinned cwd, not an absolute pathname it can resolve
    # again through a subsequently replaced final symlink.
    count=$#
    index=1
    while [ "$index" -lt "$count" ]; do
        arg=$1
        shift
        set -- "$@" "$arg"
        index=$((index + 1))
    done
    shift
    exec rsync "$@" .
)
