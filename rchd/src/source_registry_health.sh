# Invoked by the daemon health probe with the SAME registry as source admission.
# This is writable-storage evidence, never a grant or a durability receipt.
# In particular, do not replace the claim transaction's write/sync/rename barriers
# with this probe. No claim, fence, receipt, lock or quarantine record is opened.
rch_source_registry_health() (
    set -eu
    umask 077
    registry=$1
    authority=${registry%/*}

    refuse_registry_health() {
        printf 'RCH_SOURCE_REGISTRY_UNWRITABLE %s: %s\n' "$1" "$2" >&2
        exit 74
    }

    # Do not follow an authority/record-directory symlink, repair its permissions,
    # or silently choose another filesystem. /tmp itself may be a platform alias.
    # Concurrent first probes/builds may create the same directory; revalidate it
    # after mkdir rather than interpreting EEXIST as a storage failure.
    for directory in "$authority" "$registry" "$registry/released" \
        "$registry/cancelled" "$registry/quarantine"; do
        [ ! -L "$directory" ] || refuse_registry_health "$directory" symlink
        if [ ! -d "$directory" ]; then
            mkdir -- "$directory" 2>/dev/null || {
                [ -d "$directory" ] && [ ! -L "$directory" ] \
                    || refuse_registry_health "$directory" mkdir
            }
        fi
        [ -d "$directory" ] && [ ! -L "$directory" ] \
            || refuse_registry_health "$directory" directory_changed
    done

    # df/test -w miss per-user EDQUOT and delayed write errors. Exercise actual
    # file creation, a nonempty write, rename, read-back and cleanup in each
    # record directory. Random PRIVATE subdirectories never match record globs
    # and allow simultaneous health checks without acquiring the registry flock.
    # No syncfs here: a liveness probe must not flush every compiler's dirty pages.
    for directory in "$registry" "$registry/released" \
        "$registry/cancelled" "$registry/quarantine"; do
        (
            scratch=$(mktemp -d "$directory/.health-probe.XXXXXXXXXX") \
                || refuse_registry_health "$directory" create
            cleanup_registry_health() {
                # Only our two scratch names can be removed. Never recurse or
                # traverse a replacement symlink, even on a failure/signal path.
                [ -d "$scratch" ] && [ ! -L "$scratch" ] || return 1
                rm -f -- "$scratch/write" "$scratch/renamed" && rmdir -- "$scratch"
            }
            trap 'outcome=$?; trap - 0; if ! cleanup_registry_health; then
                printf "RCH_SOURCE_REGISTRY_UNWRITABLE %s: cleanup\n" "$directory" >&2
                outcome=74
            fi; exit "$outcome"' 0
            trap 'exit 74' 1 2 15
            printf '%s\n' RCH_SOURCE_REGISTRY_HEALTH_V1 > "$scratch/write" \
                || refuse_registry_health "$directory" write
            mv -- "$scratch/write" "$scratch/renamed" \
                || refuse_registry_health "$directory" rename
            actual=$(cat -- "$scratch/renamed") \
                || refuse_registry_health "$directory" read
            [ "$actual" = RCH_SOURCE_REGISTRY_HEALTH_V1 ] \
                || refuse_registry_health "$directory" readback
        ) || exit 74
    done
    printf 'health_check\n'
)
