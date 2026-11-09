# Private worker entrypoint beneath the existing disk monitor. Its arguments
# are structured by prepared.rs; the original command never enters this script
# as shell source. Preparation and the selected workload share the same owner,
# budget, cwd, environment and streams.
rch_worker_prepare_binary=$1
rch_worker_prepare_project=$2
rch_worker_prepare_runtime=$3
rch_worker_prepare_original=$4
shift 4

# Preserve the exact newline, NUL bytes and terminal status in a bounded frame,
# matching the dispatcher preparation protocol. Preparation never consumes the
# workload's stdin or places its layout marker on the compiler's stdout.
rch_worker_prepare_output=$(
    {
        "$rch_worker_prepare_binary" prepare --project "$rch_worker_prepare_project" \
            --runtime "$rch_worker_prepare_runtime" --execution-layout </dev/null
        rch_worker_prepare_status=$?
        printf 'RCH_PREPARE_STATUS:%s' "$rch_worker_prepare_status"
    } | head -c 256 | od -An -v -tx1
) || exit 121
rch_worker_prepare_node=$(printf '%s\nRCH_PREPARE_STATUS:0' RCH_PREPARED_NODE_MODULES | od -An -v -tx1) || exit 121
rch_worker_prepare_pnp=$(printf '%s\nRCH_PREPARE_STATUS:0' RCH_PREPARED_YARN_PNP | od -An -v -tx1) || exit 121
case "$rch_worker_prepare_output" in
    "$rch_worker_prepare_node")
        # Only this layout uses .bin. Adding it before preparation could let a
        # retained .bin/yarn replace the manager selected by the original PATH.
        PATH="$rch_worker_prepare_project/node_modules/.bin${PATH+:$PATH}"
        export PATH
        exec sh -c "$rch_worker_prepare_original"
        ;;
    "$rch_worker_prepare_pnp")
        if [ "$rch_worker_prepare_runtime" != node ] || [ "$#" = 0 ]; then
            printf 'rch-wkr: Yarn PnP requires literal tsc --noEmit --incremental false --composite false arguments; the command was not run\n' >&2
            exit 121
        fi
        exec yarn "$@"
        ;;
    *)
        printf 'rch-wkr: dependency preparation failed or returned an unknown layout; the command was not run\n' >&2
        exit 121
        ;;
esac
