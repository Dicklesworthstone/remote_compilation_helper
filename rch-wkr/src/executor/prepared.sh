# Private worker entrypoint beneath the existing disk monitor. Its arguments
# are structured by prepared.rs; the original command never enters this script
# as shell source. Preparation and the selected workload share the same owner,
# budget, cwd, environment and streams.
rch_worker_prepare_binary=$1
rch_worker_prepare_project=$2
rch_worker_prepare_root=$3
rch_worker_prepare_runtime=$4
rch_worker_prepare_original=$5
shift 5

# Preserve the exact newline, NUL bytes and terminal status in a bounded frame,
# matching the dispatcher preparation protocol. Preparation never consumes the
# workload's stdin or places its layout marker on the compiler's stdout.
rch_worker_prepare_output=$(
    {
        "$rch_worker_prepare_binary" prepare --project "$rch_worker_prepare_project" \
            --runtime "$rch_worker_prepare_runtime" --execution-layout --workspace-root \
            --expected-preparation-root "$rch_worker_prepare_root" </dev/null
        rch_worker_prepare_status=$?
        printf 'RCH_PREPARE_STATUS:%s' "$rch_worker_prepare_status"
    } | head -c 256 | od -An -v -tx1
) || exit 121
rch_worker_prepare_layout=unknown
rch_worker_prepare_parents=0
while [ "$rch_worker_prepare_parents" -le 64 ]; do
    rch_worker_prepare_node=$(printf '%s\nRCH_PREPARE_STATUS:0' "RCH_PREPARED_NODE_MODULES:$rch_worker_prepare_parents" | od -An -v -tx1) || exit 121
    rch_worker_prepare_pnp=$(printf '%s\nRCH_PREPARE_STATUS:0' "RCH_PREPARED_YARN_PNP:$rch_worker_prepare_parents" | od -An -v -tx1) || exit 121
    case "$rch_worker_prepare_output" in
        "$rch_worker_prepare_node") rch_worker_prepare_layout=node_modules; break ;;
        "$rch_worker_prepare_pnp") rch_worker_prepare_layout=yarn_pnp; break ;;
    esac
    rch_worker_prepare_parents=$((rch_worker_prepare_parents + 1))
done
case "$rch_worker_prepare_layout" in
    node_modules)
        # Only this layout uses .bin. Adding it before preparation could let a
        # retained .bin/yarn replace the manager selected by the original PATH.
        rch_worker_prepare_add_bin() {
            [ -d "$1/node_modules/.bin" ] || return 0
            rch_worker_prepare_bin=$(CDPATH= cd "$1/node_modules/.bin" && pwd -P && printf x) || exit 121
            rch_worker_prepare_bin=${rch_worker_prepare_bin%?}
            rch_worker_prepare_bin=${rch_worker_prepare_bin%?}
            case "$rch_worker_prepare_bin" in
                *:*|'') printf 'rch-wkr: prepared tool directory cannot enter PATH; the command was not run\n' >&2; exit 121 ;;
                /*) ;;
                *) exit 121 ;;
            esac
            PATH="$rch_worker_prepare_bin${PATH+:$PATH}"
            export PATH
        }
        rch_worker_prepare_ancestor_bins() {
            [ "$2" -le 64 ] || exit 121
            if [ "$1" != "$rch_worker_prepare_root" ]; then
                case "$rch_worker_prepare_root:$1" in
                    /:/*) ;;
                    *) case "$1" in "$rch_worker_prepare_root"/*) ;; *) exit 121 ;; esac ;;
                esac
                case "${1%/*}" in
                    '') rch_worker_prepare_ancestor_bins / "$(($2 + 1))" ;;
                    *) rch_worker_prepare_ancestor_bins "${1%/*}" "$(($2 + 1))" ;;
                esac
            fi
            rch_worker_prepare_add_bin "$1"
        }
        rch_worker_prepare_ancestor_bins "$rch_worker_prepare_project" 0
        exec sh -c "$rch_worker_prepare_original"
        ;;
    yarn_pnp)
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
