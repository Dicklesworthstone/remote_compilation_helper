# Part of the workload, never an untracked SSH setup step. The caller places
# this wrapper inside the same environment, timeout and process-group owner as
# the compiler. Preparation metadata must never enter the compiler's stdout.
# Do not use node_modules existence as a freshness proof: the worker owns the
# fingerprint, cross-process transaction and interrupted-install refusal.
# The runtime is selected by the classified compilation kind, never guessed
# from shell text. It is only a hint for lockfile-free projects; the worker
# remains authoritative about locked package-manager selection.
case "${1-}" in
    node|bun) ;;
    *) printf 'rch: invalid dependency preparation runtime; the command was not run\n' >&2
       exit 121 ;;
esac
if [ "$#" -lt 2 ]; then
    printf 'rch: missing prepared workload; the command was not run\n' >&2
    exit 121
fi
rch_prepare_runtime=$1
shift
rch_prepare_proved=0
rch_prepare_project=.
rch_prepare_workspace=0
rch_prepare_layout=node_modules
rch_prepare_tsc_arguments=0
# A success status alone does not describe how project tools are resolved.
# Keep the worker's final newline and status in a bounded frame; command
# substitution must not erase extra blank records or accept truncated output.
# Hex encoding also preserves NUL bytes that a shell variable cannot hold.
# Installer diagnostics already go to stderr and never enter this selector.
rch_prepare_capture() {
    rch_prepare_output=$(
        {
            "$@" </dev/null
            rch_prepare_status=$?
            printf 'RCH_PREPARE_STATUS:%s' "$rch_prepare_status"
        } | head -c 256 | od -An -v -tx1
    ) || {
        printf 'rch: dependency layout could not be read; the command was not run\n' >&2
        exit 121
    }
}
rch_prepare_select_layout() {
    rch_prepare_node_modules=$(printf '%s\nRCH_PREPARE_STATUS:0' "$1" | od -An -v -tx1) || return 1
    rch_prepare_yarn_pnp=$(printf '%s\nRCH_PREPARE_STATUS:0' "$2" | od -An -v -tx1) || return 1
    case "$rch_prepare_output" in
        "$rch_prepare_node_modules") rch_prepare_layout=node_modules ;;
        "$rch_prepare_yarn_pnp") rch_prepare_layout=yarn_pnp ;;
        *) return 1 ;;
    esac
}
if [ "${1-}" = --source-proof ]; then
    if [ "$#" -lt 4 ]; then
        printf 'rch: incomplete dependency proof binding; the command was not run\n' >&2
        exit 121
    fi
    rch_prepare_request=$2
    rch_prepare_attestation=$3
    shift 3
    if [ "${1-}" = --preparation-root ]; then
        if [ "$#" -lt 3 ]; then
            printf 'rch: incomplete workspace preparation binding; the command was not run\n' >&2
            exit 121
        fi
        rch_prepare_project=$2
        case "$rch_prepare_project" in
            /*) ;;
            *) printf 'rch: workspace preparation root is not absolute; the command was not run\n' >&2
               exit 121 ;;
        esac
        rch_prepare_workspace=1
        shift 2
    fi
    # The accepted request is durable worker state. Only its small digests
    # cross exec argv; the complete source manifest never enters shell argv.
    # A workspace proof additionally binds this actual invocation directory;
    # verifying the root's outputs cannot authorize another member's command.
    rch_prepare_verify() {
        if [ "$rch_prepare_workspace" = 1 ]; then
            set -- --invocation-project .
        fi
        rch-wkr prepare-proof --mode verify --project "$rch_prepare_project" \
            --runtime "$rch_prepare_runtime" --expected-request-digest "$rch_prepare_request" \
            --expected-attestation-digest "$rch_prepare_attestation" "$@"
    }
    rch_prepare_capture rch_prepare_verify
    if ! rch_prepare_select_layout RCH_PREPARED_DEPENDENCIES_VERIFIED RCH_PREPARED_DEPENDENCIES_VERIFIED_YARN_PNP; then
        printf 'rch: prepared dependency verification failed or returned an unknown layout; the command was not run\n' >&2
        exit 121
    fi
    rch_prepare_proved=1
fi
if [ "${1-}" = --pnp-tsc ]; then
    if [ "$#" -lt 3 ]; then
        printf 'rch: incomplete PnP TypeScript arguments; the command was not run\n' >&2
        exit 121
    fi
    rch_prepare_tsc_arguments=$2
    shift 2
    case "$rch_prepare_tsc_arguments" in
        ''|*[!0-9]*|0*)
            printf 'rch: invalid PnP TypeScript argument count; the command was not run\n' >&2
            exit 121 ;;
    esac
    if [ "${#rch_prepare_tsc_arguments}" -gt 3 ] ||
       [ "$rch_prepare_tsc_arguments" -gt 256 ] ||
       [ "$#" -le "$rch_prepare_tsc_arguments" ]; then
        printf 'rch: PnP TypeScript argument count exceeds its payload; the command was not run\n' >&2
        exit 121
    fi
fi
if [ "$rch_prepare_proved" = 1 ] || [ -e package.json ] || [ -L package.json ]; then
    if [ "$rch_prepare_proved" = 1 ]; then
        :
    else
        rch_prepare_capture rch-wkr prepare --project . --runtime "$rch_prepare_runtime" --execution-layout
        if ! rch_prepare_select_layout RCH_PREPARED_NODE_MODULES RCH_PREPARED_YARN_PNP; then
            printf 'rch: remote dependency preparation failed or returned an unknown layout; the command was not run\n' >&2
            exit 121
        fi
    fi
    if [ "$rch_prepare_layout" = yarn_pnp ]; then
        if [ "$rch_prepare_runtime" != node ]; then
            printf 'rch: Yarn PnP requires the Node runtime; the command was not run\n' >&2
            exit 121
        fi
        if [ "$rch_prepare_tsc_arguments" = 0 ]; then
            printf 'rch: Yarn PnP requires literal tsc --noEmit --incremental false --composite false arguments; the command was not run\n' >&2
            exit 121
        fi
        # Rotate the validated literal compiler arguments behind the original
        # shell payload, then discard that payload. No shell/env wrapper can
        # clear Yarn's loader or substitute a global compiler after admission.
        rch_prepare_original_arguments=$(($# - rch_prepare_tsc_arguments))
        while [ "$rch_prepare_tsc_arguments" -gt 0 ]; do
            rch_prepare_argument=$1
            shift
            set -- "$@" "$rch_prepare_argument"
            rch_prepare_tsc_arguments=$((rch_prepare_tsc_arguments - 1))
        done
        while [ "$rch_prepare_original_arguments" -gt 0 ]; do
            shift
            rch_prepare_original_arguments=$((rch_prepare_original_arguments - 1))
        done
        # Binary-only lookup refuses missing project dependencies and ignores
        # package scripts. Yarn supplies PnP and preserves this invocation cwd.
        exec yarn run --binaries-only tsc "$@"
    fi
    rch_prepare_add_bin() {
        [ -d "$1/node_modules/.bin" ] || return 0
        # The workload can change directory before invoking a project tool.
        # A relative PATH entry would then select another package's compiler
        # (or a global one), not the tools whose installation just succeeded.
        # Resolve the prepared bin directory now, independently of PWD/CDPATH.
        # Keep pwd's terminating newline distinct from newlines in the path.
        rch_prepare_bin=$(CDPATH= cd "$1/node_modules/.bin" && pwd -P && printf x) || {
            printf 'rch: prepared tool directory is unavailable; the command was not run\n' >&2
            exit 121
        }
        rch_prepare_bin=${rch_prepare_bin%?}
        rch_prepare_bin=${rch_prepare_bin%?}
        case "$rch_prepare_bin" in
            /*) ;;
            *) printf 'rch: prepared tool directory is not absolute; the command was not run\n' >&2
               exit 121 ;;
        esac
        # PATH has no quoting for a literal colon. Do not silently turn one
        # prepared directory into several unrelated executable search roots.
        case "$rch_prepare_bin" in
            *:*) printf 'rch: prepared tool directory contains a PATH separator; the command was not run\n' >&2
                 exit 121 ;;
        esac
        PATH="$rch_prepare_bin${PATH:+:$PATH}"
        export PATH
    }
    # Prepend the shared root first, then the member. Member-local tools win,
    # and hoisted tools remain available after the workload changes directory.
    if [ "$rch_prepare_workspace" = 1 ]; then
        rch_prepare_add_bin "$rch_prepare_project"
    fi
    rch_prepare_add_bin .
fi
while [ "$rch_prepare_tsc_arguments" -gt 0 ]; do
    shift
    rch_prepare_tsc_arguments=$((rch_prepare_tsc_arguments - 1))
done
exec "$@"
