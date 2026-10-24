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
if [ -e package.json ] || [ -L package.json ]; then
    if rch-wkr prepare --project . --runtime "$1" </dev/null 1>&2; then
        :
    else
        rch_prepare_status=$?
        printf 'rch: remote dependency preparation failed (exit %s); the command was not run\n' \
            "$rch_prepare_status" >&2
        exit 121
    fi
    if [ -d node_modules/.bin ]; then
        # The workload can change directory before invoking a project tool.
        # A relative PATH entry would then select another package's compiler
        # (or a global one), not the tools whose installation just succeeded.
        # Resolve the prepared bin directory now, independently of PWD/CDPATH.
        # Keep pwd's terminating newline distinct from newlines in the path.
        rch_prepare_bin=$(CDPATH= cd node_modules/.bin && pwd -P && printf x) || {
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
    fi
fi
shift
exec "$@"
