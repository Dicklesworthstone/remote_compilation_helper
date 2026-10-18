# Read-only, request-local Git status census. No persistent cache or temp files.
# Each root is a line of POSIX printf octal escapes, preserving opaque path bytes.
# The caller retains source authority through this entire worker-side process.
set -eu
set -f
LC_ALL=C
export LC_ALL

# Relative Git environment overrides can make two invocations below one
# toplevel inspect different indexes/object stores. Batch their transport, but
# do not reuse an observation across roots under any inherited Git override.
environment=$(env) || exit 73
memoize=true
case "
$environment" in *'
GIT_'*) memoize=false ;; esac

refuse() {
    printf 'RCH: incomplete repository status census\n' >&2
    exit 73
}

IFS= read -r header || refuse
[ "$header" = RCH_REPO_STATUS_REQUEST_V1 ] || refuse
printf 'RCH_REPO_STATUS_V1\n'
index=0
memo='
'
newline='
'
complete=false
while IFS= read -r encoded; do
    if [ "$encoded" = RCH_REPO_STATUS_REQUEST_END ]; then
        complete=true
        break
    fi
    [ "$index" -lt 64 ] && [ "${#encoded}" -le 81920 ] || refuse
    # Never evaluate incoming text as shell. %b sees only complete, non-NUL
    # byte escapes and an absolute path, not arbitrary escape instructions.
    printf '%s\n' "$encoded" | awk '
        NR != 1 || $0 !~ /^(\\0[0-3][0-7][0-7])+$/ ||
        substr($0, 1, 5) != "\\0057" || index($0, "\\0000") { bad = 1 }
        END { if (bad || NR != 1) exit 1 }
    ' || refuse
    root=$(printf '%b.' "$encoded") || refuse
    root=${root%.}
    state=unavailable
    # The sentinel preserves even a toplevel ending in a newline. Remove only
    # Git's final record separator. Linked worktrees have distinct toplevels.
    if top=$(GIT_OPTIONAL_LOCKS=0 git -C "$root" rev-parse --show-toplevel 2>/dev/null && printf '.'); then
        top=${top%.}
        case "$top" in *"$newline") top=${top%"$newline"} ;; *) refuse ;; esac
        case "$top" in /*) ;; *) refuse ;; esac
        # Canonical hex is an unambiguous in-memory memo key, not a filename.
        # Check od's status and exact byte count; partial output cannot alias a
        # previously clean worktree. printf is the only pipeline producer.
        octets=$(printf '%s' "$top" | od -An -v -tx1) || refuse
        key=
        for byte in $octets; do
            case "$byte" in [0-9a-f][0-9a-f]) key=$key$byte ;; *) refuse ;; esac
        done
        [ "${#key}" -eq "$((${#top} * 2))" ] || refuse
        cached=false
        if [ "$memoize" = true ]; then
            case "$memo" in
                *"$newline$key clean$newline"*) state=clean; cached=true ;;
                *"$newline$key dirty$newline"*) state=dirty; cached=true ;;
            esac
        fi
        if [ "$cached" = false ]; then
            # Porcelain v1 quotes embedded control characters in pathnames, so
            # a filename cannot manufacture our terminal marker. Drain status
            # output instead of buffering a large dirty worktree in the shell.
            state=$(
                {
                    if GIT_OPTIONAL_LOCKS=0 git -c core.quotePath=true -C "$root" status --porcelain=v1 2>/dev/null; then
                        printf 'RCH_GIT_STATUS_SUCCESS\n'
                    else
                        printf 'RCH_GIT_STATUS_FAILURE\n'
                    fi
                } | awk '
                    $0 == "RCH_GIT_STATUS_SUCCESS" || $0 == "RCH_GIT_STATUS_FAILURE" {
                        if (finished) bad = 1
                        finished = 1
                        success = ($0 == "RCH_GIT_STATUS_SUCCESS")
                        next
                    }
                    { if (finished) bad = 1; dirty = 1 }
                    END {
                        if (bad || !finished) exit 73
                        print success ? (dirty ? "dirty" : "clean") : "unavailable"
                    }
                '
            ) || refuse
            case "$state" in clean|dirty|unavailable) ;; *) refuse ;; esac
            # Failures are not memoized. No later root gets a cached assertion
            # that its repository was inspected after a failed Git invocation.
            if [ "$state" != unavailable ]; then
                memo="$memo$key $state$newline"
            fi
        fi
    fi
    printf '%s %s\n' "$index" "$state"
    index=$((index + 1))
done
[ "$complete" = true ] || refuse
# EOF is part of the request frame, including a non-newline-terminated suffix.
if IFS= read -r extra || [ -n "$extra" ]; then
    refuse
fi
printf 'RCH_REPO_STATUS_END %s\n' "$index"
