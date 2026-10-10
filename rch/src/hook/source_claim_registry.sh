# This short transaction runs under the registry flock. The caller retains the
# complete source hierarchy independently; no descriptor number is repurposed.
set -eu
umask 077
registry=$1
token=$2
digest=$3
operation=$4
requested=$(cat)
active="$registry/$token.$digest.claim"
pending="$registry/$token.$digest.pending"
released="$registry/released/$token.$digest.claim"
cancelled="$registry/cancelled/$token.$digest.claim"
cancelling="$registry/$token.$digest.cancelling"

refuse() {
    printf 'RCH: durable source ownership: %s\n' "$1" >&2
    exit 73
}

validate_record() {
    rch_claim_record_valid "$1" || refuse 'invalid claim record'
}

matches_request() {
    validate_record "$1"
    printf '%s\n' "$requested" | cmp -s - "$1" || refuse 'source claim roots changed'
}

physical_batch() {
    # Keep every delimiter, including the last one. One output record per
    # argument is essential: a newline in a symlink target must not turn one
    # root into several apparently independent roots. realpath emits at least
    # one line per input, so any embedded newline makes the count disagree.
    physical=$(realpath -m -- "$@" && printf '.') || refuse 'cannot resolve physical source root'
    physical=${physical%.}
    newline='
'
    case "$physical" in *"$newline") ;; *) refuse 'incomplete physical source roots' ;; esac
    printf '%s' "$physical" | LC_ALL=C awk -v expected="$#" '
        substr($0, 1, 1) != "/" || index($0, "\r") { bad = 1 }
        END { if (bad || NR != expected) exit 1 }
    ' || refuse 'ambiguous physical source root'
    printf '%s' "$physical"
}

physical_roots() {
    # This runs inside command substitution, not in the transaction shell.
    # Count bytes, not locale-dependent characters, and bound both argv bytes
    # and argc. The closure itself may be 32 MiB and must remain on stdin.
    # No physical result is cached across transactions: aliases may change.
    LC_ALL=C
    export LC_ALL
    set --
    batch_bytes=0
    while IFS= read -r batch_root || [ -n "$batch_root" ]; do
        root_bytes=$((${#batch_root} + 1))
        [ "$root_bytes" -le 61440 ] || refuse 'physical source root exceeds argument budget'
        if [ "$#" -ge 64 ] || [ "$((batch_bytes + root_bytes))" -gt 61440 ]; then
            physical_batch "$@"
            set --
            batch_bytes=0
        fi
        set -- "$@" "$batch_root"
        batch_bytes=$((batch_bytes + root_bytes))
    done
    if [ "$#" -gt 0 ]; then
        physical_batch "$@"
    fi
}

closures_overlap() {
    # Index path COMPONENTS, not every requested/held pair. Large dependency
    # closures must not do quadratic shell work while excluding the entire
    # worker registry. A trie stores each component once, rather than copying
    # every ancestor prefix of every root. Names remain literal byte strings.
    # The roots stay on stdin (never awk -v or exec argv, both of which impose
    # extra interpretation/size limits). $2 selects a validated record file or
    # already resolved roots. Explicit framing detects a failed producer even
    # on POSIX shells without pipefail; no partial inventory proves disjointness.
    overlap_verdict=$(
        {
            printf '%s\n' "$1" &&
            printf 'RCH_HELD_ROOTS_BEGIN\n' &&
            {
                case "$2" in
                    file) cat -- "$3" ;;
                    roots) printf '%s\n' "$3" ;;
                    *) false ;;
                esac
            } &&
            printf 'RCH_ROOTS_END\n'
        } | LC_ALL=C awk '
            BEGIN { nodes = 1; phase = 0 }
            $0 == "RCH_HELD_ROOTS_BEGIN" {
                if (phase != 0 || !wanted) bad = 1
                phase = 1
                next
            }
            $0 == "RCH_ROOTS_END" {
                if (phase != 1 || !held) bad = 1
                phase = 2
                next
            }
            {
                if (phase > 1 || substr($0, 1, 1) != "/" ||
                    index($0, "\r") || index($0, sprintf("%c", 0))) {
                    bad = 1
                    next
                }
                count = split($0, parts, "/")
                if ($0 == "/") count = 1
                for (i = 2; i <= count; i++) {
                    if (parts[i] == "" || parts[i] == "." || parts[i] == "..") bad = 1
                }
                if (bad) next
                node = 1
                if (phase == 0) {
                    wanted++
                    for (i = 2; i <= count; i++) {
                        key = node SUBSEP parts[i]
                        if (!(key in child)) {
                            # Bound index memory as well as the record bytes.
                            if (nodes >= 1000000) { bad = 1; break }
                            child[key] = ++nodes
                        }
                        node = child[key]
                    }
                    terminal[node] = 1
                } else {
                    held++
                    if (terminal[node]) overlap = 1
                    for (i = 2; i <= count; i++) {
                        key = node SUBSEP parts[i]
                        if (!(key in child)) break
                        node = child[key]
                        if (terminal[node]) overlap = 1
                    }
                    # The held root ended inside the requested trie: it is
                    # equal to, or an ancestor of, at least one wanted root.
                    if (i > count) overlap = 1
                }
            }
            END {
                if (bad || phase != 2 || !wanted || !held) exit 73
                print overlap ? "overlap" : "disjoint"
            }
        '
    ) || refuse 'cannot compare complete source root closures'
    # An awk error exit is NOT a no-overlap answer. Require a complete verdict
    # and success status, rather than treating an arbitrary nonzero as false.
    case "$overlap_verdict" in
        overlap) return 0 ;;
        disjoint) return 1 ;;
        *) refuse 'invalid source root comparison verdict' ;;
    esac
}

# An identity is bound to one exact closure for its entire history, including
# cancellation before acquisition and receipts after the active slot is gone.
for previous in "$registry/$token."*.claim "$registry/$token."*.pending \
    "$registry/$token."*.cancelling "$registry/released/$token."*.claim \
    "$registry/cancelled/$token."*.claim; do
    [ -e "$previous" ] || [ -L "$previous" ] || continue
    case "$previous" in *.pending)
        if ! rch_claim_record_valid "$previous"; then
            rch_claim_quarantine_pending "$registry" "$previous" || refuse 'cannot quarantine pending claim'
            continue
        fi
        ;;
        *.cancelling)
        if rch_claim_quarantine_fence "$registry" "$previous"; then
            continue
        fi
        ;;
    esac
    matches_request "$previous"
done

# Quarantining an incomplete write must never let its delayed acquire/recover
# become a new grant. The filename still binds the original roots digest.
# Cancellation may fence that exact unexecuted intent without granting cleanup
# authority; a valid active record, if any, remains independently required.
for previous in "$registry/quarantine/$token."*.pending; do
    [ -e "$previous" ] || [ -L "$previous" ] || continue
    [ ! -L "$previous" ] && [ -f "$previous" ] || refuse 'invalid quarantined claim'
    [ "$previous" = "$registry/quarantine/$token.$digest.pending" ] || refuse 'quarantined source identity roots changed'
    case "$operation" in acquire|recover) refuse 'source intent has an incomplete quarantined claim' ;; esac
done

if [ "$operation" = cancel ]; then
    if [ -e "$released" ] || [ -L "$released" ]; then
        refuse 'executed source grant was released, not cancelled'
    fi
    if [ -e "$cancelled" ] || [ -L "$cancelled" ]; then
        matches_request "$cancelled"
        printf unowned
        exit 0
    fi
    if rch_claim_quarantine_fence "$registry" "$cancelling"; then
        # No source activity was granted. Publish the exact caller-bound
        # cancellation receipt while retaining the legacy refusal fence.
        rch_claim_write_atomic "$registry" "$cancelled" "$digest" "$requested" || refuse 'cannot persist quarantined source cancellation'
        matches_request "$cancelled"
        sync -f "$registry/cancelled"
        sync -f "$registry"
        printf unowned
        exit 0
    fi
    if [ -e "$active" ] || [ -L "$active" ]; then
        matches_request "$active"
        [ ! -e "$pending" ] && [ ! -L "$pending" ] || refuse 'duplicate source grant'
    elif [ -e "$pending" ] || [ -L "$pending" ]; then
        matches_request "$pending"
        # Complete only an already persisted identical pending claim. It has
        # already excluded competing owners, even if readiness was not sent.
        sync -f "$pending"
        mv -- "$pending" "$active"
    fi
    if [ -e "$cancelling" ] || [ -L "$cancelling" ]; then
        matches_request "$cancelling"
    else
        rch_claim_write_atomic "$registry" "$cancelling" "$digest" "$requested" || refuse 'cannot persist source cancellation'
        matches_request "$cancelling"
    fi
    sync -f "$cancelling"
    if [ -e "$active" ]; then
        # Keep the active record as a durable overlap blocker through cleanup.
        # Normal activity refuses this marker; cleanup gets its own checked
        # activity mode and finish-cancel waits for that activity to drain.
        sync -f "$registry"
        printf owned
    else
        # An absent intent never acquired source rights. Its tombstone fences
        # delayed acquisition but grants no authority to inspect/remove a tree.
        mv -- "$cancelling" "$cancelled"
        sync -f "$cancelled"
        sync -f "$registry/cancelled"
        sync -f "$registry"
        printf unowned
    fi
    exit 0
fi

if [ "$operation" = finish-cancel ]; then
    if [ -e "$cancelled" ] || [ -L "$cancelled" ]; then
        matches_request "$cancelled"
        [ ! -e "$active" ] && [ ! -L "$active" ] || refuse 'duplicate cancelled grant'
        exit 0
    fi
    matches_request "$cancelling"
    matches_request "$active"
    [ ! -e "$pending" ] && [ ! -L "$pending" ] || refuse 'unfinished claim transition'
    mv -- "$active" "$cancelled"
    sync -f "$cancelled"
    sync -f "$registry/cancelled"
    sync -f "$registry"
    exit 0
fi

if [ "$operation" = released ]; then
    if [ -e "$released" ] || [ -L "$released" ]; then
        matches_request "$released"
        printf released
    else
        printf pending
    fi
    exit 0
fi

if [ "$operation" = release ]; then
    # The receipt is the original claim, never a newly manufactured token.
    # An acknowledged move therefore proves this exact set ceased to be active.
    matches_request "$active"
    [ ! -e "$cancelling" ] && [ ! -L "$cancelling" ] || refuse 'source grant is cancelling'
    [ ! -e "$pending" ] && [ ! -L "$pending" ] || refuse 'unfinished claim transition'
    [ ! -e "$released" ] && [ ! -L "$released" ] || refuse 'duplicate release receipt'
    mv -- "$active" "$released"
    sync -f "$released"
    sync -f "$registry/released"
    sync -f "$registry"
    exit 0
fi

case "$operation" in acquire|recover) ;; *) refuse 'unknown claim operation' ;; esac
[ ! -e "$released" ] && [ ! -L "$released" ] || refuse 'source grant already released'
[ ! -e "$cancelled" ] && [ ! -L "$cancelled" ] || refuse 'source intent cancelled'
[ ! -e "$cancelling" ] && [ ! -L "$cancelling" ] || refuse 'source intent cancellation is unfinished'

# Preserve lexical roots as immutable identity, but compare physical aliases
# too. A durable GC claim uses its physical candidate path and must also fence
# a source writer reaching that same tree through a worker-side symlink.
# Resolve in bounded batches while holding the same registry lock. A resolver
# failure in ANY batch refuses the whole closure before publishing a claim.
requested_physical=$(
    physical_roots <<RCH_REQUESTED_ROOTS
$requested
RCH_REQUESTED_ROOTS
) || refuse 'cannot resolve physical source roots'

# Complete pending records retain their source exclusion. Incomplete legacy
# writes cannot have authorized activity and are quarantined under this lock;
# active-record corruption still refuses admission because ownership is unknown.
for held in "$registry"/*.claim "$registry"/*.pending; do
    [ -e "$held" ] || [ -L "$held" ] || continue
    case "$held" in *.pending)
        if ! rch_claim_record_valid "$held"; then
            rch_claim_quarantine_pending "$registry" "$held" || refuse 'cannot quarantine pending claim'
            continue
        fi
        ;;
    esac
    validate_record "$held"
    case "${held##*/}" in "$token".*)
        [ "$operation" = recover ] || refuse 'source identity already claimed'
        [ "$held" = "$active" ] || [ "$held" = "$pending" ] || refuse 'source identity roots changed'
        matches_request "$held"
        continue
        ;;
    esac
    if closures_overlap "$requested" file "$held"; then
        refuse 'unfinished overlapping source owner'
    fi
    held_physical=$(physical_roots < "$held") || refuse 'cannot resolve physical source roots'
    if closures_overlap "$requested_physical" roots "$held_physical"; then
        refuse 'unfinished overlapping physical source owner'
    fi
done

if [ "$operation" = recover ]; then
    if [ -e "$active" ] || [ -L "$active" ]; then
        matches_request "$active"
        [ ! -e "$pending" ] && [ ! -L "$pending" ] || refuse 'duplicate source grant'
        exit 0
    fi
    # Only an already-written complete claim may finish its interrupted rename.
    # Missing state never grants recovery authority, even for the same token.
    matches_request "$pending"
else
    [ ! -e "$active" ] && [ ! -L "$active" ] || refuse 'source grant already exists'
    [ ! -e "$pending" ] && [ ! -L "$pending" ] || refuse 'pending source grant already exists'
    rch_claim_write_atomic "$registry" "$pending" "$digest" "$requested" || refuse 'cannot persist source claim'
    matches_request "$pending"
fi
sync -f "$pending"
mv -- "$pending" "$active"
sync -f "$registry"
