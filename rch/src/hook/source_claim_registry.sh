# This short transaction runs under the registry flock. Source admission and
# recovery callers retain their complete source hierarchy independently. The
# create-only topology operation instead retains this mutex through mutation;
# shared translation parents never become a build's durable source grant.
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
legacy_registry=${RCH_LEGACY_SOURCE_CLAIM_REGISTRY-}
if [ -z "$legacy_registry" ] && [ "$registry" = "/var/tmp/rch-source-authority-locks/claims-v1" ]; then
    legacy_registry="/tmp/rch-source-authority-locks/claims-v1"
fi

# This transaction already names every record and containing-directory barrier.
# GNU sync -f calls syncfs, and uutils 0.10 sync FILE calls global sync(). Both
# can wait for unrelated builds while holding the worker-wide registry flock.
# Explicit fsync preserves data, metadata and every checked directory barrier.
# The local adapter also covers the shared record helpers without changing
# their GC callers outside this transaction. Topology's -d calls also need a
# directory fsync, not an implementation-dependent utility invocation. Python
# is already required by namespace custody. Missing Python fails closed.
sync() {
    case "${1-}" in
        -f|-d)
            shift
            if [ "${1-}" = -- ]; then shift; fi
            [ "$#" -eq 1 ] && [ -n "$1" ] || return 1
            python3 -I -S -c 'import os, sys
fd = os.open(sys.argv[1], os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
try: os.fsync(fd)
finally: os.close(fd)' "$1"
            ;;
        *) return 1 ;;
    esac
}

refuse() {
    printf 'RCH: durable source ownership: %s\n' "$1" >&2
    exit 73
}

# Only a validated overlap before a grant exists may request admission retry.
# Recovery and the original acquire operation retain their fail-closed contract.
busy() {
    case "$operation" in
        try-acquire|topology)
            printf 'RCH: durable source ownership: %s\n' "$1" >&2
            exit 75
            ;;
        *) refuse "$1" ;;
    esac
}

validate_record() {
    rch_claim_record_valid "$1" || refuse 'invalid claim record'
}

matches_request() {
    validate_record "$1"
    printf '%s\n' "$requested" | cmp -s - "$1" || refuse 'source claim roots changed'
}

# A visible rename is not a durable acknowledgment. An earlier transaction
# may have moved this exact record and then lost its connection or failed its
# final sync. Re-establish the barriers even on an otherwise read-only retry,
# before emitting any authority/retirement verdict. Callers validate the record
# and its state first; this helper never creates, moves or repairs a claim.
confirm_durable_record() {
    sync -f "$1" && sync -f "${1%/*}" \
        || refuse 'cannot confirm durable source record'
    if [ "${1%/*}" != "$registry" ]; then
        sync -f "$registry" || refuse 'cannot confirm durable source transition'
    fi
}

# A mutator's exit status is not proof that the requested alias was established:
# ln -s can succeed inside a raced-in destination directory. Nor is a visible
# namespace necessarily durable after a lost acknowledgement. Revalidate and
# re-establish the barriers on both creation and the already-present fast path,
# publishing exactly one readiness marker only after all checks succeed.
confirm_topology() {
    sh -c "$1" >/dev/null 2>&1 || refuse 'topology validation failed after initialization'
    while IFS= read -r topology_root; do
        [ -d "$topology_root" ] || refuse 'topology root is not a directory'
        # The validated alias can itself be a symlink. Flush its resolved
        # directory and its containing directory, then revalidate topology.
        # The latter persists the alias entry; no-follow record opens remain
        # mandatory everywhere else in the registry.
        topology_resolved=$(rch_realpath_m "$topology_root") || refuse 'cannot resolve topology root'
        topology_parent=$(rch_realpath_m "$(dirname -- "$topology_root")") || refuse 'cannot resolve topology parent'
        sync -d -- "$topology_resolved" && sync -d -- "$topology_parent" \
            || refuse 'cannot confirm durable topology'
    done <<RCH_TOPOLOGY_ROOTS
$requested
RCH_TOPOLOGY_ROOTS
    sh -c "$1" >/dev/null 2>&1 || refuse 'topology changed during confirmation'
    printf 'RCH_TOPOLOGY_OK\n'
}

physical_batch() {
    # Keep every delimiter, including the last one. One output record per
    # argument is essential: a newline in a symlink target must not turn one
    # root into several apparently independent roots. realpath emits at least
    # one line per input, so any embedded newline makes the count disagree.
    physical=$(rch_realpath_m "$@" && printf '.') || refuse 'cannot resolve physical source root'
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
    # extra interpretation/size limits). $2 selects a validated record file,
    # resolved roots, or a complete validated inventory batch. Explicit framing
    # detects a failed producer even
    # on POSIX shells without pipefail; no partial inventory proves disjointness.
    overlap_verdict=$(
        {
            printf '%s\n' "$1" &&
            {
                case "$2" in
                    (inventory) printf 'RCH_HELD_INVENTORY_BEGIN\n' ;;
                    (*) printf 'RCH_HELD_ROOTS_BEGIN\n' ;;
                esac
            } &&
            {
                # Leading-paren patterns: bash 3.2 (macOS /bin/sh) misparses
                # a bare `pattern)` inside $(...) as closing the substitution.
                case "$2" in
                    # BSD awk ends a line at NUL; as CR, which every awk
                    # refuses below, a corrupt record cannot pass as valid.
                    (file) LC_ALL=C tr '\000' '\r' < "$3" ;;
                    (roots) printf '%s\n' "$3" ;;
                    (inventory) emit_held_claim_roots "$3" ;;
                    (*) false ;;
                esac
            } &&
            printf 'RCH_ROOTS_END\n'
        } | LC_ALL=C awk '
            # BSD awk (macOS) cannot hold NUL: sprintf("%c", 0) is "" there,
            # and index(s, "") is 1, which refused every root. A shell value
            # cannot carry NUL either, so the check needs a real NUL to test.
            BEGIN { nodes = 1; phase = 0; nul = sprintf("%c", 0) }
            $0 == "RCH_HELD_ROOTS_BEGIN" || $0 == "RCH_HELD_INVENTORY_BEGIN" {
                if (phase != 0 || !wanted) bad = 1
                inventory = ($0 == "RCH_HELD_INVENTORY_BEGIN")
                phase = 1
                next
            }
            $0 == "RCH_HELD_RECORD_BEGIN" {
                if (phase != 1 || !inventory || record_open) bad = 1
                record_open = 1
                record_roots = 0
                next
            }
            $0 == "RCH_HELD_RECORD_END" {
                if (phase != 1 || !inventory || !record_open || !record_roots) bad = 1
                record_open = 0
                next
            }
            $0 == "RCH_ROOTS_END" {
                if (phase != 1 || !held || record_open) bad = 1
                phase = 2
                next
            }
            {
                if (phase > 1 || (phase == 1 && inventory && !record_open) ||
                    substr($0, 1, 1) != "/" ||
                    index($0, "\r") || (length(nul) == 1 && index($0, nul))) {
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
                    record_roots++
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

# Reuse the requested index for a batch of owners, not once per record. Start
# with one owner so an immediate conflict still returns promptly, then double
# up to 64. This bounds buffered names (~13 KiB), avoids quadratic string
# growth, and checks every owner without building a worker-wide root union.
# Quarantine and identity validation still precede any overlap verdict.
check_held_claims() {
    held_claim_names=
    held_batch_count=0
    held_batch_limit=1
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
        if [ -z "$held_claim_names" ]; then
            held_claim_names=${held##*/}
        else
            held_claim_names="$held_claim_names
${held##*/}"
        fi
        held_batch_count=$((held_batch_count + 1))
        if [ "$held_batch_count" -eq "$held_batch_limit" ]; then
            check_held_claim_batch
        fi
    done
    if [ -n "${legacy_registry-}" ] && [ "$legacy_registry" != "$registry" ] \
        && [ ! -L "$legacy_registry" ] && [ -d "$legacy_registry" ]; then
        for held in "$legacy_registry"/*.claim "$legacy_registry"/*.pending; do
            [ -e "$held" ] || [ -L "$held" ] || continue
            case "$held" in *.pending)
                rch_claim_record_valid "$held" || continue
                ;;
            esac
            validate_record "$held"
            case "${held##*/}" in "$token".*)
                [ "$operation" = recover ] || refuse 'source identity already claimed'
                matches_request "$held"
                continue
                ;;
            esac
            if [ -z "$held_claim_names" ]; then
                held_claim_names=$held
            else
                held_claim_names="$held_claim_names
$held"
            fi
            held_batch_count=$((held_batch_count + 1))
            if [ "$held_batch_count" -eq "$held_batch_limit" ]; then
                check_held_claim_batch
            fi
        done
    fi
    if [ "$held_batch_count" -gt 0 ]; then
        check_held_claim_batch
    fi
}

check_held_claim_batch() {
    if closures_overlap "$requested" inventory lexical; then
        busy 'unfinished overlapping source owner'
    fi
    if closures_overlap "$requested_physical" inventory physical; then
        busy 'unfinished overlapping physical source owner'
    fi
    held_claim_names=
    held_batch_count=0
    if [ "$held_batch_limit" -lt 64 ]; then
        held_batch_limit=$((held_batch_limit * 2))
    fi
}

emit_held_claim_roots() {
    while IFS= read -r held_name; do
        # Individual framing prevents an unterminated/empty record from being
        # hidden by concatenation with the next owner's roots. The outer end
        # marker is emitted ONLY if every read/resolution succeeds.
        case "$held_name" in
            /*) held_path=$held_name ;;
            *) held_path="$registry/$held_name" ;;
        esac
        printf 'RCH_HELD_RECORD_BEGIN\n' || return 1
        case "$1" in
            lexical) LC_ALL=C tr '\000' '\r' < "$held_path" || return 1 ;;
            physical) physical_roots < "$held_path" || return 1 ;;
            *) return 1 ;;
        esac
        printf 'RCH_HELD_RECORD_END\n' || return 1
    done <<RCH_HELD_CLAIM_NAMES
$held_claim_names
RCH_HELD_CLAIM_NAMES
}

prune_terminal_claims() {
    retention_minutes=${RCH_SOURCE_CLAIM_RETENTION_MINUTES:-1440}
    case "$retention_minutes" in
        ''|*[!0-9]*) retention_minutes=1440 ;;
    esac
    for terminal_dir in "$registry/released" "$registry/cancelled"; do
        [ ! -L "$terminal_dir" ] && [ -d "$terminal_dir" ] || continue
        find "$terminal_dir" -maxdepth 1 -type f -name '*.claim' \
            ! -name "$token.*" -mmin +"$retention_minutes" -delete 2>/dev/null || true
    done
}

df_available() {
    {
        IFS= read -r _ || return 1
        read -r _ total _ avail _ || return 1
    } <<RCH_DF_OUTPUT
$1
RCH_DF_OUTPUT
    if [ "${2-}" = inodes ]; then
        case "$total" in ''|0|*[!0-9]*) return 1 ;; esac
    fi
    case "$avail" in ''|*[!0-9]*) return 1 ;; esac
    printf '%s\n' "$avail"
}

check_registry_headroom() {
    min_free_kb=${RCH_REGISTRY_MIN_FREE_KB:-4096}
    case "$min_free_kb" in ''|*[!0-9]*) min_free_kb=4096 ;; esac
    min_free_inodes=${RCH_REGISTRY_MIN_FREE_INODES:-256}
    case "$min_free_inodes" in ''|*[!0-9]*) min_free_inodes=256 ;; esac
    df_kb_out=$(df -Pk -- "$registry" 2>/dev/null) || df_kb_out=
    free_kb=$(df_available "$df_kb_out" blocks) || free_kb=
    if [ -n "$free_kb" ] && [ "$free_kb" -lt "$min_free_kb" ]; then
        printf 'RCH_SOURCE_CLAIM_WRITE_FAILED %s/.headroom-free-kb-%s\n' "$registry" "$free_kb" >&2
        refuse 'source claim registry below reserved headroom'
    fi
    df_inodes_out=$(df -Pi -- "$registry" 2>/dev/null) || df_inodes_out=
    free_inodes=$(df_available "$df_inodes_out" inodes) || free_inodes=
    if [ -n "$free_inodes" ] && [ "$free_inodes" -lt "$min_free_inodes" ]; then
        printf 'RCH_SOURCE_CLAIM_WRITE_FAILED %s/.headroom-free-inodes-%s\n' "$registry" "$free_inodes" >&2
        refuse 'source claim registry below reserved inode headroom'
    fi
}

# rch <= 2.1.16 created .cancelling with a plain `set -C` redirect, so a full
# disk could leave it EMPTY: created, never written, never hard-linked. That
# write came only after any pending claim had been renamed active, so an empty
# record with no claim, pending, receipt or quarantine record of its identity
# never held source rights. Its filename binds this token and roots digest, so
# the cancelling caller's request is its only possible content: rewrite it
# atomically and let cancellation tombstone it as unowned. Every other invalid
# record, and every operation except cancel, still refuses.
repair_empty_legacy_cancelling() {
    [ "$operation" = cancel ] && [ "$1" = "$cancelling" ] || return 0
    [ ! -L "$1" ] && [ -f "$1" ] && [ ! -s "$1" ] || return 0
    for other in "$registry/$token."*.claim "$registry/$token."*.pending \
        "$registry/$token."*.cancelling "$registry/released/$token."* \
        "$registry/cancelled/$token."* "$registry/quarantine/$token."*; do
        [ "$other" = "$1" ] && continue
        [ ! -e "$other" ] && [ ! -L "$other" ] || return 0
    done
    repair=$(mktemp "$registry/.record-write.XXXXXXXXXX") \
        || refuse 'cannot repair empty legacy cancellation'
    if ! printf '%s\n' "$requested" > "$repair" \
        || ! rch_claim_content_valid "$repair" "$digest" \
        || ! sync -f "$repair"; then
        printf 'RCH_SOURCE_CLAIM_WRITE_FAILED %s\n' "$repair" >&2
        refuse 'cannot repair empty legacy cancellation'
    fi
    [ ! -L "$1" ] && [ -f "$1" ] && [ ! -s "$1" ] \
        || refuse 'legacy cancellation changed during repair'
    rch_mv_T "$repair" "$1"
    sync -f "$registry"
    printf 'RCH_SOURCE_CLAIM_REPAIRED_EMPTY_CANCELLATION %s\n' "$1" >&2
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
        repair_empty_legacy_cancelling "$previous"
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
    case "$operation" in acquire|try-acquire|recover|topology) refuse 'source intent has an incomplete quarantined claim' ;; esac
done

# Terminal replies retire the caller's recovery obligations. Validate the
# whole identity state before ANY handler can emit one or move another record:
# valid bytes alone do not make contradictory active/terminal state safe.
# A completed cancellation legitimately retains its cancelling marker (and a
# quarantined unexecuted intent retains its hard-linked fence); neither can
# coexist with an active or pending grant. Preserve all conflicting evidence.
if [ -e "$released" ] || [ -L "$released" ]; then
    for unfinished in "$active" "$pending" "$cancelling" "$cancelled" \
        "$registry/quarantine/$token.$digest.pending"; do
        [ ! -e "$unfinished" ] && [ ! -L "$unfinished" ] \
            || refuse 'released source grant has conflicting ownership'
    done
fi
if [ -e "$cancelled" ] || [ -L "$cancelled" ]; then
    for unfinished in "$active" "$pending" "$released"; do
        [ ! -e "$unfinished" ] && [ ! -L "$unfinished" ] \
            || refuse 'cancelled source grant has conflicting ownership'
    done
fi

if [ "$operation" = cancel ]; then
    if [ -e "$released" ] || [ -L "$released" ]; then
        refuse 'executed source grant was released, not cancelled'
    fi
    if [ -e "$cancelled" ] || [ -L "$cancelled" ]; then
        matches_request "$cancelled"
        confirm_durable_record "$cancelled"
        printf unowned
        exit 0
    fi
    if rch_claim_quarantine_fence "$registry" "$cancelling"; then
        # No source activity was granted. Publish the exact caller-bound
        # cancellation receipt while retaining the legacy refusal fence.
        rch_claim_write_atomic "$registry" "$cancelled" "$digest" "$requested" || refuse 'cannot persist quarantined source cancellation'
        matches_request "$cancelled"
        confirm_durable_record "$cancelled"
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
        confirm_durable_record "$cancelled"
        printf unowned
    fi
    exit 0
fi

if [ "$operation" = finish-cancel ]; then
    if [ -e "$cancelled" ] || [ -L "$cancelled" ]; then
        matches_request "$cancelled"
        confirm_durable_record "$cancelled"
        exit 0
    fi
    matches_request "$cancelling"
    matches_request "$active"
    [ ! -e "$pending" ] && [ ! -L "$pending" ] || refuse 'unfinished claim transition'
    mv -- "$active" "$cancelled"
    confirm_durable_record "$cancelled"
    prune_terminal_claims
    exit 0
fi

if [ "$operation" = released ]; then
    if [ -e "$released" ] || [ -L "$released" ]; then
        matches_request "$released"
        confirm_durable_record "$released"
        printf released
    else
        printf pending
    fi
    exit 0
fi

if [ "$operation" = cancelled ]; then
    # Read-only, like `released`: the exact caller-bound cancellation receipt
    # proves this identity holds no source rights (finish-cancel runs only
    # after its tree was retired). It never grants path access.
    if [ -e "$cancelled" ] || [ -L "$cancelled" ]; then
        matches_request "$cancelled"
        # Recovery may query after a rename whose durability acknowledgment
        # failed. Visibility alone cannot retire the caller's obligations.
        confirm_durable_record "$cancelled"
        printf cancelled
    else
        printf pending
    fi
    exit 0
fi

if [ "$operation" = release ]; then
    if [ -e "$released" ] || [ -L "$released" ]; then
        # Resume a completed move, not a new release. A lost acknowledgment
        # must not strand the caller, but contradictory ownership is never a
        # receipt. In particular, a released grant is NOT a cancelled intent.
        matches_request "$released"
        confirm_durable_record "$released"
        exit 0
    fi
    # The receipt is the original claim, never a newly manufactured token.
    # An acknowledged move therefore proves this exact set ceased to be active.
    matches_request "$active"
    [ ! -e "$cancelling" ] && [ ! -L "$cancelling" ] || refuse 'source grant is cancelling'
    [ ! -e "$pending" ] && [ ! -L "$pending" ] || refuse 'unfinished claim transition'
    [ ! -e "$released" ] && [ ! -L "$released" ] || refuse 'duplicate release receipt'
    mv -- "$active" "$released"
    confirm_durable_record "$released"
    prune_terminal_claims
    exit 0
fi

case "$operation" in acquire|try-acquire|recover|topology) ;; *) refuse 'unknown claim operation' ;; esac
[ ! -e "$released" ] && [ ! -L "$released" ] || refuse 'source grant already released'
[ ! -e "$cancelled" ] && [ ! -L "$cancelled" ] || refuse 'source intent cancelled'
[ ! -e "$cancelling" ] && [ ! -L "$cancelling" ] || refuse 'source intent cancellation is unfinished'

if [ "$operation" = topology ]; then
    # The caller supplies the existing read-only topology validator and its
    # create-only counterpart. Both run under THIS metadata flock. Recheck
    # after waiting: another initializer may have finished and admitted a job.
    # A healthy topology needs no mutation and therefore no source authority.
    [ "$#" -eq 6 ] || refuse 'invalid topology transaction'
    closures_overlap "$requested" roots "$requested" || refuse 'invalid topology scope'
    if sh -c "$5" >/dev/null 2>&1; then
        confirm_topology "$5"
        exit 0
    fi
fi

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

# Stream batches through reusable requested-root indexes while retaining the
# registry flock. Physical roots are resolved afresh inside this transaction;
# lexical and physical indexes remain sequential with their existing memory
# bound. No scratch file, record format or ownership transition changes.
check_held_claims

if [ "$operation" = topology ]; then
    # No active or complete pending lexical/physical source owner overlaps.
    # Retain the metadata flock through the entire create-only mutation, not
    # just its check. Every source activity needs an active claim; a claimant
    # holding kernel locks but not yet admitted must wait and resolve physical
    # paths AFTER this transaction. Never acquire source locks under metadata:
    # source acquisition uses the opposite order. The flock supervisor also
    # outlives its mutator if the dispatcher's control connection disappears.
    # No durable source claim is created for these shared topology parents.
    # The production mutator invokes ln inside a command substitution. Make
    # that operation no-target-directory even if the destination changes after
    # its absence test: no link may be created in a newly appeared directory or
    # through a newly appeared symlink. GNU coreutils are already required by
    # this protocol; Darwin workers use the g-prefixed tool when present.
    # uutils coreutils (Ubuntu 25.10+) refuses a repeated -T, so add it only
    # when the call does not already carry it (the namespace script's -sT).
    topology_create='ln() {
        case "${1-}" in
            -T|-sT|-Ts|--no-target-directory) ;;
            *) set -- -T "$@" ;;
        esac
        if command -v gln >/dev/null 2>&1; then
            command gln "$@"
        else
            command ln "$@"
        fi
    }
'
    # Suppress premature success from the mutator. Only the checked, durable
    # postcondition below acknowledges this metadata-only transaction.
    sh -c "$topology_create$6" >/dev/null || refuse 'topology initialization failed'
    confirm_topology "$5"
    exit 0
fi

if [ "$operation" = recover ]; then
    if [ -e "$active" ] || [ -L "$active" ]; then
        matches_request "$active"
        [ ! -e "$pending" ] && [ ! -L "$pending" ] || refuse 'duplicate source grant'
        confirm_durable_record "$active"
        exit 0
    fi
    # Only an already-written complete claim may finish its interrupted rename.
    # Missing state never grants recovery authority, even for the same token.
    matches_request "$pending"
else
    [ ! -e "$active" ] && [ ! -L "$active" ] || refuse 'source grant already exists'
    [ ! -e "$pending" ] && [ ! -L "$pending" ] || refuse 'pending source grant already exists'
    prune_terminal_claims
    check_registry_headroom
    rch_claim_write_atomic "$registry" "$pending" "$digest" "$requested" || refuse 'cannot persist source claim'
    matches_request "$pending"
fi
sync -f "$pending" || refuse 'cannot sync pending source claim'
mv -- "$pending" "$active" || refuse 'cannot activate source claim'
confirm_durable_record "$active"
