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
    record=$1
    [ ! -L "$record" ] && [ -f "$record" ] || refuse 'invalid claim file'
    name=${record##*/}
    record_token=${name%%.*}
    record_digest=${name#*.}
    record_digest=${record_digest%%.*}
    case "$record_token" in ''|*[!a-f0-9-]*) refuse 'invalid claim identity' ;; esac
    case "$record_digest" in *[!a-f0-9]*) refuse 'invalid claim digest' ;; esac
    [ "${#record_digest}" -eq 64 ] || refuse 'invalid claim digest length'
    size=$(wc -c < "$record")
    [ "$size" -gt 0 ] && [ "$size" -le 33554432 ] || refuse 'invalid claim size'
    actual=$(sha256sum -- "$record")
    [ "${actual%% *}" = "$record_digest" ] || refuse 'claim content digest mismatch'
    while IFS= read -r root; do
        case "$root" in /*) ;; *) refuse 'non-absolute claimed root' ;; esac
        case "$root" in *//*|*/./*|*/../*|*/.|*/..) refuse 'non-canonical claimed root' ;; esac
        [ "$root" = / ] || [ "${root%/}" = "$root" ] || refuse 'non-canonical claimed root'
    done < "$record"
}

matches_request() {
    validate_record "$1"
    printf '%s\n' "$requested" | cmp -s - "$1" || refuse 'source claim roots changed'
}

physical_root() {
    # Keep the path's own trailing newlines distinguishable from realpath's
    # record delimiter. Ambiguous path bytes must fail closed, not split into
    # multiple apparent roots after command substitution strips delimiters.
    newline='
'
    carriage_return=$(printf '\r')
    physical=$(realpath -m -- "$1" && printf '.') || refuse 'cannot resolve physical source root'
    physical=${physical%.}
    physical=${physical%"$newline"}
    case "$physical" in /*) ;; *) refuse 'invalid physical source root' ;; esac
    case "$physical" in *"$newline"*|*"$carriage_return"*) refuse 'ambiguous physical source root' ;; esac
    printf '%s\n' "$physical"
}

roots_overlap() {
    [ "$1" != / ] && [ "$2" != / ] || return 0
    case "$1" in "$2"|"$2"/*) return 0 ;; esac
    case "$2" in "$1"/*) return 0 ;; esac
    return 1
}

# An identity is bound to one exact closure for its entire history, including
# cancellation before acquisition and receipts after the active slot is gone.
for previous in "$registry/$token."*.claim "$registry/$token."*.pending \
    "$registry/$token."*.cancelling "$registry/released/$token."*.claim \
    "$registry/cancelled/$token."*.claim; do
    [ -e "$previous" ] || [ -L "$previous" ] || continue
    matches_request "$previous"
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
        (set -C; printf '%s\n' "$requested" > "$cancelling")
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
# Resolve each requested root once, rather than spawning realpath per pair.
requested_physical=$(
    while IFS= read -r wanted; do physical_root "$wanted"; done <<RCH_REQUESTED_ROOTS
$requested
RCH_REQUESTED_ROOTS
)

# An interrupted pending write is an ownership uncertainty too. A valid one
# participates in overlap checks; a corrupt one fails closed before admission.
for held in "$registry"/*.claim "$registry"/*.pending; do
    [ -e "$held" ] || [ -L "$held" ] || continue
    validate_record "$held"
    case "${held##*/}" in "$token".*)
        [ "$operation" = recover ] || refuse 'source identity already claimed'
        [ "$held" = "$active" ] || [ "$held" = "$pending" ] || refuse 'source identity roots changed'
        matches_request "$held"
        continue
        ;;
    esac
    while IFS= read -r old; do
        while IFS= read -r wanted; do
            if roots_overlap "$wanted" "$old"; then refuse 'unfinished overlapping source owner'; fi
        done <<RCH_REQUESTED_ROOTS
$requested
RCH_REQUESTED_ROOTS
        old_physical=$(physical_root "$old")
        while IFS= read -r wanted_physical; do
            if roots_overlap "$wanted_physical" "$old_physical"; then
                refuse 'unfinished overlapping physical source owner'
            fi
        done <<RCH_PHYSICAL_ROOTS
$requested_physical
RCH_PHYSICAL_ROOTS
    done < "$held"
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
    (set -C; printf '%s\n' "$requested" > "$pending")
    matches_request "$pending"
fi
sync -f "$pending"
mv -- "$pending" "$active"
sync -f "$registry"
