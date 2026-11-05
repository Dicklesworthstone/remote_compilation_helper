# A create-only projects namespace operation. The registry's topology mode
# holds its metadata mutex and checks lexical/physical source owners before
# calling create. Neither mode repairs ownership or replaces an existing path.
set -eu
case "$#" in
    3) namespace_report=0 ;;
    4)
        [ "$1" = check ] && [ "$4" = --report-json ] || exit 73
        namespace_report=1 ;;
    *) exit 73 ;;
esac
mode=$1
canonical=$2
alias=$3
case "$mode" in check|create) ;; *) exit 73 ;; esac

namespace_refuse() {
    printf 'RCH: source namespace: %s\n' "$1" >&2
    exit 73
}

namespace_incompatible() {
    # This verdict means a fixed path mapping cannot be admitted. Keep it
    # distinct from registry contention and uncertain setup/teardown failures.
    printf 'RCH_SOURCE_TOPOLOGY_INCOMPATIBLE: %s\n' "$1" >&2
    if [ -z "${canonical_physical-}" ]; then
        canonical_physical=$(namespace_realpath "$canonical") || canonical_physical='<unresolved>'
    fi
    if [ -z "${alias_physical-}" ]; then
        alias_physical=$(namespace_realpath "$alias") || alias_physical='<unresolved>'
    fi
    # Only path metadata is printed. JSON quoting keeps control characters,
    # quotes and shell metacharacters from becoming terminal/protocol input.
    python3 -I -S -c '
import json, sys
print("RCH_SOURCE_TOPOLOGY_PATHS " + json.dumps(dict(zip(
    ("canonical", "canonical_physical", "alias", "alias_physical"), sys.argv[1:]
)), ensure_ascii=True))
' "$canonical" "${canonical_physical-}" "$alias" "${alias_physical-}" >&2 \
        || printf 'RCH: source namespace: physical mapping diagnostic unavailable\n' >&2
    namespace_refuse "$2"
}

namespace_realpath() {
    # Preserve the trailing delimiter and refuse an ambiguous symlink target.
    # Command substitution alone would silently remove embedded final newlines.
    if command -v grealpath >/dev/null 2>&1; then
        physical=$(grealpath -m -- "$1" && printf '.') || return 1
    else
        physical=$(realpath -m -- "$1" && printf '.') || return 1
    fi
    physical=${physical%.}
    newline='
'
    carriage_return=$(printf '\r')
    case "$physical" in *"$newline") ;; *) return 1 ;; esac
    physical=${physical%"$newline"}
    case "$physical" in ''|*"$newline"*|*"$carriage_return"*) return 1 ;; esac
    printf '%s\n' "$physical"
}

namespace_matches() {
    [ -d "$canonical" ] && [ -d "$alias" ] || return 1
    canonical_physical=$(namespace_realpath "$canonical") || return 1
    alias_physical=$(namespace_realpath "$alias") || return 1
    [ "$canonical_physical" = "$alias_physical" ]
}

if [ "$mode" = check ]; then
    if [ "$namespace_report" -eq 0 ]; then
        namespace_matches
        exit $?
    fi
    # Doctor/probe request a report for the dispatcher's exact roots. Keep
    # ordinary admission checks silent and unchanged. The report is only an
    # observation: it neither creates paths nor grants source ownership.
    namespace_status=0
    namespace_matches 2>/dev/null || namespace_status=$?
    canonical_physical=$(namespace_realpath "$canonical" 2>/dev/null) || canonical_physical=''
    alias_physical=$(namespace_realpath "$alias" 2>/dev/null) || alias_physical=''
    exec python3 -I -S -B -c '
import json, os, stat, sys
canonical, alias, canonical_physical, alias_physical, checked = sys.argv[1:]

def directory_state(path):
    try:
        return "directory" if stat.S_ISDIR(os.stat(path).st_mode) else "not_directory"
    except FileNotFoundError:
        return "missing"
    except OSError:
        return "unavailable"

states = [directory_state(path) for path in (canonical, alias)]
outcome = "unavailable"
if "unavailable" not in states:
    if states[0] != "directory":
        outcome = "canonical_" + states[0]
    elif states[1] != "directory":
        outcome = "alias_" + states[1]
    elif canonical_physical and alias_physical:
        if canonical_physical != alias_physical:
            outcome = "conflicting_alias_base"
        elif checked == "0":
            outcome = "compatible"

report = dict(canonical=canonical, alias=alias,
              canonical_physical=canonical_physical or None,
              alias_physical=alias_physical or None, outcome=outcome)
encoded = "RCH_SOURCE_TOPOLOGY_CHECK_V1 " + json.dumps(report, ensure_ascii=True)
if len(encoded) > 65535:
    sys.exit(2)
print(encoded)
sys.exit(0 if outcome == "compatible" else 2 if outcome == "unavailable" else 1)
' "$canonical" "$alias" "$canonical_physical" "$alias_physical" "$namespace_status"
fi

# A wholly absent canonical base beside an alias that already names a real
# directory is one namespace with a name missing. Restore that name as a link.
# Creating a directory here would mint a second physical tree and turn a
# repairable gap into a permanent conflict. Best effort and create-only: when
# the link cannot be made, the conflict check below refuses as it always has.
if [ ! -e "$canonical" ] && [ ! -L "$canonical" ] && [ -d "$alias" ]; then
    alias_physical=$(namespace_realpath "$alias") || namespace_refuse 'unresolvable alias base'
    case "$canonical/" in
        "$alias_physical"/*) ;;
        *)
            mkdir -p -- "$(dirname -- "$canonical")" 2>/dev/null || :
            if command -v gln >/dev/null 2>&1; then
                gln -sT -- "$alias_physical" "$canonical" 2>/dev/null || :
            else
                ln -sT -- "$alias_physical" "$canonical" 2>/dev/null || :
            fi
            ;;
    esac
fi

# Refuse a conflicting existing alias before even creating the canonical base.
# A dangling but correctly targeted alias may become valid once that base exists.
if [ -e "$alias" ] || [ -L "$alias" ]; then
    canonical_physical=$(namespace_realpath "$canonical") || namespace_refuse 'unresolvable canonical base'
    alias_physical=$(namespace_realpath "$alias") || namespace_refuse 'unresolvable alias base'
    [ "$canonical_physical" = "$alias_physical" ] \
        || namespace_incompatible conflicting_alias_base 'conflicting alias base'
fi
if [ ! -e "$canonical" ] && [ ! -L "$canonical" ]; then
    mkdir -p -- "$canonical" || namespace_refuse 'cannot create canonical base'
fi
[ -d "$canonical" ] \
    || namespace_incompatible canonical_not_directory 'canonical base is not a directory'
if [ ! -e "$alias" ] && [ ! -L "$alias" ]; then
    # No overwrite and no implicit directory target. A competing initializer
    # may win only by establishing the exact same mapping, checked below.
    if command -v gln >/dev/null 2>&1; then
        gln -sT -- "$canonical" "$alias" 2>/dev/null || namespace_matches \
            || namespace_refuse 'cannot create alias base'
    else
        ln -sT -- "$canonical" "$alias" 2>/dev/null || namespace_matches \
            || namespace_refuse 'cannot create alias base'
    fi
fi
namespace_matches || namespace_refuse 'namespace changed during initialization'
# Only the registry may emit readiness, after postcondition and durability checks.
