set -eu
remaining=$1
shift
if [ "$remaining" -eq 0 ]; then
    exec 3<&-
    ready=$1
    shift
    if [ "$#" -gt 0 ]; then
        terminal=$1
        shift
        exec sh -c "$terminal" "$terminal" "$ready" "$@"
    fi
    printf '%s\n' "$ready"
    exec cat >/dev/null
fi
IFS= read -r record <&3 || exit 73
case "$record" in
    'x /'*) mode=-x ;;
    's /'*) mode=-s ;;
    *) exit 73 ;;
esac
lock=${record#??}
exec flock "$mode" --no-fork -- "$lock" sh -c "$0" "$0" "$((remaining - 1))" "$@"
