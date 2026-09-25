set -eu
remaining=$1
if [ "$remaining" -eq 0 ]; then
    exec 3<&-
    printf '%s\n' "$2"
    exec cat >/dev/null
fi
IFS= read -r record <&3 || exit 73
case "$record" in
    'x /'*) mode=-x ;;
    's /'*) mode=-s ;;
    *) exit 73 ;;
esac
lock=${record#??}
exec flock "$mode" --no-fork -- "$lock" sh -c "$0" "$0" "$((remaining - 1))" "$2"
