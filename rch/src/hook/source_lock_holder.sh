set -eu
remaining=$1
if [ "$remaining" -eq 0 ]; then
    exec 3<&-
    printf '%s\n' "$2"
    exec cat >/dev/null
fi
IFS= read -r lock <&3 || exit 73
case "$lock" in /*) ;; *) exit 73;; esac
exec flock -x --no-fork -- "$lock" sh -c "$0" "$0" "$((remaining - 1))" "$2"
