#!/usr/bin/env bash
# profile_benchmark.sh (bead A021) — build every binary under the legacy
# `release`, the new `wrapper-release` (rch, rabs-wrap), and the new
# `daemon-release` (rchd/rabsd/rch-wkr/rabs-wkr) profiles ON A PINNED
# WORKER (builds ride RCH per fleet doctrine), pull the binaries back,
# and record footprints + wrapper startup medians as NDJSON evidence,
# plus classifier criterion timings per profile from the worker.
#
# Usage:
#   RCH_PROFILE_WORKER=vmi1152480 scripts/profile_benchmark.sh [out.ndjson]
#   SKIP_BUILDS=1 RCH_PROFILE_WORKER=... scripts/profile_benchmark.sh  # measure-only
set -uo pipefail

WORKER="${RCH_PROFILE_WORKER:-ovh-a}"
TARGET_DIR="${CARGO_TARGET_DIR:-target}"
OUT="${1:-benchmarks/baselines/profile_split.ndjson}"
CRIT_LOG="${OUT%.ndjson}.criterion.txt"
REPS="${REPS:-20}"
MEASURE_DIR="$TARGET_DIR/profile-evidence/$WORKER"
mkdir -p "$(dirname "$OUT")" "$MEASURE_DIR"
: > "$OUT"

# Worker SSH coordinates (worker id -> host/user/key).
case "$WORKER" in
    ovh-a) W_HOST="ubuntu@51.222.245.56"; W_KEY="$HOME/.ssh/je_ovh_ssh_key.pem" ;;
    ovh-b) W_HOST="ubuntu@37.187.75.150"; W_KEY="$HOME/.ssh/je_ovh_ssh_key.pem" ;;
    *)     W_HOST="root@$WORKER";         W_KEY="$HOME/.ssh/contabo_vps_ed25519" ;;
esac

PROJECT="/data/projects/remote_compilation_helper"

remote_build() { # profile, packages...
    local profile="$1"; shift
    local pkg
    for pkg in "$@"; do
        echo "==> [remote:$WORKER] cargo build --profile $profile -p $pkg" >&2
        RCH_WORKER="$WORKER" rch exec -- cargo build --profile "$profile" -p "$pkg" >&2 || true
    done
}

pull_bin() { # profile, bin -> echoes local path (may be missing)
    local profile="$1" bin="$2"
    local glob remote_path local_path
    glob="$PROJECT/.rch-target-$WORKER-pool-*/$profile/$bin"
    remote_path=$(ssh -i "$W_KEY" -o ConnectTimeout=10 -o BatchMode=yes \
        "$W_HOST" "ls -1t $glob 2>/dev/null | head -1")
    if [[ -z "$remote_path" ]]; then
        echo "pull_bin: no binary for $bin ($profile) on $WORKER" >&2
        echo ""
        return
    fi
    mkdir -p "$MEASURE_DIR/$profile"
    rsync -q -e "ssh -i $W_KEY -o ConnectTimeout=10 -o BatchMode=yes" \
        "$W_HOST:$remote_path" "$MEASURE_DIR/$profile/" 2>/dev/null
    local_path="$MEASURE_DIR/$profile/$bin"
    [[ -x "$local_path" ]] && { echo "$local_path"; return; }
    # rsync preserves permissions only with -p; chmod defensively.
    [[ -f "$local_path" ]] && chmod +x "$local_path" && { echo "$local_path"; return; }
    echo ""
}

ns_now() { date +%s%N; }

median() {
    sort -n | awk '{a[NR]=$1} END {if (NR==0) print 0; else if (NR%2) print a[(NR+1)/2]; else print int((a[NR/2]+a[NR/2+1])/2)}'
}

startup_median_ns() {
    local bin="$1"; shift
    local tmp="/tmp/pbm_startup.$$.$RANDOM"
    : > "$tmp"
    for _ in $(seq 1 "$REPS"); do
        local s e
        s=$(ns_now)
        "$bin" "$@" >/dev/null 2>&1 || true
        e=$(ns_now)
        echo $((e - s)) >> "$tmp"
    done
    median < "$tmp"
    rm -f "$tmp"
}

emit() { printf '%s\n' "$1" >> "$OUT"; }

record_binary() {
    local profile="$1" name="$2" path="$3" role="$4"
    local size=0
    local startup="null"
    if [[ -n "$path" && -x "$path" ]]; then
        size=$(stat -c '%s' "$path" 2>/dev/null || echo 0)
        if [[ "$role" == "wrapper" ]]; then
            case "$name" in
                rch)       startup=$(startup_median_ns "$path" capabilities --json) ;;
                rabs-wrap) startup=$(startup_median_ns "$path" --help) ;;
            esac
        fi
    fi
    emit "{\"schema\":\"rabs.profile-benchmark\",\"schema_version\":1,\"worker\":\"$WORKER\",\"profile\":\"$profile\",\"binary\":\"$name\",\"role\":\"$role\",\"size_bytes\":$size,\"startup_median_ns\":$startup}"
}

if [[ "${SKIP_BUILDS:-0}" != "1" ]]; then
    echo "==> legacy release baseline (worker build)" >&2
    remote_build release rch rabs-wrap rchd rabsd rch-wkr rabs-wkr
    echo "==> wrapper-release (worker build)" >&2
    remote_build wrapper-release rch rabs-wrap
    echo "==> daemon-release (worker build)" >&2
    remote_build daemon-release rchd rabsd rch-wkr rabs-wkr
fi

record_binary release rch       "$(pull_bin release rch)"       wrapper
record_binary release rabs-wrap "$(pull_bin release rabs-wrap)" wrapper
record_binary release rchd      "$(pull_bin release rchd)"      daemon
record_binary release rabsd     "$(pull_bin release rabsd)"     daemon
record_binary release rch-wkr   "$(pull_bin release rch-wkr)"   daemon
record_binary release rabs-wkr  "$(pull_bin release rabs-wkr)"  daemon

record_binary wrapper-release rch       "$(pull_bin wrapper-release rch)"       wrapper
record_binary wrapper-release rabs-wrap "$(pull_bin wrapper-release rabs-wrap)" wrapper

record_binary daemon-release rchd     "$(pull_bin daemon-release rchd)"     daemon
record_binary daemon-release rabsd    "$(pull_bin daemon-release rabsd)"    daemon
record_binary daemon-release rch-wkr  "$(pull_bin daemon-release rch-wkr)"  daemon
record_binary daemon-release rabs-wkr "$(pull_bin daemon-release rabs-wkr)" daemon

echo "==> classifier hot-path (criterion) on worker under release + daemon-release" >&2
for profile in release daemon-release; do
    {
        echo "### profile=$profile"
        RCH_WORKER="$WORKER" rch exec -- \
            cargo test --profile "$profile" -p rch-common --bench classifier -- \
            --bench --warm-up-time 1 --measurement-time 3 2>&1 |
            grep -E 'time:'
    } >> "$CRIT_LOG" 2>/dev/null ||
        { echo "### $profile FAILED" >> "$CRIT_LOG"; true; }
done

echo "==> evidence: $OUT (+ criterion log: $CRIT_LOG)" >&2
