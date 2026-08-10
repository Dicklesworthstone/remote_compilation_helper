#!/usr/bin/env bash
# B015 (bead rabs-root-4pidu.20.15): Layer-0 benchmark driver.
#
# Runs the scenario list against one repo in two variants — stock (no
# config overlay) and layer0 (the B014 pack rendered for THIS host via
# `layer0_render`) — and appends NDJSON baseline records to the output
# file. The stored baseline is the reference point for RABS claims
# (B008 report family, kind=layer0-baseline v1).
#
# Usage:
#   rabs_layer0_bench.sh <repo-dir> <repo-name> <out.ndjson> \
#       [layer0-config-file] [cold-iterations] [warm-iterations]
#
# Scenarios: cold-check, cold-build (fresh scratch target each
# iteration), incremental-check (touch one source file, re-check).
# The scratch target dir and config overlay live OUTSIDE the repo so
# the repo tree is never mutated (the touched file is restored).
set -euo pipefail

REPO_DIR=$1
REPO_NAME=$2
OUT=$3
LAYER0_CONFIG=${4:-}
COLD_ITERS=${5:-1}
WARM_ITERS=${6:-3}

HOST=$(hostname -s 2>/dev/null || hostname)
TOOLCHAIN=$(rustc -V 2>/dev/null | tr -d '"')
SCRATCH=$(mktemp -d "${TMPDIR:-/tmp}/rabs-l0-bench.XXXXXX")
trap 'rm -rf "$SCRATCH"' EXIT

# A source file to touch for the incremental scenario. (find must not
# kill the script under `set -eo pipefail` when probing paths.)
TOUCH_FILE=$( (find "$REPO_DIR" -maxdepth 3 -name '*.rs' 2>/dev/null || true) | head -1)
[ -n "$TOUCH_FILE" ] || { echo "no .rs file to touch in $REPO_DIR" >&2; exit 2; }

now_ms() { python3 -c 'import time; print(int(time.time()*1000))'; }

emit() { # variant scenario iteration duration_ms exit_code
  printf '{"v":1,"kind":"layer0-baseline","repo":"%s","host":"%s","toolchain":"%s","variant":"%s","scenario":"%s","iteration":%s,"duration_ms":%s,"exit":%s}\n' \
    "$REPO_NAME" "$HOST" "$TOOLCHAIN" "$1" "$2" "$3" "$4" "$5" >> "$OUT"
}

run_timed() { # variant scenario iteration -- cmd...
  local variant=$1 scenario=$2 iteration=$3; shift 4
  local start end code=0
  start=$(now_ms)
  "$@" >/dev/null 2>&1 || code=$?
  end=$(now_ms)
  emit "$variant" "$scenario" "$iteration" "$((end - start))" "$code"
  return $code
}

cargo_for() { # variant target_dir -- subcmd...
  local variant=$1 target=$2; shift 3
  local -a wrapper=()
  if [ "$variant" = sccache ]; then
    wrapper=(env "RUSTC_WRAPPER=sccache" "SCCACHE_DIR=$SCRATCH/sccache-cache")
  fi
  if [ "$variant" = layer0 ] && [ -n "$LAYER0_CONFIG" ]; then
    # Apply the pack as a config OVERLAY (file path form of --config)
    # without touching the repo tree.
    CARGO_TARGET_DIR=$target CARGO_INCREMENTAL=0 \
      "${wrapper[@]}" cargo --config "$LAYER0_CONFIG" "$@" --manifest-path "$REPO_DIR/Cargo.toml"
  else
    CARGO_TARGET_DIR=$target CARGO_INCREMENTAL=0 \
      "${wrapper[@]}" cargo "$@" --manifest-path "$REPO_DIR/Cargo.toml"
  fi
}

VARIANTS=${RABS_BENCH_VARIANTS:-"stock layer0"}
for VARIANT in $VARIANTS; do
  if [ "$VARIANT" = layer0 ] && [ -z "$LAYER0_CONFIG" ]; then
    echo "layer0 config not provided; skipping layer0 variant (recorded)" >&2
    emit layer0 skipped 0 0 -1
    continue
  fi
  if [ "$VARIANT" = sccache ] && ! command -v sccache >/dev/null; then
    echo "sccache not on PATH; skipping sccache variant (recorded)" >&2
    emit sccache skipped 0 0 -1
    continue
  fi
  TARGET="$SCRATCH/target-$VARIANT"
  if [ "$VARIANT" = sccache ]; then
    rm -rf "$SCRATCH/sccache-cache"
    SCCACHE_DIR="$SCRATCH/sccache-cache" sccache --stop-server >/dev/null 2>&1 || true
  fi

  for i in $(seq 1 "$COLD_ITERS"); do
    rm -rf "$TARGET"
    run_timed "$VARIANT" cold-check "$i" -- cargo_for "$VARIANT" "$TARGET" -- check --workspace || true
  done

  for i in $(seq 1 "$WARM_ITERS"); do
    touch "$TOUCH_FILE"
    run_timed "$VARIANT" incremental-check "$i" -- cargo_for "$VARIANT" "$TARGET" -- check --workspace || true
  done

  for i in $(seq 1 "$COLD_ITERS"); do
    rm -rf "$TARGET"
    run_timed "$VARIANT" cold-build "$i" -- cargo_for "$VARIANT" "$TARGET" -- build --workspace || true
  done

  # sccache's value scenario: target wiped, COMPILE CACHE kept — the
  # repeated-cold-build a shared cache accelerates.
  if [ "$VARIANT" = sccache ]; then
    for i in $(seq 1 "$COLD_ITERS"); do
      rm -rf "$TARGET"
      run_timed "$VARIANT" cold-build-cached "$i" -- cargo_for "$VARIANT" "$TARGET" -- build --workspace || true
    done
  fi
done

echo "baseline records appended to $OUT" >&2
