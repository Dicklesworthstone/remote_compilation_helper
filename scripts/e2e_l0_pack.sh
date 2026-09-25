#!/usr/bin/env bash
# Layer-0 pack end-to-end proof (beads bd-k9wg8 / bd-z9wcn / bd-9erfp / bd-2i6ld).
#
# Unit tests prove the pack's DECISIONS. They cannot prove the decision is
# usable: a rendered config can be internally consistent and still be rejected
# by Cargo, or name a linker the host cannot invoke. This script closes that
# gap on whatever host it runs on —
#
#   1. renders the pack for THIS host with the real `layer0_render` probes,
#   2. feeds the rendered config to a real `cargo build --config`,
#   3. reads the VERBOSE rustc invocation back to confirm the flags the pack
#      claimed actually reached the compiler,
#   4. records cold-build samples in the B015 `layer0-baseline v1` NDJSON
#      format so link-time numbers land in the same shape as every other
#      Layer-0 measurement.
#
# Run it on a worker, not the dispatcher:
#   rch exec --job --result-dir l0-proof -- ./scripts/e2e_l0_pack.sh
#
# Everything it writes lands in ./l0-proof (repo-relative so job mode can
# return it). It never edits tracked files and never installs anything.
set -euo pipefail

OUT=${1:-l0-proof}
SAMPLES=${2:-3}
mkdir -p "$OUT"

log() { printf '%s\n' "$*" >&2; }

# ---------------------------------------------------------------- host facts
{
  echo "uname: $(uname -srm)"
  echo "host-date: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
  rustc -vV
  for tool in clang wild ld.lld lld sccache; do
    if command -v "$tool" >/dev/null 2>&1; then
      printf '%s: %s\n' "$tool" "$("$tool" --version 2>&1 | head -1)"
    else
      printf '%s: ABSENT\n' "$tool"
    fi
  done
  printf 'cargo-hakari: %s\n' "$(cargo hakari --version 2>&1 | head -1 || echo ABSENT)"
} >"$OUT/host.txt"
log "host inventory -> $OUT/host.txt"

# ------------------------------------------------------------------- render
cargo build -q -p rabs-key --bin layer0_render
RENDER=$(cargo metadata --no-deps --format-version 1 \
  | python3 -c 'import json,sys; print(json.load(sys.stdin)["target_directory"])')/debug/layer0_render
[ -x "$RENDER" ] || { log "layer0_render not built at $RENDER"; exit 2; }

# Two renders. The BARE one proves the pack's default posture: no opt-in knob
# is on without an explicit request. The one documented exception is the
# linker (L0-c, `layer0_render --help`): wild/lld is selected by AVAILABILITY
# alone when the clang driver and a known host triple are present, so on such
# a host the bare render carries exactly that linker block and nothing else.
# The OPTED-IN one is the subject of the flag assertions below — every knob
# in it was asked for AND proven available on this host.
"$RENDER" >"$OUT/layer0-bare.toml" 2>"$OUT/render-bare.stderr"
HOST_TRIPLE=$(rustc -vV | sed -n 's/^host: //p')
LINKER_LIVE_RE="^(\[target\.${HOST_TRIPLE//./\\.}\]|linker = \"clang\"|rustflags = \[\"-C\", \"link-arg=(-fuse-ld=lld|--ld-path=wild)\"\])$"
if grep -v '^#' "$OUT/layer0-bare.toml" | grep '[^[:space:]]' | grep -Evq "$LINKER_LIVE_RE"; then
  log "FAIL: an unrequested pack rendered live config beyond the auto-selected linker:"
  cat "$OUT/layer0-bare.toml" >&2
  exit 3
fi
if grep -q '^linker = "clang"' "$OUT/layer0-bare.toml" && ! command -v clang >/dev/null 2>&1; then
  log "FAIL: bare render selected a clang-driven linker but clang is absent"
  exit 3
fi
log "bare render touches nothing but the availability-selected linker -> $OUT/layer0-bare.toml"

TARGET_CPU=${TARGET_CPU:-x86-64-v2}
case "$(rustc -vV | sed -n 's/^host: //p')" in
  aarch64-*) TARGET_CPU=${TARGET_CPU_AARCH64:-apple-m1} ;;
esac
"$RENDER" --zthreads 4 --line-tables-only --cranelift --target-cpu "$TARGET_CPU" \
  >"$OUT/layer0.toml" 2>"$OUT/render.stderr"
log "rendered pack -> $OUT/layer0.toml"
cat "$OUT/layer0.toml" >&2
cat "$OUT/render.stderr" >&2

# What did the pack actually decide on this host? The assertions below adapt
# to that decision instead of assuming a fleet-wide answer.
LINKER_FLAG=""
grep -q -- '--ld-path=wild' "$OUT/layer0.toml" && LINKER_FLAG="--ld-path=wild"
grep -q -- '-fuse-ld=lld' "$OUT/layer0.toml" && LINKER_FLAG="-fuse-ld=lld"
HOST_TRIPLE=$(rustc -vV | sed -n 's/^host: //p')

# The pack must never key a target section on a triple this host is not.
if grep -q '^\[target\.' "$OUT/layer0.toml"; then
  grep '^\[target\.' "$OUT/layer0.toml" | while read -r section; do
    case "$section" in
      "[target.$HOST_TRIPLE]") ;;
      *) log "FAIL: rendered section $section is inert on $HOST_TRIPLE"; exit 3 ;;
    esac
  done
fi

# The pack must never name a linker driver this host cannot invoke.
if [ -n "$LINKER_FLAG" ] && ! command -v clang >/dev/null 2>&1; then
  log "FAIL: pack selected $LINKER_FLAG but clang is absent"
  exit 3
fi

# ------------------------------------------------------- scratch build subject
# A subject with enough object files that linking is a measurable share of the
# build, built OUTSIDE the repo so the tree is never mutated.
SCRATCH=$(mktemp -d "${TMPDIR:-/tmp}/rch-l0-proof.XXXXXX")
trap 'rm -rf "$SCRATCH"' EXIT
mkdir -p "$SCRATCH/subject/src/bin"
cat >"$SCRATCH/subject/Cargo.toml" <<'TOML'
[package]
name = "l0_proof_subject"
version = "0.0.0"
edition = "2021"
[workspace]
TOML
cat >"$SCRATCH/subject/src/lib.rs" <<'RS'
pub fn answer() -> u32 { 42 }
RS
for i in $(seq 1 12); do
  cat >"$SCRATCH/subject/src/bin/b$i.rs" <<RS
use std::hint::black_box;
fn main() {
    let data: Vec<u64> = (0..1024).map(|v| v * $i).collect();
    println!("{}", black_box(data.iter().sum::<u64>()));
}
RS
done

now_ms() { python3 -c 'import time; print(int(time.time()*1000))'; }

emit() { # variant scenario iteration duration_ms exit
  printf '{"v":1,"kind":"layer0-baseline","repo":"l0_proof_subject","host":"%s","toolchain":"%s","variant":"%s","scenario":"%s","iteration":%s,"duration_ms":%s,"exit":%s}\n' \
    "$(hostname -s 2>/dev/null || hostname)" "$(rustc -V)" "$1" "$2" "$3" "$4" "$5" >>"$OUT/layer0-baseline.ndjson"
}

build_once() { # variant iteration -> duration in $DURATION
  # Separate `local` statements on purpose: a single `local a=$1 b=$a` expands
  # every word BEFORE the builtin runs, so `b` would read an unset `a`.
  local variant=$1
  local iteration=$2
  local target="$SCRATCH/target-$variant-$iteration"
  local code=0 start end
  local -a extra=()
  [ "$variant" = layer0 ] && extra=(--config "$PWD/$OUT/layer0.toml")
  start=$(now_ms)
  CARGO_TARGET_DIR=$target CARGO_INCREMENTAL=0 RCH_CARGO_WRAPPER_BYPASS=1 \
    cargo build --manifest-path "$SCRATCH/subject/Cargo.toml" --verbose "${extra[@]}" \
    >"$OUT/cargo-$variant-$iteration.stdout" 2>"$OUT/cargo-$variant-$iteration.stderr" || code=$?
  end=$(now_ms)
  DURATION=$((end - start))
  emit "$variant" cold-build "$iteration" "$DURATION" "$code"
  return $code
}

# --------------------------------------------------------------- the proof
: >"$OUT/layer0-baseline.ndjson"
for i in $(seq 1 "$SAMPLES"); do
  for variant in stock layer0; do
    if ! build_once "$variant" "$i"; then
      log "FAIL: $variant build $i did not succeed; see $OUT/cargo-$variant-$i.stderr"
      tail -30 "$OUT/cargo-$variant-$i.stderr" >&2
      exit 4
    fi
    log "$variant cold-build $i: ${DURATION}ms"
  done
done

# The claim under test: the flags the pack RENDERED reached rustc. Verbose
# Cargo echoes each rustc invocation, so this reads the real command line
# rather than trusting the config text.
#
# Every knob that IS in the rendered config must be visible in the compiler
# invocation, and must NOT be visible in the stock one — a knob that renders
# but never reaches rustc is exactly the failure mode unit tests cannot see.
assert_flag() { # rendered-marker rustc-flag label
  local marker=$1 flag=$2 label=$3
  if ! grep -q -- "$marker" "$OUT/layer0.toml"; then
    log "NOTE: $label not enabled on this host; assertion skipped"
    return 0
  fi
  if ! grep -q -- "$flag" "$OUT/cargo-layer0-1.stderr"; then
    log "FAIL: pack rendered $label but no rustc invocation carried $flag"
    exit 5
  fi
  if grep -q -- "$flag" "$OUT/cargo-stock-1.stderr"; then
    log "FAIL: stock variant carried $flag; the variants are not separable"
    exit 5
  fi
  log "VERIFIED: $label reached rustc as $flag"
}

assert_flag "target-cpu=$TARGET_CPU" "target-cpu=$TARGET_CPU" "target-cpu baseline"
# Also the regression this pack version fixes: when any knob opens
# `[target.<triple>]`, Cargo's target rustflags REPLACE build.rustflags — so
# the threads flag has to be mirrored there or it silently disappears.
assert_flag "-Zthreads=4" "-Zthreads=4" "zthreads (mirrored into the target section)"

if [ -n "$LINKER_FLAG" ]; then
  if grep -q -- "$LINKER_FLAG" "$OUT/cargo-layer0-1.stderr"; then
    log "VERIFIED: rustc invoked with $LINKER_FLAG under the layer0 config"
  else
    log "FAIL: pack rendered $LINKER_FLAG but no rustc invocation carried it"
    exit 5
  fi
  if grep -q -- "$LINKER_FLAG" "$OUT/cargo-stock-1.stderr"; then
    log "FAIL: stock variant carried $LINKER_FLAG; the variants are not separable"
    exit 5
  fi
else
  log "NOTE: this host selected no faster linker; link-flag assertions skipped"
  grep -q -- 'fuse-ld\|ld-path' "$OUT/cargo-layer0-1.stderr" && {
    log "FAIL: no linker knob enabled yet a linker flag reached rustc"
    exit 5
  }
fi

python3 - "$OUT/layer0-baseline.ndjson" >"$OUT/summary.txt" <<'PY'
import json, statistics, sys
rows = [json.loads(line) for line in open(sys.argv[1]) if line.strip()]
for variant in ("stock", "layer0"):
    times = [r["duration_ms"] for r in rows if r["variant"] == variant]
    if times:
        print(f"{variant}: n={len(times)} min={min(times)} median={int(statistics.median(times))} max={max(times)}")
PY
cat "$OUT/summary.txt" >&2
log "PASS: rendered pack applied, built, and its flags reached rustc"
