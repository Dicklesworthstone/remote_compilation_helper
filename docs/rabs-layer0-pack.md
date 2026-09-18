# RABS Layer-0 configuration pack

Milestone **M-1** ships a *versioned configuration pack* before any distributed
RABS work, for two reasons: the knobs are immediate compile-latency wins at
near-zero risk, and pinning them is what makes later measurements comparable at
all (Invariant I27 — measurement precedes frontier complexity).

The pack is code, not a checklist: [`rabs-key/src/layer0_pack.rs`](../rabs-key/src/layer0_pack.rs)
assembles it from probe *evidence*, and [`layer0_render`](../rabs-key/src/bin/layer0_render.rs)
prints the resulting Cargo config. Same evidence in, byte-identical config out.

Current schema: **`LAYER0_PACK_VERSION = 4`**.

## Rendering the pack

```bash
cargo run -p rabs-key --bin layer0_render -- --help

# Nothing is enabled unless you ask for it AND the host proves it:
layer0_render                                         # inert: your defaults stay
layer0_render --zthreads 4 --target-cpu x86-64-v2     # opt into two knobs
layer0_render --cranelift --line-tables-only          # dev-iteration profile
```

Apply the output as a Cargo config **overlay**, so no file in the repo changes:

```bash
layer0_render --zthreads 4 --target-cpu x86-64-v2 > /tmp/layer0.toml
cargo build --config /tmp/layer0.toml
```

Apply it only with the same compiler that was probed — the rendered config
names that toolchain's capabilities, and a different one may not have them.

## Knob inventory

Every knob is independently toggleable (`Layer0Pack::disable(id)`), every knob
is off until both an explicit request and host evidence agree, and a disabled
knob contributes **nothing** to the config — its reason stays in the inventory.

| Knob id | Effect | Required evidence | Kill condition |
|---|---|---|---|
| `debuginfo-line-tables-only` | `profile.dev.debug = "line-tables-only"` | explicit opt-in | debugger can no longer read variables you need |
| `split-debuginfo-unpacked` | `profile.dev.split-debuginfo = "unpacked"` | explicit opt-in | separate debug files are not retained with the binary |
| `zthreads-parallel-frontend` | `-Zthreads=N` | opt-in **and** a nightly whose own `-Z help` reports `threads=val` | p95 regression or ICEs on the parallel frontend |
| `codegen-backend-cranelift` | `profile.dev.codegen-backend = "cranelift"` | opt-in **and** the backend library in that compiler's `codegen-backends/` | any crate the backend cannot compile; runtime of dev binaries matters |
| `linker-wild` / `linker-lld` | `linker = "clang"` + `--ld-path=wild` / `-fuse-ld=lld` | a real `--version` line, **a clang driver to carry the flag**, and a host triple the pack has a spelling for | link failures, or no measured link-time win |
| `target-cpu-baseline` | `-C target-cpu=<baseline>` | an explicit, *portable* baseline | binaries must run on hosts below the baseline |
| `apple-deployment-target` | `MACOSX_/IPHONEOS_DEPLOYMENT_TARGET` | an Apple host triple **and** an explicit version | you must support an older OS than the pin |
| `apple-sdk-baseline` | `SDKROOT` | an Apple host **and** a probed `xcrun` SDK version + path | the pinned SDK is not present on a machine that must build |
| `hakari-workspace-hack` | the `cargo hakari` plan (see below) | `cargo hakari` installed | feature unification changes what a lane actually builds |
| `sccache-baseline` | `build.rustc-wrapper = "sccache"` | `sccache` on PATH | interim competitor baseline only; not a RABS claim |

### Three things the pack refuses to do

1. **It never names a tool the host cannot invoke.** `wild`/`lld` answering
   `--version` is not enough: the rendered flags are carried by the `clang`
   driver, so without clang the pack falls back to the system linker and says
   why. A config that renders `linker = "clang"` on a machine without clang
   breaks *every* build it touches.
2. **It never writes a `[target.<triple>]` section for a triple the host is
   not.** Such a section is silently inert — the knob would report "enabled"
   and change nothing. Worse, Cargo lets target-specific `rustflags` *replace*
   `build.rustflags`, so a section opened by one knob can swallow another
   knob's flags; whenever any knob opens the host's target section, the threads
   flag is mirrored into it.
3. **It never pins a machine-relative baseline.** `-C target-cpu=native`
   resolves to a different CPU on every machine while the rendered pack looks
   identical — precisely the action-key fragmentation this pack exists to
   remove. `native` and `apple-latest` are refused with the request echoed.

## Per-platform baselines

Pin these explicitly rather than inheriting them; they are the inputs that
drift between machines without anyone editing a config file.

| Platform | Baseline to pin | How it is obtained |
|---|---|---|
| Linux x86-64 | `--target-cpu x86-64-v2` (raise to `v3` only if every worker and every consumer supports it) | operator choice, recorded in the pack |
| Linux aarch64 | an explicit `--target-cpu` for the fleet's floor part | operator choice |
| macOS | `--deployment-target 13.0` (or your floor) plus the SDK baseline | `xcrun --show-sdk-version` / `--show-sdk-path`, probed automatically on Apple hosts |
| iOS | `--deployment-target` → `IPHONEOS_DEPLOYMENT_TARGET` | same probe; the variable follows the *platform*, not the vendor |

`target-cpu` is deliberately **unset by default**: a baseline is a
compatibility commitment, and the pack will not make it on your behalf.

## The canonical agent command palette

One spelling per operation. Agents and scripts should use these exact strings —
every extra spelling fragments the action keys that later RABS caching depends
on. They are `PALETTE_V1` in the pack and are asserted by its tests.

| Operation | Canonical invocation |
|---|---|
| check | `cargo check --workspace --all-targets` |
| test | `cargo nextest run --workspace` |
| lint | `cargo clippy --workspace --all-targets -- -D warnings` |
| doctests | `cargo test --workspace --doc` |

Doctests are explicit rather than ambient: `cargo nextest run` does not run
them, so a lane that needs them must say so.

On a dispatcher, run each of these through `rch exec --` so the work lands on a
worker instead of competing with the agents on the local box.

## cargo-hakari / workspace-hack guidance

Feature unification drifts silently. When one lane builds a dependency with a
different feature set than another, the shared build cache stops being shared —
the symptom is a "cold" rebuild nobody can attribute to a source change. A
`workspace-hack` crate fixes the feature set across the workspace so every lane
resolves the same dependency graph.

The pack prescribes one fixed sequence (`HAKARI_PLAN`), and the last step is
the point:

```bash
cargo hakari init workspace-hack   # once, creates the crate
cargo hakari generate              # regenerate after dependency changes
cargo hakari manage-deps           # keep member Cargo.toml edges in sync
cargo hakari verify                # CI GATE: fails when the generated crate drifted
```

`cargo hakari verify` is what belongs in CI. Without it, `generate` is a step
people forget and the drift returns.

**Adopting workspace-hack in a given workspace is a separate decision** with a
real cost (a new crate plus an edge in every member manifest) and a real
benefit that should be measured, not assumed. The pack offers the knob and the
sequence; it does not adopt it for you, and this repository has not adopted it.

## Verifying a change to the pack

Unit tests prove the pack's *decisions*. They cannot prove a decision is
*usable* — a config can be internally consistent and still be rejected by
Cargo, and a rendered flag can quietly never reach the compiler. The end-to-end
proof closes that gap on whatever host it runs on:

```bash
rch exec --job --result-dir l0-proof -- ./scripts/e2e_l0_pack.sh
```

It renders the pack twice (bare and opted-in), asserts the bare render is
inert, builds a real subject with `cargo build --config`, and then reads the
**verbose rustc invocations** back to confirm each rendered flag actually
reached the compiler and is absent from the stock variant. Cold-build samples
are appended in the B015 `layer0-baseline v1` NDJSON shape
(`benchmarks/baselines/`), the same format `scripts/rabs_layer0_bench.sh`
emits.

## Benchmark gating

Every knob ships `BenchmarkVerdict::Ungated`. The pack produces knobs and
evidence; it does not produce verdicts. A consumer that wants the M-1
KILL discipline requires `Kept` before enabling anything beyond the safe core,
and `Kept` comes from B008/B015 runs on real hardware.

### Known fleet gap (2026-09-18)

No worker in the current fleet has `clang`, `lld`, `wild` or `mold` installed,
so the linker knobs cannot engage anywhere on it today and **no link-time
improvement has been measured**. Installing a clang driver plus a fast linker
on the workers is a prerequisite for any Layer-0 link-time claim; until then
the pack correctly reports "no faster linker detected" and leaves the system
linker in place.
