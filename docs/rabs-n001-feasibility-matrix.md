# N001 Feasibility Matrix — Build-Script Run-Cache Interception Contracts

Bead: `rabs-root-4pidu.32.1` (Epic N, plan §196).
Harness: `rabs-wrap/tests/n001_contract.rs` (self-contained; probes every
installed channel; every cargo invocation runs under a 120s hard deadline
and a hang is RECORDED, never stalled through). Fixture:
`rabs-wrap/tests/fixtures/n001_run_cache/` (standalone package, std-only,
directive-emitting build script that records its own invocation facts).

**Serving flag:** `rabs_protocol::run_cache_gate::RunCacheGate` — disabled
by default; enabled per (channel, mechanism) only by an admitted positive
`FeasibilityProof`; negative proofs are refused loudly and leave no
residue.

## Method

Per channel: (1) fresh stock build; (2) immediate no-op rebuild — the
directive cache mtime must NOT move (`rerun-if-changed` honored); (3)
launcher-shim experiment — displace the real build-script binary at EVERY
name cargo could exec it through, install a recording shim at each path,
no-op rebuild again, then measure whether cargo ran our file and whether
semantics survived.

Contract points measured (the bead's list): executable identity, mtimes /
fingerprint stability, output-cache behavior, inherited jobserver
descriptors (`CARGO_MAKEFLAGS --jobserver-fds=`).

## Cargo layout vintages discovered (content-verified)

| vintage | compile artifacts | directive cache | OUT_DIR |
|---|---|---|---|
| stable / beta (flat) | `build/<pkg>-<hash>/build-script-build` (+ hardlink `build_script_build-<hash>`) | `build/<pkg>-<hash>/output` | `build/<pkg>-<hash>/out/` |
| nightly 1.100.0-nightly (nested) | `build/<pkg>/<hash>/out/build_script_build` | `build/<pkg>/<run-hash>/run/stdout` | `build/<pkg>/<run-hash>/out/` |

The harness identifies dirs by CONTENT, never by name spelling, so a
future vintage fails loudly with a forensic dump instead of silently
probing the wrong file.

## Measured matrix (worker vmi1227854, 2026-08-22)

Rows quoted from the harness JSON (test stdout), lightly formatted.
`shim timeout` = the shim-mediated run hit the 120s budget.

### stable

```json
{"channel":"stable",
 "stock":{"fresh_build_ok":true,"reran_on_noop":false,
          "jobserver_makeflags_seen":true,"jobserver_fd_pair_seen":true},
 "launcher_shim":{"shim_build_succeeded":true,"shim_timed_out":true,
          "shim_executed":true,"cargo_proceeded_without_shim":false,
          "binary_bytes_changed":true,
          "jobserver_inherited_through_shim":true,
          "output_cache_correct":true}}
```

### beta — identical shape to stable

```json
{"channel":"beta",
 "stock":{"fresh_build_ok":true,"reran_on_noop":false,
          "jobserver_makeflags_seen":true,"jobserver_fd_pair_seen":true},
 "launcher_shim":{"shim_build_succeeded":true,"shim_timed_out":true,
          "shim_executed":true,"cargo_proceeded_without_shim":false,
          "binary_bytes_changed":true,
          "jobserver_inherited_through_shim":true,
          "output_cache_correct":true}}
```

### nightly (nested-layout vintage)

```json
{"channel":"nightly",
 "stock":{"fresh_build_ok":true,"reran_on_noop":true,
          "jobserver_makeflags_seen":true,"jobserver_fd_pair_seen":true},
 "launcher_shim":{"shim_build_succeeded":true,"shim_timed_out":false,
          "shim_executed":true,"cargo_proceeded_without_shim":false,
          "binary_bytes_changed":true,
          "jobserver_inherited_through_shim":true,
          "output_cache_correct":true}}
```

## Findings

1. **The shim IS executed once every name-path is covered.** An earlier
   partial harness revision displaced only one of two hardlinked names
   and reported `shim_executed:false` — a measurement artifact. With all
   names displaced and shimmed, cargo executes the planted file on every
   channel. Mechanism 2 is *mechanically* live everywhere.
2. **Semantics did NOT survive uniformly.** On stable/beta the
   shim-mediated run stalled past the 120s budget (`shim_timed_out:true`)
   even though the jobserver descriptors reached the shim and the output
   cache ended up correct. A run-cache that must preserve stock timing
   semantics cannot ship on that evidence. Nightly completed end-to-end
   through the shim on this vintage — but see finding 4 before reading
   that as durable.
3. **Fingerprint stability varies by vintage/worker.** The same no-op
   probe measured `reran_on_noop:false` for stable/beta on one worker
   (2026-08-22, earlier run) and `true` on another run of the same day —
   consistent with coarse-mtime rerun edges in some cargo builds. Any
   serving design keyed to "did not rerun" observations must treat
   single-run fingerprints as unstable evidence.
4. **Nightly layout is in motion** (`build/<pkg>/<hash>/{run,out,
   fingerprint}` appeared between toolchains installed weeks apart).
   A shim pinned to any single layout is obsolete by construction;
   mechanism-2 proofs are vintage-pinned via the evidence digest.
5. **Jobserver inheritance survives interception paths tested** — both
   stock build scripts and shim-mediated executions saw
   `--jobserver-fds=` with a read/write pair. This contract point is the
   healthiest across all channels.

## Verdict (drives the gate defaults)

| mechanism | stable | beta | nightly |
|---|---|---|---|
| canonical-driver integration | not yet proven (harness measures it at the driver layer, N002/M11 scope) | not yet proven | not yet proven |
| launcher shim | **NO-GO today** (timed-out mediated run) | **NO-GO today** (timed-out mediated run) | GO on this vintage only |

Therefore `RunCacheGate::disabled()` is the shipped posture: no channel
gets serving until ITS mechanism proof lands as an admitted positive.
Re-run the harness after any cargo/toolchain bump; admit the fresh row's
digest. The gate refuses re-admission with a different digest for the
same pair, so stale proofs cannot quietly outlive their evidence.

## Reproduction

```bash
cargo test -p rabs-wrap --test n001_contract -- --nocapture
```
(RCH offloads this fine; the harness bounds itself.)
