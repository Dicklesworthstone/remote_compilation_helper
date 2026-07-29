# bd-784xt live proof — self-test canary tolerates heterogeneous-toolchain codegen drift

**Date:** 2026-06-21 (UTC)
**Daemon under test:** rchd commit `6d5dd9f16e83` (HEAD), freshly built + restarted
(running `/proc/<pid>/exe` sha256 verified == `target_deploy_784xt/release/rchd`).
**Prior daemon (control):** rchd commit `2998dde98ca6` — 6 commits behind HEAD,
predates the fix `ef1970e`.

## What bd-784xt fixed

The daemon self-test canary's old success criterion was bit-for-bit equivalence
between the LOCAL reference build (orchestrator) and the REMOTE build (worker).
On a heterogeneous fleet where a worker's `rustc` nightly differs from the
orchestrator's, codegen differs legitimately, so a healthy worker was marked
FAILED. The fix classifies the canary into a `CanaryVerdict`
(`rch-common/binary_hash.rs::classify_canary`): byte-mismatch + marker present +
differing/unknown toolchain → `ToolchainDrift` (advisory PASS, `RCH-I018`), while
a missing marker (`MissingMarker`, `RCH-I014`) or a byte mismatch on a confirmed-
identical toolchain (`Miscompile`, `RCH-E203`) still FAIL.

## AFTER — fresh daemon 6d5dd9f (run 28): PASS on byte-mismatch

`RCH_JSON=1 rch self-test --worker hz2 --json` →

```json
{
  "run": { "id": 28, "workers_tested": 1, "workers_passed": 1, "workers_failed": 0, "duration_ms": 8184 },
  "results": [
    { "run_id": 28, "worker_id": "hz2", "passed": true,
      "local_hash":  "770654ff8204f7e12dd915b28fcd4b1cf2cb4a15102496fd6e61f840541c226d",
      "remote_hash": "4d5b5c5264c83b6f3b8f1f4adfbb50be836314d7cb77e5bfd795ce350d800814",
      "local_time_ms": 330, "remote_time_ms": 1646, "error": null } ]
}
```

The hashes DIFFER (heterogeneous codegen) yet the worker PASSES. Daemon log shows
the exact verdict + reason code:

```
INFO rch_common::remote_compilation: Verification PASSED (advisory RCH-I018):
  worker healthy; codegen differs from the orchestrator toolchain
  (local=770654ff8204f7e1 remote=4d5b5c5264c83b6f)
```

(The marker `RCH_TEST_1782013539652` was searched and found in the remote binary
before the verdict — corruption would have produced `MissingMarker`/FAIL.)

## BEFORE — old daemon 2998dde (runs 26 & 27, earlier same day): FAIL on byte-mismatch

`rch self-test history` control rows produced by the pre-fix daemon:

```
27  manual  2026-06-20T20:06:54Z  2915ms   0 passed  1 failed
    ✗ hz1: Binary hash mismatch: local=2ed9f2c1fccfd4d6 remote=49095c050338f5db
26  manual  2026-06-20T20:06:51Z 10967ms   0 passed  1 failed
    ✗ vmi1227854: Binary hash mismatch: local=c300aa22e3af8615 remote=f2cf71028ace9f5d
```

Identical condition (healthy worker, byte mismatch), opposite outcome: the pre-fix
daemon reported a hard "Binary hash mismatch" FAILURE; the fixed daemon PASSES with
the `RCH-I018` toolchain-drift advisory.

## Acceptance mapping

- "no false FAILED for a healthy worker whose rustc differs": PROVEN (run 28 hz2).
- "a genuine miscompile/corruption is still caught": marker-absent → `MissingMarker`
  FAIL (corruption); same-toolchain byte mismatch → `Miscompile` FAIL. The run()
  path conservatively passes `toolchains_match=None` (bead option 2, endorsed), so
  live mismatches resolve to advisory drift; `classify_canary` fully supports and
  unit-tests the `Some(true) -> Miscompile` activation (bead option 3) as a future
  follow-up that needs only the worker rustc threaded in — no new logic.
- "distinct reason codes": `RCH-I018` drift (advisory), `RCH-E203` miscompile,
  `RCH-I014` missing marker.
- "unit tests for the verdict logic": `binary_hash.rs` classify_canary tests
  (incl. the live hz2-style hashes).
