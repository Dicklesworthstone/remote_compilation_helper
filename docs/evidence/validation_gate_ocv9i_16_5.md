# ocv9i.16.5 — CI/release validation-matrix gate

**Date:** 2026-06-21 (UTC). **Deliverable:** `scripts/ci_validation_gate.sh`
(+ `scripts/lib/audit_closed_beads.py`).

A single gate that wires the program's validation matrix into one CI/release
check that runs WITHOUT a live fleet. Live-worker stages are skipped by default
(`--live` opts in). Produces a Markdown + JSON summary with per-stage and
per-bead status; every failed stage carries an exact reason code and the owning
remediation bead id.

## Stages and signals

| Stage | What it runs | Reason code on fail | Remediation |
|---|---|---|---|
| dep_cycles | `br dep cycles` is empty | RCH-GATE-DEP-CYCLE | …16.5 |
| closed_bead_evidence | every closed program bead cites commands/artifacts | RCH-GATE-EVIDENCE-MISSING | …16.5 |
| matrix | `cargo test -p rch-common --test reliability_coverage_matrix_e2e` | RCH-GATE-MATRIX-GAP | …16.1 |
| schema_goldens | `cargo test -p rch-common --test golden_schemas_e2e` | RCH-GATE-SCHEMA-DRIFT | …16.4 |
| ci_tiers | `cargo test -p rch-common --test ci_test_tiers_e2e` | RCH-GATE-TIER-DRIFT | …16.1 |
| e2e_mock | `e2e_remediation_program.sh --dry-run --mock-worker` | RCH-GATE-E2E-FAIL | …16.3 |
| perf_budgets | `e2e_perf_budgets.sh` (hot-path budgets) | RCH-GATE-PERF-REGRESSION | …16.7 |
| live_smoke | `e2e_real_fleet_smoke.sh` (OPT-IN `--live`) | RCH-GATE-LIVE-SMOKE-FAIL | …16.6 |

Flags: `--quick` (fast checks only), `--strict` (a commit-only thin close becomes
a hard FAIL), `--live` (include live-worker stages), `--offload` (route cargo
stages through `rch exec` to spare local CPU; falls back to local cargo).

## Green run — `ci_validation_gate.sh --offload`

```
[pass] dep_cycles             no cycles
[pass] closed_bead_evidence   all closed program beads cite evidence
[pass] matrix                 ok (offloaded)        # 28 tests
[pass] schema_goldens         ok (offloaded)        # 18 tests
[pass] ci_tiers               ok (offloaded)        # 18 tests
[pass] e2e_mock               ok                    # 8/8 scenarios
[pass] perf_budgets           ok                    # 12/12 budgets within target
[skip] live_smoke             skipped by default (pass --live)
Stages: 7 pass / 0 fail / 1 skip   ->   VALIDATION GATE: PASS
Closed-bead evidence: 58 pass / 3 warn / 0 fail (of 61 program beads)
```

## The gate caught a real regression while being built

The `schema_goldens` stage initially FAILED: `incident_reason_code_vocabulary_is_frozen`
showed the live vocabulary had **18** codes (incl. `RCH-I018 toolchain drift`,
added by the bd-784xt fix) while the frozen golden still listed **17**. The
bd-784xt change updated `incident.rs` + `rch-telemetry/remediation.rs` but missed
this golden. Fixed by adding the intentional `("RCH-I018", "toolchain drift")`
entry to the frozen list (`rch-common/tests/golden_schemas_e2e.rs`); the stage is
now green (18/18). This is precisely the agent-facing-contract drift the gate
exists to catch.

## Closed-bead evidence audit

`audit_closed_beads.py` scans every CLOSED, non-epic, non-docs bead under
`bd-session-history-remediation-ocv9i.*` and verifies the close_reason cites real
validation (tests / commands / REQ rows / files / artifacts / commit). 61 beads:
58 PASS, 3 WARN (10.3 / 11.2 / 12.3 — commit-only thin closes, flagged for review,
not a hard fail in default mode; `--strict` promotes them to FAIL), 0 FAIL.

## Acceptance mapping

- "CI can run without live fleet workers": all default stages use mock/dry-run; the
  one live stage is skipped unless `--live`.
- "Slow/live-worker tests separately labeled and skipped by default": `live_smoke`
  is opt-in.
- "Gate produces a concise Markdown and JSON summary with per-bead status":
  `target/validation-gate/summary.md` + `summary.json` (per-stage + per-bead).
- "A failed scenario includes the exact reason code and remediation bead id": each
  stage row + the failed-stage section carry both.
- "verify br dep cycles remains empty": the `dep_cycles` stage.
- "no implementation bead is closed without close-reason evidence": the
  `closed_bead_evidence` stage.
- The gate EXECUTES the program's coverage matrix (`reliability_coverage_matrix_e2e`)
  rather than adding a new matrix row — it is the meta-check that wires the matrix
  into CI.
