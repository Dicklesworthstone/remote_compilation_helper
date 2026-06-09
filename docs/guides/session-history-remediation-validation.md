# Session History Remediation Validation Contract

This is the canonical validation contract for the `bd-session-history-remediation-ocv9i`
program. Every implementation bead in the P0/P1/P2 remediation program must map
to proof before it closes.

## Required Proof Package

Each implementation bead must either add coverage or explicitly link to an
existing scenario that already covers the same behavior. The close reason must
name the evidence.

Required evidence vocabulary:

- unit tests
- integration tests
- E2E script scenario
- fault injection
- golden JSON/schema checks
- performance budget checks
- close-reason evidence

Standard JSONL and structured-test fields:

- `run_id`
- `bead_id`
- `scenario`
- `event`
- `status`
- `reason_code`
- `worker_id`
- `command_fingerprint`
- `duration_ms`
- `detail`

Implementation beads must include a validation section in the bead description,
the PR/commit narrative, or an adjacent test comment that references this
contract path:

`docs/guides/session-history-remediation-validation.md`

## Agent Control and Placement Coverage

The validation program must keep explicit coverage for agent-visible placement
and strict-remote controls:

- `RCH_WORKER`
- `RCH_VISIBILITY`
- `RCH_QUEUE_WHEN_BUSY`
- `RCH_FORCE_REMOTE`
- `RCH_REQUIRE_REMOTE`
- `RCH_NO_SELF_HEALING`
- wait timeout controls
- `--worker`
- `--all`
- `--timeout`
- worker-scoped target-dir diagnostics
- registry/package-cache availability
- target availability reason codes

These controls map primarily to `bd-session-history-remediation-ocv9i.10`,
`bd-session-history-remediation-ocv9i.12`,
`bd-session-history-remediation-ocv9i.13`, and
`bd-session-history-remediation-ocv9i.17`. Any implementation bead that changes
placement, queueing, strict remote behavior, runtime discovery, package cache
use, or target-dir diagnostics must add unit/integration coverage plus golden
output checks for the affected operator or agent surface.

## Raw Failure Classes

The matrix must preserve the raw failure classes found in session history. These
strings are intentionally operator-facing, not internal enum names:

| Failure class | Required proof |
| --- | --- |
| no admissible workers | admission unit tests, selection integration tests, E2E script scenario with all candidates rejected, close-reason evidence |
| critical pressure | pressure fault injection, doctor integration tests, E2E script scenario, close-reason evidence |
| insufficient slots | queue/admission unit tests, storm-control E2E script scenario, performance budget checks |
| hard preflight | candidate-preflight integration tests, golden JSON/schema checks for rejection output |
| active project exclusion | path dependency and admission integration tests, E2E script scenario with excluded project root |
| missing runtime/toolchain/Rust target | worker capability unit tests, fleet probe integration tests, golden JSON/schema checks |
| OS/arch mismatch | target triple unit tests, fleet-update integration tests, E2E script scenario |
| telemetry stale/age unknown | telemetry freshness unit tests, doctor integration tests, golden JSON/schema checks |
| circuit open | worker lifecycle unit tests, fault injection, E2E script scenario |
| daemon socket refused | hook self-healing integration tests, E2E script scenario, close-reason evidence |
| local fallback | exec/admission integration tests, golden JSON/schema checks, E2E script scenario |
| proof refusal | proof-mode unit tests, deferred replay integration tests, close-reason evidence |
| rsync vanished file | transfer fault injection, E2E script scenario, close-reason evidence |
| artifact miss | artifact retrieval integration tests, golden JSON/schema checks, E2E script scenario |
| queue ambiguity | queue identity unit tests, reattach integration tests, E2E script scenario |
| disk full | disk pressure fault injection, doctor integration tests, E2E script scenario |
| wrong user/path worker binary | fleet post-deploy validation integration tests, E2E script scenario, close-reason evidence |

## Epic Matrix

| Bead | Priority | Scope | Required validation package |
| --- | --- | --- | --- |
| `bd-session-history-remediation-ocv9i` | P0 | Program-level remediation from session history | This contract plus close-reason evidence for every child |
| `bd-session-history-remediation-ocv9i.1` | P0 | Temporary bypass and auto-rejoin worker lifecycle | circuit open coverage, worker lifecycle unit tests, fault injection, E2E script scenario |
| `bd-session-history-remediation-ocv9i.2` | P0 | Desired-state fleet reconciliation | no admissible workers coverage, integration tests, golden JSON/schema checks |
| `bd-session-history-remediation-ocv9i.3` | P0 | Hook daemon doctor mutual self-healing | daemon socket refused coverage, integration tests, E2E script scenario |
| `bd-session-history-remediation-ocv9i.4` | P0 | Incident ledger and readiness split | reason-code registry tests, golden JSON/schema checks, close-reason evidence |
| `bd-session-history-remediation-ocv9i.5` | P0 | Proof mode and deferred proof queue | proof refusal coverage, unit tests, integration tests, E2E script scenario |
| `bd-session-history-remediation-ocv9i.6` | P0 | Admission explainer and reason-code vocabulary | all admission failure classes, golden JSON/schema checks, E2E script scenario |
| `bd-session-history-remediation-ocv9i.7` | P0 | OS/arch-aware fleet update and worker binary validation | OS/arch mismatch and wrong user/path worker binary coverage |
| `bd-session-history-remediation-ocv9i.16` | P0 | Cross-cutting validation, fault injection, and release gates | fault injection, golden JSON/schema checks, performance budget checks |
| `bd-session-history-remediation-ocv9i.8` | P1 | Path dependency convergence and sync explainability | active project exclusion and rsync vanished file coverage |
| `bd-session-history-remediation-ocv9i.9` | P1 | Artifact retrieval target-dir precision and file-count cost model | artifact miss coverage, golden JSON/schema checks, performance budget checks |
| `bd-session-history-remediation-ocv9i.10` | P1 | Capacity queue semantics and job reattach | insufficient slots and queue ambiguity coverage |
| `bd-session-history-remediation-ocv9i.11` | P1 | Disk-pressure and target-dir management program | critical pressure and disk full coverage |
| `bd-session-history-remediation-ocv9i.12` | P1 | Explicit worker capability inventory | missing runtime/toolchain/Rust target coverage |
| `bd-session-history-remediation-ocv9i.13` | P1 | Explicit `rch exec` ergonomics for agents | local fallback and proof visibility coverage |
| `bd-session-history-remediation-ocv9i.14` | P1 | Telemetry freshness and daemon log retention | telemetry stale/age unknown coverage |
| `bd-session-history-remediation-ocv9i.17` | P1 | Config defaults, installer, and upgrade rollout | config schema integration tests, E2E script scenario, golden JSON/schema checks |
| `bd-session-history-remediation-ocv9i.15` | P2 | Operational skill runbook and postmortem workflow refresh | docs-only coverage plus close-reason evidence |

## Implementation Bead Matrix

| Bead | Failure class focus | Required validation mapping |
| --- | --- | --- |
| `bd-session-history-remediation-ocv9i.1.1` | circuit open | unit tests for lifecycle type model; golden JSON/schema checks for admin-disabled vs temporary-bypass states; close-reason evidence |
| `bd-session-history-remediation-ocv9i.1.2` | circuit open | integration tests for persisted bypass records; E2E script scenario for status output; close-reason evidence |
| `bd-session-history-remediation-ocv9i.1.3` | circuit open | fault injection for failing and recovering probes; performance budget checks for backoff; close-reason evidence |
| `bd-session-history-remediation-ocv9i.2.1` | no admissible workers | unit tests for desired-state inventory; integration tests for live eligibility diff; golden JSON/schema checks |
| `bd-session-history-remediation-ocv9i.2.2` | no admissible workers | E2E script scenario for empty fleet and all-absent fleet; golden JSON/schema checks; close-reason evidence |
| `bd-session-history-remediation-ocv9i.3.1` | daemon socket refused | hook integration tests for autostart retry; E2E script scenario with refused socket; close-reason evidence |
| `bd-session-history-remediation-ocv9i.3.2` | daemon socket refused | daemon startup unit tests; integration tests for socket consistency; golden JSON/schema checks |
| `bd-session-history-remediation-ocv9i.3.3` | daemon socket refused | doctor integration tests for hook daemon remediation; E2E script scenario; close-reason evidence |
| `bd-session-history-remediation-ocv9i.4.1` | hard preflight | unit tests for incident event schema; golden JSON/schema checks for reason-code registry |
| `bd-session-history-remediation-ocv9i.4.2` | local fallback | integration tests for append-only ledger writer and reader; close-reason evidence |
| `bd-session-history-remediation-ocv9i.4.3` | local fallback | E2E script scenario for incident-chain replay; golden JSON/schema checks |
| `bd-session-history-remediation-ocv9i.5.1` | proof refusal | unit tests for fail-closed proof-mode policy; integration tests for local fallback refusal; close-reason evidence |
| `bd-session-history-remediation-ocv9i.5.2` | proof refusal | golden JSON/schema checks for proof intent schema; integration tests for durable store |
| `bd-session-history-remediation-ocv9i.5.3` | proof refusal | integration tests for replay state machine; E2E script scenario for deferred proof replay |
| `bd-session-history-remediation-ocv9i.5.4` | proof refusal | golden JSON/schema checks for proof output and Beads handoff; close-reason evidence |
| `bd-session-history-remediation-ocv9i.6.1` | hard preflight; insufficient slots | unit tests for command classification and candidate preflight; E2E script scenario for rejected candidates |
| `bd-session-history-remediation-ocv9i.6.2` | no admissible workers; missing runtime/toolchain/Rust target | unit tests for rejection aggregation; golden JSON/schema checks for reason vocabulary |
| `bd-session-history-remediation-ocv9i.6.3` | hard preflight | classifier drift unit tests; performance budget checks for bounded refresh |
| `bd-session-history-remediation-ocv9i.6.4` | no admissible workers | golden JSON/schema checks for next-action recommendations; E2E script scenario |
| `bd-session-history-remediation-ocv9i.7.1` | OS/arch mismatch | unit tests for target triple discovery; integration tests for artifact resolver |
| `bd-session-history-remediation-ocv9i.7.2` | wrong user/path worker binary | integration tests for atomic switch and rollback-safe deploy; fault injection for failed deploy |
| `bd-session-history-remediation-ocv9i.7.3` | wrong user/path worker binary | E2E script scenario for post-deploy user/path/protocol validation; close-reason evidence |
| `bd-session-history-remediation-ocv9i.7.4` | OS/arch mismatch | golden JSON/schema checks for provenance signature; integration tests for rollback audit |
| `bd-session-history-remediation-ocv9i.8.1` | active project exclusion | integration tests for path dependency closure explain output; golden JSON/schema checks |
| `bd-session-history-remediation-ocv9i.8.2` | rsync vanished file | transfer fault injection for vanished files; E2E script scenario; close-reason evidence |
| `bd-session-history-remediation-ocv9i.8.3` | active project exclusion | E2E script scenario for force resync guardrails; close-reason evidence |
| `bd-session-history-remediation-ocv9i.9.1` | artifact miss | unit tests for target-dir-aware artifact rewriting; golden JSON/schema checks |
| `bd-session-history-remediation-ocv9i.9.2` | artifact miss | performance budget checks for file-count cost model; integration tests for manifest mode |
| `bd-session-history-remediation-ocv9i.9.3` | artifact miss | E2E script scenario for retrieval diagnostics and source-integrity tests |
| `bd-session-history-remediation-ocv9i.10.1` | queue ambiguity | unit tests for local/remote job identity correlation; golden JSON/schema checks |
| `bd-session-history-remediation-ocv9i.10.2` | insufficient slots; queue ambiguity | E2E script scenario for wait stream and no-start contract; close-reason evidence |
| `bd-session-history-remediation-ocv9i.10.3` | queue ambiguity | integration tests for reattach, cancel, and stuck-wrapper recovery |
| `bd-session-history-remediation-ocv9i.10.4` | insufficient slots | multi-agent storm-control E2E script scenario; performance budget checks |
| `bd-session-history-remediation-ocv9i.11.1` | disk full | unit tests for mount-aware root and cargo-home selection; integration tests |
| `bd-session-history-remediation-ocv9i.11.2` | critical pressure | performance budget checks for pooled target dirs; fault injection for stale reaper |
| `bd-session-history-remediation-ocv9i.11.3` | disk full | fault injection for reclaim under active builds; close-reason evidence |
| `bd-session-history-remediation-ocv9i.11.4` | critical pressure; disk full | doctor integration tests for inode, target-root, cargo-home, and log pressure reports |
| `bd-session-history-remediation-ocv9i.12.1` | missing runtime/toolchain/Rust target | golden JSON/schema checks for worker fact schema |
| `bd-session-history-remediation-ocv9i.12.2` | missing runtime/toolchain/Rust target; wrong user/path worker binary | integration tests for exact user/path probes |
| `bd-session-history-remediation-ocv9i.12.3` | missing runtime/toolchain/Rust target; hard preflight | selection unit tests for missing-capability reasons; golden JSON/schema checks |
| `bd-session-history-remediation-ocv9i.12.4` | missing runtime/toolchain/Rust target | integration tests for workers.toml SSH config and live fact validation |
| `bd-session-history-remediation-ocv9i.13.1` | local fallback | unit tests for quoted `rch exec` misuse detection; golden JSON/schema checks |
| `bd-session-history-remediation-ocv9i.13.2` | local fallback | integration tests for non-compilation policy and messaging; close-reason evidence |
| `bd-session-history-remediation-ocv9i.13.3` | local fallback | golden JSON/schema checks for execution-location contract; E2E script scenario |
| `bd-session-history-remediation-ocv9i.13.4` | proof refusal | golden JSON/schema checks for agent discovery surfaces |
| `bd-session-history-remediation-ocv9i.13.5` | proof refusal; queue ambiguity | integration tests for placement queue visibility; E2E script scenario |
| `bd-session-history-remediation-ocv9i.14.1` | telemetry stale/age unknown | unit tests for adaptive telemetry freshness model; performance budget checks |
| `bd-session-history-remediation-ocv9i.14.2` | telemetry stale/age unknown | golden JSON/schema checks for why-unhealthy status |
| `bd-session-history-remediation-ocv9i.14.3` | telemetry stale/age unknown; disk full | doctor integration tests for log rotation and log-pressure reporting |
| `bd-session-history-remediation-ocv9i.14.4` | telemetry stale/age unknown | integration tests for dashboard data adapters; golden JSON/schema checks |
| `bd-session-history-remediation-ocv9i.14.5` | telemetry stale/age unknown | integration tests for Prometheus and OpenTelemetry metrics; golden JSON/schema checks |
| `bd-session-history-remediation-ocv9i.16.1` | all failure classes | this contract, docs validation tests, close-reason evidence |
| `bd-session-history-remediation-ocv9i.16.2` | all failure classes | reusable fault injection fixtures for every raw failure class |
| `bd-session-history-remediation-ocv9i.16.3` | all failure classes | E2E script scenario coverage with JSONL logging fields |
| `bd-session-history-remediation-ocv9i.16.4` | all failure classes | golden JSON/schema checks and agent-output regression tests |
| `bd-session-history-remediation-ocv9i.16.5` | all failure classes | CI release gate enforcing this matrix |
| `bd-session-history-remediation-ocv9i.16.6` | all failure classes | real-fleet smoke and soak validation profile |
| `bd-session-history-remediation-ocv9i.16.7` | all failure classes | hot-path performance budget checks and regression suite |
| `bd-session-history-remediation-ocv9i.16.8` | all failure classes | redaction unit tests, privacy policy checks, golden JSON/schema checks |
| `bd-session-history-remediation-ocv9i.17.1` | local fallback | golden JSON/schema checks for config schema and default policy |
| `bd-session-history-remediation-ocv9i.17.2` | daemon socket refused | installer integration tests and doctor rollout E2E script scenario |
| `bd-session-history-remediation-ocv9i.17.3` | local fallback | config rollout E2E logs and golden tests |

## Documentation-Only Children

These P2 children are explicitly documentation beads. They are not considered
implementation beads for the release gate, but their close reasons still must
name the review evidence.

| Bead | Required evidence |
| --- | --- |
| `bd-session-history-remediation-ocv9i.15.1` | close-reason evidence for the refreshed canonical RCH skill |
| `bd-session-history-remediation-ocv9i.15.2` | close-reason evidence for rewritten safe automated recovery runbooks |
| `bd-session-history-remediation-ocv9i.15.3` | close-reason evidence for CASS query pack and raw-session fallback |

## Release Gate

Before closing any non-doc remediation child bead:

1. Add or link unit tests and integration tests for the behavior surface.
2. Add or link an E2E script scenario when the behavior crosses process,
   worker, filesystem, network, or agent boundaries.
3. Add fault injection for failure-path behavior.
4. Add golden JSON/schema checks for any agent- or operator-consumed output.
5. Add performance budget checks for hook, admission, queue, transfer, telemetry,
   or target-dir hot paths.
6. Put the evidence in the bead close reason.

If a proof category is not applicable, the close reason must say why and name the
existing scenario that covers the equivalent risk.
