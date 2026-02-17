# ADR-006: storage_ballast_helper Integration Mode

## Status

Accepted

## Date

2026-02-17

## Related Bead

- `bd-vvmd.4.1`

## Context

RCH needs deterministic disk-pressure handling for remote worker fleets so builds do not fail mid-flight due to low disk space. The reliability workstream requires integration with `storage_ballast_helper`, but the integration boundary must preserve:

- RCH fail-open behavior for compilation paths
- Strict safety constraints for reclaim actions
- Clear observability and operator control
- Low coupling and controlled upgrade risk

Two options were evaluated:

1. Direct crate integration (link helper library into `rchd`)
2. CLI adapter integration (invoke helper via stable command contract)

## Decision

Use **CLI adapter integration** as the default and only supported mode for the initial reliability rollout.

RCH will integrate with `storage_ballast_helper` through a versioned adapter contract and structured JSON envelopes, following the same architectural pattern already used for helper boundaries (for example, `repo_updater` contracting).

## Rationale and Tradeoffs

| Dimension | Direct Crate Integration | CLI Adapter Integration (Chosen) |
|---|---|---|
| Latency | Lower per-call overhead | Slight process-spawn overhead; acceptable for non-hot-path maintenance decisions |
| Coupling | Tight compile-time coupling; shared release cadence | Loose coupling; independent versioning and rollout |
| Safety isolation | In-process failure can affect daemon stability | Process boundary contains helper failures and resource abuse |
| Upgrade risk | Higher; helper API changes can force daemon rebuild/redeploy | Lower; compatibility can be managed with schema/version policy |
| Observability | Requires custom instrumentation glue | Natural request/response capture at adapter boundary |
| Operational rollback | Harder to unwind quickly | Fast rollback via feature flags and adapter disable |

Why this is correct for RCH now:

- Disk-pressure handling is not in the sub-millisecond hook classification hot path.
- Safety and rollback control are more important than shaving process-spawn overhead.
- Reliability workstream already depends on strict contract drift detection and clear operator diagnostics.

## Interface and Ownership Boundaries

RCH owns:

- Scheduling policy and when to request disk-pressure actions
- Safety gates and preconditions before any reclaim action is attempted
- Error mapping to RCH taxonomy and fail-open/fail-safe behavior
- Observability requirements and operator-facing status/remediation

`storage_ballast_helper` owns:

- Disk state inspection and candidate ballast/reclaim planning
- Reclaim execution primitives inside its defined scope
- Domain-specific storage decision details within contract bounds

Boundary contract requirements:

- Versioned schema (`schema_version`)
- Stable command surface (status, dry-run, apply, capability probe)
- Structured success/failure envelopes
- Deterministic timeout and retry policy
- Explicit reason codes and remediation hints

## Safety Constraints (Mandatory)

1. No broad or destructive filesystem operations (`rm -rf` style behavior is forbidden by contract and policy).
2. Reclaim scope must be explicitly allowlisted and confined to worker-managed ballast/cache/temp paths.
3. Protected path denylist is mandatory (system dirs, user homes outside managed roots, repo roots not marked safe).
4. Reclaim actions are blocked while conflicting active build operations are present on the same worker unless explicitly safe.
5. Enforced bounded escalation: inspect -> dry-run -> limited apply; never jump directly to unbounded apply.
6. Time and byte budgets are mandatory per reclaim operation with deterministic abort behavior.
7. Any safety-policy ambiguity results in non-destructive failure and no reclaim execution.

## Failure Containment and Rollback Strategy

Containment:

- Helper unavailable/timeout/schema mismatch must not crash or block `rchd`.
- Failures degrade storage-health confidence and feed worker selection penalties/quarantine logic.
- Compilation flow remains fail-open: if storage helper path is unavailable, RCH may skip remote routing for unsafe workers or allow local fallback.

Rollback:

- Feature flag controls:
  - `disabled` (helper not invoked)
  - `observe` (collect diagnostics only; no apply)
  - `enforce` (apply allowed under safety policy)
- Emergency rollback path is a single config flip to `disabled`.
- Rollback must preserve daemon uptime, clear status signaling, and stable command behavior.

## Observability Hooks Required

The adapter integration must emit:

- Structured logs with:
  - worker id
  - operation id
  - mode (`disabled`/`observe`/`enforce`)
  - helper command
  - decision path
  - pressure state
  - reclaim candidate summary
  - safety gate outcomes
  - final action/result code
- Metrics:
  - helper invocation counts by outcome
  - timeout/retry counts
  - reclaim attempted/succeeded/blocked counts
  - bytes reclaimed
  - duration histograms
  - suppression counts due to policy gates
- Tracing spans across selection -> helper decision -> action outcome for per-build correlation

## Operational Policy

- Default rollout starts in `observe` mode.
- Promotion to `enforce` requires passing reliability criteria and explicit approvals.
- If all workers are disk-unsafe and helper cannot safely resolve, scheduler must surface reason-coded diagnostics and preserve fail-open local execution behavior.

## Approval and Sign-Off Criteria

Before broad enablement of `enforce` mode, all must be true:

1. Reliability sign-off:
   - contract conformance tests passing
   - failure containment behavior validated
   - no unsafe action paths in policy audit
2. Operations sign-off:
   - runbook validated for diagnose/dry-run/repair/rollback
   - observability dashboards and alerting thresholds validated
   - canary results reviewed with no unresolved high-risk findings
3. Compatibility sign-off:
   - helper version matrix checked against supported policy
   - schema drift tests green

## Consequences

Positive:

- Strong failure isolation and safer operational posture
- Clear rollback path and independent helper lifecycle
- Better auditability of storage decisions and actions

Negative:

- Slight additional latency for helper invocations
- More contract/schema management overhead

Mitigations:

- Keep helper calls out of ultra-hot paths
- Use bounded retries/timeouts and cached capability checks
- Add compatibility suite and explicit contract drift detection

## Implementation Follow-Ons

- `bd-vvmd.4.2`: daemon integration for disk-pressure monitor + ballast policy engine
- `bd-vvmd.4.3` and `bd-vvmd.4.5`: worker selection and capabilities integration
- `bd-vvmd.6.11`: compatibility/contract drift suite

