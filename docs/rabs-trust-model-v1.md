# RABS Trust Model V1 — Single Administrative Domain

Bead S014 (plan §106). Machine-readable twin:
`rabs-protocol/src/trust_domain.rs` — a test pins every non-claim
code below against that registry, so this document cannot drift from
the code.

## The claim

RABS V1 operates inside **one trusted administrative fleet**: every
coordinator, worker, and client is provisioned and operated by the
same administrative authority. Peers authenticate (S001), capabilities
are least-privilege (S003), secrets are redacted (S007), and per-peer
resource limits bound damage from bugs and misbehaving builds (S008)
— but these controls harden a *trusted* fleet; they are not tenant
isolation.

## The explicit non-claims (V1)

Documentation, marketing, and decision receipts must not overclaim.
The following are **deliberately not promised** in V1, each with its
stable code (the same strings ride `DecisionReceipt.non_claims`):

| Code | What is NOT promised |
|---|---|
| `NO_CLAIM_MULTI_TENANT_ISOLATION` | Isolation between mutually untrusting tenants sharing a fleet. |
| `NO_CLAIM_CROSS_USER_ISOLATION` | Isolation between distinct human users inside the domain beyond ordinary OS accounts. |
| `NO_CLAIM_UNTRUSTED_CODE_CONFINEMENT` | Confinement of actively malicious build scripts/proc-macros against a determined attacker. Sandboxing (E002/E004) reduces accident surface; it is not a security boundary against the fleet operator's own workloads. |
| `NO_CLAIM_BYZANTINE_WORKER_TOLERANCE` | Correctness under workers that lie in their attestations. Verification (F024, O-series) catches drift, not coordinated deception. |

Cross-user/multi-tenant isolation is a **separate future program**
with its own design, review gates, and threat model; nothing in V1
grows into it by default. A deployment configuration requesting a
multi-tenant posture is a typed refusal at admission
(`TrustRefusal::MultiTenancyNotClaimed`), never a degraded accept.

## Where the boundary is enforced

- `trust_domain::evaluate_deployment` — the fail-closed gate.
- `trust_domain::v1_non_claims()` — the receipt/non-claim registry.
- A015 authority matrix (`authority_matrix.rs`) — per-profile serving
  authority with explicit claim boundaries per cell.
