//! Single-administrative-domain V1 + the multi-tenant non-claim
//! (bead S014; plan §106; documentation twin:
//! `docs/rabs-trust-model-v1.md`, pinned by test).
//!
//! V1 claims ONE trusted administrative fleet and nothing more.
//! Cross-user/multi-tenant isolation is a separate future program:
//!
//! - the non-claims are a CLOSED registry of stable codes — the same
//!   strings decision receipts (R001) carry, so receipts can state
//!   what they do NOT assert without inventing spellings;
//! - a deployment configuration requesting a multi-tenant posture is
//!   a TYPED REFUSAL at admission, never a degraded accept — the
//!   system cannot be talked into overclaiming;
//! - the documentation twin is pinned by test: every code below must
//!   appear verbatim in the doc, so prose and registry cannot drift.

/// The V1 trust model (the only one).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrustModel {
    /// One trusted administrative fleet: every coordinator, worker,
    /// and client provisioned by the same administrative authority.
    SingleAdministrativeDomain,
}

/// The V1 trust model constant.
pub const TRUST_MODEL_V1: TrustModel = TrustModel::SingleAdministrativeDomain;

/// Stable non-claim codes (the closed V1 registry; receipts carry
/// these exact strings).
pub const NO_CLAIM_MULTI_TENANT_ISOLATION: &str = "NO_CLAIM_MULTI_TENANT_ISOLATION";
/// Cross-user isolation beyond ordinary OS accounts.
pub const NO_CLAIM_CROSS_USER_ISOLATION: &str = "NO_CLAIM_CROSS_USER_ISOLATION";
/// Confinement of actively malicious build code.
pub const NO_CLAIM_UNTRUSTED_CODE_CONFINEMENT: &str = "NO_CLAIM_UNTRUSTED_CODE_CONFINEMENT";
/// Correctness under lying workers.
pub const NO_CLAIM_BYZANTINE_WORKER_TOLERANCE: &str = "NO_CLAIM_BYZANTINE_WORKER_TOLERANCE";

/// Every V1 non-claim, in registry order (count pinned by test).
#[must_use]
pub const fn v1_non_claims() -> [&'static str; 4] {
    [
        NO_CLAIM_MULTI_TENANT_ISOLATION,
        NO_CLAIM_CROSS_USER_ISOLATION,
        NO_CLAIM_UNTRUSTED_CODE_CONFINEMENT,
        NO_CLAIM_BYZANTINE_WORKER_TOLERANCE,
    ]
}

/// Deployment postures a configuration can request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RequestedPosture {
    /// The V1 posture: one trusted administrative fleet.
    SingleAdministrativeDomain,
    /// Mutually untrusting tenants sharing the fleet.
    MultiTenant,
    /// Isolation between distinct users as a security boundary.
    CrossUserIsolated,
}

/// Typed admission refusal for postures V1 does not claim.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrustRefusal {
    /// Multi-tenancy requested: refused, non-claim code carried.
    MultiTenancyNotClaimed {
        /// The registry code the refusal cites.
        non_claim: &'static str,
    },
    /// Cross-user isolation requested as a boundary: refused.
    CrossUserIsolationNotClaimed {
        /// The registry code the refusal cites.
        non_claim: &'static str,
    },
}

/// Admit or refuse a requested deployment posture. Fail closed: the
/// system cannot be configured into overclaiming.
///
/// # Errors
/// [`TrustRefusal`] citing the registry non-claim for any posture V1
/// does not claim.
pub const fn evaluate_deployment(requested: RequestedPosture) -> Result<TrustModel, TrustRefusal> {
    match requested {
        RequestedPosture::SingleAdministrativeDomain => Ok(TRUST_MODEL_V1),
        RequestedPosture::MultiTenant => Err(TrustRefusal::MultiTenancyNotClaimed {
            non_claim: NO_CLAIM_MULTI_TENANT_ISOLATION,
        }),
        RequestedPosture::CrossUserIsolated => Err(TrustRefusal::CrossUserIsolationNotClaimed {
            non_claim: NO_CLAIM_CROSS_USER_ISOLATION,
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The documentation twin, compiled in so prose and registry
    /// cannot drift apart.
    const DOC: &str = include_str!("../../docs/rabs-trust-model-v1.md");

    #[test]
    fn the_v1_posture_admits_and_everything_else_refuses_typed() {
        assert_eq!(
            evaluate_deployment(RequestedPosture::SingleAdministrativeDomain),
            Ok(TrustModel::SingleAdministrativeDomain)
        );
        assert_eq!(
            evaluate_deployment(RequestedPosture::MultiTenant),
            Err(TrustRefusal::MultiTenancyNotClaimed {
                non_claim: NO_CLAIM_MULTI_TENANT_ISOLATION,
            })
        );
        assert_eq!(
            evaluate_deployment(RequestedPosture::CrossUserIsolated),
            Err(TrustRefusal::CrossUserIsolationNotClaimed {
                non_claim: NO_CLAIM_CROSS_USER_ISOLATION,
            })
        );
    }

    #[test]
    fn the_non_claim_registry_is_closed_and_stable() {
        let claims = v1_non_claims();
        assert_eq!(claims.len(), 4, "closed registry, pinned");
        // Spellings are wire/receipt-stable.
        assert_eq!(
            claims,
            [
                "NO_CLAIM_MULTI_TENANT_ISOLATION",
                "NO_CLAIM_CROSS_USER_ISOLATION",
                "NO_CLAIM_UNTRUSTED_CODE_CONFINEMENT",
                "NO_CLAIM_BYZANTINE_WORKER_TOLERANCE",
            ]
        );
        // And R001 receipts can carry them verbatim (the same string
        // the receipt fixture uses).
        assert!(claims.contains(&NO_CLAIM_MULTI_TENANT_ISOLATION));
    }

    #[test]
    fn the_documentation_twin_records_every_non_claim() {
        // THE acceptance: the non-claim is recorded in docs — pinned
        // here so the doc cannot drift from the registry.
        for code in v1_non_claims() {
            assert!(
                DOC.contains(code),
                "docs/rabs-trust-model-v1.md must record {code} verbatim"
            );
        }
        // The claim itself, and the future-program framing.
        assert!(DOC.contains("Single Administrative Domain"));
        assert!(DOC.contains("separate future program"));
        // And the doc names the typed refusal, so the prose tells
        // operators what actually happens.
        assert!(DOC.contains("MultiTenancyNotClaimed"));
    }
}
