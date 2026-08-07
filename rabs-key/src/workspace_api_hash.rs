//! Workspace public-API-hash adapter slot (bead M013; plan §100's
//! absorption point; builds on the F017 door).
//!
//! F017 reserved the general public-API-hash extension point; this is
//! its WORKSPACE-KEY adapter: workspace member compiles are where an
//! upstream `public_api_hash`/RDR surface would pay most (member
//! edits dominate; most are implementation-only). The slot:
//!
//! - is TYPED now: [`WorkspaceApiHashSlot`] names the upstream
//!   surface it waits for, and the adapter routes any future value
//!   through the F017 decision (which itself routes through the F010
//!   four-condition gauntlet with its own shadow gate);
//! - is INERT until upstream lands: the only constructible state
//!   today is `UpstreamNotAvailable`, and the adapter provably
//!   returns exact-identity keying for it. The inertness test IS the
//!   deliverable — nothing here claims rustc support that does not
//!   exist.

use crate::public_api_hash::{PublicApiAvailability, PublicApiDecision, decide_public_api};

/// The workspace adapter slot.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WorkspaceApiHashSlot {
    /// Upstream rustc provides no usable surface (today's state).
    UpstreamNotAvailable,
    /// A future upstream surface, routed through F017 (which applies
    /// the F010 gauntlet + shadow gate).
    Upstream(PublicApiAvailability),
}

/// The workspace keying decision.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WorkspaceKeying {
    /// Key on conservative exact artifact identity (today, always).
    ExactIdentity,
    /// A future admitted API-hash projection (through
    /// projection_epoch, exactly like F010/F017).
    ApiHashProjection,
}

/// Decide workspace keying for the slot.
#[must_use]
pub fn decide_workspace_keying(slot: &WorkspaceApiHashSlot) -> WorkspaceKeying {
    match slot {
        WorkspaceApiHashSlot::UpstreamNotAvailable => WorkspaceKeying::ExactIdentity,
        WorkspaceApiHashSlot::Upstream(availability) => match decide_public_api(availability) {
            PublicApiDecision::InertUseExact => WorkspaceKeying::ExactIdentity,
            PublicApiDecision::AdmittedProjection(_) => WorkspaceKeying::ApiHashProjection,
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dependency_projection::{
        ObservabilityProof, ProjectionExtractor, ShadowCorpusStatus,
    };
    use crate::public_api_hash::PublicApiProjection;
    use rabs_protocol::result_identity::{DigestAlgorithm, TypedDigest};

    #[test]
    fn inert_until_upstream_lands() {
        // THE acceptance: the slot is typed, and today's only real
        // state keys on exact identity.
        assert_eq!(
            decide_workspace_keying(&WorkspaceApiHashSlot::UpstreamNotAvailable),
            WorkspaceKeying::ExactIdentity
        );
    }

    #[test]
    fn future_upstream_routes_through_the_f017_gauntlet() {
        // A claimed future surface without a clean shadow corpus stays
        // exact — the F017/F010 gate governs, not this adapter.
        let unproven = WorkspaceApiHashSlot::Upstream(PublicApiAvailability::Available {
            extractor: ProjectionExtractor {
                name: "rustc-public-api-hash".into(),
                version: 1,
                schema_version: 1,
            },
            proof: ObservabilityProof::OmittedBytesUnobservable,
            corpus: ShadowCorpusStatus::NotClean,
            projection: PublicApiProjection {
                schema_version: 1,
                api_hash: TypedDigest {
                    algorithm: DigestAlgorithm::Sha256V1,
                    domain: "rabs.public-api-hash.v1",
                    bytes: [7; 32],
                },
            },
        });
        assert_eq!(
            decide_workspace_keying(&unproven),
            WorkspaceKeying::ExactIdentity
        );
        // A hypothetically fully proven surface admits the projection.
        let proven = WorkspaceApiHashSlot::Upstream(PublicApiAvailability::Available {
            extractor: ProjectionExtractor {
                name: "rustc-public-api-hash".into(),
                version: 1,
                schema_version: 1,
            },
            proof: ObservabilityProof::OmittedBytesUnobservable,
            corpus: ShadowCorpusStatus::ZeroDivergence,
            projection: PublicApiProjection {
                schema_version: 1,
                api_hash: TypedDigest {
                    algorithm: DigestAlgorithm::Sha256V1,
                    domain: "rabs.public-api-hash.v1",
                    bytes: [7; 32],
                },
            },
        });
        assert_eq!(
            decide_workspace_keying(&proven),
            WorkspaceKeying::ApiHashProjection
        );
    }
}
