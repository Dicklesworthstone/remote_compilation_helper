//! Future `public_api_hash` extension point (bead F017; plan §62's
//! forward door; kept honest by F010's admission rules).
//!
//! Someday rustc may expose a stable public-API hash (or RDR-style
//! relink-don't-rebuild data) that could replace conservative
//! artifact identity for admitted action classes — hitting even when
//! artifact bytes changed but the API did not. This module reserves
//! that door WITHOUT opening it:
//!
//! - the slot is **typed and versioned** ([`PublicApiProjection`]),
//!   entering the key exclusively through `projection_epoch` (like any
//!   F010 projection, so API-hash keys and exact keys can never
//!   alias);
//! - it is **inert by default**: [`PublicApiAvailability`] has no
//!   enabled state constructible without an extractor version, a
//!   toolchain proof ID, and a corpus verdict — the same four-condition
//!   discipline as F010, reused, not duplicated;
//! - **no implementation exists today** and none is claimed: rustc's
//!   `-Z` API-hash surfaces are unstable and unproven; every
//!   constructor path in this module currently yields
//!   [`PublicApiDecision::InertUseExact`]. The test proving that IS
//!   the deliverable.

use crate::dependency_identity::ConsumedArtifact;
use crate::dependency_projection::{
    ObservabilityProof, ProjectionDecision, ProjectionExtractor, ShadowCorpusStatus,
    decide_projection,
};
use rabs_protocol::result_identity::TypedDigest;

/// A future public-API projection value (versioned schema).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublicApiProjection {
    /// Schema version of the API-hash data.
    pub schema_version: u32,
    /// The API hash itself (typed digest in its own domain).
    pub api_hash: TypedDigest,
}

/// Whether a public-API source is available on this toolchain. Today:
/// only [`PublicApiAvailability::NotProvided`] is constructible in
/// practice — `Available` requires proof artifacts that do not exist
/// yet, and the decision function still routes it through the full
/// F010 admission gauntlet.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PublicApiAvailability {
    /// The toolchain provides no proven API-hash surface (today's
    /// universal state).
    NotProvided,
    /// A future toolchain provides one, with its extractor and corpus
    /// standing. Admission still runs the F010 conditions.
    Available {
        /// The versioned extractor for the API-hash data.
        extractor: ProjectionExtractor,
        /// Invocation-class observability proof.
        proof: ObservabilityProof,
        /// Shadow-corpus standing.
        corpus: ShadowCorpusStatus,
        /// The projection value.
        projection: PublicApiProjection,
    },
}

/// Outcome of consulting the extension point.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PublicApiDecision {
    /// Inert: key on conservative exact identity (today's only real
    /// outcome).
    InertUseExact,
    /// A future admitted API-hash projection (routes through
    /// `projection_epoch` exactly like F010 projections).
    AdmittedProjection(PublicApiProjection),
}

/// Consult the extension point. Inert unless a FUTURE toolchain's
/// API-hash surface passes the full F010 admission conditions.
#[must_use]
pub fn decide_public_api(availability: &PublicApiAvailability) -> PublicApiDecision {
    match availability {
        PublicApiAvailability::NotProvided => PublicApiDecision::InertUseExact,
        PublicApiAvailability::Available {
            extractor,
            proof,
            corpus,
            projection,
        } => {
            // Reuse F010's gauntlet verbatim — no second admission
            // policy. The projected artifact is represented as the
            // API-hash bytes stand-in.
            let stand_in = ConsumedArtifact::RmetaBytes(projection.api_hash.clone());
            match decide_projection(*proof, Some(extractor), *corpus, &stand_in) {
                ProjectionDecision::Projected { .. } => {
                    PublicApiDecision::AdmittedProjection(projection.clone())
                }
                ProjectionDecision::ExactFallback { .. } => PublicApiDecision::InertUseExact,
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rabs_protocol::result_identity::DigestAlgorithm;

    fn projection() -> PublicApiProjection {
        PublicApiProjection {
            schema_version: 1,
            api_hash: TypedDigest {
                algorithm: DigestAlgorithm::Sha256V1,
                domain: "rabs.public-api-hash.v1",
                bytes: [7; 32],
            },
        }
    }

    #[test]
    fn inert_by_default() {
        // THE acceptance: today's universal state yields exact identity.
        assert_eq!(
            decide_public_api(&PublicApiAvailability::NotProvided),
            PublicApiDecision::InertUseExact
        );
    }

    #[test]
    fn even_an_available_surface_fails_closed_without_the_f010_conditions() {
        // A future toolchain claims availability but the corpus is not
        // clean: the F010 gauntlet (reused, not duplicated) refuses.
        let availability = PublicApiAvailability::Available {
            extractor: ProjectionExtractor {
                name: "rustc-public-api-hash".into(),
                version: 1,
                schema_version: 1,
            },
            proof: ObservabilityProof::OmittedBytesUnobservable,
            corpus: ShadowCorpusStatus::NotClean,
            projection: projection(),
        };
        assert_eq!(
            decide_public_api(&availability),
            PublicApiDecision::InertUseExact
        );
        // Ambiguous flags refuse too.
        let ambiguous = PublicApiAvailability::Available {
            extractor: ProjectionExtractor {
                name: "rustc-public-api-hash".into(),
                version: 1,
                schema_version: 1,
            },
            proof: ObservabilityProof::AmbiguousOrObservable,
            corpus: ShadowCorpusStatus::ZeroDivergence,
            projection: projection(),
        };
        assert_eq!(
            decide_public_api(&ambiguous),
            PublicApiDecision::InertUseExact
        );
    }

    #[test]
    fn a_fully_proven_future_surface_would_admit_through_projection_epoch() {
        // The door exists: all four conditions held (hypothetically) —
        // the projection admits, and by construction it flows through
        // the same projection_epoch namespace as every F010 projection.
        let availability = PublicApiAvailability::Available {
            extractor: ProjectionExtractor {
                name: "rustc-public-api-hash".into(),
                version: 1,
                schema_version: 1,
            },
            proof: ObservabilityProof::OmittedBytesUnobservable,
            corpus: ShadowCorpusStatus::ZeroDivergence,
            projection: projection(),
        };
        assert_eq!(
            decide_public_api(&availability),
            PublicApiDecision::AdmittedProjection(projection())
        );
    }
}
