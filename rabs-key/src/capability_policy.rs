//! Project capability policy (bead E016; plan §73; risks R16/R56).
//!
//! Some actions legitimately need controlled ambient access — a
//! bindgen fetch, a signing secret, the git-state object a version
//! stamp reads. The capability policy makes that CACHEABLE without
//! becoming a hole:
//!
//! - a project DECLARES scoped capabilities (network fetch scope,
//!   secret slot, git-state object) with versioned identities;
//! - an action using a granted capability stays cacheable as
//!   `HermeticWithCapabilities` (E013), and the CAPABILITY IDENTITY
//!   (name + version + scope digest) enters its key — a rotated
//!   secret version or widened network scope is a different action;
//! - unauthorized use is REFUSED with a registered reason code, never
//!   silently allowed or silently stripped.

use rabs_protocol::result_identity::TypedDigest;

use crate::canonical::CanonicalEncoder;
use crate::typed_digest::compute;

/// Digest domain for capability identities.
pub const DOMAIN_CAPABILITY: &str = "rabs.capability.v1";
/// Reason code for unauthorized capability use.
pub const SANDBOX_CAPABILITY_UNAUTHORIZED: &str = "SANDBOX_CAPABILITY_UNAUTHORIZED";

/// What a capability grants access to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CapabilityKind {
    /// Network fetch limited to a declared scope (host allowlist
    /// digest — the SCOPE is identity, not the fetched bytes).
    NetworkFetch {
        /// Digest of the canonical allowlist.
        scope_digest: TypedDigest,
    },
    /// A secret slot (value enters keys ONLY as the F006 opaque
    /// digest; the capability names the slot).
    SecretSlot {
        /// Slot name under `/run/rabs-secrets/`.
        slot: String,
    },
    /// The captured git-state object (a snapshot object, not live
    /// `.git` access).
    GitStateObject {
        /// The captured object's digest.
        object_digest: TypedDigest,
    },
}

/// One declared capability.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CapabilityDeclaration {
    /// Project-unique capability name.
    pub name: String,
    /// Declaration version (bumped on any scope change).
    pub version: u32,
    /// What it grants.
    pub kind: CapabilityKind,
}

impl CapabilityDeclaration {
    /// The capability identity digest — the value that enters a
    /// capability-scoped action key.
    #[must_use]
    pub fn identity_digest(&self) -> TypedDigest {
        let mut enc = CanonicalEncoder::new();
        enc.str(&self.name).u32(self.version);
        match &self.kind {
            CapabilityKind::NetworkFetch { scope_digest } => {
                enc.u32(1)
                    .str(scope_digest.domain)
                    .bytes(&scope_digest.bytes);
            }
            CapabilityKind::SecretSlot { slot } => {
                enc.u32(2).str(slot);
            }
            CapabilityKind::GitStateObject { object_digest } => {
                enc.u32(3)
                    .str(object_digest.domain)
                    .bytes(&object_digest.bytes);
            }
        }
        compute(DOMAIN_CAPABILITY, &enc.finish())
    }
}

/// Outcome of an action requesting capabilities.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CapabilityGrant {
    /// All requested capabilities are declared: the action runs as
    /// HermeticWithCapabilities and these identities enter its key.
    Granted {
        /// Identity digests, sorted for deterministic keying.
        identities: Vec<TypedDigest>,
    },
    /// A requested capability is not declared: refuse with the code.
    Refused {
        /// The registered reason code.
        reason_code: &'static str,
        /// The undeclared capability name.
        undeclared: String,
    },
}

/// Evaluate an action's capability requests against the project's
/// declarations.
#[must_use]
pub fn evaluate_requests(
    declared: &[CapabilityDeclaration],
    requested: &[String],
) -> CapabilityGrant {
    let mut identities = Vec::with_capacity(requested.len());
    for name in requested {
        match declared.iter().find(|d| d.name == *name) {
            Some(declaration) => identities.push(declaration.identity_digest()),
            None => {
                return CapabilityGrant::Refused {
                    reason_code: SANDBOX_CAPABILITY_UNAUTHORIZED,
                    undeclared: name.clone(),
                };
            }
        }
    }
    identities.sort_by(|a, b| (a.domain, &a.bytes).cmp(&(b.domain, &b.bytes)));
    CapabilityGrant::Granted { identities }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rabs_protocol::result_identity::DigestAlgorithm;

    fn d(domain: &'static str, tag: u8) -> TypedDigest {
        TypedDigest {
            algorithm: DigestAlgorithm::Sha256V1,
            domain,
            bytes: [tag; 32],
        }
    }

    fn declarations() -> Vec<CapabilityDeclaration> {
        vec![
            CapabilityDeclaration {
                name: "vendor-fetch".into(),
                version: 1,
                kind: CapabilityKind::NetworkFetch {
                    scope_digest: d("rabs.net-scope.v1", 1),
                },
            },
            CapabilityDeclaration {
                name: "signing-key".into(),
                version: 3,
                kind: CapabilityKind::SecretSlot {
                    slot: "slot-signing".into(),
                },
            },
            CapabilityDeclaration {
                name: "git-stamp".into(),
                version: 1,
                kind: CapabilityKind::GitStateObject {
                    object_digest: d("rabs.object.v1", 2),
                },
            },
        ]
    }

    #[test]
    fn capability_identity_enters_the_key_and_tracks_every_field() {
        // THE acceptance: the identity digest moves with name, version,
        // and scope — a rotated version or widened scope is a
        // different action.
        let base = declarations()[0].identity_digest();
        let mut renamed = declarations()[0].clone();
        renamed.name = "vendor-fetch-2".into();
        assert_ne!(base, renamed.identity_digest());
        let mut bumped = declarations()[0].clone();
        bumped.version = 2;
        assert_ne!(base, bumped.identity_digest());
        let mut widened = declarations()[0].clone();
        widened.kind = CapabilityKind::NetworkFetch {
            scope_digest: d("rabs.net-scope.v1", 9),
        };
        assert_ne!(base, widened.identity_digest());
        // Kind participates: a secret slot named like a fetch scope
        // cannot alias.
        let cross_kind = CapabilityDeclaration {
            name: "vendor-fetch".into(),
            version: 1,
            kind: CapabilityKind::SecretSlot {
                slot: "vendor-fetch".into(),
            },
        };
        assert_ne!(base, cross_kind.identity_digest());
    }

    #[test]
    fn granted_requests_yield_sorted_deterministic_identities() {
        let a = evaluate_requests(
            &declarations(),
            &["signing-key".into(), "vendor-fetch".into()],
        );
        let b = evaluate_requests(
            &declarations(),
            &["vendor-fetch".into(), "signing-key".into()],
        );
        assert_eq!(a, b, "request order never forks the keyed identities");
        let CapabilityGrant::Granted { identities } = a else {
            panic!("expected grant");
        };
        assert_eq!(identities.len(), 2);
    }

    #[test]
    fn unauthorized_use_refuses_with_the_reason_code() {
        // THE acceptance: an undeclared capability refuses — never
        // silently allowed, never silently stripped from the request.
        let outcome = evaluate_requests(
            &declarations(),
            &["vendor-fetch".into(), "prod-database".into()],
        );
        assert_eq!(
            outcome,
            CapabilityGrant::Refused {
                reason_code: SANDBOX_CAPABILITY_UNAUTHORIZED,
                undeclared: "prod-database".into(),
            }
        );
    }

    #[test]
    fn empty_requests_grant_plain_hermetic_posture() {
        // No capabilities requested: the grant is empty and the action
        // classifies plain Hermetic (E013) — the capability machinery
        // adds nothing to its key.
        assert_eq!(
            evaluate_requests(&declarations(), &[]),
            CapabilityGrant::Granted { identities: vec![] }
        );
    }
}
