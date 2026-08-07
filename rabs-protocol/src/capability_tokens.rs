//! Capability token/receipt schema (bead S003; plan §106; couples to
//! the A005 authority matrix and S007 redaction).
//!
//! Every privileged operation is exercised through an explicit,
//! least-privilege capability token:
//!
//! - eleven capability kinds, wire-tagged and pinned;
//! - a token is EXPLICIT about its session/operation context — a
//!   token minted for one operation refuses in another;
//! - least privilege: minting requires a concrete scope (an object
//!   digest, a staging prefix, an endpoint, a secret SLOT NAME);
//! - lease-bounded and revocable: validity checks the lease sequence
//!   and the revocation set, and each failure is typed;
//! - receipts are REDACTION-SAFE: the receipt schema has no field
//!   that could carry a secret value — a `ReadSecret` receipt names
//!   the slot (S007's rule: slots are shareable, values never);
//! - tokens are unavailable to arbitrary build subprocesses: the
//!   delivery enum has ONLY controlled-mount and inherited-FD arms —
//!   ambient-environment delivery is unrepresentable.

/// The eleven capability kinds (wire tags pinned by test).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(missing_docs)]
pub enum CapabilityKind {
    ReadObject,
    WriteStaging,
    ExecuteAction,
    OfferPreparedActionResult,
    MaterializeSnapshot,
    OpenNetwork,
    ReadSecret,
    EmitDiagnostics,
    SeedPeerObjects,
    RunVerification,
    AdminRepair,
}

/// Every kind, in wire-tag order.
pub const ALL_CAPABILITY_KINDS: [CapabilityKind; 11] = [
    CapabilityKind::ReadObject,
    CapabilityKind::WriteStaging,
    CapabilityKind::ExecuteAction,
    CapabilityKind::OfferPreparedActionResult,
    CapabilityKind::MaterializeSnapshot,
    CapabilityKind::OpenNetwork,
    CapabilityKind::ReadSecret,
    CapabilityKind::EmitDiagnostics,
    CapabilityKind::SeedPeerObjects,
    CapabilityKind::RunVerification,
    CapabilityKind::AdminRepair,
];

impl CapabilityKind {
    /// The wire-stable tag.
    #[must_use]
    pub const fn tag(self) -> u8 {
        match self {
            Self::ReadObject => 1,
            Self::WriteStaging => 2,
            Self::ExecuteAction => 3,
            Self::OfferPreparedActionResult => 4,
            Self::MaterializeSnapshot => 5,
            Self::OpenNetwork => 6,
            Self::ReadSecret => 7,
            Self::EmitDiagnostics => 8,
            Self::SeedPeerObjects => 9,
            Self::RunVerification => 10,
            Self::AdminRepair => 11,
        }
    }
}

/// A minted capability token.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CapabilityToken {
    /// Unique token id (issuer-assigned).
    pub token_id: u64,
    /// The capability kind.
    pub kind: CapabilityKind,
    /// Session this token belongs to.
    pub session_id: u64,
    /// Operation this token was minted FOR (explicit context).
    pub operation_id: u64,
    /// Least-privilege scope: object digest hex, staging prefix,
    /// endpoint, or secret SLOT NAME — never a secret value.
    pub scope: String,
    /// Lease bound: valid while `current_seq < expires_seq` (the
    /// J026 monotonic-lease discipline; sequences, not clocks).
    pub expires_seq: u64,
}

/// Typed minting refusal.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MintRefusal {
    /// Least privilege demands a concrete scope.
    ScopeMissing,
}

/// Mint a token (least-privilege enforced at the door).
///
/// # Errors
/// [`MintRefusal::ScopeMissing`] when `scope` is empty.
pub fn mint(
    token_id: u64,
    kind: CapabilityKind,
    session_id: u64,
    operation_id: u64,
    scope: &str,
    expires_seq: u64,
) -> Result<CapabilityToken, MintRefusal> {
    if scope.is_empty() {
        return Err(MintRefusal::ScopeMissing);
    }
    Ok(CapabilityToken {
        token_id,
        kind,
        session_id,
        operation_id,
        scope: scope.to_owned(),
        expires_seq,
    })
}

/// Typed validation refusal.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TokenRefusal {
    /// The token was revoked.
    Revoked,
    /// The lease expired (`current_seq` included).
    LeaseExpired(u64),
    /// Presented in a different session than minted for.
    WrongSession,
    /// Presented for a different operation than minted for.
    WrongOperation,
}

/// Validate a token for use in a context.
///
/// # Errors
/// The first failed check, typed: revocation, lease, session,
/// operation.
pub fn validate(
    token: &CapabilityToken,
    revoked_token_ids: &[u64],
    current_seq: u64,
    session_id: u64,
    operation_id: u64,
) -> Result<(), TokenRefusal> {
    if revoked_token_ids.contains(&token.token_id) {
        return Err(TokenRefusal::Revoked);
    }
    if current_seq >= token.expires_seq {
        return Err(TokenRefusal::LeaseExpired(current_seq));
    }
    if token.session_id != session_id {
        return Err(TokenRefusal::WrongSession);
    }
    if token.operation_id != operation_id {
        return Err(TokenRefusal::WrongOperation);
    }
    Ok(())
}

/// How a token reaches a build subprocess. There is NO ambient-
/// environment arm: arbitrary subprocesses cannot inherit tokens.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TokenDelivery {
    /// A controlled mount at a fixed path inside the sandbox.
    ControlledMount {
        /// Mount path.
        path: String,
    },
    /// An explicitly inherited file descriptor.
    InheritedFd {
        /// FD number.
        fd: u32,
    },
}

/// The audit receipt for one exercised capability. The schema has
/// NO field that could carry a secret value — receipts are
/// redaction-safe by construction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CapabilityReceipt {
    /// The token exercised.
    pub token_id: u64,
    /// The capability kind.
    pub kind: CapabilityKind,
    /// The scope exercised (for `ReadSecret`: the SLOT NAME).
    pub scope: String,
    /// The operation context.
    pub operation_id: u64,
    /// Sequence at which the exercise happened.
    pub exercised_at_seq: u64,
}

/// Produce the receipt for an exercised token.
#[must_use]
pub fn receipt(token: &CapabilityToken, exercised_at_seq: u64) -> CapabilityReceipt {
    CapabilityReceipt {
        token_id: token.token_id,
        kind: token.kind,
        scope: token.scope.clone(),
        operation_id: token.operation_id,
        exercised_at_seq,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn token() -> CapabilityToken {
        mint(
            42,
            CapabilityKind::ReadObject,
            7,  // session
            99, // operation
            "sha256:aa11",
            1_000,
        )
        .expect("scoped mint succeeds")
    }

    #[test]
    fn the_eleven_kinds_are_wire_stable() {
        let tags: Vec<u8> = ALL_CAPABILITY_KINDS.iter().map(|k| k.tag()).collect();
        assert_eq!(tags, [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11]);
        // Exhaustive: a new kind extends the array or this fails.
        assert_eq!(ALL_CAPABILITY_KINDS.len(), 11);
    }

    #[test]
    fn least_privilege_requires_a_concrete_scope() {
        assert_eq!(
            mint(1, CapabilityKind::AdminRepair, 7, 99, "", 1_000),
            Err(MintRefusal::ScopeMissing),
            "an unscoped admin capability is exactly the bug"
        );
    }

    #[test]
    fn context_lease_and_revocation_each_refuse_typed() {
        let t = token();
        // Valid in its own context.
        assert_eq!(validate(&t, &[], 500, 7, 99), Ok(()));
        // Revoked.
        assert_eq!(validate(&t, &[42], 500, 7, 99), Err(TokenRefusal::Revoked));
        // Lease expired (boundary: expiry sequence itself is expired).
        assert_eq!(
            validate(&t, &[], 1_000, 7, 99),
            Err(TokenRefusal::LeaseExpired(1_000))
        );
        // Wrong session.
        assert_eq!(
            validate(&t, &[], 500, 8, 99),
            Err(TokenRefusal::WrongSession)
        );
        // Wrong operation: explicit operation context is binding.
        assert_eq!(
            validate(&t, &[], 500, 7, 100),
            Err(TokenRefusal::WrongOperation)
        );
    }

    #[test]
    fn receipts_are_redaction_safe_by_construction() {
        // THE receipt-redaction acceptance: a ReadSecret receipt
        // names the SLOT, and the schema has no field that could
        // carry the value (exhaustive destructure proves it).
        let secret_value = "ghp_supersecrettoken12345"; // never enters
        let t = mint(
            43,
            CapabilityKind::ReadSecret,
            7,
            99,
            "cargo-registry-token", // the slot name is the scope
            1_000,
        )
        .expect("mints");
        let r = receipt(&t, 600);
        let CapabilityReceipt {
            token_id,
            kind,
            scope,
            operation_id,
            exercised_at_seq,
        } = &r; // a new field is a compile error until reviewed here
        assert_eq!(*token_id, 43);
        assert_eq!(*kind, CapabilityKind::ReadSecret);
        assert_eq!(scope, "cargo-registry-token");
        assert_eq!(*operation_id, 99);
        assert_eq!(*exercised_at_seq, 600);
        assert!(
            !format!("{r:?}").contains(secret_value),
            "no plaintext in the formatted receipt"
        );
    }

    #[test]
    fn subprocess_delivery_has_no_ambient_arm() {
        // Tokens reach subprocesses ONLY through controlled mounts or
        // inherited FDs — the exhaustive match is the proof that no
        // env-var/ambient arm exists.
        let deliveries = [
            TokenDelivery::ControlledMount {
                path: "/__rabs/caps/read-object".into(),
            },
            TokenDelivery::InheritedFd { fd: 17 },
        ];
        for d in deliveries {
            match d {
                TokenDelivery::ControlledMount { path } => {
                    assert!(path.starts_with("/__rabs/"));
                }
                TokenDelivery::InheritedFd { fd } => assert!(fd >= 3),
            }
        }
    }
}
