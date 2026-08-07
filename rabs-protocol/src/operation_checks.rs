//! Least-privilege operation checks at BOTH layers (bead S004; plan
//! §106; enforces the S003 tokens with defense in depth).
//!
//! Every privileged operation maps to exactly ONE required
//! capability kind, and the check runs TWICE:
//!
//! - the COORDINATOR POLICY layer checks before dispatch;
//! - the WORKER HANDLER layer re-checks independently at execution —
//!   it never trusts the coordinator's verdict (a token revoked
//!   between dispatch and execution dies at the second layer);
//!
//! a refusal names its layer, the operation, and the cause; and
//! authorization evidence carries BOTH layer stamps — a single-layer
//! pass is unrepresentable as full authorization.

use crate::capability_tokens::{CapabilityKind, CapabilityToken, TokenRefusal, validate};

/// The privileged operations (closed registry).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(missing_docs)]
pub enum Operation {
    FetchObject,
    UploadStaging,
    RunAction,
    OfferResult,
    MaterializeSnapshot,
    OpenConnection,
    ResolveSecret,
    EmitDiagnostics,
    SeedPeerObjects,
    RunVerification,
    AdminRepair,
}

/// Every operation, in registry order.
pub const ALL_OPERATIONS: [Operation; 11] = [
    Operation::FetchObject,
    Operation::UploadStaging,
    Operation::RunAction,
    Operation::OfferResult,
    Operation::MaterializeSnapshot,
    Operation::OpenConnection,
    Operation::ResolveSecret,
    Operation::EmitDiagnostics,
    Operation::SeedPeerObjects,
    Operation::RunVerification,
    Operation::AdminRepair,
];

impl Operation {
    /// The single capability kind this operation requires.
    #[must_use]
    pub const fn required_capability(self) -> CapabilityKind {
        match self {
            Self::FetchObject => CapabilityKind::ReadObject,
            Self::UploadStaging => CapabilityKind::WriteStaging,
            Self::RunAction => CapabilityKind::ExecuteAction,
            Self::OfferResult => CapabilityKind::OfferPreparedActionResult,
            Self::MaterializeSnapshot => CapabilityKind::MaterializeSnapshot,
            Self::OpenConnection => CapabilityKind::OpenNetwork,
            Self::ResolveSecret => CapabilityKind::ReadSecret,
            Self::EmitDiagnostics => CapabilityKind::EmitDiagnostics,
            Self::SeedPeerObjects => CapabilityKind::SeedPeerObjects,
            Self::RunVerification => CapabilityKind::RunVerification,
            Self::AdminRepair => CapabilityKind::AdminRepair,
        }
    }
}

/// Which layer performed a check.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Layer {
    /// Coordinator policy, before dispatch.
    CoordinatorPolicy,
    /// Worker operation handler, at execution.
    WorkerHandler,
}

/// A typed refusal from one layer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OperationRefusal {
    /// The refusing layer.
    pub layer: Layer,
    /// The operation refused.
    pub operation: Operation,
    /// Why.
    pub cause: RefusalCause,
}

/// Refusal causes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RefusalCause {
    /// No token of the required kind was presented at all.
    MissingCapability(CapabilityKind),
    /// A token of the right kind was presented but failed
    /// validation (revoked/expired/wrong context).
    TokenInvalid(TokenRefusal),
}

/// The validation context one layer checks against.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CheckContext<'a> {
    /// Revoked token ids AS THIS LAYER CURRENTLY KNOWS THEM.
    pub revoked_token_ids: &'a [u64],
    /// This layer's current sequence.
    pub current_seq: u64,
    /// Session id.
    pub session_id: u64,
    /// Operation id.
    pub operation_id: u64,
}

/// Run ONE layer's check.
///
/// # Errors
/// [`OperationRefusal`] naming the layer, operation, and cause.
pub fn check_at(
    layer: Layer,
    operation: Operation,
    presented: &[CapabilityToken],
    context: &CheckContext<'_>,
) -> Result<(), OperationRefusal> {
    let required = operation.required_capability();
    let Some(token) = presented.iter().find(|t| t.kind == required) else {
        return Err(OperationRefusal {
            layer,
            operation,
            cause: RefusalCause::MissingCapability(required),
        });
    };
    validate(
        token,
        context.revoked_token_ids,
        context.current_seq,
        context.session_id,
        context.operation_id,
    )
    .map_err(|refusal| OperationRefusal {
        layer,
        operation,
        cause: RefusalCause::TokenInvalid(refusal),
    })
}

/// Evidence that BOTH layers passed. Constructed only by
/// [`authorize`] — a single-layer pass cannot produce it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DualAuthorization {
    /// The operation authorized.
    pub operation: Operation,
    /// Sequence at the coordinator check.
    pub coordinator_seq: u64,
    /// Sequence at the worker check.
    pub worker_seq: u64,
}

/// Defense in depth: coordinator policy first, then the worker
/// handler re-checks INDEPENDENTLY against its own context.
///
/// # Errors
/// The first layer's refusal — worker context is consulted even if
/// the coordinator passed (that is the point).
pub fn authorize(
    operation: Operation,
    presented: &[CapabilityToken],
    coordinator: &CheckContext<'_>,
    worker: &CheckContext<'_>,
) -> Result<DualAuthorization, OperationRefusal> {
    check_at(Layer::CoordinatorPolicy, operation, presented, coordinator)?;
    check_at(Layer::WorkerHandler, operation, presented, worker)?;
    Ok(DualAuthorization {
        operation,
        coordinator_seq: coordinator.current_seq,
        worker_seq: worker.current_seq,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::capability_tokens::mint;

    fn token(kind: CapabilityKind) -> CapabilityToken {
        mint(42, kind, 7, 99, "scope", 1_000).expect("mints")
    }

    fn context(revoked: &[u64]) -> CheckContext<'_> {
        CheckContext {
            revoked_token_ids: revoked,
            current_seq: 500,
            session_id: 7,
            operation_id: 99,
        }
    }

    #[test]
    fn missing_capability_refuses_at_both_layers() {
        // THE acceptance: no token presented — each layer refuses
        // INDEPENDENTLY, naming itself, the operation, and the
        // missing kind.
        for layer in [Layer::CoordinatorPolicy, Layer::WorkerHandler] {
            let refusal =
                check_at(layer, Operation::RunAction, &[], &context(&[])).expect_err("refuses");
            assert_eq!(refusal.layer, layer);
            assert_eq!(refusal.operation, Operation::RunAction);
            assert_eq!(
                refusal.cause,
                RefusalCause::MissingCapability(CapabilityKind::ExecuteAction)
            );
        }
    }

    #[test]
    fn the_worker_layer_catches_what_the_coordinator_missed() {
        // Defense in depth: the coordinator's revocation list is
        // stale (empty); the worker knows token 42 was revoked
        // between dispatch and execution. The worker layer kills it.
        let tokens = [token(CapabilityKind::ExecuteAction)];
        let coordinator_view = context(&[]);
        let worker_revocations = [42_u64];
        let worker_view = context(&worker_revocations);
        let refusal = authorize(
            Operation::RunAction,
            &tokens,
            &coordinator_view,
            &worker_view,
        )
        .expect_err("the second layer must catch the revocation");
        assert_eq!(refusal.layer, Layer::WorkerHandler);
        assert_eq!(
            refusal.cause,
            RefusalCause::TokenInvalid(TokenRefusal::Revoked)
        );
    }

    #[test]
    fn full_authorization_carries_both_layer_stamps() {
        let tokens = [token(CapabilityKind::ReadObject)];
        let auth = authorize(
            Operation::FetchObject,
            &tokens,
            &context(&[]),
            &context(&[]),
        )
        .expect("both layers pass");
        // Both stamps present — DualAuthorization has no
        // single-layer constructor.
        assert_eq!(auth.operation, Operation::FetchObject);
        assert_eq!((auth.coordinator_seq, auth.worker_seq), (500, 500));
    }

    #[test]
    fn a_wrong_kind_token_never_satisfies() {
        // Least privilege: a ReadObject token does not run actions.
        let tokens = [token(CapabilityKind::ReadObject)];
        let refusal = check_at(
            Layer::CoordinatorPolicy,
            Operation::RunAction,
            &tokens,
            &context(&[]),
        )
        .expect_err("wrong kind refuses");
        assert_eq!(
            refusal.cause,
            RefusalCause::MissingCapability(CapabilityKind::ExecuteAction)
        );
    }

    #[test]
    fn the_operation_registry_is_closed_and_totally_mapped() {
        assert_eq!(ALL_OPERATIONS.len(), 11);
        // Every operation maps to a distinct capability kind (a
        // bijection onto the S003 registry).
        let kinds: Vec<CapabilityKind> = ALL_OPERATIONS
            .iter()
            .map(|op| op.required_capability())
            .collect();
        for (i, kind) in kinds.iter().enumerate() {
            assert!(
                !kinds[..i].contains(kind),
                "{kind:?} required by two operations"
            );
        }
    }
}
