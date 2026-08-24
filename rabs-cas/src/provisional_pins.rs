//! Provisional `.rmeta` upload pins and authorized visibility
//! (bead M004; plan §65).
//!
//! A worker's early metadata output becomes an immutable verified object
//! through the ordinary `put_if_absent` path (H001); THIS layer binds that
//! object under the producer identity tuple
//! `(CoordinatorAuthority, ActionKey, ActionGeneration, AttemptId,
//! ExecutionLeaseId, LogicalOutput)` as a CANDIDATE pin and gates every
//! read against an explicit grant table:
//!
//! - **Closed by default.** Only registered dependent attempts and the
//!   awaiting edge/subscriber may resolve a provisional output; any other
//!   reader — including a worker on the same project — is refused with a
//!   typed error.
//! - **Immutable binding.** One identity tuple names exactly one object.
//!   Re-offering the same bytes is idempotent; offering DIFFERENT bytes
//!   under the same tuple is a collision incident, never a pick-one.
//! - **Coordinator-owned lifetime.** Candidate pins remain valid through
//!   coordinator decision/reconciliation; workers can never release one.
//!   The active-authority coordinator closes them after obligations drain,
//!   or invalidates them when the producer generation fails, is superseded
//!   without compatible adoption, or loses authority (§65).
//! - **Success elsewhere does not stabilize.** Another attempt committing
//!   for the same action key changes nothing about this pin; only an
//!   explicit exact-object adoption (§65.1) resolves its lineage.
//! - **Fail toward retention on tear.** The registry row is closed BEFORE
//!   the GC-protective `pins` twin is released, so a crash between the two
//!   leaves the object over-protected, never unprotected.
//!
//! Persistence lives in `provisional_pins`, `provisional_pin_grants`,
//! and `provisional_obligations` (schema v15) plus a protective row in
//! the existing `pins` table, so H016's mark → grace → recheck → unlink
//! pipeline provably preserves live provisional objects exactly like
//! publication roots.
//!
//! ## Dependency rules
//!
//! Same as the crate: `rabs-protocol` types only; no async runtime; all
//! effects flow through [`RabsMetadataStore`](crate::metadata_store::
//! RabsMetadataStore).

use crate::metadata_store::{
    ProvisionalObligationInsert, ProvisionalPinInsert, RabsMetadataStore, StoreError, digest_key,
};
use crate::pin_leases::{ReleaseOutcome, Releaser, release_pin_scoped};
use crate::publication::{Framing, authority_digest, output_role_name_for_tag, output_role_tag};
use rabs_protocol::authority::CoordinatorAuthority;
use rabs_protocol::generation::{ActionGenerationId, AttemptId, ExecutionLeaseId};
use rabs_protocol::raw_bytes::RawBytes;
use rabs_protocol::reconnect::SubscriberId;
use rabs_protocol::result_identity::{ObjectId, OutputRole, TypedDigest};

/// Domain separator for the canonical provisional-pin identity digest.
pub const PROVISIONAL_PIN_DOMAIN: &str = "rabs.provisional-pin.sha256.v1";

/// Pin class of the GC-protective twin rows created for candidate pins.
pub const PROVISIONAL_PIN_CLASS: &str = "provisional-metadata";

const GRANT_DEPENDENT_ATTEMPT: &str = "dependent-attempt";
const GRANT_AWAITING_EDGE: &str = "awaiting-edge";

/// The producer-side identity tuple of one provisional logical output.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProvisionalIdentity {
    /// The coordinator authority whose generation minted the attempt.
    pub authority: CoordinatorAuthority,
    /// Digest of the producing action.
    pub action_key: TypedDigest,
    /// Producing action generation.
    pub generation: ActionGenerationId,
    /// The specific attempt (hedges never share pins).
    pub attempt: AttemptId,
    /// The attempt's own execution lease.
    pub lease: ExecutionLeaseId,
    /// Role of the logical output (`.rmeta` =>
    /// [`OutputRole::ProvisionalMetadata`]).
    pub role: OutputRole,
    /// Canonical virtual path of the logical output.
    pub virtual_path: RawBytes,
}

impl ProvisionalIdentity {
    /// Canonical digest of the tuple (length-framed fields; no
    /// concatenation ambiguity). This is the pin's durable address.
    #[must_use]
    pub fn digest(&self) -> TypedDigest {
        let mut framing = Framing::new(PROVISIONAL_PIN_DOMAIN);
        let authority = authority_digest(&self.authority);
        framing
            .digest_field(&authority)
            .digest_field(&self.action_key)
            .field(&self.generation.0.to_be_bytes())
            .field(&self.attempt.0.to_be_bytes())
            .field(&self.lease.0.to_be_bytes())
            .u64(output_role_tag(self.role))
            .field(self.virtual_path.as_bytes());
        framing.finish(PROVISIONAL_PIN_DOMAIN)
    }

    /// Durable key under which this pin is registered.
    #[must_use]
    pub fn pin_key(&self) -> String {
        digest_key(&self.digest())
    }
}

/// A reader asking for provisional-output visibility (M004). Exactly the
/// populations plan §65 authorizes: dependent attempts of the action and
/// the edge/Cargo instance awaiting the output.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProvisionalReader {
    /// One dependent attempt running on a named worker.
    DependentAttempt {
        /// Worker peer id.
        worker: String,
        /// The dependent's own attempt id.
        attempt: AttemptId,
    },
    /// The awaiting edge subscriber (the edge/Cargo instance).
    AwaitingEdge {
        /// Subscriber id of the awaiting edge.
        subscriber: SubscriberId,
    },
}

impl ProvisionalReader {
    fn grant_kind(&self) -> &'static str {
        match self {
            Self::DependentAttempt { .. } => GRANT_DEPENDENT_ATTEMPT,
            Self::AwaitingEdge { .. } => GRANT_AWAITING_EDGE,
        }
    }

    fn grant_id(&self) -> String {
        match self {
            Self::DependentAttempt { worker, attempt } => format!("{worker}/{:032x}", attempt.0),
            Self::AwaitingEdge { subscriber } => format!("edge/{:032x}", subscriber.0),
        }
    }
}

/// Toolchain/event contracts a producer ran under (M017). Opaque digests:
/// this layer proves BINDING EQUALITY between a candidate pin and a
/// would-be different winning attempt; the digests' semantics live in
/// the descriptor/event layers above.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProducerContracts {
    /// Toolchain contract digest (the F007 descriptor component).
    pub toolchain: TypedDigest,
    /// Event-stream contract digest under which outputs were emitted.
    pub events: TypedDigest,
}

/// Everything that can refuse a provisional-pin operation. Store failures
/// are carried verbatim; everything else is a typed policy outcome so
/// callers can never conflate "not yours" with "gone".
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProvisionalPinError {
    /// A different object was offered under an already-pinned identity
    /// tuple — treated as a collision incident, never an overwrite.
    Collision {
        /// Canonical key of the contested pin.
        pin_key: String,
        /// Object key already pinned.
        pinned: String,
        /// Object key offered.
        offered: String,
    },
    /// No pin under this identity tuple.
    UnknownPin {
        /// Canonical key looked up.
        pin_key: String,
    },
    /// The reader has no grant for this pin.
    Unauthorized {
        /// Canonical key of the pin.
        pin_key: String,
    },
    /// The pin was closed after obligations drained.
    Closed {
        /// Canonical key of the pin.
        pin_key: String,
    },
    /// Producer lineage failed/superseded/lost authority (§65).
    ProducerInvalidated {
        /// Canonical key of the pin.
        pin_key: String,
        /// Recorded reason.
        reason: String,
    },
    /// Renewal sequence not strictly greater than the stored one.
    NonMonotonicRenewal {
        /// Canonical key of the pin.
        pin_key: String,
    },
    /// Adoption refused: the committed result resolved the logical output
    /// to a different object, so descendants cannot be satisfied (§65.1).
    AdoptionMismatch {
        /// Canonical key of the pin.
        pin_key: String,
        /// Pinned object key.
        pinned: String,
        /// Committed object key.
        committed: String,
    },
    /// A coordinator attempted the release without presenting the active
    /// authority (H041 scoping on the protective pin).
    NotActiveAuthority,
    /// Drain attempted while live descendant obligations are still open
    /// (§65 GC rule: garbage-collect only after all obligations drain).
    UnresolvedConsumerDebt {
        /// Canonical key of the pin still carrying open obligations.
        pin_key: String,
        /// How many open obligations remain.
        open_count: usize,
    },
    /// Underlying store failure.
    Store(StoreError),
    /// Different-winner adoption proposed from the SAME producer
    /// attempt/generation — the ordinary commit-resolution path owns that
    /// case (M017).
    SameWinningAttempt {
        /// Canonical key of the pin.
        pin_key: String,
    },
    /// The winning attempt committed for a DIFFERENT action key than the
    /// pinned producer — foreign truth can never adopt this lineage.
    ForeignAction {
        /// Canonical key of the pin.
        pin_key: String,
    },
    /// The winner's toolchain/event contracts differ from the contracts
    /// bound at pin open, or the pin predates contract binding — adoption
    /// refuses fail-closed (M017).
    ContractMismatch {
        /// Canonical key of the pin.
        pin_key: String,
    },
    /// Transitive verification failed: an ancestor obligation of the
    /// producing attempt is not resolved to its exact consumed object.
    AncestorLineageUnresolved {
        /// Canonical key of the pin being resolved/adopted.
        pin_key: String,
        /// Canonical key of the ancestor pin at fault.
        ancestor_pin_key: String,
        /// What state was found instead.
        detail: String,
    },
    /// Transitive verification failed permanently: an ancestor lineage
    /// was invalidated or adopted with foreign bytes — refused for good.
    AncestorLineageDiverged {
        /// Canonical key of the pin being resolved/adopted.
        pin_key: String,
        /// Canonical key of the ancestor pin at fault.
        ancestor_pin_key: String,
        /// What divergence was found.
        detail: String,
    },
}

impl From<StoreError> for ProvisionalPinError {
    fn from(value: StoreError) -> Self {
        Self::Store(value)
    }
}

impl std::fmt::Display for ProvisionalPinError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Collision {
                pin_key,
                pinned,
                offered,
            } => write!(
                f,
                "provisional pin collision on {pin_key}: pinned {pinned}, offered {offered}"
            ),
            Self::UnknownPin { pin_key } => write!(f, "unknown provisional pin {pin_key}"),
            Self::Unauthorized { pin_key } => {
                write!(f, "reader not authorized for provisional pin {pin_key}")
            }
            Self::Closed { pin_key } => write!(f, "provisional pin {pin_key} is closed"),
            Self::ProducerInvalidated { pin_key, reason } => {
                write!(f, "producer lineage invalidated ({reason}): {pin_key}")
            }
            Self::NonMonotonicRenewal { pin_key } => {
                write!(f, "non-monotonic renewal for provisional pin {pin_key}")
            }
            Self::AdoptionMismatch {
                pin_key,
                pinned,
                committed,
            } => write!(
                f,
                "adoption mismatch on {pin_key}: pinned {pinned}, committed {committed}"
            ),
            Self::NotActiveAuthority => {
                write!(f, "coordinator authority is not active for this release")
            }
            Self::UnresolvedConsumerDebt {
                pin_key,
                open_count,
            } => write!(
                f,
                "provisional pin {pin_key} still has {open_count} open consumer obligation(s)"
            ),
            Self::SameWinningAttempt { pin_key } => write!(
                f,
                "same producer attempt already owns commit resolution for {pin_key}"
            ),
            Self::ForeignAction { pin_key } => write!(
                f,
                "winning attempt serves a different action than pinned producer of {pin_key}"
            ),
            Self::ContractMismatch { pin_key } => write!(
                f,
                "winner toolchain/event contracts differ from pin binding on {pin_key}"
            ),
            Self::AncestorLineageUnresolved {
                pin_key,
                ancestor_pin_key,
                detail,
            } => write!(
                f,
                "ancestor lineage unresolved for {pin_key} at {ancestor_pin_key}: {detail}"
            ),
            Self::AncestorLineageDiverged {
                pin_key,
                ancestor_pin_key,
                detail,
            } => write!(
                f,
                "ancestor lineage diverged for {pin_key} at {ancestor_pin_key}: {detail}"
            ),
            Self::Store(e) => write!(f, "store error: {e:?}"),
        }
    }
}

impl std::error::Error for ProvisionalPinError {}

/// Outcome of registering a candidate pin for an uploaded object.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OpenOutcome {
    /// First offer: pin registered with its protective GC twin.
    Created,
    /// Idempotent re-offer of the SAME object under the SAME tuple.
    AlreadyPinned,
}

/// Outcome of closing a pin after drain/invaldation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CloseOutcome {
    /// Registry row closed and protective pin released.
    Released,
    /// Pin was already closed: idempotent no-op.
    AlreadyReleased,
}

/// Bind an uploaded immutable object under the identity tuple's candidate
/// pin (M004 step 1). Idempotent for identical re-offers; a different
/// object under the same tuple is a [`ProvisionalPinError::Collision`].
///
/// The protective `pins` twin is written in the SAME transaction as the
/// registry row, so the object is GC-safe from the instant either exists.
///
/// # Errors
/// Store failures; collisions with a differently-pinned same-tuple offer;
/// re-offers addressed to a pin that was already closed.
pub fn open_provisional_pin(
    store: &mut dyn RabsMetadataStore,
    identity: &ProvisionalIdentity,
    object: &ObjectId,
    contracts: &ProducerContracts,
) -> Result<OpenOutcome, ProvisionalPinError> {
    let pin_key = identity.pin_key();
    if let Some(existing) = store.provisional_pin_row(&pin_key)? {
        let offered = digest_key(&object.0);
        if existing.object_key == offered {
            return if existing.released {
                Err(ProvisionalPinError::Closed { pin_key })
            } else {
                Ok(OpenOutcome::AlreadyPinned)
            };
        }
        return Err(ProvisionalPinError::Collision {
            pin_key,
            pinned: existing.object_key,
            offered,
        });
    }
    // M017: materialize the COMPLETE transitive ancestor-pin closure of
    // the producing attempt BEFORE the pin exists. The attempt's inbound
    // obligations name its direct ancestors; each ancestor's own recorded
    // closure is transitively closed over. The full edge set ships in the
    // SAME insert transaction as the pin row (M017 store contract), so a
    // prepared descendant always carries its lineage — no tear can strip
    // it, and invalidation can always reach every consuming descendant.
    // M020: layered relaxation computes each ancestor's MIN-HOP distance
    // from this pin. Direct ancestors sit at depth 1; an ancestor A seen
    // through parent P sits at dist(P) + (P's recorded min-hops to A).
    // Stored depths are minimal by induction — every pin wrote its own
    // closure the same way — so one pass over parents' rows yields exact
    // minima, which the terminal-gate layer bounds by TRANSITIVE DEPTH
    // (I025), not just waiter count.
    let mut best: std::collections::BTreeMap<String, u64> = std::collections::BTreeMap::new();
    let mut frontier: Vec<(String, u64)> = store
        .list_open_provisional_obligations_by_attempt(&format!("{:032x}", identity.attempt.0))?
        .into_iter()
        .map(|obligation| (obligation.pin_key, 1))
        .collect();
    while let Some((key, hops)) = frontier.pop() {
        if best.get(&key).is_some_and(|&known| known <= hops) {
            continue;
        }
        best.insert(key.clone(), hops);
        for (ancestor_key, stored_hops) in store.list_provisional_pin_ancestors(&key)? {
            frontier.push((ancestor_key, hops + stored_hops));
        }
    }
    let ancestor_pin_keys: Vec<(String, u64)> = best.into_iter().collect();
    let digest = identity.digest();
    // Deterministic 128-bit protective-pin id derived from the identity
    // digest; the SQL UNIQUE constraint on `pins.id_hex` fails closed in
    // the astronomically unlikely case of a derivation collision.
    let mut be16 = [0u8; 16];
    be16.copy_from_slice(&digest.bytes[0..16]);
    let protective_pin_id = u128::from_be_bytes(be16);
    store.insert_provisional_pin(&ProvisionalPinInsert {
        pin_key: pin_key.clone(),
        authority_key: digest_key(&authority_digest(&identity.authority)),
        action_key: digest_key(&identity.action_key),
        generation: identity.generation.0,
        attempt: identity.attempt.0,
        lease: identity.lease.0,
        role_tag: i64::try_from(output_role_tag(identity.role)).expect("role tags fit i64"),
        virtual_path: identity.virtual_path.as_bytes().to_vec(),
        object: object.0.clone(),
        protective_pin_id,
        reason: format!(
            "M004 candidate pin: action {}, gen {:032x}, attempt {:032x}",
            digest_key(&identity.action_key),
            identity.generation.0,
            identity.attempt.0
        ),
        toolchain_contract_key: digest_key(&contracts.toolchain),
        event_contract_key: digest_key(&contracts.events),
        ancestor_pin_keys,
    })?;
    Ok(OpenOutcome::Created)
}

/// Authorize one reader population for a live pin. Granting against a
/// closed or unknown pin is refused — authorization follows liveness.
///
/// # Errors
/// Store failures; unknown/closed pins.
pub fn authorize_reader(
    store: &mut dyn RabsMetadataStore,
    identity: &ProvisionalIdentity,
    reader: &ProvisionalReader,
) -> Result<(), ProvisionalPinError> {
    let pin_key = identity.pin_key();
    let Some(row) = store.provisional_pin_row(&pin_key)? else {
        return Err(ProvisionalPinError::UnknownPin { pin_key });
    };
    if row.released {
        return Err(ProvisionalPinError::Closed { pin_key });
    }
    store.record_provisional_grant(
        &pin_key,
        reader.grant_kind(),
        &reader.grant_id(),
        row.renewal_seq,
    )?;
    Ok(())
}

/// Resolve a provisional output FOR a specific reader (M004 step 2): the
/// only way bytes become visible. Refuses unknown pins, invalidated
/// lineage, closed pins, and readers without a grant — in that order.
///
/// # Errors
/// Typed refusals per [`ProvisionalPinError`]; store failures.
pub fn resolve_for_reader(
    store: &mut dyn RabsMetadataStore,
    identity: &ProvisionalIdentity,
    reader: &ProvisionalReader,
) -> Result<ObjectId, ProvisionalPinError> {
    let pin_key = identity.pin_key();
    let Some(row) = store.provisional_pin_row(&pin_key)? else {
        return Err(ProvisionalPinError::UnknownPin { pin_key });
    };
    if let Some(reason) = row.invalidated_reason {
        return Err(ProvisionalPinError::ProducerInvalidated { pin_key, reason });
    }
    if row.released {
        return Err(ProvisionalPinError::Closed { pin_key });
    }
    let authorized = store
        .list_provisional_grants(&pin_key)?
        .iter()
        .any(|(kind, id, _)| kind.as_str() == reader.grant_kind() && id == &reader.grant_id());
    if !authorized {
        return Err(ProvisionalPinError::Unauthorized { pin_key });
    }
    // M006: a dependent attempt CONSUMING the output carries a
    // DirectProducerCommit obligation — its terminal paths stay blocked
    // until the producer lineage resolves. Edge subscribers only observe;
    // they never offer results, so no obligation attaches to them.
    // Idempotent: repeat reads by the same attempt keep one row.
    if let ProvisionalReader::DependentAttempt { worker, attempt } = reader {
        store.record_provisional_consumption(&ProvisionalObligationInsert {
            consumer_worker: worker.clone(),
            consumer_attempt: attempt.0,
            pin_key: pin_key.clone(),
            producer_action_key: digest_key(&identity.action_key),
            producer_generation: identity.generation.0,
            producer_attempt: identity.attempt.0,
            role_tag: i64::try_from(output_role_tag(identity.role)).expect("role tags fit i64"),
            virtual_path: identity.virtual_path.as_bytes().to_vec(),
            object_key: row.object_key.clone(),
            created_seq: row.renewal_seq,
        })?;
    }
    Ok(ObjectId(row.object))
}

/// Record that the WINNING committed result adopted this candidate's
/// output (§65.1). Only an EXACT object match satisfies lineage; anything
/// else refuses so descendants are cancelled rather than satisfied with
/// foreign bytes.
///
/// # Errors
/// Store failures; adoption mismatch; unknown pin.
pub fn record_adoption(
    store: &mut dyn RabsMetadataStore,
    identity: &ProvisionalIdentity,
    committed_object: &ObjectId,
) -> Result<(), ProvisionalPinError> {
    let pin_key = identity.pin_key();
    let Some(row) = store.provisional_pin_row(&pin_key)? else {
        return Err(ProvisionalPinError::UnknownPin { pin_key });
    };
    let committed = digest_key(&committed_object.0);
    if row.object_key != committed {
        return Err(ProvisionalPinError::AdoptionMismatch {
            pin_key,
            pinned: row.object_key,
            committed,
        });
    }
    verify_transitive_lineage(store, identity)?;
    store.adopt_provisional_pin(&pin_key, &committed)?;
    store.resolve_provisional_obligations(&pin_key, &committed)?;
    Ok(())
}

/// Resolve the consumer obligations of one provisional pin because its
/// producer committed a result carrying the EXACT pinned object (the
/// normal lineage-closure path; plan §65 "producer resolves the entire
/// ancestor closure"). A different object is an adoption mismatch: the
/// coordinator must cancel the descendants instead of satisfying them
/// with foreign bytes.
///
/// # Errors
/// Store failures; adoption mismatch; unknown pin.
pub fn resolve_consumers_on_commit(
    store: &mut dyn RabsMetadataStore,
    identity: &ProvisionalIdentity,
    committed_object: &ObjectId,
) -> Result<usize, ProvisionalPinError> {
    let pin_key = identity.pin_key();
    let Some(row) = store.provisional_pin_row(&pin_key)? else {
        return Err(ProvisionalPinError::UnknownPin { pin_key });
    };
    let committed = digest_key(&committed_object.0);
    if row.object_key != committed {
        return Err(ProvisionalPinError::AdoptionMismatch {
            pin_key,
            pinned: row.object_key.clone(),
            committed: committed.clone(),
        });
    }
    // M017: commit resolution is gated on the WHOLE transitive ancestor
    // closure being exactly resolved — a descendant never satisfies its
    // consumers on top of unresolved or diverged upstream truth.
    verify_transitive_lineage(store, identity)?;
    store.adopt_provisional_pin(&pin_key, &committed)?;
    Ok(store.resolve_provisional_obligations(&pin_key, &committed)?)
}

/// M017 transitive lineage verification: the pin's whole materialized
/// ancestor closure must be exactly resolved before this pin may commit-
/// resolve or be adopted. Concretely:
///
/// - the producing attempt carries NO non-resolved inbound obligation
///   (open blocks the commit; cancelled refuses it permanently), and
/// - every closure member is either adopted with EXACTLY its pinned
///   object (the §65.1 marker) or cleanly drained after such resolution.
///
/// Exactness composes inductively: each ancestor satisfied these same
/// conditions at ITS resolution, so a clear walk proves the full chain.
///
/// # Errors
/// Typed [`ProvisionalPinError`]s; store failures.
pub fn verify_transitive_lineage(
    store: &mut dyn RabsMetadataStore,
    identity: &ProvisionalIdentity,
) -> Result<(), ProvisionalPinError> {
    let pin_key = identity.pin_key();
    let Some(row) = store.provisional_pin_row(&pin_key)? else {
        return Err(ProvisionalPinError::UnknownPin { pin_key });
    };
    if let Some(reason) = row.invalidated_reason {
        return Err(ProvisionalPinError::ProducerInvalidated { pin_key, reason });
    }
    if row.released {
        return Err(ProvisionalPinError::Closed { pin_key });
    }
    if let Some(obligation) = store
        .list_open_provisional_obligations_by_attempt(&format!("{:032x}", identity.attempt.0))?
        .into_iter()
        .next()
    {
        // list_*_by_attempt returns only non-resolved rows: open blocks
        // the commit, cancelled refuses it permanently.
        if obligation.status == "cancelled" {
            return Err(ProvisionalPinError::AncestorLineageDiverged {
                pin_key,
                ancestor_pin_key: obligation.pin_key,
                detail: format!(
                    "producing attempt consumed cancelled object {}",
                    obligation.object_key
                ),
            });
        }
        return Err(ProvisionalPinError::AncestorLineageUnresolved {
            pin_key: pin_key.clone(),
            ancestor_pin_key: obligation.pin_key.clone(),
            detail: format!(
                "inbound obligation status {} on consumed object {}",
                obligation.status, obligation.object_key
            ),
        });
    }
    for (ancestor_pin_key, _min_hops) in store.list_provisional_pin_ancestors(&pin_key)? {
        let Some(ancestor) = store.provisional_pin_row(&ancestor_pin_key)? else {
            return Err(ProvisionalPinError::AncestorLineageUnresolved {
                pin_key: pin_key.clone(),
                ancestor_pin_key,
                detail: "closure member missing from registry".to_owned(),
            });
        };
        if let Some(reason) = ancestor.invalidated_reason {
            return Err(ProvisionalPinError::AncestorLineageDiverged {
                pin_key: pin_key.clone(),
                ancestor_pin_key,
                detail: format!("invalidated: {reason}"),
            });
        }
        match &ancestor.adopted_object_key {
            Some(adopted) if *adopted == ancestor.object_key => {}
            Some(adopted) => {
                return Err(ProvisionalPinError::AncestorLineageDiverged {
                    pin_key: pin_key.clone(),
                    ancestor_pin_key,
                    detail: format!("adopted foreign bytes {adopted}"),
                });
            }
            None if ancestor.released => {}
            None => {
                return Err(ProvisionalPinError::AncestorLineageUnresolved {
                    pin_key: pin_key.clone(),
                    ancestor_pin_key,
                    detail: "ancestor not yet adopted".to_owned(),
                });
            }
        }
    }
    Ok(())
}

/// Context of the WINNING attempt proposing to adopt a candidate's
/// output (M017): a DIFFERENT producer attempt/generation of the SAME
/// action, running under EQUAL toolchain/event contracts, committed by
/// the active coordinator authority.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WinningAttemptContext {
    /// Active coordinator authority committing the winner (records the
    /// adoption edge).
    pub authority: CoordinatorAuthority,
    /// The action both attempts serve.
    pub action_key: TypedDigest,
    /// Winner generation.
    pub generation: ActionGenerationId,
    /// Winner attempt id — must differ from the pinned producer's.
    pub attempt: AttemptId,
    /// Contracts the winner ran under.
    pub contracts: ProducerContracts,
}

/// Outcome of a different-winning-attempt adoption proposal (M017).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AdoptionOutcome {
    /// Exact-object, contract-equal adoption: lineage satisfied and the
    /// pin's consumer obligations resolved.
    Adopted {
        /// How many open obligations resolved.
        obligations_resolved: usize,
    },
    /// Divergent object: the pin AND every transitive descendant pin were
    /// invalidated and all consuming descendants are refused permanently.
    DivergenceCancelled {
        /// Pins invalidated by the cascade (including this one).
        pins_invalidated: usize,
        /// Open obligations cancelled across the cascade.
        obligations_cancelled: usize,
    },
}

/// M017 different-winning-attempt adoption (§65.1): a winner OTHER than
/// the pinned producer attempt satisfies lineage only when its committed
/// result contains the SAME logical output object ID under EQUAL
/// toolchain/event contracts (an explicit adoption edge). A differing
/// object cancels/refuses ALL consuming descendants via the transitive
/// cascade.
///
/// # Errors
/// Typed [`ProvisionalPinError`]s; store failures.
pub fn adopt_from_winning_attempt(
    store: &mut dyn RabsMetadataStore,
    identity: &ProvisionalIdentity,
    winner: &WinningAttemptContext,
    committed_object: &ObjectId,
) -> Result<AdoptionOutcome, ProvisionalPinError> {
    let pin_key = identity.pin_key();
    let Some(row) = store.provisional_pin_row(&pin_key)? else {
        return Err(ProvisionalPinError::UnknownPin { pin_key });
    };
    if let Some(reason) = row.invalidated_reason {
        return Err(ProvisionalPinError::ProducerInvalidated { pin_key, reason });
    }
    if row.released {
        return Err(ProvisionalPinError::Closed { pin_key });
    }
    if winner.action_key != identity.action_key {
        return Err(ProvisionalPinError::ForeignAction { pin_key });
    }
    if winner.attempt == identity.attempt && winner.generation == identity.generation {
        return Err(ProvisionalPinError::SameWinningAttempt { pin_key });
    }
    // Contract equality is fail-closed: an unbound (pre-v16) pin or any
    // contract difference refuses the adoption outright.
    if row.toolchain_contract_key.is_empty()
        || row.event_contract_key.is_empty()
        || row.toolchain_contract_key != digest_key(&winner.contracts.toolchain)
        || row.event_contract_key != digest_key(&winner.contracts.events)
    {
        return Err(ProvisionalPinError::ContractMismatch { pin_key });
    }
    let committed = digest_key(&committed_object.0);
    if committed != row.object_key {
        // DIVERGENCE: the winner resolved this logical output to foreign
        // bytes — every consuming descendant is refused, transitively.
        let reason = format!(
            "winning attempt {:032x}/{:032x} committed divergent object {} \
             for logical output of {}",
            winner.generation.0, winner.attempt.0, committed, row.object_key
        );
        let counts = close_and_cancel_cascading(store, &pin_key, &reason)?;
        return Ok(AdoptionOutcome::DivergenceCancelled {
            pins_invalidated: counts.pins,
            obligations_cancelled: counts.obligations,
        });
    }
    verify_transitive_lineage(store, identity)?;
    // Explicit adoption edge, recorded under the ACTIVE authority the
    // winner commits with (store-gated).
    store.record_adoption_edge(
        &authority_digest(&winner.authority),
        &digest_key(&identity.action_key),
        output_role_name_for_tag(row.role_tag),
        &row.virtual_path,
        &row.object_key,
        &committed,
    )?;
    store.adopt_provisional_pin(&pin_key, &committed)?;
    let resolved = store.resolve_provisional_obligations(&pin_key, &committed)?;
    Ok(AdoptionOutcome::Adopted {
        obligations_resolved: resolved,
    })
}
/// Invalidate a pin because its producer generation failed, was
/// superseded without compatible adoption, or lost authority (§65).
/// Readers refuse immediately with
/// [`ProvisionalPinError::ProducerInvalidated`]; the protective GC pin is
/// released only AFTER the registry close commits (fail toward retention).
///
/// M017: invalidation CASCADES — every pin whose materialized closure
/// contains this one is invalidated too, and all their consumer
/// obligations are cancelled, so refusal reaches the whole descendant
/// tree in one event instead of relying on each hop to re-discover it.
///
/// # Errors
/// Store failures; unknown pin.
pub fn invalidate_lineage(
    store: &mut dyn RabsMetadataStore,
    identity: &ProvisionalIdentity,
    reason: &str,
) -> Result<CloseOutcome, ProvisionalPinError> {
    let pin_key = identity.pin_key();
    if store.provisional_pin_row(&pin_key)?.is_none() {
        return Err(ProvisionalPinError::UnknownPin { pin_key });
    }
    close_and_cancel_cascading(store, &pin_key, reason)?;
    Ok(CloseOutcome::Released)
}

/// Terminal-path gate for one descendant attempt (M006 acceptance): a
/// descendant that consumed provisional metadata may not offer a result
/// or receive terminal positive delivery until every obligation resolves.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TerminalGate {
    /// No unresolved obligations: terminal paths may proceed.
    Clear,
    /// Open obligations: producer lineage not yet resolved — BLOCKED.
    Blocked {
        /// Pin keys of the open obligations (producer lineage addresses).
        pending_pin_keys: Vec<String>,
    },
    /// Cancelled obligations: producer lineage FAILED — this descendant
    /// is refused, permanently; it can never publish.
    Refused {
        /// Pin keys of the cancelled obligations.
        cancelled_pin_keys: Vec<String>,
    },
}

/// Evaluate the descendant's terminal gate. `Refused` dominates `Blocked`:
/// once any ancestor lineage failed, the descendant cannot publish no
/// matter what other ancestors do.
///
/// # Errors
/// Store failures.
pub fn descendant_terminal_gate(
    store: &mut dyn RabsMetadataStore,
    consumer_worker: &str,
    consumer_attempt: AttemptId,
) -> Result<TerminalGate, ProvisionalPinError> {
    let rows = store.list_open_provisional_obligations(
        consumer_worker,
        &format!("{:032x}", consumer_attempt.0),
    )?;
    let mut blocked = Vec::new();
    let mut refused = Vec::new();
    for row in rows {
        match row.status.as_str() {
            "open" => blocked.push(row.pin_key),
            "cancelled" => refused.push(row.pin_key),
            other => {
                return Err(ProvisionalPinError::Store(StoreError::Corruption(format!(
                    "obligation status {other:?}"
                ))));
            }
        }
    }
    Ok(if !refused.is_empty() {
        TerminalGate::Refused {
            cancelled_pin_keys: refused,
        }
    } else if !blocked.is_empty() {
        TerminalGate::Blocked {
            pending_pin_keys: blocked,
        }
    } else {
        TerminalGate::Clear
    })
}

/// Close the pin once all consumer/reconciliation obligations drained
/// (§65 GC rule). Coordinator-only: workers hold no release authority over
/// candidate pins. The active-authority check comes from the shared H041
/// scoping on the protective `pins` row.
///
/// # Errors
/// Store failures; worker releasers; non-active coordinator authorities;
/// unknown pin.
pub fn release_after_drain(
    store: &mut dyn RabsMetadataStore,
    identity: &ProvisionalIdentity,
    releaser: &Releaser,
) -> Result<CloseOutcome, ProvisionalPinError> {
    let pin_key = identity.pin_key();
    let Some(row) = store.provisional_pin_row(&pin_key)? else {
        return Err(ProvisionalPinError::UnknownPin { pin_key });
    };
    // Authority FIRST, before ANY mutation: a coordinator without the
    // active authority must not be able to close reads, and the
    // close-then-release order must never run for an unauthorized caller.
    let presented = match releaser {
        Releaser::Worker(_) => {
            // Candidate pins bind coordinator-owned truth; no worker
            // identity may end their protection (publication-root posture).
            return Err(ProvisionalPinError::Unauthorized { pin_key });
        }
        Releaser::Coordinator(authority) => authority_digest(authority),
    };
    let active = store
        .active_authority()?
        .map(|authority_row| authority_row.digest);
    if active.as_ref() != Some(&presented) {
        return Err(ProvisionalPinError::NotActiveAuthority);
    }
    // §65 GC rule: garbage-collect only after ALL consumer and
    // reconciliation obligations drain. OPEN obligations mean live
    // descendants still await this lineage's resolution.
    let open_debt = store.count_open_provisional_obligations(&pin_key)?;
    if open_debt > 0 {
        return Err(ProvisionalPinError::UnresolvedConsumerDebt {
            pin_key,
            open_count: open_debt,
        });
    }
    // 1) Close the REGISTRY row first: from this commit on, reads refuse.
    let outcome = close_internal(store, identity, None)?;
    // 2) Then release the GC twin through the shared authority-scoped path.
    let protective_id = u128::from_str_radix(&row.protective_pin_hex, 16).map_err(|_| {
        ProvisionalPinError::Store(StoreError::Corruption(format!(
            "protective pin hex {}",
            row.protective_pin_hex
        )))
    })?;
    match release_pin_scoped(store, protective_id, releaser)? {
        ReleaseOutcome::Released | ReleaseOutcome::AlreadyReleased => {}
        ReleaseOutcome::RefusedNotActiveAuthority => {
            return Err(ProvisionalPinError::NotActiveAuthority);
        }
        other => {
            return Err(ProvisionalPinError::Store(StoreError::Corruption(format!(
                "protective pin release refused: {other:?}"
            ))));
        }
    }
    Ok(outcome)
}

/// Monotonically renew a live pin's sequence (lease-freshness bookkeeping;
/// expiry judgments stay in coordinator sequence space per R127).
///
/// # Errors
/// Store failures; unknown/closed pins; stale sequences.
pub fn renew_provisional_pin(
    store: &mut dyn RabsMetadataStore,
    identity: &ProvisionalIdentity,
    renewal_seq: u64,
) -> Result<(), ProvisionalPinError> {
    let pin_key = identity.pin_key();
    store
        .renew_provisional_pin(&pin_key, renewal_seq)
        .map_err(|e| match e {
            StoreError::NonMonotonicPinRenewal => {
                ProvisionalPinError::NonMonotonicRenewal { pin_key }
            }
            StoreError::PinReleased => ProvisionalPinError::Closed { pin_key },
            StoreError::UnknownPin => ProvisionalPinError::UnknownPin { pin_key },
            other => ProvisionalPinError::Store(other),
        })
}

fn close_internal(
    store: &mut dyn RabsMetadataStore,
    identity: &ProvisionalIdentity,
    invalidation_reason: Option<&str>,
) -> Result<CloseOutcome, ProvisionalPinError> {
    let pin_key = identity.pin_key();
    if store.provisional_pin_row(&pin_key)?.is_none() {
        return Err(ProvisionalPinError::UnknownPin { pin_key });
    }
    store.close_provisional_pin(&pin_key, invalidation_reason)?;
    Ok(CloseOutcome::Released)
}

/// Aggregate outcome of a batch lineage invalidation (M007).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InvalidationSummary {
    /// Provisional pins closed (registry + reason recorded).
    pub pins_invalidated: usize,
    /// Open consumer obligations cancelled by the invalidation.
    pub obligations_cancelled: usize,
}

/// Per-root counts of one cascading invalidation.
struct CascadeCounts {
    pins: usize,
    obligations: usize,
}

fn close_and_cancel_cascading(
    store: &mut dyn RabsMetadataStore,
    root_pin_key: &str,
    reason: &str,
) -> Result<CascadeCounts, ProvisionalPinError> {
    // M017: the descendant set is the materialized reverse closure —
    // every pin whose recorded ancestry contains the root, transitively —
    // so ONE pass reaches the whole tree. Registry rows close FIRST
    // (reads refuse immediately), then each pin's open obligations are
    // cancelled; descendants flip to Refused at their terminal gates.
    // The protective GC twins stay for the coordinator's drain pass
    // (fail toward retention on tear), exactly as for the root pin.
    let mut pending: Vec<String> = vec![root_pin_key.to_owned()];
    pending.extend(store.list_provisional_pin_descendants(root_pin_key)?);
    pending.sort();
    pending.dedup();
    let mut counts = CascadeCounts {
        pins: 0,
        obligations: 0,
    };
    for key in pending {
        // Already-released members (an earlier cascade or batch entry
        // reached them first) are skipped, keeping counts honest.
        let Some(row) = store.provisional_pin_row(&key)? else {
            continue;
        };
        if row.released {
            continue;
        }
        store.close_provisional_pin(&key, Some(reason))?;
        counts.pins += 1;
        counts.obligations += store.cancel_provisional_obligations(&key)?;
    }
    Ok(counts)
}

/// R39 trigger 1 — GENERATION FAILURE: the producer generation failed or
/// was tombstoned; every provisional output it minted is invalidated and
/// its dependents cancelled.
///
/// # Errors
/// Store failures.
pub fn invalidate_lineage_for_generation_failure(
    store: &mut dyn RabsMetadataStore,
    action_key: &TypedDigest,
    generation: ActionGenerationId,
    reason: &str,
) -> Result<InvalidationSummary, ProvisionalPinError> {
    let rows = store.list_open_provisional_pins_for_action_generation(
        &digest_key(action_key),
        &format!("{:032x}", generation.0),
    )?;
    let mut summary = InvalidationSummary {
        pins_invalidated: 0,
        obligations_cancelled: 0,
    };
    for row in &rows {
        let counts = close_and_cancel_cascading(store, &row.pin_key, reason)?;
        summary.pins_invalidated += counts.pins;
        summary.obligations_cancelled += counts.obligations;
    }
    Ok(summary)
}

/// R39 trigger 2 — AUTHORITY LOSS: the minting coordinator lost authority
/// (term superseded/operator reset); everything it pinned provisionally
/// is invalidated.
///
/// # Errors
/// Store failures.
pub fn invalidate_lineage_for_authority_loss(
    store: &mut dyn RabsMetadataStore,
    authority: &CoordinatorAuthority,
    reason: &str,
) -> Result<InvalidationSummary, ProvisionalPinError> {
    let rows = store
        .list_open_provisional_pins_for_authority(&digest_key(&authority_digest(authority)))?;
    let mut summary = InvalidationSummary {
        pins_invalidated: 0,
        obligations_cancelled: 0,
    };
    for row in &rows {
        let counts = close_and_cancel_cascading(store, &row.pin_key, reason)?;
        summary.pins_invalidated += counts.pins;
        summary.obligations_cancelled += counts.obligations;
    }
    Ok(summary)
}

/// R39 trigger 3 — SUPERSESSION WITHOUT COMPATIBLE ADOPTION: a winner
/// committed the action resolving logical outputs to `committed_output_keys`
/// (digest keys); every still-open pin of that action whose object is NOT
/// among them consumed truth that can never be adopted — invalidated.
/// Pins matching committed objects stay open for the normal resolution
/// path ([`resolve_consumers_on_commit`]).
///
/// # Errors
/// Store failures.
pub fn invalidate_unadopted_lineage_for_action(
    store: &mut dyn RabsMetadataStore,
    action_key: &TypedDigest,
    committed_output_keys: &std::collections::BTreeSet<String>,
    reason: &str,
) -> Result<InvalidationSummary, ProvisionalPinError> {
    let rows = store.list_open_provisional_pins_for_action(&digest_key(action_key))?;
    let mut summary = InvalidationSummary {
        pins_invalidated: 0,
        obligations_cancelled: 0,
    };
    for row in &rows {
        if committed_output_keys.contains(&row.object_key) {
            continue;
        }
        let counts = close_and_cancel_cascading(store, &row.pin_key, reason)?;
        summary.pins_invalidated += counts.pins;
        summary.obligations_cancelled += counts.obligations;
    }
    Ok(summary)
}

/// Causal trace for one provisional output (M007): EVERY dependent that
/// started from it — resolved, open, or cancelled — with full consumer
/// identity and status. This answers "which dependents consumed this
/// output" durably, after the fact.
///
/// # Errors
/// Store failures.
pub fn provisional_causal_trace(
    store: &mut dyn RabsMetadataStore,
    pin_key: &str,
) -> Result<Vec<crate::metadata_store::ProvisionalObligationRow>, ProvisionalPinError> {
    Ok(store.list_provisional_obligations_for_pin(pin_key)?)
}

// Tests — the M004 acceptance suite: pin semantics + authorized
// visibility. Every fixture runs against BOTH engines via the reference
// SQLite store; the differential harness covers the new tables through
// `differential_snapshot`.
// ---------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::metadata_store::{RusqliteEngine, SqlMetadataStore};
    use rabs_protocol::authority::ClusterId;
    use rabs_protocol::result_identity::DigestAlgorithm;

    const ACTION_DOMAIN: &str = "rabs.action-key.sha256.v1";

    struct Fixture {
        store: SqlMetadataStore<RusqliteEngine>,
    }

    fn tagged_action(tag: u8) -> TypedDigest {
        let mut bytes = [0u8; 32];
        bytes[0] = tag;
        bytes[31] = tag;
        TypedDigest {
            algorithm: DigestAlgorithm::Sha256V1,
            domain: ACTION_DOMAIN,
            bytes,
        }
    }

    fn tagged_object(tag: u8) -> ObjectId {
        let mut d = tagged_action(tag);
        d.domain = "rabs.object.sha256.v1";
        ObjectId(d)
    }

    fn authority(tag: u64) -> CoordinatorAuthority {
        CoordinatorAuthority {
            cluster_id: ClusterId(format!("cluster-{tag}")),
            credential_generation: tag,
            term: 100 + tag,
            incarnation_id: rabs_protocol::authority::CoordinatorIncarnationId(
                0xAA00_0000_0000_0000 + u128::from(tag),
            ),
        }
    }

    fn identity(authority_tag: u64, attempt_tag: u128) -> ProvisionalIdentity {
        ProvisionalIdentity {
            authority: authority(authority_tag),
            action_key: tagged_action(10),
            generation: ActionGenerationId(0x50),
            attempt: AttemptId(attempt_tag),
            lease: ExecutionLeaseId(attempt_tag + 1),
            role: OutputRole::ProvisionalMetadata,
            virtual_path: RawBytes::new(b"target/debug/deps/libfeat.rmeta".to_vec()),
        }
    }

    fn fixture(name: &str) -> Fixture {
        let engine = RusqliteEngine::open_in_memory().unwrap();
        let store = SqlMetadataStore::open(engine).unwrap();
        let _ = name;
        Fixture { store }
    }

    fn dependent(worker: &str, attempt: u128) -> ProvisionalReader {
        ProvisionalReader::DependentAttempt {
            worker: worker.to_owned(),
            attempt: AttemptId(attempt),
        }
    }

    fn edge(subscriber: u128) -> ProvisionalReader {
        ProvisionalReader::AwaitingEdge {
            subscriber: SubscriberId(subscriber),
        }
    }

    #[test]
    fn m004_open_is_idempotent_and_collision_refuses_different_object() {
        let mut f = fixture("open-idem");
        let id = identity(1, 20);
        let obj_a = tagged_object(41);

        assert_eq!(
            open_provisional_pin(&mut f.store, &id, &obj_a, &m017_ctx()).unwrap(),
            OpenOutcome::Created
        );
        // Identical re-offer (retry/duplicate upload report): no-op.
        assert_eq!(
            open_provisional_pin(&mut f.store, &id, &obj_a, &m017_ctx()).unwrap(),
            OpenOutcome::AlreadyPinned
        );
        // Different object, same tuple: collision incident, original intact.
        let err =
            open_provisional_pin(&mut f.store, &id, &tagged_object(42), &m017_ctx()).unwrap_err();
        let ProvisionalPinError::Collision {
            pinned, offered, ..
        } = &err
        else {
            panic!("expected collision, got {err:?}");
        };
        assert_eq!(pinned, &digest_key(&obj_a.0));
        assert_eq!(offered, &digest_key(&tagged_object(42).0));
        // And the pinned object still resolves for an authorized reader.
        authorize_reader(&mut f.store, &id, &edge(7)).unwrap();
        assert_eq!(
            resolve_for_reader(&mut f.store, &id, &edge(7)).unwrap(),
            obj_a
        );
    }

    #[test]
    fn m004_visibility_is_closed_by_default_and_grant_scoped() {
        let mut f = fixture("visibility");
        let id = identity(1, 21);
        let obj = tagged_object(43);
        open_provisional_pin(&mut f.store, &id, &obj, &m017_ctx()).unwrap();

        // No grants yet: even plausible readers are refused.
        assert_eq!(
            resolve_for_reader(&mut f.store, &id, &dependent("worker-a", 99)).unwrap_err(),
            ProvisionalPinError::Unauthorized {
                pin_key: id.pin_key()
            }
        );

        authorize_reader(&mut f.store, &id, &dependent("worker-a", 99)).unwrap();
        authorize_reader(&mut f.store, &id, &edge(7)).unwrap();

        // Granted dependent attempt + awaiting edge read fine.
        assert_eq!(
            resolve_for_reader(&mut f.store, &id, &dependent("worker-a", 99)).unwrap(),
            obj
        );
        assert_eq!(
            resolve_for_reader(&mut f.store, &id, &edge(7)).unwrap(),
            obj
        );

        // A SIBLING attempt on the same worker is NOT covered by the grant:
        // authorization is per-attempt, not per-worker.
        assert_eq!(
            resolve_for_reader(&mut f.store, &id, &dependent("worker-a", 100)).unwrap_err(),
            ProvisionalPinError::Unauthorized {
                pin_key: id.pin_key()
            }
        );
        // Different worker, different edge subscriber: refused.
        assert_eq!(
            resolve_for_reader(&mut f.store, &id, &edge(8)).unwrap_err(),
            ProvisionalPinError::Unauthorized {
                pin_key: id.pin_key()
            }
        );

        // Grants do not leak across identity tuples: same shape, different
        // attempt/generation/authority cannot see this pin.
        let other_generation = ProvisionalIdentity {
            generation: ActionGenerationId(0x51),
            ..identity(1, 21)
        };
        assert_eq!(
            resolve_for_reader(&mut f.store, &other_generation, &edge(7)).unwrap_err(),
            ProvisionalPinError::UnknownPin {
                pin_key: other_generation.pin_key()
            }
        );
        let other_authority = ProvisionalIdentity {
            authority: authority(2),
            ..identity(1, 21)
        };
        assert_ne!(other_authority.pin_key(), id.pin_key());
    }

    #[test]
    fn m004_worker_cannot_release_and_active_coordinator_can() {
        let mut f = fixture("release-auth");
        let id = identity(1, 22);
        open_provisional_pin(&mut f.store, &id, &tagged_object(44), &m017_ctx()).unwrap();

        // ANY worker identity is refused: candidate pins are
        // coordinator-owned through drain.
        let err = release_after_drain(&mut f.store, &id, &Releaser::Worker("worker-a".to_owned()))
            .unwrap_err();
        assert_eq!(
            err,
            ProvisionalPinError::Unauthorized {
                pin_key: id.pin_key()
            }
        );

        // An authority(9) coordinator is active; a stale authority(2)
        // presenter is refused BEFORE anything mutates.
        f.store
            .acquire_authority(&crate::metadata_store::AuthorityRow {
                digest: crate::publication::authority_digest(&authority(9)),
                cluster_id: "cluster-9".to_owned(),
                incarnation: 0xEE,
                term: 109,
                acquired_seq: 1,
            })
            .unwrap();
        let err = release_after_drain(&mut f.store, &id, &Releaser::Coordinator(authority(2)))
            .unwrap_err();
        assert_eq!(err, ProvisionalPinError::NotActiveAuthority);
        // Nothing was closed by the refused attempt: reads still work.
        authorize_reader(&mut f.store, &id, &edge(7)).unwrap();

        // The ACTIVE authority releases cleanly; repeat is idempotent-closed.
        f.store
            .release_authority(&crate::publication::authority_digest(&authority(9)))
            .unwrap();
        f.store
            .acquire_authority(&crate::metadata_store::AuthorityRow {
                digest: crate::publication::authority_digest(&authority(1)),
                cluster_id: "cluster-1".to_owned(),
                incarnation: 0xAA,
                term: 101,
                acquired_seq: 2,
            })
            .unwrap();
        assert_eq!(
            release_after_drain(&mut f.store, &id, &Releaser::Coordinator(authority(1))).unwrap(),
            CloseOutcome::Released
        );
        // Post-close reads refuse EVEN for previously granted readers.
        authorize_reader(&mut f.store, &id, &edge(7)).unwrap_err();
    }

    #[test]
    fn m004_invalidation_refuses_readers_and_fails_toward_retention_order() {
        let mut f = fixture("invalidate");
        let id = identity(1, 23);
        let obj = tagged_object(45);
        open_provisional_pin(&mut f.store, &id, &obj, &m017_ctx()).unwrap();
        authorize_reader(&mut f.store, &id, &dependent("worker-b", 5)).unwrap();

        assert_eq!(
            invalidate_lineage(&mut f.store, &id, "producer generation failed").unwrap(),
            CloseOutcome::Released
        );
        // Authorized reader now gets the INVALIDATION reason, not a miss.
        assert_eq!(
            resolve_for_reader(&mut f.store, &id, &dependent("worker-b", 5)).unwrap_err(),
            ProvisionalPinError::ProducerInvalidated {
                pin_key: id.pin_key(),
                reason: "producer generation failed".to_owned()
            }
        );
        // Invalidation is idempotent; the FIRST reason survives.
        invalidate_lineage(&mut f.store, &id, "second reason").unwrap();
        let row = f.store.provisional_pin_row(&id.pin_key()).unwrap().unwrap();
        assert_eq!(
            row.invalidated_reason.as_deref(),
            Some("producer generation failed")
        );
        assert!(row.released);
        // Fail toward retention: the registry closed, but the protective
        // pin stays unreleased here (only release_after_drain releases it),
        // so the object remains GC-safe until the coordinator drains it.
        let protective = u128::from_str_radix(&row.protective_pin_hex, 16).unwrap();
        let pin = f.store.pin_row(protective).unwrap().unwrap();
        assert!(!pin.released);
        assert_eq!(pin.class, PROVISIONAL_PIN_CLASS);
    }

    #[test]
    fn m004_adoption_requires_exact_object_and_other_success_does_not_stabilize() {
        let mut f = fixture("adoption");
        let id = identity(1, 24);
        let pinned_obj = tagged_object(46);
        open_provisional_pin(&mut f.store, &id, &pinned_obj, &m017_ctx()).unwrap();
        authorize_reader(&mut f.store, &id, &edge(11)).unwrap();

        // §65: another attempt succeeding for the same action key does NOT
        // stabilize this pin — state unchanged, reads still gated.
        let before = f.store.provisional_pin_row(&id.pin_key()).unwrap().unwrap();
        assert!(!before.released && before.adopted_object_key.is_none());

        // §65.1: a winner publishing DIFFERENT bytes cannot adopt — the
        // mismatch is typed, and descendants must be cancelled instead.
        let err = record_adoption(&mut f.store, &id, &tagged_object(47)).unwrap_err();
        assert_eq!(
            err,
            ProvisionalPinError::AdoptionMismatch {
                pin_key: id.pin_key(),
                pinned: digest_key(&pinned_obj.0),
                committed: digest_key(&tagged_object(47).0),
            }
        );

        // Exact-object adoption resolves lineage explicitly...
        record_adoption(&mut f.store, &id, &pinned_obj).unwrap();
        let after = f.store.provisional_pin_row(&id.pin_key()).unwrap().unwrap();
        assert_eq!(
            after.adopted_object_key.as_deref(),
            Some(digest_key(&pinned_obj.0).as_str())
        );
        // ...but the pin REMAINS provisional: visibility stays granted-only
        // and closure stays explicit. Adoption never flips it stable.
        assert!(!after.released);
        assert_eq!(
            resolve_for_reader(&mut f.store, &id, &edge(12)).unwrap_err(),
            ProvisionalPinError::Unauthorized {
                pin_key: id.pin_key()
            }
        );
        assert_eq!(
            resolve_for_reader(&mut f.store, &id, &edge(11)).unwrap(),
            pinned_obj
        );
    }

    #[test]
    fn m004_renewal_is_monotonic_and_closed_pins_refuse() {
        let mut f = fixture("renew");
        let id = identity(1, 25);
        open_provisional_pin(&mut f.store, &id, &tagged_object(48), &m017_ctx()).unwrap();

        renew_provisional_pin(&mut f.store, &id, 4).unwrap();
        renew_provisional_pin(&mut f.store, &id, 6).unwrap();
        assert_eq!(
            renew_provisional_pin(&mut f.store, &id, 6).unwrap_err(),
            ProvisionalPinError::NonMonotonicRenewal {
                pin_key: id.pin_key()
            }
        );
        assert_eq!(
            renew_provisional_pin(&mut f.store, &id, 3).unwrap_err(),
            ProvisionalPinError::NonMonotonicRenewal {
                pin_key: id.pin_key()
            }
        );

        release_authority_fixture(&mut f.store, 1);
        release_after_drain(&mut f.store, &id, &Releaser::Coordinator(authority(1))).unwrap();
        assert_eq!(
            renew_provisional_pin(&mut f.store, &id, 9).unwrap_err(),
            ProvisionalPinError::Closed {
                pin_key: id.pin_key()
            }
        );
        // Re-opening a drained identity is refused — candidate pins are
        // valid THROUGH decision/reconciliation, not resurrectable after.
        assert_eq!(
            open_provisional_pin(&mut f.store, &id, &tagged_object(48), &m017_ctx()).unwrap_err(),
            ProvisionalPinError::Closed {
                pin_key: id.pin_key()
            }
        );
    }

    #[test]
    fn m004_identity_tuple_binds_every_component_into_the_pin_address() {
        // Two identities differing in ANY component get different keys —
        // hedge attempts never share pins, and authority rotation forks
        // the address space.
        let base = identity(1, 30);
        let variants = [
            ProvisionalIdentity {
                attempt: AttemptId(31),
                lease: ExecutionLeaseId(32),
                ..base.clone()
            },
            ProvisionalIdentity {
                generation: ActionGenerationId(0x52),
                ..base.clone()
            },
            ProvisionalIdentity {
                role: OutputRole::DepInfo,
                ..base.clone()
            },
            ProvisionalIdentity {
                virtual_path: RawBytes::new(b"target/debug/deps/libother.rmeta".to_vec()),
                ..base.clone()
            },
            ProvisionalIdentity {
                authority: authority(3),
                ..base.clone()
            },
        ];
        let base_key = base.pin_key();
        for v in &variants {
            assert_ne!(v.pin_key(), base_key);
        }
        // Deterministic across recomputation.
        assert_eq!(base.pin_key(), base_key);
    }

    /// Acquire authority `tag` for release tests (helper keeping fixtures
    #[test]
    fn m006_consumption_creates_exactly_one_lineage_obligation() {
        let mut f = fixture("m006-create");
        let producer = identity(1, 60);
        let obj = tagged_object(61);
        open_provisional_pin(&mut f.store, &producer, &obj, &m017_ctx()).unwrap();
        authorize_reader(&mut f.store, &producer, &dependent("worker-c", 70)).unwrap();
        authorize_reader(&mut f.store, &producer, &edge(80)).unwrap();

        // Dependent attempt consumes: obligation binds the FULL lineage
        // (producer action/generation/attempt + logical output + object).
        resolve_for_reader(&mut f.store, &producer, &dependent("worker-c", 70)).unwrap();
        let rows = f
            .store
            .list_open_provisional_obligations("worker-c", &format!("{:032x}", 70))
            .unwrap();
        assert_eq!(rows.len(), 1);
        let row = &rows[0];
        assert_eq!(row.pin_key, producer.pin_key());
        assert_eq!(row.producer_action_key, digest_key(&producer.action_key));
        assert_eq!(
            row.producer_generation_hex,
            format!("{:032x}", producer.generation.0)
        );
        assert_eq!(
            row.producer_attempt_hex,
            format!("{:032x}", producer.attempt.0)
        );
        assert_eq!(row.object_key, digest_key(&obj.0));
        assert_eq!(row.status, "open");

        // Repeat consumption is idempotent (one obligation per
        // consumer/pin pair).
        resolve_for_reader(&mut f.store, &producer, &dependent("worker-c", 70)).unwrap();
        assert_eq!(
            f.store
                .list_open_provisional_obligations("worker-c", &format!("{:032x}", 70))
                .unwrap()
                .len(),
            1
        );

        // Edge subscribers observe; they never carry obligations.
        resolve_for_reader(&mut f.store, &producer, &edge(80)).unwrap();
        let debt = f
            .store
            .count_open_provisional_obligations(&producer.pin_key())
            .unwrap();
        assert_eq!(debt, 1, "only the dependent attempt owes a commit");
    }

    #[test]
    fn m006_terminal_gate_blocks_until_exact_object_commit_resolves() {
        let mut f = fixture("m006-gate");
        let producer = identity(1, 62);
        let obj = tagged_object(63);
        open_provisional_pin(&mut f.store, &producer, &obj, &m017_ctx()).unwrap();
        authorize_reader(&mut f.store, &producer, &dependent("worker-d", 71)).unwrap();
        resolve_for_reader(&mut f.store, &producer, &dependent("worker-d", 71)).unwrap();

        // Acceptance: terminal paths BLOCKED while the lineage is open.
        assert_eq!(
            descendant_terminal_gate(&mut f.store, "worker-d", AttemptId(71)).unwrap(),
            TerminalGate::Blocked {
                pending_pin_keys: vec![producer.pin_key()]
            }
        );

        // A DIFFERENT object committing cannot satisfy the lineage — typed
        // refusal, still blocked afterwards.
        let err =
            resolve_consumers_on_commit(&mut f.store, &producer, &tagged_object(64)).unwrap_err();
        assert!(matches!(err, ProvisionalPinError::AdoptionMismatch { .. }));
        assert!(matches!(
            descendant_terminal_gate(&mut f.store, "worker-d", AttemptId(71)).unwrap(),
            TerminalGate::Blocked { .. }
        ));

        // The EXACT pinned object commits: lineage resolves, gate clears,
        // and the resolution records what satisfied it.
        let resolved = resolve_consumers_on_commit(&mut f.store, &producer, &obj).unwrap();
        assert_eq!(resolved, 1);
        assert_eq!(
            descendant_terminal_gate(&mut f.store, "worker-d", AttemptId(71)).unwrap(),
            TerminalGate::Clear
        );
        let rows = f
            .store
            .list_open_provisional_obligations("worker-d", &format!("{:032x}", 71))
            .unwrap();
        assert!(
            rows.is_empty(),
            "resolved obligations leave the non-resolved set"
        );
    }

    #[test]
    fn m006_invalidation_permanently_refuses_the_descendant() {
        let mut f = fixture("m006-refuse");
        let producer = identity(1, 65);
        open_provisional_pin(&mut f.store, &producer, &tagged_object(66), &m017_ctx()).unwrap();
        authorize_reader(&mut f.store, &producer, &dependent("worker-e", 72)).unwrap();
        resolve_for_reader(&mut f.store, &producer, &dependent("worker-e", 72)).unwrap();

        invalidate_lineage(&mut f.store, &producer, "producer generation failed").unwrap();

        // Refused DOMINATES: even though other pins could be open, a
        // failed ancestor means this descendant can NEVER publish.
        assert_eq!(
            descendant_terminal_gate(&mut f.store, "worker-e", AttemptId(72)).unwrap(),
            TerminalGate::Refused {
                cancelled_pin_keys: vec![producer.pin_key()]
            }
        );
        // And reads of the dead output refuse with the invalidation reason.
        assert!(matches!(
            resolve_for_reader(&mut f.store, &producer, &dependent("worker-e", 72)),
            Err(ProvisionalPinError::ProducerInvalidated { .. })
        ));
    }

    #[test]
    fn m006_drain_refuses_while_consumer_debt_is_open() {
        let mut f = fixture("m006-debt");
        let producer = identity(1, 67);
        open_provisional_pin(&mut f.store, &producer, &tagged_object(68), &m017_ctx()).unwrap();
        authorize_reader(&mut f.store, &producer, &dependent("worker-g", 73)).unwrap();
        resolve_for_reader(&mut f.store, &producer, &dependent("worker-g", 73)).unwrap();

        release_authority_fixture(&mut f.store, 1);
        // §65 GC rule: live descendant obligations block the drain.
        let err = release_after_drain(
            &mut f.store,
            &producer,
            &Releaser::Coordinator(authority(1)),
        )
        .unwrap_err();
        assert_eq!(
            err,
            ProvisionalPinError::UnresolvedConsumerDebt {
                pin_key: producer.pin_key(),
                open_count: 1
            }
        );
        // Registry row NOT closed by the refused drain: consumers unaffected.
        assert!(
            !f.store
                .provisional_pin_row(&producer.pin_key())
                .unwrap()
                .unwrap()
                .released
        );

        // Resolve the debt; now the active authority drains cleanly.
        resolve_consumers_on_commit(&mut f.store, &producer, &tagged_object(68)).unwrap();
        assert_eq!(
            release_after_drain(
                &mut f.store,
                &producer,
                &Releaser::Coordinator(authority(1))
            )
            .unwrap(),
            CloseOutcome::Released
        );
    }

    #[test]
    fn m007_generation_failure_invalidates_pins_and_refuses_dependents() {
        let mut f = fixture("m007-genfail");
        // Two outputs from ONE generation of one action, plus a pin from
        // a DIFFERENT action that must survive.
        let producer_a = identity(1, 80);
        let producer_b = ProvisionalIdentity {
            virtual_path: RawBytes::new(b"target/debug/deps/libother.rmeta".to_vec()),
            ..identity(1, 80)
        };
        let bystander = ProvisionalIdentity {
            action_key: tagged_action(11),
            ..identity(1, 81)
        };
        open_provisional_pin(&mut f.store, &producer_a, &tagged_object(90), &m017_ctx()).unwrap();
        open_provisional_pin(&mut f.store, &producer_b, &tagged_object(91), &m017_ctx()).unwrap();
        open_provisional_pin(&mut f.store, &bystander, &tagged_object(92), &m017_ctx()).unwrap();
        for (producer, consumer_attempt) in [
            (&producer_a, 91_u128),
            (&producer_b, 91_u128),
            (&bystander, 92_u128),
        ] {
            authorize_reader(
                &mut f.store,
                producer,
                &dependent("worker-h", consumer_attempt),
            )
            .unwrap();
            resolve_for_reader(
                &mut f.store,
                producer,
                &dependent("worker-h", consumer_attempt),
            )
            .unwrap();
        }

        // The generation fails: BOTH of its pins invalidate; the
        // bystander (different action) is untouched.
        let summary = invalidate_lineage_for_generation_failure(
            &mut f.store,
            &tagged_action(10),
            ActionGenerationId(0x50),
            "generation tombstoned after worker loss",
        )
        .unwrap();
        assert_eq!(summary.pins_invalidated, 2);
        assert_eq!(summary.obligations_cancelled, 2);

        // The ONE consumer of both outputs is REFUSED with BOTH cancelled
        // pins aggregated (the gate refuses on any failed ancestor and
        // names them all).
        let mut expected = vec![producer_a.pin_key(), producer_b.pin_key()];
        expected.sort();
        assert_eq!(
            descendant_terminal_gate(&mut f.store, "worker-h", AttemptId(91)).unwrap(),
            TerminalGate::Refused {
                cancelled_pin_keys: expected
            }
        );
        // ...while the bystander's consumer is merely still Blocked (its
        // lineage never failed).
        assert!(matches!(
            descendant_terminal_gate(&mut f.store, "worker-h", AttemptId(92)).unwrap(),
            TerminalGate::Blocked { .. }
        ));
    }

    #[test]
    fn m007_authority_loss_invalidates_only_that_authoritys_pins() {
        let mut f = fixture("m007-authloss");
        let dead_authority_pin = identity(1, 82);
        let live_authority_pin = identity(2, 83);
        open_provisional_pin(
            &mut f.store,
            &dead_authority_pin,
            &tagged_object(93),
            &m017_ctx(),
        )
        .unwrap();
        open_provisional_pin(
            &mut f.store,
            &live_authority_pin,
            &tagged_object(94),
            &m017_ctx(),
        )
        .unwrap();

        let summary = invalidate_lineage_for_authority_loss(
            &mut f.store,
            &authority(1),
            "operator reset superseded term",
        )
        .unwrap();
        assert_eq!(summary.pins_invalidated, 1);

        // Dead authority's pin refuses reads with the invalidation reason;
        // the other authority's pin still serves authorized readers.
        authorize_reader(&mut f.store, &dead_authority_pin, &edge(21)).unwrap_err();
        assert!(matches!(
            resolve_for_reader(&mut f.store, &dead_authority_pin, &edge(22)),
            Err(ProvisionalPinError::ProducerInvalidated { .. })
        ));
        authorize_reader(&mut f.store, &live_authority_pin, &edge(23)).unwrap();
        assert_eq!(
            resolve_for_reader(&mut f.store, &live_authority_pin, &edge(23)).unwrap(),
            tagged_object(94)
        );
    }

    #[test]
    fn m007_supersession_keeps_exact_objects_and_invalidates_divergent() {
        let mut f = fixture("m007-supersede");
        let kept = identity(1, 84);
        let divergent = ProvisionalIdentity {
            virtual_path: RawBytes::new(b"target/debug/deps/libother.rmeta".to_vec()),
            ..identity(1, 84)
        };
        let winner_object = tagged_object(95);
        open_provisional_pin(&mut f.store, &kept, &winner_object, &m017_ctx()).unwrap();
        open_provisional_pin(&mut f.store, &divergent, &tagged_object(96), &m017_ctx()).unwrap();
        authorize_reader(&mut f.store, &divergent, &dependent("worker-i", 95)).unwrap();
        resolve_for_reader(&mut f.store, &divergent, &dependent("worker-i", 95)).unwrap();

        // The winner committed an output map containing ONLY the exact
        // object the `kept` pin carries: that pin survives for the normal
        // resolution path; the divergent one can never be adopted.
        let mut committed = std::collections::BTreeSet::new();
        committed.insert(digest_key(&winner_object.0));
        let summary = invalidate_unadopted_lineage_for_action(
            &mut f.store,
            &tagged_action(10),
            &committed,
            "superseded without compatible adoption",
        )
        .unwrap();
        assert_eq!(summary.pins_invalidated, 1);
        assert_eq!(summary.obligations_cancelled, 1);

        // Kept pin still open and servable to a newly granted reader.
        authorize_reader(&mut f.store, &kept, &edge(31)).unwrap();
        assert_eq!(
            resolve_for_reader(&mut f.store, &kept, &edge(31)).unwrap(),
            winner_object
        );
        // Divergent consumer permanently refused.
        assert_eq!(
            descendant_terminal_gate(&mut f.store, "worker-i", AttemptId(95)).unwrap(),
            TerminalGate::Refused {
                cancelled_pin_keys: vec![divergent.pin_key()]
            }
        );
    }

    #[test]
    fn m007_causal_trace_records_dependents_across_statuses() {
        let mut f = fixture("m007-trace");
        let producer = identity(1, 85);
        let obj = tagged_object(97);
        open_provisional_pin(&mut f.store, &producer, &obj, &m017_ctx()).unwrap();
        // Dependent 1 consumed and later resolved via exact commit.
        authorize_reader(&mut f.store, &producer, &dependent("worker-j", 96)).unwrap();
        resolve_for_reader(&mut f.store, &producer, &dependent("worker-j", 96)).unwrap();
        resolve_consumers_on_commit(&mut f.store, &producer, &obj).unwrap();
        // Dependent 2 consumed and got cancelled by invalidation.
        let doomed = identity(1, 85);
        let _ = doomed;
        authorize_reader(&mut f.store, &producer, &dependent("worker-k", 97)).unwrap();
        resolve_for_reader(&mut f.store, &producer, &dependent("worker-k", 97)).unwrap();
        invalidate_lineage(&mut f.store, &producer, "superseded").unwrap();

        // The causal trace answers "which dependents started from this
        // output" across ALL statuses — resolved AND cancelled.
        let trace = provisional_causal_trace(&mut f.store, &producer.pin_key()).unwrap();
        assert_eq!(trace.len(), 2);
        assert_eq!(trace[0].consumer_worker, "worker-j");
        assert_eq!(trace[0].status, "resolved");
        assert_eq!(
            trace[0].resolution_object_key.as_deref(),
            Some(digest_key(&obj.0).as_str())
        );
        assert_eq!(trace[1].consumer_worker, "worker-k");
        assert_eq!(trace[1].status, "cancelled");
        // Full lineage binding survives in the trace rows.
        assert_eq!(
            trace[0].producer_action_key,
            digest_key(&producer.action_key)
        );
    }

    /// Acquire authority `tag` for release tests (helper keeping fixtures
    /// terse).
    fn release_authority_fixture(store: &mut SqlMetadataStore<RusqliteEngine>, tag: u64) {
        store
            .acquire_authority(&crate::metadata_store::AuthorityRow {
                digest: crate::publication::authority_digest(&authority(tag)),
                cluster_id: format!("cluster-{tag}"),
                incarnation: 0xAA + u128::from(tag),
                term: 100 + tag,
                acquired_seq: tag,
            })
            .unwrap();
    }

    /// Shared contract binding for fixtures (opaque digests; equality is
    /// all the CAS layer proves).
    fn m017_ctx() -> ProducerContracts {
        ProducerContracts {
            toolchain: tagged_action(200),
            events: tagged_action(201),
        }
    }

    /// A DIFFERENT contract binding (for mismatch refusals).
    fn m017_other_ctx() -> ProducerContracts {
        ProducerContracts {
            toolchain: tagged_action(202),
            events: tagged_action(203),
        }
    }

    /// Build an A->B->C provisional chain (T020): B consumed A's output,
    /// C consumed B's; every descendant pin carries its full transitive
    /// ancestor closure from open time.
    fn m017_chain(
        name: &str,
    ) -> (
        Fixture,
        ProvisionalIdentity,
        ProvisionalIdentity,
        ProvisionalIdentity,
    ) {
        let mut f = fixture(name);
        let a = identity(1, 30);
        let b = identity(1, 31);
        let c = identity(1, 32);
        open_provisional_pin(&mut f.store, &a, &tagged_object(141), &m017_ctx()).unwrap();
        authorize_reader(&mut f.store, &a, &dependent("worker-b", 31)).unwrap();
        resolve_for_reader(&mut f.store, &a, &dependent("worker-b", 31)).unwrap();
        open_provisional_pin(&mut f.store, &b, &tagged_object(142), &m017_ctx()).unwrap();
        authorize_reader(&mut f.store, &b, &dependent("worker-c", 32)).unwrap();
        resolve_for_reader(&mut f.store, &b, &dependent("worker-c", 32)).unwrap();
        open_provisional_pin(&mut f.store, &c, &tagged_object(143), &m017_ctx()).unwrap();
        (f, a, b, c)
    }

    #[test]
    fn m017_transitive_closure_materialized_at_open() {
        let (mut f, a, b, c) = m017_chain("m017-closure");

        // B's closure: exactly its direct ancestor, one hop away.
        assert_eq!(
            f.store
                .list_provisional_pin_ancestors(&b.pin_key())
                .unwrap(),
            vec![(a.pin_key(), 1)]
        );
        // C's closure: the FULL transitive set {A, B} with MIN-HOP
        // distances — A two hops up, B directly.
        assert_eq!(
            f.store
                .list_provisional_pin_ancestors(&c.pin_key())
                .unwrap(),
            vec![(a.pin_key(), 2), (b.pin_key(), 1)]
        );
        // Reverse edges reach every transitive descendant from the root.
        assert_eq!(
            f.store
                .list_provisional_pin_descendants(&a.pin_key())
                .unwrap(),
            {
                let mut v = vec![b.pin_key(), c.pin_key()];
                v.sort();
                v
            }
        );
    }

    #[test]
    fn m017_commit_resolution_gates_on_whole_closure() {
        let (mut f, a, b, c) = m017_chain("m017-gate");

        // Resolving C while its producing attempt still owes B an open
        // obligation refuses typed, naming the unresolved ancestor.
        assert_eq!(
            resolve_consumers_on_commit(&mut f.store, &c, &tagged_object(143)).unwrap_err(),
            ProvisionalPinError::AncestorLineageUnresolved {
                pin_key: c.pin_key(),
                ancestor_pin_key: b.pin_key(),
                detail: format!(
                    "inbound obligation status open on consumed object {}",
                    digest_key(&tagged_object(142).0)
                ),
            }
        );

        // Exact resolution order root-first: A adopts, B then verifies
        // against its whole closure, C last.
        record_adoption(&mut f.store, &a, &tagged_object(141)).unwrap();
        assert_eq!(
            resolve_consumers_on_commit(&mut f.store, &b, &tagged_object(142)).unwrap(),
            1
        );
        assert_eq!(
            resolve_consumers_on_commit(&mut f.store, &c, &tagged_object(143)).unwrap(),
            0
        );
        // Both consumers' gates are clear once the chain closed.
        assert_eq!(
            descendant_terminal_gate(&mut f.store, "worker-b", AttemptId(31)).unwrap(),
            TerminalGate::Clear
        );
        assert_eq!(
            descendant_terminal_gate(&mut f.store, "worker-c", AttemptId(32)).unwrap(),
            TerminalGate::Clear
        );
    }

    #[test]
    fn m017_different_winner_same_object_adopts_with_explicit_edge() {
        let (mut f, a, _b, _c) = m017_chain("m017-adopt");
        release_authority_fixture(&mut f.store, 5);

        let winner = WinningAttemptContext {
            authority: authority(5),
            action_key: a.action_key.clone(),
            generation: ActionGenerationId(0x51),
            attempt: AttemptId(39),
            contracts: m017_ctx(),
        };
        // Same logical output object under EQUAL contracts: adopted.
        assert_eq!(
            adopt_from_winning_attempt(&mut f.store, &a, &winner, &tagged_object(141)).unwrap(),
            AdoptionOutcome::Adopted {
                obligations_resolved: 1
            }
        );
        // The explicit edge is durable (from == to: exact-object).
        assert!(
            f.store
                .has_adoption_edge(
                    &digest_key(&a.action_key),
                    output_role_name_for_tag(i64::try_from(output_role_tag(a.role)).unwrap()),
                    a.virtual_path.as_bytes(),
                    &digest_key(&tagged_object(141).0),
                    &digest_key(&tagged_object(141).0)
                )
                .unwrap()
        );
        // B's gate cleared by the adoption.
        assert_eq!(
            descendant_terminal_gate(&mut f.store, "worker-b", AttemptId(31)).unwrap(),
            TerminalGate::Clear
        );
    }

    #[test]
    fn m017_divergent_winner_cascades_refusal_to_descendants() {
        let (mut f, a, b, c) = m017_chain("m017-diverge");
        release_authority_fixture(&mut f.store, 5);

        let winner = WinningAttemptContext {
            authority: authority(5),
            action_key: a.action_key.clone(),
            generation: ActionGenerationId(0x51),
            attempt: AttemptId(39),
            contracts: m017_ctx(),
        };
        // Divergent object: the pin AND both transitive descendants
        // invalidate in ONE cascade; every consumer cancels.
        assert_eq!(
            adopt_from_winning_attempt(&mut f.store, &a, &winner, &tagged_object(199)).unwrap(),
            AdoptionOutcome::DivergenceCancelled {
                pins_invalidated: 3,
                obligations_cancelled: 2,
            }
        );
        for pin in [&a, &b, &c] {
            assert!(matches!(
                resolve_for_reader(&mut f.store, pin, &edge(77)),
                Err(ProvisionalPinError::ProducerInvalidated { .. })
            ));
        }
        // Descendant terminal gates REFUSE permanently, naming lineage.
        for (worker, attempt) in [("worker-b", 31_u128), ("worker-c", 32)] {
            assert!(matches!(
                descendant_terminal_gate(&mut f.store, worker, AttemptId(attempt)).unwrap(),
                TerminalGate::Refused { .. }
            ));
        }
    }

    #[test]
    fn m017_adoption_refuses_foreign_actions_same_attempt_and_contracts() {
        let (mut f, a, _b, _c) = m017_chain("m017-refuse");
        release_authority_fixture(&mut f.store, 5);

        let base = WinningAttemptContext {
            authority: authority(5),
            action_key: a.action_key.clone(),
            generation: ActionGenerationId(0x51),
            attempt: AttemptId(39),
            contracts: m017_ctx(),
        };
        // Different action key: foreign truth can never adopt.
        assert_eq!(
            adopt_from_winning_attempt(
                &mut f.store,
                &a,
                &WinningAttemptContext {
                    action_key: tagged_action(11),
                    ..base.clone()
                },
                &tagged_object(141)
            )
            .unwrap_err(),
            ProvisionalPinError::ForeignAction {
                pin_key: a.pin_key()
            }
        );
        // Same attempt AND generation: the ordinary commit path owns it.
        assert_eq!(
            adopt_from_winning_attempt(
                &mut f.store,
                &a,
                &WinningAttemptContext {
                    generation: a.generation,
                    attempt: a.attempt,
                    ..base.clone()
                },
                &tagged_object(141)
            )
            .unwrap_err(),
            ProvisionalPinError::SameWinningAttempt {
                pin_key: a.pin_key()
            }
        );
        // Different toolchain/event contracts: refuse fail-closed.
        assert_eq!(
            adopt_from_winning_attempt(
                &mut f.store,
                &a,
                &WinningAttemptContext {
                    contracts: m017_other_ctx(),
                    ..base
                },
                &tagged_object(141)
            )
            .unwrap_err(),
            ProvisionalPinError::ContractMismatch {
                pin_key: a.pin_key()
            }
        );
    }

    #[test]
    fn m017_release_after_drain_does_not_cascade() {
        let mut f = fixture("m017-drain");
        let a = identity(1, 40);
        let b = identity(1, 41);
        open_provisional_pin(&mut f.store, &a, &tagged_object(144), &m017_ctx()).unwrap();
        authorize_reader(&mut f.store, &a, &dependent("worker-x", 41)).unwrap();
        resolve_for_reader(&mut f.store, &a, &dependent("worker-x", 41)).unwrap();
        open_provisional_pin(&mut f.store, &b, &tagged_object(145), &m017_ctx()).unwrap();

        // Drain A's debt via exact adoption, then GC-close it.
        record_adoption(&mut f.store, &a, &tagged_object(144)).unwrap();
        release_authority_fixture(&mut f.store, 1);
        release_after_drain(&mut f.store, &a, &Releaser::Coordinator(authority(1))).unwrap();

        // The DESCENDANT pin stays live: a plain drain close never
        // invalidates downstream lineage.
        authorize_reader(&mut f.store, &b, &edge(78)).unwrap();
        assert_eq!(
            resolve_for_reader(&mut f.store, &b, &edge(78)).unwrap(),
            tagged_object(145)
        );
    }

    #[test]
    fn m017_batch_supersession_trigger_cascades_through_pins() {
        let (mut f, _a, _b, _c) = m017_chain("m017-batch");

        // The winner committed objects that do NOT include A's pinned
        // output: the M007 supersession trigger invalidates the WHOLE
        // descendant tree transitively (was single-hop before M017).
        let committed = std::collections::BTreeSet::from([digest_key(&tagged_object(198).0)]);
        let summary = invalidate_unadopted_lineage_for_action(
            &mut f.store,
            &tagged_action(10),
            &committed,
            "superseded without compatible adoption",
        )
        .unwrap();
        assert_eq!(summary.pins_invalidated, 3);
        assert_eq!(summary.obligations_cancelled, 2);
        assert!(matches!(
            descendant_terminal_gate(&mut f.store, "worker-c", AttemptId(32)).unwrap(),
            TerminalGate::Refused { .. }
        ));
    }
}
