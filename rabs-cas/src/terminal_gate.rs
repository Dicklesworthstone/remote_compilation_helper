//! Lineage-gated terminal delivery and bounded provisional-lineage
//! waiters (bead M020; invariants I44/I025; plan §87.1).
//!
//! I44: provisional metadata may unblock dependents EARLY (the pipelining
//! head — [`crate::provisional_pins::resolve_for_reader`] keeps flowing no
//! matter what this module decides), but a descendant cannot receive
//! TERMINAL SUCCESS or non-provisional final-output readiness until its
//! complete provisional ancestor closure has resolved to committed exact
//! objects.
//!
//! The delivery gate is exact per obligation: a `resolved` row satisfies
//! lineage only when its resolution object equals the consumed object;
//! anything else is foreign truth and refuses. Transitive completeness
//! composes inductively with M017 — every ancestor pin was itself gated
//! on ITS whole closure at commit-resolution time — so checking this
//! attempt's own obligation rows proves the full chain closed.
//!
//! I025/§87.1: wrappers waiting on lineage still occupy Cargo job slots,
//! so waiter admission is bounded per Cargo root on TWO axes — concurrent
//! waiter count (with producer progress slots reserved that waiters can
//! never consume) and transitive lineage depth (the wrapper's longest
//! min-hop ancestor chain). Admission returns typed refusals so the
//! frontier scheduler can fall back to full-result readiness for
//! pathological graphs instead of starving producers (R112).
//!
//! # Dependency rules
//!
//! Same as the crate: `rabs-protocol` types only; no async runtime; all
//! durable effects flow through [`RabsMetadataStore`]
//! (crate::metadata_store::RabsMetadataStore).

use crate::metadata_store::{RabsMetadataStore, StoreError};
use crate::provisional_pins::ProvisionalPinError;
use rabs_protocol::generation::AttemptId;

/// The terminal-delivery decision for one descendant attempt (I44).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TerminalDelivery {
    /// Complete transitive ancestor closure resolved to committed exact
    /// objects: terminal success and final-output readiness may proceed.
    Ready,
    /// Execution may have finished, but terminal success is WITHHELD
    /// until these producer lineages close. Early metadata keeps flowing.
    Withheld {
        /// Pins whose producer lineage is still open.
        pending_pin_keys: Vec<String>,
    },
    /// Ancestor lineage failed or resolved to foreign bytes: refused
    /// permanently; the descendant can never deliver positive terminal
    /// success.
    Refused {
        /// Pins whose lineage failed or diverged.
        refused_pin_keys: Vec<String>,
    },
}

/// Decide whether a descendant attempt may return terminal success /
/// receive final-output readiness (M020/I44).
///
/// `Refused` dominates `Withheld`: once any ancestor lineage failed or
/// resolved to foreign bytes, no amount of other closure changes the
/// outcome. A `resolved` row whose resolution object differs from the
/// consumed object is a divergence, not a satisfaction.
///
/// # Errors
/// Store failures; unknown obligation status strings (fail-closed).
pub fn lineage_gated_terminal_delivery(
    store: &mut dyn RabsMetadataStore,
    consumer_attempt: AttemptId,
) -> Result<TerminalDelivery, ProvisionalPinError> {
    let rows = store
        .list_provisional_obligations_by_attempt_all(&format!("{:032x}", consumer_attempt.0))?;
    let mut pending = Vec::new();
    let mut refused = Vec::new();
    for row in rows {
        match row.status.as_str() {
            "open" => pending.push(row.pin_key),
            "cancelled" => refused.push(row.pin_key),
            "resolved" => {
                if row.resolution_object_key.as_deref() != Some(row.object_key.as_str()) {
                    refused.push(row.pin_key);
                }
            }
            other => {
                return Err(ProvisionalPinError::Store(StoreError::Corruption(format!(
                    "obligation status {other:?}"
                ))));
            }
        }
    }
    Ok(if !refused.is_empty() {
        TerminalDelivery::Refused {
            refused_pin_keys: refused,
        }
    } else if !pending.is_empty() {
        TerminalDelivery::Withheld {
            pending_pin_keys: pending,
        }
    } else {
        TerminalDelivery::Ready
    })
}

/// The transitive-lineage depth a waiting wrapper occupies (I025): the
/// longest min-hop ancestor chain among the pins it directly consumed.
/// Zero when the attempt consumed nothing provisional.
///
/// # Errors
/// Store failures.
pub fn lineage_wait_depth(
    store: &mut dyn RabsMetadataStore,
    consumer_attempt: AttemptId,
) -> Result<u64, ProvisionalPinError> {
    let mut depth = 0u64;
    for obligation in store
        .list_open_provisional_obligations_by_attempt(&format!("{:032x}", consumer_attempt.0))?
    {
        depth = depth.max(store.provisional_pin_closure_depth(&obligation.pin_key)?);
    }
    Ok(depth)
}

/// Waiter bounds for one Cargo root (§87.1 defaults): waiters must never
/// consume every job slot, so at least one producer/progress slot stays
/// reserved, and pathological-depth graphs fall back to full-result
/// readiness rather than occupying slots indefinitely (R112).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WaiterBounds {
    /// Total provisional-lineage waiter slots per Cargo root.
    pub max_concurrent: usize,
    /// Slots reserved for producer progress; waiters can never occupy
    /// them (`max_concurrent - reserved_progress_slots` effective).
    pub reserved_progress_slots: usize,
    /// Maximum transitive lineage depth of an admitted waiter.
    pub max_lineage_depth: u64,
}

/// The transitive-lineage depth a waiting wrapper occupies (I025): one
/// hop to each directly-consumed provisional pin plus that pin's
/// deepest recorded ancestor chain. Zero when the attempt consumed
/// nothing provisional.
    }
}

/// Why a lineage-waiting wrapper could not be admitted (I025).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WaiterRefusal {
    /// The root's non-reserved waiter capacity is exhausted: stop
    /// replaying additional provisional metadata into this root and let
    /// producers drain (§87.1).
    Saturated {
        /// Cargo root key.
        root: String,
        /// Currently active waiters.
        active: usize,
        /// Effective non-reserved capacity.
        capacity: usize,
    },
    /// The wrapper's transitive lineage depth exceeds the bound:
    /// admitting it risks unbounded slot occupancy (R112).
    DepthExceeded {
        /// Cargo root key.
        root: String,
        /// Wrapper's lineage depth.
        depth: u64,
        /// Configured maximum.
        max: u64,
    },
    /// This attempt already holds an admission on the root.
    AlreadyAdmitted {
        /// Cargo root key.
        root: String,
    },
    /// The configured bounds reserve more than the total capacity.
    InvalidBounds,
}

impl std::fmt::Display for WaiterRefusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Saturated {
                root,
                active,
                capacity,
            } => write!(
                f,
                "provisional-lineage waiters saturated on root {root}: {active}/{capacity}"
            ),
            Self::DepthExceeded { root, depth, max } => {
                write!(
                    f,
                    "lineage depth {depth} exceeds bound {max} on root {root}"
                )
            }
            Self::AlreadyAdmitted { root } => {
                write!(f, "attempt already admitted as waiter on root {root}")
            }
            Self::InvalidBounds => write!(f, "reserved progress slots exceed waiter capacity"),
        }
    }
}
impl std::error::Error for WaiterRefusal {}

/// Permit for ONE admitted lineage-waiting wrapper on one Cargo root.
/// Release is EXPLICIT ([`WaiterRegistry::release`]) because the
/// coordinator drives releases from delivery/refusal events, not scope
/// exits — a dropped-but-unreleased permit leaves the slot booked, which
/// is the fail-toward-retention direction for slot accounting.
#[derive(Debug)]
pub struct WaiterPermit {
    root: String,
    attempt: u128,
    released: bool,
}

impl WaiterPermit {
    /// The Cargo root this permit waits on.
    #[must_use]
    pub fn root(&self) -> &str {
        &self.root
    }

    /// Whether the slot was already explicitly released.
    #[must_use]
    pub fn is_released(&self) -> bool {
        self.released
    }

    fn take_release(&mut self) -> Option<(String, u128)> {
        if self.released {
            None
        } else {
            self.released = true;
            Some((std::mem::take(&mut self.root), self.attempt))
        }
    }
}

#[derive(Debug, Default)]
struct RootState {
    waiters: std::collections::HashSet<u128>,
}

/// Per-Cargo-root registry of bounded provisional-lineage waiters
/// (I025). Deterministic and store-free: admission is pure capacity
/// arithmetic over caller-supplied depths.
#[derive(Debug, Default)]
pub struct WaiterRegistry {
    roots: std::collections::HashMap<String, RootState>,
    bounds: WaiterBounds,
}

impl WaiterRegistry {
    /// Registry with explicit bounds.
    #[must_use]
    pub fn new(bounds: WaiterBounds) -> Self {
        Self {
            roots: std::collections::HashMap::new(),
            bounds,
        }
    }

    /// Registry with the §87.1 default bounds.
    #[must_use]
    pub fn with_defaults() -> Self {
        Self::new(WaiterBounds::default())
    }

    fn effective_capacity(&self) -> Result<usize, WaiterRefusal> {
        self.bounds
            .max_concurrent
            .checked_sub(self.bounds.reserved_progress_slots)
            .ok_or(WaiterRefusal::InvalidBounds)
    }

    /// Admit a lineage-waiting wrapper onto a Cargo root.
    ///
    /// # Errors
    /// Typed [`WaiterRefusal`]s; never store failures (pure arithmetic).
    pub fn admit(
        &mut self,
        root: &str,
        attempt: AttemptId,
        lineage_depth: u64,
    ) -> Result<WaiterPermit, WaiterRefusal> {
        let capacity = self.effective_capacity()?;
        let state = self.roots.entry(root.to_owned()).or_default();
        if state.waiters.contains(&attempt.0) {
            return Err(WaiterRefusal::AlreadyAdmitted {
                root: root.to_owned(),
            });
        }
        if lineage_depth > self.bounds.max_lineage_depth {
            return Err(WaiterRefusal::DepthExceeded {
                root: root.to_owned(),
                depth: lineage_depth,
                max: self.bounds.max_lineage_depth,
            });
        }
        if state.waiters.len() >= capacity {
            return Err(WaiterRefusal::Saturated {
                root: root.to_owned(),
                active: state.waiters.len(),
                capacity,
            });
        }
        state.waiters.insert(attempt.0);
        Ok(WaiterPermit {
            root: root.to_owned(),
            attempt: attempt.0,
            released: false,
        })
    }

    /// Release a permit's slot (idempotent).
    pub fn release(&mut self, permit: &mut WaiterPermit) {
        if let Some((root, attempt)) = permit.take_release() {
            if let Some(state) = self.roots.get_mut(&root) {
                state.waiters.remove(&attempt);
            }
        }
    }

    /// Active waiter count for one root.
    #[must_use]
    pub fn active_waiters(&self, root: &str) -> usize {
        self.roots.get(root).map_or(0, |state| state.waiters.len())
    }
}

// ---------------------------------------------------------------------
// Tests — the M020 acceptance suite: lineage-gated terminal delivery +
// early-metadata pipelining retention + I025 bounds.
// ---------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::metadata_store::{AuthorityRow, RusqliteEngine, SqlMetadataStore, digest_key};
    use crate::provisional_pins::{
        AdoptionOutcome, ProducerContracts, ProvisionalIdentity, ProvisionalReader,
        WinningAttemptContext, adopt_from_winning_attempt, authorize_reader, open_provisional_pin,
        record_adoption, resolve_consumers_on_commit, resolve_for_reader,
    };
    use crate::publication::authority_digest;
    use rabs_protocol::authority::{ClusterId, CoordinatorAuthority};
    use rabs_protocol::generation::{ActionGenerationId, ExecutionLeaseId};
    use rabs_protocol::raw_bytes::RawBytes;
    use rabs_protocol::result_identity::{DigestAlgorithm, ObjectId, OutputRole, TypedDigest};

    const ACTION_DOMAIN: &str = "rabs.action-key.sha256.v1";

    fn tagged(tag: u8, domain: &'static str) -> TypedDigest {
        let mut bytes = [0u8; 32];
        bytes[0] = tag;
        bytes[31] = tag;
        TypedDigest {
            algorithm: DigestAlgorithm::Sha256V1,
            domain,
            bytes,
        }
    }

    fn action(tag: u8) -> TypedDigest {
        tagged(tag, ACTION_DOMAIN)
    }

    fn obj(tag: u8) -> ObjectId {
        ObjectId(tagged(tag, "rabs.object.sha256.v1"))
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

    /// Deterministic fixture identities: action 10 / generation 0x50,
    /// distinguished by attempt id only (like one workspace plane).
    fn identity(attempt_tag: u128) -> ProvisionalIdentity {
        ProvisionalIdentity {
            authority: authority(1),
            action_key: action(10),
            generation: ActionGenerationId(0x50),
            attempt: AttemptId(attempt_tag),
            lease: ExecutionLeaseId(attempt_tag + 1),
            role: OutputRole::ProvisionalMetadata,
            virtual_path: RawBytes::new(b"target/debug/deps/libfeat.rmeta".to_vec()),
        }
    }

    fn contracts() -> ProducerContracts {
        ProducerContracts {
            toolchain: action(200),
            events: action(201),
        }
    }

    fn dependent(worker: &str, attempt: u128) -> ProvisionalReader {
        ProvisionalReader::DependentAttempt {
            worker: worker.to_owned(),
            attempt: AttemptId(attempt),
        }
    }

    /// A->B->C provisional chain: C consumed B's early output, B
    /// consumed A's; every pin carries its layered min-hop closure.
    fn chain() -> (
        SqlMetadataStore<RusqliteEngine>,
        ProvisionalIdentity,
        ProvisionalIdentity,
        ProvisionalIdentity,
    ) {
        let engine = RusqliteEngine::open_in_memory().unwrap();
        let mut store = SqlMetadataStore::open(engine).unwrap();
        let a = identity(30);
        let b = identity(31);
        let c = identity(32);
        open_provisional_pin(&mut store, &a, &obj(141), &contracts()).unwrap();
        authorize_reader(&mut store, &a, &dependent("worker-b", 31)).unwrap();
        resolve_for_reader(&mut store, &a, &dependent("worker-b", 31)).unwrap();
        open_provisional_pin(&mut store, &b, &obj(142), &contracts()).unwrap();
        authorize_reader(&mut store, &b, &dependent("worker-c", 32)).unwrap();
        resolve_for_reader(&mut store, &b, &dependent("worker-c", 32)).unwrap();
        open_provisional_pin(&mut store, &c, &obj(143), &contracts()).unwrap();
        (store, a, b, c)
    }

    fn acquire_active(store: &mut SqlMetadataStore<RusqliteEngine>, tag: u64) {
        store
            .acquire_authority(&AuthorityRow {
                digest: authority_digest(&authority(tag)),
                cluster_id: format!("cluster-{tag}"),
                incarnation: 0xBB + u128::from(tag),
                term: 100 + tag,
                acquired_seq: tag,
            })
            .unwrap();
    }

    #[test]
    fn m020_terminal_success_withheld_until_closure_completes() {
        let (mut store, a, b, _c) = chain();

        // C finished executing, but B's producer lineage is still open:
        // terminal success WITHHELD, naming exactly the pending pin.
        assert_eq!(
            lineage_gated_terminal_delivery(&mut store, AttemptId(32)).unwrap(),
            TerminalDelivery::Withheld {
                pending_pin_keys: vec![b.pin_key()]
            }
        );

        // Root closes first; C remains withheld one hop up the chain.
        record_adoption(&mut store, &a, &obj(141)).unwrap();
        assert_eq!(
            lineage_gated_terminal_delivery(&mut store, AttemptId(32)).unwrap(),
            TerminalDelivery::Withheld {
                pending_pin_keys: vec![b.pin_key()]
            }
        );

        // B's commit-resolution closes its inbound debt; C goes READY —
        // and B itself was gated symmetrically on A.
        resolve_consumers_on_commit(&mut store, &b, &obj(142)).unwrap();
        assert_eq!(
            lineage_gated_terminal_delivery(&mut store, AttemptId(32)).unwrap(),
            TerminalDelivery::Ready
        );
        assert_eq!(
            lineage_gated_terminal_delivery(&mut store, AttemptId(31)).unwrap(),
            TerminalDelivery::Ready
        );
        // A consumed nothing provisional: born ready.
        assert_eq!(
            lineage_gated_terminal_delivery(&mut store, AttemptId(30)).unwrap(),
            TerminalDelivery::Ready
        );
    }

    #[test]
    fn m020_refused_dominates_after_divergent_winner_cascade() {
        let (mut store, a, b, _c) = chain();
        acquire_active(&mut store, 5);

        let winner = WinningAttemptContext {
            authority: authority(5),
            action_key: a.action_key.clone(),
            generation: ActionGenerationId(0x51),
            attempt: AttemptId(39),
            contracts: contracts(),
        };
        assert_eq!(
            adopt_from_winning_attempt(&mut store, &a, &winner, &obj(199)).unwrap(),
            AdoptionOutcome::DivergenceCancelled {
                pins_invalidated: 3,
                obligations_cancelled: 2,
            }
        );
        // Both descendants REFUSED permanently, each naming the ancestor
        // pin whose lineage failed — cancellation dominates everything.
        assert_eq!(
            lineage_gated_terminal_delivery(&mut store, AttemptId(31)).unwrap(),
            TerminalDelivery::Refused {
                refused_pin_keys: vec![a.pin_key()]
            }
        );
        assert_eq!(
            lineage_gated_terminal_delivery(&mut store, AttemptId(32)).unwrap(),
            TerminalDelivery::Refused {
                refused_pin_keys: vec![b.pin_key()]
            }
        );
    }

    #[test]
    fn m020_resolved_to_foreign_bytes_is_divergence_not_satisfaction() {
        let (mut store, _a, b, _c) = chain();
        // Simulate coordinator corruption: the STORE-level resolution
        // primitive can stamp a WRONG resolution object on B's pin (the
        // policy wrappers refuse this; the raw primitive trusts callers).
        // The gate must classify the consumer as REFUSED (foreign
        // bytes), never silently satisfied.
        store
            .resolve_provisional_obligations(&b.pin_key(), &digest_key(&obj(250).0))
            .unwrap();
        assert_eq!(
            lineage_gated_terminal_delivery(&mut store, AttemptId(32)).unwrap(),
            TerminalDelivery::Refused {
                refused_pin_keys: vec![b.pin_key()]
            }
        );
    }

    #[test]
    fn m020_early_metadata_keeps_flowing_while_terminal_withheld() {
        let (mut store, a, b, _c) = chain();
        // C is withheld on B's lineage…
        assert!(matches!(
            lineage_gated_terminal_delivery(&mut store, AttemptId(32)).unwrap(),
            TerminalDelivery::Withheld { .. }
        ));
        // …yet EARLY METADATA still flows (the I44 pipelining head):
        // new dependents resolve provisional outputs right now.
        authorize_reader(&mut store, &b, &dependent("worker-d", 44)).unwrap();
        assert_eq!(
            resolve_for_reader(&mut store, &b, &dependent("worker-d", 44)).unwrap(),
            obj(142)
        );
        authorize_reader(&mut store, &a, &dependent("worker-e", 45)).unwrap();
        assert_eq!(
            resolve_for_reader(&mut store, &a, &dependent("worker-e", 45)).unwrap(),
            obj(141)
        );
    }

    #[test]
    fn m020_waiter_count_bounded_with_producer_reserve() {
        let mut registry = WaiterRegistry::new(WaiterBounds {
            max_concurrent: 3,
            reserved_progress_slots: 1,
            max_lineage_depth: 16,
        });

        let mut p1 = registry.admit("root-1", AttemptId(1), 1).unwrap();
        registry.admit("root-1", AttemptId(2), 1).unwrap();
        assert_eq!(registry.active_waiters("root-1"), 2);

        // Capacity 3 - 1 reserved = 2 effective: the third saturates,
        // and the RESERVED slot stays producer-only under pressure.
        assert_eq!(
            registry.admit("root-1", AttemptId(3), 1).unwrap_err(),
            WaiterRefusal::Saturated {
                root: "root-1".to_owned(),
                active: 2,
                capacity: 2,
            }
        );

        // Re-admitting a live waiter refuses instead of double-booking.
        assert_eq!(
            registry.admit("root-1", AttemptId(1), 1).unwrap_err(),
            WaiterRefusal::AlreadyAdmitted {
                root: "root-1".to_owned()
            }
        );

        // Other Cargo roots are independent.
        registry.admit("root-2", AttemptId(3), 1).unwrap();

        // Release frees exactly one slot; double release is a no-op.
        registry.release(&mut p1);
        assert!(p1.is_released());
        registry.release(&mut p1);
        registry.admit("root-1", AttemptId(3), 1).unwrap();
        assert_eq!(registry.active_waiters("root-1"), 2);
    }

    #[test]
    fn m020_waiter_depth_bounded_regardless_of_capacity() {
        let mut registry = WaiterRegistry::new(WaiterBounds {
            max_concurrent: 8,
            reserved_progress_slots: 1,
            max_lineage_depth: 4,
        });
        // Empty registry: depth alone refuses (pathological graph falls
        // back to full-result readiness per §87.1).
        assert_eq!(
            registry.admit("r", AttemptId(7), 5).unwrap_err(),
            WaiterRefusal::DepthExceeded {
                root: "r".to_owned(),
                depth: 5,
                max: 4,
            }
        );
        registry.admit("r", AttemptId(7), 4).unwrap();
    }

    #[test]
    fn m020_invalid_bounds_refuse_every_admission() {
        let mut registry = WaiterRegistry::new(WaiterBounds {
            max_concurrent: 1,
            reserved_progress_slots: 2,
            max_lineage_depth: 4,
        });
        assert_eq!(
            registry.admit("r", AttemptId(1), 1).unwrap_err(),
            WaiterRefusal::InvalidBounds
        );
    }

    #[test]
    fn m020_lineage_wait_depth_tracks_transitive_chain() {
        let (mut store, _a, _b, c) = chain();
        // C consumed B, B consumed A: C's waiting depth is the two-hop
        // chain to A, not merely its direct parent.
        assert_eq!(lineage_wait_depth(&mut store, AttemptId(32)).unwrap(), 2);
        assert_eq!(lineage_wait_depth(&mut store, AttemptId(31)).unwrap(), 1);
        // A root producer waits on nothing.
        assert_eq!(lineage_wait_depth(&mut store, AttemptId(30)).unwrap(), 0);
        // The pin-level accessor agrees with the layered walk.
        assert_eq!(
            store.provisional_pin_closure_depth(&c.pin_key()).unwrap(),
            2
        );
        // Unknown pin: empty closure, zero depth (not an error).
        assert_eq!(
            store
                .provisional_pin_closure_depth(&identity(99).pin_key())
                .unwrap(),
            0
        );
    }
}
