//! Native child actions in build-script provenance (bead L008; plan
//! native-integration lane).
//!
//! A build-script (parent) action may spawn NATIVE child actions — e.g.
//! a `-sys` crate's cc compilation emitting `.a`/`.o` artifacts the
//! parent result references. Those outputs are dependencies of the
//! parent RESULT, recorded as provenance edges
//! (`parent action key → child action key`, kind `"native-child"`).
//!
//! THE GATE: the parent's result cannot COMMIT while any bound child is
//! unresolved. The coordinator binds children when the parent offer is
//! prepared; [`enforce_native_children_resolved`] runs at publication
//! admission and refuses while any binding is still `bound` (child not
//! committed). On the first admission where every child IS committed,
//! bindings flip to `satisfied` and the provenance edges are written —
//! idempotently, so retries and re-offers converge. A child that later
//! DIVERGES after the parent committed is handled by the ordinary
//! divergence machinery (H026) escalating consumers — this module only
//! owns the pre-commit ordering.
//!
//! # Dependency rules
//!
//! Same as the crate: `rabs-protocol` types only; no async runtime; all
//! durable effects flow through [`RabsMetadataStore`].

use crate::metadata_store::{RabsMetadataStore, StoreError, digest_key};
use rabs_protocol::result_identity::TypedDigest;

/// Provenance-edge kind recorded from parent to committed native child.
pub const NATIVE_CHILD_EDGE_KIND: &str = "native-child";

/// Everything the native-child layer can refuse.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NativeChildError {
    /// The named child has no committed publication: the parent cannot
    /// commit yet (L008 gate). Retry once the child commits.
    ChildUnresolved {
        /// Digest of the unresolved child action key.
        child_action_key: String,
    },
    /// Underlying store failure.
    Store(StoreError),
}

impl From<StoreError> for NativeChildError {
    fn from(value: StoreError) -> Self {
        Self::Store(value)
    }
}

impl std::fmt::Display for NativeChildError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ChildUnresolved { child_action_key } => write!(
                f,
                "native child action {child_action_key} is unresolved; \
                 parent build-script result cannot commit"
            ),
            Self::Store(e) => write!(f, "store error: {e:?}"),
        }
    }
}
impl std::error::Error for NativeChildError {}

/// Bind native child actions to a parent build-script action (L008
/// step 1). Idempotent per (parent, child); safe to re-bind on retry.
///
/// # Errors
/// Store failures.
pub fn bind_native_children(
    store: &mut dyn RabsMetadataStore,
    parent_action_key: &TypedDigest,
    child_action_keys: &[TypedDigest],
    bound_seq: u64,
) -> Result<(), NativeChildError> {
    let children: Vec<String> = child_action_keys.iter().map(digest_key).collect();
    store.bind_native_children(&digest_key(parent_action_key), &children, bound_seq)?;
    Ok(())
}

/// L008 commit gate (step 2): EVERY bound child must have a committed
/// publication. On full resolution each binding flips to `satisfied`
/// and its provenance edge (`native-child`) is written idempotently;
/// parents without bindings pass through untouched.
///
/// # Errors
/// [`NativeChildError::ChildUnresolved`] naming the FIRST unresolved
/// child (deterministic order); store failures.
pub fn enforce_native_children_resolved(
    store: &mut dyn RabsMetadataStore,
    parent_action_key: &TypedDigest,
) -> Result<(), NativeChildError> {
    let parent = digest_key(parent_action_key);
    let bindings = store.list_native_child_bindings(&parent)?;
    for (child_action_key, state) in bindings {
        match state.as_str() {
            "satisfied" => continue,
            "bound" => {
                let resolved = store
                    .published_manifest_key_str(&child_action_key)?
                    .is_some();
                if !resolved {
                    return Err(NativeChildError::ChildUnresolved {
                        child_action_key: child_action_key.clone(),
                    });
                }
                store.set_native_child_binding_state(&parent, &child_action_key, "satisfied")?;
                // Idempotent provenance edge: parent → child.
                let parent_digest = parse_digest_key(&parent)?;
                let child_digest = parse_digest_key(&child_action_key)?;
                store.add_provenance_edge(&parent_digest, &child_digest, NATIVE_CHILD_EDGE_KIND)?;
            }
            other => {
                return Err(NativeChildError::Store(StoreError::Corruption(format!(
                    "native child binding status {other:?}"
                ))));
            }
        }
    }
    Ok(())
}

fn parse_digest_key(key: &str) -> Result<TypedDigest, NativeChildError> {
    let (domain, hex) = key.split_once(':').ok_or_else(|| {
        NativeChildError::Store(StoreError::Corruption(format!("digest key {key:?}")))
    })?;
    let bytes = hex_decode(hex).ok_or_else(|| {
        NativeChildError::Store(StoreError::Corruption(format!("digest key hex {key:?}")))
    })?;
    Ok(TypedDigest {
        algorithm: rabs_protocol::result_identity::DigestAlgorithm::Sha256V1,
        domain: domain.to_owned().leak() as &'static str,
        bytes: bytes
            .try_into()
            .map_err(|_| NativeChildError::Store(StoreError::Corruption("digest length".into())))?,
    })
}

fn hex_decode(hex: &str) -> Option<Vec<u8>> {
    if !hex.len().is_multiple_of(2) {
        return None;
    }
    (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).ok())
        .collect()
}

// ---------------------------------------------------------------------
// Tests — the L008 acceptance suite: provenance edges through a -sys
// crate-shaped parent/child build.
// ---------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::metadata_store::{AuthorityRow, RusqliteEngine, SqlMetadataStore};
    use crate::publication::authority_digest;
    use rabs_protocol::authority::{ClusterId, CoordinatorAuthority};
    fn digest_of(domain: &'static str, tag: u8) -> TypedDigest {
        let mut bytes = [0u8; 32];
        bytes[0] = tag;
        bytes[31] = tag;
        TypedDigest {
            algorithm: rabs_protocol::result_identity::DigestAlgorithm::Sha256V1,
            domain,
            bytes,
        }
    }

    fn key(tag: u8) -> TypedDigest {
        digest_of("rabs.action-key.sha256.v1", tag)
    }

    fn fixture() -> SqlMetadataStore<RusqliteEngine> {
        let engine = RusqliteEngine::open_in_memory().unwrap();
        SqlMetadataStore::open(engine).unwrap()
    }

    /// Commit a minimal publication for action `tag` so the child
    /// counts as RESOLVED (mirrors serving_state::published_fixture).
    fn commit_child(store: &mut SqlMetadataStore<RusqliteEngine>, tag: u8) {
        use crate::metadata_store::{ActionEntryRow, CommitOutcome, PublicationRow, ResultKindTag};
        let coord = CoordinatorAuthority {
            cluster_id: ClusterId("c".to_owned()),
            credential_generation: 1,
            term: 101,
            incarnation_id: rabs_protocol::authority::CoordinatorIncarnationId(0xCC01),
        };
        let active = authority_digest(&coord);
        store
            .acquire_authority(&AuthorityRow {
                digest: active.clone(),
                cluster_id: "c".to_owned(),
                incarnation: 0xCC01,
                term: 101,
                acquired_seq: 1,
            })
            .unwrap();
        let action = ActionEntryRow {
            action_key: key(tag),
            key_epoch: 0,
            projection_epoch: 0,
        };
        store.upsert_action_entry(&action).unwrap();
        let generation = 10 + u128::from(tag);
        store
            .create_generation(&active, generation, &action.action_key)
            .unwrap();
        store
            .record_attempt(20 + u128::from(tag), generation, "worker-a", 5)
            .unwrap();
        let row = PublicationRow {
            action_key: action.action_key.clone(),
            descriptor_digest: digest_of("rabs.descriptor.sha256.v1", tag),
            manifest_digest: digest_of("rabs.result-manifest.sha256.v1", tag),
            evidence_digest: digest_of("rabs.evidence-bundle.sha256.v1", tag),
            winner_generation: 10 + u128::from(tag),
            winner_attempt: 20 + u128::from(tag),
            result_kind: ResultKindTag::Success,
            pin_id: u128::from(tag) + 40,
            pin_owner: "coordinator".to_owned(),
            provisional_ancestors: Vec::new(),
        };
        assert_eq!(
            store.commit_publication(&active, &row).unwrap(),
            CommitOutcome::Committed
        );
    }

    #[test]
    fn l008_unresolved_child_refuses_parent_commit() {
        let mut store = fixture();
        bind_native_children(&mut store, &key(20), &[key(21), key(22)], 5).unwrap();
        // Neither child committed: gate refuses, naming the FIRST
        // unresolved child in deterministic order.
        assert_eq!(
            enforce_native_children_resolved(&mut store, &key(20)).unwrap_err(),
            NativeChildError::ChildUnresolved {
                child_action_key: digest_key(&key(21))
            }
        );
        // Bindings stay `bound`: nothing was satisfied by the refusal.
        assert_eq!(
            store
                .list_native_child_bindings(&digest_key(&key(20)))
                .unwrap(),
            vec![
                (digest_key(&key(21)), "bound".to_owned()),
                (digest_key(&key(22)), "bound".to_owned()),
            ]
        );
    }

    #[test]
    fn l008_resolved_children_satisfy_and_write_provenance_edges() {
        let mut store = fixture();
        commit_child(&mut store, 21);
        commit_child(&mut store, 22);
        bind_native_children(&mut store, &key(20), &[key(21), key(22)], 6).unwrap();

        enforce_native_children_resolved(&mut store, &key(20)).unwrap();

        // All bindings satisfied…
        assert_eq!(
            store
                .list_native_child_bindings(&digest_key(&key(20)))
                .unwrap(),
            vec![
                (digest_key(&key(21)), "satisfied".to_owned()),
                (digest_key(&key(22)), "satisfied".to_owned()),
            ]
        );
        // …and provenance edges exist parent→child with the native kind
        // (read back through the deterministic dump).
        let snap = store.differential_snapshot().unwrap();
        let parent_k = digest_key(&key(20));
        let c21 = digest_key(&key(21));
        let c22 = digest_key(&key(22));
        assert!(snap.iter().any(|l| {
            l.contains("provenance_edges")
                && l.contains(&parent_k)
                && l.contains(&c21)
                && l.contains(NATIVE_CHILD_EDGE_KIND)
        }));
        assert!(snap.iter().any(|l| {
            l.contains("provenance_edges")
                && l.contains(&parent_k)
                && l.contains(&c22)
                && l.contains(NATIVE_CHILD_EDGE_KIND)
        }));
    }

    #[test]
    fn l008_partial_resolution_refuses_only_until_last_child_commits() {
        let mut store = fixture();
        commit_child(&mut store, 31);
        bind_native_children(&mut store, &key(30), &[key(31), key(32)], 7).unwrap();

        // First child committed, second not: still refused…
        assert_eq!(
            enforce_native_children_resolved(&mut store, &key(30)).unwrap_err(),
            NativeChildError::ChildUnresolved {
                child_action_key: digest_key(&key(32))
            }
        );
        // …then the last child lands and the SAME call now satisfies.
        commit_child(&mut store, 32);
        enforce_native_children_resolved(&mut store, &key(30)).unwrap();
        assert_eq!(
            store
                .list_native_child_bindings(&digest_key(&key(30)))
                .unwrap(),
            vec![
                (digest_key(&key(31)), "satisfied".to_owned()),
                (digest_key(&key(32)), "satisfied".to_owned()),
            ]
        );
    }

    #[test]
    fn l008_parents_without_children_pass_through() {
        let mut store = fixture();
        enforce_native_children_resolved(&mut store, &key(40)).unwrap();
    }

    #[test]
    fn l008_re_offers_converge_idempotently() {
        let mut store = fixture();
        commit_child(&mut store, 51);
        bind_native_children(&mut store, &key(50), &[key(51)], 9).unwrap();
        for _ in 0..3 {
            enforce_native_children_resolved(&mut store, &key(50)).unwrap();
        }
        // Edges are idempotent: exactly ONE provenance row despite three
        // admissions.
        let snap = store.differential_snapshot().unwrap();
        let rows = snap
            .iter()
            .filter(|l| {
                l.contains("provenance_edges")
                    && l.contains(&digest_key(&key(50)))
                    && l.contains(NATIVE_CHILD_EDGE_KIND)
            })
            .count();
        assert_eq!(rows, 1);
    }
}
