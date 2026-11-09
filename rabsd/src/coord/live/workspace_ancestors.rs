//! Current safety of committed immutable and workspace library producers.
//!
//! Physical file-generation witnesses belong to one canonical Cargo operation.
//! They are not durable serving authority. This module reuses H028's publication
//! ancestry under the coordinator's existing metadata lock, both before commit
//! and at every replay/install phase. It accepts exact committed objects only;
//! provisional adoption and a producer's positive replay samples grant nothing.

use super::{
    ActionClassRisk, CoordLive, OfferPreparedActionResult, RabsMetadataStore, ServeDecision,
    SqlValue, TypedDigest, authority_digest, digest_key, live_producer_gate, load_manifest,
    recorded_action_risk, serving_gate,
};
use rabs_cas::metadata_store::ProvisionalAncestorRow;
use rabs_cas::publication::ProvisionalAncestorRef;
use rabs_key::live_dependency::remote::RemoteDependencyOutputClass;
use rabs_key::live_dependency::workspace_dependency_cache::{
    CommittedDependencyPolicy, CommittedWorkspaceDependency,
};
use rabs_protocol::generation::AttemptAuthority;
use rabs_protocol::result_identity::{CanonicalActionResultManifest, OutputRole, ResultKind};
use std::collections::BTreeSet;
use std::time::Instant;

// Match the existing H028 admission work bound. Count every input edge, not
// just unique producers; shared ancestors do not excuse unchecked references.
const MAX_LINEAGE_EDGES: usize = 65_536;
const IMMUTABLE_LEAF_RECEIPT: &str = "rabs-committed-immutable-leaf-v1";

#[derive(Clone, Copy)]
struct ProducerPolicy {
    metadata_allowed: bool,
    domain: ProducerDomain,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum ProducerDomain {
    Workspace,
    MixedWorkspace,
    ImmutableDag,
    WorkspaceDag,
}

impl ProducerPolicy {
    const fn for_consumer(policy: CommittedDependencyPolicy) -> Self {
        let (metadata_allowed, domain) = match policy {
            CommittedDependencyPolicy::WorkspaceRlib => (false, ProducerDomain::Workspace),
            CommittedDependencyPolicy::WorkspaceMetadata => (true, ProducerDomain::Workspace),
            CommittedDependencyPolicy::MixedWorkspaceRlib => {
                (false, ProducerDomain::MixedWorkspace)
            }
            CommittedDependencyPolicy::MixedWorkspaceMetadata => {
                (true, ProducerDomain::MixedWorkspace)
            }
            CommittedDependencyPolicy::ImmutableDagRlib => (false, ProducerDomain::ImmutableDag),
            CommittedDependencyPolicy::ImmutableDagMetadata => (true, ProducerDomain::ImmutableDag),
            CommittedDependencyPolicy::WorkspaceDagRlib
            | CommittedDependencyPolicy::GeneratedWorkspaceDagRlib
            | CommittedDependencyPolicy::NativeGeneratedWorkspaceDagRlib => {
                (false, ProducerDomain::WorkspaceDag)
            }
            CommittedDependencyPolicy::WorkspaceDagMetadata
            | CommittedDependencyPolicy::GeneratedWorkspaceDagMetadata => {
                (true, ProducerDomain::WorkspaceDag)
            }
            CommittedDependencyPolicy::WorkspaceTerminalLeafMetadata
            | CommittedDependencyPolicy::WorkspaceTerminalMetadata => {
                (true, ProducerDomain::WorkspaceDag)
            }
        };
        Self {
            metadata_allowed,
            domain,
        }
    }

    const fn for_risk(risk: ActionClassRisk) -> Option<Self> {
        let policy = match risk {
            ActionClassRisk::CommittedWorkspaceRlib => CommittedDependencyPolicy::WorkspaceRlib,
            ActionClassRisk::CommittedWorkspaceMetadata => {
                CommittedDependencyPolicy::WorkspaceMetadata
            }
            ActionClassRisk::MixedWorkspaceRlib => CommittedDependencyPolicy::MixedWorkspaceRlib,
            ActionClassRisk::MixedWorkspaceMetadata => {
                CommittedDependencyPolicy::MixedWorkspaceMetadata
            }
            ActionClassRisk::ImmutableDagRlib => CommittedDependencyPolicy::ImmutableDagRlib,
            ActionClassRisk::ImmutableDagMetadata => {
                CommittedDependencyPolicy::ImmutableDagMetadata
            }
            ActionClassRisk::WorkspaceDagRlib => CommittedDependencyPolicy::WorkspaceDagRlib,
            ActionClassRisk::WorkspaceDagMetadata => {
                CommittedDependencyPolicy::WorkspaceDagMetadata
            }
            ActionClassRisk::GeneratedWorkspaceDagRlib => {
                CommittedDependencyPolicy::GeneratedWorkspaceDagRlib
            }
            ActionClassRisk::GeneratedWorkspaceDagMetadata => {
                CommittedDependencyPolicy::GeneratedWorkspaceDagMetadata
            }
            ActionClassRisk::NativeGeneratedWorkspaceDagRlib => {
                CommittedDependencyPolicy::NativeGeneratedWorkspaceDagRlib
            }
            ActionClassRisk::WorkspaceTerminalMetadata => {
                CommittedDependencyPolicy::WorkspaceTerminalMetadata
            }
            _ => return None,
        };
        Some(Self::for_consumer(policy))
    }

    fn admits_immutable_leaves(self) -> bool {
        self.domain != ProducerDomain::Workspace
    }

    fn admits_class(self, risk: ActionClassRisk) -> bool {
        let workspace = self.domain != ProducerDomain::ImmutableDag;
        let mixed = matches!(
            self.domain,
            ProducerDomain::MixedWorkspace | ProducerDomain::WorkspaceDag
        );
        let immutable_dag = matches!(
            self.domain,
            ProducerDomain::ImmutableDag | ProducerDomain::WorkspaceDag
        );
        match risk {
            ActionClassRisk::ClosedWorkspaceRlib
            | ActionClassRisk::GeneratedWorkspaceRlib
            | ActionClassRisk::NativeGeneratedWorkspaceRlib
            | ActionClassRisk::CommittedWorkspaceRlib => workspace,
            ActionClassRisk::ClosedWorkspaceMetadata
            | ActionClassRisk::GeneratedWorkspaceMetadata
            | ActionClassRisk::CommittedWorkspaceMetadata => workspace && self.metadata_allowed,
            ActionClassRisk::MixedWorkspaceRlib => mixed,
            ActionClassRisk::MixedWorkspaceMetadata => mixed && self.metadata_allowed,
            ActionClassRisk::ImmutableDagRlib => immutable_dag,
            ActionClassRisk::ImmutableDagMetadata => immutable_dag && self.metadata_allowed,
            ActionClassRisk::WorkspaceDagRlib
            | ActionClassRisk::GeneratedWorkspaceDagRlib
            | ActionClassRisk::NativeGeneratedWorkspaceDagRlib => {
                self.domain == ProducerDomain::WorkspaceDag
            }
            ActionClassRisk::WorkspaceDagMetadata
            | ActionClassRisk::GeneratedWorkspaceDagMetadata => {
                self.domain == ProducerDomain::WorkspaceDag && self.metadata_allowed
            }
            // A successful terminal check never supplies a Rust dependency,
            // even if a compiler emitted a nonempty metadata file for it.
            ActionClassRisk::WorkspaceTerminalLeafMetadata
            | ActionClassRisk::WorkspaceTerminalMetadata => false,
            _ => false,
        }
    }
}

pub(super) fn now_micros() -> i64 {
    i64::try_from(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |elapsed| elapsed.as_micros()),
    )
    .unwrap_or(i64::MAX)
}

impl CoordLive {
    /// Qualify a published immutable dependency only from the retained remote
    /// execution proof used by its verified installation owner. The durable
    /// receipt describes that exact publication; it never supplies a physical
    /// file witness or replaces current serving and ancestry checks.
    pub(crate) fn record_committed_immutable_leaf(
        &self,
        proof: &crate::coord::live_dependency::QualifiedImmutableDependencyLeaf<'_>,
        manifest_key: &str,
    ) -> Result<(), String> {
        // This can inspect retained input owners, so do it before the CAS lock.
        proof.verify()?;
        let held = self
            .authority()
            .ok_or("immutable leaf qualification has no coordinator authority")?;
        let cas = self
            .cas
            .as_ref()
            .ok_or("immutable leaf qualification has no store")?;
        let mut store = cas
            .store()
            .lock()
            .map_err(|_| "immutable leaf metadata lock is unavailable")?;
        if !self.available()
            || !store
                .active_authority()
                .map_err(store_error)?
                .is_some_and(|active| active.digest == authority_digest(&held))
        {
            return Err("immutable leaf coordinator authority changed".into());
        }
        let action_key = digest_key(proof.action_key());
        if store
            .published_manifest_key_str(&action_key)
            .map_err(store_error)?
            .as_deref()
            != Some(manifest_key)
        {
            return Err("immutable leaf has no exact committed publication".into());
        }
        let manifest = load_manifest(&mut *store, manifest_key)
            .ok_or("immutable leaf publication manifest is unavailable")?;
        if manifest.action_key != *proof.action_key()
            || manifest.canonical_descriptor_digest != *proof.descriptor_digest()
            || manifest.result_kind != ResultKind::Success
            || recorded_action_risk(&mut *store, &manifest.action_key).map_err(store_error)?
                != ActionClassRisk::LowRiskRegistry
        {
            return Err("immutable leaf differs from its retained remote action".into());
        }
        validate_immutable_library_manifest(&manifest, proof.output_class())?;
        crate::coord::native_archives::require_manifest(&mut *store, &manifest)?;
        if !store
            .list_provisional_ancestors(&action_key)
            .map_err(store_error)?
            .is_empty()
        {
            return Err("immutable dependency leaf has stored producer ancestry".into());
        }
        let standing =
            serving_gate(&mut *store, &action_key, now_micros(), 0).map_err(store_error)?;
        if standing != ServeDecision::Servable {
            return Err(format!(
                "immutable dependency leaf is not servable: {standing:?}"
            ));
        }
        if let Some(refusal) =
            live_producer_gate(&mut *store, &manifest.action_key).map_err(store_error)?
        {
            return Err(format!("immutable dependency leaf is unsafe: {refusal:?}"));
        }
        if let Some(existing) = recorded_immutable_leaf(&mut *store, &manifest, manifest_key)? {
            return if existing == proof.output_class() {
                Ok(())
            } else {
                Err("immutable leaf qualification changed execution class".into())
            };
        }
        store
            .record_decision_receipt(
                IMMUTABLE_LEAF_RECEIPT,
                &action_key,
                0,
                &immutable_leaf_decision(&manifest, manifest_key, proof.output_class()),
                "verified canonical remote immutable dependency leaf",
            )
            .map_err(store_error)
    }

    /// Check a completed terminal result without granting it producer authority.
    /// Fresh published attempts need no positive replay samples, but every
    /// adverse, class, output-object and recursive ancestry veto still applies.
    pub(crate) fn verify_terminal_completion(
        &self,
        action: &TypedDigest,
        descriptor: &TypedDigest,
        manifest_id: &TypedDigest,
        policy: CommittedDependencyPolicy,
    ) -> Result<CanonicalActionResultManifest, String> {
        let (risk, key_epoch) = match policy {
            CommittedDependencyPolicy::WorkspaceTerminalLeafMetadata => {
                (ActionClassRisk::WorkspaceTerminalLeafMetadata, 24)
            }
            CommittedDependencyPolicy::WorkspaceTerminalMetadata => {
                (ActionClassRisk::WorkspaceTerminalMetadata, 25)
            }
            _ => return Err("terminal completion has a nonterminal policy".into()),
        };
        let held = self
            .authority()
            .ok_or("terminal completion has no coordinator authority")?;
        let cas = self
            .cas
            .as_ref()
            .ok_or("terminal completion has no store")?;
        let mut store = cas
            .store()
            .lock()
            .map_err(|_| "terminal completion metadata lock is unavailable")?;
        if !self.available()
            || !store
                .active_authority()
                .map_err(store_error)?
                .is_some_and(|active| active.digest == authority_digest(&held))
        {
            return Err("terminal completion coordinator authority changed".into());
        }
        let key = digest_key(action);
        let expected_manifest = digest_key(manifest_id);
        if store
            .published_manifest_key(action)
            .map_err(store_error)?
            .as_deref()
            != Some(expected_manifest.as_str())
        {
            return Err(format!(
                "terminal completion {key} lost its exact publication"
            ));
        }
        let manifest = load_manifest(&mut *store, &expected_manifest)
            .ok_or_else(|| format!("terminal completion {key} manifest is unavailable"))?;
        if manifest.action_key != *action
            || manifest.canonical_descriptor_digest != *descriptor
            || manifest.key_epoch != key_epoch
            || manifest.result_kind != ResultKind::Success
            || recorded_action_risk(&mut *store, action).map_err(store_error)? != risk
            || manifest.logical_outputs.len() != 2
            || manifest
                .logical_outputs
                .iter()
                .filter(|output| {
                    output.role == OutputRole::ProvisionalMetadata
                        && output.virtual_path.as_bytes().ends_with(b".rmeta")
                })
                .count()
                != 1
            || manifest
                .logical_outputs
                .iter()
                .filter(|output| {
                    output.role == OutputRole::DepInfo
                        && output.virtual_path.as_bytes().ends_with(b".d")
                })
                .count()
                != 1
        {
            return Err(format!(
                "terminal completion {key} differs from its exact class or manifest"
            ));
        }
        // These are safety checks, not a new replay or a new sampling credit.
        if let Some(refusal) = live_producer_gate(&mut *store, action).map_err(store_error)? {
            return Err(format!("terminal completion {key} is unsafe: {refusal:?}"));
        }
        let standing = serving_gate(&mut *store, &key, now_micros(), 0).map_err(store_error)?;
        if standing != ServeDecision::Servable {
            return Err(format!(
                "terminal completion {key} is not servable: {standing:?}"
            ));
        }
        for output in &manifest.logical_outputs {
            if !store.query(
                "SELECT 1 FROM quarantines WHERE scope = 'logical-object' AND subject = ?1 LIMIT 1",
                &[SqlValue::Text(digest_key(&output.object.0))],
            ).map_err(store_error)?.is_empty() {
                return Err(format!("terminal completion {key} output is quarantined"));
            }
        }
        check_serving(&mut *store, action, now_micros(), 0)
            .map_err(|reason| format!("terminal completion {key} ancestry is invalid: {reason}"))?;
        Ok(manifest)
    }

    /// Check operation-owned installation witnesses against current durable
    /// producer authority. Callers still have to verify the exact physical
    /// candidate generation before and after this check.
    pub(crate) fn verify_committed_dependencies(
        &self,
        dependencies: &[CommittedWorkspaceDependency],
        consumer_policy: CommittedDependencyPolicy,
    ) -> Result<(), String> {
        let policy = ProducerPolicy::for_consumer(consumer_policy);
        let terminal_leaf =
            consumer_policy == CommittedDependencyPolicy::WorkspaceTerminalLeafMetadata;
        if (terminal_leaf && !dependencies.is_empty())
            || (!terminal_leaf && dependencies.is_empty())
            || dependencies.len() > MAX_LINEAGE_EDGES
        {
            return Err("committed workspace candidate count is outside its bound".into());
        }
        // Preserve the authority -> store lock order used during coordinator
        // startup and ordinary replay. No wrapper-supplied flag grants access.
        let held = self
            .authority()
            .ok_or("committed workspace inputs have no coordinator authority")?;
        let cas = self
            .cas
            .as_ref()
            .ok_or("committed workspace inputs have no store")?;
        let mut store = cas
            .store()
            .lock()
            .map_err(|_| "committed workspace metadata lock is unavailable")?;
        if !self.available()
            || !store
                .active_authority()
                .map_err(store_error)?
                .is_some_and(|active| active.digest == authority_digest(&held))
        {
            return Err("committed workspace coordinator authority changed".into());
        }
        let direct = dependencies
            .iter()
            .map(|input| Ancestor {
                producer: digest_key(&input.producer_action),
                role: role_name(input.role).to_owned(),
                path: input.virtual_path.as_bytes().to_vec(),
                object: digest_key(&input.object.0),
                expected: Some((
                    digest_key(&input.producer_manifest),
                    input.producer_descriptor.clone(),
                )),
                adopted: false,
            })
            .collect();
        verify_graph(&mut *store, None, direct, now_micros(), 0, None, policy)
    }
}

fn immutable_leaf_decision(
    manifest: &CanonicalActionResultManifest,
    manifest_key: &str,
    class: RemoteDependencyOutputClass,
) -> String {
    let mode = match class {
        RemoteDependencyOutputClass::Rlib => "rlib",
        RemoteDependencyOutputClass::Metadata => "metadata",
    };
    format!(
        "{mode}:{}:{manifest_key}",
        digest_key(&manifest.canonical_descriptor_digest)
    )
}

fn recorded_immutable_leaf(
    store: &mut dyn RabsMetadataStore,
    manifest: &CanonicalActionResultManifest,
    manifest_key: &str,
) -> Result<Option<RemoteDependencyOutputClass>, String> {
    let rows = store
        .query(
            "SELECT decision FROM decision_receipts WHERE kind = ?1 AND subject = ?2 AND seq = 0",
            &[
                SqlValue::Text(IMMUTABLE_LEAF_RECEIPT.to_owned()),
                SqlValue::Text(digest_key(&manifest.action_key)),
            ],
        )
        .map_err(store_error)?;
    match rows.as_slice() {
        [] => Ok(None),
        [row] => match row.as_slice() {
            [SqlValue::Text(decision)] => {
                for class in [
                    RemoteDependencyOutputClass::Rlib,
                    RemoteDependencyOutputClass::Metadata,
                ] {
                    if *decision == immutable_leaf_decision(manifest, manifest_key, class) {
                        return Ok(Some(class));
                    }
                }
                Err("immutable leaf qualification differs from its current publication".into())
            }
            _ => Err("invalid immutable leaf qualification receipt".into()),
        },
        _ => Err("ambiguous immutable leaf qualification receipt".into()),
    }
}

fn validate_immutable_library_manifest(
    manifest: &CanonicalActionResultManifest,
    class: RemoteDependencyOutputClass,
) -> Result<(), String> {
    let mut has_primary = false;
    for output in &manifest.logical_outputs {
        let path = output.virtual_path.as_bytes();
        match output.role {
            OutputRole::ProvisionalMetadata if path.ends_with(b".rmeta") => {
                has_primary |= class == RemoteDependencyOutputClass::Metadata;
            }
            OutputRole::Materializable
                if class == RemoteDependencyOutputClass::Rlib && path.ends_with(b".rlib") =>
            {
                has_primary = true;
            }
            OutputRole::DepInfo if path.ends_with(b".d") => {}
            _ => return Err("immutable leaf publication has an unsupported output".into()),
        }
    }
    if has_primary {
        Ok(())
    } else {
        Err("immutable leaf publication lacks its declared library output".into())
    }
}

pub(super) fn check_offer(
    store: &mut dyn RabsMetadataStore,
    offer: &OfferPreparedActionResult,
    now: i64,
    epoch: u64,
    lease_now: &dyn Fn() -> u64,
) -> Result<(), String> {
    let risk = recorded_action_risk(store, &offer.manifest.action_key).map_err(store_error)?;
    if matches!(
        risk,
        ActionClassRisk::GeneratedWorkspaceRlib
            | ActionClassRisk::GeneratedWorkspaceMetadata
            | ActionClassRisk::NativeGeneratedWorkspaceRlib
    ) {
        return if offer.provisional_ancestors.is_empty() {
            Ok(())
        } else {
            Err("generated workspace leaf offer contains unexpected producer ancestry".into())
        };
    }
    if risk == ActionClassRisk::WorkspaceTerminalLeafMetadata {
        return if offer.provisional_ancestors.is_empty() {
            Ok(())
        } else {
            Err("terminal leaf offer contains unexpected producer ancestry".into())
        };
    }
    let Some(policy) = ProducerPolicy::for_risk(risk) else {
        return Ok(());
    };
    if offer.provisional_ancestors.is_empty()
        || offer.provisional_ancestors.len() > MAX_LINEAGE_EDGES
    {
        return Err("committed workspace offer lacks bounded producer ancestry".into());
    }
    verify_graph(
        store,
        Some(&offer.manifest.action_key),
        offer
            .provisional_ancestors
            .iter()
            .map(Ancestor::from_ref)
            .collect(),
        now,
        epoch,
        Some((&offer.authority, lease_now)),
        policy,
    )
}

/// Called with the same store lock as preview or the following installation.
/// A missing, malformed or revoked transitive producer is a conservative miss.
pub(super) fn check_serving(
    store: &mut dyn RabsMetadataStore,
    action: &TypedDigest,
    now: i64,
    epoch: u64,
) -> Result<(), String> {
    let risk = recorded_action_risk(store, action).map_err(store_error)?;
    if matches!(
        risk,
        ActionClassRisk::GeneratedWorkspaceRlib
            | ActionClassRisk::GeneratedWorkspaceMetadata
            | ActionClassRisk::NativeGeneratedWorkspaceRlib
    ) {
        return if store
            .list_provisional_ancestors(&digest_key(action))
            .map_err(store_error)?
            .is_empty()
        {
            Ok(())
        } else {
            Err("generated workspace leaf publication contains unexpected producer ancestry".into())
        };
    }
    if risk == ActionClassRisk::WorkspaceTerminalLeafMetadata {
        return if store
            .list_provisional_ancestors(&digest_key(action))
            .map_err(store_error)?
            .is_empty()
        {
            Ok(())
        } else {
            Err("terminal leaf publication contains unexpected producer ancestry".into())
        };
    }
    let Some(policy) = ProducerPolicy::for_risk(risk) else {
        return Ok(());
    };
    let ancestors = store
        .list_provisional_ancestors(&digest_key(action))
        .map_err(store_error)?;
    if ancestors.is_empty() || ancestors.len() > MAX_LINEAGE_EDGES {
        return Err("committed workspace publication lacks bounded producer ancestry".into());
    }
    verify_graph(
        store,
        Some(action),
        ancestors.into_iter().map(Ancestor::from_row).collect(),
        now,
        epoch,
        None,
        policy,
    )
}

struct Ancestor {
    producer: String,
    role: String,
    path: Vec<u8>,
    object: String,
    // Installation witnesses bind the exact publication and descriptor, in
    // addition to the immutable action -> manifest relation checked by H028.
    expected: Option<(String, TypedDigest)>,
    adopted: bool,
}

impl Ancestor {
    fn from_ref(reference: &ProvisionalAncestorRef) -> Self {
        Self {
            producer: digest_key(&reference.producer_action_key),
            role: role_name(reference.role).to_owned(),
            path: reference.virtual_path.as_bytes().to_vec(),
            object: digest_key(&reference.consumed_object.0),
            expected: None,
            adopted: false,
        }
    }

    fn from_row(row: ProvisionalAncestorRow) -> Self {
        Self {
            producer: row.producer_action_key,
            role: row.role,
            path: row.virtual_path,
            object: row.object_key,
            expected: None,
            adopted: row.adopted,
        }
    }
}

enum Visit {
    Input(Ancestor, ProducerPolicy),
    Finished(String),
}

type LeaseCheck<'a> = (&'a AttemptAuthority, &'a dyn Fn() -> u64);

fn verify_lease(
    store: &mut dyn RabsMetadataStore,
    lease: Option<LeaseCheck<'_>>,
) -> Result<(), String> {
    if let Some((authority, now)) = lease {
        store
            .validate_attempt_lease(authority, now())
            .map_err(store_error)?;
    }
    Ok(())
}

fn verify_graph(
    store: &mut dyn RabsMetadataStore,
    consumer: Option<&TypedDigest>,
    direct: Vec<Ancestor>,
    now: i64,
    epoch: u64,
    lease: Option<LeaseCheck<'_>>,
    policy: ProducerPolicy,
) -> Result<(), String> {
    let started = Instant::now();
    let mut edges = direct.len();
    if edges > MAX_LINEAGE_EDGES {
        return Err("committed workspace ancestry exceeds admission bound".into());
    }
    let mut pending: Vec<_> = direct
        .into_iter()
        .map(|ancestor| Visit::Input(ancestor, policy))
        .collect();
    let mut active = BTreeSet::new();
    if let Some(consumer) = consumer {
        active.insert(digest_key(consumer));
    }
    let mut complete = BTreeSet::new();
    while let Some(visit) = pending.pop() {
        let (check, policy) = match visit {
            Visit::Input(check, policy) => (check, policy),
            Visit::Finished(key) => {
                active.remove(&key);
                complete.insert(key);
                continue;
            }
        };
        verify_lease(store, lease)?;
        if check.adopted {
            return Err("committed workspace ancestry contains provisional adoption".into());
        }
        if !matches!(
            check.role.as_str(),
            "materializable" | "provisional-metadata"
        ) || (check.role == "materializable" && !check.path.ends_with(b".rlib"))
            || (check.role == "provisional-metadata" && !check.path.ends_with(b".rmeta"))
        {
            return Err("committed workspace input is not an ordinary Rust artifact".into());
        }
        let manifest_key = store
            .published_manifest_key_str(&check.producer)
            .map_err(store_error)?
            .ok_or_else(|| format!("workspace producer {} is not committed", check.producer))?;
        let manifest = load_manifest(store, &manifest_key)
            .filter(|manifest| digest_key(&manifest.action_key) == check.producer)
            .ok_or_else(|| {
                format!(
                    "workspace producer {} manifest is unavailable",
                    check.producer
                )
            })?;
        verify_lease(store, lease)?;
        if manifest.result_kind != ResultKind::Success
            || check
                .expected
                .as_ref()
                .is_some_and(|(expected_manifest, descriptor)| {
                    *expected_manifest != manifest_key
                        || *descriptor != manifest.canonical_descriptor_digest
                })
            || !manifest.logical_outputs.iter().any(|output| {
                role_name(output.role) == check.role
                    && output.virtual_path.as_bytes() == check.path
                    && digest_key(&output.object.0) == check.object
            })
        {
            return Err(format!(
                "workspace producer {} does not commit the exact input",
                check.producer
            ));
        }
        if !store
            .query(
                "SELECT 1 FROM quarantines WHERE scope = 'logical-object' AND subject = ?1 LIMIT 1",
                &[SqlValue::Text(check.object)],
            )
            .map_err(store_error)?
            .is_empty()
        {
            return Err(format!(
                "workspace producer {} input is quarantined",
                check.producer
            ));
        }
        let risk = recorded_action_risk(store, &manifest.action_key).map_err(store_error)?;
        let immutable_leaf =
            if risk == ActionClassRisk::LowRiskRegistry && policy.admits_immutable_leaves() {
                let class =
                    recorded_immutable_leaf(store, &manifest, &manifest_key)?.ok_or_else(|| {
                        format!(
                            "immutable producer {} has no qualified leaf publication",
                            check.producer
                        )
                    })?;
                validate_immutable_library_manifest(&manifest, class)?;
                Some(class)
            } else {
                None
            };
        let metadata_producer = matches!(
            risk,
            ActionClassRisk::ClosedWorkspaceMetadata
                | ActionClassRisk::GeneratedWorkspaceMetadata
                | ActionClassRisk::CommittedWorkspaceMetadata
                | ActionClassRisk::MixedWorkspaceMetadata
                | ActionClassRisk::ImmutableDagMetadata
                | ActionClassRisk::WorkspaceDagMetadata
                | ActionClassRisk::GeneratedWorkspaceDagMetadata
        ) || immutable_leaf == Some(RemoteDependencyOutputClass::Metadata);
        if !(policy.admits_class(risk)
            || immutable_leaf.is_some_and(|class| {
                class == RemoteDependencyOutputClass::Rlib || policy.metadata_allowed
            }))
            || (metadata_producer && check.role != "provisional-metadata")
        {
            return Err(format!(
                "workspace producer {} lacks a closed class allowed by its consumer",
                check.producer
            ));
        }
        match risk {
            ActionClassRisk::ImmutableDagRlib => {
                validate_immutable_library_manifest(&manifest, RemoteDependencyOutputClass::Rlib)?;
            }
            ActionClassRisk::ImmutableDagMetadata => {
                validate_immutable_library_manifest(
                    &manifest,
                    RemoteDependencyOutputClass::Metadata,
                )?;
            }
            _ => {}
        }
        let current_now =
            now.saturating_add(i64::try_from(started.elapsed().as_micros()).unwrap_or(i64::MAX));
        let standing =
            serving_gate(store, &check.producer, current_now, epoch).map_err(store_error)?;
        if standing != ServeDecision::Servable {
            return Err(format!(
                "workspace producer {} is not servable: {standing:?}",
                check.producer
            ));
        }
        if let Some(refusal) =
            live_producer_gate(store, &manifest.action_key).map_err(store_error)?
        {
            return Err(format!(
                "workspace producer {} is unsafe: {refusal:?}",
                check.producer
            ));
        }
        // A retained target seed or a transitive committed producer can bypass
        // a new output-install request. Its complete publication must carry the
        // same current archive proof, even when this edge consumes only rmeta.
        crate::coord::native_archives::require_manifest(store, &manifest).map_err(|reason| {
            format!(
                "workspace producer {} native archive is unsafe: {reason}",
                check.producer
            )
        })?;
        // Validate every edge even if its producer was visited before; only the
        // expansion is shared. An active producer detects cycles, including a
        // corrupt self-reference to the consumer currently being checked.
        if active.contains(&check.producer) {
            return Err("committed workspace ancestry contains a cycle".into());
        }
        if complete.contains(&check.producer) {
            continue;
        }
        let ancestors = store
            .list_provisional_ancestors(&check.producer)
            .map_err(store_error)?;
        if (matches!(
            risk,
            ActionClassRisk::ClosedWorkspaceRlib
                | ActionClassRisk::ClosedWorkspaceMetadata
                | ActionClassRisk::GeneratedWorkspaceRlib
                | ActionClassRisk::GeneratedWorkspaceMetadata
                | ActionClassRisk::NativeGeneratedWorkspaceRlib
                | ActionClassRisk::LowRiskRegistry
        ) && !ancestors.is_empty())
            || (matches!(
                risk,
                ActionClassRisk::CommittedWorkspaceRlib
                    | ActionClassRisk::CommittedWorkspaceMetadata
                    | ActionClassRisk::MixedWorkspaceRlib
                    | ActionClassRisk::MixedWorkspaceMetadata
                    | ActionClassRisk::ImmutableDagRlib
                    | ActionClassRisk::ImmutableDagMetadata
                    | ActionClassRisk::WorkspaceDagRlib
                    | ActionClassRisk::WorkspaceDagMetadata
                    | ActionClassRisk::GeneratedWorkspaceDagRlib
                    | ActionClassRisk::GeneratedWorkspaceDagMetadata
                    | ActionClassRisk::NativeGeneratedWorkspaceDagRlib
            ) && ancestors.is_empty())
        {
            return Err(format!(
                "workspace producer {} has inconsistent class ancestry",
                check.producer
            ));
        }
        edges = edges
            .checked_add(ancestors.len())
            .filter(|count| *count <= MAX_LINEAGE_EDGES)
            .ok_or("committed workspace ancestry exceeds admission bound")?;
        active.insert(check.producer.clone());
        pending.push(Visit::Finished(check.producer));
        // Each intermediate producer retains its own class boundary. Neither
        // metadata permission nor immutable-leaf permission flows through a
        // narrower existing workspace producer.
        if let Some(producer_policy) = ProducerPolicy::for_risk(risk) {
            pending.extend(
                ancestors
                    .into_iter()
                    .map(Ancestor::from_row)
                    .map(|ancestor| Visit::Input(ancestor, producer_policy)),
            );
        }
    }
    verify_lease(store, lease)
}

const fn role_name(role: OutputRole) -> &'static str {
    match role {
        OutputRole::Materializable => "materializable",
        OutputRole::ProvisionalMetadata => "provisional-metadata",
        OutputRole::DepInfo => "dep-info",
        OutputRole::BuildScriptMetadata => "build-script-metadata",
        OutputRole::TestSideEffect => "test-side-effect",
    }
}

fn store_error(error: rabs_cas::metadata_store::StoreError) -> String {
    format!("committed workspace metadata error: {error:?}")
}

#[cfg(all(test, unix))]
pub(crate) mod tests {
    //! Real coordinator publication, verified CAS output/manifest bytes and
    //! phased delivery. Descriptor enrollment, action keys and worker evidence
    //! are explicitly synthetic fixtures, not Cargo, rustc or TLS execution.

    use super::super::metadata_replay::MetadataCallback;
    use super::super::*;
    use super::now_micros;
    use crate::janitor::store::mount_and_reconcile;
    use rabs_cas::blob_store::{DurabilityPolicy, PutLimits, put_if_absent};
    use rabs_cas::metadata_store::{ActionEntryRow, QuarantineScope, RusqliteEngine, SqlEngine};
    use rabs_cas::publication::ProvisionalAncestorRef;
    use rabs_cas::test_support::{
        install_offer_closure, offer_serving_object, sample_evidence, sample_expected_descriptor,
        tagged_digest,
    };
    use rabs_key::live_dependency::workspace_dependency_cache::{
        CommittedDependencyPolicy, CommittedWorkspaceDependency,
    };
    use rabs_protocol::generation::{ActionGenerationId, WorkerBootGeneration};
    use rabs_protocol::raw_bytes::RawBytes;
    use rabs_protocol::result_identity::{LogicalOutput, OutputRole};
    use std::cell::Cell;
    use std::os::unix::ffi::OsStrExt;

    pub(crate) struct WorkspaceLineageFixture {
        pub(crate) coord: Arc<CoordLive>,
        pub(crate) cas: Arc<LiveCas>,
        // Drop live owners before the temporary filesystem backing.
        pub(crate) root: tempfile::TempDir,
        next_generation: Cell<u128>,
    }

    impl WorkspaceLineageFixture {
        pub(crate) fn new() -> Self {
            let root = crate::test_util::private_tempdir();
            let cas = Arc::new(mount_and_reconcile(&root.path().join("cas")).unwrap());
            let coord = Arc::new(CoordLive::with_cas(Arc::clone(&cas)));
            coord
                .acquire_boot_authority("workspace-lineage-fixture")
                .unwrap();
            coord.mark_up();
            Self {
                coord,
                cas,
                root,
                next_generation: Cell::new(1),
            }
        }

        fn put(&self, bytes: &[u8]) -> ObjectId {
            let object = digest_set(bytes, DigestRequest::default(), None)
                .unwrap()
                .atp_content_id;
            put_if_absent(
                self.cas.layout(),
                &mut *self.cas.store().lock().unwrap(),
                &object,
                &mut &bytes[..],
                PutLimits::default(),
                DurabilityPolicy::FULL,
            )
            .unwrap();
            ObjectId(object)
        }

        fn enroll_attempt(&self, offer: &mut OfferPreparedActionResult) {
            let generation = self.next_generation.get();
            self.next_generation.set(generation.checked_add(1).unwrap());
            offer.authority.action_generation.generation_id = ActionGenerationId(generation);
            offer.authority.attempt_id = AttemptId(10 * generation + 1);
            offer.authority.execution_lease_id = ExecutionLeaseId(10 * generation + 2);
            offer.authority.worker_peer_id =
                PeerId(format!("workspace-lineage-worker-{generation}"));
            offer.authority.worker_boot_generation = WorkerBootGeneration(1);
            offer.authority.worker_incarnation_id = WorkerIncarnationId(generation);
            self.coord
                .admit_worker_session(&WorkerSessionOffer {
                    worker_peer_id: offer.authority.worker_peer_id.clone(),
                    boot_generation: offer.authority.worker_boot_generation,
                    incarnation: offer.authority.worker_incarnation_id,
                    reenrollment_proof: None,
                })
                .unwrap();
            {
                let mut store = self.cas.store().lock().unwrap();
                store
                    .upsert_action_entry(&ActionEntryRow {
                        action_key: offer.manifest.action_key.clone(),
                        key_epoch: offer.manifest.key_epoch,
                        projection_epoch: offer.manifest.projection_epoch,
                    })
                    .unwrap();
                store
                    .create_bound_generation(
                        &authority_digest(&offer.authority.coordinator),
                        &offer.authority.action_generation,
                        &offer.manifest.action_key,
                    )
                    .unwrap();
            }
            // Live monotonic lease admission, never an invented wall-clock lease.
            self.coord
                .admit_attempt_lease(&offer.authority, 600_000)
                .unwrap();
        }

        pub(crate) fn prepare(
            &self,
            tag: u8,
            parents: Vec<ProvisionalAncestorRef>,
            outputs: &[(&str, OutputRole, &[u8])],
        ) -> OfferPreparedActionResult {
            let class = if parents.is_empty() {
                LIVE_WORKSPACE_RLIB_CLASS
            } else {
                LIVE_COMMITTED_WORKSPACE_RLIB_CLASS
            };
            self.prepare_class(tag, parents, outputs, class)
        }

        pub(crate) fn prepare_metadata(
            &self,
            tag: u8,
            parents: Vec<ProvisionalAncestorRef>,
            outputs: &[(&str, OutputRole, &[u8])],
        ) -> OfferPreparedActionResult {
            let class = if parents.is_empty() {
                LIVE_WORKSPACE_METADATA_CLASS
            } else {
                LIVE_COMMITTED_WORKSPACE_METADATA_CLASS
            };
            self.prepare_class(tag, parents, outputs, class)
        }

        pub(crate) fn prepare_generated_leaf(
            &self,
            tag: u8,
            outputs: &[(&str, OutputRole, &[u8])],
            metadata: bool,
        ) -> OfferPreparedActionResult {
            self.prepare_class(
                tag,
                Vec::new(),
                outputs,
                if metadata {
                    LIVE_GENERATED_WORKSPACE_METADATA_CLASS
                } else {
                    LIVE_GENERATED_WORKSPACE_RLIB_CLASS
                },
            )
        }

        pub(crate) fn prepare_mixed(
            &self,
            tag: u8,
            parents: Vec<ProvisionalAncestorRef>,
            outputs: &[(&str, OutputRole, &[u8])],
            metadata: bool,
        ) -> OfferPreparedActionResult {
            assert!(!parents.is_empty());
            self.prepare_class(
                tag,
                parents,
                outputs,
                if metadata {
                    LIVE_MIXED_WORKSPACE_METADATA_CLASS
                } else {
                    LIVE_MIXED_WORKSPACE_RLIB_CLASS
                },
            )
        }

        pub(crate) fn prepare_generated_dag(
            &self,
            tag: u8,
            parents: Vec<ProvisionalAncestorRef>,
            outputs: &[(&str, OutputRole, &[u8])],
            metadata: bool,
        ) -> OfferPreparedActionResult {
            self.prepare_dag(
                tag,
                parents,
                outputs,
                if metadata {
                    CommittedDependencyPolicy::GeneratedWorkspaceDagMetadata
                } else {
                    CommittedDependencyPolicy::GeneratedWorkspaceDagRlib
                },
            )
        }

        pub(crate) fn prepare_dag(
            &self,
            tag: u8,
            parents: Vec<ProvisionalAncestorRef>,
            outputs: &[(&str, OutputRole, &[u8])],
            policy: CommittedDependencyPolicy,
        ) -> OfferPreparedActionResult {
            assert!(!parents.is_empty());
            let class = match policy {
                CommittedDependencyPolicy::ImmutableDagRlib => LIVE_IMMUTABLE_DAG_RLIB_CLASS,
                CommittedDependencyPolicy::ImmutableDagMetadata => {
                    LIVE_IMMUTABLE_DAG_METADATA_CLASS
                }
                CommittedDependencyPolicy::WorkspaceDagRlib => LIVE_WORKSPACE_DAG_RLIB_CLASS,
                CommittedDependencyPolicy::WorkspaceDagMetadata => {
                    LIVE_WORKSPACE_DAG_METADATA_CLASS
                }
                CommittedDependencyPolicy::GeneratedWorkspaceDagRlib => {
                    LIVE_GENERATED_WORKSPACE_DAG_RLIB_CLASS
                }
                CommittedDependencyPolicy::GeneratedWorkspaceDagMetadata => {
                    LIVE_GENERATED_WORKSPACE_DAG_METADATA_CLASS
                }
                CommittedDependencyPolicy::NativeGeneratedWorkspaceDagRlib => {
                    LIVE_NATIVE_GENERATED_WORKSPACE_DAG_RLIB_CLASS
                }
                _ => panic!("DAG fixture requires an independently keyed DAG policy"),
            };
            self.prepare_class(tag, parents, outputs, class)
        }

        pub(crate) fn prepare_terminal(
            &self,
            tag: u8,
            parents: Vec<ProvisionalAncestorRef>,
            outputs: &[(&str, OutputRole, &[u8])],
            policy: CommittedDependencyPolicy,
        ) -> OfferPreparedActionResult {
            let class = match policy {
                CommittedDependencyPolicy::WorkspaceTerminalLeafMetadata => {
                    LIVE_WORKSPACE_TERMINAL_LEAF_METADATA_CLASS
                }
                CommittedDependencyPolicy::WorkspaceTerminalMetadata => {
                    LIVE_WORKSPACE_TERMINAL_METADATA_CLASS
                }
                _ => panic!("terminal fixture requires an independently keyed terminal policy"),
            };
            self.prepare_class(tag, parents, outputs, class)
        }

        fn prepare_class(
            &self,
            tag: u8,
            parents: Vec<ProvisionalAncestorRef>,
            outputs: &[(&str, OutputRole, &[u8])],
            class: &str,
        ) -> OfferPreparedActionResult {
            self.prepare_class_with_key_epoch(tag, parents, outputs, class, None)
        }

        fn prepare_class_with_key_epoch(
            &self,
            tag: u8,
            parents: Vec<ProvisionalAncestorRef>,
            outputs: &[(&str, OutputRole, &[u8])],
            class: &str,
            key_epoch: Option<u32>,
        ) -> OfferPreparedActionResult {
            assert!(!outputs.is_empty());
            let logical_outputs: Vec<_> = outputs
                .iter()
                .map(|(name, role, marker)| {
                    // Rust archive arguments are model-test markers, retained
                    // byte-exact inside a structurally closed ELF/ar fixture.
                    let archive = name
                        .ends_with(".rlib")
                        .then(|| crate::test_util::closed_rlib_fixture(marker));
                    let bytes = archive.as_deref().unwrap_or(marker);
                    let object = self.put(bytes);
                    if archive.is_some() {
                        crate::test_util::record_rlib_fixture_closure(
                            &mut *self.cas.store().lock().unwrap(),
                            &object.0,
                            bytes,
                        );
                    }
                    LogicalOutput {
                        role: *role,
                        virtual_path: RawBytes::from(*name),
                        object,
                    }
                })
                .collect();
            let (base, _) =
                offer_serving_object(&self.coord.authority().unwrap(), &logical_outputs[0].object);
            let mut authority = base.authority.clone();
            authority.action_key = tagged_digest("rabs.action-key.sha256.v1", tag);
            let mut manifest = base.manifest.clone();
            manifest.action_key = authority.action_key.clone();
            manifest.key_epoch = key_epoch.unwrap_or(match class {
                LIVE_GENERATED_WORKSPACE_RLIB_CLASS => 26,
                LIVE_GENERATED_WORKSPACE_METADATA_CLASS => 27,
                LIVE_GENERATED_WORKSPACE_DAG_RLIB_CLASS => 28,
                LIVE_GENERATED_WORKSPACE_DAG_METADATA_CLASS => 29,
                LIVE_NATIVE_GENERATED_WORKSPACE_RLIB_CLASS => 30,
                LIVE_NATIVE_GENERATED_WORKSPACE_DAG_RLIB_CLASS => 31,
                LIVE_WORKSPACE_TERMINAL_LEAF_METADATA_CLASS => 24,
                LIVE_WORKSPACE_TERMINAL_METADATA_CLASS => 25,
                _ => manifest.key_epoch,
            });
            manifest.logical_outputs = logical_outputs;
            let declared: Vec<_> = manifest
                .logical_outputs
                .iter()
                .map(|output| (output.role, output.virtual_path.clone()))
                .collect();
            let build = |id: ObjectId| {
                let mut evidence = sample_evidence(&id);
                evidence.action_key = manifest.action_key.clone();
                OfferPreparedActionResult::build(
                    authority.clone(),
                    manifest.clone(),
                    id,
                    evidence,
                    base.evidence_id.clone(),
                    base.canonical_observations.clone(),
                    &declared,
                    parents.clone(),
                )
                .unwrap()
            };
            let first = build(base.manifest_id.clone());
            let bytes = encode_manifest_v1(&first.manifest);
            let mut offer = build(self.put(&bytes));
            assert_eq!(encode_manifest_v1(&offer.manifest), bytes);
            self.enroll_attempt(&mut offer);
            let mut store = self.cas.store().lock().unwrap();
            store
                .record_decision_receipt(
                    LIVE_CLASS_RECEIPT,
                    &digest_key(&offer.manifest.action_key),
                    0,
                    class,
                    "explicit synthetic workspace descriptor class for coordinator gate test",
                )
                .unwrap();
            // Output and manifest locations above contain real verified bytes;
            // only non-materialized worker/evidence closure rows are synthetic.
            install_offer_closure(&mut *store, &offer);
            offer
        }

        pub(crate) fn commit(&self, offer: &OfferPreparedActionResult) {
            assert!(matches!(
                self.coord
                    .commit_offer(offer, &sample_expected_descriptor())
                    .unwrap(),
                PublicationOutcome::Committed(_)
            ));
        }

        pub(crate) fn commit_leaf(
            &self,
            tag: u8,
            outputs: &[(&str, OutputRole, &[u8])],
        ) -> OfferPreparedActionResult {
            let offer = self.prepare(tag, Vec::new(), outputs);
            self.commit(&offer);
            offer
        }

        pub(crate) fn commit_metadata_leaf(
            &self,
            tag: u8,
            outputs: &[(&str, OutputRole, &[u8])],
        ) -> OfferPreparedActionResult {
            let offer = self.prepare_metadata(tag, Vec::new(), outputs);
            self.commit(&offer);
            offer
        }

        pub(crate) fn commit_immutable_leaf(
            &self,
            tag: u8,
            outputs: &[(&str, OutputRole, &[u8])],
            metadata: bool,
        ) -> OfferPreparedActionResult {
            let offer = self.prepare_class(tag, Vec::new(), outputs, LIVE_DEPENDENCY_CLASS);
            let class = if metadata {
                rabs_key::live_dependency::remote::RemoteDependencyOutputClass::Metadata
            } else {
                rabs_key::live_dependency::remote::RemoteDependencyOutputClass::Rlib
            };
            super::validate_immutable_library_manifest(&offer.manifest, class).unwrap();
            self.commit(&offer);
            // The input/execution qualification is explicitly synthetic here,
            // like descriptor enrollment above. Publication, exact CAS bytes,
            // current safety, ancestry and delivery exercise production code.
            self.cas
                .store()
                .lock()
                .unwrap()
                .record_decision_receipt(
                    super::IMMUTABLE_LEAF_RECEIPT,
                    &digest_key(&offer.manifest.action_key),
                    0,
                    &super::immutable_leaf_decision(
                        &offer.manifest,
                        &digest_key(&offer.manifest_id.0),
                        class,
                    ),
                    "explicit synthetic immutable leaf qualification for coordinator gate test",
                )
                .unwrap();
            offer
        }

        pub(crate) fn quarantine(&self, action: &TypedDigest) {
            self.cas
                .store()
                .lock()
                .unwrap()
                .add_quarantine(
                    QuarantineScope::ActionEntry,
                    &digest_key(action),
                    "explicit producer quarantine during lineage test",
                )
                .unwrap();
        }

        pub(crate) fn expire_archive_closure(&self, offer: &OfferPreparedActionResult) {
            let object = &offer
                .manifest
                .logical_outputs
                .iter()
                .find(|output| output.virtual_path.as_bytes().ends_with(b".rlib"))
                .unwrap()
                .object
                .0;
            let _store = self.cas.store().lock().unwrap();
            let mut engine =
                RusqliteEngine::open(&self.cas.cas_root().join("meta.sqlite")).unwrap();
            assert_eq!(
                engine
                    .execute(
                        "UPDATE decision_receipts SET kind = ?1 \
                         WHERE kind = ?2 AND subject = ?3 AND seq = 0",
                        &[
                            SqlValue::Text("native-rlib-closure-v0".into()),
                            SqlValue::Text("native-rlib-closure-v1".into()),
                            SqlValue::Text(digest_key(object)),
                        ],
                    )
                    .unwrap(),
                1,
                "expire only the selected producer archive's current proof"
            );
        }

        fn compare_twice(&self, offer: &OfferPreparedActionResult) {
            for _ in 0..2 {
                let mut comparison = offer.clone();
                self.enroll_attempt(&mut comparison);
                assert_eq!(
                    self.coord
                        .commit_offer(&comparison, &sample_expected_descriptor())
                        .unwrap(),
                    PublicationOutcome::IdempotentEvidenceAppended,
                );
            }
            assert_eq!(
                self.cas
                    .store()
                    .lock()
                    .unwrap()
                    .list_verification_samples(&offer.manifest.action_key)
                    .unwrap()
                    .len(),
                2,
            );
        }

        fn assert_unsampled(&self, offer: &OfferPreparedActionResult) {
            assert!(
                self.cas
                    .store()
                    .lock()
                    .unwrap()
                    .list_verification_samples(&offer.manifest.action_key)
                    .unwrap()
                    .is_empty()
            );
        }

        fn assert_unpublished(&self, offer: &OfferPreparedActionResult) {
            assert!(
                !self
                    .cas
                    .store()
                    .lock()
                    .unwrap()
                    .has_publication(&offer.manifest.action_key)
                    .unwrap()
            );
        }

        fn replay(
            &self,
            offer: &OfferPreparedActionResult,
            destination: &Path,
            callback: Option<&mut MetadataCallback<'_>>,
        ) -> Result<ServeOutcome, ServeError> {
            self.coord.serve_cached_result(
                &offer.manifest.action_key,
                &digest_key(&offer.manifest_id.0),
                destination,
                &expected(offer, destination),
                now_micros(),
                callback,
            )
        }
    }

    fn consumes(offer: &OfferPreparedActionResult) -> ProvisionalAncestorRef {
        let output = offer
            .manifest
            .logical_outputs
            .iter()
            .find(|output| output.role == OutputRole::ProvisionalMetadata)
            .unwrap();
        ProvisionalAncestorRef {
            producer_action_key: offer.manifest.action_key.clone(),
            role: output.role,
            virtual_path: output.virtual_path.clone(),
            consumed_object: output.object.clone(),
        }
    }

    fn witness(offer: &OfferPreparedActionResult) -> CommittedWorkspaceDependency {
        let input = consumes(offer);
        CommittedWorkspaceDependency {
            path: format!(
                "/__rabs/inputs/deps/{}",
                String::from_utf8_lossy(input.virtual_path.as_bytes())
            ),
            producer_action: input.producer_action_key,
            producer_descriptor: offer.manifest.canonical_descriptor_digest.clone(),
            producer_manifest: offer.manifest_id.0.clone(),
            role: input.role,
            virtual_path: input.virtual_path,
            object: input.consumed_object,
        }
    }

    fn expected(offer: &OfferPreparedActionResult, destination: &Path) -> ExpectedOutputs {
        ExpectedOutputs::WithDepInfo {
            paths: offer
                .manifest
                .logical_outputs
                .iter()
                .map(|output| String::from_utf8(output.virtual_path.as_bytes().to_vec()).unwrap())
                .collect(),
            mappings: vec![(
                b"/__rabs/out".to_vec(),
                destination.as_os_str().as_bytes().to_vec(),
            )],
        }
    }

    fn chain(fixture: &WorkspaceLineageFixture) -> [OfferPreparedActionResult; 3] {
        let a = fixture.commit_leaf(
            1,
            &[
                (
                    "liba.rmeta",
                    OutputRole::ProvisionalMetadata,
                    b"actual CAS metadata A",
                ),
                (
                    "liba.rlib",
                    OutputRole::Materializable,
                    b"actual CAS archive A",
                ),
            ],
        );
        let b = fixture.prepare(
            2,
            vec![consumes(&a)],
            &[
                (
                    "libb.rmeta",
                    OutputRole::ProvisionalMetadata,
                    b"actual CAS metadata B",
                ),
                (
                    "libb.rlib",
                    OutputRole::Materializable,
                    b"actual CAS archive B",
                ),
            ],
        );
        fixture.commit(&b);
        let c = fixture.prepare(
            3,
            vec![consumes(&b)],
            &[
                (
                    "libc.rmeta",
                    OutputRole::ProvisionalMetadata,
                    b"actual CAS metadata C",
                ),
                (
                    "libc.rlib",
                    OutputRole::Materializable,
                    b"actual CAS archive C",
                ),
                ("c.d", OutputRole::DepInfo, b"/__rabs/out/libc.rmeta:\n"),
            ],
        );
        fixture.commit(&c);
        [a, b, c]
    }

    #[test]
    fn native_generated_archive_producers_keep_roles_ancestry_and_current_closure() {
        for revoke_producer in [false, true] {
            let fixture = WorkspaceLineageFixture::new();
            let leaf = fixture.prepare_class(
                120,
                Vec::new(),
                &[
                    (
                        "libnative.rmeta",
                        OutputRole::ProvisionalMetadata,
                        b"native metadata",
                    ),
                    (
                        "libnative.rlib",
                        OutputRole::Materializable,
                        b"bundled native implementation",
                    ),
                ],
                LIVE_NATIVE_GENERATED_WORKSPACE_RLIB_CLASS,
            );
            assert_eq!(leaf.manifest.key_epoch, 30);
            fixture.commit(&leaf);
            let archive = leaf
                .manifest
                .logical_outputs
                .iter()
                .find(|output| output.role == OutputRole::Materializable)
                .unwrap();
            let mut archive_witness = witness(&leaf);
            archive_witness.path = format!(
                "/__rabs/inputs/deps/{}",
                String::from_utf8_lossy(archive.virtual_path.as_bytes())
            );
            archive_witness.role = archive.role;
            archive_witness.virtual_path = archive.virtual_path.clone();
            archive_witness.object = archive.object.clone();
            // This exact materializable edge catches accidental classification
            // of a native Rlib producer as metadata-only.
            fixture
                .coord
                .verify_committed_dependencies(
                    std::slice::from_ref(&archive_witness),
                    CommittedDependencyPolicy::NativeGeneratedWorkspaceDagRlib,
                )
                .unwrap();
            let archive_edge = ProvisionalAncestorRef {
                producer_action_key: leaf.manifest.action_key.clone(),
                role: archive.role,
                virtual_path: archive.virtual_path.clone(),
                consumed_object: archive.object.clone(),
            };
            let consumer = fixture.prepare_dag(
                121,
                vec![archive_edge.clone()],
                &[
                    (
                        "libconsumer.rmeta",
                        OutputRole::ProvisionalMetadata,
                        b"consumer metadata",
                    ),
                    (
                        "libconsumer.rlib",
                        OutputRole::Materializable,
                        b"native DAG consumer",
                    ),
                ],
                CommittedDependencyPolicy::NativeGeneratedWorkspaceDagRlib,
            );
            assert_eq!(consumer.manifest.key_epoch, 31);
            fixture.commit(&consumer);
            fixture.compare_twice(&consumer);
            fixture.assert_unsampled(&leaf);
            let healthy = fixture.root.path().join("native-dag-healthy");
            assert!(matches!(
                fixture.replay(&consumer, &healthy, None).unwrap(),
                ServeOutcome::Served { .. }
            ));

            let metadata_only = fixture.prepare_generated_leaf(
                122,
                &[(
                    "libmetadata.rmeta",
                    OutputRole::ProvisionalMetadata,
                    b"only metadata",
                )],
                true,
            );
            fixture.commit(&metadata_only);
            assert!(
                fixture
                    .coord
                    .verify_committed_dependencies(
                        &[witness(&metadata_only)],
                        CommittedDependencyPolicy::NativeGeneratedWorkspaceDagRlib,
                    )
                    .is_err()
            );
            let invalid_leaf = fixture.prepare_class(
                123,
                vec![archive_edge],
                &[(
                    "libinvalid.rlib",
                    OutputRole::Materializable,
                    b"invalid leaf",
                )],
                LIVE_NATIVE_GENERATED_WORKSPACE_RLIB_CLASS,
            );
            assert!(
                matches!(fixture.coord.commit_offer(&invalid_leaf, &sample_expected_descriptor()),
                Err(CommitRefusal::CommittedDependency(reason)) if reason.contains("generated workspace leaf offer"))
            );
            fixture.assert_unpublished(&invalid_leaf);
            let orphan = fixture.prepare_class(
                124,
                Vec::new(),
                &[(
                    "liborphan.rlib",
                    OutputRole::Materializable,
                    b"orphan native DAG",
                )],
                LIVE_NATIVE_GENERATED_WORKSPACE_DAG_RLIB_CLASS,
            );
            assert!(
                matches!(fixture.coord.commit_offer(&orphan, &sample_expected_descriptor()),
                Err(CommitRefusal::CommittedDependency(reason)) if reason.contains("lacks bounded producer ancestry"))
            );
            fixture.assert_unpublished(&orphan);

            if revoke_producer {
                fixture.quarantine(&leaf.manifest.action_key);
            } else {
                fixture.expire_archive_closure(&leaf);
            }
            let reason = fixture
                .coord
                .verify_committed_dependencies(
                    &[archive_witness],
                    CommittedDependencyPolicy::NativeGeneratedWorkspaceDagRlib,
                )
                .unwrap_err();
            assert!(
                reason.contains(&digest_key(&leaf.manifest.action_key)),
                "{reason}"
            );
            let refused = fixture.root.path().join("native-dag-refused");
            assert!(matches!(fixture.replay(&consumer, &refused, None).unwrap(),
                ServeOutcome::ExecutePrivately(ReplayRefusal::CommittedDependency(reason))
                    if reason.contains(&digest_key(&leaf.manifest.action_key))));
            assert!(!refused.exists());
        }
    }

    #[test]
    fn generated_workspace_leaves_keep_output_roles_origin_and_empty_ancestry() {
        for metadata in [false, true] {
            let fixture = WorkspaceLineageFixture::new();
            let mut outputs = vec![(
                "libgenerated.rmeta",
                OutputRole::ProvisionalMetadata,
                b"generated library metadata".as_slice(),
            )];
            if !metadata {
                outputs.push((
                    "libgenerated.rlib",
                    OutputRole::Materializable,
                    b"generated library implementation".as_slice(),
                ));
            }
            let leaf = fixture.prepare_generated_leaf(70, &outputs, metadata);
            assert_eq!(leaf.manifest.key_epoch, if metadata { 27 } else { 26 });
            fixture.commit(&leaf);
            fixture.assert_unsampled(&leaf);
            for (policy, allows_metadata, allows_workspace) in [
                (CommittedDependencyPolicy::WorkspaceRlib, false, true),
                (CommittedDependencyPolicy::WorkspaceMetadata, true, true),
                (CommittedDependencyPolicy::MixedWorkspaceRlib, false, true),
                (
                    CommittedDependencyPolicy::MixedWorkspaceMetadata,
                    true,
                    true,
                ),
                (CommittedDependencyPolicy::WorkspaceDagRlib, false, true),
                (CommittedDependencyPolicy::WorkspaceDagMetadata, true, true),
                (
                    CommittedDependencyPolicy::WorkspaceTerminalMetadata,
                    true,
                    true,
                ),
                (CommittedDependencyPolicy::ImmutableDagRlib, false, false),
                (CommittedDependencyPolicy::ImmutableDagMetadata, true, false),
            ] {
                let result = fixture
                    .coord
                    .verify_committed_dependencies(&[witness(&leaf)], policy);
                assert_eq!(
                    result.is_ok(),
                    allows_workspace && (!metadata || allows_metadata),
                    "metadata={metadata}, policy={policy:?}, result={result:?}"
                );
            }

            let consumer = if metadata {
                fixture.prepare_metadata(
                    71,
                    vec![consumes(&leaf)],
                    &[(
                        "libconsumer.rmeta",
                        OutputRole::ProvisionalMetadata,
                        b"consumer metadata",
                    )],
                )
            } else {
                fixture.prepare(
                    71,
                    vec![consumes(&leaf)],
                    &[
                        (
                            "libconsumer.rmeta",
                            OutputRole::ProvisionalMetadata,
                            b"consumer metadata",
                        ),
                        (
                            "libconsumer.rlib",
                            OutputRole::Materializable,
                            b"consumer archive",
                        ),
                    ],
                )
            };
            fixture.commit(&consumer);
            fixture.compare_twice(&leaf);
            fixture.compare_twice(&consumer);
            for (name, offer) in [("generated", &leaf), ("consumer", &consumer)] {
                let destination = fixture.root.path().join(format!("healthy-{name}"));
                assert!(matches!(
                    fixture.replay(offer, &destination, None).unwrap(),
                    ServeOutcome::Served { .. }
                ));
            }

            // Generated leaves cannot acquire a producer graph merely through
            // a generated class receipt, either at commit or after retention.
            let invalid = fixture.prepare_class(
                72,
                vec![consumes(&leaf)],
                &outputs,
                if metadata {
                    LIVE_GENERATED_WORKSPACE_METADATA_CLASS
                } else {
                    LIVE_GENERATED_WORKSPACE_RLIB_CLASS
                },
            );
            assert!(matches!(
                fixture.coord.commit_offer(&invalid, &sample_expected_descriptor()),
                Err(CommitRefusal::CommittedDependency(reason))
                    if reason.contains("generated workspace leaf offer")
            ));
            fixture.assert_unpublished(&invalid);

            let parent = consumes(&consumer);
            let held = fixture.cas.store().lock().unwrap();
            let mut engine =
                RusqliteEngine::open(&fixture.cas.cas_root().join("meta.sqlite")).unwrap();
            assert_eq!(
                engine.execute(
                    "INSERT INTO provisional_ancestry (consumer_action_key, producer_action_key, role, virtual_path, object_key, adopted) VALUES (?1, ?2, ?3, ?4, ?5, 0)",
                    &[
                        SqlValue::Text(digest_key(&leaf.manifest.action_key)),
                        SqlValue::Text(digest_key(&parent.producer_action_key)),
                        SqlValue::Text("provisional-metadata".into()),
                        SqlValue::Blob(parent.virtual_path.as_bytes().to_vec()),
                        SqlValue::Text(digest_key(&parent.consumed_object.0)),
                    ],
                ).unwrap(),
                1,
            );
            drop(engine);
            drop(held);
            for (name, offer, refusal) in [
                ("generated", &leaf, "generated workspace leaf publication"),
                ("consumer", &consumer, "inconsistent class ancestry"),
            ] {
                let destination = fixture.root.path().join(format!("refused-{name}"));
                assert!(matches!(
                    fixture.replay(offer, &destination, None).unwrap(),
                    ServeOutcome::ExecutePrivately(ReplayRefusal::CommittedDependency(reason))
                        if reason.contains(refusal)
                ));
                assert!(!destination.exists());
            }
        }
    }

    #[test]
    fn terminal_completion_standing_requires_exact_publication_without_positive_samples() {
        for policy in [
            CommittedDependencyPolicy::WorkspaceTerminalLeafMetadata,
            CommittedDependencyPolicy::WorkspaceTerminalMetadata,
        ] {
            let fixture = WorkspaceLineageFixture::new();
            let parents = if policy == CommittedDependencyPolicy::WorkspaceTerminalMetadata {
                let upstream = fixture.commit_metadata_leaf(
                    90,
                    &[(
                        "libupstream.rmeta",
                        OutputRole::ProvisionalMetadata,
                        b"library metadata",
                    )],
                );
                vec![consumes(&upstream)]
            } else {
                Vec::new()
            };
            let terminal = fixture.prepare_terminal(
                91,
                parents,
                &[
                    ("libterminal.rmeta", OutputRole::ProvisionalMetadata, b""),
                    (
                        "terminal.d",
                        OutputRole::DepInfo,
                        b"/__rabs/out/libterminal.rmeta:\n",
                    ),
                ],
                policy,
            );
            assert!(
                fixture
                    .coord
                    .verify_terminal_completion(
                        &terminal.manifest.action_key,
                        &terminal.manifest.canonical_descriptor_digest,
                        &terminal.manifest_id.0,
                        policy,
                    )
                    .is_err(),
                "unpublished output has no completion standing"
            );
            fixture.commit(&terminal);
            fixture.assert_unsampled(&terminal);
            fixture
                .coord
                .verify_terminal_completion(
                    &terminal.manifest.action_key,
                    &terminal.manifest.canonical_descriptor_digest,
                    &terminal.manifest_id.0,
                    policy,
                )
                .expect("a first published primary execution needs no replay samples");
            let mut descriptor = terminal.manifest.canonical_descriptor_digest.clone();
            descriptor.bytes[0] ^= 1;
            assert!(
                fixture
                    .coord
                    .verify_terminal_completion(
                        &terminal.manifest.action_key,
                        &descriptor,
                        &terminal.manifest_id.0,
                        policy,
                    )
                    .is_err()
            );
            let mut manifest = terminal.manifest_id.0.clone();
            manifest.bytes[0] ^= 1;
            assert!(
                fixture
                    .coord
                    .verify_terminal_completion(
                        &terminal.manifest.action_key,
                        &terminal.manifest.canonical_descriptor_digest,
                        &manifest,
                        policy,
                    )
                    .is_err()
            );
            let wrong = if policy == CommittedDependencyPolicy::WorkspaceTerminalMetadata {
                CommittedDependencyPolicy::WorkspaceTerminalLeafMetadata
            } else {
                CommittedDependencyPolicy::WorkspaceTerminalMetadata
            };
            assert!(
                fixture
                    .coord
                    .verify_terminal_completion(
                        &terminal.manifest.action_key,
                        &terminal.manifest.canonical_descriptor_digest,
                        &terminal.manifest_id.0,
                        wrong,
                    )
                    .is_err()
            );
        }
    }

    #[test]
    fn terminal_completion_rejects_retired_epochs_under_current_class_receipts() {
        for (policy, class, retired_epoch) in [
            (
                CommittedDependencyPolicy::WorkspaceTerminalLeafMetadata,
                LIVE_WORKSPACE_TERMINAL_LEAF_METADATA_CLASS,
                14,
            ),
            (
                CommittedDependencyPolicy::WorkspaceTerminalMetadata,
                LIVE_WORKSPACE_TERMINAL_METADATA_CLASS,
                15,
            ),
        ] {
            let fixture = WorkspaceLineageFixture::new();
            let parents = if policy == CommittedDependencyPolicy::WorkspaceTerminalMetadata {
                let upstream = fixture.commit_metadata_leaf(
                    90,
                    &[(
                        "libupstream.rmeta",
                        OutputRole::ProvisionalMetadata,
                        b"library metadata",
                    )],
                );
                vec![consumes(&upstream)]
            } else {
                Vec::new()
            };
            let outputs = [
                (
                    "libterminal.rmeta",
                    OutputRole::ProvisionalMetadata,
                    b"".as_slice(),
                ),
                (
                    "terminal.d",
                    OutputRole::DepInfo,
                    b"/__rabs/out/libterminal.rmeta:\n".as_slice(),
                ),
            ];
            let current = fixture.prepare_terminal(91, parents.clone(), &outputs, policy);
            fixture.commit(&current);
            fixture
                .coord
                .verify_terminal_completion(
                    &current.manifest.action_key,
                    &current.manifest.canonical_descriptor_digest,
                    &current.manifest_id.0,
                    policy,
                )
                .expect("current-epoch completion remains qualified");

            // Build, hash and publish an internally consistent old-epoch
            // manifest. Even a current class receipt cannot upgrade its epoch.
            let retired = fixture.prepare_class_with_key_epoch(
                92,
                parents,
                &outputs,
                class,
                Some(retired_epoch),
            );
            fixture.commit(&retired);
            assert!(
                fixture
                    .coord
                    .verify_terminal_completion(
                        &retired.manifest.action_key,
                        &retired.manifest.canonical_descriptor_digest,
                        &retired.manifest_id.0,
                        policy,
                    )
                    .unwrap_err()
                    .contains("differs from its exact class or manifest"),
                "retired epoch {retired_epoch} must not acquire v2 completion standing"
            );
        }
    }

    #[test]
    fn terminal_checks_replay_exact_outputs_without_producer_authority() {
        for committed in [false, true] {
            for bytes in [b"".as_slice(), b"nonempty terminal output".as_slice()] {
                let fixture = WorkspaceLineageFixture::new();
                let upstream = fixture.commit_metadata_leaf(
                    70,
                    &[(
                        "libupstream.rmeta",
                        OutputRole::ProvisionalMetadata,
                        b"library metadata",
                    )],
                );
                let terminal = fixture.prepare_class(
                    71,
                    if committed {
                        vec![consumes(&upstream)]
                    } else {
                        Vec::new()
                    },
                    &[
                        ("libterminal.rmeta", OutputRole::ProvisionalMetadata, bytes),
                        (
                            "terminal.d",
                            OutputRole::DepInfo,
                            b"/__rabs/out/libterminal.rmeta:\n",
                        ),
                    ],
                    if committed {
                        LIVE_WORKSPACE_TERMINAL_METADATA_CLASS
                    } else {
                        LIVE_WORKSPACE_TERMINAL_LEAF_METADATA_CLASS
                    },
                );
                fixture.commit(&terminal);
                fixture.assert_unsampled(&terminal);
                fixture.compare_twice(&terminal);
                let destination = fixture.root.path().join("terminal-result");
                assert!(matches!(
                    fixture.replay(&terminal, &destination, None).unwrap(),
                    ServeOutcome::Served { .. }
                ));
                assert_eq!(
                    std::fs::read(destination.join("libterminal.rmeta")).unwrap(),
                    bytes
                );
                assert!(destination.join("terminal.d").is_file());
                // Terminal metadata never becomes a dependency, even when it
                // is nonempty and its publication has earned replay samples.
                assert!(
                    fixture
                        .coord
                        .verify_committed_dependencies(
                            &[witness(&terminal)],
                            CommittedDependencyPolicy::WorkspaceDagMetadata,
                        )
                        .is_err()
                );
            }
        }
    }

    #[test]
    fn terminal_metadata_leaf_and_committed_ancestry_cannot_be_interchanged() {
        let fixture = WorkspaceLineageFixture::new();
        let producer = fixture.commit_metadata_leaf(
            72,
            &[(
                "libproducer.rmeta",
                OutputRole::ProvisionalMetadata,
                b"producer metadata",
            )],
        );
        let outputs = [(
            "libterminal.rmeta",
            OutputRole::ProvisionalMetadata,
            b"".as_slice(),
        )];
        let invalid_leaf = fixture.prepare_class(
            73,
            vec![consumes(&producer)],
            &outputs,
            LIVE_WORKSPACE_TERMINAL_LEAF_METADATA_CLASS,
        );
        let missing_producer = fixture.prepare_class(
            74,
            Vec::new(),
            &outputs,
            LIVE_WORKSPACE_TERMINAL_METADATA_CLASS,
        );
        for offer in [&invalid_leaf, &missing_producer] {
            assert!(matches!(
                fixture
                    .coord
                    .commit_offer(offer, &sample_expected_descriptor()),
                Err(CommitRefusal::CommittedDependency(_))
            ));
            fixture.assert_unpublished(offer);
        }
        let leaf = fixture.prepare_class(
            75,
            Vec::new(),
            &outputs,
            LIVE_WORKSPACE_TERMINAL_LEAF_METADATA_CLASS,
        );
        let dependent = fixture.prepare_class(
            76,
            vec![consumes(&producer)],
            &outputs,
            LIVE_WORKSPACE_TERMINAL_METADATA_CLASS,
        );
        for offer in [&leaf, &dependent] {
            fixture.commit(offer);
            fixture.compare_twice(offer);
            super::check_serving(
                &mut *fixture.cas.store().lock().unwrap(),
                &offer.manifest.action_key,
                now_micros(),
                // Serving uses the coordinator clock epoch, independent of
                // this terminal class's action-key schema epoch.
                0,
            )
            .unwrap();
        }
        // A persisted-row fault must not turn a producer-bearing check into a
        // leaf or let the leaf acquire invented ancestry on a later replay.
        let mut engine = RusqliteEngine::open(&fixture.cas.cas_root().join("meta.sqlite")).unwrap();
        assert_eq!(engine.execute(
            "UPDATE provisional_ancestry SET consumer_action_key = ?1 WHERE consumer_action_key = ?2",
            &[SqlValue::Text(digest_key(&leaf.manifest.action_key)),
              SqlValue::Text(digest_key(&dependent.manifest.action_key))],
        ).unwrap(), 1);
        for (index, offer) in [&leaf, &dependent].into_iter().enumerate() {
            let destination = fixture
                .root
                .path()
                .join(format!("invalid-terminal-{index}"));
            assert!(matches!(
                fixture.replay(offer, &destination, None).unwrap(),
                ServeOutcome::ExecutePrivately(ReplayRefusal::CommittedDependency(_))
            ));
            assert!(!destination.exists());
        }
    }

    #[test]
    fn terminal_metadata_rechecks_transitive_producer_revocation() {
        let fixture = WorkspaceLineageFixture::new();
        let [ancestor, _, parent] = metadata_chain(&fixture);
        let terminal = fixture.prepare_class(
            77,
            vec![consumes(&parent)],
            &[("libterminal.rmeta", OutputRole::ProvisionalMetadata, b"")],
            LIVE_WORKSPACE_TERMINAL_METADATA_CLASS,
        );
        fixture.commit(&terminal);
        fixture.compare_twice(&terminal);
        let valid = fixture.root.path().join("terminal-valid");
        assert!(matches!(
            fixture.replay(&terminal, &valid, None).unwrap(),
            ServeOutcome::Served { .. }
        ));
        fixture.quarantine(&ancestor.manifest.action_key);
        let invalid = fixture.root.path().join("terminal-revoked");
        assert!(matches!(
            fixture.replay(&terminal, &invalid, None).unwrap(),
            ServeOutcome::ExecutePrivately(ReplayRefusal::CommittedDependency(_))
        ));
        assert!(!invalid.exists());
    }

    #[test]
    fn committed_metadata_chain_keeps_archive_scope_and_rechecks_transitive_quarantine() {
        let fixture = WorkspaceLineageFixture::new();
        let [a, b, c] = metadata_chain(&fixture);
        fixture.compare_twice(&c);
        for offer in [&a, &b, &c] {
            fixture
                .coord
                .verify_committed_dependencies(
                    &[witness(offer)],
                    CommittedDependencyPolicy::WorkspaceMetadata,
                )
                .unwrap();
            assert!(
                fixture
                    .coord
                    .verify_committed_dependencies(
                        &[witness(offer)],
                        CommittedDependencyPolicy::WorkspaceRlib,
                    )
                    .is_err()
            );
        }
        let archive = fixture.prepare(
            44,
            vec![consumes(&b)],
            &[(
                "libarchive.rlib",
                OutputRole::Materializable,
                b"archive bytes",
            )],
        );
        assert!(matches!(
            fixture.coord.commit_offer(&archive, &sample_expected_descriptor()),
            Err(CommitRefusal::CommittedDependency(reason)) if reason.contains("allowed by its consumer")
        ));
        fixture.assert_unpublished(&archive);

        // The consumer's positive comparisons cannot outvote a leaf producer's
        // later quarantine, including across the intermediate metadata unit.
        fixture.quarantine(&a.manifest.action_key);
        let reason = fixture
            .coord
            .verify_committed_dependencies(
                &[witness(&c)],
                CommittedDependencyPolicy::WorkspaceMetadata,
            )
            .unwrap_err();
        assert!(
            reason.contains(&digest_key(&a.manifest.action_key)),
            "{reason}"
        );
        let destination = fixture.root.path().join("blocked-metadata-chain");
        assert!(matches!(
            fixture.replay(&c, &destination, None).unwrap(),
            ServeOutcome::ExecutePrivately(ReplayRefusal::CommittedDependency(reason))
                if reason.contains(&digest_key(&a.manifest.action_key))
        ));
        assert!(!destination.exists());
        let later = fixture.prepare_metadata(
            45,
            vec![consumes(&c)],
            &[(
                "liblater.rmeta",
                OutputRole::ProvisionalMetadata,
                b"later metadata",
            )],
        );
        assert!(matches!(
            fixture.coord.commit_offer(&later, &sample_expected_descriptor()),
            Err(CommitRefusal::CommittedDependency(reason))
                if reason.contains(&digest_key(&a.manifest.action_key))
        ));
        fixture.assert_unpublished(&later);
    }

    fn mixed_chain(
        fixture: &WorkspaceLineageFixture,
        metadata: bool,
    ) -> [OfferPreparedActionResult; 3] {
        let mut a_outputs: Vec<(&str, OutputRole, &[u8])> = vec![(
            "liba.rmeta",
            OutputRole::ProvisionalMetadata,
            b"immutable leaf metadata A",
        )];
        let mut b_outputs: Vec<(&str, OutputRole, &[u8])> = vec![(
            "libb.rmeta",
            OutputRole::ProvisionalMetadata,
            b"mixed metadata B",
        )];
        let mut c_outputs: Vec<(&str, OutputRole, &[u8])> =
            vec![("libc.rmeta", OutputRole::ProvisionalMetadata, b"metadata C")];
        if !metadata {
            a_outputs.push((
                "liba.rlib",
                OutputRole::Materializable,
                b"immutable archive A",
            ));
            b_outputs.push(("libb.rlib", OutputRole::Materializable, b"mixed archive B"));
            c_outputs.push(("libc.rlib", OutputRole::Materializable, b"mixed archive C"));
        }
        let a = fixture.commit_immutable_leaf(71, &a_outputs, metadata);
        let b = fixture.prepare_mixed(72, vec![consumes(&a)], &b_outputs, metadata);
        fixture.commit(&b);
        // A also remains visible in C's inventory. The traversal visits it
        // before expanding B, exercising repeated edges under B's own policy.
        let c = fixture.prepare_mixed(73, vec![consumes(&b), consumes(&a)], &c_outputs, metadata);
        fixture.commit(&c);
        [a, b, c]
    }

    #[test]
    fn mixed_workspace_chains_require_own_samples_and_current_immutable_leaf_safety() {
        for metadata in [false, true] {
            let fixture = WorkspaceLineageFixture::new();
            let [a, b, c] = mixed_chain(&fixture, metadata);
            let consumer = if metadata {
                CommittedDependencyPolicy::MixedWorkspaceMetadata
            } else {
                CommittedDependencyPolicy::MixedWorkspaceRlib
            };
            fixture
                .coord
                .verify_committed_dependencies(&[witness(&c)], consumer)
                .unwrap();
            for legacy in [
                CommittedDependencyPolicy::WorkspaceRlib,
                CommittedDependencyPolicy::WorkspaceMetadata,
            ] {
                for offer in [&a, &b, &c] {
                    assert!(
                        fixture
                            .coord
                            .verify_committed_dependencies(&[witness(offer)], legacy)
                            .is_err()
                    );
                }
            }
            let unsampled = fixture.root.path().join("mixed-unsampled");
            assert!(matches!(
                fixture.replay(&c, &unsampled, None).unwrap(),
                ServeOutcome::ExecutePrivately(ReplayRefusal::Sampling(
                    PrivateExecutionReason::InsufficientVerificationSamples {
                        observed: 0,
                        required: 2
                    }
                ))
            ));
            assert!(!unsampled.exists());
            fixture.compare_twice(&c);
            let destination = fixture.root.path().join("mixed-served");
            assert!(matches!(fixture.replay(&c, &destination, None).unwrap(),
                ServeOutcome::Served { files } if files.len() == if metadata { 1 } else { 2 }));
            assert_eq!(
                std::fs::read(destination.join("libc.rmeta")).unwrap(),
                b"metadata C"
            );
            if !metadata {
                assert_eq!(
                    std::fs::read(destination.join("libc.rlib")).unwrap(),
                    crate::test_util::closed_rlib_fixture(b"mixed archive C")
                );
            }
            fixture.assert_unsampled(&a);
            fixture.assert_unsampled(&b);

            fixture.quarantine(&a.manifest.action_key);
            let refused = fixture.root.path().join("mixed-revoked");
            assert!(matches!(fixture.replay(&c, &refused, None).unwrap(),
                ServeOutcome::ExecutePrivately(ReplayRefusal::CommittedDependency(reason))
                    if reason.contains(&digest_key(&a.manifest.action_key))));
            assert!(!refused.exists());
            let outputs: &[(&str, OutputRole, &[u8])] = if metadata {
                &[(
                    "libd.rmeta",
                    OutputRole::ProvisionalMetadata,
                    b"mixed metadata D",
                )]
            } else {
                &[("libd.rlib", OutputRole::Materializable, b"mixed archive D")]
            };
            let d = fixture.prepare_mixed(74, vec![consumes(&c)], outputs, metadata);
            assert!(
                matches!(fixture.coord.commit_offer(&d, &sample_expected_descriptor()),
                Err(CommitRefusal::CommittedDependency(reason)) if reason.contains(&digest_key(&a.manifest.action_key)))
            );
            fixture.assert_unpublished(&d);
        }
    }

    #[test]
    fn immutable_leaf_qualification_is_bound_to_publication_and_execution_class() {
        let fixture = WorkspaceLineageFixture::new();
        let outputs: &[(&str, OutputRole, &[u8])] = &[(
            "liba.rmeta",
            OutputRole::ProvisionalMetadata,
            b"same external metadata bytes",
        )];
        let unqualified = fixture.prepare_class(81, Vec::new(), outputs, LIVE_DEPENDENCY_CLASS);
        fixture.commit(&unqualified);
        assert!(
            fixture
                .coord
                .verify_committed_dependencies(
                    &[witness(&unqualified)],
                    CommittedDependencyPolicy::MixedWorkspaceMetadata,
                )
                .unwrap_err()
                .contains("no qualified leaf publication")
        );

        let metadata = fixture.commit_immutable_leaf(82, outputs, true);
        fixture
            .coord
            .verify_committed_dependencies(
                &[witness(&metadata)],
                CommittedDependencyPolicy::MixedWorkspaceMetadata,
            )
            .unwrap();
        assert!(
            fixture
                .coord
                .verify_committed_dependencies(
                    &[witness(&metadata)],
                    CommittedDependencyPolicy::MixedWorkspaceRlib,
                )
                .unwrap_err()
                .contains("closed class allowed")
        );
        let archive = fixture.commit_immutable_leaf(
            83,
            &[
                (
                    "liba.rmeta",
                    OutputRole::ProvisionalMetadata,
                    b"same external metadata bytes",
                ),
                (
                    "liba.rlib",
                    OutputRole::Materializable,
                    b"whole external archive",
                ),
            ],
            false,
        );
        assert_eq!(
            consumes(&metadata).consumed_object,
            consumes(&archive).consumed_object
        );
        for consumer in [
            CommittedDependencyPolicy::MixedWorkspaceMetadata,
            CommittedDependencyPolicy::MixedWorkspaceRlib,
        ] {
            fixture
                .coord
                .verify_committed_dependencies(&[witness(&archive)], consumer)
                .unwrap();
        }

        // Qualification is immutable publication evidence, not an action-only
        // flag. A valid receipt copied from a different manifest must refuse.
        let mut engine = RusqliteEngine::open(&fixture.cas.cas_root().join("meta.sqlite")).unwrap();
        assert_eq!(engine.execute(
            "UPDATE decision_receipts SET decision = ?1 WHERE kind = ?2 AND subject = ?3 AND seq = 0",
            &[
                SqlValue::Text(super::immutable_leaf_decision(&archive.manifest, &digest_key(&archive.manifest_id.0), rabs_key::live_dependency::remote::RemoteDependencyOutputClass::Rlib)),
                SqlValue::Text(super::IMMUTABLE_LEAF_RECEIPT.to_owned()),
                SqlValue::Text(digest_key(&metadata.manifest.action_key)),
            ],
        ).unwrap(), 1);
        assert!(
            fixture
                .coord
                .verify_committed_dependencies(
                    &[witness(&metadata)],
                    CommittedDependencyPolicy::MixedWorkspaceMetadata,
                )
                .unwrap_err()
                .contains("qualification differs")
        );
    }

    #[test]
    fn mixed_consumers_cannot_broaden_intermediate_legacy_workspace_producers() {
        for metadata in [false, true] {
            let fixture = WorkspaceLineageFixture::new();
            let [a, b, c] = mixed_chain(&fixture, metadata);
            fixture.compare_twice(&c);
            let held = fixture.cas.store().lock().unwrap();
            let mut engine =
                RusqliteEngine::open(&fixture.cas.cas_root().join("meta.sqlite")).unwrap();
            assert_eq!(engine.execute(
                "UPDATE decision_receipts SET decision = ?1 WHERE kind = ?2 AND subject = ?3 AND seq = 0",
                &[
                    SqlValue::Text(if metadata { LIVE_COMMITTED_WORKSPACE_METADATA_CLASS } else { LIVE_COMMITTED_WORKSPACE_RLIB_CLASS }.to_owned()),
                    SqlValue::Text(LIVE_CLASS_RECEIPT.to_owned()),
                    SqlValue::Text(digest_key(&b.manifest.action_key)),
                ],
            ).unwrap(), 1);
            drop(engine);
            drop(held);
            let consumer = if metadata {
                CommittedDependencyPolicy::MixedWorkspaceMetadata
            } else {
                CommittedDependencyPolicy::MixedWorkspaceRlib
            };
            let reason = fixture
                .coord
                .verify_committed_dependencies(&[witness(&c)], consumer)
                .unwrap_err();
            assert!(reason.contains("allowed by its consumer"), "{reason}");
            assert!(
                reason.contains(&digest_key(&a.manifest.action_key)),
                "{reason}"
            );
            let destination = fixture.root.path().join("mixed-narrow-intermediate");
            assert!(matches!(fixture.replay(&c, &destination, None).unwrap(),
                ServeOutcome::ExecutePrivately(ReplayRefusal::CommittedDependency(reason))
                    if reason.contains(&digest_key(&a.manifest.action_key))));
            assert!(!destination.exists());
        }
    }

    #[test]
    fn qualified_immutable_leaf_never_hides_nonempty_producer_ancestry() {
        let fixture = WorkspaceLineageFixture::new();
        let [a, b, c] = mixed_chain(&fixture, true);
        fixture.compare_twice(&c);
        let parent = consumes(&b);
        let held = fixture.cas.store().lock().unwrap();
        let mut engine = RusqliteEngine::open(&fixture.cas.cas_root().join("meta.sqlite")).unwrap();
        assert_eq!(engine.execute(
            "INSERT INTO provisional_ancestry (consumer_action_key, producer_action_key, role, virtual_path, object_key, adopted) VALUES (?1, ?2, ?3, ?4, ?5, 0)",
            &[
                SqlValue::Text(digest_key(&a.manifest.action_key)),
                SqlValue::Text(digest_key(&parent.producer_action_key)),
                SqlValue::Text("provisional-metadata".to_owned()),
                SqlValue::Blob(parent.virtual_path.as_bytes().to_vec()),
                SqlValue::Text(digest_key(&parent.consumed_object.0)),
            ],
        ).unwrap(), 1);
        drop(engine);
        drop(held);
        let reason = fixture
            .coord
            .verify_committed_dependencies(
                &[witness(&a)],
                CommittedDependencyPolicy::MixedWorkspaceMetadata,
            )
            .unwrap_err();
        assert!(reason.contains("inconsistent class ancestry"), "{reason}");
        let destination = fixture.root.path().join("nonleaf-external-refused");
        assert!(matches!(fixture.replay(&c, &destination, None).unwrap(),
            ServeOutcome::ExecutePrivately(ReplayRefusal::CommittedDependency(reason))
                if reason.contains("inconsistent class ancestry")));
        assert!(!destination.exists());
    }

    fn immutable_dag_chain(
        fixture: &WorkspaceLineageFixture,
        metadata: bool,
    ) -> [OfferPreparedActionResult; 4] {
        let outputs =
            |metadata_name: &'static str, archive_name: &'static str, bytes: &'static [u8]| {
                let mut result = vec![(metadata_name, OutputRole::ProvisionalMetadata, bytes)];
                if !metadata {
                    result.push((archive_name, OutputRole::Materializable, bytes));
                }
                result
            };
        let immutable_policy = if metadata {
            CommittedDependencyPolicy::ImmutableDagMetadata
        } else {
            CommittedDependencyPolicy::ImmutableDagRlib
        };
        let workspace_policy = if metadata {
            CommittedDependencyPolicy::WorkspaceDagMetadata
        } else {
            CommittedDependencyPolicy::WorkspaceDagRlib
        };
        let a = fixture.commit_immutable_leaf(
            101,
            &outputs("liba.rmeta", "liba.rlib", b"immutable root A"),
            metadata,
        );
        let b = fixture.prepare_dag(
            102,
            vec![consumes(&a)],
            &outputs("libb.rmeta", "libb.rlib", b"immutable middle B"),
            immutable_policy,
        );
        fixture.commit(&b);
        let c = fixture.prepare_dag(
            103,
            vec![consumes(&b), consumes(&a)],
            &outputs("libc.rmeta", "libc.rlib", b"workspace middle C"),
            workspace_policy,
        );
        fixture.commit(&c);
        let d = fixture.prepare_dag(
            104,
            vec![consumes(&c), consumes(&b), consumes(&a)],
            &outputs("libd.rmeta", "libd.rlib", b"metadata D"),
            workspace_policy,
        );
        fixture.commit(&d);
        [a, b, c, d]
    }

    #[test]
    fn metadata_selected_dag_edges_require_every_producers_current_archive_closure() {
        let fixture = WorkspaceLineageFixture::new();
        let [a, _b, _c, d] = immutable_dag_chain(&fixture, false);
        let selected = witness(&d);
        assert_eq!(selected.role, OutputRole::ProvisionalMetadata);
        fixture
            .coord
            .verify_committed_dependencies(
                std::slice::from_ref(&selected),
                CommittedDependencyPolicy::WorkspaceDagRlib,
            )
            .unwrap();
        fixture.compare_twice(&d);
        let healthy = fixture.root.path().join("current-archive-closure");
        assert!(matches!(
            fixture.replay(&d, &healthy, None).unwrap(),
            ServeOutcome::Served { .. }
        ));

        // Only the immutable root archive's receipt changes. Its metadata,
        // every downstream manifest/object and ordinary serving gates remain
        // valid; a metadata-selected edge must still recheck the whole producer.
        fixture.expire_archive_closure(&a);
        let reason = fixture
            .coord
            .verify_committed_dependencies(&[selected], CommittedDependencyPolicy::WorkspaceDagRlib)
            .unwrap_err();
        assert!(reason.contains("native archive"), "{reason}");
        assert!(
            reason.contains(&digest_key(&a.manifest.action_key)),
            "{reason}"
        );

        let refused = fixture.root.path().join("expired-ancestor-closure");
        let mut calls = 0;
        let mut ready = |_: &[PathBuf]| {
            calls += 1;
            Ok(())
        };
        assert!(matches!(
            fixture.replay(&d, &refused, Some(&mut ready)).unwrap(),
            ServeOutcome::ExecutePrivately(ReplayRefusal::CommittedDependency(reason))
                if reason.contains("native archive")
                    && reason.contains(&digest_key(&a.manifest.action_key))
        ));
        assert_eq!(calls, 0);
        assert!(!refused.exists());
    }

    #[test]
    fn immutable_dag_replay_requires_own_samples_and_current_transitive_producers() {
        for metadata in [false, true] {
            let fixture = WorkspaceLineageFixture::new();
            let [a, b, c, d] = immutable_dag_chain(&fixture, metadata);
            let immutable_policy = if metadata {
                CommittedDependencyPolicy::ImmutableDagMetadata
            } else {
                CommittedDependencyPolicy::ImmutableDagRlib
            };
            let workspace_policy = if metadata {
                CommittedDependencyPolicy::WorkspaceDagMetadata
            } else {
                CommittedDependencyPolicy::WorkspaceDagRlib
            };
            for offer in [&a, &b] {
                fixture
                    .coord
                    .verify_committed_dependencies(&[witness(offer)], immutable_policy)
                    .unwrap();
            }
            for offer in [&a, &b, &c, &d] {
                fixture
                    .coord
                    .verify_committed_dependencies(&[witness(offer)], workspace_policy)
                    .unwrap();
            }
            for offer in [&b, &c, &d] {
                for legacy in [
                    CommittedDependencyPolicy::MixedWorkspaceRlib,
                    CommittedDependencyPolicy::MixedWorkspaceMetadata,
                ] {
                    assert!(
                        fixture
                            .coord
                            .verify_committed_dependencies(&[witness(offer)], legacy)
                            .is_err()
                    );
                }
            }
            for offer in [&c, &d] {
                assert!(
                    fixture
                        .coord
                        .verify_committed_dependencies(&[witness(offer)], immutable_policy)
                        .is_err()
                );
            }
            let unsampled = fixture.root.path().join("dag-unsampled");
            assert!(matches!(
                fixture.replay(&d, &unsampled, None).unwrap(),
                ServeOutcome::ExecutePrivately(ReplayRefusal::Sampling(
                    PrivateExecutionReason::InsufficientVerificationSamples {
                        observed: 0,
                        required: 2
                    }
                ))
            ));
            assert!(!unsampled.exists());
            fixture.compare_twice(&d);
            let destination = fixture.root.path().join("dag-served");
            assert!(matches!(fixture.replay(&d, &destination, None).unwrap(),
                ServeOutcome::Served { files } if files.len() == if metadata { 1 } else { 2 }));
            assert_eq!(
                std::fs::read(destination.join("libd.rmeta")).unwrap(),
                b"metadata D"
            );
            if !metadata {
                assert_eq!(
                    std::fs::read(destination.join("libd.rlib")).unwrap(),
                    crate::test_util::closed_rlib_fixture(b"metadata D")
                );
            }
            for producer in [&a, &b, &c] {
                fixture.assert_unsampled(producer);
            }

            fixture.quarantine(&a.manifest.action_key);
            let refused = fixture.root.path().join("dag-revoked");
            assert!(matches!(fixture.replay(&d, &refused, None).unwrap(),
                ServeOutcome::ExecutePrivately(ReplayRefusal::CommittedDependency(reason))
                    if reason.contains(&digest_key(&a.manifest.action_key))));
            assert!(!refused.exists());
            let later = fixture.prepare_dag(
                105,
                vec![consumes(&d)],
                &[("liblater.rmeta", OutputRole::ProvisionalMetadata, b"later")],
                workspace_policy,
            );
            assert!(
                matches!(fixture.coord.commit_offer(&later, &sample_expected_descriptor()),
                Err(CommitRefusal::CommittedDependency(reason))
                    if reason.contains(&digest_key(&a.manifest.action_key)))
            );
            fixture.assert_unpublished(&later);
        }
    }

    #[test]
    fn generated_dag_replay_and_ordinary_consumers_recheck_transitive_producers() {
        for metadata in [false, true] {
            let fixture = WorkspaceLineageFixture::new();
            let [a, _b, _c, d] = immutable_dag_chain(&fixture, metadata);
            let outputs = |metadata_name, archive_name, bytes| {
                let mut outputs = vec![(metadata_name, OutputRole::ProvisionalMetadata, bytes)];
                if !metadata {
                    outputs.push((archive_name, OutputRole::Materializable, bytes));
                }
                outputs
            };
            let generated = fixture.prepare_generated_dag(
                111,
                vec![consumes(&d)],
                &outputs("libe.rmeta", "libe.rlib", b"generated E".as_slice()),
                metadata,
            );
            fixture.commit(&generated);
            let dependent = fixture.prepare_generated_dag(
                112,
                vec![consumes(&generated), consumes(&d)],
                &outputs("libf.rmeta", "libf.rlib", b"generated F".as_slice()),
                metadata,
            );
            fixture.commit(&dependent);
            let workspace_policy = if metadata {
                CommittedDependencyPolicy::WorkspaceDagMetadata
            } else {
                CommittedDependencyPolicy::WorkspaceDagRlib
            };
            let ordinary = fixture.prepare_dag(
                113,
                vec![consumes(&dependent), consumes(&generated), consumes(&d)],
                &outputs("libg.rmeta", "libg.rlib", b"ordinary G".as_slice()),
                workspace_policy,
            );
            fixture.commit(&ordinary);
            for producer in [&generated, &dependent] {
                for policy in [
                    CommittedDependencyPolicy::WorkspaceDagMetadata,
                    CommittedDependencyPolicy::GeneratedWorkspaceDagMetadata,
                ] {
                    fixture
                        .coord
                        .verify_committed_dependencies(&[witness(producer)], policy)
                        .unwrap();
                }
                for policy in [
                    CommittedDependencyPolicy::WorkspaceRlib,
                    CommittedDependencyPolicy::WorkspaceMetadata,
                    CommittedDependencyPolicy::MixedWorkspaceRlib,
                    CommittedDependencyPolicy::MixedWorkspaceMetadata,
                    CommittedDependencyPolicy::ImmutableDagRlib,
                    CommittedDependencyPolicy::ImmutableDagMetadata,
                ] {
                    assert!(
                        fixture
                            .coord
                            .verify_committed_dependencies(&[witness(producer)], policy)
                            .is_err()
                    );
                }
            }
            let unsampled = fixture.root.path().join("generated-dag-unsampled");
            assert!(matches!(
                fixture.replay(&dependent, &unsampled, None).unwrap(),
                ServeOutcome::ExecutePrivately(ReplayRefusal::Sampling(
                    PrivateExecutionReason::InsufficientVerificationSamples {
                        observed: 0,
                        required: 2
                    }
                ))
            ));
            assert!(!unsampled.exists());
            for (offer, name, bytes) in [
                (&dependent, "libf.rmeta", b"generated F".as_slice()),
                (&ordinary, "libg.rmeta", b"ordinary G".as_slice()),
            ] {
                fixture.compare_twice(offer);
                let destination = fixture.root.path().join(name);
                assert!(matches!(fixture.replay(offer, &destination, None).unwrap(),
                    ServeOutcome::Served { files }
                        if files.len() == if metadata { 1 } else { 2 }));
                assert_eq!(std::fs::read(destination.join(name)).unwrap(), bytes);
            }
            fixture.assert_unsampled(&generated);
            fixture.assert_unsampled(&d);

            fixture.quarantine(&a.manifest.action_key);
            for (offer, name) in [
                (&dependent, "generated-revoked"),
                (&ordinary, "ordinary-revoked"),
            ] {
                let refused = fixture.root.path().join(name);
                assert!(matches!(fixture.replay(offer, &refused, None).unwrap(),
                    ServeOutcome::ExecutePrivately(ReplayRefusal::CommittedDependency(reason))
                        if reason.contains(&digest_key(&a.manifest.action_key))));
                assert!(!refused.exists());
            }
            let later = fixture.prepare_generated_dag(
                114,
                vec![consumes(&ordinary)],
                &outputs("liblater.rmeta", "liblater.rlib", b"later".as_slice()),
                metadata,
            );
            assert!(matches!(
                fixture.coord.commit_offer(&later, &sample_expected_descriptor()),
                Err(CommitRefusal::CommittedDependency(reason))
                    if reason.contains(&digest_key(&a.manifest.action_key))
            ));
            fixture.assert_unpublished(&later);
        }
    }

    #[test]
    fn generated_dag_classes_require_parents_and_preserve_metadata_only_authority() {
        let fixture = WorkspaceLineageFixture::new();
        for (tag, class) in [
            (115, LIVE_GENERATED_WORKSPACE_DAG_RLIB_CLASS),
            (116, LIVE_GENERATED_WORKSPACE_DAG_METADATA_CLASS),
        ] {
            let orphan = fixture.prepare_class(
                tag,
                Vec::new(),
                &[(
                    "liborphan.rmeta",
                    OutputRole::ProvisionalMetadata,
                    b"orphan",
                )],
                class,
            );
            assert!(matches!(
                fixture.coord.commit_offer(&orphan, &sample_expected_descriptor()),
                Err(CommitRefusal::CommittedDependency(reason))
                    if reason.contains("lacks bounded producer ancestry")
            ));
            fixture.assert_unpublished(&orphan);
        }

        let [_a, _b, _c, d] = immutable_dag_chain(&fixture, true);
        let generated = fixture.prepare_generated_dag(
            117,
            vec![consumes(&d)],
            &[(
                "libe.rmeta",
                OutputRole::ProvisionalMetadata,
                b"generated E",
            )],
            true,
        );
        fixture.commit(&generated);
        for policy in [
            CommittedDependencyPolicy::WorkspaceDagRlib,
            CommittedDependencyPolicy::GeneratedWorkspaceDagRlib,
        ] {
            assert!(
                fixture
                    .coord
                    .verify_committed_dependencies(&[witness(&generated)], policy)
                    .is_err()
            );
        }
        let consumer = fixture.prepare_generated_dag(
            118,
            vec![consumes(&generated)],
            &[(
                "libf.rmeta",
                OutputRole::ProvisionalMetadata,
                b"generated F",
            )],
            true,
        );
        fixture.commit(&consumer);
        fixture.compare_twice(&consumer);
        // A stale class receipt must not conceal a missing generated producer
        // graph, even when the consumer has already earned replay samples.
        let held = fixture.cas.store().lock().unwrap();
        let mut engine = RusqliteEngine::open(&fixture.cas.cas_root().join("meta.sqlite")).unwrap();
        assert_eq!(engine.execute(
            "UPDATE provisional_ancestry SET consumer_action_key = ?1 WHERE consumer_action_key = ?2",
            &[
                SqlValue::Text("explicit-generated-test-orphan".into()),
                SqlValue::Text(digest_key(&generated.manifest.action_key)),
            ],
        ).unwrap(), 1);
        drop(engine);
        drop(held);
        let reason = fixture
            .coord
            .verify_committed_dependencies(
                &[witness(&generated)],
                CommittedDependencyPolicy::GeneratedWorkspaceDagMetadata,
            )
            .unwrap_err();
        assert!(reason.contains("inconsistent class ancestry"), "{reason}");
        let refused = fixture.root.path().join("generated-dag-without-ancestry");
        assert!(matches!(fixture.replay(&consumer, &refused, None).unwrap(),
            ServeOutcome::ExecutePrivately(ReplayRefusal::CommittedDependency(reason))
                if reason.contains("inconsistent class ancestry")));
        assert!(!refused.exists());
    }

    #[test]
    fn workspace_dag_consumers_cannot_lend_workspace_authority_to_immutable_ancestors() {
        let fixture = WorkspaceLineageFixture::new();
        let [a, b, c, d] = immutable_dag_chain(&fixture, true);
        fixture.compare_twice(&d);
        let workspace = fixture.commit_metadata_leaf(
            106,
            &[(
                "liba.rmeta",
                OutputRole::ProvisionalMetadata,
                b"immutable root A",
            )],
        );
        // First visit the same producer under the broader root policy. It must
        // still be rejected later when traversed as immutable B's input.
        let held = fixture.cas.store().lock().unwrap();
        let mut engine = RusqliteEngine::open(&fixture.cas.cas_root().join("meta.sqlite")).unwrap();
        assert_eq!(engine.execute(
            "UPDATE provisional_ancestry SET producer_action_key = ?1 WHERE producer_action_key = ?2",
            &[
                SqlValue::Text(digest_key(&workspace.manifest.action_key)),
                SqlValue::Text(digest_key(&a.manifest.action_key)),
            ],
        ).unwrap(), 3);
        drop(engine);
        drop(held);
        let reason = fixture
            .coord
            .verify_committed_dependencies(
                &[witness(&d)],
                CommittedDependencyPolicy::WorkspaceDagMetadata,
            )
            .unwrap_err();
        assert!(reason.contains("allowed by its consumer"), "{reason}");
        assert!(
            reason.contains(&digest_key(&workspace.manifest.action_key)),
            "{reason}"
        );
        let refused = fixture.root.path().join("immutable-parent-is-workspace");
        assert!(matches!(fixture.replay(&d, &refused, None).unwrap(),
            ServeOutcome::ExecutePrivately(ReplayRefusal::CommittedDependency(reason))
                if reason.contains("allowed by its consumer")));
        assert!(!refused.exists());
        fixture.assert_unsampled(&b);
        fixture.assert_unsampled(&c);
    }

    #[test]
    fn immutable_dag_metadata_cannot_authorize_archive_ancestry_or_omit_its_parents() {
        let fixture = WorkspaceLineageFixture::new();
        let [_a, b, _c, d] = immutable_dag_chain(&fixture, true);
        for policy in [
            CommittedDependencyPolicy::ImmutableDagRlib,
            CommittedDependencyPolicy::WorkspaceDagRlib,
        ] {
            assert!(
                fixture
                    .coord
                    .verify_committed_dependencies(&[witness(&b)], policy)
                    .is_err()
            );
        }
        fixture.compare_twice(&d);
        // A corrupted committed-class receipt cannot conceal the absence of
        // its required producer graph, even though exact output bytes survive.
        let held = fixture.cas.store().lock().unwrap();
        let mut engine = RusqliteEngine::open(&fixture.cas.cas_root().join("meta.sqlite")).unwrap();
        assert_eq!(engine.execute(
            "UPDATE provisional_ancestry SET consumer_action_key = ?1 WHERE consumer_action_key = ?2",
            &[
                SqlValue::Text("explicit-test-orphan".into()),
                SqlValue::Text(digest_key(&b.manifest.action_key)),
            ],
        ).unwrap(), 1);
        drop(engine);
        drop(held);
        let reason = fixture
            .coord
            .verify_committed_dependencies(
                &[witness(&b)],
                CommittedDependencyPolicy::ImmutableDagMetadata,
            )
            .unwrap_err();
        assert!(reason.contains("inconsistent class ancestry"), "{reason}");
        let refused = fixture.root.path().join("immutable-dag-without-ancestry");
        assert!(matches!(fixture.replay(&d, &refused, None).unwrap(),
            ServeOutcome::ExecutePrivately(ReplayRefusal::CommittedDependency(reason))
                if reason.contains("inconsistent class ancestry")));
        assert!(!refused.exists());
    }

    fn metadata_chain(fixture: &WorkspaceLineageFixture) -> [OfferPreparedActionResult; 3] {
        let a = fixture.commit_metadata_leaf(
            41,
            &[("liba.rmeta", OutputRole::ProvisionalMetadata, b"metadata A")],
        );
        let b = fixture.prepare_metadata(
            42,
            vec![consumes(&a)],
            &[("libb.rmeta", OutputRole::ProvisionalMetadata, b"metadata B")],
        );
        fixture.commit(&b);
        let c = fixture.prepare_metadata(
            43,
            vec![consumes(&b)],
            &[("libc.rmeta", OutputRole::ProvisionalMetadata, b"metadata C")],
        );
        fixture.commit(&c);
        [a, b, c]
    }

    #[test]
    fn metadata_only_revocation_after_delivery_is_terminal_with_an_empty_archive_tail() {
        for (producer, graph) in [
            (false, 0),
            (true, 0),
            (false, 1),
            (true, 1),
            (false, 2),
            (true, 2),
        ] {
            let fixture = WorkspaceLineageFixture::new();
            let [a, b, c] = match graph {
                0 => metadata_chain(&fixture),
                1 => mixed_chain(&fixture, true),
                _ => {
                    let [a, b, c, d] = immutable_dag_chain(&fixture, true);
                    fixture.assert_unsampled(&c);
                    [a, b, d]
                }
            };
            let (name, bytes): (&str, &[u8]) = if graph == 2 {
                ("libd.rmeta", b"metadata D")
            } else {
                ("libc.rmeta", b"metadata C")
            };
            if !producer {
                fixture.compare_twice(&c);
            }
            let destination = fixture.root.path().join("metadata-only-frontier");
            let mut calls = 0;
            let mut ready = |files: &[PathBuf]| {
                calls += 1;
                assert_eq!(files, &[destination.join(name)]);
                assert_eq!(std::fs::read(&files[0]).unwrap(), bytes);
                assert!(fixture.cas.store().try_lock().is_ok());
                // A was safe when this head was installed. Revocation here
                // must still be observed after notification, even though C
                // has no archive tail to install before returning success.
                fixture.quarantine(&a.manifest.action_key);
                Ok(())
            };
            let result = if producer {
                fixture.coord.serve_produced_result_with_metadata(
                    &c.manifest.action_key,
                    &digest_key(&c.manifest_id.0),
                    &destination,
                    &expected(&c, &destination),
                    now_micros(),
                    Some(&mut ready),
                )
            } else {
                fixture.replay(&c, &destination, Some(&mut ready))
            };
            assert_eq!(calls, 1, "producer={producer}");
            assert!(
                matches!(result, Err(ServeError::MetadataExposed { installed, reason })
                if installed == vec![destination.join(name)]
                    && reason.contains(&digest_key(&a.manifest.action_key))),
                "producer={producer}"
            );
            assert_eq!(std::fs::read(destination.join(name)).unwrap(), bytes);
            fixture.assert_unsampled(&a);
            fixture.assert_unsampled(&b);
        }
    }

    #[test]
    fn metadata_consumer_cannot_broaden_an_archive_ancestors_producer_class() {
        let fixture = WorkspaceLineageFixture::new();
        let [a, b, c] = metadata_chain(&fixture);
        fixture.compare_twice(&c);
        // Explicit persisted-state fault: B now claims the old archive class
        // while retaining its metadata producer A. A metadata root must apply
        // B's narrower policy at that edge instead of its own broader policy.
        let held = fixture.cas.store().lock().unwrap();
        let mut engine = RusqliteEngine::open(&fixture.cas.cas_root().join("meta.sqlite")).unwrap();
        assert_eq!(
            engine.execute(
                "UPDATE decision_receipts SET decision = ?1 WHERE kind = ?2 AND subject = ?3 AND seq = 0",
                &[
                    SqlValue::Text(LIVE_COMMITTED_WORKSPACE_RLIB_CLASS.into()),
                    SqlValue::Text(LIVE_CLASS_RECEIPT.into()),
                    SqlValue::Text(digest_key(&b.manifest.action_key)),
                ],
            ).unwrap(),
            1,
        );
        drop(engine);
        drop(held);
        let reason = fixture
            .coord
            .verify_committed_dependencies(
                &[witness(&c)],
                CommittedDependencyPolicy::WorkspaceMetadata,
            )
            .unwrap_err();
        assert!(reason.contains("allowed by its consumer"), "{reason}");
        assert!(
            reason.contains(&digest_key(&a.manifest.action_key)),
            "{reason}"
        );
        let destination = fixture.root.path().join("blocked-archive-ancestry");
        assert!(matches!(
            fixture.replay(&c, &destination, None).unwrap(),
            ServeOutcome::ExecutePrivately(ReplayRefusal::CommittedDependency(reason))
                if reason.contains("allowed by its consumer")
        ));
        assert!(!destination.exists());
    }

    #[test]
    fn committed_workspace_chain_accepts_unsampled_parents_but_preserves_consumer_sampling() {
        let fixture = WorkspaceLineageFixture::new();
        let [a, b, c] = chain(&fixture);
        for offer in [&a, &b, &c] {
            fixture.assert_unsampled(offer);
            fixture
                .coord
                .verify_committed_dependencies(
                    &[witness(offer)],
                    CommittedDependencyPolicy::WorkspaceRlib,
                )
                .unwrap();
        }
        let direct = fixture
            .cas
            .store()
            .lock()
            .unwrap()
            .list_provisional_ancestors(&digest_key(&c.manifest.action_key))
            .unwrap();
        assert_eq!(direct.len(), 1);
        assert_eq!(
            direct[0].producer_action_key,
            digest_key(&b.manifest.action_key)
        );
        assert!(!direct[0].adopted);
        let unsampled = fixture.root.path().join("unsampled-consumer");
        assert_eq!(
            fixture.replay(&c, &unsampled, None).unwrap(),
            ServeOutcome::ExecutePrivately(ReplayRefusal::Sampling(
                PrivateExecutionReason::InsufficientVerificationSamples {
                    observed: 0,
                    required: 2
                }
            ))
        );
        assert!(!unsampled.exists());
        fixture.compare_twice(&c);
        let destination = fixture.root.path().join("verified-consumer");
        assert!(matches!(fixture.replay(&c, &destination, None).unwrap(),
            ServeOutcome::Served { files } if files.len() == 3));
        assert_eq!(
            std::fs::read(destination.join("libc.rmeta")).unwrap(),
            b"actual CAS metadata C"
        );
        assert_eq!(
            std::fs::read(destination.join("libc.rlib")).unwrap(),
            crate::test_util::closed_rlib_fixture(b"actual CAS archive C")
        );
        fixture.assert_unsampled(&a);
        fixture.assert_unsampled(&b);
    }

    #[test]
    fn transitive_producer_quarantine_blocks_new_publication_and_previously_proven_replay() {
        let fixture = WorkspaceLineageFixture::new();
        let [a, b, c] = chain(&fixture);
        fixture.compare_twice(&c);
        let earlier = fixture.root.path().join("healthy-replay");
        assert!(matches!(
            fixture.replay(&c, &earlier, None).unwrap(),
            ServeOutcome::Served { .. }
        ));
        let d = fixture.prepare(
            4,
            vec![consumes(&c)],
            &[
                (
                    "libd.rmeta",
                    OutputRole::ProvisionalMetadata,
                    b"actual CAS metadata D",
                ),
                (
                    "libd.rlib",
                    OutputRole::Materializable,
                    b"actual CAS archive D",
                ),
            ],
        );
        fixture.quarantine(&a.manifest.action_key);
        assert!(
            matches!(fixture.coord.commit_offer(&d, &sample_expected_descriptor()),
            Err(CommitRefusal::CommittedDependency(reason)) if reason.contains(&digest_key(&a.manifest.action_key)))
        );
        fixture.assert_unpublished(&d);
        let destination = fixture.root.path().join("blocked-replay");
        assert!(matches!(fixture.replay(&c, &destination, None).unwrap(),
            ServeOutcome::ExecutePrivately(ReplayRefusal::CommittedDependency(reason))
                if reason.contains(&digest_key(&a.manifest.action_key))));
        assert!(!destination.exists());
        assert!(
            fixture
                .coord
                .verify_committed_dependencies(
                    &[witness(&c)],
                    CommittedDependencyPolicy::WorkspaceRlib,
                )
                .is_err()
        );
        fixture.assert_unsampled(&a);
        fixture.assert_unsampled(&b);
    }

    #[test]
    fn committed_workspace_rejects_uncommitted_and_different_exact_objects() {
        let fixture = WorkspaceLineageFixture::new();
        let a = fixture.prepare(
            1,
            Vec::new(),
            &[(
                "liba.rmeta",
                OutputRole::ProvisionalMetadata,
                b"actual CAS metadata A",
            )],
        );
        let b = fixture.prepare(
            2,
            vec![consumes(&a)],
            &[(
                "libb.rlib",
                OutputRole::Materializable,
                b"actual CAS archive B",
            )],
        );
        assert!(
            matches!(fixture.coord.commit_offer(&b, &sample_expected_descriptor()),
            Err(CommitRefusal::CommittedDependency(reason)) if reason.contains("not committed"))
        );
        fixture.assert_unpublished(&a);
        fixture.assert_unpublished(&b);
        fixture.commit(&a);
        fixture.commit(&b);
        let exact = witness(&a);
        fixture
            .coord
            .verify_committed_dependencies(
                std::slice::from_ref(&exact),
                CommittedDependencyPolicy::WorkspaceRlib,
            )
            .unwrap();
        for change in ["object", "manifest", "descriptor"] {
            let mut different = exact.clone();
            match change {
                "object" => different.object = fixture.put(b"other real CAS metadata"),
                "manifest" => {
                    different.producer_manifest = fixture.put(b"different manifest identity").0
                }
                "descriptor" => different.producer_descriptor.bytes[0] ^= 1,
                _ => unreachable!(),
            }
            let reason = fixture
                .coord
                .verify_committed_dependencies(
                    &[different],
                    CommittedDependencyPolicy::WorkspaceRlib,
                )
                .unwrap_err();
            assert!(
                reason.contains("does not commit the exact input"),
                "{change}: {reason}"
            );
        }
        let mut wrong = consumes(&a);
        wrong.consumed_object = fixture.put(b"other real CAS metadata");
        let c = fixture.prepare(
            3,
            vec![wrong],
            &[(
                "libc.rlib",
                OutputRole::Materializable,
                b"actual CAS archive C",
            )],
        );
        assert!(
            matches!(fixture.coord.commit_offer(&c, &sample_expected_descriptor()),
            Err(CommitRefusal::CommittedDependency(reason)) if reason.contains("does not commit the exact input"))
        );
        fixture.assert_unpublished(&c);
    }

    #[test]
    fn retained_provisional_adoption_never_becomes_committed_workspace_authority() {
        let fixture = WorkspaceLineageFixture::new();
        let [a, b, c] = chain(&fixture);
        fixture.compare_twice(&c);
        fixture
            .coord
            .verify_committed_dependencies(&[witness(&c)], CommittedDependencyPolicy::WorkspaceRlib)
            .unwrap();
        let d = fixture.prepare(
            4,
            vec![consumes(&c)],
            &[(
                "libd.rlib",
                OutputRole::Materializable,
                b"actual CAS archive D",
            )],
        );
        // Explicit persisted-state injection: the general H028 lane admits
        // adoption, but this narrower class must reject an adopted ancestor.
        let mut store = fixture.cas.store().lock().unwrap();
        {
            let mut engine =
                RusqliteEngine::open(&fixture.cas.cas_root().join("meta.sqlite")).unwrap();
            assert_eq!(
                engine.execute(
                    "UPDATE provisional_ancestry SET adopted = 1 WHERE consumer_action_key = ?1 AND producer_action_key = ?2",
                    &[SqlValue::Text(digest_key(&b.manifest.action_key)), SqlValue::Text(digest_key(&a.manifest.action_key))],
                ).unwrap(),
                1,
                "the fixture must mark exactly the retained B-to-A ancestry row as adopted",
            );
        }
        let retained = store
            .list_provisional_ancestors(&digest_key(&b.manifest.action_key))
            .unwrap();
        assert_eq!(retained.len(), 1);
        assert!(retained[0].adopted);
        drop(store);
        let reason = fixture
            .coord
            .verify_committed_dependencies(&[witness(&c)], CommittedDependencyPolicy::WorkspaceRlib)
            .unwrap_err();
        assert!(reason.contains("provisional adoption"), "{reason}");
        assert!(
            matches!(fixture.coord.commit_offer(&d, &sample_expected_descriptor()),
            Err(CommitRefusal::CommittedDependency(reason)) if reason.contains("provisional adoption"))
        );
        fixture.assert_unpublished(&d);
        let destination = fixture.root.path().join("adoption-refused");
        assert!(matches!(fixture.replay(&c, &destination, None).unwrap(),
            ServeOutcome::ExecutePrivately(ReplayRefusal::CommittedDependency(reason)) if reason.contains("provisional adoption")));
        assert!(!destination.exists());
    }

    #[test]
    fn producer_quarantine_after_consumer_metadata_is_sticky_and_never_installs_archive_tail() {
        for producer in [false, true] {
            let fixture = WorkspaceLineageFixture::new();
            let [a, b, c] = chain(&fixture);
            if !producer {
                fixture.compare_twice(&c);
            }
            let destination = fixture.root.path().join("metadata-frontier");
            let mut calls = 0;
            let mut ready = |files: &[PathBuf]| {
                calls += 1;
                assert_eq!(
                    files,
                    &[destination.join("libc.rmeta"), destination.join("c.d")]
                );
                assert_eq!(std::fs::read(&files[0]).unwrap(), b"actual CAS metadata C");
                assert_eq!(
                    std::fs::read(&files[1]).unwrap(),
                    format!("{}/libc.rmeta:\n", destination.display()).as_bytes()
                );
                assert!(!destination.join("libc.rlib").exists());
                assert!(
                    fixture.cas.store().try_lock().is_ok(),
                    "callback must run outside the store lock"
                );
                fixture.quarantine(&a.manifest.action_key);
                Ok(())
            };
            let result = if producer {
                fixture.coord.serve_produced_result_with_metadata(
                    &c.manifest.action_key,
                    &digest_key(&c.manifest_id.0),
                    &destination,
                    &expected(&c, &destination),
                    now_micros(),
                    Some(&mut ready),
                )
            } else {
                fixture.replay(&c, &destination, Some(&mut ready))
            };
            assert_eq!(calls, 1, "producer={producer}");
            assert!(
                matches!(result, Err(ServeError::MetadataExposed { installed, reason })
                if installed == vec![destination.join("libc.rmeta"), destination.join("c.d")]
                    && reason.contains(&digest_key(&a.manifest.action_key))),
                "producer={producer}"
            );
            assert_eq!(
                std::fs::read(destination.join("libc.rmeta")).unwrap(),
                b"actual CAS metadata C"
            );
            assert!(
                !destination.join("libc.rlib").exists(),
                "producer={producer}"
            );
            fixture.assert_unsampled(&a);
            fixture.assert_unsampled(&b);
        }
    }
}
