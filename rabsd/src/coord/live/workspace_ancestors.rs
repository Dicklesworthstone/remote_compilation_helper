//! Current safety of the committed producers used by workspace library caches.
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
use rabs_key::live_dependency::workspace_dependency_cache::CommittedWorkspaceDependency;
use rabs_protocol::generation::AttemptAuthority;
use rabs_protocol::result_identity::{OutputRole, ResultKind};
use std::collections::BTreeSet;
use std::time::Instant;

// Match the existing H028 admission work bound. Count every input edge, not
// just unique producers; shared ancestors do not excuse unchecked references.
const MAX_LINEAGE_EDGES: usize = 65_536;

pub(super) fn now_micros() -> i64 {
    i64::try_from(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |elapsed| elapsed.as_micros()),
    )
    .unwrap_or(i64::MAX)
}

impl CoordLive {
    /// Check operation-owned installation witnesses against current durable
    /// producer authority. Callers still have to verify the exact physical
    /// candidate generation before and after this check.
    pub(crate) fn verify_committed_workspace_dependencies(
        &self,
        dependencies: &[CommittedWorkspaceDependency],
    ) -> Result<(), String> {
        if dependencies.is_empty() || dependencies.len() > MAX_LINEAGE_EDGES {
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
        verify_graph(&mut *store, None, direct, now_micros(), 0, None)
    }
}

pub(super) fn check_offer(
    store: &mut dyn RabsMetadataStore,
    offer: &OfferPreparedActionResult,
    now: i64,
    epoch: u64,
    lease_now: &dyn Fn() -> u64,
) -> Result<(), String> {
    if recorded_action_risk(store, &offer.manifest.action_key).map_err(store_error)?
        != ActionClassRisk::CommittedWorkspaceRlib
    {
        return Ok(());
    }
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
    if recorded_action_risk(store, action).map_err(store_error)?
        != ActionClassRisk::CommittedWorkspaceRlib
    {
        return Ok(());
    }
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
    Input(Ancestor),
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
) -> Result<(), String> {
    let started = Instant::now();
    let mut edges = direct.len();
    if edges > MAX_LINEAGE_EDGES {
        return Err("committed workspace ancestry exceeds admission bound".into());
    }
    let mut pending: Vec<_> = direct.into_iter().map(Visit::Input).collect();
    let mut active = BTreeSet::new();
    if let Some(consumer) = consumer {
        active.insert(digest_key(consumer));
    }
    let mut complete = BTreeSet::new();
    while let Some(visit) = pending.pop() {
        let check = match visit {
            Visit::Input(check) => check,
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
        if !matches!(
            risk,
            ActionClassRisk::ClosedWorkspaceRlib | ActionClassRisk::CommittedWorkspaceRlib
        ) {
            return Err(format!(
                "workspace producer {} lacks a closed workspace class",
                check.producer
            ));
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
        if (risk == ActionClassRisk::ClosedWorkspaceRlib && !ancestors.is_empty())
            || (risk == ActionClassRisk::CommittedWorkspaceRlib && ancestors.is_empty())
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
        pending.extend(
            ancestors
                .into_iter()
                .map(Ancestor::from_row)
                .map(Visit::Input),
        );
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
    use rabs_key::live_dependency::workspace_dependency_cache::CommittedWorkspaceDependency;
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
            assert!(!outputs.is_empty());
            let logical_outputs: Vec<_> = outputs
                .iter()
                .map(|(name, role, bytes)| LogicalOutput {
                    role: *role,
                    virtual_path: RawBytes::from(*name),
                    object: self.put(bytes),
                })
                .collect();
            let (base, _) =
                offer_serving_object(&self.coord.authority().unwrap(), &logical_outputs[0].object);
            let mut authority = base.authority.clone();
            authority.action_key = tagged_digest("rabs.action-key.sha256.v1", tag);
            let mut manifest = base.manifest.clone();
            manifest.action_key = authority.action_key.clone();
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
                    if parents.is_empty() {
                        LIVE_WORKSPACE_RLIB_CLASS
                    } else {
                        LIVE_COMMITTED_WORKSPACE_RLIB_CLASS
                    },
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
    fn committed_workspace_chain_accepts_unsampled_parents_but_preserves_consumer_sampling() {
        let fixture = WorkspaceLineageFixture::new();
        let [a, b, c] = chain(&fixture);
        for offer in [&a, &b, &c] {
            fixture.assert_unsampled(offer);
            fixture
                .coord
                .verify_committed_workspace_dependencies(&[witness(offer)])
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
            b"actual CAS archive C"
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
                .verify_committed_workspace_dependencies(&[witness(&c)])
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
            .verify_committed_workspace_dependencies(std::slice::from_ref(&exact))
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
                .verify_committed_workspace_dependencies(&[different])
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
            .verify_committed_workspace_dependencies(&[witness(&c)])
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
            .verify_committed_workspace_dependencies(&[witness(&c)])
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
