//! The live registry and Git dependency lane (bd-14t4j / bd-k52xe): the first
//! production caller of `submit_action` → dispatch → `commit_offer`, and the
//! first path on which a verified cache answer may replace a compiler run.
//!
//! ## Roles
//!
//! The edge observes a wrapper request and computes its exact key
//! (`rabs_key::live_dependency`). This lane then either
//!
//! - **serves**: the committed result passes the coordinator's serving gate
//!   AND the live evidence/sampling floor, its canonical transcript is bound
//!   to the committed observable digest, and every declared output was
//!   installed through the existing verified materializer; or
//! - **executes privately**: the action is submitted to the ONE coordinator
//!   actor registry, a durable generation/attempt/lease is admitted for the
//!   edge host's local executor, and the subscriber's own compiler run IS
//!   that attempt. Its outputs are harvested, uploaded, and offered through
//!   the coordinator-only publication gate. A first offer commits; a
//!   matching later offer appends verification evidence (the trust ladder
//!   the sampling floor counts); a different result quarantines the action.
//!
//! Nothing here creates a second state machine: actor, attempt, lease,
//! publication, serving and sampling are the existing ones.
//!
//! ## Local executor
//!
//! The edge host is admitted as a worker (`edge-local:<host>`, boot
//! generation = coordinator term, incarnation = coordinator incarnation).
//! Its attempts run unsandboxed in the subscriber's own target tree, which
//! is exactly what the key's isolation component states. Evidence from it
//! is `ReproducibleSameWorker` at best.

use crate::coord::action_actor::{JoinRequest, SubscriptionRequirements};
use crate::coord::live::{
    ActionSubmission, CoordLive, ExpectedOutputs, ServeMode, ServeOutcome, SubmissionRefusal,
    load_manifest,
};
use crate::edge::live_facts::{
    DependencyFacts, FileSig, GENERATED_ROOT, PACKAGE_ROOT, PackageFacts, read_stable,
};
use rabs_action::state_machines::AttemptState;
use rabs_cas::blob_store::{DurabilityPolicy, PutLimits, put_if_absent};
use rabs_cas::digest_set::{DigestRequest, digest_set};
use rabs_cas::manifest_codec::encode_manifest_v1;
use rabs_cas::metadata_store::{ActionEntryRow, RabsMetadataStore, SqlValue, digest_key};
use rabs_cas::publication::{
    OfferPreparedActionResult, PublicationOutcome, observable_result_digest_v1,
};
use rabs_key::live_dependency::{
    DependencyActionPlan, LIVE_DEPENDENCY_KEY_EPOCH, LIVE_DEPENDENCY_PROJECTION_EPOCH,
    LiveDependencyKey, canonicalize_placements, dep_info_closure_violation, render_placements,
};
use rabs_key::output_declarations::OutputClass;
use rabs_key::typed_digest::compute;
use rabs_protocol::descriptor::SubscriberKind;
use rabs_protocol::durable_ids::BuildOperationId;
use rabs_protocol::generation::{AttemptAuthority, WorkerBootGeneration, WorkerIncarnationId};
use rabs_protocol::input_evidence::ActionInputManifest;
use rabs_protocol::raw_bytes::RawBytes;
use rabs_protocol::result_identity::{
    AttemptEvidenceBundle, CanonicalActionResultManifest, LogicalOutput, ObjectId, OutputRole,
    ResultKind, TypedDigest,
};
use rabs_protocol::wire_time::PeerId;
use rabs_protocol::worker_fence::WorkerSessionOffer;
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

/// Decision-receipt kind binding an action key to its canonical
/// transcript object. The binding is verified against the committed
/// observable digest on every read; it is an index, never authority.
pub const LIVE_TRANSCRIPT_RECEIPT: &str = "rabs-live-transcript-v1";
/// Execution lease for one local compile (a duration on the coordinator
/// clock). Dependency compiles are minutes at worst.
const LOCAL_LEASE_TTL_MS: u64 = 4 * 60 * 60 * 1000;
/// Largest output file the lane harvests.
const MAX_OUTPUT_BYTES: u64 = 1024 * 1024 * 1024;
/// Largest stderr transcript the lane publishes (registry dependencies run
/// with capped lints; a large transcript is not this class).
pub const MAX_TRANSCRIPT_BYTES: usize = 1024 * 1024;
/// Encoding tag of the persisted bundle-root bytes. Not `raw`: the file's
/// content id is the derived bundle-root digest, not an ATP object id.
const BUNDLE_ROOT_ENCODING: &str = "artifact-bundle-root-v1";

/// Everything the edge observed and keyed for one request.
#[derive(Debug)]
pub struct LiveDependencyRequest {
    /// The exact key and its descriptor.
    pub key: LiveDependencyKey,
    /// The planned invocation.
    pub plan: DependencyActionPlan,
    /// The complete package input manifest the key covers.
    pub inputs: ActionInputManifest,
    /// The sealed package bytes and member identities.
    pub package: Arc<PackageFacts>,
    /// Exact dependency candidate inventory and identities.
    pub dependencies: Arc<DependencyFacts>,
    /// `(path, digest)` of every extern the key covers.
    pub externs: Vec<(String, TypedDigest)>,
}

/// One output now present in the subscriber's out-dir with known bytes.
#[derive(Debug, Clone)]
pub struct KnownOutput {
    /// Absolute path.
    pub path: PathBuf,
    /// Identity observed after the bytes were established.
    pub sig: FileSig,
    /// CAS object id of the bytes.
    pub digest: TypedDigest,
}

/// The lane's answer to one request.
#[derive(Debug)]
pub enum LiveDecision {
    /// Every gate passes and the complete output plan is prepared; nothing
    /// is written until the subscriber commits to waiting for the install
    /// (so a subscriber that gave up can never race a delayed writer).
    Hit(PendingServe),
    /// Run the compiler as this admitted attempt, then complete it.
    Execute(LocalAttempt),
    /// Another subscriber owns this action's dispatch. No execution or
    /// destination writer was admitted for this request. A bounded follower
    /// may resubmit its original request; the edge must reobserve its inputs
    /// and all serving gates rather than treating leader completion as a hit.
    InFlight,
    /// Run the compiler unobserved (reason code).
    PassThrough(String),
}

/// A previewed hit awaiting the subscriber's acceptance.
#[derive(Debug)]
pub struct PendingServe {
    coord: Arc<CoordLive>,
    request: LiveDependencyRequest,
    manifest: CanonicalActionResultManifest,
    canonical_transcript: Vec<u8>,
}

/// The result of installing an accepted hit.
#[derive(Debug)]
pub enum InstallResult {
    /// Every declared output is installed and verified; replay the
    /// transcript and skip the compiler.
    Served {
        /// Exact stderr bytes for this subscriber's out-dir.
        transcript: Vec<u8>,
        /// Installed outputs (dep-info excluded: it is derived).
        installed: Vec<KnownOutput>,
    },
    /// A gate changed between preview and install; nothing was written.
    Declined(String),
    /// The synchronous install failed. It has returned, so no writer
    /// remains; the caller may run the compiler over the target tree.
    Fault(String),
}

impl PendingServe {
    /// The exact action key.
    #[must_use]
    pub fn action_key(&self) -> &TypedDigest {
        &self.request.key.action_key
    }

    /// Install under every gate again (one store lock through install).
    #[must_use]
    pub fn install(self) -> InstallResult {
        let plan = &self.request.plan;
        if let Err(reason) = self
            .request
            .package
            .verify_unchanged(Path::new(&plan.source_root))
            .and_then(|()| self.request.package.verify_generated_disjoint(plan))
            .and_then(|()| self.request.dependencies.verify_unchanged())
        {
            return InstallResult::Declined(reason);
        }
        let expected = expected_outputs(plan);
        match self.coord.serve_for_subscriber(
            &self.request.key.action_key,
            Path::new(&plan.out_dir),
            &expected,
            now_micros(),
            ServeMode::Install,
        ) {
            Ok(ServeOutcome::Served { files }) => {
                let mut installed = Vec::with_capacity(files.len());
                for path in &files {
                    let Some(committed) =
                        path.file_name()
                            .and_then(|name| name.to_str())
                            .and_then(|name| {
                                self.manifest.logical_outputs.iter().find(|output| {
                                    output.virtual_path.as_bytes() == name.as_bytes()
                                })
                            })
                    else {
                        return InstallResult::Fault(
                            "installed output is not in the manifest".into(),
                        );
                    };
                    if committed.role == OutputRole::DepInfo {
                        continue;
                    }
                    if let Ok(meta) = std::fs::symlink_metadata(path) {
                        installed.push(KnownOutput {
                            path: path.clone(),
                            sig: FileSig::of(&meta),
                            digest: committed.object.0.clone(),
                        });
                    }
                }
                InstallResult::Served {
                    transcript: render_placements(&self.canonical_transcript, plan),
                    installed,
                }
            }
            Ok(other) => InstallResult::Declined(format!("{other:?}")),
            Err(error) => InstallResult::Fault(error.to_string()),
        }
    }
}

fn expected_outputs(plan: &DependencyActionPlan) -> ExpectedOutputs {
    ExpectedOutputs::WithDepInfo {
        paths: plan.output_names().into_iter().collect::<BTreeSet<_>>(),
        mappings: plan
            .placement_mappings()
            .into_iter()
            .filter(|(real, _)| real == &plan.out_dir)
            .map(|(real, canonical)| (canonical.into_bytes(), real.into_bytes()))
            .collect(),
    }
}

fn mappings_for_plan(plan: &DependencyActionPlan) -> Vec<(String, String)> {
    let mut mappings = vec![(PACKAGE_ROOT.to_owned(), plan.source_virtual_root())];
    if plan.generated_root.is_some() {
        mappings.push((GENERATED_ROOT.to_owned(), plan.generated_virtual_root()));
    }
    mappings
}

/// What happened to a completed local attempt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CompletionOutcome {
    /// First result for this key.
    Committed,
    /// Matched the committed result; verification evidence appended.
    Verified,
    /// Diverged from the committed result; the action is quarantined.
    Quarantined,
    /// Nothing was offered (reason).
    NotPublished(String),
    /// The offer was refused by the publication gate (reason).
    Refused(String),
}

impl CompletionOutcome {
    /// Stable label for receipts.
    #[must_use]
    pub fn label(&self) -> &'static str {
        match self {
            Self::Committed => "committed",
            Self::Verified => "verified",
            Self::Quarantined => "quarantined",
            Self::NotPublished(_) => "not-published",
            Self::Refused(_) => "refused",
        }
    }
}

/// The subscriber's report of the compiler process it ran.
#[derive(Debug, Clone)]
pub struct CompletionReport {
    /// Exit code for a normal exit.
    pub exit_code: Option<i32>,
    /// Terminating signal, if any.
    pub signal: Option<i32>,
    /// Everything the compiler wrote to stdout.
    pub stdout: Vec<u8>,
    /// Everything the compiler wrote to stderr.
    pub stderr: Vec<u8>,
}

/// A complete immutable result, not yet an action publication. Capture has
/// finished ALL reads from the subscriber's input/output tree. The opaque
/// owner keeps the attempt alive without a store lock or blocking-lane permit.
/// Dropping it settles the attempt without publishing, including on disconnect.
#[derive(Debug)]
pub struct CapturedLocalAttempt {
    attempt: LocalAttempt,
    result: CapturedLocalResult,
}

#[derive(Debug)]
struct CapturedLocalResult {
    offer: OfferPreparedActionResult,
    transcript: ObjectId,
    manifest_key: String,
    known: Vec<KnownOutput>,
}

impl CapturedLocalAttempt {
    /// Action whose exact outputs were captured.
    #[must_use]
    pub fn action_key(&self) -> &TypedDigest {
        self.attempt.action_key()
    }

    /// Admitted execution identity, never supplied by the completion report.
    #[must_use]
    pub fn attempt_hex(&self) -> String {
        self.attempt.attempt_hex()
    }

    /// Content identity of the already durable canonical result manifest.
    #[must_use]
    pub fn manifest_key(&self) -> &str {
        &self.result.manifest_key
    }

    /// Publish the captured CAS objects through the existing coordinator gate.
    /// This performs no reads from the subscriber's mutable target or inputs.
    /// The transport must obtain the capture acknowledgment before calling it.
    pub fn publish(mut self) -> (CompletionOutcome, Vec<KnownOutput>) {
        let result = self.attempt.publish_captured(self.result);
        self.attempt.settle();
        match result {
            Ok(outcome) => outcome,
            Err(reason) => (CompletionOutcome::NotPublished(reason), Vec::new()),
        }
    }
}

/// Coordinator-side handle for the live dependency lane.
#[derive(Debug, Clone)]
pub struct LiveDependencyLane {
    coord: Arc<CoordLive>,
    worker: Arc<Mutex<Option<WorkerSessionOffer>>>,
}

static OPERATION_SERIAL: AtomicU64 = AtomicU64::new(1);

fn now_micros() -> i64 {
    i64::try_from(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |elapsed| elapsed.as_micros()),
    )
    .unwrap_or(i64::MAX)
}

fn host_name() -> String {
    std::fs::read_to_string("/proc/sys/kernel/hostname")
        .ok()
        .map(|name| name.trim().to_owned())
        .filter(|name| !name.is_empty())
        .unwrap_or_else(|| "localhost".to_owned())
}

fn object_id(bytes: &[u8]) -> Result<TypedDigest, String> {
    digest_set(bytes, DigestRequest::default(), None)
        .map(|digests| digests.atp_content_id)
        .map_err(|error| format!("digest: {error:?}"))
}

/// Durably store one object. The store lock is held for this object only.
fn put_bytes(cas: &crate::janitor::store::LiveCas, bytes: &[u8]) -> Result<ObjectId, String> {
    let id = object_id(bytes)?;
    let mut store = cas.store().lock().map_err(|_| "store lock poisoned")?;
    put_if_absent(
        cas.layout(),
        &mut *store,
        &id,
        &mut &bytes[..],
        PutLimits {
            max_logical_bytes: Some(bytes.len() as u64),
            expected_size: Some(bytes.len() as u64),
        },
        DurabilityPolicy::FULL,
    )
    .map_err(|error| format!("put: {error:?}"))?;
    Ok(ObjectId(id))
}

/// Persist the canonical bundle-root bytes so the derived root is a
/// durably located object with real bytes behind it (publication requires
/// the complete closure, including the root, to be durable).
fn put_bundle_root(
    cas: &crate::janitor::store::LiveCas,
    outputs: &[LogicalOutput],
) -> Result<(), String> {
    use std::io::Write;
    let bytes = rabs_key::logical_output_map::bundle_root_bytes(outputs)
        .ok_or("an empty output map has no bundle root")?;
    let root = rabs_key::logical_output_map::compute_bundle_root(outputs)
        .ok_or("an empty output map has no bundle root")?;
    // Held through the write and the location record: a concurrent
    // completion of the same result must not race the staging name.
    let mut store = cas.store().lock().map_err(|_| "store lock poisoned")?;
    if store
        .object_durably_located(&root.0)
        .map_err(|error| format!("{error:?}"))?
    {
        return Ok(());
    }
    let directory = cas.layout().root().join("bundle-roots");
    std::fs::create_dir_all(&directory).map_err(|error| error.to_string())?;
    let hex: String = root
        .0
        .bytes
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    let final_path = directory.join(format!("{hex}.{BUNDLE_ROOT_ENCODING}"));
    let staging = directory.join(format!("{hex}.{}.staging", std::process::id()));
    {
        let mut file = std::fs::File::create(&staging).map_err(|error| error.to_string())?;
        file.write_all(&bytes).map_err(|error| error.to_string())?;
        file.sync_all().map_err(|error| error.to_string())?;
    }
    std::fs::rename(&staging, &final_path).map_err(|error| error.to_string())?;
    std::fs::File::open(&directory)
        .and_then(|dir| dir.sync_all())
        .map_err(|error| error.to_string())?;
    let path = final_path.to_str().ok_or("non-UTF-8 CAS root")?;
    store
        .record_object(&root.0, bytes.len() as u64)
        .map_err(|error| format!("{error:?}"))?;
    store
        .add_location(&root.0, path, None, BUNDLE_ROOT_ENCODING, true)
        .map_err(|error| format!("{error:?}"))
}

fn output_role(class: OutputClass) -> OutputRole {
    match class {
        OutputClass::DepInfo => OutputRole::DepInfo,
        OutputClass::ProvisionalMetadata => OutputRole::ProvisionalMetadata,
        _ => OutputRole::Materializable,
    }
}

/// Load the canonical transcript bound to a committed manifest. `None`
/// when the binding is absent, unreadable, or does not reproduce the
/// committed observable digest — a hit then cannot be replayed exactly.
fn load_bound_transcript(
    store: &mut dyn RabsMetadataStore,
    manifest: &CanonicalActionResultManifest,
) -> Option<Vec<u8>> {
    use std::io::Read;
    let rows = store
        .query(
            "SELECT decision FROM decision_receipts WHERE kind = ?1 AND subject = ?2 AND seq = 0",
            &[
                SqlValue::Text(LIVE_TRANSCRIPT_RECEIPT.to_owned()),
                SqlValue::Text(digest_key(&manifest.action_key)),
            ],
        )
        .ok()?;
    let [row] = rows.as_slice() else {
        return None;
    };
    let [SqlValue::Text(object_key)] = row.as_slice() else {
        return None;
    };
    let hex = object_key
        .strip_prefix(rabs_cas::digest_set::ATP_OBJECT_CONTENT_DOMAIN)?
        .strip_prefix(':')?;
    if hex.len() != 64 {
        return None;
    }
    let mut bytes = [0_u8; 32];
    for (index, slot) in bytes.iter_mut().enumerate() {
        *slot = u8::from_str_radix(hex.get(index * 2..index * 2 + 2)?, 16).ok()?;
    }
    let id = TypedDigest {
        algorithm: rabs_protocol::result_identity::DigestAlgorithm::Sha256V1,
        domain: rabs_cas::digest_set::ATP_OBJECT_CONTENT_DOMAIN,
        bytes,
    };
    if observable_result_digest_v1(manifest, &id) != manifest.observable_result_digest {
        return None;
    }
    for (path, encoding, _) in store.object_locations(&id).ok()? {
        if encoding != rabs_cas::blob_store::RAW_PROFILE_V1
            || !std::fs::symlink_metadata(&path).is_ok_and(|meta| meta.file_type().is_file())
        {
            continue;
        }
        let Ok(file) = std::fs::File::open(&path) else {
            continue;
        };
        let mut transcript = Vec::new();
        if file
            .take(MAX_TRANSCRIPT_BYTES as u64 + 1)
            .read_to_end(&mut transcript)
            .is_err()
            || transcript.len() > MAX_TRANSCRIPT_BYTES
        {
            continue;
        }
        if object_id(&transcript).ok()? == id {
            return Some(transcript);
        }
    }
    None
}

impl LiveDependencyLane {
    /// The lane over a live coordinator.
    #[must_use]
    pub fn new(coord: Arc<CoordLive>) -> Self {
        Self {
            coord,
            worker: Arc::new(Mutex::new(None)),
        }
    }

    /// Admit (once per coordinator incarnation) the edge host's local
    /// executor as a worker session.
    fn local_worker(&self) -> Result<WorkerSessionOffer, String> {
        let authority = self.coord.authority().ok_or("no coordinator authority")?;
        let mut slot = self.worker.lock().map_err(|_| "worker slot poisoned")?;
        if let Some(offer) = slot.as_ref()
            && offer.boot_generation == WorkerBootGeneration(authority.term)
        {
            return Ok(offer.clone());
        }
        let offer = WorkerSessionOffer {
            worker_peer_id: PeerId(format!("edge-local:{}", host_name())),
            boot_generation: WorkerBootGeneration(authority.term),
            incarnation: WorkerIncarnationId(authority.incarnation_id.0),
            reenrollment_proof: None,
        };
        let (admission, started) = self.coord.admit_worker_session(&offer)?;
        if started.is_none() {
            return Err(format!("local executor not admitted: {admission:?}"));
        }
        *slot = Some(offer.clone());
        Ok(offer)
    }

    /// Preview a hit if a verified, replayable result exists; otherwise
    /// admit one private execution or report its existing dispatch owner.
    /// In-flight is not a cache hit: followers retry through this same preview
    /// and sampling gate, including any additional private verification run.
    #[must_use]
    pub fn decide(&self, request: LiveDependencyRequest) -> LiveDecision {
        let request = match self.preview(request) {
            Ok(Ok(pending)) => return LiveDecision::Hit(pending),
            Ok(Err(request)) => request,
            // Preview writes no target file, so the compiler may run; it
            // runs unobserved (this request offers no evidence).
            Err(reason) => return LiveDecision::PassThrough(format!("serve-fault: {reason}")),
        };
        match self.begin_execution(request) {
            Ok(Some(attempt)) => LiveDecision::Execute(attempt),
            Ok(None) => LiveDecision::InFlight,
            Err(reason) => LiveDecision::PassThrough(reason),
        }
    }

    /// `Ok(Ok(_))` = servable now; `Ok(Err(request))` = execute privately.
    fn preview(
        &self,
        request: LiveDependencyRequest,
    ) -> Result<Result<PendingServe, LiveDependencyRequest>, String> {
        let cas = self.coord.live_cas().ok_or("no CAS mounted")?;
        let key = request.key.action_key.clone();
        let loaded = {
            let mut store = cas.store().lock().map_err(|_| "store lock poisoned")?;
            match store
                .published_manifest_key(&key)
                .map_err(|error| format!("{error:?}"))?
            {
                None => None,
                Some(manifest_key) => {
                    load_manifest(&mut *store, &manifest_key).and_then(|manifest| {
                        load_bound_transcript(&mut *store, &manifest)
                            .map(|transcript| (manifest, transcript))
                    })
                }
            }
        };
        let Some((manifest, canonical_transcript)) = loaded else {
            return Ok(Err(request));
        };
        let expected = expected_outputs(&request.plan);
        match self.coord.serve_for_subscriber(
            &key,
            Path::new(&request.plan.out_dir),
            &expected,
            now_micros(),
            ServeMode::Preview,
        ) {
            Ok(ServeOutcome::Servable) => Ok(Ok(PendingServe {
                coord: Arc::clone(&self.coord),
                request,
                manifest,
                canonical_transcript,
            })),
            Ok(_) => Ok(Err(request)),
            Err(error) => Err(error.to_string()),
        }
    }

    fn begin_execution(
        &self,
        request: LiveDependencyRequest,
    ) -> Result<Option<LocalAttempt>, String> {
        let key = request.key.action_key.clone();
        let refusal = |error: SubmissionRefusal| format!("submission: {error:?}");
        if self.coord.submitted_actor(&key).map_err(refusal)?.is_some() {
            return Ok(None);
        }
        let worker = self.local_worker()?;
        {
            let cas = self.coord.live_cas().ok_or("no CAS mounted")?;
            let mut store = cas.store().lock().map_err(|_| "store lock poisoned")?;
            store
                .upsert_action_entry(&ActionEntryRow {
                    action_key: key.clone(),
                    key_epoch: LIVE_DEPENDENCY_KEY_EPOCH,
                    projection_epoch: LIVE_DEPENDENCY_PROJECTION_EPOCH,
                })
                .map_err(|error| format!("action entry: {error:?}"))?;
        }
        let mappings = mappings_for_plan(&request.plan);
        let submission = ActionSubmission::from_snapshot(
            request.key.descriptor.clone(),
            &request.inputs,
            Arc::clone(&request.package.snapshot),
            &mappings,
        )
        .map_err(refusal)?;
        if submission.key() != key {
            return Err("submission key differs from the edge key".into());
        }
        let join = JoinRequest {
            operation: BuildOperationId(u128::from(
                OPERATION_SERIAL.fetch_add(1, Ordering::Relaxed),
            )),
            kind: SubscriberKind::ForegroundAgent,
            queue_priority: 200,
            deadline_unix_micros: None,
            presentation: compute(
                "rabs.live-dependency.presentation.v1",
                request.plan.out_dir.as_bytes(),
            ),
            requirements: SubscriptionRequirements::unrestricted(),
        };
        self.coord
            .submit_action(submission, join, now_micros(), 0)
            .map_err(refusal)?;
        let Some(serial) = self.coord.claim_submitted_dispatch(&key).map_err(refusal)? else {
            // The atomic dispatch claim, not the optimistic lookup above,
            // arbitrates concurrent requests. Losing it means wait, not a
            // second unobserved compiler run in another subscriber's tree.
            return Ok(None);
        };
        let mut attempt = LocalAttempt {
            coord: Arc::clone(&self.coord),
            key,
            serial,
            authority: None,
            request,
            settled: false,
        };
        let authority = self
            .coord
            .begin_claimed_dispatch(&attempt.key, serial, &worker, LOCAL_LEASE_TTL_MS)
            .map_err(refusal)?;
        attempt.authority = Some(authority);
        for state in [
            AttemptState::LeaseAccepted,
            AttemptState::AwaitingInputs,
            AttemptState::Materializing,
            AttemptState::Running,
        ] {
            attempt.advance(state)?;
        }
        Ok(Some(attempt))
    }
}

/// One admitted local execution. Dropping it unsettled drains and
/// finishes the attempt WITHOUT publication. Capturing consumes this owner
/// and retains it until the result is published or abandoned.
#[derive(Debug)]
pub struct LocalAttempt {
    coord: Arc<CoordLive>,
    key: TypedDigest,
    serial: u64,
    authority: Option<AttemptAuthority>,
    request: LiveDependencyRequest,
    settled: bool,
}

impl LocalAttempt {
    /// The constructed environment the compiler must run with.
    #[must_use]
    pub fn execution_env(&self) -> &[(String, String)] {
        &self.request.plan.execution_env
    }

    /// The admitted attempt id (hex), for receipts.
    #[must_use]
    pub fn attempt_hex(&self) -> String {
        self.authority
            .as_ref()
            .map(|authority| format!("{:032x}", authority.attempt_id.0))
            .unwrap_or_default()
    }

    /// The exact action key.
    #[must_use]
    pub fn action_key(&self) -> &TypedDigest {
        &self.key
    }

    fn advance(&self, state: AttemptState) -> Result<(), String> {
        let authority = self.authority.as_ref().ok_or("attempt not admitted")?;
        self.coord
            .advance_started_dispatch(&self.key, self.serial, authority, state)
            .map_err(|error| format!("attempt {state:?}: {error:?}"))
    }

    /// Drain → Finished → complete the dispatch → retire the flight, so
    /// the next request for this key can submit a fresh attempt.
    fn settle(&mut self) {
        if self.settled {
            return;
        }
        self.settled = true;
        let Some(authority) = self.authority.as_ref() else {
            self.coord.release_dispatch_claim(&self.key, self.serial);
            return;
        };
        let finished = self
            .coord
            .advance_started_dispatch(&self.key, self.serial, authority, AttemptState::Draining)
            .and_then(|()| {
                self.coord.advance_started_dispatch(
                    &self.key,
                    self.serial,
                    authority,
                    AttemptState::Finished,
                )
            })
            .and_then(|()| {
                self.coord
                    .complete_started_dispatch(&self.key, self.serial, authority)
            })
            .and_then(|()| self.coord.retire_finished_action(&self.key).map(|_| ()));
        if finished.is_err() {
            // Leave the reconciliation-required state rather than guess.
            self.coord.release_dispatch_claim(&self.key, self.serial);
        }
    }

    /// Complete a locally owned execution without a transport handoff.
    pub fn complete(self, report: &CompletionReport) -> (CompletionOutcome, Vec<KnownOutput>) {
        match self.capture(report) {
            Ok(captured) => captured.publish(),
            Err(reason) => (CompletionOutcome::NotPublished(reason), Vec::new()),
        }
    }

    /// Capture every declared output, transcript and evidence object into CAS.
    /// This never commits an action pointer. On failure the consumed attempt
    /// is settled; on success the returned opaque owner can be acknowledged
    /// and published later without reopening any caller-owned file.
    pub fn capture(self, report: &CompletionReport) -> Result<CapturedLocalAttempt, String> {
        let result = self.capture_result(report)?;
        Ok(CapturedLocalAttempt {
            attempt: self,
            result,
        })
    }

    #[allow(clippy::too_many_lines)]
    fn capture_result(&self, report: &CompletionReport) -> Result<CapturedLocalResult, String> {
        self.advance(AttemptState::ProcessExited)?;
        if report.signal.is_some() || report.exit_code != Some(0) {
            return Err(format!(
                "compiler exit {:?} signal {:?}",
                report.exit_code, report.signal
            ));
        }
        if !report.stdout.is_empty() {
            return Err("compiler wrote to stdout".into());
        }
        if report.stderr.len() > MAX_TRANSCRIPT_BYTES {
            return Err("transcript exceeds the class bound".into());
        }
        let plan = &self.request.plan;
        self.request
            .package
            .verify_unchanged(Path::new(&plan.source_root))?;
        self.request.package.verify_generated_disjoint(plan)?;
        self.request.dependencies.verify_unchanged()?;
        let input_roots = mappings_for_plan(plan);
        // Harvest every declared output (and nothing else).
        let mut harvested = Vec::new();
        for declaration in &plan.outputs.declarations {
            let path = Path::new(&plan.out_dir).join(&declaration.virtual_path);
            let (sig, raw) = read_stable(&path, MAX_OUTPUT_BYTES)
                .map_err(|error| format!("output {}: {error}", declaration.virtual_path))?;
            let committed_bytes = if declaration.class == OutputClass::DepInfo {
                if let Some(violation) = dep_info_closure_violation(plan, &raw, |virtual_path| {
                    input_roots.iter().any(|(logical, visible)| {
                        virtual_path.strip_prefix(&format!("{visible}/")).is_some_and(|relative| {
                            self.request.package.snapshot.manifest(logical).is_some_and(|manifest| {
                                matches!(manifest.members.get(relative), Some(rabs_sandbox::snapshot_capture::MemberKind::Regular { .. }))
                            })
                        })
                    })
                }) {
                    return Err(format!("closure: {violation}"));
                }
                canonicalize_placements(&raw, plan)?
            } else {
                raw
            };
            harvested.push((declaration, path, sig, committed_bytes));
        }
        let transcript = canonicalize_placements(&report.stderr, plan)?;
        // The complete capture must be from one stable input generation, not
        // just start with one. After this barrier publication uses CAS only.
        self.request
            .package
            .verify_unchanged(Path::new(&plan.source_root))?;
        self.request.package.verify_generated_disjoint(plan)?;
        self.request.dependencies.verify_unchanged()?;
        self.advance(AttemptState::HarvestingOutputs)?;

        let cas = self.coord.live_cas().ok_or("no CAS mounted")?;
        let authority = self.authority.clone().ok_or("attempt not admitted")?;
        let mut logical_outputs = Vec::with_capacity(harvested.len());
        let mut known = Vec::new();
        // Lock order is submissions -> store everywhere in the coordinator:
        // never advance the attempt while holding the store.
        self.advance(AttemptState::UploadingOutputs)?;
        // Each put takes the store lock for itself only: decisions for other
        // compiles must not queue behind a whole completion's fsyncs. The
        // commit transaction re-verifies the complete durable closure.
        let (transcript_id, evidence_parts) = {
            for (declaration, path, sig, bytes) in &harvested {
                let object = put_bytes(cas, bytes)?;
                if declaration.class != OutputClass::DepInfo {
                    known.push(KnownOutput {
                        path: path.clone(),
                        sig: *sig,
                        digest: object.0.clone(),
                    });
                }
                logical_outputs.push(LogicalOutput {
                    role: output_role(declaration.class),
                    virtual_path: RawBytes::new(declaration.virtual_path.as_bytes().to_vec()),
                    object,
                });
            }
            put_bundle_root(cas, &logical_outputs)?;
            let transcript_id = put_bytes(cas, &transcript)?;
            let hex =
                |bytes: &[u8]| -> String { bytes.iter().map(|b| format!("{b:02x}")).collect() };
            let snapshot = serde_json::to_vec(&serde_json::json!({
                "kind": "rabs-live-dependency-snapshot-v1",
                "package_root": plan.package_root,
                "source_root": plan.source_root,
                "source_kind": plan.source_kind.as_str(),
                "generated_root": plan.generated_root,
                "build_script_output": self.request.package.build_script_output,
                "package_closure_sha256": hex(&self.request.package.snapshot.closure_digest()),
                "input_manifest": digest_key(&self.request.key.descriptor.action_inputs),
            }))
            .map_err(|error| error.to_string())?;
            let observed = serde_json::to_vec(&serde_json::json!({
                "kind": "rabs-live-dependency-observed-inputs-v2",
                "externs": self.request.externs.iter()
                    .map(|(path, digest)| serde_json::json!([path, digest_key(digest)]))
                    .collect::<Vec<_>>(),
                "dependency_directories": self.request.dependencies.directories.iter().map(|directory| {
                    serde_json::json!({
                        "path": directory.path,
                        "artifacts": directory.artifacts.iter().map(|artifact| serde_json::json!([artifact.path, digest_key(&artifact.content_digest)])).collect::<Vec<_>>(),
                    })
                }).collect::<Vec<_>>(),
                "compiler": plan.compiler,
                "out_dir": plan.out_dir,
            }))
            .map_err(|error| error.to_string())?;
            let process = serde_json::to_vec(&serde_json::json!({
                "kind": "rabs-live-dependency-process-v1",
                "exit_code": report.exit_code,
                "stderr_bytes": report.stderr.len(),
                "stderr": digest_key(&object_id(&report.stderr)?),
                "stdout_bytes": report.stdout.len(),
            }))
            .map_err(|error| error.to_string())?;
            let provenance = serde_json::to_vec(&serde_json::json!({
                "kind": "rabs-live-dependency-provenance-v1",
                "attempt": format!("{:032x}", authority.attempt_id.0),
                "generation": format!("{:032x}", authority.action_generation.generation_id.0),
                "worker": authority.worker_peer_id.0,
                "finished_unix_micros": now_micros(),
                "rabsd_version": env!("CARGO_PKG_VERSION"),
            }))
            .map_err(|error| error.to_string())?;
            let parts = [
                put_bytes(cas, &snapshot)?,
                put_bytes(cas, &observed)?,
                put_bytes(cas, &process)?,
                put_bytes(cas, &provenance)?,
            ];
            (transcript_id, parts)
        };
        self.advance(AttemptState::VerifyingOutputs)?;

        let declared: Vec<(OutputRole, RawBytes)> = logical_outputs
            .iter()
            .map(|output| (output.role, output.virtual_path.clone()))
            .collect();
        let manifest = CanonicalActionResultManifest {
            action_key: self.key.clone(),
            canonical_descriptor_digest: self.request.key.descriptor_digest.clone(),
            key_epoch: LIVE_DEPENDENCY_KEY_EPOCH,
            projection_epoch: LIVE_DEPENDENCY_PROJECTION_EPOCH,
            result_kind: ResultKind::Success,
            artifact_bundle_root: None,
            logical_outputs,
            semantic_result_digest: self.request.key.descriptor_digest.clone(),
            observable_result_digest: self.request.key.descriptor_digest.clone(),
        };
        let evidence = |manifest_id: &ObjectId| AttemptEvidenceBundle {
            action_key: self.key.clone(),
            canonical_result_manifest_id: manifest_id.clone(),
            execution_snapshot_root: evidence_parts[0].clone(),
            observed_input_report: evidence_parts[1].clone(),
            raw_process_and_event_evidence: evidence_parts[2].clone(),
            provenance_receipt: evidence_parts[3].clone(),
            incremental_snapshot: None,
        };
        // Two passes: stamping fixes the manifest bytes, whose content id
        // the evidence bundle and the offer must then name.
        let stamped = OfferPreparedActionResult::build(
            authority.clone(),
            manifest,
            transcript_id.clone(),
            evidence(&transcript_id),
            transcript_id.clone(),
            transcript_id.0.clone(),
            &declared,
            Vec::new(),
        )
        .map_err(|error| format!("offer: {error:?}"))?;
        let manifest_bytes = encode_manifest_v1(&stamped.manifest);
        let evidence_bytes = |manifest_id: &ObjectId| -> Result<Vec<u8>, String> {
            let bundle = evidence(manifest_id);
            serde_json::to_vec(&serde_json::json!({
                "kind": "rabs-attempt-evidence-bundle-v1",
                "action_key": digest_key(&bundle.action_key),
                "manifest": digest_key(&bundle.canonical_result_manifest_id.0),
                "snapshot": digest_key(&bundle.execution_snapshot_root.0),
                "observed_inputs": digest_key(&bundle.observed_input_report.0),
                "process": digest_key(&bundle.raw_process_and_event_evidence.0),
                "provenance": digest_key(&bundle.provenance_receipt.0),
            }))
            .map_err(|error| error.to_string())
        };
        let manifest_id = put_bytes(cas, &manifest_bytes)?;
        let evidence_id = put_bytes(cas, &evidence_bytes(&manifest_id)?)?;
        let offer = OfferPreparedActionResult::build(
            authority,
            stamped.manifest,
            manifest_id.clone(),
            evidence(&manifest_id),
            evidence_id,
            transcript_id.0.clone(),
            &declared,
            Vec::new(),
        )
        .map_err(|error| format!("offer: {error:?}"))?;
        if encode_manifest_v1(&offer.manifest) != manifest_bytes {
            return Err("re-stamping changed the manifest bytes".into());
        }
        self.advance(AttemptState::PreparedResultOffered)?;
        Ok(CapturedLocalResult {
            offer,
            transcript: transcript_id,
            manifest_key: digest_key(&manifest_id.0),
            known,
        })
    }

    fn publish_captured(
        &self,
        captured: CapturedLocalResult,
    ) -> Result<(CompletionOutcome, Vec<KnownOutput>), String> {
        let CapturedLocalResult {
            offer,
            transcript,
            known,
            ..
        } = captured;
        let cas = self.coord.live_cas().ok_or("no CAS mounted")?;
        let outcome = match self
            .coord
            .commit_offer(&offer, &self.request.key.descriptor_digest)
        {
            Ok(PublicationOutcome::Committed(_)) => {
                self.advance(AttemptState::AcceptedAsWinner)?;
                CompletionOutcome::Committed
            }
            Ok(PublicationOutcome::IdempotentEvidenceAppended) => {
                self.advance(AttemptState::RejectedAsDuplicate)?;
                CompletionOutcome::Verified
            }
            Ok(PublicationOutcome::Quarantined(_)) => {
                self.advance(AttemptState::RejectedAsDivergent)?;
                return Ok((CompletionOutcome::Quarantined, known));
            }
            Err(refusal) => {
                self.advance(AttemptState::RejectedAsStale)?;
                return Ok((CompletionOutcome::Refused(refusal.to_string()), known));
            }
        };
        // Index the transcript for replay. Identical re-records are
        // idempotent; the binding is re-verified on every serve.
        let mut store = cas.store().lock().map_err(|_| "store lock poisoned")?;
        let _ = store.record_decision_receipt(
            LIVE_TRANSCRIPT_RECEIPT,
            &digest_key(&self.key),
            0,
            &digest_key(&transcript.0),
            "canonical stderr transcript of the committed live dependency result",
        );
        Ok((outcome, known))
    }
}

impl Drop for LocalAttempt {
    fn drop(&mut self) {
        self.settle();
    }
}
