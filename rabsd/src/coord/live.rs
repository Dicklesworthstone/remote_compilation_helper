//! The live coordinator state (bead S6 / bridge plan Phase S): the
//! first live mounts of the D024 [`TargetLeaseRegistry`], the D031
//! [`DestinationArbiter`], and a singleflight table keyed by the Epic F
//! action key. One binary, structural authority split (plan §10): the
//! edge routes every consult through THIS state in-process, and the
//! coord region owns its lifecycle.
//!
//! ## Shadow-tier singleflight window
//!
//! Production singleflight closes a flight when the action COMPLETES.
//! In shadow tier nothing completes through us — the wrapper execs the
//! compiler and its connection closes (fds are CLOEXEC). The flight
//! window is therefore CONNECTION-SCOPED: begin at consult, end when
//! the connection drops. Two overlapping consults for one key yield
//! exactly one leader and N followers, observable and receipted. (This
//! is also the design direction: a serving wrapper will hold its
//! connection through the compile, making the window the real one.)
//!
//! ## Degraded mode
//!
//! If the coord region is down (lab-injected today, crashed tomorrow),
//! edge consults DO NOT fail: they answer in the typed
//! `shadow-coord-degraded` mode — fail-open extends to the authority
//! split itself, and the shutdown receipt shows the coord region
//! abandoned so nothing hides.

use crate::coord::action_actor::{
    ActionActor, AttemptPurpose, JoinReceipt, JoinRequest, OpenGenerationReceipt, RegisterAttempt,
    RegisterAttemptReceipt,
};
use crate::coord::target_lease::TargetLeaseRegistry;
use crate::edge::destination_arbiter::{BundleId, DestinationArbiter};
use crate::janitor::store::LiveCas;
use rabs_cas::blob_store::RAW_PROFILE_V1;
use rabs_cas::digest_set::ATP_OBJECT_CONTENT_DOMAIN;
use rabs_cas::digest_set::{DigestRequest, digest_set};
use rabs_cas::manifest_codec::decode_manifest_v1;
use rabs_cas::materialization::{decide_materialization, materialize_object};
use rabs_cas::metadata_store::{AuthorityRow, RabsMetadataStore, StoreError, digest_key};
use rabs_cas::publication::{
    AUTHORITY_DIGEST_DOMAIN, CommitDurabilityProfile, OBSERVABLE_PROJECTION_DOMAIN,
    OfferPreparedActionResult, OfferRefusal, PublicationOutcome, SEMANTIC_PROJECTION_DOMAIN,
    authority_digest, process_offer,
};
use rabs_cas::serving_state::{ServeDecision, serving_gate};
use rabs_key::action_key::{action_input_manifest_digest, compute_action_key};
use rabs_key::logical_output_map::DOMAIN_ARTIFACT_BUNDLE_ROOT;
use rabs_key::typed_digest::{DOMAIN_ACTION_KEY, DOMAIN_DESCRIPTOR};
use rabs_protocol::authority::{ClusterId, CoordinatorAuthority, CoordinatorIncarnationId};
use rabs_protocol::descriptor::{ActionDescriptor, SubscriberKind};
use rabs_protocol::generation::{
    AttemptAuthority, AttemptId, ExecutionLeaseId, LeaseRenewal, LeaseRenewalSeq,
    WorkerIncarnationId,
};
use rabs_protocol::input_evidence::{ActionInputManifest, InputFileType};
use rabs_protocol::result_identity::{
    CanonicalActionResultManifest, DigestAlgorithm, OutputRole, TypedDigest,
};
use rabs_protocol::wire_time::PeerId;
use rabs_protocol::worker_fence::{WorkerAdmission, WorkerSessionOffer};
use rabs_sandbox::snapshot_capture::{MemberKind, SealedSourceSnapshot};
use rabs_scheduler::speculation_brownout::{BrownoutDecision, PressureBand, WorkCategory, decide};
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

/// The role a consult played in its key's flight.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FlightRole {
    /// First open flight for the key.
    Leader,
    /// Joined while the leader's flight is still open.
    Follower,
    /// Coord unavailable: no flight accounting (typed, never silent).
    Degraded,
}

impl FlightRole {
    /// Receipt/report label.
    #[must_use]
    pub fn label(self) -> &'static str {
        match self {
            Self::Leader => "leader",
            Self::Follower => "follower",
            Self::Degraded => "degraded",
        }
    }
}

/// Why a commit did not happen. Every variant is a REFUSAL: nothing was
/// written, and no result may be served on its account.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CommitRefusal {
    /// No store is mounted (the janitor mount failed at boot). The
    /// daemon still runs — builds fall back locally — but it commits
    /// nothing.
    NoStore,
    /// The coordinator has not acquired its authority (coord region
    /// down, or authority acquisition failed at boot).
    NoAuthority,
    /// The offer's CoordinatorAuthority does not match the authority this
    /// incarnation holds: it was prepared under a dead coordinator and can
    /// never publish here (G019; F033 digest equality).
    StaleAuthority {
        /// Term the offering attempt was created under.
        offered_term: u64,
        /// Term this coordinator holds.
        active_term: u64,
    },
    /// The store mutex was poisoned by a panic in another commit.
    StoreUnavailable,
    /// The publication engine refused the offer (typed A018/H011 fence).
    Offer(OfferRefusal),
    /// A store error surfaced outside `process_offer`.
    Store(String),
}

/// Why the live coordinator did not grant or renew a worker-bound
/// execution lease. A refusal never emits an actor message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AttemptLeaseRefusal {
    /// No authoritative CAS metadata store is mounted.
    NoStore,
    /// This coordinator has not acquired its boot authority.
    NoAuthority,
    /// The request belongs to another coordinator incarnation.
    StaleAuthority,
    /// The metadata-store mutex is unavailable.
    StoreUnavailable,
    /// A typed durable authority/fence refusal.
    Store(StoreError),
}

/// Opaque proof that the durable coordinator transaction admitted this
/// exact attempt/lease/worker tuple. Only this module can mint one; the
/// pure action actor consumes it instead of raw worker claims.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidatedAttemptLease {
    authority: AttemptAuthority,
}

impl ValidatedAttemptLease {
    pub(crate) const fn authority(&self) -> &AttemptAuthority {
        &self.authority
    }

    #[cfg(test)]
    pub(crate) const fn for_test(authority: AttemptAuthority) -> Self {
        Self { authority }
    }
}

/// Opaque proof that a durable compare-and-swap accepted one renewal
/// under the exact current worker fence.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidatedLeaseRenewal {
    authority: AttemptAuthority,
    renewal: LeaseRenewal,
}

impl ValidatedLeaseRenewal {
    pub(crate) const fn authority(&self) -> &AttemptAuthority {
        &self.authority
    }

    pub(crate) const fn renewal(&self) -> LeaseRenewal {
        self.renewal
    }

    #[cfg(test)]
    pub(crate) const fn for_test(authority: AttemptAuthority, renewal: LeaseRenewal) -> Self {
        Self { authority, renewal }
    }
}

impl std::fmt::Display for CommitRefusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NoStore => write!(f, "no rabs-cas store mounted"),
            Self::NoAuthority => write!(f, "coordinator holds no active authority"),
            Self::StoreUnavailable => write!(f, "store lock poisoned"),
            Self::Offer(refusal) => write!(f, "offer refused: {refusal:?}"),
            Self::Store(error) => write!(f, "store error: {error}"),
            Self::StaleAuthority {
                offered_term,
                active_term,
            } => write!(
                f,
                "offer prepared under stale coordinator authority \
                 (offered term {offered_term}, active term {active_term})"
            ),
        }
    }
}

/// The answer to a serve request that is not a fault.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ServeOutcome {
    /// Materialized; these files now exist (empty when the committed
    /// manifest declares no materializable output).
    Served {
        /// The destinations written, in manifest order.
        files: Vec<PathBuf>,
    },
    /// The serving gate said no. The typed decision is preserved —
    /// "quarantined" and "expired TTL" are not the same fact.
    NotServable(ServeDecision),
    /// Servable disposition, no publication row: a torn store, never a
    /// hit.
    NoCommit,
    /// The committed manifest's bytes could not be read back (missing
    /// or undecodable copy). Conservative: no hit, nothing written.
    ManifestUnavailable {
        /// The manifest object key that could not be loaded.
        key: String,
    },
    /// The committed result does not produce the output set the caller
    /// said its work would produce. NOT a hit: materializing it would
    /// leave the caller's build missing files it was promised, or
    /// carrying files it never asked for.
    OutputSetMismatch {
        /// Expected by the caller, absent from the commit.
        missing: Vec<String>,
        /// Present in the commit, not expected by the caller.
        unexpected: Vec<String>,
    },
}

/// What the caller says the work it is about to skip would produce.
///
/// A serve that lands a different set of files than the caller's own
/// work would have produced is the one failure mode a cache must never
/// have: a build silently missing (or gaining) a file. So the check is
/// opt-OUT and explicit — never satisfied by a caller that simply forgot
/// to state its expectation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExpectedOutputs {
    /// The caller's derived output set (filenames relative to the
    /// destination root, e.g. from `rabs_key::output_derivation`). The
    /// committed manifest's materializable outputs must equal it
    /// exactly.
    Exactly(std::collections::BTreeSet<String>),
    /// The caller is not skipping any work and accepts whatever the
    /// commit declares: operator and diagnostic paths only. A wrapper
    /// must never use this.
    WhateverWasCommitted,
}

/// Why a serve could not even be attempted. Nothing is written.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ServeError {
    /// No store is mounted.
    NoStore,
    /// A lock was poisoned by a panic elsewhere.
    StoreUnavailable,
    /// The metadata store refused a lookup.
    Store(String),
    /// A manifest's virtual path would escape the destination root.
    /// Refused — a cache hit must never write outside the worktree it
    /// was asked to fill.
    UnsafeVirtualPath {
        /// The offending path, escaped for display.
        path: String,
    },
    /// Another bundle holds an overlapping destination (D031).
    DestinationConflict {
        /// The destination that overlapped.
        path: String,
        /// The bundle holding it.
        holder: String,
    },
    /// Materializing one output failed.
    Materialize {
        /// Which destination.
        path: String,
        /// The typed materialization failure.
        reason: String,
    },
}

impl std::fmt::Display for ServeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NoStore => write!(f, "no rabs-cas store mounted"),
            Self::StoreUnavailable => write!(f, "store lock poisoned"),
            Self::Store(error) => write!(f, "store error: {error}"),
            Self::UnsafeVirtualPath { path } => {
                write!(f, "virtual path {path:?} escapes the destination root")
            }
            Self::DestinationConflict { path, holder } => {
                write!(f, "destination {path} is held by {holder}")
            }
            Self::Materialize { path, reason } => write!(f, "materializing {path}: {reason}"),
        }
    }
}

/// Join a manifest's virtual path under `root`, or `None` if it would
/// leave: absolute paths, any `..` or `.` component, empty paths, and
/// (on unix) embedded NULs are all refused. A served artifact writes
/// where the caller said, or nowhere.
fn resolve_destination(root: &Path, virtual_path: &[u8]) -> Option<PathBuf> {
    use std::os::unix::ffi::OsStrExt;
    if virtual_path.is_empty() || virtual_path.contains(&0) || virtual_path[0] == b'/' {
        return None;
    }
    let mut out = root.to_path_buf();
    let mut components = 0_usize;
    for segment in virtual_path.split(|b| *b == b'/') {
        if segment.is_empty() || segment == b".." || segment == b"." {
            return None;
        }
        out.push(std::ffi::OsStr::from_bytes(segment));
        components += 1;
    }
    (components > 0).then_some(out)
}

/// Materialize every planned output, stopping at the first failure.
fn install_all(
    store: &mut dyn RabsMetadataStore,
    plan: &[(TypedDigest, PathBuf, String)],
) -> Result<Vec<PathBuf>, ServeError> {
    let mut written = Vec::with_capacity(plan.len());
    for (object, path, text) in plan {
        // The destination is a subscriber's mutable target tree, and no
        // reflink isolation has been verified here (nothing computes
        // that yet), so the policy resolves to a private copy.
        let mode = decide_materialization(true, false, false);
        materialize_object(store, object, path, mode).map_err(|e| ServeError::Materialize {
            path: text.clone(),
            reason: e.to_string(),
        })?;
        written.push(path.clone());
    }
    Ok(written)
}

/// Refusal from the shared foreground/speculative submission path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SubmissionRefusal {
    /// The coordinator is down, has no authority, or lost a state lock.
    Unavailable,
    /// Projection schema, path mapping, object identity or executable bit differs.
    InvalidSource(String),
    /// New optional work is stopped at the current pressure band.
    Brownout,
    /// A retained operation cannot silently change its serving requirements.
    ChangedRequirements,
    /// A dispatch claim is stale or has already started.
    StaleDispatch,
    /// A started attempt lost its dispatcher before a confirmed terminal state.
    /// Reconciliation is required; blindly retrying could execute twice.
    UnreconciledAttempt,
    /// The prior execution finished; consult durable serving before a new miss.
    PriorAttemptFinished,
    /// Retained actions reached the bounded admission capacity.
    Capacity,
    /// A monotonic identifier cannot be allocated without reuse.
    IdentityExhausted,
    /// Durable generation or worker-bound lease admission refused.
    Admission(String),
}

#[derive(Debug)]
struct ProjectedFile {
    root: String,
    relative: String,
    executable: bool,
}

/// A descriptor bound to actual retained source bytes BEFORE submission.
/// This initial source lane supports projected regular files. Other positive
/// input kinds need their own verified materializers and are refused explicitly.
/// Invocation, environment and negative-dependency validation remain the edge's
/// responsibility; this constructor is not a parser for untrusted wire requests.
#[derive(Debug)]
pub struct ActionSubmission {
    descriptor: ActionDescriptor,
    source: Arc<SealedSourceSnapshot>,
    files: Vec<ProjectedFile>,
}

impl ActionSubmission {
    /// Validate the positive projection against a coherent image. Mappings are
    /// `(logical snapshot root, canonical visible root)`, e.g. workspace and
    /// `/__rabs/workspace`. Neither physical backing paths nor the full snapshot
    /// digest become action-key inputs.
    pub fn from_snapshot(
        descriptor: ActionDescriptor,
        manifest: &ActionInputManifest,
        source: Arc<SealedSourceSnapshot>,
        mappings: &[(String, String)],
    ) -> Result<Self, SubmissionRefusal> {
        let invalid = |why: &str| SubmissionRefusal::InvalidSource(why.to_owned());
        let digest = action_input_manifest_digest(manifest)
            .map_err(|error| invalid(&format!("invalid input manifest: {error:?}")))?;
        if digest != descriptor.action_inputs {
            return Err(invalid("descriptor input digest does not match projection"));
        }
        if manifest.inputs.is_empty()
            || !manifest.directory_enumerations.is_empty()
            || !manifest.approved_generated_objects.is_empty()
        {
            return Err(invalid(
                "this source lane requires a nonempty regular-file projection",
            ));
        }
        let mut roots = BTreeSet::new();
        for (root, visible) in mappings {
            let canonical_root = visible == rabs_sandbox::layout::WORKSPACE
                || visible
                    .strip_prefix(&format!("{}/", rabs_sandbox::layout::REPOS))
                    .is_some_and(source_component);
            if !canonical_root || !roots.insert(root) || source.manifest(root).is_none() {
                return Err(invalid("invalid or duplicate snapshot root mapping"));
            }
        }
        for (index, (_, visible)) in mappings.iter().enumerate() {
            if mappings[..index].iter().any(|(_, prior)| prior == visible) {
                return Err(invalid("ambiguous canonical root mapping"));
            }
        }
        let mut files = Vec::new();
        let mut paths = BTreeSet::new();
        for input in &manifest.inputs {
            if input.file_type != InputFileType::Regular || !input.symlink_resolution.is_empty() {
                return Err(invalid("unsupported non-regular source projection"));
            }
            let path = std::str::from_utf8(input.virtual_path.as_bytes())
                .map_err(|_| invalid("source path is not lossless UTF-8"))?;
            let (root, relative) = mappings
                .iter()
                .find_map(|(root, visible)| {
                    path.strip_prefix(visible.as_str())
                        .and_then(|suffix| suffix.strip_prefix('/'))
                        .map(|relative| (root, relative))
                })
                .ok_or_else(|| invalid("source path is outside mapped roots"))?;
            if !relative.split('/').all(source_component) {
                return Err(invalid("source path contains unsafe components"));
            }
            if !paths.insert(path.to_owned()) {
                return Err(invalid("duplicate source path"));
            }
            let member = source
                .manifest(root)
                .and_then(|image| image.members.get(relative));
            let Some(MemberKind::Regular { mode, .. }) = member else {
                return Err(invalid(
                    "projected input is absent or not a regular captured file",
                ));
            };
            if (*mode & 0o111 != 0) != input.executable {
                return Err(invalid(
                    "projected executable bit differs from captured file",
                ));
            }
            let bytes = source
                .file_bytes(root, relative)
                .ok_or_else(|| invalid("projected file has no retained bytes"))?;
            let object = digest_set(bytes, DigestRequest::default(), None)
                .map_err(|_| invalid("source object digest failed"))?
                .atp_content_id;
            if input.object.0 != object {
                return Err(invalid("projected object differs from captured bytes"));
            }
            files.push(ProjectedFile {
                root: root.clone(),
                relative: relative.to_owned(),
                executable: input.executable,
            });
        }
        Ok(Self {
            descriptor,
            source,
            files,
        })
    }

    /// Semantic identity, independent of subscriber kind and full image identity.
    #[must_use]
    pub fn key(&self) -> TypedDigest {
        compute_action_key(&self.descriptor).final_key
    }

    /// Materialize ONLY projected files into fresh caller-owned backing. Hidden
    /// parents are created; all file modes are normalized to the keyed executable
    /// bit (0644/0755 on Unix). Execution must mount this backing read-only.
    /// Partial failure leaves inspection state and never returns a usable handle.
    pub fn materialize_into(
        &self,
        destination: &Path,
    ) -> std::io::Result<BTreeMap<String, PathBuf>> {
        use std::io::Write;
        std::fs::create_dir(destination)?;
        let mut backing = BTreeMap::new();
        for file in &self.files {
            let root = destination.join(&file.root);
            let output = root.join(&file.relative);
            let parent = output
                .parent()
                .ok_or_else(|| std::io::Error::other("missing source parent"))?;
            std::fs::create_dir_all(parent)?;
            let mut target = std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&output)?;
            let bytes = self
                .source
                .file_bytes(&file.root, &file.relative)
                .ok_or_else(|| std::io::Error::other("validated source bytes disappeared"))?;
            target.write_all(bytes)?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                target.set_permissions(std::fs::Permissions::from_mode(if file.executable {
                    0o755
                } else {
                    0o644
                }))?;
            }
            backing.insert(file.root.clone(), root);
        }
        Ok(backing)
    }
}

fn source_component(value: &str) -> bool {
    !value.is_empty() && !matches!(value, "." | "..") && !value.contains(['/', '\\', ':', '\0'])
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DispatchState {
    Queued,
    Claimed(u64),
    Started(u64),
    Finished,
    Abandoned,
}

#[derive(Debug)]
struct SubmittedActor {
    actor: ActionActor,
    input: Arc<ActionSubmission>,
    state: DispatchState,
    order: u64,
}

#[derive(Debug, Default)]
struct ActionSubmissions {
    entries: HashMap<TypedDigest, SubmittedActor>,
    serial: u64,
}

impl ActionSubmissions {
    fn next_serial(&mut self) -> Result<u64, SubmissionRefusal> {
        self.serial = self
            .serial
            .checked_add(1)
            .ok_or(SubmissionRefusal::IdentityExhausted)?;
        Ok(self.serial)
    }
}

/// A subscriber joined the coordinator's actual actor, independently of the
/// connection-scoped shadow-flight counters.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SubmissionReceipt {
    pub action_key: TypedDigest,
    pub actor_created: bool,
    pub join: JoinReceipt,
}

/// One non-clone dispatch claim. Dropping it BEFORE `begin` restores queue
/// eligibility. After worker admission, an unconfirmed drop records abandonment
/// and refuses further dispatch until reconciliation: it cannot silently retry
/// a process which may still be running.
#[derive(Debug)]
pub struct ActionDispatch<'a> {
    coord: &'a CoordLive,
    key: TypedDigest,
    serial: u64,
    input: Arc<ActionSubmission>,
    authority: Option<AttemptAuthority>,
    completed: bool,
}

impl ActionDispatch<'_> {
    pub fn input(&self) -> &ActionSubmission {
        &self.input
    }

    /// Grant the durable generation/lease and register exactly one primary.
    /// Call only after fallible source preparation; no process may start before
    /// this returns an admitted authority tuple.
    pub fn begin(
        &mut self,
        worker: &WorkerSessionOffer,
        expires_at_seq: u64,
    ) -> Result<&AttemptAuthority, SubmissionRefusal> {
        if self.authority.is_some() {
            return Err(SubmissionRefusal::StaleDispatch);
        }
        let authority =
            self.coord
                .begin_submitted_dispatch(&self.key, self.serial, worker, expires_at_seq)?;
        self.authority = Some(authority);
        self.authority
            .as_ref()
            .ok_or(SubmissionRefusal::StaleDispatch)
    }

    /// Record an observed worker lifecycle transition using the existing actor
    /// machine. This does not infer that a process ran from a successful lease.
    pub fn advance(
        &self,
        to: rabs_action::state_machines::AttemptState,
    ) -> Result<(), SubmissionRefusal> {
        use crate::coord::action_actor::AdvanceAttemptReceipt;
        let authority = self
            .authority
            .as_ref()
            .ok_or(SubmissionRefusal::StaleDispatch)?;
        let mut submissions = self
            .coord
            .submissions
            .lock()
            .map_err(|_| SubmissionRefusal::Unavailable)?;
        let entry = submissions
            .entries
            .get_mut(&self.key)
            .ok_or(SubmissionRefusal::StaleDispatch)?;
        if entry.state != DispatchState::Started(self.serial) {
            return Err(SubmissionRefusal::StaleDispatch);
        }
        match entry.actor.advance_attempt(authority.attempt_id, to) {
            AdvanceAttemptReceipt::Advanced => Ok(()),
            refusal => Err(SubmissionRefusal::Admission(format!(
                "attempt transition: {refusal:?}"
            ))),
        }
    }

    /// Complete ownership after the worker has confirmed process/stream cleanup
    /// and the attempt reached Finished. This is NOT a cache publication; offers
    /// still go through the coordinator's durable publication gate.
    pub fn complete(mut self) -> Result<(), SubmissionRefusal> {
        let authority = self
            .authority
            .as_ref()
            .ok_or(SubmissionRefusal::StaleDispatch)?;
        let mut submissions = self
            .coord
            .submissions
            .lock()
            .map_err(|_| SubmissionRefusal::Unavailable)?;
        let entry = submissions
            .entries
            .get_mut(&self.key)
            .ok_or(SubmissionRefusal::StaleDispatch)?;
        if entry.state != DispatchState::Started(self.serial)
            || !entry.actor.attempts().any(|attempt| {
                attempt.attempt == authority.attempt_id
                    && attempt.state == rabs_action::state_machines::AttemptState::Finished
            })
        {
            return Err(SubmissionRefusal::StaleDispatch);
        }
        entry.state = DispatchState::Finished;
        self.completed = true;
        Ok(())
    }
}

impl Drop for ActionDispatch<'_> {
    fn drop(&mut self) {
        if self.completed {
            return;
        }
        if let Ok(mut submissions) = self.coord.submissions.lock()
            && let Some(entry) = submissions.entries.get_mut(&self.key)
        {
            match entry.state {
                DispatchState::Claimed(serial) if serial == self.serial => {
                    entry.state = DispatchState::Queued
                }
                DispatchState::Started(serial) if serial == self.serial => {
                    entry.state = DispatchState::Abandoned
                }
                _ => {}
            }
        }
    }
}

/// The live coordinator state shared edge↔coord in-process.
#[derive(Default)]
pub struct CoordLive {
    available: AtomicBool,
    leases: Mutex<TargetLeaseRegistry>,
    arbiter: Mutex<DestinationArbiter>,
    flights: Mutex<HashMap<String, u64>>,
    /// Actual keyed actors and dispatch ownership; shared by all subscriber kinds.
    submissions: Mutex<ActionSubmissions>,
    speculation_pressure: Mutex<Option<PressureBand>>,
    /// The durable store, shared with the janitor region that mounted it.
    /// `None` when the mount failed: the daemon runs, but the coordinator
    /// refuses every commit rather than pretending to have one.
    cas: Option<std::sync::Arc<LiveCas>>,
    /// The authority acquired at coord boot; `None` until then.
    authority: Mutex<Option<CoordinatorAuthority>>,
    /// High half of every pin id this incarnation allocates: pin ids must
    /// not collide with pins written by a previous boot, and the store has
    /// no id allocator. Seeded from the boot instant.
    boot_nonce: u64,
    /// Low half of the pin id (monotone within the incarnation).
    next_pin: AtomicU64,
    /// Causal sequence for publications/incidents. Seeded from the boot
    /// instant so it stays monotone across restarts (append-only incident
    /// rows are keyed by (action, seq); a reused seq with different
    /// content is a typed store refusal, never a silent patch).
    next_seq: AtomicU64,
    /// Generations closed by this incarnation's authority acquisition
    /// (G020/R120): every still-active generation minted under a PRIOR
    /// authority, tombstoned at boot so no prior-authority attempt can
    /// ever publish.
    closed_prior_generations: AtomicU64,
}

impl std::fmt::Debug for CoordLive {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CoordLive")
            .field("available", &self.available())
            .field("cas_mounted", &self.cas.is_some())
            .field(
                "authority_held",
                &self.authority.lock().is_ok_and(|a| a.is_some()),
            )
            .finish_non_exhaustive()
    }
}

/// Microseconds since the Unix epoch, or 0 if the clock is before it.
/// Used only to seed monotone-across-restart counters.
fn boot_micros() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| u64::try_from(d.as_micros()).unwrap_or(u64::MAX))
}

impl CoordLive {
    /// New, with no store (unavailable until the coord region marks
    /// itself up). Commits refuse with [`CommitRefusal::NoStore`].
    #[must_use]
    pub fn new() -> Self {
        Self {
            boot_nonce: boot_micros(),
            next_seq: AtomicU64::new(boot_micros()),
            ..Self::default()
        }
    }

    /// New, sharing the store the janitor region mounted.
    #[must_use]
    pub fn with_cas(cas: std::sync::Arc<LiveCas>) -> Self {
        Self {
            cas: Some(cas),
            ..Self::new()
        }
    }

    /// Set optional-work admission pressure. Foreground joins remain eligible.
    /// Already-started work is not cancelled here (Q006 owns that policy).
    pub fn set_speculation_pressure(
        &self,
        pressure: PressureBand,
    ) -> Result<(), SubmissionRefusal> {
        *self
            .speculation_pressure
            .lock()
            .map_err(|_| SubmissionRefusal::Unavailable)? = Some(pressure);
        Ok(())
    }

    fn optional_admitted(&self) -> Result<bool, SubmissionRefusal> {
        let pressure = self
            .speculation_pressure
            .lock()
            .map_err(|_| SubmissionRefusal::Unavailable)?;
        Ok(decide(
            WorkCategory::NewSpeculation,
            pressure.unwrap_or(PressureBand::Normal),
        ) == BrownoutDecision::Admit)
    }

    /// Submit a cache-miss demand to the ONE coordinator actor registry. Both
    /// foreground and speculation use this path. Callers attempt durable serving
    /// separately; no raw execution observation is treated as a cache hit here.
    /// Source validation has already run in `ActionSubmission::from_snapshot`.
    pub fn submit_action(
        &self,
        input: ActionSubmission,
        mut request: JoinRequest,
        now_unix_micros: i64,
        clock_epoch: u64,
    ) -> Result<SubmissionReceipt, SubmissionRefusal> {
        if !self.available() || self.cas.is_none() {
            return Err(SubmissionRefusal::Unavailable);
        }
        let authority = self.authority().ok_or(SubmissionRefusal::Unavailable)?;
        let optional = matches!(
            request.kind,
            SubscriberKind::Speculative | SubscriberKind::GitPrewarm
        );
        if optional && !self.optional_admitted()? {
            return Err(SubmissionRefusal::Brownout);
        }
        // Caller-provided numeric priority cannot make optional work compete in
        // the foreground class; within the class it remains an ordering hint.
        if optional {
            request.queue_priority = request.queue_priority.min(199);
        }
        let key = input.key();
        let mut submissions = self
            .submissions
            .lock()
            .map_err(|_| SubmissionRefusal::Unavailable)?;
        if let Some(entry) = submissions.entries.get_mut(&key) {
            if entry.state == DispatchState::Abandoned {
                return Err(SubmissionRefusal::UnreconciledAttempt);
            }
            if entry.state == DispatchState::Finished {
                return Err(SubmissionRefusal::PriorAttemptFinished);
            }
            if entry.actor.descriptor() != &input.descriptor {
                return Err(SubmissionRefusal::InvalidSource(
                    "same key has a different descriptor".into(),
                ));
            }
            if entry
                .actor
                .subscriber(&request.operation)
                .is_some_and(|existing| existing.requirements != request.requirements)
            {
                return Err(SubmissionRefusal::ChangedRequirements);
            }
            let join = entry.actor.join(request, now_unix_micros, clock_epoch);
            return Ok(SubmissionReceipt {
                action_key: key,
                actor_created: false,
                join,
            });
        }
        const MAX_RETAINED_ACTIONS: usize = 1024;
        if submissions.entries.len() >= MAX_RETAINED_ACTIONS {
            return Err(SubmissionRefusal::Capacity);
        }
        let order = submissions.next_serial()?;
        let mut actor = ActionActor::new(
            input.descriptor.clone(),
            &authority,
            &authority.cluster_id.0,
            now_unix_micros,
        );
        let join = actor.join(request, now_unix_micros, clock_epoch);
        submissions.entries.insert(
            key.clone(),
            SubmittedActor {
                actor,
                input: Arc::new(input),
                state: DispatchState::Queued,
                order,
            },
        );
        Ok(SubmissionReceipt {
            action_key: key,
            actor_created: true,
            join,
        })
    }

    /// Claim at most one pending execution, atomically with registry mutation.
    /// Foreground class wins before numeric priority/deadline/FIFO; a join never
    /// enqueues a second item. Dropped pre-admission claims return to this queue.
    pub fn next_action_dispatch(&self) -> Result<Option<ActionDispatch<'_>>, SubmissionRefusal> {
        if !self.available() {
            return Err(SubmissionRefusal::Unavailable);
        }
        let optional_admitted = self.optional_admitted()?;
        let mut submissions = self
            .submissions
            .lock()
            .map_err(|_| SubmissionRefusal::Unavailable)?;
        let key = submissions
            .entries
            .iter()
            .filter(|(_, entry)| {
                entry.state == DispatchState::Queued
                    && (entry.actor.has_foreground_interest() || optional_admitted)
            })
            .filter_map(|(key, entry)| {
                entry.actor.strongest_interest().map(|interest| {
                    (
                        key,
                        (
                            !entry.actor.has_foreground_interest(),
                            std::cmp::Reverse(interest.priority),
                            interest.earliest_deadline_unix_micros.unwrap_or(i64::MAX),
                            entry.order,
                        ),
                    )
                })
            })
            .min_by_key(|(_, rank)| *rank)
            .map(|(key, _)| key.clone());
        let Some(key) = key else {
            return Ok(None);
        };
        let serial = submissions.next_serial()?;
        let entry = submissions
            .entries
            .get_mut(&key)
            .ok_or(SubmissionRefusal::StaleDispatch)?;
        entry.state = DispatchState::Claimed(serial);
        Ok(Some(ActionDispatch {
            coord: self,
            key,
            serial,
            input: Arc::clone(&entry.input),
            authority: None,
            completed: false,
        }))
    }

    fn begin_submitted_dispatch(
        &self,
        key: &TypedDigest,
        serial: u64,
        worker: &WorkerSessionOffer,
        expires_at_seq: u64,
    ) -> Result<AttemptAuthority, SubmissionRefusal> {
        if !self.available() {
            return Err(SubmissionRefusal::Unavailable);
        }
        let held = self.authority().ok_or(SubmissionRefusal::Unavailable)?;
        let cas = self.cas.as_ref().ok_or(SubmissionRefusal::Unavailable)?;
        let mut submissions = self
            .submissions
            .lock()
            .map_err(|_| SubmissionRefusal::Unavailable)?;
        let entry = submissions
            .entries
            .get(key)
            .ok_or(SubmissionRefusal::StaleDispatch)?;
        if entry.state != DispatchState::Claimed(serial) {
            return Err(SubmissionRefusal::StaleDispatch);
        }
        if !entry.actor.has_foreground_interest() && !self.optional_admitted()? {
            return Err(SubmissionRefusal::Brownout);
        }
        // Allocate against durable history rather than the process clock. Only
        // a bound worker lease supplies the opaque registration proof below.
        let mut actor = entry.actor.clone();
        let attempt_serial = submissions.next_serial()?;
        let lease_serial = submissions.next_serial()?;
        let identity = |counter: u64| (u128::from(self.boot_nonce) << 64) | u128::from(counter);
        let mut store = cas
            .store()
            .lock()
            .map_err(|_| SubmissionRefusal::Unavailable)?;
        let generation = store
            .allocate_bound_generation(&authority_digest(&held), key)
            .map_err(|error| SubmissionRefusal::Admission(format!("generation: {error:?}")))?;
        if actor.open_generation(generation.clone()) != OpenGenerationReceipt::Opened {
            store
                .tombstone_generation(generation.generation_id.0)
                .map_err(|error| {
                    SubmissionRefusal::Admission(format!("generation cleanup: {error:?}"))
                })?;
            return Err(SubmissionRefusal::StaleDispatch);
        }
        let authority = AttemptAuthority {
            coordinator: held,
            action_key: key.clone(),
            action_generation: generation,
            attempt_id: AttemptId(identity(attempt_serial)),
            execution_lease_id: ExecutionLeaseId(identity(lease_serial)),
            lease_renewal_seq: LeaseRenewalSeq(0),
            worker_peer_id: worker.worker_peer_id.clone(),
            worker_boot_generation: worker.boot_generation,
            worker_incarnation_id: worker.incarnation,
        };
        if let Err(error) = store.admit_attempt_lease(&authority, self.next_seq(), expires_at_seq) {
            // No executable lease was issued. Burn the failed generation before
            // allowing the still-owned queue claim to return for a fresh attempt.
            store
                .tombstone_generation(authority.action_generation.generation_id.0)
                .map_err(|cleanup| {
                    SubmissionRefusal::Admission(format!(
                        "lease: {error:?}; generation cleanup: {cleanup:?}"
                    ))
                })?;
            return Err(SubmissionRefusal::Admission(format!("lease: {error:?}")));
        }
        let receipt = actor.register_attempt(RegisterAttempt {
            validated: ValidatedAttemptLease {
                authority: authority.clone(),
            },
            purpose: AttemptPurpose::Primary,
        });
        let entry = submissions
            .entries
            .get_mut(key)
            .ok_or(SubmissionRefusal::StaleDispatch)?;
        if receipt != RegisterAttemptReceipt::Registered {
            entry.state = DispatchState::Abandoned;
            return Err(SubmissionRefusal::Admission(format!(
                "actor registration: {receipt:?}"
            )));
        }
        entry.actor = actor;
        entry.state = DispatchState::Started(serial);
        Ok(authority)
    }

    /// Read-only actor observation for subscriber delivery/diagnostics. Mutating
    /// this copy cannot mutate the coordinator or grant another dispatch.
    pub fn submitted_actor(
        &self,
        key: &TypedDigest,
    ) -> Result<Option<ActionActor>, SubmissionRefusal> {
        Ok(self
            .submissions
            .lock()
            .map_err(|_| SubmissionRefusal::Unavailable)?
            .entries
            .get(key)
            .map(|entry| entry.actor.clone()))
    }

    /// Retire a confirmed finished flight after its consumers have handled the
    /// outcome, durably fencing any late messages from its generation. Published
    /// serving records survive in the CAS. Started or abandoned executions cannot
    /// be forgotten by this cleanup path.
    pub fn retire_finished_action(&self, key: &TypedDigest) -> Result<bool, SubmissionRefusal> {
        let mut submissions = self
            .submissions
            .lock()
            .map_err(|_| SubmissionRefusal::Unavailable)?;
        if !submissions
            .entries
            .get(key)
            .is_some_and(|entry| entry.state == DispatchState::Finished)
        {
            return Ok(false);
        }
        let generation = submissions.entries[key]
            .actor
            .active_generation()
            .ok_or(SubmissionRefusal::StaleDispatch)?
            .generation_id;
        self.cas
            .as_ref()
            .ok_or(SubmissionRefusal::Unavailable)?
            .store()
            .lock()
            .map_err(|_| SubmissionRefusal::Unavailable)?
            .tombstone_generation(generation.0)
            .map_err(|error| {
                SubmissionRefusal::Admission(format!("generation retirement: {error:?}"))
            })?;
        submissions.entries.remove(key);
        Ok(true)
    }

    /// Acquire this incarnation's coordinator authority in the durable
    /// store — the fence `process_offer` checks first (an offer whose
    /// authority does not digest to the ACTIVE row is refused as
    /// `NotActiveAuthority`, so before this ran the daemon could not
    /// commit anything at all).
    ///
    /// Boot semantics (plan §10.8, V1): fresh incarnation every start and
    /// a durably advanced term. A row left behind by a previous boot of
    /// THIS store belongs to a dead incarnation — we hold the store's
    /// exclusive mount, which is the local fence — so it is released and
    /// superseded at `term + 1`. A row from a different cluster is NOT
    /// superseded: that is a misconfiguration, and it refuses loudly.
    /// Cross-host election is M6.
    ///
    /// # Errors
    /// A string reason if no store is mounted or the store refuses.
    pub fn acquire_boot_authority(&self, cluster_id: &str) -> Result<CoordinatorAuthority, String> {
        let cas = self.cas.as_ref().ok_or("no rabs-cas store mounted")?;
        let mut store = cas.store().lock().map_err(|_| "store lock poisoned")?;
        declare_coordinator_domains(&mut *store);
        let prior = store
            .active_authority()
            .map_err(|e| format!("active authority: {e:?}"))?;
        let term = match &prior {
            Some(row) if row.cluster_id != cluster_id => {
                return Err(format!(
                    "store is held by cluster {:?} but this coordinator claims {cluster_id:?} — \
                     refusing to supersede another cluster's authority",
                    row.cluster_id
                ));
            }
            Some(row) => {
                store
                    .release_authority(&row.digest)
                    .map_err(|e| format!("release prior authority: {e:?}"))?;
                row.term.saturating_add(1)
            }
            None => 1,
        };
        let authority = CoordinatorAuthority {
            cluster_id: ClusterId(cluster_id.to_owned()),
            // Credential rotation (S013) is not wired yet; generation 1
            // is this deployment's only credential generation so far.
            credential_generation: 1,
            term,
            incarnation_id: CoordinatorIncarnationId(u128::from(self.boot_nonce)),
        };
        let digest = authority_digest(&authority);
        store
            .acquire_authority(&AuthorityRow {
                digest: digest.clone(),
                cluster_id: cluster_id.to_owned(),
                incarnation: u128::from(self.boot_nonce),
                term,
                acquired_seq: self.next_seq(),
            })
            .map_err(|e: StoreError| format!("acquire authority: {e:?}"))?;
        // G020/R120: this term supersedes every prior one. Durably close
        // all still-active generations minted under earlier authorities so
        // no prior-authority attempt can publish; publication-eligible
        // work reissues only in fresh generations minted (above the
        // never-reuse high-water mark) under THIS authority. Fail-closed:
        // if closure cannot be made durable, this incarnation refuses the
        // authority rather than running where R120 is unenforceable — the
        // acquired row is released and re-acquired at the next boot.
        let closed = store
            .close_generations_for_other_authorities(&digest)
            .map_err(|e: StoreError| format!("close prior-authority generations: {e:?}"))?;
        self.closed_prior_generations
            .store(closed, Ordering::Relaxed);
        drop(store);
        *self
            .authority
            .lock()
            .map_err(|_| "authority lock poisoned")? = Some(authority.clone());
        Ok(authority)
    }

    /// The authority this incarnation holds, if it acquired one.
    #[must_use]
    pub fn authority(&self) -> Option<CoordinatorAuthority> {
        self.authority.lock().ok().and_then(|a| a.clone())
    }

    /// How many prior-authority generations this incarnation's boot
    /// closed (G020); zero for the first boot over a fresh store.
    #[must_use]
    pub fn closed_prior_generations(&self) -> u64 {
        self.closed_prior_generations.load(Ordering::Relaxed)
    }

    /// Admit one worker connection through the durable S022 fence.
    /// The returned sequence exists only for admitted sessions and must
    /// be presented to [`Self::release_worker_session`]. Stale/identity
    /// refusals write nothing; clone ambiguity durably marks the fence and
    /// revokes the worker's leases but appends no session journal row.
    ///
    /// # Errors
    /// A precise reason if the CAS, coordinator authority, lock, or
    /// metadata transaction is unavailable.
    pub fn admit_worker_session(
        &self,
        offer: &WorkerSessionOffer,
    ) -> Result<(WorkerAdmission, Option<u64>), String> {
        let cas = self.cas.as_ref().ok_or("no rabs-cas store mounted")?;
        let held = self.authority().ok_or("no coordinator authority")?;
        let started_seq = self.next_seq();
        let mut store = cas.store().lock().map_err(|_| "store lock poisoned")?;
        let admission = store
            .admit_worker_session(&authority_digest(&held), offer, started_seq)
            .map_err(|e| format!("worker session admission: {e:?}"))?;
        let admitted = matches!(
            admission,
            WorkerAdmission::AdmitNewGeneration
                | WorkerAdmission::AdmitReconnect
                | WorkerAdmission::AdmitResume
                | WorkerAdmission::AdmitViaReenrollment
        );
        Ok((admission, admitted.then_some(started_seq)))
    }

    /// End the exact worker session that owns the active incarnation.
    /// A stale connection cannot clear a newer session's fence.
    ///
    /// # Errors
    /// A precise reason if the CAS, coordinator authority, lock, or
    /// metadata transaction is unavailable.
    pub fn release_worker_session(
        &self,
        worker: &PeerId,
        incarnation: WorkerIncarnationId,
        started_seq: u64,
    ) -> Result<bool, String> {
        let cas = self.cas.as_ref().ok_or("no rabs-cas store mounted")?;
        let held = self.authority().ok_or("no coordinator authority")?;
        let ended_seq = self.next_seq();
        let mut store = cas.store().lock().map_err(|_| "store lock poisoned")?;
        store
            .release_worker_session(
                &authority_digest(&held),
                worker,
                incarnation,
                started_seq,
                ended_seq,
            )
            .map_err(|e| format!("worker session release: {e:?}"))
    }

    /// Atomically grant one attempt and its execution lease under the
    /// exact active worker boot-generation/incarnation tuple.
    ///
    /// # Errors
    /// A typed refusal when this coordinator/store is unavailable, the
    /// request names stale coordinator authority, or any durable generation
    /// or worker fence rejects it.
    pub fn admit_attempt_lease(
        &self,
        authority: &AttemptAuthority,
        expires_at_seq: u64,
    ) -> Result<ValidatedAttemptLease, AttemptLeaseRefusal> {
        let cas = self.cas.as_ref().ok_or(AttemptLeaseRefusal::NoStore)?;
        let held = self.authority().ok_or(AttemptLeaseRefusal::NoAuthority)?;
        if authority_digest(&authority.coordinator) != authority_digest(&held) {
            return Err(AttemptLeaseRefusal::StaleAuthority);
        }
        let recorded_seq = self.next_seq();
        let mut store = cas
            .store()
            .lock()
            .map_err(|_| AttemptLeaseRefusal::StoreUnavailable)?;
        store
            .admit_attempt_lease(authority, recorded_seq, expires_at_seq)
            .map_err(AttemptLeaseRefusal::Store)?;
        Ok(ValidatedAttemptLease {
            authority: authority.clone(),
        })
    }

    /// Renew one attempt lease by durable compare-and-swap, revalidating
    /// the exact current worker fence in the same transaction.
    ///
    /// # Errors
    /// As [`Self::admit_attempt_lease`], plus lease ownership/sequence
    /// refusals.
    pub fn renew_attempt_lease(
        &self,
        authority: &AttemptAuthority,
        renewal: LeaseRenewal,
        expires_at_seq: u64,
    ) -> Result<ValidatedLeaseRenewal, AttemptLeaseRefusal> {
        let cas = self.cas.as_ref().ok_or(AttemptLeaseRefusal::NoStore)?;
        let held = self.authority().ok_or(AttemptLeaseRefusal::NoAuthority)?;
        if authority_digest(&authority.coordinator) != authority_digest(&held) {
            return Err(AttemptLeaseRefusal::StaleAuthority);
        }
        let mut store = cas
            .store()
            .lock()
            .map_err(|_| AttemptLeaseRefusal::StoreUnavailable)?;
        store
            .renew_attempt_lease(authority, renewal, expires_at_seq)
            .map_err(AttemptLeaseRefusal::Store)?;
        Ok(ValidatedLeaseRenewal {
            authority: authority.clone(),
            renewal,
        })
    }

    /// Commit a worker's prepared-result offer: the coordinator-only
    /// compare-and-set publication transaction (I8/I9/I10 — the worker
    /// offers, only this commits).
    ///
    /// The object BYTES are not this call's business: under
    /// [`CommitDurabilityProfile::RequireDurableClosure`] the engine
    /// refuses any offer whose closure is not already durably located, so
    /// an incomplete upload can never become a committed pointer.
    ///
    /// # Errors
    /// A typed [`CommitRefusal`]. Nothing is written on any of them.
    pub fn commit_offer(
        &self,
        offer: &OfferPreparedActionResult,
        expected_descriptor: &TypedDigest,
    ) -> Result<PublicationOutcome, CommitRefusal> {
        let cas = self.cas.as_ref().ok_or(CommitRefusal::NoStore)?;
        let held = self.authority().ok_or(CommitRefusal::NoAuthority)?;
        // G019 offer-admission fence: refuse an offer prepared under any
        // OTHER authority BEFORE the store transaction opens — a dead
        // incarnation's attempts never publish here, independent of what
        // the durable active row or `process_offer` would later say.
        if authority_digest(&offer.authority.coordinator) != authority_digest(&held) {
            return Err(CommitRefusal::StaleAuthority {
                offered_term: offer.authority.coordinator.term,
                active_term: held.term,
            });
        }
        let pin_id = self.next_pin_id();
        let seq = self.next_seq();
        let mut store = cas
            .store()
            .lock()
            .map_err(|_| CommitRefusal::StoreUnavailable)?;

        // A018 classification needs the COMMITTED manifest for this key.
        // Resolve it up front, out of its CAS bytes: `process_offer`
        // borrows the store for the whole admission, so the resolver it
        // takes cannot itself touch the store — and the only key it ever
        // asks for is this one. Reading the bytes (rather than
        // remembering the manifest in process memory) is what makes
        // classification survive a restart.
        let committed_key = store
            .published_manifest_key(&offer.manifest.action_key)
            .map_err(|e| CommitRefusal::Store(format!("{e:?}")))?;
        let committed = match &committed_key {
            Some(key) => load_manifest(&mut *store, key),
            None => None,
        };
        let resolver = |key: &str| match (&committed_key, &committed) {
            (Some(committed_key), Some(manifest)) if committed_key == key => Some(manifest.clone()),
            _ => None,
        };

        process_offer(
            &mut *store,
            offer,
            expected_descriptor,
            resolver,
            pin_id,
            seq,
            CommitDurabilityProfile::RequireDurableClosure,
        )
        .map_err(CommitRefusal::Offer)
    }

    /// Serve a committed action into a live worktree: the first path in
    /// RABS by which a cache hit becomes files on disk.
    ///
    /// Order matters and is fail-closed at every step:
    ///
    /// 1. the H040 serving gate decides — anything but `Servable` (no
    ///    record, quarantined, blocked, expired) returns the typed
    ///    decision and writes nothing;
    /// 2. the committed manifest is reloaded from its CAS bytes, so
    ///    what gets materialized is what was committed, not what some
    ///    process remembered;
    /// 3. the commit's materializable outputs are checked against
    ///    `expected` — a caller skipping work must get exactly the files
    ///    that work would have produced, or no hit at all;
    /// 4. every destination is resolved under `destination_root` and
    ///    refused if it escapes (absolute, `..`, empty);
    /// 5. the D031 arbiter reserves ALL of them all-or-nothing, so two
    ///    concurrent serves cannot install into overlapping paths;
    /// 6. only then do bytes land, each verified against its object id
    ///    and renamed into place.
    ///
    /// A failure part-way leaves the files already written in place —
    /// they are individually correct, verified artifacts — and reports
    /// the failure; the caller must not treat a partial serve as a hit.
    ///
    /// # Errors
    /// A typed [`ServeError`]. The non-error non-serve cases (nothing
    /// committed, not servable) are [`ServeOutcome`] variants, because
    /// they are normal answers, not faults.
    pub fn serve_action(
        &self,
        action_key: &TypedDigest,
        destination_root: &Path,
        expected: &ExpectedOutputs,
        now_unix_micros: i64,
        now_epoch: u64,
    ) -> Result<ServeOutcome, ServeError> {
        let cas = self.cas.as_ref().ok_or(ServeError::NoStore)?;
        let key = digest_key(action_key);
        let mut store = cas
            .store()
            .lock()
            .map_err(|_| ServeError::StoreUnavailable)?;
        declare_coordinator_domains(&mut *store);

        match serving_gate(&mut *store, &key, now_unix_micros, now_epoch)
            .map_err(|e| ServeError::Store(format!("{e:?}")))?
        {
            ServeDecision::Servable => {}
            decision => return Ok(ServeOutcome::NotServable(decision)),
        }
        let Some(manifest_key) = store
            .published_manifest_key(action_key)
            .map_err(|e| ServeError::Store(format!("{e:?}")))?
        else {
            // A servable disposition with no publication row is a torn
            // store, not a hit.
            return Ok(ServeOutcome::NoCommit);
        };
        let Some(manifest) = load_manifest(&mut *store, &manifest_key) else {
            return Ok(ServeOutcome::ManifestUnavailable { key: manifest_key });
        };

        // The interlock: does this commit produce what the caller's own
        // work would have produced? Checked BEFORE any path resolution,
        // reservation, or byte — a mismatch must cost nothing.
        if let ExpectedOutputs::Exactly(expected) = expected {
            let mut committed_outputs = std::collections::BTreeSet::new();
            for output in &manifest.logical_outputs {
                if output.role != OutputRole::Materializable {
                    continue;
                }
                // No lossy comparison in a safety interlock: a path this
                // build cannot even read is a path it cannot promise.
                let text = std::str::from_utf8(output.virtual_path.as_bytes()).map_err(|_| {
                    ServeError::UnsafeVirtualPath {
                        path: output.virtual_path.escaped(),
                    }
                })?;
                committed_outputs.insert(text.to_owned());
            }
            if committed_outputs != *expected {
                return Ok(ServeOutcome::OutputSetMismatch {
                    missing: expected.difference(&committed_outputs).cloned().collect(),
                    unexpected: committed_outputs.difference(expected).cloned().collect(),
                });
            }
        }

        // Resolve destinations first: nothing is reserved, and no byte
        // is written, until every path is known to stay inside the root.
        let mut plan: Vec<(TypedDigest, PathBuf, String)> = Vec::new();
        for output in &manifest.logical_outputs {
            if output.role != OutputRole::Materializable {
                continue;
            }
            let path = resolve_destination(destination_root, output.virtual_path.as_bytes())
                .ok_or_else(|| ServeError::UnsafeVirtualPath {
                    path: output.virtual_path.escaped(),
                })?;
            let text = path.to_string_lossy().into_owned();
            plan.push((output.object.0.clone(), path, text));
        }
        if plan.is_empty() {
            return Ok(ServeOutcome::Served { files: Vec::new() });
        }

        // D031: reserve every destination all-or-nothing before any
        // install, so a concurrent serve into an overlapping path is
        // refused rather than interleaved.
        let bundle = BundleId(format!("serve:{key}:{}", self.next_seq()));
        let paths: Vec<String> = plan.iter().map(|(_, _, text)| text.clone()).collect();
        {
            let mut arbiter = self
                .arbiter
                .lock()
                .map_err(|_| ServeError::StoreUnavailable)?;
            arbiter.reserve(&bundle, &paths).map_err(|conflict| {
                ServeError::DestinationConflict {
                    path: conflict.path,
                    holder: conflict.holder.0,
                }
            })?;
        }
        let result = install_all(&mut *store, &plan);
        if let Ok(mut arbiter) = self.arbiter.lock() {
            arbiter.release(&bundle);
        }
        let files = result?;
        Ok(ServeOutcome::Served { files })
    }

    /// Allocate a pin id unique to this incarnation.
    fn next_pin_id(&self) -> u128 {
        let low = self.next_pin.fetch_add(1, Ordering::Relaxed);
        (u128::from(self.boot_nonce) << 64) | u128::from(low)
    }

    /// Allocate the next causal sequence.
    fn next_seq(&self) -> u64 {
        self.next_seq.fetch_add(1, Ordering::Relaxed)
    }

    /// The coord region is up (called from coord work at boot).
    pub fn mark_up(&self) {
        self.available.store(true, Ordering::Release);
    }

    /// The coord region is down (shutdown or crash).
    pub fn mark_down(&self) {
        self.available.store(false, Ordering::Release);
    }

    /// Whether the authority split is live.
    #[must_use]
    pub fn available(&self) -> bool {
        self.available.load(Ordering::Acquire)
    }

    /// Begin a flight for `key` (connection-scoped window).
    #[must_use]
    pub fn begin_flight(&self, key: &str) -> FlightRole {
        if !self.available() {
            return FlightRole::Degraded;
        }
        let Ok(mut flights) = self.flights.lock() else {
            return FlightRole::Degraded;
        };
        let count = flights.entry(key.to_string()).or_insert(0);
        *count += 1;
        if *count == 1 {
            FlightRole::Leader
        } else {
            FlightRole::Follower
        }
    }

    /// End one flight participation for `key` (connection closed).
    pub fn end_flight(&self, key: &str) {
        if let Ok(mut flights) = self.flights.lock()
            && let Some(count) = flights.get_mut(key)
        {
            *count = count.saturating_sub(1);
            if *count == 0 {
                flights.remove(key);
            }
        }
    }

    /// Coord status as one JSON line (`--coord-status` surface).
    #[must_use]
    pub fn status_json(&self) -> String {
        let open_flights = self.flights.lock().map(|f| f.len()).unwrap_or(0);
        let (lease_holders, reservations) = (
            // The registries expose no len today; report mount state —
            // the numbers arrive when Phase 1 gives them real traffic.
            self.leases.lock().is_ok(),
            self.arbiter.lock().is_ok(),
        );
        let authority = self.authority();
        format!(
            "{{\"v\":1,\"kind\":\"coord-status\",\"available\":{},\"open_flights\":{open_flights},\
             \"lease_registry_mounted\":{lease_holders},\"destination_arbiter_mounted\":{reservations},\
             \"cas_mounted\":{},\"authority_held\":{},\"authority_term\":{},\
             \"closed_prior_authority_generations\":{}}}",
            self.available(),
            self.cas.is_some(),
            authority.is_some(),
            authority.map_or(0, |a| a.term),
            self.closed_prior_generations(),
        )
    }

    /// Exclusive access to the lease registry (Phase 1 serving path).
    pub fn leases(&self) -> &Mutex<TargetLeaseRegistry> {
        &self.leases
    }

    /// Exclusive access to the destination arbiter (Phase 1 path).
    pub fn arbiter(&self) -> &Mutex<DestinationArbiter> {
        &self.arbiter
    }
}

/// Declare every digest domain the coordinator reads back out of a
/// store a PREVIOUS incarnation wrote.
///
/// Domain restore is fail-closed (R121): a process may only re-type a
/// stored domain it names itself, as a `'static` from its own build.
/// Writes intern implicitly, which covers everything within one
/// incarnation — but a fresh coordinator's very first acts are READS
/// (its predecessor's authority row, the committed publication for a key
/// it is about to admit), so it declares them here at boot. Anything not
/// on this list still fails closed.
pub fn declare_coordinator_domains(store: &mut dyn RabsMetadataStore) {
    for domain in [
        AUTHORITY_DIGEST_DOMAIN,
        DOMAIN_ACTION_KEY,
        DOMAIN_DESCRIPTOR,
        DOMAIN_ARTIFACT_BUNDLE_ROOT,
        ATP_OBJECT_CONTENT_DOMAIN,
        SEMANTIC_PROJECTION_DOMAIN,
        OBSERVABLE_PROJECTION_DOMAIN,
    ] {
        store.intern_domain(domain);
    }
}

/// Load a canonical result manifest out of its CAS bytes, by object
/// digest key (`domain:hex`, as stored on the publication row).
///
/// `None` for every "cannot be sure" case — an unparsable key, a key
/// that is not an object id, no non-quarantined raw copy, unreadable
/// bytes, or bytes that do not decode. A caller that needs the manifest
/// then refuses conservatively; a wrong manifest would mean a wrong
/// divergence verdict, which is far worse than a refusal.
#[must_use]
pub fn load_manifest(
    store: &mut dyn RabsMetadataStore,
    manifest_key: &str,
) -> Option<CanonicalActionResultManifest> {
    let object = object_id_from_key(manifest_key)?;
    let locations = store.object_locations(&object).ok()?;
    locations
        .into_iter()
        // Only the raw representation is bytes-as-stored; compressed and
        // packed copies need their own decoders (H030) and are skipped
        // rather than mis-read.
        .filter(|(_, encoding, _)| encoding == RAW_PROFILE_V1)
        .find_map(|(path, _, _)| {
            let bytes = std::fs::read(&path).ok()?;
            decode_manifest_v1(&bytes).ok()
        })
}

/// Parse a `rabs.object.sha256.v1:<64 hex>` digest key back into a typed
/// digest. The domain is this build's `'static` constant — a key naming
/// any other domain is refused, never re-typed (R121).
fn object_id_from_key(key: &str) -> Option<TypedDigest> {
    let hex = key
        .strip_prefix(ATP_OBJECT_CONTENT_DOMAIN)?
        .strip_prefix(':')?;
    if hex.len() != 64 {
        return None;
    }
    let mut bytes = [0_u8; 32];
    let (pairs, _) = hex.as_bytes().as_chunks::<2>();
    for (slot, pair) in bytes.iter_mut().zip(pairs) {
        let text = std::str::from_utf8(pair).ok()?;
        *slot = u8::from_str_radix(text, 16).ok()?;
    }
    Some(TypedDigest {
        algorithm: DigestAlgorithm::Sha256V1,
        domain: ATP_OBJECT_CONTENT_DOMAIN,
        bytes,
    })
}

/// The cluster this coordinator claims (`RABS_CLUSTER_ID`, default
/// `local`). One store may only ever be held by one cluster's authority.
#[must_use]
pub fn cluster_id() -> String {
    std::env::var("RABS_CLUSTER_ID").unwrap_or_else(|_| "local".to_owned())
}

/// Build the coord region work: mark the authority split live, acquire
/// this incarnation's coordinator authority in the durable store, hold
/// until shutdown.
///
/// Authority acquisition is fail-closed on its own terms and fail-open for
/// the daemon: if it fails, the region logs the typed reason and stays up
/// WITHOUT authority, so consults still answer and builds still run — but
/// [`CoordLive::commit_offer`] refuses every commit
/// ([`CommitRefusal::NoAuthority`]) instead of publishing under an
/// authority nobody granted.
pub fn coord_work(
    coord: std::sync::Arc<CoordLive>,
) -> rabs_asupersync::daemon_runtime::SubsystemWork {
    Box::new(move |cx, mut shutdown| {
        Box::pin(async move {
            if std::env::var("RABS_LAB_COORD_DOWN").is_ok() {
                // Lab fault injection: the coord region dies at boot;
                // edge consults must survive in degraded mode and the
                // receipt must show this region abandoned.
                return Err("lab: coord region down (RABS_LAB_COORD_DOWN)".to_string());
            }
            coord.mark_up();
            match coord.acquire_boot_authority(&cluster_id()) {
                Ok(authority) => println!(
                    "{{\"v\":1,\"kind\":\"coord-authority-acquired\",\"cluster_id\":\"{}\",\
                     \"credential_generation\":{},\"term\":{},\"incarnation\":\"{}\",\
                     \"digest\":\"{}\",\"prior_generations_closed\":{}}}",
                    authority.cluster_id.0,
                    authority.credential_generation,
                    authority.term,
                    authority.incarnation_id.0,
                    digest_key(&authority_digest(&authority)),
                    coord.closed_prior_generations(),
                ),
                Err(reason) => println!(
                    "{{\"v\":1,\"kind\":\"coord-authority-refused\",\"reason\":\"{}\"}}",
                    reason.replace('"', "'")
                ),
            }
            cx.trace("coord region up: leases + arbiter + singleflight mounted");
            shutdown.wait().await;
            coord.mark_down();
            Ok(())
        })
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::coord::action_actor::SubscriptionRequirements;
    use crate::janitor::store::mount_and_reconcile;
    use rabs_cas::test_support::{attempt_authority_for, offer_under, sample_expected_descriptor};
    use rabs_protocol::descriptor::ActionClass;
    use rabs_protocol::durable_ids::BuildOperationId;
    use rabs_protocol::generation::{
        AttemptId, ExecutionLeaseId, LeaseRenewalSeq, WorkerBootGeneration,
    };
    use rabs_protocol::input_evidence::{INPUT_EVIDENCE_SCHEMA_VERSION, PositiveInput};
    use rabs_protocol::raw_bytes::RawBytes;
    use rabs_protocol::result_identity::ObjectId;
    use rabs_protocol::worker_fence::WorkerLeaseBindingRejection;
    use rabs_sandbox::snapshot_capture::capture_sealed_source;
    use std::sync::Arc;

    fn source_fixture() -> (
        tempfile::TempDir,
        Arc<SealedSourceSnapshot>,
        ActionInputManifest,
        ActionDescriptor,
    ) {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("input.txt"), b"projected bytes\n").unwrap();
        std::fs::write(dir.path().join("unrelated.txt"), b"not an input\n").unwrap();
        let source = Arc::new(
            capture_sealed_source(
                &[("workspace".into(), dir.path().to_path_buf())],
                false,
                2,
                4096,
            )
            .unwrap(),
        );
        let object = ObjectId(
            digest_set(b"projected bytes\n", DigestRequest::default(), None)
                .unwrap()
                .atp_content_id,
        );
        let manifest = ActionInputManifest {
            schema_version: INPUT_EVIDENCE_SCHEMA_VERSION,
            inputs: vec![PositiveInput {
                virtual_path: RawBytes::from("/__rabs/workspace/input.txt"),
                object,
                file_type: InputFileType::Regular,
                executable: false,
                symlink_resolution: vec![],
            }],
            ..ActionInputManifest::default()
        };
        let d = rabs_key::typed_digest::compute("rabs.submission-test.v1", b"fixture");
        let descriptor = ActionDescriptor {
            key_epoch: 1,
            projection_epoch: 1,
            action_class: ActionClass::CodeGeneratorRun,
            normalized_invocation: d.clone(),
            virtual_working_directory: d.clone(),
            action_inputs: action_input_manifest_digest(&manifest).unwrap(),
            negative_dependencies: d.clone(),
            dependency_inputs: d.clone(),
            toolchain: d.clone(),
            output_platform: d.clone(),
            environment: d.clone(),
            sandbox_semantic_policy: d.clone(),
            build_path_semantic_policy: d.clone(),
            execution_semantics: d.clone(),
            output_declarations: d,
        };
        (dir, source, manifest, descriptor)
    }

    fn submission(
        source: &Arc<SealedSourceSnapshot>,
        manifest: &ActionInputManifest,
        descriptor: &ActionDescriptor,
    ) -> ActionSubmission {
        ActionSubmission::from_snapshot(
            descriptor.clone(),
            manifest,
            Arc::clone(source),
            &[("workspace".into(), rabs_sandbox::layout::WORKSPACE.into())],
        )
        .unwrap()
    }

    fn request(operation: u128, kind: SubscriberKind, priority: u8) -> JoinRequest {
        JoinRequest {
            operation: BuildOperationId(operation),
            kind,
            queue_priority: priority,
            deadline_unix_micros: None,
            presentation: rabs_key::typed_digest::compute("rabs.presentation.v1", b"plain"),
            requirements: SubscriptionRequirements::unrestricted(),
        }
    }

    fn submission_coordinator() -> (tempfile::TempDir, CoordLive) {
        let state = tempfile::tempdir().unwrap();
        let coord = CoordLive::with_cas(Arc::new(mount_and_reconcile(state.path()).unwrap()));
        coord.acquire_boot_authority("submission-tests").unwrap();
        coord.mark_up();
        (state, coord)
    }

    #[test]
    fn projected_source_binds_bytes_and_materializes_only_keyed_inputs() {
        let (live, source, manifest, descriptor) = source_fixture();
        let input = submission(&source, &manifest, &descriptor);
        std::fs::write(live.path().join("input.txt"), b"edited after capture").unwrap();
        let fresh = tempfile::tempdir().unwrap();
        let target = fresh.path().join("projection");
        let paths = input.materialize_into(&target).unwrap();
        assert_eq!(
            std::fs::read(paths["workspace"].join("input.txt")).unwrap(),
            b"projected bytes\n"
        );
        assert!(!paths["workspace"].join("unrelated.txt").exists());
        assert_eq!(
            input.materialize_into(&target).unwrap_err().kind(),
            std::io::ErrorKind::AlreadyExists
        );
        let edited = Arc::new(
            capture_sealed_source(
                &[("workspace".into(), live.path().to_path_buf())],
                false,
                2,
                4096,
            )
            .unwrap(),
        );
        assert!(matches!(
            ActionSubmission::from_snapshot(
                descriptor,
                &manifest,
                edited,
                &[("workspace".into(), rabs_sandbox::layout::WORKSPACE.into())]
            ),
            Err(SubmissionRefusal::InvalidSource(_))
        ));
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                std::fs::metadata(paths["workspace"].join("input.txt"))
                    .unwrap()
                    .permissions()
                    .mode()
                    & 0o777,
                0o644
            );
        }
    }

    #[test]
    fn projection_refuses_missing_unsafe_and_mismatched_evidence() {
        let (_live, source, manifest, descriptor) = source_fixture();
        let mapping = [("workspace".into(), rabs_sandbox::layout::WORKSPACE.into())];
        for path in [
            "/__rabs/workspace/../input.txt",
            "/__rabs/workspace/input.txt/",
            "/__rabs/workspace/missing",
            "/__rabs/workspace-else/input.txt",
            "/__rabs/workspace/input\0.txt",
            "/__rabs/workspace/./input.txt",
        ] {
            let mut changed = manifest.clone();
            changed.inputs[0].virtual_path = RawBytes::from(path);
            let mut described = descriptor.clone();
            described.action_inputs = action_input_manifest_digest(&changed).unwrap();
            assert!(
                matches!(
                    ActionSubmission::from_snapshot(
                        described,
                        &changed,
                        Arc::clone(&source),
                        &mapping
                    ),
                    Err(SubmissionRefusal::InvalidSource(_))
                ),
                "{path:?}"
            );
        }
        for case in 0..5 {
            let mut changed = manifest.clone();
            match case {
                0 => changed.inputs[0].object.0.bytes[0] ^= 1,
                1 => changed.inputs[0].executable = true,
                2 => changed.inputs[0].file_type = InputFileType::Symlink,
                3 => changed.inputs[0]
                    .symlink_resolution
                    .push(RawBytes::from("input.txt")),
                _ => changed
                    .approved_generated_objects
                    .push(changed.inputs[0].object.clone()),
            }
            let mut described = descriptor.clone();
            described.action_inputs = action_input_manifest_digest(&changed).unwrap();
            assert!(matches!(
                ActionSubmission::from_snapshot(described, &changed, Arc::clone(&source), &mapping),
                Err(SubmissionRefusal::InvalidSource(_))
            ));
        }
        for invalid in [
            vec![],
            vec![("workspace".into(), "/tmp/hidden".into())],
            vec![(
                "missing-root".into(),
                rabs_sandbox::layout::WORKSPACE.into(),
            )],
            vec![mapping[0].clone(), mapping[0].clone()],
        ] {
            assert!(matches!(
                ActionSubmission::from_snapshot(
                    descriptor.clone(),
                    &manifest,
                    Arc::clone(&source),
                    &invalid
                ),
                Err(SubmissionRefusal::InvalidSource(_))
            ));
        }
        let mut mismatched = descriptor;
        mismatched.action_inputs.bytes[0] ^= 1;
        assert!(matches!(
            ActionSubmission::from_snapshot(mismatched, &manifest, source, &mapping),
            Err(SubmissionRefusal::InvalidSource(_))
        ));
    }

    #[test]
    fn shared_queue_prioritizes_foreground_and_restores_unstarted_claims() {
        let (_state, coord) = submission_coordinator();
        let (_live, source, manifest, descriptor) = source_fixture();
        let optional = coord
            .submit_action(
                submission(&source, &manifest, &descriptor),
                request(1, SubscriberKind::Speculative, 255),
                1,
                0,
            )
            .unwrap();
        let mut foreground_descriptor = descriptor.clone();
        foreground_descriptor.normalized_invocation.bytes[0] ^= 1;
        let foreground = coord
            .submit_action(
                submission(&source, &manifest, &foreground_descriptor),
                request(2, SubscriberKind::ForegroundAgent, 0),
                2,
                0,
            )
            .unwrap();
        {
            let first = coord.next_action_dispatch().unwrap().unwrap();
            assert_eq!(
                first.input().key(),
                foreground.action_key,
                "foreground class beats arbitrary optional priority"
            );
            let second = coord.next_action_dispatch().unwrap().unwrap();
            assert_eq!(second.input().key(), optional.action_key);
            assert!(coord.next_action_dispatch().unwrap().is_none());
            // An actual failed preparation does not permanently claim work.
            let existing = tempfile::tempdir().unwrap();
            assert!(first.input().materialize_into(existing.path()).is_err());
        }
        assert_eq!(
            coord.next_action_dispatch().unwrap().unwrap().input().key(),
            foreground.action_key
        );
        coord.set_speculation_pressure(PressureBand::Hard).unwrap();
        assert!(matches!(
            coord.submit_action(
                submission(&source, &manifest, &descriptor),
                request(3, SubscriberKind::Speculative, 1),
                3,
                0
            ),
            Err(SubmissionRefusal::Brownout)
        ));
        let joined = coord
            .submit_action(
                submission(&source, &manifest, &descriptor),
                request(1, SubscriberKind::ForegroundAgent, 1),
                4,
                0,
            )
            .unwrap();
        assert!(
            !joined.actor_created,
            "foreground rejoins original optional actor under pressure"
        );
        assert!(
            coord
                .submitted_actor(&optional.action_key)
                .unwrap()
                .unwrap()
                .has_foreground_interest()
        );
        let mut conflicting = request(1, SubscriberKind::ForegroundAgent, 2);
        conflicting.requirements.minimum_evidence_bundles = 1;
        assert_eq!(
            coord
                .submit_action(
                    submission(&source, &manifest, &descriptor),
                    conflicting,
                    5,
                    0
                )
                .unwrap_err(),
            SubmissionRefusal::ChangedRequirements
        );
        assert_eq!(
            coord
                .submitted_actor(&optional.action_key)
                .unwrap()
                .unwrap()
                .subscriber(&BuildOperationId(1))
                .unwrap()
                .interests,
            2
        );
    }

    #[test]
    fn pressure_and_worker_fences_are_rechecked_before_start() {
        let (_state, coord) = submission_coordinator();
        let (_live, source, manifest, descriptor) = source_fixture();
        let receipt = coord
            .submit_action(
                submission(&source, &manifest, &descriptor),
                request(1, SubscriberKind::Speculative, 1),
                1,
                0,
            )
            .unwrap();
        let worker = worker_offer(1, 1);
        let expiry = i64::MAX as u64;
        {
            let mut claim = coord.next_action_dispatch().unwrap().unwrap();
            coord.set_speculation_pressure(PressureBand::Soft).unwrap();
            assert_eq!(
                claim.begin(&worker, expiry).unwrap_err(),
                SubmissionRefusal::Brownout
            );
            assert_eq!(
                coord
                    .submitted_actor(&receipt.action_key)
                    .unwrap()
                    .unwrap()
                    .attempts()
                    .count(),
                0
            );
        }
        assert!(coord.next_action_dispatch().unwrap().is_none());
        coord
            .set_speculation_pressure(PressureBand::Normal)
            .unwrap();
        {
            let mut claim = coord.next_action_dispatch().unwrap().unwrap();
            assert_eq!(
                claim.begin(&worker, expiry).unwrap_err(),
                SubmissionRefusal::Admission("lease: UnknownWorkerFence".into()),
                "unadmitted worker cannot obtain execution lease"
            );
        }
        coord.admit_worker_session(&worker).unwrap();
        let mut claim = coord.next_action_dispatch().unwrap().unwrap();
        let authority = claim.begin(&worker, expiry).unwrap().clone();
        assert_eq!(
            claim.begin(&worker, expiry).unwrap_err(),
            SubmissionRefusal::StaleDispatch
        );
        assert_eq!(
            coord
                .submitted_actor(&receipt.action_key)
                .unwrap()
                .unwrap()
                .attempts()
                .count(),
            1
        );
        assert_eq!(
            coord
                .submitted_actor(&receipt.action_key)
                .unwrap()
                .unwrap()
                .attempts()
                .next()
                .unwrap()
                .attempt,
            authority.attempt_id
        );
        assert!(coord.next_action_dispatch().unwrap().is_none());
        drop(claim); // Started, no terminal process proof: never blindly requeue.
        assert!(coord.next_action_dispatch().unwrap().is_none());
        assert!(!coord.retire_finished_action(&receipt.action_key).unwrap());
        assert_eq!(
            coord
                .submit_action(
                    submission(&source, &manifest, &descriptor),
                    request(2, SubscriberKind::ForegroundAgent, 200),
                    2,
                    0
                )
                .unwrap_err(),
            SubmissionRefusal::UnreconciledAttempt
        );
    }

    fn worker_offer(generation: u64, incarnation: u128) -> WorkerSessionOffer {
        WorkerSessionOffer {
            worker_peer_id: PeerId("worker-a".to_owned()),
            boot_generation: WorkerBootGeneration(generation),
            incarnation: WorkerIncarnationId(incarnation),
            reenrollment_proof: None,
        }
    }

    #[test]
    fn overlapping_flights_one_leader_then_followers() {
        let coord = CoordLive::new();
        coord.mark_up();
        assert_eq!(coord.begin_flight("k1"), FlightRole::Leader);
        assert_eq!(coord.begin_flight("k1"), FlightRole::Follower);
        assert_eq!(coord.begin_flight("k1"), FlightRole::Follower);
        // A different key gets its own leader.
        assert_eq!(coord.begin_flight("k2"), FlightRole::Leader);
        // Window closes only when every participant ends.
        coord.end_flight("k1");
        coord.end_flight("k1");
        assert_eq!(
            coord.begin_flight("k1"),
            FlightRole::Follower,
            "leader still open"
        );
        coord.end_flight("k1");
        coord.end_flight("k1");
        assert_eq!(
            coord.begin_flight("k1"),
            FlightRole::Leader,
            "window closed"
        );
    }

    #[test]
    fn degraded_mode_is_typed_never_silent() {
        let coord = CoordLive::new(); // never marked up
        assert_eq!(coord.begin_flight("k"), FlightRole::Degraded);
        coord.mark_up();
        assert_eq!(coord.begin_flight("k"), FlightRole::Leader);
        coord.mark_down();
        assert_eq!(coord.begin_flight("k"), FlightRole::Degraded);
    }

    #[test]
    fn status_reports_mounts_and_open_flights() {
        let coord = CoordLive::new();
        coord.mark_up();
        let _ = coord.begin_flight("k1");
        let status = coord.status_json();
        assert!(status.contains("\"available\":true"), "{status}");
        assert!(status.contains("\"open_flights\":1"), "{status}");
        assert!(
            status.contains("\"lease_registry_mounted\":true"),
            "{status}"
        );
        assert!(
            status.contains("\"destination_arbiter_mounted\":true"),
            "{status}"
        );
    }

    #[test]
    fn worker_fence_is_atomic_exact_owner_and_durable() {
        let dir = tempfile::tempdir().expect("temp store");
        let cas = Arc::new(mount_and_reconcile(dir.path()).expect("mount"));
        let coord = CoordLive::with_cas(Arc::clone(&cas));
        coord
            .acquire_boot_authority("test-cluster")
            .expect("authority");

        let first = worker_offer(5, 0x11);
        let (admission, started) = coord.admit_worker_session(&first).expect("first admission");
        assert_eq!(admission, WorkerAdmission::AdmitNewGeneration);
        let started = started.expect("admitted session sequence");

        let (reconnect, reconnect_started) = coord
            .admit_worker_session(&first)
            .expect("reconnect admission");
        assert_eq!(reconnect, WorkerAdmission::AdmitReconnect);
        let reconnect_started = reconnect_started.expect("reconnect session sequence");
        assert_ne!(reconnect_started, started);

        let (clone, clone_started) = coord
            .admit_worker_session(&worker_offer(5, 0x22))
            .expect("clone decision");
        assert_eq!(clone, WorkerAdmission::RejectCloneAmbiguity);
        assert_eq!(clone_started, None, "a rejected clone opens no session");
        assert!(
            !coord
                .release_worker_session(
                    &PeerId("worker-a".to_owned()),
                    WorkerIncarnationId(0x22),
                    started,
                )
                .expect("wrong-owner release")
        );
        assert!(
            coord
                .release_worker_session(
                    &PeerId("worker-a".to_owned()),
                    WorkerIncarnationId(0x11),
                    started,
                )
                .expect("exact-owner release")
        );

        let (still_clone, still_clone_started) = coord
            .admit_worker_session(&worker_offer(5, 0x22))
            .expect("clone decision with reconnect still open");
        assert_eq!(still_clone, WorkerAdmission::RejectCloneAmbiguity);
        assert_eq!(still_clone_started, None);
        assert!(
            coord
                .release_worker_session(
                    &PeerId("worker-a".to_owned()),
                    WorkerIncarnationId(0x11),
                    reconnect_started,
                )
                .expect("final reconnect release")
        );

        let (resume, resumed_seq) = coord
            .admit_worker_session(&worker_offer(5, 0x22))
            .expect("resume admission");
        assert_eq!(resume, WorkerAdmission::RejectCloneAmbiguity);
        assert_eq!(
            resumed_seq, None,
            "ending sessions cannot select the legitimate clone"
        );

        drop(coord);
        drop(cas);
        let reopened = Arc::new(mount_and_reconcile(dir.path()).expect("reopen"));
        let restarted = CoordLive::with_cas(reopened);
        restarted
            .acquire_boot_authority("test-cluster")
            .expect("restarted authority");
        let (stale, stale_seq) = restarted
            .admit_worker_session(&worker_offer(4, 0x33))
            .expect("stale decision");
        assert_eq!(stale, WorkerAdmission::RejectStaleBootGeneration);
        assert_eq!(stale_seq, None);

        let mut rolled_back = worker_offer(1, 0x44);
        rolled_back.reenrollment_proof = Some(1);
        let (rejected_reset, rejected_reset_seq) = restarted
            .admit_worker_session(&rolled_back)
            .expect("rolled-back reenrollment decision");
        assert_eq!(rejected_reset, WorkerAdmission::RejectStaleBootGeneration);
        assert_eq!(rejected_reset_seq, None);

        let mut reenrolled = worker_offer(5, 0x44);
        reenrolled.reenrollment_proof = Some(1);
        let (reset, reset_seq) = restarted
            .admit_worker_session(&reenrolled)
            .expect("operator reenrollment");
        assert_eq!(reset, WorkerAdmission::AdmitViaReenrollment);
        assert!(reset_seq.is_some());

        let mut replay = worker_offer(5, 0x55);
        replay.reenrollment_proof = Some(1);
        let (rejected_replay, replay_seq) = restarted
            .admit_worker_session(&replay)
            .expect("replayed proof decision");
        assert_eq!(rejected_replay, WorkerAdmission::RejectCloneAmbiguity);
        assert_eq!(replay_seq, None);
    }

    #[test]
    fn t038_clone_ambiguity_durably_revokes_old_leases_until_reenrollment() {
        let dir = tempfile::tempdir().expect("temp store");
        let cas = Arc::new(mount_and_reconcile(dir.path()).expect("mount"));
        let coord = CoordLive::with_cas(Arc::clone(&cas));
        let coordinator = coord
            .acquire_boot_authority("test-cluster")
            .expect("authority");
        let authority_digest = authority_digest(&coordinator);

        let first = worker_offer(5, 0x11);
        assert_eq!(
            coord.admit_worker_session(&first).expect("first session").0,
            WorkerAdmission::AdmitNewGeneration
        );

        let mut incumbent = attempt_authority_for(&coordinator);
        incumbent.worker_boot_generation = WorkerBootGeneration(5);
        incumbent.worker_incarnation_id = WorkerIncarnationId(0x11);
        {
            let mut store = cas.store().lock().expect("store lock");
            store
                .upsert_action_entry(&rabs_cas::metadata_store::ActionEntryRow {
                    action_key: incumbent.action_key.clone(),
                    key_epoch: 1,
                    projection_epoch: 1,
                })
                .expect("action entry");
            store
                .create_bound_generation(
                    &authority_digest,
                    &incumbent.action_generation,
                    &incumbent.action_key,
                )
                .expect("bound generation");
        }
        coord
            .admit_attempt_lease(&incumbent, 100)
            .expect("incumbent lease");
        let first_renewal = LeaseRenewal {
            lease: incumbent.execution_lease_id,
            seq: LeaseRenewalSeq(2),
        };
        coord
            .renew_attempt_lease(&incumbent, first_renewal, 200)
            .expect("incumbent renewal");
        incumbent.lease_renewal_seq = LeaseRenewalSeq(2);

        assert_eq!(
            coord
                .admit_worker_session(&worker_offer(5, 0x22))
                .expect("clone decision"),
            (WorkerAdmission::RejectCloneAmbiguity, None)
        );
        assert_eq!(
            coord
                .admit_worker_session(&first)
                .expect("incumbent reconnect decision"),
            (WorkerAdmission::RejectCloneAmbiguity, None),
            "ambiguity fences the incumbent as well as the challenger"
        );
        assert_eq!(
            coord.renew_attempt_lease(
                &incumbent,
                LeaseRenewal {
                    lease: incumbent.execution_lease_id,
                    seq: LeaseRenewalSeq(3),
                },
                300,
            ),
            Err(AttemptLeaseRefusal::Store(StoreError::WorkerLeaseRejected(
                WorkerLeaseBindingRejection::CloneAmbiguous,
            )))
        );

        let mut stale_offer = offer_under(&coordinator);
        stale_offer.authority = incumbent.clone();
        assert_eq!(
            coord.commit_offer(&stale_offer, &sample_expected_descriptor()),
            Err(CommitRefusal::Offer(OfferRefusal::Store(
                StoreError::WorkerLeaseRejected(WorkerLeaseBindingRejection::CloneAmbiguous),
            )))
        );
        {
            let mut store = cas.store().lock().expect("store lock");
            assert!(
                !store
                    .has_publication(&incumbent.action_key)
                    .expect("publication query")
            );
            assert!(
                store
                    .worker_incarnation_fence(&incumbent.worker_peer_id)
                    .expect("fence query")
                    .expect("worker fence")
                    .clone_ambiguous
            );
            assert!(
                store
                    .lease_state(incumbent.execution_lease_id.0)
                    .expect("lease query")
                    .expect("incumbent lease")
                    .released,
                "clone detection durably revokes pre-ambiguity leases"
            );
        }

        drop(coord);
        drop(cas);
        let reopened = Arc::new(mount_and_reconcile(dir.path()).expect("reopen"));
        let mut store = reopened.store().lock().expect("reopened store lock");
        assert_eq!(
            store.validate_attempt_lease(&incumbent),
            Err(StoreError::WorkerLeaseRejected(
                WorkerLeaseBindingRejection::CloneAmbiguous,
            )),
            "ambiguity survives process/store reopen"
        );

        let mut selected = worker_offer(5, 0x22);
        selected.reenrollment_proof = Some(1);
        assert_eq!(
            store.admit_worker_session(&authority_digest, &selected, 400),
            Ok(WorkerAdmission::AdmitViaReenrollment)
        );
        assert_eq!(
            store.validate_attempt_lease(&incumbent),
            Err(StoreError::WorkerLeaseRejected(
                WorkerLeaseBindingRejection::IncarnationMismatch,
            )),
            "the revoked incumbent lease cannot revive after selecting another clone"
        );

        let mut replacement = incumbent.clone();
        replacement.attempt_id = AttemptId(21);
        replacement.execution_lease_id = ExecutionLeaseId(31);
        replacement.lease_renewal_seq = LeaseRenewalSeq(1);
        replacement.worker_incarnation_id = WorkerIncarnationId(0x22);
        store
            .admit_attempt_lease(&replacement, 401, 500)
            .expect("replacement lease");
        store
            .renew_attempt_lease(
                &replacement,
                LeaseRenewal {
                    lease: replacement.execution_lease_id,
                    seq: LeaseRenewalSeq(2),
                },
                600,
            )
            .expect("replacement renewal");
        replacement.lease_renewal_seq = LeaseRenewalSeq(2);
        assert_eq!(
            store.validate_attempt_lease(&replacement),
            Ok(rabs_cas::metadata_store::LeaseState {
                released: false,
                renewal_seq: 2,
            })
        );
    }
}
