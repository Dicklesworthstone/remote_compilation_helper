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

mod output_install;
mod request_owned_install;
pub(super) use request_owned_install::RequestOwnedInstallError;
#[cfg(test)]
mod produced_result_tests;

use crate::coord::action_actor::{
    ActionActor, AttemptPurpose, CancelReceipt, JoinReceipt, JoinRequest, OpenGenerationReceipt,
    PromoteReceipt, RegisterAttempt, RegisterAttemptReceipt, SubscriptionRequirements,
};
use crate::coord::target_lease::TargetLeaseRegistry;
use crate::edge::destination_arbiter::{BundleId, DestinationArbiter, reserve_scoped};
use crate::janitor::store::LiveCas;
use rabs_cas::blob_store::RAW_PROFILE_V1;
use rabs_cas::digest_set::ATP_OBJECT_CONTENT_DOMAIN;
use rabs_cas::digest_set::{DigestRequest, digest_set};
use rabs_cas::manifest_codec::{decode_manifest_v1, encode_manifest_v1};
use rabs_cas::materialization::ActionMaterializeFailure;
use rabs_cas::metadata_store::{
    AuthorityRow, RabsMetadataStore, SqlValue, StoreError, TrustEvaluationRow, digest_key,
};
use rabs_cas::publication::{
    AUTHORITY_DIGEST_DOMAIN, CommitDurabilityProfile, OBSERVABLE_PROJECTION_DOMAIN,
    OfferPreparedActionResult, OfferRefusal, PublicationOutcome, SEMANTIC_PROJECTION_DOMAIN,
    authority_digest, process_offer_resolving,
};
use rabs_cas::serving_sample_gate::{
    ActionClassRisk, PrivateExecutionReason, SampleGateDecision, SamplingPolicy,
    class_safety_refusal, serving_sample_decision,
};
use rabs_cas::serving_state::{ServeDecision, serving_gate};
use rabs_cas::trust_evidence::{DISPOSITION_SERVABLE, evidence_set_digest};
use rabs_key::action_key::{action_input_manifest_digest, compute_action_key};
use rabs_key::logical_output_map::DOMAIN_ARTIFACT_BUNDLE_ROOT;
use rabs_key::typed_digest::{DOMAIN_ACTION_KEY, DOMAIN_DESCRIPTOR};
use rabs_protocol::authority::{ClusterId, CoordinatorAuthority, CoordinatorIncarnationId};
use rabs_protocol::dashboards::{
    SpeculationDefaultOnDecisionRecord, SpeculationDefaultOnGateInput, SpeculationDefaultOnPosture,
    SpeculationRoiPanel, SpeculationRunOutcome, SpeculationRunRecord, build_speculation_roi,
    evaluate_speculation_default_on_gate,
};
use rabs_protocol::descriptor::{ActionDescriptor, SubscriberKind};
use rabs_protocol::durable_ids::BuildOperationId;
use rabs_protocol::generation::{
    AttemptAuthority, AttemptId, ExecutionLeaseId, LeaseRenewal, LeaseRenewalSeq,
    WorkerIncarnationId,
};
use rabs_protocol::input_evidence::{ActionInputManifest, InputFileType};
use rabs_protocol::release_authorization::{
    ReleaseAuthorization, ReleaseAuthorizationMode, authorization as release_standing,
};
use rabs_protocol::result_identity::{
    CanonicalActionResultManifest, DigestAlgorithm, ObjectId, TypedDigest,
};
use rabs_protocol::serving::{
    CiCanonicalWriterClaim, CiCanonicalWriterPolicy, CiEvaluationContext, CiPolicyApproval,
    CiPolicyRefusal, TrustEvidenceTier, evaluate_ci_canonical_writer_claim,
};
use rabs_protocol::wire_time::PeerId;
use rabs_protocol::worker_fence::{WorkerAdmission, WorkerSessionOffer};
use rabs_sandbox::snapshot_capture::{MemberKind, SealedSourceSnapshot};
use rabs_scheduler::acquisition_order::{GrantRefusal, RootGrant, TransferableToken};
use rabs_scheduler::fairness::{FairQueue, TenantKey};
use rabs_scheduler::speculation_brownout::{
    BrownoutDecision, PressureBand, SpeculationProvenance, WorkCategory, band, decide,
};
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Instant;

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

/// Why a work-skipping edge request must execute privately instead.
/// These decisions precede destination reservation and all artifact writes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReplayRefusal {
    /// A completed comparison failed. Negative evidence, including an
    /// unattributed failure, must never be averaged away by later passes.
    FailedVerification {
        /// Number of adverse observations retained for this action.
        observations: u64,
    },
    /// The latest independently verified result has exhausted its replay
    /// allowance, or no durable live comparison has established one yet.
    FreshVerificationRequired,
    /// The existing class/evidence/sampling policy requires private execution.
    Sampling(PrivateExecutionReason),
}

/// The answer to a serve request that is not a fault.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ServeOutcome {
    /// The result may be retained, but this request is not authorized to
    /// skip execution. Nothing has been reserved or installed.
    ExecutePrivately(ReplayRefusal),
    /// Materialized; these files now exist (empty when the committed
    /// manifest declares no materializable output).
    Served {
        /// The destinations written, in installation order (.rmeta first).
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
    /// T011: this BUILD is not authorized to serve. The stock
    /// differential corpus gate has not passed for the running binary —
    /// no verdict, an expired one, one recorded for a different build,
    /// or one carrying no evidence — and the deployment runs in
    /// [`ReleaseAuthorizationMode::Required`].
    ///
    /// Distinct from [`Self::NotServable`], which is about one action.
    /// This is about the whole binary, so it is checked before any
    /// per-action state is read: a build that may not serve must not
    /// serve even an action whose own record is impeccable. The
    /// standing is preserved because "we never ran the gate here" and
    /// "the deployed build is not the one we proved" call for different
    /// operator responses.
    ReleaseUnauthorized {
        /// Why the running build is unproven.
        standing: ReleaseAuthorization,
    },
    /// Preview only: every gate passed and the complete output plan
    /// (including subscriber dep-info derivation in private scratch) was
    /// prepared. Nothing was reserved or installed; a later install request
    /// re-evaluates every gate under one store lock.
    Servable,
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

/// Whether a serve request installs or only evaluates every gate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServeMode {
    /// Reserve destinations and install verified outputs.
    Install,
    /// Evaluate gates and prepare the complete plan; write no target file.
    Preview,
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
    /// committed manifest's complete logical-output set must equal it
    /// exactly.
    Exactly(std::collections::BTreeSet<String>),
    /// Exact outputs plus byte-preserving canonical-directory to subscriber-
    /// directory mappings used ONLY for private dep-info derivation. Neither
    /// the mappings nor derived .d bytes change the action/CAS identity.
    WithDepInfo {
        /// Complete canonical output names, including .rmeta and .d.
        paths: std::collections::BTreeSet<String>,
        /// Directory mappings; component boundaries and longest-prefix order
        /// are validated before deriving any subscriber output.
        mappings: Vec<(Vec<u8>, Vec<u8>)>,
    },
    /// Canonical Cargo consumes the exact namespace-visible .d bytes. These
    /// mappings translate validation and freshness I/O only; they never rewrite
    /// the compiler's paths or the installed dep-info. The retained driver
    /// capability constructs and revalidates the backing mappings.
    CanonicalCargo {
        /// Complete output names relative to the retained target directory.
        paths: std::collections::BTreeSet<String>,
        /// The compiler's absolute namespace-visible working directory.
        working_directory: Vec<u8>,
        /// Namespace roots and their private filesystem backings.
        mappings: Vec<(Vec<u8>, Vec<u8>)>,
    },
    /// The caller is not skipping any work and accepts whatever the
    /// commit declares: operator and diagnostic paths only. A wrapper
    /// must never use this.
    WhateverWasCommitted,
}

/// A serve refusal or interrupted materialization. `Materialize` retains the
/// exact installed prefix; it MUST NOT be interpreted as an untouched target
/// tree or permission to run a compiler. A lost reply is likewise uncertain.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ServeError {
    /// Work-skipping replay requires this process's live, active coordinator.
    CoordinatorUnavailable,
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
    /// Whole-plan or dep-info preparation failed before any target output was
    /// installed. Private scratch may have been written; no CAS bytes changed.
    Preparation {
        /// The affected destination (presentation only).
        path: String,
        /// Why the complete plan could not be prepared.
        reason: String,
    },
    /// The existing materializer's full failure, including any already
    /// installed, verified prefix. Never erase this delivery-frontier evidence.
    Materialize(ActionMaterializeFailure),
}

impl std::fmt::Display for ServeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::CoordinatorUnavailable => write!(f, "no live coordinator authority for replay"),
            Self::NoStore => write!(f, "no rabs-cas store mounted"),
            Self::StoreUnavailable => write!(f, "store lock poisoned"),
            Self::Store(error) => write!(f, "store error: {error}"),
            Self::UnsafeVirtualPath { path } => {
                write!(f, "virtual path {path:?} escapes the destination root")
            }
            Self::DestinationConflict { path, holder } => {
                write!(f, "destination {path} is held by {holder}")
            }
            Self::Preparation { path, reason } => write!(f, "preparing {path}: {reason}"),
            Self::Materialize(failure) => write!(
                f,
                "materialization interrupted after {} installed outputs: {}",
                failure.installed.len(),
                failure.error,
            ),
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

// The class receipt is derived from the actual keyed descriptor at submission,
// never from a class/risk flag supplied in a socket frame. Its sequence is fixed:
// an action key has one semantic class, independent of attempts and restarts.
const LIVE_CLASS_RECEIPT: &str = "rabs-live-action-class-v1";
const LIVE_DEPENDENCY_CLASS: &str = "rustc-dependency-compile";
const LIVE_PRIVATE_CLASS: &str = "private-only";

// This is an additional floor, not a replacement for the stored serving policy.
// In particular it never promotes a quarantined/evidence-pending record, renews
// its TTL, or changes a trust-policy version. Every edge-delivered artifact
// passes this floor, including the opt-in live dependency lane.
const LIVE_SAMPLING_POLICY: SamplingPolicy = SamplingPolicy::sample_all(2, 10_000);
const LIVE_VERIFICATION_RECEIPT: &str = "rabs-live-verification-v1";
const LIVE_INSTALL_RECEIPT: &str = "rabs-live-replay-install-v1";

/// Default cache installations after one new independent comparison.
/// Opt-in SPRT replaces only this ceiling with its evidence-qualified limit;
/// the same comparison binding and durable installation receipts remain required.
pub const LIVE_REPLAY_INSTALL_LIMIT: u64 = 16;

fn record_descriptor_class(
    store: &mut dyn RabsMetadataStore,
    descriptor: &ActionDescriptor,
) -> Result<(), StoreError> {
    let class = if descriptor.action_class
        == rabs_protocol::descriptor::ActionClass::RustcDependencyCompile
    {
        LIVE_DEPENDENCY_CLASS
    } else {
        LIVE_PRIVATE_CLASS
    };
    store.record_decision_receipt(
        LIVE_CLASS_RECEIPT,
        &digest_key(&compute_action_key(descriptor).final_key),
        0,
        class,
        "semantic class bound to the submitted action descriptor",
    )
}

fn recorded_action_risk(
    store: &mut dyn RabsMetadataStore,
    action: &TypedDigest,
) -> Result<ActionClassRisk, StoreError> {
    let rows = store.query(
        "SELECT decision FROM decision_receipts \
         WHERE kind = ?1 AND subject = ?2 AND seq = 0",
        &[
            SqlValue::Text(LIVE_CLASS_RECEIPT.to_owned()),
            SqlValue::Text(digest_key(action)),
        ],
    )?;
    match rows.as_slice() {
        // Legacy publications and unknown classes do not silently become
        // dependency actions, including after a coordinator restart.
        [] => Ok(ActionClassRisk::Elevated),
        [row] => match row.as_slice() {
            [SqlValue::Text(class)] if class == LIVE_DEPENDENCY_CLASS => {
                Ok(ActionClassRisk::LowRiskRegistry)
            }
            [SqlValue::Text(_)] => Ok(ActionClassRisk::Elevated),
            _ => Err(StoreError::Backend(
                "invalid live action-class receipt".to_owned(),
            )),
        },
        _ => Err(StoreError::Backend(
            "ambiguous live action-class receipt".to_owned(),
        )),
    }
}

/// Record ONLY a comparison admitted by the real publication engine. A first
/// publication is not a comparison, and retransmitting the winning attempt is
/// not a second execution. Invalid/stale offers never reach this function.
fn record_live_verification(
    store: &mut dyn RabsMetadataStore,
    offer: &OfferPreparedActionResult,
    outcome: &PublicationOutcome,
    committed: Option<&CanonicalActionResultManifest>,
) -> Result<(), StoreError> {
    let passed = match outcome {
        PublicationOutcome::Committed(_) => return Ok(()),
        PublicationOutcome::IdempotentEvidenceAppended => true,
        PublicationOutcome::Quarantined(_) => false,
    };
    let action = &offer.manifest.action_key;
    let attempt = offer.authority.attempt_id.0;
    if passed {
        // A repeated pointer is not itself a verified comparison. Bind the
        // offered value to its content id AND the independently loaded baseline.
        // Missing/corrupt baseline bytes must never manufacture passing evidence.
        let baseline = committed
            .ok_or_else(|| StoreError::Backend("verification baseline unavailable".to_owned()))?;
        let bytes = encode_manifest_v1(&offer.manifest);
        let offered_id = digest_set(&bytes, DigestRequest::default(), None)
            .map_err(|_| StoreError::Backend("verification manifest digest failed".to_owned()))?
            .atp_content_id;
        if offered_id != offer.manifest_id.0 || encode_manifest_v1(baseline) != bytes {
            return Err(StoreError::Backend(
                "verification manifest does not match its committed bytes".to_owned(),
            ));
        }
        let rows = store.query(
            "SELECT winner_attempt_hex FROM action_publications WHERE action_key = ?1",
            &[SqlValue::Text(digest_key(action))],
        )?;
        let [row] = rows.as_slice() else {
            return Err(StoreError::Backend(
                "missing verification baseline".to_owned(),
            ));
        };
        let [SqlValue::Text(winner)] = row.as_slice() else {
            return Err(StoreError::Backend(
                "invalid verification baseline".to_owned(),
            ));
        };
        let winner = u128::from_str_radix(winner, 16)
            .map_err(|_| StoreError::Backend("invalid winner attempt identity".to_owned()))?;
        if winner == attempt {
            return Ok(());
        }
    }

    let samples = store.list_verification_samples(action)?;
    // Never overwrite a failure with a pass, or count a replay twice. Some
    // store backends implement record_verification_sample as an upsert, so
    // allocate a fresh sequence instead of assuming a reserved sequence is free.
    if samples.iter().any(|sample| {
        u128::from_str_radix(&sample.attempt_hex, 16).ok() == Some(attempt)
            && (passed || !sample.passed)
    }) {
        return Ok(());
    }
    let seq = samples
        .iter()
        .map(|sample| sample.seq)
        .max()
        .map_or(Some(0), |seq| seq.checked_add(1))
        .ok_or_else(|| StoreError::Backend("verification sequence exhausted".to_owned()))?;
    store.record_verification_sample(action, attempt, passed, seq)?;
    if passed {
        // Only this admission path can renew replay authority. Raw samples,
        // retransmissions, the original winner, and failed attempts cannot.
        // If this second durable write fails, the old allowance remains in
        // force; another independent comparison is needed to renew it.
        store.record_decision_receipt(
            LIVE_VERIFICATION_RECEIPT,
            &digest_key(action),
            seq,
            &format!("{attempt:032x}"),
            &digest_key(&offer.manifest_id.0),
        )?;
    }
    Ok(())
}

struct ReplayInstallPermit {
    subject: String,
    seq: u64,
}

/// Inspect the durable allowance without spending it. Both preview and install
/// read it afresh under the CAS lock; only an actual installation appends a
/// receipt, before any output writes. The comparison and spent permits survive
/// coordinator restarts and cannot be reset by replaying an old offer.
fn live_replay_permit(
    store: &mut dyn RabsMetadataStore,
    action: &TypedDigest,
    manifest_key: &str,
) -> Result<Option<ReplayInstallPermit>, StoreError> {
    let action_key = digest_key(action);
    let rows = store.query(
        "SELECT seq, decision, reason FROM decision_receipts \
         WHERE kind = ?1 AND subject = ?2 ORDER BY seq DESC LIMIT 1",
        &[
            SqlValue::Text(LIVE_VERIFICATION_RECEIPT.to_owned()),
            SqlValue::Text(action_key.clone()),
        ],
    )?;
    let Some(row) = rows.first() else {
        return Ok(None);
    };
    let [
        SqlValue::Int(seq),
        SqlValue::Text(attempt),
        SqlValue::Text(manifest),
    ] = row.as_slice()
    else {
        return Err(StoreError::Corruption(
            "live verification receipt shape".into(),
        ));
    };
    let seq = u64::try_from(*seq)
        .map_err(|_| StoreError::Corruption("live verification sequence".into()))?;
    if manifest != manifest_key
        || attempt.len() != 32
        || !attempt.bytes().all(|byte| byte.is_ascii_hexdigit())
        || !store
            .list_verification_samples(action)?
            .iter()
            .any(|sample| sample.passed && sample.seq == seq && sample.attempt_hex == *attempt)
    {
        return Err(StoreError::Corruption(
            "unbound live verification receipt".into(),
        ));
    }
    let subject = format!("{action_key}:{seq}");
    let installed = store.query(
        "SELECT seq, decision, reason FROM decision_receipts \
         WHERE kind = ?1 AND subject = ?2 ORDER BY seq",
        &[
            SqlValue::Text(LIVE_INSTALL_RECEIPT.to_owned()),
            SqlValue::Text(subject.clone()),
        ],
    )?;
    for (index, row) in installed.iter().enumerate() {
        let expected_seq = i64::try_from(index)
            .map_err(|_| StoreError::Corruption("live replay sequence exhausted".into()))?;
        if !matches!(
            row.as_slice(),
            [SqlValue::Int(seq), SqlValue::Text(decision), SqlValue::Text(reason)]
                if *seq == expected_seq && decision == "install" && reason == manifest_key
        ) {
            return Err(StoreError::Corruption("invalid live replay receipt".into()));
        }
    }
    let used = u64::try_from(installed.len())
        .map_err(|_| StoreError::Corruption("live replay count exhausted".into()))?;
    // None means the opt-in is off, not that evidence failed. Some(0) is a
    // hard verification requirement and must never inherit the fixed budget.
    // Policy changes reuse these same receipts, so they cannot replenish it.
    let limit = LIVE_SAMPLING_POLICY
        .replay_install_limit(store, action)?
        .unwrap_or(LIVE_REPLAY_INSTALL_LIMIT);
    Ok((used < limit).then_some(ReplayInstallPermit { subject, seq: used }))
}

/// Final live replay admission, called with the SAME store lock subsequently
/// held through manifest reload and installation. No result from this function
/// is a reusable authorization token: every request is evaluated afresh.
fn live_replay_gate(
    store: &mut dyn RabsMetadataStore,
    action: &TypedDigest,
    policy: &SamplingPolicy,
) -> Result<Option<ReplayRefusal>, StoreError> {
    let risk = recorded_action_risk(store, action)?;
    let adverse = store
        .list_verification_samples(action)?
        .iter()
        .filter(|sample| !sample.passed)
        .count();
    if adverse != 0 {
        return Ok(Some(ReplayRefusal::FailedVerification {
            observations: u64::try_from(adverse).unwrap_or(u64::MAX),
        }));
    }
    match serving_sample_decision(store, action, risk, policy)? {
        SampleGateDecision::ServeFromCache => Ok(None),
        SampleGateDecision::ExecutePrivately(reason) => Ok(Some(ReplayRefusal::Sampling(reason))),
    }
}

/// A current primary producer bypasses positive sample counts and replay
/// cadence, while retaining every adverse-evidence and class admission veto.
fn live_producer_gate(
    store: &mut dyn RabsMetadataStore,
    action: &TypedDigest,
) -> Result<Option<ReplayRefusal>, StoreError> {
    if recorded_action_risk(store, action)? == ActionClassRisk::Elevated {
        return Ok(Some(ReplayRefusal::Sampling(
            PrivateExecutionReason::ElevatedClassRisk,
        )));
    }
    let adverse = store
        .list_verification_samples(action)?
        .iter()
        .filter(|sample| !sample.passed)
        .count();
    if adverse != 0 {
        return Ok(Some(ReplayRefusal::FailedVerification {
            observations: u64::try_from(adverse).unwrap_or(u64::MAX),
        }));
    }
    Ok(class_safety_refusal(store, action)?.map(ReplayRefusal::Sampling))
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

#[derive(Debug)]
struct ProjectedDirectory {
    root: String,
    relative: String,
}

/// A descriptor bound to actual retained source bytes BEFORE submission.
/// This source lane supports projected regular files and complete captured
/// directory inventories. Other positive input kinds need their own verified
/// materializers and are refused explicitly. Separately retained key-only
/// evidence never becomes a compiler-visible filesystem input.
/// Invocation, environment and negative-dependency validation remain the edge's
/// responsibility; this constructor is not a parser for untrusted wire requests.
#[derive(Debug)]
pub struct ActionSubmission {
    descriptor: ActionDescriptor,
    source: Arc<SealedSourceSnapshot>,
    files: Vec<ProjectedFile>,
    directories: Vec<ProjectedDirectory>,
    evidence: Vec<Arc<[u8]>>,
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
        Self::from_snapshot_with_evidence(descriptor, manifest, source, mappings, &[])
    }

    /// Validate captured compiler inputs plus retained non-executable evidence,
    /// such as a completed Cargo build-script stdout record. Every evidence
    /// object must exactly match one positive manifest input outside all mapped
    /// source roots. Its bytes are retained for the submission's lifetime but
    /// never materialized or mounted. This cannot replace a captured source
    /// file or fill a missing member of an enumerated source tree.
    pub fn from_snapshot_with_evidence(
        descriptor: ActionDescriptor,
        manifest: &ActionInputManifest,
        source: Arc<SealedSourceSnapshot>,
        mappings: &[(String, String)],
        evidence: &[(String, Vec<u8>)],
    ) -> Result<Self, SubmissionRefusal> {
        let invalid = |why: &str| SubmissionRefusal::InvalidSource(why.to_owned());
        let digest = action_input_manifest_digest(manifest)
            .map_err(|error| invalid(&format!("invalid input manifest: {error:?}")))?;
        if digest != descriptor.action_inputs {
            return Err(invalid("descriptor input digest does not match projection"));
        }
        if (manifest.inputs.is_empty() && manifest.directory_enumerations.is_empty())
            || !manifest.approved_generated_objects.is_empty()
        {
            return Err(invalid(
                "this source lane requires captured files or complete directories",
            ));
        }
        let mut roots = BTreeSet::new();
        for (root, visible) in mappings {
            let canonical_root = visible == rabs_sandbox::layout::WORKSPACE
                || visible
                    .strip_prefix(&format!("{}/", rabs_sandbox::layout::REPOS))
                    .is_some_and(source_component);
            if !canonical_root
                || !source_component(root)
                || !roots.insert(root)
                || source.manifest(root).is_none()
            {
                return Err(invalid("invalid or duplicate snapshot root mapping"));
            }
        }
        for (index, (_, visible)) in mappings.iter().enumerate() {
            if mappings[..index].iter().any(|(_, prior)| {
                Path::new(prior).starts_with(visible) || Path::new(visible).starts_with(prior)
            }) {
                return Err(invalid("ambiguous canonical root mapping"));
            }
        }
        let mut retained_evidence = BTreeMap::new();
        for (path, bytes) in evidence {
            let canonical = path
                .strip_prefix(&format!("{}/", rabs_sandbox::layout::WORKSPACE))
                .is_some_and(|relative| relative.split('/').all(source_component))
                || path
                    .strip_prefix(&format!("{}/", rabs_sandbox::layout::REPOS))
                    .and_then(|relative| relative.split_once('/'))
                    .is_some_and(|(root, relative)| {
                        source_component(root) && relative.split('/').all(source_component)
                    });
            if !canonical
                || mappings.iter().any(|(_, visible)| {
                    Path::new(path).starts_with(visible) || Path::new(visible).starts_with(path)
                })
                || retained_evidence
                    .insert(path.as_str(), Arc::<[u8]>::from(bytes.as_slice()))
                    .is_some()
            {
                return Err(invalid(
                    "invalid, overlapping or duplicate key-only evidence",
                ));
            }
        }
        let mut files = Vec::new();
        let mut paths = BTreeSet::new();
        let mut projected_members = BTreeSet::new();
        let mut matched_evidence = BTreeSet::new();
        for input in &manifest.inputs {
            if input.file_type != InputFileType::Regular || !input.symlink_resolution.is_empty() {
                return Err(invalid("unsupported non-regular source projection"));
            }
            let path = std::str::from_utf8(input.virtual_path.as_bytes())
                .map_err(|_| invalid("source path is not lossless UTF-8"))?;
            if !paths.insert(path.to_owned()) {
                return Err(invalid("duplicate source path"));
            }
            if let Some(bytes) = retained_evidence.get(path) {
                let object = digest_set(bytes, DigestRequest::default(), None)
                    .map_err(|_| invalid("evidence object digest failed"))?
                    .atp_content_id;
                if input.executable || input.object.0 != object {
                    return Err(invalid("key-only evidence differs from its retained bytes"));
                }
                matched_evidence.insert(path);
                continue;
            }
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
            projected_members.insert((root.clone(), relative.to_owned()));
            files.push(ProjectedFile {
                root: root.clone(),
                relative: relative.to_owned(),
                executable: input.executable,
            });
        }
        if matched_evidence.len() != retained_evidence.len() {
            return Err(invalid(
                "key-only evidence is absent from the input manifest",
            ));
        }

        // A directory listing promises an exact namespace, including empty
        // directories. Require the complete captured tree for each root with
        // listings, rather than accepting a listing whose unprojected children
        // would disappear when materialized. Roots with files only retain the
        // existing sparse-projection semantics.
        let mut declared: BTreeMap<String, BTreeMap<String, Vec<String>>> = BTreeMap::new();
        for enumeration in &manifest.directory_enumerations {
            let path = std::str::from_utf8(enumeration.virtual_path.as_bytes())
                .map_err(|_| invalid("directory path is not lossless UTF-8"))?;
            let (root, relative) = mappings
                .iter()
                .find_map(|(root, visible)| {
                    if path == visible {
                        Some((root, ""))
                    } else {
                        path.strip_prefix(visible.as_str())
                            .and_then(|suffix| suffix.strip_prefix('/'))
                            .map(|relative| (root, relative))
                    }
                })
                .ok_or_else(|| invalid("directory listing is outside mapped roots"))?;
            if (!relative.is_empty() && !relative.split('/').all(source_component))
                || enumeration
                    .entries
                    .windows(2)
                    .any(|pair| pair[0] >= pair[1])
            {
                return Err(invalid("directory listing has unsafe or duplicate entries"));
            }
            let entries = enumeration
                .entries
                .iter()
                .map(|entry| {
                    let name = std::str::from_utf8(entry.as_bytes())
                        .map_err(|_| invalid("directory entry is not lossless UTF-8"))?;
                    if !source_component(name) {
                        return Err(invalid("directory entry contains unsafe components"));
                    }
                    Ok(name.to_owned())
                })
                .collect::<Result<Vec<_>, _>>()?;
            if declared
                .entry(root.clone())
                .or_default()
                .insert(relative.to_owned(), entries)
                .is_some()
            {
                return Err(invalid("duplicate directory listing"));
            }
        }
        let mut directories = Vec::new();
        for (root, listings) in declared {
            let captured = source
                .manifest(&root)
                .ok_or_else(|| invalid("listed root was not captured"))?;
            let mut expected = BTreeMap::from([(String::new(), BTreeSet::new())]);
            for (relative, member) in &captured.members {
                if !relative.split('/').all(source_component) {
                    return Err(invalid("captured directory has unsafe members"));
                }
                match member {
                    MemberKind::Directory => {
                        expected.insert(relative.clone(), BTreeSet::new());
                    }
                    MemberKind::Regular { .. } => {
                        if !projected_members.contains(&(root.clone(), relative.clone())) {
                            return Err(invalid("listed tree contains an unprojected file"));
                        }
                    }
                    MemberKind::Symlink { .. } => {
                        return Err(invalid("listed tree contains an unsupported symlink"));
                    }
                }
            }
            for relative in captured.members.keys() {
                let (parent, name) = relative.rsplit_once('/').unwrap_or(("", relative));
                expected
                    .get_mut(parent)
                    .ok_or_else(|| invalid("captured tree omits a parent directory"))?
                    .insert(name.to_owned());
            }
            if expected.len() != listings.len()
                || expected.iter().any(|(relative, entries)| {
                    listings
                        .get(relative)
                        .is_none_or(|listing| !listing.iter().eq(entries.iter()))
                })
            {
                return Err(invalid(
                    "directory listings differ from the complete captured tree",
                ));
            }
            directories.extend(expected.into_keys().map(|relative| ProjectedDirectory {
                root: root.clone(),
                relative,
            }));
        }
        if files.is_empty() && directories.is_empty() {
            return Err(invalid(
                "source projection has no captured files or directories",
            ));
        }
        Ok(Self {
            descriptor,
            source,
            files,
            directories,
            evidence: retained_evidence.into_values().collect(),
        })
    }

    /// Semantic identity, independent of subscriber kind and full image identity.
    #[must_use]
    pub fn key(&self) -> TypedDigest {
        compute_action_key(&self.descriptor).final_key
    }

    /// Materialize ONLY projected files and validated complete directory trees
    /// into fresh caller-owned backing. Key-only evidence stays unmounted.
    /// Hidden parents are created; all file modes are normalized to the keyed
    /// executable bit (0644/0755 on Unix). Execution mounts this backing read-only.
    /// Partial failure leaves inspection state and never returns a usable handle.
    pub fn materialize_into(
        &self,
        destination: &Path,
    ) -> std::io::Result<BTreeMap<String, PathBuf>> {
        use std::io::Write;
        std::fs::create_dir(destination)?;
        let mut backing = BTreeMap::new();
        for directory in &self.directories {
            let root = destination.join(&directory.root);
            std::fs::create_dir_all(root.join(&directory.relative))?;
            backing.insert(directory.root.clone(), root);
        }
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

    /// Total retained input bytes, including key-only evidence (for Q009
    /// transfer/storage cost accounting).
    #[must_use]
    pub fn source_bytes(&self) -> u64 {
        self.files
            .iter()
            .filter_map(|file| self.source.file_bytes(&file.root, &file.relative))
            .map(|bytes| u64::try_from(bytes.len()).unwrap_or(u64::MAX))
            .chain(
                self.evidence
                    .iter()
                    .map(|bytes| u64::try_from(bytes.len()).unwrap_or(u64::MAX)),
            )
            .fold(0_u64, u64::saturating_add)
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
    started_as_speculative: bool,
    promoted_from_speculation: bool,
    started_at: Option<Instant>,
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
    /// this returns an admitted authority tuple. `lease_ttl_ms` is a duration;
    /// the coordinator derives the deadline from its own monotonic clock.
    pub fn begin(
        &mut self,
        worker: &WorkerSessionOffer,
        lease_ttl_ms: u64,
    ) -> Result<&AttemptAuthority, SubmissionRefusal> {
        if self.authority.is_some() {
            return Err(SubmissionRefusal::StaleDispatch);
        }
        let authority =
            self.coord
                .begin_submitted_dispatch(&self.key, self.serial, worker, lease_ttl_ms)?;
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
        let authority = self
            .authority
            .as_ref()
            .ok_or(SubmissionRefusal::StaleDispatch)?;
        self.coord
            .advance_started_dispatch(&self.key, self.serial, authority, to)
    }

    /// Complete ownership after the worker has confirmed process/stream cleanup
    /// and the attempt reached Finished. This is NOT a cache publication; offers
    /// still go through the coordinator's durable publication gate.
    pub fn complete(mut self) -> Result<(), SubmissionRefusal> {
        let authority = self
            .authority
            .as_ref()
            .ok_or(SubmissionRefusal::StaleDispatch)?;
        self.coord
            .complete_started_dispatch(&self.key, self.serial, authority)?;
        self.completed = true;
        Ok(())
    }
}

impl Drop for ActionDispatch<'_> {
    fn drop(&mut self) {
        if !self.completed {
            self.coord.release_dispatch_claim(&self.key, self.serial);
        }
    }
}

/// Subscriber capability for an edge attached to this coordinator.
///
/// Clones share the authoritative registry; they cannot claim execution or
/// publish results. This is an in-process capability boundary, not a remote
/// authentication protocol. Materialization still uses coordinator-owned state.
///
/// ```compile_fail,E0599
/// use rabsd::coord::live::EdgeSubscriber;
/// fn dispatch(edge: EdgeSubscriber) {
///     edge.next_action_dispatch();
/// }
/// ```
///
/// ```compile_fail,E0599
/// use rabsd::coord::live::EdgeSubscriber;
/// fn publish(edge: EdgeSubscriber) {
///     let _publish = EdgeSubscriber::commit_offer;
/// }
/// ```
#[derive(Debug, Clone)]
pub struct EdgeSubscriber {
    coord: Arc<CoordLive>,
}

impl EdgeSubscriber {
    pub fn submit_action(
        &self,
        input: ActionSubmission,
        request: JoinRequest,
        now_unix_micros: i64,
        clock_epoch: u64,
    ) -> Result<SubmissionReceipt, SubmissionRefusal> {
        self.coord
            .submit_action(input, request, now_unix_micros, clock_epoch)
    }

    /// Detach a subscriber's interest from an in-flight action (bead G005).
    pub fn cancel_subscriber(
        &self,
        action_key: &TypedDigest,
        operation: BuildOperationId,
    ) -> Result<CancelReceipt, SubmissionRefusal> {
        self.coord.cancel_subscriber(action_key, operation)
    }

    /// Promote an attached subscriber's interest in place (bead Q005 / G004).
    pub fn promote_subscriber(
        &self,
        action_key: &TypedDigest,
        operation: BuildOperationId,
        deadline_unix_micros: Option<i64>,
    ) -> Result<PromoteReceipt, SubmissionRefusal> {
        self.coord
            .promote_subscriber(action_key, operation, deadline_unix_micros)
    }

    pub fn serve_action(
        &self,
        action_key: &TypedDigest,
        destination_root: &Path,
        expected: &ExpectedOutputs,
        now_unix_micros: i64,
        now_epoch: u64,
    ) -> Result<ServeOutcome, ServeError> {
        // Every edge request must pass the live evidence/class gate. Omitting
        // expected outputs changes only output-set matching; it is not an
        // inspection capability and cannot waive trust or sampling policy.
        self.coord.serve_action_inner(
            action_key,
            destination_root,
            expected,
            now_unix_micros,
            now_epoch,
            Some(LIVE_SAMPLING_POLICY),
            ServeMode::Install,
        )
    }

    #[must_use]
    pub fn available(&self) -> bool {
        self.coord.available()
    }

    #[must_use]
    pub fn status_json(&self) -> String {
        self.coord.status_json()
    }

    #[must_use]
    pub fn begin_flight(&self, key: &str) -> FlightRole {
        self.coord.begin_flight(key)
    }

    pub fn end_flight(&self, key: &str) {
        self.coord.end_flight(key);
    }
}

/// Durable `decision_receipts` kind written whenever the Q010 default-on
/// speculation gate is evaluated (`rabsd::coord::live`).
pub const SPECULATION_DEFAULT_ON_RECEIPT_KIND: &str = "speculation_default_on_gate";

/// Durable `decision_receipts` kind written whenever a Q007 git/worktree
/// prewarm event is handled (`rabsd::coord::live`).
pub const GIT_PREWARM_RECEIPT_KIND: &str = "q007_git_prewarm_event";

/// Durable `decision_receipts` kind written whenever a Q008 CI canonical
/// prewarm publication is promoted (`rabsd::coord::live`).
pub const CI_CANONICAL_PREWARM_RECEIPT_KIND: &str = "q008_ci_canonical_prewarm";

/// Durable `decision_receipts` kind written whenever the live Cargo root-permit
/// broker admits, refuses, or completes a Cargo root (`bd-d4uqa` / `T016`).
pub const CARGO_ROOT_BROKER_RECEIPT_KIND: &str = "cargo_root_permit_broker";

/// Receipt emitted when a Cargo build request is enqueued in the live root-permit broker (`bd-d4uqa`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CargoRootEnqueueReceipt {
    /// Owning tenant across fairness dimensions.
    pub tenant: TenantKey,
    /// Unique Cargo root invocation identifier.
    pub root_id: String,
    /// Enqueue tick.
    pub enqueued_at: u64,
    /// Durable receipt sequence in `decision_receipts`.
    pub receipt_seq: u64,
}

/// Receipt emitted when the live Cargo root-permit broker grants a root permit (`bd-d4uqa` / `T016`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CargoRootGrantReceipt {
    /// Owning tenant.
    pub tenant: TenantKey,
    /// Granted Cargo root invocation identifier.
    pub root_id: String,
    /// Granted root capacity `C` (`1` implicit + `C - 1` transferable jobserver tokens).
    pub capacity: u32,
    /// Enqueue-to-grant wait time in ticks.
    pub wait_ticks: u64,
    /// Active Cargo roots after this grant (`<= max_concurrent_cargo_roots`).
    pub active_cargo_roots: u32,
    /// Configured ceiling on concurrent Cargo roots (`T016`).
    pub max_concurrent_cargo_roots: u32,
    /// Durable receipt sequence in `decision_receipts`.
    pub receipt_seq: u64,
}

/// Receipt emitted when an active Cargo root completes and releases its root grant (`bd-d4uqa`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CargoRootCompletionReceipt {
    /// Completed Cargo root invocation identifier.
    pub root_id: String,
    /// Active Cargo roots remaining after completion.
    pub active_cargo_roots: u32,
    /// Durable receipt sequence in `decision_receipts`.
    pub receipt_seq: u64,
}

/// Live telemetry snapshot for the coordinator's Cargo root-permit broker (`bd-d4uqa` / `T016`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CargoRootBrokerTelemetry {
    /// Maximum concurrent Cargo roots allowed by policy (`T016`).
    pub max_concurrent_cargo_roots: u32,
    /// Per-root capacity `C` (`1` implicit + `C - 1` transferable tokens).
    pub per_root_capacity: u32,
    /// Currently active Cargo roots holding an open `RootGrant`.
    pub active_cargo_roots: u32,
    /// High-water mark of active Cargo roots observed (`must be <= max_concurrent_cargo_roots`).
    pub peak_active_cargo_roots: u32,
    /// Requests currently waiting in the weighted fair queue.
    pub queued_requests: u64,
    /// Total requests enqueued.
    pub total_enqueued: u64,
    /// Total root permits granted.
    pub total_granted: u64,
    /// Total root permits completed and released.
    pub total_completed: u64,
    /// Total admission attempts deferred/refused because `active_cargo_roots == max_concurrent_cargo_roots`.
    pub total_root_cap_refusals: u64,
    /// Hard starvation bound in ticks configured on the `FairQueue`.
    pub starvation_bound: u64,
    /// Worst observed enqueue-to-grant lag per agent (`agent -> max_wait_ticks`).
    pub worst_lag_by_agent: BTreeMap<String, u64>,
    /// Count of granted items whose wait exceeded `starvation_bound`.
    pub starvation_violations: u64,
    /// Service order of granted `root_id`s for deterministic replay auditing.
    pub granted_order: Vec<String>,
}

struct CargoRootBrokerState {
    max_concurrent_cargo_roots: u32,
    per_root_capacity: u32,
    queue: FairQueue,
    queued_count: u64,
    active_grants: BTreeMap<String, RootGrant>,
    peak_active_cargo_roots: u32,
    total_enqueued: u64,
    total_granted: u64,
    total_completed: u64,
    total_root_cap_refusals: u64,
    worst_lag_by_agent: BTreeMap<String, u64>,
    starvation_violations: u64,
    granted_order: Vec<String>,
}

impl Default for CargoRootBrokerState {
    fn default() -> Self {
        Self {
            max_concurrent_cargo_roots: 4,
            per_root_capacity: 4,
            queue: FairQueue::new(64, 16),
            queued_count: 0,
            active_grants: BTreeMap::new(),
            peak_active_cargo_roots: 0,
            total_enqueued: 0,
            total_granted: 0,
            total_completed: 0,
            total_root_cap_refusals: 0,
            worst_lag_by_agent: BTreeMap::new(),
            starvation_violations: 0,
            granted_order: Vec::new(),
        }
    }
}

/// Git / workspace lifecycle event triggering prewarm (bead Q007; plan §15).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GitPrewarmEventKind {
    /// `git checkout <branch>` or `git switch`.
    BranchCheckout,
    /// `HEAD` moved within the active worktree.
    HeadChange,
    /// `git pull`, `git rebase`, or `git merge`.
    PullRebaseMerge,
    /// `git worktree add` created a new worktree.
    WorktreeCreation,
    /// `Cargo.lock` or package lockfile updated.
    LockfileUpdate,
    /// `rust-toolchain.toml` or compiler version changed.
    ToolchainChange,
    /// Commit pushed to CI canonical prewarm pipeline.
    CiPush,
}

impl GitPrewarmEventKind {
    /// Stable machine token for durable receipts and logs.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::BranchCheckout => "branch-checkout",
            Self::HeadChange => "head-change",
            Self::PullRebaseMerge => "pull-rebase-merge",
            Self::WorktreeCreation => "worktree-creation",
            Self::LockfileUpdate => "lockfile-update",
            Self::ToolchainChange => "toolchain-change",
            Self::CiPush => "ci-push",
        }
    }
}

/// Outcome for one critical-path or test-subset action during a Q007 prewarm event.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PrewarmStageOutcome {
    /// Action is already committed and servable in CAS (or warm from nearest ancestor / CI).
    AlreadyWarm {
        /// Semantic action key.
        action_key: TypedDigest,
    },
    /// Action was queued in the coordinator under `SubscriberKind::GitPrewarm`.
    QueuedPrewarm {
        /// Semantic action key.
        action_key: TypedDigest,
        /// Whether this prewarm created a new `ActionActor` or joined an existing one.
        actor_created: bool,
    },
    /// Prewarm stopped immediately due to foreground pressure or brownout.
    StoppedUnderForegroundPressure {
        /// Semantic action key skipped when foreground pressure interrupted prewarm.
        action_key: TypedDigest,
    },
}

/// Structured input event for Q007 git checkout/HEAD/worktree prewarm.
#[derive(Debug)]
pub struct GitPrewarmEvent {
    /// Unique event identifier for durable receipt correlation.
    pub event_id: String,
    /// Triggering git / worktree lifecycle event kind.
    pub kind: GitPrewarmEventKind,
    /// Target `HEAD` commit OID being warmed.
    pub head_commit_oid: String,
    /// Candidate ancestor commit OIDs ordered nearest-first.
    pub parent_commit_oids: Vec<String>,
    /// Worktree identifier.
    pub worktree_id: String,
    /// Digest of the lockfile state.
    pub lockfile_digest: TypedDigest,
    /// Digest of the active toolchain state.
    pub toolchain_digest: TypedDigest,
    /// Dependency critical-path actions to prewarm first.
    pub dependency_critical_path: Vec<ActionSubmission>,
    /// Workspace critical-path actions to prewarm second.
    pub workspace_critical_path: Vec<ActionSubmission>,
    /// Optional canonical test subset to prewarm after compile critical paths.
    pub canonical_test_subset: Vec<ActionSubmission>,
    /// Candidate worker peers to seed for this prewarm wave.
    pub likely_workers: Vec<PeerId>,
    /// Base `BuildOperationId` used to mint distinct subscriber IDs per prewarmed action.
    pub operation_base_id: u128,
    /// Timestamp (Unix microseconds).
    pub now_unix_micros: i64,
    /// Coordinator clock epoch.
    pub clock_epoch: u64,
}

/// Auditable receipt emitted by [`CoordLive::handle_git_prewarm_event`] (bead Q007).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GitPrewarmReceipt {
    /// Event identifier.
    pub event_id: String,
    /// Event kind.
    pub kind: GitPrewarmEventKind,
    /// Target `HEAD` commit OID.
    pub head_commit_oid: String,
    /// Nearest warm ancestor commit located from coordinator/CI state, if any.
    pub nearest_ancestor_commit_oid: Option<String>,
    /// Per-action outcomes along the dependency critical path.
    pub dependency_actions: Vec<PrewarmStageOutcome>,
    /// Per-action outcomes along the workspace critical path.
    pub workspace_actions: Vec<PrewarmStageOutcome>,
    /// Per-action outcomes for the optional canonical test subset.
    pub canonical_test_actions: Vec<PrewarmStageOutcome>,
    /// Admitted non-ambiguous workers seeded for this prewarm event.
    pub seeded_workers: Vec<PeerId>,
    /// Whether prewarm stopped early due to foreground pressure.
    pub stopped_under_foreground_pressure: bool,
    /// Durable receipt sequence in `decision_receipts`.
    pub receipt_seq: u64,
}

/// Auditable receipt emitted when a CI canonical profile publication is promoted to
/// `TrustEvidenceTier::CiPolicyApproved` and registered for developer pull prewarm (bead Q008).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CiCanonicalPrewarmReceipt {
    /// Pushed commit OID that CI prebuilt.
    pub commit_oid: String,
    /// Canonical profile name (e.g. `"check"`, `"test"`, `"clippy"`, `"release"`).
    pub profile_name: String,
    /// Content-addressed semantic action key (identical for local agent and CI builds).
    pub action_key: TypedDigest,
    /// Verified S011 CI policy approval record.
    pub approval: CiPolicyApproval,
    /// Assigned trust tier (`TrustEvidenceTier::CiPolicyApproved`).
    pub assigned_tier: TrustEvidenceTier,
    /// Version appended to `action_trust_evaluations`.
    pub trust_ledger_version: u32,
    /// Durable receipt sequence in `decision_receipts`.
    pub receipt_seq: u64,
}

/// Access/publication policy decision when consulting an action under a required
/// [`TrustEvidenceTier`] (bead Q008).
///
/// Trust tier is publication/access policy, NEVER content identity: local agent
/// results and CI canonical results share the same [`TypedDigest`] action key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrustAccessDecision {
    /// The action's evaluated trust tier meets or exceeds `required_tier`.
    Permitted {
        /// Current evaluated tier on the action's trust ledger.
        observed_tier: TrustEvidenceTier,
        /// Minimum tier demanded by the caller/lane.
        required_tier: TrustEvidenceTier,
    },
    /// The action is useful for lower-tier (e.g. local developer/agent) use,
    /// but requires additional verification or CI policy approval before
    /// serving a higher-tier (e.g. release) lane.
    NeedsAdditionalVerification {
        /// Current evaluated tier on the action's trust ledger.
        observed_tier: TrustEvidenceTier,
        /// Minimum tier demanded by the caller/lane.
        required_tier: TrustEvidenceTier,
    },
}

#[derive(Default)]
struct PrewarmCoordinatorState {
    warm_commits: BTreeMap<String, BTreeSet<String>>,
    receipts: Vec<GitPrewarmReceipt>,
}

#[derive(Default)]
struct SpeculationGateState {
    posture: SpeculationDefaultOnPosture,
    baseline_foreground_latencies_ms: Vec<u64>,
    with_speculation_foreground_latencies_ms: Vec<u64>,
    pressure_regressions: u64,
    last_decision: Option<SpeculationDefaultOnDecisionRecord>,
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
    speculation_provenance: Mutex<SpeculationProvenance>,
    speculation_runs: Mutex<Vec<SpeculationRunRecord>>,
    speculation_gate: Mutex<SpeculationGateState>,
    prewarm_state: Mutex<PrewarmCoordinatorState>,
    cargo_root_broker: Mutex<CargoRootBrokerState>,
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
    /// Lease durations use this incarnation's monotonic clock, never the
    /// publication sequence or an unsynchronized peer/wall-clock timestamp.
    /// Acquiring fresh authority fences every deadline from a previous boot.
    lease_clock: OnceLock<Instant>,
    /// Generations closed by this incarnation's authority acquisition
    /// (G020/R120): every still-active generation minted under a PRIOR
    /// authority, tombstoned at boot so no prior-authority attempt can
    /// ever publish.
    closed_prior_generations: AtomicU64,
    /// T011: identity of the binary this coordinator is running, matched
    /// EXACTLY against the build a release verdict names. Empty until an
    /// operator sets it, which under
    /// [`ReleaseAuthorizationMode::Required`] means no verdict can match
    /// and nothing serves — fail-closed, and the right direction for a
    /// deployment that asked for enforcement without saying what it is
    /// running.
    build_identity: String,
    /// T011: what this deployment does about an unproven build. Advisory
    /// by default, so wiring the gate in cannot by itself stop a healthy
    /// deployment from serving.
    release_mode: ReleaseAuthorizationMode,
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
    /// Mint an edge capability without transferring coordinator ownership.
    #[must_use]
    pub fn edge_subscriber(self: &Arc<Self>) -> EdgeSubscriber {
        EdgeSubscriber {
            coord: Arc::clone(self),
        }
    }

    /// New, with no store (unavailable until the coord region marks
    /// itself up). Commits refuse with [`CommitRefusal::NoStore`].
    #[must_use]
    pub fn new() -> Self {
        Self {
            boot_nonce: boot_micros(),
            next_seq: AtomicU64::new(boot_micros()),
            lease_clock: OnceLock::from(Instant::now()),
            build_identity: rabs_protocol::release_authorization::default_build_identity(),
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

    /// T011: declare which build this coordinator is, and what it does
    /// when that build is not release-authorized.
    ///
    /// The two are set together on purpose. A mode without a build
    /// identity cannot match any verdict, and a build identity without
    /// a mode does nothing — offering them separately would make the
    /// half-configured state the easy one to reach.
    ///
    /// `build` must be the same identity the corpus gate recorded via
    /// `PromotionAuthorized::into_verdict`; the comparison is exact.
    #[must_use]
    pub fn with_release_authorization(
        self,
        build: impl Into<String>,
        release_mode: ReleaseAuthorizationMode,
    ) -> Self {
        Self {
            build_identity: build.into(),
            release_mode,
            ..self
        }
    }

    /// T011 (`bd-dockb`): set the release-authorization mode while keeping
    /// the coordinator's derived [`default_build_identity`].
    ///
    /// [`default_build_identity`]: rabs_protocol::release_authorization::default_build_identity
    #[must_use]
    pub fn with_release_mode(self, release_mode: ReleaseAuthorizationMode) -> Self {
        Self {
            release_mode,
            ..self
        }
    }

    /// The running build identity consulted against durable release verdicts.
    #[must_use]
    pub fn build_identity(&self) -> &str {
        &self.build_identity
    }

    /// T011: this coordinator's standing with the stock differential
    /// corpus gate, read from the durable verdict.
    ///
    /// Reported regardless of mode — an advisory deployment learns what
    /// enforcement would do to it BEFORE it turns enforcement on, which
    /// is the point of shipping the mechanism ahead of the switch.
    ///
    /// # Errors
    /// [`ServeError::NoStore`] with no mounted store,
    /// [`ServeError::StoreUnavailable`] if the store lock is poisoned,
    /// or [`ServeError::Store`] on a backend failure. A store that
    /// cannot be read does not silently become an authorization.
    pub fn release_authorization(
        &self,
        now_unix_micros: i64,
        now_epoch: u64,
    ) -> Result<ReleaseAuthorization, ServeError> {
        let cas = self.cas.as_ref().ok_or(ServeError::NoStore)?;
        let mut store = cas
            .store()
            .lock()
            .map_err(|_| ServeError::StoreUnavailable)?;
        let verdict = store
            .release_verdict(&self.build_identity)
            .map_err(|error| ServeError::Store(format!("{error:?}")))?;
        Ok(release_standing(
            verdict.as_ref(),
            &self.build_identity,
            now_unix_micros,
            now_epoch,
        ))
    }

    /// The configured release-authorization mode.
    #[must_use]
    pub const fn release_mode(&self) -> ReleaseAuthorizationMode {
        self.release_mode
    }

    /// The release standing as a status token, without ever blocking.
    ///
    /// Status must not be able to hang behind a long serve, so this
    /// takes the store lock with `try_lock` and reports `"unknown"`
    /// when it is busy, unmounted, poisoned, or unreadable. Every one
    /// of those is reported as not-knowing rather than as a pass: a
    /// status line that read "authorized" because the store was busy
    /// would be the exact inversion of what this gate is for.
    fn release_standing_for_status(&self) -> &'static str {
        let now = i64::try_from(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |d| d.as_micros()),
        )
        .unwrap_or(i64::MAX);
        let Some(cas) = self.cas.as_ref() else {
            return "unknown";
        };
        let Ok(mut store) = cas.store().try_lock() else {
            return "unknown";
        };
        match store.release_verdict(&self.build_identity) {
            Ok(verdict) => release_standing(
                verdict.as_ref(),
                &self.build_identity,
                now,
                // The serving record's clock epoch column defaults to 0
                // until the coordinator populates a real one, and a
                // verdict is written against that same convention.
                0,
            )
            .token(),
            Err(_) => "unknown",
        }
    }

    /// Set optional-work admission and execution pressure (bead Q006; I012).
    ///
    /// - `PressureBand::Soft`: stops admitting new speculative/optional work;
    ///   already-running speculative work finishes.
    /// - `PressureBand::Hard`: stops admitting new speculative/optional work
    ///   AND cancels/drains running low-value speculative work (tombstoning its
    ///   durable generation in the store), while foreground-promoted work and
    ///   cleanup/object-integrity work remain unaffected.
    pub fn set_speculation_pressure(
        &self,
        pressure: PressureBand,
    ) -> Result<(), SubmissionRefusal> {
        let mut submissions = self
            .submissions
            .lock()
            .map_err(|_| SubmissionRefusal::Unavailable)?;
        let mut cancelled_runs: Vec<SpeculationRunRecord> = Vec::new();
        if decide(WorkCategory::RunningLowValueSpeculation, pressure)
            == BrownoutDecision::CancelAndDrain
        {
            let mut to_tombstone: Vec<u128> = Vec::new();
            for entry in submissions.entries.values_mut() {
                if !matches!(entry.state, DispatchState::Started(_)) {
                    continue;
                }
                if let Some(generation_id) = entry
                    .actor
                    .cancel_low_value_speculation_under_pressure(pressure)
                {
                    to_tombstone.push(generation_id.0);
                    let elapsed_ms = entry.started_at.take().map_or(1, |started| {
                        u64::try_from(started.elapsed().as_millis())
                            .unwrap_or(u64::MAX)
                            .max(1)
                    });
                    let bytes = entry.input.source_bytes();
                    entry.state = DispatchState::Queued;
                    cancelled_runs.push(SpeculationRunRecord {
                        outcome: SpeculationRunOutcome::CancelledUnderPressure,
                        saved_foreground_latency_ms: 0,
                        execution_cost_ms: elapsed_ms,
                        transfer_cost_bytes: bytes,
                        storage_cost_bytes: bytes,
                    });
                }
            }
            if !to_tombstone.is_empty()
                && let Some(cas) = self.cas.as_ref()
            {
                let mut store = cas
                    .store()
                    .lock()
                    .map_err(|_| SubmissionRefusal::Unavailable)?;
                for generation_id in to_tombstone {
                    store.tombstone_generation(generation_id).map_err(|error| {
                        SubmissionRefusal::Admission(format!(
                            "pressure generation cleanup: {error:?}"
                        ))
                    })?;
                }
            }
        }
        *self
            .speculation_pressure
            .lock()
            .map_err(|_| SubmissionRefusal::Unavailable)? = Some(pressure);
        if !cancelled_runs.is_empty() {
            let mut provenance = self
                .speculation_provenance
                .lock()
                .map_err(|_| SubmissionRefusal::Unavailable)?;
            for _ in 0..cancelled_runs.len() {
                provenance.record(BrownoutDecision::CancelAndDrain, true);
            }
            drop(provenance);
            self.speculation_runs
                .lock()
                .map_err(|_| SubmissionRefusal::Unavailable)?
                .extend(cancelled_runs);
        }
        Ok(())
    }

    /// Classify raw pressure permille against soft/hard thresholds and apply
    /// the resulting [`PressureBand`] (bead Q006; I012).
    pub fn apply_speculation_pressure_permille(
        &self,
        pressure_permille: u16,
        soft_threshold: u16,
        hard_threshold: u16,
    ) -> Result<PressureBand, SubmissionRefusal> {
        let classified = band(pressure_permille, soft_threshold, hard_threshold);
        self.set_speculation_pressure(classified)?;
        Ok(classified)
    }

    /// Current speculation pressure band (`PressureBand::Normal` by default).
    pub fn speculation_pressure(&self) -> Result<PressureBand, SubmissionRefusal> {
        Ok(self
            .speculation_pressure
            .lock()
            .map_err(|_| SubmissionRefusal::Unavailable)?
            .unwrap_or(PressureBand::Normal))
    }

    /// Whether a work category is admitted under current pressure (cleanup and
    /// object-integrity work remain required at every band; bead Q006 / I012).
    pub fn work_category_admitted(
        &self,
        category: WorkCategory,
    ) -> Result<bool, SubmissionRefusal> {
        let pressure = self.speculation_pressure()?;
        Ok(decide(category, pressure) == BrownoutDecision::Admit)
    }

    /// Snapshot of speculation brownout provenance accounting (bead Q006 / I012).
    pub fn speculation_provenance(&self) -> Result<SpeculationProvenance, SubmissionRefusal> {
        Ok(*self
            .speculation_provenance
            .lock()
            .map_err(|_| SubmissionRefusal::Unavailable)?)
    }

    /// Snapshot of recorded speculation run provenance records (bead Q009).
    pub fn speculation_runs(&self) -> Result<Vec<SpeculationRunRecord>, SubmissionRefusal> {
        Ok(self
            .speculation_runs
            .lock()
            .map_err(|_| SubmissionRefusal::Unavailable)?
            .clone())
    }

    /// Build the [`SpeculationRoiPanel`] from live speculation provenance runs (bead Q009).
    pub fn speculation_roi_panel(&self) -> Result<SpeculationRoiPanel, SubmissionRefusal> {
        let runs = self
            .speculation_runs
            .lock()
            .map_err(|_| SubmissionRefusal::Unavailable)?;
        Ok(build_speculation_roi(&runs))
    }

    /// Current default-on speculation posture (bead Q010; defaults to [`SpeculationDefaultOnPosture::DefaultOff`]).
    pub fn speculation_default_on_posture(
        &self,
    ) -> Result<SpeculationDefaultOnPosture, SubmissionRefusal> {
        Ok(self
            .speculation_gate
            .lock()
            .map_err(|_| SubmissionRefusal::Unavailable)?
            .posture)
    }

    /// Record a foreground command latency sample with or without speculation active (bead Q010).
    pub fn record_foreground_latency_sample(
        &self,
        with_speculation: bool,
        latency_ms: u64,
    ) -> Result<(), SubmissionRefusal> {
        let mut gate = self
            .speculation_gate
            .lock()
            .map_err(|_| SubmissionRefusal::Unavailable)?;
        if with_speculation {
            gate.with_speculation_foreground_latencies_ms
                .push(latency_ms);
        } else {
            gate.baseline_foreground_latencies_ms.push(latency_ms);
        }
        Ok(())
    }

    /// Record a pressure regression attributed to speculation and immediately demote
    /// default-on posture back to [`SpeculationDefaultOnPosture::DefaultOff`] (bead Q010).
    pub fn record_speculation_pressure_regression(&self) -> Result<(), SubmissionRefusal> {
        let mut gate = self
            .speculation_gate
            .lock()
            .map_err(|_| SubmissionRefusal::Unavailable)?;
        gate.pressure_regressions = gate.pressure_regressions.saturating_add(1);
        gate.posture = SpeculationDefaultOnPosture::DefaultOff;
        Ok(())
    }

    /// Evaluate the Q010 default-on speculation gate against the live ROI dashboard,
    /// foreground p95 latency samples, and pressure regressions, updating the coordinator's
    /// default-on posture and writing a durable decision receipt when a CAS store is mounted.
    pub fn evaluate_speculation_default_on_gate(
        &self,
    ) -> Result<SpeculationDefaultOnDecisionRecord, SubmissionRefusal> {
        let roi = self.speculation_roi_panel()?;
        let decision = {
            let mut gate = self
                .speculation_gate
                .lock()
                .map_err(|_| SubmissionRefusal::Unavailable)?;
            let input = SpeculationDefaultOnGateInput {
                roi,
                baseline_foreground_latencies_ms: gate.baseline_foreground_latencies_ms.clone(),
                with_speculation_foreground_latencies_ms: gate
                    .with_speculation_foreground_latencies_ms
                    .clone(),
                pressure_regressions: gate.pressure_regressions,
            };
            let record = evaluate_speculation_default_on_gate(&input);
            gate.posture = record.posture;
            gate.last_decision = Some(record.clone());
            record
        };
        if let Some(cas) = self.cas.as_ref() {
            let seq = self.next_seq.fetch_add(1, Ordering::Relaxed);
            let mut store = cas
                .store()
                .lock()
                .map_err(|_| SubmissionRefusal::Unavailable)?;
            store
                .record_decision_receipt(
                    SPECULATION_DEFAULT_ON_RECEIPT_KIND,
                    &self.build_identity,
                    seq,
                    decision.decision_token(),
                    &decision.reason_summary(),
                )
                .map_err(|error| {
                    SubmissionRefusal::Admission(format!(
                        "speculation gate decision receipt failed: {error:?}"
                    ))
                })?;
        }
        Ok(decision)
    }

    /// Latest evaluated [`SpeculationDefaultOnDecisionRecord`], if any (bead Q010).
    pub fn latest_speculation_default_on_decision(
        &self,
    ) -> Result<Option<SpeculationDefaultOnDecisionRecord>, SubmissionRefusal> {
        Ok(self
            .speculation_gate
            .lock()
            .map_err(|_| SubmissionRefusal::Unavailable)?
            .last_decision
            .clone())
    }

    /// Submit a default-on speculative action gated on [`SpeculationDefaultOnPosture::DefaultOn`] (bead Q010).
    ///
    /// Ships default-off: until [`Self::evaluate_speculation_default_on_gate`] proves positive
    /// net saved foreground latency and improved foreground p95 without pressure regressions,
    /// automatic default-on speculation is refused with [`SubmissionRefusal::Admission`].
    pub fn submit_default_on_speculation(
        &self,
        input: ActionSubmission,
        request: JoinRequest,
        now_unix_micros: i64,
        clock_epoch: u64,
    ) -> Result<SubmissionReceipt, SubmissionRefusal> {
        if !matches!(
            request.kind,
            SubscriberKind::Speculative | SubscriberKind::GitPrewarm
        ) {
            return Err(SubmissionRefusal::Admission(
                "submit_default_on_speculation requires optional SubscriberKind".to_owned(),
            ));
        }
        if !self.speculation_default_on_posture()?.permits_default_on() {
            return Err(SubmissionRefusal::Admission(
                "default-on speculation gated off: requires positive p95 ROI and improved foreground p95 without pressure regressions".to_owned(),
            ));
        }
        self.submit_action(input, request, now_unix_micros, clock_epoch)
    }

    fn has_queued_foreground_pressure(&self) -> Result<bool, SubmissionRefusal> {
        let submissions = self
            .submissions
            .lock()
            .map_err(|_| SubmissionRefusal::Unavailable)?;
        Ok(submissions.entries.values().any(|entry| {
            entry.state == DispatchState::Queued && entry.actor.has_foreground_interest()
        }))
    }

    fn is_action_already_warm_in_store(
        &self,
        action_key: &TypedDigest,
        now_unix_micros: i64,
        clock_epoch: u64,
    ) -> Result<bool, SubmissionRefusal> {
        let Some(cas) = self.cas.as_ref() else {
            return Ok(false);
        };
        let key_str = digest_key(action_key);
        let mut store = cas
            .store()
            .lock()
            .map_err(|_| SubmissionRefusal::Unavailable)?;
        declare_coordinator_domains(&mut *store);
        Ok(matches!(
            serving_gate(&mut *store, &key_str, now_unix_micros, clock_epoch),
            Ok(ServeDecision::Servable)
        ))
    }

    /// Handle a Q007 git checkout / HEAD / worktree / lockfile / toolchain / CI push
    /// prewarm event:
    ///
    /// 1. Locate the nearest warm ancestor state from `event.parent_commit_oids`.
    /// 2. Prewarm the dependency critical path, workspace critical path, and optional
    ///    canonical test subset in priority order (`190`, `180`, `170`).
    /// 3. Stop instantly if foreground pressure (`Soft`/`Hard` band or queued foreground
    ///    work) is active before or during submission.
    /// 4. Seed admitted, non-ambiguous `likely_workers`.
    /// 5. Emit a structured [`GitPrewarmReceipt`] and append a durable row to
    ///    `decision_receipts` (`GIT_PREWARM_RECEIPT_KIND`).
    pub fn handle_git_prewarm_event(
        &self,
        event: GitPrewarmEvent,
    ) -> Result<GitPrewarmReceipt, SubmissionRefusal> {
        if !self.available() || self.cas.is_none() {
            return Err(SubmissionRefusal::Unavailable);
        }
        let (nearest_ancestor_commit_oid, mut head_warm_keys) = {
            let prewarm = self
                .prewarm_state
                .lock()
                .map_err(|_| SubmissionRefusal::Unavailable)?;
            let found = event.parent_commit_oids.iter().find_map(|parent| {
                prewarm
                    .warm_commits
                    .get(parent)
                    .map(|keys| (parent.clone(), keys.clone()))
            });
            match found {
                Some((ancestor, keys)) => (Some(ancestor), keys),
                None => (None, BTreeSet::new()),
            }
        };

        let mut op_cursor = event.operation_base_id;
        let mut stopped_under_foreground_pressure = false;
        let presentation = rabs_key::typed_digest::compute("rabs.presentation.v1", b"git-prewarm");

        let mut process_stage = |submissions: Vec<ActionSubmission>,
                                 priority: u8|
         -> Result<Vec<PrewarmStageOutcome>, SubmissionRefusal> {
            let mut outcomes = Vec::with_capacity(submissions.len());
            for submission in submissions {
                let action_key = submission.key();
                let key_str = digest_key(&action_key);
                if stopped_under_foreground_pressure
                    || !self.optional_admitted()?
                    || self.has_queued_foreground_pressure()?
                {
                    stopped_under_foreground_pressure = true;
                    outcomes
                        .push(PrewarmStageOutcome::StoppedUnderForegroundPressure { action_key });
                    continue;
                }
                if head_warm_keys.contains(&key_str)
                    || self.is_action_already_warm_in_store(
                        &action_key,
                        event.now_unix_micros,
                        event.clock_epoch,
                    )?
                {
                    head_warm_keys.insert(key_str);
                    outcomes.push(PrewarmStageOutcome::AlreadyWarm { action_key });
                    continue;
                }
                let op_id = op_cursor;
                op_cursor = op_cursor.saturating_add(1);
                let request = JoinRequest {
                    operation: BuildOperationId(op_id),
                    kind: SubscriberKind::GitPrewarm,
                    queue_priority: priority,
                    deadline_unix_micros: None,
                    presentation: presentation.clone(),
                    requirements: SubscriptionRequirements::unrestricted(),
                };
                match self.submit_action(
                    submission,
                    request,
                    event.now_unix_micros,
                    event.clock_epoch,
                ) {
                    Ok(receipt) => {
                        head_warm_keys.insert(key_str);
                        outcomes.push(PrewarmStageOutcome::QueuedPrewarm {
                            action_key: receipt.action_key,
                            actor_created: receipt.actor_created,
                        });
                    }
                    Err(SubmissionRefusal::Brownout) => {
                        stopped_under_foreground_pressure = true;
                        outcomes.push(PrewarmStageOutcome::StoppedUnderForegroundPressure {
                            action_key,
                        });
                    }
                    Err(other) => return Err(other),
                }
            }
            Ok(outcomes)
        };

        let dependency_actions = process_stage(event.dependency_critical_path, 190)?;
        let workspace_actions = process_stage(event.workspace_critical_path, 180)?;
        let canonical_test_actions = process_stage(event.canonical_test_subset, 170)?;

        let cas = self.cas.as_ref().ok_or(SubmissionRefusal::Unavailable)?;
        let receipt_seq = self.next_seq();
        let mut seeded_workers = Vec::new();
        {
            let mut store = cas
                .store()
                .lock()
                .map_err(|_| SubmissionRefusal::Unavailable)?;
            for worker in &event.likely_workers {
                let admitted = store
                    .worker_incarnation_fence(worker)
                    .map_err(|error| {
                        SubmissionRefusal::Admission(format!("worker fence lookup: {error:?}"))
                    })?
                    .is_some_and(|fence| !fence.clone_ambiguous);
                if admitted && !seeded_workers.contains(worker) {
                    seeded_workers.push(worker.clone());
                }
            }
            let decision_token = if stopped_under_foreground_pressure {
                "stopped-foreground-pressure"
            } else {
                "prewarm-dispatched"
            };
            let summary = format!(
                "kind={};head={};ancestor={};worktree={};lockfile={};toolchain={};dep={};ws={};tests={};workers={}",
                event.kind.as_str(),
                event.head_commit_oid,
                nearest_ancestor_commit_oid.as_deref().unwrap_or("none"),
                event.worktree_id,
                digest_key(&event.lockfile_digest),
                digest_key(&event.toolchain_digest),
                dependency_actions.len(),
                workspace_actions.len(),
                canonical_test_actions.len(),
                seeded_workers.len(),
            );
            store
                .record_decision_receipt(
                    GIT_PREWARM_RECEIPT_KIND,
                    &event.event_id,
                    receipt_seq,
                    decision_token,
                    &summary,
                )
                .map_err(|error| {
                    SubmissionRefusal::Admission(format!("git prewarm receipt: {error:?}"))
                })?;
        }

        let receipt = GitPrewarmReceipt {
            event_id: event.event_id,
            kind: event.kind,
            head_commit_oid: event.head_commit_oid.clone(),
            nearest_ancestor_commit_oid,
            dependency_actions,
            workspace_actions,
            canonical_test_actions,
            seeded_workers,
            stopped_under_foreground_pressure,
            receipt_seq,
        };
        {
            let mut prewarm = self
                .prewarm_state
                .lock()
                .map_err(|_| SubmissionRefusal::Unavailable)?;
            prewarm
                .warm_commits
                .insert(event.head_commit_oid, head_warm_keys);
            prewarm.receipts.push(receipt.clone());
        }
        Ok(receipt)
    }

    /// Snapshot of recorded Q007 git/worktree prewarm receipts.
    pub fn prewarm_receipts(&self) -> Result<Vec<GitPrewarmReceipt>, SubmissionRefusal> {
        Ok(self
            .prewarm_state
            .lock()
            .map_err(|_| SubmissionRefusal::Unavailable)?
            .receipts
            .clone())
    }

    /// Promote a committed canonical profile build from a CI writer lane to
    /// [`TrustEvidenceTier::CiPolicyApproved`] via the S011 policy evaluator and
    /// register its commit/action in the prewarm ledger so developer pulls receive
    /// guaranteed-warm artifacts (bead Q008; depends on Q007 + S011).
    ///
    /// Trust tier is publication/access policy, NEVER content identity: the
    /// `action_key` is unchanged from a local-agent build of the same descriptor.
    #[allow(clippy::too_many_arguments)]
    pub fn publish_ci_canonical_prewarm<P, F>(
        &self,
        commit_oid: &str,
        profile_name: &str,
        expected_policy_id: &TypedDigest,
        policy_history: &[CiCanonicalWriterPolicy],
        claim: &CiCanonicalWriterClaim,
        independently_observed_verification: rabs_protocol::provenance_receipt::VerificationLevel,
        verify_policy_content: P,
        verify_signature: F,
    ) -> Result<CiCanonicalPrewarmReceipt, SubmissionRefusal>
    where
        P: FnOnce(&TypedDigest, &[u8]) -> bool,
        F: FnOnce(
            rabs_protocol::serving::CiSignatureAlgorithm,
            &TypedDigest,
            u64,
            &[u8],
            &[u8],
        ) -> bool,
    {
        if !self.available() || self.cas.is_none() {
            return Err(SubmissionRefusal::Unavailable);
        }
        let held = self.authority().ok_or(SubmissionRefusal::Unavailable)?;
        let held_digest = authority_digest(&held);
        let cas = self.cas.as_ref().ok_or(SubmissionRefusal::Unavailable)?;

        let active_policy = policy_history
            .iter()
            .filter(|p| &p.policy_id == expected_policy_id)
            .max_by_key(|p| p.version)
            .ok_or_else(|| {
                SubmissionRefusal::Admission(format!(
                    "ci policy refusal: {:?}",
                    CiPolicyRefusal::NoCurrentPolicy
                ))
            })?;

        let (approval, ledger_version, receipt_seq) = {
            let mut store = cas
                .store()
                .lock()
                .map_err(|_| SubmissionRefusal::Unavailable)?;
            declare_coordinator_domains(&mut *store);
            match store.active_authority().map_err(|error| {
                SubmissionRefusal::Admission(format!("active authority: {error:?}"))
            })? {
                Some(active) if active.digest == held_digest => {}
                _ => return Err(SubmissionRefusal::Unavailable),
            }
            let action_key_str = digest_key(&claim.action_key);
            let quarantined = !store
                .query(
                    "SELECT 1 FROM quarantines WHERE scope = 'action-entry' AND subject = ?1 LIMIT 1",
                    &[SqlValue::Text(action_key_str.clone())],
                )
                .map_err(|error| {
                    SubmissionRefusal::Admission(format!("quarantine check: {error:?}"))
                })?
                .is_empty();
            if quarantined {
                return Err(SubmissionRefusal::Admission(
                    "cannot promote quarantined action to CiPolicyApproved".to_owned(),
                ));
            }
            let manifest_key = store
                .published_manifest_key(&claim.action_key)
                .map_err(|error| {
                    SubmissionRefusal::Admission(format!("published manifest lookup: {error:?}"))
                })?
                .ok_or_else(|| {
                    SubmissionRefusal::Admission(
                        "action has no committed publication to approve".to_owned(),
                    )
                })?;
            let manifest_digest = object_id_from_key(&manifest_key).ok_or_else(|| {
                SubmissionRefusal::Admission("invalid published manifest key".to_owned())
            })?;
            let evidence_keys = store
                .list_evidence_keys(&claim.action_key)
                .map_err(|error| {
                    SubmissionRefusal::Admission(format!("evidence keys lookup: {error:?}"))
                })?;
            let expected_evidence_set_digest = evidence_set_digest(&evidence_keys);
            let latest_eval =
                store
                    .latest_trust_evaluation(&claim.action_key)
                    .map_err(|error| {
                        SubmissionRefusal::Admission(format!("trust ledger lookup: {error:?}"))
                    })?;
            let trust_ledger_high_water = latest_eval.as_ref().map_or(0, |row| row.evaluated_seq);
            let publication_causal_sequence = trust_ledger_high_water.max(1);
            let ledger_version = latest_eval
                .as_ref()
                .map_or(Some(1), |row| row.version.checked_add(1))
                .ok_or(SubmissionRefusal::IdentityExhausted)?;

            let context = CiEvaluationContext {
                expected_policy_id: expected_policy_id.clone(),
                expected_policy_version: active_policy.version,
                expected_policy_content_digest: active_policy.policy_content_digest.clone(),
                expected_action_key: claim.action_key.clone(),
                expected_canonical_result_manifest_id: ObjectId(manifest_digest),
                expected_evidence_set_digest,
                independently_observed_verification,
                coordinator_causal_sequence: claim.evaluated_causal_sequence,
                publication_causal_sequence,
                trust_ledger_high_water,
            };
            let approval = evaluate_ci_canonical_writer_claim(
                policy_history,
                claim,
                &context,
                verify_policy_content,
                verify_signature,
            )
            .map_err(|refusal| {
                SubmissionRefusal::Admission(format!("ci policy refusal: {refusal:?}"))
            })?;

            store
                .append_trust_evaluation(
                    &held_digest,
                    &claim.action_key,
                    &TrustEvaluationRow {
                        version: ledger_version,
                        state: "ci-policy-approved".to_owned(),
                        reason: format!(
                            "ci-lane={};policy-v={};commit={};profile={}",
                            approval.lane_id(),
                            approval.policy_version(),
                            commit_oid,
                            profile_name,
                        ),
                        evaluated_seq: claim.evaluated_causal_sequence,
                    },
                )
                .map_err(|error| {
                    SubmissionRefusal::Admission(format!("append trust evaluation: {error:?}"))
                })?;
            store
                .set_serving_disposition_key(&action_key_str, DISPOSITION_SERVABLE)
                .map_err(|error| {
                    SubmissionRefusal::Admission(format!("set serving disposition: {error:?}"))
                })?;
            let receipt_seq = self.next_seq();
            store
                .record_decision_receipt(
                    CI_CANONICAL_PREWARM_RECEIPT_KIND,
                    &format!("{commit_oid}:{profile_name}"),
                    receipt_seq,
                    "ci-policy-approved",
                    &action_key_str,
                )
                .map_err(|error| {
                    SubmissionRefusal::Admission(format!("ci prewarm decision receipt: {error:?}"))
                })?;
            (approval, ledger_version, receipt_seq)
        };

        {
            let mut prewarm = self
                .prewarm_state
                .lock()
                .map_err(|_| SubmissionRefusal::Unavailable)?;
            prewarm
                .warm_commits
                .entry(commit_oid.to_owned())
                .or_default()
                .insert(digest_key(&claim.action_key));
        }

        Ok(CiCanonicalPrewarmReceipt {
            commit_oid: commit_oid.to_owned(),
            profile_name: profile_name.to_owned(),
            action_key: claim.action_key.clone(),
            assigned_tier: approval.evaluation().evaluated_tier(),
            approval,
            trust_ledger_version: ledger_version,
            receipt_seq,
        })
    }

    /// Evaluate whether a committed action satisfies `required_tier` under
    /// publication/access policy (bead Q008).
    ///
    /// Local agent results (e.g. `UnverifiedCandidate` or `ShadowMatched`)
    /// remain immediately useful for developer/agent tiers, while release or
    /// CI-gated lanes require `TrustEvidenceTier::CiPolicyApproved` or higher
    /// verification without changing the content-addressed `action_key`.
    pub fn evaluate_trust_tier_access(
        &self,
        action_key: &TypedDigest,
        required_tier: TrustEvidenceTier,
    ) -> Result<TrustAccessDecision, SubmissionRefusal> {
        let cas = self.cas.as_ref().ok_or(SubmissionRefusal::Unavailable)?;
        let mut store = cas
            .store()
            .lock()
            .map_err(|_| SubmissionRefusal::Unavailable)?;
        declare_coordinator_domains(&mut *store);
        if !store.has_publication(action_key).map_err(|error| {
            SubmissionRefusal::Admission(format!("publication check: {error:?}"))
        })? {
            return Err(SubmissionRefusal::Admission(
                "action has no committed publication".to_owned(),
            ));
        }
        let latest = store
            .latest_trust_evaluation(action_key)
            .map_err(|error| SubmissionRefusal::Admission(format!("trust lookup: {error:?}")))?;
        let observed_tier = match latest.as_ref().map(|row| row.state.as_str()) {
            Some("project-release-eligible") => TrustEvidenceTier::ProjectReleaseEligible,
            Some("ci-policy-approved") => TrustEvidenceTier::CiPolicyApproved,
            Some("reproducible-cross-worker") => TrustEvidenceTier::ReproducibleCrossWorker,
            Some("reproducible-same-worker") => TrustEvidenceTier::ReproducibleSameWorker,
            Some("shadow-matched") => TrustEvidenceTier::ShadowMatched,
            _ => TrustEvidenceTier::UnverifiedCandidate,
        };
        if observed_tier >= required_tier {
            Ok(TrustAccessDecision::Permitted {
                observed_tier,
                required_tier,
            })
        } else {
            Ok(TrustAccessDecision::NeedsAdditionalVerification {
                observed_tier,
                required_tier,
            })
        }
    }

    /// Configure the live Cargo root-permit broker and weighted fair queue (`bd-d4uqa` / `T016`).
    pub fn configure_cargo_root_broker(
        &self,
        max_concurrent_cargo_roots: u32,
        per_root_capacity: u32,
        starvation_bound: u64,
        deadline_window: u64,
    ) -> Result<(), SubmissionRefusal> {
        if max_concurrent_cargo_roots == 0 || per_root_capacity == 0 {
            return Err(SubmissionRefusal::Admission(
                "cargo root broker capacities must be non-zero".to_owned(),
            ));
        }
        let mut broker = self
            .cargo_root_broker
            .lock()
            .map_err(|_| SubmissionRefusal::Unavailable)?;
        broker.max_concurrent_cargo_roots = max_concurrent_cargo_roots;
        broker.per_root_capacity = per_root_capacity;
        broker.queue = FairQueue::new(starvation_bound, deadline_window);
        broker.queued_count = 0;
        broker.active_grants.clear();
        broker.peak_active_cargo_roots = 0;
        broker.total_enqueued = 0;
        broker.total_granted = 0;
        broker.total_completed = 0;
        broker.total_root_cap_refusals = 0;
        broker.worst_lag_by_agent.clear();
        broker.starvation_violations = 0;
        broker.granted_order.clear();
        Ok(())
    }

    /// Set a tenant's scheduling weight in the live Cargo root-permit broker (`bd-d4uqa`).
    pub fn set_cargo_root_tenant_weight(
        &self,
        tenant: TenantKey,
        weight: u64,
    ) -> Result<(), SubmissionRefusal> {
        let mut broker = self
            .cargo_root_broker
            .lock()
            .map_err(|_| SubmissionRefusal::Unavailable)?;
        broker.queue.set_weight(tenant, weight);
        Ok(())
    }

    /// Enqueue a Cargo root request into the live coordinator's weighted fair queue (`bd-d4uqa`).
    pub fn enqueue_cargo_root_request(
        &self,
        tenant: TenantKey,
        root_id: &str,
        cost: u64,
        now_tick: u64,
        deadline: Option<u64>,
    ) -> Result<CargoRootEnqueueReceipt, SubmissionRefusal> {
        if !self.available() || self.cas.is_none() || self.authority().is_none() {
            return Err(SubmissionRefusal::Unavailable);
        }
        if root_id.is_empty() {
            return Err(SubmissionRefusal::Admission(
                "root_id must not be empty".to_owned(),
            ));
        }
        let mut broker = self
            .cargo_root_broker
            .lock()
            .map_err(|_| SubmissionRefusal::Unavailable)?;
        broker
            .queue
            .enqueue(tenant.clone(), root_id, cost, now_tick, deadline);
        broker.queued_count = broker.queued_count.saturating_add(1);
        broker.total_enqueued = broker.total_enqueued.saturating_add(1);
        drop(broker);

        let receipt_seq = self.next_seq.fetch_add(1, Ordering::Relaxed);
        if let Some(cas) = self.cas.as_ref() {
            let mut store = cas
                .store()
                .lock()
                .map_err(|_| SubmissionRefusal::Unavailable)?;
            store
                .record_decision_receipt(
                    CARGO_ROOT_BROKER_RECEIPT_KIND,
                    root_id,
                    receipt_seq,
                    "enqueued",
                    &format!(
                        "agent={} project={} ci={} cost={} tick={}",
                        tenant.agent, tenant.project, tenant.ci, cost, now_tick
                    ),
                )
                .map_err(|error| {
                    SubmissionRefusal::Admission(format!("broker enqueue receipt: {error:?}"))
                })?;
        }
        Ok(CargoRootEnqueueReceipt {
            tenant,
            root_id: root_id.to_owned(),
            enqueued_at: now_tick,
            receipt_seq,
        })
    }

    /// Admit the next Cargo root from the weighted fair queue if active root capacity permits (`bd-d4uqa` / `T016`).
    ///
    /// Enforces `active_cargo_roots <= max_concurrent_cargo_roots`: when at capacity, records a
    /// durable `"root_cap_reached"` receipt and returns `Ok(None)` without opening a grant.
    pub fn admit_next_cargo_root(
        &self,
        now_tick: u64,
    ) -> Result<Option<CargoRootGrantReceipt>, SubmissionRefusal> {
        if !self.available() || self.cas.is_none() || self.authority().is_none() {
            return Err(SubmissionRefusal::Unavailable);
        }
        let mut broker = self
            .cargo_root_broker
            .lock()
            .map_err(|_| SubmissionRefusal::Unavailable)?;
        let active_count = u32::try_from(broker.active_grants.len()).unwrap_or(u32::MAX);
        if active_count >= broker.max_concurrent_cargo_roots {
            broker.total_root_cap_refusals = broker.total_root_cap_refusals.saturating_add(1);
            let max_roots = broker.max_concurrent_cargo_roots;
            drop(broker);

            let receipt_seq = self.next_seq.fetch_add(1, Ordering::Relaxed);
            if let Some(cas) = self.cas.as_ref() {
                let mut store = cas
                    .store()
                    .lock()
                    .map_err(|_| SubmissionRefusal::Unavailable)?;
                store
                    .record_decision_receipt(
                        CARGO_ROOT_BROKER_RECEIPT_KIND,
                        "broker_capacity_gate",
                        receipt_seq,
                        "root_cap_reached",
                        &format!(
                            "active_cargo_roots={active_count} max_concurrent_cargo_roots={max_roots} tick={now_tick}"
                        ),
                    )
                    .map_err(|error| {
                        SubmissionRefusal::Admission(format!(
                            "broker cap refusal receipt: {error:?}"
                        ))
                    })?;
            }
            return Ok(None);
        }

        let Some(item) = broker.queue.dequeue(now_tick) else {
            return Ok(None);
        };
        broker.queued_count = broker.queued_count.saturating_sub(1);
        let capacity = broker.per_root_capacity;
        let grant = RootGrant::open(capacity).map_err(|error| {
            SubmissionRefusal::Admission(format!("root grant open failed: {error:?}"))
        })?;
        let root_id = item.label.clone();
        broker.active_grants.insert(root_id.clone(), grant);
        let new_active = u32::try_from(broker.active_grants.len()).unwrap_or(u32::MAX);
        if new_active > broker.peak_active_cargo_roots {
            broker.peak_active_cargo_roots = new_active;
        }
        let wait_ticks = now_tick.saturating_sub(item.enqueued_at);
        if wait_ticks > broker.queue.starvation_bound {
            broker.starvation_violations = broker.starvation_violations.saturating_add(1);
        }
        broker
            .worst_lag_by_agent
            .entry(item.tenant.agent.clone())
            .and_modify(|worst| *worst = (*worst).max(wait_ticks))
            .or_insert(wait_ticks);
        broker.total_granted = broker.total_granted.saturating_add(1);
        broker.granted_order.push(root_id.clone());
        let max_roots = broker.max_concurrent_cargo_roots;
        drop(broker);

        let receipt_seq = self.next_seq.fetch_add(1, Ordering::Relaxed);
        if let Some(cas) = self.cas.as_ref() {
            let mut store = cas
                .store()
                .lock()
                .map_err(|_| SubmissionRefusal::Unavailable)?;
            store
                .record_decision_receipt(
                    CARGO_ROOT_BROKER_RECEIPT_KIND,
                    &root_id,
                    receipt_seq,
                    "root_granted",
                    &format!(
                        "agent={} capacity={} wait_ticks={} active={}/{}",
                        item.tenant.agent, capacity, wait_ticks, new_active, max_roots
                    ),
                )
                .map_err(|error| {
                    SubmissionRefusal::Admission(format!("broker grant receipt: {error:?}"))
                })?;
        }

        Ok(Some(CargoRootGrantReceipt {
            tenant: item.tenant,
            root_id,
            capacity,
            wait_ticks,
            active_cargo_roots: new_active,
            max_concurrent_cargo_roots: max_roots,
            receipt_seq,
        }))
    }

    /// Issue one transferable jobserver token from an active Cargo root's `C - 1` budget (`bd-d4uqa`).
    pub fn issue_cargo_jobserver_token(
        &self,
        root_id: &str,
    ) -> Result<Result<TransferableToken, GrantRefusal>, SubmissionRefusal> {
        let mut broker = self
            .cargo_root_broker
            .lock()
            .map_err(|_| SubmissionRefusal::Unavailable)?;
        let Some(grant) = broker.active_grants.get_mut(root_id) else {
            return Ok(Err(GrantRefusal::GrantClosed));
        };
        Ok(grant.issue_transferable())
    }

    /// Release one transferable jobserver token back to an active Cargo root (`bd-d4uqa`).
    pub fn release_cargo_jobserver_token(
        &self,
        root_id: &str,
        token: &TransferableToken,
    ) -> Result<Result<(), GrantRefusal>, SubmissionRefusal> {
        let mut broker = self
            .cargo_root_broker
            .lock()
            .map_err(|_| SubmissionRefusal::Unavailable)?;
        let Some(grant) = broker.active_grants.get_mut(root_id) else {
            return Ok(Err(GrantRefusal::GrantClosed));
        };
        Ok(grant.release(token))
    }

    /// Complete an active Cargo root, closing its `RootGrant` and freeing one root slot (`bd-d4uqa`).
    pub fn complete_cargo_root(
        &self,
        root_id: &str,
        now_tick: u64,
    ) -> Result<CargoRootCompletionReceipt, SubmissionRefusal> {
        if !self.available() || self.cas.is_none() || self.authority().is_none() {
            return Err(SubmissionRefusal::Unavailable);
        }
        let mut broker = self
            .cargo_root_broker
            .lock()
            .map_err(|_| SubmissionRefusal::Unavailable)?;
        let Some(mut grant) = broker.active_grants.remove(root_id) else {
            return Err(SubmissionRefusal::Admission(format!(
                "unknown or already completed cargo root: {root_id}"
            )));
        };
        grant.close();
        broker.total_completed = broker.total_completed.saturating_add(1);
        let remaining = u32::try_from(broker.active_grants.len()).unwrap_or(u32::MAX);
        drop(broker);

        let receipt_seq = self.next_seq.fetch_add(1, Ordering::Relaxed);
        if let Some(cas) = self.cas.as_ref() {
            let mut store = cas
                .store()
                .lock()
                .map_err(|_| SubmissionRefusal::Unavailable)?;
            store
                .record_decision_receipt(
                    CARGO_ROOT_BROKER_RECEIPT_KIND,
                    root_id,
                    receipt_seq,
                    "root_completed",
                    &format!("remaining_active={remaining} tick={now_tick}"),
                )
                .map_err(|error| {
                    SubmissionRefusal::Admission(format!("broker completion receipt: {error:?}"))
                })?;
        }

        Ok(CargoRootCompletionReceipt {
            root_id: root_id.to_owned(),
            active_cargo_roots: remaining,
            receipt_seq,
        })
    }

    /// Snapshot live telemetry for the Cargo root-permit broker (`bd-d4uqa` / `T016`).
    pub fn cargo_root_broker_telemetry(
        &self,
    ) -> Result<CargoRootBrokerTelemetry, SubmissionRefusal> {
        let broker = self
            .cargo_root_broker
            .lock()
            .map_err(|_| SubmissionRefusal::Unavailable)?;
        Ok(CargoRootBrokerTelemetry {
            max_concurrent_cargo_roots: broker.max_concurrent_cargo_roots,
            per_root_capacity: broker.per_root_capacity,
            active_cargo_roots: u32::try_from(broker.active_grants.len()).unwrap_or(u32::MAX),
            peak_active_cargo_roots: broker.peak_active_cargo_roots,
            queued_requests: broker.queued_count,
            total_enqueued: broker.total_enqueued,
            total_granted: broker.total_granted,
            total_completed: broker.total_completed,
            total_root_cap_refusals: broker.total_root_cap_refusals,
            starvation_bound: broker.queue.starvation_bound,
            worst_lag_by_agent: broker.worst_lag_by_agent.clone(),
            starvation_violations: broker.starvation_violations,
            granted_order: broker.granted_order.clone(),
        })
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

    fn record_brownout_refusal(&self) -> Result<(), SubmissionRefusal> {
        self.speculation_provenance
            .lock()
            .map_err(|_| SubmissionRefusal::Unavailable)?
            .record(BrownoutDecision::StopAdmitting, false);
        self.speculation_runs
            .lock()
            .map_err(|_| SubmissionRefusal::Unavailable)?
            .push(SpeculationRunRecord {
                outcome: SpeculationRunOutcome::AdmissionRefusedBrownout,
                saved_foreground_latency_ms: 0,
                execution_cost_ms: 0,
                transfer_cost_bytes: 0,
                storage_cost_bytes: 0,
            });
        Ok(())
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
            self.record_brownout_refusal()?;
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
            let was_optional_only = !entry.actor.has_foreground_interest();
            let join = entry.actor.join(request, now_unix_micros, clock_epoch);
            if was_optional_only && entry.actor.has_foreground_interest() {
                entry.promoted_from_speculation = true;
            }
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
        {
            let cas = self.cas.as_ref().ok_or(SubmissionRefusal::Unavailable)?;
            let mut store = cas
                .store()
                .lock()
                .map_err(|_| SubmissionRefusal::Unavailable)?;
            match store.active_authority().map_err(|error| {
                SubmissionRefusal::Admission(format!("class authority: {error:?}"))
            })? {
                Some(active) if active.digest == authority_digest(&authority) => {}
                _ => return Err(SubmissionRefusal::Unavailable),
            }
            // Projection and bounded admission checks have succeeded. A
            // rejected queue flood must not grow the durable class ledger.
            // This follows the submissions -> store order used by dispatch.
            // The socket caller never supplies this keyed risk classification.
            record_descriptor_class(&mut *store, &input.descriptor).map_err(|error| {
                SubmissionRefusal::Admission(format!("action class: {error:?}"))
            })?;
        }
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
                started_as_speculative: optional,
                promoted_from_speculation: false,
                started_at: None,
            },
        );
        Ok(SubmissionReceipt {
            action_key: key,
            actor_created: true,
            join,
        })
    }

    /// Detach a subscriber's interest from an in-flight action (bead G005).
    ///
    /// - When other subscribers remain attached, the action and its active
    ///   attempt/generation survive without interruption.
    /// - When the last subscriber detaches, the active generation is drained
    ///   and tombstoned in the durable store so no in-flight worker attempt can
    ///   publish after cancellation.
    pub fn cancel_subscriber(
        &self,
        key: &TypedDigest,
        operation: BuildOperationId,
    ) -> Result<CancelReceipt, SubmissionRefusal> {
        if !self.available() {
            return Err(SubmissionRefusal::Unavailable);
        }
        let mut submissions = self
            .submissions
            .lock()
            .map_err(|_| SubmissionRefusal::Unavailable)?;
        let entry = submissions
            .entries
            .get_mut(key)
            .ok_or(SubmissionRefusal::StaleDispatch)?;
        let active_generation_id = entry
            .actor
            .active_generation()
            .map(|generation| generation.generation_id.0);
        let receipt = entry.actor.cancel_subscriber(operation);
        if receipt == CancelReceipt::LastInterestCancelledGeneration {
            if matches!(
                entry.state,
                DispatchState::Claimed(_) | DispatchState::Started(_)
            ) {
                entry.state = DispatchState::Queued;
            }
            if let Some(generation_id) = active_generation_id
                && let Some(cas) = self.cas.as_ref()
            {
                let mut store = cas
                    .store()
                    .lock()
                    .map_err(|_| SubmissionRefusal::Unavailable)?;
                store.tombstone_generation(generation_id).map_err(|error| {
                    SubmissionRefusal::Admission(format!(
                        "last-subscriber drain generation tombstone: {error:?}"
                    ))
                })?;
            }
        }
        Ok(receipt)
    }

    /// Promote an attached subscriber's interest in place without creating a
    /// duplicate actor or execution attempt (bead Q005 / G004).
    pub fn promote_subscriber(
        &self,
        key: &TypedDigest,
        operation: BuildOperationId,
        deadline_unix_micros: Option<i64>,
    ) -> Result<PromoteReceipt, SubmissionRefusal> {
        if !self.available() {
            return Err(SubmissionRefusal::Unavailable);
        }
        let mut submissions = self
            .submissions
            .lock()
            .map_err(|_| SubmissionRefusal::Unavailable)?;
        let entry = submissions
            .entries
            .get_mut(key)
            .ok_or(SubmissionRefusal::StaleDispatch)?;
        let was_optional_only = !entry.actor.has_foreground_interest();
        let receipt = entry
            .actor
            .promote_with_deadline(operation, deadline_unix_micros);
        if was_optional_only && entry.actor.has_foreground_interest() {
            entry.promoted_from_speculation = true;
        }
        Ok(receipt)
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
        lease_ttl_ms: u64,
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
            self.record_brownout_refusal()?;
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
        // Arm the TTL after fallible generation preparation. Recheck after
        // durable admission so slow SQL/fsync cannot return expired proof.
        let admitted = self
            .lease_deadline(lease_ttl_ms)
            .and_then(|(_, deadline)| {
                store.admit_attempt_lease(&authority, self.next_seq(), deadline)
            })
            .and_then(|()| self.confirm_live_admission(&mut *store, &authority));
        if let Err(error) = admitted {
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
        entry.started_at = Some(Instant::now());
        Ok(authority)
    }

    /// Claim the queued execution of ONE known key. The edge's live
    /// dependency lane executes exactly the action its subscriber asked for;
    /// it must not take whatever happens to rank first in the shared queue.
    /// `None` when the key is not queued (another claim or attempt owns it).
    pub(crate) fn claim_submitted_dispatch(
        &self,
        key: &TypedDigest,
    ) -> Result<Option<u64>, SubmissionRefusal> {
        if !self.available() {
            return Err(SubmissionRefusal::Unavailable);
        }
        let mut submissions = self
            .submissions
            .lock()
            .map_err(|_| SubmissionRefusal::Unavailable)?;
        if !submissions
            .entries
            .get(key)
            .is_some_and(|entry| entry.state == DispatchState::Queued)
        {
            return Ok(None);
        }
        let serial = submissions.next_serial()?;
        let entry = submissions
            .entries
            .get_mut(key)
            .ok_or(SubmissionRefusal::StaleDispatch)?;
        entry.state = DispatchState::Claimed(serial);
        Ok(Some(serial))
    }

    /// Admit a claimed dispatch: durable generation, attempt and lease.
    pub(crate) fn begin_claimed_dispatch(
        &self,
        key: &TypedDigest,
        serial: u64,
        worker: &WorkerSessionOffer,
        lease_ttl_ms: u64,
    ) -> Result<AttemptAuthority, SubmissionRefusal> {
        self.begin_submitted_dispatch(key, serial, worker, lease_ttl_ms)
    }

    /// One observed attempt transition through the actor machine, for the
    /// dispatch claim `(key, serial)` that started `authority`.
    pub(crate) fn advance_started_dispatch(
        &self,
        key: &TypedDigest,
        serial: u64,
        authority: &AttemptAuthority,
        to: rabs_action::state_machines::AttemptState,
    ) -> Result<(), SubmissionRefusal> {
        use crate::coord::action_actor::AdvanceAttemptReceipt;
        let mut submissions = self
            .submissions
            .lock()
            .map_err(|_| SubmissionRefusal::Unavailable)?;
        let entry = submissions
            .entries
            .get_mut(key)
            .ok_or(SubmissionRefusal::StaleDispatch)?;
        if entry.state != DispatchState::Started(serial) {
            return Err(SubmissionRefusal::StaleDispatch);
        }
        match entry.actor.advance_attempt(authority.attempt_id, to) {
            AdvanceAttemptReceipt::Advanced => Ok(()),
            refusal => Err(SubmissionRefusal::Admission(format!(
                "attempt transition: {refusal:?}"
            ))),
        }
    }

    /// Mark a started dispatch finished once its attempt reached `Finished`.
    pub(crate) fn complete_started_dispatch(
        &self,
        key: &TypedDigest,
        serial: u64,
        authority: &AttemptAuthority,
    ) -> Result<(), SubmissionRefusal> {
        let mut submissions = self
            .submissions
            .lock()
            .map_err(|_| SubmissionRefusal::Unavailable)?;
        let entry = submissions
            .entries
            .get_mut(key)
            .ok_or(SubmissionRefusal::StaleDispatch)?;
        if entry.state != DispatchState::Started(serial)
            || !entry.actor.attempts().any(|attempt| {
                attempt.attempt == authority.attempt_id
                    && attempt.state == rabs_action::state_machines::AttemptState::Finished
            })
        {
            return Err(SubmissionRefusal::StaleDispatch);
        }
        entry.state = DispatchState::Finished;
        if entry.started_as_speculative {
            let elapsed_ms = entry.started_at.take().map_or(1, |started| {
                u64::try_from(started.elapsed().as_millis())
                    .unwrap_or(u64::MAX)
                    .max(1)
            });
            let bytes = entry.input.source_bytes();
            let outcome =
                if entry.promoted_from_speculation || entry.actor.has_foreground_interest() {
                    SpeculationRunOutcome::PromotedToForeground
                } else {
                    SpeculationRunOutcome::SavedCompleted
                };
            self.speculation_provenance
                .lock()
                .map_err(|_| SubmissionRefusal::Unavailable)?
                .record_completed();
            self.speculation_runs
                .lock()
                .map_err(|_| SubmissionRefusal::Unavailable)?
                .push(SpeculationRunRecord {
                    outcome,
                    saved_foreground_latency_ms: elapsed_ms,
                    execution_cost_ms: elapsed_ms,
                    transfer_cost_bytes: bytes,
                    storage_cost_bytes: bytes,
                });
        }
        Ok(())
    }

    /// Drop semantics of an unconfirmed claim: before admission the queue
    /// regains it; after admission it is abandoned pending reconciliation,
    /// never silently retried.
    pub(crate) fn release_dispatch_claim(&self, key: &TypedDigest, serial: u64) {
        if let Ok(mut submissions) = self.submissions.lock()
            && let Some(entry) = submissions.entries.get_mut(key)
        {
            match entry.state {
                DispatchState::Claimed(claimed) if claimed == serial => {
                    entry.state = DispatchState::Queued;
                }
                DispatchState::Started(started) if started == serial => {
                    entry.state = DispatchState::Abandoned;
                }
                _ => {}
            }
        }
    }

    /// The mounted store, for coordinator-side lanes in this crate.
    pub(crate) fn live_cas(&self) -> Option<&Arc<LiveCas>> {
        self.cas.as_ref()
    }

    /// Serve under the edge's live evidence/sampling floor (the same gate
    /// [`EdgeSubscriber::serve_action`] applies). `ServeMode::Preview`
    /// answers [`ServeOutcome::Servable`] instead of installing.
    pub(crate) fn serve_for_subscriber(
        &self,
        action_key: &TypedDigest,
        destination_root: &Path,
        expected: &ExpectedOutputs,
        now_unix_micros: i64,
        mode: ServeMode,
    ) -> Result<ServeOutcome, ServeError> {
        self.serve_action_inner(
            action_key,
            destination_root,
            expected,
            now_unix_micros,
            0,
            Some(LIVE_SAMPLING_POLICY),
            mode,
        )
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
        let pressure = self
            .speculation_pressure
            .lock()
            .map_err(|_| SubmissionRefusal::Unavailable)?
            .unwrap_or(PressureBand::Normal);
        debug_assert_eq!(
            decide(WorkCategory::Cleanup, pressure),
            BrownoutDecision::Admit,
            "cleanup work must remain required under every pressure band"
        );
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
    /// The TTL is a duration in milliseconds on this coordinator's clock.
    ///
    /// # Errors
    /// A typed refusal when this coordinator/store is unavailable, the
    /// request names stale coordinator authority, or any durable generation
    /// or worker fence rejects it.
    pub fn admit_attempt_lease(
        &self,
        authority: &AttemptAuthority,
        lease_ttl_ms: u64,
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
        let (_, expires_at_seq) = self
            .lease_deadline(lease_ttl_ms)
            .map_err(AttemptLeaseRefusal::Store)?;
        store
            .admit_attempt_lease(authority, recorded_seq, expires_at_seq)
            .map_err(AttemptLeaseRefusal::Store)?;
        self.confirm_live_admission(&mut *store, authority)
            .map_err(AttemptLeaseRefusal::Store)?;
        Ok(ValidatedAttemptLease {
            authority: authority.clone(),
        })
    }

    /// Renew one attempt lease by durable compare-and-swap, revalidating
    /// the exact current worker fence in the same transaction. A duration
    /// re-arms a still-live lease; an expired lease requires a new attempt.
    ///
    /// # Errors
    /// As [`Self::admit_attempt_lease`], plus lease ownership/sequence
    /// refusals.
    pub fn renew_attempt_lease(
        &self,
        authority: &AttemptAuthority,
        renewal: LeaseRenewal,
        lease_ttl_ms: u64,
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
        let (_, expires_at_seq) = self
            .lease_deadline(lease_ttl_ms)
            .map_err(AttemptLeaseRefusal::Store)?;
        store
            .renew_attempt_lease(authority, renewal, expires_at_seq, &|| self.lease_now_ms())
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
    /// A typed [`CommitRefusal`]. Refusals do not publish this offer;
    /// already-verified lineage reconciliation and uploaded objects may remain.
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

        // Retain this action's pre-offer baseline for comparison feedback.
        // Producers are resolved on demand by the SAME admission walk below,
        // after its fences, through the already-held store. No second graph
        // walk, eager manifest map, nested metadata lock, or daemon-lifetime
        // cache of producer state is needed.
        let committed_key = store
            .published_manifest_key(&offer.manifest.action_key)
            .map_err(|e| CommitRefusal::Store(format!("{e:?}")))?;
        let committed = match &committed_key {
            Some(key) => load_manifest(&mut *store, key),
            None => None,
        };
        let resolver = |store: &mut dyn RabsMetadataStore, key: &str| {
            if committed_key.as_deref() == Some(key) {
                // An unavailable baseline must remain unavailable, rather than
                // becoming a different comparison after a second read.
                committed.clone()
            } else {
                load_manifest(store, key)
            }
        };

        let outcome = process_offer_resolving(
            &mut *store,
            offer,
            expected_descriptor,
            resolver,
            pin_id,
            seq,
            CommitDurabilityProfile::RequireDurableClosure,
            || self.lease_now_ms(),
        )
        .map_err(CommitRefusal::Offer)?;
        if let Err(error) =
            record_live_verification(&mut *store, offer, &outcome, committed.as_ref())
        {
            // The canonical publication/quarantine ALREADY succeeded. Never
            // turn missing feedback into a false "nothing committed" refusal
            // that could cause a caller to rerun completed work. Missing
            // positive evidence cannot pass the live sampling floor; a
            // divergence was already durably blocked by process_offer.
            eprintln!(
                "{}",
                serde_json::json!({
                    "v": 1,
                    "kind": "rabsd-verification-feedback-error",
                    "action_key": digest_key(&offer.manifest.action_key),
                    "error": format!("{error:?}"),
                })
            );
        }
        Ok(outcome)
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
    /// 3. the complete logical-output set is checked against `expected`;
    ///    unsupported roles or dep-info derivations refuse before installation;
    /// 4. every destination is resolved under `destination_root` and
    ///    refused if it escapes (absolute, `..`, empty);
    /// 5. the D031 arbiter reserves ALL of them all-or-nothing, so two
    ///    concurrent serves cannot install into overlapping paths;
    /// 6. only then do bytes land, each verified against its object id,
    ///    privately derived where needed, stamped and renamed into place.
    ///
    /// A failure part-way leaves the files already written in place —
    /// they are individually verified artifacts or subscriber derivations —
    /// and reports the exact installed prefix. A partial serve is not a hit
    /// and never authorizes uncoordinated compiler execution.
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
        // Coordinator-owned inspection/materialization. Restricted edge
        // callers route through serve_action_inner with the sampling floor.
        self.serve_action_inner(
            action_key,
            destination_root,
            expected,
            now_unix_micros,
            now_epoch,
            None,
            ServeMode::Install,
        )
    }

    /// Install the exact successfully published result of the current remote
    /// producer. The opaque live-dependency owner and fresh wrapper consent
    /// authorize this call; it is not available to the restricted edge cache
    /// reader. All mutable authority, publication, release and quarantine gates
    /// remain active. Subsequent reads still spend the normal replay allowance.
    pub(super) fn serve_produced_result(
        &self,
        action_key: &TypedDigest,
        manifest_key: &str,
        destination_root: &Path,
        expected: &ExpectedOutputs,
        now_unix_micros: i64,
    ) -> Result<ServeOutcome, ServeError> {
        self.serve_action_bound(
            action_key,
            destination_root,
            expected,
            now_unix_micros,
            0,
            None,
            ServeMode::Install,
            Some(manifest_key),
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn serve_action_inner(
        &self,
        action_key: &TypedDigest,
        destination_root: &Path,
        expected: &ExpectedOutputs,
        now_unix_micros: i64,
        now_epoch: u64,
        sampling: Option<SamplingPolicy>,
        mode: ServeMode,
    ) -> Result<ServeOutcome, ServeError> {
        self.serve_action_bound(
            action_key,
            destination_root,
            expected,
            now_unix_micros,
            now_epoch,
            sampling,
            mode,
            None,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn serve_action_bound(
        &self,
        action_key: &TypedDigest,
        destination_root: &Path,
        expected: &ExpectedOutputs,
        now_unix_micros: i64,
        now_epoch: u64,
        sampling: Option<SamplingPolicy>,
        mode: ServeMode,
        produced_manifest: Option<&str>,
    ) -> Result<ServeOutcome, ServeError> {
        // Take the authority snapshot BEFORE the store lock, preserving the
        // existing authority -> store lock order during coordinator startup.
        let replay_authority = if sampling.is_some() || produced_manifest.is_some() {
            if !self.available() {
                return Err(ServeError::CoordinatorUnavailable);
            }
            Some(self.authority().ok_or(ServeError::CoordinatorUnavailable)?)
        } else {
            None
        };
        let cas = self.cas.as_ref().ok_or(ServeError::NoStore)?;
        let key = digest_key(action_key);
        let mut store = cas
            .store()
            .lock()
            .map_err(|_| ServeError::StoreUnavailable)?;
        declare_coordinator_domains(&mut *store);
        if let Some(ref held) = replay_authority {
            if !self.available() {
                return Err(ServeError::CoordinatorUnavailable);
            }
            match store
                .active_authority()
                .map_err(|error| ServeError::Store(format!("{error:?}")))?
            {
                Some(active) if active.digest == authority_digest(held) => {}
                _ => return Err(ServeError::CoordinatorUnavailable),
            }
        }

        // T011: the BUILD-level question, asked before any per-action
        // state is read. A binary the corpus gate has not cleared must
        // not serve even an action whose own serving record is
        // impeccable, so this sits ahead of `serving_gate` rather than
        // beside it — strictest-first, the same ordering discipline the
        // per-action gate uses internally.
        //
        // Under the default Advisory mode this never refuses; it only
        // evaluates, so the standing is available to the status surface
        // and the operator can see what Required would have done.
        let standing = release_standing(
            store
                .release_verdict(&self.build_identity)
                .map_err(|error| ServeError::Store(format!("{error:?}")))?
                .as_ref(),
            &self.build_identity,
            now_unix_micros,
            now_epoch,
        );
        if !standing.permits_serving(self.release_mode) {
            return Ok(ServeOutcome::ReleaseUnauthorized { standing });
        }

        match serving_gate(&mut *store, &key, now_unix_micros, now_epoch)
            .map_err(|e| ServeError::Store(format!("{e:?}")))?
        {
            ServeDecision::Servable => {}
            decision => return Ok(ServeOutcome::NotServable(decision)),
        }
        if let Some(policy) = sampling
            && let Some(refusal) = live_replay_gate(&mut *store, action_key, &policy)
                .map_err(|error| ServeError::Store(format!("{error:?}")))?
        {
            return Ok(ServeOutcome::ExecutePrivately(refusal));
        }
        if produced_manifest.is_some()
            && let Some(refusal) = live_producer_gate(&mut *store, action_key)
                .map_err(|error| ServeError::Store(format!("{error:?}")))?
        {
            return Ok(ServeOutcome::ExecutePrivately(refusal));
        }
        let Some(manifest_key) = store
            .published_manifest_key(action_key)
            .map_err(|e| ServeError::Store(format!("{e:?}")))?
        else {
            // A servable disposition with no publication row is a torn
            // store, not a hit.
            return Ok(ServeOutcome::NoCommit);
        };
        if produced_manifest.is_some_and(|expected| expected != manifest_key) {
            return Ok(ServeOutcome::ManifestUnavailable { key: manifest_key });
        }
        let Some(manifest) = load_manifest(&mut *store, &manifest_key) else {
            return Ok(ServeOutcome::ManifestUnavailable { key: manifest_key });
        };
        if manifest.action_key != *action_key {
            // A corrupt publication pointer must not substitute another
            // action's otherwise valid, content-addressed output manifest.
            return Ok(ServeOutcome::ManifestUnavailable { key: manifest_key });
        }
        if sampling.is_some()
            && live_replay_permit(&mut *store, action_key, &manifest_key)
                .map_err(|error| ServeError::Store(format!("{error:?}")))?
                .is_none()
        {
            return Ok(ServeOutcome::ExecutePrivately(
                ReplayRefusal::FreshVerificationRequired,
            ));
        }
        // One complete logical-output map: do not silently discard .rmeta or
        // dep-info. Canonical .d files are verified and derived privately before
        // any target write. Unsupported roles and incomplete mappings refuse.
        let plan =
            match output_install::prepare(&mut *store, &manifest, destination_root, expected)? {
                Ok(plan) => plan,
                Err(outcome) => return Ok(outcome),
            };
        if mode == ServeMode::Preview {
            return Ok(ServeOutcome::Servable);
        }
        if plan.outputs.is_empty() {
            if sampling.is_some() {
                let Some(permit) = live_replay_permit(&mut *store, action_key, &manifest_key)
                    .map_err(|error| ServeError::Store(format!("{error:?}")))?
                else {
                    return Ok(ServeOutcome::ExecutePrivately(
                        ReplayRefusal::FreshVerificationRequired,
                    ));
                };
                store
                    .record_decision_receipt(
                        LIVE_INSTALL_RECEIPT,
                        &permit.subject,
                        permit.seq,
                        "install",
                        &manifest_key,
                    )
                    .map_err(|error| ServeError::Store(format!("{error:?}")))?;
            }
            return Ok(ServeOutcome::Served { files: Vec::new() });
        }

        // D031: reserve every destination all-or-nothing before any staging or
        // install. The reservation stays live across the metadata-lock handoff,
        // so another subscriber cannot race private preparation into the same
        // final namespace.
        let bundle = BundleId(format!("serve:{key}:{}", self.next_seq()));
        use rabs_protocol::raw_bytes::RawBytes;
        use std::os::unix::ffi::OsStrExt;
        let paths: Vec<Vec<u8>> = plan
            .outputs
            .iter()
            .map(|out| out.destination.as_os_str().as_bytes().to_vec())
            .collect();
        let _reservation = reserve_scoped(&self.arbiter, bundle, &paths).map_err(|conflict| {
            ServeError::DestinationConflict {
                path: RawBytes::new(conflict.path).escaped(),
                holder: conflict.holder.0,
            }
        })?;

        // Select exact non-quarantined replicas while metadata is authoritative,
        // then release the global store mutex for expensive copy/hash/derivation.
        // The staged owner exposes no final destination and carries no serving
        // authority. A corrupt replica is settled only after reacquiring metadata.
        let selected = output_install::select_for_install(&mut *store, &plan)?;
        drop(store);
        let prepared = match output_install::stage_for_install(selected, &plan) {
            Ok(prepared) => prepared,
            Err(failure) => {
                let mut store = cas
                    .store()
                    .lock()
                    .map_err(|_| ServeError::StoreUnavailable)?;
                return Err(output_install::settle_stage_failure(&mut *store, failure));
            }
        };

        // Bytes may have taken arbitrarily long to stage. Re-enter every mutable
        // authority/gating boundary before the FIRST rename. The prepared CAS
        // owner independently rechecks object quarantine, selected locations and
        // private file generations during install.
        let mut store = cas
            .store()
            .lock()
            .map_err(|_| ServeError::StoreUnavailable)?;
        declare_coordinator_domains(&mut *store);
        if let Some(ref held) = replay_authority {
            if !self.available() {
                return Err(ServeError::CoordinatorUnavailable);
            }
            match store
                .active_authority()
                .map_err(|error| ServeError::Store(format!("{error:?}")))?
            {
                Some(active) if active.digest == authority_digest(held) => {}
                _ => return Err(ServeError::CoordinatorUnavailable),
            }
        }
        let standing = release_standing(
            store
                .release_verdict(&self.build_identity)
                .map_err(|error| ServeError::Store(format!("{error:?}")))?
                .as_ref(),
            &self.build_identity,
            now_unix_micros,
            now_epoch,
        );
        if !standing.permits_serving(self.release_mode) {
            return Ok(ServeOutcome::ReleaseUnauthorized { standing });
        }
        match serving_gate(&mut *store, &key, now_unix_micros, now_epoch)
            .map_err(|error| ServeError::Store(format!("{error:?}")))?
        {
            ServeDecision::Servable => {}
            decision => return Ok(ServeOutcome::NotServable(decision)),
        }
        if let Some(policy) = sampling
            && let Some(refusal) = live_replay_gate(&mut *store, action_key, &policy)
                .map_err(|error| ServeError::Store(format!("{error:?}")))?
        {
            return Ok(ServeOutcome::ExecutePrivately(refusal));
        }
        if produced_manifest.is_some()
            && let Some(refusal) = live_producer_gate(&mut *store, action_key)
                .map_err(|error| ServeError::Store(format!("{error:?}")))?
        {
            return Ok(ServeOutcome::ExecutePrivately(refusal));
        }
        match store
            .published_manifest_key(action_key)
            .map_err(|error| ServeError::Store(format!("{error:?}")))?
        {
            Some(current) if current == manifest_key => {}
            Some(current) => return Ok(ServeOutcome::ManifestUnavailable { key: current }),
            None => return Ok(ServeOutcome::NoCommit),
        }
        if sampling.is_some() {
            let Some(permit) = live_replay_permit(&mut *store, action_key, &manifest_key)
                .map_err(|error| ServeError::Store(format!("{error:?}")))?
            else {
                return Ok(ServeOutcome::ExecutePrivately(
                    ReplayRefusal::FreshVerificationRequired,
                ));
            };
            // Spend only after the post-staging gates pass. A failed/partial
            // install still conservatively consumes this durable allowance.
            store
                .record_decision_receipt(
                    LIVE_INSTALL_RECEIPT,
                    &permit.subject,
                    permit.seq,
                    "install",
                    &manifest_key,
                )
                .map_err(|error| ServeError::Store(format!("{error:?}")))?;
        }
        let files = output_install::install_prepared(&mut *store, &plan, prepared)?;
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

    /// This process's own monotonic time domain. The origin never changes
    /// while its authority is live, including during an idle partition.
    fn lease_now_ms(&self) -> u64 {
        u64::try_from(
            self.lease_clock
                .get_or_init(Instant::now)
                .elapsed()
                .as_millis(),
        )
        .unwrap_or(u64::MAX)
    }

    fn confirm_live_admission(
        &self,
        store: &mut dyn RabsMetadataStore,
        authority: &AttemptAuthority,
    ) -> Result<(), StoreError> {
        let lease = store.validate_attempt_lease(authority, self.lease_now_ms())?;
        // Validation itself performs SQL reads; sample again after them.
        if self.lease_now_ms() >= lease.expires_at_own_monotonic_ms {
            return Err(StoreError::LeaseExpired);
        }
        Ok(())
    }

    fn lease_deadline(&self, ttl_ms: u64) -> Result<(u64, u64), StoreError> {
        let now = self.lease_now_ms();
        let deadline = now
            .checked_add(ttl_ms)
            .filter(|deadline| ttl_ms > 0 && *deadline <= i64::MAX as u64)
            .ok_or(StoreError::LeaseExpired)?;
        Ok((now, deadline))
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
             \"closed_prior_authority_generations\":{},\
             \"build_identity\":\"{}\",\"release_mode\":\"{}\",\"release_standing\":\"{}\"}}",
            self.available(),
            self.cas.is_some(),
            authority.is_some(),
            authority.map_or(0, |a| a.term),
            self.closed_prior_generations(),
            self.build_identity.replace('"', "'"),
            match self.release_mode {
                ReleaseAuthorizationMode::Advisory => "advisory",
                ReleaseAuthorizationMode::Required => "required",
            },
            // T011: reported under BOTH modes, so an advisory
            // deployment can see it would be refused before it flips
            // the switch. A store that cannot be read reports
            // "unknown" rather than borrowing the authorized token —
            // the status line never reads better than the evidence.
            self.release_standing_for_status(),
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

/// Maximum canonical manifest bytes accepted by live replay. Oversized
/// manifests produce a conservative miss, not an unbounded daemon allocation.
const MAX_LIVE_MANIFEST_BYTES: u64 = 16 * 1024 * 1024;

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
    use std::io::Read;

    let object = object_id_from_key(manifest_key)?;
    // A quarantine of the logical object is stronger than selecting another
    // physical copy. Do not infer release from an omitted serving reference.
    if !store
        .query(
            "SELECT 1 FROM quarantines WHERE scope = 'logical-object' AND subject = ?1 LIMIT 1",
            &[SqlValue::Text(manifest_key.to_owned())],
        )
        .ok()?
        .is_empty()
    {
        return None;
    }
    let locations = store.object_locations(&object).ok()?;
    for (path, encoding, _) in locations {
        // Preserve the existing representation boundary: compressed/packed
        // copies require their own decoders and are not raw manifests.
        if encoding != RAW_PROFILE_V1 {
            continue;
        }
        // Stored manifests are regular CAS files. In particular, do not open
        // a recorded FIFO/device or follow a symlink before applying the byte
        // bound. The content digest remains authoritative after opening.
        if !std::fs::symlink_metadata(&path).is_ok_and(|meta| meta.file_type().is_file()) {
            continue;
        }
        let Ok(file) = std::fs::File::open(&path) else {
            continue;
        };
        let mut bytes = Vec::new();
        if file
            .take(MAX_LIVE_MANIFEST_BYTES + 1)
            .read_to_end(&mut bytes)
            .is_err()
            || u64::try_from(bytes.len()).ok()? > MAX_LIVE_MANIFEST_BYTES
        {
            continue;
        }
        let digests = digest_set(&bytes, DigestRequest::default(), None).ok()?;
        if digests.atp_content_id != object {
            // Decodable bytes are not necessarily the committed bytes. A bad
            // location must never drive divergence comparison or installation.
            // Quarantine just THIS copy, then try another verified replica.
            store.set_location_quarantined(&object, &path, true).ok()?;
            continue;
        }
        let Ok(manifest) = decode_manifest_v1(&bytes) else {
            continue;
        };
        if rabs_key::logical_output_map::verify_manifest_bundle_root(&manifest).is_ok()
            && rabs_cas::publication::semantic_result_digest_v1(&manifest)
                == manifest.semantic_result_digest
            && encode_manifest_v1(&manifest) == bytes
        {
            return Some(manifest);
        }
    }
    None
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
    use rabs_protocol::input_evidence::{
        DirectoryEnumeration, INPUT_EVIDENCE_SCHEMA_VERSION, PositiveInput,
    };
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
        let dir = crate::test_util::private_tempdir();
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

    #[allow(clippy::type_complexity)]
    fn complete_projection_fixture() -> (
        tempfile::TempDir,
        Arc<SealedSourceSnapshot>,
        ActionInputManifest,
        ActionDescriptor,
        Vec<(String, String)>,
    ) {
        let root = crate::test_util::private_tempdir();
        let package = root.path().join("package");
        let generated = root.path().join("generated");
        let native = root.path().join("native");
        std::fs::create_dir(&package).unwrap();
        std::fs::create_dir_all(generated.join("nested/also-empty")).unwrap();
        std::fs::create_dir(generated.join("empty")).unwrap();
        std::fs::create_dir(&native).unwrap();
        std::fs::write(package.join("input.txt"), b"projected bytes\n").unwrap();
        std::fs::write(package.join("unrelated.txt"), b"unprojected package file").unwrap();
        std::fs::write(generated.join("nested/libnative.a"), b"retained archive").unwrap();
        let source = Arc::new(
            capture_sealed_source(
                &[
                    ("package".into(), package),
                    ("generated".into(), generated),
                    ("native".into(), native),
                ],
                false,
                2,
                4096,
            )
            .unwrap(),
        );
        let inputs = [
            (
                "/__rabs/repos/package/input.txt",
                b"projected bytes\n".as_slice(),
            ),
            (
                "/__rabs/repos/package-generated/nested/libnative.a",
                b"retained archive".as_slice(),
            ),
        ]
        .into_iter()
        .map(|(path, bytes)| PositiveInput {
            virtual_path: RawBytes::from(path),
            object: ObjectId(
                digest_set(bytes, DigestRequest::default(), None)
                    .unwrap()
                    .atp_content_id,
            ),
            file_type: InputFileType::Regular,
            executable: false,
            symlink_resolution: Vec::new(),
        })
        .collect();
        let directory_enumerations = [
            ("/__rabs/repos/package-generated", vec!["empty", "nested"]),
            ("/__rabs/repos/package-generated/empty", vec![]),
            (
                "/__rabs/repos/package-generated/nested",
                vec!["also-empty", "libnative.a"],
            ),
            ("/__rabs/repos/package-generated/nested/also-empty", vec![]),
            ("/__rabs/repos/package-native-0000", vec![]),
        ]
        .into_iter()
        .map(|(path, entries)| DirectoryEnumeration {
            virtual_path: RawBytes::from(path),
            entries: entries.into_iter().map(RawBytes::from).collect(),
        })
        .collect();
        let manifest = ActionInputManifest {
            schema_version: INPUT_EVIDENCE_SCHEMA_VERSION,
            inputs,
            directory_enumerations,
            approved_generated_objects: Vec::new(),
        };
        let (_base, _image, _inputs, mut descriptor) = source_fixture();
        descriptor.action_inputs = action_input_manifest_digest(&manifest).unwrap();
        let mappings = vec![
            ("package".into(), "/__rabs/repos/package".into()),
            ("generated".into(), "/__rabs/repos/package-generated".into()),
            ("native".into(), "/__rabs/repos/package-native-0000".into()),
        ];
        (root, source, manifest, descriptor, mappings)
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
        let state = crate::test_util::private_tempdir();
        let coord = CoordLive::with_cas(Arc::new(mount_and_reconcile(state.path()).unwrap()));
        coord.acquire_boot_authority("submission-tests").unwrap();
        coord.mark_up();
        (state, coord)
    }

    #[test]
    fn execution_lease_uses_monotonic_time_independently_of_publication_sequence() {
        use rabs_cas::test_support::{install_admission_world, install_offer_closure};

        let (_state, coord) = submission_coordinator();
        let held = coord.authority().unwrap();
        let offer = offer_under(&held);
        let cas = coord.cas.as_ref().unwrap();
        {
            let mut store = cas.store().lock().unwrap();
            install_admission_world(&mut *store, &held);
            install_offer_closure(&mut *store, &offer);
        }
        // Receipt sequences can be arbitrarily far ahead of a lease's clock
        // without shortening its TTL. No wall-clock comparison belongs here.
        coord
            .next_seq
            .store(i64::MAX as u64 - 100, Ordering::Relaxed);
        assert!(matches!(
            coord
                .commit_offer(&offer, &sample_expected_descriptor())
                .unwrap(),
            PublicationOutcome::Committed(_)
        ));
    }

    #[test]
    fn expired_execution_cannot_publish_or_renew_after_an_idle_partition_or_restart() {
        use rabs_cas::test_support::{install_admission_world, install_offer_closure};
        use std::time::Duration;

        let (state, mut coord) = submission_coordinator();
        let held = coord.authority().unwrap();
        let offer = offer_under(&held);
        {
            let mut store = coord.cas.as_ref().unwrap().store().lock().unwrap();
            install_admission_world(&mut *store, &held);
            install_offer_closure(&mut *store, &offer);
        }
        // Deterministically model a quiet partition: elapsed monotonic time
        // advances beyond the fixture's 60-second lease without any receipt
        // traffic, waiting, or dependency on the machine's wall clock.
        let sequence = coord.next_seq.load(Ordering::Relaxed);
        coord.lease_clock = OnceLock::from(Instant::now() - Duration::from_secs(61));
        assert!(coord.lease_now_ms() >= 61_000);
        assert_eq!(coord.next_seq.load(Ordering::Relaxed), sequence);
        assert_eq!(
            coord.commit_offer(&offer, &sample_expected_descriptor()),
            Err(CommitRefusal::Offer(OfferRefusal::LeaseExpired))
        );
        assert_eq!(
            coord.renew_attempt_lease(
                &offer.authority,
                LeaseRenewal {
                    lease: offer.authority.execution_lease_id,
                    seq: LeaseRenewalSeq(offer.authority.lease_renewal_seq.0 + 1),
                },
                60_000,
            ),
            Err(AttemptLeaseRefusal::Store(StoreError::LeaseExpired))
        );
        {
            let mut store = coord.cas.as_ref().unwrap().store().lock().unwrap();
            assert!(!store.has_publication(&offer.manifest.action_key).unwrap());
            assert!(store.object_located(&offer.manifest_id.0).unwrap());
            assert!(store.object_located(&offer.evidence_id.0).unwrap());
        }
        drop(coord);

        let restarted = CoordLive::with_cas(Arc::new(mount_and_reconcile(state.path()).unwrap()));
        restarted
            .acquire_boot_authority("submission-tests")
            .unwrap();
        assert!(matches!(
            restarted.commit_offer(&offer, &sample_expected_descriptor()),
            Err(CommitRefusal::StaleAuthority { .. })
        ));
        assert!(restarted.closed_prior_generations() > 0);
        assert!(
            !restarted
                .cas
                .as_ref()
                .unwrap()
                .store()
                .lock()
                .unwrap()
                .has_publication(&offer.manifest.action_key)
                .unwrap()
        );
    }

    #[test]
    fn coordinator_arms_lease_deadlines_from_durations_and_rejects_empty_or_overflowing_ttl() {
        use std::time::Duration;

        let mut coord = CoordLive::new();
        coord.lease_clock = OnceLock::from(Instant::now() - Duration::from_secs(61));
        let (now, deadline) = coord.lease_deadline(5_000).unwrap();
        assert!(now >= 61_000);
        assert_eq!(deadline - now, 5_000);
        assert_eq!(coord.lease_deadline(0), Err(StoreError::LeaseExpired));
        assert_eq!(
            coord.lease_deadline(u64::MAX),
            Err(StoreError::LeaseExpired)
        );
    }

    #[test]
    fn live_serving_class_is_key_bound_and_survives_reopen() {
        let (state, coord) = submission_coordinator();
        let (_source_dir, source, manifest, mut descriptor) = source_fixture();
        descriptor.action_class = ActionClass::RustcDependencyCompile;
        let dependency = coord
            .submit_action(
                submission(&source, &manifest, &descriptor),
                request(1, SubscriberKind::ForegroundAgent, 1),
                1,
                0,
            )
            .unwrap();
        descriptor.action_class = ActionClass::RustcWorkspaceCompile;
        let workspace = coord
            .submit_action(
                submission(&source, &manifest, &descriptor),
                request(2, SubscriberKind::ForegroundAgent, 1),
                2,
                0,
            )
            .unwrap();
        assert_ne!(dependency.action_key, workspace.action_key);
        drop(coord);
        let reopened = mount_and_reconcile(state.path()).unwrap();
        let mut store = reopened.store().lock().unwrap();
        assert_eq!(
            recorded_action_risk(&mut *store, &dependency.action_key).unwrap(),
            ActionClassRisk::LowRiskRegistry
        );
        assert_eq!(
            recorded_action_risk(&mut *store, &workspace.action_key).unwrap(),
            ActionClassRisk::Elevated
        );
        let unknown = rabs_key::typed_digest::compute(DOMAIN_ACTION_KEY, b"not submitted");
        assert_eq!(
            recorded_action_risk(&mut *store, &unknown).unwrap(),
            ActionClassRisk::Elevated
        );
    }

    #[test]
    fn projected_source_binds_bytes_and_materializes_only_keyed_inputs() {
        let (live, source, manifest, descriptor) = source_fixture();
        let input = submission(&source, &manifest, &descriptor);
        std::fs::write(live.path().join("input.txt"), b"edited after capture").unwrap();
        let fresh = crate::test_util::private_tempdir();
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
    fn complete_projection_retains_empty_directories_and_original_captured_bytes() {
        let (live, source, manifest, descriptor, mappings) = complete_projection_fixture();
        let input =
            ActionSubmission::from_snapshot(descriptor, &manifest, Arc::clone(&source), &mappings)
                .unwrap();
        std::fs::write(
            live.path().join("generated/nested/libnative.a"),
            b"changed archive",
        )
        .unwrap();
        std::fs::write(live.path().join("generated/empty/late-file"), b"later").unwrap();
        let target = live.path().join("projection");
        let paths = input.materialize_into(&target).unwrap();
        assert_eq!(paths.len(), 3);
        assert_eq!(
            std::fs::read(paths["generated"].join("nested/libnative.a")).unwrap(),
            b"retained archive"
        );
        for empty in [
            paths["generated"].join("empty"),
            paths["generated"].join("nested/also-empty"),
            paths["native"].clone(),
        ] {
            assert!(empty.is_dir());
            assert_eq!(std::fs::read_dir(empty).unwrap().count(), 0);
        }
        assert!(!paths["package"].join("unrelated.txt").exists());

        // A directory-only retained tree is a real input, including an empty
        // root, and needs no fabricated file to survive materialization.
        let mut empty_only = manifest;
        empty_only.inputs.clear();
        empty_only.directory_enumerations.retain(|enumeration| {
            enumeration.virtual_path.as_bytes() == b"/__rabs/repos/package-native-0000"
        });
        let mut descriptor = input.descriptor.clone();
        descriptor.action_inputs = action_input_manifest_digest(&empty_only).unwrap();
        let empty = ActionSubmission::from_snapshot(descriptor, &empty_only, source, &mappings)
            .unwrap()
            .materialize_into(&live.path().join("empty-projection"))
            .unwrap();
        assert_eq!(empty.len(), 1);
        assert!(empty["native"].is_dir());
    }

    #[test]
    fn complete_projection_refuses_missing_extra_unsafe_or_unprojected_directory_members() {
        let (_live, source, manifest, descriptor, mappings) = complete_projection_fixture();
        for case in 0..11 {
            let mut changed = manifest.clone();
            match case {
                0 => {
                    changed.directory_enumerations.remove(0);
                }
                1 => {
                    changed.directory_enumerations.remove(3);
                }
                2 => {
                    changed.directory_enumerations[0].entries.remove(0);
                }
                3 => changed.directory_enumerations[1]
                    .entries
                    .push(RawBytes::from("invented")),
                4 => changed.directory_enumerations.push(DirectoryEnumeration {
                    virtual_path: RawBytes::from(
                        "/__rabs/repos/package-generated/nested/libnative.a",
                    ),
                    entries: Vec::new(),
                }),
                5 => {
                    changed.directory_enumerations[1].virtual_path =
                        RawBytes::from("/__rabs/repos/unmapped/empty");
                }
                6 => changed.directory_enumerations[0].entries.reverse(),
                7 => {
                    changed.directory_enumerations[1].entries =
                        vec![RawBytes::from("duplicate"), RawBytes::from("duplicate")]
                }
                8 => changed.directory_enumerations[1].entries = vec![RawBytes::from("../escape")],
                9 => {
                    changed.directory_enumerations[1].virtual_path =
                        RawBytes::from("/__rabs/repos/package-generated/../escape");
                }
                _ => {
                    changed.inputs.remove(1);
                }
            }
            let mut described = descriptor.clone();
            described.action_inputs = action_input_manifest_digest(&changed).unwrap();
            assert!(
                matches!(
                    ActionSubmission::from_snapshot(
                        described,
                        &changed,
                        Arc::clone(&source),
                        &mappings,
                    ),
                    Err(SubmissionRefusal::InvalidSource(_))
                ),
                "case {case}"
            );
        }
    }

    #[test]
    fn key_only_evidence_retains_exact_bytes_without_becoming_a_source_mount() {
        let (live, source, mut manifest, mut descriptor, mappings) = complete_projection_fixture();
        let path = "/__rabs/repos/package-native-records/0000";
        let record = b"cargo::rustc-link-search=native=/__rabs/out/cargo/debug/build/a/out\n";
        manifest.inputs.push(PositiveInput {
            virtual_path: RawBytes::from(path),
            object: ObjectId(
                digest_set(record, DigestRequest::default(), None)
                    .unwrap()
                    .atp_content_id,
            ),
            file_type: InputFileType::Regular,
            executable: false,
            symlink_resolution: Vec::new(),
        });
        descriptor.action_inputs = action_input_manifest_digest(&manifest).unwrap();
        assert!(
            ActionSubmission::from_snapshot(
                descriptor.clone(),
                &manifest,
                Arc::clone(&source),
                &mappings,
            )
            .is_err()
        );
        let mut evidence = vec![(path.to_owned(), record.to_vec())];
        let input = ActionSubmission::from_snapshot_with_evidence(
            descriptor.clone(),
            &manifest,
            Arc::clone(&source),
            &mappings,
            &evidence,
        )
        .unwrap();
        evidence[0].1 = b"changed caller storage".to_vec();
        assert_eq!(input.evidence[0].as_ref(), record);
        assert_eq!(input.source_bytes(), 16 + 16 + record.len() as u64);
        let target = live.path().join("with-record");
        let paths = input.materialize_into(&target).unwrap();
        assert_eq!(
            paths.keys().map(String::as_str).collect::<Vec<_>>(),
            ["generated", "native", "package"]
        );
        assert!(!target.join("package-native-records").exists());
        assert!(!paths["native"].join("0000").exists());

        for case in 0..9 {
            let mut changed = manifest.clone();
            let mut evidence = vec![(path.to_owned(), record.to_vec())];
            match case {
                0 => evidence[0].1.push(b'!'),
                1 => changed.inputs.last_mut().unwrap().executable = true,
                2 => changed.inputs.last_mut().unwrap().file_type = InputFileType::Symlink,
                3 => evidence.push((format!("{path}-unused"), record.to_vec())),
                4 => evidence.push(evidence[0].clone()),
                5 => evidence.push((
                    "/__rabs/repos/package/input.txt".into(),
                    b"projected bytes\n".to_vec(),
                )),
                6 => evidence[0].0 = "/host/records/0000".into(),
                7 => evidence[0].0 = "/__rabs/repos/package-native-records/../0000".into(),
                _ => changed.directory_enumerations.push(DirectoryEnumeration {
                    virtual_path: RawBytes::from("/__rabs/repos/package-native-records"),
                    entries: vec![RawBytes::from("0000")],
                }),
            }
            let mut described = descriptor.clone();
            described.action_inputs = action_input_manifest_digest(&changed).unwrap();
            assert!(
                ActionSubmission::from_snapshot_with_evidence(
                    described,
                    &changed,
                    Arc::clone(&source),
                    &mappings,
                    &evidence,
                )
                .is_err(),
                "case {case}"
            );
        }
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
            let existing = crate::test_util::private_tempdir();
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
        let lease_ttl_ms = 60_000;
        {
            let mut claim = coord.next_action_dispatch().unwrap().unwrap();
            coord.set_speculation_pressure(PressureBand::Soft).unwrap();
            assert_eq!(
                claim.begin(&worker, lease_ttl_ms).unwrap_err(),
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
                claim.begin(&worker, lease_ttl_ms).unwrap_err(),
                SubmissionRefusal::Admission("lease: UnknownWorkerFence".into()),
                "unadmitted worker cannot obtain execution lease"
            );
        }
        coord.admit_worker_session(&worker).unwrap();
        let mut claim = coord.next_action_dispatch().unwrap().unwrap();
        let authority = claim.begin(&worker, lease_ttl_ms).unwrap().clone();
        assert_eq!(
            claim.begin(&worker, lease_ttl_ms).unwrap_err(),
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
    fn workspace_execution_retirement_allows_fresh_attempt_without_publishing() {
        use crate::coord::live_dependency::settle_completed_dispatch;
        use rabs_action::state_machines::AttemptState;

        let (_state, coord) = submission_coordinator();
        let (_source_root, source, manifest, mut descriptor) = source_fixture();
        descriptor.action_class = ActionClass::RustcWorkspaceCompile;
        let worker = worker_offer(1, 17);
        coord.admit_worker_session(&worker).unwrap();
        let mut attempts = Vec::new();
        for operation in 1..=2 {
            let submitted = coord
                .submit_action(
                    submission(&source, &manifest, &descriptor),
                    request(operation, SubscriberKind::ForegroundAgent, 200),
                    i64::try_from(operation).unwrap(),
                    0,
                )
                .unwrap();
            let key = submitted.action_key;
            let serial = coord.claim_submitted_dispatch(&key).unwrap().unwrap();
            let authority = coord
                .begin_claimed_dispatch(&key, serial, &worker, 60_000)
                .unwrap();
            assert!(!attempts.contains(&authority.attempt_id));
            attempts.push(authority.attempt_id);
            // Explicit lifecycle fixture, not a claim that a compiler ran.
            for state in [
                AttemptState::LeaseAccepted,
                AttemptState::AwaitingInputs,
                AttemptState::Materializing,
                AttemptState::Running,
                AttemptState::ProcessExited,
                AttemptState::HarvestingOutputs,
                AttemptState::UploadingOutputs,
                AttemptState::VerifyingOutputs,
                AttemptState::PreparedResultOffered,
            ] {
                coord
                    .advance_started_dispatch(&key, serial, &authority, state)
                    .unwrap();
            }
            settle_completed_dispatch(&coord, &key, serial, &authority).unwrap();
            assert!(coord.submitted_actor(&key).unwrap().is_none());
            let mut store = coord.live_cas().unwrap().store().lock().unwrap();
            assert!(store.published_manifest_key(&key).unwrap().is_none());
            assert!(store.list_verification_samples(&key).unwrap().is_empty());
        }
        assert_eq!(attempts.len(), 2);
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
        let dir = crate::test_util::private_tempdir();
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
        let dir = crate::test_util::private_tempdir();
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
            .admit_attempt_lease(&incumbent, 60_000)
            .expect("incumbent lease");
        let first_renewal = LeaseRenewal {
            lease: incumbent.execution_lease_id,
            seq: LeaseRenewalSeq(2),
        };
        coord
            .renew_attempt_lease(&incumbent, first_renewal, 60_000)
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
            store.validate_attempt_lease(&incumbent, 10),
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
            store.validate_attempt_lease(&incumbent, 10),
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
                &|| 10,
            )
            .expect("replacement renewal");
        replacement.lease_renewal_seq = LeaseRenewalSeq(2);
        assert_eq!(
            store.validate_attempt_lease(&replacement, 10),
            Ok(rabs_cas::metadata_store::LeaseState {
                released: false,
                renewal_seq: 2,
                expires_at_own_monotonic_ms: 600,
            })
        );
    }

    #[test]
    fn speculation_browns_out_before_foreground() {
        use rabs_action::state_machines::AttemptState;

        let (_state, coord) = submission_coordinator();
        let (_live, source, manifest, base_descriptor) = source_fixture();
        let worker = worker_offer(1, 1);
        coord.admit_worker_session(&worker).unwrap();
        let lease_ttl_ms = 60_000;

        let desc_with_tag = |tag: u8| {
            let mut d = base_descriptor.clone();
            d.normalized_invocation.bytes[0] = tag;
            d
        };

        // 1. Normal pressure: speculative S1 starts and finishes before pressure (saved).
        assert_eq!(
            coord
                .apply_speculation_pressure_permille(100, 600, 850)
                .unwrap(),
            PressureBand::Normal
        );
        let s1_desc = desc_with_tag(1);
        let s1 = coord
            .submit_action(
                submission(&source, &manifest, &s1_desc),
                request(1, SubscriberKind::Speculative, 10),
                1,
                0,
            )
            .unwrap();
        let mut s1_dispatch = coord.next_action_dispatch().unwrap().unwrap();
        let _s1_auth = s1_dispatch.begin(&worker, lease_ttl_ms).unwrap().clone();
        for state in [
            AttemptState::LeaseAccepted,
            AttemptState::AwaitingInputs,
            AttemptState::Materializing,
            AttemptState::Running,
            AttemptState::ProcessExited,
            AttemptState::Draining,
            AttemptState::Finished,
        ] {
            s1_dispatch.advance(state).unwrap();
        }
        s1_dispatch.complete().unwrap();

        // Start S2 (speculative, then joined by ForegroundAgent -> promoted) and S3 (low-value speculative).
        let s2_desc = desc_with_tag(2);
        let s2 = coord
            .submit_action(
                submission(&source, &manifest, &s2_desc),
                request(2, SubscriberKind::Speculative, 10),
                2,
                0,
            )
            .unwrap();
        let mut s2_dispatch = coord.next_action_dispatch().unwrap().unwrap();
        let _s2_auth = s2_dispatch.begin(&worker, lease_ttl_ms).unwrap().clone();
        for state in [
            AttemptState::LeaseAccepted,
            AttemptState::AwaitingInputs,
            AttemptState::Materializing,
            AttemptState::Running,
        ] {
            s2_dispatch.advance(state).unwrap();
        }
        // Foreground subscriber joins S2 while running -> suspends brownout on S2.
        let s2_fg = coord
            .submit_action(
                submission(&source, &manifest, &s2_desc),
                request(20, SubscriberKind::ForegroundAgent, 200),
                3,
                0,
            )
            .unwrap();
        assert!(!s2_fg.actor_created);

        let s3_desc = desc_with_tag(3);
        let s3 = coord
            .submit_action(
                submission(&source, &manifest, &s3_desc),
                request(3, SubscriberKind::Speculative, 10),
                4,
                0,
            )
            .unwrap();
        let mut s3_dispatch = coord.next_action_dispatch().unwrap().unwrap();
        let s3_auth = s3_dispatch.begin(&worker, lease_ttl_ms).unwrap().clone();
        s3_dispatch.advance(AttemptState::LeaseAccepted).unwrap();

        // 2. Soft pressure: new speculation stops admitting; running S3 survives; foreground admits.
        assert_eq!(
            coord
                .apply_speculation_pressure_permille(650, 600, 850)
                .unwrap(),
            PressureBand::Soft
        );
        let s4_desc = desc_with_tag(4);
        assert_eq!(
            coord
                .submit_action(
                    submission(&source, &manifest, &s4_desc),
                    request(4, SubscriberKind::Speculative, 10),
                    5,
                    0,
                )
                .unwrap_err(),
            SubmissionRefusal::Brownout
        );
        // Running S3 is NOT cancelled at Soft: it can still advance.
        s3_dispatch.advance(AttemptState::AwaitingInputs).unwrap();
        s3_dispatch.advance(AttemptState::Materializing).unwrap();
        s3_dispatch.advance(AttemptState::Running).unwrap();

        // Foreground F1 admits and starts under Soft pressure.
        let f1_desc = desc_with_tag(5);
        let f1 = coord
            .submit_action(
                submission(&source, &manifest, &f1_desc),
                request(5, SubscriberKind::ForegroundAgent, 200),
                6,
                0,
            )
            .unwrap();
        let mut f1_dispatch = coord.next_action_dispatch().unwrap().unwrap();
        assert_eq!(f1_dispatch.input().key(), f1.action_key);
        let _f1_auth = f1_dispatch.begin(&worker, lease_ttl_ms).unwrap().clone();
        for state in [
            AttemptState::LeaseAccepted,
            AttemptState::AwaitingInputs,
            AttemptState::Materializing,
            AttemptState::Running,
        ] {
            f1_dispatch.advance(state).unwrap();
        }

        // 3. Hard pressure: low-value running speculation S3 cancels and drains;
        //    promoted S2, foreground F1, and cleanup/integrity work remain unaffected.
        assert_eq!(
            coord
                .apply_speculation_pressure_permille(900, 600, 850)
                .unwrap(),
            PressureBand::Hard
        );
        assert!(
            coord
                .work_category_admitted(WorkCategory::Foreground)
                .unwrap()
        );
        assert!(coord.work_category_admitted(WorkCategory::Cleanup).unwrap());
        assert!(
            coord
                .work_category_admitted(WorkCategory::ObjectIntegrity)
                .unwrap()
        );

        // S3's attempt was transitioned to Draining, its generation closed and durably tombstoned.
        let s3_actor = coord.submitted_actor(&s3.action_key).unwrap().unwrap();
        assert!(s3_actor.active_generation().is_none());
        assert_eq!(
            s3_actor.attempts().next().unwrap().state,
            AttemptState::Draining
        );
        assert_eq!(
            s3_dispatch
                .advance(AttemptState::ProcessExited)
                .unwrap_err(),
            SubmissionRefusal::StaleDispatch
        );
        assert!(matches!(
            coord.renew_attempt_lease(
                &s3_auth,
                LeaseRenewal {
                    lease: s3_auth.execution_lease_id,
                    seq: LeaseRenewalSeq(1),
                },
                lease_ttl_ms,
            ),
            Err(AttemptLeaseRefusal::Store(StoreError::GenerationTombstoned))
        ));
        drop(s3_dispatch);

        // Promoted S2 and foreground F1 continue and complete cleanly under Hard pressure.
        for state in [
            AttemptState::ProcessExited,
            AttemptState::Draining,
            AttemptState::Finished,
        ] {
            s2_dispatch.advance(state).unwrap();
            f1_dispatch.advance(state).unwrap();
        }
        s2_dispatch.complete().unwrap();
        f1_dispatch.complete().unwrap();

        // Cleanup (`retire_finished_action`) succeeds under Hard pressure.
        assert!(coord.retire_finished_action(&s1.action_key).unwrap());
        assert!(coord.retire_finished_action(&s2.action_key).unwrap());
        assert!(coord.retire_finished_action(&f1.action_key).unwrap());

        // Provenance and Q009 ROI dashboard reflect exact runs (1 saved completed,
        // 1 promoted to foreground, 1 cancelled under pressure, 1 admission refused).
        let provenance = coord.speculation_provenance().unwrap();
        assert_eq!(
            provenance,
            SpeculationProvenance {
                wasted_cancelled: 1,
                saved_completed: 2,
                admissions_refused: 1,
            }
        );
        let roi = coord.speculation_roi_panel().unwrap();
        assert_eq!(roi.promoted, 1);
        assert_eq!(roi.cancelled, 1);
        assert_eq!(roi.wasted, 1);
        assert_eq!(roi.saved, 2);
        assert_eq!(roi.admissions_refused, 1);
        assert!(roi.saved_foreground_latency_ms >= 2);
        assert!(roi.wasted_execution_cost_ms >= 1);
        assert!(roi.wasted_transfer_cost_bytes > 0);
        assert!(roi.wasted_storage_cost_bytes > 0);

        // Q010: Default-on speculation ships DefaultOff and refuses automatic submission until
        // the gate evaluates positive ROI + improved foreground p95 + zero pressure regressions.
        coord
            .set_speculation_pressure(PressureBand::Normal)
            .unwrap();
        assert_eq!(
            coord.speculation_default_on_posture().unwrap(),
            SpeculationDefaultOnPosture::DefaultOff
        );
        let s6_desc = desc_with_tag(6);
        assert!(matches!(
            coord.submit_default_on_speculation(
                submission(&source, &manifest, &s6_desc),
                request(40, SubscriberKind::Speculative, 10),
                1_900_000,
                0,
            ),
            Err(SubmissionRefusal::Admission(reason)) if reason.contains("default-on speculation gated off")
        ));

        // Evaluate before foreground latency samples are recorded -> remains DefaultOff.
        let initial_gate = coord.evaluate_speculation_default_on_gate().unwrap();
        assert_eq!(
            initial_gate.posture,
            SpeculationDefaultOnPosture::DefaultOff
        );
        assert!(!initial_gate.permits_default_on());

        // Record baseline and speculative foreground latency samples showing strict p95 improvement.
        for ms in [420_u64, 510, 640] {
            coord.record_foreground_latency_sample(false, ms).unwrap();
        }
        for ms in [120_u64, 180, 240] {
            coord.record_foreground_latency_sample(true, ms).unwrap();
        }
        let passing_gate = coord.evaluate_speculation_default_on_gate().unwrap();
        assert_eq!(passing_gate.posture, SpeculationDefaultOnPosture::DefaultOn);
        assert!(passing_gate.permits_default_on());
        assert_eq!(passing_gate.decision_token(), "default-on-authorized");
        assert_eq!(
            coord.latest_speculation_default_on_decision().unwrap(),
            Some(passing_gate.clone())
        );

        // Default-on speculation submission is now permitted.
        let admitted_default_on = coord
            .submit_default_on_speculation(
                submission(&source, &manifest, &s6_desc),
                request(40, SubscriberKind::Speculative, 10),
                1_900_000,
                0,
            )
            .unwrap();
        assert!(admitted_default_on.actor_created);

        // Recording a pressure regression immediately demotes posture back to DefaultOff.
        coord.record_speculation_pressure_regression().unwrap();
        assert_eq!(
            coord.speculation_default_on_posture().unwrap(),
            SpeculationDefaultOnPosture::DefaultOff
        );
        let regressed_gate = coord.evaluate_speculation_default_on_gate().unwrap();
        assert_eq!(
            regressed_gate.posture,
            SpeculationDefaultOnPosture::DefaultOff
        );
        assert!(!regressed_gate.permits_default_on());
    }

    #[test]
    fn q007_git_prewarm_events_locate_ancestor_seed_workers_and_stop_under_foreground_pressure() {
        let (_state, coord) = submission_coordinator();
        let (_live, source, manifest, base_descriptor) = source_fixture();
        let worker_ok = worker_offer(1, 0x101);
        coord.admit_worker_session(&worker_ok).unwrap();

        let desc_with_tag = |tag: u8| {
            let mut d = base_descriptor.clone();
            d.normalized_invocation.bytes[0] = tag;
            d
        };

        let dep_desc = desc_with_tag(11);
        let ws_desc = desc_with_tag(12);
        let test_desc = desc_with_tag(13);
        let lockfile_digest = rabs_key::typed_digest::compute("rabs.lockfile.v1", b"Cargo.lock-v1");
        let toolchain_digest =
            rabs_key::typed_digest::compute("rabs.toolchain.v1", b"nightly-2026-06-06");

        // 1. Initial branch checkout warms dep, workspace, and canonical test subset.
        let checkout_receipt = coord
            .handle_git_prewarm_event(GitPrewarmEvent {
                event_id: "evt-checkout-1".to_owned(),
                kind: GitPrewarmEventKind::BranchCheckout,
                head_commit_oid: "commit-a1".to_owned(),
                parent_commit_oids: vec!["commit-root".to_owned()],
                worktree_id: "wt-main".to_owned(),
                lockfile_digest: lockfile_digest.clone(),
                toolchain_digest: toolchain_digest.clone(),
                dependency_critical_path: vec![submission(&source, &manifest, &dep_desc)],
                workspace_critical_path: vec![submission(&source, &manifest, &ws_desc)],
                canonical_test_subset: vec![submission(&source, &manifest, &test_desc)],
                likely_workers: vec![
                    worker_ok.worker_peer_id.clone(),
                    PeerId("unadmitted-worker".to_owned()),
                ],
                operation_base_id: 500,
                now_unix_micros: 10_000,
                clock_epoch: 0,
            })
            .unwrap();
        assert_eq!(checkout_receipt.nearest_ancestor_commit_oid, None);
        assert!(!checkout_receipt.stopped_under_foreground_pressure);
        assert_eq!(
            checkout_receipt.seeded_workers,
            vec![worker_ok.worker_peer_id.clone()]
        );
        assert!(matches!(
            checkout_receipt.dependency_actions.as_slice(),
            [PrewarmStageOutcome::QueuedPrewarm {
                actor_created: true,
                ..
            }]
        ));
        assert!(matches!(
            checkout_receipt.workspace_actions.as_slice(),
            [PrewarmStageOutcome::QueuedPrewarm {
                actor_created: true,
                ..
            }]
        ));
        assert!(matches!(
            checkout_receipt.canonical_test_actions.as_slice(),
            [PrewarmStageOutcome::QueuedPrewarm {
                actor_created: true,
                ..
            }]
        ));

        // 2. Child commit locates `commit-a1` as nearest warm ancestor: dep is AlreadyWarm, new ws2 queues.
        let ws2_desc = desc_with_tag(14);
        let head_change_receipt = coord
            .handle_git_prewarm_event(GitPrewarmEvent {
                event_id: "evt-head-2".to_owned(),
                kind: GitPrewarmEventKind::HeadChange,
                head_commit_oid: "commit-a2".to_owned(),
                parent_commit_oids: vec!["commit-a1".to_owned(), "commit-root".to_owned()],
                worktree_id: "wt-main".to_owned(),
                lockfile_digest: lockfile_digest.clone(),
                toolchain_digest: toolchain_digest.clone(),
                dependency_critical_path: vec![submission(&source, &manifest, &dep_desc)],
                workspace_critical_path: vec![submission(&source, &manifest, &ws2_desc)],
                canonical_test_subset: Vec::new(),
                likely_workers: vec![worker_ok.worker_peer_id.clone()],
                operation_base_id: 600,
                now_unix_micros: 20_000,
                clock_epoch: 0,
            })
            .unwrap();
        assert_eq!(
            head_change_receipt.nearest_ancestor_commit_oid.as_deref(),
            Some("commit-a1")
        );
        assert!(matches!(
            head_change_receipt.dependency_actions.as_slice(),
            [PrewarmStageOutcome::AlreadyWarm { .. }]
        ));
        assert!(matches!(
            head_change_receipt.workspace_actions.as_slice(),
            [PrewarmStageOutcome::QueuedPrewarm {
                actor_created: true,
                ..
            }]
        ));

        // 3. Submit a foreground action -> queued foreground demand causes subsequent prewarm to stop instantly.
        let fg_desc = desc_with_tag(15);
        coord
            .submit_action(
                submission(&source, &manifest, &fg_desc),
                request(700, SubscriberKind::ForegroundAgent, 200),
                25_000,
                0,
            )
            .unwrap();

        let ws3_desc = desc_with_tag(16);
        let pressured_receipt = coord
            .handle_git_prewarm_event(GitPrewarmEvent {
                event_id: "evt-worktree-3".to_owned(),
                kind: GitPrewarmEventKind::WorktreeCreation,
                head_commit_oid: "commit-a3".to_owned(),
                parent_commit_oids: vec!["commit-a2".to_owned()],
                worktree_id: "wt-feature".to_owned(),
                lockfile_digest,
                toolchain_digest,
                dependency_critical_path: Vec::new(),
                workspace_critical_path: vec![submission(&source, &manifest, &ws3_desc)],
                canonical_test_subset: Vec::new(),
                likely_workers: Vec::new(),
                operation_base_id: 800,
                now_unix_micros: 30_000,
                clock_epoch: 0,
            })
            .unwrap();
        assert!(pressured_receipt.stopped_under_foreground_pressure);
        assert!(matches!(
            pressured_receipt.workspace_actions.as_slice(),
            [PrewarmStageOutcome::StoppedUnderForegroundPressure { .. }]
        ));
        assert_eq!(coord.prewarm_receipts().unwrap().len(), 3);
    }

    #[test]
    fn q008_ci_canonical_prewarm_promotes_trust_tier_and_warms_developer_pulls() {
        use rabs_cas::test_support::{install_admission_world, install_offer_closure};
        use rabs_protocol::provenance_receipt::VerificationLevel;
        use rabs_protocol::serving::{
            CI_CANONICAL_WRITER_POLICY_SCHEMA_VERSION, CI_POLICY_CLAIM_SCHEMA_VERSION,
            CI_POLICY_CONTENT_DOMAIN, CI_POLICY_ID_DOMAIN, CI_SIGNER_FINGERPRINT_DOMAIN,
            CiActionKeyScope, CiClaimAuthenticator, CiLaneAuthorization, CiLaneRole,
            CiSignatureAlgorithm,
        };

        let (_state, coord) = submission_coordinator();
        let held = coord.authority().unwrap();
        let offer = offer_under(&held);
        let action_key = offer.manifest.action_key.clone();
        {
            let mut store = coord.cas.as_ref().unwrap().store().lock().unwrap();
            install_admission_world(&mut *store, &held);
            install_offer_closure(&mut *store, &offer);
        }
        assert!(matches!(
            coord
                .commit_offer(&offer, &sample_expected_descriptor())
                .unwrap(),
            PublicationOutcome::Committed(_)
        ));

        // 1. Local/initial publication is immediately useful for UnverifiedCandidate tier,
        //    but requires additional verification for CiPolicyApproved / release lanes.
        assert_eq!(
            coord
                .evaluate_trust_tier_access(&action_key, TrustEvidenceTier::UnverifiedCandidate)
                .unwrap(),
            TrustAccessDecision::Permitted {
                observed_tier: TrustEvidenceTier::UnverifiedCandidate,
                required_tier: TrustEvidenceTier::UnverifiedCandidate,
            }
        );
        assert_eq!(
            coord
                .evaluate_trust_tier_access(&action_key, TrustEvidenceTier::CiPolicyApproved)
                .unwrap(),
            TrustAccessDecision::NeedsAdditionalVerification {
                observed_tier: TrustEvidenceTier::UnverifiedCandidate,
                required_tier: TrustEvidenceTier::CiPolicyApproved,
            }
        );

        // 2. Build a signed S011 CI canonical writer policy + claim for the exact same action_key.
        let policy_id = rabs_key::typed_digest::compute(CI_POLICY_ID_DOMAIN, b"ci-main-policy");
        let signer_fp =
            rabs_key::typed_digest::compute(CI_SIGNER_FINGERPRINT_DOMAIN, b"ci-ed25519-key-1");
        let mut policy = CiCanonicalWriterPolicy {
            schema_version: CI_CANONICAL_WRITER_POLICY_SCHEMA_VERSION,
            policy_id: policy_id.clone(),
            policy_content_digest: rabs_key::typed_digest::compute(
                CI_POLICY_CONTENT_DOMAIN,
                b"placeholder",
            ),
            version: 1,
            revoked: false,
            authorizations: vec![CiLaneAuthorization {
                lane_id: "github-actions-main".to_owned(),
                signer_fingerprint: signer_fp.clone(),
                signer_generation: 1,
                signature_algorithm: CiSignatureAlgorithm::Ed25519V1,
                action_key_scope: CiActionKeyScope::Exact(action_key.clone()),
                role: CiLaneRole::Producer,
                minimum_verification: VerificationLevel::CoordinatorDigestRecompute,
                revoked: false,
            }],
        };
        policy.policy_content_digest =
            rabs_key::typed_digest::compute(CI_POLICY_CONTENT_DOMAIN, &policy.canonical_bytes());

        let (evidence_digest, high_water) = {
            let mut store = coord.cas.as_ref().unwrap().store().lock().unwrap();
            let keys = store.list_evidence_keys(&action_key).unwrap();
            let high_water = store
                .latest_trust_evaluation(&action_key)
                .unwrap()
                .map_or(0, |r| r.evaluated_seq);
            (evidence_set_digest(&keys), high_water)
        };

        let claim = CiCanonicalWriterClaim {
            schema_version: CI_POLICY_CLAIM_SCHEMA_VERSION,
            policy_version: 1,
            policy_id: policy_id.clone(),
            policy_content_digest: policy.policy_content_digest.clone(),
            lane_id: "github-actions-main".to_owned(),
            signer_fingerprint: signer_fp,
            signer_generation: 1,
            action_key: action_key.clone(),
            canonical_result_manifest_id: offer.manifest_id.clone(),
            evidence_set_digest: evidence_digest,
            role: CiLaneRole::Producer,
            verification: VerificationLevel::CoordinatorDigestRecompute,
            evaluated_causal_sequence: high_water + 10,
            authenticator: CiClaimAuthenticator {
                algorithm: CiSignatureAlgorithm::Ed25519V1,
                bytes: vec![0xAA; 64],
            },
        };

        let ci_receipt = coord
            .publish_ci_canonical_prewarm(
                "commit-ci-pushed-1",
                "release",
                &policy_id,
                std::slice::from_ref(&policy),
                &claim,
                VerificationLevel::CoordinatorDigestRecompute,
                |expected, canonical| {
                    *expected
                        == rabs_key::typed_digest::compute(CI_POLICY_CONTENT_DOMAIN, canonical)
                },
                |_alg, _fp, _gen, _body, sig| sig == [0xAA; 64],
            )
            .unwrap();
        assert_eq!(
            ci_receipt.assigned_tier,
            TrustEvidenceTier::CiPolicyApproved
        );
        assert_eq!(ci_receipt.action_key, action_key);

        // 3. After CI canonical writer promotion, CiPolicyApproved access is permitted on the same action_key.
        assert_eq!(
            coord
                .evaluate_trust_tier_access(&action_key, TrustEvidenceTier::CiPolicyApproved)
                .unwrap(),
            TrustAccessDecision::Permitted {
                observed_tier: TrustEvidenceTier::CiPolicyApproved,
                required_tier: TrustEvidenceTier::CiPolicyApproved,
            }
        );

        // 4. Developer pull (`PullRebaseMerge`) referencing `commit-ci-pushed-1` locates the CI prewarm state.
        let pull_receipt = coord
            .handle_git_prewarm_event(GitPrewarmEvent {
                event_id: "evt-dev-pull-1".to_owned(),
                kind: GitPrewarmEventKind::PullRebaseMerge,
                head_commit_oid: "commit-ci-pushed-1".to_owned(),
                parent_commit_oids: vec!["commit-ci-pushed-1".to_owned()],
                worktree_id: "wt-dev".to_owned(),
                lockfile_digest: rabs_key::typed_digest::compute("rabs.lockfile.v1", b"lock"),
                toolchain_digest: rabs_key::typed_digest::compute("rabs.toolchain.v1", b"tc"),
                dependency_critical_path: Vec::new(),
                workspace_critical_path: Vec::new(),
                canonical_test_subset: Vec::new(),
                likely_workers: Vec::new(),
                operation_base_id: 900,
                now_unix_micros: 50_000,
                clock_epoch: 0,
            })
            .unwrap();
        assert_eq!(
            pull_receipt.nearest_ancestor_commit_oid.as_deref(),
            Some("commit-ci-pushed-1")
        );
    }

    #[test]
    fn g005_q005_live_coord_promote_and_cancel_subscriber_drains_and_tombstones_last_interest() {
        let (_state, coord) = submission_coordinator();
        let coord = Arc::new(coord);
        let (_live, source, manifest, descriptor) = source_fixture();
        let worker = worker_offer(1, 0x101);
        coord.admit_worker_session(&worker).unwrap();

        let edge = coord.edge_subscriber();
        let sub1 = edge
            .submit_action(
                submission(&source, &manifest, &descriptor),
                request(701, SubscriberKind::Speculative, 120),
                1_000,
                0,
            )
            .unwrap();
        assert!(sub1.actor_created);
        let key = sub1.action_key.clone();

        // Promote speculative subscriber in place to Foreground without creating a new actor.
        assert_eq!(
            edge.promote_subscriber(&key, BuildOperationId(701), Some(80_000))
                .unwrap(),
            PromoteReceipt::Promoted
        );

        // Attach a second subscriber to the same action.
        let sub2 = edge
            .submit_action(
                submission(&source, &manifest, &descriptor),
                request(702, SubscriberKind::ForegroundAgent, 210),
                1_020,
                0,
            )
            .unwrap();
        assert!(!sub2.actor_created);

        // Claim and begin dispatch on the worker.
        let mut dispatch = coord.next_action_dispatch().unwrap().unwrap();
        let _authority = dispatch.begin(&worker, 60_000).unwrap().clone();

        // Cancel subscriber 701; subscriber 702 keeps the action and attempt alive.
        assert_eq!(
            edge.cancel_subscriber(&key, BuildOperationId(701)).unwrap(),
            CancelReceipt::SharedWorkContinues { retained: 1 }
        );
        let actor_mid = coord.submitted_actor(&key).unwrap().unwrap();
        assert!(actor_mid.active_generation().is_some());

        // Cancel the last subscriber 702; active generation drains and is tombstoned in the store.
        assert_eq!(
            edge.cancel_subscriber(&key, BuildOperationId(702)).unwrap(),
            CancelReceipt::LastInterestCancelledGeneration
        );
        let actor_after = coord.submitted_actor(&key).unwrap().unwrap();
        assert!(actor_after.active_generation().is_none());
        assert_eq!(
            actor_after.slot(),
            rabs_action::state_machines::PublicationSlotState::Absent
        );
    }

    #[test]
    fn bd_d4uqa_live_cargo_root_broker_fifteen_agent_storm_bounds_roots_and_starvation_with_receipts()
     {
        let (_state, coord) = submission_coordinator();
        let starvation_bound = 64_u64;
        let max_roots = 4_u32;
        let per_root_capacity = 4_u32;
        coord
            .configure_cargo_root_broker(max_roots, per_root_capacity, starvation_bound, 16)
            .unwrap();

        let tenants: Vec<TenantKey> = (0..15)
            .map(|i| TenantKey {
                agent: format!("agent-{i:02}"),
                project: format!("repo-{i:02}"),
                ci: i % 5 == 0,
            })
            .collect();
        // Give agent-00 a higher weight (4) to verify weighted fairness in live coordinator service order.
        coord
            .set_cargo_root_tenant_weight(tenants[0].clone(), 4)
            .unwrap();

        // Schedule 15 agents x 6 Cargo roots = 90 roots across staggered ticks.
        let mut arrivals: BTreeMap<u64, Vec<(usize, String)>> = BTreeMap::new();
        for (j, tenant) in tenants.iter().enumerate() {
            for round in 0..6_u64 {
                let tick = round * 30 + (j as u64) * 2;
                arrivals
                    .entry(tick)
                    .or_default()
                    .push((j, format!("{}/cargo-root-{round}", tenant.agent)));
            }
        }

        let total_expected = 90_usize;
        let mut active_queue: std::collections::VecDeque<(String, u64)> =
            std::collections::VecDeque::new();
        let mut completed = 0_usize;
        let mut tick = 0_u64;

        while completed < total_expected {
            // Complete any active root whose 3-tick compile window finished.
            while let Some((front_id, finish_tick)) = active_queue.front().cloned() {
                if tick >= finish_tick {
                    active_queue.pop_front();
                    let comp = coord.complete_cargo_root(&front_id, tick).unwrap();
                    assert!(comp.active_cargo_roots < max_roots);
                    completed += 1;
                } else {
                    break;
                }
            }

            if let Some(batch) = arrivals.remove(&tick) {
                for (j, root_id) in batch {
                    coord
                        .enqueue_cargo_root_request(tenants[j].clone(), &root_id, 100, tick, None)
                        .unwrap();
                }
            }

            // Attempt to admit up to max_roots + 1 times to exercise both normal grants and the T016 cap refusal.
            for _ in 0..=max_roots {
                if let Some(grant_receipt) = coord.admit_next_cargo_root(tick).unwrap() {
                    assert!(
                        grant_receipt.active_cargo_roots <= max_roots,
                        "T016: active Cargo roots must never exceed granted ceiling"
                    );
                    assert_eq!(grant_receipt.capacity, per_root_capacity);

                    // Exercise C-1 transferable jobserver tokens on the live root.
                    let tok1 = coord
                        .issue_cargo_jobserver_token(&grant_receipt.root_id)
                        .unwrap()
                        .unwrap();
                    let tok2 = coord
                        .issue_cargo_jobserver_token(&grant_receipt.root_id)
                        .unwrap()
                        .unwrap();
                    let tok3 = coord
                        .issue_cargo_jobserver_token(&grant_receipt.root_id)
                        .unwrap()
                        .unwrap();
                    // 4th transferable token on capacity=4 must be refused as TransferablesExhausted.
                    assert_eq!(
                        coord
                            .issue_cargo_jobserver_token(&grant_receipt.root_id)
                            .unwrap(),
                        Err(GrantRefusal::TransferablesExhausted {
                            outstanding: 3,
                            capacity: 4
                        })
                    );
                    coord
                        .release_cargo_jobserver_token(&grant_receipt.root_id, &tok1)
                        .unwrap()
                        .unwrap();
                    coord
                        .release_cargo_jobserver_token(&grant_receipt.root_id, &tok2)
                        .unwrap()
                        .unwrap();
                    coord
                        .release_cargo_jobserver_token(&grant_receipt.root_id, &tok3)
                        .unwrap()
                        .unwrap();

                    active_queue.push_back((grant_receipt.root_id, tick + 3));
                } else {
                    break;
                }
            }

            tick += 1;
        }

        let telemetry = coord.cargo_root_broker_telemetry().unwrap();
        assert_eq!(telemetry.total_enqueued, 90);
        assert_eq!(telemetry.total_granted, 90);
        assert_eq!(telemetry.total_completed, 90);
        assert_eq!(telemetry.active_cargo_roots, 0);
        assert!(telemetry.peak_active_cargo_roots <= max_roots);
        assert!(telemetry.peak_active_cargo_roots > 1);
        assert_eq!(
            telemetry.starvation_violations, 0,
            "no starvation beyond policy bound ({starvation_bound} ticks): {:?}",
            telemetry.worst_lag_by_agent
        );

        // Verify durable telemetry receipts in SQLite `decision_receipts`.
        let mut store = coord.cas.as_ref().unwrap().store().lock().unwrap();
        let rows = store
            .query(
                "SELECT decision FROM decision_receipts WHERE kind = ?1",
                &[SqlValue::Text(CARGO_ROOT_BROKER_RECEIPT_KIND.to_owned())],
            )
            .unwrap();
        let enqueued_receipts = rows
            .iter()
            .filter(|r| matches!(r.as_slice(), [SqlValue::Text(d)] if d == "enqueued"))
            .count();
        let granted_receipts = rows
            .iter()
            .filter(|r| matches!(r.as_slice(), [SqlValue::Text(d)] if d == "root_granted"))
            .count();
        let completed_receipts = rows
            .iter()
            .filter(|r| matches!(r.as_slice(), [SqlValue::Text(d)] if d == "root_completed"))
            .count();
        assert_eq!(enqueued_receipts, 90);
        assert_eq!(granted_receipts, 90);
        assert_eq!(completed_receipts, 90);
    }
}
