//! Explicit Cargo fetch/resolution capture and offline canonical replay
//! (bead E025; plan §82.1; risk R76).
//!
//! This is an EDGE-OWNED, nonpublishing phase. It never becomes an ordinary
//! schedulable/cacheable action: a bounded broker may acquire missing bytes,
//! the edge verifies and seals their immutable object closure, and only then
//! may compilation run from a fresh operation-owned Cargo home in a closed
//! canonical namespace. The user's Cargo argv is carried as raw bytes and is
//! never amended with `--locked`, `--offline`, `--frozen`, or any other flag.
//!
//! E026 owns workspace mutation replay. This first authoritative slice
//! therefore requires an existing lockfile to remain byte-identical through
//! resolution; a missing or changed lockfile downgrades/refuses coherently.

use crate::edge::snapshot_lineage::{
    LineageError, RequestedCommandSnapshot, ResolvedExecutionSnapshot, SnapshotLineage,
};
use rabs_cas::dependency_snapshot::{DependencySourceManifest, SnapshotError};
use rabs_key::canonical::CanonicalEncoder;
use rabs_key::cargo_config_provenance::DOMAIN_CARGO_CONFIG_PROVENANCE;
use rabs_key::toolchain::DOMAIN_TOOLCHAIN_CONTRACT;
use rabs_key::typed_digest::compute;
use rabs_protocol::capability_tokens::CapabilityToken;
use rabs_protocol::input_evidence::{
    ActionInputManifest, EnforcementState, INPUT_EVIDENCE_SCHEMA_VERSION, IsolationEvidenceRecord,
};
use rabs_protocol::object_model::ObjectKind;
use rabs_protocol::raw_bytes::RawBytes;
use rabs_protocol::result_identity::{DigestAlgorithm, ObjectId, TypedDigest};
use rabs_sandbox::canonical_mounts::{CanonicalMountPlan, MountPlanError};
use rabs_sandbox::canonical_namespace::CanonicalNamespaceSpec;
use rabs_sandbox::network_isolation::{
    BoundedNetworkPolicy, BoundedNetworkReceipt, NetworkGateRefusal, NetworkGrant,
    evaluate_open_network,
};
use std::collections::HashSet;
use std::path::{Path, PathBuf};

/// Version of the capture/validation record.
pub const CARGO_RESOLUTION_SCHEMA_VERSION: u32 = 1;
/// Digest of the exact original Cargo program and argv.
pub const DOMAIN_CARGO_INVOCATION: &str = "rabs.cargo-invocation.sha256.v1";
/// Digest of the semantic captured resolution closure.
pub const DOMAIN_CARGO_RESOLUTION: &str = "rabs.cargo-resolution.sha256.v1";
/// Authoritative content-addressed object domain.
pub const ATP_OBJECT_CONTENT_DOMAIN: &str = "rabs.object.sha256.v1";

const MAX_INVOCATION_ARGS: usize = 4_096;
const MAX_INVOCATION_BYTES: usize = 1024 * 1024;

/// Exact original Cargo invocation. Raw bytes preserve non-UTF8 Unix argv;
/// `effective_config_offline` is the already-resolved K015/config/env fact
/// for `net.offline=true` or `CARGO_NET_OFFLINE=true`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CargoInvocation {
    /// Program bytes (`cargo` or an exact path whose basename is `cargo`).
    pub program: RawBytes,
    /// Original argument vector, in order.
    pub args: Vec<RawBytes>,
    /// Effective Cargo config forbids network independently of argv.
    pub effective_config_offline: bool,
}

impl CargoInvocation {
    /// Validate the bounded exact invocation.
    ///
    /// # Errors
    /// [`CargoResolutionRefusal::InvalidInvocation`] for a non-Cargo,
    /// empty, NUL-bearing, or unbounded invocation.
    pub fn validate(&self) -> Result<(), CargoResolutionRefusal> {
        let program = self.program.as_bytes();
        let basename = program
            .rsplit(|byte| *byte == b'/')
            .next()
            .unwrap_or(program);
        if basename != b"cargo" || program.contains(&0) {
            return Err(CargoResolutionRefusal::InvalidInvocation(
                "program must be an exact NUL-free cargo path".into(),
            ));
        }
        if self.args.len() > MAX_INVOCATION_ARGS {
            return Err(CargoResolutionRefusal::InvalidInvocation(
                "argument count exceeds E025 bound".into(),
            ));
        }
        let mut total = program.len();
        for arg in &self.args {
            if arg.as_bytes().contains(&0) {
                return Err(CargoResolutionRefusal::InvalidInvocation(
                    "Cargo argv contains NUL".into(),
                ));
            }
            total = total.checked_add(arg.len()).ok_or_else(|| {
                CargoResolutionRefusal::InvalidInvocation("argument bytes overflow".into())
            })?;
        }
        if total > MAX_INVOCATION_BYTES {
            return Err(CargoResolutionRefusal::InvalidInvocation(
                "argument bytes exceed E025 bound".into(),
            ));
        }
        Ok(())
    }

    /// Whether exact user/config semantics prohibit a fetch.
    #[must_use]
    pub fn forbids_network(&self) -> bool {
        if self.effective_config_offline {
            return true;
        }
        let mut index = 0;
        while index < self.args.len() {
            let arg = self.args[index].as_bytes();
            if matches!(arg, b"--offline" | b"--frozen") {
                return true;
            }
            if let Some(value) = arg.strip_prefix(b"--config=") {
                if config_sets_offline(value) {
                    return true;
                }
            }
            if arg == b"--config"
                && self
                    .args
                    .get(index + 1)
                    .is_some_and(|value| config_sets_offline(value.as_bytes()))
            {
                return true;
            }
            index += 1;
        }
        false
    }

    /// Typed digest of the exact original invocation and effective offline
    /// fact. No rewritten/executed argv exists in this record.
    #[must_use]
    pub fn digest(&self) -> TypedDigest {
        let mut encoder = CanonicalEncoder::new();
        encoder
            .u32(CARGO_RESOLUTION_SCHEMA_VERSION)
            .bytes(self.program.as_bytes())
            .seq(&self.args, |encoder, arg| {
                encoder.bytes(arg.as_bytes());
            })
            .bool(self.effective_config_offline);
        compute(DOMAIN_CARGO_INVOCATION, &encoder.finish())
    }
}

/// Whether immutable captured inputs already satisfy Cargo resolution.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CargoFetchNeed {
    /// Complete declared CAS closure: no capability is evaluated/exercised.
    CapturedClosureComplete,
    /// Missing bytes require the explicit brokered phase.
    NetworkRequired,
}

/// Result of authorization. This is authority to use a BOUNDED broker, not
/// authority to share the host network with Cargo.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CargoFetchAuthorization {
    /// No fetch and no capability use.
    CapturedClosure,
    /// Exact grant/policy pair to pass to `prepare_brokered_fetch`.
    Brokered {
        /// Validated session/operation/lease-bound grant.
        grant: NetworkGrant,
        /// Exact endpoint/request/redirect/byte declaration.
        policy: BoundedNetworkPolicy,
    },
}

/// Authorize the fetch decision without executing or mutating anything.
/// User offline/frozen semantics take precedence over capability lookup.
///
/// # Errors
/// Typed fail-closed refusal. Network need without authority always includes
/// a human-actionable explanation.
pub fn authorize_fetch_resolution(
    invocation: &CargoInvocation,
    need: CargoFetchNeed,
    policy: Option<BoundedNetworkPolicy>,
    tokens: &[CapabilityToken],
    revoked_token_ids: &[u64],
    current_seq: u64,
    session_id: u64,
    operation_id: u64,
) -> Result<CargoFetchAuthorization, CargoResolutionRefusal> {
    invocation.validate()?;
    if need == CargoFetchNeed::CapturedClosureComplete {
        return Ok(CargoFetchAuthorization::CapturedClosure);
    }
    if invocation.forbids_network() {
        return Err(CargoResolutionRefusal::UserForbidsNetwork {
            explanation: "Cargo --offline/--frozen or effective net.offline=true forbids the fetch phase",
        });
    }
    let policy = policy.ok_or(CargoResolutionRefusal::NetworkCapabilityRequired {
        explanation: "Cargo resolution needs uncaptured registry/git/index bytes, but no bounded fetch policy was declared",
    })?;
    let grant = evaluate_open_network(
        tokens,
        revoked_token_ids,
        current_seq,
        session_id,
        operation_id,
    )
    .map_err(map_network_refusal)?;
    let expected = policy.scope_binding();
    if grant.scope() != expected {
        return Err(CargoResolutionRefusal::NetworkScopeMismatch {
            expected,
            presented: grant.scope().to_owned(),
        });
    }
    Ok(CargoFetchAuthorization::Brokered { grant, policy })
}

/// Semantic role of one immutable object captured for offline Cargo.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CargoCapturedRole {
    /// Exact resolved `Cargo.lock` bytes.
    ResolvedLockfile,
    /// Credential-free materialized effective Cargo configuration.
    EffectiveConfig,
    /// Exact resolved package/source selection record.
    SourceSelection,
    /// Registry `config.json`.
    RegistryIndexConfig,
    /// Consulted registry/sparse-index entry body.
    RegistryIndexEntry,
    /// Checksummed `.crate` archive.
    RegistryArchive,
    /// Verified unpacked registry source tree.
    RegistrySourceTree,
    /// Exact Git database objects needed by the locked revision.
    GitDatabase,
    /// Verified checkout tree at the exact locked revision.
    GitCheckout,
    /// Path-source immutable snapshot.
    PathSource,
    /// Canonical manifest proving a registry/git source tree's members.
    DependencySourceManifest,
}

impl CargoCapturedRole {
    const fn tag(self) -> u32 {
        match self {
            Self::ResolvedLockfile => 1,
            Self::EffectiveConfig => 2,
            Self::SourceSelection => 3,
            Self::RegistryIndexConfig => 4,
            Self::RegistryIndexEntry => 5,
            Self::RegistryArchive => 6,
            Self::RegistrySourceTree => 7,
            Self::GitDatabase => 8,
            Self::GitCheckout => 9,
            Self::PathSource => 10,
            Self::DependencySourceManifest => 11,
        }
    }

    const fn is_source_tree(self) -> bool {
        matches!(self, Self::RegistrySourceTree | Self::GitCheckout)
    }
}

/// One captured immutable input with its canonical visible path and exact
/// Cargo source identity. Physical CAS/materialization paths are absent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CapturedCargoObject {
    /// Semantic role.
    pub role: CargoCapturedRole,
    /// Canonical virtual path in the resolution/offline view.
    pub virtual_path: RawBytes,
    /// Authoritative object identity.
    pub object: ObjectId,
    /// Object kind needed by the materializer.
    pub object_kind: ObjectKind,
    /// Bounded logical object size.
    pub content_length: u64,
    /// Exact Cargo source/package/registry identity, or a fixed role label.
    pub source_identity: RawBytes,
    /// Cargo checksum or exact Git revision where applicable.
    pub resolved_checksum: Option<RawBytes>,
}

/// Existing lockfile state at the requested snapshot. Absence is explicit;
/// E025 refuses that case until E026 can replay Cargo's mutation safely.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InitialLockfile {
    /// No lockfile existed.
    Absent,
    /// Exact initial lockfile object.
    Present(ObjectId),
}

/// Bounds on one captured Cargo closure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CargoCaptureLimits {
    /// Maximum number of captured objects.
    pub max_objects: u32,
    /// Maximum aggregate logical bytes.
    pub max_total_bytes: u64,
}

/// Verification link from a captured registry/git source tree to K002's
/// member manifest and Cargo's own checksum/revision.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedDependencySource {
    /// Captured source tree object.
    pub source_tree: ObjectId,
    /// Captured canonical manifest object.
    pub manifest_object: ObjectId,
    /// What Cargo resolved (lockfile checksum or exact Git revision).
    pub resolved_checksum: String,
    /// K002 member manifest.
    pub manifest: DependencySourceManifest,
}

/// Redaction-safe evidence from the nonpublishing fetch attempt. Token and
/// timing facts remain evidence; only captured content enters resolution
/// identity.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CargoFetchReceipt {
    /// Bounds and trusted broker mechanism actually installed.
    pub network: BoundedNetworkReceipt,
    /// Requests issued, redirects included.
    pub requests: u32,
    /// Accepted response-body bytes.
    pub response_bytes: u64,
    /// Immutable objects captured by the fetch.
    pub captured_objects: u32,
    /// Logical bytes of captured objects.
    pub captured_bytes: u64,
    /// True only after all staging objects verified atomically.
    pub completed_and_verified: bool,
    /// Stored receipt object; linked as evidence but excluded from the
    /// semantic resolution digest.
    pub receipt_object: ObjectId,
}

/// Complete immutable result of fetch/resolution before offline validation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CargoResolutionCapture {
    /// Schema version.
    pub schema_version: u32,
    /// Operation whose private resolution overlay produced this capture.
    pub operation_id: u64,
    /// D032 requested snapshot digest.
    pub requested_snapshot_sha256: [u8; 32],
    /// Original unmodified invocation.
    pub invocation: CargoInvocation,
    /// F007 toolchain contract.
    pub toolchain_contract: TypedDigest,
    /// K015 effective-config provenance.
    pub config_provenance: TypedDigest,
    /// Initial lockfile state.
    pub initial_lockfile: InitialLockfile,
    /// Canonically sorted immutable closure.
    pub objects: Vec<CapturedCargoObject>,
    /// CAS closure/dataset root for the fresh Cargo-home materialization.
    pub closure_root: ObjectId,
    /// K002 source-tree verification links.
    pub verified_sources: Vec<VerifiedDependencySource>,
    /// Separate fetch evidence when acquisition was necessary.
    pub fetch_receipt: Option<CargoFetchReceipt>,
}

/// Trusted materializer attestation for one fresh, operation-owned Cargo
/// home. `backing` is attempt-local placement and never enters identity.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CargoHomeMaterialization {
    /// Owning operation.
    pub operation_id: u64,
    /// Fresh nonzero materialization generation/nonce.
    pub generation: u64,
    /// Physical backing, mounted at canonical `/__rabs/cargo-home`.
    pub backing: PathBuf,
    /// Closure materialized into this home.
    pub closure_root: ObjectId,
    /// Exact objects placed under Cargo home, canonical order.
    pub materialized_objects: Vec<ObjectId>,
    /// Materializer observed the backing absent/empty before population.
    pub started_empty: bool,
}

/// Result of running Cargo's resolution validation in that fresh home with
/// physical egress denied.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OfflineValidationEvidence {
    /// Closure used by the validation run.
    pub closure_root: ObjectId,
    /// Lockfile Cargo observed/reproduced.
    pub reproduced_lockfile: ObjectId,
    /// Package/source selection Cargo reproduced.
    pub reproduced_source_selection: ObjectId,
    /// Actual sandbox controls from the validation launch.
    pub isolation: IsolationEvidenceRecord,
}

/// Versioned sealed record. Fetch receipt identity is linked for audit but
/// excluded from `resolution_digest`, so token ids/timing cannot fragment
/// two byte-identical resolutions.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CargoResolutionRecord {
    /// Schema version.
    pub schema_version: u32,
    /// Semantic digest fed into D032's resolved snapshot generation.
    pub resolution_digest: TypedDigest,
    /// Exact invocation digest.
    pub invocation_digest: TypedDigest,
    /// Closure root.
    pub closure_root: ObjectId,
    /// Optional attempt-evidence link.
    pub fetch_receipt_object: Option<ObjectId>,
}

/// Canonical build plan after successful fresh-home offline validation.
/// Fields that could be mutated into an ambient build stay private.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OfflineCanonicalPlan {
    invocation: CargoInvocation,
    mount_plan: CanonicalMountPlan,
    input_manifest: ActionInputManifest,
    sealed: ResolvedExecutionSnapshot,
    record: CargoResolutionRecord,
}

impl OfflineCanonicalPlan {
    /// Original byte-exact Cargo invocation.
    #[must_use]
    pub const fn invocation(&self) -> &CargoInvocation {
        &self.invocation
    }

    /// Explicit positive inputs for downstream minimal-closure derivation.
    #[must_use]
    pub const fn input_manifest(&self) -> &ActionInputManifest {
        &self.input_manifest
    }

    /// Sealed D032 generation.
    #[must_use]
    pub const fn sealed(&self) -> ResolvedExecutionSnapshot {
        self.sealed
    }

    /// Versioned resolution record.
    #[must_use]
    pub const fn record(&self) -> &CargoResolutionRecord {
        &self.record
    }

    /// Compile the immutable, network-denied canonical namespace spec.
    ///
    /// # Errors
    /// Typed mount-plan validation error.
    pub fn namespace_spec(&self) -> Result<CanonicalNamespaceSpec, MountPlanError> {
        self.mount_plan.to_spec()
    }
}

/// Typed E025 refusal. Every arm is fail-closed for authoritative execution;
/// a higher-level pre-frontier nonpublishing fallback may still run the
/// ORIGINAL command if its policy independently permits that.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CargoResolutionRefusal {
    /// Malformed or unbounded original invocation.
    InvalidInvocation(String),
    /// User/config semantics prohibit any fetch.
    UserForbidsNetwork {
        /// Actionable explanation.
        explanation: &'static str,
    },
    /// Missing declared policy or `OpenNetwork` capability.
    NetworkCapabilityRequired {
        /// Actionable explanation.
        explanation: &'static str,
    },
    /// Token failed context/lease/revocation/ambiguity checks.
    NetworkCapabilityRejected(String),
    /// Token scope does not bind the exact bounded policy.
    NetworkScopeMismatch {
        /// Expected binding.
        expected: String,
        /// Presented binding.
        presented: String,
    },
    /// Capture schema/order/domain/bounds failure.
    InvalidCapture(String),
    /// Missing/changed lockfile needs E026's private-overlay replay lane.
    WorkspaceMutationRequiresE026,
    /// K002 source checksum/member verification failed.
    DependencySourceInvalid(String),
    /// Captured manifest object does not name the canonical member record.
    DependencyManifestObjectMismatch,
    /// Materialization was not a fresh exact rendering of the closure.
    InvalidCargoHomeMaterialization(String),
    /// Closed offline validation did not reproduce the captured resolution.
    OfflineValidationFailed(String),
    /// Capture belongs to another requested snapshot.
    RequestedSnapshotMismatch,
    /// D032 refused the seal.
    SnapshotLineage(String),
}

/// Validate capture + fresh-home replay, seal D032, and construct the
/// network-denied canonical plan. No action may register before this call
/// succeeds.
///
/// # Errors
/// [`CargoResolutionRefusal`] for any policy, integrity, materialization,
/// offline replay, or lineage failure.
#[allow(clippy::too_many_arguments)]
pub fn seal_offline_resolution(
    lineage: &mut SnapshotLineage,
    capture: &CargoResolutionCapture,
    limits: CargoCaptureLimits,
    materialization: &CargoHomeMaterialization,
    validation: &OfflineValidationEvidence,
    toolchain_backing: impl Into<PathBuf>,
    workspace_backing: impl Into<PathBuf>,
    home_backing: impl Into<PathBuf>,
) -> Result<OfflineCanonicalPlan, CargoResolutionRefusal> {
    capture.validate(limits)?;
    if lineage.requested().manifest_sha256 != capture.requested_snapshot_sha256 {
        return Err(CargoResolutionRefusal::RequestedSnapshotMismatch);
    }
    validate_materialization(capture, materialization)?;
    validate_offline_evidence(capture, validation)?;

    let resolution_digest = capture.resolution_digest();
    let sealed = lineage
        .seal(resolution_digest.bytes)
        .map_err(|error| CargoResolutionRefusal::SnapshotLineage(format!("{error:?}")))?;

    let mut approved: Vec<ObjectId> = capture
        .objects
        .iter()
        .map(|entry| entry.object.clone())
        .collect();
    approved.push(capture.closure_root.clone());
    canonicalize_object_ids(&mut approved)?;
    let input_manifest = ActionInputManifest {
        schema_version: INPUT_EVIDENCE_SCHEMA_VERSION,
        approved_generated_objects: approved,
        ..ActionInputManifest::default()
    };
    let mount_plan = CanonicalMountPlan::new(
        toolchain_backing,
        workspace_backing,
        &materialization.backing,
        home_backing,
    );
    let record = CargoResolutionRecord {
        schema_version: CARGO_RESOLUTION_SCHEMA_VERSION,
        resolution_digest,
        invocation_digest: capture.invocation.digest(),
        closure_root: capture.closure_root.clone(),
        fetch_receipt_object: capture
            .fetch_receipt
            .as_ref()
            .map(|receipt| receipt.receipt_object.clone()),
    };
    Ok(OfflineCanonicalPlan {
        invocation: capture.invocation.clone(),
        mount_plan,
        input_manifest,
        sealed,
        record,
    })
}

impl CargoResolutionCapture {
    fn validate(&self, limits: CargoCaptureLimits) -> Result<(), CargoResolutionRefusal> {
        if self.schema_version != CARGO_RESOLUTION_SCHEMA_VERSION {
            return Err(CargoResolutionRefusal::InvalidCapture(
                "unsupported schema version".into(),
            ));
        }
        if self.operation_id == 0 || limits.max_objects == 0 || limits.max_total_bytes == 0 {
            return Err(CargoResolutionRefusal::InvalidCapture(
                "operation and capture bounds must be nonzero".into(),
            ));
        }
        self.invocation.validate()?;
        require_digest_domain(
            &self.toolchain_contract,
            DOMAIN_TOOLCHAIN_CONTRACT,
            "toolchain",
        )?;
        require_digest_domain(
            &self.config_provenance,
            DOMAIN_CARGO_CONFIG_PROVENANCE,
            "effective Cargo config",
        )?;
        require_object(&self.closure_root, "closure root")?;
        if self.objects.is_empty() || self.objects.len() > limits.max_objects as usize {
            return Err(CargoResolutionRefusal::InvalidCapture(
                "captured object count is empty or over bound".into(),
            ));
        }
        let mut total = 0u64;
        let mut previous_key: Option<(u32, Vec<u8>, Vec<u8>)> = None;
        let mut paths = HashSet::new();
        for entry in &self.objects {
            require_object(&entry.object, "captured object")?;
            validate_virtual_path(entry.virtual_path.as_bytes())?;
            if entry.source_identity.is_empty() {
                return Err(CargoResolutionRefusal::InvalidCapture(
                    "captured object source identity is empty".into(),
                ));
            }
            if entry.role.is_source_tree()
                && entry
                    .resolved_checksum
                    .as_ref()
                    .is_none_or(RawBytes::is_empty)
            {
                return Err(CargoResolutionRefusal::InvalidCapture(
                    "source tree lacks Cargo checksum/revision".into(),
                ));
            }
            total = total.checked_add(entry.content_length).ok_or_else(|| {
                CargoResolutionRefusal::InvalidCapture("captured bytes overflow".into())
            })?;
            let key = (
                entry.role.tag(),
                entry.virtual_path.as_bytes().to_vec(),
                entry.source_identity.as_bytes().to_vec(),
            );
            if previous_key
                .as_ref()
                .is_some_and(|previous| previous >= &key)
            {
                return Err(CargoResolutionRefusal::InvalidCapture(
                    "captured objects are not in strict canonical order".into(),
                ));
            }
            previous_key = Some(key);
            if !paths.insert(entry.virtual_path.as_bytes().to_vec()) {
                return Err(CargoResolutionRefusal::InvalidCapture(
                    "duplicate captured virtual path".into(),
                ));
            }
        }
        if total > limits.max_total_bytes {
            return Err(CargoResolutionRefusal::InvalidCapture(
                "captured bytes exceed bound".into(),
            ));
        }
        for role in [
            CargoCapturedRole::ResolvedLockfile,
            CargoCapturedRole::EffectiveConfig,
            CargoCapturedRole::SourceSelection,
        ] {
            if self
                .objects
                .iter()
                .filter(|entry| entry.role == role)
                .count()
                != 1
            {
                return Err(CargoResolutionRefusal::InvalidCapture(format!(
                    "capture requires exactly one {role:?} object"
                )));
            }
        }
        let resolved_lockfile = self.required_object(CargoCapturedRole::ResolvedLockfile)?;
        match &self.initial_lockfile {
            InitialLockfile::Present(initial) if initial == resolved_lockfile => {}
            InitialLockfile::Absent | InitialLockfile::Present(_) => {
                return Err(CargoResolutionRefusal::WorkspaceMutationRequiresE026);
            }
        }
        self.validate_fetch_receipt(limits)?;
        self.validate_sources()?;
        Ok(())
    }

    fn validate_fetch_receipt(
        &self,
        limits: CargoCaptureLimits,
    ) -> Result<(), CargoResolutionRefusal> {
        let Some(receipt) = &self.fetch_receipt else {
            return Ok(());
        };
        if self.invocation.forbids_network() {
            return Err(CargoResolutionRefusal::InvalidCapture(
                "offline/frozen invocation cannot carry fetch evidence".into(),
            ));
        }
        require_object(&receipt.receipt_object, "fetch receipt")?;
        let budget = receipt.network.budget;
        if !receipt.completed_and_verified
            || receipt.requests > budget.max_requests
            || receipt.response_bytes > budget.max_response_bytes
            || receipt.captured_objects > limits.max_objects
            || receipt.captured_bytes > limits.max_total_bytes
        {
            return Err(CargoResolutionRefusal::InvalidCapture(
                "fetch receipt is incomplete or exceeds declared bounds".into(),
            ));
        }
        Ok(())
    }

    fn validate_sources(&self) -> Result<(), CargoResolutionRefusal> {
        let trees: Vec<&CapturedCargoObject> = self
            .objects
            .iter()
            .filter(|entry| entry.role.is_source_tree())
            .collect();
        if trees.len() != self.verified_sources.len() {
            return Err(CargoResolutionRefusal::InvalidCapture(
                "every source tree requires exactly one verification manifest".into(),
            ));
        }
        let mut seen = HashSet::new();
        for verification in &self.verified_sources {
            require_object(&verification.source_tree, "verified source tree")?;
            require_object(&verification.manifest_object, "dependency manifest")?;
            if !seen.insert(object_key(&verification.source_tree)) {
                return Err(CargoResolutionRefusal::InvalidCapture(
                    "duplicate source-tree verification".into(),
                ));
            }
            let tree = trees
                .iter()
                .find(|tree| tree.object == verification.source_tree)
                .ok_or_else(|| {
                    CargoResolutionRefusal::InvalidCapture(
                        "verification names an uncaptured source tree".into(),
                    )
                })?;
            verification
                .manifest
                .validate(&verification.resolved_checksum)
                .map_err(|error| source_error(&error))?;
            validate_dependency_members(&verification.manifest)?;
            if tree.resolved_checksum.as_ref().map(RawBytes::as_bytes)
                != Some(verification.resolved_checksum.as_bytes())
            {
                return Err(CargoResolutionRefusal::DependencySourceInvalid(
                    "captured tree checksum differs from Cargo resolution".into(),
                ));
            }
            let expected_manifest = dependency_manifest_object(&verification.manifest);
            if verification.manifest_object != expected_manifest {
                return Err(CargoResolutionRefusal::DependencyManifestObjectMismatch);
            }
            let captured_manifest = self.objects.iter().any(|entry| {
                entry.role == CargoCapturedRole::DependencySourceManifest
                    && entry.object == verification.manifest_object
            });
            if !captured_manifest {
                return Err(CargoResolutionRefusal::InvalidCapture(
                    "verified dependency manifest is absent from capture".into(),
                ));
            }
        }
        Ok(())
    }

    fn required_object(
        &self,
        role: CargoCapturedRole,
    ) -> Result<&ObjectId, CargoResolutionRefusal> {
        self.objects
            .iter()
            .find(|entry| entry.role == role)
            .map(|entry| &entry.object)
            .ok_or_else(|| CargoResolutionRefusal::InvalidCapture(format!("missing {role:?}")))
    }

    fn resolution_digest(&self) -> TypedDigest {
        let mut encoder = CanonicalEncoder::new();
        encoder
            .u32(self.schema_version)
            .bytes(&self.requested_snapshot_sha256);
        frame_digest(&mut encoder, &self.invocation.digest());
        frame_digest(&mut encoder, &self.toolchain_contract);
        frame_digest(&mut encoder, &self.config_provenance);
        match &self.initial_lockfile {
            InitialLockfile::Absent => {
                encoder.u32(0);
            }
            InitialLockfile::Present(object) => {
                encoder.u32(1);
                frame_object(&mut encoder, object);
            }
        }
        encoder.seq(&self.objects, |encoder, entry| {
            encoder
                .u32(entry.role.tag())
                .bytes(entry.virtual_path.as_bytes());
            frame_object(encoder, &entry.object);
            encoder
                .u32(rabs_protocol::object_model::object_kind_tag(
                    entry.object_kind,
                ))
                .u64(entry.content_length)
                .bytes(entry.source_identity.as_bytes())
                .option(entry.resolved_checksum.as_ref(), |encoder, checksum| {
                    encoder.bytes(checksum.as_bytes());
                });
        });
        frame_object(&mut encoder, &self.closure_root);
        compute(DOMAIN_CARGO_RESOLUTION, &encoder.finish())
    }
}

fn validate_materialization(
    capture: &CargoResolutionCapture,
    materialization: &CargoHomeMaterialization,
) -> Result<(), CargoResolutionRefusal> {
    if materialization.operation_id != capture.operation_id
        || materialization.generation == 0
        || !materialization.started_empty
        || materialization.closure_root != capture.closure_root
        || !safe_absolute_backing(&materialization.backing)
    {
        return Err(CargoResolutionRefusal::InvalidCargoHomeMaterialization(
            "Cargo home is not a fresh operation-owned rendering of the closure".into(),
        ));
    }
    let mut expected: Vec<ObjectId> = capture
        .objects
        .iter()
        .filter(|entry| {
            entry
                .virtual_path
                .as_bytes()
                .starts_with(b"/__rabs/cargo-home/")
        })
        .map(|entry| entry.object.clone())
        .collect();
    canonicalize_object_ids(&mut expected)?;
    let mut actual = materialization.materialized_objects.clone();
    canonicalize_object_ids(&mut actual)?;
    if actual != expected {
        return Err(CargoResolutionRefusal::InvalidCargoHomeMaterialization(
            "Cargo home object set differs from the sealed closure".into(),
        ));
    }
    Ok(())
}

fn validate_offline_evidence(
    capture: &CargoResolutionCapture,
    validation: &OfflineValidationEvidence,
) -> Result<(), CargoResolutionRefusal> {
    if validation.closure_root != capture.closure_root
        || &validation.reproduced_lockfile
            != capture.required_object(CargoCapturedRole::ResolvedLockfile)?
        || &validation.reproduced_source_selection
            != capture.required_object(CargoCapturedRole::SourceSelection)?
    {
        return Err(CargoResolutionRefusal::OfflineValidationFailed(
            "fresh-home Cargo resolution did not reproduce captured objects".into(),
        ));
    }
    let network_denied = validation
        .isolation
        .controls
        .iter()
        .any(|(control, state)| {
            control.as_bytes() == b"network-deny"
                && matches!(state, EnforcementState::Enforced { .. })
        });
    if !validation.isolation.fully_enforced() || !network_denied {
        return Err(CargoResolutionRefusal::OfflineValidationFailed(
            "offline validation lacked enforced network denial".into(),
        ));
    }
    Ok(())
}

fn map_network_refusal(error: NetworkGateRefusal) -> CargoResolutionRefusal {
    match error {
        NetworkGateRefusal::NoOpenNetworkToken => {
            CargoResolutionRefusal::NetworkCapabilityRequired {
                explanation: "Cargo resolution needs uncaptured bytes; grant one operation-bound OpenNetwork capability for the exact bounded scope",
            }
        }
        other => CargoResolutionRefusal::NetworkCapabilityRejected(format!("{other:?}")),
    }
}

fn config_sets_offline(value: &[u8]) -> bool {
    let compact: Vec<u8> = value
        .iter()
        .copied()
        .filter(|byte| !byte.is_ascii_whitespace())
        .collect();
    compact == b"net.offline=true"
}

fn require_digest_domain(
    digest: &TypedDigest,
    domain: &'static str,
    label: &str,
) -> Result<(), CargoResolutionRefusal> {
    if digest.algorithm != DigestAlgorithm::Sha256V1 || digest.domain != domain {
        return Err(CargoResolutionRefusal::InvalidCapture(format!(
            "{label} uses the wrong typed-digest domain"
        )));
    }
    Ok(())
}

fn require_object(object: &ObjectId, label: &str) -> Result<(), CargoResolutionRefusal> {
    require_digest_domain(&object.0, ATP_OBJECT_CONTENT_DOMAIN, label)
}

fn validate_virtual_path(path: &[u8]) -> Result<(), CargoResolutionRefusal> {
    if !canonical_absolute_bytes(path)
        || !(path == b"/__rabs/workspace/Cargo.lock"
            || path.starts_with(b"/__rabs/cargo-home/")
            || path.starts_with(b"/__rabs/resolution/")
            || path.starts_with(b"/__rabs/repos/"))
    {
        return Err(CargoResolutionRefusal::InvalidCapture(
            "captured object path is noncanonical or outside E025 roots".into(),
        ));
    }
    Ok(())
}

fn validate_dependency_members(
    manifest: &DependencySourceManifest,
) -> Result<(), CargoResolutionRefusal> {
    for member in &manifest.members {
        let path = member.relative_path.as_bytes();
        if path.is_empty()
            || path.starts_with(b"/")
            || path.ends_with(b"/")
            || path.contains(&0)
            || path
                .split(|byte| *byte == b'/')
                .any(|part| part.is_empty() || part == b"." || part == b"..")
        {
            return Err(CargoResolutionRefusal::DependencySourceInvalid(
                "dependency member path can escape its source root".into(),
            ));
        }
        require_digest_domain(
            &member.content_digest,
            ATP_OBJECT_CONTENT_DOMAIN,
            "dependency member",
        )?;
    }
    Ok(())
}

fn dependency_manifest_object(manifest: &DependencySourceManifest) -> ObjectId {
    let mut encoder = CanonicalEncoder::new();
    encoder
        .u32(CARGO_RESOLUTION_SCHEMA_VERSION)
        .str(&manifest.source_checksum)
        .str(&manifest.cargo_checksum)
        .seq(&manifest.members, |encoder, member| {
            encoder.str(&member.relative_path);
            frame_digest(encoder, &member.content_digest);
            encoder.bool(member.executable);
        });
    ObjectId(compute(ATP_OBJECT_CONTENT_DOMAIN, &encoder.finish()))
}

fn frame_object(encoder: &mut CanonicalEncoder, object: &ObjectId) {
    frame_digest(encoder, &object.0);
}

fn frame_digest(encoder: &mut CanonicalEncoder, digest: &TypedDigest) {
    encoder
        .u32(match digest.algorithm {
            DigestAlgorithm::Sha256V1 => 1,
        })
        .str(digest.domain)
        .bytes(&digest.bytes);
}

fn object_key(object: &ObjectId) -> (&'static str, [u8; 32]) {
    (object.0.domain, object.0.bytes)
}

fn canonicalize_object_ids(objects: &mut Vec<ObjectId>) -> Result<(), CargoResolutionRefusal> {
    for object in objects.iter() {
        require_object(object, "materialized/input object")?;
    }
    objects.sort_by_key(object_key);
    objects.dedup();
    Ok(())
}

fn canonical_absolute_bytes(path: &[u8]) -> bool {
    path.first() == Some(&b'/')
        && path.last() != Some(&b'/')
        && !path.contains(&0)
        && path
            .split(|byte| *byte == b'/')
            .skip(1)
            .all(|part| !part.is_empty() && part != b"." && part != b"..")
}

fn safe_absolute_backing(path: &Path) -> bool {
    path.is_absolute() && path.components().count() > 1
}

fn source_error(error: &SnapshotError) -> CargoResolutionRefusal {
    CargoResolutionRefusal::DependencySourceInvalid(format!("{error:?}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use rabs_cas::dependency_snapshot::SnapshotMember;
    use rabs_protocol::input_evidence::IsolationEvidenceRecord;
    use rabs_sandbox::network_isolation::{
        BrokerChannel, NetworkAuthority, NetworkBudget, NetworkScheme,
    };

    fn digest(domain: &'static str, tag: u8) -> TypedDigest {
        TypedDigest {
            algorithm: DigestAlgorithm::Sha256V1,
            domain,
            bytes: [tag; 32],
        }
    }

    fn object(tag: u8) -> ObjectId {
        ObjectId(digest(ATP_OBJECT_CONTENT_DOMAIN, tag))
    }

    fn entry(
        role: CargoCapturedRole,
        path: &str,
        tag: u8,
        identity: &str,
        checksum: Option<&str>,
    ) -> CapturedCargoObject {
        CapturedCargoObject {
            role,
            virtual_path: RawBytes::from(path),
            object: object(tag),
            object_kind: if role.is_source_tree() {
                ObjectKind::DirectoryObject
            } else {
                ObjectKind::FileObject
            },
            content_length: 100 + u64::from(tag),
            source_identity: RawBytes::from(identity),
            resolved_checksum: checksum.map(RawBytes::from),
        }
    }

    fn invocation(args: &[&str], offline_config: bool) -> CargoInvocation {
        CargoInvocation {
            program: RawBytes::from("cargo"),
            args: args.iter().map(|arg| RawBytes::from(*arg)).collect(),
            effective_config_offline: offline_config,
        }
    }

    fn policy() -> BoundedNetworkPolicy {
        BoundedNetworkPolicy::new(
            vec![NetworkAuthority::new(NetworkScheme::Https, "index.crates.io", 443).unwrap()],
            NetworkBudget {
                max_requests: 20,
                max_redirects: 2,
                max_response_bytes: 1_000_000,
            },
        )
        .unwrap()
    }

    fn manifest() -> DependencySourceManifest {
        DependencySourceManifest {
            source_checksum: "tree-sha256-abc".into(),
            cargo_checksum: "cargo-checksum-abc".into(),
            members: vec![
                SnapshotMember {
                    relative_path: "Cargo.toml".into(),
                    content_digest: digest(ATP_OBJECT_CONTENT_DOMAIN, 51),
                    executable: false,
                },
                SnapshotMember {
                    relative_path: "src/lib.rs".into(),
                    content_digest: digest(ATP_OBJECT_CONTENT_DOMAIN, 52),
                    executable: false,
                },
            ],
        }
    }

    fn capture() -> CargoResolutionCapture {
        let source_manifest = manifest();
        let manifest_object = dependency_manifest_object(&source_manifest);
        let objects = vec![
            entry(
                CargoCapturedRole::ResolvedLockfile,
                "/__rabs/workspace/Cargo.lock",
                1,
                "workspace-lockfile",
                None,
            ),
            entry(
                CargoCapturedRole::EffectiveConfig,
                "/__rabs/resolution/effective-config",
                2,
                "effective-config-v1",
                None,
            ),
            entry(
                CargoCapturedRole::SourceSelection,
                "/__rabs/resolution/source-selection",
                3,
                "cargo-package-selection-v1",
                None,
            ),
            entry(
                CargoCapturedRole::RegistryIndexConfig,
                "/__rabs/cargo-home/registry/index/crates-io/config.json",
                4,
                "registry+https://github.com/rust-lang/crates.io-index",
                None,
            ),
            entry(
                CargoCapturedRole::RegistryIndexEntry,
                "/__rabs/cargo-home/registry/index/crates-io/se/rd/serde",
                5,
                "registry-package:serde",
                None,
            ),
            entry(
                CargoCapturedRole::RegistryArchive,
                "/__rabs/cargo-home/registry/cache/crates-io/serde-1.0.0.crate",
                6,
                "registry-package:serde@1.0.0",
                Some("cargo-checksum-abc"),
            ),
            entry(
                CargoCapturedRole::RegistrySourceTree,
                "/__rabs/cargo-home/registry/src/crates-io/serde-1.0.0",
                7,
                "registry-package:serde@1.0.0",
                Some("cargo-checksum-abc"),
            ),
            CapturedCargoObject {
                role: CargoCapturedRole::DependencySourceManifest,
                virtual_path: RawBytes::from("/__rabs/resolution/manifests/serde-1.0.0.manifest"),
                object: manifest_object.clone(),
                object_kind: ObjectKind::ApplicationDefinedObject,
                content_length: 200,
                source_identity: RawBytes::from("registry-package:serde@1.0.0"),
                resolved_checksum: Some(RawBytes::from("cargo-checksum-abc")),
            },
        ];
        CargoResolutionCapture {
            schema_version: CARGO_RESOLUTION_SCHEMA_VERSION,
            operation_id: 77,
            requested_snapshot_sha256: [9; 32],
            invocation: invocation(&["build", "--locked"], false),
            toolchain_contract: digest(DOMAIN_TOOLCHAIN_CONTRACT, 10),
            config_provenance: digest(DOMAIN_CARGO_CONFIG_PROVENANCE, 11),
            initial_lockfile: InitialLockfile::Present(object(1)),
            objects,
            closure_root: object(90),
            verified_sources: vec![VerifiedDependencySource {
                source_tree: object(7),
                manifest_object,
                resolved_checksum: "cargo-checksum-abc".into(),
                manifest: source_manifest,
            }],
            fetch_receipt: None,
        }
    }

    fn limits() -> CargoCaptureLimits {
        CargoCaptureLimits {
            max_objects: 100,
            max_total_bytes: 10_000_000,
        }
    }

    fn materialization(
        capture: &CargoResolutionCapture,
        backing: &str,
    ) -> CargoHomeMaterialization {
        CargoHomeMaterialization {
            operation_id: capture.operation_id,
            generation: 1,
            backing: PathBuf::from(backing),
            closure_root: capture.closure_root.clone(),
            materialized_objects: capture
                .objects
                .iter()
                .filter(|entry| {
                    entry
                        .virtual_path
                        .as_bytes()
                        .starts_with(b"/__rabs/cargo-home/")
                })
                .map(|entry| entry.object.clone())
                .collect(),
            started_empty: true,
        }
    }

    fn isolation() -> IsolationEvidenceRecord {
        IsolationEvidenceRecord {
            schema_version: INPUT_EVIDENCE_SCHEMA_VERSION,
            requested_profile: RawBytes::from("strict-hermetic-linux"),
            controls: vec![
                (
                    RawBytes::from("network-deny"),
                    EnforcementState::Enforced { mechanism: "netns" },
                ),
                (
                    RawBytes::from("closed-mount-view"),
                    EnforcementState::Enforced {
                        mechanism: "bubblewrap-binds",
                    },
                ),
            ],
        }
    }

    fn validation(capture: &CargoResolutionCapture) -> OfflineValidationEvidence {
        OfflineValidationEvidence {
            closure_root: capture.closure_root.clone(),
            reproduced_lockfile: capture
                .required_object(CargoCapturedRole::ResolvedLockfile)
                .unwrap()
                .clone(),
            reproduced_source_selection: capture
                .required_object(CargoCapturedRole::SourceSelection)
                .unwrap()
                .clone(),
            isolation: isolation(),
        }
    }

    fn seal(
        capture: &CargoResolutionCapture,
        backing: &str,
    ) -> Result<OfflineCanonicalPlan, CargoResolutionRefusal> {
        let mut lineage = SnapshotLineage::new(RequestedCommandSnapshot {
            manifest_sha256: capture.requested_snapshot_sha256,
        });
        seal_offline_resolution(
            &mut lineage,
            capture,
            limits(),
            &materialization(capture, backing),
            &validation(capture),
            "/store/toolchain",
            "/store/workspace",
            "/store/home",
        )
    }

    #[test]
    fn same_lockfile_and_exact_objects_reproduce_in_two_fresh_homes() {
        let capture = capture();
        let a = seal(&capture, "/attempt/a/cargo-home").unwrap();
        let b = seal(&capture, "/attempt/b/cargo-home").unwrap();
        assert_eq!(a.record().resolution_digest, b.record().resolution_digest);
        assert_eq!(a.record().invocation_digest, b.record().invocation_digest);
        assert_eq!(a.input_manifest(), b.input_manifest());
        assert_eq!(a.invocation(), &capture.invocation);
        assert!(!a.namespace_spec().unwrap().allows_network());
        assert!(!b.namespace_spec().unwrap().allows_network());
    }

    #[test]
    fn captured_object_change_changes_resolution_identity() {
        let base = capture();
        let mut changed = base.clone();
        changed.objects[4].object = object(55);
        let a = seal(&base, "/attempt/a/cargo-home").unwrap();
        let b = seal(&changed, "/attempt/b/cargo-home").unwrap();
        assert_ne!(a.record().resolution_digest, b.record().resolution_digest);
    }

    #[test]
    fn network_required_without_capability_refuses_with_explanation() {
        let err = authorize_fetch_resolution(
            &invocation(&["build", "--locked"], false),
            CargoFetchNeed::NetworkRequired,
            Some(policy()),
            &[],
            &[],
            10,
            5,
            9,
        )
        .unwrap_err();
        assert!(matches!(
            err,
            CargoResolutionRefusal::NetworkCapabilityRequired { explanation }
                if explanation.contains("uncaptured bytes")
        ));
    }

    #[test]
    fn offline_or_frozen_never_exercises_valid_capability() {
        for argv in [
            vec!["build", "--offline"],
            vec!["--frozen", "build"],
            vec!["build", "--config=net.offline = true"],
            vec!["build", "--config", "net.offline=true"],
        ] {
            let policy = policy();
            let token = rabs_protocol::capability_tokens::mint(
                7,
                rabs_protocol::capability_tokens::CapabilityKind::OpenNetwork,
                5,
                9,
                &policy.scope_binding(),
                100,
            )
            .unwrap();
            assert!(matches!(
                authorize_fetch_resolution(
                    &invocation(&argv, false),
                    CargoFetchNeed::NetworkRequired,
                    Some(policy),
                    &[token],
                    &[],
                    10,
                    5,
                    9,
                ),
                Err(CargoResolutionRefusal::UserForbidsNetwork { .. })
            ));
        }
    }

    #[test]
    fn valid_capability_binds_exact_policy_and_preserves_argv() {
        let policy = policy();
        let token = rabs_protocol::capability_tokens::mint(
            7,
            rabs_protocol::capability_tokens::CapabilityKind::OpenNetwork,
            5,
            9,
            &policy.scope_binding(),
            100,
        )
        .unwrap();
        let original = invocation(
            &["+nightly", "build", "--locked", "--config", "build.jobs=2"],
            false,
        );
        let authorization = authorize_fetch_resolution(
            &original,
            CargoFetchNeed::NetworkRequired,
            Some(policy.clone()),
            &[token],
            &[],
            10,
            5,
            9,
        )
        .unwrap();
        let CargoFetchAuthorization::Brokered {
            grant,
            policy: admitted,
        } = authorization
        else {
            panic!("network-required resolution must produce broker authorization");
        };
        assert_eq!(grant.scope(), policy.scope_binding());
        assert_eq!(admitted, policy);
        assert_eq!(original.args[2].as_bytes(), b"--locked");
        assert!(
            !original
                .args
                .iter()
                .any(|arg| arg.as_bytes() == b"--offline")
        );
    }

    #[test]
    fn closure_complete_preserves_user_offline_flag_without_capability_use() {
        let original = invocation(&["build", "--offline"], false);
        assert_eq!(
            authorize_fetch_resolution(
                &original,
                CargoFetchNeed::CapturedClosureComplete,
                None,
                &[],
                &[],
                10,
                5,
                9,
            ),
            Ok(CargoFetchAuthorization::CapturedClosure)
        );
        let mut capture = capture();
        capture.invocation = original.clone();
        let plan = seal(&capture, "/attempt/offline/cargo-home").unwrap();
        assert_eq!(plan.invocation(), &original);
    }

    #[test]
    fn changed_or_missing_lockfile_is_owned_by_e026() {
        let mut changed = capture();
        changed.initial_lockfile = InitialLockfile::Present(object(88));
        assert_eq!(
            seal(&changed, "/attempt/changed/cargo-home"),
            Err(CargoResolutionRefusal::WorkspaceMutationRequiresE026)
        );
        let mut absent = capture();
        absent.initial_lockfile = InitialLockfile::Absent;
        assert_eq!(
            seal(&absent, "/attempt/absent/cargo-home"),
            Err(CargoResolutionRefusal::WorkspaceMutationRequiresE026)
        );
    }

    #[test]
    fn missing_or_ambient_home_objects_refuse_before_seal() {
        let capture = capture();
        let mut home = materialization(&capture, "/attempt/a/cargo-home");
        home.materialized_objects.pop();
        let mut lineage = SnapshotLineage::new(RequestedCommandSnapshot {
            manifest_sha256: capture.requested_snapshot_sha256,
        });
        let err = seal_offline_resolution(
            &mut lineage,
            &capture,
            limits(),
            &home,
            &validation(&capture),
            "/store/toolchain",
            "/store/workspace",
            "/store/home",
        )
        .unwrap_err();
        assert!(matches!(
            err,
            CargoResolutionRefusal::InvalidCargoHomeMaterialization(_)
        ));
        assert_eq!(
            lineage.register_action("compile-serde"),
            Err(LineageError::NotSealed)
        );
    }

    #[test]
    fn offline_validation_must_prove_network_denial() {
        let capture = capture();
        let mut evidence = validation(&capture);
        evidence.isolation.controls[0].1 = EnforcementState::NotEnforced {
            reason: "ambient-network",
        };
        let mut lineage = SnapshotLineage::new(RequestedCommandSnapshot {
            manifest_sha256: capture.requested_snapshot_sha256,
        });
        assert!(matches!(
            seal_offline_resolution(
                &mut lineage,
                &capture,
                limits(),
                &materialization(&capture, "/attempt/a/cargo-home"),
                &evidence,
                "/store/toolchain",
                "/store/workspace",
                "/store/home",
            ),
            Err(CargoResolutionRefusal::OfflineValidationFailed(_))
        ));
    }

    #[test]
    fn source_checksum_or_manifest_tampering_refuses() {
        let mut checksum = capture();
        checksum.verified_sources[0].resolved_checksum = "other".into();
        assert!(matches!(
            seal(&checksum, "/attempt/checksum/cargo-home"),
            Err(CargoResolutionRefusal::DependencySourceInvalid(_))
        ));

        let mut manifest_id = capture();
        manifest_id.verified_sources[0].manifest_object = object(44);
        assert_eq!(
            seal(&manifest_id, "/attempt/manifest/cargo-home"),
            Err(CargoResolutionRefusal::DependencyManifestObjectMismatch)
        );
    }

    #[test]
    fn capture_seals_d032_before_actions_register() {
        let capture = capture();
        let mut lineage = SnapshotLineage::new(RequestedCommandSnapshot {
            manifest_sha256: capture.requested_snapshot_sha256,
        });
        assert_eq!(
            lineage.register_action("compile-serde"),
            Err(LineageError::NotSealed)
        );
        let plan = seal_offline_resolution(
            &mut lineage,
            &capture,
            limits(),
            &materialization(&capture, "/attempt/a/cargo-home"),
            &validation(&capture),
            "/store/toolchain",
            "/store/workspace",
            "/store/home",
        )
        .unwrap();
        let binding = lineage.register_action("compile-serde").unwrap();
        assert_eq!(binding.sealed, plan.sealed());
        assert_eq!(
            binding.sealed.resolution_sha256,
            plan.record().resolution_digest.bytes
        );
    }

    #[test]
    fn attempt_paths_and_fetch_receipt_ids_do_not_fragment_resolution_identity() {
        let mut a = capture();
        let mut b = a.clone();
        let network = BoundedNetworkReceipt {
            token_id: 7,
            scope_binding: policy().scope_binding(),
            authorities: policy().authorities().to_vec(),
            budget: policy().budget(),
            mechanism: "edge-fetch-broker-v1",
            channel: BrokerChannel::InheritedFd(7),
        };
        a.fetch_receipt = Some(CargoFetchReceipt {
            network: network.clone(),
            requests: 3,
            response_bytes: 500,
            captured_objects: 4,
            captured_bytes: 500,
            completed_and_verified: true,
            receipt_object: object(91),
        });
        b.fetch_receipt = Some(CargoFetchReceipt {
            network,
            requests: 4,
            response_bytes: 700,
            captured_objects: 4,
            captured_bytes: 700,
            completed_and_verified: true,
            receipt_object: object(92),
        });
        let pa = seal(&a, "/attempt/a/cargo-home").unwrap();
        let pb = seal(&b, "/different/physical/path").unwrap();
        assert_eq!(pa.record().resolution_digest, pb.record().resolution_digest);
        assert_ne!(
            pa.record().fetch_receipt_object,
            pb.record().fetch_receipt_object
        );
    }
}
