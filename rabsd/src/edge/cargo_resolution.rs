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
//!
//! This module is currently contract groundwork, not a production vertical
//! slice: trusted capture/materialization/validation constructors are compiled
//! only for unit tests until the edge driver, CAS materializer, bounded broker,
//! and offline runner can produce them from live evidence. Release code cannot
//! synthesize the opaque attestations needed to seal a plan.

use crate::edge::snapshot_lineage::{ResolvedExecutionSnapshot, SnapshotLineage};
use rabs_cas::dependency_snapshot::{DependencySourceManifest, SnapshotError};
use rabs_cas::digest_set::{ATP_OBJECT_CONTENT_DOMAIN, DigestRequest, StreamingObjectWriter};
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
use rabs_sandbox::canonical_mounts::{CanonicalMountPlan, UnitMount};
use rabs_sandbox::canonical_namespace::CanonicalNamespaceSpec;
#[cfg(all(test, unix))]
use rabs_sandbox::canonical_namespace::{
    HostIsolationSupport, IsolationError, NamespaceLaunch, build_canonical_argv_raw,
};
use rabs_sandbox::layout;
use rabs_sandbox::network_isolation::{
    BoundedNetworkPolicy, BoundedNetworkReceipt, BrokerChannel, NetworkAuthority,
    NetworkGateRefusal, NetworkGrant, NetworkScheme, evaluate_open_network,
};
use rabs_sandbox::snapshot_capture::SnapshotProvenance;
use std::collections::HashSet;
use std::path::{Path, PathBuf};

/// Version of the capture/validation record.
pub const CARGO_RESOLUTION_SCHEMA_VERSION: u32 = 1;
/// Digest of the exact original Cargo program and argv.
pub const DOMAIN_CARGO_INVOCATION: &str = "rabs.cargo-invocation.sha256.v1";
/// Digest binding verified Cargo configuration replay semantics.
pub const DOMAIN_CARGO_CONFIG_REPLAY: &str = "rabs.cargo-config-replay.sha256.v1";
/// Digest of the semantic captured resolution closure.
pub const DOMAIN_CARGO_RESOLUTION: &str = "rabs.cargo-resolution.sha256.v1";
/// Digest binding a completed broker receipt to its exact captured closure.
pub const DOMAIN_CARGO_FETCH_CAPTURE: &str = "rabs.cargo-fetch-capture.sha256.v1";
const MAX_INVOCATION_ARGS: usize = 4_096;
const MAX_INVOCATION_BYTES: usize = 1024 * 1024;

type ObjectSortKey = (&'static str, [u8; 32]);

/// Exact original Cargo invocation. Raw bytes preserve non-UTF8 Unix argv.
/// Configuration semantics are carried separately by
/// [`CargoConfigReplay`], so an authorization caller cannot assert an
/// unrelated `net.offline` bit beside these bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CargoInvocation {
    /// Exact canonical toolchain Cargo path.
    pub program: RawBytes,
    /// Original argument vector, in order.
    pub args: Vec<RawBytes>,
}

impl CargoInvocation {
    /// Validate the bounded exact invocation.
    ///
    /// # Errors
    /// [`CargoResolutionRefusal::InvalidInvocation`] for a non-Cargo,
    /// empty, NUL-bearing, or unbounded invocation.
    pub fn validate(&self) -> Result<(), CargoResolutionRefusal> {
        let program = self.program.as_bytes();
        if program != b"/__rabs/toolchain/bin/cargo" {
            return Err(CargoResolutionRefusal::InvalidInvocation(
                "program must be canonical toolchain cargo".into(),
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
        self.validate_build_shape()?;
        Ok(())
    }

    fn validate_build_shape(&self) -> Result<(), CargoResolutionRefusal> {
        let mut subcommand_index = 0;
        while let Some(arg) = self.args.get(subcommand_index).map(RawBytes::as_bytes) {
            if arg.starts_with(b"+") {
                return Err(CargoResolutionRefusal::InvalidInvocation(
                    "Cargo +toolchain selectors require typed K016 expansion evidence".into(),
                ));
            }
            if matches!(
                arg,
                b"--locked" | b"--offline" | b"--frozen" | b"--quiet" | b"-q" | b"-v"
            ) || arg.starts_with(b"--verbose")
                || arg.starts_with(b"--color=")
            {
                subcommand_index += 1;
                continue;
            }
            if let Some(value) = arg.strip_prefix(b"--config=") {
                validate_cli_config(value)?;
                subcommand_index += 1;
                continue;
            }
            if arg == b"--config" {
                let value = self.args.get(subcommand_index + 1).ok_or_else(|| {
                    CargoResolutionRefusal::InvalidInvocation("--config requires a value".into())
                })?;
                validate_cli_config(value.as_bytes())?;
                subcommand_index += 2;
                continue;
            }
            break;
        }
        let Some(subcommand) = self.args.get(subcommand_index).map(RawBytes::as_bytes) else {
            return Err(CargoResolutionRefusal::InvalidInvocation(
                "Cargo build-family subcommand is required".into(),
            ));
        };
        if !matches!(
            subcommand,
            b"build" | b"check" | b"test" | b"clippy" | b"doc" | b"run" | b"bench"
        ) {
            return Err(CargoResolutionRefusal::InvalidInvocation(
                "only exact built-in Cargo build-family subcommands are admitted".into(),
            ));
        }

        let mut index = subcommand_index + 1;
        while index < self.args.len() {
            let arg = self.args[index].as_bytes();
            if arg == b"--" {
                break;
            }
            if arg == b"--target-dir" || arg.starts_with(b"--target-dir=") {
                return Err(CargoResolutionRefusal::InvalidInvocation(
                    "Cargo target-dir overrides escape the canonical output mount".into(),
                ));
            }
            if arg == b"-Z"
                || arg.starts_with(b"-Z")
                || matches!(arg, b"--lockfile-path" | b"--artifact-dir")
                || arg.starts_with(b"--lockfile-path=")
                || arg.starts_with(b"--artifact-dir=")
            {
                return Err(CargoResolutionRefusal::InvalidInvocation(
                    "unstable/path-detaching Cargo options require typed replay support".into(),
                ));
            }
            if let Some(path) = arg.strip_prefix(b"--manifest-path=") {
                validate_workspace_cli_path(path, "manifest path")?;
            } else if arg == b"--manifest-path" {
                let path = self.args.get(index + 1).ok_or_else(|| {
                    CargoResolutionRefusal::InvalidInvocation(
                        "--manifest-path requires a value".into(),
                    )
                })?;
                validate_workspace_cli_path(path.as_bytes(), "manifest path")?;
                index += 1;
            }
            if let Some(value) = arg.strip_prefix(b"--config=") {
                validate_cli_config(value)?;
            } else if arg == b"--config" {
                let value = self.args.get(index + 1).ok_or_else(|| {
                    CargoResolutionRefusal::InvalidInvocation("--config requires a value".into())
                })?;
                validate_cli_config(value.as_bytes())?;
                index += 1;
            }
            index += 1;
        }
        Ok(())
    }

    /// Whether exact user/config semantics prohibit a fetch.
    #[must_use]
    pub fn forbids_network(&self, config: &CargoConfigReplay) -> bool {
        if config.effective_offline {
            return true;
        }
        let mut index = 0;
        while index < self.args.len() {
            let arg = self.args[index].as_bytes();
            if arg == b"--" {
                break;
            }
            if matches!(arg, b"--offline" | b"--frozen") {
                return true;
            }
            if let Some(value) = arg.strip_prefix(b"--config=")
                && config_sets_offline(value)
            {
                return true;
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

    /// Typed digest of the exact original invocation. No
    /// rewritten/executed argv or independently asserted config fact exists
    /// in this record.
    #[must_use]
    pub fn digest(&self) -> TypedDigest {
        let mut encoder = CanonicalEncoder::new();
        encoder
            .u32(CARGO_RESOLUTION_SCHEMA_VERSION)
            .bytes(self.program.as_bytes())
            .seq(&self.args, |encoder, arg| {
                encoder.bytes(arg.as_bytes());
            });
        compute(DOMAIN_CARGO_INVOCATION, &encoder.finish())
    }
}

/// Trusted K015/K019 replay contract for the exact Cargo configuration
/// layers visible to one resolution operation.
///
/// The optional object is the original credential-free `$CARGO_HOME`
/// configuration layer, not a flattened effective configuration. Workspace
/// and CLI layers retain their original locations and precedence. This bounded
/// WIP contract must refuse ancestor and environment layers for which it has no
/// replay channel, derive the offline fact from the same observed contract,
/// and prove that K019 mapped the effective target directory onto the canonical
/// output mount.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CargoConfigReplay {
    session_id: u64,
    operation_id: u64,
    requested_snapshot_sha256: [u8; 32],
    invocation_digest: TypedDigest,
    provenance: TypedDigest,
    cargo_home_config: Option<ObjectId>,
    effective_offline: bool,
    canonical_target_dir: RawBytes,
}

impl CargoConfigReplay {
    /// Test model of a completed K015/K019 origin-preserving replay analysis.
    /// Production construction stays unavailable until the trusted live
    /// producer is wired.
    #[cfg(test)]
    #[allow(clippy::too_many_arguments)]
    fn from_verified_layers(
        session_id: u64,
        operation_id: u64,
        requested_snapshot_sha256: [u8; 32],
        invocation_digest: TypedDigest,
        provenance: TypedDigest,
        cargo_home_config: Option<ObjectId>,
        effective_offline: bool,
        canonical_target_dir: RawBytes,
    ) -> Self {
        Self {
            session_id,
            operation_id,
            requested_snapshot_sha256,
            invocation_digest,
            provenance,
            cargo_home_config,
            effective_offline,
            canonical_target_dir,
        }
    }

    fn validate_for_operation(
        &self,
        session_id: u64,
        operation_id: u64,
        requested_snapshot_sha256: [u8; 32],
        invocation: &CargoInvocation,
    ) -> Result<(), CargoResolutionRefusal> {
        if self.session_id != session_id
            || self.operation_id != operation_id
            || self.requested_snapshot_sha256 != requested_snapshot_sha256
            || self.invocation_digest != invocation.digest()
            || self.session_id == 0
            || self.operation_id == 0
            || self.canonical_target_dir.as_bytes() != b"/__rabs/out/cargo-target"
        {
            return Err(CargoResolutionRefusal::InvalidConfigReplay(
                "config replay does not bind this operation and canonical target".into(),
            ));
        }
        require_digest_domain(
            &self.provenance,
            DOMAIN_CARGO_CONFIG_PROVENANCE,
            "Cargo config replay",
        )?;
        if let Some(object) = &self.cargo_home_config {
            require_object(object, "Cargo home config replay")?;
        }
        Ok(())
    }

    fn digest(&self) -> TypedDigest {
        let mut encoder = CanonicalEncoder::new();
        encoder
            .u32(CARGO_RESOLUTION_SCHEMA_VERSION)
            .bytes(&self.requested_snapshot_sha256);
        frame_digest(&mut encoder, &self.invocation_digest);
        frame_digest(&mut encoder, &self.provenance);
        encoder
            .option(self.cargo_home_config.as_ref(), frame_object)
            .bool(self.effective_offline)
            .bytes(self.canonical_target_dir.as_bytes());
        compute(DOMAIN_CARGO_CONFIG_REPLAY, &encoder.finish())
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

/// Exact authority context for one fetch/resolution decision. Bundling the
/// fields keeps session/operation/lease facts from being reordered at call
/// sites and gives the gate one coherent context.
#[derive(Debug, Clone, Copy)]
pub struct CargoNetworkAuthorizationContext<'a> {
    /// Presented capability tokens.
    pub tokens: &'a [CapabilityToken],
    /// Issuer-revoked token ids.
    pub revoked_token_ids: &'a [u64],
    /// Current monotonic coordinator sequence.
    pub current_seq: u64,
    /// Session being resolved.
    pub session_id: u64,
    /// Operation being resolved.
    pub operation_id: u64,
    /// D018/D032 requested workspace snapshot supplying config layers.
    pub requested_snapshot_sha256: [u8; 32],
}

/// Result of authorization. This is authority to use a BOUNDED broker, not
/// authority to share the host network with Cargo.
#[derive(Debug, PartialEq, Eq)]
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

impl CargoFetchAuthorization {
    /// Consume a brokered authorization into its one-shot grant and exact
    /// policy. A pre-existing captured closure returns `None`; callers may
    /// not clone or replay the grant.
    #[must_use]
    pub fn into_brokered(self) -> Option<(NetworkGrant, BoundedNetworkPolicy)> {
        match self {
            Self::CapturedClosure => None,
            Self::Brokered { grant, policy } => Some((grant, policy)),
        }
    }
}

/// Authorize the fetch decision without executing or mutating anything.
/// User offline/frozen semantics take precedence over capability lookup.
///
/// # Errors
/// Typed fail-closed refusal. Network need without authority always includes
/// a human-actionable explanation.
pub fn authorize_fetch_resolution(
    invocation: &CargoInvocation,
    config: &CargoConfigReplay,
    need: CargoFetchNeed,
    policy: Option<BoundedNetworkPolicy>,
    context: CargoNetworkAuthorizationContext<'_>,
) -> Result<CargoFetchAuthorization, CargoResolutionRefusal> {
    invocation.validate()?;
    config.validate_for_operation(
        context.session_id,
        context.operation_id,
        context.requested_snapshot_sha256,
        invocation,
    )?;
    if need == CargoFetchNeed::CapturedClosureComplete {
        return Ok(CargoFetchAuthorization::CapturedClosure);
    }
    if invocation.forbids_network(config) {
        return Err(CargoResolutionRefusal::UserForbidsNetwork {
            explanation: "Cargo --offline/--frozen or effective net.offline=true forbids the fetch phase",
        });
    }
    let policy = policy.ok_or(CargoResolutionRefusal::NetworkCapabilityRequired {
        explanation: "Cargo resolution needs uncaptured registry/git/index bytes, but no bounded fetch policy was declared",
    })?;
    let grant = evaluate_open_network(
        context.tokens,
        context.revoked_token_ids,
        context.current_seq,
        context.session_id,
        context.operation_id,
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
    /// Exact credential-free original `$CARGO_HOME/config.toml` layer.
    /// This is never a flattened effective configuration.
    CargoHomeConfig,
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
            Self::CargoHomeConfig => 2,
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
    /// Maximum aggregate encoded path/source/checksum/manifest metadata.
    pub max_metadata_bytes: u64,
    /// Maximum aggregate K002 source-manifest members.
    pub max_source_members: u32,
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

/// Redaction-safe evidence from a COMPLETED nonpublishing fetch attempt.
/// Fields are opaque: only [`complete_cargo_fetch`] can bind the trusted
/// broker's finalized receipt to an exact captured closure.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CargoFetchReceipt {
    network: BoundedNetworkReceipt,
    closure_root: ObjectId,
    closure_binding: TypedDigest,
    captured_objects: u32,
    captured_bytes: u64,
    receipt_object: ObjectId,
}

impl CargoFetchReceipt {
    /// Trusted broker receipt.
    #[must_use]
    pub const fn network(&self) -> &BoundedNetworkReceipt {
        &self.network
    }

    /// Captured closure root finalized under the broker lease.
    #[must_use]
    pub const fn closure_root(&self) -> &ObjectId {
        &self.closure_root
    }

    /// Exact canonical object/path binding finalized by the capture.
    #[must_use]
    pub const fn closure_binding(&self) -> &TypedDigest {
        &self.closure_binding
    }

    /// Number of immutable captured objects.
    #[must_use]
    pub const fn captured_objects(&self) -> u32 {
        self.captured_objects
    }

    /// Aggregate logical bytes of immutable captured objects.
    #[must_use]
    pub const fn captured_bytes(&self) -> u64 {
        self.captured_bytes
    }

    /// Content id of the canonical receipt record.
    #[must_use]
    pub const fn receipt_object(&self) -> &ObjectId {
        &self.receipt_object
    }
}

/// Complete immutable result of fetch/resolution before offline validation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CargoResolutionCapture {
    /// Schema version.
    pub schema_version: u32,
    /// Session whose operation produced this capture.
    pub session_id: u64,
    /// Operation whose private resolution overlay produced this capture.
    pub operation_id: u64,
    /// Whether the immutable closure existed already or required the
    /// brokered acquisition phase.
    pub fetch_need: CargoFetchNeed,
    /// D032 requested snapshot digest.
    pub requested_snapshot_sha256: [u8; 32],
    /// Original unmodified invocation.
    pub invocation: CargoInvocation,
    /// F007 toolchain contract.
    pub toolchain_contract: TypedDigest,
    /// Origin-preserving K015/K019 configuration replay contract.
    pub config: CargoConfigReplay,
    /// Initial lockfile state.
    pub initial_lockfile: InitialLockfile,
    /// Canonically sorted immutable closure.
    pub objects: Vec<CapturedCargoObject>,
    /// CAS closure/dataset root for the fresh Cargo-home materialization.
    pub closure_root: ObjectId,
    /// K002 source-tree verification links.
    pub verified_sources: Vec<VerifiedDependencySource>,
    /// Opaque finalized fetch evidence, present exactly when
    /// `fetch_need == NetworkRequired`.
    pub fetch_receipt: Option<CargoFetchReceipt>,
}

/// Bind a finalized, nonforgeable broker receipt to the exact object/path
/// closure captured before Cargo is allowed to run offline.
///
/// # Errors
/// Refuses invalid object domains, an empty/unbounded object count, or byte
/// counter overflow.
pub fn complete_cargo_fetch(
    network: BoundedNetworkReceipt,
    closure_root: ObjectId,
    objects: &[CapturedCargoObject],
) -> Result<CargoFetchReceipt, CargoResolutionRefusal> {
    require_object(&closure_root, "fetch closure root")?;
    let captured_objects = u32::try_from(objects.len()).map_err(|_| {
        CargoResolutionRefusal::InvalidCapture("captured object count exceeds u32".into())
    })?;
    if captured_objects == 0 {
        return Err(CargoResolutionRefusal::InvalidCapture(
            "brokered fetch produced no captured objects".into(),
        ));
    }
    let mut captured_bytes = 0u64;
    for entry in objects {
        require_object(&entry.object, "fetch captured object")?;
        captured_bytes = captured_bytes
            .checked_add(entry.content_length)
            .ok_or_else(|| {
                CargoResolutionRefusal::InvalidCapture("captured bytes overflow".into())
            })?;
    }
    let expected_root = captured_closure_root(objects)?;
    if closure_root != expected_root {
        return Err(CargoResolutionRefusal::InvalidCapture(
            "fetch closure root does not bind the exact captured mappings".into(),
        ));
    }
    let closure_binding = captured_closure_binding(objects);

    let mut encoder = CanonicalEncoder::new();
    encoder
        .u32(CARGO_RESOLUTION_SCHEMA_VERSION)
        .u64(network.token_id())
        .u64(network.session_id())
        .u64(network.operation_id())
        .u64(network.completed_at_seq())
        .str(network.scope_binding())
        .u32(network.requests())
        .u32(network.redirects())
        .u64(network.response_bytes());
    let budget = network.budget();
    encoder
        .u32(budget.max_requests)
        .u32(budget.max_redirects)
        .u64(budget.max_response_bytes)
        .seq(network.allowed_authorities(), frame_authority)
        .seq(network.observed_authorities(), frame_authority)
        .str(network.mechanism());
    frame_broker_channel(&mut encoder, network.channel());
    frame_object(&mut encoder, &closure_root);
    frame_digest(&mut encoder, &closure_binding);
    encoder.u32(captured_objects).u64(captured_bytes);
    let receipt_object = object_id_for_bytes(&encoder.finish())?;

    Ok(CargoFetchReceipt {
        network,
        closure_root,
        closure_binding,
        captured_objects,
        captured_bytes,
        receipt_object,
    })
}

/// One exact path/object/kind/size entry observed in a materialized Cargo
/// home. Comparing these mappings (rather than a deduplicated object-id
/// set) proves that aliases, missing paths, wrong kinds, and extras refuse.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MaterializedCargoObject {
    virtual_path: RawBytes,
    object: ObjectId,
    object_kind: ObjectKind,
    content_length: u64,
}

impl MaterializedCargoObject {
    fn from_capture(entry: &CapturedCargoObject) -> Self {
        Self {
            virtual_path: entry.virtual_path.clone(),
            object: entry.object.clone(),
            object_kind: entry.object_kind,
            content_length: entry.content_length,
        }
    }
}

/// Trusted daemon materializer attestation for one fresh, operation-owned
/// Cargo home. Fields are private so an RPC/client caller cannot seal
/// lineage by constructing a bool-only "fresh" claim. `backing` is
/// attempt-local placement and never enters identity.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CargoHomeMaterialization {
    /// Owning session.
    session_id: u64,
    /// Owning operation.
    operation_id: u64,
    /// Fresh nonzero materialization generation/nonce.
    generation: u64,
    /// Physical backing, mounted at canonical `/__rabs/cargo-home`.
    backing: PathBuf,
    /// Closure materialized into this home.
    closure_root: ObjectId,
    /// Exact path/object/kind/size mappings, canonical order.
    materialized_objects: Vec<MaterializedCargoObject>,
    /// Materializer observed the backing absent/empty before population.
    started_empty: bool,
}

impl CargoHomeMaterialization {
    /// Test model of the daemon's verified fresh-directory scan.
    #[cfg(test)]
    fn from_verified_scan(
        session_id: u64,
        operation_id: u64,
        generation: u64,
        backing: PathBuf,
        closure_root: ObjectId,
        materialized_objects: Vec<MaterializedCargoObject>,
        started_empty: bool,
    ) -> Self {
        Self {
            session_id,
            operation_id,
            generation,
            backing,
            closure_root,
            materialized_objects,
            started_empty,
        }
    }
}

/// Trusted daemon attestation for the writable surfaces exposed to Cargo
/// and build scripts. Both roots must be freshly created for this exact
/// session/operation; otherwise an ambient HOME file or stale target artifact
/// could influence an allegedly closed replay without appearing in inputs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CargoWritableMaterialization {
    session_id: u64,
    operation_id: u64,
    generation: u64,
    home_backing: PathBuf,
    target_backing: PathBuf,
    home_started_empty: bool,
    target_started_empty: bool,
}

impl CargoWritableMaterialization {
    /// Test model of two freshly verified operation-owned directories.
    #[cfg(test)]
    fn from_verified_empty_roots(
        session_id: u64,
        operation_id: u64,
        generation: u64,
        home_backing: PathBuf,
        target_backing: PathBuf,
        home_started_empty: bool,
        target_started_empty: bool,
    ) -> Self {
        Self {
            session_id,
            operation_id,
            generation,
            home_backing,
            target_backing,
            home_started_empty,
            target_started_empty,
        }
    }
}

/// Result of the trusted daemon runner executing Cargo's resolution
/// validation in that fresh home with physical egress denied. Fields are
/// private so untrusted request data cannot synthesize enforcement.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OfflineValidationEvidence {
    /// Session whose operation was validated.
    session_id: u64,
    /// Operation whose fresh home was validated.
    operation_id: u64,
    /// Exact materialization generation validated.
    materialization_generation: u64,
    /// Exact fresh writable-surface generation validated.
    writable_generation: u64,
    /// Original Cargo invocation executed for validation.
    invocation_digest: TypedDigest,
    /// Exact K015/K019 replay contract visible to validation Cargo.
    config_replay_digest: TypedDigest,
    /// Exact F007 toolchain contract used by validation Cargo.
    toolchain_contract: TypedDigest,
    /// Requested immutable workspace snapshot used by validation Cargo.
    requested_snapshot_sha256: [u8; 32],
    /// Closure used by the validation run.
    closure_root: ObjectId,
    /// Lockfile Cargo observed/reproduced.
    reproduced_lockfile: ObjectId,
    /// Package/source selection Cargo reproduced.
    reproduced_source_selection: ObjectId,
    /// Actual sandbox controls from the validation launch.
    isolation: IsolationEvidenceRecord,
}

impl OfflineValidationEvidence {
    /// Test model of a completed daemon-owned canonical launch and the object
    /// identities parsed from Cargo's successful output.
    #[cfg(test)]
    #[allow(clippy::too_many_arguments)]
    fn from_completed_launch(
        session_id: u64,
        operation_id: u64,
        materialization_generation: u64,
        writable_generation: u64,
        invocation_digest: TypedDigest,
        config_replay_digest: TypedDigest,
        toolchain_contract: TypedDigest,
        requested_snapshot_sha256: [u8; 32],
        closure_root: ObjectId,
        reproduced_lockfile: ObjectId,
        reproduced_source_selection: ObjectId,
        isolation: IsolationEvidenceRecord,
    ) -> Self {
        Self {
            session_id,
            operation_id,
            materialization_generation,
            writable_generation,
            invocation_digest,
            config_replay_digest,
            toolchain_contract,
            requested_snapshot_sha256,
            closure_root,
            reproduced_lockfile,
            reproduced_source_selection,
            isolation,
        }
    }
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
#[derive(Debug, PartialEq, Eq)]
pub struct OfflineCanonicalPlan {
    invocation: CargoInvocation,
    namespace_spec: CanonicalNamespaceSpec,
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

    /// Already-validated immutable, network-denied canonical namespace.
    #[must_use]
    #[cfg(test)]
    const fn namespace_spec(&self) -> &CanonicalNamespaceSpec {
        &self.namespace_spec
    }

    /// Test-model projection of the original byte-exact invocation into the
    /// validated network-denied namespace. Production deliberately exposes no
    /// replayable argv until a trusted executor owns the fresh-root lease.
    ///
    /// # Errors
    /// Host isolation support or canonical-launch validation refusal.
    #[cfg(all(test, unix))]
    fn namespace_launch(
        self,
        support: &HostIsolationSupport,
    ) -> Result<NamespaceLaunch, IsolationError> {
        build_canonical_argv_raw(
            &self.namespace_spec,
            support,
            &self.invocation.program,
            &self.invocation.args,
        )
    }
}

/// Typed E025 refusal. Every arm is fail-closed for authoritative execution;
/// a higher-level pre-frontier nonpublishing fallback may still run the
/// ORIGINAL command if its policy independently permits that.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CargoResolutionRefusal {
    /// Malformed or unbounded original invocation.
    InvalidInvocation(String),
    /// K015/K019 replay evidence is missing, mismatched, or not canonical.
    InvalidConfigReplay(String),
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
    /// HOME/target roots were not fresh operation-owned writable surfaces.
    InvalidWritableMaterialization(String),
    /// Closed offline validation did not reproduce the captured resolution.
    OfflineValidationFailed(String),
    /// Capture belongs to another requested snapshot.
    RequestedSnapshotMismatch,
    /// D032 refused the seal.
    SnapshotLineage(String),
    /// The immutable canonical build view could not be constructed.
    CanonicalPlanInvalid(String),
}

/// Validate capture + disposable fresh-home replay, require a second distinct
/// fresh writable generation for authoritative execution, seal D032, and
/// construct the network-denied canonical plan. No action may register before
/// this call succeeds. Validation HOME/target roots are never reused by the
/// returned plan.
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
    validation_writable: &CargoWritableMaterialization,
    validation: &OfflineValidationEvidence,
    execution_writable: &CargoWritableMaterialization,
    toolchain_backing: impl Into<PathBuf>,
    workspace_backing: impl Into<PathBuf>,
    workspace_provenance: SnapshotProvenance,
) -> Result<OfflineCanonicalPlan, CargoResolutionRefusal> {
    let toolchain_backing = toolchain_backing.into();
    let workspace_backing = workspace_backing.into();
    capture.validate(limits)?;
    if lineage.requested().manifest_sha256 != capture.requested_snapshot_sha256 {
        return Err(CargoResolutionRefusal::RequestedSnapshotMismatch);
    }
    if workspace_provenance.manifest_sha256 != capture.requested_snapshot_sha256 {
        return Err(CargoResolutionRefusal::RequestedSnapshotMismatch);
    }
    validate_materialization(capture, materialization)?;
    validate_writable_materialization(capture, validation_writable)?;
    validate_writable_disjoint_from_immutable(
        validation_writable,
        materialization,
        &toolchain_backing,
        &workspace_backing,
    )?;
    validate_offline_evidence(capture, materialization, validation_writable, validation)?;
    validate_writable_materialization(capture, execution_writable)?;
    validate_writable_disjoint_from_immutable(
        execution_writable,
        materialization,
        &toolchain_backing,
        &workspace_backing,
    )?;
    validate_distinct_writable_materializations(validation_writable, execution_writable)?;

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
    let mut mount_plan = CanonicalMountPlan::new(
        &toolchain_backing,
        &workspace_backing,
        &materialization.backing,
        &execution_writable.home_backing,
    )
    .with_immutable_source(workspace_backing, workspace_provenance)
    .with_immutable_cargo_home();
    mount_plan.out_units.push(UnitMount {
        unit: "cargo-target".into(),
        backing: execution_writable.target_backing.clone(),
    });
    mount_plan.extra_env.push((
        "CARGO_TARGET_DIR".into(),
        format!("{}/cargo-target", layout::OUT),
    ));
    let namespace_spec = mount_plan
        .to_spec()
        .map_err(|error| CargoResolutionRefusal::CanonicalPlanInvalid(error.to_string()))?;
    if namespace_spec.allows_network() {
        return Err(CargoResolutionRefusal::CanonicalPlanInvalid(
            "offline canonical plan unexpectedly allows network".into(),
        ));
    }

    let resolution_digest = capture.resolution_digest();
    let sealed = lineage
        .seal(resolution_digest.bytes)
        .map_err(|error| CargoResolutionRefusal::SnapshotLineage(format!("{error:?}")))?;
    let record = CargoResolutionRecord {
        schema_version: CARGO_RESOLUTION_SCHEMA_VERSION,
        resolution_digest,
        invocation_digest: capture.invocation.digest(),
        closure_root: capture.closure_root.clone(),
        fetch_receipt_object: capture
            .fetch_receipt
            .as_ref()
            .map(|receipt| receipt.receipt_object().clone()),
    };
    Ok(OfflineCanonicalPlan {
        invocation: capture.invocation.clone(),
        namespace_spec,
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
        if self.session_id == 0
            || self.operation_id == 0
            || limits.max_objects == 0
            || limits.max_total_bytes == 0
            || limits.max_metadata_bytes == 0
            || limits.max_source_members == 0
        {
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
        self.config.validate_for_operation(
            self.session_id,
            self.operation_id,
            self.requested_snapshot_sha256,
            &self.invocation,
        )?;
        require_object(&self.closure_root, "closure root")?;
        if self.objects.is_empty() || self.objects.len() > limits.max_objects as usize {
            return Err(CargoResolutionRefusal::InvalidCapture(
                "captured object count is empty or over bound".into(),
            ));
        }
        let mut total = 0u64;
        let mut metadata_total = 0u64;
        let mut previous_key: Option<(u32, Vec<u8>, Vec<u8>)> = None;
        let mut paths = HashSet::new();
        for entry in &self.objects {
            require_object(&entry.object, "captured object")?;
            validate_virtual_path(entry.virtual_path.as_bytes())?;
            validate_role_schema(entry)?;
            if entry.source_identity.is_empty() {
                return Err(CargoResolutionRefusal::InvalidCapture(
                    "captured object source identity is empty".into(),
                ));
            }
            if matches!(
                entry.role,
                CargoCapturedRole::RegistryArchive
                    | CargoCapturedRole::RegistrySourceTree
                    | CargoCapturedRole::GitDatabase
                    | CargoCapturedRole::GitCheckout
            ) && entry
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
            let entry_metadata = entry
                .virtual_path
                .len()
                .checked_add(entry.source_identity.len())
                .and_then(|size| {
                    size.checked_add(entry.resolved_checksum.as_ref().map_or(0, RawBytes::len))
                })
                .ok_or_else(|| {
                    CargoResolutionRefusal::InvalidCapture("capture metadata overflow".into())
                })?;
            metadata_total = metadata_total
                .checked_add(entry_metadata as u64)
                .ok_or_else(|| {
                    CargoResolutionRefusal::InvalidCapture("capture metadata overflow".into())
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
        if self.closure_root != captured_closure_root(&self.objects)? {
            return Err(CargoResolutionRefusal::InvalidCapture(
                "closure root does not bind the exact canonical object mappings".into(),
            ));
        }
        metadata_total = metadata_total
            .checked_add(self.source_metadata_size(limits.max_source_members)?)
            .ok_or_else(|| {
                CargoResolutionRefusal::InvalidCapture("capture metadata overflow".into())
            })?;
        if metadata_total > limits.max_metadata_bytes {
            return Err(CargoResolutionRefusal::InvalidCapture(
                "capture metadata exceeds bound".into(),
            ));
        }
        for role in [
            CargoCapturedRole::ResolvedLockfile,
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
        let captured_home_configs: Vec<&CapturedCargoObject> = self
            .objects
            .iter()
            .filter(|entry| entry.role == CargoCapturedRole::CargoHomeConfig)
            .collect();
        match (
            &self.config.cargo_home_config,
            captured_home_configs.as_slice(),
        ) {
            (None, []) => {}
            (Some(expected), [captured]) if expected == &captured.object => {}
            _ => {
                return Err(CargoResolutionRefusal::InvalidConfigReplay(
                    "config replay does not name exactly its captured Cargo-home layer".into(),
                ));
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
        self.validate_cargo_cache_readiness()?;
        Ok(())
    }

    fn source_metadata_size(&self, max_source_members: u32) -> Result<u64, CargoResolutionRefusal> {
        let mut member_count = 0u32;
        let mut bytes = 0u64;
        for verification in &self.verified_sources {
            member_count = member_count
                .checked_add(
                    u32::try_from(verification.manifest.members.len()).map_err(|_| {
                        CargoResolutionRefusal::InvalidCapture(
                            "dependency member count exceeds u32".into(),
                        )
                    })?,
                )
                .ok_or_else(|| {
                    CargoResolutionRefusal::InvalidCapture(
                        "dependency member count overflow".into(),
                    )
                })?;
            let fixed = verification
                .resolved_checksum
                .len()
                .checked_add(verification.manifest.source_checksum.len())
                .and_then(|size| size.checked_add(verification.manifest.cargo_checksum.len()))
                .ok_or_else(|| {
                    CargoResolutionRefusal::InvalidCapture(
                        "dependency metadata length overflow".into(),
                    )
                })?;
            bytes = bytes.checked_add(fixed as u64).ok_or_else(|| {
                CargoResolutionRefusal::InvalidCapture("dependency metadata overflow".into())
            })?;
            for member in &verification.manifest.members {
                bytes = bytes
                    .checked_add(member.relative_path.len() as u64)
                    .and_then(|size| {
                        size.checked_add(member.content_digest.domain.len() as u64 + 33)
                    })
                    .ok_or_else(|| {
                        CargoResolutionRefusal::InvalidCapture(
                            "dependency metadata overflow".into(),
                        )
                    })?;
            }
        }
        if member_count > max_source_members {
            return Err(CargoResolutionRefusal::InvalidCapture(
                "dependency source-member count exceeds bound".into(),
            ));
        }
        Ok(bytes)
    }

    fn validate_fetch_receipt(
        &self,
        limits: CargoCaptureLimits,
    ) -> Result<(), CargoResolutionRefusal> {
        let receipt = match (self.fetch_need, self.fetch_receipt.as_ref()) {
            (CargoFetchNeed::CapturedClosureComplete, None) => return Ok(()),
            (CargoFetchNeed::NetworkRequired, Some(receipt)) => receipt,
            (CargoFetchNeed::CapturedClosureComplete, Some(_)) => {
                return Err(CargoResolutionRefusal::InvalidCapture(
                    "pre-existing closure cannot carry brokered-fetch evidence".into(),
                ));
            }
            (CargoFetchNeed::NetworkRequired, None) => {
                return Err(CargoResolutionRefusal::InvalidCapture(
                    "network-required closure lacks finalized broker evidence".into(),
                ));
            }
        };
        if self.invocation.forbids_network(&self.config) {
            return Err(CargoResolutionRefusal::InvalidCapture(
                "offline/frozen invocation cannot carry fetch evidence".into(),
            ));
        }
        require_object(&receipt.receipt_object, "fetch receipt")?;
        let captured_bytes = self.objects.iter().try_fold(0u64, |total, entry| {
            total.checked_add(entry.content_length).ok_or_else(|| {
                CargoResolutionRefusal::InvalidCapture("captured bytes overflow".into())
            })
        })?;
        if receipt.network.session_id() != self.session_id
            || receipt.network.operation_id() != self.operation_id
            || receipt.closure_root != self.closure_root
            || receipt.closure_binding != captured_closure_binding(&self.objects)
            || receipt.captured_objects > limits.max_objects
            || receipt.captured_objects as usize != self.objects.len()
            || receipt.captured_bytes > limits.max_total_bytes
            || receipt.captured_bytes != captured_bytes
        {
            return Err(CargoResolutionRefusal::InvalidCapture(
                "fetch receipt does not bind this operation's exact captured closure".into(),
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
        let mut previous_key: Option<(ObjectSortKey, ObjectSortKey)> = None;
        for verification in &self.verified_sources {
            require_object(&verification.source_tree, "verified source tree")?;
            require_object(&verification.manifest_object, "dependency manifest")?;
            if !seen.insert(object_key(&verification.source_tree)) {
                return Err(CargoResolutionRefusal::InvalidCapture(
                    "duplicate source-tree verification".into(),
                ));
            }
            let key = (
                object_key(&verification.source_tree),
                object_key(&verification.manifest_object),
            );
            if previous_key
                .as_ref()
                .is_some_and(|previous| previous >= &key)
            {
                return Err(CargoResolutionRefusal::InvalidCapture(
                    "dependency source proofs are not in strict canonical order".into(),
                ));
            }
            previous_key = Some(key);
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
            let expected_manifest = dependency_manifest_object(&verification.manifest)?;
            if verification.manifest_object != expected_manifest
                || verification.source_tree != verification.manifest_object
            {
                return Err(CargoResolutionRefusal::DependencyManifestObjectMismatch);
            }
            let captured_manifest = self.objects.iter().find(|entry| {
                entry.role == CargoCapturedRole::DependencySourceManifest
                    && entry.object == verification.manifest_object
            });
            let Some(captured_manifest) = captured_manifest else {
                return Err(CargoResolutionRefusal::InvalidCapture(
                    "verified dependency manifest is absent from capture".into(),
                ));
            };
            if captured_manifest.source_identity != tree.source_identity
                || captured_manifest.resolved_checksum != tree.resolved_checksum
            {
                return Err(CargoResolutionRefusal::DependencySourceInvalid(
                    "source tree and K002 manifest name different source identities".into(),
                ));
            }
        }
        Ok(())
    }

    fn validate_cargo_cache_readiness(&self) -> Result<(), CargoResolutionRefusal> {
        if self
            .objects
            .iter()
            .any(|entry| entry.role == CargoCapturedRole::PathSource)
        {
            return Err(CargoResolutionRefusal::InvalidCapture(
                "path-source replay is not wired to a verified canonical repo mount".into(),
            ));
        }

        for entry in &self.objects {
            if entry.role == CargoCapturedRole::RegistryIndexEntry {
                let Some((namespace, Some(relative))) =
                    cargo_home_scoped_path(entry.virtual_path.as_bytes(), b"registry/index")
                else {
                    return Err(CargoResolutionRefusal::InvalidCapture(
                        "registry index entry lacks its Cargo source namespace".into(),
                    ));
                };
                if !relative.starts_with(b".cache/") || relative.len() == b".cache/".len() {
                    return Err(CargoResolutionRefusal::InvalidCapture(
                        "sparse registry entry must live below index/<source>/.cache".into(),
                    ));
                }
                let config_path = cargo_home_scoped_path_bytes(
                    b"registry/index",
                    namespace,
                    Some(b"config.json"),
                );
                if !self.objects.iter().any(|candidate| {
                    candidate.role == CargoCapturedRole::RegistryIndexConfig
                        && candidate.virtual_path.as_bytes() == config_path
                }) {
                    return Err(CargoResolutionRefusal::InvalidCapture(
                        "sparse registry entry lacks its captured config.json".into(),
                    ));
                }
            }
        }

        for tree in self
            .objects
            .iter()
            .filter(|entry| entry.role.is_source_tree())
        {
            let verification = self
                .verified_sources
                .iter()
                .find(|verification| verification.source_tree == tree.object)
                .ok_or_else(|| {
                    CargoResolutionRefusal::InvalidCapture(
                        "source tree lacks its readiness manifest".into(),
                    )
                })?;
            if !verification
                .manifest
                .members
                .iter()
                .any(|member| member.relative_path == ".cargo-ok")
            {
                return Err(CargoResolutionRefusal::DependencySourceInvalid(
                    "Cargo source tree lacks the .cargo-ok readiness marker".into(),
                ));
            }

            match tree.role {
                CargoCapturedRole::RegistrySourceTree => {
                    let Some((namespace, Some(package_dir))) =
                        cargo_home_scoped_path(tree.virtual_path.as_bytes(), b"registry/src")
                    else {
                        return Err(CargoResolutionRefusal::InvalidCapture(
                            "registry source tree lacks its Cargo source namespace".into(),
                        ));
                    };
                    if package_dir.contains(&b'/') {
                        return Err(CargoResolutionRefusal::InvalidCapture(
                            "registry source tree must name one package directory".into(),
                        ));
                    }
                    let mut archive_name = package_dir.to_vec();
                    archive_name.extend_from_slice(b".crate");
                    let archive_path = cargo_home_scoped_path_bytes(
                        b"registry/cache",
                        namespace,
                        Some(&archive_name),
                    );
                    if !self.objects.iter().any(|candidate| {
                        candidate.role == CargoCapturedRole::RegistryArchive
                            && candidate.virtual_path.as_bytes() == archive_path
                            && candidate.source_identity == tree.source_identity
                            && candidate.resolved_checksum == tree.resolved_checksum
                            && candidate.content_length > 0
                    }) {
                        return Err(CargoResolutionRefusal::InvalidCapture(
                            "registry source tree lacks its nonempty checksummed .crate archive"
                                .into(),
                        ));
                    }
                    let index_prefix =
                        cargo_home_scoped_path_bytes(b"registry/index", namespace, Some(b".cache"));
                    let index_entry_prefix = with_trailing_slash(&index_prefix);
                    if !self.objects.iter().any(|candidate| {
                        candidate.role == CargoCapturedRole::RegistryIndexEntry
                            && candidate
                                .virtual_path
                                .as_bytes()
                                .starts_with(&index_entry_prefix)
                            && candidate.source_identity == tree.source_identity
                            && candidate
                                .virtual_path
                                .as_bytes()
                                .strip_prefix(index_entry_prefix.as_slice())
                                .is_some_and(|relative| {
                                    sparse_index_path_matches_package(relative, package_dir)
                                })
                    }) {
                        return Err(CargoResolutionRefusal::InvalidCapture(
                            "registry source tree lacks its exact package-bound sparse index entry"
                                .into(),
                        ));
                    }
                }
                CargoCapturedRole::GitCheckout => {
                    let Some((namespace, Some(checkout))) =
                        cargo_home_scoped_path(tree.virtual_path.as_bytes(), b"git/checkouts")
                    else {
                        return Err(CargoResolutionRefusal::InvalidCapture(
                            "Git checkout lacks its Cargo source namespace".into(),
                        ));
                    };
                    if checkout.contains(&b'/') {
                        return Err(CargoResolutionRefusal::InvalidCapture(
                            "Git checkout must name one locked checkout directory".into(),
                        ));
                    }
                    let database_path = cargo_home_scoped_path_bytes(b"git/db", namespace, None);
                    if !self.objects.iter().any(|candidate| {
                        candidate.role == CargoCapturedRole::GitDatabase
                            && candidate.virtual_path.as_bytes() == database_path
                            && candidate.source_identity == tree.source_identity
                            && candidate.resolved_checksum == tree.resolved_checksum
                    }) {
                        return Err(CargoResolutionRefusal::InvalidCapture(
                            "Git checkout lacks its locked-revision database".into(),
                        ));
                    }
                }
                _ => {
                    return Err(CargoResolutionRefusal::InvalidCapture(
                        "non-source role reached Cargo source readiness validation".into(),
                    ));
                }
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
        frame_digest(&mut encoder, &self.config.digest());
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
        encoder.seq(&self.verified_sources, |encoder, verification| {
            frame_object(encoder, &verification.source_tree);
            frame_object(encoder, &verification.manifest_object);
            encoder
                .str(&verification.resolved_checksum)
                .str(&verification.manifest.source_checksum)
                .str(&verification.manifest.cargo_checksum);
        });
        frame_object(&mut encoder, &self.closure_root);
        compute(DOMAIN_CARGO_RESOLUTION, &encoder.finish())
    }
}

fn validate_materialization(
    capture: &CargoResolutionCapture,
    materialization: &CargoHomeMaterialization,
) -> Result<(), CargoResolutionRefusal> {
    if materialization.session_id != capture.session_id
        || materialization.operation_id != capture.operation_id
        || materialization.generation == 0
        || !materialization.started_empty
        || materialization.closure_root != capture.closure_root
        || !safe_absolute_backing(&materialization.backing)
    {
        return Err(CargoResolutionRefusal::InvalidCargoHomeMaterialization(
            "Cargo home is not a fresh operation-owned rendering of the closure".into(),
        ));
    }
    let expected: Vec<MaterializedCargoObject> = capture
        .objects
        .iter()
        .filter(|entry| {
            entry
                .virtual_path
                .as_bytes()
                .starts_with(b"/__rabs/cargo-home/")
        })
        .map(MaterializedCargoObject::from_capture)
        .collect();
    if materialization.materialized_objects != expected {
        return Err(CargoResolutionRefusal::InvalidCargoHomeMaterialization(
            "Cargo home path/object/kind/size mapping differs from the sealed closure".into(),
        ));
    }
    Ok(())
}

fn validate_writable_materialization(
    capture: &CargoResolutionCapture,
    writable: &CargoWritableMaterialization,
) -> Result<(), CargoResolutionRefusal> {
    if writable.session_id != capture.session_id
        || writable.operation_id != capture.operation_id
        || writable.generation == 0
        || !writable.home_started_empty
        || !writable.target_started_empty
        || !safe_absolute_backing(&writable.home_backing)
        || !safe_absolute_backing(&writable.target_backing)
        || backings_overlap(&writable.home_backing, &writable.target_backing)
    {
        return Err(CargoResolutionRefusal::InvalidWritableMaterialization(
            "HOME and target roots are not fresh operation-owned writable surfaces".into(),
        ));
    }
    Ok(())
}

fn validate_distinct_writable_materializations(
    validation: &CargoWritableMaterialization,
    execution: &CargoWritableMaterialization,
) -> Result<(), CargoResolutionRefusal> {
    let validation_roots = [&validation.home_backing, &validation.target_backing];
    let execution_roots = [&execution.home_backing, &execution.target_backing];
    if validation.generation == execution.generation
        || validation_roots.iter().any(|validation_root| {
            execution_roots
                .iter()
                .any(|execution_root| backings_overlap(validation_root, execution_root))
        })
    {
        return Err(CargoResolutionRefusal::InvalidWritableMaterialization(
            "validation and execution require distinct fresh writable generations".into(),
        ));
    }
    Ok(())
}

fn validate_writable_disjoint_from_immutable(
    writable: &CargoWritableMaterialization,
    cargo_home: &CargoHomeMaterialization,
    toolchain_backing: &Path,
    workspace_backing: &Path,
) -> Result<(), CargoResolutionRefusal> {
    let writable_roots = [&writable.home_backing, &writable.target_backing];
    let immutable_roots = [
        cargo_home.backing.as_path(),
        toolchain_backing,
        workspace_backing,
    ];
    if writable_roots.iter().any(|writable_root| {
        immutable_roots
            .iter()
            .any(|immutable_root| backings_overlap(writable_root, immutable_root))
    }) {
        return Err(CargoResolutionRefusal::InvalidWritableMaterialization(
            "writable HOME/target aliases an immutable replay backing".into(),
        ));
    }
    Ok(())
}

fn validate_offline_evidence(
    capture: &CargoResolutionCapture,
    materialization: &CargoHomeMaterialization,
    writable: &CargoWritableMaterialization,
    validation: &OfflineValidationEvidence,
) -> Result<(), CargoResolutionRefusal> {
    if validation.session_id != capture.session_id
        || validation.session_id != materialization.session_id
        || validation.operation_id != capture.operation_id
        || validation.operation_id != materialization.operation_id
        || validation.materialization_generation != materialization.generation
        || validation.writable_generation != writable.generation
        || validation.invocation_digest != capture.invocation.digest()
        || validation.config_replay_digest != capture.config.digest()
        || validation.toolchain_contract != capture.toolchain_contract
        || validation.requested_snapshot_sha256 != capture.requested_snapshot_sha256
        || validation.closure_root != capture.closure_root
        || &validation.reproduced_lockfile
            != capture.required_object(CargoCapturedRole::ResolvedLockfile)?
        || &validation.reproduced_source_selection
            != capture.required_object(CargoCapturedRole::SourceSelection)?
    {
        return Err(CargoResolutionRefusal::OfflineValidationFailed(
            "fresh-home Cargo resolution did not reproduce captured objects".into(),
        ));
    }
    let enforced_control_count = |name: &[u8]| {
        validation
            .isolation
            .controls
            .iter()
            .filter(|(control, state)| {
                control.as_bytes() == name && matches!(state, EnforcementState::Enforced { .. })
            })
            .count()
    };
    if validation.isolation.schema_version != INPUT_EVIDENCE_SCHEMA_VERSION
        || validation.isolation.requested_profile.as_bytes() != b"strict-hermetic-linux"
        || validation.isolation.controls.is_empty()
        || !validation.isolation.fully_enforced()
        || enforced_control_count(b"network-deny") != 1
        || enforced_control_count(b"closed-mount-view") != 1
    {
        return Err(CargoResolutionRefusal::OfflineValidationFailed(
            "offline validation lacked the exact strict closed/network-denied boundary".into(),
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

fn validate_workspace_cli_path(path: &[u8], label: &str) -> Result<(), CargoResolutionRefusal> {
    let canonical_relative = !path.is_empty()
        && path.first() != Some(&b'/')
        && path.last() != Some(&b'/')
        && !path.contains(&0)
        && path
            .split(|byte| *byte == b'/')
            .all(|part| !part.is_empty() && part != b"." && part != b"..");
    let canonical_workspace_absolute =
        canonical_absolute_bytes(path) && path.starts_with(b"/__rabs/workspace/");
    if canonical_relative || canonical_workspace_absolute {
        Ok(())
    } else {
        Err(CargoResolutionRefusal::InvalidInvocation(format!(
            "{label} must remain canonically inside /__rabs/workspace"
        )))
    }
}

fn validate_cli_config(value: &[u8]) -> Result<(), CargoResolutionRefusal> {
    if value.is_empty() || value.contains(&0) {
        return Err(CargoResolutionRefusal::InvalidInvocation(
            "--config value is empty or contains NUL".into(),
        ));
    }
    let compact: Vec<u8> = value
        .iter()
        .copied()
        .filter(|byte| !byte.is_ascii_whitespace())
        .collect();
    if let Some(separator) = compact.iter().position(|byte| *byte == b'=') {
        let key = &compact[..separator];
        if key == b"build.target-dir" {
            return Err(CargoResolutionRefusal::InvalidInvocation(
                "inline Cargo target-dir overrides escape the canonical output mount".into(),
            ));
        }
        if !matches!(key, b"net.offline" | b"build.jobs") {
            return Err(CargoResolutionRefusal::InvalidInvocation(
                "inline --config key lacks typed K015/K019 replay support".into(),
            ));
        }
        return Ok(());
    }
    validate_workspace_cli_path(value, "--config path")
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

fn validate_role_schema(entry: &CapturedCargoObject) -> Result<(), CargoResolutionRefusal> {
    let path = entry.virtual_path.as_bytes();
    let valid = match entry.role {
        CargoCapturedRole::ResolvedLockfile => {
            path == b"/__rabs/workspace/Cargo.lock" && entry.object_kind == ObjectKind::FileObject
        }
        CargoCapturedRole::CargoHomeConfig => {
            path == b"/__rabs/cargo-home/config.toml" && entry.object_kind == ObjectKind::FileObject
        }
        CargoCapturedRole::SourceSelection => {
            path.starts_with(b"/__rabs/resolution/source-selection/")
                && entry.object_kind == ObjectKind::ApplicationDefinedObject
        }
        CargoCapturedRole::RegistryIndexConfig => {
            cargo_home_scoped_path(path, b"registry/index").is_some_and(|(_, relative)| {
                relative.is_some_and(|relative| relative == b"config.json")
            }) && entry.object_kind == ObjectKind::FileObject
        }
        CargoCapturedRole::RegistryIndexEntry => {
            cargo_home_scoped_path(path, b"registry/index").is_some_and(|(_, relative)| {
                relative.is_some_and(|relative| {
                    relative.starts_with(b".cache/") && relative.len() > b".cache/".len()
                })
            }) && entry.object_kind == ObjectKind::FileObject
        }
        CargoCapturedRole::RegistryArchive => {
            cargo_home_scoped_path(path, b"registry/cache").is_some_and(|(_, relative)| {
                relative
                    .is_some_and(|archive| !archive.contains(&b'/') && archive.ends_with(b".crate"))
            }) && entry.object_kind == ObjectKind::FileObject
                && entry.content_length > 0
        }
        CargoCapturedRole::RegistrySourceTree => {
            cargo_home_scoped_path(path, b"registry/src").is_some_and(|(_, relative)| {
                relative.is_some_and(|package| !package.contains(&b'/'))
            }) && entry.object_kind == ObjectKind::DirectoryObject
        }
        CargoCapturedRole::GitDatabase => {
            cargo_home_scoped_path(path, b"git/db").is_some_and(|(_, relative)| relative.is_none())
                && entry.object_kind == ObjectKind::DirectoryObject
        }
        CargoCapturedRole::GitCheckout => {
            cargo_home_scoped_path(path, b"git/checkouts").is_some_and(|(_, relative)| {
                relative.is_some_and(|checkout| !checkout.contains(&b'/'))
            }) && entry.object_kind == ObjectKind::DirectoryObject
        }
        CargoCapturedRole::PathSource => {
            path.starts_with(b"/__rabs/repos/") && entry.object_kind == ObjectKind::SnapshotObject
        }
        CargoCapturedRole::DependencySourceManifest => {
            path.starts_with(b"/__rabs/resolution/manifests/")
                && entry.object_kind == ObjectKind::ApplicationDefinedObject
        }
    };
    if valid {
        Ok(())
    } else {
        Err(CargoResolutionRefusal::InvalidCapture(format!(
            "captured {:?} has an invalid path/object-kind pairing",
            entry.role
        )))
    }
}

fn validate_dependency_members(
    manifest: &DependencySourceManifest,
) -> Result<(), CargoResolutionRefusal> {
    for (label, value) in [
        ("source checksum", manifest.source_checksum.as_str()),
        ("Cargo checksum", manifest.cargo_checksum.as_str()),
    ] {
        if value.is_empty()
            || value
                .bytes()
                .any(|byte| byte.is_ascii_whitespace() || byte.is_ascii_control())
        {
            return Err(CargoResolutionRefusal::DependencySourceInvalid(format!(
                "dependency {label} cannot be represented unambiguously"
            )));
        }
    }
    for member in &manifest.members {
        let path = member.relative_path.as_bytes();
        if path.is_empty()
            || path.starts_with(b"/")
            || path.ends_with(b"/")
            || path.contains(&0)
            || path
                .iter()
                .any(|byte| byte.is_ascii_whitespace() || byte.is_ascii_control())
            || path
                .split(|byte| *byte == b'/')
                .any(|part| part.is_empty() || part == b"." || part == b"..")
        {
            return Err(CargoResolutionRefusal::DependencySourceInvalid(
                "dependency member path is unsafe or cannot be represented unambiguously".into(),
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

fn captured_closure_binding(objects: &[CapturedCargoObject]) -> TypedDigest {
    let mut encoder = CanonicalEncoder::new();
    encoder.u32(CARGO_RESOLUTION_SCHEMA_VERSION);
    encoder.seq(objects, |encoder, entry| {
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
    compute(DOMAIN_CARGO_FETCH_CAPTURE, &encoder.finish())
}

fn captured_closure_root(
    objects: &[CapturedCargoObject],
) -> Result<ObjectId, CargoResolutionRefusal> {
    let binding = captured_closure_binding(objects);
    let mut encoder = CanonicalEncoder::new();
    encoder
        .u32(CARGO_RESOLUTION_SCHEMA_VERSION)
        .str(DOMAIN_CARGO_FETCH_CAPTURE);
    frame_digest(&mut encoder, &binding);
    object_id_for_bytes(&encoder.finish())
}

fn frame_authority(encoder: &mut CanonicalEncoder, authority: &NetworkAuthority) {
    let scheme = match authority.scheme() {
        NetworkScheme::Https => 1,
    };
    encoder
        .u32(scheme)
        .str(authority.host())
        .u32(u32::from(authority.port()));
}

fn frame_broker_channel(encoder: &mut CanonicalEncoder, channel: &BrokerChannel) {
    match channel {
        BrokerChannel::InheritedFd(fd) => {
            encoder.u32(1).u32(*fd);
        }
        BrokerChannel::ControlledSocket(path) => {
            encoder.u32(2).bytes(path.as_bytes());
        }
    }
}

fn object_id_for_bytes(bytes: &[u8]) -> Result<ObjectId, CargoResolutionRefusal> {
    let mut writer = StreamingObjectWriter::new(DigestRequest::default(), Some(bytes.len() as u64));
    writer.write(bytes).map_err(|error| {
        CargoResolutionRefusal::InvalidCapture(format!("object hashing failed: {error:?}"))
    })?;
    let digests = writer.finish().map_err(|error| {
        CargoResolutionRefusal::InvalidCapture(format!("object hashing failed: {error:?}"))
    })?;
    Ok(ObjectId(digests.atp_content_id))
}

fn dependency_manifest_object(
    manifest: &DependencySourceManifest,
) -> Result<ObjectId, CargoResolutionRefusal> {
    let canonical = manifest.to_canonical_lines();
    object_id_for_bytes(canonical.as_bytes()).map_err(|error| {
        CargoResolutionRefusal::DependencySourceInvalid(format!(
            "dependency manifest hashing failed: {error:?}"
        ))
    })
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

fn object_key(object: &ObjectId) -> ObjectSortKey {
    (object.0.domain, object.0.bytes)
}

fn cargo_home_scoped_path<'a>(
    path: &'a [u8],
    relative_root: &[u8],
) -> Option<(&'a [u8], Option<&'a [u8]>)> {
    let relative = path.strip_prefix(b"/__rabs/cargo-home/")?;
    let relative = relative.strip_prefix(relative_root)?.strip_prefix(b"/")?;
    if relative.is_empty() {
        return None;
    }
    match relative.iter().position(|byte| *byte == b'/') {
        Some(separator) => Some((&relative[..separator], Some(&relative[separator + 1..]))),
        None => Some((relative, None)),
    }
}

fn cargo_home_scoped_path_bytes(
    relative_root: &[u8],
    namespace: &[u8],
    suffix: Option<&[u8]>,
) -> Vec<u8> {
    let mut path = b"/__rabs/cargo-home/".to_vec();
    path.extend_from_slice(relative_root);
    path.push(b'/');
    path.extend_from_slice(namespace);
    if let Some(suffix) = suffix {
        path.push(b'/');
        path.extend_from_slice(suffix);
    }
    path
}

fn with_trailing_slash(path: &[u8]) -> Vec<u8> {
    let mut path = path.to_vec();
    path.push(b'/');
    path
}

fn sparse_index_path_matches_package(relative: &[u8], package_dir: &[u8]) -> bool {
    let Some(crate_name) = relative.rsplit(|byte| *byte == b'/').next() else {
        return false;
    };
    if crate_name.is_empty()
        || !crate_name
            .iter()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
    {
        return false;
    }
    let mut package_prefix = crate_name.to_vec();
    package_prefix.push(b'-');
    if package_dir
        .strip_prefix(package_prefix.as_slice())
        .is_none_or(<[u8]>::is_empty)
    {
        return false;
    }

    let mut expected = Vec::with_capacity(relative.len());
    match crate_name.len() {
        1 => expected.extend_from_slice(b"1/"),
        2 => expected.extend_from_slice(b"2/"),
        3 => {
            expected.extend_from_slice(b"3/");
            expected.push(crate_name[0]);
            expected.push(b'/');
        }
        _ => {
            expected.extend_from_slice(&crate_name[..2]);
            expected.push(b'/');
            expected.extend_from_slice(&crate_name[2..4]);
            expected.push(b'/');
        }
    }
    expected.extend_from_slice(crate_name);
    relative == expected
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
    path.is_absolute()
        && path.components().count() > 1
        && path.components().all(|component| {
            matches!(
                component,
                std::path::Component::RootDir | std::path::Component::Normal(_)
            )
        })
}

fn backings_overlap(left: &Path, right: &Path) -> bool {
    let left = std::fs::canonicalize(left).unwrap_or_else(|_| left.to_path_buf());
    let right = std::fs::canonicalize(right).unwrap_or_else(|_| right.to_path_buf());
    left.starts_with(&right) || right.starts_with(&left)
}

fn source_error(error: &SnapshotError) -> CargoResolutionRefusal {
    CargoResolutionRefusal::DependencySourceInvalid(format!("{error:?}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::edge::snapshot_lineage::{LineageError, RequestedCommandSnapshot};
    use rabs_cas::dependency_snapshot::SnapshotMember;
    use rabs_protocol::input_evidence::IsolationEvidenceRecord;
    use rabs_sandbox::layout;
    use rabs_sandbox::network_isolation::{
        BoundedFetchBroker, BrokerChannel, BrokerLeaseContext, BrokerObservation,
        CapabilityAuthoritySnapshot, NetworkAuthority, NetworkBudget, NetworkScheme,
        finish_brokered_fetch, prepare_brokered_fetch,
    };
    use rabs_sandbox::snapshot_capture::FsSemanticClass;

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
            object_kind: match role {
                CargoCapturedRole::RegistrySourceTree | CargoCapturedRole::GitCheckout => {
                    ObjectKind::DirectoryObject
                }
                CargoCapturedRole::PathSource => ObjectKind::SnapshotObject,
                CargoCapturedRole::SourceSelection
                | CargoCapturedRole::DependencySourceManifest => {
                    ObjectKind::ApplicationDefinedObject
                }
                _ => ObjectKind::FileObject,
            },
            content_length: 100 + u64::from(tag),
            source_identity: RawBytes::from(identity),
            resolved_checksum: checksum.map(RawBytes::from),
        }
    }

    fn invocation(args: &[&str]) -> CargoInvocation {
        CargoInvocation {
            program: RawBytes::from("/__rabs/toolchain/bin/cargo"),
            args: args.iter().map(|arg| RawBytes::from(*arg)).collect(),
        }
    }

    fn config_replay(
        session_id: u64,
        operation_id: u64,
        requested_snapshot_sha256: [u8; 32],
        invocation: &CargoInvocation,
        cargo_home_config: Option<ObjectId>,
        effective_offline: bool,
    ) -> CargoConfigReplay {
        CargoConfigReplay::from_verified_layers(
            session_id,
            operation_id,
            requested_snapshot_sha256,
            invocation.digest(),
            digest(DOMAIN_CARGO_CONFIG_PROVENANCE, 11),
            cargo_home_config,
            effective_offline,
            RawBytes::from("/__rabs/out/cargo-target"),
        )
    }

    fn authorization_context(tokens: &[CapabilityToken]) -> CargoNetworkAuthorizationContext<'_> {
        CargoNetworkAuthorizationContext {
            tokens,
            revoked_token_ids: &[],
            current_seq: 10,
            session_id: 5,
            operation_id: 9,
            requested_snapshot_sha256: [8; 32],
        }
    }

    fn authorization_config(
        invocation: &CargoInvocation,
        effective_offline: bool,
    ) -> CargoConfigReplay {
        config_replay(5, 9, [8; 32], invocation, None, effective_offline)
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

    #[derive(Debug)]
    struct TestBrokerGuard;

    struct TestBroker {
        observation: BrokerObservation,
    }

    impl BoundedFetchBroker for TestBroker {
        type Guard = TestBrokerGuard;

        fn attach(
            &mut self,
            _policy: &BoundedNetworkPolicy,
            _lease: BrokerLeaseContext,
        ) -> Result<(Self::Guard, BrokerChannel), String> {
            Ok((TestBrokerGuard, BrokerChannel::InheritedFd(7)))
        }

        fn finish(&mut self, _guard: Self::Guard) -> Result<BrokerObservation, String> {
            Ok(self.observation.clone())
        }

        fn mechanism(&self) -> &'static str {
            "edge-fetch-broker-v1"
        }
    }

    fn completed_fetch_receipt(
        capture: &CargoResolutionCapture,
        token_id: u64,
        requests: u32,
        response_bytes: u64,
    ) -> CargoFetchReceipt {
        let policy = policy();
        let token = rabs_protocol::capability_tokens::mint(
            token_id,
            rabs_protocol::capability_tokens::CapabilityKind::OpenNetwork,
            capture.session_id,
            capture.operation_id,
            &policy.scope_binding(),
            100,
        )
        .unwrap();
        let authorization = authorize_fetch_resolution(
            &capture.invocation,
            &capture.config,
            CargoFetchNeed::NetworkRequired,
            Some(policy),
            CargoNetworkAuthorizationContext {
                tokens: &[token],
                revoked_token_ids: &[],
                current_seq: 10,
                session_id: capture.session_id,
                operation_id: capture.operation_id,
                requested_snapshot_sha256: capture.requested_snapshot_sha256,
            },
        )
        .unwrap();
        let (grant, policy) = authorization
            .into_brokered()
            .expect("network-required capture needs broker authority");
        let authority = policy.authorities()[0].clone();
        let mut broker = TestBroker {
            observation: BrokerObservation {
                authorities: vec![authority],
                requests,
                redirects: 0,
                response_bytes,
            },
        };
        let lease = prepare_brokered_fetch(
            &CanonicalNamespaceSpec::new(),
            grant,
            policy,
            &mut broker,
            &[],
            11,
        )
        .unwrap();
        let network = finish_brokered_fetch(lease, || {
            Ok(CapabilityAuthoritySnapshot::new(12, Vec::new()))
        })
        .unwrap();
        complete_cargo_fetch(network, capture.closure_root.clone(), &capture.objects).unwrap()
    }

    fn manifest() -> DependencySourceManifest {
        DependencySourceManifest {
            source_checksum: "tree-sha256-abc".into(),
            cargo_checksum: "cargo-checksum-abc".into(),
            members: vec![
                SnapshotMember {
                    relative_path: ".cargo-ok".into(),
                    content_digest: digest(ATP_OBJECT_CONTENT_DOMAIN, 50),
                    executable: false,
                },
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
        let manifest_object = dependency_manifest_object(&source_manifest).unwrap();
        let manifest_length = source_manifest.to_canonical_lines().len() as u64;
        let objects = vec![
            entry(
                CargoCapturedRole::ResolvedLockfile,
                "/__rabs/workspace/Cargo.lock",
                1,
                "workspace-lockfile",
                None,
            ),
            entry(
                CargoCapturedRole::CargoHomeConfig,
                "/__rabs/cargo-home/config.toml",
                2,
                "cargo-home-config-v1",
                None,
            ),
            entry(
                CargoCapturedRole::SourceSelection,
                "/__rabs/resolution/source-selection/resolved",
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
                "/__rabs/cargo-home/registry/index/crates-io/.cache/se/rd/serde",
                5,
                "registry-package:serde@1.0.0",
                None,
            ),
            entry(
                CargoCapturedRole::RegistryArchive,
                "/__rabs/cargo-home/registry/cache/crates-io/serde-1.0.0.crate",
                6,
                "registry-package:serde@1.0.0",
                Some("cargo-checksum-abc"),
            ),
            CapturedCargoObject {
                role: CargoCapturedRole::RegistrySourceTree,
                virtual_path: RawBytes::from(
                    "/__rabs/cargo-home/registry/src/crates-io/serde-1.0.0",
                ),
                object: manifest_object.clone(),
                object_kind: ObjectKind::DirectoryObject,
                content_length: manifest_length,
                source_identity: RawBytes::from("registry-package:serde@1.0.0"),
                resolved_checksum: Some(RawBytes::from("cargo-checksum-abc")),
            },
            CapturedCargoObject {
                role: CargoCapturedRole::DependencySourceManifest,
                virtual_path: RawBytes::from("/__rabs/resolution/manifests/serde-1.0.0.manifest"),
                object: manifest_object.clone(),
                object_kind: ObjectKind::ApplicationDefinedObject,
                content_length: manifest_length,
                source_identity: RawBytes::from("registry-package:serde@1.0.0"),
                resolved_checksum: Some(RawBytes::from("cargo-checksum-abc")),
            },
        ];
        let closure_root = captured_closure_root(&objects).unwrap();
        let invocation = invocation(&["build", "--locked"]);
        let config = config_replay(5, 77, [9; 32], &invocation, Some(object(2)), false);
        CargoResolutionCapture {
            schema_version: CARGO_RESOLUTION_SCHEMA_VERSION,
            session_id: 5,
            operation_id: 77,
            fetch_need: CargoFetchNeed::CapturedClosureComplete,
            requested_snapshot_sha256: [9; 32],
            invocation,
            toolchain_contract: digest(DOMAIN_TOOLCHAIN_CONTRACT, 10),
            config,
            initial_lockfile: InitialLockfile::Present(object(1)),
            objects,
            closure_root,
            verified_sources: vec![VerifiedDependencySource {
                source_tree: manifest_object.clone(),
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
            max_metadata_bytes: 1_000_000,
            max_source_members: 10_000,
        }
    }

    fn materialization(
        capture: &CargoResolutionCapture,
        backing: &str,
    ) -> CargoHomeMaterialization {
        CargoHomeMaterialization::from_verified_scan(
            capture.session_id,
            capture.operation_id,
            1,
            PathBuf::from(backing),
            capture.closure_root.clone(),
            capture
                .objects
                .iter()
                .filter(|entry| {
                    entry
                        .virtual_path
                        .as_bytes()
                        .starts_with(b"/__rabs/cargo-home/")
                })
                .map(MaterializedCargoObject::from_capture)
                .collect(),
            true,
        )
    }

    fn writable(
        capture: &CargoResolutionCapture,
        root: &str,
        generation: u64,
    ) -> CargoWritableMaterialization {
        CargoWritableMaterialization::from_verified_empty_roots(
            capture.session_id,
            capture.operation_id,
            generation,
            PathBuf::from(root).join("home"),
            PathBuf::from(root).join("target"),
            true,
            true,
        )
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

    fn validation(
        capture: &CargoResolutionCapture,
        writable: &CargoWritableMaterialization,
    ) -> OfflineValidationEvidence {
        OfflineValidationEvidence::from_completed_launch(
            capture.session_id,
            capture.operation_id,
            1,
            writable.generation,
            capture.invocation.digest(),
            capture.config.digest(),
            capture.toolchain_contract.clone(),
            capture.requested_snapshot_sha256,
            capture.closure_root.clone(),
            capture
                .required_object(CargoCapturedRole::ResolvedLockfile)
                .unwrap()
                .clone(),
            capture
                .required_object(CargoCapturedRole::SourceSelection)
                .unwrap()
                .clone(),
            isolation(),
        )
    }

    fn workspace_provenance(capture: &CargoResolutionCapture) -> SnapshotProvenance {
        SnapshotProvenance {
            snapshot_root: "workspace".into(),
            fs_class: FsSemanticClass::GenerationScan,
            manifest_sha256: capture.requested_snapshot_sha256,
        }
    }

    fn seal(
        capture: &CargoResolutionCapture,
        backing: &str,
    ) -> Result<OfflineCanonicalPlan, CargoResolutionRefusal> {
        let mut lineage = SnapshotLineage::new(RequestedCommandSnapshot {
            manifest_sha256: capture.requested_snapshot_sha256,
        });
        let materialization = materialization(capture, backing);
        let validation_writable = writable(capture, &format!("{backing}-validation"), 1);
        let validation = validation(capture, &validation_writable);
        let execution_writable = writable(capture, &format!("{backing}-execution"), 2);
        seal_offline_resolution(
            &mut lineage,
            capture,
            limits(),
            &materialization,
            &validation_writable,
            &validation,
            &execution_writable,
            "/store/toolchain",
            "/store/workspace",
            workspace_provenance(capture),
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
        assert!(!a.namespace_spec().allows_network());
        assert!(!b.namespace_spec().allows_network());
    }

    #[test]
    fn captured_object_change_changes_resolution_identity() {
        let base = capture();
        let mut changed = base.clone();
        changed.objects[4].object = object(55);
        changed.closure_root = captured_closure_root(&changed.objects).unwrap();
        let a = seal(&base, "/attempt/a/cargo-home").unwrap();
        let b = seal(&changed, "/attempt/b/cargo-home").unwrap();
        assert_ne!(a.record().resolution_digest, b.record().resolution_digest);
    }

    #[test]
    fn network_required_without_capability_refuses_with_explanation() {
        let invocation = invocation(&["build", "--locked"]);
        let config = authorization_config(&invocation, false);
        let err = authorize_fetch_resolution(
            &invocation,
            &config,
            CargoFetchNeed::NetworkRequired,
            Some(policy()),
            authorization_context(&[]),
        )
        .unwrap_err();
        assert!(matches!(
            err,
            CargoResolutionRefusal::NetworkCapabilityRequired { explanation }
                if explanation.contains("uncaptured bytes")
        ));
    }

    #[test]
    fn config_replay_must_bind_snapshot_and_exact_invocation_before_authorization() {
        let actual_invocation = invocation(&["build"]);
        let wrong_invocation = invocation(&["check"]);
        let config = authorization_config(&wrong_invocation, false);
        assert!(matches!(
            authorize_fetch_resolution(
                &actual_invocation,
                &config,
                CargoFetchNeed::CapturedClosureComplete,
                None,
                authorization_context(&[]),
            ),
            Err(CargoResolutionRefusal::InvalidConfigReplay(_))
        ));

        let config = config_replay(5, 9, [7; 32], &actual_invocation, None, false);
        assert!(matches!(
            authorize_fetch_resolution(
                &actual_invocation,
                &config,
                CargoFetchNeed::CapturedClosureComplete,
                None,
                authorization_context(&[]),
            ),
            Err(CargoResolutionRefusal::InvalidConfigReplay(_))
        ));
    }

    #[test]
    fn effective_offline_config_never_exercises_valid_capability() {
        let invocation = invocation(&["build"]);
        let config = authorization_config(&invocation, true);
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
                &invocation,
                &config,
                CargoFetchNeed::NetworkRequired,
                Some(policy),
                authorization_context(&[token]),
            ),
            Err(CargoResolutionRefusal::UserForbidsNetwork { .. })
        ));
    }

    #[test]
    fn invocation_admission_refuses_unbound_programs_subcommands_and_path_escapes() {
        for invalid in [
            CargoInvocation {
                program: RawBytes::from("cargo"),
                args: vec![RawBytes::from("build")],
            },
            invocation(&["+nightly", "build"]),
            invocation(&["clean"]),
            invocation(&["build", "-Zunstable-options"]),
            invocation(&["build", "--target-dir=/tmp/out"]),
            invocation(&["build", "--lockfile-path", "/tmp/Cargo.lock"]),
            invocation(&["build", "--artifact-dir=/tmp/out"]),
            invocation(&["build", "--manifest-path", "/usr/src/Cargo.toml"]),
            invocation(&["build", "--manifest-path", "../other/Cargo.toml"]),
            invocation(&["build", "--config", "build.target-dir='/tmp/out'"]),
            invocation(&["build", "--config", "source.crates-io.replace-with='other'"]),
        ] {
            assert!(matches!(
                invalid.validate(),
                Err(CargoResolutionRefusal::InvalidInvocation(_))
            ));
        }

        assert!(
            invocation(&[
                "--frozen",
                "build",
                "--manifest-path=/__rabs/workspace/member/Cargo.toml",
                "--config",
                "build.jobs=2",
            ])
            .validate()
            .is_ok()
        );
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
            let invocation = invocation(&argv);
            let config = authorization_config(&invocation, false);
            assert!(matches!(
                authorize_fetch_resolution(
                    &invocation,
                    &config,
                    CargoFetchNeed::NetworkRequired,
                    Some(policy),
                    authorization_context(&[token]),
                ),
                Err(CargoResolutionRefusal::UserForbidsNetwork { .. })
            ));
        }
    }

    #[test]
    fn program_arguments_after_separator_do_not_change_cargo_network_policy() {
        let config = authorization_config(&invocation(&["build"]), false);
        assert!(!invocation(&["test", "--", "--offline"]).forbids_network(&config));
        assert!(!invocation(&["run", "--", "--frozen"]).forbids_network(&config));
        assert!(invocation(&["test", "--offline", "--", "filter"]).forbids_network(&config));
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
        let original = invocation(&["build", "--locked", "--config", "build.jobs=2"]);
        let config = authorization_config(&original, false);
        let authorization = authorize_fetch_resolution(
            &original,
            &config,
            CargoFetchNeed::NetworkRequired,
            Some(policy.clone()),
            authorization_context(&[token]),
        )
        .unwrap();
        let (grant, admitted) = authorization
            .into_brokered()
            .expect("network-required resolution must produce broker authorization");
        assert_eq!(grant.scope(), policy.scope_binding());
        assert_eq!(admitted, policy);
        assert_eq!(original.args[1].as_bytes(), b"--locked");
        assert!(
            !original
                .args
                .iter()
                .any(|arg| arg.as_bytes() == b"--offline")
        );
    }

    #[test]
    fn closure_complete_preserves_user_offline_flag_without_capability_use() {
        let original = invocation(&["build", "--offline"]);
        let config = authorization_config(&original, false);
        assert_eq!(
            authorize_fetch_resolution(
                &original,
                &config,
                CargoFetchNeed::CapturedClosureComplete,
                None,
                authorization_context(&[]),
            ),
            Ok(CargoFetchAuthorization::CapturedClosure)
        );
        let mut capture = capture();
        capture.invocation = original.clone();
        capture.config = config_replay(
            capture.session_id,
            capture.operation_id,
            capture.requested_snapshot_sha256,
            &original,
            Some(object(2)),
            false,
        );
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
        let validation_writable = writable(&capture, "/attempt/a/validation", 1);
        let validation = validation(&capture, &validation_writable);
        let execution_writable = writable(&capture, "/attempt/a/execution", 2);
        let err = seal_offline_resolution(
            &mut lineage,
            &capture,
            limits(),
            &home,
            &validation_writable,
            &validation,
            &execution_writable,
            "/store/toolchain",
            "/store/workspace",
            workspace_provenance(&capture),
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
    fn validation_and_execution_require_disjoint_fresh_writable_generations() {
        let capture = capture();
        let materialization = materialization(&capture, "/attempt/a/cargo-home");
        let validation_writable = writable(&capture, "/attempt/a/validation", 1);
        let validation = validation(&capture, &validation_writable);

        for execution_writable in [
            writable(&capture, "/attempt/a/execution", 1),
            writable(&capture, "/attempt/a/validation", 2),
            writable(&capture, "/attempt/a/cargo-home/nested", 2),
        ] {
            let mut lineage = SnapshotLineage::new(RequestedCommandSnapshot {
                manifest_sha256: capture.requested_snapshot_sha256,
            });
            assert!(matches!(
                seal_offline_resolution(
                    &mut lineage,
                    &capture,
                    limits(),
                    &materialization,
                    &validation_writable,
                    &validation,
                    &execution_writable,
                    "/store/toolchain",
                    "/store/workspace",
                    workspace_provenance(&capture),
                ),
                Err(CargoResolutionRefusal::InvalidWritableMaterialization(_))
            ));
            assert_eq!(
                lineage.register_action("compile-serde"),
                Err(LineageError::NotSealed)
            );
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn physical_backing_alias_check_uses_existing_canonical_identity() {
        assert!(backings_overlap(
            Path::new("/tmp"),
            Path::new("/proc/self/root/tmp")
        ));
    }

    #[test]
    fn offline_validation_must_prove_network_denial() {
        let capture = capture();
        let validation_writable = writable(&capture, "/attempt/a/validation", 1);
        let mut evidence = validation(&capture, &validation_writable);
        let execution_writable = writable(&capture, "/attempt/a/execution", 2);
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
                &validation_writable,
                &evidence,
                &execution_writable,
                "/store/toolchain",
                "/store/workspace",
                workspace_provenance(&capture),
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

        let mut ambiguous_member = manifest();
        ambiguous_member.members[1].relative_path =
            "Cargo.toml rabs.object.v1 deadbeef 0\nmember injected".into();
        assert!(matches!(
            validate_dependency_members(&ambiguous_member),
            Err(CargoResolutionRefusal::DependencySourceInvalid(message))
                if message.contains("unambiguously")
        ));

        let mut ambiguous_checksum = manifest();
        ambiguous_checksum.cargo_checksum = "cargo-checksum-abc\nmember injected".into();
        assert!(matches!(
            validate_dependency_members(&ambiguous_checksum),
            Err(CargoResolutionRefusal::DependencySourceInvalid(message))
                if message.contains("unambiguously")
        ));
    }

    #[test]
    fn cargo_cache_readiness_requires_sparse_layout_archive_and_marker() {
        let mut wrong_sparse_path = capture();
        wrong_sparse_path.objects[4].virtual_path =
            RawBytes::from("/__rabs/cargo-home/registry/index/crates-io/se/rd/serde");
        assert!(matches!(
            wrong_sparse_path.validate_cargo_cache_readiness(),
            Err(CargoResolutionRefusal::InvalidCapture(message))
                if message.contains(".cache")
        ));

        let mut unrelated_sparse_entry = capture();
        unrelated_sparse_entry.objects[4].virtual_path =
            RawBytes::from("/__rabs/cargo-home/registry/index/crates-io/.cache/ra/nd/rand");
        assert!(matches!(
            unrelated_sparse_entry.validate_cargo_cache_readiness(),
            Err(CargoResolutionRefusal::InvalidCapture(message))
                if message.contains("package-bound")
        ));

        let mut wrong_sparse_identity = capture();
        wrong_sparse_identity.objects[4].source_identity =
            RawBytes::from("registry-package:other@1.0.0");
        assert!(matches!(
            wrong_sparse_identity.validate_cargo_cache_readiness(),
            Err(CargoResolutionRefusal::InvalidCapture(message))
                if message.contains("package-bound")
        ));

        let mut missing_archive = capture();
        missing_archive
            .objects
            .retain(|entry| entry.role != CargoCapturedRole::RegistryArchive);
        assert!(matches!(
            missing_archive.validate_cargo_cache_readiness(),
            Err(CargoResolutionRefusal::InvalidCapture(message))
                if message.contains(".crate archive")
        ));

        let mut missing_marker = capture();
        missing_marker.verified_sources[0]
            .manifest
            .members
            .retain(|member| member.relative_path != ".cargo-ok");
        assert!(matches!(
            missing_marker.validate_cargo_cache_readiness(),
            Err(CargoResolutionRefusal::DependencySourceInvalid(message))
                if message.contains(".cargo-ok")
        ));

        let mut git = capture();
        let tree = git
            .objects
            .iter_mut()
            .find(|entry| entry.role == CargoCapturedRole::RegistrySourceTree)
            .unwrap();
        tree.role = CargoCapturedRole::GitCheckout;
        tree.virtual_path =
            RawBytes::from("/__rabs/cargo-home/git/checkouts/example-a1b2c3d4/deadbeef");
        tree.source_identity = RawBytes::from("git+https://example.invalid/repo#deadbeef");
        tree.resolved_checksum = Some(RawBytes::from("deadbeef"));
        git.verified_sources[0].resolved_checksum = "deadbeef".into();
        assert!(matches!(
            git.validate_cargo_cache_readiness(),
            Err(CargoResolutionRefusal::InvalidCapture(message))
                if message.contains("locked-revision database")
        ));
        git.objects.push(CapturedCargoObject {
            role: CargoCapturedRole::GitDatabase,
            virtual_path: RawBytes::from("/__rabs/cargo-home/git/db/example-a1b2c3d4"),
            object: object(70),
            object_kind: ObjectKind::DirectoryObject,
            content_length: 1,
            source_identity: RawBytes::from("git+https://example.invalid/repo#deadbeef"),
            resolved_checksum: Some(RawBytes::from("deadbeef")),
        });
        assert_eq!(git.validate_cargo_cache_readiness(), Ok(()));

        let mut path_source = capture();
        path_source.objects.push(entry(
            CargoCapturedRole::PathSource,
            "/__rabs/repos/local-dependency",
            71,
            "repo:local-dependency",
            None,
        ));
        assert!(matches!(
            path_source.validate_cargo_cache_readiness(),
            Err(CargoResolutionRefusal::InvalidCapture(message))
                if message.contains("path-source replay")
        ));
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
        let validation_writable = writable(&capture, "/attempt/a/validation", 1);
        let validation = validation(&capture, &validation_writable);
        let execution_writable = writable(&capture, "/attempt/a/execution", 2);
        let plan = seal_offline_resolution(
            &mut lineage,
            &capture,
            limits(),
            &materialization(&capture, "/attempt/a/cargo-home"),
            &validation_writable,
            &validation,
            &execution_writable,
            "/store/toolchain",
            "/store/workspace",
            workspace_provenance(&capture),
        )
        .unwrap();
        let binding = lineage.register_action("compile-serde").unwrap();
        assert_eq!(binding.sealed, plan.sealed());
        assert_eq!(
            binding.sealed.resolution_sha256,
            plan.record().resolution_digest.bytes
        );
        assert!(
            plan.namespace_spec()
                .ro_binds
                .iter()
                .any(|bind| { bind.visible == std::path::Path::new(layout::WORKSPACE) })
        );
        assert!(
            plan.namespace_spec()
                .ro_binds
                .iter()
                .any(|bind| { bind.visible == std::path::Path::new(layout::CARGO_HOME) })
        );
        assert!(!plan.namespace_spec().rw_binds.iter().any(|bind| {
            matches!(
                bind.visible.to_str(),
                Some(layout::WORKSPACE | layout::CARGO_HOME)
            )
        }));
        assert!(
            plan.namespace_spec()
                .rw_binds
                .iter()
                .any(|bind| { bind.visible == std::path::Path::new("/__rabs/out/cargo-target") })
        );
        assert!(plan.namespace_spec().env.iter().any(|(key, value)| {
            key == "CARGO_TARGET_DIR" && value == "/__rabs/out/cargo-target"
        }));
    }

    #[test]
    fn invalid_canonical_plan_refuses_without_sealing_lineage() {
        let capture = capture();
        let mut lineage = SnapshotLineage::new(RequestedCommandSnapshot {
            manifest_sha256: capture.requested_snapshot_sha256,
        });
        let validation_writable = writable(&capture, "/attempt/a/validation", 1);
        let validation = validation(&capture, &validation_writable);
        let execution_writable = writable(&capture, "/attempt/a/execution", 2);
        let result = seal_offline_resolution(
            &mut lineage,
            &capture,
            limits(),
            &materialization(&capture, "/attempt/a/cargo-home"),
            &validation_writable,
            &validation,
            &execution_writable,
            "/store/workspace",
            "/store/workspace",
            workspace_provenance(&capture),
        );
        assert!(matches!(
            result,
            Err(CargoResolutionRefusal::CanonicalPlanInvalid(_))
        ));
        assert_eq!(
            lineage.register_action("compile-serde"),
            Err(LineageError::NotSealed)
        );
    }

    #[cfg(unix)]
    #[test]
    fn offline_plan_executes_the_original_non_utf8_argv_without_projection() {
        use std::os::unix::ffi::OsStrExt;

        let mut capture = capture();
        capture.invocation = CargoInvocation {
            program: RawBytes::from("/__rabs/toolchain/bin/cargo"),
            args: vec![
                RawBytes::from("test"),
                RawBytes::from("--"),
                RawBytes::new(b"filter-\xFE".to_vec()),
            ],
        };
        capture.config = config_replay(
            capture.session_id,
            capture.operation_id,
            capture.requested_snapshot_sha256,
            &capture.invocation,
            Some(object(2)),
            false,
        );
        let plan = seal(&capture, "/attempt/raw/cargo-home").unwrap();
        let support = HostIsolationSupport {
            bubblewrap: Some("bubblewrap 0.11.1".into()),
            unprivileged_userns: true,
            overlayfs: true,
            cgroup_v2: true,
            landlock: true,
        };
        let launch = plan.namespace_launch(&support).unwrap();
        let command_separator = launch
            .argv
            .iter()
            .position(|arg| arg.as_os_str() == std::ffi::OsStr::new("--"))
            .unwrap();
        assert_eq!(
            launch.argv[command_separator + 1].as_os_str().as_bytes(),
            capture.invocation.program.as_bytes()
        );
        assert_eq!(
            launch.argv[command_separator + 4].as_os_str().as_bytes(),
            capture.invocation.args[2].as_bytes()
        );
    }

    #[test]
    fn attempt_paths_and_fetch_receipt_ids_do_not_fragment_resolution_identity() {
        let mut a = capture();
        let mut b = a.clone();
        a.fetch_need = CargoFetchNeed::NetworkRequired;
        a.fetch_receipt = Some(completed_fetch_receipt(&a, 7, 3, 500));
        b.fetch_need = CargoFetchNeed::NetworkRequired;
        b.fetch_receipt = Some(completed_fetch_receipt(&b, 8, 4, 700));
        let pa = seal(&a, "/attempt/a/cargo-home").unwrap();
        let pb = seal(&b, "/different/physical/path").unwrap();
        assert_eq!(pa.record().resolution_digest, pb.record().resolution_digest);
        assert_ne!(
            pa.record().fetch_receipt_object,
            pb.record().fetch_receipt_object
        );
    }

    #[test]
    fn fetch_receipt_from_another_session_cannot_seal() {
        let mut capture = capture();
        let mut other = capture.clone();
        other.session_id += 1;
        other.config = config_replay(
            other.session_id,
            other.operation_id,
            other.requested_snapshot_sha256,
            &other.invocation,
            Some(object(2)),
            false,
        );
        capture.fetch_need = CargoFetchNeed::NetworkRequired;
        capture.fetch_receipt = Some(completed_fetch_receipt(&other, 7, 3, 500));
        assert!(matches!(
            seal(&capture, "/attempt/wrong-session/cargo-home"),
            Err(CargoResolutionRefusal::InvalidCapture(message))
                if message.contains("exact captured closure")
        ));
    }
}
