//! One canonical operation's committed Rust artifact installation witnesses.
//!
//! Neither a path, a digest memo, a published-but-uninstalled output nor a raw
//! completion can mint a witness. The published-result installation owners call
//! this registry only after verifying actual files in place. Metadata is
//! registered before notifying Cargo; archives require complete installation.

use super::{CanonicalPaths, ordinary_absolute};
use crate::coord::canonical_local::RestoredTargetProvenance;
use crate::coord::live::CoordLive;
use crate::coord::live_dependency::remote::{QualifiedImmutableDependencyLeaf, RemoteValidation};
use crate::coord::live_dependency::{
    KnownOutput, LiveDependencyRequest, committed_output, known_installed_output, object_id,
};
use crate::edge::live_facts::{DependencyFacts, FileSig};
use rabs_cas::digest_set::ATP_OBJECT_CONTENT_DOMAIN;
use rabs_cas::manifest_codec::encode_manifest_v1;
use rabs_cas::metadata_store::digest_key;
use rabs_cas::publication::ProvisionalAncestorRef;
use rabs_key::live_dependency::DependencySourceKind;
use rabs_key::live_dependency::workspace_dependency_cache::{
    CommittedDependencyPolicy, CommittedWorkspaceDependency,
    committed_dependency_descriptor_policy, validate_committed_workspace_dependencies,
};
use rabs_key::typed_digest::{DOMAIN_ACTION_KEY, DOMAIN_DESCRIPTOR};
use rabs_protocol::authority::CoordinatorAuthority;
use rabs_protocol::raw_bytes::RawBytes;
use rabs_protocol::result_identity::{
    CanonicalActionResultManifest, DigestAlgorithm, ObjectId, OutputRole, TypedDigest,
};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::io;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, Weak};

// Several profiles/directories can occur within an operation. A full registry
// stops minting entries; future consumers safely retain fresh execution.
const MAX_COMMITTED_OUTPUTS: usize = 16_384;
const TARGET_ROOT: &str = "/__rabs/out/cargo";
const MAX_SEED_PATH_BYTES: usize = 4096;

#[derive(Debug, Clone)]
struct InstalledProducer {
    generation: FileSig,
    authority: CoordinatorAuthority,
    dependency: CommittedWorkspaceDependency,
}

#[derive(Debug, Default)]
pub(super) struct CommittedOutputs(Mutex<BTreeMap<PathBuf, InstalledProducer>>);

/// Historical installation provenance carried by one private target seed.
///
/// These serialized facts confer no current file or coordinator authority.
/// Only the target-state owner can bind a verified restored tree to them; a
/// subsequent rehydration checks actual bytes and current producer safety.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct CommittedOutputSeeds {
    outputs: Vec<CommittedOutputSeed>,
}

/// A changed local output can prevent optional retention without invalidating
/// the completed build. Revoked known producers cannot: Cargo may have reused
/// those bytes without executing a wrapper that would recheck their lineage.
#[derive(Debug)]
pub(crate) enum CommittedOutputExportError {
    CannotRetain(String),
    InvalidProducer(String),
}

impl std::fmt::Display for CommittedOutputExportError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::CannotRetain(reason) | Self::InvalidProducer(reason) => {
                formatter.write_str(reason)
            }
        }
    }
}

impl std::error::Error for CommittedOutputExportError {}

/// The format fixes each digest field's algorithm and domain. Stored text can
/// neither invent a digest domain nor reinterpret another class of object.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct CommittedOutputSeed {
    path: String,
    producer_action: [u8; 32],
    producer_descriptor: [u8; 32],
    producer_manifest: [u8; 32],
    role: SeedRole,
    virtual_path: Vec<u8>,
    object: [u8; 32],
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
enum SeedRole {
    Metadata,
    Archive,
}

impl CommittedOutputSeed {
    fn from_dependency(dependency: &CommittedWorkspaceDependency) -> Result<Self, String> {
        let bytes = |digest: &TypedDigest, domain: &'static str| -> Result<[u8; 32], String> {
            if digest.algorithm != DigestAlgorithm::Sha256V1 || digest.domain != domain {
                return Err("committed target provenance has an unexpected digest domain".into());
            }
            Ok(digest.bytes)
        };
        Ok(Self {
            path: dependency.path.clone(),
            producer_action: bytes(&dependency.producer_action, DOMAIN_ACTION_KEY)?,
            producer_descriptor: bytes(&dependency.producer_descriptor, DOMAIN_DESCRIPTOR)?,
            producer_manifest: bytes(&dependency.producer_manifest, ATP_OBJECT_CONTENT_DOMAIN)?,
            role: match dependency.role {
                OutputRole::ProvisionalMetadata => SeedRole::Metadata,
                OutputRole::Materializable => SeedRole::Archive,
                _ => return Err("committed target provenance is not a Rust artifact".into()),
            },
            virtual_path: dependency.virtual_path.as_bytes().to_vec(),
            object: bytes(&dependency.object.0, ATP_OBJECT_CONTENT_DOMAIN)?,
        })
    }

    fn dependency(&self) -> CommittedWorkspaceDependency {
        let digest = |domain: &'static str, bytes: [u8; 32]| TypedDigest {
            algorithm: DigestAlgorithm::Sha256V1,
            domain,
            bytes,
        };
        CommittedWorkspaceDependency {
            path: self.path.clone(),
            producer_action: digest(DOMAIN_ACTION_KEY, self.producer_action),
            producer_descriptor: digest(DOMAIN_DESCRIPTOR, self.producer_descriptor),
            producer_manifest: digest(ATP_OBJECT_CONTENT_DOMAIN, self.producer_manifest),
            role: match self.role {
                SeedRole::Metadata => OutputRole::ProvisionalMetadata,
                SeedRole::Archive => OutputRole::Materializable,
            },
            virtual_path: RawBytes::from(self.virtual_path.as_slice()),
            object: ObjectId(digest(ATP_OBJECT_CONTENT_DOMAIN, self.object)),
        }
    }

    fn relative_path(&self) -> Result<&Path, String> {
        let path = Path::new(&self.path);
        if self.path.len() > MAX_SEED_PATH_BYTES || !ordinary_absolute(path) {
            return Err("committed target provenance path is not normalized".into());
        }
        let relative = path
            .strip_prefix(TARGET_ROOT)
            .map_err(|_| "committed target provenance is outside the Cargo target")?;
        let name = relative
            .file_name()
            .and_then(|name| name.to_str())
            .ok_or("committed target provenance has no artifact basename")?;
        let suffix = match self.role {
            SeedRole::Metadata => ".rmeta",
            SeedRole::Archive => ".rlib",
        };
        if name.as_bytes() != self.virtual_path.as_slice() || !name.ends_with(suffix) {
            return Err("committed target provenance role or output spelling differs".into());
        }
        Ok(relative)
    }
}

impl CommittedOutputSeeds {
    pub(crate) fn is_empty(&self) -> bool {
        self.outputs.is_empty()
    }

    pub(crate) fn len(&self) -> usize {
        self.outputs.len()
    }

    pub(crate) fn validate(&self) -> Result<(), String> {
        if self.outputs.len() > MAX_COMMITTED_OUTPUTS {
            return Err("committed target provenance exceeds its output bound".into());
        }
        let mut previous: Option<&str> = None;
        for output in &self.outputs {
            output.relative_path()?;
            if previous.is_some_and(|previous| previous >= output.path.as_str()) {
                return Err("committed target provenance is not uniquely ordered".into());
            }
            previous = Some(output.path.as_str());
        }
        Ok(())
    }

    /// Check the privately copied target before publishing its seed. This does
    /// not mint witnesses; it prevents a changed capture from replacing a good
    /// seed with provenance referring to bytes that were never saved.
    pub(crate) fn verify_target(
        &self,
        target: &Path,
        stopped: &dyn Fn() -> bool,
    ) -> io::Result<()> {
        checkpoint(stopped)?;
        self.validate().map_err(io::Error::other)?;
        let before = std::fs::symlink_metadata(target)?;
        if !before.is_dir() {
            return Err(io::Error::other(
                "committed target provenance requires an ordinary target directory",
            ));
        }
        for output in &self.outputs {
            checkpoint(stopped)?;
            let mut physical = target.to_path_buf();
            for component in output
                .relative_path()
                .map_err(io::Error::other)?
                .components()
            {
                physical.push(component.as_os_str());
                if std::fs::symlink_metadata(&physical)?
                    .file_type()
                    .is_symlink()
                {
                    return Err(io::Error::other(
                        "committed target provenance traverses a symlink",
                    ));
                }
            }
            let installed = known_installed_output(&physical, &output.dependency().object.0)
                .map_err(io::Error::other)?;
            if installed.sig.size() == 0 {
                return Err(io::Error::other(
                    "committed target provenance contains an empty Rust artifact",
                ));
            }
        }
        checkpoint(stopped)?;
        let after = std::fs::symlink_metadata(target)?;
        if !after.is_dir() || (before.dev(), before.ino()) != (after.dev(), after.ino()) {
            return Err(io::Error::other(
                "committed target provenance root changed during verification",
            ));
        }
        Ok(())
    }
}

fn checkpoint(stopped: &dyn Fn() -> bool) -> io::Result<()> {
    if stopped() {
        Err(io::Error::new(
            io::ErrorKind::Interrupted,
            "committed target provenance verification cancelled",
        ))
    } else {
        Ok(())
    }
}

/// Opaque proof for one original dependency observation. Only the canonical
/// operation can construct it from verified committed installations. Neither
/// equal bytes nor a refreshed observation can substitute another generation.
#[derive(Debug)]
pub struct CommittedWorkspaceInputs {
    paths: Arc<CanonicalPaths>,
    observed: Arc<DependencyFacts>,
    consumer_policy: CommittedDependencyPolicy,
    coordinator: Weak<CoordLive>,
    authority: CoordinatorAuthority,
    generations: Vec<(PathBuf, FileSig)>,
    dependencies: Vec<CommittedWorkspaceDependency>,
}

impl CommittedWorkspaceInputs {
    pub(crate) fn policy(&self) -> CommittedDependencyPolicy {
        self.consumer_policy
    }

    pub(crate) fn dependencies(&self) -> &[CommittedWorkspaceDependency] {
        &self.dependencies
    }

    pub(crate) fn verify(&self, request: &LiveDependencyRequest) -> Result<(), String> {
        self.consumer_policy
            .validate_plan(&request.plan)
            .map_err(|error| error.to_string())?;
        if committed_dependency_descriptor_policy(&request.key.descriptor)
            != Some(self.consumer_policy)
            || !Arc::ptr_eq(&self.observed, &request.dependencies)
            || request
                .canonical_paths
                .as_ref()
                .is_none_or(|paths| !Arc::ptr_eq(paths, &self.paths))
        {
            return Err("committed dependency capability belongs to another request owner".into());
        }
        self.verify_original()
    }

    /// A broader metadata producer profile cannot lend its capability to the
    /// independently keyed archive class, even for the same observed files.
    pub(crate) fn verify_for_policy(
        &self,
        consumer_policy: CommittedDependencyPolicy,
    ) -> Result<(), String> {
        if consumer_policy != self.consumer_policy {
            return Err("committed dependency capability belongs to another consumer class".into());
        }
        self.verify_original()
    }

    /// Historical commit is insufficient: original generations and current
    /// transitive producer safety are rechecked at every live boundary.
    pub(crate) fn verify_original(&self) -> Result<(), String> {
        let coordinator = self
            .coordinator
            .upgrade()
            .ok_or("committed dependency coordinator no longer exists")?;
        if coordinator.authority().as_ref() != Some(&self.authority) {
            return Err("committed dependency coordinator authority changed".into());
        }
        let candidates = self.observed.candidate_generations()?;
        if candidates.len() != self.generations.len() || candidates.len() != self.dependencies.len()
        {
            return Err("committed dependency inventory changed".into());
        }
        for (((path, generation, digest), (expected_path, expected_generation)), dependency) in
            candidates
                .iter()
                .zip(&self.generations)
                .zip(&self.dependencies)
        {
            if path != expected_path
                || generation != expected_generation
                || digest != &dependency.object.0
                || self.paths.physical(Path::new(&dependency.path))? != *path
            {
                return Err("committed dependency generation changed after capture".into());
            }
        }
        coordinator.verify_committed_dependencies(&self.dependencies, self.consumer_policy)?;
        self.observed.verify_unchanged()
    }

    /// Reuse H028's durable ancestry for already committed exact objects. No
    /// provisional reader obligation or adoption authority is introduced.
    pub(crate) fn ancestors(&self) -> Vec<ProvisionalAncestorRef> {
        let mut seen = BTreeSet::new();
        self.dependencies
            .iter()
            .filter_map(|dependency| {
                let role = match dependency.role {
                    OutputRole::ProvisionalMetadata => "provisional-metadata",
                    OutputRole::Materializable => "materializable",
                    _ => return None,
                };
                let identity = (
                    digest_key(&dependency.producer_action),
                    role,
                    dependency.virtual_path.as_bytes().to_vec(),
                );
                if !seen.insert(identity) {
                    return None;
                }
                Some(ProvisionalAncestorRef {
                    producer_action_key: dependency.producer_action.clone(),
                    role: dependency.role,
                    virtual_path: dependency.virtual_path.clone(),
                    consumed_object: dependency.object.clone(),
                })
            })
            .collect()
    }
}

impl CanonicalPaths {
    /// Recheck every registered producer at operation completion, including
    /// Cargo Fresh outputs and builds that do not retain a private target.
    /// This checks current publication standing, not optional seed eligibility:
    /// a changed local file must not hide another producer's revoked ancestry.
    /// No physical output lookup is needed, so the barrier remains valid after
    /// the completed target moves to its independent output owner.
    pub(crate) fn verify_completed_producers(
        &self,
        coordinator: &Arc<CoordLive>,
        stopped: &dyn Fn() -> bool,
    ) -> io::Result<()> {
        checkpoint(stopped)?;
        let authority = coordinator
            .authority()
            .ok_or_else(|| io::Error::other("completed target has no coordinator authority"))?;
        let dependencies = {
            let registered = self
                .committed_outputs
                .0
                .lock()
                .map_err(|_| io::Error::other("committed output registry poisoned"))?;
            if registered
                .values()
                .any(|witness| witness.authority != authority)
            {
                return Err(io::Error::other(
                    "completed target lost its original coordinator authority",
                ));
            }
            registered
                .values()
                .map(|witness| witness.dependency.clone())
                .collect::<Vec<_>>()
        };
        let verified = Self::verify_seed_producers(coordinator, &authority, &dependencies, stopped);
        // Cancellation can arrive while the durable lineage check is running.
        // Preserve its terminal Interrupted classification instead of turning
        // it into an optional target-retention warning or a generic refusal.
        checkpoint(stopped)?;
        verified.map_err(|error| match error {
            CommittedOutputExportError::CannotRetain(reason) => {
                io::Error::new(io::ErrorKind::Interrupted, reason)
            }
            CommittedOutputExportError::InvalidProducer(reason) => io::Error::other(format!(
                "completed target provenance is no longer valid: {reason}"
            )),
        })
    }

    /// Capture only this operation's verified installed producers after Cargo
    /// and publication writers drain, while the coordinator is still live.
    /// Raw target files and local/request-owned results never enter this map.
    pub(crate) fn export_committed_outputs(
        &self,
        coordinator: &Arc<CoordLive>,
        stopped: &dyn Fn() -> bool,
    ) -> Result<CommittedOutputSeeds, CommittedOutputExportError> {
        use CommittedOutputExportError::{CannotRetain, InvalidProducer};

        checkpoint(stopped).map_err(|error| CannotRetain(error.to_string()))?;
        let authority = coordinator.authority().ok_or_else(|| {
            InvalidProducer("committed target export has no coordinator authority".into())
        })?;
        let registered = self
            .committed_outputs
            .0
            .lock()
            .map_err(|_| InvalidProducer("committed output registry poisoned".into()))?
            .clone();
        if registered
            .values()
            .any(|witness| witness.authority != authority)
        {
            return Err(InvalidProducer(
                "committed target export lost its coordinator authority".into(),
            ));
        }
        let dependencies = registered
            .values()
            .map(|witness| witness.dependency.clone())
            .collect::<Vec<_>>();
        // Check every known producer even if an earlier local replacement will
        // prevent retention. A stale file must not hide another Fresh unit's
        // revoked publication, including its transitive or immutable parents.
        Self::verify_seed_producers(coordinator, &authority, &dependencies, stopped)?;
        let mut seeds = CommittedOutputSeeds {
            outputs: registered
                .values()
                .map(|witness| CommittedOutputSeed::from_dependency(&witness.dependency))
                .collect::<Result<_, _>>()
                .map_err(CannotRetain)?,
        };
        // Physical PathBuf ordering compares components, while the durable
        // format orders canonical path bytes across every retained directory.
        seeds
            .outputs
            .sort_unstable_by(|left, right| left.path.cmp(&right.path));
        let pending = self.observe_seed_outputs(&seeds, stopped);
        // Hashing can be lengthy. Recheck current producer safety afterwards,
        // including when an output changed and optional retention must fail.
        Self::verify_seed_producers(coordinator, &authority, &dependencies, stopped)?;
        let pending = pending.map_err(CannotRetain)?;
        for (path, generation, _) in &pending {
            let witness = registered.get(path).ok_or_else(|| {
                CannotRetain("committed target export changed its original output path".into())
            })?;
            if witness.generation != *generation {
                return Err(CannotRetain(
                    "committed target export lost its installed generation".into(),
                ));
            }
        }
        self.verify_seed_generations(&pending, stopped)
            .map_err(CannotRetain)?;
        Ok(seeds)
    }

    /// Only a completely restored private target can re-establish installation
    /// witnesses. Historical rows never supply a file generation or authority:
    /// both are acquired now, before Cargo can use any restored output.
    pub(crate) fn rehydrate_committed_outputs(
        &self,
        coordinator: &Arc<CoordLive>,
        restored: RestoredTargetProvenance,
        stopped: &dyn Fn() -> bool,
    ) -> Result<usize, String> {
        checkpoint(stopped).map_err(|error| error.to_string())?;
        let target = self.physical(Path::new(TARGET_ROOT))?;
        let seeds = restored
            .seeds_for(&target)
            .map_err(|error| format!("restored committed target ownership: {error}"))?;
        if !self
            .committed_outputs
            .0
            .lock()
            .map_err(|_| "committed output registry poisoned")?
            .is_empty()
        {
            return Err("restored committed outputs require an unused operation registry".into());
        }
        let authority = coordinator
            .authority()
            .ok_or("restored committed outputs have no coordinator authority")?;
        let pending = self.observe_seed_outputs(seeds, stopped)?;
        Self::verify_seed_producers(
            coordinator,
            &authority,
            &pending
                .iter()
                .map(|(_, _, dependency)| dependency.clone())
                .collect::<Vec<_>>(),
            stopped,
        )
        .map_err(|error| format!("restored committed output provenance: {error}"))?;
        self.verify_seed_generations(&pending, stopped)?;
        restored
            .seeds_for(&target)
            .map_err(|error| format!("restored committed target ownership: {error}"))?;
        let mut registered = self
            .committed_outputs
            .0
            .lock()
            .map_err(|_| "committed output registry poisoned")?;
        if !registered.is_empty() {
            return Err("restored committed output registry acquired another writer".into());
        }
        checkpoint(stopped).map_err(|error| error.to_string())?;
        for (path, generation, dependency) in pending {
            registered.insert(
                path,
                InstalledProducer {
                    generation,
                    authority: authority.clone(),
                    dependency,
                },
            );
        }
        Ok(registered.len())
    }

    fn observe_seed_outputs(
        &self,
        seeds: &CommittedOutputSeeds,
        stopped: &dyn Fn() -> bool,
    ) -> Result<Vec<(PathBuf, FileSig, CommittedWorkspaceDependency)>, String> {
        seeds.validate()?;
        let mut pending = Vec::with_capacity(seeds.len());
        for output in &seeds.outputs {
            checkpoint(stopped).map_err(|error| error.to_string())?;
            let dependency = output.dependency();
            let physical = self.physical(Path::new(&dependency.path))?;
            let installed = known_installed_output(&physical, &dependency.object.0)?;
            if installed.sig.size() == 0 {
                return Err("restored committed Rust artifact is empty".into());
            }
            pending.push((physical, installed.sig, dependency));
        }
        Ok(pending)
    }

    fn verify_seed_producers(
        coordinator: &Arc<CoordLive>,
        authority: &CoordinatorAuthority,
        dependencies: &[CommittedWorkspaceDependency],
        stopped: &dyn Fn() -> bool,
    ) -> Result<(), CommittedOutputExportError> {
        use CommittedOutputExportError::{CannotRetain, InvalidProducer};

        checkpoint(stopped).map_err(|error| CannotRetain(error.to_string()))?;
        if !dependencies.is_empty() {
            coordinator
                .verify_committed_dependencies(
                    dependencies,
                    // Keep all admitted producer families in the inventory. Each
                    // later consumer still enforces its own narrower class policy.
                    CommittedDependencyPolicy::WorkspaceDagMetadata,
                )
                .map_err(InvalidProducer)?;
        }
        if !coordinator.available() || coordinator.authority().as_ref() != Some(authority) {
            return Err(InvalidProducer(
                "committed target coordinator authority changed".into(),
            ));
        }
        checkpoint(stopped).map_err(|error| CannotRetain(error.to_string()))
    }

    fn verify_seed_generations(
        &self,
        pending: &[(PathBuf, FileSig, CommittedWorkspaceDependency)],
        stopped: &dyn Fn() -> bool,
    ) -> Result<(), String> {
        for (path, generation, dependency) in pending {
            checkpoint(stopped).map_err(|error| error.to_string())?;
            let metadata = std::fs::symlink_metadata(path).map_err(|error| error.to_string())?;
            if self.physical(Path::new(&dependency.path))? != *path
                || !metadata.is_file()
                || FileSig::of(&metadata) != *generation
            {
                return Err("committed target output changed during producer verification".into());
            }
        }
        checkpoint(stopped).map_err(|error| error.to_string())
    }

    /// Every retained candidate, including unreferenced alternatives, must be an
    /// exact current generation installed by this operation from an admitted
    /// producer. The consumer class retains its own producer-policy boundary.
    pub(crate) fn capture_committed_inputs(
        self: &Arc<Self>,
        coordinator: &Arc<CoordLive>,
        observed: Arc<DependencyFacts>,
        consumer_policy: CommittedDependencyPolicy,
    ) -> Result<Arc<CommittedWorkspaceInputs>, String> {
        let authority = coordinator.authority().ok_or("no coordinator authority")?;
        let candidates = observed.candidate_generations()?;
        let mut dependencies = Vec::with_capacity(candidates.len());
        let mut generations = Vec::with_capacity(candidates.len());
        {
            let registered = self
                .committed_outputs
                .0
                .lock()
                .map_err(|_| "committed output registry poisoned")?;
            for (path, generation, digest) in candidates {
                let witness = registered
                    .get(&path)
                    .ok_or("retained Rust candidate has no committed installation witness")?;
                if witness.authority != authority
                    || witness.generation != generation
                    || witness.dependency.object.0 != digest
                    || self.physical(Path::new(&witness.dependency.path))? != path
                {
                    return Err(
                        "retained Rust candidate differs from its committed installation".into(),
                    );
                }
                generations.push((path, generation));
                dependencies.push(witness.dependency.clone());
            }
        }
        validate_committed_workspace_dependencies(
            &self.dependency_facts(&observed.directories)?,
            &dependencies,
        )
        .map_err(|error| error.to_string())?;
        let result = Arc::new(CommittedWorkspaceInputs {
            paths: Arc::clone(self),
            observed,
            consumer_policy,
            coordinator: Arc::downgrade(coordinator),
            authority,
            generations,
            dependencies,
        });
        result.verify_original()?;
        Ok(result)
    }

    /// Only published-result installation owners call this after the verified
    /// head or successful `finish_installation`; never request-owned installs.
    pub(in crate::coord::live_dependency) fn remember_committed_outputs(
        &self,
        coordinator: &Arc<CoordLive>,
        request: &LiveDependencyRequest,
        manifest: &CanonicalActionResultManifest,
        manifest_key: &str,
        installed: &[KnownOutput],
        remote: Option<&RemoteValidation>,
    ) -> Result<(), String> {
        let qualification = match request.plan.source_kind {
            DependencySourceKind::WorkspaceClosedRlib
            | DependencySourceKind::WorkspaceCommittedRlib
            | DependencySourceKind::WorkspaceClosedMetadata
            | DependencySourceKind::WorkspaceCommittedMetadata
            | DependencySourceKind::WorkspaceMixedRlib
            | DependencySourceKind::WorkspaceMixedMetadata => None,
            DependencySourceKind::RegistryPackage
            | DependencySourceKind::GitCheckout
            | DependencySourceKind::DirectoryPackage => {
                let Some(remote) = remote else {
                    return Ok(());
                };
                match remote.verify_committed_producer(request)? {
                    Some(
                        CommittedDependencyPolicy::ImmutableDagRlib
                        | CommittedDependencyPolicy::ImmutableDagMetadata,
                    ) => None,
                    Some(_) => {
                        return Err(
                            "immutable committed installation has another consumer policy".into(),
                        );
                    }
                    None => {
                        let Some(qualified) = remote.immutable_dependency_leaf(request)? else {
                            return Ok(());
                        };
                        Some(qualified)
                    }
                }
            }
            DependencySourceKind::WorkspaceExecutionOnly => return Ok(()),
        };
        if request
            .canonical_paths
            .as_ref()
            .is_none_or(|paths| !std::ptr::eq(self, paths.as_ref()))
            || manifest.action_key != request.key.action_key
            || manifest.canonical_descriptor_digest != request.key.descriptor_digest
        {
            return Err("committed installation differs from its retained operation/action".into());
        }
        self.register_installed_producer(
            coordinator,
            manifest,
            manifest_key,
            Path::new(&request.plan.out_dir),
            installed,
            qualification.as_ref(),
        )
    }

    /// Actual publication and generation gate shared by both delivery phases.
    /// The directory comes from the retained request, never a wrapper frame.
    fn register_installed_producer(
        &self,
        coordinator: &Arc<CoordLive>,
        manifest: &CanonicalActionResultManifest,
        manifest_key: &str,
        output_directory: &Path,
        installed: &[KnownOutput],
        qualification: Option<&QualifiedImmutableDependencyLeaf<'_>>,
    ) -> Result<(), String> {
        let manifest_id = object_id(&encode_manifest_v1(manifest))?;
        if digest_key(&manifest_id) != manifest_key {
            return Err("committed installation manifest identity changed".into());
        }
        let authority = coordinator.authority().ok_or("no coordinator authority")?;
        let mut pending = Vec::new();
        for installed in installed {
            let output = committed_output(manifest, &installed.path)?;
            let name = installed.path.file_name().and_then(|name| name.to_str());
            let rust_output = match (output.role, name) {
                (OutputRole::ProvisionalMetadata, Some(name)) => name.ends_with(".rmeta"),
                (OutputRole::Materializable, Some(name)) => name.ends_with(".rlib"),
                _ => false,
            };
            if !rust_output || installed.sig.size() == 0 {
                continue;
            }
            let logical = self.logical(&installed.path)?;
            let expected =
                output_directory.join(name.ok_or("committed Rust output has no basename")?);
            let metadata =
                std::fs::symlink_metadata(&installed.path).map_err(|error| error.to_string())?;
            if logical != expected
                || self.physical(&logical)? != installed.path
                || !metadata.is_file()
                || FileSig::of(&metadata) != installed.sig
                || installed.digest != output.object.0
            {
                return Err("committed Rust output changed before witness registration".into());
            }
            let dependency = CommittedWorkspaceDependency {
                path: logical
                    .into_os_string()
                    .into_string()
                    .map_err(|_| "committed Rust output path is not UTF-8")?,
                producer_action: manifest.action_key.clone(),
                producer_descriptor: manifest.canonical_descriptor_digest.clone(),
                producer_manifest: manifest_id.clone(),
                role: output.role,
                virtual_path: output.virtual_path.clone(),
                object: ObjectId(installed.digest.clone()),
            };
            pending.push((installed.path.clone(), installed.sig, dependency));
        }
        if pending.is_empty() {
            return Ok(());
        }
        // Every actual installed Rust file was checked above. Qualification is
        // not minted from a published-but-uninstalled manifest or a local claim.
        if let Some(qualification) = qualification {
            if qualification.action_key() != &manifest.action_key
                || qualification.descriptor_digest() != &manifest.canonical_descriptor_digest
            {
                return Err(
                    "immutable producer qualification belongs to another publication".into(),
                );
            }
            coordinator.record_committed_immutable_leaf(qualification, manifest_key)?;
        }
        coordinator.verify_committed_dependencies(
            &pending
                .iter()
                .map(|(_, _, dependency)| dependency.clone())
                .collect::<Vec<_>>(),
            // Registration retains every admitted producer family. Capture
            // and every later recheck separately enforce the consumer's policy;
            // archive consumers retain their original archive-only ancestry.
            CommittedDependencyPolicy::WorkspaceDagMetadata,
        )?;
        if coordinator.authority().as_ref() != Some(&authority) {
            return Err("coordinator authority changed before committed registration".into());
        }
        for (path, generation, _) in &pending {
            let metadata = std::fs::symlink_metadata(path).map_err(|error| error.to_string())?;
            if !metadata.is_file() || FileSig::of(&metadata) != *generation {
                return Err("committed Rust output changed during publication verification".into());
            }
        }
        let mut registered = self
            .committed_outputs
            .0
            .lock()
            .map_err(|_| "committed output registry poisoned")?;
        let additional = pending
            .iter()
            .filter(|(path, _, _)| !registered.contains_key(path))
            .count();
        if registered.len().saturating_add(additional) > MAX_COMMITTED_OUTPUTS {
            return Ok(());
        }
        for (path, generation, dependency) in pending {
            registered.insert(
                path,
                InstalledProducer {
                    generation,
                    authority: authority.clone(),
                    dependency,
                },
            );
        }
        Ok(())
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use crate::coord::live::WorkspaceLineageFixture;
    use crate::coord::live_dependency::known_installed_output;
    use crate::edge::live_facts::{LiveFacts, digest_stable};
    use rabs_cas::publication::OfferPreparedActionResult;
    use rabs_key::live_dependency::{LiveRustcRequest, plan_canonical_workspace_execution};
    use std::os::unix::fs::DirBuilderExt;

    const OUTPUT: &str = "/__rabs/out/cargo/debug/deps";
    const METADATA: &[u8] = b"exact committed metadata fixture";
    const ARCHIVE: &[u8] = b"whole exact committed archive fixture";

    fn paths() -> Arc<CanonicalPaths> {
        let owner = Arc::new(crate::test_util::private_tempdir());
        let mappings = super::super::ROOTS
            .iter()
            .enumerate()
            .map(|(index, root)| {
                let backing = owner.path().join(index.to_string());
                std::fs::DirBuilder::new()
                    .mode(0o700)
                    .create(&backing)
                    .unwrap();
                (PathBuf::from(root), backing)
            })
            .collect();
        let paths = CanonicalPaths::new(owner, mappings).unwrap();
        std::fs::create_dir_all(paths.physical(Path::new(OUTPUT)).unwrap()).unwrap();
        paths
    }

    fn observed(paths: &CanonicalPaths, explicit_archive: bool) -> Arc<DependencyFacts> {
        let mut argv = [
            "/__rabs/toolchain/bin/rustc",
            "--crate-name=consumer",
            "--crate-type=lib",
            "--edition=2021",
            "consumer/src/lib.rs",
            "--error-format=json",
            "--json=artifacts",
            "--emit=dep-info,metadata,link",
            "--out-dir",
            OUTPUT,
            "-L",
            "dependency=/__rabs/out/cargo/debug/deps",
        ]
        .into_iter()
        .map(str::to_owned)
        .collect::<Vec<_>>();
        argv.push(format!(
            "--extern=upstream={OUTPUT}/libupstream.{}",
            if explicit_archive { "rlib" } else { "rmeta" }
        ));
        let env = [
            ("HOME", "/__rabs/home"),
            ("CARGO_HOME", "/__rabs/cargo-home"),
            ("CARGO_MANIFEST_DIR", "/__rabs/workspace/consumer"),
            ("CARGO_PKG_NAME", "consumer"),
            ("LD_LIBRARY_PATH", "/__rabs/toolchain/lib"),
        ]
        .into_iter()
        .map(|(name, value)| (name.to_owned(), value.to_owned()))
        .collect::<Vec<_>>();
        let plan = plan_canonical_workspace_execution(
            LiveRustcRequest {
                argv: &argv,
                env: &env,
                cwd: "/__rabs/workspace",
            },
            "x86_64-unknown-linux-gnu",
        )
        .unwrap();
        LiveFacts::new()
            .dependencies(&paths.project_plan(&plan).unwrap())
            .unwrap()
    }

    fn install_bytes(
        paths: &CanonicalPaths,
        offer: &OfferPreparedActionResult,
        name: &str,
        bytes: &[u8],
    ) -> KnownOutput {
        let path = paths.physical(&Path::new(OUTPUT).join(name)).unwrap();
        std::fs::write(&path, bytes).unwrap();
        let output = committed_output(&offer.manifest, &path).unwrap();
        known_installed_output(&path, &output.object.0).unwrap()
    }

    fn register(
        paths: &CanonicalPaths,
        fixture: &WorkspaceLineageFixture,
        offer: &OfferPreparedActionResult,
        installed: &[KnownOutput],
    ) -> Result<(), String> {
        paths.register_installed_producer(
            &fixture.coord,
            &offer.manifest,
            &digest_key(&offer.manifest_id.0),
            Path::new(OUTPUT),
            installed,
            None,
        )
    }

    fn restored_owner(
        paths: &CanonicalPaths,
        seeds: CommittedOutputSeeds,
    ) -> RestoredTargetProvenance {
        // This is the explicit synthetic restore boundary for registry tests.
        // The target-state tests exercise real seed storage and private copies.
        RestoredTargetProvenance::for_test(&paths.physical(Path::new(TARGET_ROOT)).unwrap(), seeds)
            .unwrap()
    }

    #[test]
    fn restored_committed_parents_reestablish_consumer_witnesses_under_new_authority() {
        for immutable in [false, true] {
            for archive in [false, true] {
                let fixture = WorkspaceLineageFixture::new();
                let mut outputs = vec![(
                    "libupstream.rmeta",
                    OutputRole::ProvisionalMetadata,
                    METADATA,
                )];
                if archive {
                    outputs.push(("libupstream.rlib", OutputRole::Materializable, ARCHIVE));
                }
                // Only immutable qualification/class enrollment is synthetic.
                // Publication, objects, installation and safety use real CAS.
                let offer = if immutable {
                    fixture.commit_immutable_leaf(71, &outputs, !archive)
                } else if archive {
                    fixture.commit_leaf(71, &outputs)
                } else {
                    fixture.commit_metadata_leaf(71, &outputs)
                };
                let original = paths();
                let installed = outputs
                    .iter()
                    .map(|(name, _, bytes)| install_bytes(&original, &offer, name, bytes))
                    .collect::<Vec<_>>();
                let old_generation = installed[0].sig;
                register(&original, &fixture, &offer, &installed).unwrap();
                let consumer = match (immutable, archive) {
                    (false, false) => CommittedDependencyPolicy::WorkspaceMetadata,
                    (false, true) => CommittedDependencyPolicy::WorkspaceRlib,
                    (true, false) => CommittedDependencyPolicy::MixedWorkspaceMetadata,
                    (true, true) => CommittedDependencyPolicy::MixedWorkspaceRlib,
                };
                let before = original
                    .capture_committed_inputs(
                        &fixture.coord,
                        observed(&original, archive),
                        consumer,
                    )
                    .unwrap();
                let seeds = original
                    .export_committed_outputs(&fixture.coord, &|| false)
                    .unwrap();
                assert_eq!(seeds.len(), outputs.len());
                let serialized = serde_json::to_vec(&seeds).unwrap();
                let seeds = serde_json::from_slice(&serialized).unwrap();

                let restored = paths();
                for (name, _, bytes) in &outputs {
                    install_bytes(&restored, &offer, name, bytes);
                }
                assert!(
                    restored
                        .capture_committed_inputs(
                            &fixture.coord,
                            observed(&restored, archive),
                            consumer,
                        )
                        .is_err(),
                    "retained bytes alone must not grant installation authority"
                );
                fixture.coord.mark_down();
                let restarted = Arc::new(CoordLive::with_cas(Arc::clone(&fixture.cas)));
                restarted
                    .acquire_boot_authority("workspace-lineage-fixture")
                    .unwrap();
                restarted.mark_up();
                assert!(before.verify_original().is_err());
                assert_eq!(
                    restored
                        .rehydrate_committed_outputs(
                            &restarted,
                            restored_owner(&restored, seeds),
                            &|| false,
                        )
                        .unwrap(),
                    outputs.len()
                );
                let after = restored
                    .capture_committed_inputs(&restarted, observed(&restored, archive), consumer)
                    .unwrap();
                after.verify_original().unwrap();
                assert_eq!(after.dependencies(), before.dependencies());
                {
                    let registered = restored.committed_outputs.0.lock().unwrap();
                    let metadata = restored
                        .physical(&Path::new(OUTPUT).join("libupstream.rmeta"))
                        .unwrap();
                    let witness = registered.get(&metadata).unwrap();
                    assert_ne!(witness.generation, old_generation);
                    assert_eq!(Some(&witness.authority), restarted.authority().as_ref());
                }
                assert_eq!(
                    serde_json::to_vec(
                        &restored
                            .export_committed_outputs(&restarted, &|| false)
                            .unwrap()
                    )
                    .unwrap(),
                    serialized,
                    "durable provenance must contain neither physical generation nor boot authority"
                );
                if !archive {
                    assert!(
                        restored
                            .capture_committed_inputs(
                                &restarted,
                                observed(&restored, false),
                                CommittedDependencyPolicy::MixedWorkspaceRlib,
                            )
                            .is_err(),
                        "restoration must preserve the metadata/archive producer boundary"
                    );
                }
            }
        }
    }

    #[test]
    fn restored_committed_output_failure_never_partially_registers_the_seed() {
        for fault in [
            "changed",
            "missing",
            "quarantined",
            "changed-manifest",
            "cancelled",
            "foreign-owner",
        ] {
            let fixture = WorkspaceLineageFixture::new();
            let outputs = [
                (
                    "libupstream.rmeta",
                    OutputRole::ProvisionalMetadata,
                    METADATA,
                ),
                ("libupstream.rlib", OutputRole::Materializable, ARCHIVE),
            ];
            let offer = fixture.commit_leaf(72, &outputs);
            let original = paths();
            let installed = outputs
                .iter()
                .map(|(name, _, bytes)| install_bytes(&original, &offer, name, bytes))
                .collect::<Vec<_>>();
            register(&original, &fixture, &offer, &installed).unwrap();
            let mut seeds = original
                .export_committed_outputs(&fixture.coord, &|| false)
                .unwrap();
            if fault == "changed-manifest" {
                seeds.outputs[0].producer_manifest[0] ^= 1;
            }
            let restored = paths();
            for (name, _, bytes) in &outputs {
                install_bytes(&restored, &offer, name, bytes);
            }
            let owner = restored_owner(
                if fault == "foreign-owner" {
                    &original
                } else {
                    &restored
                },
                seeds,
            );
            let metadata = restored
                .physical(&Path::new(OUTPUT).join("libupstream.rmeta"))
                .unwrap();
            match fault {
                "changed" => std::fs::write(&metadata, b"changed restored Rust metadata").unwrap(),
                "missing" => {
                    std::fs::rename(&metadata, metadata.with_extension("displaced")).unwrap();
                }
                "quarantined" => fixture.quarantine(&offer.manifest.action_key),
                "changed-manifest" | "cancelled" | "foreign-owner" => {}
                _ => unreachable!(),
            }
            assert!(
                restored
                    .rehydrate_committed_outputs(&fixture.coord, owner, &|| fault == "cancelled")
                    .is_err(),
                "{fault} provenance must not restore authority"
            );
            assert!(
                restored.committed_outputs.0.lock().unwrap().is_empty(),
                "{fault} must not leave a usable witness for the unchanged archive"
            );
        }
    }

    #[test]
    fn restored_committed_output_rechecks_transitive_ancestor_revocation() {
        let fixture = WorkspaceLineageFixture::new();
        let ancestor = fixture.commit_metadata_leaf(
            73,
            &[(
                "libancestor.rmeta",
                OutputRole::ProvisionalMetadata,
                b"original ancestor metadata",
            )],
        );
        let offer = fixture.prepare_metadata(
            74,
            vec![ProvisionalAncestorRef {
                producer_action_key: ancestor.manifest.action_key.clone(),
                role: OutputRole::ProvisionalMetadata,
                virtual_path: RawBytes::from("libancestor.rmeta"),
                consumed_object: ancestor.manifest.logical_outputs[0].object.clone(),
            }],
            &[(
                "libupstream.rmeta",
                OutputRole::ProvisionalMetadata,
                METADATA,
            )],
        );
        fixture.commit(&offer);
        let original = paths();
        let installed = install_bytes(&original, &offer, "libupstream.rmeta", METADATA);
        register(&original, &fixture, &offer, &[installed]).unwrap();
        let seeds = original
            .export_committed_outputs(&fixture.coord, &|| false)
            .unwrap();
        let restored = paths();
        install_bytes(&restored, &offer, "libupstream.rmeta", METADATA);
        fixture.quarantine(&ancestor.manifest.action_key);
        assert!(
            restored
                .rehydrate_committed_outputs(
                    &fixture.coord,
                    restored_owner(&restored, seeds),
                    &|| false,
                )
                .is_err(),
            "an unchanged immediate producer must not hide revoked upstream ancestry"
        );
        assert!(restored.committed_outputs.0.lock().unwrap().is_empty());
    }

    #[test]
    fn restored_dependency_dags_keep_their_policy_and_recheck_transitive_quarantine() {
        for policy in [
            CommittedDependencyPolicy::ImmutableDagMetadata,
            CommittedDependencyPolicy::ImmutableDagRlib,
            CommittedDependencyPolicy::WorkspaceDagMetadata,
            CommittedDependencyPolicy::WorkspaceDagRlib,
        ] {
            let fixture = WorkspaceLineageFixture::new();
            let archive = matches!(
                policy,
                CommittedDependencyPolicy::ImmutableDagRlib
                    | CommittedDependencyPolicy::WorkspaceDagRlib
            );
            let workspace = matches!(
                policy,
                CommittedDependencyPolicy::WorkspaceDagMetadata
                    | CommittedDependencyPolicy::WorkspaceDagRlib
            );
            let mut parent_outputs =
                vec![("libparent.rmeta", OutputRole::ProvisionalMetadata, METADATA)];
            let mut outputs = vec![(
                "libupstream.rmeta",
                OutputRole::ProvisionalMetadata,
                METADATA,
            )];
            if archive {
                parent_outputs.push(("libparent.rlib", OutputRole::Materializable, ARCHIVE));
                outputs.push(("libupstream.rlib", OutputRole::Materializable, ARCHIVE));
            }
            let parent = fixture.commit_immutable_leaf(80, &parent_outputs, !archive);
            let immutable = fixture.prepare_dag(
                81,
                vec![parent_dependency(&parent)],
                &outputs,
                if archive {
                    CommittedDependencyPolicy::ImmutableDagRlib
                } else {
                    CommittedDependencyPolicy::ImmutableDagMetadata
                },
            );
            fixture.commit(&immutable);
            let offer = if workspace {
                let offer =
                    fixture.prepare_dag(82, vec![parent_dependency(&immutable)], &outputs, policy);
                fixture.commit(&offer);
                offer
            } else {
                immutable
            };
            let original = paths();
            let installed = outputs
                .iter()
                .map(|(name, _, bytes)| install_bytes(&original, &offer, name, bytes))
                .collect::<Vec<_>>();
            register(&original, &fixture, &offer, &installed).unwrap();
            let persisted = serde_json::to_vec(
                &original
                    .export_committed_outputs(&fixture.coord, &|| false)
                    .unwrap(),
            )
            .unwrap();
            let seeds: CommittedOutputSeeds = serde_json::from_slice(&persisted).unwrap();

            fixture.coord.mark_down();
            let restarted = Arc::new(CoordLive::with_cas(Arc::clone(&fixture.cas)));
            restarted
                .acquire_boot_authority("workspace-lineage-fixture")
                .unwrap();
            restarted.mark_up();
            let restored = paths();
            for (name, _, bytes) in &outputs {
                install_bytes(&restored, &offer, name, bytes);
            }
            assert_eq!(
                restored
                    .rehydrate_committed_outputs(
                        &restarted,
                        restored_owner(&restored, seeds.clone()),
                        &|| false,
                    )
                    .unwrap(),
                outputs.len()
            );
            let candidates = observed(&restored, archive);
            let inputs = restored
                .capture_committed_inputs(&restarted, Arc::clone(&candidates), policy)
                .unwrap();
            inputs.verify_for_policy(policy).unwrap();
            for legacy in [
                CommittedDependencyPolicy::WorkspaceRlib,
                CommittedDependencyPolicy::WorkspaceMetadata,
                CommittedDependencyPolicy::MixedWorkspaceRlib,
                CommittedDependencyPolicy::MixedWorkspaceMetadata,
            ] {
                assert!(
                    restored
                        .capture_committed_inputs(&restarted, Arc::clone(&candidates), legacy,)
                        .is_err(),
                    "restored {policy:?} must not widen legacy {legacy:?}"
                );
            }
            if workspace {
                assert!(
                    restored
                        .capture_committed_inputs(
                            &restarted,
                            Arc::clone(&candidates),
                            CommittedDependencyPolicy::ImmutableDagMetadata,
                        )
                        .is_err(),
                    "immutable consumers must not inherit workspace DAG authority"
                );
            }
            if !archive {
                assert!(
                    restored
                        .capture_committed_inputs(
                            &restarted,
                            Arc::clone(&candidates),
                            CommittedDependencyPolicy::WorkspaceDagRlib,
                        )
                        .is_err(),
                    "restored metadata DAGs must not authorize archive consumers"
                );
            }
            restored
                .export_committed_outputs(&restarted, &|| false)
                .unwrap();

            let rejected = paths();
            for (name, _, bytes) in &outputs {
                install_bytes(&rejected, &offer, name, bytes);
            }
            fixture.quarantine(&parent.manifest.action_key);
            assert!(inputs.verify_original().is_err());
            assert!(
                rejected
                    .rehydrate_committed_outputs(
                        &restarted,
                        restored_owner(&rejected, seeds),
                        &|| false,
                    )
                    .is_err(),
                "a revoked immutable root must reject the entire restored DAG"
            );
            assert!(rejected.committed_outputs.0.lock().unwrap().is_empty());
            assert!(matches!(
                restored.export_committed_outputs(&restarted, &|| false),
                Err(CommittedOutputExportError::InvalidProducer(_))
            ));
        }
    }

    #[test]
    fn completed_producer_barrier_rejects_revocation_without_target_export() {
        let fixture = WorkspaceLineageFixture::new();
        let offer = fixture.commit_metadata_leaf(
            80,
            &[(
                "libupstream.rmeta",
                OutputRole::ProvisionalMetadata,
                METADATA,
            )],
        );
        let original = paths();
        let installed = install_bytes(&original, &offer, "libupstream.rmeta", METADATA);
        register(&original, &fixture, &offer, &[installed]).unwrap();
        // No target-state owner or seed export is involved. Completion safety
        // comes from the operation's actual installed producer witnesses.
        original
            .verify_completed_producers(&fixture.coord, &|| false)
            .unwrap();
        fixture.quarantine(&offer.manifest.action_key);
        let error = original
            .verify_completed_producers(&fixture.coord, &|| false)
            .unwrap_err();
        assert!(error.to_string().contains("completed target provenance"));
    }

    #[test]
    fn completed_producer_barrier_rechecks_ancestry_after_copy_and_target_move() {
        let fixture = WorkspaceLineageFixture::new();
        let ancestor = fixture.commit_metadata_leaf(
            81,
            &[(
                "libancestor.rmeta",
                OutputRole::ProvisionalMetadata,
                b"original ancestor metadata",
            )],
        );
        let offer = fixture.prepare_metadata(
            82,
            vec![ProvisionalAncestorRef {
                producer_action_key: ancestor.manifest.action_key.clone(),
                role: OutputRole::ProvisionalMetadata,
                virtual_path: RawBytes::from("libancestor.rmeta"),
                consumed_object: ancestor.manifest.logical_outputs[0].object.clone(),
            }],
            &[(
                "libupstream.rmeta",
                OutputRole::ProvisionalMetadata,
                METADATA,
            )],
        );
        fixture.commit(&offer);
        let original = paths();
        let installed = install_bytes(&original, &offer, "libupstream.rmeta", METADATA);
        let original_output = installed.path.clone();
        register(&original, &fixture, &offer, &[installed]).unwrap();
        let seeds = original
            .export_committed_outputs(&fixture.coord, &|| false)
            .unwrap();
        assert_eq!(seeds.len(), 1);
        let copied = paths();
        std::fs::copy(
            &original_output,
            copied
                .physical(&Path::new(OUTPUT).join("libupstream.rmeta"))
                .unwrap(),
        )
        .unwrap();
        seeds
            .verify_target(&copied.physical(Path::new(TARGET_ROOT)).unwrap(), &|| false)
            .unwrap();
        let original_target = original.physical(Path::new(TARGET_ROOT)).unwrap();
        std::fs::rename(
            &original_target,
            original._owner.path().join("completed-target"),
        )
        .unwrap();
        assert!(!original_target.exists());
        original
            .verify_completed_producers(&fixture.coord, &|| false)
            .expect("moving a completed tree does not change its registered producer identities");
        // The export and actual copied bytes were both valid. A later upstream
        // quarantine must still prevent completion, even though the immediate
        // producer and its copied artifact are unchanged.
        fixture.quarantine(&ancestor.manifest.action_key);
        assert!(
            original
                .verify_completed_producers(&fixture.coord, &|| false)
                .is_err()
        );
    }

    #[test]
    fn completed_producer_barrier_preserves_cancellation_and_original_authority() {
        let fixture = WorkspaceLineageFixture::new();
        let offer = fixture.commit_metadata_leaf(
            83,
            &[(
                "libupstream.rmeta",
                OutputRole::ProvisionalMetadata,
                METADATA,
            )],
        );
        let original = paths();
        let installed = install_bytes(&original, &offer, "libupstream.rmeta", METADATA);
        register(&original, &fixture, &offer, &[installed]).unwrap();
        original
            .verify_completed_producers(&fixture.coord, &|| false)
            .unwrap();
        let stopped = std::sync::atomic::AtomicBool::new(true);
        assert_eq!(
            original
                .verify_completed_producers(&fixture.coord, &|| {
                    stopped.load(std::sync::atomic::Ordering::Acquire)
                })
                .unwrap_err()
                .kind(),
            io::ErrorKind::Interrupted
        );
        assert!(stopped.load(std::sync::atomic::Ordering::Acquire));
        fixture.coord.mark_down();
        assert!(
            original
                .verify_completed_producers(&fixture.coord, &|| false)
                .is_err()
        );
        fixture.coord.mark_up();
        original
            .verify_completed_producers(&fixture.coord, &|| false)
            .unwrap();
        fixture
            .coord
            .acquire_boot_authority("workspace-lineage-fixture")
            .unwrap();
        let error = original
            .verify_completed_producers(&fixture.coord, &|| false)
            .unwrap_err();
        assert!(error.to_string().contains("original coordinator authority"));
    }

    #[test]
    fn target_export_refuses_changed_generations_and_never_discovers_unregistered_producers() {
        let fixture = WorkspaceLineageFixture::new();
        let offer = fixture.commit_metadata_leaf(
            75,
            &[(
                "libupstream.rmeta",
                OutputRole::ProvisionalMetadata,
                METADATA,
            )],
        );
        let original = paths();
        let installed = install_bytes(&original, &offer, "libupstream.rmeta", METADATA);
        let seeds = original
            .export_committed_outputs(&fixture.coord, &|| false)
            .unwrap();
        assert!(
            seeds.is_empty(),
            "matching a published CAS object must not discover installation authority"
        );
        let restored = paths();
        install_bytes(&restored, &offer, "libupstream.rmeta", METADATA);
        assert_eq!(
            restored
                .rehydrate_committed_outputs(
                    &fixture.coord,
                    restored_owner(&restored, seeds),
                    &|| false,
                )
                .unwrap(),
            0
        );
        assert!(
            restored
                .capture_committed_inputs(
                    &fixture.coord,
                    observed(&restored, false),
                    CommittedDependencyPolicy::WorkspaceMetadata,
                )
                .is_err()
        );
        let metadata = installed.path.clone();
        register(&original, &fixture, &offer, &[installed]).unwrap();
        let replacement = metadata.with_extension("replacement");
        std::fs::write(&replacement, METADATA).unwrap();
        std::fs::rename(&metadata, metadata.with_extension("original")).unwrap();
        std::fs::rename(&replacement, &metadata).unwrap();
        assert!(
            matches!(
                original.export_committed_outputs(&fixture.coord, &|| false),
                Err(CommittedOutputExportError::CannotRetain(_))
            ),
            "equal replacement bytes must not refresh the recorded installation generation"
        );
    }

    #[test]
    fn target_export_does_not_hide_revoked_fresh_producers_behind_changed_local_files() {
        let fixture = WorkspaceLineageFixture::new();
        let changed = fixture.commit_metadata_leaf(
            78,
            &[("libalpha.rmeta", OutputRole::ProvisionalMetadata, METADATA)],
        );
        let fresh = fixture.commit_metadata_leaf(
            79,
            &[(
                "libupstream.rmeta",
                OutputRole::ProvisionalMetadata,
                METADATA,
            )],
        );
        let original = paths();
        let installed = install_bytes(&original, &changed, "libalpha.rmeta", METADATA);
        let changed_path = installed.path.clone();
        register(&original, &fixture, &changed, &[installed]).unwrap();
        let installed = install_bytes(&original, &fresh, "libupstream.rmeta", METADATA);
        register(&original, &fixture, &fresh, &[installed]).unwrap();
        std::fs::write(&changed_path, b"a locally replaced output").unwrap();
        assert!(matches!(
            original.export_committed_outputs(&fixture.coord, &|| false),
            Err(CommittedOutputExportError::CannotRetain(_))
        ));
        original
            .verify_completed_producers(&fixture.coord, &|| false)
            .expect("a local replacement alone can prevent retention without revoking producers");
        fixture.quarantine(&fresh.manifest.action_key);
        assert!(
            original
                .verify_completed_producers(&fixture.coord, &|| false)
                .is_err(),
            "an optional capture warning must not bypass completion's current producer check"
        );
        assert!(
            matches!(
                original.export_committed_outputs(&fixture.coord, &|| false),
                Err(CommittedOutputExportError::InvalidProducer(_))
            ),
            "known unsafe Fresh ancestry must be terminal even when another file prevents retention"
        );
    }

    #[test]
    fn committed_seed_schema_rejects_aliases_roles_duplicate_rows_and_untyped_digests() {
        let fixture = WorkspaceLineageFixture::new();
        let offer = fixture.commit_metadata_leaf(
            76,
            &[(
                "libupstream.rmeta",
                OutputRole::ProvisionalMetadata,
                METADATA,
            )],
        );
        let original = paths();
        let installed = install_bytes(&original, &offer, "libupstream.rmeta", METADATA);
        register(&original, &fixture, &offer, &[installed]).unwrap();
        let seeds = original
            .export_committed_outputs(&fixture.coord, &|| false)
            .unwrap();
        for path in [
            "/__rabs/workspace/libupstream.rmeta",
            "/__rabs/out/cargo/../libupstream.rmeta",
            "/__rabs/out/cargo//debug/deps/libupstream.rmeta",
            "/__rabs/out/cargo/debug/deps/other.rmeta",
        ] {
            let mut invalid = seeds.clone();
            invalid.outputs[0].path = path.to_owned();
            assert!(invalid.validate().is_err(), "{path}");
        }
        let mut invalid = seeds.clone();
        invalid.outputs[0].role = SeedRole::Archive;
        assert!(invalid.validate().is_err());
        let mut invalid = seeds.clone();
        invalid.outputs.push(invalid.outputs[0].clone());
        assert!(invalid.validate().is_err());
        let invalid = CommittedOutputSeeds {
            outputs: vec![seeds.outputs[0].clone(); MAX_COMMITTED_OUTPUTS + 1],
        };
        assert!(invalid.validate().is_err());
        let mut dependency = seeds.outputs[0].dependency();
        dependency.producer_manifest.domain = DOMAIN_ACTION_KEY;
        assert!(CommittedOutputSeed::from_dependency(&dependency).is_err());
        let mut encoded = serde_json::to_value(&seeds).unwrap();
        encoded["outputs"][0]["authority"] = serde_json::json!("invented owner");
        assert!(serde_json::from_value::<CommittedOutputSeeds>(encoded).is_err());
    }

    #[test]
    fn target_export_orders_provenance_across_distinct_output_directories() {
        let fixture = WorkspaceLineageFixture::new();
        let offer = fixture.commit_metadata_leaf(
            77,
            &[(
                "libupstream.rmeta",
                OutputRole::ProvisionalMetadata,
                METADATA,
            )],
        );
        let original = paths();
        let installed = install_bytes(&original, &offer, "libupstream.rmeta", METADATA);
        register(&original, &fixture, &offer, &[installed]).unwrap();
        let other_directory = Path::new("/__rabs/out/cargo/debug-extra/deps");
        let other = original.physical(other_directory).unwrap();
        std::fs::create_dir_all(&other).unwrap();
        let other = other.join("libupstream.rmeta");
        std::fs::write(&other, METADATA).unwrap();
        let output = committed_output(&offer.manifest, &other).unwrap();
        let installed = known_installed_output(&other, &output.object.0).unwrap();
        original
            .register_installed_producer(
                &fixture.coord,
                &offer.manifest,
                &digest_key(&offer.manifest_id.0),
                other_directory,
                &[installed],
                None,
            )
            .unwrap();
        let seeds = original
            .export_committed_outputs(&fixture.coord, &|| false)
            .unwrap();
        seeds.validate().unwrap();
        assert_eq!(seeds.len(), 2);
        assert_eq!(
            seeds.outputs[0].path,
            "/__rabs/out/cargo/debug-extra/deps/libupstream.rmeta"
        );
        assert_eq!(seeds.outputs[1].path, format!("{OUTPUT}/libupstream.rmeta"));
    }

    #[test]
    fn immutable_metadata_installation_is_bound_to_mixed_metadata_owner_and_generation() {
        let fixture = WorkspaceLineageFixture::new();
        // Only qualification/class enrollment is synthetic. This exercises
        // real publication, CAS bytes and physical installation witnesses;
        // it does not mint the remote leaf capability used in production.
        let offer = fixture.commit_immutable_leaf(
            46,
            &[(
                "libupstream.rmeta",
                OutputRole::ProvisionalMetadata,
                METADATA,
            )],
            true,
        );
        let original = paths();
        let installed = install_bytes(&original, &offer, "libupstream.rmeta", METADATA);
        let path = installed.path.clone();
        let generation = installed.sig;
        let before = observed(&original, false);
        assert!(
            original
                .capture_committed_inputs(
                    &fixture.coord,
                    Arc::clone(&before),
                    CommittedDependencyPolicy::MixedWorkspaceMetadata,
                )
                .is_err(),
            "committed-but-unregistered files have no installation capability"
        );
        register(&original, &fixture, &offer, &[installed]).unwrap();
        let inputs = original
            .capture_committed_inputs(
                &fixture.coord,
                Arc::clone(&before),
                CommittedDependencyPolicy::MixedWorkspaceMetadata,
            )
            .unwrap();
        inputs.verify_original().unwrap();
        assert_eq!(inputs.ancestors().len(), 1);
        assert_eq!(
            inputs.ancestors()[0].producer_action_key,
            offer.manifest.action_key
        );
        for other in [
            CommittedDependencyPolicy::MixedWorkspaceRlib,
            CommittedDependencyPolicy::WorkspaceRlib,
            CommittedDependencyPolicy::WorkspaceMetadata,
        ] {
            assert!(inputs.verify_for_policy(other).is_err());
            assert!(
                original
                    .capture_committed_inputs(&fixture.coord, Arc::clone(&before), other)
                    .is_err(),
                "external metadata cannot lend authority to {other:?}"
            );
        }
        let copied = paths();
        let _installed = install_bytes(&copied, &offer, "libupstream.rmeta", METADATA);
        assert!(
            copied
                .capture_committed_inputs(
                    &fixture.coord,
                    observed(&copied, false),
                    CommittedDependencyPolicy::MixedWorkspaceMetadata,
                )
                .is_err()
        );

        let replacement = path.with_file_name("replacement.tmp");
        std::fs::write(&replacement, METADATA).unwrap();
        std::fs::rename(&replacement, &path).unwrap();
        let (current, digest) = digest_stable(&path).unwrap();
        assert_ne!(generation, current);
        assert_eq!(digest, object_id(METADATA).unwrap());
        assert!(inputs.verify_original().is_err());
        assert!(
            original
                .capture_committed_inputs(
                    &fixture.coord,
                    observed(&original, false),
                    CommittedDependencyPolicy::MixedWorkspaceMetadata,
                )
                .is_err()
        );
        register(
            &original,
            &fixture,
            &offer,
            &[known_installed_output(&path, &digest).unwrap()],
        )
        .unwrap();
        let current = original
            .capture_committed_inputs(
                &fixture.coord,
                observed(&original, false),
                CommittedDependencyPolicy::MixedWorkspaceMetadata,
            )
            .unwrap();
        current.verify_original().unwrap();
        assert!(inputs.verify_original().is_err());
        fixture.quarantine(&offer.manifest.action_key);
        assert!(current.verify_original().is_err());
    }

    #[test]
    fn immutable_archive_head_never_registers_an_uninstalled_tail_or_unknown_candidate() {
        let fixture = WorkspaceLineageFixture::new();
        let offer = fixture.commit_immutable_leaf(
            47,
            &[
                (
                    "libupstream.rmeta",
                    OutputRole::ProvisionalMetadata,
                    METADATA,
                ),
                ("libupstream.rlib", OutputRole::Materializable, ARCHIVE),
            ],
            false,
        );
        let paths = paths();
        let metadata = install_bytes(&paths, &offer, "libupstream.rmeta", METADATA);
        register(&paths, &fixture, &offer, &[metadata]).unwrap();
        for consumer in [
            CommittedDependencyPolicy::MixedWorkspaceRlib,
            CommittedDependencyPolicy::MixedWorkspaceMetadata,
        ] {
            let captured = paths
                .capture_committed_inputs(&fixture.coord, observed(&paths, false), consumer)
                .unwrap();
            assert_eq!(captured.dependencies().len(), 1);
            assert_eq!(
                captured.dependencies()[0].role,
                OutputRole::ProvisionalMetadata
            );
        }
        for consumer in [
            CommittedDependencyPolicy::WorkspaceRlib,
            CommittedDependencyPolicy::WorkspaceMetadata,
        ] {
            assert!(
                paths
                    .capture_committed_inputs(&fixture.coord, observed(&paths, false), consumer,)
                    .is_err()
            );
        }
        let archive = install_bytes(&paths, &offer, "libupstream.rlib", ARCHIVE);
        assert!(
            paths
                .capture_committed_inputs(
                    &fixture.coord,
                    observed(&paths, true),
                    CommittedDependencyPolicy::MixedWorkspaceRlib,
                )
                .is_err(),
            "manifest membership and file presence do not register the tail"
        );
        // Existing metadata-shadowing projection remains unchanged: an unused
        // sibling archive is not part of the retained candidate namespace.
        assert_eq!(
            paths
                .capture_committed_inputs(
                    &fixture.coord,
                    observed(&paths, false),
                    CommittedDependencyPolicy::MixedWorkspaceRlib,
                )
                .unwrap()
                .dependencies()
                .len(),
            1
        );
        register(&paths, &fixture, &offer, &[archive]).unwrap();
        let complete = paths
            .capture_committed_inputs(
                &fixture.coord,
                observed(&paths, true),
                CommittedDependencyPolicy::MixedWorkspaceRlib,
            )
            .unwrap();
        assert_eq!(complete.dependencies().len(), 2);
        assert!(
            complete
                .dependencies()
                .iter()
                .any(|input| input.role == OutputRole::Materializable
                    && input.object.0 == object_id(ARCHIVE).unwrap())
        );
        std::fs::write(
            paths
                .physical(&Path::new(OUTPUT).join("libunknown.rmeta"))
                .unwrap(),
            b"unattributed alternative",
        )
        .unwrap();
        assert!(complete.verify_original().is_err());
        assert!(
            paths
                .capture_committed_inputs(
                    &fixture.coord,
                    observed(&paths, true),
                    CommittedDependencyPolicy::MixedWorkspaceRlib,
                )
                .is_err()
        );
    }

    fn parent_dependency(offer: &OfferPreparedActionResult) -> ProvisionalAncestorRef {
        let output = &offer.manifest.logical_outputs[0];
        ProvisionalAncestorRef {
            producer_action_key: offer.manifest.action_key.clone(),
            role: output.role,
            virtual_path: output.virtual_path.clone(),
            consumed_object: output.object.clone(),
        }
    }

    #[test]
    fn immutable_dag_metadata_installation_preserves_policy_and_transitive_revocation() {
        let fixture = WorkspaceLineageFixture::new();
        // Descriptor/class enrollment is explicitly synthetic. All object
        // bytes, publication, ancestry, installed files and generation checks
        // below use the actual CAS and canonical installation registry.
        let parent = fixture.commit_immutable_leaf(
            60,
            &[("libparent.rmeta", OutputRole::ProvisionalMetadata, METADATA)],
            true,
        );
        let offer = fixture.prepare_dag(
            61,
            vec![parent_dependency(&parent)],
            &[(
                "libupstream.rmeta",
                OutputRole::ProvisionalMetadata,
                METADATA,
            )],
            CommittedDependencyPolicy::ImmutableDagMetadata,
        );
        let paths = paths();
        let installed = install_bytes(&paths, &offer, "libupstream.rmeta", METADATA);
        assert!(register(&paths, &fixture, &offer, std::slice::from_ref(&installed)).is_err());
        assert!(paths.committed_outputs.0.lock().unwrap().is_empty());
        fixture.commit(&offer);
        register(&paths, &fixture, &offer, &[installed]).unwrap();
        let candidates = observed(&paths, false);
        let mut retained = Vec::new();
        for policy in [
            CommittedDependencyPolicy::ImmutableDagMetadata,
            CommittedDependencyPolicy::WorkspaceDagMetadata,
        ] {
            let inputs = paths
                .capture_committed_inputs(&fixture.coord, Arc::clone(&candidates), policy)
                .unwrap();
            assert_eq!(inputs.policy(), policy);
            inputs.verify_for_policy(policy).unwrap();
            assert_eq!(inputs.dependencies().len(), 1);
            assert_eq!(inputs.ancestors(), vec![parent_dependency(&offer)]);
            let other = if policy == CommittedDependencyPolicy::ImmutableDagMetadata {
                CommittedDependencyPolicy::WorkspaceDagMetadata
            } else {
                CommittedDependencyPolicy::ImmutableDagMetadata
            };
            assert!(inputs.verify_for_policy(other).is_err());
            retained.push(inputs);
        }
        for policy in [
            CommittedDependencyPolicy::WorkspaceRlib,
            CommittedDependencyPolicy::WorkspaceMetadata,
            CommittedDependencyPolicy::MixedWorkspaceRlib,
            CommittedDependencyPolicy::MixedWorkspaceMetadata,
            CommittedDependencyPolicy::ImmutableDagRlib,
            CommittedDependencyPolicy::WorkspaceDagRlib,
        ] {
            assert!(
                paths
                    .capture_committed_inputs(&fixture.coord, Arc::clone(&candidates), policy)
                    .is_err(),
                "a published metadata DAG cannot authorize {policy:?}"
            );
        }
        fixture.quarantine(&parent.manifest.action_key);
        for inputs in retained {
            assert!(inputs.verify_original().is_err());
            assert!(
                paths
                    .capture_committed_inputs(
                        &fixture.coord,
                        Arc::clone(&candidates),
                        inputs.policy(),
                    )
                    .is_err()
            );
        }
    }

    #[test]
    fn dag_archive_installation_keeps_tail_owner_and_exact_file_generation() {
        for producer_policy in [
            CommittedDependencyPolicy::ImmutableDagRlib,
            CommittedDependencyPolicy::WorkspaceDagRlib,
        ] {
            let fixture = WorkspaceLineageFixture::new();
            let parent = fixture.commit_immutable_leaf(
                62,
                &[
                    ("libparent.rmeta", OutputRole::ProvisionalMetadata, METADATA),
                    ("libparent.rlib", OutputRole::Materializable, ARCHIVE),
                ],
                false,
            );
            let offer = fixture.prepare_dag(
                63,
                vec![parent_dependency(&parent)],
                &[
                    (
                        "libupstream.rmeta",
                        OutputRole::ProvisionalMetadata,
                        METADATA,
                    ),
                    ("libupstream.rlib", OutputRole::Materializable, ARCHIVE),
                ],
                producer_policy,
            );
            fixture.commit(&offer);
            let original = paths();
            let metadata = install_bytes(&original, &offer, "libupstream.rmeta", METADATA);
            let metadata_path = metadata.path.clone();
            let generation = metadata.sig;
            register(&original, &fixture, &offer, &[metadata]).unwrap();
            let head = original
                .capture_committed_inputs(
                    &fixture.coord,
                    observed(&original, false),
                    producer_policy,
                )
                .unwrap();
            assert_eq!(head.dependencies().len(), 1);
            let candidates = observed(&original, false);
            for policy in [
                CommittedDependencyPolicy::WorkspaceRlib,
                CommittedDependencyPolicy::WorkspaceMetadata,
                CommittedDependencyPolicy::MixedWorkspaceRlib,
                CommittedDependencyPolicy::MixedWorkspaceMetadata,
            ] {
                assert!(
                    original
                        .capture_committed_inputs(&fixture.coord, Arc::clone(&candidates), policy)
                        .is_err(),
                    "existing policy {policy:?} must not silently admit a new DAG producer"
                );
            }
            if producer_policy == CommittedDependencyPolicy::WorkspaceDagRlib {
                for policy in [
                    CommittedDependencyPolicy::ImmutableDagRlib,
                    CommittedDependencyPolicy::ImmutableDagMetadata,
                ] {
                    assert!(
                        original
                            .capture_committed_inputs(
                                &fixture.coord,
                                Arc::clone(&candidates),
                                policy
                            )
                            .is_err(),
                        "immutable DAG consumers cannot gain workspace producer authority"
                    );
                }
            }
            let archive = install_bytes(&original, &offer, "libupstream.rlib", ARCHIVE);
            assert!(
                original
                    .capture_committed_inputs(
                        &fixture.coord,
                        observed(&original, true),
                        producer_policy,
                    )
                    .is_err(),
                "a manifest-listed tail is not an installed output witness"
            );
            head.verify_original().unwrap();
            register(&original, &fixture, &offer, &[archive]).unwrap();
            let complete = original
                .capture_committed_inputs(
                    &fixture.coord,
                    observed(&original, true),
                    producer_policy,
                )
                .unwrap();
            assert_eq!(complete.dependencies().len(), 2);
            let copied = paths();
            let _metadata = install_bytes(&copied, &offer, "libupstream.rmeta", METADATA);
            let _archive = install_bytes(&copied, &offer, "libupstream.rlib", ARCHIVE);
            assert!(
                copied
                    .capture_committed_inputs(
                        &fixture.coord,
                        observed(&copied, true),
                        producer_policy,
                    )
                    .is_err()
            );
            let replacement = metadata_path.with_file_name("replacement.tmp");
            std::fs::write(&replacement, METADATA).unwrap();
            std::fs::rename(&replacement, &metadata_path).unwrap();
            let (current, digest) = digest_stable(&metadata_path).unwrap();
            assert_ne!(generation, current);
            assert_eq!(digest, object_id(METADATA).unwrap());
            assert!(head.verify_original().is_err());
            assert!(complete.verify_original().is_err());
            assert!(
                original
                    .capture_committed_inputs(
                        &fixture.coord,
                        observed(&original, true),
                        producer_policy,
                    )
                    .is_err()
            );
            register(
                &original,
                &fixture,
                &offer,
                &[known_installed_output(&metadata_path, &digest).unwrap()],
            )
            .unwrap();
            let current = original
                .capture_committed_inputs(
                    &fixture.coord,
                    observed(&original, true),
                    producer_policy,
                )
                .unwrap();
            current.verify_original().unwrap();
            assert!(complete.verify_original().is_err());
            fixture.quarantine(&parent.manifest.action_key);
            assert!(current.verify_original().is_err());
        }
    }

    #[test]
    fn committed_capability_cannot_cross_the_archive_and_metadata_consumer_classes() {
        let fixture = WorkspaceLineageFixture::new();
        let offer = fixture.commit_leaf(
            44,
            &[(
                "libupstream.rmeta",
                OutputRole::ProvisionalMetadata,
                METADATA,
            )],
        );
        let paths = paths();
        let metadata = install_bytes(&paths, &offer, "libupstream.rmeta", METADATA);
        register(&paths, &fixture, &offer, &[metadata]).unwrap();
        let candidates = observed(&paths, false);
        for (policy, other) in [
            (
                CommittedDependencyPolicy::WorkspaceRlib,
                CommittedDependencyPolicy::WorkspaceMetadata,
            ),
            (
                CommittedDependencyPolicy::WorkspaceMetadata,
                CommittedDependencyPolicy::WorkspaceRlib,
            ),
        ] {
            let captured = paths
                .capture_committed_inputs(&fixture.coord, Arc::clone(&candidates), policy)
                .unwrap();
            assert_eq!(captured.policy(), policy);
            captured.verify_for_policy(policy).unwrap();
            assert!(captured.verify_for_policy(other).is_err());
        }
        for kind in [
            DependencySourceKind::WorkspaceExecutionOnly,
            DependencySourceKind::WorkspaceClosedRlib,
            DependencySourceKind::WorkspaceClosedMetadata,
            DependencySourceKind::RegistryPackage,
        ] {
            assert!(CommittedDependencyPolicy::from_source_kind(kind).is_none());
        }
    }

    #[test]
    fn committed_metadata_installation_cannot_authorize_archive_consumers() {
        let fixture = WorkspaceLineageFixture::new();
        let offer = fixture.prepare_metadata(
            45,
            Vec::new(),
            &[(
                "libupstream.rmeta",
                OutputRole::ProvisionalMetadata,
                METADATA,
            )],
        );
        let paths = paths();
        let installed = install_bytes(&paths, &offer, "libupstream.rmeta", METADATA);
        assert!(register(&paths, &fixture, &offer, std::slice::from_ref(&installed)).is_err());
        assert!(paths.committed_outputs.0.lock().unwrap().is_empty());
        fixture.commit(&offer);
        register(&paths, &fixture, &offer, &[installed]).unwrap();
        let candidates = observed(&paths, false);
        let metadata = paths
            .capture_committed_inputs(
                &fixture.coord,
                Arc::clone(&candidates),
                CommittedDependencyPolicy::WorkspaceMetadata,
            )
            .unwrap();
        metadata
            .verify_for_policy(CommittedDependencyPolicy::WorkspaceMetadata)
            .unwrap();
        assert!(
            metadata
                .verify_for_policy(CommittedDependencyPolicy::WorkspaceRlib)
                .is_err()
        );
        assert!(
            paths
                .capture_committed_inputs(
                    &fixture.coord,
                    candidates,
                    CommittedDependencyPolicy::WorkspaceRlib,
                )
                .is_err()
        );
        fixture.quarantine(&offer.manifest.action_key);
        assert!(metadata.verify_original().is_err());
    }

    #[test]
    fn committed_head_does_not_lend_authority_to_an_uninstalled_archive_or_unknown_sibling() {
        let fixture = WorkspaceLineageFixture::new();
        let offer = fixture.commit_leaf(
            40,
            &[
                (
                    "libupstream.rmeta",
                    OutputRole::ProvisionalMetadata,
                    METADATA,
                ),
                ("libupstream.rlib", OutputRole::Materializable, ARCHIVE),
            ],
        );
        let paths = paths();
        let metadata = install_bytes(&paths, &offer, "libupstream.rmeta", METADATA);
        register(&paths, &fixture, &offer, &[metadata]).unwrap();
        let head = paths
            .capture_committed_inputs(
                &fixture.coord,
                observed(&paths, false),
                CommittedDependencyPolicy::WorkspaceRlib,
            )
            .unwrap();
        assert_eq!(head.dependencies().len(), 1);
        assert_eq!(
            head.ancestors()[0].producer_action_key,
            offer.manifest.action_key
        );
        assert_eq!(
            head.ancestors()[0].consumed_object.0,
            object_id(METADATA).unwrap()
        );
        // Publication membership and mere file presence cannot bless the tail.
        let archive = install_bytes(&paths, &offer, "libupstream.rlib", ARCHIVE);
        assert!(
            paths
                .capture_committed_inputs(
                    &fixture.coord,
                    observed(&paths, true),
                    CommittedDependencyPolicy::WorkspaceRlib,
                )
                .is_err()
        );
        // Existing projection omits the non-explicit shadowed archive entirely.
        assert_eq!(
            paths
                .capture_committed_inputs(
                    &fixture.coord,
                    observed(&paths, false),
                    CommittedDependencyPolicy::WorkspaceRlib,
                )
                .unwrap()
                .dependencies()
                .len(),
            1
        );
        register(&paths, &fixture, &offer, &[archive]).unwrap();
        let complete = paths
            .capture_committed_inputs(
                &fixture.coord,
                observed(&paths, true),
                CommittedDependencyPolicy::WorkspaceRlib,
            )
            .unwrap();
        assert_eq!(complete.dependencies().len(), 2);
        assert_eq!(complete.ancestors().len(), 2);
        std::fs::write(
            paths
                .physical(&Path::new(OUTPUT).join("libunknown.rmeta"))
                .unwrap(),
            b"unattributed alternative",
        )
        .unwrap();
        assert!(
            paths
                .capture_committed_inputs(
                    &fixture.coord,
                    observed(&paths, false),
                    CommittedDependencyPolicy::WorkspaceRlib,
                )
                .is_err()
        );
        assert!(complete.verify_original().is_err());
    }

    #[test]
    fn same_byte_replacement_refuses_old_witness_even_after_fresh_observation() {
        let fixture = WorkspaceLineageFixture::new();
        let offer = fixture.commit_leaf(
            41,
            &[(
                "libupstream.rmeta",
                OutputRole::ProvisionalMetadata,
                METADATA,
            )],
        );
        let paths = paths();
        let metadata = install_bytes(&paths, &offer, "libupstream.rmeta", METADATA);
        let path = metadata.path.clone();
        let old_generation = metadata.sig;
        register(&paths, &fixture, &offer, &[metadata]).unwrap();
        let inputs = paths
            .capture_committed_inputs(
                &fixture.coord,
                observed(&paths, false),
                CommittedDependencyPolicy::WorkspaceRlib,
            )
            .unwrap();
        inputs.verify_original().unwrap();
        let replacement = path.with_file_name("replacement.tmp");
        std::fs::write(&replacement, METADATA).unwrap();
        std::fs::rename(&replacement, &path).unwrap();
        let (new_generation, same_object) = digest_stable(&path).unwrap();
        assert_ne!(old_generation, new_generation);
        assert_eq!(same_object, object_id(METADATA).unwrap());
        assert!(inputs.verify_original().is_err());
        assert!(
            paths
                .capture_committed_inputs(
                    &fixture.coord,
                    observed(&paths, false),
                    CommittedDependencyPolicy::WorkspaceRlib,
                )
                .is_err()
        );
        // A verified reinstall may mint the new generation; old observations
        // never refresh themselves or inherit the new witness.
        let verified = known_installed_output(&path, &same_object).unwrap();
        register(&paths, &fixture, &offer, &[verified]).unwrap();
        paths
            .capture_committed_inputs(
                &fixture.coord,
                observed(&paths, false),
                CommittedDependencyPolicy::WorkspaceRlib,
            )
            .unwrap()
            .verify_original()
            .unwrap();
        assert!(inputs.verify_original().is_err());
    }

    #[test]
    fn copied_artifacts_in_another_operation_have_no_inherited_producer_capability() {
        let fixture = WorkspaceLineageFixture::new();
        let offer = fixture.commit_leaf(
            42,
            &[(
                "libupstream.rmeta",
                OutputRole::ProvisionalMetadata,
                METADATA,
            )],
        );
        let original = paths();
        let metadata = install_bytes(&original, &offer, "libupstream.rmeta", METADATA);
        register(&original, &fixture, &offer, &[metadata]).unwrap();
        original
            .capture_committed_inputs(
                &fixture.coord,
                observed(&original, false),
                CommittedDependencyPolicy::WorkspaceRlib,
            )
            .unwrap();
        let other = paths();
        let _copied = install_bytes(&other, &offer, "libupstream.rmeta", METADATA);
        assert!(
            other
                .capture_committed_inputs(
                    &fixture.coord,
                    observed(&other, false),
                    CommittedDependencyPolicy::WorkspaceRlib,
                )
                .is_err()
        );
    }

    #[test]
    fn uncommitted_capture_cannot_register_and_quarantine_revokes_retained_proof() {
        let fixture = WorkspaceLineageFixture::new();
        let offer = fixture.prepare(
            43,
            Vec::new(),
            &[(
                "libupstream.rmeta",
                OutputRole::ProvisionalMetadata,
                METADATA,
            )],
        );
        let paths = paths();
        let metadata = install_bytes(&paths, &offer, "libupstream.rmeta", METADATA);
        assert!(register(&paths, &fixture, &offer, &[metadata]).is_err());
        assert!(paths.committed_outputs.0.lock().unwrap().is_empty());
        fixture.commit(&offer);
        let path = paths
            .physical(&Path::new(OUTPUT).join("libupstream.rmeta"))
            .unwrap();
        let metadata = known_installed_output(&path, &object_id(METADATA).unwrap()).unwrap();
        register(&paths, &fixture, &offer, &[metadata]).unwrap();
        let inputs = paths
            .capture_committed_inputs(
                &fixture.coord,
                observed(&paths, false),
                CommittedDependencyPolicy::WorkspaceRlib,
            )
            .unwrap();
        fixture.quarantine(&offer.manifest.action_key);
        assert!(inputs.verify_original().is_err());
        assert!(
            paths
                .capture_committed_inputs(
                    &fixture.coord,
                    observed(&paths, false),
                    CommittedDependencyPolicy::WorkspaceRlib,
                )
                .is_err()
        );
        let metadata = known_installed_output(&path, &object_id(METADATA).unwrap()).unwrap();
        assert!(register(&paths, &fixture, &offer, &[metadata]).is_err());
    }
}
