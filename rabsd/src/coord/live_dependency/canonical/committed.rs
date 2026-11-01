//! One canonical operation's committed Rust artifact installation witnesses.
//!
//! Neither a path, a digest memo, a published-but-uninstalled output nor a raw
//! completion can mint a witness. The published-result installation owners call
//! this registry only after verifying actual files in place. Metadata is
//! registered before notifying Cargo; archives require complete installation.

use super::CanonicalPaths;
use crate::coord::live::CoordLive;
use crate::coord::live_dependency::remote::{QualifiedImmutableDependencyLeaf, RemoteValidation};
use crate::coord::live_dependency::{
    KnownOutput, LiveDependencyRequest, committed_output, object_id,
};
use crate::edge::live_facts::{DependencyFacts, FileSig};
use rabs_cas::manifest_codec::encode_manifest_v1;
use rabs_cas::metadata_store::digest_key;
use rabs_cas::publication::ProvisionalAncestorRef;
use rabs_key::live_dependency::DependencySourceKind;
use rabs_key::live_dependency::workspace_dependency_cache::{
    CommittedWorkspaceDependency, validate_committed_workspace_dependencies,
};
use rabs_protocol::authority::CoordinatorAuthority;
use rabs_protocol::result_identity::{CanonicalActionResultManifest, ObjectId, OutputRole};
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, Weak};

// Several profiles/directories can occur within an operation. A full registry
// stops minting entries; future consumers safely retain fresh execution.
const MAX_COMMITTED_OUTPUTS: usize = 16_384;

#[derive(Debug, Clone)]
struct InstalledProducer {
    generation: FileSig,
    authority: CoordinatorAuthority,
    dependency: CommittedWorkspaceDependency,
}

#[derive(Debug, Default)]
pub(super) struct CommittedOutputs(Mutex<BTreeMap<PathBuf, InstalledProducer>>);

/// Opaque proof for one original dependency observation. Only the canonical
/// operation can construct it from verified committed installations. Neither
/// equal bytes nor a refreshed observation can substitute another generation.
#[derive(Debug)]
pub struct CommittedWorkspaceInputs {
    paths: Arc<CanonicalPaths>,
    observed: Arc<DependencyFacts>,
    consumer_kind: DependencySourceKind,
    coordinator: Weak<CoordLive>,
    authority: CoordinatorAuthority,
    generations: Vec<(PathBuf, FileSig)>,
    dependencies: Vec<CommittedWorkspaceDependency>,
}

impl CommittedWorkspaceInputs {
    pub(crate) fn dependencies(&self) -> &[CommittedWorkspaceDependency] {
        &self.dependencies
    }

    pub(crate) fn verify(&self, request: &LiveDependencyRequest) -> Result<(), String> {
        if request.plan.source_kind != self.consumer_kind
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
    pub(crate) fn verify_for_kind(
        &self,
        consumer_kind: DependencySourceKind,
    ) -> Result<(), String> {
        if consumer_kind != self.consumer_kind {
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
        coordinator
            .verify_committed_workspace_dependencies(&self.dependencies, self.consumer_kind)?;
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
    /// Every retained candidate, including unreferenced alternatives, must be an
    /// exact current generation installed by this operation from an admitted
    /// producer. The consumer class retains its own producer-policy boundary.
    pub(crate) fn capture_committed_workspace_inputs(
        self: &Arc<Self>,
        coordinator: &Arc<CoordLive>,
        observed: Arc<DependencyFacts>,
        consumer_kind: DependencySourceKind,
    ) -> Result<Arc<CommittedWorkspaceInputs>, String> {
        if !matches!(
            consumer_kind,
            DependencySourceKind::WorkspaceCommittedRlib
                | DependencySourceKind::WorkspaceCommittedMetadata
                | DependencySourceKind::WorkspaceMixedRlib
                | DependencySourceKind::WorkspaceMixedMetadata
        ) {
            return Err(
                "committed dependency capture requires an exact committed consumer class".into(),
            );
        }
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
            consumer_kind,
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
                let Some(qualified) = remote.immutable_dependency_leaf(request)? else {
                    return Ok(());
                };
                Some(qualified)
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
        coordinator.verify_committed_workspace_dependencies(
            &pending
                .iter()
                .map(|(_, _, dependency)| dependency.clone())
                .collect::<Vec<_>>(),
            // Registration retains every admitted producer family. Capture
            // and every later recheck separately enforce the consumer's kind;
            // archive consumers retain their original archive-only ancestry.
            DependencySourceKind::WorkspaceMixedMetadata,
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
                .capture_committed_workspace_inputs(
                    &fixture.coord,
                    Arc::clone(&before),
                    DependencySourceKind::WorkspaceMixedMetadata,
                )
                .is_err(),
            "committed-but-unregistered files have no installation capability"
        );
        register(&original, &fixture, &offer, &[installed]).unwrap();
        let inputs = original
            .capture_committed_workspace_inputs(
                &fixture.coord,
                Arc::clone(&before),
                DependencySourceKind::WorkspaceMixedMetadata,
            )
            .unwrap();
        inputs.verify_original().unwrap();
        assert_eq!(inputs.ancestors().len(), 1);
        assert_eq!(
            inputs.ancestors()[0].producer_action_key,
            offer.manifest.action_key
        );
        for other in [
            DependencySourceKind::WorkspaceMixedRlib,
            DependencySourceKind::WorkspaceCommittedRlib,
            DependencySourceKind::WorkspaceCommittedMetadata,
        ] {
            assert!(inputs.verify_for_kind(other).is_err());
            assert!(
                original
                    .capture_committed_workspace_inputs(&fixture.coord, Arc::clone(&before), other,)
                    .is_err(),
                "external metadata cannot lend authority to {other:?}"
            );
        }
        let copied = paths();
        let _installed = install_bytes(&copied, &offer, "libupstream.rmeta", METADATA);
        assert!(
            copied
                .capture_committed_workspace_inputs(
                    &fixture.coord,
                    observed(&copied, false),
                    DependencySourceKind::WorkspaceMixedMetadata,
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
                .capture_committed_workspace_inputs(
                    &fixture.coord,
                    observed(&original, false),
                    DependencySourceKind::WorkspaceMixedMetadata,
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
            .capture_committed_workspace_inputs(
                &fixture.coord,
                observed(&original, false),
                DependencySourceKind::WorkspaceMixedMetadata,
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
            DependencySourceKind::WorkspaceMixedRlib,
            DependencySourceKind::WorkspaceMixedMetadata,
        ] {
            let captured = paths
                .capture_committed_workspace_inputs(
                    &fixture.coord,
                    observed(&paths, false),
                    consumer,
                )
                .unwrap();
            assert_eq!(captured.dependencies().len(), 1);
            assert_eq!(
                captured.dependencies()[0].role,
                OutputRole::ProvisionalMetadata
            );
        }
        for consumer in [
            DependencySourceKind::WorkspaceCommittedRlib,
            DependencySourceKind::WorkspaceCommittedMetadata,
        ] {
            assert!(
                paths
                    .capture_committed_workspace_inputs(
                        &fixture.coord,
                        observed(&paths, false),
                        consumer,
                    )
                    .is_err()
            );
        }
        let archive = install_bytes(&paths, &offer, "libupstream.rlib", ARCHIVE);
        assert!(
            paths
                .capture_committed_workspace_inputs(
                    &fixture.coord,
                    observed(&paths, true),
                    DependencySourceKind::WorkspaceMixedRlib,
                )
                .is_err(),
            "manifest membership and file presence do not register the tail"
        );
        // Existing metadata-shadowing projection remains unchanged: an unused
        // sibling archive is not part of the retained candidate namespace.
        assert_eq!(
            paths
                .capture_committed_workspace_inputs(
                    &fixture.coord,
                    observed(&paths, false),
                    DependencySourceKind::WorkspaceMixedRlib,
                )
                .unwrap()
                .dependencies()
                .len(),
            1
        );
        register(&paths, &fixture, &offer, &[archive]).unwrap();
        let complete = paths
            .capture_committed_workspace_inputs(
                &fixture.coord,
                observed(&paths, true),
                DependencySourceKind::WorkspaceMixedRlib,
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
                .capture_committed_workspace_inputs(
                    &fixture.coord,
                    observed(&paths, true),
                    DependencySourceKind::WorkspaceMixedRlib,
                )
                .is_err()
        );
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
        for (kind, other) in [
            (
                DependencySourceKind::WorkspaceCommittedRlib,
                DependencySourceKind::WorkspaceCommittedMetadata,
            ),
            (
                DependencySourceKind::WorkspaceCommittedMetadata,
                DependencySourceKind::WorkspaceCommittedRlib,
            ),
        ] {
            let captured = paths
                .capture_committed_workspace_inputs(&fixture.coord, Arc::clone(&candidates), kind)
                .unwrap();
            captured.verify_for_kind(kind).unwrap();
            assert!(captured.verify_for_kind(other).is_err());
        }
        for kind in [
            DependencySourceKind::WorkspaceExecutionOnly,
            DependencySourceKind::WorkspaceClosedRlib,
            DependencySourceKind::WorkspaceClosedMetadata,
            DependencySourceKind::RegistryPackage,
        ] {
            assert!(
                paths
                    .capture_committed_workspace_inputs(
                        &fixture.coord,
                        Arc::clone(&candidates),
                        kind
                    )
                    .is_err()
            );
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
            .capture_committed_workspace_inputs(
                &fixture.coord,
                Arc::clone(&candidates),
                DependencySourceKind::WorkspaceCommittedMetadata,
            )
            .unwrap();
        metadata
            .verify_for_kind(DependencySourceKind::WorkspaceCommittedMetadata)
            .unwrap();
        assert!(
            metadata
                .verify_for_kind(DependencySourceKind::WorkspaceCommittedRlib)
                .is_err()
        );
        assert!(
            paths
                .capture_committed_workspace_inputs(
                    &fixture.coord,
                    candidates,
                    DependencySourceKind::WorkspaceCommittedRlib,
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
            .capture_committed_workspace_inputs(
                &fixture.coord,
                observed(&paths, false),
                DependencySourceKind::WorkspaceCommittedRlib,
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
                .capture_committed_workspace_inputs(
                    &fixture.coord,
                    observed(&paths, true),
                    DependencySourceKind::WorkspaceCommittedRlib,
                )
                .is_err()
        );
        // Existing projection omits the non-explicit shadowed archive entirely.
        assert_eq!(
            paths
                .capture_committed_workspace_inputs(
                    &fixture.coord,
                    observed(&paths, false),
                    DependencySourceKind::WorkspaceCommittedRlib,
                )
                .unwrap()
                .dependencies()
                .len(),
            1
        );
        register(&paths, &fixture, &offer, &[archive]).unwrap();
        let complete = paths
            .capture_committed_workspace_inputs(
                &fixture.coord,
                observed(&paths, true),
                DependencySourceKind::WorkspaceCommittedRlib,
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
                .capture_committed_workspace_inputs(
                    &fixture.coord,
                    observed(&paths, false),
                    DependencySourceKind::WorkspaceCommittedRlib,
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
            .capture_committed_workspace_inputs(
                &fixture.coord,
                observed(&paths, false),
                DependencySourceKind::WorkspaceCommittedRlib,
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
                .capture_committed_workspace_inputs(
                    &fixture.coord,
                    observed(&paths, false),
                    DependencySourceKind::WorkspaceCommittedRlib,
                )
                .is_err()
        );
        // A verified reinstall may mint the new generation; old observations
        // never refresh themselves or inherit the new witness.
        let verified = known_installed_output(&path, &same_object).unwrap();
        register(&paths, &fixture, &offer, &[verified]).unwrap();
        paths
            .capture_committed_workspace_inputs(
                &fixture.coord,
                observed(&paths, false),
                DependencySourceKind::WorkspaceCommittedRlib,
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
            .capture_committed_workspace_inputs(
                &fixture.coord,
                observed(&original, false),
                DependencySourceKind::WorkspaceCommittedRlib,
            )
            .unwrap();
        let other = paths();
        let _copied = install_bytes(&other, &offer, "libupstream.rmeta", METADATA);
        assert!(
            other
                .capture_committed_workspace_inputs(
                    &fixture.coord,
                    observed(&other, false),
                    DependencySourceKind::WorkspaceCommittedRlib,
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
            .capture_committed_workspace_inputs(
                &fixture.coord,
                observed(&paths, false),
                DependencySourceKind::WorkspaceCommittedRlib,
            )
            .unwrap();
        fixture.quarantine(&offer.manifest.action_key);
        assert!(inputs.verify_original().is_err());
        assert!(
            paths
                .capture_committed_workspace_inputs(
                    &fixture.coord,
                    observed(&paths, false),
                    DependencySourceKind::WorkspaceCommittedRlib,
                )
                .is_err()
        );
        let metadata = known_installed_output(&path, &object_id(METADATA).unwrap()).unwrap();
        assert!(register(&paths, &fixture, &offer, &[metadata]).is_err());
    }
}
