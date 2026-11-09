//! Attempt-bound preparation joins the namespace without changing source selection.

use super::*;
use rch_common::prepared_dependencies::{
    PREPARED_DEPENDENCY_VERSION, PreparedDependencyAttestation, PreparedDependencyFile,
    PreparedDependencyFileKind, PreparedDependencyInventory, PreparedDependencyRequest,
    PreparedDependencyState, union_selected_inventory, validate_attestation, validate_request,
    validate_state,
};

#[derive(Clone)]
pub(super) struct PreparedDependencyProof {
    request: PreparedDependencyRequest,
    state: PreparedDependencyState,
    attestation: Option<PreparedDependencyAttestation>,
}

impl PreparedDependencyProof {
    pub(super) fn source_owner(&self) -> &str {
        &self.request.source_owner
    }
}

fn selected_inventory(
    root: &PreparedSourceContentRoot,
) -> anyhow::Result<PreparedDependencyInventory> {
    let files = root
        .manifest
        .files
        .iter()
        .map(|file| PreparedDependencyFile {
            path: file.path.clone(),
            kind: match file.kind {
                SourceContentEntryKind::Regular => PreparedDependencyFileKind::Regular,
                SourceContentEntryKind::Symlink => PreparedDependencyFileKind::Symlink,
            },
            sha256: file.sha256.clone(),
            byte_count: file.byte_count,
            executable: file.executable,
            symlink_target: file.symlink_target.clone(),
        })
        .collect();
    let mut directories = root
        .directories
        .iter()
        .map(|path| {
            path.to_str()
                .map(str::to_owned)
                .context("prepared dependency source directory is not UTF-8")
        })
        .collect::<anyhow::Result<Vec<_>>>()?;
    // The shared wire contract uses String ordering, while rsync uses PathBuf.
    directories.sort();
    Ok(PreparedDependencyInventory { files, directories })
}

fn validate_root_request(
    root: &PreparedSourceContentRoot,
    request: &PreparedDependencyRequest,
) -> anyhow::Result<()> {
    validate_request(request)?;
    let spec = root
        .clean_overlay
        .as_ref()
        .context("prepared dependency proof requires a clean-overlay source root")?;
    let selected = selected_inventory(root)?;
    anyhow::ensure!(
        root.manifest.is_primary
            && root.manifest.mode == SyncClosureMode::Full
            && root.clean_overlay_namespace.is_some()
            && request.source_root == root.manifest.remote_root
            && request.source_content_root == root.manifest.content_root
            && Path::new(&request.project_relative) == spec.invocation_directory
            && request.files == selected.files
            && request.directories == selected.directories,
        "prepared dependency request does not bind the exact selected execution root"
    );
    anyhow::ensure!(
        request.preparation_relative() == selected_preparation_root(root, request)?,
        "prepared dependency root differs from the selected workspace declaration"
    );
    Ok(())
}

fn selected_preparation_root(
    root: &PreparedSourceContentRoot,
    request: &PreparedDependencyRequest,
) -> anyhow::Result<String> {
    let regular = request
        .files
        .iter()
        .filter(|file| file.kind == PreparedDependencyFileKind::Regular)
        .map(|file| file.path.clone())
        .collect();
    rch_common::node_workspace::resolve_preparation_root(
        &request.project_relative,
        &regular,
        &root.workspace_declarations,
    )
    .map_err(anyhow::Error::msg)
}

/// Only classified Node/Bun clean-overlay executions acquire this obligation.
/// A standalone Bun script with no selected package manifest needs no installer.
pub(in crate::hook) fn prepare_dependency_request(
    prepared: &[PreparedSourceContentRoot],
    remote_cwd: &str,
    kind: Option<CompilationKind>,
    build_id: u64,
    attempt_id: &str,
    source_identity: &str,
    policy_command: &str,
) -> anyhow::Result<Option<PreparedDependencyRequest>> {
    if !matches!(
        kind,
        Some(CompilationKind::Tsc | CompilationKind::BunTest | CompilationKind::BunTypecheck)
    ) {
        return Ok(None);
    }
    let mut candidates = prepared
        .iter()
        .filter(|root| root.manifest.is_primary && root.clean_overlay.is_some());
    let Some(root) = candidates.next() else {
        return Ok(None);
    };
    anyhow::ensure!(
        candidates.next().is_none(),
        "prepared dependency execution has multiple primary clean-overlay roots"
    );
    let relative = Path::new(remote_cwd)
        .strip_prefix(&root.manifest.remote_root)
        .context("prepared dependency execution directory escapes the selected source root")?;
    let project_relative = relative
        .to_str()
        .context("prepared dependency execution directory is not UTF-8")?
        .to_owned();
    let expected_cwd = if project_relative.is_empty() {
        root.manifest.remote_root.clone()
    } else {
        format!("{}/{project_relative}", root.manifest.remote_root)
    };
    anyhow::ensure!(
        expected_cwd == remote_cwd,
        "prepared dependency execution directory must be a literal source path"
    );
    if !project_relative.is_empty() {
        selected_source_path(&project_relative)?;
    }
    anyhow::ensure!(
        relative
            == root
                .clean_overlay
                .as_ref()
                .context("prepared dependency source lost its clean-overlay policy")?
                .invocation_directory,
        "prepared dependency execution directory differs from the selected invocation"
    );
    let package_manifest = if project_relative.is_empty() {
        "package.json".to_owned()
    } else {
        format!("{project_relative}/package.json")
    };
    let selected = selected_inventory(root)?;
    if !selected
        .files
        .iter()
        .any(|file| file.path == package_manifest)
    {
        return Ok(None);
    }
    let mut request = PreparedDependencyRequest {
        schema_version: PREPARED_DEPENDENCY_VERSION,
        attempt_id: attempt_id.to_owned(),
        source_owner: source_identity.to_owned(),
        build_id: build_id.to_string(),
        command_sha256: sha256_hex(policy_command.as_bytes()),
        source_content_root: root.manifest.content_root.clone(),
        source_root: root.manifest.remote_root.clone(),
        project_relative,
        preparation_relative: None,
        files: selected.files,
        directories: selected.directories,
    };
    let preparation = selected_preparation_root(root, &request)?;
    if preparation != request.project_relative {
        request.preparation_relative = Some(preparation);
    }
    validate_root_request(root, &request)?;
    Ok(Some(request))
}

fn proof_inventory(
    root: &PreparedSourceContentRoot,
) -> anyhow::Result<PreparedDependencyInventory> {
    let Some(proof) = &root.prepared_dependencies else {
        return selected_inventory(root);
    };
    validate_root_request(root, &proof.request)?;
    validate_state(&proof.request, &proof.state)?;
    if let Some(attestation) = &proof.attestation {
        validate_attestation(&proof.request, attestation)?;
        anyhow::ensure!(
            proof.state == attestation.state,
            "prepared dependency attestation state changed after attachment"
        );
    }
    Ok(union_selected_inventory(
        &proof.request,
        &proof.state.inventory,
    )?)
}

pub(super) fn namespace_inventory(
    root: &PreparedSourceContentRoot,
) -> anyhow::Result<(Vec<PathBuf>, Vec<PathBuf>)> {
    let inventory = proof_inventory(root)?;
    let mut files = inventory
        .files
        .into_iter()
        .map(|file| PathBuf::from(file.path))
        .collect::<Vec<_>>();
    let mut directories = inventory
        .directories
        .into_iter()
        .map(PathBuf::from)
        .collect::<Vec<_>>();
    files.sort();
    directories.sort();
    Ok((files, directories))
}

async fn attach_proof(
    prepared: &mut [PreparedSourceContentRoot],
    proof: PreparedDependencyProof,
) -> anyhow::Result<()> {
    let mut matching = prepared.iter().enumerate().filter(|(_, root)| {
        root.manifest.remote_root == proof.request.source_root
            && root.manifest.content_root == proof.request.source_content_root
    });
    let (index, root) = matching
        .next()
        .context("prepared dependency proof has no matching selected source root")?;
    anyhow::ensure!(
        matching.next().is_none(),
        "prepared dependency proof matches multiple source roots"
    );
    validate_root_request(root, &proof.request)?;
    if let Some(previous) = &root.prepared_dependencies {
        anyhow::ensure!(
            previous.request == proof.request && previous.attestation.is_none(),
            "prepared dependency proof cannot replace an attempt or a completed attestation"
        );
    }
    // Publish the union only after the actual rsync filter policy accepts every
    // name. A cancelled or failed rebuild leaves the old obligation intact.
    let mut candidate = root.clone();
    candidate.prepared_dependencies = Some(proof);
    let (files, directories) = namespace_inventory(&candidate)?;
    let namespace = tokio::task::spawn_blocking(move || {
        create_clean_overlay_source_namespace(&files, &directories)
    })
    .await
    .context("join prepared dependency namespace construction")??;
    candidate.clean_overlay_namespace = Some(Arc::new(namespace));
    clean_overlay_namespace_pipeline(&candidate).await?;
    prepared[index] = candidate;
    Ok(())
}

/// Prior state can authorize a namespace check, but never a final receipt.
pub(in crate::hook) async fn attach_prepared_state(
    prepared: &mut [PreparedSourceContentRoot],
    request: &PreparedDependencyRequest,
    state: &PreparedDependencyState,
) -> anyhow::Result<()> {
    validate_state(request, state)?;
    attach_proof(
        prepared,
        PreparedDependencyProof {
            request: request.clone(),
            state: state.clone(),
            attestation: None,
        },
    )
    .await
}

pub(in crate::hook) async fn attach_prepared_attestation(
    prepared: &mut [PreparedSourceContentRoot],
    request: &PreparedDependencyRequest,
    attestation: &PreparedDependencyAttestation,
) -> anyhow::Result<()> {
    validate_attestation(request, attestation)?;
    attach_proof(
        prepared,
        PreparedDependencyProof {
            request: request.clone(),
            state: attestation.state.clone(),
            attestation: Some(attestation.clone()),
        },
    )
    .await
}

/// Reuse the independent worker SHA verifier for every attested dependency.
/// This ephemeral manifest is never substituted for the selected source root.
pub(super) fn verification_manifest(
    root: &PreparedSourceContentRoot,
) -> anyhow::Result<Option<SourceContentRootManifest>> {
    let Some(proof) = &root.prepared_dependencies else {
        return Ok(None);
    };
    proof_inventory(root)?;
    output_verification_manifest(&root.manifest, &proof.state.inventory).map(Some)
}

fn output_verification_manifest(
    source: &SourceContentRootManifest,
    inventory: &PreparedDependencyInventory,
) -> anyhow::Result<SourceContentRootManifest> {
    let mut manifest = source.clone();
    manifest.files = inventory
        .files
        .iter()
        .map(|file| SourceContentFile {
            path: file.path.clone(),
            kind: match file.kind {
                PreparedDependencyFileKind::Regular => SourceContentEntryKind::Regular,
                PreparedDependencyFileKind::Symlink => SourceContentEntryKind::Symlink,
            },
            symlink_target: file.symlink_target.clone(),
            sha256: file.sha256.clone(),
            byte_count: file.byte_count,
            executable: file.executable,
        })
        .collect();
    manifest.file_count = manifest.files.len();
    manifest.byte_count = manifest.files.iter().try_fold(0_u64, |sum, file| {
        sum.checked_add(file.byte_count)
            .context("prepared dependency verification byte count overflow")
    })?;
    Ok(manifest)
}

pub(super) fn receipt_attestations(
    prepared: &[PreparedSourceContentRoot],
    build_id: &str,
    command_sha256: &str,
) -> anyhow::Result<Vec<PreparedDependencyAttestation>> {
    let mut attestations = Vec::new();
    for root in prepared {
        // Coalescing only absorbs non-primary roots. It cannot hide a second
        // installer or silently discard an independently captured obligation.
        let mut children = root.coalesced.iter().collect::<Vec<_>>();
        while let Some(child) = children.pop() {
            anyhow::ensure!(
                child.prepared_dependencies.is_none(),
                "coalesced source root carries an unrepresented preparation proof"
            );
            children.extend(&child.coalesced);
        }
        let Some(proof) = &root.prepared_dependencies else {
            continue;
        };
        proof_inventory(root)?;
        let attestation = proof
            .attestation
            .as_ref()
            .context("prior prepared dependency state cannot authorize a source receipt")?;
        anyhow::ensure!(
            proof.request.build_id == build_id && proof.request.command_sha256 == command_sha256,
            "prepared dependency attestation belongs to another build or command"
        );
        attestations.push(attestation.clone());
    }
    Ok(attestations)
}
