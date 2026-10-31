//! Coordinator-side source upload from an approved coherent snapshot.
//!
//! Only explicitly selected regular files leave the captured image. The sender
//! never rereads a mutable checkout, walks worker paths, or dispatches execution.
//! It uses the sandbox's ONE manifest identity implementation and verifies every
//! transfer reply before the delivery engine reaches its execution frontier.
//! Source availability is not action-key validity or cache-publication authority.

pub(crate) mod control;
mod preparation;
mod toolchain;

pub use super::source_manifest::request_manifest;
use super::source_manifest::{digest, invalid, require};
use super::worker_delivery::{MAX_FRAME_BYTES, WorkerAuthentication, WorkerPeer, validate_request};
use crate::edge::live_facts::RetainedDependencyArtifact;
use rabs_asupersync::worker_transport::MAX_JSON_RECORD;
use rabs_sandbox::cargo_home::ISOLATED_GIT_CARGO_HOME_SOURCE_VERSION;
#[cfg(all(test, unix))]
use rabs_sandbox::cargo_home::{CARGO_HOME_SOURCE_VERSION, CargoHomeProjection};
use rabs_sandbox::generated_source::GeneratedSource;
#[cfg(all(test, unix))]
use rabs_sandbox::snapshot_capture::capture_sealed_source;
use rabs_sandbox::snapshot_capture::{MemberKind, SealedSourceSnapshot};
use rabs_sandbox::source_transfer::{
    MAX_SOURCE_CHUNK, MAX_SOURCE_FILES, SOURCE_TRANSFER, SourceFile, SourceManifest, SourceReceiver,
};
use rabs_sandbox::toolchain_cache::RetainedToolchain;
use rabs_sandbox::toolchain_dataset::{
    PreparedToolchain, ToolchainLimits, capture_toolchain_with_cloner,
};
use rabs_sandbox::toolchain_transfer::TOOLCHAIN_TRANSFER_VERSION;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::path::{Component, Path, PathBuf};
use std::sync::Arc;

use control::PreparationControl;

enum PreparationToolchain {
    Captured(PreparedToolchain),
    Retained(Arc<RetainedToolchain>),
}

impl PreparationToolchain {
    fn image(&self) -> &PreparedToolchain {
        match self {
            Self::Captured(image) => image,
            Self::Retained(owner) => owner.image(),
        }
    }

    fn root(&self) -> &Path {
        self.image().root()
    }

    fn attach(self, upload: SourceUpload, request: &Value) -> io::Result<SourceUpload> {
        match self {
            Self::Captured(image) => upload.with_toolchain(image, request),
            Self::Retained(owner) => upload.with_retained_toolchain(owner, request),
        }
    }
}

/// Bound the number of independently captured repositories in one source tree.
pub const MAX_SOURCE_ROOTS: usize = 64;
// Outstanding chunks, not concurrent filesystem writers on the worker.
const SOURCE_WINDOW: usize = 4;

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn manifest_value(manifest: &SourceManifest) -> Value {
    json!({"manifest_sha256":hex(&manifest.digest()),
        "files":manifest.files().iter().map(|file| json!({
            "path":file.path, "bytes":file.len, "sha256":hex(&file.sha256), "executable":file.executable,
        })).collect::<Vec<_>>()})
}

/// Prepare an executable request AND retain its exact source bytes in a new
/// private directory. This is a blocking operator operation, not reactor work.
/// Select either source_files for one root, or source_roots mapping stable IDs
/// to {path, files}. Relative host paths resolve against source_root; absolute
/// paths explicitly select another checkout. A closure's files are installed as
/// ID/relative-path under /__rabs/workspace, preserving sibling path dependencies.
/// All roots share ONE paired capture; only selected regular files are copied.
/// Alternatively cargo_source: {manifest: "app/Cargo.toml"} resolves a locked,
/// offline local Cargo graph from a retained copy of the entire approved anchor.
/// It includes every captured regular file, preserving build-script/include data.
/// That mode may run compiler probes, never builds. Explicit vendor selection
/// adds checked crates.io and locked Git directory sources. Other Cargo config
/// and symlinks refuse; manifests and source replacements are not rewritten.
/// Optional cargo_home selects an admitted cache prefix in an explicitly selected
/// manifest; its version/prefix is preserved for worker-side private Cargo-home replay.
///
/// The directory contains source/ and request.json. All selected source files
/// are verified through SourceReceiver and synced before request.json is even
/// created. The latter is the readiness marker: a failed/partial bundle is
/// retained, never overwritten, retried in place, or silently dispatched.
/// Execute using that source directory, NOT the mutable original checkout.
/// Recapture at execution still verifies the saved manifest before dispatch.
/// Host root paths are stripped from the prepared request, not sent to workers.
/// The supplied command_context/argv remains exact; use a canonical member cwd
/// when Cargo's manifest lives under a selected ID instead of the workspace root.
///
/// The caller owns the destination parent and excludes concurrent modification
/// by processes with its own credentials, as for ordinary worker deliveries.
///
/// # Errors
/// Invalid/conflicting specifications, unsafe or missing selected members,
/// incoherent capture, resource limits, existing destinations, and I/O failures.
pub fn prepare_source_bundle(
    source_root: &Path,
    specification: &Value,
    destination: &Path,
) -> io::Result<Value> {
    prepare_source_bundle_inner(
        source_root,
        specification,
        destination,
        false,
        false,
        None,
        &PreparationControl::uncontrolled(),
    )
    .map(|(report, _source)| report)
}

/// Retain the selected service-owned compiler image while preparing independent
/// source bytes. The lease is a driver capability, never a decoded host path.
/// The canonical driver keeps the sealed receiver alive for Cargo projection.
#[cfg(target_os = "linux")]
pub(crate) fn prepare_local_bundle_controlled(
    source_root: &Path,
    specification: &Value,
    destination: &Path,
    toolchain: Option<Arc<RetainedToolchain>>,
    control: &PreparationControl<'_>,
) -> io::Result<(Value, SourceReceiver)> {
    prepare_source_bundle_inner(
        source_root,
        specification,
        destination,
        false,
        true,
        toolchain,
        control,
    )
}

/// Capture immutable inputs for a daemon job whose worker request ID is not yet
/// allocated. The saved request remains explicit LOCAL allocation intent and is
/// rejected by every execution-wire validator. Only the daemon's exclusive
/// claimed owner may bind an actual ID, immediately before authenticated dispatch.
///
/// # Errors
/// The same capture/placement errors as [`prepare_source_bundle`], or any
/// specification that does not request exactly `request_id: "allocate"`.
pub fn prepare_source_template(
    source_root: &Path,
    specification: &Value,
    destination: &Path,
) -> io::Result<Value> {
    require(
        specification["kind"] == "canonical-exec"
            && specification["request_id"].as_str() == Some("allocate"),
        "daemon source templates require explicit request allocation intent",
    )?;
    let mut probe = specification.clone();
    // This zero exists only during the ordinary source/request validators. It
    // is never written to request.json, returned as an identity, or dispatched.
    probe["request_id"] = json!(0);
    prepare_source_bundle_inner(
        source_root,
        &probe,
        destination,
        true,
        false,
        None,
        &PreparationControl::uncontrolled(),
    )
    .map(|(report, _source)| report)
}

fn prepare_source_bundle_inner(
    source_root: &Path,
    specification: &Value,
    destination: &Path,
    allocation_intent: bool,
    selected_planning_toolchain: bool,
    retained_toolchain: Option<Arc<RetainedToolchain>>,
    control: &PreparationControl<'_>,
) -> io::Result<(Value, SourceReceiver)> {
    control.checkpoint()?;
    let inputs = preparation::SourcePreparation::parse(source_root, specification)?;
    require(
        destination.is_absolute()
            && destination.file_name().is_some()
            && destination
                .components()
                .all(|part| matches!(part, Component::RootDir | Component::Normal(_))),
        "bundle destination must be absolute without traversal",
    )?;
    let parent = fs::canonicalize(
        destination
            .parent()
            .ok_or_else(|| invalid("bundle parent"))?,
    )?;
    let destination = parent.join(
        destination
            .file_name()
            .ok_or_else(|| invalid("bundle name"))?,
    );
    require(destination.to_str().is_some(), "bundle path must be UTF-8")?;
    match fs::symlink_metadata(&destination) {
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(error),
        Ok(_) => {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                "bundle destination already exists",
            ));
        }
    }
    // The selected compiler tree is retained with source. It no longer relies
    // on a corresponding path or preinstalled compiler on the eventual worker.
    let expected_toolchain = super::worker_delivery::toolchain_identity(specification)?;
    let toolchain_source = specification
        .get("toolchain_source")
        .map(|value| {
            let path = value
                .as_str()
                .filter(|path| !path.is_empty() && path.len() <= 4096)
                .ok_or_else(|| invalid("toolchain_source must be an absolute local directory"))?;
            let path = PathBuf::from(path);
            require(path.is_absolute(), "toolchain_source must be absolute")?;
            let canonical = fs::canonicalize(&path)?;
            require(
                !destination.starts_with(&canonical),
                "bundle destination must be outside the selected toolchain",
            )?;
            if let Some(expected) = &expected_toolchain
                && retained_toolchain.is_none()
            {
                // Reject a caller's stale explicit pin before creating output.
                // Capture still checks the pin again across its own mutation
                // barrier; this preflight never authorizes later bytes.
                let current = rabs_sandbox::toolchain_dataset::fingerprint_toolchain(
                    &path,
                    &ToolchainLimits::default(),
                    || control.is_cancelled(),
                )?;
                require(
                    &current == expected,
                    "local toolchain does not match the specified toolchain_identity",
                )?;
            }
            Ok::<_, io::Error>(path)
        })
        .transpose()?;
    if let Some(retained) = &retained_toolchain {
        require(
            selected_planning_toolchain,
            "retained toolchains are only admitted by the canonical driver",
        )?;
        let source = toolchain_source
            .as_ref()
            .ok_or_else(|| invalid("retained toolchain requires an explicit source binding"))?;
        retained.verify(source, || control.is_cancelled())?;
        if let Some(expected) = &expected_toolchain {
            require(
                retained.image().identity() == expected,
                "retained toolchain does not match the specified toolchain_identity",
            )?;
        }
    }
    control.checkpoint()?;
    // The local canonical bridge must not run an ambient RUSTC/CARGO during
    // source planning. Capture the selected dataset first and plan through its
    // retained executable paths. Existing operator preparation keeps its
    // ordinary validate-before-destination behavior.
    let planning_toolchain = if selected_planning_toolchain {
        let source = toolchain_source
            .as_ref()
            .ok_or_else(|| invalid("canonical preparation requires toolchain_source"))?;
        let mut builder = fs::DirBuilder::new();
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt;
            builder.mode(0o700);
        }
        builder.create(&destination)?;
        if let Some(retained) = retained_toolchain {
            Some(PreparationToolchain::Retained(retained))
        } else {
            let prepared = capture_toolchain_with_cloner(
                source,
                &destination.join("toolchain"),
                expected_toolchain.as_ref(),
                &ToolchainLimits::default(),
                || control.is_cancelled(),
                rabs_cas::materialization::try_verified_reflink,
            )?;
            prepared.sync(|| control.is_cancelled())?;
            Some(PreparationToolchain::Captured(prepared))
        }
    } else {
        None
    };
    let mut upload = inputs.capture_controlled(
        planning_toolchain.as_ref().map(PreparationToolchain::root),
        control,
    )?;
    control.checkpoint()?;
    if let Some(prepared) = &planning_toolchain {
        prepared
            .image()
            .verify_retained_generation(|| control.is_cancelled())?;
    }
    if let Some(context) = specification.get("dependency_context") {
        require(
            context["version"] == rabs_sandbox::dependency_context::DEPENDENCY_CONTEXT_VERSION,
            "unsupported dependency execution context for source preparation",
        )?;
        require(
            context["artifact_roots"]
                .as_array()
                .is_some_and(Vec::is_empty),
            "dependency artifacts require the live keyed artifact observer",
        )?;
        require(
            context.get("generated_root").is_none_or(Value::is_null),
            "generated dependency inputs require the live Cargo output observer",
        )?;
        // Operator-prepared dependency leaves use the same package prefix as
        // live Cargo actions. Arbitrary operator paths cannot stand in for the
        // live observer's retained and keyed dependency artifact closure.
        upload = upload.with_dependency_artifacts(Vec::new())?;
    }
    let mut builder = fs::DirBuilder::new();
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }
    if planning_toolchain.is_none() {
        builder.create(&destination)?; // Exclusive; never merge into an old bundle.
    }
    let toolchain = if let Some(prepared) = planning_toolchain {
        Some(prepared)
    } else {
        toolchain_source
            .as_ref()
            .map(|source| {
                let prepared = capture_toolchain_with_cloner(
                    source,
                    &destination.join("toolchain"),
                    expected_toolchain.as_ref(),
                    &ToolchainLimits::default(),
                    || control.is_cancelled(),
                    rabs_cas::materialization::try_verified_reflink,
                )?;
                prepared.sync(|| control.is_cancelled())?;
                Ok::<_, io::Error>(PreparationToolchain::Captured(prepared))
            })
            .transpose()?
    };
    let mut request = specification.clone();
    let fields = request
        .as_object_mut()
        .ok_or_else(|| invalid("source preparation object"))?;
    fields.remove("source_files");
    fields.remove("source_roots");
    fields.remove("cargo_source");
    fields.remove("toolchain_source");
    if let Some(mut home) = inputs.cargo_home_projection() {
        let prefix = home["prefix"]
            .as_str()
            .ok_or_else(|| invalid("prepared Cargo home prefix missing"))?;
        let git_prefix = format!("{prefix}/git/db/");
        if upload
            .manifest
            .files()
            .iter()
            .any(|file| file.path.starts_with(&git_prefix))
        {
            // Negotiate the stronger shape only when the captured bundle
            // actually contains reconstructed Git objects. Registry-only
            // requests retain their existing exact saved-operation version.
            home["version"] = json!(ISOLATED_GIT_CARGO_HOME_SOURCE_VERSION);
        }
        fields.insert("cargo_home".to_owned(), home);
    }
    if let Some(prepared) = &toolchain {
        fields.remove("toolchain_backing");
        fields.insert(
            "toolchain_transfer".to_owned(),
            json!(TOOLCHAIN_TRANSFER_VERSION),
        );
        fields.insert(
            "toolchain_identity".to_owned(),
            super::worker_delivery::toolchain_identity_value(prepared.image().identity()),
        );
    }
    fields.insert("source_manifest".to_owned(), upload.wire_manifest());
    // One validator for prepared and hand-authored execution requests. This
    // preserves argv, output declarations, timeouts, and unknown extensions.
    validate_request(&request)?;
    let prepared_toolchain_root = toolchain.as_ref().map(|owner| owner.root().to_path_buf());
    if let Some(toolchain) = toolchain {
        upload = toolchain.attach(upload, &request)?;
    }
    upload.validate_request(&request)?;
    if allocation_intent {
        request["request_id"] = json!("allocate");
    }
    let request_bytes = serde_json::to_vec(&request)?;
    let source = destination.join("source");
    let mut receiver = SourceReceiver::create(&source, upload.manifest.clone())?;
    for file in upload.manifest.files() {
        control.checkpoint()?;
        let bytes = upload.file_bytes(&file.path)?;
        for (index, chunk) in bytes.chunks(MAX_SOURCE_CHUNK).enumerate() {
            control.checkpoint()?;
            receiver.write_chunk(
                &file.path,
                index as u64 * MAX_SOURCE_CHUNK as u64,
                chunk,
                Sha256::digest(chunk).into(),
            )?;
        }
    }
    control.checkpoint()?;
    receiver.seal_cancellable(|| control.is_cancelled())?;
    // Sync only the validated closure, children before parents. Reverse lexical
    // path order puts every directory after its descendants, including root.
    let mut directories = BTreeSet::from([PathBuf::new()]);
    for file in upload.manifest.files() {
        control.checkpoint()?;
        File::open(source.join(&file.path))?.sync_all()?;
        for directory in Path::new(&file.path).ancestors().skip(1) {
            directories.insert(directory.to_path_buf());
        }
    }
    for directory in directories.iter().rev() {
        control.checkpoint()?;
        File::open(source.join(directory))?.sync_all()?;
    }
    File::open(&destination)?.sync_all()?;
    // Full source durability precedes any parseable request. If this write or
    // sync fails, report failure and retain the new directory for inspection.
    control.checkpoint()?;
    let request_path = destination.join("request.json");
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut output = options.open(&request_path)?;
    output.write_all(&request_bytes)?;
    output.sync_all()?;
    File::open(&destination)?.sync_all()?;
    File::open(&parent)?.sync_all()?;
    Ok((
        json!({"kind":if allocation_intent {"prepared-source-template"} else {"prepared-source-bundle"}, "directory":destination,
        "source_root":source, "request_path":request_path, "request_id":request["request_id"],
        "request_sha256":hex(&Sha256::digest(&request_bytes)),
        "manifest_sha256":hex(&upload.manifest.digest()), "source_roots":inputs.root_count(),
        "source_files":upload.manifest.files().len(), "source_bytes":upload.manifest.total_bytes(),
        "toolchain_identity":request.get("toolchain_identity"),
        "toolchain_root":prepared_toolchain_root,
        "toolchain_transfer":request.get("toolchain_transfer"),
        "executed":false, "publication_authorized":false}),
        receiver,
    ))
}

#[derive(Debug, Clone)]
enum SourceLayout {
    /// Preserve the single-root protocol's original relative paths.
    Root(String),
    /// Each first path component names one root in the SAME captured image.
    Closure,
    /// Original package plus separately verified compiler dependency artifacts.
    /// Every retained byte belongs to the same source-transfer manifest.
    Dependency {
        root: String,
        generated: Option<GeneratedSource>,
        native: Vec<GeneratedSource>,
        artifacts: Arc<std::collections::BTreeMap<String, Arc<RetainedDependencyArtifact>>>,
        artifacts_selected: bool,
    },
}

fn valid_closure_root(root: &str) -> bool {
    use rabs_sandbox::snapshot_capture::{MemberDisposition, member_disposition};
    !root.is_empty()
        && root.len() <= 64
        && !matches!(root, "." | "..")
        && root
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"._-".contains(&byte))
        && member_disposition(root, false) == MemberDisposition::Include
}

/// Immutable captured bytes plus an explicit regular-file projection. The full
/// source snapshot digest is provenance, not substituted for the projected root.
#[derive(Debug, Clone)]
pub struct SourceUpload {
    image: Arc<SealedSourceSnapshot>,
    layout: SourceLayout,
    manifest: SourceManifest,
    toolchain: Option<toolchain::ToolchainUpload>,
}

impl SourceUpload {
    /// Callers apply their upload/confidentiality policy before selecting paths.
    /// This method cannot implicitly include siblings, symlink targets or secrets.
    pub fn from_snapshot(
        image: Arc<SealedSourceSnapshot>,
        root: &str,
        paths: &[String],
    ) -> io::Result<Self> {
        Self::from_snapshot_controlled(image, root, paths, &PreparationControl::uncontrolled())
    }

    pub(crate) fn from_snapshot_controlled(
        image: Arc<SealedSourceSnapshot>,
        root: &str,
        paths: &[String],
        control: &PreparationControl<'_>,
    ) -> io::Result<Self> {
        control.checkpoint()?;
        require(
            !paths.is_empty() && paths.len() <= MAX_SOURCE_FILES,
            "source projection file count",
        )?;
        let captured = image
            .manifest(root)
            .ok_or_else(|| invalid("unknown source snapshot root"))?;
        let mut files = Vec::with_capacity(paths.len());
        for path in paths {
            control.checkpoint()?;
            let Some(MemberKind::Regular {
                size,
                content_sha256,
                mode,
                ..
            }) = captured.members.get(path)
            else {
                return Err(invalid("projected source must be a captured regular file"));
            };
            let bytes = image
                .file_bytes(root, path)
                .ok_or_else(|| invalid("captured source bytes missing"))?;
            require(
                bytes.len() as u64 == *size && control.sha256(bytes)? == *content_sha256,
                "captured source disagrees with its manifest",
            )?;
            files.push(SourceFile {
                path: path.clone(),
                len: *size,
                sha256: *content_sha256,
                executable: mode & 0o111 != 0,
            });
        }
        Ok(Self {
            image,
            layout: SourceLayout::Root(root.to_owned()),
            manifest: SourceManifest::new(files)?,
            toolchain: None,
        })
    }

    /// Project several repositories from ONE coherent closure capture. Root IDs
    /// become directory names under /__rabs/workspace: app/Cargo.toml can retain
    /// an ordinary ../dep path dependency without rewriting either manifest.
    /// No separately captured snapshots can be combined by this constructor.
    ///
    /// Each tuple contains a logical snapshot root and its approved relative
    /// files. Only those files enter source-files-v1; the worker receives no host
    /// roots or new mounting instructions. A missing/unsafe member refuses the
    /// whole projection. This does not prove Cargo dependency completeness.
    pub fn from_snapshot_closure(
        image: Arc<SealedSourceSnapshot>,
        roots: &[(String, Vec<String>)],
    ) -> io::Result<Self> {
        Self::from_snapshot_closure_controlled(image, roots, &PreparationControl::uncontrolled())
    }

    pub(crate) fn from_snapshot_closure_controlled(
        image: Arc<SealedSourceSnapshot>,
        roots: &[(String, Vec<String>)],
        control: &PreparationControl<'_>,
    ) -> io::Result<Self> {
        use rabs_sandbox::snapshot_capture::{MemberDisposition, member_disposition};
        control.checkpoint()?;
        require(
            !roots.is_empty() && roots.len() <= MAX_SOURCE_ROOTS,
            "source closure root count",
        )?;
        let mut names = BTreeSet::new();
        let mut files = Vec::new();
        for (root, paths) in roots {
            control.checkpoint()?;
            require(
                valid_closure_root(root) && names.insert(root.to_ascii_lowercase()),
                "unsafe, hidden, duplicate or case-colliding source closure root",
            )?;
            require(
                paths.len() <= MAX_SOURCE_FILES.saturating_sub(files.len()),
                "source closure exceeds aggregate file count",
            )?;
            let selected =
                Self::from_snapshot_controlled(Arc::clone(&image), root, paths, control)?;
            for mut file in selected.manifest.files().iter().cloned() {
                file.path = format!("{root}/{}", file.path);
                // The saved bundle is recaptured as a single workspace before
                // transfer. Refuse a prefix that would hide its selected bytes.
                require(
                    member_disposition(&file.path, false) == MemberDisposition::Include,
                    "source closure path is excluded by capture policy",
                )?;
                files.push(file);
            }
        }
        Ok(Self {
            image,
            layout: SourceLayout::Closure,
            manifest: SourceManifest::new(files)?,
            toolchain: None,
        })
    }

    /// Bundle one captured package with exact dependency artifacts retained by
    /// the live action's filesystem observer. The caller must verify these bytes
    /// against its keyed candidate inventory before selecting them and keep the
    /// original-input witnesses through execution and installation.
    ///
    /// Package members are rooted at package/; dependency paths are exactly
    /// dependencies/NNNN/basename. Both share the existing bounded, authenticated
    /// source-files transfer, including its per-file reuse and seal verification.
    /// This constructor never opens a mutable dependency path on the caller.
    pub fn with_dependency_artifacts(self, artifacts: Vec<(String, Vec<u8>)>) -> io::Result<Self> {
        self.with_retained_dependency_artifacts(
            artifacts
                .into_iter()
                .map(|(path, bytes)| {
                    (
                        path,
                        Arc::new(RetainedDependencyArtifact::from_bytes(bytes)),
                    )
                })
                .collect(),
        )
    }

    /// Attach immutable artifact owners selected by the live input observer.
    /// Their exact bytes and transport digests were sealed together; cloning
    /// this upload neither copies nor rehashes them. The receiving worker still
    /// verifies every actual byte against this manifest before execution.
    pub(crate) fn with_retained_dependency_artifacts(
        mut self,
        artifacts: Vec<(String, Arc<RetainedDependencyArtifact>)>,
    ) -> io::Result<Self> {
        require(
            self.toolchain.is_none(),
            "dependency bundle must be selected before toolchain attachment",
        )?;
        let (root, generated, native, mut files) = match &self.layout {
            SourceLayout::Root(root) => (
                root.clone(),
                None,
                Vec::new(),
                self.manifest
                    .files()
                    .iter()
                    .cloned()
                    .map(|mut file| {
                        file.path = format!("package/{}", file.path);
                        file
                    })
                    .collect::<Vec<_>>(),
            ),
            SourceLayout::Dependency {
                root,
                generated,
                native,
                artifacts_selected: false,
                ..
            } => (
                root.clone(),
                generated.clone(),
                native.clone(),
                self.manifest.files().to_vec(),
            ),
            _ => {
                return Err(invalid(
                    "dependency artifacts require one unselected package bundle",
                ));
            }
        };
        require(
            artifacts.len() <= MAX_SOURCE_FILES.saturating_sub(self.manifest.files().len()),
            "dependency bundle exceeds aggregate file count",
        )?;
        let mut retained = std::collections::BTreeMap::new();
        for (path, artifact) in artifacts {
            let components: Vec<_> = path.split('/').collect();
            require(
                components.len() == 3
                    && components[0] == "dependencies"
                    && components[1].len() == 4
                    && components[1].bytes().all(|byte| byte.is_ascii_digit())
                    && components[1].parse::<usize>().is_ok_and(|index| {
                        index < rabs_sandbox::dependency_context::MAX_DEPENDENCY_DIRS
                    })
                    && components[2].starts_with("lib")
                    && (components[2].ends_with(".rmeta") || components[2].ends_with(".rlib")),
                "dependency bundle contains an unsupported artifact path",
            )?;
            let file = SourceFile {
                path: path.clone(),
                len: artifact.bytes().len() as u64,
                sha256: artifact.sha256(),
                executable: false,
            };
            require(
                retained.insert(path, artifact).is_none(),
                "dependency bundle repeats an artifact path",
            )?;
            files.push(file);
        }
        self.manifest = SourceManifest::new(files)?;
        self.layout = SourceLayout::Dependency {
            root,
            generated,
            native,
            artifacts: Arc::new(retained),
            artifacts_selected: true,
        };
        Ok(self)
    }

    /// Include the complete captured Cargo OUT_DIR tree without reopening it.
    /// The generated root and package must share the exact coherent snapshot
    /// owner. Selection may precede or follow dependency artifacts, but may not
    /// be repeated or occur after toolchain attachment. Empty generated roots
    /// remain explicit selections in the dependency context, without fake files.
    pub fn with_generated_snapshot(
        mut self,
        image: Arc<SealedSourceSnapshot>,
        root: &str,
        paths: &[String],
    ) -> io::Result<Self> {
        require(
            self.toolchain.is_none(),
            "generated source must be selected before toolchain attachment",
        )?;
        let generated = GeneratedSource::from_snapshot(image, root, paths)?;
        require(
            generated.shares_snapshot(&self.image),
            "package and generated source must share one coherent snapshot",
        )?;
        let (package, native, artifacts, artifacts_selected, mut files) = match &self.layout {
            SourceLayout::Root(package) => (
                package.clone(),
                Vec::new(),
                Arc::new(std::collections::BTreeMap::new()),
                false,
                self.manifest
                    .files()
                    .iter()
                    .cloned()
                    .map(|mut file| {
                        file.path = format!("package/{}", file.path);
                        file
                    })
                    .collect::<Vec<_>>(),
            ),
            SourceLayout::Dependency {
                root: package,
                generated: None,
                native,
                artifacts,
                artifacts_selected,
            } => (
                package.clone(),
                native.clone(),
                Arc::clone(artifacts),
                *artifacts_selected,
                self.manifest.files().to_vec(),
            ),
            _ => {
                return Err(invalid(
                    "generated source requires one unselected package bundle",
                ));
            }
        };
        require(
            generated.files().len() <= MAX_SOURCE_FILES.saturating_sub(files.len()),
            "generated bundle exceeds aggregate file count",
        )?;
        files.extend_from_slice(generated.files());
        self.manifest = SourceManifest::new(files)?;
        self.layout = SourceLayout::Dependency {
            root: package,
            generated: Some(generated),
            native,
            artifacts,
            artifacts_selected,
        };
        Ok(self)
    }

    /// Retain a propagated native tree from the SAME coherent source capture.
    /// The index is allocated here, rather than accepted from a caller. Empty
    /// trees retain directory/mount intent without invented source files.
    pub fn with_native_snapshot(
        mut self,
        image: Arc<SealedSourceSnapshot>,
        root: &str,
        paths: &[String],
    ) -> io::Result<Self> {
        require(
            self.toolchain.is_none(),
            "native inputs must precede toolchain attachment",
        )?;
        let (package, generated, mut native, artifacts, artifacts_selected, mut files) =
            match &self.layout {
                SourceLayout::Root(package) => (
                    package.clone(),
                    None,
                    Vec::new(),
                    Arc::new(BTreeMap::new()),
                    false,
                    self.manifest
                        .files()
                        .iter()
                        .cloned()
                        .map(|mut file| {
                            file.path = format!("package/{}", file.path);
                            file
                        })
                        .collect::<Vec<_>>(),
                ),
                SourceLayout::Dependency {
                    root: package,
                    generated,
                    native,
                    artifacts,
                    artifacts_selected,
                } => (
                    package.clone(),
                    generated.clone(),
                    native.clone(),
                    Arc::clone(artifacts),
                    *artifacts_selected,
                    self.manifest.files().to_vec(),
                ),
                SourceLayout::Closure => {
                    return Err(invalid("native inputs require a dependency source bundle"));
                }
            };
        require(
            native.len() < rabs_sandbox::dependency_context::MAX_NATIVE_ROOTS,
            "too many propagated native source trees",
        )?;
        let source = GeneratedSource::from_snapshot_with_prefix(
            image,
            root,
            paths,
            &format!("native/{:04}", native.len()),
        )?;
        require(
            source.shares_snapshot(&self.image),
            "native inputs and package must share one coherent snapshot",
        )?;
        require(
            source.files().len() <= MAX_SOURCE_FILES.saturating_sub(files.len()),
            "native source exceeds aggregate file count",
        )?;
        files.extend_from_slice(source.files());
        native.push(source);
        self.manifest = SourceManifest::new(files)?;
        self.layout = SourceLayout::Dependency {
            root: package,
            generated,
            native,
            artifacts,
            artifacts_selected,
        };
        Ok(self)
    }

    fn file_bytes(&self, path: &str) -> io::Result<&[u8]> {
        let (root, relative) = match &self.layout {
            SourceLayout::Root(root) => (root.as_str(), path),
            SourceLayout::Closure => path
                .split_once('/')
                .ok_or_else(|| invalid("source closure member lacks its root"))?,
            SourceLayout::Dependency {
                root,
                generated,
                native,
                artifacts,
                ..
            } => {
                if let Some(relative) = path.strip_prefix("package/") {
                    (root.as_str(), relative)
                } else if path.starts_with("generated/") {
                    return generated
                        .as_ref()
                        .and_then(|source| source.file_bytes(path))
                        .ok_or_else(|| invalid("retained generated source missing"));
                } else if path.starts_with("native/") {
                    return native
                        .iter()
                        .find_map(|source| source.file_bytes(path))
                        .ok_or_else(|| invalid("retained native source missing"));
                } else {
                    return artifacts
                        .get(path)
                        .map(|artifact| artifact.bytes())
                        .ok_or_else(|| invalid("retained dependency artifact missing"));
                }
            }
        };
        self.image
            .file_bytes(root, relative)
            .ok_or_else(|| invalid("retained source missing"))
    }

    /// Bind a newly captured image to the ORIGINAL saved execution request.
    /// A checkout edit after request preparation refuses; it never silently
    /// changes the manifest under the same request ID.
    pub fn for_request(
        image: Arc<SealedSourceSnapshot>,
        root: &str,
        request: &Value,
    ) -> io::Result<Self> {
        let manifest =
            request_manifest(request)?.ok_or_else(|| invalid("request has no source manifest"))?;
        let paths: Vec<_> = manifest
            .files()
            .iter()
            .map(|file| file.path.clone())
            .collect();
        let upload = Self::from_snapshot(image, root, &paths)?;
        upload.validate_source_request(request)?;
        Ok(upload)
    }

    /// Attach a separately approved, retained compiler tree. Source selection
    /// alone never grants access to a neighbouring toolchain or a host pathname.
    pub fn with_toolchain(
        mut self,
        prepared: PreparedToolchain,
        request: &Value,
    ) -> io::Result<Self> {
        require(
            self.toolchain.is_none(),
            "toolchain upload already attached",
        )?;
        self.validate_source_request(request)?;
        self.toolchain = Some(toolchain::ToolchainUpload::new(prepared, request)?);
        self.validate_request(request)?;
        Ok(self)
    }

    /// Reuse one retained compiler image across dependency actions. The owner
    /// keeps its private backing alive through every upload. Range reads remain
    /// anchored to the captured inventory and the worker verifies the seal.
    pub fn with_shared_toolchain(
        mut self,
        prepared: Arc<PreparedToolchain>,
        request: &Value,
    ) -> io::Result<Self> {
        require(
            self.toolchain.is_none(),
            "toolchain upload already attached",
        )?;
        self.validate_source_request(request)?;
        self.toolchain = Some(toolchain::ToolchainUpload::from_shared(prepared, request)?);
        self.validate_request(request)?;
        Ok(self)
    }

    /// Keep the service's bounded generation lease through the entire upload.
    /// The image cannot escape its counted owner or outlive its private backing.
    pub(crate) fn with_retained_toolchain(
        mut self,
        retained: Arc<RetainedToolchain>,
        request: &Value,
    ) -> io::Result<Self> {
        require(
            self.toolchain.is_none(),
            "toolchain upload already attached",
        )?;
        self.validate_source_request(request)?;
        self.toolchain = Some(toolchain::ToolchainUpload::from_retained(
            retained, request,
        )?);
        self.validate_request(request)?;
        Ok(self)
    }

    #[must_use]
    pub fn wire_manifest(&self) -> Value {
        manifest_value(&self.manifest)
    }

    fn begin_frame(&self, request: &Value) -> Value {
        let mut frame = json!({"kind":"source-begin", "request_id":request["request_id"],
            "manifest":self.wire_manifest(), "allow_cached_files":true});
        if let Some(home) = request.get("cargo_home") {
            frame["cargo_home"] = home.clone();
        }
        frame
    }

    /// A missing-file hint narrows transfer, never the declared input closure.
    /// An older worker without the extension receives the entire projection.
    /// Unknown paths cannot turn this into a request to upload sibling files.
    fn missing_files(&self, reply: &Value) -> io::Result<Option<BTreeSet<String>>> {
        let Some(value) = reply.get("missing_files") else {
            return Ok(None);
        };
        let rows = value
            .as_array()
            .filter(|rows| rows.len() <= self.manifest.files().len())
            .ok_or_else(|| invalid("source missing-file list outside its bound"))?;
        let mut missing = BTreeSet::new();
        let mut previous: Option<&str> = None;
        for row in rows {
            let path = row
                .as_str()
                .ok_or_else(|| invalid("source missing path is not a string"))?;
            require(
                self.manifest
                    .files()
                    .binary_search_by(|file| file.path.as_str().cmp(path))
                    .is_ok(),
                "worker requested a source path outside the approved projection",
            )?;
            require(
                previous.is_none_or(|last| last < path),
                "source missing-file list must be sorted and unique",
            )?;
            previous = Some(path);
            missing.insert(path.to_owned());
        }
        Ok(Some(missing))
    }

    pub fn validate_request(&self, request: &Value) -> io::Result<()> {
        self.validate_source_request(request)?;
        require(
            super::worker_delivery::toolchain_transfer(request)? == self.toolchain.is_some(),
            "toolchain transfer requires explicitly retained toolchain bytes",
        )?;
        if let Some(toolchain) = &self.toolchain {
            toolchain.validate_request(request)?;
        }
        Ok(())
    }

    fn validate_source_request(&self, request: &Value) -> io::Result<()> {
        require(
            request["kind"] == "canonical-exec" && request["request_id"].as_u64().is_some(),
            "source upload requires an original execution request",
        )?;
        require(
            request_manifest(request)?.as_ref() == Some(&self.manifest),
            "captured source differs from the saved execution manifest",
        )?;
        if let SourceLayout::Dependency {
            root,
            generated,
            native,
            ..
        } = &self.layout
        {
            if request["dependency_context"]["version"]
                == rabs_sandbox::dependency_context::CANONICAL_WORKSPACE_CONTEXT_VERSION
            {
                let captured = self
                    .image
                    .manifest(root)
                    .ok_or_else(|| invalid("workspace source root was not captured"))?;
                let mut directories = Vec::new();
                let mut files = BTreeSet::new();
                for (path, kind) in &captured.members {
                    match kind {
                        MemberKind::Directory => directories.push(path.clone()),
                        MemberKind::Regular { .. } => {
                            files.insert(format!("package/{path}"));
                        }
                        MemberKind::Symlink { .. } => {
                            return Err(invalid("workspace execution source contains a symlink"));
                        }
                    }
                }
                rabs_sandbox::generated_source::validate_generated_directories(&directories)?;
                let selected = self
                    .manifest
                    .files()
                    .iter()
                    .filter(|file| file.path.starts_with("package/"))
                    .map(|file| file.path.clone())
                    .collect::<BTreeSet<_>>();
                require(
                    request["dependency_context"]["source_root"] == rabs_sandbox::layout::WORKSPACE
                        && request["dependency_context"]["source_directories"]
                            == json!(directories)
                        && selected == files,
                    "workspace execution requires the exact complete sealed source tree",
                )?;
            }
            require(
                generated.is_some() == request["dependency_context"]["generated_root"].is_string(),
                "generated source selection differs from the execution context",
            )?;
            if let Some(generated) = generated {
                require(
                    request["dependency_context"]["generated_directories"]
                        == json!(generated.directories()),
                    "generated directory topology differs from the captured execution inputs",
                )?;
            } else {
                require(
                    request["dependency_context"]
                        .get("generated_directories")
                        .is_none_or(|value| value.as_array().is_some_and(Vec::is_empty)),
                    "generated directories require a captured generated root",
                )?;
            }
            match request["dependency_context"].get("native_roots") {
                None if native.is_empty() => {}
                Some(value) => {
                    let roots = value
                        .as_array()
                        .ok_or_else(|| invalid("native roots must be an array"))?;
                    require(
                        roots.len() == native.len(),
                        "native source selection differs from execution context",
                    )?;
                    for (root, source) in roots.iter().zip(native) {
                        require(
                            root["prefix"] == source.prefix()
                                && root["directories"] == json!(source.directories()),
                            "native directory topology or prefix differs from captured inputs",
                        )?;
                    }
                }
                _ => return Err(invalid("native source context is missing")),
            }
        }
        let begin = self.begin_frame(request);
        require(
            serde_json::to_vec(&begin)?.len() <= MAX_JSON_RECORD,
            "source manifest exceeds the transport record bound",
        )
    }

    /// Extend the ordinary grant without changing its output/retention policy.
    /// This is checked BEFORE transmission of either source bytes or execution.
    pub(crate) fn grant(&self, hello: &Value, grant: &Value) -> io::Result<Value> {
        require(
            hello["source_transfers"]
                .as_array()
                .is_some_and(|values| values.iter().any(|value| value == SOURCE_TRANSFER)),
            "worker does not support source-files-v1",
        )?;
        require(
            grant["kind"] == "session-ok"
                && grant
                    .get("source_transfer")
                    .is_none_or(|value| value == SOURCE_TRANSFER),
            "conflicting source transfer selection",
        )?;
        let mut grant = grant.clone();
        grant["source_transfer"] = json!(SOURCE_TRANSFER);
        if let Some(toolchain) = &self.toolchain {
            toolchain.select(hello, &mut grant)?;
        } else {
            require(
                grant.get("toolchain_transfer").is_none() && grant.get("toolchain_reuse").is_none(),
                "toolchain transfer was not authorized by this upload",
            )?;
        }
        Ok(grant)
    }

    /// Send one source projection over an ALREADY admitted session. A failed
    /// exchange is terminal for this operation; there is no execution retry.
    /// Transport implementations enforce one absolute upload-phase deadline.
    /// Toolchain reuse is selected by the actual authenticated session grant,
    /// never inferred from a ready response or the saved execution request.
    pub(crate) fn transmit<P: WorkerPeer + ?Sized>(
        &self,
        peer: &mut P,
        request: &Value,
        toolchain_reuse_selected: bool,
    ) -> io::Result<()> {
        self.validate_request(request)?;
        require(
            !toolchain_reuse_selected || self.toolchain.is_some(),
            "toolchain reuse requires an authorized toolchain upload",
        )?;
        let id = request["request_id"]
            .as_u64()
            .ok_or_else(|| invalid("source request identity"))?;
        let identity = hex(&self.manifest.digest());
        let check = |reply: &Value, kind: &str| -> io::Result<()> {
            require(
                reply["kind"] == kind
                    && reply["request_id"].as_u64() == Some(id)
                    && reply["manifest_sha256"].as_str() == Some(identity.as_str()),
                "source response kind or identity mismatch",
            )
        };
        peer.send(&self.begin_frame(request))?;
        let reply = peer.receive()?;
        check(&reply, "source-ready")?;
        require(
            reply["sealed"] == false,
            "new source operation unexpectedly already sealed",
        )?;
        // Request semantics must not disappear on an older worker that accepts
        // unknown fields. The exact echo is required BEFORE sending any source
        // bytes; neither missing-file cache hints nor TLS identity waive it.
        require(
            reply.get("cargo_home") == request.get("cargo_home"),
            "worker did not accept the exact Cargo home replay selection",
        )?;
        let missing = self.missing_files(&reply)?;
        // Four bounded chunks fit below the worker's eight-frame / 2 MiB
        // deferred-source limit, including maximum encoded paths and hashes.
        // Keep the window full across files: one validated acknowledgment
        // releases one slot, not the whole batch. Retain only exact ACK debts,
        // never another copy of the already sealed source payload. A failure
        // returns from this operation immediately, without retrying its tail.
        let mut outstanding = std::collections::VecDeque::with_capacity(SOURCE_WINDOW);
        let acknowledge_one =
            |peer: &mut P, outstanding: &mut std::collections::VecDeque<(&str, u64)>| {
                let &(path, next) = outstanding
                    .front()
                    .ok_or_else(|| invalid("source upload has no pending acknowledgment"))?;
                let reply = peer.receive()?;
                check(&reply, "source-chunk-accepted")?;
                require(
                    reply["path"].as_str() == Some(path)
                        && reply["next_offset"].as_u64() == Some(next),
                    "source acknowledgment does not cover the transmitted range",
                )?;
                // An invalid or lost ACK must not return credit or permit
                // another source chunk. Keep the debt through validation.
                let _ = outstanding.pop_front();
                Ok::<(), io::Error>(())
            };
        for file in self.manifest.files() {
            if missing
                .as_ref()
                .is_some_and(|paths| !paths.contains(&file.path))
            {
                continue;
            }
            let bytes = self.file_bytes(&file.path)?;
            for (index, chunk) in bytes.chunks(MAX_SOURCE_CHUNK).enumerate() {
                let offset = (index as u64) * MAX_SOURCE_CHUNK as u64;
                let next = offset + chunk.len() as u64;
                peer.send(
                    &json!({"kind":"source-chunk", "request_id":id, "manifest_sha256":identity,
                    "path":file.path, "offset":offset, "data_hex":hex(chunk),
                    "chunk_sha256":hex(&Sha256::digest(chunk))}),
                )?;
                outstanding.push_back((file.path.as_str(), next));
                if outstanding.len() == SOURCE_WINDOW {
                    acknowledge_one(peer, &mut outstanding)?;
                }
            }
        }
        // No seal, ownership transfer or execution can precede acknowledgment
        // of EVERY transmitted chunk, including the remaining window. Any
        // failed write, malformed reply or deadline aborts without retrying.
        while !outstanding.is_empty() {
            acknowledge_one(peer, &mut outstanding)?;
        }
        // Even a completely warm projection needs this exact final seal. A
        // missing-file hint by itself grants neither execution nor publication.
        peer.send(&json!({"kind":"source-seal", "request_id":id, "manifest_sha256":identity}))?;
        let reply = peer.receive()?;
        check(&reply, "source-ready")?;
        require(
            reply.get("cargo_home") == request.get("cargo_home"),
            "worker sealed a different Cargo home replay selection",
        )?;
        require(
            reply["sealed"] == true,
            "worker did not seal the complete source projection",
        )?;
        if let Some(toolchain) = &self.toolchain {
            toolchain.transmit(peer, request, toolchain_reuse_selected)?;
        }
        Ok(())
    }
}

/// Source staging inside an ordinary peer's negotiation frontier. The secure
/// adapter performs this internally AFTER its TLS-key-bound challenge instead;
/// wrapping an already-restricted authenticated adapter would bypass no checks.
/// This wrapper neither retries nor changes the original execution request.
pub struct SourcePeer<'a, P: ?Sized> {
    inner: &'a mut P,
    upload: &'a SourceUpload,
    request: &'a Value,
    attempted: bool,
}

impl<'a, P: WorkerPeer + ?Sized> SourcePeer<'a, P> {
    pub fn new(inner: &'a mut P, upload: &'a SourceUpload, request: &'a Value) -> io::Result<Self> {
        upload.validate_request(request)?;
        require(
            upload.toolchain.is_none(),
            "toolchain transfer requires authenticated delivery",
        )?;
        Ok(Self {
            inner,
            upload,
            request,
            attempted: false,
        })
    }
}

impl<P: WorkerPeer + ?Sized> WorkerPeer for SourcePeer<'_, P> {
    fn checkpoint(&mut self) -> io::Result<()> {
        self.inner.checkpoint()
    }
    fn artifact_byte_cache(&self) -> Option<&super::worker_delivery::ArtifactByteCache> {
        self.inner.artifact_byte_cache()
    }
    fn transfer_deadline(&self) -> Option<std::time::Instant> {
        self.inner.transfer_deadline()
    }
    fn live_continuation(&self) -> Option<&super::worker_delivery::SealedResult> {
        self.inner.live_continuation()
    }
    fn send(&mut self, frame: &Value) -> io::Result<()> {
        self.inner.send(frame)
    }
    fn receive(&mut self) -> io::Result<Value> {
        self.inner.receive()
    }
    fn authentication(&self) -> Option<WorkerAuthentication> {
        self.inner.authentication()
    }
    fn negotiate(&mut self, hello: &Value, grant: &Value) -> io::Result<()> {
        require(!self.attempted, "source negotiation cannot be retried")?;
        self.attempted = true;
        let grant = self.upload.grant(hello, grant)?;
        self.inner.negotiate(hello, &grant)?;
        self.upload.transmit(self.inner, self.request, false)
    }
}

#[cfg(all(test, unix))]
mod tests {
    mod cargo_home_tests;

    use super::*;
    use std::collections::{BTreeMap, VecDeque};

    #[cfg(target_os = "linux")]
    #[test]
    #[ignore = "requires RABS_REFLINK_TEST_ROOT on a real reflink-capable filesystem"]
    fn toolchain_capture_requires_real_reflink_and_retains_independent_bytes() {
        use std::cell::Cell;
        use std::os::unix::fs::{MetadataExt, PermissionsExt};

        let root = std::env::var_os("RABS_REFLINK_TEST_ROOT")
            .expect("set RABS_REFLINK_TEST_ROOT to a reflink-capable filesystem");
        let owner = tempfile::Builder::new()
            .prefix("rabs-toolchain-reflink-")
            .permissions(fs::Permissions::from_mode(0o700))
            .tempdir_in(root)
            .unwrap();
        let source = owner.path().join("source");
        fs::create_dir(&source).unwrap();
        let compiler = source.join("compiler");
        let bytes = b"toolchain reflink isolation\0\xff".repeat(4096);
        fs::write(&compiler, &bytes).unwrap();
        fs::set_permissions(&compiler, fs::Permissions::from_mode(0o755)).unwrap();
        let cloned = Cell::new(0);
        let prepared = capture_toolchain_with_cloner(
            &source,
            &owner.path().join("retained"),
            None,
            &ToolchainLimits::default(),
            || false,
            |input, output, parent| {
                let success =
                    rabs_cas::materialization::try_verified_reflink(input, output, parent);
                if success {
                    cloned.set(cloned.get() + 1);
                }
                success
            },
        )
        .unwrap();
        assert_eq!(
            cloned.get(),
            1,
            "copy fallback cannot satisfy the reflink gate"
        );
        let retained = prepared.root().join("compiler");
        assert_ne!(
            fs::metadata(&compiler).unwrap().ino(),
            fs::metadata(&retained).unwrap().ino()
        );
        assert_eq!(fs::metadata(&compiler).unwrap().mode() & 0o777, 0o755);
        assert_eq!(fs::metadata(&retained).unwrap().mode() & 0o777, 0o555);
        fs::write(&compiler, b"source changed after capture").unwrap();
        assert_eq!(fs::read(&retained).unwrap(), bytes);
        prepared.verify(|| false).unwrap();
        assert!(prepared.verify_source_unchanged(&source, || false).is_err());
    }

    #[test]
    fn unresolved_cargo_plans_are_refused_before_execution_or_resume() {
        let request = json!({"cargo_source":{"manifest":"Cargo.toml"}});
        let error = request_manifest(&request).unwrap_err();
        assert!(error.to_string().contains("--worker-prepare"));
    }

    fn fixture(root: &std::path::Path) -> (SourceUpload, Value, Vec<u8>) {
        std::fs::create_dir(root.join("src")).unwrap();
        let bytes: Vec<_> = (0..MAX_SOURCE_CHUNK + 17)
            .map(|n| (n % 256) as u8)
            .collect();
        std::fs::write(root.join("src/lib.rs"), &bytes).unwrap();
        std::fs::write(root.join("empty"), b"").unwrap();
        std::fs::write(root.join("not-selected.private"), b"must not be sent").unwrap();
        let image = Arc::new(
            capture_sealed_source(
                &[("workspace".into(), root.to_path_buf())],
                false,
                2,
                200_000,
            )
            .unwrap(),
        );
        let upload =
            SourceUpload::from_snapshot(image, "workspace", &["src/lib.rs".into(), "empty".into()])
                .unwrap();
        let request = json!({"kind":"canonical-exec", "request_id":7, "program":"fixture",
            "toolchain_backing":"/tc", "source_manifest":upload.wire_manifest()});
        (upload, request, bytes)
    }

    #[test]
    fn dependency_bundle_transfers_retained_package_and_exact_metadata_closure() {
        let root = tempfile::tempdir().unwrap();
        let (package, mut request, source_bytes) = fixture(root.path());
        let metadata: Vec<_> = (0..MAX_SOURCE_CHUNK + 29)
            .map(|index| (index % 251) as u8)
            .collect();
        let archive = b"!<arch>\nexact archive input".to_vec();
        let upload = package
            .clone()
            .with_dependency_artifacts(vec![
                ("dependencies/0000/libdirect.rmeta".into(), metadata.clone()),
                (
                    "dependencies/0002/libtransitive.rlib".into(),
                    archive.clone(),
                ),
            ])
            .unwrap();
        request["source_manifest"] = upload.wire_manifest();
        upload.validate_request(&request).unwrap();
        // Later writes cannot change already selected source or artifact bytes.
        std::fs::write(root.path().join("src/lib.rs"), b"changed after capture").unwrap();
        let mut peer = ReceiverPeer::new();
        peer.prefilled
            .insert("package/src/lib.rs".into(), source_bytes.clone());
        peer.prefilled.insert(
            "dependencies/0002/libtransitive.rlib".into(),
            archive.clone(),
        );
        peer.missing = Some(json!(["dependencies/0000/libdirect.rmeta"]));
        upload.transmit(&mut peer, &request, false).unwrap();
        let received = peer.receiver.as_ref().unwrap().sealed_root().unwrap();
        assert_eq!(
            std::fs::read(received.join("package/src/lib.rs")).unwrap(),
            source_bytes
        );
        assert_eq!(std::fs::read(received.join("package/empty")).unwrap(), b"");
        assert_eq!(
            std::fs::read(received.join("dependencies/0000/libdirect.rmeta")).unwrap(),
            metadata
        );
        assert_eq!(
            std::fs::read(received.join("dependencies/0002/libtransitive.rlib")).unwrap(),
            archive
        );
        assert!(!received.join("package/not-selected.private").exists());
        let chunks: Vec<_> = peer
            .sent
            .iter()
            .filter(|frame| frame["kind"] == "source-chunk")
            .collect();
        assert_eq!(chunks.len(), 2);
        assert!(
            chunks
                .iter()
                .all(|frame| { frame["path"] == "dependencies/0000/libdirect.rmeta" })
        );
        assert_eq!(peer.sent.last().unwrap()["kind"], "source-seal");
        assert!(
            peer.sent
                .iter()
                .all(|frame| frame["kind"] != "canonical-exec")
        );
        let changed = package
            .with_dependency_artifacts(vec![
                (
                    "dependencies/0000/libdirect.rmeta".into(),
                    b"other metadata".to_vec(),
                ),
                ("dependencies/0002/libtransitive.rlib".into(), archive),
            ])
            .unwrap();
        assert_ne!(upload.manifest.digest(), changed.manifest.digest());
        assert!(changed.validate_request(&request).is_err());
    }

    #[test]
    fn shared_dependency_byte_owners_transfer_into_independent_real_receivers() {
        let root = tempfile::tempdir().unwrap();
        let (package, mut request, source_bytes) = fixture(root.path());
        let original = root.path().join("liboriginal.rmeta");
        let bytes: Vec<_> = (0..MAX_SOURCE_CHUNK * 2 + 29)
            .map(|index| (index % 251) as u8)
            .collect();
        fs::write(&original, &bytes).unwrap();
        let artifact = Arc::new(RetainedDependencyArtifact::from_bytes(
            fs::read(&original).unwrap(),
        ));
        let path = "dependencies/0000/liboriginal.rmeta";
        let raw = package
            .clone()
            .with_dependency_artifacts(vec![(path.into(), bytes.clone())])
            .unwrap();
        let upload = package
            .with_retained_dependency_artifacts(vec![(path.into(), Arc::clone(&artifact))])
            .unwrap();
        assert_eq!(upload.wire_manifest(), raw.wire_manifest());
        let SourceLayout::Dependency { artifacts, .. } = &upload.layout else {
            panic!("typed artifacts lost their dependency layout");
        };
        assert!(Arc::ptr_eq(artifacts.get(path).unwrap(), &artifact));
        request["source_manifest"] = upload.wire_manifest();
        fs::write(&original, b"caller changed after byte retention").unwrap();
        fs::write(root.path().join("src/lib.rs"), b"caller changed package").unwrap();
        drop(artifact);

        let cloned = upload.clone();
        let mut first = ReceiverPeer::new();
        let mut second = ReceiverPeer::new();
        upload.transmit(&mut first, &request, false).unwrap();
        cloned.transmit(&mut second, &request, false).unwrap();
        let first_root = first.receiver.as_ref().unwrap().sealed_root().unwrap();
        let second_root = second.receiver.as_ref().unwrap().sealed_root().unwrap();
        for received in [first_root, second_root] {
            assert_eq!(fs::read(received.join(path)).unwrap(), bytes);
            assert_eq!(
                fs::read(received.join("package/src/lib.rs")).unwrap(),
                source_bytes
            );
        }
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        assert_ne!(
            fs::metadata(first_root.join(path)).unwrap().ino(),
            fs::metadata(second_root.join(path)).unwrap().ino(),
        );
        fs::set_permissions(first_root.join(path), fs::Permissions::from_mode(0o600)).unwrap();
        fs::write(
            first_root.join(path),
            b"one subscriber changed its private copy",
        )
        .unwrap();
        assert_eq!(fs::read(second_root.join(path)).unwrap(), bytes);
        assert_eq!(cloned.file_bytes(path).unwrap(), bytes);
    }

    #[test]
    fn dependency_bundle_refuses_unmodeled_members_and_duplicate_names() {
        let root = tempfile::tempdir().unwrap();
        let (package, _, _) = fixture(root.path());
        for path in [
            "package/libdep.rmeta",
            "dependencies/0000/libproc.so",
            "dependencies/0000/libnative.a",
            "dependencies/0000/nested/libdep.rmeta",
            "dependencies/../libdep.rmeta",
            "dependencies/0/libdep.rmeta",
            "dependencies/0064/libdep.rmeta",
        ] {
            assert!(
                package
                    .clone()
                    .with_dependency_artifacts(vec![(path.into(), b"data".to_vec())])
                    .is_err(),
                "{path}"
            );
        }
        assert!(
            package
                .clone()
                .with_dependency_artifacts(vec![
                    ("dependencies/0000/libdep.rmeta".into(), b"first".to_vec()),
                    ("dependencies/0000/libdep.rmeta".into(), b"second".to_vec()),
                ])
                .is_err()
        );
        let leaf = package.with_dependency_artifacts(Vec::new()).unwrap();
        assert!(
            leaf.manifest
                .files()
                .iter()
                .all(|file| file.path.starts_with("package/"))
        );
        assert!(leaf.with_dependency_artifacts(Vec::new()).is_err());
    }

    fn generated_fixture(root: &Path, populated: bool) -> Arc<SealedSourceSnapshot> {
        use std::os::unix::fs::PermissionsExt;
        fs::create_dir_all(root.join("package/src")).unwrap();
        fs::create_dir_all(root.join("out")).unwrap();
        fs::write(
            root.join("package/src/lib.rs"),
            b"include!(concat!(env!(\"OUT_DIR\"), \"/nested/generated.rs\"));\n",
        )
        .unwrap();
        if populated {
            fs::create_dir(root.join("out/nested")).unwrap();
            fs::create_dir_all(root.join("out/empty/inner")).unwrap();
            fs::write(
                root.join("out/nested/generated.rs"),
                b"pub const GENERATED: u64 = 42;\n",
            )
            .unwrap();
            let bytes: Vec<_> = (0..MAX_SOURCE_CHUNK + 13)
                .map(|index| (index % 251) as u8)
                .collect();
            fs::write(root.join("out/data.bin"), bytes).unwrap();
            fs::set_permissions(root.join("out/data.bin"), fs::Permissions::from_mode(0o755))
                .unwrap();
        }
        Arc::new(
            capture_sealed_source(
                &[
                    ("package".into(), root.join("package")),
                    ("generated".into(), root.join("out")),
                ],
                false,
                2,
                300_000,
            )
            .unwrap(),
        )
    }

    #[test]
    fn workspace_execution_upload_requires_every_file_and_empty_directory_from_one_capture() {
        use rabs_sandbox::dependency_context::CANONICAL_WORKSPACE_CONTEXT_VERSION;
        let root = tempfile::tempdir().unwrap();
        fs::create_dir_all(root.path().join("src")).unwrap();
        fs::create_dir_all(root.path().join("empty/inner")).unwrap();
        fs::write(
            root.path().join("src/lib.rs"),
            b"pub const README: &str = include_str!(\"../README\");\n",
        )
        .unwrap();
        fs::write(root.path().join("README"), b"sibling input\n").unwrap();
        let image = Arc::new(
            capture_sealed_source(
                &[("workspace".into(), root.path().to_path_buf())],
                false,
                1,
                4096,
            )
            .unwrap(),
        );
        let upload = SourceUpload::from_snapshot(
            Arc::clone(&image),
            "workspace",
            &["README".into(), "src/lib.rs".into()],
        )
        .unwrap()
        .with_dependency_artifacts(Vec::new())
        .unwrap();
        let request = json!({"kind":"canonical-exec","request_id":41,
            "program":"/__rabs/toolchain/bin/rustc",
            "source_manifest":upload.wire_manifest(),
            "dependency_context":{"version":CANONICAL_WORKSPACE_CONTEXT_VERSION,
                "source_root":"/__rabs/workspace", "source_directories":["empty","empty/inner","src"],
                "generated_root":null,"generated_directories":[]}});
        upload.validate_request(&request).unwrap();
        for directories in [
            json!(["src"]),
            json!(["empty", "empty/inner", "extra", "src"]),
            Value::Null,
        ] {
            let mut changed = request.clone();
            changed["dependency_context"]["source_directories"] = directories;
            assert!(upload.validate_request(&changed).is_err());
        }
        let subset = SourceUpload::from_snapshot(image, "workspace", &["src/lib.rs".into()])
            .unwrap()
            .with_dependency_artifacts(Vec::new())
            .unwrap();
        let mut missing_sibling = request.clone();
        missing_sibling["source_manifest"] = subset.wire_manifest();
        assert!(subset.validate_request(&missing_sibling).is_err());
        // Upload authority remains the sealed capture even if the mutable
        // original changes after selection; execution rechecks its owner too.
        fs::write(root.path().join("README"), b"changed after capture\n").unwrap();
        upload.validate_request(&request).unwrap();
    }

    #[test]
    fn propagated_native_bundle_retains_exact_bytes_and_empty_directories() {
        let root = tempfile::tempdir().unwrap();
        let image = generated_fixture(root.path(), true);
        let paths = ["nested/generated.rs".into(), "data.bin".into()];
        let package =
            SourceUpload::from_snapshot(Arc::clone(&image), "package", &["src/lib.rs".into()])
                .unwrap();
        let upload = package
            .clone()
            .with_native_snapshot(Arc::clone(&image), "generated", &paths)
            .unwrap()
            .with_dependency_artifacts(Vec::new())
            .unwrap();
        let request = json!({"kind":"canonical-exec", "request_id":19,
            "program":"fixture", "toolchain_backing":"/tc",
            "dependency_context":{"generated_root":null,"generated_directories":[],
                "native_roots":[{"path":"/__rabs/out/cargo/debug/build/provider/out", "prefix":"native/0000", "directories":["empty","empty/inner","nested"]}]},
            "source_manifest":upload.wire_manifest()});
        upload.validate_request(&request).unwrap();
        assert_eq!(
            upload.file_bytes("native/0000/data.bin").unwrap(),
            image.file_bytes("generated", "data.bin").unwrap()
        );
        assert!(upload.file_bytes("native/0001/data.bin").is_err());
        assert!(
            package
                .clone()
                .with_native_snapshot(Arc::clone(&image), "generated", &paths[..1])
                .is_err()
        );
        let other = tempfile::tempdir().unwrap();
        let other_image = generated_fixture(other.path(), true);
        assert!(
            package
                .with_native_snapshot(other_image, "generated", &paths)
                .is_err()
        );
        for native in [
            Value::Null,
            json!([]),
            json!([{"prefix":"native/0001", "directories":["empty","empty/inner","nested"]}]),
            json!([{"prefix":"native/0000", "directories":["nested"]}]),
        ] {
            let mut changed = request.clone();
            changed["dependency_context"]["native_roots"] = native;
            assert!(upload.validate_request(&changed).is_err());
        }
        let mut peer = ReceiverPeer::new();
        upload.transmit(&mut peer, &request, false).unwrap();
        let received = peer.receiver.as_ref().unwrap().sealed_root().unwrap();
        assert_eq!(
            fs::read(received.join("native/0000/data.bin")).unwrap(),
            image.file_bytes("generated", "data.bin").unwrap()
        );
        assert!(!received.join("generated").exists());
        assert!(
            !received.join("native/0000/empty").exists(),
            "worker reconstructs directory intent separately from authenticated file bytes"
        );
    }

    #[test]
    fn generated_dependency_bundle_transfers_one_retained_snapshot_and_resumes_exactly() {
        use std::os::unix::fs::PermissionsExt;
        let root = tempfile::tempdir().unwrap();
        let image = generated_fixture(root.path(), true);
        let package =
            SourceUpload::from_snapshot(Arc::clone(&image), "package", &["src/lib.rs".into()])
                .unwrap();
        let paths = ["nested/generated.rs".into(), "data.bin".into()];
        let artifacts = vec![(
            "dependencies/0000/libdep.rmeta".into(),
            b"retained dependency metadata".to_vec(),
        )];
        let upload = package
            .clone()
            .with_generated_snapshot(Arc::clone(&image), "generated", &paths)
            .unwrap()
            .with_dependency_artifacts(artifacts.clone())
            .unwrap();
        let reverse_order = package
            .with_dependency_artifacts(artifacts)
            .unwrap()
            .with_generated_snapshot(Arc::clone(&image), "generated", &paths)
            .unwrap();
        assert_eq!(upload.wire_manifest(), reverse_order.wire_manifest());
        let request = json!({"kind":"canonical-exec", "request_id":7,
            "program":"fixture", "toolchain_backing":"/tc",
            "dependency_context":{"generated_root":"/cargo/build/pkg/out",
                "generated_directories":["empty", "empty/inner", "nested"]},
            "source_manifest":upload.wire_manifest()});
        upload.validate_request(&request).unwrap();
        let mut missing_context = request.clone();
        missing_context["dependency_context"]["generated_root"] = Value::Null;
        assert!(upload.validate_request(&missing_context).is_err());
        for directories in [
            json!([]),
            json!(["nested"]),
            json!(["empty", "empty/inner", "nested", "unobserved"]),
            json!(["nested", "empty", "empty/inner"]),
            Value::Null,
        ] {
            let mut different_tree = request.clone();
            different_tree["dependency_context"]["generated_directories"] = directories;
            assert!(upload.validate_request(&different_tree).is_err());
        }

        fs::write(root.path().join("package/src/lib.rs"), b"changed package").unwrap();
        fs::write(root.path().join("out/data.bin"), b"changed generated bytes").unwrap();
        fs::write(root.path().join("out/new.rs"), b"not in captured tree").unwrap();
        let mut peer = ReceiverPeer::new();
        for file in upload.manifest.files() {
            if file.path != "generated/data.bin" {
                peer.prefilled.insert(
                    file.path.clone(),
                    upload.file_bytes(&file.path).unwrap().to_vec(),
                );
            }
        }
        peer.missing = Some(json!(["generated/data.bin"]));
        upload.transmit(&mut peer, &request, false).unwrap();
        let received = peer.receiver.as_ref().unwrap().sealed_root().unwrap();
        for file in upload.manifest.files() {
            assert_eq!(
                fs::read(received.join(&file.path)).unwrap(),
                upload.file_bytes(&file.path).unwrap()
            );
            assert_eq!(
                fs::metadata(received.join(&file.path))
                    .unwrap()
                    .permissions()
                    .mode()
                    & 0o111
                    != 0,
                file.executable
            );
        }
        assert!(!received.join("generated/new.rs").exists());
        let chunks: Vec<_> = peer
            .sent
            .iter()
            .filter(|frame| frame["kind"] == "source-chunk")
            .collect();
        assert_eq!(chunks.len(), 2);
        assert!(
            chunks
                .iter()
                .all(|frame| frame["path"] == "generated/data.bin")
        );
        assert_eq!(peer.sent.last().unwrap()["kind"], "source-seal");
        let recaptured = Arc::new(
            capture_sealed_source(
                &[("saved".into(), received.to_path_buf())],
                false,
                2,
                300_000,
            )
            .unwrap(),
        );
        let resumed = SourceUpload::for_request(recaptured, "saved", &request).unwrap();
        assert_eq!(resumed.wire_manifest(), upload.wire_manifest());
        for file in upload.manifest.files() {
            assert_eq!(
                resumed.file_bytes(&file.path).unwrap(),
                upload.file_bytes(&file.path).unwrap()
            );
        }
    }

    #[test]
    fn generated_bundle_refuses_incoherent_or_repeated_source_selection() {
        let root = tempfile::tempdir().unwrap();
        let image = generated_fixture(root.path(), true);
        let package =
            SourceUpload::from_snapshot(Arc::clone(&image), "package", &["src/lib.rs".into()])
                .unwrap();
        let paths = ["data.bin".into(), "nested/generated.rs".into()];
        let separate = Arc::new(
            capture_sealed_source(
                &[("generated".into(), root.path().join("out"))],
                false,
                2,
                300_000,
            )
            .unwrap(),
        );
        assert!(
            package
                .clone()
                .with_generated_snapshot(separate, "generated", &paths)
                .is_err()
        );
        assert!(
            package
                .clone()
                .with_generated_snapshot(Arc::clone(&image), "missing", &paths)
                .is_err()
        );
        assert!(
            package
                .clone()
                .with_generated_snapshot(Arc::clone(&image), "generated", &paths[..1])
                .is_err()
        );
        let selected = package
            .with_generated_snapshot(Arc::clone(&image), "generated", &paths)
            .unwrap();
        assert!(
            selected
                .clone()
                .with_generated_snapshot(image, "generated", &paths)
                .is_err()
        );
        let selected = selected.with_dependency_artifacts(Vec::new()).unwrap();
        assert!(selected.with_dependency_artifacts(Vec::new()).is_err());
    }

    #[test]
    fn empty_generated_bundle_keeps_mount_intent_without_inventing_manifest_files() {
        let root = tempfile::tempdir().unwrap();
        let image = generated_fixture(root.path(), false);
        let package =
            SourceUpload::from_snapshot(Arc::clone(&image), "package", &["src/lib.rs".into()])
                .unwrap();
        let plain = package
            .clone()
            .with_dependency_artifacts(Vec::new())
            .unwrap();
        let generated = package
            .with_generated_snapshot(image, "generated", &[])
            .unwrap()
            .with_dependency_artifacts(Vec::new())
            .unwrap();
        assert_eq!(plain.wire_manifest(), generated.wire_manifest());
        assert_eq!(generated.manifest.files().len(), 1);
        let mut request = json!({"kind":"canonical-exec", "request_id":7,
            "program":"fixture", "toolchain_backing":"/tc",
            "source_manifest":generated.wire_manifest()});
        plain.validate_request(&request).unwrap();
        assert!(generated.validate_request(&request).is_err());
        request["dependency_context"] = json!({"generated_root":"/cargo/build/pkg/out",
            "generated_directories":[]});
        generated.validate_request(&request).unwrap();
        assert!(plain.validate_request(&request).is_err());
        let mut peer = ReceiverPeer::new();
        generated.transmit(&mut peer, &request, false).unwrap();
        let received = peer.receiver.as_ref().unwrap().sealed_root().unwrap();
        assert!(received.join("package/src/lib.rs").is_file());
        assert!(!received.join("generated").exists());
    }

    struct ReceiverPeer {
        owner: tempfile::TempDir,
        receiver: Option<SourceReceiver>,
        replies: VecDeque<Value>,
        sent: Vec<Value>,
        corrupt_ack: bool,
        prefilled: BTreeMap<String, Vec<u8>>,
        missing: Option<Value>,
        lose_seal_ack: bool,
    }
    impl ReceiverPeer {
        fn new() -> Self {
            Self {
                owner: crate::test_util::private_tempdir(),
                receiver: None,
                replies: VecDeque::new(),
                sent: Vec::new(),
                corrupt_ack: false,
                prefilled: BTreeMap::new(),
                missing: None,
                lose_seal_ack: false,
            }
        }
    }
    impl WorkerPeer for ReceiverPeer {
        fn send(&mut self, frame: &Value) -> io::Result<()> {
            self.sent.push(frame.clone());
            let id = frame["request_id"].clone();
            let response = match frame["kind"].as_str() {
                Some("session-ok") => return Ok(()),
                Some("source-begin") => {
                    let manifest =
                        request_manifest(&json!({"source_manifest":frame["manifest"]}))?.unwrap();
                    let identity = hex(&manifest.digest());
                    let mut receiver =
                        SourceReceiver::create(&self.owner.path().join("workspace"), manifest)?;
                    for (path, bytes) in &self.prefilled {
                        for (index, chunk) in bytes.chunks(MAX_SOURCE_CHUNK).enumerate() {
                            receiver.write_chunk(
                                path,
                                index as u64 * MAX_SOURCE_CHUNK as u64,
                                chunk,
                                Sha256::digest(chunk).into(),
                            )?;
                        }
                    }
                    self.receiver = Some(receiver);
                    let mut reply = json!({"kind":"source-ready", "request_id":id, "manifest_sha256":identity, "sealed":false});
                    if let Some(missing) = &self.missing {
                        reply["missing_files"] = missing.clone();
                    }
                    reply
                }
                Some("source-chunk") => {
                    let raw = frame["data_hex"].as_str().unwrap();
                    let bytes = (0..raw.len())
                        .step_by(2)
                        .map(|index| u8::from_str_radix(&raw[index..index + 2], 16).unwrap())
                        .collect::<Vec<_>>();
                    let offset = self.receiver.as_mut().unwrap().write_chunk(
                        frame["path"].as_str().unwrap(),
                        frame["offset"].as_u64().unwrap(),
                        &bytes,
                        digest(&frame["chunk_sha256"])?,
                    )?;
                    json!({"kind":"source-chunk-accepted", "request_id":id, "manifest_sha256":frame["manifest_sha256"],
                        "path":frame["path"], "next_offset":if self.corrupt_ack { offset + 1 } else { offset }})
                }
                Some("source-seal") => {
                    self.receiver.as_mut().unwrap().seal()?;
                    if self.lose_seal_ack {
                        return Ok(());
                    }
                    json!({"kind":"source-ready", "request_id":id, "manifest_sha256":frame["manifest_sha256"], "sealed":true})
                }
                _ => return Err(invalid("source sender must not dispatch execution")),
            };
            self.replies.push_back(response);
            Ok(())
        }
        fn receive(&mut self) -> io::Result<Value> {
            self.replies
                .pop_front()
                .ok_or_else(|| invalid("no response"))
        }
    }

    #[test]
    fn transmits_only_selected_captured_bytes_even_after_checkout_changes() {
        let root = tempfile::tempdir().unwrap();
        let (upload, request, bytes) = fixture(root.path());
        std::fs::write(root.path().join("src/lib.rs"), b"changed checkout").unwrap();
        let mut peer = ReceiverPeer::new();
        let hello = json!({"source_transfers":[SOURCE_TRANSFER]});
        SourcePeer::new(&mut peer, &upload, &request)
            .unwrap()
            .negotiate(&hello, &json!({"kind":"session-ok"}))
            .unwrap();
        let source = peer.receiver.as_ref().unwrap().sealed_root().unwrap();
        assert_eq!(std::fs::read(source.join("src/lib.rs")).unwrap(), bytes);
        assert_eq!(std::fs::read(source.join("empty")).unwrap(), b"");
        assert!(!source.join("not-selected.private").exists());
        assert_eq!(
            peer.sent
                .iter()
                .filter(|frame| frame["kind"] == "source-chunk")
                .count(),
            2
        );
        assert_eq!(peer.sent[0]["source_transfer"], SOURCE_TRANSFER);
        assert!(
            peer.sent
                .iter()
                .all(|frame| frame["kind"] != "canonical-exec")
        );
        let image = Arc::new(
            capture_sealed_source(
                &[("workspace".into(), root.path().to_path_buf())],
                false,
                2,
                200_000,
            )
            .unwrap(),
        );
        assert!(
            SourceUpload::for_request(image, "workspace", &request).is_err(),
            "recapture must not silently change a saved request"
        );
    }

    #[test]
    fn negotiation_and_ack_failures_stop_before_seal_or_execution() {
        let root = tempfile::tempdir().unwrap();
        let (upload, request, _) = fixture(root.path());
        let mut peer = ReceiverPeer::new();
        assert!(
            SourcePeer::new(&mut peer, &upload, &request)
                .unwrap()
                .negotiate(&json!({}), &json!({"kind":"session-ok"}))
                .is_err()
        );
        assert!(peer.sent.is_empty());
        peer.corrupt_ack = true;
        assert!(
            SourcePeer::new(&mut peer, &upload, &request)
                .unwrap()
                .negotiate(
                    &json!({"source_transfers":[SOURCE_TRANSFER]}),
                    &json!({"kind":"session-ok"})
                )
                .is_err()
        );
        assert!(peer.receiver.as_ref().unwrap().sealed_root().is_none());
        assert!(
            peer.sent
                .iter()
                .all(|frame| frame["kind"] != "source-seal" && frame["kind"] != "canonical-exec")
        );
    }

    #[test]
    fn source_request_validation_rejects_aliases_and_changed_identity() {
        let root = tempfile::tempdir().unwrap();
        let (upload, request, _) = fixture(root.path());
        let mut mixed = request.clone();
        mixed["workspace_backing"] = json!("/worker/path");
        assert!(request_manifest(&mixed).is_err());
        let mut changed = request.clone();
        changed["source_manifest"]["files"][0]["path"] = json!("../escape");
        assert!(request_manifest(&changed).is_err());
        let mut changed = request.clone();
        changed["source_manifest"]["manifest_sha256"] = json!("00".repeat(32));
        assert!(request_manifest(&changed).is_err());
        let mut changed = request;
        changed.as_object_mut().unwrap().remove("source_manifest");
        assert!(upload.validate_request(&changed).is_err());
    }

    #[test]
    fn warm_source_sends_no_chunks_but_preserves_manifest_and_final_seal() {
        let root = tempfile::tempdir().unwrap();
        let (upload, request, bytes) = fixture(root.path());
        let original = serde_json::to_vec(&request).unwrap();
        let mut peer = ReceiverPeer::new();
        peer.prefilled.insert("src/lib.rs".into(), bytes.clone());
        peer.missing = Some(json!([]));
        upload.transmit(&mut peer, &request, false).unwrap();
        assert_eq!(peer.sent.len(), 2);
        assert_eq!(peer.sent[0], upload.begin_frame(&request));
        assert_eq!(peer.sent[0]["allow_cached_files"], true);
        assert_eq!(peer.sent[0]["manifest"], request["source_manifest"]);
        assert_eq!(peer.sent[1]["kind"], "source-seal");
        assert_eq!(
            peer.sent[1]["manifest_sha256"],
            request["source_manifest"]["manifest_sha256"]
        );
        assert_eq!(serde_json::to_vec(&request).unwrap(), original);
        let source = peer.receiver.as_ref().unwrap().sealed_root().unwrap();
        assert_eq!(std::fs::read(source.join("src/lib.rs")).unwrap(), bytes);
        assert_eq!(std::fs::read(source.join("empty")).unwrap(), b"");
        assert!(!source.join("not-selected.private").exists());
    }

    #[test]
    fn source_authority_cannot_select_or_start_unretained_toolchain_reuse() {
        use rabs_sandbox::toolchain_transfer::TOOLCHAIN_REUSE_VERSION;

        let root = tempfile::tempdir().unwrap();
        let (upload, request, _) = fixture(root.path());
        let hello = json!({"source_transfers":[SOURCE_TRANSFER],
            "toolchain_transfers":[TOOLCHAIN_TRANSFER_VERSION],
            "toolchain_reuses":[TOOLCHAIN_REUSE_VERSION]});
        let mut grant = json!({"kind":"session-ok"});
        let selected = upload.grant(&hello, &grant).unwrap();
        assert!(selected.get("toolchain_transfer").is_none());
        assert!(selected.get("toolchain_reuse").is_none());
        grant["toolchain_reuse"] = json!(TOOLCHAIN_REUSE_VERSION);
        assert!(upload.grant(&hello, &grant).is_err());
        let mut peer = ReceiverPeer::new();
        assert!(upload.transmit(&mut peer, &request, true).is_err());
        assert!(peer.sent.is_empty());
    }

    #[test]
    fn mixed_source_transfers_only_missing_captured_files() {
        let root = tempfile::tempdir().unwrap();
        let (_, _, bytes) = fixture(root.path());
        std::fs::write(root.path().join("changed.rs"), b"new source").unwrap();
        let image = Arc::new(
            capture_sealed_source(
                &[("workspace".into(), root.path().to_path_buf())],
                false,
                2,
                200_000,
            )
            .unwrap(),
        );
        let upload = SourceUpload::from_snapshot(
            image,
            "workspace",
            &["src/lib.rs".into(), "changed.rs".into(), "empty".into()],
        )
        .unwrap();
        let request = json!({"kind":"canonical-exec", "request_id":8, "program":"fixture",
            "toolchain_backing":"/tc", "source_manifest":upload.wire_manifest()});
        std::fs::write(root.path().join("changed.rs"), b"changed after capture").unwrap();
        let mut peer = ReceiverPeer::new();
        peer.prefilled.insert("src/lib.rs".into(), bytes.clone());
        peer.missing = Some(json!(["changed.rs"]));
        upload.transmit(&mut peer, &request, false).unwrap();
        let chunks: Vec<_> = peer
            .sent
            .iter()
            .filter(|frame| frame["kind"] == "source-chunk")
            .collect();
        assert_eq!(chunks.len(), 1);
        assert_eq!(chunks[0]["path"], "changed.rs");
        assert_eq!(chunks[0]["data_hex"], hex(b"new source"));
        let source = peer.receiver.as_ref().unwrap().sealed_root().unwrap();
        assert_eq!(std::fs::read(source.join("src/lib.rs")).unwrap(), bytes);
        assert_eq!(
            std::fs::read(source.join("changed.rs")).unwrap(),
            b"new source"
        );
    }

    #[test]
    fn malformed_missing_hints_never_upload_extra_files_or_reach_seal() {
        let root = tempfile::tempdir().unwrap();
        let (upload, request, _) = fixture(root.path());
        for missing in [
            Value::Null,
            json!(true),
            json!([1]),
            json!(["not-selected.private"]),
            json!(["../escape"]),
            json!(["src/lib.rs", "empty"]),
            json!(["empty", "empty"]),
            json!(["empty", "src/lib.rs", "extra"]),
        ] {
            let mut peer = ReceiverPeer::new();
            peer.missing = Some(missing);
            assert!(upload.transmit(&mut peer, &request, false).is_err());
            assert_eq!(peer.sent.len(), 1);
            assert_eq!(peer.sent[0]["kind"], "source-begin");
            assert!(peer.receiver.as_ref().unwrap().sealed_root().is_none());
        }
    }

    #[test]
    fn all_cached_claim_without_bytes_or_without_seal_ack_cannot_finish_negotiation() {
        let root = tempfile::tempdir().unwrap();
        let (upload, request, bytes) = fixture(root.path());
        for lose_ack in [false, true] {
            let mut peer = ReceiverPeer::new();
            peer.missing = Some(json!([]));
            if lose_ack {
                peer.prefilled.insert("src/lib.rs".into(), bytes.clone());
                peer.lose_seal_ack = true;
            }
            let mut source = SourcePeer::new(&mut peer, &upload, &request).unwrap();
            let hello = json!({"source_transfers":[SOURCE_TRANSFER]});
            assert!(
                source
                    .negotiate(&hello, &json!({"kind":"session-ok"}))
                    .is_err()
            );
            assert!(
                source
                    .negotiate(&hello, &json!({"kind":"session-ok"}))
                    .is_err()
            );
            assert_eq!(peer.sent.len(), 3); // grant, begin, seal; never execution or retry.
            assert!(
                peer.sent
                    .iter()
                    .all(|frame| frame["kind"] != "canonical-exec")
            );
        }
    }

    fn preparation_specification() -> Value {
        json!({"kind":"canonical-exec", "request_id":27, "program":"rustc",
            "toolchain_backing":"/opt/rust-toolchain", "args":["src/lib.rs", "--crate-type", "lib"],
            "source_files":["src/lib.rs", "empty"], "timeout_ms":120000,
            "extension":{"keep":"exactly"}})
    }

    #[test]
    fn daemon_template_retains_allocation_intent_and_exact_inputs_without_becoming_a_wire_request()
    {
        let checkout = tempfile::tempdir().unwrap();
        let (_, _, bytes) = fixture(checkout.path());
        let owner = tempfile::tempdir().unwrap();
        let mut spec = preparation_specification();
        spec["request_id"] = json!("allocate");
        let directory = owner.path().join("template");
        assert!(prepare_source_bundle(checkout.path(), &spec, &directory).is_err());
        assert!(!directory.exists());
        let prepared = prepare_source_template(checkout.path(), &spec, &directory).unwrap();
        assert_eq!(prepared["kind"], "prepared-source-template");
        assert_eq!(prepared["request_id"], "allocate");
        let request_bytes = fs::read(directory.join("request.json")).unwrap();
        let request: Value = serde_json::from_slice(&request_bytes).unwrap();
        assert_eq!(request["request_id"], "allocate");
        assert_eq!(request["args"], spec["args"]);
        assert_eq!(request["extension"], spec["extension"]);
        assert_eq!(
            fs::read(directory.join("source/src/lib.rs")).unwrap(),
            bytes
        );
        assert_eq!(
            prepared["request_sha256"],
            hex(&Sha256::digest(&request_bytes))
        );
        assert!(validate_request(&request).is_err());
        let mut assigned = request;
        assigned["request_id"] = json!(8001);
        validate_request(&assigned).unwrap();
        let next = owner.path().join("numeric-is-not-an-intent");
        spec["request_id"] = json!(8001);
        assert!(prepare_source_template(checkout.path(), &spec, &next).is_err());
        assert!(!next.exists());
    }

    #[test]
    fn prepared_bundle_retains_exact_bytes_and_is_consumed_by_the_real_source_sender() {
        use std::os::unix::fs::PermissionsExt;
        let checkout = tempfile::tempdir().unwrap();
        let (_, _, bytes) = fixture(checkout.path());
        let spec = preparation_specification();
        let original_spec = spec.clone();
        let owner = tempfile::tempdir().unwrap();
        let directory = owner.path().join("bundle");
        let prepared = prepare_source_bundle(checkout.path(), &spec, &directory).unwrap();
        let source = PathBuf::from(prepared["source_root"].as_str().unwrap());
        let request_bytes = fs::read(prepared["request_path"].as_str().unwrap()).unwrap();
        let request: Value = serde_json::from_slice(&request_bytes).unwrap();
        validate_request(&request).unwrap();
        let manifest = request_manifest(&request).unwrap().unwrap();
        assert_eq!(manifest.files().len(), 2);
        assert_eq!(manifest.total_bytes(), bytes.len() as u64);
        assert_eq!(
            prepared["request_sha256"],
            hex(&Sha256::digest(&request_bytes))
        );
        assert_eq!(prepared["manifest_sha256"], hex(&manifest.digest()));
        assert_eq!(prepared["source_bytes"], bytes.len());
        assert_eq!(prepared["source_files"], 2);
        assert_eq!(prepared["executed"], false);
        assert_eq!(prepared["publication_authorized"], false);
        assert_eq!(spec, original_spec);
        let mut without_manifest = request.clone();
        without_manifest
            .as_object_mut()
            .unwrap()
            .remove("source_manifest");
        let mut without_selection = spec;
        without_selection
            .as_object_mut()
            .unwrap()
            .remove("source_files");
        assert_eq!(
            without_manifest, without_selection,
            "command and extensions are immutable"
        );
        assert_eq!(
            fs::metadata(&directory).unwrap().permissions().mode() & 0o777,
            0o700
        );
        assert_eq!(
            fs::metadata(directory.join("request.json"))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
        assert_eq!(
            fs::metadata(source.join("src/lib.rs"))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o444
        );
        assert!(!source.join("not-selected.private").exists());
        assert!(!prepared.to_string().contains("must not be sent"));

        // The source checkout can disappear. The existing execution upload
        // consumes only the saved request and recaptured retained projection.
        fs::rename(checkout.path().join("src"), checkout.path().join("old-src")).unwrap();
        let image =
            capture_sealed_source(&[("workspace".into(), source)], false, 2, 200_000).unwrap();
        let upload = SourceUpload::for_request(Arc::new(image), "workspace", &request).unwrap();
        let mut peer = ReceiverPeer::new();
        upload.transmit(&mut peer, &request, false).unwrap();
        let received = peer.receiver.as_ref().unwrap().sealed_root().unwrap();
        assert_eq!(fs::read(received.join("src/lib.rs")).unwrap(), bytes);
        assert_eq!(fs::read(received.join("empty")).unwrap(), b"");
        assert!(
            peer.sent
                .iter()
                .all(|frame| frame["kind"] != "canonical-exec")
        );
    }

    #[test]
    fn preparation_preserves_executable_modes_and_rejects_tampered_retained_source() {
        use std::os::unix::fs::PermissionsExt;
        let checkout = tempfile::tempdir().unwrap();
        fs::write(checkout.path().join("run"), b"#!/bin/sh\nexit 0\n").unwrap();
        fs::set_permissions(
            checkout.path().join("run"),
            fs::Permissions::from_mode(0o700),
        )
        .unwrap();
        let owner = tempfile::tempdir().unwrap();
        let directory = owner.path().join("bundle");
        let mut spec = preparation_specification();
        spec["source_files"] = json!(["run"]);
        prepare_source_bundle(checkout.path(), &spec, &directory).unwrap();
        let source = directory.join("source");
        let request: Value =
            serde_json::from_slice(&fs::read(directory.join("request.json")).unwrap()).unwrap();
        assert_eq!(request["source_manifest"]["files"][0]["executable"], true);
        assert_eq!(
            fs::metadata(source.join("run"))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o555
        );
        fs::set_permissions(source.join("run"), fs::Permissions::from_mode(0o700)).unwrap();
        fs::write(source.join("run"), b"#!/bin/sh\nexit 1\n").unwrap();
        let image =
            capture_sealed_source(&[("workspace".into(), source)], false, 2, 200_000).unwrap();
        assert!(SourceUpload::for_request(Arc::new(image), "workspace", &request).is_err());
    }

    #[test]
    fn ambiguous_or_invalid_preparation_never_creates_a_bundle() {
        let checkout = tempfile::tempdir().unwrap();
        fixture(checkout.path());
        let owner = tempfile::tempdir().unwrap();
        let directory = owner.path().join("bundle");
        let good = preparation_specification();
        let mut bad = vec![Value::Null, json!([])];
        for (field, value) in [
            ("kind", json!("result-resume")),
            ("request_id", json!(-1)),
            ("source_manifest", Value::Null),
            ("workspace_backing", json!("/host")),
            ("source_files", Value::Null),
            ("source_files", json!([])),
            ("source_files", json!([false])),
            ("source_files", json!(["empty", "empty"])),
            ("source_files", json!(["missing"])),
            ("source_files", json!(["../escape"])),
            ("source_files", json!(["src"])),
            ("timeout_ms", json!(0)),
            ("args", json!([1])),
            ("program", json!("")),
            ("artifacts", json!({"unit":"bad", "files":["../escape"]})),
        ] {
            let mut spec = good.clone();
            spec[field] = value;
            bad.push(spec);
        }
        for spec in bad {
            assert!(
                prepare_source_bundle(checkout.path(), &spec, &directory).is_err(),
                "{spec}"
            );
            assert!(
                !directory.exists(),
                "invalid input must not publish partial output"
            );
        }
        let mut oversized = good;
        oversized["extension"] = json!("x".repeat(MAX_FRAME_BYTES));
        assert!(prepare_source_bundle(checkout.path(), &oversized, &directory).is_err());
        assert!(!directory.exists());
    }

    #[test]
    fn preparation_does_not_follow_selected_symlinks_or_replace_existing_bundles() {
        use std::os::unix::fs::symlink;
        let checkout = tempfile::tempdir().unwrap();
        fixture(checkout.path());
        symlink("empty", checkout.path().join("alias")).unwrap();
        let owner = tempfile::tempdir().unwrap();
        let directory = owner.path().join("bundle");
        let mut spec = preparation_specification();
        spec["source_files"] = json!(["alias"]);
        assert!(prepare_source_bundle(checkout.path(), &spec, &directory).is_err());
        assert!(!directory.exists());
        spec["source_files"] = json!(["empty"]);
        prepare_source_bundle(checkout.path(), &spec, &directory).unwrap();
        let request_before = fs::read(directory.join("request.json")).unwrap();
        spec["request_id"] = json!(99);
        assert_eq!(
            prepare_source_bundle(checkout.path(), &spec, &directory)
                .unwrap_err()
                .kind(),
            io::ErrorKind::AlreadyExists
        );
        assert_eq!(
            fs::read(directory.join("request.json")).unwrap(),
            request_before
        );
        let alias = owner.path().join("alias");
        symlink(&directory, &alias).unwrap();
        assert!(prepare_source_bundle(checkout.path(), &spec, &alias).is_err());
        assert_eq!(
            fs::read(directory.join("request.json")).unwrap(),
            request_before
        );
    }

    #[test]
    fn unresolved_preparation_fields_cannot_be_dispatched_even_with_a_valid_manifest() {
        let checkout = tempfile::tempdir().unwrap();
        let (_, mut request, _) = fixture(checkout.path());
        request["source_files"] = json!(["empty"]);
        assert!(validate_request(&request).is_err());
        request.as_object_mut().unwrap().remove("source_manifest");
        request["workspace_backing"] = json!("/somewhere");
        assert!(validate_request(&request).is_err());
    }

    #[test]
    fn preparation_requires_an_absolute_new_destination_and_absolute_source() {
        let checkout = tempfile::tempdir().unwrap();
        fixture(checkout.path());
        let owner = tempfile::tempdir().unwrap();
        let spec = preparation_specification();
        assert!(
            prepare_source_bundle(Path::new("relative"), &spec, &owner.path().join("bundle"))
                .is_err()
        );
        for destination in [
            PathBuf::from("relative"),
            PathBuf::from("/"),
            owner.path().join("../bundle"),
        ] {
            assert!(prepare_source_bundle(checkout.path(), &spec, &destination).is_err());
        }
        assert!(fs::read_dir(owner.path()).unwrap().next().is_none());
    }

    fn closure_fixture(base: &Path) -> (Arc<SealedSourceSnapshot>, Vec<(String, Vec<String>)>) {
        for root in ["app", "dep"] {
            fs::create_dir_all(base.join(root).join("src")).unwrap();
            fs::write(base.join(root).join("src/lib.rs"), root.as_bytes()).unwrap();
            fs::write(
                base.join(root).join("not-selected.private"),
                b"not approved",
            )
            .unwrap();
        }
        fs::write(
            base.join("app/Cargo.toml"),
            b"[dependencies]\ndep = { path = \"../dep\" }\n",
        )
        .unwrap();
        fs::write(
            base.join("dep/Cargo.toml"),
            b"[package]\nname = \"dep\"\nversion = \"0.1.0\"\n",
        )
        .unwrap();
        let image = capture_sealed_source(
            &[
                ("app".into(), base.join("app")),
                ("dep".into(), base.join("dep")),
            ],
            false,
            2,
            200_000,
        )
        .unwrap();
        let selection = ["app", "dep"]
            .into_iter()
            .map(|root| {
                (
                    root.to_owned(),
                    vec!["Cargo.toml".into(), "src/lib.rs".into()],
                )
            })
            .collect();
        (Arc::new(image), selection)
    }

    #[test]
    fn closure_transfer_preserves_sibling_layout_and_one_retained_generation() {
        let base = tempfile::tempdir().unwrap();
        let (image, selection) = closure_fixture(base.path());
        let upload = SourceUpload::from_snapshot_closure(image, &selection).unwrap();
        let request = json!({"kind":"canonical-exec", "request_id":7,
            "source_manifest":upload.wire_manifest()});
        fs::write(base.path().join("app/src/lib.rs"), b"new app").unwrap();
        fs::write(base.path().join("dep/src/lib.rs"), b"new dep").unwrap();
        let mut peer = ReceiverPeer::new();
        upload.transmit(&mut peer, &request, false).unwrap();
        let root = peer.receiver.as_ref().unwrap().sealed_root().unwrap();
        assert_eq!(fs::read(root.join("app/src/lib.rs")).unwrap(), b"app");
        assert_eq!(fs::read(root.join("dep/src/lib.rs")).unwrap(), b"dep");
        assert_eq!(
            fs::read(root.join("app/Cargo.toml")).unwrap(),
            b"[dependencies]\ndep = { path = \"../dep\" }\n"
        );
        for name in ["app", "dep"] {
            assert!(!root.join(name).join("not-selected.private").exists());
        }
        assert_eq!(upload.manifest.files().len(), 4);
        assert!(!request.to_string().contains(base.path().to_str().unwrap()));
        assert!(
            peer.sent
                .iter()
                .all(|frame| frame["kind"] != "canonical-exec")
        );
    }

    #[test]
    fn closure_cache_hints_reuse_other_roots_without_widening_selection() {
        let base = tempfile::tempdir().unwrap();
        let (image, selection) = closure_fixture(base.path());
        let upload = SourceUpload::from_snapshot_closure(image, &selection).unwrap();
        let request = json!({"kind":"canonical-exec", "request_id":7,
            "source_manifest":upload.wire_manifest()});
        let mut peer = ReceiverPeer::new();
        for file in upload.manifest.files() {
            if file.path != "dep/src/lib.rs" {
                peer.prefilled.insert(
                    file.path.clone(),
                    upload.file_bytes(&file.path).unwrap().to_vec(),
                );
            }
        }
        peer.missing = Some(json!(["dep/src/lib.rs"]));
        upload.transmit(&mut peer, &request, false).unwrap();
        let chunks: Vec<_> = peer
            .sent
            .iter()
            .filter(|frame| frame["kind"] == "source-chunk")
            .collect();
        assert_eq!(chunks.len(), 1);
        assert_eq!(chunks[0]["path"], "dep/src/lib.rs");
        assert_eq!(chunks[0]["data_hex"], hex(b"dep"));
        assert_eq!(peer.sent.last().unwrap()["kind"], "source-seal");
        let mut foreign = ReceiverPeer::new();
        foreign.missing = Some(json!(["dep/not-selected.private"]));
        assert!(upload.transmit(&mut foreign, &request, false).is_err());
        assert_eq!(foreign.sent.len(), 1);
    }

    #[test]
    fn closure_namespace_refuses_unsafe_hidden_duplicate_and_excess_roots() {
        let base = tempfile::tempdir().unwrap();
        let (image, selection) = closure_fixture(base.path());
        assert!(SourceUpload::from_snapshot_closure(Arc::clone(&image), &[]).is_err());
        for name in [
            "", ".", "..", ".git", "target", "a/b", "a\\b", "a:b", "abs\0", "other",
        ] {
            assert!(
                SourceUpload::from_snapshot_closure(
                    Arc::clone(&image),
                    &[(name.into(), vec!["src/lib.rs".into()])]
                )
                .is_err(),
                "{name:?}"
            );
        }
        assert!(
            SourceUpload::from_snapshot_closure(
                Arc::clone(&image),
                &[selection[0].clone(), selection[0].clone()]
            )
            .is_err()
        );
        assert!(
            SourceUpload::from_snapshot_closure(
                image,
                &vec![selection[0].clone(); MAX_SOURCE_ROOTS + 1]
            )
            .is_err()
        );
    }

    #[test]
    fn incomplete_or_nonregular_root_refuses_the_entire_closure_projection() {
        let base = tempfile::tempdir().unwrap();
        let (image, selection) = closure_fixture(base.path());
        for files in [
            vec![],
            vec!["missing".into()],
            vec!["src".into()],
            vec!["src/lib.rs".into(), "src/lib.rs".into()],
        ] {
            let mut selected = selection.clone();
            selected[1].1 = files;
            assert!(SourceUpload::from_snapshot_closure(Arc::clone(&image), &selected).is_err());
        }
        std::os::unix::fs::symlink("src/lib.rs", base.path().join("dep/alias")).unwrap();
        let image = Arc::new(
            capture_sealed_source(
                &[
                    ("app".into(), base.path().join("app")),
                    ("dep".into(), base.path().join("dep")),
                ],
                false,
                2,
                200_000,
            )
            .unwrap(),
        );
        let mut selected = selection;
        selected[1].1 = vec!["alias".into()];
        assert!(SourceUpload::from_snapshot_closure(image, &selected).is_err());
    }

    #[test]
    fn closure_identity_ignores_selection_order_but_binds_dependency_bytes_and_modes() {
        use std::os::unix::fs::PermissionsExt;
        let base = tempfile::tempdir().unwrap();
        let (image, mut selection) = closure_fixture(base.path());
        let original = SourceUpload::from_snapshot_closure(Arc::clone(&image), &selection).unwrap();
        selection.reverse();
        for (_, files) in &mut selection {
            files.reverse();
        }
        assert_eq!(
            SourceUpload::from_snapshot_closure(image, &selection)
                .unwrap()
                .wire_manifest(),
            original.wire_manifest()
        );
        for change_mode in [false, true] {
            if change_mode {
                fs::write(base.path().join("dep/src/lib.rs"), b"dep").unwrap();
                fs::set_permissions(
                    base.path().join("dep/src/lib.rs"),
                    fs::Permissions::from_mode(0o755),
                )
                .unwrap();
            } else {
                fs::write(base.path().join("dep/src/lib.rs"), b"changed dependency").unwrap();
            }
            let image = Arc::new(
                capture_sealed_source(
                    &[
                        ("app".into(), base.path().join("app")),
                        ("dep".into(), base.path().join("dep")),
                    ],
                    false,
                    2,
                    200_000,
                )
                .unwrap(),
            );
            let changed = SourceUpload::from_snapshot_closure(image, &selection).unwrap();
            assert_ne!(changed.manifest.digest(), original.manifest.digest());
            assert!(
                original
                    .validate_request(&json!({"kind":"canonical-exec", "request_id":7,
                "source_manifest":changed.wire_manifest()}))
                    .is_err()
            );
        }
    }
}
