//! Coordinator-side source upload from an approved coherent snapshot.
//!
//! Only explicitly selected regular files leave the captured image. The sender
//! never rereads a mutable checkout, walks worker paths, or dispatches execution.
//! It uses the sandbox's ONE manifest identity implementation and verifies every
//! transfer reply before the delivery engine reaches its execution frontier.
//! Source availability is not action-key validity or cache-publication authority.

mod preparation;

use super::worker_delivery::{MAX_FRAME_BYTES, WorkerAuthentication, WorkerPeer, validate_request};
use rabs_asupersync::worker_transport::MAX_JSON_RECORD;
use rabs_sandbox::cargo_home::{CARGO_HOME_SOURCE_VERSION, CargoHomeProjection};
#[cfg(all(test, unix))]
use rabs_sandbox::snapshot_capture::capture_sealed_source;
use rabs_sandbox::snapshot_capture::{MemberKind, SealedSourceSnapshot};
use rabs_sandbox::source_transfer::{
    MAX_SOURCE_CHUNK, MAX_SOURCE_FILES, SOURCE_TRANSFER, SourceFile, SourceManifest, SourceReceiver,
};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::path::{Component, Path, PathBuf};
use std::sync::Arc;

/// Bound the number of independently captured repositories in one source tree.
pub const MAX_SOURCE_ROOTS: usize = 64;
// Outstanding chunks, not concurrent filesystem writers on the worker.
const SOURCE_WINDOW: usize = 4;

fn invalid(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}
fn require(condition: bool, message: &str) -> io::Result<()> {
    if condition {
        Ok(())
    } else {
        Err(invalid(message))
    }
}
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}
fn digest(value: &Value) -> io::Result<[u8; 32]> {
    let value = value
        .as_str()
        .ok_or_else(|| invalid("source digest is not a string"))?;
    require(
        value.len() == 64
            && value
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
        "source digest must be 64 lowercase hex digits",
    )?;
    let mut digest = [0_u8; 32];
    for (slot, pair) in digest.iter_mut().zip(value.as_bytes().chunks_exact(2)) {
        let digit = |byte: u8| {
            if byte <= b'9' {
                byte - b'0'
            } else {
                byte - b'a' + 10
            }
        };
        *slot = (digit(pair[0]) << 4) | digit(pair[1]);
    }
    Ok(digest)
}

fn manifest_value(manifest: &SourceManifest) -> Value {
    json!({"manifest_sha256":hex(&manifest.digest()),
        "files":manifest.files().iter().map(|file| json!({
            "path":file.path, "bytes":file.len, "sha256":hex(&file.sha256), "executable":file.executable,
        })).collect::<Vec<_>>()})
}

/// Decode only JSON shape; the worker shares the sandbox's registry-only
/// projection policy. The original field remains unchanged in the saved request
/// and its fingerprint. This validates intent, not Cargo resolution provenance.
fn validate_cargo_home(request: &Value, manifest: &SourceManifest) -> io::Result<()> {
    let Some(home) = request.get("cargo_home") else {
        return Ok(());
    };
    require(
        home.as_object().is_some_and(|object| object.len() == 2)
            && home["version"] == CARGO_HOME_SOURCE_VERSION,
        "cargo_home requires a supported version and prefix",
    )?;
    let prefix = home["prefix"]
        .as_str()
        .ok_or_else(|| invalid("cargo_home prefix must be a string"))?;
    CargoHomeProjection::new(prefix, manifest)?;
    Ok(())
}

/// Validate the optional source declaration without requiring source bytes.
/// Resume and verified local delivery recovery use this without a checkout.
pub fn request_manifest(request: &Value) -> io::Result<Option<SourceManifest>> {
    require(
        request.get("source_files").is_none()
            && request.get("source_roots").is_none()
            && request.get("cargo_source").is_none(),
        "source_files/source_roots/cargo_source are preparation specifications, not execution manifests; use --worker-prepare",
    )?;
    let Some(value) = request.get("source_manifest") else {
        require(
            request.get("cargo_home").is_none(),
            "cargo_home requires an uploaded source_manifest",
        )?;
        return Ok(None);
    };
    require(
        request.get("workspace_backing").is_none(),
        "source_manifest and workspace_backing are mutually exclusive",
    )?;
    require(
        value.as_object().is_some_and(|object| object.len() == 2),
        "source manifest requires exactly files and manifest_sha256",
    )?;
    let rows = value["files"]
        .as_array()
        .filter(|rows| rows.len() <= MAX_SOURCE_FILES)
        .ok_or_else(|| invalid("source file list outside its bound"))?;
    let mut files = Vec::with_capacity(rows.len());
    for row in rows {
        require(
            row.as_object().is_some_and(|object| object.len() == 4),
            "invalid source file fields",
        )?;
        files.push(SourceFile {
            path: row["path"]
                .as_str()
                .ok_or_else(|| invalid("invalid source path"))?
                .to_owned(),
            len: row["bytes"]
                .as_u64()
                .ok_or_else(|| invalid("invalid source length"))?,
            sha256: digest(&row["sha256"])?,
            executable: row["executable"]
                .as_bool()
                .ok_or_else(|| invalid("invalid source executable bit"))?,
        });
    }
    let manifest = SourceManifest::new(files)?;
    require(
        manifest.digest() == digest(&value["manifest_sha256"])?,
        "source manifest digest mismatch",
    )?;
    validate_cargo_home(request, &manifest)?;
    Ok(Some(manifest))
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
/// Optional cargo_home selects a registry-only prefix in an explicitly selected
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
    // The local compiler installation may have a different physical path than
    // the worker's installation. Only its verified content identity is sent.
    let expected_toolchain = super::worker_delivery::toolchain_identity(specification)?;
    let toolchain = specification
        .get("toolchain_source")
        .map(|value| {
            let path = value
                .as_str()
                .filter(|path| !path.is_empty() && path.len() <= 4096)
                .ok_or_else(|| invalid("toolchain_source must be an absolute local directory"))?;
            let identity = rabs_sandbox::toolchain_dataset::fingerprint_toolchain(
                Path::new(path),
                &rabs_sandbox::toolchain_dataset::ToolchainLimits::default(),
                || false,
            )?;
            require(
                expected_toolchain
                    .as_ref()
                    .is_none_or(|expected| expected == &identity),
                "local toolchain does not match the specified toolchain_identity",
            )?;
            Ok::<_, io::Error>(identity)
        })
        .transpose()?;
    let upload = inputs.capture()?;
    let mut request = specification.clone();
    let fields = request
        .as_object_mut()
        .ok_or_else(|| invalid("source preparation object"))?;
    fields.remove("source_files");
    fields.remove("source_roots");
    fields.remove("cargo_source");
    fields.remove("toolchain_source");
    if let Some(identity) = &toolchain {
        fields.insert(
            "toolchain_identity".to_owned(),
            super::worker_delivery::toolchain_identity_value(identity),
        );
    }
    fields.insert("source_manifest".to_owned(), upload.wire_manifest());
    // One validator for prepared and hand-authored execution requests. This
    // preserves argv, output declarations, timeouts, and unknown extensions.
    validate_request(&request)?;
    upload.validate_request(&request)?;
    let request_bytes = serde_json::to_vec(&request)?;

    let mut builder = fs::DirBuilder::new();
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }
    builder.create(&destination)?; // Exclusive; never merge into an old bundle.
    let source = destination.join("source");
    let mut receiver = SourceReceiver::create(&source, upload.manifest.clone())?;
    for file in upload.manifest.files() {
        let bytes = upload.file_bytes(&file.path)?;
        for (index, chunk) in bytes.chunks(MAX_SOURCE_CHUNK).enumerate() {
            receiver.write_chunk(
                &file.path,
                index as u64 * MAX_SOURCE_CHUNK as u64,
                chunk,
                Sha256::digest(chunk).into(),
            )?;
        }
    }
    receiver.seal()?;
    // Sync only the validated closure, children before parents. Reverse lexical
    // path order puts every directory after its descendants, including root.
    let mut directories = BTreeSet::from([PathBuf::new()]);
    for file in upload.manifest.files() {
        File::open(source.join(&file.path))?.sync_all()?;
        for directory in Path::new(&file.path).ancestors().skip(1) {
            directories.insert(directory.to_path_buf());
        }
    }
    for directory in directories.iter().rev() {
        File::open(source.join(directory))?.sync_all()?;
    }
    File::open(&destination)?.sync_all()?;
    // Full source durability precedes any parseable request. If this write or
    // sync fails, report failure and retain the new directory for inspection.
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
    Ok(
        json!({"kind":"prepared-source-bundle", "directory":destination,
        "source_root":source, "request_path":request_path, "request_id":request["request_id"],
        "request_sha256":hex(&Sha256::digest(&request_bytes)),
        "manifest_sha256":hex(&upload.manifest.digest()), "source_roots":inputs.root_count(),
        "source_files":upload.manifest.files().len(), "source_bytes":upload.manifest.total_bytes(),
        "toolchain_identity":request.get("toolchain_identity"),
        "executed":false, "publication_authorized":false}),
    )
}

#[derive(Debug, Clone)]
enum SourceLayout {
    /// Preserve the single-root protocol's original relative paths.
    Root(String),
    /// Each first path component names one root in the SAME captured image.
    Closure,
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
}

impl SourceUpload {
    /// Callers apply their upload/confidentiality policy before selecting paths.
    /// This method cannot implicitly include siblings, symlink targets or secrets.
    pub fn from_snapshot(
        image: Arc<SealedSourceSnapshot>,
        root: &str,
        paths: &[String],
    ) -> io::Result<Self> {
        require(
            !paths.is_empty() && paths.len() <= MAX_SOURCE_FILES,
            "source projection file count",
        )?;
        let captured = image
            .manifest(root)
            .ok_or_else(|| invalid("unknown source snapshot root"))?;
        let mut files = Vec::with_capacity(paths.len());
        for path in paths {
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
                bytes.len() as u64 == *size
                    && <[u8; 32]>::from(Sha256::digest(bytes)) == *content_sha256,
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
        use rabs_sandbox::snapshot_capture::{MemberDisposition, member_disposition};
        require(
            !roots.is_empty() && roots.len() <= MAX_SOURCE_ROOTS,
            "source closure root count",
        )?;
        let mut names = BTreeSet::new();
        let mut files = Vec::new();
        for (root, paths) in roots {
            require(
                valid_closure_root(root) && names.insert(root.to_ascii_lowercase()),
                "unsafe, hidden, duplicate or case-colliding source closure root",
            )?;
            require(
                paths.len() <= MAX_SOURCE_FILES.saturating_sub(files.len()),
                "source closure exceeds aggregate file count",
            )?;
            let selected = Self::from_snapshot(Arc::clone(&image), root, paths)?;
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
        })
    }

    fn file_bytes(&self, path: &str) -> io::Result<&[u8]> {
        let (root, relative) = match &self.layout {
            SourceLayout::Root(root) => (root.as_str(), path),
            SourceLayout::Closure => path
                .split_once('/')
                .ok_or_else(|| invalid("source closure member lacks its root"))?,
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
        upload.validate_request(request)?;
        Ok(upload)
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
        require(
            request["kind"] == "canonical-exec" && request["request_id"].as_u64().is_some(),
            "source upload requires an original execution request",
        )?;
        require(
            request_manifest(request)?.as_ref() == Some(&self.manifest),
            "captured source differs from the saved execution manifest",
        )?;
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
        Ok(grant)
    }

    /// Send one source projection over an ALREADY admitted session. A failed
    /// exchange is terminal for this operation; there is no execution retry.
    /// Transport implementations enforce one absolute upload-phase deadline.
    pub(crate) fn transmit<P: WorkerPeer + ?Sized>(
        &self,
        peer: &mut P,
        request: &Value,
    ) -> io::Result<()> {
        self.validate_request(request)?;
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
        // Batch across files too: tiny dependency inputs must not each cost a
        // full round trip. Retain only expected acknowledgment descriptors,
        // never another copy of the already sealed source payload.
        let mut outstanding = Vec::with_capacity(SOURCE_WINDOW);
        let acknowledge_batch = |peer: &mut P, outstanding: &mut Vec<(&str, u64)>| {
            for (path, next) in outstanding.drain(..) {
                let reply = peer.receive()?;
                check(&reply, "source-chunk-accepted")?;
                require(
                    reply["path"].as_str() == Some(path)
                        && reply["next_offset"].as_u64() == Some(next),
                    "source acknowledgment does not cover the transmitted range",
                )?;
            }
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
                outstanding.push((file.path.as_str(), next));
                if outstanding.len() == SOURCE_WINDOW {
                    acknowledge_batch(peer, &mut outstanding)?;
                }
            }
        }
        // No seal, ownership transfer or execution can precede acknowledgment
        // of EVERY transmitted chunk, including the final partial batch. Any
        // failed write, malformed reply or deadline aborts without retrying.
        acknowledge_batch(peer, &mut outstanding)?;
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
        )
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
        Ok(Self {
            inner,
            upload,
            request,
            attempted: false,
        })
    }
}

impl<P: WorkerPeer + ?Sized> WorkerPeer for SourcePeer<'_, P> {
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
        self.upload.transmit(self.inner, self.request)
    }
}

#[cfg(all(test, unix))]
mod tests {
    mod cargo_home_tests;

    use super::*;
    use std::collections::{BTreeMap, VecDeque};

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
                owner: tempfile::tempdir().unwrap(),
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
        upload.transmit(&mut peer, &request).unwrap();
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
        upload.transmit(&mut peer, &request).unwrap();
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
            assert!(upload.transmit(&mut peer, &request).is_err());
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
        upload.transmit(&mut peer, &request).unwrap();
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
        upload.transmit(&mut peer, &request).unwrap();
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
        upload.transmit(&mut peer, &request).unwrap();
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
        assert!(upload.transmit(&mut foreign, &request).is_err());
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
