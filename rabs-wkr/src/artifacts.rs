//! Declared compiler artifacts, captured from one private canonical output mount.
//!
//! The worker chooses the physical backing. Exact-file declarations remain
//! strict. Explicit tree-files-v1 declarations name a minimum required file set
//! and export the complete bounded regular-file closure (directories implicit).
//! Harvesting runs AFTER the process group and drains have resolved, never over
//! a caller-selected host directory. Every file is copied into immutable bounded
//! diagnostic-range storage. This is a transport offer, not a CAS publication.

use crate::output::{CapturedStream, MAX_OUTPUT_CHUNK_BYTES, MAX_RETAINED_STREAM_BYTES};
use rabs_sandbox::artifact_tree::{MAX_TREE_ENTRIES, MAX_TREE_FILES, MAX_TREE_MANIFEST_BYTES, TREE_FILES_VERSION};
use rabs_sandbox::canonical_mounts::UnitMount;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File, Metadata};
use std::io::{self, Read};
use std::path::{Path, PathBuf};

/// Maximum names in an exact declaration or a tree's minimum required set.
pub const MAX_ARTIFACT_FILES: usize = 128;
/// Total retained artifact bytes per execution; not a limit on compiler writes.
pub const MAX_ARTIFACT_BYTES: u64 = MAX_RETAINED_STREAM_BYTES;
/// Version of the named-file range protocol.
pub const ARTIFACT_TRANSFER: &str = "files-v1";

fn invalid(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message.into())
}

/// A validated, nonempty output contract. No physical path is carried here.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArtifactPlan {
    unit: String,
    files: BTreeSet<String>,
    directories: BTreeSet<String>,
    tree: bool,
}

impl ArtifactPlan {
    /// Reject aliases, traversal, duplicate files and file/directory conflicts
    /// before execution. Path spelling is preserved, never silently normalized.
    pub fn new(unit: String, paths: Vec<String>) -> io::Result<Self> {
        Self::bounded(unit, paths, MAX_ARTIFACT_FILES)
    }

    /// Opt in to the complete regular-file output tree, with mandatory final
    /// outputs. Old workers reject the unknown declaration field before launch;
    /// neither endpoint may silently downgrade it to an exact-file request.
    pub fn new_tree(unit: String, required: Vec<String>) -> io::Result<Self> {
        let mut plan = Self::new(unit, required)?;
        if !cfg!(target_os = "linux") {
            return Err(io::Error::new(io::ErrorKind::Unsupported, "artifact tree capture requires Linux"));
        }
        rabs_sandbox::artifact_tree::validate_tree_names(plan.files())?;
        plan.tree = true;
        Ok(plan)
    }

    /// A sealed result contains its COMPLETE exact set, not the original tree's
    /// minimum. Rehydration reconstructs only these names and never rediscovers
    /// outputs or permits a caller's exact declaration to exceed its own bound.
    pub(crate) fn from_retained(unit: String, paths: Vec<String>) -> io::Result<Self> {
        Self::bounded(unit, paths, MAX_TREE_FILES)
    }

    fn bounded(unit: String, paths: Vec<String>, limit: usize) -> io::Result<Self> {
        if unit.is_empty()
            || unit.len() > 64
            || matches!(unit.as_str(), "." | "..")
            || !unit.bytes().all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
        {
            return Err(invalid("invalid artifact unit"));
        }
        if paths.is_empty() || paths.len() > limit {
            return Err(invalid("artifact file count outside its bound"));
        }
        let mut files = BTreeSet::new();
        let mut directories = BTreeSet::new();
        for path in paths {
            if path.len() > 1024
                || path.chars().any(char::is_control)
                || path.contains(['\\', ':'])
                || path.split('/').count() > 32
                || path.split('/').any(|part| part.is_empty() || matches!(part, "." | ".."))
            {
                return Err(invalid("unsafe artifact path"));
            }
            for (offset, _) in path.match_indices('/') {
                directories.insert(path[..offset].to_owned());
            }
            if !files.insert(path) {
                return Err(invalid("duplicate artifact path"));
            }
        }
        if files.iter().any(|path| directories.contains(path)) {
            return Err(invalid("artifact file overlaps an output directory"));
        }
        Ok(Self { unit, files, directories, tree:false })
    }

    /// Visible output root the compiler must be instructed to use explicitly.
    #[must_use]
    pub fn virtual_root(&self) -> String {
        format!("/__rabs/out/{}", self.unit)
    }

    /// Declared required names in bytewise lexical order. For a completed tree,
    /// the full output set is in CapturedArtifacts::manifest, not this minimum.
    pub fn files(&self) -> impl Iterator<Item = &str> {
        self.files.iter().map(String::as_str)
    }
}

/// Fresh output backing owned by exactly one execution. The host path is never
/// selected by a peer. Only this directory is mounted writable for this unit.
#[derive(Debug)]
pub struct PreparedArtifacts {
    plan: ArtifactPlan,
    directory: tempfile::TempDir,
}

impl PreparedArtifacts {
    /// Prepare fresh backing and declared parent directories. A later attempt
    /// cannot observe stale output files from an earlier successful compile.
    pub fn new(plan: ArtifactPlan) -> io::Result<Self> {
        let directory = tempfile::Builder::new().prefix("rabs-artifacts-").tempdir()?;
        for relative in &plan.directories {
            fs::create_dir_all(directory.path().join(relative))?;
        }
        Ok(Self { plan, directory })
    }

    /// Worker-local backing for the canonical mount, not a wire destination.
    #[must_use]
    pub fn backing(&self) -> &Path {
        self.directory.path()
    }

    /// Reuse D005's canonical output-unit mount, rather than constructing argv.
    #[must_use]
    pub fn mount(&self) -> UnitMount {
        UnitMount {
            unit: self.plan.unit.clone(),
            backing: self.directory.path().to_path_buf(),
        }
    }

    /// Capture after successful exit, zero residual group members and no
    /// interruption. The backing must remain quiescent through final verification.
    /// Exact mode rejects any undeclared entry and every hard link as before.
    /// Tree mode captures all regular files and admits only closed internal hard
    /// links, copying aliases independently; it never follows symlinks or mounts.
    pub fn capture(self, stopped: impl Fn() -> bool) -> io::Result<CapturedArtifacts> {
        if self.plan.tree {
            #[cfg(target_os = "linux")]
            return self.capture_tree(stopped);
            #[cfg(not(target_os = "linux"))]
            return Err(io::Error::new(io::ErrorKind::Unsupported, "artifact tree capture requires Linux"));
        }
        let mut pending = vec![PathBuf::new()];
        let mut found = BTreeSet::new();
        let mut entries = 0_usize;
        while let Some(relative) = pending.pop() {
            if stopped() {
                return Err(io::Error::new(io::ErrorKind::TimedOut, "artifact capture interrupted"));
            }
            for entry in fs::read_dir(self.backing().join(&relative))? {
                entries += 1;
                if entries > MAX_TREE_ENTRIES {
                    return Err(invalid("artifact directory entry limit exceeded"));
                }
                let entry = entry?;
                let path = relative.join(entry.file_name());
                let name = path.to_str().ok_or_else(|| invalid("non-UTF-8 artifact path"))?;
                let metadata = fs::symlink_metadata(entry.path())?;
                if metadata.is_dir() {
                    if !self.plan.directories.contains(name) {
                        return Err(invalid(format!("undeclared artifact directory: {name}")));
                    }
                    pending.push(path);
                } else {
                    regular_private_file(&metadata)?;
                    if !self.plan.files.contains(name) {
                        return Err(invalid(format!("undeclared artifact: {name}")));
                    }
                    found.insert(name.to_owned());
                }
            }
        }
        if found != self.plan.files {
            return Err(invalid("compiler did not produce every declared artifact"));
        }
        let mut files = BTreeMap::new();
        let mut total_bytes = 0_u64;
        for name in &self.plan.files {
            // No sandbox process remains to replace these private paths. Inspect
            // both the directory entry and opened file; retrieval never reopens it.
            regular_private_file(&fs::symlink_metadata(self.backing().join(name))?)?;
            let file = File::open(self.backing().join(name))?;
            let metadata = file.metadata()?;
            regular_private_file(&metadata)?;
            total_bytes = total_bytes.checked_add(metadata.len())
                .filter(|size| *size <= MAX_ARTIFACT_BYTES)
                .ok_or_else(|| invalid("artifact byte limit exceeded"))?;
            #[cfg(unix)]
            let executable = {
                use std::os::unix::fs::PermissionsExt;
                metadata.permissions().mode() & 0o111 != 0
            };
            #[cfg(not(unix))]
            let executable = false;
            let bytes = CapturedStream::from_reader(
                CaptureReader { file, stopped: &stopped }, metadata.len(),
            )?;
            files.insert(name.clone(), CapturedArtifact { executable, bytes });
        }
        if stopped() {
            return Err(io::Error::new(io::ErrorKind::TimedOut, "artifact capture interrupted"));
        }
        finish_capture(self.plan.clone(), files)
    }

    #[cfg(target_os = "linux")]
    fn capture_tree(self, stopped: impl Fn() -> bool) -> io::Result<CapturedArtifacts> {
        use rabs_sandbox::artifact_tree::TreeInventory;
        use std::os::unix::fs::PermissionsExt;

        let inventory = TreeInventory::scan(self.backing(), &self.plan.files, MAX_ARTIFACT_BYTES, &stopped)?;
        let mut files = BTreeMap::new();
        for name in inventory.names() {
            let file = inventory.open_file(name)?;
            let metadata = file.metadata()?;
            // Retain the same inode for the post-read check even though the
            // copying reader owns its descriptor. No original output is linked.
            let witness = file.try_clone()?;
            let bytes = CapturedStream::from_reader(
                CaptureReader { file, stopped: &stopped }, metadata.len(),
            )?;
            inventory.verify_file(name, &witness)?;
            files.insert(name.to_owned(), CapturedArtifact {
                executable: metadata.permissions().mode() & 0o111 != 0, bytes,
            });
        }
        inventory.verify(&stopped)?;
        let bundle = finish_capture(self.plan.clone(), files)?;
        if bundle.total_bytes != inventory.total_bytes() {
            return Err(invalid("artifact tree changed length during capture"));
        }
        Ok(bundle)
    }
}

fn regular_private_file(metadata: &Metadata) -> io::Result<()> {
    if !metadata.is_file() {
        return Err(invalid("artifact must be a regular file, never a symlink or special file"));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if metadata.nlink() != 1 {
            return Err(invalid("hard-linked artifact refused"));
        }
    }
    Ok(())
}

struct CaptureReader<'a, F> {
    file: File,
    stopped: &'a F,
}

impl<F: Fn() -> bool> Read for CaptureReader<'_, F> {
    fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
        if (self.stopped)() {
            // Interrupted would be retried by read_exact, defeating cancellation.
            return Err(io::Error::new(io::ErrorKind::TimedOut, "artifact capture interrupted"));
        }
        self.file.read(bytes)
    }
}

fn hash_field(hasher: &mut Sha256, bytes: &[u8]) {
    hasher.update((bytes.len() as u64).to_be_bytes());
    hasher.update(bytes);
}

#[derive(Debug)]
struct CapturedArtifact {
    executable: bool,
    bytes: CapturedStream,
}

/// Complete immutable artifact bundle. Fields are private so a successful
/// capture cannot later change its declared names, modes, hashes or lengths.
#[derive(Debug)]
pub struct CapturedArtifacts {
    plan: ArtifactPlan,
    files: BTreeMap<String, CapturedArtifact>,
    total_bytes: u64,
    manifest_sha256: String,
}

fn finish_capture(plan: ArtifactPlan, files: BTreeMap<String, CapturedArtifact>) -> io::Result<CapturedArtifacts> {
    let mut total_bytes = 0_u64;
    let mut hasher = Sha256::new();
    hash_field(&mut hasher, b"rabs.worker-artifact-manifest.v1");
    hash_field(&mut hasher, plan.unit.as_bytes());
    hasher.update((files.len() as u64).to_be_bytes());
    for (name, file) in &files {
        total_bytes = total_bytes.checked_add(file.bytes.len())
            .filter(|total| *total <= MAX_ARTIFACT_BYTES)
            .ok_or_else(|| invalid("artifact byte limit exceeded"))?;
        hash_field(&mut hasher, name.as_bytes());
        hasher.update([u8::from(file.executable)]);
        hasher.update(file.bytes.len().to_be_bytes());
        hash_field(&mut hasher, file.bytes.sha256().as_bytes());
    }
    let manifest_sha256 = hasher.finalize().iter().map(|b| format!("{b:02x}")).collect();
    let bundle = CapturedArtifacts { plan, files, total_bytes, manifest_sha256 };
    if serde_json::to_vec(&bundle.manifest())?.len() > MAX_TREE_MANIFEST_BYTES {
        return Err(invalid("artifact manifest exceeds transport/retention bound"));
    }
    Ok(bundle)
}

impl CapturedArtifacts {
    /// Original declaration, including whether its files were a tree minimum.
    #[must_use]
    pub fn plan(&self) -> &ArtifactPlan { &self.plan }

    /// Digest over the canonical unit, names, executable bits, sizes and hashes.
    #[must_use]
    pub fn manifest_sha256(&self) -> &str { &self.manifest_sha256 }

    /// Total bytes retained, bounded independently of the number of files.
    #[must_use]
    pub fn total_bytes(&self) -> u64 { self.total_bytes }

    /// Read ONLY a previously declared and captured name; this never opens a path.
    pub fn read_chunk(&mut self, name: &str, offset: u64, size: usize) -> io::Result<Vec<u8>> {
        self.files.get_mut(name).ok_or_else(|| invalid("unknown artifact"))?
            .bytes.read_chunk(offset, size)
    }

    /// Stable COMPLETE descriptors for negotiation/ACK; no physical backing is
    /// disclosed. Both declaration modes use the same exact-set manifest hash.
    #[must_use]
    pub fn manifest(&self) -> serde_json::Value {
        let files: Vec<_> = self.files.iter().map(|(name, artifact)| serde_json::json!({
            "name": name, "bytes": artifact.bytes.len(), "sha256": artifact.bytes.sha256(),
            "executable": artifact.executable,
        })).collect();
        serde_json::json!({
            "unit": self.plan.unit, "files": files, "total_bytes": self.total_bytes,
            "manifest_sha256": self.manifest_sha256,
        })
    }

    /// Identity of one retained file for independently verified range responses.
    pub fn file_identity(&self, name: &str) -> Option<(u64, &str, bool)> {
        self.files.get(name).map(|file| (file.bytes.len(), file.bytes.sha256(), file.executable))
    }
}

/// Decode a request's optional artifact declaration without accepting any host
/// backing path. Unsupported declaration fields are refusals, not ignored hints.
/// `tree: "tree-files-v1"` makes `files` the mandatory minimum rather than the
/// entire set. Old workers reject that field instead of executing a weaker plan.
pub fn parse_plan(request: &serde_json::Value) -> Result<Option<ArtifactPlan>, String> {
    let Some(value) = request.get("artifacts") else { return Ok(None); };
    let object = value.as_object().ok_or("artifacts must be an object")?;
    if object.keys().any(|key| key != "unit" && key != "files" && key != "tree") {
        return Err("unsupported artifact declaration field".to_owned());
    }
    let tree = match value.get("tree") {
        None => false,
        Some(value) if value.as_str() == Some(TREE_FILES_VERSION) => true,
        Some(_) => return Err("unsupported artifact tree declaration".to_owned()),
    };
    let unit = value.get("unit").and_then(serde_json::Value::as_str)
        .ok_or("artifact unit must be a string")?;
    let files = value.get("files").and_then(serde_json::Value::as_array)
        .filter(|files| !files.is_empty() && files.len() <= MAX_ARTIFACT_FILES)
        .ok_or("artifact files must contain 1..=128 names")?;
    let paths = files.iter().map(|file| file.as_str().map(str::to_owned)
        .ok_or_else(|| "artifact names must be strings".to_owned()))
        .collect::<Result<Vec<_>, _>>()?;
    let plan = if tree { ArtifactPlan::new_tree(unit.to_owned(), paths) }
        else { ArtifactPlan::new(unit.to_owned(), paths) };
    plan.map(Some).map_err(|error| error.to_string())
}

/// An absent selection keeps artifact capture disabled. No unknown version may
/// silently fall back to a successful digest-only result for requested files.
pub fn transfer_requested(ack: &str) -> Result<bool, String> {
    let value: serde_json::Value = serde_json::from_str(ack).map_err(|e| e.to_string())?;
    match value.get("artifact_transfer") {
        None => Ok(false),
        Some(value) if value.as_str() == Some(ARTIFACT_TRANSFER) => Ok(true),
        Some(_) => Err("unsupported artifact_transfer selection".to_owned()),
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ArtifactAck {
    request_id: u64,
    manifest_sha256: String,
    total_bytes: u64,
}

impl ArtifactAck {
    fn new(request_id: u64, bundle: &CapturedArtifacts) -> Self {
        Self { request_id, manifest_sha256: bundle.manifest_sha256().to_owned(), total_bytes: bundle.total_bytes() }
    }

    fn parse(value: &serde_json::Value) -> Option<Self> {
        Some(Self {
            request_id: value.get("request_id")?.as_u64()?,
            manifest_sha256: value.get("manifest_sha256")?.as_str()?.to_owned(),
            total_bytes: value.get("total_bytes")?.as_u64()?,
        })
    }
}

/// Session-owned delivery state: at most one unacknowledged bundle, no global
/// file registry and no implicit eviction on new work. An ACK is a receiver's
/// acceptance claim, never proof of cache publication or independent execution.
#[derive(Debug, Default)]
pub struct ArtifactTransferState {
    pending: Option<(ArtifactAck, CapturedArtifacts)>,
    last_ack: Option<ArtifactAck>,
}

impl ArtifactTransferState {
    /// Whether admitting new execution would discard undelivered artifacts.
    #[must_use]
    pub fn is_pending(&self) -> bool { self.pending.is_some() }

    /// Request holding the session's bounded retention capacity.
    #[must_use]
    pub fn pending_request_id(&self) -> Option<u64> {
        self.pending.as_ref().map(|(identity, _)| identity.request_id)
    }

    /// Transfer a completed bundle into the session without evicting another.
    pub fn retain(&mut self, request_id: u64, bundle: CapturedArtifacts) -> Result<(), String> {
        if self.pending.is_some() { return Err("artifacts-unacknowledged".to_owned()); }
        self.pending = Some((ArtifactAck::new(request_id, &bundle), bundle));
        Ok(())
    }

    /// Serve a bounded, repeatable range of a captured name. No caller-selected
    /// path is reopened; replacing original compiler files cannot affect reads.
    pub fn read_frame(&mut self, value: &serde_json::Value) -> Result<String, String> {
        let (identity, bundle) = self.pending.as_mut().ok_or("unknown-artifact-request")?;
        if value.get("request_id").and_then(serde_json::Value::as_u64) != Some(identity.request_id) {
            return Err("unknown-artifact-request".to_owned());
        }
        if value.get("path").is_some() || value.get("backing").is_some() {
            return Err("artifact-host-paths-not-accepted".to_owned());
        }
        let name = value.get("name").and_then(serde_json::Value::as_str).ok_or("artifact name required")?;
        let offset = value.get("offset").and_then(serde_json::Value::as_u64).ok_or("artifact offset required")?;
        let size = match value.get("max_bytes") {
            None => MAX_OUTPUT_CHUNK_BYTES,
            Some(value) => value.as_u64().and_then(|size| usize::try_from(size).ok())
                .filter(|size| *size > 0 && *size <= MAX_OUTPUT_CHUNK_BYTES)
                .ok_or("invalid artifact chunk size")?,
        };
        let bytes = bundle.read_chunk(name, offset, size).map_err(|e| e.to_string())?;
        let (total_bytes, sha256, executable) = bundle.file_identity(name).ok_or("unknown artifact")?;
        let next_offset = offset.checked_add(bytes.len() as u64).ok_or("artifact offset overflow")?;
        let data_hex: String = bytes.iter().map(|b| format!("{b:02x}")).collect();
        Ok(serde_json::json!({
            "kind": "artifact-chunk", "request_id": identity.request_id, "name": name,
            "offset": offset, "next_offset": next_offset, "total_bytes": total_bytes,
            "eof": next_offset == total_bytes, "data_hex": data_hex, "sha256": sha256,
            "executable": executable, "chunk_sha256": crate::session::sha256_hex(&bytes),
            "manifest_sha256": identity.manifest_sha256,
        }).to_string())
    }

    /// Release only an exactly acknowledged bundle. The last ACK may be retried
    /// without releasing a later execution's files. Disconnect drops all state.
    pub fn acknowledge(&mut self, value: &serde_json::Value) -> Result<String, String> {
        let ack = ArtifactAck::parse(value).ok_or("artifact-ack-mismatch")?;
        let already_released = if self.pending.as_ref().is_some_and(|(identity, _)| identity == &ack) {
            drop(self.pending.take());
            self.last_ack = Some(ack.clone());
            false
        } else if self.last_ack.as_ref() == Some(&ack) {
            true
        } else {
            return Err("artifact-ack-mismatch".to_owned());
        };
        Ok(serde_json::json!({
            "kind": "artifact-acknowledged", "request_id": ack.request_id,
            "already_released": already_released,
        }).to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn plan(paths: &[&str]) -> ArtifactPlan {
        ArtifactPlan::new("dep".into(), paths.iter().map(|s| (*s).into()).collect()).unwrap()
    }

    #[test]
    fn declarations_refuse_aliases_and_overlapping_files_before_execution() {
        for path in ["", "/abs", "../x", "x/../y", "./x", "a//b", "a/", "a\\b", "x:y", "a\0b"] {
            assert!(ArtifactPlan::new("dep".into(), vec![path.into()]).is_err(), "{path:?}");
        }
        for unit in ["", ".", "..", "a/b", "x\\y", "a:b"] {
            assert!(ArtifactPlan::new(unit.into(), vec!["x".into()]).is_err());
        }
        for paths in [vec![], vec!["x"; MAX_ARTIFACT_FILES + 1], vec!["x", "x"], vec!["a", "a-z", "a/b"]] {
            assert!(ArtifactPlan::new("dep".into(), paths.into_iter().map(str::to_owned).collect()).is_err());
        }
        assert_eq!(plan(&["obj/a.rlib", "dep.d"]).virtual_root(), "/__rabs/out/dep");
    }

    #[test]
    fn fresh_backing_and_binary_artifacts_are_snapshotted_as_one_exact_set() {
        let plan = plan(&["obj/lib.rlib", "dep.d"]);
        let prepared = PreparedArtifacts::new(plan.clone()).unwrap();
        let next = PreparedArtifacts::new(plan.clone()).unwrap();
        assert_ne!(prepared.backing(), next.backing());
        fs::write(prepared.backing().join("obj/lib.rlib"), b"archive\0\xff").unwrap();
        fs::write(prepared.backing().join("dep.d"), b"target: source.rs\n").unwrap();
        assert!(!next.backing().join("obj/lib.rlib").exists());
        let mut captured = prepared.capture(|| false).unwrap();
        assert_eq!(captured.plan(), &plan);
        assert_eq!(captured.read_chunk("obj/lib.rlib", 0, 64).unwrap(), b"archive\0\xff");
        assert_eq!(captured.file_identity("obj/lib.rlib").unwrap().1, crate::session::sha256_hex(b"archive\0\xff"));
        assert!(captured.read_chunk("../secret", 0, 64).is_err());
        assert!(captured.read_chunk("dep.d", u64::MAX, 1).is_err());
        assert_eq!(captured.manifest()["files"].as_array().unwrap().len(), 2);
    }

    #[test]
    fn missing_extra_oversized_and_interrupted_artifacts_never_form_an_offer() {
        for case in 0..4 {
            let prepared = PreparedArtifacts::new(plan(&["a"])).unwrap();
            match case {
                0 => {}
                1 => { fs::write(prepared.backing().join("a"), b"ok").unwrap(); fs::write(prepared.backing().join("extra"), b"bad").unwrap(); }
                2 => { File::create(prepared.backing().join("a")).unwrap().set_len(MAX_ARTIFACT_BYTES + 1).unwrap(); }
                _ => { fs::write(prepared.backing().join("a"), b"ok").unwrap(); }
            }
            assert!(prepared.capture(|| case == 3).is_err());
        }
    }

    #[cfg(unix)]
    #[test]
    fn symlinks_directories_and_hard_links_cannot_export_host_files() {
        use std::os::unix::fs::symlink;
        let outside = tempfile::tempdir().unwrap();
        fs::write(outside.path().join("secret"), b"private").unwrap();
        for case in 0..3 {
            let prepared = PreparedArtifacts::new(plan(&["a"])).unwrap();
            let a = prepared.backing().join("a");
            match case {
                0 => symlink(outside.path().join("secret"), a).unwrap(),
                1 => fs::hard_link(outside.path().join("secret"), a).unwrap(),
                _ => fs::create_dir(a).unwrap(),
            }
            assert!(prepared.capture(|| false).is_err());
        }
        let prepared = PreparedArtifacts::new(plan(&["nested/a"])).unwrap();
        // Replace a declared directory with a symlink without deleting its data.
        fs::rename(prepared.backing().join("nested"), prepared.backing().join("saved")).unwrap();
        symlink(outside.path(), prepared.backing().join("nested")).unwrap();
        assert!(prepared.capture(|| false).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn canonical_manifest_is_order_independent_but_binds_modes_and_bytes() {
        use std::os::unix::fs::PermissionsExt;
        let capture = |paths: &[&str], executable, bytes: &[u8]| {
            let prepared = PreparedArtifacts::new(plan(paths)).unwrap();
            fs::write(prepared.backing().join("a"), bytes).unwrap();
            fs::write(prepared.backing().join("b"), b"b").unwrap();
            fs::set_permissions(prepared.backing().join("a"), fs::Permissions::from_mode(if executable { 0o755 } else { 0o644 })).unwrap();
            fs::set_permissions(prepared.backing().join("b"), fs::Permissions::from_mode(0o644)).unwrap();
            prepared.capture(|| false).unwrap().manifest_sha256().to_owned()
        };
        let original = capture(&["a", "b"], false, b"a");
        assert_eq!(original, capture(&["b", "a"], false, b"a"));
        assert_ne!(original, capture(&["a", "b"], true, b"a"));
        assert_ne!(original, capture(&["a", "b"], false, b"changed"));
    }

    fn bundle() -> CapturedArtifacts {
        let prepared = PreparedArtifacts::new(plan(&["a"])).unwrap();
        fs::write(prepared.backing().join("a"), b"A\0\xffB").unwrap();
        prepared.capture(|| false).unwrap()
    }

    #[test]
    fn named_ranges_and_ack_retries_never_evict_a_newer_bundle() {
        let first = bundle();
        // Independent SHA-256/framing golden for binary bytes A 00 ff B,
        // unit=dep, name=a, executable=false. This is a wire contract.
        assert_eq!(first.manifest_sha256(),
            "548324c3a5c96511944c6ec6af94ee9bbb6683170bb0143f9d99cd192f80bfd6");
        let ack = serde_json::json!({"request_id": 1, "manifest_sha256": first.manifest_sha256(), "total_bytes": 4});
        let mut state = ArtifactTransferState::default();
        state.retain(1, first).unwrap();
        assert!(state.retain(2, bundle()).is_err());
        let read = serde_json::json!({"request_id": 1, "name": "a", "offset": 1, "max_bytes": 2});
        let response = state.read_frame(&read).unwrap();
        assert_eq!(state.read_frame(&read).unwrap(), response);
        let response: serde_json::Value = serde_json::from_str(&response).unwrap();
        assert_eq!(response["data_hex"], "00ff");
        assert_eq!(response["chunk_sha256"], crate::session::sha256_hex(b"\0\xff"));
        let mut wrong = ack.clone();
        wrong["total_bytes"] = serde_json::json!(3);
        assert!(state.acknowledge(&wrong).is_err());
        assert!(state.is_pending());
        state.acknowledge(&ack).unwrap();
        state.retain(2, bundle()).unwrap();
        let duplicate: serde_json::Value = serde_json::from_str(&state.acknowledge(&ack).unwrap()).unwrap();
        assert_eq!(duplicate["already_released"], true);
        assert_eq!(state.pending_request_id(), Some(2));
        assert!(ArtifactTransferState::default().read_frame(&read).is_err());
    }

    #[test]
    fn artifact_ranges_refuse_unknown_names_paths_ids_and_bounds() {
        let mut state = ArtifactTransferState::default();
        state.retain(1, bundle()).unwrap();
        let read = serde_json::json!({"request_id": 1, "name": "a", "offset": 0, "max_bytes": 4});
        for (key, value) in [
            ("request_id", serde_json::json!(2)), ("name", serde_json::json!("../a")),
            ("path", serde_json::json!("/etc/passwd")), ("offset", serde_json::json!(u64::MAX)),
            ("max_bytes", serde_json::json!(0)), ("max_bytes", serde_json::json!(65537)),
        ] {
            let mut bad = read.clone(); bad[key] = value;
            assert!(state.read_frame(&bad).is_err());
        }
        assert!(state.read_frame(&read).is_ok());
    }

    #[test]
    fn declarations_and_transfer_versions_are_never_lossily_interpreted() {
        assert!(parse_plan(&serde_json::json!({})).unwrap().is_none());
        let valid = serde_json::json!({"unit": "dep", "files": ["a", "nested/b"]});
        assert!(parse_plan(&serde_json::json!({"artifacts": valid})).unwrap().is_some());
        for invalid in [
            serde_json::Value::Null, serde_json::json!({"unit": "dep", "files": ["a", 1]}),
            serde_json::json!({"unit": "dep", "files": ["a"], "backing": "/tmp"}),
            serde_json::json!({"unit": "dep", "files": ["a", "a/b"]}),
        ] { assert!(parse_plan(&serde_json::json!({"artifacts": invalid})).is_err()); }
        assert!(!transfer_requested("{}").unwrap());
        assert!(transfer_requested(r#"{"artifact_transfer":"files-v1"}"#).unwrap());
        for selection in [serde_json::Value::Null, serde_json::json!(true), serde_json::json!("files-v2")] {
            assert!(transfer_requested(&serde_json::json!({"artifact_transfer": selection}).to_string()).is_err());
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn tree_mode_captures_cargo_outputs_and_closed_hardlinks_without_changing_exact_mode() {
        use std::os::unix::fs::PermissionsExt;
        let plan = ArtifactPlan::new_tree("build".into(), vec!["debug/app".into()]).unwrap();
        let prepared = PreparedArtifacts::new(plan.clone()).unwrap();
        fs::create_dir_all(prepared.backing().join("debug/deps")).unwrap();
        fs::create_dir_all(prepared.backing().join("debug/.fingerprint/app-hash")).unwrap();
        fs::create_dir_all(prepared.backing().join("debug/incremental/empty")).unwrap();
        fs::write(prepared.backing().join("debug/deps/app-hash"), b"ELF\0\xff").unwrap();
        fs::set_permissions(prepared.backing().join("debug/deps/app-hash"), fs::Permissions::from_mode(0o755)).unwrap();
        fs::hard_link(prepared.backing().join("debug/deps/app-hash"), prepared.backing().join("debug/app")).unwrap();
        fs::write(prepared.backing().join("debug/.fingerprint/app-hash/bin-app"), b"fingerprint").unwrap();
        fs::write(prepared.backing().join("debug/.cargo-lock"), b"").unwrap();
        let mut bundle = prepared.capture(|| false).unwrap();
        assert_eq!(bundle.plan(), &plan);
        assert_eq!(bundle.manifest()["files"].as_array().unwrap().len(), 4);
        assert_eq!(bundle.read_chunk("debug/app", 0, 64).unwrap(), b"ELF\0\xff");
        assert_eq!(bundle.read_chunk("debug/deps/app-hash", 0, 64).unwrap(), b"ELF\0\xff");
        assert!(bundle.file_identity("debug/app").unwrap().2);
        assert_eq!(bundle.total_bytes(), 21);
        let exact = PreparedArtifacts::new(ArtifactPlan::new("build".into(), vec!["debug/app".into()]).unwrap()).unwrap();
        fs::write(exact.backing().join("debug/app"), b"ok").unwrap();
        fs::write(exact.backing().join("debug/unrequested"), b"extra").unwrap();
        assert!(exact.capture(|| false).is_err(), "exact mode must not widen its contract");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn tree_mode_never_omits_invalid_or_external_outputs() {
        use std::os::unix::fs::symlink;
        for case in 0..4 {
            let prepared = PreparedArtifacts::new(ArtifactPlan::new_tree("build".into(), vec!["app".into()]).unwrap()).unwrap();
            let outside = tempfile::tempdir().unwrap();
            fs::write(outside.path().join("secret"), b"secret").unwrap();
            if case != 0 { fs::write(prepared.backing().join("app"), b"ok").unwrap(); }
            match case {
                0 => fs::write(prepared.backing().join("other"), b"not the required output").unwrap(),
                1 => symlink(outside.path().join("secret"), prepared.backing().join("extra")).unwrap(),
                2 => fs::hard_link(outside.path().join("secret"), prepared.backing().join("extra")).unwrap(),
                _ => fs::write(prepared.backing().join("APP"), b"case alias").unwrap(),
            }
            assert!(prepared.capture(|| false).is_err(), "case {case}");
        }
    }

    #[test]
    fn tree_declaration_versions_never_downgrade_and_retained_bounds_are_separate() {
        let request = serde_json::json!({"artifacts":{"unit":"build", "files":["debug/app"]}});
        assert!(!parse_plan(&request).unwrap().unwrap().tree);
        for version in [serde_json::Value::Null, serde_json::json!(true), serde_json::json!("tree-files-v2")] {
            let mut bad = request.clone(); bad["artifacts"]["tree"] = version;
            assert!(parse_plan(&bad).is_err());
        }
        let names: Vec<_> = (0..MAX_ARTIFACT_FILES + 1).map(|index| format!("f{index}")).collect();
        assert!(ArtifactPlan::new("build".into(), names.clone()).is_err());
        assert!(ArtifactPlan::from_retained("build".into(), names).is_ok());
        #[cfg(target_os = "linux")]
        {
            let mut tree = request;
            tree["artifacts"]["tree"] = serde_json::json!(TREE_FILES_VERSION);
            assert!(parse_plan(&tree).unwrap().unwrap().tree);
        }
    }
}
