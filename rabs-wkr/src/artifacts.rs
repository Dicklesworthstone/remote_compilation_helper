//! Declared compiler artifacts, captured from one private canonical output mount.
//!
//! The worker chooses the physical backing. The request names only a canonical
//! unit and an exact set of relative files. Harvesting runs AFTER the process
//! group and drains have resolved, never over a caller-selected host directory.
//! Every file is snapshotted into the same immutable, bounded storage used for
//! diagnostic ranges. This is a prepared transport offer, not a CAS publication.

use crate::output::{CapturedStream, MAX_RETAINED_STREAM_BYTES};
use rabs_sandbox::canonical_mounts::UnitMount;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File, Metadata};
use std::io::{self, Read};
use std::path::{Path, PathBuf};

/// Maximum files in one artifact offer, independently of peer frame limits.
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
}

impl ArtifactPlan {
    /// Reject aliases, traversal, duplicate files and file/directory conflicts
    /// before execution. Path spelling is preserved, never silently normalized.
    pub fn new(unit: String, paths: Vec<String>) -> io::Result<Self> {
        if unit.is_empty()
            || unit.len() > 64
            || matches!(unit.as_str(), "." | "..")
            || !unit.bytes().all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
        {
            return Err(invalid("invalid artifact unit"));
        }
        if paths.is_empty() || paths.len() > MAX_ARTIFACT_FILES {
            return Err(invalid("artifact file count outside 1..=128"));
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
        Ok(Self { unit, files, directories })
    }

    /// Visible output root the compiler must be instructed to use explicitly.
    #[must_use]
    pub fn virtual_root(&self) -> String {
        format!("/__rabs/out/{}", self.unit)
    }

    /// Stable relative names in bytewise lexical order.
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

    /// Capture the exact declared file set after all sandbox writers are gone.
    ///
    /// The caller must have confirmed successful process exit, zero residual
    /// group members and no interruption. The private backing is quiescent;
    /// symlinks, special files, hard links, unknown entries and missing files
    /// refuse the ENTIRE offer. Cancellation is checked during copying too.
    pub fn capture(self, stopped: impl Fn() -> bool) -> io::Result<CapturedArtifacts> {
        let mut pending = vec![PathBuf::new()];
        let mut found = BTreeSet::new();
        let mut entries = 0_usize;
        while let Some(relative) = pending.pop() {
            if stopped() {
                return Err(io::Error::new(io::ErrorKind::TimedOut, "artifact capture interrupted"));
            }
            for entry in fs::read_dir(self.backing().join(&relative))? {
                entries += 1;
                if entries > 4096 {
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
        let mut hasher = Sha256::new();
        hash_field(&mut hasher, b"rabs.worker-artifact-manifest.v1");
        hash_field(&mut hasher, self.plan.unit.as_bytes());
        hasher.update((files.len() as u64).to_be_bytes());
        for (name, file) in &files {
            hash_field(&mut hasher, name.as_bytes());
            hasher.update([u8::from(file.executable)]);
            hasher.update(file.bytes.len().to_be_bytes());
            hash_field(&mut hasher, file.bytes.sha256().as_bytes());
        }
        let manifest_sha256 = hasher.finalize().iter().map(|b| format!("{b:02x}")).collect();
        Ok(CapturedArtifacts { plan: self.plan.clone(), files, total_bytes, manifest_sha256 })
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

impl CapturedArtifacts {
    /// The execution's exact declaration, checked again at result completion.
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

    /// Stable descriptors for negotiation/ACK; no physical backing is disclosed.
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
}
