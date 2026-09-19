//! Coherent snapshot capture with mutation detection/retry and
//! path-dependency closure (bead D018; invariant I2; plan §28/§78).
//!
//! A snapshot that mixes bytes from two moments is worse than no
//! snapshot: it can type-check, build, and poison portable authority
//! with a state no developer ever had. This module establishes a
//! COHERENT capture boundary or refuses, never something in between:
//!
//! - on filesystems with a real atomic primitive (snapshot/reflink),
//!   one scan of the frozen image is authoritative by construction;
//! - everywhere else, an attempt is TWO full stable scans, each file
//!   read through an open descriptor (hash the bytes, fstat the SAME
//!   descriptor before and after the read); the attempt stands only
//!   if the scans are byte- and metadata-identical;
//! - ANY divergence — directory-set change, inode replacement, content
//!   or size/mtime drift, symlink retarget, kind change, instability
//!   under an open descriptor — discards the ENTIRE attempt and
//!   retries the capture from scratch;
//! - bounded attempts exhausted ⇒ a typed refusal carrying the last
//!   divergence, because refusing authoritative snapshotting beats
//!   fabricating one (the honest-work rule, in code);
//! - `.git` is hidden unless a canonical git-state object is declared
//!   (D031 lands that object; the flag is the contract here);
//! - the manifest binds the snapshot root and the filesystem semantic
//!   class into a digest that provenance and every child action
//!   request carry (I2's "bind the boundary" clause).
//!
//! Membership is policy, not accident: the always-include set
//! (lockfile, `.cargo` config, toolchain files) is explicit, ephemeral
//! locks and mutable build outputs are excluded by class, and the
//! path-dependency closure is captured all-or-nothing — one root
//! failing coherence refuses the WHOLE closure.
//!
//! The older manifest APIs retain observations, not source bytes. Q003's
//! [`capture_sealed_source`] retains the accepted descriptor-read bytes across
//! a paired scan of the complete closure, independent of later checkout edits.

use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;

/// How the underlying filesystem lets us establish the boundary.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FsSemanticClass {
    /// A true point-in-time snapshot primitive (LVM/btrfs/ZFS/APFS
    /// snapshot): one scan of the frozen image is coherent by
    /// construction.
    AtomicSnapshot,
    /// Reflink/clone of the tree completed before scanning; coherent
    /// if the clone itself was atomic per-file plus a verified quiet
    /// directory generation (still single-scan authoritative here —
    /// the CLONE is what the generation watcher guards).
    Reflink,
    /// No primitive: coherence must be PROVEN by paired stable scans
    /// with retry (the default, and the honest floor).
    GenerationScan,
}

/// What one member of the tree looked like during a scan.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MemberKind {
    /// Regular file, read through an open descriptor.
    Regular {
        /// Byte length (fstat on the open descriptor).
        size: u64,
        /// Inode (0 where the platform has none).
        inode: u64,
        /// mtime in nanoseconds since epoch (0 where unavailable).
        mtime_ns: u128,
        /// SHA-256 of the bytes actually read.
        content_sha256: [u8; 32],
        /// Permission bits (Unix 0o777; readonly/writable on other platforms).
        mode: u32,
    },
    /// Symlink — structure preserved byte-for-byte, never followed.
    Symlink {
        /// Raw target bytes as a lossless string.
        target: String,
    },
    /// Directory (presence/shape member).
    Directory,
}

/// One full stable scan: relative path → observed member.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ScanObservation {
    /// Sorted member map (BTreeMap keeps digest input deterministic).
    pub members: BTreeMap<String, MemberKind>,
    // Local mutation evidence only, never part of the portable manifest hash.
    // Keeping this across passes catches write/restore cycles whose bytes and
    // mtime match again. Synthetic scanners can populate members via Default.
    identities: BTreeMap<String, FileIdentity>,
}

/// The first divergence between two scans of one attempt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Divergence {
    /// The set of paths itself changed.
    DirectorySetChanged {
        /// Paths present only in the second scan.
        added: Vec<String>,
        /// Paths present only in the first scan.
        removed: Vec<String>,
    },
    /// Same path, replaced inode (atomic-save rename, unlink+create).
    InodeReplaced {
        /// The affected path.
        path: String,
    },
    /// Same inode, different bytes.
    ContentChanged {
        /// The affected path.
        path: String,
    },
    /// Size/mtime moved without a content difference we accept —
    /// metadata inconsistency is a divergence, not a shrug (I2).
    MetadataInconsistent {
        /// The affected path.
        path: String,
    },
    /// Symlink points somewhere else now.
    SymlinkRetargeted {
        /// The affected path.
        path: String,
    },
    /// Regular↔symlink↔directory changed species.
    KindChanged {
        /// The affected path.
        path: String,
    },
    /// A file was unstable UNDER its own open descriptor (fstat
    /// before/after the read disagreed) — reported by the scanner.
    UnstableDuringRead {
        /// The affected path.
        path: String,
    },
}

/// Scanner-reported failure of one scan pass.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ScanError {
    /// A file changed identity/size/metadata while its descriptor was
    /// open — the pass is void and counts as a divergence.
    UnstableDuringRead {
        /// The affected path.
        path: String,
    },
    /// I/O failure reading the tree (permission, vanished root, …).
    Io {
        /// The affected path.
        path: String,
        /// Stringified cause (kept typed-enough for tests and `rch why`).
        cause: String,
    },
}

/// A boxed scan function, for closures over heterogeneous roots.
pub type BoxedScanner = Box<dyn FnMut(u32, u32) -> Result<ScanObservation, ScanError>>;

/// Typed refusal: no coherent boundary could be established.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CaptureRefusal {
    /// Attempts actually consumed.
    pub attempts: u32,
    /// What broke the final attempt.
    pub last_divergence: Divergence,
}

impl std::fmt::Display for CaptureRefusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "no coherent snapshot boundary after {} attempts; last divergence: {:?}",
            self.attempts, self.last_divergence
        )
    }
}

impl std::error::Error for CaptureRefusal {}

/// Hard I/O failure (distinct from coherence refusal: retry cannot fix
/// a vanished root or permission wall, so it surfaces immediately).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CaptureIoError {
    /// The affected path.
    pub path: String,
    /// Stringified cause.
    pub cause: String,
}

impl std::fmt::Display for CaptureIoError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "snapshot scan I/O failure at {}: {}",
            self.path, self.cause
        )
    }
}

impl std::error::Error for CaptureIoError {}

/// Capture failure: either a typed coherence refusal or hard I/O.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CaptureError {
    /// Bounded retries exhausted without a coherent pair.
    Incoherent(CaptureRefusal),
    /// Hard I/O failure.
    Io(CaptureIoError),
    /// An unsupported or unsafe source cannot become a sealed image.
    Rejected {
        /// Logical member/root, without source bytes.
        path: String,
        /// The policy or resource boundary that refused capture.
        reason: CaptureRejection,
    },
}

/// Sealed-source refusal reasons, distinct from transient mutations and I/O.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CaptureRejection {
    /// Empty/duplicate root identity, or an identity unsafe as a path component.
    InvalidRoot,
    /// A path cannot be represented losslessly and safely in the manifest.
    InvalidPath,
    /// Devices, sockets, FIFOs and unsupported filesystem objects are refused.
    UnsupportedKind,
    /// A symlink is absolute or escapes its captured root.
    UnsafeSymlink,
    /// A descendant crosses a mount boundary, including a bind mount.
    CrossMount,
    /// The complete closure exceeds the caller's retained-byte limit.
    ByteLimitExceeded,
}

/// Capture configuration.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CaptureConfig {
    /// Filesystem semantic class (bound into the manifest).
    pub fs_class: FsSemanticClass,
    /// Whole-capture attempts before refusing (≥1).
    pub max_attempts: u32,
}

impl CaptureConfig {
    /// Generation-scan default: paired scans, three attempts.
    #[must_use]
    pub const fn generation_scan() -> Self {
        Self {
            fs_class: FsSemanticClass::GenerationScan,
            max_attempts: 3,
        }
    }
}

/// The authoritative result: a coherent manifest with its binding
/// digest. Child action requests carry [`SnapshotProvenance`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SnapshotManifest {
    /// The captured root (logical: workspace or closure-repo id).
    pub root: String,
    /// How coherence was established.
    pub fs_class: FsSemanticClass,
    /// The verified members.
    pub members: BTreeMap<String, MemberKind>,
    /// Digest binding root + class + every member (path, kind, bytes).
    pub manifest_sha256: [u8; 32],
}

/// What provenance and every child action request must carry (I2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SnapshotProvenance {
    /// The snapshot root.
    pub snapshot_root: String,
    /// The filesystem semantic class that established the boundary.
    pub fs_class: FsSemanticClass,
    /// The manifest digest.
    pub manifest_sha256: [u8; 32],
}

impl SnapshotManifest {
    /// The provenance binding for child action requests.
    #[must_use]
    pub fn provenance(&self) -> SnapshotProvenance {
        SnapshotProvenance {
            snapshot_root: self.root.clone(),
            fs_class: self.fs_class,
            manifest_sha256: self.manifest_sha256,
        }
    }

    fn seal(root: &str, fs_class: FsSemanticClass, members: BTreeMap<String, MemberKind>) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(root.as_bytes());
        hasher.update([0u8]);
        hasher.update(match fs_class {
            FsSemanticClass::AtomicSnapshot => b"atomic-snapshot".as_slice(),
            FsSemanticClass::Reflink => b"reflink".as_slice(),
            FsSemanticClass::GenerationScan => b"generation-scan".as_slice(),
        });
        for (path, kind) in &members {
            hasher.update([0u8]);
            hasher.update(path.as_bytes());
            hasher.update([0u8]);
            match kind {
                MemberKind::Regular {
                    size,
                    inode: _, // inode is host-physical, not identity
                    mtime_ns: _,
                    content_sha256,
                    mode,
                } => {
                    hasher.update(b"f");
                    hasher.update(size.to_le_bytes());
                    hasher.update(content_sha256);
                    hasher.update(mode.to_le_bytes());
                }
                MemberKind::Symlink { target } => {
                    hasher.update(b"l");
                    hasher.update(target.as_bytes());
                }
                MemberKind::Directory => hasher.update(b"d"),
            }
        }
        let manifest_sha256 = hasher.finalize().into();
        Self {
            root: root.to_string(),
            fs_class,
            members,
            manifest_sha256,
        }
    }
}

/// First divergence between the two scans of one attempt, if any.
#[must_use]
pub fn first_divergence(first: &ScanObservation, second: &ScanObservation) -> Option<Divergence> {
    let added: Vec<String> = second
        .members
        .keys()
        .filter(|k| !first.members.contains_key(*k))
        .cloned()
        .collect();
    let removed: Vec<String> = first
        .members
        .keys()
        .filter(|k| !second.members.contains_key(*k))
        .cloned()
        .collect();
    if !added.is_empty() || !removed.is_empty() {
        return Some(Divergence::DirectorySetChanged { added, removed });
    }
    for (path, a) in &first.members {
        let b = &second.members[path];
        match (a, b) {
            (
                MemberKind::Regular {
                    size: sa,
                    inode: ia,
                    mtime_ns: ma,
                    content_sha256: ca,
                    mode: moda,
                },
                MemberKind::Regular {
                    size: sb,
                    inode: ib,
                    mtime_ns: mb,
                    content_sha256: cb,
                    mode: modb,
                },
            ) => {
                if ia != ib {
                    return Some(Divergence::InodeReplaced { path: path.clone() });
                }
                if ca != cb {
                    return Some(Divergence::ContentChanged { path: path.clone() });
                }
                if sa != sb || ma != mb || moda != modb {
                    return Some(Divergence::MetadataInconsistent { path: path.clone() });
                }
            }
            (MemberKind::Symlink { target: ta }, MemberKind::Symlink { target: tb }) => {
                if ta != tb {
                    return Some(Divergence::SymlinkRetargeted { path: path.clone() });
                }
            }
            (MemberKind::Directory, MemberKind::Directory) => {}
            _ => return Some(Divergence::KindChanged { path: path.clone() }),
        }
    }
    for path in first.identities.keys().chain(second.identities.keys()) {
        if first.identities.get(path) != second.identities.get(path) {
            return Some(Divergence::MetadataInconsistent { path: path.clone() });
        }
    }
    None
}

/// Establish a coherent snapshot of one root, or refuse.
///
/// `scan` is called with `(attempt, pass)` — pass is 0 or 1 within an
/// attempt for [`FsSemanticClass::GenerationScan`], always 0 for the
/// single-scan primitive classes. Every retry re-runs the ENTIRE
/// capture: nothing from a diverged attempt survives into the manifest.
pub fn capture_coherent<F>(
    config: CaptureConfig,
    root: &str,
    mut scan: F,
) -> Result<SnapshotManifest, CaptureError>
where
    F: FnMut(u32, u32) -> Result<ScanObservation, ScanError>,
{
    let attempts = config.max_attempts.max(1);
    let mut last_divergence: Option<Divergence> = None;
    for attempt in 0..attempts {
        match run_attempt(config, root, attempt, &mut scan) {
            Ok(manifest) => return Ok(manifest),
            Err(AttemptOutcome::Diverged(divergence)) => last_divergence = Some(divergence),
            Err(AttemptOutcome::Io(io)) => return Err(CaptureError::Io(io)),
        }
    }
    Err(CaptureError::Incoherent(CaptureRefusal {
        attempts,
        last_divergence: last_divergence.unwrap_or(Divergence::DirectorySetChanged {
            added: Vec::new(),
            removed: Vec::new(),
        }),
    }))
}

enum AttemptOutcome {
    Diverged(Divergence),
    Io(CaptureIoError),
}

fn run_attempt<F>(
    config: CaptureConfig,
    root: &str,
    attempt: u32,
    scan: &mut F,
) -> Result<SnapshotManifest, AttemptOutcome>
where
    F: FnMut(u32, u32) -> Result<ScanObservation, ScanError>,
{
    let map_err = |e: ScanError| match e {
        ScanError::UnstableDuringRead { path } => {
            AttemptOutcome::Diverged(Divergence::UnstableDuringRead { path })
        }
        ScanError::Io { path, cause } => AttemptOutcome::Io(CaptureIoError { path, cause }),
    };
    let first = scan(attempt, 0).map_err(map_err)?;
    match config.fs_class {
        // A real snapshot/reflink primitive froze the tree: one scan
        // of the frozen image is authoritative by construction.
        FsSemanticClass::AtomicSnapshot | FsSemanticClass::Reflink => {
            Ok(SnapshotManifest::seal(root, config.fs_class, first.members))
        }
        FsSemanticClass::GenerationScan => {
            let second = scan(attempt, 1).map_err(map_err)?;
            match first_divergence(&first, &second) {
                None => Ok(SnapshotManifest::seal(
                    root,
                    config.fs_class,
                    second.members,
                )),
                Some(divergence) => Err(AttemptOutcome::Diverged(divergence)),
            }
        }
    }
}

/// Capture a path-dependency closure all-or-nothing: every root must
/// establish coherence or the WHOLE closure refuses (a closure mixing
/// a fresh workspace with a stale path-dep is exactly the mixed state
/// I2 forbids). Roots are `(logical_id, scanner)` pairs — logical IDs
/// per D001, never mutable checkout paths.
pub fn capture_closure<F>(
    config: CaptureConfig,
    roots: &mut [(String, F)],
) -> Result<Vec<SnapshotManifest>, (String, CaptureError)>
where
    F: FnMut(u32, u32) -> Result<ScanObservation, ScanError>,
{
    let mut manifests = Vec::with_capacity(roots.len());
    for (logical_id, scan) in roots.iter_mut() {
        match capture_coherent(config, logical_id, scan) {
            Ok(manifest) => manifests.push(manifest),
            Err(e) => return Err((logical_id.clone(), e)),
        }
    }
    Ok(manifests)
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct SealedRoot {
    manifest: SnapshotManifest,
    files: BTreeMap<String, Arc<[u8]>>,
}

/// Verified source bytes, owned independently of the mutable checkouts.
/// No mutable manifest or byte access is exposed. Clones share immutable bytes.
#[derive(Clone, PartialEq, Eq)]
pub struct SealedSourceSnapshot {
    roots: BTreeMap<String, SealedRoot>,
    digest: [u8; 32],
}

impl std::fmt::Debug for SealedSourceSnapshot {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Diagnostics must not dump potentially large/private source bytes.
        formatter
            .debug_struct("SealedSourceSnapshot")
            .field("root_count", &self.roots.len())
            .field("closure_digest", &self.digest)
            .finish_non_exhaustive()
    }
}

/// A fresh materialization owned by the caller. Execution must mount these
/// backing directories read-only; the mutable checkout is never a backing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MaterializedSource {
    roots: BTreeMap<String, (PathBuf, SnapshotProvenance)>,
}

impl MaterializedSource {
    /// Private physical backing for a captured logical root.
    #[must_use]
    pub fn backing(&self, root: &str) -> Option<&Path> {
        self.roots.get(root).map(|(path, _)| path.as_path())
    }

    /// Provenance of the bytes written to this root.
    #[must_use]
    pub fn provenance(&self, root: &str) -> Option<SnapshotProvenance> {
        self.roots
            .get(root)
            .map(|(_, provenance)| provenance.clone())
    }
}

impl SealedSourceSnapshot {
    /// Manifest of a logical root, with no mutable access.
    #[must_use]
    pub fn manifest(&self, root: &str) -> Option<&SnapshotManifest> {
        self.roots.get(root).map(|root| &root.manifest)
    }

    /// Provenance for a logical root's execution mount.
    #[must_use]
    pub fn provenance(&self, root: &str) -> Option<SnapshotProvenance> {
        self.manifest(root).map(SnapshotManifest::provenance)
    }

    /// The descriptor-read bytes accepted at the coherent boundary.
    #[must_use]
    pub fn file_bytes(&self, root: &str, path: &str) -> Option<&[u8]> {
        self.roots.get(root)?.files.get(path).map(AsRef::as_ref)
    }

    /// Identity of the complete sorted closure, not just its workspace root.
    #[must_use]
    pub const fn closure_digest(&self) -> [u8; 32] {
        self.digest
    }

    /// Write retained bytes into a NEW destination, without reading source
    /// checkouts or making hardlinks. Existing destinations are refused.
    /// A failure leaves an unpublished partial directory for caller inspection;
    /// this operation never deletes files or returns a partial handle.
    pub fn materialize_into(&self, destination: &Path) -> Result<MaterializedSource, CaptureError> {
        use std::io::Write;

        std::fs::create_dir(destination).map_err(|error| capture_io(destination, error))?;
        let mut materialized = BTreeMap::new();
        for (id, root) in &self.roots {
            let backing = destination.join(id);
            std::fs::create_dir(&backing).map_err(|error| capture_io(&backing, error))?;
            // Parents sort before descendants. Symlinks are created only AFTER
            // all directory/file writes, so they cannot redirect those writes.
            for (path, kind) in &root.manifest.members {
                let output = backing.join(path);
                match kind {
                    MemberKind::Directory => {
                        std::fs::create_dir(&output).map_err(|error| capture_io(&output, error))?;
                    }
                    MemberKind::Regular { mode, .. } => {
                        let mut file = std::fs::OpenOptions::new()
                            .write(true)
                            .create_new(true)
                            .open(&output)
                            .map_err(|error| capture_io(&output, error))?;
                        file.write_all(&root.files[path])
                            .map_err(|error| capture_io(&output, error))?;
                        set_file_mode(&file, *mode).map_err(|error| capture_io(&output, error))?;
                    }
                    MemberKind::Symlink { .. } => {}
                }
            }
            for (path, kind) in &root.manifest.members {
                if let MemberKind::Symlink { target } = kind {
                    let output = backing.join(path);
                    materialize_symlink(target, &output, &root.manifest.members, path)?;
                }
            }
            materialized.insert(id.clone(), (backing, root.manifest.provenance()));
        }
        Ok(MaterializedSource {
            roots: materialized,
        })
    }
}

#[cfg(unix)]
fn set_file_mode(file: &std::fs::File, mode: u32) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    file.set_permissions(std::fs::Permissions::from_mode(mode))
}

#[cfg(not(unix))]
fn set_file_mode(file: &std::fs::File, mode: u32) -> std::io::Result<()> {
    let mut permissions = file.metadata()?.permissions();
    permissions.set_readonly(mode & 0o222 == 0);
    file.set_permissions(permissions)
}

fn materialize_symlink(
    target: &str,
    output: &Path,
    members: &BTreeMap<String, MemberKind>,
    path: &str,
) -> Result<(), CaptureError> {
    let resolved = resolve_captured_link(members, path, target)?;
    #[cfg(unix)]
    {
        let _ = resolved;
        std::os::unix::fs::symlink(target, output).map_err(|error| capture_io(output, error))
    }
    #[cfg(windows)]
    {
        let directory =
            resolved.is_empty() || matches!(members.get(&resolved), Some(MemberKind::Directory));
        if directory {
            std::os::windows::fs::symlink_dir(target, output)
        } else {
            std::os::windows::fs::symlink_file(target, output)
        }
        .map_err(|error| capture_io(output, error))
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = (resolved, output);
        Err(reject(path, CaptureRejection::UnsupportedKind))
    }
}

fn capture_io(path: &Path, error: std::io::Error) -> CaptureError {
    CaptureError::Io(CaptureIoError {
        path: path.to_string_lossy().into_owned(),
        cause: error.to_string(),
    })
}

fn reject(path: &str, reason: CaptureRejection) -> CaptureError {
    CaptureError::Rejected {
        path: path.to_string(),
        reason,
    }
}

fn safe_component(value: &str) -> bool {
    !value.is_empty() && !matches!(value, "." | "..") && !value.contains(['/', '\\', ':', '\0'])
}

#[derive(Debug)]
struct RetainedScan {
    observation: ScanObservation,
    files: BTreeMap<String, Arc<[u8]>>,
}

/// Seal a complete path-dependency closure with paired generation scans.
/// `max_bytes` bounds the cumulative regular-file bytes in EACH closure pass;
/// at most two such passes are retained while validating an attempt. This is
/// filesystem work, not a wall-time bound on an unresponsive filesystem.
/// Absolute/escaping symlinks, special nodes and non-lossless paths are refused.
pub fn capture_sealed_source(
    roots: &[(String, PathBuf)],
    declared_git_state: bool,
    max_attempts: u32,
    max_bytes: u64,
) -> Result<SealedSourceSnapshot, CaptureError> {
    capture_sealed_source_with(
        roots,
        declared_git_state,
        max_attempts,
        max_bytes,
        |_, _| {},
    )
}

fn capture_sealed_source_with(
    roots: &[(String, PathBuf)],
    declared_git_state: bool,
    max_attempts: u32,
    max_bytes: u64,
    mut after_pass: impl FnMut(u32, u32),
) -> Result<SealedSourceSnapshot, CaptureError> {
    let mut ordered = BTreeMap::new();
    for (id, path) in roots {
        if !safe_component(id) || ordered.insert(id.clone(), path.clone()).is_some() {
            return Err(reject(id, CaptureRejection::InvalidRoot));
        }
    }
    if ordered.is_empty() {
        return Err(reject("", CaptureRejection::InvalidRoot));
    }
    let attempts = max_attempts.max(1);
    let mut last = None;
    for attempt in 0..attempts {
        let result = (|| {
            let first = scan_retained_closure(&ordered, declared_git_state, max_bytes)?;
            after_pass(attempt, 0);
            let second = scan_retained_closure(&ordered, declared_git_state, max_bytes)?;
            after_pass(attempt, 1);
            for (id, first_root) in &first {
                if let Some(divergence) =
                    first_divergence(&first_root.observation, &second[id].observation)
                {
                    return Err(CaptureError::Incoherent(CaptureRefusal {
                        attempts: attempt + 1,
                        last_divergence: divergence,
                    }));
                }
            }
            let roots: BTreeMap<_, _> = second
                .into_iter()
                .map(|(id, scan)| {
                    let manifest = SnapshotManifest::seal(
                        &id,
                        FsSemanticClass::GenerationScan,
                        scan.observation.members,
                    );
                    (
                        id,
                        SealedRoot {
                            manifest,
                            files: scan.files,
                        },
                    )
                })
                .collect();
            let mut digest = Sha256::new();
            digest.update(b"rabs.sealed-source-closure.v1\0");
            for (id, root) in &roots {
                digest.update((id.len() as u64).to_le_bytes());
                digest.update(id.as_bytes());
                digest.update(root.manifest.manifest_sha256);
            }
            Ok(SealedSourceSnapshot {
                roots,
                digest: digest.finalize().into(),
            })
        })();
        match result {
            Ok(snapshot) => return Ok(snapshot),
            Err(CaptureError::Incoherent(refusal)) => last = Some(refusal.last_divergence),
            Err(error) => return Err(error),
        }
    }
    match last {
        Some(last_divergence) => Err(CaptureError::Incoherent(CaptureRefusal {
            attempts,
            last_divergence,
        })),
        None => Err(CaptureError::Io(CaptureIoError {
            path: String::new(),
            cause: "capture ended without a scan result".to_string(),
        })),
    }
}

fn scan_retained_closure(
    roots: &BTreeMap<String, PathBuf>,
    declared_git_state: bool,
    max_bytes: u64,
) -> Result<BTreeMap<String, RetainedScan>, CaptureError> {
    let mut remaining = max_bytes;
    let mut scans = BTreeMap::new();
    for (id, root) in roots {
        let metadata = std::fs::symlink_metadata(root).map_err(|error| capture_io(root, error))?;
        if !metadata.is_dir() {
            return Err(reject(id, CaptureRejection::UnsupportedKind));
        }
        let mut scan = RetainedScan {
            observation: ScanObservation::default(),
            files: BTreeMap::new(),
        };
        #[cfg(target_os = "linux")]
        scan_retained_root(
            root,
            &metadata,
            declared_git_state,
            &mut remaining,
            &mut scan,
        )?;
        #[cfg(not(target_os = "linux"))]
        scan_retained_directory(root, "", declared_git_state, &mut remaining, &mut scan)?;
        for (path, kind) in &scan.observation.members {
            if let MemberKind::Symlink { target } = kind {
                resolve_captured_link(&scan.observation.members, path, target)?;
            }
        }
        scans.insert(id.clone(), scan);
    }
    Ok(scans)
}

#[cfg(target_os = "linux")]
fn sealed_open_error(path: &str, error: rustix::io::Errno) -> CaptureError {
    match error {
        rustix::io::Errno::XDEV => reject(path, CaptureRejection::CrossMount),
        rustix::io::Errno::LOOP => reject(path, CaptureRejection::UnsafeSymlink),
        rustix::io::Errno::AGAIN | rustix::io::Errno::NOENT => sealed_unstable(path),
        // ENOSYS / EINVAL / permission failures are refusals, not permission
        // to fall back to an unconfined pathname traversal.
        error => capture_io(Path::new(path), std::io::Error::from(error)),
    }
}

#[cfg(target_os = "linux")]
fn sealed_unstable(path: &str) -> CaptureError {
    CaptureError::Incoherent(CaptureRefusal {
        attempts: 0,
        last_divergence: Divergence::UnstableDuringRead {
            path: path.to_string(),
        },
    })
}

#[cfg(target_os = "linux")]
fn open_sealed_entry(
    root: &std::fs::File,
    relative: &str,
    flags: rustix::fs::OFlags,
) -> Result<std::fs::File, CaptureError> {
    use rustix::fs::{Mode, ResolveFlags, openat2};
    openat2(
        root,
        relative,
        flags,
        Mode::empty(),
        ResolveFlags::BENEATH | ResolveFlags::NO_SYMLINKS | ResolveFlags::NO_XDEV,
    )
    .map(std::fs::File::from)
    .map_err(|error| sealed_open_error(relative, error))
}

#[cfg(target_os = "linux")]
fn scan_retained_root(
    path: &Path,
    observed: &std::fs::Metadata,
    declared_git_state: bool,
    remaining: &mut u64,
    scan: &mut RetainedScan,
) -> Result<(), CaptureError> {
    use rustix::fs::{CWD, Mode, OFlags, ResolveFlags, openat2};

    // The explicit root is the trust boundary. Ordinary ancestor aliases (e.g.
    // /dp -> /data/projects) remain valid; a leaf symlink and proc magic links
    // do not. Descendants use stricter resolution from this anchored descriptor.
    let root = openat2(
        CWD,
        path,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
        ResolveFlags::NO_MAGICLINKS,
    )
    .map(std::fs::File::from)
    .map_err(|error| sealed_open_error(&path.to_string_lossy(), error))?;
    let before = root.metadata().map_err(|error| capture_io(path, error))?;
    if identity_of(observed) != identity_of(&before) {
        return Err(sealed_unstable(""));
    }
    scan_retained_directory_fd(&root, &root, "", declared_git_state, remaining, scan)?;
    let after = root.metadata().map_err(|error| capture_io(path, error))?;
    if identity_of(&before) != identity_of(&after) {
        return Err(sealed_unstable(""));
    }
    // Empty relative name is reserved for the root's local mutation evidence;
    // it is never a manifest member or a portable identity input.
    scan.observation
        .identities
        .insert(String::new(), identity_of(&after));
    Ok(())
}

#[cfg(target_os = "linux")]
fn scan_retained_directory_fd(
    root: &std::fs::File,
    directory: &std::fs::File,
    relative: &str,
    declared_git_state: bool,
    remaining: &mut u64,
    scan: &mut RetainedScan,
) -> Result<(), CaptureError> {
    use rustix::fs::{Dir, OFlags, readlinkat};

    let before = directory
        .metadata()
        .map_err(|error| capture_io(Path::new(relative), error))?;
    let mut entries =
        Dir::read_from(directory).map_err(|error| sealed_open_error(relative, error))?;
    while let Some(entry) = entries.read() {
        let entry = entry.map_err(|error| sealed_open_error(relative, error))?;
        let name = entry.file_name();
        if matches!(name.to_bytes(), b"." | b"..") {
            continue;
        }
        let name = name
            .to_str()
            .ok()
            .filter(|name| safe_component(name))
            .ok_or_else(|| reject(relative, CaptureRejection::InvalidPath))?;
        let rel = if relative.is_empty() {
            name.to_string()
        } else {
            format!("{relative}/{name}")
        };
        if member_disposition(&rel, declared_git_state) != MemberDisposition::Include {
            continue;
        }
        // O_PATH inspects special files without opening them for I/O. With
        // NOFOLLOW, openat2 permits the terminal symlink itself as a descriptor.
        let entry_flags = OFlags::PATH | OFlags::NOFOLLOW | OFlags::CLOEXEC;
        let observed = open_sealed_entry(root, &rel, entry_flags)?;
        let metadata = observed
            .metadata()
            .map_err(|error| capture_io(Path::new(&rel), error))?;
        let member = if metadata.file_type().is_symlink() {
            let target = readlinkat(&observed, "", Vec::new())
                .map_err(|error| sealed_open_error(&rel, error))?;
            let target = target
                .to_str()
                .map_err(|_| reject(&rel, CaptureRejection::InvalidPath))?;
            MemberKind::Symlink {
                target: target.to_string(),
            }
        } else if metadata.is_dir() {
            let child = open_sealed_entry(
                root,
                &rel,
                OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            )?;
            let child_metadata = child
                .metadata()
                .map_err(|error| capture_io(Path::new(&rel), error))?;
            if identity_of(&metadata) != identity_of(&child_metadata) {
                return Err(sealed_unstable(&rel));
            }
            scan_retained_directory_fd(root, &child, &rel, declared_git_state, remaining, scan)?;
            MemberKind::Directory
        } else if metadata.is_file() {
            let file = open_sealed_entry(
                root,
                &rel,
                OFlags::RDONLY
                    | OFlags::NONBLOCK
                    | OFlags::NOCTTY
                    | OFlags::NOFOLLOW
                    | OFlags::CLOEXEC,
            )?;
            let (member, bytes) = read_retained_descriptor(
                file,
                Path::new(&rel),
                &rel,
                &metadata,
                remaining,
                |_| {},
            )?;
            scan.files.insert(rel.clone(), bytes.into());
            member
        } else {
            return Err(reject(&rel, CaptureRejection::UnsupportedKind));
        };
        // Re-resolve through the root even after descriptor reads: a rename or
        // mount substitution must not leave a retired inode in the sealed tree.
        let current = open_sealed_entry(root, &rel, entry_flags)?;
        let after = current
            .metadata()
            .map_err(|error| capture_io(Path::new(&rel), error))?;
        if identity_of(&metadata) != identity_of(&after) {
            return Err(sealed_unstable(&rel));
        }
        scan.observation
            .identities
            .insert(rel.clone(), identity_of(&after));
        scan.observation.members.insert(rel, member);
    }
    let after = directory
        .metadata()
        .map_err(|error| capture_io(Path::new(relative), error))?;
    if identity_of(&before) != identity_of(&after) {
        return Err(sealed_unstable(relative));
    }
    Ok(())
}

// Other platforms retain the path-based scanner. They do not claim Linux's
// descriptor-relative symlink and mount-boundary guarantees.
#[cfg(not(target_os = "linux"))]
fn scan_retained_directory(
    directory: &Path,
    relative: &str,
    declared_git_state: bool,
    remaining: &mut u64,
    scan: &mut RetainedScan,
) -> Result<(), CaptureError> {
    let entries = std::fs::read_dir(directory).map_err(|error| capture_io(directory, error))?;
    for entry in entries {
        let entry = entry.map_err(|error| capture_io(directory, error))?;
        let name = entry.file_name();
        let name = name
            .to_str()
            .filter(|name| safe_component(name))
            .ok_or_else(|| reject(relative, CaptureRejection::InvalidPath))?;
        let path = entry.path();
        let rel = if relative.is_empty() {
            name.to_string()
        } else {
            format!("{relative}/{name}")
        };
        if member_disposition(&rel, declared_git_state) != MemberDisposition::Include {
            continue;
        }
        let metadata =
            std::fs::symlink_metadata(&path).map_err(|error| capture_io(&path, error))?;
        let member = if metadata.file_type().is_symlink() {
            let target = std::fs::read_link(&path).map_err(|error| capture_io(&path, error))?;
            let target = target
                .to_str()
                .ok_or_else(|| reject(&rel, CaptureRejection::InvalidPath))?;
            MemberKind::Symlink {
                target: target.to_string(),
            }
        } else if metadata.is_dir() {
            scan_retained_directory(&path, &rel, declared_git_state, remaining, scan)?;
            MemberKind::Directory
        } else if metadata.is_file() {
            let (member, bytes) = read_retained_file(&path, &rel, &metadata, remaining)?;
            scan.files.insert(rel.clone(), bytes.into());
            member
        } else {
            return Err(reject(&rel, CaptureRejection::UnsupportedKind));
        };
        let after = std::fs::symlink_metadata(&path).map_err(|error| capture_io(&path, error))?;
        if identity_of(&metadata) != identity_of(&after) {
            return Err(CaptureError::Incoherent(CaptureRefusal {
                attempts: 0,
                last_divergence: Divergence::UnstableDuringRead { path: rel },
            }));
        }
        scan.observation
            .identities
            .insert(rel.clone(), identity_of(&after));
        scan.observation.members.insert(rel, member);
    }
    Ok(())
}

#[cfg(any(not(target_os = "linux"), test))]
fn read_retained_file(
    path: &Path,
    relative: &str,
    observed: &std::fs::Metadata,
    remaining: &mut u64,
) -> Result<(MemberKind, Vec<u8>), CaptureError> {
    read_retained_file_with(path, relative, observed, remaining, |_| {})
}

#[cfg(any(not(target_os = "linux"), test))]
fn read_retained_file_with(
    path: &Path,
    relative: &str,
    observed: &std::fs::Metadata,
    remaining: &mut u64,
    after_chunk: impl FnMut(usize),
) -> Result<(MemberKind, Vec<u8>), CaptureError> {
    let file = std::fs::File::open(path).map_err(|error| capture_io(path, error))?;
    read_retained_descriptor(file, path, relative, observed, remaining, after_chunk)
}

fn read_retained_descriptor(
    mut file: std::fs::File,
    path: &Path,
    relative: &str,
    observed: &std::fs::Metadata,
    remaining: &mut u64,
    mut after_chunk: impl FnMut(usize),
) -> Result<(MemberKind, Vec<u8>), CaptureError> {
    use std::io::Read;
    let unstable = || {
        CaptureError::Incoherent(CaptureRefusal {
            attempts: 0,
            last_divergence: Divergence::UnstableDuringRead {
                path: relative.to_string(),
            },
        })
    };
    if observed.len() > *remaining {
        return Err(reject(relative, CaptureRejection::ByteLimitExceeded));
    }
    let before = file.metadata().map_err(|error| capture_io(path, error))?;
    if !before.is_file() || identity_of(observed) != identity_of(&before) {
        return Err(unstable());
    }
    let mut bytes = Vec::new();
    let mut buffer = [0u8; 64 * 1024];
    loop {
        let count = file
            .read(&mut buffer)
            .map_err(|error| capture_io(path, error))?;
        if count == 0 {
            break;
        }
        if count as u64 > *remaining {
            return Err(reject(relative, CaptureRejection::ByteLimitExceeded));
        }
        *remaining -= count as u64;
        bytes.extend_from_slice(&buffer[..count]);
        after_chunk(count);
    }
    let after = file.metadata().map_err(|error| capture_io(path, error))?;
    if identity_of(&before) != identity_of(&after)
        || before.len() != after.len()
        || bytes.len() as u64 != after.len()
        || mode_of(&before) != mode_of(&after)
    {
        return Err(unstable());
    }
    let member = MemberKind::Regular {
        size: after.len(),
        inode: inode_of(&after),
        mtime_ns: mtime_ns_of(&after),
        content_sha256: Sha256::digest(&bytes).into(),
        mode: mode_of(&after),
    };
    Ok((member, bytes))
}

/// Resolve links against the captured tree, including chained links and `..`
/// after a link expansion. Lexical normalization alone would permit escapes.
fn resolve_captured_link(
    members: &BTreeMap<String, MemberKind>,
    path: &str,
    target: &str,
) -> Result<String, CaptureError> {
    use std::collections::VecDeque;
    let invalid = || reject(path, CaptureRejection::UnsafeSymlink);
    let mut resolved: Vec<String> = path.split('/').map(str::to_string).collect();
    resolved.pop();
    let mut pending: VecDeque<String> = target.split('/').map(str::to_string).collect();
    let mut links = 0;
    if Path::new(target).is_absolute() || target.contains(['\\', ':']) {
        return Err(invalid());
    }
    while let Some(component) = pending.pop_front() {
        match component.as_str() {
            "" | "." => continue,
            ".." => {
                resolved.pop().ok_or_else(invalid)?;
            }
            _ => {
                resolved.push(component);
                let current = resolved.join("/");
                match members.get(&current) {
                    Some(MemberKind::Symlink { target }) => {
                        links += 1;
                        if links > 40
                            || Path::new(target).is_absolute()
                            || target.contains(['\\', ':'])
                        {
                            return Err(invalid());
                        }
                        resolved.pop();
                        for component in target.split('/').rev() {
                            pending.push_front(component.to_string());
                        }
                    }
                    Some(MemberKind::Directory) => {}
                    Some(MemberKind::Regular { .. }) if pending.is_empty() => {}
                    _ => return Err(invalid()),
                }
            }
        }
    }
    Ok(resolved.join("/"))
}

/// Membership disposition for one repo-relative path.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MemberDisposition {
    /// Part of the snapshot.
    Include,
    /// Mutable build output (`target/` subtree) — never captured.
    ExcludeBuildOutput,
    /// Ephemeral lock/cache droppings — never captured.
    ExcludeEphemeralLock,
    /// `.git` hidden: no canonical git-state object was declared.
    HiddenGitState,
    /// Refused by the E027 source-capture policy (credential and key
    /// locations, or a project-declared non-uploadable class).
    ///
    /// A distinct disposition rather than a silent drop: what did NOT
    /// leave the machine is exactly the thing an operator needs to be
    /// able to see, and a capture that quietly omitted files would be
    /// indistinguishable from one that lost them.
    ExcludeSecretPolicy,
}

/// Names that are always-include even when untracked/ignored: the
/// build-identity files the bead enumerates (lockfile, `.cargo`
/// configuration, toolchain files).
const ALWAYS_INCLUDE: &[&str] = &[
    "Cargo.lock",
    ".cargo/config.toml",
    ".cargo/config",
    "rust-toolchain.toml",
    "rust-toolchain",
];

/// Ephemeral lock/cache file names (never the identity-bearing
/// `Cargo.lock`, which is in the always-include set).
fn is_ephemeral_lock(rel_path: &str) -> bool {
    let name = rel_path.rsplit('/').next().unwrap_or(rel_path);
    name == ".package-cache"
        || name == ".rustc_info.json"
        || name == "CACHEDIR.TAG"
        || (name.ends_with(".lock") && name != "Cargo.lock")
}

/// Classify one repo-relative path for snapshot membership.
/// `declared_git_state` is whether a canonical git-state object was
/// declared for this capture (D031); without it `.git` stays hidden.
#[must_use]
pub fn member_disposition(rel_path: &str, declared_git_state: bool) -> MemberDisposition {
    // E027 source-capture policy is consulted FIRST, ahead of the
    // always-include set. This is the boundary where bytes leave the
    // developer's machine, and `source_capture`'s own doctrine is that
    // structural refusals dominate configuration — a build-identity
    // file is not a reason to upload a credential.
    //
    // Only `BuildInputAllowed` may be captured. Every other class means
    // "not uploadable": `Denied` and `SecretCapability` are credential
    // locations, `LocalOnly` and `ExplicitOperatorApproval` are paths
    // the project declared non-portable. Erring toward exclusion is
    // right here — a false positive costs an action its remote
    // execution, a false negative ships a secret to a worker.
    //
    // SCOPE, stated rather than implied: this applies the NAME-based
    // policy only. `PathShape::REGULAR` is passed because membership is
    // decided from a relative path with no filesystem facts attached;
    // the structural refusals (symlink escape, device/socket nodes,
    // unrelated ancestors) remain the scanner's own job, which it
    // already does — symlinks are recorded and never followed, and
    // paths outside the root are refused. `configured` is `None`
    // because no project policy file is plumbed here yet, so only the
    // built-in seed set applies; a project that wants to declare extra
    // classes has nowhere to say so, which is a real follow-up.
    if !matches!(
        crate::source_capture::classify_path(
            rel_path.as_bytes(),
            crate::source_capture::PathShape::REGULAR,
            None,
        ),
        crate::source_capture::SourceCapturePolicy::BuildInputAllowed
    ) {
        return MemberDisposition::ExcludeSecretPolicy;
    }
    if ALWAYS_INCLUDE.contains(&rel_path) {
        return MemberDisposition::Include;
    }
    if rel_path == ".git" || rel_path.starts_with(".git/") {
        return if declared_git_state {
            MemberDisposition::Include
        } else {
            MemberDisposition::HiddenGitState
        };
    }
    if rel_path == "target" || rel_path.starts_with("target/") {
        return MemberDisposition::ExcludeBuildOutput;
    }
    if is_ephemeral_lock(rel_path) {
        return MemberDisposition::ExcludeEphemeralLock;
    }
    MemberDisposition::Include
}

/// Real-filesystem scan of `root`, honoring [`member_disposition`]:
/// every regular file is read through an OPEN descriptor — fstat the
/// descriptor, hash the bytes, fstat again, and any identity/size/
/// mtime movement between the two is [`ScanError::UnstableDuringRead`]
/// (I2's descriptor-verified read). Symlinks are recorded, never
/// followed. Paths are recorded relative with `/` separators.
pub fn scan_directory(
    root: &std::path::Path,
    declared_git_state: bool,
) -> Result<ScanObservation, ScanError> {
    let mut observation = ScanObservation::default();
    let mut pending: Vec<std::path::PathBuf> = vec![root.to_path_buf()];
    while let Some(dir) = pending.pop() {
        let entries = std::fs::read_dir(&dir).map_err(|e| ScanError::Io {
            path: dir.to_string_lossy().into_owned(),
            cause: e.to_string(),
        })?;
        for entry in entries {
            let entry = entry.map_err(|e| ScanError::Io {
                path: dir.to_string_lossy().into_owned(),
                cause: e.to_string(),
            })?;
            let path = entry.path();
            let rel = path
                .strip_prefix(root)
                .expect("walk stays under root")
                .to_string_lossy()
                .replace(std::path::MAIN_SEPARATOR, "/");
            if member_disposition(&rel, declared_git_state) != MemberDisposition::Include {
                continue;
            }
            let meta = std::fs::symlink_metadata(&path).map_err(|e| ScanError::Io {
                path: rel.clone(),
                cause: e.to_string(),
            })?;
            observation
                .identities
                .insert(rel.clone(), identity_of(&meta));
            if meta.file_type().is_symlink() {
                let target = std::fs::read_link(&path).map_err(|e| ScanError::Io {
                    path: rel.clone(),
                    cause: e.to_string(),
                })?;
                observation.members.insert(
                    rel,
                    MemberKind::Symlink {
                        target: target.to_string_lossy().into_owned(),
                    },
                );
            } else if meta.is_dir() {
                observation.members.insert(rel, MemberKind::Directory);
                pending.push(path);
            } else {
                observation
                    .members
                    .insert(rel.clone(), read_regular_via_descriptor(&path, &rel)?);
            }
        }
    }
    Ok(observation)
}

fn read_regular_via_descriptor(path: &std::path::Path, rel: &str) -> Result<MemberKind, ScanError> {
    use std::io::Read;
    let mut file = std::fs::File::open(path).map_err(|e| ScanError::Io {
        path: rel.to_string(),
        cause: e.to_string(),
    })?;
    let io_err = |e: std::io::Error| ScanError::Io {
        path: rel.to_string(),
        cause: e.to_string(),
    };
    let before = file.metadata().map_err(io_err)?;
    let mut hasher = Sha256::new();
    let mut buf = [0u8; 64 * 1024];
    let mut total: u64 = 0;
    loop {
        let n = file.read(&mut buf).map_err(io_err)?;
        if n == 0 {
            break;
        }
        total += n as u64;
        hasher.update(&buf[..n]);
    }
    let after = file.metadata().map_err(io_err)?;
    let (before_id, after_id) = (identity_of(&before), identity_of(&after));
    if before_id != after_id
        || before.len() != after.len()
        || total != after.len()
        || mode_of(&before) != mode_of(&after)
    {
        return Err(ScanError::UnstableDuringRead {
            path: rel.to_string(),
        });
    }
    Ok(MemberKind::Regular {
        size: after.len(),
        inode: inode_of(&after),
        mtime_ns: mtime_ns_of(&after),
        content_sha256: hasher.finalize().into(),
        mode: mode_of(&after),
    })
}

#[cfg(unix)]
fn mode_of(meta: &std::fs::Metadata) -> u32 {
    use std::os::unix::fs::PermissionsExt;
    meta.permissions().mode() & 0o777
}

#[cfg(not(unix))]
fn mode_of(meta: &std::fs::Metadata) -> u32 {
    if meta.permissions().readonly() {
        0o444
    } else {
        0o666
    }
}

/// Descriptor identity and mutation metadata verified around a read.
/// Unix change time detects writes whose original mtime was restored; device
/// identity prevents an equal inode number on another filesystem from matching.
#[derive(Debug, Clone, PartialEq, Eq)]
struct FileIdentity {
    inode: u64,
    device: u64,
    mtime_ns: u128,
    ctime_secs: i64,
    ctime_ns: i64,
}

fn identity_of(meta: &std::fs::Metadata) -> FileIdentity {
    #[cfg(unix)]
    let (device, ctime_secs, ctime_ns) = {
        use std::os::unix::fs::MetadataExt;
        (meta.dev(), meta.ctime(), meta.ctime_nsec())
    };
    #[cfg(not(unix))]
    let (device, ctime_secs, ctime_ns) = (0, 0, 0);
    FileIdentity {
        inode: inode_of(meta),
        device,
        mtime_ns: mtime_ns_of(meta),
        ctime_secs,
        ctime_ns,
    }
}

#[cfg(unix)]
fn inode_of(meta: &std::fs::Metadata) -> u64 {
    use std::os::unix::fs::MetadataExt;
    meta.ino()
}

#[cfg(not(unix))]
fn inode_of(_meta: &std::fs::Metadata) -> u64 {
    0
}

fn mtime_ns_of(meta: &std::fs::Metadata) -> u128 {
    meta.modified()
        .ok()
        .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
        .map_or(0, |d| d.as_nanos())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(unix)]
    #[test]
    fn real_ancestor_alias_and_internal_relative_link_remain_supported() {
        let retained = tempfile::tempdir().unwrap().keep();
        let actual = retained.join("actual");
        let root = actual.join("project");
        std::fs::create_dir_all(root.join("src")).unwrap();
        std::fs::write(root.join("src/input"), b"source via alias").unwrap();
        std::os::unix::fs::symlink("src/input", root.join("link")).unwrap();
        let alias = retained.join("alias");
        std::os::unix::fs::symlink(&actual, &alias).unwrap();
        let image = capture_sealed_source(
            &[("workspace".to_string(), alias.join("project"))],
            false,
            2,
            1024,
        )
        .unwrap();
        assert_eq!(
            image.file_bytes("workspace", "src/input"),
            Some(b"source via alias".as_slice())
        );
        let output = image
            .materialize_into(&retained.join("materialized"))
            .unwrap();
        assert_eq!(
            std::fs::read(output.backing("workspace").unwrap().join("link")).unwrap(),
            b"source via alias"
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    #[ignore = "requires privilege to create a private mount namespace; run explicitly on an authorized worker"]
    fn private_mount_namespace_refuses_bind_mounted_members() {
        const CHILD_ROOT: &str = "RABS_BIND_TEST_CHILD_ROOT";
        if let Some(root) = std::env::var_os(CHILD_ROOT) {
            let root = PathBuf::from(root);
            // Prove the real bind mount succeeded before exercising capture.
            assert_eq!(
                std::fs::read(root.join("mounted/secret")).unwrap(),
                b"external bytes"
            );
            let result = capture_sealed_source(&[("workspace".to_string(), root)], false, 2, 1024);
            assert!(
                matches!(result, Err(CaptureError::Rejected { .. })),
                "bind mount must be refused, got {result:?}"
            );
            assert!(matches!(
                result,
                Err(CaptureError::Rejected {
                    reason: CaptureRejection::CrossMount,
                    ..
                })
            ));
            return;
        }
        let retained = tempfile::tempdir().unwrap().keep();
        let root = retained.join("source");
        let outside = retained.join("outside");
        std::fs::create_dir_all(root.join("mounted")).unwrap();
        std::fs::create_dir(&outside).unwrap();
        std::fs::write(outside.join("secret"), b"external bytes").unwrap();
        std::fs::write(root.join("local"), b"safe source").unwrap();
        let normal =
            capture_sealed_source(&[("workspace".to_string(), root.clone())], false, 2, 1024)
                .unwrap();
        assert_eq!(
            normal.file_bytes("workspace", "local"),
            Some(b"safe source".as_slice())
        );
        let output = std::process::Command::new("unshare")
            .args(["--mount", "--propagation", "private", "sh", "-c"])
            .arg("set -eu; mount --bind \"$1\" \"$2\"; exec \"$3\" --exact snapshot_capture::tests::private_mount_namespace_refuses_bind_mounted_members --ignored --nocapture")
            .arg("rch-private-bind-test")
            .arg(&outside)
            .arg(root.join("mounted"))
            .arg(std::env::current_exe().unwrap())
            .env(CHILD_ROOT, &root)
            .output()
            .unwrap();
        std::fs::write(retained.join("child.stdout"), &output.stdout).unwrap();
        std::fs::write(retained.join("child.stderr"), &output.stderr).unwrap();
        assert!(
            output.status.success(),
            "private mount child failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        // Namespace teardown leaves the parent's source tree unchanged.
        assert!(!root.join("mounted/secret").exists());
        eprintln!(
            "retained private bind-mount fixture: {}",
            retained.display()
        );
    }

    #[cfg(unix)]
    #[test]
    fn restored_mtime_write_between_observation_and_open_is_refused() {
        let dir = tempfile::tempdir().unwrap().keep();
        let path = dir.join("input.rs");
        std::fs::write(&path, b"original source").unwrap();
        let observed = std::fs::metadata(&path).unwrap();
        // Same inode, size and mtime: only change time exposes this real write.
        std::thread::sleep(std::time::Duration::from_millis(5));
        std::fs::write(&path, b"modified source").unwrap();
        std::fs::File::options()
            .write(true)
            .open(&path)
            .unwrap()
            .set_modified(observed.modified().unwrap())
            .unwrap();
        let mut budget = 1024;
        let result = read_retained_file(&path, "input.rs", &observed, &mut budget);
        assert!(
            matches!(result, Err(CaptureError::Incoherent(_))),
            "a real intervening write must be refused even when mtime is restored: {result:?}"
        );
        eprintln!(
            "retained restored-mtime mutation fixture: {}",
            dir.display()
        );
    }

    #[cfg(unix)]
    #[test]
    fn real_mid_read_write_with_restored_mtime_refuses_hybrid_bytes() {
        use std::io::{Seek, Write};
        let retained = tempfile::tempdir().unwrap().keep();
        let path = retained.join("input");
        let original = vec![b'A'; 192 * 1024];
        std::fs::write(&path, &original).unwrap();
        let observed = std::fs::metadata(&path).unwrap();
        let mut budget = original.len() as u64;
        let mut chunks = 0;
        let mut first_chunk = 0;
        // Schedule a real write after the first descriptor read. This controls
        // interleaving only: the scanner still reads and stats the actual file.
        // Writer changes prefix first, then suffix. A-prefix/B-suffix NEVER
        // exists on disk, but a reader missing the mutation would return it.
        let result = read_retained_file_with(&path, "input", &observed, &mut budget, |count| {
            chunks += 1;
            if chunks == 1 {
                first_chunk = count;
                std::thread::sleep(std::time::Duration::from_millis(5));
                let mut writer = std::fs::File::options().write(true).open(&path).unwrap();
                writer.rewind().unwrap();
                writer.write_all(&vec![b'B'; first_chunk]).unwrap();
                writer
                    .write_all(&vec![b'B'; original.len() - first_chunk])
                    .unwrap();
                writer.set_modified(observed.modified().unwrap()).unwrap();
            }
        });
        assert!(chunks >= 3, "mutation must occur during a multi-chunk read");
        assert!(first_chunk > 0 && first_chunk <= 64 * 1024);
        if let Ok((_, bytes)) = &result {
            assert!(bytes[..first_chunk].iter().all(|byte| *byte == b'A'));
            assert!(bytes[first_chunk..].iter().all(|byte| *byte == b'B'));
            panic!(
                "accepted hybrid that never existed: first_chunk={first_chunk}, total={}",
                bytes.len()
            );
        }
        assert!(
            matches!(result, Err(CaptureError::Incoherent(_))),
            "must refuse a hybrid image that never existed: {result:?}"
        );
        assert_eq!(std::fs::read(&path).unwrap(), vec![b'B'; original.len()]);
        eprintln!(
            "retained real mid-read mutation fixture: {}, first_chunk={first_chunk}",
            retained.display()
        );
    }

    #[test]
    fn generated_real_tree_mutations_retry_the_entire_closure() {
        let retained = tempfile::tempdir().unwrap().keep();
        // Deterministic generated orders exercise both in-place writes with
        // restored mtimes and rename-based inode replacement, on real files.
        for seed in 0..32_usize {
            let root = retained.join(format!("case-{seed}"));
            std::fs::create_dir(&root).unwrap();
            let mut files = Vec::new();
            for index in 0..4 {
                let path = root.join(format!("file-{index}"));
                std::fs::write(&path, b"generation-A").unwrap();
                files.push(path);
            }
            let roots = vec![("workspace".to_string(), root.clone())];
            let mut passes = Vec::new();
            let image = capture_sealed_source_with(&roots, false, 2, 1024, |attempt, pass| {
                passes.push((attempt, pass));
                if attempt == 0 && pass == 0 {
                    for offset in 0..4 {
                        let index = (offset + seed) % 4;
                        let path = &files[index];
                        if (seed >> index) & 1 == 0 {
                            let modified = std::fs::metadata(path).unwrap().modified().unwrap();
                            std::fs::write(path, b"generation-B").unwrap();
                            std::fs::File::options()
                                .write(true)
                                .open(path)
                                .unwrap()
                                .set_modified(modified)
                                .unwrap();
                        } else {
                            // Keep the replaced file outside the captured root;
                            // no fixture cleanup can mask a missing member.
                            let old = retained.join(format!("old-{seed}-{index}"));
                            std::fs::rename(path, old).unwrap();
                            std::fs::write(path, b"generation-B").unwrap();
                        }
                    }
                }
            })
            .unwrap();
            assert_eq!(passes, [(0, 0), (0, 1), (1, 0), (1, 1)], "seed={seed}");
            for index in 0..4 {
                assert_eq!(
                    image.file_bytes("workspace", &format!("file-{index}")),
                    Some(b"generation-B".as_slice()),
                    "seed={seed} member={index} must come from the accepted pass"
                );
            }
        }
        eprintln!(
            "retained generated mutation fixtures: {}",
            retained.display()
        );
    }

    #[cfg(unix)]
    #[test]
    fn real_write_restore_between_passes_invalidates_the_observation() {
        let retained = tempfile::tempdir().unwrap().keep();
        let root = retained.join("source");
        std::fs::create_dir(&root).unwrap();
        let path = root.join("input");
        std::fs::write(&path, b"generation-A").unwrap();
        let modified = std::fs::metadata(&path).unwrap().modified().unwrap();
        let initial = scan_directory(&root, false).unwrap();
        let mut passes = Vec::new();
        let image = capture_sealed_source_with(
            &[("workspace".to_string(), root.clone())],
            false,
            2,
            1024,
            |attempt, pass| {
                passes.push((attempt, pass));
                if attempt == 0 && pass == 0 {
                    std::thread::sleep(std::time::Duration::from_millis(5));
                    std::fs::write(&path, b"generation-B").unwrap();
                    std::fs::write(&path, b"generation-A").unwrap();
                    std::fs::File::options()
                        .write(true)
                        .open(&path)
                        .unwrap()
                        .set_modified(modified)
                        .unwrap();
                }
            },
        )
        .unwrap();
        assert_eq!(passes, [(0, 0), (0, 1), (1, 0), (1, 1)]);
        let final_scan = scan_directory(&root, false).unwrap();
        assert!(matches!(
            first_divergence(&initial, &final_scan),
            Some(Divergence::MetadataInconsistent { .. })
        ));
        // Local change-time evidence must not perturb portable source identity
        // when the accepted bytes and semantic metadata are unchanged.
        assert_eq!(
            SnapshotManifest::seal(
                "workspace",
                FsSemanticClass::GenerationScan,
                initial.members
            )
            .manifest_sha256,
            SnapshotManifest::seal(
                "workspace",
                FsSemanticClass::GenerationScan,
                final_scan.members
            )
            .manifest_sha256
        );
        assert_eq!(
            image.file_bytes("workspace", "input"),
            Some(b"generation-A".as_slice())
        );
    }

    #[cfg(unix)]
    #[test]
    fn real_directory_swap_to_escaping_symlink_never_seals_external_bytes() {
        let retained = tempfile::tempdir().unwrap().keep();
        let outside = retained.join("outside");
        std::fs::create_dir(&outside).unwrap();
        std::fs::write(outside.join("secret"), b"must not enter snapshot").unwrap();
        for index in 0..2 {
            let root = retained.join(format!("root-{index}"));
            let child = root.join("src");
            std::fs::create_dir_all(&child).unwrap();
            std::fs::write(child.join("safe"), b"workspace source").unwrap();
            let target = if index % 2 == 0 {
                outside.clone()
            } else {
                PathBuf::from("../outside")
            };
            let error = capture_sealed_source_with(
                &[("workspace".to_string(), root.clone())],
                false,
                2,
                1024,
                |attempt, pass| {
                    if attempt == 0 && pass == 0 {
                        std::fs::rename(&child, retained.join(format!("old-src-{index}"))).unwrap();
                        std::os::unix::fs::symlink(&target, &child).unwrap();
                    }
                },
            )
            .unwrap_err();
            assert!(
                matches!(
                    error,
                    CaptureError::Rejected {
                        reason: CaptureRejection::UnsafeSymlink,
                        ..
                    }
                ),
                "case={index} must refuse path escape: {error:?}"
            );
        }
        eprintln!("retained path-escape fixtures: {}", retained.display());
    }

    #[test]
    fn sealed_closure_retries_all_roots_after_between_pass_mutation() {
        let dir = tempfile::tempdir().unwrap();
        let a = dir.path().join("a");
        let b = dir.path().join("b");
        std::fs::create_dir(&a).unwrap();
        std::fs::create_dir(&b).unwrap();
        std::fs::write(a.join("file"), "a-old").unwrap();
        std::fs::write(b.join("file"), "b-old").unwrap();
        let roots = vec![("a".into(), a.clone()), ("b".into(), b.clone())];
        let mut passes = Vec::new();
        let image = capture_sealed_source_with(&roots, false, 3, 100, |attempt, pass| {
            passes.push((attempt, pass));
            if attempt == 0 && pass == 0 {
                // Mutation happens after BOTH roots' first scans. A loop
                // independently sealing each root cannot establish this pair.
                std::fs::write(a.join("file"), "a-new").unwrap();
                std::fs::write(b.join("file"), "b-new").unwrap();
                std::fs::write(b.join("added"), "new member").unwrap();
            }
        })
        .unwrap();
        assert_eq!(passes, [(0, 0), (0, 1), (1, 0), (1, 1)]);
        assert_eq!(image.file_bytes("a", "file"), Some(b"a-new".as_slice()));
        assert_eq!(image.file_bytes("b", "file"), Some(b"b-new".as_slice()));
        assert_eq!(
            image.file_bytes("b", "added"),
            Some(b"new member".as_slice())
        );
        // Retained bytes, not a second filesystem lookup, feed execution.
        std::fs::write(a.join("file"), "a-later").unwrap();
        let materialized = image.materialize_into(&dir.path().join("image")).unwrap();
        assert_eq!(
            std::fs::read(materialized.backing("a").unwrap().join("file")).unwrap(),
            b"a-new"
        );
    }

    #[test]
    fn sealed_closure_refuses_sustained_mutation_in_one_dependency() {
        let dir = tempfile::tempdir().unwrap();
        let a = dir.path().join("a");
        let b = dir.path().join("b");
        std::fs::create_dir(&a).unwrap();
        std::fs::create_dir(&b).unwrap();
        std::fs::write(a.join("file"), "quiet workspace").unwrap();
        std::fs::write(b.join("file"), "dependency-initial").unwrap();
        let roots = vec![("a".into(), a), ("b".into(), b.clone())];
        let mut mutations = 0;
        let error = capture_sealed_source_with(&roots, false, 3, 100, |attempt, pass| {
            if pass == 0 {
                mutations += 1;
                std::fs::write(b.join("file"), format!("dependency-{attempt}")).unwrap();
            }
        })
        .unwrap_err();
        assert_eq!(mutations, 3);
        assert!(matches!(
            error,
            CaptureError::Incoherent(CaptureRefusal { attempts: 3, .. })
        ));
    }

    fn hash_of(gen_marker: u64, path: &str) -> [u8; 32] {
        let mut h = Sha256::new();
        h.update(gen_marker.to_le_bytes());
        h.update(path.as_bytes());
        h.finalize().into()
    }

    /// A simulated tree where every file's content hash is derived
    /// from the generation that last wrote it — a manifest mixing
    /// generations is therefore mechanically detectable.
    fn scan_of(files: &[(&str, u64, u64)]) -> ScanObservation {
        let mut members = BTreeMap::new();
        for (path, generation, inode) in files {
            members.insert(
                (*path).to_string(),
                MemberKind::Regular {
                    size: 100,
                    inode: *inode,
                    mtime_ns: u128::from(*generation),
                    content_sha256: hash_of(*generation, path),
                    mode: 0o644,
                },
            );
        }
        ScanObservation {
            members,
            ..ScanObservation::default()
        }
    }

    #[test]
    fn quiet_tree_captures_on_the_first_attempt() {
        let scans = scan_of(&[("src/lib.rs", 1, 10), ("Cargo.lock", 1, 11)]);
        let manifest = capture_coherent(
            CaptureConfig::generation_scan(),
            "workspace",
            |_attempt, _pass| Ok(scans.clone()),
        )
        .unwrap();
        assert_eq!(manifest.members.len(), 2);
        assert_eq!(manifest.fs_class, FsSemanticClass::GenerationScan);
    }

    #[test]
    fn concurrent_mutation_forces_retry_and_never_a_mixed_snapshot() {
        // THE acceptance. A mutator rewrites b.rs between the two scans
        // of attempt 0 (so scan pairs disagree), then goes quiet. The
        // engine must discard attempt 0 ENTIRELY and produce, on a
        // later attempt, a manifest whose every content hash comes from
        // ONE generation — a mix of gen-1 a.rs with gen-2 b.rs (what a
        // naive "keep what matched" capture would emit) must be
        // impossible.
        let mut scan_calls = 0u32;
        let manifest = capture_coherent(
            CaptureConfig::generation_scan(),
            "workspace",
            |attempt, pass| {
                scan_calls += 1;
                let generation = if attempt == 0 && pass == 1 { 2 } else { 1 };
                // After the mutation lands (attempt >= 1) the whole
                // tree is at generation 2.
                let generation = if attempt >= 1 { 2 } else { generation };
                Ok(scan_of(&[
                    ("a.rs", if attempt == 0 { 1 } else { generation }, 10),
                    ("b.rs", generation, 11),
                ]))
            },
        )
        .unwrap();
        assert!(scan_calls > 2, "attempt 0 must not have satisfied capture");
        // Every member's hash comes from one single generation.
        let gens: std::collections::BTreeSet<[u8; 32]> = manifest
            .members
            .iter()
            .map(|(path, kind)| match kind {
                MemberKind::Regular { content_sha256, .. } => {
                    assert_eq!(*content_sha256, hash_of(2, path), "{path} must be gen-2");
                    *content_sha256
                }
                other => panic!("unexpected member {other:?}"),
            })
            .collect();
        assert_eq!(gens.len(), 2, "both files present, both gen-2");
    }

    #[test]
    fn sustained_mutation_exhausts_attempts_into_a_typed_refusal() {
        let mut generation = 0u64;
        let err = capture_coherent(
            CaptureConfig::generation_scan(),
            "workspace",
            |_attempt, _pass| {
                generation += 1; // every scan sees a different world
                Ok(scan_of(&[("hot.rs", generation, 10)]))
            },
        )
        .unwrap_err();
        match err {
            CaptureError::Incoherent(refusal) => {
                assert_eq!(refusal.attempts, 3);
                assert!(matches!(
                    refusal.last_divergence,
                    Divergence::ContentChanged { .. } | Divergence::MetadataInconsistent { .. }
                ));
            }
            CaptureError::Io(io) => panic!("wrong error class: {io}"),
            CaptureError::Rejected { .. } => panic!("unexpected policy refusal"),
        }
    }

    #[test]
    fn every_divergence_species_is_detected() {
        let base = scan_of(&[("a.rs", 1, 10)]);
        // Directory set changed.
        let grown = scan_of(&[("a.rs", 1, 10), ("new.rs", 1, 12)]);
        assert!(matches!(
            first_divergence(&base, &grown),
            Some(Divergence::DirectorySetChanged { added, .. }) if added == vec!["new.rs"]
        ));
        // Inode replaced (atomic save) — content identical.
        let mut replaced = base.clone();
        if let Some(MemberKind::Regular { inode, .. }) = replaced.members.get_mut("a.rs") {
            *inode = 99;
        }
        assert!(matches!(
            first_divergence(&base, &replaced),
            Some(Divergence::InodeReplaced { path }) if path == "a.rs"
        ));
        // Content changed.
        let rewritten = scan_of(&[("a.rs", 2, 10)]);
        // (gen bump changes hash AND mtime; content wins the ordering)
        assert!(matches!(
            first_divergence(&base, &rewritten),
            Some(Divergence::ContentChanged { path }) if path == "a.rs"
        ));
        // Metadata-only inconsistency (same bytes, moved mtime).
        let mut touched = base.clone();
        if let Some(MemberKind::Regular { mtime_ns, .. }) = touched.members.get_mut("a.rs") {
            *mtime_ns += 1;
        }
        assert!(matches!(
            first_divergence(&base, &touched),
            Some(Divergence::MetadataInconsistent { path }) if path == "a.rs"
        ));
        // Symlink retarget + kind change.
        let mut link_a = ScanObservation::default();
        link_a
            .members
            .insert("l".into(), MemberKind::Symlink { target: "x".into() });
        let mut link_b = ScanObservation::default();
        link_b
            .members
            .insert("l".into(), MemberKind::Symlink { target: "y".into() });
        assert!(matches!(
            first_divergence(&link_a, &link_b),
            Some(Divergence::SymlinkRetargeted { .. })
        ));
        let mut dir = ScanObservation::default();
        dir.members.insert("l".into(), MemberKind::Directory);
        assert!(matches!(
            first_divergence(&link_a, &dir),
            Some(Divergence::KindChanged { .. })
        ));
    }

    #[test]
    fn unstable_read_under_descriptor_diverges_the_attempt_not_the_capture() {
        // Pass 0 of attempt 0 reports descriptor instability; the
        // engine retries and attempt 1 succeeds.
        let steady = scan_of(&[("a.rs", 1, 10)]);
        let manifest = capture_coherent(
            CaptureConfig::generation_scan(),
            "workspace",
            |attempt, _pass| {
                if attempt == 0 {
                    Err(ScanError::UnstableDuringRead {
                        path: "a.rs".into(),
                    })
                } else {
                    Ok(steady.clone())
                }
            },
        )
        .unwrap();
        assert_eq!(manifest.members.len(), 1);
    }

    #[test]
    fn hard_io_failure_surfaces_immediately_without_retry_laundering() {
        let mut calls = 0u32;
        let err = capture_coherent(
            CaptureConfig::generation_scan(),
            "workspace",
            |_attempt, _pass| {
                calls += 1;
                Err(ScanError::Io {
                    path: "gone".into(),
                    cause: "permission denied".into(),
                })
            },
        )
        .unwrap_err();
        assert!(matches!(err, CaptureError::Io(_)));
        assert_eq!(calls, 1, "I/O failure is not a coherence retry");
    }

    #[test]
    fn atomic_snapshot_class_is_single_scan_and_binds_its_class() {
        let mut calls = 0u32;
        let scans = scan_of(&[("a.rs", 1, 10)]);
        let manifest = capture_coherent(
            CaptureConfig {
                fs_class: FsSemanticClass::AtomicSnapshot,
                max_attempts: 3,
            },
            "workspace",
            |_a, _p| {
                calls += 1;
                Ok(scans.clone())
            },
        )
        .unwrap();
        assert_eq!(calls, 1, "a frozen image needs exactly one scan");
        assert_eq!(manifest.fs_class, FsSemanticClass::AtomicSnapshot);
    }

    #[test]
    fn closure_capture_is_all_or_nothing() {
        // Workspace coherent, path-dep permanently mutating: the WHOLE
        // closure refuses, naming the failing root.
        let ws = scan_of(&[("src/lib.rs", 1, 10)]);
        let mut dep_generation = 0u64;
        let ws_scan = {
            let ws = ws.clone();
            move |_a: u32, _p: u32| Ok(ws.clone())
        };
        let dep_scan = move |_a: u32, _p: u32| {
            dep_generation += 1;
            Ok(scan_of(&[("src/dep.rs", dep_generation, 20)]))
        };
        let mut roots: Vec<(String, BoxedScanner)> = vec![
            ("workspace".to_string(), Box::new(ws_scan)),
            ("dep-logical-id".to_string(), Box::new(dep_scan)),
        ];
        let (failing_root, err) =
            capture_closure(CaptureConfig::generation_scan(), &mut roots).unwrap_err();
        assert_eq!(failing_root, "dep-logical-id");
        assert!(matches!(err, CaptureError::Incoherent(_)));
    }

    #[test]
    fn manifest_digest_binds_root_class_and_members() {
        let scans = scan_of(&[("a.rs", 1, 10)]);
        let capture = |root: &str, class: FsSemanticClass| {
            capture_coherent(
                CaptureConfig {
                    fs_class: class,
                    max_attempts: 1,
                },
                root,
                |_a, _p| Ok(scans.clone()),
            )
            .unwrap()
        };
        let base = capture("workspace", FsSemanticClass::AtomicSnapshot);
        let other_root = capture("dep-x", FsSemanticClass::AtomicSnapshot);
        let other_class = capture("workspace", FsSemanticClass::Reflink);
        assert_ne!(base.manifest_sha256, other_root.manifest_sha256);
        assert_ne!(base.manifest_sha256, other_class.manifest_sha256);
        let provenance = base.provenance();
        assert_eq!(provenance.manifest_sha256, base.manifest_sha256);
        assert_eq!(provenance.snapshot_root, "workspace");
    }

    #[test]
    fn credential_locations_never_enter_the_snapshot() {
        // THE reason this wiring exists. Before it, member_disposition's
        // fallthrough was Include, so anything not explicitly excluded
        // was captured and shipped to a remote worker — including a
        // credential sitting in the workspace. The E027 policy existed
        // the whole time and nothing called it.
        //
        // Paths are spelled the way the scanner produces them: relative,
        // `/`-separated, no leading slash.
        for path in [
            ".env",
            ".env.production",
            ".ENV",
            "id_rsa",
            ".ssh/id_ed25519",
            "deploy/signing.pem",
            "certs/store.p12",
            "release.keystore",
            ".aws/credentials",
            ".netrc",
            ".docker/config.json",
            ".gnupg/secring.gpg",
        ] {
            assert_eq!(
                member_disposition(path, false),
                MemberDisposition::ExcludeSecretPolicy,
                "{path} would have been captured and uploaded"
            );
        }
    }

    #[test]
    fn ordinary_sources_are_still_captured() {
        // The other half, and the reason the half above means anything:
        // a policy that withheld everything would satisfy it while
        // making remote execution impossible. Includes the near-misses
        // that a sloppier matcher would swallow.
        for path in [
            "src/lib.rs",
            "build.rs",
            "Cargo.toml",
            "fixtures/generated.bin",
            "src/environment.rs",
            "app.environment",
            "docs/PEMDAS.md",
            "crates/keystore_client/src/lib.rs",
        ] {
            assert_eq!(
                member_disposition(path, false),
                MemberDisposition::Include,
                "{path} must still be captured"
            );
        }
    }

    #[test]
    fn the_accepted_false_positives_are_pinned_not_discovered() {
        // The seed set matches a path COMPONENT by prefix, so it catches
        // `.env.production` — and also catches things that are not
        // secrets. This pins the boundary so the next reader meets it as
        // a decision rather than as a surprise, and does not "fix" it by
        // loosening the rule.
        //
        // Measured against this repository: of 1,257 tracked files
        // exactly ONE is withheld, `dashboard/.env.example`. It is a
        // placeholder template, not a build input, so the cost of
        // excluding it is nothing and the benefit of not special-casing
        // it is that `.env.example` cannot become a place to smuggle a
        // real credential past the policy.
        for template in [".env.example", "dashboard/.env.example", ".env.template"] {
            assert_eq!(
                member_disposition(template, false),
                MemberDisposition::ExcludeSecretPolicy,
                "{template}: accepted false positive — templates are withheld on purpose"
            );
        }
        // Same prefix rule, and here it is doing real work: .envrc is a
        // direnv script that very commonly holds credentials.
        assert_eq!(
            member_disposition(".envrc", false),
            MemberDisposition::ExcludeSecretPolicy
        );

        // The asymmetry that justifies all of the above: a false
        // positive costs an action its remote execution, a false
        // negative ships a credential off the machine. Erring toward
        // exclusion is correct, and is why none of these are
        // special-cased back in.
    }

    #[test]
    fn no_always_include_path_is_withheld_by_secret_policy() {
        // The collision guard for the ordering choice. Secret policy is
        // consulted BEFORE the always-include set, which is right —
        // a build-identity file is not a reason to upload a credential
        // — but it means a future secret pattern that happened to match
        // `.cargo/config.toml` would silently stop capturing it and
        // break every remote build with a confusing error.
        //
        // Today none of them collide. If that changes, this names which
        // one, here, rather than in a build failure on a worker.
        for path in ALWAYS_INCLUDE {
            assert_eq!(
                member_disposition(path, false),
                MemberDisposition::Include,
                "{path} is an always-include build-identity file but the secret \
                 policy now withholds it: the seed set and ALWAYS_INCLUDE have collided"
            );
        }
    }

    #[test]
    fn membership_policy_matches_the_bead_enumeration() {
        // Always-include identity files (even when untracked/ignored).
        for path in [
            "Cargo.lock",
            ".cargo/config.toml",
            "rust-toolchain.toml",
            "rust-toolchain",
        ] {
            assert_eq!(
                member_disposition(path, false),
                MemberDisposition::Include,
                "{path}"
            );
        }
        // Sources and untracked policy-relevant files include.
        assert_eq!(
            member_disposition("src/lib.rs", false),
            MemberDisposition::Include
        );
        assert_eq!(
            member_disposition("fixtures/generated.bin", false),
            MemberDisposition::Include
        );
        // Build outputs and ephemeral locks stay out.
        assert_eq!(
            member_disposition("target/debug/foo", false),
            MemberDisposition::ExcludeBuildOutput
        );
        for path in [
            ".cargo/.package-cache",
            "target-info/.rustc_info.json",
            "somewhere/flock.lock",
        ] {
            assert_ne!(
                member_disposition(path, false),
                MemberDisposition::Include,
                "{path}"
            );
        }
        // .git hidden without a declared canonical git-state object…
        assert_eq!(
            member_disposition(".git/HEAD", false),
            MemberDisposition::HiddenGitState
        );
        // …and visible with one.
        assert_eq!(
            member_disposition(".git/HEAD", true),
            MemberDisposition::Include
        );
        // A `targets/` directory is not `target/` (prefix, not glob).
        assert_eq!(
            member_disposition("targets/x.rs", false),
            MemberDisposition::Include
        );
    }
}
