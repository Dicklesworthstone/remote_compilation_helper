//! Edge-host observation for the live dependency lane (bd-14t4j /
//! bd-k52xe): the facts `rabs_key::live_dependency` keys, read from this
//! host's filesystem and compiler, memoized by file identity.
//!
//! `rabs-key` is pure; something has to look at real bytes. This module is
//! that something, with three rules:
//!
//! 1. **Descriptor-verified reads.** A file is hashed through an open
//!    descriptor whose identity (device, inode, size, mtime, ctime) must be
//!    unchanged before and after the read. A file that moves while it is
//!    read produces an error, never a digest.
//! 2. **Memoization never outlives identity.** Every memoized digest is
//!    re-validated against a fresh `lstat` of the same path on every use;
//!    a differing identity re-reads. ctime is included because a write can
//!    restore mtime but never ctime.
//! 3. **Slow facts are warmed, not awaited.** Hashing a toolchain sysroot
//!    (hundreds of MiB) or a large package must not sit on a compiler's
//!    critical path. The first request starts a bounded background warm and
//!    is answered [`FactsMiss::Pending`]; the compiler then runs exactly as
//!    it would without RABS.

use rabs_cas::digest_set::{DigestRequest, StreamingObjectWriter};
use rabs_key::canonical::CanonicalEncoder;
use rabs_key::dependency_candidates::{
    CandidateClass, CandidateRead, ClosureRefusal, CrateFlavor, DependencyDirectoryFact,
    classify_candidate, read_candidate, referenced_candidates,
};
use rabs_key::live_dependency::{
    DependencyActionPlan, DependencySourceKind, ExternFact, PlannedExtern, ToolchainFacts,
    build_script_env_names,
};
use rabs_key::typed_digest::compute;
use rabs_protocol::result_identity::TypedDigest;
use rabs_sandbox::snapshot_capture::{
    MemberDisposition, MemberKind, SealedSourceSnapshot, capture_sealed_source, member_disposition,
};
use std::collections::HashMap;
use std::io::Read;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// Domain of the sysroot tree digest.
pub const DOMAIN_SYSROOT_TREE: &str = "rabs.live-dependency.sysroot-tree.v1";
/// Logical root name of a captured package in its sealed snapshot.
pub const PACKAGE_ROOT: &str = "package";
/// Separate sealed root for compiler inputs produced by a Cargo build script.
pub const GENERATED_ROOT: &str = "generated";

/// Largest package tree the lane captures at all.
const MAX_PACKAGE_BYTES: u64 = 64 * 1024 * 1024;
/// Packages up to this size are captured on the request path.
const SYNCHRONOUS_PACKAGE_BYTES: u64 = 4 * 1024 * 1024;
/// Most files one package may contain.
const MAX_PACKAGE_FILES: usize = 20_000;
/// Bound on memoized file digests before the memo is reset.
const MAX_MEMOIZED_FILES: usize = 65_536;
/// Bound on retained package snapshots (their bytes stay in memory).
const MAX_RETAINED_PACKAGE_BYTES: u64 = 512 * 1024 * 1024;
/// A failed toolchain probe is retried after this long.
const PROBE_RETRY: Duration = Duration::from_secs(30);
/// Concurrent background warms (each hashes a lot of bytes).
const MAX_WARMING: usize = 2;
/// Largest single crate file the closure reads.
const MAX_CANDIDATE_FILE_BYTES: u64 = 512 * 1024 * 1024;
/// Most directory entries one closure lists (warm target directories hold
/// every crate, executable and temporary a project ever built).
const MAX_DEPENDENCY_ENTRIES: usize = 262_144;
/// Cold (unmemoized) crate bytes read on the request path; beyond this the
/// closure warms in the background and the compiler runs normally.
const SYNCHRONOUS_DEPENDENCY_BYTES: u64 = 32 * 1024 * 1024;
/// Bound on memoized candidate observations before the memo is reset.
const MAX_MEMOIZED_CANDIDATES: usize = 16_384;

/// Identity of one filesystem object at one moment.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FileSig {
    dev: u64,
    ino: u64,
    size: u64,
    mtime_ns: i128,
    ctime_ns: i128,
}

impl FileSig {
    /// The identity recorded in `meta`.
    #[must_use]
    pub fn of(meta: &std::fs::Metadata) -> Self {
        Self {
            dev: meta.dev(),
            ino: meta.ino(),
            size: meta.size(),
            mtime_ns: i128::from(meta.mtime()) * 1_000_000_000 + i128::from(meta.mtime_nsec()),
            ctime_ns: i128::from(meta.ctime()) * 1_000_000_000 + i128::from(meta.ctime_nsec()),
        }
    }

    /// Logical byte length.
    #[must_use]
    pub const fn size(&self) -> u64 {
        self.size
    }
}

/// Why a fact is not available for this request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FactsMiss {
    /// Being computed in the background; run the compiler normally.
    Pending,
    /// Not keyable on this host (reason code + detail).
    Refused(String),
}

impl std::fmt::Display for FactsMiss {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Pending => f.write_str("facts-pending"),
            Self::Refused(detail) => write!(f, "facts-refused: {detail}"),
        }
    }
}

fn lstat_regular(path: &Path) -> std::io::Result<FileSig> {
    let meta = std::fs::symlink_metadata(path)?;
    if !meta.file_type().is_file() {
        return Err(std::io::Error::other("not a regular file"));
    }
    Ok(FileSig::of(&meta))
}

/// Read a whole regular file through one descriptor whose identity must
/// not move during the read. `max_bytes` bounds the allocation.
///
/// # Errors
/// I/O failures, non-regular files, oversized files, or identity movement.
pub fn read_stable(path: &Path, max_bytes: u64) -> std::io::Result<(FileSig, Vec<u8>)> {
    let before = lstat_regular(path)?;
    if before.size > max_bytes {
        return Err(std::io::Error::other("file exceeds the byte bound"));
    }
    let file = std::fs::File::open(path)?;
    let opened = FileSig::of(&file.metadata()?);
    let mut bytes = Vec::with_capacity(usize::try_from(before.size).unwrap_or(0));
    file.take(max_bytes + 1).read_to_end(&mut bytes)?;
    let after = lstat_regular(path)?;
    if opened != before || after != before || bytes.len() as u64 != before.size {
        return Err(std::io::Error::other("file changed while it was read"));
    }
    Ok((before, bytes))
}

/// Stream-hash a regular file into its CAS object identity, with the same
/// identity discipline as [`read_stable`].
///
/// # Errors
/// As [`read_stable`].
pub fn digest_stable(path: &Path) -> std::io::Result<(FileSig, TypedDigest)> {
    let before = lstat_regular(path)?;
    let mut file = std::fs::File::open(path)?;
    let opened = FileSig::of(&file.metadata()?);
    let mut writer = StreamingObjectWriter::new(DigestRequest::default(), Some(before.size));
    let mut buffer = vec![0_u8; 256 * 1024];
    loop {
        let read = file.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        writer
            .write(&buffer[..read])
            .map_err(|error| std::io::Error::other(format!("{error:?}")))?;
    }
    let digest = writer
        .finish()
        .map_err(|error| std::io::Error::other(format!("{error:?}")))?
        .atp_content_id;
    let after = lstat_regular(path)?;
    if opened != before || after != before {
        return Err(std::io::Error::other("file changed while it was hashed"));
    }
    Ok((before, digest))
}

/// A probed toolchain plus the identity of every file its digests cover.
#[derive(Debug)]
struct ProbedToolchain {
    facts: ToolchainFacts,
    covered: Vec<(PathBuf, FileSig)>,
}

impl ProbedToolchain {
    fn still_current(&self) -> bool {
        self.covered
            .iter()
            .all(|(path, sig)| lstat_regular(path).is_ok_and(|now| now == *sig))
    }
}

#[derive(Debug)]
enum Slot<T> {
    Warming,
    Ready(Arc<T>),
    Failed { reason: String, at: Instant },
}

/// A captured package: the sealed bytes the key was computed from and the
/// identity of every member, for re-verification after execution.
#[derive(Debug)]
pub struct PackageFacts {
    /// Sealed bytes of the complete package tree.
    pub snapshot: Arc<SealedSourceSnapshot>,
    /// Every regular file: relative path, CAS object id of its sealed
    /// bytes, executable bit — sorted by path.
    pub files: Vec<(String, TypedDigest, bool)>,
    /// Every regular file in the captured generated-input tree, if any.
    pub generated_files: Vec<(String, TypedDigest, bool)>,
    /// Exact Cargo build-script stdout record, bound into the action key.
    pub build_script_output: Option<Vec<u8>>,
    source_kind: DependencySourceKind,
    members: Vec<(String, MemberSig)>,
    generated: Option<GeneratedObservation>,
    bytes: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum MemberSig {
    Directory,
    File(FileSig),
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct GeneratedObservation {
    root: PathBuf,
    members: Vec<(String, MemberSig)>,
    // Unlike compiler output directories this is a read-only input tree.
    // Retain every directory generation to detect transient added inputs.
    directories: Vec<(PathBuf, FileSig)>,
    script_output: (PathBuf, FileSig),
    root_output: (PathBuf, FileSig),
}

impl PackageFacts {
    /// Re-walk `root` and require exactly the captured members with the
    /// captured identities. Used after the compiler ran against the live
    /// tree: a result is only publishable if its inputs never moved.
    ///
    /// # Errors
    /// A description of the first difference.
    pub fn verify_unchanged(&self, root: &Path) -> Result<(), String> {
        let (members, _) = walk_package(root, self.source_kind)?;
        if let Some(generated) = &self.generated
            && observe_generated(&generated.root)?.0 != *generated
        {
            return Err("generated inputs changed during execution".into());
        }
        if members == self.members {
            Ok(())
        } else {
            Err("the package tree changed during execution".into())
        }
    }

    /// Generated inputs must never alias directories or files the compiler
    /// or a cache installation can write. Rechecked at both delivery gates.
    pub fn verify_generated_disjoint(&self, plan: &DependencyActionPlan) -> Result<(), String> {
        let Some(generated) = &self.generated else {
            return Ok(());
        };
        let output = std::fs::symlink_metadata(&plan.out_dir)
            .map_err(|error| format!("output directory: {error}"))?;
        let source = std::fs::symlink_metadata(&plan.source_root)
            .map_err(|error| format!("source directory: {error}"))?;
        if !output.is_dir() || !source.is_dir() {
            return Err("source/output root is not a real directory".into());
        }
        for other in [&plan.out_dir, &plan.source_root] {
            let canonical = std::fs::canonicalize(other)
                .map_err(|error| format!("source/output topology: {error}"))?;
            if generated.root.starts_with(&canonical) || canonical.starts_with(&generated.root) {
                return Err("generated input tree overlaps source or compiler output".into());
            }
        }
        for (_, sig) in &generated.directories {
            if [(output.dev(), output.ino()), (source.dev(), source.ino())]
                .contains(&(sig.dev, sig.ino))
            {
                return Err("generated input directory aliases source or compiler output".into());
            }
        }
        for name in plan.output_names() {
            let path = Path::new(&plan.out_dir).join(name);
            let meta = match std::fs::symlink_metadata(&path) {
                Ok(meta) => meta,
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
                Err(error) => return Err(format!("output identity: {error}")),
            };
            if [(generated.script_output.1.dev, generated.script_output.1.ino), (generated.root_output.1.dev, generated.root_output.1.ino)].contains(&(meta.dev(), meta.ino())) || generated.members.iter().any(|(_, member)| {
                matches!(member, MemberSig::File(sig) if sig.dev == meta.dev() && sig.ino == meta.ino())
            }) {
                return Err("generated input aliases a declared compiler output".into());
            }
        }
        Ok(())
    }
}

/// The locator-exact dependency closure of one compile
/// ([`rabs_key::dependency_candidates`]): the referenced candidate groups
/// and the direct externs' exact identities, with the identity of every
/// file read to establish them. Rechecked before a hit installs and after
/// a local compiler exits.
#[derive(Debug)]
pub struct DependencyFacts {
    /// Pure facts bound to the action key, in first-use directory order.
    pub directories: Vec<DependencyDirectoryFact>,
    /// Exact content identity of every planned `--extern` file.
    pub externs: Vec<ExternFact>,
    request: DependencyRequest,
    /// Every file read to establish the facts, with its identity then.
    read: Vec<(PathBuf, FileSig)>,
    facts: Arc<LiveFacts>,
}

impl DependencyFacts {
    /// Recompute the closure and require identical facts, and require every
    /// file read for the key to be untouched (a later file may only JOIN a
    /// referenced group with identical metadata, e.g. a pipelined `.rlib`).
    /// Unrelated members of the directories may change freely: the crate
    /// locator never examines them.
    ///
    /// # Errors
    /// A description of the first difference.
    pub fn verify_unchanged(&self) -> Result<(), String> {
        for (path, sig) in &self.read {
            if lstat_regular(path).ok() != Some(*sig) {
                return Err(format!(
                    "dependency input {} changed after keying",
                    path.display()
                ));
            }
        }
        let now = close_dependencies(&self.facts, &self.request, None)?;
        if now.directories != self.directories || now.externs != self.externs {
            return Err("referenced dependency candidates changed".into());
        }
        Ok(())
    }
}

/// What one closure is computed from.
#[derive(Debug, Clone)]
struct DependencyRequest {
    roots: Vec<PathBuf>,
    out_dir: PathBuf,
    outputs: Vec<String>,
    /// Direct externs as (root index, file name).
    seeds: Vec<(usize, String)>,
}

/// A computed closure before it is wrapped for re-verification.
struct Closure {
    directories: Vec<DependencyDirectoryFact>,
    externs: Vec<ExternFact>,
    read: Vec<(PathBuf, FileSig)>,
}

/// One memoized observation of a candidate file.
#[derive(Debug)]
struct CandidateObservation {
    read: CandidateRead,
    exact: TypedDigest,
}

/// Why a closure computation stopped early.
const COLD_BUDGET_EXHAUSTED: &str = "cold dependency bytes exceed the request budget";

fn reject_dependency_output_aliases(
    request: &DependencyRequest,
    read: &[(PathBuf, FileSig)],
) -> Result<(), String> {
    let optional_metadata = |path: &Path| match std::fs::symlink_metadata(path) {
        Ok(meta) => Ok(Some(meta)),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error.to_string()),
    };
    if let Some(output) = optional_metadata(&request.out_dir)? {
        if !output.is_dir() {
            return Err("output root is not a real directory".into());
        }
        // Outputs are excluded from the listing by name in the out-dir. A
        // lexically different root naming the same real directory would
        // list this compile's own outputs as inputs.
        for root in &request.roots {
            let dependency = std::fs::symlink_metadata(root).map_err(|error| error.to_string())?;
            if root != &request.out_dir
                && dependency.dev() == output.dev()
                && dependency.ino() == output.ino()
            {
                return Err("dependency root aliases the output directory".into());
            }
        }
    }
    for name in &request.outputs {
        if let Some(output) = optional_metadata(&request.out_dir.join(name))? {
            if !output.is_file() {
                return Err("declared output is not a regular file".into());
            }
            if read
                .iter()
                .any(|(_, input)| input.dev == output.dev() && input.ino == output.ino())
            {
                return Err("dependency candidate aliases a declared output".into());
            }
        }
    }
    Ok(())
}

fn dependency_request(plan: &DependencyActionPlan) -> Result<DependencyRequest, String> {
    let seeds = plan
        .externs
        .iter()
        .filter_map(|planned| match planned {
            PlannedExtern::File { path, .. } => Some(path),
            PlannedExtern::Toolchain { .. } => None,
        })
        .map(|path| {
            let (directory, name) = path.rsplit_once('/').ok_or("extern without a directory")?;
            let index = plan
                .dependency_dirs
                .iter()
                .position(|root| root == directory)
                .ok_or("extern outside the planned dependency directories")?;
            Ok((index, name.to_owned()))
        })
        .collect::<Result<Vec<_>, String>>()?;
    Ok(DependencyRequest {
        roots: plan.dependency_dirs.iter().map(PathBuf::from).collect(),
        out_dir: PathBuf::from(&plan.out_dir),
        outputs: plan.output_names(),
        seeds,
    })
}

/// Locator-visible member names of each root (outputs of this compile in
/// the out-dir excluded). Inert members are skipped by name, unstatted.
fn list_dependency_roots(request: &DependencyRequest) -> Result<Vec<Vec<String>>, String> {
    let mut listings = Vec::with_capacity(request.roots.len());
    let mut scanned = 0_usize;
    for root in &request.roots {
        let meta = std::fs::symlink_metadata(root).map_err(|e| e.to_string())?;
        if !meta.is_dir() {
            return Err("dependency root is not a real directory".into());
        }
        let mut names = Vec::new();
        for entry in std::fs::read_dir(root).map_err(|e| e.to_string())? {
            let entry = entry.map_err(|e| e.to_string())?;
            scanned += 1;
            if scanned > MAX_DEPENDENCY_ENTRIES {
                return Err("dependency directory entries exceed class bound".into());
            }
            let Ok(name) = entry.file_name().into_string() else {
                // A non-UTF-8 name never matches a Cargo crate file name.
                continue;
            };
            if classify_candidate(&name) == CandidateClass::Inert
                || (root == &request.out_dir && request.outputs.contains(&name))
            {
                continue;
            }
            names.push(name);
        }
        names.sort();
        listings.push(names);
    }
    Ok(listings)
}

/// Compute the closure. `cold_budget` bounds bytes read from disk (memo
/// misses); exhausting it fails with [`COLD_BUDGET_EXHAUSTED`].
fn close_dependencies(
    facts: &LiveFacts,
    request: &DependencyRequest,
    cold_budget: Option<u64>,
) -> Result<Closure, String> {
    let listings = list_dependency_roots(request)?;
    let paths: Vec<String> = request
        .roots
        .iter()
        .map(|root| {
            root.to_str()
                .map(str::to_owned)
                .ok_or("non-UTF-8 dependency root")
        })
        .collect::<Result<_, _>>()?;
    let mut read = Vec::new();
    let mut observed: HashMap<(usize, String), TypedDigest> = HashMap::new();
    let mut cold = 0_u64;
    let directories = referenced_candidates(
        &paths,
        &listings,
        &request.seeds,
        |directory, name, flavor| {
            let path = request.roots[directory].join(name);
            let (sig, observation, read_bytes) = facts.candidate(&path, flavor)?;
            cold = cold.saturating_add(read_bytes);
            if cold_budget.is_some_and(|budget| cold > budget) {
                return Err(COLD_BUDGET_EXHAUSTED.to_owned());
            }
            read.push((path, sig));
            observed.insert((directory, name.to_owned()), observation.exact.clone());
            Ok(observation.read.clone())
        },
    )
    .map_err(|refusal| match refusal {
        ClosureRefusal::Read(detail) if detail == COLD_BUDGET_EXHAUSTED => detail,
        other => other.to_string(),
    })?;
    let externs = request
        .seeds
        .iter()
        .map(|(directory, name)| {
            let content_digest = observed
                .get(&(*directory, name.clone()))
                .cloned()
                .ok_or("an extern was not observed")?;
            Ok(ExternFact {
                path: format!("{}/{name}", paths[*directory]),
                content_digest,
            })
        })
        .collect::<Result<Vec<_>, String>>()?;
    read.sort_by(|a, b| a.0.cmp(&b.0));
    read.dedup_by(|a, b| a.0 == b.0);
    reject_dependency_output_aliases(request, &read)?;
    Ok(Closure {
        directories,
        externs,
        read,
    })
}

/// Largest build-script stdout record the lane reads.
const MAX_BUILD_SCRIPT_RECORD_BYTES: u64 = 4 * 1024 * 1024;

/// The `cargo:rustc-env` names Cargo recorded for the build script whose
/// output directory is `out_dir`. Cargo keeps the script's stdout beside
/// `OUT_DIR` and names that `OUT_DIR` in `root-output`; both layouts are
/// understood (`<unit>/output` and the build-dir layout's
/// `<unit>/run/stdout`). The record must name exactly this `OUT_DIR`.
///
/// # Errors
/// No record, a record for another directory, or an unreadable record.
pub fn build_script_env(out_dir: &Path) -> Result<Vec<String>, String> {
    let unit = out_dir
        .parent()
        .filter(|_| out_dir.is_absolute() && out_dir.file_name() == Some("out".as_ref()))
        .ok_or("OUT_DIR is not a Cargo build-script output directory")?;
    for (stdout, root) in [
        (unit.join("output"), unit.join("root-output")),
        (unit.join("run/stdout"), unit.join("run/root-output")),
    ] {
        match lstat_regular(&stdout) {
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(error) => return Err(format!("{}: {error}", stdout.display())),
        }
        let (_, named) = read_stable(&root, 64 * 1024)
            .map_err(|error| format!("{}: {error}", root.display()))?;
        if named != out_dir.as_os_str().as_encoded_bytes() {
            return Err("the build-script record names another OUT_DIR".into());
        }
        let (_, record) = read_stable(&stdout, MAX_BUILD_SCRIPT_RECORD_BYTES)
            .map_err(|error| format!("{}: {error}", stdout.display()))?;
        let record =
            String::from_utf8(record).map_err(|_| "the build-script record is not UTF-8")?;
        return build_script_env_names(&record);
    }
    Err("no build-script record beside OUT_DIR".into())
}

/// The CAS object identity of `bytes` (what [`digest_stable`] computes for
/// a file with these contents).
fn object_digest(bytes: &[u8]) -> std::io::Result<TypedDigest> {
    let mut writer = StreamingObjectWriter::new(DigestRequest::default(), Some(bytes.len() as u64));
    writer
        .write(bytes)
        .map_err(|error| std::io::Error::other(format!("{error:?}")))?;
    Ok(writer
        .finish()
        .map_err(|error| std::io::Error::other(format!("{error:?}")))?
        .atp_content_id)
}

/// Walk a package tree: every directory and regular file with its
/// identity, sorted by relative path. Symlinks and special files refuse:
/// the class keys a plain tree. Cargo Git checkouts exclude their root
/// `.git` entry before inspecting it: Git metadata is neither an admitted
/// source input nor a capability to read/upload repository credentials.
fn walk_package(
    root: &Path,
    source_kind: DependencySourceKind,
) -> Result<(Vec<(String, MemberSig)>, u64), String> {
    let root_identity = || {
        let meta = std::fs::symlink_metadata(root)
            .map_err(|error| format!("lstat package root {}: {error}", root.display()))?;
        if !meta.file_type().is_dir() {
            return Err("package root is not a real directory".to_owned());
        }
        Ok(FileSig::of(&meta))
    };
    // Warm memo lookups and post-execution verification do not repeat the
    // sealed capture's root checks. They must independently reject a root
    // symlink, even if it resolves to the same captured member inodes.
    let root_before = root_identity()?;
    let mut members = Vec::new();
    let mut total = 0_u64;
    let mut pending = vec![(root.to_path_buf(), String::new())];
    while let Some((directory, prefix)) = pending.pop() {
        let entries = std::fs::read_dir(&directory)
            .map_err(|error| format!("read_dir {}: {error}", directory.display()))?;
        for entry in entries {
            let entry = entry.map_err(|error| format!("read_dir entry: {error}"))?;
            let name = entry
                .file_name()
                .into_string()
                .map_err(|_| "non-UTF-8 package path".to_owned())?;
            if source_kind == DependencySourceKind::GitCheckout
                && prefix.is_empty()
                && name == ".git"
            {
                continue;
            }
            let relative = if prefix.is_empty() {
                name
            } else {
                format!("{prefix}/{name}")
            };
            let meta = std::fs::symlink_metadata(entry.path())
                .map_err(|error| format!("lstat {relative}: {error}"))?;
            if meta.file_type().is_dir() {
                members.push((relative.clone(), MemberSig::Directory));
                pending.push((entry.path(), relative));
            } else if meta.file_type().is_file() {
                total = total.saturating_add(meta.len());
                members.push((relative, MemberSig::File(FileSig::of(&meta))));
            } else {
                return Err(format!("non-regular package member {relative}"));
            }
            if members.len() > MAX_PACKAGE_FILES || total > MAX_PACKAGE_BYTES {
                return Err("package exceeds the capture bounds".into());
            }
        }
    }
    if root_identity()? != root_before {
        return Err("package root changed while its members were observed".into());
    }
    members.sort_by(|a, b| a.0.cmp(&b.0));
    Ok((members, total))
}

fn observe_generated(root: &Path) -> Result<(GeneratedObservation, u64), String> {
    // A lexical root reached through an ancestor symlink may overlap the
    // compiler's writable tree despite the planner's disjoint-path check.
    for ancestor in root.ancestors() {
        if !std::fs::symlink_metadata(ancestor)
            .map_err(|error| format!("generated input ancestor: {error}"))?
            .is_dir()
        {
            return Err("generated input ancestor is not a real directory".into());
        }
    }
    let before = FileSig::of(
        &std::fs::symlink_metadata(root).map_err(|error| format!("generated root: {error}"))?,
    );
    let (members, bytes) = walk_package(root, DependencySourceKind::RegistryPackage)?;
    let mut directories = vec![(root.to_path_buf(), before)];
    for (relative, member) in &members {
        if member_disposition(relative, false) != MemberDisposition::Include {
            return Err(format!(
                "generated member {relative} is outside the capture policy"
            ));
        }
        if matches!(member, MemberSig::Directory) {
            let path = root.join(relative);
            let metadata = std::fs::symlink_metadata(&path)
                .map_err(|error| format!("generated directory: {error}"))?;
            if !metadata.is_dir() {
                return Err("generated member ceased to be a directory".into());
            }
            directories.push((path, FileSig::of(&metadata)));
        }
    }
    let after = FileSig::of(
        &std::fs::symlink_metadata(root).map_err(|error| format!("generated root: {error}"))?,
    );
    if after != before {
        return Err("generated root changed during observation".into());
    }
    // The pinned Cargo run record is a sibling of OUT_DIR. Unknown
    // layouts remain unserved; root-output binds this record to our unit.
    let run = root
        .parent()
        .ok_or("generated root has no parent")?
        .join("run");
    let run_meta = std::fs::symlink_metadata(&run)
        .map_err(|error| format!("build-script run directory: {error}"))?;
    if !run_meta.is_dir() {
        return Err("build-script run directory is not real".into());
    }
    directories.push((run.clone(), FileSig::of(&run_meta)));
    let root_output = run.join("root-output");
    let (root_sig, root_bytes) = read_stable(&root_output, 64 * 1024)
        .map_err(|error| format!("build-script root-output: {error}"))?;
    if root_bytes != root.to_str().ok_or("non-UTF-8 generated root")?.as_bytes() {
        return Err("Cargo build-script record names a different OUT_DIR".into());
    }
    let script_output = run.join("stdout");
    let script_sig =
        lstat_regular(&script_output).map_err(|error| format!("build-script stdout: {error}"))?;
    if script_sig.size > 1024 * 1024 {
        return Err("build-script output record exceeds limit".into());
    }
    Ok((
        GeneratedObservation {
            root: root.to_path_buf(),
            members,
            directories,
            script_output: (script_output, script_sig),
            root_output: (root_output, root_sig),
        },
        bytes
            .saturating_add(script_sig.size)
            .saturating_add(root_sig.size),
    ))
}

fn captured_files(
    snapshot: &SealedSourceSnapshot,
    logical_root: &str,
    observed: &[(String, MemberSig)],
) -> Result<Vec<(String, TypedDigest, bool)>, String> {
    let manifest = snapshot
        .manifest(logical_root)
        .ok_or("capture lost its root")?;
    let captured_count = manifest
        .members
        .values()
        .filter(|member| matches!(member, MemberKind::Regular { .. }))
        .count();
    let observed_count = observed
        .iter()
        .filter(|(_, sig)| matches!(sig, MemberSig::File(_)))
        .count();
    if captured_count != observed_count
        || manifest
            .members
            .values()
            .any(|member| matches!(member, MemberKind::Symlink { .. }))
    {
        return Err("capture does not cover the complete input tree".into());
    }
    let mut files = Vec::with_capacity(captured_count);
    for (relative, member) in &manifest.members {
        if let MemberKind::Regular { mode, .. } = member {
            let bytes = snapshot
                .file_bytes(logical_root, relative)
                .ok_or("sealed bytes missing for a captured member")?;
            let object = rabs_cas::digest_set::digest_set(bytes, DigestRequest::default(), None)
                .map_err(|error| format!("digest: {error:?}"))?
                .atp_content_id;
            files.push((relative.clone(), object, mode & 0o111 != 0));
        }
    }
    Ok(files)
}

fn capture_package(
    root: &Path,
    source_kind: DependencySourceKind,
    generated_root: Option<&Path>,
) -> Result<PackageFacts, String> {
    let (before, bytes) = walk_package(root, source_kind)?;
    let (generated, generated_bytes) = match generated_root {
        Some(root) => {
            let (observation, size) = observe_generated(root)?;
            (Some(observation), size)
        }
        None => (None, 0),
    };
    let bytes = bytes.saturating_add(generated_bytes);
    if bytes > MAX_PACKAGE_BYTES
        || before.len() + generated.as_ref().map_or(0, |tree| tree.members.len())
            > MAX_PACKAGE_FILES
    {
        return Err("combined source and generated inputs exceed capture bounds".into());
    }
    // The key's "complete package tree" claim requires the capture policy
    // to have excluded nothing a compiler could read.
    for (relative, _) in &before {
        if member_disposition(relative, false) != MemberDisposition::Include {
            return Err(format!(
                "package member {relative} is outside the capture policy"
            ));
        }
    }
    let mut roots = vec![(PACKAGE_ROOT.to_owned(), root.to_path_buf())];
    if let Some(root) = generated_root {
        roots.push((GENERATED_ROOT.to_owned(), root.to_path_buf()));
    }
    let snapshot = capture_sealed_source(&roots, false, 3, MAX_PACKAGE_BYTES)
        .map_err(|error| format!("capture: {error:?}"))?;
    let (after, _) = walk_package(root, source_kind)?;
    if after != before {
        return Err("package changed during capture".into());
    }
    let (generated_files, build_script_output) = match &generated {
        Some(tree) => {
            let (sig, output) = read_stable(&tree.script_output.0, 1024 * 1024)
                .map_err(|error| format!("build-script stdout capture: {error}"))?;
            if sig != tree.script_output.1 {
                return Err("build-script output record changed during capture".into());
            }
            if observe_generated(&tree.root)?.0 != *tree {
                return Err("generated inputs changed during capture".into());
            }
            (
                captured_files(&snapshot, GENERATED_ROOT, &tree.members)?,
                Some(output),
            )
        }
        None => (Vec::new(), None),
    };
    let files = captured_files(&snapshot, PACKAGE_ROOT, &before)?;
    Ok(PackageFacts {
        snapshot: Arc::new(snapshot),
        files,
        generated_files,
        build_script_output,
        source_kind,
        members: before,
        generated,
        bytes,
    })
}

fn probe_toolchain(compiler: &Path, env: &[(String, String)]) -> Result<ProbedToolchain, String> {
    let bin = compiler.parent().ok_or("compiler has no parent")?;
    if compiler.file_name().and_then(|n| n.to_str()) != Some("rustc")
        || bin.file_name().and_then(|n| n.to_str()) != Some("bin")
    {
        return Err("compiler is not <sysroot>/bin/rustc".into());
    }
    let sysroot = bin.parent().ok_or("compiler has no sysroot")?;
    let run = |args: &[&str]| -> Result<String, String> {
        let output = std::process::Command::new(compiler)
            .args(args)
            .env_clear()
            .envs(env.iter().map(|(name, value)| (name, value)))
            .stdin(std::process::Stdio::null())
            .output()
            .map_err(|error| format!("probe {args:?}: {error}"))?;
        if !output.status.success() {
            return Err(format!("probe {args:?} exited {}", output.status));
        }
        String::from_utf8(output.stdout).map_err(|_| format!("probe {args:?}: non-UTF-8"))
    };
    let verbose_version = run(&["-vV"])?.trim_end().to_owned();
    let printed = run(&["--print", "sysroot"])?;
    if Path::new(printed.trim_end()) != sysroot {
        return Err(
            "compiler resolves a different sysroot (a proxy, not a toolchain binary)".into(),
        );
    }

    let mut covered = Vec::new();
    let (compiler_sig, compiler_binary_digest) =
        digest_stable(compiler).map_err(|error| format!("hash compiler: {error}"))?;
    covered.push((compiler.to_path_buf(), compiler_sig));

    let lib = sysroot.join("lib");
    let mut runtime = Vec::new();
    let mut entries: Vec<PathBuf> = std::fs::read_dir(&lib)
        .map_err(|error| format!("read {}: {error}", lib.display()))?
        .filter_map(|entry| entry.ok().map(|entry| entry.path()))
        .collect();
    entries.sort();
    for path in entries {
        let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
        if !name.contains(".so") || lstat_regular(&path).is_err() {
            continue;
        }
        let (sig, digest) =
            digest_stable(&path).map_err(|error| format!("hash {name}: {error}"))?;
        covered.push((path.clone(), sig));
        runtime.push(digest);
    }

    // Every file below lib/rustlib/<target>/lib: std and friends, which a
    // compile links metadata and inlinable code from.
    let rustlib = lib.join("rustlib");
    let mut tree = Vec::new();
    let mut targets: Vec<PathBuf> = std::fs::read_dir(&rustlib)
        .map_err(|error| format!("read {}: {error}", rustlib.display()))?
        .filter_map(|entry| entry.ok().map(|entry| entry.path().join("lib")))
        .filter(|path| path.is_dir())
        .collect();
    targets.sort();
    while let Some(directory) = targets.pop() {
        let entries = std::fs::read_dir(&directory)
            .map_err(|error| format!("read {}: {error}", directory.display()))?;
        for entry in entries {
            let path = entry.map_err(|error| error.to_string())?.path();
            let meta = std::fs::symlink_metadata(&path).map_err(|error| error.to_string())?;
            if meta.is_dir() {
                targets.push(path);
            } else if meta.is_file() {
                let (sig, digest) =
                    digest_stable(&path).map_err(|error| format!("hash sysroot: {error}"))?;
                let relative = path
                    .strip_prefix(sysroot)
                    .map_err(|_| "sysroot member escaped")?
                    .to_str()
                    .ok_or("non-UTF-8 sysroot member")?
                    .to_owned();
                covered.push((path, sig));
                tree.push((relative, digest));
            }
        }
    }
    tree.sort_by(|a, b| a.0.cmp(&b.0));
    let mut enc = CanonicalEncoder::new();
    enc.u64(tree.len() as u64);
    for (relative, digest) in &tree {
        enc.str(relative).str(digest.domain).bytes(&digest.bytes);
    }
    Ok(ProbedToolchain {
        facts: ToolchainFacts {
            compiler_binary_digest,
            verbose_version,
            sysroot_root_digest: compute(DOMAIN_SYSROOT_TREE, &enc.finish()),
            runtime_libraries: runtime,
        },
        covered,
    })
}

/// The memoized observation state shared by every edge connection.
#[derive(Debug, Default)]
pub struct LiveFacts {
    files: Mutex<HashMap<PathBuf, (FileSig, TypedDigest)>>,
    toolchains: Mutex<HashMap<PathBuf, Slot<ProbedToolchain>>>,
    packages: Mutex<HashMap<PackageKey, Slot<PackageFacts>>>,
    candidates: Mutex<HashMap<PathBuf, (FileSig, Arc<CandidateObservation>)>>,
    warming: Mutex<usize>,
}

type PackageKey = (PathBuf, DependencySourceKind, Option<PathBuf>);

impl LiveFacts {
    /// Empty state.
    #[must_use]
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    /// The locator-exact dependency closure of a planned compile, with the
    /// exact identity of each direct extern. Cold closures larger than
    /// [`SYNCHRONOUS_DEPENDENCY_BYTES`] warm in the bounded background pool.
    ///
    /// # Errors
    /// [`FactsMiss`]; a reachable proc-macro or dylib refuses.
    pub fn dependencies(
        self: &Arc<Self>,
        plan: &DependencyActionPlan,
    ) -> Result<Arc<DependencyFacts>, FactsMiss> {
        let request = dependency_request(plan).map_err(FactsMiss::Refused)?;
        match close_dependencies(self, &request, Some(SYNCHRONOUS_DEPENDENCY_BYTES)) {
            Ok(closure) => Ok(Arc::new(DependencyFacts {
                directories: closure.directories,
                externs: closure.externs,
                request,
                read: closure.read,
                facts: Arc::clone(self),
            })),
            Err(reason) if reason == COLD_BUDGET_EXHAUSTED => {
                // Fill the memo off the critical path; this compile runs
                // normally. A full pool simply leaves the next request cold.
                self.start_warm(move |facts| {
                    let _ = close_dependencies(facts, &request, None);
                });
                Err(FactsMiss::Pending)
            }
            Err(reason) => Err(FactsMiss::Refused(reason)),
        }
    }

    /// Observe one crate file through the identity-keyed memo: its identity
    /// now, its observation, and the bytes read from disk (0 on a hit).
    fn candidate(
        &self,
        path: &Path,
        flavor: CrateFlavor,
    ) -> Result<(FileSig, Arc<CandidateObservation>, u64), String> {
        let now = lstat_regular(path).map_err(|error| format!("{}: {error}", path.display()))?;
        if let Ok(memo) = self.candidates.lock()
            && let Some((sig, observation)) = memo.get(path)
            && *sig == now
        {
            return Ok((now, Arc::clone(observation), 0));
        }
        let (sig, bytes) = read_stable(path, MAX_CANDIDATE_FILE_BYTES)
            .map_err(|error| format!("{}: {error}", path.display()))?;
        let exact = object_digest(&bytes).map_err(|error| error.to_string())?;
        let observation = Arc::new(CandidateObservation {
            read: read_candidate(flavor, &bytes, exact.clone()),
            exact: exact.clone(),
        });
        self.remember(path, sig, exact);
        if let Ok(mut memo) = self.candidates.lock() {
            if memo.len() >= MAX_MEMOIZED_CANDIDATES {
                memo.clear();
            }
            memo.insert(path.to_path_buf(), (sig, Arc::clone(&observation)));
        }
        Ok((sig, observation, sig.size))
    }

    fn start_warm(self: &Arc<Self>, work: impl FnOnce(&Self) + Send + 'static) -> bool {
        {
            let Ok(mut warming) = self.warming.lock() else {
                return false;
            };
            if *warming >= MAX_WARMING {
                return false;
            }
            *warming += 1;
        }
        let facts = Arc::clone(self);
        let spawned = std::thread::Builder::new()
            .name("rabs-facts-warm".to_owned())
            .spawn(move || {
                work(&facts);
                if let Ok(mut warming) = facts.warming.lock() {
                    *warming -= 1;
                }
            });
        if spawned.is_err()
            && let Ok(mut warming) = self.warming.lock()
        {
            *warming -= 1;
        }
        spawned.is_ok()
    }

    /// The content digest of a regular file, memoized by identity.
    ///
    /// # Errors
    /// I/O failures and identity movement while hashing.
    pub fn file_digest(&self, path: &Path) -> std::io::Result<TypedDigest> {
        let now = lstat_regular(path)?;
        if let Ok(files) = self.files.lock()
            && let Some((sig, digest)) = files.get(path)
            && *sig == now
        {
            return Ok(digest.clone());
        }
        let (sig, digest) = digest_stable(path)?;
        self.remember(path, sig, digest.clone());
        Ok(digest)
    }

    /// Record a digest the caller established by reading or writing the
    /// exact bytes (ingested outputs, materialized hits).
    pub fn remember(&self, path: &Path, sig: FileSig, digest: TypedDigest) {
        if let Ok(mut files) = self.files.lock() {
            if files.len() >= MAX_MEMOIZED_FILES {
                files.clear();
            }
            files.insert(path.to_path_buf(), (sig, digest));
        }
    }

    /// Facts for an absolute `<sysroot>/bin/rustc`. A first request warms
    /// in the background and answers [`FactsMiss::Pending`].
    ///
    /// # Errors
    /// [`FactsMiss`].
    pub fn toolchain(
        self: &Arc<Self>,
        compiler: &Path,
        env: &[(String, String)],
    ) -> Result<ToolchainFacts, FactsMiss> {
        if !compiler.is_absolute() {
            return Err(FactsMiss::Refused("compiler path is not absolute".into()));
        }
        {
            let mut toolchains = self
                .toolchains
                .lock()
                .map_err(|_| FactsMiss::Refused("toolchain memo poisoned".into()))?;
            match toolchains.get(compiler) {
                Some(Slot::Ready(probed)) if probed.still_current() => {
                    return Ok(probed.facts.clone());
                }
                Some(Slot::Warming) => return Err(FactsMiss::Pending),
                Some(Slot::Failed { reason, at }) if at.elapsed() < PROBE_RETRY => {
                    return Err(FactsMiss::Refused(reason.clone()));
                }
                _ => {}
            }
            toolchains.insert(compiler.to_path_buf(), Slot::Warming);
        }
        let compiler_owned = compiler.to_path_buf();
        let env = env.to_vec();
        let started = self.start_warm(move |facts| {
            let slot = match probe_toolchain(&compiler_owned, &env) {
                Ok(probed) => Slot::Ready(Arc::new(probed)),
                Err(reason) => Slot::Failed {
                    reason,
                    at: Instant::now(),
                },
            };
            if let Ok(mut toolchains) = facts.toolchains.lock() {
                toolchains.insert(compiler_owned, slot);
            }
        });
        if !started && let Ok(mut toolchains) = self.toolchains.lock() {
            toolchains.remove(compiler);
        }
        Err(FactsMiss::Pending)
    }

    /// The sealed source tree of a registry package or complete Cargo Git
    /// checkout. Git metadata is excluded only for a Git checkout; all
    /// other source-policy exclusions refuse the capture. Small trees are
    /// captured on the request path; larger ones warm in the background.
    ///
    /// # Errors
    /// [`FactsMiss`].
    pub fn package(
        self: &Arc<Self>,
        root: &Path,
        source_kind: DependencySourceKind,
        generated_root: Option<&Path>,
    ) -> Result<Arc<PackageFacts>, FactsMiss> {
        let key = (
            root.to_path_buf(),
            source_kind,
            generated_root.map(Path::to_path_buf),
        );
        let (members, bytes) = walk_package(root, source_kind).map_err(FactsMiss::Refused)?;
        let (generated, generated_bytes) = match generated_root {
            Some(root) => {
                let (observation, size) = observe_generated(root).map_err(FactsMiss::Refused)?;
                (Some(observation), size)
            }
            None => (None, 0),
        };
        let bytes = bytes.saturating_add(generated_bytes);
        {
            let packages = self
                .packages
                .lock()
                .map_err(|_| FactsMiss::Refused("package memo poisoned".into()))?;
            match packages.get(&key) {
                Some(Slot::Ready(facts))
                    if facts.members == members && facts.generated == generated =>
                {
                    return Ok(Arc::clone(facts));
                }
                Some(Slot::Warming) => return Err(FactsMiss::Pending),
                Some(Slot::Failed { reason, at }) if at.elapsed() < PROBE_RETRY => {
                    return Err(FactsMiss::Refused(reason.clone()));
                }
                _ => {}
            }
        }
        if bytes <= SYNCHRONOUS_PACKAGE_BYTES {
            let captured =
                capture_package(root, source_kind, generated_root).map_err(FactsMiss::Refused)?;
            let captured = Arc::new(captured);
            self.retain_package(key, Slot::Ready(Arc::clone(&captured)));
            return Ok(captured);
        }
        self.retain_package(key.clone(), Slot::Warming);
        let owned = key.clone();
        let started = self.start_warm(move |facts| {
            let slot = match capture_package(&owned.0, owned.1, owned.2.as_deref()) {
                Ok(captured) => Slot::Ready(Arc::new(captured)),
                Err(reason) => Slot::Failed {
                    reason,
                    at: Instant::now(),
                },
            };
            facts.retain_package(owned, slot);
        });
        if !started && let Ok(mut packages) = self.packages.lock() {
            packages.remove(&key);
        }
        Err(FactsMiss::Pending)
    }

    fn retain_package(&self, key: PackageKey, slot: Slot<PackageFacts>) {
        let Ok(mut packages) = self.packages.lock() else {
            return;
        };
        let retained: u64 = packages
            .values()
            .map(|slot| match slot {
                Slot::Ready(facts) => facts.bytes,
                _ => 0,
            })
            .sum();
        if retained > MAX_RETAINED_PACKAGE_BYTES {
            packages.retain(|_, slot| !matches!(slot, Slot::Ready(_)));
        }
        packages.insert(key, slot);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn generated_fixture() -> (tempfile::TempDir, DependencyActionPlan) {
        let dir = tempfile::tempdir().unwrap();
        let cargo_home = dir.path().join("cargo-home");
        let source = cargo_home.join("registry/src/index/generated-1.0");
        let generated = dir.path().join("build-script/out");
        let output = dir.path().join("compiler-output");
        for root in [&source, &generated, &output] {
            std::fs::create_dir_all(root).unwrap();
        }
        std::fs::write(
            source.join("lib.rs"),
            b"include!(concat!(env!(\"OUT_DIR\"), \"/value.rs\"));",
        )
        .unwrap();
        std::fs::write(generated.join("value.rs"), b"pub const VALUE:u32=17;").unwrap();
        std::fs::create_dir(generated.parent().unwrap().join("run")).unwrap();
        std::fs::write(
            generated.parent().unwrap().join("run/stdout"),
            b"cargo::rustc-cfg=generated\n",
        )
        .unwrap();
        std::fs::write(
            generated.parent().unwrap().join("run/root-output"),
            generated.to_str().unwrap(),
        )
        .unwrap();
        let argv = vec![
            "/toolchain/bin/rustc".into(),
            source.join("lib.rs").to_str().unwrap().into(),
            "--crate-name=generated".into(),
            "--crate-type=rlib".into(),
            "--emit=dep-info,metadata,link".into(),
            "--error-format=json".into(),
            "--cap-lints=allow".into(),
            "--out-dir".into(),
            output.to_str().unwrap().into(),
        ];
        let env = vec![
            ("CARGO_HOME".into(), cargo_home.to_str().unwrap().into()),
            ("CARGO_MANIFEST_DIR".into(), source.to_str().unwrap().into()),
            ("CARGO_PKG_NAME".into(), "generated".into()),
            ("OUT_DIR".into(), generated.to_str().unwrap().into()),
        ];
        let plan = rabs_key::live_dependency::plan_dependency_action(
            rabs_key::live_dependency::LiveRustcRequest {
                argv: &argv,
                cwd: source.to_str().unwrap(),
                env: &env,
                build_script_env: Some(&[]),
                generated_inputs: true,
            },
            "x86_64-unknown-linux-gnu",
        )
        .unwrap();
        (dir, plan)
    }

    #[test]
    fn generated_inputs_capture_revalidate_bytes_members_and_script_record() {
        let (_dir, plan) = generated_fixture();
        let source = Path::new(&plan.source_root);
        let generated = Path::new(plan.generated_root.as_ref().unwrap());
        let facts = LiveFacts::new();
        let capture = || {
            facts
                .package(source, plan.source_kind, Some(generated))
                .unwrap()
        };
        let first = capture();
        assert_eq!(first.generated_files.len(), 1);
        assert_eq!(
            first.snapshot.file_bytes(GENERATED_ROOT, "value.rs"),
            Some(b"pub const VALUE:u32=17;".as_slice())
        );
        assert!(Arc::ptr_eq(&first, &capture()));
        first.verify_unchanged(source).unwrap();
        first.verify_generated_disjoint(&plan).unwrap();
        // The same source root requested without generated inputs has a
        // distinct memo and cannot inherit the broader capture accidentally.
        let plain = facts.package(source, plan.source_kind, None).unwrap();
        assert!(plain.generated_files.is_empty());
        assert!(plain.snapshot.manifest(GENERATED_ROOT).is_none());
        std::fs::write(generated.join("value.rs"), b"pub const VALUE:u32=23;").unwrap();
        assert!(first.verify_unchanged(source).is_err());
        let changed = capture();
        assert_ne!(first.generated_files, changed.generated_files);
        let hidden = generated.join("transient.rs");
        std::fs::write(&hidden, b"a new generated member").unwrap();
        assert!(changed.verify_unchanged(source).is_err());
        let added = capture();
        assert_eq!(added.generated_files.len(), 2);
        std::fs::rename(
            &hidden,
            generated.parent().unwrap().join("moved-transient.rs"),
        )
        .unwrap();
        assert!(added.verify_unchanged(source).is_err());
        assert!(
            changed.verify_unchanged(source).is_err(),
            "directory generation remembers transient membership"
        );
        let current = capture();
        std::fs::write(
            generated.parent().unwrap().join("run/stdout"),
            b"cargo::rustc-env=MY_VALUE=example\n",
        )
        .unwrap();
        assert!(current.verify_unchanged(source).is_err());
        assert_ne!(current.build_script_output, capture().build_script_output);
    }

    #[test]
    fn generated_inputs_refuse_symlinks_and_compiler_output_aliases() {
        let (dir, plan) = generated_fixture();
        let source = Path::new(&plan.source_root);
        let generated = Path::new(plan.generated_root.as_ref().unwrap());
        let facts = LiveFacts::new();
        let captured = facts
            .package(source, plan.source_kind, Some(generated))
            .unwrap();
        let output = Path::new(&plan.out_dir).join(plan.output_names()[0].clone());
        std::fs::hard_link(generated.join("value.rs"), &output).unwrap();
        assert!(
            captured
                .verify_generated_disjoint(&plan)
                .unwrap_err()
                .contains("aliases a declared compiler output")
        );
        std::fs::rename(&output, dir.path().join("displaced-output")).unwrap();
        let alias = dir.path().join("script-parent-alias");
        std::os::unix::fs::symlink(generated.parent().unwrap(), &alias).unwrap();
        assert!(
            facts
                .package(source, plan.source_kind, Some(&alias.join("out")))
                .is_err()
        );
        let moved = generated.parent().unwrap().join("moved-out");
        std::fs::rename(generated, &moved).unwrap();
        std::os::unix::fs::symlink(&moved, generated).unwrap();
        assert!(captured.verify_unchanged(source).is_err());
        assert!(
            facts
                .package(source, plan.source_kind, Some(generated))
                .is_err()
        );

        let (_other, other_plan) = generated_fixture();
        let other_generated = Path::new(other_plan.generated_root.as_ref().unwrap());
        std::os::unix::fs::symlink("value.rs", other_generated.join("alias.rs")).unwrap();
        assert!(
            LiveFacts::new()
                .package(
                    Path::new(&other_plan.source_root),
                    other_plan.source_kind,
                    Some(other_generated)
                )
                .is_err()
        );
    }

    #[test]
    fn generated_inputs_empty_tree_still_requires_real_cargo_output_record() {
        let (dir, plan) = generated_fixture();
        let generated = Path::new(plan.generated_root.as_ref().unwrap());
        std::fs::rename(
            generated.join("value.rs"),
            dir.path().join("displaced-value.rs"),
        )
        .unwrap();
        let facts = LiveFacts::new();
        let captured = facts
            .package(
                Path::new(&plan.source_root),
                plan.source_kind,
                Some(generated),
            )
            .unwrap();
        assert!(captured.generated_files.is_empty());
        assert!(
            captured
                .snapshot
                .manifest(GENERATED_ROOT)
                .unwrap()
                .members
                .is_empty()
        );
        std::fs::rename(
            generated.parent().unwrap().join("run/stdout"),
            dir.path().join("displaced-cargo-output"),
        )
        .unwrap();
        assert!(
            captured
                .verify_unchanged(Path::new(&plan.source_root))
                .is_err()
        );
        assert!(
            facts
                .package(
                    Path::new(&plan.source_root),
                    plan.source_kind,
                    Some(generated)
                )
                .is_err()
        );
    }

    const HASH_A: &str = "aaaaaaaaaaaaaaaa";
    const HASH_B: &str = "bbbbbbbbbbbbbbbb";
    const HASH_MACRO: &str = "dddddddddddddddd";

    /// Serialized-metadata-shaped bytes referencing the given extra filenames.
    fn metadata(references: &[&str], salt: &str) -> Vec<u8> {
        let mut bytes = b"rust\0\0\0\x0a".to_vec();
        bytes.extend_from_slice(salt.as_bytes());
        for reference in references {
            bytes.extend_from_slice(format!("\x11-{reference}\x01").as_bytes());
        }
        bytes
    }

    /// An `ar` archive whose `lib.rmeta` member stores the metadata raw.
    fn rlib(metadata: &[u8]) -> Vec<u8> {
        let mut out = b"!<arch>\n".to_vec();
        let header = format!(
            "{:<16}{:<12}{:<6}{:<6}{:<8}{:<10}`\n",
            "lib.rmeta/",
            0,
            0,
            0,
            644,
            metadata.len()
        );
        out.extend_from_slice(header.as_bytes());
        out.extend_from_slice(metadata);
        if metadata.len() % 2 == 1 {
            out.push(b'\n');
        }
        out
    }

    /// Cargo's layout: one directory is the out-dir and the search path;
    /// the compile's direct extern is `libb`, which depends on `liba`.
    fn cargo_layout() -> (tempfile::TempDir, PathBuf, DependencyRequest) {
        let dir = tempfile::tempdir().unwrap();
        let deps = dir.path().join("deps");
        std::fs::create_dir(&deps).unwrap();
        std::fs::write(
            deps.join(format!("liba-{HASH_A}.rmeta")),
            metadata(&[], "a"),
        )
        .unwrap();
        std::fs::write(
            deps.join(format!("libb-{HASH_B}.rmeta")),
            metadata(&[HASH_A], "b"),
        )
        .unwrap();
        let request = DependencyRequest {
            roots: vec![deps.clone()],
            out_dir: deps.clone(),
            outputs: vec![
                "libcurrent-cccccccccccccccc.rmeta".into(),
                "libcurrent-cccccccccccccccc.rlib".into(),
                "current-cccccccccccccccc.d".into(),
            ],
            seeds: vec![(0, format!("libb-{HASH_B}.rmeta"))],
        };
        (dir, deps, request)
    }

    fn capture(facts: &Arc<LiveFacts>, request: &DependencyRequest) -> DependencyFacts {
        let closure = close_dependencies(facts, request, None).unwrap();
        DependencyFacts {
            directories: closure.directories,
            externs: closure.externs,
            request: request.clone(),
            read: closure.read,
            facts: Arc::clone(facts),
        }
    }

    #[test]
    fn referenced_candidates_survive_sibling_churn_and_pipelined_rlibs() {
        let (_dir, deps, request) = cargo_layout();
        let facts = LiveFacts::new();
        let first = capture(&facts, &request);
        assert_eq!(first.directories[0].groups.len(), 1);
        assert_eq!(
            first.directories[0].groups[0].stem,
            format!("liba-{HASH_A}")
        );
        assert_eq!(first.externs.len(), 1);
        // A parallel build writes siblings into the same directory while
        // this compile runs: other crates, an unrelated proc-macro, a test
        // executable, rustc temporaries and this compile's own outputs.
        std::fs::write(
            deps.join("libother-eeeeeeeeeeeeeeee.rmeta"),
            metadata(&[], "o"),
        )
        .unwrap();
        std::fs::write(deps.join(format!("libmacro-{HASH_MACRO}.so")), b"\x7fELF").unwrap();
        std::fs::write(deps.join("proj-ffffffffffffffff"), b"test executable").unwrap();
        std::fs::write(deps.join("x-0.x.1a2b-cgu.0.rcgu.o"), b"object").unwrap();
        std::fs::create_dir(deps.join("rmetaAbC123")).unwrap();
        std::fs::write(
            deps.join("libcurrent-cccccccccccccccc.rmeta"),
            b"new output",
        )
        .unwrap();
        first.verify_unchanged().unwrap();
        // Pipelining finishes the dependency's rlib later: same metadata.
        std::fs::write(
            deps.join(format!("liba-{HASH_A}.rlib")),
            rlib(&metadata(&[], "a")),
        )
        .unwrap();
        first.verify_unchanged().unwrap();
        let later = capture(&facts, &request);
        assert_eq!(later.directories, first.directories);
        assert_eq!(later.externs, first.externs);
    }

    #[test]
    fn referenced_changes_refuse_verification() {
        // A referenced crate's metadata is rewritten.
        let (_dir, deps, request) = cargo_layout();
        let facts = LiveFacts::new();
        let first = capture(&facts, &request);
        std::fs::write(
            deps.join(format!("liba-{HASH_A}.rmeta")),
            metadata(&[], "A"),
        )
        .unwrap();
        assert!(first.verify_unchanged().is_err());
        // Rewritten with identical bytes: the file read for the key moved.
        let (_dir, deps, request) = cargo_layout();
        let first = capture(&facts, &request);
        let path = deps.join(format!("liba-{HASH_A}.rmeta"));
        let bytes = std::fs::read(&path).unwrap();
        std::fs::remove_file(&path).unwrap();
        std::fs::write(&path, bytes).unwrap();
        assert!(first.verify_unchanged().is_err());
        // A late rlib whose metadata disagrees with the rmeta.
        let (_dir, deps, request) = cargo_layout();
        let first = capture(&facts, &request);
        std::fs::write(
            deps.join(format!("liba-{HASH_A}.rlib")),
            rlib(&metadata(&[], "different")),
        )
        .unwrap();
        assert!(first.verify_unchanged().is_err());
        // The direct extern itself changes.
        let (_dir, deps, request) = cargo_layout();
        let first = capture(&facts, &request);
        std::fs::write(
            deps.join(format!("libb-{HASH_B}.rmeta")),
            metadata(&[HASH_A], "b2"),
        )
        .unwrap();
        assert!(first.verify_unchanged().is_err());
    }

    #[test]
    fn a_reachable_proc_macro_refuses_and_roots_must_be_real_directories() {
        let (dir, deps, request) = cargo_layout();
        let facts = LiveFacts::new();
        std::fs::write(deps.join(format!("libmacro-{HASH_MACRO}.so")), b"\x7fELF").unwrap();
        std::fs::write(
            deps.join(format!("libb-{HASH_B}.rmeta")),
            metadata(&[HASH_A, HASH_MACRO], "b"),
        )
        .unwrap();
        let error = close_dependencies(&facts, &request, None).err().unwrap();
        assert!(error.contains("proc-macro"), "{error}");
        // Move the SAME member inodes behind a root symlink.
        let (dir2, deps2, request2) = cargo_layout();
        let captured = capture(&facts, &request2);
        let moved = dir2.path().join("moved");
        std::fs::rename(&deps2, &moved).unwrap();
        std::os::unix::fs::symlink(&moved, &deps2).unwrap();
        assert!(captured.verify_unchanged().is_err());
        drop(dir);
    }

    #[test]
    fn dependency_candidates_refuse_physical_output_aliases() {
        let (_dir, deps, request) = cargo_layout();
        let facts = LiveFacts::new();
        let captured = capture(&facts, &request);
        captured.verify_unchanged().unwrap();
        // An alias created after keying must also refuse at pre-hit / completion.
        std::fs::hard_link(
            deps.join(format!("liba-{HASH_A}.rmeta")),
            deps.join("libcurrent-cccccccccccccccc.rmeta"),
        )
        .unwrap();
        assert!(
            captured
                .verify_unchanged()
                .unwrap_err()
                .contains("aliases a declared output")
        );

        // The root itself is not a symlink; its parent is. Lexically disjoint
        // roots still identify the same real directory and cannot be input/output.
        let (dir, deps, mut request) = cargo_layout();
        let alias_parent = dir.path().join("alias");
        std::os::unix::fs::symlink(dir.path(), &alias_parent).unwrap();
        request.roots = vec![alias_parent.join("deps")];
        request.out_dir = deps;
        assert!(
            close_dependencies(&facts, &request, None)
                .err()
                .unwrap()
                .contains("aliases the output directory")
        );
    }

    #[test]
    fn build_script_records_are_read_from_either_cargo_layout_for_this_out_dir_only() {
        let dir = tempfile::tempdir().unwrap();
        let stdout = "cargo:rustc-cfg=x\ncargo:rustc-env=FLAVOR=fast\ncargo::rustc-env=A=b\n";
        // Classic layout: build/<pkg>-<hash>/{out,output,root-output}.
        let classic = dir.path().join("build/demo-0123456789abcdef");
        std::fs::create_dir_all(classic.join("out")).unwrap();
        std::fs::write(classic.join("output"), stdout).unwrap();
        std::fs::write(
            classic.join("root-output"),
            classic.join("out").as_os_str().as_encoded_bytes(),
        )
        .unwrap();
        assert_eq!(
            build_script_env(&classic.join("out")).unwrap(),
            ["A", "FLAVOR"]
        );
        // Build-dir layout: build/<pkg>/<hash>/{out,run/stdout,run/root-output}.
        let unit = dir.path().join("build/demo/0123456789abcdef");
        std::fs::create_dir_all(unit.join("out")).unwrap();
        std::fs::create_dir_all(unit.join("run")).unwrap();
        std::fs::write(unit.join("run/stdout"), stdout).unwrap();
        std::fs::write(
            unit.join("run/root-output"),
            unit.join("out").as_os_str().as_encoded_bytes(),
        )
        .unwrap();
        assert_eq!(
            build_script_env(&unit.join("out")).unwrap(),
            ["A", "FLAVOR"]
        );
        // A record naming another OUT_DIR is not this script's record.
        std::fs::write(unit.join("run/root-output"), b"/elsewhere/out").unwrap();
        assert!(build_script_env(&unit.join("out")).is_err());
        // No record, a non-`out` directory, or a relative path refuse.
        let bare = dir.path().join("build/bare-1/out");
        std::fs::create_dir_all(&bare).unwrap();
        assert!(build_script_env(&bare).is_err());
        assert!(build_script_env(&classic).is_err());
        assert!(build_script_env(Path::new("relative/out")).is_err());
    }

    #[test]
    fn cold_closures_respect_the_request_budget_and_warm_through_the_memo() {
        let (_dir, _deps, request) = cargo_layout();
        let facts = LiveFacts::new();
        assert_eq!(
            close_dependencies(&facts, &request, Some(1)).err().unwrap(),
            COLD_BUDGET_EXHAUSTED
        );
        // A warm memo reads nothing from disk, so any budget suffices.
        close_dependencies(&facts, &request, None).unwrap();
        close_dependencies(&facts, &request, Some(0)).unwrap();
    }

    #[test]
    fn stable_reads_bind_identity_and_memo_revalidates() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("libdep.rmeta");
        std::fs::write(&path, b"first").unwrap();
        let facts = LiveFacts::new();
        let first = facts.file_digest(&path).unwrap();
        assert_eq!(facts.file_digest(&path).unwrap(), first);
        let (_, bytes) = read_stable(&path, 1024).unwrap();
        assert_eq!(bytes, b"first");
        assert!(read_stable(&path, 2).is_err());
        // Same length, new content: the memo must not answer stale.
        std::fs::write(&path, b"other").unwrap();
        assert_ne!(facts.file_digest(&path).unwrap(), first);
        let link = dir.path().join("link");
        std::os::unix::fs::symlink(&path, &link).unwrap();
        assert!(facts.file_digest(&link).is_err());
    }

    #[test]
    fn package_capture_covers_the_complete_tree_and_detects_change() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("itoa-1.0.15");
        std::fs::create_dir_all(root.join("src")).unwrap();
        std::fs::write(root.join("Cargo.toml"), b"[package]\n").unwrap();
        std::fs::write(root.join("src/lib.rs"), b"pub fn f() {}\n").unwrap();
        let facts = LiveFacts::new();
        let captured = facts
            .package(&root, DependencySourceKind::RegistryPackage, None)
            .unwrap();
        assert_eq!(
            captured
                .snapshot
                .file_bytes(PACKAGE_ROOT, "src/lib.rs")
                .unwrap(),
            b"pub fn f() {}\n"
        );
        assert!(Arc::ptr_eq(
            &captured,
            &facts
                .package(&root, DependencySourceKind::RegistryPackage, None)
                .unwrap()
        ));
        captured.verify_unchanged(&root).unwrap();
        std::fs::write(root.join("src/extra.rs"), b"").unwrap();
        assert!(captured.verify_unchanged(&root).is_err());
        assert!(!Arc::ptr_eq(
            &captured,
            &facts
                .package(&root, DependencySourceKind::RegistryPackage, None)
                .unwrap()
        ));
        std::os::unix::fs::symlink("lib.rs", root.join("src/alias.rs")).unwrap();
        assert!(matches!(
            facts.package(&root, DependencySourceKind::RegistryPackage, None),
            Err(FactsMiss::Refused(_))
        ));
    }

    fn write_git_checkout(root: &Path) {
        std::fs::create_dir_all(root.join("crates/dep/src")).unwrap();
        std::fs::create_dir_all(root.join(".git/objects")).unwrap();
        std::fs::write(root.join("Cargo.toml"), b"[workspace]\n").unwrap();
        std::fs::write(root.join("crates/dep/Cargo.toml"), b"[package]\n").unwrap();
        std::fs::write(
            root.join("crates/dep/src/lib.rs"),
            b"pub const README: &str = include_str!(\"../../../README.md\");\n",
        )
        .unwrap();
        std::fs::write(root.join("README.md"), b"first\n").unwrap();
        std::fs::write(root.join(".git/config"), b"private repository metadata\n").unwrap();
        // Traversing metadata would encounter an unsupported member. The
        // source walk must prune `.git` before inspecting its children.
        std::os::unix::fs::symlink("missing-object", root.join(".git/objects/link")).unwrap();
    }

    #[test]
    fn git_capture_never_reads_metadata_and_metadata_edits_preserve_the_memo() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("checkout");
        write_git_checkout(&root);
        let facts = LiveFacts::new();
        let captured = facts
            .package(&root, DependencySourceKind::GitCheckout, None)
            .unwrap();
        assert_eq!(captured.source_kind, DependencySourceKind::GitCheckout);
        assert_eq!(captured.files.len(), 4);
        assert!(
            captured
                .files
                .iter()
                .all(|(path, _, _)| path != ".git" && !path.starts_with(".git/"))
        );
        assert!(
            captured
                .snapshot
                .manifest(PACKAGE_ROOT)
                .unwrap()
                .members
                .keys()
                .all(|path| path != ".git" && !path.starts_with(".git/"))
        );
        assert!(
            captured
                .snapshot
                .file_bytes(PACKAGE_ROOT, ".git/config")
                .is_none()
        );

        std::fs::write(root.join(".git/config"), b"changed private metadata\n").unwrap();
        std::fs::write(root.join(".git/index"), b"new metadata\n").unwrap();
        captured.verify_unchanged(&root).unwrap();
        assert!(Arc::ptr_eq(
            &captured,
            &facts
                .package(&root, DependencySourceKind::GitCheckout, None)
                .unwrap()
        ));

        // A strict registry request for this same physical root must not
        // inherit the Git cache's permission to omit metadata.
        assert!(matches!(
            facts.package(&root, DependencySourceKind::RegistryPackage, None),
            Err(FactsMiss::Refused(_))
        ));
        assert!(Arc::ptr_eq(
            &captured,
            &facts
                .package(&root, DependencySourceKind::GitCheckout, None)
                .unwrap()
        ));
    }

    #[test]
    fn git_capture_binds_dirty_sibling_bytes_and_new_checkout_members() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("checkout");
        write_git_checkout(&root);
        let facts = LiveFacts::new();
        let captured = facts
            .package(&root, DependencySourceKind::GitCheckout, None)
            .unwrap();
        let file_digest = |capture: &PackageFacts, relative: &str| {
            capture
                .files
                .iter()
                .find(|(path, _, _)| path == relative)
                .unwrap()
                .1
                .clone()
        };
        let original = file_digest(&captured, "README.md");
        assert_eq!(
            captured.snapshot.file_bytes(PACKAGE_ROOT, "README.md"),
            Some(b"first\n".as_slice())
        );

        // The package lives at crates/dep, but its whole checkout is the
        // source closure. A same-length dirty sibling edit changes bytes
        // without changing the Cargo revision directory's name.
        std::fs::write(root.join("README.md"), b"other\n").unwrap();
        assert!(captured.verify_unchanged(&root).is_err());
        let dirty = facts
            .package(&root, DependencySourceKind::GitCheckout, None)
            .unwrap();
        assert!(!Arc::ptr_eq(&captured, &dirty));
        assert_ne!(file_digest(&dirty, "README.md"), original);
        assert_eq!(
            captured.snapshot.file_bytes(PACKAGE_ROOT, "README.md"),
            Some(b"first\n".as_slice()),
            "the admitted snapshot retains its original bytes"
        );
        std::fs::write(root.join("README.md"), b"first\n").unwrap();
        assert!(dirty.verify_unchanged(&root).is_err());
        let restored = facts
            .package(&root, DependencySourceKind::GitCheckout, None)
            .unwrap();
        assert_eq!(file_digest(&restored, "README.md"), original);

        std::fs::write(root.join("crates/new.rs"), b"// untracked input\n").unwrap();
        assert!(restored.verify_unchanged(&root).is_err());
        let added = facts
            .package(&root, DependencySourceKind::GitCheckout, None)
            .unwrap();
        assert_eq!(added.files.len(), restored.files.len() + 1);
        assert_eq!(
            added.snapshot.file_bytes(PACKAGE_ROOT, "crates/new.rs"),
            Some(b"// untracked input\n".as_slice())
        );
    }

    #[test]
    fn identical_source_trees_keep_distinct_capture_policy_memos() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("lib.rs"), b"pub fn f() {}\n").unwrap();
        let facts = LiveFacts::new();
        let git = facts
            .package(dir.path(), DependencySourceKind::GitCheckout, None)
            .unwrap();
        let registry = facts
            .package(dir.path(), DependencySourceKind::RegistryPackage, None)
            .unwrap();
        assert_eq!(git.files, registry.files);
        assert!(!Arc::ptr_eq(&git, &registry));
        assert_eq!(git.source_kind, DependencySourceKind::GitCheckout);
        assert_eq!(registry.source_kind, DependencySourceKind::RegistryPackage);
        assert!(Arc::ptr_eq(
            &git,
            &facts
                .package(dir.path(), DependencySourceKind::GitCheckout, None)
                .unwrap()
        ));
        assert!(Arc::ptr_eq(
            &registry,
            &facts
                .package(dir.path(), DependencySourceKind::RegistryPackage, None)
                .unwrap()
        ));
    }

    #[test]
    fn warm_package_and_verification_refuse_a_symlink_to_the_same_member_inodes() {
        for source_kind in [
            DependencySourceKind::RegistryPackage,
            DependencySourceKind::GitCheckout,
        ] {
            let dir = tempfile::tempdir().unwrap();
            let root = dir.path().join("source");
            std::fs::create_dir_all(root.join("src")).unwrap();
            std::fs::write(root.join("src/lib.rs"), b"pub fn f() {}\n").unwrap();
            let facts = LiveFacts::new();
            let captured = facts.package(&root, source_kind, None).unwrap();
            let (members, _) = walk_package(&root, source_kind).unwrap();

            let moved = dir.path().join("another-parent/source");
            std::fs::create_dir_all(moved.parent().unwrap()).unwrap();
            std::fs::rename(&root, &moved).unwrap();
            std::os::unix::fs::symlink(&moved, &root).unwrap();
            assert_eq!(
                walk_package(&moved, source_kind).unwrap().0,
                members,
                "the symlink points at precisely the original member identities"
            );
            assert!(matches!(
                facts.package(&root, source_kind, None),
                Err(FactsMiss::Refused(reason)) if reason.contains("root is not a real directory")
            ));
            assert!(
                captured
                    .verify_unchanged(&root)
                    .unwrap_err()
                    .contains("root is not a real directory")
            );
        }
    }

    #[test]
    fn git_metadata_file_or_link_is_pruned_but_other_exclusions_still_refuse() {
        for metadata_is_link in [false, true] {
            let dir = tempfile::tempdir().unwrap();
            std::fs::write(dir.path().join("lib.rs"), b"pub fn f() {}\n").unwrap();
            if metadata_is_link {
                std::os::unix::fs::symlink("absent", dir.path().join(".git")).unwrap();
            } else {
                std::fs::write(dir.path().join(".git"), b"gitdir: private-location\n").unwrap();
            }
            let facts = LiveFacts::new();
            let captured = facts
                .package(dir.path(), DependencySourceKind::GitCheckout, None)
                .unwrap();
            assert_eq!(captured.files.len(), 1);
            assert!(captured.snapshot.file_bytes(PACKAGE_ROOT, ".git").is_none());
            assert!(matches!(
                facts.package(dir.path(), DependencySourceKind::RegistryPackage, None),
                Err(FactsMiss::Refused(_))
            ));
        }

        for excluded in ["target/generated.rs", ".package-cache", ".env", "alias.rs"] {
            let dir = tempfile::tempdir().unwrap();
            write_git_checkout(dir.path());
            let path = dir.path().join(excluded);
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            if excluded == "alias.rs" {
                std::os::unix::fs::symlink("README.md", &path).unwrap();
            } else {
                std::fs::write(&path, b"excluded bytes\n").unwrap();
            }
            assert!(
                matches!(
                    LiveFacts::new().package(dir.path(), DependencySourceKind::GitCheckout, None),
                    Err(FactsMiss::Refused(_))
                ),
                "Git capture must still refuse {excluded}"
            );
        }
    }

    #[test]
    fn a_first_toolchain_request_warms_without_blocking() {
        let facts = LiveFacts::new();
        assert_eq!(
            facts.toolchain(Path::new("rustc"), &[]),
            Err(FactsMiss::Refused("compiler path is not absolute".into()))
        );
        let dir = tempfile::tempdir().unwrap();
        let fake = dir.path().join("bin/rustc");
        std::fs::create_dir_all(fake.parent().unwrap()).unwrap();
        std::fs::write(&fake, b"not a compiler").unwrap();
        assert_eq!(facts.toolchain(&fake, &[]), Err(FactsMiss::Pending));
        // The warm fails (not executable); the failure is remembered.
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            match facts.toolchain(&fake, &[]) {
                Err(FactsMiss::Refused(_)) => break,
                Err(FactsMiss::Pending) if Instant::now() < deadline => {
                    std::thread::sleep(Duration::from_millis(10));
                }
                other => panic!("unexpected probe outcome {other:?}"),
            }
        }
    }
}
