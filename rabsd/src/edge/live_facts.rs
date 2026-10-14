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
use rabs_key::live_dependency::{
    DependencyActionPlan, DependencyDirectoryFact, DependencySourceKind, ExternFact, ToolchainFacts,
};
use rabs_key::typed_digest::compute;
use rabs_protocol::result_identity::TypedDigest;
use rabs_sandbox::snapshot_capture::{
    MemberDisposition, MemberKind, SealedSourceSnapshot, capture_sealed_source, member_disposition,
};
use std::collections::{BTreeMap, HashMap};
use std::io::Read;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

mod toolchain_hashing;
mod toolchain_probe;

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
const MAX_DEPENDENCY_BYTES: u64 = 512 * 1024 * 1024;
const MAX_DEPENDENCY_FILES: usize = 4096;
const MAX_DEPENDENCY_MEMOS: usize = 128;

/// Identity of one filesystem object at one moment.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
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
    digest_stable_at(path, lstat_regular(path)?)
}

fn digest_stable_at(path: &Path, before: FileSig) -> std::io::Result<(FileSig, TypedDigest)> {
    let mut file = std::fs::File::open(path)?;
    let opened = file.metadata()?;
    if !opened.is_file() || FileSig::of(&opened) != before || lstat_regular(path)? != before {
        return Err(std::io::Error::other("file changed before it was hashed"));
    }
    let mut writer = StreamingObjectWriter::new(DigestRequest::default(), Some(before.size));
    let mut buffer = vec![0_u8; 256 * 1024];
    let mut remaining = before.size;
    while remaining > 0 {
        let limit =
            usize::try_from(remaining.min(buffer.len() as u64)).map_err(std::io::Error::other)?;
        let read = file.read(&mut buffer[..limit])?;
        if read == 0 {
            return Err(std::io::Error::other("file shrank while it was hashed"));
        }
        writer
            .write(&buffer[..read])
            .map_err(|error| std::io::Error::other(format!("{error:?}")))?;
        remaining -= read as u64;
    }
    let mut extra = [0_u8; 1];
    if file.read(&mut extra)? != 0 {
        return Err(std::io::Error::other("file grew while it was hashed"));
    }
    if FileSig::of(&file.metadata()?) != before || lstat_regular(path)? != before {
        return Err(std::io::Error::other("file changed while it was hashed"));
    }
    let digest = writer
        .finish()
        .map_err(|error| std::io::Error::other(format!("{error:?}")))?
        .atp_content_id;
    Ok((before, digest))
}

/// Files and directory generations observed BEFORE running either probe.
/// Unlike Cargo output directories, a toolchain must not change while an
/// action uses it. Retaining only positive files misses newly installed
/// libraries, newly populated target directories and transient membership.
#[derive(Debug)]
struct ToolchainInputs {
    compiler: (PathBuf, FileSig),
    runtime_libraries: Vec<(PathBuf, FileSig)>,
    sysroot_files: Vec<(PathBuf, FileSig)>,
    directories: Vec<(PathBuf, FileSig)>,
}

impl ToolchainInputs {
    fn record_directory(&mut self, path: &Path) -> Result<(), String> {
        let meta = std::fs::symlink_metadata(path)
            .map_err(|error| format!("toolchain directory {}: {error}", path.display()))?;
        if !meta.is_dir() {
            return Err(format!(
                "toolchain directory is not a real directory: {}",
                path.display()
            ));
        }
        self.directories
            .push((path.to_path_buf(), FileSig::of(&meta)));
        Ok(())
    }

    fn still_current(&self) -> bool {
        let directories_current = || {
            self.directories.iter().all(|(path, sig)| {
                std::fs::symlink_metadata(path)
                    .is_ok_and(|meta| meta.is_dir() && FileSig::of(&meta) == *sig)
            })
        };
        directories_current()
            && std::iter::once(&self.compiler)
                .chain(&self.runtime_libraries)
                .chain(&self.sysroot_files)
                .all(|(path, sig)| lstat_regular(path).is_ok_and(|now| now == *sig))
            && directories_current()
    }
}

/// Enumeration errors are unknown input closure, never an absent member.
fn toolchain_entries(directory: &Path) -> Result<Vec<PathBuf>, String> {
    let entries = std::fs::read_dir(directory)
        .map_err(|error| format!("read {}: {error}", directory.display()))?;
    let mut paths = entries
        .map(|entry| entry.map(|entry| entry.path()))
        .collect::<std::io::Result<Vec<_>>>()
        .map_err(|error| format!("enumerate {}: {error}", directory.display()))?;
    paths.sort();
    Ok(paths)
}

fn observe_toolchain_inputs(compiler: &Path, sysroot: &Path) -> Result<ToolchainInputs, String> {
    let compiler_sig = lstat_regular(compiler).map_err(|error| format!("compiler: {error}"))?;
    let mut inputs = ToolchainInputs {
        compiler: (compiler.to_path_buf(), compiler_sig),
        runtime_libraries: Vec::new(),
        sysroot_files: Vec::new(),
        directories: Vec::new(),
    };
    let lib = sysroot.join("lib");
    let rustlib = lib.join("rustlib");
    for root in [
        sysroot.to_path_buf(),
        sysroot.join("bin"),
        lib.clone(),
        rustlib.clone(),
    ] {
        inputs.record_directory(&root)?;
    }
    // Preserve the existing Linux runtime-library selection and key order.
    // A selected symlink or unreadable file can no longer disappear from
    // the closure just because lstat_regular failed.
    for path in toolchain_entries(&lib)? {
        let name = path
            .file_name()
            .and_then(|name| name.to_str())
            .ok_or("non-UTF-8 toolchain runtime entry")?;
        if name.contains(".so") {
            let sig = lstat_regular(&path)
                .map_err(|error| format!("toolchain runtime {name}: {error}"))?;
            inputs.runtime_libraries.push((path, sig));
        }
    }
    let mut pending = Vec::new();
    for target in toolchain_entries(&rustlib)? {
        let meta = std::fs::symlink_metadata(&target)
            .map_err(|error| format!("toolchain target {}: {error}", target.display()))?;
        if meta.is_file() {
            // rustup's installer/component records are not target libraries.
            // The containing directory still binds their membership changes.
            continue;
        }
        inputs.record_directory(&target)?;
        let target_lib = target.join("lib");
        match std::fs::symlink_metadata(&target_lib) {
            Ok(meta) if meta.is_dir() => pending.push(target_lib),
            // Keep the target parent even when lib/ does not yet exist. A
            // later target install must invalidate the warm toolchain memo.
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Ok(_) => return Err("toolchain target library root is not a real directory".into()),
            Err(error) => return Err(format!("toolchain target library root: {error}")),
        }
    }
    while let Some(directory) = pending.pop() {
        inputs.record_directory(&directory)?;
        for path in toolchain_entries(&directory)? {
            let meta = std::fs::symlink_metadata(&path)
                .map_err(|error| format!("toolchain input {}: {error}", path.display()))?;
            if meta.is_dir() {
                pending.push(path);
            } else if meta.is_file() {
                inputs.sysroot_files.push((path, FileSig::of(&meta)));
            } else {
                // No silent omission of a library or directory link. Linked
                // toolchains need a separately closed link/target profile.
                return Err(format!("non-regular toolchain input: {}", path.display()));
            }
        }
    }
    inputs.sysroot_files.sort_by(|a, b| a.0.cmp(&b.0));
    if !inputs.still_current() {
        return Err("toolchain inputs changed during enumeration".into());
    }
    Ok(inputs)
}

/// A probed toolchain plus its complete observed file/directory closure.
#[derive(Debug)]
struct ProbedToolchain {
    facts: ToolchainFacts,
    inputs: ToolchainInputs,
}

impl ProbedToolchain {
    fn still_current(&self) -> bool {
        self.inputs.still_current()
    }
}

/// Retain the exact toolchain observation used to key one live request.
/// This is a read-only witness, not a filesystem lock or execution lease.
/// A refreshed shared memo must never replace an in-flight request's original
/// file/directory generations, even when the replacement has identical bytes.
#[derive(Debug, Clone)]
pub struct ToolchainGuard {
    observed: Arc<ProbedToolchain>,
}

impl ToolchainGuard {
    /// Recheck the original compiler path and all its observed inputs without
    /// warming, probing, or adopting a newer memo generation.
    ///
    /// # Errors
    /// The request names another compiler, or its toolchain changed since keying.
    pub fn verify_unchanged(&self, compiler: &Path) -> Result<(), String> {
        if compiler != self.observed.inputs.compiler.0.as_path() {
            return Err("toolchain guard names a different compiler".into());
        }
        if !self.observed.still_current() {
            return Err("toolchain inputs changed after request keying".into());
        }
        Ok(())
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

/// Exact regular-file candidate closure for compiler dependency resolution.
/// Rechecked before a hit installs and after a local compiler exits.
#[derive(Debug)]
pub struct DependencyFacts {
    /// Pure facts bound to the action key, in first-use directory order.
    pub directories: Vec<DependencyDirectoryFact>,
    roots: Vec<(PathBuf, Vec<String>)>,
    members: Vec<Vec<(String, FileSig)>>,
    output: DependencyOutput,
    // Each root must remain the same real directory. Its generation is NOT
    // bound: Cargo's parallel, pipelined compiles churn scratch entries in
    // dependency directories that rustc never opens as crates. Candidate
    // membership and identity are compared exactly instead. What this gives
    // up: a crate-named file created AND removed between two walks is not
    // seen. rustc and Cargo only rename finished crates into place and never
    // remove them during a build; another local writer could, as it could
    // equally rewrite package sources the instant after a check.
    root_identities: Vec<(u64, u64)>,
}

impl DependencyFacts {
    /// Refuse changes to any candidate, member name, root or root type.
    pub fn verify_unchanged(&self) -> Result<(), String> {
        let (members, _) = walk_dependencies(&self.roots)?;
        reject_dependency_output_aliases(&self.roots, &members, &self.output)?;
        if dependency_root_identities(&self.roots)? != self.root_identities {
            return Err("dependency directory was replaced".into());
        }
        if members != self.members {
            return Err("dependency directory candidates changed".into());
        }
        Ok(())
    }
}

type DependencyRoots = Vec<(PathBuf, Vec<String>)>;
type DependencyMembers = Vec<Vec<(String, FileSig)>>;
type DependencyOutput = (PathBuf, Vec<String>);

fn dependency_root_identities(roots: &DependencyRoots) -> Result<Vec<(u64, u64)>, String> {
    roots
        .iter()
        .map(|(root, _)| dependency_root_identity(root))
        .collect()
}

fn reject_dependency_output_aliases(
    roots: &DependencyRoots,
    members: &DependencyMembers,
    (out_dir, output_names): &DependencyOutput,
) -> Result<(), String> {
    let optional_metadata = |path: &Path| match std::fs::symlink_metadata(path) {
        Ok(meta) => Ok(Some(meta)),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error.to_string()),
    };
    if let Some(output) = optional_metadata(out_dir)? {
        if !output.is_dir() {
            return Err("output root is not a real directory".into());
        }
        for (root, _) in roots {
            let dependency = std::fs::symlink_metadata(root).map_err(|error| error.to_string())?;
            if root != out_dir
                && dependency.dev() == output.dev()
                && dependency.ino() == output.ino()
            {
                return Err("dependency root aliases the output directory".into());
            }
        }
    }
    for name in output_names {
        if let Some(output) = optional_metadata(&out_dir.join(name))? {
            if !output.is_file() {
                return Err("declared output is not a regular file".into());
            }
            if members.iter().flatten().any(|(_, candidate)| {
                candidate.dev == output.dev() && candidate.ino == output.ino()
            }) {
                return Err("dependency candidate aliases a declared output".into());
            }
        }
    }
    Ok(())
}

/// Whether rustc's crate locator can ever open `name` as a crate for the
/// Linux targets this class admits. Every flavor `find_library_crate`
/// collects — rlib, rmeta, dylib (`.so`, proc-macros included), sdylib
/// interface (`.rs`) and the static-library rejections — is spelled
/// `lib<crate>…` (`rustc_metadata::locator`). Every other entry of a
/// dependency directory is some compile's private scratch or a non-crate
/// output: codegen units (`*.rcgu.o`), rustc's `rmeta*` and archive temp
/// directories, dep-info, executables. None is ever a compiler input, and
/// under Cargo's parallel, pipelined builds they appear and vanish while
/// unrelated crates compile, so binding them made identical builds refuse
/// or disagree by timing alone.
fn crate_locator_may_open(name: &std::ffi::OsStr) -> bool {
    name.as_encoded_bytes().starts_with(b"lib")
}

/// The same real directory, ignoring the generation churn that other
/// compiles' scratch files cause; candidate changes are compared exactly.
fn dependency_root_identity(root: &Path) -> Result<(u64, u64), String> {
    let meta = std::fs::symlink_metadata(root).map_err(|e| e.to_string())?;
    if !meta.is_dir() {
        return Err("dependency root is not a real directory".to_owned());
    }
    Ok((meta.dev(), meta.ino()))
}

fn walk_dependencies(roots: &DependencyRoots) -> Result<(DependencyMembers, u64), String> {
    let mut inventories = Vec::new();
    let mut bytes = 0_u64;
    let mut count = 0_usize;
    for (root, excluded_outputs) in roots {
        let before = dependency_root_identity(root)?;
        let mut members = Vec::new();
        for entry in std::fs::read_dir(root).map_err(|e| e.to_string())? {
            let entry = entry.map_err(|e| e.to_string())?;
            if !crate_locator_may_open(&entry.file_name()) {
                continue;
            }
            let name = entry
                .file_name()
                .into_string()
                .map_err(|_| "non-UTF-8 dependency candidate")?;
            // These exact files are this invocation's writes, never inputs.
            if excluded_outputs.contains(&name) {
                continue;
            }
            count += 1;
            if count > MAX_DEPENDENCY_FILES {
                return Err("dependency candidate count exceeds class bound".into());
            }
            let meta = std::fs::symlink_metadata(entry.path()).map_err(|e| e.to_string())?;
            // Proc-macro/dylib (`.so`), interface (`.rs`) and static-library
            // candidates stay refusals: the class keys plain Rust metadata.
            if !meta.is_file() || !(name.ends_with(".rlib") || name.ends_with(".rmeta")) {
                return Err(format!("unsupported dependency directory member {name}"));
            }
            members.push((name, FileSig::of(&meta)));
        }
        if dependency_root_identity(root)? != before {
            return Err("dependency directory changed while enumerating".into());
        }
        let members = metadata_shadowed_rlibs_removed(members)?;
        for (_, sig) in &members {
            bytes = bytes
                .checked_add(sig.size)
                .ok_or("dependency byte count overflow")?;
            if bytes > MAX_DEPENDENCY_BYTES {
                return Err("dependency candidate bytes exceed class bound".into());
            }
        }
        inventories.push(members);
    }
    Ok((inventories, bytes))
}

/// The class only compiles libraries, so rustc needs nothing but crate
/// METADATA from dependencies (`only_needs_metadata` in the locator): once a
/// crate's `.rmeta` fills the candidate slot, `extract_one` returns before
/// opening any `.rlib` of that crate. Under Cargo pipelining a dependency's
/// `.rlib` is still being written while its dependents compile, so keying
/// it made identical builds disagree by timing. The locator skips an empty
/// `.rmeta`, so only a non-empty sibling shadows the `.rlib`. An `.rlib`
/// strictly OLDER than its `.rmeta` comes from a different compile than the
/// metadata and might still be selected by hash: refuse that mixed pair.
fn metadata_shadowed_rlibs_removed(
    mut members: Vec<(String, FileSig)>,
) -> Result<Vec<(String, FileSig)>, String> {
    let metadata: BTreeMap<String, FileSig> = members
        .iter()
        .filter_map(|(name, sig)| Some((name.strip_suffix(".rmeta")?.to_owned(), *sig)))
        .collect();
    let mut kept = Vec::with_capacity(members.len());
    for (name, sig) in members.drain(..) {
        if let Some(stem) = name.strip_suffix(".rlib")
            && let Some(rmeta) = metadata.get(stem)
            && rmeta.size > 0
        {
            if sig.mtime_ns < rmeta.mtime_ns {
                return Err(format!(
                    "dependency {name} is older than its metadata sibling"
                ));
            }
            continue;
        }
        kept.push((name, sig));
    }
    kept.sort_by(|a, b| a.0.cmp(&b.0));
    Ok(kept)
}

fn capture_dependencies(
    facts: &LiveFacts,
    roots: DependencyRoots,
    members: DependencyMembers,
    output: DependencyOutput,
    mut cold_budget: Option<u64>,
) -> Result<DependencyFacts, FactsMiss> {
    let root_identities = dependency_root_identities(&roots).map_err(FactsMiss::Refused)?;
    let mut directories = Vec::new();
    for ((root, _), inventory) in roots.iter().zip(&members) {
        let mut artifacts = Vec::new();
        for (name, sig) in inventory {
            let path = root.join(name);
            artifacts.push(ExternFact {
                path: path
                    .to_str()
                    .ok_or_else(|| FactsMiss::Refused("non-UTF-8 dependency path".into()))?
                    .to_owned(),
                content_digest: facts.dependency_digest(&path, *sig, &mut cold_budget)?,
            });
        }
        directories.push(DependencyDirectoryFact {
            path: root
                .to_str()
                .ok_or_else(|| FactsMiss::Refused("non-UTF-8 dependency root".into()))?
                .to_owned(),
            artifacts,
        });
    }
    let captured = DependencyFacts {
        directories,
        roots,
        members,
        output,
        root_identities,
    };
    captured.verify_unchanged().map_err(FactsMiss::Refused)?;
    Ok(captured)
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
    // Cargo's completed run record for this OUT_DIR. The build-dir layout
    // keeps it in a `run/` sibling of OUT_DIR (`root-output`, `stdout`);
    // the classic `build/<pkg>-<hash>/` layout that stable Cargo uses keeps
    // the same two records beside `out/` (`root-output`, `output`). Any
    // other layout remains unserved; root-output binds the record to our
    // unit either way, and both directories' identities are revalidated.
    let unit = root.parent().ok_or("generated root has no parent")?;
    let (run, script_record) = match std::fs::symlink_metadata(unit.join("run")) {
        Ok(meta) if meta.is_dir() => (unit.join("run"), "stdout"),
        Ok(_) => return Err("build-script run directory is not real".into()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            (unit.to_path_buf(), "output")
        }
        Err(error) => return Err(format!("build-script run directory: {error}")),
    };
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
    let script_output = run.join(script_record);
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
    // Probe output, binary bytes and library facts must belong to this one
    // observed generation, not successive stages of a toolchain update.
    let inputs = observe_toolchain_inputs(compiler, sysroot)?;
    // The shared warm pool must not be held forever by a hung version/sysroot
    // child, an inherited pipe, or unbounded diagnostic output. The existing
    // process supervisor owns cleanup before a failed observation is returned.
    let (verbose_version, printed) = toolchain_probe::identity(compiler, env)?;
    let verbose_version = verbose_version.trim_end().to_owned();
    if Path::new(printed.trim_end()) != sysroot {
        return Err(
            "compiler resolves a different sysroot (a proxy, not a toolchain binary)".into(),
        );
    }

    // One bounded batch owns every read. Its size-aware scheduling and
    // hardlink coalescing never change canonical compiler/library ordering.
    let digests = toolchain_hashing::hash(&inputs)?;

    // Every file below lib/rustlib/<target>/lib: std and friends, which a
    // compile links metadata and inlinable code from.
    let mut tree = Vec::new();
    for ((path, _), digest) in inputs.sysroot_files.iter().zip(digests.sysroot) {
        let relative = path
            .strip_prefix(sysroot)
            .map_err(|_| "sysroot member escaped")?
            .to_str()
            .ok_or("non-UTF-8 sysroot member")?
            .to_owned();
        tree.push((relative, digest));
    }
    tree.sort_by(|a, b| a.0.cmp(&b.0));
    let mut enc = CanonicalEncoder::new();
    enc.u64(tree.len() as u64);
    for (relative, digest) in &tree {
        enc.str(relative).str(digest.domain).bytes(&digest.bytes);
    }
    let probed = ProbedToolchain {
        facts: ToolchainFacts {
            compiler_binary_digest: digests.compiler,
            verbose_version,
            sysroot_root_digest: compute(DOMAIN_SYSROOT_TREE, &enc.finish()),
            runtime_libraries: digests.runtime,
        },
        inputs,
    };
    if !probed.still_current() {
        return Err("toolchain inputs changed while it was probed".into());
    }
    Ok(probed)
}

/// The memoized observation state shared by every edge connection.
#[derive(Debug, Default)]
pub struct LiveFacts {
    files: Mutex<HashMap<PathBuf, (FileSig, TypedDigest)>>,
    toolchains: Mutex<HashMap<PathBuf, Slot<ProbedToolchain>>>,
    packages: Mutex<HashMap<PackageKey, Slot<PackageFacts>>>,
    dependencies: Mutex<DependencyMemos>,
    warming: Mutex<usize>,
}

type PackageKey = (PathBuf, DependencySourceKind, Option<PathBuf>);

/// Host-local memo identity, NOT an action key or serving authority. A
/// reservation/backoff for one observed inventory must not mask a newer
/// generation of the same directories. Keeping generations in separate
/// entries also keeps old in-flight work inside MAX_DEPENDENCY_MEMOS.
#[derive(Debug, PartialEq, Eq, Hash)]
struct DependencyObservation {
    roots: DependencyRoots,
    output: DependencyOutput,
    members: DependencyMembers,
    root_identities: Vec<(u64, u64)>,
}

#[derive(Debug)]
enum DependencySlot {
    Warming(Arc<()>),
    Ready(Arc<DependencyFacts>),
    Failed { reason: String, at: Instant },
}

type DependencyMemos = HashMap<Arc<DependencyObservation>, DependencySlot>;

/// One capture owns only its exact observation and reservation token.
/// Abandonment must not erase another capture or leave a permanent Warming
/// entry. The token also fences identical observations after eviction/retry.
struct DependencyReservation {
    facts: Arc<LiveFacts>,
    observation: Arc<DependencyObservation>,
    token: Arc<()>,
}

impl DependencyReservation {
    fn insert(
        facts: &Arc<LiveFacts>,
        memos: &mut DependencyMemos,
        observation: Arc<DependencyObservation>,
    ) -> Self {
        let token = Arc::new(());
        memos.insert(
            Arc::clone(&observation),
            DependencySlot::Warming(Arc::clone(&token)),
        );
        Self {
            facts: Arc::clone(facts),
            observation,
            token,
        }
    }

    fn finish(
        self,
        captured: Result<DependencyFacts, FactsMiss>,
        retain_failure: bool,
    ) -> Result<Arc<DependencyFacts>, FactsMiss> {
        let captured = captured.and_then(|captured| {
            if captured.roots != self.observation.roots
                || captured.output != self.observation.output
                || captured.members != self.observation.members
                || captured.root_identities != self.observation.root_identities
            {
                return Err(FactsMiss::Refused(
                    "dependency capture does not match its admitted observation".into(),
                ));
            }
            Ok(Arc::new(captured))
        });
        {
            let mut memos = self
                .facts
                .dependencies
                .lock()
                .map_err(|_| FactsMiss::Refused("dependency memo poisoned".into()))?;
            if !matches!(
                memos.get(&self.observation),
                Some(DependencySlot::Warming(token)) if Arc::ptr_eq(token, &self.token)
            ) {
                return Err(FactsMiss::Pending);
            }
            match &captured {
                Ok(captured) => {
                    memos.insert(
                        Arc::clone(&self.observation),
                        DependencySlot::Ready(Arc::clone(captured)),
                    );
                }
                Err(FactsMiss::Refused(reason)) if retain_failure => {
                    memos.insert(
                        Arc::clone(&self.observation),
                        DependencySlot::Failed {
                            reason: reason.clone(),
                            at: Instant::now(),
                        },
                    );
                }
                Err(_) => {}
            }
        }
        captured
    }
}

impl Drop for DependencyReservation {
    fn drop(&mut self) {
        if let Ok(mut memos) = self.facts.dependencies.lock()
            && matches!(
                memos.get(&self.observation),
                Some(DependencySlot::Warming(token)) if Arc::ptr_eq(token, &self.token)
            )
        {
            memos.remove(&self.observation);
        }
    }
}

/// Own the shared warm-pool slot through thread-start failure and unwinding,
/// not only the happy-path tail of the work closure.
struct WarmPermit {
    facts: Arc<LiveFacts>,
}

impl Drop for WarmPermit {
    fn drop(&mut self) {
        if let Ok(mut warming) = self.facts.warming.lock() {
            *warming = warming.saturating_sub(1);
        }
    }
}

impl LiveFacts {
    /// Empty state.
    #[must_use]
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    /// Capture exact dependency directory contents with bounded cold hashing.
    /// Only bytes missing from the identity-validated file memo consume the
    /// request budget. A large inventory of known outputs needs no background
    /// slot merely because this invocation has a different output mapping.
    pub fn dependencies(
        self: &Arc<Self>,
        plan: &DependencyActionPlan,
    ) -> Result<Arc<DependencyFacts>, FactsMiss> {
        let roots: DependencyRoots = plan
            .dependency_dirs
            .iter()
            .map(|root| {
                (
                    PathBuf::from(root),
                    if root == &plan.out_dir {
                        plan.output_names()
                    } else {
                        Vec::new()
                    },
                )
            })
            .collect();
        let (members, _) = walk_dependencies(&roots).map_err(FactsMiss::Refused)?;
        let output = (PathBuf::from(&plan.out_dir), plan.output_names());
        reject_dependency_output_aliases(&roots, &members, &output).map_err(FactsMiss::Refused)?;
        let root_identities = dependency_root_identities(&roots).map_err(FactsMiss::Refused)?;
        let observation = Arc::new(DependencyObservation {
            roots,
            output,
            members,
            root_identities,
        });
        let reservation = {
            let mut memos = self
                .dependencies
                .lock()
                .map_err(|_| FactsMiss::Refused("dependency memo poisoned".into()))?;
            match memos.get(&observation) {
                Some(DependencySlot::Ready(captured)) => return Ok(Arc::clone(captured)),
                Some(DependencySlot::Warming(_)) => return Err(FactsMiss::Pending),
                Some(DependencySlot::Failed { reason, at }) if at.elapsed() < PROBE_RETRY => {
                    return Err(FactsMiss::Refused(reason.clone()));
                }
                _ => {}
            }
            if memos.len() >= MAX_DEPENDENCY_MEMOS {
                memos.retain(|_, slot| matches!(slot, DependencySlot::Warming(_)));
            }
            if memos.len() >= MAX_DEPENDENCY_MEMOS {
                return Err(FactsMiss::Pending);
            }
            DependencyReservation::insert(self, &mut memos, Arc::clone(&observation))
        };

        let captured = if self.dependency_budget_fits(
            &observation.roots,
            &observation.members,
            SYNCHRONOUS_PACKAGE_BYTES,
        ) {
            capture_dependencies(
                self,
                observation.roots.clone(),
                observation.members.clone(),
                observation.output.clone(),
                Some(SYNCHRONOUS_PACKAGE_BYTES),
            )
        } else {
            Err(FactsMiss::Pending)
        };
        if !matches!(captured, Err(FactsMiss::Pending)) {
            return reservation.finish(captured, false);
        }

        self.start_warm(move |facts| {
            let captured = capture_dependencies(
                facts,
                observation.roots.clone(),
                observation.members.clone(),
                observation.output.clone(),
                None,
            );
            let _ = reservation.finish(captured, true);
        });
        Err(FactsMiss::Pending)
    }

    /// Scheduling estimate only. The foreground capture independently charges
    /// each actual cache miss, without holding this mutex over filesystem I/O.
    fn dependency_budget_fits(
        &self,
        roots: &DependencyRoots,
        members: &DependencyMembers,
        mut budget: u64,
    ) -> bool {
        let files = self.files.lock().ok();
        for ((root, _), inventory) in roots.iter().zip(members) {
            for (name, sig) in inventory {
                if files
                    .as_ref()
                    .and_then(|files| files.get(&root.join(name)))
                    .is_some_and(|(cached, _)| cached == sig)
                {
                    continue;
                }
                let Some(remaining) = budget.checked_sub(sig.size) else {
                    return false;
                };
                budget = remaining;
            }
        }
        true
    }

    /// Charge only a real memo miss, using the inventory's admitted size.
    /// Eviction after the estimate must never permit an unbounded cold read.
    fn dependency_digest(
        &self,
        path: &Path,
        expected: FileSig,
        cold_budget: &mut Option<u64>,
    ) -> Result<TypedDigest, FactsMiss> {
        let now = lstat_regular(path).map_err(|error| FactsMiss::Refused(error.to_string()))?;
        if now != expected {
            return Err(FactsMiss::Refused(
                "dependency changed after enumeration".into(),
            ));
        }
        if let Ok(files) = self.files.lock()
            && let Some((sig, digest)) = files.get(path)
            && *sig == expected
        {
            return Ok(digest.clone());
        }
        if let Some(remaining) = cold_budget {
            *remaining = remaining
                .checked_sub(expected.size)
                .ok_or(FactsMiss::Pending)?;
        }
        let (sig, digest) = digest_stable_at(path, expected)
            .map_err(|error| FactsMiss::Refused(error.to_string()))?;
        self.remember(path, sig, digest.clone());
        Ok(digest)
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
        let permit = WarmPermit {
            facts: Arc::clone(self),
        };
        std::thread::Builder::new()
            .name("rabs-facts-warm".to_owned())
            .spawn(move || {
                let active_permit = permit;
                work(&active_permit.facts);
            })
            .is_ok()
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

    /// Retain the ready observation that produced `expected` for this request.
    /// The memo lock protects only acquisition; later validation uses the
    /// retained observation and does not block unrelated requests on this lock.
    ///
    /// # Errors
    /// No matching ready observation remains, or its filesystem inputs changed.
    pub fn toolchain_guard(
        &self,
        compiler: &Path,
        expected: &ToolchainFacts,
    ) -> Result<ToolchainGuard, FactsMiss> {
        let observed = {
            let toolchains = self
                .toolchains
                .lock()
                .map_err(|_| FactsMiss::Refused("toolchain memo poisoned".into()))?;
            match toolchains.get(compiler) {
                Some(Slot::Ready(probed)) if &probed.facts == expected => Arc::clone(probed),
                _ => return Err(FactsMiss::Pending),
            }
        };
        let guard = ToolchainGuard { observed };
        guard
            .verify_unchanged(compiler)
            .map_err(FactsMiss::Refused)?;
        Ok(guard)
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

    fn dependency_observation(plan: &DependencyActionPlan) -> Arc<DependencyObservation> {
        let roots: DependencyRoots = plan
            .dependency_dirs
            .iter()
            .map(|root| {
                (
                    PathBuf::from(root),
                    if root == &plan.out_dir {
                        plan.output_names()
                    } else {
                        Vec::new()
                    },
                )
            })
            .collect();
        let (members, _) = walk_dependencies(&roots).unwrap();
        let output = (PathBuf::from(&plan.out_dir), plan.output_names());
        reject_dependency_output_aliases(&roots, &members, &output).unwrap();
        let root_identities = dependency_root_identities(&roots).unwrap();
        Arc::new(DependencyObservation {
            roots,
            output,
            members,
            root_identities,
        })
    }

    fn dependency_reservation(
        facts: &Arc<LiveFacts>,
        observation: &Arc<DependencyObservation>,
    ) -> DependencyReservation {
        let mut memos = facts.dependencies.lock().unwrap();
        assert!(!memos.contains_key(observation));
        DependencyReservation::insert(facts, &mut memos, Arc::clone(observation))
    }

    // These exercise observation/admission, not rustc metadata validity or
    // serving qualification. The files are regular dependency candidates.
    fn dependency_budget_fixture(
        sizes: &[u64],
    ) -> (tempfile::TempDir, DependencyActionPlan, Vec<PathBuf>) {
        let (dir, mut plan) = generated_fixture();
        plan.dependency_dirs = vec![plan.out_dir.clone()];
        let paths = sizes
            .iter()
            .enumerate()
            .map(|(index, size)| {
                let path = Path::new(&plan.out_dir).join(format!("libbudget{index}.rmeta"));
                std::fs::File::create(&path)
                    .unwrap()
                    .set_len(*size)
                    .unwrap();
                path
            })
            .collect();
        (dir, plan, paths)
    }

    #[test]
    fn warm_dependency_bytes_admit_new_output_mappings_without_a_warm_slot() {
        let (dir, mut plan, paths) = dependency_budget_fixture(&[SYNCHRONOUS_PACKAGE_BYTES + 1]);
        let facts = LiveFacts::new();
        let expected = facts.file_digest(&paths[0]).unwrap();
        // Forbid a background rescue: warm identities must suffice even
        // while the background pool is occupied with other observations.
        *facts.warming.lock().unwrap() = MAX_WARMING;
        let first = facts.dependencies(&plan).expect("warm dependency admitted");
        first.verify_unchanged().unwrap();
        assert_eq!(first.directories[0].artifacts[0].content_digest, expected);
        assert!(Arc::ptr_eq(&first, &facts.dependencies(&plan).unwrap()));
        let other = dir.path().join("another-output-mapping");
        std::fs::create_dir(&other).unwrap();
        plan.out_dir = other.to_str().unwrap().to_owned();
        let second = facts
            .dependencies(&plan)
            .expect("new mapping, same warm bytes");
        assert!(!Arc::ptr_eq(&first, &second));
        assert_eq!(second.directories[0].artifacts[0].content_digest, expected);
        assert_eq!(*facts.warming.lock().unwrap(), MAX_WARMING);
    }

    #[test]
    fn small_cold_tail_in_a_large_warm_inventory_is_admitted() {
        let (_dir, plan, paths) = dependency_budget_fixture(&[SYNCHRONOUS_PACKAGE_BYTES + 1, 17]);
        let facts = LiveFacts::new();
        let warm = facts.file_digest(&paths[0]).unwrap();
        *facts.warming.lock().unwrap() = MAX_WARMING;
        let captured = facts.dependencies(&plan).expect("only 17 bytes are cold");
        assert_eq!(captured.directories[0].artifacts.len(), 2);
        assert_eq!(captured.directories[0].artifacts[0].content_digest, warm);
        assert_eq!(
            captured.directories[0].artifacts[1].content_digest,
            digest_stable(&paths[1]).unwrap().1
        );
        captured.verify_unchanged().unwrap();
    }

    #[test]
    fn dependency_read_budget_is_shared_and_memo_hits_are_free() {
        let (_dir, _plan, paths) = dependency_budget_fixture(&[9, 7]);
        let facts = LiveFacts::new();
        let first = lstat_regular(&paths[0]).unwrap();
        let second = lstat_regular(&paths[1]).unwrap();
        let mut budget = Some(9);
        let digest = facts
            .dependency_digest(&paths[0], first, &mut budget)
            .unwrap();
        assert_eq!(budget, Some(0));
        assert_eq!(
            facts
                .dependency_digest(&paths[0], first, &mut budget)
                .unwrap(),
            digest
        );
        assert_eq!(budget, Some(0));
        assert_eq!(
            facts.dependency_digest(&paths[1], second, &mut budget),
            Err(FactsMiss::Pending)
        );
        assert_eq!(budget, Some(0));
        assert!(!facts.files.lock().unwrap().contains_key(&paths[1]));
    }

    #[test]
    fn memo_eviction_after_estimation_cannot_authorize_a_cold_read() {
        let (_dir, plan, paths) = dependency_budget_fixture(&[17]);
        let facts = LiveFacts::new();
        facts.file_digest(&paths[0]).unwrap();
        let roots = vec![(PathBuf::from(&plan.out_dir), plan.output_names())];
        let (members, _) = walk_dependencies(&roots).unwrap();
        assert!(facts.dependency_budget_fits(&roots, &members, 0));
        facts.files.lock().unwrap().clear();
        assert!(matches!(
            capture_dependencies(
                &facts,
                roots,
                members,
                (PathBuf::from(&plan.out_dir), plan.output_names()),
                Some(0),
            ),
            Err(FactsMiss::Pending)
        ));
        assert!(!facts.files.lock().unwrap().contains_key(&paths[0]));
    }

    #[test]
    fn dependency_replacement_after_enumeration_refuses_before_spending_budget() {
        let (dir, _plan, paths) = dependency_budget_fixture(&[17]);
        let facts = LiveFacts::new();
        let observed = lstat_regular(&paths[0]).unwrap();
        std::fs::rename(&paths[0], dir.path().join("retained-old-input")).unwrap();
        std::fs::write(&paths[0], b"replacement bytes").unwrap();
        let mut budget = Some(17);
        assert!(matches!(
            facts.dependency_digest(&paths[0], observed, &mut budget),
            Err(FactsMiss::Refused(reason)) if reason.contains("after enumeration")
        ));
        assert_eq!(budget, Some(17));
        assert!(facts.files.lock().unwrap().is_empty());
    }

    #[test]
    fn replaced_warm_candidate_becomes_cold_and_cannot_reuse_its_old_digest() {
        let (dir, plan, paths) = dependency_budget_fixture(&[SYNCHRONOUS_PACKAGE_BYTES + 1]);
        let facts = LiveFacts::new();
        let old = facts.file_digest(&paths[0]).unwrap();
        *facts.warming.lock().unwrap() = MAX_WARMING;
        let captured = facts.dependencies(&plan).unwrap();
        std::fs::rename(&paths[0], dir.path().join("retained-old-input")).unwrap();
        std::fs::write(
            &paths[0],
            vec![1; usize::try_from(SYNCHRONOUS_PACKAGE_BYTES + 1).unwrap()],
        )
        .unwrap();
        assert!(captured.verify_unchanged().is_err());
        assert!(matches!(facts.dependencies(&plan), Err(FactsMiss::Pending)));
        // Failed warm admission releases this inventory's reservation.
        // After observing the new bytes the next request can try again.
        let new = facts.file_digest(&paths[0]).unwrap();
        assert_ne!(old, new);
        let changed = facts.dependencies(&plan).unwrap();
        assert_eq!(changed.directories[0].artifacts[0].content_digest, new);
        changed.verify_unchanged().unwrap();
    }

    #[test]
    fn warm_admission_preserves_negative_candidates_and_output_alias_refusals() {
        let (_dir, plan, paths) = dependency_budget_fixture(&[SYNCHRONOUS_PACKAGE_BYTES + 1]);
        let facts = LiveFacts::new();
        facts.file_digest(&paths[0]).unwrap();
        *facts.warming.lock().unwrap() = MAX_WARMING;
        let before = facts.dependencies(&plan).unwrap();
        std::fs::write(Path::new(&plan.out_dir).join("libnew.rmeta"), b"new").unwrap();
        assert!(before.verify_unchanged().is_err());
        let after = facts.dependencies(&plan).unwrap();
        assert_eq!(after.directories[0].artifacts.len(), 2);
        let output = Path::new(&plan.out_dir).join(&plan.output_names()[0]);
        std::fs::hard_link(&paths[0], output).unwrap();
        assert!(matches!(
            facts.dependencies(&plan),
            Err(FactsMiss::Refused(reason)) if reason.contains("aliases a declared output")
        ));
    }

    #[test]
    fn cold_dependency_still_warms_in_the_existing_bounded_pool() {
        let (_dir, plan, _paths) = dependency_budget_fixture(&[SYNCHRONOUS_PACKAGE_BYTES + 1]);
        let facts = LiveFacts::new();
        assert!(matches!(facts.dependencies(&plan), Err(FactsMiss::Pending)));
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            assert!(Instant::now() < deadline, "dependency warm did not finish");
            match facts.dependencies(&plan) {
                Ok(captured) => {
                    captured.verify_unchanged().unwrap();
                    assert_eq!(captured.directories[0].artifacts.len(), 1);
                    break;
                }
                Err(FactsMiss::Pending) => std::thread::sleep(Duration::from_millis(5)),
                Err(error) => panic!("dependency warm refused: {error}"),
            }
        }
    }

    #[test]
    fn large_cold_inventory_does_not_spend_the_foreground_budget_before_deferral() {
        let (_dir, plan, _paths) =
            dependency_budget_fixture(&[SYNCHRONOUS_PACKAGE_BYTES / 2 + 1; 2]);
        let facts = LiveFacts::new();
        *facts.warming.lock().unwrap() = MAX_WARMING;
        assert!(matches!(facts.dependencies(&plan), Err(FactsMiss::Pending)));
        assert!(facts.files.lock().unwrap().is_empty());
    }

    #[test]
    fn foreground_capture_reservations_keep_the_inventory_memo_bounded() {
        let (dir, plan, _paths) = dependency_budget_fixture(&[17]);
        let facts = LiveFacts::new();
        {
            let mut memos = facts.dependencies.lock().unwrap();
            for index in 0..MAX_DEPENDENCY_MEMOS {
                memos.insert(
                    Arc::new(DependencyObservation {
                        roots: Vec::new(),
                        output: (dir.path().join(format!("out-{index}")), Vec::new()),
                        members: Vec::new(),
                        root_identities: Vec::new(),
                    }),
                    DependencySlot::Warming(Arc::new(())),
                );
            }
        }
        assert!(matches!(facts.dependencies(&plan), Err(FactsMiss::Pending)));
        assert_eq!(
            facts.dependencies.lock().unwrap().len(),
            MAX_DEPENDENCY_MEMOS
        );
        assert!(facts.files.lock().unwrap().is_empty());
        assert_eq!(*facts.warming.lock().unwrap(), 0);
    }

    #[test]
    fn newer_dependency_generation_is_not_blocked_by_older_reservation() {
        let (_dir, plan, _paths) = dependency_budget_fixture(&[17]);
        let facts = LiveFacts::new();
        let original = dependency_observation(&plan);
        let owner = dependency_reservation(&facts, &original);
        std::fs::write(Path::new(&plan.out_dir).join("libnew.rmeta"), b"new").unwrap();

        *facts.warming.lock().unwrap() = MAX_WARMING;
        let newer = facts.dependencies(&plan).expect("new generation admitted");
        assert_eq!(newer.directories[0].artifacts.len(), 2);
        drop(owner);
        assert!(Arc::ptr_eq(&newer, &facts.dependencies(&plan).unwrap()));
        newer.verify_unchanged().unwrap();
    }

    #[test]
    fn stale_reservation_token_cannot_replace_identical_successor() {
        let (_dir, plan, _paths) = dependency_budget_fixture(&[17]);
        let facts = LiveFacts::new();
        let observation = dependency_observation(&plan);
        let original = dependency_reservation(&facts, &observation);
        facts.dependencies.lock().unwrap().remove(&observation);
        let successor = dependency_reservation(&facts, &observation);
        let successor_token = Arc::clone(&successor.token);

        let captured = capture_dependencies(
            &facts,
            observation.roots.clone(),
            observation.members.clone(),
            observation.output.clone(),
            None,
        );
        assert!(matches!(
            original.finish(captured, true),
            Err(FactsMiss::Pending)
        ));
        assert!(matches!(
            facts.dependencies.lock().unwrap().get(&observation),
            Some(DependencySlot::Warming(current)) if Arc::ptr_eq(current, &successor_token)
        ));

        let captured = capture_dependencies(
            &facts,
            observation.roots.clone(),
            observation.members.clone(),
            observation.output.clone(),
            None,
        );
        successor.finish(captured, true).unwrap();
        facts
            .dependencies(&plan)
            .unwrap()
            .verify_unchanged()
            .unwrap();
    }

    #[test]
    fn failed_observation_backoff_does_not_follow_changed_generation() {
        let (_dir, plan, paths) = dependency_budget_fixture(&[17]);
        let facts = LiveFacts::new();
        let original = dependency_observation(&plan);
        dependency_reservation(&facts, &original)
            .finish(
                Err(FactsMiss::Refused("old generation failed".into())),
                true,
            )
            .unwrap_err();

        assert!(matches!(
            facts.dependencies(&plan),
            Err(FactsMiss::Refused(reason)) if reason == "old generation failed"
        ));

        std::fs::write(&paths[0], b"changed generation").unwrap();
        facts
            .dependencies(&plan)
            .unwrap()
            .verify_unchanged()
            .unwrap();
    }

    #[test]
    fn observed_hashing_keeps_streaming_identity() {
        let dir = tempfile::tempdir().unwrap();
        for (name, bytes) in [
            ("empty", Vec::new()),
            ("binary", vec![0, 255, 10, 0, 128]),
            ("multiple-buffers", vec![137; 512 * 1024 + 17]),
        ] {
            let path = dir.path().join(name);
            std::fs::write(&path, &bytes).unwrap();
            let observed = lstat_regular(&path).unwrap();
            let mut writer =
                StreamingObjectWriter::new(DigestRequest::default(), Some(bytes.len() as u64));
            writer.write(&bytes).unwrap();
            let expected = writer.finish().unwrap().atp_content_id;
            assert_eq!(
                digest_stable_at(&path, observed).unwrap(),
                (observed, expected)
            );
        }
    }

    #[test]
    fn observed_hashing_refuses_replacement() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("libdep.rmeta");
        std::fs::write(&path, b"before").unwrap();
        let observed = lstat_regular(&path).unwrap();
        std::fs::rename(&path, dir.path().join("retained-original")).unwrap();
        std::fs::write(&path, b"after!").unwrap();
        assert!(digest_stable_at(&path, observed).is_err());
        assert!(digest_stable(&path).is_ok());
    }

    #[test]
    fn observed_hashing_refuses_growth_shrinkage_and_symlink_replacement() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("libdep.rmeta");
        std::fs::write(&path, b"small").unwrap();
        let observed = lstat_regular(&path).unwrap();
        std::fs::OpenOptions::new()
            .write(true)
            .open(&path)
            .unwrap()
            .set_len(16 * 1024 * 1024)
            .unwrap();
        assert!(digest_stable_at(&path, observed).is_err());

        let grown = lstat_regular(&path).unwrap();
        std::fs::write(&path, b"x").unwrap();
        assert!(digest_stable_at(&path, grown).is_err());

        let current = lstat_regular(&path).unwrap();
        let retained = dir.path().join("retained-bytes");
        std::fs::rename(&path, &retained).unwrap();
        std::os::unix::fs::symlink(&retained, &path).unwrap();
        assert!(digest_stable_at(&path, current).is_err());
    }

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
    fn classic_cargo_layout_binds_the_run_record_beside_out_dir() {
        // Stable Cargo: target/<profile>/build/<pkg>-<hash>/{out,output,root-output}.
        let dir = tempfile::tempdir().unwrap();
        let unit = dir.path().join("build/anyhow-5c8e82dba5ceda6b");
        let out = unit.join("out");
        std::fs::create_dir_all(&out).unwrap();
        std::fs::write(out.join("value.rs"), b"pub const VALUE: u32 = 17;").unwrap();
        std::fs::write(unit.join("output"), b"cargo:rustc-cfg=std_backtrace\n").unwrap();
        std::fs::write(unit.join("root-output"), out.to_str().unwrap()).unwrap();
        std::fs::write(unit.join("stderr"), b"").unwrap();
        std::fs::write(unit.join("invoked.timestamp"), b"This file has an mtime").unwrap();
        let (observed, _) = observe_generated(&out).unwrap();
        assert_eq!(observed.script_output.0, unit.join("output"));
        assert_eq!(observed.root_output.0, unit.join("root-output"));
        assert_eq!(observe_generated(&out).unwrap().0, observed);
        // A rerun of the build script rewrites the record: never the same.
        std::fs::write(unit.join("output"), b"cargo:rustc-cfg=other\n").unwrap();
        assert_ne!(observe_generated(&out).unwrap().0, observed);
        // The record must name THIS OUT_DIR.
        std::fs::write(unit.join("root-output"), b"/elsewhere/out").unwrap();
        assert!(
            observe_generated(&out)
                .unwrap_err()
                .contains("different OUT_DIR")
        );
        // A `run` entry that is not a directory is neither layout: refuse.
        std::fs::write(unit.join("root-output"), out.to_str().unwrap()).unwrap();
        std::fs::write(unit.join("run"), b"not a directory").unwrap();
        assert!(observe_generated(&out).unwrap_err().contains("not real"));
        // Without any record there is nothing to bind: refuse.
        std::fs::remove_file(unit.join("run")).unwrap();
        std::fs::remove_file(unit.join("output")).unwrap();
        assert!(observe_generated(&out).unwrap_err().contains("stdout"));
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

    #[test]
    fn dependency_candidates_revalidate_content_membership_and_root_type() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("deps");
        std::fs::create_dir(&root).unwrap();
        let artifact = root.join("libdep.rmeta");
        std::fs::write(&artifact, b"first").unwrap();
        std::fs::write(root.join("dep.d"), b"arbitrary dep-info placement").unwrap();
        let roots = vec![(root.clone(), vec!["libcurrent.rmeta".into()])];
        let memo = LiveFacts::new();
        let capture = || {
            let (members, _) = walk_dependencies(&roots).unwrap();
            capture_dependencies(
                &memo,
                roots.clone(),
                members,
                (root.clone(), vec!["libcurrent.rmeta".into()]),
                None,
            )
            .unwrap()
        };
        let first = capture();
        // Dep-info is never opened as a crate: it is neither listed nor keyed.
        assert_eq!(first.directories[0].artifacts.len(), 1);
        // This invocation's exact declared outputs may appear while executing.
        std::fs::write(root.join("libcurrent.rmeta"), b"new output").unwrap();
        first.verify_unchanged().unwrap();
        std::fs::remove_file(root.join("dep.d")).unwrap();
        first.verify_unchanged().unwrap();
        std::fs::write(&artifact, b"other").unwrap();
        assert!(first.verify_unchanged().is_err());
        let changed = capture();
        assert_ne!(
            changed.directories[0].artifacts,
            first.directories[0].artifacts
        );
        std::fs::write(root.join("libtransitive.rlib"), b"another candidate").unwrap();
        assert!(changed.verify_unchanged().is_err());
        let added = capture();
        assert_eq!(added.directories[0].artifacts.len(), 2);
        // Move the SAME member inodes behind a root symlink: warm facts must
        // refuse, even though every candidate signature would still match.
        let moved = dir.path().join("moved");
        std::fs::rename(&root, &moved).unwrap();
        std::os::unix::fs::symlink(&moved, &root).unwrap();
        assert!(added.verify_unchanged().is_err());
        assert!(walk_dependencies(&roots).is_err());
    }

    #[test]
    fn dependency_candidates_refuse_unmodeled_crate_files_and_symlinks() {
        // Everything rustc's locator could open that this class does not
        // model (proc-macros/dylibs, interfaces, static libs) still refuses.
        for name in [
            "libmacro.so",
            "libmacro.dylib",
            "libnative.a",
            "libiface.rs",
            "libunknown",
        ] {
            let dir = tempfile::tempdir().unwrap();
            std::fs::write(dir.path().join(name), b"not a Rust candidate").unwrap();
            assert!(
                walk_dependencies(&vec![(dir.path().to_path_buf(), Vec::new())]).is_err(),
                "{name}"
            );
        }
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir(dir.path().join("libnested.rlib")).unwrap();
        assert!(walk_dependencies(&vec![(dir.path().to_path_buf(), Vec::new())]).is_err());
        let dir = tempfile::tempdir().unwrap();
        std::os::unix::fs::symlink("missing", dir.path().join("libalias.rmeta")).unwrap();
        assert!(walk_dependencies(&vec![(dir.path().to_path_buf(), Vec::new())]).is_err());
    }

    #[test]
    fn entries_the_crate_locator_never_opens_are_not_inputs() {
        // The scratch real Cargo leaves in a shared or pipelined dependency
        // directory while OTHER crates compile, observed on crates.io builds.
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().to_path_buf();
        std::fs::write(root.join("libdep-0123.rmeta"), b"metadata").unwrap();
        let roots = vec![(root.clone(), Vec::new())];
        let (members, _) = walk_dependencies(&roots).unwrap();
        let captured = capture_dependencies(
            &LiveFacts::new(),
            roots.clone(),
            members.clone(),
            (dir.path().join("out"), Vec::new()),
            None,
        )
        .unwrap();
        std::fs::write(
            root.join("regex_syntax-0123.regex_syntax.ab12-cgu.13.rcgu.o"),
            b"codegen unit",
        )
        .unwrap();
        std::fs::create_dir(root.join("rmeta9POLSO")).unwrap();
        std::fs::write(root.join("rmeta9POLSO/full.rmeta"), b"in flight").unwrap();
        std::fs::write(root.join("serde_derive-0123.d"), b"dep-info").unwrap();
        std::fs::write(root.join("app-0123"), b"executable").unwrap();
        std::fs::create_dir(root.join(".tmpQx.temp-archive")).unwrap();
        assert_eq!(walk_dependencies(&roots).unwrap().0, members);
        captured.verify_unchanged().unwrap();
        // A crate the locator CAN open still changes the inputs.
        std::fs::write(root.join("libother-4567.rmeta"), b"other metadata").unwrap();
        assert!(
            captured
                .verify_unchanged()
                .unwrap_err()
                .contains("candidates changed")
        );
    }

    #[test]
    fn a_pipelined_rlib_is_shadowed_by_its_metadata_and_stale_pairs_refuse() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().to_path_buf();
        let roots = vec![(root.clone(), Vec::new())];
        let rmeta = root.join("libdep-0123.rmeta");
        std::fs::write(&rmeta, b"metadata").unwrap();
        let (before, _) = walk_dependencies(&roots).unwrap();
        let captured = capture_dependencies(
            &LiveFacts::new(),
            roots.clone(),
            before.clone(),
            (dir.path().join("out"), Vec::new()),
            None,
        )
        .unwrap();
        // rustc finishes the dependency's codegen while its dependent runs:
        // the library compile only ever reads the metadata, so nothing moved.
        std::thread::sleep(Duration::from_millis(5));
        std::fs::write(root.join("libdep-0123.rlib"), b"archive").unwrap();
        assert_eq!(walk_dependencies(&roots).unwrap().0, before);
        captured.verify_unchanged().unwrap();
        assert_eq!(captured.directories[0].artifacts.len(), 1);

        // Metadata rewritten AFTER the archive: the pair is from two compiles.
        std::thread::sleep(Duration::from_millis(5));
        std::fs::write(&rmeta, b"newer metadata").unwrap();
        assert!(
            walk_dependencies(&roots)
                .unwrap_err()
                .contains("older than its metadata")
        );

        // The locator skips an empty rmeta, so the archive is the candidate.
        std::fs::write(&rmeta, b"").unwrap();
        std::fs::write(root.join("libdep-0123.rlib"), b"archive").unwrap();
        let (members, _) = walk_dependencies(&roots).unwrap();
        let names: Vec<_> = members[0].iter().map(|(name, _)| name.as_str()).collect();
        assert_eq!(names, ["libdep-0123.rlib", "libdep-0123.rmeta"]);

        // Without any metadata sibling the archive is keyed like before.
        let lone = tempfile::tempdir().unwrap();
        std::fs::write(lone.path().join("libsolo-89.rlib"), b"archive").unwrap();
        let (members, _) =
            walk_dependencies(&vec![(lone.path().to_path_buf(), Vec::new())]).unwrap();
        assert_eq!(members[0].len(), 1);
    }

    #[test]
    fn dependency_candidates_refuse_physical_output_aliases() {
        let dir = tempfile::tempdir().unwrap();
        let real_parent = dir.path().join("real");
        let dependencies = real_parent.join("deps");
        let out = dir.path().join("out");
        std::fs::create_dir_all(&dependencies).unwrap();
        std::fs::create_dir(&out).unwrap();
        std::fs::write(dependencies.join("libdep.rlib"), b"dependency bytes").unwrap();
        let roots = vec![(dependencies.clone(), Vec::new())];
        let output = (out.clone(), vec!["libcurrent.rlib".into()]);
        let (members, _) = walk_dependencies(&roots).unwrap();
        let captured =
            capture_dependencies(&LiveFacts::new(), roots, members, output, None).unwrap();
        captured.verify_unchanged().unwrap();
        // An alias created after keying must also refuse at pre-hit / completion.
        std::fs::hard_link(
            dependencies.join("libdep.rlib"),
            out.join("libcurrent.rlib"),
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
        let alias_parent = dir.path().join("alias");
        std::os::unix::fs::symlink(&real_parent, &alias_parent).unwrap();
        let alias_roots = vec![(alias_parent.join("deps"), Vec::new())];
        let (members, _) = walk_dependencies(&alias_roots).unwrap();
        assert!(
            reject_dependency_output_aliases(&alias_roots, &members, &(dependencies, Vec::new()))
                .unwrap_err()
                .contains("aliases the output directory")
        );
    }

    #[test]
    fn dependency_roots_are_bound_by_identity_not_generation() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("dependency");
        let out = dir.path().join("out");
        std::fs::create_dir(&root).unwrap();
        std::fs::create_dir(&out).unwrap();
        std::fs::write(root.join("libstable.rlib"), b"stable").unwrap();
        let roots = vec![(root.clone(), Vec::new())];
        let (members, _) = walk_dependencies(&roots).unwrap();
        let captured = capture_dependencies(
            &LiveFacts::new(),
            roots.clone(),
            members.clone(),
            (out, Vec::new()),
            None,
        )
        .unwrap();
        // Scratch churn bumps the directory generation; it is not an input.
        std::fs::write(root.join("stable-0.stable.1-cgu.0.rcgu.o"), b"o").unwrap();
        std::fs::remove_file(root.join("stable-0.stable.1-cgu.0.rcgu.o")).unwrap();
        captured.verify_unchanged().unwrap();
        // Deliberately NOT detected any more: a crate-named file renamed in
        // and out again between two walks. rustc and Cargo never do this
        // (they rename finished crates into place and keep them for the
        // build); binding the generation instead refused every pipelined
        // compile whose dependency was still writing codegen units.
        let outside = dir.path().join("transient.rmeta");
        std::fs::write(&outside, b"transient candidate").unwrap();
        std::fs::rename(&outside, root.join("libtransient.rmeta")).unwrap();
        std::fs::rename(root.join("libtransient.rmeta"), &outside).unwrap();
        captured.verify_unchanged().unwrap();
        // The same path naming a DIFFERENT directory is still refused, even
        // when it holds the very same candidate inode.
        let moved = dir.path().join("moved");
        std::fs::rename(&root, &moved).unwrap();
        std::fs::create_dir(&root).unwrap();
        std::fs::rename(moved.join("libstable.rlib"), root.join("libstable.rlib")).unwrap();
        assert_eq!(
            walk_dependencies(&roots).unwrap().0[0][0].0,
            "libstable.rlib"
        );
        assert!(
            captured
                .verify_unchanged()
                .unwrap_err()
                .contains("was replaced")
        );
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

    // A scripted version/sysroot probe over real filesystem inputs. This
    // exercises toolchain observation, not a real compiler or cache hit.
    fn toolchain_fixture() -> (tempfile::TempDir, PathBuf) {
        use std::os::unix::fs::PermissionsExt;
        // Short paths also fit macOS's smaller Unix-domain socket address.
        let dir = tempfile::Builder::new()
            .prefix("rt-")
            .tempdir_in("/tmp")
            .unwrap();
        let root = dir.path().join("toolchain");
        for relative in [
            "bin",
            "lib/rustlib/test-host/lib/self-contained",
            "lib/rustlib/future-target",
        ] {
            std::fs::create_dir_all(root.join(relative)).unwrap();
        }
        std::fs::write(root.join("lib/libdriver.so"), b"runtime-v1").unwrap();
        std::fs::write(
            root.join("lib/rustlib/test-host/lib/libcore.rlib"),
            b"core-v1",
        )
        .unwrap();
        std::fs::write(
            root.join("lib/rustlib/test-host/lib/self-contained/crt.o"),
            b"startup-v1",
        )
        .unwrap();
        let compiler = root.join("bin/rustc");
        std::fs::write(
            &compiler,
            br#"#!/bin/sh
root=${0%/bin/rustc}
if [ -n "${RABS_TEST_LOG:-}" ]; then
    printf 'probe\n' >> "$RABS_TEST_LOG"
fi
case "$*" in
    '-vV')
        case "${RABS_TEST_MUTATE:-}" in
            add) printf 'new\n' > "$root/lib/rustlib/test-host/lib/libinjected.rlib" ;;
            change) printf 'runtime-v2' > "$root/lib/libdriver.so" ;;
        esac
        printf 'rustc fixture\nhost: x86_64-unknown-linux-gnu\n'
        ;;
    '--print sysroot') printf '%s\n' "$root" ;;
    *) exit 64 ;;
esac
"#,
        )
        .unwrap();
        std::fs::set_permissions(&compiler, std::fs::Permissions::from_mode(0o700)).unwrap();
        (dir, compiler)
    }

    #[test]
    fn complete_unchanged_toolchain_inputs_preserve_fact_identity() {
        let (_dir, compiler) = toolchain_fixture();
        let first = probe_toolchain(&compiler, &[]).unwrap();
        assert!(first.still_current());
        assert_eq!(first.inputs.runtime_libraries.len(), 1);
        assert_eq!(first.inputs.sysroot_files.len(), 2);
        assert_eq!(first.facts, probe_toolchain(&compiler, &[]).unwrap().facts);
        assert!(first.still_current());
    }

    #[test]
    fn added_toolchain_libraries_and_target_roots_invalidate_warm_facts() {
        for relative in [
            "lib/libanother.so",
            "lib/rustlib/test-host/lib/libanother.rlib",
            "lib/rustlib/test-host/lib/self-contained/another.o",
            "lib/rustlib/new-target/lib/libcore.rlib",
            "lib/rustlib/future-target/lib/libcore.rlib",
        ] {
            let (_dir, compiler) = toolchain_fixture();
            let root = compiler.parent().unwrap().parent().unwrap();
            let first = probe_toolchain(&compiler, &[]).unwrap();
            let new = root.join(relative);
            std::fs::create_dir_all(new.parent().unwrap()).unwrap();
            std::fs::write(&new, b"new compiler input").unwrap();
            // The old positive-file-only check accepts all of these: no
            // previously hashed file has moved or changed its bytes.
            assert!(
                std::iter::once(&first.inputs.compiler)
                    .chain(&first.inputs.runtime_libraries)
                    .chain(&first.inputs.sysroot_files)
                    .all(|(path, sig)| lstat_regular(path).unwrap() == *sig)
            );
            assert!(
                !first.still_current(),
                "missed new toolchain input {relative}"
            );
            let changed = probe_toolchain(&compiler, &[]).unwrap();
            assert!(changed.still_current());
            assert_ne!(first.facts, changed.facts, "new bytes must key {relative}");
        }
    }

    #[test]
    fn transient_toolchain_membership_invalidates_observation_not_canonical_bytes() {
        let (dir, compiler) = toolchain_fixture();
        let root = compiler.parent().unwrap().parent().unwrap();
        let outside = dir.path().join("transient.rlib");
        std::fs::write(&outside, b"temporary input").unwrap();
        let first = probe_toolchain(&compiler, &[]).unwrap();
        let inside = root.join("lib/rustlib/test-host/lib/libtransient.rlib");
        std::fs::rename(&outside, &inside).unwrap();
        std::fs::rename(&inside, &outside).unwrap();
        assert!(!first.still_current());
        // Directory generations are freshness evidence, NOT action-key
        // fields. Re-observing the same complete bytes retains the same key.
        let refreshed = probe_toolchain(&compiler, &[]).unwrap();
        assert!(refreshed.still_current());
        assert_eq!(first.facts, refreshed.facts);
    }

    #[test]
    fn toolchain_root_links_cannot_reuse_the_same_positive_file_identities() {
        for relative in [
            "",
            "lib",
            "lib/rustlib/test-host/lib",
            "lib/rustlib/test-host/lib/self-contained",
        ] {
            let (dir, compiler) = toolchain_fixture();
            let root = compiler.parent().unwrap().parent().unwrap();
            let first = probe_toolchain(&compiler, &[]).unwrap();
            let selected = if relative.is_empty() {
                root.to_path_buf()
            } else {
                root.join(relative)
            };
            let retained = dir.path().join("retained-directory");
            std::fs::rename(&selected, &retained).unwrap();
            std::os::unix::fs::symlink(&retained, &selected).unwrap();
            assert!(
                std::iter::once(&first.inputs.compiler)
                    .chain(&first.inputs.runtime_libraries)
                    .chain(&first.inputs.sysroot_files)
                    .all(|(path, sig)| lstat_regular(path).unwrap() == *sig)
            );
            assert!(!first.still_current(), "linked directory {relative}");
            assert!(probe_toolchain(&compiler, &[]).is_err());
        }
    }

    #[test]
    fn linked_toolchain_members_refuse_before_running_a_probe() {
        for (relative, target) in [
            ("lib/libalias.so", "libdriver.so"),
            ("lib/rustlib/test-host/lib/libalias.rlib", "libcore.rlib"),
            ("lib/rustlib/test-host/lib/nested", "self-contained"),
            ("lib/rustlib/linked-target", "test-host"),
            ("lib/rustlib/future-target/lib", "missing"),
        ] {
            let (dir, compiler) = toolchain_fixture();
            let root = compiler.parent().unwrap().parent().unwrap();
            std::os::unix::fs::symlink(target, root.join(relative)).unwrap();
            let log = dir.path().join("probe.log");
            let env = vec![("RABS_TEST_LOG".to_owned(), log.to_str().unwrap().to_owned())];
            assert!(probe_toolchain(&compiler, &env).is_err(), "{relative}");
            assert!(!log.exists(), "an incomplete inventory reached the probe");
        }
    }

    #[test]
    fn special_toolchain_library_members_are_not_silently_omitted() {
        for relative in [
            "lib/libsocket.so",
            "lib/rustlib/test-host/lib/libsocket.rlib",
        ] {
            let (dir, compiler) = toolchain_fixture();
            let root = compiler.parent().unwrap().parent().unwrap();
            let _socket = std::os::unix::net::UnixListener::bind(root.join(relative)).unwrap();
            let log = dir.path().join("probe.log");
            let env = vec![("RABS_TEST_LOG".to_owned(), log.to_str().unwrap().to_owned())];
            assert!(probe_toolchain(&compiler, &env).is_err());
            assert!(!log.exists());
        }
    }

    #[test]
    fn a_probe_cannot_mix_version_output_with_changed_library_inputs() {
        for mutation in ["add", "change"] {
            let (dir, compiler) = toolchain_fixture();
            let log = dir.path().join("probe.log");
            let env = vec![
                ("RABS_TEST_LOG".to_owned(), log.to_str().unwrap().to_owned()),
                ("RABS_TEST_MUTATE".to_owned(), mutation.to_owned()),
            ];
            assert!(probe_toolchain(&compiler, &env).is_err(), "{mutation}");
            assert_eq!(std::fs::read_to_string(&log).unwrap(), "probe\nprobe\n");
            // A subsequent clean observation can accept the new generation.
            assert!(probe_toolchain(&compiler, &[]).unwrap().still_current());
        }
    }

    #[test]
    fn public_toolchain_lookup_never_serves_stale_facts_when_rewarming_is_full() {
        let (_dir, compiler) = toolchain_fixture();
        let root = compiler.parent().unwrap().parent().unwrap();
        let probed = probe_toolchain(&compiler, &[]).unwrap();
        let expected = probed.facts.clone();
        let facts = LiveFacts::new();
        facts
            .toolchains
            .lock()
            .unwrap()
            .insert(compiler.clone(), Slot::Ready(Arc::new(probed)));
        *facts.warming.lock().unwrap() = MAX_WARMING;
        assert_eq!(facts.toolchain(&compiler, &[]).unwrap(), expected);
        std::fs::write(root.join("lib/rustlib/test-host/lib/libnew.rlib"), b"new").unwrap();
        assert_eq!(facts.toolchain(&compiler, &[]), Err(FactsMiss::Pending));
        assert!(!facts.toolchains.lock().unwrap().contains_key(&compiler));
        assert_eq!(*facts.warming.lock().unwrap(), MAX_WARMING);
    }

    #[test]
    fn toolchain_guard_requires_the_matching_ready_observation() {
        let (_dir, compiler) = toolchain_fixture();
        let probed = probe_toolchain(&compiler, &[]).unwrap();
        let expected = probed.facts.clone();
        let facts = LiveFacts::new();
        assert!(matches!(
            facts.toolchain_guard(&compiler, &expected),
            Err(FactsMiss::Pending)
        ));
        facts
            .toolchains
            .lock()
            .unwrap()
            .insert(compiler.clone(), Slot::Ready(Arc::new(probed)));
        let guard = facts.toolchain_guard(&compiler, &expected).unwrap();
        guard.verify_unchanged(&compiler).unwrap();
        let mut wrong_facts = expected;
        wrong_facts.verbose_version.push_str(" changed");
        assert!(matches!(
            facts.toolchain_guard(&compiler, &wrong_facts),
            Err(FactsMiss::Pending)
        ));
        assert!(
            guard
                .verify_unchanged(&compiler.with_file_name("another-rustc"))
                .unwrap_err()
                .contains("different compiler")
        );
    }

    #[test]
    fn retained_toolchain_guard_cannot_adopt_a_refreshed_equal_byte_generation() {
        let (_dir, compiler) = toolchain_fixture();
        let root = compiler.parent().unwrap().parent().unwrap();
        let probed = probe_toolchain(&compiler, &[]).unwrap();
        let expected = probed.facts.clone();
        let facts = LiveFacts::new();
        facts
            .toolchains
            .lock()
            .unwrap()
            .insert(compiler.clone(), Slot::Ready(Arc::new(probed)));
        let original = facts.toolchain_guard(&compiler, &expected).unwrap();
        facts.toolchains.lock().unwrap().clear();
        original.verify_unchanged(&compiler).unwrap();

        let library = root.join("lib/libdriver.so");
        let retained = root.join("lib/retained-runtime");
        std::fs::rename(&library, &retained).unwrap();
        std::fs::write(&library, b"runtime-v1").unwrap();
        let refreshed = probe_toolchain(&compiler, &[]).unwrap();
        assert_eq!(refreshed.facts, expected, "canonical bytes did not change");
        facts
            .toolchains
            .lock()
            .unwrap()
            .insert(compiler.clone(), Slot::Ready(Arc::new(refreshed)));
        facts
            .toolchain_guard(&compiler, &expected)
            .unwrap()
            .verify_unchanged(&compiler)
            .unwrap();
        assert!(original.verify_unchanged(&compiler).is_err());
    }

    #[test]
    fn retained_toolchain_guard_detects_membership_without_consuming_warm_capacity() {
        let (_dir, compiler) = toolchain_fixture();
        let root = compiler.parent().unwrap().parent().unwrap();
        let probed = probe_toolchain(&compiler, &[]).unwrap();
        let expected = probed.facts.clone();
        let facts = LiveFacts::new();
        facts
            .toolchains
            .lock()
            .unwrap()
            .insert(compiler.clone(), Slot::Ready(Arc::new(probed)));
        let guard = facts.toolchain_guard(&compiler, &expected).unwrap();
        *facts.warming.lock().unwrap() = MAX_WARMING;
        std::fs::write(root.join("lib/rustlib/test-host/lib/libnew.rlib"), b"new").unwrap();
        assert!(guard.verify_unchanged(&compiler).is_err());
        assert!(matches!(
            facts.toolchain_guard(&compiler, &expected),
            Err(FactsMiss::Refused(_))
        ));
        assert_eq!(*facts.warming.lock().unwrap(), MAX_WARMING);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn failed_probe_processes_release_the_actual_shared_warm_pool() {
        let (first_dir, first) = toolchain_fixture();
        let (second_dir, second) = toolchain_fixture();
        let (_healthy_dir, healthy) = toolchain_fixture();
        let facts = LiveFacts::new();
        // Hold two real probe processes until both warm slots are in use.
        // Marker files are outside the observed toolchain, not keyed inputs.
        let script = br#"#!/bin/sh
printf started > "$STARTED"
while [ ! -f "$RELEASE" ]; do /bin/sleep 0.01; done
trap 'exit 0' TERM
while :; do printf '%0200d' 0; done
"#;
        let probes = [(&first, first_dir.path()), (&second, second_dir.path())];
        for (compiler, root) in probes {
            std::fs::write(compiler, script).unwrap();
            let env = vec![
                ("STARTED".into(), root.join("started").to_str().unwrap().into()),
                ("RELEASE".into(), root.join("release").to_str().unwrap().into()),
            ];
            assert_eq!(facts.toolchain(compiler, &env), Err(FactsMiss::Pending));
        }
        let deadline = Instant::now() + Duration::from_secs(8);
        while probes.iter().any(|(_, root)| !root.join("started").exists()) {
            assert!(Instant::now() < deadline, "probe processes did not start");
            std::thread::sleep(Duration::from_millis(5));
        }
        assert_eq!(*facts.warming.lock().unwrap(), MAX_WARMING);
        assert_eq!(facts.toolchain(&healthy, &[]), Err(FactsMiss::Pending));
        assert!(!facts.toolchains.lock().unwrap().contains_key(&healthy));

        for (_, root) in probes {
            std::fs::write(root.join("release"), b"continue").unwrap();
        }
        let deadline = Instant::now() + Duration::from_secs(8);
        while *facts.warming.lock().unwrap() != 0 {
            assert!(Instant::now() < deadline, "failed probes stranded warm capacity");
            std::thread::sleep(Duration::from_millis(5));
        }
        for (compiler, _) in probes {
            assert!(matches!(
                facts.toolchain(compiler, &[]),
                Err(FactsMiss::Refused(reason)) if reason.contains("capture exceeds")
            ));
            assert!(matches!(
                facts.toolchains.lock().unwrap().get(compiler),
                Some(Slot::Failed { .. })
            ));
        }
        // This is the ordinary public lookup, not an injected Ready slot or
        // a manual capacity reset. Unrelated toolchains can now warm again.
        let deadline = Instant::now() + Duration::from_secs(8);
        loop {
            match facts.toolchain(&healthy, &[]) {
                Ok(toolchain) => {
                    facts
                        .toolchain_guard(&healthy, &toolchain)
                        .unwrap()
                        .verify_unchanged(&healthy)
                        .unwrap();
                    break;
                }
                Err(FactsMiss::Pending) => {
                    assert!(Instant::now() < deadline, "healthy toolchain could not recover");
                    std::thread::sleep(Duration::from_millis(5));
                }
                Err(error) => panic!("healthy probe refused after capacity recovery: {error}"),
            }
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn a_failed_reprobe_cannot_resurrect_an_old_toolchain_guard() {
        let (_dir, compiler) = toolchain_fixture();
        let facts = LiveFacts::new();
        let observed = probe_toolchain(&compiler, &[]).unwrap();
        let expected = observed.facts.clone();
        facts
            .toolchains
            .lock()
            .unwrap()
            .insert(compiler.clone(), Slot::Ready(Arc::new(observed)));
        let guard = facts.toolchain_guard(&compiler, &expected).unwrap();
        std::fs::write(
            &compiler,
            b"#!/bin/sh\nwhile :; do printf '%0200d' 0 >&2; done\n",
        )
        .unwrap();
        assert!(guard.verify_unchanged(&compiler).is_err());
        assert_eq!(facts.toolchain(&compiler, &[]), Err(FactsMiss::Pending));
        let deadline = Instant::now() + Duration::from_secs(8);
        loop {
            match facts.toolchain(&compiler, &[]) {
                Err(FactsMiss::Refused(reason)) => {
                    assert!(reason.contains("capture exceeds"), "{reason}");
                    break;
                }
                Err(FactsMiss::Pending) => {
                    assert!(Instant::now() < deadline, "failed reprobe stayed pending");
                    std::thread::sleep(Duration::from_millis(5));
                }
                Ok(_) => panic!("a partial failed probe became ready toolchain facts"),
            }
        }
        assert!(facts.toolchain_guard(&compiler, &expected).is_err());
        assert!(guard.verify_unchanged(&compiler).is_err());
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
