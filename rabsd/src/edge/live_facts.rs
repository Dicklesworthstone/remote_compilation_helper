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
use rabs_key::live_dependency::ToolchainFacts;
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
    members: Vec<(String, MemberSig)>,
    bytes: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum MemberSig {
    Directory,
    File(FileSig),
}

impl PackageFacts {
    /// Re-walk `root` and require exactly the captured members with the
    /// captured identities. Used after the compiler ran against the live
    /// tree: a result is only publishable if its inputs never moved.
    ///
    /// # Errors
    /// A description of the first difference.
    pub fn verify_unchanged(&self, root: &Path) -> Result<(), String> {
        let (members, _) = walk_package(root)?;
        if members == self.members {
            Ok(())
        } else {
            Err("the package tree changed during execution".into())
        }
    }
}

/// Walk a package tree: every directory and regular file with its
/// identity, sorted by relative path. Symlinks and special files refuse:
/// the class keys a plain tree.
fn walk_package(root: &Path) -> Result<(Vec<(String, MemberSig)>, u64), String> {
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
    members.sort_by(|a, b| a.0.cmp(&b.0));
    Ok((members, total))
}

fn capture_package(root: &Path) -> Result<PackageFacts, String> {
    let (before, bytes) = walk_package(root)?;
    // The key's "complete package tree" claim requires the capture policy
    // to have excluded nothing a compiler could read.
    for (relative, _) in &before {
        if member_disposition(relative, false) != MemberDisposition::Include {
            return Err(format!(
                "package member {relative} is outside the capture policy"
            ));
        }
    }
    let snapshot = capture_sealed_source(
        &[(PACKAGE_ROOT.to_owned(), root.to_path_buf())],
        false,
        3,
        MAX_PACKAGE_BYTES,
    )
    .map_err(|error| format!("capture: {error:?}"))?;
    let (after, _) = walk_package(root)?;
    if after != before {
        return Err("package changed during capture".into());
    }
    let manifest = snapshot
        .manifest(PACKAGE_ROOT)
        .ok_or("capture lost its root")?;
    let captured_files = manifest
        .members
        .values()
        .filter(|member| matches!(member, MemberKind::Regular { .. }))
        .count();
    let walked_files = before
        .iter()
        .filter(|(_, sig)| matches!(sig, MemberSig::File(_)))
        .count();
    if captured_files != walked_files
        || manifest
            .members
            .values()
            .any(|member| matches!(member, MemberKind::Symlink { .. }))
    {
        return Err("capture does not cover the complete package tree".into());
    }
    let mut files = Vec::with_capacity(captured_files);
    for (relative, member) in &manifest.members {
        if let MemberKind::Regular { mode, .. } = member {
            let bytes = snapshot
                .file_bytes(PACKAGE_ROOT, relative)
                .ok_or("sealed bytes missing for a captured member")?;
            let object = rabs_cas::digest_set::digest_set(bytes, DigestRequest::default(), None)
                .map_err(|error| format!("digest: {error:?}"))?
                .atp_content_id;
            files.push((relative.clone(), object, mode & 0o111 != 0));
        }
    }
    Ok(PackageFacts {
        snapshot: Arc::new(snapshot),
        files,
        members: before,
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
    packages: Mutex<HashMap<PathBuf, Slot<PackageFacts>>>,
    warming: Mutex<usize>,
}

impl LiveFacts {
    /// Empty state.
    #[must_use]
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
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

    /// The sealed complete tree of a registry package. Small packages are
    /// captured on the request path; larger ones warm in the background.
    ///
    /// # Errors
    /// [`FactsMiss`].
    pub fn package(self: &Arc<Self>, root: &Path) -> Result<Arc<PackageFacts>, FactsMiss> {
        let (members, bytes) = walk_package(root).map_err(FactsMiss::Refused)?;
        {
            let packages = self
                .packages
                .lock()
                .map_err(|_| FactsMiss::Refused("package memo poisoned".into()))?;
            match packages.get(root) {
                Some(Slot::Ready(facts)) if facts.members == members => {
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
            let captured = capture_package(root).map_err(FactsMiss::Refused)?;
            let captured = Arc::new(captured);
            self.retain_package(root, Slot::Ready(Arc::clone(&captured)));
            return Ok(captured);
        }
        self.retain_package(root, Slot::Warming);
        let owned = root.to_path_buf();
        let started = self.start_warm(move |facts| {
            let slot = match capture_package(&owned) {
                Ok(captured) => Slot::Ready(Arc::new(captured)),
                Err(reason) => Slot::Failed {
                    reason,
                    at: Instant::now(),
                },
            };
            facts.retain_package(&owned, slot);
        });
        if !started && let Ok(mut packages) = self.packages.lock() {
            packages.remove(root);
        }
        Err(FactsMiss::Pending)
    }

    fn retain_package(&self, root: &Path, slot: Slot<PackageFacts>) {
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
        packages.insert(root.to_path_buf(), slot);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
        let captured = facts.package(&root).unwrap();
        assert_eq!(
            captured
                .snapshot
                .file_bytes(PACKAGE_ROOT, "src/lib.rs")
                .unwrap(),
            b"pub fn f() {}\n"
        );
        assert!(Arc::ptr_eq(&captured, &facts.package(&root).unwrap()));
        captured.verify_unchanged(&root).unwrap();
        std::fs::write(root.join("src/extra.rs"), b"").unwrap();
        assert!(captured.verify_unchanged(&root).is_err());
        assert!(!Arc::ptr_eq(&captured, &facts.package(&root).unwrap()));
        std::os::unix::fs::symlink("lib.rs", root.join("src/alias.rs")).unwrap();
        assert!(matches!(facts.package(&root), Err(FactsMiss::Refused(_))));
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
