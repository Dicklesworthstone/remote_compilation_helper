//! Request-bound registry-cache replay into an operation-owned Cargo home.
//!
//! This is input delivery, not Cargo resolution evidence or action-cache
//! authority. Only explicitly selected registry cache/index/source files are
//! copied. Cargo configuration, credentials, installed binaries, global cache
//! databases and lock files are NOT imported. Cargo keeps its original argv
//! and workspace configuration; the canonical namespace still denies network.
//! The input snapshot stays read-only; the independent Cargo home is writable
//! scratch so Cargo may lock, unpack and maintain its own cache metadata.

use crate::canonical_namespace::CanonicalNamespaceSpec;
use crate::snapshot_capture::{MemberKind, capture_sealed_source};
use crate::source_transfer::{MAX_SOURCE_BYTES, MAX_SOURCE_CHUNK, SourceManifest, SourceReceiver};
use sha2::{Digest, Sha256};
use std::fs::{self, File};
use std::io;
use std::path::{Path, PathBuf};

/// An optional source-begin extension, explicitly echoed before source upload.
pub const CARGO_HOME_SOURCE_VERSION: &str = "registry-cargo-home-v1";

fn invalid(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}
fn require(condition: bool, message: &str) -> io::Result<()> {
    if condition { Ok(()) } else { Err(invalid(message)) }
}
fn checkpoint(stopped: &impl Fn() -> bool) -> io::Result<()> {
    if stopped() {
        Err(io::Error::new(io::ErrorKind::TimedOut, "Cargo home preparation interrupted"))
    } else { Ok(()) }
}

/// Validated projection from a directory in the exact transferred source tree.
/// Host paths are neither accepted nor carried by this declaration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CargoHomeProjection {
    prefix: String,
    source_digest: [u8; 32],
    files: SourceManifest,
}

impl CargoHomeProjection {
    pub fn new(prefix: &str, source: &SourceManifest) -> io::Result<Self> {
        require(!prefix.is_empty() && prefix.len() <= 512
            && !prefix.contains(['\\', ':']) && !prefix.chars().any(char::is_control)
            && prefix.split('/').count() <= 16
            && prefix.split('/').all(|part| !part.is_empty() && !matches!(part, "." | "..")),
            "Cargo home prefix must be a bounded relative directory")?;
        let prefix_with_slash = format!("{prefix}/");
        let mut files = Vec::new();
        for file in source.files() {
            let Some(relative) = file.path.strip_prefix(&prefix_with_slash) else { continue; };
            let mut parts = relative.split('/');
            require(parts.next() == Some("registry")
                && matches!(parts.next(), Some("cache" | "index" | "src"))
                && parts.next().is_some(),
                "Cargo home imports only registry/cache, registry/index and registry/src")?;
            let mut selected = file.clone();
            selected.path = relative.to_owned();
            files.push(selected);
        }
        require(!files.is_empty(), "Cargo home prefix has no declared registry files")?;
        Ok(Self { prefix: prefix.to_owned(), source_digest: source.digest(),
            files: SourceManifest::new(files)? })
    }

    #[must_use]
    pub fn prefix(&self) -> &str { &self.prefix }

    /// Reuse coherent capture and SourceReceiver verification, rather than
    /// trusting chmod-only protection or copying unchecked mutable pathnames.
    /// The caller owns the private source/destination parent and excludes
    /// concurrent same-credential mutation, as for ordinary source transfer.
    /// Snapshot scans and filesystem sync are not claimed interruptible; the
    /// same absolute upload budget is checked around them and during copying.
    pub fn prepare(
        &self, source: &SourceReceiver, destination: &Path, stopped: impl Fn() -> bool,
    ) -> io::Result<PreparedCargoHome> {
        checkpoint(&stopped)?;
        require(source.manifest().digest() == self.source_digest,
            "Cargo home projection belongs to another source manifest")?;
        let root = source.sealed_root().ok_or_else(|| invalid("Cargo home requires a sealed source"))?;
        let image = capture_sealed_source(
            &[("cargo-home".to_owned(), root.join(&self.prefix))], false, 2, MAX_SOURCE_BYTES,
        ).map_err(|_| invalid("Cargo home source capture refused"))?;
        checkpoint(&stopped)?;
        // Inspect every selected file BEFORE creating a destination. Captured
        // bytes must still match the original transfer identity, including mode.
        for expected in self.files.files() {
            let member = image.manifest("cargo-home")
                .and_then(|manifest| manifest.members.get(&expected.path));
            let Some(MemberKind::Regular { size, content_sha256, mode, .. }) = member else {
                return Err(invalid("Cargo home member is missing or not regular"));
            };
            require(*size == expected.len && *content_sha256 == expected.sha256
                && (*mode & 0o111 != 0) == expected.executable,
                "Cargo home source differs from the transferred bytes or mode")?;
        }
        checkpoint(&stopped)?;
        let mut receiver = SourceReceiver::create(destination, self.files.clone())?;
        for expected in self.files.files() {
            let bytes = image.file_bytes("cargo-home", &expected.path)
                .ok_or_else(|| invalid("retained Cargo home member missing"))?;
            for (index, chunk) in bytes.chunks(MAX_SOURCE_CHUNK).enumerate() {
                checkpoint(&stopped)?;
                receiver.write_chunk(&expected.path, index as u64 * MAX_SOURCE_CHUNK as u64,
                    chunk, Sha256::digest(chunk).into())?;
            }
        }
        checkpoint(&stopped)?;
        let root = receiver.seal()?.to_path_buf();
        checkpoint(&stopped)?;
        // This is intentionally independent writable runtime state, not an
        // immutable source owner. SourceReceiver's normalized read-only mode
        // protects delivery, then Cargo receives ordinary private file modes.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            for file in self.files.files() {
                checkpoint(&stopped)?;
                fs::set_permissions(root.join(&file.path), fs::Permissions::from_mode(
                    if file.executable { 0o700 } else { 0o600 },
                ))?;
            }
        }
        checkpoint(&stopped)?;
        let directory = File::open(&root)?;
        Ok(PreparedCargoHome { root, directory })
    }
}

/// Only successful copying and whole-projection verification create this value.
/// The caller's source owner retains its private parent through process cleanup.
#[derive(Debug)]
pub struct PreparedCargoHome {
    root: PathBuf,
    directory: File,
}

impl PreparedCargoHome {
    /// Replace only the canonical Cargo-home mount, never HOME, source, outputs
    /// or environment. All checks precede mutation. Caller must retain this
    /// owner until compilation and every descendant writer have drained.
    pub fn apply_to(&self, spec: &mut CanonicalNamespaceSpec) -> io::Result<()> {
        let current = fs::symlink_metadata(&self.root)?;
        require(current.is_dir(), "prepared Cargo home is no longer an ordinary directory")?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            let owned = self.directory.metadata()?;
            require(current.dev() == owned.dev() && current.ino() == owned.ino(),
                "prepared Cargo home directory was replaced")?;
        }
        let visible = Path::new(crate::layout::CARGO_HOME);
        let overlaps = |path: &Path| path.starts_with(visible) || visible.starts_with(path);
        require(!spec.ro_binds.iter().any(|bind| overlaps(&bind.visible)),
            "read-only mount shadows Cargo home")?;
        let mut selected = None;
        for (index, bind) in spec.rw_binds.iter().enumerate() {
            if bind.visible == visible {
                require(selected.replace(index).is_none(), "duplicate Cargo home mount")?;
            } else {
                require(!overlaps(&bind.visible), "writable mount shadows Cargo home")?;
                let backing = fs::canonicalize(&bind.backing)?;
                require(!backing.starts_with(&self.root) && !self.root.starts_with(&backing),
                    "another writable mount aliases prepared Cargo home")?;
            }
        }
        let index = selected.ok_or_else(|| invalid("canonical Cargo home mount is missing"))?;
        spec.rw_binds[index].backing = self.root.clone();
        Ok(())
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use crate::canonical_namespace::Bind;
    use crate::source_transfer::SourceFile;
    use std::os::unix::fs::{MetadataExt, PermissionsExt, symlink};

    fn file(path: &str, bytes: &[u8]) -> SourceFile {
        SourceFile { path:path.to_owned(), len:bytes.len() as u64,
            sha256:Sha256::digest(bytes).into(), executable:false }
    }
    fn fixture(parent: &Path) -> (SourceReceiver, CargoHomeProjection) {
        let entries: [(&str, &[u8]); 3] = [
            ("app/lib.rs", b"not a cache file"),
            ("cache/registry/cache/example/pkg-1.crate", b"archive\0\xff"),
            ("cache/registry/index/example/empty", b""),
        ];
        let manifest = SourceManifest::new(entries.iter().map(|(path, bytes)| file(path, bytes)).collect()).unwrap();
        let projection = CargoHomeProjection::new("cache", &manifest).unwrap();
        let mut receiver = SourceReceiver::create(&parent.join("source"), manifest).unwrap();
        for (path, bytes) in entries {
            if !bytes.is_empty() {
                receiver.write_chunk(path, 0, bytes, Sha256::digest(bytes).into()).unwrap();
            }
        }
        receiver.seal().unwrap();
        (receiver, projection)
    }
    fn spec(parent: &Path) -> CanonicalNamespaceSpec {
        let mut spec = CanonicalNamespaceSpec::new();
        for (name, visible) in [("original-home", crate::layout::CARGO_HOME), ("runtime-home", crate::layout::HOME)] {
            let backing = parent.join(name);
            fs::create_dir_all(&backing).unwrap();
            spec.rw_binds.push(Bind::new(backing, visible));
        }
        spec
    }

    #[test]
    fn projection_refuses_unselected_prefixes_and_non_registry_state() {
        let good = SourceManifest::new(vec![file("cache/registry/cache/example/a.crate", b"x")]).unwrap();
        for prefix in ["", "/cache", "cache/", "../cache", "cache//nested", "cache\\x", "other", "cac"] {
            assert!(CargoHomeProjection::new(prefix, &good).is_err(), "{prefix}");
        }
        for relative in ["credentials", "credentials.toml", "config.toml", "bin/rustc",
            ".package-cache", ".global-cache", "git/db/repo", "registry/credentials.toml"] {
            let manifest = SourceManifest::new(vec![good.files()[0].clone(), file(&format!("cache/{relative}"), b"private")]).unwrap();
            assert!(CargoHomeProjection::new("cache", &manifest).is_err(), "{relative}");
        }
    }

    #[test]
    fn verified_cache_is_independent_writable_and_does_not_touch_original_home() {
        let parent = tempfile::tempdir().unwrap();
        let (source, projection) = fixture(parent.path());
        let prepared = projection.prepare(&source, &parent.path().join("cache-runtime"), || false).unwrap();
        let mut spec = spec(parent.path());
        let original = spec.clone();
        let sentinel = original.rw_binds[0].backing.join("credentials.toml");
        fs::write(&sentinel, b"never import").unwrap();
        prepared.apply_to(&mut spec).unwrap();
        assert_eq!(spec.rw_binds[1], original.rw_binds[1]);
        assert_eq!(spec.env, original.env);
        assert_eq!(spec.cwd, original.cwd);
        let cache_file = prepared.root.join("registry/cache/example/pkg-1.crate");
        let source_file = source.sealed_root().unwrap().join("cache/registry/cache/example/pkg-1.crate");
        assert_eq!(fs::read(&cache_file).unwrap(), b"archive\0\xff");
        assert_ne!(fs::metadata(&cache_file).unwrap().ino(), fs::metadata(&source_file).unwrap().ino());
        assert_eq!(fs::metadata(&cache_file).unwrap().permissions().mode() & 0o777, 0o600);
        assert!(!prepared.root.join("credentials.toml").exists());
        assert!(!prepared.root.join("app").exists());
        fs::write(&cache_file, b"Cargo may update its private cache").unwrap();
        fs::write(prepared.root.join(".package-cache"), b"runtime lock").unwrap();
        assert_eq!(fs::read(source_file).unwrap(), b"archive\0\xff");
        assert_eq!(fs::read(sentinel).unwrap(), b"never import");
    }

    #[test]
    fn changed_bytes_mode_and_symlink_never_prepare_a_cargo_home() {
        for change in 0..3 {
            let parent = tempfile::tempdir().unwrap();
            let (source, projection) = fixture(parent.path());
            let path = source.sealed_root().unwrap().join("cache/registry/cache/example/pkg-1.crate");
            fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
            match change {
                0 => fs::write(&path, b"changed\0\xff").unwrap(),
                1 => fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap(),
                _ => {
                    let saved = parent.path().join("saved");
                    fs::rename(&path, &saved).unwrap();
                    symlink(saved, &path).unwrap();
                }
            }
            let target = parent.path().join("refused");
            assert!(projection.prepare(&source, &target, || false).is_err());
            assert!(!target.exists());
        }
    }

    #[test]
    fn cancellation_and_existing_destinations_never_return_partial_owners() {
        let parent = tempfile::tempdir().unwrap();
        let (source, projection) = fixture(parent.path());
        let target = parent.path().join("refused");
        assert_eq!(projection.prepare(&source, &target, || true).unwrap_err().kind(), io::ErrorKind::TimedOut);
        assert!(!target.exists());
        fs::create_dir(&target).unwrap();
        fs::write(target.join("sentinel"), b"preserve").unwrap();
        assert!(projection.prepare(&source, &target, || false).is_err());
        assert_eq!(fs::read(target.join("sentinel")).unwrap(), b"preserve");
    }

    #[test]
    fn mount_refusal_is_atomic_and_replaced_root_cannot_be_installed() {
        let parent = tempfile::tempdir().unwrap();
        let (source, projection) = fixture(parent.path());
        let prepared = projection.prepare(&source, &parent.path().join("cache-runtime"), || false).unwrap();
        for case in 0..4 {
            let mut spec = spec(parent.path());
            match case {
                0 => { spec.rw_binds.remove(0); }
                1 => spec.rw_binds.push(spec.rw_binds[0].clone()),
                2 => spec.ro_binds.push(spec.rw_binds[0].clone()),
                _ => spec.rw_binds[1].backing = prepared.root.clone(),
            }
            let before = spec.clone();
            assert!(prepared.apply_to(&mut spec).is_err());
            assert_eq!(spec, before);
        }
        let saved = parent.path().join("retired-cache");
        fs::rename(&prepared.root, &saved).unwrap();
        fs::create_dir(&prepared.root).unwrap();
        let mut spec = spec(parent.path());
        let before = spec.clone();
        assert!(prepared.apply_to(&mut spec).is_err());
        assert_eq!(spec, before);
    }
}
