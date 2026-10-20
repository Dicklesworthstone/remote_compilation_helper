//! Request-bound registry-cache replay into an operation-owned Cargo home.
//!
//! This is input delivery, not Cargo resolution evidence or action-cache
//! authority. Only explicitly selected registry cache/index/source files are
//! copied. Cargo configuration, credentials, installed binaries, global cache
//! databases and lock files are NOT imported. Cargo keeps its original argv
//! and workspace configuration; the canonical namespace still denies network.
//! The input snapshot stays read-only; the independent Cargo home is writable
//! scratch so Cargo may lock, unpack and maintain its own cache metadata.
//! The isolated version also derives an independent read-only workspace with
//! the transport prefix absent. Cache delivery must not add workspace members
//! or alter directory enumeration by Cargo and build scripts.

use crate::canonical_namespace::CanonicalNamespaceSpec;
use crate::snapshot_capture::{MemberKind, SealedSourceSnapshot, capture_sealed_source};
use crate::source_transfer::{MAX_SOURCE_BYTES, MAX_SOURCE_CHUNK, SourceManifest, SourceReceiver};
use sha2::{Digest, Sha256};
use std::fs::{self, File};
use std::io;
use std::path::{Path, PathBuf};

/// An optional source-begin extension, explicitly echoed before source upload.
pub const CARGO_HOME_SOURCE_VERSION: &str = "registry-cargo-home-v1";
/// Cache transport members are excluded from the compiler-visible workspace.
/// The legacy version retains its original visible-prefix semantics, including
/// for saved operations and recovery requests.
pub const ISOLATED_CARGO_HOME_SOURCE_VERSION: &str = "isolated-registry-cargo-home-v1";

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
fn checkpoint(stopped: &impl Fn() -> bool) -> io::Result<()> {
    if stopped() {
        Err(io::Error::new(
            io::ErrorKind::TimedOut,
            "Cargo home preparation interrupted",
        ))
    } else {
        Ok(())
    }
}

/// Validated projection from a directory in the exact transferred source tree.
/// Host paths are neither accepted nor carried by this declaration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CargoHomeProjection {
    prefix: String,
    source_digest: [u8; 32],
    files: SourceManifest,
    workspace: Option<SourceManifest>,
}

impl CargoHomeProjection {
    pub fn new(prefix: &str, source: &SourceManifest) -> io::Result<Self> {
        Self::for_version(CARGO_HOME_SOURCE_VERSION, prefix, source)
    }

    /// Decode the exact negotiated version. New behavior must never silently
    /// reinterpret a previously admitted operation's source layout.
    pub fn for_version(version: &str, prefix: &str, source: &SourceManifest) -> io::Result<Self> {
        require(
            matches!(
                version,
                CARGO_HOME_SOURCE_VERSION | ISOLATED_CARGO_HOME_SOURCE_VERSION
            ),
            "unsupported Cargo home projection version",
        )?;
        require(
            !prefix.is_empty()
                && prefix.len() <= 512
                && !prefix.contains(['\\', ':'])
                && !prefix.chars().any(char::is_control)
                && prefix.split('/').count() <= 16
                && prefix
                    .split('/')
                    .all(|part| !part.is_empty() && !matches!(part, "." | "..")),
            "Cargo home prefix must be a bounded relative directory",
        )?;
        let prefix_with_slash = format!("{prefix}/");
        let mut files = Vec::new();
        let mut workspace = Vec::new();
        for file in source.files() {
            let Some(relative) = file.path.strip_prefix(&prefix_with_slash) else {
                workspace.push(file.clone());
                continue;
            };
            let mut parts = relative.split('/');
            require(
                parts.next() == Some("registry")
                    && matches!(parts.next(), Some("cache" | "index" | "src"))
                    && parts.next().is_some(),
                "Cargo home imports only registry/cache, registry/index and registry/src",
            )?;
            let mut selected = file.clone();
            selected.path = relative.to_owned();
            files.push(selected);
        }
        require(
            !files.is_empty(),
            "Cargo home prefix has no declared registry files",
        )?;
        Ok(Self {
            prefix: prefix.to_owned(),
            source_digest: source.digest(),
            files: SourceManifest::new(files)?,
            workspace: if version == ISOLATED_CARGO_HOME_SOURCE_VERSION {
                Some(SourceManifest::new(workspace)?)
            } else {
                None
            },
        })
    }

    #[must_use]
    pub fn version(&self) -> &'static str {
        if self.workspace.is_some() {
            ISOLATED_CARGO_HOME_SOURCE_VERSION
        } else {
            CARGO_HOME_SOURCE_VERSION
        }
    }

    #[must_use]
    pub fn prefix(&self) -> &str {
        &self.prefix
    }

    /// Reuse coherent capture and SourceReceiver verification, rather than
    /// trusting chmod-only protection or copying unchecked mutable pathnames.
    /// The caller owns the private source/destination parent and excludes
    /// concurrent same-credential mutation, as for ordinary source transfer.
    /// Snapshot scans and filesystem sync are not claimed interruptible; the
    /// same absolute upload budget is checked around them and during copying.
    pub fn prepare(
        &self,
        source: &SourceReceiver,
        destination: &Path,
        stopped: impl Fn() -> bool,
    ) -> io::Result<PreparedCargoHome> {
        checkpoint(&stopped)?;
        require(
            source.manifest().digest() == self.source_digest,
            "Cargo home projection belongs to another source manifest",
        )?;
        let root = source
            .sealed_root()
            .ok_or_else(|| invalid("Cargo home requires a sealed source"))?;
        // Isolated mode derives BOTH views from one complete retained capture.
        // The original source receiver remains unchanged for transfer identity,
        // recovery and any source-byte reuse; it is never mounted as workspace.
        let capture_root = if self.workspace.is_some() {
            root.to_path_buf()
        } else {
            root.join(&self.prefix)
        };
        let image = capture_sealed_source(
            &[("cargo-home".to_owned(), capture_root)],
            false,
            2,
            MAX_SOURCE_BYTES,
        )
        .map_err(|_| invalid("Cargo home source capture refused"))?;
        checkpoint(&stopped)?;
        let cache_prefix = self.workspace.as_ref().map(|_| self.prefix.as_str());
        verify_members(&image, &self.files, cache_prefix)?;
        if let Some(workspace) = &self.workspace {
            verify_members(&image, workspace, None)?;
        }
        checkpoint(&stopped)?;
        let (home_destination, workspace) = if let Some(workspace) = &self.workspace {
            require(
                destination.is_absolute() && destination.file_name().is_some(),
                "isolated Cargo inputs require an absolute new directory",
            )?;
            let destination = fs::canonicalize(
                destination
                    .parent()
                    .ok_or_else(|| invalid("isolated Cargo input parent missing"))?,
            )?
            .join(
                destination
                    .file_name()
                    .ok_or_else(|| invalid("isolated Cargo input name missing"))?,
            );
            require(
                !overlaps(&destination, root),
                "isolated Cargo inputs require separate private storage",
            )?;
            let mut builder = fs::DirBuilder::new();
            #[cfg(unix)]
            {
                use std::os::unix::fs::DirBuilderExt;
                builder.mode(0o700);
            }
            builder.create(&destination)?;
            let projected = copy_members(
                &image,
                workspace,
                None,
                &destination.join("workspace"),
                &stopped,
            )?;
            let directory = File::open(&projected)?;
            (
                destination.join("cargo-home"),
                Some(PreparedWorkspace {
                    root: projected,
                    directory,
                    source_root: root.to_path_buf(),
                }),
            )
        } else {
            (destination.to_path_buf(), None)
        };
        let root = copy_members(
            &image,
            &self.files,
            cache_prefix,
            &home_destination,
            &stopped,
        )?;
        checkpoint(&stopped)?;
        // This is intentionally independent writable runtime state, not an
        // immutable source owner. SourceReceiver's normalized read-only mode
        // protects delivery, then Cargo receives ordinary private file modes.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            for file in self.files.files() {
                checkpoint(&stopped)?;
                fs::set_permissions(
                    root.join(&file.path),
                    fs::Permissions::from_mode(if file.executable { 0o700 } else { 0o600 }),
                )?;
            }
        }
        checkpoint(&stopped)?;
        let directory = File::open(&root)?;
        Ok(PreparedCargoHome {
            root,
            directory,
            workspace,
        })
    }
}

fn captured_path(prefix: Option<&str>, path: &str) -> String {
    prefix.map_or_else(|| path.to_owned(), |prefix| format!("{prefix}/{path}"))
}

/// Validate every selected member before creating either derived tree.
fn verify_members(
    image: &SealedSourceSnapshot,
    files: &SourceManifest,
    prefix: Option<&str>,
) -> io::Result<()> {
    for expected in files.files() {
        let path = captured_path(prefix, &expected.path);
        let member = image
            .manifest("cargo-home")
            .and_then(|manifest| manifest.members.get(&path));
        let Some(MemberKind::Regular {
            size,
            content_sha256,
            mode,
            ..
        }) = member
        else {
            return Err(invalid("Cargo input member is missing or not regular"));
        };
        require(
            *size == expected.len
                && *content_sha256 == expected.sha256
                && (*mode & 0o111 != 0) == expected.executable,
            "Cargo input differs from the transferred bytes or mode",
        )?;
    }
    Ok(())
}

fn copy_members(
    image: &SealedSourceSnapshot,
    files: &SourceManifest,
    prefix: Option<&str>,
    destination: &Path,
    stopped: &impl Fn() -> bool,
) -> io::Result<PathBuf> {
    checkpoint(stopped)?;
    let mut receiver = SourceReceiver::create(destination, files.clone())?;
    for expected in files.files() {
        let path = captured_path(prefix, &expected.path);
        let bytes = image
            .file_bytes("cargo-home", &path)
            .ok_or_else(|| invalid("retained Cargo input member missing"))?;
        for (index, chunk) in bytes.chunks(MAX_SOURCE_CHUNK).enumerate() {
            checkpoint(stopped)?;
            receiver.write_chunk(
                &expected.path,
                index as u64 * MAX_SOURCE_CHUNK as u64,
                chunk,
                Sha256::digest(chunk).into(),
            )?;
        }
    }
    checkpoint(stopped)?;
    let root = receiver.seal()?.to_path_buf();
    checkpoint(stopped)?;
    Ok(root)
}

/// Only successful copying and whole-projection verification create this value.
/// The caller's source owner retains its private parent through process cleanup.
#[derive(Debug)]
pub struct PreparedCargoHome {
    root: PathBuf,
    directory: File,
    workspace: Option<PreparedWorkspace>,
}

#[derive(Debug)]
struct PreparedWorkspace {
    root: PathBuf,
    directory: File,
    source_root: PathBuf,
}

impl PreparedCargoHome {
    #[must_use]
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// The compiler-visible source tree for isolated transport, or None for
    /// legacy requests whose original source prefix remains visible.
    #[must_use]
    pub fn projected_workspace(&self) -> Option<&Path> {
        self.workspace
            .as_ref()
            .map(|workspace| workspace.root.as_path())
    }

    /// Apply the negotiated Cargo-home and optional isolated-workspace views.
    /// HOME, outputs, environment and cwd remain unchanged. All checks precede
    /// mutation; the caller retains this owner through process/drain cleanup.
    pub fn apply_to(&self, spec: &mut CanonicalNamespaceSpec) -> io::Result<()> {
        verify_directory(&self.root, &self.directory)?;
        if let Some(workspace) = &self.workspace {
            verify_directory(&workspace.root, &workspace.directory)?;
        }
        let visible = Path::new(crate::layout::CARGO_HOME);
        let home_overlaps = |path: &Path| overlaps(path, visible);
        require(
            !spec
                .ro_binds
                .iter()
                .any(|bind| home_overlaps(&bind.visible)),
            "read-only mount shadows Cargo home",
        )?;
        let mut selected = None;
        for (index, bind) in spec.rw_binds.iter().enumerate() {
            if bind.visible == visible {
                require(
                    selected.replace(index).is_none(),
                    "duplicate Cargo home mount",
                )?;
            } else {
                require(
                    !home_overlaps(&bind.visible),
                    "writable mount shadows Cargo home",
                )?;
                let backing = fs::canonicalize(&bind.backing)?;
                require(
                    !backing.starts_with(&self.root) && !self.root.starts_with(&backing),
                    "another writable mount aliases prepared Cargo home",
                )?;
            }
        }
        let index = selected.ok_or_else(|| invalid("canonical Cargo home mount is missing"))?;
        let mut workspace_slot = None;
        if let Some(workspace) = &self.workspace {
            let visible = Path::new(crate::layout::WORKSPACE);
            for (read_only, binds) in [(true, &spec.ro_binds), (false, &spec.rw_binds)] {
                for (slot, bind) in binds.iter().enumerate() {
                    if bind.visible == visible {
                        require(
                            workspace_slot.replace((read_only, slot)).is_none(),
                            "duplicate isolated workspace mount",
                        )?;
                        require(
                            bind.backing == workspace.source_root || bind.backing == workspace.root,
                            "workspace mount is not owned by this Cargo projection",
                        )?;
                        continue;
                    }
                    require(
                        !overlaps(&bind.visible, visible),
                        "another mount shadows the isolated workspace",
                    )?;
                    let backing = fs::canonicalize(&bind.backing)?;
                    require(
                        !overlaps(&backing, &workspace.root)
                            && !overlaps(&backing, &workspace.source_root),
                        "another mount aliases isolated or transport-only source",
                    )?;
                    if read_only {
                        require(
                            !overlaps(&backing, &self.root),
                            "another mount exposes the prepared Cargo home",
                        )?;
                    }
                }
            }
            require(
                workspace_slot.is_some(),
                "canonical workspace mount is missing",
            )?;
        }
        let mut prepared = spec.clone();
        prepared.rw_binds[index].backing = self.root.clone();
        if let (Some(workspace), Some((read_only, slot))) = (&self.workspace, workspace_slot) {
            if read_only {
                prepared.ro_binds[slot].backing = workspace.root.clone();
            } else {
                let mut bind = prepared.rw_binds.remove(slot);
                bind.backing = workspace.root.clone();
                prepared.ro_binds.push(bind);
            }
        }
        *spec = prepared;
        Ok(())
    }
}

fn overlaps(left: &Path, right: &Path) -> bool {
    left.starts_with(right) || right.starts_with(left)
}

fn verify_directory(root: &Path, directory: &File) -> io::Result<()> {
    let current = fs::symlink_metadata(root)?;
    require(
        current.is_dir() && fs::canonicalize(root)? == root,
        "prepared Cargo input is no longer an ordinary owned directory",
    )?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let owned = directory.metadata()?;
        require(
            current.dev() == owned.dev() && current.ino() == owned.ino(),
            "prepared Cargo input directory was replaced",
        )?;
    }
    Ok(())
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use crate::canonical_namespace::Bind;
    use crate::source_transfer::SourceFile;
    use std::os::unix::fs::{MetadataExt, PermissionsExt, symlink};

    fn file(path: &str, bytes: &[u8]) -> SourceFile {
        SourceFile {
            path: path.to_owned(),
            len: bytes.len() as u64,
            sha256: Sha256::digest(bytes).into(),
            executable: false,
        }
    }
    fn fixture(parent: &Path) -> (SourceReceiver, CargoHomeProjection) {
        let entries: [(&str, &[u8]); 3] = [
            ("app/lib.rs", b"not a cache file"),
            ("cache/registry/cache/example/pkg-1.crate", b"archive\0\xff"),
            ("cache/registry/index/example/empty", b""),
        ];
        let manifest = SourceManifest::new(
            entries
                .iter()
                .map(|(path, bytes)| file(path, bytes))
                .collect(),
        )
        .unwrap();
        let projection = CargoHomeProjection::new("cache", &manifest).unwrap();
        let mut receiver = SourceReceiver::create(&parent.join("source"), manifest).unwrap();
        for (path, bytes) in entries {
            if !bytes.is_empty() {
                receiver
                    .write_chunk(path, 0, bytes, Sha256::digest(bytes).into())
                    .unwrap();
            }
        }
        receiver.seal().unwrap();
        (receiver, projection)
    }
    fn spec(parent: &Path) -> CanonicalNamespaceSpec {
        let mut spec = CanonicalNamespaceSpec::new();
        for (name, visible) in [
            ("original-home", crate::layout::CARGO_HOME),
            ("runtime-home", crate::layout::HOME),
        ] {
            let backing = parent.join(name);
            fs::create_dir_all(&backing).unwrap();
            spec.rw_binds.push(Bind::new(backing, visible));
        }
        spec
    }

    #[test]
    fn projection_refuses_unselected_prefixes_and_non_registry_state() {
        let good =
            SourceManifest::new(vec![file("cache/registry/cache/example/a.crate", b"x")]).unwrap();
        for prefix in [
            "",
            "/cache",
            "cache/",
            "../cache",
            "cache//nested",
            "cache\\x",
            "other",
            "cac",
        ] {
            assert!(CargoHomeProjection::new(prefix, &good).is_err(), "{prefix}");
        }
        for relative in [
            "credentials",
            "credentials.toml",
            "config.toml",
            "bin/rustc",
            ".package-cache",
            ".global-cache",
            "git/db/repo",
            "registry/credentials.toml",
        ] {
            let manifest = SourceManifest::new(vec![
                good.files()[0].clone(),
                file(&format!("cache/{relative}"), b"private"),
            ])
            .unwrap();
            assert!(
                CargoHomeProjection::new("cache", &manifest).is_err(),
                "{relative}"
            );
        }
    }

    fn private() -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();
        fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o700)).unwrap();
        dir
    }

    #[test]
    fn verified_cache_is_independent_writable_and_does_not_touch_original_home() {
        let parent = private();
        let (source, projection) = fixture(parent.path());
        let prepared = projection
            .prepare(&source, &parent.path().join("cache-runtime"), || false)
            .unwrap();
        let mut spec = spec(parent.path());
        let original = spec.clone();
        let sentinel = original.rw_binds[0].backing.join("credentials.toml");
        fs::write(&sentinel, b"never import").unwrap();
        prepared.apply_to(&mut spec).unwrap();
        assert_eq!(spec.rw_binds[1], original.rw_binds[1]);
        assert_eq!(spec.env, original.env);
        assert_eq!(spec.cwd, original.cwd);
        let cache_file = prepared.root.join("registry/cache/example/pkg-1.crate");
        let source_file = source
            .sealed_root()
            .unwrap()
            .join("cache/registry/cache/example/pkg-1.crate");
        assert_eq!(fs::read(&cache_file).unwrap(), b"archive\0\xff");
        assert_ne!(
            fs::metadata(&cache_file).unwrap().ino(),
            fs::metadata(&source_file).unwrap().ino()
        );
        assert_eq!(
            fs::metadata(&cache_file).unwrap().permissions().mode() & 0o777,
            0o600
        );
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
            let parent = private();
            let (source, projection) = fixture(parent.path());
            let path = source
                .sealed_root()
                .unwrap()
                .join("cache/registry/cache/example/pkg-1.crate");
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
        let parent = private();
        let (source, projection) = fixture(parent.path());
        let target = parent.path().join("refused");
        assert_eq!(
            projection
                .prepare(&source, &target, || true)
                .unwrap_err()
                .kind(),
            io::ErrorKind::TimedOut
        );
        assert!(!target.exists());
        fs::create_dir(&target).unwrap();
        fs::write(target.join("sentinel"), b"preserve").unwrap();
        assert!(projection.prepare(&source, &target, || false).is_err());
        assert_eq!(fs::read(target.join("sentinel")).unwrap(), b"preserve");
    }

    #[test]
    fn mount_refusal_is_atomic_and_replaced_root_cannot_be_installed() {
        let parent = private();
        let (source, projection) = fixture(parent.path());
        let prepared = projection
            .prepare(&source, &parent.path().join("cache-runtime"), || false)
            .unwrap();
        for case in 0..4 {
            let mut spec = spec(parent.path());
            match case {
                0 => {
                    spec.rw_binds.remove(0);
                }
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

    fn isolated_fixture(parent: &Path) -> (SourceReceiver, CargoHomeProjection) {
        let (source, _) = fixture(parent);
        let projection = CargoHomeProjection::for_version(
            ISOLATED_CARGO_HOME_SOURCE_VERSION,
            "cache",
            source.manifest(),
        )
        .unwrap();
        (source, projection)
    }

    fn workspace_spec(parent: &Path, source: &Path) -> CanonicalNamespaceSpec {
        let mut spec = spec(parent);
        spec.rw_binds
            .push(Bind::new(source, crate::layout::WORKSPACE));
        spec
    }

    #[test]
    fn isolated_cache_keeps_transport_members_out_of_workspace_enumeration() {
        let parent = private();
        let (source, projection) = isolated_fixture(parent.path());
        let source_root = source.sealed_root().unwrap();
        let original = source.manifest().clone();
        let legacy = CargoHomeProjection::new("cache", source.manifest()).unwrap();
        assert_eq!(legacy.version(), CARGO_HOME_SOURCE_VERSION);
        assert_eq!(projection.version(), ISOLATED_CARGO_HOME_SOURCE_VERSION);
        assert_ne!(projection, legacy);
        assert!(CargoHomeProjection::for_version("unknown", "cache", source.manifest()).is_err());
        let prepared = projection
            .prepare(&source, &parent.path().join("isolated"), || false)
            .unwrap();
        let workspace = prepared.projected_workspace().unwrap();
        let names = fs::read_dir(workspace)
            .unwrap()
            .map(|entry| entry.unwrap().file_name())
            .collect::<Vec<_>>();
        assert_eq!(names, [std::ffi::OsString::from("app")]);
        assert_eq!(
            fs::read(workspace.join("app/lib.rs")).unwrap(),
            b"not a cache file"
        );
        assert_eq!(
            fs::metadata(workspace.join("app/lib.rs")).unwrap().mode() & 0o777,
            0o444
        );
        assert_ne!(
            fs::metadata(workspace.join("app/lib.rs")).unwrap().ino(),
            fs::metadata(source_root.join("app/lib.rs")).unwrap().ino()
        );
        assert!(source_root.join("cache").is_dir());
        assert_eq!(source.manifest(), &original);
        assert_eq!(
            fs::read(prepared.root().join("registry/cache/example/pkg-1.crate")).unwrap(),
            b"archive\0\xff"
        );
        assert!(
            prepared
                .root()
                .join("registry/index/example/empty")
                .is_file()
        );
        assert!(!prepared.root().join("app").exists());

        let mut namespace = workspace_spec(parent.path(), source_root);
        let before = namespace.clone();
        prepared.apply_to(&mut namespace).unwrap();
        assert!(
            namespace
                .ro_binds
                .iter()
                .any(|bind| bind.visible == Path::new(crate::layout::WORKSPACE)
                    && bind.backing == workspace)
        );
        assert!(
            !namespace
                .rw_binds
                .iter()
                .any(|bind| bind.visible == Path::new(crate::layout::WORKSPACE))
        );
        assert!(
            namespace
                .rw_binds
                .iter()
                .any(|bind| bind.visible == Path::new(crate::layout::CARGO_HOME)
                    && bind.backing == prepared.root())
        );
        assert_eq!(namespace.env, before.env);
        assert_eq!(namespace.cwd, before.cwd);
        assert!(!namespace.allows_network());
        prepared.apply_to(&mut namespace).unwrap();

        let old = legacy
            .prepare(&source, &parent.path().join("legacy"), || false)
            .unwrap();
        assert!(old.projected_workspace().is_none());
        let mut legacy_namespace = workspace_spec(parent.path(), source_root);
        old.apply_to(&mut legacy_namespace).unwrap();
        assert!(
            legacy_namespace
                .rw_binds
                .iter()
                .any(|bind| bind.visible == Path::new(crate::layout::WORKSPACE)
                    && bind.backing == source_root)
        );
    }

    #[test]
    fn isolated_projection_checks_workspace_bytes_and_mode_before_creating_storage() {
        for change in 0..3 {
            let parent = private();
            let (source, projection) = isolated_fixture(parent.path());
            let path = source.sealed_root().unwrap().join("app/lib.rs");
            match change {
                0 => {
                    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
                    fs::write(&path, b"different source").unwrap();
                }
                1 => fs::set_permissions(&path, fs::Permissions::from_mode(0o555)).unwrap(),
                _ => {
                    let saved = parent.path().join("replaced-source");
                    fs::rename(&path, &saved).unwrap();
                    symlink(saved, &path).unwrap();
                }
            }
            let destination = parent.path().join("must-not-exist");
            assert!(projection.prepare(&source, &destination, || false).is_err());
            assert!(!destination.exists());
        }
    }

    #[test]
    fn isolated_destination_cannot_alias_its_sealed_transfer_tree() {
        let parent = private();
        let (source, projection) = isolated_fixture(parent.path());
        let source_root = source.sealed_root().unwrap();
        let alias = parent.path().join("source-alias");
        symlink(source_root, &alias).unwrap();
        assert!(
            projection
                .prepare(&source, &alias.join("nested"), || false)
                .is_err()
        );
        assert!(!source_root.join("nested").exists());
    }

    #[test]
    fn isolated_projection_cancellation_never_returns_one_half_of_the_pair() {
        for stop_after_workspace in [true, false] {
            let parent = private();
            let (source, projection) = isolated_fixture(parent.path());
            let destination = parent.path().join("cancelled");
            let frontier = if stop_after_workspace {
                destination.join("workspace/app/lib.rs")
            } else {
                destination.join("cargo-home/registry/cache/example/pkg-1.crate")
            };
            let error = projection
                .prepare(&source, &destination, || frontier.exists())
                .unwrap_err();
            assert_eq!(error.kind(), io::ErrorKind::TimedOut);
            assert_eq!(
                fs::read(source.sealed_root().unwrap().join("app/lib.rs")).unwrap(),
                b"not a cache file"
            );
            assert!(projection.prepare(&source, &destination, || false).is_err());
        }
    }

    #[test]
    fn isolated_mount_rejects_source_aliases_and_replaced_roots_atomically() {
        let parent = private();
        let (source, projection) = isolated_fixture(parent.path());
        let source_root = source.sealed_root().unwrap();
        let prepared = projection
            .prepare(&source, &parent.path().join("isolated"), || false)
            .unwrap();
        let workspace = prepared.projected_workspace().unwrap();
        for case in 0..6 {
            let mut namespace = workspace_spec(parent.path(), source_root);
            match case {
                0 => {
                    namespace.rw_binds.pop();
                }
                1 => namespace
                    .ro_binds
                    .push(Bind::new(source_root, crate::layout::WORKSPACE)),
                2 => namespace
                    .ro_binds
                    .push(Bind::new(source_root, "/__rabs/repos/leaked-source")),
                3 => namespace.rw_binds[1].backing = workspace.to_path_buf(),
                4 => namespace
                    .rw_binds
                    .push(Bind::new(parent.path(), "/__rabs/workspace/hidden")),
                _ => namespace.rw_binds.last_mut().unwrap().backing = parent.path().to_path_buf(),
            }
            let before = namespace.clone();
            assert!(prepared.apply_to(&mut namespace).is_err(), "case {case}");
            assert_eq!(namespace, before, "case {case}");
        }
        fs::rename(workspace, parent.path().join("retired-workspace")).unwrap();
        fs::create_dir(workspace).unwrap();
        let mut namespace = workspace_spec(parent.path(), source_root);
        let before = namespace.clone();
        assert!(prepared.apply_to(&mut namespace).is_err());
        assert_eq!(namespace, before);
    }
}
