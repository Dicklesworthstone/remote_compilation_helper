//! Restart-safe private Cargo target state for the local canonical driver.
//!
//! The caller holds StateOwner through every operation and exposes only fresh
//! workspace/target copies to Cargo. This cache never skips Cargo or authorizes
//! action-result publication. One committed seed and one pending replacement
//! may coexist: the temporary disk bound is twice max_bytes, plus bounded
//! metadata. Failed captures preserve the previous committed seed.

use super::{create_private, private_directory};
use crate::edge::live_facts::read_stable;
use rabs_cas::materialization::{publish_new_directory, try_verified_reflink};
use rabs_sandbox::artifact_tree::{
    MAX_PRIVATE_TREE_BYTES, MAX_PRIVATE_TREE_ENTRIES, TreeInventory,
};
use rabs_sandbox::cargo_target::state::{
    MAX_SNAPSHOT_METADATA_BYTES, PrivateTreeSnapshot, SourceTimestamps,
};
use rabs_sandbox::source_transfer::{SourceFile, SourceManifest};
use rustix::fs::{CWD, Dir, Mode, OFlags, ResolveFlags, openat2};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::ffi::OsStr;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::time::SystemTime;

const VERSION: &str = "canonical-private-target-v1";
const DIGEST_DOMAIN: &[u8] = b"rabs.canonical-private-target.metadata.v1\0";
const METADATA: &str = "metadata.json";

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

fn default_max_bytes() -> u64 {
    1024 * 1024 * 1024
}

/// The epoch identifies host runtime inputs outside the captured Rust toolchain.
/// The caller also binds it into the target compatibility key.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct TargetCacheConfig {
    pub runtime_epoch: String,
    #[serde(default = "default_max_bytes")]
    pub max_bytes: u64,
}

impl TargetCacheConfig {
    pub fn validate(&self) -> io::Result<()> {
        require(
            !self.runtime_epoch.is_empty()
                && self.runtime_epoch.len() <= 256
                && self
                    .runtime_epoch
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-')),
            "target cache runtime_epoch must be 1..256 ASCII letters, digits, dots, underscores or hyphens",
        )?;
        require(
            self.max_bytes > 0 && self.max_bytes <= MAX_PRIVATE_TREE_BYTES,
            "target cache max_bytes must be between 1 and 8589934592",
        )
    }
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SourceRow {
    path: String,
    len: u64,
    sha256: [u8; 32],
    executable: bool,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SeedPayload {
    version: String,
    key: [u8; 32],
    source: Vec<SourceRow>,
    source_times: SourceTimestamps,
    target: PrivateTreeSnapshot,
}

impl SeedPayload {
    fn source_manifest(&self) -> io::Result<SourceManifest> {
        SourceManifest::new(
            self.source
                .iter()
                .map(|file| SourceFile {
                    path: file.path.clone(),
                    len: file.len,
                    sha256: file.sha256,
                    executable: file.executable,
                })
                .collect(),
        )
    }
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SeedEnvelope {
    sha256: [u8; 32],
    payload: SeedPayload,
}

/// Keep generated metadata under the same bound as persisted input, without
/// first allocating an arbitrarily large serialized tree.
fn encode(value: &impl Serialize) -> io::Result<Vec<u8>> {
    struct BoundedBytes(Vec<u8>);
    impl Write for BoundedBytes {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            require(
                self.0.len().saturating_add(bytes.len()) <= MAX_SNAPSHOT_METADATA_BYTES as usize,
                "target seed metadata exceeds its byte bound",
            )?;
            self.0.extend_from_slice(bytes);
            Ok(bytes.len())
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }
    let mut bytes = BoundedBytes(Vec::new());
    serde_json::to_writer(&mut bytes, value).map_err(io::Error::other)?;
    Ok(bytes.0)
}

fn payload_digest(payload: &SeedPayload) -> io::Result<[u8; 32]> {
    let mut digest = Sha256::new();
    digest.update(DIGEST_DOMAIN);
    digest.update(encode(payload)?);
    Ok(digest.finalize().into())
}

fn open_directory(path: &Path) -> io::Result<File> {
    private_directory(path)?;
    let directory = File::from(openat2(
        CWD,
        path,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
        Mode::empty(),
        ResolveFlags::NO_SYMLINKS | ResolveFlags::NO_MAGICLINKS,
    )?);
    check_private_directory(directory)
}

/// Known cache children must remain on their parent's mount, including a
/// same-device bind mount at the child itself. Absolute traversal roots alone
/// cannot establish that boundary.
fn open_child_directory(parent: &File, name: &OsStr) -> io::Result<File> {
    let directory = File::from(openat2(
        parent,
        name,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
        ResolveFlags::BENEATH | ResolveFlags::NO_SYMLINKS | ResolveFlags::NO_XDEV,
    )?);
    check_private_directory(directory)
}

fn check_private_directory(directory: File) -> io::Result<File> {
    let metadata = directory.metadata()?;
    require(
        metadata.uid() == rustix::process::geteuid().as_raw() && metadata.mode() & 0o7777 == 0o700,
        "private target directories must be owned and mode 0700",
    )?;
    Ok(directory)
}

fn child_name(path: &Path) -> io::Result<&OsStr> {
    path.file_name()
        .ok_or_else(|| invalid("private cache child needs an ordinary name"))
}

fn present_directory(path: &Path, parent: &File) -> io::Result<bool> {
    match open_child_directory(parent, child_name(path)?) {
        Ok(_) => Ok(true),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error),
    }
}

fn private_metadata(path: &Path) -> io::Result<()> {
    let metadata = fs::symlink_metadata(path)?;
    require(
        metadata.is_file()
            && metadata.uid() == rustix::process::geteuid().as_raw()
            && metadata.mode() & 0o7777 == 0o600
            && metadata.nlink() == 1,
        "target seed metadata must be a private, ordinary unaliased file",
    )
}

/// Membership checks are bounded before any recovery removal. No unrelated
/// name, symlink, special file or mounted subtree becomes cleanup authority.
fn generation_members(path: &Path, parent: &File, complete: bool) -> io::Result<File> {
    let generation = open_child_directory(parent, child_name(path)?)?;
    let mut target = false;
    let mut metadata = false;
    for entry in fs::read_dir(path)? {
        let entry = entry?;
        match entry.file_name().to_str() {
            Some("target") if !target => {
                open_child_directory(&generation, OsStr::new("target"))?;
                target = true;
            }
            Some(METADATA) if !metadata => {
                private_metadata(&entry.path())?;
                metadata = true;
            }
            _ => return Err(invalid("unexpected entry in private target generation")),
        }
    }
    require(!complete || (target && metadata), "incomplete target seed")?;
    Ok(generation)
}

/// An interrupted first copy can contain no regular files, which is correctly
/// outside the artifact inventory's nonempty-output contract. Such pending
/// state is still reclaimable after this separate, bounded no-follow check.
fn validate_directory_only_tree(root: &File) -> io::Result<()> {
    fn visit(directory: &File, depth: usize, count: &mut usize) -> io::Result<()> {
        require(
            depth <= 32,
            "pending target directory depth exceeds its bound",
        )?;
        let mut entries = Dir::read_from(directory)?;
        while let Some(entry) = entries.read() {
            let entry = entry?;
            if matches!(entry.file_name().to_bytes(), b"." | b"..") {
                continue;
            }
            *count += 1;
            require(
                *count <= MAX_PRIVATE_TREE_ENTRIES,
                "pending target directory count exceeds its bound",
            )?;
            let child = File::from(openat2(
                directory,
                entry.file_name(),
                OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                Mode::empty(),
                ResolveFlags::BENEATH | ResolveFlags::NO_SYMLINKS | ResolveFlags::NO_XDEV,
            )?);
            let metadata = child.metadata()?;
            require(
                metadata.uid() == rustix::process::geteuid().as_raw()
                    && metadata.mode() & 0o7000 == 0
                    && metadata.mode() & 0o700 == 0o700,
                "pending target directory is not ordinary owner-accessible state",
            )?;
            visit(&child, depth + 1, count)?;
        }
        Ok(())
    }
    let mut count = 0;
    visit(root, 0, &mut count)
}

/// One private owner under the caller's exclusive canonical StateOwner lock.
pub(super) struct TargetState {
    root: PathBuf,
    owner: File,
    key: [u8; 32],
    max_bytes: u64,
    workspace: PathBuf,
    manifest: SourceManifest,
    source_times: SourceTimestamps,
}

impl TargetState {
    pub fn open(
        state_parent: &Path,
        config: &TargetCacheConfig,
        key: [u8; 32],
        workspace: &Path,
        manifest: &SourceManifest,
    ) -> io::Result<Self> {
        config.validate()?;
        private_directory(state_parent)?;
        let root = state_parent.join("private-target-v1");
        match create_private(&root) {
            Ok(()) => File::open(state_parent)?.sync_all()?,
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
            Err(error) => return Err(error),
        }
        let owner = open_child_directory(&File::open(state_parent)?, child_name(&root)?)?;
        require(
            !workspace.starts_with(&root) && !root.starts_with(workspace),
            "private target cache and runtime workspace must be disjoint",
        )?;
        let source_times = SourceTimestamps::capture(workspace, manifest, &|| false)?;
        let state = Self {
            root,
            owner,
            key,
            max_bytes: config.max_bytes,
            workspace: workspace.to_path_buf(),
            manifest: manifest.clone(),
            source_times,
        };
        state.recover()?;
        Ok(state)
    }

    fn verify_owner(&self) -> io::Result<()> {
        let held = self.owner.metadata()?;
        let current = open_directory(&self.root)?.metadata()?;
        require(
            (held.dev(), held.ino()) == (current.dev(), current.ino()),
            "private target cache owner was replaced",
        )
    }

    fn recover(&self) -> io::Result<()> {
        self.verify_owner()?;
        for entry in fs::read_dir(&self.root)? {
            let entry = entry?;
            require(
                matches!(
                    entry.file_name().to_str(),
                    Some("seed" | "pending" | "previous")
                ),
                "unrelated entry in private target cache",
            )?;
            open_child_directory(&self.owner, &entry.file_name())?;
        }
        // A pending directory has never crossed the publication frontier, even
        // when it already contains apparently complete metadata.
        self.remove_generation("pending")?;
        let seed = self.root.join("seed");
        let previous = self.root.join("previous");
        if present_directory(&previous, &self.owner)? {
            if present_directory(&seed, &self.owner)? {
                self.remove_generation("previous")?;
            } else {
                let _previous = generation_members(&previous, &self.owner, true)?;
                self.verify_owner()?;
                publish_new_directory(&previous, &seed)?;
            }
        }
        self.verify_owner()
    }

    fn remove_generation(&self, name: &str) -> io::Result<()> {
        require(
            matches!(name, "pending" | "previous" | "seed"),
            "invalid target generation name",
        )?;
        self.verify_owner()?;
        let path = self.root.join(name);
        if !present_directory(&path, &self.owner)? {
            return Ok(());
        }
        let generation = generation_members(&path, &self.owner, false)?;
        let target = path.join("target");
        let target_owner = if present_directory(&target, &generation)? {
            Some(open_child_directory(&generation, OsStr::new("target"))?)
        } else {
            None
        };
        if let Some(target_owner) = &target_owner {
            // Inventory closes cleanup over the existing regular-file profile
            // and its hard bound. Rust's recursive removal does not follow
            // symbolic links; malformed or excessive trees refuse before it.
            if let Err(error) =
                TreeInventory::scan_complete_private(&target, MAX_PRIVATE_TREE_BYTES, &|| false)
                && validate_directory_only_tree(target_owner).is_err()
            {
                return Err(error);
            }
        }
        self.verify_owner()?;
        // Retain the checked generation and target descriptors through removal,
        // and recheck both child mount boundaries after the inventory pass.
        let current = generation_members(&path, &self.owner, false)?;
        let held = generation.metadata()?;
        let current_metadata = current.metadata()?;
        require(
            (held.dev(), held.ino()) == (current_metadata.dev(), current_metadata.ino()),
            "private target generation changed before cleanup",
        )?;
        if let Some(target_owner) = &target_owner {
            let held = target_owner.metadata()?;
            let current = open_child_directory(&generation, OsStr::new("target"))?.metadata()?;
            require(
                (held.dev(), held.ino()) == (current.dev(), current.ino()),
                "private target tree changed before cleanup",
            )?;
        }
        fs::remove_dir_all(&path)?;
        self.owner.sync_all()?;
        self.verify_owner()
    }

    fn load_seed(&self) -> io::Result<Option<SeedPayload>> {
        self.verify_owner()?;
        let seed = self.root.join("seed");
        if !present_directory(&seed, &self.owner)? {
            return Ok(None);
        }
        let _generation = generation_members(&seed, &self.owner, true)?;
        let metadata = seed.join(METADATA);
        let (_, bytes) = read_stable(&metadata, MAX_SNAPSHOT_METADATA_BYTES)?;
        private_metadata(&metadata)?;
        let envelope: SeedEnvelope = serde_json::from_slice(&bytes).map_err(io::Error::other)?;
        require(
            envelope.payload.version == VERSION
                && payload_digest(&envelope.payload)? == envelope.sha256,
            "private target metadata version or digest differs",
        )?;
        envelope.payload.target.validate()?;
        envelope.payload.source_times.validate()?;
        envelope.payload.source_manifest()?;
        require(
            envelope.payload.target.total_bytes() <= self.max_bytes,
            "private target seed exceeds configured byte limit",
        )?;
        self.verify_owner()?;
        Ok(Some(envelope.payload))
    }

    /// On error the caller must discard the candidate target. A healthy seed
    /// must survive a failed private destination or an ineligible source edit;
    /// neither means that the committed Cargo state is corrupt. The adapter
    /// remains available to capture a successful cold execution in this same
    /// operation, including after an unusable target seed was encountered.
    pub fn restore(&mut self, fresh_empty_target: &Path) -> io::Result<bool> {
        let result = self.restore_inner(fresh_empty_target);
        if result.is_err() {
            // Timestamp restoration may have failed after changing only part
            // of the independent workspace. Re-observe its exact input bytes
            // and current times before a cold Cargo execution can become a
            // replacement seed. The sealed source is never retimed.
            self.source_times =
                SourceTimestamps::capture(&self.workspace, &self.manifest, &|| false)?;
        }
        result
    }

    fn restore_inner(&mut self, fresh_empty_target: &Path) -> io::Result<bool> {
        let seed = match self.load_seed() {
            Ok(Some(seed)) => seed,
            Ok(None) => return Ok(false),
            Err(error) => {
                // Unreadable metadata cannot establish a bounded compatible
                // generation. Retire it through the existing checked cleanup;
                // later destination/source errors must not retire a valid one.
                self.remove_generation("seed")?;
                return Err(error);
            }
        };
        if seed.key != self.key {
            return Ok(false);
        }
        require(
            !fresh_empty_target.starts_with(&self.workspace)
                && !self.workspace.starts_with(fresh_empty_target),
            "private restore target and runtime workspace must be disjoint",
        )?;
        require(
            SourceTimestamps::capture(&self.workspace, &self.manifest, &|| false)?
                == self.source_times,
            "runtime workspace changed before target restoration",
        )?;
        let previous = seed.source_manifest()?;
        let wanted = seed.source_times.for_edits(
            &previous,
            &self.manifest,
            &self.source_times,
            &seed.target,
            SystemTime::now(),
        )?;
        seed.target.restore_into_with_cloner(
            &self.root.join("seed/target"),
            fresh_empty_target,
            &|| false,
            try_verified_reflink,
        )?;
        wanted.restore_exact(&self.workspace, &self.manifest, &|| false)?;
        self.verify_owner()?;
        self.source_times = wanted;
        Ok(true)
    }

    /// Called only after successful Cargo exit and full process/session drain.
    /// Snapshotting and cloning finish before the old seed is moved aside.
    pub fn capture(&self, target: &Path) -> io::Result<()> {
        self.verify_owner()?;
        require(
            SourceTimestamps::capture(&self.workspace, &self.manifest, &|| false)?
                == self.source_times,
            "runtime workspace changed during Cargo execution",
        )?;
        let snapshot = PrivateTreeSnapshot::capture(target, self.max_bytes, &|| false)?;
        let pending = self.root.join("pending");
        let previous = self.root.join("previous");
        require(
            !present_directory(&pending, &self.owner)?
                && !present_directory(&previous, &self.owner)?,
            "unfinished private target publication requires recovery",
        )?;
        create_private(&pending)?;
        let copied = pending.join("target");
        create_private(&copied)?;
        snapshot.restore_into_with_cloner(target, &copied, &|| false, try_verified_reflink)?;
        require(
            SourceTimestamps::capture(&self.workspace, &self.manifest, &|| false)?
                == self.source_times,
            "runtime workspace changed during target capture",
        )?;
        let payload = SeedPayload {
            version: VERSION.into(),
            key: self.key,
            source: self
                .manifest
                .files()
                .iter()
                .map(|file| SourceRow {
                    path: file.path.clone(),
                    len: file.len,
                    sha256: file.sha256,
                    executable: file.executable,
                })
                .collect(),
            source_times: self.source_times.clone(),
            target: snapshot,
        };
        let sha256 = payload_digest(&payload)?;
        let bytes = encode(&SeedEnvelope { sha256, payload })?;
        let mut metadata = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(pending.join(METADATA))?;
        metadata.write_all(&bytes)?;
        metadata.sync_all()?;
        File::open(&pending)?.sync_all()?;
        self.verify_owner()?;
        let _pending = generation_members(&pending, &self.owner, true)?;
        let seed = self.root.join("seed");
        if present_directory(&seed, &self.owner)? {
            publish_new_directory(&seed, &previous)?;
        }
        publish_new_directory(&pending, &seed)?;
        self.remove_generation("previous")?;
        self.verify_owner()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::{FileTimes, Permissions};
    use std::os::unix::fs::{PermissionsExt, symlink};
    use std::time::{Duration, UNIX_EPOCH};

    fn private() -> tempfile::TempDir {
        tempfile::Builder::new()
            .permissions(Permissions::from_mode(0o700))
            .tempdir()
            .unwrap()
    }

    fn config() -> TargetCacheConfig {
        TargetCacheConfig {
            runtime_epoch: "runtime-1".into(),
            max_bytes: 1024 * 1024,
        }
    }

    fn source(root: &Path, value: &[u8]) -> SourceManifest {
        let file = root.join("lib.rs");
        fs::write(&file, value).unwrap();
        File::open(&file)
            .unwrap()
            .set_times(FileTimes::new().set_modified(UNIX_EPOCH + Duration::from_secs(1000)))
            .unwrap();
        SourceManifest::new(vec![SourceFile {
            path: "lib.rs".into(),
            len: value.len() as u64,
            sha256: Sha256::digest(value).into(),
            executable: false,
        }])
        .unwrap()
    }

    fn completed_target(root: &Path, value: &[u8]) {
        fs::write(root.join("artifact"), value).unwrap();
    }

    #[test]
    fn config_requires_explicit_bounded_runtime_epoch_and_snapshot_budget() {
        let defaults: TargetCacheConfig =
            serde_json::from_str(r#"{"runtime_epoch":"host.tools-1"}"#).unwrap();
        assert_eq!(defaults.max_bytes, 1024 * 1024 * 1024);
        defaults.validate().unwrap();
        let long_epoch = "a".repeat(257);
        for value in ["", "bad epoch", "../host", "é", long_epoch.as_str()] {
            assert!(
                TargetCacheConfig {
                    runtime_epoch: value.into(),
                    ..config()
                }
                .validate()
                .is_err()
            );
        }
        for max_bytes in [0, MAX_PRIVATE_TREE_BYTES + 1] {
            assert!(
                TargetCacheConfig {
                    max_bytes,
                    ..config()
                }
                .validate()
                .is_err()
            );
        }
        assert!(serde_json::from_str::<TargetCacheConfig>(r#"{"max_bytes":100}"#).is_err());
        assert!(
            serde_json::from_str::<TargetCacheConfig>(r#"{"runtime_epoch":"x","unexpected":1}"#)
                .is_err()
        );
    }

    #[test]
    fn cache_children_refuse_mount_crossings_and_parent_escape() {
        // Exercise the real openat2 boundary using Linux's existing procfs
        // mount; this test does not create mounts or need mount privileges.
        let filesystem_root = File::open("/").unwrap();
        assert_ne!(
            filesystem_root.metadata().unwrap().dev(),
            fs::metadata("/proc").unwrap().dev(),
            "native Linux test requires its existing procfs mount"
        );
        let mount = open_child_directory(&filesystem_root, OsStr::new("proc")).unwrap_err();
        assert_eq!(
            mount.raw_os_error(),
            Some(rustix::io::Errno::XDEV.raw_os_error())
        );

        let parent = private();
        create_private(&parent.path().join("child")).unwrap();
        let parent = open_directory(parent.path()).unwrap();
        assert!(open_child_directory(&parent, OsStr::new("child")).is_ok());
        let escape = open_child_directory(&parent, OsStr::new("../")).unwrap_err();
        assert_eq!(
            escape.raw_os_error(),
            Some(rustix::io::Errno::XDEV.raw_os_error())
        );
    }

    #[test]
    fn restart_restores_independent_target_and_exact_source_times() {
        let state = private();
        let first_workspace = private();
        let manifest = source(first_workspace.path(), b"pub const V:u8=1;");
        let first_target = private();
        completed_target(first_target.path(), b"completed Cargo target");
        let mut first = TargetState::open(
            state.path(),
            &config(),
            [1; 32],
            first_workspace.path(),
            &manifest,
        )
        .unwrap();
        let empty = private();
        assert!(!first.restore(empty.path()).unwrap());
        first.capture(first_target.path()).unwrap();
        let original_times = first.source_times.clone();
        drop(first);

        let next_workspace = private();
        source(next_workspace.path(), b"pub const V:u8=1;");
        File::open(next_workspace.path().join("lib.rs"))
            .unwrap()
            .set_times(FileTimes::new().set_modified(UNIX_EPOCH + Duration::from_secs(2000)))
            .unwrap();
        let mut next = TargetState::open(
            state.path(),
            &config(),
            [1; 32],
            next_workspace.path(),
            &manifest,
        )
        .unwrap();
        let target = private();
        assert!(next.restore(target.path()).unwrap());
        assert_eq!(next.source_times, original_times);
        assert_eq!(
            fs::read(target.path().join("artifact")).unwrap(),
            b"completed Cargo target"
        );
        let seed = state.path().join("private-target-v1/seed/target/artifact");
        assert_ne!(
            fs::metadata(&seed).unwrap().ino(),
            fs::metadata(target.path().join("artifact")).unwrap().ino()
        );
        fs::write(target.path().join("artifact"), b"later private output").unwrap();
        assert_eq!(fs::read(seed).unwrap(), b"completed Cargo target");
        next.capture(target.path()).unwrap();
        assert!(!state.path().join("private-target-v1/previous").exists());
    }

    #[test]
    fn incompatible_key_stays_cold_and_source_edits_become_newer_than_seed() {
        let state = private();
        let first_workspace = private();
        let first_manifest = source(first_workspace.path(), b"old source");
        let target = private();
        completed_target(target.path(), b"old artifact");
        let first = TargetState::open(
            state.path(),
            &config(),
            [2; 32],
            first_workspace.path(),
            &first_manifest,
        )
        .unwrap();
        first.capture(target.path()).unwrap();
        let target_time = fs::metadata(target.path().join("artifact"))
            .unwrap()
            .modified()
            .unwrap();
        drop(first);

        let workspace = private();
        let manifest = source(workspace.path(), b"edited source");
        let empty = private();
        let mut incompatible = TargetState::open(
            state.path(),
            &config(),
            [3; 32],
            workspace.path(),
            &manifest,
        )
        .unwrap();
        assert!(!incompatible.restore(empty.path()).unwrap());
        assert_eq!(fs::read_dir(empty.path()).unwrap().count(), 0);
        drop(incompatible);
        let mut edited = TargetState::open(
            state.path(),
            &config(),
            [2; 32],
            workspace.path(),
            &manifest,
        )
        .unwrap();
        assert!(edited.restore(empty.path()).unwrap());
        assert!(
            fs::metadata(workspace.path().join("lib.rs"))
                .unwrap()
                .modified()
                .unwrap()
                > target_time
        );
        assert_eq!(
            fs::read(workspace.path().join("lib.rs")).unwrap(),
            b"edited source"
        );
    }

    #[test]
    fn corrupt_seed_is_replaced_by_the_same_successful_cold_operation() {
        for corruption in 0..3 {
            let state = private();
            let workspace = private();
            let manifest = source(workspace.path(), b"source");
            let target = private();
            completed_target(target.path(), b"original artifact");
            let mut cache = TargetState::open(
                state.path(),
                &config(),
                [4; 32],
                workspace.path(),
                &manifest,
            )
            .unwrap();
            cache.capture(target.path()).unwrap();
            let seed = state.path().join("private-target-v1/seed");
            if corruption == 1 {
                let mut envelope: SeedEnvelope =
                    serde_json::from_slice(&fs::read(seed.join(METADATA)).unwrap()).unwrap();
                envelope.payload.key = [7; 32];
                fs::write(seed.join(METADATA), encode(&envelope).unwrap()).unwrap();
            } else if corruption == 2 {
                // Bounded reads must not prevent cleanup of the known owned
                // metadata leaf: unlinking never needs to read its bytes.
                OpenOptions::new()
                    .write(true)
                    .open(seed.join(METADATA))
                    .unwrap()
                    .set_len(MAX_SNAPSHOT_METADATA_BYTES + 1)
                    .unwrap();
            } else {
                fs::write(seed.join("target/artifact"), b"corrupt artifact").unwrap();
            }
            let candidate = private();
            assert!(cache.restore(candidate.path()).is_err());
            // Corrupt metadata is retired immediately. A verified descriptor
            // with unusable target bytes is replaced only after Cargo has
            // produced a successful independent cold target. Neither case
            // requires another cold command before a healthy seed is retained.
            assert_eq!(seed.exists(), corruption == 0);
            cache.capture(target.path()).unwrap();
            drop(cache);
            let mut recovered = TargetState::open(
                state.path(),
                &config(),
                [4; 32],
                workspace.path(),
                &manifest,
            )
            .unwrap();
            let fresh = private();
            assert!(recovered.restore(fresh.path()).unwrap());
            assert_eq!(
                fs::read(fresh.path().join("artifact")).unwrap(),
                b"original artifact"
            );
        }
    }

    #[test]
    fn failed_destination_keeps_committed_seed_and_accepts_a_cold_replacement() {
        for missing_destination in [false, true] {
            let state = private();
            let workspace = private();
            let manifest = source(workspace.path(), b"source");
            let target = private();
            completed_target(target.path(), b"committed artifact");
            let mut cache = TargetState::open(
                state.path(),
                &config(),
                [9; 32],
                workspace.path(),
                &manifest,
            )
            .unwrap();
            cache.capture(target.path()).unwrap();
            let seed = state.path().join("private-target-v1/seed");
            let metadata = fs::read(seed.join(METADATA)).unwrap();
            let candidate_owner = private();
            let candidate = if missing_destination {
                candidate_owner.path().join("not-created")
            } else {
                completed_target(candidate_owner.path(), b"unrelated destination bytes");
                candidate_owner.path().to_path_buf()
            };
            let error = cache.restore(&candidate).unwrap_err();
            if missing_destination {
                assert_eq!(error.kind(), io::ErrorKind::NotFound);
            }
            assert_eq!(fs::read(seed.join(METADATA)).unwrap(), metadata);
            assert_eq!(
                fs::read(seed.join("target/artifact")).unwrap(),
                b"committed artifact"
            );

            // The caller keeps this adapter, runs Cargo with its original
            // cold target, and captures only after successful process drain.
            completed_target(target.path(), b"successful cold replacement");
            cache.capture(target.path()).unwrap();
            drop(cache);
            let next_workspace = private();
            source(next_workspace.path(), b"source");
            let mut next = TargetState::open(
                state.path(),
                &config(),
                [9; 32],
                next_workspace.path(),
                &manifest,
            )
            .unwrap();
            let next_target = private();
            assert!(next.restore(next_target.path()).unwrap());
            assert_eq!(
                fs::read(next_target.path().join("artifact")).unwrap(),
                b"successful cold replacement"
            );
        }
    }

    #[test]
    fn ineligible_edit_keeps_healthy_seed_until_successful_cold_replacement() {
        let state = private();
        let old_workspace = private();
        let old_manifest = source(old_workspace.path(), b"old source");
        let old_target = private();
        completed_target(old_target.path(), b"old artifact");
        // A host clock step backwards cannot safely order this edit after the
        // retained target. It does not invalidate the old target's own bytes.
        File::open(old_target.path().join("artifact"))
            .unwrap()
            .set_times(
                FileTimes::new().set_modified(SystemTime::now() + Duration::from_secs(86_400)),
            )
            .unwrap();
        TargetState::open(
            state.path(),
            &config(),
            [10; 32],
            old_workspace.path(),
            &old_manifest,
        )
        .unwrap()
        .capture(old_target.path())
        .unwrap();
        let seed = state.path().join("private-target-v1/seed");
        let metadata = fs::read(seed.join(METADATA)).unwrap();

        let edited_workspace = private();
        let edited_manifest = source(edited_workspace.path(), b"edited source");
        let mut cache = TargetState::open(
            state.path(),
            &config(),
            [10; 32],
            edited_workspace.path(),
            &edited_manifest,
        )
        .unwrap();
        let candidate = private();
        let error = cache.restore(candidate.path()).unwrap_err();
        assert!(error.to_string().contains("clock cannot order"));
        assert_eq!(fs::read(seed.join(METADATA)).unwrap(), metadata);
        assert_eq!(
            fs::read(seed.join("target/artifact")).unwrap(),
            b"old artifact"
        );
        assert_eq!(fs::read_dir(candidate.path()).unwrap().count(), 0);

        let cold_target = private();
        completed_target(cold_target.path(), b"artifact from edited source");
        cache.capture(cold_target.path()).unwrap();
        drop(cache);
        let mut next = TargetState::open(
            state.path(),
            &config(),
            [10; 32],
            edited_workspace.path(),
            &edited_manifest,
        )
        .unwrap();
        assert!(next.restore(candidate.path()).unwrap());
        assert_eq!(
            fs::read(candidate.path().join("artifact")).unwrap(),
            b"artifact from edited source"
        );
    }

    #[test]
    fn recovery_discards_pending_and_restores_previous_after_interrupted_publish() {
        for (rotated, stage) in [
            (false, 0),
            (false, 1),
            (false, 2),
            (true, 0),
            (true, 1),
            (true, 2),
        ] {
            let state = private();
            let workspace = private();
            let manifest = source(workspace.path(), b"source");
            let target = private();
            completed_target(target.path(), b"committed target");
            let cache = TargetState::open(
                state.path(),
                &config(),
                [5; 32],
                workspace.path(),
                &manifest,
            )
            .unwrap();
            cache.capture(target.path()).unwrap();
            let root = state.path().join("private-target-v1");
            create_private(&root.join("pending")).unwrap();
            create_private(&root.join("pending/target")).unwrap();
            if stage == 1 {
                create_private(&root.join("pending/target/nested")).unwrap();
            } else if stage == 2 {
                fs::write(root.join("pending/target/partial"), b"unfinished").unwrap();
            }
            if rotated {
                publish_new_directory(&root.join("seed"), &root.join("previous")).unwrap();
            }
            drop(cache);
            let mut recovered = TargetState::open(
                state.path(),
                &config(),
                [5; 32],
                workspace.path(),
                &manifest,
            )
            .unwrap();
            let restored = private();
            assert!(recovered.restore(restored.path()).unwrap());
            assert_eq!(
                fs::read(restored.path().join("artifact")).unwrap(),
                b"committed target"
            );
            assert!(!root.join("pending").exists());
            assert!(!root.join("previous").exists());
        }
    }

    #[test]
    fn changed_workspace_or_oversized_capture_preserves_committed_seed() {
        let state = private();
        let workspace = private();
        let manifest = source(workspace.path(), b"source");
        let target = private();
        completed_target(target.path(), b"valid");
        let settings = TargetCacheConfig {
            max_bytes: 10,
            ..config()
        };
        let cache = TargetState::open(
            state.path(),
            &settings,
            [6; 32],
            workspace.path(),
            &manifest,
        )
        .unwrap();
        cache.capture(target.path()).unwrap();
        let seed = state.path().join("private-target-v1/seed/target/artifact");
        completed_target(target.path(), b"oversized target bytes");
        assert!(cache.capture(target.path()).is_err());
        assert_eq!(fs::read(&seed).unwrap(), b"valid");
        fs::write(workspace.path().join("lib.rs"), b"mutated during execution").unwrap();
        assert!(cache.capture(target.path()).is_err());
        assert_eq!(fs::read(seed).unwrap(), b"valid");
    }

    #[test]
    fn recovery_never_follows_a_generation_symlink() {
        let state = private();
        let workspace = private();
        let manifest = source(workspace.path(), b"source");
        let root = state.path().join("private-target-v1");
        create_private(&root).unwrap();
        let outside = private();
        fs::write(outside.path().join("must-remain"), b"unrelated").unwrap();
        symlink(outside.path(), root.join("pending")).unwrap();
        assert!(
            TargetState::open(
                state.path(),
                &config(),
                [7; 32],
                workspace.path(),
                &manifest
            )
            .is_err()
        );
        assert_eq!(
            fs::read(outside.path().join("must-remain")).unwrap(),
            b"unrelated"
        );
        assert!(
            fs::symlink_metadata(root.join("pending"))
                .unwrap()
                .file_type()
                .is_symlink()
        );
    }

    #[test]
    fn directory_only_pending_cleanup_refuses_nested_symlinks() {
        let state = private();
        let workspace = private();
        let manifest = source(workspace.path(), b"source");
        let root = state.path().join("private-target-v1");
        create_private(&root).unwrap();
        create_private(&root.join("pending")).unwrap();
        create_private(&root.join("pending/target")).unwrap();
        let outside = private();
        fs::write(outside.path().join("must-remain"), b"unrelated").unwrap();
        let alias = root.join("pending/target/alias");
        symlink(outside.path(), &alias).unwrap();
        assert!(
            TargetState::open(
                state.path(),
                &config(),
                [8; 32],
                workspace.path(),
                &manifest
            )
            .is_err()
        );
        assert_eq!(
            fs::read(outside.path().join("must-remain")).unwrap(),
            b"unrelated"
        );
        assert!(
            fs::symlink_metadata(alias)
                .unwrap()
                .file_type()
                .is_symlink()
        );
    }
}
