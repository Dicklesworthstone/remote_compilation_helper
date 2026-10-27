//! Restart-safe private Cargo target state for the local canonical driver.
//!
//! The caller holds StateOwner through every operation and exposes only fresh
//! workspace/target copies to Cargo. This cache never skips Cargo or authorizes
//! action-result publication. Compatibility families retain independent seeds
//! under an aggregate snapshot-byte and count budget. One pending replacement may
//! coexist: the temporary disk bound is twice max_bytes, plus bounded metadata.
//! Failed captures preserve the committed families.

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
use std::fs::{self, File, FileTimes, OpenOptions};
use std::io::{self, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::time::SystemTime;

const VERSION: &str = "canonical-private-target-v1";
const DIGEST_DOMAIN: &[u8] = b"rabs.canonical-private-target.metadata.v1\0";
const METADATA: &str = "metadata.json";
const FAMILIES_ROOT: &str = "private-target-v2";
const LEGACY_ROOT: &str = "private-target-v1";
const MAX_FAMILIES: usize = 32;

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

fn default_max_families() -> usize {
    8
}

/// The epoch identifies host runtime inputs outside the captured Rust toolchain.
/// The caller also binds it into the target compatibility key.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct TargetCacheConfig {
    pub runtime_epoch: String,
    #[serde(default = "default_max_bytes")]
    pub max_bytes: u64,
    #[serde(default = "default_max_families")]
    pub max_families: usize,
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
        )?;
        require(
            (1..=MAX_FAMILIES).contains(&self.max_families),
            "target cache max_families must be between 1 and 32",
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

/// One publication transaction, retained below a checked parent directory.
struct TargetFamily {
    root: PathBuf,
    owner: File,
    parent: File,
}

impl TargetFamily {
    fn open(root: PathBuf, parent: &File) -> io::Result<Self> {
        Ok(Self {
            owner: open_child_directory(parent, child_name(&root)?)?,
            parent: parent.try_clone()?,
            root,
        })
    }

    fn verify_owner(&self) -> io::Result<()> {
        let held = self.owner.metadata()?;
        let child = open_child_directory(&self.parent, child_name(&self.root)?)?.metadata()?;
        let current = open_directory(&self.root)?.metadata()?;
        require(
            (held.dev(), held.ino()) == (child.dev(), child.ino())
                && (held.dev(), held.ino()) == (current.dev(), current.ino()),
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
        self.verify_owner()?;
        Ok(Some(envelope.payload))
    }

    fn promote(&self) -> io::Result<()> {
        self.verify_owner()?;
        // Recency is only retention policy. Never alter a target or source
        // timestamp to manufacture Cargo freshness.
        self.owner
            .set_times(FileTimes::new().set_modified(SystemTime::now()))?;
        self.owner.sync_all()?;
        self.verify_owner()
    }

    fn remove_empty(&self) -> io::Result<()> {
        self.verify_owner()?;
        require(
            fs::read_dir(&self.root)?.next().is_none(),
            "nonempty private target family cannot be retired",
        )?;
        self.verify_owner()?;
        fs::remove_dir(&self.root)?;
        self.parent.sync_all()
    }
}

fn family_name(key: &[u8; 32]) -> String {
    key.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn family_key(name: &OsStr) -> io::Result<[u8; 32]> {
    let name = name
        .to_str()
        .ok_or_else(|| invalid("private target family name is not UTF-8"))?;
    require(
        name.len() == 64
            && name
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)),
        "private target family name must be a lowercase SHA-256 digest",
    )?;
    let mut key = [0; 32];
    for (index, byte) in key.iter_mut().enumerate() {
        *byte =
            u8::from_str_radix(&name[index * 2..index * 2 + 2], 16).map_err(io::Error::other)?;
    }
    Ok(key)
}

struct RetainedFamily {
    family: TargetFamily,
    key: [u8; 32],
    bytes: u64,
    used: SystemTime,
}

/// No global mutable index is needed: the exclusive StateOwner serializes
/// writers, and each bounded directory is its own recoverable transaction.
struct TargetFamilies {
    root: TargetFamily,
    max_bytes: u64,
    max_families: usize,
}

impl TargetFamilies {
    fn open(state_parent: &Path, config: &TargetCacheConfig) -> io::Result<Self> {
        private_directory(state_parent)?;
        let parent = open_directory(state_parent)?;
        let path = state_parent.join(FAMILIES_ROOT);
        match create_private(&path) {
            Ok(()) => parent.sync_all()?,
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
            Err(error) => return Err(error),
        }
        Ok(Self {
            root: TargetFamily::open(path, &parent)?,
            max_bytes: config.max_bytes,
            max_families: config.max_families,
        })
    }

    fn family(&self, key: &[u8; 32]) -> io::Result<TargetFamily> {
        self.root.verify_owner()?;
        let path = self.root.root.join(family_name(key));
        match create_private(&path) {
            Ok(()) => self.root.owner.sync_all()?,
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
            Err(error) => return Err(error),
        }
        TargetFamily::open(path, &self.root.owner)
    }

    /// Validate names and the hard entry count before traversing any family.
    /// One extra directory permits a new family's in-flight candidate while
    /// all committed seeds remain available until publication succeeds.
    fn retained(&self) -> io::Result<Vec<RetainedFamily>> {
        self.root.verify_owner()?;
        let mut names = Vec::new();
        for entry in fs::read_dir(&self.root.root)? {
            let entry = entry?;
            let key = family_key(&entry.file_name())?;
            require(
                names.len() < MAX_FAMILIES + 1,
                "private target family count exceeds its recovery bound",
            )?;
            names.push((entry.path(), key));
        }
        let mut retained = Vec::new();
        for (path, key) in names {
            let family = TargetFamily::open(path, &self.root.owner)?;
            family.recover()?;
            let seed = match family.load_seed() {
                Ok(Some(seed)) if seed.key == key => seed,
                Ok(None) => {
                    family.remove_empty()?;
                    continue;
                }
                // Metadata is not serving authority unless it matches this
                // exact family. Retire through the same bounded, no-follow
                // cleanup used by single-family recovery.
                Ok(Some(_)) | Err(_) => {
                    family.remove_generation("seed")?;
                    family.remove_empty()?;
                    continue;
                }
            };
            let used = family.owner.metadata()?.modified()?;
            retained.push(RetainedFamily {
                bytes: seed.target.total_bytes(),
                family,
                key,
                used,
            });
        }
        self.root.verify_owner()?;
        Ok(retained)
    }

    fn prune(&self, protect: Option<[u8; 32]>) -> io::Result<()> {
        let mut retained = self.retained()?;
        let mut bytes = retained.iter().try_fold(0u64, |total, family| {
            total
                .checked_add(family.bytes)
                .ok_or_else(|| invalid("private target retained bytes overflow"))
        })?;
        let mut count = retained.len();
        retained.sort_by_key(|entry| {
            // A selected seed larger than a newly lowered budget cannot be
            // protected. A freshly captured seed always fits by construction.
            (
                protect == Some(entry.key) && entry.bytes <= self.max_bytes,
                entry.used,
                entry.key,
            )
        });
        for entry in retained {
            if count <= self.max_families && bytes <= self.max_bytes {
                break;
            }
            entry.family.remove_generation("seed")?;
            entry.family.remove_empty()?;
            bytes -= entry.bytes;
            count -= 1;
        }
        self.root.verify_owner()
    }

    /// Move the recovered single-family format without copying target bytes.
    /// A crash leaves the directory entirely at the old name or the new one;
    /// existing v2 state wins if an older binary later recreated the v1 name.
    fn migrate(&self, state_parent: &Path) -> io::Result<bool> {
        self.root.verify_owner()?;
        let path = state_parent.join(LEGACY_ROOT);
        let parent = &self.root.parent;
        if !present_directory(&path, parent)? {
            return Ok(false);
        }
        let legacy = TargetFamily::open(path, parent)?;
        legacy.recover()?;
        let seed = match legacy.load_seed() {
            Ok(Some(seed)) => seed,
            Ok(None) => {
                legacy.remove_empty()?;
                return Ok(false);
            }
            Err(_) => {
                legacy.remove_generation("seed")?;
                legacy.remove_empty()?;
                return Ok(false);
            }
        };
        let name = family_name(&seed.key);
        if present_directory(&self.root.root.join(&name), &self.root.owner)? {
            legacy.remove_generation("seed")?;
            legacy.remove_empty()?;
            return Ok(false);
        }
        legacy.verify_owner()?;
        self.root.verify_owner()?;
        rustix::fs::renameat_with(
            parent,
            OsStr::new(LEGACY_ROOT),
            &self.root.owner,
            OsStr::new(&name),
            rustix::fs::RenameFlags::NOREPLACE,
        )?;
        parent.sync_all()?;
        self.root.owner.sync_all()?;
        self.root.verify_owner()?;
        let moved = TargetFamily::open(self.root.root.join(name), &self.root.owner)?;
        let before = legacy.owner.metadata()?;
        let after = moved.owner.metadata()?;
        require(
            (before.dev(), before.ino()) == (after.dev(), after.ino()),
            "private target family changed during migration",
        )?;
        Ok(true)
    }
}

/// One selected family under the caller's exclusive canonical StateOwner lock.
pub(super) struct TargetState {
    families: TargetFamilies,
    family: TargetFamily,
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
        require(
            !workspace.starts_with(state_parent) && !state_parent.starts_with(workspace),
            "private target cache and runtime workspace must be disjoint",
        )?;
        let source_times = SourceTimestamps::capture(workspace, manifest, &|| false)?;
        let families = TargetFamilies::open(state_parent, config)?;
        // Restore aggregate bounds before migration can introduce one family,
        // then enforce the same limits before creating this operation's slot.
        families.prune(Some(key))?;
        if families.migrate(state_parent)? {
            families.prune(Some(key))?;
        }
        let family = families.family(&key)?;
        Ok(Self {
            families,
            family,
            key,
            max_bytes: config.max_bytes,
            workspace: workspace.to_path_buf(),
            manifest: manifest.clone(),
            source_times,
        })
    }

    fn verify_owner(&self) -> io::Result<()> {
        self.families.root.verify_owner()?;
        self.family.verify_owner()
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
        self.verify_owner()?;
        let seed = match self.family.load_seed().and_then(|seed| {
            if let Some(seed) = &seed {
                require(
                    seed.key == self.key && seed.target.total_bytes() <= self.max_bytes,
                    "private target seed family or configured byte limit differs",
                )?;
            }
            Ok(seed)
        }) {
            Ok(Some(seed)) => seed,
            Ok(None) => return Ok(false),
            Err(error) => {
                // Unreadable metadata cannot establish a bounded compatible
                // generation. Retire it through the existing checked cleanup;
                // later destination/source errors must not retire a valid one.
                self.family.remove_generation("seed")?;
                return Err(error);
            }
        };
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
            &self.family.root.join("seed/target"),
            fresh_empty_target,
            &|| false,
            try_verified_reflink,
        )?;
        wanted.restore_exact(&self.workspace, &self.manifest, &|| false)?;
        self.verify_owner()?;
        self.source_times = wanted;
        self.family.promote()?;
        Ok(true)
    }

    /// Called only after the driver accepts Cargo's completed exit and drains
    /// all processes/sessions. Normally failed tests may retain compilation
    /// state; their outcome is never a cached test result.
    /// Snapshotting and cloning finish before the old seed is moved aside.
    pub fn capture(&self, target: &Path) -> io::Result<()> {
        self.verify_owner()?;
        require(
            SourceTimestamps::capture(&self.workspace, &self.manifest, &|| false)?
                == self.source_times,
            "runtime workspace changed during Cargo execution",
        )?;
        let snapshot = PrivateTreeSnapshot::capture(target, self.max_bytes, &|| false)?;
        let pending = self.family.root.join("pending");
        let previous = self.family.root.join("previous");
        require(
            !present_directory(&pending, &self.family.owner)?
                && !present_directory(&previous, &self.family.owner)?,
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
        let _pending = generation_members(&pending, &self.family.owner, true)?;
        let seed = self.family.root.join("seed");
        if present_directory(&seed, &self.family.owner)? {
            publish_new_directory(&seed, &previous)?;
        }
        publish_new_directory(&pending, &seed)?;
        self.family.remove_generation("previous")?;
        self.family.promote()?;
        // Only a complete, durable candidate can displace another family.
        // Startup repeats this bounded pruning after a crash at this frontier.
        self.families.prune(Some(self.key))?;
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
            max_families: default_max_families(),
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

    fn family_path(state: &Path, key: [u8; 32]) -> PathBuf {
        state.join(FAMILIES_ROOT).join(family_name(&key))
    }

    fn capture_family(state: &Path, settings: &TargetCacheConfig, key: [u8; 32], value: &[u8]) {
        let workspace = private();
        let manifest = source(workspace.path(), b"source");
        let target = private();
        completed_target(target.path(), value);
        TargetState::open(state, settings, key, workspace.path(), &manifest)
            .unwrap()
            .capture(target.path())
            .unwrap();
    }

    fn restore_family(
        state: &Path,
        settings: &TargetCacheConfig,
        key: [u8; 32],
    ) -> Option<Vec<u8>> {
        let workspace = private();
        let manifest = source(workspace.path(), b"source");
        let mut cache =
            TargetState::open(state, settings, key, workspace.path(), &manifest).unwrap();
        let target = private();
        cache
            .restore(target.path())
            .unwrap()
            .then(|| fs::read(target.path().join("artifact")).unwrap())
    }

    fn last_used(state: &Path, key: [u8; 32], seconds: u64) {
        File::open(family_path(state, key))
            .unwrap()
            .set_times(FileTimes::new().set_modified(UNIX_EPOCH + Duration::from_secs(seconds)))
            .unwrap();
    }

    #[test]
    fn config_requires_explicit_bounded_runtime_epoch_and_snapshot_budget() {
        let defaults: TargetCacheConfig =
            serde_json::from_str(r#"{"runtime_epoch":"host.tools-1"}"#).unwrap();
        assert_eq!(defaults.max_bytes, 1024 * 1024 * 1024);
        assert_eq!(defaults.max_families, 8);
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
        for max_families in [0, MAX_FAMILIES + 1] {
            assert!(
                TargetCacheConfig {
                    max_families,
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
    fn alternating_families_survive_restarts_and_evict_the_least_recent_use() {
        let state = private();
        let settings = TargetCacheConfig {
            max_families: 2,
            ..config()
        };
        capture_family(state.path(), &settings, [11; 32], b"first workspace");
        capture_family(state.path(), &settings, [12; 32], b"second toolchain");
        last_used(state.path(), [11; 32], 100);
        last_used(state.path(), [12; 32], 200);

        // A restore, even without another capture, persists promotion across
        // the next independently opened owner. Merely selecting a family does
        // not manufacture Cargo freshness or make the target a shared inode.
        assert_eq!(
            restore_family(state.path(), &settings, [11; 32]).as_deref(),
            Some(b"first workspace".as_slice())
        );
        capture_family(state.path(), &settings, [13; 32], b"third profile");
        assert!(!family_path(state.path(), [12; 32]).exists());
        assert_eq!(
            restore_family(state.path(), &settings, [11; 32]).as_deref(),
            Some(b"first workspace".as_slice())
        );
        assert_eq!(
            restore_family(state.path(), &settings, [13; 32]).as_deref(),
            Some(b"third profile".as_slice())
        );
        assert_eq!(
            fs::read_dir(state.path().join(FAMILIES_ROOT))
                .unwrap()
                .count(),
            2
        );
    }

    #[test]
    fn byte_budget_is_aggregate_and_failed_candidates_do_not_evict_families() {
        let state = private();
        let settings = TargetCacheConfig {
            max_bytes: 10,
            ..config()
        };
        capture_family(state.path(), &settings, [14; 32], b"aaaaaa");
        capture_family(state.path(), &settings, [15; 32], b"bbbb");
        last_used(state.path(), [14; 32], 200);
        last_used(state.path(), [15; 32], 100);

        let workspace = private();
        let manifest = source(workspace.path(), b"source");
        let cache = TargetState::open(
            state.path(),
            &settings,
            [16; 32],
            workspace.path(),
            &manifest,
        )
        .unwrap();
        let oversized = private();
        completed_target(oversized.path(), b"too large for the entire cache");
        assert!(cache.capture(oversized.path()).is_err());
        for key in [[14; 32], [15; 32]] {
            assert!(family_path(state.path(), key).join("seed").exists());
        }
        drop(cache);

        // This successful four-byte candidate is published before the older
        // four-byte family is evicted. The six-byte seed remains usable.
        capture_family(state.path(), &settings, [16; 32], b"cccc");
        assert!(!family_path(state.path(), [15; 32]).exists());
        assert_eq!(
            restore_family(state.path(), &settings, [14; 32]).as_deref(),
            Some(b"aaaaaa".as_slice())
        );
        assert_eq!(
            restore_family(state.path(), &settings, [16; 32]).as_deref(),
            Some(b"cccc".as_slice())
        );
        let families = TargetFamilies::open(state.path(), &settings)
            .unwrap()
            .retained()
            .unwrap();
        assert_eq!(families.iter().map(|entry| entry.bytes).sum::<u64>(), 10);
    }

    #[test]
    fn empty_and_interrupted_new_families_preserve_committed_capacity() {
        for partial in [false, true] {
            let state = private();
            let settings = TargetCacheConfig {
                max_families: 1,
                ..config()
            };
            capture_family(state.path(), &settings, [17; 32], b"committed");
            let workspace = private();
            let manifest = source(workspace.path(), b"source");
            let candidate = TargetState::open(
                state.path(),
                &settings,
                [18; 32],
                workspace.path(),
                &manifest,
            )
            .unwrap();
            assert!(family_path(state.path(), [17; 32]).join("seed").exists());
            if partial {
                let pending = candidate.family.root.join("pending");
                create_private(&pending).unwrap();
                create_private(&pending.join("target")).unwrap();
                completed_target(&pending.join("target"), b"not committed");
            }
            drop(candidate);
            assert_eq!(
                restore_family(state.path(), &settings, [17; 32]).as_deref(),
                Some(b"committed".as_slice())
            );
            assert!(!family_path(state.path(), [18; 32]).exists());
        }
    }

    #[test]
    fn startup_enforces_lowered_limits_and_postpublication_crash_budget() {
        let state = private();
        let roomy = TargetCacheConfig {
            max_families: 3,
            ..config()
        };
        for byte in 19..=21 {
            capture_family(state.path(), &roomy, [byte; 32], &[byte; 4]);
            last_used(state.path(), [byte; 32], u64::from(byte));
        }
        // Three committed families are also the crash frontier when a
        // two-family cache publishes a third before its pruning completes.
        let bounded = TargetCacheConfig {
            max_families: 2,
            max_bytes: 8,
            ..config()
        };
        assert_eq!(
            restore_family(state.path(), &bounded, [19; 32]),
            Some(vec![19; 4])
        );
        assert!(!family_path(state.path(), [20; 32]).exists());
        assert!(family_path(state.path(), [21; 32]).join("seed").exists());

        let too_small = TargetCacheConfig {
            max_bytes: 3,
            ..bounded
        };
        assert!(restore_family(state.path(), &too_small, [19; 32]).is_none());
        assert!(!family_path(state.path(), [19; 32]).join("seed").exists());
        assert!(!family_path(state.path(), [21; 32]).exists());
    }

    #[test]
    fn legacy_seed_migrates_without_copying_and_recovers_interrupted_rotation() {
        for rotated in [false, true] {
            let state = private();
            capture_family(state.path(), &config(), [22; 32], b"legacy target");
            let current = family_path(state.path(), [22; 32]);
            let retained_inode = fs::metadata(current.join("seed/target/artifact"))
                .unwrap()
                .ino();
            let legacy = state.path().join(LEGACY_ROOT);
            fs::rename(&current, &legacy).unwrap();
            if rotated {
                publish_new_directory(&legacy.join("seed"), &legacy.join("previous")).unwrap();
                create_private(&legacy.join("pending")).unwrap();
                create_private(&legacy.join("pending/target")).unwrap();
                completed_target(&legacy.join("pending/target"), b"unfinished replacement");
            }
            assert_eq!(
                restore_family(state.path(), &config(), [22; 32]).as_deref(),
                Some(b"legacy target".as_slice())
            );
            assert!(!legacy.exists());
            assert_eq!(
                fs::metadata(current.join("seed/target/artifact"))
                    .unwrap()
                    .ino(),
                retained_inode,
                "migration must rename the retained tree, not recopy it"
            );
            assert!(!current.join("pending").exists());
            assert!(!current.join("previous").exists());
            // Reopening after the rename is the other migration crash state.
            assert_eq!(
                restore_family(state.path(), &config(), [22; 32]).as_deref(),
                Some(b"legacy target".as_slice())
            );
        }
    }

    #[test]
    fn legacy_migration_keeps_existing_family_and_an_unselected_family() {
        for same_key in [false, true] {
            let state = private();
            let legacy_state = private();
            capture_family(state.path(), &config(), [23; 32], b"newer family");
            let legacy_key = if same_key { [23; 32] } else { [24; 32] };
            capture_family(legacy_state.path(), &config(), legacy_key, b"older family");
            fs::rename(
                family_path(legacy_state.path(), legacy_key),
                state.path().join(LEGACY_ROOT),
            )
            .unwrap();
            assert_eq!(
                restore_family(state.path(), &config(), [23; 32]).as_deref(),
                Some(b"newer family".as_slice())
            );
            assert!(!state.path().join(LEGACY_ROOT).exists());
            if !same_key {
                assert_eq!(
                    restore_family(state.path(), &config(), [24; 32]).as_deref(),
                    Some(b"older family".as_slice())
                );
            }
        }
    }

    #[test]
    fn a_misnamed_family_cannot_supply_another_compatibility_key() {
        let state = private();
        capture_family(state.path(), &config(), [25; 32], b"wrong key");
        capture_family(state.path(), &config(), [26; 32], b"unrelated valid family");
        fs::rename(
            family_path(state.path(), [25; 32]),
            family_path(state.path(), [27; 32]),
        )
        .unwrap();
        assert!(restore_family(state.path(), &config(), [27; 32]).is_none());
        assert_eq!(
            restore_family(state.path(), &config(), [26; 32]).as_deref(),
            Some(b"unrelated valid family".as_slice())
        );
        assert!(!family_path(state.path(), [27; 32]).exists());
    }

    #[test]
    fn family_discovery_refuses_unknown_names_symlinks_and_excessive_membership() {
        for bad_entry in 0..3 {
            let state = private();
            let workspace = private();
            let manifest = source(workspace.path(), b"source");
            let outside = private();
            fs::write(outside.path().join("must-remain"), b"unrelated").unwrap();
            let root = state.path().join(FAMILIES_ROOT);
            create_private(&root).unwrap();
            match bad_entry {
                0 => fs::write(root.join("unrelated"), b"do not remove").unwrap(),
                1 => symlink(outside.path(), root.join(family_name(&[28; 32]))).unwrap(),
                _ => {
                    for index in 0..MAX_FAMILIES + 2 {
                        let byte = u8::try_from(index).unwrap();
                        create_private(&root.join(family_name(&[byte; 32]))).unwrap();
                    }
                }
            }
            let before = fs::read_dir(&root).unwrap().count();
            assert!(
                TargetState::open(
                    state.path(),
                    &config(),
                    [29; 32],
                    workspace.path(),
                    &manifest
                )
                .is_err()
            );
            assert_eq!(fs::read_dir(&root).unwrap().count(), before);
            assert_eq!(
                fs::read(outside.path().join("must-remain")).unwrap(),
                b"unrelated"
            );
        }
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
        let seed = family_path(state.path(), [1; 32]).join("seed/target/artifact");
        assert_ne!(
            fs::metadata(&seed).unwrap().ino(),
            fs::metadata(target.path().join("artifact")).unwrap().ino()
        );
        fs::write(target.path().join("artifact"), b"later private output").unwrap();
        assert_eq!(fs::read(seed).unwrap(), b"completed Cargo target");
        next.capture(target.path()).unwrap();
        assert!(!family_path(state.path(), [1; 32]).join("previous").exists());
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
        for (corruption, reopened) in [
            (0, false),
            (1, false),
            (2, false),
            (0, true),
            (1, true),
            (2, true),
        ] {
            let state = private();
            capture_family(state.path(), &config(), [30; 32], b"other family");
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
            let seed = family_path(state.path(), [4; 32]).join("seed");
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
            if reopened {
                drop(cache);
                cache = TargetState::open(
                    state.path(),
                    &config(),
                    [4; 32],
                    workspace.path(),
                    &manifest,
                )
                .unwrap();
            }
            let candidate = private();
            let restored = cache.restore(candidate.path());
            if reopened && corruption != 0 {
                // Startup reads every bounded descriptor for accounting and
                // retires malformed metadata before selecting the cold slot.
                assert!(!restored.unwrap());
            } else {
                assert!(restored.is_err());
            }
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
            drop(recovered);
            assert_eq!(
                restore_family(state.path(), &config(), [30; 32]).as_deref(),
                Some(b"other family".as_slice())
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
            let seed = family_path(state.path(), [9; 32]).join("seed");
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
        let seed = family_path(state.path(), [10; 32]).join("seed");
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
            let root = family_path(state.path(), [5; 32]);
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
        let seed = family_path(state.path(), [6; 32]).join("seed/target/artifact");
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
