//! SDK byte reuse for the authenticated canonical Cargo service.
//!
//! Cache entries are hints owned independently of the fresh SDK receiver.
//! A complete ordered file inventory freezes every offered range before entry
//! transfer; the sender selects only a verified range or zero. The complete
//! SDK seal remains the only transition into executable toolchain custody.

use super::private_directory;
use super::wire::{
    ToolchainFilePage, ToolchainFilePlan, ToolchainPrefixOffer, ToolchainResume, digest, invalid,
    require,
};
use rabs_protocol::raw_bytes::encode_hex;
use rabs_sandbox::toolchain_dataset::ToolchainIdentity;
use rabs_sandbox::toolchain_file_cache::{
    CacheWriter, SnapshotRange, Snapshots, ToolchainFileCache, same_state,
};
use rabs_sandbox::toolchain_transfer::{
    MAX_TOOLCHAIN_CHUNK, MAX_TOOLCHAIN_METADATA_BYTES, ToolchainCheckpointError, ToolchainEntry,
    ToolchainEntryKind, ToolchainFile, ToolchainReceiver,
};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fs::{self, File};
use std::io::{self, Read, Seek};
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::sync::Arc;

#[cfg(all(test, target_os = "linux"))]
mod tests;

fn checkpoint(stopped: &impl Fn() -> bool) -> io::Result<()> {
    if stopped() {
        Err(io::Error::new(
            io::ErrorKind::Interrupted,
            "SDK file reuse stopped",
        ))
    } else {
        Ok(())
    }
}

fn cache_warning(stage: &str, error: &io::Error) {
    eprintln!(
        "{}",
        serde_json::json!({
            "kind":"canonical-remote-toolchain-cache-warning",
            "stage":stage,
            "message":error.to_string().chars().take(1024).collect::<String>(),
        })
    );
}

/// One service-wide capacity and writer lock. Authenticated peers partition
/// object names, never the quota, and cannot discover another peer's bytes.
pub(super) struct RemoteToolchainFileCache {
    cache: ToolchainFileCache,
    owner: Arc<tempfile::TempDir>,
}

impl RemoteToolchainFileCache {
    pub(super) fn new(parent: &Path, max_bytes: u64) -> io::Result<Self> {
        private_directory(parent)?;
        let owner = Arc::new(
            tempfile::Builder::new()
                .prefix("canonical-remote-sdk-files-")
                .permissions(fs::Permissions::from_mode(0o700))
                .tempdir_in(parent)?,
        );
        let cache = ToolchainFileCache::open(owner.path(), max_bytes)?;
        Ok(Self { cache, owner })
    }

    pub(super) fn for_peer(
        &self,
        peer: [u8; 32],
        identity: ToolchainIdentity,
        stopped: &impl Fn() -> bool,
    ) -> io::Result<ToolchainFileInput> {
        checkpoint(stopped)?;
        let cache = self.cache.for_peer(peer)?;
        let snapshots = match Snapshots::new(cache.clone(), identity.bytes) {
            Ok(snapshots) => Some(snapshots),
            Err(error) => {
                cache_warning("snapshot", &error);
                None
            }
        };
        checkpoint(stopped)?;
        Ok(ToolchainFileInput {
            identity,
            files: BTreeMap::new(),
            last_path: None,
            count: 0,
            bytes: 0,
            metadata: 0,
            snapshots,
            writer: None,
            cache,
            writer_attempted: false,
            current: None,
            sealed: false,
            failed: false,
            _owner: Arc::clone(&self.owner),
        })
    }
}

struct PlannedFile {
    expected: ToolchainFile,
    hit: Option<SnapshotRange>,
}

/// An error poisons this upload independently of the ordinary receiver. In
/// particular, a corrupt imported range cannot be retried as an ordinary miss.
pub(super) struct ToolchainFileInput {
    identity: ToolchainIdentity,
    files: BTreeMap<String, PlannedFile>,
    last_path: Option<String>,
    count: u64,
    bytes: u64,
    metadata: usize,
    snapshots: Option<Snapshots>,
    writer: Option<CacheWriter>,
    cache: ToolchainFileCache,
    writer_attempted: bool,
    current: Option<ToolchainFile>,
    sealed: bool,
    failed: bool,
    // Snapshots and writer close before the private cache storage owner.
    _owner: Arc<tempfile::TempDir>,
}

impl ToolchainFileInput {
    fn begin(&mut self, stopped: &impl Fn() -> bool) -> io::Result<()> {
        require(!self.failed, "SDK file upload was already refused")?;
        self.failed = true;
        checkpoint(stopped)
    }

    pub(super) fn can_decline(&self) -> bool {
        !self.failed && !self.sealed && self.count == 0
    }

    pub(super) fn page(
        &mut self,
        page: &ToolchainFilePage,
        stopped: &impl Fn() -> bool,
    ) -> io::Result<ToolchainFilePlan> {
        self.begin(stopped)?;
        require(
            !self.sealed && u64::from(page.first) == self.count,
            "SDK file pages overlap, skip members or arrive after sealing",
        )?;
        let files = page.native()?;
        if !self.writer_attempted {
            self.writer_attempted = true;
            self.writer = match self.cache.writer(stopped) {
                Ok(writer) => writer,
                Err(error) => {
                    cache_warning("writer", &error);
                    None
                }
            };
            checkpoint(stopped)?;
        }
        let mut plan = ToolchainFilePlan {
            first: page.first,
            missing_files: Vec::new(),
            prefixes: Vec::new(),
        };
        for expected in files {
            checkpoint(stopped)?;
            require(
                self.last_path
                    .as_ref()
                    .is_none_or(|last| last < &expected.path),
                "SDK files must preserve canonical order across pages",
            )?;
            let index =
                u32::try_from(self.count).map_err(|_| invalid("SDK file index overflow"))?;
            self.count = self
                .count
                .checked_add(1)
                .filter(|count| *count <= self.identity.files)
                .ok_or_else(|| invalid("SDK file pages exceed the declared count"))?;
            self.bytes = self
                .bytes
                .checked_add(expected.bytes)
                .filter(|bytes| *bytes <= self.identity.bytes)
                .ok_or_else(|| invalid("SDK file pages exceed the declared bytes"))?;
            self.metadata = self
                .metadata
                .checked_add(256 + 2 * expected.path.len())
                .filter(|bytes| *bytes <= MAX_TOOLCHAIN_METADATA_BYTES)
                .ok_or_else(|| invalid("SDK file pages exceed their metadata bound"))?;
            let hit = match &mut self.snapshots {
                Some(snapshots) => snapshots.append(&expected, true, stopped)?,
                None => None,
            };
            if hit.is_some_and(|hit| hit.bytes == expected.bytes) {
                if let Some(writer) = &mut self.writer {
                    writer.protect(&expected.sha256);
                }
            } else if expected.bytes != 0 {
                plan.missing_files.push(index);
                if let Some(hit) = hit {
                    plan.prefixes.push(ToolchainPrefixOffer {
                        index,
                        offset: hit.bytes,
                        sha256: encode_hex(&hit.sha256),
                    });
                }
            }
            self.last_path = Some(expected.path.clone());
            self.files
                .insert(expected.path.clone(), PlannedFile { expected, hit });
        }
        plan.validate(page)?;
        checkpoint(stopped)?;
        self.failed = false;
        Ok(plan)
    }

    pub(super) fn seal_manifest(&mut self, stopped: &impl Fn() -> bool) -> io::Result<(u64, u64)> {
        self.begin(stopped)?;
        require(
            !self.sealed && self.count == self.identity.files && self.bytes == self.identity.bytes,
            "SDK file inventory differs from the complete declared image",
        )?;
        if let Some(snapshots) = &mut self.snapshots {
            snapshots.seal(stopped)?;
        }
        checkpoint(stopped)?;
        self.sealed = true;
        self.failed = false;
        Ok((self.count, self.bytes))
    }

    pub(super) fn entry(
        &mut self,
        receiver: &mut ToolchainReceiver,
        entry: ToolchainEntry,
        resume: Option<ToolchainResume>,
        stopped: &impl Fn() -> bool,
    ) -> io::Result<()> {
        self.begin(stopped)?;
        require(
            self.sealed && self.current.is_none(),
            "SDK entry arrived before inventory sealing or the previous file completed",
        )?;
        let planned = match &entry.kind {
            ToolchainEntryKind::File { bytes, executable } => {
                let planned = self
                    .files
                    .remove(&entry.path)
                    .ok_or_else(|| invalid("SDK file is absent from its negotiated inventory"))?;
                require(
                    planned.expected.bytes == *bytes && planned.expected.executable == *executable,
                    "SDK entry differs from its negotiated length or executable mode",
                )?;
                Some(planned)
            }
            _ => {
                require(
                    !self.files.contains_key(&entry.path) && resume.is_none(),
                    "SDK non-file entry replaces a regular member or selects file bytes",
                )?;
                None
            }
        };
        receiver.entry(entry)?;
        if let Some(PlannedFile { expected, hit }) = planned {
            let resume =
                resume.ok_or_else(|| invalid("SDK file entry requires a prefix selection"))?;
            let sha256 = digest(&resume.sha256)?;
            require(
                if resume.offset == 0 {
                    sha256 == <[u8; 32]>::from(Sha256::digest([]))
                } else {
                    hit.is_some_and(|hit| hit.bytes == resume.offset && hit.sha256 == sha256)
                },
                "SDK prefix selection differs from the frozen offer",
            )?;
            let mut prefix = None;
            if let Some(hit) = hit.filter(|hit| hit.bytes == resume.offset && hit.sha256 == sha256)
            {
                let mut snapshot = self
                    .snapshots
                    .as_mut()
                    .ok_or_else(|| invalid("SDK snapshot owner disappeared"))?
                    .materialize(hit, stopped)?;
                if hit.bytes == expected.bytes {
                    receiver.import_file(&expected, &mut snapshot, stopped)?;
                } else {
                    import_prefix(receiver, &expected, &mut snapshot, hit, stopped)?;
                    prefix = Some(snapshot);
                }
            }
            if resume.offset == expected.bytes {
                // This also validates empty files, whose only legal offset is
                // zero. Imported full hits already crossed the digest check.
                self.remember(receiver, &expected, stopped)?;
            } else {
                if let Some(writer) = &mut self.writer
                    && let Err(error) = writer.begin_prefix(
                        &expected,
                        prefix.as_mut(),
                        resume.offset,
                        sha256,
                        stopped,
                    )
                {
                    cache_warning("prefix-start", &error);
                    self.writer = None;
                }
                self.current = Some(expected);
            }
        }
        checkpoint(stopped)?;
        self.failed = false;
        Ok(())
    }

    pub(super) fn write_chunk(
        &mut self,
        receiver: &mut ToolchainReceiver,
        path: &str,
        offset: u64,
        bytes: &[u8],
        sha256: [u8; 32],
        stopped: &impl Fn() -> bool,
    ) -> io::Result<()> {
        self.begin(stopped)?;
        let expected = self
            .current
            .as_ref()
            .filter(|file| file.path == path)
            .ok_or_else(|| invalid("SDK bytes have no incomplete negotiated file"))?;
        receiver.write_chunk(path, offset, bytes, sha256)?;
        if let Some(writer) = &mut self.writer
            && let Err(error) = writer.append_prefix(expected, offset, bytes, stopped)
        {
            cache_warning("prefix-append", &error);
            self.writer = None;
        }
        if offset.checked_add(bytes.len() as u64) == Some(expected.bytes) {
            let expected = self.current.take().expect("completed negotiated file");
            self.remember(receiver, &expected, stopped)?;
        }
        checkpoint(stopped)?;
        self.failed = false;
        Ok(())
    }

    fn remember(
        &mut self,
        receiver: &mut ToolchainReceiver,
        expected: &ToolchainFile,
        stopped: &impl Fn() -> bool,
    ) -> io::Result<()> {
        let Some(writer) = &mut self.writer else {
            return Ok(());
        };
        if let Err(error) = writer.finish_prefix(expected, stopped) {
            cache_warning("prefix-finish", &error);
            self.writer = None;
            return Ok(());
        }
        match writer.remember(receiver, expected, stopped) {
            Ok(()) => Ok(()),
            Err(ToolchainCheckpointError::Source(error)) => Err(error),
            Err(ToolchainCheckpointError::Destination(error)) => {
                cache_warning("checkpoint", &error);
                self.writer = None;
                Ok(())
            }
        }
    }

    pub(super) fn finish(&mut self, stopped: &impl Fn() -> bool) -> io::Result<()> {
        self.begin(stopped)?;
        require(
            self.sealed && self.files.is_empty() && self.current.is_none(),
            "SDK upload ended before every negotiated file completed",
        )?;
        self.writer.take();
        checkpoint(stopped)
    }
}

fn import_prefix(
    receiver: &mut ToolchainReceiver,
    expected: &ToolchainFile,
    input: &mut File,
    range: SnapshotRange,
    stopped: &impl Fn() -> bool,
) -> io::Result<()> {
    checkpoint(stopped)?;
    let before = input.metadata()?;
    require(
        range.bytes != 0 && range.bytes < expected.bytes && before.len() == range.bytes,
        "SDK prefix has an invalid retained range",
    )?;
    input.rewind()?;
    let mut offset = 0_u64;
    let mut hash = Sha256::new();
    let mut buffer = [0_u8; MAX_TOOLCHAIN_CHUNK];
    while offset < range.bytes {
        checkpoint(stopped)?;
        let count = (range.bytes - offset).min(buffer.len() as u64) as usize;
        input.read_exact(&mut buffer[..count])?;
        let bytes = &buffer[..count];
        hash.update(bytes);
        receiver.write_chunk(&expected.path, offset, bytes, Sha256::digest(bytes).into())?;
        offset += count as u64;
    }
    checkpoint(stopped)?;
    require(
        input.read(&mut buffer[..1])? == 0
            && same_state(&before, &input.metadata()?)
            && <[u8; 32]>::from(hash.finalize()) == range.sha256,
        "SDK prefix snapshot changed during import",
    )
}
