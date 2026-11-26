//! Linear publication checkpoints, owned by the existing job-journal gate.
//!
//! The caller verifies that gate before and after each operation and persists
//! a newly created/forked reference before appending or exposing outputs. The
//! log lives beside the lease, independently of disposable retrieval staging.
//! Only the original predecessor of the one pending rename must survive a
//! restart; untouched baselines are observed again under the output lock.

use anyhow::{Context, Result, ensure};
use rustix::fs::{Mode, OFlags};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::ffi::CString;
use std::fs::{File, Metadata};
use std::io::Write;
use std::os::fd::AsFd;
use std::os::unix::fs::{FileExt, MetadataExt};
use std::path::{Component, Path, PathBuf};

const MAX_RECORD_BYTES: usize = 64 * 1024;
const DIGEST_BYTES: u64 = 32;
const NAME_PREFIX: &str = ".rch-publication-";
const NAME_SUFFIX: &str = ".journal";
const READ_FLAGS: OFlags = OFlags::RDONLY
    .union(OFlags::CLOEXEC)
    .union(OFlags::NOFOLLOW)
    .union(OFlags::NONBLOCK)
    .union(OFlags::NOCTTY);

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Intent {
    pub(super) relative: PathBuf,
    pub(super) hash: String,
    pub(super) prior: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Checkpoint {
    offset: u64,
    sequence: u64,
    head: [u8; 32],
    count: u64,
}

/// The serialized reference is constant-sized regardless of published files.
/// A deserialized reference must replay before it can append. Clones retain
/// an optimistic cursor, whose exact EOF/metadata check rejects stale writers.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct JournalRef {
    version: u32,
    name: String,
    directory_device: u64,
    directory_inode: u64,
    device: u64,
    inode: u64,
    owner: u32,
    binding: String,
    initial: Checkpoint,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    terminal: Option<Checkpoint>,
    #[serde(skip)]
    cursor: Option<Cursor>,
}

#[derive(Clone, Debug)]
struct Cursor {
    checkpoint: Checkpoint,
    pending: Option<Intent>,
    observed: Observation,
    torn_tail: bool,
    sealed: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct Observation {
    length: u64,
    modified: (i64, i64),
    changed: (i64, i64),
}

impl Observation {
    fn of(metadata: &Metadata) -> Self {
        Self {
            length: metadata.len(),
            modified: (metadata.mtime(), metadata.mtime_nsec()),
            changed: (metadata.ctime(), metadata.ctime_nsec()),
        }
    }
}

#[derive(Debug)]
pub(super) struct Replay {
    pub(super) published: BTreeMap<PathBuf, String>,
    pub(super) pending: Option<Intent>,
    pub(super) torn_tail: bool,
    pub(super) sealed: bool,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Frame {
    sequence: u64,
    event: Event,
}

#[derive(Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
enum Event {
    Header { version: u32, binding: String },
    SeedPublished { relative: PathBuf, hash: String },
    SeedPending { intent: Intent },
    Start,
    Pending { intent: Intent },
    Published { relative: PathBuf, hash: String },
    Seal,
}

fn validate_hash(hash: &str) -> Result<()> {
    ensure!(
        hash.len() == 64
            && hash
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)),
        "publication journal has a noncanonical BLAKE3 digest"
    );
    Ok(())
}

fn validate_relative(relative: &Path) -> Result<()> {
    let normalized: PathBuf = relative.components().collect();
    ensure!(
        !relative.as_os_str().is_empty()
            && normalized.as_os_str() == relative.as_os_str()
            && relative
                .components()
                .all(|part| matches!(part, Component::Normal(_)))
            && relative
                .to_str()
                .is_some_and(|path| !path.chars().any(char::is_control)),
        "publication journal has an unsafe relative output path"
    );
    Ok(())
}

fn validate_intent(intent: &Intent) -> Result<()> {
    validate_relative(&intent.relative)?;
    validate_hash(&intent.hash)?;
    if let Some(prior) = &intent.prior {
        validate_hash(prior)?;
    }
    Ok(())
}

fn digest(previous: &[u8; 32], length: &[u8; 4], payload: &[u8]) -> [u8; 32] {
    let mut hash = blake3::Hasher::new();
    hash.update(b"rch-publication-journal-v1\0");
    hash.update(previous);
    hash.update(length);
    hash.update(payload);
    *hash.finalize().as_bytes()
}

fn encode(checkpoint: &Checkpoint, event: Event) -> Result<(Vec<u8>, Checkpoint)> {
    let payload = serde_json::to_vec(&Frame {
        sequence: checkpoint.sequence,
        event,
    })?;
    ensure!(
        payload.len() <= MAX_RECORD_BYTES,
        "publication journal record exceeds its size bound"
    );
    let length = u32::try_from(payload.len())?.to_be_bytes();
    let head = digest(&checkpoint.head, &length, &payload);
    let mut bytes = Vec::with_capacity(payload.len() + 36);
    bytes.extend_from_slice(&length);
    bytes.extend_from_slice(&payload);
    bytes.extend_from_slice(&head);
    let mut next = checkpoint.clone();
    next.offset = next
        .offset
        .checked_add(bytes.len() as u64)
        .context("publication journal offset overflow")?;
    next.sequence = next
        .sequence
        .checked_add(1)
        .context("publication journal sequence overflow")?;
    next.head = head;
    Ok((bytes, next))
}

impl JournalRef {
    fn validate_directory(&self, directory: &File) -> Result<()> {
        let metadata = directory.metadata()?;
        ensure!(
            self.version == 1
                && metadata.is_dir()
                && metadata.dev() == self.directory_device
                && metadata.ino() == self.directory_inode
                && metadata.uid() == self.owner
                && self.owner == rustix::process::geteuid().as_raw()
                && metadata.mode() & 0o022 == 0,
            "publication journal directory identity or ownership changed"
        );
        Ok(())
    }

    fn filename(&self) -> Result<CString> {
        let token = self
            .name
            .strip_prefix(NAME_PREFIX)
            .and_then(|name| name.strip_suffix(NAME_SUFFIX));
        ensure!(
            token.is_some_and(
                |token| token.len() == 32 && token.bytes().all(|byte| byte.is_ascii_hexdigit())
            ),
            "publication journal reference has an unsafe filename"
        );
        Ok(CString::new(self.name.as_bytes())?)
    }

    fn verify_file(&self, file: &File) -> Result<Observation> {
        let metadata = file.metadata()?;
        ensure!(
            metadata.is_file()
                && metadata.dev() == self.device
                && metadata.ino() == self.inode
                && metadata.uid() == self.owner
                && metadata.nlink() == 1
                && metadata.mode() & 0o7777 == 0o600,
            "publication journal file identity, links or private permissions changed"
        );
        Ok(Observation::of(&metadata))
    }

    fn open(&self, directory: &File, append: bool) -> Result<File> {
        self.validate_directory(directory)?;
        let flags = if append {
            OFlags::RDWR
                | OFlags::APPEND
                | OFlags::CLOEXEC
                | OFlags::NOFOLLOW
                | OFlags::NONBLOCK
                | OFlags::NOCTTY
        } else {
            READ_FLAGS
        };
        let file = File::from(rustix::fs::openat(
            directory.as_fd(),
            self.filename()?.as_c_str(),
            flags,
            Mode::empty(),
        )?);
        self.verify_file(&file)?;
        Ok(file)
    }

    fn verify_named(&self, directory: &File, held: &File, expected: &Observation) -> Result<()> {
        ensure!(
            self.verify_file(held)? == *expected,
            "publication journal changed while held"
        );
        let named = self.open(directory, false)?;
        ensure!(
            self.verify_file(&named)? == *expected,
            "publication journal changed at its recorded name"
        );
        Ok(())
    }

    fn create_file(directory: &File, binding: &str) -> Result<(Self, File)> {
        validate_hash(binding)?;
        let metadata = directory.metadata()?;
        let owner = rustix::process::geteuid().as_raw();
        ensure!(
            metadata.is_dir() && metadata.uid() == owner && metadata.mode() & 0o022 == 0,
            "unsafe publication journal directory"
        );
        let name = format!(
            "{NAME_PREFIX}{}{NAME_SUFFIX}",
            uuid::Uuid::new_v4().simple()
        );
        let file = File::from(rustix::fs::openat(
            directory.as_fd(),
            name.as_str(),
            OFlags::RDWR
                | OFlags::CREATE
                | OFlags::EXCL
                | OFlags::CLOEXEC
                | OFlags::NOFOLLOW
                | OFlags::NONBLOCK
                | OFlags::NOCTTY,
            Mode::RUSR | Mode::WUSR,
        )?);
        let metadata = file.metadata()?;
        let directory_metadata = directory.metadata()?;
        let reference = Self {
            version: 1,
            name,
            directory_device: directory_metadata.dev(),
            directory_inode: directory_metadata.ino(),
            device: metadata.dev(),
            inode: metadata.ino(),
            owner,
            binding: binding.into(),
            initial: Checkpoint {
                offset: 0,
                sequence: 0,
                head: [0; 32],
                count: 0,
            },
            terminal: None,
            cursor: None,
        };
        reference.verify_file(&file)?;
        reference.validate_directory(directory)?;
        Ok((reference, file))
    }

    /// Bootstrap existing inline progress once before switching the lease to
    /// this reference. Each seed is bounded; Start pins the entire seed prefix.
    pub(super) fn create(
        directory: &File,
        binding: &str,
        published: &BTreeMap<PathBuf, String>,
        pending: Option<Intent>,
    ) -> Result<Self> {
        for (relative, hash) in published {
            validate_relative(relative)?;
            validate_hash(hash)?;
        }
        if let Some(intent) = &pending {
            validate_intent(intent)?;
            ensure!(
                !published.contains_key(&intent.relative),
                "pending publication is already committed"
            );
        }
        let (mut reference, mut file) = Self::create_file(directory, binding)?;
        let mut checkpoint = reference.initial.clone();
        let mut append = |event| -> Result<()> {
            let (bytes, next) = encode(&checkpoint, event)?;
            file.write_all(&bytes)?;
            checkpoint = next;
            Ok(())
        };
        append(Event::Header {
            version: 1,
            binding: binding.into(),
        })?;
        for (relative, hash) in published {
            append(Event::SeedPublished {
                relative: relative.clone(),
                hash: hash.clone(),
            })?;
        }
        if let Some(intent) = &pending {
            append(Event::SeedPending {
                intent: intent.clone(),
            })?;
        }
        append(Event::Start)?;
        checkpoint.count = published.len() as u64;
        reference.initial = checkpoint;
        file.sync_all()?;
        directory.sync_all()?;
        reference.replay(directory, binding)?;
        Ok(reference)
    }

    /// Reconstruct logical state only from a complete authenticated prefix.
    /// A torn final append is retained and requires fork before further writes.
    pub(super) fn replay(&mut self, directory: &File, binding: &str) -> Result<Replay> {
        self.cursor = None;
        validate_hash(binding)?;
        ensure!(
            binding == self.binding,
            "publication journal phase binding changed"
        );
        let file = self.open(directory, false)?;
        let observed = self.verify_file(&file)?;
        let mut checkpoint = Checkpoint {
            offset: 0,
            sequence: 0,
            head: [0; 32],
            count: 0,
        };
        let mut published = BTreeMap::new();
        let mut pending: Option<Intent> = None;
        let mut header = false;
        let mut started = false;
        let mut sealed = false;
        let mut torn_tail = false;
        while checkpoint.offset < observed.length {
            ensure!(
                !sealed,
                "publication journal has bytes after its terminal seal"
            );
            let remaining = observed.length - checkpoint.offset;
            if remaining < 4 {
                torn_tail = true;
                break;
            }
            let mut length = [0; 4];
            file.read_exact_at(&mut length, checkpoint.offset)?;
            let size = u32::from_be_bytes(length) as usize;
            ensure!(
                size > 0 && size <= MAX_RECORD_BYTES,
                "publication journal frame length exceeds its bound"
            );
            let frame_length = 4 + size as u64 + DIGEST_BYTES;
            if remaining < frame_length {
                torn_tail = true;
                break;
            }
            let mut payload = vec![0; size];
            file.read_exact_at(&mut payload, checkpoint.offset + 4)?;
            let mut stored_head = [0; 32];
            file.read_exact_at(&mut stored_head, checkpoint.offset + 4 + size as u64)?;
            ensure!(
                stored_head == digest(&checkpoint.head, &length, &payload),
                "publication journal checksum chain is corrupt"
            );
            let frame: Frame = serde_json::from_slice(&payload)
                .context("invalid complete publication journal frame")?;
            ensure!(
                frame.sequence == checkpoint.sequence,
                "publication journal sequence is discontinuous"
            );
            checkpoint.offset += frame_length;
            checkpoint.sequence = checkpoint
                .sequence
                .checked_add(1)
                .context("publication journal sequence overflow")?;
            checkpoint.head = stored_head;
            match frame.event {
                Event::Header {
                    version,
                    binding: recorded,
                } => {
                    ensure!(
                        frame.sequence == 0 && !header && version == 1 && recorded == binding,
                        "publication journal header contradicts its reference"
                    );
                    header = true;
                }
                Event::SeedPublished { relative, hash } => {
                    ensure!(
                        header && !started && pending.is_none(),
                        "publication bootstrap record is out of order"
                    );
                    validate_relative(&relative)?;
                    validate_hash(&hash)?;
                    ensure!(
                        published.insert(relative, hash).is_none(),
                        "duplicate publication bootstrap path"
                    );
                }
                Event::SeedPending { intent } => {
                    ensure!(
                        header
                            && !started
                            && pending.is_none()
                            && !published.contains_key(&intent.relative),
                        "publication bootstrap pending record is out of order"
                    );
                    validate_intent(&intent)?;
                    pending = Some(intent);
                }
                Event::Start => {
                    ensure!(
                        header && !started,
                        "publication journal start is out of order"
                    );
                    checkpoint.count = published.len() as u64;
                    ensure!(
                        checkpoint == self.initial,
                        "publication journal bootstrap prefix changed"
                    );
                    started = true;
                }
                Event::Pending { intent } => {
                    ensure!(
                        started && pending.is_none() && !published.contains_key(&intent.relative),
                        "publication intent is duplicate or out of order"
                    );
                    validate_intent(&intent)?;
                    pending = Some(intent);
                }
                Event::Published { relative, hash } => {
                    ensure!(
                        started
                            && pending.as_ref().is_some_and(
                                |intent| intent.relative == relative && intent.hash == hash
                            ),
                        "publication commit has no exact pending intent"
                    );
                    ensure!(
                        published.insert(relative, hash).is_none(),
                        "duplicate published output path"
                    );
                    pending = None;
                }
                Event::Seal => {
                    ensure!(
                        started && pending.is_none(),
                        "publication seal precedes completion of its pending rename"
                    );
                    sealed = true;
                }
            }
            checkpoint.count = published.len() as u64;
        }
        ensure!(
            started,
            "publication journal lost its complete bootstrap prefix"
        );
        if let Some(expected) = &self.terminal {
            ensure!(
                sealed && !torn_tail && checkpoint == *expected,
                "publication journal lost or changed its pinned terminal seal"
            );
        }
        self.verify_named(directory, &file, &observed)?;
        if sealed {
            self.terminal = Some(checkpoint.clone());
        }
        self.cursor = Some(Cursor {
            checkpoint,
            pending: pending.clone(),
            observed,
            torn_tail,
            sealed,
        });
        Ok(Replay {
            published,
            pending,
            torn_tail,
            sealed,
        })
    }

    /// The owner checks its hydrated published map before starting a path.
    /// Keeping that map out of this cursor avoids duplicating growing state.
    pub(super) fn append_pending(
        &mut self,
        directory: &File,
        relative: &Path,
        hash: &str,
        prior: Option<&str>,
    ) -> Result<()> {
        let intent = Intent {
            relative: relative.into(),
            hash: hash.into(),
            prior: prior.map(str::to_owned),
        };
        validate_intent(&intent)?;
        self.append(directory, Event::Pending { intent })
    }

    pub(super) fn append_published(
        &mut self,
        directory: &File,
        relative: &Path,
        hash: &str,
    ) -> Result<()> {
        self.append(
            directory,
            Event::Published {
                relative: relative.into(),
                hash: hash.into(),
            },
        )
    }

    pub(super) fn seal(&mut self, directory: &File) -> Result<()> {
        self.append(directory, Event::Seal)
    }

    pub(super) fn is_sealed(&self) -> bool {
        self.terminal.is_some()
    }

    /// Export the exact private log only after a complete validated replay.
    /// The daemon never interprets publication events or caller output paths;
    /// its final cleanup consumes this bounded byte binding under our gate.
    pub(super) fn released_payload(
        &self,
        directory: &File,
    ) -> Result<rch_common::job_identity::JobLeasePayload> {
        let cursor = self
            .cursor
            .as_ref()
            .context("publication release requires replay")?;
        ensure!(
            cursor.sealed
                && !cursor.torn_tail
                && cursor.pending.is_none()
                && self.terminal.as_ref() == Some(&cursor.checkpoint),
            "publication release requires an exact terminal seal"
        );
        let file = self.open(directory, false)?;
        let observed = self.verify_file(&file)?;
        ensure!(
            observed == cursor.observed
                && observed.length == cursor.checkpoint.offset
                && observed.length <= rch_common::job_identity::JOB_CUSTODY_RELEASE_MAX_BYTES,
            "publication release changed or exceeds its byte bound"
        );
        let mut hash = blake3::Hasher::new();
        let mut buffer = [0_u8; 64 * 1024];
        let mut offset = 0;
        while offset < observed.length {
            let length = usize::try_from((observed.length - offset).min(buffer.len() as u64))?;
            file.read_exact_at(&mut buffer[..length], offset)?;
            hash.update(&buffer[..length]);
            offset += length as u64;
        }
        self.verify_named(directory, &file, &observed)?;
        Ok(rch_common::job_identity::JobLeasePayload {
            name: self.name.clone(),
            bytes: observed.length,
            blake3: hash.finalize().to_hex().to_string(),
        })
    }

    pub(super) fn binding(&self) -> &str {
        &self.binding
    }

    #[cfg(test)]
    pub(super) fn has_cursor(&self) -> bool {
        self.cursor.is_some()
    }

    fn append(&mut self, directory: &File, event: Event) -> Result<()> {
        // Never reinstall this cursor after an ambiguous write or sync error.
        let mut cursor = self
            .cursor
            .take()
            .context("publication journal must replay before appending")?;
        ensure!(
            !cursor.torn_tail && !cursor.sealed,
            "publication journal must fork its torn tail or is already sealed"
        );
        let mut next_pending = cursor.pending.clone();
        let mut count = cursor.checkpoint.count;
        let sealed = match &event {
            Event::Pending { intent } => {
                ensure!(
                    next_pending.is_none(),
                    "publication already has a pending rename"
                );
                next_pending = Some(intent.clone());
                false
            }
            Event::Published { relative, hash } => {
                ensure!(
                    next_pending
                        .as_ref()
                        .is_some_and(|intent| intent.relative == *relative && intent.hash == *hash),
                    "publication commit has no exact pending intent"
                );
                next_pending = None;
                count = count.checked_add(1).context("publication count overflow")?;
                false
            }
            Event::Seal => {
                ensure!(next_pending.is_none(), "cannot seal a pending publication");
                true
            }
            _ => anyhow::bail!("bootstrap records cannot be appended after publication starts"),
        };
        let mut file = self.open(directory, true)?;
        ensure!(
            self.verify_file(&file)? == cursor.observed
                && cursor.observed.length == cursor.checkpoint.offset,
            "stale publication journal cursor; replay before retrying"
        );
        let mut head = [0; 32];
        file.read_exact_at(
            &mut head,
            cursor
                .checkpoint
                .offset
                .checked_sub(DIGEST_BYTES)
                .context("publication cursor has no complete head")?,
        )?;
        ensure!(
            head == cursor.checkpoint.head,
            "publication journal head changed before append"
        );
        let (bytes, mut next) = encode(&cursor.checkpoint, event)?;
        next.count = count;
        file.write_all(&bytes)?;
        file.sync_all()?;
        let observed = self.verify_file(&file)?;
        ensure!(
            observed.length == next.offset,
            "publication journal end changed while appending"
        );
        let mut recorded = vec![0; bytes.len()];
        file.read_exact_at(&mut recorded, cursor.checkpoint.offset)?;
        ensure!(
            recorded == bytes,
            "publication journal append did not retain its exact bytes"
        );
        self.verify_named(directory, &file, &observed)?;
        if sealed {
            self.terminal = Some(next.clone());
        }
        cursor.checkpoint = next;
        cursor.pending = next_pending;
        cursor.observed = observed;
        cursor.sealed = sealed;
        self.cursor = Some(cursor);
        Ok(())
    }

    /// Preserve the old inode, including incomplete bytes or snapshot custody.
    /// Only an exceptional fork copies O(n) bytes; ordinary appends stay bounded.
    pub(super) fn fork(&self, directory: &File, binding: &str) -> Result<Self> {
        let mut source = self.clone();
        source.replay(directory, binding)?;
        let cursor = source
            .cursor
            .as_ref()
            .context("publication replay omitted its cursor")?;
        let input = source.open(directory, false)?;
        source.verify_named(directory, &input, &cursor.observed)?;
        let (mut target, mut output) = Self::create_file(directory, binding)?;
        target.initial = source.initial.clone();
        target.terminal = source.terminal.clone();
        let mut copied = 0;
        let mut buffer = [0; MAX_RECORD_BYTES];
        while copied < cursor.checkpoint.offset {
            let length =
                usize::try_from((cursor.checkpoint.offset - copied).min(buffer.len() as u64))?;
            input.read_exact_at(&mut buffer[..length], copied)?;
            output.write_all(&buffer[..length])?;
            copied += length as u64;
        }
        source.verify_named(directory, &input, &cursor.observed)?;
        output.sync_all()?;
        directory.sync_all()?;
        target.replay(directory, binding)?;
        Ok(target)
    }
}

#[cfg(test)]
#[path = "publication_journal_tests.rs"]
mod tests;
