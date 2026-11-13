//! Stream an explicitly retained compiler tree inside authenticated admission.
//! Every reply names the original request and complete dataset identity. The
//! receiver must seal all entries and bytes before execution can be dispatched.
//! Negotiated reuse permits that seal to come from a fully verified retained
//! dataset; a cache claim without the selected protocol never skips an upload.

use super::{digest, hex, invalid, require};
use crate::coord::worker_delivery::{
    EncodedWorkerFrame, WorkerPeer, toolchain_identity, toolchain_identity_value,
    toolchain_transfer,
};
use rabs_sandbox::toolchain_cache::RetainedToolchain;
use rabs_sandbox::toolchain_dataset::PreparedToolchain;
use rabs_sandbox::toolchain_transfer::{
    MAX_TOOLCHAIN_CHUNK, MAX_TOOLCHAIN_FILE_PAGE_BYTES, MAX_TOOLCHAIN_FILE_PAGE_ENTRIES,
    MAX_TOOLCHAIN_METADATA_BYTES, TOOLCHAIN_FILE_REUSE_VERSION, TOOLCHAIN_PREFIX_REUSE_VERSION,
    TOOLCHAIN_REUSE_VERSION, TOOLCHAIN_TRANSFER_VERSION, ToolchainEntry, ToolchainEntryKind,
};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::io;
use std::sync::Arc;

mod pipeline;

// Stay below the worker's eight deferred frames and 2 MiB aggregate bound.
// The shared window spans entries and chunks, including small and empty files.
// Only acknowledgment descriptors are retained, never queued payload buffers.
const CHUNK_WINDOW: usize = 4;

#[derive(Clone, Copy)]
struct FileResume {
    offset: u64,
    sha256: [u8; 32],
}

impl FileResume {
    fn empty() -> Self {
        Self {
            offset: 0,
            sha256: Sha256::digest([]).into(),
        }
    }
}

fn check_reply(
    reply: &Value,
    request_id: u64,
    identity: &[u8; 32],
    kind: &str,
    fields: usize,
) -> io::Result<()> {
    require(
        reply
            .as_object()
            .is_some_and(|object| object.len() == fields)
            && reply["kind"] == kind
            && reply["request_id"].as_u64() == Some(request_id)
            && digest(&reply["sha256"])? == *identity,
        "toolchain acknowledgment kind, shape or identity mismatch",
    )
}

/// Optional file reuse has a larger metadata charge than the ordinary tree.
/// Decide eligibility from the immutable entry inventory without opening or
/// hashing files; an otherwise valid SDK must retain its ordinary cold route.
fn select_file_reuse<'a>(
    hello: &Value,
    grant: &mut Value,
    entries: impl IntoIterator<Item = &'a ToolchainEntry>,
) -> io::Result<()> {
    let offered = hello["toolchain_file_reuses"]
        .as_array()
        .is_some_and(|versions| {
            versions
                .iter()
                .any(|version| version == TOOLCHAIN_FILE_REUSE_VERSION)
        });
    let selected = offered
        && entries
            .into_iter()
            .try_fold(0_usize, |metadata, entry| {
                if matches!(&entry.kind, ToolchainEntryKind::File { .. }) {
                    metadata
                        .checked_add(256 + 2 * entry.path.len())
                        .filter(|total| *total <= MAX_TOOLCHAIN_METADATA_BYTES)
                } else {
                    Some(metadata)
                }
            })
            .is_some();
    require(
        grant
            .get("toolchain_file_reuse")
            .is_none_or(|value| selected && value == TOOLCHAIN_FILE_REUSE_VERSION),
        "conflicting, unsupported or excessive toolchain file reuse selection",
    )?;
    if selected {
        grant["toolchain_file_reuse"] = json!(TOOLCHAIN_FILE_REUSE_VERSION);
    }
    Ok(())
}

#[derive(Debug, Clone)]
enum ToolchainOwner {
    Independent(Arc<PreparedToolchain>),
    Retained(Arc<RetainedToolchain>),
}

impl std::ops::Deref for ToolchainOwner {
    type Target = PreparedToolchain;

    fn deref(&self) -> &Self::Target {
        match self {
            Self::Independent(image) => image,
            Self::Retained(owner) => owner.image(),
        }
    }
}

#[derive(Debug, Clone)]
pub(super) struct ToolchainUpload {
    prepared: ToolchainOwner,
    entries: Arc<Vec<ToolchainEntry>>,
}

impl ToolchainUpload {
    pub(super) fn new(prepared: PreparedToolchain, request: &Value) -> io::Result<Self> {
        Self::from_shared(Arc::new(prepared), request)
    }

    pub(super) fn from_shared(
        prepared: Arc<PreparedToolchain>,
        request: &Value,
    ) -> io::Result<Self> {
        let entries = Arc::new(prepared.entries()?);
        let upload = Self {
            prepared: ToolchainOwner::Independent(prepared),
            entries,
        };
        upload.validate_request(request)?;
        Ok(upload)
    }

    pub(super) fn from_retained(
        retained: Arc<RetainedToolchain>,
        request: &Value,
    ) -> io::Result<Self> {
        retained.image().verify_retained_generation(|| false)?;
        let entries = Arc::new(retained.image().entries()?);
        let upload = Self {
            prepared: ToolchainOwner::Retained(retained),
            entries,
        };
        upload.validate_request(request)?;
        Ok(upload)
    }

    pub(super) fn validate_request(&self, request: &Value) -> io::Result<()> {
        require(
            toolchain_transfer(request)?,
            "retained toolchain requires explicit transfer",
        )?;
        require(
            request.get("toolchain_backing").is_none(),
            "transferred toolchain cannot fall back to a host path",
        )?;
        require(
            toolchain_identity(request)?.as_ref() == Some(self.prepared.identity()),
            "retained toolchain differs from the saved request identity",
        )?;
        require(!self.entries.is_empty(), "toolchain has no root entry")
    }

    pub(super) fn select(&self, hello: &Value, grant: &mut Value) -> io::Result<()> {
        require(
            hello["toolchain_transfers"]
                .as_array()
                .is_some_and(|versions| {
                    versions
                        .iter()
                        .any(|version| version == TOOLCHAIN_TRANSFER_VERSION)
                }),
            "worker does not support toolchain-tree-v1",
        )?;
        require(
            grant
                .get("toolchain_transfer")
                .is_none_or(|value| value == TOOLCHAIN_TRANSFER_VERSION),
            "conflicting toolchain transfer selection",
        )?;
        grant["toolchain_transfer"] = json!(TOOLCHAIN_TRANSFER_VERSION);
        let reuse = hello["toolchain_reuses"]
            .as_array()
            .is_some_and(|versions| {
                versions
                    .iter()
                    .any(|version| version == TOOLCHAIN_REUSE_VERSION)
            });
        require(
            grant
                .get("toolchain_reuse")
                .is_none_or(|value| reuse && value == TOOLCHAIN_REUSE_VERSION),
            "conflicting or unsupported toolchain reuse selection",
        )?;
        if reuse {
            grant["toolchain_reuse"] = json!(TOOLCHAIN_REUSE_VERSION);
        }
        select_file_reuse(hello, grant, self.entries.iter())?;
        let prefix = grant.get("toolchain_file_reuse").is_some()
            && hello["toolchain_prefix_reuses"]
                .as_array()
                .is_some_and(|versions| {
                    versions
                        .iter()
                        .any(|version| version == TOOLCHAIN_PREFIX_REUSE_VERSION)
                });
        require(
            grant
                .get("toolchain_prefix_reuse")
                .is_none_or(|value| prefix && value == TOOLCHAIN_PREFIX_REUSE_VERSION),
            "conflicting or unadvertised toolchain prefix reuse selection",
        )?;
        if prefix {
            grant["toolchain_prefix_reuse"] = json!(TOOLCHAIN_PREFIX_REUSE_VERSION);
        }
        Ok(())
    }

    fn prefix_digest<P: WorkerPeer + ?Sized>(
        &self,
        peer: &mut P,
        path: &str,
        length: u64,
    ) -> io::Result<[u8; 32]> {
        let mut hash = Sha256::new();
        let mut offset = 0;
        while offset < length {
            peer.checkpoint()?;
            let maximum = (length - offset).min(MAX_TOOLCHAIN_CHUNK as u64) as usize;
            let chunk = self.prepared.read_chunk(path, offset, maximum, || false)?;
            require(
                !chunk.is_empty() && chunk.len() <= maximum,
                "retained toolchain prefix read changed its range",
            )?;
            hash.update(&chunk);
            offset += chunk.len() as u64;
        }
        peer.checkpoint()?;
        Ok(hash.finalize().into())
    }

    /// Exchange the retained file identities in bounded pages before any tree
    /// entry. Hints select payload bytes only; every namespace entry and the
    /// final complete-dataset seal remain mandatory, including an all-hit tree.
    fn transmit_file_manifest<P: WorkerPeer + ?Sized>(
        &self,
        peer: &mut P,
        request_id: u64,
        prefix_selected: bool,
    ) -> io::Result<BTreeMap<String, FileResume>> {
        peer.checkpoint()?;
        let identity = self.prepared.identity();
        let files = self.prepared.files()?;
        let (bytes, _) = files
            .iter()
            .try_fold((0_u64, 0_usize), |(bytes, metadata), file| {
                let bytes = bytes
                    .checked_add(file.bytes)
                    .ok_or_else(|| invalid("toolchain file byte total overflow"))?;
                let metadata = metadata
                    .checked_add(256 + 2 * file.path.len())
                    .filter(|total| *total <= MAX_TOOLCHAIN_METADATA_BYTES)
                    .ok_or_else(|| invalid("toolchain file manifest metadata limit exceeded"))?;
                Ok::<_, io::Error>((bytes, metadata))
            })?;
        require(
            files.len() as u64 == identity.files && bytes == identity.bytes,
            "toolchain file manifest differs from the retained dataset totals",
        )?;
        let sha256 = hex(&identity.sha256);
        let mut resumes = BTreeMap::new();
        let mut offset = 0;
        while offset < files.len() {
            peer.checkpoint()?;
            let mut frame = json!({"kind":"toolchain-file-manifest", "request_id":request_id,
                "sha256":sha256, "offset":offset, "files":[]});
            let mut encoded_bytes = serde_json::to_vec(&frame)?.len();
            let page = frame["files"].as_array_mut().unwrap();
            while offset + page.len() < files.len() && page.len() < MAX_TOOLCHAIN_FILE_PAGE_ENTRIES
            {
                let file = &files[offset + page.len()];
                let value = json!({"path":file.path, "bytes":file.bytes,
                    "executable":file.executable, "sha256":hex(&file.sha256)});
                let next = encoded_bytes
                    + serde_json::to_vec(&value)?.len()
                    + usize::from(!page.is_empty());
                if next > MAX_TOOLCHAIN_FILE_PAGE_BYTES {
                    break;
                }
                page.push(value);
                encoded_bytes = next;
            }
            require(
                !page.is_empty(),
                "toolchain file exceeds its manifest page bound",
            )?;
            let next = offset + page.len();
            peer.send_encoded(EncodedWorkerFrame::new(&frame)?)?;
            let reply = peer.receive()?;
            check_reply(
                &reply,
                request_id,
                &identity.sha256,
                "toolchain-file-manifest-accepted",
                if prefix_selected { 6 } else { 5 },
            )?;
            require(
                serde_json::to_vec(&reply)?.len() <= MAX_TOOLCHAIN_FILE_PAGE_BYTES,
                "toolchain file manifest reply exceeds its byte bound",
            )?;
            require(
                reply["next_offset"].as_u64() == Some(next as u64),
                "toolchain file manifest acknowledgment does not cover its exact page",
            )?;
            let paths = reply["missing"]
                .as_array()
                .filter(|paths| paths.len() <= next - offset)
                .ok_or_else(|| {
                    invalid("toolchain file manifest missing set is absent or excessive")
                })?;
            let mut missing = BTreeSet::new();
            for path in paths {
                let path = path
                    .as_str()
                    .ok_or_else(|| invalid("toolchain missing file is not a path"))?;
                require(
                    files[offset..next]
                        .binary_search_by(|file| file.path.as_str().cmp(path))
                        .is_ok()
                        && missing.insert(path.to_owned()),
                    "toolchain file manifest missing set contains a duplicate or foreign path",
                )?;
            }
            for file in &files[offset..next] {
                let resume = if missing.contains(&file.path) {
                    FileResume::empty()
                } else {
                    FileResume {
                        offset: file.bytes,
                        sha256: file.sha256,
                    }
                };
                require(
                    resumes.insert(file.path.clone(), resume).is_none(),
                    "toolchain file manifest repeats a retained path",
                )?;
            }
            if prefix_selected {
                let prefixes = reply["prefixes"]
                    .as_array()
                    .filter(|prefixes| prefixes.len() <= missing.len())
                    .ok_or_else(|| invalid("toolchain prefixes are absent or excessive"))?;
                let mut offered = BTreeSet::new();
                for prefix in prefixes {
                    require(
                        prefix.as_object().is_some_and(|object| {
                            object.len() == 3
                                && ["path", "offset", "sha256"]
                                    .iter()
                                    .all(|key| object.contains_key(*key))
                        }),
                        "toolchain prefix has invalid fields",
                    )?;
                    let path = prefix["path"]
                        .as_str()
                        .ok_or_else(|| invalid("toolchain prefix path must be a string"))?;
                    let index = files[offset..next]
                        .binary_search_by(|file| file.path.as_str().cmp(path))
                        .map_err(|_| invalid("toolchain prefix names a foreign file"))?;
                    let file = &files[offset + index];
                    let length = prefix["offset"]
                        .as_u64()
                        .filter(|length| *length > 0 && *length < file.bytes)
                        .ok_or_else(|| invalid("toolchain prefix offset is outside its file"))?;
                    require(
                        missing.contains(path) && offered.insert(path.to_owned()),
                        "toolchain prefix is duplicated or not missing on this page",
                    )?;
                    let expected = digest(&prefix["sha256"])?;
                    // A stored worker prefix is an untrusted byte hint. Its
                    // claimed digest never selects an offset until the retained
                    // source independently hashes that exact bounded range.
                    if self.prefix_digest(peer, path, length)? == expected {
                        *resumes.get_mut(path).expect("manifest file was inserted") = FileResume {
                            offset: length,
                            sha256: expected,
                        };
                    }
                }
            }
            offset = next;
        }
        peer.send(
            &json!({"kind":"toolchain-file-manifest-seal", "request_id":request_id,
            "sha256":sha256}),
        )?;
        let reply = peer.receive()?;
        check_reply(
            &reply,
            request_id,
            &identity.sha256,
            "toolchain-file-manifest-ready",
            5,
        )?;
        require(
            reply["files"].as_u64() == Some(identity.files)
                && reply["bytes"].as_u64() == Some(identity.bytes),
            "worker accepted different toolchain file manifest totals",
        )?;
        Ok(resumes)
    }

    pub(super) fn transmit<P: WorkerPeer + ?Sized>(
        &self,
        peer: &mut P,
        request: &Value,
        reuse_selected: bool,
        file_reuse_selected: bool,
    ) -> io::Result<()> {
        self.transmit_with_prefix(peer, request, reuse_selected, file_reuse_selected, false)
    }

    pub(super) fn transmit_with_prefix<P: WorkerPeer + ?Sized>(
        &self,
        peer: &mut P,
        request: &Value,
        reuse_selected: bool,
        file_reuse_selected: bool,
        prefix_selected: bool,
    ) -> io::Result<()> {
        self.validate_request(request)?;
        require(
            !prefix_selected || file_reuse_selected,
            "toolchain prefix reuse requires negotiated file reuse",
        )?;
        let id = request["request_id"]
            .as_u64()
            .ok_or_else(|| invalid("toolchain request identity"))?;
        let identity = self.prepared.identity();
        let sha256 = hex(&identity.sha256);
        peer.send(&json!({"kind":"toolchain-begin", "request_id":id,
            "identity":toolchain_identity_value(identity), "entries":self.entries.len()}))?;
        let reply = peer.receive()?;
        check_reply(&reply, id, &identity.sha256, "toolchain-ready", 4)?;
        match reply["sealed"].as_bool() {
            Some(true) => {
                require(reuse_selected, "toolchain reuse was not negotiated")?;
                return Ok(());
            }
            Some(false) => {}
            None => return Err(invalid("toolchain ready seal must be a boolean")),
        }
        let resumes = if file_reuse_selected {
            Some(self.transmit_file_manifest(peer, id, prefix_selected)?)
        } else {
            None
        };
        let mut window = pipeline::UploadWindow::new(peer, id, identity.sha256);
        for entry in self.entries.iter() {
            let value = match &entry.kind {
                ToolchainEntryKind::Directory => json!({"kind":"directory"}),
                ToolchainEntryKind::Symlink { target } => {
                    json!({"kind":"symlink", "target":target})
                }
                ToolchainEntryKind::File { bytes, executable } => {
                    json!({"kind":"file", "bytes":bytes, "executable":executable})
                }
            };
            let resume = resumes
                .as_ref()
                .and_then(|files| files.get(&entry.path))
                .copied()
                .unwrap_or_else(FileResume::empty);
            let mut frame = json!({"kind":"toolchain-entry", "request_id":id, "sha256":sha256,
                "path":entry.path, "entry":value});
            let expected =
                if prefix_selected && matches!(&entry.kind, ToolchainEntryKind::File { .. }) {
                    frame["resume"] = json!({"offset":resume.offset, "sha256":hex(&resume.sha256)});
                    pipeline::ExpectedAck::ResumedEntry {
                        path: &entry.path,
                        next_offset: resume.offset,
                    }
                } else {
                    pipeline::ExpectedAck::Entry { path: &entry.path }
                };
            window.queue(&frame, expected)?;
            if let ToolchainEntryKind::File { bytes, .. } = &entry.kind {
                let mut offset = resume.offset;
                while offset < *bytes {
                    // The retained inventory checks the opened file's identity
                    // and stamps around every bounded read. A changed sender
                    // cannot obtain the worker's final expected-digest seal.
                    let chunk = self.prepared.read_chunk(
                        &entry.path,
                        offset,
                        MAX_TOOLCHAIN_CHUNK,
                        || false,
                    )?;
                    require(!chunk.is_empty(), "retained toolchain file ended early")?;
                    let next = offset
                        .checked_add(chunk.len() as u64)
                        .filter(|next| *next <= *bytes)
                        .ok_or_else(|| {
                            invalid("retained toolchain exceeded declared file length")
                        })?;
                    window.queue(
                        &json!({"kind":"toolchain-chunk", "request_id":id, "sha256":sha256,
                        "path":entry.path, "offset":offset, "data_hex":hex(&chunk),
                        "chunk_sha256":hex(&Sha256::digest(&chunk))}),
                        pipeline::ExpectedAck::Chunk {
                            path: &entry.path,
                            next_offset: next,
                        },
                    )?;
                    offset = next;
                }
            }
        }
        window.finish()?;
        peer.send(&json!({"kind":"toolchain-seal", "request_id":id, "sha256":sha256}))?;
        let reply = peer.receive()?;
        check_reply(&reply, id, &identity.sha256, "toolchain-ready", 4)?;
        require(
            reply["sealed"] == true,
            "worker did not seal the complete toolchain",
        )
    }
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;
    mod pipeline_tests;
    mod prefix_tests;
    use rabs_sandbox::toolchain_dataset::{ToolchainIdentity, ToolchainLimits, capture_toolchain};
    use rabs_sandbox::toolchain_transfer::{
        ToolchainCheckpointError, ToolchainFile, ToolchainReceiver,
    };
    use std::collections::{BTreeMap, VecDeque};
    use std::fs;
    use std::os::unix::fs::{PermissionsExt, symlink};
    use std::path::Path;

    fn fixture(root: &Path) -> (ToolchainUpload, Value, Vec<u8>) {
        fs::set_permissions(root, fs::Permissions::from_mode(0o700)).unwrap();
        let original = root.join("original");
        fs::create_dir_all(original.join("bin")).unwrap();
        fs::create_dir(original.join("empty-directory")).unwrap();
        let bytes: Vec<_> = (0..MAX_TOOLCHAIN_CHUNK * 5 + 7)
            .map(|value| (value % 251) as u8)
            .collect();
        fs::write(original.join("bin/compiler"), &bytes).unwrap();
        fs::set_permissions(
            original.join("bin/compiler"),
            fs::Permissions::from_mode(0o755),
        )
        .unwrap();
        fs::write(original.join("empty-file"), []).unwrap();
        symlink("bin/compiler", original.join("rustc")).unwrap();
        let retained = capture_toolchain(
            &original,
            &root.join("retained"),
            None,
            &ToolchainLimits::default(),
            || false,
        )
        .unwrap();
        let request = json!({"kind":"canonical-exec", "request_id":0,
            "toolchain_transfer":TOOLCHAIN_TRANSFER_VERSION,
            "toolchain_identity":toolchain_identity_value(retained.identity())});
        (
            ToolchainUpload::new(retained, &request).unwrap(),
            request,
            bytes,
        )
    }

    struct ReceiverPeer {
        owner: tempfile::TempDir,
        receiver: Option<ToolchainReceiver>,
        sealed: Option<PreparedToolchain>,
        replies: VecDeque<Value>,
        sent: Vec<Value>,
        maximum_pending: usize,
        fault: Option<&'static str>,
        reuse_enabled: bool,
        file_reuse_enabled: bool,
        expected: Option<ToolchainIdentity>,
        file_manifest: BTreeMap<String, ToolchainFile>,
        file_hits: BTreeSet<String>,
        manifest_sealed: bool,
        cached_files: BTreeMap<[u8; 32], fs::File>,
        stopped: bool,
    }

    impl ReceiverPeer {
        fn new() -> Self {
            let owner = tempfile::tempdir().unwrap();
            fs::set_permissions(owner.path(), fs::Permissions::from_mode(0o700)).unwrap();
            Self {
                owner,
                receiver: None,
                sealed: None,
                replies: VecDeque::new(),
                sent: Vec::new(),
                maximum_pending: 0,
                fault: None,
                reuse_enabled: false,
                file_reuse_enabled: false,
                expected: None,
                file_manifest: BTreeMap::new(),
                file_hits: BTreeSet::new(),
                manifest_sealed: false,
                cached_files: BTreeMap::new(),
                stopped: false,
            }
        }

        fn checkpoint_completed_file(&mut self, path: &str) -> io::Result<()> {
            if let Some(expected) = self.file_manifest.get(path) {
                let destination = tempfile::NamedTempFile::new_in(self.owner.path())?;
                let verified = self
                    .receiver
                    .as_mut()
                    .unwrap()
                    .checkpoint_file(expected, destination.as_file().try_clone()?, || {
                        self.stopped
                    })
                    .map_err(|error| match error {
                        ToolchainCheckpointError::Source(error)
                        | ToolchainCheckpointError::Destination(error) => error,
                    })?;
                self.cached_files
                    .insert(expected.sha256, verified.into_file());
            }
            Ok(())
        }
    }

    impl WorkerPeer for ReceiverPeer {
        fn send(&mut self, frame: &Value) -> io::Result<()> {
            self.sent.push(frame.clone());
            let id = &frame["request_id"];
            let identity = &frame["sha256"];
            let reply = match frame["kind"].as_str().unwrap() {
                "toolchain-begin" => {
                    require(
                        frame.as_object().unwrap().len() == 4,
                        "toolchain begin shape changed",
                    )?;
                    let expected =
                        toolchain_identity(&json!({"toolchain_identity":frame["identity"]}))?
                            .unwrap();
                    // This transport fixture is warmed by the real receiver
                    // below. A hit still rehashes the retained tree before
                    // replying; it is not a claim about worker pool execution.
                    if self.reuse_enabled
                        && let Some(cached) = &self.sealed
                        && cached.identity() == &expected
                    {
                        cached.verify(|| self.stopped)?;
                        self.replies.push_back(json!({"kind":"toolchain-ready",
                            "request_id":id, "sha256":hex(&expected.sha256), "sealed":true}));
                        return Ok(());
                    }
                    self.sealed = None;
                    self.expected = Some(expected);
                    self.file_manifest.clear();
                    self.file_hits.clear();
                    self.manifest_sealed = false;
                    self.receiver = Some(ToolchainReceiver::create(
                        &self
                            .owner
                            .path()
                            .join(format!("received-{}", self.sent.len())),
                        expected,
                        ToolchainLimits::default(),
                    )?);
                    json!({"kind":"toolchain-ready", "request_id":id, "sha256":hex(&expected.sha256), "sealed":false})
                }
                "toolchain-file-manifest" => {
                    require(
                        self.file_reuse_enabled && !self.manifest_sealed,
                        "file manifest was not selected",
                    )?;
                    require(
                        frame["offset"].as_u64() == Some(self.file_manifest.len() as u64),
                        "file page offset mismatch",
                    )?;
                    let files = frame["files"]
                        .as_array()
                        .ok_or_else(|| invalid("file page missing"))?;
                    require(
                        !files.is_empty()
                            && files.len() <= MAX_TOOLCHAIN_FILE_PAGE_ENTRIES
                            && serde_json::to_vec(frame)?.len() <= MAX_TOOLCHAIN_FILE_PAGE_BYTES,
                        "file page exceeds bound",
                    )?;
                    let mut missing = Vec::new();
                    for file in files {
                        let file = ToolchainFile {
                            path: file["path"].as_str().unwrap().to_owned(),
                            bytes: file["bytes"].as_u64().unwrap(),
                            executable: file["executable"].as_bool().unwrap(),
                            sha256: digest(&file["sha256"])?,
                        };
                        require(
                            self.file_manifest
                                .last_key_value()
                                .is_none_or(|(path, _)| path < &file.path),
                            "file page paths are not strictly ordered",
                        )?;
                        if !self.cached_files.contains_key(&file.sha256) {
                            missing.push(file.path.clone());
                        } else {
                            self.file_hits.insert(file.path.clone());
                        }
                        self.file_manifest.insert(file.path.clone(), file);
                    }
                    json!({"kind":"toolchain-file-manifest-accepted", "request_id":id,
                        "sha256":identity, "next_offset":self.file_manifest.len(), "missing":missing})
                }
                "toolchain-file-manifest-seal" => {
                    let expected = self.expected.unwrap();
                    let bytes = self
                        .file_manifest
                        .values()
                        .map(|file| file.bytes)
                        .sum::<u64>();
                    require(
                        self.file_reuse_enabled
                            && !self.manifest_sealed
                            && expected.files == self.file_manifest.len() as u64
                            && expected.bytes == bytes,
                        "file manifest totals differ",
                    )?;
                    self.manifest_sealed = true;
                    json!({"kind":"toolchain-file-manifest-ready", "request_id":id, "sha256":identity,
                        "files":expected.files, "bytes":bytes})
                }
                "toolchain-entry" => {
                    let entry = &frame["entry"];
                    let kind = match entry["kind"].as_str().unwrap() {
                        "directory" => ToolchainEntryKind::Directory,
                        "symlink" => ToolchainEntryKind::Symlink {
                            target: entry["target"].as_str().unwrap().to_owned(),
                        },
                        "file" => ToolchainEntryKind::File {
                            bytes: entry["bytes"].as_u64().unwrap(),
                            executable: entry["executable"].as_bool().unwrap(),
                        },
                        _ => return Err(invalid("unexpected entry kind")),
                    };
                    self.receiver.as_mut().unwrap().entry(ToolchainEntry {
                        path: frame["path"].as_str().unwrap().to_owned(),
                        kind,
                    })?;
                    if self.file_reuse_enabled {
                        require(
                            self.manifest_sealed,
                            "file manifest was not accepted before entries",
                        )?;
                        let path = frame["path"].as_str().unwrap();
                        if let Some(file) = self.file_manifest.get(path) {
                            if self.file_hits.contains(path) {
                                let input = self.cached_files.get_mut(&file.sha256).unwrap();
                                self.receiver
                                    .as_mut()
                                    .unwrap()
                                    .import_file(file, input, || self.stopped)?;
                            } else if file.bytes == 0 {
                                self.checkpoint_completed_file(path)?;
                            }
                        }
                    }
                    json!({"kind":"toolchain-entry-accepted", "request_id":id, "sha256":identity, "path":frame["path"]})
                }
                "toolchain-chunk" => {
                    let encoded = frame["data_hex"].as_str().unwrap();
                    let bytes: Vec<_> = (0..encoded.len())
                        .step_by(2)
                        .map(|offset| u8::from_str_radix(&encoded[offset..offset + 2], 16).unwrap())
                        .collect();
                    let offset = frame["offset"].as_u64().unwrap();
                    self.receiver.as_mut().unwrap().write_chunk(
                        frame["path"].as_str().unwrap(),
                        offset,
                        &bytes,
                        digest(&frame["chunk_sha256"])?,
                    )?;
                    let path = frame["path"].as_str().unwrap();
                    if self
                        .file_manifest
                        .get(path)
                        .is_some_and(|file| file.bytes == offset + bytes.len() as u64)
                    {
                        self.checkpoint_completed_file(path)?;
                    }
                    json!({"kind":"toolchain-chunk-accepted", "request_id":id, "sha256":identity,
                        "path":frame["path"], "next_offset":offset + bytes.len() as u64})
                }
                "toolchain-seal" => {
                    self.sealed = Some(self.receiver.as_mut().unwrap().seal(|| false)?);
                    json!({"kind":"toolchain-ready", "request_id":id, "sha256":identity, "sealed":true})
                }
                _ => return Err(invalid("sender attempted a non-toolchain operation")),
            };
            self.replies.push_back(reply);
            self.maximum_pending = self.maximum_pending.max(self.replies.len());
            Ok(())
        }

        fn receive(&mut self) -> io::Result<Value> {
            let mut reply = self
                .replies
                .pop_front()
                .ok_or_else(|| invalid("missing reply"))?;
            match self.fault {
                Some("identity") => reply["sha256"] = json!("ab".repeat(32)),
                Some("request") => reply["request_id"] = json!(999),
                Some("extra") => reply["extra"] = json!(true),
                Some("seal-type") => reply["sealed"] = json!("true"),
                Some("upper-digest") => reply["sha256"] = json!("AB".repeat(32)),
                Some("missing-digest") => {
                    reply.as_object_mut().unwrap().remove("sha256");
                }
                Some("kind") => reply["kind"] = json!("source-ready"),
                Some("file-offset") if reply["kind"] == "toolchain-file-manifest-accepted" => {
                    reply["next_offset"] = json!(0)
                }
                Some("file-foreign") if reply["kind"] == "toolchain-file-manifest-accepted" => {
                    reply["missing"] = json!(["foreign"])
                }
                Some("file-duplicate") if reply["kind"] == "toolchain-file-manifest-accepted" => {
                    let first = reply["missing"][0].clone();
                    reply["missing"] = json!([first, first]);
                }
                Some("file-type") if reply["kind"] == "toolchain-file-manifest-accepted" => {
                    reply["missing"] = json!([true])
                }
                Some("file-extra") if reply["kind"] == "toolchain-file-manifest-accepted" => {
                    reply["extra"] = json!(true)
                }
                Some("file-identity") if reply["kind"] == "toolchain-file-manifest-accepted" => {
                    reply["sha256"] = json!("ab".repeat(32))
                }
                Some("file-request") if reply["kind"] == "toolchain-file-manifest-accepted" => {
                    reply["request_id"] = json!(999)
                }
                Some("file-count") if reply["kind"] == "toolchain-file-manifest-ready" => {
                    reply["files"] = json!(0)
                }
                Some("file-bytes") if reply["kind"] == "toolchain-file-manifest-ready" => {
                    reply["bytes"] = json!(0)
                }
                Some("file-lost") if reply["kind"] == "toolchain-file-manifest-accepted" => {
                    return Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "lost file page ACK",
                    ));
                }
                Some("lost-ready") if reply["kind"] == "toolchain-ready" => {
                    return Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "lost ready ACK",
                    ));
                }
                Some("entry") if reply["kind"] == "toolchain-entry-accepted" => {
                    reply["path"] = json!("foreign")
                }
                Some("offset") if reply["kind"] == "toolchain-chunk-accepted" => {
                    reply["next_offset"] = json!(0)
                }
                Some("lost-chunk") if reply["kind"] == "toolchain-chunk-accepted" => {
                    return Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "lost chunk ACK",
                    ));
                }
                Some("lost-completed-file")
                    if reply["kind"] == "toolchain-chunk-accepted"
                        && reply["next_offset"].as_u64()
                            == self
                                .file_manifest
                                .get(reply["path"].as_str().unwrap())
                                .map(|file| file.bytes) =>
                {
                    return Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "lost completed-file ACK",
                    ));
                }
                Some("seal") if reply["sealed"] == true => reply["sealed"] = json!(false),
                _ => {}
            }
            Ok(reply)
        }
    }

    #[test]
    fn retained_tree_streams_binary_chunks_links_and_empty_entries_to_real_receiver() {
        let root = tempfile::tempdir().unwrap();
        let (upload, request, bytes) = fixture(root.path());
        fs::rename(
            root.path().join("original"),
            root.path().join("unavailable-original"),
        )
        .unwrap();
        let mut peer = ReceiverPeer::new();
        upload.transmit(&mut peer, &request, false, false).unwrap();
        let received = peer.sealed.as_ref().unwrap();
        received.verify(|| false).unwrap();
        assert_eq!(received.identity(), upload.prepared.identity());
        assert_eq!(fs::read(received.root().join("rustc")).unwrap(), bytes);
        assert!(received.root().join("empty-directory").is_dir());
        assert_eq!(fs::read(received.root().join("empty-file")).unwrap(), b"");
        assert_eq!(peer.maximum_pending, CHUNK_WINDOW);
        assert_eq!(peer.sent.last().unwrap()["kind"], "toolchain-seal");
        assert!(
            peer.sent
                .iter()
                .all(|frame| frame["kind"] != "canonical-exec")
        );
    }

    #[test]
    fn retained_upload_owns_the_selected_generation_after_pool_and_caller_release() {
        use rabs_sandbox::toolchain_cache::ToolchainPool;
        use std::time::Duration;

        let root = crate::test_util::private_tempdir();
        let source = root.path().join("source");
        let pool_root = root.path().join("pool");
        // Separate private siblings satisfy the pool's source/retention
        // boundary. These are real transfer bytes, never an executed compiler.
        for directory in [&source, &pool_root] {
            fs::create_dir(directory).unwrap();
            fs::set_permissions(directory, fs::Permissions::from_mode(0o700)).unwrap();
        }
        fs::create_dir(source.join("bin")).unwrap();
        let bytes: Vec<_> = (0..MAX_TOOLCHAIN_CHUNK + 17)
            .map(|index| (index % 251) as u8)
            .collect();
        let original = source.join("bin/compiler");
        fs::write(&original, &bytes).unwrap();
        fs::set_permissions(&original, fs::Permissions::from_mode(0o755)).unwrap();
        symlink("bin/compiler", source.join("rustc")).unwrap();
        let pool = ToolchainPool::new(&pool_root, 1, |_, _, _| false).unwrap();
        let lease = pool
            .acquire(&source, Duration::from_secs(5), || false)
            .unwrap();
        let identity = *lease.image().identity();
        let request = json!({"kind":"canonical-exec", "request_id":7,
            "toolchain_transfer":TOOLCHAIN_TRANSFER_VERSION,
            "toolchain_identity":toolchain_identity_value(&identity)});

        let mut mismatched_identity = identity;
        mismatched_identity.sha256[0] ^= 1;
        let mut mismatched_request = request.clone();
        mismatched_request["toolchain_identity"] = toolchain_identity_value(&mismatched_identity);
        let error =
            ToolchainUpload::from_retained(Arc::clone(&lease), &mismatched_request).unwrap_err();
        assert!(
            error
                .to_string()
                .contains("differs from the saved request identity")
        );

        let backing = lease.owner_path().to_path_buf();
        let weak = Arc::downgrade(&lease);
        let upload = ToolchainUpload::from_retained(Arc::clone(&lease), &request).unwrap();
        drop(lease);
        pool.shutdown().unwrap();
        drop(pool);
        assert!(weak.upgrade().is_some());
        assert!(backing.is_dir());

        // The only strong owner is the upload. A later original-source write
        // must neither change its identity nor be substituted into the stream.
        let changed = vec![0xa5; bytes.len()];
        fs::write(&original, &changed).unwrap();
        assert_eq!(fs::read(&original).unwrap(), changed);
        let mut peer = ReceiverPeer::new();
        upload.transmit(&mut peer, &request, false, false).unwrap();
        let received = peer.sealed.as_ref().unwrap();
        received.verify(|| false).unwrap();
        assert_eq!(received.identity(), &identity);
        assert_eq!(fs::read(received.root().join("rustc")).unwrap(), bytes);
        assert!(
            peer.sent
                .iter()
                .any(|frame| frame["kind"] == "toolchain-chunk")
        );
        assert_eq!(peer.sent.last().unwrap()["kind"], "toolchain-seal");
        assert!(peer.replies.is_empty());

        drop(upload);
        assert!(weak.upgrade().is_none());
        assert!(!backing.exists());
        // Receiver ownership is independent of the released sender generation.
        received.verify(|| false).unwrap();
        assert_eq!(fs::read(received.root().join("rustc")).unwrap(), bytes);
    }

    #[test]
    fn reuse_selection_requires_supported_transfer_and_an_advertised_version() {
        let root = tempfile::tempdir().unwrap();
        let (upload, _, _) = fixture(root.path());
        let hello = json!({"toolchain_transfers":[TOOLCHAIN_TRANSFER_VERSION]});
        for advertised in [
            None,
            Some(Value::Null),
            Some(json!([])),
            Some(json!(["toolchain-reuse-v2"])),
            Some(json!([TOOLCHAIN_REUSE_VERSION])),
        ] {
            let selected = advertised.as_ref() == Some(&json!([TOOLCHAIN_REUSE_VERSION]));
            let mut offered = hello.clone();
            if let Some(value) = advertised {
                offered["toolchain_reuses"] = value;
            }
            let mut grant = json!({"kind":"session-ok"});
            upload.select(&offered, &mut grant).unwrap();
            assert_eq!(grant["toolchain_transfer"], TOOLCHAIN_TRANSFER_VERSION);
            assert_eq!(grant.get("toolchain_reuse").is_some(), selected);
            if selected {
                assert_eq!(grant["toolchain_reuse"], TOOLCHAIN_REUSE_VERSION);
            }
            for value in [Value::Null, json!(true), json!("toolchain-reuse-v2")] {
                let mut invalid = json!({"kind":"session-ok", "toolchain_reuse":value});
                assert!(upload.select(&offered, &mut invalid).is_err());
            }
            if !selected {
                let mut unsolicited =
                    json!({"kind":"session-ok", "toolchain_reuse":TOOLCHAIN_REUSE_VERSION});
                assert!(upload.select(&offered, &mut unsolicited).is_err());
            }
        }
        let mut grant = json!({"kind":"session-ok"});
        assert!(
            upload
                .select(
                    &json!({"toolchain_reuses":[TOOLCHAIN_REUSE_VERSION]}),
                    &mut grant
                )
                .is_err()
        );
        assert!(grant.get("toolchain_reuse").is_none());
    }

    #[test]
    fn file_reuse_requires_its_advertised_version_and_remains_independent_of_whole_reuse() {
        let root = tempfile::tempdir().unwrap();
        let (upload, _, _) = fixture(root.path());
        for offered in [
            None,
            Some(Value::Null),
            Some(json!([])),
            Some(json!(["toolchain-file-reuse-v2"])),
            Some(json!([TOOLCHAIN_FILE_REUSE_VERSION])),
        ] {
            let selected = offered.as_ref() == Some(&json!([TOOLCHAIN_FILE_REUSE_VERSION]));
            let mut hello = json!({"toolchain_transfers":[TOOLCHAIN_TRANSFER_VERSION]});
            if let Some(value) = offered {
                hello["toolchain_file_reuses"] = value;
            }
            let mut grant = json!({"kind":"session-ok"});
            upload.select(&hello, &mut grant).unwrap();
            assert_eq!(grant["toolchain_transfer"], TOOLCHAIN_TRANSFER_VERSION);
            assert_eq!(grant.get("toolchain_file_reuse").is_some(), selected);
            assert!(grant.get("toolchain_reuse").is_none());
            for value in [Value::Null, json!(true), json!("toolchain-file-reuse-v2")] {
                let mut invalid = json!({"kind":"session-ok", "toolchain_file_reuse":value});
                assert!(upload.select(&hello, &mut invalid).is_err());
            }
            if !selected {
                let mut unsolicited = json!({"kind":"session-ok", "toolchain_file_reuse":TOOLCHAIN_FILE_REUSE_VERSION});
                assert!(upload.select(&hello, &mut unsolicited).is_err());
            }
        }
        assert!(
            upload
                .select(
                    &json!({"toolchain_file_reuses":[TOOLCHAIN_FILE_REUSE_VERSION]}),
                    &mut json!({"kind":"session-ok"})
                )
                .is_err()
        );
    }

    #[test]
    fn file_reuse_metadata_capacity_preserves_ordinary_transfer_at_its_boundary() {
        // One long, ordinary relative path and repeated references exercise the
        // aggregate budget without allocating a large synthetic SDK inventory.
        let entry = ToolchainEntry {
            path: format!("{}compiler", format!("{}/", "d".repeat(200)).repeat(19)),
            kind: ToolchainEntryKind::File {
                bytes: 1,
                executable: true,
            },
        };
        let charge = 256 + 2 * entry.path.len();
        let last_fitting = MAX_TOOLCHAIN_METADATA_BYTES / charge;
        let hello = json!({"toolchain_file_reuses":[TOOLCHAIN_FILE_REUSE_VERSION]});
        for count in [last_fitting, last_fitting + 1] {
            assert!(
                count * (128 + entry.path.len()) <= MAX_TOOLCHAIN_METADATA_BYTES,
                "the ordinary tree protocol still fits this inventory"
            );
            let mut grant =
                json!({"kind":"session-ok", "toolchain_transfer":TOOLCHAIN_TRANSFER_VERSION});
            select_file_reuse(&hello, &mut grant, std::iter::repeat_n(&entry, count)).unwrap();
            assert_eq!(grant["toolchain_transfer"], TOOLCHAIN_TRANSFER_VERSION);
            assert_eq!(
                grant.get("toolchain_file_reuse").is_some(),
                count == last_fitting
            );
        }
        let mut forced =
            json!({"kind":"session-ok", "toolchain_file_reuse":TOOLCHAIN_FILE_REUSE_VERSION});
        assert!(
            select_file_reuse(
                &hello,
                &mut forced,
                std::iter::repeat_n(&entry, last_fitting + 1)
            )
            .is_err()
        );

        let directory = ToolchainEntry {
            path: entry.path.clone(),
            kind: ToolchainEntryKind::Directory,
        };
        let mut grant = json!({"kind":"session-ok"});
        select_file_reuse(
            &hello,
            &mut grant,
            std::iter::repeat_n(&directory, last_fitting + 1),
        )
        .unwrap();
        assert_eq!(
            grant["toolchain_file_reuse"], TOOLCHAIN_FILE_REUSE_VERSION,
            "directories are not file-manifest records"
        );
    }

    #[test]
    fn completed_files_reuse_real_bytes_but_keep_all_entries_and_the_final_dataset_seal() {
        let root = tempfile::tempdir().unwrap();
        let (upload, mut request, bytes) = fixture(root.path());
        let mut peer = ReceiverPeer::new();
        peer.file_reuse_enabled = true;
        upload.transmit(&mut peer, &request, false, true).unwrap();
        assert_eq!(peer.cached_files.len(), 2);
        assert!(
            peer.sent
                .iter()
                .any(|frame| frame["kind"] == "toolchain-chunk")
        );
        let cold_end = peer.sent.len();
        request["request_id"] = json!(1);
        upload.transmit(&mut peer, &request, false, true).unwrap();
        let warm = &peer.sent[cold_end..];
        assert_eq!(warm[0]["kind"], "toolchain-begin");
        assert_eq!(warm[1]["kind"], "toolchain-file-manifest");
        assert_eq!(warm[2]["kind"], "toolchain-file-manifest-seal");
        assert_eq!(
            warm.iter()
                .filter(|frame| frame["kind"] == "toolchain-entry")
                .count(),
            upload.entries.len()
        );
        assert!(warm.iter().all(|frame| frame["kind"] != "toolchain-chunk"));
        assert_eq!(warm.last().unwrap()["kind"], "toolchain-seal");
        let received = peer.sealed.as_ref().unwrap();
        received.verify(|| false).unwrap();
        assert_eq!(received.identity(), upload.prepared.identity());
        assert_eq!(fs::read(received.root().join("rustc")).unwrap(), bytes);
        assert!(received.root().join("empty-directory").is_dir());
        assert!(peer.replies.is_empty());

        // Whole-image readiness takes precedence, including when both optional
        // protocols were negotiated. It must not start file-manifest traffic.
        peer.reuse_enabled = true;
        let before = peer.sent.len();
        request["request_id"] = json!(2);
        upload.transmit(&mut peer, &request, true, true).unwrap();
        assert_eq!(peer.sent.len(), before + 1);
        assert_eq!(peer.sent[before]["kind"], "toolchain-begin");
    }

    #[test]
    fn completed_file_checkpoints_survive_lost_ack_without_reusing_an_incomplete_tree() {
        let root = tempfile::tempdir().unwrap();
        let (upload, mut request, bytes) = fixture(root.path());
        let mut first = ReceiverPeer::new();
        first.file_reuse_enabled = true;
        first.fault = Some("lost-completed-file");
        assert_eq!(
            upload
                .transmit(&mut first, &request, false, true)
                .unwrap_err()
                .kind(),
            io::ErrorKind::UnexpectedEof
        );
        assert!(first.sealed.is_none());
        assert!(
            first
                .sent
                .iter()
                .all(|frame| frame["kind"] != "toolchain-seal")
        );
        let completed_digest: [u8; 32] = Sha256::digest(&bytes).into();
        assert!(first.cached_files.contains_key(&completed_digest));

        let mut resumed = ReceiverPeer::new();
        resumed.file_reuse_enabled = true;
        resumed.cached_files = std::mem::take(&mut first.cached_files);
        drop(first);
        request["request_id"] = json!(3);
        upload
            .transmit(&mut resumed, &request, false, true)
            .unwrap();
        assert!(
            resumed
                .sent
                .iter()
                .all(|frame| frame["kind"] != "toolchain-chunk")
        );
        assert_eq!(resumed.sent.last().unwrap()["kind"], "toolchain-seal");
        let received = resumed.sealed.as_ref().unwrap();
        received.verify(|| false).unwrap();
        assert_eq!(received.identity(), upload.prepared.identity());
        assert_eq!(fs::read(received.root().join("rustc")).unwrap(), bytes);
    }

    #[test]
    fn changed_sdk_reuses_only_identical_file_bytes_and_restores_new_executable_modes() {
        let root = tempfile::tempdir().unwrap();
        let (upload, mut request, bytes) = fixture(root.path());
        let mut peer = ReceiverPeer::new();
        peer.file_reuse_enabled = true;
        upload.transmit(&mut peer, &request, false, true).unwrap();
        let before = peer.sent.len();
        let original = root.path().join("original");
        fs::write(original.join("empty-file"), b"new SDK payload").unwrap();
        fs::set_permissions(
            original.join("bin/compiler"),
            fs::Permissions::from_mode(0o644),
        )
        .unwrap();
        let changed = capture_toolchain(
            &original,
            &root.path().join("retained-next"),
            None,
            &ToolchainLimits::default(),
            || false,
        )
        .unwrap();
        assert_ne!(changed.identity(), upload.prepared.identity());
        request["request_id"] = json!(4);
        request["toolchain_identity"] = toolchain_identity_value(changed.identity());
        let changed = ToolchainUpload::new(changed, &request).unwrap();
        changed.transmit(&mut peer, &request, false, true).unwrap();
        let chunks = peer.sent[before..]
            .iter()
            .filter(|frame| frame["kind"] == "toolchain-chunk")
            .collect::<Vec<_>>();
        assert_eq!(chunks.len(), 1);
        assert_eq!(chunks[0]["path"], "empty-file");
        let received = peer.sealed.as_ref().unwrap();
        received.verify(|| false).unwrap();
        assert_eq!(received.identity(), changed.prepared.identity());
        assert_eq!(fs::read(received.root().join("rustc")).unwrap(), bytes);
        assert_eq!(
            fs::read(received.root().join("empty-file")).unwrap(),
            b"new SDK payload"
        );
        assert_eq!(
            fs::metadata(received.root().join("bin/compiler"))
                .unwrap()
                .permissions()
                .mode()
                & 0o111,
            0
        );
        assert_eq!(peer.sent.last().unwrap()["kind"], "toolchain-seal");
    }

    #[test]
    fn malformed_or_lost_file_manifest_acknowledgments_never_send_tree_entries_or_a_seal() {
        let root = tempfile::tempdir().unwrap();
        let (upload, request, _) = fixture(root.path());
        for fault in [
            "file-offset",
            "file-foreign",
            "file-duplicate",
            "file-type",
            "file-extra",
            "file-identity",
            "file-request",
            "file-count",
            "file-bytes",
            "file-lost",
        ] {
            let mut peer = ReceiverPeer::new();
            peer.file_reuse_enabled = true;
            peer.fault = Some(fault);
            assert!(
                upload.transmit(&mut peer, &request, false, true).is_err(),
                "{fault}"
            );
            assert!(peer.sealed.is_none());
            assert!(
                peer.sent.iter().all(|frame| !matches!(
                    frame["kind"].as_str(),
                    Some(
                        "toolchain-entry" | "toolchain-chunk" | "toolchain-seal" | "canonical-exec"
                    )
                )),
                "{fault}"
            );
        }
    }

    #[test]
    fn negotiated_receiver_warmth_skips_every_entry_chunk_and_seal() {
        let root = tempfile::tempdir().unwrap();
        let (upload, mut request, bytes) = fixture(root.path());
        let mut peer = ReceiverPeer::new();
        peer.reuse_enabled = true;
        // A selected miss follows the complete bounded transfer protocol.
        upload.transmit(&mut peer, &request, true, false).unwrap();
        assert_eq!(peer.maximum_pending, CHUNK_WINDOW);
        assert!(
            peer.sent
                .iter()
                .any(|frame| frame["kind"] == "toolchain-chunk")
        );
        assert_eq!(peer.sent.last().unwrap()["kind"], "toolchain-seal");
        let cold_end = peer.sent.len();
        request["request_id"] = json!(1);
        let original = serde_json::to_vec(&request).unwrap();
        upload.transmit(&mut peer, &request, true, false).unwrap();
        assert_eq!(peer.sent.len(), cold_end + 1);
        assert_eq!(
            peer.sent[cold_end],
            json!({"kind":"toolchain-begin", "request_id":1,
            "identity":request["toolchain_identity"], "entries":upload.entries.len()})
        );
        assert_eq!(serde_json::to_vec(&request).unwrap(), original);
        assert_eq!(
            fs::read(peer.sealed.as_ref().unwrap().root().join("rustc")).unwrap(),
            bytes
        );
        assert!(peer.replies.is_empty());
    }

    #[test]
    fn warm_reply_requires_negotiation_and_exact_identity_shape_and_boolean_seal() {
        let root = tempfile::tempdir().unwrap();
        let (upload, request, _) = fixture(root.path());
        let mut peer = ReceiverPeer::new();
        upload.transmit(&mut peer, &request, false, false).unwrap();
        peer.reuse_enabled = true;
        for fault in [
            None,
            Some("identity"),
            Some("request"),
            Some("extra"),
            Some("seal-type"),
            Some("upper-digest"),
            Some("missing-digest"),
            Some("kind"),
            Some("lost-ready"),
        ] {
            peer.fault = fault;
            let before = peer.sent.len();
            // The unfaulted warm reply is still refused without selection.
            assert!(
                upload
                    .transmit(&mut peer, &request, fault.is_some(), false)
                    .is_err(),
                "{fault:?}"
            );
            assert_eq!(peer.sent.len(), before + 1);
            assert_eq!(peer.sent[before]["kind"], "toolchain-begin");
        }
    }

    #[test]
    fn cancelled_or_corrupted_warm_verification_never_authorizes_more_frames() {
        let root = tempfile::tempdir().unwrap();
        let (upload, request, _) = fixture(root.path());
        let mut peer = ReceiverPeer::new();
        upload.transmit(&mut peer, &request, false, false).unwrap();
        peer.reuse_enabled = true;
        peer.stopped = true;
        let before = peer.sent.len();
        assert_eq!(
            upload
                .transmit(&mut peer, &request, true, false)
                .unwrap_err()
                .kind(),
            io::ErrorKind::Interrupted
        );
        assert_eq!(peer.sent.len(), before + 1);
        assert!(peer.replies.is_empty());
        peer.stopped = false;
        let compiler = peer.sealed.as_ref().unwrap().root().join("bin/compiler");
        fs::set_permissions(&compiler, fs::Permissions::from_mode(0o755)).unwrap();
        fs::write(&compiler, b"changed cached bytes").unwrap();
        assert!(upload.transmit(&mut peer, &request, true, false).is_err());
        assert_eq!(peer.sent.len(), before + 2);
        assert!(peer.replies.is_empty());
    }

    #[test]
    fn incorrect_or_lost_acknowledgments_never_complete_transfer() {
        let root = tempfile::tempdir().unwrap();
        let (upload, request, _) = fixture(root.path());
        for fault in ["identity", "extra", "entry", "offset", "lost-chunk", "seal"] {
            let mut peer = ReceiverPeer::new();
            peer.fault = Some(fault);
            assert!(
                upload.transmit(&mut peer, &request, false, false).is_err(),
                "{fault}"
            );
            if fault != "seal" {
                assert!(peer.sealed.is_none(), "{fault}");
                assert!(
                    peer.sent
                        .iter()
                        .all(|frame| frame["kind"] != "toolchain-seal")
                );
            }
            assert!(
                peer.sent
                    .iter()
                    .all(|frame| frame["kind"] != "canonical-exec")
            );
        }
    }

    #[test]
    fn changed_retained_compiler_refuses_before_a_seal_can_authorize_execution() {
        let root = tempfile::tempdir().unwrap();
        let (upload, request, mut bytes) = fixture(root.path());
        let compiler = upload.prepared.root().join("bin/compiler");
        fs::set_permissions(&compiler, fs::Permissions::from_mode(0o755)).unwrap();
        bytes[0] ^= 0xff;
        fs::write(&compiler, bytes).unwrap();
        let mut peer = ReceiverPeer::new();
        assert!(upload.transmit(&mut peer, &request, false, false).is_err());
        assert!(peer.sealed.is_none());
        assert!(
            peer.sent
                .iter()
                .all(|frame| frame["kind"] != "toolchain-seal")
        );
    }
}
