//! Bounded messages for one authenticated canonical operation per connection.
//!
//! The TLS/ATP layer owns framing and peer identity. This layer admits only
//! logical build intent and bytes. Requests cannot select host paths or carry
//! coordinator authority, worker assignments or in-process subscriber handles.
//! Diagnostic bytes are presentation, never filesystem or execution authority.

use super::super::remote_artifacts::ArtifactPrefix;
use super::super::remote_operation::RemoteOperationSettings;
use asupersync::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use rabs_asupersync::worker_transport::{MAX_JSON_RECORD, runtime_transport_now};
use rabs_protocol::durable_ids::BuildOperationId;
use rabs_protocol::raw_bytes::encode_hex;
use rabs_protocol::reconnect::{ResumableToken, SubscriberId};
use rabs_sandbox::artifact_tree::{
    MAX_ARTIFACT_BYTES, MAX_ARTIFACT_FILES, MAX_ARTIFACT_MANIFEST_BYTES,
};
use rabs_sandbox::source_transfer::{
    ArtifactManifest, MAX_SOURCE_BYTES, MAX_SOURCE_CHUNK, MAX_SOURCE_FILES,
    MAX_SOURCE_PREFIX_HINT_BYTES, SourceFile, SourceManifest,
};
use rabs_sandbox::toolchain_dataset::{
    TOOLCHAIN_DATASET_VERSION, ToolchainIdentity, ToolchainLimits,
};
use rabs_sandbox::toolchain_transfer::{
    MAX_TOOLCHAIN_FILE_PAGE_BYTES, ToolchainEntry, ToolchainEntryKind, ToolchainFile,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fmt;
use std::future::{Future, poll_fn};
use std::io;
use std::pin::pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::task::Poll;
use std::time::{Duration, Instant};

pub(super) const VERSION: &str = "canonical-compile-remote-v1";
/// v12 adds source-relative captured stdin for noninteractive execution.
/// Reattachment retains the original input custody, diagnostic frontiers and
/// artifact custody. Peers predating v12 refuse before admission.
pub(super) const WIRE_VERSION: &str = "canonical-compile-remote-v12";
pub(super) const TOOLCHAIN_PAGE_FILES: usize = 64;
/// Source declarations retain their existing file/path/byte limits. Paging
/// removes only the requirement that every source path fit in the Hello frame.
pub(super) const SOURCE_PAGE_FILES: usize = 64;
/// A maximum-length path still leaves this declaration far below one ATP
/// record. Neither a large target nor its complete manifest becomes one frame.
pub(super) const ARTIFACT_PAGE_FILES: usize = 64;
/// Artifact and source offers have the same bounded index/offset/SHA shape and
/// share the control-record budget, leaving room for the full missing-file list.
pub(super) const MAX_ARTIFACT_PREFIX_HINT_BYTES: usize = MAX_SOURCE_PREFIX_HINT_BYTES;
pub(super) const WINDOW: u64 = 4;
pub(super) const IO_BUDGET: Duration = Duration::from_secs(15);
pub(super) const ADMISSION_BUDGET: Duration = Duration::from_secs(30 * 60);
pub(super) const ADMISSION_POLL: Duration = Duration::from_millis(100);
/// A disconnected operation retains its existing execution and input custody
/// briefly, within the original execution/delivery deadline. No restart replay.
pub(super) const RESUME_GRACE: Duration = Duration::from_secs(60);
const CANCELLATION_POLL: Duration = Duration::from_millis(100);
const READS_BEFORE_YIELD: usize = 32;

pub(super) fn invalid(detail: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, detail.into())
}

pub(super) fn require(condition: bool, detail: &str) -> io::Result<()> {
    if condition {
        Ok(())
    } else {
        Err(invalid(detail))
    }
}

pub(super) fn checkpoint(stopped: &AtomicBool, deadline: Instant) -> io::Result<()> {
    if stopped.load(Ordering::Acquire) {
        Err(io::Error::new(
            io::ErrorKind::Interrupted,
            "remote canonical operation cancelled",
        ))
    } else if Instant::now() >= deadline {
        Err(io::Error::new(
            io::ErrorKind::TimedOut,
            "remote canonical operation deadline exceeded",
        ))
    } else {
        Ok(())
    }
}

pub(super) fn decode_hex(value: &str, maximum: usize) -> io::Result<Vec<u8>> {
    require(
        value.len().is_multiple_of(2) && value.len() / 2 <= maximum,
        "remote byte string exceeds its bound or has an odd length",
    )?;
    fn digit(value: u8) -> io::Result<u8> {
        match value {
            b'0'..=b'9' => Ok(value - b'0'),
            b'a'..=b'f' => Ok(value - b'a' + 10),
            _ => Err(invalid(
                "remote byte strings require canonical lowercase hexadecimal",
            )),
        }
    }
    value
        .as_bytes()
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| Ok((digit(pair[0])? << 4) | digit(pair[1])?))
        .collect()
}

pub(super) fn digest(value: &str) -> io::Result<[u8; 32]> {
    decode_hex(value, 32)?
        .try_into()
        .map_err(|_| invalid("expected a SHA-256 digest"))
}

/// The wire carries no subscriber selector: one canonical command has exactly
/// one diagnostic/publication owner. Debug output must never expose its secret.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct OperationToken {
    operation: String,
    incarnation: String,
    secret: String,
}

impl fmt::Debug for OperationToken {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("OperationToken")
            .field("operation", &self.operation)
            .field("incarnation", &self.incarnation)
            .field("secret", &"[redacted]")
            .finish()
    }
}

impl OperationToken {
    pub(super) fn from_native(token: &ResumableToken) -> Self {
        Self {
            operation: encode_hex(&token.request.0.to_be_bytes()),
            incarnation: encode_hex(&token.issued_by_incarnation.to_be_bytes()),
            secret: encode_hex(&token.secret),
        }
    }

    pub(super) fn native(&self) -> io::Result<ResumableToken> {
        fn id(value: &str) -> io::Result<u128> {
            let bytes: [u8; 16] = decode_hex(value, 16)?
                .try_into()
                .map_err(|_| invalid("remote operation token requires a 128-bit identity"))?;
            let value = u128::from_be_bytes(bytes);
            require(value != 0, "remote operation token has a zero identity")?;
            Ok(value)
        }
        let secret = digest(&self.secret)?;
        require(
            secret != [0; 32],
            "remote operation token has a zero secret",
        )?;
        Ok(ResumableToken {
            request: BuildOperationId(id(&self.operation)?),
            subscriber: SubscriberId(1),
            issued_by_incarnation: id(&self.incarnation)?,
            secret,
        })
    }

    pub(super) fn validate(&self) -> io::Result<()> {
        self.native().map(|_| ())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ManifestFile {
    path: String,
    bytes: u64,
    sha256: String,
    executable: bool,
}

impl ManifestFile {
    fn from_native(file: &SourceFile) -> Self {
        Self {
            path: file.path.clone(),
            bytes: file.len,
            sha256: encode_hex(&file.sha256),
            executable: file.executable,
        }
    }

    fn native(&self) -> io::Result<SourceFile> {
        require(
            self.path.len() <= 1024,
            "remote manifest path exceeds its bound",
        )?;
        Ok(SourceFile {
            path: self.path.clone(),
            len: self.bytes,
            sha256: digest(&self.sha256)?,
            executable: self.executable,
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Manifest {
    files: Vec<ManifestFile>,
    pub(super) manifest_sha256: String,
}

impl Manifest {
    pub(super) fn from_native(manifest: &SourceManifest) -> Self {
        Self {
            files: manifest
                .files()
                .iter()
                .map(ManifestFile::from_native)
                .collect(),
            manifest_sha256: encode_hex(&manifest.digest()),
        }
    }

    #[cfg(test)]
    pub(super) fn native(&self) -> io::Result<SourceManifest> {
        let files = self
            .files
            .iter()
            .map(ManifestFile::native)
            .collect::<io::Result<Vec<_>>>()?;
        let manifest = SourceManifest::new(files)?;
        require(
            manifest.digest() == digest(&self.manifest_sha256)?,
            "remote manifest digest differs from its complete file declaration",
        )?;
        Ok(manifest)
    }
}

/// V5 binds the entire source tree before accepting any payload or reserving
/// an operation. This identity uses the unchanged source manifest domain;
/// the larger artifact profile cannot grant source-upload capacity.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct SourceDeclaration {
    manifest_sha256: String,
    files: u32,
    bytes: u64,
    metadata_bytes: u64,
}

impl SourceDeclaration {
    pub(super) fn from_native(manifest: &SourceManifest) -> Self {
        Self {
            manifest_sha256: encode_hex(&manifest.digest()),
            files: manifest.files().len() as u32,
            bytes: manifest.total_bytes(),
            metadata_bytes: manifest.metadata_bytes(),
        }
    }

    fn validate(&self) -> io::Result<()> {
        require(
            self.files != 0
                && self.files as usize <= MAX_SOURCE_FILES
                && self.bytes <= MAX_SOURCE_BYTES
                && self.metadata_bytes != 0
                // Canonical entries contain a bounded path plus two u64s,
                // a mode byte and SHA-256. The fixed header fits in 128 bytes.
                && self.metadata_bytes <= 128 + u64::from(self.files) * (1024 + 8 + 8 + 1 + 32),
            "remote source declaration exceeds its existing source profile",
        )?;
        digest(&self.manifest_sha256)?;
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct SourcePage {
    first: u32,
    files: Vec<ManifestFile>,
}

impl SourcePage {
    pub(super) fn from_native(first: usize, files: &[SourceFile]) -> io::Result<Self> {
        require(
            !files.is_empty()
                && files.len() <= SOURCE_PAGE_FILES
                && first < MAX_SOURCE_FILES
                && first + files.len() <= MAX_SOURCE_FILES,
            "remote source manifest page exceeds its bound",
        )?;
        Ok(Self {
            first: first as u32,
            files: files.iter().map(ManifestFile::from_native).collect(),
        })
    }
}

/// Metadata custody only. No source path is created and no compilation can
/// be admitted until finish verifies the complete declared namespace/digest.
pub(super) struct SourcePages {
    declaration: SourceDeclaration,
    files: Vec<SourceFile>,
    bytes: u64,
    entry_bytes: u64,
}

impl SourcePages {
    pub(super) fn new(declaration: SourceDeclaration) -> io::Result<Self> {
        declaration.validate()?;
        Ok(Self {
            declaration,
            files: Vec::new(),
            bytes: 0,
            entry_bytes: 0,
        })
    }

    pub(super) fn push(&mut self, page: SourcePage) -> io::Result<()> {
        require(
            page.first as usize == self.files.len()
                && !page.files.is_empty()
                && page.files.len() <= SOURCE_PAGE_FILES
                && self.files.len() + page.files.len() <= self.declaration.files as usize,
            "remote source pages overlap, skip members or exceed their declared count",
        )?;
        let files = page
            .files
            .iter()
            .map(ManifestFile::native)
            .collect::<io::Result<Vec<_>>>()?;
        let mut prior = self.files.last().map(|file| file.path.as_str());
        let mut bytes = self.bytes;
        let mut entry_bytes = self.entry_bytes;
        for file in &files {
            require(
                prior.is_none_or(|prior| prior < file.path.as_str()),
                "remote source pages must preserve canonical path order",
            )?;
            prior = Some(&file.path);
            bytes = bytes
                .checked_add(file.len)
                .filter(|bytes| *bytes <= self.declaration.bytes)
                .ok_or_else(|| invalid("remote source pages exceed their declared bytes"))?;
            entry_bytes = entry_bytes
                .checked_add(file.path.len() as u64 + 8 + 8 + 1 + 32)
                .filter(|bytes| *bytes <= self.declaration.metadata_bytes)
                .ok_or_else(|| invalid("remote source pages exceed their metadata budget"))?;
        }
        SourceManifest::new(files.clone())?;
        self.files.extend(files);
        self.bytes = bytes;
        self.entry_bytes = entry_bytes;
        Ok(())
    }

    pub(super) fn finish(self) -> io::Result<SourceManifest> {
        require(
            self.files.len() == self.declaration.files as usize
                && self.bytes == self.declaration.bytes,
            "remote source manifest ended before its complete declaration",
        )?;
        let manifest = SourceManifest::new(self.files)?;
        require(
            manifest.digest() == digest(&self.declaration.manifest_sha256)?
                && manifest.metadata_bytes() == self.declaration.metadata_bytes,
            "remote source manifest differs from its declared identity",
        )?;
        Ok(manifest)
    }
}

/// V4 negotiates an output-specific, finite storage profile independently of
/// source upload. The declaration is small even for a many-file Cargo target;
/// no output paths are created until all bounded pages match this identity.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ArtifactDeclaration {
    pub(super) manifest_sha256: String,
    files: u32,
    bytes: u64,
    metadata_bytes: u64,
}

impl ArtifactDeclaration {
    pub(super) fn from_native(manifest: &ArtifactManifest) -> Self {
        Self {
            manifest_sha256: encode_hex(&manifest.digest()),
            files: manifest.files().len() as u32,
            bytes: manifest.total_bytes(),
            metadata_bytes: manifest.metadata_bytes(),
        }
    }

    fn validate(&self) -> io::Result<()> {
        require(
            self.files != 0
                && u64::from(self.files) <= MAX_ARTIFACT_FILES as u64
                && self.bytes <= MAX_ARTIFACT_BYTES
                && self.metadata_bytes != 0
                && self.metadata_bytes <= MAX_ARTIFACT_MANIFEST_BYTES as u64,
            "remote artifact declaration exceeds the negotiated output profile",
        )?;
        digest(&self.manifest_sha256)?;
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ArtifactPage {
    first: u32,
    files: Vec<ManifestFile>,
}

impl ArtifactPage {
    pub(super) fn from_native(first: usize, files: &[SourceFile]) -> io::Result<Self> {
        require(
            !files.is_empty()
                && files.len() <= ARTIFACT_PAGE_FILES
                && first < MAX_ARTIFACT_FILES
                && first + files.len() <= MAX_ARTIFACT_FILES,
            "remote artifact manifest page exceeds its bound",
        )?;
        Ok(Self {
            first: first as u32,
            files: files.iter().map(ManifestFile::from_native).collect(),
        })
    }
}

/// Bounded metadata only. Every chunk of file data goes directly to the
/// anchored receiver after this complete declaration has been validated.
pub(super) struct ArtifactPages {
    declaration: ArtifactDeclaration,
    files: Vec<SourceFile>,
    bytes: u64,
    entry_bytes: u64,
}

impl ArtifactPages {
    pub(super) fn new(declaration: ArtifactDeclaration) -> io::Result<Self> {
        declaration.validate()?;
        Ok(Self {
            declaration,
            files: Vec::new(),
            bytes: 0,
            entry_bytes: 0,
        })
    }

    pub(super) fn push(&mut self, page: ArtifactPage) -> io::Result<()> {
        require(
            page.first as usize == self.files.len()
                && !page.files.is_empty()
                && page.files.len() <= ARTIFACT_PAGE_FILES
                && self.files.len() + page.files.len() <= self.declaration.files as usize,
            "remote artifact pages overlap, skip members or exceed their declared count",
        )?;
        let files = page
            .files
            .iter()
            .map(ManifestFile::native)
            .collect::<io::Result<Vec<_>>>()?;
        let mut prior = self.files.last().map(|file| file.path.as_str());
        let mut bytes = self.bytes;
        let mut entry_bytes = self.entry_bytes;
        for file in &files {
            require(
                prior.is_none_or(|prior| prior < file.path.as_str()),
                "remote artifact pages must preserve canonical path order",
            )?;
            prior = Some(&file.path);
            bytes = bytes
                .checked_add(file.len)
                .filter(|bytes| *bytes <= self.declaration.bytes)
                .ok_or_else(|| invalid("remote artifact pages exceed their declared bytes"))?;
            // Canonical entries contain a u64 path length, the path, a u64
            // file length, one mode byte and a SHA-256 digest. This early bound
            // includes every allocated name; finish also checks domain/header
            // overhead against the exact canonical manifest size.
            entry_bytes = entry_bytes
                .checked_add(file.path.len() as u64 + 8 + 8 + 1 + 32)
                .filter(|bytes| *bytes <= self.declaration.metadata_bytes)
                .ok_or_else(|| invalid("remote artifact pages exceed their metadata budget"))?;
        }
        // Validate each page before retaining it; global namespace collisions
        // and exact whole-manifest identity are checked again at finish.
        ArtifactManifest::new(files.clone())?;
        self.files.extend(files);
        self.bytes = bytes;
        self.entry_bytes = entry_bytes;
        Ok(())
    }

    pub(super) fn finish(self) -> io::Result<ArtifactManifest> {
        require(
            self.files.len() == self.declaration.files as usize
                && self.bytes == self.declaration.bytes,
            "remote artifact manifest ended before its complete declaration",
        )?;
        let manifest = ArtifactManifest::new(self.files)?;
        require(
            manifest.digest() == digest(&self.declaration.manifest_sha256)?
                && manifest.metadata_bytes() == self.declaration.metadata_bytes,
            "remote artifact manifest differs from its declared identity",
        )?;
        Ok(manifest)
    }
}

/// Payload selection after the complete artifact manifest has been checked.
/// Omitted members must already have independent byte custody at the client;
/// the final full-tree seal and coordinator publication checks remain required.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct ArtifactPlan {
    pub(super) manifest_sha256: String,
    pub(super) missing_files: Vec<u16>,
    pub(super) prefixes: Vec<ArtifactPrefixOffer>,
}

/// Frozen receiver bytes, offered only as an optional transfer cursor. The
/// captured producer must hash its own prefix before choosing this offset.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ArtifactPrefixOffer {
    pub(super) index: u16,
    pub(super) offset: u64,
    pub(super) sha256: String,
}

impl ArtifactPrefixOffer {
    pub(super) fn from_native(prefix: &ArtifactPrefix) -> Self {
        Self {
            index: prefix.index,
            offset: prefix.offset,
            sha256: encode_hex(&prefix.sha256),
        }
    }
}

impl ArtifactPlan {
    pub(super) fn all(manifest: &ArtifactManifest) -> io::Result<Self> {
        let missing_files = manifest
            .files()
            .iter()
            .enumerate()
            .filter(|(_, file)| file.len != 0)
            .map(|(index, _)| {
                u16::try_from(index)
                    .map_err(|_| invalid("artifact delivery index exceeds its wire bound"))
            })
            .collect::<io::Result<Vec<_>>>()?;
        Self::new(manifest, missing_files)
    }

    pub(super) fn new(manifest: &ArtifactManifest, missing_files: Vec<u16>) -> io::Result<Self> {
        Self::with_prefixes(manifest, missing_files, Vec::new())
    }

    pub(super) fn with_prefixes(
        manifest: &ArtifactManifest,
        missing_files: Vec<u16>,
        prefixes: Vec<ArtifactPrefixOffer>,
    ) -> io::Result<Self> {
        Self::from_request(
            encode_hex(&manifest.digest()),
            missing_files,
            prefixes,
            manifest,
        )
    }

    pub(super) fn prefix_for(&self, index: usize) -> Option<&ArtifactPrefixOffer> {
        self.prefixes
            .binary_search_by_key(&index, |prefix| usize::from(prefix.index))
            .ok()
            .map(|position| &self.prefixes[position])
    }

    /// The original missing-file selection remains intact across attachments.
    /// A live receiver can skip its completed prefix and resume one partial
    /// member, but every result still requires a full manifest/byte seal.
    pub(super) fn validate_cursor(
        &self,
        manifest: &ArtifactManifest,
        file_index: u32,
        offset: u64,
    ) -> io::Result<()> {
        let index = file_index as usize;
        if index == manifest.files().len() {
            return require(
                offset == 0,
                "completed artifact cursor has a nonzero offset",
            );
        }
        require(
            manifest
                .files()
                .get(index)
                .is_some_and(|file| offset < file.len)
                && u16::try_from(index)
                    .is_ok_and(|index| self.missing_files.binary_search(&index).is_ok()),
            "artifact resume cursor is outside the selected file payloads",
        )
    }

    pub(super) fn from_request(
        manifest_sha256: String,
        missing_files: Vec<u16>,
        prefixes: Vec<ArtifactPrefixOffer>,
        manifest: &ArtifactManifest,
    ) -> io::Result<Self> {
        require(
            digest(&manifest_sha256)? == manifest.digest(),
            "artifact delivery plan differs from the captured manifest",
        )?;
        require(
            missing_files.len() <= MAX_ARTIFACT_FILES
                && missing_files.len() <= manifest.files().len()
                && missing_files.windows(2).all(|pair| pair[0] < pair[1])
                && missing_files.iter().all(|index| {
                    manifest
                        .files()
                        .get(usize::from(*index))
                        .is_some_and(|file| file.len != 0)
                }),
            "artifact delivery indexes must be a bounded ordered subset of nonempty files",
        )?;
        require(
            prefixes.len() <= missing_files.len()
                && prefixes
                    .windows(2)
                    .all(|pair| pair[0].index < pair[1].index),
            "artifact prefixes must be a bounded ordered subset of missing files",
        )?;
        let mut encoded_bytes = 2_usize; // The array's opening and closing brackets.
        for (position, prefix) in prefixes.iter().enumerate() {
            require(
                missing_files.binary_search(&prefix.index).is_ok()
                    && manifest
                        .files()
                        .get(usize::from(prefix.index))
                        .is_some_and(|file| prefix.offset != 0 && prefix.offset < file.len),
                "artifact prefix must name an incomplete requested file",
            )?;
            digest(&prefix.sha256)?;
            // Reject malformed rows before serializing them; the complete
            // valid offer list occupies at most a fraction of one ATP record.
            encoded_bytes = encoded_bytes
                .checked_add(serde_json::to_vec(prefix)?.len() + usize::from(position != 0))
                .filter(|bytes| *bytes <= MAX_ARTIFACT_PREFIX_HINT_BYTES)
                .ok_or_else(|| invalid("artifact prefix offers exceed their metadata bound"))?;
        }
        Ok(Self {
            manifest_sha256,
            missing_files,
            prefixes,
        })
    }
}

/// A retained prefix, indexed by the complete manifest's canonical path order.
/// The sender independently checks its bytes before selecting this cursor.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct SourcePrefixOffer {
    pub(super) index: u16,
    pub(super) offset: u64,
    pub(super) sha256: String,
}

/// Missing input bytes, indexed by the complete manifest's canonical path order.
/// These hints never grant source authority: the receiver must still seal the
/// entire declared tree, including every independently imported cache hit.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct SourcePlan {
    pub(super) manifest_sha256: String,
    pub(super) missing_files: Vec<u16>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub(super) prefixes: Vec<SourcePrefixOffer>,
}

impl SourcePlan {
    pub(super) fn all(manifest: &SourceManifest) -> io::Result<Self> {
        let missing_files = manifest
            .files()
            .iter()
            .enumerate()
            .filter(|(_, file)| file.len != 0)
            .map(|(index, _)| {
                u16::try_from(index)
                    .map_err(|_| invalid("source upload index exceeds its wire bound"))
            })
            .collect::<io::Result<Vec<_>>>()?;
        Self::new(manifest, missing_files)
    }

    pub(super) fn new(manifest: &SourceManifest, missing_files: Vec<u16>) -> io::Result<Self> {
        Self::with_prefixes(manifest, missing_files, Vec::new())
    }

    pub(super) fn with_prefixes(
        manifest: &SourceManifest,
        missing_files: Vec<u16>,
        prefixes: Vec<SourcePrefixOffer>,
    ) -> io::Result<Self> {
        let plan = Self {
            manifest_sha256: encode_hex(&manifest.digest()),
            missing_files,
            prefixes,
        };
        plan.validate(manifest)?;
        Ok(plan)
    }

    pub(super) fn prefix_for(&self, index: usize) -> Option<&SourcePrefixOffer> {
        self.prefixes
            .binary_search_by_key(&index, |prefix| usize::from(prefix.index))
            .ok()
            .map(|position| &self.prefixes[position])
    }

    pub(super) fn validate(&self, manifest: &SourceManifest) -> io::Result<()> {
        require(
            digest(&self.manifest_sha256)? == manifest.digest(),
            "source upload plan differs from the captured manifest",
        )?;
        require(
            self.missing_files.len() <= MAX_SOURCE_FILES
                && self.missing_files.windows(2).all(|pair| pair[0] < pair[1])
                && self.missing_files.iter().all(|index| {
                    manifest
                        .files()
                        .get(usize::from(*index))
                        .is_some_and(|file| file.len != 0)
                }),
            "source upload indexes must be a bounded ordered subset of nonempty files",
        )?;
        require(
            self.prefixes.len() <= self.missing_files.len()
                && self
                    .prefixes
                    .windows(2)
                    .all(|pair| pair[0].index < pair[1].index),
            "source prefixes must be a bounded ordered subset of missing files",
        )?;
        let mut encoded_bytes = 2_usize; // The array's opening and closing brackets.
        for (position, prefix) in self.prefixes.iter().enumerate() {
            require(
                self.missing_files.binary_search(&prefix.index).is_ok()
                    && manifest
                        .files()
                        .get(usize::from(prefix.index))
                        .is_some_and(|file| prefix.offset != 0 && prefix.offset < file.len),
                "source prefix must name an incomplete requested file",
            )?;
            digest(&prefix.sha256)?;
            // Validate each small row before serializing it. A malformed digest
            // or unbounded list cannot allocate another large JSON record here.
            encoded_bytes = encoded_bytes
                .checked_add(serde_json::to_vec(prefix)?.len() + usize::from(position != 0))
                .filter(|bytes| *bytes <= MAX_SOURCE_PREFIX_HINT_BYTES)
                .ok_or_else(|| invalid("source prefix offers exceed their metadata bound"))?;
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Toolchain {
    version: String,
    sha256: String,
    files: u64,
    bytes: u64,
}

impl Toolchain {
    pub(super) fn from_native(identity: &ToolchainIdentity) -> Self {
        Self {
            version: TOOLCHAIN_DATASET_VERSION.into(),
            sha256: encode_hex(&identity.sha256),
            files: identity.files,
            bytes: identity.bytes,
        }
    }

    pub(super) fn native(&self) -> io::Result<ToolchainIdentity> {
        let limits = ToolchainLimits::default();
        require(
            self.version == TOOLCHAIN_DATASET_VERSION
                && self.files != 0
                && self.files <= limits.max_entries as u64
                && self.bytes <= limits.max_bytes,
            "unsupported or oversized remote toolchain identity",
        )?;
        Ok(ToolchainIdentity {
            sha256: digest(&self.sha256)?,
            files: self.files,
            bytes: self.bytes,
        })
    }
}

/// A regular SDK member's byte identity. This inventory is only a transfer
/// hint: the receiver still verifies directories, links and the complete SDK.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ToolchainFileSpec {
    path: String,
    bytes: u64,
    executable: bool,
    sha256: String,
}

impl ToolchainFileSpec {
    fn from_native(file: &ToolchainFile) -> Self {
        Self {
            path: file.path.clone(),
            bytes: file.bytes,
            executable: file.executable,
            sha256: encode_hex(&file.sha256),
        }
    }

    fn native(&self) -> io::Result<ToolchainFile> {
        require(
            !self.path.is_empty()
                && self.path.len() <= 4096
                && !self.path.contains(['\\', ':'])
                && !self.path.chars().any(char::is_control)
                && self.path.split('/').count() <= 64
                && self
                    .path
                    .split('/')
                    .all(|part| part.len() <= 255 && !matches!(part, "" | "." | ".."))
                && self.bytes <= ToolchainLimits::default().max_bytes,
            "SDK file hints require bounded canonical relative paths and bytes",
        )?;
        Ok(ToolchainFile {
            path: self.path.clone(),
            bytes: self.bytes,
            executable: self.executable,
            sha256: digest(&self.sha256)?,
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ToolchainFilePage {
    pub(super) first: u32,
    pub(super) files: Vec<ToolchainFileSpec>,
}

impl ToolchainFilePage {
    pub(super) fn from_native(first: usize, files: &[ToolchainFile]) -> io::Result<Self> {
        let page = Self {
            first: u32::try_from(first).map_err(|_| invalid("SDK file index exceeds its bound"))?,
            files: files.iter().map(ToolchainFileSpec::from_native).collect(),
        };
        page.native()?;
        Ok(page)
    }

    pub(super) fn native(&self) -> io::Result<Vec<ToolchainFile>> {
        require(
            !self.files.is_empty()
                && self.files.len() <= TOOLCHAIN_PAGE_FILES
                && u64::from(self.first) + self.files.len() as u64
                    <= ToolchainLimits::default().max_entries as u64,
            "SDK file page exceeds its count or index bound",
        )?;
        let files = self
            .files
            .iter()
            .map(ToolchainFileSpec::native)
            .collect::<io::Result<Vec<_>>>()?;
        require(
            files.windows(2).all(|pair| pair[0].path < pair[1].path)
                && serde_json::to_vec(self)?.len() <= MAX_TOOLCHAIN_FILE_PAGE_BYTES,
            "SDK file page exceeds its metadata bound or canonical order",
        )?;
        Ok(files)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ToolchainPrefixOffer {
    pub(super) index: u32,
    pub(super) offset: u64,
    pub(super) sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ToolchainFilePlan {
    pub(super) first: u32,
    pub(super) missing_files: Vec<u32>,
    pub(super) prefixes: Vec<ToolchainPrefixOffer>,
}

impl ToolchainFilePlan {
    pub(super) fn validate(&self, page: &ToolchainFilePage) -> io::Result<()> {
        let files = page.native()?;
        let file = |index: u32| {
            index
                .checked_sub(page.first)
                .and_then(|index| files.get(index as usize))
        };
        require(
            self.first == page.first
                && self.missing_files.len() <= files.len()
                && self.missing_files.windows(2).all(|pair| pair[0] < pair[1])
                && self
                    .missing_files
                    .iter()
                    .all(|index| file(*index).is_some_and(|file| file.bytes != 0)),
            "SDK missing-file plan must be an ordered subset of this exact page",
        )?;
        require(
            self.prefixes.len() <= self.missing_files.len()
                && self
                    .prefixes
                    .windows(2)
                    .all(|pair| pair[0].index < pair[1].index),
            "SDK prefix plan must be an ordered subset of missing files",
        )?;
        for prefix in &self.prefixes {
            require(
                self.missing_files.binary_search(&prefix.index).is_ok()
                    && file(prefix.index)
                        .is_some_and(|file| prefix.offset != 0 && prefix.offset < file.bytes),
                "SDK prefix must select an incomplete member of this exact page",
            )?;
            digest(&prefix.sha256)?;
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ToolchainResume {
    pub(super) offset: u64,
    pub(super) sha256: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct CargoHome {
    version: String,
    prefix: String,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "kebab-case", deny_unknown_fields)]
pub(super) enum Entry {
    Directory {
        path: String,
    },
    Symlink {
        path: String,
        target: String,
    },
    File {
        path: String,
        bytes: u64,
        executable: bool,
    },
}

impl Entry {
    pub(super) fn from_native(entry: ToolchainEntry) -> Self {
        match entry.kind {
            ToolchainEntryKind::Directory => Self::Directory { path: entry.path },
            ToolchainEntryKind::Symlink { target } => Self::Symlink {
                path: entry.path,
                target,
            },
            ToolchainEntryKind::File { bytes, executable } => Self::File {
                path: entry.path,
                bytes,
                executable,
            },
        }
    }

    pub(super) fn native(self) -> ToolchainEntry {
        let (path, kind) = match self {
            Self::Directory { path } => (path, ToolchainEntryKind::Directory),
            Self::Symlink { path, target } => (path, ToolchainEntryKind::Symlink { target }),
            Self::File {
                path,
                bytes,
                executable,
            } => (path, ToolchainEntryKind::File { bytes, executable }),
        };
        ToolchainEntry { path, kind }
    }
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Chunk {
    pub(super) path: String,
    pub(super) offset: u64,
    sha256: String,
    bytes: String,
}

impl Chunk {
    pub(super) fn new(path: &str, offset: u64, bytes: &[u8]) -> io::Result<Self> {
        require(
            !bytes.is_empty() && bytes.len() <= MAX_SOURCE_CHUNK,
            "invalid remote chunk length",
        )?;
        Ok(Self {
            path: path.into(),
            offset,
            sha256: encode_hex(&Sha256::digest(bytes)),
            bytes: encode_hex(bytes),
        })
    }

    pub(super) fn verified_bytes(&self) -> io::Result<(Vec<u8>, [u8; 32])> {
        let bytes = decode_hex(&self.bytes, MAX_SOURCE_CHUNK)?;
        let expected = digest(&self.sha256)?;
        require(
            !bytes.is_empty() && <[u8; 32]>::from(Sha256::digest(&bytes)) == expected,
            "remote chunk is empty or its digest differs",
        )?;
        Ok((bytes, expected))
    }
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Output {
    pub(super) offset: u64,
    pub(super) bytes: String,
}

/// The authenticated coordinator owns any reused SDK for this operation.
/// Reuse changes only which input bytes are sent, never their declared identity.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub(super) enum ToolchainDisposition {
    Upload,
    UploadFiles,
    Reuse,
}

/// Field-less messages are empty struct variants, never unit variants: serde's
/// internally tagged unit visitor skips remaining entries, so
/// `deny_unknown_fields` would not refuse `{"kind":"poll","extra":1}`.
/// The JSON is the same `{"kind":"poll"}` either way.
#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
pub(super) enum Message {
    Hello {
        version: String,
        build_identity: String,
        require_release: bool,
        settings: Box<RemoteOperationSettings>,
        source_manifest: SourceDeclaration,
        toolchain_identity: Toolchain,
        cargo_home: Option<CargoHome>,
    },
    Resume {
        version: String,
        build_identity: String,
        require_release: bool,
        token: OperationToken,
        stdout_offset: u64,
        stderr_offset: u64,
    },
    ResumePending {},
    CancelOperation {
        version: String,
        build_identity: String,
        require_release: bool,
        token: OperationToken,
    },
    Cancelled {},
    SourceManifestPage {
        page: SourcePage,
    },
    SourceManifestEnd {},
    Queued {},
    Ready {
        toolchain: ToolchainDisposition,
        source: SourcePlan,
        resume: OperationToken,
    },
    SourceChunk {
        chunk: Chunk,
    },
    ToolchainEntry {
        entry: Entry,
    },
    ToolchainFilePage {
        page: ToolchainFilePage,
    },
    ToolchainFilePlan {
        plan: ToolchainFilePlan,
    },
    ToolchainFilesEnd {},
    ToolchainFilesReady {
        files: u64,
        bytes: u64,
    },
    ToolchainFilesDecline {},
    ToolchainFilesDeclined {},
    ToolchainResumedEntry {
        entry: Entry,
        resume: Option<ToolchainResume>,
    },
    ToolchainChunk {
        chunk: Chunk,
    },
    WindowEnd {
        count: u64,
    },
    Window {
        count: u64,
    },
    InputsDone {},
    Accepted {},
    Poll {},
    Progress {
        stdout: Output,
        stderr: Output,
    },
    BuildFinished {
        exit_code: i32,
        stdout_bytes: u64,
        stderr_bytes: u64,
        target: Option<ArtifactDeclaration>,
    },
    ReceiveTarget {},
    ArtifactManifestPage {
        page: ArtifactPage,
    },
    ArtifactManifestEnd {},
    ReceiveArtifacts {
        manifest_sha256: String,
        missing_files: Vec<u16>,
        prefixes: Vec<ArtifactPrefixOffer>,
        file_index: u32,
        offset: u64,
    },
    ArtifactChunk {
        chunk: Chunk,
    },
    ArtifactEnd {},
    Received {
        manifest_sha256: String,
    },
    Commit {
        manifest_sha256: String,
    },
    Published {
        manifest_sha256: String,
    },
    Complete {
        exit_code: i32,
    },
    Delivered {},
    Close {},
    Cancel {},
    Failure {
        message: String,
    },
}

/// A fixed byte/frame deadline and a finite buffer belong to this connection.
/// Partial records are never continued on another connection. A fresh wire can
/// reattach to the same operation using its independently retained frontiers.
pub(super) struct Wire<S> {
    stream: S,
    buffered: Vec<u8>,
    failed: bool,
}

impl<S: AsyncRead + AsyncWrite + Unpin> Wire<S> {
    pub(super) fn new(stream: S) -> Self {
        Self {
            stream,
            buffered: Vec::new(),
            failed: false,
        }
    }

    /// A local filesystem/output error, protocol refusal or cancellation must
    /// never trigger network recovery, even if it uses the same error kind.
    pub(super) fn can_resume_after(&self, error: &io::Error) -> bool {
        self.failed
            && matches!(
                error.kind(),
                io::ErrorKind::ConnectionReset
                    | io::ErrorKind::ConnectionAborted
                    | io::ErrorKind::BrokenPipe
                    | io::ErrorKind::UnexpectedEof
                    | io::ErrorKind::TimedOut
                    | io::ErrorKind::NotConnected
            )
    }

    pub(super) async fn send(
        &mut self,
        message: &Message,
        stopped: &AtomicBool,
        deadline: Instant,
    ) -> io::Result<()> {
        require(
            !self.failed,
            "remote connection is terminal after an I/O failure",
        )?;
        let result = async {
            checkpoint(stopped, deadline)?;
            let mut bytes = serde_json::to_vec(message)?;
            require(
                bytes.len() <= MAX_JSON_RECORD,
                "remote record exceeds its ATP bound",
            )?;
            bytes.push(b'\n');
            let write_deadline = deadline.min(Instant::now() + IO_BUDGET);
            controlled_future(stopped, write_deadline, async {
                self.stream.write_all(&bytes).await?;
                self.stream.flush().await
            })
            .await
        }
        .await;
        // ATP retains partial output independently of this future. A later
        // error-reporting send must never resume an expired Commit/Complete.
        if result.is_err() {
            self.failed = true;
        }
        result
    }

    pub(super) async fn receive(
        &mut self,
        stopped: &AtomicBool,
        deadline: Instant,
    ) -> io::Result<Message> {
        self.receive_until(stopped, deadline.min(Instant::now() + IO_BUDGET))
            .await
    }

    /// A client may wait while the server seals an SDK or revalidates complete
    /// artifact provenance. Keep the original phase deadline through that idle
    /// wait; the enclosing ATP adapter still bounds each partial wire record.
    pub(super) async fn receive_until(
        &mut self,
        stopped: &AtomicBool,
        deadline: Instant,
    ) -> io::Result<Message> {
        require(
            !self.failed,
            "remote connection is terminal after an I/O failure",
        )?;
        let result = async {
            let message = controlled_future(
                stopped,
                deadline,
                read_record(&mut self.stream, &mut self.buffered),
            )
            .await?;
            match message {
                Message::Failure { message } => Err(invalid(format!(
                    "remote canonical service: {}",
                    message.chars().take(4096).collect::<String>()
                ))),
                Message::Cancel {} => Err(io::Error::new(
                    io::ErrorKind::Interrupted,
                    "remote client cancelled its operation",
                )),
                message => Ok(message),
            }
        }
        .await;
        if result.is_err() {
            self.failed = true;
        }
        result
    }
}

/// Poll one retained I/O future while an independent timer observes atomic
/// cancellation. Ticks neither recreate partial reads/writes nor renew the
/// supplied deadline. A quiet peer therefore cannot delay local cancellation.
pub(super) async fn controlled_future<T>(
    stopped: &AtomicBool,
    deadline: Instant,
    future: impl Future<Output = io::Result<T>>,
) -> io::Result<T> {
    let mut work = pin!(future);
    loop {
        checkpoint(stopped, deadline)?;
        let budget = CANCELLATION_POLL.min(deadline.saturating_duration_since(Instant::now()));
        let mut tick = pin!(asupersync::time::sleep(runtime_transport_now(), budget));
        let completed = poll_fn(|cx| {
            if let Err(error) = checkpoint(stopped, deadline) {
                return Poll::Ready(Err(error));
            }
            if let Poll::Ready(result) = work.as_mut().poll(cx) {
                return Poll::Ready(result.map(Some));
            }
            if tick.as_mut().poll(cx).is_ready() {
                Poll::Ready(Ok(None))
            } else {
                Poll::Pending
            }
        })
        .await?;
        if let Some(completed) = completed {
            checkpoint(stopped, deadline)?;
            return Ok(completed);
        }
    }
}

async fn read_record<S: AsyncRead + Unpin>(
    stream: &mut S,
    buffered: &mut Vec<u8>,
) -> io::Result<Message> {
    let mut scanned = 0;
    // Heap, not the future's state: read_record nests in every receive loop.
    let mut chunk = vec![0_u8; 16 * 1024];
    let mut reads = 0;
    loop {
        if let Some(offset) = buffered[scanned..].iter().position(|byte| *byte == b'\n') {
            let end = scanned + offset;
            require(
                end <= MAX_JSON_RECORD,
                "remote record exceeds its ATP bound",
            )?;
            let message = serde_json::from_slice(&buffered[..end])
                .map_err(|error| invalid(error.to_string()))?;
            buffered.drain(..=end);
            return Ok(message);
        }
        require(
            buffered.len() <= MAX_JSON_RECORD,
            "remote record exceeds its ATP bound",
        )?;
        scanned = buffered.len();
        let capacity = chunk.len().min(MAX_JSON_RECORD + 1 - buffered.len());
        let count = stream.read(&mut chunk[..capacity]).await?;
        if count == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "remote connection ended without a terminal receipt",
            ));
        }
        buffered.extend_from_slice(&chunk[..count]);
        reads += 1;
        if reads == READS_BEFORE_YIELD {
            reads = 0;
            // A continuously ready socket must return to the owning poll so
            // its deadline and cancellation win over more buffered input.
            let mut yielded = false;
            poll_fn(|cx| {
                if yielded {
                    Poll::Ready(())
                } else {
                    yielded = true;
                    cx.waker().wake_by_ref();
                    Poll::Pending
                }
            })
            .await;
        }
    }
}

/// Both directions acknowledge exact cumulative counts after at most four
/// chunks/entries. TCP can pipeline a window without unbounded queued memory.
#[derive(Debug, Default)]
pub(super) struct Window {
    count: u64,
    pending: u64,
}

impl Window {
    pub(super) fn record(&mut self) -> io::Result<bool> {
        require(
            self.pending < WINDOW,
            "remote transfer exceeded its unacknowledged window",
        )?;
        self.count = self
            .count
            .checked_add(1)
            .ok_or_else(|| invalid("remote transfer counter exhausted"))?;
        self.pending += 1;
        Ok(self.pending == WINDOW)
    }

    pub(super) fn pending(&self) -> bool {
        self.pending != 0
    }
    pub(super) fn count(&self) -> u64 {
        self.count
    }

    pub(super) fn acknowledge(&mut self, count: u64) -> io::Result<()> {
        require(
            self.pending != 0 && count == self.count,
            "remote transfer acknowledgment is stale or out of order",
        )?;
        self.pending = 0;
        Ok(())
    }
}

#[cfg(test)]
mod prefix_tests;

#[cfg(test)]
mod artifact_plan_tests {
    use super::*;

    fn manifest() -> ArtifactManifest {
        ArtifactManifest::new(vec![
            SourceFile {
                path: "program".into(),
                len: 3,
                sha256: Sha256::digest(b"bin").into(),
                executable: true,
            },
            SourceFile {
                path: "empty".into(),
                len: 0,
                sha256: Sha256::digest([]).into(),
                executable: false,
            },
            SourceFile {
                path: "deps/lib.rmeta".into(),
                len: 4,
                sha256: Sha256::digest(b"meta").into(),
                executable: false,
            },
        ])
        .unwrap()
    }

    #[test]
    fn artifact_plans_select_only_ordered_nonempty_manifest_members() {
        let manifest = manifest();
        let all = ArtifactPlan::all(&manifest).unwrap();
        assert_eq!(all.missing_files, [0, 2]);
        assert_eq!(all.manifest_sha256, encode_hex(&manifest.digest()));
        assert!(all.prefixes.is_empty());
        for missing in [vec![], vec![0], vec![2], vec![0, 2]] {
            assert_eq!(
                ArtifactPlan::new(&manifest, missing.clone())
                    .unwrap()
                    .missing_files,
                missing,
            );
        }
        for missing in [
            vec![0, 0],
            vec![2, 0],
            vec![1],
            vec![3],
            vec![u16::MAX],
            vec![0; MAX_ARTIFACT_FILES + 1],
        ] {
            assert!(ArtifactPlan::new(&manifest, missing).is_err());
        }
    }

    fn prefix(index: u16, offset: u64) -> ArtifactPrefixOffer {
        ArtifactPrefixOffer {
            index,
            offset,
            sha256: encode_hex(&Sha256::digest(b"retained prefix")),
        }
    }

    #[test]
    fn artifact_prefixes_are_optional_ordered_hints_for_requested_members() {
        let manifest = manifest();
        for offers in [vec![], vec![prefix(0, 1)], vec![prefix(0, 3), prefix(2, 2)]] {
            let plan = ArtifactPlan::with_prefixes(&manifest, vec![0, 2], offers.clone()).unwrap();
            assert_eq!(plan.prefixes, offers);
            assert_eq!(
                plan.prefix_for(0),
                offers.first().filter(|offer| offer.index == 0)
            );
            assert_eq!(
                plan.prefix_for(2),
                offers.iter().find(|offer| offer.index == 2)
            );
            assert!(plan.prefix_for(1).is_none());
            assert!(plan.prefix_for(usize::MAX).is_none());
        }
        let native = ArtifactPrefix {
            index: 2,
            offset: 2,
            sha256: Sha256::digest(b"bi").into(),
        };
        assert_eq!(
            ArtifactPrefixOffer::from_native(&native),
            ArtifactPrefixOffer {
                index: 2,
                offset: 2,
                sha256: encode_hex(&Sha256::digest(b"bi")),
            },
        );
    }

    #[test]
    fn artifact_prefixes_refuse_unsafe_ranges_members_order_and_digests() {
        let manifest = manifest();
        for (missing, offers) in [
            (vec![0, 2], vec![prefix(0, 0)]),
            (vec![0, 2], vec![prefix(0, 4)]),
            (vec![0, 2], vec![prefix(0, u64::MAX)]),
            (vec![0, 2], vec![prefix(2, 3)]),
            (vec![0, 2], vec![prefix(1, 1)]),
            (vec![0, 2], vec![prefix(3, 1)]),
            (vec![0, 2], vec![prefix(u16::MAX, 1)]),
            (vec![2], vec![prefix(0, 1)]),
            (vec![], vec![prefix(0, 1)]),
            (vec![0, 2], vec![prefix(0, 1), prefix(0, 2)]),
            (vec![0, 2], vec![prefix(2, 1), prefix(0, 1)]),
            (vec![0, 2], vec![prefix(0, 1); MAX_ARTIFACT_FILES + 1]),
        ] {
            assert!(ArtifactPlan::with_prefixes(&manifest, missing, offers).is_err());
        }
        for sha256 in [
            String::new(),
            "FF".repeat(32),
            "gg".repeat(32),
            "ab".repeat(33),
        ] {
            let mut offered = prefix(0, 1);
            offered.sha256 = sha256;
            assert!(ArtifactPlan::with_prefixes(&manifest, vec![0], vec![offered]).is_err());
        }
        let plan = ArtifactPlan::with_prefixes(&manifest, vec![0], vec![prefix(0, 1)]).unwrap();
        assert!(
            ArtifactPlan::from_request(
                "00".repeat(32),
                plan.missing_files,
                plan.prefixes,
                &manifest,
            )
            .is_err()
        );
    }

    #[test]
    fn artifact_prefix_metadata_is_bounded_below_one_control_record() {
        let manifest = ArtifactManifest::new(
            (0..MAX_ARTIFACT_FILES)
                .map(|index| SourceFile {
                    path: format!("artifact-{index:05}"),
                    len: 2,
                    sha256: Sha256::digest(b"ab").into(),
                    executable: false,
                })
                .collect(),
        )
        .unwrap();
        let missing = ArtifactPlan::all(&manifest).unwrap().missing_files;
        let mut offers = Vec::new();
        let mut bytes = 2;
        let next = loop {
            let offered = prefix(u16::try_from(offers.len()).unwrap(), 1);
            let added =
                serde_json::to_vec(&offered).unwrap().len() + usize::from(!offers.is_empty());
            if bytes + added > MAX_ARTIFACT_PREFIX_HINT_BYTES {
                break offered;
            }
            bytes += added;
            offers.push(offered);
        };
        assert!(offers.len() < MAX_ARTIFACT_FILES);
        assert_eq!(serde_json::to_vec(&offers).unwrap().len(), bytes);
        let plan = ArtifactPlan::with_prefixes(&manifest, missing.clone(), offers.clone()).unwrap();
        let record = serde_json::to_vec(&Message::ReceiveArtifacts {
            manifest_sha256: plan.manifest_sha256,
            missing_files: plan.missing_files,
            prefixes: plan.prefixes,
            file_index: 0,
            offset: 0,
        })
        .unwrap();
        assert!(record.len() < MAX_JSON_RECORD);
        offers.push(next);
        let error = ArtifactPlan::with_prefixes(&manifest, missing, offers).unwrap_err();
        assert!(error.to_string().contains("metadata bound"), "{error}");
    }

    #[test]
    fn artifact_plan_reuse_does_not_waive_complete_manifest_identity() {
        let original = manifest();
        let identity = encode_hex(&original.digest());
        for missing in [vec![], vec![0], vec![0, 2]] {
            for corrupt in ["00".repeat(32), "ff".repeat(31), "FF".repeat(32)] {
                assert!(
                    ArtifactPlan::from_request(corrupt, missing.clone(), vec![], &original)
                        .is_err()
                );
            }
            // A reused file's bytes, path, length and mode remain part of the
            // complete identity even when the request sends none of its bytes.
            for changed in 0..4 {
                let mut files = original.files().to_vec();
                match changed {
                    0 => files[2].sha256 = Sha256::digest(b"new").into(),
                    1 => files[2].path = "another-program".into(),
                    2 => files[2].executable = false,
                    _ => files[2].len += 1,
                }
                let different = ArtifactManifest::new(files).unwrap();
                assert!(
                    ArtifactPlan::from_request(
                        identity.clone(),
                        missing.clone(),
                        vec![],
                        &different,
                    )
                    .is_err()
                );
            }
        }
    }

    #[test]
    fn artifact_resume_cursors_select_only_incomplete_payloads_or_the_complete_tree() {
        let manifest = manifest();
        let all = ArtifactPlan::all(&manifest).unwrap();
        for (index, offset) in [(0, 0), (0, 3), (2, 0), (2, 2), (3, 0)] {
            all.validate_cursor(&manifest, index, offset).unwrap();
        }
        for (index, offset) in [
            (0, 4),
            (0, u64::MAX),
            (1, 0),
            (2, 3),
            (3, 1),
            (4, 0),
            (u32::MAX, 0),
        ] {
            assert!(
                all.validate_cursor(&manifest, index, offset).is_err(),
                "accepted cursor {index}:{offset}",
            );
        }

        // Reused members cannot become payloads on reattachment. The original
        // selected file may resume partway through, or have finished entirely.
        let reused = ArtifactPlan::new(&manifest, vec![2]).unwrap();
        assert!(reused.validate_cursor(&manifest, 0, 0).is_err());
        reused.validate_cursor(&manifest, 2, 1).unwrap();
        reused.validate_cursor(&manifest, 3, 0).unwrap();
        let reused_all = ArtifactPlan::new(&manifest, vec![]).unwrap();
        assert!(reused_all.validate_cursor(&manifest, 2, 0).is_err());
        reused_all.validate_cursor(&manifest, 3, 0).unwrap();

        // A tree of empty files still has one terminal cursor, not an
        // arbitrary offset that could authorize an unlisted payload.
        let empty = ArtifactManifest::new(vec![SourceFile {
            path: "empty".into(),
            len: 0,
            sha256: Sha256::digest([]).into(),
            executable: false,
        }])
        .unwrap();
        let plan = ArtifactPlan::all(&empty).unwrap();
        plan.validate_cursor(&empty, 1, 0).unwrap();
        assert!(plan.validate_cursor(&empty, 0, 0).is_err());
        assert!(plan.validate_cursor(&empty, 1, 1).is_err());
        assert!(plan.validate_cursor(&empty, 2, 0).is_err());
    }

    #[test]
    fn retained_artifact_cursor_is_independent_of_optional_original_prefix_offers() {
        let manifest = manifest();
        let offers = vec![prefix(0, 3), prefix(2, 1)];
        let plan = ArtifactPlan::with_prefixes(&manifest, vec![0, 2], offers.clone()).unwrap();
        // An untouched file still starts at zero until the sender chooses the
        // hint. A rejected hint can leave fewer accepted bytes; a selected one
        // can subsequently advance beyond its offered prefix on the same live
        // receiver. None of these frontiers rewrites the immutable offer list.
        for (index, offset) in [(0, 0), (0, 1), (0, 3), (2, 0), (2, 2), (3, 0)] {
            plan.validate_cursor(&manifest, index, offset).unwrap();
        }
        assert_eq!(plan.prefixes, offers);
        for (index, offset) in [(0, 4), (1, 0), (2, 3), (3, 1), (4, 0)] {
            assert!(plan.validate_cursor(&manifest, index, offset).is_err());
        }
    }

    #[test]
    fn maximum_artifact_plan_is_compact_even_for_large_manifest_paths() {
        let manifest = ArtifactManifest::new(
            (0..MAX_ARTIFACT_FILES)
                .map(|index| SourceFile {
                    path: format!("{index:05}/{}", "a".repeat(384)),
                    len: 1,
                    sha256: Sha256::digest(b"x").into(),
                    executable: false,
                })
                .collect(),
        )
        .unwrap();
        let plan = ArtifactPlan::all(&manifest).unwrap();
        assert_eq!(plan.missing_files.len(), MAX_ARTIFACT_FILES);
        assert_eq!(plan.missing_files.first(), Some(&0));
        assert_eq!(
            usize::from(*plan.missing_files.last().unwrap()),
            MAX_ARTIFACT_FILES - 1,
        );
        // The wire carries indexes rather than repeating the paged paths.
        let bytes = serde_json::to_vec(&Message::ReceiveArtifacts {
            manifest_sha256: plan.manifest_sha256,
            missing_files: plan.missing_files,
            prefixes: plan.prefixes,
            file_index: 0,
            offset: 0,
        })
        .unwrap();
        assert!(bytes.len() < 100 * 1024);
        assert!(bytes.len() < MAX_JSON_RECORD);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use asupersync::io::ReadBuf;
    use serde_json::json;
    use std::pin::Pin;
    use std::sync::Arc;
    use std::sync::atomic::AtomicUsize;
    use std::task::{Context, Waker};

    struct MemoryStream {
        input: Vec<u8>,
        offset: usize,
        quantum: usize,
        eof: bool,
        reads: Arc<AtomicUsize>,
        output: Vec<u8>,
        write_gate: Option<Arc<AtomicBool>>,
        write_prefix: usize,
    }

    impl MemoryStream {
        fn new(input: Vec<u8>, quantum: usize) -> Self {
            Self {
                input,
                offset: 0,
                quantum,
                eof: true,
                reads: Arc::new(AtomicUsize::new(0)),
                output: Vec::new(),
                write_gate: None,
                write_prefix: usize::MAX,
            }
        }
    }

    impl AsyncRead for MemoryStream {
        fn poll_read(
            self: Pin<&mut Self>,
            _: &mut Context<'_>,
            output: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            let stream = self.get_mut();
            stream.reads.fetch_add(1, Ordering::Relaxed);
            if stream.offset == stream.input.len() && !stream.eof {
                // Deliberately supply no wakeup. The controller's own timer
                // must observe stop/deadline without assistance from its peer.
                return Poll::Pending;
            }
            let count = output
                .remaining()
                .min(stream.quantum)
                .min(stream.input.len() - stream.offset);
            output.put_slice(&stream.input[stream.offset..stream.offset + count]);
            stream.offset += count;
            Poll::Ready(Ok(()))
        }
    }

    impl AsyncWrite for MemoryStream {
        fn poll_write(
            self: Pin<&mut Self>,
            _: &mut Context<'_>,
            bytes: &[u8],
        ) -> Poll<io::Result<usize>> {
            let stream = self.get_mut();
            let allowed = if stream
                .write_gate
                .as_ref()
                .is_some_and(|open| !open.load(Ordering::Acquire))
            {
                stream.write_prefix.saturating_sub(stream.output.len())
            } else {
                usize::MAX
            };
            if allowed == 0 {
                return Poll::Pending;
            }
            let count = bytes.len().min(3).min(allowed);
            stream.output.extend_from_slice(&bytes[..count]);
            Poll::Ready(Ok(count))
        }

        fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }

        fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            self.poll_flush(cx)
        }
    }

    fn ready<T>(future: impl Future<Output = T>) -> T {
        let mut future = pin!(future);
        let mut context = Context::from_waker(Waker::noop());
        for _ in 0..100_000 {
            if let Poll::Ready(value) = future.as_mut().poll(&mut context) {
                return value;
            }
        }
        panic!("deterministic remote record did not settle");
    }

    fn native_timer_test(future: impl Future<Output = ()> + Send + 'static) {
        let runtime = asupersync::runtime::RuntimeBuilder::current_thread()
            .build()
            .unwrap();
        let handle = runtime.handle();
        rabs_asupersync::daemon_runtime::block_on_top_level(&runtime, async move {
            handle
                .spawn(async move {
                    asupersync::time::timeout(
                        runtime_transport_now(),
                        Duration::from_secs(2),
                        future,
                    )
                    .await
                    .expect("wire cancellation/deadline failed to wake idle I/O");
                })
                .await
        });
    }

    fn record(message: &Message) -> Vec<u8> {
        let mut bytes = serde_json::to_vec(message).unwrap();
        bytes.push(b'\n');
        bytes
    }

    fn operation_token() -> OperationToken {
        OperationToken::from_native(&ResumableToken {
            request: BuildOperationId(u128::MAX),
            subscriber: SubscriberId(1),
            issued_by_incarnation: 0x0123_4567_89ab_cdef_fedc_ba98_7654_3210,
            secret: [0xab; 32],
        })
    }

    fn source_manifest() -> SourceManifest {
        SourceManifest::new(vec![
            SourceFile {
                path: "src/lib.rs".into(),
                len: 1,
                sha256: Sha256::digest(b"x").into(),
                executable: false,
            },
            SourceFile {
                path: "empty".into(),
                len: 0,
                sha256: Sha256::digest([]).into(),
                executable: false,
            },
            SourceFile {
                path: "Cargo.toml".into(),
                len: 1,
                sha256: Sha256::digest(b"m").into(),
                executable: false,
            },
        ])
        .unwrap()
    }

    #[test]
    fn operation_tokens_keep_native_identity_and_refuse_ambiguous_credentials() {
        let token = operation_token();
        let native = token.native().unwrap();
        assert_eq!(native.request, BuildOperationId(u128::MAX));
        assert_eq!(native.subscriber, SubscriberId(1));
        assert_eq!(
            native.issued_by_incarnation,
            0x0123_4567_89ab_cdef_fedc_ba98_7654_3210,
        );
        assert_eq!(native.secret, [0xab; 32]);
        assert_eq!(OperationToken::from_native(&native), token);
        let encoded = serde_json::to_vec(&token).unwrap();
        let decoded: OperationToken = serde_json::from_slice(&encoded).unwrap();
        assert_eq!(decoded.native().unwrap(), native);

        for field in ["operation", "incarnation"] {
            for invalid in [
                String::new(),
                "00".repeat(16),
                "ff".repeat(15),
                "ff".repeat(17),
                "f".repeat(31),
                "FF".repeat(16),
                "gg".repeat(16),
            ] {
                let mut value = serde_json::to_value(&token).unwrap();
                value[field] = json!(invalid);
                let changed: OperationToken = serde_json::from_value(value).unwrap();
                assert!(changed.validate().is_err(), "accepted {field}={invalid:?}");
            }
        }
        for invalid in [
            String::new(),
            "00".repeat(32),
            "ab".repeat(31),
            "ab".repeat(33),
            "a".repeat(63),
            "AB".repeat(32),
            "gg".repeat(32),
        ] {
            let mut changed = token.clone();
            changed.secret = invalid;
            assert!(changed.validate().is_err());
        }
        for field in ["subscriber", "peer", "root", "extra"] {
            let mut value = serde_json::to_value(&token).unwrap();
            value[field] = json!(1);
            assert!(serde_json::from_value::<OperationToken>(value).is_err());
        }
        for field in ["operation", "incarnation", "secret"] {
            let mut value = serde_json::to_value(&token).unwrap();
            value[field] = json!(1);
            assert!(serde_json::from_value::<OperationToken>(value).is_err());
            let duplicate = format!(
                "{{\"{field}\":\"00\",{}",
                &String::from_utf8(encoded.clone()).unwrap()[1..],
            );
            assert!(serde_json::from_str::<OperationToken>(&duplicate).is_err());
        }
    }

    #[test]
    fn operation_token_and_recovery_message_debug_output_redact_the_bearer_secret() {
        let token = operation_token();
        let debug = format!("{token:?}");
        assert!(debug.contains("[redacted]"));
        assert!(!debug.contains(&token.secret));
        assert!(debug.contains(&token.operation));
        assert!(debug.contains(&token.incarnation));
        for message in [
            Message::Ready {
                toolchain: ToolchainDisposition::Reuse,
                source: SourcePlan::all(&source_manifest()).unwrap(),
                resume: token.clone(),
            },
            Message::Resume {
                version: WIRE_VERSION.into(),
                build_identity: "service-build".into(),
                require_release: false,
                token: token.clone(),
                stdout_offset: 17,
                stderr_offset: 29,
            },
            Message::CancelOperation {
                version: WIRE_VERSION.into(),
                build_identity: "service-build".into(),
                require_release: false,
                token: token.clone(),
            },
        ] {
            let debug = format!("{message:?}");
            assert!(debug.contains("[redacted]"));
            assert!(!debug.contains(&token.secret));
            // The authenticated wire still carries the exact credential;
            // redaction changes diagnostics, never authentication semantics.
            let encoded = serde_json::to_string(&message).unwrap();
            assert!(encoded.contains(&token.secret));
            let decoded: Message = serde_json::from_str(&encoded).unwrap();
            assert_eq!(serde_json::to_string(&decoded).unwrap(), encoded);
        }
    }

    #[test]
    fn local_errors_never_authorize_reattachment_on_a_healthy_connection() {
        let wire = Wire::new(MemoryStream::new(Vec::new(), 3));
        for kind in [
            io::ErrorKind::ConnectionReset,
            io::ErrorKind::ConnectionAborted,
            io::ErrorKind::BrokenPipe,
            io::ErrorKind::UnexpectedEof,
            io::ErrorKind::TimedOut,
            io::ErrorKind::NotConnected,
            io::ErrorKind::Interrupted,
            io::ErrorKind::InvalidData,
            io::ErrorKind::PermissionDenied,
        ] {
            // Filesystem/output errors can have the same kinds as a lost
            // socket. Only an error from this actual wire can permit recovery.
            assert!(!wire.can_resume_after(&io::Error::new(kind, "local failure")));
        }
    }

    #[test]
    fn fragmented_and_coalesced_records_keep_the_exact_next_phase() {
        let mut bytes = record(&Message::Queued {});
        bytes.extend(record(&Message::Ready {
            toolchain: ToolchainDisposition::Reuse,
            source: SourcePlan::all(&source_manifest()).unwrap(),
            resume: operation_token(),
        }));
        bytes.extend(record(&Message::Window { count: 4 }));
        bytes.extend(record(&Message::Complete { exit_code: 0 }));
        for quantum in [1, 3, 16 * 1024] {
            let mut stream = MemoryStream::new(bytes.clone(), quantum);
            let mut buffered = Vec::new();
            assert!(matches!(
                ready(read_record(&mut stream, &mut buffered)).unwrap(),
                Message::Queued {}
            ));
            assert!(matches!(
                ready(read_record(&mut stream, &mut buffered)).unwrap(),
                Message::Ready {
                    toolchain: ToolchainDisposition::Reuse,
                    ..
                }
            ));
            assert!(matches!(
                ready(read_record(&mut stream, &mut buffered)).unwrap(),
                Message::Window { count: 4 }
            ));
            assert!(matches!(
                ready(read_record(&mut stream, &mut buffered)).unwrap(),
                Message::Complete { exit_code: 0 }
            ));
            assert!(buffered.is_empty());
            if quantum == 16 * 1024 {
                assert_eq!(stream.reads.load(Ordering::Relaxed), 1);
            }
        }
    }

    #[test]
    fn record_boundary_allows_the_delimiter_but_refuses_oversize_and_partial_eof() {
        let payload = serde_json::to_vec(&Message::Poll {}).unwrap();
        for (length, accepted) in [(MAX_JSON_RECORD, true), (MAX_JSON_RECORD + 1, false)] {
            let mut bytes = payload.clone();
            bytes.resize(length, b' ');
            bytes.push(b'\n');
            let mut stream = MemoryStream::new(bytes, usize::MAX);
            let mut buffered = Vec::new();
            let result = ready(read_record(&mut stream, &mut buffered));
            if accepted {
                assert!(matches!(result.unwrap(), Message::Poll {}));
            } else {
                assert_eq!(result.unwrap_err().kind(), io::ErrorKind::InvalidData);
                assert!(buffered.len() <= MAX_JSON_RECORD + 1);
            }
        }
        for bytes in [Vec::new(), payload, br#"{"kind":"po"#.to_vec()] {
            let mut stream = MemoryStream::new(bytes, 3);
            assert_eq!(
                ready(read_record(&mut stream, &mut Vec::new()))
                    .unwrap_err()
                    .kind(),
                io::ErrorKind::UnexpectedEof
            );
        }
    }

    #[test]
    fn continuously_ready_fragments_yield_before_starving_the_controller() {
        let mut bytes = serde_json::to_vec(&Message::Poll {}).unwrap();
        bytes.resize(4 * READS_BEFORE_YIELD, b' ');
        bytes.push(b'\n');
        let mut stream = MemoryStream::new(bytes, 1);
        let reads = Arc::clone(&stream.reads);
        let mut buffered = Vec::new();
        let mut future = pin!(read_record(&mut stream, &mut buffered));
        let mut context = Context::from_waker(Waker::noop());
        assert!(future.as_mut().poll(&mut context).is_pending());
        assert_eq!(reads.load(Ordering::Relaxed), READS_BEFORE_YIELD);
        assert!(matches!(ready(future), Ok(Message::Poll {})));
    }

    #[test]
    fn retained_write_continues_after_multiple_control_ticks_without_duplicate_prefix() {
        native_timer_test(async {
            let gate = Arc::new(AtomicBool::new(false));
            let release = Arc::clone(&gate);
            let setter = std::thread::spawn(move || {
                std::thread::sleep(Duration::from_millis(230));
                release.store(true, Ordering::Release);
            });
            let mut stream = MemoryStream::new(Vec::new(), 3);
            stream.write_gate = Some(gate);
            stream.write_prefix = 5;
            let mut wire = Wire::new(stream);
            let message = Message::Window { count: 17 };
            wire.send(
                &message,
                &AtomicBool::new(false),
                Instant::now() + Duration::from_secs(1),
            )
            .await
            .unwrap();
            setter.join().unwrap();
            assert_eq!(wire.stream.output, record(&message));
        });
    }

    #[test]
    fn atomic_stop_wakes_stalled_partial_read_and_write_without_a_peer_event() {
        native_timer_test(async {
            for writing in [false, true] {
                let stopped = Arc::new(AtomicBool::new(false));
                let stop = Arc::clone(&stopped);
                let setter = std::thread::spawn(move || {
                    std::thread::sleep(Duration::from_millis(25));
                    stop.store(true, Ordering::Release);
                });
                let prefix = br#"{"kind":"#.to_vec();
                let mut stream = MemoryStream::new(prefix.clone(), 3);
                stream.eof = false;
                stream.write_gate = Some(Arc::new(AtomicBool::new(false)));
                stream.write_prefix = 5;
                let mut wire = Wire::new(stream);
                let deadline = Instant::now() + Duration::from_secs(60);
                let error = if writing {
                    wire.send(&Message::Poll {}, &stopped, deadline)
                        .await
                        .unwrap_err()
                } else {
                    wire.receive_until(&stopped, deadline).await.unwrap_err()
                };
                setter.join().unwrap();
                assert_eq!(error.kind(), io::ErrorKind::Interrupted);
                assert!(!wire.can_resume_after(&error));
                if writing {
                    assert_eq!(wire.stream.output, record(&Message::Poll {})[..5]);
                } else {
                    assert_eq!(wire.buffered, prefix);
                }
            }
        });
    }

    #[test]
    fn whole_phase_wait_expires_at_its_fixed_deadline_without_peer_wakeups() {
        native_timer_test(async {
            let mut stream = MemoryStream::new(Vec::new(), 1);
            stream.eof = false;
            let mut wire = Wire::new(stream);
            let error = wire
                .receive_until(
                    &AtomicBool::new(false),
                    Instant::now() + Duration::from_millis(30),
                )
                .await
                .unwrap_err();
            assert_eq!(error.kind(), io::ErrorKind::TimedOut);
            assert!(wire.can_resume_after(&error));
        });
    }

    #[test]
    fn failed_partial_io_never_resumes_when_error_reporting_or_the_peer_recovers() {
        native_timer_test(async {
            for writing in [false, true] {
                for cancelled in [false, true] {
                    let stopped = Arc::new(AtomicBool::new(false));
                    let setter = cancelled.then(|| {
                        let stop = Arc::clone(&stopped);
                        std::thread::spawn(move || {
                            std::thread::sleep(Duration::from_millis(25));
                            stop.store(true, Ordering::Release);
                        })
                    });
                    let gate = Arc::new(AtomicBool::new(false));
                    let mut stream = MemoryStream::new(br#"{"kind":"#.to_vec(), 3);
                    stream.eof = false;
                    stream.write_gate = Some(Arc::clone(&gate));
                    stream.write_prefix = 5;
                    let mut wire = Wire::new(stream);
                    let deadline = Instant::now()
                        + if cancelled {
                            Duration::from_secs(1)
                        } else {
                            Duration::from_millis(30)
                        };
                    let error = if writing {
                        wire.send(
                            &Message::Commit {
                                manifest_sha256: "11".repeat(32),
                            },
                            &stopped,
                            deadline,
                        )
                        .await
                        .unwrap_err()
                    } else {
                        wire.receive_until(&stopped, deadline).await.unwrap_err()
                    };
                    if let Some(setter) = setter {
                        setter.join().unwrap();
                    }
                    assert_eq!(
                        error.kind(),
                        if cancelled {
                            io::ErrorKind::Interrupted
                        } else {
                            io::ErrorKind::TimedOut
                        }
                    );
                    assert_eq!(wire.can_resume_after(&error), !cancelled);
                    let written = wire.stream.output.clone();
                    let reads = wire.stream.reads.load(Ordering::Relaxed);
                    if writing {
                        assert_eq!(written.len(), 5);
                    } else {
                        assert!(!wire.buffered.is_empty());
                    }

                    // A fresh budget, cleared cancellation and ready peer must
                    // not let generic Failure reporting flush the stale Commit.
                    stopped.store(false, Ordering::Release);
                    gate.store(true, Ordering::Release);
                    wire.stream.input = record(&Message::Ready {
                        toolchain: ToolchainDisposition::Upload,
                        source: SourcePlan::all(&source_manifest()).unwrap(),
                        resume: operation_token(),
                    });
                    wire.stream.offset = 0;
                    wire.stream.eof = true;
                    let deadline = Instant::now() + Duration::from_secs(1);
                    assert!(
                        wire.send(
                            &Message::Failure {
                                message: "operation aborted".into(),
                            },
                            &stopped,
                            deadline,
                        )
                        .await
                        .is_err()
                    );
                    assert!(wire.receive_until(&stopped, deadline).await.is_err());
                    assert!(wire.receive(&stopped, deadline).await.is_err());
                    assert_eq!(wire.stream.output, written);
                    assert_eq!(wire.stream.reads.load(Ordering::Relaxed), reads);
                }
            }
        });
    }

    #[test]
    fn peer_failure_cancel_malformed_record_and_eof_are_terminal() {
        native_timer_test(async {
            for first in [
                record(&Message::Failure {
                    message: "refused".into(),
                }),
                record(&Message::Cancel {}),
                b"{invalid}\n".to_vec(),
                Vec::new(),
            ] {
                let is_transport_failure = first.is_empty();
                let mut wire = Wire::new(MemoryStream::new(first, 3));
                let stopped = AtomicBool::new(false);
                let deadline = Instant::now() + Duration::from_secs(1);
                let error = wire.receive_until(&stopped, deadline).await.unwrap_err();
                assert_eq!(wire.can_resume_after(&error), is_transport_failure);
                let reads = wire.stream.reads.load(Ordering::Relaxed);
                wire.stream.input = record(&Message::Ready {
                    toolchain: ToolchainDisposition::Upload,
                    source: SourcePlan::all(&source_manifest()).unwrap(),
                    resume: operation_token(),
                });
                wire.stream.offset = 0;
                assert!(wire.receive_until(&stopped, deadline).await.is_err());
                assert!(
                    wire.send(&Message::Poll {}, &stopped, deadline)
                        .await
                        .is_err()
                );
                assert_eq!(wire.stream.reads.load(Ordering::Relaxed), reads);
                assert!(wire.stream.output.is_empty());
            }
        });
    }

    #[test]
    fn wire_refuses_duplicate_unknown_and_host_control_fields() {
        for bytes in [
            br#"{"kind":"poll","extra":1}"#.as_slice(),
            br#"{"kind":"queued","position":1}"#,
            br#"{"kind":"queued","kind":"ready"}"#,
            br#"{"kind":"ready"}"#,
            br#"{"kind":"ready","toolchain":"unknown"}"#,
            br#"{"kind":"ready","toolchain":"reuse","toolchain":"upload"}"#,
            br#"{"kind":"ready","toolchain":"reuse","toolchain_root":"/server/sdk"}"#,
            br#"{"kind":"window","count":1,"count":2}"#,
            br#"{"kind":"source-chunk","chunk":{"path":"x","offset":0,"sha256":"","bytes":"","source_root":"/"}}"#,
        ] {
            assert!(serde_json::from_slice::<Message>(bytes).is_err());
        }
        let ready = serde_json::to_value(Message::Ready {
            toolchain: ToolchainDisposition::Reuse,
            source: SourcePlan::all(&source_manifest()).unwrap(),
            resume: operation_token(),
        })
        .unwrap();
        let mut missing_resume = ready.clone();
        missing_resume.as_object_mut().unwrap().remove("resume");
        assert!(serde_json::from_value::<Message>(missing_resume).is_err());
        for field in ["toolchain_root", "source_root", "peer", "extra"] {
            let mut value = ready.clone();
            value[field] = json!("/not-an-input-capability");
            assert!(serde_json::from_value::<Message>(value).is_err());
        }
        let settings = json!({"state_root":"/server/state"});
        assert!(serde_json::from_value::<RemoteOperationSettings>(settings).is_err());
    }

    #[test]
    fn field_less_messages_keep_their_exact_wire_bytes() {
        // Empty struct variants exist only so deny_unknown_fields applies;
        // peers built before that change exchange the identical records.
        for (message, bytes) in [
            (Message::Queued {}, r#"{"kind":"queued"}"#),
            (Message::ResumePending {}, r#"{"kind":"resume-pending"}"#),
            (Message::Cancelled {}, r#"{"kind":"cancelled"}"#),
            (Message::InputsDone {}, r#"{"kind":"inputs-done"}"#),
            (Message::Accepted {}, r#"{"kind":"accepted"}"#),
            (
                Message::ToolchainFilesEnd {},
                r#"{"kind":"toolchain-files-end"}"#,
            ),
            (
                Message::ToolchainFilesDecline {},
                r#"{"kind":"toolchain-files-decline"}"#,
            ),
            (
                Message::ToolchainFilesDeclined {},
                r#"{"kind":"toolchain-files-declined"}"#,
            ),
            (Message::Poll {}, r#"{"kind":"poll"}"#),
            (Message::ReceiveTarget {}, r#"{"kind":"receive-target"}"#),
            (
                Message::ArtifactManifestEnd {},
                r#"{"kind":"artifact-manifest-end"}"#,
            ),
            (Message::ArtifactEnd {}, r#"{"kind":"artifact-end"}"#),
            (Message::Delivered {}, r#"{"kind":"delivered"}"#),
            (Message::Close {}, r#"{"kind":"close"}"#),
            (Message::Cancel {}, r#"{"kind":"cancel"}"#),
        ] {
            assert_eq!(serde_json::to_string(&message).unwrap(), bytes);
            let decoded: Message = serde_json::from_str(bytes).unwrap();
            assert_eq!(serde_json::to_string(&decoded).unwrap(), bytes);
            let extra = format!("{},\"extra\":1}}", &bytes[..bytes.len() - 1]);
            assert!(serde_json::from_str::<Message>(&extra).is_err(), "{extra}");
        }
    }

    #[test]
    fn ready_contract_carries_exact_upload_or_reuse_disposition() {
        let manifest = source_manifest();
        let plan = SourcePlan::all(&manifest).unwrap();
        let token = operation_token();
        for (spelling, expected) in [
            ("upload", ToolchainDisposition::Upload),
            ("upload-files", ToolchainDisposition::UploadFiles),
            ("reuse", ToolchainDisposition::Reuse),
        ] {
            let bytes = serde_json::to_vec(&json!({
                "kind": "ready", "toolchain": spelling, "source": plan, "resume": token
            }))
            .unwrap();
            let Message::Ready {
                toolchain,
                source,
                resume,
            } = serde_json::from_slice::<Message>(&bytes).unwrap()
            else {
                panic!("expected explicit SDK and source admission");
            };
            assert_eq!(toolchain, expected);
            assert_eq!(source, plan);
            source.validate(&manifest).unwrap();
            assert_eq!(resume, token);
            resume.validate().unwrap();
            assert_eq!(
                serde_json::to_value(Message::Ready {
                    toolchain,
                    source,
                    resume
                })
                .unwrap(),
                json!({"kind": "ready", "toolchain": spelling, "source": plan, "resume": token})
            );
        }
    }

    #[test]
    fn sdk_file_pages_preserve_native_identities_and_reject_unbounded_names() {
        let files = vec![
            ToolchainFile {
                path: "bin/rustc".into(),
                bytes: 9,
                executable: true,
                sha256: Sha256::digest(b"compiler!").into(),
            },
            ToolchainFile {
                path: "lib/empty".into(),
                bytes: 0,
                executable: false,
                sha256: Sha256::digest([]).into(),
            },
        ];
        let page = ToolchainFilePage::from_native(7, &files).unwrap();
        assert_eq!(page.native().unwrap(), files);
        let message = Message::ToolchainFilePage { page: page.clone() };
        let encoded = serde_json::to_vec(&message).unwrap();
        let Message::ToolchainFilePage { page: decoded } =
            serde_json::from_slice(&encoded).unwrap()
        else {
            panic!("SDK page roundtrip changed its phase")
        };
        assert_eq!(decoded.first, 7);
        assert_eq!(decoded.native().unwrap(), files);
        for path in [
            "",
            "../rustc",
            "bin//rustc",
            "/bin/rustc",
            "bin/./rustc",
            "C:/rustc",
            "bin\\rustc",
            "bin/rustc\n",
        ] {
            let mut changed = files.clone();
            changed[0].path = path.into();
            assert!(
                ToolchainFilePage::from_native(0, &changed).is_err(),
                "{path:?}"
            );
        }
        assert!(ToolchainFilePage::from_native(0, &[]).is_err());
        assert!(ToolchainFilePage::from_native(u32::MAX as usize, &files).is_err());
        let mut reversed = files.clone();
        reversed.reverse();
        assert!(ToolchainFilePage::from_native(0, &reversed).is_err());
        let mut forged = serde_json::to_value(message).unwrap();
        forged["page"]["files"][0]["sha256"] = json!("FF".repeat(32));
        let Message::ToolchainFilePage { page: forged } = serde_json::from_value(forged).unwrap()
        else {
            unreachable!()
        };
        assert!(forged.native().is_err());
    }

    #[test]
    fn sdk_file_plan_binds_its_page_and_exact_incomplete_ranges() {
        let files = vec![
            ToolchainFile {
                path: "a".into(),
                bytes: 10,
                executable: false,
                sha256: Sha256::digest(b"0123456789").into(),
            },
            ToolchainFile {
                path: "b".into(),
                bytes: 0,
                executable: false,
                sha256: Sha256::digest([]).into(),
            },
            ToolchainFile {
                path: "c".into(),
                bytes: 7,
                executable: true,
                sha256: Sha256::digest(b"compile").into(),
            },
        ];
        let page = ToolchainFilePage::from_native(10, &files).unwrap();
        let plan = ToolchainFilePlan {
            first: 10,
            missing_files: vec![10, 12],
            prefixes: vec![ToolchainPrefixOffer {
                index: 12,
                offset: 3,
                sha256: encode_hex(&Sha256::digest(b"com")),
            }],
        };
        plan.validate(&page).unwrap();
        ToolchainFilePlan {
            first: 10,
            missing_files: vec![],
            prefixes: vec![],
        }
        .validate(&page)
        .unwrap();
        for missing in [
            vec![9],
            vec![13],
            vec![11],
            vec![12, 10],
            vec![10, 10],
            vec![10],
        ] {
            let mut changed = plan.clone();
            changed.missing_files = missing;
            assert!(changed.validate(&page).is_err());
        }
        for offset in [0, 7, u64::MAX] {
            let mut changed = plan.clone();
            changed.prefixes[0].offset = offset;
            assert!(changed.validate(&page).is_err());
        }
        let mut changed = plan.clone();
        changed.first = 0;
        assert!(changed.validate(&page).is_err());
        let mut changed = plan.clone();
        changed.prefixes.push(changed.prefixes[0].clone());
        assert!(changed.validate(&page).is_err());
        let mut changed = plan;
        changed.prefixes[0].sha256 = "00".repeat(31);
        assert!(changed.validate(&page).is_err());
    }

    #[test]
    fn source_plans_bind_canonical_manifest_members_and_refuse_ambiguous_hints() {
        let manifest = source_manifest();
        assert_eq!(
            manifest
                .files()
                .iter()
                .map(|file| file.path.as_str())
                .collect::<Vec<_>>(),
            ["Cargo.toml", "empty", "src/lib.rs"],
        );
        let all = SourcePlan::all(&manifest).unwrap();
        assert_eq!(all.missing_files, [0, 2]);
        assert_eq!(all.manifest_sha256, encode_hex(&manifest.digest()));
        SourcePlan::new(&manifest, Vec::new()).unwrap();
        SourcePlan::new(&manifest, vec![0]).unwrap();
        SourcePlan::new(&manifest, vec![2]).unwrap();
        for missing in [
            vec![0, 0],
            vec![2, 0],
            vec![1],
            vec![3],
            vec![u16::MAX],
            vec![0; MAX_SOURCE_FILES + 1],
        ] {
            assert!(SourcePlan::new(&manifest, missing).is_err());
        }
        for digest in ["00".repeat(32), "ff".repeat(31), "FF".repeat(32)] {
            let mut plan = all.clone();
            plan.manifest_sha256 = digest;
            assert!(plan.validate(&manifest).is_err());
        }
        for changed in 0..4 {
            let mut files = manifest.files().to_vec();
            match changed {
                0 => files[0].sha256 = Sha256::digest(b"changed").into(),
                1 => files[0].path = "Cargo.lock".into(),
                2 => files[0].executable = true,
                _ => files[0].len += 1,
            }
            let different = SourceManifest::new(files).unwrap();
            assert!(all.validate(&different).is_err());
        }
    }

    #[test]
    fn source_plan_wire_shape_refuses_unbounded_types_and_unknown_fields() {
        let valid = serde_json::to_value(SourcePlan::all(&source_manifest()).unwrap()).unwrap();
        for index in [json!(-1), json!(65536), json!("0"), json!(0.5)] {
            let mut value = valid.clone();
            value["missing_files"] = json!([index]);
            assert!(serde_json::from_value::<SourcePlan>(value).is_err());
        }
        for field in ["root", "source_root", "peer", "extra"] {
            let mut value = valid.clone();
            value[field] = json!("/not-an-input-capability");
            assert!(serde_json::from_value::<SourcePlan>(value).is_err());
        }
        let duplicate = format!(
            "{{\"manifest_sha256\":\"{}\",\"missing_files\":[],\"missing_files\":[0]}}",
            encode_hex(&source_manifest().digest()),
        );
        assert!(serde_json::from_str::<SourcePlan>(&duplicate).is_err());
        for bytes in [
            br#"{"kind":"ready","toolchain":"upload"}"#.as_slice(),
            br#"{"kind":"ready","toolchain":"reuse","source":null}"#,
            br#"{"kind":"ready","toolchain":"reuse","source":{"missing_files":[]}}"#,
        ] {
            assert!(serde_json::from_slice::<Message>(bytes).is_err());
        }
    }

    #[test]
    fn artifact_delivery_wire_requires_explicit_bounded_file_indexes() {
        let identity = "ab".repeat(32);
        let valid = json!({
            "kind":"receive-artifacts", "manifest_sha256":identity,
            "missing_files":[0, 2],
            "prefixes":[],
            "file_index":0, "offset":7,
        });
        assert!(matches!(
            serde_json::from_value::<Message>(valid.clone()).unwrap(),
            Message::ReceiveArtifacts { missing_files, file_index: 0, offset: 7, .. }
                if missing_files == [0, 2]
        ));
        for index in [json!(-1), json!(65536), json!("0"), json!(0.5)] {
            let mut value = valid.clone();
            value["missing_files"] = json!([index]);
            assert!(serde_json::from_value::<Message>(value).is_err());
        }
        for index in [
            json!(-1),
            json!(u64::from(u32::MAX) + 1),
            json!("0"),
            json!(0.5),
        ] {
            let mut value = valid.clone();
            value["file_index"] = index;
            assert!(serde_json::from_value::<Message>(value).is_err());
        }
        for offset in [json!(-1), json!("0"), json!(0.5)] {
            let mut value = valid.clone();
            value["offset"] = offset;
            assert!(serde_json::from_value::<Message>(value).is_err());
        }
        for field in [
            "manifest_sha256",
            "missing_files",
            "prefixes",
            "file_index",
            "offset",
        ] {
            let mut value = valid.clone();
            value.as_object_mut().unwrap().remove(field);
            assert!(serde_json::from_value::<Message>(value).is_err());
        }
        for field in ["path", "root", "extra"] {
            let mut value = valid.clone();
            value[field] = json!("/not-a-path-capability");
            assert!(serde_json::from_value::<Message>(value).is_err());
        }
        assert!(
            serde_json::from_value::<Message>(json!({
                "kind":"receive-artifacts", "manifest_sha256":identity,
            }))
            .is_err()
        );
        let duplicate = format!(
            "{{\"kind\":\"receive-artifacts\",\"manifest_sha256\":\"{identity}\",\"missing_files\":[],\"missing_files\":[0],\"prefixes\":[],\"file_index\":0,\"offset\":0}}"
        );
        assert!(serde_json::from_str::<Message>(&duplicate).is_err());
    }

    #[test]
    fn artifact_delivery_wire_requires_explicit_typed_prefix_offers() {
        let identity = "ab".repeat(32);
        let valid = json!({
            "kind":"receive-artifacts", "manifest_sha256":identity,
            "missing_files":[0],
            "prefixes":[{"index":0,"offset":1,"sha256":identity}],
            "file_index":0, "offset":0,
        });
        assert!(matches!(
            serde_json::from_value::<Message>(valid.clone()).unwrap(),
            Message::ReceiveArtifacts { prefixes, .. }
                if prefixes.len() == 1 && prefixes[0].index == 0 && prefixes[0].offset == 1
        ));
        for field in ["index", "offset", "sha256"] {
            let mut value = valid.clone();
            value["prefixes"][0].as_object_mut().unwrap().remove(field);
            assert!(serde_json::from_value::<Message>(value).is_err());
        }
        for (field, invalid) in [
            ("index", json!(-1)),
            ("index", json!(65536)),
            ("index", json!("0")),
            ("offset", json!(-1)),
            ("offset", json!(0.5)),
            ("offset", json!("1")),
            ("sha256", json!(vec![0; 32])),
            ("path", json!("/untrusted")),
        ] {
            let mut value = valid.clone();
            value["prefixes"][0][field] = invalid;
            assert!(serde_json::from_value::<Message>(value).is_err());
        }
        for prefixes in [json!(null), json!({}), json!(1)] {
            let mut value = valid.clone();
            value["prefixes"] = prefixes;
            assert!(serde_json::from_value::<Message>(value).is_err());
        }
        let mut absent = valid;
        absent.as_object_mut().unwrap().remove("prefixes");
        assert!(serde_json::from_value::<Message>(absent).is_err());
        let duplicate = format!(
            "{{\"kind\":\"receive-artifacts\",\"manifest_sha256\":\"{identity}\",\"missing_files\":[0],\"prefixes\":[],\"prefixes\":[],\"file_index\":0,\"offset\":0}}"
        );
        assert!(serde_json::from_str::<Message>(&duplicate).is_err());
        let duplicate_offset = format!(
            "{{\"kind\":\"receive-artifacts\",\"manifest_sha256\":\"{identity}\",\"missing_files\":[0],\"prefixes\":[{{\"index\":0,\"offset\":1,\"offset\":2,\"sha256\":\"{identity}\"}}],\"file_index\":0,\"offset\":0}}"
        );
        assert!(serde_json::from_str::<Message>(&duplicate_offset).is_err());
    }

    #[test]
    fn maximum_source_plan_stays_compact_for_long_manifest_paths() {
        let files = (0..MAX_SOURCE_FILES)
            .map(|index| SourceFile {
                path: format!("{index:04}/{}", "x".repeat(900)),
                len: 1,
                sha256: Sha256::digest(b"x").into(),
                executable: false,
            })
            .collect();
        let manifest = SourceManifest::new(files).unwrap();
        let source = SourcePlan::all(&manifest).unwrap();
        assert_eq!(source.missing_files.len(), MAX_SOURCE_FILES);
        let bytes = serde_json::to_vec(&Message::Ready {
            toolchain: ToolchainDisposition::Reuse,
            source,
            resume: operation_token(),
        })
        .unwrap();
        assert!(bytes.len() < 24 * 1024);
        assert!(bytes.len() <= MAX_JSON_RECORD);
        let Message::Ready { source, .. } = serde_json::from_slice(&bytes).unwrap() else {
            panic!("expected source admission");
        };
        source.validate(&manifest).unwrap();
    }

    #[test]
    fn windows_refuse_overflow_duplicates_and_skipped_acknowledgments() {
        let mut window = Window::default();
        assert!(window.acknowledge(0).is_err());
        for index in 1..=WINDOW {
            assert_eq!(window.record().unwrap(), index == WINDOW);
        }
        assert!(window.record().is_err());
        assert!(window.acknowledge(WINDOW - 1).is_err());
        window.acknowledge(WINDOW).unwrap();
        assert!(window.acknowledge(WINDOW).is_err());
        assert!(!window.record().unwrap());
        window.acknowledge(WINDOW + 1).unwrap();
    }

    fn artifact_file(path: &str, bytes: &[u8]) -> SourceFile {
        SourceFile {
            path: path.into(),
            len: bytes.len() as u64,
            sha256: Sha256::digest(bytes).into(),
            executable: false,
        }
    }

    #[test]
    fn source_pages_transfer_a_large_complete_tree_under_original_frame_limits() {
        let native = SourceManifest::new(
            (0..MAX_SOURCE_FILES)
                .map(|index| SourceFile {
                    path: format!(
                        "workspace/{index:04}/{}/{}/source.rs",
                        "a".repeat(240),
                        "b".repeat(240)
                    ),
                    len: 0,
                    sha256: Sha256::digest([]).into(),
                    executable: index % 2 == 0,
                })
                .collect(),
        )
        .unwrap();
        assert!(
            serde_json::to_vec(&Manifest::from_native(&native))
                .unwrap()
                .len()
                > MAX_JSON_RECORD
        );
        let declaration = SourceDeclaration::from_native(&native);
        assert!(serde_json::to_vec(&declaration).unwrap().len() < 256);
        let mut received = SourcePages::new(declaration).unwrap();
        for (index, files) in native.files().chunks(SOURCE_PAGE_FILES).enumerate() {
            let page = SourcePage::from_native(index * SOURCE_PAGE_FILES, files).unwrap();
            let bytes = serde_json::to_vec(&Message::SourceManifestPage { page }).unwrap();
            assert!(bytes.len() < MAX_JSON_RECORD);
            let Message::SourceManifestPage { page } = serde_json::from_slice(&bytes).unwrap()
            else {
                panic!("expected a source declaration page");
            };
            received.push(page).unwrap();
        }
        assert_eq!(received.finish().unwrap(), native);
    }

    #[test]
    fn source_declarations_keep_existing_resource_and_digest_limits() {
        let valid = SourceDeclaration::from_native(&source_manifest());
        for case in 0..7 {
            let mut declaration = valid.clone();
            match case {
                0 => declaration.files = 0,
                1 => declaration.files = (MAX_SOURCE_FILES + 1) as u32,
                2 => declaration.bytes = MAX_SOURCE_BYTES + 1,
                3 => declaration.metadata_bytes = 0,
                4 => declaration.metadata_bytes = u64::MAX,
                5 => declaration.manifest_sha256 = "ab".repeat(31),
                _ => declaration.manifest_sha256 = "AB".repeat(32),
            }
            assert!(SourcePages::new(declaration).is_err(), "{case}");
        }
    }

    #[test]
    fn source_pages_refuse_reordering_unsafe_names_and_aggregate_overruns() {
        let native = source_manifest();
        for case in 0..10 {
            let mut pages = SourcePages::new(SourceDeclaration::from_native(&native)).unwrap();
            pages
                .push(SourcePage::from_native(0, &native.files()[..1]).unwrap())
                .unwrap();
            let mut page = SourcePage::from_native(1, &native.files()[1..]).unwrap();
            match case {
                0 => page.first = 0,
                1 => page.first = 2,
                2 => page.files.clear(),
                3 => page.files = vec![page.files[0].clone(); SOURCE_PAGE_FILES + 1],
                4 => page.files.reverse(),
                5 => page.files[0].path = native.files()[0].path.clone(),
                6 => page.files[0].bytes = MAX_SOURCE_BYTES,
                7 => page.files[0].path = "z".repeat(1025),
                8 => page.files[0].sha256 = "AB".repeat(32),
                _ => page.files[0].path = "src/../escape".into(),
            }
            assert!(pages.push(page).is_err(), "{case}");
        }
        let mut declaration = SourceDeclaration::from_native(&native);
        declaration.metadata_bytes = 1;
        let mut pages = SourcePages::new(declaration).unwrap();
        assert!(
            pages
                .push(SourcePage::from_native(0, native.files()).unwrap())
                .is_err()
        );
    }

    #[test]
    fn source_pages_require_complete_source_identity_and_cross_page_namespace() {
        let native = source_manifest();
        let artifact = ArtifactManifest::new(native.files().to_vec()).unwrap();
        assert_ne!(artifact.digest(), native.digest());
        for case in 0..5 {
            let mut declaration = SourceDeclaration::from_native(&native);
            let mut files = native.files().to_vec();
            match case {
                0 => declaration.manifest_sha256 = encode_hex(&artifact.digest()),
                1 => declaration.metadata_bytes += 1,
                2 => declaration.bytes += 1,
                3 => {
                    files.pop();
                }
                _ => files[0].executable = !files[0].executable,
            }
            let mut pages = SourcePages::new(declaration).unwrap();
            pages
                .push(SourcePage::from_native(0, &files).unwrap())
                .unwrap();
            assert!(pages.finish().is_err(), "{case}");
        }
        let first = artifact_file("a", b"a");
        let second = artifact_file("a/b", b"b");
        let mut declaration = SourceDeclaration::from_native(
            &SourceManifest::new(vec![first.clone(), artifact_file("b", b"b")]).unwrap(),
        );
        declaration.metadata_bytes += 2;
        let mut pages = SourcePages::new(declaration).unwrap();
        pages
            .push(SourcePage::from_native(0, &[first]).unwrap())
            .unwrap();
        pages
            .push(SourcePage::from_native(1, &[second]).unwrap())
            .unwrap();
        assert!(
            pages
                .finish()
                .unwrap_err()
                .to_string()
                .contains("also an input directory")
        );
    }

    #[test]
    fn artifact_pages_admit_large_targets_without_enlarging_source_or_record_limits() {
        let native = ArtifactManifest::new(
            (0..MAX_ARTIFACT_FILES)
                .map(|index| SourceFile {
                    path: format!("debug/deps/{index:05}-{}", "x".repeat(192)),
                    len: if index == 0 {
                        rabs_sandbox::source_transfer::MAX_SOURCE_BYTES + 1
                    } else {
                        0
                    },
                    sha256: Sha256::digest([]).into(),
                    executable: false,
                })
                .collect(),
        )
        .unwrap();
        // This checks declaration transport, not the large file's payload.
        assert!(SourceManifest::new(native.files().to_vec()).is_err());
        let declaration = ArtifactDeclaration::from_native(&native);
        assert!(serde_json::to_vec(&declaration).unwrap().len() < 256);
        let mut received = ArtifactPages::new(declaration).unwrap();
        let mut encoded_bytes = 0;
        for (index, files) in native.files().chunks(ARTIFACT_PAGE_FILES).enumerate() {
            let page = ArtifactPage::from_native(index * ARTIFACT_PAGE_FILES, files).unwrap();
            let bytes = serde_json::to_vec(&Message::ArtifactManifestPage { page }).unwrap();
            assert!(bytes.len() < MAX_JSON_RECORD);
            encoded_bytes += bytes.len();
            let Message::ArtifactManifestPage { page } = serde_json::from_slice(&bytes).unwrap()
            else {
                panic!("expected an artifact declaration page");
            };
            received.push(page).unwrap();
        }
        assert!(encoded_bytes > MAX_JSON_RECORD);
        assert_eq!(received.finish().unwrap(), native);
    }

    #[test]
    fn artifact_declarations_refuse_excessive_resources_before_accepting_pages() {
        let native = ArtifactManifest::new(vec![artifact_file("data", b"x")]).unwrap();
        let valid = ArtifactDeclaration::from_native(&native);
        for case in 0..7 {
            let mut declaration = valid.clone();
            match case {
                0 => declaration.files = 0,
                1 => declaration.files = (MAX_ARTIFACT_FILES + 1) as u32,
                2 => declaration.bytes = MAX_ARTIFACT_BYTES + 1,
                3 => declaration.metadata_bytes = 0,
                4 => declaration.metadata_bytes = MAX_ARTIFACT_MANIFEST_BYTES as u64 + 1,
                5 => declaration.manifest_sha256 = "ab".repeat(31),
                _ => declaration.manifest_sha256 = "AB".repeat(32),
            }
            assert!(ArtifactPages::new(declaration).is_err(), "{case}");
        }
    }

    #[test]
    fn artifact_pages_refuse_gaps_repeats_reordering_and_budget_overruns() {
        let native = ArtifactManifest::new(vec![
            artifact_file("a", b"a"),
            artifact_file("b", b"b"),
            artifact_file("c", b"c"),
        ])
        .unwrap();
        for case in 0..9 {
            let mut pages = ArtifactPages::new(ArtifactDeclaration::from_native(&native)).unwrap();
            pages
                .push(ArtifactPage::from_native(0, &native.files()[..1]).unwrap())
                .unwrap();
            let mut page = ArtifactPage::from_native(1, &native.files()[1..]).unwrap();
            match case {
                0 => page.first = 0,
                1 => page.first = 2,
                2 => page.files.clear(),
                3 => page.files = vec![page.files[0].clone(); ARTIFACT_PAGE_FILES + 1],
                4 => page.files.reverse(),
                5 => page.files[0].path = "a".into(),
                6 => page.files[0].bytes = MAX_ARTIFACT_BYTES,
                7 => page.files[0].path = "z".repeat(1025),
                _ => page.files[0].sha256 = "AB".repeat(32),
            }
            assert!(pages.push(page).is_err(), "{case}");
        }
        let mut declaration = ArtifactDeclaration::from_native(&native);
        declaration.metadata_bytes = 1;
        let mut pages = ArtifactPages::new(declaration).unwrap();
        assert!(
            pages
                .push(ArtifactPage::from_native(0, native.files()).unwrap())
                .is_err()
        );
    }

    #[test]
    fn artifact_pages_require_exact_domain_complete_counts_and_global_namespace() {
        let native =
            ArtifactManifest::new(vec![artifact_file("a", b"a"), artifact_file("b", b"b")])
                .unwrap();
        let source = SourceManifest::new(native.files().to_vec()).unwrap();
        assert_ne!(source.digest(), native.digest());
        for case in 0..4 {
            let mut declaration = ArtifactDeclaration::from_native(&native);
            match case {
                0 => declaration.manifest_sha256 = encode_hex(&source.digest()),
                1 => declaration.metadata_bytes += 1,
                2 => declaration.bytes += 1,
                _ => {}
            }
            let mut pages = ArtifactPages::new(declaration).unwrap();
            let files = if case == 3 {
                &native.files()[..1]
            } else {
                native.files()
            };
            pages
                .push(ArtifactPage::from_native(0, files).unwrap())
                .unwrap();
            assert!(pages.finish().is_err(), "{case}");
        }
        let mut pages = ArtifactPages::new(ArtifactDeclaration::from_native(&native)).unwrap();
        let first = artifact_file("A", b"a");
        let second = artifact_file("a", b"b");
        pages
            .push(ArtifactPage::from_native(0, &[first]).unwrap())
            .unwrap();
        pages
            .push(ArtifactPage::from_native(1, &[second]).unwrap())
            .unwrap();
        // Each page alone is valid and the paths are strictly sorted. Only
        // whole-manifest validation can detect this cross-page alias.
        assert!(pages.finish().is_err());
    }

    #[test]
    fn bytes_and_manifests_bind_exact_content_and_modes() {
        let bytes = b"binary\0\xff";
        let mut chunk = Chunk::new("artifact", 0, bytes).unwrap();
        assert_eq!(chunk.verified_bytes().unwrap().0, bytes);
        chunk.bytes.replace_range(0..2, "ff");
        assert!(chunk.verified_bytes().is_err());
        for invalid in ["f", "FF", "é", "00ff"] {
            assert!(decode_hex(invalid, 1).is_err());
        }
        let native = SourceManifest::new(vec![SourceFile {
            path: "bin/program".into(),
            len: bytes.len() as u64,
            sha256: Sha256::digest(bytes).into(),
            executable: true,
        }])
        .unwrap();
        let mut manifest = Manifest::from_native(&native);
        assert_eq!(manifest.native().unwrap(), native);
        manifest.files[0].executable = false;
        assert!(manifest.native().is_err());
    }
}
