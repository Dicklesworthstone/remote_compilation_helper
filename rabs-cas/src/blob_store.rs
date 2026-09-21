//! H003 — filesystem blob/chunk store with atomic `put_if_absent`
//! (plan §90; invariants I8/I33; risks R25/R65).
//!
//! The write pipeline, in order, with NO partial path ever published:
//!
//! 1. stream into a PRIVATE staging file (per-process, per-put name —
//!    never inside the published namespace), computing the H002
//!    [`DigestSet`] while writing and enforcing the logical-size limit
//!    as bytes arrive (a limit breach aborts the stream, it never
//!    truncates);
//! 2. verify the computed content id against the DECLARED object id
//!    and the declared logical size — mismatches are typed refusals
//!    and the staging file is removed;
//! 3. fsync the staging file per [`DurabilityPolicy`];
//! 4. publish by atomic `hard_link` into the namespace keyed
//!    `(logical_object_id, storage_profile_id, encoded_digest)` —
//!    create-exclusive, so a concurrent writer can never overwrite an
//!    existing representation — then fsync the containing directory
//!    before durability is reported;
//! 5. record the object + location (with the profile's encoding tag)
//!    in the metadata store; the staging file is removed last (the
//!    race LOSER also cleans its temp).
//!
//! A publish that finds the path already present VERIFIES the existing
//! representation byte-for-byte (by digest recompute): identical →
//! idempotent duplicate; different → a digest-domain
//! collision/corruption INCIDENT — the incoming candidate is preserved
//! under `quarantine/`, every implicated location row is flagged, a
//! logical-object quarantine row opens, and publication is REFUSED.
//! The store never picks a winner (T044's rule).
//!
//! This bead ships the `raw-v1` storage profile (encoded digest ==
//! logical digest). The namespace already keys by profile + encoded
//! digest so H030 can add compressed/packed representations without
//! re-keying anything.
//!
//! Crash injection: [`FaultPoint`] names every step boundary;
//! [`put_if_absent_with_fault`] aborts the pipeline exactly there (the
//! H015 pattern). The acceptance tests drive every point and assert
//! the published namespace never holds a partial object and a retry
//! converges.

use std::fs;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use rabs_protocol::result_identity::TypedDigest;

use crate::collision_policy::REASON_OBJECT_COLLISION_QUARANTINED;
use crate::digest_set::{DigestError, DigestRequest, StreamingObjectWriter};
use crate::metadata_store::{QuarantineScope, RabsMetadataStore, StoreError, digest_key};

/// The storage profile this bead ships: bytes stored exactly as the
/// logical object (encoded digest == logical digest).
pub const RAW_PROFILE_V1: &str = "raw-v1";

/// Domain of encoded-representation digests (H030): the digest of the
/// ENCODED bytes, distinct by construction from the logical content
/// domain so an encoded digest can never pose as object identity.
pub const ENCODED_REPRESENTATION_DOMAIN: &str = "rabs.encoded-representation.sha256.v1";

/// A streaming profile decoder (H030). Read encoded bytes and write logical
/// bytes to the supplied, size-limited sink. Propagate read/write failures and
/// reject truncated frames. A successful decoder must consume the entire input.
///
/// The store never buffers a whole representation or logical object. Codecs
/// must also bound their own working memory (including windows advertised in
/// untrusted headers); a sink cannot police allocations internal to a codec.
pub type RepresentationDecoder<'a> = &'a dyn Fn(&mut dyn Read, &mut dyn Write) -> Result<(), String>;

/// One verified stored representation of a logical object (H030;
/// risk R81): raw/zstd/packed representations coexist, each under its
/// own unambiguous pathname; NONE of them changes the logical
/// identity or any action key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredRepresentationId {
    /// The logical object this represents.
    pub logical: TypedDigest,
    /// The storage profile (encoding) of this representation.
    pub storage_profile: String,
    /// Digest of the encoded bytes (equals `logical` for raw).
    pub encoded_digest: TypedDigest,
    /// Size of the encoded bytes.
    pub encoded_size: u64,
}

/// How hard the store pushes bytes to the platter before reporting
/// durable.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DurabilityPolicy {
    /// fsync the staging file before publish.
    pub fsync_file: bool,
    /// fsync the containing directory after the atomic link.
    pub fsync_directory: bool,
}

impl DurabilityPolicy {
    /// Full durability: both fsyncs (the default for authoritative
    /// stores).
    pub const FULL: Self = Self {
        fsync_file: true,
        fsync_directory: true,
    };

    /// Whether this policy satisfies the FULL profile — the only state a
    /// location row may record as `durable` (H032).
    #[must_use]
    pub const fn is_full(self) -> bool {
        self.fsync_file && self.fsync_directory
    }
}

/// Streaming limits enforced while bytes arrive.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct PutLimits {
    /// Hard cap on logical bytes (decompression-bomb guard when the
    /// reader decodes an encoded transport stream). Exceeding it
    /// ABORTS the stream.
    pub max_logical_bytes: Option<u64>,
    /// Declared logical size, verified exactly at finish.
    pub expected_size: Option<u64>,
}

/// Independent, mandatory resource ceilings for encoded ingestion (H030).
/// No unbounded default: callers must choose both budgets before reading an
/// untrusted representation. Expected sizes are checked before I/O when they
/// exceed these ceilings, during streaming on overruns, and at EOF on underruns.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EncodedPutLimits {
    /// Maximum encoded bytes accepted into staging.
    pub max_encoded_bytes: u64,
    /// Maximum decoded bytes accepted into the logical hasher.
    pub max_logical_bytes: u64,
    /// Declared encoded byte count, when supplied by the transfer header.
    pub expected_encoded_size: Option<u64>,
    /// Declared logical byte count, when supplied by the object manifest.
    pub expected_logical_size: Option<u64>,
}

impl EncodedPutLimits {
    fn validate(self) -> Result<(), PutError> {
        if self
            .expected_encoded_size
            .is_some_and(|n| n > self.max_encoded_bytes)
        {
            return Err(PutError::EncodedLimitExceeded {
                limit: self.max_encoded_bytes,
            });
        }
        if self
            .expected_logical_size
            .is_some_and(|n| n > self.max_logical_bytes)
        {
            return Err(PutError::LogicalLimitExceeded {
                limit: self.max_logical_bytes,
            });
        }
        Ok(())
    }
}

/// Typed put failures. Refusals remove the staging file; none of them
/// publish anything.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PutError {
    /// Encoded input exceeded its configured staging budget.
    EncodedLimitExceeded {
        /// Maximum encoded bytes permitted.
        limit: u64,
    },
    /// Encoded input differs from the size declared by its transfer header.
    EncodedSizeMismatch {
        /// Declared encoded byte count.
        expected: u64,
        /// Observed byte count (at most one extra byte on overrun).
        actual: u64,
    },
    /// The stream exceeded [`PutLimits::max_logical_bytes`].
    LogicalLimitExceeded {
        /// The configured cap.
        limit: u64,
    },
    /// Digest/size verification failed (mismatch with declared).
    Digest(DigestError),
    /// The computed content id differs from the declared object id.
    DeclaredDigestMismatch {
        /// Declared (expected) digest key.
        declared: String,
        /// Computed digest key.
        computed: String,
    },
    /// Existing representation under this key holds DIFFERENT bytes:
    /// collision/corruption incident. Both candidates preserved.
    CollisionIncident {
        /// The contested digest key.
        digest: String,
        /// Published path holding the existing (preserved) bytes.
        existing_path: String,
        /// Quarantine path preserving the refused incoming bytes.
        preserved_incoming_path: String,
    },
    /// The encoded representation failed to decode back to logical
    /// bytes (H030 verification).
    EncodingDecodeFailed {
        /// The storage profile whose decoder refused.
        profile: String,
        /// Decoder error text.
        error: String,
    },
    /// Metadata-store failure.
    Store(StoreError),
    /// Filesystem failure, step named.
    Io {
        /// Pipeline step that failed.
        step: &'static str,
        /// Stringified I/O error.
        error: String,
    },
    /// Crash injected at the named fault point (test harness).
    CrashInjected(FaultPoint),
}

impl From<StoreError> for PutError {
    fn from(e: StoreError) -> Self {
        Self::Store(e)
    }
}

/// Successful outcomes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PutOutcome {
    /// This call published the representation and recorded it.
    Stored {
        /// The published path.
        path: String,
    },
    /// An identical representation was already published (verified
    /// byte-for-byte by digest recompute); this call's temp is cleaned.
    IdempotentDuplicate {
        /// The existing published path.
        path: String,
    },
}

/// Every step boundary of the put pipeline, for crash injection. The
/// pipeline aborts (simulated kill) IMMEDIATELY after completing the
/// named step.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FaultPoint {
    /// Staging file written (not yet synced).
    StagingWritten,
    /// Staging file fsynced.
    StagingSynced,
    /// Atomic link into the published namespace done (directory not
    /// yet synced, metadata not recorded).
    Linked,
    /// Containing directory fsynced (metadata not recorded).
    DirectorySynced,
    /// Object + location recorded in the metadata store (staging file
    /// not yet cleaned).
    MetadataRecorded,
}

/// The store layout: everything lives under one root.
#[derive(Debug, Clone)]
pub struct BlobStoreLayout {
    root: PathBuf,
}

/// Process-wide uniquifier for staging/quarantine names (combined with
/// the pid, so concurrent puts — including across processes — never
/// share a staging path).
static PUT_COUNTER: AtomicU64 = AtomicU64::new(0);

impl BlobStoreLayout {
    /// Open (creating directories as needed) a store rooted at `root`.
    ///
    /// # Errors
    /// [`PutError::Io`] when the directories cannot be created.
    pub fn open(root: &Path) -> Result<Self, PutError> {
        let layout = Self {
            root: root.to_path_buf(),
        };
        for dir in [
            layout.objects_dir(),
            layout.staging_dir(),
            layout.quarantine_dir(),
        ] {
            fs::create_dir_all(&dir).map_err(|e| PutError::Io {
                step: "create-layout",
                error: e.to_string(),
            })?;
        }
        Ok(layout)
    }

    /// The store root (H007 journals/op-staging live under it too).
    #[must_use]
    pub fn root(&self) -> &Path {
        &self.root
    }

    fn objects_dir(&self) -> PathBuf {
        self.root.join("objects")
    }

    fn staging_dir(&self) -> PathBuf {
        self.root.join("staging")
    }

    fn quarantine_dir(&self) -> PathBuf {
        self.root.join("quarantine")
    }

    /// Published path for `(logical id, profile, encoded digest)`.
    /// Digest keys contain `:`/arbitrary domain text, so path segments
    /// use hex only, with a two-hex-char fan-out directory.
    #[must_use]
    pub fn published_path(
        &self,
        logical: &TypedDigest,
        profile: &str,
        encoded: &TypedDigest,
    ) -> PathBuf {
        let logical_hex = hex(&logical.bytes);
        let encoded_hex = hex(&encoded.bytes);
        self.objects_dir()
            .join(&logical_hex[..2])
            .join(format!("{logical_hex}.{profile}.{encoded_hex}"))
    }

    fn fresh_staging_path(&self) -> PathBuf {
        let n = PUT_COUNTER.fetch_add(1, Ordering::SeqCst);
        self.staging_dir()
            .join(format!("put-{}-{n}.tmp", std::process::id()))
    }

    fn quarantine_path(&self, logical: &TypedDigest) -> PathBuf {
        let n = PUT_COUNTER.fetch_add(1, Ordering::SeqCst);
        self.quarantine_dir().join(format!(
            "incoming-{}-{}-{n}",
            hex(&logical.bytes),
            std::process::id()
        ))
    }
}

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        let _ = write!(out, "{b:02x}");
    }
    out
}

pub(crate) fn io_err(step: &'static str) -> impl FnOnce(std::io::Error) -> PutError {
    move |e| PutError::Io {
        step,
        error: e.to_string(),
    }
}

/// Hash a file's bytes under an arbitrary digest domain (the same
/// length-framed prefix rule as [`crate::digest_set`]): used to verify
/// existing representations whose expected digest may live under the
/// logical OR the encoded domain (H030).
fn hash_file_under_domain(path: &Path, domain: &'static str) -> Result<TypedDigest, PutError> {
    use sha2::{Digest as _, Sha256};
    let mut file = fs::File::open(path).map_err(io_err("open-existing"))?;
    let mut hasher = Sha256::new();
    hasher.update((domain.len() as u64).to_be_bytes());
    hasher.update(domain.as_bytes());
    let mut buffer = vec![0_u8; 64 * 1024];
    loop {
        let n = file.read(&mut buffer).map_err(io_err("read-existing"))?;
        if n == 0 {
            break;
        }
        hasher.update(&buffer[..n]);
    }
    Ok(TypedDigest {
        algorithm: rabs_protocol::result_identity::DigestAlgorithm::Sha256V1,
        domain,
        bytes: hasher.finalize().into(),
    })
}

/// Recompute the logical content id of an existing file (used to
/// verify a representation found under the target path, and by H007
/// recovery to decide resume-vs-clean for a staged write).
pub(crate) fn recompute_file_digest(path: &Path) -> Result<TypedDigest, PutError> {
    let mut file = fs::File::open(path).map_err(io_err("open-existing"))?;
    let mut writer = StreamingObjectWriter::new(DigestRequest::default(), None);
    let mut buffer = vec![0_u8; 64 * 1024];
    loop {
        let n = file.read(&mut buffer).map_err(io_err("read-existing"))?;
        if n == 0 {
            break;
        }
        writer.write(&buffer[..n]).map_err(PutError::Digest)?;
    }
    Ok(writer.finish().map_err(PutError::Digest)?.atp_content_id)
}

/// Atomic `put_if_absent` for the `raw-v1` profile. See the module
/// docs for the pipeline; this is the production entry (no fault).
///
/// # Errors
/// A typed [`PutError`]; refusals publish nothing and clean the
/// staging file.
pub fn put_if_absent(
    layout: &BlobStoreLayout,
    store: &mut dyn RabsMetadataStore,
    declared: &TypedDigest,
    reader: &mut dyn Read,
    limits: PutLimits,
    durability: DurabilityPolicy,
) -> Result<PutOutcome, PutError> {
    put_if_absent_with_fault(layout, store, declared, reader, limits, durability, None)
}

/// [`put_if_absent`] with a crash-injection point (H015 pattern): the
/// pipeline stops dead immediately after the named step, leaving
/// whatever on-disk/metadata state that step left. Production callers
/// pass `None` via [`put_if_absent`].
///
/// # Errors
/// As [`put_if_absent`], plus [`PutError::CrashInjected`].
#[allow(clippy::too_many_lines)]
pub fn put_if_absent_with_fault(
    layout: &BlobStoreLayout,
    store: &mut dyn RabsMetadataStore,
    declared: &TypedDigest,
    reader: &mut dyn Read,
    limits: PutLimits,
    durability: DurabilityPolicy,
    fault: Option<FaultPoint>,
) -> Result<PutOutcome, PutError> {
    let staging = layout.fresh_staging_path();

    // 1. Stream to the private staging file, hashing while writing and
    // enforcing the logical cap as bytes arrive.
    let result = stream_to_staging(&staging, reader, limits);
    let digests = match result {
        Ok(digests) => digests,
        Err(e) => {
            let _ = fs::remove_file(&staging);
            return Err(e);
        }
    };

    // 2. Verify the computed id against the DECLARED identity.
    if digests.atp_content_id != *declared {
        let computed = digest_key(&digests.atp_content_id);
        let _ = fs::remove_file(&staging);
        return Err(PutError::DeclaredDigestMismatch {
            declared: digest_key(declared),
            computed,
        });
    }
    if fault == Some(FaultPoint::StagingWritten) {
        return Err(PutError::CrashInjected(FaultPoint::StagingWritten));
    }

    publish_staged_inner(
        layout,
        store,
        declared,
        &staging,
        digests.logical_size,
        durability,
        fault,
        RAW_PROFILE_V1,
        declared,
    )
}

/// Publish an ALREADY-VERIFIED staged file (steps 3–5 of the
/// pipeline): fsync per durability policy, atomic create-exclusive
/// link, directory fsync, metadata record, staging cleanup. Used by
/// the put path and by H007 journal recovery when it RESUMES a staged
/// write whose bytes verify against the declared identity — the
/// caller vouches for that verification.
///
/// # Errors
/// As [`put_if_absent`].
pub fn publish_staged(
    layout: &BlobStoreLayout,
    store: &mut dyn RabsMetadataStore,
    declared: &TypedDigest,
    staging: &Path,
    durability: DurabilityPolicy,
) -> Result<PutOutcome, PutError> {
    let logical_size = fs::metadata(staging).map_err(io_err("stat-staging"))?.len();
    publish_staged_inner(
        layout,
        store,
        declared,
        staging,
        logical_size,
        durability,
        None,
        RAW_PROFILE_V1,
        declared,
    )
}

/// Steps 3–5 for ANY representation (H030): `profile` + `file_digest`
/// name the representation — for raw the file digest IS the logical
/// identity, for encoded profiles it is the encoded digest — while
/// `declared`/`logical_size` remain the LOGICAL object recorded in
/// metadata. Representation selection never changes logical identity.
#[allow(clippy::too_many_arguments)]
fn publish_staged_inner(
    layout: &BlobStoreLayout,
    store: &mut dyn RabsMetadataStore,
    declared: &TypedDigest,
    staging: &Path,
    logical_size: u64,
    durability: DurabilityPolicy,
    fault: Option<FaultPoint>,
    profile: &str,
    file_digest: &TypedDigest,
) -> Result<PutOutcome, PutError> {
    // 3. fsync file data per durability policy.
    if durability.fsync_file {
        let file = fs::File::open(staging).map_err(io_err("open-for-sync"))?;
        file.sync_all().map_err(io_err("fsync-staging"))?;
    }
    if fault == Some(FaultPoint::StagingSynced) {
        return Err(PutError::CrashInjected(FaultPoint::StagingSynced));
    }

    // 4. Atomic create-exclusive publish: hard_link never overwrites,
    // so a concurrent writer's representation is never clobbered —
    // and different profiles publish DIFFERENT pathnames, so they
    // never race one ambiguous name (H030/R81).
    let target = layout.published_path(declared, profile, file_digest);
    let target_dir = target
        .parent()
        .ok_or_else(|| PutError::Io {
            step: "target-parent",
            error: "published path has no parent".to_owned(),
        })?
        .to_path_buf();
    fs::create_dir_all(&target_dir).map_err(io_err("create-fanout"))?;
    match fs::hard_link(staging, &target) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
            // Race loser or re-put: VERIFY the existing representation
            // before conceding idempotency.
            return handle_existing(
                layout,
                store,
                declared,
                logical_size,
                profile,
                file_digest,
                staging,
                &target,
                durability,
            );
        }
        Err(e) => {
            let _ = fs::remove_file(staging);
            return Err(io_err("publish-link")(e));
        }
    }
    if fault == Some(FaultPoint::Linked) {
        return Err(PutError::CrashInjected(FaultPoint::Linked));
    }

    // ...then the containing directory, BEFORE durability is reported.
    if durability.fsync_directory {
        let dir = fs::File::open(&target_dir).map_err(io_err("open-dir"))?;
        dir.sync_all().map_err(io_err("fsync-dir"))?;
    }
    if fault == Some(FaultPoint::DirectorySynced) {
        return Err(PutError::CrashInjected(FaultPoint::DirectorySynced));
    }

    // 5. Record object + location; encoding tag is the profile. The
    // location claims durability only when the policy actually was the
    // full profile (H032).
    store.record_object(declared, logical_size)?;
    store.add_location(
        declared,
        &target.to_string_lossy(),
        None,
        profile,
        durability.is_full(),
    )?;
    if fault == Some(FaultPoint::MetadataRecorded) {
        return Err(PutError::CrashInjected(FaultPoint::MetadataRecorded));
    }

    let _ = fs::remove_file(staging);
    Ok(PutOutcome::Stored {
        path: target.to_string_lossy().into_owned(),
    })
}

/// H030: publish an encoded representation only after streaming verification
/// against its logical identity. Encoded and logical byte budgets are enforced
/// independently, before accepting each chunk. No whole-object allocation is
/// performed, and a failed decoder write cannot be ignored to publish a prefix.
/// Raw callers use [`put_if_absent`].
///
/// # Errors
/// Typed [`PutError`]; refusals before publication leave neither an object nor
/// metadata. The owned staging file is cleaned on every return path or unwind.
#[allow(clippy::too_many_arguments)]
pub fn put_encoded_representation(
    layout: &BlobStoreLayout,
    store: &mut dyn RabsMetadataStore,
    declared_logical: &TypedDigest,
    profile: &str,
    encoded: &mut dyn Read,
    decoder: RepresentationDecoder<'_>,
    limits: EncodedPutLimits,
    durability: DurabilityPolicy,
) -> Result<(StoredRepresentationId, PutOutcome), PutError> {
    // Header claims cannot enlarge a budget or trigger an allocation.
    limits.validate()?;
    let staging = layout.fresh_staging_path();
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&staging)
        .map_err(io_err("create-staging"))?;
    // Install cleanup only AFTER exclusive creation: never unlink somebody
    // else's file when a stale name or a symlink occupied the candidate path.
    let _cleanup = EncodedStagingCleanup(&staging);
    let (encoded_digest, encoded_size) = stream_encoded(&mut file, encoded, limits)?;
    drop(file);

    let logical_size = verify_decoded_representation(
        &staging,
        declared_logical,
        profile,
        decoder,
        limits,
        encoded_size,
    )?;
    let outcome = publish_staged_inner(
        layout,
        store,
        declared_logical,
        &staging,
        logical_size,
        durability,
        None,
        profile,
        &encoded_digest,
    )?;
    Ok((
        StoredRepresentationId {
            logical: declared_logical.clone(),
            storage_profile: profile.to_owned(),
            encoded_digest,
            encoded_size,
        },
        outcome,
    ))
}

struct EncodedStagingCleanup<'a>(&'a Path);

impl Drop for EncodedStagingCleanup<'_> {
    fn drop(&mut self) {
        // Publication may already have unlinked staging or preserved an
        // incident under quarantine. Neither case removes the published file.
        let _ = fs::remove_file(self.0);
    }
}

fn stream_encoded(
    file: &mut fs::File,
    encoded: &mut dyn Read,
    limits: EncodedPutLimits,
) -> Result<(TypedDigest, u64), PutError> {
    use sha2::{Digest as _, Sha256};
    let mut hasher = Sha256::new();
    hasher.update((ENCODED_REPRESENTATION_DOMAIN.len() as u64).to_be_bytes());
    hasher.update(ENCODED_REPRESENTATION_DOMAIN.as_bytes());
    let mut buffer = [0_u8; 64 * 1024];
    let mut total = 0_u64;
    let ceiling = limits
        .expected_encoded_size
        .unwrap_or(limits.max_encoded_bytes)
        .min(limits.max_encoded_bytes);
    loop {
        // Probe one byte beyond the ceiling, rather than treating a capped
        // reader's synthetic EOF as a valid, silently truncated representation.
        let read_len = ceiling
            .saturating_sub(total)
            .saturating_add(1)
            .min(buffer.len() as u64) as usize;
        let n = match encoded.read(&mut buffer[..read_len]) {
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            result => result.map_err(io_err("read-encoded"))?,
        };
        if n == 0 {
            break;
        }
        total = total
            .checked_add(n as u64)
            .ok_or(PutError::Digest(DigestError::SizeOverflow))?;
        if total > limits.max_encoded_bytes {
            return Err(PutError::EncodedLimitExceeded {
                limit: limits.max_encoded_bytes,
            });
        }
        if let Some(expected) = limits.expected_encoded_size
            && total > expected
        {
            return Err(PutError::EncodedSizeMismatch {
                expected,
                actual: total,
            });
        }
        hasher.update(&buffer[..n]);
        file.write_all(&buffer[..n])
            .map_err(io_err("write-staging"))?;
    }
    if let Some(expected) = limits.expected_encoded_size
        && total != expected
    {
        return Err(PutError::EncodedSizeMismatch {
            expected,
            actual: total,
        });
    }
    Ok((
        TypedDigest {
            algorithm: rabs_protocol::result_identity::DigestAlgorithm::Sha256V1,
            domain: ENCODED_REPRESENTATION_DOMAIN,
            bytes: hasher.finalize().into(),
        },
        total,
    ))
}

/// Hash-only sink: no decoded bytes are retained. The first refusal is sticky
/// even when a decoder mistakenly catches a write error and returns success.
struct BoundedLogicalWriter {
    digest: StreamingObjectWriter,
    limits: EncodedPutLimits,
    written: u64,
    failure: Option<PutError>,
}

impl Write for BoundedLogicalWriter {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        if self.failure.is_some() {
            return Err(std::io::Error::other("logical sink already refused output"));
        }
        let result = (|| {
            let next = self
                .written
                .checked_add(bytes.len() as u64)
                .ok_or(PutError::Digest(DigestError::SizeOverflow))?;
            if next > self.limits.max_logical_bytes {
                return Err(PutError::LogicalLimitExceeded {
                    limit: self.limits.max_logical_bytes,
                });
            }
            if let Some(expected) = self.limits.expected_logical_size
                && next > expected
            {
                return Err(PutError::Digest(DigestError::LogicalSizeMismatch {
                    expected,
                    actual: next,
                }));
            }
            self.digest.write(bytes).map_err(PutError::Digest)?;
            self.written = next;
            Ok(())
        })();
        match result {
            Ok(()) => Ok(bytes.len()),
            Err(error) => {
                self.failure = Some(error);
                Err(std::io::Error::other("logical output exceeded its budget"))
            }
        }
    }

    fn flush(&mut self) -> std::io::Result<()> {
        if self.failure.is_some() {
            Err(std::io::Error::other("logical sink already refused output"))
        } else {
            Ok(())
        }
    }
}

fn verify_decoded_representation(
    staging: &Path,
    declared: &TypedDigest,
    profile: &str,
    decoder: RepresentationDecoder<'_>,
    limits: EncodedPutLimits,
    encoded_size: u64,
) -> Result<u64, PutError> {
    let mut input = fs::File::open(staging)
        .map_err(io_err("read-staged"))?
        .take(encoded_size);
    let mut output = BoundedLogicalWriter {
        digest: StreamingObjectWriter::new(DigestRequest::default(), limits.expected_logical_size),
        limits,
        written: 0,
        failure: None,
    };
    let decoded = decoder(&mut input, &mut output);
    if let Some(error) = output.failure {
        return Err(error);
    }
    decoded.map_err(|error| PutError::EncodingDecodeFailed {
        profile: profile.to_owned(),
        error,
    })?;
    if input.limit() != 0 {
        return Err(PutError::EncodingDecodeFailed {
            profile: profile.to_owned(),
            error: "decoder did not consume the complete representation".to_owned(),
        });
    }
    let digests = output.digest.finish().map_err(PutError::Digest)?;
    if digests.atp_content_id != *declared {
        return Err(PutError::DeclaredDigestMismatch {
            declared: digest_key(declared),
            computed: digest_key(&digests.atp_content_id),
        });
    }
    Ok(digests.logical_size)
}

pub(crate) fn stream_to_staging(
    staging: &Path,
    reader: &mut dyn Read,
    limits: PutLimits,
) -> Result<crate::digest_set::DigestSet, PutError> {
    let mut file = fs::File::create(staging).map_err(io_err("create-staging"))?;
    let mut writer = StreamingObjectWriter::new(DigestRequest::default(), limits.expected_size);
    let mut buffer = vec![0_u8; 64 * 1024];
    let mut total: u64 = 0;
    loop {
        let n = reader.read(&mut buffer).map_err(io_err("read-source"))?;
        if n == 0 {
            break;
        }
        total = total.saturating_add(n as u64);
        if let Some(limit) = limits.max_logical_bytes
            && total > limit
        {
            return Err(PutError::LogicalLimitExceeded { limit });
        }
        writer.write(&buffer[..n]).map_err(PutError::Digest)?;
        file.write_all(&buffer[..n])
            .map_err(io_err("write-staging"))?;
    }
    writer.finish().map_err(PutError::Digest)
}

/// The target path already exists: verify it against the EXPECTED
/// file digest (logical id for raw, encoded digest for encoded
/// profiles). Identical → idempotent (clean own temp). Different →
/// collision/corruption incident: preserve the incoming candidate,
/// quarantine every implicated location, open the logical-object
/// quarantine, REFUSE.
#[allow(clippy::too_many_arguments)]
fn handle_existing(
    layout: &BlobStoreLayout,
    store: &mut dyn RabsMetadataStore,
    declared: &TypedDigest,
    logical_size: u64,
    profile: &str,
    file_digest: &TypedDigest,
    staging: &Path,
    target: &Path,
    durability: DurabilityPolicy,
) -> Result<PutOutcome, PutError> {
    let existing_digest = hash_file_under_domain(target, file_digest.domain)?;
    if existing_digest == *file_digest {
        // Identical representation already published. Make sure the
        // metadata rows exist (the original writer may have died
        // between link and record), then clean OUR temp — the race
        // loser's duty. The original writer's fsync state is UNKNOWN
        // (it may have died before the directory sync), so under the
        // full profile the loser fsyncs the published copy itself
        // before this location may claim durability (H032).
        if durability.is_full() {
            let file = fs::File::open(target).map_err(io_err("fsync-existing"))?;
            file.sync_all().map_err(io_err("fsync-existing"))?;
            if let Some(dir) = target.parent() {
                let dir = fs::File::open(dir).map_err(io_err("fsync-existing-dir"))?;
                dir.sync_all().map_err(io_err("fsync-existing-dir"))?;
            }
        }
        store.record_object(declared, logical_size)?;
        store.add_location(
            declared,
            &target.to_string_lossy(),
            None,
            profile,
            durability.is_full(),
        )?;
        let _ = fs::remove_file(staging);
        return Ok(PutOutcome::IdempotentDuplicate {
            path: target.to_string_lossy().into_owned(),
        });
    }

    // Existing digest, different bytes: incident. Preserve BOTH
    // candidates — the existing file stays exactly where it is; the
    // incoming staging file moves to quarantine (rename, same fs).
    let preserved = layout.quarantine_path(declared);
    fs::rename(staging, &preserved).map_err(io_err("preserve-incoming"))?;
    store.add_quarantine(
        QuarantineScope::LogicalObject,
        &digest_key(declared),
        REASON_OBJECT_COLLISION_QUARANTINED,
    )?;
    // Flag every implicated location row (the published copy is now
    // suspect evidence, not identity).
    store.set_location_quarantined(declared, &target.to_string_lossy(), true)?;
    Err(PutError::CollisionIncident {
        digest: digest_key(declared),
        existing_path: target.to_string_lossy().into_owned(),
        preserved_incoming_path: preserved.to_string_lossy().into_owned(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::digest_set::digest_set;
    use crate::metadata_store::{RusqliteEngine, SqlMetadataStore};
    use std::sync::atomic::AtomicU64 as TestCounter;

    static DIR_COUNTER: TestCounter = TestCounter::new(0);

    fn fresh_root(tag: &str) -> PathBuf {
        let n = DIR_COUNTER.fetch_add(1, Ordering::SeqCst);
        let root = std::env::temp_dir().join(format!("rabs-h003-{}-{tag}-{n}", std::process::id()));
        fs::create_dir_all(&root).unwrap();
        root
    }

    fn store() -> SqlMetadataStore<RusqliteEngine> {
        SqlMetadataStore::open(RusqliteEngine::open_in_memory().unwrap()).unwrap()
    }

    fn id_of(bytes: &[u8]) -> TypedDigest {
        digest_set(bytes, DigestRequest::default(), None)
            .unwrap()
            .atp_content_id
    }

    /// Everything under objects/ must be a COMPLETE object: any file
    /// present re-digests to the logical id its filename claims.
    fn assert_no_partial_published(layout: &BlobStoreLayout) {
        let objects = layout.objects_dir();
        let mut stack = vec![objects];
        while let Some(dir) = stack.pop() {
            let Ok(entries) = fs::read_dir(&dir) else {
                continue;
            };
            for entry in entries {
                let path = entry.unwrap().path();
                if path.is_dir() {
                    stack.push(path);
                    continue;
                }
                let name = path.file_name().unwrap().to_string_lossy().into_owned();
                let segments: Vec<&str> = name.split('.').collect();
                let [logical_hex, profile, encoded_hex] = segments.as_slice() else {
                    panic!("unexpected published name {name}");
                };
                // Raw files re-digest to the logical id; encoded files
                // to their encoded digest — either way, only COMPLETE
                // correct representations may be visible.
                let (domain, claimed) = if *profile == RAW_PROFILE_V1 {
                    (crate::digest_set::ATP_OBJECT_CONTENT_DOMAIN, *logical_hex)
                } else {
                    (ENCODED_REPRESENTATION_DOMAIN, *encoded_hex)
                };
                let recomputed = hash_file_under_domain(&path, domain).unwrap();
                assert_eq!(
                    hex(&recomputed.bytes),
                    claimed,
                    "partial or corrupt representation exposed at {}",
                    path.display()
                );
            }
        }
    }

    #[test]
    fn h003_put_stores_then_idempotent_and_staging_clean() {
        let layout = BlobStoreLayout::open(&fresh_root("basic")).unwrap();
        let mut store = store();
        let bytes = b"h003 object bytes".to_vec();
        let declared = id_of(&bytes);

        let outcome = put_if_absent(
            &layout,
            &mut store,
            &declared,
            &mut bytes.as_slice(),
            PutLimits {
                max_logical_bytes: Some(1024),
                expected_size: Some(bytes.len() as u64),
            },
            DurabilityPolicy::FULL,
        )
        .unwrap();
        let PutOutcome::Stored { path } = outcome else {
            panic!("expected Stored, got {outcome:?}");
        };
        assert_eq!(fs::read(&path).unwrap(), bytes);
        assert!(store.object_located(&declared).unwrap());

        // Re-put: verified idempotent duplicate, same path, temp clean.
        let again = put_if_absent(
            &layout,
            &mut store,
            &declared,
            &mut bytes.as_slice(),
            PutLimits::default(),
            DurabilityPolicy::FULL,
        )
        .unwrap();
        assert_eq!(again, PutOutcome::IdempotentDuplicate { path });
        assert_eq!(
            fs::read_dir(layout.staging_dir()).unwrap().count(),
            0,
            "race loser must clean its temp"
        );
        assert_no_partial_published(&layout);
    }

    #[test]
    fn h003_refusals_publish_nothing_and_clean_staging() {
        let layout = BlobStoreLayout::open(&fresh_root("refusals")).unwrap();
        let mut store = store();
        let bytes = b"refusal bytes".to_vec();
        let declared = id_of(&bytes);

        // Declared-digest mismatch (declared id of DIFFERENT bytes).
        let wrong = id_of(b"other bytes");
        assert!(matches!(
            put_if_absent(
                &layout,
                &mut store,
                &wrong,
                &mut bytes.as_slice(),
                PutLimits::default(),
                DurabilityPolicy::FULL,
            ),
            Err(PutError::DeclaredDigestMismatch { .. })
        ));

        // Logical cap exceeded mid-stream.
        assert_eq!(
            put_if_absent(
                &layout,
                &mut store,
                &declared,
                &mut bytes.as_slice(),
                PutLimits {
                    max_logical_bytes: Some(4),
                    expected_size: None,
                },
                DurabilityPolicy::FULL,
            ),
            Err(PutError::LogicalLimitExceeded { limit: 4 })
        );

        // Declared-size mismatch.
        assert!(matches!(
            put_if_absent(
                &layout,
                &mut store,
                &declared,
                &mut bytes.as_slice(),
                PutLimits {
                    max_logical_bytes: None,
                    expected_size: Some(3),
                },
                DurabilityPolicy::FULL,
            ),
            Err(PutError::Digest(DigestError::LogicalSizeMismatch { .. }))
        ));

        assert!(!store.object_located(&declared).unwrap());
        assert_eq!(fs::read_dir(layout.staging_dir()).unwrap().count(), 0);
        assert_no_partial_published(&layout);
    }

    #[test]
    fn h003_existing_digest_different_bytes_is_quarantined_incident() {
        let layout = BlobStoreLayout::open(&fresh_root("collision")).unwrap();
        let mut store = store();
        let bytes = b"honest object".to_vec();
        let declared = id_of(&bytes);
        put_if_absent(
            &layout,
            &mut store,
            &declared,
            &mut bytes.as_slice(),
            PutLimits::default(),
            DurabilityPolicy::FULL,
        )
        .unwrap();

        // Corrupt the published copy on disk, then re-put the honest
        // bytes: the store finds digest-present/bytes-differ.
        let target = layout.published_path(&declared, RAW_PROFILE_V1, &declared);
        fs::write(&target, b"corrupted!").unwrap();
        let result = put_if_absent(
            &layout,
            &mut store,
            &declared,
            &mut bytes.as_slice(),
            PutLimits::default(),
            DurabilityPolicy::FULL,
        );
        let Err(PutError::CollisionIncident {
            digest,
            existing_path,
            preserved_incoming_path,
        }) = result
        else {
            panic!("expected collision incident, got {result:?}");
        };
        assert_eq!(digest, digest_key(&declared));
        // BOTH candidates preserved: existing untouched in place,
        // incoming under quarantine/.
        assert_eq!(fs::read(&existing_path).unwrap(), b"corrupted!");
        assert_eq!(fs::read(&preserved_incoming_path).unwrap(), bytes);
        // Quarantine row + implicated location flagged; publication
        // refused (pointer unchanged).
        let snapshot = store.differential_snapshot().unwrap();
        assert!(
            snapshot
                .iter()
                .any(|l| l.starts_with("quarantines|logical-object|")
                    && l.contains(REASON_OBJECT_COLLISION_QUARANTINED))
        );
        assert!(
            store
                .reconciliation_scan()
                .unwrap()
                .iter()
                .any(|row| row.quarantined)
        );
        assert_eq!(fs::read_dir(layout.staging_dir()).unwrap().count(), 0);
    }

    #[test]
    fn h003_crash_injection_at_every_step_never_exposes_a_partial_object() {
        for fault in [
            FaultPoint::StagingWritten,
            FaultPoint::StagingSynced,
            FaultPoint::Linked,
            FaultPoint::DirectorySynced,
            FaultPoint::MetadataRecorded,
        ] {
            let layout = BlobStoreLayout::open(&fresh_root("crash")).unwrap();
            let mut store = store();
            let bytes = format!("crash object {fault:?}").into_bytes();
            let declared = id_of(&bytes);

            let result = put_if_absent_with_fault(
                &layout,
                &mut store,
                &declared,
                &mut bytes.as_slice(),
                PutLimits::default(),
                DurabilityPolicy::FULL,
                Some(fault),
            );
            assert_eq!(result, Err(PutError::CrashInjected(fault)));

            // The published namespace holds no PARTIAL object at any
            // kill point: either absent or complete-and-correct.
            assert_no_partial_published(&layout);
            // A location row may exist only when the published file
            // does (metadata never points at nothing).
            for row in store.reconciliation_scan().unwrap() {
                assert!(
                    Path::new(&row.store_path).exists(),
                    "{fault:?}: metadata points at missing path {}",
                    row.store_path
                );
            }

            // Restarted-writer retry converges (Stored if the link
            // never happened, verified-idempotent otherwise), and the
            // world is fully consistent after it.
            let retry = put_if_absent(
                &layout,
                &mut store,
                &declared,
                &mut bytes.as_slice(),
                PutLimits::default(),
                DurabilityPolicy::FULL,
            )
            .unwrap();
            let path = match retry {
                PutOutcome::Stored { path } | PutOutcome::IdempotentDuplicate { path } => path,
            };
            assert_eq!(fs::read(&path).unwrap(), bytes);
            assert!(store.object_located(&declared).unwrap());
            // The RETRY cleaned its own temp; the dead writer's staging
            // orphan (private, never published) may remain — sweeping
            // those is H007's staging-journal job, not the put path's.
            assert!(
                fs::read_dir(layout.staging_dir()).unwrap().count() <= 1,
                "{fault:?}: retry left its own staging temp behind"
            );
            assert_no_partial_published(&layout);
        }
    }

    const ENCODED_LIMITS: EncodedPutLimits = EncodedPutLimits {
        max_encoded_bytes: 4096,
        max_logical_bytes: 4096,
        expected_encoded_size: None,
        expected_logical_size: None,
    };

    /// A reversible test profile that can be decoded with constant memory.
    fn xor_encode(bytes: &[u8]) -> Vec<u8> {
        bytes.iter().map(|b| b ^ 0xa5).collect()
    }

    fn xor_decoder(input: &mut dyn Read, output: &mut dyn Write) -> Result<(), String> {
        let mut buffer = [0_u8; 128];
        loop {
            let n = input.read(&mut buffer).map_err(|e| e.to_string())?;
            if n == 0 {
                return Ok(());
            }
            for b in &mut buffer[..n] {
                *b ^= 0xa5;
            }
            output.write_all(&buffer[..n]).map_err(|e| e.to_string())?;
        }
    }

    #[test]
    fn h030_encoded_and_raw_representations_coexist_without_ambiguity() {
        let layout = BlobStoreLayout::open(&fresh_root("h030")).unwrap();
        let mut store = store();
        let bytes = b"multi-representation object".to_vec();
        let declared = id_of(&bytes);

        let PutOutcome::Stored { path: raw_path } = put_if_absent(
            &layout,
            &mut store,
            &declared,
            &mut bytes.as_slice(),
            PutLimits::default(),
            DurabilityPolicy::FULL,
        )
        .unwrap() else {
            panic!("raw put must store");
        };
        let encoded = xor_encode(&bytes);
        let (representation, outcome) = put_encoded_representation(
            &layout,
            &mut store,
            &declared,
            "xor-v1",
            &mut encoded.as_slice(),
            &xor_decoder,
            EncodedPutLimits {
                expected_encoded_size: Some(encoded.len() as u64),
                expected_logical_size: Some(bytes.len() as u64),
                ..ENCODED_LIMITS
            },
            DurabilityPolicy::FULL,
        )
        .unwrap();
        let PutOutcome::Stored { path: encoded_path } = outcome else {
            panic!("encoded put must store");
        };

        // Distinct unambiguous pathnames; encoded bytes live at the
        // encoded path; the representation names everything.
        assert_ne!(raw_path, encoded_path);
        assert_eq!(fs::read(&encoded_path).unwrap(), encoded);
        assert_eq!(representation.storage_profile, "xor-v1");
        assert_eq!(representation.encoded_size, encoded.len() as u64);
        assert_eq!(
            representation.encoded_digest.domain,
            ENCODED_REPRESENTATION_DOMAIN
        );
        assert_eq!(representation.logical, declared);

        // Both representations are location rows of ONE logical
        // object, tagged by profile.
        let encodings: Vec<String> = store
            .reconciliation_scan()
            .unwrap()
            .into_iter()
            .map(|row| row.encoding)
            .collect();
        assert!(encodings.contains(&"raw-v1".to_owned()));
        assert!(encodings.contains(&"xor-v1".to_owned()));

        // Re-put of the same encoded representation: verified
        // idempotent against the ENCODED digest.
        let (_, again) = put_encoded_representation(
            &layout,
            &mut store,
            &declared,
            "xor-v1",
            &mut encoded.as_slice(),
            &xor_decoder,
            ENCODED_LIMITS,
            DurabilityPolicy::FULL,
        )
        .unwrap();
        assert_eq!(again, PutOutcome::IdempotentDuplicate { path: encoded_path });
        assert_eq!(fs::read_dir(layout.staging_dir()).unwrap().count(), 0);
    }

    #[test]
    fn h030_decode_verification_refuses_wrong_and_bombing_representations() {
        let layout = BlobStoreLayout::open(&fresh_root("h030-verify")).unwrap();
        let mut store = store();
        let bytes = b"verified object".to_vec();
        let declared = id_of(&bytes);
        let encoded = xor_encode(&bytes);

        // Decoder that produces the WRONG logical bytes: refused, and
        // nothing published anywhere.
        let bad_decoder = |input: &mut dyn Read, output: &mut dyn Write| {
            std::io::copy(input, &mut std::io::sink()).map_err(|e| e.to_string())?;
            output.write_all(b"other bytes").map_err(|e| e.to_string())
        };
        assert!(matches!(
            put_encoded_representation(
                &layout,
                &mut store,
                &declared,
                "xor-v1",
                &mut encoded.as_slice(),
                &bad_decoder,
                ENCODED_LIMITS,
                DurabilityPolicy::FULL,
            ),
            Err(PutError::DeclaredDigestMismatch { .. })
        ));

        // Decoder failure is typed.
        let failing = |_: &mut dyn Read, _: &mut dyn Write| Err("truncated frame".to_owned());
        assert!(matches!(
            put_encoded_representation(
                &layout,
                &mut store,
                &declared,
                "xor-v1",
                &mut encoded.as_slice(),
                &failing,
                ENCODED_LIMITS,
                DurabilityPolicy::FULL,
            ),
            Err(PutError::EncodingDecodeFailed { .. })
        ));

        // Decompression bomb: decoded bytes exceed the logical cap.
        let attempted = std::cell::Cell::new(0);
        let bomb = |_: &mut dyn Read, output: &mut dyn Write| {
            for _ in 0..1_000_000 {
                attempted.set(attempted.get() + 1);
                output.write_all(&[0_u8; 32]).map_err(|e| e.to_string())?;
            }
            Ok(())
        };
        assert_eq!(
            put_encoded_representation(
                &layout,
                &mut store,
                &declared,
                "bomb-v1",
                &mut encoded.as_slice(),
                &bomb,
                EncodedPutLimits {
                    max_logical_bytes: 64,
                    ..ENCODED_LIMITS
                },
                DurabilityPolicy::FULL,
            ),
            Err(PutError::LogicalLimitExceeded { limit: 64 })
        );
        assert_eq!(attempted.get(), 3, "stop the bomb before expanding it");

        assert!(!store.object_located(&declared).unwrap());
        assert_eq!(fs::read_dir(layout.staging_dir()).unwrap().count(), 0);
        assert_no_partial_published(&layout);
    }

    #[test]
    fn h030_concurrent_profiles_publish_distinct_records_not_one_race() {
        let layout = BlobStoreLayout::open(&fresh_root("h030-race")).unwrap();
        let bytes = b"contended multi-encoding object".to_vec();
        let declared = id_of(&bytes);

        let workers: Vec<_> = (0..8)
            .map(|i| {
                let layout = layout.clone();
                let bytes = bytes.clone();
                let declared = declared.clone();
                std::thread::spawn(move || {
                    let mut store = store();
                    if i % 2 == 0 {
                        put_if_absent(
                            &layout,
                            &mut store,
                            &declared,
                            &mut bytes.as_slice(),
                            PutLimits::default(),
                            DurabilityPolicy::FULL,
                        )
                        .map(|outcome| ("raw-v1", outcome))
                    } else {
                        let encoded = xor_encode(&bytes);
                        put_encoded_representation(
                            &layout,
                            &mut store,
                            &declared,
                            "xor-v1",
                            &mut encoded.as_slice(),
                            &xor_decoder,
                            ENCODED_LIMITS,
                            DurabilityPolicy::FULL,
                        )
                        .map(|(_, outcome)| ("xor-v1", outcome))
                    }
                })
            })
            .collect();
        let outcomes: Vec<(&str, PutOutcome)> = workers
            .into_iter()
            .map(|t| t.join().unwrap().unwrap())
            .collect();

        // Exactly one Stored PER PROFILE: different profiles never
        // contend on one ambiguous pathname.
        for profile in ["raw-v1", "xor-v1"] {
            let stored = outcomes
                .iter()
                .filter(|(p, o)| *p == profile && matches!(o, PutOutcome::Stored { .. }))
                .count();
            assert_eq!(stored, 1, "profile {profile}");
        }
        assert_eq!(fs::read_dir(layout.staging_dir()).unwrap().count(), 0);
        assert_no_partial_published(&layout);
    }

    #[test]
    fn h030_representation_ops_never_touch_action_keys() {
        let layout = BlobStoreLayout::open(&fresh_root("h030-keys")).unwrap();
        let mut store = store();
        let bytes = b"identity-stable object".to_vec();
        let declared = id_of(&bytes);
        let before: Vec<String> = store
            .differential_snapshot()
            .unwrap()
            .into_iter()
            .filter(|l| l.starts_with("action_"))
            .collect();
        put_if_absent(
            &layout,
            &mut store,
            &declared,
            &mut bytes.as_slice(),
            PutLimits::default(),
            DurabilityPolicy::FULL,
        )
        .unwrap();
        let encoded = xor_encode(&bytes);
        put_encoded_representation(
            &layout,
            &mut store,
            &declared,
            "xor-v1",
            &mut encoded.as_slice(),
            &xor_decoder,
            ENCODED_LIMITS,
            DurabilityPolicy::FULL,
        )
        .unwrap();
        let after: Vec<String> = store
            .differential_snapshot()
            .unwrap()
            .into_iter()
            .filter(|l| l.starts_with("action_"))
            .collect();
        // Representation selection never changes action keys (H030).
        assert_eq!(before, after);
    }

    fn assert_encoded_refusal_clean(
        layout: &BlobStoreLayout,
        store: &mut SqlMetadataStore<RusqliteEngine>,
    ) {
        assert!(store.reconciliation_scan().unwrap().is_empty());
        assert_eq!(fs::read_dir(layout.staging_dir()).unwrap().count(), 0);
        assert_eq!(fs::read_dir(layout.objects_dir()).unwrap().count(), 0);
    }

    #[test]
    fn h030_encoded_budget_stops_source_before_decoding() {
        let layout = BlobStoreLayout::open(&fresh_root("encoded-cap")).unwrap();
        let mut store = store();
        let mut source = std::io::repeat(7).take(1_000_000);
        let decoder = |_: &mut dyn Read, _: &mut dyn Write| -> Result<(), String> {
            panic!("encoded overrun must refuse before invoking the decoder");
        };
        assert_eq!(
            put_encoded_representation(
                &layout,
                &mut store,
                &id_of(b"unused"),
                "xor-v1",
                &mut source,
                &decoder,
                EncodedPutLimits {
                    max_encoded_bytes: 8,
                    ..ENCODED_LIMITS
                },
                DurabilityPolicy::FULL,
            ),
            Err(PutError::EncodedLimitExceeded { limit: 8 })
        );
        assert_eq!(source.limit(), 1_000_000 - 9, "one-byte overrun probe");
        assert_encoded_refusal_clean(&layout, &mut store);
    }

    #[test]
    fn h030_oversized_header_claims_are_refused_without_reading() {
        for limits in [
            EncodedPutLimits {
                expected_encoded_size: Some(4097),
                ..ENCODED_LIMITS
            },
            EncodedPutLimits {
                expected_logical_size: Some(4097),
                ..ENCODED_LIMITS
            },
        ] {
            let layout = BlobStoreLayout::open(&fresh_root("header-cap")).unwrap();
            let mut store = store();
            let mut source = std::io::Cursor::new(b"unread");
            let result = put_encoded_representation(
                &layout,
                &mut store,
                &id_of(b"unused"),
                "xor-v1",
                &mut source,
                &xor_decoder,
                limits,
                DurabilityPolicy::FULL,
            );
            assert!(matches!(
                result,
                Err(PutError::EncodedLimitExceeded { limit: 4096 })
                    | Err(PutError::LogicalLimitExceeded { limit: 4096 })
            ));
            assert_eq!(source.position(), 0);
            assert_encoded_refusal_clean(&layout, &mut store);
        }
    }

    #[test]
    fn h030_encoded_expected_size_rejects_short_and_long_streams_before_decode() {
        for bytes in [b"ab".as_slice(), b"abcd".as_slice()] {
            let mut source = bytes;
            let layout = BlobStoreLayout::open(&fresh_root("encoded-size")).unwrap();
            let mut store = store();
            let decoder = |_: &mut dyn Read, _: &mut dyn Write| -> Result<(), String> {
                panic!("encoded length mismatch must refuse before decoding");
            };
            assert_eq!(
                put_encoded_representation(
                    &layout,
                    &mut store,
                    &id_of(b"unused"),
                    "xor-v1",
                    &mut source,
                    &decoder,
                    EncodedPutLimits {
                        expected_encoded_size: Some(3),
                        ..ENCODED_LIMITS
                    },
                    DurabilityPolicy::FULL,
                ),
                Err(PutError::EncodedSizeMismatch {
                    expected: 3,
                    actual: bytes.len() as u64,
                })
            );
            assert_encoded_refusal_clean(&layout, &mut store);
        }
    }

    #[test]
    fn h030_logical_expected_size_is_independent_of_encoded_size() {
        let bytes = b"abc";
        let encoded = xor_encode(bytes);
        for expected in [2, 4] {
            let layout = BlobStoreLayout::open(&fresh_root("logical-size")).unwrap();
            let mut store = store();
            assert_eq!(
                put_encoded_representation(
                    &layout,
                    &mut store,
                    &id_of(bytes),
                    "xor-v1",
                    &mut encoded.as_slice(),
                    &xor_decoder,
                    EncodedPutLimits {
                        expected_encoded_size: Some(3),
                        expected_logical_size: Some(expected),
                        ..ENCODED_LIMITS
                    },
                    DurabilityPolicy::FULL,
                ),
                Err(PutError::Digest(DigestError::LogicalSizeMismatch {
                    expected,
                    actual: 3,
                }))
            );
            assert_encoded_refusal_clean(&layout, &mut store);
        }
    }

    #[test]
    fn h030_swallowed_sink_failure_cannot_publish_a_valid_prefix() {
        let layout = BlobStoreLayout::open(&fresh_root("sticky-refusal")).unwrap();
        let mut store = store();
        let decoder = |input: &mut dyn Read, output: &mut dyn Write| {
            std::io::copy(input, &mut std::io::sink()).map_err(|e| e.to_string())?;
            output.write_all(b"ok").map_err(|e| e.to_string())?;
            assert!(output.write_all(b"excess").is_err());
            assert!(output.flush().is_err());
            assert!(output.write(b"").is_err());
            // The accepted prefix has the expected identity, but a decoder
            // that ignores a refusal must NEVER turn that prefix into a hit.
            Ok(())
        };
        assert_eq!(
            put_encoded_representation(
                &layout,
                &mut store,
                &id_of(b"ok"),
                "broken-v1",
                &mut b"frame".as_slice(),
                &decoder,
                EncodedPutLimits {
                    max_logical_bytes: 2,
                    ..ENCODED_LIMITS
                },
                DurabilityPolicy::FULL,
            ),
            Err(PutError::LogicalLimitExceeded { limit: 2 })
        );
        assert_encoded_refusal_clean(&layout, &mut store);
    }

    #[test]
    fn h030_decoder_must_consume_complete_encoded_input() {
        let layout = BlobStoreLayout::open(&fresh_root("trailing-input")).unwrap();
        let mut store = store();
        let decoder = |_: &mut dyn Read, _: &mut dyn Write| Ok(());
        assert!(matches!(
            put_encoded_representation(
                &layout,
                &mut store,
                &id_of(b""),
                "empty-v1",
                &mut b"unconsumed suffix".as_slice(),
                &decoder,
                ENCODED_LIMITS,
                DurabilityPolicy::FULL,
            ),
            Err(PutError::EncodingDecodeFailed { .. })
        ));
        assert_encoded_refusal_clean(&layout, &mut store);
    }

    #[test]
    fn h030_exact_caps_accept_empty_and_multibuffer_objects() {
        for size in [0, 131_073] {
            let bytes = vec![42_u8; size];
            let encoded = xor_encode(&bytes);
            let layout = BlobStoreLayout::open(&fresh_root("exact-caps")).unwrap();
            let mut store = store();
            let (representation, outcome) = put_encoded_representation(
                &layout,
                &mut store,
                &id_of(&bytes),
                "xor-v1",
                &mut encoded.as_slice(),
                &xor_decoder,
                EncodedPutLimits {
                    max_encoded_bytes: size as u64,
                    max_logical_bytes: size as u64,
                    expected_encoded_size: Some(size as u64),
                    expected_logical_size: Some(size as u64),
                },
                DurabilityPolicy::FULL,
            )
            .unwrap();
            assert_eq!(representation.logical, id_of(&bytes));
            let PutOutcome::Stored { path } = outcome else {
                panic!("first representation must be stored");
            };
            assert_eq!(fs::read(path).unwrap(), encoded);
            assert_eq!(fs::read_dir(layout.staging_dir()).unwrap().count(), 0);
            assert_no_partial_published(&layout);
        }
    }

    #[test]
    fn h030_interrupted_encoded_read_is_retried() {
        struct InterruptedOnce<'a> {
            remaining: &'a [u8],
            interrupted: bool,
        }
        impl Read for InterruptedOnce<'_> {
            fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
                if !self.interrupted {
                    self.interrupted = true;
                    return Err(std::io::ErrorKind::Interrupted.into());
                }
                self.remaining.read(buf)
            }
        }
        let layout = BlobStoreLayout::open(&fresh_root("interrupted")).unwrap();
        let mut store = store();
        let encoded = xor_encode(b"retried");
        let mut source = InterruptedOnce {
            remaining: &encoded,
            interrupted: false,
        };
        assert!(put_encoded_representation(
            &layout,
            &mut store,
            &id_of(b"retried"),
            "xor-v1",
            &mut source,
            &xor_decoder,
            ENCODED_LIMITS,
            DurabilityPolicy::FULL,
        )
        .is_ok());
        assert_eq!(fs::read_dir(layout.staging_dir()).unwrap().count(), 0);
    }

    #[test]
    fn h030_decoder_unwind_cleans_owned_staging() {
        let layout = BlobStoreLayout::open(&fresh_root("decoder-unwind")).unwrap();
        let mut store = store();
        let decoder = |_: &mut dyn Read, _: &mut dyn Write| -> Result<(), String> {
            panic!("codec failed unexpectedly");
        };
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            put_encoded_representation(
                &layout,
                &mut store,
                &id_of(b"unused"),
                "panic-v1",
                &mut b"frame".as_slice(),
                &decoder,
                ENCODED_LIMITS,
                DurabilityPolicy::FULL,
            )
        }));
        assert!(result.is_err());
        assert_encoded_refusal_clean(&layout, &mut store);
    }

    #[test]
    fn h003_concurrent_writers_one_stores_rest_verify_idempotent() {
        let layout = BlobStoreLayout::open(&fresh_root("race")).unwrap();
        let bytes = b"contended object".to_vec();
        let declared = id_of(&bytes);

        let workers: Vec<_> = (0..8)
            .map(|_| {
                let layout = layout.clone();
                let bytes = bytes.clone();
                let declared = declared.clone();
                std::thread::spawn(move || {
                    // Each thread gets its own metadata store handle
                    // (in-memory): the filesystem is the contended
                    // resource under test.
                    let mut store = store();
                    put_if_absent(
                        &layout,
                        &mut store,
                        &declared,
                        &mut bytes.as_slice(),
                        PutLimits::default(),
                        DurabilityPolicy::FULL,
                    )
                })
            })
            .collect();
        let outcomes: Vec<_> = workers
            .into_iter()
            .map(|t| t.join().unwrap().unwrap())
            .collect();

        let stored = outcomes
            .iter()
            .filter(|o| matches!(o, PutOutcome::Stored { .. }))
            .count();
        assert_eq!(stored, 1, "exactly one writer wins the publish");
        assert_eq!(outcomes.len(), 8);
        let target = layout.published_path(&declared, RAW_PROFILE_V1, &declared);
        assert_eq!(fs::read(&target).unwrap(), bytes);
        // Every loser cleaned its temp.
        assert_eq!(fs::read_dir(layout.staging_dir()).unwrap().count(), 0);
        assert_no_partial_published(&layout);
    }
}
