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
//!    in one metadata transaction; the staging file is removed last (the
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

mod raw_target_observation;
pub use raw_target_observation::RawTargetObservation;

/// The storage profile this bead ships: bytes stored exactly as the
/// logical object (encoded digest == logical digest).
pub const RAW_PROFILE_V1: &str = "raw-v1";

/// Domain of encoded-representation digests (H030): the digest of the
/// ENCODED bytes, distinct by construction from the logical content
/// domain so an encoded digest can never pose as object identity.
pub const ENCODED_REPRESENTATION_DOMAIN: &str = "rabs.encoded-representation.sha256.v1";

/// A profile's decoder: encoded bytes → logical bytes (H030
/// verification input; errors are the profile's own diagnostics).
pub type RepresentationDecoder<'a> = &'a dyn Fn(&[u8]) -> Result<Vec<u8>, String>;

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

/// Typed put failures. Refusals remove the staging file; none of them
/// publish anything.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PutError {
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

/// Name suggestions. A restarted process can reuse both a PID and a sequence
/// number, so only exclusive filesystem creation establishes ownership.
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

    fn create_staging(&self, sequence: &AtomicU64) -> Result<(PathBuf, fs::File), PutError> {
        loop {
            let n = sequence.fetch_add(1, Ordering::Relaxed);
            let path = self
                .staging_dir()
                .join(format!("put-{}-{n}.tmp", std::process::id()));
            match create_private_file(&path) {
                Ok(file) => return Ok((path, file)),
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(error) => return Err(io_err("create-staging")(error)),
            }
        }
    }

    fn preserve_incoming(
        &self,
        staging: &Path,
        logical: &TypedDigest,
        sequence: &AtomicU64,
    ) -> Result<PathBuf, PutError> {
        loop {
            let n = sequence.fetch_add(1, Ordering::Relaxed);
            let candidate = self.quarantine_dir().join(format!(
                "incoming-{}-{}-{n}",
                hex(&logical.bytes),
                std::process::id()
            ));
            match fs::hard_link(staging, &candidate) {
                Ok(()) => return Ok(candidate),
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(error) => return Err(io_err("preserve-incoming")(error)),
            }
        }
    }
}

/// A staging name may still link to a published object after a crash.
/// Never reopen an existing inode for a fresh writer.
pub(crate) fn create_private_file(path: &Path) -> std::io::Result<fs::File> {
    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    options.open(path)
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
    let (staging, file) = layout.create_staging(&PUT_COUNTER)?;

    // 1. Stream to the private staging file, hashing while writing and
    // enforcing the logical cap as bytes arrive.
    let result = stream_to_staging(file, reader, limits);
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

/// Publish an already-verified raw staging file using a fresh destination
/// observation made without the metadata lock. All fsyncs, no-clobber linking,
/// metadata recording and collision handling remain in the ordinary publisher.
///
/// # Errors
/// As [`publish_staged`]. A stale or newly appeared duplicate is a typed step
/// error recognized by [`RawTargetObservation::changed`]; leave the stage intact
/// and reobserve only after releasing the store lock. Never fall back to hashing
/// an artifact under that lock on this path.
pub fn publish_staged_with_observation(
    layout: &BlobStoreLayout,
    store: &mut dyn RabsMetadataStore,
    declared: &TypedDigest,
    staging: &Path,
    durability: DurabilityPolicy,
    observation: &RawTargetObservation,
) -> Result<PutOutcome, PutError> {
    observation.check_binding(
        &layout.published_path(declared, RAW_PROFILE_V1, declared),
        declared,
    )?;
    let logical_size = fs::metadata(staging).map_err(io_err("stat-staging"))?.len();
    publish_staged_observed_inner(
        layout,
        store,
        declared,
        staging,
        logical_size,
        durability,
        None,
        RAW_PROFILE_V1,
        declared,
        Some(observation),
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
    publish_staged_observed_inner(
        layout,
        store,
        declared,
        staging,
        logical_size,
        durability,
        fault,
        profile,
        file_digest,
        None,
    )
}

#[allow(clippy::too_many_arguments)]
fn publish_staged_observed_inner(
    layout: &BlobStoreLayout,
    store: &mut dyn RabsMetadataStore,
    declared: &TypedDigest,
    staging: &Path,
    logical_size: u64,
    durability: DurabilityPolicy,
    fault: Option<FaultPoint>,
    profile: &str,
    file_digest: &TypedDigest,
    observation: Option<&RawTargetObservation>,
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
                observation,
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

    // 5. Record object + location in one transaction; encoding tag is the
    // profile. The location claims durability only when the policy actually
    // was the full profile (H032).
    store.record_object_location(
        declared,
        logical_size,
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

/// H030: publish one ENCODED representation of an already-known
/// logical object. The encoded bytes stream to staging while their
/// digest (under [`ENCODED_REPRESENTATION_DOMAIN`]) is computed; the
/// representation is then VERIFIED — `decoder` must reproduce bytes
/// that digest to `declared_logical` (raw callers use
/// [`put_if_absent`] instead) — before the standard atomic publish at
/// the representation's own `(logical, profile, encoded)` pathname.
/// `limits.max_logical_bytes` caps the DECODED size (bomb guard);
/// `limits.expected_size` verifies the ENCODED byte count.
///
/// # Errors
/// Typed [`PutError`]; refusals publish nothing and clean staging.
#[allow(clippy::too_many_arguments)]
pub fn put_encoded_representation(
    layout: &BlobStoreLayout,
    store: &mut dyn RabsMetadataStore,
    declared_logical: &TypedDigest,
    profile: &str,
    encoded: &mut dyn Read,
    decoder: RepresentationDecoder<'_>,
    limits: PutLimits,
    durability: DurabilityPolicy,
) -> Result<(StoredRepresentationId, PutOutcome), PutError> {
    let (staging, mut file) = layout.create_staging(&PUT_COUNTER)?;

    // Stream encoded bytes to staging, hashing under the ENCODED
    // domain and counting encoded size.
    let stream = (|| -> Result<(TypedDigest, u64), PutError> {
        use sha2::{Digest as _, Sha256};
        let mut hasher = Sha256::new();
        hasher.update((ENCODED_REPRESENTATION_DOMAIN.len() as u64).to_be_bytes());
        hasher.update(ENCODED_REPRESENTATION_DOMAIN.as_bytes());
        let mut buffer = vec![0_u8; 64 * 1024];
        let mut total: u64 = 0;
        loop {
            let n = encoded.read(&mut buffer).map_err(io_err("read-encoded"))?;
            if n == 0 {
                break;
            }
            total = total.saturating_add(n as u64);
            hasher.update(&buffer[..n]);
            file.write_all(&buffer[..n])
                .map_err(io_err("write-staging"))?;
        }
        if let Some(expected) = limits.expected_size
            && expected != total
        {
            return Err(PutError::Digest(DigestError::LogicalSizeMismatch {
                expected,
                actual: total,
            }));
        }
        Ok((
            TypedDigest {
                algorithm: rabs_protocol::result_identity::DigestAlgorithm::Sha256V1,
                domain: ENCODED_REPRESENTATION_DOMAIN,
                bytes: hasher.finalize().into(),
            },
            total,
        ))
    })();
    drop(file);
    let (encoded_digest, encoded_size) = match stream {
        Ok(v) => v,
        Err(e) => {
            let _ = fs::remove_file(&staging);
            return Err(e);
        }
    };

    // VERIFY: the representation must decode to the declared logical
    // object; the decoded size honors the bomb guard.
    let verify = (|| -> Result<u64, PutError> {
        let encoded_bytes = fs::read(&staging).map_err(io_err("read-staged"))?;
        let logical_bytes =
            decoder(&encoded_bytes).map_err(|error| PutError::EncodingDecodeFailed {
                profile: profile.to_owned(),
                error,
            })?;
        if let Some(limit) = limits.max_logical_bytes
            && logical_bytes.len() as u64 > limit
        {
            return Err(PutError::LogicalLimitExceeded { limit });
        }
        let computed = crate::digest_set::digest_set(
            &logical_bytes,
            crate::digest_set::DigestRequest::default(),
            None,
        )
        .map_err(PutError::Digest)?
        .atp_content_id;
        if computed != *declared_logical {
            return Err(PutError::DeclaredDigestMismatch {
                declared: digest_key(declared_logical),
                computed: digest_key(&computed),
            });
        }
        Ok(logical_bytes.len() as u64)
    })();
    let logical_size = match verify {
        Ok(v) => v,
        Err(e) => {
            let _ = fs::remove_file(&staging);
            return Err(e);
        }
    };

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

pub(crate) fn stream_to_staging(
    mut file: fs::File,
    reader: &mut dyn Read,
    limits: PutLimits,
) -> Result<crate::digest_set::DigestSet, PutError> {
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
    observation: Option<&RawTargetObservation>,
) -> Result<PutOutcome, PutError> {
    let existing_digest = match observation {
        Some(observation) => observation.digest(target, file_digest)?,
        None => hash_file_under_domain(target, file_digest.domain)?,
    };
    if existing_digest == *file_digest {
        // Identical representation already published. Make sure the
        // metadata rows exist (the original writer may have died
        // between link and record), then clean OUR temp — the race
        // loser's duty. The original writer's fsync state is UNKNOWN
        // (it may have died before the directory sync), so under the
        // full profile the loser fsyncs the published copy itself
        // before this location may claim durability (H032).
        if durability.is_full() {
            if let Some(observation) = observation {
                observation.sync(target, file_digest)?;
            } else {
                let file = fs::File::open(target).map_err(io_err("fsync-existing"))?;
                file.sync_all().map_err(io_err("fsync-existing"))?;
            }
            if let Some(dir) = target.parent() {
                let dir = fs::File::open(dir).map_err(io_err("fsync-existing-dir"))?;
                dir.sync_all().map_err(io_err("fsync-existing-dir"))?;
            }
        }
        if let Some(observation) = observation {
            observation.validate(target, file_digest)?;
        }
        store.record_object_location(
            declared,
            logical_size,
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
    // incoming bytes get a new, exclusive link beside older incident evidence.
    if let Some(observation) = observation {
        observation.validate(target, file_digest)?;
    }
    let preserved = layout.preserve_incoming(staging, declared, &PUT_COUNTER)?;
    if durability.fsync_directory {
        fs::File::open(layout.quarantine_dir())
            .and_then(|directory| directory.sync_all())
            .map_err(io_err("fsync-quarantine-dir"))?;
    }
    store.add_quarantine(
        QuarantineScope::LogicalObject,
        &digest_key(declared),
        REASON_OBJECT_COLLISION_QUARANTINED,
    )?;
    // Flag every implicated location row (the published copy is now
    // suspect evidence, not identity).
    store.set_location_quarantined(declared, &target.to_string_lossy(), true)?;
    let _ = fs::remove_file(staging);
    Err(PutError::CollisionIncident {
        digest: digest_key(declared),
        existing_path: target.to_string_lossy().into_owned(),
        preserved_incoming_path: preserved.to_string_lossy().into_owned(),
    })
}

/// Outcome of publishing one object under the H005 compression policy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyPutOutcome {
    /// Policy decision applied to this object.
    pub decision: crate::compression_policy::CompressionDecision,
    /// Resulting publish outcome (`Stored` or `IdempotentDuplicate`).
    pub outcome: PutOutcome,
    /// Logical (uncompressed) byte length.
    pub logical_bytes: u64,
    /// Stored (encoded or raw) byte length.
    pub encoded_bytes: u64,
    /// Storage profile recorded in `object_locations` (`raw-v1` or compressed profile).
    pub storage_profile: String,
}

/// Outcome of publishing a deterministic H021 `RBSPACK1` small-object pack.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PackedPutOutcome {
    /// Content digest of the published pack blob itself.
    pub pack_digest: TypedDigest,
    /// On-disk path of the published pack blob.
    pub pack_path: String,
    /// Number of deduplicated logical members indexed inside the pack.
    pub member_count: usize,
    /// Total byte length of the published pack blob.
    pub pack_bytes: u64,
}

/// Result of attempting to decode a non-raw, non-pack encoded CAS object in
/// [`read_verified_object`].
///
/// Separating [`Self::UnsupportedEncoding`] from [`Self::Corrupt`] guarantees
/// that a reader lacking a codec for a valid representation (e.g. `zstd-3`)
/// skips that replica instead of falsely quarantining healthy data.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DecodedObject {
    /// Decoded logical bytes ready for content-digest verification.
    Decoded(Vec<u8>),
    /// Caller does not support this storage profile; do NOT quarantine.
    UnsupportedEncoding,
    /// Encoded payload is corrupt or exceeds bounds; quarantine this location.
    Corrupt(String),
}

fn is_valid_encoded_profile_tag(tag: &str) -> bool {
    !tag.is_empty()
        && tag.len() <= 64
        && tag != RAW_PROFILE_V1
        && tag != crate::pack::PACK_PROFILE_V1
        && !tag.contains("..")
        && tag
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
}

/// H005 + H030 live write helper: decide raw vs encoded storage via
/// [`crate::compression_policy::decide`], publish through
/// [`put_if_absent`] or [`put_encoded_representation`] (falling back to raw if
/// the encoded output is not strictly smaller than the logical bytes), and
/// optionally meter the outcome into [`crate::compression_policy::CompressionMetrics`].
///
/// # Errors
/// Typed [`PutError`]; refusals publish nothing and leave staging clean.
#[allow(clippy::too_many_arguments)]
pub fn put_with_compression_policy<E>(
    layout: &BlobStoreLayout,
    store: &mut dyn RabsMetadataStore,
    declared: &TypedDigest,
    class: crate::compression_policy::ObjectClass,
    pressure: crate::compression_policy::CpuPressure,
    logical_bytes: &[u8],
    encoder: E,
    decoder: RepresentationDecoder<'_>,
    limits: PutLimits,
    durability: DurabilityPolicy,
    metrics: Option<&mut crate::compression_policy::CompressionMetrics>,
) -> Result<PolicyPutOutcome, PutError>
where
    E: FnOnce(
        &[u8],
        crate::compression_policy::CompressionProfile,
    ) -> Result<(String, Vec<u8>), String>,
{
    use crate::compression_policy::{CompressionDecision, SkipReason};

    let logical_len = logical_bytes.len() as u64;
    if let Some(limit) = limits.max_logical_bytes
        && logical_len > limit
    {
        return Err(PutError::LogicalLimitExceeded { limit });
    }
    if let Some(expected) = limits.expected_size
        && expected != logical_len
    {
        return Err(PutError::Digest(DigestError::LogicalSizeMismatch {
            expected,
            actual: logical_len,
        }));
    }

    let decision = crate::compression_policy::decide(class, logical_len, logical_bytes, pressure);
    match decision {
        CompressionDecision::Skip(_) => {
            let mut slice = logical_bytes;
            let outcome = put_if_absent(layout, store, declared, &mut slice, limits, durability)?;
            if let Some(m) = metrics {
                m.record(decision, logical_len, logical_len, 0);
            }
            Ok(PolicyPutOutcome {
                decision,
                outcome,
                logical_bytes: logical_len,
                encoded_bytes: logical_len,
                storage_profile: RAW_PROFILE_V1.to_owned(),
            })
        }
        CompressionDecision::Compress(profile) => {
            let start = std::time::Instant::now();
            let (profile_tag, encoded) = encoder(logical_bytes, profile).map_err(|error| {
                PutError::EncodingDecodeFailed {
                    profile: profile.name.to_owned(),
                    error,
                }
            })?;
            let cpu_micros = u64::try_from(start.elapsed().as_micros()).unwrap_or(u64::MAX);
            if !is_valid_encoded_profile_tag(&profile_tag) {
                return Err(PutError::EncodingDecodeFailed {
                    profile: profile_tag,
                    error: "invalid or reserved encoded storage profile tag".to_owned(),
                });
            }
            // Economic guard: never store an encoded copy that is not strictly
            // smaller than raw bytes.
            if encoded.len() >= logical_bytes.len() {
                let mut slice = logical_bytes;
                let outcome =
                    put_if_absent(layout, store, declared, &mut slice, limits, durability)?;
                let fallback_decision = CompressionDecision::Skip(SkipReason::AlreadyCompressed);
                if let Some(m) = metrics {
                    m.record(fallback_decision, logical_len, logical_len, cpu_micros);
                }
                return Ok(PolicyPutOutcome {
                    decision: fallback_decision,
                    outcome,
                    logical_bytes: logical_len,
                    encoded_bytes: logical_len,
                    storage_profile: RAW_PROFILE_V1.to_owned(),
                });
            }
            let encoded_len = encoded.len() as u64;
            let encoded_limits = PutLimits {
                max_logical_bytes: limits.max_logical_bytes.or(Some(logical_len)),
                expected_size: Some(encoded_len),
            };
            let mut slice = encoded.as_slice();
            let (rep, outcome) = put_encoded_representation(
                layout,
                store,
                declared,
                &profile_tag,
                &mut slice,
                decoder,
                encoded_limits,
                durability,
            )?;
            if let Some(m) = metrics {
                m.record(decision, logical_len, rep.encoded_size, cpu_micros);
            }
            Ok(PolicyPutOutcome {
                decision,
                outcome,
                logical_bytes: logical_len,
                encoded_bytes: rep.encoded_size,
                storage_profile: rep.storage_profile,
            })
        }
    }
}

/// H021 live write helper: build a deterministic canonical `RBSPACK1` pack from
/// small logical objects, publish the pack blob atomically via [`put_if_absent`],
/// and record `pack-v1` member location rows pointing into the published pack.
///
/// # Errors
/// [`PutError::Io`] / [`PutError::Digest`] / [`PutError::Store`] if packing or
/// publication fails.
pub fn put_packed_members(
    layout: &BlobStoreLayout,
    store: &mut dyn RabsMetadataStore,
    members: &[(TypedDigest, &[u8])],
    durability: DurabilityPolicy,
) -> Result<PackedPutOutcome, PutError> {
    let pack_bytes = crate::pack::build_pack(members).map_err(|error| PutError::Io {
        step: "build-pack",
        error: format!("{error:?}"),
    })?;
    let pack_index = crate::pack::PackIndex::parse(&pack_bytes).map_err(|error| PutError::Io {
        step: "parse-pack",
        error: format!("{error:?}"),
    })?;
    let pack_digest = crate::digest_set::digest_set(&pack_bytes, DigestRequest::default(), None)
        .map_err(PutError::Digest)?
        .atp_content_id;
    let pack_len = pack_bytes.len() as u64;
    let mut slice = pack_bytes.as_slice();
    let outcome = put_if_absent(
        layout,
        store,
        &pack_digest,
        &mut slice,
        PutLimits {
            max_logical_bytes: Some(pack_len),
            expected_size: Some(pack_len),
        },
        durability,
    )?;
    let pack_path = match outcome {
        PutOutcome::Stored { path } | PutOutcome::IdempotentDuplicate { path } => path,
    };
    let mut seen_keys = std::collections::BTreeSet::new();
    let member_digests: Vec<TypedDigest> = members
        .iter()
        .filter(|(d, _)| seen_keys.insert(digest_key(d)))
        .map(|(d, _)| d.clone())
        .collect();
    crate::pack::record_pack_member_locations(
        store,
        &pack_path,
        &pack_index,
        &member_digests,
        durability.is_full(),
    )?;
    Ok(PackedPutOutcome {
        pack_digest,
        pack_path,
        member_count: pack_index.members.len(),
        pack_bytes: pack_len,
    })
}

/// Read and cryptographically verify one logical object across `raw-v1`,
/// `pack-v1`, and encoded compression profiles.
///
/// Enforces logical-object quarantine up front; any regular file whose bytes do
/// not decode/digest back to `object` is quarantined at the location scope
/// before trying the next replica. Replicas whose encoding is unrecognized by
/// `decode_encoded` (`DecodedObject::UnsupportedEncoding`) are skipped without
/// quarantine. Never follows symlinks or opens FIFOs.
///
/// # Errors
/// Store errors from reading quarantine/location rows or flagging a corrupt replica.
pub fn read_verified_object<D>(
    store: &mut dyn RabsMetadataStore,
    object: &TypedDigest,
    max_logical_bytes: u64,
    mut decode_encoded: D,
) -> Result<Option<Vec<u8>>, StoreError>
where
    D: FnMut(&str, &[u8]) -> DecodedObject,
{
    if !store
        .query(
            "SELECT 1 FROM quarantines WHERE scope = 'logical-object' AND subject = ?1 LIMIT 1",
            &[crate::metadata_store::SqlValue::Text(digest_key(object))],
        )?
        .is_empty()
    {
        return Ok(None);
    }
    let locations = store.object_locations(object)?;
    for (path, encoding, _) in locations {
        if encoding == RAW_PROFILE_V1 {
            let Some(bytes) = read_regular_bounded(&path, max_logical_bytes) else {
                continue;
            };
            if verify_logical_bytes(&bytes, object) {
                return Ok(Some(bytes));
            }
            store.set_location_quarantined(object, &path, true)?;
            continue;
        }
        if encoding == crate::pack::PACK_PROFILE_V1 {
            let Some((pack_path, offset_str)) = path.rsplit_once('#') else {
                store.set_location_quarantined(object, &path, true)?;
                continue;
            };
            let Ok(declared_offset) = offset_str.parse::<u64>() else {
                store.set_location_quarantined(object, &path, true)?;
                continue;
            };
            let max_pack_bytes = max_logical_bytes
                .saturating_add(crate::pack::MAX_PACK_INDEX_BYTES)
                .saturating_add(64 << 20);
            let Some(pack_bytes) = read_regular_bounded(pack_path, max_pack_bytes) else {
                continue;
            };
            let Ok(index) = crate::pack::PackIndex::parse(&pack_bytes) else {
                store.set_location_quarantined(object, &path, true)?;
                continue;
            };
            let key = digest_key(object);
            let offset_matches = index
                .members
                .binary_search_by(|m| m.key.as_str().cmp(key.as_str()))
                .ok()
                .is_some_and(|i| index.members[i].offset == declared_offset);
            if !offset_matches {
                store.set_location_quarantined(object, &path, true)?;
                continue;
            }
            let Some(member) = index.member_bytes(&pack_bytes, object) else {
                store.set_location_quarantined(object, &path, true)?;
                continue;
            };
            if member.len() as u64 <= max_logical_bytes && verify_logical_bytes(member, object) {
                return Ok(Some(member.to_vec()));
            }
            store.set_location_quarantined(object, &path, true)?;
            continue;
        }
        // Encoded representation (e.g. zstd-3, zstd-1, deflate-v1). Allow small
        // framing headroom on disk while still enforcing `max_logical_bytes` on
        // the decoded logical output.
        let Some(encoded_bytes) =
            read_regular_bounded(&path, max_logical_bytes.saturating_add(4096))
        else {
            continue;
        };
        match decode_encoded(&encoding, &encoded_bytes) {
            DecodedObject::Decoded(decoded) => {
                if decoded.len() as u64 <= max_logical_bytes
                    && verify_logical_bytes(&decoded, object)
                {
                    return Ok(Some(decoded));
                }
                store.set_location_quarantined(object, &path, true)?;
            }
            DecodedObject::UnsupportedEncoding => {
                continue;
            }
            DecodedObject::Corrupt(_) => {
                store.set_location_quarantined(object, &path, true)?;
            }
        }
    }
    Ok(None)
}

fn read_regular_bounded(path: &str, max_bytes: u64) -> Option<Vec<u8>> {
    if !fs::symlink_metadata(path).is_ok_and(|meta| meta.file_type().is_file()) {
        return None;
    }
    let file = fs::File::open(path).ok()?;
    let mut bytes = Vec::new();
    file.take(max_bytes.saturating_add(1))
        .read_to_end(&mut bytes)
        .ok()?;
    (bytes.len() as u64 <= max_bytes).then_some(bytes)
}

fn verify_logical_bytes(bytes: &[u8], expected: &TypedDigest) -> bool {
    crate::digest_set::digest_set(bytes, DigestRequest::default(), None)
        .is_ok_and(|digests| digests.atp_content_id == *expected)
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

    #[test]
    fn a_restarted_writer_preserves_both_collision_records() {
        let root = tempfile::tempdir().unwrap();
        let layout = BlobStoreLayout::open(root.path()).unwrap();
        let declared = id_of(b"contested");
        let preserve = |bytes: &[u8]| {
            let (stage, mut file) = layout.create_staging(&AtomicU64::new(0)).unwrap();
            file.write_all(bytes).unwrap();
            drop(file);
            let evidence = layout
                .preserve_incoming(&stage, &declared, &AtomicU64::new(0))
                .unwrap();
            fs::remove_file(stage).unwrap();
            evidence
        };
        let first = preserve(b"earlier observation");
        let second = preserve(b"later observation");
        assert_ne!(first, second);
        assert_eq!(fs::read(first).unwrap(), b"earlier observation");
        assert_eq!(fs::read(second).unwrap(), b"later observation");
    }

    #[test]
    fn restarting_stage_sequence_preserves_a_linked_object() {
        let root = tempfile::tempdir().unwrap();
        let layout = BlobStoreLayout::open(root.path()).unwrap();
        let old = b"first durable object";
        let declared = id_of(old);
        let (leftover, mut file) = layout.create_staging(&AtomicU64::new(0)).unwrap();
        file.write_all(old).unwrap();
        drop(file);
        let published = layout.published_path(&declared, RAW_PROFILE_V1, &declared);
        fs::create_dir_all(published.parent().unwrap()).unwrap();
        fs::hard_link(&leftover, &published).unwrap();

        // Same PID and counter after restart, with the post-link cleanup pending.
        let (new_path, file) = layout.create_staging(&AtomicU64::new(0)).unwrap();
        assert_ne!(new_path, leftover);
        let new = b"another build result";
        let digests = stream_to_staging(file, &mut new.as_slice(), PutLimits::default()).unwrap();
        assert_eq!(digests.atp_content_id, id_of(new));
        assert_eq!(fs::read(&new_path).unwrap(), new);
        assert_eq!(fs::read(&leftover).unwrap(), old);
        assert_eq!(fs::read(&published).unwrap(), old);
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
    fn duplicate_ingestion_preserves_location_quarantine_and_accepts_clean_replica() {
        let layout = BlobStoreLayout::open(&fresh_root("quarantined-duplicate")).unwrap();
        let alternate = BlobStoreLayout::open(&fresh_root("clean-replica")).unwrap();
        let mut store = store();
        let bytes = b"verified bytes on a disk under investigation";
        let declared = id_of(bytes);
        let PutOutcome::Stored { path } = put_if_absent(
            &layout,
            &mut store,
            &declared,
            &mut bytes.as_slice(),
            PutLimits::default(),
            DurabilityPolicy::FULL,
        )
        .unwrap() else {
            panic!("first ingestion must store a new copy");
        };
        store
            .set_location_quarantined(&declared, &path, true)
            .unwrap();

        // The duplicate path rehashes the existing representation and may
        // still report idempotent ingestion. That check does not adjudicate
        // a device/incident quarantine or make this copy selectable again.
        assert_eq!(
            put_if_absent(
                &layout,
                &mut store,
                &declared,
                &mut bytes.as_slice(),
                PutLimits::default(),
                DurabilityPolicy::FULL,
            )
            .unwrap(),
            PutOutcome::IdempotentDuplicate { path: path.clone() }
        );
        assert_eq!(fs::read(&path).unwrap(), bytes);
        assert!(!store.object_located(&declared).unwrap());
        assert!(!store.object_durably_located(&declared).unwrap());
        assert!(store.object_locations(&declared).unwrap().is_empty());

        // Quarantine belongs to one copy. A separately verified, durable
        // replica restores availability without clearing the suspect one.
        let PutOutcome::Stored {
            path: alternate_path,
        } = put_if_absent(
            &alternate,
            &mut store,
            &declared,
            &mut bytes.as_slice(),
            PutLimits::default(),
            DurabilityPolicy::FULL,
        )
        .unwrap()
        else {
            panic!("alternate storage must receive a new copy");
        };
        assert!(store.object_durably_located(&declared).unwrap());
        assert_eq!(
            store.object_locations(&declared).unwrap(),
            vec![(alternate_path, RAW_PROFILE_V1.to_owned(), true)]
        );
        assert!(
            store
                .reconciliation_scan()
                .unwrap()
                .iter()
                .any(|row| row.store_path == path && row.quarantined)
        );
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

    /// Test profile: bytes stored reversed.
    fn rev_encode(bytes: &[u8]) -> Vec<u8> {
        bytes.iter().rev().copied().collect()
    }

    fn rev_decoder(encoded: &[u8]) -> Result<Vec<u8>, String> {
        Ok(encoded.iter().rev().copied().collect())
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
        let encoded = rev_encode(&bytes);
        let (representation, outcome) = put_encoded_representation(
            &layout,
            &mut store,
            &declared,
            "rev-v1",
            &mut encoded.as_slice(),
            &rev_decoder,
            PutLimits {
                max_logical_bytes: Some(1024),
                expected_size: Some(encoded.len() as u64),
            },
            DurabilityPolicy::FULL,
        )
        .unwrap();
        let PutOutcome::Stored { path: rev_path } = outcome else {
            panic!("encoded put must store");
        };

        // Distinct unambiguous pathnames; encoded bytes live at the
        // encoded path; the representation names everything.
        assert_ne!(raw_path, rev_path);
        assert_eq!(fs::read(&rev_path).unwrap(), encoded);
        assert_eq!(representation.storage_profile, "rev-v1");
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
        assert!(encodings.contains(&"rev-v1".to_owned()));

        // Re-put of the same encoded representation: verified
        // idempotent against the ENCODED digest.
        let (_, again) = put_encoded_representation(
            &layout,
            &mut store,
            &declared,
            "rev-v1",
            &mut encoded.as_slice(),
            &rev_decoder,
            PutLimits::default(),
            DurabilityPolicy::FULL,
        )
        .unwrap();
        assert_eq!(again, PutOutcome::IdempotentDuplicate { path: rev_path });
        assert_eq!(fs::read_dir(layout.staging_dir()).unwrap().count(), 0);
    }

    #[test]
    fn h030_decode_verification_refuses_wrong_and_bombing_representations() {
        let layout = BlobStoreLayout::open(&fresh_root("h030-verify")).unwrap();
        let mut store = store();
        let bytes = b"verified object".to_vec();
        let declared = id_of(&bytes);
        let encoded = rev_encode(&bytes);

        // Decoder that produces the WRONG logical bytes: refused, and
        // nothing published anywhere.
        let bad_decoder = |_: &[u8]| -> Result<Vec<u8>, String> { Ok(b"other bytes".to_vec()) };
        assert!(matches!(
            put_encoded_representation(
                &layout,
                &mut store,
                &declared,
                "rev-v1",
                &mut encoded.as_slice(),
                &bad_decoder,
                PutLimits::default(),
                DurabilityPolicy::FULL,
            ),
            Err(PutError::DeclaredDigestMismatch { .. })
        ));

        // Decoder failure is typed.
        let failing = |_: &[u8]| -> Result<Vec<u8>, String> { Err("truncated frame".to_owned()) };
        assert!(matches!(
            put_encoded_representation(
                &layout,
                &mut store,
                &declared,
                "rev-v1",
                &mut encoded.as_slice(),
                &failing,
                PutLimits::default(),
                DurabilityPolicy::FULL,
            ),
            Err(PutError::EncodingDecodeFailed { .. })
        ));

        // Decompression bomb: decoded bytes exceed the logical cap.
        let bomb = |_: &[u8]| -> Result<Vec<u8>, String> { Ok(vec![0_u8; 4096]) };
        assert_eq!(
            put_encoded_representation(
                &layout,
                &mut store,
                &declared,
                "bomb-v1",
                &mut encoded.as_slice(),
                &bomb,
                PutLimits {
                    max_logical_bytes: Some(64),
                    expected_size: None,
                },
                DurabilityPolicy::FULL,
            ),
            Err(PutError::LogicalLimitExceeded { limit: 64 })
        );

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
                        let encoded = rev_encode(&bytes);
                        put_encoded_representation(
                            &layout,
                            &mut store,
                            &declared,
                            "rev-v1",
                            &mut encoded.as_slice(),
                            &rev_decoder,
                            PutLimits::default(),
                            DurabilityPolicy::FULL,
                        )
                        .map(|(_, outcome)| ("rev-v1", outcome))
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
        for profile in ["raw-v1", "rev-v1"] {
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
        let encoded = rev_encode(&bytes);
        put_encoded_representation(
            &layout,
            &mut store,
            &declared,
            "rev-v1",
            &mut encoded.as_slice(),
            &rev_decoder,
            PutLimits::default(),
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

    #[test]
    fn h005_policy_put_skips_tiny_and_precompressed_and_round_trips_encoded() {
        use crate::compression_policy::{
            CompressionDecision, CompressionMetrics, CpuPressure, ObjectClass, SkipReason,
        };

        let layout = BlobStoreLayout::open(&fresh_root("policy-put")).unwrap();
        let mut store = store();
        let mut metrics = CompressionMetrics::default();

        // Simple deterministic RLE-style test codec (shrinks repetitive data).
        let encode = |input: &[u8], _profile: crate::compression_policy::CompressionProfile| {
            let mut out = Vec::new();
            let mut i = 0;
            while i < input.len() {
                let b = input[i];
                let mut run = 1u8;
                while i + usize::from(run) < input.len()
                    && input[i + usize::from(run)] == b
                    && run < 255
                {
                    run += 1;
                }
                out.push(run);
                out.push(b);
                i += usize::from(run);
            }
            Ok(("rle-test-v1".to_owned(), out))
        };
        let decode = |encoded: &[u8]| -> Result<Vec<u8>, String> {
            if !encoded.len().is_multiple_of(2) {
                return Err("odd rle buffer".to_owned());
            }
            let mut out = Vec::new();
            for pair in encoded.as_chunks::<2>().0 {
                out.extend(std::iter::repeat_n(pair[1], usize::from(pair[0])));
            }
            Ok(out)
        };

        // 1. Tiny payload skips compression and stores raw.
        let tiny = b"tiny dep-info";
        let tiny_id = id_of(tiny);
        let tiny_res = put_with_compression_policy(
            &layout,
            &mut store,
            &tiny_id,
            ObjectClass::DepInfo,
            CpuPressure::Low,
            tiny,
            encode,
            &decode,
            PutLimits::default(),
            DurabilityPolicy::FULL,
            Some(&mut metrics),
        )
        .unwrap();
        assert_eq!(
            tiny_res.decision,
            CompressionDecision::Skip(SkipReason::Tiny)
        );
        assert_eq!(tiny_res.storage_profile, RAW_PROFILE_V1);

        // 2. Large compressible payload compresses and verifies on read.
        let big = vec![b'A'; 16 * 1024];
        let big_id = id_of(&big);
        let big_res = put_with_compression_policy(
            &layout,
            &mut store,
            &big_id,
            ObjectClass::CompilerArtifact,
            CpuPressure::Low,
            &big,
            encode,
            &decode,
            PutLimits::default(),
            DurabilityPolicy::FULL,
            Some(&mut metrics),
        )
        .unwrap();
        assert!(matches!(big_res.decision, CompressionDecision::Compress(_)));
        assert_eq!(big_res.storage_profile, "rle-test-v1");
        assert!(big_res.encoded_bytes < big_res.logical_bytes);

        // Unsupported encoding must NOT quarantine the healthy encoded replica.
        let skipped = read_verified_object(&mut store, &big_id, 32 * 1024, |_, _| {
            DecodedObject::UnsupportedEncoding
        })
        .unwrap();
        assert_eq!(skipped, None);
        assert_eq!(
            store.object_locations(&big_id).unwrap().len(),
            1,
            "unsupported encoding must leave healthy replica unquarantined"
        );

        let loaded = read_verified_object(&mut store, &big_id, 32 * 1024, |enc, bytes| {
            if enc == "rle-test-v1" {
                decode(bytes).map_or_else(DecodedObject::Corrupt, DecodedObject::Decoded)
            } else {
                DecodedObject::UnsupportedEncoding
            }
        })
        .unwrap()
        .expect("compressed object must read back verified");
        assert_eq!(loaded, big);
        assert_eq!(metrics.compressed_objects, 1);
        assert_eq!(metrics.skipped_objects, 1);

        // Regression: PutLimits must be enforced upfront on the Compress path,
        // and reserved/unsafe profile tags must be refused.
        assert!(matches!(
            put_with_compression_policy(
                &layout,
                &mut store,
                &big_id,
                ObjectClass::CompilerArtifact,
                CpuPressure::Low,
                &big,
                encode,
                &decode,
                PutLimits {
                    max_logical_bytes: Some(1024),
                    expected_size: None,
                },
                DurabilityPolicy::FULL,
                None,
            ),
            Err(PutError::LogicalLimitExceeded { limit: 1024 })
        ));
        assert!(matches!(
            put_with_compression_policy(
                &layout,
                &mut store,
                &big_id,
                ObjectClass::CompilerArtifact,
                CpuPressure::Low,
                &big,
                encode,
                &decode,
                PutLimits {
                    max_logical_bytes: None,
                    expected_size: Some(123),
                },
                DurabilityPolicy::FULL,
                None,
            ),
            Err(PutError::Digest(DigestError::LogicalSizeMismatch {
                expected: 123,
                ..
            }))
        ));
        assert!(matches!(
            put_with_compression_policy(
                &layout,
                &mut store,
                &big_id,
                ObjectClass::CompilerArtifact,
                CpuPressure::Low,
                &big,
                |_, _| Ok(("../escape".to_owned(), vec![1, 2, 3])),
                &decode,
                PutLimits::default(),
                DurabilityPolicy::FULL,
                None,
            ),
            Err(PutError::EncodingDecodeFailed { .. })
        ));
    }

    #[test]
    fn h021_packed_members_put_read_and_quarantine_corrupt_pack_member() {
        let layout = BlobStoreLayout::open(&fresh_root("pack-put")).unwrap();
        let mut store = store();
        let a = b"dep-info-a: src/lib.rs\n";
        let b = b"dep-info-b: src/main.rs\n";
        let a_id = id_of(a);
        let b_id = id_of(b);

        // Include duplicate `a` to verify deduplication in put_packed_members.
        let packed = put_packed_members(
            &layout,
            &mut store,
            &[
                (a_id.clone(), a.as_slice()),
                (b_id.clone(), b.as_slice()),
                (a_id.clone(), a.as_slice()),
            ],
            DurabilityPolicy::FULL,
        )
        .unwrap();
        assert_eq!(packed.member_count, 2);
        assert!(Path::new(&packed.pack_path).is_file());

        let got_a = read_verified_object(&mut store, &a_id, 4096, |_, _| {
            DecodedObject::UnsupportedEncoding
        })
        .unwrap()
        .expect("member a must load from pack");
        let got_b = read_verified_object(&mut store, &b_id, 4096, |_, _| {
            DecodedObject::UnsupportedEncoding
        })
        .unwrap()
        .expect("member b must load from pack");
        assert_eq!(got_a, a);
        assert_eq!(got_b, b);

        // Corrupt the pack payload on disk: reading refuses and quarantines the location.
        let mut raw_pack = fs::read(&packed.pack_path).unwrap();
        *raw_pack.last_mut().unwrap() ^= 0xff;
        fs::write(&packed.pack_path, &raw_pack).unwrap();
        let corrupt = read_verified_object(&mut store, &b_id, 4096, |_, _| {
            DecodedObject::UnsupportedEncoding
        })
        .unwrap();
        assert_eq!(corrupt, None);
        assert!(store.object_locations(&b_id).unwrap().is_empty());
    }
}
