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

    // 5. Record object + location; encoding tag is the profile.
    store.record_object(declared, logical_size)?;
    store.add_location(declared, &target.to_string_lossy(), None, profile)?;
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
    let staging = layout.fresh_staging_path();

    // Stream encoded bytes to staging, hashing under the ENCODED
    // domain and counting encoded size.
    let stream = (|| -> Result<(TypedDigest, u64), PutError> {
        use sha2::{Digest as _, Sha256};
        let mut file = fs::File::create(&staging).map_err(io_err("create-staging"))?;
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
) -> Result<PutOutcome, PutError> {
    let existing_digest = hash_file_under_domain(target, file_digest.domain)?;
    if existing_digest == *file_digest {
        // Identical representation already published. Make sure the
        // metadata rows exist (the original writer may have died
        // between link and record), then clean OUR temp — the race
        // loser's duty.
        store.record_object(declared, logical_size)?;
        store.add_location(declared, &target.to_string_lossy(), None, profile)?;
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
}
