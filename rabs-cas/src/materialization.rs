//! Materialization: turning a committed CAS object into a file in a
//! live worktree (bead bd-bres9), under the D023 mode policy.
//!
//! Two halves:
//!
//! - [`decide_materialization`] — the mode policy (D023; invariant I33;
//!   risk R65), unchanged: a writable hardlink to an immutable CAS inode
//!   is unrepresentable, not merely discouraged.
//! - [`materialize_object`] — the byte path. It resolves a
//!   non-quarantined raw copy through the metadata store, independently
//!   refuses quarantined logical objects, and streams a regular file into
//!   staging beside the destination while hashing, REFUSES if the recomputed
//!   content id is not the object's identity, and only then renames it
//!   into place. Unverified bytes are never installed, and a partially
//!   written file is never visible at the destination path. A corrupt
//!   replica is durably quarantined without deleting its forensic bytes.
//!
//! [`MaterializationMode::VerifiedCowReflink`] attempts Linux FICLONE
//! only after a private filesystem probe verifies content and metadata
//! isolation. Unsupported or failed clones fall back to a verified private
//! copy (I33). Both paths verify the object identity before publication;
//! the reflink path hashes the actual staged clone.
//! `ReadOnlyBind` still needs mount privileges and is a typed refusal.
//!
//! ## Why the mode policy looks like this
//!
//! A writable hardlink to an immutable CAS inode is the classic cache
//! corruption: the "copy" IS the original, and one `cargo` touching
//! its output rewrites the shared bytes for the whole fleet. The rule
//! is structural here:
//!
//! - [`MaterializationMode`] has NO writable-hardlink variant — the
//!   forbidden mode is unrepresentable, not discouraged;
//! - mutable destinations (target/OUT_DIR/temp/incremental) get
//!   [`MaterializationMode::PrivateCopy`] or a CoW reflink whose
//!   isolation was VERIFIED on this filesystem; an unverified reflink
//!   implementation falls back to copy;
//! - immutable views use read-only binds;
//! - mtime adjustments apply only to private materializations (the
//!   mode carries the permission).

use std::io::{Read, Seek};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Instant, SystemTime};

#[cfg(test)]
use filetime::FileTime;
use rabs_protocol::raw_bytes::RawBytes;
use rabs_protocol::result_identity::{OutputRole, TypedDigest};

use crate::blob_store::RAW_PROFILE_V1;
use crate::digest_set::{DigestRequest, StreamingObjectWriter};
use crate::metadata_store::{RabsMetadataStore, SqlValue, StoreError, digest_key};

/// Process-wide uniquifier for materialization staging names, so two
/// concurrent materializations of the same destination never share a
/// temp path.
static MATERIALIZE_COUNTER: AtomicU64 = AtomicU64::new(0);

/// Why a materialization did not happen. Every variant leaves the
/// destination path exactly as it was.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MaterializeError {
    /// The mode is not implemented on this path (see the module docs).
    ModeUnsupported(MaterializationMode),
    /// The store knows no usable copy of the object: no location at all,
    /// none non-quarantined, or none in a representation this profile
    /// can read.
    NoUsableCopy {
        /// The object's digest key.
        object: String,
    },
    /// The logical object is quarantined. Even a byte-correct physical
    /// replica cannot authorize its installation until the repair flow runs.
    QuarantinedObject {
        /// The object's digest key.
        object: String,
    },
    /// Every candidate copy failed to read.
    Unreadable {
        /// The last path tried.
        path: String,
        /// The io error.
        error: String,
    },
    /// The stored bytes do not hash to the object's identity. The CAS
    /// copy is corrupt; nothing is installed.
    ContentMismatch {
        /// The object the caller asked for.
        expected: String,
        /// What the bytes actually digest to.
        found: String,
        /// Where those bytes live.
        path: String,
    },
    /// A filesystem step failed.
    Io {
        /// Which step.
        step: &'static str,
        /// The error text.
        error: String,
    },
    /// The metadata store refused a lookup.
    Store(String),
    /// An action-level plan declared the same destination path twice
    /// (K004): refused before any installation begins, because two
    /// writers to one path have no coherent ordering.
    DuplicateDestination {
        /// The duplicated destination path.
        path: String,
    },
    /// A file output is also an ancestor of another output. Neither can be
    /// installed coherently as a regular file in the same bundle.
    OverlappingDestinations {
        /// The output that would need to be both a file and a directory.
        parent: String,
        /// The output beneath it.
        child: String,
    },
    /// A destination is not a named file or contains parent traversal.
    /// Parent components cannot be collapsed safely through possible symlinks.
    UnsafeDestination {
        /// The rejected path, for diagnostics only.
        path: String,
    },
}

impl std::fmt::Display for MaterializeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ModeUnsupported(mode) => write!(f, "materialization mode {mode:?} unimplemented"),
            Self::NoUsableCopy { object } => write!(f, "no usable copy of {object}"),
            Self::QuarantinedObject { object } => {
                write!(f, "logical object {object} is quarantined")
            }
            Self::Unreadable { path, error } => write!(f, "unreadable copy {path}: {error}"),
            Self::ContentMismatch {
                expected,
                found,
                path,
            } => write!(f, "{path} holds {found}, not {expected}"),
            Self::Io { step, error } => write!(f, "{step}: {error}"),
            Self::Store(error) => write!(f, "store: {error}"),
            Self::DuplicateDestination { path } => {
                write!(f, "action plan declares {path} as a destination twice")
            }
            Self::OverlappingDestinations { parent, child } => {
                write!(f, "action output {parent} is an ancestor of output {child}")
            }
            Self::UnsafeDestination { path } => {
                write!(f, "action destination {path} is not a safe named file")
            }
        }
    }
}

fn io_err(step: &'static str) -> impl Fn(std::io::Error) -> MaterializeError {
    move |error| MaterializeError::Io {
        step,
        error: error.to_string(),
    }
}

/// Materialize `object` at `destination`.
///
/// The bytes are verified against the object's identity BEFORE the file
/// becomes visible: a corrupt CAS copy is a typed refusal, never an
/// installed artifact. The destination is replaced atomically (staging
/// file + rename), so a reader either sees the previous file or the
/// complete new one.
///
/// Returns the number of bytes written.
///
/// # Errors
/// A typed [`MaterializeError`]; on any of them the destination path is
/// untouched and the staging file is removed.
pub fn materialize_object(
    store: &mut dyn RabsMetadataStore,
    object: &TypedDigest,
    destination: &Path,
    mode: MaterializationMode,
) -> Result<u64, MaterializeError> {
    materialize_object_prepared(store, object, destination, mode, |_| Ok(()))
}

/// Run all fallible metadata preparation on the verified, private staging
/// inode. The destination is not published until preparation succeeds, so an
/// error cannot leave an installed output absent from the action receipt.
fn materialize_object_prepared(
    store: &mut dyn RabsMetadataStore,
    object: &TypedDigest,
    destination: &Path,
    mode: MaterializationMode,
    prepare_metadata: impl Fn(&std::fs::File) -> std::io::Result<()>,
) -> Result<u64, MaterializeError> {
    if mode == MaterializationMode::ReadOnlyBind {
        return Err(MaterializeError::ModeUnsupported(mode));
    }
    let key = digest_key(object);
    // A location lookup only chooses physical replicas. Logical quarantine
    // dominates every replica, including one whose content digest is correct.
    // Check before creating destination directories or staging any bytes.
    if !store
        .query(
            "SELECT 1 FROM quarantines WHERE scope = 'logical-object' AND subject = ?1 LIMIT 1",
            &[SqlValue::Text(key.clone())],
        )
        .map_err(|error| MaterializeError::Store(format!("{error:?}")))?
        .is_empty()
    {
        return Err(MaterializeError::QuarantinedObject { object: key });
    }
    let locations = store
        .object_locations(object)
        .map_err(|e: StoreError| MaterializeError::Store(format!("{e:?}")))?;
    let raw: Vec<String> = locations
        .into_iter()
        .filter(|(_, encoding, _)| encoding == RAW_PROFILE_V1)
        .map(|(path, _, _)| path)
        .collect();
    if raw.is_empty() {
        return Err(MaterializeError::NoUsableCopy { object: key });
    }

    let parent = destination
        .parent()
        .ok_or_else(|| MaterializeError::Io {
            step: "destination-parent",
            error: "destination has no parent directory".to_owned(),
        })?
        .to_path_buf();
    std::fs::create_dir_all(&parent).map_err(io_err("create-destination-dir"))?;

    let mut last: Option<MaterializeError> = None;
    for source in raw {
        match copy_verified(
            &source,
            object,
            &key,
            &parent,
            destination,
            mode,
            &prepare_metadata,
        ) {
            Ok((bytes, _reflinked)) => return Ok(bytes),
            // Preserve the immediate corruption refusal, but also persist
            // containment so subsequent requests do not repeatedly select
            // the same bad copy. A healthy replica becomes eligible on the
            // next request; this request never silently hides corruption.
            Err(error @ MaterializeError::ContentMismatch { .. }) => {
                store
                    .set_location_quarantined(object, &source, true)
                    .map_err(|quarantine| MaterializeError::Store(format!("{quarantine:?}")))?;
                return Err(error);
            }
            Err(error) => last = Some(error),
        }
    }
    Err(last.unwrap_or(MaterializeError::NoUsableCopy { object: key }))
}

/// A CAS copy must be an ordinary file, never a stream/device or a symlink.
/// Reject obvious bad paths before opening, and inspect the opened handle as
/// well. Linux also prevents a raced final-component symlink and uses a
/// nonblocking open, so a swapped FIFO cannot stall opening the recorded copy.
fn open_cas_copy(source: &str) -> Result<std::fs::File, MaterializeError> {
    let unreadable = |error: std::io::Error| MaterializeError::Unreadable {
        path: source.to_owned(),
        error: error.to_string(),
    };
    let not_regular = || {
        unreadable(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "CAS copy is not a regular file",
        ))
    };
    if !std::fs::symlink_metadata(source)
        .map_err(unreadable)?
        .file_type()
        .is_file()
    {
        return Err(not_regular());
    }
    #[cfg(target_os = "linux")]
    let file = {
        use rustix::fs::{Mode, OFlags, open};

        open(
            source,
            OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::NONBLOCK,
            Mode::empty(),
        )
        .map(std::fs::File::from)
        .map_err(|error| unreadable(std::io::Error::from(error)))?
    };
    #[cfg(not(target_os = "linux"))]
    let file = std::fs::File::open(source).map_err(unreadable)?;
    if !file.metadata().map_err(unreadable)?.is_file() {
        return Err(not_regular());
    }
    Ok(file)
}

/// Stream one copy into a staging file next to `destination`, verifying
/// the content id as the bytes go past, prepare its metadata, then rename.
fn copy_verified(
    source: &str,
    object: &TypedDigest,
    key: &str,
    parent: &Path,
    destination: &Path,
    mode: MaterializationMode,
    prepare_metadata: &impl Fn(&std::fs::File) -> std::io::Result<()>,
) -> Result<(u64, bool), MaterializeError> {
    let mut input = open_cas_copy(source)?;
    let staging = staging_path(parent, destination);
    let mut output = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .open(&staging)
        .map_err(io_err("create-staging"))?;
    let reflinked = mode == MaterializationMode::VerifiedCowReflink
        && try_verified_reflink(&input, &output, parent);
    let prepare = if reflinked {
        // Hash the actual private clone, not a potentially changing source.
        output
            .try_clone()
            .map(|clone| input = clone)
            .map_err(io_err("read-cloned-staging"))
    } else {
        // A failed ioctl may have touched the staging file. The fallback must
        // not retain a suffix from that attempt, even for an empty CAS object.
        output
            .set_len(0)
            .map_err(io_err("reset-staging"))
            .and_then(|()| output.rewind().map_err(io_err("rewind-staging")))
    };
    if let Err(error) = prepare {
        let _ = std::fs::remove_file(&staging);
        return Err(error);
    }
    let mut writer = StreamingObjectWriter::new(DigestRequest::default(), None);
    let mut buffer = vec![0_u8; 64 * 1024];
    let outcome = loop {
        let read = match input.read(&mut buffer) {
            Ok(0) => break Ok(()),
            Ok(n) => n,
            Err(e) => {
                break Err(MaterializeError::Unreadable {
                    path: source.to_owned(),
                    error: e.to_string(),
                });
            }
        };
        if let Err(e) = writer.write(&buffer[..read]) {
            break Err(MaterializeError::Io {
                step: "digest",
                error: format!("{e:?}"),
            });
        }
        if !reflinked && let Err(e) = std::io::Write::write_all(&mut output, &buffer[..read]) {
            break Err(MaterializeError::Io {
                step: "write-staging",
                error: e.to_string(),
            });
        }
    };
    if let Err(error) = outcome {
        let _ = std::fs::remove_file(&staging);
        return Err(error);
    }
    let computed = match writer.finish() {
        Ok(set) => set.atp_content_id,
        Err(e) => {
            let _ = std::fs::remove_file(&staging);
            return Err(MaterializeError::Io {
                step: "digest-finish",
                error: format!("{e:?}"),
            });
        }
    };
    if computed != *object {
        let _ = std::fs::remove_file(&staging);
        return Err(MaterializeError::ContentMismatch {
            expected: key.to_owned(),
            found: digest_key(&computed),
            path: source.to_owned(),
        });
    }
    if let Err(error) = prepare_metadata(&output) {
        // The reflink input can also hold the staging inode open. Close both
        // handles before unlinking, including on platforms denying open-file
        // deletion. Never touch the previous destination on this path.
        drop(input);
        drop(output);
        let _ = std::fs::remove_file(&staging);
        return Err(io_err("prepare-staging-metadata")(error));
    }
    // Subscriber preparation may change the private bytes (for example a
    // canonical .d file becomes subscriber-specific). Report the installed
    // length, not the canonical source length. Do this before visibility.
    let written = match output.metadata() {
        Ok(metadata) => metadata.len(),
        Err(error) => {
            drop(input);
            drop(output);
            let _ = std::fs::remove_file(&staging);
            return Err(io_err("prepared-staging-metadata")(error));
        }
    };
    // Both bytes and freshness metadata are ready. There must be no fallible
    // preparation after this rename: success transfers output ownership to
    // the caller, and an error must still mean the destination was untouched.
    if let Err(error) = std::fs::rename(&staging, destination) {
        let _ = std::fs::remove_file(&staging);
        return Err(MaterializeError::Io {
            step: "rename-into-place",
            error: error.to_string(),
        });
    }
    Ok((written, reflinked))
}

/// Only Linux's safe FICLONE binding is enabled. Other platforms retain the
/// verified-copy backend until their clone API has equivalent isolation tests.
#[cfg(all(
    target_os = "linux",
    not(any(target_arch = "sparc", target_arch = "sparc64"))
))]
fn try_verified_reflink(input: &std::fs::File, output: &std::fs::File, parent: &Path) -> bool {
    use std::os::unix::fs::MetadataExt;

    let (Ok(source), Ok(target)) = (input.metadata(), output.metadata()) else {
        return false;
    };
    if !source.is_file()
        || !target.is_file()
        || source.dev() != target.dev()
        || source.ino() == target.ino()
    {
        return false;
    }
    // Do not cache a probe by st_dev alone: remounts/device reuse and differing
    // filesystem policies can invalidate it. Anonymous probes are bounded (4KiB)
    // and leave no named files behind.
    verify_reflink_isolation(parent).unwrap_or(false)
        && rustix::fs::ioctl_ficlone(output, input).is_ok()
}

#[cfg(not(all(
    target_os = "linux",
    not(any(target_arch = "sparc", target_arch = "sparc64"))
)))]
fn try_verified_reflink(_input: &std::fs::File, _output: &std::fs::File, _parent: &Path) -> bool {
    false
}

#[cfg(all(
    target_os = "linux",
    not(any(target_arch = "sparc", target_arch = "sparc64"))
))]
fn verify_reflink_isolation(parent: &Path) -> std::io::Result<bool> {
    use rustix::fs::{Mode, OFlags, open};
    use std::io::Write;
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    let anonymous = || {
        open(
            parent,
            OFlags::TMPFILE | OFlags::RDWR | OFlags::CLOEXEC,
            Mode::RUSR | Mode::WUSR,
        )
        .map(std::fs::File::from)
        .map_err(std::io::Error::from)
    };
    let mut source = anonymous()?;
    let mut clone = anonymous()?;
    let bytes = [0x5a; 4096];
    source.write_all(&bytes)?;
    source.set_modified(SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(100))?;
    let before = source.metadata()?;
    if rustix::fs::ioctl_ficlone(&clone, &source).is_err()
        || clone.metadata()?.ino() == before.ino()
    {
        return Ok(false);
    }
    clone.write_all(b"changed private content")?;
    clone.set_len(23)?;
    clone.set_permissions(std::fs::Permissions::from_mode(0o640))?;
    clone.set_modified(SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(200))?;
    let after = source.metadata()?;
    source.rewind()?;
    let mut original = Vec::new();
    source.read_to_end(&mut original)?;
    Ok(original == bytes
        && before.len() == after.len()
        && before.mode() == after.mode()
        && before.modified()? == after.modified()?)
}

fn staging_path(parent: &Path, destination: &Path) -> PathBuf {
    let n = MATERIALIZE_COUNTER.fetch_add(1, Ordering::SeqCst);
    let name = destination
        .file_name()
        .map_or_else(|| "object".to_owned(), |n| n.to_string_lossy().into_owned());
    parent.join(format!(".rabs-mat-{}-{n}-{name}.tmp", std::process::id()))
}

/// How a CAS object may be materialized. There is deliberately no
/// writable-hardlink variant (I33).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MaterializationMode {
    /// Full private copy: mutation and mtime changes permitted.
    PrivateCopy,
    /// Prefer a copy-on-write reflink after verifying isolation on this
    /// filesystem; fall back to a private copy if unsupported or unverified.
    /// Both outcomes permit mutation and mtime changes (I33).
    VerifiedCowReflink,
    /// Read-only bind of the CAS bytes: no mutation, no mtime change.
    ReadOnlyBind,
}

impl MaterializationMode {
    /// Whether the materialized path may be mutated.
    #[must_use]
    pub const fn mutation_permitted(self) -> bool {
        matches!(self, Self::PrivateCopy | Self::VerifiedCowReflink)
    }

    /// Whether mtime adjustments are permitted (private forms only).
    #[must_use]
    pub const fn mtime_permitted(self) -> bool {
        self.mutation_permitted()
    }
}

/// Choose the materialization mode for a destination.
///
/// `reflink_isolation_verified` — whether THIS filesystem's reflink
/// was differentially proven to isolate content AND metadata; an
/// unsupported/unverified implementation falls back to copy.
#[must_use]
pub const fn decide_materialization(
    destination_mutable: bool,
    reflink_available: bool,
    reflink_isolation_verified: bool,
) -> MaterializationMode {
    if !destination_mutable {
        return MaterializationMode::ReadOnlyBind;
    }
    if reflink_available && reflink_isolation_verified {
        return MaterializationMode::VerifiedCowReflink;
    }
    // Unverified reflink or none: PRIVATE COPY, never a hardlink.
    MaterializationMode::PrivateCopy
}

// ---------------------------------------------------------------------
// Action-level pipelined materialization (K004; plan §87; invariant I12).
//
// Cargo completes its internal metadata dependency edge when it parses
// a rustc artifact-notification line whose path ends in `.rmeta`. On a
// cache hit, serving therefore has ONE ordering obligation: the exact
// `.rmeta` output must be fetched, verified, and fully materialized —
// including its freshness metadata — before any other output is touched,
// because the caller may replay the notification the moment this
// function's head phase is done (the replay itself is K005's contract).
// ---------------------------------------------------------------------

/// One declared output of a cached action, resolved to its local
/// destination. The caller owns the virtual-to-real mapping (plan §87
/// step 1: "resolve the exact `.rmeta` logical output and
/// Cargo-requested path"); this layer owns ordering, verification,
/// atomicity, and freshness.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlannedActionOutput {
    /// Role tag from the canonical logical-output map. Rows with
    /// [`OutputRole::ProvisionalMetadata`] are the pipelining head.
    pub role: OutputRole,
    /// Canonical virtual path (byte-preserving receipt identity).
    pub virtual_path: RawBytes,
    /// The committed CAS object this destination must receive.
    pub object: TypedDigest,
    /// The local path Cargo requested.
    pub destination: PathBuf,
}

/// One installed output with its measured latency.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OutputMaterialized {
    /// Role tag.
    pub role: OutputRole,
    /// Canonical virtual path.
    pub virtual_path: RawBytes,
    /// Where the bytes were installed.
    pub destination: PathBuf,
    /// Verified bytes written.
    pub bytes: u64,
    /// This output's install latency, nanoseconds.
    pub nanos: u128,
}

/// Success receipt for one action materialization. Latencies here are
/// MEASURED, not assumed: the bead's small-artifact hit target (<50ms)
/// is a property callers observe through `head_nanos`, not a claim.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ActionMaterializationReceipt {
    /// Wall-clock nanoseconds for the whole call.
    pub total_nanos: u128,
    /// Wall-clock nanoseconds from call start through completion of
    /// the LAST `.rmeta`-role output — the pipelining gate. Zero when
    /// the plan declares no provisional metadata.
    pub head_nanos: u128,
    /// Wall-clock nanoseconds spent on the tail phase alone.
    pub tail_nanos: u128,
    /// Outputs in installation order (head first, then tail).
    pub installed: Vec<OutputMaterialized>,
}

/// Why an action-level materialization aborted. The already-installed
/// prefix stays on disk (each file was verified before its rename) but
/// is reported so no caller can mistake it for a servable result:
/// plan §87 replays events only against a FULLY materializable result,
/// so any failure means bypass serving for this action.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ActionMaterializeFailure {
    /// Successfully installed prefix, in order.
    pub installed: Vec<OutputMaterialized>,
    /// The refusal that stopped the action.
    pub error: MaterializeError,
}

/// Deterministic within-phase order: byte order by canonical virtual
/// path, then role rank, then destination path. Not input order — this
/// function's receipt must be reproducible even for hand-built plans.
fn role_rank(role: OutputRole) -> u8 {
    match role {
        OutputRole::ProvisionalMetadata => 0,
        OutputRole::DepInfo => 1,
        OutputRole::BuildScriptMetadata => 2,
        OutputRole::TestSideEffect => 3,
        OutputRole::Materializable => 4,
    }
}

fn planned_order_key(p: &PlannedActionOutput) -> (Vec<u8>, u8, PathBuf) {
    (
        p.virtual_path.as_bytes().to_vec(),
        role_rank(p.role),
        p.destination.clone(),
    )
}

/// Install ONE declared output: verify, stamp the private staging inode,
/// then atomically rename it into place (plan §30:
/// outputs newer than inputs from Cargo's perspective). Stamping is
/// gated on `mode.mtime_permitted()` structurally — mtime changes are
/// ever applied only to private materializations.
fn install_one(
    store: &mut dyn RabsMetadataStore,
    out: &PlannedActionOutput,
    freshness: SystemTime,
    mode: MaterializationMode,
    prepare: &impl Fn(&PlannedActionOutput, &std::fs::File) -> std::io::Result<()>,
) -> Result<OutputMaterialized, MaterializeError> {
    let began = Instant::now();
    let bytes = materialize_object_prepared(
        store,
        &out.object,
        &out.destination,
        mode,
        |staged| {
            prepare(out, staged)?;
            if mode.mtime_permitted() {
                staged.set_modified(freshness)
            } else {
                Ok(())
            }
        },
    )?;
    Ok(OutputMaterialized {
        role: out.role,
        virtual_path: out.virtual_path.clone(),
        destination: out.destination.clone(),
        bytes,
        nanos: began.elapsed().as_nanos(),
    })
}

/// Byte-preserving, whole-bundle lexical preflight. Resolve relative names
/// against one working-directory snapshot, ignore `.` components, and reject
/// duplicate or ancestor destinations before the first filesystem mutation.
/// This is NOT filesystem containment: the caller's destination ownership and
/// symlink/case-sensitivity policy remain required.
fn validate_action_destinations(outputs: &[PlannedActionOutput]) -> Result<(), MaterializeError> {
    use std::path::Component;

    if outputs.is_empty() {
        return Ok(());
    }
    let cwd = std::env::current_dir().map_err(io_err("destination-working-directory"))?;
    let mut seen = std::collections::BTreeSet::<PathBuf>::new();
    for out in outputs {
        let path = &out.destination;
        if path.file_name().is_none()
            || path.components().any(|part| part == Component::ParentDir)
        {
            return Err(MaterializeError::UnsafeDestination {
                path: path.to_string_lossy().into_owned(),
            });
        }
        let absolute = cwd.join(path);
        if !absolute.is_absolute() {
            return Err(MaterializeError::UnsafeDestination {
                path: path.to_string_lossy().into_owned(),
            });
        }
        let key: PathBuf = absolute
            .components()
            .filter(|part| *part != Component::CurDir)
            .collect();
        if !seen.insert(key.clone()) {
            return Err(MaterializeError::DuplicateDestination {
                path: key.to_string_lossy().into_owned(),
            });
        }
    }
    // Path ordering groups descendants immediately after their ancestor.
    // Adjacent checks therefore cover all overlaps without a quadratic scan.
    let mut previous: Option<&PathBuf> = None;
    for path in &seen {
        if let Some(parent) = previous
            && path.starts_with(parent)
        {
            return Err(MaterializeError::OverlappingDestinations {
                parent: parent.to_string_lossy().into_owned(),
                child: path.to_string_lossy().into_owned(),
            });
        }
        previous = Some(path);
    }
    Ok(())
}

/// Materialize a cached action's outputs with `.rmeta` first (K004;
/// plan §87 steps 1–3 and 6).
///
/// Ordering contract: every [`OutputRole::ProvisionalMetadata`] output
/// is fetched, byte-verified, freshness-stamped while private, and
/// atomically renamed into place BEFORE any other output begins. Within each
/// phase the order is deterministic ([`planned_order_key`]). Every installed
/// file carries the SAME freshness timestamp captured once at call
/// start, so the bundle is coherent from Cargo's mtime-sensitive
/// freshness view (risk R6: incoherent hit mtimes cause rebuild storms
/// or false freshness) and repeated hits stay storm-free.
///
/// Fail-fast: the first refusal aborts the action and returns the
/// installed prefix plus the error. A corrupt CAS copy refuses
/// immediately (`ContentMismatch`) rather than trying another location
/// — silently substituting a second copy would hide store corruption.
///
/// # Errors
/// [`ActionMaterializeFailure`] with the installed prefix; duplicate,
/// ancestor-overlapping, and parent-traversing destinations are refused
/// before anything is touched.
pub fn materialize_action_outputs(
    store: &mut dyn RabsMetadataStore,
    outputs: &[PlannedActionOutput],
    mode: MaterializationMode,
) -> Result<ActionMaterializationReceipt, ActionMaterializeFailure> {
    materialize_action_outputs_prepared(store, outputs, mode, SystemTime::now(), &|_, _| Ok(()))
}

/// Materialize a complete plan with subscriber-specific preparation of each
/// verified PRIVATE staging inode, before its freshness stamp and atomic rename.
///
/// The callback never sees unverified CAS bytes and cannot mutate a CAS inode.
/// It may derive dep-info or apply an independently established output mode.
/// Its result is subscriber-local: never publish derived bytes under the source
/// object identity. `freshness` is a caller-established floor, not an assertion
/// that live inputs still match the action. The normal authority, destination
/// ownership and input-validation requirements remain the caller's responsibility.
///
/// # Errors
/// Preparation failure leaves that destination untouched and reports any
/// previously installed prefix. A prefix is NOT permission to execute locally;
/// subscriber delivery/ownership recovery must resolve the exposure frontier.
pub fn materialize_action_outputs_prepared(
    store: &mut dyn RabsMetadataStore,
    outputs: &[PlannedActionOutput],
    mode: MaterializationMode,
    freshness: SystemTime,
    prepare: &impl Fn(&PlannedActionOutput, &std::fs::File) -> std::io::Result<()>,
) -> Result<ActionMaterializationReceipt, ActionMaterializeFailure> {
    // This validates one bundle; it is not a cross-request reservation.
    // The operation's destination arbiter remains the caller's obligation.
    validate_action_destinations(outputs).map_err(|error| ActionMaterializeFailure {
        installed: Vec::new(),
        error,
    })?;

    let mut ordered: Vec<&PlannedActionOutput> = outputs.iter().collect();
    ordered.sort_by_key(|p| planned_order_key(p));
    let (heads, tails): (Vec<_>, Vec<_>) = ordered
        .into_iter()
        .partition(|out| out.role == OutputRole::ProvisionalMetadata);

    let started = Instant::now();
    let mut installed = Vec::with_capacity(outputs.len());

    for out in &heads {
        match install_one(store, out, freshness, mode, prepare) {
            Ok(done) => installed.push(done),
            Err(error) => {
                return Err(ActionMaterializeFailure { installed, error });
            }
        }
    }
    let head_nanos = started.elapsed().as_nanos();

    let tail_started = Instant::now();
    for out in &tails {
        match install_one(store, out, freshness, mode, prepare) {
            Ok(done) => installed.push(done),
            Err(error) => {
                return Err(ActionMaterializeFailure { installed, error });
            }
        }
    }
    let tail_nanos = tail_started.elapsed().as_nanos();

    Ok(ActionMaterializationReceipt {
        total_nanos: started.elapsed().as_nanos(),
        head_nanos,
        tail_nanos,
        installed,
    })
}

// ---------------------------------------------------------------------
// Gated verbatim artifact-notification replay (K005; plan §87 steps
// 4–7; verified against Cargo source at pin 04b8ad83).
//
// Cargo's CURRENT process parses the rustc artifact-notification line
// (the JSON with an "artifact" key) and — when the path ends in
// `.rmeta` — marks its internal metadata dependency edge complete,
// unblocking dependents. This is NOT Cargo's outward `compiler-artifact`
// message: only Cargo generates that, and nothing here ever constructs
// it (D008 rule 2). The replay emits ONLY bytes a previous real build
// stored: this module has no serde model of any notification shape and
// no constructor for one — synthesis is structurally impossible.
//
// The gating invariant is the whole point: a line becomes emittable
// exactly when its announced output is FULLY materialized (verified +
// renamed + stamped), never before. On a cache hit the stream Cargo
// observes therefore matches stock pipelining where it matters: the
// `.rmeta` notification arrives first and every other notification
// arrives after its file exists.
// ---------------------------------------------------------------------

/// One rustc artifact-notification line stored from the winning
/// attempt, bound to the output it announces. `exact_line` is replayed
/// BYTE-VERBATIM — it carries the exact output path Cargo requested,
/// and rewriting it would hand Cargo a path it never asked for (D008
/// rule 1; subscriber translation is a separate layer's concern and
/// deliberately does not apply to notifications).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredArtifactNotification {
    /// Byte-verbatim JSON line (no trailing newline).
    pub exact_line: Vec<u8>,
    /// The destination path this line announces; must equal the
    /// `PlannedActionOutput::destination` it gates on.
    pub announced_destination: PathBuf,
}

/// Why a replay plan cannot be built. Every variant is a refusal to
/// serve, never a best-effort stream: emitting an event whose output
/// cannot be proven complete would corrupt Cargo's dependency state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReplayPlanError {
    /// A line announces a path that is not in the materialization
    /// plan: there is no proof its file exists.
    UnboundLine {
        /// The unbindable announced path.
        path: String,
    },
    /// Two lines announce the same output. Exactly-once replay makes
    /// duplicates unrepresentable rather than deduplicated.
    DuplicateAnnouncement {
        /// The twice-announced path.
        path: String,
    },
    /// A zero-byte stored line: not a notification.
    EmptyLine,
}

impl std::fmt::Display for ReplayPlanError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UnboundLine { path } => {
                write!(f, "notification names {path}, which is not in the plan")
            }
            Self::DuplicateAnnouncement { path } => {
                write!(f, "two notifications announce {path}")
            }
            Self::EmptyLine => write!(f, "stored notification line is empty"),
        }
    }
}

impl std::error::Error for ReplayPlanError {}

/// Build the gated replay stream for a SUCCESSFUL action
/// materialization (plan §87 steps 4–7).
///
/// The returned lines are the caller's own stored bytes verbatim, in
/// emission order: each line appears exactly once, positioned at the
/// point its announced output completed installation — so `.rmeta`
/// lines lead (K004 head phase), and no line can ever precede its
/// file. Outputs without a stored notification produce no event.
///
/// The empty stream is valid: some actions (deterministic failures
/// bypass serving entirely; some outputs have no notification) replay
/// nothing.
///
/// # Errors
/// [`ReplayPlanError`] — the caller must bypass serving rather than
/// emit a partial or unprovable stream.
pub fn plan_notification_replay(
    receipt: &ActionMaterializationReceipt,
    lines: &[StoredArtifactNotification],
) -> Result<Vec<Vec<u8>>, ReplayPlanError> {
    if lines.iter().any(|l| l.exact_line.is_empty()) {
        return Err(ReplayPlanError::EmptyLine);
    }
    let mut by_destination: std::collections::HashMap<&Path, &StoredArtifactNotification> =
        std::collections::HashMap::with_capacity(lines.len());
    for line in lines {
        if by_destination
            .insert(line.announced_destination.as_path(), line)
            .is_some()
        {
            return Err(ReplayPlanError::DuplicateAnnouncement {
                path: line.announced_destination.to_string_lossy().into_owned(),
            });
        }
    }
    // Every announced path must be a planned, installed output;
    // otherwise no proof of completeness exists for it.
    let installed_by_destination: std::collections::HashMap<&Path, usize> = receipt
        .installed
        .iter()
        .enumerate()
        .map(|(position, done)| (done.destination.as_path(), position))
        .collect();
    for line in lines {
        if !installed_by_destination.contains_key(line.announced_destination.as_path()) {
            return Err(ReplayPlanError::UnboundLine {
                path: line.announced_destination.to_string_lossy().into_owned(),
            });
        }
    }

    // Walk installation order; emit each announcing line at the point
    // its output became complete. The gate is structural: the loop
    // iterates INSTALLED outputs only, so a line cannot precede its
    // file under any input ordering.
    let mut stream = Vec::with_capacity(lines.len());
    for done in &receipt.installed {
        if let Some(line) = by_destination.get(done.destination.as_path()) {
            stream.push(line.exact_line.clone());
        }
    }
    Ok(stream)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::path::PathBuf;

    /// Simple content fingerprint for the corruption tests (FNV-1a —
    /// test-local; real CAS identity uses typed SHA-256 digests).
    fn fingerprint(path: &PathBuf) -> u64 {
        let bytes = fs::read(path).unwrap();
        let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
        for byte in bytes {
            hash ^= u64::from(byte);
            hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
        }
        hash
    }

    fn scratch_dir(name: &str) -> PathBuf {
        let dir = std::env::temp_dir()
            .join("rabs-d023-tests")
            .join(format!("{}-{name}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn writable_hardlinks_are_unrepresentable_and_fallbacks_apply() {
        // Structural: exhaustive match — no hardlink variant exists.
        for mode in [
            MaterializationMode::PrivateCopy,
            MaterializationMode::VerifiedCowReflink,
            MaterializationMode::ReadOnlyBind,
        ] {
            match mode {
                MaterializationMode::PrivateCopy
                | MaterializationMode::VerifiedCowReflink
                | MaterializationMode::ReadOnlyBind => {}
            }
        }
        // Decision table: immutable -> read-only bind; mutable with
        // UNVERIFIED reflink -> private copy (the fallback rule);
        // verified reflink -> CoW.
        assert_eq!(
            decide_materialization(false, true, true),
            MaterializationMode::ReadOnlyBind
        );
        assert_eq!(
            decide_materialization(true, true, false),
            MaterializationMode::PrivateCopy,
            "unverified reflink implementations fall back to copy"
        );
        assert_eq!(
            decide_materialization(true, false, false),
            MaterializationMode::PrivateCopy
        );
        assert_eq!(
            decide_materialization(true, true, true),
            MaterializationMode::VerifiedCowReflink
        );
    }

    #[test]
    fn private_copy_mutation_never_changes_cas_bytes() {
        // THE acceptance: materialize via private copy, mutate the
        // materialization aggressively — the CAS object's fingerprint
        // is unchanged.
        let dir = scratch_dir("private-copy");
        let cas_object = dir.join("cas-object.rlib");
        fs::write(&cas_object, b"immutable cas bytes").unwrap();
        let before = fingerprint(&cas_object);

        let materialized = dir.join("target-out.rlib");
        fs::copy(&cas_object, &materialized).unwrap();
        // Mutate the materialization (what cargo/rustc might do).
        fs::write(&materialized, b"locally rewritten output").unwrap();

        assert_eq!(
            fingerprint(&cas_object),
            before,
            "CAS digest must never change after materialization mutation"
        );
        let _ = fs::remove_dir_all(&dir);
    }

    /// A store with `bytes` really put into a real blob layout.
    fn store_with_object(
        dir: &Path,
        bytes: &[u8],
    ) -> (
        crate::metadata_store::SqlMetadataStore<crate::metadata_store::RusqliteEngine>,
        crate::blob_store::BlobStoreLayout,
        TypedDigest,
    ) {
        use crate::blob_store::{BlobStoreLayout, DurabilityPolicy, PutLimits, put_if_absent};
        use crate::digest_set::digest_set;
        use crate::metadata_store::{RusqliteEngine, SqlMetadataStore};

        let layout = BlobStoreLayout::open(&dir.join("blobs")).unwrap();
        let engine = RusqliteEngine::open(&dir.join("meta.sqlite")).unwrap();
        let mut store = SqlMetadataStore::open(engine).unwrap();
        let declared = digest_set(bytes, DigestRequest::default(), None)
            .unwrap()
            .atp_content_id;
        let mut reader = bytes;
        put_if_absent(
            &layout,
            &mut store,
            &declared,
            &mut reader,
            PutLimits::default(),
            DurabilityPolicy::FULL,
        )
        .expect("put");
        (store, layout, declared)
    }

    #[test]
    fn h017_production_materialization_preserves_cas_content_and_metadata() {
        let dir = tempfile::tempdir().unwrap().keep();
        let bytes = b"shared immutable artifact".repeat(4096);
        let (mut store, _layout, object) = store_with_object(&dir, &bytes);
        let source = PathBuf::from(&store.object_locations(&object).unwrap()[0].0);
        let before = fs::metadata(&source).unwrap();
        let target = dir.join("target.rlib");
        assert_eq!(
            materialize_object(
                &mut store,
                &object,
                &target,
                MaterializationMode::VerifiedCowReflink
            )
            .unwrap(),
            bytes.len() as u64
        );
        assert_eq!(fs::read(&target).unwrap(), bytes);
        #[cfg(unix)]
        {
            use std::os::unix::fs::{MetadataExt, PermissionsExt};
            assert_ne!(before.ino(), fs::metadata(&target).unwrap().ino());
            fs::set_permissions(&target, fs::Permissions::from_mode(0o600)).unwrap();
            assert_eq!(fs::metadata(&source).unwrap().mode(), before.mode());
        }
        filetime::set_file_mtime(&target, FileTime::from_unix_time(123, 0)).unwrap();
        fs::write(&target, b"mutated subscriber output").unwrap();
        assert_eq!(fs::read(&source).unwrap(), bytes);
        assert_eq!(
            fs::metadata(&source).unwrap().modified().unwrap(),
            before.modified().unwrap()
        );
        eprintln!(
            "H017 production content/metadata isolation evidence: {}",
            dir.display()
        );
    }

    #[test]
    fn h017_reflink_request_still_refuses_corrupt_bytes_before_publication() {
        let dir = tempfile::tempdir().unwrap().keep();
        let (mut store, _layout, object) = store_with_object(&dir, b"original object");
        let source = &store.object_locations(&object).unwrap()[0].0;
        fs::write(source, b"corrupt object").unwrap();
        let target = dir.join("existing.rlib");
        fs::write(&target, b"previous artifact").unwrap();
        assert!(matches!(
            materialize_object(
                &mut store,
                &object,
                &target,
                MaterializationMode::VerifiedCowReflink
            ),
            Err(MaterializeError::ContentMismatch { .. })
        ));
        assert_eq!(fs::read(&target).unwrap(), b"previous artifact");
    }

    #[test]
    fn h017_empty_object_replaces_existing_output_without_stale_suffix() {
        let dir = tempfile::tempdir().unwrap().keep();
        let (mut store, _layout, object) = store_with_object(&dir, b"");
        let target = dir.join("empty.rlib");
        fs::write(&target, b"previous nonempty output").unwrap();
        assert_eq!(
            materialize_object(
                &mut store,
                &object,
                &target,
                MaterializationMode::VerifiedCowReflink
            )
            .unwrap(),
            0
        );
        assert!(fs::read(&target).unwrap().is_empty());
    }

    #[cfg(all(
        target_os = "linux",
        not(any(target_arch = "sparc", target_arch = "sparc64"))
    ))]
    #[test]
    fn h017_tmpfs_unsupported_reflink_falls_back_to_verified_copy() {
        let dir = tempfile::tempdir_in("/dev/shm").unwrap().keep();
        let source = dir.join("source");
        let target = dir.join("target");
        let bytes = b"tmpfs fallback artifact";
        fs::write(&source, bytes).unwrap();
        // This case requires a genuinely unsupported filesystem, not an injected
        // ioctl failure. The separate opt-in test requires real reflink success.
        assert!(!verify_reflink_isolation(&dir).unwrap());
        let object = crate::digest_set::digest_set(bytes, DigestRequest::default(), None)
            .unwrap()
            .atp_content_id;
        let (count, reflinked) = copy_verified(
            source.to_str().unwrap(),
            &object,
            &digest_key(&object),
            &dir,
            &target,
            MaterializationMode::VerifiedCowReflink,
            &|_| Ok(()),
        )
        .unwrap();
        assert!(!reflinked);
        assert_eq!(count, bytes.len() as u64);
        assert_eq!(fs::read(&target).unwrap(), bytes);
        fs::write(&target, b"independent").unwrap();
        assert_eq!(fs::read(&source).unwrap(), bytes);
        eprintln!(
            "H017 tmpfs verified-copy fallback evidence: {}",
            dir.display()
        );
    }

    #[cfg(all(
        target_os = "linux",
        not(any(target_arch = "sparc", target_arch = "sparc64"))
    ))]
    #[test]
    #[ignore = "requires RABS_REFLINK_TEST_ROOT on a real reflink-capable filesystem"]
    fn h017_real_reflink_backend_is_required_and_mutation_independent() {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};

        let root = std::env::var_os("RABS_REFLINK_TEST_ROOT").expect("explicit capable filesystem");
        let dir = tempfile::tempdir_in(root).unwrap().keep();
        assert!(
            verify_reflink_isolation(&dir).unwrap(),
            "filesystem must support real reflinks"
        );
        let source = dir.join("source");
        let target = dir.join("target");
        let bytes = b"reflink immutable artifact".repeat(4096);
        fs::write(&source, &bytes).unwrap();
        let before = fs::metadata(&source).unwrap();
        let object = crate::digest_set::digest_set(&bytes, DigestRequest::default(), None)
            .unwrap()
            .atp_content_id;
        let (count, reflinked) = copy_verified(
            source.to_str().unwrap(),
            &object,
            &digest_key(&object),
            &dir,
            &target,
            MaterializationMode::VerifiedCowReflink,
            &|_| Ok(()),
        )
        .unwrap();
        assert!(
            reflinked,
            "copy fallback must not satisfy the positive reflink gate"
        );
        assert_eq!(count, bytes.len() as u64);
        assert_eq!(fs::read(&target).unwrap(), bytes);
        assert_ne!(before.ino(), fs::metadata(&target).unwrap().ino());
        fs::set_permissions(&target, fs::Permissions::from_mode(0o600)).unwrap();
        filetime::set_file_mtime(&target, FileTime::from_unix_time(123, 0)).unwrap();
        fs::write(&target, b"target changed").unwrap();
        assert_eq!(fs::read(&source).unwrap(), bytes);
        let after = fs::metadata(&source).unwrap();
        assert_eq!(after.mode(), before.mode());
        assert_eq!(after.modified().unwrap(), before.modified().unwrap());
        fs::write(&source, b"source changed later").unwrap();
        assert_eq!(fs::read(&target).unwrap(), b"target changed");
        eprintln!(
            "H017 real reflink content+metadata evidence: {}",
            dir.display()
        );
    }

    #[test]
    fn materializes_real_bytes_and_the_copy_is_private() {
        let dir = scratch_dir("materialize");
        let bytes = b"the committed artifact bytes".repeat(1000);
        let (mut store, _layout, object) = store_with_object(&dir, &bytes);

        // Into a path whose parent does not exist yet (a fresh worktree).
        let destination = dir
            .join("worktree")
            .join("target")
            .join("debug")
            .join("lib.rlib");
        let written = materialize_object(
            &mut store,
            &object,
            &destination,
            MaterializationMode::PrivateCopy,
        )
        .expect("materialize");
        assert_eq!(written as usize, bytes.len());
        assert_eq!(fs::read(&destination).unwrap(), bytes);

        // The D023 property, now on the REAL path: mutating what we
        // materialized cannot reach back into the CAS bytes.
        let cas_path = store.object_locations(&object).unwrap()[0].0.clone();
        let before = fingerprint(&PathBuf::from(&cas_path));
        fs::write(&destination, b"cargo rewrote its output").unwrap();
        assert_eq!(
            fingerprint(&PathBuf::from(&cas_path)),
            before,
            "materialization must never alias the CAS inode"
        );

        // No staging litter beside the destination.
        let leftovers: Vec<_> = fs::read_dir(destination.parent().unwrap())
            .unwrap()
            .flatten()
            .filter(|e| e.file_name().to_string_lossy().starts_with(".rabs-mat-"))
            .collect();
        assert!(leftovers.is_empty(), "staging files left behind");
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_corrupt_store_copy_is_refused_and_nothing_is_installed() {
        let dir = scratch_dir("corrupt");
        let bytes = b"honest bytes";
        let (mut store, _layout, object) = store_with_object(&dir, bytes);

        // Rot the stored copy behind the store's back (bit rot, a bad
        // disk, a careless operator).
        let cas_path = store.object_locations(&object).unwrap()[0].0.clone();
        fs::write(&cas_path, b"tampered!!!!").unwrap();

        let destination = dir.join("out.rlib");
        let outcome = materialize_object(
            &mut store,
            &object,
            &destination,
            MaterializationMode::PrivateCopy,
        );
        assert!(
            matches!(outcome, Err(MaterializeError::ContentMismatch { .. })),
            "corrupt bytes must be refused, got {outcome:?}"
        );
        assert!(
            !destination.exists(),
            "a refused materialization must install nothing"
        );
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn an_object_with_no_copy_and_an_unimplemented_mode_are_typed_refusals() {
        let dir = scratch_dir("no-copy");
        let (mut store, _layout, object) = store_with_object(&dir, b"present");
        let absent = crate::digest_set::digest_set(b"never stored", DigestRequest::default(), None)
            .unwrap()
            .atp_content_id;

        assert!(matches!(
            materialize_object(
                &mut store,
                &absent,
                &dir.join("a.rlib"),
                MaterializationMode::PrivateCopy
            ),
            Err(MaterializeError::NoUsableCopy { .. })
        ));
        // Copy is not a substitute for a requested read-only bind.
        assert_eq!(
            materialize_object(
                &mut store,
                &object,
                &dir.join("b.rlib"),
                MaterializationMode::ReadOnlyBind,
            ),
            Err(MaterializeError::ModeUnsupported(
                MaterializationMode::ReadOnlyBind
            ))
        );
        assert!(!dir.join("b.rlib").exists());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn logical_quarantine_blocks_byte_correct_artifacts_before_destination_creation() {
        use crate::metadata_store::QuarantineScope;

        let dir = tempfile::tempdir().unwrap();
        let (mut store, _layout, object) = store_with_object(dir.path(), b"valid bytes");
        let key = digest_key(&object);
        store
            .add_quarantine(QuarantineScope::LogicalObject, &key, "unresolved incident")
            .unwrap();
        for mode in [
            MaterializationMode::PrivateCopy,
            MaterializationMode::VerifiedCowReflink,
        ] {
            let destination = dir.path().join("subscriber/target/out.rlib");
            assert_eq!(
                materialize_object(&mut store, &object, &destination, mode),
                Err(MaterializeError::QuarantinedObject {
                    object: key.clone()
                })
            );
            assert!(!dir.path().join("subscriber").exists());
        }
        let existing = dir.path().join("existing.rlib");
        fs::write(&existing, b"older output").unwrap();
        assert!(matches!(
            materialize_object(
                &mut store,
                &object,
                &existing,
                MaterializationMode::PrivateCopy
            ),
            Err(MaterializeError::QuarantinedObject { .. })
        ));
        assert_eq!(fs::read(&existing).unwrap(), b"older output");
    }

    #[test]
    fn corrupt_materialization_durably_excludes_the_bad_location() {
        let dir = tempfile::tempdir().unwrap();
        let (mut store, _layout, object) = store_with_object(dir.path(), b"valid bytes");
        let source = PathBuf::from(&store.object_locations(&object).unwrap()[0].0);
        fs::write(&source, b"corrupt bytes").unwrap();
        let destination = dir.path().join("out.rlib");
        fs::write(&destination, b"old output").unwrap();
        assert!(matches!(
            materialize_object(
                &mut store,
                &object,
                &destination,
                MaterializationMode::PrivateCopy
            ),
            Err(MaterializeError::ContentMismatch { .. })
        ));
        assert_eq!(fs::read(&destination).unwrap(), b"old output");
        // Preserve the bad bytes for inspection instead of deleting evidence.
        assert_eq!(fs::read(&source).unwrap(), b"corrupt bytes");
        drop(store);

        let engine = RusqliteEngine::open(&dir.path().join("meta.sqlite")).unwrap();
        let mut reopened = SqlMetadataStore::open(engine).unwrap();
        reopened.intern_domain(object.domain);
        assert!(reopened.object_locations(&object).unwrap().is_empty());
        assert!(matches!(
            materialize_object(
                &mut reopened,
                &object,
                &destination,
                MaterializationMode::PrivateCopy
            ),
            Err(MaterializeError::NoUsableCopy { .. })
        ));
        assert_eq!(fs::read(&destination).unwrap(), b"old output");
    }

    #[test]
    fn cas_copy_opening_accepts_only_regular_files() {
        let dir = tempfile::tempdir().unwrap();
        let source = dir.path().join("copy");
        fs::write(&source, b"regular bytes").unwrap();
        let mut file = open_cas_copy(source.to_str().unwrap()).unwrap();
        let mut bytes = Vec::new();
        file.read_to_end(&mut bytes).unwrap();
        assert_eq!(bytes, b"regular bytes");
        assert!(matches!(
            open_cas_copy(dir.path().to_str().unwrap()),
            Err(MaterializeError::Unreadable { .. })
        ));
        assert!(matches!(
            open_cas_copy(dir.path().join("missing").to_str().unwrap()),
            Err(MaterializeError::Unreadable { .. })
        ));
    }

    #[cfg(unix)]
    #[test]
    fn cas_copy_opening_refuses_symlinks_and_unbounded_devices() {
        let dir = tempfile::tempdir().unwrap();
        let source = dir.path().join("copy");
        let alias = dir.path().join("alias");
        fs::write(&source, b"valid object bytes").unwrap();
        std::os::unix::fs::symlink(&source, &alias).unwrap();
        assert!(matches!(
            open_cas_copy(alias.to_str().unwrap()),
            Err(MaterializeError::Unreadable { .. })
        ));
        // A raw File::open + read-to-EOF loop would never finish on this
        // device. It must be rejected before any content hashing begins.
        assert!(matches!(
            open_cas_copy("/dev/zero"),
            Err(MaterializeError::Unreadable { .. })
        ));
    }

    #[test]
    fn materializing_over_an_existing_file_replaces_it_atomically() {
        let dir = scratch_dir("replace");
        let bytes = b"new committed output";
        let (mut store, _layout, object) = store_with_object(&dir, bytes);
        let destination = dir.join("out.rlib");
        fs::write(&destination, b"a stale artifact from an older build").unwrap();

        materialize_object(
            &mut store,
            &object,
            &destination,
            MaterializationMode::PrivateCopy,
        )
        .expect("materialize");
        assert_eq!(fs::read(&destination).unwrap(), bytes);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn failed_staging_metadata_preserves_existing_bytes_and_freshness() {
        for mode in [
            MaterializationMode::PrivateCopy,
            MaterializationMode::VerifiedCowReflink,
        ] {
            let dir = tempfile::tempdir().unwrap();
            let (mut store, _layout, object) = store_with_object(dir.path(), b"new bytes");
            let destination = dir.path().join("out.rmeta");
            fs::write(&destination, b"previous output").unwrap();
            let previous = FileTime::from_unix_time(1_000_000_000, 0);
            filetime::set_file_mtime(&destination, previous).unwrap();
            let original_stamp = fs::metadata(&destination).unwrap().modified().unwrap();
            let calls = std::cell::Cell::new(0);

            let failure = materialize_object_prepared(
                &mut store,
                &object,
                &destination,
                mode,
                |staged| {
                    calls.set(calls.get() + 1);
                    assert_eq!(staged.metadata()?.len(), 9);
                    assert_eq!(fs::read(&destination)?, b"previous output");
                    staged.set_modified(SystemTime::UNIX_EPOCH)?;
                    Err(std::io::Error::other("injected metadata failure"))
                },
            )
            .unwrap_err();

            assert_eq!(calls.get(), 1, "metadata is prepared before one publication");
            assert!(matches!(
                failure,
                MaterializeError::Io {
                    step: "prepare-staging-metadata",
                    ..
                }
            ));
            assert_eq!(fs::read(&destination).unwrap(), b"previous output");
            assert_eq!(
                fs::metadata(&destination).unwrap().modified().unwrap(),
                original_stamp
            );
            assert!(fs::read_dir(dir.path()).unwrap().all(|entry| {
                !entry
                    .unwrap()
                    .file_name()
                    .to_string_lossy()
                    .starts_with(".rabs-mat-")
            }));
        }
    }

    #[test]
    fn failed_staging_metadata_does_not_publish_a_new_destination() {
        let dir = tempfile::tempdir().unwrap();
        let (mut store, _layout, object) = store_with_object(dir.path(), b"new bytes");
        let destination = dir.path().join("new.rmeta");
        let result = materialize_object_prepared(
            &mut store,
            &object,
            &destination,
            MaterializationMode::PrivateCopy,
            |_| Err(std::io::Error::other("injected metadata failure")),
        );
        assert!(result.is_err());
        assert!(!destination.exists());
        assert!(fs::read_dir(dir.path()).unwrap().all(|entry| {
            !entry
                .unwrap()
                .file_name()
                .to_string_lossy()
                .starts_with(".rabs-mat-")
        }));
    }

    #[test]
    fn action_freshness_is_installed_without_changing_cas_metadata() {
        for mode in [
            MaterializationMode::PrivateCopy,
            MaterializationMode::VerifiedCowReflink,
        ] {
            let dir = tempfile::tempdir().unwrap();
            let (mut store, _layout, object) = store_with_object(dir.path(), b"metadata bytes");
            let source = PathBuf::from(&store.object_locations(&object).unwrap()[0].0);
            let source_stamp = fs::metadata(&source).unwrap().modified().unwrap();
            let output = PlannedActionOutput {
                role: OutputRole::ProvisionalMetadata,
                virtual_path: RawBytes::from("out.rmeta"),
                object,
                destination: dir.path().join("out.rmeta"),
            };
            let freshness = SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(1_234_567_890);

            let receipt = install_one(&mut store, &output, freshness, mode, &|_, _| Ok(())).unwrap();

            assert_eq!(receipt.bytes, 14);
            assert_eq!(receipt.destination, output.destination);
            assert_eq!(fs::read(&output.destination).unwrap(), b"metadata bytes");
            assert_eq!(
                fs::metadata(&output.destination).unwrap().modified().unwrap(),
                freshness
            );
            assert_eq!(
                fs::metadata(&source).unwrap().modified().unwrap(),
                source_stamp
            );
        }
    }

    #[test]
    fn the_forbidden_hardlink_mode_demonstrably_corrupts() {
        // The negative control: WHY the variant does not exist. A
        // writable hardlink aliases the inode — mutating through the
        // alias changes the CAS bytes. This test documents the hazard
        // the policy kills (and doubles as the inode-alias corruption
        // probe for filesystems under test).
        let dir = scratch_dir("hardlink-hazard");
        let cas_object = dir.join("cas-object.rlib");
        fs::write(&cas_object, b"immutable cas bytes").unwrap();
        let before = fingerprint(&cas_object);

        let alias = dir.join("aliased-out.rlib");
        fs::hard_link(&cas_object, &alias).unwrap();
        fs::write(&alias, b"corrupted through the alias").unwrap();

        assert_ne!(
            fingerprint(&cas_object),
            before,
            "the hazard is real: alias mutation rewrites CAS bytes — \
             which is exactly why no writable-hardlink mode exists"
        );
        let _ = fs::remove_dir_all(&dir);
    }

    // -----------------------------------------------------------------
    // K004: pipelined action materialization (.rmeta first; plan §87).
    // -----------------------------------------------------------------

    use crate::blob_store::{BlobStoreLayout, DurabilityPolicy, PutLimits, put_if_absent};
    use crate::digest_set::digest_set;
    use crate::metadata_store::{RusqliteEngine, SqlMetadataStore};
    use rabs_protocol::raw_bytes::RawBytes;
    use rabs_protocol::result_identity::OutputRole;

    type TestStore = SqlMetadataStore<RusqliteEngine>;

    /// One action, ONE store: every output object of an action goes
    /// into this store, because a served hit resolves through a single
    /// CAS. Returns the scratch dir (destination parent), the layout,
    /// and the store.
    fn k004_fixture(name: &str) -> (PathBuf, BlobStoreLayout, TestStore) {
        let dir = scratch_dir(name);
        let layout = BlobStoreLayout::open(&dir.join("blobs")).unwrap();
        let engine = RusqliteEngine::open(&dir.join("meta.sqlite")).unwrap();
        let store = SqlMetadataStore::open(engine).unwrap();
        (dir, layout, store)
    }

    /// Commit `bytes` into the shared store and declare the planned
    /// output Cargo asked for.
    fn planned(
        dir: &Path,
        layout: &BlobStoreLayout,
        store: &mut TestStore,
        role: OutputRole,
        name: &str,
        bytes: &[u8],
    ) -> PlannedActionOutput {
        let declared = digest_set(bytes, DigestRequest::default(), None)
            .unwrap()
            .atp_content_id;
        let mut reader = bytes;
        put_if_absent(
            layout,
            store,
            &declared,
            &mut reader,
            PutLimits::default(),
            DurabilityPolicy::FULL,
        )
        .expect("put");
        PlannedActionOutput {
            role,
            virtual_path: RawBytes::new(name.as_bytes().to_vec()),
            object: declared,
            destination: dir.join(name),
        }
    }

    /// Rot the stored copy of `object` behind the store's back.
    fn rot(store: &mut TestStore, object: &TypedDigest) {
        let cas_path = store.object_locations(object).unwrap()[0].0.clone();
        fs::write(cas_path, b"tampered!!!!").unwrap();
    }

    #[test]
    fn rmeta_installs_before_everything_else_even_when_tail_copy_is_corrupt() {
        // THE ordering proof, black-box: corrupt ONE tail object's
        // stored copy. The action must fail — but the `.rmeta` must
        // already be on disk with exact verified bytes, proving the
        // head phase completed before the failing tail began.
        let (dir, layout, mut store) = k004_fixture("k004-head-first");
        let head = planned(
            &dir,
            &layout,
            &mut store,
            OutputRole::ProvisionalMetadata,
            "libfeat.rmeta",
            b"the exact provisional metadata",
        );
        let tail_a = planned(
            &dir,
            &layout,
            &mut store,
            OutputRole::Materializable,
            "b_libfeat.rlib",
            b"codegen a",
        );
        let tail_b = planned(
            &dir,
            &layout,
            &mut store,
            OutputRole::Materializable,
            "a_libfeat.rlib",
            b"codegen b",
        );
        rot(&mut store, &tail_b.object);

        let failure = materialize_action_outputs(
            &mut store,
            &[tail_a, tail_b.clone(), head.clone()],
            MaterializationMode::PrivateCopy,
        )
        .expect_err("corrupt tail copy must abort");
        assert!(
            matches!(failure.error, MaterializeError::ContentMismatch { .. }),
            "unexpected error: {:?}",
            failure.error
        );
        // Head installed BEFORE any tail work:
        assert_eq!(
            fs::read(&head.destination).unwrap(),
            b"the exact provisional metadata",
            ".rmeta must be fully installed before the tail failed"
        );
        // The deterministic tail order ran a_libfeat (corrupt) first,
        // so NOTHING of the tail survived; only the head is installed.
        assert_eq!(failure.installed.len(), 1);
        assert_eq!(failure.installed[0].virtual_path, head.virtual_path);
        assert!(
            !tail_b.destination.exists(),
            "the corrupt copy must install nothing"
        );
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn corrupt_rmeta_aborts_before_any_tail_output_is_installed() {
        let (dir, layout, mut store) = k004_fixture("k004-corrupt-head");
        let head = planned(
            &dir,
            &layout,
            &mut store,
            OutputRole::ProvisionalMetadata,
            "libx.rmeta",
            b"provisional metadata bytes",
        );
        let tail = planned(
            &dir,
            &layout,
            &mut store,
            OutputRole::Materializable,
            "libx.rlib",
            b"codegen",
        );
        rot(&mut store, &head.object);

        let failure = materialize_action_outputs(
            &mut store,
            &[tail, head.clone()],
            MaterializationMode::PrivateCopy,
        )
        .expect_err("corrupt head must abort");
        assert!(matches!(
            failure.error,
            MaterializeError::ContentMismatch { .. }
        ));
        assert!(failure.installed.is_empty());
        assert!(!dir.join("libx.rlib").exists(), "no tail output may exist");
        assert!(!head.destination.exists());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn freshness_stamp_is_one_coherent_instant_newer_than_preexisting_state() {
        // Plan §30 / risk R6: every output carries the SAME fresh mtime
        // so Cargo's mtime-sensitive freshness sees one coherent bundle,
        // newer than anything that predated the hit.
        let (dir, layout, mut store) = k004_fixture("k004-freshness");
        let head = planned(
            &dir,
            &layout,
            &mut store,
            OutputRole::ProvisionalMetadata,
            "m.rmeta",
            b"meta",
        );
        let depinfo = planned(
            &dir,
            &layout,
            &mut store,
            OutputRole::DepInfo,
            "lib.d",
            b"dep info",
        );
        let rlib = planned(
            &dir,
            &layout,
            &mut store,
            OutputRole::Materializable,
            "lib.rlib",
            b"codegen",
        );

        // Pre-existing files at the destinations (an older build's
        // outputs): the hit must land strictly NEWER than these.
        for out in [&head, &depinfo, &rlib] {
            fs::write(&out.destination, b"stale older build").unwrap();
        }
        let stale = filetime::FileTime::from_system_time(
            std::time::SystemTime::now() - std::time::Duration::from_secs(3600),
        );
        for out in [&head, &depinfo, &rlib] {
            filetime::set_file_mtime(&out.destination, stale).unwrap();
        }

        let receipt = materialize_action_outputs(
            &mut store,
            &[rlib, depinfo, head],
            MaterializationMode::PrivateCopy,
        )
        .expect("hit");
        assert_eq!(receipt.installed.len(), 3);

        let stamps: Vec<_> = receipt
            .installed
            .iter()
            .map(|done| {
                filetime::FileTime::from_last_modification_time(
                    &fs::metadata(&done.destination).unwrap(),
                )
            })
            .collect();
        assert_eq!(stamps[0], stamps[1], "one coherent bundle stamp");
        assert_eq!(stamps[1], stamps[2], "one coherent bundle stamp");
        assert!(
            stamps[0]
                > filetime::FileTime::from_system_time(
                    std::time::SystemTime::now() - std::time::Duration::from_secs(60)
                ),
            "hit outputs must be newer than recent inputs"
        );

        // Bytes are the committed objects, not the stale files.
        assert_eq!(fs::read(dir.join("m.rmeta")).unwrap(), b"meta");
        assert_eq!(fs::read(dir.join("lib.rlib")).unwrap(), b"codegen");
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn receipt_order_is_deterministic_and_head_phase_is_measured() {
        let (dir, layout, mut store) = k004_fixture("k004-receipt");
        let head = planned(
            &dir,
            &layout,
            &mut store,
            OutputRole::ProvisionalMetadata,
            "z.rmeta",
            b"m",
        );
        let t1 = planned(
            &dir,
            &layout,
            &mut store,
            OutputRole::Materializable,
            "c.rlib",
            b"1",
        );
        let t2 = planned(
            &dir,
            &layout,
            &mut store,
            OutputRole::Materializable,
            "a.rlib",
            b"2",
        );
        let t3 = planned(&dir, &layout, &mut store, OutputRole::DepInfo, "b.d", b"3");

        // Input order deliberately scrambled; head declared LAST.
        let receipt = materialize_action_outputs(
            &mut store,
            &[t3, t1, head.clone(), t2],
            MaterializationMode::PrivateCopy,
        )
        .expect("hit");

        let names: Vec<String> = receipt
            .installed
            .iter()
            .map(|d| d.virtual_path.as_utf8().unwrap().to_owned())
            .collect();
        assert_eq!(
            names,
            vec![
                "z.rmeta".to_owned(),
                "a.rlib".to_owned(),
                "b.d".to_owned(),
                "c.rlib".to_owned()
            ],
            "head first, then deterministic virtual-path byte order"
        );
        assert!(receipt.head_nanos >= receipt.installed[0].nanos);
        assert!(receipt.tail_nanos > 0);
        assert!(receipt.total_nanos >= receipt.head_nanos + receipt.tail_nanos);
        assert!(
            receipt.head_nanos < 50_000_000,
            "small-artifact head phase took {}ns; the <50ms hit target is \
             a property this layer must exhibit on trivial inputs",
            receipt.head_nanos
        );
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn duplicate_destinations_are_refused_before_any_installation() {
        let (dir, layout, mut store) = k004_fixture("k004-duplicate");
        let a = planned(
            &dir,
            &layout,
            &mut store,
            OutputRole::Materializable,
            "same.rlib",
            b"1",
        );
        let other = planned(
            &dir,
            &layout,
            &mut store,
            OutputRole::DepInfo,
            "other.d",
            b"2",
        );
        let collision = PlannedActionOutput {
            role: OutputRole::Materializable,
            virtual_path: RawBytes::new(b"different-virtual".to_vec()),
            object: other.object.clone(),
            destination: a.destination.clone(),
        };
        let failure = materialize_action_outputs(
            &mut store,
            &[a.clone(), collision],
            MaterializationMode::PrivateCopy,
        )
        .expect_err("duplicate destination");
        assert!(matches!(
            failure.error,
            MaterializeError::DuplicateDestination { .. }
        ));
        assert!(failure.installed.is_empty());
        assert!(!a.destination.exists(), "nothing installed");
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn lexical_destination_aliases_are_refused_without_installation() {
        let dir = tempfile::tempdir().unwrap();
        let (mut store, _layout, object) = store_with_object(dir.path(), b"artifact");
        let first = PlannedActionOutput {
            role: OutputRole::Materializable,
            virtual_path: RawBytes::from("first"),
            object,
            destination: dir.path().join("out.rlib"),
        };
        let alias = PlannedActionOutput {
            virtual_path: RawBytes::from("second"),
            destination: dir.path().join(".").join("out.rlib"),
            ..first.clone()
        };
        let failure = materialize_action_outputs(
            &mut store,
            &[first.clone(), alias],
            MaterializationMode::PrivateCopy,
        )
        .unwrap_err();
        assert!(matches!(
            failure.error,
            MaterializeError::DuplicateDestination { .. }
        ));
        assert!(failure.installed.is_empty());
        assert!(!first.destination.exists());

        // Relative and absolute spelling must name the same reservation key.
        let relative = PlannedActionOutput {
            destination: PathBuf::from("relative-output.rlib"),
            ..first.clone()
        };
        let absolute = PlannedActionOutput {
            destination: std::env::current_dir().unwrap().join(&relative.destination),
            ..first
        };
        assert!(matches!(
            validate_action_destinations(&[relative, absolute]),
            Err(MaterializeError::DuplicateDestination { .. })
        ));
    }

    #[test]
    fn ancestor_destinations_are_refused_before_either_installation_order() {
        let dir = tempfile::tempdir().unwrap();
        let (mut store, _layout, object) = store_with_object(dir.path(), b"artifact");
        let parent = PlannedActionOutput {
            role: OutputRole::Materializable,
            virtual_path: RawBytes::from("parent"),
            object,
            destination: dir.path().join("bundle"),
        };
        let child = PlannedActionOutput {
            role: OutputRole::ProvisionalMetadata,
            virtual_path: RawBytes::from("child"),
            destination: parent.destination.join("child.rmeta"),
            ..parent.clone()
        };
        for outputs in [
            [parent.clone(), child.clone()],
            [child.clone(), parent.clone()],
        ] {
            let failure = materialize_action_outputs(
                &mut store,
                &outputs,
                MaterializationMode::PrivateCopy,
            )
            .unwrap_err();
            assert!(matches!(
                failure.error,
                MaterializeError::OverlappingDestinations { .. }
            ));
            assert!(failure.installed.is_empty());
            assert!(!parent.destination.exists());
        }
    }

    #[test]
    fn parent_traversal_is_not_lexically_collapsed_through_possible_symlinks() {
        let dir = tempfile::tempdir().unwrap();
        let (mut store, _layout, object) = store_with_object(dir.path(), b"artifact");
        let output = PlannedActionOutput {
            role: OutputRole::ProvisionalMetadata,
            virtual_path: RawBytes::from("out.rmeta"),
            object,
            destination: dir.path().join("untrusted/../out.rmeta"),
        };
        let failure = materialize_action_outputs(
            &mut store,
            &[output],
            MaterializationMode::PrivateCopy,
        )
        .unwrap_err();
        assert!(matches!(
            failure.error,
            MaterializeError::UnsafeDestination { .. }
        ));
        assert!(failure.installed.is_empty());
        assert!(!dir.path().join("untrusted").exists());
        assert!(!dir.path().join("out.rmeta").exists());
    }

    #[cfg(unix)]
    #[test]
    fn distinct_non_utf8_destinations_do_not_collide_through_lossy_display() {
        use std::os::unix::ffi::OsStringExt;

        let dir = tempfile::tempdir().unwrap();
        let (mut store, _layout, object) = store_with_object(dir.path(), b"artifact");
        let first = PlannedActionOutput {
            role: OutputRole::Materializable,
            virtual_path: RawBytes::from("first"),
            object,
            destination: dir
                .path()
                .join(std::ffi::OsString::from_vec(b"out-\xff".to_vec())),
        };
        let second = PlannedActionOutput {
            virtual_path: RawBytes::from("second"),
            destination: dir
                .path()
                .join(std::ffi::OsString::from_vec(b"out-\xfe".to_vec())),
            ..first.clone()
        };
        assert_eq!(
            first.destination.to_string_lossy(),
            second.destination.to_string_lossy()
        );
        let receipt = materialize_action_outputs(
            &mut store,
            &[first.clone(), second.clone()],
            MaterializationMode::PrivateCopy,
        )
        .unwrap();
        assert_eq!(receipt.installed.len(), 2);
        assert_eq!(fs::read(&first.destination).unwrap(), b"artifact");
        assert_eq!(fs::read(&second.destination).unwrap(), b"artifact");
    }

    #[test]
    fn empty_plan_is_a_vacuous_success_and_unsupported_modes_refuse() {
        let (dir, layout, mut store) = k004_fixture("k004-empty");
        let receipt = materialize_action_outputs(&mut store, &[], MaterializationMode::PrivateCopy)
            .expect("empty plan");
        assert_eq!(receipt.installed, Vec::new());
        // Vacuous phases still cost the elapsed() call itself — a few
        // hundred ns — so the honest assertion is the <50ms gate, not
        // a literal zero.
        assert!(receipt.head_nanos < 50_000_000);
        assert!(receipt.tail_nanos < 50_000_000);

        // The mode policy still rules at action level: an unimplemented
        // mode is refused, never downgraded.
        let out = planned(
            &dir,
            &layout,
            &mut store,
            OutputRole::Materializable,
            "x.rlib",
            b"x",
        );
        assert!(matches!(
            materialize_action_outputs(&mut store, &[out], MaterializationMode::ReadOnlyBind),
            Err(ActionMaterializeFailure {
                error: MaterializeError::ModeUnsupported(MaterializationMode::ReadOnlyBind),
                ..
            })
        ));
        let _ = fs::remove_dir_all(&dir);
    }

    // -----------------------------------------------------------------
    // K005: gated verbatim artifact-notification replay.
    // -----------------------------------------------------------------

    use crate::materialization::StoredArtifactNotification;

    fn notification(destination: &Path, body: &str) -> StoredArtifactNotification {
        StoredArtifactNotification {
            exact_line: body.as_bytes().to_vec(),
            announced_destination: destination.to_path_buf(),
        }
    }

    #[test]
    fn replay_is_gated_on_materialization_and_byte_verbatim() {
        let (dir, layout, mut store) = k004_fixture("k005-gated");
        let head = planned(
            &dir,
            &layout,
            &mut store,
            OutputRole::ProvisionalMetadata,
            "libg.rmeta",
            b"meta",
        );
        let depinfo = planned(
            &dir,
            &layout,
            &mut store,
            OutputRole::DepInfo,
            "libg.d",
            b"d",
        );
        let rlib = planned(
            &dir,
            &layout,
            &mut store,
            OutputRole::Materializable,
            "libg.rlib",
            b"code",
        );
        let receipt = materialize_action_outputs(
            &mut store,
            &[depinfo.clone(), rlib.clone(), head.clone()],
            MaterializationMode::PrivateCopy,
        )
        .expect("hit");

        // dep-info carries NO stored notification: no event for it.
        let lines = [
            notification(
                &rlib.destination,
                r#"{"artifact":"/wt/target/debug/libg.rlib","notification":true}"#,
            ),
            notification(
                &head.destination,
                r#"{"artifact":"/wt/target/debug/libg.rmeta","notification":true}"#,
            ),
        ];
        let stream = plan_notification_replay(&receipt, &lines).expect("stream");
        assert_eq!(stream.len(), 2, "exactly the stored lines, once each");
        assert!(
            stream[0].windows(11).any(|w| w == b"libg.rmeta\""),
            ".rmeta notification must lead: it is what unblocks dependents"
        );
        assert_eq!(
            stream[1], lines[0].exact_line,
            "tail line is byte-verbatim after its output"
        );
    }

    #[test]
    fn unbound_duplicate_and_empty_lines_are_typed_refusals() {
        let (dir, layout, mut store) = k004_fixture("k005-refusals");
        let head = planned(
            &dir,
            &layout,
            &mut store,
            OutputRole::ProvisionalMetadata,
            "m.rmeta",
            b"m",
        );
        let receipt = materialize_action_outputs(
            &mut store,
            std::slice::from_ref(&head),
            MaterializationMode::PrivateCopy,
        )
        .expect("hit");

        let stranger = dir.join("not-in-plan.rlib");
        assert_eq!(
            plan_notification_replay(&receipt, &[notification(&stranger, r#"{"artifact":"x"}"#)],),
            Err(ReplayPlanError::UnboundLine {
                path: stranger.to_string_lossy().into_owned()
            }),
            "no proof of completeness -> refuse, never emit"
        );
        let line = notification(&head.destination, r#"{"artifact":"m"}"#);
        assert_eq!(
            plan_notification_replay(&receipt, &[line.clone(), line]),
            Err(ReplayPlanError::DuplicateAnnouncement {
                path: head.destination.to_string_lossy().into_owned()
            }),
            "exactly-once makes duplicates unrepresentable"
        );
        assert_eq!(
            plan_notification_replay(&receipt, &[notification(&head.destination, "")]),
            Err(ReplayPlanError::EmptyLine),
        );
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn cache_hit_stream_matches_stock_pipelining() {
        // THE acceptance scenario. Stock pipelining observable order:
        // the .rmeta notification FIRST (Cargo's metadata edge
        // completes; dependents start), then remaining notifications,
        // each only after its output exists on disk. The cache-hit
        // stream must reproduce exactly that, from verbatim bytes.
        let (dir, layout, mut store) = k004_fixture("k005-stock-pipelining");
        let head = planned(
            &dir,
            &layout,
            &mut store,
            OutputRole::ProvisionalMetadata,
            "libs.rmeta",
            b"meta",
        );
        let rlib = planned(
            &dir,
            &layout,
            &mut store,
            OutputRole::Materializable,
            "libs.rlib",
            b"code",
        );
        let receipt = materialize_action_outputs(
            &mut store,
            &[rlib.clone(), head.clone()],
            MaterializationMode::PrivateCopy,
        )
        .expect("hit");

        let rmeta_line =
            br#"{"artifact":"/wt/target/debug/deps/libs.rmeta","focus":["Meta"]}"#.to_vec();
        let rlib_line =
            br#"{"artifact":"/wt/target/debug/deps/libs.rlib","focus":["Codegen"]}"#.to_vec();
        let stock_order = vec![rmeta_line.clone(), rlib_line.clone()];

        // Input deliberately REVERSED vs stock: gating, not input
        // order, produces the pipelining sequence.
        let stream = plan_notification_replay(
            &receipt,
            &[
                StoredArtifactNotification {
                    exact_line: rlib_line,
                    announced_destination: rlib.destination.clone(),
                },
                StoredArtifactNotification {
                    exact_line: rmeta_line,
                    announced_destination: head.destination.clone(),
                },
            ],
        )
        .expect("stream");

        assert_eq!(
            stream, stock_order,
            ".rmeta leads; each line follows its file"
        );

        // Structural anti-synthesis: every emitted byte came from a
        // stored line — the module exposes no constructor that could
        // have produced these bytes by itself.
        for (emitted, stored) in stream.iter().zip(stock_order.iter()) {
            assert_eq!(emitted, stored);
        }
        let _ = fs::remove_dir_all(&dir);
    }
}
