//! Materialization: turning a committed CAS object into a file in a
//! live worktree (bead bd-bres9), under the D023 mode policy.
//!
//! Two halves:
//!
//! - [`decide_materialization`] — the mode policy (D023; invariant I33;
//!   risk R65), unchanged: a writable hardlink to an immutable CAS inode
//!   is unrepresentable, not merely discouraged.
//! - [`materialize_object`] — the byte path. It resolves a
//!   non-quarantined raw copy through the metadata store (the store is
//!   the authority on where copies are), streams it into a staging file
//!   beside the destination while hashing, REFUSES if the recomputed
//!   content id is not the object's identity, and only then renames it
//!   into place. Unverified bytes are never installed, and a partially
//!   written file is never visible at the destination path.
//!
//! Only [`MaterializationMode::PrivateCopy`] is implemented here.
//! `VerifiedCowReflink` needs the H017 reflink backend AND something
//! that actually verifies reflink isolation on the filesystem in hand
//! (nothing computes that today); `ReadOnlyBind` needs mount
//! privileges. Both are typed refusals rather than a silent downgrade —
//! a caller that asked for CoW isolation and got a copy would be
//! reasoning about the wrong isolation properties.
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

use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use rabs_protocol::result_identity::TypedDigest;

use crate::blob_store::RAW_PROFILE_V1;
use crate::digest_set::{DigestRequest, StreamingObjectWriter};
use crate::metadata_store::{RabsMetadataStore, StoreError, digest_key};

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
}

impl std::fmt::Display for MaterializeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ModeUnsupported(mode) => write!(f, "materialization mode {mode:?} unimplemented"),
            Self::NoUsableCopy { object } => write!(f, "no usable copy of {object}"),
            Self::Unreadable { path, error } => write!(f, "unreadable copy {path}: {error}"),
            Self::ContentMismatch {
                expected,
                found,
                path,
            } => write!(f, "{path} holds {found}, not {expected}"),
            Self::Io { step, error } => write!(f, "{step}: {error}"),
            Self::Store(error) => write!(f, "store: {error}"),
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
    if mode != MaterializationMode::PrivateCopy {
        return Err(MaterializeError::ModeUnsupported(mode));
    }
    let key = digest_key(object);
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
        match copy_verified(&source, object, &key, &parent, destination) {
            Ok(bytes) => return Ok(bytes),
            // A corrupt copy is reported as such immediately: silently
            // trying the next one would hide store corruption that the
            // GC/quarantine flow needs to hear about.
            Err(error @ MaterializeError::ContentMismatch { .. }) => return Err(error),
            Err(error) => last = Some(error),
        }
    }
    Err(last.unwrap_or(MaterializeError::NoUsableCopy { object: key }))
}

/// Stream one copy into a staging file next to `destination`, verifying
/// the content id as the bytes go past, then rename into place.
fn copy_verified(
    source: &str,
    object: &TypedDigest,
    key: &str,
    parent: &Path,
    destination: &Path,
) -> Result<u64, MaterializeError> {
    let mut input = std::fs::File::open(source).map_err(|e| MaterializeError::Unreadable {
        path: source.to_owned(),
        error: e.to_string(),
    })?;
    let staging = staging_path(parent, destination);
    let mut output = std::fs::File::create(&staging).map_err(io_err("create-staging"))?;
    let mut writer = StreamingObjectWriter::new(DigestRequest::default(), None);
    let mut buffer = vec![0_u8; 64 * 1024];
    let mut written = 0_u64;
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
        if let Err(e) = std::io::Write::write_all(&mut output, &buffer[..read]) {
            break Err(MaterializeError::Io {
                step: "write-staging",
                error: e.to_string(),
            });
        }
        written += read as u64;
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
    // The bytes are the object's. Publish them atomically; a reader
    // never observes a half-written artifact at the destination.
    if let Err(error) = std::fs::rename(&staging, destination) {
        let _ = std::fs::remove_file(&staging);
        return Err(MaterializeError::Io {
            step: "rename-into-place",
            error: error.to_string(),
        });
    }
    Ok(written)
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
    /// Copy-on-write reflink VERIFIED isolated on this filesystem:
    /// mutation permitted (the write is redirected), mtime permitted.
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
        // A mode we cannot honor is refused, never downgraded to a copy.
        for mode in [
            MaterializationMode::VerifiedCowReflink,
            MaterializationMode::ReadOnlyBind,
        ] {
            assert_eq!(
                materialize_object(&mut store, &object, &dir.join("b.rlib"), mode),
                Err(MaterializeError::ModeUnsupported(mode))
            );
        }
        assert!(!dir.join("b.rlib").exists());
        let _ = fs::remove_dir_all(&dir);
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
}
