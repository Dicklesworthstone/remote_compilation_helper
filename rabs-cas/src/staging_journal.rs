//! H007 — staging directories and append journals (plan §90; crash
//! recovery for in-flight CAS writes).
//!
//! Layout under the blob-store root:
//!
//! - `staging/<op>/<attempt>/object` — each in-flight write stages in
//!   its OWN per-operation, per-attempt directory, never inside the
//!   published namespace;
//! - `journals/<op>.journal` — one append-only journal per operation
//!   recording every attempt's lifecycle: `begin` (declared identity +
//!   staging path), then exactly one of `published` / `aborted`.
//!
//! Journal records are length-framed and checksummed
//! (`len(u32 be) || payload || blake3_4(payload)`), so a crash mid-
//! append leaves a TORN TAIL that replay detects and stops at — every
//! record before the tail is trusted, nothing after it is guessed.
//! Appends are fsynced before the corresponding filesystem step is
//! considered intent-recorded (write-ahead: `begin` lands before bytes
//! stream, `published` after the atomic link, so replay can always
//! bound what the crashed process may have done).
//!
//! [`recover_operations`] scans every journal against staging/
//! published reality and resolves each non-terminal attempt:
//!
//! - staged bytes VERIFY against the declared identity → **resume**:
//!   publish through the H003 pipeline (`publish_staged`) and record
//!   `published`;
//! - staged bytes missing/partial/wrong → **clean**: remove the
//!   attempt's staging directory and record `aborted`;
//! - terminal attempts keep their outcome; their leftover staging is
//!   swept (the dead-writer orphan case H003's crash tests defer
//!   here).
//!
//! Recovery never appends after a torn tail: once every attempt is
//! resolved its outcome lives in durable reality (published objects +
//! metadata rows), so the journal is RETIRED whole. Running recovery
//! twice is a no-op.

use std::fs;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use rabs_protocol::result_identity::TypedDigest;

use crate::blob_store::{
    BlobStoreLayout, DurabilityPolicy, PutError, PutLimits, PutOutcome, io_err, publish_staged,
    recompute_file_digest, stream_to_staging,
};
use crate::metadata_store::{RabsMetadataStore, digest_key};

/// One journal record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum JournalRecord {
    /// An attempt began staging bytes for `declared_key`.
    Begin {
        /// Attempt id, hex.
        attempt_hex: String,
        /// Declared digest key (`domain:hex`) of the staged object.
        declared_key: String,
    },
    /// The attempt's object was published (atomic link done).
    Published {
        /// Attempt id, hex.
        attempt_hex: String,
    },
    /// The attempt was abandoned; its staging is garbage.
    Aborted {
        /// Attempt id, hex.
        attempt_hex: String,
        /// Why.
        reason: String,
    },
}

impl JournalRecord {
    fn encode(&self) -> String {
        match self {
            Self::Begin {
                attempt_hex,
                declared_key,
            } => format!("begin|{attempt_hex}|{declared_key}"),
            Self::Published { attempt_hex } => format!("published|{attempt_hex}"),
            Self::Aborted {
                attempt_hex,
                reason,
            } => format!("aborted|{attempt_hex}|{reason}"),
        }
    }

    fn decode(payload: &str) -> Option<Self> {
        let mut parts = payload.splitn(3, '|');
        let kind = parts.next()?;
        let attempt_hex = parts.next()?.to_owned();
        match kind {
            "begin" => Some(Self::Begin {
                attempt_hex,
                declared_key: parts.next()?.to_owned(),
            }),
            "published" => Some(Self::Published { attempt_hex }),
            "aborted" => Some(Self::Aborted {
                attempt_hex,
                reason: parts.next().unwrap_or("").to_owned(),
            }),
            _ => None,
        }
    }
}

/// Replay result: every intact record in order, plus whether the file
/// ended in a torn/corrupt tail.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JournalReplay {
    /// Intact records, journal order.
    pub records: Vec<JournalRecord>,
    /// A truncated or checksum-failed tail was found (and ignored).
    pub torn_tail: bool,
}

fn record_checksum(payload: &[u8]) -> [u8; 4] {
    let digest = blake3::hash(payload);
    let mut out = [0_u8; 4];
    out.copy_from_slice(&digest.as_bytes()[..4]);
    out
}

fn journals_dir(layout: &BlobStoreLayout) -> PathBuf {
    layout.root().join("journals")
}

fn journal_path(layout: &BlobStoreLayout, op_hex: &str) -> PathBuf {
    journals_dir(layout).join(format!("{op_hex}.journal"))
}

fn op_staging_dir(layout: &BlobStoreLayout, op_hex: &str) -> PathBuf {
    layout.root().join("staging").join(op_hex)
}

fn u128_hex(v: u128) -> String {
    format!("{v:032x}")
}

/// Handle to one operation's staging + journal.
#[derive(Debug, Clone)]
pub struct StagingJournal {
    layout: BlobStoreLayout,
    op_hex: String,
}

impl StagingJournal {
    /// Open (creating the journal directory if needed) the journal for
    /// operation `op`.
    ///
    /// # Errors
    /// [`PutError::Io`] when the directory cannot be created.
    pub fn open(layout: &BlobStoreLayout, op: u128) -> Result<Self, PutError> {
        fs::create_dir_all(journals_dir(layout)).map_err(io_err("create-journals-dir"))?;
        Ok(Self {
            layout: layout.clone(),
            op_hex: u128_hex(op),
        })
    }

    /// The attempt's staging directory (`staging/<op>/<attempt>/`).
    #[must_use]
    pub fn attempt_dir(&self, attempt: u128) -> PathBuf {
        op_staging_dir(&self.layout, &self.op_hex).join(u128_hex(attempt))
    }

    /// Append one record and fsync the journal file.
    ///
    /// # Errors
    /// [`PutError::Io`] on append/sync failure.
    pub fn append(&self, record: &JournalRecord) -> Result<(), PutError> {
        let payload = record.encode();
        let payload = payload.as_bytes();
        let mut framed = Vec::with_capacity(payload.len() + 8);
        framed.extend_from_slice(&(payload.len() as u32).to_be_bytes());
        framed.extend_from_slice(payload);
        framed.extend_from_slice(&record_checksum(payload));
        let mut file = fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(journal_path(&self.layout, &self.op_hex))
            .map_err(io_err("open-journal"))?;
        file.write_all(&framed).map_err(io_err("append-journal"))?;
        file.sync_all().map_err(io_err("fsync-journal"))?;
        Ok(())
    }

    /// Replay the journal, tolerating a torn tail.
    ///
    /// # Errors
    /// [`PutError::Io`] when the journal exists but cannot be read.
    pub fn replay(&self) -> Result<JournalReplay, PutError> {
        replay_file(&journal_path(&self.layout, &self.op_hex))
    }
}

fn replay_file(path: &Path) -> Result<JournalReplay, PutError> {
    let bytes = match fs::read(path) {
        Ok(bytes) => bytes,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return Ok(JournalReplay {
                records: Vec::new(),
                torn_tail: false,
            });
        }
        Err(e) => return Err(io_err("read-journal")(e)),
    };
    let mut records = Vec::new();
    let mut cursor = 0_usize;
    let mut torn_tail = false;
    while cursor < bytes.len() {
        let Some(header) = bytes.get(cursor..cursor + 4) else {
            torn_tail = true;
            break;
        };
        let len = u32::from_be_bytes([header[0], header[1], header[2], header[3]]) as usize;
        let Some(payload) = bytes.get(cursor + 4..cursor + 4 + len) else {
            torn_tail = true;
            break;
        };
        let Some(stored_sum) = bytes.get(cursor + 4 + len..cursor + 8 + len) else {
            torn_tail = true;
            break;
        };
        if stored_sum != record_checksum(payload) {
            torn_tail = true;
            break;
        }
        let Some(record) = std::str::from_utf8(payload)
            .ok()
            .and_then(JournalRecord::decode)
        else {
            torn_tail = true;
            break;
        };
        records.push(record);
        cursor += 8 + len;
    }
    Ok(JournalReplay { records, torn_tail })
}

/// Journaled `put_if_absent`: write-ahead `begin`, stage under the
/// attempt's own directory, verify + publish through the H003
/// pipeline, then record the terminal outcome. Refusals record
/// `aborted` and clean the attempt's staging directory.
///
/// # Errors
/// A typed [`PutError`]; refusals publish nothing.
#[allow(clippy::too_many_arguments)]
pub fn put_if_absent_journaled(
    layout: &BlobStoreLayout,
    store: &mut dyn RabsMetadataStore,
    op: u128,
    attempt: u128,
    declared: &TypedDigest,
    reader: &mut dyn Read,
    limits: PutLimits,
    durability: DurabilityPolicy,
) -> Result<PutOutcome, PutError> {
    let journal = StagingJournal::open(layout, op)?;
    let attempt_hex = u128_hex(attempt);
    let dir = journal.attempt_dir(attempt);
    fs::create_dir_all(&dir).map_err(io_err("create-attempt-dir"))?;
    // Write-ahead intent BEFORE any object bytes exist.
    journal.append(&JournalRecord::Begin {
        attempt_hex: attempt_hex.clone(),
        declared_key: digest_key(declared),
    })?;

    let staging = dir.join("object");
    let outcome = stage_verify_publish(
        layout, store, declared, reader, limits, durability, &staging,
    );
    match &outcome {
        Ok(_) => {
            journal.append(&JournalRecord::Published {
                attempt_hex: attempt_hex.clone(),
            })?;
        }
        Err(e) => {
            journal.append(&JournalRecord::Aborted {
                attempt_hex: attempt_hex.clone(),
                reason: format!("{e:?}"),
            })?;
        }
    }
    let _ = fs::remove_dir_all(&dir);
    outcome
}

fn stage_verify_publish(
    layout: &BlobStoreLayout,
    store: &mut dyn RabsMetadataStore,
    declared: &TypedDigest,
    reader: &mut dyn Read,
    limits: PutLimits,
    durability: DurabilityPolicy,
    staging: &Path,
) -> Result<PutOutcome, PutError> {
    let digests = match stream_to_staging(staging, reader, limits) {
        Ok(digests) => digests,
        Err(e) => {
            let _ = fs::remove_file(staging);
            return Err(e);
        }
    };
    if digests.atp_content_id != *declared {
        let computed = digest_key(&digests.atp_content_id);
        let _ = fs::remove_file(staging);
        return Err(PutError::DeclaredDigestMismatch {
            declared: digest_key(declared),
            computed,
        });
    }
    publish_staged(layout, store, declared, staging, durability)
}

/// What recovery did to one attempt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RecoveryAction {
    /// Staged bytes verified against the declared identity and were
    /// published.
    Resumed {
        /// Published path.
        path: String,
    },
    /// Staging was missing/partial/wrong (or the attempt was already
    /// terminal); leftovers removed.
    Cleaned,
}

/// The recovery product.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct RecoveryReport {
    /// Per (op hex, attempt hex) resolution of non-terminal attempts.
    pub resolved: Vec<(String, String, RecoveryAction)>,
    /// Journals that ended in a torn/corrupt tail (rewritten).
    pub torn_journals: Vec<String>,
    /// Journals fully terminal and retired this pass.
    pub retired_journals: Vec<String>,
}

/// Scan every journal, resolve every non-terminal attempt
/// (resume-or-clean), sweep terminal attempts' staging leftovers,
/// rewrite torn journals, and retire fully-terminal ones. Idempotent.
///
/// # Errors
/// [`PutError`] on filesystem/store failures (individual attempt
/// resolutions that legitimately refuse — e.g. collision incidents —
/// are recorded as `aborted`, not surfaced as errors).
pub fn recover_operations(
    layout: &BlobStoreLayout,
    store: &mut dyn RabsMetadataStore,
    durability: DurabilityPolicy,
) -> Result<RecoveryReport, PutError> {
    let mut report = RecoveryReport::default();
    let journals = journals_dir(layout);
    fs::create_dir_all(&journals).map_err(io_err("create-journals-dir"))?;
    let mut journal_files: Vec<PathBuf> = fs::read_dir(&journals)
        .map_err(io_err("read-journals-dir"))?
        .filter_map(|entry| {
            let path = entry.ok()?.path();
            (path.extension().is_some_and(|e| e == "journal")).then_some(path)
        })
        .collect();
    journal_files.sort();

    for path in journal_files {
        let op_hex = path
            .file_stem()
            .map(|s| s.to_string_lossy().into_owned())
            .unwrap_or_default();
        let replay = replay_file(&path)?;
        if replay.torn_tail {
            report.torn_journals.push(op_hex.clone());
        }

        // Fold to per-attempt final state, preserving begin metadata.
        let mut attempts: Vec<(String, Option<String>, bool)> = Vec::new(); // (attempt, declared_key if open, terminal)
        for record in &replay.records {
            match record {
                JournalRecord::Begin {
                    attempt_hex,
                    declared_key,
                } => {
                    if !attempts.iter().any(|(a, _, _)| a == attempt_hex) {
                        attempts.push((attempt_hex.clone(), Some(declared_key.clone()), false));
                    }
                }
                JournalRecord::Published { attempt_hex }
                | JournalRecord::Aborted { attempt_hex, .. } => {
                    if let Some(entry) = attempts.iter_mut().find(|(a, _, _)| a == attempt_hex) {
                        entry.2 = true;
                    }
                }
            }
        }

        for (attempt_hex, declared_key, terminal) in &attempts {
            let attempt_dir = op_staging_dir(layout, &op_hex).join(attempt_hex);
            if *terminal {
                // Dead writer's leftovers (H003's deferred orphans).
                let _ = fs::remove_dir_all(&attempt_dir);
                continue;
            }
            let staged = attempt_dir.join("object");
            let action = resolve_open_attempt(layout, store, declared_key, &staged, durability)?;
            let _ = fs::remove_dir_all(&attempt_dir);
            report
                .resolved
                .push((op_hex.clone(), attempt_hex.clone(), action));
        }

        // Every attempt is now terminal: retire the journal and the
        // operation's staging directory. (Rewrite is unnecessary — the
        // resolved state is fully reflected in durable reality.)
        let _ = fs::remove_dir_all(op_staging_dir(layout, &op_hex));
        fs::remove_file(&path).map_err(io_err("retire-journal"))?;
        report.retired_journals.push(op_hex);
    }
    Ok(report)
}

/// Resolve one open attempt: resume iff the staged bytes verify
/// against the declared identity; clean otherwise. Publication
/// refusals (e.g. a collision incident) resolve as Cleaned — the
/// incident machinery has already preserved the evidence.
fn resolve_open_attempt(
    layout: &BlobStoreLayout,
    store: &mut dyn RabsMetadataStore,
    declared_key: &Option<String>,
    staged: &Path,
    durability: DurabilityPolicy,
) -> Result<RecoveryAction, PutError> {
    let Some(declared_key) = declared_key else {
        return Ok(RecoveryAction::Cleaned);
    };
    if !staged.exists() {
        return Ok(RecoveryAction::Cleaned);
    }
    let recomputed = match recompute_file_digest(staged) {
        Ok(digest) => digest,
        Err(_) => return Ok(RecoveryAction::Cleaned),
    };
    if digest_key(&recomputed) != *declared_key {
        return Ok(RecoveryAction::Cleaned);
    }
    match publish_staged(layout, store, &recomputed, staged, durability) {
        Ok(PutOutcome::Stored { path } | PutOutcome::IdempotentDuplicate { path }) => {
            Ok(RecoveryAction::Resumed { path })
        }
        Err(PutError::CollisionIncident { .. }) => Ok(RecoveryAction::Cleaned),
        Err(e) => Err(e),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::digest_set::{DigestRequest, digest_set};
    use crate::metadata_store::{RusqliteEngine, SqlMetadataStore};
    use std::sync::atomic::{AtomicU64, Ordering};

    static DIR_COUNTER: AtomicU64 = AtomicU64::new(0);

    fn fresh_layout(tag: &str) -> BlobStoreLayout {
        let n = DIR_COUNTER.fetch_add(1, Ordering::SeqCst);
        let root = std::env::temp_dir().join(format!("rabs-h007-{}-{tag}-{n}", std::process::id()));
        fs::create_dir_all(&root).unwrap();
        BlobStoreLayout::open(&root).unwrap()
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
    fn h007_journaled_put_records_lifecycle_and_cleans_staging() {
        let layout = fresh_layout("basic");
        let mut store = store();
        let bytes = b"journaled object".to_vec();
        let declared = id_of(&bytes);

        let outcome = put_if_absent_journaled(
            &layout,
            &mut store,
            5,
            9,
            &declared,
            &mut bytes.as_slice(),
            PutLimits::default(),
            DurabilityPolicy::FULL,
        )
        .unwrap();
        assert!(matches!(outcome, PutOutcome::Stored { .. }));

        let journal = StagingJournal::open(&layout, 5).unwrap();
        let replay = journal.replay().unwrap();
        assert!(!replay.torn_tail);
        assert_eq!(
            replay.records,
            vec![
                JournalRecord::Begin {
                    attempt_hex: format!("{:032x}", 9),
                    declared_key: digest_key(&declared),
                },
                JournalRecord::Published {
                    attempt_hex: format!("{:032x}", 9),
                },
            ]
        );
        assert!(!journal.attempt_dir(9).exists());

        // A refused put records `aborted`.
        let wrong = id_of(b"different bytes");
        let refused = put_if_absent_journaled(
            &layout,
            &mut store,
            5,
            10,
            &wrong,
            &mut bytes.as_slice(),
            PutLimits::default(),
            DurabilityPolicy::FULL,
        );
        assert!(matches!(
            refused,
            Err(PutError::DeclaredDigestMismatch { .. })
        ));
        let replay = journal.replay().unwrap();
        assert!(matches!(
            replay.records.last(),
            Some(JournalRecord::Aborted { attempt_hex, .. }) if *attempt_hex == format!("{:032x}", 10)
        ));

        // Recovery over a fully-terminal journal just retires it.
        let report = recover_operations(&layout, &mut store, DurabilityPolicy::FULL).unwrap();
        assert!(report.resolved.is_empty());
        assert_eq!(report.retired_journals, vec![format!("{:032x}", 5)]);
        assert!(journal.replay().unwrap().records.is_empty());
    }

    #[test]
    fn h007_crash_mid_stage_recovery_resumes_complete_and_cleans_partial() {
        let layout = fresh_layout("recover");
        let mut store = store();

        // Simulate a writer that died mid-operation: journal has
        // `begin` for two attempts; attempt A staged COMPLETE bytes,
        // attempt B staged a PARTIAL prefix. No terminal records.
        let complete = b"complete staged object".to_vec();
        let declared_a = id_of(&complete);
        let journal = StagingJournal::open(&layout, 7).unwrap();
        let dir_a = journal.attempt_dir(1);
        let dir_b = journal.attempt_dir(2);
        fs::create_dir_all(&dir_a).unwrap();
        fs::create_dir_all(&dir_b).unwrap();
        journal
            .append(&JournalRecord::Begin {
                attempt_hex: format!("{:032x}", 1),
                declared_key: digest_key(&declared_a),
            })
            .unwrap();
        journal
            .append(&JournalRecord::Begin {
                attempt_hex: format!("{:032x}", 2),
                declared_key: digest_key(&declared_a),
            })
            .unwrap();
        fs::write(dir_a.join("object"), &complete).unwrap();
        fs::write(dir_b.join("object"), &complete[..5]).unwrap();

        let report = recover_operations(&layout, &mut store, DurabilityPolicy::FULL).unwrap();
        assert_eq!(report.resolved.len(), 2);
        let action_a = &report
            .resolved
            .iter()
            .find(|(_, a, _)| *a == format!("{:032x}", 1))
            .unwrap()
            .2;
        let RecoveryAction::Resumed { path } = action_a else {
            panic!("complete staging must RESUME, got {action_a:?}");
        };
        assert_eq!(fs::read(path).unwrap(), complete);
        assert!(store.object_located(&declared_a).unwrap());
        let action_b = &report
            .resolved
            .iter()
            .find(|(_, a, _)| *a == format!("{:032x}", 2))
            .unwrap()
            .2;
        assert_eq!(*action_b, RecoveryAction::Cleaned);

        // Staging fully swept, journal retired, second pass a no-op.
        assert!(!op_staging_dir(&layout, &format!("{:032x}", 7)).exists());
        let again = recover_operations(&layout, &mut store, DurabilityPolicy::FULL).unwrap();
        assert!(again.resolved.is_empty() && again.retired_journals.is_empty());
    }

    #[test]
    fn h007_torn_tail_is_detected_and_never_trusted() {
        let layout = fresh_layout("torn");
        let mut store = store();
        let bytes = b"torn tail object".to_vec();
        let declared = id_of(&bytes);
        let journal = StagingJournal::open(&layout, 3).unwrap();
        journal
            .append(&JournalRecord::Begin {
                attempt_hex: format!("{:032x}", 1),
                declared_key: digest_key(&declared),
            })
            .unwrap();
        journal
            .append(&JournalRecord::Published {
                attempt_hex: format!("{:032x}", 1),
            })
            .unwrap();

        // Crash mid-append: a truncated frame, then (separately) a
        // checksum-corrupt frame.
        let path = journals_dir(&layout).join(format!("{:032x}.journal", 3));
        let intact = fs::read(&path).unwrap();
        for tail in [
            vec![0, 0, 0, 42, b'p', b'a', b'r'], // truncated payload
            {
                let payload = b"aborted|deadbeef|x".to_vec();
                let mut frame = (payload.len() as u32).to_be_bytes().to_vec();
                frame.extend_from_slice(&payload);
                frame.extend_from_slice(&[0, 0, 0, 0]); // wrong checksum
                frame
            },
        ] {
            let mut torn = intact.clone();
            torn.extend_from_slice(&tail);
            fs::write(&path, &torn).unwrap();
            let replay = journal.replay().unwrap();
            assert!(replay.torn_tail, "tail {tail:?} must be detected");
            assert_eq!(replay.records.len(), 2, "intact prefix fully trusted");
        }

        // Recovery over the torn journal reports it and still resolves
        // cleanly (all recorded attempts are terminal).
        let report = recover_operations(&layout, &mut store, DurabilityPolicy::FULL).unwrap();
        assert_eq!(report.torn_journals, vec![format!("{:032x}", 3)]);
        assert_eq!(report.retired_journals, vec![format!("{:032x}", 3)]);
    }

    #[test]
    fn h007_recovery_is_reconstructible_at_every_crash_boundary() {
        // Crash the journaled put at each lifecycle boundary by
        // REPLAYING the exact on-disk states it passes through, and
        // assert recovery resolves every one without partial exposure.
        let bytes = b"boundary object".to_vec();
        struct Boundary {
            name: &'static str,
            stage_bytes: Option<&'static [u8]>, // staged file content at crash
            begin_recorded: bool,
        }
        let boundaries = [
            Boundary {
                name: "after-begin-no-bytes",
                stage_bytes: None,
                begin_recorded: true,
            },
            Boundary {
                name: "after-partial-stage",
                stage_bytes: Some(b"boundary"),
                begin_recorded: true,
            },
            Boundary {
                name: "after-full-stage",
                stage_bytes: Some(b"boundary object"),
                begin_recorded: true,
            },
        ];
        for boundary in boundaries {
            let layout = fresh_layout(boundary.name);
            let mut store = store();
            let declared = id_of(&bytes);
            let journal = StagingJournal::open(&layout, 11).unwrap();
            let dir = journal.attempt_dir(1);
            fs::create_dir_all(&dir).unwrap();
            if boundary.begin_recorded {
                journal
                    .append(&JournalRecord::Begin {
                        attempt_hex: format!("{:032x}", 1),
                        declared_key: digest_key(&declared),
                    })
                    .unwrap();
            }
            if let Some(staged) = boundary.stage_bytes {
                fs::write(dir.join("object"), staged).unwrap();
            }

            let report = recover_operations(&layout, &mut store, DurabilityPolicy::FULL).unwrap();
            assert_eq!(report.resolved.len(), 1, "{}", boundary.name);
            match &report.resolved[0].2 {
                RecoveryAction::Resumed { path } => {
                    assert_eq!(
                        fs::read(path).unwrap(),
                        bytes,
                        "{}: resumed object must be complete",
                        boundary.name
                    );
                    assert!(store.object_located(&declared).unwrap());
                }
                RecoveryAction::Cleaned => {
                    assert!(
                        !store.object_located(&declared).unwrap(),
                        "{}: cleaned attempt must not be recorded",
                        boundary.name
                    );
                }
            }
            assert!(!dir.exists(), "{}: staging swept", boundary.name);
            assert!(
                journal.replay().unwrap().records.is_empty(),
                "{}: journal retired",
                boundary.name
            );
        }
    }
}
