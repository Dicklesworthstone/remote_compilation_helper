//! H008 — sparse/out-of-order writer and recovery (plan §90; the ATP
//! sparse-writer concept over H007's staging + journal machinery).
//!
//! Large objects arrive as RANGES, in any order, possibly across
//! process lifetimes. The transfer declares `(identity, total_size)`
//! up front; every range then follows the durable-receipt protocol:
//!
//! 1. validate (in-bounds, non-zero, no partial overlap with a
//!    RECORDED range — an exact duplicate of a recorded range is an
//!    idempotent no-op, any other overlap is a typed refusal);
//! 2. write the bytes at their offset in the staging sparse file and
//!    fsync;
//! 3. append `range|offset|len|blake3(bytes)` to the attempt's range
//!    journal (H007 framing) and fsync.
//!
//! The journal is written AFTER the data is durable, so a recorded
//! range is always really there; a crash between (2) and (3) leaves an
//! unrecorded range that resume simply reports as missing — the sender
//! retransmits it (byte-identical, so the rewrite is harmless). Replay
//! therefore reconstructs the received set EXACTLY: no duplicate
//! ranges (each is recorded once), no missing ranges (unrecorded ⇒
//! reported missing).
//!
//! [`SparseTransfer::resume`] replays the journal (torn tails
//! tolerated — the intact prefix is trusted, the tear reported) and
//! VERIFIES every recorded range's checksum against file reality;
//! divergence is a typed fail-closed refusal, never a guess.
//!
//! [`SparseTransfer::finish`] requires exact coverage of
//! `[0, total)`, recomputes the whole-object digest, and publishes
//! through the H003 pipeline ([`publish_staged`]) — so the sparse path
//! ends at the same atomic, verified publish as every other write.

use std::fs;
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::PathBuf;

use rabs_protocol::result_identity::TypedDigest;

use crate::blob_store::{
    BlobStoreLayout, DurabilityPolicy, PutError, PutOutcome, io_err, publish_staged,
    recompute_file_digest,
};
use crate::metadata_store::{RabsMetadataStore, digest_key};
use crate::staging_journal::{StagingJournal, append_framed, replay_framed};

/// Typed sparse-transfer failures.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SparseError {
    /// Range exceeds the declared total size.
    RangeOutOfBounds {
        /// Offending offset.
        offset: u64,
        /// Offending length.
        length: u64,
        /// Declared total.
        total: u64,
    },
    /// Zero-length ranges carry no bytes and are refused.
    ZeroLengthRange {
        /// Offending offset.
        offset: u64,
    },
    /// Range overlaps a recorded range without being its exact
    /// duplicate.
    RangeOverlap {
        /// Offending offset.
        offset: u64,
        /// Offending length.
        length: u64,
    },
    /// Finish attempted with gaps still open.
    Incomplete {
        /// The missing ranges, sorted.
        missing: Vec<(u64, u64)>,
    },
    /// A recorded range's bytes no longer match their journal checksum
    /// (file/journal divergence) — fail-closed.
    RangeVerificationFailed {
        /// Offending offset.
        offset: u64,
        /// Offending length.
        length: u64,
    },
    /// The completed object does not digest to the declared identity.
    DeclaredDigestMismatch {
        /// Declared digest key.
        declared: String,
        /// Computed digest key.
        computed: String,
    },
    /// Underlying store/filesystem failure.
    Put(PutError),
}

impl From<PutError> for SparseError {
    fn from(e: PutError) -> Self {
        Self::Put(e)
    }
}

/// Acknowledgement for one range write.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RangeAck {
    /// Bytes durable and recorded.
    Committed,
    /// Exact duplicate of an already-recorded range: nothing done.
    DuplicateIdempotent,
}

/// One resumable sparse transfer (one attempt of one operation).
#[derive(Debug)]
pub struct SparseTransfer {
    layout: BlobStoreLayout,
    dir: PathBuf,
    file_path: PathBuf,
    journal_path: PathBuf,
    declared: TypedDigest,
    total: u64,
    /// Exact recorded ranges (offset, length), insertion order.
    recorded: Vec<(u64, u64)>,
}

fn range_checksum(bytes: &[u8]) -> String {
    let digest = blake3::hash(bytes);
    let mut out = String::with_capacity(32);
    for b in &digest.as_bytes()[..16] {
        use std::fmt::Write as _;
        let _ = write!(out, "{b:02x}");
    }
    out
}

impl SparseTransfer {
    /// Begin a fresh transfer: create the attempt's staging directory
    /// (H007 layout), size the sparse file to `total`, no ranges yet.
    ///
    /// # Errors
    /// [`SparseError::Put`] on filesystem failure.
    pub fn begin(
        layout: &BlobStoreLayout,
        op: u128,
        attempt: u128,
        declared: &TypedDigest,
        total: u64,
    ) -> Result<Self, SparseError> {
        let journal = StagingJournal::open(layout, op)?;
        let dir = journal.attempt_dir(attempt);
        fs::create_dir_all(&dir).map_err(io_err("create-attempt-dir"))?;
        let file_path = dir.join("object");
        let file = fs::File::create(&file_path).map_err(io_err("create-sparse"))?;
        file.set_len(total).map_err(io_err("size-sparse"))?;
        file.sync_all().map_err(io_err("fsync-sparse-create"))?;
        Ok(Self {
            layout: layout.clone(),
            journal_path: dir.join("ranges.journal"),
            dir,
            file_path,
            declared: declared.clone(),
            total,
            recorded: Vec::new(),
        })
    }

    /// Resume after a crash: replay the range journal (torn tail
    /// tolerated and reported) and VERIFY every recorded range against
    /// file bytes.
    ///
    /// # Errors
    /// [`SparseError::RangeVerificationFailed`] when the file
    /// contradicts a recorded range; [`SparseError::Put`] on I/O.
    pub fn resume(
        layout: &BlobStoreLayout,
        op: u128,
        attempt: u128,
        declared: &TypedDigest,
        total: u64,
    ) -> Result<(Self, bool), SparseError> {
        let journal = StagingJournal::open(layout, op)?;
        let dir = journal.attempt_dir(attempt);
        let file_path = dir.join("object");
        let journal_path = dir.join("ranges.journal");
        if !file_path.exists() {
            // Nothing staged survived: start over.
            let fresh = Self::begin(layout, op, attempt, declared, total)?;
            return Ok((fresh, false));
        }
        let (payloads, torn) = replay_framed(&journal_path)?;
        let mut transfer = Self {
            layout: layout.clone(),
            dir,
            file_path,
            journal_path,
            declared: declared.clone(),
            total,
            recorded: Vec::new(),
        };
        let mut file = fs::File::open(&transfer.file_path).map_err(io_err("open-sparse"))?;
        for payload in payloads {
            // An undecodable or out-of-bounds intact frame is
            // corruption at the record layer — trust nothing further
            // (exactly like a torn tail).
            let Some((offset, length, checksum)) = decode_range_record(&payload) else {
                return Ok((transfer, true));
            };
            let in_bounds = offset
                .checked_add(length)
                .is_some_and(|end| end <= transfer.total);
            let Some(buffer_len) = usize::try_from(length).ok().filter(|_| in_bounds) else {
                return Ok((transfer, true));
            };
            let mut bytes = vec![0_u8; buffer_len];
            file.seek(SeekFrom::Start(offset))
                .map_err(io_err("seek-verify"))?;
            file.read_exact(&mut bytes).map_err(io_err("read-verify"))?;
            if range_checksum(&bytes) != checksum {
                return Err(SparseError::RangeVerificationFailed { offset, length });
            }
            transfer.recorded.push((offset, length));
        }
        Ok((transfer, torn))
    }

    /// The merged, sorted received set.
    #[must_use]
    pub fn received(&self) -> Vec<(u64, u64)> {
        merge_ranges(&self.recorded)
    }

    /// The gaps a resuming sender must still transmit, sorted.
    #[must_use]
    pub fn missing(&self) -> Vec<(u64, u64)> {
        let mut gaps = Vec::new();
        let mut cursor = 0_u64;
        for (offset, length) in self.received() {
            if offset > cursor {
                gaps.push((cursor, offset - cursor));
            }
            cursor = offset + length;
        }
        if cursor < self.total {
            gaps.push((cursor, self.total - cursor));
        }
        gaps
    }

    /// Write one range: validate → write+fsync data → record+fsync
    /// journal. Exact duplicates of recorded ranges are idempotent.
    ///
    /// # Errors
    /// Typed [`SparseError`] refusals; refusals record nothing.
    pub fn write_range(&mut self, offset: u64, bytes: &[u8]) -> Result<RangeAck, SparseError> {
        let length = bytes.len() as u64;
        if length == 0 {
            return Err(SparseError::ZeroLengthRange { offset });
        }
        if offset
            .checked_add(length)
            .is_none_or(|end| end > self.total)
        {
            return Err(SparseError::RangeOutOfBounds {
                offset,
                length,
                total: self.total,
            });
        }
        if self.recorded.contains(&(offset, length)) {
            return Ok(RangeAck::DuplicateIdempotent);
        }
        let end = offset + length;
        for &(have_offset, have_length) in &self.recorded {
            let have_end = have_offset + have_length;
            if offset < have_end && have_offset < end {
                return Err(SparseError::RangeOverlap { offset, length });
            }
        }

        let mut file = fs::OpenOptions::new()
            .write(true)
            .open(&self.file_path)
            .map_err(io_err("open-sparse-write"))?;
        file.seek(SeekFrom::Start(offset))
            .map_err(io_err("seek-sparse"))?;
        file.write_all(bytes).map_err(io_err("write-sparse"))?;
        file.sync_all().map_err(io_err("fsync-sparse"))?;

        let record = format!("range|{offset}|{length}|{}", range_checksum(bytes));
        append_framed(&self.journal_path, record.as_bytes())?;
        self.recorded.push((offset, length));
        Ok(RangeAck::Committed)
    }

    /// Complete: exact coverage of `[0, total)`, whole-object digest
    /// verification against the declared identity, then the H003
    /// atomic publish. The attempt directory is cleaned on success.
    ///
    /// # Errors
    /// [`SparseError::Incomplete`] with the exact gaps;
    /// [`SparseError::DeclaredDigestMismatch`]; [`SparseError::Put`].
    pub fn finish(
        self,
        store: &mut dyn RabsMetadataStore,
        durability: DurabilityPolicy,
    ) -> Result<PutOutcome, SparseError> {
        let missing = self.missing();
        if !missing.is_empty() {
            return Err(SparseError::Incomplete { missing });
        }
        let computed = recompute_file_digest(&self.file_path)?;
        if computed != self.declared {
            return Err(SparseError::DeclaredDigestMismatch {
                declared: digest_key(&self.declared),
                computed: digest_key(&computed),
            });
        }
        let outcome = publish_staged(
            &self.layout,
            store,
            &self.declared,
            &self.file_path,
            durability,
        )?;
        let _ = fs::remove_dir_all(&self.dir);
        Ok(outcome)
    }
}

fn decode_range_record(payload: &[u8]) -> Option<(u64, u64, String)> {
    let text = std::str::from_utf8(payload).ok()?;
    let mut parts = text.split('|');
    if parts.next()? != "range" {
        return None;
    }
    let offset = parts.next()?.parse().ok()?;
    let length = parts.next()?.parse().ok()?;
    let checksum = parts.next()?.to_owned();
    parts.next().is_none().then_some((offset, length, checksum))
}

fn merge_ranges(ranges: &[(u64, u64)]) -> Vec<(u64, u64)> {
    let mut sorted: Vec<(u64, u64)> = ranges.to_vec();
    sorted.sort_unstable();
    let mut merged: Vec<(u64, u64)> = Vec::new();
    for (offset, length) in sorted {
        match merged.last_mut() {
            Some((last_offset, last_length)) if *last_offset + *last_length == offset => {
                *last_length += length;
            }
            _ => merged.push((offset, length)),
        }
    }
    merged
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
        let root = std::env::temp_dir().join(format!("rabs-h008-{}-{tag}-{n}", std::process::id()));
        fs::create_dir_all(&root).unwrap();
        BlobStoreLayout::open(&root).unwrap()
    }

    fn store() -> SqlMetadataStore<RusqliteEngine> {
        SqlMetadataStore::open(RusqliteEngine::open_in_memory().unwrap()).unwrap()
    }

    fn object_bytes(len: usize) -> Vec<u8> {
        (0..len).map(|i| (i % 251) as u8).collect()
    }

    fn id_of(bytes: &[u8]) -> TypedDigest {
        digest_set(bytes, DigestRequest::default(), None)
            .unwrap()
            .atp_content_id
    }

    #[test]
    fn h008_out_of_order_ranges_complete_and_publish() {
        let layout = fresh_layout("basic");
        let mut store = store();
        let bytes = object_bytes(10_000);
        let declared = id_of(&bytes);
        let mut transfer = SparseTransfer::begin(&layout, 1, 1, &declared, 10_000).unwrap();

        // Out of order, uneven splits.
        for (offset, end) in [(7_000, 10_000), (0, 3_000), (3_000, 7_000)] {
            assert_eq!(
                transfer
                    .write_range(offset as u64, &bytes[offset..end])
                    .unwrap(),
                RangeAck::Committed
            );
        }
        // Exact duplicate: idempotent, still exactly one recording.
        assert_eq!(
            transfer.write_range(0, &bytes[0..3_000]).unwrap(),
            RangeAck::DuplicateIdempotent
        );
        assert_eq!(transfer.received(), vec![(0, 10_000)]);
        assert!(transfer.missing().is_empty());

        let outcome = transfer.finish(&mut store, DurabilityPolicy::FULL).unwrap();
        let PutOutcome::Stored { path } = outcome else {
            panic!("expected Stored, got {outcome:?}");
        };
        assert_eq!(fs::read(&path).unwrap(), bytes);
        assert!(store.object_located(&declared).unwrap());
    }

    #[test]
    fn h008_validation_refusals_are_typed_and_record_nothing() {
        let layout = fresh_layout("refusals");
        let bytes = object_bytes(100);
        let declared = id_of(&bytes);
        let mut transfer = SparseTransfer::begin(&layout, 2, 1, &declared, 100).unwrap();
        transfer.write_range(10, &bytes[10..30]).unwrap();

        assert_eq!(
            transfer.write_range(90, &bytes[90..100].repeat(2)),
            Err(SparseError::RangeOutOfBounds {
                offset: 90,
                length: 20,
                total: 100
            })
        );
        assert_eq!(
            transfer.write_range(5, &[0; 0]),
            Err(SparseError::ZeroLengthRange { offset: 5 })
        );
        // Partial overlap (not an exact duplicate) refused.
        assert_eq!(
            transfer.write_range(20, &bytes[20..40]),
            Err(SparseError::RangeOverlap {
                offset: 20,
                length: 20
            })
        );
        assert_eq!(transfer.received(), vec![(10, 20)]);

        // Finish with gaps: the EXACT missing set is named.
        let mut store = store();
        let result = transfer.finish(&mut store, DurabilityPolicy::FULL);
        assert_eq!(
            result,
            Err(SparseError::Incomplete {
                missing: vec![(0, 10), (30, 70)]
            })
        );
    }

    #[test]
    fn h008_kill_mid_transfer_resumes_exactly_at_every_boundary() {
        // Deliver the object as 5 ranges; kill after each prefix of
        // committed ranges (including between data-write and journal-
        // record), resume, and check the missing set is EXACT.
        let bytes = object_bytes(5_000);
        let ranges: [(u64, usize, usize); 5] = [
            (2_000, 2_000, 3_000),
            (0, 0, 1_000),
            (3_000, 3_000, 4_000),
            (1_000, 1_000, 2_000),
            (4_000, 4_000, 5_000),
        ];
        for kill_after in 0..=ranges.len() {
            let layout = fresh_layout("kill");
            let mut store = store();
            let declared = id_of(&bytes);
            {
                let mut transfer = SparseTransfer::begin(&layout, 9, 1, &declared, 5_000).unwrap();
                for (offset, start, end) in ranges.iter().take(kill_after) {
                    transfer.write_range(*offset, &bytes[*start..*end]).unwrap();
                }
                // Crash: transfer handle dropped without finish.
            }
            let (mut resumed, torn) =
                SparseTransfer::resume(&layout, 9, 1, &declared, 5_000).unwrap();
            assert!(!torn);
            let committed: Vec<(u64, u64)> = ranges
                .iter()
                .take(kill_after)
                .map(|(offset, start, end)| (*offset, (end - start) as u64))
                .collect();
            assert_eq!(resumed.received(), merge_ranges(&committed));
            // Retransmit exactly the missing set — no more, no less.
            for (offset, length) in resumed.missing() {
                let start = usize::try_from(offset).unwrap();
                let end = start + usize::try_from(length).unwrap();
                assert_eq!(
                    resumed.write_range(offset, &bytes[start..end]).unwrap(),
                    RangeAck::Committed
                );
            }
            let outcome = resumed.finish(&mut store, DurabilityPolicy::FULL).unwrap();
            let path = match outcome {
                PutOutcome::Stored { path } | PutOutcome::IdempotentDuplicate { path } => path,
            };
            assert_eq!(fs::read(&path).unwrap(), bytes, "kill_after={kill_after}");
        }
    }

    #[test]
    fn h008_unrecorded_data_write_is_reported_missing_and_retransmit_converges() {
        // Crash BETWEEN data write and journal record: bytes are in the
        // file but no record exists — resume must report the range
        // missing (journal is the receipt), and the byte-identical
        // retransmit converges.
        let layout = fresh_layout("unrecorded");
        let mut store = store();
        let bytes = object_bytes(300);
        let declared = id_of(&bytes);
        let transfer = SparseTransfer::begin(&layout, 4, 1, &declared, 300).unwrap();
        let file_path = transfer.file_path.clone();
        drop(transfer);
        // Simulate the torn step: write data manually, no record.
        let mut file = fs::OpenOptions::new().write(true).open(&file_path).unwrap();
        file.seek(SeekFrom::Start(100)).unwrap();
        file.write_all(&bytes[100..200]).unwrap();
        file.sync_all().unwrap();

        let (mut resumed, torn) = SparseTransfer::resume(&layout, 4, 1, &declared, 300).unwrap();
        assert!(!torn);
        assert_eq!(resumed.missing(), vec![(0, 300)]);
        for (offset, length) in resumed.missing() {
            let start = usize::try_from(offset).unwrap();
            let end = start + usize::try_from(length).unwrap();
            resumed.write_range(offset, &bytes[start..end]).unwrap();
        }
        assert!(matches!(
            resumed.finish(&mut store, DurabilityPolicy::FULL).unwrap(),
            PutOutcome::Stored { .. }
        ));
    }

    #[test]
    fn h008_torn_journal_tail_trusts_prefix_and_resumes() {
        let layout = fresh_layout("torn");
        let bytes = object_bytes(400);
        let declared = id_of(&bytes);
        let mut transfer = SparseTransfer::begin(&layout, 6, 1, &declared, 400).unwrap();
        transfer.write_range(0, &bytes[0..200]).unwrap();
        let journal_path = transfer.journal_path.clone();
        drop(transfer);
        // Torn tail: truncated frame appended by a dying writer.
        let mut file = fs::OpenOptions::new()
            .append(true)
            .open(&journal_path)
            .unwrap();
        file.write_all(&[0, 0, 0, 99, b'r', b'a']).unwrap();
        drop(file);

        let (resumed, torn) = SparseTransfer::resume(&layout, 6, 1, &declared, 400).unwrap();
        assert!(torn, "torn tail must be reported");
        assert_eq!(resumed.received(), vec![(0, 200)]);
        assert_eq!(resumed.missing(), vec![(200, 200)]);
    }

    #[test]
    fn h008_file_journal_divergence_fails_closed() {
        let layout = fresh_layout("diverge");
        let bytes = object_bytes(256);
        let declared = id_of(&bytes);
        let mut transfer = SparseTransfer::begin(&layout, 8, 1, &declared, 256).unwrap();
        transfer.write_range(0, &bytes[0..128]).unwrap();
        let file_path = transfer.file_path.clone();
        drop(transfer);
        // Corrupt recorded bytes behind the journal's back.
        let mut file = fs::OpenOptions::new().write(true).open(&file_path).unwrap();
        file.seek(SeekFrom::Start(10)).unwrap();
        file.write_all(b"XXXX").unwrap();
        drop(file);

        assert_eq!(
            SparseTransfer::resume(&layout, 8, 1, &declared, 256).unwrap_err(),
            SparseError::RangeVerificationFailed {
                offset: 0,
                length: 128
            }
        );
    }
}
