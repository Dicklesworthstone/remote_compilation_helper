use super::*;
use std::io::{Cursor, Write};

fn offer(bytes: &[u8], offset: usize) -> SourcePrefixOffer {
    SourcePrefixOffer {
        index: 0,
        offset: offset as u64,
        sha256: encode_hex(&Sha256::digest(&bytes[..offset])),
    }
}

#[test]
fn prefix_selection_hashes_retained_file_bytes_and_seeks_to_the_exact_unaligned_tail() {
    let bytes: Vec<_> = (0..MAX_SOURCE_CHUNK * 3 + 29)
        .map(|index| (index % 251) as u8)
        .collect();
    let offset = MAX_SOURCE_CHUNK + 13;
    let matching = offer(&bytes, offset);
    let mut corrupt = matching.clone();
    corrupt.sha256 = encode_hex(&Sha256::digest(b"a different retained prefix"));
    for (prefix, expected_offset) in [(Some(&matching), offset), (Some(&corrupt), 0), (None, 0)] {
        let mut retained = tempfile::tempfile().unwrap();
        retained.write_all(&bytes).unwrap();
        // The helper must hash from the beginning, regardless of a former read.
        retained.seek(SeekFrom::Start(71)).unwrap();
        let selected = source_prefix_offset(
            &mut retained,
            prefix,
            &AtomicBool::new(false),
            Instant::now() + Duration::from_secs(5),
        )
        .unwrap();
        assert_eq!(selected, expected_offset as u64);
        assert_eq!(retained.stream_position().unwrap(), selected);
        let mut tail = Vec::new();
        retained.read_to_end(&mut tail).unwrap();
        assert_eq!(tail, bytes[expected_offset..]);
    }
}

#[test]
fn prefix_selection_refuses_short_retained_files_instead_of_falling_back() {
    let bytes = b"complete independently captured source";
    let mut retained = Cursor::new(&bytes[..11]);
    let error = source_prefix_offset(
        &mut retained,
        Some(&offer(bytes, 12)),
        &AtomicBool::new(false),
        Instant::now() + Duration::from_secs(5),
    )
    .unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::UnexpectedEof);
}

#[test]
fn prefix_hashing_checks_cancellation_between_bounded_reads() {
    struct CancelAfterRead<'a> {
        inner: Cursor<Vec<u8>>,
        stopped: &'a AtomicBool,
        reads: usize,
        maximum_read: usize,
    }

    impl Read for CancelAfterRead<'_> {
        fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
            self.reads += 1;
            self.maximum_read = self.maximum_read.max(bytes.len());
            let count = self.inner.read(bytes)?;
            self.stopped.store(true, Ordering::Release);
            Ok(count)
        }
    }

    impl Seek for CancelAfterRead<'_> {
        fn seek(&mut self, position: SeekFrom) -> io::Result<u64> {
            self.inner.seek(position)
        }
    }

    let bytes = vec![43; MAX_SOURCE_CHUNK * 3 + 19];
    let offered = offer(&bytes, MAX_SOURCE_CHUNK * 2 + 13);
    let stopped = AtomicBool::new(false);
    let mut reader = CancelAfterRead {
        inner: Cursor::new(bytes),
        stopped: &stopped,
        reads: 0,
        maximum_read: 0,
    };
    let error = source_prefix_offset(
        &mut reader,
        Some(&offered),
        &stopped,
        Instant::now() + Duration::from_secs(5),
    )
    .unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::Interrupted);
    assert_eq!(reader.reads, 1);
    assert_eq!(reader.maximum_read, MAX_SOURCE_CHUNK);
}

#[test]
fn prefix_selection_checks_cancellation_and_deadline_before_touching_retained_bytes() {
    let bytes = b"source bytes";
    for (cancelled, deadline, kind) in [
        (
            true,
            Instant::now() + Duration::from_secs(5),
            io::ErrorKind::Interrupted,
        ),
        (false, Instant::now(), io::ErrorKind::TimedOut),
    ] {
        let mut reader = Cursor::new(bytes);
        reader.set_position(7);
        let error = source_prefix_offset(
            &mut reader,
            Some(&offer(bytes, 3)),
            &AtomicBool::new(cancelled),
            deadline,
        )
        .unwrap_err();
        assert_eq!(error.kind(), kind);
        assert_eq!(reader.position(), 7);
    }
}
