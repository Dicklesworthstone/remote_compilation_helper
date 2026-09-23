//! Bounded, lossy observation of live process output, separate from capture.
//!
//! A stopped or slow consumer must never stop either pipe drain. Producers use
//! try_lock and keep at most one fixed tail per stream. Consumers receive exact
//! stream offsets and explicit gaps; these bytes are NOT a complete transcript,
//! a process outcome, or evidence that output is durable. The ordinary drains
//! still retain every accepted byte and decide whether capture succeeded.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;

/// Maximum resident preview bytes per stream, independent of output volume.
pub const MAX_PREVIEW_BYTES: usize = 8192;

/// The two process pipes. No pathname or caller-selected stream is accepted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PreviewStream {
    Stdout,
    Stderr,
}

impl PreviewStream {
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Stdout => "stdout",
            Self::Stderr => "stderr",
        }
    }
}

/// One exact contiguous preview segment, possibly preceded by skipped bytes.
/// Empty segments report a gap when all new observations were contended out.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OutputPreview {
    pub stream: PreviewStream,
    pub offset: u64,
    pub bytes: Vec<u8>,
    pub skipped_bytes: u64,
    /// Number observed by the producer, possibly beyond this segment's end.
    pub observed_bytes: u64,
}

#[derive(Debug)]
struct Tail {
    bytes: Vec<u8>,
    start: u64,
    end: u64,
    emitted: u64,
}

impl Default for Tail {
    fn default() -> Self {
        Self {
            bytes: Vec::with_capacity(MAX_PREVIEW_BYTES),
            start: 0,
            end: 0,
            emitted: 0,
        }
    }
}

#[derive(Debug, Default)]
struct Lane {
    observed: AtomicU64,
    tail: Mutex<Tail>,
}

impl Lane {
    fn record(&self, offset: u64, bytes: &[u8]) {
        let Some(end) = offset.checked_add(bytes.len() as u64) else { return; };
        if bytes.is_empty() { return; }
        // The real lane supplies monotonic offsets after successful retention.
        // Observational misuse cannot rewind the consumer or overflow a length.
        let previous = self.observed.fetch_max(end, Ordering::AcqRel);
        if offset < previous { return; }
        let Ok(mut tail) = self.tail.try_lock() else { return; };
        if tail.end != offset {
            tail.bytes.clear();
            tail.start = offset;
        }
        if bytes.len() >= MAX_PREVIEW_BYTES {
            tail.bytes.clear();
            tail.bytes.extend_from_slice(&bytes[bytes.len() - MAX_PREVIEW_BYTES..]);
            tail.start = end - MAX_PREVIEW_BYTES as u64;
        } else {
            let discard = (tail.bytes.len() + bytes.len()).saturating_sub(MAX_PREVIEW_BYTES);
            if discard != 0 {
                tail.bytes.drain(..discard);
                tail.start += discard as u64;
            }
            tail.bytes.extend_from_slice(bytes);
        }
        tail.end = end;
    }

    fn take(&self, stream: PreviewStream) -> Option<OutputPreview> {
        let Ok(mut tail) = self.tail.try_lock() else { return None; };
        let observed = self.observed.load(Ordering::Acquire);
        if tail.end > tail.emitted {
            let offset = tail.start.max(tail.emitted);
            let skip = usize::try_from(offset - tail.start).ok()?;
            let bytes = tail.bytes.get(skip..)?.to_vec();
            let skipped_bytes = offset - tail.emitted;
            tail.emitted = tail.end;
            Some(OutputPreview { stream, offset, bytes, skipped_bytes, observed_bytes: observed })
        } else if observed > tail.emitted {
            // No retained preview survived contention. Expose the gap instead
            // of claiming continuity or making an empty stream look complete.
            let skipped_bytes = observed - tail.emitted;
            tail.emitted = observed;
            Some(OutputPreview {
                stream, offset: observed, bytes: Vec::new(), skipped_bytes,
                observed_bytes: observed,
            })
        } else {
            None
        }
    }
}

/// One invocation's independently bounded stdout/stderr preview tails.
/// Cloning an Arc to this observer grants neither cancellation nor file access.
#[derive(Debug, Default)]
pub struct LiveOutputPreview {
    stdout: Lane,
    stderr: Lane,
}

impl LiveOutputPreview {
    /// Called only after the ordinary drain has accepted and retained a chunk.
    /// Never waits for a consumer, executes a callback, or performs filesystem IO.
    pub fn record(&self, stream: PreviewStream, offset: u64, bytes: &[u8]) {
        match stream {
            PreviewStream::Stdout => self.stdout.record(offset, bytes),
            PreviewStream::Stderr => self.stderr.record(offset, bytes),
        }
    }

    /// Consume at most one bounded segment for one stream. Offsets do not depend
    /// on chunk or UTF-8 boundaries. Repeated reads without progress return None.
    pub fn take(&self, stream: PreviewStream) -> Option<OutputPreview> {
        match stream {
            PreviewStream::Stdout => self.stdout.take(stream),
            PreviewStream::Stderr => self.stderr.take(stream),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    #[test]
    fn independent_binary_streams_are_incremental_without_repeating_prefixes() {
        let preview = LiveOutputPreview::default();
        preview.record(PreviewStream::Stdout, 0, b"out\0\xff");
        preview.record(PreviewStream::Stderr, 0, "雪".as_bytes());
        let first = preview.take(PreviewStream::Stdout).unwrap();
        assert_eq!(first.bytes, b"out\0\xff");
        assert_eq!((first.offset, first.skipped_bytes, first.observed_bytes), (0, 0, 5));
        assert!(preview.take(PreviewStream::Stdout).is_none());
        preview.record(PreviewStream::Stdout, 5, b"next");
        let next = preview.take(PreviewStream::Stdout).unwrap();
        assert_eq!(next.bytes, b"next");
        assert_eq!((next.offset, next.skipped_bytes), (5, 0));
        assert_eq!(preview.take(PreviewStream::Stderr).unwrap().bytes, "雪".as_bytes());
    }

    #[test]
    fn slow_consumer_receives_the_bounded_tail_and_an_exact_gap() {
        let preview = LiveOutputPreview::default();
        let bytes: Vec<_> = (0..MAX_PREVIEW_BYTES * 5 + 13).map(|i| (i % 251) as u8).collect();
        for (i, chunk) in bytes.chunks(997).enumerate() {
            preview.record(PreviewStream::Stdout, (i * 997) as u64, chunk);
        }
        let result = preview.take(PreviewStream::Stdout).unwrap();
        assert_eq!(result.bytes, bytes[bytes.len() - MAX_PREVIEW_BYTES..]);
        assert_eq!(result.offset, (bytes.len() - MAX_PREVIEW_BYTES) as u64);
        assert_eq!(result.skipped_bytes, result.offset);
        assert_eq!(result.observed_bytes, bytes.len() as u64);
        let tail = preview.stdout.tail.lock().unwrap();
        assert_eq!(tail.bytes.len(), MAX_PREVIEW_BYTES);
        assert_eq!(tail.bytes.capacity(), MAX_PREVIEW_BYTES);
    }

    #[test]
    fn contended_consumer_cannot_block_a_producer_and_gaps_remain_visible() {
        let preview = Arc::new(LiveOutputPreview::default());
        preview.record(PreviewStream::Stdout, 0, b"before");
        let held = preview.stdout.tail.lock().unwrap();
        let other = Arc::clone(&preview);
        let (done, completed) = std::sync::mpsc::channel();
        let producer = std::thread::spawn(move || {
            other.record(PreviewStream::Stdout, 6, b"missed");
            let _ = done.send(());
        });
        let without_consumer = completed.recv_timeout(std::time::Duration::from_secs(2));
        drop(held); // Release even on regression, before joining the producer.
        producer.join().unwrap();
        assert!(without_consumer.is_ok(), "preview backpressured its pipe drain");
        assert_eq!(preview.take(PreviewStream::Stdout).unwrap().bytes, b"before");
        let gap = preview.take(PreviewStream::Stdout).unwrap();
        assert_eq!((gap.offset, gap.skipped_bytes, gap.observed_bytes), (12, 6, 12));
        assert!(gap.bytes.is_empty());
        preview.record(PreviewStream::Stdout, 12, b"after");
        let after = preview.take(PreviewStream::Stdout).unwrap();
        assert_eq!((after.offset, after.skipped_bytes), (12, 0));
        assert_eq!(after.bytes, b"after");
    }

    #[test]
    fn a_later_chunk_cannot_join_across_a_dropped_segment() {
        let preview = LiveOutputPreview::default();
        preview.record(PreviewStream::Stdout, 0, b"before");
        {
            let _held = preview.stdout.tail.lock().unwrap();
            preview.record(PreviewStream::Stdout, 6, b"missed");
        }
        preview.record(PreviewStream::Stdout, 12, b"after");
        let result = preview.take(PreviewStream::Stdout).unwrap();
        assert_eq!(result.bytes, b"after");
        assert_eq!((result.offset, result.skipped_bytes), (12, 12));
    }

    #[test]
    fn a_single_large_chunk_and_invalid_offsets_never_expand_memory_or_rewind() {
        let preview = LiveOutputPreview::default();
        preview.record(PreviewStream::Stdout, 0, &vec![7; MAX_PREVIEW_BYTES * 8]);
        let first = preview.take(PreviewStream::Stdout).unwrap();
        assert_eq!(first.bytes.len(), MAX_PREVIEW_BYTES);
        preview.record(PreviewStream::Stdout, 0, b"duplicate");
        preview.record(PreviewStream::Stdout, u64::MAX, b"overflow");
        assert!(preview.take(PreviewStream::Stdout).is_none());
        preview.record(PreviewStream::Stdout, (MAX_PREVIEW_BYTES * 8) as u64, b"tail");
        let result = preview.take(PreviewStream::Stdout).unwrap();
        assert_eq!(result.bytes, b"tail");
        assert_eq!(result.skipped_bytes, 0);
        assert_eq!(preview.stdout.tail.lock().unwrap().bytes.capacity(), MAX_PREVIEW_BYTES);
    }
}
