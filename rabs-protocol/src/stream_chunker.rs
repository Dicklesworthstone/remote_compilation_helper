//! Bounded stdout/stderr/NDJSON streaming without whole-output
//! buffering (bead C007; risk R36).
//!
//! Compiler output can be enormous — a pathological build emits
//! gigabytes of diagnostics — and Cargo consumes line-delimited JSON,
//! so the wrapper/edge stream path must (a) split ONLY at newline
//! boundaries, byte-exactly, (b) preserve order, and (c) hold a hard
//! resident-memory bound no input can break:
//!
//! - complete lines within the line bound are emitted as
//!   [`StreamItem::Line`] the moment their newline arrives — nothing
//!   waits for the end of the output;
//! - a line EXCEEDING the bound flips to spill mode: its bytes divert
//!   to the spill sink (a CAS object in the edge; byte accounting
//!   here), the resident partial buffer never grows past the bound,
//!   and the finished line is emitted as [`StreamItem::SpilledLine`]
//!   naming the spill object and total size — Cargo-visible streams
//!   get a typed marker instead of an OOM;
//! - stdout and stderr each keep their own line discipline; a shared
//!   arrival sequence records cross-stream interleaving, so a
//!   consumer can reconstruct exactly what a terminal would have
//!   shown.
//!
//! The adversarial acceptance below feeds a GIGABYTE-scale single
//! line and asserts the resident bound holds at EVERY step.

/// Which standard stream a chunk belongs to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StdStream {
    /// Child stdout (Cargo's NDJSON rides here).
    Stdout,
    /// Child stderr (human diagnostics).
    Stderr,
}

/// One emitted stream item, stamped with the shared arrival sequence.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StreamItem {
    /// A complete line (terminator included), within the line bound.
    Line {
        /// Source stream.
        stream: StdStream,
        /// Shared arrival sequence (cross-stream ordering).
        seq: u64,
        /// The exact line bytes, newline included.
        bytes: Vec<u8>,
    },
    /// A line that exceeded the bound: its bytes went to the spill
    /// sink; this item is the in-stream marker.
    SpilledLine {
        /// Source stream.
        stream: StdStream,
        /// Shared arrival sequence.
        seq: u64,
        /// Spill object id (the edge's CAS handle).
        spill_id: u64,
        /// Total bytes of the oversized line (terminator included).
        total_bytes: u64,
    },
}

/// Byte-accounting spill sink (the edge daemon owns the real object
/// writes; fixtures inspect the accounting).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SpillSink {
    /// Completed spill objects: (id, total bytes).
    pub objects: Vec<(u64, u64)>,
    /// Bytes of the spill object currently being written.
    pub open_bytes: u64,
    next_id: u64,
}

impl SpillSink {
    fn open(&mut self) -> u64 {
        self.next_id += 1;
        self.open_bytes = 0;
        self.next_id
    }

    fn append(&mut self, bytes: u64) {
        self.open_bytes += bytes;
    }

    fn close(&mut self, id: u64) -> u64 {
        let total = self.open_bytes;
        self.objects.push((id, total));
        self.open_bytes = 0;
        total
    }
}

/// Per-stream chunker state.
#[derive(Debug, Clone, PartialEq, Eq)]
struct LaneState {
    /// Bounded partial-line buffer (never exceeds the line bound).
    partial: Vec<u8>,
    /// Open spill (id) when the current line exceeded the bound.
    spilling: Option<u64>,
}

/// The two-stream mux with a hard per-line resident bound.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StreamMux {
    max_line_bytes: usize,
    stdout: LaneState,
    stderr: LaneState,
    seq: u64,
}

impl StreamMux {
    /// A mux whose resident partial buffers never exceed
    /// `max_line_bytes` each.
    #[must_use]
    pub const fn new(max_line_bytes: usize) -> Self {
        Self {
            max_line_bytes,
            stdout: LaneState {
                partial: Vec::new(),
                spilling: None,
            },
            stderr: LaneState {
                partial: Vec::new(),
                spilling: None,
            },
            seq: 0,
        }
    }

    /// Current resident bytes across both partial buffers (the bound's
    /// subject; fixtures assert on it after every feed).
    #[must_use]
    pub fn resident_bytes(&self) -> usize {
        self.stdout.partial.len() + self.stderr.partial.len()
    }

    /// Feed one chunk as read from the child's pipe. Emits every
    /// completed item in order; partial tails stay buffered (bounded)
    /// or spill.
    pub fn feed(
        &mut self,
        stream: StdStream,
        chunk: &[u8],
        sink: &mut SpillSink,
    ) -> Vec<StreamItem> {
        let mut items = Vec::new();
        let mut rest = chunk;
        while !rest.is_empty() {
            let newline = rest.iter().position(|b| *b == b'\n');
            let (take, line_complete) = match newline {
                Some(i) => (&rest[..=i], true),
                None => (rest, false),
            };
            rest = &rest[take.len()..];
            self.absorb(stream, take, line_complete, sink, &mut items);
        }
        items
    }

    /// Flush the tail at end-of-stream: an unterminated final line is
    /// emitted as-is (Cargo tools do this on abnormal exits).
    pub fn finish(&mut self, stream: StdStream, sink: &mut SpillSink) -> Option<StreamItem> {
        let lane = self.lane(stream);
        if lane.spilling.is_none() && lane.partial.is_empty() {
            return None;
        }
        let mut items = Vec::new();
        self.absorb(stream, &[], true, sink, &mut items);
        items.pop()
    }

    const fn lane(&mut self, stream: StdStream) -> &mut LaneState {
        match stream {
            StdStream::Stdout => &mut self.stdout,
            StdStream::Stderr => &mut self.stderr,
        }
    }

    fn absorb(
        &mut self,
        stream: StdStream,
        bytes: &[u8],
        line_complete: bool,
        sink: &mut SpillSink,
        items: &mut Vec<StreamItem>,
    ) {
        let max = self.max_line_bytes;
        let lane = match stream {
            StdStream::Stdout => &mut self.stdout,
            StdStream::Stderr => &mut self.stderr,
        };
        if let Some(spill_id) = lane.spilling {
            // Already spilling this line: bytes go straight to the
            // sink, resident stays flat.
            sink.append(bytes.len() as u64);
            if line_complete {
                let total = sink.close(spill_id);
                lane.spilling = None;
                self.seq += 1;
                items.push(StreamItem::SpilledLine {
                    stream,
                    seq: self.seq,
                    spill_id,
                    total_bytes: total,
                });
            }
            return;
        }
        if lane.partial.len() + bytes.len() > max {
            // The line just exceeded the bound: divert the buffered
            // prefix AND these bytes to a fresh spill object.
            let spill_id = sink.open();
            sink.append(lane.partial.len() as u64);
            sink.append(bytes.len() as u64);
            lane.partial.clear();
            if line_complete {
                let total = sink.close(spill_id);
                self.seq += 1;
                items.push(StreamItem::SpilledLine {
                    stream,
                    seq: self.seq,
                    spill_id,
                    total_bytes: total,
                });
            } else {
                lane.spilling = Some(spill_id);
            }
            return;
        }
        lane.partial.extend_from_slice(bytes);
        if line_complete && !lane.partial.is_empty() {
            self.seq += 1;
            items.push(StreamItem::Line {
                stream,
                seq: self.seq,
                bytes: std::mem::take(&mut lane.partial),
            });
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn c007_ndjson_framing_and_cross_stream_ordering_survive_chunking() {
        // NDJSON on stdout, human text on stderr, delivered in
        // adversarial chunk splits (mid-line, multi-line, split right
        // at the newline). Emitted lines must be byte-exact and the
        // shared sequence must reflect arrival order.
        let mut mux = StreamMux::new(1024);
        let mut sink = SpillSink::default();
        let mut items = Vec::new();
        items.extend(mux.feed(StdStream::Stdout, b"{\"reason\":\"compi", &mut sink));
        items.extend(mux.feed(StdStream::Stderr, b"warning: unus", &mut sink));
        items.extend(mux.feed(
            StdStream::Stdout,
            b"ler-message\"}\n{\"a\":1}\n{\"b\"",
            &mut sink,
        ));
        items.extend(mux.feed(StdStream::Stderr, b"ed variable\n", &mut sink));
        items.extend(mux.feed(StdStream::Stdout, b":2}\n", &mut sink));
        let expected: Vec<(StdStream, &[u8])> = vec![
            (StdStream::Stdout, b"{\"reason\":\"compiler-message\"}\n"),
            (StdStream::Stdout, b"{\"a\":1}\n"),
            (StdStream::Stderr, b"warning: unused variable\n"),
            (StdStream::Stdout, b"{\"b\":2}\n"),
        ];
        assert_eq!(items.len(), expected.len());
        for (i, ((stream, bytes), item)) in expected.iter().zip(&items).enumerate() {
            let StreamItem::Line {
                stream: s,
                seq,
                bytes: b,
            } = item
            else {
                panic!("item {i} spilled unexpectedly");
            };
            assert_eq!(s, stream, "item {i}");
            assert_eq!(b.as_slice(), *bytes, "item {i}: byte-exact framing");
            assert_eq!(*seq, i as u64 + 1, "arrival order");
        }
        assert!(sink.objects.is_empty(), "nothing spilled");
        assert_eq!(mux.resident_bytes(), 0, "all lines complete");
    }

    #[test]
    fn c007_gigabyte_diagnostic_line_stays_within_the_resident_bound() {
        // THE adversarial acceptance: ONE line of a gigabyte (no
        // newline until the end), fed in 64 KiB chunks. The resident
        // bound (64 KiB) must hold after EVERY feed; the line arrives
        // as a single SpilledLine accounting for every byte.
        const BOUND: usize = 64 * 1024;
        const CHUNK: usize = 64 * 1024;
        const CHUNKS: usize = 16 * 1024; // 16384 * 64 KiB = 1 GiB
        let mut mux = StreamMux::new(BOUND);
        let mut sink = SpillSink::default();
        let chunk = vec![b'x'; CHUNK];
        let mut emitted = Vec::new();
        for i in 0..CHUNKS {
            emitted.extend(mux.feed(StdStream::Stderr, &chunk, &mut sink));
            assert!(
                mux.resident_bytes() <= BOUND,
                "chunk {i}: resident {} exceeded bound",
                mux.resident_bytes()
            );
        }
        assert!(emitted.is_empty(), "no newline yet: nothing emitted");
        emitted.extend(mux.feed(StdStream::Stderr, b"\n", &mut sink));
        assert_eq!(emitted.len(), 1);
        let StreamItem::SpilledLine {
            stream,
            spill_id,
            total_bytes,
            ..
        } = &emitted[0]
        else {
            panic!("a gigabyte line must spill");
        };
        assert_eq!(*stream, StdStream::Stderr);
        assert_eq!(
            *total_bytes,
            (CHUNK * CHUNKS + 1) as u64,
            "every byte accounted (terminator included)"
        );
        assert_eq!(sink.objects, vec![(*spill_id, *total_bytes)]);
        assert_eq!(mux.resident_bytes(), 0);
        // The stream recovers: the NEXT line is ordinary.
        let after = mux.feed(StdStream::Stderr, b"error: done\n", &mut sink);
        assert!(matches!(&after[0], StreamItem::Line { bytes, .. } if bytes == b"error: done\n"));
    }

    #[test]
    fn c007_exact_bound_lines_stay_resident_and_finish_flushes_tails() {
        let mut mux = StreamMux::new(8);
        let mut sink = SpillSink::default();
        // Exactly at the bound (7 bytes + newline = 8): resident, not
        // spilled.
        let items = mux.feed(StdStream::Stdout, b"1234567\n", &mut sink);
        assert!(matches!(&items[0], StreamItem::Line { bytes, .. } if bytes == b"1234567\n"));
        // One byte over: spills.
        let items = mux.feed(StdStream::Stdout, b"12345678\n", &mut sink);
        assert!(matches!(
            &items[0],
            StreamItem::SpilledLine { total_bytes: 9, .. }
        ));
        // An unterminated tail flushes on finish (abnormal exit).
        assert!(mux.feed(StdStream::Stderr, b"tail", &mut sink).is_empty());
        let flushed = mux.finish(StdStream::Stderr, &mut sink).unwrap();
        assert!(matches!(&flushed, StreamItem::Line { bytes, .. } if bytes == b"tail"));
        assert!(mux.finish(StdStream::Stderr, &mut sink).is_none());
    }
}
