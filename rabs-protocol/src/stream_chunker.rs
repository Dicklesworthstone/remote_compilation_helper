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

// ---------------------------------------------------------------------
// Serving-side faithful replay (K006; plan §86).
//
// The capture side (above, C007) turns a child's pipes into bounded
// stream items. A cache hit must reproduce what the stock build showed:
// the SAME bytes, in the SAME per-channel order, with line framing
// intact — including oversized spilled lines, which are streamed back
// chunk-wise so a stored gigabyte diagnostic can never become a
// resident gigabyte on replay. Nothing here constructs compiler events
// or diagnostics: replay moves previously captured bytes and nothing
// else (K005's anti-synthesis rule extends to every channel).
// ---------------------------------------------------------------------

/// One canonical observation record stored from the winning attempt,
/// in shared arrival order (the C007 `seq`). These records ARE the
/// cache's memory of stdout/stderr; exit status rides as the terminal
/// record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CanonicalObservation {
    /// An exact captured line (terminator included), within the
    /// capture-time line bound.
    Line {
        /// Source stream.
        stream: StdStream,
        /// Shared arrival sequence.
        seq: u64,
        /// Exact bytes as captured.
        bytes: Vec<u8>,
    },
    /// Marker for an oversized captured line; its bytes live in spill
    /// object `spill_id` (`total_bytes` includes the terminator).
    SpilledLine {
        /// Source stream.
        stream: StdStream,
        /// Shared arrival sequence.
        seq: u64,
        /// The edge's spill object handle.
        spill_id: u64,
        /// Exact total byte count of the original line.
        total_bytes: u64,
    },
    /// Terminal observation: the attempt's exit status. Preserved as
    /// data — never re-derived, never synthesized.
    TerminalExit {
        /// The process exit code.
        code: i32,
    },
}

/// Why a stored transcript cannot be faithfully replayed. Every
/// variant means BYPASS SERVING for this action: emitting a transcript
/// that differs from what the stock build produced is worse than
/// running the command.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReplayError {
    /// The named spill object is gone (GC ate it, store corruption).
    SpillUnavailable {
        /// The missing object id.
        spill_id: u64,
    },
    /// The spill object holds fewer bytes than the marker recorded:
    /// truncation would silently corrupt the replayed line.
    SpillShortBytes {
        /// The affected object id.
        spill_id: u64,
        /// Bytes the marker promised.
        expected_total: u64,
        /// Bytes actually readable.
        found: u64,
    },
}

impl std::fmt::Display for ReplayError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::SpillUnavailable { spill_id } => {
                write!(f, "spill object {spill_id} unavailable")
            }
            Self::SpillShortBytes {
                spill_id,
                expected_total,
                found,
            } => {
                write!(
                    f,
                    "spill {spill_id} holds {found} of {expected_total} promised bytes"
                )
            }
        }
    }
}

impl std::error::Error for ReplayError {}

/// Read access to stored spill objects. Chunked by design: the replayer
/// never asks for more than its buffer, so implementations can stream
/// from disk/CAS without whole-object buffering.
pub trait SpillLookup {
    /// Read up to `buf.len()` bytes at `offset` from spill object
    /// `spill_id`. Returns bytes read (0 past end). Unknown ids return
    /// 0 — the caller distinguishes via the marker's promised total.
    ///
    /// # Errors
    /// Implementation I/O errors propagate.
    fn read_spill(&self, spill_id: u64, offset: u64, buf: &mut [u8]) -> std::io::Result<usize>;
}

/// Replay a stored observation list faithfully (plan §86: preserve
/// line-delimited framing and ordering; cap memory via streaming).
///
/// `emit` receives each byte run in stored arrival order, tagged with
/// its channel; spilled lines arrive as consecutive chunks of at most
/// `chunk_bytes` — resident memory is O(`chunk_bytes`), never O(line).
/// `exit` receives the terminal status exactly once when present.
///
/// # Errors
/// [`ReplayError`] — the caller must bypass serving; partial emission
/// has already happened, but every emitted byte WAS part of the stored
/// transcript, and the typed error names the corruption.
pub fn replay_observations<S: SpillLookup>(
    observations: &[CanonicalObservation],
    spills: &S,
    chunk_bytes: usize,
    mut emit: impl FnMut(StdStream, &[u8]),
    mut exit: impl FnMut(i32),
) -> Result<(), ReplayError> {
    assert!(
        chunk_bytes > 0,
        "zero-sized replay chunks cannot make progress"
    );
    for obs in observations {
        match obs {
            CanonicalObservation::Line { stream, bytes, .. } => {
                emit(*stream, bytes);
            }
            CanonicalObservation::SpilledLine {
                stream,
                spill_id,
                total_bytes,
                ..
            } => {
                let mut offset = 0_u64;
                let mut buffer = vec![0_u8; chunk_bytes];
                while offset < *total_bytes {
                    let want = usize::try_from(*total_bytes - offset)
                        .unwrap_or(chunk_bytes)
                        .min(chunk_bytes);
                    let read = spills
                        .read_spill(*spill_id, offset, &mut buffer[..want])
                        .map_err(|_| ReplayError::SpillUnavailable {
                            spill_id: *spill_id,
                        })?;
                    if read == 0 {
                        break;
                    }
                    emit(*stream, &buffer[..read]);
                    offset += read as u64;
                }
                if offset < *total_bytes {
                    return Err(ReplayError::SpillShortBytes {
                        spill_id: *spill_id,
                        expected_total: *total_bytes,
                        found: offset,
                    });
                }
            }
            CanonicalObservation::TerminalExit { code } => exit(*code),
        }
    }
    Ok(())
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

    // -----------------------------------------------------------------
    // K006: serving-side faithful replay.
    // -----------------------------------------------------------------

    use crate::stream_chunker::{
        CanonicalObservation, ReplayError, SpillLookup, replay_observations,
    };
    use std::collections::HashMap;

    /// Spill store over captured bytes (the edge daemon owns the real
    /// CAS objects; fixtures hold plain maps).
    struct MapSpills(HashMap<u64, Vec<u8>>);

    impl SpillLookup for MapSpills {
        fn read_spill(&self, spill_id: u64, offset: u64, buf: &mut [u8]) -> std::io::Result<usize> {
            let Some(object) = self.0.get(&spill_id) else {
                return Ok(0);
            };
            let start = offset as usize;
            if start >= object.len() {
                return Ok(0);
            }
            let end = (start + buf.len()).min(object.len());
            buf[..end - start].copy_from_slice(&object[start..end]);
            Ok(end - start)
        }
    }

    #[test]
    fn k006_replay_reproduces_stock_bytes_across_channels_including_spill() {
        // STOCK capture: interleaved stdout/stderr through the C007
        // mux exactly as a real build streams — NDJSON on stdout,
        // human diagnostics + one bound-breaking line + CRLF +
        // unterminated tail on stderr.
        let mut mux = StreamMux::new(64);
        let mut sink = SpillSink::default();
        let stdout_feed_1 = br#"{"reason":"compiler-artifact","package_id":"reg-dep"}"#;
        let stdout_feed_2 = b"\n";
        let stderr_line_1: &[u8] = b"warning: unused import: `std::io`\r\n";
        let giant_line: Vec<u8> = {
            let mut v = b"E: pathological diagnostic ".to_vec();
            v.extend(std::iter::repeat_n(b'x', 200));
            v.push(b'\n');
            v
        };
        let stderr_tail = b"truncated diagnostic without newline";

        let mut stock_stdout: Vec<u8> = Vec::new();
        let mut stock_stderr: Vec<u8> = Vec::new();
        stock_stdout.extend_from_slice(stdout_feed_1);
        stock_stdout.extend_from_slice(stdout_feed_2);
        stock_stderr.extend_from_slice(stderr_line_1);
        stock_stderr.extend_from_slice(&giant_line);
        stock_stderr.extend_from_slice(stderr_tail);

        let mut items = Vec::new();
        items.extend(mux.feed(StdStream::Stdout, stdout_feed_1, &mut sink));
        items.extend(mux.feed(StdStream::Stdout, stdout_feed_2, &mut sink));
        items.extend(mux.feed(StdStream::Stderr, stderr_line_1, &mut sink));
        // The giant line crosses feed boundaries too — spill state
        // must survive partial arrival.
        let (giant_head, giant_rest) = giant_line.split_at(90);
        items.extend(mux.feed(StdStream::Stderr, giant_head, &mut sink));
        items.extend(mux.feed(StdStream::Stderr, giant_rest, &mut sink));
        items.extend(mux.feed(StdStream::Stderr, stderr_tail, &mut sink));
        items.extend(mux.finish(StdStream::Stderr, &mut sink));
        assert!(
            items
                .iter()
                .any(|i| matches!(i, StreamItem::SpilledLine { .. }))
        );

        // Canonicalize: capture items -> observation records; the
        // single spilled item's bytes are known (the giant line).
        let mut observations = Vec::new();
        let mut spills: HashMap<u64, Vec<u8>> = HashMap::new();
        for item in &items {
            match item {
                StreamItem::Line { stream, seq, bytes } => {
                    observations.push(CanonicalObservation::Line {
                        stream: *stream,
                        seq: *seq,
                        bytes: bytes.clone(),
                    })
                }
                StreamItem::SpilledLine {
                    stream,
                    seq,
                    spill_id,
                    total_bytes,
                } => {
                    assert_eq!(*total_bytes as usize, giant_line.len());
                    spills.insert(*spill_id, giant_line.clone());
                    observations.push(CanonicalObservation::SpilledLine {
                        stream: *stream,
                        seq: *seq,
                        spill_id: *spill_id,
                        total_bytes: *total_bytes,
                    });
                }
            }
        }
        observations.push(CanonicalObservation::TerminalExit { code: 101 });

        // Shared arrival order must be strictly increasing across
        // channels (the interleaving record).
        let seqs: Vec<u64> = observations
            .iter()
            .filter_map(|o| match o {
                CanonicalObservation::Line { seq, .. }
                | CanonicalObservation::SpilledLine { seq, .. } => Some(*seq),
                _ => None,
            })
            .collect();
        assert!(
            seqs.windows(2).all(|w| w[0] < w[1]),
            "arrival order is the replay contract"
        );

        // REPLAY: whole captured lines go verbatim; the spilled line
        // streams chunk-wise (chunk bound proven in the dedicated
        // test below).
        let mut out_stdout: Vec<u8> = Vec::new();
        let mut out_stderr: Vec<u8> = Vec::new();
        let mut exits = Vec::new();
        replay_observations(
            &observations,
            &MapSpills(spills),
            16,
            |stream, bytes| match stream {
                StdStream::Stdout => out_stdout.extend_from_slice(bytes),
                StdStream::Stderr => out_stderr.extend_from_slice(bytes),
            },
            |code| exits.push(code),
        )
        .expect("faithful replay");

        assert_eq!(out_stdout, stock_stdout, "stdout byte/order fidelity");
        assert_eq!(out_stderr, stock_stderr, "stderr byte/order fidelity");
        assert_eq!(exits, vec![101], "exit status preserved as data");
    }

    #[test]
    fn k006_missing_or_truncated_spill_objects_are_typed_refusals() {
        let observations = [CanonicalObservation::SpilledLine {
            stream: StdStream::Stderr,
            seq: 1,
            spill_id: 7,
            total_bytes: 100,
        }];
        // Unknown id -> read_spill returns 0 bytes -> short-bytes
        // refusal naming both numbers (never a silent empty line).
        assert_eq!(
            replay_observations(
                &observations,
                &MapSpills(HashMap::new()),
                32,
                |_, _| {},
                |_| {}
            ),
            Err(ReplayError::SpillShortBytes {
                spill_id: 7,
                expected_total: 100,
                found: 0
            }),
        );
        // Truncated store: 40 of the promised 100 bytes readable.
        let truncated = MapSpills(HashMap::from([(7_u64, vec![b'x'; 40])]));
        assert_eq!(
            replay_observations(&observations, &truncated, 32, |_, _| {}, |_| {}),
            Err(ReplayError::SpillShortBytes {
                spill_id: 7,
                expected_total: 100,
                found: 40
            }),
        );

        // THE memory-cap proof: a 100-byte spilled line replays in
        // chunks of at most the budget (32), never as one 100-byte
        // resident emission — and reassembles byte-exactly.
        let full = vec![b'x'; 100];
        let mut chunks = Vec::new();
        replay_observations(
            &observations,
            &MapSpills(HashMap::from([(7_u64, full.clone())])),
            32,
            |_, bytes| chunks.push(bytes.to_vec()),
            |_| {},
        )
        .expect("chunked replay");
        assert!(chunks.iter().all(|c| c.len() <= 32));
        let joined: Vec<u8> = chunks.concat();
        assert_eq!(joined.len(), 100);
        assert_eq!(joined, full);
    }
}
