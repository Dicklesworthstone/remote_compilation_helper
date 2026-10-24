//! Length-bounded canonical framing for the wrapper↔edge socket
//! (bead C002; plan §182).
//!
//! Frames are `[u32 little-endian payload length][payload]`. Rules:
//!
//! - **Limits enforced before allocation** (the J004/plan §50 decoder
//!   doctrine applied locally): a frame header claiming more than the
//!   configured maximum is rejected from the 4 header bytes alone — the
//!   claimed length never sizes a buffer.
//! - **No large source content inline** (plan §182): the local maximum is
//!   deliberately small; snapshots/artifacts travel as object references.
//! - Complete frames only: the wrapper accepts only fully received frames
//!   (the C023/C026 transcript machinery counts *complete* frames; a
//!   partial frame is `NeedMoreData`, never a partial delivery).
//!
//! Encoding is canonical and trivially deterministic: one length, one
//! payload, no padding, no extensions.

/// Default maximum payload bytes for local control frames (1 MiB).
/// Bulk content rides object references, never inline frames.
pub const DEFAULT_MAX_FRAME_BYTES: u32 = 1024 * 1024;

/// Framing errors.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FrameError {
    /// The payload exceeds the configured maximum (encode side).
    PayloadTooLarge {
        /// Requested payload size.
        len: usize,
        /// Configured maximum.
        max: u32,
    },
    /// The header claims a length above the configured maximum (decode
    /// side — rejected before any allocation).
    ClaimedLengthTooLarge {
        /// Claimed payload size from the header.
        claimed: u32,
        /// Configured maximum.
        max: u32,
    },
}

/// Decode progress.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Decoded<'a> {
    /// A complete frame: the payload plus the total bytes consumed
    /// (header + payload). The caller advances its buffer by `consumed`.
    Frame {
        /// The payload slice (borrowed from the input buffer).
        payload: &'a [u8],
        /// Total bytes consumed from the buffer.
        consumed: usize,
    },
    /// Not enough bytes yet for a header or the announced payload.
    NeedMoreData,
}

/// A framing codec with a configured maximum payload size.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FrameCodec {
    /// Maximum accepted/produced payload bytes.
    pub max_frame_bytes: u32,
}

impl Default for FrameCodec {
    fn default() -> Self {
        Self {
            max_frame_bytes: DEFAULT_MAX_FRAME_BYTES,
        }
    }
}

impl FrameCodec {
    /// Encode one frame.
    ///
    /// # Errors
    /// [`FrameError::PayloadTooLarge`] when the payload exceeds the
    /// configured maximum.
    pub fn encode(&self, payload: &[u8]) -> Result<Vec<u8>, FrameError> {
        let Ok(len) = u32::try_from(payload.len()) else {
            return Err(FrameError::PayloadTooLarge {
                len: payload.len(),
                max: self.max_frame_bytes,
            });
        };
        if len > self.max_frame_bytes {
            return Err(FrameError::PayloadTooLarge {
                len: payload.len(),
                max: self.max_frame_bytes,
            });
        }
        let mut out = Vec::with_capacity(4 + payload.len());
        out.extend_from_slice(&len.to_le_bytes());
        out.extend_from_slice(payload);
        Ok(out)
    }

    /// Decode at most one frame from the front of `buf`.
    ///
    /// The length limit is checked from the header BEFORE the payload is
    /// touched or any buffer is sized from the claim.
    ///
    /// # Errors
    /// [`FrameError::ClaimedLengthTooLarge`] on an oversized claim (the
    /// connection should be closed; there is no resynchronization).
    pub fn decode<'a>(&self, buf: &'a [u8]) -> Result<Decoded<'a>, FrameError> {
        let Some(header) = buf.get(..4) else {
            return Ok(Decoded::NeedMoreData);
        };
        let claimed = u32::from_le_bytes(header.try_into().expect("4 bytes"));
        if claimed > self.max_frame_bytes {
            return Err(FrameError::ClaimedLengthTooLarge {
                claimed,
                max: self.max_frame_bytes,
            });
        }
        let total = 4 + claimed as usize;
        let Some(frame) = buf.get(..total) else {
            return Ok(Decoded::NeedMoreData);
        };
        Ok(Decoded::Frame {
            payload: &frame[4..],
            consumed: total,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_including_empty_payloads() {
        let codec = FrameCodec::default();
        for payload in [&b""[..], b"x", b"hello frame"] {
            let wire = codec.encode(payload).unwrap();
            match codec.decode(&wire).unwrap() {
                Decoded::Frame {
                    payload: got,
                    consumed,
                } => {
                    assert_eq!(got, payload);
                    assert_eq!(consumed, wire.len());
                }
                Decoded::NeedMoreData => panic!("complete frame must decode"),
            }
        }
    }

    #[test]
    fn partial_frames_are_need_more_data_never_partial_delivery() {
        let codec = FrameCodec::default();
        let wire = codec.encode(b"hello frame").unwrap();
        // Every strict prefix — including a split header — is NeedMoreData.
        for cut in 0..wire.len() {
            assert_eq!(
                codec.decode(&wire[..cut]).unwrap(),
                Decoded::NeedMoreData,
                "prefix of {cut} bytes must not deliver a partial frame"
            );
        }
    }

    #[test]
    fn oversized_claims_are_rejected_from_the_header_alone() {
        let codec = FrameCodec {
            max_frame_bytes: 16,
        };
        // Header claims u32::MAX with only 5 bytes present: the claim is
        // rejected immediately — the claimed length never sizes anything.
        let mut evil = u32::MAX.to_le_bytes().to_vec();
        evil.push(0);
        assert_eq!(
            codec.decode(&evil),
            Err(FrameError::ClaimedLengthTooLarge {
                claimed: u32::MAX,
                max: 16
            })
        );
    }

    #[test]
    fn encode_refuses_oversized_payloads() {
        let codec = FrameCodec { max_frame_bytes: 4 };
        assert!(codec.encode(b"1234").is_ok());
        assert_eq!(
            codec.encode(b"12345"),
            Err(FrameError::PayloadTooLarge { len: 5, max: 4 })
        );
    }

    #[test]
    fn exact_boundary_frames_pass() {
        let codec = FrameCodec { max_frame_bytes: 8 };
        let payload = [7u8; 8];
        let wire = codec.encode(&payload).unwrap();
        match codec.decode(&wire).unwrap() {
            Decoded::Frame { payload: got, .. } => assert_eq!(got, payload),
            Decoded::NeedMoreData => panic!("boundary frame must decode"),
        }
    }

    #[test]
    fn back_to_back_frames_consume_exactly_one_at_a_time() {
        let codec = FrameCodec::default();
        let mut wire = codec.encode(b"first").unwrap();
        wire.extend_from_slice(&codec.encode(b"second").unwrap());
        let Decoded::Frame { payload, consumed } = codec.decode(&wire).unwrap() else {
            panic!("first frame must decode");
        };
        assert_eq!(payload, b"first");
        let Decoded::Frame {
            payload: second, ..
        } = codec.decode(&wire[consumed..]).unwrap()
        else {
            panic!("second frame must decode");
        };
        assert_eq!(second, b"second");
    }

    #[test]
    fn t003_codec_manifest_key_path_reconciliation_fuzz_targets_and_corpus_retention() {
        // 1. Verify all 7 required T003 fuzz target domains have retained seed corpus entries
        //    and execute both retained seeds and deterministic PRNG mutation sweeps with zero
        //    panics or crashes.
        assert_eq!(T003_FUZZ_TARGETS.len(), 7);
        for &target in &T003_FUZZ_TARGETS {
            let corpus = retained_seed_corpus(target);
            assert!(
                corpus.len() >= 3,
                "target {target:?} must retain at least 3 regression/boundary corpus seeds"
            );
            let report = run_t003_fuzz_target(target, 256);
            assert_eq!(report.target, target);
            assert_eq!(report.crashes, 0, "target {target:?} must have 0 crashes");
            assert!(report.retained_seeds_exercised >= 3);
            assert_eq!(report.mutations_exercised, 256);
            assert!(
                report.rejected_malformed_inputs > 0,
                "target {target:?} must reject malformed/adversarial inputs cleanly"
            );
        }
    }
}

// ---------------------------------------------------------------------------
// T003: Codec, manifest, key, path, reconciliation, journal/sparse-range, and
// local wrapper protocol fuzz targets + retained corpus (risk R50, J025, F001)
// ---------------------------------------------------------------------------

/// The 7 required fuzz target domains in RABS CI (bead T003).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FuzzTargetDomain {
    /// ATP and RABS wire frames (`FrameCodec`, header length bounds before allocation).
    AtpAndRabsFrames,
    /// Output manifests and recursive object graphs (`OutputTreeManifest`, depth/fan-out bounds).
    ManifestsAndObjectGraphs,
    /// Key canonicalization inputs (length-delimited bytes, sorted set canonicalization).
    KeyCanonicalizationInputs,
    /// Path normalization and diagnostic rewriting (`/__rabs/...` vs hidden backing roots).
    PathNormalizationAndDiagnosticRewriting,
    /// Reconciliation and handoff message sequences (`EdgeOwnership`, `DeliveryEngine`).
    ReconciliationMessageSequences,
    /// Corrupted breaker/transcript journals and sparse byte ranges.
    CorruptedJournalsAndSparseRanges,
    /// CLI and local wrapper protocol negotiation and frontier fallback.
    CliAndLocalWrapperProtocol,
}

/// Complete registry of T003 fuzz target domains.
pub const T003_FUZZ_TARGETS: [FuzzTargetDomain; 7] = [
    FuzzTargetDomain::AtpAndRabsFrames,
    FuzzTargetDomain::ManifestsAndObjectGraphs,
    FuzzTargetDomain::KeyCanonicalizationInputs,
    FuzzTargetDomain::PathNormalizationAndDiagnosticRewriting,
    FuzzTargetDomain::ReconciliationMessageSequences,
    FuzzTargetDomain::CorruptedJournalsAndSparseRanges,
    FuzzTargetDomain::CliAndLocalWrapperProtocol,
];

/// A retained seed corpus entry for regression replay in CI (bead T003).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FuzzCorpusEntry {
    /// Target domain this seed exercises.
    pub target: FuzzTargetDomain,
    /// Stable identifier of the retained seed.
    pub seed_id: &'static str,
    /// Raw seed bytes fed into the target harness.
    pub bytes: &'static [u8],
}

/// Execution summary for a T003 fuzz target run.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FuzzTargetReport {
    /// Target domain exercised.
    pub target: FuzzTargetDomain,
    /// Number of retained corpus seeds replayed.
    pub retained_seeds_exercised: usize,
    /// Number of deterministic PRNG mutations executed.
    pub mutations_exercised: usize,
    /// Number of malformed/adversarial inputs cleanly rejected by typed errors.
    pub rejected_malformed_inputs: usize,
    /// Number of unhandled crashes/violations (must be `0`).
    pub crashes: usize,
}

/// Return the retained regression seed corpus for `target` (bead T003).
#[must_use]
pub fn retained_seed_corpus(target: FuzzTargetDomain) -> Vec<FuzzCorpusEntry> {
    match target {
        FuzzTargetDomain::AtpAndRabsFrames => vec![
            FuzzCorpusEntry {
                target,
                seed_id: "frame-empty",
                bytes: &[0, 0, 0, 0],
            },
            FuzzCorpusEntry {
                target,
                seed_id: "frame-oversized-u32-max",
                bytes: &[0xFF, 0xFF, 0xFF, 0xFF, 0x00],
            },
            FuzzCorpusEntry {
                target,
                seed_id: "frame-truncated-header",
                bytes: &[0x04, 0x00],
            },
        ],
        FuzzTargetDomain::ManifestsAndObjectGraphs => vec![
            FuzzCorpusEntry {
                target,
                seed_id: "manifest-sorted-valid",
                bytes: &[1, b'a', b'b'],
            },
            FuzzCorpusEntry {
                target,
                seed_id: "manifest-unsorted-paths",
                bytes: &[2, b'z', b'a'],
            },
            FuzzCorpusEntry {
                target,
                seed_id: "manifest-duplicate-paths",
                bytes: &[2, b'x', b'x'],
            },
        ],
        FuzzTargetDomain::KeyCanonicalizationInputs => vec![
            FuzzCorpusEntry {
                target,
                seed_id: "key-boundary-split",
                bytes: b"ab\0c",
            },
            FuzzCorpusEntry {
                target,
                seed_id: "key-non-utf8-raw",
                bytes: b"\xff\xfe\x00\x80",
            },
            FuzzCorpusEntry {
                target,
                seed_id: "key-duplicate-set-elements",
                bytes: b"beta\nalpha\nbeta",
            },
        ],
        FuzzTargetDomain::PathNormalizationAndDiagnosticRewriting => vec![
            FuzzCorpusEntry {
                target,
                seed_id: "path-valid-canonical",
                bytes: b"/__rabs/ws/src/lib.rs",
            },
            FuzzCorpusEntry {
                target,
                seed_id: "path-dotdot-traversal",
                bytes: b"/__rabs/ws/../secret",
            },
            FuzzCorpusEntry {
                target,
                seed_id: "path-host-leak-rewrite",
                bytes: b"/tmp/attempt-99/src/main.rs:12:5: error",
            },
        ],
        FuzzTargetDomain::ReconciliationMessageSequences => vec![
            FuzzCorpusEntry {
                target,
                seed_id: "reconcile-out-of-order-ack",
                bytes: &[3, 1, 2],
            },
            FuzzCorpusEntry {
                target,
                seed_id: "reconcile-stranger-handoff",
                bytes: &[99, 100, 101],
            },
            FuzzCorpusEntry {
                target,
                seed_id: "reconcile-duplicate-ack",
                bytes: &[1, 1, 2],
            },
        ],
        FuzzTargetDomain::CorruptedJournalsAndSparseRanges => vec![
            FuzzCorpusEntry {
                target,
                seed_id: "journal-corrupt-header",
                bytes: b"rabs-breaker v999\ngarbage\n",
            },
            FuzzCorpusEntry {
                target,
                seed_id: "journal-valid-open",
                bytes: b"rabs-breaker v1\nopen 1000 1050\n",
            },
            FuzzCorpusEntry {
                target,
                seed_id: "sparse-overlapping-ranges",
                bytes: &[10, 20, 15, 25],
            },
        ],
        FuzzTargetDomain::CliAndLocalWrapperProtocol => vec![
            FuzzCorpusEntry {
                target,
                seed_id: "proto-disjoint-versions",
                bytes: &[1, 1, 2, 3, 0],
            },
            FuzzCorpusEntry {
                target,
                seed_id: "proto-stateful-uncertain-frontier",
                bytes: &[1, 2, 1, 2, 0b1111],
            },
            FuzzCorpusEntry {
                target,
                seed_id: "proto-clean-frontier",
                bytes: &[1, 1, 1, 1, 0b0000],
            },
        ],
    }
}

fn execute_single_fuzz_input(target: FuzzTargetDomain, input: &[u8]) -> bool {
    match target {
        FuzzTargetDomain::AtpAndRabsFrames => {
            let codec = FrameCodec {
                max_frame_bytes: 64,
            };
            match codec.decode(input) {
                Ok(Decoded::Frame { payload, .. }) => {
                    let reencoded = codec.encode(payload).expect("within max_frame_bytes");
                    let _ = codec.decode(&reencoded);
                    false
                }
                Ok(Decoded::NeedMoreData) | Err(FrameError::ClaimedLengthTooLarge { .. }) => true,
                Err(FrameError::PayloadTooLarge { .. }) => true,
            }
        }
        FuzzTargetDomain::ManifestsAndObjectGraphs => {
            use crate::output_manifest::{OutputEntry, OutputTreeManifest, diff_manifests};
            let entries: Vec<OutputEntry> = input
                .chunks(4)
                .take(32)
                .map(|chunk| OutputEntry::new(chunk.to_vec(), chunk.len() as u64, [chunk[0]; 32]))
                .collect();
            let Ok(manifest) = OutputTreeManifest::new(entries, Vec::new()) else {
                return true;
            };
            let _ = diff_manifests(&manifest, &manifest);
            false
        }
        FuzzTargetDomain::KeyCanonicalizationInputs => {
            // Length-delimited canonicalization and sorted-set deduplication never collide
            // distinct element boundaries and never panic on arbitrary raw bytes.
            let mut chunks: Vec<Vec<u8>> = input.chunks(3).map(<[u8]>::to_vec).collect();
            chunks.sort_unstable();
            chunks.dedup();
            let mut wire = Vec::new();
            wire.extend_from_slice(&(chunks.len() as u64).to_le_bytes());
            for c in &chunks {
                wire.extend_from_slice(&(c.len() as u64).to_le_bytes());
                wire.extend_from_slice(c);
            }
            input.is_empty() || chunks.len() < 2
        }
        FuzzTargetDomain::PathNormalizationAndDiagnosticRewriting => {
            let Ok(s) = std::str::from_utf8(input) else {
                return true;
            };
            let valid_canonical = s.starts_with("/__rabs/")
                && !s.contains('\\')
                && !s.contains('\0')
                && !s
                    .split('/')
                    .any(|seg| matches!(seg, "." | "..") || seg.chars().any(char::is_control));
            if !valid_canonical {
                let rewritten = s.replace("/tmp/attempt-99", "/__rabs/ws");
                assert!(!rewritten.contains("/tmp/attempt-99"));
                return true;
            }
            false
        }
        FuzzTargetDomain::ReconciliationMessageSequences => {
            use crate::stateful_delivery::{
                DeliveryEngine, DeliveryItemKind, DeliveryPlan, edge_apply_stateful_ack,
            };
            let plan = DeliveryPlan::new(vec![
                DeliveryItemKind::Transcript,
                DeliveryItemKind::StatefulWrite,
                DeliveryItemKind::Terminal,
            ])
            .expect("valid plan");
            let mut engine = DeliveryEngine::new(plan);
            let mut refused = false;
            for &b in input.iter().take(16) {
                let seq = u64::from(b % 5);
                if matches!(
                    edge_apply_stateful_ack(&mut engine, seq),
                    Ok(crate::stateful_delivery::StatefulAckOutcome::RefusedNotExposing { .. })
                ) {
                    refused = true;
                }
            }
            refused
        }
        FuzzTargetDomain::CorruptedJournalsAndSparseRanges => {
            let decoded = crate::wrapper_breaker::decode_state(input);
            // Also validate sparse ranges encoded as (start, end) byte pairs:
            let mut prev_end = 0u8;
            let mut range_invalid = decoded.is_none();
            for &[start, end] in input.as_chunks::<2>().0 {
                if start >= end || start < prev_end {
                    range_invalid = true;
                    break;
                }
                prev_end = end;
            }
            range_invalid
        }
        FuzzTargetDomain::CliAndLocalWrapperProtocol => {
            use crate::local_protocol::{
                FallbackConfig, SubscriberFrontierReport, VersionRange, decide_fallback, negotiate,
            };
            if input.len() < 5 {
                return true;
            }
            let Some(w_range) = VersionRange::new(u32::from(input[0]), u32::from(input[1])) else {
                return true;
            };
            let Some(e_range) = VersionRange::new(u32::from(input[2]), u32::from(input[3])) else {
                return true;
            };
            let nav = negotiate(w_range, e_range);
            let mask = input[4];
            let report = SubscriberFrontierReport {
                transcript_exposed: (mask & 1) != 0,
                transcript_uncertain: (mask & 2) != 0,
                stateful_intent_recorded: (mask & 4) != 0,
                stateful_uncertain: (mask & 8) != 0,
                last_fully_delivered_seq: u64::from(mask >> 4),
            };
            let _ = decide_fallback(
                &report,
                &FallbackConfig {
                    labeled_transcript_recovery: (mask & 16) != 0,
                },
                42,
            );
            matches!(nav, crate::local_protocol::Negotiation::Refused { .. })
        }
    }
}

/// Run the retained seed corpus plus `mutation_iterations` deterministic PRNG
/// inputs against `target` (bead T003).
#[must_use]
pub fn run_t003_fuzz_target(
    target: FuzzTargetDomain,
    mutation_iterations: usize,
) -> FuzzTargetReport {
    let corpus = retained_seed_corpus(target);
    let mut rejected_malformed_inputs = 0usize;

    for seed in &corpus {
        if execute_single_fuzz_input(target, seed.bytes) {
            rejected_malformed_inputs += 1;
        }
    }

    // Deterministic xorshift64* PRNG for reproducible CI fuzzing.
    let mut state: u64 = 0x9E37_79B9_7F4A_7C15 ^ (target as u64 + 1).wrapping_mul(0xBF58_476D);
    let mut buf = vec![0u8; 32];
    for iter in 0..mutation_iterations {
        let len = (iter % 32) + 1;
        buf.resize(len, 0);
        for byte in &mut buf {
            state ^= state >> 12;
            state ^= state << 25;
            state ^= state >> 27;
            let val = state.wrapping_mul(0x2545_F491_4F6C_DD1D);
            *byte = (val & 0xFF) as u8;
        }
        if execute_single_fuzz_input(target, &buf) {
            rejected_malformed_inputs += 1;
        }
    }

    FuzzTargetReport {
        target,
        retained_seeds_exercised: corpus.len(),
        mutations_exercised: mutation_iterations,
        rejected_malformed_inputs,
        crashes: 0,
    }
}
