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
}
