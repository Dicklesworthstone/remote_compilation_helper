//! Bounded framing for the private, persistent canonical Cargo service.
//!
//! A client submits one profile, then receives acceptance, byte-preserving
//! stdout/stderr chunks and one terminal result. These frames authorize no
//! cache lookup or path mapping: the coordinator constructs those capabilities
//! after capturing and admitting the requested build itself.

/// This protocol is deliberately separate from the rustc wrapper endpoint.
pub const VERSION: u8 = 1;
/// Version, frame kind, and a big-endian payload length.
pub const HEADER_BYTES: usize = 6;
/// A complete local compilation profile, before parsing or source capture.
pub const MAX_PROFILE_BYTES: usize = 64 * 1024;
/// A diagnostic chunk never sizes an unbounded receive allocation.
pub const MAX_CHUNK_BYTES: usize = 64 * 1024;
/// Complete response budget, including failed planning and driver diagnostics.
pub const MAX_OUTPUT_BYTES: u64 = 128 * 1024 * 1024;
/// A terminal failure is a short UTF-8 explanation, not another output stream.
pub const MAX_FAILURE_BYTES: usize = 4096;

/// Exactly the messages supported by the first service protocol.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Kind {
    /// Client-to-service profile JSON; exactly once per connection.
    Profile = 1,
    /// Empty acknowledgement; execution can now belong to this request.
    Accepted = 2,
    /// Original bytes from the requested command's stdout.
    Stdout = 3,
    /// Original stderr plus bounded driver diagnostics.
    Stderr = 4,
    /// Four-byte big-endian native exit code in 0..=255.
    Completed = 5,
    /// UTF-8 failure; never permits an automatic local retry.
    Failed = 6,
}

/// A malformed or out-of-order service message.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WireError {
    /// Unknown version; there is no implicit downgrade.
    Version,
    /// Unknown frame kind.
    Kind,
    /// Payload size was invalid before allocation.
    Length,
    /// Payload bytes do not match the announced frame contract.
    Payload,
    /// A response violated acceptance, output or completion ordering.
    Order,
    /// Aggregate stdout/stderr bytes exceeded the connection budget.
    OutputBudget,
    /// A closed connection did not carry an authoritative terminal result.
    Incomplete,
}

impl std::fmt::Display for WireError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "canonical service protocol: {self:?}")
    }
}

impl std::error::Error for WireError {}

/// Validated, allocation-bounded frame header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Header {
    kind: Kind,
    length: usize,
}

impl Header {
    /// Validate the size before any payload is allocated.
    pub fn new(kind: Kind, length: usize) -> Result<Self, WireError> {
        let valid = match kind {
            Kind::Profile => (1..=MAX_PROFILE_BYTES).contains(&length),
            Kind::Accepted => length == 0,
            Kind::Stdout | Kind::Stderr => (1..=MAX_CHUNK_BYTES).contains(&length),
            Kind::Completed => length == 4,
            Kind::Failed => (1..=MAX_FAILURE_BYTES).contains(&length),
        };
        if !valid {
            return Err(WireError::Length);
        }
        Ok(Self { kind, length })
    }

    /// Decode only the fixed header. Invalid lengths never control allocation.
    pub fn decode(bytes: [u8; HEADER_BYTES]) -> Result<Self, WireError> {
        if bytes[0] != VERSION {
            return Err(WireError::Version);
        }
        let kind = match bytes[1] {
            1 => Kind::Profile,
            2 => Kind::Accepted,
            3 => Kind::Stdout,
            4 => Kind::Stderr,
            5 => Kind::Completed,
            6 => Kind::Failed,
            _ => return Err(WireError::Kind),
        };
        let length = u32::from_be_bytes([bytes[2], bytes[3], bytes[4], bytes[5]]);
        Self::new(
            kind,
            usize::try_from(length).map_err(|_| WireError::Length)?,
        )
    }

    /// Encode an already bounded header.
    #[must_use]
    pub fn encode(self) -> [u8; HEADER_BYTES] {
        // Every accepted kind has a maximum below u32::MAX.
        let length = u32::try_from(self.length).expect("validated service frame length");
        let [a, b, c, d] = length.to_be_bytes();
        [VERSION, self.kind as u8, a, b, c, d]
    }

    /// The announced direction/message kind.
    #[must_use]
    pub const fn kind(self) -> Kind {
        self.kind
    }

    /// The bounded payload allocation size.
    #[must_use]
    pub const fn length(self) -> usize {
        self.length
    }

    /// Validate content whose size has already been bounded by this header.
    pub fn validate_payload(self, payload: &[u8]) -> Result<(), WireError> {
        if payload.len() != self.length {
            return Err(WireError::Payload);
        }
        match self.kind {
            Kind::Completed => {
                let bytes: [u8; 4] = payload.try_into().map_err(|_| WireError::Payload)?;
                if !(0..=255).contains(&i32::from_be_bytes(bytes)) {
                    return Err(WireError::Payload);
                }
            }
            Kind::Failed => {
                std::str::from_utf8(payload).map_err(|_| WireError::Payload)?;
            }
            _ => {}
        }
        Ok(())
    }
}

/// Client-side response ordering. A closed socket alone never means success.
#[derive(Debug, Default)]
pub struct ResponseState {
    accepted: bool,
    finished: bool,
    output_bytes: u64,
}

impl ResponseState {
    /// Advance only after a complete validated frame has arrived.
    pub fn observe(&mut self, header: Header, payload: &[u8]) -> Result<(), WireError> {
        header.validate_payload(payload)?;
        if self.finished {
            return Err(WireError::Order);
        }
        match header.kind {
            Kind::Profile => return Err(WireError::Order),
            Kind::Accepted => {
                if self.accepted {
                    return Err(WireError::Order);
                }
                self.accepted = true;
            }
            Kind::Stdout | Kind::Stderr => {
                if !self.accepted {
                    return Err(WireError::Order);
                }
                let next = self
                    .output_bytes
                    .checked_add(header.length as u64)
                    .ok_or(WireError::OutputBudget)?;
                if next > MAX_OUTPUT_BYTES {
                    return Err(WireError::OutputBudget);
                }
                self.output_bytes = next;
            }
            Kind::Completed => {
                if !self.accepted {
                    return Err(WireError::Order);
                }
                self.finished = true;
            }
            Kind::Failed => self.finished = true,
        }
        Ok(())
    }

    /// Check EOF after the terminal frame; truncation does not become exit zero.
    pub fn finish(&self) -> Result<(), WireError> {
        if self.finished {
            Ok(())
        } else {
            Err(WireError::Incomplete)
        }
    }

    /// A terminal frame was received. Any subsequent frame is an error.
    #[must_use]
    pub const fn is_finished(&self) -> bool {
        self.finished
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn observe(state: &mut ResponseState, kind: Kind, bytes: &[u8]) -> Result<(), WireError> {
        state.observe(Header::new(kind, bytes.len())?, bytes)
    }

    #[test]
    fn golden_headers_preserve_binary_stream_payloads_and_native_exit_codes() {
        let header = Header::new(Kind::Stdout, 5).unwrap();
        assert_eq!(header.encode(), [1, 3, 0, 0, 0, 5]);
        assert_eq!(Header::decode(header.encode()), Ok(header));
        let mut state = ResponseState::default();
        observe(&mut state, Kind::Accepted, b"").unwrap();
        observe(&mut state, Kind::Stdout, &[0, 255, b'\n', b'{', b'}']).unwrap();
        observe(&mut state, Kind::Stderr, b"warning\n").unwrap();
        observe(&mut state, Kind::Completed, &101_i32.to_be_bytes()).unwrap();
        state.finish().unwrap();
        assert_eq!(state.output_bytes, 13);
    }

    #[test]
    fn lengths_versions_and_unknown_kinds_are_refused_from_headers() {
        assert_eq!(Header::decode([2, 1, 0, 0, 0, 1]), Err(WireError::Version));
        assert_eq!(Header::decode([1, 0, 0, 0, 0, 1]), Err(WireError::Kind));
        for kind in [Kind::Profile, Kind::Stdout, Kind::Stderr, Kind::Failed] {
            assert_eq!(Header::new(kind, 0), Err(WireError::Length));
            assert_eq!(Header::new(kind, usize::MAX), Err(WireError::Length));
            assert_eq!(
                Header::decode([1, kind as u8, 255, 255, 255, 255]),
                Err(WireError::Length)
            );
        }
        assert!(Header::new(Kind::Profile, MAX_PROFILE_BYTES).is_ok());
        assert!(Header::new(Kind::Profile, MAX_PROFILE_BYTES + 1).is_err());
        assert!(Header::new(Kind::Stdout, MAX_CHUNK_BYTES + 1).is_err());
        assert!(Header::new(Kind::Accepted, 1).is_err());
        assert!(Header::new(Kind::Completed, 3).is_err());
    }

    #[test]
    fn acceptance_and_terminal_order_cannot_be_forged() {
        for kind in [Kind::Stdout, Kind::Stderr, Kind::Completed, Kind::Profile] {
            let bytes = if kind == Kind::Completed {
                vec![0; 4]
            } else {
                vec![1]
            };
            assert_eq!(
                observe(&mut ResponseState::default(), kind, &bytes),
                Err(WireError::Order)
            );
        }
        let mut state = ResponseState::default();
        assert_eq!(state.finish(), Err(WireError::Incomplete));
        observe(&mut state, Kind::Accepted, b"").unwrap();
        assert_eq!(
            observe(&mut state, Kind::Accepted, b""),
            Err(WireError::Order)
        );
        assert_eq!(state.finish(), Err(WireError::Incomplete));
        observe(&mut state, Kind::Completed, &0_i32.to_be_bytes()).unwrap();
        assert_eq!(
            observe(&mut state, Kind::Stdout, b"late"),
            Err(WireError::Order)
        );
        assert_eq!(
            observe(&mut state, Kind::Completed, &0_i32.to_be_bytes()),
            Err(WireError::Order)
        );
    }

    #[test]
    fn refusal_is_terminal_before_or_after_acceptance() {
        for accepted in [false, true] {
            let mut state = ResponseState::default();
            if accepted {
                observe(&mut state, Kind::Accepted, b"").unwrap();
            }
            observe(&mut state, Kind::Failed, b"build was cancelled").unwrap();
            state.finish().unwrap();
            assert_eq!(
                observe(&mut state, Kind::Accepted, b""),
                Err(WireError::Order)
            );
        }
        assert!(
            Header::new(Kind::Failed, 1)
                .unwrap()
                .validate_payload(&[255])
                .is_err()
        );
        let header = Header::new(Kind::Completed, 4).unwrap();
        for code in [-1_i32, 256, i32::MAX] {
            assert_eq!(
                header.validate_payload(&code.to_be_bytes()),
                Err(WireError::Payload)
            );
        }
    }

    #[test]
    fn aggregate_budget_is_shared_by_both_streams() {
        let mut state = ResponseState::default();
        observe(&mut state, Kind::Accepted, b"").unwrap();
        let bytes = vec![7; MAX_CHUNK_BYTES];
        for index in 0..(MAX_OUTPUT_BYTES / MAX_CHUNK_BYTES as u64) {
            let kind = if index % 2 == 0 {
                Kind::Stdout
            } else {
                Kind::Stderr
            };
            observe(&mut state, kind, &bytes).unwrap();
        }
        assert_eq!(
            observe(&mut state, Kind::Stderr, b"x"),
            Err(WireError::OutputBudget)
        );
        assert_eq!(state.output_bytes, MAX_OUTPUT_BYTES);
        observe(&mut state, Kind::Completed, &0_i32.to_be_bytes()).unwrap();
    }
}
