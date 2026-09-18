//! Complete, byte-exact diagnostic snapshots owned by one worker session.
//!
//! A drain's resident head is not present in its spill file. Retain BOTH in
//! private anonymous files before dropping the drain, hashing the same bytes
//! that will be returned. Retrieval never reopens a caller-supplied path or a
//! mutable spill name. Closing the owning files releases these scratch copies;
//! they are not durable CAS publications or reconnect-resumption records.

use rabs_asupersync::stream_drain::LaneDrain;
use sha2::{Digest, Sha256};
use std::fs::File;
use std::io::{self, Cursor, Read, Seek, SeekFrom, Write};

/// Maximum raw bytes in one retrieval response (hex encoding doubles this).
pub const MAX_OUTPUT_CHUNK_BYTES: usize = 64 * 1024;
/// Worker-local cap per retained stream. Oversize capture refuses, never truncates.
pub const MAX_RETAINED_STREAM_BYTES: u64 = 1024 * 1024 * 1024;

/// An immutable complete stream. The writable file handle is private; consumers
/// can only inspect its committed length/digest and read bounded byte ranges.
#[derive(Debug)]
pub struct CapturedStream {
    file: File,
    len: u64,
    sha256: String,
}

impl CapturedStream {
    /// Copy exactly `len` bytes and refuse early EOF, surplus bytes or an
    /// excessive claim. Memory use is one fixed-size copy buffer. Call from
    /// the blocking execution owner, never the async control reactor.
    pub fn from_reader(mut reader: impl Read, len: u64) -> io::Result<Self> {
        if len > MAX_RETAINED_STREAM_BYTES {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "output retention limit exceeded"));
        }
        let mut file = tempfile::tempfile()?;
        let mut hasher = Sha256::new();
        let mut remaining = len;
        let mut buffer = [0_u8; MAX_OUTPUT_CHUNK_BYTES];
        while remaining != 0 {
            let take = usize::try_from(remaining.min(buffer.len() as u64))
                .map_err(|_| io::Error::other("output length does not fit a chunk"))?;
            reader.read_exact(&mut buffer[..take])?;
            file.write_all(&buffer[..take])?;
            hasher.update(&buffer[..take]);
            remaining -= take as u64;
        }
        // read_exact retries Interrupted. A single extra byte proves that the
        // supplied receipt is not the complete stream, including len == 0.
        match reader.read_exact(&mut buffer[..1]) {
            Err(error) if error.kind() == io::ErrorKind::UnexpectedEof => {}
            Err(error) => return Err(error),
            Ok(()) => {
                return Err(io::Error::new(io::ErrorKind::InvalidData, "output exceeds its receipt"));
            }
        }
        file.flush()?;
        let sha256 = hasher.finalize().iter().map(|byte| format!("{byte:02x}")).collect();
        Ok(Self { file, len, sha256 })
    }

    /// Snapshot the actual resident prefix followed by the entire spill tail.
    /// Recorded lengths must agree before a snapshot can become readable.
    pub fn from_lane(lane: &LaneDrain) -> io::Result<Self> {
        let expected = (lane.resident().len() as u64)
            .checked_add(lane.spilled_bytes())
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "output length overflow"))?;
        if expected != lane.total_bytes() || expected > MAX_RETAINED_STREAM_BYTES {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "invalid output capture length"));
        }
        let head = Cursor::new(lane.resident());
        match lane.spill() {
            None => Self::from_reader(head, expected),
            Some(spill) => {
                let file = File::open(&spill.path)?;
                let metadata = file.metadata()?;
                if !metadata.is_file() || metadata.len() != spill.bytes {
                    return Err(io::Error::new(io::ErrorKind::InvalidData, "spill receipt mismatch"));
                }
                Self::from_reader(head.chain(file), expected)
            }
        }
    }

    /// Exact original stream length, including both drain tiers.
    #[must_use]
    pub fn len(&self) -> u64 {
        self.len
    }

    /// Whether the compiler wrote no bytes on this stream.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// SHA-256 of the immutable snapshot, not of a later reopened spill file.
    #[must_use]
    pub fn sha256(&self) -> &str {
        &self.sha256
    }

    /// Read a replayable range. Offset at EOF is a valid empty final chunk;
    /// offset beyond EOF, zero size and oversize requests are refusals. No
    /// offset-plus-length arithmetic can wrap and no read allocates past the cap.
    pub fn read_chunk(&mut self, offset: u64, max_bytes: usize) -> io::Result<Vec<u8>> {
        if offset > self.len || max_bytes == 0 || max_bytes > MAX_OUTPUT_CHUNK_BYTES {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "invalid output range"));
        }
        let count = usize::try_from((self.len - offset).min(max_bytes as u64))
            .map_err(|_| io::Error::other("output range does not fit a chunk"))?;
        self.file.seek(SeekFrom::Start(offset))?;
        let mut bytes = vec![0; count];
        self.file.read_exact(&mut bytes)?;
        Ok(bytes)
    }
}

/// The two separately identified streams from the same completed execution.
#[derive(Debug)]
pub struct CapturedOutputs {
    /// Complete standard output.
    pub stdout: CapturedStream,
    /// Complete standard error.
    pub stderr: CapturedStream,
}

impl CapturedOutputs {
    /// Capture all-or-nothing: a failed stderr capture drops the stdout scratch
    /// snapshot too. Original drain spill files are left intact for diagnosis.
    pub fn from_lanes(stdout: &LaneDrain, stderr: &LaneDrain) -> io::Result<Self> {
        Ok(Self {
            stdout: CapturedStream::from_lane(stdout)?,
            stderr: CapturedStream::from_lane(stderr)?,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn binary_ranges_are_replayable_bounded_and_hash_the_complete_stream() {
        let bytes: Vec<u8> = (0..MAX_OUTPUT_CHUNK_BYTES * 2 + 13).map(|i| (i % 256) as u8).collect();
        let mut stream = CapturedStream::from_reader(bytes.as_slice(), bytes.len() as u64).unwrap();
        assert_eq!(stream.sha256(), crate::session::sha256_hex(&bytes));
        let first = stream.read_chunk(0, MAX_OUTPUT_CHUNK_BYTES).unwrap();
        assert_eq!(first.len(), MAX_OUTPUT_CHUNK_BYTES);
        assert_eq!(stream.read_chunk(0, MAX_OUTPUT_CHUNK_BYTES).unwrap(), first);
        let mut restored = first;
        while (restored.len() as u64) < stream.len() {
            restored.extend(stream.read_chunk(restored.len() as u64, MAX_OUTPUT_CHUNK_BYTES).unwrap());
        }
        assert_eq!(restored, bytes);
        assert!(stream.read_chunk(stream.len(), 1).unwrap().is_empty());
        for (offset, size) in [(0, 0), (0, MAX_OUTPUT_CHUNK_BYTES + 1), (u64::MAX, 1)] {
            assert_eq!(stream.read_chunk(offset, size).unwrap_err().kind(), io::ErrorKind::InvalidInput);
        }
    }

    #[test]
    fn empty_is_explicit_and_receipt_mismatches_never_become_partial_success() {
        let mut empty = CapturedStream::from_reader(&b""[..], 0).unwrap();
        assert!(empty.is_empty());
        assert_eq!(empty.sha256(), crate::session::sha256_hex(b""));
        assert!(empty.read_chunk(0, 1).unwrap().is_empty());
        assert_eq!(CapturedStream::from_reader(&b"x"[..], 2).unwrap_err().kind(), io::ErrorKind::UnexpectedEof);
        assert_eq!(CapturedStream::from_reader(&b"xy"[..], 1).unwrap_err().kind(), io::ErrorKind::InvalidData);
        assert!(CapturedStream::from_reader(&b"x"[..], 0).is_err());
        assert!(CapturedStream::from_reader(io::empty(), MAX_RETAINED_STREAM_BYTES + 1).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn actual_drain_heads_and_spills_survive_spill_replacement() {
        use rabs_asupersync::stream_drain::{DrainLimits, join_lane, spawn_lanes};
        use std::process::{Command, Stdio};
        let dir = tempfile::tempdir().unwrap();
        let mut child = Command::new("sh")
            .args(["-c", "printf 'A\\000\\377B'; printf 'err\\n' >&2"])
            .stdout(Stdio::piped()).stderr(Stdio::piped()).spawn().unwrap();
        let (stdout, stderr) = spawn_lanes(&mut child, &DrainLimits {
            resident_bound: 2, spill_dir: dir.path().to_path_buf(),
        });
        assert!(child.wait().unwrap().success());
        let stdout = join_lane(stdout.unwrap()).unwrap();
        let stderr = join_lane(stderr.unwrap()).unwrap();
        let mut captured = CapturedOutputs::from_lanes(&stdout, &stderr).unwrap();
        std::fs::write(&stdout.spill().unwrap().path, b"replaced").unwrap();
        std::fs::write(&stderr.spill().unwrap().path, b"replaced").unwrap();
        assert_eq!(captured.stdout.read_chunk(0, 10).unwrap(), b"A\0\xffB");
        assert_eq!(captured.stderr.read_chunk(0, 10).unwrap(), b"err\n");
        assert_eq!(captured.stdout.sha256(), crate::session::sha256_hex(b"A\0\xffB"));
        assert!(CapturedOutputs::from_lanes(&stdout, &stderr).is_err());
    }
}
