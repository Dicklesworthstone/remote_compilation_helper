//! One bounded acknowledgment window across the entire cold toolchain tree.
//! Entries and chunks keep their original wire order and exact response checks.
//! No payload is retained in this window, and any failure permanently stops it.
//! A valid oldest ACK releases only its own credit: later controls remain in
//! flight while the sender refills that space, instead of draining each burst.

use super::{CHUNK_WINDOW, WorkerPeer, digest, invalid, require};
use serde_json::Value;
use std::collections::VecDeque;
use std::io;

// The worker permits eight deferred frames / 2 MiB. Stay strictly below both
// ceilings, including a large metadata entry rather than only regular chunks.
pub(super) const MAX_IN_FLIGHT_BYTES: usize = 1024 * 1024;

pub(super) enum ExpectedAck<'a> {
    Entry { path: &'a str },
    Chunk { path: &'a str, next_offset: u64 },
}

impl ExpectedAck<'_> {
    fn path(&self) -> &str {
        match self {
            Self::Entry { path } | Self::Chunk { path, .. } => path,
        }
    }

    fn check_request(&self, frame: &Value, request_id: u64, identity: &[u8; 32]) -> io::Result<()> {
        let kind = match self {
            Self::Entry { .. } => "toolchain-entry",
            Self::Chunk { .. } => "toolchain-chunk",
        };
        require(
            frame["kind"] == kind
                && frame["request_id"].as_u64() == Some(request_id)
                && frame["path"].as_str() == Some(self.path())
                && digest(&frame["sha256"])? == *identity,
            "toolchain upload window cannot send a foreign or non-payload control",
        )
    }

    fn check_reply(&self, reply: &Value, request_id: u64, identity: &[u8; 32]) -> io::Result<()> {
        let (kind, fields) = match self {
            Self::Entry { .. } => ("toolchain-entry-accepted", 4),
            Self::Chunk { .. } => ("toolchain-chunk-accepted", 5),
        };
        require(
            reply
                .as_object()
                .is_some_and(|object| object.len() == fields)
                && reply["kind"] == kind
                && reply["request_id"].as_u64() == Some(request_id)
                && digest(&reply["sha256"])? == *identity
                && reply["path"].as_str() == Some(self.path()),
            "toolchain acknowledgment kind, shape, identity or entry mismatch",
        )?;
        if let Self::Chunk { next_offset, .. } = self {
            require(
                reply["next_offset"].as_u64() == Some(*next_offset),
                "toolchain acknowledgment does not cover the transmitted range",
            )?;
        }
        Ok(())
    }
}

pub(super) struct UploadWindow<'peer, 'paths, P: WorkerPeer + ?Sized> {
    peer: &'peer mut P,
    request_id: u64,
    identity: [u8; 32],
    // The byte charge includes the encoded frame and its newline. Retaining
    // it per control is necessary when metadata and chunks have different sizes.
    pending: VecDeque<(ExpectedAck<'paths>, usize)>,
    pending_bytes: usize,
    failed: bool,
}

impl<'peer, 'paths, P: WorkerPeer + ?Sized> UploadWindow<'peer, 'paths, P> {
    pub(super) fn new(peer: &'peer mut P, request_id: u64, identity: [u8; 32]) -> Self {
        Self {
            peer,
            request_id,
            identity,
            pending: VecDeque::with_capacity(CHUNK_WINDOW),
            pending_bytes: 0,
            failed: false,
        }
    }

    pub(super) fn queue(&mut self, frame: &Value, expected: ExpectedAck<'paths>) -> io::Result<()> {
        require(!self.failed, "toolchain upload window already failed")?;
        // Burn before any validation, I/O or possibly partial write. A caller
        // cannot reuse this window after a failed send, read or acknowledgment.
        self.failed = true;
        expected.check_request(frame, self.request_id, &self.identity)?;
        let bytes = serde_json::to_vec(frame)?
            .len()
            .checked_add(1)
            .filter(|bytes| *bytes <= MAX_IN_FLIGHT_BYTES)
            .ok_or_else(|| invalid("toolchain control exceeds its byte window"))?;
        while self.pending_bytes > MAX_IN_FLIGHT_BYTES - bytes {
            self.acknowledge_one()?;
        }
        self.peer.send(frame)?;
        self.pending.push_back((expected, bytes));
        self.pending_bytes += bytes;
        if self.pending.len() == CHUNK_WINDOW {
            // One validated reply makes room for one more control. Do not
            // wait for the rest of the window: those bytes are already owned
            // by the same admitted transfer and retain their exact ACK debt.
            self.acknowledge_one()?;
        }
        self.failed = false;
        Ok(())
    }

    fn acknowledge_one(&mut self) -> io::Result<()> {
        let (expected, bytes) = self
            .pending
            .front()
            .ok_or_else(|| invalid("toolchain byte credit has no pending acknowledgment"))?;
        let reply = self.peer.receive()?;
        expected.check_reply(&reply, self.request_id, &self.identity)?;
        // A malformed, lost or out-of-order ACK earns no credit. Keep the
        // debt until every identity/range check above has succeeded.
        self.pending_bytes = self
            .pending_bytes
            .checked_sub(*bytes)
            .ok_or_else(|| invalid("toolchain upload byte credit underflow"))?;
        let _ = self.pending.pop_front();
        Ok(())
    }

    /// The caller may request the final seal only after every sent control has
    /// its own valid ACK. Dropping or failing a window never drains or retries.
    pub(super) fn finish(mut self) -> io::Result<()> {
        require(!self.failed, "toolchain upload window already failed")?;
        self.failed = true;
        while !self.pending.is_empty() {
            self.acknowledge_one()?;
        }
        require(
            self.pending_bytes == 0,
            "toolchain upload has unacknowledged bytes",
        )
    }
}
