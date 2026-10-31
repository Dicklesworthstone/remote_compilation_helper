//! A private byte hint received before execution completes.
//!
//! No path is created and no result is admitted by these frames. Only a complete
//! bounded contiguous candidate can be considered by the ordinary artifact
//! receiver, after its terminal manifest independently names the same bytes.

use super::{Item, digest, hash, invalid, is_hex, number, require, text};
use rabs_protocol::metadata_prefetch::{CHUNK_BYTES, MAX_BYTES, VERSION};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::fs::File;
use std::io::{self, Write};

pub(super) struct MetadataPrefetch {
    request: u64,
    selected: Option<String>,
    item: Option<Item>,
    bytes: Vec<u8>,
    hasher: Sha256,
    complete: bool,
}

impl MetadataPrefetch {
    pub(super) fn new(request: u64, selected: Option<String>) -> Self {
        Self {
            request,
            selected,
            item: None,
            bytes: Vec::new(),
            hasher: Sha256::new(),
            complete: false,
        }
    }

    pub(super) fn selected(&self) -> bool {
        self.selected.is_some()
    }

    pub(super) fn accept(&mut self, frame: &Value) -> io::Result<()> {
        let name = self
            .selected
            .as_deref()
            .ok_or_else(|| invalid("unnegotiated metadata prefetch"))?;
        require(
            !self.complete
                && frame.as_object().is_some_and(|object| object.len() == 13)
                && text(frame, "kind")? == "metadata-prefetch"
                && text(frame, "version")? == VERSION
                && number(frame, "request_id")? == self.request
                && text(frame, "name")? == name
                && frame.get("executable").and_then(Value::as_bool) == Some(false)
                && frame.get("publication_authorized").and_then(Value::as_bool) == Some(false),
            "invalid metadata prefetch identity or authority",
        )?;
        let len = number(frame, "total_bytes")?;
        require(
            len != 0 && len <= MAX_BYTES as u64,
            "metadata prefetch exceeds its byte bound",
        )?;
        let sha256 = digest(frame, "sha256")?;
        if let Some(item) = &self.item {
            require(
                item.len == len && item.sha256 == sha256,
                "metadata prefetch changed its identity",
            )?;
        }
        let offset = self.bytes.len() as u64;
        require(
            offset < len && number(frame, "offset")? == offset,
            "metadata prefetch is not contiguous",
        )?;
        let count = (len - offset).min(CHUNK_BYTES as u64) as usize;
        let encoded = text(frame, "data_hex")?;
        require(
            is_hex(encoded, count * 2),
            "metadata prefetch encoding or chunk length mismatch",
        )?;
        let mut bytes = Vec::with_capacity(count);
        for pair in encoded.as_bytes().as_chunks::<2>().0 {
            let digit = |byte: u8| {
                if byte <= b'9' {
                    byte - b'0'
                } else {
                    byte - b'a' + 10
                }
            };
            bytes.push(digit(pair[0]) * 16 + digit(pair[1]));
        }
        let next = offset + count as u64;
        require(
            number(frame, "next_offset")? == next
                && frame.get("eof").and_then(Value::as_bool) == Some(next == len)
                && digest(frame, "chunk_sha256")? == hash(&bytes),
            "metadata prefetch chunk range or digest mismatch",
        )?;
        self.hasher.update(&bytes);
        if next == len {
            let actual: String = self
                .hasher
                .clone()
                .finalize()
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect();
            require(
                actual == sha256,
                "complete metadata prefetch digest mismatch",
            )?;
            self.complete = true;
        }
        self.bytes.extend_from_slice(&bytes);
        if self.item.is_none() {
            self.item = Some(Item {
                name: name.to_owned(),
                len,
                sha256,
                executable: false,
            });
        }
        Ok(())
    }

    /// Terminal completion may overtake the remaining optional chunks. An
    /// incomplete candidate disappears here, without affecting normal ranges.
    pub(super) fn complete(&self) -> Option<&Self> {
        self.complete.then_some(self)
    }

    /// The caller has already validated its terminal manifest and opened a new
    /// private output file. Rehash while copying, then let the ordinary download
    /// completion enforce its digest, mode, fsync and byte-cache accounting.
    pub(super) fn copy(
        &self,
        item: &Item,
        file: &mut File,
        mut checkpoint: impl FnMut() -> io::Result<()>,
    ) -> io::Result<Option<Sha256>> {
        let Some(candidate) = self.item.as_ref().filter(|candidate| {
            self.complete
                && candidate.name == item.name
                && candidate.len == item.len
                && candidate.sha256 == item.sha256
                && candidate.executable == item.executable
        }) else {
            return Ok(None);
        };
        require(
            candidate.len == self.bytes.len() as u64,
            "metadata prefetch lost its complete bytes",
        )?;
        let mut hasher = Sha256::new();
        for bytes in self.bytes.chunks(CHUNK_BYTES) {
            checkpoint()?;
            file.write_all(bytes)?;
            hasher.update(bytes);
        }
        checkpoint()?;
        Ok(Some(hasher))
    }
}
