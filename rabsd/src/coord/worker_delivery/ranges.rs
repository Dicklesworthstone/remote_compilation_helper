//! One bounded FIFO for verified ranges across an artifact manifest.
//!
//! The four-request limit is shared by every file, not multiplied by file count.
//! Only a fully checked and written oldest response releases its credit. File
//! descriptors and incremental hashes stay with that file until its complete
//! digest, mode and sync succeed. Failure never drains, retries or acknowledges.

use super::{
    CHUNK_BYTES, Item, Manifest, ResumeSource, WorkerPeer, create_file, digest, hash, is_hex,
    number, receive, require, text,
};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::collections::VecDeque;
use std::fs::File;
use std::io::{self, Write};
use std::path::{Path, PathBuf};

const RANGE_WINDOW: usize = 4;

struct Download<'a> {
    item: &'a Item,
    manifest_hash: Option<&'a str>,
    file: File,
    hasher: Sha256,
    offset: u64,
    requested: u64,
    empty_requested: bool,
    outstanding: usize,
}

impl<'a> Download<'a> {
    fn open(
        item: &'a Item,
        manifest_hash: Option<&'a str>,
        path: &Path,
        source: Option<&ResumeSource>,
    ) -> io::Result<Self> {
        let mut file = create_file(path)?;
        let mut hasher = Sha256::new();
        let offset = match source {
            Some(source) => source.copy_prefix(
                if manifest_hash.is_some() { "artifacts" } else { "diagnostics" },
                &item.name,
                item.len,
                &mut file,
                &mut hasher,
            )?,
            None => 0,
        };
        Ok(Self {
            item,
            manifest_hash,
            file,
            hasher,
            offset,
            requested: offset,
            empty_requested: false,
            outstanding: 0,
        })
    }

    fn needs_range(&self) -> bool {
        self.requested < self.item.len || (self.item.len == 0 && !self.empty_requested)
    }

    fn request(&mut self, peer: &mut impl WorkerPeer, id: u64) -> io::Result<()> {
        let artifact = self.manifest_hash.is_some();
        let mut frame = json!({"kind":if artifact {"artifact-read"} else {"output-read"},
            "request_id":id,"offset":self.requested,"max_bytes":CHUNK_BYTES});
        frame[if artifact { "name" } else { "stream" }] = json!(self.item.name);
        // A failed write may already have reached the peer. Propagate it once;
        // never retry this control or consume any of its outstanding responses.
        peer.send(&frame)?;
        self.outstanding += 1;
        self.empty_requested |= self.item.len == 0;
        self.requested += (self.item.len - self.requested).min(CHUNK_BYTES as u64);
        Ok(())
    }

    fn accept(&mut self, chunk: &Value, id: u64) -> io::Result<()> {
        let artifact = self.manifest_hash.is_some();
        require(self.outstanding != 0, "unsolicited byte chunk")?;
        require(
            text(chunk, "kind")? == if artifact { "artifact-chunk" } else { "output-chunk" },
            "expected byte chunk",
        )?;
        require(
            number(chunk, "request_id")? == id
                && text(chunk, if artifact { "name" } else { "stream" })? == self.item.name
                && number(chunk, "offset")? == self.offset
                && number(chunk, "total_bytes")? == self.item.len
                && digest(chunk, "sha256")? == self.item.sha256,
            "chunk identity mismatch",
        )?;
        if let Some(hash) = self.manifest_hash {
            require(
                digest(chunk, "manifest_sha256")? == hash
                    && chunk.get("executable").and_then(Value::as_bool) == Some(self.item.executable),
                "chunk manifest/mode mismatch",
            )?;
        }
        let count = (self.item.len - self.offset).min(CHUNK_BYTES as u64) as usize;
        let encoded = text(chunk, "data_hex")?;
        require(is_hex(encoded, count * 2), "chunk encoding or length mismatch")?;
        let mut bytes = Vec::with_capacity(count);
        for pair in encoded.as_bytes().as_chunks::<2>().0 {
            let digit = |b: u8| if b <= b'9' { b - b'0' } else { b - b'a' + 10 };
            bytes.push(digit(pair[0]) * 16 + digit(pair[1]));
        }
        let next = self.offset + count as u64;
        require(
            number(chunk, "next_offset")? == next
                && chunk.get("eof").and_then(Value::as_bool) == Some(next == self.item.len)
                && digest(chunk, "chunk_sha256")? == hash(&bytes),
            "chunk range or digest mismatch",
        )?;
        self.file.write_all(&bytes)?;
        self.hasher.update(&bytes);
        self.offset = next;
        self.outstanding -= 1;
        Ok(())
    }

    fn finish(self) -> io::Result<()> {
        require(
            self.offset == self.item.len && self.outstanding == 0,
            "incomplete file has outstanding ranges",
        )?;
        let actual: String = self.hasher.finalize().iter().map(|b| format!("{b:02x}")).collect();
        require(actual == self.item.sha256, "complete file digest mismatch")?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            self.file.set_permissions(std::fs::Permissions::from_mode(if self.item.executable {
                0o700
            } else {
                0o600
            }))?;
        }
        self.file.sync_all()
    }
}

fn download_many<'a>(
    peer: &mut impl WorkerPeer,
    worker: &str,
    id: u64,
    targets: impl Iterator<Item = (&'a Item, Option<&'a str>, PathBuf)>,
) -> io::Result<()> {
    let mut targets = targets.fuse();
    let mut active: VecDeque<Download<'a>> = VecDeque::with_capacity(RANGE_WINDOW);
    let mut outstanding = 0_usize;
    loop {
        while outstanding < RANGE_WINDOW {
            if active.back().is_none_or(|file| !file.needs_range()) {
                let Some((item, manifest_hash, path)) = targets.next() else {
                    break;
                };
                let file = Download::open(item, manifest_hash, &path, peer.resume_source())?;
                // A complete NONEMPTY local hint needs no range request, but
                // is not trusted until its full hash, permissions and sync pass.
                // Empty files still require their ordinary zero-length reply.
                if item.len != 0 && file.offset == item.len {
                    file.finish()?;
                    continue;
                }
                active.push_back(file);
            }
            active.back_mut().expect("range owner").request(peer, id)?;
            outstanding += 1;
        }
        let Some(file) = active.front_mut() else {
            return Ok(());
        };
        let chunk = receive(peer, worker)?;
        file.accept(&chunk, id)?;
        outstanding -= 1;
        if file.offset == file.item.len {
            // Verify and sync the oldest file before consuming ANY response
            // for its successor. Later controls may be in flight, never credited
            // as verified output. Any failure leaves all private files retained.
            active.pop_front().expect("completed range owner").finish()?;
        }
    }
}

/// Diagnostics retain their independent stream boundary and Cargo stdout check.
pub(super) fn download(
    peer: &mut impl WorkerPeer,
    worker: &str,
    id: u64,
    item: &Item,
    manifest_hash: Option<&str>,
    path: &Path,
) -> io::Result<()> {
    download_many(peer, worker, id, std::iter::once((item, manifest_hash, path.to_path_buf())))
}

/// The complete artifact manifest and directory set were validated by the
/// receiver before entry. Share four requests and at most four open writers
/// across small, empty and large files; do not allocate per-file payload buffers.
pub(super) fn download_artifacts(
    peer: &mut impl WorkerPeer,
    worker: &str,
    id: u64,
    manifest: &Manifest,
    root: &Path,
) -> io::Result<()> {
    download_many(
        peer,
        worker,
        id,
        manifest.files.iter().map(|item| (item, Some(manifest.sha256.as_str()), root.join(&item.name))),
    )
}
