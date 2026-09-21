//! Negotiated request-bound source upload, before durable execution admission.
//!
//! The wire names a manifest and relative files, never the worker's staging
//! directory. A sealed owner is moved to the execution lifetime; reconnects
//! discard incomplete staging, not execution history. Completed result recovery
//! uses the ORIGINAL source-bearing request fingerprint and needs no reupload.

use rabs_sandbox::source_transfer::{
    MAX_SOURCE_CHUNK, MAX_SOURCE_FILES, SOURCE_TRANSFER, SourceFile, SourceManifest, SourceReceiver,
};
use serde_json::{Value, json};
use std::io;
use std::time::{Duration, Instant};

const UPLOAD_BUDGET: Duration = Duration::from_secs(5 * 60);

fn invalid(message: &str) -> String { message.to_owned() }

pub fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn decode_hex(value: &str, maximum: usize) -> Result<Vec<u8>, String> {
    if value.len() % 2 != 0 || value.len() / 2 > maximum
        || !value.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err(invalid("invalid bounded source hex"));
    }
    value.as_bytes().chunks_exact(2).map(|pair| {
        let digit = |byte: u8| if byte <= b'9' { byte - b'0' } else { byte - b'a' + 10 };
        Ok((digit(pair[0]) << 4) | digit(pair[1]))
    }).collect()
}

fn digest(value: &Value) -> Result<[u8; 32], String> {
    decode_hex(value.as_str().ok_or("source digest must be a string")?, 32)?
        .try_into().map_err(|_| invalid("source digest must contain 32 bytes"))
}

/// Interpret only the bounded source manifest. Other request fields remain
/// untouched so the journal fingerprints the exact original execution request.
pub fn parse_manifest(value: &Value) -> Result<SourceManifest, String> {
    if !value.as_object().is_some_and(|object| object.len() == 2) {
        return Err(invalid("source manifest requires exactly files and manifest_sha256"));
    }
    let rows = value["files"].as_array().filter(|rows| rows.len() <= MAX_SOURCE_FILES)
        .ok_or("invalid source file list")?;
    let mut files = Vec::with_capacity(rows.len());
    for row in rows {
        if !row.as_object().is_some_and(|object| object.len() == 4) {
            return Err(invalid("invalid source file fields"));
        }
        files.push(SourceFile {
            path: row["path"].as_str().ok_or("source path must be a string")?.to_owned(),
            len: row["bytes"].as_u64().ok_or("source length must be unsigned")?,
            sha256: digest(&row["sha256"])?,
            executable: row["executable"].as_bool().ok_or("source executable bit must be boolean")?,
        });
    }
    let manifest = SourceManifest::new(files).map_err(|error| error.to_string())?;
    if manifest.digest() != digest(&value["manifest_sha256"])? {
        return Err(invalid("source manifest digest mismatch"));
    }
    Ok(manifest)
}

pub fn request_manifest(request: &Value) -> Result<Option<SourceManifest>, String> {
    match request.get("source_manifest") {
        None => Ok(None),
        Some(value) => {
            if request.get("workspace_backing").is_some() {
                return Err(invalid("source manifest and worker workspace path are mutually exclusive"));
            }
            parse_manifest(value).map(Some)
        }
    }
}

pub fn selected(frame: &str) -> Result<bool, String> {
    let value: Value = serde_json::from_str(frame).map_err(|error| error.to_string())?;
    match value.get("source_transfer") {
        None => Ok(false),
        Some(value) if value.as_str() == Some(SOURCE_TRANSFER) => Ok(true),
        Some(_) => Err(invalid("unsupported source_transfer selection")),
    }
}

/// Keeps worker-owned source bytes alive until the process and all writers have
/// drained. It conveys no publication permission and is never reconstructed from
/// an arbitrary path supplied in a frame.
pub struct SourceOwner {
    receiver: SourceReceiver,
    _directory: tempfile::TempDir,
    request_id: u64,
    deadline: Instant,
}

#[derive(Default)]
pub struct SourceTransferState {
    pending: Option<SourceOwner>,
}

impl SourceTransferState {
    /// Handle only source-begin/chunk/seal after explicit session negotiation.
    /// Busy is computed by the execution driver, not asserted by the sender.
    pub fn handle(&mut self, value: &Value, enabled: bool, busy: bool) -> Result<Value, String> {
        if !enabled { return Err(invalid("source transfer not negotiated")); }
        if busy { return Err(invalid("worker-busy-or-result-pending")); }
        let id = value["request_id"].as_u64().ok_or("source request_id must be unsigned")?;
        if value["kind"] == "source-begin" {
            let manifest = parse_manifest(&value["manifest"])?;
            if let Some(owner) = &self.pending {
                if owner.request_id != id || owner.receiver.manifest() != &manifest {
                    return Err(invalid("another source transfer owns this session"));
                }
                if Instant::now() >= owner.deadline { return Err(invalid("source upload deadline exceeded")); }
                return Ok(json!({"kind":"source-ready", "request_id":id,
                    "manifest_sha256":hex(&manifest.digest()),
                    "sealed":owner.receiver.sealed_root().is_some()}));
            }
            let directory = tempfile::Builder::new().prefix("rabs-source-").tempdir()
                .map_err(|error| error.to_string())?;
            let receiver = SourceReceiver::create(&directory.path().join("workspace"), manifest)
                .map_err(|error| error.to_string())?;
            let identity = hex(&receiver.manifest().digest());
            self.pending = Some(SourceOwner {
                receiver, _directory: directory, request_id: id,
                deadline: Instant::now() + UPLOAD_BUDGET,
            });
            return Ok(json!({"kind":"source-ready", "request_id":id,
                "manifest_sha256":identity, "sealed":false}));
        }
        let owner = self.pending.as_mut().ok_or("no source transfer in this session")?;
        if owner.request_id != id || owner.receiver.manifest().digest() != digest(&value["manifest_sha256"])? {
            return Err(invalid("source transfer identity mismatch"));
        }
        if Instant::now() >= owner.deadline { return Err(invalid("source upload deadline exceeded")); }
        match value["kind"].as_str() {
            Some("source-chunk") => {
                let path = value["path"].as_str().ok_or("source chunk lacks a relative path")?;
                let offset = value["offset"].as_u64().ok_or("source chunk offset must be unsigned")?;
                let bytes = decode_hex(value["data_hex"].as_str().ok_or("source chunk lacks data")?, MAX_SOURCE_CHUNK)?;
                let next = owner.receiver.write_chunk(path, offset, &bytes, digest(&value["chunk_sha256"])?)
                    .map_err(|error| error.to_string())?;
                Ok(json!({"kind":"source-chunk-accepted", "request_id":id,
                    "manifest_sha256":hex(&owner.receiver.manifest().digest()),
                    "path":path, "next_offset":next}))
            }
            Some("source-seal") => {
                owner.receiver.seal().map_err(|error| error.to_string())?;
                Ok(json!({"kind":"source-ready", "request_id":id,
                    "manifest_sha256":hex(&owner.receiver.manifest().digest()), "sealed":true}))
            }
            _ => Err(invalid("unknown source operation")),
        }
    }

    /// Resolve the private physical path WITHOUT changing the raw request. The
    /// caller does this before journal admission, then transfers ownership only
    /// after admission succeeds. Host paths never enter a source fingerprint.
    pub fn prepared_path(&self, request: &Value, enabled: bool) -> Result<Option<String>, String> {
        let Some(manifest) = request_manifest(request)? else { return Ok(None); };
        if !enabled { return Err(invalid("source transfer not negotiated")); }
        let owner = self.pending.as_ref().ok_or("execution source has not been uploaded")?;
        if request["request_id"].as_u64() != Some(owner.request_id)
            || owner.receiver.manifest() != &manifest
        {
            return Err(invalid("execution differs from its uploaded source identity"));
        }
        if Instant::now() >= owner.deadline { return Err(invalid("source upload deadline exceeded")); }
        let path = owner.receiver.sealed_root().ok_or("execution source is not completely verified")?;
        path.to_str().map(|path| Some(path.to_owned())).ok_or_else(|| invalid("worker staging path is not UTF-8"))
    }

    /// Call only after prepared_path and successful durable admission, on the
    /// same session owner. Keeping this separate prevents an admission refusal
    /// from accidentally losing the already-verified input snapshot.
    pub fn take_prepared(&mut self, request: &Value) -> io::Result<Option<SourceOwner>> {
        if request.get("source_manifest").is_none() { return Ok(None); }
        self.prepared_path(request, true).map_err(io::Error::other)?;
        Ok(self.pending.take())
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use sha2::{Digest, Sha256};

    fn manifest() -> Value {
        let bytes = b"source\0\xff";
        let file = SourceFile { path:"src/lib.rs".to_owned(), len:bytes.len() as u64,
            sha256:Sha256::digest(bytes).into(), executable:false };
        let manifest = SourceManifest::new(vec![file]).unwrap();
        json!({"manifest_sha256":hex(&manifest.digest()), "files":[{
            "path":"src/lib.rs", "bytes":bytes.len(), "sha256":hex(&Sha256::digest(bytes)), "executable":false,
        }]})
    }

    #[test]
    fn source_negotiation_and_identity_precede_execution_ownership() {
        let manifest = manifest();
        let request = json!({"kind":"canonical-exec", "request_id":7, "source_manifest":manifest});
        let begin = json!({"kind":"source-begin", "request_id":7, "manifest":manifest});
        let mut state = SourceTransferState::default();
        assert!(state.handle(&begin, false, false).is_err());
        assert!(state.handle(&begin, true, true).is_err());
        assert!(state.prepared_path(&request, true).is_err());
        assert_eq!(state.handle(&begin, true, false).unwrap()["sealed"], false);
        assert!(state.prepared_path(&request, true).is_err());
        let identity = manifest["manifest_sha256"].clone();
        let chunk = json!({"kind":"source-chunk", "request_id":7, "manifest_sha256":identity,
            "path":"src/lib.rs", "offset":0, "data_hex":hex(b"source\0\xff"),
            "chunk_sha256":hex(&Sha256::digest(b"source\0\xff"))});
        let mut foreign = chunk.clone(); foreign["request_id"] = json!(8);
        assert!(state.handle(&foreign, true, false).is_err());
        state.handle(&chunk, true, false).unwrap();
        state.handle(&json!({"kind":"source-seal", "request_id":7, "manifest_sha256":identity}), true, false).unwrap();
        assert!(state.prepared_path(&request, false).is_err());
        let path = state.prepared_path(&request, true).unwrap().unwrap();
        assert_eq!(std::fs::read(std::path::Path::new(&path).join("src/lib.rs")).unwrap(), b"source\0\xff");
        let mut mixed = request.clone(); mixed["workspace_backing"] = json!("/untrusted");
        assert!(state.prepared_path(&mixed, true).is_err());
        let owner = state.take_prepared(&request).unwrap().unwrap();
        assert!(state.prepared_path(&request, true).is_err());
        assert!(std::path::Path::new(&path).exists());
        drop(owner);
        assert!(!std::path::Path::new(&path).exists());
    }
}
