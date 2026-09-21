//! Negotiated request-bound source upload, before durable execution admission.
//!
//! The wire names a manifest and relative files, never the worker's staging
//! directory. A sealed owner is moved to the execution lifetime; reconnects
//! discard incomplete staging, not execution history. Completed result recovery
//! uses the ORIGINAL source-bearing request fingerprint and needs no reupload.
//! Optional source-byte reuse is explicit in source-begin. It saves transport,
//! never grants action-cache authority or skips the request's final source seal.

mod cache;

use rabs_sandbox::source_transfer::{
    MAX_SOURCE_CHUNK, MAX_SOURCE_FILES, SOURCE_TRANSFER, SourceFile, SourceManifest, SourceReceiver,
};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
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
    allow_cached_files: bool,
    missing_files: Vec<String>,
    reused_bytes: u64,
    cache: Option<cache::SourceCache>,
    cache_write_error: Option<String>,
    source_failed: bool,
}

impl SourceOwner {
    fn ready(&self) -> Value {
        let mut reply = json!({"kind":"source-ready", "request_id":self.request_id,
            "manifest_sha256":hex(&self.receiver.manifest().digest()),
            "sealed":self.receiver.sealed_root().is_some() && !self.source_failed});
        if self.allow_cached_files {
            // This is the frozen initial missing set, not a new cache lookup on
            // every retry. Reused bytes already belong to this private receiver.
            reply["missing_files"] = json!(self.missing_files);
            reply["source_reused_bytes"] = json!(self.reused_bytes);
            reply["cache_write_error"] = json!(self.cache_write_error);
        }
        reply
    }
}

#[derive(Default)]
pub struct SourceTransferState {
    pending: Option<SourceOwner>,
    #[cfg(test)]
    cache_override: Option<cache::SourceCache>,
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
            let allow_cached_files = match value.get("allow_cached_files") {
                None => false,
                Some(value) => value.as_bool().ok_or("allow_cached_files must be boolean")?,
            };
            if let Some(owner) = &self.pending {
                if owner.request_id != id || owner.receiver.manifest() != &manifest
                    || owner.allow_cached_files != allow_cached_files
                {
                    return Err(invalid("another source transfer owns this session"));
                }
                if owner.source_failed { return Err(invalid("execution source verification failed")); }
                if Instant::now() >= owner.deadline { return Err(invalid("source upload deadline exceeded")); }
                return Ok(owner.ready());
            }
            let deadline = Instant::now() + UPLOAD_BUDGET;
            let cache = if allow_cached_files {
                #[cfg(test)]
                let configured = self.cache_override.clone().map_or_else(cache::SourceCache::configured, |cache| Ok(Some(cache)));
                #[cfg(not(test))]
                let configured = cache::SourceCache::configured();
                configured.map_err(|error| format!("source cache configuration: {error}"))?
            } else { None };
            let directory = tempfile::Builder::new().prefix("rabs-source-").tempdir()
                .map_err(|error| error.to_string())?;
            let mut receiver = SourceReceiver::create(&directory.path().join("workspace"), manifest)
                .map_err(|error| error.to_string())?;
            let mut missing_files = Vec::new();
            let mut reused_bytes = 0;
            for file in receiver.manifest().files().to_vec() {
                if Instant::now() >= deadline { return Err(invalid("source upload deadline exceeded")); }
                if file.len == 0 { continue; }
                if let Some(bytes) = cache.as_ref().and_then(|cache| cache.load(&file)) {
                    // Read and verify the COMPLETE cached object first. A miss
                    // must leave staging untouched, not poison it mid-copy.
                    for (index, chunk) in bytes.chunks(MAX_SOURCE_CHUNK).enumerate() {
                        receiver.write_chunk(&file.path, index as u64 * MAX_SOURCE_CHUNK as u64,
                            chunk, Sha256::digest(chunk).into()).map_err(|error| error.to_string())?;
                    }
                    reused_bytes += file.len;
                } else {
                    missing_files.push(file.path);
                }
            }
            if Instant::now() >= deadline { return Err(invalid("source upload deadline exceeded")); }
            let owner = SourceOwner {
                receiver, _directory: directory, request_id: id,
                deadline, allow_cached_files, missing_files, reused_bytes, cache,
                cache_write_error: None, source_failed: false,
            };
            let reply = owner.ready();
            self.pending = Some(owner);
            return Ok(reply);
        }
        let owner = self.pending.as_mut().ok_or("no source transfer in this session")?;
        if owner.source_failed { return Err(invalid("execution source verification failed")); }
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
                // Seed once, before execution owns the source. Optional cache
                // storage failure is not an execution failure; discovering a
                // changed source is, and remains fenced on subsequent frames.
                if let Some(cache) = owner.cache.take() {
                    match cache.remember(&owner.receiver) {
                        Ok(_) => {}
                        Err(cache::RememberError::Cache(error)) => owner.cache_write_error = Some(error.to_string()),
                        Err(cache::RememberError::Source(error)) => {
                            owner.source_failed = true;
                            return Err(format!("sealed source verification failed: {error}"));
                        }
                    }
                }
                if Instant::now() >= owner.deadline { return Err(invalid("source upload deadline exceeded")); }
                Ok(owner.ready())
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
        if owner.source_failed { return Err(invalid("execution source verification failed")); }
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

    fn projection(files: &[(&str, &[u8], bool)]) -> Value {
        let manifest = SourceManifest::new(files.iter().map(|(path, bytes, executable)| SourceFile {
            path: (*path).into(), len: bytes.len() as u64,
            sha256: Sha256::digest(bytes).into(), executable: *executable,
        }).collect()).unwrap();
        json!({"manifest_sha256":hex(&manifest.digest()), "files":manifest.files().iter().map(|file| {
            json!({"path":file.path, "bytes":file.len, "sha256":hex(&file.sha256), "executable":file.executable})
        }).collect::<Vec<_>>()})
    }

    fn cached_state(parent: &std::path::Path) -> SourceTransferState {
        SourceTransferState {
            cache_override: Some(cache::SourceCache::open(parent).unwrap()),
            ..SourceTransferState::default()
        }
    }

    fn begin(manifest: &Value, id: u64) -> Value {
        json!({"kind":"source-begin", "request_id":id, "manifest":manifest, "allow_cached_files":true})
    }

    fn seal(manifest: &Value, id: u64) -> Value {
        json!({"kind":"source-seal", "request_id":id, "manifest_sha256":manifest["manifest_sha256"]})
    }

    fn upload(state: &mut SourceTransferState, manifest: &Value, id: u64, path: &str, bytes: &[u8]) {
        for (index, chunk) in bytes.chunks(MAX_SOURCE_CHUNK).enumerate() {
            state.handle(&json!({"kind":"source-chunk", "request_id":id,
                "manifest_sha256":manifest["manifest_sha256"], "path":path,
                "offset":index * MAX_SOURCE_CHUNK, "data_hex":hex(chunk),
                "chunk_sha256":hex(&Sha256::digest(chunk))}), true, false).unwrap();
        }
    }

    #[test]
    fn cold_upload_then_reopened_cache_reuses_private_bytes_but_still_requires_seal() {
        use std::os::unix::fs::MetadataExt;
        let cache = tempfile::tempdir().unwrap();
        let bytes: Vec<_> = (0..MAX_SOURCE_CHUNK + 7).map(|i| (i % 251) as u8).collect();
        let manifest = projection(&[("src/lib.rs", &bytes, false), ("empty", b"", false)]);
        let mut cold = cached_state(cache.path());
        let reply = cold.handle(&begin(&manifest, 7), true, false).unwrap();
        assert_eq!(reply["missing_files"], json!(["src/lib.rs"]));
        assert_eq!(reply["source_reused_bytes"], 0);
        assert!(cold.handle(&seal(&manifest, 7), true, false).is_err());
        upload(&mut cold, &manifest, 7, "src/lib.rs", &bytes);
        assert_eq!(cold.handle(&seal(&manifest, 7), true, false).unwrap()["sealed"], true);
        drop(cold); // A fresh session has no source owner; only verified cache objects survive.

        let mut warm = cached_state(cache.path());
        let reply = warm.handle(&begin(&manifest, 8), true, false).unwrap();
        assert_eq!(reply["missing_files"], json!([]));
        assert_eq!(reply["source_reused_bytes"], bytes.len());
        assert_eq!(reply["sealed"], false);
        let request = json!({"kind":"canonical-exec", "request_id":8, "source_manifest":manifest});
        assert!(warm.prepared_path(&request, true).is_err());
        let until = warm.pending.as_ref().unwrap().deadline;
        assert_eq!(warm.handle(&begin(&manifest, 8), true, false).unwrap(), reply);
        assert_eq!(warm.pending.as_ref().unwrap().deadline, until);
        warm.handle(&seal(&manifest, 8), true, false).unwrap();
        let root = std::path::PathBuf::from(warm.prepared_path(&request, true).unwrap().unwrap());
        assert_eq!(std::fs::read(root.join("src/lib.rs")).unwrap(), bytes);
        assert_eq!(std::fs::read(root.join("empty")).unwrap(), b"");
        let cached = cache.path().join("source-files-v1").join(format!("{}.src", hex(&Sha256::digest(&bytes))));
        assert_ne!(std::fs::metadata(cached).unwrap().ino(), std::fs::metadata(root.join("src/lib.rs")).unwrap().ino());
        let owner = warm.take_prepared(&request).unwrap().unwrap();
        assert!(warm.prepared_path(&request, true).is_err());
        assert!(root.exists());
        drop(owner);
    }

    #[test]
    fn edited_files_miss_while_renamed_bytes_reuse_with_request_specific_modes() {
        use std::os::unix::fs::PermissionsExt;
        let cache = tempfile::tempdir().unwrap();
        let first = projection(&[("a", b"unchanged", false), ("b", b"before", false)]);
        let mut cold = cached_state(cache.path());
        cold.handle(&begin(&first, 1), true, false).unwrap();
        upload(&mut cold, &first, 1, "a", b"unchanged");
        upload(&mut cold, &first, 1, "b", b"before");
        cold.handle(&seal(&first, 1), true, false).unwrap();
        let next = projection(&[("renamed/a", b"unchanged", true), ("b", b"after", false)]);
        let mut warm = cached_state(cache.path());
        let start = begin(&next, 2);
        let reply = warm.handle(&start, true, false).unwrap();
        assert_eq!(reply["missing_files"], json!(["b"]));
        assert_eq!(reply["source_reused_bytes"], 9);
        assert!(warm.handle(&seal(&next, 2), true, false).is_err());
        upload(&mut warm, &next, 2, "b", b"after");
        // Retried begin reports the original missing set, not current file offsets.
        assert_eq!(warm.handle(&start, true, false).unwrap(), reply);
        warm.handle(&seal(&next, 2), true, false).unwrap();
        let request = json!({"request_id":2, "source_manifest":next});
        let root = std::path::PathBuf::from(warm.prepared_path(&request, true).unwrap().unwrap());
        assert_eq!(std::fs::read(root.join("b")).unwrap(), b"after");
        assert_eq!(std::fs::metadata(root.join("renamed/a")).unwrap().permissions().mode() & 0o777, 0o555);
        assert_eq!(std::fs::metadata(root.join("b")).unwrap().permissions().mode() & 0o777, 0o444);
        assert_ne!(first["manifest_sha256"], next["manifest_sha256"]);
    }

    #[test]
    fn corrupt_cached_content_requires_upload_and_can_be_repaired_without_reexecution() {
        use std::os::unix::fs::PermissionsExt;
        let cache = tempfile::tempdir().unwrap();
        let manifest = projection(&[("lib.rs", b"good", false)]);
        let mut state = cached_state(cache.path());
        state.handle(&begin(&manifest, 1), true, false).unwrap();
        upload(&mut state, &manifest, 1, "lib.rs", b"good");
        state.handle(&seal(&manifest, 1), true, false).unwrap();
        let cached = cache.path().join("source-files-v1").join(format!("{}.src", hex(&Sha256::digest(b"good"))));
        std::fs::set_permissions(&cached, std::fs::Permissions::from_mode(0o600)).unwrap();
        std::fs::write(&cached, b"evil").unwrap();
        let mut next = cached_state(cache.path());
        assert_eq!(next.handle(&begin(&manifest, 2), true, false).unwrap()["missing_files"], json!(["lib.rs"]));
        assert!(next.handle(&seal(&manifest, 2), true, false).is_err());
        upload(&mut next, &manifest, 2, "lib.rs", b"good");
        next.handle(&seal(&manifest, 2), true, false).unwrap();
        assert_eq!(std::fs::read(cached).unwrap(), b"good");
        assert_eq!(cached_state(cache.path()).handle(&begin(&manifest, 3), true, false).unwrap()["missing_files"], json!([]));
    }

    #[test]
    fn reuse_selection_is_explicit_immutable_and_does_not_renew_expired_ownership() {
        let cache = tempfile::tempdir().unwrap();
        let manifest = manifest();
        let mut state = cached_state(cache.path());
        let mut start = begin(&manifest, 7);
        start["allow_cached_files"] = json!("true");
        assert!(state.handle(&start, true, false).is_err());
        start["allow_cached_files"] = json!(true);
        assert!(state.handle(&start, false, false).is_err());
        assert!(state.handle(&start, true, true).is_err());
        state.handle(&start, true, false).unwrap();
        start["allow_cached_files"] = json!(false);
        assert!(state.handle(&start, true, false).is_err());
        let owner = state.pending.as_mut().unwrap();
        owner.deadline = Instant::now() - Duration::from_secs(1);
        let expired = owner.deadline;
        assert!(state.handle(&begin(&manifest, 7), true, false).is_err());
        assert!(state.handle(&seal(&manifest, 7), true, false).is_err());
        assert_eq!(state.pending.as_ref().unwrap().deadline, expired);
        let mut legacy = cached_state(cache.path());
        let reply = legacy.handle(&json!({"kind":"source-begin", "request_id":8, "manifest":manifest}), true, false).unwrap();
        assert!(reply.get("missing_files").is_none());
        assert!(legacy.pending.as_ref().unwrap().cache.is_none());
    }

    #[test]
    fn cache_storage_failure_is_optional_but_changed_execution_source_is_fenced() {
        let cache = tempfile::tempdir().unwrap();
        let manifest = projection(&[("lib.rs", b"good", false)]);
        let mut state = cached_state(cache.path());
        state.handle(&begin(&manifest, 1), true, false).unwrap();
        upload(&mut state, &manifest, 1, "lib.rs", b"good");
        // A foreign cache entry is never deleted and prevents only optional writes.
        std::fs::write(cache.path().join("source-files-v1/foreign"), b"preserve").unwrap();
        let reply = state.handle(&seal(&manifest, 1), true, false).unwrap();
        assert_eq!(reply["sealed"], true);
        assert!(reply["cache_write_error"].as_str().is_some());
        assert!(state.prepared_path(&json!({"request_id":1, "source_manifest":manifest}), true).is_ok());
        assert_eq!(std::fs::read(cache.path().join("source-files-v1/foreign")).unwrap(), b"preserve");

        let clean_cache = tempfile::tempdir().unwrap();
        let mut changed = cached_state(clean_cache.path());
        changed.handle(&begin(&manifest, 2), true, false).unwrap();
        upload(&mut changed, &manifest, 2, "lib.rs", b"good");
        let source = changed.pending.as_ref().unwrap()._directory.path().join("workspace/lib.rs");
        std::fs::write(source, b"evil").unwrap(); // Same length; metadata alone is not identity.
        assert!(changed.handle(&seal(&manifest, 2), true, false).is_err());
        let request = json!({"request_id":2, "source_manifest":manifest});
        assert!(changed.prepared_path(&request, true).is_err());
        assert!(changed.handle(&seal(&manifest, 2), true, false).is_err());
        assert!(changed.take_prepared(&request).is_err());
    }
}
