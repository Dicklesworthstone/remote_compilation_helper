//! Coordinator-side source upload from an approved coherent snapshot.
//!
//! Only explicitly selected regular files leave the captured image. The sender
//! never rereads a mutable checkout, walks worker paths, or dispatches execution.
//! It uses the sandbox's ONE manifest identity implementation and verifies every
//! transfer reply before the delivery engine reaches its execution frontier.
//! Source availability is not action-key validity or cache-publication authority.

use super::worker_delivery::{WorkerAuthentication, WorkerPeer};
use rabs_asupersync::worker_transport::MAX_JSON_RECORD;
use rabs_sandbox::snapshot_capture::{MemberKind, SealedSourceSnapshot};
use rabs_sandbox::source_transfer::{
    MAX_SOURCE_CHUNK, MAX_SOURCE_FILES, SOURCE_TRANSFER, SourceFile, SourceManifest,
};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::io;
use std::sync::Arc;

fn invalid(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}
fn require(condition: bool, message: &str) -> io::Result<()> {
    if condition { Ok(()) } else { Err(invalid(message)) }
}
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}
fn digest(value: &Value) -> io::Result<[u8; 32]> {
    let value = value.as_str().ok_or_else(|| invalid("source digest is not a string"))?;
    require(value.len() == 64 && value.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
        "source digest must be 64 lowercase hex digits")?;
    let mut digest = [0_u8; 32];
    for (slot, pair) in digest.iter_mut().zip(value.as_bytes().chunks_exact(2)) {
        let digit = |byte: u8| if byte <= b'9' { byte - b'0' } else { byte - b'a' + 10 };
        *slot = (digit(pair[0]) << 4) | digit(pair[1]);
    }
    Ok(digest)
}

/// Validate the optional source declaration without requiring source bytes.
/// Resume and verified local delivery recovery use this without a checkout.
pub fn request_manifest(request: &Value) -> io::Result<Option<SourceManifest>> {
    let Some(value) = request.get("source_manifest") else { return Ok(None); };
    require(request.get("workspace_backing").is_none(),
        "source_manifest and workspace_backing are mutually exclusive")?;
    require(value.as_object().is_some_and(|object| object.len() == 2),
        "source manifest requires exactly files and manifest_sha256")?;
    let rows = value["files"].as_array().filter(|rows| rows.len() <= MAX_SOURCE_FILES)
        .ok_or_else(|| invalid("source file list outside its bound"))?;
    let mut files = Vec::with_capacity(rows.len());
    for row in rows {
        require(row.as_object().is_some_and(|object| object.len() == 4), "invalid source file fields")?;
        files.push(SourceFile {
            path: row["path"].as_str().ok_or_else(|| invalid("invalid source path"))?.to_owned(),
            len: row["bytes"].as_u64().ok_or_else(|| invalid("invalid source length"))?,
            sha256: digest(&row["sha256"])?,
            executable: row["executable"].as_bool().ok_or_else(|| invalid("invalid source executable bit"))?,
        });
    }
    let manifest = SourceManifest::new(files)?;
    require(manifest.digest() == digest(&value["manifest_sha256"])?, "source manifest digest mismatch")?;
    Ok(Some(manifest))
}

/// Immutable captured bytes plus an explicit regular-file projection. The full
/// source snapshot digest is provenance, not substituted for the projected root.
#[derive(Debug, Clone)]
pub struct SourceUpload {
    image: Arc<SealedSourceSnapshot>,
    root: String,
    manifest: SourceManifest,
}

impl SourceUpload {
    /// Callers apply their upload/confidentiality policy before selecting paths.
    /// This method cannot implicitly include siblings, symlink targets or secrets.
    pub fn from_snapshot(
        image: Arc<SealedSourceSnapshot>, root: &str, paths: &[String],
    ) -> io::Result<Self> {
        require(!paths.is_empty() && paths.len() <= MAX_SOURCE_FILES, "source projection file count")?;
        let captured = image.manifest(root).ok_or_else(|| invalid("unknown source snapshot root"))?;
        let mut files = Vec::with_capacity(paths.len());
        for path in paths {
            let Some(MemberKind::Regular { size, content_sha256, mode, .. }) = captured.members.get(path) else {
                return Err(invalid("projected source must be a captured regular file"));
            };
            let bytes = image.file_bytes(root, path).ok_or_else(|| invalid("captured source bytes missing"))?;
            require(bytes.len() as u64 == *size && <[u8; 32]>::from(Sha256::digest(bytes)) == *content_sha256,
                "captured source disagrees with its manifest")?;
            files.push(SourceFile { path:path.clone(), len:*size, sha256:*content_sha256, executable:mode & 0o111 != 0 });
        }
        Ok(Self { image, root:root.to_owned(), manifest:SourceManifest::new(files)? })
    }

    /// Bind a newly captured image to the ORIGINAL saved execution request.
    /// A checkout edit after request preparation refuses; it never silently
    /// changes the manifest under the same request ID.
    pub fn for_request(image: Arc<SealedSourceSnapshot>, root: &str, request: &Value) -> io::Result<Self> {
        let manifest = request_manifest(request)?.ok_or_else(|| invalid("request has no source manifest"))?;
        let paths: Vec<_> = manifest.files().iter().map(|file| file.path.clone()).collect();
        let upload = Self::from_snapshot(image, root, &paths)?;
        upload.validate_request(request)?;
        Ok(upload)
    }

    #[must_use]
    pub fn wire_manifest(&self) -> Value {
        json!({"manifest_sha256":hex(&self.manifest.digest()),
            "files":self.manifest.files().iter().map(|file| json!({
                "path":file.path, "bytes":file.len, "sha256":hex(&file.sha256), "executable":file.executable,
            })).collect::<Vec<_>>()})
    }

    fn begin_frame(&self, request: &Value) -> Value {
        json!({"kind":"source-begin", "request_id":request["request_id"],
            "manifest":self.wire_manifest(), "allow_cached_files":true})
    }

    /// A missing-file hint narrows transfer, never the declared input closure.
    /// An older worker without the extension receives the entire projection.
    /// Unknown paths cannot turn this into a request to upload sibling files.
    fn missing_files(&self, reply: &Value) -> io::Result<Option<BTreeSet<String>>> {
        let Some(value) = reply.get("missing_files") else { return Ok(None); };
        let rows = value.as_array().filter(|rows| rows.len() <= self.manifest.files().len())
            .ok_or_else(|| invalid("source missing-file list outside its bound"))?;
        let mut missing = BTreeSet::new();
        let mut previous: Option<&str> = None;
        for row in rows {
            let path = row.as_str().ok_or_else(|| invalid("source missing path is not a string"))?;
            require(self.manifest.files().binary_search_by(|file| file.path.as_str().cmp(path)).is_ok(),
                "worker requested a source path outside the approved projection")?;
            require(previous.is_none_or(|last| last < path),
                "source missing-file list must be sorted and unique")?;
            previous = Some(path);
            missing.insert(path.to_owned());
        }
        Ok(Some(missing))
    }

    pub fn validate_request(&self, request: &Value) -> io::Result<()> {
        require(request["kind"] == "canonical-exec" && request["request_id"].as_u64().is_some(),
            "source upload requires an original execution request")?;
        require(request_manifest(request)?.as_ref() == Some(&self.manifest),
            "captured source differs from the saved execution manifest")?;
        let begin = self.begin_frame(request);
        require(serde_json::to_vec(&begin)?.len() <= MAX_JSON_RECORD, "source manifest exceeds the transport record bound")
    }

    /// Extend the ordinary grant without changing its output/retention policy.
    /// This is checked BEFORE transmission of either source bytes or execution.
    pub(crate) fn grant(&self, hello: &Value, grant: &Value) -> io::Result<Value> {
        require(hello["source_transfers"].as_array().is_some_and(|values| values.iter().any(|value| value == SOURCE_TRANSFER)),
            "worker does not support source-files-v1")?;
        require(grant["kind"] == "session-ok" && grant.get("source_transfer").is_none_or(|value| value == SOURCE_TRANSFER),
            "conflicting source transfer selection")?;
        let mut grant = grant.clone();
        grant["source_transfer"] = json!(SOURCE_TRANSFER);
        Ok(grant)
    }

    /// Send one source projection over an ALREADY admitted session. A failed
    /// exchange is terminal for this operation; there is no execution retry.
    /// Transport implementations enforce one absolute upload-phase deadline.
    pub(crate) fn transmit<P: WorkerPeer + ?Sized>(&self, peer: &mut P, request: &Value) -> io::Result<()> {
        self.validate_request(request)?;
        let id = request["request_id"].as_u64().ok_or_else(|| invalid("source request identity"))?;
        let identity = hex(&self.manifest.digest());
        let check = |reply: &Value, kind: &str| -> io::Result<()> {
            require(reply["kind"] == kind && reply["request_id"].as_u64() == Some(id)
                && reply["manifest_sha256"].as_str() == Some(identity.as_str()),
                "source response kind or identity mismatch")
        };
        peer.send(&self.begin_frame(request))?;
        let reply = peer.receive()?;
        check(&reply, "source-ready")?;
        require(reply["sealed"] == false, "new source operation unexpectedly already sealed")?;
        let missing = self.missing_files(&reply)?;
        for file in self.manifest.files() {
            if missing.as_ref().is_some_and(|paths| !paths.contains(&file.path)) { continue; }
            let bytes = self.image.file_bytes(&self.root, &file.path).ok_or_else(|| invalid("retained source missing"))?;
            for (index, chunk) in bytes.chunks(MAX_SOURCE_CHUNK).enumerate() {
                let offset = (index as u64) * MAX_SOURCE_CHUNK as u64;
                let next = offset + chunk.len() as u64;
                peer.send(&json!({"kind":"source-chunk", "request_id":id, "manifest_sha256":identity,
                    "path":file.path, "offset":offset, "data_hex":hex(chunk),
                    "chunk_sha256":hex(&Sha256::digest(chunk))}))?;
                let reply = peer.receive()?;
                check(&reply, "source-chunk-accepted")?;
                require(reply["path"].as_str() == Some(file.path.as_str()) && reply["next_offset"].as_u64() == Some(next),
                    "source acknowledgment does not cover the transmitted range")?;
            }
        }
        // Even a completely warm projection needs this exact final seal. A
        // missing-file hint by itself grants neither execution nor publication.
        peer.send(&json!({"kind":"source-seal", "request_id":id, "manifest_sha256":identity}))?;
        let reply = peer.receive()?;
        check(&reply, "source-ready")?;
        require(reply["sealed"] == true, "worker did not seal the complete source projection")
    }
}

/// Source staging inside an ordinary peer's negotiation frontier. The secure
/// adapter performs this internally AFTER its TLS-key-bound challenge instead;
/// wrapping an already-restricted authenticated adapter would bypass no checks.
/// This wrapper neither retries nor changes the original execution request.
pub struct SourcePeer<'a, P: ?Sized> {
    inner: &'a mut P,
    upload: &'a SourceUpload,
    request: &'a Value,
    attempted: bool,
}

impl<'a, P: WorkerPeer + ?Sized> SourcePeer<'a, P> {
    pub fn new(inner: &'a mut P, upload: &'a SourceUpload, request: &'a Value) -> io::Result<Self> {
        upload.validate_request(request)?;
        Ok(Self { inner, upload, request, attempted:false })
    }
}

impl<P: WorkerPeer + ?Sized> WorkerPeer for SourcePeer<'_, P> {
    fn send(&mut self, frame: &Value) -> io::Result<()> { self.inner.send(frame) }
    fn receive(&mut self) -> io::Result<Value> { self.inner.receive() }
    fn authentication(&self) -> Option<WorkerAuthentication> { self.inner.authentication() }
    fn negotiate(&mut self, hello: &Value, grant: &Value) -> io::Result<()> {
        require(!self.attempted, "source negotiation cannot be retried")?;
        self.attempted = true;
        let grant = self.upload.grant(hello, grant)?;
        self.inner.negotiate(hello, &grant)?;
        self.upload.transmit(self.inner, self.request)
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use rabs_sandbox::snapshot_capture::capture_sealed_source;
    use rabs_sandbox::source_transfer::SourceReceiver;
    use std::collections::{BTreeMap, VecDeque};

    fn fixture(root: &std::path::Path) -> (SourceUpload, Value, Vec<u8>) {
        std::fs::create_dir(root.join("src")).unwrap();
        let bytes: Vec<_> = (0..MAX_SOURCE_CHUNK + 17).map(|n| (n % 256) as u8).collect();
        std::fs::write(root.join("src/lib.rs"), &bytes).unwrap();
        std::fs::write(root.join("empty"), b"").unwrap();
        std::fs::write(root.join("not-selected.private"), b"must not be sent").unwrap();
        let image = Arc::new(capture_sealed_source(&[("workspace".into(), root.to_path_buf())], false, 2, 200_000).unwrap());
        let upload = SourceUpload::from_snapshot(image, "workspace", &["src/lib.rs".into(), "empty".into()]).unwrap();
        let request = json!({"kind":"canonical-exec", "request_id":7, "program":"fixture",
            "toolchain_backing":"/tc", "source_manifest":upload.wire_manifest()});
        (upload, request, bytes)
    }

    struct ReceiverPeer {
        owner: tempfile::TempDir,
        receiver: Option<SourceReceiver>,
        replies: VecDeque<Value>,
        sent: Vec<Value>,
        corrupt_ack: bool,
        prefilled: BTreeMap<String, Vec<u8>>,
        missing: Option<Value>,
        lose_seal_ack: bool,
    }
    impl ReceiverPeer {
        fn new() -> Self {
            Self { owner:tempfile::tempdir().unwrap(), receiver:None, replies:VecDeque::new(), sent:Vec::new(), corrupt_ack:false,
                prefilled:BTreeMap::new(), missing:None, lose_seal_ack:false }
        }
    }
    impl WorkerPeer for ReceiverPeer {
        fn send(&mut self, frame: &Value) -> io::Result<()> {
            self.sent.push(frame.clone());
            let id = frame["request_id"].clone();
            let response = match frame["kind"].as_str() {
                Some("session-ok") => return Ok(()),
                Some("source-begin") => {
                    let manifest = request_manifest(&json!({"source_manifest":frame["manifest"]}))?.unwrap();
                    let identity = hex(&manifest.digest());
                    let mut receiver = SourceReceiver::create(&self.owner.path().join("workspace"), manifest)?;
                    for (path, bytes) in &self.prefilled {
                        for (index, chunk) in bytes.chunks(MAX_SOURCE_CHUNK).enumerate() {
                            receiver.write_chunk(path, index as u64 * MAX_SOURCE_CHUNK as u64,
                                chunk, Sha256::digest(chunk).into())?;
                        }
                    }
                    self.receiver = Some(receiver);
                    let mut reply = json!({"kind":"source-ready", "request_id":id, "manifest_sha256":identity, "sealed":false});
                    if let Some(missing) = &self.missing { reply["missing_files"] = missing.clone(); }
                    reply
                }
                Some("source-chunk") => {
                    let raw = frame["data_hex"].as_str().unwrap();
                    let bytes = (0..raw.len()).step_by(2).map(|index| u8::from_str_radix(&raw[index..index + 2], 16).unwrap()).collect::<Vec<_>>();
                    let offset = self.receiver.as_mut().unwrap().write_chunk(frame["path"].as_str().unwrap(),
                        frame["offset"].as_u64().unwrap(), &bytes, digest(&frame["chunk_sha256"])? )?;
                    json!({"kind":"source-chunk-accepted", "request_id":id, "manifest_sha256":frame["manifest_sha256"],
                        "path":frame["path"], "next_offset":if self.corrupt_ack { offset + 1 } else { offset }})
                }
                Some("source-seal") => {
                    self.receiver.as_mut().unwrap().seal()?;
                    if self.lose_seal_ack { return Ok(()); }
                    json!({"kind":"source-ready", "request_id":id, "manifest_sha256":frame["manifest_sha256"], "sealed":true})
                }
                _ => return Err(invalid("source sender must not dispatch execution")),
            };
            self.replies.push_back(response);
            Ok(())
        }
        fn receive(&mut self) -> io::Result<Value> { self.replies.pop_front().ok_or_else(|| invalid("no response")) }
    }

    #[test]
    fn transmits_only_selected_captured_bytes_even_after_checkout_changes() {
        let root = tempfile::tempdir().unwrap();
        let (upload, request, bytes) = fixture(root.path());
        std::fs::write(root.path().join("src/lib.rs"), b"changed checkout").unwrap();
        let mut peer = ReceiverPeer::new();
        let hello = json!({"source_transfers":[SOURCE_TRANSFER]});
        SourcePeer::new(&mut peer, &upload, &request).unwrap().negotiate(&hello, &json!({"kind":"session-ok"})).unwrap();
        let source = peer.receiver.as_ref().unwrap().sealed_root().unwrap();
        assert_eq!(std::fs::read(source.join("src/lib.rs")).unwrap(), bytes);
        assert_eq!(std::fs::read(source.join("empty")).unwrap(), b"");
        assert!(!source.join("not-selected.private").exists());
        assert_eq!(peer.sent.iter().filter(|frame| frame["kind"] == "source-chunk").count(), 2);
        assert_eq!(peer.sent[0]["source_transfer"], SOURCE_TRANSFER);
        assert!(peer.sent.iter().all(|frame| frame["kind"] != "canonical-exec"));
        let image = Arc::new(capture_sealed_source(&[("workspace".into(), root.path().to_path_buf())], false, 2, 200_000).unwrap());
        assert!(SourceUpload::for_request(image, "workspace", &request).is_err(), "recapture must not silently change a saved request");
    }

    #[test]
    fn negotiation_and_ack_failures_stop_before_seal_or_execution() {
        let root = tempfile::tempdir().unwrap();
        let (upload, request, _) = fixture(root.path());
        let mut peer = ReceiverPeer::new();
        assert!(SourcePeer::new(&mut peer, &upload, &request).unwrap()
            .negotiate(&json!({}), &json!({"kind":"session-ok"})).is_err());
        assert!(peer.sent.is_empty());
        peer.corrupt_ack = true;
        assert!(SourcePeer::new(&mut peer, &upload, &request).unwrap()
            .negotiate(&json!({"source_transfers":[SOURCE_TRANSFER]}), &json!({"kind":"session-ok"})).is_err());
        assert!(peer.receiver.as_ref().unwrap().sealed_root().is_none());
        assert!(peer.sent.iter().all(|frame| frame["kind"] != "source-seal" && frame["kind"] != "canonical-exec"));
    }

    #[test]
    fn source_request_validation_rejects_aliases_and_changed_identity() {
        let root = tempfile::tempdir().unwrap();
        let (upload, request, _) = fixture(root.path());
        let mut mixed = request.clone(); mixed["workspace_backing"] = json!("/worker/path");
        assert!(request_manifest(&mixed).is_err());
        let mut changed = request.clone(); changed["source_manifest"]["files"][0]["path"] = json!("../escape");
        assert!(request_manifest(&changed).is_err());
        let mut changed = request.clone(); changed["source_manifest"]["manifest_sha256"] = json!("00".repeat(32));
        assert!(request_manifest(&changed).is_err());
        let mut changed = request; changed.as_object_mut().unwrap().remove("source_manifest");
        assert!(upload.validate_request(&changed).is_err());
    }

    #[test]
    fn warm_source_sends_no_chunks_but_preserves_manifest_and_final_seal() {
        let root = tempfile::tempdir().unwrap();
        let (upload, request, bytes) = fixture(root.path());
        let original = serde_json::to_vec(&request).unwrap();
        let mut peer = ReceiverPeer::new();
        peer.prefilled.insert("src/lib.rs".into(), bytes.clone());
        peer.missing = Some(json!([]));
        upload.transmit(&mut peer, &request).unwrap();
        assert_eq!(peer.sent.len(), 2);
        assert_eq!(peer.sent[0], upload.begin_frame(&request));
        assert_eq!(peer.sent[0]["allow_cached_files"], true);
        assert_eq!(peer.sent[0]["manifest"], request["source_manifest"]);
        assert_eq!(peer.sent[1]["kind"], "source-seal");
        assert_eq!(peer.sent[1]["manifest_sha256"], request["source_manifest"]["manifest_sha256"]);
        assert_eq!(serde_json::to_vec(&request).unwrap(), original);
        let source = peer.receiver.as_ref().unwrap().sealed_root().unwrap();
        assert_eq!(std::fs::read(source.join("src/lib.rs")).unwrap(), bytes);
        assert_eq!(std::fs::read(source.join("empty")).unwrap(), b"");
        assert!(!source.join("not-selected.private").exists());
    }

    #[test]
    fn mixed_source_transfers_only_missing_captured_files() {
        let root = tempfile::tempdir().unwrap();
        let (_, _, bytes) = fixture(root.path());
        std::fs::write(root.path().join("changed.rs"), b"new source").unwrap();
        let image = Arc::new(capture_sealed_source(&[("workspace".into(), root.path().to_path_buf())], false, 2, 200_000).unwrap());
        let upload = SourceUpload::from_snapshot(image, "workspace",
            &["src/lib.rs".into(), "changed.rs".into(), "empty".into()]).unwrap();
        let request = json!({"kind":"canonical-exec", "request_id":8, "program":"fixture",
            "toolchain_backing":"/tc", "source_manifest":upload.wire_manifest()});
        std::fs::write(root.path().join("changed.rs"), b"changed after capture").unwrap();
        let mut peer = ReceiverPeer::new();
        peer.prefilled.insert("src/lib.rs".into(), bytes.clone());
        peer.missing = Some(json!(["changed.rs"]));
        upload.transmit(&mut peer, &request).unwrap();
        let chunks: Vec<_> = peer.sent.iter().filter(|frame| frame["kind"] == "source-chunk").collect();
        assert_eq!(chunks.len(), 1);
        assert_eq!(chunks[0]["path"], "changed.rs");
        assert_eq!(chunks[0]["data_hex"], hex(b"new source"));
        let source = peer.receiver.as_ref().unwrap().sealed_root().unwrap();
        assert_eq!(std::fs::read(source.join("src/lib.rs")).unwrap(), bytes);
        assert_eq!(std::fs::read(source.join("changed.rs")).unwrap(), b"new source");
    }

    #[test]
    fn malformed_missing_hints_never_upload_extra_files_or_reach_seal() {
        let root = tempfile::tempdir().unwrap();
        let (upload, request, _) = fixture(root.path());
        for missing in [Value::Null, json!(true), json!([1]), json!(["not-selected.private"]),
            json!(["../escape"]), json!(["src/lib.rs", "empty"]),
            json!(["empty", "empty"]), json!(["empty", "src/lib.rs", "extra"])] {
            let mut peer = ReceiverPeer::new();
            peer.missing = Some(missing);
            assert!(upload.transmit(&mut peer, &request).is_err());
            assert_eq!(peer.sent.len(), 1);
            assert_eq!(peer.sent[0]["kind"], "source-begin");
            assert!(peer.receiver.as_ref().unwrap().sealed_root().is_none());
        }
    }

    #[test]
    fn all_cached_claim_without_bytes_or_without_seal_ack_cannot_finish_negotiation() {
        let root = tempfile::tempdir().unwrap();
        let (upload, request, bytes) = fixture(root.path());
        for lose_ack in [false, true] {
            let mut peer = ReceiverPeer::new();
            peer.missing = Some(json!([]));
            if lose_ack {
                peer.prefilled.insert("src/lib.rs".into(), bytes.clone());
                peer.lose_seal_ack = true;
            }
            let mut source = SourcePeer::new(&mut peer, &upload, &request).unwrap();
            let hello = json!({"source_transfers":[SOURCE_TRANSFER]});
            assert!(source.negotiate(&hello, &json!({"kind":"session-ok"})).is_err());
            assert!(source.negotiate(&hello, &json!({"kind":"session-ok"})).is_err());
            assert_eq!(peer.sent.len(), 3); // grant, begin, seal; never execution or retry.
            assert!(peer.sent.iter().all(|frame| frame["kind"] != "canonical-exec"));
        }
    }
}
