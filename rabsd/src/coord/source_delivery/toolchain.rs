//! Stream an explicitly retained compiler tree inside authenticated admission.
//! Every reply names the original request and complete dataset identity. The
//! receiver must seal all entries and bytes before execution can be dispatched.
//! Negotiated reuse permits that seal to come from a fully verified retained
//! dataset; a cache claim without the selected protocol never skips an upload.

use super::{digest, hex, invalid, require};
use crate::coord::worker_delivery::{
    WorkerPeer, toolchain_identity, toolchain_identity_value, toolchain_transfer,
};
use rabs_sandbox::toolchain_dataset::PreparedToolchain;
use rabs_sandbox::toolchain_transfer::{
    MAX_TOOLCHAIN_CHUNK, TOOLCHAIN_REUSE_VERSION, TOOLCHAIN_TRANSFER_VERSION, ToolchainEntry,
    ToolchainEntryKind,
};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::io;
use std::sync::Arc;

mod pipeline;

// Stay below the worker's eight deferred frames and 2 MiB aggregate bound.
// The shared window spans entries and chunks, including small and empty files.
// Only acknowledgment descriptors are retained, never queued payload buffers.
const CHUNK_WINDOW: usize = 4;

#[derive(Debug, Clone)]
pub(super) struct ToolchainUpload {
    prepared: Arc<PreparedToolchain>,
    entries: Arc<Vec<ToolchainEntry>>,
}

impl ToolchainUpload {
    pub(super) fn new(prepared: PreparedToolchain, request: &Value) -> io::Result<Self> {
        let entries = Arc::new(prepared.entries()?);
        let upload = Self {
            prepared: Arc::new(prepared),
            entries,
        };
        upload.validate_request(request)?;
        Ok(upload)
    }

    pub(super) fn validate_request(&self, request: &Value) -> io::Result<()> {
        require(
            toolchain_transfer(request)?,
            "retained toolchain requires explicit transfer",
        )?;
        require(
            request.get("toolchain_backing").is_none(),
            "transferred toolchain cannot fall back to a host path",
        )?;
        require(
            toolchain_identity(request)?.as_ref() == Some(self.prepared.identity()),
            "retained toolchain differs from the saved request identity",
        )?;
        require(!self.entries.is_empty(), "toolchain has no root entry")
    }

    pub(super) fn select(&self, hello: &Value, grant: &mut Value) -> io::Result<()> {
        require(
            hello["toolchain_transfers"]
                .as_array()
                .is_some_and(|versions| {
                    versions
                        .iter()
                        .any(|version| version == TOOLCHAIN_TRANSFER_VERSION)
                }),
            "worker does not support toolchain-tree-v1",
        )?;
        require(
            grant
                .get("toolchain_transfer")
                .is_none_or(|value| value == TOOLCHAIN_TRANSFER_VERSION),
            "conflicting toolchain transfer selection",
        )?;
        grant["toolchain_transfer"] = json!(TOOLCHAIN_TRANSFER_VERSION);
        let reuse = hello["toolchain_reuses"]
            .as_array()
            .is_some_and(|versions| {
                versions
                    .iter()
                    .any(|version| version == TOOLCHAIN_REUSE_VERSION)
            });
        require(
            grant
                .get("toolchain_reuse")
                .is_none_or(|value| reuse && value == TOOLCHAIN_REUSE_VERSION),
            "conflicting or unsupported toolchain reuse selection",
        )?;
        if reuse {
            grant["toolchain_reuse"] = json!(TOOLCHAIN_REUSE_VERSION);
        }
        Ok(())
    }

    pub(super) fn transmit<P: WorkerPeer + ?Sized>(
        &self,
        peer: &mut P,
        request: &Value,
        reuse_selected: bool,
    ) -> io::Result<()> {
        self.validate_request(request)?;
        let id = request["request_id"]
            .as_u64()
            .ok_or_else(|| invalid("toolchain request identity"))?;
        let identity = self.prepared.identity();
        let sha256 = hex(&identity.sha256);
        let check = |reply: &Value, kind: &str, fields: usize| -> io::Result<()> {
            require(
                reply
                    .as_object()
                    .is_some_and(|object| object.len() == fields)
                    && reply["kind"] == kind
                    && reply["request_id"].as_u64() == Some(id)
                    && digest(&reply["sha256"])? == identity.sha256,
                "toolchain acknowledgment kind, shape or identity mismatch",
            )
        };
        peer.send(&json!({"kind":"toolchain-begin", "request_id":id,
            "identity":toolchain_identity_value(identity), "entries":self.entries.len()}))?;
        let reply = peer.receive()?;
        check(&reply, "toolchain-ready", 4)?;
        match reply["sealed"].as_bool() {
            Some(true) => {
                require(reuse_selected, "toolchain reuse was not negotiated")?;
                return Ok(());
            }
            Some(false) => {}
            None => return Err(invalid("toolchain ready seal must be a boolean")),
        }
        let mut window = pipeline::UploadWindow::new(peer, id, identity.sha256);
        for entry in self.entries.iter() {
            let value = match &entry.kind {
                ToolchainEntryKind::Directory => json!({"kind":"directory"}),
                ToolchainEntryKind::Symlink { target } => {
                    json!({"kind":"symlink", "target":target})
                }
                ToolchainEntryKind::File { bytes, executable } => {
                    json!({"kind":"file", "bytes":bytes, "executable":executable})
                }
            };
            window.queue(
                &json!({"kind":"toolchain-entry", "request_id":id, "sha256":sha256,
                "path":entry.path, "entry":value}),
                pipeline::ExpectedAck::Entry { path: &entry.path },
            )?;
            if let ToolchainEntryKind::File { bytes, .. } = &entry.kind {
                let mut offset = 0_u64;
                while offset < *bytes {
                    // The retained inventory checks the opened file's identity
                    // and stamps around every bounded read. A changed sender
                    // cannot obtain the worker's final expected-digest seal.
                    let chunk = self.prepared.read_chunk(
                        &entry.path,
                        offset,
                        MAX_TOOLCHAIN_CHUNK,
                        || false,
                    )?;
                    require(!chunk.is_empty(), "retained toolchain file ended early")?;
                    let next = offset
                        .checked_add(chunk.len() as u64)
                        .filter(|next| *next <= *bytes)
                        .ok_or_else(|| {
                            invalid("retained toolchain exceeded declared file length")
                        })?;
                    window.queue(
                        &json!({"kind":"toolchain-chunk", "request_id":id, "sha256":sha256,
                        "path":entry.path, "offset":offset, "data_hex":hex(&chunk),
                        "chunk_sha256":hex(&Sha256::digest(&chunk))}),
                        pipeline::ExpectedAck::Chunk { path: &entry.path, next_offset: next },
                    )?;
                    offset = next;
                }
            }
        }
        window.finish()?;
        peer.send(&json!({"kind":"toolchain-seal", "request_id":id, "sha256":sha256}))?;
        let reply = peer.receive()?;
        check(&reply, "toolchain-ready", 4)?;
        require(
            reply["sealed"] == true,
            "worker did not seal the complete toolchain",
        )
    }
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;
    mod pipeline_tests;
    use rabs_sandbox::toolchain_dataset::{ToolchainLimits, capture_toolchain};
    use rabs_sandbox::toolchain_transfer::ToolchainReceiver;
    use std::collections::VecDeque;
    use std::fs;
    use std::os::unix::fs::{PermissionsExt, symlink};
    use std::path::Path;

    fn fixture(root: &Path) -> (ToolchainUpload, Value, Vec<u8>) {
        fs::set_permissions(root, fs::Permissions::from_mode(0o700)).unwrap();
        let original = root.join("original");
        fs::create_dir_all(original.join("bin")).unwrap();
        fs::create_dir(original.join("empty-directory")).unwrap();
        let bytes: Vec<_> = (0..MAX_TOOLCHAIN_CHUNK * 5 + 7)
            .map(|value| (value % 251) as u8)
            .collect();
        fs::write(original.join("bin/compiler"), &bytes).unwrap();
        fs::set_permissions(
            original.join("bin/compiler"),
            fs::Permissions::from_mode(0o755),
        )
        .unwrap();
        fs::write(original.join("empty-file"), []).unwrap();
        symlink("bin/compiler", original.join("rustc")).unwrap();
        let retained = capture_toolchain(
            &original,
            &root.join("retained"),
            None,
            &ToolchainLimits::default(),
            || false,
        )
        .unwrap();
        let request = json!({"kind":"canonical-exec", "request_id":0,
            "toolchain_transfer":TOOLCHAIN_TRANSFER_VERSION,
            "toolchain_identity":toolchain_identity_value(retained.identity())});
        (
            ToolchainUpload::new(retained, &request).unwrap(),
            request,
            bytes,
        )
    }

    struct ReceiverPeer {
        owner: tempfile::TempDir,
        receiver: Option<ToolchainReceiver>,
        sealed: Option<PreparedToolchain>,
        replies: VecDeque<Value>,
        sent: Vec<Value>,
        maximum_pending: usize,
        fault: Option<&'static str>,
        reuse_enabled: bool,
        stopped: bool,
    }

    impl ReceiverPeer {
        fn new() -> Self {
            let owner = tempfile::tempdir().unwrap();
            fs::set_permissions(owner.path(), fs::Permissions::from_mode(0o700)).unwrap();
            Self {
                owner,
                receiver: None,
                sealed: None,
                replies: VecDeque::new(),
                sent: Vec::new(),
                maximum_pending: 0,
                fault: None,
                reuse_enabled: false,
                stopped: false,
            }
        }
    }

    impl WorkerPeer for ReceiverPeer {
        fn send(&mut self, frame: &Value) -> io::Result<()> {
            self.sent.push(frame.clone());
            let id = &frame["request_id"];
            let identity = &frame["sha256"];
            let reply = match frame["kind"].as_str().unwrap() {
                "toolchain-begin" => {
                    require(
                        frame.as_object().unwrap().len() == 4,
                        "toolchain begin shape changed",
                    )?;
                    let expected =
                        toolchain_identity(&json!({"toolchain_identity":frame["identity"]}))?
                            .unwrap();
                    // This transport fixture is warmed by the real receiver
                    // below. A hit still rehashes the retained tree before
                    // replying; it is not a claim about worker pool execution.
                    if self.reuse_enabled
                        && let Some(cached) = &self.sealed
                        && cached.identity() == &expected
                    {
                        cached.verify(|| self.stopped)?;
                        self.replies.push_back(json!({"kind":"toolchain-ready",
                            "request_id":id, "sha256":hex(&expected.sha256), "sealed":true}));
                        return Ok(());
                    }
                    self.sealed = None;
                    self.receiver = Some(ToolchainReceiver::create(
                        &self
                            .owner
                            .path()
                            .join(format!("received-{}", self.sent.len())),
                        expected,
                        ToolchainLimits::default(),
                    )?);
                    json!({"kind":"toolchain-ready", "request_id":id, "sha256":hex(&expected.sha256), "sealed":false})
                }
                "toolchain-entry" => {
                    let entry = &frame["entry"];
                    let kind = match entry["kind"].as_str().unwrap() {
                        "directory" => ToolchainEntryKind::Directory,
                        "symlink" => ToolchainEntryKind::Symlink {
                            target: entry["target"].as_str().unwrap().to_owned(),
                        },
                        "file" => ToolchainEntryKind::File {
                            bytes: entry["bytes"].as_u64().unwrap(),
                            executable: entry["executable"].as_bool().unwrap(),
                        },
                        _ => return Err(invalid("unexpected entry kind")),
                    };
                    self.receiver.as_mut().unwrap().entry(ToolchainEntry {
                        path: frame["path"].as_str().unwrap().to_owned(),
                        kind,
                    })?;
                    json!({"kind":"toolchain-entry-accepted", "request_id":id, "sha256":identity, "path":frame["path"]})
                }
                "toolchain-chunk" => {
                    let encoded = frame["data_hex"].as_str().unwrap();
                    let bytes: Vec<_> = (0..encoded.len())
                        .step_by(2)
                        .map(|offset| u8::from_str_radix(&encoded[offset..offset + 2], 16).unwrap())
                        .collect();
                    let offset = frame["offset"].as_u64().unwrap();
                    self.receiver.as_mut().unwrap().write_chunk(
                        frame["path"].as_str().unwrap(),
                        offset,
                        &bytes,
                        digest(&frame["chunk_sha256"])?,
                    )?;
                    json!({"kind":"toolchain-chunk-accepted", "request_id":id, "sha256":identity,
                        "path":frame["path"], "next_offset":offset + bytes.len() as u64})
                }
                "toolchain-seal" => {
                    self.sealed = Some(self.receiver.as_mut().unwrap().seal(|| false)?);
                    json!({"kind":"toolchain-ready", "request_id":id, "sha256":identity, "sealed":true})
                }
                _ => return Err(invalid("sender attempted a non-toolchain operation")),
            };
            self.replies.push_back(reply);
            self.maximum_pending = self.maximum_pending.max(self.replies.len());
            Ok(())
        }

        fn receive(&mut self) -> io::Result<Value> {
            let mut reply = self
                .replies
                .pop_front()
                .ok_or_else(|| invalid("missing reply"))?;
            match self.fault {
                Some("identity") => reply["sha256"] = json!("ab".repeat(32)),
                Some("request") => reply["request_id"] = json!(999),
                Some("extra") => reply["extra"] = json!(true),
                Some("seal-type") => reply["sealed"] = json!("true"),
                Some("upper-digest") => reply["sha256"] = json!("AB".repeat(32)),
                Some("missing-digest") => {
                    reply.as_object_mut().unwrap().remove("sha256");
                }
                Some("kind") => reply["kind"] = json!("source-ready"),
                Some("lost-ready") if reply["kind"] == "toolchain-ready" => {
                    return Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "lost ready ACK",
                    ));
                }
                Some("entry") if reply["kind"] == "toolchain-entry-accepted" => {
                    reply["path"] = json!("foreign")
                }
                Some("offset") if reply["kind"] == "toolchain-chunk-accepted" => {
                    reply["next_offset"] = json!(0)
                }
                Some("lost-chunk") if reply["kind"] == "toolchain-chunk-accepted" => {
                    return Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "lost chunk ACK",
                    ));
                }
                Some("seal") if reply["sealed"] == true => reply["sealed"] = json!(false),
                _ => {}
            }
            Ok(reply)
        }
    }

    #[test]
    fn retained_tree_streams_binary_chunks_links_and_empty_entries_to_real_receiver() {
        let root = tempfile::tempdir().unwrap();
        let (upload, request, bytes) = fixture(root.path());
        fs::rename(
            root.path().join("original"),
            root.path().join("unavailable-original"),
        )
        .unwrap();
        let mut peer = ReceiverPeer::new();
        upload.transmit(&mut peer, &request, false).unwrap();
        let received = peer.sealed.as_ref().unwrap();
        received.verify(|| false).unwrap();
        assert_eq!(received.identity(), upload.prepared.identity());
        assert_eq!(fs::read(received.root().join("rustc")).unwrap(), bytes);
        assert!(received.root().join("empty-directory").is_dir());
        assert_eq!(fs::read(received.root().join("empty-file")).unwrap(), b"");
        assert_eq!(peer.maximum_pending, CHUNK_WINDOW);
        assert_eq!(peer.sent.last().unwrap()["kind"], "toolchain-seal");
        assert!(
            peer.sent
                .iter()
                .all(|frame| frame["kind"] != "canonical-exec")
        );
    }

    #[test]
    fn reuse_selection_requires_supported_transfer_and_an_advertised_version() {
        let root = tempfile::tempdir().unwrap();
        let (upload, _, _) = fixture(root.path());
        let hello = json!({"toolchain_transfers":[TOOLCHAIN_TRANSFER_VERSION]});
        for advertised in [
            None,
            Some(Value::Null),
            Some(json!([])),
            Some(json!(["toolchain-reuse-v2"])),
            Some(json!([TOOLCHAIN_REUSE_VERSION])),
        ] {
            let selected = advertised.as_ref() == Some(&json!([TOOLCHAIN_REUSE_VERSION]));
            let mut offered = hello.clone();
            if let Some(value) = advertised {
                offered["toolchain_reuses"] = value;
            }
            let mut grant = json!({"kind":"session-ok"});
            upload.select(&offered, &mut grant).unwrap();
            assert_eq!(grant["toolchain_transfer"], TOOLCHAIN_TRANSFER_VERSION);
            assert_eq!(grant.get("toolchain_reuse").is_some(), selected);
            if selected {
                assert_eq!(grant["toolchain_reuse"], TOOLCHAIN_REUSE_VERSION);
            }
            for value in [Value::Null, json!(true), json!("toolchain-reuse-v2")] {
                let mut invalid = json!({"kind":"session-ok", "toolchain_reuse":value});
                assert!(upload.select(&offered, &mut invalid).is_err());
            }
            if !selected {
                let mut unsolicited =
                    json!({"kind":"session-ok", "toolchain_reuse":TOOLCHAIN_REUSE_VERSION});
                assert!(upload.select(&offered, &mut unsolicited).is_err());
            }
        }
        let mut grant = json!({"kind":"session-ok"});
        assert!(
            upload
                .select(
                    &json!({"toolchain_reuses":[TOOLCHAIN_REUSE_VERSION]}),
                    &mut grant
                )
                .is_err()
        );
        assert!(grant.get("toolchain_reuse").is_none());
    }

    #[test]
    fn negotiated_receiver_warmth_skips_every_entry_chunk_and_seal() {
        let root = tempfile::tempdir().unwrap();
        let (upload, mut request, bytes) = fixture(root.path());
        let mut peer = ReceiverPeer::new();
        peer.reuse_enabled = true;
        // A selected miss follows the complete bounded transfer protocol.
        upload.transmit(&mut peer, &request, true).unwrap();
        assert_eq!(peer.maximum_pending, CHUNK_WINDOW);
        assert!(
            peer.sent
                .iter()
                .any(|frame| frame["kind"] == "toolchain-chunk")
        );
        assert_eq!(peer.sent.last().unwrap()["kind"], "toolchain-seal");
        let cold_end = peer.sent.len();
        request["request_id"] = json!(1);
        let original = serde_json::to_vec(&request).unwrap();
        upload.transmit(&mut peer, &request, true).unwrap();
        assert_eq!(peer.sent.len(), cold_end + 1);
        assert_eq!(
            peer.sent[cold_end],
            json!({"kind":"toolchain-begin", "request_id":1,
            "identity":request["toolchain_identity"], "entries":upload.entries.len()})
        );
        assert_eq!(serde_json::to_vec(&request).unwrap(), original);
        assert_eq!(
            fs::read(peer.sealed.as_ref().unwrap().root().join("rustc")).unwrap(),
            bytes
        );
        assert!(peer.replies.is_empty());
    }

    #[test]
    fn warm_reply_requires_negotiation_and_exact_identity_shape_and_boolean_seal() {
        let root = tempfile::tempdir().unwrap();
        let (upload, request, _) = fixture(root.path());
        let mut peer = ReceiverPeer::new();
        upload.transmit(&mut peer, &request, false).unwrap();
        peer.reuse_enabled = true;
        for fault in [
            None,
            Some("identity"),
            Some("request"),
            Some("extra"),
            Some("seal-type"),
            Some("upper-digest"),
            Some("missing-digest"),
            Some("kind"),
            Some("lost-ready"),
        ] {
            peer.fault = fault;
            let before = peer.sent.len();
            // The unfaulted warm reply is still refused without selection.
            assert!(
                upload
                    .transmit(&mut peer, &request, fault.is_some())
                    .is_err(),
                "{fault:?}"
            );
            assert_eq!(peer.sent.len(), before + 1);
            assert_eq!(peer.sent[before]["kind"], "toolchain-begin");
        }
    }

    #[test]
    fn cancelled_or_corrupted_warm_verification_never_authorizes_more_frames() {
        let root = tempfile::tempdir().unwrap();
        let (upload, request, _) = fixture(root.path());
        let mut peer = ReceiverPeer::new();
        upload.transmit(&mut peer, &request, false).unwrap();
        peer.reuse_enabled = true;
        peer.stopped = true;
        let before = peer.sent.len();
        assert_eq!(
            upload
                .transmit(&mut peer, &request, true)
                .unwrap_err()
                .kind(),
            io::ErrorKind::Interrupted
        );
        assert_eq!(peer.sent.len(), before + 1);
        assert!(peer.replies.is_empty());
        peer.stopped = false;
        let compiler = peer.sealed.as_ref().unwrap().root().join("bin/compiler");
        fs::set_permissions(&compiler, fs::Permissions::from_mode(0o755)).unwrap();
        fs::write(&compiler, b"changed cached bytes").unwrap();
        assert!(upload.transmit(&mut peer, &request, true).is_err());
        assert_eq!(peer.sent.len(), before + 2);
        assert!(peer.replies.is_empty());
    }

    #[test]
    fn incorrect_or_lost_acknowledgments_never_complete_transfer() {
        let root = tempfile::tempdir().unwrap();
        let (upload, request, _) = fixture(root.path());
        for fault in ["identity", "extra", "entry", "offset", "lost-chunk", "seal"] {
            let mut peer = ReceiverPeer::new();
            peer.fault = Some(fault);
            assert!(
                upload.transmit(&mut peer, &request, false).is_err(),
                "{fault}"
            );
            if fault != "seal" {
                assert!(peer.sealed.is_none(), "{fault}");
                assert!(
                    peer.sent
                        .iter()
                        .all(|frame| frame["kind"] != "toolchain-seal")
                );
            }
            assert!(
                peer.sent
                    .iter()
                    .all(|frame| frame["kind"] != "canonical-exec")
            );
        }
    }

    #[test]
    fn changed_retained_compiler_refuses_before_a_seal_can_authorize_execution() {
        let root = tempfile::tempdir().unwrap();
        let (upload, request, mut bytes) = fixture(root.path());
        let compiler = upload.prepared.root().join("bin/compiler");
        fs::set_permissions(&compiler, fs::Permissions::from_mode(0o755)).unwrap();
        bytes[0] ^= 0xff;
        fs::write(&compiler, bytes).unwrap();
        let mut peer = ReceiverPeer::new();
        assert!(upload.transmit(&mut peer, &request, false).is_err());
        assert!(peer.sealed.is_none());
        assert!(
            peer.sent
                .iter()
                .all(|frame| frame["kind"] != "toolchain-seal")
        );
    }
}
