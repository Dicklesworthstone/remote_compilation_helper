//! Stream an explicitly retained compiler tree inside authenticated admission.
//! Every reply names the original request and complete dataset identity. The
//! receiver must seal all entries and bytes before execution can be dispatched.

use super::{digest, hex, invalid, require};
use crate::coord::worker_delivery::{
    WorkerPeer, toolchain_identity, toolchain_identity_value, toolchain_transfer,
};
use rabs_sandbox::toolchain_dataset::PreparedToolchain;
use rabs_sandbox::toolchain_transfer::{
    MAX_TOOLCHAIN_CHUNK, TOOLCHAIN_TRANSFER_VERSION, ToolchainEntry, ToolchainEntryKind,
};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::io;
use std::sync::Arc;

// Stay below the worker's eight deferred frames and 2 MiB aggregate bound.
// Only acknowledgment offsets are retained; at most one 64 KiB chunk is held.
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
        Ok(())
    }

    pub(super) fn transmit<P: WorkerPeer + ?Sized>(
        &self,
        peer: &mut P,
        request: &Value,
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
        require(
            reply["sealed"] == false,
            "new toolchain transfer unexpectedly sealed",
        )?;
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
            peer.send(
                &json!({"kind":"toolchain-entry", "request_id":id, "sha256":sha256,
                "path":entry.path, "entry":value}),
            )?;
            let reply = peer.receive()?;
            check(&reply, "toolchain-entry-accepted", 4)?;
            require(
                reply["path"].as_str() == Some(entry.path.as_str()),
                "toolchain acknowledgment names another entry",
            )?;
            if let ToolchainEntryKind::File { bytes, .. } = &entry.kind {
                let mut offset = 0_u64;
                let mut pending = Vec::with_capacity(CHUNK_WINDOW);
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
                    peer.send(
                        &json!({"kind":"toolchain-chunk", "request_id":id, "sha256":sha256,
                        "path":entry.path, "offset":offset, "data_hex":hex(&chunk),
                        "chunk_sha256":hex(&Sha256::digest(&chunk))}),
                    )?;
                    offset = next;
                    pending.push(next);
                    if pending.len() == CHUNK_WINDOW || offset == *bytes {
                        for expected in pending.drain(..) {
                            let reply = peer.receive()?;
                            check(&reply, "toolchain-chunk-accepted", 5)?;
                            require(
                                reply["path"].as_str() == Some(entry.path.as_str())
                                    && reply["next_offset"].as_u64() == Some(expected),
                                "toolchain acknowledgment does not cover the transmitted range",
                            )?;
                        }
                    }
                }
            }
        }
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
                    let expected =
                        toolchain_identity(&json!({"toolchain_identity":frame["identity"]}))?
                            .unwrap();
                    self.receiver = Some(ToolchainReceiver::create(
                        &self.owner.path().join("received"),
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
                Some("extra") => reply["extra"] = json!(true),
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
        upload.transmit(&mut peer, &request).unwrap();
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
    fn incorrect_or_lost_acknowledgments_never_complete_transfer() {
        let root = tempfile::tempdir().unwrap();
        let (upload, request, _) = fixture(root.path());
        for fault in ["identity", "extra", "entry", "offset", "lost-chunk", "seal"] {
            let mut peer = ReceiverPeer::new();
            peer.fault = Some(fault);
            assert!(upload.transmit(&mut peer, &request).is_err(), "{fault}");
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
        assert!(upload.transmit(&mut peer, &request).is_err());
        assert!(peer.sealed.is_none());
        assert!(
            peer.sent
                .iter()
                .all(|frame| frame["kind"] != "toolchain-seal")
        );
    }
}
