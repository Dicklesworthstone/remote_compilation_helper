//! Real retained SDK sender and filesystem receiver, with explicit transport
//! observations. These establish protocol/byte-reuse behavior, not a speed claim.

use super::*;
use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::path::PathBuf;

fn retained_root() -> PathBuf {
    tempfile::Builder::new()
        .prefix("rabs-toolchain-prefix-")
        .permissions(fs::Permissions::from_mode(0o700))
        .tempdir()
        .unwrap()
        .keep()
}

struct PrefixPeer {
    root: PathBuf,
    receiver: Option<ToolchainReceiver>,
    sealed: Option<PreparedToolchain>,
    expected: Option<ToolchainIdentity>,
    manifest: BTreeMap<String, ToolchainFile>,
    replies: VecDeque<Value>,
    sent: Vec<Value>,
    prefix_file: File,
    prefix_length: u64,
    prefix_sha256: [u8; 32],
    prefix_selected: bool,
    full_file_hit: bool,
    imported_bytes: u64,
    maximum_pending: usize,
    fault: Option<&'static str>,
    valid_payload_acks: usize,
    sent_at_bad_ack: Option<usize>,
    hashing_prefix: bool,
    prefix_checkpoints: usize,
    stop_at_prefix_checkpoint: Option<usize>,
}

impl PrefixPeer {
    fn new(bytes: &[u8], prefix_length: usize) -> Self {
        let root = retained_root();
        let mut prefix_file = OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(root.join("retained-prefix"))
            .unwrap();
        prefix_file.write_all(&bytes[..prefix_length]).unwrap();
        Self {
            root,
            receiver: None,
            sealed: None,
            expected: None,
            manifest: BTreeMap::new(),
            replies: VecDeque::new(),
            sent: Vec::new(),
            prefix_file,
            prefix_length: prefix_length as u64,
            prefix_sha256: Sha256::digest(&bytes[..prefix_length]).into(),
            prefix_selected: true,
            full_file_hit: false,
            imported_bytes: 0,
            maximum_pending: 0,
            fault: None,
            valid_payload_acks: 0,
            sent_at_bad_ack: None,
            hashing_prefix: false,
            prefix_checkpoints: 0,
            stop_at_prefix_checkpoint: None,
        }
    }

    fn payload_count(&self) -> usize {
        self.sent
            .iter()
            .filter(|frame| {
                matches!(
                    frame["kind"].as_str(),
                    Some("toolchain-entry" | "toolchain-chunk")
                )
            })
            .count()
    }

    fn network_bytes(&self) -> usize {
        self.sent
            .iter()
            .filter(|frame| frame["kind"] == "toolchain-chunk")
            .map(|frame| frame["data_hex"].as_str().unwrap().len() / 2)
            .sum()
    }

    fn import_prefix(&mut self, path: &str, length: u64, expected: [u8; 32]) -> io::Result<()> {
        require(
            length <= self.prefix_file.metadata()?.len(),
            "fixture prefix length exceeds retained file",
        )?;
        self.prefix_file.seek(SeekFrom::Start(0))?;
        let mut hash = Sha256::new();
        let mut offset = 0;
        while offset < length {
            let mut bytes = vec![0; (length - offset).min(MAX_TOOLCHAIN_CHUNK as u64) as usize];
            self.prefix_file.read_exact(&mut bytes)?;
            hash.update(&bytes);
            self.receiver.as_mut().unwrap().write_chunk(
                path,
                offset,
                &bytes,
                Sha256::digest(&bytes).into(),
            )?;
            offset += bytes.len() as u64;
        }
        require(
            <[u8; 32]>::from(hash.finalize()) == expected,
            "fixture prefix digest differs from selected prefix",
        )?;
        self.imported_bytes += length;
        Ok(())
    }
}

impl WorkerPeer for PrefixPeer {
    fn send(&mut self, frame: &Value) -> io::Result<()> {
        self.sent.push(frame.clone());
        let id = &frame["request_id"];
        let identity = &frame["sha256"];
        let reply = match frame["kind"].as_str().unwrap() {
            "toolchain-begin" => {
                let expected =
                    toolchain_identity(&json!({"toolchain_identity":frame["identity"]}))?.unwrap();
                self.expected = Some(expected);
                self.receiver = Some(ToolchainReceiver::create(
                    &self.root.join("received"),
                    expected,
                    ToolchainLimits::default(),
                )?);
                json!({"kind":"toolchain-ready", "request_id":id, "sha256":hex(&expected.sha256), "sealed":false})
            }
            "toolchain-file-manifest" => {
                require(
                    frame["offset"].as_u64() == Some(self.manifest.len() as u64),
                    "manifest page offset differs",
                )?;
                let mut missing = Vec::new();
                let mut prefixes = Vec::new();
                for file in frame["files"].as_array().unwrap() {
                    let file = ToolchainFile {
                        path: file["path"].as_str().unwrap().into(),
                        bytes: file["bytes"].as_u64().unwrap(),
                        executable: file["executable"].as_bool().unwrap(),
                        sha256: digest(&file["sha256"])?,
                    };
                    let hit = self.full_file_hit && file.path == "bin/compiler";
                    if !hit {
                        missing.push(file.path.clone());
                        if self.prefix_selected
                            && file.path == "bin/compiler"
                            && self.prefix_length > 0
                        {
                            prefixes.push(json!({"path":file.path, "offset":self.prefix_length, "sha256":hex(&self.prefix_sha256)}));
                        }
                    }
                    self.manifest.insert(file.path.clone(), file);
                }
                let mut reply = json!({"kind":"toolchain-file-manifest-accepted", "request_id":id, "sha256":identity,
                    "next_offset":self.manifest.len(), "missing":missing});
                if self.prefix_selected {
                    reply["prefixes"] = json!(prefixes);
                }
                reply
            }
            "toolchain-file-manifest-seal" => {
                self.hashing_prefix = false;
                let expected = self.expected.unwrap();
                require(
                    self.manifest.len() as u64 == expected.files
                        && self.manifest.values().map(|file| file.bytes).sum::<u64>()
                            == expected.bytes,
                    "fixture manifest totals differ",
                )?;
                json!({"kind":"toolchain-file-manifest-ready", "request_id":id, "sha256":identity, "files":expected.files, "bytes":expected.bytes})
            }
            "toolchain-entry" => {
                let path = frame["path"].as_str().unwrap();
                let kind = match frame["entry"]["kind"].as_str().unwrap() {
                    "directory" => ToolchainEntryKind::Directory,
                    "symlink" => ToolchainEntryKind::Symlink {
                        target: frame["entry"]["target"].as_str().unwrap().into(),
                    },
                    "file" => ToolchainEntryKind::File {
                        bytes: frame["entry"]["bytes"].as_u64().unwrap(),
                        executable: frame["entry"]["executable"].as_bool().unwrap(),
                    },
                    _ => return Err(invalid("unexpected fixture entry")),
                };
                let regular_file = matches!(kind, ToolchainEntryKind::File { .. });
                self.receiver.as_mut().unwrap().entry(ToolchainEntry {
                    path: path.into(),
                    kind,
                })?;
                let mut reply = json!({"kind":"toolchain-entry-accepted", "request_id":id, "sha256":identity, "path":path});
                if self.prefix_selected && regular_file {
                    let resume = frame["resume"]
                        .as_object()
                        .ok_or_else(|| invalid("selected file lacks resume identity"))?;
                    require(
                        resume.len() == 2
                            && resume.contains_key("offset")
                            && resume.contains_key("sha256"),
                        "resume identity shape changed",
                    )?;
                    let offset = frame["resume"]["offset"]
                        .as_u64()
                        .ok_or_else(|| invalid("resume offset is not numeric"))?;
                    let expected = digest(&frame["resume"]["sha256"])?;
                    if offset > 0 {
                        require(
                            path == "bin/compiler",
                            "fixture has no retained bytes for this file",
                        )?;
                        self.import_prefix(path, offset, expected)?;
                    } else {
                        require(
                            expected == <[u8; 32]>::from(Sha256::digest([])),
                            "cold entry must bind empty bytes",
                        )?;
                    }
                    reply["next_offset"] = json!(offset);
                } else {
                    require(
                        frame.get("resume").is_none(),
                        "unselected or non-file entry gained resume metadata",
                    )?;
                }
                reply
            }
            "toolchain-chunk" => {
                let encoded = frame["data_hex"].as_str().unwrap();
                let bytes: Vec<_> = (0..encoded.len())
                    .step_by(2)
                    .map(|offset| u8::from_str_radix(&encoded[offset..offset + 2], 16).unwrap())
                    .collect();
                let path = frame["path"].as_str().unwrap();
                let offset = frame["offset"].as_u64().unwrap();
                self.receiver.as_mut().unwrap().write_chunk(
                    path,
                    offset,
                    &bytes,
                    digest(&frame["chunk_sha256"])?,
                )?;
                json!({"kind":"toolchain-chunk-accepted", "request_id":id, "sha256":identity, "path":path, "next_offset":offset + bytes.len() as u64})
            }
            "toolchain-seal" => {
                require(
                    self.replies.is_empty(),
                    "seal overtook unacknowledged prefix controls",
                )?;
                self.sealed = Some(self.receiver.as_mut().unwrap().seal(|| false)?);
                json!({"kind":"toolchain-ready", "request_id":id, "sha256":identity, "sealed":true})
            }
            _ => return Err(invalid("unexpected toolchain control")),
        };
        self.replies.push_back(reply);
        self.maximum_pending = self.maximum_pending.max(self.replies.len());
        Ok(())
    }

    fn receive(&mut self) -> io::Result<Value> {
        let mut reply = self
            .replies
            .pop_front()
            .ok_or_else(|| invalid("missing fixture reply"))?;
        if reply["kind"] == "toolchain-file-manifest-accepted" {
            self.hashing_prefix = true;
            match self.fault {
                Some("corrupt-hash") => reply["prefixes"][0]["sha256"] = json!("ab".repeat(32)),
                Some("foreign") => reply["prefixes"][0]["path"] = json!("foreign-file"),
                Some("duplicate") => {
                    let prefix = reply["prefixes"][0].clone();
                    reply["prefixes"] = json!([prefix, prefix]);
                }
                Some("full-length") => {
                    reply["prefixes"][0]["offset"] = json!(self.manifest["bin/compiler"].bytes)
                }
                Some("zero") => reply["prefixes"][0]["offset"] = json!(0),
                Some("float") => reply["prefixes"][0]["offset"] = json!(1.5),
                Some("hash-shape") => reply["prefixes"][0]["sha256"] = json!("not-a-digest"),
                Some("extra") => reply["prefixes"][0]["authority"] = json!(true),
                Some("not-missing") => reply["missing"] = json!(["empty-file"]),
                Some("absent-prefixes") => {
                    reply.as_object_mut().unwrap().remove("prefixes");
                }
                Some("unsolicited") => reply["prefixes"] = json!([]),
                _ => {}
            }
        }
        let payload = matches!(
            reply["kind"].as_str(),
            Some("toolchain-entry-accepted" | "toolchain-chunk-accepted")
        );
        if reply["kind"] == "toolchain-entry-accepted"
            && reply["path"] == "bin/compiler"
            && self.fault.is_some_and(|fault| fault.starts_with("ack-"))
        {
            self.sent_at_bad_ack = Some(self.payload_count());
            match self.fault {
                Some("ack-wrong-offset") => reply["next_offset"] = json!(self.prefix_length + 1),
                Some("ack-legacy") => {
                    reply.as_object_mut().unwrap().remove("next_offset");
                }
                Some("ack-null") => reply["next_offset"] = Value::Null,
                Some("ack-foreign") => reply["path"] = json!("foreign-file"),
                Some("ack-missing") => {
                    return Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "lost resumed-entry ACK",
                    ));
                }
                _ => unreachable!(),
            }
        } else if payload {
            self.valid_payload_acks += 1;
        }
        Ok(reply)
    }

    fn checkpoint(&mut self) -> io::Result<()> {
        if self.hashing_prefix {
            self.prefix_checkpoints += 1;
            if self.stop_at_prefix_checkpoint == Some(self.prefix_checkpoints) {
                return Err(io::Error::new(
                    io::ErrorKind::Interrupted,
                    "cancelled while hashing retained SDK prefix",
                ));
            }
        }
        Ok(())
    }
}

#[test]
fn verified_prefix_sends_only_the_tail_and_seals_the_exact_sdk() {
    let root = retained_root();
    let (upload, request, bytes) = fixture(&root);
    let prefix = MAX_TOOLCHAIN_CHUNK * 2 + 17;
    let mut peer = PrefixPeer::new(&bytes, prefix);
    upload
        .transmit_with_prefix(&mut peer, &request, false, true, true)
        .unwrap();
    assert_eq!(peer.imported_bytes, prefix as u64);
    assert_eq!(peer.network_bytes(), bytes.len() - prefix);
    let chunks: Vec<_> = peer
        .sent
        .iter()
        .filter(|frame| frame["kind"] == "toolchain-chunk")
        .collect();
    assert_eq!(chunks[0]["offset"], prefix);
    assert!(
        chunks
            .iter()
            .all(|frame| frame["offset"].as_u64().unwrap() >= prefix as u64)
    );
    for frame in peer
        .sent
        .iter()
        .filter(|frame| frame["kind"] == "toolchain-entry")
    {
        if frame["entry"]["kind"] == "file" {
            assert!(frame["resume"].is_object());
        } else {
            assert!(frame.get("resume").is_none());
        }
    }
    assert_eq!(peer.maximum_pending, CHUNK_WINDOW);
    assert!(peer.replies.is_empty());
    let received = peer.sealed.as_ref().unwrap();
    received.verify(|| false).unwrap();
    assert_eq!(received.identity(), upload.prepared.identity());
    assert_eq!(
        received.entries().unwrap(),
        upload.prepared.entries().unwrap()
    );
    assert_eq!(
        fs::read(received.root().join("bin/compiler")).unwrap(),
        bytes
    );
    assert_eq!(fs::read(received.root().join("rustc")).unwrap(), bytes);
    assert_eq!(fs::read(received.root().join("empty-file")).unwrap(), b"");
    assert!(received.root().join("empty-directory").is_dir());
}

#[test]
fn corrupt_prefix_claim_selects_zero_and_uploads_every_byte() {
    let root = retained_root();
    let (upload, request, bytes) = fixture(&root);
    let mut peer = PrefixPeer::new(&bytes, MAX_TOOLCHAIN_CHUNK + 7);
    peer.fault = Some("corrupt-hash");
    upload
        .transmit_with_prefix(&mut peer, &request, false, true, true)
        .unwrap();
    assert_eq!(peer.imported_bytes, 0);
    assert_eq!(peer.network_bytes(), bytes.len());
    let entry = peer
        .sent
        .iter()
        .find(|frame| frame["kind"] == "toolchain-entry" && frame["path"] == "bin/compiler")
        .unwrap();
    assert_eq!(
        entry["resume"],
        json!({"offset":0,"sha256":hex(&Sha256::digest([]))})
    );
    let first = peer
        .sent
        .iter()
        .find(|frame| frame["kind"] == "toolchain-chunk")
        .unwrap();
    assert_eq!(first["offset"], 0);
    let received = peer.sealed.as_ref().unwrap();
    assert_eq!(received.identity(), upload.prepared.identity());
    assert_eq!(
        fs::read(received.root().join("bin/compiler")).unwrap(),
        bytes
    );
}

#[test]
fn full_file_hits_still_bind_the_entry_offset_and_complete_dataset() {
    let root = retained_root();
    let (upload, request, bytes) = fixture(&root);
    let mut peer = PrefixPeer::new(&bytes, bytes.len());
    peer.full_file_hit = true;
    upload
        .transmit_with_prefix(&mut peer, &request, false, true, true)
        .unwrap();
    assert_eq!(peer.network_bytes(), 0);
    assert_eq!(peer.imported_bytes, bytes.len() as u64);
    let entry = peer
        .sent
        .iter()
        .find(|frame| frame["kind"] == "toolchain-entry" && frame["path"] == "bin/compiler")
        .unwrap();
    assert_eq!(entry["resume"]["offset"], bytes.len());
    assert_eq!(entry["resume"]["sha256"], hex(&Sha256::digest(&bytes)));
    assert_eq!(
        peer.sealed.as_ref().unwrap().identity(),
        upload.prepared.identity()
    );
}

#[test]
fn malformed_foreign_duplicate_and_full_length_hints_stop_before_any_tree_entry() {
    let root = retained_root();
    let (upload, request, bytes) = fixture(&root);
    for fault in [
        "foreign",
        "duplicate",
        "full-length",
        "zero",
        "float",
        "hash-shape",
        "extra",
        "not-missing",
        "absent-prefixes",
    ] {
        let mut peer = PrefixPeer::new(&bytes, MAX_TOOLCHAIN_CHUNK + 7);
        peer.fault = Some(fault);
        assert!(
            upload
                .transmit_with_prefix(&mut peer, &request, false, true, true)
                .is_err(),
            "{fault}"
        );
        assert_eq!(peer.payload_count(), 0, "{fault}");
        assert!(peer.sealed.is_none(), "{fault}");
        assert!(
            !peer
                .sent
                .iter()
                .any(|frame| frame["kind"] == "toolchain-file-manifest-seal"),
            "{fault}"
        );
    }
}

#[test]
fn incorrect_lost_or_legacy_entry_ack_never_releases_upload_credit() {
    let root = retained_root();
    let (upload, request, bytes) = fixture(&root);
    for fault in [
        "ack-wrong-offset",
        "ack-legacy",
        "ack-null",
        "ack-foreign",
        "ack-missing",
    ] {
        let mut peer = PrefixPeer::new(&bytes, MAX_TOOLCHAIN_CHUNK + 7);
        peer.fault = Some(fault);
        assert!(
            upload
                .transmit_with_prefix(&mut peer, &request, false, true, true)
                .is_err(),
            "{fault}"
        );
        assert_eq!(
            peer.payload_count(),
            peer.sent_at_bad_ack.unwrap(),
            "no later control after {fault}"
        );
        assert_eq!(
            peer.payload_count(),
            CHUNK_WINDOW + peer.valid_payload_acks,
            "only valid older ACKs release credit: {fault}"
        );
        assert!(peer.sealed.is_none(), "{fault}");
        assert!(
            !peer
                .sent
                .iter()
                .any(|frame| frame["kind"] == "toolchain-seal"),
            "{fault}"
        );
    }
}

#[test]
fn cancellation_is_observed_between_bounded_prefix_reads() {
    let root = retained_root();
    let (upload, request, bytes) = fixture(&root);
    let mut peer = PrefixPeer::new(&bytes, MAX_TOOLCHAIN_CHUNK * 3 + 7);
    peer.stop_at_prefix_checkpoint = Some(2);
    let error = upload
        .transmit_with_prefix(&mut peer, &request, false, true, true)
        .unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::Interrupted);
    assert_eq!(peer.prefix_checkpoints, 2);
    assert_eq!(peer.payload_count(), 0);
    assert_eq!(peer.network_bytes(), 0);
    assert!(peer.sealed.is_none());
    assert!(
        !peer
            .sent
            .iter()
            .any(|frame| frame["kind"] == "toolchain-file-manifest-seal")
    );
}

#[test]
fn prefix_capability_is_explicit_and_requires_file_reuse() {
    let root = retained_root();
    let (upload, request, bytes) = fixture(&root);
    let cold = json!({"toolchain_transfers":[TOOLCHAIN_TRANSFER_VERSION]});
    let mut grant = json!({});
    upload.select(&cold, &mut grant).unwrap();
    assert!(grant.get("toolchain_prefix_reuse").is_none());
    let prefix_without_files = json!({"toolchain_transfers":[TOOLCHAIN_TRANSFER_VERSION], "toolchain_prefix_reuses":[TOOLCHAIN_PREFIX_REUSE_VERSION]});
    let mut grant = json!({});
    upload.select(&prefix_without_files, &mut grant).unwrap();
    assert!(grant.get("toolchain_prefix_reuse").is_none());
    let capable = json!({"toolchain_transfers":[TOOLCHAIN_TRANSFER_VERSION], "toolchain_file_reuses":[TOOLCHAIN_FILE_REUSE_VERSION], "toolchain_prefix_reuses":[TOOLCHAIN_PREFIX_REUSE_VERSION]});
    let mut grant = json!({});
    upload.select(&capable, &mut grant).unwrap();
    assert_eq!(
        grant["toolchain_prefix_reuse"],
        TOOLCHAIN_PREFIX_REUSE_VERSION
    );
    for hello in [&cold, &prefix_without_files] {
        let mut unsolicited = json!({"toolchain_prefix_reuse":TOOLCHAIN_PREFIX_REUSE_VERSION});
        assert!(upload.select(hello, &mut unsolicited).is_err());
    }
    let mut peer = PrefixPeer::new(&bytes, 7);
    assert!(
        upload
            .transmit_with_prefix(&mut peer, &request, false, false, true)
            .is_err()
    );
    assert!(peer.sent.is_empty());
}

#[test]
fn legacy_file_reuse_keeps_its_original_frames_and_rejects_unsolicited_prefixes() {
    let root = retained_root();
    let (upload, request, bytes) = fixture(&root);
    let mut peer = PrefixPeer::new(&bytes, 7);
    peer.prefix_selected = false;
    upload.transmit(&mut peer, &request, false, true).unwrap();
    assert_eq!(peer.network_bytes(), bytes.len());
    assert_eq!(peer.imported_bytes, 0);
    assert!(peer.sent.iter().all(|frame| frame.get("resume").is_none()));
    assert_eq!(
        peer.sealed.as_ref().unwrap().identity(),
        upload.prepared.identity()
    );
    let mut unsolicited = PrefixPeer::new(&bytes, 7);
    unsolicited.prefix_selected = false;
    unsolicited.fault = Some("unsolicited");
    assert!(
        upload
            .transmit(&mut unsolicited, &request, false, true)
            .is_err()
    );
    assert_eq!(unsolicited.payload_count(), 0);
}
