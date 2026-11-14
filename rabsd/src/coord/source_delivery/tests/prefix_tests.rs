//! Sender negotiation against a real source-file receiver. The peer is a wire
//! fixture; these tests prove selected ranges, acknowledgment credit and final
//! byte identity, not TLS, compiler execution or fleet throughput.

use super::*;

struct PrefixPeer {
    inner: ReceiverPeer,
    echo: Option<Value>,
    hints: Option<Value>,
    retained: BTreeMap<String, Vec<u8>>,
    started: BTreeSet<String>,
    imported: usize,
    maximum_pending: usize,
    checkpoints: usize,
    stop_at: Option<usize>,
}

impl PrefixPeer {
    fn new(path: &str, prefix: &[u8]) -> Self {
        let mut inner = ReceiverPeer::new();
        inner.missing = Some(json!([path]));
        Self {
            inner,
            echo: Some(json!(SOURCE_PREFIX_REUSE_VERSION)),
            hints: Some(json!([{"path":path, "offset":prefix.len(),
                "sha256":hex(&Sha256::digest(prefix))}])),
            retained: [(path.to_owned(), prefix.to_vec())].into(),
            started: BTreeSet::new(),
            imported: 0,
            maximum_pending: 0,
            checkpoints: 0,
            stop_at: None,
        }
    }

    fn chunks(&self) -> Vec<&Value> {
        self.inner
            .sent
            .iter()
            .filter(|frame| frame["kind"] == "source-chunk")
            .collect()
    }

    fn network_bytes(&self) -> usize {
        self.chunks()
            .iter()
            .map(|frame| frame["data_hex"].as_str().unwrap().len() / 2)
            .sum()
    }
}

impl WorkerPeer for PrefixPeer {
    fn checkpoint(&mut self) -> io::Result<()> {
        self.checkpoints += 1;
        if self.stop_at == Some(self.checkpoints) {
            return Err(io::Error::new(
                io::ErrorKind::Interrupted,
                "fixture cancellation",
            ));
        }
        Ok(())
    }

    fn send(&mut self, frame: &Value) -> io::Result<()> {
        if frame["kind"] == "source-chunk" {
            let path = frame["path"].as_str().unwrap();
            if self.echo.as_ref() == Some(&json!(SOURCE_PREFIX_REUSE_VERSION)) {
                if self.started.insert(path.to_owned()) {
                    let resume = frame
                        .get("resume")
                        .expect("first chunk must select a prefix");
                    assert_eq!(resume.as_object().unwrap().len(), 2);
                    let offset = resume["offset"].as_u64().unwrap();
                    assert_eq!(frame["offset"].as_u64(), Some(offset));
                    let expected = digest(&resume["sha256"])?;
                    if offset == 0 {
                        assert_eq!(expected, <[u8; 32]>::from(Sha256::digest([])));
                    } else {
                        // Import only the independently retained fixture bytes
                        // selected by the sender, through the REAL receiver.
                        let retained = self.retained.get(path).expect("unknown prefix selected");
                        assert_eq!(offset, retained.len() as u64);
                        assert_eq!(expected, <[u8; 32]>::from(Sha256::digest(retained)));
                        for (index, chunk) in retained.chunks(MAX_SOURCE_CHUNK).enumerate() {
                            self.inner.receiver.as_mut().unwrap().write_chunk(
                                path,
                                index as u64 * MAX_SOURCE_CHUNK as u64,
                                chunk,
                                Sha256::digest(chunk).into(),
                            )?;
                        }
                        self.imported += retained.len();
                    }
                } else {
                    assert!(
                        frame.get("resume").is_none(),
                        "later chunks cannot reselect"
                    );
                }
            } else {
                assert!(
                    frame.get("resume").is_none(),
                    "old peers receive original frames"
                );
            }
        }
        self.inner.send(frame)?;
        if frame["kind"] == "source-begin" {
            assert_eq!(frame["source_prefix_reuse"], SOURCE_PREFIX_REUSE_VERSION);
            let reply = self.inner.replies.back_mut().unwrap();
            if let Some(echo) = &self.echo {
                reply["source_prefix_reuse"] = echo.clone();
            }
            if let Some(hints) = &self.hints {
                reply["prefixes"] = hints.clone();
            }
        }
        if frame["kind"] == "source-chunk" {
            self.maximum_pending = self.maximum_pending.max(self.inner.replies.len());
        }
        Ok(())
    }

    fn receive(&mut self) -> io::Result<Value> {
        self.inner.receive()
    }
}

fn large_fixture(root: &Path) -> (SourceUpload, Value, Vec<u8>) {
    fs::create_dir(root.join("src")).unwrap();
    let bytes: Vec<_> = (0..MAX_SOURCE_CHUNK * 9 + 119)
        .map(|index| (index % 251) as u8)
        .collect();
    fs::write(root.join("src/lib.rs"), &bytes).unwrap();
    fs::write(root.join("empty"), []).unwrap();
    let image = Arc::new(
        capture_sealed_source(
            &[("workspace".into(), root.to_path_buf())],
            false,
            2,
            1_000_000,
        )
        .unwrap(),
    );
    let upload =
        SourceUpload::from_snapshot(image, "workspace", &["src/lib.rs".into(), "empty".into()])
            .unwrap();
    let request = json!({"kind":"canonical-exec", "request_id":17, "program":"fixture",
        "toolchain_backing":"/tc", "source_manifest":upload.wire_manifest()});
    (upload, request, bytes)
}

#[test]
fn resumes_unaligned_source_prefix_and_preserves_pipeline_and_complete_seal() {
    let root = tempfile::tempdir().unwrap();
    let (upload, request, bytes) = large_fixture(root.path());
    let original_request = serde_json::to_vec(&request).unwrap();
    let offset = MAX_SOURCE_CHUNK * 2 + 13;
    let mut peer = PrefixPeer::new("src/lib.rs", &bytes[..offset]);
    fs::write(root.path().join("src/lib.rs"), b"changed mutable checkout").unwrap();
    upload.transmit(&mut peer, &request, false, false).unwrap();
    assert_eq!(peer.imported, offset);
    assert_eq!(peer.network_bytes(), bytes.len() - offset);
    assert_eq!(peer.maximum_pending, SOURCE_WINDOW);
    let chunks = peer.chunks();
    assert_eq!(chunks[0]["offset"], offset);
    assert_eq!(chunks[0]["resume"]["offset"], offset);
    assert!(
        chunks
            .iter()
            .skip(1)
            .all(|chunk| chunk.get("resume").is_none())
    );
    assert_eq!(peer.inner.sent.last().unwrap()["kind"], "source-seal");
    let received = peer.inner.receiver.as_ref().unwrap().sealed_root().unwrap();
    assert_eq!(fs::read(received.join("src/lib.rs")).unwrap(), bytes);
    assert_eq!(fs::read(received.join("empty")).unwrap(), b"");
    assert_eq!(serde_json::to_vec(&request).unwrap(), original_request);
}

#[test]
fn dependency_metadata_prefix_uses_retained_artifact_bytes() {
    let root = tempfile::tempdir().unwrap();
    let (package, mut request, source) = fixture(root.path());
    let path = "dependencies/0000/libdependency.rmeta";
    let metadata: Vec<_> = (0..MAX_SOURCE_CHUNK * 3 + 29)
        .map(|index| (index % 239) as u8)
        .collect();
    let artifact = Arc::new(RetainedDependencyArtifact::from_bytes(metadata.clone()));
    let upload = package
        .with_retained_dependency_artifacts(vec![(path.into(), artifact)])
        .unwrap();
    request["source_manifest"] = upload.wire_manifest();
    let offset = MAX_SOURCE_CHUNK + 19;
    let mut peer = PrefixPeer::new(path, &metadata[..offset]);
    peer.inner
        .prefilled
        .insert("package/src/lib.rs".into(), source);
    upload.transmit(&mut peer, &request, false, false).unwrap();
    assert_eq!(peer.network_bytes(), metadata.len() - offset);
    assert_eq!(peer.imported, offset);
    assert!(peer.chunks().iter().all(|chunk| chunk["path"] == path));
    let received = peer.inner.receiver.as_ref().unwrap().sealed_root().unwrap();
    assert_eq!(fs::read(received.join(path)).unwrap(), metadata);
}

#[test]
fn incorrect_or_unoffered_prefix_selects_explicit_zero_and_transfers_full_file() {
    let root = tempfile::tempdir().unwrap();
    let (upload, request, bytes) = fixture(root.path());
    for corrupt in [true, false] {
        let mut peer = PrefixPeer::new("src/lib.rs", &bytes[..17]);
        if corrupt {
            // The worker truthfully hashes DIFFERENT retained bytes. The
            // sender must hash its own prefix before deciding to reuse it.
            peer.retained.get_mut("src/lib.rs").unwrap()[0] ^= 1;
            peer.hints.as_mut().unwrap()[0]["sha256"] =
                json!(hex(&Sha256::digest(&peer.retained["src/lib.rs"])));
        } else {
            peer.hints = Some(json!([]));
        }
        upload.transmit(&mut peer, &request, false, false).unwrap();
        assert_eq!(peer.imported, 0);
        assert_eq!(peer.network_bytes(), bytes.len());
        assert_eq!(
            peer.chunks()[0]["resume"],
            json!({"offset":0, "sha256":hex(&Sha256::digest([]))})
        );
        let received = peer.inner.receiver.as_ref().unwrap().sealed_root().unwrap();
        assert_eq!(fs::read(received.join("src/lib.rs")).unwrap(), bytes);
    }
}

#[test]
fn legacy_peer_ignores_offer_and_receives_original_full_upload() {
    let root = tempfile::tempdir().unwrap();
    let (upload, request, bytes) = fixture(root.path());
    let mut peer = PrefixPeer::new("src/lib.rs", &bytes[..17]);
    peer.echo = None;
    peer.hints = None;
    peer.inner.missing = None;
    upload.transmit(&mut peer, &request, false, false).unwrap();
    assert_eq!(peer.imported, 0);
    assert_eq!(peer.network_bytes(), bytes.len());
    assert!(
        peer.chunks()
            .iter()
            .all(|chunk| chunk.get("resume").is_none())
    );
    assert_eq!(peer.inner.sent.last().unwrap()["kind"], "source-seal");
}

#[test]
fn negotiated_whole_file_hits_still_require_final_source_seal() {
    let root = tempfile::tempdir().unwrap();
    let (upload, request, bytes) = fixture(root.path());
    let mut peer = PrefixPeer::new("src/lib.rs", &bytes[..17]);
    peer.inner
        .prefilled
        .insert("src/lib.rs".into(), bytes.clone());
    peer.inner.missing = Some(json!([]));
    peer.hints = Some(json!([]));
    upload.transmit(&mut peer, &request, false, false).unwrap();
    assert_eq!(peer.network_bytes(), 0);
    assert_eq!(peer.inner.sent.len(), 2);
    assert_eq!(peer.inner.sent[1]["kind"], "source-seal");
    assert!(
        peer.inner
            .receiver
            .as_ref()
            .unwrap()
            .sealed_root()
            .is_some()
    );
}

#[test]
fn invalid_negotiation_and_prefix_hints_never_send_payload_or_seal() {
    let root = tempfile::tempdir().unwrap();
    let (upload, request, bytes) = fixture(root.path());
    let good =
        json!({"path":"src/lib.rs", "offset":17, "sha256":hex(&Sha256::digest(&bytes[..17]))});
    let mut cases = vec![
        (
            None,
            Some(json!([good.clone()])),
            Some(json!(["src/lib.rs"])),
        ),
        (
            Some(json!("unknown-version")),
            Some(json!([])),
            Some(json!(["src/lib.rs"])),
        ),
        (
            Some(Value::Null),
            Some(json!([])),
            Some(json!(["src/lib.rs"])),
        ),
        (
            Some(json!(SOURCE_PREFIX_REUSE_VERSION)),
            None,
            Some(json!(["src/lib.rs"])),
        ),
        (
            Some(json!(SOURCE_PREFIX_REUSE_VERSION)),
            Some(Value::Null),
            Some(json!(["src/lib.rs"])),
        ),
        (
            Some(json!(SOURCE_PREFIX_REUSE_VERSION)),
            Some(json!([])),
            None,
        ),
        // A cached whole-file hit cannot also be offered as a missing prefix.
        (
            Some(json!(SOURCE_PREFIX_REUSE_VERSION)),
            Some(json!([good.clone()])),
            Some(json!([])),
        ),
        (
            Some(json!(SOURCE_PREFIX_REUSE_VERSION)),
            Some(json!([good.clone(), good.clone()])),
            Some(json!(["empty", "src/lib.rs"])),
        ),
    ];
    for (field, value) in [
        ("path", json!("not-selected.private")),
        ("path", json!("../outside")),
        ("path", json!("empty")),
        ("path", json!(7)),
        ("offset", json!(0)),
        ("offset", json!(-1)),
        ("offset", json!(1.5)),
        ("offset", json!(bytes.len())),
        ("offset", json!(bytes.len() + 1)),
        ("sha256", json!("00")),
        ("sha256", json!("Z".repeat(64))),
        ("unexpected", json!(true)),
    ] {
        let mut hint = good.clone();
        hint[field] = value;
        cases.push((
            Some(json!(SOURCE_PREFIX_REUSE_VERSION)),
            Some(json!([hint])),
            Some(json!(["empty", "src/lib.rs"])),
        ));
    }
    for (echo, hints, missing) in cases {
        let mut peer = PrefixPeer::new("src/lib.rs", &bytes[..17]);
        peer.echo = echo;
        peer.hints = hints;
        peer.inner.missing = missing;
        assert!(upload.transmit(&mut peer, &request, false, false).is_err());
        assert_eq!(peer.inner.sent.len(), 1);
        assert_eq!(peer.inner.sent[0]["kind"], "source-begin");
        assert!(
            peer.inner
                .receiver
                .as_ref()
                .unwrap()
                .sealed_root()
                .is_none()
        );
    }
}

#[test]
fn sorted_prefix_inventory_and_serialized_byte_budget_are_required() {
    let root = tempfile::tempdir().unwrap();
    let (mut upload, _, _) = fixture(root.path());
    // This unit-level inventory exercise deliberately does not transmit: only
    // the manifest-bound hint parser is under test, with a large legal file set.
    let files: Vec<_> = (0..300)
        .map(|index| SourceFile {
            path: format!("{}/{index:04}", "d".repeat(900)),
            len: 2,
            sha256: Sha256::digest(b"xy").into(),
            executable: false,
        })
        .collect();
    upload.manifest = SourceManifest::new(files.clone()).unwrap();
    let missing = files
        .iter()
        .map(|file| file.path.clone())
        .collect::<BTreeSet<_>>();
    let hints: Vec<_> = files
        .iter()
        .map(|file| json!({"path":file.path, "offset":1, "sha256":hex(&Sha256::digest(b"x"))}))
        .collect();
    let reply = json!({"source_prefix_reuse":SOURCE_PREFIX_REUSE_VERSION, "prefixes":hints});
    assert!(serde_json::to_vec(&reply["prefixes"]).unwrap().len() > MAX_SOURCE_PREFIX_HINT_BYTES);
    let error = upload
        .source_prefixes(&reply, Some(&missing))
        .err()
        .unwrap();
    assert!(error.to_string().contains("byte bound"));
    let reversed =
        json!({"source_prefix_reuse":SOURCE_PREFIX_REUSE_VERSION, "prefixes":[hints[1],hints[0]]});
    let error = upload
        .source_prefixes(&reversed, Some(&missing))
        .err()
        .unwrap();
    assert!(error.to_string().contains("sorted"));
}

#[test]
fn bad_resumed_tail_ack_retains_debt_and_never_reaches_seal() {
    let root = tempfile::tempdir().unwrap();
    let (upload, request, bytes) = large_fixture(root.path());
    let mut peer = PrefixPeer::new("src/lib.rs", &bytes[..MAX_SOURCE_CHUNK + 13]);
    peer.inner.corrupt_ack = true;
    assert!(upload.transmit(&mut peer, &request, false, false).is_err());
    assert_eq!(peer.chunks().len(), SOURCE_WINDOW);
    assert_eq!(peer.maximum_pending, SOURCE_WINDOW);
    assert!(
        peer.inner
            .sent
            .iter()
            .all(|frame| frame["kind"] != "source-seal" && frame["kind"] != "canonical-exec")
    );
    assert!(
        peer.inner
            .receiver
            .as_ref()
            .unwrap()
            .sealed_root()
            .is_none()
    );
}

#[test]
fn cancellation_during_retained_prefix_hashing_sends_no_tail() {
    let root = tempfile::tempdir().unwrap();
    let (upload, request, bytes) = large_fixture(root.path());
    let mut peer = PrefixPeer::new("src/lib.rs", &bytes[..MAX_SOURCE_CHUNK * 4 + 13]);
    peer.stop_at = Some(2);
    let error = upload
        .transmit(&mut peer, &request, false, false)
        .unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::Interrupted);
    assert_eq!(peer.checkpoints, 2);
    assert_eq!(peer.inner.sent.len(), 1);
    assert!(
        peer.inner
            .receiver
            .as_ref()
            .unwrap()
            .sealed_root()
            .is_none()
    );
}
