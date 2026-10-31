//! Real receiver/filesystem coverage. Transport and compiler result are explicit
//! fixtures; these tests do not claim native rustc or TLS qualification.

use super::*;
use rabs_protocol::metadata_prefetch::{CHUNK_BYTES as PREFETCH_CHUNK_BYTES, MAX_BYTES, VERSION};

const NAME: &str = "libdep.rmeta";

fn prefetch(bytes: &[u8], offset: usize) -> Value {
    let end = (offset + PREFETCH_CHUNK_BYTES).min(bytes.len());
    let part = &bytes[offset..end];
    json!({"kind":"metadata-prefetch", "version":VERSION, "request_id":7,
        "name":NAME, "total_bytes":bytes.len(), "sha256":hash(bytes),
        "executable":false, "offset":offset, "next_offset":end,
        "data_hex":part.iter().map(|byte| format!("{byte:02x}")).collect::<String>(),
        "chunk_sha256":hash(part), "eof":end == bytes.len(), "publication_authorized":false})
}

fn metadata_fixture(destination: &Path, bytes: &[u8]) -> (Value, Script) {
    let mut request = request();
    request["artifacts"]["files"] = json!([NAME]);
    let mut peer = fixture(destination);
    peer.replies[0]["metadata_prefetches"] = json!([VERSION]);
    let mut hasher = Sha256::new();
    field(&mut hasher, b"rabs.worker-artifact-manifest.v1");
    field(&mut hasher, b"dep");
    hasher.update(1_u64.to_be_bytes());
    field(&mut hasher, NAME.as_bytes());
    hasher.update([0]);
    hasher.update((bytes.len() as u64).to_be_bytes());
    field(&mut hasher, hash(bytes).as_bytes());
    let manifest_sha256: String = hasher
        .finalize()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    peer.replies[1]["artifact_manifest"] = json!({"unit":"dep", "files":[{
        "name":NAME, "bytes":bytes.len(), "sha256":hash(bytes), "executable":false}],
        "total_bytes":bytes.len(), "manifest_sha256":manifest_sha256});
    peer.replies.remove(4);
    for (index, part) in bytes.chunks(CHUNK_BYTES).enumerate().rev() {
        let offset = index * CHUNK_BYTES;
        let mut frame = chunk(NAME, part, true);
        frame["manifest_sha256"] = json!(manifest_sha256);
        frame["offset"] = json!(offset);
        frame["next_offset"] = json!(offset + part.len());
        frame["total_bytes"] = json!(bytes.len());
        frame["sha256"] = json!(hash(bytes));
        frame["eof"] = json!(offset + part.len() == bytes.len());
        peer.replies.insert(4, frame);
    }
    (request, peer)
}

#[test]
fn complete_prefetch_delivers_only_after_terminal_validation_without_metadata_ranges() {
    let parent = tempfile::tempdir().unwrap();
    let destination = parent.path().join("delivery");
    let bytes = vec![0x9d; PREFETCH_CHUNK_BYTES + 31];
    let (request, mut peer) = metadata_fixture(&destination, &bytes);
    peer.replies.remove(4);
    peer.replies.remove(4);
    peer.replies
        .insert(1, prefetch(&bytes, PREFETCH_CHUNK_BYTES));
    peer.replies.insert(1, prefetch(&bytes, 0));
    let mut peer = AdmissionPeer {
        inner: peer,
        reject: false,
        admitted: false,
    };
    let delivered = receive_execution(&mut peer, &request, "worker", &destination).unwrap();
    assert!(delivered.acknowledgments_confirmed);
    assert_eq!(
        std::fs::read(destination.join("artifacts").join(NAME)).unwrap(),
        bytes
    );
    assert_eq!(delivered.receipt["transport_authenticated"], true);
    assert_eq!(delivered.receipt["publication_authorized"], false);
    assert_eq!(peer.inner.sent[0]["metadata_prefetch"], VERSION);
    assert!(
        !peer
            .inner
            .sent
            .iter()
            .any(|frame| frame["kind"] == "artifact-read")
    );
    assert!(peer.inner.replies.is_empty());
}

#[test]
fn partial_changed_and_unavailable_candidates_fall_back_to_final_artifact_ranges() {
    for variant in ["partial", "changed", "unavailable"] {
        let parent = tempfile::tempdir().unwrap();
        let destination = parent.path().join("delivery");
        let bytes = vec![0x52; PREFETCH_CHUNK_BYTES + 19];
        let (request, mut peer) = metadata_fixture(&destination, &bytes);
        match variant {
            "partial" => peer.replies.insert(1, prefetch(&bytes, 0)),
            "changed" => {
                let stale = vec![0x41; bytes.len()];
                peer.replies
                    .insert(1, prefetch(&stale, PREFETCH_CHUNK_BYTES));
                peer.replies.insert(1, prefetch(&stale, 0));
            }
            _ => {}
        }
        let delivered = receive_execution(&mut peer, &request, "worker", &destination).unwrap();
        assert!(delivered.acknowledgments_confirmed, "{variant}");
        assert_eq!(
            std::fs::read(destination.join("artifacts").join(NAME)).unwrap(),
            bytes
        );
        assert_eq!(
            peer.sent
                .iter()
                .filter(|frame| frame["kind"] == "artifact-read")
                .count(),
            2
        );
        assert!(peer.replies.is_empty());
    }
}

#[test]
fn malformed_or_unnegotiated_prefetch_never_produces_a_receipt_or_ack() {
    for variant in [
        "unnegotiated",
        "request",
        "name",
        "offset",
        "length",
        "mode",
        "digest",
        "chunk",
        "eof",
        "authority",
        "version",
        "extra",
        "duplicate",
    ] {
        let parent = tempfile::tempdir().unwrap();
        let destination = parent.path().join("delivery");
        let (request, mut peer) = metadata_fixture(&destination, b"metadata");
        let mut frame = prefetch(b"metadata", 0);
        match variant {
            "unnegotiated" => {
                peer.replies[0]
                    .as_object_mut()
                    .unwrap()
                    .remove("metadata_prefetches");
            }
            "request" => frame["request_id"] = json!(8),
            "name" => frame["name"] = json!("other.rmeta"),
            "offset" => frame["offset"] = json!(1),
            "length" => frame["total_bytes"] = json!(MAX_BYTES + 1),
            "mode" => frame["executable"] = json!(true),
            "digest" => frame["sha256"] = json!(hash(b"not-metadata")),
            "chunk" => frame["chunk_sha256"] = json!(hash(b"not-metadata")),
            "eof" => frame["eof"] = json!(false),
            "authority" => frame["publication_authorized"] = json!(true),
            "version" => frame["version"] = json!("rmeta-prefetch-v2"),
            "extra" => frame["retained_result_sha256"] = json!(hash(b"bogus")),
            "duplicate" => peer.replies.insert(1, frame.clone()),
            _ => unreachable!(),
        }
        peer.replies.insert(1, frame);
        assert!(
            receive_execution(&mut peer, &request, "worker", &destination).is_err(),
            "{variant}"
        );
        assert!(no_ack(&peer), "{variant}");
        assert!(!destination.join("delivery.json").exists(), "{variant}");
        assert!(
            !destination.join("artifacts").join(NAME).exists(),
            "{variant}"
        );
    }
}

#[test]
fn complete_hint_cannot_substitute_for_a_terminal_result() {
    let parent = tempfile::tempdir().unwrap();
    let destination = parent.path().join("delivery");
    let (request, mut peer) = metadata_fixture(&destination, b"metadata");
    peer.replies.truncate(1);
    peer.replies.push_back(prefetch(b"metadata", 0));
    let failure = receive_execution(&mut peer, &request, "worker", &destination).unwrap_err();
    assert!(failure.execution_may_have_run);
    assert!(failure.sealed_result.is_none());
    assert!(no_ack(&peer));
    assert!(!destination.join("delivery.json").exists());
    assert!(!destination.join("artifacts").join(NAME).exists());
}

#[test]
fn complete_candidate_is_only_a_hint_for_exact_manifest_identity() {
    let parent = tempfile::tempdir().unwrap();
    let mut hint = super::super::metadata_prefetch::MetadataPrefetch::new(7, Some(NAME.into()));
    hint.accept(&prefetch(b"metadata", 0)).unwrap();
    for variant in ["name", "bytes", "digest", "mode"] {
        let mut item = Item {
            name: NAME.into(),
            len: 8,
            sha256: hash(b"metadata"),
            executable: false,
        };
        match variant {
            "name" => item.name = "other.rmeta".into(),
            "bytes" => item.len += 1,
            "digest" => item.sha256 = hash(b"Metadata"),
            "mode" => item.executable = true,
            _ => unreachable!(),
        }
        let mut file = create_file(&parent.path().join(variant)).unwrap();
        assert!(hint.copy(&item, &mut file, || Ok(())).unwrap().is_none());
        assert_eq!(file.metadata().unwrap().len(), 0);
    }
    let item = Item {
        name: NAME.into(),
        len: 8,
        sha256: hash(b"metadata"),
        executable: false,
    };
    let mut file = create_file(&parent.path().join("cancelled")).unwrap();
    assert_eq!(
        hint.copy(&item, &mut file, || Err(io::ErrorKind::Interrupted.into()))
            .unwrap_err()
            .kind(),
        io::ErrorKind::Interrupted
    );
    assert_eq!(file.metadata().unwrap().len(), 0);
}
