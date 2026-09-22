//! Complete-tree acceptance through the production delivery, recovery and CAS
//! paths. The peer is scripted: these tests prove receiver behavior, not that a
//! worker or Cargo executed. Real worker compilation is exercised separately.

use super::*;
use crate::coord::delivery_archive::{archive_delivery, restore_delivery};
use crate::coord::delivery_recovery::{DeliveryTrust, recover_existing_delivery};
use std::collections::BTreeMap;
use std::fs;

fn tree_request() -> Value {
    let mut request = request();
    request["artifacts"]["tree"] = json!(TREE_FILES_VERSION);
    request
}

fn refresh_manifest(manifest: &mut Value) {
    let rows = manifest["files"].as_array().unwrap();
    let mut hasher = Sha256::new();
    field(&mut hasher, b"rabs.worker-artifact-manifest.v1");
    field(&mut hasher, manifest["unit"].as_str().unwrap().as_bytes());
    hasher.update((rows.len() as u64).to_be_bytes());
    let mut total = 0_u64;
    for row in rows {
        field(&mut hasher, row["name"].as_str().unwrap().as_bytes());
        hasher.update([u8::from(row["executable"].as_bool().unwrap())]);
        let bytes = row["bytes"].as_u64().unwrap();
        hasher.update(bytes.to_be_bytes());
        field(&mut hasher, row["sha256"].as_str().unwrap().as_bytes());
        total = total.checked_add(bytes).unwrap();
    }
    manifest["total_bytes"] = json!(total);
    manifest["manifest_sha256"] = json!(hasher.finalize().iter().map(|byte| format!("{byte:02x}")).collect::<String>());
}

fn tree_fixture(destination: &Path, count: usize) -> (Script, BTreeMap<String, Vec<u8>>) {
    assert!(count > 0);
    let mut bytes = BTreeMap::from([("a".to_owned(), b"A\0\xffB".to_vec())]);
    for index in 1..count {
        bytes.insert(format!("deps/f{index:04}"), format!("payload-{index}").into_bytes());
    }
    let mut manifest = json!({"unit":"dep", "files":bytes.iter().map(|(name, bytes)| {
        json!({"name":name, "bytes":bytes.len(), "sha256":hash(bytes), "executable":name == "a"})
    }).collect::<Vec<_>>()});
    refresh_manifest(&mut manifest);
    let mut peer = fixture(destination);
    let mut replies: VecDeque<_> = peer.replies.iter().take(4).cloned().collect();
    replies[1]["artifact_manifest"] = manifest.clone();
    for (name, bytes) in &bytes {
        let mut reply = chunk(name, bytes, true);
        reply["manifest_sha256"] = manifest["manifest_sha256"].clone();
        reply["executable"] = json!(name == "a");
        replies.push_back(reply);
    }
    replies.push_back(peer.replies[5].clone());
    replies.push_back(peer.replies[6].clone());
    peer.replies = replies;
    (peer, bytes)
}

#[test]
fn tree_delivery_verifies_every_file_before_ack_and_preserves_exact_request() {
    for lose_ack in [false, true] {
        let owner = tempfile::tempdir().unwrap();
        let destination = owner.path().join("delivery");
        let request = tree_request();
        let original = serde_json::to_vec(&request).unwrap();
        let (mut peer, expected) = tree_fixture(&destination, 130);
        if lose_ack { peer.fail_send = Some("artifact-ack"); }
        let delivered = receive_execution(&mut peer, &request, "worker", &destination).unwrap();
        assert_eq!(delivered.acknowledgments_confirmed, !lose_ack);
        assert_eq!(delivered.receipt["artifact_manifest"]["files"].as_array().unwrap().len(), 130);
        assert_eq!(delivered.receipt["request_sha256"], hash(&original));
        assert_eq!(serde_json::to_vec(&request).unwrap(), original);
        assert_eq!(peer.sent[1], request);
        assert_eq!(peer.sent.iter().filter(|frame| frame["kind"] == "canonical-exec").count(), 1);
        assert_eq!(peer.sent.iter().filter(|frame| frame["kind"] == "artifact-read").count(), 130);
        for (name, bytes) in &expected {
            assert_eq!(fs::read(destination.join("artifacts").join(name)).unwrap(), *bytes);
        }
        let recovered = recover_existing_delivery(&request, "worker", &destination, DeliveryTrust::Loopback)
            .unwrap().unwrap();
        assert_eq!(recovered.receipt, delivered.receipt);
        assert_eq!(recovered.receipt["publication_authorized"], false);
        assert_eq!(recovered.receipt["reexecute"], false);
        // A non-required intermediate is just as binding as the final executable.
        fs::write(destination.join("artifacts/deps/f0129"), b"bad-content").unwrap();
        assert!(recover_existing_delivery(&request, "worker", &destination, DeliveryTrust::Loopback).is_err());
    }
}

#[test]
fn tree_manifests_refuse_unsafe_incomplete_or_noncanonical_sets_before_ranges() {
    for case in 0..11 {
        let owner = tempfile::tempdir().unwrap();
        let destination = owner.path().join("refused");
        let (mut peer, _) = tree_fixture(&destination, 3);
        let manifest = &mut peer.replies[1]["artifact_manifest"];
        match case {
            0 => { manifest["files"].as_array_mut().unwrap().remove(0); }
            1 => manifest["files"][1]["name"] = json!("../escape"),
            2 => manifest["files"][1]["name"] = json!("A"),
            3 => manifest["files"][1]["name"] = json!("a"),
            4 => manifest["files"][1]["name"] = json!("a/child"),
            5 => manifest["files"].as_array_mut().unwrap().reverse(),
            6 => manifest["unit"] = json!("different-unit"),
            7 => manifest["files"][1]["sha256"] = json!("AB".repeat(32)),
            8 => manifest["files"][1]["bytes"] = json!(MAX_DELIVERY_BYTES),
            9 => manifest["files"][1]["name"] = json!("d/".repeat(33) + "x"),
            _ => manifest["files"][1]["name"] = json!("x".repeat(1025)),
        }
        // Even a freshly recomputed digest cannot bless unsafe path/set semantics.
        refresh_manifest(manifest);
        let failure = receive_execution(&mut peer, &tree_request(), "worker", &destination).unwrap_err();
        assert!(failure.execution_may_have_run, "case {case}");
        assert_eq!(peer.sent.len(), 2, "no range reads on case {case}");
        assert!(no_ack(&peer));
        assert!(!destination.join("delivery.json").exists());
    }
}

#[test]
fn exact_declarations_do_not_accept_tree_results_and_invalid_versions_never_dispatch() {
    let owner = tempfile::tempdir().unwrap();
    let destination = owner.path().join("exact");
    let (mut peer, _) = tree_fixture(&destination, 3);
    assert!(receive_execution(&mut peer, &request(), "worker", &destination).is_err());
    assert_eq!(peer.sent.len(), 2);
    assert!(no_ack(&peer));
    for version in [Value::Null, json!(true), json!("tree-files-v2"), json!({"version":TREE_FILES_VERSION})] {
        let mut request = request();
        request["artifacts"]["tree"] = version;
        let destination = owner.path().join("never-created");
        let mut peer = fixture(&destination);
        let failure = receive_execution(&mut peer, &request, "worker", &destination).unwrap_err();
        assert!(!failure.execution_may_have_run);
        assert!(peer.sent.is_empty());
        assert_eq!(peer.replies.len(), 7);
        assert!(!destination.exists());
    }
}

#[test]
fn tree_resume_retrieves_the_full_recorded_set_without_any_execution_dispatch() {
    let owner = tempfile::tempdir().unwrap();
    let destination = owner.path().join("resumed");
    let (mut peer, expected) = tree_fixture(&destination, 3);
    peer.replies[0]["request_high_water"] = json!(7);
    peer.replies[0]["result_retentions"] = json!([RESULT_RETENTION]);
    peer.replies[1]["resumed"] = json!(true);
    peer.replies[1]["result_retention"] = json!(RESULT_RETENTION);
    peer.replies[1]["retained_result_sha256"] = json!(hash(b"retained full tree"));
    let request = tree_request();
    let delivery = receive_operation(&mut peer, &request, "worker", &destination, DeliveryMode::Resume).unwrap();
    assert!(delivery.acknowledgments_confirmed);
    assert_eq!(peer.sent[1], DeliveryMode::Resume.frame(&request));
    assert!(peer.sent.iter().all(|frame| frame["kind"] != "canonical-exec"));
    for (name, bytes) in expected {
        assert_eq!(fs::read(destination.join("artifacts").join(name)).unwrap(), bytes);
    }
    let mut changed = request.clone();
    changed["artifacts"].as_object_mut().unwrap().remove("tree");
    assert!(recover_existing_delivery(&changed, "worker", &destination, DeliveryTrust::Loopback).is_err());
}

#[test]
fn full_tree_archive_restores_after_store_reopen_without_the_original_delivery() {
    use crate::janitor::store::mount_and_reconcile;
    use rabs_cas::metadata_store::{RabsMetadataStore, digest_key};

    let owner = tempfile::tempdir().unwrap();
    let destination = owner.path().join("delivery");
    let (mut peer, expected) = tree_fixture(&destination, 130);
    let request = tree_request();
    let delivered = receive_execution(&mut peer, &request, "worker", &destination).unwrap();
    let cas_root = owner.path().join("cas");
    let cas = mount_and_reconcile(&cas_root).unwrap();
    let archive = archive_delivery(&cas, &request, "worker", &destination, DeliveryTrust::Loopback).unwrap();
    assert_eq!(archive.file_count, 132);
    assert_eq!(archive_delivery(&cas, &request, "worker", &destination, DeliveryTrust::Loopback).unwrap(), archive);
    {
        let mut store = cas.store().lock().unwrap();
        assert!(store.list_publications().unwrap().is_empty());
        assert_eq!(store.authority_count().unwrap(), 0);
        let gc = store.gc_snapshot(1).unwrap();
        for object in &gc.located_objects {
            assert!(gc.reachable_from_pins.contains(object));
        }
    }
    drop(cas);
    fs::rename(&destination, owner.path().join("retired-delivery")).unwrap();
    let cas = mount_and_reconcile(&cas_root).unwrap();
    let restored = owner.path().join("restored");
    let result = restore_delivery(&cas, &digest_key(&archive.root), &request, "worker", &restored, DeliveryTrust::Loopback).unwrap();
    assert_eq!(result.receipt, delivered.receipt);
    assert!(!result.acknowledgments_confirmed);
    for (name, bytes) in &expected {
        assert_eq!(fs::read(restored.join("artifacts").join(name)).unwrap(), *bytes);
    }
    assert_eq!(restore_delivery(&cas, &digest_key(&archive.root), &request, "worker", &restored, DeliveryTrust::Loopback)
        .unwrap().receipt, delivered.receipt);
    fs::write(restored.join("artifacts/deps/f0129"), b"bad-content").unwrap();
    assert!(restore_delivery(&cas, &digest_key(&archive.root), &request, "worker", &restored, DeliveryTrust::Loopback).is_err());
    assert_eq!(fs::read(restored.join("artifacts/deps/f0129")).unwrap(), b"bad-content");
}

#[test]
fn output_parent_creation_is_exclusive_and_cannot_merge_an_existing_alias() {
    let owner = tempfile::tempdir().unwrap();
    fs::create_dir(owner.path().join("nested")).unwrap();
    fs::write(owner.path().join("nested/evidence"), b"untouched").unwrap();
    assert!(create_artifact_directories(owner.path(), ["nested/a"]).is_err());
    assert_eq!(fs::read(owner.path().join("nested/evidence")).unwrap(), b"untouched");
    let new = owner.path().join("new");
    fs::create_dir(&new).unwrap();
    create_artifact_directories(&new, ["x/a", "x/y/b", "x/y/c"]).unwrap();
    assert!(new.join("x/y").is_dir());
}
