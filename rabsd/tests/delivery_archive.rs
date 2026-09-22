//! Real CAS/recovery/CLI tests. No compiler, remote fixture, or action authority.
#![cfg(unix)]
use rabsd::coord::delivery_archive::{archive_delivery, parse_archive_key, restore_delivery};
use rabsd::coord::delivery_recovery::{DeliveryTrust, install_delivery_outputs, recover_existing_delivery};
use rabsd::janitor::store::{LiveCas, mount_and_reconcile};
use rabs_cas::blob_store::RAW_PROFILE_V1;
use rabs_cas::digest_set::{DigestRequest, digest_set};
use rabs_cas::metadata_store::{QuarantineScope, RabsMetadataStore, SqlValue, digest_key};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

fn hex(bytes: &[u8]) -> String { bytes.iter().map(|b| format!("{b:02x}")).collect() }
fn hash(bytes: &[u8]) -> String { hex(&Sha256::digest(bytes)) }
fn write(path: &Path, bytes: &[u8], executable: bool) {
    fs::write(path,bytes).unwrap();
    fs::set_permissions(path,fs::Permissions::from_mode(if executable {0o700} else {0o600})).unwrap();
}
fn field(h: &mut Sha256, bytes: &[u8]) { h.update((bytes.len() as u64).to_be_bytes()); h.update(bytes); }
struct Fixture { _root: tempfile::TempDir, source: PathBuf, cas_root: PathBuf, request: Value }
impl Fixture {
    fn new() -> Self {
        let root = tempfile::tempdir().unwrap();
        let source = root.path().join("delivery");
        fs::create_dir(&source).unwrap(); fs::set_permissions(&source,fs::Permissions::from_mode(0o700)).unwrap();
        fs::create_dir_all(source.join("artifacts/nested")).unwrap();
        fs::create_dir(source.join("diagnostics")).unwrap();
        let stdout = b"diagnostic\0\xff";
        let artifact = b"compiled\0\xff";
        write(&source.join("diagnostics/stdout"),stdout,false);
        write(&source.join("diagnostics/stderr"),b"",false);
        write(&source.join("artifacts/nested/a"),artifact,true);
        let request = json!({"kind":"canonical-exec","request_id":7,"program":"rustc","args":["input.rs"],
            "toolchain_backing":"/tc","workspace_backing":"/ws","artifacts":{"unit":"dep","files":["nested/a"]}});
        let mut h = Sha256::new(); field(&mut h,b"rabs.worker-artifact-manifest.v1"); field(&mut h,b"dep");
        h.update(1_u64.to_be_bytes()); field(&mut h,b"nested/a"); h.update([1_u8]);
        h.update((artifact.len() as u64).to_be_bytes()); field(&mut h,hash(artifact).as_bytes());
        assert_eq!(hex(&h.clone().finalize()),"7497e2536c19fb3baafb427a06172b18c4875de95d09c10030d895b99ea6636a");
        let receipt = json!({"version":1,"kind":"verified-worker-delivery","request_id":7,
            "worker_id":"worker","boot_generation":1,"incarnation":"00000000000000000000000000000001",
            "request_sha256":hash(&serde_json::to_vec(&request).unwrap()),"exit_code":0,"stop_reason":null,
            "stdout_bytes":stdout.len(),"stdout_sha256":hash(stdout),"stderr_bytes":0,"stderr_sha256":hash(b""),
            "artifact_manifest":{"unit":"dep","files":[{"name":"nested/a","bytes":artifact.len(),
                "sha256":hash(artifact),"executable":true}],"total_bytes":artifact.len(),"manifest_sha256":hex(&h.finalize())},
            "total_bytes":stdout.len()+artifact.len(),"transport_authenticated":false,
            "worker_spki_sha256":null,"authenticated_session_id":null,"identity_generation":null,
            "publication_authorized":false,"reexecute":false});
        write(&source.join("delivery.json"),&serde_json::to_vec(&receipt).unwrap(),false);
        let cas_root = root.path().join("cas");
        Self { _root:root, source, cas_root, request }
    }
    fn destination(&self, name: &str) -> PathBuf { self._root.path().join(name) }
    fn mount(&self) -> LiveCas { mount_and_reconcile(&self.cas_root).unwrap() }
}

#[test]
fn archive_deduplicates_protects_full_closure_and_restores_after_store_reopen() {
    let f = Fixture::new(); let cas = f.mount();
    let archive = archive_delivery(&cas,&f.request,"worker",&f.source,DeliveryTrust::Loopback).unwrap();
    assert_eq!(archive.file_count,3);
    let repeat = archive_delivery(&cas,&f.request,"worker",&f.source,DeliveryTrust::Loopback).unwrap();
    assert_eq!(archive,repeat);
    {
        let mut store = cas.store().lock().unwrap();
        let snapshot = store.gc_snapshot(1).unwrap();
        assert_eq!(snapshot.pinned_roots,vec![digest_key(&archive.root)]);
        for object in &snapshot.located_objects {
            assert!(snapshot.reachable_from_pins.contains(object));
        }
        assert!(store.list_publications().unwrap().is_empty());
        assert_eq!(store.authority_count().unwrap(),0);
        assert!(store.query("SELECT 1 FROM action_entries", &[]).unwrap().is_empty());
    }
    let world = rabs_cas::gc::GcWorld { reclaim_budget:usize::MAX, reconciliation_complete:true, ..Default::default() };
    assert!(rabs_cas::gc::plan_gc(&mut *cas.store().lock().unwrap(),&world,rabs_cas::gc::GcMode::Emergency,2)
        .unwrap().reclaim.is_empty());
    drop(cas);
    // Original source is no longer required, and may not be trusted anymore.
    write(&f.source.join("artifacts/nested/a"),b"changed",true);
    let cas = f.mount(); let dest = f.destination("restored");
    let restored = restore_delivery(&cas,&digest_key(&archive.root),&f.request,"worker",&dest,DeliveryTrust::Loopback).unwrap();
    assert!(!restored.acknowledgments_confirmed);
    assert_eq!(fs::read(dest.join("artifacts/nested/a")).unwrap(),b"compiled\0\xff");
    assert_eq!(fs::metadata(dest.join("artifacts/nested/a")).unwrap().permissions().mode() & 0o777,0o700);
    assert_eq!(fs::read(dest.join("diagnostics/stdout")).unwrap(),b"diagnostic\0\xff");
    assert!(!dest.join(".restore-staging").exists());
    recover_existing_delivery(&f.request,"worker",&dest,DeliveryTrust::Loopback).unwrap().unwrap();
    let original_inode = {
        use std::os::unix::fs::MetadataExt;
        fs::metadata(dest.join("artifacts/nested/a")).unwrap().ino()
    };
    let again = restore_delivery(&cas,&digest_key(&archive.root),&f.request,"worker",&dest,DeliveryTrust::Loopback).unwrap();
    assert_eq!(again.receipt,restored.receipt);
    {
        use std::os::unix::fs::MetadataExt;
        assert_eq!(fs::metadata(dest.join("artifacts/nested/a")).unwrap().ino(),original_inode);
    }
}

#[test]
fn a_valid_different_result_for_the_same_request_never_overwrites_existing_delivery() {
    let f = Fixture::new(); let alternate = Fixture::new(); let cas = f.mount();
    let first = archive_delivery(&cas,&f.request,"worker",&f.source,DeliveryTrust::Loopback).unwrap();
    let dest = f.destination("already-restored");
    restore_delivery(&cas,&digest_key(&first.root),&f.request,"worker",&dest,DeliveryTrust::Loopback).unwrap();
    let changed = b"other___\0\xff";
    write(&alternate.source.join("artifacts/nested/a"),changed,true);
    let mut receipt: Value = serde_json::from_slice(&fs::read(alternate.source.join("delivery.json")).unwrap()).unwrap();
    receipt["artifact_manifest"]["files"][0]["sha256"] = json!(hash(changed));
    let mut h = Sha256::new(); field(&mut h,b"rabs.worker-artifact-manifest.v1"); field(&mut h,b"dep");
    h.update(1_u64.to_be_bytes()); field(&mut h,b"nested/a"); h.update([1_u8]);
    h.update((changed.len() as u64).to_be_bytes()); field(&mut h,hash(changed).as_bytes());
    receipt["artifact_manifest"]["manifest_sha256"] = json!(hex(&h.finalize()));
    write(&alternate.source.join("delivery.json"),&serde_json::to_vec(&receipt).unwrap(),false);
    let second = archive_delivery(&cas,&alternate.request,"worker",&alternate.source,DeliveryTrust::Loopback).unwrap();
    assert_ne!(first.root,second.root);
    assert!(restore_delivery(&cas,&digest_key(&second.root),&f.request,"worker",&dest,DeliveryTrust::Loopback).is_err());
    assert_eq!(fs::read(dest.join("artifacts/nested/a")).unwrap(),b"compiled\0\xff");
    // Damaged output is not an idempotent success and is not silently repaired.
    write(&dest.join("artifacts/nested/a"),b"damaged",true);
    assert!(restore_delivery(&cas,&digest_key(&first.root),&f.request,"worker",&dest,DeliveryTrust::Loopback).is_err());
    assert_eq!(fs::read(dest.join("artifacts/nested/a")).unwrap(),b"damaged");
}

#[test]
fn corrupted_source_never_creates_an_archive_pin_or_action_entry() {
    let f = Fixture::new(); let cas = f.mount();
    write(&f.source.join("diagnostics/stdout"),b"wrong",false);
    assert!(archive_delivery(&cas,&f.request,"worker",&f.source,DeliveryTrust::Loopback).is_err());
    let mut store = cas.store().lock().unwrap();
    assert!(store.gc_snapshot(1).unwrap().pinned_roots.is_empty());
    assert!(store.list_publications().unwrap().is_empty());
}

#[test]
fn restore_refuses_changed_request_wrong_trust_and_existing_destination() {
    let f = Fixture::new(); let cas = f.mount();
    let archive = archive_delivery(&cas,&f.request,"worker",&f.source,DeliveryTrust::Loopback).unwrap();
    let key = digest_key(&archive.root);
    let mut changed = f.request.clone(); changed["args"] = json!(["other.rs"]);
    let dest = f.destination("wrong-request");
    assert!(restore_delivery(&cas,&key,&changed,"worker",&dest,DeliveryTrust::Loopback).is_err());
    assert!(!dest.join("delivery.json").exists());
    let dest = f.destination("wrong-trust");
    assert!(restore_delivery(&cas,&key,&f.request,"worker",&dest,DeliveryTrust::PinnedWorker([1;32])).is_err());
    assert!(!dest.join("delivery.json").exists());
    let existing = f.destination("existing"); fs::create_dir(&existing).unwrap();
    write(&existing.join("untouched"),b"existing",false);
    assert!(restore_delivery(&cas,&key,&f.request,"worker",&existing,DeliveryTrust::Loopback).is_err());
    assert_eq!(fs::read(existing.join("untouched")).unwrap(),b"existing");
    assert_eq!(fs::read_dir(existing).unwrap().count(),1);
}

#[test]
fn corrupt_replica_is_quarantined_and_a_verified_replica_can_restore() {
    let f = Fixture::new(); let cas = f.mount();
    let archive = archive_delivery(&cas,&f.request,"worker",&f.source,DeliveryTrust::Loopback).unwrap();
    let object = digest_set(b"compiled\0\xff",DigestRequest::default(),None).unwrap().atp_content_id;
    let original = cas.store().lock().unwrap().object_locations(&object).unwrap()[0].0.clone();
    // Same length but wrong content: size checks alone are insufficient.
    fs::set_permissions(&original,fs::Permissions::from_mode(0o600)).unwrap();
    fs::write(&original,b"corrupt!\0\xff").unwrap();
    let replica = f.destination("valid-replica"); write(&replica,b"compiled\0\xff",false);
    fs::File::open(&replica).unwrap().sync_all().unwrap();
    cas.store().lock().unwrap().add_location(&object,replica.to_str().unwrap(),None,RAW_PROFILE_V1,true).unwrap();
    restore_delivery(&cas,&digest_key(&archive.root),&f.request,"worker",&f.destination("replicated"),DeliveryTrust::Loopback).unwrap();
    assert!(cas.store().lock().unwrap().reconciliation_scan().unwrap().iter()
        .any(|row| row.store_path == original && row.quarantined));
}

#[test]
fn logical_quarantine_blocks_even_correct_archived_content() {
    for quarantine_root in [false,true] {
        let f = Fixture::new(); let cas = f.mount();
        let archive = archive_delivery(&cas,&f.request,"worker",&f.source,DeliveryTrust::Loopback).unwrap();
        let object = if quarantine_root { archive.root.clone() } else {
            digest_set(b"compiled\0\xff",DigestRequest::default(),None).unwrap().atp_content_id
        };
        cas.store().lock().unwrap().add_quarantine(QuarantineScope::LogicalObject,&digest_key(&object),"operator hold").unwrap();
        let dest = f.destination("quarantined");
        assert!(restore_delivery(&cas,&digest_key(&archive.root),&f.request,"worker",&dest,DeliveryTrust::Loopback).is_err());
        assert!(!dest.join("delivery.json").exists());
        assert!(archive_delivery(&cas,&f.request,"worker",&f.source,DeliveryTrust::Loopback).is_err());
    }
}

#[test]
fn released_root_and_foreign_digest_domains_refuse_before_restoration() {
    let f = Fixture::new(); let cas = f.mount();
    let archive = archive_delivery(&cas,&f.request,"worker",&f.source,DeliveryTrust::Loopback).unwrap();
    cas.store().lock().unwrap().release_pin(archive.pin,"rabs-delivery-archive").unwrap();
    assert!(restore_delivery(&cas,&digest_key(&archive.root),&f.request,"worker",&f.destination("released"),DeliveryTrust::Loopback).is_err());
    assert!(!f.destination("released").exists());
    for bad in ["", "rabs.action-key.sha256.v1:00", "rabs.object.sha256.v1:ABC"] {
        assert!(parse_archive_key(bad).is_err());
    }
}

#[test]
fn diagnostic_failure_delivery_archives_without_inventing_artifacts() {
    let f = Fixture::new();
    // Preserve the original artifact tree outside the delivery instead of deleting it.
    fs::rename(f.source.join("artifacts"),f.destination("failure-artifacts")).unwrap();
    fs::create_dir(f.source.join("artifacts")).unwrap();
    let mut receipt: Value = serde_json::from_slice(&fs::read(f.source.join("delivery.json")).unwrap()).unwrap();
    receipt["exit_code"] = json!(1); receipt["artifact_manifest"] = Value::Null;
    receipt["total_bytes"] = receipt["stdout_bytes"].clone();
    write(&f.source.join("delivery.json"),&serde_json::to_vec(&receipt).unwrap(),false);
    let cas = f.mount();
    let archive = archive_delivery(&cas,&f.request,"worker",&f.source,DeliveryTrust::Loopback).unwrap();
    assert_eq!(archive.file_count,2);
    let dest = f.destination("failed-result");
    let restored = restore_delivery(&cas,&digest_key(&archive.root),&f.request,"worker",&dest,DeliveryTrust::Loopback).unwrap();
    assert_eq!(restored.receipt["exit_code"],1);
    assert_eq!(fs::read_dir(dest.join("artifacts")).unwrap().count(),0);
}

#[test]
fn real_cli_archives_then_restores_without_a_worker_or_compiler() {
    let f = Fixture::new(); let request_path = f.destination("request.json");
    fs::write(&request_path,serde_json::to_vec(&f.request).unwrap()).unwrap();
    let bin = env!("CARGO_BIN_EXE_rabs-delivery-cas");
    let archived = std::process::Command::new(bin).arg("archive").arg(&f.cas_root)
        .arg(&request_path).arg("worker").arg(&f.source).arg("loopback").output().unwrap();
    assert!(archived.status.success(),"{}",String::from_utf8_lossy(&archived.stderr));
    let archive: Value = serde_json::from_slice(&archived.stdout).unwrap();
    let dest = f.destination("cli-restored");
    let restored = std::process::Command::new(bin).arg("restore").arg(&f.cas_root)
        .arg(archive["root"].as_str().unwrap()).arg(&request_path).arg("worker").arg(&dest)
        .arg("loopback").output().unwrap();
    assert!(restored.status.success(),"{}",String::from_utf8_lossy(&restored.stderr));
    let restored: Value = serde_json::from_slice(&restored.stdout).unwrap();
    assert_eq!(restored["receipt"]["publication_authorized"],false);
    assert_eq!(restored["reexecute"],false);
    assert_eq!(fs::read(dest.join("artifacts/nested/a")).unwrap(),b"compiled\0\xff");
    let cas = f.mount();
    assert!(cas.store().lock().unwrap().query("SELECT 1 FROM action_entries",&[] as &[SqlValue]).unwrap().is_empty());
}

#[test]
fn archived_nested_executable_outputs_install_without_aliasing_the_archive_or_delivery() {
    let f = Fixture::new(); let cas = f.mount();
    let archive = archive_delivery(&cas, &f.request, "worker", &f.source, DeliveryTrust::Loopback).unwrap();
    let restored = f.destination("restored");
    restore_delivery(&cas, &digest_key(&archive.root), &f.request, "worker", &restored, DeliveryTrust::Loopback).unwrap();
    let restored = restored.canonicalize().unwrap();
    let target = restored.parent().unwrap().join("target");
    let result = install_delivery_outputs(&f.request, "worker", &restored, &target, DeliveryTrust::Loopback).unwrap();
    assert_eq!(result.file_count, 1);
    assert_eq!(fs::read(target.join("nested/a")).unwrap(), b"compiled\0\xff");
    assert_eq!(fs::metadata(target.join("nested/a")).unwrap().permissions().mode() & 0o7777, 0o700);
    write(&target.join("nested/a"), b"modified", true);
    assert_eq!(fs::read(restored.join("artifacts/nested/a")).unwrap(), b"compiled\0\xff");
    let second = f.destination("second-restored");
    restore_delivery(&cas, &digest_key(&archive.root), &f.request, "worker", &second, DeliveryTrust::Loopback).unwrap();
    assert_eq!(fs::read(second.join("artifacts/nested/a")).unwrap(), b"compiled\0\xff");
}
