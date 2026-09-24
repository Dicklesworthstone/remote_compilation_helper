//! Exercise failure/retry through the real archive, CAS and delivery verifier.
//! No worker or compiler is started; a failed restore must not occupy its target.
#![cfg(unix)]

use rabs_cas::blob_store::RAW_PROFILE_V1;
use rabs_cas::digest_set::{DigestRequest, digest_set};
use rabs_cas::metadata_store::{RabsMetadataStore, digest_key};
use rabsd::coord::delivery_archive::{archive_delivery, restore_delivery};
use rabsd::coord::delivery_recovery::{DeliveryTrust, recover_existing_delivery};
use rabsd::janitor::store::{LiveCas, mount_and_reconcile};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::fs::{self, File};
use std::os::unix::fs::{MetadataExt, PermissionsExt, symlink};
use std::path::{Path, PathBuf};

const STDOUT: &[u8] = b"diagnostic\0\xff";
const ARTIFACT: &[u8] = b"compiled\0\xff";

fn hash(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn write(path: &Path, bytes: &[u8], executable: bool) {
    fs::write(path, bytes).unwrap();
    let mode = if executable { 0o700 } else { 0o600 };
    fs::set_permissions(path, fs::Permissions::from_mode(mode)).unwrap();
}

fn field(hasher: &mut Sha256, bytes: &[u8]) {
    hasher.update((bytes.len() as u64).to_be_bytes());
    hasher.update(bytes);
}

struct Fixture {
    root: tempfile::TempDir,
    source: PathBuf,
    request: Value,
}

impl Fixture {
    fn new() -> Self {
        let root = tempfile::tempdir().unwrap();
        let source = root.path().join("delivery");
        fs::create_dir(&source).unwrap();
        fs::set_permissions(&source, fs::Permissions::from_mode(0o700)).unwrap();
        fs::create_dir_all(source.join("artifacts/nested")).unwrap();
        fs::create_dir(source.join("diagnostics")).unwrap();
        write(&source.join("artifacts/nested/a"), ARTIFACT, true);
        write(&source.join("diagnostics/stdout"), STDOUT, false);
        write(&source.join("diagnostics/stderr"), b"", false);
        let request = json!({
            "kind": "canonical-exec", "request_id": 7, "program": "rustc",
            "args": ["input.rs"], "toolchain_backing": "/tc", "workspace_backing": "/ws",
            "artifacts": {"unit": "dep", "files": ["nested/a"]}
        });
        let mut manifest = Sha256::new();
        field(&mut manifest, b"rabs.worker-artifact-manifest.v1");
        field(&mut manifest, b"dep");
        manifest.update(1_u64.to_be_bytes());
        field(&mut manifest, b"nested/a");
        manifest.update([1_u8]);
        manifest.update((ARTIFACT.len() as u64).to_be_bytes());
        field(&mut manifest, hash(ARTIFACT).as_bytes());
        let manifest_hash: String = manifest
            .finalize()
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect();
        let receipt = json!({
            "version": 1, "kind": "verified-worker-delivery", "request_id": 7,
            "worker_id": "worker", "boot_generation": 1,
            "incarnation": "00000000000000000000000000000001",
            "request_sha256": hash(&serde_json::to_vec(&request).unwrap()),
            "exit_code": 0, "stop_reason": null,
            "stdout_bytes": STDOUT.len(), "stdout_sha256": hash(STDOUT),
            "stderr_bytes": 0, "stderr_sha256": hash(b""),
            "artifact_manifest": {
                "unit": "dep", "files": [{"name": "nested/a", "bytes": ARTIFACT.len(),
                    "sha256": hash(ARTIFACT), "executable": true}],
                "total_bytes": ARTIFACT.len(), "manifest_sha256": manifest_hash
            },
            "total_bytes": STDOUT.len() + ARTIFACT.len(), "transport_authenticated": false,
            "worker_spki_sha256": null, "authenticated_session_id": null,
            "identity_generation": null, "publication_authorized": false, "reexecute": false
        });
        write(
            &source.join("delivery.json"),
            &serde_json::to_vec(&receipt).unwrap(),
            false,
        );
        Self {
            root,
            source,
            request,
        }
    }

    fn path(&self, name: &str) -> PathBuf {
        self.root.path().join(name)
    }

    fn mount(&self) -> LiveCas {
        mount_and_reconcile(&self.path("cas")).unwrap()
    }

    fn staging(&self) -> Vec<PathBuf> {
        let mut paths: Vec<_> = fs::read_dir(self.root.path())
            .unwrap()
            .map(Result::unwrap)
            .filter(|entry| {
                entry
                    .file_name()
                    .to_string_lossy()
                    .starts_with(".rabs-delivery-restore-")
            })
            .map(|entry| entry.path())
            .collect();
        paths.sort();
        paths
    }

    fn archive(&self, cas: &LiveCas) -> String {
        digest_key(
            &archive_delivery(cas, &self.request, "worker", &self.source, DeliveryTrust::Loopback)
                .unwrap()
                .root,
        )
    }
}

#[test]
fn rejected_trust_does_not_strand_the_destination_for_a_correct_retry() {
    let f = Fixture::new();
    let cas = f.mount();
    let key = f.archive(&cas);
    let destination = f.path("restored");
    assert!(
        restore_delivery(
            &cas,
            &key,
            &f.request,
            "worker",
            &destination,
            DeliveryTrust::PinnedWorker([1; 32]),
        )
        .is_err()
    );
    assert!(
        !destination.exists(),
        "a refused restore must not claim the final delivery directory"
    );
    let failed_staging = f.staging();
    let restored = restore_delivery(
        &cas,
        &key,
        &f.request,
        "worker",
        &destination,
        DeliveryTrust::Loopback,
    )
    .unwrap();
    assert_eq!(fs::read(destination.join("artifacts/nested/a")).unwrap(), ARTIFACT);
    assert!(!restored.acknowledgments_confirmed);
    assert_eq!(restored.receipt["publication_authorized"], false);
    assert_eq!(restored.receipt["reexecute"], false);
    assert_eq!(f.staging(), failed_staging, "failed staging is never consumed");
}

#[test]
fn late_replica_failure_retains_evidence_and_can_retry_after_cas_reopen() {
    let f = Fixture::new();
    let cas = f.mount();
    let key = f.archive(&cas);
    // stdout sorts after the artifact and stderr, so this fails AFTER earlier
    // output files were copied. It exercises a real mid-restore failure.
    let object = digest_set(STDOUT, DigestRequest::default(), None)
        .unwrap()
        .atp_content_id;
    let original = cas.store().lock().unwrap().object_locations(&object).unwrap()[0]
        .0
        .clone();
    fs::set_permissions(&original, fs::Permissions::from_mode(0o600)).unwrap();
    fs::write(&original, vec![b'x'; STDOUT.len()]).unwrap();
    let destination = f.path("restored");
    let error = restore_delivery(
        &cas,
        &key,
        &f.request,
        "worker",
        &destination,
        DeliveryTrust::Loopback,
    )
    .unwrap_err();
    assert!(!destination.exists(), "partial output must remain private");
    let failed_staging = f.staging();
    assert_eq!(failed_staging.len(), 1);
    assert!(error.contains(&failed_staging[0].display().to_string()));
    assert_eq!(fs::read(failed_staging[0].join("artifacts/nested/a")).unwrap(), ARTIFACT);
    assert!(cas.store().lock().unwrap().reconciliation_scan().unwrap().iter().any(
        |row| row.store_path == original && row.quarantined
    ));
    // Supply a NEW verified replica; do not overwrite the quarantined evidence.
    let replica = f.path("healthy-stdout-replica");
    write(&replica, STDOUT, false);
    File::open(&replica).unwrap().sync_all().unwrap();
    File::open(f.root.path()).unwrap().sync_all().unwrap();
    cas.store()
        .lock()
        .unwrap()
        .add_location(&object, replica.to_str().unwrap(), None, RAW_PROFILE_V1, true)
        .unwrap();
    drop(cas);
    let cas = f.mount();
    restore_delivery(
        &cas,
        &key,
        &f.request,
        "worker",
        &destination,
        DeliveryTrust::Loopback,
    )
    .unwrap();
    recover_existing_delivery(&f.request, "worker", &destination, DeliveryTrust::Loopback)
        .unwrap()
        .unwrap();
    assert_eq!(fs::read(destination.join("diagnostics/stdout")).unwrap(), STDOUT);
    assert_eq!(fs::read(destination.join("artifacts/nested/a")).unwrap(), ARTIFACT);
    assert_eq!(f.staging(), failed_staging);
    assert_eq!(fs::read(&original).unwrap(), vec![b'x'; STDOUT.len()]);
    assert_eq!(fs::read(f.source.join("diagnostics/stdout")).unwrap(), STDOUT);
    assert!(cas.store().lock().unwrap().list_publications().unwrap().is_empty());
    assert_eq!(cas.store().lock().unwrap().authority_count().unwrap(), 0);
}

#[test]
fn completed_restore_publishes_one_private_independent_tree_and_reuses_it() {
    let f = Fixture::new();
    let cas = f.mount();
    let key = f.archive(&cas);
    let destination = f.path("restored");
    restore_delivery(
        &cas,
        &key,
        &f.request,
        "worker",
        &destination,
        DeliveryTrust::Loopback,
    )
    .unwrap();
    assert!(f.staging().is_empty());
    let mut entries: Vec<_> = fs::read_dir(&destination)
        .unwrap()
        .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    entries.sort();
    assert_eq!(entries, vec!["artifacts".to_owned(), "delivery.json".to_owned(), "diagnostics".to_owned()]);
    assert_eq!(fs::metadata(&destination).unwrap().permissions().mode() & 0o777, 0o700);
    let artifact = destination.join("artifacts/nested/a");
    let before = fs::metadata(&artifact).unwrap();
    assert_eq!(before.nlink(), 1);
    assert_eq!(before.permissions().mode() & 0o777, 0o700);
    assert_ne!(before.ino(), fs::metadata(f.source.join("artifacts/nested/a")).unwrap().ino());
    restore_delivery(
        &cas,
        &key,
        &f.request,
        "worker",
        &destination,
        DeliveryTrust::Loopback,
    )
    .unwrap();
    assert_eq!(fs::metadata(artifact).unwrap().ino(), before.ino());
    assert!(f.staging().is_empty());
}

#[test]
fn existing_empty_partial_and_symlink_destinations_are_never_adopted() {
    let f = Fixture::new();
    let cas = f.mount();
    let key = f.archive(&cas);
    let empty = f.path("empty");
    fs::create_dir(&empty).unwrap();
    let partial = f.path("legacy-partial");
    fs::create_dir_all(partial.join(".restore-staging")).unwrap();
    write(&partial.join("sentinel"), b"keep", false);
    let link = f.path("link");
    symlink(&empty, &link).unwrap();
    for destination in [&empty, &partial, &link] {
        assert!(
            restore_delivery(
                &cas,
                &key,
                &f.request,
                "worker",
                destination,
                DeliveryTrust::Loopback,
            )
            .is_err()
        );
    }
    assert_eq!(fs::read_dir(&empty).unwrap().count(), 0);
    assert_eq!(fs::read(partial.join("sentinel")).unwrap(), b"keep");
    assert!(partial.join(".restore-staging").is_dir());
    assert_eq!(fs::read_link(link).unwrap(), empty);
    assert!(f.staging().is_empty());
}
