//! Preparation runs against a verified private inode, before its installation.
//! These tests exercise the real CAS and the production materializer, not a
//! substitute copy loop. They do not claim a compiler was skipped.
#![cfg(unix)]

use std::io::{Read, Seek, Write};
use std::path::Path;
use std::time::{Duration, UNIX_EPOCH};

use rabs_cas::blob_store::{DurabilityPolicy, PutLimits, put_if_absent};
use rabs_cas::digest_set::{DigestRequest, digest_set};
use rabs_cas::metadata_store::RabsMetadataStore;
use rabs_cas::materialization::{
    MaterializationMode, PlannedActionOutput, materialize_action_outputs_prepared,
};
use rabs_protocol::raw_bytes::RawBytes;
use rabs_protocol::result_identity::OutputRole;
use rabsd::janitor::store::{LiveCas, mount_and_reconcile};

fn output(cas: &LiveCas, root: &Path, name: &str, role: OutputRole, bytes: &[u8]) -> PlannedActionOutput {
    let object = digest_set(bytes, DigestRequest::default(), None).unwrap().atp_content_id;
    put_if_absent(
        cas.layout(), &mut *cas.store().lock().unwrap(), &object, &mut &bytes[..],
        PutLimits::default(), DurabilityPolicy::FULL,
    ).unwrap();
    PlannedActionOutput {
        role, virtual_path: RawBytes::from(name), object, destination: root.join(name),
    }
}

#[test]
fn preparation_sees_verified_bytes_and_installs_derived_bytes_on_a_private_inode() {
    let dir = tempfile::tempdir().unwrap();
    let cas = mount_and_reconcile(&dir.path().join("cas")).unwrap();
    let out = output(&cas, dir.path(), "dep.d", OutputRole::DepInfo, b"canonical");
    let original = cas.store().lock().unwrap().object_locations(&out.object).unwrap()[0].0.clone();
    let before = std::fs::read(&original).unwrap();
    let stamp = UNIX_EPOCH + Duration::from_secs(1_700_000_000);
    let receipt = materialize_action_outputs_prepared(
        &mut *cas.store().lock().unwrap(), std::slice::from_ref(&out),
        MaterializationMode::PrivateCopy, stamp,
        &|planned, file| {
            assert_eq!(planned.role, OutputRole::DepInfo);
            let mut file = file.try_clone()?;
            file.rewind()?;
            let mut bytes = Vec::new();
            file.read_to_end(&mut bytes)?;
            assert_eq!(bytes, b"canonical");
            file.rewind()?;
            file.set_len(0)?;
            file.write_all(b"subscriber-specific dep-info")
        },
    ).unwrap();
    assert_eq!(std::fs::read(&out.destination).unwrap(), b"subscriber-specific dep-info");
    assert_eq!(receipt.installed[0].bytes, 28);
    assert_eq!(std::fs::metadata(&out.destination).unwrap().modified().unwrap(), stamp);
    assert_eq!(std::fs::read(&original).unwrap(), before, "CAS identity must not be rewritten");
    use std::os::unix::fs::MetadataExt;
    let source = std::fs::metadata(&original).unwrap();
    let installed = std::fs::metadata(&out.destination).unwrap();
    assert_ne!((source.dev(), source.ino()), (installed.dev(), installed.ino()));
}

#[test]
fn failed_preparation_never_replaces_the_previous_destination() {
    let dir = tempfile::tempdir().unwrap();
    let cas = mount_and_reconcile(&dir.path().join("cas")).unwrap();
    let out = output(&cas, dir.path(), "dep.d", OutputRole::DepInfo, b"canonical");
    std::fs::write(&out.destination, b"previous complete file").unwrap();
    let failure = materialize_action_outputs_prepared(
        &mut *cas.store().lock().unwrap(), std::slice::from_ref(&out),
        MaterializationMode::PrivateCopy, UNIX_EPOCH,
        &|_, file| {
            file.set_len(0)?;
            Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "unmapped source path"))
        },
    ).unwrap_err();
    assert!(failure.installed.is_empty());
    assert_eq!(std::fs::read(&out.destination).unwrap(), b"previous complete file");
}

#[test]
fn a_later_preparation_failure_reports_the_exact_verified_metadata_prefix() {
    let dir = tempfile::tempdir().unwrap();
    let cas = mount_and_reconcile(&dir.path().join("cas")).unwrap();
    // Reverse lexical and declaration order: metadata must still install first.
    let tail = output(&cas, dir.path(), "a.d", OutputRole::DepInfo, b"canonical");
    let head = output(&cas, dir.path(), "z.rmeta", OutputRole::ProvisionalMetadata, b"metadata");
    let failure = materialize_action_outputs_prepared(
        &mut *cas.store().lock().unwrap(), &[tail.clone(), head.clone()],
        MaterializationMode::PrivateCopy, UNIX_EPOCH,
        &|planned, _| if planned.role == OutputRole::DepInfo {
            Err(std::io::Error::other("derivation refused"))
        } else { Ok(()) },
    ).unwrap_err();
    assert_eq!(failure.installed.len(), 1);
    assert_eq!(failure.installed[0].destination, head.destination);
    assert_eq!(std::fs::read(&head.destination).unwrap(), b"metadata");
    assert!(!tail.destination.exists());
}

#[test]
fn byte_verification_precedes_preparation() {
    use std::cell::Cell;
    use std::os::unix::fs::PermissionsExt;
    let dir = tempfile::tempdir().unwrap();
    let cas = mount_and_reconcile(&dir.path().join("cas")).unwrap();
    let out = output(&cas, dir.path(), "dep.d", OutputRole::DepInfo, b"canonical");
    let location = cas.store().lock().unwrap().object_locations(&out.object).unwrap()[0].0.clone();
    std::fs::set_permissions(&location, std::fs::Permissions::from_mode(0o600)).unwrap();
    std::fs::write(&location, b"corrupted").unwrap();
    let called = Cell::new(false);
    let failure = materialize_action_outputs_prepared(
        &mut *cas.store().lock().unwrap(), std::slice::from_ref(&out),
        MaterializationMode::PrivateCopy, UNIX_EPOCH,
        &|_, _| { called.set(true); Ok(()) },
    ).unwrap_err();
    assert!(!called.get());
    assert!(failure.installed.is_empty());
    assert!(!out.destination.exists());
}
