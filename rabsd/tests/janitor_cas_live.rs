//! bd-hfhq2 daemon-level acceptance: the running `rabsd` binary mounts
//! the rabs-cas store in its janitor region and reconciles it fail-closed
//! at boot — INCLUDING recovering from a store left torn by a crash mid
//! publication (`FaultPoint::Linked`: object bytes linked into the
//! published namespace, metadata never recorded). rabs-cas proves this
//! durability property in its own tests at LIBRARY fidelity; this proves
//! it holds UNDER THE RUNNING DAEMON (bridge-plan governing principle 4:
//! library-done + live-done together are the real done).
#![cfg(unix)]

use std::process::{Command, Stdio};

use rabs_cas::blob_store::{
    BlobStoreLayout, DurabilityPolicy, FaultPoint, PutError, PutLimits, put_if_absent_with_fault,
};
use rabs_cas::digest_set::{DigestRequest, digest_set};
use rabs_cas::metadata_store::{RusqliteEngine, SqlMetadataStore};

fn boot_once(state_dir: &std::path::Path) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_rabsd"))
        .args(["--run-for-ms", "1500"])
        .env("RABS_SOCKET_PATH", state_dir.join("rabsd.sock"))
        .env("RABS_BOOT_MARKER", state_dir.join("rabsd.boot"))
        .env("RABS_STATE_DIR", state_dir)
        .env("RABS_CONFIG", "/nonexistent-rabs-config")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .expect("run rabsd")
}

#[test]
fn daemon_mounts_and_reconciles_cas_on_boot() {
    let dir = tempfile::tempdir().unwrap();
    let out = boot_once(dir.path());
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        out.status.success(),
        "rabsd did not exit clean:\nSTDOUT:{stdout}\nSTDERR:{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        stdout.contains("\"kind\":\"janitor-cas-mounted\""),
        "no janitor mount line: {stdout}"
    );
    assert!(
        stdout.contains("\"serving_refused\":false"),
        "a fresh store must allow serving: {stdout}"
    );
    // The daemon actually created the on-disk store.
    let cas = dir.path().join("cas");
    assert!(
        cas.join("blobs").join("objects").is_dir(),
        "blob objects dir not created"
    );
    assert!(cas.join("meta.sqlite").exists(), "metadata db not created");
}

#[test]
fn daemon_recovers_from_a_store_torn_mid_publication() {
    let dir = tempfile::tempdir().unwrap();
    let cas = dir.path().join("cas");

    // Crash a publication mid-flight against the exact store the daemon
    // will mount: object linked into the published namespace, metadata
    // never recorded (the classic "died between link and commit" tear).
    {
        let layout = BlobStoreLayout::open(&cas.join("blobs")).unwrap();
        let engine = RusqliteEngine::open(&cas.join("meta.sqlite")).unwrap();
        let mut store = SqlMetadataStore::open(engine).unwrap();
        let bytes = b"torn-object-payload";
        let declared = digest_set(bytes, DigestRequest::default(), None)
            .unwrap()
            .atp_content_id;
        let mut reader: &[u8] = bytes;
        let outcome = put_if_absent_with_fault(
            &layout,
            &mut store,
            &declared,
            &mut reader,
            PutLimits::default(),
            DurabilityPolicy::FULL,
            Some(FaultPoint::Linked),
        );
        assert!(
            matches!(outcome, Err(PutError::CrashInjected(FaultPoint::Linked))),
            "expected an injected crash at Linked, got {outcome:?}"
        );
        // store + engine drop here — the sqlite handle is released so the
        // daemon can open the same metadata db.
    }

    // The daemon must mount + reconcile the torn store, not crash.
    let out = boot_once(dir.path());
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        out.status.success(),
        "daemon crashed booting over a torn store:\nSTDOUT:{stdout}\nSTDERR:{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        stdout.contains("\"kind\":\"janitor-cas-mounted\""),
        "janitor did not mount over the torn store: {stdout}"
    );

    // Recovery is stable: a second boot over the reconciled store also
    // comes up clean (no re-tear, no accumulation).
    let out2 = boot_once(dir.path());
    assert!(
        out2.status.success(),
        "second boot over the recovered store failed: {}",
        String::from_utf8_lossy(&out2.stderr)
    );
}
