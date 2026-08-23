//! W1 remainder (bd-hfhq2): the running `rabsd` janitor region OWNS
//! quota/GC — it runs one GC sweep over the mounted store at boot and
//! publishes usage + quota evidence. Library fidelity for plan/execute
//! lives in rabs-cas; this proves OWNERSHIP holds under the running
//! daemon (governing principle 4: library-done + live-done together).
#![cfg(unix)]

use rabs_cas::blob_store::{BlobStoreLayout, DurabilityPolicy, PutLimits, put_if_absent};
use rabs_cas::digest_set::{DigestRequest, digest_set};
use rabs_cas::metadata_store::{RusqliteEngine, SqlMetadataStore};
use std::path::Path;
use std::process::{Command, Stdio};

fn boot_once(state_dir: &std::path::Path, quota: Option<&str>) -> std::process::Output {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_rabsd"));
    cmd.args(["--run-for-ms", "1500"])
        .env("RABS_SOCKET_PATH", state_dir.join("rabsd.sock"))
        .env("RABS_BOOT_MARKER", state_dir.join("rabsd.boot"))
        .env("RABS_STATE_DIR", state_dir)
        .env("RABS_CONFIG", "/nonexistent-rabs-config")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    if let Some(q) = quota {
        cmd.env("RABS_QUOTA_BYTES", q);
    }
    cmd.output().expect("run rabsd")
}

/// Seed one real object into the store the daemon will mount, so the
/// sweep has something to account for and usage is nonzero.
fn seed_one_object(cas: &Path) {
    let layout = BlobStoreLayout::open(&cas.join("blobs")).unwrap();
    let engine = RusqliteEngine::open(&cas.join("meta.sqlite")).unwrap();
    let mut store = SqlMetadataStore::open(engine).unwrap();
    let bytes = b"w1-gc-live-payload";
    let declared = digest_set(bytes, DigestRequest::default(), None)
        .unwrap()
        .atp_content_id;
    let mut reader: &[u8] = bytes;
    put_if_absent(
        &layout,
        &mut store,
        &declared,
        &mut reader,
        PutLimits::default(),
        DurabilityPolicy::FULL,
    )
    .unwrap();
    // Drop handles so the daemon can open the same metadata db.
}

#[test]
fn daemon_janitor_runs_gc_sweep_and_reports_usage() {
    let dir = tempfile::tempdir().unwrap();
    seed_one_object(&dir.path().join("cas"));

    let out = boot_once(dir.path(), None);
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        out.status.success(),
        "rabsd did not exit clean:\nSTDOUT:{stdout}\nSTDERR:{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        stdout.contains("\"kind\":\"janitor-cas-mounted\""),
        "no mount line: {stdout}"
    );
    assert!(
        stdout.contains("\"kind\":\"janitor-gc-sweep\""),
        "no gc-sweep line — janitor does not own GC: {stdout}"
    );
    assert!(
        stdout.contains("\"kind\":\"janitor-store-usage\""),
        "no usage line: {stdout}"
    );
    // Seeded payload makes usage nonzero.
    let usage_line = stdout
        .lines()
        .find(|l| l.contains("\"kind\":\"janitor-store-usage\""))
        .expect("usage line");
    let bytes: u64 = usage_line
        .split("\"bytes\":")
        .nth(1)
        .and_then(|rest| rest.trim_end_matches('}').parse().ok())
        .expect("usage bytes parse");
    assert!(bytes > 0, "seeded object must count toward usage");
}

#[test]
fn daemon_janitor_publishes_quota_exceeded_loudly_and_stays_clean() {
    let dir = tempfile::tempdir().unwrap();
    seed_one_object(&dir.path().join("cas"));

    // Quota far below the seeded object: breach path.
    let out = boot_once(dir.path(), Some("10"));
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        out.status.success(),
        "quota breach must NOT crash the daemon (advisory-first):\nSTDOUT:{stdout}\nSTDERR:{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        stdout.contains("\"kind\":\"janitor-quota-exceeded\""),
        "breach must be published loudly: {stdout}"
    );
    // And the daemon still exits clean afterwards.
    assert!(
        stdout.contains("\"kind\":\"janitor-store-usage\""),
        "usage evidence follows the breach line: {stdout}"
    );
}
