//! Exercise periodic physical GC through the real daemon, with actual CAS bytes.
//! Uses the prebuilt Cargo test binary, never a nested Cargo build. No SSH,
//! compiler execution, served-cache hit, or fleet qualification is claimed.
#![cfg(unix)]

use rabs_cas::blob_store::{DurabilityPolicy, PutLimits, RAW_PROFILE_V1, put_if_absent};
use rabs_cas::digest_set::{DigestRequest, digest_set};
use rabs_cas::metadata_store::{RabsMetadataStore, digest_key};
use rabsd::janitor::store::mount_and_reconcile;
use serde_json::Value;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::time::{Duration, Instant};

struct Seeded {
    root: tempfile::TempDir,
    orphan: PathBuf,
    pinned: PathBuf,
    orphan_key: String,
}

fn seed() -> Seeded {
    let root = tempfile::tempdir().unwrap();
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let cas = mount_and_reconcile(&root.path().join("cas")).unwrap();
    let mut store = cas.store().lock().unwrap();
    let mut paths = Vec::new();
    let mut orphan_key = String::new();
    for (index, bytes) in [
        b"collect these raw bytes".as_slice(),
        b"retain pinned raw bytes",
    ]
    .into_iter()
    .enumerate()
    {
        let object = digest_set(bytes, DigestRequest::default(), None)
            .unwrap()
            .atp_content_id;
        put_if_absent(
            cas.layout(),
            &mut *store,
            &object,
            &mut &bytes[..],
            PutLimits::default(),
            DurabilityPolicy::FULL,
        )
        .unwrap();
        paths.push(
            cas.layout()
                .published_path(&object, RAW_PROFILE_V1, &object),
        );
        if index == 0 {
            orphan_key = digest_key(&object);
        } else {
            store
                .create_pin(
                    71,
                    &object,
                    "coordinator",
                    "action-publication",
                    None,
                    None,
                    true,
                    "fixture retained root",
                )
                .unwrap();
        }
    }
    drop(store);
    drop(cas);
    Seeded {
        root,
        orphan: paths[0].clone(),
        pinned: paths[1].clone(),
        orphan_key,
    }
}

fn boot(root: &Path, reclaim: &str) -> Output {
    // Files hold logs so a full stdout pipe cannot deadlock this regression.
    // Bound the outer process too: shutdown regressions must fail, not hang CI.
    let stdout = root.join(format!("gc-{reclaim}-stdout"));
    let stderr = root.join(format!("gc-{reclaim}-stderr"));
    let mut child = Command::new(env!("CARGO_BIN_EXE_rabsd"))
        .args(["--run-for-ms", "4500"])
        .env("RABS_SOCKET_PATH", root.join("edge.sock"))
        .env("RABS_BOOT_MARKER", root.join("boot.marker"))
        .env("RABS_STATE_DIR", root)
        .env("RABS_CONFIG", root.join("no-config.toml"))
        .env("RABS_LIVE_DEPENDENCY", "0")
        .env("RABS_GC_RECLAIM", reclaim)
        .env("RABS_GC_INTERVAL_SECS", "1")
        .env("RABS_GC_GRACE_SECS", "1")
        .env("RABS_GC_MAX_LOCATIONS", "1")
        .env("RABS_QUOTA_BYTES", "10")
        .env_remove("RABS_LAB_COORD_DOWN")
        .stdin(Stdio::null())
        .stdout(fs::File::create(&stdout).unwrap())
        .stderr(fs::File::create(&stderr).unwrap())
        .spawn()
        .unwrap();
    let deadline = Instant::now() + Duration::from_secs(20);
    let status = loop {
        if let Some(status) = child.try_wait().unwrap() {
            break status;
        }
        if Instant::now() >= deadline {
            // This is the exact child created by this test, not a PID search.
            let _ = child.kill();
            let _ = child.wait();
            panic!(
                "janitor daemon did not stop; stderr: {}",
                fs::read_to_string(&stderr).unwrap()
            );
        }
        std::thread::sleep(Duration::from_millis(20));
    };
    Output {
        status,
        stdout: fs::read(stdout).unwrap(),
        stderr: fs::read(stderr).unwrap(),
    }
}

fn events(output: &Output) -> Vec<Value> {
    assert!(
        output.status.success(),
        "daemon failed: {}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8_lossy(&output.stdout)
        .lines()
        .filter_map(|line| serde_json::from_str(line).ok())
        .collect()
}

#[test]
fn running_daemon_reclaims_after_grace_preserves_pins_and_repeats_without_double_accounting() {
    let fixture = seed();
    let output = boot(fixture.root.path(), "1");
    let records = events(&output);
    let sweeps: Vec<_> = records
        .iter()
        .filter(|row| row["kind"] == "janitor-physical-gc")
        .collect();
    assert!(sweeps.len() >= 3, "periodic sweeps missing: {records:?}");
    assert!(
        sweeps
            .iter()
            .any(|row| row["observed"] == 1 && row["unlinked_files"] == 0),
        "no separate mark/grace observation: {records:?}"
    );
    assert_eq!(
        sweeps
            .iter()
            .map(|row| row["unlinked_files"].as_u64().unwrap())
            .sum::<u64>(),
        1
    );
    assert_eq!(
        sweeps
            .iter()
            .map(|row| row["unlinked_bytes"].as_u64().unwrap())
            .sum::<u64>(),
        b"collect these raw bytes".len() as u64
    );
    assert!(
        !fixture.orphan.exists(),
        "metadata-only GC left the physical payload behind"
    );
    assert_eq!(
        fs::read(&fixture.pinned).unwrap(),
        b"retain pinned raw bytes"
    );
    assert!(
        records
            .iter()
            .filter(|row| row["kind"] == "janitor-store-usage")
            .count()
            >= 3
    );
    // Child shutdown joins maintenance and releases the real mount. Verify
    // retained metadata directly, not from a log's claimed reclaimed count.
    let reopened = mount_and_reconcile(&fixture.root.path().join("cas")).unwrap();
    assert!(!reopened.serving_refused);
    let mut store = reopened.store().lock().unwrap();
    let rows = store
        .query(
            "SELECT store_path FROM object_locations WHERE object_key = ?1",
            &[rabs_cas::metadata_store::SqlValue::Text(fixture.orphan_key)],
        )
        .unwrap();
    assert!(rows.is_empty());
    assert_eq!(store.gc_snapshot(999).unwrap().pinned_roots.len(), 1);
}

#[test]
fn recurring_accounting_and_quota_breach_never_enable_physical_deletion_implicitly() {
    let fixture = seed();
    let output = boot(fixture.root.path(), "0");
    let records = events(&output);
    assert!(records.iter().any(|row| row["kind"] == "janitor-gc-sweep"));
    assert!(
        records
            .iter()
            .filter(|row| row["kind"] == "janitor-store-usage")
            .count()
            >= 3
    );
    assert!(
        records
            .iter()
            .any(|row| row["kind"] == "janitor-quota-exceeded")
    );
    assert!(
        !records
            .iter()
            .any(|row| row["kind"] == "janitor-physical-gc")
    );
    assert_eq!(
        fs::read(&fixture.orphan).unwrap(),
        b"collect these raw bytes"
    );
    assert_eq!(
        fs::read(&fixture.pinned).unwrap(),
        b"retain pinned raw bytes"
    );
    assert!(mount_and_reconcile(&fixture.root.path().join("cas")).is_ok());
}
