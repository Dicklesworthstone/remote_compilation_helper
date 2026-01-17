//! E2E tests for self-test infrastructure (hash verification + remote compilation).

use anyhow::{Context, Result, bail};
use chrono::Utc;
use rch_common::binary_hash::compute_binary_hash;
use rch_common::e2e::RustProjectFixture;
use rch_common::remote_compilation::RemoteCompilationTest;
use rch_common::test_change::{TestChangeGuard, TestCodeChange};
use rch_common::types::{WorkerConfig, WorkerId};
use std::path::Path;
use std::time::Duration;
use tempfile::TempDir;
use tokio::process::Command;
use tokio::time::sleep;
use tracing::info;

fn init_test_logging() {
    let _ = tracing_subscriber::fmt()
        .with_test_writer()
        .with_max_level(tracing::Level::DEBUG)
        .try_init();
}

async fn build_release(project_dir: &Path) -> Result<()> {
    let output = Command::new("cargo")
        .arg("build")
        .arg("--release")
        .current_dir(project_dir)
        .env("CARGO_INCREMENTAL", "0")
        .output()
        .await
        .context("Failed to execute cargo build")?;

    if !output.status.success() {
        bail!(
            "Local build failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }

    Ok(())
}

fn binary_path(project_dir: &Path, name: &str) -> std::path::PathBuf {
    let target_dir = std::env::var_os("CARGO_TARGET_DIR")
        .map(std::path::PathBuf::from)
        .map(|path| {
            if path.is_absolute() {
                path
            } else {
                project_dir.join(path)
            }
        })
        .unwrap_or_else(|| project_dir.join("target"));

    target_dir.join("release").join(name)
}

fn load_worker_from_env() -> Option<WorkerConfig> {
    let host = std::env::var("RCH_E2E_WORKER_HOST").ok()?;
    if host.starts_with("mock://") {
        return None;
    }

    let user = std::env::var("RCH_E2E_WORKER_USER").unwrap_or_else(|_| whoami::username());
    let identity_file =
        std::env::var("RCH_E2E_WORKER_KEY").unwrap_or_else(|_| "~/.ssh/id_rsa".to_string());

    Some(WorkerConfig {
        id: WorkerId::new("e2e-worker"),
        host,
        user,
        identity_file,
        total_slots: 4,
        priority: 100,
        tags: Vec::new(),
    })
}

#[tokio::test]
async fn test_binary_hash_computation_e2e() {
    init_test_logging();
    info!("[e2e::self_test] TEST START: binary_hash_computation");

    let temp_dir = TempDir::new().expect("temp dir");
    let project = RustProjectFixture::minimal("hash_test");
    project.create_in(temp_dir.path()).expect("create project");

    build_release(temp_dir.path()).await.expect("local build");

    let bin_path = binary_path(temp_dir.path(), "hash_test");
    let hash1 = compute_binary_hash(&bin_path).expect("hash 1");
    let hash2 = compute_binary_hash(&bin_path).expect("hash 2");

    assert_eq!(hash1.code_hash, hash2.code_hash);
    assert!(!hash1.code_hash.is_empty());

    info!("[e2e::self_test] TEST PASS: binary_hash_computation");
}

#[tokio::test]
async fn test_code_change_produces_different_hash() {
    init_test_logging();
    info!("[e2e::self_test] TEST START: code_change_hash_diff");

    let suffix = Utc::now().timestamp_nanos_opt().unwrap_or(0);
    let project_name = format!("change_test_{}", suffix);

    let temp_dir = TempDir::new().expect("temp dir");
    let project = RustProjectFixture::minimal(&project_name);
    project.create_in(temp_dir.path()).expect("create project");

    info!("Building project {} in {:?}", project_name, temp_dir.path());
    build_release(temp_dir.path()).await.expect("initial build");

    let bin_path = binary_path(temp_dir.path(), &project_name);
    let hash1 = compute_binary_hash(&bin_path).expect("hash 1");

    let change = TestCodeChange::for_main_rs(temp_dir.path()).expect("test change");
    let _guard = TestChangeGuard::new(change).expect("apply test change");

    // Ensure filesystem timestamp advances so cargo detects the change.
    sleep(Duration::from_millis(1100)).await;

    // Touch the file to guarantee mtime update
    let main_rs = temp_dir.path().join("src/main.rs");
    let status = Command::new("touch")
        .arg(&main_rs)
        .status()
        .await
        .expect("touch command");
    assert!(status.success(), "touch failed");

    info!("Rebuilding project after change...");
    build_release(temp_dir.path())
        .await
        .expect("rebuild after change");

    let hash2 = compute_binary_hash(&bin_path).expect("hash 2");

    assert_ne!(hash1.code_hash, hash2.code_hash);

    info!("[e2e::self_test] TEST PASS: code_change_hash_diff");
}

#[tokio::test]
async fn test_remote_compilation_verification_e2e() {
    init_test_logging();
    info!("[e2e::self_test] TEST START: remote_compilation_verification");

    let Some(worker) = load_worker_from_env() else {
        info!("[e2e::self_test] SKIP: RCH_E2E_WORKER_HOST not set");
        return;
    };

    let temp_dir = TempDir::new().expect("temp dir");
    let project = RustProjectFixture::minimal("remote_test");
    project.create_in(temp_dir.path()).expect("create project");

    let test = RemoteCompilationTest::new(worker, temp_dir.path().to_path_buf());
    let result = test.run().await.expect("remote compilation test");

    assert!(
        result.success,
        "remote verification failed: {:?}",
        result.error
    );
    assert_eq!(result.local_hash.code_hash, result.remote_hash.code_hash);

    info!("[e2e::self_test] TEST PASS: remote_compilation_verification");
}
