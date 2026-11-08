//! The actual worker must bind the accepted attempt before running a workload.
#![cfg(target_os = "linux")]

use rch_common::prepared_dependencies::{
    PreparedDependencyAttestation, PreparedDependencyFile, PreparedDependencyFileKind,
    PreparedDependencyRequest,
};
use sha2::{Digest, Sha256};
use std::fs;
use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::process::{Command, Output, Stdio};

fn selected(path: &str, bytes: &[u8]) -> PreparedDependencyFile {
    let mut sha256 = String::with_capacity(64);
    for byte in Sha256::digest(bytes) {
        use std::fmt::Write;
        write!(&mut sha256, "{byte:02x}").unwrap();
    }
    PreparedDependencyFile {
        path: path.to_owned(),
        kind: PreparedDependencyFileKind::Regular,
        sha256,
        byte_count: bytes.len() as u64,
        executable: false,
        symlink_target: None,
    }
}

fn command(root: &Path, project: &Path, mode: &str) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_rch-wkr"));
    command
        .env_clear()
        .env("HOME", root.join("home"))
        .env("XDG_CACHE_HOME", root.join("cache"))
        .env(
            "PATH",
            format!("{}:/usr/bin:/bin", root.join("bin").display()),
        )
        .env("TOKIO_WORKER_THREADS", "2")
        .env("RCH_PREPARE_INSTALL_TIMEOUT_SECS", "3")
        .env("RCH_TEST_INSTALL_COUNT", root.join("installer-count"))
        .args(["prepare-proof", "--mode", mode, "--project"])
        .arg(project)
        .args(["--runtime", "node"])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    command
}

fn install(
    root: &Path,
    project: &Path,
    request: &PreparedDependencyRequest,
) -> PreparedDependencyAttestation {
    let mut child = command(root, project, "install")
        .stdin(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(&serde_json::to_vec(request).unwrap())
        .unwrap();
    let result = child.wait_with_output().unwrap();
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    serde_json::from_slice(&result.stdout).unwrap()
}

fn verify(
    root: &Path,
    project: &Path,
    request: &PreparedDependencyRequest,
    attestation: &PreparedDependencyAttestation,
) -> Output {
    command(root, project, "verify")
        .args(["--expected-request-digest", &request.digest().unwrap()])
        .args([
            "--expected-attestation-digest",
            &attestation.digest().unwrap(),
        ])
        .output()
        .unwrap()
}

#[test]
fn verify_uses_stored_request_without_stdin_and_rejects_old_attempts_or_changed_outputs() {
    let fixture = tempfile::tempdir().unwrap();
    let root = fixture.path();
    let project = root.join("project");
    for name in ["project", "home", "bin"] {
        fs::create_dir(root.join(name)).unwrap();
    }
    let manifest = b"{\"name\":\"prepared-output-fixture\"}\n";
    let lock = b"{\"lockfileVersion\":3}\n";
    fs::write(project.join("package.json"), manifest).unwrap();
    fs::write(project.join("package-lock.json"), lock).unwrap();
    let manager = root.join("bin/npm");
    fs::write(&manager, b"#!/bin/sh\nset -eu\n[ \"$#\" = 1 ] && [ \"$1\" = ci ]\nmkdir -p node_modules\nprintf 'verified output\\n' > node_modules/dependency.js\nprintf 'install\\n' >> \"$RCH_TEST_INSTALL_COUNT\"\n").unwrap();
    fs::set_permissions(&manager, fs::Permissions::from_mode(0o700)).unwrap();
    let mut request = PreparedDependencyRequest {
        schema_version: 1,
        attempt_id: "attempt-first".to_owned(),
        source_owner: "12345678-1234-1234-1234-123456789abc".to_owned(),
        build_id: "12345".to_owned(),
        command_sha256: "a".repeat(64),
        source_content_root: "b".repeat(64),
        source_root: project.to_str().unwrap().to_owned(),
        project_relative: String::new(),
        files: vec![
            selected("package-lock.json", lock),
            selected("package.json", manifest),
        ],
        directories: Vec::new(),
    };
    let first = install(root, &project, &request);
    let result = verify(root, &project, &request, &first);
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    assert_eq!(result.stdout, b"RCH_PREPARED_DEPENDENCIES_VERIFIED\n");
    assert_eq!(
        fs::read(root.join("installer-count")).unwrap(),
        b"install\n"
    );

    let old_request = request.clone();
    request.attempt_id = "attempt-next".to_owned();
    let second = install(root, &project, &request);
    assert!(verify(root, &project, &request, &second).status.success());
    let replay = verify(root, &project, &old_request, &first);
    assert!(
        !replay.status.success(),
        "an old accepted attempt cannot execute after replacement"
    );
    assert!(String::from_utf8_lossy(&replay.stderr).contains("does not match"));
    assert_eq!(
        fs::read(root.join("installer-count")).unwrap(),
        b"install\n"
    );

    fs::write(
        project.join("node_modules/dependency.js"),
        b"tampered output\n",
    )
    .unwrap();
    let tampered = verify(root, &project, &request, &second);
    assert!(!tampered.status.success());
    assert!(String::from_utf8_lossy(&tampered.stderr).contains("inventory changed"));
    assert_eq!(
        fs::read(root.join("installer-count")).unwrap(),
        b"install\n"
    );
}
