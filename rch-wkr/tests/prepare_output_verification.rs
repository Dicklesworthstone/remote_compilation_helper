//! The actual worker must bind the accepted attempt before running a workload.
#![cfg(target_os = "linux")]

use rch_common::prepared_dependencies::{
    PreparedDependencyAttestation, PreparedDependencyDisposition, PreparedDependencyFile,
    PreparedDependencyFileKind, PreparedDependencyRequest,
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
    verify_from(root, project, request, attestation, None)
}

fn verify_from(
    root: &Path,
    project: &Path,
    request: &PreparedDependencyRequest,
    attestation: &PreparedDependencyAttestation,
    invocation: Option<&Path>,
) -> Output {
    let mut command = command(root, project, "verify");
    if let Some(invocation) = invocation {
        command
            .current_dir(invocation)
            .args(["--invocation-project", "."]);
    }
    command
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
    fs::write(&manager, b"#!/bin/sh\nset -eu\n[ \"$#\" = 3 ] && [ \"$1\" = --prefix ] && [ \"$2\" = \"$PWD\" ] && [ \"$3\" = ci ]\nmkdir -p node_modules\nprintf 'verified output\\n' > node_modules/dependency.js\nprintf 'install\\n' >> \"$RCH_TEST_INSTALL_COUNT\"\n").unwrap();
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
        preparation_relative: None,
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

#[test]
fn workspace_verification_requires_the_accepted_member_cwd_and_reuses_one_root_install() {
    let fixture = tempfile::tempdir().unwrap();
    let root = fixture.path();
    let project = root.join("project");
    for name in [
        "project/packages/a/src",
        "project/packages/b/tests",
        "home",
        "bin",
    ] {
        fs::create_dir_all(root.join(name)).unwrap();
    }
    let manifest = br#"{"name":"root","private":true,"workspaces":["packages/*"]}"#;
    let lock = b"{\"lockfileVersion\":3}\n";
    let member_a_manifest = br#"{"name":"member-a"}"#;
    let member_b_manifest = br#"{"name":"member-b"}"#;
    fs::write(project.join("package.json"), manifest).unwrap();
    fs::write(project.join("package-lock.json"), lock).unwrap();
    fs::write(project.join("packages/a/package.json"), member_a_manifest).unwrap();
    fs::write(project.join("packages/b/package.json"), member_b_manifest).unwrap();
    fs::write(project.join("packages/a/src/index.ts"), b"export {};\n").unwrap();
    fs::write(
        project.join("packages/b/tests/member.test.ts"),
        b"export {};\n",
    )
    .unwrap();
    let manager = root.join("bin/npm");
    fs::write(
        &manager,
        br#"#!/bin/sh
set -eu
[ "$#" = 3 ] && [ "$1" = --prefix ] && [ "$2" = "$PWD" ] && [ "$3" = ci ]
mkdir -p node_modules
printf 'root-owned output\n' > node_modules/dependency.js
printf 'install\n' >> "$RCH_TEST_INSTALL_COUNT"
"#,
    )
    .unwrap();
    fs::set_permissions(&manager, fs::Permissions::from_mode(0o700)).unwrap();
    let mut request = PreparedDependencyRequest {
        schema_version: 1,
        attempt_id: "member-a".to_owned(),
        source_owner: "12345678-1234-1234-1234-123456789abc".to_owned(),
        build_id: "12345".to_owned(),
        command_sha256: "a".repeat(64),
        source_content_root: "b".repeat(64),
        source_root: project.to_str().unwrap().to_owned(),
        project_relative: "packages/a".to_owned(),
        preparation_relative: Some(String::new()),
        files: vec![
            selected("package-lock.json", lock),
            selected("package.json", manifest),
            selected("packages/a/package.json", member_a_manifest),
            selected("packages/a/src/index.ts", b"export {};\n"),
            selected("packages/b/package.json", member_b_manifest),
            selected("packages/b/tests/member.test.ts", b"export {};\n"),
        ],
        directories: vec![
            "packages".to_owned(),
            "packages/a".to_owned(),
            "packages/a/src".to_owned(),
            "packages/b".to_owned(),
            "packages/b/tests".to_owned(),
        ],
    };
    let member_a = project.join("packages/a");
    let member_b = project.join("packages/b");
    let first = install(root, &project, &request);
    assert_eq!(first.state.project, project.to_str().unwrap());
    let missing = verify(root, &project, &request, &first);
    assert!(!missing.status.success());
    assert!(String::from_utf8_lossy(&missing.stderr).contains("requires --invocation-project"));
    for wrong in [&project, &member_b] {
        let result = verify_from(root, &project, &request, &first, Some(wrong));
        assert!(!result.status.success());
        assert!(String::from_utf8_lossy(&result.stderr).contains("invocation directory"));
    }
    assert!(
        verify_from(root, &project, &request, &first, Some(&member_a))
            .status
            .success()
    );

    let old_request = request.clone();
    request.attempt_id = "member-b".to_owned();
    request.project_relative = "packages/b".to_owned();
    let second = install(root, &project, &request);
    assert_eq!(second.disposition, PreparedDependencyDisposition::Retained);
    assert_eq!(second.state, first.state);
    assert!(
        verify_from(root, &project, &request, &second, Some(&member_b))
            .status
            .success()
    );
    assert!(
        !verify_from(root, &project, &old_request, &first, Some(&member_a))
            .status
            .success()
    );
    assert_eq!(
        fs::read(root.join("installer-count")).unwrap(),
        b"install\n"
    );
    assert!(project.join("node_modules/dependency.js").is_file());
    assert!(!member_a.join("node_modules").exists());
    assert!(!member_b.join("node_modules").exists());

    for relative in ["packages/a/src", "packages/b/tests"] {
        request.attempt_id = relative.replace('/', "-");
        request.project_relative = relative.to_owned();
        let nested = project.join(relative);
        let proof = install(root, &project, &request);
        assert_eq!(proof.disposition, PreparedDependencyDisposition::Retained);
        assert_eq!(proof.state, first.state);
        let verified = verify_from(root, &project, &request, &proof, Some(&nested));
        assert!(
            verified.status.success(),
            "{}",
            String::from_utf8_lossy(&verified.stderr)
        );
        for wrong in [&project, &member_a, &member_b] {
            let refused = verify_from(root, &project, &request, &proof, Some(wrong));
            assert!(!refused.status.success(), "{relative}: {}", wrong.display());
            assert!(String::from_utf8_lossy(&refused.stderr).contains("invocation directory"));
        }
        assert!(!nested.join("node_modules").exists());
    }
    assert_eq!(
        fs::read(root.join("installer-count")).unwrap(),
        b"install\n"
    );
}
