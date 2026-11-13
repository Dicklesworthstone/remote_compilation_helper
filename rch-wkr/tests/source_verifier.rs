//! Verify source-content frames through the real synchronous worker command.
#![cfg(unix)]

use sha2::{Digest as _, Sha256};
use std::fmt::Write as _;
use std::fs;
use std::io::Write as _;
use std::os::unix::fs::{PermissionsExt as _, symlink};
use std::path::Path;
use std::process::{Command, Output, Stdio};

fn fixture() -> tempfile::TempDir {
    let directory = tempfile::Builder::new()
        .prefix("source-verifier-cli-")
        .disable_cleanup(true)
        .tempdir()
        .unwrap();
    fs::write(directory.path().join("blocked-log"), b"keep").unwrap();
    directory
}

fn command(directory: &Path) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_rch-wkr"));
    command
        .arg("verify-source-content")
        .env_clear()
        .env("PATH", directory.join("no-executables"))
        .env("TOKIO_WORKER_THREADS", "0")
        .env("RCH_LOG_FILE", directory.join("blocked-log/worker.log"))
        .current_dir(directory)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    command
}

fn row(path: &str, bytes: &[u8], kind: &str) -> String {
    let mut digest = String::with_capacity(64);
    for byte in Sha256::digest(bytes) {
        write!(&mut digest, "{byte:02x}").unwrap();
    }
    format!("{digest}\t{}\t{kind}\t{path}\n", bytes.len())
}

fn verify(directory: &Path, root: &Path, count: &str, total: &str, manifest: &[u8]) -> Output {
    let mut child = command(directory)
        .arg("verify")
        .arg(root)
        .args([count, total])
        .stdin(Stdio::piped())
        .spawn()
        .unwrap();
    match child.stdin.take().unwrap().write_all(manifest) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::BrokenPipe => {}
        Err(error) => panic!("write test manifest: {error}"),
    }
    child.wait_with_output().unwrap()
}

fn assert_status(output: &Output, code: i32) {
    assert_eq!(
        output.status.code(),
        Some(code),
        "stdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn probe_needs_neither_runtime_logging_nor_host_utilities() {
    let directory = fixture();
    let output = command(directory.path())
        .arg("probe")
        .stdin(Stdio::null())
        .output()
        .unwrap();
    assert_status(&output, 0);
    assert_eq!(output.stdout, b"RCH_SOURCE_CONTENT_VERIFIER_V1\n");
    assert!(output.stderr.is_empty());
    let extra = command(directory.path())
        .args(["probe", "extra"])
        .stdin(Stdio::null())
        .output()
        .unwrap();
    assert_status(&extra, 69);
    assert!(extra.stdout.is_empty());
}

#[test]
fn stdin_manifest_verifies_literal_binary_executable_and_link_bytes() {
    let directory = fixture();
    let root = directory.path().join("root ' ; $(touch injected)");
    fs::create_dir_all(root.join("nested")).unwrap();
    let name = "nested/input ' ; $(touch injected) café.bin";
    let bytes = b"\0binary\xff\nbytes";
    fs::write(root.join(name), bytes).unwrap();
    fs::write(root.join("empty"), b"").unwrap();
    fs::write(root.join("executable"), b"run").unwrap();
    for path in [name, "empty"] {
        fs::set_permissions(root.join(path), fs::Permissions::from_mode(0o644)).unwrap();
    }
    fs::set_permissions(root.join("executable"), fs::Permissions::from_mode(0o755)).unwrap();
    let target = "../executable";
    symlink(target, root.join("nested/link")).unwrap();
    let alias = directory.path().join("root-alias");
    symlink(&root, &alias).unwrap();
    let manifest = row(name, bytes, "0")
        + &row("empty", b"", "0")
        + &row("executable", b"run", "1")
        + &row("nested/link", target.as_bytes(), "L");
    let total = bytes.len() + b"run".len() + target.len();
    let output = verify(
        directory.path(),
        &alias,
        "4",
        &total.to_string(),
        manifest.as_bytes(),
    );
    assert_status(&output, 0);
    assert_eq!(
        output.stdout,
        format!("RCH_SOURCE_CONTENT_VERIFIED\t4\t{total}\n").as_bytes()
    );
    assert!(output.stderr.is_empty());
    assert_eq!(fs::read(root.join(name)).unwrap(), bytes);
    assert_eq!(
        fs::read_link(root.join("nested/link")).unwrap(),
        Path::new(target)
    );
    assert!(!directory.path().join("injected").exists());
    assert!(!root.join("injected").exists());
    let empty = verify(directory.path(), &root, "0", "0", b"");
    assert_status(&empty, 0);
    assert_eq!(empty.stdout, b"RCH_SOURCE_CONTENT_VERIFIED\t0\t0\n");
    assert!(empty.stderr.is_empty());
}

#[test]
fn refusal_frames_preserve_status_and_never_publish_partial_verification() {
    let directory = fixture();
    let root = directory.path().join("root");
    fs::create_dir(&root).unwrap();
    let path = root.join("source");
    fs::write(&path, b"data").unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
    let valid = row("source", b"data", "0");
    for (manifest, count, total, status, reason) in [
        (row("source", b"fake", "0"), "1", "4", 65, "sha256:source"),
        (row("source", b"data", "1"), "1", "4", 66, "mode:source"),
        (row("../outside", b"data", "0"), "1", "4", 62, "unsafe_path"),
        (valid.clone(), "2", "4", 67, "count:1"),
        (valid.clone(), "1", "5", 68, "bytes:4"),
        (valid.clone(), "1", "3", 68, "bytes:source"),
        (valid.replace("\t4\t", "\t5\t"), "1", "4", 64, "size:source"),
        (
            valid.clone() + &row("source", b"data", "L"),
            "2",
            "8",
            63,
            "not_symlink:source",
        ),
        (valid.clone() + &valid, "2", "8", 69, "read_or_manifest"),
        (valid.trim_end().to_owned(), "1", "4", 67, "count"),
        (valid, "01", "4", 69, "read_or_manifest"),
    ] {
        let output = verify(directory.path(), &root, count, total, manifest.as_bytes());
        assert_status(&output, status);
        assert!(output.stdout.is_empty());
        assert_eq!(
            output.stderr,
            format!("RCH_SOURCE_CONTENT_ERROR:{reason}\n").as_bytes()
        );
        assert_eq!(fs::read(&path).unwrap(), b"data");
        assert_eq!(
            fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o644
        );
    }
}
