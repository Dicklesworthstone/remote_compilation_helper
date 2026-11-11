//! Run the actual native source-retirement command against real directories.

#![cfg(target_os = "linux")]
#![forbid(unsafe_code)]

use std::os::unix::fs::{MetadataExt, symlink};
use std::path::Path;
use std::process::{Command, Output, Stdio};

const IDENTITY: &str = "1234567890abcdef1234567890abcdef";

fn retain_command(source: &Path, retained: &Path, identity: &str, allow_absent: bool) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_rch-wkr"));
    command
        .args(["source-retain", "retain"])
        .arg(source)
        .arg(retained)
        .arg(identity)
        .arg(if allow_absent { "1" } else { "0" })
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    command
}

fn assert_refused(output: &Output) {
    assert_eq!(output.status.code(), Some(74), "{output:?}");
    assert!(output.stdout.is_empty(), "{output:?}");
    assert!(
        String::from_utf8_lossy(&output.stderr).starts_with("RCH_SOURCE_RETENTION_REFUSED:"),
        "{output:?}",
    );
}

#[test]
fn capability_reports_real_linux_no_replace_support_without_runtime_output() {
    let output = Command::new(env!("CARGO_BIN_EXE_rch-wkr"))
        .args(["source-retain", "probe"])
        .output()
        .unwrap();
    assert!(output.status.success(), "{output:?}");
    assert_eq!(output.stdout, b"rch-wkr source-retain v1\n");
    assert!(output.stderr.is_empty(), "{output:?}");
}

#[test]
fn worker_moves_exact_source_once_and_retains_its_sealed_identity() {
    let owner = tempfile::tempdir().unwrap();
    let source = owner.path().join("source α ' \" $literal `path`");
    let retained = owner.path().join("retained α ' \" $literal `path`");
    std::fs::create_dir(&source).unwrap();
    std::fs::write(source.join("input"), b"\0complete source\xff").unwrap();
    symlink("input", source.join("link")).unwrap();
    let inode = std::fs::metadata(&source).unwrap().ino();
    for _ in 0..2 {
        let output = retain_command(&source, &retained, IDENTITY, false)
            .env("PATH", owner.path().join("no-tools"))
            .output()
            .unwrap();
        assert!(output.status.success(), "{output:?}");
        assert_eq!(output.stdout, b"RCH_SOURCE_RETAINED\n");
        assert!(output.stderr.is_empty(), "{output:?}");
        assert!(!source.exists());
        assert_eq!(std::fs::metadata(&retained).unwrap().ino(), inode);
        assert_eq!(
            std::fs::read(retained.join("input")).unwrap(),
            b"\0complete source\xff"
        );
        assert_eq!(
            std::fs::read_link(retained.join("link")).unwrap(),
            Path::new("input")
        );
        assert!(retained.join(".rch-retention-v1").is_symlink());
    }
    let output = retain_command(
        &source,
        &retained,
        "abcdef1234567890abcdef1234567890",
        false,
    )
    .output()
    .unwrap();
    assert_refused(&output);
    assert_eq!(std::fs::metadata(retained).unwrap().ino(), inode);
}

#[test]
fn absence_is_explicit_and_symlinks_or_invalid_requests_never_report_completion() {
    let owner = tempfile::tempdir().unwrap();
    let source = owner.path().join("source");
    let retained = owner.path().join("retained");
    assert_refused(
        &retain_command(&source, &retained, IDENTITY, false)
            .output()
            .unwrap(),
    );
    let absent = retain_command(&source, &retained, IDENTITY, true)
        .output()
        .unwrap();
    assert!(absent.status.success(), "{absent:?}");
    assert_eq!(absent.stdout, b"RCH_SOURCE_ABSENT_BEFORE_MATERIALIZATION\n");
    assert!(absent.stderr.is_empty(), "{absent:?}");
    symlink("missing", &source).unwrap();
    assert_refused(
        &retain_command(&source, &retained, IDENTITY, true)
            .output()
            .unwrap(),
    );
    assert_refused(
        &retain_command(&source, &retained, "invalid", true)
            .output()
            .unwrap(),
    );
    assert!(source.is_symlink());
    assert!(!retained.exists());
}

#[test]
fn competing_retirements_never_overwrite_the_winning_tree() {
    let owner = tempfile::tempdir().unwrap();
    let first = owner.path().join("first");
    let second = owner.path().join("second");
    let retained = owner.path().join("retained");
    for (source, bytes) in [
        (&first, b"first".as_slice()),
        (&second, b"second".as_slice()),
    ] {
        std::fs::create_dir(source).unwrap();
        std::fs::write(source.join("input"), bytes).unwrap();
    }
    let first_child = retain_command(&first, &retained, IDENTITY, false)
        .spawn()
        .unwrap();
    let second_child = retain_command(&second, &retained, IDENTITY, false)
        .spawn()
        .unwrap();
    let first_output = first_child.wait_with_output().unwrap();
    let second_output = second_child.wait_with_output().unwrap();
    assert_ne!(
        first_output.status.success(),
        second_output.status.success(),
        "{first_output:?}\n{second_output:?}"
    );
    let (winner, loser, refused) = if first_output.status.success() {
        (b"first".as_slice(), &second, &second_output)
    } else {
        (b"second".as_slice(), &first, &first_output)
    };
    assert_refused(refused);
    assert_eq!(std::fs::read(retained.join("input")).unwrap(), winner);
    assert!(loser.join("input").is_file());
}
