//! Exercise the worker's actual internal header-probe command and wire format.

#![cfg(unix)]
#![forbid(unsafe_code)]

use std::io::Write;
use std::os::unix::fs::symlink;
use std::process::{Command, Output, Stdio};

fn inspect(input: &[u8]) -> Output {
    let mut child = Command::new(env!("CARGO_BIN_EXE_rch-wkr"))
        .args(["artifact-headers", "inspect"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child.stdin.take().unwrap().write_all(input).unwrap();
    child.wait_with_output().unwrap()
}

#[test]
fn capability_probe_runs_without_log_or_runtime_output() {
    let output = Command::new(env!("CARGO_BIN_EXE_rch-wkr"))
        .args(["artifact-headers", "probe"])
        .output()
        .unwrap();
    assert!(output.status.success(), "{output:?}");
    assert_eq!(output.stdout, b"rch-wkr artifact-headers v1\n");
    assert!(output.stderr.is_empty(), "{output:?}");
}

#[test]
fn worker_returns_exact_bounded_header_bytes_from_authorized_cargo_target() {
    let owner = tempfile::tempdir().unwrap();
    let source = owner.path().join("source");
    let target = owner.path().join("pool");
    std::fs::create_dir(&source).unwrap();
    std::fs::create_dir_all(target.join("debug")).unwrap();
    symlink(&target, source.join("target")).unwrap();
    let contents: Vec<u8> = (0..=255).collect();
    std::fs::write(target.join("debug/é 'binary"), &contents).unwrap();
    let relative = "target/debug/é 'binary";
    let input = serde_json::to_vec(&(
        source.to_str().unwrap(),
        Some(target.to_str().unwrap()),
        [relative],
    ))
    .unwrap();
    let output = inspect(&input);
    assert!(output.status.success(), "{output:?}");
    assert!(output.stderr.is_empty(), "{output:?}");
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&output.stdout).unwrap(),
        serde_json::json!([[relative, contents[..64]]]),
    );
}

#[test]
fn unsafe_or_failed_inventory_emits_no_partial_json() {
    let owner = tempfile::tempdir().unwrap();
    std::fs::write(owner.path().join("good"), b"\x7fELF").unwrap();
    symlink(owner.path().join("good"), owner.path().join("linked")).unwrap();
    for path in ["missing", "linked", "../outside", "good\nextra"] {
        let input =
            serde_json::to_vec(&(owner.path().to_str().unwrap(), None::<&str>, ["good", path]))
                .unwrap();
        let output = inspect(&input);
        assert_eq!(output.status.code(), Some(73), "{path:?}: {output:?}");
        assert!(output.stdout.is_empty(), "{path:?}: {output:?}");
        assert!(
            String::from_utf8_lossy(&output.stderr).starts_with("RCH_ARTIFACT_HEADERS_UNSAFE "),
            "{path:?}: {output:?}",
        );
    }
}
