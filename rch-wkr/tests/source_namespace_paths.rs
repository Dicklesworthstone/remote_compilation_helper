//! Run both packaged source-topology adapters against this exact worker build.
#![cfg(unix)]

use rch_common::source_namespace_paths::{PROBE_REPLY, REFUSAL_EXIT, shell_script};
use std::fs;
use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _, symlink};
use std::path::Path;
use std::process::{Command, Output};

const ADAPTERS: [&str; 2] = [
    include_str!("../../rch/src/hook/source_namespace_paths.sh"),
    include_str!("../../rchd/src/source_namespace_paths.sh"),
];

fn command(adapter: &str, directory: &Path) -> Command {
    let mut command = Command::new("/bin/sh");
    command
        .arg("-c")
        .arg(shell_script(adapter))
        .arg("rch-source-namespace")
        .env_clear()
        // Native path resolution and creation must not need host utilities.
        .env("PATH", directory.join("no-executables"))
        .env("RCH_WKR_BIN", env!("CARGO_BIN_EXE_rch-wkr"))
        .current_dir(directory);
    command
}

fn assert_status(output: &Output, status: i32) {
    assert_eq!(
        output.status.code(),
        Some(status),
        "stdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

fn report(output: &Output, expected: &str) -> serde_json::Value {
    assert!(output.stderr.is_empty());
    assert!(output.stdout.is_ascii());
    let stdout = std::str::from_utf8(&output.stdout).unwrap();
    assert_eq!(stdout.lines().count(), 1);
    let value: serde_json::Value = serde_json::from_str(
        stdout
            .strip_prefix("RCH_SOURCE_TOPOLOGY_CHECK_V1 ")
            .expect("versioned topology report"),
    )
    .unwrap();
    assert_eq!(value["outcome"], expected);
    value
}

#[test]
fn capability_probe_has_no_runtime_or_logging_output() {
    let fixture = tempfile::tempdir().unwrap();
    let not_a_directory = fixture.path().join("not-a-log-directory");
    fs::write(&not_a_directory, b"keep").unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_rch-wkr"))
        .args(["source-namespace-paths", "probe"])
        .env("RUST_LOG", "trace")
        .env("RCH_LOG_FILE", not_a_directory.join("worker.log"))
        .env("TOKIO_WORKER_THREADS", "0")
        .output()
        .unwrap();
    assert_status(&output, 0);
    assert_eq!(output.stdout, format!("{PROBE_REPLY}\n").as_bytes());
    assert!(output.stderr.is_empty());
}

#[test]
fn adapters_create_and_report_literal_paths_without_host_utilities() {
    for adapter in ADAPTERS {
        let fixture = tempfile::tempdir().unwrap();
        let root = fs::canonicalize(fixture.path()).unwrap();
        let canonical = root.join("canonical ' \" ; $(touch injected)");
        let alias = root.join("alias $HOME ' \" ; $(touch injected)");
        let missing = command(adapter, &root)
            .arg("check")
            .arg(&canonical)
            .arg(&alias)
            .arg("--report-json")
            .output()
            .unwrap();
        assert_status(&missing, 1);
        report(&missing, "canonical_missing");
        assert_eq!(fs::read_dir(&root).unwrap().count(), 0);

        for _ in 0..2 {
            let created = command(adapter, &root)
                .arg("create")
                .arg(&canonical)
                .arg(&alias)
                .output()
                .unwrap();
            assert_status(&created, 0);
            assert!(created.stdout.is_empty() && created.stderr.is_empty());
            assert_eq!(fs::read_link(&alias).unwrap(), canonical);
            let checked = command(adapter, &root)
                .arg("check")
                .arg(&canonical)
                .arg(&alias)
                .arg("--report-json")
                .output()
                .unwrap();
            assert_status(&checked, 0);
            let observed = report(&checked, "compatible");
            assert_eq!(observed["canonical"], canonical.to_str().unwrap());
            assert_eq!(observed["alias"], alias.to_str().unwrap());
            assert_eq!(observed["canonical_physical"], canonical.to_str().unwrap());
            assert_eq!(observed["alias_physical"], canonical.to_str().unwrap());
            assert_eq!(fs::read_dir(&root).unwrap().count(), 2);
            assert_eq!(fs::read_dir(&canonical).unwrap().count(), 0);
        }
    }
}

#[test]
fn missing_and_old_workers_refuse_before_any_path_mutation() {
    for adapter in ADAPTERS {
        let fixture = tempfile::tempdir().unwrap();
        let root = fixture.path();
        let canonical = root.join("canonical");
        let alias = root.join("alias");
        let invoked = root.join("operation-invoked");
        let old = root.join("old-worker");
        fs::write(
            &old,
            "#!/bin/sh\nif [ \"${2-}\" = probe ]; then printf '%s\\n' 'rch-wkr source-namespace-paths v0'; exit 0; fi\n: > \"$RCH_TEST_INVOKED\"\n",
        )
        .unwrap();
        fs::set_permissions(&old, fs::Permissions::from_mode(0o700)).unwrap();
        for binary in [root.join("missing-worker"), old] {
            let output = command(adapter, root)
                .env("RCH_WKR_BIN", binary)
                .env("RCH_TEST_INVOKED", &invoked)
                .arg("create")
                .arg(&canonical)
                .arg(&alias)
                .output()
                .unwrap();
            assert_status(&output, REFUSAL_EXIT);
            assert!(output.stdout.is_empty());
            assert!(String::from_utf8_lossy(&output.stderr).contains("deploy a current worker"));
            assert!(!canonical.exists());
            assert!(fs::symlink_metadata(&alias).is_err());
            assert!(
                !invoked.exists(),
                "old worker must not receive the operation"
            );
        }
    }
}

#[test]
fn conflict_diagnostics_preserve_existing_names_and_escape_physical_targets() {
    for adapter in ADAPTERS {
        let fixture = tempfile::tempdir().unwrap();
        let root = fs::canonicalize(fixture.path()).unwrap();
        let canonical = root.join("canonical");
        let alias = root.join("alias");
        let physical = root.join("physical\t\u{1b}[31m-é-😀");
        fs::create_dir(&canonical).unwrap();
        fs::create_dir(&physical).unwrap();
        fs::write(physical.join("keep"), b"private source contents").unwrap();
        symlink(&physical, &alias).unwrap();
        let inode = fs::symlink_metadata(&alias).unwrap().ino();
        let checked = command(adapter, &root)
            .arg("check")
            .arg(&canonical)
            .arg(&alias)
            .arg("--report-json")
            .output()
            .unwrap();
        assert_status(&checked, 1);
        let observed = report(&checked, "conflicting_alias_base");
        assert_eq!(observed["alias_physical"], physical.to_str().unwrap());
        let created = command(adapter, &root)
            .arg("create")
            .arg(&canonical)
            .arg(&alias)
            .output()
            .unwrap();
        assert_status(&created, REFUSAL_EXIT);
        assert!(created.stdout.is_empty());
        assert!(created.stderr.is_ascii());
        let diagnostic = std::str::from_utf8(&created.stderr).unwrap();
        assert!(
            diagnostic.starts_with("RCH_SOURCE_TOPOLOGY_INCOMPATIBLE: conflicting_alias_base\n")
        );
        let mapping: serde_json::Value = serde_json::from_str(
            diagnostic
                .lines()
                .find_map(|line| line.strip_prefix("RCH_SOURCE_TOPOLOGY_PATHS "))
                .unwrap(),
        )
        .unwrap();
        assert_eq!(mapping["alias_physical"], physical.to_str().unwrap());
        assert!(!diagnostic.contains(['\t', '\u{1b}']));
        assert!(!diagnostic.contains("private source contents"));
        assert_eq!(fs::symlink_metadata(&alias).unwrap().ino(), inode);
        assert_eq!(fs::read_link(&alias).unwrap(), physical);
        assert_eq!(
            fs::read(physical.join("keep")).unwrap(),
            b"private source contents"
        );
        assert_eq!(fs::read_dir(&canonical).unwrap().count(), 0);
    }
}

#[test]
fn unavailable_mapping_and_invalid_mode_keep_their_protocol_exit_codes() {
    for adapter in ADAPTERS {
        let fixture = tempfile::tempdir().unwrap();
        let root = fixture.path();
        let canonical = root.join("canonical");
        let alias = root.join("alias");
        let invalid = command(adapter, root)
            .arg("create")
            .arg(&canonical)
            .arg(&alias)
            .arg("--report-json")
            .output()
            .unwrap();
        assert_status(&invalid, REFUSAL_EXIT);
        assert!(invalid.stdout.is_empty());
        assert_eq!(fs::read_dir(root).unwrap().count(), 0);
        symlink("canonical", &canonical).unwrap();
        let unavailable = command(adapter, root)
            .arg("check")
            .arg(&canonical)
            .arg(&canonical)
            .arg("--report-json")
            .output()
            .unwrap();
        assert_status(&unavailable, 2);
        let observed = report(&unavailable, "unavailable");
        assert!(observed["canonical_physical"].is_null());
        assert!(observed["alias_physical"].is_null());
        let silent = command(adapter, root)
            .arg("check")
            .arg(&canonical)
            .arg(&canonical)
            .output()
            .unwrap();
        assert_status(&silent, 1);
        assert!(silent.stdout.is_empty() && silent.stderr.is_empty());
        assert!(fs::symlink_metadata(&alias).is_err());
    }
}
