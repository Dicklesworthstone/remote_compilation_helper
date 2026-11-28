#![cfg(target_os = "linux")]

//! Pure-Rust integration tests for `rabs-live-test` (replaces the legacy
//! live-test runner test suite with a POSIX sh fake-cargo fixture).

use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fs;
use std::os::unix::fs::{PermissionsExt, symlink};
use std::os::unix::process::ExitStatusExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

const FAKE_CARGO_SH: &str = r#"#!/bin/sh
set -eu
calls_file="$TEST_CALLS_FILE"
printf '%s\t%s\t%s\t%s\t%s\t%s\n' \
    "$*" \
    "${RUSTUP_TOOLCHAIN:-}" \
    "${RUSTFLAGS:-}" \
    "${CARGO_MAKEFLAGS:-}" \
    "${RABS_TEST_BINARIES:-}" \
    "${RABS_CANONICAL_TEST_WRAPPER:-}|${RABS_TEST_WORKER_BIN:-}" \
    >> "$calls_file"

mode="${TEST_MODE:-ok}"
subcmd="$1"

if [ "$subcmd" = "build" ]; then
    if [ "$mode" = "nonzero" ]; then
        exit 31
    fi
    if [ "$mode" = "malformed" ]; then
        printf '{broken json\n'
        exit 0
    fi
    if [ "$mode" = "duplicate-json" ]; then
        printf '{"reason":"build-finished","success":true,"success":false}\n'
        exit 0
    fi
    if [ "$mode" = "failed-finish" ]; then
        printf '{"reason":"build-finished","success":false}\n'
        exit 0
    fi
    if [ "$mode" = "wrong-tree" ]; then
        printf '{"reason":"compiler-artifact","target":{"name":"rabs-wrap","kind":["bin"],"src_path":"/wrong/rabs-wrap/src/main.rs"},"profile":{"test":false},"executable":"%s"}\n' "$FAKE_BIN_DIR/rabs-wrap"
        printf '{"reason":"build-finished","success":true}\n'
        exit 0
    fi
    if [ "$mode" = "ambiguous" ]; then
        printf '{"reason":"compiler-artifact","target":{"name":"rabs-wrap","kind":["bin"],"src_path":"%s/rabs-wrap/src/main.rs"},"profile":{"test":false},"executable":"%s"}\n' "$FAKE_WS" "$FAKE_BIN_DIR/rabs-wrap"
        printf '{"reason":"compiler-artifact","target":{"name":"rabs-wrap","kind":["bin"],"src_path":"%s/rabs-wrap/src/main.rs"},"profile":{"test":false},"executable":"%s"}\n' "$FAKE_WS" "$FAKE_BIN_DIR/rabs-wrap-alt"
        printf '{"reason":"build-finished","success":true}\n'
        exit 0
    fi
    if [ "$mode" = "nonexec" ]; then
        printf '{"reason":"compiler-artifact","target":{"name":"rabs-wrap","kind":["bin"],"src_path":"%s/rabs-wrap/src/main.rs"},"profile":{"test":false},"executable":"%s"}\n' "$FAKE_WS" "$FAKE_BIN_DIR/rabs-wrap-nonexec"
        printf '{"reason":"compiler-artifact","target":{"name":"rabsd","kind":["bin"],"src_path":"%s/rabsd/src/main.rs"},"profile":{"test":false},"executable":"%s"}\n' "$FAKE_WS" "$FAKE_BIN_DIR/rabsd"
        printf '{"reason":"build-finished","success":true}\n'
        exit 0
    fi
    if [ "$mode" = "symlink" ]; then
        printf '{"reason":"compiler-artifact","target":{"name":"rabs-wrap","kind":["bin"],"src_path":"%s/rabs-wrap/src/main.rs"},"profile":{"test":false},"executable":"%s"}\n' "$FAKE_WS" "$FAKE_BIN_DIR/rabs-wrap-link"
        printf '{"reason":"compiler-artifact","target":{"name":"rabsd","kind":["bin"],"src_path":"%s/rabsd/src/main.rs"},"profile":{"test":false},"executable":"%s"}\n' "$FAKE_WS" "$FAKE_BIN_DIR/rabsd"
        printf '{"reason":"build-finished","success":true}\n'
        exit 0
    fi
    # Normal build artifacts
    printf '{"reason":"compiler-artifact","target":{"name":"rabs-wrap","kind":["bin"],"src_path":"%s/rabs-wrap/src/main.rs"},"profile":{"test":false},"executable":"%s"}\n' "$FAKE_WS" "$FAKE_BIN_DIR/rabs-wrap"
    case " $* " in
        *" -p rabs-wkr "*)
            printf '{"reason":"compiler-artifact","target":{"name":"rabs-wkr","kind":["bin"],"src_path":"%s/rabs-wkr/src/main.rs"},"profile":{"test":false},"executable":"%s"}\n' "$FAKE_WS" "$FAKE_BIN_DIR/rabs-wkr"
            printf '{"reason":"compiler-artifact","target":{"name":"rabs-cargo-root","kind":["bin"],"src_path":"%s/rabs-wkr/src/bin/rabs-cargo-root.rs"},"profile":{"test":false},"executable":"%s"}\n' "$FAKE_WS" "$FAKE_BIN_DIR/rabs-cargo-root"
            ;;
        *)
            if [ "$mode" != "missing" ]; then
                printf '{"reason":"compiler-artifact","target":{"name":"rabsd","kind":["bin"],"src_path":"%s/rabsd/src/main.rs"},"profile":{"test":false},"executable":"%s"}\n' "$FAKE_WS" "$FAKE_BIN_DIR/rabsd"
            fi
            ;;
    esac
    printf '{"reason":"build-finished","success":true}\n'
    exit 0
fi

if [ "$subcmd" = "test" ]; then
    case " $* " in
        *" --no-run "*)
            printf '{"reason":"compiler-artifact","target":{"name":"rabsd","kind":["bin"],"src_path":"%s/rabsd/src/main.rs"},"profile":{"test":false},"executable":"%s"}\n' "$FAKE_WS" "$FAKE_BIN_DIR/rabsd"
            printf '{"reason":"compiler-artifact","target":{"name":"canonical_check_local","kind":["test"],"src_path":"%s/rabsd/tests/canonical_check_local.rs"},"profile":{"test":true},"executable":"%s"}\n' "$FAKE_WS" "$FAKE_BIN_DIR/canonical_check_local"
            printf '{"reason":"build-finished","success":true}\n'
            exit 0
            ;;
    esac
    if [ -n "${TEST_SIGNAL:-}" ]; then
        kill -"$TEST_SIGNAL" "$$"
    fi
    exit "${TEST_EXIT:-0}"
fi

exit 99
"#;

struct Harness {
    _dir: tempfile::TempDir,
    workspace: PathBuf,
    bin_dir: PathBuf,
    fake_cargo: PathBuf,
    calls_file: PathBuf,
    output_dir: PathBuf,
}

impl Harness {
    fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let workspace = dir.path().join("workspace");
        let bin_dir = dir.path().join("built-bins");
        let calls_file = dir.path().join("calls.tsv");
        let output_dir = dir.path().join("report-out");
        fs::create_dir_all(workspace.join("rabs-wrap/src")).unwrap();
        fs::create_dir_all(workspace.join("rabsd/src")).unwrap();
        fs::create_dir_all(workspace.join("rabsd/tests")).unwrap();
        fs::create_dir_all(workspace.join("rabs-wkr/src/bin")).unwrap();
        fs::create_dir_all(&bin_dir).unwrap();
        fs::write(workspace.join("Cargo.toml"), "[workspace]\n").unwrap();
        fs::write(workspace.join("rabs-wrap/src/main.rs"), "fn main() {}\n").unwrap();
        fs::write(workspace.join("rabsd/src/main.rs"), "fn main() {}\n").unwrap();
        fs::write(workspace.join("rabsd/tests/canonical_check_local.rs"), "").unwrap();
        fs::write(workspace.join("rabs-wkr/src/main.rs"), "fn main() {}\n").unwrap();
        fs::write(
            workspace.join("rabs-wkr/src/bin/rabs-cargo-root.rs"),
            "fn main() {}\n",
        )
        .unwrap();

        for name in [
            "rabs-wrap",
            "rabs-wrap-alt",
            "rabsd",
            "rabs-wkr",
            "rabs-cargo-root",
            "canonical_check_local",
        ] {
            let path = bin_dir.join(name);
            fs::write(&path, format!("binary-payload-{name}")).unwrap();
            fs::set_permissions(&path, fs::Permissions::from_mode(0o755)).unwrap();
        }
        let nonexec = bin_dir.join("rabs-wrap-nonexec");
        fs::write(&nonexec, b"not-executable").unwrap();
        fs::set_permissions(&nonexec, fs::Permissions::from_mode(0o644)).unwrap();
        symlink(bin_dir.join("rabs-wrap"), bin_dir.join("rabs-wrap-link")).unwrap();

        let fake_cargo = dir.path().join("fake-cargo");
        fs::write(&fake_cargo, FAKE_CARGO_SH).unwrap();
        fs::set_permissions(&fake_cargo, fs::Permissions::from_mode(0o755)).unwrap();

        Self {
            _dir: dir,
            workspace,
            bin_dir,
            fake_cargo,
            calls_file,
            output_dir,
        }
    }

    fn run(&self, extra_args: &[&str], env: &[(&str, &str)]) -> Output {
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_rabs-live-test"));
        cmd.arg("--workspace")
            .arg(&self.workspace)
            .arg("--cargo")
            .arg(&self.fake_cargo)
            .arg("--output-dir")
            .arg(&self.output_dir)
            .args(extra_args)
            .env("TEST_CALLS_FILE", &self.calls_file)
            .env("FAKE_BIN_DIR", &self.bin_dir)
            .env("FAKE_WS", fs::canonicalize(&self.workspace).unwrap());
        for &(k, v) in env {
            cmd.env(k, v);
        }
        cmd.output().unwrap()
    }

    fn calls(&self) -> Vec<String> {
        fs::read_to_string(&self.calls_file)
            .unwrap_or_default()
            .lines()
            .map(str::to_owned)
            .collect()
    }

    fn report(&self) -> Value {
        serde_json::from_str(&fs::read_to_string(self.output_dir.join("run.json")).unwrap())
            .unwrap()
    }

    fn binaries(&self) -> Value {
        serde_json::from_str(&fs::read_to_string(self.output_dir.join("binaries.json")).unwrap())
            .unwrap()
    }
}

fn sha256_file(path: &Path) -> String {
    let bytes = fs::read(path).unwrap();
    Sha256::digest(&bytes)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

#[test]
fn worktrees_suite_prepares_fingerprinted_manifest_preserves_env_and_runs_tests() {
    let h = Harness::new();
    let out = h.run(
        &["--", "smoke_filter", "--exact"],
        &[
            ("RUSTUP_TOOLCHAIN", "nightly-fixture"),
            ("RUSTFLAGS", "-C debuginfo=1"),
            ("CARGO_MAKEFLAGS", "-j --jobserver-auth=3,4"),
            ("RABS_TEST_BINARIES", "/stale/manifest.json"),
        ],
    );
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let calls = h.calls();
    assert_eq!(calls.len(), 2, "calls: {calls:?}");
    assert!(calls[0].starts_with("build --locked"));
    assert!(calls[0].contains("--profile daemon-release"));
    assert!(calls[0].contains("-p rabs-wrap -p rabsd --bins"));
    assert!(calls[1].starts_with("test --locked"));
    assert!(
        calls[1].contains(
            "-p rabs-wrap --test live_cargo_worktrees -- --nocapture smoke_filter --exact"
        )
    );
    // Ambient env preserved; stale RABS_TEST_BINARIES stripped on build and replaced on test.
    let build_fields: Vec<&str> = calls[0].split('\t').collect();
    assert_eq!(build_fields[1], "nightly-fixture");
    assert_eq!(build_fields[2], "-C debuginfo=1");
    assert_eq!(build_fields[3], "-j --jobserver-auth=3,4");
    assert_eq!(build_fields[4], "");
    let test_fields: Vec<&str> = calls[1].split('\t').collect();
    assert_eq!(
        test_fields[4],
        h.output_dir.join("binaries.json").display().to_string()
    );

    let bins = h.binaries();
    assert_eq!(bins["schema"], "rabs.test-binaries");
    assert_eq!(bins["version"], 1);
    assert_eq!(bins["profile"], "daemon-release");
    assert_eq!(
        bins["rabs-wrap"]["sha256"],
        sha256_file(&h.bin_dir.join("rabs-wrap"))
    );
    assert_eq!(
        bins["rabsd"]["sha256"],
        sha256_file(&h.bin_dir.join("rabsd"))
    );
    assert_eq!(
        fs::metadata(h.output_dir.join("binaries.json"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o600
    );
    let report = h.report();
    assert_eq!(report["build_exit"], 0);
    assert_eq!(report["test_exit"], 0);
    assert_eq!(report["suite"], "worktrees");
}

#[test]
fn canonical_suite_builds_worker_and_test_harness_and_passes_include_ignored_serial() {
    let h = Harness::new();
    let out = h.run(&["--suite", "canonical", "--profile", "dev"], &[]);
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let calls = h.calls();
    assert_eq!(
        calls.len(),
        3,
        "expected build + test --no-run + test: {calls:?}"
    );
    assert!(calls[0].contains("-p rabs-wrap -p rabs-wkr --bins"));
    assert!(calls[1].contains("-p rabsd --test canonical_check_local --no-run"));
    assert!(calls[2].contains("-- --nocapture --include-ignored --test-threads=1"));
    let test_fields: Vec<&str> = calls[2].split('\t').collect();
    assert_eq!(
        test_fields[5],
        format!(
            "{}|{}",
            h.bin_dir.join("rabs-wrap").display(),
            h.bin_dir.join("rabs-wkr").display()
        )
    );
    let bins = h.binaries();
    assert_eq!(bins["schema"], "rabs.canonical-test-binaries");
    assert!(bins["rabs-wkr"]["sha256"].is_string());
    assert!(bins["rabs-cargo-root"]["sha256"].is_string());
    assert!(bins["canonical_check_local"]["sha256"].is_string());
    let report = h.report();
    assert_eq!(report["build_exit"], 0);
    assert_eq!(report["test_preparation_exit"], 0);
    assert_eq!(report["test_exit"], 0);
}

#[test]
fn build_and_test_failures_and_signals_propagate_without_masking() {
    let h_build = Harness::new();
    let out = h_build.run(&[], &[("TEST_MODE", "nonzero")]);
    assert_eq!(out.status.code(), Some(31));
    assert_eq!(h_build.calls().len(), 1);
    assert!(!h_build.output_dir.join("binaries.json").exists());
    assert_eq!(h_build.report()["build_exit"], 31);
    assert!(h_build.report()["test_exit"].is_null());

    let h_test = Harness::new();
    let out = h_test.run(&[], &[("TEST_EXIT", "37")]);
    assert_eq!(out.status.code(), Some(37));
    assert_eq!(h_test.report()["build_exit"], 0);
    assert_eq!(h_test.report()["test_exit"], 37);

    let h_sig = Harness::new();
    let out = h_sig.run(&[], &[("TEST_SIGNAL", "15")]);
    assert_eq!(out.status.signal(), Some(15));
    assert_eq!(h_sig.report()["test_exit"], -15);
}

#[test]
fn malformed_duplicate_missing_wrong_tree_ambiguous_nonexec_and_symlink_all_refuse() {
    for mode in [
        "missing",
        "malformed",
        "duplicate-json",
        "failed-finish",
        "wrong-tree",
        "ambiguous",
        "nonexec",
        "symlink",
    ] {
        let h = Harness::new();
        let out = h.run(&[], &[("TEST_MODE", mode)]);
        assert_eq!(
            out.status.code(),
            Some(2),
            "mode {mode} should refuse with exit 2; stderr={}",
            String::from_utf8_lossy(&out.stderr)
        );
        assert_eq!(h.calls().len(), 1, "mode {mode} must never run tests");
        assert!(!h.output_dir.join("binaries.json").exists(), "mode {mode}");
        assert!(h.report()["preparation_error"].is_string(), "mode {mode}");
    }
}

#[test]
fn existing_output_dir_and_missing_cargo_refuse_without_mutation() {
    let h = Harness::new();
    fs::create_dir(&h.output_dir).unwrap();
    fs::write(h.output_dir.join("binaries.json"), "keep-these-bytes").unwrap();
    let out = h.run(&[], &[]);
    assert_eq!(out.status.code(), Some(2));
    assert_eq!(
        fs::read_to_string(h.output_dir.join("binaries.json")).unwrap(),
        "keep-these-bytes"
    );
    assert!(h.calls().is_empty());

    let h2 = Harness::new();
    let missing = Command::new(env!("CARGO_BIN_EXE_rabs-live-test"))
        .arg("--workspace")
        .arg(&h2.workspace)
        .arg("--cargo")
        .arg("/does/not/exist/cargo")
        .arg("--output-dir")
        .arg(&h2.output_dir)
        .output()
        .unwrap();
    assert_eq!(missing.status.code(), Some(2));
    assert!(!h2.output_dir.exists());

    // Ensure clippy sees BTreeMap used if needed — sanity-check --version.
    let mut versions = BTreeMap::new();
    let ver = Command::new(env!("CARGO_BIN_EXE_rabs-live-test"))
        .arg("--version")
        .output()
        .unwrap();
    assert!(ver.status.success());
    versions.insert("rabs-live-test", String::from_utf8(ver.stdout).unwrap());
    assert!(versions["rabs-live-test"].starts_with("rabs-live-test "));
}
