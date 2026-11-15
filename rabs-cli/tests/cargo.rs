//! Real frontend processes with an execed Rust driver fixture.
//! These tests exercise validation and handoff, not compilation or TLS transport.
//! Fixtures are retained; no source, operation or test directories are removed.

#![cfg(target_os = "linux")]
#![forbid(unsafe_code)]

use serde_json::{Value, json};
use std::ffi::{OsStr, OsString};
use std::fs::{self, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt, symlink};
use std::os::unix::process::ExitStatusExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

const BINARY: &str = env!("CARGO_BIN_EXE_rabs-cargo");
const PIN: &str = "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef";

fn private_directory(path: &Path) {
    fs::create_dir(path).unwrap();
    fs::set_permissions(path, fs::Permissions::from_mode(0o700)).unwrap();
}

fn new_file(path: &Path, bytes: &[u8], mode: u32) {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(mode)
        .open(path)
        .unwrap();
    file.write_all(bytes).unwrap();
    file.set_permissions(fs::Permissions::from_mode(mode))
        .unwrap();
}

fn rewrite_json(path: &Path, change: impl FnOnce(&mut Value)) {
    let mut value: Value = serde_json::from_slice(&fs::read(path).unwrap()).unwrap();
    change(&mut value);
    fs::write(path, serde_json::to_vec(&value).unwrap()).unwrap();
}

fn quote(value: &OsStr) -> String {
    format!("'{}'", value.to_str().unwrap().replace('\'', "'\\''"))
}

fn driver_fixture(path: &Path) {
    let adapter = format!(
        "#!/bin/sh\nexec {} --exact native_cargo_driver_fixture --ignored --nocapture -- \"$@\"\n",
        quote(std::env::current_exe().unwrap().as_os_str())
    );
    new_file(path, adapter.as_bytes(), 0o700);
}

struct Fixture {
    root: PathBuf,
    source: PathBuf,
    toolchain: PathBuf,
    operations: PathBuf,
    staging: PathBuf,
    outputs: PathBuf,
    local: PathBuf,
    remote: PathBuf,
    daemon: PathBuf,
    report: PathBuf,
}

impl Fixture {
    fn new() -> Self {
        let root = tempfile::Builder::new()
            .prefix("rabs-native-cargo-")
            .tempdir()
            .unwrap()
            .keep();
        let source = root.join("workspace α");
        let toolchain = root.join("captured sdk");
        let state = root.join("state");
        let operations = root.join("local operations");
        let staging = root.join("remote operations");
        let outputs = root.join("outputs");
        let tls = root.join("tls");
        for directory in [
            &source,
            &toolchain,
            &state,
            &operations,
            &staging,
            &outputs,
            &tls,
        ] {
            private_directory(directory);
        }
        private_directory(&toolchain.join("bin"));
        // Ordinary executable files establish frontend path validation only.
        // The Rust driver fixture never invokes these compiler placeholders.
        for name in ["cargo", "rustc", "rustdoc", "cargo-clippy", "clippy-driver"] {
            new_file(
                &toolchain.join("bin").join(name),
                b"unused compiler fixture",
                0o700,
            );
        }
        let wrapper = root.join("rabs-wrap");
        new_file(&wrapper, b"unused wrapper fixture", 0o700);
        new_file(
            &source.join("Cargo.toml"),
            b"[package]\nname='fixture'\nversion='0.1.0'\n",
            0o600,
        );
        private_directory(&source.join("inputs"));
        new_file(
            &source.join("inputs/request.bin"),
            b"\0captured input\xff",
            0o600,
        );
        for name in ["ca.pem", "edge.pem", "edge.key"] {
            new_file(&tls.join(name), b"unused TLS fixture", 0o600);
        }
        let local = root.join("local profile.json");
        new_file(&local, &serde_json::to_vec(&json!({
            "version":"canonical-compile-local-v1", "source_root":source,
            "toolchain_root":toolchain, "state_root":state, "operation_root":operations,
            "wrapper":wrapper, "command":"build", "selection":{"packages":["saved-package"],"release":true},
            "jobs":2, "timeout_seconds":90, "env":{"PROJECT_VALUE":"literal secret fixture"},
        })).unwrap(), 0o600);
        let remote = root.join("remote profile.json");
        new_file(&remote, &serde_json::to_vec(&json!({
            "version":"canonical-compile-remote-v1", "source_root":source,
            "toolchain_root":toolchain, "staging_root":staging, "output_root":outputs,
            "coordinator":"[2001:db8::1]:7443", "server_name":"coordinator.example", "coordinator_pin":PIN,
            "tls":{"ca":tls.join("ca.pem"), "certificate":tls.join("edge.pem"), "private_key":tls.join("edge.key")},
            "settings":{"command":"build", "jobs":2, "timeout_seconds":90,
                "env":{"PROJECT_VALUE":"literal secret fixture"}},
        })).unwrap(), 0o600);
        let daemon = root.join("native driver 'fixture'");
        driver_fixture(&daemon);
        let report = root.join("driver-report.json");
        Self {
            root,
            source,
            toolchain,
            operations,
            staging,
            outputs,
            local,
            remote,
            daemon,
            report,
        }
    }

    fn command_using(&self, remote: bool, binary: &Path) -> Command {
        let mut command = Command::new(binary);
        command
            .arg(if remote { "--remote" } else { "--local" })
            .arg(if remote { &self.remote } else { &self.local })
            .env_remove("CARGO_RABS_DAEMON")
            .env_remove("RABS_REMOTE_ARTIFACT_REUSE_ROOT")
            .env("RABS_CARGO_TEST_REPORT", &self.report)
            .env(
                "RABS_CARGO_TEST_ORIGINAL",
                if remote { &self.remote } else { &self.local },
            )
            .env("RABS_CARGO_TEST_UNRELATED", "preserved literally")
            .stdin(Stdio::null());
        for key in [
            "CARGO_RABS_CANONICAL_ACTIVE",
            "CARGO_RABS_REMOTE_ACTIVE",
            "RCH_RABS_WORKER_ACTIVE",
            "CARGO_RABS_ROOT_BUDGET_DIR",
            "CARGO_RABS_ROOT_CAPACITY",
            "CARGO_RABS_ROOT_CGROUP",
        ] {
            command.env_remove(key);
        }
        command
    }

    fn command(&self, remote: bool) -> Command {
        let mut command = self.command_using(remote, Path::new(BINARY));
        command.arg("--rabsd").arg(&self.daemon);
        command
    }

    fn report(&self) -> Value {
        serde_json::from_slice(&fs::read(&self.report).unwrap()).unwrap()
    }

    fn handed_off(&self, output: Output) -> Value {
        assert_eq!(output.status.code(), Some(47), "{output:?}");
        let stderr = String::from_utf8(output.stderr).unwrap();
        assert!(stderr.contains("rabs-cargo: retained profile"), "{stderr}");
        assert!(!stderr.contains("literal secret fixture"), "{stderr}");
        self.report()
    }

    fn refused(&self, output: Output) -> String {
        assert_eq!(output.status.code(), Some(2), "{output:?}");
        assert!(output.stdout.is_empty(), "{output:?}");
        let stderr = String::from_utf8(output.stderr).unwrap();
        assert!(stderr.contains("rabs-cargo: refused:"), "{stderr}");
        assert!(!stderr.contains("literal secret fixture"), "{stderr}");
        assert!(
            !self.report.exists(),
            "driver must not execute after refusal"
        );
        assert_eq!(fs::read_dir(&self.operations).unwrap().count(), 0);
        assert_eq!(fs::read_dir(&self.staging).unwrap().count(), 0);
        assert_eq!(fs::read_dir(&self.outputs).unwrap().count(), 0);
        stderr
    }
}

#[test]
#[ignore = "Rust subprocess driver fixture, invoked only by frontend handoff tests"]
fn native_cargo_driver_fixture() {
    let arguments: Vec<OsString> = std::env::args_os().collect();
    let delimiter = arguments
        .iter()
        .position(|argument| argument == "--")
        .unwrap();
    let arguments = &arguments[delimiter + 1..];
    assert_eq!(
        arguments.len(),
        2,
        "driver receives exactly one native operation"
    );
    assert!(
        arguments[0] == "--canonical-compile-local" || arguments[0] == "--canonical-compile-remote"
    );
    let retained = Path::new(&arguments[1]);
    assert_ne!(
        retained,
        Path::new(&std::env::var_os("RABS_CARGO_TEST_ORIGINAL").unwrap())
    );
    let metadata = fs::symlink_metadata(retained).unwrap();
    assert!(metadata.is_file());
    assert_eq!(metadata.mode() & 0o777, 0o400);
    assert_eq!(
        fs::symlink_metadata(retained.parent().unwrap())
            .unwrap()
            .mode()
            & 0o777,
        0o700
    );
    if std::env::var_os("RABS_CARGO_TEST_MUTATE_ORIGINAL").is_some() {
        fs::write(
            std::env::var_os("RABS_CARGO_TEST_ORIGINAL").unwrap(),
            b"changed after exec",
        )
        .unwrap();
    }
    let profile: Value = serde_json::from_slice(&fs::read(retained).unwrap()).unwrap();
    if arguments[0] == "--canonical-compile-remote" {
        assert!(profile.get("output_root").is_none());
        assert!(!Path::new(profile["output_destination"].as_str().unwrap()).exists());
        let capture = Path::new(profile["staging_root"].as_str().unwrap());
        assert_eq!(capture.parent(), retained.parent());
        assert_eq!(capture.file_name(), Some(OsStr::new("capture")));
        assert_eq!(fs::symlink_metadata(capture).unwrap().mode() & 0o777, 0o700);
    }
    let mut input = Vec::new();
    std::io::stdin().read_to_end(&mut input).unwrap();
    let arguments: Vec<_> = arguments
        .iter()
        .map(|argument| argument.to_str().unwrap())
        .collect();
    let result = json!({
        "argv":arguments, "profile":profile, "retained":retained, "stdin":input,
        "pid":std::process::id(), "active":std::env::var("CARGO_RABS_CANONICAL_ACTIVE").unwrap(),
        "unrelated":std::env::var("RABS_CARGO_TEST_UNRELATED").unwrap(),
    });
    new_file(
        Path::new(&std::env::var_os("RABS_CARGO_TEST_REPORT").unwrap()),
        &serde_json::to_vec(&result).unwrap(),
        0o600,
    );
    if std::env::var_os("RABS_CARGO_TEST_SIGNAL").is_some() {
        rustix::process::kill_process(rustix::process::getpid(), rustix::process::Signal::TERM)
            .unwrap();
        panic!("driver signal termination must propagate");
    }
    std::process::exit(47);
}

#[test]
fn help_version_and_release_identity_do_not_need_profiles_or_a_driver() {
    for argument in ["--help", "--version", "--rabs-build-info"] {
        let output = Command::new(BINARY)
            .arg(argument)
            .env("CARGO_RABS_DAEMON", "/missing/native-driver")
            .output()
            .unwrap();
        assert!(output.status.success(), "{argument}: {output:?}");
        assert!(!output.stdout.is_empty());
        assert!(output.stderr.is_empty());
        if argument == "--rabs-build-info" {
            let value: Value = serde_json::from_slice(&output.stdout).unwrap();
            assert_eq!(value["tool"], "rabs-cargo");
        }
    }
}

#[test]
fn local_intent_is_retained_before_one_exec_and_original_edits_cannot_replace_it() {
    let fixture = Fixture::new();
    let child = fixture
        .command(false)
        .env("RABS_CARGO_TEST_MUTATE_ORIGINAL", "1")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let pid = child.id();
    let report = fixture.handed_off(child.wait_with_output().unwrap());
    assert_eq!(report["pid"], pid);
    assert_eq!(report["active"], "1");
    assert_eq!(report["unrelated"], "preserved literally");
    assert_eq!(report["profile"]["command"], "build");
    assert_eq!(
        report["profile"]["selection"]["packages"],
        json!(["saved-package"])
    );
    assert_eq!(report["profile"]["selection"]["release"], true);
    assert_eq!(
        report["profile"]["env"]["PROJECT_VALUE"],
        "literal secret fixture"
    );
    assert!(Path::new(report["retained"].as_str().unwrap()).starts_with(&fixture.operations));
    assert_eq!(fs::read(&fixture.local).unwrap(), b"changed after exec");
    assert_eq!(fs::read_dir(&fixture.operations).unwrap().count(), 1);
}

#[test]
fn explicit_commands_replace_saved_selection_and_preserve_literal_runtime_tails() {
    for (arguments, command, field, tail) in [
        (
            vec![
                "build",
                "--workspace",
                "--exclude",
                "skipped",
                "--target",
                "x86_64-unknown-linux-gnu",
                "--profile",
                "dev",
            ],
            "build",
            "packages",
            json!([]),
        ),
        (
            vec![
                "test",
                "--package=pkg",
                "filter text",
                "--",
                "--exact",
                "a b",
            ],
            "test",
            "test_args",
            json!(["--exact", "a b"]),
        ),
        (
            vec!["clippy", "--all-targets", "--", "-Dwarnings"],
            "clippy",
            "lint_args",
            json!(["-Dwarnings"]),
        ),
        (
            vec!["doc", "--document-private-items", "--no-deps"],
            "doc",
            "packages",
            json!([]),
        ),
    ] {
        let fixture = Fixture::new();
        let report = fixture.handed_off(fixture.command(false).args(arguments).output().unwrap());
        assert_eq!(report["profile"]["command"], command);
        assert_eq!(report["profile"]["selection"][field], tail);
        assert_eq!(report["profile"]["selection"]["release"], false);
        assert_eq!(report["profile"]["jobs"], 2);
        assert_eq!(report["profile"]["timeout_seconds"], 90);
    }
}

#[test]
fn direct_local_execution_inherits_exact_nonterminal_input_and_process_identity() {
    for (arguments, tail, expected_tail) in [
        (
            vec!["run", "--bin", "app", "--", "", "--remote", "α\nβ"],
            "run_args",
            json!(["", "--remote", "α\nβ"]),
        ),
        (
            vec![
                "--stdin", "inherit", "test", "--test", "reader", "--", "", "--remote", "α β",
            ],
            "test_args",
            json!(["", "--remote", "α β"]),
        ),
    ] {
        let fixture = Fixture::new();
        let input = b"\0literal stdin\xff\n";
        let mut child = fixture
            .command(false)
            .args(arguments)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let pid = child.id();
        child.stdin.take().unwrap().write_all(input).unwrap();
        let report = fixture.handed_off(child.wait_with_output().unwrap());
        assert_eq!(report["pid"], pid);
        assert_eq!(report["stdin"], json!(input));
        assert_eq!(report["profile"]["selection"][tail], expected_tail);
        if tail == "test_args" {
            assert_eq!(report["profile"]["stdin"], "inherit");
        }
    }
}

#[test]
fn remote_execution_retains_explicit_input_and_local_presentation() {
    for (command, input_flag, input, saved_field, saved_input) in [
        ("run", "--stdin", "closed", "stdin_file", "inputs/old.bin"),
        (
            "run",
            "--stdin-file",
            "inputs/request.bin",
            "stdin",
            "inherit",
        ),
        ("bench", "--stdin", "closed", "stdin_file", "inputs/old.bin"),
        (
            "bench",
            "--stdin-file",
            "inputs/request.bin",
            "stdin",
            "inherit",
        ),
        ("test", "--stdin", "closed", "stdin_file", "inputs/old.bin"),
        (
            "test",
            "--stdin-file",
            "inputs/request.bin",
            "stdin",
            "inherit",
        ),
    ] {
        let fixture = Fixture::new();
        rewrite_json(&fixture.remote, |profile| {
            profile["settings"][saved_field] = saved_input.into();
            profile["stdout_presentation"] = "cargo-json-subscriber-v1".into();
        });
        let report = fixture.handed_off(
            fixture
                .command(true)
                .args([input_flag, input, command])
                .output()
                .unwrap(),
        );
        let profile = &report["profile"];
        let field = if input_flag == "--stdin" {
            "stdin"
        } else {
            "stdin_file"
        };
        assert_eq!(profile["settings"][field], input);
        assert!(profile["settings"].get(saved_field).is_none());
        assert_eq!(profile["settings"]["command"], command);
        assert_eq!(profile["stdout_presentation"], "cargo-json-subscriber-v1");
        assert!(profile["settings"].get("stdout_presentation").is_none());
        assert!(
            Path::new(profile["output_destination"].as_str().unwrap())
                .starts_with(&fixture.outputs)
        );
        assert!(Path::new(report["retained"].as_str().unwrap()).starts_with(&fixture.staging));
        assert_eq!(fs::read_dir(&fixture.outputs).unwrap().count(), 0);
    }
}

#[test]
fn service_and_remote_execution_refuse_implicit_or_inherited_stdin_before_handoff() {
    for remote in [false, true] {
        for (command, explicit) in [
            ("run", false),
            ("run", true),
            ("bench", false),
            ("bench", true),
            ("test", true),
        ] {
            let fixture = Fixture::new();
            if !remote {
                rewrite_json(&fixture.local, |profile| {
                    profile["service_socket"] = json!(fixture.root.join("canonical.sock"))
                });
            }
            let mut process = fixture.command(remote);
            if explicit {
                process.args(["--stdin", "inherit"]);
            }
            process.arg(command);
            assert!(
                fixture
                    .refused(process.output().unwrap())
                    .contains("requires explicit closed stdin")
            );
        }
    }
}

#[test]
fn local_service_closed_and_captured_input_and_remote_nonexecuting_bench_are_reachable() {
    for command in ["run", "test", "bench"] {
        for input in [
            ["--stdin", "closed"],
            ["--stdin-file", "inputs/request.bin"],
        ] {
            let fixture = Fixture::new();
            rewrite_json(&fixture.local, |profile| {
                profile["service_socket"] = json!(fixture.root.join("canonical.sock"))
            });
            let report = fixture.handed_off(
                fixture
                    .command(false)
                    .args(input)
                    .arg(command)
                    .output()
                    .unwrap(),
            );
            assert_eq!(report["profile"]["command"], command);
            assert!(report["profile"].get("service_socket").is_some());
        }
    }
    let fixture = Fixture::new();
    let report = fixture.handed_off(
        fixture
            .command(true)
            .args(["bench", "--no-run"])
            .output()
            .unwrap(),
    );
    assert_eq!(report["profile"]["settings"]["selection"]["no_run"], true);
}

#[test]
fn test_input_preserves_closed_defaults_and_distinguishes_cargo_no_run_from_a_harness_tail() {
    for (remote, shared) in [(false, false), (false, true), (true, false)] {
        for no_run in [false, true] {
            let fixture = Fixture::new();
            if shared {
                rewrite_json(&fixture.local, |profile| {
                    profile["service_socket"] = json!(fixture.root.join("canonical.sock"))
                });
            }
            let mut command = fixture.command(remote);
            command.arg("test");
            if no_run {
                command.arg("--no-run");
            }
            let report = fixture.handed_off(command.output().unwrap());
            let logical = if remote {
                &report["profile"]["settings"]
            } else {
                &report["profile"]
            };
            assert_eq!(logical["command"], "test");
            assert_eq!(logical["selection"]["no_run"], no_run);
            assert!(logical.get("stdin").is_none());
            assert!(logical.get("stdin_file").is_none());
        }
        for input in [
            ["--stdin", "inherit"],
            ["--stdin-file", "inputs/request.bin"],
        ] {
            let fixture = Fixture::new();
            if shared {
                rewrite_json(&fixture.local, |profile| {
                    profile["service_socket"] = json!(fixture.root.join("canonical.sock"))
                });
            }
            fixture.refused(
                fixture
                    .command(remote)
                    .args(input)
                    .args(["test", "--no-run"])
                    .output()
                    .unwrap(),
            );
        }
        let fixture = Fixture::new();
        if shared {
            rewrite_json(&fixture.local, |profile| {
                profile["service_socket"] = json!(fixture.root.join("canonical.sock"))
            });
        }
        let report = fixture.handed_off(
            fixture
                .command(remote)
                .args(["--stdin-file", "inputs/request.bin", "test", "--", "--no-run"])
                .output()
                .unwrap(),
        );
        let logical = if remote {
            &report["profile"]["settings"]
        } else {
            &report["profile"]
        };
        assert_eq!(logical["stdin_file"], "inputs/request.bin");
        assert_eq!(logical["selection"]["no_run"], false);
        assert_eq!(logical["selection"]["test_args"], json!(["--no-run"]));
    }
}

#[test]
fn native_output_destination_and_previous_result_hints_remain_exact() {
    let fixture = Fixture::new();
    let destination = fixture.outputs.join("new result");
    let previous = fixture.outputs.join("previous result");
    private_directory(&previous);
    rewrite_json(&fixture.remote, |profile| {
        profile.as_object_mut().unwrap().remove("output_root");
        profile["output_destination"] = json!(destination);
        profile["artifact_reuse_root"] = json!(previous);
    });
    let report = fixture.handed_off(fixture.command(true).arg("build").output().unwrap());
    assert_eq!(report["profile"]["output_destination"], json!(destination));
    assert_eq!(report["profile"]["artifact_reuse_root"], json!(previous));
    assert!(!destination.exists());
}

#[test]
fn each_remote_invocation_owns_a_distinct_retained_profile_and_absent_destination() {
    let fixture = Fixture::new();
    let first = fixture.handed_off(fixture.command(true).output().unwrap());
    let second_report = fixture.root.join("second-driver-report.json");
    let output = fixture
        .command(true)
        .env("RABS_CARGO_TEST_REPORT", &second_report)
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(47), "{output:?}");
    let second: Value = serde_json::from_slice(&fs::read(second_report).unwrap()).unwrap();
    assert_ne!(first["retained"], second["retained"]);
    assert_ne!(
        first["profile"]["output_destination"],
        second["profile"]["output_destination"]
    );
    assert_eq!(fs::read_dir(&fixture.staging).unwrap().count(), 2);
    assert_eq!(fs::read_dir(&fixture.outputs).unwrap().count(), 0);
}

#[test]
fn malformed_duplicate_oversized_and_unsafe_profiles_refuse_without_private_state() {
    for case in 0..10 {
        let fixture = Fixture::new();
        match case {
            0 => fs::write(&fixture.local, b"{\"version\":\"canonical-compile-local-v1\",\"version\":\"canonical-compile-local-v1\"}").unwrap(),
            1 => fs::write(&fixture.local, b"{\"env\":{\"DUPLICATE\":\"first\",\"DUPLICATE\":\"second\"}}").unwrap(),
            2 => fs::write(&fixture.local, vec![b' '; 65 * 1024]).unwrap(),
            3 => rewrite_json(&fixture.local, |profile| profile["unknown_execution_setting"] = true.into()),
            4 => rewrite_json(&fixture.local, |profile| profile["toolchain"] = "rustup:nightly".into()),
            5 => rewrite_json(&fixture.local, |profile| profile["env"]["LD_PRELOAD"] = "literal secret fixture".into()),
            6 => rewrite_json(&fixture.local, |profile| profile["operation_root"] = json!(fixture.source)),
            7 => fs::set_permissions(&fixture.local, fs::Permissions::from_mode(0o622)).unwrap(),
            8 => fs::set_permissions(&fixture.operations, fs::Permissions::from_mode(0o755)).unwrap(),
            9 => {
                let alias = fixture.root.join("source alias");
                symlink(&fixture.source, &alias).unwrap();
                rewrite_json(&fixture.local, |profile| profile["source_root"] = json!(alias));
            }
            _ => unreachable!(),
        }
        fixture.refused(fixture.command(false).output().unwrap());
    }
}

#[test]
fn invalid_input_fields_and_ambiguous_remote_authority_refuse_before_dispatch() {
    for case in 0..9 {
        let fixture = Fixture::new();
        rewrite_json(&fixture.remote, |profile| match case {
            0 => profile["settings"]["stdin_file"] = "../outside".into(),
            1 => {
                profile["settings"]["command"] = "run".into();
                profile["settings"]["stdin_file"] = "inputs/request.bin".into();
                profile["settings"]["stdin"] = "closed".into();
            }
            2 => profile["coordinator_pin"] = "0".repeat(64).into(),
            3 => profile["output_destination"] = json!(fixture.outputs.join("ambiguous")),
            4 => profile["stdout_presentation"] = "unknown".into(),
            5 => profile["settings"]["stdout_presentation"] = "raw".into(),
            6 => profile["artifact_reuse_root"] = json!(fixture.outputs),
            7 => {
                let key = fixture.source.join("edge.key");
                new_file(&key, b"unused key", 0o600);
                profile["tls"]["private_key"] = json!(key);
            }
            8 => profile["settings"]["command"] = "shell".into(),
            _ => unreachable!(),
        });
        fixture.refused(fixture.command(true).output().unwrap());
    }
}

#[test]
fn captured_input_names_share_the_native_relative_path_boundary() {
    for path in [
        "../outside",
        "/absolute",
        "input\\request",
        "input:request",
        "input\nrequest",
        "input//request",
        "input/./request",
    ] {
        let fixture = Fixture::new();
        fixture.refused(
            fixture
                .command(true)
                .args(["--stdin-file", path, "run"])
                .output()
                .unwrap(),
        );
    }
    let fixture = Fixture::new();
    let ambiguous = fixture.root.join("source\\alias");
    private_directory(&ambiguous);
    rewrite_json(&fixture.local, |profile| {
        profile["source_root"] = json!(ambiguous)
    });
    fixture.refused(fixture.command(false).output().unwrap());
}

#[test]
fn recursion_and_root_admission_guards_precede_all_operation_state() {
    for key in [
        "CARGO_RABS_CANONICAL_ACTIVE",
        "CARGO_RABS_REMOTE_ACTIVE",
        "RCH_RABS_WORKER_ACTIVE",
        "CARGO_RABS_ROOT_BUDGET_DIR",
        "CARGO_RABS_ROOT_CAPACITY",
        "CARGO_RABS_ROOT_CGROUP",
    ] {
        let fixture = Fixture::new();
        fixture.refused(fixture.command(false).env(key, "1").output().unwrap());
    }
    let fixture = Fixture::new();
    fixture.refused(
        fixture
            .command_using(false, Path::new(BINARY))
            .arg("--rabsd")
            .arg(BINARY)
            .output()
            .unwrap(),
    );
}

#[test]
fn explicit_and_environment_drivers_are_exclusive_and_signal_status_is_preserved() {
    let fixture = Fixture::new();
    fixture.handed_off(
        fixture
            .command(false)
            .env("CARGO_RABS_DAEMON", "/missing/driver")
            .output()
            .unwrap(),
    );
    let fixture = Fixture::new();
    fixture.handed_off(
        fixture
            .command_using(false, Path::new(BINARY))
            .env("CARGO_RABS_DAEMON", &fixture.daemon)
            .output()
            .unwrap(),
    );
    let fixture = Fixture::new();
    fixture.refused(
        fixture
            .command_using(false, Path::new(BINARY))
            .env("CARGO_RABS_DAEMON", "/missing/driver")
            .output()
            .unwrap(),
    );
    let fixture = Fixture::new();
    let output = fixture
        .command(false)
        .env("RABS_CARGO_TEST_SIGNAL", "1")
        .output()
        .unwrap();
    assert_eq!(
        output.status.signal(),
        Some(rustix::process::Signal::TERM.as_raw())
    );
    assert_eq!(fixture.report()["active"], "1");
    assert_eq!(fs::read_dir(&fixture.operations).unwrap().count(), 1);
}

#[test]
fn sibling_driver_is_resolved_from_physical_frontend_not_path_or_public_symlink() {
    let fixture = Fixture::new();
    let generation = fixture.root.join("generation one");
    private_directory(&generation);
    let binary = generation.join("rabs-cargo");
    fs::copy(BINARY, &binary).unwrap();
    fs::set_permissions(&binary, fs::Permissions::from_mode(0o700)).unwrap();
    driver_fixture(&generation.join("rabsd"));
    let public = fixture.root.join("public launcher");
    symlink(&binary, &public).unwrap();
    let report = fixture.handed_off(
        fixture
            .command_using(false, &public)
            .env("PATH", "/does/not/contain/tools")
            .output()
            .unwrap(),
    );
    assert_eq!(
        report["profile"]["toolchain_root"],
        json!(fixture.toolchain)
    );
}
