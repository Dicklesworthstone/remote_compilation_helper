//! Real frontend processes with execed Rust driver and RCH fixtures.
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
const SUBCOMMAND: &str = env!("CARGO_BIN_EXE_cargo-rabs");
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

fn rustup_fixture(path: &Path) {
    // Keep libtest's status text off the discovery pipe. The Rust fixture
    // writes its controlled protocol reply through the inherited descriptor.
    let adapter = format!(
        "#!/bin/sh\nexec 3>&1\nexec {} --exact native_rustup_discovery_fixture --ignored --nocapture -- \"$@\" >/dev/null\n",
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
        let subcommand = binary == Path::new(SUBCOMMAND);
        if subcommand {
            command.arg("rabs");
        }
        command
            .arg(match (subcommand, remote) {
                (true, true) => "--rabs-canonical-remote",
                (true, false) => "--rabs-canonical-local",
                (false, true) => "--remote",
                (false, false) => "--local",
            })
            .arg(if remote { &self.remote } else { &self.local })
            .env_remove("CARGO_RABS_DAEMON")
            .env_remove("CARGO_RABS_RUSTUP")
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

    fn worker_command(&self) -> Command {
        let profile = self.root.join("worker profile.json");
        new_file(
            &profile,
            &serde_json::to_vec(&json!({
                "version":"canonical-cargo-v1", "source_root":self.source,
                "toolchain_root":self.toolchain, "operation_root":self.operations,
                "listen":"127.0.0.1:7443", "worker":"fixture-worker", "worker_spki_sha256":PIN,
            }))
            .unwrap(),
            0o600,
        );
        let mut command = Command::new(SUBCOMMAND);
        command
            .args(["rabs", "--rabs-canonical"])
            .arg(&profile)
            .env("CARGO_RABS_DAEMON", &self.daemon)
            .env("RABS_CARGO_TEST_REPORT", &self.report)
            .env("RABS_CARGO_TEST_ORIGINAL", &profile)
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

    fn rustup_command(&self, remote: bool) -> Command {
        rewrite_json(if remote { &self.remote } else { &self.local }, |profile| {
            profile.as_object_mut().unwrap().remove("toolchain_root");
            profile["toolchain"] = "rustup".into();
        });
        let rustup = self.root.join("rustup fixture");
        rustup_fixture(&rustup);
        let mut command = self.command(remote);
        command
            .env("CARGO_RABS_RUSTUP", rustup)
            .env(
                "RABS_CARGO_TEST_RUSTUP_PATH",
                self.toolchain.join("bin/rustc"),
            )
            .env(
                "RABS_CARGO_TEST_RUSTUP_REPORT",
                self.root.join("rustup-report.json"),
            );
        command
    }

    fn rustup_report(&self) -> Value {
        serde_json::from_slice(&fs::read(self.root.join("rustup-report.json")).unwrap()).unwrap()
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
        self.refused_with_prefix(output, "rabs-cargo: refused:")
    }

    fn refused_subcommand(&self, output: Output) -> String {
        self.refused_with_prefix(output, "cargo-rabs: refused:")
    }

    fn refused_with_prefix(&self, output: Output, prefix: &str) -> String {
        assert_eq!(output.status.code(), Some(2), "{output:?}");
        assert!(output.stdout.is_empty(), "{output:?}");
        let stderr = String::from_utf8(output.stderr).unwrap();
        assert!(stderr.contains(prefix), "{stderr}");
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
    if arguments
        .first()
        .is_some_and(|argument| argument == "--worker-build-tls")
    {
        native_worker_cargo_driver_fixture(arguments);
    }
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
        "rustup_auto_install":std::env::var("RUSTUP_AUTO_INSTALL").ok(),
        "rustup_toolchain":std::env::var("RUSTUP_TOOLCHAIN").ok(),
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

/// Inspect the real frontend's retained direct-worker handoff. This fixture
/// reads the named source input to verify literal path/bytes only; it does not
/// claim to perform the worker's immutable capture, sandbox or TLS execution.
fn native_worker_cargo_driver_fixture(arguments: &[OsString]) -> ! {
    assert_eq!(arguments.len(), 11);
    assert_eq!(arguments[1], "--replay-diagnostics");
    assert_eq!(arguments[2], "--prepare-from");
    assert_eq!(arguments[5], "127.0.0.1:7443");
    assert_eq!(arguments[6], "fixture-worker");
    assert_eq!(arguments[7], PIN);
    let source = Path::new(&arguments[3]);
    let retained = Path::new(&arguments[4]);
    let directory = retained.parent().unwrap();
    assert_eq!(retained.file_name(), Some(OsStr::new("spec.json")));
    assert_eq!(
        fs::symlink_metadata(retained).unwrap().mode() & 0o777,
        0o400
    );
    assert_eq!(
        fs::symlink_metadata(directory).unwrap().mode() & 0o777,
        0o700
    );
    for (argument, name) in arguments[8..].iter().zip(["bundle", "delivery", "outputs"]) {
        assert_eq!(Path::new(argument), directory.join(name));
        assert!(!Path::new(argument).exists());
    }
    let spec: Value = serde_json::from_slice(&fs::read(retained).unwrap()).unwrap();
    let operation: Value =
        serde_json::from_slice(&fs::read(directory.join("operation.json")).unwrap()).unwrap();
    assert_eq!(operation["automatic_retry"], false);
    assert_eq!(operation["publication_authorized"], false);
    let input = spec["captured_stdin"]["path"]
        .as_str()
        .map(|path| fs::read(source.join(path)).unwrap());
    new_file(
        Path::new(&std::env::var_os("RABS_CARGO_TEST_REPORT").unwrap()),
        &serde_json::to_vec(&json!({
            "spec":spec, "operation":operation, "source_input":input,
            "pid":std::process::id(), "active":std::env::var("CARGO_RABS_CANONICAL_ACTIVE").unwrap(),
        })).unwrap(),
        0o600,
    );
    std::process::exit(47);
}

#[test]
#[ignore = "Rust Rustup protocol fixture, invoked only by discovery tests"]
fn native_rustup_discovery_fixture() {
    let mut arguments = std::env::args_os();
    let arguments: Vec<_> = arguments
        .by_ref()
        .skip_while(|value| value != "--")
        .skip(1)
        .map(|value| value.into_string().unwrap())
        .collect();
    let mut input = Vec::new();
    std::io::stdin().read_to_end(&mut input).unwrap();
    let report = json!({
        "argv":arguments, "cwd":std::env::current_dir().unwrap(), "stdin":input,
        "auto_install":std::env::var("RUSTUP_AUTO_INSTALL").ok(),
        "selected":std::env::var("RUSTUP_TOOLCHAIN").ok(),
        "home":std::env::var("RUSTUP_HOME").ok(), "pid":std::process::id(),
    });
    new_file(
        Path::new(&std::env::var_os("RABS_CARGO_TEST_RUSTUP_REPORT").unwrap()),
        &serde_json::to_vec(&report).unwrap(),
        0o600,
    );
    let mode = std::env::var("RABS_CARGO_TEST_RUSTUP_MODE").unwrap_or_default();
    if mode == "fail" {
        eprintln!("private discovery error must not be copied to frontend output");
        std::process::exit(19);
    }
    let mut output = OpenOptions::new()
        .write(true)
        .open("/proc/self/fd/3")
        .unwrap();
    if mode == "oversized" {
        let _ = output.write_all(&vec![b'x'; 8192]);
        std::process::exit(0);
    }
    if mode == "binary" {
        output.write_all(b"/toolchain/bin/rustc\xff\n").unwrap();
        std::process::exit(0);
    }
    let path = std::env::var("RABS_CARGO_TEST_RUSTUP_PATH").unwrap();
    if mode != "empty" {
        output.write_all(path.as_bytes()).unwrap();
        if mode != "no-newline" {
            output.write_all(b"\n").unwrap();
        }
    }
    if mode == "multiple" {
        output.write_all(b"/unrequested/bin/rustc\n").unwrap();
    }
    if mode == "hang" {
        std::thread::sleep(std::time::Duration::from_secs(30));
    }
    if mode == "pipe-held" {
        let child_report = std::env::var_os("RABS_CARGO_TEST_RUSTUP_CHILD").unwrap();
        let _child = Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "native_rustup_descendant_fixture",
                "--ignored",
                "--nocapture",
            ])
            .spawn()
            .unwrap();
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
        while !Path::new(&child_report).exists() {
            assert!(
                std::time::Instant::now() < deadline,
                "discovery descendant did not start"
            );
            std::thread::sleep(std::time::Duration::from_millis(2));
        }
        // Exit while the child is still owned so this fixture deliberately
        // leaves a descendant holding the probe output after its leader exits.
        std::process::exit(0);
    }
    std::process::exit(0);
}

#[test]
#[ignore = "in-group pipe holder for the Rustup cleanup regression"]
fn native_rustup_descendant_fixture() {
    new_file(
        Path::new(&std::env::var_os("RABS_CARGO_TEST_RUSTUP_CHILD").unwrap()),
        std::process::id().to_string().as_bytes(),
        0o600,
    );
    std::thread::sleep(std::time::Duration::from_secs(30));
    std::process::exit(0);
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
fn cargo_subcommand_canonical_aliases_keep_check_defaults_and_explicit_literal_selection() {
    for remote in [false, true] {
        for explicit in [false, true] {
            let fixture = Fixture::new();
            let before = fs::read(if remote {
                &fixture.remote
            } else {
                &fixture.local
            })
            .unwrap();
            let mut command = fixture.command_using(remote, Path::new(SUBCOMMAND));
            command.env("CARGO_RABS_DAEMON", &fixture.daemon);
            if explicit {
                command.args(["--", "test", "--no-run", "--", "--rabs-remote", "literal α"]);
            }
            let report = fixture.handed_off(command.output().unwrap());
            let profile = if remote {
                &report["profile"]["settings"]
            } else {
                &report["profile"]
            };
            assert_eq!(profile["command"], if explicit { "test" } else { "check" });
            if explicit {
                assert_eq!(profile["selection"]["no_run"], true);
                assert_eq!(
                    profile["selection"]["test_args"],
                    json!(["--rabs-remote", "literal α"])
                );
            } else {
                assert_eq!(profile["selection"]["packages"], json!([]));
                assert_eq!(profile["selection"]["release"], false);
            }
            assert_eq!(
                fs::read(if remote {
                    &fixture.remote
                } else {
                    &fixture.local
                })
                .unwrap(),
                before
            );
        }
    }
}

#[test]
fn cargo_subcommand_inherited_input_keeps_binary_bytes_process_and_literal_tail() {
    let fixture = Fixture::new();
    let input = b"\0literal stdin\xff\n";
    let mut child = fixture
        .command_using(false, Path::new(SUBCOMMAND))
        .env("CARGO_RABS_DAEMON", &fixture.daemon)
        .args([
            "--rabs-stdin=inherit",
            "--",
            "test",
            "--test",
            "reader",
            "--",
            "--rabs-stdin-file",
            "",
            "literal α",
        ])
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
    assert_eq!(report["profile"]["stdin"], "inherit");
    assert_eq!(
        report["profile"]["selection"]["test_args"],
        json!(["--rabs-stdin-file", "", "literal α"])
    );
}

#[test]
fn cargo_subcommand_canonical_input_overrides_saved_policy_for_each_runtime_command() {
    for remote in [false, true] {
        for cargo in [
            vec!["run"],
            vec!["test"],
            vec!["nextest", "run", "--test-threads", "2"],
            vec!["bench"],
        ] {
            for captured in [false, true] {
                let fixture = Fixture::new();
                if cargo[0] == "nextest" {
                    new_file(
                        &fixture.toolchain.join("bin/cargo-nextest"),
                        b"unused captured runner fixture",
                        0o700,
                    );
                }
                let original = if remote {
                    &fixture.remote
                } else {
                    &fixture.local
                };
                rewrite_json(original, |profile| {
                    let settings = if remote {
                        &mut profile["settings"]
                    } else {
                        profile
                    };
                    if captured {
                        settings["stdin"] = "inherit".into();
                    } else {
                        settings["stdin_file"] = "inputs/old.bin".into();
                    }
                });
                let before = fs::read(original).unwrap();
                let mut command = fixture.command_using(remote, Path::new(SUBCOMMAND));
                command.env("CARGO_RABS_DAEMON", &fixture.daemon);
                if captured {
                    command.args(["--rabs-stdin-file", "inputs/request.bin"]);
                } else {
                    command.arg("--rabs-stdin=closed");
                }
                command.arg("--").args(&cargo);
                let report = fixture.handed_off(command.output().unwrap());
                let settings = if remote {
                    &report["profile"]["settings"]
                } else {
                    &report["profile"]
                };
                assert_eq!(settings["command"], cargo[0]);
                if cargo[0] == "nextest" {
                    assert_eq!(settings["selection"]["test_threads"], 2);
                    assert_eq!(settings["jobs"], 2);
                }
                if captured {
                    assert_eq!(settings["stdin_file"], "inputs/request.bin");
                    assert!(settings.get("stdin").is_none());
                } else {
                    assert_eq!(settings["stdin"], "closed");
                    assert!(settings.get("stdin_file").is_none());
                }
                assert_eq!(fs::read(original).unwrap(), before);
            }
        }
    }
}

#[test]
fn cargo_subcommand_worker_captured_input_reaches_the_single_native_handoff() {
    for cargo in [
        vec!["run"],
        vec!["test"],
        vec!["nextest", "run", "--test-threads", "2"],
        vec!["bench"],
    ] {
        let fixture = Fixture::new();
        if cargo[0] == "nextest" {
            new_file(
                &fixture.toolchain.join("bin/cargo-nextest"),
                b"unused captured runner fixture",
                0o700,
            );
        }
        let path = "inputs/request α.bin";
        let input = b"\0captured source input\xff\n";
        new_file(&fixture.source.join(path), input, 0o600);
        let child = fixture
            .worker_command()
            .arg(format!("--rabs-stdin-file={path}"))
            .arg("--")
            .args(&cargo)
            .args(["--", "--rabs-stdin=closed", ""])
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let pid = child.id();
        let output = child.wait_with_output().unwrap();
        assert_eq!(output.status.code(), Some(47), "{output:?}");
        assert!(
            String::from_utf8(output.stderr)
                .unwrap()
                .contains("retained worker operation")
        );
        let report = fixture.report();
        assert_eq!(report["pid"], pid);
        assert_eq!(report["active"], "1");
        assert_eq!(report["source_input"], json!(input));
        assert_eq!(report["spec"]["captured_stdin"]["path"], path);
        assert_eq!(
            report["spec"]["captured_stdin"]["version"],
            "source-file-stdin-v1"
        );
        let args = report["spec"]["args"].as_array().unwrap();
        assert_eq!(args[0], cargo[0]);
        if cargo[0] == "nextest" {
            assert_eq!(report["spec"]["jobserver_grant"], 1);
            assert_eq!(report["spec"]["artifacts"]["cargo"]["build_jobs"], 1);
            assert_eq!(
                report["spec"]["artifacts"]["cargo"]["selection"]["test_threads"],
                2
            );
        }
        assert_eq!(
            &args[args.len() - 3..],
            &[json!("--"), json!("--rabs-stdin=closed"), json!("")]
        );
        assert_eq!(fs::read(fixture.source.join(path)).unwrap(), input);
        assert_eq!(fs::read_dir(&fixture.operations).unwrap().count(), 1);
    }
}

#[test]
fn cargo_subcommand_input_does_not_bypass_native_route_or_execution_restrictions() {
    for route in ["local", "remote", "worker"] {
        let mut rejected = vec![
            vec!["--rabs-stdin", "unknown", "run"],
            vec!["--rabs-stdin-file", "../outside", "run"],
            vec!["--rabs-stdin-file", "inputs/request.bin", "check"],
            vec![
                "--rabs-stdin-file",
                "inputs/request.bin",
                "test",
                "--no-run",
            ],
            vec![
                "--rabs-stdin-file",
                "inputs/request.bin",
                "nextest",
                "run",
                "--no-run",
            ],
            vec![
                "--rabs-stdin",
                "closed",
                "--rabs-stdin-file",
                "inputs/request.bin",
                "run",
            ],
            vec!["--", "run", "--rabs-stdin", "closed"],
        ];
        if route != "local" {
            rejected.push(vec!["--rabs-stdin", "inherit", "run"]);
        }
        for args in rejected {
            let fixture = Fixture::new();
            let mut command = if route == "worker" {
                fixture.worker_command()
            } else {
                fixture.command_using(route == "remote", Path::new(SUBCOMMAND))
            };
            command.env("CARGO_RABS_DAEMON", &fixture.daemon).args(args);
            fixture.refused_subcommand(command.output().unwrap());
        }
    }
    let fixture = Fixture::new();
    rewrite_json(&fixture.local, |profile| {
        profile["service_socket"] = json!(fixture.root.join("canonical.sock"));
    });
    fixture.refused_subcommand(
        fixture
            .command_using(false, Path::new(SUBCOMMAND))
            .env("CARGO_RABS_DAEMON", &fixture.daemon)
            .args(["--rabs-stdin", "inherit", "run"])
            .output()
            .unwrap(),
    );
}

#[test]
fn cargo_subcommand_rustup_discovery_reexecutes_its_native_guard() {
    let fixture = Fixture::new();
    rewrite_json(&fixture.local, |profile| {
        profile.as_object_mut().unwrap().remove("toolchain_root");
        profile["toolchain"] = "rustup".into();
    });
    let rustup = fixture.root.join("rustup fixture");
    rustup_fixture(&rustup);
    let output = fixture
        .command_using(false, Path::new(SUBCOMMAND))
        .env("CARGO_RABS_DAEMON", &fixture.daemon)
        .env("CARGO_RABS_RUSTUP", &rustup)
        .env(
            "RABS_CARGO_TEST_RUSTUP_PATH",
            fixture.toolchain.join("bin/rustc"),
        )
        .env(
            "RABS_CARGO_TEST_RUSTUP_REPORT",
            fixture.root.join("rustup-report.json"),
        )
        .args(["--", "+selected-native", "check"])
        .output()
        .unwrap();
    let report = fixture.handed_off(output);
    assert_eq!(
        report["profile"]["toolchain_root"],
        json!(fixture.toolchain)
    );
    assert_eq!(
        fixture.rustup_report()["argv"],
        json!(["which", "--toolchain", "selected-native", "rustc"])
    );
}

#[test]
fn rustup_discovery_preserves_caller_context_and_retains_only_the_physical_sdk() {
    for remote in [false, true] {
        let fixture = Fixture::new();
        let caller = fixture.root.join("original caller");
        private_directory(&caller);
        let mut command = fixture.rustup_command(remote);
        command
            .current_dir(&caller)
            .env("RUSTUP_TOOLCHAIN", "caller-selected-nightly")
            .env("RUSTUP_HOME", fixture.root.join("caller rustup home"))
            .env("RUSTUP_AUTO_INSTALL", "1");
        if remote {
            command.env("RABS_CARGO_TEST_RUSTUP_MODE", "no-newline");
        }
        let report = fixture.handed_off(command.output().unwrap());
        let discovery = fixture.rustup_report();
        assert_eq!(discovery["argv"], json!(["which", "rustc"]));
        assert_eq!(discovery["cwd"], json!(caller));
        assert_eq!(discovery["auto_install"], "0");
        assert_eq!(discovery["selected"], "caller-selected-nightly");
        assert_eq!(
            discovery["home"],
            json!(fixture.root.join("caller rustup home"))
        );
        assert_eq!(discovery["stdin"], json!([]));
        assert_eq!(
            report["rustup_auto_install"], "1",
            "discovery must not change driver environment"
        );
        assert_eq!(report["rustup_toolchain"], "caller-selected-nightly");
        assert_eq!(
            report["profile"]["toolchain_root"],
            json!(fixture.toolchain)
        );
        assert!(report["profile"].get("toolchain").is_none());
        assert_eq!(
            fs::read_dir(if remote {
                &fixture.staging
            } else {
                &fixture.operations
            })
            .unwrap()
            .count(),
            1
        );
    }
}

#[test]
fn rustup_cli_override_precedes_environment_and_runtime_tails_remain_literal() {
    let fixture = Fixture::new();
    let mut command = fixture.rustup_command(false);
    command
        .env("RUSTUP_TOOLCHAIN", "environment-choice")
        .args([
            "--",
            "+nightly-2026-08-31",
            "run",
            "--",
            "+literal",
            "--toolchain",
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = command.spawn().unwrap();
    let input = b"\0workload payload\xff";
    child.stdin.take().unwrap().write_all(input).unwrap();
    let report = fixture.handed_off(child.wait_with_output().unwrap());
    let discovery = fixture.rustup_report();
    assert_eq!(
        discovery["argv"],
        json!(["which", "--toolchain", "nightly-2026-08-31", "rustc"])
    );
    assert_eq!(discovery["selected"], "environment-choice");
    assert_eq!(
        discovery["stdin"],
        json!([]),
        "discovery cannot consume program input"
    );
    assert_eq!(report["stdin"], json!(input));
    assert_eq!(
        report["profile"]["selection"]["run_args"],
        json!(["+literal", "--toolchain"])
    );
}

#[test]
fn rustup_lookup_supports_relative_override_and_ordered_relative_or_empty_path_entries() {
    for variant in ["relative-override", "relative-path", "empty-path"] {
        let fixture = Fixture::new();
        let mut command = fixture.rustup_command(false);
        command.current_dir(&fixture.root);
        if variant == "relative-override" {
            command.env("CARGO_RABS_RUSTUP", "rustup fixture");
        } else {
            let denied = fixture.root.join("denied");
            private_directory(&denied);
            new_file(&denied.join("rustup"), b"not executable", 0o600);
            let selected = if variant == "relative-path" {
                let relative = fixture.root.join("relative");
                private_directory(&relative);
                relative
            } else {
                fixture.root.clone()
            };
            rustup_fixture(&selected.join("rustup"));
            command.env_remove("CARGO_RABS_RUSTUP").env(
                "PATH",
                if variant == "relative-path" {
                    "missing:denied:relative"
                } else {
                    "missing:denied:"
                },
            );
        }
        let report = fixture.handed_off(command.arg("check").output().unwrap());
        assert_eq!(
            report["profile"]["toolchain_root"],
            json!(fixture.toolchain)
        );
        assert_eq!(fixture.rustup_report()["cwd"], json!(fixture.root));
    }
}

#[test]
fn ambiguous_toolchain_intent_and_invalid_profiles_do_not_launch_discovery() {
    for case in 0..9 {
        let fixture = Fixture::new();
        let mut command = fixture.rustup_command(case >= 6);
        let profile = if case >= 6 {
            &fixture.remote
        } else {
            &fixture.local
        };
        match case {
            0 => rewrite_json(profile, |value| {
                value["toolchain_root"] = json!(fixture.toolchain)
            }),
            1 => rewrite_json(profile, |value| {
                value.as_object_mut().unwrap().remove("toolchain");
            }),
            2 => rewrite_json(profile, |value| value["toolchain"] = "nightly".into()),
            3 => {
                rewrite_json(profile, |value| {
                    value.as_object_mut().unwrap().remove("toolchain");
                    value["toolchain_root"] = json!(fixture.toolchain);
                });
                command.args(["+nightly", "build"]);
            }
            4 => rewrite_json(profile, |value| {
                value["unknown_execution_control"] = true.into()
            }),
            5 => {
                fs::set_permissions(&fixture.operations, fs::Permissions::from_mode(0o755)).unwrap()
            }
            6 => rewrite_json(profile, |value| {
                value["tls"]["private_key"] = json!(fixture.root.join("missing-key"))
            }),
            7 => rewrite_json(profile, |value| {
                value["output_destination"] = json!(fixture.outputs.join("ambiguous"))
            }),
            8 => rewrite_json(profile, |value| value["coordinator_pin"] = "invalid".into()),
            _ => unreachable!(),
        }
        fixture.refused(command.output().unwrap());
        assert!(
            !fixture.root.join("rustup-report.json").exists(),
            "case {case} launched discovery before validation"
        );
    }
}

#[test]
fn invalid_rustup_executables_and_replies_refuse_before_backend_execution() {
    for mode in ["fail", "oversized", "binary", "multiple", "empty"] {
        let fixture = Fixture::new();
        let stderr = fixture.refused(
            fixture
                .rustup_command(false)
                .env("RABS_CARGO_TEST_RUSTUP_MODE", mode)
                .output()
                .unwrap(),
        );
        assert!(!stderr.contains("private discovery error"));
    }
    for selected in ["", "/missing/rustup", BINARY] {
        let fixture = Fixture::new();
        fixture.refused(
            fixture
                .rustup_command(false)
                .env("CARGO_RABS_RUSTUP", selected)
                .output()
                .unwrap(),
        );
        assert!(!fixture.root.join("rustup-report.json").exists());
    }
    for path in [
        "relative/bin/rustc",
        "/toolchain/../elsewhere/bin/rustc",
        "/toolchain/bin/cargo",
    ] {
        let fixture = Fixture::new();
        fixture.refused(
            fixture
                .rustup_command(false)
                .env("RABS_CARGO_TEST_RUSTUP_PATH", path)
                .output()
                .unwrap(),
        );
    }
}

#[test]
fn discovered_toolchains_keep_the_ordinary_directory_and_executable_contract() {
    for case in 0..4 {
        let fixture = Fixture::new();
        let mut command = fixture.rustup_command(false);
        match case {
            0 => {
                let alias = fixture.root.join("linked toolchain");
                symlink(&fixture.toolchain, &alias).unwrap();
                command.env("RABS_CARGO_TEST_RUSTUP_PATH", alias.join("bin/rustc"));
            }
            1 => fs::set_permissions(
                fixture.toolchain.join("bin/rustc"),
                fs::Permissions::from_mode(0o600),
            )
            .unwrap(),
            2 => fs::set_permissions(
                fixture.toolchain.join("bin/cargo"),
                fs::Permissions::from_mode(0o600),
            )
            .unwrap(),
            3 => {
                let sdk = fixture.root.join("symlinked compiler sdk");
                private_directory(&sdk);
                private_directory(&sdk.join("bin"));
                new_file(&sdk.join("bin/cargo"), b"unused compiler fixture", 0o700);
                symlink(fixture.toolchain.join("bin/rustc"), sdk.join("bin/rustc")).unwrap();
                command.env("RABS_CARGO_TEST_RUSTUP_PATH", sdk.join("bin/rustc"));
            }
            _ => unreachable!(),
        }
        fixture.refused(command.output().unwrap());
    }
}

fn assert_process_stopped(pid: u32) {
    let path = format!("/proc/{pid}/status");
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
    loop {
        match fs::read_to_string(&path) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return,
            Ok(status)
                if status.lines().any(|line| {
                    line.starts_with("State:")
                        && line
                            .split_whitespace()
                            .nth(1)
                            .is_some_and(|state| matches!(state, "Z" | "X"))
                }) =>
            {
                return;
            }
            Ok(_) => {}
            Err(error) => panic!("cannot inspect discovery process {pid}: {error}"),
        }
        assert!(
            std::time::Instant::now() < deadline,
            "discovery process {pid} remained alive"
        );
        std::thread::sleep(std::time::Duration::from_millis(5));
    }
}

#[test]
fn stalled_rustup_and_descendant_output_writers_share_the_five_second_deadline() {
    for mode in ["hang", "pipe-held"] {
        let fixture = Fixture::new();
        let descendant = fixture.root.join("rustup-child.pid");
        let started = std::time::Instant::now();
        let stderr = fixture.refused(
            fixture
                .rustup_command(false)
                .env("RABS_CARGO_TEST_RUSTUP_MODE", mode)
                .env("RABS_CARGO_TEST_RUSTUP_CHILD", &descendant)
                .output()
                .unwrap(),
        );
        assert!(stderr.contains("timed out"), "{stderr}");
        assert!(started.elapsed() < std::time::Duration::from_secs(10));
        assert_process_stopped(fixture.rustup_report()["pid"].as_u64().unwrap() as u32);
        if mode == "pipe-held" {
            assert_process_stopped(fs::read_to_string(descendant).unwrap().parse().unwrap());
        }
    }
}

#[test]
fn terminating_the_frontend_drains_its_independently_owned_rustup_process() {
    use rustix::process::{Pid, Signal, kill_process};
    for signal in [Signal::INT, Signal::TERM, Signal::KILL] {
        let fixture = Fixture::new();
        let child = fixture
            .rustup_command(false)
            .env("RABS_CARGO_TEST_RUSTUP_MODE", "hang")
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(3);
        let discovery = loop {
            if let Ok(bytes) = fs::read(fixture.root.join("rustup-report.json"))
                && let Ok(report) = serde_json::from_slice::<Value>(&bytes)
            {
                break report;
            }
            assert!(std::time::Instant::now() < deadline, "Rustup did not start");
            std::thread::sleep(std::time::Duration::from_millis(2));
        };
        kill_process(Pid::from_child(&child), signal).unwrap();
        let output = child.wait_with_output().unwrap();
        assert!(output.status.signal().is_some(), "{output:?}");
        assert_process_stopped(discovery["pid"].as_u64().unwrap() as u32);
        assert!(!fixture.report.exists());
        assert_eq!(fs::read_dir(&fixture.operations).unwrap().count(), 0);
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
fn nextest_unknown_runtime_concurrency_refuses_before_native_handoff() {
    for remote in [false, true] {
        for arguments in [
            vec!["nextest", "run"],
            vec!["nextest", "run", "--test-threads", "1", "--", "--jobs=8"],
        ] {
            let fixture = Fixture::new();
            new_file(
                &fixture.toolchain.join("bin/cargo-nextest"),
                b"unused captured runner fixture",
                0o700,
            );
            let stderr = fixture.refused(fixture.command(remote).args(arguments).output().unwrap());
            assert!(
                stderr.contains("test-threads") || stderr.contains("concurrency"),
                "{stderr}"
            );
        }
    }
}

#[test]
fn nextest_invalid_partitions_refuse_before_native_handoff() {
    for remote in [false, true] {
        for partition in ["hash:0/3", "slice:4/3", "count:1/0", "unknown:1/3"] {
            let fixture = Fixture::new();
            new_file(
                &fixture.toolchain.join("bin/cargo-nextest"),
                b"unused captured runner fixture",
                0o700,
            );
            let stderr = fixture.refused(
                fixture
                    .command(remote)
                    .args([
                        "nextest",
                        "run",
                        "--test-threads",
                        "1",
                        "--partition",
                        partition,
                    ])
                    .output()
                    .unwrap(),
            );
            assert!(stderr.contains("partition"), "{stderr}");
        }
    }
}

#[test]
fn nextest_validates_captured_runner_and_retains_local_and_remote_intent() {
    for remote in [false, true] {
        let fixture = Fixture::new();
        fixture.refused(
            fixture
                .command(remote)
                .args(["nextest", "run"])
                .output()
                .unwrap(),
        );
        new_file(
            &fixture.toolchain.join("bin/cargo-nextest"),
            b"unused captured runner fixture",
            0o700,
        );
        let report = fixture.handed_off(
            fixture
                .command(remote)
                .args([
                    "nextest",
                    "run",
                    "--workspace",
                    "--cargo-profile",
                    "release",
                    "--profile",
                    "ci",
                    "--test-threads",
                    "1",
                    "--partition",
                    "slice:2/3",
                    "-E",
                    "package(core)",
                    "--",
                    "--exact",
                ])
                .output()
                .unwrap(),
        );
        let settings = if remote {
            &report["profile"]["settings"]
        } else {
            &report["profile"]
        };
        assert_eq!(settings["command"], "nextest");
        assert_eq!(settings["selection"]["profile"], "release");
        assert_eq!(settings["selection"]["runner_profile"], "ci");
        assert_eq!(settings["selection"]["test_threads"], 1);
        assert_eq!(settings["selection"]["partition"], "slice:2/3");
        assert_eq!(
            settings["selection"]["filtersets"],
            json!(["package(core)"])
        );
        assert_eq!(settings["selection"]["test_args"], json!(["--exact"]));
        assert_eq!(settings["selection"]["packages"], json!([]));
        assert_eq!(settings["jobs"], 2);
    }
}

#[test]
fn selected_vendor_intent_reaches_local_and_remote_drivers_unchanged() {
    for remote in [false, true] {
        for binary in [BINARY, SUBCOMMAND] {
            let fixture = Fixture::new();
            let profile = if remote {
                &fixture.remote
            } else {
                &fixture.local
            };
            rewrite_json(profile, |profile| {
                let settings = if remote {
                    &mut profile["settings"]
                } else {
                    profile
                };
                settings["vendor"] = json!("vendor");
                settings["source_selection"] = json!("cargo-unit-graph-v1");
            });
            let mut command = fixture.command_using(remote, Path::new(binary));
            command.env("CARGO_RABS_DAEMON", &fixture.daemon).args([
                "--",
                "check",
                "--package",
                "selected-package",
            ]);
            let report = fixture.handed_off(command.output().unwrap());
            let retained = &report["profile"];
            let settings = if remote {
                &retained["settings"]
            } else {
                retained
            };
            assert_eq!(settings["vendor"], "vendor");
            assert_eq!(settings["source_selection"], "cargo-unit-graph-v1");
            assert_eq!(settings["command"], "check");
            assert_eq!(
                settings["selection"]["packages"],
                json!(["selected-package"])
            );
            assert!(settings.get("cargo_home_source").is_none());
        }
    }
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
                .args([
                    "--stdin-file",
                    "inputs/request.bin",
                    "test",
                    "--",
                    "--no-run",
                ])
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

struct RchFixture {
    root: PathBuf,
    rch: PathBuf,
    report: PathBuf,
}

fn rch_process_fixture(path: &Path, route: &str) {
    let adapter = format!(
        "#!/bin/sh\nexport RABS_RCH_TEST_ROUTE={}\nexec {} --exact native_rch_process_fixture --ignored --nocapture -- \"$@\"\n",
        quote(OsStr::new(route)),
        quote(std::env::current_exe().unwrap().as_os_str()),
    );
    new_file(path, adapter.as_bytes(), 0o700);
}

impl RchFixture {
    fn new() -> Self {
        let root = tempfile::Builder::new()
            .prefix("rabs-native-rch-")
            .tempdir()
            .unwrap()
            .keep();
        let rch = root.join("RCH 'fixture'");
        rch_process_fixture(&rch, "explicit");
        let report = root.join("rch-report.json");
        Self { root, rch, report }
    }

    fn configure(&self, command: &mut Command) {
        command
            .current_dir(&self.root)
            .env("CARGO_RABS_RCH", &self.rch)
            .env("RABS_RCH_TEST_REPORT", &self.report)
            // None of these local tools may be probed or executed by this mode.
            .env("CARGO", "/missing/dispatcher-cargo")
            .env("CARGO_RABS_DAEMON", "/missing/dispatcher-daemon")
            .env("CARGO_RABS_WRAP", "/missing/dispatcher-wrapper")
            .env("CARGO_RABS_RUSTUP", "/missing/dispatcher-rustup")
            .env("RUSTUP_TOOLCHAIN", "selected-custom-toolchain")
            .env("RCH_WORKER", "selected-worker")
            .env("RCH_REQUIRE_REMOTE", "0")
            .env("RCH_RABS_WORKER_CACHE", "0")
            .stdin(Stdio::null());
        for key in [
            "CARGO_RABS_CANONICAL_ACTIVE",
            "CARGO_RABS_REMOTE_ACTIVE",
            "RCH_RABS_WORKER_ACTIVE",
            "CARGO_RABS_ROOT_BUDGET_DIR",
            "CARGO_RABS_ROOT_CAPACITY",
            "CARGO_RABS_ROOT_CGROUP",
            "RABS_RCH_TEST_SIGNAL",
            "RABS_RCH_TEST_JOBSERVER",
            "RABS_RCH_TEST_STATUS",
        ] {
            command.env_remove(key);
        }
    }

    fn command_using(&self, binary: &Path) -> Command {
        let mut command = Command::new(binary);
        self.configure(&mut command);
        command.arg("--rch");
        command
    }

    fn command(&self) -> Command {
        self.command_using(Path::new(BINARY))
    }

    fn report(&self) -> Value {
        serde_json::from_slice(&fs::read(&self.report).unwrap()).unwrap()
    }

    fn refused(&self, output: Output) -> String {
        assert_eq!(output.status.code(), Some(2), "{output:?}");
        assert!(output.stdout.is_empty(), "{output:?}");
        let stderr = String::from_utf8(output.stderr).unwrap();
        assert!(stderr.contains("rabs-cargo: refused:"), "{stderr}");
        assert!(
            !self.report.exists(),
            "RCH must not execute after a frontend refusal"
        );
        stderr
    }
}

#[test]
#[ignore = "Rust RCH fixture, invoked only by native handoff tests"]
fn native_rch_process_fixture() {
    let mut arguments = std::env::args_os();
    let arguments: Vec<_> = arguments
        .by_ref()
        .skip_while(|argument| argument != "--")
        .skip(1)
        .map(|argument| argument.into_string().unwrap())
        .collect();
    let mut input = Vec::new();
    std::io::stdin().read_to_end(&mut input).unwrap();
    let mut token = None;
    if std::env::var_os("RABS_RCH_TEST_JOBSERVER").is_some() {
        // The original descriptors must still exist across both execs. The
        // FIFO-backed jobserver uses the same shared token queue when opened
        // through procfs; no invented or duplicated token is admitted.
        let mut reader = OpenOptions::new()
            .read(true)
            .open("/proc/self/fd/3")
            .unwrap();
        let mut writer = OpenOptions::new()
            .write(true)
            .open("/proc/self/fd/4")
            .unwrap();
        let mut byte = [0];
        reader.read_exact(&mut byte).unwrap();
        writer.write_all(&byte).unwrap();
        token = Some(byte[0]);
    }
    let report = json!({
        "argv":arguments, "cwd":std::env::current_dir().unwrap(), "stdin":input,
        "pid":std::process::id(), "route":std::env::var("RABS_RCH_TEST_ROUTE").unwrap(),
        "required":std::env::var("RCH_REQUIRE_REMOTE").ok(),
        "cache":std::env::var("RCH_RABS_WORKER_CACHE").ok(),
        "remote_active":std::env::var("CARGO_RABS_REMOTE_ACTIVE").ok(),
        "canonical_active":std::env::var("CARGO_RABS_CANONICAL_ACTIVE").ok(),
        "worker_active":std::env::var("RCH_RABS_WORKER_ACTIVE").ok(),
        "cargo":std::env::var("CARGO").ok(),
        "daemon":std::env::var("CARGO_RABS_DAEMON").ok(),
        "wrapper":std::env::var("CARGO_RABS_WRAP").ok(),
        "toolchain":std::env::var("RUSTUP_TOOLCHAIN").ok(),
        "worker":std::env::var("RCH_WORKER").ok(),
        "jobserver":std::env::var("CARGO_MAKEFLAGS").ok(), "token":token,
    });
    new_file(
        Path::new(&std::env::var_os("RABS_RCH_TEST_REPORT").unwrap()),
        &serde_json::to_vec(&report).unwrap(),
        0o600,
    );
    std::io::stdout()
        .lock()
        .write_all(b"\0RCH stdout\xff\n")
        .unwrap();
    std::io::stderr()
        .lock()
        .write_all(b"\0RCH stderr\xfe\n")
        .unwrap();
    if std::env::var_os("RABS_RCH_TEST_SIGNAL").is_some() {
        rustix::process::kill_process(rustix::process::getpid(), rustix::process::Signal::TERM)
            .unwrap();
        panic!("RCH signal termination must propagate");
    }
    std::process::exit(
        std::env::var("RABS_RCH_TEST_STATUS")
            .map(|status| status.parse().unwrap())
            .unwrap_or(47),
    );
}

#[test]
fn rch_handoff_preserves_literal_arguments_input_context_and_process_identity() {
    let fixture = RchFixture::new();
    let cargo_arguments = [
        "+nightly-2026-08-31",
        "test",
        "name with spaces",
        "--",
        "",
        "a'quoted\"value",
        "$(printf unintended)",
        "α β",
        "--remote",
        "--rabs-unknown",
    ];
    let mut child = fixture
        .command()
        .arg("--")
        .args(cargo_arguments)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let pid = child.id();
    let input = b"\0opaque user input\xff\n";
    child.stdin.take().unwrap().write_all(input).unwrap();
    let output = child.wait_with_output().unwrap();
    assert_eq!(output.status.code(), Some(47), "{output:?}");
    // libtest contributes its fixture preamble; the final raw stream bytes
    // come from the execed RCH fixture without any frontend transformation.
    assert!(output.stdout.ends_with(b"\0RCH stdout\xff\n"), "{output:?}");
    assert_eq!(output.stderr, b"\0RCH stderr\xfe\n");
    let report = fixture.report();
    let mut expected = vec!["exec", "--source-content-receipt", "--", "cargo"];
    expected.extend(cargo_arguments);
    assert_eq!(report["argv"], json!(expected));
    assert_eq!(report["stdin"], json!(input));
    assert_eq!(report["pid"], pid);
    assert_eq!(report["cwd"], json!(fixture.root));
    assert_eq!(report["required"], "1");
    assert_eq!(report["cache"], "1");
    assert_eq!(report["remote_active"], "1");
    assert_eq!(report["canonical_active"], Value::Null);
    assert_eq!(report["worker_active"], Value::Null);
    assert_eq!(report["cargo"], "/missing/dispatcher-cargo");
    assert_eq!(report["daemon"], "/missing/dispatcher-daemon");
    assert_eq!(report["wrapper"], "/missing/dispatcher-wrapper");
    assert_eq!(report["toolchain"], "selected-custom-toolchain");
    assert_eq!(report["worker"], "selected-worker");
}

#[test]
fn rch_handoff_defaults_to_build_and_preserves_failure_and_signal_status() {
    for status in [0, 23, 101, 130, 255] {
        let fixture = RchFixture::new();
        let output = fixture
            .command()
            .env("RABS_RCH_TEST_STATUS", status.to_string())
            .output()
            .unwrap();
        assert_eq!(output.status.code(), Some(status), "{output:?}");
        assert_eq!(
            fixture.report()["argv"],
            json!(["exec", "--source-content-receipt", "--", "cargo", "build"])
        );
    }
    let fixture = RchFixture::new();
    let output = fixture
        .command()
        .arg("check")
        .env("RABS_RCH_TEST_SIGNAL", "1")
        .output()
        .unwrap();
    assert_eq!(
        output.status.signal(),
        Some(rustix::process::Signal::TERM.as_raw())
    );
    assert_eq!(fixture.report()["required"], "1");
}

#[test]
fn cargo_subcommand_remote_alias_uses_only_rch_and_never_retries_locally() {
    for arguments in [
        vec![],
        vec!["--", "+nightly-selected", "test", "--", "--rabs-no-start"],
    ] {
        let fixture = RchFixture::new();
        let mut command = Command::new(SUBCOMMAND);
        fixture.configure(&mut command);
        let output = command
            .args(["rabs", "--rabs-remote"])
            .args(&arguments)
            .env("RABS_RCH_TEST_STATUS", "255")
            .output()
            .unwrap();
        assert_eq!(output.status.code(), Some(255), "{output:?}");
        let mut expected = vec!["exec", "--source-content-receipt", "--", "cargo"];
        if arguments.is_empty() {
            expected.push("build");
        } else {
            expected.extend_from_slice(&arguments[1..]);
        }
        let report = fixture.report();
        assert_eq!(report["argv"], json!(expected));
        assert_eq!(report["required"], "1");
        assert_eq!(report["cache"], "1");
        assert_eq!(report["toolchain"], "selected-custom-toolchain");
    }
}

#[test]
fn rch_handoff_preserves_live_jobserver_descriptors_and_token_count() {
    let fixture = RchFixture::new();
    let fifo = fixture.root.join("jobserver");
    rustix::fs::mkfifoat(
        rustix::fs::CWD,
        &fifo,
        rustix::fs::Mode::RUSR | rustix::fs::Mode::WUSR,
    )
    .unwrap();
    let mut tokens = OpenOptions::new()
        .read(true)
        .write(true)
        .custom_flags(rustix::fs::OFlags::NONBLOCK.bits() as i32)
        .open(&fifo)
        .unwrap();
    tokens.write_all(b"T").unwrap();
    let mut command = Command::new("/bin/sh");
    fixture.configure(&mut command);
    let output = command
        .args([
            "-c",
            "exec 3<\"$1\"; exec 4>\"$1\"; shift; exec \"$@\"",
            "jobserver-handoff",
        ])
        .arg(&fifo)
        .args([BINARY, "--rch", "check"])
        .env("RABS_RCH_TEST_JOBSERVER", "1")
        .env("CARGO_MAKEFLAGS", "-j --jobserver-auth=3,4")
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(47), "{output:?}");
    let report = fixture.report();
    assert_eq!(report["jobserver"], "-j --jobserver-auth=3,4");
    assert_eq!(report["token"], b'T');
    let mut returned = [0_u8; 2];
    assert_eq!(tokens.read(&mut returned).unwrap(), 1);
    assert_eq!(returned[0], b'T');
    assert_eq!(
        tokens.read(&mut returned).unwrap_err().kind(),
        std::io::ErrorKind::WouldBlock
    );
}

#[test]
fn rch_handoff_refuses_recursive_context_and_incompatible_local_authority() {
    for key in [
        "CARGO_RABS_CANONICAL_ACTIVE",
        "CARGO_RABS_REMOTE_ACTIVE",
        "RCH_RABS_WORKER_ACTIVE",
        "CARGO_RABS_ROOT_BUDGET_DIR",
        "CARGO_RABS_ROOT_CAPACITY",
        "CARGO_RABS_ROOT_CGROUP",
    ] {
        let fixture = RchFixture::new();
        fixture.refused(
            fixture
                .command()
                .arg("check")
                .env(key, "1")
                .output()
                .unwrap(),
        );
    }
}

#[test]
fn rch_handoff_refuses_frontend_controls_and_opaque_arguments_before_execution() {
    use std::os::unix::ffi::OsStringExt;
    for control in [
        "--rch",
        "--cache",
        "--local=p.json",
        "--remote",
        "--rabsd",
        "--stdin=closed",
        "--stdin-file",
        "--rabs-no-start",
        "--rabs-unknown",
    ] {
        for after_command in [false, true] {
            let fixture = RchFixture::new();
            let mut command = fixture.command();
            if after_command {
                command.arg("build");
            }
            fixture.refused(command.arg(control).output().unwrap());
        }
    }
    let fixture = RchFixture::new();
    let error = fixture.refused(
        fixture
            .command()
            .args([
                OsString::from("build"),
                OsString::from_vec(b"bad\xff".to_vec()),
            ])
            .output()
            .unwrap(),
    );
    assert!(error.contains("UTF-8"));
}

#[test]
fn rch_handoff_resolves_physical_siblings_before_path_and_preserves_explicit_selection() {
    for route in ["sibling", "path", "explicit"] {
        let fixture = RchFixture::new();
        let generation = fixture.root.join("generation");
        let path_bin = fixture.root.join("path bin");
        private_directory(&generation);
        private_directory(&path_bin);
        let binary = generation.join("rabs-cargo");
        fs::copy(BINARY, &binary).unwrap();
        fs::set_permissions(&binary, fs::Permissions::from_mode(0o700)).unwrap();
        if route != "path" {
            rch_process_fixture(&generation.join("rch"), "sibling");
        }
        rch_process_fixture(&path_bin.join("rch"), "path");
        let public = fixture.root.join("public frontend");
        symlink(&binary, &public).unwrap();
        let mut command = fixture.command_using(&public);
        command.env("PATH", &path_bin);
        if route != "explicit" {
            command.env_remove("CARGO_RABS_RCH");
        }
        let output = command.output().unwrap();
        assert_eq!(output.status.code(), Some(47), "{route}: {output:?}");
        assert_eq!(fixture.report()["route"], route);
    }
}

#[test]
fn rch_handoff_refuses_invalid_or_recursive_explicit_executables_without_fallback() {
    for kind in [
        "missing",
        "empty",
        "not-executable",
        "directory",
        "symlink",
        "hardlink",
    ] {
        let fixture = RchFixture::new();
        let selected = fixture.root.join("selected");
        let frontend = if kind == "hardlink" {
            // Keep both links on the same filesystem even when TMPDIR differs
            // from Cargo's target volume.
            let copied = fixture.root.join("frontend");
            fs::copy(BINARY, &copied).unwrap();
            copied
        } else {
            PathBuf::from(BINARY)
        };
        match kind {
            "not-executable" => new_file(&selected, b"not executable", 0o600),
            "directory" => private_directory(&selected),
            "symlink" => symlink(BINARY, &selected).unwrap(),
            "hardlink" => fs::hard_link(&frontend, &selected).unwrap(),
            _ => (),
        }
        // A valid PATH candidate must never override an invalid explicit choice.
        rch_process_fixture(&fixture.root.join("rch"), "path-must-not-run");
        let value = if kind == "empty" {
            Path::new("")
        } else {
            &selected
        };
        fixture.refused(
            fixture
                .command_using(&frontend)
                .env("CARGO_RABS_RCH", value)
                .env("PATH", &fixture.root)
                .output()
                .unwrap(),
        );
    }
}

#[test]
fn rch_mode_help_needs_no_profile_backend_or_toolchain() {
    let output = Command::new(BINARY)
        .args(["--rch", "--help"])
        .env("CARGO_RABS_RCH", "/missing/rch")
        .env("CARGO_RABS_DAEMON", "/missing/daemon")
        .output()
        .unwrap();
    assert!(output.status.success(), "{output:?}");
    assert!(String::from_utf8(output.stdout).unwrap().contains("--rch"));
    assert!(output.stderr.is_empty());
}
