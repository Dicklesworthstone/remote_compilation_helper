//! Real native recovery processes and an execed Rust transport fixture.
//! Fixtures are retained: no repository, source, or test directories are removed.

#![cfg(target_os = "linux")]
#![forbid(unsafe_code)]

use rustix::fs::{Mode, SealFlags};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::ffi::{OsStr, OsString};
use std::fs::{self, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt, symlink};
use std::os::unix::process::ExitStatusExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::time::{Duration, Instant};

const BINARY: &str = env!("CARGO_BIN_EXE_rabs-recover");
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

fn digest(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut result = String::new();
    for byte in Sha256::digest(bytes) {
        write!(result, "{byte:02x}").unwrap();
    }
    result
}

fn quote(value: &OsStr) -> String {
    format!("'{}'", value.to_str().unwrap().replace('\'', "'\\''"))
}

struct Fixture {
    root: PathBuf,
    state: PathBuf,
    intent: PathBuf,
    record: PathBuf,
    request: PathBuf,
    daemon: PathBuf,
    report: PathBuf,
    request_bytes: Vec<u8>,
}

impl Fixture {
    fn new(canonical: Option<bool>) -> Self {
        let root = tempfile::Builder::new()
            .prefix("rabs-native-recovery-")
            .tempdir()
            .unwrap()
            .keep();
        let state = root.join("original state");
        private_directory(&state);
        let intent = if canonical.is_some() {
            root.join("canonical operation")
        } else {
            state.join("result-18446744073709551615")
        };
        private_directory(&intent);
        let (record, request, request_value, record_value) = if let Some(legacy) = canonical {
            private_directory(&intent.join("bundle"));
            let request = json!({
                "kind": "canonical-exec", "request_id": u64::MAX,
                "program": "/__rabs/toolchain/bin/cargo-clippy", "source_manifest": {},
                "artifacts": {"unit":"cargo", "tree":"tree-files-v1", "cargo":"cargo-private-incremental-test-json-v1"},
                "environment": {"RABS_RECOVERY_SECRET":"must-not-be-printed"},
            });
            let mut record = json!({
                "version":"canonical-cargo-v1", "operation_directory":intent,
                "request_id":"allocate", "automatic_retry":false, "publication_authorized":false,
                "prepared_build_argv":["/never-execute-the-recorded-program", "--worker-build-tls", "--replay-diagnostics",
                    "[2001:db8::1]:7443", "worker α", PIN, intent.join("bundle"), intent.join("delivery"), intent.join("outputs")],
            });
            if !legacy {
                record["recovery"] = json!({
                    "schema":"rabs-canonical-cargo-recovery-v1", "transport_state_dir":state,
                    "request_file":"bundle/request.json", "partial_delivery":"delivery",
                    "recovery_mode":"resume-or-acknowledge-only", "worker_id":"worker α",
                    "worker_spki_sha256":PIN, "listen":"[2001:db8::1]:7443",
                    "reexecute":false, "publication_authorized":false,
                });
            }
            (
                intent.join("operation.json"),
                intent.join("bundle/request.json"),
                request,
                record,
            )
        } else {
            let request = json!({
                "kind":"canonical-exec", "request_id":u64::MAX,
                "program":"/__rabs/toolchain/bin/rustc", "dependency_context":"dependency-exec-v8",
                "environment":{"RABS_RECOVERY_SECRET":"must-not-be-printed"},
            });
            let record = json!({
                "schema":"rabs-live-remote-recovery-v1", "recovery_mode":"resume-or-acknowledge-only",
                "execution_state":"unknown", "reexecute":false, "publication_authorized":false,
                "request_file":"request.json", "partial_delivery":"delivery", "transport_state_dir":state,
                "request_id":u64::MAX, "action_key":"action-α", "request_sha256":"filled below",
                "remote_configuration":{"remote_protocol":1, "worker_id":"worker α", "worker_spki_sha256":PIN,
                    "listen":"[2001:db8::1]:7443"},
            });
            (
                intent.join("recovery.json"),
                intent.join("request.json"),
                request,
                record,
            )
        };
        // Whitespace is deliberate: the handoff must retain exact bytes, not
        // deserialize and re-serialize the request before sending it onward.
        let mut request_bytes = serde_json::to_vec_pretty(&request_value).unwrap();
        request_bytes.push(b'\n');
        let mut record_value = record_value;
        if canonical.is_none() {
            record_value["request_sha256"] = digest(&request_bytes).into();
        }
        new_file(&request, &request_bytes, 0o600);
        new_file(&record, &serde_json::to_vec(&record_value).unwrap(), 0o600);
        let daemon = root.join("native transport 'fixture'");
        let adapter = format!(
            "#!/bin/sh\nexec {} --exact native_daemon_fixture --ignored --nocapture -- \"$@\"\n",
            quote(std::env::current_exe().unwrap().as_os_str())
        );
        new_file(&daemon, adapter.as_bytes(), 0o700);
        let report = root.join("transport-report.json");
        Self {
            root,
            state,
            intent,
            record,
            request,
            daemon,
            report,
            request_bytes,
        }
    }

    fn live() -> Self {
        Self::new(None)
    }

    fn canonical(legacy: bool) -> Self {
        Self::new(Some(legacy))
    }

    fn command(&self) -> Command {
        self.command_using(Path::new(BINARY))
    }

    fn command_using(&self, binary: &Path) -> Command {
        let mut command = Command::new(binary);
        if binary == Path::new(SUBCOMMAND) {
            command.args(["rabs", "--rabs-recover"]);
        }
        command
            .arg(&self.intent)
            .env_remove("CARGO_RABS_DAEMON")
            .env("RABS_STATE_DIR", self.root.join("wrong current state"))
            .env("RABS_COORD_TLS_CA", self.root.join("coordinator ca.pem"))
            .env(
                "RABS_COORD_TLS_CERT",
                self.root.join("coordinator cert.pem"),
            )
            .env("RABS_COORD_TLS_KEY", self.root.join("coordinator key.pem"))
            .env("RABS_RECOVER_TEST_REPORT", &self.report)
            .env("RABS_RECOVER_TEST_SOURCE", &self.request)
            .env("RABS_RECOVER_TEST_UNRELATED", "preserved verbatim")
            .stdin(Stdio::null());
        command
    }

    fn operation(&self, option: &str, destination: &Path) -> Command {
        let mut command = self.command();
        command
            .arg(option)
            .arg(destination)
            .arg("--rabsd")
            .arg(&self.daemon);
        command
    }

    fn refused(&self, output: Output) -> String {
        assert_eq!(output.status.code(), Some(2), "{output:?}");
        assert!(output.stdout.is_empty(), "{output:?}");
        let stderr = String::from_utf8(output.stderr).unwrap();
        assert!(stderr.contains("rabs-recover: refused:"), "{stderr}");
        assert!(stderr.contains("no execution retry"), "{stderr}");
        assert!(!stderr.contains("must-not-be-printed"), "{stderr}");
        assert!(!self.report.exists(), "transport must not run on refusal");
        stderr
    }

    fn report(&self) -> Value {
        serde_json::from_slice(&fs::read(&self.report).unwrap()).unwrap()
    }

    fn refresh_request_digest(&self) {
        let hash = digest(&fs::read(&self.request).unwrap());
        rewrite_json(&self.record, |record| {
            record["request_sha256"] = hash.into()
        });
    }
}

#[test]
#[ignore = "Rust subprocess transport fixture; invoked only by the operator process tests"]
fn native_daemon_fixture() {
    let report = std::env::var_os("RABS_RECOVER_TEST_REPORT").expect("fixture report path");
    let all: Vec<OsString> = std::env::args_os().collect();
    let delimiter = all.iter().position(|argument| argument == "--").unwrap();
    let arguments = &all[delimiter + 1..];
    assert_eq!(arguments[0], "--worker-exec-tls");
    let request_path = arguments
        .iter()
        .find(|argument| argument.as_encoded_bytes().starts_with(b"/proc/self/fd/"))
        .unwrap();
    let original_fd = Path::new(request_path).file_name().unwrap();
    let fdinfo = fs::read_to_string(Path::new("/proc/self/fdinfo").join(original_fd)).unwrap();
    assert!(fdinfo.lines().any(|line| line == "pos:\t0"), "{fdinfo}");
    // Replace the mutable source after exec. The transport must still see the
    // originally validated snapshot, not reopen that source pathname.
    if std::env::var_os("RABS_RECOVER_TEST_MUTATE_SOURCE").is_some() {
        fs::write(
            std::env::var_os("RABS_RECOVER_TEST_SOURCE").unwrap(),
            b"changed-after-handoff",
        )
        .unwrap();
    }
    let mut request = OpenOptions::new()
        .read(true)
        .write(true)
        .open(request_path)
        .unwrap();
    let seals = rustix::fs::fcntl_get_seals(&request).unwrap();
    assert!(
        seals.contains(SealFlags::WRITE | SealFlags::GROW | SealFlags::SHRINK | SealFlags::SEAL)
    );
    assert!(request.write_all(b"forbidden change").is_err());
    assert!(request.set_len(0).is_err());
    assert!(request.set_len(2 * 1024 * 1024).is_err());
    let mut bytes = Vec::new();
    request.read_to_end(&mut bytes).unwrap();
    if let Some(ready) = std::env::var_os("RABS_RECOVER_TEST_READY") {
        new_file(Path::new(&ready), b"native transport entered", 0o600);
    }
    let mut input = Vec::new();
    std::io::stdin().read_to_end(&mut input).unwrap();
    let arguments: Vec<_> = arguments
        .iter()
        .map(|value| value.to_str().unwrap())
        .collect();
    let result = json!({
        "argv":arguments, "request":bytes, "stdin":input, "pid":std::process::id(),
        "state":std::env::var("RABS_STATE_DIR").unwrap(),
        "tls":[std::env::var("RABS_COORD_TLS_CA").unwrap(),std::env::var("RABS_COORD_TLS_CERT").unwrap(),std::env::var("RABS_COORD_TLS_KEY").unwrap()],
        "unrelated":std::env::var("RABS_RECOVER_TEST_UNRELATED").unwrap(), "sealed":true,
        "generation":std::env::var("RABS_RECOVER_TEST_GENERATION").ok(),
    });
    // create_new makes a second transport execution fail rather than masking
    // duplicate handoffs by overwriting the first result.
    new_file(
        Path::new(&report),
        &serde_json::to_vec(&result).unwrap(),
        0o600,
    );
    if std::env::var_os("RABS_RECOVER_TEST_SIGNAL").is_some() {
        rustix::process::kill_process(rustix::process::getpid(), rustix::process::Signal::TERM)
            .unwrap();
        panic!("default signal termination must be preserved");
    }
    std::process::exit(37);
}

#[test]
fn inspect_both_schemas_without_credentials_or_native_transport() {
    for fixture in [Fixture::live(), Fixture::canonical(false)] {
        let output = fixture
            .command()
            .env_remove("RABS_COORD_TLS_CA")
            .env_remove("RABS_COORD_TLS_CERT")
            .env_remove("RABS_COORD_TLS_KEY")
            .env("CARGO_RABS_DAEMON", "/does/not/exist")
            .output()
            .unwrap();
        assert!(output.status.success(), "{output:?}");
        let result: Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(result["kind"], "rabs-remote-recovery-intent");
        assert_eq!(result["request_id"], u64::MAX);
        assert_eq!(
            result["transport_state_dir"],
            fixture.state.to_str().unwrap()
        );
        assert_eq!(result["worker_id"], "worker α");
        assert_eq!(result["outputs_verified"], false);
        assert_eq!(result["publication_authorized"], false);
        assert_eq!(result["reexecute"], false);
        if fixture.record.ends_with("recovery.json") {
            assert_eq!(result["action_key"], "action-α");
            assert_eq!(result["origin"], "live-dependency");
        } else {
            assert_eq!(result["action_key"], Value::Null);
            assert_eq!(result["origin"], "canonical-cargo");
        }
        assert!(!String::from_utf8_lossy(&output.stdout).contains("must-not-be-printed"));
        assert!(!fixture.report.exists());
        assert!(!fixture.intent.join("delivery").exists());
    }
}

#[test]
fn cargo_subcommand_recovery_resumes_the_exact_retained_delivery_without_reexecution() {
    for kind in ["default-new", "default-existing", "explicit-delivery"] {
        let fixture = Fixture::canonical(false);
        let before = fs::read(&fixture.record).unwrap();
        let destination = if kind == "explicit-delivery" {
            fixture.root.join("retained delivery")
        } else {
            fixture.intent.join("delivery")
        };
        if kind != "default-new" {
            private_directory(&destination);
            new_file(
                &destination.join("untrusted-prefix"),
                b"retained partial bytes",
                0o600,
            );
        }
        let mut command = fixture.command_using(Path::new(SUBCOMMAND));
        command.env("CARGO_RABS_DAEMON", &fixture.daemon);
        if kind == "explicit-delivery" {
            command.arg("--delivery").arg(&destination);
        }
        let output = command.output().unwrap();
        assert_eq!(output.status.code(), Some(37), "{kind}: {output:?}");
        let report = fixture.report();
        assert_eq!(report["argv"][0], "--worker-exec-tls");
        assert_eq!(report["argv"][1], "--resume");
        assert_eq!(
            report["argv"].as_array().unwrap().last().unwrap(),
            &json!(destination)
        );
        assert_eq!(report["request"], json!(fixture.request_bytes));
        assert_eq!(report["state"], json!(fixture.state));
        assert_eq!(report["sealed"], true);
        assert_eq!(fs::read(&fixture.record).unwrap(), before);
        assert_eq!(fs::read(&fixture.request).unwrap(), fixture.request_bytes);
        assert!(!fixture.intent.join("outputs").exists());
        if kind != "default-new" {
            assert_eq!(
                fs::read(destination.join("untrusted-prefix")).unwrap(),
                b"retained partial bytes"
            );
        }
    }
}

#[test]
fn cargo_subcommand_recovery_refuses_public_or_overlapping_retained_delivery() {
    for public in [false, true] {
        let fixture = Fixture::canonical(false);
        let mut command = fixture.command_using(Path::new(SUBCOMMAND));
        command.env("CARGO_RABS_DAEMON", &fixture.daemon);
        if public {
            let delivery = fixture.intent.join("delivery");
            private_directory(&delivery);
            fs::set_permissions(&delivery, fs::Permissions::from_mode(0o755)).unwrap();
        } else {
            command.arg("--delivery").arg(fixture.intent.join("bundle"));
        }
        let output = command.output().unwrap();
        assert_eq!(output.status.code(), Some(2), "{output:?}");
        assert!(output.stdout.is_empty());
        assert!(!fixture.report.exists());
        assert_eq!(fs::read(&fixture.request).unwrap(), fixture.request_bytes);
    }
}

#[test]
fn resume_executes_once_with_exact_snapshot_state_peer_stdin_and_environment() {
    for fixture in [Fixture::live(), Fixture::canonical(false)] {
        let destination = fixture.root.join("new recovery 'directory'");
        let mut command = fixture.operation("--resume-to", &destination);
        command
            .env("RABS_RECOVER_TEST_MUTATE_SOURCE", "1")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let mut child = command.spawn().unwrap();
        let pid = child.id();
        child
            .stdin
            .take()
            .unwrap()
            .write_all(b"original stdin\0payload")
            .unwrap();
        let output = child.wait_with_output().unwrap();
        assert_eq!(output.status.code(), Some(37), "{output:?}");
        let report = fixture.report();
        let argv = report["argv"].as_array().unwrap();
        assert_eq!(argv.len(), 7);
        assert_eq!(argv[0], "--worker-exec-tls");
        assert_eq!(argv[1], "--resume");
        assert_eq!(argv[2], "[2001:db8::1]:7443");
        assert_eq!(argv[3], "worker α");
        assert_eq!(argv[4], PIN);
        assert!(argv[5].as_str().unwrap().starts_with("/proc/self/fd/"));
        assert_eq!(argv[6], destination.to_str().unwrap());
        assert_eq!(report["request"], json!(fixture.request_bytes));
        assert_eq!(report["stdin"], json!(b"original stdin\0payload".to_vec()));
        assert_eq!(report["pid"], pid);
        assert_eq!(report["state"], fixture.state.to_str().unwrap());
        assert_eq!(
            report["tls"],
            json!([
                fixture.root.join("coordinator ca.pem"),
                fixture.root.join("coordinator cert.pem"),
                fixture.root.join("coordinator key.pem")
            ])
        );
        assert_eq!(report["unrelated"], "preserved verbatim");
        assert_eq!(report["sealed"], true);
        assert_eq!(
            fs::read(&fixture.request).unwrap(),
            b"changed-after-handoff"
        );
        assert!(
            !destination.exists(),
            "the driver does not create a delivery"
        );
    }
}

#[test]
fn resume_prefix_selection_and_acknowledgment_reach_the_same_native_operator() {
    for mode in [
        "default-prefix",
        "explicit-prefix",
        "no-prefix",
        "acknowledge",
    ] {
        let fixture = Fixture::live();
        let delivery = fixture.intent.join("delivery");
        private_directory(&delivery);
        new_file(
            &delivery.join("delivery.json"),
            b"retained native transport metadata",
            0o600,
        );
        new_file(&delivery.join("partial-output"), b"untrusted bytes", 0o600);
        let destination = fixture.root.join("later delivery");
        let (mut command, expected) = match mode {
            "acknowledge" => (
                fixture.operation("--acknowledge", &delivery),
                "--acknowledge",
            ),
            "no-prefix" => {
                let mut command = fixture.operation("--resume-to", &destination);
                command.arg("--no-prefix");
                (command, "--resume")
            }
            "explicit-prefix" => {
                let later = fixture.root.join("another partial delivery");
                private_directory(&later);
                let mut command = fixture.operation("--resume-to", &destination);
                command.arg("--prefix-from").arg(later);
                (command, "--resume-from")
            }
            _ => (
                fixture.operation("--resume-to", &destination),
                "--resume-from",
            ),
        };
        let output = command.output().unwrap();
        assert_eq!(output.status.code(), Some(37), "{mode}: {output:?}");
        let report = fixture.report();
        assert_eq!(report["argv"][1], expected);
        if mode == "default-prefix" {
            assert_eq!(report["argv"][2], delivery.to_str().unwrap());
        } else if mode == "explicit-prefix" {
            assert_eq!(
                report["argv"][2],
                fixture
                    .root
                    .join("another partial delivery")
                    .to_str()
                    .unwrap()
            );
        }
        assert_eq!(
            fs::read(delivery.join("partial-output")).unwrap(),
            b"untrusted bytes"
        );
    }
}

#[test]
fn legacy_canonical_state_is_explicit_and_recorded_state_cannot_be_replaced() {
    let fixture = Fixture::canonical(true);
    let refused = fixture.refused(fixture.command().output().unwrap());
    assert!(refused.contains("ORIGINAL admission state"));
    let output = fixture
        .command()
        .arg("--canonical-state-dir")
        .arg(&fixture.state)
        .output()
        .unwrap();
    assert!(output.status.success(), "{output:?}");
    let destination = fixture.root.join("recovered legacy result");
    let output = fixture
        .operation("--resume-to", &destination)
        .arg("--canonical-state-dir")
        .arg(&fixture.state)
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(37), "{output:?}");
    assert_eq!(fixture.report()["state"], fixture.state.to_str().unwrap());

    for fixture in [Fixture::canonical(false), Fixture::live()] {
        let replacement = fixture.root.join("replacement state");
        private_directory(&replacement);
        fixture.refused(
            fixture
                .command()
                .arg("--canonical-state-dir")
                .arg(replacement)
                .output()
                .unwrap(),
        );
    }
}

#[test]
fn corrupted_authority_identity_and_request_records_never_start_transport() {
    let live_changes: [fn(&mut Value); 12] = [
        |record| record["reexecute"] = true.into(),
        |record| record["publication_authorized"] = true.into(),
        |record| record["request_id"] = 0.into(),
        |record| record["request_id"] = json!(1.0),
        |record| record["request_sha256"] = "a".repeat(64).into(),
        |record| record["request_file"] = "other.json".into(),
        |record| record["partial_delivery"] = "other".into(),
        |record| record["remote_configuration"]["remote_protocol"] = json!(1.0),
        |record| record["remote_configuration"]["worker_spki_sha256"] = "0".repeat(64).into(),
        |record| record["remote_configuration"]["worker_id"] = "worker\nname".into(),
        |record| record["remote_configuration"]["listen"] = "hostname:7443".into(),
        |record| record["remote_configuration"]["listen"] = "[fe80::1%eth0]:7443".into(),
    ];
    for change in live_changes {
        let fixture = Fixture::live();
        rewrite_json(&fixture.record, change);
        fixture.refused(
            fixture
                .operation("--resume-to", &fixture.root.join("new"))
                .output()
                .unwrap(),
        );
    }
    let canonical_changes: [fn(&mut Value); 6] = [
        |record| record["automatic_retry"] = true.into(),
        |record| record["prepared_build_argv"][1] = "--worker-exec-tls".into(),
        |record| record["prepared_build_argv"][6] = "/elsewhere/bundle".into(),
        |record| record["request_id"] = 17.into(),
        |record| record["recovery"]["worker_spki_sha256"] = "a".repeat(64).into(),
        |record| record["recovery"]["unexpected_authority"] = true.into(),
    ];
    for change in canonical_changes {
        let fixture = Fixture::canonical(false);
        rewrite_json(&fixture.record, change);
        fixture.refused(fixture.command().output().unwrap());
    }
    for request in [
        br#"{"kind":"canonical-exec","request_id":18446744073709551616}"#.as_slice(),
        br#"{"kind":"canonical-exec","request_id":1,"nested":{"duplicate":1,"duplicate":2}}"#,
        br#"{"kind":"canonical-exec","request_id":NaN}"#,
    ] {
        let fixture = Fixture::live();
        fs::write(&fixture.request, request).unwrap();
        fixture.refresh_request_digest();
        fixture.refused(fixture.command().output().unwrap());
    }
    for field in [
        "program",
        "source_manifest",
        "dependency_context",
        "artifacts",
    ] {
        let fixture = Fixture::canonical(false);
        rewrite_json(&fixture.request, |request| {
            request[field] = json!("unsupported")
        });
        fixture.refused(fixture.command().output().unwrap());
    }
}

#[test]
fn records_and_directories_require_private_ordinary_nofollow_ownership() {
    for kind in [
        "record-mode",
        "request-hardlink",
        "record-symlink",
        "request-fifo",
        "root-mode",
        "ancestor-symlink",
        "ambiguous",
        "oversize",
    ] {
        let fixture = Fixture::live();
        let mut command = fixture.command();
        match kind {
            "record-mode" => {
                fs::set_permissions(&fixture.record, fs::Permissions::from_mode(0o644)).unwrap()
            }
            "request-hardlink" => {
                fs::hard_link(&fixture.request, fixture.root.join("another-request-link")).unwrap()
            }
            "record-symlink" => {
                let retained = fixture.root.join("retained-record");
                fs::rename(&fixture.record, &retained).unwrap();
                symlink(retained, &fixture.record).unwrap();
            }
            "request-fifo" => {
                fs::rename(&fixture.request, fixture.root.join("retained-request")).unwrap();
                rustix::fs::mkfifoat(rustix::fs::CWD, &fixture.request, Mode::RUSR | Mode::WUSR)
                    .unwrap();
            }
            "root-mode" => {
                fs::set_permissions(&fixture.intent, fs::Permissions::from_mode(0o750)).unwrap()
            }
            "ancestor-symlink" => {
                let alias = fixture.root.join("state-alias");
                symlink(&fixture.state, &alias).unwrap();
                command = Command::new(BINARY);
                command.arg(alias.join(fixture.intent.file_name().unwrap()));
            }
            "ambiguous" => new_file(&fixture.intent.join("operation.json"), b"{}", 0o600),
            "oversize" => OpenOptions::new()
                .write(true)
                .open(&fixture.request)
                .unwrap()
                .set_len(1024 * 1024)
                .unwrap(),
            _ => unreachable!(),
        }
        fixture.refused(command.output().unwrap());
    }
}

#[test]
fn destination_prefix_and_tls_refusals_preserve_all_retained_data() {
    for kind in [
        "existing",
        "dangling",
        "nested",
        "ancestor",
        "prefix-missing",
        "prefix-public",
        "prefix-overlap",
        "missing-tls",
        "relative-tls",
        "ack-missing",
        "ack-hardlink",
    ] {
        let fixture = Fixture::live();
        let mut destination = fixture.root.join("new");
        let mut extra: Vec<OsString> = Vec::new();
        match kind {
            "existing" => private_directory(&destination),
            "dangling" => symlink(fixture.root.join("absent-target"), &destination).unwrap(),
            "nested" => destination = fixture.intent.join("child"),
            "ancestor" => destination = fixture.state.clone(),
            "prefix-missing" => extra.extend([
                "--prefix-from".into(),
                fixture.root.join("absent-prefix").into_os_string(),
            ]),
            "prefix-public" => {
                let prefix = fixture.intent.join("delivery");
                private_directory(&prefix);
                fs::set_permissions(prefix, fs::Permissions::from_mode(0o755)).unwrap();
            }
            "prefix-overlap" => {
                let prefix = fixture.root.join("prefix");
                private_directory(&prefix);
                destination = prefix.join("new");
                extra.extend(["--prefix-from".into(), prefix.into_os_string()]);
            }
            "ack-missing" => private_directory(&destination),
            "ack-hardlink" => {
                private_directory(&destination);
                new_file(&destination.join("delivery.json"), b"{}", 0o600);
                fs::hard_link(
                    destination.join("delivery.json"),
                    fixture.root.join("linked-delivery-record"),
                )
                .unwrap();
            }
            _ => {}
        }
        let option = if kind.starts_with("ack-") {
            "--acknowledge"
        } else {
            "--resume-to"
        };
        let mut command = fixture.operation(option, &destination);
        command.args(extra);
        if kind == "missing-tls" {
            command.env_remove("RABS_COORD_TLS_KEY");
        } else if kind == "relative-tls" {
            command.env("RABS_COORD_TLS_KEY", "relative-key.pem");
        }
        fixture.refused(command.output().unwrap());
        assert_eq!(
            fs::read(&fixture.request).unwrap(),
            fixture.request_bytes,
            "{kind}"
        );
    }
}

#[test]
fn explicit_daemon_selection_never_falls_through_or_recurses() {
    for selected in [
        OsString::new(),
        OsString::from("/does/not/exist"),
        OsString::from(BINARY),
    ] {
        let fixture = Fixture::live();
        fixture.refused(
            fixture
                .command()
                .arg("--resume-to")
                .arg(fixture.root.join("new"))
                .arg("--rabsd")
                .arg(selected)
                .env("CARGO_RABS_DAEMON", &fixture.daemon)
                .output()
                .unwrap(),
        );
    }
    for selected in ["", "/does/not/exist"] {
        let fixture = Fixture::live();
        let path = fixture.root.join("bin");
        private_directory(&path);
        symlink(&fixture.daemon, path.join("rabsd")).unwrap();
        fixture.refused(
            fixture
                .command()
                .arg("--resume-to")
                .arg(fixture.root.join("new"))
                .env("CARGO_RABS_DAEMON", selected)
                .env("PATH", path)
                .output()
                .unwrap(),
        );
    }
    let fixture = Fixture::live();
    let output = fixture
        .command()
        .arg("--resume-to")
        .arg(fixture.root.join("new"))
        .env("CARGO_RABS_DAEMON", &fixture.daemon)
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(37), "{output:?}");
}

#[test]
fn installed_sibling_generation_survives_activation_during_native_recovery() {
    let first = Fixture::live();
    let second = Fixture::live();
    let versions = first.root.join("versions");
    private_directory(&versions);
    for generation in ["alpha", "beta"] {
        let directory = versions.join(generation);
        private_directory(&directory);
        fs::copy(BINARY, directory.join("rabs-recover")).unwrap();
        let adapter = format!(
            "#!/bin/sh\nRABS_RECOVER_TEST_GENERATION={generation}\nexport RABS_RECOVER_TEST_GENERATION\nexec {} --exact native_daemon_fixture --ignored --nocapture -- \"$@\"\n",
            quote(std::env::current_exe().unwrap().as_os_str())
        );
        new_file(&directory.join("rabsd"), adapter.as_bytes(), 0o700);
    }
    let current = first.root.join("current");
    let next = first.root.join("next-activation");
    symlink(versions.join("alpha"), &current).unwrap();
    symlink(versions.join("beta"), &next).unwrap();
    let public = first.root.join("public");
    private_directory(&public);
    symlink(current.join("rabs-recover"), public.join("rabs-recover")).unwrap();
    symlink(current.join("rabsd"), public.join("rabsd")).unwrap();
    let driver = public.join("rabs-recover");
    let ready = first.root.join("old-native-transport-ready");
    let mut child = first
        .command_using(&driver)
        .arg("--resume-to")
        .arg(first.root.join("old delivery"))
        .env("PATH", &public)
        .env("RABS_RECOVER_TEST_READY", &ready)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let old_pid = child.id();
    let mut stdin = child.stdin.take().unwrap();
    let deadline = Instant::now() + Duration::from_secs(5);
    while !ready.exists() {
        assert!(
            child.try_wait().unwrap().is_none(),
            "old recovery exited before native transport handoff"
        );
        assert!(Instant::now() < deadline, "native transport did not start");
        std::thread::sleep(Duration::from_millis(5));
    }
    // Exchange activates beta atomically while retaining both symlink objects
    // and both complete generations. The alpha transport is still in flight.
    rustix::fs::renameat_with(
        rustix::fs::CWD,
        &next,
        rustix::fs::CWD,
        &current,
        rustix::fs::RenameFlags::EXCHANGE,
    )
    .unwrap();
    assert_eq!(fs::read_link(&current).unwrap(), versions.join("beta"));
    assert_eq!(fs::read_link(&next).unwrap(), versions.join("alpha"));
    stdin.write_all(b"finish original recovery").unwrap();
    drop(stdin);
    let original = child.wait_with_output().unwrap();
    assert_eq!(original.status.code(), Some(37), "{original:?}");
    assert_eq!(first.report()["generation"], "alpha");
    assert_eq!(first.report()["pid"], old_pid);
    assert_eq!(first.report()["state"], first.state.to_str().unwrap());
    assert_eq!(first.report()["request"], json!(first.request_bytes));
    let current = second
        .command_using(&driver)
        .arg("--resume-to")
        .arg(second.root.join("new delivery"))
        .env("PATH", public)
        .output()
        .unwrap();
    assert_eq!(current.status.code(), Some(37), "{current:?}");
    assert_eq!(second.report()["generation"], "beta");
    assert_eq!(second.report()["state"], second.state.to_str().unwrap());
    assert_eq!(second.report()["request"], json!(second.request_bytes));
    for generation in ["alpha", "beta"] {
        assert!(versions.join(generation).join("rabs-recover").is_file());
        assert!(versions.join(generation).join("rabsd").is_file());
    }
}

#[test]
fn native_exec_preserves_transport_signal_status() {
    let fixture = Fixture::live();
    let output = fixture
        .operation("--resume-to", &fixture.root.join("new"))
        .env("RABS_RECOVER_TEST_SIGNAL", "1")
        .output()
        .unwrap();
    assert_eq!(output.status.signal(), Some(15), "{output:?}");
    assert!(fixture.report.exists());
}

#[test]
fn command_help_version_and_build_identity_are_native_and_standalone() {
    for argument in ["--help", "-h", "--version"] {
        let output = Command::new(BINARY).arg(argument).output().unwrap();
        assert!(output.status.success(), "{output:?}");
        assert!(String::from_utf8_lossy(&output.stdout).contains("rabs-recover"));
    }
    let output = Command::new(BINARY)
        .arg("--rabs-build-info")
        .output()
        .unwrap();
    assert!(output.status.success(), "{output:?}");
    let value: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(value["tool"], "rabs-recover");
    let fixture = Fixture::live();
    fixture.refused(fixture.command().arg("--rabs-build-info").output().unwrap());
}

const JOB_ID: &str = "0123456789abcdef0123456789abcdef";

struct JobFixture {
    root: PathBuf,
    operation: PathBuf,
    record: PathBuf,
    socket: PathBuf,
    daemon: PathBuf,
    report: PathBuf,
    _listener: Option<std::os::unix::net::UnixListener>,
}

impl JobFixture {
    fn new(pooled: bool, live_stderr: Option<bool>, online: bool) -> Self {
        let root = tempfile::Builder::new()
            .prefix("rjob-")
            .tempdir()
            .unwrap()
            .keep();
        let operation = root.join(format!("cargo-{JOB_ID}"));
        private_directory(&operation);
        let socket = root.join("owner/socket");
        let listener = if online {
            private_directory(socket.parent().unwrap());
            let listener = std::os::unix::net::UnixListener::bind(&socket).unwrap();
            fs::set_permissions(&socket, fs::Permissions::from_mode(0o600)).unwrap();
            Some(listener)
        } else {
            None
        };
        let saved_driver = "/never-run-the-recorded-driver";
        let submit = if pooled {
            json!([
                saved_driver,
                "--job-submit-pool",
                JOB_ID,
                operation.join("pool.json"),
                operation.join("bundle"),
                operation.join("delivery"),
                operation.join("outputs")
            ])
        } else {
            json!([
                saved_driver,
                "--job-submit-allocated",
                JOB_ID,
                "[2001:db8::1]:7443",
                "worker-a",
                PIN,
                operation.join("bundle"),
                operation.join("delivery"),
                operation.join("outputs")
            ])
        };
        let wait = if live_stderr == Some(true) {
            json!([saved_driver, "--job-wait", "--live-stderr", JOB_ID])
        } else {
            json!([saved_driver, "--job-wait", JOB_ID])
        };
        let mut value = json!({
            "version":"canonical-cargo-v1", "request_id":"allocate",
            "operation_directory":operation, "automatic_retry":false,
            "publication_authorized":false, "job_id":JOB_ID, "daemon_socket":socket,
            "job_submit_argv":submit, "job_wait_argv":wait,
            "job_status_argv":[saved_driver, "--job-status", JOB_ID],
            "job_cancel_argv":[saved_driver, "--job-cancel", JOB_ID],
        });
        if pooled {
            value["worker_pool"] = json!([
                {"address":"127.0.0.1:7443", "worker":"worker-a", "worker_spki_sha256":PIN},
                {"address":"[2001:db8::2]:7444", "worker":"worker-b", "worker_spki_sha256":"ab".repeat(32)},
            ]);
        }
        if let Some(live_stderr) = live_stderr {
            value["live_stderr"] = live_stderr.into();
        }
        let record = operation.join("operation.json");
        new_file(&record, &serde_json::to_vec(&value).unwrap(), 0o600);
        let daemon = root.join("native job 'fixture'");
        new_file(
            &daemon,
            format!(
                "#!/bin/sh\nexec {} --exact native_job_daemon_fixture --ignored --nocapture -- \"$@\"\n",
                quote(std::env::current_exe().unwrap().as_os_str()),
            ).as_bytes(),
            0o700,
        );
        let report = root.join("job-report.json");
        Self {
            root,
            operation,
            record,
            socket,
            daemon,
            report,
            _listener: listener,
        }
    }

    fn command(&self) -> Command {
        self.command_using(BINARY)
    }

    fn command_using(&self, binary: &str) -> Command {
        let mut command = Command::new(binary);
        if binary == SUBCOMMAND {
            command.args(["rabs", "--rabs-recover"]);
        }
        command
            .arg(&self.operation)
            .current_dir(&self.root)
            .env_clear()
            .env("PATH", "/usr/bin:/bin")
            .env("CARGO_RABS_DAEMON", &self.daemon)
            .env("CARGO_RABS_CANONICAL_ACTIVE", "0")
            .env("RABS_SOCKET_PATH", "/wrong/current/socket")
            .env("RABS_STATE_DIR", self.root.join("unrelated current state"))
            .env("RABS_RECOVER_JOB_REPORT", &self.report)
            .env("RABS_RECOVER_JOB_UNRELATED", "preserved verbatim")
            .stdin(Stdio::null());
        command
    }

    fn report(&self) -> Value {
        serde_json::from_slice(&fs::read(&self.report).unwrap()).unwrap()
    }

    fn unchanged(&self, before: &[u8]) {
        assert_eq!(fs::read(&self.record).unwrap(), before);
        for missing in ["bundle", "outputs", "pool.json", "spec.json"] {
            assert!(!self.operation.join(missing).exists(), "{missing}");
        }
    }

    fn refused(&self, output: Output) {
        assert_eq!(output.status.code(), Some(2), "{output:?}");
        assert!(output.stdout.is_empty(), "{output:?}");
        let stderr = String::from_utf8(output.stderr).unwrap();
        assert!(stderr.contains("rabs-recover: refused:"), "{stderr}");
        assert!(stderr.contains("no execution retry"), "{stderr}");
        assert!(!stderr.contains("must-not-be-printed"), "{stderr}");
        assert!(
            !self.report.exists(),
            "the daemon must not start on refusal"
        );
    }
}

#[test]
#[ignore = "Rust daemon-job fixture, invoked only by native recovery tests"]
fn native_job_daemon_fixture() {
    let arguments: Vec<String> = std::env::args_os()
        .skip_while(|argument| argument != "--")
        .skip(1)
        .map(|argument| argument.into_string().unwrap())
        .collect();
    assert!(matches!(
        arguments[0].as_str(),
        "--job-wait"
            | "--job-status"
            | "--job-cancel"
            | "--job-resume"
            | "--job-recover-local"
            | "--job-acknowledge"
    ));
    let mut input = Vec::new();
    std::io::stdin().read_to_end(&mut input).unwrap();
    let mut token = None;
    if std::env::var_os("RABS_RECOVER_JOB_JOBSERVER").is_some() {
        let mut reader = OpenOptions::new()
            .read(true)
            .open("/proc/self/fd/7")
            .unwrap();
        let mut writer = OpenOptions::new()
            .write(true)
            .open("/proc/self/fd/8")
            .unwrap();
        let mut byte = [0];
        reader.read_exact(&mut byte).unwrap();
        writer.write_all(&byte).unwrap();
        token = Some(byte[0]);
    }
    let value = json!({
        "argv":arguments, "pid":std::process::id(), "stdin":input,
        "cwd":std::env::current_dir().unwrap(),
        "socket":std::env::var("RABS_SOCKET_PATH").unwrap(),
        "state":std::env::var("RABS_STATE_DIR").unwrap(),
        "active":std::env::var("CARGO_RABS_CANONICAL_ACTIVE").unwrap(),
        "tls":[std::env::var("RABS_COORD_TLS_CA").ok(), std::env::var("RABS_COORD_TLS_CERT").ok(),
            std::env::var("RABS_COORD_TLS_KEY").ok()],
        "unrelated":std::env::var("RABS_RECOVER_JOB_UNRELATED").unwrap(),
        "jobserver":std::env::var("CARGO_MAKEFLAGS").ok(), "token":token,
    });
    new_file(
        Path::new(&std::env::var_os("RABS_RECOVER_JOB_REPORT").unwrap()),
        &serde_json::to_vec(&value).unwrap(),
        0o600,
    );
    std::io::stdout()
        .lock()
        .write_all(b"\0job stdout\xff\n")
        .unwrap();
    std::io::stderr()
        .lock()
        .write_all(b"\0job stderr\xfe\n")
        .unwrap();
    if std::env::var_os("RABS_RECOVER_JOB_SIGNAL").is_some() {
        rustix::process::kill_process(rustix::process::getpid(), rustix::process::Signal::TERM)
            .unwrap();
        panic!("daemon signal termination must propagate");
    }
    std::process::exit(
        std::env::var("RABS_RECOVER_JOB_STATUS")
            .map(|value| value.parse().unwrap())
            .unwrap_or(37),
    );
}

#[test]
#[ignore = "Rust submission fixture, invoked only by the native frontend/recovery regression"]
fn native_worker_submission_fixture() {
    let arguments: Vec<OsString> = std::env::args_os()
        .skip_while(|argument| argument != "--")
        .skip(1)
        .collect();
    assert!(matches!(
        arguments[0].to_str(),
        Some("--worker-build-tls" | "--job-build")
    ));
    let preparation = arguments
        .iter()
        .position(|argument| argument == "--prepare-from")
        .expect("one native preparation handoff");
    let specification = Path::new(&arguments[preparation + 2]);
    let operation = specification.parent().unwrap();
    let value: Value = serde_json::from_slice(&fs::read(specification).unwrap()).unwrap();
    assert_eq!(value["kind"], "canonical-exec");
    assert_eq!(value["request_id"], "allocate");
    if value.get("captured_stdin").is_some() {
        assert_eq!(value["artifacts"]["cargo"], "cargo-run-json-v1");
        assert_eq!(
            value["captured_stdin"],
            json!({
                "version":"source-file-stdin-v1", "path":"input.bin",
            })
        );
    } else {
        assert_eq!(value["artifacts"]["cargo"], "cargo-json-v1");
    }
    assert!(!operation.join("bundle").exists());
    let arguments: Vec<_> = arguments
        .iter()
        .map(|argument| argument.to_str().unwrap())
        .collect();
    let report = json!({"operation":operation, "argv":arguments});
    new_file(
        Path::new(&std::env::var_os("RABS_SUBMISSION_RECOVERY_REPORT").unwrap()),
        &serde_json::to_vec(&report).unwrap(),
        0o600,
    );
    // This is a handoff fixture, not an execution or delivery receipt. The
    // direct recovery case below separately supplies a prepared request.
    std::process::exit(37);
}

#[test]
fn native_worker_submission_records_feed_native_recovery_without_resubmission() {
    for (placement, captured_input) in [
        ("direct", false),
        ("daemon", false),
        ("pool", false),
        ("direct", true),
        ("daemon", true),
        ("pool", true),
    ] {
        worker_submission_recovers(placement, captured_input);
    }
}

#[test]
fn native_worker_captured_stdin_direct_submission_recovers_without_resubmission() {
    // The direct route requires no Unix listener, allowing real frontend and
    // recovery processes to run on hosts that prohibit socket creation.
    worker_submission_recovers("direct", true);
}

fn worker_submission_recovers(placement: &str, captured_input: bool) {
    let root = tempfile::Builder::new()
        .prefix("rwrec-")
        .tempdir()
        .unwrap()
        .keep();
    let source = root.join("source");
    let toolchain = root.join("sdk");
    let operations = root.join("operations");
    let state = root.join("original state");
    for path in [&source, &toolchain, &operations, &state] {
        private_directory(path);
    }
    private_directory(&toolchain.join("bin"));
    for name in ["cargo", "rustc"] {
        new_file(
            &toolchain.join("bin").join(name),
            b"unused compiler fixture",
            0o700,
        );
    }
    new_file(
        &source.join("Cargo.toml"),
        b"[package]\nname='fixture'\nversion='0.1.0'\n",
        0o600,
    );
    if captured_input {
        new_file(&source.join("input.bin"), b"\0captured\xff\n", 0o600);
    }
    let submitter = root.join("native submission fixture");
    new_file(
            &submitter,
            format!(
                "#!/bin/sh\nexec {} --exact native_worker_submission_fixture --ignored --nocapture -- \"$@\"\n",
                quote(std::env::current_exe().unwrap().as_os_str()),
            )
            .as_bytes(),
            0o700,
        );
    let socket = root.join("socket");
    let _listener = if placement != "direct" {
        let listener = std::os::unix::net::UnixListener::bind(&socket).unwrap();
        fs::set_permissions(&socket, fs::Permissions::from_mode(0o600)).unwrap();
        Some(listener)
    } else {
        None
    };
    let mut profile = json!({
        "version":"canonical-cargo-v1", "source_root":source,
        "toolchain_root":toolchain, "operation_root":operations,
        "env":{"PROJECT_VALUE":"must-not-be-printed"},
    });
    if placement == "pool" {
        profile["workers"] = json!([
            {"listen":"127.0.0.1:7443", "worker":"worker-a", "worker_spki_sha256":PIN},
            {"listen":"[2001:db8::2]:7444", "worker":"worker-b", "worker_spki_sha256":"ab".repeat(32)},
        ]);
    } else {
        profile["listen"] = "127.0.0.1:7443".into();
        profile["worker"] = "worker-a".into();
        profile["worker_spki_sha256"] = PIN.into();
    }
    if placement != "direct" {
        profile["daemon_socket"] = json!(socket);
        profile["live_stderr"] = true.into();
    }
    let profile_path = root.join("profile.json");
    new_file(&profile_path, &serde_json::to_vec(&profile).unwrap(), 0o600);
    let submission_report = root.join("submission-report.json");
    let output = Command::new(env!("CARGO_BIN_EXE_rabs-cargo"))
        .arg("--worker")
        .arg(&profile_path)
        .arg("--rabsd")
        .arg(&submitter)
        .args(if captured_input {
            vec!["--stdin-file", "input.bin", "--", "run"]
        } else {
            vec!["--", "build", "--workspace"]
        })
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env("RABS_SUBMISSION_RECOVERY_REPORT", &submission_report)
        .stdin(Stdio::null())
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(37), "{placement}: {output:?}");
    let submission: Value = serde_json::from_slice(&fs::read(&submission_report).unwrap()).unwrap();
    let operation = PathBuf::from(submission["operation"].as_str().unwrap());
    let specification: Value =
        serde_json::from_slice(&fs::read(operation.join("spec.json")).unwrap()).unwrap();
    if captured_input {
        assert_eq!(
            specification["captured_stdin"],
            json!({
                "version":"source-file-stdin-v1", "path":"input.bin",
            })
        );
    } else {
        assert!(specification.get("captured_stdin").is_none());
    }
    let record = operation.join("operation.json");
    let before = fs::read(&record).unwrap();
    let metadata: Value = serde_json::from_slice(&before).unwrap();
    assert_eq!(metadata["automatic_retry"], false);
    assert_eq!(metadata["publication_authorized"], false);

    // Recovery must use only retained ownership. Moving the original
    // inputs keeps them intact while proving neither frontend recaptures.
    fs::rename(&source, root.join("retained source")).unwrap();
    fs::rename(&toolchain, root.join("retained sdk")).unwrap();
    fs::rename(&profile_path, root.join("retained profile.json")).unwrap();

    let mut inspect = Command::new(BINARY);
    inspect
        .arg(&operation)
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env("CARGO_RABS_DAEMON", "/must/not/execute")
        .stdin(Stdio::null());
    if placement == "direct" {
        // Native preparation replaces allocation intent with an exact
        // request before execution. Model that boundary explicitly; this
        // test does not claim to prepare a real toolchain or use TLS.
        let mut request = json!({
            "kind":"canonical-exec", "request_id":u64::MAX,
            "program":"/__rabs/toolchain/bin/cargo", "source_manifest":{},
            "artifacts":{"unit":"cargo", "tree":"tree-files-v1", "cargo":"cargo-json-v1"},
        });
        if captured_input {
            request["captured_stdin"] = specification["captured_stdin"].clone();
            request["artifacts"]["cargo"] = "cargo-run-json-v1".into();
        }
        private_directory(&operation.join("bundle"));
        new_file(
            &operation.join("bundle/request.json"),
            &serde_json::to_vec(&request).unwrap(),
            0o600,
        );
        inspect.arg("--canonical-state-dir").arg(&state);
    }
    let inspected = inspect.output().unwrap();
    assert!(inspected.status.success(), "{placement}: {inspected:?}");
    let result: Value = serde_json::from_slice(&inspected.stdout).unwrap();
    assert_eq!(result["publication_authorized"], false);
    assert_eq!(result["reexecute"], false);
    assert!(!String::from_utf8_lossy(&inspected.stdout).contains("must-not-be-printed"));
    if placement == "direct" {
        assert_eq!(result["kind"], "rabs-remote-recovery-intent");
        assert_eq!(result["request_id"], u64::MAX);
        assert_eq!(result["worker_id"], "worker-a");
        assert_eq!(result["transport_state_dir"], json!(state));
    } else {
        assert_eq!(result["kind"], "rabs-daemon-job-intent");
        assert_eq!(result["job_id"], metadata["job_id"]);
        assert_eq!(result["daemon_socket"], json!(socket));
        let control = root.join("native recovery fixture");
        new_file(
                &control,
                format!(
                    "#!/bin/sh\nexec {} --exact native_job_daemon_fixture --ignored --nocapture -- \"$@\"\n",
                    quote(std::env::current_exe().unwrap().as_os_str()),
                )
                .as_bytes(),
                0o700,
            );
        let report = root.join("recovery-report.json");
        let waited = Command::new(BINARY)
            .arg(&operation)
            .args(["--wait", "--rabsd"])
            .arg(&control)
            .env_clear()
            .env("PATH", "/usr/bin:/bin")
            .env("RABS_STATE_DIR", root.join("unrelated current state"))
            .env("CARGO_RABS_CANONICAL_ACTIVE", "0")
            .env("RABS_RECOVER_JOB_REPORT", &report)
            .env("RABS_RECOVER_JOB_UNRELATED", "preserved verbatim")
            .stdin(Stdio::null())
            .output()
            .unwrap();
        assert_eq!(waited.status.code(), Some(37), "{placement}: {waited:?}");
        let handoff: Value = serde_json::from_slice(&fs::read(&report).unwrap()).unwrap();
        assert_eq!(
            handoff["argv"],
            json!(["--job-wait", "--live-stderr", metadata["job_id"]])
        );
        assert_eq!(handoff["socket"], json!(socket));
        assert_eq!(handoff["tls"], json!([null, null, null]));
        assert!(!operation.join("bundle").exists());
    }
    assert_eq!(fs::read(&record).unwrap(), before);
    assert_eq!(fs::read_dir(&operations).unwrap().count(), 1);
    assert!(!operation.join("outputs").exists());
    assert!(!operation.join("delivery").exists());
}

#[test]
fn daemon_job_inspection_needs_no_socket_bundle_toolchain_or_driver() {
    for pooled in [false, true] {
        for live in [None, Some(false), Some(true)] {
            let fixture = JobFixture::new(pooled, live, false);
            let before = fs::read(&fixture.record).unwrap();
            let output = fixture
                .command()
                .env("CARGO_RABS_DAEMON", "/missing/driver")
                .output()
                .unwrap();
            assert!(output.status.success(), "{output:?}");
            assert!(output.stderr.is_empty());
            let value: Value = serde_json::from_slice(&output.stdout).unwrap();
            assert_eq!(value["kind"], "rabs-daemon-job-intent");
            assert_eq!(value["job_id"], JOB_ID);
            assert_eq!(value["request_id"], "allocate");
            assert_eq!(value["daemon_socket"], json!(fixture.socket));
            assert_eq!(value["live_stderr"], live.unwrap_or(false));
            for key in [
                "job_status_queried",
                "outputs_verified",
                "publication_authorized",
                "reexecute",
            ] {
                assert_eq!(value[key], false, "{key}");
            }
            assert!(!fixture.socket.parent().unwrap().exists());
            assert!(!fixture.report.exists());
            fixture.unchanged(&before);
        }
    }
}

#[test]
fn daemon_job_controls_use_the_same_owner_without_source_or_client_tls() {
    for pooled in [false, true] {
        for live in [None, Some(false), Some(true)] {
            for (option, action) in [
                ("--wait", "--job-wait"),
                ("--status", "--job-status"),
                ("--cancel", "--job-cancel"),
            ] {
                let fixture = JobFixture::new(pooled, live, true);
                let before = fs::read(&fixture.record).unwrap();
                let output = fixture.command().arg(option).output().unwrap();
                assert_eq!(output.status.code(), Some(37), "{option}: {output:?}");
                let report = fixture.report();
                let expected = if option == "--wait" && live == Some(true) {
                    json!([action, "--live-stderr", JOB_ID])
                } else {
                    json!([action, JOB_ID])
                };
                assert_eq!(report["argv"], expected);
                assert_eq!(report["socket"], json!(fixture.socket));
                assert_eq!(
                    report["state"],
                    json!(fixture.root.join("unrelated current state"))
                );
                assert_eq!(report["active"], "1");
                assert_eq!(report["tls"], json!([null, null, null]));
                assert_eq!(report["unrelated"], "preserved verbatim");
                assert_eq!(report["cwd"], json!(fixture.root));
                fixture.unchanged(&before);
            }
        }
    }
}

#[test]
fn cargo_subcommand_recovery_defaults_to_wait_and_preserves_explicit_job_controls() {
    for (option, action) in [
        (None, "--job-wait"),
        (Some("--status"), "--job-status"),
        (Some("--cancel"), "--job-cancel"),
    ] {
        let fixture = JobFixture::new(true, Some(true), true);
        let before = fs::read(&fixture.record).unwrap();
        let mut command = fixture.command_using(SUBCOMMAND);
        if let Some(option) = option {
            command.arg(option);
        }
        let output = command.output().unwrap();
        assert_eq!(output.status.code(), Some(37), "{output:?}");
        let expected = if option.is_none() {
            json!([action, "--live-stderr", JOB_ID])
        } else {
            json!([action, JOB_ID])
        };
        let report = fixture.report();
        assert_eq!(report["argv"], expected);
        assert_eq!(report["socket"], json!(fixture.socket));
        assert_eq!(report["tls"], json!([null, null, null]));
        fixture.unchanged(&before);
    }
}

#[test]
fn daemon_job_result_controls_preserve_retained_state_and_never_submit() {
    for pooled in [false, true] {
        for case in ["resume", "prefix", "fresh", "delivery", "acknowledge"] {
            let fixture = JobFixture::new(pooled, Some(true), true);
            let before = fs::read(&fixture.record).unwrap();
            let old = fixture.operation.join("delivery");
            private_directory(&old);
            new_file(&old.join("retained"), b"unverified retained bytes", 0o600);
            let destination = fixture.root.join("new delivery 'α'");
            let mut command = fixture.command();
            let expected = match case {
                "delivery" | "acknowledge" => {
                    let (option, action) = if case == "delivery" {
                        ("--delivery", "--job-recover-local")
                    } else {
                        ("--acknowledge", "--job-acknowledge")
                    };
                    command.arg(option).arg(&old);
                    json!([action, JOB_ID, old])
                }
                _ => {
                    command.arg("--resume-to").arg(&destination);
                    if case == "prefix" {
                        command.arg("--prefix-from").arg(&old);
                        json!(["--job-resume", JOB_ID, destination, old])
                    } else {
                        if case == "fresh" {
                            command.arg("--no-prefix");
                        }
                        json!(["--job-resume", JOB_ID, destination])
                    }
                }
            };
            let output = command.output().unwrap();
            assert_eq!(output.status.code(), Some(37), "{case}: {output:?}");
            assert_eq!(fixture.report()["argv"], expected);
            assert!(
                !destination.exists(),
                "the frontend must not create result directories"
            );
            assert_eq!(
                fs::read(old.join("retained")).unwrap(),
                b"unverified retained bytes"
            );
            fixture.unchanged(&before);
        }
    }
}

#[test]
fn daemon_job_handoff_preserves_process_identity_binary_streams_and_jobserver_tokens() {
    let fixture = JobFixture::new(false, Some(true), true);
    let fifo = fixture.root.join("jobserver");
    rustix::fs::mkfifoat(rustix::fs::CWD, &fifo, Mode::RUSR | Mode::WUSR).unwrap();
    let mut queue = fs::File::from(
        rustix::fs::open(
            &fifo,
            rustix::fs::OFlags::RDWR | rustix::fs::OFlags::NONBLOCK | rustix::fs::OFlags::CLOEXEC,
            Mode::empty(),
        )
        .unwrap(),
    );
    queue.write_all(b"T").unwrap();
    let configured = fixture.command();
    let mut command = Command::new("/bin/sh");
    command
        .args([
            "-c",
            "exec 7<\"$1\"; exec 8>\"$1\"; shift; exec \"$@\"",
            "job-fds",
        ])
        .arg(&fifo)
        .arg(BINARY)
        .arg(&fixture.operation)
        .arg("--wait")
        .env_clear()
        .current_dir(&fixture.root);
    for (name, value) in configured.get_envs() {
        if let Some(value) = value {
            command.env(name, value);
        }
    }
    let mut child = command
        .env("RABS_RECOVER_JOB_JOBSERVER", "1")
        .env("CARGO_MAKEFLAGS", "-j --jobserver-auth=7,8")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let pid = child.id();
    let input = b"original stdin\0\xff\n";
    child.stdin.take().unwrap().write_all(input).unwrap();
    let output = child.wait_with_output().unwrap();
    assert_eq!(output.status.code(), Some(37), "{output:?}");
    assert!(output.stdout.ends_with(b"\0job stdout\xff\n"), "{output:?}");
    assert_eq!(output.stderr, b"\0job stderr\xfe\n");
    let report = fixture.report();
    assert_eq!(report["pid"], pid);
    assert_eq!(report["stdin"], json!(input));
    assert_eq!(report["jobserver"], "-j --jobserver-auth=7,8");
    assert_eq!(report["token"], b'T');
    let mut token = [0];
    queue.read_exact(&mut token).unwrap();
    assert_eq!(token, *b"T");
    assert_eq!(
        queue.read(&mut token).unwrap_err().kind(),
        std::io::ErrorKind::WouldBlock
    );
}

#[test]
fn daemon_job_handoff_keeps_control_failures_and_signal_termination() {
    for code in [0, 23, 101, 130, 255] {
        let fixture = JobFixture::new(true, None, true);
        let output = fixture
            .command()
            .arg("--cancel")
            .env("RABS_RECOVER_JOB_STATUS", code.to_string())
            .output()
            .unwrap();
        assert_eq!(output.status.code(), Some(code), "{output:?}");
        assert_eq!(fixture.report()["argv"], json!(["--job-cancel", JOB_ID]));
    }
    let fixture = JobFixture::new(false, None, true);
    let output = fixture
        .command()
        .arg("--wait")
        .env("RABS_RECOVER_JOB_SIGNAL", "1")
        .output()
        .unwrap();
    assert_eq!(output.status.signal(), Some(15), "{output:?}");
    assert!(fixture.report.exists());
}

#[test]
fn daemon_job_records_cannot_change_authority_identity_or_fixed_native_commands() {
    for case in [
        "version",
        "numeric-request",
        "job-id",
        "directory",
        "automatic-retry",
        "publication",
        "mixed-direct",
        "mixed-recovery",
        "unknown-field",
        "missing-job-id",
        "status-submits",
        "wait-id",
        "driver-mismatch",
        "relative-driver",
        "wait-mode-mismatch",
        "live-type",
        "submit-id",
        "submit-count",
        "submit-outputs",
        "submit-worker",
        "submit-pin",
        "submit-listen",
        "argument-nul",
        "socket-long",
        "socket-relative",
        "socket-overlap",
        "pool-empty",
        "pool-oversize",
        "pool-fields",
        "pool-identity",
        "pool-pin",
        "pool-mapped-address",
        "pool-wildcard",
        "pool-source-path",
        "pool-address",
        "pool-null",
    ] {
        let fixture = JobFixture::new(case.starts_with("pool-"), None, true);
        rewrite_json(&fixture.record, |record| match case {
            "version" => record["version"] = "unsupported".into(),
            "numeric-request" => record["request_id"] = 7.into(),
            "job-id" => record["job_id"] = JOB_ID.to_uppercase().into(),
            "directory" => record["operation_directory"] = json!(fixture.root),
            "automatic-retry" => record["automatic_retry"] = true.into(),
            "publication" => record["publication_authorized"] = true.into(),
            "mixed-direct" => record["prepared_build_argv"] = json!(["/never-run"]),
            "mixed-recovery" => record["recovery"] = json!({"reexecute":true}),
            "unknown-field" => record["unexpected"] = "must-not-be-printed".into(),
            "missing-job-id" => {
                record.as_object_mut().unwrap().remove("job_id");
            }
            "status-submits" => record["job_status_argv"][1] = "--job-submit-allocated".into(),
            "wait-id" => record["job_wait_argv"][2] = "f".repeat(32).into(),
            "driver-mismatch" => record["job_cancel_argv"][0] = "/other/driver".into(),
            "relative-driver" => {
                for name in [
                    "job_submit_argv",
                    "job_status_argv",
                    "job_wait_argv",
                    "job_cancel_argv",
                ] {
                    record[name][0] = "relative-driver".into();
                }
            }
            "wait-mode-mismatch" => record["live_stderr"] = true.into(),
            "live-type" => record["live_stderr"] = "true".into(),
            "submit-id" => record["job_submit_argv"][2] = "f".repeat(32).into(),
            "submit-count" => record["job_submit_argv"]
                .as_array_mut()
                .unwrap()
                .push("extra".into()),
            "submit-outputs" => {
                record["job_submit_argv"][8] = json!(fixture.root.join("other-output"))
            }
            "submit-worker" => record["job_submit_argv"][4] = "worker α".into(),
            "submit-pin" => record["job_submit_argv"][5] = "0".repeat(64).into(),
            "submit-listen" => record["job_submit_argv"][3] = "localhost:7443".into(),
            "argument-nul" => record["job_submit_argv"][4] = "\0must-not-be-printed".into(),
            "socket-long" => record["daemon_socket"] = format!("/{}", "s".repeat(108)).into(),
            "socket-relative" => record["daemon_socket"] = "relative/socket".into(),
            "socket-overlap" => record["daemon_socket"] = json!(fixture.operation.join("socket")),
            "pool-empty" => record["worker_pool"] = json!([]),
            "pool-oversize" => {
                record["worker_pool"] = json!(vec![record["worker_pool"][0].clone(); 33])
            }
            "pool-fields" => record["worker_pool"][0]["unexpected"] = true.into(),
            "pool-identity" => record["worker_pool"][1]["worker"] = "worker-a".into(),
            "pool-pin" => record["worker_pool"][1]["worker_spki_sha256"] = PIN.into(),
            "pool-mapped-address" => {
                record["worker_pool"][1]["address"] = "[::ffff:127.0.0.1]:7443".into()
            }
            "pool-wildcard" => record["worker_pool"][1]["address"] = "0.0.0.0:7443".into(),
            "pool-source-path" => {
                record["job_submit_argv"][3] = json!(fixture.root.join("other-pool"))
            }
            "pool-address" => record["worker_pool"][1]["address"] = "localhost:7444".into(),
            "pool-null" => record["worker_pool"] = Value::Null,
            _ => unreachable!(),
        });
        let before = fs::read(&fixture.record).unwrap();
        fixture.refused(fixture.command().arg("--status").output().unwrap());
        fixture.unchanged(&before);
    }
}

#[test]
fn daemon_job_records_and_active_sockets_require_private_ordinary_ownership() {
    for case in [
        "record-mode",
        "root-mode",
        "record-hardlink",
        "record-symlink",
        "record-fifo",
        "record-oversize",
        "duplicate-json",
        "duplicate-intents",
        "socket-missing",
        "socket-file",
        "socket-fifo",
        "socket-symlink",
        "socket-parent-alias",
        "socket-mode",
        "socket-parent-mode",
    ] {
        let initially_online = !matches!(case, "socket-missing" | "socket-file" | "socket-fifo");
        let fixture = JobFixture::new(false, None, initially_online);
        match case {
            "record-mode" => {
                fs::set_permissions(&fixture.record, fs::Permissions::from_mode(0o640)).unwrap()
            }
            "root-mode" => {
                fs::set_permissions(&fixture.operation, fs::Permissions::from_mode(0o750)).unwrap()
            }
            "record-hardlink" => {
                fs::hard_link(&fixture.record, fixture.root.join("record-alias")).unwrap()
            }
            "record-symlink" | "record-fifo" => {
                let retained = fixture.root.join("retained-record");
                fs::rename(&fixture.record, &retained).unwrap();
                if case == "record-symlink" {
                    symlink(retained, &fixture.record).unwrap();
                } else {
                    rustix::fs::mkfifoat(rustix::fs::CWD, &fixture.record, Mode::RUSR | Mode::WUSR)
                        .unwrap();
                }
            }
            "record-oversize" => OpenOptions::new()
                .write(true)
                .open(&fixture.record)
                .unwrap()
                .set_len(1024 * 1024)
                .unwrap(),
            "duplicate-json" => {
                let record = fs::read_to_string(&fixture.record).unwrap();
                fs::write(
                    &fixture.record,
                    format!("{{\"job_id\":\"{JOB_ID}\",{}", &record[1..]),
                )
                .unwrap();
            }
            "duplicate-intents" => new_file(&fixture.operation.join("recovery.json"), b"{}", 0o600),
            "socket-file" | "socket-fifo" => {
                private_directory(fixture.socket.parent().unwrap());
                if case == "socket-file" {
                    new_file(&fixture.socket, b"not a socket", 0o600);
                } else {
                    rustix::fs::mkfifoat(rustix::fs::CWD, &fixture.socket, Mode::RUSR | Mode::WUSR)
                        .unwrap();
                }
            }
            "socket-symlink" => {
                let retained = fixture.root.join("retained-socket");
                fs::rename(&fixture.socket, &retained).unwrap();
                symlink(retained, &fixture.socket).unwrap();
            }
            "socket-parent-alias" => {
                let alias = fixture.root.join("alias");
                symlink(fixture.socket.parent().unwrap(), &alias).unwrap();
                rewrite_json(&fixture.record, |record| {
                    record["daemon_socket"] = json!(alias.join("socket"))
                });
            }
            "socket-mode" => {
                fs::set_permissions(&fixture.socket, fs::Permissions::from_mode(0o660)).unwrap()
            }
            "socket-parent-mode" => fs::set_permissions(
                fixture.socket.parent().unwrap(),
                fs::Permissions::from_mode(0o775),
            )
            .unwrap(),
            "socket-missing" => {}
            _ => unreachable!(),
        }
        fixture.refused(fixture.command().arg("--wait").output().unwrap());
    }
}

#[test]
fn daemon_job_result_paths_cannot_replace_inputs_outputs_or_partial_receivers() {
    for case in [
        "resume-existing",
        "resume-dangling",
        "resume-bundle",
        "resume-output",
        "resume-current",
        "resume-parent-alias",
        "delivery-bundle",
        "delivery-output",
        "ack-root",
        "delivery-public",
        "prefix-missing",
        "prefix-public",
        "prefix-destination",
        "prefix-bundle",
        "prefix-output",
        "prefix-symlink",
    ] {
        let fixture = JobFixture::new(true, Some(true), true);
        let before = fs::read(&fixture.record).unwrap();
        let mut option = "--resume-to";
        let mut destination = fixture.root.join("new-delivery");
        let mut prefix = None;
        match case {
            "resume-existing" => private_directory(&destination),
            "resume-dangling" => symlink(fixture.root.join("missing"), &destination).unwrap(),
            "resume-bundle" => destination = fixture.operation.join("bundle"),
            "resume-output" => destination = fixture.operation.join("outputs"),
            "resume-current" => destination = fixture.operation.join("delivery"),
            "resume-parent-alias" => {
                let parent = fixture.root.join("actual-parent");
                private_directory(&parent);
                let alias = fixture.root.join("alias");
                symlink(parent, &alias).unwrap();
                destination = alias.join("new-delivery");
            }
            "delivery-bundle" | "delivery-output" | "delivery-public" => {
                option = "--delivery";
                if case != "delivery-public" {
                    destination = fixture.operation.join(if case == "delivery-bundle" {
                        "bundle"
                    } else {
                        "outputs"
                    });
                }
                private_directory(&destination);
                if case == "delivery-public" {
                    fs::set_permissions(&destination, fs::Permissions::from_mode(0o755)).unwrap();
                }
            }
            "ack-root" => {
                option = "--acknowledge";
                destination = fixture.operation.clone();
            }
            "prefix-missing" => prefix = Some(fixture.root.join("missing-prefix")),
            _ => {
                let selected = match case {
                    "prefix-bundle" => fixture.operation.join("bundle"),
                    "prefix-output" => fixture.operation.join("outputs"),
                    _ => fixture.root.join("partial"),
                };
                private_directory(&selected);
                if case == "prefix-public" {
                    fs::set_permissions(&selected, fs::Permissions::from_mode(0o755)).unwrap();
                }
                if case == "prefix-destination" {
                    destination = selected.join("new-delivery");
                }
                prefix = if case == "prefix-symlink" {
                    let alias = fixture.root.join("prefix-alias");
                    symlink(selected, &alias).unwrap();
                    Some(alias)
                } else {
                    Some(selected)
                };
            }
        }
        let mut command = fixture.command();
        command.arg(option).arg(destination);
        if let Some(prefix) = prefix {
            command.arg("--prefix-from").arg(prefix);
        }
        fixture.refused(command.output().unwrap());
        assert_eq!(fs::read(&fixture.record).unwrap(), before);
    }
}

#[test]
fn daemon_job_controls_cannot_bypass_a_direct_owner_or_replace_daemon_admission_state() {
    for fixture in [Fixture::live(), Fixture::canonical(false)] {
        for option in ["--wait", "--status", "--cancel", "--delivery"] {
            let mut command = fixture.command();
            command.arg(option).arg("--rabsd").arg(&fixture.daemon);
            if option == "--delivery" {
                command = fixture.operation(option, &fixture.root.join("delivery"));
            }
            fixture.refused(command.output().unwrap());
        }
    }
    let fixture = JobFixture::new(false, None, true);
    fixture.refused(
        fixture
            .command()
            .arg("--status")
            .arg("--canonical-state-dir")
            .arg(&fixture.root)
            .output()
            .unwrap(),
    );
    fixture.refused(
        fixture
            .command()
            .arg("--status")
            .arg("--resume-to")
            .arg(fixture.root.join("another-result"))
            .output()
            .unwrap(),
    );
    fixture.refused(
        fixture
            .command()
            .arg("--status")
            .env("CARGO_RABS_DAEMON", BINARY)
            .output()
            .unwrap(),
    );
    let output = fixture
        .command()
        .arg("--status")
        .env("CARGO_RABS_DAEMON", "/missing/ignored-override")
        .arg("--rabsd")
        .arg(&fixture.daemon)
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(37), "{output:?}");
    assert_eq!(fixture.report()["argv"], json!(["--job-status", JOB_ID]));
}
