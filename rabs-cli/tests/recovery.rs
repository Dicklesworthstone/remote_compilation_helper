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

const BINARY: &str = env!("CARGO_BIN_EXE_rabs-recover");
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
        let mut command = Command::new(BINARY);
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
