//! Real --worker-prepare and Cargo path-dependency integration.
//!
//! Cargo builds the CLI's retained sibling layout with an existing lockfile,
//! offline and outside the source tree. This is source-layout/Cargo proof, not
//! proof of remote transport, canonical namespace isolation or cache serving.
//! Missing Cargo/compiler support is a test failure, never a passing skip.
#![cfg(target_os = "linux")]

use rabs_sandbox::snapshot_capture::capture_sealed_source;
use rabsd::coord::source_delivery::SourceUpload;
use serde_json::{Value, json};
use std::fs::{self, File};
use std::io::Read;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::Arc;
use std::time::{Duration, Instant};

struct OwnedProcess {
    child: Child,
    reaped: bool,
}

impl Drop for OwnedProcess {
    fn drop(&mut self) {
        if !self.reaped {
            // All launched commands own a new process group. A timed-out Cargo
            // must not leave its compiler/linker running after the test fails.
            let group = format!("-{}", self.child.id());
            let _ = Command::new("/bin/kill")
                .args(["-KILL", "--", &group])
                .stdin(Stdio::null()).stdout(Stdio::null()).stderr(Stdio::null()).status();
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
    }
}

fn captured(path: &Path) -> Vec<u8> {
    let mut bytes = Vec::new();
    File::open(path).unwrap().take(4 * 1024 * 1024 + 1).read_to_end(&mut bytes).unwrap();
    assert!(bytes.len() <= 4 * 1024 * 1024, "fixture output exceeded its bound");
    bytes
}

fn run(root: &Path, command: &mut Command, budget: Duration) -> (ExitStatus, Vec<u8>, Vec<u8>) {
    let logs = tempfile::tempdir_in(root).unwrap();
    let stdout = logs.path().join("stdout");
    let stderr = logs.path().join("stderr");
    let mut owned = OwnedProcess {
        child: command.process_group(0).stdin(Stdio::null())
            .stdout(File::create(&stdout).unwrap()).stderr(File::create(&stderr).unwrap())
            .spawn().expect("fixture process must be available"),
        reaped: false,
    };
    let deadline = Instant::now() + budget;
    let status = loop {
        if let Some(status) = owned.child.try_wait().unwrap() { break status; }
        assert!(Instant::now() < deadline, "fixture process timed out: {}", String::from_utf8_lossy(&captured(&stderr)));
        std::thread::sleep(Duration::from_millis(5));
    };
    owned.reaped = true;
    (status, captured(&stdout), captured(&stderr))
}

struct Fixture {
    root: tempfile::TempDir,
    app: PathBuf,
    dep: PathBuf,
    spec: Value,
}

impl Fixture {
    fn new() -> Self {
        let root = tempfile::tempdir().unwrap();
        // Deliberately unrelated host paths: the declared IDs, not host layout,
        // establish the app -> ../dep relationship in the worker projection.
        let app = root.path().join("application checkout");
        let dep = root.path().join("elsewhere/dependency checkout");
        fs::create_dir_all(app.join("src")).unwrap();
        fs::create_dir_all(dep.join("src")).unwrap();
        fs::write(app.join("Cargo.toml"), concat!(
            "[package]\nname = \"closure_app\"\nversion = \"0.1.0\"\nedition = \"2021\"\n",
            "[workspace]\n[dependencies]\nclosure_dep = { path = \"../dep\" }\n",
        )).unwrap();
        fs::write(dep.join("Cargo.toml"),
            "[package]\nname = \"closure_dep\"\nversion = \"0.1.0\"\nedition = \"2021\"\n").unwrap();
        fs::write(app.join("Cargo.lock"), concat!(
            "version = 4\n\n[[package]]\nname = \"closure_app\"\nversion = \"0.1.0\"\n",
            "dependencies = [\"closure_dep\"]\n\n[[package]]\nname = \"closure_dep\"\nversion = \"0.1.0\"\n",
        )).unwrap();
        fs::write(app.join("src/main.rs"),
            "fn main() { println!(\"{}:{}\", closure_dep::answer(), env!(\"BUILD_LABEL\")); }\n").unwrap();
        fs::write(dep.join("src/lib.rs"), "pub fn answer() -> u32 { 42 }\n").unwrap();
        fs::write(dep.join("not-approved.private"), b"do not upload this").unwrap();
        fs::write(root.path().join("invalid-config.toml"), "[not valid TOML").unwrap();
        let spec = json!({"kind":"canonical-exec", "request_id":81, "program":"cargo",
            "args":["build", "--frozen", "--jobs=1"], "toolchain_backing":"/worker/toolchain",
            "command_context":{"version":"env-cwd-v1", "cwd":"/__rabs/workspace/app",
                "env":{"CARGO_TARGET_DIR":"/__rabs/out/build", "BUILD_LABEL":"exact\n雪"}},
            "source_roots":{
                "app":{"path":".", "files":["Cargo.toml", "Cargo.lock", "src/main.rs"]},
                "dep":{"path":dep, "files":["Cargo.toml", "src/lib.rs"]}},
            "artifacts":{"unit":"build", "files":["debug/closure_app"]}});
        Self { root, app, dep, spec }
    }

    fn prepare(&self, name: &str, specification: &Value) -> (PathBuf, ExitStatus, Vec<u8>, Vec<u8>) {
        let spec_path = self.root.path().join(format!("{name}.json"));
        fs::write(&spec_path, serde_json::to_vec(specification).unwrap()).unwrap();
        let bundle = self.root.path().join(name);
        let mut command = Command::new(env!("CARGO_BIN_EXE_rabsd"));
        command.arg("--worker-prepare").arg(&self.app).arg(spec_path).arg(&bundle)
            .current_dir(self.root.path())
            .env("RABS_CONFIG", self.root.path().join("invalid-config.toml"))
            .env("RABS_SOCKET_PATH", self.root.path().join("must-not-bind.sock"))
            .env("RABS_STATE_DIR", self.root.path().join("must-not-create-state"));
        let (status, stdout, stderr) = run(self.root.path(), &mut command, Duration::from_secs(15));
        assert!(!self.root.path().join("must-not-bind.sock").exists());
        assert!(!self.root.path().join("must-not-create-state").exists());
        (bundle, status, stdout, stderr)
    }
}

#[test]
fn prepared_multi_repository_bundle_builds_with_real_cargo_after_checkout_changes() {
    let fixture = Fixture::new();
    let (bundle, status, stdout, stderr) = fixture.prepare("bundle", &fixture.spec);
    assert!(status.success(), "{}", String::from_utf8_lossy(&stderr));
    assert!(stderr.is_empty());
    let summary: Value = serde_json::from_slice(&stdout).unwrap();
    assert_eq!(summary["source_roots"], 2);
    assert_eq!(summary["source_files"], 5);
    assert_eq!(summary["executed"], false);
    assert_eq!(summary["publication_authorized"], false);
    let request_bytes = fs::read(bundle.join("request.json")).unwrap();
    let request: Value = serde_json::from_slice(&request_bytes).unwrap();
    assert!(request.get("source_roots").is_none());
    assert!(!request.to_string().contains(fixture.dep.to_str().unwrap()));
    assert_eq!(request["command_context"], fixture.spec["command_context"]);
    let source = bundle.join("source");
    for (host, relative) in [(&fixture.app, "app/Cargo.toml"), (&fixture.dep, "dep/Cargo.toml")] {
        assert_eq!(fs::read(source.join(relative)).unwrap(), fs::read(host.join("Cargo.toml")).unwrap());
    }
    assert!(!source.join("dep/not-approved.private").exists());
    fs::write(fixture.dep.join("src/lib.rs"), "pub fn answer() -> u32 { 99 }\n").unwrap();
    fs::rename(&fixture.app, fixture.root.path().join("retired-application")).unwrap();

    // Exercise Cargo's actual path resolution on the retained files. The target
    // is private and outside source. This local fixture intentionally does not
    // claim to execute the canonical request through a remote worker namespace.
    let target = fixture.root.path().join("target");
    let cargo_home = fixture.root.path().join("cargo-home");
    fs::create_dir(&cargo_home).unwrap();
    let cargo = std::env::var_os("CARGO").unwrap_or_else(|| "cargo".into());
    let mut command = Command::new(cargo);
    command.env_clear();
    for key in ["PATH", "HOME", "RUSTUP_HOME", "RUSTUP_TOOLCHAIN", "LD_LIBRARY_PATH", "RUSTC"] {
        if let Some(value) = std::env::var_os(key) { command.env(key, value); }
    }
    command.current_dir(source.join("app"))
        .args(["build", "--frozen", "--jobs=1", "--message-format=json"])
        .arg("--target-dir").arg(&target)
        .env("CARGO_HOME", cargo_home)
        .env("BUILD_LABEL", request["command_context"]["env"]["BUILD_LABEL"].as_str().unwrap());
    let (status, _, stderr) = run(fixture.root.path(), &mut command, Duration::from_secs(60));
    assert!(status.success(), "real Cargo failed: {}", String::from_utf8_lossy(&stderr));
    let mut executable = Command::new(target.join("debug/closure_app"));
    let (status, stdout, stderr) = run(fixture.root.path(), &mut executable, Duration::from_secs(5));
    assert!(status.success(), "{}", String::from_utf8_lossy(&stderr));
    assert_eq!(stdout, "42:exact\n雪\n".as_bytes(), "must build captured dependency, not later checkout bytes");
    assert_eq!(fs::read(bundle.join("request.json")).unwrap(), request_bytes);
    let image = Arc::new(capture_sealed_source(&[("workspace".into(), source)], false, 2, 200_000).unwrap());
    assert_eq!(SourceUpload::for_request(image, "workspace", &request).unwrap().wire_manifest(), request["source_manifest"]);
}

#[test]
fn invalid_or_unresolved_closure_specs_cannot_create_bundles_or_start_execution() {
    let fixture = Fixture::new();
    for case in 0..4 {
        let mut spec = fixture.spec.clone();
        match case {
            0 => spec["source_files"] = json!(["Cargo.toml"]),
            1 => spec["source_roots"]["dep"]["files"] = json!(["missing.rs"]),
            2 => spec["source_roots"]["dep"]["path"] = json!("../escape"),
            _ => spec["source_roots"]["DEP"] = spec["source_roots"]["dep"].clone(),
        }
        let (bundle, status, stdout, stderr) = fixture.prepare(&format!("bad-{case}"), &spec);
        assert_eq!(status.code(), Some(2));
        assert!(stdout.is_empty());
        assert_eq!(serde_json::from_slice::<Value>(&stderr).unwrap()["kind"], "worker-prepare-failed");
        assert!(!bundle.exists());
    }
    let path = fixture.root.path().join("unresolved.json");
    fs::write(&path, serde_json::to_vec(&fixture.spec).unwrap()).unwrap();
    let delivery = fixture.root.path().join("never-delivered");
    let mut command = Command::new(env!("CARGO_BIN_EXE_rabsd"));
    command.args(["--worker-exec-loopback", "127.0.0.1:0", "fixture-worker"]).arg(path).arg(&delivery);
    let (status, stdout, stderr) = run(fixture.root.path(), &mut command, Duration::from_secs(10));
    assert!(!status.success());
    assert!(stdout.is_empty());
    let failure: Value = serde_json::from_slice(&stderr).unwrap();
    assert_eq!(failure["execution_may_have_run"], false);
    assert!(failure["detail"].as_str().unwrap().contains("--worker-prepare"));
    assert!(!delivery.exists());
}
