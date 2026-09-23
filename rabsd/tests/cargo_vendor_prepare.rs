//! Actual preparation CLI and Cargo dependency-resolution/build coverage.
//! The opt-in controlled-host case also uses native TLS and the real worker.
//! No registry is contacted: generated vendored fixtures provide the full graph.
#![cfg(target_os = "linux")]

use rabs_sandbox::snapshot_capture::capture_sealed_source;
use rabsd::coord::source_delivery::SourceUpload;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fs::{self, File};
use std::io::Read;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::Arc;
use std::time::{Duration, Instant};

const LOG_LIMIT: u64 = 4 * 1024 * 1024;
const REGISTRY: &str = "registry+https://github.com/rust-lang/crates.io-index";
const LABEL: &str = "exact\n雪";
const WORKER: &str = "vendor-build-test";

fn hash(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}
fn write(root: &Path, path: &str, bytes: impl AsRef<[u8]>) {
    let path = root.join(path);
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(path, bytes).unwrap();
}
fn read_log(path: &Path) -> Vec<u8> {
    let mut bytes = Vec::new();
    File::open(path)
        .unwrap()
        .take(LOG_LIMIT + 1)
        .read_to_end(&mut bytes)
        .unwrap();
    assert!(
        bytes.len() as u64 <= LOG_LIMIT,
        "fixture output exceeded its bound"
    );
    bytes
}

struct Process {
    child: Child,
    stdout: PathBuf,
    stderr: PathBuf,
    reaped: bool,
}
impl Process {
    fn spawn(owner: &Path, name: &str, command: &mut Command) -> Self {
        let stdout = owner.join(format!("{name}.stdout"));
        let stderr = owner.join(format!("{name}.stderr"));
        let child = command
            .process_group(0)
            .stdin(Stdio::null())
            .stdout(File::create(&stdout).unwrap())
            .stderr(File::create(&stderr).unwrap())
            .spawn()
            .expect("fixture executable must be available; missing tools are not a pass");
        Self {
            child,
            stdout,
            stderr,
            reaped: false,
        }
    }
    fn wait(&mut self, budget: Duration) -> (ExitStatus, Vec<u8>, Vec<u8>) {
        let until = Instant::now() + budget;
        loop {
            for path in [&self.stdout, &self.stderr] {
                assert!(
                    fs::metadata(path).unwrap().len() <= LOG_LIMIT,
                    "unbounded fixture output"
                );
            }
            if let Some(status) = self.child.try_wait().unwrap() {
                self.reaped = true;
                return (status, read_log(&self.stdout), read_log(&self.stderr));
            }
            assert!(
                Instant::now() < until,
                "fixture timeout: {}",
                String::from_utf8_lossy(&read_log(&self.stderr))
            );
            std::thread::sleep(Duration::from_millis(5));
        }
    }
    fn listening(&mut self) -> String {
        let until = Instant::now() + Duration::from_secs(20);
        loop {
            let log = read_log(&self.stderr);
            for line in String::from_utf8_lossy(&log).lines() {
                if let Ok(value) = serde_json::from_str::<Value>(line)
                    && value["kind"] == "worker-exec-listening"
                {
                    assert_eq!(value["transport"], "mutual-tls-atp");
                    assert_eq!(value["authentication_required"], true);
                    return value["address"].as_str().unwrap().to_owned();
                }
            }
            if let Some(status) = self.child.try_wait().unwrap() {
                self.reaped = true;
                panic!(
                    "receiver exited before listening ({status}): {}",
                    String::from_utf8_lossy(&log)
                );
            }
            assert!(Instant::now() < until, "receiver readiness timeout");
            std::thread::sleep(Duration::from_millis(5));
        }
    }
}
impl Drop for Process {
    fn drop(&mut self) {
        if self.reaped || self.child.try_wait().ok().flatten().is_some() {
            return;
        }
        let group = format!("-{}", self.child.id());
        let signal = |name: &str| {
            let _ = Command::new("/bin/kill")
                .args([name, "--", group.as_str()])
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status();
        };
        signal("-TERM");
        let until = Instant::now() + Duration::from_secs(5);
        while Instant::now() < until {
            if self.child.try_wait().ok().flatten().is_some() {
                return;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        // These are private, explicitly owned fixture groups, not fleet jobs.
        signal("-KILL");
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn command(program: impl AsRef<std::ffi::OsStr>) -> Command {
    let mut command = Command::new(program);
    command.env_clear();
    for name in [
        "PATH",
        "LD_LIBRARY_PATH",
        "DYLD_LIBRARY_PATH",
        "RUSTUP_HOME",
        "RUSTUP_TOOLCHAIN",
    ] {
        if let Some(value) = std::env::var_os(name) {
            command.env(name, value);
        }
    }
    command
}

struct Fixture {
    owner: tempfile::TempDir,
    anchor: PathBuf,
    cargo: PathBuf,
    rustc: PathBuf,
    specification: Value,
}
impl Fixture {
    fn new() -> Self {
        let owner = tempfile::tempdir().unwrap();
        let anchor = owner.path().join("approved source");
        fs::create_dir(&anchor).unwrap();
        let cargo = fs::canonicalize(std::env::var_os("CARGO").expect("Cargo test runner"))
            .expect("installed Cargo executable");
        let rustc = cargo.parent().unwrap().join("rustc");
        assert!(
            rustc.is_file(),
            "run this fixture with a complete installed toolchain, not only a rustup proxy"
        );
        write(
            &anchor,
            "Cargo.toml",
            "[workspace]\nmembers=['app','local_dep']\nresolver='2'\n",
        );
        write(
            &anchor,
            ".cargo/config.toml",
            "[source.crates-io]\nreplace-with='vendored-sources'\n[source.vendored-sources]\ndirectory='vendor'\n",
        );
        write(
            &anchor,
            "app/Cargo.toml",
            "[package]\nname='vendor_app'\nversion='0.1.0'\nedition='2021'\n[dependencies]\nlocal_dep={path='../local_dep'}\nregistry_dep='=1.0.0'\n",
        );
        write(
            &anchor,
            "app/src/main.rs",
            "fn main() { println!(\"{}:{}\", registry_dep::answer()+local_dep::answer(), env!(\"BUILD_LABEL\")); }\n",
        );
        write(
            &anchor,
            "local_dep/Cargo.toml",
            "[package]\nname='local_dep'\nversion='0.1.0'\nedition='2021'\n",
        );
        write(
            &anchor,
            "local_dep/src/lib.rs",
            "pub fn answer() -> u32 { 2 }\n",
        );
        let leaf = Self::vendor(
            &anchor,
            "registry_leaf",
            BTreeMap::from([
                (
                    "Cargo.toml",
                    "[package]\nname='registry_leaf'\nversion='1.0.0'\nedition='2021'\n",
                ),
                ("src/lib.rs", "pub fn answer() -> u32 { 40 }\n"),
            ]),
        );
        let dep = Self::vendor(
            &anchor,
            "registry_dep",
            BTreeMap::from([
                (
                    "Cargo.toml",
                    "[package]\nname='registry_dep'\nversion='1.0.0'\nedition='2021'\nbuild='build.rs'\n[dependencies]\nregistry_leaf='=1.0.0'\n[build-dependencies]\nregistry_leaf='=1.0.0'\n",
                ),
                (
                    "build.rs",
                    "fn main() { let n: u32 = std::fs::read_to_string(\"payload.txt\").unwrap().trim().parse().unwrap(); assert_eq!(n, registry_leaf::answer()); let out=std::path::PathBuf::from(std::env::var_os(\"OUT_DIR\").unwrap()); std::fs::write(out.join(\"generated.rs\"), format!(\"pub const GENERATED:u32={n};\")).unwrap(); println!(\"cargo:rerun-if-changed=payload.txt\"); }\n",
                ),
                (
                    "src/lib.rs",
                    "include!(concat!(env!(\"OUT_DIR\"),\"/generated.rs\")); pub fn answer() -> u32 { GENERATED+registry_leaf::answer()-40 }\n",
                ),
                ("payload.txt", "40\n"),
                // This checks the production distinction between a package manifest
                // and nested checksum-covered test data that Cargo never resolves.
                (
                    "test-fixtures/Cargo.toml",
                    "not a Cargo manifest; ordinary fixture data\n",
                ),
            ]),
        );
        write(
            &anchor,
            "Cargo.lock",
            format!(
                "version=4\n\n[[package]]\nname='local_dep'\nversion='0.1.0'\n\n[[package]]\nname='registry_dep'\nversion='1.0.0'\nsource='{REGISTRY}'\nchecksum='{dep}'\ndependencies=['registry_leaf']\n\n[[package]]\nname='registry_leaf'\nversion='1.0.0'\nsource='{REGISTRY}'\nchecksum='{leaf}'\n\n[[package]]\nname='vendor_app'\nversion='0.1.0'\ndependencies=['local_dep','registry_dep']\n"
            ),
        );
        let specification = json!({"kind":"canonical-exec","request_id":91,
            "program":"/__rabs/toolchain/bin/cargo","args":["build","--frozen","--jobs=1","-p","vendor_app"],
            "toolchain_backing":cargo.parent().and_then(Path::parent).unwrap(),
            "timeout_ms":90000,"jobserver_grant":1,
            "cargo_source":{"manifest":"Cargo.toml","vendor":"vendor"},
            "command_context":{"version":"env-cwd-v1","cwd":"/__rabs/workspace",
                "env":{"CARGO_TARGET_DIR":"/__rabs/out/build","CARGO_INCREMENTAL":"0","BUILD_LABEL":LABEL}},
            "artifacts":{"unit":"build","files":["debug/vendor_app"],"tree":"tree-files-v1"}});
        Self {
            owner,
            anchor,
            cargo,
            rustc,
            specification,
        }
    }
    fn vendor(root: &Path, name: &str, files: BTreeMap<&str, &str>) -> String {
        let mut checksums = serde_json::Map::new();
        for (path, bytes) in files {
            write(root, &format!("vendor/{name}/{path}"), bytes);
            checksums.insert(path.to_owned(), json!(hash(bytes.as_bytes())));
        }
        // Synthetic directory-source package metadata, not registry authenticity
        // evidence. Cargo's directory source matches it to the synthetic lock.
        let package = hash(format!("generated fixture package {name}").as_bytes());
        write(
            root,
            &format!("vendor/{name}/.cargo-checksum.json"),
            serde_json::to_vec(&json!({"package":package,"files":checksums})).unwrap(),
        );
        package
    }
    fn git() -> (Self, String) {
        let owner = tempfile::tempdir().unwrap();
        let anchor = owner.path().join("approved source");
        fs::create_dir(&anchor).unwrap();
        let cargo = fs::canonicalize(std::env::var_os("CARGO").expect("Cargo test runner"))
            .expect("installed Cargo executable");
        let rustc = cargo.parent().unwrap().join("rustc");
        assert!(
            rustc.is_file(),
            "Git vendor fixture requires a complete installed toolchain"
        );
        let repository = owner.path().join("original-git");
        write(
            &repository,
            "Cargo.toml",
            "[workspace]\nmembers=['dep','leaf']\nresolver='2'\n[workspace.package]\nversion='1.0.0'\nedition='2021'\n",
        );
        write(
            &repository,
            "dep/Cargo.toml",
            "[package]\nname='git_dep'\nversion.workspace=true\nedition.workspace=true\nbuild='build.rs'\n[dependencies]\ngit_leaf={path='../leaf'}\n[build-dependencies]\ngit_leaf={path='../leaf'}\n",
        );
        write(
            &repository,
            "dep/build.rs",
            "fn main() { let n: u32=std::fs::read_to_string(\"payload.txt\").unwrap().trim().parse().unwrap(); assert_eq!(n, git_leaf::answer()); let out=std::path::PathBuf::from(std::env::var_os(\"OUT_DIR\").unwrap()); std::fs::write(out.join(\"generated.rs\"), format!(\"pub const GENERATED:u32={n};\")).unwrap(); println!(\"cargo:rerun-if-changed=payload.txt\"); }\n",
        );
        write(&repository, "dep/payload.txt", "40\n");
        write(
            &repository,
            "dep/src/lib.rs",
            "include!(concat!(env!(\"OUT_DIR\"),\"/generated.rs\")); pub fn answer() -> u32 { GENERATED+git_leaf::answer()-40 }\n",
        );
        write(
            &repository,
            "leaf/Cargo.toml",
            "[package]\nname='git_leaf'\nversion.workspace=true\nedition.workspace=true\n",
        );
        write(
            &repository,
            "leaf/src/lib.rs",
            "pub fn answer() -> u32 { 40 }\n",
        );
        let git = |name: &str, args: &[&str]| {
            let mut cmd = command("git");
            cmd.current_dir(&repository)
                .args(args)
                .env("GIT_CONFIG_NOSYSTEM", "1")
                .env("GIT_CONFIG_GLOBAL", owner.path().join("absent-git-config"));
            let (status, stdout, stderr) =
                Process::spawn(owner.path(), name, &mut cmd).wait(Duration::from_secs(15));
            assert!(
                status.success(),
                "{name}: {}",
                String::from_utf8_lossy(&stderr)
            );
            stdout
        };
        git("git-init", &["init", "--initial-branch=main"]);
        git("git-add", &["add", "."]);
        git(
            "git-commit",
            &[
                "-c",
                "user.name=Fixture",
                "-c",
                "user.email=fixture@example.invalid",
                "-c",
                "core.hooksPath=/dev/null",
                "commit",
                "--no-gpg-sign",
                "-m",
                "captured Git source",
            ],
        );
        let revision = String::from_utf8(git("git-revision", &["rev-parse", "HEAD"]))
            .unwrap()
            .trim()
            .to_owned();
        assert_eq!(revision.len(), 40);
        let url = format!("file://{}", repository.display());
        write(
            &anchor,
            "Cargo.toml",
            "[workspace]\nmembers=['app','local_dep']\nresolver='2'\n",
        );
        write(
            &anchor,
            "app/Cargo.toml",
            format!(
                "[package]\nname='vendor_app'\nversion='0.1.0'\nedition='2021'\n[dependencies]\nlocal_dep={{path='../local_dep'}}\ngit_dep={{git='{url}',rev='{revision}'}}\n"
            ),
        );
        write(
            &anchor,
            "app/src/main.rs",
            "fn main() { println!(\"{}:{}\", git_dep::answer()+local_dep::answer(), env!(\"BUILD_LABEL\")); }\n",
        );
        write(
            &anchor,
            "local_dep/Cargo.toml",
            "[package]\nname='local_dep'\nversion='0.1.0'\nedition='2021'\n",
        );
        write(
            &anchor,
            "local_dep/src/lib.rs",
            "pub fn answer() -> u32 { 2 }\n",
        );
        let seed_home = owner.path().join("seed-cargo-home");
        let cargo_run = |name: &str, args: &[&str]| {
            let mut cmd = command(&cargo);
            cmd.current_dir(&anchor)
                .args(args)
                .env("CARGO_HOME", &seed_home)
                .env("RUSTC", &rustc)
                .env("CARGO_NET_GIT_FETCH_WITH_CLI", "true")
                .env("GIT_CONFIG_NOSYSTEM", "1")
                .env("GIT_CONFIG_GLOBAL", owner.path().join("absent-git-config"));
            let (status, stdout, stderr) =
                Process::spawn(owner.path(), name, &mut cmd).wait(Duration::from_secs(30));
            assert!(
                status.success(),
                "{name}: {}",
                String::from_utf8_lossy(&stderr)
            );
            stdout
        };
        cargo_run("git-lock", &["generate-lockfile"]);
        let config = cargo_run(
            "git-vendor",
            &["vendor", "--locked", "--versioned-dirs", "vendor"],
        );
        write(&anchor, ".cargo/config.toml", config);
        let lock = fs::read_to_string(anchor.join("Cargo.lock")).unwrap();
        assert!(lock.contains(&format!("git+{url}?rev={revision}#{revision}")));
        assert!(!lock.contains("checksum ="));
        for package in ["git_dep", "git_leaf"] {
            let checksums: Value = serde_json::from_slice(
                &fs::read(anchor.join(format!("vendor/{package}-1.0.0/.cargo-checksum.json")))
                    .unwrap(),
            )
            .unwrap();
            assert_eq!(checksums.get("package"), Some(&Value::Null));
        }
        // Cargo retains this sibling path in a Git directory-source manifest.
        // It resolves the dependency by the original Git source, not this path.
        let dep_manifest =
            fs::read_to_string(anchor.join("vendor/git_dep-1.0.0/Cargo.toml")).unwrap();
        assert!(dep_manifest.contains("path = \"../leaf\""));
        fs::rename(&repository, owner.path().join("retired-original-git")).unwrap();
        fs::rename(&seed_home, owner.path().join("retired-seed-cargo-home")).unwrap();
        let specification = json!({"kind":"canonical-exec","request_id":92,
            "program":"/__rabs/toolchain/bin/cargo","args":["build","--frozen","--jobs=1","-p","vendor_app"],
            "toolchain_backing":cargo.parent().and_then(Path::parent).unwrap(),
            "timeout_ms":90000,"jobserver_grant":1,
            "cargo_source":{"manifest":"Cargo.toml","vendor":"vendor"},
            "command_context":{"version":"env-cwd-v1","cwd":"/__rabs/workspace",
                "env":{"CARGO_TARGET_DIR":"/__rabs/out/build","CARGO_INCREMENTAL":"0","BUILD_LABEL":LABEL}},
            "artifacts":{"unit":"build","files":["debug/vendor_app"],"tree":"tree-files-v1"}});
        (
            Self {
                owner,
                anchor,
                cargo,
                rustc,
                specification,
            },
            revision,
        )
    }
    fn prepare(&self, name: &str) -> (PathBuf, ExitStatus, Vec<u8>, Vec<u8>) {
        let spec = self.owner.path().join(format!("{name}.json"));
        fs::write(&spec, self.specification.to_string()).unwrap();
        let bundle = self.owner.path().join(name);
        let mut cmd = command(env!("CARGO_BIN_EXE_rabsd"));
        cmd.arg("--worker-prepare")
            .arg(&self.anchor)
            .arg(spec)
            .arg(&bundle)
            .env("CARGO", &self.cargo)
            .env("RUSTC", &self.rustc)
            .env("RUSTC_WRAPPER", "/must-not-execute-a-wrapper");
        let result =
            Process::spawn(self.owner.path(), name, &mut cmd).wait(Duration::from_secs(45));
        (bundle, result.0, result.1, result.2)
    }
    fn prepared(&self) -> (PathBuf, Value) {
        let (bundle, status, stdout, stderr) = self.prepare("bundle");
        assert!(status.success(), "{}", String::from_utf8_lossy(&stderr));
        let summary: Value = serde_json::from_slice(&stdout).unwrap();
        assert_eq!(summary["executed"], false);
        assert_eq!(summary["publication_authorized"], false);
        let request: Value =
            serde_json::from_slice(&fs::read(bundle.join("request.json")).unwrap()).unwrap();
        let mut expected = self.specification.clone();
        expected.as_object_mut().unwrap().remove("cargo_source");
        expected["source_manifest"] = request["source_manifest"].clone();
        assert_eq!(
            request, expected,
            "only preparation intent becomes a manifest"
        );
        assert_eq!(
            fs::read(bundle.join("source/.cargo/config.toml")).unwrap(),
            fs::read(self.anchor.join(".cargo/config.toml")).unwrap()
        );
        assert_eq!(
            fs::read(bundle.join("source/Cargo.lock")).unwrap(),
            fs::read(self.anchor.join("Cargo.lock")).unwrap()
        );
        (bundle, request)
    }
}

#[test]
fn real_preparation_and_frozen_cargo_build_use_captured_transitive_and_build_script_inputs() {
    let fixture = Fixture::new();
    let (bundle, request) = fixture.prepared();
    write(
        &fixture.anchor,
        "vendor/registry_leaf/src/lib.rs",
        "pub fn answer() -> u32 { 99 }\n",
    );
    fs::rename(
        &fixture.anchor,
        fixture.owner.path().join("retired-checkout"),
    )
    .unwrap();
    let home = fixture.owner.path().join("local-cargo-home");
    fs::create_dir(&home).unwrap();
    let target = fixture.owner.path().join("local-target");
    let mut cmd = command(&fixture.cargo);
    cmd.current_dir(bundle.join("source"))
        .args(["build", "--frozen", "--jobs=1", "-p", "vendor_app"])
        .arg("--target-dir")
        .arg(&target)
        .env("CARGO_HOME", &home)
        .env("RUSTC", &fixture.rustc)
        .env("CARGO_INCREMENTAL", "0")
        .env("BUILD_LABEL", LABEL);
    let (status, _, stderr) =
        Process::spawn(fixture.owner.path(), "cargo-build", &mut cmd).wait(Duration::from_secs(90));
    assert!(status.success(), "{}", String::from_utf8_lossy(&stderr));
    let (status, stdout, stderr) = Process::spawn(
        fixture.owner.path(),
        "built-binary",
        &mut command(target.join("debug/vendor_app")),
    )
    .wait(Duration::from_secs(5));
    assert!(status.success(), "{}", String::from_utf8_lossy(&stderr));
    assert_eq!(stdout, format!("42:{LABEL}\n").as_bytes());
    let image = capture_sealed_source(
        &[("workspace".into(), bundle.join("source"))],
        false,
        2,
        2_000_000,
    )
    .unwrap();
    assert_eq!(
        SourceUpload::for_request(Arc::new(image), "workspace", &request)
            .unwrap()
            .wire_manifest(),
        request["source_manifest"]
    );
    assert!(
        fs::read_dir(home)
            .unwrap()
            .all(|entry| entry.unwrap().file_name() != "credentials.toml")
    );
}

#[test]
fn corrupted_or_unapproved_vendor_inputs_never_publish_a_prepared_bundle() {
    for case in 0..4 {
        let mut fixture = Fixture::new();
        match case {
            0 => write(&fixture.anchor, "vendor/registry_dep/payload.txt", "99\n"),
            1 => write(
                &fixture.anchor,
                "vendor/registry_dep/unlisted.txt",
                "not approved by the checksum map",
            ),
            2 => {
                fixture.specification["cargo_source"]["vendor"] = json!("../outside");
            }
            _ => write(
                &fixture.anchor,
                ".cargo/config.toml",
                "[source.crates-io]\nreplace-with='vendor'\n[source.vendor]\ndirectory='/outside'\n",
            ),
        }
        let (bundle, status, stdout, stderr) = fixture.prepare("refused");
        assert!(!status.success(), "case {case}");
        assert!(stdout.is_empty());
        assert!(!bundle.exists());
        let error: Value = serde_json::from_slice(&stderr).unwrap();
        assert_eq!(error["kind"], "worker-prepare-failed");
        assert!(!String::from_utf8_lossy(&stderr).contains("worker-exec-listening"));
    }
}

#[test]
fn lock_mismatch_cannot_be_blessed_by_matching_vendor_file_hashes() {
    let fixture = Fixture::new();
    let path = fixture.anchor.join("Cargo.lock");
    let lock = fs::read_to_string(&path).unwrap();
    let actual = hash(b"generated fixture package registry_dep");
    fs::write(&path, lock.replace(&actual, &"00".repeat(32))).unwrap();
    let (bundle, status, stdout, _) = fixture.prepare("wrong-lock");
    assert!(!status.success());
    assert!(stdout.is_empty());
    assert!(!bundle.exists());
    assert!(
        fs::read_to_string(path).unwrap().contains(&"00".repeat(32)),
        "planning may not repair the original lock"
    );
}

#[test]
fn real_git_workspace_vendor_prepares_and_builds_without_original_repository_or_cache() {
    let (fixture, _) = Fixture::git();
    let original_lock = fs::read(fixture.anchor.join("Cargo.lock")).unwrap();
    let original_config = fs::read(fixture.anchor.join(".cargo/config.toml")).unwrap();
    let (bundle, request) = fixture.prepared();
    write(
        &fixture.anchor,
        "vendor/git_leaf-1.0.0/src/lib.rs",
        "pub fn answer() -> u32 { 99 }\n",
    );
    fs::rename(
        &fixture.anchor,
        fixture.owner.path().join("retired-checkout"),
    )
    .unwrap();
    let home = fixture.owner.path().join("empty-git-build-home");
    fs::create_dir(&home).unwrap();
    let target = fixture.owner.path().join("git-build-target");
    let mut cmd = command(&fixture.cargo);
    cmd.current_dir(bundle.join("source"))
        .args(["build", "--frozen", "--jobs=1", "-p", "vendor_app"])
        .arg("--target-dir")
        .arg(&target)
        .env("CARGO_HOME", &home)
        .env("CARGO_NET_OFFLINE", "true")
        .env("RUSTC", &fixture.rustc)
        .env("CARGO_INCREMENTAL", "0")
        .env("BUILD_LABEL", LABEL);
    let (status, _, stderr) = Process::spawn(fixture.owner.path(), "git-bundle-build", &mut cmd)
        .wait(Duration::from_secs(90));
    assert!(status.success(), "{}", String::from_utf8_lossy(&stderr));
    let (status, stdout, stderr) = Process::spawn(
        fixture.owner.path(),
        "git-bundle-binary",
        &mut command(target.join("debug/vendor_app")),
    )
    .wait(Duration::from_secs(5));
    assert!(status.success(), "{}", String::from_utf8_lossy(&stderr));
    assert_eq!(stdout, format!("42:{LABEL}\n").as_bytes());
    assert_eq!(
        fs::read(bundle.join("source/Cargo.lock")).unwrap(),
        original_lock
    );
    assert_eq!(
        fs::read(bundle.join("source/.cargo/config.toml")).unwrap(),
        original_config
    );
    assert!(
        !home.join("git").exists(),
        "the prepared build must not fetch Git sources"
    );
    assert!(
        !home.join("registry").exists(),
        "the fixture has no registry dependency"
    );
    let image = capture_sealed_source(
        &[("workspace".into(), bundle.join("source"))],
        false,
        2,
        2_000_000,
    )
    .unwrap();
    assert_eq!(
        SourceUpload::for_request(Arc::new(image), "workspace", &request)
            .unwrap()
            .wire_manifest(),
        request["source_manifest"]
    );
}

#[test]
fn real_git_vendor_refuses_changed_bytes_and_inconsistent_pinned_revision() {
    for case in 0..2 {
        let (fixture, revision) = Fixture::git();
        match case {
            0 => write(
                &fixture.anchor,
                "vendor/git_leaf-1.0.0/src/lib.rs",
                "pub fn answer() -> u32 { 99 }\n",
            ),
            _ => {
                let path = fixture.anchor.join("Cargo.lock");
                let lock = fs::read_to_string(&path).unwrap();
                let changed =
                    lock.replace(&format!("#{revision}"), &format!("#{}", "0".repeat(40)));
                assert_ne!(lock, changed);
                fs::write(path, changed).unwrap();
            }
        }
        let before = fs::read(fixture.anchor.join("Cargo.lock")).unwrap();
        let (bundle, status, stdout, stderr) = fixture.prepare("git-refused");
        assert!(
            !status.success(),
            "case {case}: {}",
            String::from_utf8_lossy(&stderr)
        );
        assert!(stdout.is_empty());
        assert!(!bundle.exists());
        let error: Value = serde_json::from_slice(&stderr).unwrap();
        assert_eq!(error["kind"], "worker-prepare-failed");
        assert_eq!(
            fs::read(fixture.anchor.join("Cargo.lock")).unwrap(),
            before,
            "preparation cannot repair captured lock evidence"
        );
    }
}

struct Certificates {
    server: rabs_asupersync::worker_transport::TlsFiles,
    worker: rabs_asupersync::worker_transport::TlsFiles,
}
impl Certificates {
    fn new(root: &Path) -> Self {
        let run = |args: &[&str]| {
            let mut cmd = command("openssl");
            cmd.current_dir(root).args(args);
            let (status, _, errors) =
                Process::spawn(root, "openssl", &mut cmd).wait(Duration::from_secs(15));
            assert!(status.success(), "{}", String::from_utf8_lossy(&errors));
        };
        run(&[
            "req",
            "-x509",
            "-newkey",
            "rsa:2048",
            "-nodes",
            "-sha256",
            "-days",
            "1",
            "-subj",
            "/CN=Vendor Test CA",
            "-keyout",
            "ca.key",
            "-out",
            "ca.pem",
            "-addext",
            "basicConstraints=critical,CA:TRUE",
            "-addext",
            "keyUsage=critical,keyCertSign,cRLSign",
        ]);
        for (name, usage, serial) in [("server", "serverAuth", "2"), ("worker", "clientAuth", "3")]
        {
            let key = format!("{name}.key");
            let csr = format!("{name}.csr");
            let cert = format!("{name}.pem");
            let ext = format!("{name}.ext");
            run(&[
                "req",
                "-new",
                "-newkey",
                "rsa:2048",
                "-nodes",
                "-sha256",
                "-subj",
                "/CN=localhost",
                "-keyout",
                &key,
                "-out",
                &csr,
            ]);
            fs::write(root.join(&ext), format!("basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage={usage}\nsubjectAltName=DNS:localhost\n")).unwrap();
            run(&[
                "x509",
                "-req",
                "-in",
                &csr,
                "-CA",
                "ca.pem",
                "-CAkey",
                "ca.key",
                "-set_serial",
                serial,
                "-days",
                "1",
                "-sha256",
                "-extfile",
                &ext,
                "-out",
                &cert,
            ]);
        }
        let files = |name: &str| rabs_asupersync::worker_transport::TlsFiles {
            ca: root.join("ca.pem"),
            certificate: root.join(format!("{name}.pem")),
            private_key: root.join(format!("{name}.key")),
        };
        Self {
            server: files("server"),
            worker: files("worker"),
        }
    }
}

#[test]
#[ignore = "requires canonical-capable Linux, OpenSSL and matching RABS_TEST_WORKER_BIN; run explicitly"]
fn automatic_vendored_bundle_builds_over_native_tls_and_replays_installed_outputs_offline() {
    let missing =
        rabs_sandbox::canonical_namespace::HostIsolationSupport::probe().missing_for_canonical();
    assert!(
        missing.is_empty(),
        "canonical isolation is required: {missing:?}"
    );
    let worker_binary = PathBuf::from(
        std::env::var_os("RABS_TEST_WORKER_BIN")
            .expect("set RABS_TEST_WORKER_BIN to the absolute rabs-wkr built from this revision"),
    );
    assert!(worker_binary.is_absolute() && worker_binary.is_file());
    let fixture = Fixture::new();
    let (bundle, request) = fixture.prepared();
    fs::rename(
        &fixture.anchor,
        fixture.owner.path().join("retired-checkout"),
    )
    .unwrap();
    let credentials = fixture.owner.path().join("credentials");
    fs::create_dir(&credentials).unwrap();
    let certificates = Certificates::new(&credentials);
    let identity = certificates.worker.local_identity().unwrap();
    let pin: String = identity
        .fingerprint
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    let delivery = fixture.owner.path().join("delivery");
    let installed = fixture.owner.path().join("installed");
    let args = ["--worker-build-tls", "127.0.0.1:0", WORKER, pin.as_str()];
    let mut receiver_command = command(env!("CARGO_BIN_EXE_rabsd"));
    receiver_command
        .args(args)
        .arg(&bundle)
        .arg(&delivery)
        .arg(&installed)
        .env(
            "RABS_STATE_DIR",
            fixture.owner.path().join("coordinator-state"),
        )
        .env("RABS_COORD_TLS_CA", &certificates.server.ca)
        .env("RABS_COORD_TLS_CERT", &certificates.server.certificate)
        .env("RABS_COORD_TLS_KEY", &certificates.server.private_key);
    let mut receiver = Process::spawn(fixture.owner.path(), "tls-receiver", &mut receiver_command);
    let address = receiver.listening();
    let state = fixture.owner.path().join("worker-state");
    let mut worker_command = command(worker_binary);
    worker_command
        .args(["--coordinator", &address, "--worker-id", WORKER, "--once"])
        .env("RABS_WORKER_STATE_DIR", &state)
        .env("RABS_WORKER_TLS_CA", &certificates.worker.ca)
        .env("RABS_WORKER_TLS_CERT", &certificates.worker.certificate)
        .env("RABS_WORKER_TLS_KEY", &certificates.worker.private_key)
        .env("RABS_WORKER_TLS_SERVER_NAME", "localhost");
    let mut worker = Process::spawn(fixture.owner.path(), "real-worker", &mut worker_command);
    let (status, stdout, stderr) = receiver.wait(Duration::from_secs(180));
    assert!(status.success(), "{}", String::from_utf8_lossy(&stderr));
    let (status, _, errors) = worker.wait(Duration::from_secs(20));
    assert!(status.success(), "{}", String::from_utf8_lossy(&errors));
    let report: Value = serde_json::from_slice(&stdout).unwrap();
    assert_eq!(report["kind"], "worker-build");
    assert_eq!(
        report["delivery"]["receipt"]["transport_authenticated"],
        true
    );
    assert_eq!(report["delivery"]["receipt"]["worker_spki_sha256"], pin);
    assert_eq!(report["delivery"]["receipt"]["exit_code"], 0);
    assert_eq!(report["delivery"]["acknowledgments_confirmed"], true);
    assert_eq!(report["publication_authorized"], false);
    assert!(!report["installed_outputs"].is_null());
    let (status, output, errors) = Process::spawn(
        fixture.owner.path(),
        "installed-binary",
        &mut command(installed.join("debug/vendor_app")),
    )
    .wait(Duration::from_secs(5));
    assert!(status.success(), "{}", String::from_utf8_lossy(&errors));
    assert_eq!(output, format!("42:{LABEL}\n").as_bytes());
    assert!(!state.join("retained-result").exists());
    let receipt = fs::read(delivery.join("delivery.json")).unwrap();
    fs::rename(
        bundle.join("source"),
        fixture.owner.path().join("retired-source"),
    )
    .unwrap();
    let mut offline = command(env!("CARGO_BIN_EXE_rabsd"));
    offline
        .args(args)
        .arg(&bundle)
        .arg(&delivery)
        .arg(&installed);
    let (status, output, errors) =
        Process::spawn(fixture.owner.path(), "offline-replay", &mut offline)
            .wait(Duration::from_secs(15));
    assert!(status.success(), "{}", String::from_utf8_lossy(&errors));
    assert!(!String::from_utf8_lossy(&errors).contains("worker-exec-listening"));
    let repeated: Value = serde_json::from_slice(&output).unwrap();
    assert_eq!(
        repeated["delivery"]["receipt"],
        report["delivery"]["receipt"]
    );
    assert_eq!(repeated["reexecute"], false);
    assert_eq!(fs::read(delivery.join("delivery.json")).unwrap(), receipt);
    assert_eq!(
        serde_json::from_slice::<Value>(&fs::read(bundle.join("request.json")).unwrap()).unwrap(),
        request
    );
}
