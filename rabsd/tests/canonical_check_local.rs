//! Native CLI boundary checks and an explicit controlled-host Cargo/cache test.
//! The ignored tests run the production namespace, wrapper, coordinator, CAS,
//! compiler and sampling policy. It never injects a cache row or substitutes a
//! fake namespace probe. Run it with `RABS_CANONICAL_TEST_WRAPPER=/abs/rabs-wrap`
//! on a Linux host permitting bubblewrap's full canonical namespace.
//! The remote test additionally needs matching `RABS_TEST_WORKER_BIN=/abs/rabs-wkr`
//! and OpenSSL; it creates real mutual TLS credentials and a loopback worker.
#![cfg(target_os = "linux")]

use rabs_asupersync::process_groups::ManagedProcessGroup;
use rabs_asupersync::region_tree::Attribution;
use rabs_asupersync::stream_drain::DrainLimits;
use rabs_asupersync::worker_transport::TlsFiles;
use rabs_sandbox::canonical_namespace::HostIsolationSupport;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io::{IsTerminal, Read, Write};
use std::net::TcpListener;
use std::os::unix::fs::{DirBuilderExt, MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

fn write(root: &Path, relative: &str, bytes: impl AsRef<[u8]>) {
    let path = root.join(relative);
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(path, bytes).unwrap();
}

fn sha(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn vendor(root: &Path, name: &str, files: BTreeMap<&str, &str>) -> String {
    let mut checksums = serde_json::Map::new();
    for (path, bytes) in files {
        write(root, &format!("vendor/{name}/{path}"), bytes);
        checksums.insert(path.to_owned(), json!(sha(bytes.as_bytes())));
    }
    // Synthetic directory-source metadata, not registry authenticity evidence.
    let package = sha(format!("canonical local fixture {name}").as_bytes());
    write(
        root,
        &format!("vendor/{name}/.cargo-checksum.json"),
        serde_json::to_vec(&json!({"package":package,"files":checksums})).unwrap(),
    );
    package
}

fn source(root: &Path, value: u32) {
    source_with_generated(root, value, false);
}

fn source_with_generated(root: &Path, value: u32, generated: bool) {
    write(
        root,
        "Cargo.toml",
        "[package]\nname='canonical_app'\nversion='0.1.0'\nedition='2021'\n[dependencies]\ncanonical_dep='=1.0.0'\noptional_build={path='optional-build',optional=true}\n[dev-dependencies]\ndev_macro={path='dev-macro'}\n",
    );
    write(
        root,
        "src/lib.rs",
        "pub fn answer()->u32 { canonical_dep::answer() }\n",
    );
    write(
        root,
        "src/main.rs",
        "fn main() { println!(\"{}\", canonical_app::answer()); }\n",
    );
    write(
        root,
        ".cargo/config.toml",
        "[source.crates-io]\nreplace-with='vendored-sources'\n[source.vendored-sources]\ndirectory='vendor'\n",
    );
    write(
        root,
        "optional-build/Cargo.toml",
        "[package]\nname='optional_build'\nversion='1.0.0'\nedition='2021'\n",
    );
    write(root, "optional-build/src/lib.rs", "pub fn unused() {}\n");
    write(
        root,
        "optional-build/build.rs",
        "fn main() { panic!(\"inactive build script must never execute\"); }\n",
    );
    write(
        root,
        "dev-macro/Cargo.toml",
        "[package]\nname='dev_macro'\nversion='1.0.0'\nedition='2021'\n[lib]\nproc-macro=true\n",
    );
    write(root, "dev-macro/src/lib.rs", "extern crate proc_macro;\n");
    let leaf_source = if generated {
        "const _: &str = env!(\"CANONICAL_BUILD_MARKER\");\ninclude!(concat!(env!(\"OUT_DIR\"), \"/value.rs\"));\n".to_owned()
    } else {
        format!("pub const fn answer()->u32 {{ {value} }}\n")
    };
    let mut leaf_files = BTreeMap::from([
        (
            "Cargo.toml",
            "[package]\nname='canonical_leaf'\nversion='1.0.0'\nedition='2021'\n",
        ),
        ("src/lib.rs", leaf_source.as_str()),
    ]);
    if generated {
        // Only Cargo's build script can read this workspace input. The remote
        // compiler receives the resulting OUT_DIR tree, not the outer workspace.
        // Editing this input leaves every vendored package byte unchanged.
        write(root, "generated-value.txt", value.to_string());
        leaf_files.insert(
            "build.rs",
            r#"fn main() {
    let value = std::fs::read_to_string("../../generated-value.txt").unwrap();
    let value: u32 = value.trim().parse().unwrap();
    let out = std::path::PathBuf::from(std::env::var_os("OUT_DIR").unwrap());
    std::fs::write(out.join("value.rs"), format!("pub const fn answer()->u32 {{ {value} }}\n")).unwrap();
    println!("cargo::rerun-if-changed=../../generated-value.txt");
    println!("cargo::rustc-env=CANONICAL_BUILD_MARKER=generated");
}
"#,
        );
    }
    let leaf = vendor(root, "canonical_leaf", leaf_files);
    let dep = vendor(
        root,
        "canonical_dep",
        BTreeMap::from([
            (
                "Cargo.toml",
                "[package]\nname='canonical_dep'\nversion='1.0.0'\nedition='2021'\n[dependencies]\ncanonical_leaf='=1.0.0'\n",
            ),
            (
                "src/lib.rs",
                "pub const fn answer()->u32 { canonical_leaf::answer()+2 }\n",
            ),
        ]),
    );
    write(
        root,
        "Cargo.lock",
        format!(
            "version=4\n\n[[package]]\nname='canonical_app'\nversion='0.1.0'\ndependencies=['canonical_dep','dev_macro','optional_build']\n\n[[package]]\nname='canonical_dep'\nversion='1.0.0'\nsource='registry+https://github.com/rust-lang/crates.io-index'\nchecksum='{dep}'\ndependencies=['canonical_leaf']\n\n[[package]]\nname='canonical_leaf'\nversion='1.0.0'\nsource='registry+https://github.com/rust-lang/crates.io-index'\nchecksum='{leaf}'\n\n[[package]]\nname='dev_macro'\nversion='1.0.0'\n\n[[package]]\nname='optional_build'\nversion='1.0.0'\n"
        ),
    );
}

fn generated_dependency(root: &Path) {
    write(root, "generated-value.txt", "2\n");
    vendor(
        root,
        "canonical_dep",
        BTreeMap::from([
            (
                "Cargo.toml",
                "[package]\nname='canonical_dep'\nversion='1.0.0'\nedition='2021'\n[dependencies]\ncanonical_leaf='=1.0.0'\n",
            ),
            (
                "build.rs",
                r#"fn main() {
    let package = std::path::PathBuf::from(std::env::var_os("CARGO_MANIFEST_DIR").unwrap());
    let input = package.parent().unwrap().parent().unwrap().join("generated-value.txt");
    let value: u32 = std::fs::read_to_string(&input).unwrap().trim().parse().unwrap();
    let output = std::path::PathBuf::from(std::env::var_os("OUT_DIR").unwrap());
    std::fs::write(output.join("generated.rs"), format!("const GENERATED_OFFSET: u32 = {value};\n")).unwrap();
    println!("cargo:rerun-if-changed={}", input.display());
}
"#,
            ),
            (
                "src/lib.rs",
                "include!(concat!(env!(\"OUT_DIR\"), \"/generated.rs\"));\npub const fn answer()->u32 { canonical_leaf::answer()+GENERATED_OFFSET }\n",
            ),
        ]),
    );
}

fn generated_native_dependency(root: &Path, leaf: bool) {
    // Keep generator intermediates in private TMPDIR: changing the workspace
    // value changes only the archive in the compiler's retained OUT_DIR, not
    // its Rust source, generated Rust, native search path or Cargo directives.
    write(
        root,
        "generated-value.txt",
        if leaf { "40\n" } else { "2\n" },
    );
    write(root, "generated-empty-name.txt", "before\n");
    vendor(
        root,
        if leaf {
            "canonical_leaf"
        } else {
            "canonical_dep"
        },
        BTreeMap::from([
            (
                "Cargo.toml",
                if leaf {
                    "[package]\nname='canonical_leaf'\nversion='1.0.0'\nedition='2021'\n"
                } else {
                    "[package]\nname='canonical_dep'\nversion='1.0.0'\nedition='2021'\n[dependencies]\ncanonical_leaf='=1.0.0'\n"
                },
            ),
            (
                "build.rs",
                r#"fn main() {
    let package = std::path::PathBuf::from(std::env::var_os("CARGO_MANIFEST_DIR").unwrap());
    let input = package.parent().unwrap().parent().unwrap().join("generated-value.txt");
    let value: u32 = std::fs::read_to_string(&input).unwrap().trim().parse().unwrap();
    let directory_input = package.parent().unwrap().parent().unwrap().join("generated-empty-name.txt");
    let directory_name = std::fs::read_to_string(&directory_input).unwrap();
    let output = std::path::PathBuf::from(std::env::var_os("OUT_DIR").unwrap()).join("native");
    let scratch = std::env::temp_dir().join("canonical-dependency-native-inputs");
    std::fs::create_dir_all(&output).unwrap();
    std::fs::create_dir_all(output.join("empty").join(directory_name.trim())).unwrap();
    std::fs::create_dir_all(&scratch).unwrap();
    std::fs::write(scratch.join("answer.c"), format!("unsigned int rabs_native_answer(void) {{ return {value}; }}\n")).unwrap();
    assert!(std::process::Command::new("/usr/bin/cc")
        .args(["-c", "-fPIC", "-o"])
        .arg(scratch.join("answer.o")).arg(scratch.join("answer.c"))
        .status().unwrap().success());
    assert!(std::process::Command::new("/usr/bin/ar")
        .arg("crsD").arg(output.join("librabs_answer.a")).arg(scratch.join("answer.o"))
        .status().unwrap().success());
    println!("cargo:rerun-if-changed={}", input.display());
    println!("cargo:rerun-if-changed={}", directory_input.display());
    println!("cargo:rustc-link-search=native={}", output.display());
    println!("cargo:rustc-link-lib=static=rabs_answer");
}
"#,
            ),
            (
                "src/lib.rs",
                if leaf {
                    "extern \"C\" { fn rabs_native_answer() -> u32; }\npub fn answer()->u32 { unsafe { rabs_native_answer() } }\n"
                } else {
                    "extern \"C\" { fn rabs_native_answer() -> u32; }\npub fn answer()->u32 { canonical_leaf::answer() + unsafe { rabs_native_answer() } }\n"
                },
            ),
        ]),
    );
    if leaf {
        // Cargo propagates the leaf's native search path through this middle
        // dependency. It has neither a build script nor an OUT_DIR of its own,
        // so successful worker execution requires the foreign generated root.
        vendor(
            root,
            "canonical_dep",
            BTreeMap::from([
                (
                    "Cargo.toml",
                    "[package]\nname='canonical_dep'\nversion='1.0.0'\nedition='2021'\n[dependencies]\ncanonical_leaf='=1.0.0'\n",
                ),
                (
                    "src/lib.rs",
                    "pub fn answer()->u32 { canonical_leaf::answer()+2 }\n",
                ),
            ]),
        );
    }
}

fn generated_native_workspace(root: &Path) {
    workspace_execution_feature(root);
    write(root, "workspace-native-value.txt", "1\n");
    write(root, "workspace-native-kind.txt", "static\n");
    write(
        root,
        "build.rs",
        r#"fn main() {
    let package = std::path::PathBuf::from(std::env::var_os("CARGO_MANIFEST_DIR").unwrap());
    let input = package.join("workspace-native-value.txt");
    let value: u32 = std::fs::read_to_string(&input).unwrap().trim().parse().unwrap();
    let kind_input = package.join("workspace-native-kind.txt");
    let kind = std::fs::read_to_string(&kind_input).unwrap();
    let output = std::path::PathBuf::from(std::env::var_os("OUT_DIR").unwrap()).join("native");
    std::fs::create_dir_all(&output).unwrap();
    std::fs::write(output.join("answer.c"), format!("unsigned int rabs_workspace_native_answer(void) {{ return {value}; }}\n")).unwrap();
    assert!(std::process::Command::new("/usr/bin/cc")
        .args(["-c", "-fPIC", "-o"])
        .arg(output.join("answer.o")).arg(output.join("answer.c"))
        .status().unwrap().success());
    assert!(std::process::Command::new("/usr/bin/ar")
        .arg("crsD").arg(output.join("librabs_workspace_answer.a")).arg(output.join("answer.o"))
        .status().unwrap().success());
    println!("cargo:rerun-if-changed={}", input.display());
    println!("cargo:rerun-if-changed={}", kind_input.display());
    println!("cargo:rustc-link-search=native={}", output.display());
    println!("cargo:rustc-link-lib={}=rabs_workspace_answer", kind.trim());
    println!("cargo:rustc-env=WORKSPACE_NATIVE_EXPECTED={}", 42 + value);
}
"#,
    );
    write(
        root,
        "src/lib.rs",
        "#[cfg(not(feature=\"remote_workspace\"))]\ncompile_error!(\"selected workspace feature was lost\");\nconst _: &str = env!(\"CARGO_PRIMARY_PACKAGE\");\nconst _: &str = include_str!(\"../workspace-readme.txt\");\nextern \"C\" { fn rabs_workspace_native_answer() -> u32; }\npub fn answer()->u32 { canonical_dep::answer() + unsafe { rabs_workspace_native_answer() } }\n",
    );
    // FFI cannot be checked in a const expression. Execute the delivered
    // binary and compare against both Cargo's generated expectation and the
    // test's independent expected value after each real worker completion.
    write(
        root,
        "src/main.rs",
        "fn main() { let answer = canonical_app::answer(); assert_eq!(answer, env!(\"WORKSPACE_NATIVE_EXPECTED\").parse::<u32>().unwrap()); println!(\"{answer}\"); }\n",
    );
}

fn run(root: &Path, number: u32, profile: &Value) -> (i32, Vec<Value>, String) {
    run_with_environment(root, number, profile, &[])
}

fn run_with_environment(
    root: &Path,
    number: u32,
    profile: &Value,
    environment: &[(String, String)],
) -> (i32, Vec<Value>, String) {
    run_with_stdin(root, number, profile, environment, Stdio::null())
}

fn run_with_input(
    root: &Path,
    number: u32,
    profile: &Value,
    environment: &[(String, String)],
    input: &[u8],
) -> (i32, Vec<Value>, String) {
    // Keep this fixture write below PIPE_BUF so it cannot block before the
    // child starts. EOF follows the exact input bytes through the real pipe.
    assert!(input.len() <= 4096);
    let (reader, writer) = rustix::pipe::pipe_with(rustix::pipe::PipeFlags::CLOEXEC).unwrap();
    fs::File::from(writer).write_all(input).unwrap();
    run_with_stdin(root, number, profile, environment, Stdio::from(reader))
}

fn run_with_stdin(
    root: &Path,
    number: u32,
    profile: &Value,
    environment: &[(String, String)],
    stdin: Stdio,
) -> (i32, Vec<Value>, String) {
    let path = root.join(format!("profile-{number}.json"));
    fs::write(&path, serde_json::to_vec(profile).unwrap()).unwrap();
    let mut command = Command::new(env!("CARGO_BIN_EXE_rabsd"));
    command
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env("RABS_CONFIG", root.join("config.toml"))
        .env("RABS_SPRT_SAMPLING", "0")
        .envs(environment.iter().map(|(name, value)| (name, value)))
        .args(["--canonical-compile-local"])
        .arg(path)
        .stdin(stdin)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    // No ambient compiler, wrapper, loader flags or daemon socket survives.
    // The production driver independently enforces the same environment split.
    let started = Instant::now();
    let process = ManagedProcessGroup::spawn_command(command, Attribution::default()).unwrap();
    let output = process
        .wait_with_bounded_drain_budget(
            &DrainLimits::new(root.join(format!("drain-{number}"))),
            64 * 1024 * 1024,
            || started.elapsed() > Duration::from_secs(600),
        )
        .unwrap();
    assert!(
        started.elapsed() < Duration::from_secs(600),
        "canonical compilation timed out"
    );
    assert_eq!(output.residual_group_members, 0);
    let mut stderr = String::new();
    output
        .stderr
        .reader()
        .unwrap()
        .read_to_string(&mut stderr)
        .unwrap();
    let mut stdout = String::new();
    output
        .stdout
        .reader()
        .unwrap()
        .read_to_string(&mut stdout)
        .unwrap();
    let events = stderr
        .lines()
        .filter_map(|line| serde_json::from_str::<Value>(line).ok())
        .collect();
    (
        output.status.code().unwrap_or(-1),
        events,
        format!("stdout:\n{stdout}\nstderr:\n{stderr}"),
    )
}

#[test]
fn cli_rejects_profile_environment_instead_of_granting_an_ambient_mount_capability() {
    let root = tempfile::tempdir().unwrap();
    fs::write(root.path().join("config.toml"), "[rabs]\n").unwrap();
    let profile = json!({"version":"canonical-compile-local-v1", "source_root":"/source",
        "toolchain_root":"/toolchain", "state_root":"/state", "operation_root":"/operations",
        "wrapper":"/rabs-wrap", "env":{"RABS_SOCKET_PATH":"/ordinary-daemon.sock"}});
    let (code, _, output) = run(root.path(), 0, &profile);
    assert_eq!(code, 2, "{output}");
    assert!(output.contains("unknown field `env`"), "{output}");
    assert!(!output.contains("canonical-compilation-started"));
}

#[test]
fn cli_refuses_executing_run_and_bench_terminal_input_before_touching_profile_roots() {
    use rustix::pty::{OpenptFlags, ioctl_tiocgptpeer, openpt, unlockpt};

    let root = tempfile::tempdir().unwrap();
    fs::write(root.path().join("config.toml"), "[rabs]\n").unwrap();
    let flags = OpenptFlags::RDWR | OpenptFlags::NOCTTY | OpenptFlags::CLOEXEC;
    let terminal = openpt(flags).unwrap();
    unlockpt(&terminal).unwrap();
    for (number, command, selection, refused) in [
        (0, "run", json!({"run_args":["--no-run"]}), true),
        (1, "bench", json!({"test_args":["--no-run"]}), true),
        (2, "bench", json!({"no_run":true}), false),
    ] {
        // None of these paths exists. A terminal refusal must happen before
        // source validation/capture, namespace probes, or operation allocation.
        let profile = json!({"version":"canonical-compile-local-v1", "command":command,
            "source_root":root.path().join("missing-source"),
            "toolchain_root":root.path().join("missing-toolchain"),
            "state_root":root.path().join("missing-state"),
            "operation_root":root.path().join("missing-operations"),
            "wrapper":root.path().join("missing-wrapper"), "selection":selection});
        let stdin = fs::File::from(ioctl_tiocgptpeer(&terminal, flags).unwrap());
        assert!(stdin.is_terminal(), "the fixture must use an actual PTY");
        let (code, events, output) =
            run_with_stdin(root.path(), number, &profile, &[], Stdio::from(stdin));
        assert_eq!(code, if refused { 2 } else { 1 }, "{output}");
        assert_eq!(
            output.contains("canonical run/bench requires nonterminal stdin"),
            refused,
            "{output}"
        );
        if refused {
            assert!(output.contains("/dev/null"), "{output}");
            assert!(output.contains("delivered build"), "{output}");
        } else {
            assert!(output.contains("No such file or directory"), "{output}");
        }
        assert!(events.is_empty(), "{output}");
        assert!(
            !output.contains("canonical-compilation-started"),
            "{output}"
        );
        for path in ["missing-source", "missing-state", "missing-operations"] {
            assert!(!root.path().join(path).exists(), "{output}");
        }

        // The same executing profiles accept an actual pipe and reach normal
        // source validation. Full Cargo execution checks the byte stream below.
        let (code, _, output) =
            run_with_input(root.path(), number + 10, &profile, &[], b"piped input\n");
        assert_eq!(code, 1, "{output}");
        assert!(output.contains("No such file or directory"), "{output}");
        assert!(!output.contains("requires nonterminal stdin"), "{output}");
    }
}

fn decisions(events: &[Value], decision: &str) -> BTreeMap<String, String> {
    events
        .iter()
        .filter(|event| event["kind"] == "rabsd-live-dependency" && event["decision"] == decision)
        .filter_map(|event| {
            Some((
                event["crate"].as_str()?.to_owned(),
                event["key"].as_str()?.to_owned(),
            ))
        })
        .collect()
}

fn native_fixture() -> (tempfile::TempDir, Value) {
    let support = HostIsolationSupport::probe();
    assert!(
        support.missing_for_canonical().is_empty(),
        "measured host support: {support:?}"
    );
    let wrapper = fs::canonicalize(
        std::env::var_os("RABS_CANONICAL_TEST_WRAPPER")
            .expect("set RABS_CANONICAL_TEST_WRAPPER to the freshly built native rabs-wrap"),
    )
    .unwrap();
    let cargo =
        fs::canonicalize(std::env::var_os("CARGO").expect("Cargo test runner executable")).unwrap();
    let toolchain = cargo.parent().and_then(Path::parent).unwrap();
    assert!(
        toolchain.join("bin/rustc").is_file(),
        "a complete native toolchain is required"
    );
    let owner = tempfile::Builder::new()
        .prefix("rabs-canon-")
        .tempdir_in("/tmp")
        .unwrap();
    fs::set_permissions(owner.path(), fs::Permissions::from_mode(0o700)).unwrap();
    for name in ["source-a", "source-b", "state", "ops"] {
        fs::DirBuilder::new()
            .mode(0o700)
            .create(owner.path().join(name))
            .unwrap();
    }
    fs::write(
        owner.path().join("config.toml"),
        "[rabs]\nrelease_authorization='advisory'\n",
    )
    .unwrap();
    let first = owner.path().join("source-a");
    let second = owner.path().join("source-b");
    source(&first, 40);
    source(&second, 40);
    let profile = json!({"version":"canonical-compile-local-v1", "source_root":first,
        "toolchain_root":toolchain, "state_root":owner.path().join("state"),
        "operation_root":owner.path().join("ops"), "wrapper":wrapper, "vendor":"vendor",
        "jobs":1, "timeout_seconds":300});
    (owner, profile)
}

/// Native service/client processes keep diagnostics in ordinary files so two
/// simultaneous Cargo roots cannot block on an undrained test-harness pipe.
struct SharedServiceChild {
    process: Option<ManagedProcessGroup>,
    stdout: PathBuf,
    stderr: PathBuf,
    drain: PathBuf,
}

impl SharedServiceChild {
    fn spawn(root: &Path, name: &str, mut command: Command) -> Self {
        let stdout = root.join(format!("{name}.stdout"));
        let stderr = root.join(format!("{name}.stderr"));
        command
            .stdin(Stdio::null())
            .stdout(fs::File::create(&stdout).unwrap())
            .stderr(fs::File::create(&stderr).unwrap());
        Self {
            process: Some(
                ManagedProcessGroup::spawn_command(command, Attribution::default()).unwrap(),
            ),
            stdout,
            stderr,
            drain: root.join(format!("{name}-drain")),
        }
    }

    fn diagnostics(&self) -> String {
        format!(
            "stdout:\n{}\nstderr:\n{}",
            String::from_utf8_lossy(&read_bounded(&self.stdout)),
            String::from_utf8_lossy(&read_bounded(&self.stderr))
        )
    }

    fn events(&self) -> Vec<Value> {
        String::from_utf8(read_bounded(&self.stderr))
            .unwrap()
            .lines()
            .filter_map(|line| serde_json::from_str(line).ok())
            .collect()
    }

    fn assert_running(&mut self) {
        assert!(
            self.process
                .as_mut()
                .unwrap()
                .leader_try_wait()
                .unwrap()
                .is_none(),
            "native service/client exited before its owned operation completed: {}",
            self.diagnostics()
        );
    }

    fn finish(mut self, budget: Duration, cancel: bool) -> (i32, Vec<Value>, String) {
        let started = Instant::now();
        let output = self
            .process
            .take()
            .unwrap()
            .wait_with_bounded_drain_budget(&DrainLimits::new(&self.drain), 0, || {
                cancel || started.elapsed() >= budget
            })
            .unwrap();
        assert_eq!(output.residual_group_members, 0);
        assert!(
            cancel || started.elapsed() < budget,
            "native service/client exceeded its budget: {}",
            self.diagnostics()
        );
        (
            output.status.code().unwrap_or(-1),
            self.events(),
            self.diagnostics(),
        )
    }
}

impl Drop for SharedServiceChild {
    fn drop(&mut self) {
        if let Some(process) = self.process.take() {
            let _ =
                process.wait_with_bounded_drain_budget(&DrainLimits::new(&self.drain), 0, || true);
        }
    }
}

fn shared_service_command(root: &Path) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_rabsd"));
    command
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env("RABS_CONFIG", root.join("config.toml"))
        .env("RABS_SPRT_SAMPLING", "0");
    command
}

fn shared_service_client(root: &Path, number: u32, profile: &Value) -> SharedServiceChild {
    let path = root.join(format!("shared-profile-{number}.json"));
    fs::write(&path, serde_json::to_vec(profile).unwrap()).unwrap();
    let mut command = shared_service_command(root);
    command.arg("--canonical-compile-local").arg(path);
    SharedServiceChild::spawn(root, &format!("shared-client-{number}"), command)
}

fn shared_service_source(root: &Path, label: &str, value: u32) {
    write(root, "service-label.txt", label);
    write(root, "service-value.txt", value.to_string());
    write(
        root,
        "build.rs",
        r#"fn main() {
    let label = std::fs::read_to_string("service-label.txt").unwrap();
    let value: u32 = std::fs::read_to_string("service-value.txt").unwrap().trim().parse().unwrap();
    let out = std::path::PathBuf::from(std::env::var_os("OUT_DIR").unwrap());
    std::fs::write(out.join("shared-service-ready"), label.trim()).unwrap();
    println!("cargo::warning=SERVICE_DIAGNOSTIC_{}_ONLY", label.trim());
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(240);
    while !out.join("shared-service-release").is_file() {
        assert!(std::time::Instant::now() < deadline, "shared service fixture was never released");
        std::thread::sleep(std::time::Duration::from_millis(20));
    }
    std::fs::write(out.join("service-value.rs"), format!("const SERVICE_VALUE: u32 = {value};\n")).unwrap();
    println!("cargo::rustc-env=SERVICE_LABEL={}", label.trim());
    println!("cargo::rerun-if-changed=service-label.txt");
    println!("cargo::rerun-if-changed=service-value.txt");
}
"#,
    );
    write(
        root,
        "src/lib.rs",
        "include!(concat!(env!(\"OUT_DIR\"), \"/service-value.rs\"));\npub fn answer()->u32 { canonical_dep::answer()+SERVICE_VALUE }\n",
    );
    write(
        root,
        "src/main.rs",
        "fn main() { println!(\"{}:{}\", env!(\"SERVICE_LABEL\"), canonical_app::answer()); }\n",
    );
}

/// Inspect only active private Cargo targets. Delivered targets and captured
/// toolchains are excluded; Cargo's per-unit directory layout is not guessed.
fn shared_service_markers(operations: &Path, label: &str) -> Vec<PathBuf> {
    let mut pending = Vec::new();
    for entry in fs::read_dir(operations).unwrap() {
        let entry = entry.unwrap();
        if entry
            .file_name()
            .to_str()
            .is_some_and(|name| name.starts_with("rabs-compile-"))
        {
            for target in ["target", "restored-target"] {
                let path = entry.path().join(target);
                if fs::symlink_metadata(&path).is_ok_and(|metadata| metadata.is_dir()) {
                    pending.push(path);
                }
            }
        }
    }
    let mut markers = Vec::new();
    let mut visited = 0;
    while let Some(directory) = pending.pop() {
        let entries = match fs::read_dir(&directory) {
            Ok(entries) => entries,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(error) => panic!("reading {}: {error}", directory.display()),
        };
        for entry in entries {
            let entry = match entry {
                Ok(entry) => entry,
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
                Err(error) => panic!("reading {}: {error}", directory.display()),
            };
            visited += 1;
            assert!(visited <= 20_000, "unexpectedly large Cargo fixture target");
            let file_type = match entry.file_type() {
                Ok(file_type) => file_type,
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
                Err(error) => panic!("reading {}: {error}", entry.path().display()),
            };
            if file_type.is_dir() {
                pending.push(entry.path());
            } else if file_type.is_file()
                && entry.file_name() == "shared-service-ready"
                && fs::read(entry.path()).is_ok_and(|bytes| bytes == label.as_bytes())
            {
                markers.push(entry.path());
            }
        }
    }
    markers
}

fn wait_for_shared_service_marker(
    operations: &Path,
    label: &str,
    service: &mut SharedServiceChild,
    client: &mut SharedServiceChild,
) -> PathBuf {
    let deadline = Instant::now() + Duration::from_secs(150);
    loop {
        service.assert_running();
        client.assert_running();
        let markers = shared_service_markers(operations, label);
        assert!(
            markers.len() <= 1,
            "ambiguous active {label} build: {markers:?}"
        );
        if let Some(marker) = markers.into_iter().next() {
            return marker;
        }
        assert!(
            Instant::now() < deadline,
            "actual Cargo build script never reached its synchronization point: {}\n{}",
            client.diagnostics(),
            service.diagnostics()
        );
        std::thread::sleep(Duration::from_millis(20));
    }
}

fn assert_shared_service_build(
    root: &Path,
    number: u32,
    events: &[Value],
    output: &str,
    expected: &str,
    target_state: &str,
) -> PathBuf {
    let started = events
        .iter()
        .filter(|event| event["kind"] == "canonical-compilation-started")
        .collect::<Vec<_>>();
    assert_eq!(started.len(), 1, "{output}");
    assert_eq!(started[0]["private_target_state"], target_state, "{output}");
    let completed = events
        .iter()
        .filter(|event| event["kind"] == "canonical-build-completed")
        .collect::<Vec<_>>();
    assert_eq!(completed.len(), 1, "{output}");
    let target = PathBuf::from(completed[0]["target_directory"].as_str().unwrap());
    assert_eq!(target.file_name().unwrap(), "target");
    assert_eq!(target.parent().unwrap().parent().unwrap(), root.join("ops"));
    let executables = output
        .lines()
        .filter_map(|line| serde_json::from_str::<Value>(line).ok())
        .filter(|event| event["reason"] == "compiler-artifact")
        .filter_map(|event| event["executable"].as_str().map(PathBuf::from))
        .collect::<BTreeSet<_>>();
    let binary = executables
        .into_iter()
        .filter(|path| path.file_name().is_some_and(|name| name == "canonical_app"))
        .collect::<Vec<_>>();
    assert_eq!(
        binary.len(),
        1,
        "Cargo must name one actual linked application: {output}"
    );
    let relative = binary[0].strip_prefix("/__rabs/out/cargo").unwrap();
    assert!(
        relative
            .components()
            .all(|part| matches!(part, std::path::Component::Normal(_)))
    );
    let binary = target.join(relative);
    assert_eq!(fs::canonicalize(&binary).unwrap(), binary);
    let mut command = Command::new(&binary);
    command
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .current_dir(root);
    let process = SharedServiceChild::spawn(root, &format!("shared-binary-{number}"), command);
    let stdout = process.stdout.clone();
    let stderr = process.stderr.clone();
    let (code, _, diagnostics) = process.finish(Duration::from_secs(10), false);
    assert_eq!(code, 0, "{diagnostics}");
    assert_eq!(read_bounded(&stdout), expected.as_bytes(), "{diagnostics}");
    assert!(read_bounded(&stderr).is_empty(), "{diagnostics}");
    target
}

fn retained_service_toolchains(state: &Path) -> Vec<(PathBuf, u64, u64)> {
    let mut images = fs::read_dir(state.join("canonical-compile-v1"))
        .unwrap()
        .map(Result::unwrap)
        .filter(|entry| {
            entry
                .file_name()
                .as_encoded_bytes()
                .starts_with(b"retained-toolchain-")
        })
        .map(|entry| {
            assert!(entry.file_type().unwrap().is_dir());
            let tree = entry.path().join("tree");
            let compiler = fs::symlink_metadata(tree.join("bin/rustc")).unwrap();
            assert!(compiler.is_file());
            (tree, compiler.dev(), compiler.ino())
        })
        .collect::<Vec<_>>();
    images.sort();
    images
}

/// Pause only the actual worker process, never substitute its executor or
/// result. Resume before native fixture owners drain, including on assertion
/// failure. The caller verifies this fresh worker has not reached execution.
struct PausedNativeWorker(rustix::process::Pid);

impl PausedNativeWorker {
    fn pause(worker: &NativeWorker) -> Self {
        let pid = worker.process.as_ref().unwrap().pgid();
        let pid = rustix::process::Pid::from_raw(i32::try_from(pid).unwrap()).unwrap();
        rustix::process::kill_process(pid, rustix::process::Signal::STOP).unwrap();
        let paused = Self(pid);
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            let status = fs::read_to_string(format!("/proc/{}/status", pid.as_raw_pid())).unwrap();
            if status.lines().any(|line| {
                line.starts_with("State:") && line.split_whitespace().nth(1) == Some("T")
            }) {
                return paused;
            }
            assert!(Instant::now() < deadline, "native worker did not stop");
            std::thread::sleep(Duration::from_millis(2));
        }
    }
}

impl Drop for PausedNativeWorker {
    fn drop(&mut self) {
        if rustix::process::kill_process(self.0, rustix::process::Signal::CONT).is_err() {
            // NativeWorker still owns reaping if resumption was refused.
            let _ = rustix::process::kill_process(self.0, rustix::process::Signal::KILL);
        }
    }
}

fn shared_remote_operation(operations: &Path, label: &str) -> PathBuf {
    let owners = fs::read_dir(operations)
        .unwrap()
        .map(Result::unwrap)
        .filter(|entry| entry.file_type().unwrap().is_dir())
        .map(|entry| entry.path())
        .filter(|path| {
            fs::read(path.join("bundle/source/shared-flight-label.txt"))
                .is_ok_and(|bytes| bytes == label.as_bytes())
        })
        .collect::<Vec<_>>();
    assert_eq!(owners.len(), 1, "missing unique {label} source owner");
    owners.into_iter().next().unwrap()
}

fn shared_remote_source(root: &Path, label: &str, value: u32) {
    source(root, value);
    write(root, "shared-flight-label.txt", label);
    write(
        root,
        "src/main.rs",
        "fn main() { println!(\"{}:{}\", include_str!(\"../shared-flight-label.txt\"), canonical_app::answer()); }\n",
    );
}

#[test]
#[ignore = "requires full Linux bubblewrap isolation, OpenSSL, matching RABS_CANONICAL_TEST_WRAPPER and RABS_TEST_WORKER_BIN; actual concurrent canonical Cargo clients, shared TLS compiler execution and origin cancellation"]
fn canonical_shared_remote_flight_survives_origin_cancellation() {
    let (owner, mut first_profile) = native_fixture();
    let root = owner.path();
    for (source, label) in [("source-a", "origin"), ("source-b", "survivor")] {
        shared_remote_source(&root.join(source), label, 40);
    }
    let (mut worker, environment) = NativeWorker::start(root);
    let socket = root.join("canonical-service.sock");
    let service_profile = root.join("shared-remote-service.json");
    fs::write(
        &service_profile,
        serde_json::to_vec(&json!({
            "version":"canonical-compile-service-v1", "state_root":root.join("state"),
            "socket":socket, "max_roots":2, "jobs_per_root":1,
        }))
        .unwrap(),
    )
    .unwrap();
    first_profile["command"] = json!("build");
    first_profile["service_socket"] = json!(socket);
    let mut second_profile = first_profile.clone();
    second_profile["source_root"] = json!(root.join("source-b"));
    let mut command = shared_service_command(root);
    command
        .envs(environment.iter().map(|(name, value)| (name, value)))
        .arg("--canonical-compile-service")
        .arg(service_profile);
    let mut service = SharedServiceChild::spawn(root, "shared-remote-service", command);
    let service_pid = service.process.as_ref().unwrap().pgid();
    let deadline = Instant::now() + Duration::from_secs(60);
    while !socket.exists()
        || !service
            .events()
            .iter()
            .any(|event| event["kind"] == "canonical-service-listening")
    {
        service.assert_running();
        assert!(Instant::now() < deadline, "{}", service.diagnostics());
        std::thread::sleep(Duration::from_millis(10));
    }

    let mut first = shared_service_client(root, 5100, &first_profile);
    let deadline = Instant::now() + Duration::from_secs(240);
    let key = loop {
        let events = service.events();
        let offered = decisions(&events, "shared-remote-offer");
        if let Some(key) = offered.get("canonical_leaf")
            && events.iter().any(|event| {
                event["kind"] == "rabsd-remote-dependency-admitted" && event["key"] == *key
            })
        {
            break key.clone();
        }
        service.assert_running();
        first.assert_running();
        assert!(Instant::now() < deadline, "{}", service.diagnostics());
        std::thread::sleep(Duration::from_millis(2));
    };
    let paused = PausedNativeWorker::pause(&worker);
    // The worker durably records an execution before launching its lease or
    // compiler. Read that real journal while the process is stopped: absence
    // of a compiler-acquisition log alone cannot rule out an expiring lease.
    let journal: Value =
        serde_json::from_slice(&read_bounded(&worker.state.join("requests.json"))).unwrap();
    assert!(
        journal.get("last").is_some_and(Value::is_null),
        "worker passed the required pre-execution pause boundary: {journal}"
    );
    // This fresh worker is still transferring inputs. Never waive the durable
    // admission check or manufacture a completed result to arrange overlap.
    assert!(
        !worker
            .events()
            .iter()
            .any(|event| event["kind"] == "worker-toolchain-acquired"),
        "worker passed the required pre-execution pause boundary"
    );
    let origin = shared_remote_operation(&root.join("ops"), "origin");
    let mut second = shared_service_client(root, 5101, &second_profile);
    let deadline = Instant::now() + Duration::from_secs(90);
    loop {
        let joined = service
            .events()
            .iter()
            .filter(|event| {
                event["kind"] == "rabsd-shared-remote-subscribed" && event["key"] == key
            })
            .count();
        if joined == 2 {
            break;
        }
        assert!(
            joined < 2,
            "one client subscribed to the same active action twice"
        );
        service.assert_running();
        first.assert_running();
        second.assert_running();
        assert!(Instant::now() < deadline, "{}", service.diagnostics());
        std::thread::sleep(Duration::from_millis(5));
    }
    let survivor = shared_remote_operation(&root.join("ops"), "survivor");
    assert_ne!(origin, survivor);
    let (code, events, output) = first.finish(Duration::from_secs(15), true);
    assert_ne!(code, 0, "{output}");
    assert!(
        !events
            .iter()
            .any(|event| event["kind"] == "canonical-build-completed")
    );
    let deadline = Instant::now() + Duration::from_secs(30);
    while !service.events().iter().any(|event| {
        event["kind"] == "canonical-service-session-error"
            && event["reason"].as_str().is_some_and(|reason| {
                reason.contains("canonical client disconnected; its operation was drained")
            })
    }) {
        service.assert_running();
        second.assert_running();
        assert!(
            Instant::now() < deadline,
            "origin did not drain independently of shared execution: {}",
            service.diagnostics()
        );
        std::thread::sleep(Duration::from_millis(5));
    }
    // The initiating operation has returned, but its actual captured source
    // must remain until the service-owned producer no longer reads it.
    assert_eq!(
        read_bounded(&origin.join("bundle/source/shared-flight-label.txt")),
        b"origin"
    );
    assert_eq!(service.process.as_ref().unwrap().pgid(), service_pid);
    second.assert_running();
    drop(paused);

    let (code, events, output) = second.finish(Duration::from_secs(240), false);
    assert_eq!(code, 0, "{output}\n{}", service.diagnostics());
    let target =
        assert_shared_service_build(root, 5101, &events, &output, "survivor:42\n", "disabled");
    assert_ne!(target, origin.join("target"));
    let receipt = worker.completed_receipt();
    let current = service.events();
    for kind in [
        "rabsd-remote-dependency-admitted",
        "rabsd-remote-dependency-executed",
    ] {
        assert_eq!(
            current
                .iter()
                .filter(|event| event["kind"] == kind && event["key"] == key)
                .count(),
            1,
            "one real producer and only the surviving destination may complete: {current:?}"
        );
    }
    assert!(
        !current.iter().any(|event| {
            event["key"] == key
                && (matches!(
                    event["kind"].as_str(),
                    Some(
                        "rabsd-remote-dependency-failed" | "rabsd-remote-dependency-install-failed"
                    )
                ) || (event["kind"] == "rabsd-live-dependency"
                    && matches!(
                        event["decision"].as_str(),
                        Some("execute" | "hit" | "served")
                    )))
        }),
        "fallback or replay must not satisfy the shared producer: {current:?}"
    );
    assert!(
        !origin.exists(),
        "finished producer retained its departed origin"
    );
    assert!(
        !survivor.exists(),
        "delivered target retained its operation owner"
    );

    // This was only the initial publication. A later cold target must acquire
    // fresh verification through a new producer, even though the service lives.
    let later = shared_service_client(root, 5102, &second_profile);
    let (code, events, output) = later.finish(Duration::from_secs(240), false);
    assert_eq!(code, 0, "{output}\n{}", service.diagnostics());
    let later_target =
        assert_shared_service_build(root, 5102, &events, &output, "survivor:42\n", "disabled");
    assert_ne!(target, later_target);
    assert_eq!(
        service
            .events()
            .iter()
            .filter(|event| {
                event["kind"] == "rabsd-remote-dependency-admitted" && event["key"] == key
            })
            .count(),
        2,
        "a terminal cohort bypassed fresh verification or split its action key"
    );
    assert!(
        worker.completed_receipt()["request_id"].as_u64().unwrap()
            > receipt["request_id"].as_u64().unwrap()
    );
    service.finish(Duration::from_secs(15), true);
    worker.finish();
}

#[test]
#[ignore = "requires full Linux bubblewrap isolation, OpenSSL, matching RABS_CANONICAL_TEST_WRAPPER and RABS_TEST_WORKER_BIN; queues distinct actual Cargo actions behind a busy authenticated worker"]
fn canonical_shared_remote_queue_coalesces_and_survives_origin_cancellation() {
    let (owner, mut first_profile) = native_fixture();
    let root = owner.path();
    fs::DirBuilder::new()
        .mode(0o700)
        .create(root.join("source-c"))
        .unwrap();
    for (directory, label, value) in [
        ("source-a", "running", 40),
        ("source-b", "queued-origin", 80),
        ("source-c", "queued-survivor", 80),
    ] {
        shared_remote_source(&root.join(directory), label, value);
    }
    let (mut worker, environment) = NativeWorker::start(root);
    let socket = root.join("canonical-service.sock");
    let service_profile = root.join("shared-queue-service.json");
    fs::write(
        &service_profile,
        serde_json::to_vec(&json!({
            "version":"canonical-compile-service-v1", "state_root":root.join("state"),
            "socket":socket, "max_roots":3, "jobs_per_root":1,
        }))
        .unwrap(),
    )
    .unwrap();
    first_profile["command"] = json!("build");
    first_profile["service_socket"] = json!(socket);
    first_profile["timeout_seconds"] = json!(600);
    let mut queued_profile = first_profile.clone();
    queued_profile["source_root"] = json!(root.join("source-b"));
    let mut survivor_profile = first_profile.clone();
    survivor_profile["source_root"] = json!(root.join("source-c"));
    let mut command = shared_service_command(root);
    command
        .envs(environment.iter().map(|(name, value)| (name, value)))
        .arg("--canonical-compile-service")
        .arg(service_profile);
    let mut service = SharedServiceChild::spawn(root, "shared-queue-service", command);
    let deadline = Instant::now() + Duration::from_secs(60);
    while !socket.exists()
        || !service
            .events()
            .iter()
            .any(|event| event["kind"] == "canonical-service-listening")
    {
        service.assert_running();
        assert!(Instant::now() < deadline, "{}", service.diagnostics());
        std::thread::sleep(Duration::from_millis(10));
    }

    let mut first = shared_service_client(root, 5200, &first_profile);
    let deadline = Instant::now() + Duration::from_secs(240);
    let running_key = loop {
        let events = service.events();
        let offered = decisions(&events, "shared-remote-offer");
        if let Some(key) = offered.get("canonical_leaf")
            && events.iter().any(|event| {
                event["kind"] == "rabsd-remote-dependency-admitted" && event["key"] == *key
            })
        {
            break key.clone();
        }
        service.assert_running();
        first.assert_running();
        assert!(Instant::now() < deadline, "{}", service.diagnostics());
        std::thread::sleep(Duration::from_millis(2));
    };
    let paused = PausedNativeWorker::pause(&worker);
    let journal = read_bounded(&worker.state.join("requests.json"));
    let state: Value = serde_json::from_slice(&journal).unwrap();
    assert!(
        state.get("last").is_some_and(Value::is_null),
        "the native worker must be paused before a compiler lease begins: {state}"
    );

    let mut queued = shared_service_client(root, 5201, &queued_profile);
    let deadline = Instant::now() + Duration::from_secs(90);
    let queued_key = loop {
        let events = service.events();
        let offered = decisions(&events, "shared-remote-offer");
        if let Some(key) = offered.get("canonical_leaf")
            && key != &running_key
            && events.iter().any(|event| {
                event["kind"] == "rabsd-shared-remote-subscribed"
                    && event["key"] == *key
                    && event["disposition"] == "queued"
            })
        {
            break key.clone();
        }
        service.assert_running();
        first.assert_running();
        queued.assert_running();
        assert!(
            Instant::now() < deadline,
            "busy pool did not retain an acknowledged distinct action: {}",
            service.diagnostics()
        );
        std::thread::sleep(Duration::from_millis(5));
    };
    let origin = shared_remote_operation(&root.join("ops"), "queued-origin");
    let mut survivor = shared_service_client(root, 5202, &survivor_profile);
    let deadline = Instant::now() + Duration::from_secs(90);
    loop {
        let joined = service.events().iter().any(|event| {
            event["kind"] == "rabsd-shared-remote-subscribed"
                && event["key"] == queued_key
                && event["disposition"] == "joined"
        });
        if joined {
            break;
        }
        service.assert_running();
        first.assert_running();
        queued.assert_running();
        survivor.assert_running();
        assert!(
            Instant::now() < deadline,
            "identical queued demand did not coalesce: {}",
            service.diagnostics()
        );
        std::thread::sleep(Duration::from_millis(5));
    }
    let surviving_operation = shared_remote_operation(&root.join("ops"), "queued-survivor");
    assert_ne!(origin, surviving_operation);
    assert_eq!(read_bounded(&worker.state.join("requests.json")), journal);
    assert!(
        !service.events().iter().any(|event| {
            event["kind"] == "rabsd-remote-dependency-admitted" && event["key"] == queued_key
        }),
        "queued demand consumed a busy worker or minted execution authority"
    );

    let (code, events, output) = queued.finish(Duration::from_secs(15), true);
    assert_ne!(code, 0, "{output}");
    assert!(
        !events
            .iter()
            .any(|event| event["kind"] == "canonical-build-completed")
    );
    let deadline = Instant::now() + Duration::from_secs(30);
    while !service.events().iter().any(|event| {
        event["kind"] == "canonical-service-session-error"
            && event["reason"].as_str().is_some_and(|reason| {
                reason.contains("canonical client disconnected; its operation was drained")
            })
    }) {
        service.assert_running();
        first.assert_running();
        survivor.assert_running();
        assert!(
            Instant::now() < deadline,
            "queued origin did not drain independently: {}",
            service.diagnostics()
        );
        std::thread::sleep(Duration::from_millis(5));
    }
    assert_eq!(
        read_bounded(&origin.join("bundle/source/shared-flight-label.txt")),
        b"queued-origin"
    );
    // The departed origin's captured inputs remain owned by the queue, while
    // the surviving subscriber retains its own destination and validation.
    drop(paused);
    let (code, events, output) = first.finish(Duration::from_secs(240), false);
    assert_eq!(code, 0, "{output}\n{}", service.diagnostics());
    assert_shared_service_build(root, 5200, &events, &output, "running:42\n", "disabled");
    let (code, events, output) = survivor.finish(Duration::from_secs(240), false);
    assert_eq!(code, 0, "{output}\n{}", service.diagnostics());
    let target = assert_shared_service_build(
        root,
        5202,
        &events,
        &output,
        "queued-survivor:82\n",
        "disabled",
    );
    assert_ne!(target, origin.join("target"));
    worker.completed_receipt();
    let events = service.events();
    for key in [&running_key, &queued_key] {
        for kind in [
            "rabsd-remote-dependency-admitted",
            "rabsd-remote-dependency-executed",
        ] {
            assert_eq!(
                events
                    .iter()
                    .filter(|event| event["kind"] == kind && event["key"] == *key)
                    .count(),
                1,
                "each key needs exactly one actual producer and surviving installation: {events:?}"
            );
        }
        assert!(
            !events.iter().any(|event| {
                event["key"] == *key
                    && (matches!(
                        event["kind"].as_str(),
                        Some(
                            "rabsd-remote-dependency-failed"
                                | "rabsd-remote-dependency-install-failed"
                        )
                    ) || (event["kind"] == "rabsd-live-dependency"
                        && matches!(
                            event["decision"].as_str(),
                            Some("execute" | "hit" | "served")
                        )))
            }),
            "local fallback or replay cannot satisfy queued native execution: {events:?}"
        );
    }
    assert!(
        !origin.exists(),
        "completed queue retained its departed origin"
    );
    assert!(
        !surviving_operation.exists(),
        "completed delivery retained its subscriber operation"
    );
    service.finish(Duration::from_secs(15), true);
    worker.finish();
}

#[test]
#[ignore = "requires full Linux bubblewrap isolation, OpenSSL, matching RABS_CANONICAL_TEST_WRAPPER and RABS_TEST_WORKER_BIN; actual TLS upload loss retries on a second worker within one action generation"]
fn canonical_shared_remote_failover_preserves_generation_and_surviving_subscriber() {
    let (owner, mut origin_profile) = native_fixture();
    let root = owner.path();
    shared_remote_source(&root.join("source-a"), "retry-origin", 40);
    shared_remote_source(&root.join("source-b"), "retry-survivor", 40);
    let (coordinator, identities) = native_certificates(
        &root.join("credentials"),
        &["worker-first", "worker-second"],
    );
    let first_root = root.join("worker-first");
    let second_root = root.join("worker-second");
    for directory in [&first_root, &second_root] {
        fs::DirBuilder::new().mode(0o700).create(directory).unwrap();
    }
    let (first_worker, first_environment) = NativeWorker::start_with_identity(
        &first_root,
        "failover-first",
        &coordinator,
        &identities[0],
    );
    let (mut second_worker, second_environment) = NativeWorker::start_with_identity(
        &second_root,
        "failover-second",
        &coordinator,
        &identities[1],
    );
    let pool = [first_environment.as_slice(), second_environment.as_slice()]
        .into_iter()
        .map(|environment| {
            let value = |name| {
                environment
                    .iter()
                    .find(|(key, _)| key == name)
                    .unwrap()
                    .1
                    .clone()
            };
            json!({
                "listen":value("RABS_DEPENDENCY_WORKER_LISTEN"),
                "worker_id":value("RABS_DEPENDENCY_WORKER_ID"),
                "worker_spki_sha256":value("RABS_DEPENDENCY_WORKER_SPKI_SHA256"),
            })
        })
        .collect::<Vec<_>>();
    assert_ne!(pool[0]["worker_spki_sha256"], pool[1]["worker_spki_sha256"]);
    let socket = root.join("canonical-service.sock");
    let service_profile = root.join("shared-failover-service.json");
    fs::write(
        &service_profile,
        serde_json::to_vec(&json!({
            "version":"canonical-compile-service-v1", "state_root":root.join("state"),
            "socket":socket, "max_roots":2, "jobs_per_root":1,
        }))
        .unwrap(),
    )
    .unwrap();
    origin_profile["command"] = json!("build");
    origin_profile["service_socket"] = json!(socket);
    origin_profile["timeout_seconds"] = json!(600);
    let mut survivor_profile = origin_profile.clone();
    survivor_profile["source_root"] = json!(root.join("source-b"));
    let mut command = shared_service_command(root);
    command
        .envs(
            first_environment
                .iter()
                .filter(|(name, _)| name.starts_with("RABS_COORD_TLS_"))
                .map(|(name, value)| (name, value)),
        )
        .env(
            "RABS_DEPENDENCY_WORKERS_JSON",
            serde_json::to_string(&pool).unwrap(),
        )
        .arg("--canonical-compile-service")
        .arg(service_profile);
    let mut service = SharedServiceChild::spawn(root, "shared-failover-service", command);
    let deadline = Instant::now() + Duration::from_secs(60);
    while !socket.exists()
        || !service
            .events()
            .iter()
            .any(|event| event["kind"] == "canonical-service-listening")
    {
        service.assert_running();
        assert!(Instant::now() < deadline, "{}", service.diagnostics());
        std::thread::sleep(Duration::from_millis(10));
    }

    let mut origin = shared_service_client(root, 5300, &origin_profile);
    let deadline = Instant::now() + Duration::from_secs(240);
    let key = loop {
        let events = service.events();
        let offered = decisions(&events, "shared-remote-offer");
        if let Some(key) = offered.get("canonical_leaf")
            && let Some(admitted) = events.iter().find(|event| {
                event["kind"] == "rabsd-remote-dependency-admitted" && event["key"] == *key
            })
        {
            assert_eq!(admitted["worker_id"], "failover-first");
            assert_eq!(admitted["purpose"], "primary");
            break key.clone();
        }
        service.assert_running();
        origin.assert_running();
        assert!(Instant::now() < deadline, "{}", service.diagnostics());
        std::thread::sleep(Duration::from_millis(2));
    };
    let paused = PausedNativeWorker::pause(&first_worker);
    let journal_path = first_worker.state.join("requests.json");
    let journal = read_bounded(&journal_path);
    let state: Value = serde_json::from_slice(&journal).unwrap();
    assert!(
        state.get("last").is_some_and(Value::is_null),
        "the failed worker must not have accepted canonical-exec: {state}"
    );
    first_worker.assert_fresh_toolchain_upload_incomplete(Path::new(
        origin_profile["toolchain_root"].as_str().unwrap(),
    ));
    let origin_operation = shared_remote_operation(&root.join("ops"), "retry-origin");
    let mut survivor = shared_service_client(root, 5301, &survivor_profile);
    let deadline = Instant::now() + Duration::from_secs(90);
    while !service.events().iter().any(|event| {
        event["kind"] == "rabsd-shared-remote-subscribed"
            && event["key"] == key
            && event["disposition"] == "joined"
    }) {
        service.assert_running();
        origin.assert_running();
        survivor.assert_running();
        assert!(Instant::now() < deadline, "{}", service.diagnostics());
        std::thread::sleep(Duration::from_millis(5));
    }
    let (code, events, output) = origin.finish(Duration::from_secs(15), true);
    assert_ne!(code, 0, "{output}");
    assert!(
        !events
            .iter()
            .any(|event| event["kind"] == "canonical-build-completed")
    );
    let deadline = Instant::now() + Duration::from_secs(30);
    while !service.events().iter().any(|event| {
        event["kind"] == "canonical-service-session-error"
            && event["reason"].as_str().is_some_and(|reason| {
                reason.contains("canonical client disconnected; its operation was drained")
            })
    }) {
        service.assert_running();
        survivor.assert_running();
        assert!(Instant::now() < deadline, "{}", service.diagnostics());
        std::thread::sleep(Duration::from_millis(5));
    }
    assert_eq!(
        read_bounded(&origin_operation.join("bundle/source/shared-flight-label.txt")),
        b"retry-origin"
    );
    // The stopped worker lacks a required toolchain member, so it cannot have
    // acknowledged toolchain-ready. The coordinator therefore cannot even
    // start writing canonical-exec. Its real TLS EOF must trigger failover;
    // no transport result or compiler receipt is injected by this fixture.
    rustix::process::kill_process(paused.0, rustix::process::Signal::KILL).unwrap();
    drop(paused);
    first_worker.finish();
    assert_eq!(read_bounded(&journal_path), journal);

    let (code, events, output) = survivor.finish(Duration::from_secs(300), false);
    assert_eq!(code, 0, "{output}\n{}", service.diagnostics());
    assert_shared_service_build(
        root,
        5301,
        &events,
        &output,
        "retry-survivor:42\n",
        "disabled",
    );
    second_worker.completed_receipt();
    let events = service.events();
    let admissions = events
        .iter()
        .filter(|event| event["kind"] == "rabsd-remote-dependency-admitted" && event["key"] == key)
        .collect::<Vec<_>>();
    assert_eq!(admissions.len(), 2, "{events:?}");
    assert_eq!(admissions[0]["worker_id"], "failover-first");
    assert_eq!(admissions[1]["worker_id"], "failover-second");
    assert_eq!(admissions[0]["purpose"], "primary");
    assert_eq!(admissions[1]["purpose"], "retry");
    for admission in &admissions {
        for field in ["generation_id", "attempt_id", "execution_lease_id"] {
            let value = admission[field].as_str().unwrap();
            assert_eq!(value.len(), 32, "missing actual {field}: {admission}");
            assert!(value.bytes().all(|byte| byte.is_ascii_hexdigit()));
        }
    }
    assert_eq!(
        admissions[0]["generation_id"],
        admissions[1]["generation_id"]
    );
    assert_ne!(admissions[0]["attempt_id"], admissions[1]["attempt_id"]);
    assert_ne!(
        admissions[0]["execution_lease_id"],
        admissions[1]["execution_lease_id"]
    );
    assert_eq!(
        events
            .iter()
            .filter(
                |event| event["kind"] == "rabsd-remote-dependency-executed" && event["key"] == key
            )
            .count(),
        1,
        "one surviving subscriber must receive the actual retry result: {events:?}"
    );
    assert!(
        !events.iter().any(|event| {
            event["key"] == key
                && (matches!(
                    event["kind"].as_str(),
                    Some(
                        "rabsd-remote-dependency-failed" | "rabsd-remote-dependency-install-failed"
                    )
                ) || (event["kind"] == "rabsd-live-dependency"
                    && matches!(
                        event["decision"].as_str(),
                        Some("execute" | "hit" | "served")
                    )))
        }),
        "fallback or replay cannot satisfy actual failover: {events:?}"
    );
    assert!(
        !origin_operation.exists(),
        "the retry retained its departed origin"
    );
    service.finish(Duration::from_secs(15), true);
    second_worker.finish();
}

#[test]
#[ignore = "requires full canonical bubblewrap namespaces, native toolchain and matching RABS_CANONICAL_TEST_WRAPPER; runs concurrent actual Cargo builds through one persistent service"]
fn canonical_shared_service_overlaps_builds_scopes_cancellation_and_reuses_private_targets() {
    let (owner, mut first_profile) = native_fixture();
    let root = owner.path();
    let socket = root.join("canonical-service.sock");
    let service_profile = root.join("canonical-service.json");
    fs::write(
        &service_profile,
        serde_json::to_vec(&json!({
            "version":"canonical-compile-service-v1", "state_root":root.join("state"),
            "socket":socket, "max_roots":2, "jobs_per_root":1,
        }))
        .unwrap(),
    )
    .unwrap();
    shared_service_source(&root.join("source-a"), "A", 101);
    shared_service_source(&root.join("source-b"), "B", 202);
    first_profile["command"] = json!("build");
    first_profile["service_socket"] = json!(socket);
    first_profile["target_cache"] =
        json!({"runtime_epoch":"shared-service-native-v1", "max_bytes":268435456});
    let mut second_profile = first_profile.clone();
    second_profile["source_root"] = json!(root.join("source-b"));
    let mut command = shared_service_command(root);
    command
        .arg("--canonical-compile-service")
        .arg(&service_profile);
    let mut service = SharedServiceChild::spawn(root, "shared-service", command);
    let service_pid = service.process.as_ref().unwrap().pgid();
    let deadline = Instant::now() + Duration::from_secs(60);
    loop {
        service.assert_running();
        if socket.exists()
            && service
                .events()
                .iter()
                .any(|event| event["kind"] == "canonical-service-listening")
        {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "service did not start: {}",
            service.diagnostics()
        );
        std::thread::sleep(Duration::from_millis(20));
    }

    let mut first = shared_service_client(root, 5000, &first_profile);
    let first_marker =
        wait_for_shared_service_marker(&root.join("ops"), "A", &mut service, &mut first);
    let mut second = shared_service_client(root, 5001, &second_profile);
    let second_marker =
        wait_for_shared_service_marker(&root.join("ops"), "B", &mut service, &mut second);
    // Both native build scripts are simultaneously paused inside independent
    // Cargo roots. This is overlap evidence, not an elapsed-time speedup claim.
    first.assert_running();
    second.assert_running();
    assert_eq!(read_bounded(&first_marker), b"A");
    assert_eq!(read_bounded(&second_marker), b"B");
    let operations = root.join("ops");
    let operation_owner = |marker: &Path| {
        marker
            .ancestors()
            .find(|path| path.parent() == Some(operations.as_path()))
            .unwrap()
            .to_path_buf()
    };
    let first_owner = operation_owner(&first_marker);
    let second_owner = operation_owner(&second_marker);
    assert_ne!(first_owner, second_owner);
    let toolchains = retained_service_toolchains(&root.join("state"));
    assert_eq!(
        toolchains.len(),
        1,
        "concurrent builds must share one actual captured compiler"
    );
    for (operation, label) in [(&first_owner, b"A"), (&second_owner, b"B")] {
        assert!(
            !operation.join("bundle/toolchain").exists(),
            "a shared operation must not recopy the complete toolchain"
        );
        assert_eq!(
            read_bounded(&operation.join("runtime-workspace/service-label.txt")),
            label,
            "each active Cargo root must use its own captured workspace"
        );
    }
    let occupied_targets = fs::read_dir(root.join("ops")).unwrap().count();
    let busy = shared_service_client(root, 5002, &second_profile);
    let (code, events, output) = busy.finish(Duration::from_secs(15), false);
    assert_ne!(
        code, 0,
        "a third root must not bypass service capacity: {output}"
    );
    assert!(
        output.contains("busy") || output.contains("capacity"),
        "{output}"
    );
    assert!(
        !events
            .iter()
            .any(|event| event["kind"] == "canonical-compilation-started"),
        "{output}"
    );
    assert_eq!(
        fs::read_dir(root.join("ops")).unwrap().count(),
        occupied_targets
    );

    let (code, events, output) = first.finish(Duration::from_secs(15), true);
    assert_ne!(code, 0, "cancelled client completed successfully: {output}");
    assert!(
        !events
            .iter()
            .any(|event| event["kind"] == "canonical-build-completed")
    );
    let deadline = Instant::now() + Duration::from_secs(30);
    while first_owner.exists() {
        service.assert_running();
        second.assert_running();
        assert!(
            Instant::now() < deadline,
            "disconnecting A did not drain its actual Cargo root: {}",
            service.diagnostics()
        );
        std::thread::sleep(Duration::from_millis(20));
    }
    service.assert_running();
    second.assert_running();
    assert_eq!(service.process.as_ref().unwrap().pgid(), service_pid);
    fs::write(
        second_marker
            .parent()
            .unwrap()
            .join("shared-service-release"),
        b"released",
    )
    .unwrap();
    let (code, events, output) = second.finish(Duration::from_secs(180), false);
    assert_eq!(code, 0, "{output}\n{}", service.diagnostics());
    assert!(output.contains("SERVICE_DIAGNOSTIC_B_ONLY"), "{output}");
    assert!(!output.contains("SERVICE_DIAGNOSTIC_A_ONLY"), "{output}");
    let second_target =
        assert_shared_service_build(root, 5001, &events, &output, "B:244\n", "cold");
    assert_eq!(
        retained_service_toolchains(&root.join("state")),
        toolchains,
        "cancelling another client must preserve the selected compiler image"
    );
    assert!(!service.diagnostics().contains("SERVICE_DIAGNOSTIC_B_ONLY"));

    // Use the same running service and exact source again. The private target
    // must restore actual Cargo fingerprints, not a fabricated success reply.
    let warm = shared_service_client(root, 5003, &second_profile);
    let (code, events, output) = warm.finish(Duration::from_secs(180), false);
    assert_eq!(code, 0, "{output}");
    let warm_target =
        assert_shared_service_build(root, 5003, &events, &output, "B:244\n", "restored");
    assert_ne!(second_target, warm_target);
    assert_eq!(
        retained_service_toolchains(&root.join("state")),
        toolchains,
        "a subsequent build must reuse the same compiler inode and backing"
    );
    let fresh_app = output
        .lines()
        .filter_map(|line| serde_json::from_str::<Value>(line).ok())
        .filter(|event| {
            event["reason"] == "compiler-artifact" && event["target"]["name"] == "canonical_app"
        })
        .collect::<Vec<_>>();
    assert!(!fresh_app.is_empty(), "{output}");
    assert!(
        fresh_app.iter().all(|event| event["fresh"] == true),
        "{output}"
    );
    service.assert_running();
    assert_eq!(service.process.as_ref().unwrap().pgid(), service_pid);

    // A source mutation must produce a new actual compiler result through the
    // same authority. The build-script marker proves fresh execution occurred.
    write(&root.join("source-b"), "service-value.txt", "203");
    let mut changed = shared_service_client(root, 5004, &second_profile);
    let changed_marker =
        wait_for_shared_service_marker(&root.join("ops"), "B", &mut service, &mut changed);
    fs::write(
        changed_marker
            .parent()
            .unwrap()
            .join("shared-service-release"),
        b"released",
    )
    .unwrap();
    let (code, events, output) = changed.finish(Duration::from_secs(180), false);
    assert_eq!(code, 0, "{output}");
    let changed_target =
        assert_shared_service_build(root, 5004, &events, &output, "B:245\n", "cold");
    assert_ne!(changed_target, warm_target);
    assert!(
        shared_service_markers(&root.join("ops"), "A").is_empty(),
        "cancelled Cargo root did not drain"
    );
    service.assert_running();
    service.finish(Duration::from_secs(15), true);
    assert!(
        retained_service_toolchains(&root.join("state")).is_empty(),
        "service shutdown must join preparation and release its retained images"
    );

    // An existing private cache must not turn a dead service into permission
    // to start a second standalone coordinator or silently compile locally.
    let retained = fs::read_dir(root.join("ops")).unwrap().count();
    let absent = shared_service_client(root, 5005, &second_profile);
    let (code, events, output) = absent.finish(Duration::from_secs(15), false);
    assert_ne!(code, 0, "{output}");
    assert!(
        !events
            .iter()
            .any(|event| event["kind"] == "canonical-compilation-started"
                || event["kind"] == "canonical-build-completed"),
        "{output}"
    );
    assert_eq!(fs::read_dir(root.join("ops")).unwrap().count(), retained);
}

#[test]
fn canonical_shared_client_refuses_missing_service_before_namespace_or_state_acquisition() {
    let root = tempfile::Builder::new()
        .prefix("rabs-service-missing-")
        .tempdir_in("/tmp")
        .unwrap();
    fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).unwrap();
    for name in ["source", "toolchain", "state", "ops", "tools"] {
        fs::DirBuilder::new()
            .mode(0o700)
            .create(root.path().join(name))
            .unwrap();
    }
    write(
        root.path(),
        "config.toml",
        "[rabs]\nrelease_authorization='advisory'\n",
    );
    write(root.path(), "tools/rabs-wrap", "#!/bin/sh\nexit 99\n");
    fs::set_permissions(
        root.path().join("tools/rabs-wrap"),
        fs::Permissions::from_mode(0o700),
    )
    .unwrap();
    let profile = json!({
        "version":"canonical-compile-local-v1", "command":"build",
        "source_root":root.path().join("source"), "toolchain_root":root.path().join("toolchain"),
        "state_root":root.path().join("state"), "operation_root":root.path().join("ops"),
        "wrapper":root.path().join("tools/rabs-wrap"), "service_socket":root.path().join("missing.sock"),
    });
    let (code, events, output) = run(root.path(), 5100, &profile);
    assert_ne!(code, 0, "{output}");
    assert!(output.contains("No such file or directory"), "{output}");
    assert!(
        !events
            .iter()
            .any(|event| event["kind"] == "canonical-compilation-started"
                || event["kind"] == "canonical-build-completed"),
        "{output}"
    );
    for name in ["state", "ops", "source", "toolchain"] {
        assert_eq!(
            fs::read_dir(root.path().join(name)).unwrap().count(),
            0,
            "missing service must not trigger local fallback: {output}"
        );
    }
}

#[test]
#[ignore = "requires real bubblewrap namespaces, native toolchain and RABS_CANONICAL_TEST_WRAPPER"]
fn canonical_cargo_earns_cross_worktree_dependency_hits_and_invalidates_changed_source() {
    let (owner, mut profile) = native_fixture();
    let second = owner.path().join("source-b");
    let mut first_keys = None;
    // Production fixed sampling requires the initial result and two genuine
    // compiler comparisons. Every run has a fresh target; Cargo's own
    // fingerprints cannot satisfy any of these compiles or the subsequent hit.
    for number in 1..=3 {
        let (code, events, output) = run(owner.path(), number, &profile);
        assert_eq!(code, 0, "{output}");
        let keys = decisions(&events, "execute");
        assert_eq!(
            keys.len(),
            2,
            "both external crates must actually execute: {output}"
        );
        assert!(
            keys.contains_key("canonical_leaf") && keys.contains_key("canonical_dep"),
            "{output}"
        );
        if let Some(expected) = &first_keys {
            assert_eq!(
                &keys, expected,
                "canonical action identity changed between fresh targets"
            );
        } else {
            first_keys = Some(keys);
        }
        assert!(
            decisions(&events, "hit").is_empty(),
            "unearned hit: {output}"
        );
    }
    profile["source_root"] = json!(second);
    write(
        &second,
        "src/lib.rs",
        "pub fn answer()->u32 { canonical_dep::answer()+1 }\n",
    );
    let (code, events, output) = run(owner.path(), 4, &profile);
    assert_eq!(code, 0, "{output}");
    assert_eq!(
        decisions(&events, "hit"),
        first_keys.unwrap(),
        "cross-worktree reuse failed: {output}"
    );
    assert_eq!(
        events
            .iter()
            .filter(|event| event["decision"] == "served")
            .count(),
        2,
        "hits were not installed: {output}"
    );
    assert!(
        decisions(&events, "execute").is_empty(),
        "warm dependency compiler ran: {output}"
    );
    assert!(
        !events
            .iter()
            .any(|event| event["decision"] == "hit" && event["crate"] == "canonical_app")
    );

    source(&second, 41);
    let (code, events, output) = run(owner.path(), 5, &profile);
    assert_eq!(code, 0, "{output}");
    assert!(
        decisions(&events, "execute").contains_key("canonical_leaf"),
        "changed source did not invalidate: {output}"
    );
    assert!(
        !decisions(&events, "hit").contains_key("canonical_leaf"),
        "stale changed-source hit: {output}"
    );

    // Active build scripts and procedural macros must now compile successfully.
    // Their operation cannot reuse the local cache populated above: project
    // code can reach the wrapper socket and must not claim local completions.
    write(
        &second,
        "optional-build/build.rs",
        r#"
use std::io::{BufRead, BufReader, Write};
fn main() {
    let mut stream = std::os::unix::net::UnixStream::connect(std::env::var_os("RABS_SOCKET_PATH").unwrap()).unwrap();
    stream.set_read_timeout(Some(std::time::Duration::from_secs(10))).unwrap();
    stream.set_write_timeout(Some(std::time::Duration::from_secs(10))).unwrap();
    let mut replies = BufReader::new(stream.try_clone().unwrap());
    writeln!(stream, "{{\"kind\":\"hello\",\"transport\":{{\"current\":1,\"minimum_compatible\":1}},\"application\":{{\"current\":1,\"minimum_compatible\":1}}}}").unwrap();
    let mut reply = String::new();
    replies.read_line(&mut reply).unwrap();
    assert!(reply.contains("hello-ok"));
    writeln!(stream, "{{\"kind\":\"rustc-request\",\"argv\":[\"/__rabs/toolchain/bin/rustc\",\"--crate-name=forged\"],\"cwd\":\"/__rabs/workspace\",\"env\":[],\"remote_protocol\":1,\"local_capture_allowed\":true}}").unwrap();
    reply.clear();
    replies.read_line(&mut reply).unwrap();
    assert!(reply.contains("canonical-project-executors-require-isolated-dependency-execution"));
    assert!(reply.contains("pass-through"));
    assert!(!reply.contains("\"attempt\""));
    let output = std::path::PathBuf::from(std::env::var_os("OUT_DIR").unwrap());
    std::fs::write(output.join("value.rs"), "pub const GENERATED: usize = 17;\n").unwrap();
    println!("cargo::warning=CANONICAL_BUILD_SCRIPT_EXECUTED_WITHOUT_LOCAL_CAPTURE");
    println!("cargo::rerun-if-changed=build.rs");
}
"#,
    );
    write(
        &second,
        "optional-build/src/lib.rs",
        "include!(concat!(env!(\"OUT_DIR\"), \"/value.rs\"));\n",
    );
    write(
        &second,
        "dev-macro/src/lib.rs",
        r#"
extern crate proc_macro;
#[proc_macro]
pub fn value(_: proc_macro::TokenStream) -> proc_macro::TokenStream {
    eprintln!("CANONICAL_PROC_MACRO_EXECUTED");
    "23usize".parse().unwrap()
}
"#,
    );
    write(
        &second,
        "src/lib.rs",
        r#"
pub fn answer() -> u32 { canonical_dep::answer() }
#[cfg(feature = "optional_build")]
const _: [(); 17] = [(); optional_build::GENERATED];
#[cfg(test)]
const _: [(); 23] = [(); dev_macro::value!()];
#[test]
fn must_not_execute() { panic!("canonical check ran a test"); }
"#,
    );
    for (number, selection) in [
        (6, json!({"lib":true, "features":["optional_build"]})),
        (7, json!({"tests":true})),
    ] {
        profile["selection"] = selection;
        let (code, events, output) = run(owner.path(), number, &profile);
        assert_eq!(code, 0, "executor-bearing compilation failed: {output}");
        assert!(
            output.contains(if number == 6 {
                "CANONICAL_BUILD_SCRIPT_EXECUTED_WITHOUT_LOCAL_CAPTURE"
            } else {
                "CANONICAL_PROC_MACRO_EXECUTED"
            }),
            "{output}"
        );
        assert!(
            output.contains("canonical-project-executors-require-isolated-dependency-execution"),
            "{output}"
        );
        assert!(
            events
                .iter()
                .any(|event| event["kind"] == "canonical-compilation-started"),
            "selected executor never reached canonical compilation: {output}"
        );
        assert!(
            decisions(&events, "execute").is_empty() && decisions(&events, "hit").is_empty(),
            "executor-bearing operation obtained local compiler authority: {output}"
        );
        assert!(
            !events.iter().any(|event| event["decision"] == "served"),
            "{output}"
        );
    }
    assert!(
        fs::read_dir(owner.path().join("ops"))
            .unwrap()
            .next()
            .is_none(),
        "completed operations retained mutable targets or live endpoints"
    );
}

/// This exercises Cargo's private fingerprints, not shared action-cache
/// authorization: a warm build must report `fresh` even for workspace units,
/// while edits and feature changes still execute the affected compiler units.
#[test]
#[ignore = "requires real bubblewrap namespaces, native toolchain and RABS_CANONICAL_TEST_WRAPPER; actual canonical target reuse and delivered executable validation"]
fn canonical_private_targets_reuse_relocated_builds_and_preserve_current_outputs() {
    use std::os::unix::fs::MetadataExt;

    let (owner, mut profile) = native_fixture();
    let second = owner.path().join("source-b");
    for name in ["source-a", "source-b"] {
        let root = owner.path().join(name);
        let manifest = root.join("Cargo.toml");
        fs::write(
            &manifest,
            format!(
                "{}\n[features]\nextra=[]\n",
                fs::read_to_string(&manifest).unwrap()
            ),
        )
        .unwrap();
        write(
            &root,
            "src/main.rs",
            "fn main(){println!(\"{}\",canonical_app::answer()+u32::from(cfg!(feature=\"extra\"))*100);}\n",
        );
    }
    profile["command"] = json!("build");
    profile["target_cache"] = json!({"runtime_epoch":"native-fixture-v1",
        "max_bytes":268435456, "max_families":2});

    let families = || {
        fs::read_dir(
            owner
                .path()
                .join("state/canonical-compile-v1/private-target-v2"),
        )
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .collect::<std::collections::BTreeSet<_>>()
    };

    let state = |events: &[Value], expected: &str| {
        let started = events
            .iter()
            .filter(|event| event["kind"] == "canonical-compilation-started")
            .collect::<Vec<_>>();
        assert_eq!(started.len(), 1);
        assert_eq!(started[0]["private_target_state"], expected, "{events:?}");
        assert_eq!(started[0]["workspace_cache"], false);
    };
    let freshness = |output: &str, dependencies: bool, workspace: bool| {
        let artifacts = output
            .lines()
            .filter_map(|line| serde_json::from_str::<Value>(line).ok())
            .filter(|event| event["reason"] == "compiler-artifact")
            .collect::<Vec<_>>();
        for (name, expected) in [
            ("canonical_leaf", dependencies),
            ("canonical_dep", dependencies),
            ("canonical_app", workspace),
        ] {
            let selected = artifacts
                .iter()
                .filter(|event| event["target"]["name"] == name)
                .collect::<Vec<_>>();
            assert!(
                !selected.is_empty(),
                "missing real Cargo artifact for {name}: {output}"
            );
            assert!(
                selected.iter().all(|event| event["fresh"] == expected),
                "unexpected Cargo freshness for {name}: {output}"
            );
        }
    };

    let (code, events, output) = run(owner.path(), 100, &profile);
    assert_eq!(code, 0, "{output}");
    state(&events, "cold");
    freshness(&output, false, false);
    let (first_target, first_archives) = delivered_build(owner.path(), 100, &events, &output, 42);
    let initial_families = families();
    assert_eq!(initial_families.len(), 1);

    profile["source_root"] = json!(second);
    let (code, events, output) = run(owner.path(), 101, &profile);
    assert_eq!(code, 0, "{output}");
    state(&events, "restored");
    freshness(&output, true, true);
    let (warm_target, warm_archives) = delivered_build(owner.path(), 101, &events, &output, 42);
    assert_ne!(first_target, warm_target);
    assert_eq!(first_archives, warm_archives);
    assert!(decisions(&events, "execute").is_empty());
    assert!(decisions(&events, "hit").is_empty());
    let first_binary = first_target.join("target/debug/canonical_app");
    let warm_binary = warm_target.join("target/debug/canonical_app");
    let first_inode = fs::metadata(&first_binary).unwrap();
    let warm_inode = fs::metadata(&warm_binary).unwrap();
    assert_ne!(
        (first_inode.dev(), first_inode.ino()),
        (warm_inode.dev(), warm_inode.ino())
    );
    fs::write(&first_binary, b"caller replaced its delivered binary").unwrap();

    let (code, events, output) = run(owner.path(), 102, &profile);
    assert_eq!(code, 0, "{output}");
    state(&events, "restored");
    freshness(&output, true, true);
    delivered_build(owner.path(), 102, &events, &output, 42);

    write(
        &second,
        "src/lib.rs",
        "pub fn answer()->u32 { canonical_dep::answer()+1 }\n",
    );
    let (code, events, output) = run(owner.path(), 103, &profile);
    assert_eq!(code, 0, "{output}");
    // Code generation may consume source bytes absent from Cargo dep-info
    // (for example assembler .incbin inputs). Its private state is source-exact.
    state(&events, "cold");
    freshness(&output, false, false);
    delivered_build(owner.path(), 103, &events, &output, 43);
    let original_families = families()
        .difference(&initial_families)
        .cloned()
        .collect::<std::collections::BTreeSet<_>>();
    assert_eq!(original_families.len(), 1);

    profile["selection"] = json!({"features":["extra"]});
    let (code, events, output) = run(owner.path(), 104, &profile);
    assert_eq!(code, 0, "{output}");
    state(&events, "restored");
    freshness(&output, true, false);
    delivered_build(owner.path(), 104, &events, &output, 143);

    profile["command"] = json!("check");
    for number in [105, 106] {
        let (code, events, output) = run(owner.path(), number, &profile);
        assert_eq!(code, 0, "{output}");
        // Metadata-only checks have their own source-edit compatibility family.
        state(&events, if number == 105 { "cold" } else { "restored" });
        if number == 106 {
            freshness(&output, true, true);
        }
        assert!(
            !events
                .iter()
                .any(|event| event["kind"] == "canonical-build-completed")
        );
    }

    // Checks use a separate source-edit policy. Returning to the exact build
    // family must recover the completed executable and every Cargo fingerprint.
    profile["command"] = json!("build");
    let (code, events, output) = run(owner.path(), 107, &profile);
    assert_eq!(code, 0, "{output}");
    state(&events, "restored");
    freshness(&output, true, true);
    delivered_build(owner.path(), 107, &events, &output, 143);

    // Ambient host tools belong to the operator's runtime epoch. A changed
    // epoch cannot inherit Cargo's prior fingerprint state under the old one.
    profile["target_cache"]["runtime_epoch"] = json!("native-fixture-v2");
    let (code, events, output) = run(owner.path(), 108, &profile);
    assert_eq!(code, 0, "{output}");
    state(&events, "cold");
    freshness(&output, false, false);
    delivered_build(owner.path(), 108, &events, &output, 143);

    // A rejected optional restore must not discard the adapter that captures
    // this command's successful cold Cargo output. The very next invocation
    // must be warm, including the workspace executable.
    let retained_families = families();
    assert_eq!(retained_families.len(), 2);
    let added = retained_families
        .difference(&original_families)
        .collect::<Vec<_>>();
    assert_eq!(added.len(), 1);
    let second_family = added[0].clone();
    let seed_binary = second_family.join("seed/target/debug/canonical_app");
    fs::write(&seed_binary, b"corrupted private target").unwrap();
    let (code, events, output) = run(owner.path(), 109, &profile);
    assert_eq!(code, 0, "{output}");
    state(&events, "cold");
    freshness(&output, false, false);
    assert!(
        events.iter().any(|event| {
            event["kind"] == "canonical-target-state-unavailable" && event["stage"] == "restore"
        }),
        "corrupted seed was not refused: {output}"
    );
    delivered_build(owner.path(), 109, &events, &output, 143);

    let (code, events, output) = run(owner.path(), 110, &profile);
    assert_eq!(code, 0, "{output}");
    state(&events, "restored");
    freshness(&output, true, true);
    delivered_build(owner.path(), 110, &events, &output, 143);

    // A return to a previous runtime family restores its own complete Cargo
    // state. Neither switching families nor repairing one corrupts the other.
    for (number, epoch) in [(111, "native-fixture-v1"), (112, "native-fixture-v2")] {
        profile["target_cache"]["runtime_epoch"] = json!(epoch);
        let (code, events, output) = run(owner.path(), number, &profile);
        assert_eq!(code, 0, "{output}");
        state(&events, "restored");
        freshness(&output, true, true);
        delivered_build(owner.path(), number, &events, &output, 143);
        assert_eq!(families(), retained_families);
    }

    // The third family exceeds the configured count. Evict only the older
    // successful family; keep the just-published state and the recent one.
    profile["target_cache"]["runtime_epoch"] = json!("native-fixture-v3");
    let (code, events, output) = run(owner.path(), 113, &profile);
    assert_eq!(code, 0, "{output}");
    state(&events, "cold");
    freshness(&output, false, false);
    delivered_build(owner.path(), 113, &events, &output, 143);
    let retained = families();
    assert_eq!(retained.len(), 2);
    assert!(retained.contains(&second_family));
    assert!(retained.is_disjoint(&original_families));

    profile["target_cache"]["runtime_epoch"] = json!("native-fixture-v2");
    let (code, events, output) = run(owner.path(), 114, &profile);
    assert_eq!(code, 0, "{output}");
    state(&events, "restored");
    freshness(&output, true, true);
    delivered_build(owner.path(), 114, &events, &output, 143);

    profile["target_cache"]["runtime_epoch"] = json!("native-fixture-v1");
    let (code, events, output) = run(owner.path(), 115, &profile);
    assert_eq!(code, 0, "{output}");
    state(&events, "cold");
    freshness(&output, false, false);
    delivered_build(owner.path(), 115, &events, &output, 143);
    assert_eq!(families().len(), 2);
}

fn assert_test_execution(events: &[Value], state: &str, executed: bool) {
    let started = events
        .iter()
        .filter(|event| event["kind"] == "canonical-compilation-started")
        .collect::<Vec<_>>();
    assert_eq!(started.len(), 1, "{events:?}");
    assert_eq!(started[0]["command"], "test");
    assert_eq!(started[0]["private_target_state"], state, "{events:?}");
    assert_eq!(started[0]["test_execution"], executed);
    assert_eq!(started[0]["test_result_cache"], false);
    assert_eq!(started[0]["workspace_cache"], false);
    assert!(
        decisions(events, "execute").is_empty() && decisions(events, "hit").is_empty(),
        "project test code must not obtain local cache authority: {events:?}"
    );
    assert!(
        !events.iter().any(|event| event["decision"] == "served"),
        "{events:?}"
    );
    if executed {
        assert!(
            !events
                .iter()
                .any(|event| event["kind"] == "canonical-build-completed"),
            "an executed test outcome must not be delivered as a compilation result"
        );
    }
}

fn test_harness_artifacts(output: &str) -> Vec<Value> {
    let artifacts = output
        .lines()
        .filter_map(|line| serde_json::from_str::<Value>(line).ok())
        .filter(|event| {
            event["reason"] == "compiler-artifact"
                && event["target"]["name"] == "canonical_app"
                && event["profile"]["test"] == true
                && event["executable"].is_string()
        })
        .collect::<Vec<_>>();
    assert_eq!(
        artifacts.len(),
        1,
        "missing selected test harness: {output}"
    );
    artifacts
}

/// Warm compiler artifacts may eliminate compilation, never a current test
/// execution. A counter in the writable private target makes the same harness
/// change from success to failure without changing any captured source byte.
#[test]
#[ignore = "requires real bubblewrap namespaces, native toolchain and RABS_CANONICAL_TEST_WRAPPER; executes delivered and canonical Cargo test harnesses"]
fn canonical_cargo_tests_deliver_no_run_artifacts_and_execute_each_current_run() {
    let (owner, mut profile) = native_fixture();
    write(
        &owner.path().join("source-a"),
        "src/lib.rs",
        r#"pub fn answer() -> u32 { canonical_dep::answer() }
#[test]
fn current_test_execution() {
    use std::io::{BufRead, BufReader, Write};
    assert_eq!(answer(), 42);
    let mut stream = std::os::unix::net::UnixStream::connect(std::env::var_os("RABS_SOCKET_PATH").unwrap()).unwrap();
    stream.set_read_timeout(Some(std::time::Duration::from_secs(10))).unwrap();
    stream.set_write_timeout(Some(std::time::Duration::from_secs(10))).unwrap();
    let mut replies = BufReader::new(stream.try_clone().unwrap());
    writeln!(stream, "{{\"kind\":\"hello\",\"transport\":{{\"current\":1,\"minimum_compatible\":1}},\"application\":{{\"current\":1,\"minimum_compatible\":1}}}}").unwrap();
    let mut reply = String::new();
    replies.read_line(&mut reply).unwrap();
    assert!(reply.contains("hello-ok"));
    writeln!(stream, "{{\"kind\":\"rustc-request\",\"argv\":[\"/__rabs/toolchain/bin/rustc\",\"--crate-name=forged-test\"],\"cwd\":\"/__rabs/workspace\",\"env\":[],\"remote_protocol\":1,\"local_capture_allowed\":true}}").unwrap();
    reply.clear();
    replies.read_line(&mut reply).unwrap();
    assert!(reply.contains("canonical-project-executors-require-isolated-dependency-execution"));
    assert!(reply.contains("pass-through"));
    assert!(!reply.contains("\"attempt\""));
    let path = std::path::Path::new("/__rabs/out/cargo/test-executions");
    let previous: u32 = match std::fs::read_to_string(path) {
        Ok(value) => value.parse().unwrap(),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => 0,
        Err(error) => panic!("{error}"),
    };
    let current = previous + 1;
    std::fs::write(path, current.to_string()).unwrap();
    println!("CANONICAL_CURRENT_TEST_EXECUTION={current}");
    assert!(current < 3, "current test execution must report its present failure");
}
"#,
    );
    profile["command"] = json!("test");
    profile["target_cache"] = json!({"runtime_epoch":"native-tests-v1", "max_bytes":268435456});
    profile["selection"] = json!({"lib":true, "no_run":true});

    let (code, events, output) = run(owner.path(), 200, &profile);
    assert_eq!(code, 0, "{output}");
    assert_test_execution(&events, "cold", false);
    assert!(
        !output.contains("CANONICAL_CURRENT_TEST_EXECUTION="),
        "{output}"
    );
    let completed = events
        .iter()
        .filter(|event| event["kind"] == "canonical-build-completed")
        .collect::<Vec<_>>();
    assert_eq!(completed.len(), 1, "{output}");
    assert_eq!(completed[0]["command"], "test");
    assert_eq!(completed[0]["tests_executed"], false);
    assert_eq!(completed[0]["canonical_target"], "/__rabs/out/cargo");
    let target = PathBuf::from(completed[0]["target_directory"].as_str().unwrap());
    assert_eq!(fs::canonicalize(&target).unwrap(), target);
    let delivery_owner = target.parent().unwrap();
    assert_eq!(delivery_owner.parent().unwrap(), owner.path().join("ops"));
    assert_eq!(
        fs::read_dir(delivery_owner)
            .unwrap()
            .map(|entry| entry.unwrap().file_name())
            .collect::<Vec<_>>(),
        [std::ffi::OsString::from("target")],
        "test delivery must retain only the completed target"
    );
    assert!(!target.join("test-executions").exists());
    let artifacts = test_harness_artifacts(&output);
    assert_eq!(artifacts[0]["fresh"], false, "{output}");
    let relative = Path::new(artifacts[0]["executable"].as_str().unwrap())
        .strip_prefix("/__rabs/out/cargo")
        .unwrap();
    let harness = target.join(relative);
    let metadata = fs::symlink_metadata(&harness).unwrap();
    assert!(
        metadata.is_file() && metadata.len() > 0 && metadata.permissions().mode() & 0o111 != 0,
        "no-run must deliver the actual linked Cargo test harness"
    );

    // Exercise the delivered executable without running its test body, which
    // needs the live canonical endpoint. Cargo's reported path, not a guessed
    // target layout, identifies the harness.
    let mut command = Command::new(&harness);
    command
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .arg("--list")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let started = Instant::now();
    let listed = ManagedProcessGroup::spawn_command(command, Attribution::default())
        .unwrap()
        .wait_with_bounded_drain_budget(
            &DrainLimits::new(owner.path().join("delivered-test-list")),
            16 * 1024,
            || started.elapsed() > Duration::from_secs(10),
        )
        .unwrap();
    assert!(listed.status.success(), "{listed:?}");
    assert_eq!(listed.residual_group_members, 0);
    let mut listing = String::new();
    listed
        .stdout
        .reader()
        .unwrap()
        .read_to_string(&mut listing)
        .unwrap();
    assert!(
        listing.contains("current_test_execution: test"),
        "{listing}"
    );
    assert!(!target.join("test-executions").exists());

    profile["selection"] = json!({"lib":true, "test_filter":"current_test_execution",
        "test_args":["--nocapture","--test-threads=1"]});
    for current in 1..=4 {
        let (code, events, output) = run(owner.path(), 200 + current, &profile);
        assert_eq!(code, if current < 3 { 0 } else { 101 }, "{output}");
        assert_test_execution(&events, "restored", true);
        assert_eq!(
            test_harness_artifacts(&output)[0]["fresh"],
            true,
            "{output}"
        );
        assert!(
            output.contains(&format!("CANONICAL_CURRENT_TEST_EXECUTION={current}")),
            "fresh compilation state skipped or replayed a test execution: {output}"
        );
        assert_eq!(
            fs::read_to_string(sole_retained_target(owner.path()).join("test-executions")).unwrap(),
            current.to_string(),
            "both passing and failing test runs must retain only current private state"
        );
        assert!(!target.join("test-executions").exists());
    }
    assert_eq!(
        fs::read_dir(owner.path().join("ops")).unwrap().count(),
        1,
        "only the explicitly delivered no-run target may survive"
    );
}

#[test]
#[ignore = "requires real bubblewrap namespaces, native toolchain with rustdoc and RABS_CANONICAL_TEST_WRAPPER; executes actual Cargo documentation tests"]
fn canonical_cargo_doctests_execute_with_captured_rustdoc_and_preserve_failures() {
    let (owner, mut profile) = native_fixture();
    let rustdoc = Path::new(profile["toolchain_root"].as_str().unwrap()).join("bin/rustdoc");
    let metadata = fs::symlink_metadata(rustdoc).unwrap();
    assert!(
        metadata.is_file() && metadata.permissions().mode() & 0o111 != 0,
        "the captured native toolchain must contain its real rustdoc"
    );
    write(
        &owner.path().join("source-a"),
        "src/lib.rs",
        r#"/// The same compiled documentation example must execute on every request.
///
/// ```
/// assert_eq!(canonical_app::answer(), 42);
/// let path = std::path::Path::new("/__rabs/out/cargo/doctest-executions");
/// let previous: u32 = match std::fs::read_to_string(path) {
///     Ok(value) => value.parse().unwrap(),
///     Err(error) if error.kind() == std::io::ErrorKind::NotFound => 0,
///     Err(error) => panic!("{error}"),
/// };
/// let current = previous + 1;
/// std::fs::write(path, current.to_string()).unwrap();
/// assert!(current < 3, "current documentation test must report its present failure");
/// ```
pub fn answer() -> u32 { canonical_dep::answer() }
"#,
    );
    profile["command"] = json!("test");
    profile["selection"] = json!({"doc":true, "test_args":["--nocapture","--test-threads=1"]});
    profile["target_cache"] = json!({"runtime_epoch":"native-doctests-v1", "max_bytes":268435456});
    for current in 1..=3 {
        let (code, events, output) = run(owner.path(), 210 + current, &profile);
        assert_eq!(code, if current < 3 { 0 } else { 101 }, "{output}");
        assert_test_execution(
            &events,
            if current == 1 { "cold" } else { "restored" },
            true,
        );
        assert_eq!(
            fs::read_to_string(sole_retained_target(owner.path()).join("doctest-executions"))
                .unwrap(),
            current.to_string(),
            "captured rustdoc must run this request's example despite warm compilation: {output}"
        );
        if current == 3 {
            assert!(
                output.contains("current documentation test must report its present failure"),
                "{output}"
            );
        }
    }
    assert!(
        fs::read_dir(owner.path().join("ops"))
            .unwrap()
            .next()
            .is_none(),
        "documentation tests must not retain operation owners or deliver test outcomes"
    );
}

#[test]
#[ignore = "requires real bubblewrap namespaces, native toolchain and RABS_CANONICAL_TEST_WRAPPER; executes current programs with inherited input and private Cargo freshness"]
fn canonical_cargo_run_preserves_default_target_input_arguments_and_every_current_exit() {
    let (owner, mut profile) = native_fixture();
    let source = owner.path().join("source-a");
    let manifest = fs::read_to_string(source.join("Cargo.toml")).unwrap();
    write(
        &source,
        "Cargo.toml",
        manifest.replacen("[package]", "[package]\ndefault-run='canonical_app'", 1),
    );
    write(
        &source,
        "src/bin/unselected.rs",
        "compile_error!(\"run selected the wrong binary\"); fn main() {}\n",
    );
    write(
        &source,
        "src/main.rs",
        r#"use std::io::{BufRead, BufReader, Read, Write};
fn main() {
    assert_eq!(canonical_app::answer(), 42);
    let args = std::env::args().skip(1).collect::<Vec<_>>();
    assert_eq!(&args[..4], &["--literal", "", "雪", "line\nvalue"]);
    let mut input = String::new();
    std::io::stdin().read_to_string(&mut input).unwrap();
    assert_eq!(input, "current program input\n");
    let mut stream = std::os::unix::net::UnixStream::connect(std::env::var_os("RABS_SOCKET_PATH").unwrap()).unwrap();
    stream.set_read_timeout(Some(std::time::Duration::from_secs(10))).unwrap();
    let mut replies = BufReader::new(stream.try_clone().unwrap());
    writeln!(stream, "{{\"kind\":\"hello\",\"transport\":{{\"current\":1,\"minimum_compatible\":1}},\"application\":{{\"current\":1,\"minimum_compatible\":1}}}}").unwrap();
    let mut reply = String::new(); replies.read_line(&mut reply).unwrap();
    assert!(reply.contains("hello-ok"));
    writeln!(stream, "{{\"kind\":\"rustc-request\",\"argv\":[\"/__rabs/toolchain/bin/rustc\",\"--crate-name=forged-run\"],\"cwd\":\"/__rabs/workspace\",\"env\":[],\"remote_protocol\":1,\"local_capture_allowed\":true}}").unwrap();
    reply.clear(); replies.read_line(&mut reply).unwrap();
    assert!(reply.contains("canonical-project-executors-require-isolated-dependency-execution"));
    assert!(!reply.contains("\"attempt\""));
    let path = "/__rabs/out/cargo/program-executions";
    let count: u32 = std::fs::read_to_string(path).ok().map(|value| value.parse().unwrap()).unwrap_or(0) + 1;
    std::fs::write(path, count.to_string()).unwrap();
    println!("CURRENT_PROGRAM_EXECUTION={count}");
    if args.iter().any(|arg| arg == "--fail") { std::process::exit(7); }
}
"#,
    );
    profile["command"] = json!("run");
    profile["selection"] = json!({"run_args":["--literal", "", "雪", "line\nvalue"]});
    profile["target_cache"] = json!({"runtime_epoch":"native-run-v1", "max_bytes":268435456});
    for number in 1..=4 {
        if number == 3 {
            profile["selection"]["run_args"]
                .as_array_mut()
                .unwrap()
                .push(json!("--fail"));
        }
        let (code, events, output) = run_with_input(
            owner.path(),
            3000 + number,
            &profile,
            &[],
            b"current program input\n",
        );
        assert_eq!(code, if number < 3 { 0 } else { 7 }, "{output}");
        let started = events
            .iter()
            .find(|event| event["kind"] == "canonical-compilation-started")
            .unwrap();
        assert_eq!(started["run_execution"], true);
        assert_eq!(started["program_result_cache"], false);
        assert_eq!(
            started["private_target_state"],
            if number == 1 { "cold" } else { "restored" }
        );
        assert!(
            decisions(&events, "execute").is_empty() && decisions(&events, "hit").is_empty(),
            "{output}"
        );
        assert!(
            !events.iter().any(|event| event["decision"] == "served"
                || event["kind"] == "canonical-build-completed"),
            "{output}"
        );
        assert!(
            output.contains(&format!("CURRENT_PROGRAM_EXECUTION={number}")),
            "{output}"
        );
        assert_eq!(
            fs::read_to_string(sole_retained_target(owner.path()).join("program-executions"))
                .unwrap(),
            number.to_string()
        );
        let binary = output
            .lines()
            .filter_map(|line| serde_json::from_str::<Value>(line).ok())
            .find(|event| {
                event["reason"] == "compiler-artifact" && event["target"]["kind"] == json!(["bin"])
            })
            .unwrap();
        assert_eq!(binary["fresh"], number != 1, "{output}");
    }
    assert!(
        fs::read_dir(owner.path().join("ops"))
            .unwrap()
            .next()
            .is_none()
    );
}

#[test]
#[ignore = "requires real bubblewrap namespaces, native toolchain and RABS_CANONICAL_TEST_WRAPPER; executes custom benchmarks and verifies no-run delivery plus warm execution"]
fn canonical_cargo_bench_delivers_no_run_then_executes_each_current_custom_harness() {
    let (owner, mut profile) = native_fixture();
    let source = owner.path().join("source-a");
    let manifest = fs::read_to_string(source.join("Cargo.toml")).unwrap();
    write(
        &source,
        "Cargo.toml",
        format!("{manifest}\n[[bench]]\nname='timing'\npath='benches/timing.rs'\nharness=false\n"),
    );
    write(
        &source,
        "benches/timing.rs",
        r#"fn main() {
    assert_eq!(canonical_app::answer(), 42);
    assert!(!cfg!(debug_assertions), "bench lost its default release profile");
    let args = std::env::args().skip(1).collect::<Vec<_>>();
    assert!(args.iter().any(|arg| arg == "selected"));
    assert!(args.windows(3).any(|args| args == ["--literal", "", "雪"]));
    let path = "/__rabs/out/cargo/benchmark-executions";
    let count: u32 = std::fs::read_to_string(path).ok().map(|value| value.parse().unwrap()).unwrap_or(0) + 1;
    std::fs::write(path, count.to_string()).unwrap();
    println!("CURRENT_BENCHMARK_EXECUTION={count}");
    if count >= 3 { std::process::exit(11); }
}
"#,
    );
    profile["command"] = json!("bench");
    profile["selection"] = json!({"bench":["timing"], "no_run":true});
    profile["target_cache"] = json!({"runtime_epoch":"native-bench-v1", "max_bytes":268435456});
    let (code, events, output) = run(owner.path(), 3100, &profile);
    assert_eq!(code, 0, "{output}");
    assert!(!output.contains("CURRENT_BENCHMARK_EXECUTION="), "{output}");
    let delivered = events
        .iter()
        .find(|event| event["kind"] == "canonical-build-completed")
        .unwrap();
    assert_eq!(delivered["command"], "bench");
    let delivered_target = PathBuf::from(delivered["target_directory"].as_str().unwrap());
    assert!(!delivered_target.join("benchmark-executions").exists());
    let benchmark = output
        .lines()
        .filter_map(|line| serde_json::from_str::<Value>(line).ok())
        .find(|event| event["reason"] == "compiler-artifact" && event["target"]["name"] == "timing")
        .unwrap();
    let relative = Path::new(benchmark["executable"].as_str().unwrap())
        .strip_prefix("/__rabs/out/cargo")
        .unwrap();
    let executable = fs::symlink_metadata(delivered_target.join(relative)).unwrap();
    assert!(
        executable.is_file()
            && executable.len() > 0
            && executable.permissions().mode() & 0o111 != 0
    );
    profile["selection"] =
        json!({"bench":["timing"], "test_filter":"selected", "test_args":["--literal", "", "雪"]});
    for number in 1..=4 {
        let (code, events, output) = run(owner.path(), 3100 + number, &profile);
        if number < 3 {
            assert_eq!(code, 0, "{output}");
        } else {
            assert_ne!(code, 0, "{output}");
        }
        let started = events
            .iter()
            .find(|event| event["kind"] == "canonical-compilation-started")
            .unwrap();
        assert_eq!(started["benchmark_execution"], true);
        assert_eq!(started["benchmark_result_cache"], false);
        assert_eq!(started["private_target_state"], "restored");
        assert!(
            decisions(&events, "execute").is_empty() && decisions(&events, "hit").is_empty(),
            "{output}"
        );
        assert!(
            !events.iter().any(|event| event["decision"] == "served"
                || event["kind"] == "canonical-build-completed"),
            "{output}"
        );
        assert!(
            output.contains(&format!("CURRENT_BENCHMARK_EXECUTION={number}")),
            "{output}"
        );
        assert_eq!(
            fs::read_to_string(sole_retained_target(owner.path()).join("benchmark-executions"))
                .unwrap(),
            number.to_string()
        );
        assert!(!delivered_target.join("benchmark-executions").exists());
    }
}

fn sole_retained_target(root: &Path) -> PathBuf {
    let families = fs::read_dir(root.join("state/canonical-compile-v1/private-target-v2"))
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .collect::<Vec<_>>();
    assert_eq!(
        families.len(),
        1,
        "this test must retain one compatible family"
    );
    let target = families[0].join("seed/target");
    assert!(target.is_dir(), "the family must have a committed target");
    target
}

fn read_bounded(path: &Path) -> Vec<u8> {
    const MAXIMUM: u64 = 4 * 1024 * 1024;
    let mut bytes = Vec::new();
    fs::File::open(path)
        .unwrap()
        .take(MAXIMUM + 1)
        .read_to_end(&mut bytes)
        .unwrap();
    assert!(
        bytes.len() as u64 <= MAXIMUM,
        "oversized fixture file: {}",
        path.display()
    );
    bytes
}

// Other native integration binaries have private certificate fixtures. Keep
// this one limited to a CA and the identities consumed by the production
// outward-worker transport; every OpenSSL process has a finite group lifetime.
fn native_certificates(root: &Path, workers: &[&str]) -> (TlsFiles, Vec<TlsFiles>) {
    fs::create_dir(root).unwrap();
    let openssl = |name: &str, arguments: &[&str]| {
        let mut command = Command::new("/usr/bin/openssl");
        command
            .env_clear()
            .env("PATH", "/usr/bin:/bin")
            .current_dir(root)
            .args(arguments)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let started = Instant::now();
        let output = ManagedProcessGroup::spawn_command(command, Attribution::default())
            .unwrap()
            .wait_with_bounded_drain_budget(
                &DrainLimits::new(root.join(format!("drain-{name}"))),
                1024 * 1024,
                || started.elapsed() > Duration::from_secs(20),
            )
            .unwrap();
        let mut stderr = String::new();
        output
            .stderr
            .reader()
            .unwrap()
            .read_to_string(&mut stderr)
            .unwrap();
        assert!(output.status.success(), "OpenSSL {name}: {stderr}");
        assert!(
            started.elapsed() < Duration::from_secs(20),
            "OpenSSL {name} timed out"
        );
        assert_eq!(output.residual_group_members, 0);
    };
    openssl(
        "ca",
        &[
            "req",
            "-x509",
            "-newkey",
            "rsa:2048",
            "-nodes",
            "-sha256",
            "-days",
            "1",
            "-subj",
            "/CN=Canonical dependency test CA",
            "-keyout",
            "ca.key",
            "-out",
            "ca.pem",
            "-addext",
            "basicConstraints=critical,CA:TRUE",
            "-addext",
            "keyUsage=critical,keyCertSign,cRLSign",
        ],
    );
    for (index, name) in std::iter::once("coordinator")
        .chain(workers.iter().copied())
        .enumerate()
    {
        let usage = if index == 0 {
            "serverAuth"
        } else {
            "clientAuth"
        };
        let serial = (index + 2).to_string();
        let key = format!("{name}.key");
        let csr = format!("{name}.csr");
        let certificate = format!("{name}.pem");
        let extensions = format!("{name}.ext");
        openssl(
            &format!("{name}-request"),
            &[
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
            ],
        );
        fs::write(root.join(&extensions), format!("basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage={usage}\nsubjectAltName=DNS:localhost\n")).unwrap();
        openssl(
            &format!("{name}-sign"),
            &[
                "x509",
                "-req",
                "-in",
                &csr,
                "-CA",
                "ca.pem",
                "-CAkey",
                "ca.key",
                "-set_serial",
                &serial,
                "-days",
                "1",
                "-sha256",
                "-extfile",
                &extensions,
                "-out",
                &certificate,
            ],
        );
    }
    let files = |name: &str| TlsFiles {
        ca: root.join("ca.pem"),
        certificate: root.join(format!("{name}.pem")),
        private_key: root.join(format!("{name}.key")),
    };
    (
        files("coordinator"),
        workers.iter().map(|name| files(name)).collect(),
    )
}

struct NativeWorker {
    process: Option<ManagedProcessGroup>,
    state: PathBuf,
    temporary: PathBuf,
    stdout: PathBuf,
    stderr: PathBuf,
    drain: PathBuf,
}

impl NativeWorker {
    fn start(root: &Path) -> (Self, Vec<(String, String)>) {
        const ID: &str = "canonical-dependency-worker";
        let (coordinator, workers) = native_certificates(&root.join("credentials"), &["worker"]);
        Self::start_with_identity(root, ID, &coordinator, &workers[0])
    }

    fn start_with_identity(
        root: &Path,
        id: &str,
        coordinator: &TlsFiles,
        worker: &TlsFiles,
    ) -> (Self, Vec<(String, String)>) {
        let binary = fs::canonicalize(
            std::env::var_os("RABS_TEST_WORKER_BIN")
                .expect("set RABS_TEST_WORKER_BIN to the matching native rabs-wkr"),
        )
        .unwrap();
        let reserved = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = reserved.local_addr().unwrap().to_string();
        let pin: String = worker
            .local_identity()
            .unwrap()
            .fingerprint
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect();
        let environment = vec![
            ("RABS_DEPENDENCY_WORKER_LISTEN".into(), address.clone()),
            ("RABS_DEPENDENCY_WORKER_ID".into(), id.into()),
            ("RABS_DEPENDENCY_WORKER_SPKI_SHA256".into(), pin),
            (
                "RABS_COORD_TLS_CA".into(),
                coordinator.ca.display().to_string(),
            ),
            (
                "RABS_COORD_TLS_CERT".into(),
                coordinator.certificate.display().to_string(),
            ),
            (
                "RABS_COORD_TLS_KEY".into(),
                coordinator.private_key.display().to_string(),
            ),
        ];
        let state = root.join("worker-state");
        let temporary = root.join("worker-tmp");
        fs::DirBuilder::new()
            .mode(0o700)
            .create(&temporary)
            .unwrap();
        let stdout = root.join("worker.stdout");
        let stderr = root.join("worker.stderr");
        let mut command = Command::new(binary);
        command
            .env_clear()
            .env("PATH", "/usr/bin:/bin")
            .env("TMPDIR", &temporary)
            .args(["--coordinator", &address, "--worker-id", id])
            .env("RABS_WORKER_STATE_DIR", &state)
            .env(
                "RABS_WORKER_TOOLCHAIN_CACHE_BYTES",
                rabs_sandbox::toolchain_dataset::ToolchainLimits::default()
                    .max_bytes
                    .to_string(),
            )
            .env("RABS_WORKER_TLS_CA", &worker.ca)
            .env("RABS_WORKER_TLS_CERT", &worker.certificate)
            .env("RABS_WORKER_TLS_KEY", &worker.private_key)
            .env("RABS_WORKER_TLS_SERVER_NAME", "localhost")
            .stdin(Stdio::null())
            .stdout(fs::File::create(&stdout).unwrap())
            .stderr(fs::File::create(&stderr).unwrap());
        // A collision now fails authenticated admission; a foreign listener
        // cannot satisfy this freshly generated worker/coordinator identity.
        drop(reserved);
        let process = ManagedProcessGroup::spawn_command(command, Attribution::default()).unwrap();
        (
            Self {
                process: Some(process),
                state,
                temporary,
                stdout,
                stderr,
                drain: root.join("worker-stop"),
            },
            environment,
        )
    }

    /// Called only after stopping a fresh worker, whose empty request journal
    /// excludes an earlier execution and whose launch has no durable cache.
    /// Missing bytes in its private upload tree are stronger evidence than an
    /// empty journal: the sender cannot have received the required ready reply
    /// and started writing an execution frame that has not been journaled yet.
    fn assert_fresh_toolchain_upload_incomplete(&self, source: &Path) {
        let mut pending = vec![PathBuf::new()];
        let mut required: Option<(PathBuf, u64)> = None;
        while let Some(relative) = pending.pop() {
            let metadata = fs::symlink_metadata(source.join(&relative)).unwrap();
            if metadata.is_dir() {
                for entry in fs::read_dir(source.join(&relative)).unwrap() {
                    pending.push(relative.join(entry.unwrap().file_name()));
                }
            } else if metadata.is_file()
                && metadata.len() != 0
                && required.as_ref().is_none_or(|(last, _)| relative > *last)
            {
                required = Some((relative, metadata.len()));
            }
        }
        let (relative, bytes) = required.expect("the native toolchain must contain file bytes");
        let mut uploads = 0;
        for entry in fs::read_dir(&self.temporary).unwrap() {
            let entry = entry.unwrap();
            if !entry
                .file_name()
                .as_encoded_bytes()
                .starts_with(b"rabs-toolchain-upload-")
            {
                continue;
            }
            uploads += 1;
            assert!(entry.file_type().unwrap().is_dir());
            let member = entry.path().join("dataset").join(&relative);
            match fs::symlink_metadata(&member) {
                Ok(metadata) => assert!(
                    metadata.is_file() && metadata.len() < bytes,
                    "the test missed the incomplete upload window: {}",
                    member.display()
                ),
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => panic!("cannot inspect {}: {error}", member.display()),
            }
        }
        assert!(uploads <= 1, "a fresh worker must own at most one upload");
    }

    fn events(&self) -> Vec<Value> {
        [&self.stdout, &self.stderr]
            .into_iter()
            .flat_map(|path| {
                String::from_utf8(read_bounded(path))
                    .unwrap()
                    .lines()
                    .filter_map(|line| serde_json::from_str::<Value>(line).ok())
                    .collect::<Vec<_>>()
            })
            .collect()
    }

    fn completed_receipt(&mut self) -> Value {
        let until = Instant::now() + Duration::from_secs(15);
        loop {
            assert!(
                self.process
                    .as_mut()
                    .unwrap()
                    .leader_try_wait()
                    .unwrap()
                    .is_none(),
                "native worker exited: {}",
                String::from_utf8_lossy(&read_bounded(&self.stderr))
            );
            if self.state.join("requests.json").is_file() {
                let state: Value =
                    serde_json::from_slice(&read_bounded(&self.state.join("requests.json")))
                        .unwrap();
                let last = &state["last"];
                if last["resolved"] == true && last["receipt"]["retained_result_released"] == true {
                    assert_eq!(last["receipt"]["executed"], true);
                    assert_eq!(last["receipt"]["exit_code"], 0);
                    assert_eq!(last["receipt"]["residual_group_members"], 0);
                    assert!(last["receipt"]["stop_reason"].is_null());
                    return last.clone();
                }
            }
            assert!(
                Instant::now() < until,
                "worker result did not settle: {:?}",
                self.events()
            );
            std::thread::sleep(Duration::from_millis(10));
        }
    }

    fn finish(mut self) {
        let output = self
            .process
            .take()
            .unwrap()
            .wait_with_bounded_drain_budget(&DrainLimits::new(&self.drain), 0, || true)
            .unwrap();
        assert_eq!(
            output.residual_group_members, 0,
            "native worker outlived its test owner"
        );
    }
}

impl Drop for NativeWorker {
    fn drop(&mut self) {
        if let Some(process) = self.process.take() {
            let _ =
                process.wait_with_bounded_drain_budget(&DrainLimits::new(&self.drain), 0, || true);
        }
    }
}

fn assert_answer(root: &Path, answer: u32, workspace_edit: bool) {
    write(
        root,
        "src/lib.rs",
        format!(
            "#[cfg(not(feature=\"remote_workspace\"))]\ncompile_error!(\"selected workspace feature was lost\");\nconst _: &str = env!(\"CARGO_PRIMARY_PACKAGE\");\nconst _: &str = include_str!(\"../workspace-readme.txt\");\nconst _: [(); {answer}] = [(); canonical_dep::answer() as usize];\npub fn answer()->u32 {{ canonical_dep::answer()+{} }}\n",
            u32::from(workspace_edit)
        ),
    );
}

fn workspace_execution_feature(root: &Path) {
    let manifest = fs::read_to_string(root.join("Cargo.toml")).unwrap();
    write(
        root,
        "Cargo.toml",
        format!("{manifest}\n[features]\nremote_workspace=[]\n"),
    );
    write(
        root,
        "workspace-readme.txt",
        "retained workspace input outside src\n",
    );
    fs::create_dir_all(root.join("empty-workspace/nested")).unwrap();
}

fn distinct_check_binary(root: &Path) {
    // Keep one binary with an independently observable crate name. The build
    // variants retain canonical_app as their linked executable.
    write(
        root,
        "Cargo.toml",
        "[package]\nname='canonical_app'\nversion='0.1.0'\nedition='2021'\nautobins=false\n[dependencies]\ncanonical_dep='=1.0.0'\noptional_build={path='optional-build',optional=true}\n[dev-dependencies]\ndev_macro={path='dev-macro'}\n[features]\nremote_workspace=[]\n[[bin]]\nname='canonical_cli'\npath='src/main.rs'\n",
    );
}

/// Read the real production store only after the canonical driver has exited.
/// A successful fresh workspace compile may retain CAS byte objects, but must
/// never create an action publication, serving record or replay qualification.
fn assert_fresh_workspace_execution(
    root: &Path,
    events: &[Value],
    output: &str,
    name: &str,
    key: &str,
    observed: &mut BTreeMap<String, BTreeSet<String>>,
) -> String {
    use rabs_cas::metadata_store::{RabsMetadataStore, SqlValue};

    let key = key.to_owned();
    assert!(
        events.iter().any(|event| {
            event["kind"] == "rabsd-live-dependency"
                && event["decision"] == "remote-offer"
                && event["crate"] == name
                && event["key"] == key
        }),
        "the actual workspace unit {name} was not offered remotely: {output}"
    );
    assert!(
        events.iter().any(|event| {
            event["kind"] == "rabsd-remote-dependency-executed" && event["key"] == key
        }),
        "workspace unit {name} did not complete through the worker: {output}"
    );
    assert!(
        !decisions(events, "hit").contains_key(name),
        "workspace result was replayed: {output}"
    );
    assert!(
        !decisions(events, "execute").contains_key(name),
        "workspace result used local cache capture: {output}"
    );
    let cas =
        rabsd::janitor::store::mount_and_reconcile(&root.join("state/canonical-compile-v1/cas"))
            .unwrap();
    let mut store = cas.store().lock().unwrap();
    assert!(
        store.published_manifest_key_str(&key).unwrap().is_none(),
        "workspace result was published"
    );
    assert!(
        !store.has_serving_state_key(&key).unwrap(),
        "workspace gained a serving record"
    );
    assert!(
        !store.has_evidence_key(&key).unwrap(),
        "workspace gained publication evidence"
    );
    assert!(
        store
            .query(
                "SELECT attempt_hex FROM verification_samples WHERE action_key = ?1",
                &[SqlValue::Text(key.clone())],
            )
            .unwrap()
            .is_empty(),
        "workspace gained replay verification samples"
    );
    assert!(
        store
            .query(
                "SELECT decision FROM decision_receipts WHERE kind = ?1 AND subject = ?2",
                &[
                    SqlValue::Text(rabsd::coord::live_dependency::LIVE_TRANSCRIPT_RECEIPT.into()),
                    SqlValue::Text(key.clone()),
                ],
            )
            .unwrap()
            .is_empty(),
        "workspace transcript was indexed for cache replay"
    );
    let attempts = store
        .query(
            "SELECT a.id_hex FROM action_attempts a JOIN action_generations g \
         ON a.generation_hex = g.id_hex WHERE g.action_key = ?1 ORDER BY a.id_hex",
            &[SqlValue::Text(key.clone())],
        )
        .unwrap()
        .into_iter()
        .map(|row| {
            let [SqlValue::Text(attempt)] = row.as_slice() else {
                panic!("unexpected workspace execution attempt row: {row:?}");
            };
            attempt.clone()
        })
        .collect::<BTreeSet<_>>();
    assert!(
        !attempts.is_empty(),
        "workspace completion lacks an actual admitted attempt"
    );
    if let Some(previous) = observed.insert(key.clone(), attempts.clone()) {
        assert!(attempts.is_superset(&previous));
        assert_eq!(
            attempts.len(),
            previous.len() + 1,
            "an identical workspace request must acquire a fresh attempt"
        );
    }
    key
}

fn assert_fresh_workspace_units(
    root: &Path,
    events: &[Value],
    output: &str,
    names: &[&str],
    observed: &mut BTreeMap<String, BTreeSet<String>>,
) -> BTreeMap<String, String> {
    let offered = decisions(events, "remote-offer");
    names
        .iter()
        .map(|name| {
            let key = offered
                .get(*name)
                .unwrap_or_else(|| panic!("workspace unit {name} was not offered: {output}"));
            (
                name.to_string(),
                assert_fresh_workspace_execution(root, events, output, name, key, observed),
            )
        })
        .collect()
}

/// Resolve Cargo's actual artifact records into the retained target tree.
/// The pinned Cargo uses per-unit build directories; guessing `debug/deps`
/// misses valid outputs and would never exercise the worker/cache assertions.
fn delivered_cargo_outputs(target: &Path, output: &str, name: &str, suffix: &str) -> Vec<PathBuf> {
    output
        .lines()
        .filter_map(|line| serde_json::from_str::<Value>(line).ok())
        .filter(|event| event["reason"] == "compiler-artifact" && event["target"]["name"] == name)
        .flat_map(|event| event["filenames"].as_array().unwrap().clone())
        .filter_map(|filename| {
            let filename = PathBuf::from(filename.as_str().unwrap());
            (filename
                .extension()
                .and_then(|extension| extension.to_str())
                == Some(suffix))
            .then_some(filename)
        })
        .map(|filename| {
            let relative = filename.strip_prefix("/__rabs/out/cargo").unwrap();
            assert!(
                !relative.as_os_str().is_empty()
                    && relative
                        .components()
                        .all(|part| matches!(part, std::path::Component::Normal(_))),
                "Cargo reported an escaping artifact: {}",
                filename.display()
            );
            let physical = target.join(relative);
            assert_eq!(
                fs::canonicalize(&physical).unwrap(),
                physical,
                "Cargo output must resolve inside its ordinary retained target tree"
            );
            assert!(fs::symlink_metadata(&physical).unwrap().is_file());
            physical
        })
        .collect()
}

/// Validate the delivered user output, including a real executable consuming
/// the remotely produced or replayed archives. The driver may retain only the
/// target tree after its coordinator, wrapper sessions and compiler have drained.
fn delivered_build(
    root: &Path,
    number: u32,
    events: &[Value],
    output: &str,
    answer: u32,
) -> (PathBuf, BTreeMap<String, Vec<u8>>) {
    let completed = events
        .iter()
        .filter(|event| event["kind"] == "canonical-build-completed")
        .collect::<Vec<_>>();
    assert_eq!(
        completed.len(),
        1,
        "each successful build must report exactly one delivered target"
    );
    let event = completed[0];
    assert_eq!(event["version"], "canonical-compile-local-v1");
    assert_eq!(event["canonical_target"], "/__rabs/out/cargo");
    let target = PathBuf::from(event["target_directory"].as_str().unwrap());
    assert_eq!(target.file_name().unwrap(), "target");
    assert_eq!(
        fs::canonicalize(&target).unwrap(),
        target,
        "delivered target must be an ordinary physical directory"
    );
    let owner = target.parent().unwrap().to_path_buf();
    assert_eq!(owner.parent().unwrap(), root.join("ops"));
    assert!(
        owner
            .file_name()
            .unwrap()
            .to_str()
            .unwrap()
            .starts_with("rabs-build-")
    );
    assert_eq!(
        fs::metadata(&owner).unwrap().permissions().mode() & 0o777,
        0o700
    );
    let retained = fs::read_dir(&owner)
        .unwrap()
        .map(|entry| entry.unwrap().file_name())
        .collect::<Vec<_>>();
    assert_eq!(
        retained,
        [std::ffi::OsString::from("target")],
        "source, Cargo home, toolchain and control socket must not survive output delivery"
    );

    let mut archives = BTreeMap::new();
    for name in ["canonical_leaf", "canonical_dep"] {
        let candidates = delivered_cargo_outputs(&target, output, name, "rlib");
        assert_eq!(
            candidates.len(),
            1,
            "missing or ambiguous delivered {name} archive"
        );
        assert!(fs::symlink_metadata(&candidates[0]).unwrap().is_file());
        let bytes = read_bounded(&candidates[0]);
        assert!(
            bytes.len() > 8 && bytes.starts_with(b"!<arch>\n"),
            "delivered {name} must be a real nonempty Rust archive"
        );
        archives.insert(name.to_owned(), bytes);
    }

    let binary = target.join("debug/canonical_app");
    let metadata = fs::symlink_metadata(&binary).unwrap();
    assert!(
        metadata.is_file() && metadata.len() > 0 && metadata.permissions().mode() & 0o111 != 0,
        "Cargo build must deliver its linked executable"
    );
    let mut command = Command::new(&binary);
    command
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .current_dir(root)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let started = Instant::now();
    let output = ManagedProcessGroup::spawn_command(command, Attribution::default())
        .unwrap()
        .wait_with_bounded_drain_budget(
            &DrainLimits::new(root.join(format!("delivered-binary-{number}"))),
            16 * 1024,
            || started.elapsed() > Duration::from_secs(10),
        )
        .unwrap();
    assert!(
        started.elapsed() < Duration::from_secs(10),
        "delivered binary timed out"
    );
    assert!(
        output.status.success(),
        "delivered binary failed: {:?}",
        output.status
    );
    assert_eq!(output.residual_group_members, 0);
    let mut stdout = Vec::new();
    output
        .stdout
        .reader()
        .unwrap()
        .read_to_end(&mut stdout)
        .unwrap();
    assert_eq!(
        stdout,
        format!("{answer}\n").as_bytes(),
        "linked binary used stale or incorrect dependency code"
    );
    let mut stderr = Vec::new();
    output
        .stderr
        .reader()
        .unwrap()
        .read_to_end(&mut stderr)
        .unwrap();
    assert!(stderr.is_empty(), "{:?}", String::from_utf8_lossy(&stderr));
    (owner, archives)
}

#[test]
#[ignore = "requires full Linux bubblewrap isolation, OpenSSL, matching RABS_CANONICAL_TEST_WRAPPER and RABS_TEST_WORKER_BIN; actual Cargo/TLS worker/cache execution"]
fn canonical_cargo_offloads_real_dependency_samples_then_replays_across_worktrees() {
    remote_dependency_replay("check", GeneratedDependency::None);
}

#[test]
#[ignore = "requires full Linux bubblewrap isolation, OpenSSL, matching RABS_CANONICAL_TEST_WRAPPER and RABS_TEST_WORKER_BIN; actual Cargo build/TLS worker/archive cache and linked binary execution"]
fn canonical_cargo_build_offloads_archives_replays_and_delivers_a_working_binary() {
    remote_dependency_replay("build", GeneratedDependency::None);
}

#[test]
#[ignore = "requires full Linux bubblewrap isolation, OpenSSL, matching RABS_CANONICAL_TEST_WRAPPER and RABS_TEST_WORKER_BIN; actual generated-input Cargo/TLS worker/cache execution"]
fn canonical_cargo_offloads_generated_metadata_replays_and_invalidates_changed_out_dir() {
    remote_dependency_replay("check", GeneratedDependency::Consumer);
}

#[test]
#[ignore = "requires full Linux bubblewrap isolation, OpenSSL, matching RABS_CANONICAL_TEST_WRAPPER and RABS_TEST_WORKER_BIN; actual generated-input Cargo/TLS worker/archive execution"]
fn canonical_cargo_build_offloads_generated_archives_and_delivers_changed_output() {
    remote_dependency_replay("build", GeneratedDependency::Consumer);
}

#[test]
#[ignore = "requires full Linux bubblewrap isolation, OpenSSL, matching RABS_CANONICAL_TEST_WRAPPER and RABS_TEST_WORKER_BIN; actual generated-source Cargo/TLS worker/cache execution"]
fn canonical_cargo_offloads_generated_dependency_metadata_and_invalidates_generated_bytes() {
    remote_dependency_replay("check", GeneratedDependency::Leaf);
}

#[test]
#[ignore = "requires full Linux bubblewrap isolation, OpenSSL, matching RABS_CANONICAL_TEST_WRAPPER and RABS_TEST_WORKER_BIN; actual generated-source archive cache and linked binary execution"]
fn canonical_cargo_build_offloads_generated_archives_and_delivers_current_generated_code() {
    remote_dependency_replay("build", GeneratedDependency::Leaf);
}

#[test]
#[ignore = "requires full Linux bubblewrap isolation, cc, ar, OpenSSL, matching RABS_CANONICAL_TEST_WRAPPER and RABS_TEST_WORKER_BIN; actual generated native archive execution, remote cache replay and linked binary validation"]
fn canonical_cargo_build_bundles_generated_native_archives_replays_and_invalidates_them() {
    remote_dependency_replay("build", GeneratedDependency::NativeConsumer);
}

#[test]
#[ignore = "requires full Linux bubblewrap isolation, cc, ar, OpenSSL, matching RABS_CANONICAL_TEST_WRAPPER and RABS_TEST_WORKER_BIN; actual native-input Cargo checks, worker sampling, cache replay and archive-only invalidation"]
fn canonical_cargo_check_offloads_native_dependency_metadata_replays_and_invalidates_archives() {
    remote_dependency_replay("check", GeneratedDependency::NativeConsumer);
}

#[test]
#[ignore = "requires full Linux bubblewrap isolation, cc, ar, OpenSSL, matching RABS_CANONICAL_TEST_WRAPPER and RABS_TEST_WORKER_BIN; actual transitive generated native roots, dependency replay and delivered executable validation"]
fn canonical_cargo_build_offloads_propagated_native_archives_and_invalidates_transitive_consumers()
{
    remote_dependency_replay("build", GeneratedDependency::NativeLeaf);
}

#[test]
#[ignore = "requires full Linux bubblewrap isolation, cc, ar, OpenSSL, matching RABS_CANONICAL_TEST_WRAPPER and RABS_TEST_WORKER_BIN; actual transitive native metadata checks and archive-only cache invalidation"]
fn canonical_cargo_check_offloads_propagated_native_roots_and_invalidates_transitive_consumers() {
    remote_dependency_replay("check", GeneratedDependency::NativeLeaf);
}

#[test]
#[ignore = "requires full Linux bubblewrap isolation, cc, ar, OpenSSL, matching RABS_CANONICAL_TEST_WRAPPER and RABS_TEST_WORKER_BIN; actual fresh workspace native archive execution, dependency replay and linked binary validation"]
fn canonical_cargo_build_executes_own_native_workspace_archives_fresh_while_dependencies_replay() {
    remote_native_workspace("build");
}

#[test]
#[ignore = "requires full Linux bubblewrap isolation, cc, ar, OpenSSL, matching RABS_CANONICAL_TEST_WRAPPER and RABS_TEST_WORKER_BIN; actual fresh workspace native metadata, dependency replay, invalidation and modifier refusal"]
fn canonical_cargo_check_executes_own_native_workspace_metadata_fresh_while_dependencies_replay() {
    remote_native_workspace("check");
}

fn remote_native_workspace(command: &str) {
    let (owner, mut profile) = native_fixture();
    let source = owner.path().join("source-a");
    generated_native_workspace(&source);
    let build = command == "build";
    profile["command"] = json!(command);
    profile["selection"] = json!({"features":["remote_workspace"]});
    if !build {
        profile["selection"]["lib"] = json!(true);
    }
    let (mut worker, environment) = NativeWorker::start(owner.path());
    let mut dependency_keys = None;
    let mut dependency_archives = None;
    let mut workspace_attempts = BTreeMap::new();
    let mut previous_workspace = None;
    let mut previous_archive = None;
    let mut receipt: Option<Value> = None;
    let mut retained_targets = BTreeSet::new();

    for number in 1..=5 {
        let cold = number <= 3;
        if number == 5 {
            // Change only the native generator's input. Cargo manifests,
            // build.rs, Rust sources and external package bytes are unchanged.
            write(&source, "workspace-native-value.txt", "2\n");
        }
        let (code, events, output) =
            run_with_environment(owner.path(), 500 + number, &profile, &environment);
        assert_eq!(code, 0, "{output}\nworker: {:?}", worker.events());
        let archive = if build {
            let (target, archives) = delivered_build(
                owner.path(),
                500 + number,
                &events,
                &output,
                if number == 5 { 44 } else { 43 },
            );
            assert!(retained_targets.insert(target.clone()));
            if let Some(expected) = &dependency_archives {
                assert_eq!(
                    &archives, expected,
                    "own workspace native inputs changed the external dependency archives"
                );
            } else {
                dependency_archives = Some(archives);
            }
            let workspace_archives =
                delivered_cargo_outputs(&target.join("target"), &output, "canonical_app", "rlib");
            assert_eq!(workspace_archives.len(), 1, "{output}");
            let archive = read_bounded(&workspace_archives[0]);
            assert!(archive.len() > 8 && archive.starts_with(b"!<arch>\n"));
            Some(archive)
        } else {
            assert!(
                !events
                    .iter()
                    .any(|event| event["kind"] == "canonical-build-completed"),
                "metadata checks must not deliver an executable or archive: {output}"
            );
            None
        };

        let workspace = assert_fresh_workspace_units(
            owner.path(),
            &events,
            &output,
            &["canonical_app"],
            &mut workspace_attempts,
        );
        if number == 5 {
            assert_ne!(
                Some(&workspace),
                previous_workspace.as_ref(),
                "changed own native inputs reused the previous workspace execution key"
            );
            if build {
                assert_ne!(
                    archive, previous_archive,
                    "changed own native inputs reused stale workspace archive bytes"
                );
            }
        }
        previous_workspace = Some(workspace.clone());
        previous_archive = archive;
        let offered = decisions(&events, "remote-offer");
        if cold {
            assert_eq!(offered.len(), 3, "{output}");
            assert!(
                offered.contains_key("canonical_leaf") && offered.contains_key("canonical_dep"),
                "{output}"
            );
            assert!(decisions(&events, "hit").is_empty(), "{output}");
            let external = offered
                .iter()
                .filter(|(name, _)| name.as_str() != "canonical_app")
                .map(|(name, key)| (name.clone(), key.clone()))
                .collect::<BTreeMap<_, _>>();
            if let Some(expected) = &dependency_keys {
                assert_eq!(
                    &external, expected,
                    "fresh native workspace runs split dependency keys"
                );
            } else {
                dependency_keys = Some(external);
            }
        } else {
            assert_eq!(
                offered, workspace,
                "only the workspace must execute on a warm build: {output}"
            );
            assert_eq!(
                Some(&decisions(&events, "hit")),
                dependency_keys.as_ref(),
                "unchanged dependencies must replay while own native inputs compile afresh: {output}"
            );
            assert_eq!(
                events
                    .iter()
                    .filter(|event| event["decision"] == "served")
                    .count(),
                2,
                "{output}"
            );
        }
        let completed = events
            .iter()
            .filter(|event| event["kind"] == "rabsd-remote-dependency-executed")
            .filter_map(|event| event["key"].as_str())
            .collect::<BTreeSet<_>>();
        assert_eq!(
            completed,
            offered
                .values()
                .map(String::as_str)
                .collect::<BTreeSet<_>>(),
            "{output}"
        );
        assert!(decisions(&events, "execute").is_empty(), "{output}");
        assert!(
            !events.iter().any(|event| matches!(
                event["kind"].as_str(),
                Some("rabsd-remote-dependency-failed" | "rabsd-remote-dependency-install-failed")
            )),
            "{output}"
        );
        let next = worker.completed_receipt();
        if let Some(previous) = &receipt {
            assert!(
                next["request_id"].as_u64().unwrap()
                    >= previous["request_id"].as_u64().unwrap() + if cold { 3 } else { 1 },
                "fresh workspace compilation reused an earlier worker receipt"
            );
        }
        receipt = Some(next);
        assert_eq!(
            worker
                .events()
                .iter()
                .filter(|event| event["kind"] == "worker-toolchain-acquired")
                .count(),
            if cold {
                3 * number as usize
            } else {
                9 + number as usize - 3
            },
            "each qualifying dependency and every workspace compile must reach the worker"
        );
    }
    if !build {
        // The exact same stock Cargo check accepts this valid rustc modifier,
        // but it is outside the worker's default static-bundle contract. It
        // must compile locally without acquiring execution or cache authority.
        write(&source, "workspace-native-kind.txt", "static:-bundle\n");
        let (code, events, output) =
            run_with_environment(owner.path(), 506, &profile, &environment);
        assert_eq!(code, 0, "{output}");
        for decision in ["remote-offer", "hit", "execute"] {
            assert!(
                !decisions(&events, decision).contains_key("canonical_app"),
                "native modifiers must not borrow the worker metadata class: {output}"
            );
        }
        assert!(
            events.iter().any(|event| {
                event["kind"] == "rabsd-live-dependency"
                    && event["crate"] == "canonical_app"
                    && event["decision"] == "shadow"
                    && event["reason"] == "LIVE_DEP_NATIVE_LIB"
            }),
            "the actual native modifier did not reach admission: {output}"
        );
        assert_eq!(
            Some(&decisions(&events, "hit")),
            dependency_keys.as_ref(),
            "unsupported workspace metadata must not disable independent dependency hits: {output}"
        );
        assert_eq!(
            Some(worker.completed_receipt()),
            receipt,
            "an unsupported native modifier started a worker compiler"
        );
    }
    let retained = fs::read_dir(owner.path().join("ops"))
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .collect::<BTreeSet<_>>();
    assert_eq!(
        retained, retained_targets,
        "only delivered target trees may survive"
    );
    worker.finish();
}

fn metadata_check_targets(root: &Path, leaf: u32) {
    source(root, leaf);
    // Keep the unused development-macro files in the snapshot, but select a
    // plain graph so every requested compiler shape must reach the worker.
    write(
        root,
        "Cargo.toml",
        "[package]\nname='canonical_app'\nversion='0.1.0'\nedition='2021'\nautobins=false\n[dependencies]\ncanonical_dep='=1.0.0'\n[lib]\ntest=true\nbench=false\n[[bin]]\nname='canonical_cli'\npath='src/main.rs'\ntest=true\nbench=false\n[[example]]\nname='metadata_example'\npath='examples/metadata.rs'\ntest=false\nbench=false\n[[test]]\nname='metadata_integration'\npath='tests/metadata.rs'\n[[test]]\nname='metadata_custom_integration'\npath='tests/custom_metadata.rs'\nharness=false\n[[bench]]\nname='metadata_bench'\npath='benches/metadata.rs'\nharness=false\n[[bench]]\nname='metadata_standard_bench'\npath='benches/standard_metadata.rs'\nharness=true\n",
    );
    let checksum = |name: &str| {
        let value: Value = serde_json::from_slice(&read_bounded(
            &root.join(format!("vendor/{name}/.cargo-checksum.json")),
        ))
        .unwrap();
        value["package"].as_str().unwrap().to_owned()
    };
    write(
        root,
        "Cargo.lock",
        format!(
            "version=4\n\n[[package]]\nname='canonical_app'\nversion='0.1.0'\ndependencies=['canonical_dep']\n\n[[package]]\nname='canonical_dep'\nversion='1.0.0'\nsource='registry+https://github.com/rust-lang/crates.io-index'\nchecksum='{}'\ndependencies=['canonical_leaf']\n\n[[package]]\nname='canonical_leaf'\nversion='1.0.0'\nsource='registry+https://github.com/rust-lang/crates.io-index'\nchecksum='{}'\n",
            checksum("canonical_dep"),
            checksum("canonical_leaf")
        ),
    );
    let expected = leaf + 2;
    write(
        root,
        "src/lib.rs",
        format!(
            "const _: &str = env!(\"CARGO_PRIMARY_PACKAGE\");\nconst _: [(); {expected}] = [(); canonical_dep::answer() as usize];\npub const fn answer()->u32 {{ canonical_dep::answer() }}\n#[test]\nfn library_body_must_not_run() {{ panic!(\"RABS_CHECK_TARGET_EXECUTED\"); }}\n"
        ),
    );
    let consumer = format!(
        "#![allow(dead_code)]\nconst _: &str = env!(\"CARGO_PRIMARY_PACKAGE\");\nconst _: [(); {expected}] = [(); canonical_app::answer() as usize];\nfn main() {{ panic!(\"RABS_CHECK_TARGET_EXECUTED\"); }}\n#[test]\nfn body_must_not_run() {{ panic!(\"RABS_CHECK_TARGET_EXECUTED\"); }}\n"
    );
    for path in [
        "src/main.rs",
        "examples/metadata.rs",
        "tests/metadata.rs",
        "tests/custom_metadata.rs",
        "benches/metadata.rs",
        "benches/standard_metadata.rs",
    ] {
        write(root, path, &consumer);
    }
}

#[test]
#[ignore = "requires full Linux bubblewrap isolation, OpenSSL, matching RABS_CANONICAL_TEST_WRAPPER and RABS_TEST_WORKER_BIN; actual all-target Cargo checks, metadata installation and fresh workspace execution"]
fn canonical_cargo_check_offloads_binary_example_and_test_harness_metadata_without_running_them() {
    let (owner, mut profile) = native_fixture();
    let first = owner.path().join("source-a");
    let second = owner.path().join("source-b");
    metadata_check_targets(&first, 40);
    metadata_check_targets(&second, 40);
    profile["command"] = json!("check");
    profile["selection"] = json!({"all_targets":true});
    let (mut worker, environment) = NativeWorker::start(owner.path());
    let expected = BTreeMap::from([
        ("canonical_app".to_owned(), 2_usize),
        ("canonical_cli".to_owned(), 2),
        ("metadata_example".to_owned(), 1),
        ("metadata_integration".to_owned(), 1),
        ("metadata_custom_integration".to_owned(), 1),
        ("metadata_bench".to_owned(), 1),
        ("metadata_standard_bench".to_owned(), 1),
    ]);
    let mut attempts = BTreeMap::new();
    let mut previous_keys = BTreeSet::new();
    let mut previous_receipt: Option<Value> = None;
    let mut final_output = String::new();
    for number in 1..=3 {
        if number >= 2 {
            profile["source_root"] = json!(second);
        }
        if number == 3 {
            metadata_check_targets(&second, 41);
            // Retain only the final, freshly compiled target so the test can
            // inspect the actual installed empty metadata files after drain.
            // No earlier run has a target seed that could satisfy compilation.
            profile["target_cache"] =
                json!({"runtime_epoch":"metadata-target-fixture-v1", "max_bytes":268435456});
        }
        let (code, events, output) =
            run_with_environment(owner.path(), 400 + number, &profile, &environment);
        assert_eq!(code, 0, "{output}\nworker: {:?}", worker.events());
        assert!(
            !output.contains("RABS_CHECK_TARGET_EXECUTED"),
            "a program/test body ran: {output}"
        );
        assert!(
            decisions(&events, "hit").is_empty() && decisions(&events, "execute").is_empty(),
            "a workspace unit used cache authority or local fallback: {output}"
        );
        assert!(
            !events.iter().any(|event| matches!(
                event["kind"].as_str(),
                Some(
                    "rabsd-remote-dependency-failed"
                        | "rabsd-remote-dependency-install-failed"
                        | "canonical-build-completed"
                )
            )),
            "{output}"
        );
        // A crate name is insufficient: a library/binary and its check-mode
        // test harness are distinct requests with the same crate name.
        let offered = events
            .iter()
            .filter(|event| {
                event["kind"] == "rabsd-live-dependency" && event["decision"] == "remote-offer"
            })
            .map(|event| {
                (
                    event["key"].as_str().unwrap().to_owned(),
                    event["crate"].as_str().unwrap().to_owned(),
                )
            })
            .collect::<BTreeMap<_, _>>();
        assert_eq!(
            offered.len(),
            11,
            "two external dependencies and all nine workspace units must execute: {output}"
        );
        let completed = events
            .iter()
            .filter(|event| event["kind"] == "rabsd-remote-dependency-executed")
            .map(|event| event["key"].as_str().unwrap().to_owned())
            .collect::<BTreeSet<_>>();
        assert_eq!(
            completed,
            offered.keys().cloned().collect::<BTreeSet<_>>(),
            "not every offered unit installed successfully: {output}"
        );
        let mut observed = BTreeMap::new();
        let mut workspace_keys = BTreeSet::new();
        for (key, name) in &offered {
            if expected.contains_key(name) {
                *observed.entry(name.clone()).or_insert(0_usize) += 1;
                workspace_keys.insert(assert_fresh_workspace_execution(
                    owner.path(),
                    &events,
                    &output,
                    name,
                    key,
                    &mut attempts,
                ));
            }
        }
        assert_eq!(
            observed, expected,
            "a selected target/harness stayed local: {output}"
        );
        if number == 3 {
            assert!(
                workspace_keys.is_disjoint(&previous_keys),
                "changed retained inputs reused an earlier workspace identity"
            );
        }
        previous_keys = workspace_keys;
        let artifacts = output
            .lines()
            .filter_map(|line| serde_json::from_str::<Value>(line).ok())
            .filter(|event| event["reason"] == "compiler-artifact")
            .collect::<Vec<_>>();
        assert_eq!(artifacts.len(), 11, "{output}");
        assert!(
            artifacts
                .iter()
                .all(|event| event["fresh"] == false && event["executable"].is_null()),
            "check must produce current metadata without a runnable target: {output}"
        );
        let receipt = worker.completed_receipt();
        if let Some(previous) = &previous_receipt {
            assert!(
                receipt["request_id"].as_u64().unwrap()
                    >= previous["request_id"].as_u64().unwrap() + 11,
                "unchanged/changed checks must acquire fresh worker attempts"
            );
        }
        previous_receipt = Some(receipt);
        assert_eq!(
            worker
                .events()
                .iter()
                .filter(|event| event["kind"] == "worker-toolchain-acquired")
                .count(),
            11 * number as usize
        );
        final_output = output;
    }
    let target = sole_retained_target(owner.path());
    for (name, count) in &expected {
        let metadata = delivered_cargo_outputs(&target, &final_output, name, "rmeta")
            .into_iter()
            .map(|path| fs::symlink_metadata(path).unwrap())
            .collect::<Vec<_>>();
        assert_eq!(
            metadata.len(),
            *count,
            "installed {name} metadata files are incomplete"
        );
        assert!(
            metadata
                .iter()
                .all(|file| file.is_file() && file.permissions().mode() & 0o111 == 0)
        );
        let empty = metadata.iter().filter(|file| file.len() == 0).count();
        assert_eq!(
            empty,
            if name == "canonical_app" { 1 } else { *count },
            "empty rustc metadata must survive worker capture and installation for {name}"
        );
    }
    assert!(
        fs::read_dir(owner.path().join("ops"))
            .unwrap()
            .next()
            .is_none(),
        "checks must not retain an operation or deliver an executable"
    );
    worker.finish();
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum GeneratedDependency {
    None,
    Leaf,
    Consumer,
    NativeConsumer,
    NativeLeaf,
}

impl GeneratedDependency {
    fn generated_consumer(self) -> bool {
        matches!(self, Self::Consumer | Self::NativeConsumer)
    }

    fn assert_answer(self, root: &Path, answer: u32, workspace_edit: bool) {
        if matches!(self, Self::NativeConsumer | Self::NativeLeaf) {
            // FFI cannot be evaluated in a Rust const assertion. The delivered
            // executable calls this assertion after linking the returned rlib,
            // proving that the bundled native object has the current behavior.
            write(
                root,
                "src/lib.rs",
                format!(
                    "#[cfg(not(feature=\"remote_workspace\"))]\ncompile_error!(\"selected workspace feature was lost\");\nconst _: &str = env!(\"CARGO_PRIMARY_PACKAGE\");\nconst _: &str = include_str!(\"../workspace-readme.txt\");\npub fn answer()->u32 {{ let answer = canonical_dep::answer(); assert_eq!(answer, {answer}); answer+{} }}\n",
                    u32::from(workspace_edit)
                ),
            );
        } else {
            assert_answer(root, answer, workspace_edit);
        }
    }
}

/// Exercise the production native CLI, wrapper, remote executor, CAS sampling,
/// exact delivery and invalidation using the same dependency graph in each mode.
fn remote_dependency_replay(command: &str, generated: GeneratedDependency) {
    let (owner, mut profile) = native_fixture();
    profile["command"] = json!(command);
    profile["selection"] = json!({"features":["remote_workspace"]});
    let build = command == "build";
    if build {
        // Permit Cargo to start a downstream compiler while its dependency's
        // acknowledged metadata hit is still installing the archive tail.
        profile["jobs"] = json!(2);
    }
    // Native fixtures require Cargo's propagated search roots to survive every
    // eligible consumer: the ordinary workspace library and metadata binary
    // have no OUT_DIR or direct native-library directive of their own.
    let workspace_units: &[&str] = if build {
        &["canonical_app"]
    } else {
        &["canonical_app", "canonical_cli"]
    };
    let remote_unit_count = 2 + workspace_units.len();
    let first = owner.path().join("source-a");
    let second = owner.path().join("source-b");
    match generated {
        GeneratedDependency::None => {}
        GeneratedDependency::Leaf => {
            source_with_generated(&first, 40, true);
            source_with_generated(&second, 40, true);
        }
        GeneratedDependency::Consumer => {
            generated_dependency(&first);
            generated_dependency(&second);
        }
        GeneratedDependency::NativeConsumer => {
            generated_native_dependency(&first, false);
            generated_native_dependency(&second, false);
        }
        GeneratedDependency::NativeLeaf => {
            generated_native_dependency(&first, true);
            generated_native_dependency(&second, true);
        }
    }
    workspace_execution_feature(&first);
    workspace_execution_feature(&second);
    if !build {
        distinct_check_binary(&first);
        distinct_check_binary(&second);
    }
    generated.assert_answer(&first, 42, false);
    generated.assert_answer(&second, 42, true);
    let (mut worker, environment) = NativeWorker::start(owner.path());
    let mut first_keys = None;
    let mut receipt: Option<Value> = None;
    let mut first_archives = None;
    let mut retained_targets = BTreeSet::new();
    let mut workspace_attempts = BTreeMap::new();
    for number in 1..=3 {
        let (code, events, output) =
            run_with_environment(owner.path(), number, &profile, &environment);
        assert_eq!(code, 0, "{output}\nworker: {:?}", worker.events());
        if build {
            let (target, archives) = delivered_build(owner.path(), number, &events, &output, 42);
            assert!(
                retained_targets.insert(target),
                "a successful build reused mutable output"
            );
            if let Some(expected) = &first_archives {
                assert_eq!(
                    &archives, expected,
                    "cold archive samples differ byte-for-byte"
                );
            } else {
                first_archives = Some(archives);
            }
        } else {
            assert!(
                !events
                    .iter()
                    .any(|event| event["kind"] == "canonical-build-completed")
            );
        }
        let offered = decisions(&events, "remote-offer");
        assert_eq!(
            offered.len(),
            remote_unit_count,
            "every eligible unit must use the actual worker: {output}"
        );
        assert!(
            offered.contains_key("canonical_leaf") && offered.contains_key("canonical_dep"),
            "{output}"
        );
        let completed = events
            .iter()
            .filter(|event| event["kind"] == "rabsd-remote-dependency-executed")
            .filter_map(|event| event["key"].as_str())
            .collect::<BTreeSet<_>>();
        assert_eq!(
            completed,
            offered
                .values()
                .map(String::as_str)
                .collect::<BTreeSet<_>>(),
            "remote offers did not complete: {output}"
        );
        assert!(
            decisions(&events, "execute").is_empty() && decisions(&events, "hit").is_empty(),
            "fallback or unearned hit cannot qualify this remote test: {output}"
        );
        assert!(
            !events.iter().any(|event| matches!(
                event["kind"].as_str(),
                Some("rabsd-remote-dependency-failed" | "rabsd-remote-dependency-install-failed")
            )),
            "{output}"
        );
        assert_fresh_workspace_units(
            owner.path(),
            &events,
            &output,
            workspace_units,
            &mut workspace_attempts,
        );
        let dependency_keys = offered
            .into_iter()
            .filter(|(name, _)| !workspace_units.contains(&name.as_str()))
            .collect::<BTreeMap<_, _>>();
        if let Some(expected) = &first_keys {
            assert_eq!(
                &dependency_keys, expected,
                "fresh canonical targets split the worker key"
            );
        } else {
            first_keys = Some(dependency_keys);
        }
        let next = worker.completed_receipt();
        if let Some(previous) = &receipt {
            assert!(
                next["request_id"].as_u64().unwrap()
                    >= previous["request_id"].as_u64().unwrap() + remote_unit_count as u64,
                "every eligible unit must advance actual worker admission"
            );
        }
        receipt = Some(next);
    }
    let before_replay = worker
        .events()
        .into_iter()
        .filter(|event| event["kind"] == "worker-toolchain-acquired")
        .count();
    assert_eq!(
        before_replay,
        3 * remote_unit_count,
        "every qualifying production must reach the native worker executor"
    );
    // Repeat the unchanged workload after the dependencies qualify for cache
    // serving, then relocate it and edit only the workspace library. Both must
    // compile every eligible workspace target afresh while replaying the same
    // dependencies.
    for (number, source, answer) in [(4, &first, 42), (5, &second, 43)] {
        profile["source_root"] = json!(source);
        let (code, events, output) =
            run_with_environment(owner.path(), number, &profile, &environment);
        assert_eq!(code, 0, "{output}");
        if build {
            let (target, archives) =
                delivered_build(owner.path(), number, &events, &output, answer);
            assert!(retained_targets.insert(target));
            assert_eq!(
                Some(&archives),
                first_archives.as_ref(),
                "warm replay must deliver the exact remotely compiled dependency archives"
            );
        }
        assert_eq!(
            decisions(&events, "hit"),
            first_keys.clone().unwrap(),
            "canonical dependency replay failed: {output}"
        );
        assert_eq!(
            events
                .iter()
                .filter(|event| event["decision"] == "served")
                .count(),
            2,
            "{output}"
        );
        if build {
            let acknowledged = events
                .iter()
                .enumerate()
                .filter(|(_, event)| event["kind"] == "rabsd-metadata-prefix-acknowledged")
                .map(|(index, event)| {
                    assert_eq!(event["sequence"], 1, "{output}");
                    assert!(
                        event["bytes"].as_u64().is_some_and(|bytes| bytes > 0),
                        "{output}"
                    );
                    assert!(
                        event["manifest_key"]
                            .as_str()
                            .is_some_and(|key| !key.is_empty()),
                        "{output}"
                    );
                    let key = event["key"].as_str().unwrap();
                    let terminal = events
                        .iter()
                        .position(|candidate| {
                            candidate["decision"] == "served" && candidate["key"] == key
                        })
                        .expect("acknowledged metadata must finish the exact cache replay");
                    assert!(
                        index < terminal,
                        "metadata ACK followed complete installation: {output}"
                    );
                    key
                })
                .collect::<Vec<_>>();
            assert_eq!(
                acknowledged.len(),
                2,
                "each archive cache hit must deliver one metadata prefix: {output}"
            );
            assert_eq!(
                acknowledged.into_iter().collect::<BTreeSet<_>>(),
                first_keys
                    .as_ref()
                    .unwrap()
                    .values()
                    .map(String::as_str)
                    .collect::<BTreeSet<_>>(),
                "metadata delivery did not cover the actual remotely compiled archive hits: {output}"
            );
        }
        let workspace_keys = assert_fresh_workspace_units(
            owner.path(),
            &events,
            &output,
            workspace_units,
            &mut workspace_attempts,
        );
        assert_eq!(
            decisions(&events, "remote-offer"),
            workspace_keys,
            "every eligible workspace unit must execute while dependencies replay: {output}"
        );
        assert!(decisions(&events, "execute").is_empty(), "{output}");
        let next = worker.completed_receipt();
        assert!(
            next["request_id"].as_u64().unwrap()
                > receipt.as_ref().unwrap()["request_id"].as_u64().unwrap(),
            "workspace execution reused an earlier worker receipt"
        );
        receipt = Some(next);
        assert_eq!(
            worker
                .events()
                .into_iter()
                .filter(|event| event["kind"] == "worker-toolchain-acquired")
                .count(),
            before_replay + workspace_units.len() * (number as usize - 3),
            "each warm workload must execute all eligible workspace units"
        );
    }

    if generated != GeneratedDependency::None {
        // This edit changes only the build script's workspace input. Package
        // source, Cargo stdout directives and rustc-env stay identical; the
        // completed generated bytes must invalidate the selected action and
        // its consumers while independent dependencies remain reusable.
        write(
            &second,
            "generated-value.txt",
            if matches!(
                generated,
                GeneratedDependency::Leaf | GeneratedDependency::NativeLeaf
            ) {
                "41"
            } else {
                "3\n"
            },
        );
    } else {
        source(&second, 41);
        workspace_execution_feature(&second);
        if !build {
            distinct_check_binary(&second);
        }
    }
    generated.assert_answer(&second, 43, false);
    let (code, events, output) = run_with_environment(owner.path(), 6, &profile, &environment);
    assert_eq!(
        code, 0,
        "changed dependency metadata must satisfy the new const result: {output}"
    );
    let mut changed_archives = None;
    if build {
        let (target, archives) = delivered_build(owner.path(), 6, &events, &output, 43);
        assert!(retained_targets.insert(target));
        let previous = first_archives.as_ref().unwrap();
        if generated.generated_consumer() {
            assert_eq!(
                archives["canonical_leaf"], previous["canonical_leaf"],
                "editing a generator input changed the independent leaf archive"
            );
        } else {
            assert_ne!(
                archives["canonical_leaf"], previous["canonical_leaf"],
                "changed source or generated input reused stale canonical_leaf archive bytes"
            );
        }
        if generated == GeneratedDependency::NativeLeaf {
            // The middle crate consumes unchanged Rust metadata. Its archive
            // remains byte-identical, but its key must still bind the changed
            // foreign native tree and the linked executable must return 43.
            assert_eq!(
                archives["canonical_dep"], previous["canonical_dep"],
                "an archive-only native mutation changed the pure Rust middle archive"
            );
        } else {
            assert_ne!(
                archives["canonical_dep"], previous["canonical_dep"],
                "changed dependency inputs reused stale consumer archive bytes"
            );
        }
        changed_archives = Some(archives);
    }
    let changed = decisions(&events, "remote-offer");
    let changed_names: &[&str] = if generated.generated_consumer() {
        &["canonical_dep"]
    } else {
        &["canonical_leaf", "canonical_dep"]
    };
    assert_eq!(
        changed.len(),
        changed_names.len() + workspace_units.len(),
        "changed dependencies and every eligible workspace unit must execute remotely: {output}"
    );
    assert_fresh_workspace_units(
        owner.path(),
        &events,
        &output,
        workspace_units,
        &mut workspace_attempts,
    );
    let first_keys = first_keys.unwrap();
    for name in changed_names {
        assert_ne!(
            changed[*name], first_keys[*name],
            "stale {name} action identity"
        );
        assert!(
            events
                .iter()
                .any(|event| event["kind"] == "rabsd-remote-dependency-executed"
                    && event["key"] == changed[*name]),
            "{name} did not complete remotely: {output}"
        );
    }
    let hits = decisions(&events, "hit");
    if generated.generated_consumer() {
        assert_eq!(
            hits,
            BTreeMap::from([(
                "canonical_leaf".to_owned(),
                first_keys["canonical_leaf"].clone()
            )]),
            "the unchanged leaf must replay while its generated-input consumer rebuilds: {output}"
        );
    } else {
        assert!(hits.is_empty(), "{output}");
    }
    assert!(decisions(&events, "execute").is_empty(), "{output}");
    if generated == GeneratedDependency::NativeLeaf {
        // The foreign generated tree is more than the archive selected by -l.
        // Change only an empty subtree; source, Cargo directives and .a bytes
        // stay identical. Both the provider and its transitive native-path
        // consumer must get a different identity, including for cargo check
        // where rustc need not open any of these native files.
        write(&second, "generated-empty-name.txt", "after\n");
        let (code, events, output) = run_with_environment(owner.path(), 8, &profile, &environment);
        assert_eq!(code, 0, "{output}\nworker: {:?}", worker.events());
        if build {
            let (target, archives) = delivered_build(owner.path(), 8, &events, &output, 43);
            assert!(retained_targets.insert(target));
            assert_eq!(
                Some(archives),
                changed_archives,
                "an empty generated directory changed the compiled Rust/native archive bytes"
            );
        }
        let directory_changed = decisions(&events, "remote-offer");
        assert_eq!(directory_changed.len(), remote_unit_count, "{output}");
        assert!(decisions(&events, "hit").is_empty(), "{output}");
        assert!(decisions(&events, "execute").is_empty(), "{output}");
        for name in ["canonical_leaf", "canonical_dep"] {
            assert_ne!(
                directory_changed[name], changed[name],
                "changed foreign generated directory retained the {name} key"
            );
            assert!(
                events.iter().any(|event| {
                    event["kind"] == "rabsd-remote-dependency-executed"
                        && event["key"] == directory_changed[name]
                }),
                "directory-invalidated {name} did not complete remotely: {output}"
            );
        }
        assert_fresh_workspace_units(
            owner.path(),
            &events,
            &output,
            workspace_units,
            &mut workspace_attempts,
        );
        let next = worker.completed_receipt();
        assert!(
            next["request_id"].as_u64().unwrap()
                >= receipt.as_ref().unwrap()["request_id"].as_u64().unwrap()
                    + 2 * remote_unit_count as u64,
            "archive and directory changes did not each acquire new worker executions"
        );
    }
    // This fixture's selected script deliberately panics. Cargo must actually
    // run it and preserve that failure, while every dependency cache attempt
    // remains under worker authority rather than local wrapper claims.
    profile["selection"] = json!({"lib":true,"features":["remote_workspace","optional_build"]});
    let (code, events, output) = run_with_environment(owner.path(), 7, &profile, &environment);
    assert_ne!(
        code, 0,
        "the selected failing build script was skipped: {output}"
    );
    assert!(
        output.contains("inactive build script must never execute"),
        "{output}"
    );
    assert!(
        events
            .iter()
            .any(|event| event["kind"] == "canonical-compilation-started"),
        "{output}"
    );
    assert!(
        !events
            .iter()
            .any(|event| event["kind"] == "canonical-build-completed"),
        "{output}"
    );
    assert!(
        decisions(&events, "execute").is_empty(),
        "project executors must never turn remote refusal into local cache admission: {output}"
    );
    let retained = fs::read_dir(owner.path().join("ops"))
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .collect::<BTreeSet<_>>();
    assert_eq!(
        retained, retained_targets,
        "only successful build targets may survive; checks and rejected graphs retain no operation"
    );
    worker.finish();
}

/// A warm check never supplies lint coverage. Clippy owns its current outcome;
/// private state can be restored only for its exact source and lint selection.
#[test]
#[ignore = "requires real bubblewrap namespaces, native Clippy components and RABS_CANONICAL_TEST_WRAPPER"]
fn canonical_clippy_preserves_current_lints_and_separates_private_target_families() {
    let (owner, mut profile) = native_fixture();
    let toolchain = Path::new(profile["toolchain_root"].as_str().unwrap());
    for component in ["cargo-clippy", "clippy-driver"] {
        assert!(
            toolchain.join("bin").join(component).is_file(),
            "install native {component}"
        );
    }
    let source = owner.path().join("source-a");
    write(
        &source,
        "src/lib.rs",
        r#"
pub fn answer() -> u32 { return canonical_dep::answer(); }
pub fn configured_lint(project_marker: u32) -> u32 { project_marker }
"#,
    );
    write(&source, "clippy.toml", "disallowed-names = []\n");
    profile["selection"] = json!({"lib":true});
    profile["target_cache"] = json!({"runtime_epoch":"native-clippy-v1", "max_bytes":268435456});
    let (code, _, output) = run(owner.path(), 1000, &profile);
    assert_eq!(
        code, 0,
        "ordinary Cargo check must accept this lint-only problem: {output}"
    );

    let assert_lint_run = |events: &[Value], state: &str| {
        let started = events
            .iter()
            .filter(|event| event["kind"] == "canonical-compilation-started")
            .collect::<Vec<_>>();
        assert_eq!(started.len(), 1, "{events:?}");
        assert_eq!(started[0]["command"], "clippy");
        assert_eq!(started[0]["lint_execution"], true);
        assert_eq!(started[0]["lint_result_cache"], false);
        assert_eq!(started[0]["private_target_state"], state);
        assert!(
            decisions(events, "execute").is_empty(),
            "Clippy must not gain local rustc cache publication: {events:?}"
        );
        assert!(
            decisions(events, "hit").is_empty(),
            "without a worker Clippy must not acquire local compiler hits: {events:?}"
        );
    };
    profile["command"] = json!("clippy");
    profile["selection"] =
        json!({"lib":true, "no_deps":true, "lint_args":["-Dclippy::needless_return"]});
    let (code, events, output) = run(owner.path(), 1001, &profile);
    assert_eq!(
        code, 101,
        "the warm check must not suppress Clippy: {output}"
    );
    assert!(output.contains("clippy::needless_return"), "{output}");
    assert_lint_run(&events, "cold");

    profile["selection"] = json!({"lib":true, "no_deps":true,
        "lint_args":["-Aclippy::needless_return", "-Dclippy::disallowed_names"]});
    for (number, state) in [(1002, "cold"), (1003, "restored")] {
        let (code, events, output) = run(owner.path(), number, &profile);
        assert_eq!(code, 0, "{output}");
        assert_lint_run(&events, state);
        assert!(
            !events
                .iter()
                .any(|event| event["kind"] == "canonical-build-completed"),
            "lint success is not a delivered build artifact: {events:?}"
        );
    }
    profile["selection"]["lint_args"] = json!(["-Dclippy::needless_return"]);
    let (code, events, output) = run(owner.path(), 1004, &profile);
    assert_eq!(
        code, 101,
        "changed lint levels must report the current failure: {output}"
    );
    assert!(output.contains("clippy::needless_return"), "{output}");
    assert_lint_run(&events, "cold");

    profile["selection"]["lint_args"] =
        json!(["-Aclippy::needless_return", "-Dclippy::disallowed_names"]);
    write(
        &source,
        "clippy.toml",
        "disallowed-names = [\"project_marker\"]\n",
    );
    let (code, events, output) = run(owner.path(), 1005, &profile);
    assert_eq!(
        code, 101,
        "a configuration-only edit must change lint execution: {output}"
    );
    assert!(output.contains("clippy::disallowed_names"), "{output}");
    assert_lint_run(&events, "cold");
}
