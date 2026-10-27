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
use std::io::Read;
use std::net::TcpListener;
use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
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

fn generated_native_dependency(root: &Path) {
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
    let output = std::path::PathBuf::from(std::env::var_os("OUT_DIR").unwrap()).join("native");
    std::fs::create_dir_all(&output).unwrap();
    std::fs::write(output.join("answer.c"), format!("unsigned int rabs_native_answer(void) {{ return {value}; }}\n")).unwrap();
    assert!(std::process::Command::new("/usr/bin/cc")
        .args(["-c", "-fPIC", "-o"])
        .arg(output.join("answer.o")).arg(output.join("answer.c"))
        .status().unwrap().success());
    assert!(std::process::Command::new("/usr/bin/ar")
        .arg("crsD").arg(output.join("librabs_answer.a")).arg(output.join("answer.o"))
        .status().unwrap().success());
    println!("cargo:rerun-if-changed={}", input.display());
    println!("cargo:rustc-link-search=native={}", output.display());
    println!("cargo:rustc-link-lib=static=rabs_answer");
}
"#,
            ),
            (
                "src/lib.rs",
                "extern \"C\" { fn rabs_native_answer() -> u32; }\npub fn answer()->u32 { canonical_leaf::answer() + unsafe { rabs_native_answer() } }\n",
            ),
        ]),
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
        .stdin(Stdio::null())
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
    let (first_target, first_archives) = delivered_build(owner.path(), 100, &events, 42);
    let initial_families = families();
    assert_eq!(initial_families.len(), 1);

    profile["source_root"] = json!(second);
    let (code, events, output) = run(owner.path(), 101, &profile);
    assert_eq!(code, 0, "{output}");
    state(&events, "restored");
    freshness(&output, true, true);
    let (warm_target, warm_archives) = delivered_build(owner.path(), 101, &events, 42);
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
    delivered_build(owner.path(), 102, &events, 42);

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
    delivered_build(owner.path(), 103, &events, 43);
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
    delivered_build(owner.path(), 104, &events, 143);

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
    delivered_build(owner.path(), 107, &events, 143);

    // Ambient host tools belong to the operator's runtime epoch. A changed
    // epoch cannot inherit Cargo's prior fingerprint state under the old one.
    profile["target_cache"]["runtime_epoch"] = json!("native-fixture-v2");
    let (code, events, output) = run(owner.path(), 108, &profile);
    assert_eq!(code, 0, "{output}");
    state(&events, "cold");
    freshness(&output, false, false);
    delivered_build(owner.path(), 108, &events, 143);

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
    delivered_build(owner.path(), 109, &events, 143);

    let (code, events, output) = run(owner.path(), 110, &profile);
    assert_eq!(code, 0, "{output}");
    state(&events, "restored");
    freshness(&output, true, true);
    delivered_build(owner.path(), 110, &events, 143);

    // A return to a previous runtime family restores its own complete Cargo
    // state. Neither switching families nor repairing one corrupts the other.
    for (number, epoch) in [(111, "native-fixture-v1"), (112, "native-fixture-v2")] {
        profile["target_cache"]["runtime_epoch"] = json!(epoch);
        let (code, events, output) = run(owner.path(), number, &profile);
        assert_eq!(code, 0, "{output}");
        state(&events, "restored");
        freshness(&output, true, true);
        delivered_build(owner.path(), number, &events, 143);
        assert_eq!(families(), retained_families);
    }

    // The third family exceeds the configured count. Evict only the older
    // successful family; keep the just-published state and the recent one.
    profile["target_cache"]["runtime_epoch"] = json!("native-fixture-v3");
    let (code, events, output) = run(owner.path(), 113, &profile);
    assert_eq!(code, 0, "{output}");
    state(&events, "cold");
    freshness(&output, false, false);
    delivered_build(owner.path(), 113, &events, 143);
    let retained = families();
    assert_eq!(retained.len(), 2);
    assert!(retained.contains(&second_family));
    assert!(retained.is_disjoint(&original_families));

    profile["target_cache"]["runtime_epoch"] = json!("native-fixture-v2");
    let (code, events, output) = run(owner.path(), 114, &profile);
    assert_eq!(code, 0, "{output}");
    state(&events, "restored");
    freshness(&output, true, true);
    delivered_build(owner.path(), 114, &events, 143);

    profile["target_cache"]["runtime_epoch"] = json!("native-fixture-v1");
    let (code, events, output) = run(owner.path(), 115, &profile);
    assert_eq!(code, 0, "{output}");
    state(&events, "cold");
    freshness(&output, false, false);
    delivered_build(owner.path(), 115, &events, 143);
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
// this one limited to a CA and the two identities consumed by the production
// outward-worker transport; every OpenSSL process has a finite group lifetime.
fn native_certificates(root: &Path) -> (TlsFiles, TlsFiles) {
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
    for (name, usage, serial) in [
        ("coordinator", "serverAuth", "2"),
        ("worker", "clientAuth", "3"),
    ] {
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
                serial,
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
    (files("coordinator"), files("worker"))
}

struct NativeWorker {
    process: Option<ManagedProcessGroup>,
    state: PathBuf,
    stdout: PathBuf,
    stderr: PathBuf,
    drain: PathBuf,
}

impl NativeWorker {
    fn start(root: &Path) -> (Self, Vec<(String, String)>) {
        const ID: &str = "canonical-dependency-worker";
        let binary = fs::canonicalize(
            std::env::var_os("RABS_TEST_WORKER_BIN")
                .expect("set RABS_TEST_WORKER_BIN to the matching native rabs-wkr"),
        )
        .unwrap();
        let (coordinator, worker) = native_certificates(&root.join("credentials"));
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
            ("RABS_DEPENDENCY_WORKER_ID".into(), ID.into()),
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
        let stdout = root.join("worker.stdout");
        let stderr = root.join("worker.stderr");
        let mut command = Command::new(binary);
        command
            .env_clear()
            .env("PATH", "/usr/bin:/bin")
            .args(["--coordinator", &address, "--worker-id", ID])
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
                stdout,
                stderr,
                drain: root.join("worker-stop"),
            },
            environment,
        )
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

fn assert_local_native_workspace(events: &[Value], output: &str) {
    for decision in ["remote-offer", "hit", "execute"] {
        assert!(
            !decisions(events, decision).contains_key("canonical_app"),
            "the workspace consumer of a propagated native path must remain local and uncached: {output}"
        );
    }
    assert!(
        events.iter().any(|event| {
            event["kind"] == "rabsd-live-dependency"
                && event["crate"] == "canonical_app"
                && event["decision"] == "shadow"
                && matches!(
                    event["reason"].as_str(),
                    Some("LIVE_DEP_SEARCH_PATH" | "LIVE_DEP_NATIVE_LIB")
                )
        }),
        "the actual workspace invocation must refuse its propagated native input: {output}"
    );
}

/// Validate the delivered user output, including a real executable consuming
/// the remotely produced or replayed archives. The driver may retain only the
/// target tree after its coordinator, wrapper sessions and compiler have drained.
fn delivered_build(
    root: &Path,
    number: u32,
    events: &[Value],
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
        let prefix = format!("lib{name}-");
        let candidates = fs::read_dir(target.join("debug/deps"))
            .unwrap()
            .map(|entry| entry.unwrap().path())
            .filter(|path| {
                path.file_name()
                    .and_then(|file| file.to_str())
                    .is_some_and(|file| file.starts_with(&prefix) && file.ends_with(".rlib"))
            })
            .collect::<Vec<_>>();
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

fn metadata_check_targets(root: &Path, leaf: u32) {
    source(root, leaf);
    // Keep the unused development-macro files in the snapshot, but select a
    // plain graph so every requested compiler shape must reach the worker.
    write(
        root,
        "Cargo.toml",
        "[package]\nname='canonical_app'\nversion='0.1.0'\nedition='2021'\nautobins=false\n[dependencies]\ncanonical_dep='=1.0.0'\n[lib]\ntest=true\nbench=false\n[[bin]]\nname='canonical_cli'\npath='src/main.rs'\ntest=true\nbench=false\n[[example]]\nname='metadata_example'\npath='examples/metadata.rs'\ntest=false\nbench=false\n[[test]]\nname='metadata_integration'\npath='tests/metadata.rs'\n[[bench]]\nname='metadata_bench'\npath='benches/metadata.rs'\nharness=false\n",
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
        "benches/metadata.rs",
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
        ("metadata_bench".to_owned(), 1),
    ]);
    let mut attempts = BTreeMap::new();
    let mut previous_keys = BTreeSet::new();
    let mut previous_receipt: Option<Value> = None;
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
            9,
            "two external dependencies and all seven workspace units must execute: {output}"
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
        assert_eq!(artifacts.len(), 9, "{output}");
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
                    >= previous["request_id"].as_u64().unwrap() + 9,
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
            9 * number as usize
        );
    }
    let target = sole_retained_target(owner.path());
    for (name, count) in &expected {
        let prefix = format!("lib{name}-");
        let directory = if name == "metadata_example" {
            "debug/examples"
        } else {
            "debug/deps"
        };
        let metadata = fs::read_dir(target.join(directory))
            .unwrap()
            .map(|entry| entry.unwrap().path())
            .filter(|path| {
                path.file_name()
                    .unwrap()
                    .to_str()
                    .is_some_and(|file| file.starts_with(&prefix) && file.ends_with(".rmeta"))
            })
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
}

impl GeneratedDependency {
    fn generated_consumer(self) -> bool {
        matches!(self, Self::Consumer | Self::NativeConsumer)
    }

    fn assert_answer(self, root: &Path, answer: u32, workspace_edit: bool) {
        if self == Self::NativeConsumer {
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
    // Cargo propagates the dependency's native search path to its consumers.
    // The workspace lane has no authority to capture another package's OUT_DIR.
    let workspace_remote = generated != GeneratedDependency::NativeConsumer;
    let workspace_units: &[&str] = if !workspace_remote {
        &[]
    } else if build {
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
            assert!(build, "native archive replay requires actual codegen");
            generated_native_dependency(&first);
            generated_native_dependency(&second);
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
            let (target, archives) = delivered_build(owner.path(), number, &events, 42);
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
        if workspace_remote {
            assert_fresh_workspace_units(
                owner.path(),
                &events,
                &output,
                workspace_units,
                &mut workspace_attempts,
            );
        } else {
            assert_local_native_workspace(&events, &output);
        }
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
            let (target, archives) = delivered_build(owner.path(), number, &events, answer);
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
        if workspace_remote {
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
        } else {
            assert_local_native_workspace(&events, &output);
            assert!(
                decisions(&events, "remote-offer").is_empty(),
                "both native fixture dependencies must replay while the workspace compiles locally: {output}"
            );
        }
        assert!(decisions(&events, "execute").is_empty(), "{output}");
        let next = worker.completed_receipt();
        if workspace_remote {
            assert!(
                next["request_id"].as_u64().unwrap()
                    > receipt.as_ref().unwrap()["request_id"].as_u64().unwrap(),
                "workspace execution reused an earlier worker receipt"
            );
        } else {
            assert_eq!(
                Some(&next),
                receipt.as_ref(),
                "warm native dependencies unexpectedly executed again"
            );
        }
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
            if generated == GeneratedDependency::Leaf {
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
    if build {
        let (target, archives) = delivered_build(owner.path(), 6, &events, 43);
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
        assert_ne!(
            archives["canonical_dep"], previous["canonical_dep"],
            "changed dependency inputs reused stale consumer archive bytes"
        );
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
    if workspace_remote {
        assert_fresh_workspace_units(
            owner.path(),
            &events,
            &output,
            workspace_units,
            &mut workspace_attempts,
        );
    } else {
        assert_local_native_workspace(&events, &output);
    }
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
