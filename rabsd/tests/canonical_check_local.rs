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
    let leaf_source = format!("pub const fn answer()->u32 {{ {value} }}\n");
    let leaf = vendor(
        root,
        "canonical_leaf",
        BTreeMap::from([
            (
                "Cargo.toml",
                "[package]\nname='canonical_leaf'\nversion='1.0.0'\nedition='2021'\n",
            ),
            ("src/lib.rs", leaf_source.as_str()),
        ]),
    );
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
    profile["target_cache"] = json!({"runtime_epoch":"native-fixture-v1", "max_bytes":268435456});

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
    state(&events, "restored");
    freshness(&output, true, false);
    delivered_build(owner.path(), 103, &events, 43);

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
        state(&events, "restored");
        if number == 106 {
            freshness(&output, true, true);
        }
        assert!(
            !events
                .iter()
                .any(|event| event["kind"] == "canonical-build-completed")
        );
    }

    // Ambient host tools belong to the operator's runtime epoch. A changed
    // epoch cannot inherit Cargo's prior fingerprint state under the old one.
    profile["command"] = json!("build");
    profile["target_cache"]["runtime_epoch"] = json!("native-fixture-v2");
    let (code, events, output) = run(owner.path(), 107, &profile);
    assert_eq!(code, 0, "{output}");
    state(&events, "cold");
    freshness(&output, false, false);
    delivered_build(owner.path(), 107, &events, 143);
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
            "const _: [(); {answer}] = [(); canonical_dep::answer() as usize];\npub fn answer()->u32 {{ canonical_dep::answer()+{} }}\n",
            u32::from(workspace_edit)
        ),
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
    remote_dependency_replay("check");
}

#[test]
#[ignore = "requires full Linux bubblewrap isolation, OpenSSL, matching RABS_CANONICAL_TEST_WRAPPER and RABS_TEST_WORKER_BIN; actual Cargo build/TLS worker/archive cache and linked binary execution"]
fn canonical_cargo_build_offloads_archives_replays_and_delivers_a_working_binary() {
    remote_dependency_replay("build");
}

/// Exercise the production native CLI, wrapper, remote executor, CAS sampling,
/// exact delivery and invalidation using the same dependency graph in each mode.
fn remote_dependency_replay(command: &str) {
    let (owner, mut profile) = native_fixture();
    profile["command"] = json!(command);
    let build = command == "build";
    let first = owner.path().join("source-a");
    let second = owner.path().join("source-b");
    assert_answer(&first, 42, false);
    assert_answer(&second, 42, true);
    let (mut worker, environment) = NativeWorker::start(owner.path());
    let mut first_keys = None;
    let mut receipt: Option<Value> = None;
    let mut first_archives = None;
    let mut retained_targets = BTreeSet::new();
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
            2,
            "both dependency nodes must use the actual worker: {output}"
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
        if let Some(expected) = &first_keys {
            assert_eq!(
                &offered, expected,
                "fresh canonical targets split the worker key"
            );
        } else {
            first_keys = Some(offered);
        }
        let next = worker.completed_receipt();
        if let Some(previous) = &receipt {
            assert!(
                next["request_id"].as_u64().unwrap()
                    >= previous["request_id"].as_u64().unwrap() + 2,
                "each dependency must advance actual worker admission"
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
        before_replay, 6,
        "every qualifying production must reach the native worker executor"
    );
    profile["source_root"] = json!(second);
    let (code, events, output) = run_with_environment(owner.path(), 4, &profile, &environment);
    assert_eq!(code, 0, "{output}");
    if build {
        let (target, archives) = delivered_build(owner.path(), 4, &events, 43);
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
        "relocated dependency replay failed: {output}"
    );
    assert_eq!(
        events
            .iter()
            .filter(|event| event["decision"] == "served")
            .count(),
        2,
        "{output}"
    );
    assert!(
        decisions(&events, "remote-offer").is_empty() && decisions(&events, "execute").is_empty(),
        "{output}"
    );
    assert_eq!(
        worker.completed_receipt(),
        receipt.unwrap(),
        "cache replay executed a worker"
    );
    assert_eq!(
        worker
            .events()
            .into_iter()
            .filter(|event| event["kind"] == "worker-toolchain-acquired")
            .count(),
        before_replay
    );

    source(&second, 41);
    assert_answer(&second, 43, false);
    let (code, events, output) = run_with_environment(owner.path(), 5, &profile, &environment);
    assert_eq!(
        code, 0,
        "changed dependency metadata must satisfy the new const result: {output}"
    );
    if build {
        let (target, archives) = delivered_build(owner.path(), 5, &events, 43);
        assert!(retained_targets.insert(target));
        for name in ["canonical_leaf", "canonical_dep"] {
            assert_ne!(
                archives[name],
                first_archives.as_ref().unwrap()[name],
                "changed source reused stale {name} archive bytes"
            );
        }
    }
    let changed = decisions(&events, "remote-offer");
    assert_eq!(
        changed.len(),
        2,
        "both the changed leaf and its metadata consumer must execute remotely: {output}"
    );
    let first_keys = first_keys.unwrap();
    for name in ["canonical_leaf", "canonical_dep"] {
        assert_ne!(
            changed[name], first_keys[name],
            "stale {name} action identity"
        );
        assert!(
            events
                .iter()
                .any(|event| event["kind"] == "rabsd-remote-dependency-executed"
                    && event["key"] == changed[name]),
            "{name} did not complete remotely: {output}"
        );
    }
    assert!(
        decisions(&events, "hit").is_empty() && decisions(&events, "execute").is_empty(),
        "{output}"
    );
    // This fixture's selected script deliberately panics. Cargo must actually
    // run it and preserve that failure, while every dependency cache attempt
    // remains under worker authority rather than local wrapper claims.
    profile["selection"] = json!({"lib":true,"features":["optional_build"]});
    let (code, events, output) = run_with_environment(owner.path(), 6, &profile, &environment);
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
