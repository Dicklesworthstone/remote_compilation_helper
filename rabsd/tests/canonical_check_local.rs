//! Native CLI boundary checks and an explicit controlled-host Cargo/cache test.
//! The ignored test runs the production namespace, wrapper, coordinator, CAS,
//! compiler and sampling policy. It never injects a cache row or substitutes a
//! fake namespace probe. Run it with `RABS_CANONICAL_TEST_WRAPPER=/abs/rabs-wrap`
//! on a Linux host permitting bubblewrap's full canonical namespace.
#![cfg(target_os = "linux")]

use rabs_asupersync::process_groups::ManagedProcessGroup;
use rabs_asupersync::region_tree::Attribution;
use rabs_asupersync::stream_drain::DrainLimits;
use rabs_sandbox::canonical_namespace::HostIsolationSupport;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fs;
use std::io::Read;
use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
use std::path::Path;
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
    let leaf_source = format!("pub fn answer()->u32 {{ {value} }}\n");
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
                "pub fn answer()->u32 { canonical_leaf::answer()+2 }\n",
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
    let path = root.join(format!("profile-{number}.json"));
    fs::write(&path, serde_json::to_vec(profile).unwrap()).unwrap();
    let mut command = Command::new(env!("CARGO_BIN_EXE_rabsd"));
    command
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env("RABS_CONFIG", root.join("config.toml"))
        .env("RABS_SPRT_SAMPLING", "0")
        .args(["--canonical-check-local"])
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
        "canonical check timed out"
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
    let profile = json!({"version":"canonical-check-local-v1", "source_root":"/source",
        "toolchain_root":"/toolchain", "state_root":"/state", "operation_root":"/operations",
        "wrapper":"/rabs-wrap", "env":{"RABS_SOCKET_PATH":"/ordinary-daemon.sock"}});
    let (code, _, output) = run(root.path(), 0, &profile);
    assert_eq!(code, 2, "{output}");
    assert!(output.contains("unknown field `env`"), "{output}");
    assert!(!output.contains("canonical-check-started"));
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

#[test]
#[ignore = "requires real bubblewrap namespaces, native toolchain and RABS_CANONICAL_TEST_WRAPPER"]
fn canonical_cargo_earns_cross_worktree_dependency_hits_and_invalidates_changed_source() {
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
    let mut profile = json!({"version":"canonical-check-local-v1", "source_root":first,
        "toolchain_root":toolchain, "state_root":owner.path().join("state"),
        "operation_root":owner.path().join("ops"), "wrapper":wrapper, "vendor":"vendor",
        "jobs":1, "timeout_seconds":300});
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

    // Inactive optional and development executors did not block the actual
    // library checks above. Selecting either executor must still refuse before
    // exposing the dependency cache endpoint or executing its project code.
    for (number, selection) in [
        (6, json!({"lib":true, "features":["optional_build"]})),
        (7, json!({"tests":true})),
    ] {
        profile["selection"] = selection;
        let (code, events, output) = run(owner.path(), number, &profile);
        assert_ne!(code, 0, "executor-bearing graph was admitted: {output}");
        assert!(
            output.contains("build scripts or procedural macros"),
            "{output}"
        );
        assert!(
            !output.contains("inactive build script must never execute"),
            "{output}"
        );
        assert!(
            !events
                .iter()
                .any(|event| event["kind"] == "canonical-check-started"),
            "selected executor reached cache admission: {output}"
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
