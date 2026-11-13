//! Registry/topology regressions against the compiled shell constants.
//! These exercise local worker protocol transactions, not a live SSH fleet.
//! Namespace path behavior is covered by the common module and worker CLI tests.
#![cfg(target_os = "linux")]

use std::fmt::Write as _;
use std::path::Path;
use std::process::{Command, Output, Stdio};

use sha2::{Digest as _, Sha256};

#[test]
fn source_topology_acknowledgement_and_release_protocol() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("workspace root");
    let fixture = tempfile::tempdir().expect("protocol fixture");
    let registry = fixture.path().join("registry.sh");
    let helpers = fixture.path().join("helpers.sh");
    let retry = fixture.path().join("retry.sh");
    std::fs::write(
        &registry,
        format!(
            "{}\n{}",
            rch_common::wkr_locate::WKR_LOCATE_SHELL,
            include_str!("../src/hook/source_claim_registry.sh"),
        ),
    )
    .expect("write compiled registry");
    std::fs::write(
        &helpers,
        rch_common::stale_target_reap::SOURCE_CLAIM_RECORD_HELPERS,
    )
    .expect("write compiled helpers");
    std::fs::write(
        &retry,
        format!(
            "{}\n{}",
            rch_common::wkr_locate::WKR_LOCATE_SHELL,
            include_str!("../src/hook/source_claim_admission.sh"),
        ),
    )
    .expect("write compiled admission retry");

    let output = Command::new("python3")
        .arg(root.join("scripts/tests/test_source_topology.py"))
        .env("RCH_TEST_SOURCE_TOPOLOGY_SCRIPT", &registry)
        .env("RCH_TEST_SOURCE_TOPOLOGY_HELPERS", &helpers)
        .env("RCH_TEST_SOURCE_TOPOLOGY_RETRY", &retry)
        .env("RCH_TEST_SOURCE_TOPOLOGY_SHELL", "sh")
        .env("RCH_WKR_BIN", rch_common::testing::worker_binary())
        .output()
        .expect("Python 3 is required for the source-topology registry regressions");
    assert!(
        output.status.success(),
        "source-topology protocol failed:\n{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
}

struct NativeTopologyFixture {
    root: tempfile::TempDir,
    registry: std::path::PathBuf,
    canonical: std::path::PathBuf,
    alias: std::path::PathBuf,
    roots: String,
    digest: String,
}

impl NativeTopologyFixture {
    fn new() -> Self {
        let root = tempfile::tempdir().unwrap();
        let registry = root.path().join("registry");
        for directory in ["", "released", "cancelled", "quarantine"] {
            std::fs::create_dir_all(registry.join(directory)).unwrap();
        }
        std::fs::write(registry.join("metadata.lock"), b"").unwrap();
        let canonical = root.path().join("canonical");
        let alias = root.path().join("alias");
        let roots = format!("{}\n{}\n", alias.display(), canonical.display());
        let mut digest = String::with_capacity(64);
        for byte in Sha256::digest(roots.as_bytes()) {
            write!(&mut digest, "{byte:02x}").unwrap();
        }
        Self {
            root,
            registry,
            canonical,
            alias,
            roots,
            digest,
        }
    }

    fn arguments(&self, operation: &str, token: &str) -> Vec<String> {
        vec![
            "-w".into(),
            "5".into(),
            "-x".into(),
            self.registry.join("metadata.lock").to_str().unwrap().into(),
            "sh".into(),
            "-c".into(),
            format!(
                "{}\n{}\n{}",
                rch_common::wkr_locate::WKR_LOCATE_SHELL,
                rch_common::stale_target_reap::SOURCE_CLAIM_RECORD_HELPERS,
                include_str!("../src/hook/source_claim_registry.sh")
            ),
            "rch-native-topology-test".into(),
            self.registry.to_str().unwrap().into(),
            token.into(),
            self.digest.clone(),
            operation.into(),
        ]
    }

    fn operation(&self, operation: &str, token: &str) -> Output {
        use std::io::Write as _;
        let mut child = Command::new("flock")
            .args(self.arguments(operation, token))
            .env("RCH_WKR_BIN", rch_common::testing::worker_binary())
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        child
            .stdin
            .take()
            .unwrap()
            .write_all(self.roots.as_bytes())
            .unwrap();
        child.wait_with_output().unwrap()
    }

    fn retry_command(&self) -> Command {
        let quote = |value: &str| shell_escape::escape(value.into()).into_owned();
        let adapter = rch_common::source_namespace_paths::shell_script(include_str!(
            "../src/hook/source_namespace_paths.sh"
        ));
        let mut arguments = self.arguments("topology", "b1");
        for operation in ["check", "create"] {
            arguments.push(format!(
                "set -- {operation} {} {}\n{adapter}",
                quote(self.canonical.to_str().unwrap()),
                quote(self.alias.to_str().unwrap())
            ));
        }
        let invocation = arguments
            .iter()
            .map(|argument| quote(argument))
            .collect::<Vec<_>>()
            .join(" ");
        let program = format!(
            "rch_source_attempt() {{ (\nset +e\n\
             flock {invocation} <<'RCH_TOPOLOGY_TEST_ROOTS'\n{}\
             RCH_TOPOLOGY_TEST_ROOTS\n\
             status=$?\nprintf '%s\\n' \"$status\" >> {}\nexit \"$status\"\n\
             ); }}\nrch_admission_retry_seconds=3\n{}\n{}",
            self.roots,
            quote(self.root.path().join("attempts").to_str().unwrap()),
            rch_common::wkr_locate::WKR_LOCATE_SHELL,
            include_str!("../src/hook/source_claim_admission.sh")
        );
        let mut command = Command::new("sh");
        command
            .args(["-c", &program])
            .env("RCH_WKR_BIN", rch_common::testing::worker_binary())
            .env("RCH_TIMING_SCALE", "1")
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        command
    }

    fn attempts(&self) -> String {
        std::fs::read_to_string(self.root.path().join("attempts")).unwrap_or_default()
    }

    fn assert_no_live_claims(&self) {
        assert!(std::fs::read_dir(&self.registry).unwrap().all(|entry| {
            let path = entry.unwrap().path();
            !matches!(
                path.extension().and_then(|value| value.to_str()),
                Some("claim" | "pending")
            )
        }));
    }
}

fn assert_success(output: &Output) {
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn native_namespace_conflicts_do_not_retry_the_same_worker() {
    let fixture = NativeTopologyFixture::new();
    let physical = fixture.root.path().join("other");
    std::fs::create_dir(&fixture.canonical).unwrap();
    std::fs::create_dir(&physical).unwrap();
    std::os::unix::fs::symlink(&physical, &fixture.alias).unwrap();
    let output = fixture.retry_command().output().unwrap();
    assert_eq!(output.status.code(), Some(73));
    assert!(output.stdout.is_empty());
    assert!(
        String::from_utf8_lossy(&output.stderr)
            .contains("RCH_SOURCE_TOPOLOGY_INCOMPATIBLE: conflicting_alias_base")
    );
    assert_eq!(fixture.attempts(), "73\n");
    assert_eq!(std::fs::read_link(&fixture.alias).unwrap(), physical);
    fixture.assert_no_live_claims();
}

#[test]
fn native_namespace_retry_releases_metadata_lock_for_legacy_owner_release() {
    let fixture = NativeTopologyFixture::new();
    assert_success(&fixture.operation("acquire", "a1"));
    let mut child = fixture.retry_command().spawn().unwrap();
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    while fixture.attempts().is_empty() {
        if std::time::Instant::now() >= deadline || child.try_wait().unwrap().is_some() {
            let _ = child.kill();
            let output = child.wait_with_output().unwrap();
            panic!(
                "namespace retry never reported a completed busy attempt: {}",
                String::from_utf8_lossy(&output.stderr)
            );
        }
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
    let no_paths_before_release =
        !fixture.canonical.exists() && std::fs::symlink_metadata(&fixture.alias).is_err();
    let released = fixture.operation("release", "a1");
    if !released.status.success() {
        let _ = child.kill();
        let _ = child.wait();
    }
    assert_success(&released);
    let output = child.wait_with_output().unwrap();
    assert_success(&output);
    assert!(no_paths_before_release);
    assert_eq!(output.stdout, b"RCH_TOPOLOGY_OK\n");
    let attempts = fixture.attempts();
    assert!(
        attempts.starts_with("75\n") && attempts.ends_with("0\n"),
        "{attempts}"
    );
    assert_eq!(
        std::fs::read_link(&fixture.alias).unwrap(),
        fixture.canonical
    );
    fixture.assert_no_live_claims();
    assert_eq!(
        std::fs::read_dir(fixture.registry.join("released"))
            .unwrap()
            .filter(|entry| entry
                .as_ref()
                .unwrap()
                .path()
                .extension()
                .is_some_and(|ext| ext == "claim"))
            .count(),
        1
    );
}
