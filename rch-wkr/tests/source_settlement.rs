//! Native source-settlement process, framing and lock-lifetime contracts.

#![cfg(unix)]

use std::fs;
use std::io::Write as _;
use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _, symlink};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};
use std::time::{Duration, Instant};

use rustix::fs::{FlockOperation, Mode, OFlags};
use rustix::io::Errno;
use sha2::{Digest as _, Sha256};

const WORKER: &str = env!("CARGO_BIN_EXE_rch-wkr");
const TOKEN: &str = "ab19";
const ROOTS: &[u8] = b"/owned/source\n";
const TRANSACTION: &str = r#"
IFS= read -r root || exit 41
[ "$root" = /owned/source ] || exit 42
case "$4" in
    locate) printf located ;;
    settle-cancel) printf settled ;;
    *) exit 43 ;;
esac
"#;

struct Fixture {
    directory: tempfile::TempDir,
    current: PathBuf,
    legacy: PathBuf,
    digest: String,
    native_path: PathBuf,
}

fn private_directory(path: &Path) {
    fs::create_dir_all(path).unwrap();
    fs::set_permissions(path, fs::Permissions::from_mode(0o700)).unwrap();
}

fn private_file(path: &Path, contents: &[u8]) {
    fs::write(path, contents).unwrap();
    fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
}

impl Fixture {
    fn new(namespace: &str) -> Self {
        let directory = tempfile::Builder::new()
            .disable_cleanup(true)
            .tempdir()
            .unwrap();
        private_directory(directory.path());
        let current = directory.path().join("current ' ; $literal `literal`");
        let legacy = directory.path().join("legacy ' ; $literal `literal`");
        let native_path = directory.path().join("native-bin");
        for path in [&current, &legacy, &native_path] {
            private_directory(path);
        }
        symlink("/bin/sh", native_path.join("sh")).unwrap();
        let digest: String = Sha256::digest(ROOTS)
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect();
        let selected = if namespace == "current" {
            &current
        } else {
            &legacy
        };
        private_file(
            &selected.join(format!("{TOKEN}.{digest}.cancelling")),
            ROOTS,
        );
        private_file(&selected.join(format!("{TOKEN}.activity.lock")), b"");
        for path in [&current, &legacy] {
            private_file(&path.join("metadata.lock"), b"");
        }
        Self {
            directory,
            current,
            legacy,
            digest,
            native_path,
        }
    }

    fn command(&self, operation: &str, expected: &str, transaction: &str) -> Command {
        let mut command = Command::new(WORKER);
        command
            .arg("source-settlement")
            .arg(&self.current)
            .arg(&self.legacy)
            .args([TOKEN, &self.digest, transaction, operation, expected])
            .env("RCH_TIMING_SCALE", "1")
            .env("PATH", &self.native_path)
            .env("TMPDIR", self.directory.path().join("unavailable-tmp"))
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        command
    }

    fn run(&self, operation: &str, expected: &str, transaction: &str) -> Output {
        run(self.command(operation, expected, transaction))
    }
}

fn run(mut command: Command) -> Output {
    let mut child = command.spawn().unwrap();
    // Invalid requests may refuse before consuming their already bounded
    // input. Successful operations still prove the roots reached the child.
    let _ = child.stdin.take().unwrap().write_all(ROOTS);
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        if child.try_wait().unwrap().is_some() {
            return child.wait_with_output().unwrap();
        }
        if Instant::now() >= deadline {
            child.kill().unwrap();
            let output = child.wait_with_output().unwrap();
            panic!("source-settlement exceeded its test deadline: {output:?}");
        }
        std::thread::sleep(Duration::from_millis(10));
    }
}

#[test]
fn source_settlement_cli_discovers_locates_and_settles_both_namespaces() {
    for namespace in ["current", "legacy"] {
        let fixture = Fixture::new(namespace);
        for (operation, expected, response) in [
            (
                "discover",
                "",
                format!("RCH_SOURCE_AUTHORITY_DISCOVERY {namespace}\n"),
            ),
            (
                "locate",
                "",
                format!("RCH_SOURCE_AUTHORITY_NAMESPACE {namespace}\n"),
            ),
            (
                "settle-cancel",
                namespace,
                "RCH_SOURCE_CANCELLATION_SETTLED\n".to_owned(),
            ),
        ] {
            let output = fixture.run(operation, expected, TRANSACTION);
            assert!(output.status.success(), "{output:?}");
            assert_eq!(output.stdout, response.as_bytes());
            assert!(output.stderr.is_empty());
        }
        let peer = if namespace == "current" {
            &fixture.legacy
        } else {
            &fixture.current
        };
        assert!(!peer.join(format!("{TOKEN}.activity.lock")).exists());
        assert!(!fixture.directory.path().join("unavailable-tmp").exists());
    }
}

#[test]
fn source_settlement_probe_and_invalid_scale_never_need_runtime_storage() {
    let fixture = Fixture::new("current");
    let output = Command::new(WORKER)
        .args(["source-settlement", "probe"])
        .env("PATH", &fixture.native_path)
        .env("TMPDIR", fixture.directory.path().join("unavailable-tmp"))
        .output()
        .unwrap();
    assert!(output.status.success(), "{output:?}");
    assert_eq!(output.stdout, b"rch-wkr source-settlement v1\n");
    assert!(output.stderr.is_empty());
    let activity = fixture.current.join(format!("{TOKEN}.activity.lock"));
    fs::set_permissions(&activity, fs::Permissions::from_mode(0o666)).unwrap();
    for scale in ["NaN", "0.99", "10.01", " 1", "1\n", "1;true"] {
        let mut command = fixture.command("locate", "", TRANSACTION);
        command.env("RCH_TIMING_SCALE", scale);
        let output = run(command);
        assert_eq!(output.status.code(), Some(73), "{scale:?}: {output:?}");
        assert!(output.stdout.is_empty());
        assert!(String::from_utf8_lossy(&output.stderr).contains("invalid RCH_TIMING_SCALE"));
        assert_eq!(fs::metadata(&activity).unwrap().mode() & 0o777, 0o666);
    }
}

#[test]
fn source_settlement_rejects_extra_missing_and_failed_transaction_frames() {
    let fixture = Fixture::new("current");
    for transaction in [
        "printf 'located\\n'",
        "printf 'locatedlocated'",
        "printf 'locate'",
        "printf 'settled'",
        "printf located; exit 9",
        "exit 0",
    ] {
        let output = fixture.run("locate", "", transaction);
        assert_eq!(output.status.code(), Some(73), "{transaction}: {output:?}");
        assert!(output.stdout.is_empty(), "{transaction}: {output:?}");
        assert!(
            String::from_utf8_lossy(&output.stderr).contains("RCH_SOURCE_CANCELLATION_UNSETTLED")
        );
    }
}

#[test]
fn source_settlement_checks_namespace_binding_before_starting_transaction() {
    let fixture = Fixture::new("legacy");
    let output = fixture.run("settle-cancel", "current", ": > \"$1/ran\"; printf settled");
    assert_eq!(output.status.code(), Some(73), "{output:?}");
    assert!(output.stdout.is_empty());
    assert!(String::from_utf8_lossy(&output.stderr).contains("changed from recorded binding"));
    assert!(!fixture.legacy.join("ran").exists());
}

#[test]
fn source_settlement_revalidates_lock_names_after_transaction_success() {
    let fixture = Fixture::new("current");
    symlink("/bin/mv", fixture.native_path.join("mv")).unwrap();
    let output = fixture.run(
        "locate",
        "",
        r#"
mv "$1/metadata.lock" "$1/retained-metadata" || exit 42
: > "$1/metadata.lock"
printf located
"#,
    );
    assert_eq!(output.status.code(), Some(73), "{output:?}");
    assert!(output.stdout.is_empty());
    assert!(String::from_utf8_lossy(&output.stderr).contains("registry lock changed"));
    assert_ne!(
        fs::metadata(fixture.current.join("metadata.lock"))
            .unwrap()
            .ino(),
        fs::metadata(fixture.current.join("retained-metadata"))
            .unwrap()
            .ino(),
    );
}

struct TransactionGuard {
    coordinator: Child,
    finish: PathBuf,
}

impl Drop for TransactionGuard {
    fn drop(&mut self) {
        // Wake the transaction even when an assertion fails; it must never be
        // an unbounded child of this test process after coordinator death.
        let _ = fs::write(&self.finish, b"finish");
        if self.coordinator.try_wait().ok().flatten().is_none() {
            let _ = self.coordinator.kill();
        }
        let _ = self.coordinator.wait();
    }
}

fn wait_until(mut predicate: impl FnMut() -> bool) {
    let deadline = Instant::now() + Duration::from_secs(5);
    while !predicate() {
        assert!(
            Instant::now() < deadline,
            "native transaction did not settle in time"
        );
        std::thread::sleep(Duration::from_millis(10));
    }
}

#[test]
fn source_settlement_transaction_keeps_original_locks_after_coordinator_dies() {
    let fixture = Fixture::new("current");
    symlink("/bin/sleep", fixture.native_path.join("sleep")).unwrap();
    let mut command = fixture.command(
        "locate",
        "",
        r#"
IFS= read -r root || exit 42
printf '%s\n' "$$" > "$1/transaction-pid"
while [ ! -f "$1/finish" ]; do sleep 0.02; done
printf located
"#,
    );
    // The orphan transaction must not retain the test's output-reader pipe.
    command.stdout(Stdio::null()).stderr(Stdio::null());
    let mut coordinator = command.spawn().unwrap();
    coordinator.stdin.take().unwrap().write_all(ROOTS).unwrap();
    let mut guard = TransactionGuard {
        coordinator,
        finish: fixture.current.join("finish"),
    };
    wait_until(|| fixture.current.join("transaction-pid").exists());
    guard.coordinator.kill().unwrap();
    guard.coordinator.wait().unwrap();
    let mut descriptors = Vec::new();
    for path in [
        fixture.current.join(format!("{TOKEN}.activity.lock")),
        fixture.current.join("metadata.lock"),
        fixture.legacy.join("metadata.lock"),
    ] {
        let descriptor = rustix::fs::open(
            &path,
            OFlags::RDWR | OFlags::CLOEXEC | OFlags::NOFOLLOW,
            Mode::empty(),
        )
        .unwrap();
        assert!(
            matches!(
                rustix::fs::flock(&descriptor, FlockOperation::NonBlockingLockExclusive),
                Err(Errno::AGAIN | Errno::ACCESS)
            ),
            "transaction lost {} when coordinator died",
            path.display()
        );
        descriptors.push(descriptor);
    }
    private_file(&guard.finish, b"finish");
    for descriptor in &descriptors {
        wait_until(|| {
            rustix::fs::flock(descriptor, FlockOperation::NonBlockingLockExclusive).is_ok()
        });
    }
}
