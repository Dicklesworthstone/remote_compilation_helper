//! End-to-end checks of the recovery-reserve wrappers that rch, rchd and the
//! hook send to workers, run against this build's `rch-wkr` exactly as a
//! worker shell runs them.
#![cfg(unix)]

use rch_common::recovery_reserve::{
    PROBE_REPLY, admission_command, readiness_command, recovery_command,
};
use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

const CAPACITY: u64 = 64 * 1024 * 1024;

fn run(command: &str, stdin: &[u8]) -> Output {
    use std::io::Write as _;
    let mut child = Command::new("sh")
        .arg("-c")
        .arg(command)
        .env("RCH_WKR_BIN", env!("CARGO_BIN_EXE_rch-wkr"))
        .env_remove("RCH_RECOVERY_RESERVE_FD")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("start worker shell");
    child.stdin.take().unwrap().write_all(stdin).unwrap();
    child.wait_with_output().expect("worker shell output")
}

fn stderr(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

struct Fixture {
    _root: tempfile::TempDir,
    registry: PathBuf,
}

impl Fixture {
    fn new() -> Self {
        let root = tempfile::tempdir().unwrap();
        let registry = root.path().join("authority/claims");
        Self {
            _root: root,
            registry,
        }
    }

    fn registry(&self) -> &str {
        self.registry.to_str().unwrap()
    }

    fn reserve(&self) -> PathBuf {
        self.registry.join(".recovery-v1/reserve.v1")
    }

    fn marker(&self) -> PathBuf {
        self.registry.parent().unwrap().join("payload-ran")
    }

    fn touch_marker(&self) -> String {
        format!("touch {}", self.marker().display())
    }
}

#[test]
fn probe_names_this_protocol() {
    let output = Command::new(env!("CARGO_BIN_EXE_rch-wkr"))
        .args(["recovery-reserve", "probe"])
        .output()
        .unwrap();
    assert!(output.status.success());
    assert_eq!(
        String::from_utf8_lossy(&output.stdout).trim_end(),
        PROBE_REPLY
    );
}

#[test]
fn readiness_provisions_a_physically_allocated_reserve_once() {
    let fixture = Fixture::new();
    let first = run(&readiness_command(fixture.registry()), b"");
    assert!(first.status.success(), "{}", stderr(&first));
    let reserve = std::fs::metadata(fixture.reserve()).unwrap();
    assert_eq!(reserve.len(), CAPACITY);
    assert!(reserve.blocks() * 512 >= CAPACITY, "reserve is sparse");
    assert_eq!(reserve.mode() & 0o777, 0o600);
    let second = run(&readiness_command(fixture.registry()), b"");
    assert!(second.status.success(), "{}", stderr(&second));
    assert_eq!(
        std::fs::metadata(fixture.reserve()).unwrap().ino(),
        reserve.ino()
    );
}

#[test]
fn admission_wrapper_preserves_piped_roots_and_shared_lease() {
    let fixture = Fixture::new();
    let payload = "test -n \"$RCH_RECOVERY_RESERVE_FD\" && \
                   test \"$RCH_RECOVERY_RESERVE_MODE\" = shared && \
                   test -z \"${MSYS_NO_PATHCONV-}\" && cat";
    let output = run(
        &admission_command(fixture.registry(), payload),
        b"/data/project\n/data/dependency\n",
    );
    assert!(output.status.success(), "{}", stderr(&output));
    assert_eq!(output.stdout, b"/data/project\n/data/dependency\n");
    assert_eq!(
        std::fs::metadata(fixture.reserve()).unwrap().len(),
        CAPACITY
    );
}

#[test]
fn shared_lease_callbacks_are_no_ops() {
    let fixture = Fixture::new();
    let payload = format!(
        "__gc_source_registry={}; rch_gc_reserve_claim bind fc-x.claim && echo ok",
        fixture.registry()
    );
    let output = run(&admission_command(fixture.registry(), &payload), b"");
    assert!(output.status.success(), "{}", stderr(&output));
    assert_eq!(output.stdout, b"ok\n");
}

#[test]
fn recovery_without_a_reserve_preserves_stdin_and_creates_no_reserve() {
    let fixture = Fixture::new();
    std::fs::create_dir_all(&fixture.registry).unwrap();
    // Owner-only, as production's `umask 077` creates it; a group-writable
    // registry (the fleet's umask 002) is refused before any reserve lookup.
    for directory in [fixture.registry.parent().unwrap(), &fixture.registry] {
        std::fs::set_permissions(directory, std::fs::Permissions::from_mode(0o700)).unwrap();
    }
    let output = run(
        &recovery_command(fixture.registry(), "cat"),
        b"cancel-token\n",
    );
    assert!(output.status.success(), "{}", stderr(&output));
    assert_eq!(output.stdout, b"cancel-token\n");
    assert!(!fixture.registry.join(".recovery-v1").exists());
}

#[test]
fn recovery_refuses_a_partial_reserve_without_running_its_payload() {
    let fixture = Fixture::new();
    let private = fixture.registry.join(".recovery-v1");
    std::fs::create_dir_all(&private).unwrap();
    for directory in [
        fixture.registry.parent().unwrap(),
        &fixture.registry,
        &private,
    ] {
        std::fs::set_permissions(directory, std::fs::Permissions::from_mode(0o700)).unwrap();
    }
    let output = run(
        &recovery_command(fixture.registry(), &fixture.touch_marker()),
        b"",
    );
    assert_eq!(output.status.code(), Some(74), "{}", stderr(&output));
    assert!(stderr(&output).starts_with("RCH_RECOVERY_RESERVE_UNSAFE "));
    assert!(!stderr(&output).contains("directory ownership"));
    assert!(!fixture.marker().exists());
}

#[test]
fn an_exclusive_owner_blocks_admission_payloads() {
    let fixture = Fixture::new();
    assert!(
        run(&readiness_command(fixture.registry()), b"")
            .status
            .success()
    );
    let held = std::fs::File::open(fixture.reserve()).unwrap();
    rustix::fs::flock(&held, rustix::fs::FlockOperation::LockExclusive).unwrap();
    let output = run(
        &admission_command(fixture.registry(), &fixture.touch_marker()),
        b"",
    );
    assert_eq!(output.status.code(), Some(74), "{}", stderr(&output));
    assert!(stderr(&output).contains("recovery lease busy"));
    assert!(!fixture.marker().exists());
    drop(held);
    let admitted = run(
        &admission_command(fixture.registry(), &fixture.touch_marker()),
        b"",
    );
    assert!(admitted.status.success(), "{}", stderr(&admitted));
    assert!(fixture.marker().exists());
}

#[test]
fn corrupt_headers_refuse_admission() {
    use std::os::unix::fs::FileExt as _;
    let fixture = Fixture::new();
    assert!(
        run(&readiness_command(fixture.registry()), b"")
            .status
            .success()
    );
    let file = std::fs::OpenOptions::new()
        .write(true)
        .open(fixture.reserve())
        .unwrap();
    file.write_at(b"{\"torn\":", 0).unwrap();
    let output = run(
        &admission_command(fixture.registry(), &fixture.touch_marker()),
        b"",
    );
    assert_eq!(output.status.code(), Some(74), "{}", stderr(&output));
    assert!(!fixture.marker().exists());
}

fn write_claim(directory: &Path, content: &[u8]) -> String {
    use sha2::Digest as _;
    let digest: String = sha2::Sha256::digest(content)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    let name = format!("fc-01234567-89ab-cdef-0123-456789abcdef.{digest}.claim");
    std::fs::write(directory.join(&name), content).unwrap();
    std::fs::set_permissions(
        directory.join(&name),
        std::fs::Permissions::from_mode(0o600),
    )
    .unwrap();
    name
}

fn private_file(path: &Path) {
    std::fs::write(path, b"").unwrap();
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).unwrap();
}

/// Release the payload bytes (same inode), as a full disk's recovery would.
fn spend(fixture: &Fixture) {
    std::fs::OpenOptions::new()
        .write(true)
        .open(fixture.reserve())
        .unwrap()
        .set_len(4096)
        .unwrap();
}

fn bind_payload(fixture: &Fixture, descriptor: &Path, name: &str) -> String {
    format!(
        "__gc_source_registry={registry}; test \"$RCH_RECOVERY_RESERVE_MODE\" = exclusive || exit 9; \
         exec 8<{descriptor}; rch_gc_reserve_claim bind {name}",
        registry = fixture.registry(),
        descriptor = descriptor.display(),
    )
}

/// A spent (exclusive) lease binds a GC claim through the shell callback;
/// refill then waits for that exact record's same-inode retirement receipt.
#[test]
fn exclusive_bind_gates_refill_until_retirement() {
    let fixture = Fixture::new();
    assert!(
        run(&readiness_command(fixture.registry()), b"")
            .status
            .success()
    );
    spend(&fixture);
    let metadata = fixture.registry.join("metadata.lock");
    private_file(&metadata);
    let name = write_claim(&fixture.registry, b"gc owner record\n");

    // fd 8 must be the registry's own metadata lock: nothing is bound, and
    // readiness refills the unbound spent reserve.
    let other = fixture
        .registry
        .parent()
        .unwrap()
        .join("other-metadata.lock");
    private_file(&other);
    let wrong = run(
        &recovery_command(fixture.registry(), &bind_payload(&fixture, &other, &name)),
        b"",
    );
    assert!(!wrong.status.success());
    assert!(stderr(&wrong).contains("GC metadata descriptor changed"));
    let unbound = run(&readiness_command(fixture.registry()), b"");
    assert!(unbound.status.success(), "{}", stderr(&unbound));
    assert_eq!(
        std::fs::metadata(fixture.reserve()).unwrap().len(),
        CAPACITY
    );

    spend(&fixture);
    let bound = run(
        &recovery_command(
            fixture.registry(),
            &bind_payload(&fixture, &metadata, &name),
        ),
        b"",
    );
    assert!(bound.status.success(), "{}", stderr(&bound));
    let second = write_claim(&fixture.registry, b"another gc owner\n");
    let rebind = run(
        &recovery_command(
            fixture.registry(),
            &bind_payload(&fixture, &metadata, &second),
        ),
        b"",
    );
    assert!(!rebind.status.success());
    assert!(stderr(&rebind).contains("previous emergency GC claim still bound"));

    let pending = run(&readiness_command(fixture.registry()), b"");
    assert_eq!(pending.status.code(), Some(75), "{}", stderr(&pending));
    assert!(stderr(&pending).contains("recovery-pending"));

    // Recovery borrows the spent lease but never reconciles GC's claim or
    // refills its generation, before or after the claim's retirement.
    let header = std::fs::read(fixture.reserve()).unwrap();
    let released = fixture.registry.join("released");
    std::fs::create_dir(&released).unwrap();
    std::fs::set_permissions(&released, std::fs::Permissions::from_mode(0o700)).unwrap();
    for retired in [false, true] {
        if retired {
            std::fs::rename(fixture.registry.join(&name), released.join(&name)).unwrap();
        }
        let recovered = run(
            &recovery_command(
                fixture.registry(),
                "test \"$RCH_RECOVERY_RESERVE_MODE\" = exclusive && printf recovered",
            ),
            b"",
        );
        assert!(recovered.status.success(), "{}", stderr(&recovered));
        assert_eq!(recovered.stdout, b"recovered");
        assert_eq!(std::fs::read(fixture.reserve()).unwrap(), header);
    }
    let refilled = run(&readiness_command(fixture.registry()), b"");
    assert!(refilled.status.success(), "{}", stderr(&refilled));
    assert_eq!(
        std::fs::metadata(fixture.reserve()).unwrap().len(),
        CAPACITY
    );
}
