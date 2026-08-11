//! S2 acceptance on the REAL wrapper binary: exec fidelity (exit codes,
//! signals, unbuffered streaming), daemon-alive consult against a live
//! rabsd, daemon-dead fail-open with the breaker opening per the C-epic
//! model, and the interposition proof — a real cargo build is
//! byte-identical with and without the wrapper.
#![cfg(unix)]

use std::os::unix::fs::PermissionsExt;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

fn wrap() -> &'static str {
    env!("CARGO_BIN_EXE_rabs-wrap")
}

/// The rabsd binary lives beside ours in the target dir; build it once
/// if a fresh checkout hasn't yet.
fn rabsd_bin() -> std::path::PathBuf {
    let path = std::path::Path::new(wrap()).with_file_name("rabsd");
    if !path.exists() {
        let status = Command::new(env!("CARGO"))
            .args(["build", "-p", "rabsd", "--bin", "rabsd"])
            .status()
            .expect("build rabsd");
        assert!(status.success());
    }
    path
}

fn write_script(dir: &std::path::Path, name: &str, body: &str) -> std::path::PathBuf {
    let path = dir.join(name);
    std::fs::write(&path, format!("#!/bin/sh\n{body}")).unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
    path
}

fn wrap_env(dir: &std::path::Path) -> Vec<(String, String)> {
    vec![
        (
            "RABS_BREAKER_FILE".into(),
            dir.join("breaker").display().to_string(),
        ),
        (
            "RABS_SOCKET_PATH".into(),
            dir.join("absent.sock").display().to_string(),
        ),
    ]
}

#[test]
fn exec_preserves_exit_codes_args_and_streams() {
    let dir = tempfile::tempdir().unwrap();
    let fake = write_script(
        dir.path(),
        "fake-rustc",
        "echo \"args:$#:$1:$2\"\necho stderr-line >&2\nexit 42\n",
    );
    let mut command = Command::new(wrap());
    command.arg(&fake).args(["--crate-name", "fx"]);
    for (key, value) in wrap_env(dir.path()) {
        command.env(key, value);
    }
    let output = command.output().unwrap();
    assert_eq!(output.status.code(), Some(42), "exit code preserved");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("args:2:--crate-name:fx"), "{stdout}");
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("stderr-line"),
        "stderr stream preserved"
    );
}

#[test]
fn exec_preserves_death_by_signal() {
    let dir = tempfile::tempdir().unwrap();
    let fake = write_script(dir.path(), "fake-rustc", "kill -TERM $$\n");
    let mut command = Command::new(wrap());
    command.arg(&fake).args(["--crate-name", "fx"]);
    for (key, value) in wrap_env(dir.path()) {
        command.env(key, value);
    }
    let status = command.status().unwrap();
    use std::os::unix::process::ExitStatusExt;
    assert_eq!(
        status.signal(),
        Some(libc_sigterm()),
        "signal death visible to the parent exactly as rustc's would be"
    );
}

const fn libc_sigterm() -> i32 {
    15
}

#[test]
fn streaming_is_unbuffered_by_construction_10mb_stderr() {
    let dir = tempfile::tempdir().unwrap();
    // 10 MiB of stderr via exec'd real chain: byte count must survive.
    let fake = write_script(
        dir.path(),
        "fake-rustc",
        "dd if=/dev/zero bs=1048576 count=10 2>/dev/null | tr '\\0' 'e' >&2\n",
    );
    let mut command = Command::new(wrap());
    command.arg(&fake).arg("--emit=metadata");
    for (key, value) in wrap_env(dir.path()) {
        command.env(key, value);
    }
    let output = command.output().unwrap();
    assert!(output.status.success());
    assert_eq!(output.stderr.len(), 10 * 1048576, "every byte arrived");
}

#[test]
fn probes_skip_state_entirely() {
    let dir = tempfile::tempdir().unwrap();
    let fake = write_script(dir.path(), "fake-rustc", "echo probe-ok\n");
    let breaker = dir.path().join("breaker");
    let mut command = Command::new(wrap());
    command.arg(&fake).arg("-vV");
    command.env("RABS_BREAKER_FILE", &breaker);
    command.env("RABS_SOCKET_PATH", dir.path().join("absent.sock"));
    let output = command.output().unwrap();
    assert!(output.status.success());
    assert!(
        !breaker.exists(),
        "a probe must not touch breaker state at all"
    );
}

#[test]
fn daemon_dead_fails_open_fast_and_breaker_opens_per_model() {
    let dir = tempfile::tempdir().unwrap();
    let fake = write_script(dir.path(), "fake-rustc", "exit 0\n");
    let envs = wrap_env(dir.path());
    // Default policy opens after 3 consecutive failures. (Wall-clock
    // budgets are NOT asserted here: this suite runs in parallel with
    // a cargo-build test on a contended host — observed 71s of pure
    // process-scheduling starvation. Latency is enforced by the
    // release-profile overhead gate under controlled conditions; THIS
    // test owns the breaker-model semantics.)
    for _ in 0..3 {
        let mut command = Command::new(wrap());
        command.arg(&fake).args(["--crate-name", "fx"]);
        for (key, value) in &envs {
            command.env(key, value);
        }
        assert!(command.status().unwrap().success(), "fail-open held");
    }
    let state = std::fs::read(dir.path().join("breaker")).unwrap();
    let decoded = rabs_protocol::wrapper_breaker::decode_state(&state).unwrap();
    assert!(
        matches!(
            decoded,
            rabs_protocol::wrapper_breaker::BreakerState::Open { .. }
        ),
        "3 failures must open the breaker: {decoded:?}"
    );
    // Open breaker: still fail-open, still success, state stays open.
    let mut command = Command::new(wrap());
    command.arg(&fake).args(["--crate-name", "fx"]);
    for (key, value) in &envs {
        command.env(key, value);
    }
    assert!(command.status().unwrap().success());
    let decoded = rabs_protocol::wrapper_breaker::decode_state(
        &std::fs::read(dir.path().join("breaker")).unwrap(),
    )
    .unwrap();
    assert!(
        matches!(
            decoded,
            rabs_protocol::wrapper_breaker::BreakerState::Open { .. }
        ),
        "skip-to-local must not rewrite the open state: {decoded:?}"
    );
}

#[test]
fn daemon_alive_consult_succeeds_and_breaker_stays_closed() {
    let dir = tempfile::tempdir().unwrap();
    let socket = dir.path().join("rabsd.sock");
    let marker = dir.path().join("rabsd.boot");
    let mut daemon = Command::new(rabsd_bin())
        .env("RABS_SOCKET_PATH", &socket)
        .env("RABS_BOOT_MARKER", &marker)
        .env("RABS_CONFIG", "/nonexistent-rabs-config")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn rabsd");
    let deadline = Instant::now() + Duration::from_secs(10);
    while !socket.exists() {
        assert!(Instant::now() < deadline, "socket never appeared");
        std::thread::sleep(Duration::from_millis(10));
    }

    let fake = write_script(dir.path(), "fake-rustc", "exit 0\n");
    let breaker = dir.path().join("breaker");
    for _ in 0..5 {
        let mut command = Command::new(wrap());
        command.arg(&fake).args(["--crate-name", "fx"]);
        command.env("RABS_BREAKER_FILE", &breaker);
        command.env("RABS_SOCKET_PATH", &socket);
        assert!(command.status().unwrap().success());
    }
    let decoded =
        rabs_protocol::wrapper_breaker::decode_state(&std::fs::read(&breaker).unwrap()).unwrap();
    assert_eq!(
        decoded,
        rabs_protocol::wrapper_breaker::BreakerState::fresh(),
        "successful consults keep the breaker closed-fresh"
    );

    Command::new("kill")
        .args(["-TERM", &daemon.id().to_string()])
        .status()
        .unwrap();
    assert_eq!(daemon.wait().unwrap().code(), Some(0));
}

#[test]
fn interposition_build_is_byte_identical_with_and_without_wrapper() {
    // THE fixtures-unchanged proof: a real cargo build of a fixture
    // crate produces byte-identical artifacts with the wrapper
    // interposed (shadow pass-through) and without it. Daemon-dead
    // here — interposition must be inert even in the worst case.
    let dir = tempfile::tempdir().unwrap();
    let source = dir.path().join("fx");
    std::fs::create_dir_all(source.join("src")).unwrap();
    std::fs::write(
        source.join("Cargo.toml"),
        "[package]\nname = \"fx\"\nversion = \"0.1.0\"\nedition = \"2021\"\n\n[workspace]\n",
    )
    .unwrap();
    std::fs::write(source.join("src/main.rs"), "fn main() {}\n").unwrap();

    // ONE target path for both arms (a different target dir embeds
    // different object paths in the binary — that would test the
    // filesystem, not the wrapper): build plain, save bytes, wipe the
    // scratch target, build wrapped, compare.
    let target = dir.path().join("t");
    let build = |wrapper: Option<&str>| -> Vec<u8> {
        let mut command = Command::new(env!("CARGO"));
        command
            .args(["build", "--offline"])
            .current_dir(&source)
            .env("CARGO_TARGET_DIR", &target)
            .env("CARGO_INCREMENTAL", "0")
            .env("RABS_BREAKER_FILE", dir.path().join("breaker"))
            .env("RABS_SOCKET_PATH", dir.path().join("absent.sock"));
        match wrapper {
            Some(wrapper) => command.env("RUSTC_WRAPPER", wrapper),
            None => command.env_remove("RUSTC_WRAPPER"),
        };
        let output = command.output().unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        std::fs::read(target.join("debug/fx")).unwrap()
    };

    let without_wrapper = build(None);
    std::fs::remove_dir_all(&target).unwrap(); // scratch target, test-owned
    let with_wrapper = build(Some(wrap()));
    assert_eq!(
        with_wrapper, without_wrapper,
        "interposed shadow wrapper must be byte-inert"
    );
}
