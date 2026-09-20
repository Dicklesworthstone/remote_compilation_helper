//! S2 acceptance on the REAL wrapper binary: exec fidelity (exit codes,
//! signals, unbuffered streaming), daemon-alive consult against a live
//! rabsd, daemon-dead fail-open with the breaker opening per the C-epic
//! model, and the interposition proof — a real cargo build is
//! byte-identical with and without the wrapper.
#![cfg(unix)]

use std::ffi::OsString;
use std::os::unix::ffi::OsStringExt;
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
fn exec_preserves_non_utf8_argv_and_compiler_path() {
    let dir = tempfile::tempdir().unwrap();
    let compiler = write_script(
        dir.path(),
        "compiler",
        "printf '%s\\n' \"$@\"\necho compiler-stderr >&2\nexit 23\n",
    );
    let raw_compiler = dir
        .path()
        .join(OsString::from_vec(b"compiler-\xff".to_vec()));
    std::fs::copy(&compiler, &raw_compiler).unwrap();
    let raw_arg = OsString::from_vec(b"source-\xfe.rs".to_vec());
    let cases = [
        (
            &compiler,
            vec![raw_arg.clone(), OsString::new(), "café".into()],
        ),
        (&raw_compiler, vec!["source.rs".into()]),
        (&raw_compiler, vec![raw_arg]),
    ];

    for (executable, args) in cases {
        let direct = Command::new(executable).args(&args).output().unwrap();
        assert_eq!(direct.status.code(), Some(23));
        let wrapped = Command::new(wrap())
            .arg(executable)
            .args(&args)
            .envs(wrap_env(dir.path()))
            .output()
            .unwrap();
        assert_eq!(wrapped.status, direct.status, "wrapper must not panic");
        assert_eq!(wrapped.stdout, direct.stdout, "argv bytes changed");
        assert_eq!(wrapped.stderr, direct.stderr, "compiler stderr changed");
        assert!(
            !dir.path().join("breaker").exists(),
            "unrepresentable argv must bypass observation, not alter breaker state"
        );
    }
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
    // Report what actually happened: a bare `assert!` here said only
    // "false", which is useless for an intermittent failure. This one is
    // flaky (~1 run in 12 on a busy fleet worker) and the exit status is
    // the whole question — a signal death means the pipeline in the fake
    // rustc died, an exit code means the wrapper propagated a failure.
    use std::os::unix::process::ExitStatusExt;
    assert!(
        output.status.success(),
        "wrapper exited non-zero streaming 10 MiB of stderr: code={:?} signal={:?} \
         stderr_len={} stdout_len={}",
        output.status.code(),
        output.status.signal(),
        output.stderr.len(),
        output.stdout.len()
    );
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
fn busy_breaker_in_another_process_does_not_block_compiler_exec() {
    let dir = tempfile::tempdir().unwrap();
    let marker = dir.path().join("compiler-ran");
    let fake = write_script(
        dir.path(),
        "fake-rustc",
        "printf ran > \"$RABS_TEST_COMPILER_MARKER\"\nexit 42\n",
    );
    let guard = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .open(dir.path().join("breaker.lock"))
        .unwrap();
    guard.try_lock().unwrap();

    let mut child = Command::new(wrap())
        .arg(&fake)
        .args(["--crate-name", "fx"])
        .envs(wrap_env(dir.path()))
        .env("RABS_TEST_COMPILER_MARKER", &marker)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    // A watchdog, not a latency benchmark: a blocking lock must not hang
    // the whole test runner. The parent retains the lock until child exit.
    let deadline = Instant::now() + Duration::from_secs(10);
    let status = loop {
        if let Some(status) = child.try_wait().unwrap() {
            break status;
        }
        if Instant::now() >= deadline {
            drop(guard);
            let _ = child.kill();
            let _ = child.wait();
            panic!("wrapper waited for another process's breaker lock");
        }
        std::thread::sleep(Duration::from_millis(10));
    };
    assert_eq!(status.code(), Some(42));
    assert_eq!(std::fs::read(&marker).unwrap(), b"ran");
    assert!(!dir.path().join("breaker").exists());
    drop(guard);

    // After the holder exits, a fresh wrapper may consult and record the
    // absent daemon normally. A stale lock file must not strand it open.
    let status = Command::new(wrap())
        .arg(&fake)
        .args(["--crate-name", "fx"])
        .envs(wrap_env(dir.path()))
        .env("RABS_TEST_COMPILER_MARKER", &marker)
        .status()
        .unwrap();
    assert_eq!(status.code(), Some(42));
    let state = std::fs::read(dir.path().join("breaker")).unwrap();
    assert_eq!(
        rabs_protocol::wrapper_breaker::decode_state(&state).unwrap(),
        rabs_protocol::wrapper_breaker::BreakerState::Closed {
            consecutive_failures: 1,
        }
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
        .env("RABS_STATE_DIR", dir.path().join("state"))
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

    let fake = write_script(
        dir.path(),
        "fake-rustc",
        "printf '%s' \"$RABS_TEST_BINARY_ENV\"\nexit 0\n",
    );
    let breaker = dir.path().join("breaker");
    let raw_value = b"binary-\xff\xfe";
    for _ in 0..5 {
        let mut command = Command::new(wrap());
        command.arg(&fake).args(["--crate-name", "fx"]);
        command.env("RABS_BREAKER_FILE", &breaker);
        command.env("RABS_SOCKET_PATH", &socket);
        // Exercise observation, not merely the daemon-dead early return.
        // Neither unrelated values, Cargo values, nor non-UTF-8 names
        // may make enumeration panic or rewrite the compiler environment.
        command.env(
            "RABS_TEST_BINARY_ENV",
            OsString::from_vec(raw_value.to_vec()),
        );
        command.env(
            "CARGO_RABS_BINARY_ENV",
            OsString::from_vec(raw_value.to_vec()),
        );
        command.env(OsString::from_vec(b"RABS_TEST_\xff".to_vec()), "untouched");
        let output = command.output().unwrap();
        assert!(output.status.success(), "{:?}", output.stderr);
        assert_eq!(output.stdout.as_slice(), raw_value);
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
