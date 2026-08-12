//! S1 acceptance: the real `rabsd` binary — CLI timing budgets, config
//! refusal, obligation-clean boot/shutdown cycles, SIGTERM budget, and
//! kill -9 crash-evidence recovery. Everything here spawns the actual
//! binary (CARGO_BIN_EXE): no harness shortcuts.
#![cfg(unix)]

use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

fn rabsd() -> Command {
    Command::new(env!("CARGO_BIN_EXE_rabsd"))
}

fn run_capture(args: &[&str], envs: &[(&str, &str)]) -> (String, String, i32, Duration) {
    let start = Instant::now();
    let mut command = rabsd();
    command.args(args);
    for (key, value) in envs {
        command.env(key, value);
    }
    let output = command.output().expect("spawn rabsd");
    (
        String::from_utf8_lossy(&output.stdout).into_owned(),
        String::from_utf8_lossy(&output.stderr).into_owned(),
        output.status.code().unwrap_or(-1),
        start.elapsed(),
    )
}

#[test]
fn version_help_and_check_config_meet_the_10ms_budget() {
    // First call warms fs caches; budget measured on the second.
    let _ = run_capture(&["--version"], &[]);
    for args in [["--version"], ["--help"]] {
        let (stdout, _, code, elapsed) = run_capture(&args, &[]);
        assert_eq!(code, 0);
        assert!(stdout.contains("rabsd"), "{stdout}");
        assert!(
            elapsed < Duration::from_millis(50),
            "{args:?} took {elapsed:?} (10ms budget with process-spawn slack)"
        );
    }
    let dir = tempfile::tempdir().unwrap();
    let config = dir.path().join("config.toml");
    std::fs::write(&config, "[rabs]\nsocket_path = \"/tmp/x.sock\"\n").unwrap();
    let (stdout, _, code, _) = run_capture(
        &["--check-config"],
        &[("RABS_CONFIG", config.to_str().unwrap())],
    );
    assert_eq!(code, 0);
    assert!(
        stdout.contains("\"socket_path\":\"/tmp/x.sock\""),
        "{stdout}"
    );
}

#[test]
fn unknown_config_keys_refuse_loudly() {
    let dir = tempfile::tempdir().unwrap();
    let config = dir.path().join("config.toml");
    std::fs::write(&config, "[rabs]\nsocket_path = \"/tmp/x\"\ntypo_key = 1\n").unwrap();
    let (_, stderr, code, _) = run_capture(
        &["--check-config"],
        &[("RABS_CONFIG", config.to_str().unwrap())],
    );
    assert_eq!(code, 1);
    assert!(stderr.contains("typo_key"), "{stderr}");
    assert!(stderr.contains("known keys"), "{stderr}");
}

#[test]
fn hundred_boot_shutdown_cycles_all_obligation_clean() {
    // THE S1 acceptance loop: 100 real boot/shutdown cycles, every
    // receipt clean, every marker removed. Unique socket per test —
    // the default path collides across concurrent daemons (found live
    // on hz2 when S3 landed the edge server). Unique STATE DIR too: the
    // janitor mounts a real store under it and the coordinator acquires
    // its authority there, so sharing the default directory would make
    // concurrent daemons fight over one store (and scribble on the
    // developer's own).
    let dir = tempfile::tempdir().unwrap();
    let marker = dir.path().join("rabsd.boot");
    let socket = dir.path().join("rabsd.sock");
    let state = dir.path().join("state");
    for cycle in 0..100 {
        let (stdout, stderr, code, _) = run_capture(
            &["--run-for-ms", "5"],
            &[
                ("RABS_BOOT_MARKER", marker.to_str().unwrap()),
                ("RABS_SOCKET_PATH", socket.to_str().unwrap()),
                ("RABS_STATE_DIR", state.to_str().unwrap()),
                ("RABS_CONFIG", "/nonexistent-rabs-config"),
            ],
        );
        assert_eq!(code, 0, "cycle {cycle}: exit={code}\n{stderr}");
        let receipt = stdout.lines().last().unwrap_or_default();
        assert!(
            receipt.contains("\"clean\":true"),
            "cycle {cycle}: unclean receipt: {receipt}"
        );
        assert!(
            !marker.exists(),
            "cycle {cycle}: clean shutdown must remove the boot marker"
        );
    }
}

fn spawn_daemon(marker: &std::path::Path) -> Child {
    // Unique socket AND state dir beside the marker: concurrent daemons
    // on one host must never share the default socket path or the store.
    let socket = marker.with_extension("sock");
    rabsd()
        .env("RABS_BOOT_MARKER", marker)
        .env("RABS_SOCKET_PATH", &socket)
        .env("RABS_STATE_DIR", marker.with_extension("state"))
        .env("RABS_CONFIG", "/nonexistent-rabs-config")
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn daemon")
}

fn wait_for_marker(marker: &std::path::Path) {
    let deadline = Instant::now() + Duration::from_secs(5);
    while !marker.exists() {
        assert!(Instant::now() < deadline, "daemon never wrote boot marker");
        std::thread::sleep(Duration::from_millis(5));
    }
}

#[test]
fn sigterm_exits_clean_within_budget() {
    let dir = tempfile::tempdir().unwrap();
    let marker = dir.path().join("rabsd.boot");
    let mut child = spawn_daemon(&marker);
    wait_for_marker(&marker);
    // Give the signal listener a beat to install, then SIGTERM.
    std::thread::sleep(Duration::from_millis(150));
    let start = Instant::now();
    let status = Command::new("kill")
        .args(["-TERM", &child.id().to_string()])
        .status()
        .expect("send SIGTERM");
    assert!(status.success());
    let exit = child.wait().expect("daemon exit");
    let elapsed = start.elapsed();
    assert!(
        elapsed < Duration::from_millis(500),
        "SIGTERM-to-exit took {elapsed:?} (100ms budget + test slack)"
    );
    assert_eq!(exit.code(), Some(0), "clean exit after SIGTERM");
    assert!(!marker.exists(), "clean shutdown removed the marker");
}

#[test]
fn kill_nine_leaves_evidence_and_next_boot_reports_recovery() {
    let dir = tempfile::tempdir().unwrap();
    let marker = dir.path().join("rabsd.boot");
    let mut child = spawn_daemon(&marker);
    wait_for_marker(&marker);
    child.kill().expect("SIGKILL"); // kill -9: no cleanup possible
    child.wait().expect("reaped");
    assert!(marker.exists(), "kill -9 must leave the crash evidence");

    // Same socket as the killed daemon: the recovery boot also
    // exercises stale-socket takeover (liveness probe on a dead peer).
    let socket = marker.with_extension("sock");
    let (stdout, stderr, code, _) = run_capture(
        &["--run-for-ms", "10"],
        &[
            ("RABS_BOOT_MARKER", marker.to_str().unwrap()),
            ("RABS_SOCKET_PATH", socket.to_str().unwrap()),
            (
                "RABS_STATE_DIR",
                marker.with_extension("state").to_str().unwrap(),
            ),
            ("RABS_CONFIG", "/nonexistent-rabs-config"),
        ],
    );
    assert_eq!(code, 0, "{stderr}");
    assert!(
        stderr.contains("rabsd-recovery"),
        "next boot must report the unclean prior incarnation: {stderr}"
    );
    assert!(
        stdout.contains("\"recovered_from_unclean\":true"),
        "{stdout}"
    );
}
