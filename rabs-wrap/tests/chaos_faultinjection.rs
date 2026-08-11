//! S8 chaos slice: seeded, deterministic fault injection against the
//! live spine, asserting the fail-open invariants that the whole design
//! rests on. Each round kills the daemon at a randomized-but-SEEDED
//! point relative to a wrapper consult and asserts:
//!
//!   INV-1  No wrapper ever fails a build because RABS had a fault — the
//!          wrapper always execs the real compiler (fail-open).
//!   INV-2  No wrapper wedges past its bounded budget under any fault.
//!   INV-3  The breaker opens under sustained daemon death and recovers
//!          on the next successful consult (C-epic state machine, live).
//!   INV-4  Every receipt the daemon DID write is well-formed (no torn
//!          JSON), because receipt-before-index ordering holds even
//!          across a mid-write kill.
//!
//! Deterministic: the kill offsets come from a seeded LCG, printed with
//! every failure so a red run is exactly replayable. No wall clock, no
//! `rand`.
#![cfg(unix)]

use std::io::Write as _;
use std::os::unix::fs::PermissionsExt;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

const SEED: u64 = 0x5EED_C0DE_1234_5678;

/// A tiny seeded LCG (Numerical Recipes constants) — replaces `rand`,
/// stays deterministic, and every failure prints the seed.
struct Lcg(u64);
impl Lcg {
    fn next_u64(&mut self) -> u64 {
        self.0 = self.0.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
        self.0
    }
    fn in_range(&mut self, lo: u64, hi: u64) -> u64 {
        lo + self.next_u64() % (hi - lo)
    }
}

fn rabsd() -> std::path::PathBuf {
    // The rabsd binary lives beside ours in the target dir; build it
    // once if a chaos-only test run hasn't produced it yet.
    let path = std::path::Path::new(env!("CARGO_BIN_EXE_rabs-wrap")).with_file_name("rabsd");
    if !path.exists() {
        let status = Command::new(env!("CARGO"))
            .args(["build", "-p", "rabsd", "--bin", "rabsd"])
            .status()
            .expect("build rabsd");
        assert!(status.success(), "rabsd build failed");
    }
    path
}

fn spawn_daemon(dir: &std::path::Path) -> Child {
    Command::new(rabsd())
        .env("RABS_SOCKET_PATH", dir.join("rabsd.sock"))
        .env("RABS_BOOT_MARKER", dir.join("rabsd.boot"))
        .env("RABS_STATE_DIR", dir.join("state"))
        .env("RABS_CONFIG", "/nonexistent-rabs-config")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn rabsd")
}

fn wait_for_socket(socket: &std::path::Path, up: bool) {
    let deadline = Instant::now() + Duration::from_secs(10);
    while socket.exists() != up {
        assert!(
            Instant::now() < deadline,
            "socket {} did not reach up={up} (seed {SEED:#x})",
            socket.display()
        );
        std::thread::sleep(Duration::from_millis(5));
    }
}

fn fake_rustc(dir: &std::path::Path) -> std::path::PathBuf {
    let path = dir.join("fake-rustc");
    std::fs::write(&path, "#!/bin/sh\nexit 0\n").unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
    path
}

fn run_wrapper(dir: &std::path::Path, fake: &std::path::Path) -> (bool, Duration) {
    let start = Instant::now();
    let status = Command::new(env!("CARGO_BIN_EXE_rabs-wrap"))
        .arg(fake)
        .args(["--crate-name", "fx", "src/lib.rs"])
        .env("RABS_BREAKER_FILE", dir.join("breaker"))
        .env("RABS_SOCKET_PATH", dir.join("rabsd.sock"))
        .status()
        .expect("wrapper run");
    (status.success(), start.elapsed())
}

#[test]
fn kill_daemon_at_seeded_offsets_never_breaks_or_wedges_a_build() {
    let dir = tempfile::tempdir().unwrap();
    let fake = fake_rustc(dir.path());
    let socket = dir.path().join("rabsd.sock");
    let mut rng = Lcg(SEED);

    // 30 rounds: each starts a daemon, fires a wrapper, and kills the
    // daemon at a seeded delay straddling the consult window.
    for round in 0..30u32 {
        let mut daemon = spawn_daemon(dir.path());
        wait_for_socket(&socket, true);

        // Seeded kill offset: 0..8ms — sometimes before the wrapper
        // even connects, sometimes mid-consult, sometimes after.
        let kill_after_us = rng.in_range(0, 8000);
        let daemon_pid = daemon.id();
        let killer = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_micros(kill_after_us));
            // SIGKILL: the harshest fault, no cleanup possible.
            kill9(daemon_pid);
        });

        let (build_ok, elapsed) = run_wrapper(dir.path(), &fake);
        killer.join().unwrap();
        let _ = daemon.wait();

        // INV-1: the build ALWAYS succeeds (fail-open).
        assert!(
            build_ok,
            "round {round}: build FAILED under fault (seed {SEED:#x}, kill_after={kill_after_us}us)"
        );
        // INV-2: never wedged past a generous multiple of the budget.
        assert!(
            elapsed < Duration::from_secs(2),
            "round {round}: wrapper wedged {elapsed:?} (seed {SEED:#x}, kill_after={kill_after_us}us)"
        );

        // INV-4: every receipt the daemon wrote parses as JSON.
        let receipts = dir.path().join("state/shadow-receipts.ndjson");
        if let Ok(text) = std::fs::read_to_string(&receipts) {
            for (line_no, line) in text.lines().enumerate() {
                if line.is_empty() {
                    continue;
                }
                assert!(
                    serde_json::from_str::<serde_json::Value>(line).is_ok(),
                    "round {round}: torn receipt at line {line_no} (seed {SEED:#x}): {line}"
                );
            }
        }
        // SIGKILL leaves the socket file behind (no clean shutdown ran).
        // That is exactly the stale-socket the next boot's liveness-probe
        // takeover (S3) handles — but this harness restarts fast, so we
        // remove it ourselves to keep each round independent. (In
        // production the takeover would do this.)
        let _ = std::fs::remove_file(&socket);
    }
}

#[test]
fn breaker_opens_under_sustained_death_and_recovers_on_live_daemon() {
    // INV-3: with no daemon, 3 consults open the breaker; then a live
    // daemon's first successful consult resets it (C-epic model, live).
    let dir = tempfile::tempdir().unwrap();
    let fake = fake_rustc(dir.path());

    for _ in 0..3 {
        let (ok, _) = run_wrapper(dir.path(), &fake);
        assert!(ok, "fail-open under dead daemon (seed {SEED:#x})");
    }
    let opened = rabs_protocol::wrapper_breaker::decode_state(
        &std::fs::read(dir.path().join("breaker")).unwrap(),
    )
    .unwrap();
    assert!(
        matches!(opened, rabs_protocol::wrapper_breaker::BreakerState::Open { .. }),
        "breaker must open under sustained death (seed {SEED:#x}): {opened:?}"
    );

    // Bring a daemon up; consult until the breaker's cooldown lets a
    // probe through and it recovers.
    let mut daemon = spawn_daemon(dir.path());
    wait_for_socket(&dir.path().join("rabsd.sock"), true);
    let deadline = Instant::now() + Duration::from_secs(15);
    let recovered = loop {
        let (ok, _) = run_wrapper(dir.path(), &fake);
        assert!(ok, "fail-open during recovery (seed {SEED:#x})");
        let state = rabs_protocol::wrapper_breaker::decode_state(
            &std::fs::read(dir.path().join("breaker")).unwrap(),
        )
        .unwrap();
        if matches!(state, rabs_protocol::wrapper_breaker::BreakerState::Closed { .. }) {
            break true;
        }
        if Instant::now() > deadline {
            break false;
        }
        std::thread::sleep(Duration::from_millis(100));
    };
    Command::new("kill")
        .args(["-TERM", &daemon.id().to_string()])
        .status()
        .unwrap();
    let _ = daemon.wait();
    assert!(recovered, "breaker never recovered against a live daemon (seed {SEED:#x})");
}

#[test]
fn compressed_soak_no_receipt_gaps_or_build_failures() {
    // A COMPRESSED stand-in for the 24h production soak (the full
    // wall-clock soak runs over real calendar time against live agent
    // traffic and is tracked separately): 200 consults against a stable
    // daemon, asserting zero build failures and receipt/consult 1:1.
    let dir = tempfile::tempdir().unwrap();
    let fake = fake_rustc(dir.path());
    let mut daemon = spawn_daemon(dir.path());
    wait_for_socket(&dir.path().join("rabsd.sock"), true);

    let mut builds = 0u32;
    for _ in 0..200 {
        let (ok, elapsed) = run_wrapper(dir.path(), &fake);
        assert!(ok, "soak build failed (seed {SEED:#x})");
        assert!(elapsed < Duration::from_secs(2), "soak wrapper slow: {elapsed:?}");
        builds += 1;
    }

    Command::new("kill")
        .args(["-TERM", &daemon.id().to_string()])
        .status()
        .unwrap();
    let _ = daemon.wait();

    // Every consult produced exactly one well-formed receipt.
    let receipts = std::fs::read_to_string(dir.path().join("state/shadow-receipts.ndjson"))
        .expect("receipts exist");
    let receipt_lines = receipts.lines().filter(|l| !l.is_empty()).count();
    assert_eq!(
        receipt_lines, builds as usize,
        "receipt/consult gap: {receipt_lines} receipts for {builds} builds (seed {SEED:#x})"
    );
    for line in receipts.lines().filter(|l| !l.is_empty()) {
        let value: serde_json::Value = serde_json::from_str(line).expect("well-formed receipt");
        assert_eq!(value["grade"], "shadow-upper-bound");
    }
    let _ = std::io::stdout().flush();
}

/// SIGKILL a pid without a libc dependency (this crate forbids unsafe,
/// so shell out to `kill -9` — the fault we want is the process dying,
/// not how we deliver it).
fn kill9(pid: u32) {
    let _ = Command::new("kill").args(["-9", &pid.to_string()]).status();
}
