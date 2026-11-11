//! `rch-wkr setsid`: the session launcher Darwin workers use in place of the
//! missing setsid(1).
#![cfg(unix)]

use std::process::Command;
use std::time::{Duration, Instant};

#[test]
fn passes_every_argument_through_verbatim() {
    let output = Command::new(env!("CARGO_BIN_EXE_rch-wkr"))
        .args([
            "setsid",
            "sh",
            "-c",
            "printf '%s|' \"$@\"",
            "argv0",
            "-v",
            "--help",
            "a b",
        ])
        .output()
        .unwrap();
    assert!(output.status.success(), "{output:?}");
    assert_eq!(output.stdout, b"-v|--help|a b|");
}

#[test]
fn the_command_leads_its_own_session() {
    let mut child = Command::new(env!("CARGO_BIN_EXE_rch-wkr"))
        .args(["setsid", "sleep", "30"])
        .spawn()
        .unwrap();
    let pid = rustix::process::Pid::from_child(&child);
    let deadline = Instant::now() + Duration::from_secs(10);
    let led = loop {
        if rustix::process::getsid(Some(pid)).ok() == Some(pid) {
            break true;
        }
        if Instant::now() > deadline {
            break false;
        }
        std::thread::sleep(Duration::from_millis(20));
    };
    let _ = child.kill();
    let _ = child.wait();
    assert!(led, "rch-wkr setsid did not start a new session");
}

#[test]
fn exec_failure_is_an_error_not_a_silent_success() {
    let output = Command::new(env!("CARGO_BIN_EXE_rch-wkr"))
        .args(["setsid", "/nonexistent/rch-test-command"])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(1), "{output:?}");
    assert!(String::from_utf8_lossy(&output.stderr).contains("/nonexistent/rch-test-command"));
}

#[test]
fn closed_standard_descriptors_are_restored_after_native_startup() {
    let owner = tempfile::Builder::new()
        .prefix("rch-setsid-stdio-")
        .disable_cleanup(true)
        .tempdir()
        .unwrap();
    for mask in 0_u8..=7 {
        let witness = owner.path().join(format!("descriptors-{mask}"));
        let script = r#"
state=0
( : 3>&0 ) 2>/dev/null && state=$((state | 1))
( : 3>&1 ) 2>/dev/null && state=$((state | 2))
( : 3>&2 2>/dev/null ) && state=$((state | 4))
printf '%s' "$state" > "$1"
"#;
        let status = Command::new(env!("CARGO_BIN_EXE_rch-wkr"))
            .args(["setsid", "--closed-stdio", &mask.to_string(), "--"])
            .args(["/bin/sh", "-c", script, "rch-fd-witness"])
            .arg(&witness)
            .status()
            .unwrap();
        assert!(status.success(), "mask {mask}: {status:?}");
        assert_eq!(
            std::fs::read_to_string(&witness).unwrap(),
            (7 ^ mask).to_string(),
            "native startup reopened a descriptor for mask {mask}"
        );
    }
}
