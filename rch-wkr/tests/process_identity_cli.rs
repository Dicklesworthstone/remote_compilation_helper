//! Exercise the real worker binary, not merely Clap or shell parsing.
//! Identity control must not depend on optional logging or a Tokio runtime.

use std::process::{Command, Output};

fn probe(pid: u32) -> Output {
    let directory = tempfile::tempdir().expect("temporary directory");
    let not_a_directory = directory.path().join("not-a-directory");
    std::fs::write(&not_a_directory, b"not a log directory").unwrap();
    Command::new(env!("CARGO_BIN_EXE_rch-wkr"))
        .args(["process-identity", &pid.to_string()])
        // Both would break the ordinary worker startup path. Neither can
        // block an otherwise available native identity or change its output.
        .env("RCH_LOG_FILE", not_a_directory.join("worker.log"))
        .env("TOKIO_WORKER_THREADS", "0")
        .output()
        .expect("run candidate worker")
}

#[test]
fn invalid_identities_refuse_without_runtime_or_log_initialization() {
    for pid in [0, 1, u32::MAX] {
        let output = probe(pid);
        assert!(!output.status.success(), "invalid PID {pid} was accepted");
        assert!(
            output.stdout.is_empty(),
            "failure emitted a partial witness"
        );
        let diagnostic = String::from_utf8_lossy(&output.stderr);
        assert!(
            diagnostic.contains("kernel process identity unavailable"),
            "unexpected control-path failure for {pid}: {diagnostic}"
        );
    }
}

#[cfg(not(target_os = "macos"))]
#[test]
fn unsupported_native_helper_never_invents_a_birth_identity() {
    let output = probe(std::process::id());
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("kernel process identity unavailable")
    );
}

#[cfg(target_os = "macos")]
#[test]
fn native_worker_witness_is_stable_and_reaped_birth_is_not_reissued() {
    struct OwnedChild(std::process::Child);
    impl Drop for OwnedChild {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }
    let child = OwnedChild(Command::new("/bin/sleep").arg("60").spawn().unwrap());
    let pid = child.0.id();
    let expected = rch_common::process_identity::remote_process_witness(pid)
        .expect("real kernel witness for our live child");
    let first = probe(pid);
    assert!(first.status.success(), "{:?}", first);
    assert!(first.stderr.is_empty(), "control output must be data only");
    assert_eq!(first.stdout, format!("{expected}\n").as_bytes());
    let again = probe(pid);
    assert!(again.status.success(), "{:?}", again);
    assert_eq!(again.stdout, first.stdout);

    drop(child); // Kill and reap the exact direct child, never a historical PID.
    let after = probe(pid);
    if after.status.success() {
        // A very fast PID reuse is legal; it must have a different birth.
        assert_ne!(after.stdout, first.stdout);
    } else {
        assert!(after.stdout.is_empty());
    }
}
