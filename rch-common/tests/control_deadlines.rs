//! Execute the production control protocol, including its compiled composition.
#[cfg(target_os = "linux")]
#[test]
fn worker_control_deadlines() {
    let directory = tempfile::tempdir().expect("temporary protocol directory");
    let protocol = directory.path().join("protocol.sh");
    std::fs::write(&protocol, rch_common::REMOTE_PROCESS_IDENTITY_SCRIPT)
        .expect("write compiled control protocol");
    let status = std::process::Command::new("python3")
        .arg(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/control_deadlines.py"
        ))
        .env("RCH_CONTROL_TEST_PROTOCOL", &protocol)
        .status()
        .expect("run control deadline regressions (requires Python 3)");
    assert!(status.success(), "control deadline regressions failed");
}

/// Exercise the real public capture APIs with native processes. These tests
/// intentionally have their own filter so they do not invoke the legacy suite.
#[cfg(unix)]
mod control_capture_native {
    use std::io;
    use std::process::Output;
    use std::time::Duration;

    use rch_common::ssh::{capture_control_output, capture_supervised_output_inherited_group};
    use tokio::process::Command;
    use tokio::time::Instant;

    const INPUT_SIZE: usize = 8 * 1024 * 1024;

    async fn capture(
        command: &mut Command,
        input: &[u8],
        stdout_limit: usize,
        stderr_limit: usize,
        deadline: Instant,
        inherited: bool,
    ) -> io::Result<Output> {
        if inherited {
            capture_supervised_output_inherited_group(
                command,
                Some(input),
                stdout_limit,
                stderr_limit,
                deadline,
            )
            .await
        } else {
            capture_control_output(command, Some(input), stdout_limit, stderr_limit, deadline).await
        }
    }

    #[tokio::test]
    async fn early_nonzero_refusal_preserves_status_and_complete_diagnostics() {
        for inherited in [false, true] {
            // Close input before producing more diagnostics than fit in an
            // ordinary pipe. Upload failure must not cancel either reader.
            let mut command = Command::new("sh");
            command.args(["-c", "exec 0<&-; head -c 131072 /dev/zero >&2; printf 'refused\\n'; printf 'invalid scale\\n' >&2; exit 73"]);
            let input = vec![b'x'; INPUT_SIZE];
            let output = capture(
                &mut command,
                &input,
                128,
                256 * 1024,
                Instant::now() + Duration::from_secs(10),
                inherited,
            )
            .await
            .expect("a complete nonzero refusal must survive BrokenPipe during upload");
            assert_eq!(output.status.code(), Some(73));
            assert_eq!(output.stdout, b"refused\n");
            let mut expected = vec![0; 131_072];
            expected.extend_from_slice(b"invalid scale\n");
            assert_eq!(output.stderr, expected);
        }
    }

    #[tokio::test]
    async fn incomplete_upload_never_accepts_a_successful_receipt() {
        for inherited in [false, true] {
            let mut command = Command::new("sh");
            command.args(["-c", "exec 0<&-; printf 'receipt\\n'; exit 0"]);
            let input = vec![b'x'; INPUT_SIZE];
            let error = capture(
                &mut command,
                &input,
                128,
                128,
                Instant::now() + Duration::from_secs(10),
                inherited,
            )
            .await
            .expect_err("successful output cannot repair an incomplete upload");
            assert_eq!(error.kind(), io::ErrorKind::BrokenPipe);
        }
    }

    #[tokio::test]
    async fn early_refusal_does_not_bypass_either_output_bound() {
        for inherited in [false, true] {
            for script in [
                "exec 0<&-; head -c 65 /dev/zero; exit 73",
                "exec 0<&-; head -c 65 /dev/zero >&2; exit 73",
            ] {
                let mut command = Command::new("sh");
                command.args(["-c", script]);
                let input = vec![b'x'; INPUT_SIZE];
                let error = capture(
                    &mut command,
                    &input,
                    64,
                    64,
                    Instant::now() + Duration::from_secs(10),
                    inherited,
                )
                .await
                .expect_err("a failed upload cannot excuse truncated diagnostic evidence");
                assert_eq!(error.kind(), io::ErrorKind::InvalidData);
            }
        }
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn early_closed_input_retains_deadline_and_owned_child_cleanup() {
        use rustix::process::{Pid, PidfdFlags, Signal};
        use std::os::fd::{AsFd, OwnedFd};

        struct ExactChild(OwnedFd);
        impl Drop for ExactChild {
            fn drop(&mut self) {
                let _ = rustix::process::pidfd_send_signal(&self.0, Signal::KILL);
            }
        }

        for inherited in [false, true] {
            let directory = tempfile::tempdir().unwrap().keep();
            let ready = directory.join("ready");
            let child_ready = ready.clone();
            let task = tokio::spawn(async move {
                let mut command = Command::new("sh");
                command.args(["-c", "exec 0<&-; printf '%s\\n' \"$$\" > \"$1\"; printf 'refusal pending\\n' >&2; exec 1>&- 2>&-; exec sleep 60", "rch-refusal-deadline"])
                    .arg(child_ready);
                let input = vec![b'x'; INPUT_SIZE];
                capture(
                    &mut command,
                    &input,
                    128,
                    128,
                    Instant::now() + Duration::from_secs(3),
                    inherited,
                )
                .await
            });
            let pid = tokio::time::timeout(Duration::from_secs(2), async {
                loop {
                    if let Ok(contents) = std::fs::read_to_string(&ready)
                        && let Ok(pid) = contents.trim().parse::<i32>()
                    {
                        break Pid::from_raw(pid).unwrap();
                    }
                    tokio::time::sleep(Duration::from_millis(5)).await;
                }
            })
            .await
            .expect("the real child must close stdin and start before its deadline");
            let child = ExactChild(rustix::process::pidfd_open(pid, PidfdFlags::empty()).unwrap());
            let error = task
                .await
                .unwrap()
                .expect_err("an unfinished refusal cannot outlive the capture budget");
            assert_eq!(error.kind(), io::ErrorKind::TimedOut);
            let event = tokio::io::unix::AsyncFd::new(child.0.as_fd()).unwrap();
            let _ready = tokio::time::timeout(Duration::from_secs(3), event.readable())
                .await
                .expect("deadline expiry must still terminate the exact owned child")
                .unwrap();
        }
    }
}
