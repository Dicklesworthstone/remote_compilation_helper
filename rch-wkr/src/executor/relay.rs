//! Output completion belongs to the command execution future. A descendant
//! retaining a pipe after the foreground command exits cannot keep the worker
//! awaiting EOF forever. This does not prove that descendants have stopped;
//! process-group/scope cleanup remains the surrounding execution owner's job.

use std::future::Future;
use std::io;
use std::process::ExitStatus;
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

/// The running command has no new time limit. This allowance starts only once
/// its terminal status is observed; output not drained by then is incomplete.
pub(super) const POST_EXIT_DRAIN: Duration = Duration::from_secs(5);

pub(super) async fn stream(
    mut reader: impl AsyncRead + Unpin,
    mut writer: impl AsyncWrite + Unpin,
    name: &'static str,
) -> bool {
    let result = async {
        let mut buffer = [0_u8; 4096];
        loop {
            let count = reader.read(&mut buffer).await?;
            if count == 0 {
                return Ok::<_, io::Error>(());
            }
            writer.write_all(&buffer[..count]).await?;
            writer.flush().await?;
        }
    }
    .await;
    if let Err(error) = result {
        tracing::error!(stream = name, %error, "Command output relay failed");
        false
    } else {
        true
    }
}

/// Poll the wait and both relays together, without detached JoinHandles. A
/// dropped execution or failed wait therefore also drops the pipe readers.
/// Tokio's standard-output writers can have an OS blocking write in flight;
/// this is a bound on pipe drainage, not a hard shutdown guarantee for a blocked
/// standard-output device. No EOF or successful output is invented on expiry.
pub(super) async fn collect(
    wait: impl Future<Output = io::Result<ExitStatus>>,
    stdout: impl Future<Output = bool>,
    stderr: impl Future<Output = bool>,
    drain: Duration,
) -> io::Result<(ExitStatus, bool, bool)> {
    tokio::pin!(wait, stdout, stderr);
    let mut stdout_done = None;
    let mut stderr_done = None;
    let status = loop {
        tokio::select! {
            // Observe an available exit even under sustained output traffic.
            biased;
            status = &mut wait => break status?,
            done = &mut stdout, if stdout_done.is_none() => stdout_done = Some(done),
            done = &mut stderr, if stderr_done.is_none() => stderr_done = Some(done),
        }
    };

    let deadline = tokio::time::sleep(drain);
    tokio::pin!(deadline);
    loop {
        if let (Some(stdout_done), Some(stderr_done)) = (stdout_done, stderr_done) {
            return Ok((status, stdout_done, stderr_done));
        }
        tokio::select! {
            biased;
            _ = &mut deadline => {
                tracing::error!(
                    drain_ms = drain.as_millis(),
                    "Command exited but output relay did not reach EOF before its drain deadline"
                );
                return Ok((status, stdout_done.unwrap_or(false), stderr_done.unwrap_or(false)));
            }
            done = &mut stdout, if stdout_done.is_none() => stdout_done = Some(done),
            done = &mut stderr, if stderr_done.is_none() => stderr_done = Some(done),
        }
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::os::unix::process::ExitStatusExt;
    use std::pin::Pin;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::task::{Context, Poll};
    use tokio::sync::oneshot;

    fn status(code: i32) -> ExitStatus {
        ExitStatus::from_raw(code << 8)
    }

    #[tokio::test]
    async fn finished_streams_still_wait_for_the_command() {
        let (send, receive) = oneshot::channel();
        let mut collected = Box::pin(collect(
            async { receive.await.unwrap() },
            async { true },
            async { true },
            Duration::ZERO,
        ));
        // Poll both stream completions while the command is explicitly gated.
        // A zero drain allowance must not expire a still-running command.
        tokio::select! {
            biased;
            result = &mut collected => panic!("returned before command exit: {result:?}"),
            () = tokio::task::yield_now() => {}
        }
        send.send(Ok(status(42))).unwrap();
        let (exit, stdout, stderr) = collected.await.unwrap();
        assert_eq!(exit.code(), Some(42));
        assert!(stdout && stderr);
    }

    struct PendingRelay(Arc<AtomicUsize>);

    impl Future for PendingRelay {
        type Output = bool;

        fn poll(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<bool> {
            Poll::Pending
        }
    }

    impl Drop for PendingRelay {
        fn drop(&mut self) {
            self.0.fetch_add(1, Ordering::SeqCst);
        }
    }

    #[tokio::test]
    async fn retained_pipes_expire_without_losing_the_terminal_status() {
        for code in [0, 42] {
            let dropped = Arc::new(AtomicUsize::new(0));
            let collected = collect(
                async { Ok(status(code)) },
                PendingRelay(dropped.clone()),
                PendingRelay(dropped.clone()),
                Duration::from_millis(10),
            );
            let (exit, stdout, stderr) = tokio::time::timeout(Duration::from_secs(5), collected)
                .await
                .expect("post-exit pipes must have a finite drain")
                .unwrap();
            assert_eq!(exit.code(), Some(code));
            assert!(!stdout && !stderr);
            assert_eq!(dropped.load(Ordering::SeqCst), 2);
        }
    }

    #[tokio::test]
    async fn cancellation_drops_both_relays_instead_of_detaching_them() {
        let dropped = Arc::new(AtomicUsize::new(0));
        let mut collected = Box::pin(collect(
            std::future::pending(),
            PendingRelay(dropped.clone()),
            PendingRelay(dropped.clone()),
            POST_EXIT_DRAIN,
        ));
        tokio::select! {
            biased;
            result = &mut collected => panic!("unexpected terminal result: {result:?}"),
            () = tokio::task::yield_now() => {}
        }
        drop(collected);
        assert_eq!(dropped.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn wait_failure_preserves_error_and_drops_both_relays() {
        let dropped = Arc::new(AtomicUsize::new(0));
        let error = collect(
            async { Err(io::Error::other("wait failed")) },
            PendingRelay(dropped.clone()),
            PendingRelay(dropped.clone()),
            POST_EXIT_DRAIN,
        )
        .await
        .unwrap_err();
        assert_eq!(error.to_string(), "wait failed");
        assert_eq!(dropped.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn either_stream_failure_is_retained() {
        for expected in [(true, false), (false, true), (false, false), (true, true)] {
            let (exit, stdout, stderr) = collect(
                async { Ok(status(0)) },
                async { expected.0 },
                async { expected.1 },
                POST_EXIT_DRAIN,
            )
            .await
            .unwrap();
            assert!(exit.success());
            assert_eq!((stdout, stderr), expected);
        }
    }

    #[tokio::test]
    async fn streams_both_binary_pipes_concurrently_before_exit() {
        let (stdout, mut stdout_source) = tokio::io::duplex(64);
        let (stderr, mut stderr_source) = tokio::io::duplex(64);
        let (exited, wait) = oneshot::channel();
        let bytes: Vec<u8> = (0..=255).cycle().take(128 * 1024).collect();
        let mut out = Vec::new();
        let mut err = Vec::new();
        let writer = async {
            let (a, b) = tokio::join!(
                stdout_source.write_all(&bytes),
                stderr_source.write_all(&bytes),
            );
            a.unwrap();
            b.unwrap();
            stdout_source.shutdown().await.unwrap();
            stderr_source.shutdown().await.unwrap();
            exited.send(Ok(status(0))).unwrap();
        };
        let reader = collect(
            async { wait.await.unwrap() },
            stream(stdout, &mut out, "stdout"),
            stream(stderr, &mut err, "stderr"),
            POST_EXIT_DRAIN,
        );
        let (result, ()) = tokio::time::timeout(Duration::from_secs(10), async {
            tokio::join!(reader, writer)
        })
        .await
        .expect("both small-capacity pipes must be drained concurrently");
        let (exit, stdout, stderr) = result.unwrap();
        assert!(exit.success() && stdout && stderr);
        assert_eq!(out, bytes);
        assert_eq!(err, bytes);
    }
}
