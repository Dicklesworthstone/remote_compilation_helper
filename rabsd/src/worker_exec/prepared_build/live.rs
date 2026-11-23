//! Direct TLS build diagnostics. Execution owns its transport on a joined
//! thread; the caller alone owns its console. The only shared output is a
//! bounded, nonblocking preview, never a completion or publication receipt.

use super::*;
use crate::prepared_jobs::{
    ClientDeadline, live::StderrPrefix, report_client_error, with_stopped_client_console,
};
use asupersync::signal::ShutdownController;
use rabs_asupersync::stream_drain::preview::{LiveOutputPreview, PreviewStream};
use rabsd::coord::secure_worker_delivery::{OperationCancellation, WorkerOutputObserver};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, SyncSender};
use std::thread::{self, JoinHandle};

const OBSERVATION_INTERVAL: Duration = Duration::from_millis(25);

/// Keep process signals connected to cancellation even while the caller's
/// console is stalled. The bridge owns no worker resources and is always joined.
struct SignalBridge {
    cancellation: OperationCancellation,
    stopped: Arc<AtomicBool>,
    done: Arc<AtomicBool>,
    thread: Option<JoinHandle<()>>,
}

impl SignalBridge {
    fn start() -> io::Result<Self> {
        let shutdown = Arc::new(ShutdownController::new());
        shutdown.listen_for_signals();
        let cancellation = OperationCancellation::new();
        let stopped = Arc::new(AtomicBool::new(false));
        let done = Arc::new(AtomicBool::new(false));
        let child_cancellation = cancellation.clone();
        let child_stopped = Arc::clone(&stopped);
        let child_done = Arc::clone(&done);
        let thread = thread::Builder::new()
            .name("rabs-direct-signals".into())
            .spawn(move || {
                while !child_done.load(Ordering::Acquire) {
                    if shutdown.is_shutting_down() {
                        child_stopped.store(true, Ordering::Release);
                        child_cancellation.cancel();
                        break;
                    }
                    thread::sleep(OBSERVATION_INTERVAL);
                }
            })?;
        Ok(Self {
            cancellation,
            stopped,
            done,
            thread: Some(thread),
        })
    }
}

impl Drop for SignalBridge {
    fn drop(&mut self) {
        self.done.store(true, Ordering::Release);
        self.cancellation.cancel();
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

struct CancelOnDrop(OperationCancellation);
impl Drop for CancelOnDrop {
    fn drop(&mut self) {
        self.0.cancel();
    }
}

/// A console error requests cancellation and then joins the execution's ordinary
/// authenticated cleanup. A panic also cancels before scope joins its child.
/// There is no detached executor, forwarding thread, or output-sized queue.
fn execute_observed<T: Send>(
    cancellation: &OperationCancellation,
    stopped: &AtomicBool,
    deadline: &ClientDeadline,
    prefix: &mut StderrPrefix,
    stderr: &mut impl Write,
    execute: impl FnOnce(Arc<LiveOutputPreview>, SyncSender<Value>) -> io::Result<T> + Send,
) -> io::Result<T> {
    let preview = Arc::new(LiveOutputPreview::default());
    let (listening, notifications) = mpsc::sync_channel(1);
    thread::scope(|scope| {
        let _cancel = CancelOnDrop(cancellation.clone());
        let producer = Arc::clone(&preview);
        #[cfg(target_os = "linux")]
        let output_deadline = deadline.output.clone();
        let execution = thread::Builder::new()
            .name("rabs-direct-execution".into())
            .spawn_scoped(scope, move || {
                let result = execute(producer, listening);
                // A blocked sink must notice completion without waiting for
                // its caller to finish that very write and poll this thread.
                #[cfg(target_os = "linux")]
                output_deadline.limit(Instant::now() + DIAGNOSTIC_REPLAY_BUDGET);
                result
            })?;
        let presentation = (|| -> io::Result<()> {
            loop {
                if stopped.load(Ordering::Acquire) || cancellation.is_cancelled() {
                    return Err(io::Error::new(
                        io::ErrorKind::Interrupted,
                        "direct build cancelled",
                    ));
                }
                if Instant::now() >= deadline.get() {
                    return Err(io::Error::new(
                        io::ErrorKind::TimedOut,
                        "direct build presentation deadline exceeded",
                    ));
                }
                // Observe completion before draining. If the producer finishes
                // during this pass, the next pass consumes its last observation.
                let finished = execution.is_finished();
                // The callback can submit only the one listener announcement;
                // it never writes to stderr on the execution owner.
                for message in notifications.try_iter() {
                    writeln!(stderr, "{message}")?;
                    stderr.flush()?;
                }
                if let Some(segment) = preview.take(PreviewStream::Stderr) {
                    prefix.append(
                        segment.offset,
                        segment.skipped_bytes,
                        &segment.bytes,
                        stderr,
                    )?;
                }
                if finished {
                    return Ok(());
                }
                thread::sleep(OBSERVATION_INTERVAL);
            }
        })();
        if presentation.is_err() {
            cancellation.cancel();
        }
        let result = execution
            .join()
            .map_err(|_| io::Error::other("direct execution owner panicked"))?;
        presentation?;
        result
    })
}

pub(super) fn validate_request(request: &Value) -> io::Result<()> {
    if rabs_sandbox::cargo_artifacts::requested(request)?.is_none() {
        return Err(invalid(
            "live stderr requires the native whole-Cargo diagnostics contract",
        ));
    }
    Ok(())
}

fn replay_completed(
    snapshot: DiagnosticSnapshot,
    prefix: &StderrPrefix,
    report: &Value,
    stdout: &mut impl Write,
    stderr: &mut impl Write,
    until: Instant,
    replay_started: &mut bool,
) -> io::Result<()> {
    let snapshot = snapshot.after_stderr_prefix(&prefix.descriptor()?, until)?;
    // A fast execution may have produced no live preview at all. Even the first
    // failed final write can expose bytes, independently of the prefix state.
    *replay_started = true;
    emit_report(report, Some(snapshot), stdout, stderr, until)
}

impl PreparedBuild<'_> {
    pub(super) fn report_live(&self, reserved: Option<ReservedWorkerAdmission>) -> i32 {
        let mut prefix = StderrPrefix::default();
        let mut execution_may_have_run = false;
        let mut final_replay_started = false;
        let result = (|| -> io::Result<i32> {
            if self.pin.is_none() {
                return Err(invalid("live stderr requires pinned TLS worker delivery"));
            }
            let request = self
                .request()
                .map_err(|error| io::Error::other(error.detail))?;
            validate_request(&request)?;
            // Bound the entire presentation, including accept, toolchain/source
            // upload and result transfer. Completion shortens the same console
            // deadline; a final replay never obtains a fresh execution budget.
            let budget = Duration::from_millis(
                request["timeout_ms"]
                    .as_u64()
                    .unwrap_or(super::super::MAX_EXECUTION_MILLIS)
                    .min(super::super::MAX_EXECUTION_MILLIS),
            ) + rabs_sandbox::toolchain_transfer::TOOLCHAIN_UPLOAD_BUDGET
                + super::super::ACCEPT_BUDGET
                + super::super::HANDSHAKE_BUDGET
                + super::super::TRANSFER_ALLOWANCE * 2;
            let deadline = ClientDeadline::new(Instant::now() + budget);
            let signals = SignalBridge::start()?;
            with_stopped_client_console(&deadline, &signals.stopped, |mut stdout, mut stderr| {
                execution_may_have_run = true;
                let (delivery, installed) = execute_observed(
                    &signals.cancellation,
                    &signals.stopped,
                    &deadline,
                    &mut prefix,
                    &mut stderr,
                    |preview, listening| {
                        let mut on_listening = |address: std::net::SocketAddr| {
                            listening.try_send(json!({
                                "kind":"worker-exec-listening", "address":address.to_string(),
                                "expected_worker":self.worker, "expected_worker_spki_sha256":self.pin,
                                "request_id":request["request_id"], "transport":"mutual-tls-atp",
                                "operation":if self.mode == DeliveryMode::Resume { "result-resume" } else { "canonical-exec" },
                                "authentication_required":true,
                            })).map_err(|_| invalid("direct listener announcement was not accepted"))
                        };
                        self.execute_bound(
                            &request,
                            Some(TlsOperationControl {
                                cancellation: signals.cancellation.clone(),
                                preview: Some(WorkerOutputObserver::Direct(preview)),
                                on_listening: &mut on_listening,
                            }),
                            reserved,
                        )
                        .map_err(|error| io::Error::other(error.detail))
                    },
                )?;
                let until = deadline.complete();
                let snapshot = DiagnosticSnapshot::from_delivery(&delivery, until)?;
                let report = self.report_value(&delivery, installed.as_ref());
                replay_completed(
                    snapshot,
                    &prefix,
                    &report,
                    &mut stdout,
                    &mut stderr,
                    until,
                    &mut final_replay_started,
                )?;
                let code = delivery.receipt["exit_code"]
                    .as_i64()
                    .and_then(|code| i32::try_from(code).ok())
                    .unwrap_or(1);
                Ok(if code == 0 && installed.is_none() {
                    1
                } else {
                    code
                })
            })
        })();
        match result {
            Ok(code) => code,
            Err(error) => {
                report_client_error(json!({
                    "kind":"worker-build-error", "directory":self.directory,
                    "output_directory":self.output, "detail":error.to_string(),
                    "execution_may_have_run":execution_may_have_run, "reexecute":false,
                    "diagnostics_may_have_been_exposed":prefix.exposed() || final_replay_started,
                }));
                1
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::super::tests::diagnostic_snapshot;
    use super::*;
    #[cfg(target_os = "linux")]
    use std::io::Read;

    #[cfg(target_os = "linux")]
    fn child_capture(
        root: &Path,
        observer: Arc<LiveOutputPreview>,
        cancellation: &OperationCancellation,
        done: &AtomicBool,
    ) -> (Vec<u8>, Vec<u8>) {
        use rabs_asupersync::process_groups::ManagedProcessGroup;
        use rabs_asupersync::region_tree::Attribution;
        use rabs_asupersync::stream_drain::DrainLimits;
        use std::process::{Command, Stdio};

        let mut command = Command::new("sh");
        command.args(["-c", "printf 'first\\000\\377' >&2; while [ ! -e \"$GATE\" ]; do sleep 0.01; done; printf 'tail' >&2; printf 'stdout\\000\\377'"])
            .env("GATE", root.join("continue"))
            .stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::piped());
        let group = ManagedProcessGroup::spawn_command(command, Attribution::default()).unwrap();
        let until = Instant::now() + Duration::from_secs(10);
        let output = group
            .wait_with_bounded_drain_preview(
                &DrainLimits {
                    resident_bound: 2,
                    spill_dir: root.join("spill"),
                },
                1024,
                Some(observer),
                || cancellation.is_cancelled() || Instant::now() >= until,
            )
            .unwrap();
        assert_eq!(
            output.residual_group_members, 0,
            "child ownership must drain before return"
        );
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        output
            .stdout
            .reader()
            .unwrap()
            .read_to_end(&mut stdout)
            .unwrap();
        output
            .stderr
            .reader()
            .unwrap()
            .read_to_end(&mut stderr)
            .unwrap();
        done.store(true, Ordering::Release);
        (stdout, stderr)
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn real_child_stderr_is_visible_before_exit_and_verified_replay_does_not_duplicate_it() {
        struct GateWriter<'a> {
            root: &'a Path,
            done: &'a AtomicBool,
            bytes: Vec<u8>,
        }
        impl Write for GateWriter<'_> {
            fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
                if self.bytes.is_empty() {
                    assert!(
                        !self.done.load(Ordering::Acquire),
                        "first bytes arrived only after exit"
                    );
                    fs::write(self.root.join("continue"), b"proceed")?;
                }
                self.bytes.extend_from_slice(bytes);
                Ok(bytes.len())
            }
            fn flush(&mut self) -> io::Result<()> {
                Ok(())
            }
        }
        let directory = tempfile::tempdir().unwrap();
        let done = AtomicBool::new(false);
        let cancellation = OperationCancellation::new();
        let stopped = AtomicBool::new(false);
        let deadline = ClientDeadline::new(Instant::now() + Duration::from_secs(10));
        let mut prefix = StderrPrefix::default();
        let mut stderr = GateWriter {
            root: directory.path(),
            done: &done,
            bytes: Vec::new(),
        };
        let (out, err) = execute_observed(
            &cancellation,
            &stopped,
            &deadline,
            &mut prefix,
            &mut stderr,
            |preview, _| {
                Ok(child_capture(
                    directory.path(),
                    preview,
                    &cancellation,
                    &done,
                ))
            },
        )
        .unwrap();
        assert!(done.load(Ordering::Acquire));
        assert!(prefix.exposed());
        assert_eq!(out, b"stdout\0\xff");
        assert_eq!(err, b"first\0\xfftail");
        let snapshot = diagnostic_snapshot(&out, &err)
            .after_stderr_prefix(&prefix.descriptor().unwrap(), deadline.get())
            .unwrap();
        let mut stdout = Vec::new();
        snapshot
            .emit(&mut stdout, &mut stderr, deadline.get())
            .unwrap();
        assert_eq!(stdout, out);
        assert_eq!(
            stderr.bytes, err,
            "already exposed bytes may not be replayed"
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn partial_console_failure_cancels_and_joins_the_real_child_before_returning() {
        struct Partial(Vec<u8>);
        impl Write for Partial {
            fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
                if self.0.is_empty() {
                    self.0.push(bytes[0]);
                    Ok(1)
                } else {
                    Err(io::Error::new(io::ErrorKind::BrokenPipe, "closed console"))
                }
            }
            fn flush(&mut self) -> io::Result<()> {
                Ok(())
            }
        }
        let directory = tempfile::tempdir().unwrap();
        let done = AtomicBool::new(false);
        let cancellation = OperationCancellation::new();
        let deadline = ClientDeadline::new(Instant::now() + Duration::from_secs(10));
        let mut prefix = StderrPrefix::default();
        let mut stderr = Partial(Vec::new());
        let error = execute_observed(
            &cancellation,
            &AtomicBool::new(false),
            &deadline,
            &mut prefix,
            &mut stderr,
            |preview, _| {
                Ok(child_capture(
                    directory.path(),
                    preview,
                    &cancellation,
                    &done,
                ))
            },
        )
        .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::BrokenPipe);
        assert!(cancellation.is_cancelled());
        assert!(
            done.load(Ordering::Acquire),
            "execution was detached instead of joined"
        );
        assert_eq!(stderr.0, b"f");
        assert!(
            prefix.descriptor().is_err(),
            "partial exposure cannot authorize final replay"
        );
        assert!(!directory.path().join("continue").exists());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn stalled_console_times_out_without_holding_the_child_or_changing_socket_flags() {
        use std::os::unix::net::UnixStream;
        let (mut sink, _reader) = UnixStream::pair().unwrap();
        sink.set_nonblocking(true).unwrap();
        loop {
            match sink.write(&[0; 16 * 1024]) {
                Ok(count) => assert!(count > 0),
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => break,
                Err(error) => panic!("fill controlled-output socket: {error}"),
            }
        }
        sink.set_nonblocking(false).unwrap();
        let directory = tempfile::tempdir().unwrap();
        let done = AtomicBool::new(false);
        let stopped = AtomicBool::new(false);
        let cancellation = OperationCancellation::new();
        let deadline = ClientDeadline::new(Instant::now() + Duration::from_secs(3));
        let mut prefix = StderrPrefix::default();
        let mut stderr =
            rabsd::ControlledOutput::new(&sink, &stopped, Instant::now() + Duration::from_secs(1))
                .unwrap();
        let error = execute_observed(
            &cancellation,
            &stopped,
            &deadline,
            &mut prefix,
            &mut stderr,
            |preview, _| {
                Ok(child_capture(
                    directory.path(),
                    preview,
                    &cancellation,
                    &done,
                ))
            },
        )
        .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::TimedOut);
        assert!(
            prefix.exposed(),
            "the bounded sink must have attempted the actual preview"
        );
        assert!(done.load(Ordering::Acquire));
        assert!(cancellation.is_cancelled());
        assert!(
            !rustix::fs::fcntl_getfl(&sink)
                .unwrap()
                .contains(rustix::fs::OFlags::NONBLOCK)
        );
    }

    #[test]
    fn mismatched_live_prefix_refuses_both_final_streams() {
        let deadline = ClientDeadline::new(Instant::now() + Duration::from_secs(5));
        let mut prefix = StderrPrefix::default();
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        prefix.append(0, 0, b"observed", &mut stderr).unwrap();
        let mut replay_started = false;
        let error = replay_completed(
            diagnostic_snapshot(b"must remain hidden", b"different final stream"),
            &prefix,
            &json!({"kind":"worker-build"}),
            &mut stdout,
            &mut stderr,
            deadline.get(),
            &mut replay_started,
        )
        .unwrap_err();
        assert!(error.to_string().contains("differs"));
        assert!(stdout.is_empty(), "mismatched diagnostics exposed stdout");
        assert!(!replay_started, "prefix verification must precede replay");
        assert_eq!(
            stderr, b"observed",
            "no implicit replay may follow a mismatch"
        );
    }

    #[test]
    fn failed_final_write_reports_possible_exposure_even_without_a_live_preview() {
        struct Partial(Vec<u8>);
        impl Write for Partial {
            fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
                if self.0.is_empty() {
                    self.0.push(bytes[0]);
                    Ok(1)
                } else {
                    Err(io::Error::new(io::ErrorKind::BrokenPipe, "closed stdout"))
                }
            }
            fn flush(&mut self) -> io::Result<()> {
                Ok(())
            }
        }
        let prefix = StderrPrefix::default();
        let mut stdout = Partial(Vec::new());
        let mut stderr = Vec::new();
        let mut replay_started = false;
        let error = replay_completed(
            diagnostic_snapshot(b"output", b"stderr"),
            &prefix,
            &json!({"kind":"worker-build"}),
            &mut stdout,
            &mut stderr,
            Instant::now() + Duration::from_secs(3),
            &mut replay_started,
        )
        .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::BrokenPipe);
        assert!(!prefix.exposed());
        assert!(
            replay_started,
            "final exposure is independent of preview availability"
        );
        assert_eq!(stdout.0, b"o");
        assert!(
            stderr.is_empty(),
            "the failed transcript cannot be followed by a success report"
        );
    }

    #[test]
    fn bounded_tail_gap_stops_early_output_and_preserves_complete_final_replay() {
        use rabs_asupersync::stream_drain::preview::MAX_PREVIEW_BYTES;
        let cancellation = OperationCancellation::new();
        let deadline = ClientDeadline::new(Instant::now() + Duration::from_secs(5));
        let mut prefix = StderrPrefix::default();
        let mut stderr = Vec::new();
        let bytes = vec![0xff; MAX_PREVIEW_BYTES * 8];
        let snapshot = execute_observed(
            &cancellation,
            &AtomicBool::new(false),
            &deadline,
            &mut prefix,
            &mut stderr,
            |preview, _| {
                preview.record(PreviewStream::Stderr, 0, &bytes);
                Ok(diagnostic_snapshot(b"final output", &bytes))
            },
        )
        .unwrap();
        assert!(
            stderr.is_empty(),
            "a lost prefix is not a contiguous transcript"
        );
        let snapshot = snapshot
            .after_stderr_prefix(&prefix.descriptor().unwrap(), deadline.get())
            .unwrap();
        let mut stdout = Vec::new();
        snapshot
            .emit(&mut stdout, &mut stderr, deadline.get())
            .unwrap();
        assert_eq!(stdout, b"final output");
        assert_eq!(stderr, bytes);
    }
}
