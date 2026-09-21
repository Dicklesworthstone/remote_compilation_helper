//! Persistent worker connection supervision, not execution retry.
//!
//! Each session owns and drains its execution/transfer tasks before returning
//! the SAME journal to this supervisor. Restoration runs outside the native
//! reactor. A new connection always repeats transport authentication and
//! application admission; only request-status/result-resume can reconcile work.
//! SIGTERM/SIGINT request cancellation through that session's Cx, then WAIT for
//! the session's existing cleanup and durable outcome path. No task abort or
//! dropped execution future is used to manufacture a clean shutdown.

use asupersync::cx::Cx;
use asupersync::runtime::RuntimeBuilder;
use asupersync::signal::{ShutdownController, ShutdownReceiver};
use asupersync::types::CancelKind;
use rabs_wkr::request_journal::WorkerJournal;
use rabs_wkr::session::CapabilityReport;
use std::future::{Future, poll_fn};
use std::pin::pin;
use std::sync::Arc;
use std::task::Poll;
use std::time::{Duration, Instant};

const INITIAL_DELAY_MS: u64 = 250;
const MAX_DELAY_MS: u64 = 30_000;
const STABLE_SESSION: Duration = Duration::from_secs(60);

/// Equal jitter avoids both synchronized fleet reconnects and zero-delay spins.
/// Entropy is derived from the already-random process incarnation; it is used
/// ONLY for scheduling and grants no security or execution authority.
struct Backoff {
    ceiling_ms: u64,
    entropy: u64,
}

impl Backoff {
    fn new(incarnation: u128) -> Self {
        let seed = incarnation as u64 ^ (incarnation >> 64) as u64;
        Self {
            ceiling_ms: INITIAL_DELAY_MS,
            entropy: if seed == 0 { 0x9e37_79b9_7f4a_7c15 } else { seed },
        }
    }

    fn next(&mut self, admitted_for: Option<Duration>) -> Duration {
        // A slow failed handshake is not a healthy session. Immediate EOF after
        // successful admission also must not reset an outage's backoff.
        if admitted_for.is_some_and(|elapsed| elapsed >= STABLE_SESSION) {
            self.ceiling_ms = INITIAL_DELAY_MS;
        }
        self.entropy ^= self.entropy << 13;
        self.entropy ^= self.entropy >> 7;
        self.entropy ^= self.entropy << 17;
        let floor = self.ceiling_ms.div_ceil(2);
        let millis = floor + self.entropy % (self.ceiling_ms - floor + 1);
        self.ceiling_ms = self.ceiling_ms.saturating_mul(2).min(MAX_DELAY_MS);
        Duration::from_millis(millis)
    }
}

/// The signal observer and session run in the SAME native task. A signal wakes
/// this poll, publishes cancellation, and immediately polls the interrupted IO.
/// Unlike racing-and-dropping a future, we still await process/stream cleanup.
async fn drain_on_shutdown<F: Future>(
    cx: &Cx,
    mut shutdown: ShutdownReceiver,
    session: F,
) -> F::Output {
    let mut session = pin!(session);
    let mut signal = pin!(shutdown.wait());
    let mut requested = false;
    poll_fn(|task| {
        if !requested && signal.as_mut().poll(task).is_ready() {
            requested = true;
            cx.cancel_with(CancelKind::User, Some("worker process shutdown"));
        }
        session.as_mut().poll(task)
    }).await
}

/// Only the disposable timer is raced against shutdown, never execution.
async fn backoff_or_shutdown(mut shutdown: ShutdownReceiver, delay: Duration) -> bool {
    let mut signal = pin!(shutdown.wait());
    let mut timer = pin!(asupersync::time::timeout(
        asupersync::time::wall_now(), delay, std::future::pending::<()>(),
    ));
    poll_fn(|cx| {
        if signal.as_mut().poll(cx).is_ready() {
            return Poll::Ready(true);
        }
        if timer.as_mut().poll(cx).is_ready() {
            return Poll::Ready(false);
        }
        Poll::Pending
    }).await
}

/// Lifecycle success is not compiler success. A cancelled compiler can have a
/// durably recorded nonzero result and a clean process drain. Conversely a
/// prior uncertain admission or a failed fsync must remain visibly unclean.
fn shutdown_exit(report: &CapabilityReport, journal: &WorkerJournal) -> i32 {
    let status = journal.status(journal.high_water().unwrap_or(0));
    let clean = matches!(status["status"].as_str(), Some("unknown" | "terminal-observed"));
    eprintln!("{}", serde_json::json!({
        "kind":"worker-shutdown-receipt", "worker_id":report.worker_id,
        "clean":clean, "request_high_water":journal.high_water(),
        "request_status":status["status"],
        "retained_result_available":journal.has_retained_result(),
        "boot_generation":journal.boot_generation().0,
        "incarnation":format!("{:032x}", journal.incarnation().0),
        "reexecute":false,
    }));
    i32::from(!clean)
}

/// Run until process shutdown or an unrecoverable journal failure. `once` keeps
/// the explicit one-session operator/test contract, including no connect retry.
/// Socket errors and peer EOF never cause the caller to replay a compiler.
pub(super) fn run(
    coordinator: String,
    report: CapabilityReport,
    once: bool,
    mut journal: WorkerJournal,
) -> i32 {
    let controller = Arc::new(ShutdownController::new());
    controller.listen_for_signals();
    let runtime = match RuntimeBuilder::current_thread().build() {
        Ok(runtime) => runtime,
        Err(error) => {
            eprintln!("rabs-wkr: runtime build failed: {error:?}");
            return 1;
        }
    };
    let report = Arc::new(report);
    let mut backoff = Backoff::new(journal.incarnation().0);
    loop {
        if controller.is_shutting_down() {
            return shutdown_exit(&report, &journal);
        }
        let handle = runtime.handle();
        let endpoint = coordinator.clone();
        let capability = Arc::clone(&report);
        let shutdown = controller.subscribe();
        let (outcome, returned_journal, admitted_for) = runtime.block_on(async move {
            handle.spawn(async move {
                let cx = Cx::current().expect("runtime task Cx");
                let mut admitted_at: Option<Instant> = None;
                let outcome = drain_on_shutdown(&cx, shutdown, super::session_loop(
                    &cx, &endpoint, &capability, once, &mut journal, &mut admitted_at,
                )).await;
                // session_loop has joined process cleanup and dropped both
                // range-transfer owners before we regain durable ownership.
                (outcome, journal, admitted_at.map(|start| start.elapsed()))
            }).await
        });
        journal = returned_journal;
        if controller.is_shutting_down() {
            // No spool reload, new handshake or new admission after shutdown.
            // Durable retained bytes are deliberately left for the next boot.
            return shutdown_exit(&report, &journal);
        }
        if once {
            return match outcome {
                Ok(()) => 0,
                Err(error) => {
                    eprintln!("rabs-wkr: session ended: {error}");
                    1
                }
            };
        }
        // Never reopen or replace this owner to recover from uncertain fsync.
        // In particular no new boot/incarnation or cleared high-water is minted
        // merely because the coordinator disconnected.
        if let Err(error) = journal.prepare_reconnect() {
            eprintln!("{}", serde_json::json!({
                "kind":"worker-reconnect-refused", "worker_id":report.worker_id,
                "reason":"durable-recovery-failed", "detail":error.to_string(),
                "request_high_water":journal.high_water(), "reexecute":false,
            }));
            return 1;
        }
        if controller.is_shutting_down() {
            return shutdown_exit(&report, &journal);
        }
        let delay = backoff.next(admitted_for);
        eprintln!("{}", serde_json::json!({
            "kind":"worker-reconnect-scheduled", "worker_id":report.worker_id,
            "reason":if outcome.is_ok() {"peer-closed"} else {"session-error"},
            // Peer-supplied handshake bodies may contain tokens or source data.
            "error_sha256":outcome.as_ref().err().map(|error| rabs_wkr::session::sha256_hex(error.as_bytes())),
            "delay_ms":delay.as_millis(), "boot_generation":journal.boot_generation().0,
            "incarnation":format!("{:032x}", journal.incarnation().0),
            "request_high_water":journal.high_water(),
            "retained_result_available":journal.has_retained_result(), "reexecute":false,
        }));
        // The timer/signal task holds no execution lease or network session.
        // The exclusive journal lock remains held, including during backoff.
        let handle = runtime.handle();
        let shutdown = controller.subscribe();
        runtime.block_on(async move {
            handle.spawn(backoff_or_shutdown(shutdown, delay)).await
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn jitter_is_nonzero_bounded_and_outage_backoff_saturates() {
        for seed in [0, 1, u128::MAX, 0x1234_5678_9abc_def0] {
            let mut backoff = Backoff::new(seed);
            let mut ceiling = INITIAL_DELAY_MS;
            for _ in 0..1_000 {
                let delay = backoff.next(None);
                assert!(delay >= Duration::from_millis(ceiling.div_ceil(2)));
                assert!(delay <= Duration::from_millis(ceiling));
                ceiling = ceiling.saturating_mul(2).min(MAX_DELAY_MS);
            }
            assert_eq!(backoff.ceiling_ms, MAX_DELAY_MS);
        }
    }

    #[test]
    fn only_a_stable_admitted_session_resets_backoff() {
        let mut backoff = Backoff::new(7);
        for _ in 0..20 { backoff.next(None); }
        assert!(backoff.next(Some(Duration::from_millis(1))) >= Duration::from_millis(MAX_DELAY_MS / 2));
        assert!(backoff.next(Some(STABLE_SESSION - Duration::from_nanos(1))) >= Duration::from_millis(MAX_DELAY_MS / 2));
        assert!(backoff.next(Some(STABLE_SESSION)) <= Duration::from_millis(INITIAL_DELAY_MS));
        assert_eq!(backoff.ceiling_ms, INITIAL_DELAY_MS * 2);
    }

    #[test]
    fn incarnation_jitter_spreads_concurrent_workers() {
        let delays: std::collections::BTreeSet<_> = (1..=64_u128)
            .map(|seed| Backoff::new(seed).next(None)).collect();
        assert!(delays.len() > 16);
    }

    #[test]
    fn shutdown_polls_session_cleanup_instead_of_dropping_it() {
        let runtime = RuntimeBuilder::current_thread().build().unwrap();
        let handle = runtime.handle();
        runtime.block_on(async move {
            handle.spawn(async move {
                let cx = Cx::current().unwrap();
                let controller = ShutdownController::new();
                let mut entered = false;
                let mut cleaned = false;
                let session = poll_fn(|task| {
                    if !entered {
                        entered = true;
                        controller.shutdown();
                        task.waker().wake_by_ref();
                        return Poll::Pending;
                    }
                    assert!(cx.is_cancel_requested());
                    cleaned = true;
                    Poll::Ready(37)
                });
                assert_eq!(drain_on_shutdown(&cx, controller.subscribe(), session).await, 37);
                assert!(entered && cleaned, "cleanup must finish before the session returns");
            }).await
        });
    }

    #[test]
    fn shutdown_interrupts_backoff_without_waiting_for_its_ceiling() {
        let controller = ShutdownController::new();
        controller.shutdown();
        let runtime = RuntimeBuilder::current_thread().build().unwrap();
        let handle = runtime.handle();
        runtime.block_on(async move {
            handle.spawn(async move {
                assert!(backoff_or_shutdown(controller.subscribe(), Duration::from_secs(30)).await);
                let running = ShutdownController::new();
                assert!(!backoff_or_shutdown(running.subscribe(), Duration::ZERO).await);
            }).await
        });
    }

    #[cfg(unix)]
    #[test]
    fn shutdown_receipt_cannot_certify_an_uncertain_admission() {
        let root = tempfile::tempdir().unwrap();
        let mut journal = WorkerJournal::open(root.path(), "shutdown-test", "coord").unwrap();
        let report = CapabilityReport {
            worker_id: "shutdown-test".to_owned(), canonical_namespace: false,
            missing: Vec::new(), slots: 1,
        };
        assert_eq!(shutdown_exit(&report, &journal), 0);
        let request = serde_json::json!({"kind":"canonical-exec", "request_id":7});
        journal.admit(&request, Duration::from_secs(1)).unwrap();
        let before = std::fs::read(root.path().join("requests.json")).unwrap();
        assert_eq!(shutdown_exit(&report, &journal), 1);
        assert_eq!(std::fs::read(root.path().join("requests.json")).unwrap(), before);
    }

    /// The actual session driver, real TCP and a real managed shell process
    /// group. The executor seam is explicit: this does not claim canonical
    /// sandbox or fleet qualification. No user process or shared daemon is used.
    #[cfg(target_os = "linux")]
    #[test]
    fn shutdown_drains_real_execution_and_records_outcome_before_returning() {
        use rabs_asupersync::process_groups::ManagedProcessGroup;
        use rabs_asupersync::region_tree::Attribution;
        use rabs_asupersync::stream_drain::DrainLimits;
        use rabs_asupersync::worker_transport::WorkerConnection;
        use rabs_wkr::execution::{ExecutionTask, StopReason};
        use rabs_wkr::session::{ExecResult, PressureSample, sha256_hex};
        use std::io::{Read, Write};
        use std::os::unix::process::ExitStatusExt;
        use std::process::{Command, Stdio};

        let root = tempfile::tempdir().unwrap();
        let pid_file = root.path().join("owned-pids");
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let address = listener.local_addr().unwrap().to_string();
        let controller = Arc::new(ShutdownController::new());
        let trigger = Arc::clone(&controller);
        let started_file = pid_file.clone();
        let peer = std::thread::spawn(move || {
            let until = Instant::now() + Duration::from_secs(5);
            let mut socket = loop {
                match listener.accept() {
                    Ok((socket, _)) => break socket,
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        if Instant::now() >= until {
                            trigger.shutdown();
                            panic!("test worker did not connect");
                        }
                        std::thread::sleep(Duration::from_millis(5));
                    }
                    Err(error) => { trigger.shutdown(); panic!("accept: {error}"); }
                }
            };
            socket.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
            socket.set_write_timeout(Some(Duration::from_secs(5))).unwrap();
            writeln!(socket, "{}", serde_json::json!({
                "kind":"canonical-exec", "request_id":42, "program":"explicit-test-executor",
                "toolchain_backing":"/unused", "workspace_backing":"/unused",
            })).unwrap();
            let mut started = false;
            while Instant::now() < until {
                if std::fs::read_to_string(&started_file).is_ok_and(|text| text.lines().count() == 2) {
                    started = true;
                    break;
                }
                std::thread::sleep(Duration::from_millis(5));
            }
            // Always release a waiting driver, even when setup did not succeed.
            trigger.shutdown();
            assert!(started, "real shell and descendant must exist before cancellation");
            let mut byte = [0];
            assert_eq!(socket.read(&mut byte).unwrap(), 0, "session closes after drain");
        });
        let runtime = RuntimeBuilder::current_thread().build().unwrap();
        let handle = runtime.handle();
        let mut journal = WorkerJournal::open(&root.path().join("state"), "shutdown-test", &address).unwrap();
        let spill_root = root.path().join("spills");
        let process_pid_file = pid_file.clone();
        journal = runtime.block_on(async move {
            handle.spawn(async move {
                let cx = Cx::current().unwrap();
                let socket = asupersync::net::TcpStream::connect(address).await.unwrap();
                let mut stream = WorkerConnection::LoopbackFixture(socket);
                let report = CapabilityReport {
                    worker_id:"shutdown-test".to_owned(), canonical_namespace:true,
                    missing:Vec::new(), slots:1,
                };
                let driver = crate::drive_session(
                    &mut stream, &report, false, Some(&mut journal), false,
                    move |request, timeout, _| {
                        let pid_file = process_pid_file.clone();
                        let spills = spill_root.clone();
                        ExecutionTask::spawn(request.request_id, timeout, move |control| {
                            let mut command = Command::new("sh");
                            command.args(["-c", "printf '%s\\n' \"$$\" > \"$PID_FILE\"; sleep 60 & printf '%s\\n' \"$!\" >> \"$PID_FILE\"; wait"])
                                .env("PID_FILE", pid_file)
                                .stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::piped());
                            let group = ManagedProcessGroup::spawn_command(command, Attribution::default()).unwrap();
                            let output = group.wait_with_bounded_drain_controlled(
                                &DrainLimits { resident_bound:1024, spill_dir:spills },
                                || control.reason().is_some(),
                            ).unwrap();
                            assert_eq!(control.reason(), Some(StopReason::SessionLost));
                            assert_eq!(output.residual_group_members, 0);
                            ExecResult {
                                request_id:request.request_id,
                                exit_code:output.status.code().unwrap_or_else(|| 128 + output.status.signal().unwrap_or(1)),
                                stdout_sha256:sha256_hex(output.stdout.resident()),
                                stderr_sha256:sha256_hex(output.stderr.resident()),
                                executed:true, residual_group_members:output.residual_group_members,
                                stdout_spill_bytes:0, stderr_spill_bytes:0,
                                stdout_spill_path:None, stderr_spill_path:None,
                            }
                        })
                    },
                    || PressureSample { load_x100:0, free_disk_mib:100 },
                );
                assert!(drain_on_shutdown(&cx, controller.subscribe(), driver).await.is_err());
                let status = journal.status(42);
                assert_eq!(status["status"], "terminal-observed");
                assert_eq!(status["receipt"]["stop_reason"], "session-lost");
                assert_eq!(status["receipt"]["exit_code"], 125);
                assert_eq!(shutdown_exit(&report, &journal), 0);
                journal
            }).await
        });
        peer.join().unwrap();
        let before = journal.status(42);
        drop(journal);
        let journal = WorkerJournal::open(&root.path().join("state"), "shutdown-test", &listener_address(&before, root.path())).err();
        // The receipt itself, not a fabricated status, was durably written.
        let saved: serde_json::Value = serde_json::from_slice(
            &std::fs::read(root.path().join("state/requests.json")).unwrap(),
        ).unwrap();
        assert_eq!(saved["last"]["resolved"], true);
        assert_eq!(saved["last"]["receipt"], before["receipt"]);
        assert!(journal.is_some(), "an unrelated endpoint cannot acquire the journal");
    }

    #[cfg(target_os = "linux")]
    fn listener_address(_status: &serde_json::Value, _root: &std::path::Path) -> String {
        // Intentionally foreign endpoint for the final binding refusal assertion.
        "not-the-admitted-coordinator".to_owned()
    }
}
