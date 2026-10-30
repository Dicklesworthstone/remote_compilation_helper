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

/// Durable delivery progress, sampled before and after one connection. A
/// terminal process receipt alone is not progress: both result streams must
/// have been accepted and their joint release persisted. Remembering the
/// session's starting state prevents repeated ACKs or request-status queries
/// from making a broken connection look productive.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct DeliveryProgress {
    request_id: Option<u64>,
    completed_and_released: bool,
}

impl DeliveryProgress {
    fn read(journal: &WorkerJournal) -> Self {
        let request_id = journal.high_water();
        let status = journal.status(request_id.unwrap_or(0));
        Self::from_status(request_id, &status)
    }

    fn from_status(request_id: Option<u64>, status: &serde_json::Value) -> Self {
        let receipt = &status["receipt"];
        let completed_and_released = request_id.is_some()
            && status["status"] == "terminal-observed"
            && status["request_id"].as_u64() == request_id
            && receipt["request_id"].as_u64() == request_id
            && receipt["kind"] == "exec-result"
            && receipt["executed"] == true
            && receipt["residual_group_members"] == 0
            && receipt
                .get("stop_reason")
                .is_some_and(serde_json::Value::is_null)
            && receipt["exit_code"]
                .as_u64()
                .is_some_and(|code| code <= 255)
            && receipt["retained_result_released"] == true
            && receipt["retained_result_sha256"]
                .as_str()
                .is_some_and(|digest| {
                    digest.len() == 64 && digest.bytes().all(|byte| byte.is_ascii_hexdigit())
                });
        Self {
            request_id,
            completed_and_released,
        }
    }

    fn advanced_to(self, after: Self) -> bool {
        after.completed_and_released
            && match (self.request_id, after.request_id) {
                (None, Some(_)) => true,
                (Some(before), Some(after)) => {
                    after > before || (after == before && !self.completed_and_released)
                }
                _ => false,
            }
    }
}

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
            entropy: if seed == 0 {
                0x9e37_79b9_7f4a_7c15
            } else {
                seed
            },
        }
    }

    fn next(&mut self, admitted_for: Option<Duration>, completed_delivery: bool) -> Duration {
        // A slow failed handshake is not a healthy session. Immediate EOF after
        // successful admission also must not reset an outage's backoff. A short
        // compile whose complete result was durably accepted IS useful work:
        // the coordinator deliberately closes that one-operation connection.
        // Do not turn a series of successful small compiles into 30s reconnects.
        if completed_delivery || admitted_for.is_some_and(|elapsed| elapsed >= STABLE_SESSION) {
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
            // Acknowledge the request before entering the explicit drain phase.
            // This is not acknowledgement that execution cleanup has completed.
            let _ = cx.checkpoint();
        }
        session.as_mut().poll(task)
    })
    .await
}

/// Only the disposable timer is raced against shutdown, never execution.
async fn backoff_or_shutdown(mut shutdown: ShutdownReceiver, delay: Duration) -> bool {
    let mut signal = pin!(shutdown.wait());
    let mut timer = pin!(asupersync::time::timeout(
        asupersync::time::wall_now(),
        delay,
        std::future::pending::<()>(),
    ));
    poll_fn(|cx| {
        if signal.as_mut().poll(cx).is_ready() {
            return Poll::Ready(true);
        }
        if timer.as_mut().poll(cx).is_ready() {
            return Poll::Ready(false);
        }
        Poll::Pending
    })
    .await
}

/// Lifecycle success is not compiler success. A cancelled compiler can have a
/// durably recorded nonzero result and a clean process drain. Conversely a
/// prior uncertain admission or a failed fsync must remain visibly unclean.
fn shutdown_exit(report: &CapabilityReport, journal: &WorkerJournal) -> i32 {
    let status = journal.status(journal.high_water().unwrap_or(0));
    let clean = matches!(
        status["status"].as_str(),
        Some("unknown" | "terminal-observed")
    );
    eprintln!(
        "{}",
        serde_json::json!({
            "kind":"worker-shutdown-receipt", "worker_id":report.worker_id,
            "clean":clean, "request_high_water":journal.high_water(),
            "request_status":status["status"],
            "retained_result_available":journal.has_retained_result(),
            "boot_generation":journal.boot_generation().0,
            "incarnation":format!("{:032x}", journal.incarnation().0),
            "reexecute":false,
        })
    );
    i32::from(!clean)
}

/// Worker-owned resources retained across reconnects and dropped after drain.
#[derive(Clone)]
pub(super) struct RuntimeResources {
    pub host_budget: Option<Arc<rabs_wkr::host_budget::HostBudget>>,
    pub target_cache: Option<Arc<rabs_wkr::target_cache::TargetCache>>,
    pub source_cache: Option<rabs_wkr::source_transfer::SourceCache>,
}

/// Run until process shutdown or an unrecoverable journal failure. `once` keeps
/// the explicit one-session operator/test contract, including no connect retry.
/// Socket errors and peer EOF never cause the caller to replay a compiler.
pub(super) fn run(
    coordinator: String,
    report: CapabilityReport,
    once: bool,
    mut journal: WorkerJournal,
    resources: RuntimeResources,
) -> i32 {
    // This strong scope spans reconnects but not process exit. The registry is
    // weak, so every ordinary return releases idle datasets AFTER session drain.
    // No static TempDir owner or detached janitor can leak them on clean exit.
    let _toolchains = match rabs_wkr::session::ToolchainReuseScope::from_environment() {
        Ok(scope) => scope,
        Err(error) => {
            eprintln!("rabs-wkr: toolchain pool configuration: {error}");
            return 1;
        }
    };
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
        let resources = resources.clone();
        let shutdown = controller.subscribe();
        let before_delivery = DeliveryProgress::read(&journal);
        let (outcome, returned_journal, admitted_for) =
            crate::block_on_worker_runtime(&runtime, async move {
                handle
                    .spawn(async move {
                        let cx = Cx::current().expect("runtime task Cx");
                        let mut admitted_at: Option<Instant> = None;
                        let outcome = drain_on_shutdown(
                            &cx,
                            shutdown,
                            super::session_loop(
                                &cx,
                                &endpoint,
                                &capability,
                                once,
                                &mut journal,
                                &mut admitted_at,
                                resources,
                            ),
                        )
                        .await;
                        // session_loop has joined process cleanup and dropped both
                        // range-transfer owners before we regain durable ownership.
                        (outcome, journal, admitted_at.map(|start| start.elapsed()))
                    })
                    .await
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
            eprintln!(
                "{}",
                serde_json::json!({
                    "kind":"worker-reconnect-refused", "worker_id":report.worker_id,
                    "reason":"durable-recovery-failed", "detail":error.to_string(),
                    "request_high_water":journal.high_water(), "reexecute":false,
                })
            );
            return 1;
        }
        if controller.is_shutting_down() {
            return shutdown_exit(&report, &journal);
        }
        let completed_delivery =
            outcome.is_ok() && before_delivery.advanced_to(DeliveryProgress::read(&journal));
        let delay = backoff.next(admitted_for, completed_delivery);
        eprintln!(
            "{}",
            serde_json::json!({
                "kind":"worker-reconnect-scheduled", "worker_id":report.worker_id,
                "reason":if outcome.is_ok() {"peer-closed"} else {"session-error"},
                // Peer-supplied handshake bodies may contain tokens or source data.
                "error_sha256":outcome.as_ref().err().map(|error| rabs_wkr::session::sha256_hex(error.as_bytes())),
                "delay_ms":delay.as_millis(), "boot_generation":journal.boot_generation().0,
                "incarnation":format!("{:032x}", journal.incarnation().0),
                "request_high_water":journal.high_water(),
                "retained_result_available":journal.has_retained_result(), "reexecute":false,
                "completed_delivery":completed_delivery,
            })
        );
        // The timer/signal task holds no execution lease or network session.
        // The exclusive journal lock remains held, including during backoff.
        let handle = runtime.handle();
        let shutdown = controller.subscribe();
        crate::block_on_worker_runtime(&runtime, async move {
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
                let delay = backoff.next(None, false);
                assert!(delay >= Duration::from_millis(ceiling.div_ceil(2)));
                assert!(delay <= Duration::from_millis(ceiling));
                ceiling = ceiling.saturating_mul(2).min(MAX_DELAY_MS);
            }
            assert_eq!(backoff.ceiling_ms, MAX_DELAY_MS);
        }
    }

    #[test]
    fn empty_short_sessions_preserve_outage_backoff() {
        let mut backoff = Backoff::new(7);
        for _ in 0..20 {
            backoff.next(None, false);
        }
        assert!(
            backoff.next(Some(Duration::from_millis(1)), false)
                >= Duration::from_millis(MAX_DELAY_MS / 2)
        );
        assert!(
            backoff.next(Some(STABLE_SESSION - Duration::from_nanos(1)), false)
                >= Duration::from_millis(MAX_DELAY_MS / 2)
        );
        assert!(
            backoff.next(Some(STABLE_SESSION), false) <= Duration::from_millis(INITIAL_DELAY_MS)
        );
        assert_eq!(backoff.ceiling_ms, INITIAL_DELAY_MS * 2);
    }

    #[test]
    fn incarnation_jitter_spreads_concurrent_workers() {
        let delays: std::collections::BTreeSet<_> = (1..=64_u128)
            .map(|seed| Backoff::new(seed).next(None, false))
            .collect();
        assert!(delays.len() > 16);
    }

    #[test]
    fn repeated_short_deliveries_reset_a_saturated_outage_without_busy_retry() {
        let mut backoff = Backoff::new(19);
        for _ in 0..20 {
            backoff.next(None, false);
        }
        assert_eq!(backoff.ceiling_ms, MAX_DELAY_MS);
        for _ in 0..100 {
            let delay = backoff.next(Some(Duration::from_millis(1)), true);
            assert!(delay >= Duration::from_millis(INITIAL_DELAY_MS / 2));
            assert!(delay <= Duration::from_millis(INITIAL_DELAY_MS));
        }
        let unproductive = backoff.next(Some(Duration::from_millis(1)), false);
        assert!(unproductive >= Duration::from_millis(INITIAL_DELAY_MS));
        assert!(unproductive <= Duration::from_millis(INITIAL_DELAY_MS * 2));
        for _ in 0..20 {
            backoff.next(None, false);
        }
        assert_eq!(backoff.ceiling_ms, MAX_DELAY_MS);
    }

    #[test]
    fn only_new_complete_durable_deliveries_are_productive() {
        use serde_json::json;

        // Explicit journal-status fixtures exercise the reconnect observer,
        // not the writer's admission, process execution or output verification.
        let status = |id| {
            json!({
                "kind":"request-status", "request_id":id, "status":"terminal-observed",
                "receipt": {
                    "kind":"exec-result", "request_id":id, "executed":true,
                    "exit_code":0, "residual_group_members":0, "stop_reason":null,
                    "retained_result_sha256":"ab".repeat(32), "retained_result_released":true,
                },
            })
        };
        let empty = DeliveryProgress::from_status(None, &serde_json::Value::Null);
        let completed = DeliveryProgress::from_status(Some(7), &status(7));
        assert!(empty.advanced_to(completed));
        assert!(
            !completed.advanced_to(completed),
            "repeated ACK is not progress"
        );
        assert!(!completed.advanced_to(empty));
        assert!(completed.advanced_to(DeliveryProgress::from_status(Some(8), &status(8))));
        assert!(!completed.advanced_to(DeliveryProgress::from_status(Some(6), &status(6))));

        let mut pending = status(7);
        pending["receipt"]["retained_result_released"] = json!(false);
        let pending = DeliveryProgress::from_status(Some(7), &pending);
        assert!(!empty.advanced_to(pending));
        assert!(
            pending.advanced_to(completed),
            "first complete recovery is progress"
        );

        for (field, value) in [
            ("kind", json!("error")),
            ("request_id", json!(8)),
            ("executed", json!(false)),
            ("exit_code", json!(-1)),
            ("exit_code", json!(256)),
            ("residual_group_members", json!(1)),
            ("stop_reason", json!("session-lost")),
            ("stop_reason", json!("cancelled")),
            ("retained_result_sha256", json!("invalid")),
            ("retained_result_released", json!(false)),
        ] {
            let mut refused = status(7);
            refused["receipt"][field] = value;
            assert!(
                !empty.advanced_to(DeliveryProgress::from_status(Some(7), &refused)),
                "{field}"
            );
        }
        for state in [
            "execution-uncertain",
            "journal-unavailable",
            "unknown",
            "retired",
        ] {
            let mut refused = status(7);
            refused["status"] = json!(state);
            assert!(
                !empty.advanced_to(DeliveryProgress::from_status(Some(7), &refused)),
                "{state}"
            );
        }
        let mut missing = status(7);
        missing["receipt"]
            .as_object_mut()
            .unwrap()
            .remove("stop_reason");
        assert!(!empty.advanced_to(DeliveryProgress::from_status(Some(7), &missing)));
        let mut diagnostic = status(7);
        diagnostic["receipt"]["exit_code"] = json!(101);
        assert!(
            empty.advanced_to(DeliveryProgress::from_status(Some(7), &diagnostic)),
            "a delivered compiler error is useful work, not a connection outage"
        );
    }

    #[test]
    fn shutdown_polls_session_cleanup_instead_of_dropping_it() {
        let runtime = RuntimeBuilder::current_thread().build().unwrap();
        let handle = runtime.handle();
        crate::block_on_worker_runtime(&runtime, async move {
            handle
                .spawn(async move {
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
                    assert_eq!(
                        drain_on_shutdown(&cx, controller.subscribe(), session).await,
                        37
                    );
                    assert!(
                        entered && cleaned,
                        "cleanup must finish before the session returns"
                    );
                })
                .await
        });
    }

    #[test]
    fn shutdown_interrupts_backoff_without_waiting_for_its_ceiling() {
        let controller = ShutdownController::new();
        controller.shutdown();
        let runtime = RuntimeBuilder::current_thread().build().unwrap();
        let handle = runtime.handle();
        crate::block_on_worker_runtime(&runtime, async move {
            handle
                .spawn(async move {
                    assert!(
                        backoff_or_shutdown(controller.subscribe(), Duration::from_secs(30)).await
                    );
                    let running = ShutdownController::new();
                    assert!(!backoff_or_shutdown(running.subscribe(), Duration::ZERO).await);
                })
                .await
        });
    }

    #[cfg(unix)]
    #[test]
    fn shutdown_receipt_cannot_certify_an_uncertain_admission() {
        use std::os::unix::fs::PermissionsExt;
        let root = tempfile::tempdir().unwrap();
        std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let mut journal = WorkerJournal::open(root.path(), "shutdown-test", "coord").unwrap();
        let report = CapabilityReport {
            worker_id: "shutdown-test".to_owned(),
            canonical_namespace: false,
            dependency_modes: vec![],
            missing: Vec::new(),
            slots: 1,
        };
        assert_eq!(shutdown_exit(&report, &journal), 0);
        let request = serde_json::json!({"kind":"canonical-exec", "request_id":7});
        journal.admit(&request, Duration::from_secs(1)).unwrap();
        let before = std::fs::read(root.path().join("requests.json")).unwrap();
        assert_eq!(shutdown_exit(&report, &journal), 1);
        assert_eq!(
            std::fs::read(root.path().join("requests.json")).unwrap(),
            before
        );
    }

    /// Real TCP, native session driver, durable captures/ACKs and actual short
    /// managed shell commands. The executor seam deliberately substitutes the
    /// shell for a canonical compiler; this is not a fleet benchmark.
    #[cfg(target_os = "linux")]
    #[test]
    fn short_process_results_reset_backoff_only_after_durable_delivery() {
        use rabs_asupersync::process_groups::ManagedProcessGroup;
        use rabs_asupersync::region_tree::Attribution;
        use rabs_asupersync::stream_drain::DrainLimits;
        use rabs_wkr::execution::ExecutionTask;
        use rabs_wkr::output::CapturedOutputs;
        use rabs_wkr::result_spool::{ResultRecipient, RetentionTarget};
        use rabs_wkr::session::{ExecResult, PressureSample, sha256_hex};
        use serde_json::{Value, json};
        use std::io::{BufRead, BufReader, Write};
        use std::net::{TcpListener, TcpStream};
        use std::process::{Command, Stdio};

        fn receive(peer: &mut BufReader<TcpStream>) -> Value {
            let mut line = String::new();
            assert!(peer.read_line(&mut line).unwrap() > 0);
            serde_json::from_str(&line).unwrap()
        }

        let root = tempfile::tempdir().unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let address = listener.local_addr().unwrap().to_string();
        let mut journal =
            WorkerJournal::open(&root.path().join("state"), "short-work", &address).unwrap();
        let runtime = RuntimeBuilder::current_thread().build().unwrap();
        let mut backoff = Backoff::new(41);
        for _ in 0..20 {
            backoff.next(None, false);
        }

        // A nonzero compiler-style result with completely delivered diagnostics
        // is also a healthy connection. No output or execution is replayed.
        for (id, exit_code) in [(1_u64, 0), (2, 0), (3, 101)] {
            let before = DeliveryProgress::read(&journal);
            let peer_listener = listener.try_clone().unwrap();
            let peer = std::thread::spawn(move || {
                let until = Instant::now() + Duration::from_secs(10);
                let socket = loop {
                    match peer_listener.accept() {
                        Ok((socket, _)) => break socket,
                        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                            assert!(Instant::now() < until, "session did not connect");
                            std::thread::sleep(Duration::from_millis(5));
                        }
                        Err(error) => panic!("accept: {error}"),
                    }
                };
                socket
                    .set_read_timeout(Some(Duration::from_secs(10)))
                    .unwrap();
                socket
                    .set_write_timeout(Some(Duration::from_secs(10)))
                    .unwrap();
                let mut peer = BufReader::new(socket);
                writeln!(peer.get_mut(), "{}", json!({
                    "kind":"canonical-exec", "request_id":id, "program":"explicit-shell-test-seam",
                    "toolchain_backing":"/unused", "workspace_backing":"/unused",
                })).unwrap();
                let result = receive(&mut peer);
                assert_eq!(result["kind"], "exec-result");
                assert_eq!(result["exit_code"], exit_code);
                assert_eq!(result["executed"], true);
                assert_eq!(result["stdout_sha256"], sha256_hex(b"short-work"));
                assert_eq!(result["stdout_bytes"], 10);
                assert_eq!(result["stderr_bytes"], 0);
                writeln!(
                    peer.get_mut(),
                    "{}",
                    json!({"kind":"request-status", "request_id":id})
                )
                .unwrap();
                assert_eq!(
                    receive(&mut peer)["receipt"]["retained_result_released"],
                    false
                );
                writeln!(peer.get_mut(), "{}", json!({
                    "kind":"output-ack", "request_id":id,
                    "stdout_sha256":result["stdout_sha256"], "stderr_sha256":result["stderr_sha256"],
                    "stdout_bytes":result["stdout_bytes"], "stderr_bytes":result["stderr_bytes"],
                })).unwrap();
                assert_eq!(receive(&mut peer)["kind"], "output-acknowledged");
            });
            let handle = runtime.handle();
            let endpoint = address.clone();
            let journal_root = journal.storage_root().to_path_buf();
            let spills = root.path().join(format!("spills-{id}"));
            let started = Instant::now();
            journal = crate::block_on_worker_runtime(&runtime, async move {
                handle
                    .spawn(async move {
                        let mut socket =
                            asupersync::net::TcpStream::connect(endpoint).await.unwrap();
                        let report = CapabilityReport {
                            worker_id: "short-work".to_owned(),
                            canonical_namespace: true,
                            dependency_modes: Vec::new(),
                            missing: Vec::new(),
                            slots: 1,
                        };
                        crate::drive_session(
                            &mut socket,
                            &report,
                            true,
                            Some(&mut journal),
                            false,
                            move |request, timeout, plan| {
                                let retention = RetentionTarget::from_admitted(
                                    &journal_root,
                                    request.request_id,
                                    ResultRecipient::LoopbackFixture,
                                )?;
                                let spills = spills.clone();
                                ExecutionTask::spawn_for_delivery(
                                    request.request_id,
                                    timeout,
                                    plan,
                                    Some(retention),
                                    move |control| {
                                        let mut command = Command::new("sh");
                                        command
                                            .args([
                                                "-c",
                                                "printf short-work; exit \"$RABS_TEST_EXIT\"",
                                            ])
                                            .env("RABS_TEST_EXIT", exit_code.to_string())
                                            .stdin(Stdio::null())
                                            .stdout(Stdio::piped())
                                            .stderr(Stdio::piped());
                                        let group = ManagedProcessGroup::spawn_command(
                                            command,
                                            Attribution::default(),
                                        )
                                        .unwrap();
                                        let output = group
                                            .wait_with_bounded_drain_controlled(
                                                &DrainLimits {
                                                    resident_bound: 1024,
                                                    spill_dir: spills,
                                                },
                                                || control.reason().is_some(),
                                            )
                                            .unwrap();
                                        assert_eq!(output.residual_group_members, 0);
                                        let captured = CapturedOutputs::from_lanes(
                                            &output.stdout,
                                            &output.stderr,
                                        )
                                        .unwrap();
                                        let result = ExecResult {
                                            request_id: request.request_id,
                                            exit_code: output.status.code().unwrap(),
                                            executed: true,
                                            residual_group_members: output.residual_group_members,
                                            stdout_sha256: captured.stdout.sha256().to_owned(),
                                            stderr_sha256: captured.stderr.sha256().to_owned(),
                                            stdout_spill_bytes: output.stdout.spilled_bytes(),
                                            stderr_spill_bytes: output.stderr.spilled_bytes(),
                                            stdout_spill_path: None,
                                            stderr_spill_path: None,
                                        };
                                        control.retain_outputs(Ok(captured)).unwrap();
                                        result
                                    },
                                )
                            },
                            || PressureSample {
                                load_x100: 0,
                                free_disk_mib: 100,
                            },
                        )
                        .await
                        .unwrap();
                        journal
                    })
                    .await
            });
            peer.join().unwrap();
            assert!(started.elapsed() < STABLE_SESSION);
            let after = DeliveryProgress::read(&journal);
            assert!(before.advanced_to(after));
            assert!(!after.advanced_to(DeliveryProgress::read(&journal)));
            let delay = backoff.next(Some(started.elapsed()), before.advanced_to(after));
            assert!(delay <= Duration::from_millis(INITIAL_DELAY_MS));
            assert_eq!(
                journal.status(id)["receipt"]["retained_result_released"],
                true
            );
        }
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
        let retained_endpoint = address.clone();
        let controller = Arc::new(ShutdownController::new());
        let trigger = Arc::clone(&controller);
        let started_file = pid_file.clone();
        let peer =
            std::thread::spawn(move || {
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
                        Err(error) => {
                            trigger.shutdown();
                            panic!("accept: {error}");
                        }
                    }
                };
                socket
                    .set_read_timeout(Some(Duration::from_secs(10)))
                    .unwrap();
                socket
                    .set_write_timeout(Some(Duration::from_secs(5)))
                    .unwrap();
                writeln!(socket, "{}", serde_json::json!({
                "kind":"canonical-exec", "request_id":42, "program":"explicit-test-executor",
                "toolchain_backing":"/unused", "workspace_backing":"/unused",
            })).unwrap();
                let mut started = false;
                while Instant::now() < until {
                    if std::fs::read_to_string(&started_file)
                        .is_ok_and(|text| text.lines().count() == 2)
                    {
                        started = true;
                        break;
                    }
                    std::thread::sleep(Duration::from_millis(5));
                }
                // Always release a waiting driver, even when setup did not succeed.
                trigger.shutdown();
                assert!(
                    started,
                    "real shell and descendant must exist before cancellation"
                );
                let mut byte = [0];
                assert_eq!(
                    socket.read(&mut byte).unwrap(),
                    0,
                    "session closes after drain"
                );
            });
        let runtime = RuntimeBuilder::current_thread().build().unwrap();
        let handle = runtime.handle();
        let mut journal =
            WorkerJournal::open(&root.path().join("state"), "shutdown-test", &address).unwrap();
        let spill_root = root.path().join("spills");
        let process_pid_file = pid_file.clone();
        journal = crate::block_on_worker_runtime(&runtime, async move {
            handle.spawn(async move {
                let cx = Cx::current().unwrap();
                let socket = asupersync::net::TcpStream::connect(address).await.unwrap();
                let mut stream = WorkerConnection::LoopbackFixture(socket);
                let report = CapabilityReport {
                    worker_id:"shutdown-test".to_owned(), canonical_namespace:true,
                    dependency_modes:Vec::new(), missing:Vec::new(), slots:1,
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
        let journal = WorkerJournal::open(
            &root.path().join("state"),
            "shutdown-test",
            &retained_endpoint,
        )
        .unwrap();
        // Reopening the SAME owner proves that cleanup, not just an in-memory
        // result, crossed the durable outcome barrier before shutdown returned.
        assert_eq!(journal.status(42), before);
        let saved: serde_json::Value = serde_json::from_slice(
            &std::fs::read(root.path().join("state/requests.json")).unwrap(),
        )
        .unwrap();
        assert_eq!(saved["last"]["resolved"], true);
        assert_eq!(saved["last"]["receipt"], before["receipt"]);
    }
}
