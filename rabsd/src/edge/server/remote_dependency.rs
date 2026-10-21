//! A long worker compile owns private output only. Installation has a second
//! acknowledged frontier, so caller loss during compilation cannot leave a
//! delayed writer targeting Cargo's directory.
use super::liveness::{Limit, OwnedWork, Permit, WorkError};
use super::rustc_request::LiveEdge;
use super::{EdgeStream, backpressure, read_frame, write_frame};
use crate::coord::live_dependency::remote::{PendingRemote, PendingRemoteInstall, RemoteResult};
use crate::coord::live_dependency::{InstallResult, MAX_TRANSCRIPT_BYTES};
use crate::coord::secure_worker_delivery::OperationCancellation;
use asupersync::io::AsyncBufRead;
use rabs_cas::metadata_store::digest_key;
use serde_json::{Value, json};
use std::future::{Future, poll_fn};
use std::pin::{Pin, pin};
use std::sync::Arc;
use std::task::Poll;
use std::time::Duration;

const REMOTE_WAIT: Duration = Duration::from_secs(50 * 60);
const INSTALLATION_WAIT: Duration = Duration::from_secs(60);

// Even a settled failure authorizes fallback only for this accepted action.
// Keep the identity on uncertain outcomes too, so diagnostic recovery and
// later settlement cannot be confused with another worker execution.
fn failure(key: &str, reason: impl ToString, finished: bool) -> String {
    json!({
        "kind":"rustc-decision", "decision":"remote-failed", "remote_protocol":1,
        "action_key":key,
        "reason":reason.to_string(), "execution_finished":finished,
        "writer_returned":true, "compiler_skip_authorized":false,
    })
    .to_string()
}

/// Cancel before OwnedWork's destructor joins the blocking owner. Region
/// cancellation cannot strand a listener or detach a remote compiler driver.
struct RemoteWork {
    work: OwnedWork<RemoteResult>,
    cancellation: OperationCancellation,
}

impl Drop for RemoteWork {
    fn drop(&mut self) {
        self.cancellation.cancel();
    }
}

#[allow(clippy::large_enum_variant)]
enum Waited {
    Completed(Result<RemoteResult, WorkError>),
    CallerLost,
}

/// Observe without consuming any bytes. A cancelled frame read could discard a
/// partial ACK and leave the next protocol phase reading its suffix as a new
/// frame. Even one premature byte is invalid while the caller must be waiting.
async fn caller_activity(reader: &mut (impl AsyncBufRead + Unpin)) {
    poll_fn(|cx| Pin::new(&mut *reader).poll_fill_buf(cx).map(|_| ())).await;
}

async fn wait_owned(owner: &mut RemoteWork, stream: &mut EdgeStream) -> Waited {
    let mut completed = pin!(owner.work.wait());
    // There is no valid caller message during private execution. EOF, a
    // premature ACK, malformed data or the bounded deadline all cancel it.
    let mut caller = pin!(asupersync::time::timeout(
        asupersync::time::wall_now(),
        REMOTE_WAIT,
        caller_activity(stream),
    ));
    poll_fn(|cx| {
        if caller.as_mut().poll(cx).is_ready() {
            return Poll::Ready(Waited::CallerLost);
        }
        match completed.as_mut().poll(cx) {
            Poll::Ready(result) => Poll::Ready(Waited::Completed(result)),
            Poll::Pending => Poll::Pending,
        }
    })
    .await
}

enum InstallationCapacity {
    Ready(Permit),
    TimedOut,
    CallerLost,
}

async fn wait_installation(installations: &Limit, stream: &mut EdgeStream) -> InstallationCapacity {
    let mut capacity = pin!(asupersync::time::timeout(
        asupersync::time::wall_now(),
        INSTALLATION_WAIT,
        installations.wait(),
    ));
    // The wrapper is still waiting for remote-ready. No early message grants
    // permission to install; disconnect or cancellation retires private output.
    let mut caller = pin!(caller_activity(stream));
    poll_fn(|cx| {
        if caller.as_mut().poll(cx).is_ready() {
            return Poll::Ready(InstallationCapacity::CallerLost);
        }
        match capacity.as_mut().poll(cx) {
            Poll::Ready(Ok(permit)) => Poll::Ready(InstallationCapacity::Ready(permit)),
            Poll::Ready(Err(_)) => Poll::Ready(InstallationCapacity::TimedOut),
            Poll::Pending => Poll::Pending,
        }
    })
    .await
}

/// None retires the connection. Every success or local-fallback response is
/// returned only after the corresponding synchronous writer has finished.
pub(super) async fn complete_on_connection(
    executions: &Limit,
    installations: &Limit,
    live: Arc<LiveEdge>,
    pending: Box<PendingRemote>,
    reply: String,
    may_wait: bool,
    stream: &mut EdgeStream,
) -> Option<String> {
    let Some(permit) = executions.acquire() else {
        drop(pending);
        return Some(backpressure::capacity_reply(may_wait, "remote-execution"));
    };
    let key = digest_key(pending.action_key());
    let accepted = write_frame(stream, &reply).await
        && read_frame(stream).await.is_some_and(|frame| {
            serde_json::from_slice::<Value>(&frame).is_ok_and(|value| {
                value["kind"] == "rustc-remote-accept"
                    && value["remote_protocol"].as_u64() == Some(1)
                    && value["action_key"].as_str() == Some(key.as_str())
            })
        });
    if !accepted {
        drop(pending);
        return None;
    }
    let cancellation = OperationCancellation::new();
    let worker_cancellation = cancellation.clone();
    let work = match permit.finish(move || (*pending).execute(worker_cancellation)) {
        Ok(work) => work,
        Err(error) => return Some(failure(&key, error, true)),
    };
    let mut owned = RemoteWork { work, cancellation };
    let result = match wait_owned(&mut owned, stream).await {
        Waited::Completed(Ok(result)) => result,
        Waited::Completed(Err(error)) => return Some(failure(&key, error, false)),
        Waited::CallerLost => {
            owned.cancellation.cancel();
            // No output installation is possible from this abandoned result.
            // Await cleanup cooperatively; Drop remains the final join guard.
            drop(owned.work.wait().await);
            return None;
        }
    };
    let pending = match result {
        RemoteResult::Ready(pending) => pending,
        RemoteResult::Failed {
            reason,
            execution_finished,
        } => {
            super::log_line(
                "rabsd-remote-dependency-failed",
                &[("key", &key), ("reason", &reason)],
            );
            return Some(failure(&key, reason, execution_finished));
        }
    };
    let installation = match wait_installation(installations, stream).await {
        InstallationCapacity::Ready(permit) => permit,
        InstallationCapacity::CallerLost => return None,
        InstallationCapacity::TimedOut => {
            return Some(failure(
                &key,
                "remote result is complete but installation capacity did not become available",
                true,
            ));
        }
    };
    let capture = pending.capture().to_owned();
    let ready = json!({
        "kind":"rustc-decision", "decision":"remote-ready", "remote_protocol":1,
        "action_key":key, "capture":capture, "capture_protocol":1,
        "compiler_skip_authorized":false,
    })
    .to_string();
    // The first ACK authorized private computation only. Check the exact
    // capture here so no early/foreign ACK grants a subscriber write.
    let accepted = write_frame(stream, &ready).await
        && read_frame(stream).await.is_some_and(|frame| {
            serde_json::from_slice::<Value>(&frame).is_ok_and(|value| {
                value["kind"] == "rustc-accept"
                    && value["capture"].as_str() == Some(capture.as_str())
            })
        });
    if !accepted {
        drop(pending);
        return None;
    }
    match installation.finish(move || install(live, pending)) {
        Ok(mut work) => Some(
            work.wait()
                .await
                .unwrap_or_else(|error| failure(&key, error, true)),
        ),
        Err(error) => Some(failure(&key, error, true)),
    }
}

fn install(live: Arc<LiveEdge>, pending: PendingRemoteInstall) -> String {
    let key = digest_key(pending.action_key());
    match pending.install() {
        InstallResult::Served {
            transcript,
            installed,
        } => {
            if transcript.len() > MAX_TRANSCRIPT_BYTES {
                return failure(&key, "remote transcript exceeds its declared bound", true);
            }
            for output in installed {
                live.facts.remember(&output.path, output.sig, output.digest);
            }
            super::log_line("rabsd-remote-dependency-executed", &[("key", &key)]);
            let stderr: String = transcript
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect();
            json!({
                "kind":"rustc-decision", "decision":"remote-complete", "remote_protocol":1,
                "action_key":key, "stderr_hex":stderr, "writer_returned":true,
                "compiler_skip_authorized":true,
            })
            .to_string()
        }
        InstallResult::Declined(reason) | InstallResult::Fault(reason) => {
            super::log_line(
                "rabsd-remote-dependency-install-failed",
                &[("key", &key), ("reason", &reason)],
            );
            failure(&key, reason, true)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::super::{FRAME_READ_BUFFER_BYTES, MATERIALIZATION_WORKERS};
    use super::*;
    use asupersync::net::unix::UnixListener;
    use asupersync::runtime::RuntimeBuilder;
    use rabs_asupersync::daemon_runtime::block_on_top_level;
    use std::io::Write;
    use std::sync::mpsc;

    #[derive(Clone, Copy)]
    enum InstallationPeerAction {
        ReleaseSlot,
        Disconnect,
        PartialAck,
    }

    fn assert_available_slots(capacity: &Limit, count: usize) {
        let permits: Vec<_> = (0..count)
            .map(|_| capacity.acquire().expect("installation capacity was lost"))
            .collect();
        assert!(capacity.acquire().is_none(), "installation capacity grew");
        drop(permits);
    }

    /// The real peer acts only after the production wait has returned Pending
    /// with every installation slot held. No sleeps or preloaded input can
    /// substitute for waking a queued wait through the native socket reactor.
    fn installation_wait_with_native_peer(action: InstallationPeerAction) {
        let root = crate::test_util::private_tempdir();
        let path = root.path().join("installation.sock");
        let capacity = Limit::new(MATERIALIZATION_WORKERS);
        let mut occupied: Vec<_> = (0..MATERIALIZATION_WORKERS)
            .map(|_| capacity.acquire().unwrap())
            .collect();
        let (queued, queue_observed) = mpsc::channel();
        let (finished, finish_observed) = mpsc::channel();
        let runtime = RuntimeBuilder::current_thread().build().unwrap();
        let (result, was_queued, stayed_saturated, partial_preserved) =
            block_on_top_level(&runtime, async {
                let listener = UnixListener::bind(&path).await.unwrap();
                let peer = std::thread::spawn(move || {
                    let mut socket = std::os::unix::net::UnixStream::connect(path).unwrap();
                    socket
                        .set_write_timeout(Some(Duration::from_secs(5)))
                        .unwrap();
                    queue_observed
                        .recv_timeout(Duration::from_secs(10))
                        .expect("the installation wait must actually queue");
                    match action {
                        InstallationPeerAction::ReleaseSlot => drop(occupied.pop().unwrap()),
                        InstallationPeerAction::Disconnect => {
                            socket.shutdown(std::net::Shutdown::Both).unwrap();
                        }
                        InstallationPeerAction::PartialAck => {
                            // Keep the connection open: a frame reader would
                            // wait for the missing ACK terminator or its deadline.
                            socket.write_all(b"{").unwrap();
                        }
                    }
                    finish_observed
                        .recv_timeout(Duration::from_secs(10))
                        .expect("the native installation wait must terminate");
                    drop(occupied);
                });
                let (socket, _) = asupersync::time::timeout(
                    asupersync::time::wall_now(),
                    Duration::from_secs(5),
                    listener.accept(),
                )
                .await
                .expect("native peer did not connect")
                .unwrap();
                let mut socket = EdgeStream::with_capacity(FRAME_READ_BUFFER_BYTES, socket);
                let mut was_queued = false;
                let result = {
                    let mut waiting = pin!(wait_installation(&capacity, &mut socket));
                    asupersync::time::timeout(
                        asupersync::time::wall_now(),
                        Duration::from_secs(5),
                        poll_fn(|cx| {
                            let result = waiting.as_mut().poll(cx);
                            if result.is_pending() && !was_queued {
                                was_queued = true;
                                queued.send(()).unwrap();
                            }
                            result
                        }),
                    )
                    .await
                };
                // Cancellation must drop the queued future before capacity is
                // checked. The peer still holds every unreleased slot here.
                let stayed_saturated = capacity.acquire().is_none();
                let partial_preserved = if matches!(action, InstallationPeerAction::PartialAck) {
                    let mut context = std::task::Context::from_waker(std::task::Waker::noop());
                    matches!(Pin::new(&mut socket).poll_fill_buf(&mut context),
                        Poll::Ready(Ok(buffer)) if buffer == b"{")
                } else {
                    true
                };
                drop(queued);
                let _ = finished.send(());
                // Every peer operation has a finite socket/channel deadline;
                // release its held permits and join even when the wait timed out.
                peer.join().unwrap();
                (result, was_queued, stayed_saturated, partial_preserved)
            });
        assert!(was_queued, "the test must exercise saturated installation");
        assert!(stayed_saturated, "waiting lost a held installation permit");
        assert!(partial_preserved, "a premature ACK byte was consumed");
        match (
            action,
            result.expect("installation wait did not react within five seconds"),
        ) {
            (InstallationPeerAction::ReleaseSlot, InstallationCapacity::Ready(permit)) => {
                assert_available_slots(&capacity, MATERIALIZATION_WORKERS - 1);
                drop(permit);
            }
            (
                InstallationPeerAction::Disconnect | InstallationPeerAction::PartialAck,
                InstallationCapacity::CallerLost,
            ) => {}
            _ => panic!("installation wait chose the wrong connection/capacity outcome"),
        }
        assert_available_slots(&capacity, MATERIALIZATION_WORKERS);
    }

    #[test]
    fn saturated_installation_wait_acquires_a_slot_released_by_another_thread() {
        installation_wait_with_native_peer(InstallationPeerAction::ReleaseSlot);
    }

    #[test]
    fn disconnected_queued_installer_retires_without_losing_capacity() {
        installation_wait_with_native_peer(InstallationPeerAction::Disconnect);
    }

    #[test]
    fn premature_partial_ack_cancels_a_queued_installer_without_consuming_input() {
        installation_wait_with_native_peer(InstallationPeerAction::PartialAck);
    }

    #[test]
    fn premature_partial_message_is_observed_without_consuming_protocol_bytes() {
        let mut reader = asupersync::io::BufReader::new(&b"{"[..]);
        let mut context = std::task::Context::from_waker(std::task::Waker::noop());
        {
            let mut activity = pin!(caller_activity(&mut reader));
            assert!(activity.as_mut().poll(&mut context).is_ready());
        }
        let Poll::Ready(Ok(buffer)) = Pin::new(&mut reader).poll_fill_buf(&mut context) else {
            panic!("the observed caller bytes must stay in the connection buffer");
        };
        assert_eq!(buffer, b"{");
    }

    #[test]
    fn uncertain_remote_work_never_authorizes_local_execution() {
        let reply: Value =
            serde_json::from_str(&failure("this-action", "lost worker session", false)).unwrap();
        assert_eq!(reply["action_key"], "this-action");
        assert_eq!(
            reply["writer_returned"], true,
            "the transport has no subscriber writer"
        );
        assert_eq!(
            reply["execution_finished"], false,
            "a private destination does not prove execution stopped"
        );
        assert_eq!(reply["compiler_skip_authorized"], false);
        assert_eq!(reply["remote_protocol"], 1);
    }

    #[test]
    fn settled_remote_refusal_is_a_typed_stock_compiler_fallback() {
        let reply: Value =
            serde_json::from_str(&failure("this-action", "unkeyed env-dep", true)).unwrap();
        assert_eq!(reply["action_key"], "this-action");
        assert_eq!(reply["execution_finished"], true);
        assert_eq!(reply["writer_returned"], true);
        assert_eq!(reply["compiler_skip_authorized"], false);
        assert_eq!(reply["decision"], "remote-failed");
    }
}
