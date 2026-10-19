//! A long worker compile owns private output only. Installation has a second
//! acknowledged frontier, so caller loss during compilation cannot leave a
//! delayed writer targeting Cargo's directory.
use super::liveness::{Limit, OwnedWork, WorkError};
use super::rustc_request::LiveEdge;
use super::{EdgeStream, backpressure, read_frame, read_frame_bounded, write_frame};
use crate::coord::live_dependency::remote::{PendingRemote, PendingRemoteInstall, RemoteResult};
use crate::coord::live_dependency::{InstallResult, MAX_TRANSCRIPT_BYTES};
use crate::coord::secure_worker_delivery::OperationCancellation;
use rabs_cas::metadata_store::digest_key;
use serde_json::{Value, json};
use std::future::{Future, poll_fn};
use std::pin::pin;
use std::sync::Arc;
use std::task::Poll;
use std::time::Duration;

const REMOTE_WAIT: Duration = Duration::from_secs(50 * 60);

fn failure(reason: impl ToString, finished: bool) -> String {
    json!({
        "kind":"rustc-decision", "decision":"remote-failed", "remote_protocol":1,
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

async fn wait_owned(owner: &mut RemoteWork, stream: &mut EdgeStream) -> Waited {
    let mut completed = pin!(owner.work.wait());
    // There is no valid caller message during private execution. EOF, a
    // premature ACK, malformed data or the bounded deadline all cancel it.
    let mut caller = pin!(read_frame_bounded(
        stream,
        REMOTE_WAIT,
        super::MAX_FRAME_BYTES
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
        Err(error) => return Some(failure(error, true)),
    };
    let mut owned = RemoteWork { work, cancellation };
    let result = match wait_owned(&mut owned, stream).await {
        Waited::Completed(Ok(result)) => result,
        Waited::Completed(Err(error)) => return Some(failure(error, false)),
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
            return Some(failure(reason, execution_finished));
        }
    };
    let Some(installation) = installations.acquire() else {
        return Some(failure(
            "remote result is complete but installation capacity is unavailable",
            true,
        ));
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
                .unwrap_or_else(|error| failure(error, true)),
        ),
        Err(error) => Some(failure(error, true)),
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
                return failure("remote transcript exceeds its declared bound", true);
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
            failure(reason, true)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn uncertain_remote_work_never_authorizes_local_execution() {
        let reply: Value = serde_json::from_str(&failure("lost worker session", false)).unwrap();
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
        let reply: Value = serde_json::from_str(&failure("unkeyed env-dep", true)).unwrap();
        assert_eq!(reply["execution_finished"], true);
        assert_eq!(reply["writer_returned"], true);
        assert_eq!(reply["compiler_skip_authorized"], false);
        assert_eq!(reply["decision"], "remote-failed");
    }
}
