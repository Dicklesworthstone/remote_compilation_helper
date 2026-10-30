//! Service-owned remote execution and independent subscriber delivery.
//!
//! A reserved offer does not launch work. Its exact wrapper acknowledgment
//! starts one supervised producer; subsequent offers can retain membership in
//! that open flight. Losing a subscriber releases only that interest. The
//! service owns and joins the transport even after the originating edge exits.

use super::super::shared_work::{SharedWork, Subscription};
use super::{
    CoordLive, LiveDependencyRequest, OperationCancellation, PendingRemote, PendingRemoteInstall,
    RemoteInstallAuthority, RemoteOutput, RemoteResult, RemoteValidation, TypedDigest,
};
use std::fmt;
use std::sync::Arc;

const MAX_SHARED_SUBSCRIBERS: usize = 256;

/// The canonical service's bounded owner of all shared remote producer threads.
/// Keep this separate from `RemoteDependencies`: producers retain the worker
/// pool, and must never retain their own thread registry through that pool.
pub struct SharedRemoteExecutions {
    work: SharedWork<TypedDigest, SharedRemoteResult>,
}

impl fmt::Debug for SharedRemoteExecutions {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SharedRemoteExecutions")
            .finish_non_exhaustive()
    }
}

impl SharedRemoteExecutions {
    /// One execution owner per configured worker and one service-wide bound on
    /// retained subscribers, including offers awaiting their acknowledgment.
    #[must_use]
    pub fn new(worker_count: usize) -> Arc<Self> {
        Arc::new(Self {
            work: SharedWork::new(worker_count, MAX_SHARED_SUBSCRIBERS),
        })
    }

    /// Seal new work and membership, cancel active actions, then join every
    /// producer before the service releases coordinator or filesystem custody.
    pub fn shutdown(&self) -> Result<(), String> {
        self.work
            .shutdown()
            .map_err(|error| format!("shared remote execution shutdown: {error}"))
    }

    pub(super) fn try_join(&self, key: &TypedDigest) -> Option<Subscription<SharedRemoteResult>> {
        self.work.try_join(key)
    }
}

/// This capability can only be constructed from the current producer's
/// successful H011 publication. It contains no arbitrary-key lookup path and
/// cannot contain an affine workspace result. Terminal flights reject joins.
#[derive(Debug)]
pub(super) enum SharedRemoteResult {
    Published(Arc<RemoteOutput>),
    Failed {
        reason: String,
        execution_finished: bool,
    },
}

impl SharedRemoteResult {
    fn from_remote(result: RemoteResult) -> Self {
        match result {
            RemoteResult::Failed {
                reason,
                execution_finished,
            } => Self::Failed {
                reason,
                execution_finished,
            },
            RemoteResult::Ready(ready) => {
                if ready.request.is_execution_only() {
                    return Self::Failed {
                        reason: "fresh workspace execution cannot enter a shared result flight"
                            .into(),
                        execution_finished: true,
                    };
                }
                if let Err(reason) = ready.output.verify_binding(&ready.request) {
                    return Self::Failed {
                        reason,
                        execution_finished: true,
                    };
                }
                match ready.result.into_shared_output(ready.output) {
                    Ok(output) => Self::Published(output),
                    Err(reason) => Self::Failed {
                        reason,
                        execution_finished: true,
                    },
                }
            }
        }
    }
}

#[derive(Debug)]
struct SubscriberRequest {
    coord: Arc<CoordLive>,
    request: LiveDependencyRequest,
    validation: RemoteValidation,
}

impl SubscriberRequest {
    fn ready(self, output: Arc<RemoteOutput>) -> RemoteResult {
        if self.request.is_execution_only() {
            return RemoteResult::Failed {
                reason: "workspace requests require their own fresh remote execution".into(),
                execution_finished: true,
            };
        }
        if let Err(reason) = output.verify_binding(&self.request) {
            return RemoteResult::Failed {
                reason,
                execution_finished: true,
            };
        }
        // No filesystem work or target authority is exercised by this wait.
        // The acknowledged installation thread revalidates THIS request's
        // witnesses and uses THIS request's destination and presentation.
        RemoteResult::Ready(PendingRemoteInstall {
            coord: self.coord,
            request: self.request,
            output,
            validation: self.validation,
            result: RemoteInstallAuthority::Published,
        })
    }
}

enum Offer {
    Start {
        executions: Arc<SharedRemoteExecutions>,
        pending: Box<PendingRemote>,
    },
    Joined(Subscription<SharedRemoteResult>),
}

/// An unaccepted private-execution offer. Dropping a starter releases its
/// reserved worker without starting a flight; dropping a follower removes only
/// its enrolled interest. Neither offer grants permission to write outputs.
pub struct PendingSharedRemote {
    subscriber: SubscriberRequest,
    offer: Offer,
}

impl fmt::Debug for PendingSharedRemote {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PendingSharedRemote")
            .field("action_key", self.action_key())
            .finish_non_exhaustive()
    }
}

impl PendingSharedRemote {
    pub(super) fn starter(executions: Arc<SharedRemoteExecutions>, pending: PendingRemote) -> Self {
        let subscriber = SubscriberRequest {
            coord: Arc::clone(&pending.lane.coord),
            request: pending.request.clone(),
            validation: pending.invocation.validation.clone(),
        };
        Self {
            subscriber,
            offer: Offer::Start {
                executions,
                pending: Box::new(pending),
            },
        }
    }

    pub(super) fn joined(
        coord: Arc<CoordLive>,
        request: LiveDependencyRequest,
        validation: RemoteValidation,
        subscription: Subscription<SharedRemoteResult>,
    ) -> Self {
        Self {
            subscriber: SubscriberRequest {
                coord,
                request,
                validation,
            },
            offer: Offer::Joined(subscription),
        }
    }

    #[must_use]
    pub fn action_key(&self) -> &TypedDigest {
        &self.subscriber.request.key.action_key
    }

    /// Consume only after the exact action's `rustc-remote-accept` frame.
    /// A follower uses its already enrolled membership, even if the producer
    /// completed between the offer and this acknowledgment. No new member can
    /// join a terminal flight or reuse its current-producer privilege later.
    pub fn accept(self) -> Result<SharedRemoteSubscription, String> {
        let Self { subscriber, offer } = self;
        if subscriber.request.is_execution_only() {
            return Err("workspace execution cannot accept a shared remote offer".into());
        }
        let work = match offer {
            Offer::Joined(subscription) => subscription,
            Offer::Start {
                executions,
                pending,
            } => {
                let cancellation = OperationCancellation::new();
                let cancel = cancellation.clone();
                executions
                    .work
                    .start(
                        subscriber.request.key.action_key.clone(),
                        move || cancel.cancel(),
                        move || SharedRemoteResult::from_remote((*pending).execute(cancellation)),
                    )
                    .map_err(|error| format!("shared remote execution admission: {error}"))?
            }
        };
        Ok(SharedRemoteSubscription {
            subscriber: Some(subscriber),
            work,
        })
    }
}

/// One caller's interest and immutable input witnesses. It owns no worker
/// transport and cannot cancel another caller's demand. Drop removes only this
/// membership; the supervisor signals cancellation when the last one leaves.
pub struct SharedRemoteSubscription {
    subscriber: Option<SubscriberRequest>,
    work: Subscription<SharedRemoteResult>,
}

impl fmt::Debug for SharedRemoteSubscription {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SharedRemoteSubscription")
            .field(
                "action_key",
                &self
                    .subscriber
                    .as_ref()
                    .map(|subscriber| &subscriber.request.key.action_key),
            )
            .finish_non_exhaustive()
    }
}

impl SharedRemoteSubscription {
    /// Return at most one private installation offer for this subscriber. A
    /// producer panic retains uncertain execution semantics; it never grants
    /// local retry merely because its native thread has returned.
    pub async fn wait(&mut self) -> RemoteResult {
        let outcome = self.work.wait().await;
        let Some(subscriber) = self.subscriber.take() else {
            return RemoteResult::Failed {
                reason: "shared remote subscriber result already consumed".into(),
                // A prior delivery may still own a writer, or the first
                // result may have reported uncertain remote execution.
                execution_finished: false,
            };
        };
        match outcome {
            Ok(result) => match result.as_ref() {
                SharedRemoteResult::Published(output) => subscriber.ready(Arc::clone(output)),
                SharedRemoteResult::Failed {
                    reason,
                    execution_finished,
                } => RemoteResult::Failed {
                    reason: reason.clone(),
                    execution_finished: *execution_finished,
                },
            },
            Err(error) => RemoteResult::Failed {
                reason: format!("shared remote execution owner failed: {error}"),
                execution_finished: false,
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::super::request_owned_tests::Fixture;
    use super::*;
    use std::future::Future;
    use std::pin::pin;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::mpsc;
    use std::task::{Context, Poll, Wake, Waker};
    use std::time::{Duration, Instant};

    struct ThreadWake(std::thread::Thread);

    impl Wake for ThreadWake {
        fn wake(self: Arc<Self>) {
            self.0.unpark();
        }
    }

    fn wait<T>(future: impl Future<Output = T>) -> T {
        let mut future = pin!(future);
        let waker = Waker::from(Arc::new(ThreadWake(std::thread::current())));
        let mut context = Context::from_waker(&waker);
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            match future.as_mut().poll(&mut context) {
                Poll::Ready(result) => return result,
                Poll::Pending => {
                    let remaining = deadline.saturating_duration_since(Instant::now());
                    assert!(
                        !remaining.is_zero(),
                        "shared remote result did not complete"
                    );
                    std::thread::park_timeout(remaining);
                }
            }
        }
    }

    #[test]
    fn completed_remote_cohort_rejects_new_producer_result_subscribers() {
        // Real CAS capture supplies immutable manifest custody. The Published
        // tag is explicit fixture input to exercise cohort membership only;
        // this test does not claim H011 admission, rustc execution or TLS.
        let fixture = Fixture::new();
        let captured = fixture.capture();
        let output = Arc::new(RemoteOutput {
            manifest: captured.manifest().clone(),
            manifest_key: captured.captured.manifest_key.clone(),
            canonical_transcript: vec![b'x'; 64 * 1024],
        });
        let key = output.manifest.action_key.clone();
        let executions = SharedRemoteExecutions::new(1);
        let cancelled = Arc::new(AtomicUsize::new(0));
        let cancel = Arc::clone(&cancelled);
        let produced = Arc::clone(&output);
        let (release, released) = mpsc::sync_channel(1);
        let origin = executions
            .work
            .start(
                key.clone(),
                move || {
                    cancel.fetch_add(1, Ordering::AcqRel);
                },
                move || {
                    released.recv().unwrap();
                    SharedRemoteResult::Published(produced)
                },
            )
            .unwrap();
        let mut survivor = executions.try_join(&key).unwrap();
        let mut other = executions.try_join(&key).unwrap();
        drop(origin);
        assert_eq!(cancelled.load(Ordering::Acquire), 0);
        release.send(()).unwrap();
        let first = wait(survivor.wait()).unwrap();
        let second = wait(other.wait()).unwrap();
        assert!(Arc::ptr_eq(&first, &second));
        let SharedRemoteResult::Published(shared) = first.as_ref() else {
            panic!("the surviving cohort lost its published capture");
        };
        assert!(Arc::ptr_eq(shared, &output));
        // Even while existing members retain the exact producer result, a
        // later request must reenter normal replay/verification policy.
        assert!(executions.try_join(&key).is_none());
        executions.shutdown().unwrap();
        assert!(executions.try_join(&key).is_none());
        drop(survivor);
        drop(other);
        assert_eq!(cancelled.load(Ordering::Acquire), 0);
    }
}
