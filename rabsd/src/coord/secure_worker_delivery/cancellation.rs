//! Sticky cancellation for one daemon-owned worker operation.
//!
//! This capability carries local intent only. It neither sends a signal nor
//! proves that a worker stopped; the authenticated operation still owns remote
//! cancellation, cleanup, result verification and acknowledgment.

use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll, Waker};

#[derive(Debug)]
struct Waiter {
    registration: Arc<()>,
    waker: Waker,
}

#[derive(Debug, Default)]
struct State {
    cancelled: bool,
    waiters: Vec<Waiter>,
}

/// Cloneable cancellation intent scoped to a single operation, independent of
/// process-wide signals. Cancellation is permanent and wakes every registered
/// waiter, including callers observing successive transport phases.
#[derive(Clone, Default, Debug)]
pub struct OperationCancellation {
    state: Arc<Mutex<State>>,
}

impl OperationCancellation {
    /// Create an operation with no cancellation requested.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Request cancellation once. Repeated requests remain harmless while the
    /// execution owner drains cleanup and verified delivery.
    pub fn cancel(&self) {
        let waiters = {
            let mut state = self.state.lock().unwrap_or_else(|error| error.into_inner());
            if state.cancelled {
                return;
            }
            state.cancelled = true;
            std::mem::take(&mut state.waiters)
        };
        // A wake can immediately poll or inspect this token. Never invoke an
        // executor's waker while holding the state lock.
        for waiter in waiters {
            waiter.waker.wake();
        }
    }

    /// Whether cancellation has been requested, regardless of worker cleanup.
    #[must_use]
    pub fn is_cancelled(&self) -> bool {
        self.state
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .cancelled
    }

    /// Wait for sticky cancellation. Dropping this future unregisters its
    /// waker without consuming the intent or affecting any other waiter.
    pub async fn cancelled(&self) {
        CancellationWait {
            cancellation: self,
            registration: None,
        }
        .await;
    }
}

struct CancellationWait<'a> {
    cancellation: &'a OperationCancellation,
    registration: Option<Arc<()>>,
}

impl Future for CancellationWait<'_> {
    type Output = ();

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<()> {
        let this = self.get_mut();
        // Clone and eventually drop executor-owned wakers outside our lock.
        let replacement = cx.waker().clone();
        let mut replaced = None;
        let mut state = this
            .cancellation
            .state
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        if state.cancelled {
            return Poll::Ready(());
        }
        if let Some(registration) = &this.registration {
            if let Some(waiter) = state
                .waiters
                .iter_mut()
                .find(|waiter| Arc::ptr_eq(&waiter.registration, registration))
                && !waiter.waker.will_wake(cx.waker())
            {
                replaced = Some(std::mem::replace(&mut waiter.waker, replacement));
            }
        } else {
            // Allocation identity avoids a wrapping numeric waiter counter.
            let registration = Arc::new(());
            state.waiters.push(Waiter {
                registration: Arc::clone(&registration),
                waker: replacement,
            });
            this.registration = Some(registration);
        }
        drop(state);
        drop(replaced);
        Poll::Pending
    }
}

impl Drop for CancellationWait<'_> {
    fn drop(&mut self) {
        let Some(registration) = &self.registration else {
            return;
        };
        let removed = {
            let mut state = self
                .cancellation
                .state
                .lock()
                .unwrap_or_else(|error| error.into_inner());
            state
                .waiters
                .iter()
                .position(|waiter| Arc::ptr_eq(&waiter.registration, registration))
                .map(|index| state.waiters.swap_remove(index))
        };
        drop(removed);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::mpsc::{self, Receiver, Sender};
    use std::task::Wake;
    use std::time::Duration;

    struct ObservedWake {
        cancellation: OperationCancellation,
        wakes: AtomicUsize,
        notify: Sender<()>,
    }

    impl Wake for ObservedWake {
        fn wake(self: Arc<Self>) {
            self.wake_by_ref();
        }

        fn wake_by_ref(self: &Arc<Self>) {
            // This inspection also verifies that cancel wakes outside its lock.
            assert!(self.cancellation.is_cancelled());
            self.wakes.fetch_add(1, Ordering::SeqCst);
            let _ = self.notify.send(());
        }
    }

    fn observer(token: &OperationCancellation) -> (Arc<ObservedWake>, Waker, Receiver<()>) {
        let (notify, receiver) = mpsc::channel();
        let observed = Arc::new(ObservedWake {
            cancellation: token.clone(),
            wakes: AtomicUsize::new(0),
            notify,
        });
        let waker = Waker::from(Arc::clone(&observed));
        (observed, waker, receiver)
    }

    #[test]
    fn cancellation_wakes_a_registered_waiter_from_another_thread() {
        let token = OperationCancellation::new();
        let (observed, waker, notified) = observer(&token);
        let mut waiting = Box::pin(token.cancelled());
        assert!(
            waiting
                .as_mut()
                .poll(&mut Context::from_waker(&waker))
                .is_pending()
        );
        let other = token.clone();
        let cancelling = std::thread::spawn(move || other.cancel());
        notified.recv_timeout(Duration::from_secs(2)).unwrap();
        cancelling.join().unwrap();
        assert!(
            waiting
                .as_mut()
                .poll(&mut Context::from_waker(&waker))
                .is_ready()
        );
        assert_eq!(observed.wakes.load(Ordering::SeqCst), 1);
        assert!(token.is_cancelled());
    }

    #[test]
    fn cancellation_is_sticky_before_first_poll_and_for_later_phases() {
        let token = OperationCancellation::default();
        assert!(!token.is_cancelled());
        let mut first = Box::pin(token.cancelled());
        token.cancel();
        token.cancel();
        assert!(
            first
                .as_mut()
                .poll(&mut Context::from_waker(Waker::noop()))
                .is_ready()
        );
        drop(first);
        let mut next_phase = Box::pin(token.cancelled());
        assert!(
            next_phase
                .as_mut()
                .poll(&mut Context::from_waker(Waker::noop()))
                .is_ready()
        );
    }

    #[test]
    fn dropping_a_waiter_does_not_consume_intent_or_wake_the_abandoned_task() {
        let token = OperationCancellation::new();
        let (abandoned, abandoned_waker, _) = observer(&token);
        let mut first = Box::pin(token.cancelled());
        assert!(
            first
                .as_mut()
                .poll(&mut Context::from_waker(&abandoned_waker))
                .is_pending()
        );
        drop(first);
        assert!(!token.is_cancelled());
        let (current, current_waker, _) = observer(&token);
        let mut second = Box::pin(token.cancelled());
        assert!(
            second
                .as_mut()
                .poll(&mut Context::from_waker(&current_waker))
                .is_pending()
        );
        token.cancel();
        assert_eq!(abandoned.wakes.load(Ordering::SeqCst), 0);
        assert_eq!(current.wakes.load(Ordering::SeqCst), 1);
        assert!(
            second
                .as_mut()
                .poll(&mut Context::from_waker(&current_waker))
                .is_ready()
        );
    }

    #[test]
    fn concurrent_waiters_keep_distinct_current_wakers_and_cancel_once() {
        let token = OperationCancellation::new();
        let (old, old_waker, _) = observer(&token);
        let (updated, updated_waker, _) = observer(&token);
        let (independent, independent_waker, _) = observer(&token);
        let mut first = Box::pin(token.cancelled());
        let mut second = Box::pin(token.cancelled());
        assert!(
            first
                .as_mut()
                .poll(&mut Context::from_waker(&old_waker))
                .is_pending()
        );
        assert!(
            second
                .as_mut()
                .poll(&mut Context::from_waker(&independent_waker))
                .is_pending()
        );
        assert!(
            first
                .as_mut()
                .poll(&mut Context::from_waker(&updated_waker))
                .is_pending()
        );
        token.cancel();
        token.cancel();
        assert_eq!(old.wakes.load(Ordering::SeqCst), 0);
        assert_eq!(updated.wakes.load(Ordering::SeqCst), 1);
        assert_eq!(independent.wakes.load(Ordering::SeqCst), 1);
        assert!(
            first
                .as_mut()
                .poll(&mut Context::from_waker(&updated_waker))
                .is_ready()
        );
        assert!(
            second
                .as_mut()
                .poll(&mut Context::from_waker(&independent_waker))
                .is_ready()
        );
    }
}
