//! Scoped blocking publication, including cancellation and same-session retry.
//!
//! A dropped `spawn_blocking` handle does not stop its publisher. Keep the
//! output lock and journal-owner gate in one dedicated worker and join it
//! before returning the borrowed session, even when its future is cancelled.
//! The caller's reactor remains available during ordinary publication; a
//! recovery deadline requests cancellation rather than waiting for the whole
//! phase. Checkpoints bound cooperative work, not in-flight filesystem
//! operations. In particular, cancellation may wait for a slow fsync.

use super::{File, RecoveryRecipe, RecoverySession};
use anyhow::{Context, Result};
use std::cell::RefCell;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread::JoinHandle;

thread_local! {
    // Installed only in a dedicated publication thread, never a Tokio worker.
    // Shared fingerprint/copy helpers remain usable outside publication.
    static CANCELLED: RefCell<Option<Arc<AtomicBool>>> = const { RefCell::new(None) };
}

#[derive(Debug, thiserror::Error)]
#[error("artifact publication cancelled; journal and staging retained for same-id recovery")]
pub(super) struct PublicationCancelled;

pub(super) fn checkpoint() -> Result<()> {
    if CANCELLED.with(|slot| {
        slot.borrow()
            .as_ref()
            .is_some_and(|flag| flag.load(Ordering::Acquire))
    }) {
        return Err(PublicationCancelled.into());
    }
    Ok(())
}

/// Per-invocation observation points; production supplies a no-op observer.
/// Tests pause or fail here without replacing the real copier or journal.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum PublicationPoint {
    BeforeFile,
    PendingDurable,
    Renamed,
    PublishedDurable,
}

type Outcome = (RecoveryRecipe, Result<()>);

struct PublicationScope<'a> {
    session: &'a mut RecoverySession,
    cancelled: Arc<AtomicBool>,
    worker: Option<JoinHandle<Outcome>>,
}

impl PublicationScope<'_> {
    fn join(&mut self) -> Result<()> {
        let worker = self
            .worker
            .take()
            .context("publication worker already joined")?;
        match worker.join() {
            Ok((recipe, result)) => {
                // Includes all acknowledged checkpoints before an error or
                // cancellation. A same-session retry must not restore the
                // pre-publication recipe over a more recent durable journal.
                self.session.recipe = recipe;
                result
            }
            Err(_) => {
                // The thread has stopped and released its locks. A panic can
                // occur after a committed checkpoint, so reload the writer's
                // acknowledged state instead of trusting the borrowed copy.
                self.session.recipe = super::load_recipe(&self.session.writer)
                    .context("reload acknowledged publication state after worker panic")?;
                anyhow::bail!("artifact publication worker panicked; journal retained")
            }
        }
    }
}

impl Drop for PublicationScope<'_> {
    fn drop(&mut self) {
        if self.worker.is_some() {
            self.cancelled.store(true, Ordering::Release);
            // Cancellation is a request, not permission to return this mutable
            // session while a hidden publisher still writes its journal. Drain
            // to the next checkpoint while keeping the source owner alive.
            if let Err(error) = self.join() {
                tracing::debug!("publication scope drained: {error:#}");
            }
        }
    }
}

pub(super) async fn run(
    session: &mut RecoverySession,
    publication_lock: File,
    work: impl FnOnce(&mut RecoverySession) -> Result<()> + Send + 'static,
) -> Result<()> {
    let mut owned = RecoverySession {
        recipe: session.recipe.clone(),
        // Keep the exact recovery-owner gate, not a newly loaded journal.
        writer: session.writer.clone(),
    };
    let cancelled = Arc::new(AtomicBool::new(false));
    let worker_cancelled = Arc::clone(&cancelled);
    let (done, completed) = tokio::sync::oneshot::channel();
    let worker = std::thread::Builder::new()
        .name("rch-publication".into())
        .spawn(move || {
            CANCELLED.with(|slot| *slot.borrow_mut() = Some(worker_cancelled));
            let result = checkpoint().and_then(|()| work(&mut owned));
            let recipe = owned.recipe;
            // Complete filesystem/ownership teardown before waking the caller.
            // On panic, unwinding drops these and the sender as well.
            drop(publication_lock);
            drop(owned.writer);
            let _ = done.send(());
            (recipe, result)
        })
        .context("start scoped artifact publication worker")?;
    let mut scope = PublicationScope {
        session,
        cancelled,
        worker: Some(worker),
    };
    // Both normal completion and sender drop (panic) wake this future. Dropping
    // it at this await instead requests shutdown through PublicationScope.
    let _ = completed.await;
    scope.join()
}
