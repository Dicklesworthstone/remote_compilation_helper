//! Wrapper panic containment: unwind, nonprinting hook, no abort
//! (bead C022; invariant I49; risk R105).
//!
//! The tiny wrapper sits between Cargo and the build. If IT panics, the
//! failure must never masquerade as compiler output (a Rust panic
//! message on stderr reads like a build diagnostic to Cargo and to
//! humans, R105) and must never abort the process out from under the
//! fallback logic. The containment stack:
//!
//! - **panic = unwind** is the required strategy for the wrapper
//!   binary. Abort-on-panic is prohibited unless a SEPARATE minimal
//!   parent guard is proven to deliver the same fallback —
//!   [`validate_strategy`] refuses the unproven configuration.
//! - **Nonprinting hook**: [`RecordingHookGuard`] replaces the default
//!   printing panic hook with one that records the panic internally
//!   (message + location) and writes NOTHING to the wrapper's streams;
//!   the previous hook is restored on drop (RAII).
//! - **Top-level containment**: [`run_contained`] wraps the wrapper's
//!   work in `catch_unwind`; a panic surfaces as a typed
//!   [`PanicRecord`], never as a crash.
//! - **Frontier-governed recovery**: [`contain_panic`] decides what the
//!   contained wrapper does next. BEFORE any exposure it executes the
//!   exact original wrapper/compiler chain (seamless — the user sees a
//!   normal build). AFTER exposure it fails per the applicable C005/
//!   C006 delivery frontier: labeled recovery only where configured,
//!   and no uncoordinated fallback once stateful intent exists.
//! - **Allocator abort mitigation**: infallible allocation aborts on
//!   OOM regardless of panic strategy, so wrapper buffers are gated by
//!   [`AllocationBudget`] — beyond-budget reservations are typed
//!   refusals the caller handles, not aborts.
//!
//! The injected-panic tests below (before/after exposure) feed T037.

use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::{Arc, Mutex};

use crate::local_protocol::{
    FallbackAction, FallbackConfig, SubscriberFrontierReport, decide_fallback,
};

/// One contained panic, recorded internally — NEVER printed to the
/// streams Cargo watches.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PanicRecord {
    /// The panic payload rendered to text (`Any` payloads that are not
    /// strings record a fixed marker).
    pub message: String,
    /// `file:line:column` when the hook saw a location.
    pub location: Option<String>,
}

/// The wrapper's configured panic strategy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PanicStrategy {
    /// Required default: unwind into the top-level containment.
    Unwind,
    /// Abort-on-panic. Permitted ONLY when a separate minimal parent
    /// guard is proven to deliver the same fallback behavior.
    Abort {
        /// Whether the parent-guard equivalence proof exists.
        parent_guard_proven: bool,
    },
}

/// Typed refusal for a prohibited strategy configuration.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StrategyError {
    /// Abort without a proven parent guard would strand the fallback:
    /// a panic would kill the wrapper before it can run the original
    /// chain or fail per the frontier.
    AbortWithoutParentGuard,
}

/// Validate the wrapper's panic strategy (I49).
///
/// # Errors
/// [`StrategyError::AbortWithoutParentGuard`] for the prohibited
/// configuration.
pub const fn validate_strategy(strategy: PanicStrategy) -> Result<(), StrategyError> {
    match strategy {
        PanicStrategy::Unwind
        | PanicStrategy::Abort {
            parent_guard_proven: true,
        } => Ok(()),
        PanicStrategy::Abort {
            parent_guard_proven: false,
        } => Err(StrategyError::AbortWithoutParentGuard),
    }
}

/// RAII guard that installs a NONPRINTING panic hook recording into the
/// given store, restoring the previous hook on drop. While the guard
/// lives, a wrapper panic writes nothing to stdout/stderr — the record
/// is internal state for the containment logic and diagnostics
/// channel, never Cargo-visible output (R105).
pub struct RecordingHookGuard {
    previous: Option<PanicHook>,
}

/// The boxed panic-hook type `std::panic::take_hook` returns.
type PanicHook = Box<dyn Fn(&std::panic::PanicHookInfo<'_>) + Sync + Send + 'static>;

impl RecordingHookGuard {
    /// Install the recording hook.
    #[must_use]
    pub fn install(store: Arc<Mutex<Vec<PanicRecord>>>) -> Self {
        let previous = std::panic::take_hook();
        std::panic::set_hook(Box::new(move |info| {
            let message = info
                .payload()
                .downcast_ref::<&str>()
                .map(ToString::to_string)
                .or_else(|| info.payload().downcast_ref::<String>().cloned())
                .unwrap_or_else(|| "<non-string panic payload>".to_owned());
            let location = info.location().map(ToString::to_string);
            if let Ok(mut records) = store.lock() {
                records.push(PanicRecord { message, location });
            }
            // Deliberately NO printing of any kind.
        }));
        Self {
            previous: Some(previous),
        }
    }
}

impl Drop for RecordingHookGuard {
    fn drop(&mut self) {
        if let Some(previous) = self.previous.take() {
            // Restore whatever hook was installed before us.
            std::panic::set_hook(previous);
        }
    }
}

/// Top-level unwind containment: run the wrapper's work; a panic
/// becomes the most recent [`PanicRecord`] from the store (or a
/// marker record when the hook could not capture it), never a crash.
///
/// # Errors
/// The recorded panic.
pub fn run_contained<T>(
    work: impl FnOnce() -> T,
    store: &Arc<Mutex<Vec<PanicRecord>>>,
) -> Result<T, PanicRecord> {
    match catch_unwind(AssertUnwindSafe(work)) {
        Ok(value) => Ok(value),
        Err(_payload) => {
            let record = store
                .lock()
                .ok()
                .and_then(|records| records.last().cloned())
                .unwrap_or_else(|| PanicRecord {
                    message: "<panic captured without hook record>".to_owned(),
                    location: None,
                });
            Err(record)
        }
    }
}

/// What the contained wrapper does after an internal panic.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ContainedOutcome {
    /// Nothing was exposed: execute the EXACT original wrapper/compiler
    /// chain — the user sees a normal local build, not a wrapper bug.
    RunExactOriginalChain,
    /// Exposure exists: the panic fails per the applicable delivery
    /// frontier (C005/C006) — labeled recovery only where configured,
    /// no uncoordinated fallback once stateful intent exists.
    FrontierGoverned(FallbackAction),
}

/// Decide the post-panic action from the subscriber's frontiers. An
/// internal wrapper panic is a WRAPPER failure, never a build failure:
/// before any exposure it is invisible (original chain runs); after
/// exposure the ordinary frontier rules apply unchanged — a panic
/// grants no extra fallback permission.
#[must_use]
pub fn contain_panic(
    report: &SubscriberFrontierReport,
    config: &FallbackConfig,
    request_id: u128,
) -> ContainedOutcome {
    let nothing_exposed = !report.transcript_exposed
        && !report.transcript_uncertain
        && !report.stateful_intent_recorded
        && !report.stateful_uncertain;
    if nothing_exposed {
        ContainedOutcome::RunExactOriginalChain
    } else {
        ContainedOutcome::FrontierGoverned(decide_fallback(report, config, request_id))
    }
}

/// Typed refusal for a reservation beyond the wrapper's allocation
/// budget — returned to the caller instead of letting an infallible
/// allocation abort the process on OOM.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AllocationRefused {
    /// Bytes requested.
    pub requested: usize,
    /// Bytes still available under the budget.
    pub available: usize,
}

/// Bounded allocation accountant for wrapper buffers (the allocator-
/// abort/OOM mitigation): every sizable buffer reserves here first;
/// beyond-budget requests refuse instead of aborting.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AllocationBudget {
    limit: usize,
    used: usize,
}

impl AllocationBudget {
    /// A budget of `limit` bytes.
    #[must_use]
    pub const fn new(limit: usize) -> Self {
        Self { limit, used: 0 }
    }

    /// Reserve `bytes` from the budget.
    ///
    /// # Errors
    /// [`AllocationRefused`] when the reservation would exceed the
    /// budget; the budget is unchanged on refusal.
    pub const fn reserve(&mut self, bytes: usize) -> Result<(), AllocationRefused> {
        let available = self.limit - self.used;
        if bytes > available {
            return Err(AllocationRefused {
                requested: bytes,
                available,
            });
        }
        self.used += bytes;
        Ok(())
    }

    /// Return `bytes` to the budget (buffer dropped).
    pub const fn release(&mut self, bytes: usize) {
        self.used = self.used.saturating_sub(bytes);
    }

    /// Bytes currently reserved.
    #[must_use]
    pub const fn used(&self) -> usize {
        self.used
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The global panic hook is process state: the two tests that
    /// install the recording hook serialize on this lock so they never
    /// interleave hook installs (and no other test in this crate
    /// panics intentionally).
    static HOOK_LOCK: Mutex<()> = Mutex::new(());

    #[test]
    fn c022_injected_panic_before_exposure_runs_the_exact_original_chain() {
        let _serial = HOOK_LOCK.lock().unwrap();
        let store = Arc::new(Mutex::new(Vec::new()));
        let guard = RecordingHookGuard::install(Arc::clone(&store));
        // The wrapper panics before ANY exposure...
        let result: Result<(), PanicRecord> =
            run_contained(|| panic!("internal wrapper bug 42"), &store);
        drop(guard);
        // ...the panic is CONTAINED and recorded internally (message +
        // location), not printed and not a crash...
        let record = result.unwrap_err();
        assert_eq!(record.message, "internal wrapper bug 42");
        assert!(
            record
                .location
                .as_deref()
                .unwrap_or("")
                .contains("wrapper_panic.rs"),
            "hook records the location: {:?}",
            record.location
        );
        assert_eq!(store.lock().unwrap().len(), 1, "exactly one record");
        // ...and with a clean frontier the outcome is the EXACT
        // original chain, regardless of recovery configuration.
        let clean = SubscriberFrontierReport::default();
        for config in [
            FallbackConfig::default(),
            FallbackConfig {
                labeled_transcript_recovery: true,
            },
        ] {
            assert_eq!(
                contain_panic(&clean, &config, 7),
                ContainedOutcome::RunExactOriginalChain
            );
        }
    }

    #[test]
    fn c022_contained_success_passes_through_and_restores_the_hook() {
        let _serial = HOOK_LOCK.lock().unwrap();
        let store = Arc::new(Mutex::new(Vec::new()));
        {
            let _guard = RecordingHookGuard::install(Arc::clone(&store));
            let value = run_contained(|| 40 + 2, &store).unwrap();
            assert_eq!(value, 42);
        }
        // Guard dropped: the recording hook is gone; a fresh install
        // still works (RAII restored the previous hook, not a poison).
        assert!(store.lock().unwrap().is_empty(), "no panic, no record");
        let store2 = Arc::new(Mutex::new(Vec::new()));
        let guard2 = RecordingHookGuard::install(Arc::clone(&store2));
        let err = run_contained(|| -> () { panic!("second install works") }, &store2).unwrap_err();
        drop(guard2);
        assert_eq!(err.message, "second install works");
    }

    #[test]
    fn c022_injected_panic_after_exposure_fails_per_the_frontier() {
        // Transcript exposed, recovery OFF: reconnect-or-fail.
        let transcript = SubscriberFrontierReport {
            transcript_exposed: true,
            last_fully_delivered_seq: 9,
            ..Default::default()
        };
        assert!(matches!(
            contain_panic(&transcript, &FallbackConfig::default(), 7),
            ContainedOutcome::FrontierGoverned(FallbackAction::ReconnectOrFailCoherently { .. })
        ));
        // Recovery ON: labeled rerun behind the boundary marker.
        match contain_panic(
            &transcript,
            &FallbackConfig {
                labeled_transcript_recovery: true,
            },
            7,
        ) {
            ContainedOutcome::FrontierGoverned(FallbackAction::DetachAndRunLabeled {
                boundary_marker,
            }) => {
                assert!(boundary_marker.contains("delivered seq 9"));
            }
            other => panic!("expected labeled recovery, got {other:?}"),
        }
        // Stateful intent recorded: a wrapper panic grants NO extra
        // permission — no local rerun under any configuration.
        let stateful = SubscriberFrontierReport {
            stateful_intent_recorded: true,
            ..Default::default()
        };
        for config in [
            FallbackConfig::default(),
            FallbackConfig {
                labeled_transcript_recovery: true,
            },
        ] {
            assert!(matches!(
                contain_panic(&stateful, &config, 7),
                ContainedOutcome::FrontierGoverned(
                    FallbackAction::ReconnectOrFailCoherently { .. }
                )
            ));
        }
        // Even bare UNCERTAINTY is exposure (R116): no seamless rerun.
        let uncertain = SubscriberFrontierReport {
            transcript_uncertain: true,
            ..Default::default()
        };
        assert!(matches!(
            contain_panic(&uncertain, &FallbackConfig::default(), 7),
            ContainedOutcome::FrontierGoverned(_)
        ));
    }

    #[test]
    fn c022_abort_strategy_requires_the_parent_guard_proof() {
        assert_eq!(validate_strategy(PanicStrategy::Unwind), Ok(()));
        assert_eq!(
            validate_strategy(PanicStrategy::Abort {
                parent_guard_proven: true
            }),
            Ok(())
        );
        assert_eq!(
            validate_strategy(PanicStrategy::Abort {
                parent_guard_proven: false
            }),
            Err(StrategyError::AbortWithoutParentGuard)
        );
    }

    #[test]
    fn c022_allocation_budget_refuses_instead_of_aborting() {
        let mut budget = AllocationBudget::new(1024);
        budget.reserve(1000).unwrap();
        // Beyond-budget: typed refusal naming request and headroom —
        // the OOM path is a decision, not an abort.
        assert_eq!(
            budget.reserve(100),
            Err(AllocationRefused {
                requested: 100,
                available: 24,
            })
        );
        assert_eq!(budget.used(), 1000, "refusal changes nothing");
        budget.release(500);
        budget.reserve(100).unwrap();
        assert_eq!(budget.used(), 600);
    }
}
