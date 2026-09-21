//! Persistent worker connection supervision, not execution retry.
//!
//! Each session owns and drains its execution/transfer tasks before returning
//! the SAME journal to this supervisor. Restoration and backoff run outside the
//! native reactor. A new connection always repeats transport authentication and
//! application admission; only request-status/result-resume can reconcile work.

use asupersync::cx::Cx;
use asupersync::runtime::RuntimeBuilder;
use rabs_wkr::request_journal::WorkerJournal;
use rabs_wkr::session::CapabilityReport;
use std::sync::Arc;
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

/// Run until process shutdown or an unrecoverable journal failure. `once` keeps
/// the explicit one-session operator/test contract, including no connect retry.
/// Socket errors and peer EOF never cause the caller to replay a compiler.
pub(super) fn run(
    coordinator: String,
    report: CapabilityReport,
    once: bool,
    mut journal: WorkerJournal,
) -> i32 {
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
        let handle = runtime.handle();
        let endpoint = coordinator.clone();
        let capability = Arc::clone(&report);
        let (outcome, returned_journal, admitted_for) = runtime.block_on(async move {
            handle.spawn(async move {
                let cx = Cx::current().expect("runtime task Cx");
                let mut admitted_at: Option<Instant> = None;
                let outcome = super::session_loop(
                    &cx, &endpoint, &capability, once, &mut journal, &mut admitted_at,
                ).await;
                // session_loop has joined process cleanup and dropped both
                // range-transfer owners before we regain durable ownership.
                (outcome, journal, admitted_at.map(|start| start.elapsed()))
            }).await
        });
        journal = returned_journal;
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
        // No runtime task, process lease or network session is held in backoff.
        // The exclusive journal lock deliberately remains held across this wait.
        std::thread::sleep(delay);
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
}
