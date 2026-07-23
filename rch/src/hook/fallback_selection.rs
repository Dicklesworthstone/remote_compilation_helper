//! Capacity-aware worker selection for the remote-failure fallback loop.
//!
//! When a remote build FAILS for a worker-fault reason (an OOM signal-kill, a
//! missing worker system dependency, a missing toolchain, or a generic pipeline
//! error), the hook should NOT immediately revert the heavy compile to the local
//! orchestrator — that floods the box that coordinates the whole fleet
//! ([[rch_local_fallback_floods_trj_oom_crate]]). Instead it retries the build on
//! a *different, higher-capacity* worker, using the memory-pressure / slot
//! telemetry the daemon already tracks (surfaced via `GET /status`). Local
//! execution is a genuine last resort, gated by `compilation.allow_local_fallback`.
//!
//! This module owns the pure ranking logic so it is unit-testable without a live
//! daemon: [`WorkerCapacitySnapshot`] captures the capacity signals for one
//! worker and [`pick_bigger_worker`] chooses the best untried candidate. The
//! caller ([`super::run_exec`]) turns the picked worker id into a `preferred_workers`
//! re-query so the daemon reserves exactly that worker for the retry.

use std::cmp::Ordering;

use rch_common::WorkerId;

use crate::status_types::{DaemonFullStatusResponse, WorkerStatusFromApi};

/// Memory-pressure score at/above which a worker is treated as having only
/// *warning*-level RAM headroom. Mirrors the daemon's disk-pressure policy
/// (`warning_memory_pressure`).
const WARNING_MEMORY_PRESSURE: f64 = 80.0;
/// Memory-pressure score at/above which a worker has *near-critical* RAM
/// headroom (mirrors `critical_memory_pressure`). Genuinely critical workers are
/// excluded up-front via [`WorkerCapacitySnapshot::pressure_critical`].
const CRITICAL_MEMORY_PRESSURE: f64 = 92.0;

/// Capacity signals for a single worker, distilled from the daemon status so the
/// ranking is independent of the wire type.
#[derive(Debug, Clone, PartialEq)]
pub(super) struct WorkerCapacitySnapshot {
    pub(super) id: WorkerId,
    /// Eligible to receive a build right now (status healthy, circuit not open).
    pub(super) healthy: bool,
    /// Daemon flagged this worker's storage/memory pressure as critical — a hard
    /// exclusion (it is exactly the kind of small/stressed worker an OOM retry
    /// must avoid).
    pub(super) pressure_critical: bool,
    /// Currently free CPU slots (`total_slots - used_slots`).
    pub(super) free_slots: u32,
    /// Total CPU slots — a proxy for machine size / total RAM across the fleet.
    pub(super) total_slots: u32,
    /// 0-100 speed score.
    pub(super) speed_score: f64,
    /// Latest memory-pressure sample (0-100; lower means more free RAM). `None`
    /// when telemetry is unavailable.
    pub(super) memory_pressure: Option<f64>,
}

impl WorkerCapacitySnapshot {
    fn from_status(worker: &WorkerStatusFromApi) -> Self {
        let healthy = worker.status.eq_ignore_ascii_case("healthy")
            && !worker.circuit_state.eq_ignore_ascii_case("open");
        let pressure_critical = worker
            .pressure_state
            .as_deref()
            .is_some_and(|state| state.eq_ignore_ascii_case("critical"));
        Self {
            id: WorkerId::new(worker.id.clone()),
            healthy,
            pressure_critical,
            free_slots: worker.total_slots.saturating_sub(worker.used_slots),
            total_slots: worker.total_slots,
            speed_score: worker.speed_score,
            memory_pressure: worker.pressure_memory_pressure,
        }
    }

    /// RAM headroom proxy (higher is better). Unknown pressure is treated as a
    /// neutral midpoint so a worker with no telemetry neither dominates nor is
    /// unfairly penalized versus workers with known-good headroom.
    fn memory_headroom(&self) -> f64 {
        match self.memory_pressure {
            Some(pressure) => 100.0 - pressure,
            None => 50.0,
        }
    }

    /// Coarse RAM-headroom bucket (higher is better): healthy (or unknown) beats
    /// warning beats near-critical, regardless of machine size. This keeps an
    /// OOM retry off a large-but-memory-stressed box.
    fn headroom_bucket(&self) -> u8 {
        match self.memory_pressure {
            Some(pressure) if pressure >= CRITICAL_MEMORY_PRESSURE => 0,
            Some(pressure) if pressure >= WARNING_MEMORY_PRESSURE => 1,
            _ => 2,
        }
    }
}

/// Build capacity snapshots for every worker in a daemon status response.
pub(super) fn build_capacity_snapshots(
    status: &DaemonFullStatusResponse,
) -> Vec<WorkerCapacitySnapshot> {
    status
        .workers
        .iter()
        .map(WorkerCapacitySnapshot::from_status)
        .collect()
}

/// Order two candidates by capacity: `Greater` means the left worker is the
/// better retry target (bigger / more RAM headroom). Priority, most significant
/// first: RAM-headroom bucket, total slots (machine size), fine-grained memory
/// headroom, free slots, then speed score.
fn capacity_order(a: &WorkerCapacitySnapshot, b: &WorkerCapacitySnapshot) -> Ordering {
    a.headroom_bucket()
        .cmp(&b.headroom_bucket())
        .then_with(|| a.total_slots.cmp(&b.total_slots))
        .then_with(|| {
            a.memory_headroom()
                .partial_cmp(&b.memory_headroom())
                .unwrap_or(Ordering::Equal)
        })
        .then_with(|| a.free_slots.cmp(&b.free_slots))
        .then_with(|| {
            a.speed_score
                .partial_cmp(&b.speed_score)
                .unwrap_or(Ordering::Equal)
        })
}

/// Pick the best *untried* worker to retry a failed build on — the one with the
/// most capacity / RAM headroom (see [`capacity_order`]).
///
/// Filtering:
/// * only `healthy` workers whose pressure is not `critical`,
/// * never a worker already in `tried`,
/// * when `allowed` is non-empty (an explicit `RCH_WORKER(S)` pin), the
///   candidate must be within it — a retry must never escape the operator's pin.
///
/// Ties break on ascending worker id for determinism. Returns `None` when no
/// eligible untried worker remains (retries are exhausted).
pub(super) fn pick_bigger_worker(
    snapshots: &[WorkerCapacitySnapshot],
    tried: &[WorkerId],
    allowed: &[WorkerId],
) -> Option<WorkerId> {
    let mut best: Option<&WorkerCapacitySnapshot> = None;
    for candidate in snapshots {
        if !candidate.healthy || candidate.pressure_critical {
            continue;
        }
        if tried.iter().any(|id| id == &candidate.id) {
            continue;
        }
        if !allowed.is_empty() && !allowed.iter().any(|id| id == &candidate.id) {
            continue;
        }
        best = match best {
            None => Some(candidate),
            Some(current) => match capacity_order(candidate, current) {
                Ordering::Greater => Some(candidate),
                Ordering::Less => Some(current),
                // Deterministic tie-break: smaller id wins.
                Ordering::Equal => {
                    if candidate.id.as_str() < current.id.as_str() {
                        Some(candidate)
                    } else {
                        Some(current)
                    }
                }
            },
        };
    }
    best.map(|snapshot| snapshot.id.clone())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn snap(
        id: &str,
        healthy: bool,
        total_slots: u32,
        free_slots: u32,
        memory_pressure: Option<f64>,
    ) -> WorkerCapacitySnapshot {
        WorkerCapacitySnapshot {
            id: WorkerId::new(id.to_string()),
            healthy,
            pressure_critical: false,
            free_slots,
            total_slots,
            speed_score: 50.0,
            memory_pressure,
        }
    }

    #[test]
    fn picks_the_bigger_machine_when_headroom_is_comparable() {
        // Both healthy headroom; the bigger machine (more total slots ~ more RAM)
        // is preferred for an OOM retry.
        let snaps = vec![
            snap("small", true, 8, 8, Some(20.0)),
            snap("big", true, 64, 4, Some(20.0)),
        ];
        let pick = pick_bigger_worker(&snaps, &[], &[]);
        assert_eq!(pick, Some(WorkerId::new("big")));
    }

    #[test]
    fn avoids_memory_stressed_worker_even_if_larger() {
        // A large box with warning-level memory pressure loses to a smaller box
        // with healthy RAM headroom — exactly what an OOM retry must do.
        let snaps = vec![
            snap("big_stressed", true, 128, 100, Some(88.0)),
            snap("small_healthy", true, 16, 16, Some(10.0)),
        ];
        let pick = pick_bigger_worker(&snaps, &[], &[]);
        assert_eq!(pick, Some(WorkerId::new("small_healthy")));
    }

    #[test]
    fn excludes_tried_and_unhealthy_and_critical_workers() {
        let mut critical = snap("critical", true, 256, 256, Some(99.0));
        critical.pressure_critical = true;
        let snaps = vec![
            snap("tried", true, 128, 128, Some(5.0)),
            snap("unhealthy", false, 128, 128, Some(5.0)),
            critical,
            snap("eligible", true, 32, 32, Some(30.0)),
        ];
        let pick = pick_bigger_worker(&snaps, &[WorkerId::new("tried")], &[]);
        assert_eq!(pick, Some(WorkerId::new("eligible")));
    }

    #[test]
    fn respects_the_allowed_pin() {
        // Even though "big" is larger, the operator pinned only "pinned".
        let snaps = vec![
            snap("big", true, 128, 128, Some(10.0)),
            snap("pinned", true, 16, 16, Some(10.0)),
        ];
        let pick = pick_bigger_worker(&snaps, &[], &[WorkerId::new("pinned")]);
        assert_eq!(pick, Some(WorkerId::new("pinned")));
    }

    #[test]
    fn returns_none_when_all_candidates_exhausted() {
        let snaps = vec![snap("only", true, 32, 32, Some(10.0))];
        let pick = pick_bigger_worker(&snaps, &[WorkerId::new("only")], &[]);
        assert_eq!(pick, None);
    }

    #[test]
    fn unknown_pressure_ranks_between_healthy_and_warning() {
        // total_slots equal; a known-healthy worker beats an unknown-pressure
        // worker, which in turn beats a warning-pressure worker.
        let snaps = vec![
            snap("warning", true, 32, 32, Some(85.0)),
            snap("unknown", true, 32, 32, None),
            snap("healthy", true, 32, 32, Some(5.0)),
        ];
        assert_eq!(
            pick_bigger_worker(&snaps, &[], &[]),
            Some(WorkerId::new("healthy"))
        );
        assert_eq!(
            pick_bigger_worker(&snaps, &[WorkerId::new("healthy")], &[]),
            Some(WorkerId::new("unknown"))
        );
    }

    #[test]
    fn ties_break_on_ascending_id() {
        let snaps = vec![
            snap("bbb", true, 32, 32, Some(10.0)),
            snap("aaa", true, 32, 32, Some(10.0)),
        ];
        assert_eq!(
            pick_bigger_worker(&snaps, &[], &[]),
            Some(WorkerId::new("aaa"))
        );
    }
}
