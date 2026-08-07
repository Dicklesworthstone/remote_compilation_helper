//! Obligation-leak + quiescence dashboards (bead G015; Epic G
//! observability; invariant I7's visibility arm).
//!
//! Region-close blocking (G002) is only useful if a human can SEE the
//! stuck obligation. The dashboard model is pure fold-state: every
//! open/resolve event updates per-region rows keyed by (region path,
//! obligation kind) with age tracking in causal ticks; the alert rule
//! fires when an obligation outlives its threshold. Quiescence status
//! summarizes what a closing region still owes.

use crate::obligations::ObligationKind;

/// One outstanding-obligation row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OutstandingRow {
    /// Region path (G001 attribution path).
    pub region: String,
    /// Obligation kind.
    pub kind: ObligationKind,
    /// Causal tick when opened.
    pub opened_at_tick: u64,
}

/// A fired alert.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StuckObligationAlert {
    /// The stuck row.
    pub row: OutstandingRow,
    /// Its age in ticks at alert time.
    pub age_ticks: u64,
}

/// Quiescence status of one region asked to close.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum QuiescenceStatus {
    /// Nothing outstanding: the region may close.
    Quiescent,
    /// Still draining, with everything owed listed by kind + age.
    Draining {
        /// Outstanding kinds with ages.
        owed: Vec<(ObligationKind, u64)>,
    },
}

/// The dashboard fold state.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ObligationDashboard {
    outstanding: Vec<OutstandingRow>,
}

impl ObligationDashboard {
    /// Record an obligation opening.
    pub fn opened(&mut self, region: &str, kind: ObligationKind, tick: u64) {
        self.outstanding.push(OutstandingRow {
            region: region.to_owned(),
            kind,
            opened_at_tick: tick,
        });
    }

    /// Record an obligation resolving.
    pub fn resolved(&mut self, region: &str, kind: ObligationKind) {
        if let Some(pos) = self
            .outstanding
            .iter()
            .position(|r| r.region == region && r.kind == kind)
        {
            self.outstanding.remove(pos);
        }
    }

    /// The outstanding view, sorted oldest first (the dashboard body).
    #[must_use]
    pub fn outstanding_by_age(&self) -> Vec<&OutstandingRow> {
        let mut rows: Vec<&OutstandingRow> = self.outstanding.iter().collect();
        rows.sort_by_key(|r| r.opened_at_tick);
        rows
    }

    /// Alert rule: rows older than `threshold_ticks` at `now`.
    #[must_use]
    pub fn stuck_alerts(&self, now: u64, threshold_ticks: u64) -> Vec<StuckObligationAlert> {
        self.outstanding
            .iter()
            .filter_map(|row| {
                let age = now.saturating_sub(row.opened_at_tick);
                (age > threshold_ticks).then(|| StuckObligationAlert {
                    row: row.clone(),
                    age_ticks: age,
                })
            })
            .collect()
    }

    /// Quiescence status for a region asked to close.
    #[must_use]
    pub fn quiescence(&self, region: &str, now: u64) -> QuiescenceStatus {
        let owed: Vec<(ObligationKind, u64)> = self
            .outstanding
            .iter()
            .filter(|r| r.region == region)
            .map(|r| (r.kind, now.saturating_sub(r.opened_at_tick)))
            .collect();
        if owed.is_empty() {
            QuiescenceStatus::Quiescent
        } else {
            QuiescenceStatus::Draining { owed }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ObligationKind as K;

    const REGION: &str =
        "RabsCoordinatorRoot/ActionRegistryRegion/ActionRegion/AttemptSet/AttemptProxy";

    #[test]
    fn dashboard_shows_a_seeded_leak_by_region_type_and_age() {
        // THE acceptance: seed a leak (opened, never resolved) among
        // resolved traffic; the dashboard shows exactly it, with
        // region, type, and age.
        let mut dash = ObligationDashboard::default();
        dash.opened(REGION, K::SandboxCleanup, 10);
        dash.opened(REGION, K::DiagnosticStream, 12);
        dash.opened("RabsEdgeRoot/CargoDriverRegion", K::CargoRootPermit, 5);
        dash.resolved(REGION, K::DiagnosticStream);
        dash.resolved("RabsEdgeRoot/CargoDriverRegion", K::CargoRootPermit);
        let rows = dash.outstanding_by_age();
        assert_eq!(rows.len(), 1, "only the leak remains");
        assert_eq!(rows[0].region, REGION);
        assert_eq!(rows[0].kind, K::SandboxCleanup);
        assert_eq!(rows[0].opened_at_tick, 10);
    }

    #[test]
    fn alert_fires_on_a_stuck_obligation_and_only_then() {
        // THE acceptance: the alert fires when the age crosses the
        // threshold — and not before.
        let mut dash = ObligationDashboard::default();
        dash.opened(REGION, K::ProcessGroupDrain, 100);
        assert!(dash.stuck_alerts(150, 100).is_empty(), "young: no alert");
        let alerts = dash.stuck_alerts(250, 100);
        assert_eq!(alerts.len(), 1);
        assert_eq!(alerts[0].row.kind, K::ProcessGroupDrain);
        assert_eq!(alerts[0].age_ticks, 150);
        // Resolution silences the alert.
        dash.resolved(REGION, K::ProcessGroupDrain);
        assert!(dash.stuck_alerts(1_000, 100).is_empty());
    }

    #[test]
    fn quiescence_lists_everything_a_closing_region_owes() {
        let mut dash = ObligationDashboard::default();
        dash.opened(REGION, K::SandboxCleanup, 10);
        dash.opened(REGION, K::OutputStagingPin, 20);
        dash.opened("other-region", K::JournalCheckpoint, 1);
        let status = dash.quiescence(REGION, 30);
        assert_eq!(
            status,
            QuiescenceStatus::Draining {
                owed: vec![(K::SandboxCleanup, 20), (K::OutputStagingPin, 10)]
            },
            "owed list is per-region with ages; other regions excluded"
        );
        dash.resolved(REGION, K::SandboxCleanup);
        dash.resolved(REGION, K::OutputStagingPin);
        assert_eq!(dash.quiescence(REGION, 40), QuiescenceStatus::Quiescent);
        // The other region still drains independently.
        assert!(matches!(
            dash.quiescence("other-region", 40),
            QuiescenceStatus::Draining { .. }
        ));
    }
}
