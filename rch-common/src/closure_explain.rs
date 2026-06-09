//! Path-dependency closure sync explanation (bd-session-history-remediation-ocv9i.8.1).
//!
//! Backs `rch sync --explain` / the doctor surface: for every root in a
//! [`DependencyClosurePlan`], it joins the *planner* facts (why a root is
//! included, its risk class, sync order) with *convergence* facts (local vs
//! remote revision/hash, last sync time) into a [`ClosureExplainReport`] so an
//! operator sees the whole closure — and why each root will (or won't) sync —
//! without inspecting Cargo manifests, the daemon, and the remote separately.
//!
//! Convergence facts are supplied by the caller (the daemon's repo-convergence
//! layer), so this stays a pure, deterministic join with no I/O.

use std::collections::BTreeMap;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use crate::dependency_closure_planner::{
    DependencyClosurePlan, DependencyRiskClass, DependencySyncReason,
};

/// Per-root convergence facts (local vs remote state), keyed into the explain
/// join by canonical root path.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct RootConvergence {
    /// Whether the root exists locally at all.
    pub present: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub local_revision: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub local_hash: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub remote_revision: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub remote_hash: Option<String>,
    /// Last successful sync time (Unix ms), if ever synced.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_sync_unix_ms: Option<u64>,
}

/// The effective sync action for one root, derived from convergence.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RootSyncOutcome {
    /// Local root is missing — cannot sync.
    MissingRoot,
    /// Never synced to the remote (no remote hash yet) — first sync needed.
    SyncNeeded,
    /// Remote is out of date relative to local — re-sync needed.
    StaleRemote,
    /// Local and remote agree — nothing to do.
    NoOpClean,
}

impl RootSyncOutcome {
    /// Whether this outcome implies a transfer will occur.
    #[must_use]
    pub const fn needs_sync(self) -> bool {
        matches!(self, Self::SyncNeeded | Self::StaleRemote)
    }
}

/// Derive the sync outcome for a root from its convergence facts.
#[must_use]
pub fn derive_outcome(c: &RootConvergence) -> RootSyncOutcome {
    if !c.present {
        return RootSyncOutcome::MissingRoot;
    }
    match (&c.local_hash, &c.remote_hash) {
        (_, None) => RootSyncOutcome::SyncNeeded,
        (Some(l), Some(r)) if l == r => RootSyncOutcome::NoOpClean,
        _ => RootSyncOutcome::StaleRemote,
    }
}

/// One explained root: planner facts joined with convergence facts.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClosureExplainEntry {
    pub order_index: usize,
    pub package_root: PathBuf,
    pub package_name: String,
    /// Why the root is in the closure.
    pub included_reason: DependencySyncReason,
    /// Planner risk class.
    pub risk: DependencyRiskClass,
    pub convergence: RootConvergence,
    /// Effective sync action derived from convergence.
    pub sync_action: RootSyncOutcome,
}

/// The full explanation report for a closure plan.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClosureExplainReport {
    pub entry_manifest_path: PathBuf,
    /// True when the closure planner failed open (degraded to a safe fallback).
    pub fail_open: bool,
    pub entries: Vec<ClosureExplainEntry>,
    /// Count of roots that will actually transfer.
    pub sync_count: usize,
    /// Count of roots missing locally.
    pub missing_count: usize,
}

impl ClosureExplainReport {
    /// True when nothing needs to sync and nothing is missing — a clean no-op.
    #[must_use]
    pub fn is_clean_noop(&self) -> bool {
        self.sync_count == 0 && self.missing_count == 0
    }

    /// Human-readable explanation block.
    #[must_use]
    pub fn render(&self) -> String {
        let mut s = format!(
            "path-dependency closure ({} roots, {} to sync, {} missing{}):",
            self.entries.len(),
            self.sync_count,
            self.missing_count,
            if self.fail_open { ", FAIL-OPEN" } else { "" },
        );
        for e in &self.entries {
            s.push_str(&format!(
                "\n  [{}] {} ({:?}, risk={:?}) -> {:?}",
                e.order_index, e.package_name, e.included_reason, e.risk, e.sync_action,
            ));
            s.push_str(&format!(
                "\n      local rev={} hash={} | remote rev={} hash={} | last_sync_ms={}",
                opt(&e.convergence.local_revision),
                opt(&e.convergence.local_hash),
                opt(&e.convergence.remote_revision),
                opt(&e.convergence.remote_hash),
                e.convergence
                    .last_sync_unix_ms
                    .map_or_else(|| "never".to_string(), |v| v.to_string()),
            ));
        }
        if self.is_clean_noop() {
            s.push_str("\n  -> clean: nothing to sync");
        }
        s
    }
}

fn opt(o: &Option<String>) -> &str {
    o.as_deref().unwrap_or("-")
}

/// Build the explanation report by joining a closure plan with per-root
/// convergence facts (keyed by canonical root path). Roots with no convergence
/// entry are treated as missing.
#[must_use]
pub fn explain_closure(
    plan: &DependencyClosurePlan,
    convergence: &BTreeMap<PathBuf, RootConvergence>,
) -> ClosureExplainReport {
    let mut entries = Vec::with_capacity(plan.sync_order.len());
    let mut sync_count = 0;
    let mut missing_count = 0;

    for action in &plan.sync_order {
        let conv = convergence
            .get(&action.package_root)
            .cloned()
            .unwrap_or_default();
        let outcome = derive_outcome(&conv);
        match outcome {
            RootSyncOutcome::MissingRoot => missing_count += 1,
            o if o.needs_sync() => sync_count += 1,
            _ => {}
        }
        entries.push(ClosureExplainEntry {
            order_index: action.order_index,
            package_root: action.package_root.clone(),
            package_name: action.package_name.clone(),
            included_reason: action.metadata.reason,
            risk: action.risk,
            convergence: conv,
            sync_action: outcome,
        });
    }

    ClosureExplainReport {
        entry_manifest_path: plan.entry_manifest_path.clone(),
        fail_open: plan.fail_open,
        entries,
        sync_count,
        missing_count,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dependency_closure_planner::{
        DependencyClosurePlanState, DependencySyncAction, DependencySyncMetadata,
    };

    fn action(
        idx: usize,
        root: &str,
        name: &str,
        reason: DependencySyncReason,
    ) -> DependencySyncAction {
        DependencySyncAction {
            order_index: idx,
            package_root: PathBuf::from(root),
            manifest_path: PathBuf::from(format!("{root}/Cargo.toml")),
            package_name: name.to_string(),
            risk: DependencyRiskClass::Low,
            metadata: DependencySyncMetadata {
                reason,
                workspace_member: reason == DependencySyncReason::WorkspaceMember,
                root_package: reason == DependencySyncReason::EntryPoint,
                inbound_dependency_names: Vec::new(),
                dependent_roots: Vec::new(),
                notes: Vec::new(),
            },
        }
    }

    fn plan(actions: Vec<DependencySyncAction>) -> DependencyClosurePlan {
        DependencyClosurePlan {
            state: DependencyClosurePlanState::Ready,
            entry_manifest_path: PathBuf::from("/proj/Cargo.toml"),
            workspace_root: Some(PathBuf::from("/proj")),
            canonical_roots: actions.iter().map(|a| a.package_root.clone()).collect(),
            sync_order: actions,
            fail_open: false,
            fail_open_reason: None,
            issues: Vec::new(),
        }
    }

    fn converged(local: &str, remote: &str) -> RootConvergence {
        RootConvergence {
            present: true,
            local_revision: Some("rev".to_string()),
            local_hash: Some(local.to_string()),
            remote_revision: Some("rev".to_string()),
            remote_hash: Some(remote.to_string()),
            last_sync_unix_ms: Some(1_700_000_000_000),
        }
    }

    #[test]
    fn derive_outcome_covers_all_states() {
        assert_eq!(
            derive_outcome(&RootConvergence::default()),
            RootSyncOutcome::MissingRoot
        );
        assert_eq!(
            derive_outcome(&converged("h", "h")),
            RootSyncOutcome::NoOpClean
        );
        assert_eq!(
            derive_outcome(&converged("h1", "h2")),
            RootSyncOutcome::StaleRemote
        );
        let never = RootConvergence {
            present: true,
            local_hash: Some("h".to_string()),
            remote_hash: None,
            ..RootConvergence::default()
        };
        assert_eq!(derive_outcome(&never), RootSyncOutcome::SyncNeeded);
    }

    #[test]
    fn multi_crate_clean_no_op() {
        let p = plan(vec![
            action(0, "/proj/a", "a", DependencySyncReason::EntryPoint),
            action(1, "/proj/b", "b", DependencySyncReason::WorkspaceMember),
        ]);
        let mut conv = BTreeMap::new();
        conv.insert(PathBuf::from("/proj/a"), converged("h", "h"));
        conv.insert(PathBuf::from("/proj/b"), converged("h", "h"));
        let report = explain_closure(&p, &conv);
        assert_eq!(report.entries.len(), 2);
        assert!(report.is_clean_noop());
        assert_eq!(report.sync_count, 0);
        assert!(
            report
                .entries
                .iter()
                .all(|e| e.sync_action == RootSyncOutcome::NoOpClean)
        );
    }

    #[test]
    fn sibling_repo_transitive_dependency_is_explained() {
        // A path dep in a sibling repo (outside the workspace root).
        let p = plan(vec![
            action(0, "/proj/main", "main", DependencySyncReason::EntryPoint),
            action(
                1,
                "/sibling/lib",
                "lib",
                DependencySyncReason::TransitivePathDependency,
            ),
        ]);
        let mut conv = BTreeMap::new();
        conv.insert(PathBuf::from("/proj/main"), converged("h", "h"));
        conv.insert(PathBuf::from("/sibling/lib"), converged("h", "h"));
        let report = explain_closure(&p, &conv);
        let sib = report
            .entries
            .iter()
            .find(|e| e.package_name == "lib")
            .unwrap();
        assert_eq!(
            sib.included_reason,
            DependencySyncReason::TransitivePathDependency
        );
    }

    #[test]
    fn stale_remote_root_needs_sync() {
        let p = plan(vec![action(
            0,
            "/proj/a",
            "a",
            DependencySyncReason::EntryPoint,
        )]);
        let mut conv = BTreeMap::new();
        conv.insert(
            PathBuf::from("/proj/a"),
            converged("localhash", "OLDremote"),
        );
        let report = explain_closure(&p, &conv);
        assert_eq!(report.entries[0].sync_action, RootSyncOutcome::StaleRemote);
        assert_eq!(report.sync_count, 1);
        assert!(!report.is_clean_noop());
    }

    #[test]
    fn missing_root_is_flagged() {
        let p = plan(vec![action(
            0,
            "/proj/gone",
            "gone",
            DependencySyncReason::TransitivePathDependency,
        )]);
        // No convergence entry -> missing.
        let report = explain_closure(&p, &BTreeMap::new());
        assert_eq!(report.entries[0].sync_action, RootSyncOutcome::MissingRoot);
        assert_eq!(report.missing_count, 1);
        assert!(!report.is_clean_noop());
    }

    #[test]
    fn render_and_serde_roundtrip() {
        let p = plan(vec![action(
            0,
            "/proj/a",
            "a",
            DependencySyncReason::EntryPoint,
        )]);
        let mut conv = BTreeMap::new();
        conv.insert(PathBuf::from("/proj/a"), converged("h", "h"));
        let report = explain_closure(&p, &conv);
        let text = report.render();
        assert!(text.contains("path-dependency closure"));
        assert!(text.contains("clean: nothing to sync"));
        let back: ClosureExplainReport =
            serde_json::from_str(&serde_json::to_string(&report).unwrap()).unwrap();
        assert_eq!(report, back);
    }

    #[test]
    fn fail_open_plan_is_marked() {
        let mut p = plan(vec![action(
            0,
            "/proj/a",
            "a",
            DependencySyncReason::EntryPoint,
        )]);
        p.fail_open = true;
        let report = explain_closure(&p, &BTreeMap::new());
        assert!(report.fail_open);
        assert!(report.render().contains("FAIL-OPEN"));
    }
}
