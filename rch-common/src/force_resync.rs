//! Agent-safe force-resync for stale path-dependency roots
//! (bd-session-history-remediation-ocv9i.8.3).
//!
//! When stale dependency roots block verification, an agent needs ONE supported
//! command that invalidates the worker-side cache for those roots, resyncs the
//! closure, and explains what changed — *without ever deleting worker data
//! outside an RCH-managed root*. This module plans that invalidation
//! ([`plan_force_resync`]) with a hard safety guard (every target must live
//! strictly under the RCH-managed base, and the base itself can never be the
//! target), and reports the outcome ([`apply_force_resync`]) — deferring
//! safely, with no destructive action, when the worker is unreachable.

use std::path::{Path, PathBuf};

use anyhow::Context as _;
use serde::{Deserialize, Serialize};

/// A stale root to force-resync: its local project root and the worker-side
/// RCH-managed cache path that should be invalidated.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StaleRoot {
    pub local_root: PathBuf,
    pub worker_cache_path: PathBuf,
}

/// A planned, safety-checked cache invalidation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InvalidationAction {
    pub local_root: PathBuf,
    pub worker_cache_path: PathBuf,
}

/// A refused invalidation (its target would escape the RCH-managed root).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RefusedInvalidation {
    pub local_root: PathBuf,
    pub worker_cache_path: PathBuf,
    pub reason: String,
}

/// A safety-checked force-resync plan.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ForceResyncPlan {
    pub managed_base: PathBuf,
    pub invalidations: Vec<InvalidationAction>,
    pub refused: Vec<RefusedInvalidation>,
}

impl ForceResyncPlan {
    /// True when at least one root was refused on safety grounds.
    #[must_use]
    pub fn has_refusals(&self) -> bool {
        !self.refused.is_empty()
    }
}

/// Whether `target` is a *safe* invalidation target under `managed_base`: it
/// must be strictly inside the base (never the base itself, never an ancestor,
/// never an escaping `..` path).
#[must_use]
pub fn is_safe_invalidation_target(target: &Path, managed_base: &Path) -> bool {
    // Reject any traversal component up front; we operate on declared paths.
    if target
        .components()
        .any(|c| matches!(c, std::path::Component::ParentDir))
    {
        return false;
    }
    target.starts_with(managed_base) && target != managed_base
}

/// Build explicit force-resync through worker collection's ownership,
/// retention, liveness, and emergency-storage machinery. The selected scope
/// remains one immediate child of the existing managed base.
///
/// # Errors
///
/// Refuses unsafe bases, nested or escaping candidates, and ambiguous names.
pub fn remote_invalidation_command(path: &Path, managed_base: &Path) -> anyhow::Result<String> {
    let registry = crate::stale_target_reap::SOURCE_CLAIM_REGISTRY;
    let command = remote_invalidation_script(path, managed_base, registry)?;
    Ok(crate::stale_target_reap::with_gc_recovery_reserve(
        registry, &command,
    ))
}

/// The same guarded transaction for an explicit source registry. Production
/// wraps it in the emergency reserve; isolated native fixtures use their own
/// registry without touching deployed worker ownership.
///
/// # Errors
///
/// Refuses a candidate outside the exact normalized managed-base scope.
pub fn remote_invalidation_script(
    path: &Path,
    managed_base: &Path,
    registry: &str,
) -> anyhow::Result<String> {
    let base = managed_base.to_str().context("managed base is not UTF-8")?;
    let normalized =
        crate::types::validate_worker_remote_base(base, None).map_err(anyhow::Error::msg)?;
    anyhow::ensure!(
        normalized == base
            && is_safe_invalidation_target(path, managed_base)
            && path.parent() == Some(managed_base),
        "force-resync requires an immediate child of its normalized managed base"
    );
    let leaf = path
        .file_name()
        .and_then(|name| name.to_str())
        .context("cache directory name is not UTF-8")?;
    anyhow::ensure!(
        !leaf.chars().any(char::is_control),
        "cache directory name contains control characters"
    );
    let guard = crate::stale_target_reap::source_claim_gc_guard_fragment_with_registry(registry);
    let (liveness, cleanup) = crate::stale_target_reap::gc_liveness_guard_fragments();
    Ok(format!(
        r#"{guard}
{locate}
set -u
__sync_base={base}
__sync_leaf={leaf}
__held=''; __proc=''
rch_sync_end() {{
    {cleanup}
    __held=''; __proc=''
    if ! __gc_source_end; then
        printf 'RCH_SYNC_INVALIDATION_REFUSED retirement-failed\n' >&2
        return 1
    fi
}}
rch_sync_refuse_held() {{
    printf 'RCH_SYNC_INVALIDATION_REFUSED %s\n' "$1" >&2
    rch_sync_end || exit 73
    exit 73
}}
# An absent cache needs no removal. Existing links are never treated as absent.
if [ ! -e "$__sync_base" ] && [ ! -L "$__sync_base" ]; then
    printf 'RCH_SYNC_INVALIDATED absent\n'; exit 0
fi
if [ -L "$__sync_base" ] || ! cd -P -- "$__sync_base"; then
    printf 'RCH_SYNC_INVALIDATION_REFUSED managed-base\n' >&2; exit 73
fi
__sync_root=$(pwd -P) || exit 73
case "$__sync_root" in /*/*) ;; *)
    printf 'RCH_SYNC_INVALIDATION_REFUSED shallow-managed-base\n' >&2; exit 73;;
esac
__sync_target="$__sync_root/$__sync_leaf"
if [ ! -e "./$__sync_leaf" ] && [ ! -L "./$__sync_leaf" ]; then
    printf 'RCH_SYNC_INVALIDATED absent\n'; exit 0
fi
if [ -L "./$__sync_leaf" ] || [ ! -d "./$__sync_leaf" ]; then
    printf 'RCH_SYNC_INVALIDATION_REFUSED cache-directory\n' >&2; exit 73
fi
if ! rch_wkr_locate || [ "$("$RCH_WKR" force-resync probe)" != 'rch-wkr force-resync v1' ]; then
    printf 'RCH_SYNC_INVALIDATION_REFUSED deploy-rch-wkr-with-force-resync\n' >&2; exit 73
fi
__sync_worker=$RCH_WKR
__sync_identity=$("$__sync_worker" force-resync inspect "$__sync_target") || exit 73
if __gc_source_begin "$__sync_target"; then :; else
    __sync_admission=$?
    if [ "$__sync_admission" -eq 4 ]; then
        printf 'RCH_SYNC_INVALIDATED absent\n'; exit 0
    fi
    printf 'RCH_SYNC_INVALIDATION_REFUSED source-or-retention-%s\n' "$__sync_admission" >&2
    exit 73
fi
{liveness}
__sync_handles=$(__gc_handles "$__sync_target")
__sync_processes=$(__gc_procs "$__sync_target")
if [ "$__sync_handles" != free ] || [ "$__sync_processes" != free ]; then
    rch_sync_refuse_held "activity-handles-$__sync_handles-processes-$__sync_processes"
fi
# The source transaction serializes RCH admission. Recheck the initially
# observed directory after that wait and the process census. The native helper
# repeats these identities through each descriptor-relative unlink and keeps
# the canonical candidate in its argv for abandoned-claim reconciliation.
if [ "$__gc_candidate" != "$__sync_target" ] \
    || [ "$(pwd -P)" != "$__sync_root" ] \
    || [ ! "$__sync_base" -ef . ] \
    || [ -L "$__sync_base" ] \
    || [ -L "./$__sync_leaf" ] \
    || [ ! "$__sync_target" -ef "./$__sync_leaf" ]; then
    rch_sync_refuse_held changed-directory
fi
__sync_status=0
__sync_removed=$("$__sync_worker" force-resync apply "$__sync_target" "$__sync_identity" "$__gc_source_registry" "$__gc_reservation") || __sync_status=$?
rch_sync_end || exit 73
[ "$__sync_status" -eq 0 ] || exit "$__sync_status"
[ "$__sync_removed" = removed ] || exit 73
printf 'RCH_SYNC_INVALIDATED removed\n'
"#,
        base = shell_escape::escape(base.into()),
        leaf = shell_escape::escape(leaf.into()),
        locate = crate::wkr_locate::WKR_LOCATE_SHELL,
    ))
}

/// Plan the force-resync: each stale root whose worker cache path is safely
/// under `managed_base` becomes an invalidation; any other is refused (never
/// invalidated) so no worker data outside the managed root is ever touched.
#[must_use]
pub fn plan_force_resync(stale: &[StaleRoot], managed_base: &Path) -> ForceResyncPlan {
    let mut invalidations = Vec::new();
    let mut refused = Vec::new();
    for root in stale {
        if is_safe_invalidation_target(&root.worker_cache_path, managed_base) {
            invalidations.push(InvalidationAction {
                local_root: root.local_root.clone(),
                worker_cache_path: root.worker_cache_path.clone(),
            });
        } else {
            refused.push(RefusedInvalidation {
                local_root: root.local_root.clone(),
                worker_cache_path: root.worker_cache_path.clone(),
                reason:
                    "target is not strictly inside the RCH-managed base; refusing to invalidate"
                        .to_string(),
            });
        }
    }
    ForceResyncPlan {
        managed_base: managed_base.to_path_buf(),
        invalidations,
        refused,
    }
}

/// Outcome of applying a force-resync plan.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ResyncOutcome {
    /// Invalidations were applied and a closure resync should follow.
    Applied,
    /// The worker was unreachable — deferred with NO destructive action.
    DeferredWorkerUnavailable,
}

/// The agent-facing report of a force-resync.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ForceResyncReport {
    pub outcome: ResyncOutcome,
    /// Local roots that were stale (named so the agent sees the original cause).
    pub previously_stale_roots: Vec<PathBuf>,
    /// Worker cache paths that were invalidated (empty when deferred).
    pub invalidated: Vec<PathBuf>,
    /// Roots refused on safety grounds.
    pub refused: Vec<RefusedInvalidation>,
    pub detail: String,
}

impl ForceResyncReport {
    /// Whether anything was actually invalidated.
    #[must_use]
    pub fn did_invalidate(&self) -> bool {
        !self.invalidated.is_empty()
    }

    /// Human-readable explanation of what changed.
    #[must_use]
    pub fn render(&self) -> String {
        let mut s = format!(
            "force-resync: {:?} — {} stale root(s), {} invalidated, {} refused\n  {}",
            self.outcome,
            self.previously_stale_roots.len(),
            self.invalidated.len(),
            self.refused.len(),
            self.detail,
        );
        for r in &self.previously_stale_roots {
            s.push_str(&format!("\n  stale: {}", r.display()));
        }
        for r in &self.refused {
            s.push_str(&format!(
                "\n  REFUSED: {} ({})",
                r.worker_cache_path.display(),
                r.reason
            ));
        }
        s
    }
}

/// Apply a plan, gated on worker reachability. When the worker is unreachable
/// the resync is deferred and NO invalidation is reported (no destructive
/// action is taken). The actual `rm` + resync transfer is performed by the
/// caller using `report.invalidated`; this models the safe decision + report.
#[must_use]
pub fn apply_force_resync(plan: &ForceResyncPlan, worker_reachable: bool) -> ForceResyncReport {
    let previously_stale_roots: Vec<PathBuf> = plan
        .invalidations
        .iter()
        .map(|a| a.local_root.clone())
        .chain(plan.refused.iter().map(|r| r.local_root.clone()))
        .collect();

    if !worker_reachable {
        return ForceResyncReport {
            outcome: ResyncOutcome::DeferredWorkerUnavailable,
            previously_stale_roots,
            invalidated: Vec::new(),
            refused: plan.refused.clone(),
            detail: "worker unavailable; force-resync deferred (no destructive action taken)"
                .to_string(),
        };
    }

    let invalidated: Vec<PathBuf> = plan
        .invalidations
        .iter()
        .map(|a| a.worker_cache_path.clone())
        .collect();
    let detail = format!(
        "invalidated {} RCH-managed cache path(s) under {}; closure will resync",
        invalidated.len(),
        plan.managed_base.display(),
    );
    ForceResyncReport {
        outcome: ResyncOutcome::Applied,
        previously_stale_roots,
        invalidated,
        refused: plan.refused.clone(),
        detail,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn stale(local: &str, cache: &str) -> StaleRoot {
        StaleRoot {
            local_root: PathBuf::from(local),
            worker_cache_path: PathBuf::from(cache),
        }
    }

    const BASE: &str = "/data/tmp/rch-sync";

    #[test]
    fn safe_target_must_be_strictly_inside_base() {
        let base = Path::new(BASE);
        assert!(is_safe_invalidation_target(
            Path::new("/data/tmp/rch-sync/proj-a"),
            base
        ));
        // The base itself is never a target (would wipe everything).
        assert!(!is_safe_invalidation_target(base, base));
        // Outside the base.
        assert!(!is_safe_invalidation_target(
            Path::new("/home/user/project"),
            base
        ));
        // Traversal escape.
        assert!(!is_safe_invalidation_target(
            Path::new("/data/tmp/rch-sync/../../etc"),
            base
        ));
    }

    #[test]
    fn plan_invalidates_managed_and_refuses_escaping() {
        let stale_roots = vec![
            stale("/data/projects/a", "/data/tmp/rch-sync/proj-a"),
            stale("/data/projects/b", "/home/user/b"), // escapes the managed base
            stale("/data/projects/c", BASE),           // == base, must refuse
        ];
        let plan = plan_force_resync(&stale_roots, Path::new(BASE));
        assert_eq!(plan.invalidations.len(), 1);
        assert_eq!(
            plan.invalidations[0].local_root,
            PathBuf::from("/data/projects/a")
        );
        assert_eq!(plan.refused.len(), 2);
        assert!(plan.has_refusals());
    }

    #[test]
    fn forced_resync_after_stale_applies_and_names_root() {
        // Forced resync after a root went stale: it is invalidated and the
        // report names the previously-stale local root.
        let plan = plan_force_resync(
            &[stale("/data/projects/a", "/data/tmp/rch-sync/proj-a")],
            Path::new(BASE),
        );
        let report = apply_force_resync(&plan, true);
        assert_eq!(report.outcome, ResyncOutcome::Applied);
        assert!(report.did_invalidate());
        assert_eq!(
            report.invalidated,
            vec![PathBuf::from("/data/tmp/rch-sync/proj-a")]
        );
        assert!(
            report
                .previously_stale_roots
                .contains(&PathBuf::from("/data/projects/a"))
        );
        assert!(report.render().contains("/data/projects/a"));
    }

    #[test]
    fn force_resync_with_unavailable_worker_defers_safely() {
        let plan = plan_force_resync(
            &[stale("/data/projects/a", "/data/tmp/rch-sync/proj-a")],
            Path::new(BASE),
        );
        let report = apply_force_resync(&plan, false);
        assert_eq!(report.outcome, ResyncOutcome::DeferredWorkerUnavailable);
        assert!(
            !report.did_invalidate(),
            "deferred must not invalidate anything"
        );
        assert!(report.invalidated.is_empty());
        // The previously-stale root is still named for the agent.
        assert!(
            report
                .previously_stale_roots
                .contains(&PathBuf::from("/data/projects/a"))
        );
        assert!(report.detail.contains("no destructive action"));
    }

    #[test]
    fn refused_roots_are_surfaced_in_report() {
        let plan = plan_force_resync(&[stale("/data/projects/b", "/etc/passwd")], Path::new(BASE));
        let report = apply_force_resync(&plan, true);
        assert_eq!(report.refused.len(), 1);
        assert!(report.render().contains("REFUSED"));
        // Even applied, nothing outside the managed base was invalidated.
        assert!(report.invalidated.is_empty());
    }

    #[test]
    fn report_serde_roundtrip() {
        let plan = plan_force_resync(
            &[stale("/data/projects/a", "/data/tmp/rch-sync/proj-a")],
            Path::new(BASE),
        );
        let report = apply_force_resync(&plan, true);
        let back: ForceResyncReport =
            serde_json::from_str(&serde_json::to_string(&report).unwrap()).unwrap();
        assert_eq!(report, back);
    }
}
