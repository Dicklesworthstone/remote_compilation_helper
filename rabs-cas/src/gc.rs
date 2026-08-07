//! Dry-run and active-safe garbage collection (bead H014; plan §62/§63;
//! risks R26/R58).
//!
//! GC never guesses: it plans from ONE consistent metadata snapshot
//! (H010's `gc_snapshot` — pinned roots + reachability closure + located
//! objects, taken in a single store transaction) and refuses to touch:
//!
//! - pinned or pin-reachable objects (valid pins are law);
//! - anything an ACTIVE build, materialization, transfer, or open reader
//!   is using (live protections supplied by the runtime);
//! - authoritative evidence classes — publication roots and quarantine
//!   incident evidence — which even DISK-PRESSURE EMERGENCY mode never
//!   blindly deletes;
//! - provisional/staging objects before reconciliation has run (they may
//!   be the only copy of an unreconciled truth).
//!
//! Eviction among the remaining candidates follows the policy layers:
//! provisional/staging first (post-reconciliation), then committed
//! results by LRU value, then hot dependencies, then toolchains — and
//! within a layer, least-recently-used first. The plan is truncated by a
//! reclaim budget so a GC run stops before it competes with foreground
//! IO.
//!
//! Dry-run parity is the acceptance bar: `plan_gc` is PURE (same snapshot
//! → same plan), `execute_gc` reclaims exactly the planned locations and
//! records a planned-vs-actual receipt; a skip at execution time (row
//! vanished, protection appeared) is COUNTED, never papered over. The
//! mark → tombstone → grace → unlink pipeline over these plans is bead
//! H022.

use std::collections::BTreeMap;
use std::collections::BTreeSet;

use crate::metadata_store::{GcReceiptRow, RabsMetadataStore, StoreError};

/// GC run mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GcMode {
    /// Ordinary background reclaim.
    Normal,
    /// Disk-pressure emergency: widens eviction to hot dependencies and
    /// toolchains, but NEVER touches authoritative evidence.
    Emergency,
}

impl GcMode {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Normal => "normal",
            Self::Emergency => "emergency",
        }
    }
}

/// Policy class of an object (the retention layers of plan §62).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum PolicyClass {
    /// Provisional/staging state: aggressive eviction, but ONLY after
    /// reconciliation has confirmed it is not the sole copy of truth.
    ProvisionalStaging,
    /// Committed results: evicted by LRU/value.
    CommittedResult,
    /// Hot dependencies: longer retention; evicted only under emergency.
    HotDependency,
    /// Toolchains/sysroots: longest ordinary retention; emergency only.
    Toolchain,
    /// Authoritative evidence (publication roots, incident/quarantine
    /// evidence): NEVER evicted by GC, in any mode.
    AuthoritativeEvidence,
}

/// Why a location is not in the reclaim plan.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProtectionReason {
    /// Object is a pin root or pin-reachable.
    PinnedOrReachable,
    /// An active build holds it.
    ActiveBuild,
    /// An active materialization holds it.
    Materialization,
    /// An active transfer holds it.
    Transfer,
    /// An open reader holds it.
    OpenReader,
    /// Authoritative evidence class.
    AuthoritativeEvidence,
    /// Provisional state not yet reconciled.
    AwaitingReconciliation,
    /// Class retained in this mode (hot dep/toolchain outside emergency).
    RetainedByPolicy,
    /// Plan budget exhausted before this candidate.
    BudgetTruncated,
}

/// Live protections supplied by the runtime at plan time. Everything is
/// digest KEYS (`domain:hex`), matching snapshot output.
#[derive(Debug, Clone, Default)]
pub struct ActiveProtections {
    /// Objects held by active builds.
    pub active_builds: BTreeSet<String>,
    /// Objects held by in-flight materializations.
    pub materializations: BTreeSet<String>,
    /// Objects held by in-flight transfers.
    pub transfers: BTreeSet<String>,
    /// Objects held by open readers.
    pub open_readers: BTreeSet<String>,
}

/// Per-object policy input: class + last-use sequence (LRU value).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ObjectPolicy {
    /// Retention class.
    pub class: PolicyClass,
    /// Last-use logical sequence (lower = colder = evicted first).
    pub last_use_seq: u64,
}

/// The GC world: everything a plan needs beyond the store snapshot.
#[derive(Debug, Clone, Default)]
pub struct GcWorld {
    /// Live protections.
    pub protections: ActiveProtections,
    /// Policy per object key; unlisted objects default to
    /// `CommittedResult` at `last_use_seq = 0` (coldest).
    pub policies: BTreeMap<String, ObjectPolicy>,
    /// Whether reconciliation has run since the provisional state was
    /// written (gates aggressive provisional eviction).
    pub reconciliation_complete: bool,
    /// Maximum locations one run may reclaim (stops before foreground IO
    /// collapse).
    pub reclaim_budget: usize,
}

/// One plannable location (object key + store path).
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct LocationRef {
    /// Object digest key.
    pub object_key: String,
    /// Store path of this copy.
    pub store_path: String,
}

/// The dry-run product: exactly what `execute_gc` will do.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GcPlan {
    /// Run mode.
    pub mode: GcMode,
    /// Locations to reclaim, in eviction order.
    pub reclaim: Vec<LocationRef>,
    /// Locations examined and protected, with the reason.
    pub protected: Vec<(LocationRef, ProtectionReason)>,
    /// Whether the reclaim budget truncated the plan.
    pub truncated: bool,
    /// Snapshot sequence the plan was computed from.
    pub seq: u64,
}

/// Execution receipt: planned vs actual, never conflated.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GcExecutionReceipt {
    /// The plan that was executed.
    pub planned: usize,
    /// Locations actually reclaimed.
    pub reclaimed: Vec<LocationRef>,
    /// Planned locations that could not be reclaimed (already gone).
    pub skipped: Vec<LocationRef>,
}

fn default_policy() -> ObjectPolicy {
    ObjectPolicy {
        class: PolicyClass::CommittedResult,
        last_use_seq: 0,
    }
}

const fn eviction_layer(class: PolicyClass) -> u8 {
    match class {
        PolicyClass::ProvisionalStaging => 0,
        PolicyClass::CommittedResult => 1,
        PolicyClass::HotDependency => 2,
        PolicyClass::Toolchain => 3,
        // Unreachable in a plan; ordered last for completeness.
        PolicyClass::AuthoritativeEvidence => 4,
    }
}

/// The single protection judgment shared by plan-time evaluation and the
/// H022 pre-unlink RECHECK — one implementation, so the two can never
/// drift apart.
fn protection_for(
    preserved: &BTreeSet<String>,
    world: &GcWorld,
    mode: GcMode,
    object_key: &str,
    policy: ObjectPolicy,
) -> Option<ProtectionReason> {
    if preserved.contains(object_key) {
        Some(ProtectionReason::PinnedOrReachable)
    } else if world.protections.active_builds.contains(object_key) {
        Some(ProtectionReason::ActiveBuild)
    } else if world.protections.materializations.contains(object_key) {
        Some(ProtectionReason::Materialization)
    } else if world.protections.transfers.contains(object_key) {
        Some(ProtectionReason::Transfer)
    } else if world.protections.open_readers.contains(object_key) {
        Some(ProtectionReason::OpenReader)
    } else {
        match policy.class {
            // NEVER deleted, no mode exempts it.
            PolicyClass::AuthoritativeEvidence => Some(ProtectionReason::AuthoritativeEvidence),
            PolicyClass::ProvisionalStaging if !world.reconciliation_complete => {
                Some(ProtectionReason::AwaitingReconciliation)
            }
            PolicyClass::HotDependency | PolicyClass::Toolchain if mode == GcMode::Normal => {
                Some(ProtectionReason::RetainedByPolicy)
            }
            _ => None,
        }
    }
}

fn preserved_set(snapshot: &crate::metadata_store::GcSnapshot) -> BTreeSet<String> {
    snapshot
        .pinned_roots
        .iter()
        .chain(snapshot.reachable_from_pins.iter())
        .cloned()
        .collect()
}

/// Compute a GC plan from one consistent store snapshot. PURE given the
/// snapshot: calling it twice on an unchanged store yields the identical
/// plan (the dry-run parity guarantee).
///
/// # Errors
/// Store errors from taking the snapshot or the reconciliation scan.
pub fn plan_gc(
    store: &mut dyn RabsMetadataStore,
    world: &GcWorld,
    mode: GcMode,
    seq: u64,
) -> Result<GcPlan, StoreError> {
    let snapshot = store.gc_snapshot(seq)?;
    let scan = store.reconciliation_scan()?;
    let preserved = preserved_set(&snapshot);

    let mut candidates: Vec<(LocationRef, ObjectPolicy)> = Vec::new();
    let mut protected: Vec<(LocationRef, ProtectionReason)> = Vec::new();
    for row in scan {
        let location = LocationRef {
            object_key: row.object_key.clone(),
            store_path: row.store_path,
        };
        let policy = world
            .policies
            .get(&row.object_key)
            .copied()
            .unwrap_or_else(default_policy);
        match protection_for(&preserved, world, mode, &row.object_key, policy) {
            Some(reason) => protected.push((location, reason)),
            None => candidates.push((location, policy)),
        }
    }

    // Eviction order: most-aggressive layer first, coldest first, then
    // the location itself for full determinism.
    candidates.sort_by(|(a_loc, a_pol), (b_loc, b_pol)| {
        (eviction_layer(a_pol.class), a_pol.last_use_seq, a_loc).cmp(&(
            eviction_layer(b_pol.class),
            b_pol.last_use_seq,
            b_loc,
        ))
    });

    let truncated = candidates.len() > world.reclaim_budget;
    let mut reclaim = Vec::with_capacity(candidates.len().min(world.reclaim_budget));
    for (i, (location, _)) in candidates.into_iter().enumerate() {
        if i < world.reclaim_budget {
            reclaim.push(location);
        } else {
            protected.push((location, ProtectionReason::BudgetTruncated));
        }
    }
    Ok(GcPlan {
        mode,
        reclaim,
        protected,
        truncated,
        seq,
    })
}

/// Execute a plan: reclaim exactly the planned locations and record the
/// planned-vs-actual receipt. A planned row that no longer exists is a
/// SKIP in the receipt, never a silent success.
///
/// # Errors
/// Store errors; the receipt row is recorded even when some reclaims
/// skipped.
pub fn execute_gc(
    store: &mut dyn RabsMetadataStore,
    plan: &GcPlan,
) -> Result<GcExecutionReceipt, StoreError> {
    let mut reclaimed = Vec::new();
    let mut skipped = Vec::new();
    for location in &plan.reclaim {
        if store.remove_location_by_key(&location.object_key, &location.store_path)? {
            reclaimed.push(location.clone());
        } else {
            skipped.push(location.clone());
        }
    }
    store.record_gc_receipt(&GcReceiptRow {
        seq: plan.seq,
        mode: plan.mode.as_str().to_owned(),
        planned: plan.reclaim.len() as u64,
        reclaimed: reclaimed.len() as u64,
        skipped: skipped.len() as u64,
        truncated: plan.truncated,
    })?;
    Ok(GcExecutionReceipt {
        planned: plan.reclaim.len(),
        reclaimed,
        skipped,
    })
}

/// One unlink pass's outcome (H022): what was unlinked after the final
/// recheck, and what the recheck RESCUED.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnlinkReceipt {
    /// Tombstoned locations whose grace elapsed and whose final recheck
    /// confirmed no protection: unlinked.
    pub unlinked: Vec<LocationRef>,
    /// Tombstoned locations the final recheck found protected again (a
    /// reader, pin, or edge appeared during grace): tombstone cancelled,
    /// location kept.
    pub rescued: Vec<(LocationRef, ProtectionReason)>,
}

/// H022 phase 1 — MARK: tombstone every planned location. Nothing is
/// deleted here; the tombstone only starts the grace clock
/// (`plan.seq + grace_windows`). Re-marking is idempotent and keeps the
/// original deadline.
///
/// # Errors
/// Store errors from tombstone insertion.
pub fn mark_plan(
    store: &mut dyn RabsMetadataStore,
    plan: &GcPlan,
    grace_windows: u64,
) -> Result<usize, StoreError> {
    for location in &plan.reclaim {
        store.add_gc_tombstone(
            &location.object_key,
            &location.store_path,
            plan.seq,
            plan.seq.saturating_add(grace_windows),
        )?;
    }
    Ok(plan.reclaim.len())
}

/// H022 phases 2–4 — GRACE, RECHECK, UNLINK: take the tombstones whose
/// grace window has elapsed at `now_seq`, re-evaluate protection against
/// a FRESH snapshot and the CURRENT live protections, and only then
/// unlink. The recheck defeats the race where a new read,
/// materialization, pin, or reachability edge appeared between mark and
/// unlink: such a location is rescued (tombstone cancelled), never
/// deleted.
///
/// # Errors
/// Store errors; rescues and unlinks already performed stand.
pub fn unlink_due(
    store: &mut dyn RabsMetadataStore,
    world: &GcWorld,
    mode: GcMode,
    now_seq: u64,
) -> Result<UnlinkReceipt, StoreError> {
    let due = store.due_gc_tombstones(now_seq)?;
    let mut unlinked = Vec::new();
    let mut rescued = Vec::new();
    if due.is_empty() {
        return Ok(UnlinkReceipt { unlinked, rescued });
    }
    // The FINAL recheck runs on a fresh consistent snapshot, not the one
    // the plan was computed from.
    let snapshot = store.gc_snapshot(now_seq)?;
    let preserved = preserved_set(&snapshot);
    for tombstone in due {
        let location = LocationRef {
            object_key: tombstone.object_key.clone(),
            store_path: tombstone.store_path.clone(),
        };
        let policy = world
            .policies
            .get(&tombstone.object_key)
            .copied()
            .unwrap_or_else(default_policy);
        match protection_for(&preserved, world, mode, &tombstone.object_key, policy) {
            Some(reason) => {
                store.remove_gc_tombstone(&tombstone.object_key, &tombstone.store_path)?;
                rescued.push((location, reason));
            }
            None => {
                store.remove_location_by_key(&tombstone.object_key, &tombstone.store_path)?;
                store.remove_gc_tombstone(&tombstone.object_key, &tombstone.store_path)?;
                unlinked.push(location);
            }
        }
    }
    Ok(UnlinkReceipt { unlinked, rescued })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::metadata_store::{
        FsqliteEngine, RabsMetadataStore, RusqliteEngine, SqlMetadataStore, digest_key,
    };
    use rabs_protocol::result_identity::{DigestAlgorithm, TypedDigest};
    use std::sync::atomic::{AtomicU64, Ordering};

    static DB_COUNTER: AtomicU64 = AtomicU64::new(0);

    fn fresh_path(tag: &str) -> std::path::PathBuf {
        let n = DB_COUNTER.fetch_add(1, Ordering::SeqCst);
        std::env::temp_dir().join(format!("rabs-h014-{}-{}-{}.db", std::process::id(), tag, n))
    }

    fn digest(tag: u8) -> TypedDigest {
        TypedDigest {
            algorithm: DigestAlgorithm::Sha256V1,
            domain: "rabs.object.sha256.v1",
            bytes: [tag; 32],
        }
    }

    fn key(tag: u8) -> String {
        digest_key(&digest(tag))
    }

    /// World: pinned root 1 → reachable 2; active-build 3; open-reader 4;
    /// authoritative evidence 5; unreconciled provisional 6; reconciled
    /// provisional 7; cold committed 8; warm committed 9; hot dep 10;
    /// toolchain 11.
    fn install_world(store: &mut dyn RabsMetadataStore) {
        for tag in 1..=11u8 {
            store.record_object(&digest(tag), 64).unwrap();
            store
                .add_location(&digest(tag), &format!("/cas/{tag}"), Some(1), "raw")
                .unwrap();
        }
        store
            .create_pin(
                1,
                &digest(1),
                "coordinator",
                "action-publication",
                None,
                None,
                true,
                "publication root",
            )
            .unwrap();
        store
            .add_object_edge(&digest(1), &digest(2), "manifest-entry")
            .unwrap();
    }

    fn world() -> GcWorld {
        let mut policies = BTreeMap::new();
        policies.insert(
            key(5),
            ObjectPolicy {
                class: PolicyClass::AuthoritativeEvidence,
                last_use_seq: 0,
            },
        );
        for tag in [6u8, 7] {
            policies.insert(
                key(tag),
                ObjectPolicy {
                    class: PolicyClass::ProvisionalStaging,
                    last_use_seq: 0,
                },
            );
        }
        policies.insert(
            key(8),
            ObjectPolicy {
                class: PolicyClass::CommittedResult,
                last_use_seq: 10,
            },
        );
        policies.insert(
            key(9),
            ObjectPolicy {
                class: PolicyClass::CommittedResult,
                last_use_seq: 50,
            },
        );
        policies.insert(
            key(10),
            ObjectPolicy {
                class: PolicyClass::HotDependency,
                last_use_seq: 5,
            },
        );
        policies.insert(
            key(11),
            ObjectPolicy {
                class: PolicyClass::Toolchain,
                last_use_seq: 5,
            },
        );
        let mut protections = ActiveProtections::default();
        protections.active_builds.insert(key(3));
        protections.open_readers.insert(key(4));
        GcWorld {
            protections,
            policies,
            reconciliation_complete: false,
            reclaim_budget: 100,
        }
    }

    fn reason_for(plan: &GcPlan, object_key: &str) -> Option<ProtectionReason> {
        plan.protected
            .iter()
            .find(|(l, _)| l.object_key == object_key)
            .map(|(_, r)| *r)
    }

    #[test]
    fn h014_protection_classes_are_never_planned() {
        let mut store = SqlMetadataStore::open(RusqliteEngine::open_in_memory().unwrap()).unwrap();
        install_world(&mut store);
        let plan = plan_gc(&mut store, &world(), GcMode::Normal, 1).unwrap();

        assert_eq!(
            reason_for(&plan, &key(1)),
            Some(ProtectionReason::PinnedOrReachable)
        );
        assert_eq!(
            reason_for(&plan, &key(2)),
            Some(ProtectionReason::PinnedOrReachable),
            "edge-reachable object is preserved"
        );
        assert_eq!(
            reason_for(&plan, &key(3)),
            Some(ProtectionReason::ActiveBuild)
        );
        assert_eq!(
            reason_for(&plan, &key(4)),
            Some(ProtectionReason::OpenReader)
        );
        assert_eq!(
            reason_for(&plan, &key(5)),
            Some(ProtectionReason::AuthoritativeEvidence)
        );
        assert_eq!(
            reason_for(&plan, &key(6)),
            Some(ProtectionReason::AwaitingReconciliation),
            "provisional state is protected until reconciliation runs"
        );
        assert_eq!(
            reason_for(&plan, &key(10)),
            Some(ProtectionReason::RetainedByPolicy)
        );
        assert_eq!(
            reason_for(&plan, &key(11)),
            Some(ProtectionReason::RetainedByPolicy)
        );
        // Normal mode, unreconciled: only the committed results evict,
        // coldest first.
        let planned: Vec<&str> = plan.reclaim.iter().map(|l| l.object_key.as_str()).collect();
        assert_eq!(planned, vec![key(8).as_str(), key(9).as_str()]);
        assert!(!plan.truncated);
    }

    #[test]
    fn h014_policy_layers_order_eviction_after_reconciliation() {
        let mut store = SqlMetadataStore::open(RusqliteEngine::open_in_memory().unwrap()).unwrap();
        install_world(&mut store);
        let mut w = world();
        w.reconciliation_complete = true;
        let plan = plan_gc(&mut store, &w, GcMode::Normal, 2).unwrap();
        // Provisional (both) evict FIRST, then committed by LRU.
        let planned: Vec<&str> = plan.reclaim.iter().map(|l| l.object_key.as_str()).collect();
        assert_eq!(
            planned,
            vec![
                key(6).as_str(),
                key(7).as_str(),
                key(8).as_str(),
                key(9).as_str()
            ]
        );
    }

    #[test]
    fn h014_emergency_widens_but_never_deletes_authoritative_evidence() {
        let mut store = SqlMetadataStore::open(RusqliteEngine::open_in_memory().unwrap()).unwrap();
        install_world(&mut store);
        let mut w = world();
        w.reconciliation_complete = true;
        let plan = plan_gc(&mut store, &w, GcMode::Emergency, 3).unwrap();
        let planned: Vec<&str> = plan.reclaim.iter().map(|l| l.object_key.as_str()).collect();
        // Hot dep + toolchain now evictable...
        assert!(planned.contains(&key(10).as_str()));
        assert!(planned.contains(&key(11).as_str()));
        // ...but authoritative evidence, pins, and live users still are not.
        assert_eq!(
            reason_for(&plan, &key(5)),
            Some(ProtectionReason::AuthoritativeEvidence)
        );
        assert_eq!(
            reason_for(&plan, &key(1)),
            Some(ProtectionReason::PinnedOrReachable)
        );
        assert_eq!(
            reason_for(&plan, &key(3)),
            Some(ProtectionReason::ActiveBuild)
        );
    }

    #[test]
    fn h014_budget_truncates_and_is_reported() {
        let mut store = SqlMetadataStore::open(RusqliteEngine::open_in_memory().unwrap()).unwrap();
        install_world(&mut store);
        let mut w = world();
        w.reconciliation_complete = true;
        w.reclaim_budget = 1;
        let plan = plan_gc(&mut store, &w, GcMode::Normal, 4).unwrap();
        assert!(plan.truncated);
        assert_eq!(plan.reclaim.len(), 1);
        // The most aggressive candidate (coldest provisional) went first.
        assert_eq!(plan.reclaim[0].object_key, key(6));
        assert!(
            plan.protected
                .iter()
                .any(|(_, r)| *r == ProtectionReason::BudgetTruncated)
        );
    }

    #[test]
    fn h014_dry_run_parity_with_actual_execution() {
        let mut store = SqlMetadataStore::open(RusqliteEngine::open_in_memory().unwrap()).unwrap();
        install_world(&mut store);
        let mut w = world();
        w.reconciliation_complete = true;

        // Dry run twice: identical plans (purity over an unchanged store,
        // modulo the gc_runs bookkeeping row which planning records).
        let dry = plan_gc(&mut store, &w, GcMode::Normal, 5).unwrap();
        let dry_again = plan_gc(&mut store, &w, GcMode::Normal, 5).unwrap();
        assert_eq!(dry.reclaim, dry_again.reclaim);
        assert_eq!(dry.protected, dry_again.protected);

        // Execute: exactly the planned locations reclaimed, zero skips.
        let receipt = execute_gc(&mut store, &dry).unwrap();
        assert_eq!(receipt.reclaimed, dry.reclaim);
        assert!(receipt.skipped.is_empty());
        // The reclaimed copies are gone; protected ones remain.
        let remaining: Vec<String> = store
            .reconciliation_scan()
            .unwrap()
            .into_iter()
            .map(|r| r.object_key)
            .collect();
        assert!(!remaining.contains(&key(8)));
        assert!(remaining.contains(&key(5)));
        assert!(remaining.contains(&key(1)));
        // Planned-vs-actual receipt persisted.
        assert!(
            store
                .differential_snapshot()
                .unwrap()
                .iter()
                .any(|l| l.starts_with("gc_receipts|") && l.contains("normal"))
        );

        // Re-executing the same plan: everything already gone → all
        // skips, honestly counted.
        let rerun = execute_gc(&mut store, &dry).unwrap();
        assert!(rerun.reclaimed.is_empty());
        assert_eq!(rerun.skipped, dry.reclaim);
    }

    #[test]
    fn h014_differential_reference_vs_frankensqlite() {
        fn scenario(store: &mut dyn RabsMetadataStore) -> Vec<String> {
            install_world(store);
            let mut w = world();
            w.reconciliation_complete = true;
            let plan = plan_gc(store, &w, GcMode::Emergency, 9).unwrap();
            let receipt = execute_gc(store, &plan).unwrap();
            assert!(!receipt.reclaimed.is_empty());
            store.differential_snapshot().unwrap()
        }
        let mut reference =
            SqlMetadataStore::open(RusqliteEngine::open(&fresh_path("ref")).unwrap()).unwrap();
        let mut candidate =
            SqlMetadataStore::open(FsqliteEngine::open(&fresh_path("fsq")).unwrap()).unwrap();
        assert_eq!(scenario(&mut reference), scenario(&mut candidate));
    }

    #[test]
    fn h022_mark_never_deletes_and_unlink_waits_for_grace() {
        let mut store = SqlMetadataStore::open(RusqliteEngine::open_in_memory().unwrap()).unwrap();
        install_world(&mut store);
        let mut w = world();
        w.reconciliation_complete = true;
        let plan = plan_gc(&mut store, &w, GcMode::Normal, 100).unwrap();
        assert_eq!(plan.reclaim.len(), 4); // 6, 7, 8, 9

        // MARK: nothing deleted.
        assert_eq!(mark_plan(&mut store, &plan, 10).unwrap(), 4);
        let located: Vec<String> = store
            .reconciliation_scan()
            .unwrap()
            .into_iter()
            .map(|r| r.object_key)
            .collect();
        for tag in [6u8, 7, 8, 9] {
            assert!(located.contains(&key(tag)), "mark must not delete");
        }

        // During grace: unlink is a no-op.
        let early = unlink_due(&mut store, &w, GcMode::Normal, 105).unwrap();
        assert!(early.unlinked.is_empty());
        assert!(early.rescued.is_empty());

        // Re-mark is idempotent and keeps the ORIGINAL deadline.
        assert_eq!(mark_plan(&mut store, &plan, 10_000).unwrap(), 4);
        let due = store.due_gc_tombstones(110).unwrap();
        assert_eq!(due.len(), 4, "original grace deadline survives re-mark");

        // Grace elapsed: unlink proceeds for all four.
        let receipt = unlink_due(&mut store, &w, GcMode::Normal, 110).unwrap();
        assert_eq!(receipt.unlinked.len(), 4);
        assert!(receipt.rescued.is_empty());
        let located: Vec<String> = store
            .reconciliation_scan()
            .unwrap()
            .into_iter()
            .map(|r| r.object_key)
            .collect();
        for tag in [6u8, 7, 8, 9] {
            assert!(!located.contains(&key(tag)));
        }
        // Tombstones are consumed.
        assert!(store.due_gc_tombstones(u64::MAX).unwrap().is_empty());
    }

    #[test]
    fn h022_final_recheck_rescues_the_mark_to_unlink_race() {
        let mut store = SqlMetadataStore::open(RusqliteEngine::open_in_memory().unwrap()).unwrap();
        install_world(&mut store);
        let mut w = world();
        w.reconciliation_complete = true;
        let plan = plan_gc(&mut store, &w, GcMode::Normal, 100).unwrap();
        mark_plan(&mut store, &plan, 10).unwrap();

        // THE RACE: between mark and unlink, a reader opens object 8, a
        // new pin lands on object 9, and object 6 becomes reachable from
        // the pinned root via a new edge.
        w.protections.open_readers.insert(key(8));
        store
            .create_pin(
                77,
                &digest(9),
                "reader-service",
                "materialization",
                None,
                None,
                false,
                "late pin",
            )
            .unwrap();
        store
            .add_object_edge(&digest(1), &digest(6), "late-edge")
            .unwrap();

        let receipt = unlink_due(&mut store, &w, GcMode::Normal, 110).unwrap();
        // Only object 7 is still unprotected.
        assert_eq!(
            receipt
                .unlinked
                .iter()
                .map(|l| l.object_key.as_str())
                .collect::<Vec<_>>(),
            vec![key(7).as_str()]
        );
        let rescued_reasons: BTreeMap<&str, ProtectionReason> = receipt
            .rescued
            .iter()
            .map(|(l, r)| (l.object_key.as_str(), *r))
            .collect();
        assert_eq!(
            rescued_reasons.get(key(6).as_str()),
            Some(&ProtectionReason::PinnedOrReachable)
        );
        assert_eq!(
            rescued_reasons.get(key(8).as_str()),
            Some(&ProtectionReason::OpenReader)
        );
        assert_eq!(
            rescued_reasons.get(key(9).as_str()),
            Some(&ProtectionReason::PinnedOrReachable)
        );
        // Rescued locations survive with their tombstones cancelled.
        let located: Vec<String> = store
            .reconciliation_scan()
            .unwrap()
            .into_iter()
            .map(|r| r.object_key)
            .collect();
        for tag in [6u8, 8, 9] {
            assert!(located.contains(&key(tag)), "rescued object kept its copy");
        }
        assert!(store.due_gc_tombstones(u64::MAX).unwrap().is_empty());
    }

    /// Deterministic splitmix-style generator: the property suite must
    /// reproduce exactly from a seed.
    struct Rng(u64);

    impl Rng {
        fn next(&mut self) -> u64 {
            self.0 = self.0.wrapping_add(0x9e37_79b9_7f4a_7c15);
            let mut z = self.0;
            z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
            z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
            z ^ (z >> 31)
        }

        fn below(&mut self, n: u64) -> u64 {
            self.next() % n.max(1)
        }

        fn chance(&mut self, percent: u64) -> bool {
            self.below(100) < percent
        }
    }

    /// H016 (R26): under seeded-random object graphs, pins, and
    /// interleaved concurrent operations (new objects/locations standing
    /// in for `put_if_absent` uploads, seeding edges, materialization and
    /// reader churn), the full mark → grace → recheck → unlink pipeline
    /// NEVER deletes an object that is pinned, pin-reachable, or held by
    /// a live protection at unlink time. Interleaving is simulated
    /// deterministically (single-threaded op schedule), not with OS
    /// threads.
    #[test]
    fn h016_property_gc_preserves_pinned_and_reachable_objects() {
        for seed in 0..30u64 {
            let mut rng = Rng(seed.wrapping_mul(0x1234_5678_9abc_def1) + 1);
            let mut store =
                SqlMetadataStore::open(RusqliteEngine::open_in_memory().unwrap()).unwrap();

            // Random world: objects, locations, edges (cycles allowed),
            // pins, policies.
            let object_count = 12 + rng.below(12) as u8;
            let mut next_tag = object_count;
            let mut pin_id = 1u128;
            for tag in 0..object_count {
                store.record_object(&digest(tag), 64).unwrap();
                store
                    .add_location(&digest(tag), &format!("/cas/{tag}"), Some(1), "raw")
                    .unwrap();
            }
            for _ in 0..(object_count as u64 * 2) {
                let a = rng.below(u64::from(object_count)) as u8;
                let b = rng.below(u64::from(object_count)) as u8;
                store
                    .add_object_edge(&digest(a), &digest(b), "edge")
                    .unwrap();
            }
            for tag in 0..object_count {
                if rng.chance(25) {
                    store
                        .create_pin(
                            pin_id,
                            &digest(tag),
                            "prop",
                            "root",
                            None,
                            None,
                            true,
                            "property pin",
                        )
                        .unwrap();
                    pin_id += 1;
                }
            }
            let mut w = GcWorld {
                reconciliation_complete: true,
                reclaim_budget: 1000,
                ..GcWorld::default()
            };
            for tag in 0..object_count {
                let class = match rng.below(5) {
                    0 => PolicyClass::ProvisionalStaging,
                    1 => PolicyClass::HotDependency,
                    2 => PolicyClass::Toolchain,
                    3 => PolicyClass::AuthoritativeEvidence,
                    _ => PolicyClass::CommittedResult,
                };
                w.policies.insert(
                    key(tag),
                    ObjectPolicy {
                        class,
                        last_use_seq: rng.below(100),
                    },
                );
            }

            let mut seq = 100u64;
            for _round in 0..8 {
                // Concurrent-operation churn interleaved with GC phases.
                for tag in 0..object_count {
                    if rng.chance(15) {
                        w.protections.open_readers.insert(key(tag));
                    } else if rng.chance(15) {
                        w.protections.open_readers.remove(&key(tag));
                    }
                    if rng.chance(10) {
                        w.protections.materializations.insert(key(tag));
                    } else if rng.chance(10) {
                        w.protections.materializations.remove(&key(tag));
                    }
                }
                // put_if_absent-style upload of a brand-new object +
                // seeding edge from an existing object.
                if rng.chance(60) {
                    let fresh = next_tag;
                    next_tag = next_tag.wrapping_add(1);
                    store.record_object(&digest(fresh), 64).unwrap();
                    store
                        .add_location(&digest(fresh), &format!("/cas/{fresh}"), Some(1), "raw")
                        .unwrap();
                    let from = rng.below(u64::from(object_count)) as u8;
                    store
                        .add_object_edge(&digest(from), &digest(fresh), "seeded")
                        .unwrap();
                }
                let mode = if rng.chance(30) {
                    GcMode::Emergency
                } else {
                    GcMode::Normal
                };

                let plan = plan_gc(&mut store, &w, mode, seq).unwrap();
                mark_plan(&mut store, &plan, 3).unwrap();
                // More churn DURING grace (the race the recheck defeats).
                for tag in 0..object_count {
                    if rng.chance(10) {
                        w.protections.open_readers.insert(key(tag));
                    }
                }
                if rng.chance(50) {
                    let a = rng.below(u64::from(object_count)) as u8;
                    let b = rng.below(u64::from(object_count)) as u8;
                    store
                        .add_object_edge(&digest(a), &digest(b), "late")
                        .unwrap();
                }
                seq += 5;
                let located_before: BTreeSet<String> = store
                    .reconciliation_scan()
                    .unwrap()
                    .into_iter()
                    .map(|r| r.object_key)
                    .collect();
                unlink_due(&mut store, &w, mode, seq).unwrap();

                // THE INVARIANT (R26): GC never DELETES a protected copy.
                // Every object that is pinned/pin-reachable, held by a
                // live protection, or authoritative evidence at unlink
                // time, and that HAD a location going in, still has one.
                // (An object whose only copy was legitimately collected
                // in an earlier round and only later gained a protection
                // is not GC's to resurrect.)
                let snapshot = store.gc_snapshot(seq).unwrap();
                let located_after: BTreeSet<String> = store
                    .reconciliation_scan()
                    .unwrap()
                    .into_iter()
                    .map(|r| r.object_key)
                    .collect();
                let mut must_survive: BTreeSet<String> = preserved_set(&snapshot);
                must_survive.extend(w.protections.open_readers.iter().cloned());
                must_survive.extend(w.protections.materializations.iter().cloned());
                for (object_key, policy) in &w.policies {
                    if policy.class == PolicyClass::AuthoritativeEvidence {
                        must_survive.insert(object_key.clone());
                    }
                }
                for object_key in must_survive.intersection(&located_before) {
                    assert!(
                        located_after.contains(object_key),
                        "seed {seed}: protected object {object_key} lost its location"
                    );
                }
            }
        }
    }

    #[test]
    fn h022_differential_mark_grace_unlink_reference_vs_frankensqlite() {
        fn scenario(store: &mut dyn RabsMetadataStore) -> Vec<String> {
            install_world(store);
            let mut w = world();
            w.reconciliation_complete = true;
            let plan = plan_gc(store, &w, GcMode::Normal, 100).unwrap();
            mark_plan(store, &plan, 10).unwrap();
            w.protections.open_readers.insert(key(8));
            let receipt = unlink_due(store, &w, GcMode::Normal, 110).unwrap();
            assert_eq!(receipt.rescued.len(), 1);
            store.differential_snapshot().unwrap()
        }
        let mut reference =
            SqlMetadataStore::open(RusqliteEngine::open(&fresh_path("ref22")).unwrap()).unwrap();
        let mut candidate =
            SqlMetadataStore::open(FsqliteEngine::open(&fresh_path("fsq22")).unwrap()).unwrap();
        assert_eq!(scenario(&mut reference), scenario(&mut candidate));
    }
}
