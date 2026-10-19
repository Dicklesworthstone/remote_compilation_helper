//! `rch rabs gc` — operator surface over the H014 CAS garbage-collection
//! engine ([`rabs_cas::gc`]).
//!
//! Three subcommands, one bounded receipt each:
//!
//! - `plan` — dry-run receipt: what would be reclaimed and why, per
//!   retention layer, plus every protected location under a stable
//!   `STORAGE_*` reason code. Nothing is mutated.
//! - `run` — computes a fresh plan and executes it through
//!   [`rabs_cas::gc::execute_gc`] with active-build protection supplied by
//!   the operator (`--protect`, repeatable); the engine persists the
//!   planned-vs-actual `gc_receipts` row itself.
//! - `history` — prior runs from the store's persisted receipts with
//!   planned-vs-actual deltas.
//!
//! This command never invents GC policy: eviction ordering, pin
//! reachability, protection rules, and receipt persistence belong to the
//! engine. The CLI classifies, bounds, and renders.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use clap::Subcommand;
use rabs_cas::gc::{
    self, ActiveProtections, GcMode, GcWorld, ObjectPolicy, PolicyClass, ProtectionReason,
};
use rabs_cas::metadata_store::{
    RabsMetadataStore, RusqliteEngine, SqlMetadataStore, SqlValue, StoreError,
};
use serde::Serialize;

use crate::ui::context::OutputContext;
use rch_common::ApiResponse;

/// Default cap on listed locations per receipt section (output stays
/// bounded regardless of store size).
pub const DEFAULT_MAX_LISTED: usize = 200;
/// Default reclaim budget handed to the engine.
pub const DEFAULT_RECLAIM_BUDGET: usize = 256;
/// Default and maximum number of history rows rendered.
pub const DEFAULT_HISTORY_LIMIT: usize = 50;
pub const MAX_HISTORY_LIMIT: usize = 1_000;

// Stable reason codes (R005). These spell out WHY a location is or is not
// in the reclaim plan; consumers may match on the exact strings.
pub const RC_PINNED_OR_REACHABLE: &str = "STORAGE_GC_PROTECTED_PINNED_OR_REACHABLE";
pub const RC_ACTIVE_BUILD: &str = "STORAGE_GC_PROTECTED_ACTIVE_BUILD";
pub const RC_MATERIALIZATION: &str = "STORAGE_GC_PROTECTED_MATERIALIZATION";
pub const RC_TRANSFER: &str = "STORAGE_GC_PROTECTED_TRANSFER";
pub const RC_OPEN_READER: &str = "STORAGE_GC_PROTECTED_OPEN_READER";
pub const RC_AUTHORITATIVE_EVIDENCE: &str = "STORAGE_GC_PROTECTED_AUTHORITATIVE_EVIDENCE";
pub const RC_AWAITING_RECONCILIATION: &str = "STORAGE_GC_PROTECTED_AWAITING_RECONCILIATION";
pub const RC_RETAINED_BY_POLICY: &str = "STORAGE_GC_RETAINED_BY_POLICY";
pub const RC_BUDGET_TRUNCATED: &str = "STORAGE_GC_BUDGET_TRUNCATED";
pub const RC_QUARANTINE_RECLAIM_CANDIDATE: &str = "QUARANTINE_GC_RECLAIM_CANDIDATE";
pub const RC_CAS_ROOT_MISSING: &str = "STORAGE_GC_CAS_ROOT_MISSING";

/// The stable reason code for one engine protection verdict.
#[must_use]
pub const fn reason_code_for(reason: ProtectionReason) -> &'static str {
    match reason {
        ProtectionReason::PinnedOrReachable => RC_PINNED_OR_REACHABLE,
        ProtectionReason::ActiveBuild => RC_ACTIVE_BUILD,
        ProtectionReason::Materialization => RC_MATERIALIZATION,
        ProtectionReason::Transfer => RC_TRANSFER,
        ProtectionReason::OpenReader => RC_OPEN_READER,
        ProtectionReason::AuthoritativeEvidence => RC_AUTHORITATIVE_EVIDENCE,
        ProtectionReason::AwaitingReconciliation => RC_AWAITING_RECONCILIATION,
        ProtectionReason::RetainedByPolicy => RC_RETAINED_BY_POLICY,
        ProtectionReason::BudgetTruncated => RC_BUDGET_TRUNCATED,
    }
}

/// Retention-layer name for one policy class (stable wire spelling).
#[must_use]
pub const fn layer_name(class: PolicyClass) -> &'static str {
    match class {
        PolicyClass::ProvisionalStaging => "provisional-staging",
        PolicyClass::CommittedResult => "committed-result",
        PolicyClass::HotDependency => "hot-dependency",
        PolicyClass::Toolchain => "toolchain",
        PolicyClass::AuthoritativeEvidence => "authoritative-evidence",
    }
}

/// One store location.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct LocationDto {
    /// Object digest key (`domain:hex`).
    pub object_key: String,
    /// Recorded store path of this copy.
    pub store_path: String,
}

/// One protected location plus its stable reason code.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ProtectedDto {
    /// Object digest key.
    pub object_key: String,
    /// Store path of this copy.
    pub store_path: String,
    /// Stable `STORAGE_*` reason code.
    pub reason_code: &'static str,
}

/// Count of locations sharing one reason code.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ReasonCount {
    /// Stable `STORAGE_*`/`QUARANTINE_*` reason code.
    pub reason_code: &'static str,
    /// Locations carrying it.
    pub count: u64,
}

/// Per-retention-layer reclaim/protected totals.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct LayerCount {
    /// Layer name (stable wire spelling).
    pub layer: &'static str,
    /// Locations in the reclaim plan from this layer.
    pub reclaim: u64,
    /// Locations protected in this layer.
    pub protected_locations: u64,
}

/// Dry-run receipt for `rch rabs gc plan`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct GcPlanReceipt {
    /// Receipt schema tag.
    pub schema: &'static str,
    /// Run mode (`normal`/`emergency`).
    pub mode: &'static str,
    /// Snapshot sequence the plan was computed from.
    pub seq: u64,
    /// Reclaim budget in effect.
    pub budget: usize,
    /// Whether the budget truncated the plan.
    pub truncated: bool,
    /// Total reclaimable locations.
    pub reclaim_total: u64,
    /// Reclaimable locations actually listed (bounded).
    pub reclaim: Vec<LocationDto>,
    /// Whether `reclaim` was truncated by `max_listed`.
    pub reclaim_truncated: bool,
    /// Total protected locations.
    pub protected_total: u64,
    /// Protected locations actually listed (bounded).
    pub protected: Vec<ProtectedDto>,
    /// Whether `protected` was truncated by `max_listed`.
    pub protected_truncated: bool,
    /// Counts per reason code (sorted by code).
    pub reason_counts: Vec<ReasonCount>,
    /// Per-layer reclaim/protected totals.
    pub layers: Vec<LayerCount>,
    /// Planned reclaims whose copy is currently quarantined
    /// ([`RC_QUARANTINE_RECLAIM_CANDIDATE`]); informational only.
    pub quarantine_reclaim_candidates: u64,
}

/// Execution receipt for `rch rabs gc run`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct GcRunReceipt {
    /// Receipt schema tag.
    pub schema: &'static str,
    /// Run mode (`normal`/`emergency`).
    pub mode: &'static str,
    /// Snapshot sequence the executed plan was computed from.
    pub seq: u64,
    /// Locations the plan intended to reclaim.
    pub planned: u64,
    /// Locations actually reclaimed.
    pub reclaimed: Vec<LocationDto>,
    /// Planned locations already gone when executed (skipped, never silent).
    pub skipped: Vec<LocationDto>,
    /// Whether the underlying plan was budget-truncated.
    pub truncated: bool,
    /// Quarantined copies among the reclaimed ([`RC_QUARANTINE_RECLAIM_CANDIDATE`]).
    pub quarantine_reclaimed: u64,
}

/// One persisted prior run.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct GcHistoryEntry {
    /// Logical sequence of the run.
    pub seq: u64,
    /// Run mode (`normal`/`emergency`).
    pub mode: String,
    /// Locations the run planned to reclaim.
    pub planned: u64,
    /// Locations actually reclaimed.
    pub reclaimed: u64,
    /// Planned locations skipped (already gone).
    pub skipped: u64,
    /// Whether the run was budget-truncated.
    pub truncated: bool,
    /// `planned - reclaimed - skipped`; nonzero means the receipt is
    /// internally inconsistent (a bug worth surfacing, never papering over).
    pub unaccounted: i64,
}

/// History receipt for `rch rabs gc history`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct GcHistoryReceipt {
    /// Receipt schema tag.
    pub schema: &'static str,
    /// Entries, newest first.
    pub entries: Vec<GcHistoryEntry>,
    /// Number of entries returned (after bounding).
    pub count: u64,
}

const PLAN_SCHEMA: &str = "rch.rabs-gc-plan.v1";
const RUN_SCHEMA: &str = "rch.rabs-gc-run.v1";
const HISTORY_SCHEMA: &str = "rch.rabs-gc-history.v1";

/// Next monotonic run sequence: one past the highest persisted receipt.
///
/// # Errors
/// Store errors from the aggregate query.
pub fn next_seq(store: &mut dyn RabsMetadataStore) -> Result<u64, StoreError> {
    let rows = store.query("SELECT COALESCE(MAX(seq), 0) FROM gc_receipts", &[])?;
    let last = match rows.first().and_then(|r| r.first()) {
        // MAX over persisted u64 counts is non-negative by construction;
        // a negative value would be store corruption, clamped to restart.
        Some(SqlValue::Int(n)) => u64::try_from((*n).max(0)).unwrap_or(0),
        _ => 0,
    };
    // The NEXT sequence is one past the last persisted receipt: a fresh
    // store starts at 1, and every executed run advances by exactly one.
    // Returning the max itself made the first plan seq 0 and pinned every
    // later run to the same number once a receipt was recorded.
    Ok(last.saturating_add(1))
}

/// Build the engine [`GcWorld`] from operator input. Protections enter as
/// ACTIVE BUILD holds (`--protect`, repeatable). Reconciliation defaults
/// to INCOMPLETE so unreconciled provisional state stays protected unless
/// the caller asserts otherwise.
#[must_use]
pub fn build_world(protected_keys: &[String], budget: usize, reconciled: bool) -> GcWorld {
    GcWorld {
        protections: ActiveProtections {
            active_builds: protected_keys.iter().cloned().collect(),
            ..ActiveProtections::default()
        },
        policies: BTreeMap::new(),
        reconciliation_complete: reconciled,
        reclaim_budget: budget.max(1),
    }
}

/// Parse `--mode`.
///
/// # Errors
/// Any value other than `normal`/`emergency` (case-insensitive).
pub fn parse_mode(mode: Option<&str>) -> anyhow::Result<GcMode> {
    match mode.map(str::to_ascii_lowercase).as_deref() {
        None | Some("normal") => Ok(GcMode::Normal),
        Some("emergency") => Ok(GcMode::Emergency),
        Some(other) => Err(anyhow::anyhow!(
            "invalid --mode '{other}' (expected normal|emergency)"
        )),
    }
}

const fn mode_str(mode: GcMode) -> &'static str {
    match mode {
        GcMode::Normal => "normal",
        GcMode::Emergency => "emergency",
    }
}

/// Resolve the CAS root: `--cas-root` > `RABS_STATE_DIR/cas` >
/// `~/.cache/rch/rabs-state/cas` (mirrors rabsd's boot layout).
///
/// # Errors
/// Only environmental oddities (unreadable HOME fallback is `/tmp`).
pub fn resolve_cas_root(flag: Option<&Path>) -> anyhow::Result<PathBuf> {
    if let Some(p) = flag {
        return Ok(p.to_path_buf());
    }
    if let Ok(state) = std::env::var("RABS_STATE_DIR") {
        return Ok(PathBuf::from(state).join("cas"));
    }
    let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".to_string());
    Ok(Path::new(&home).join(".cache/rch/rabs-state/cas"))
}

/// Open the metadata index under `cas_root`. Refuses to auto-create: an
/// operator GC command against a nonexistent store is a mistake, not a
/// fresh install.
///
/// # Errors
/// [`RC_CAS_ROOT_MISSING`] when the index file does not exist; engine and
/// store open failures otherwise.
pub fn open_store(cas_root: &Path) -> anyhow::Result<SqlMetadataStore<RusqliteEngine>> {
    let meta = cas_root.join("meta.sqlite");
    if !meta.exists() {
        anyhow::bail!(
            "{RC_CAS_ROOT_MISSING}: no RABS metadata index at {} (boot rabsd first or pass --cas-root)",
            meta.display()
        );
    }
    let engine =
        RusqliteEngine::open(&meta).map_err(|e| anyhow::anyhow!("metadata engine: {e:?}"))?;
    SqlMetadataStore::open(engine).map_err(|e| anyhow::anyhow!("metadata store: {e:?}"))
}

/// Quarantined `(object_key, store_path)` pairs, from one scan.
fn quarantined_set(
    store: &mut dyn RabsMetadataStore,
) -> Result<BTreeSet<(String, String)>, StoreError> {
    Ok(store
        .reconciliation_scan()?
        .into_iter()
        .filter(|row| row.quarantined)
        .map(|row| (row.object_key, row.store_path))
        .collect())
}

fn intersect_quarantine(
    plan_reclaim: &[rabs_cas::gc::LocationRef],
    quarantined: &BTreeSet<(String, String)>,
) -> u64 {
    plan_reclaim
        .iter()
        .filter(|loc| quarantined.contains(&(loc.object_key.clone(), loc.store_path.clone())))
        .count() as u64
}

/// Class of one object under `world` (mirrors the engine's default rule:
/// unlisted objects are cold committed results).
fn class_of(world: &GcWorld, object_key: &str) -> PolicyClass {
    world
        .policies
        .get(object_key)
        .map_or(PolicyClass::CommittedResult, |p: &ObjectPolicy| p.class)
}

/// Dry-run receipt over the H014 engine. Pure given store contents: the
/// engine guarantees identical plans on unchanged stores.
///
/// # Errors
/// Store errors from snapshot/scan queries.
pub fn plan_receipt(
    store: &mut dyn RabsMetadataStore,
    world: &GcWorld,
    mode: GcMode,
    max_listed: usize,
) -> Result<GcPlanReceipt, StoreError> {
    let seq = next_seq(store)?;
    let plan = gc::plan_gc(store, world, mode, seq)?;
    let quarantined = quarantined_set(store)?;

    // Per-location classification for LAYER summaries only; protection
    // and ordering remain entirely engine-owned.
    let mut layer_totals: BTreeMap<&'static str, (u64, u64)> = BTreeMap::new();
    for loc in &plan.reclaim {
        let entry = layer_totals
            .entry(layer_name(class_of(world, &loc.object_key)))
            .or_insert((0, 0));
        entry.0 += 1;
    }
    let mut reason_counts: BTreeMap<&'static str, u64> = BTreeMap::new();
    for (loc, reason) in &plan.protected {
        let entry = layer_totals
            .entry(layer_name(class_of(world, &loc.object_key)))
            .or_insert((0, 0));
        entry.1 += 1;
        *reason_counts.entry(reason_code_for(*reason)).or_insert(0) += 1;
    }

    let reclaim: Vec<LocationDto> = plan
        .reclaim
        .iter()
        .take(max_listed)
        .map(|l| LocationDto {
            object_key: l.object_key.clone(),
            store_path: l.store_path.clone(),
        })
        .collect();
    let protected: Vec<ProtectedDto> = plan
        .protected
        .iter()
        .take(max_listed)
        .map(|(l, r)| ProtectedDto {
            object_key: l.object_key.clone(),
            store_path: l.store_path.clone(),
            reason_code: reason_code_for(*r),
        })
        .collect();

    Ok(GcPlanReceipt {
        schema: PLAN_SCHEMA,
        mode: mode_str(mode),
        seq: plan.seq,
        budget: world.reclaim_budget,
        truncated: plan.truncated,
        reclaim_total: plan.reclaim.len() as u64,
        reclaim_truncated: plan.reclaim.len() > reclaim.len(),
        reclaim,
        protected_total: plan.protected.len() as u64,
        protected_truncated: plan.protected.len() > protected.len(),
        protected,
        reason_counts: reason_counts
            .into_iter()
            .map(|(reason_code, count)| ReasonCount { reason_code, count })
            .collect(),
        layers: layer_totals
            .into_iter()
            .map(|(layer, (reclaim, protected_locations))| LayerCount {
                layer,
                reclaim,
                protected_locations,
            })
            .collect(),
        quarantine_reclaim_candidates: intersect_quarantine(&plan.reclaim, &quarantined),
    })
}

/// Execute a freshly computed plan and return the actual reclaim receipt.
/// The engine records the persisted `gc_receipts` row.
///
/// # Errors
/// Store errors from planning, scanning, execution, or receipt recording.
pub fn run_receipt(
    store: &mut dyn RabsMetadataStore,
    world: &GcWorld,
    mode: GcMode,
    max_listed: usize,
) -> Result<GcRunReceipt, StoreError> {
    let seq = next_seq(store)?;
    let plan = gc::plan_gc(store, world, mode, seq)?;
    let quarantined = quarantined_set(store)?;
    let quarantine_reclaimed = intersect_quarantine(&plan.reclaim, &quarantined);
    let receipt = gc::execute_gc(store, &plan)?;

    let bounded = |locs: &[rabs_cas::gc::LocationRef]| {
        locs.iter()
            .take(max_listed)
            .map(|l| LocationDto {
                object_key: l.object_key.clone(),
                store_path: l.store_path.clone(),
            })
            .collect::<Vec<LocationDto>>()
    };

    Ok(GcRunReceipt {
        schema: RUN_SCHEMA,
        mode: mode_str(mode),
        seq: plan.seq,
        planned: receipt.planned as u64,
        reclaimed: bounded(&receipt.reclaimed),
        skipped: bounded(&receipt.skipped),
        truncated: plan.truncated,
        quarantine_reclaimed,
    })
}

/// Prior runs, newest first, from persisted receipts.
///
/// # Errors
/// Store errors from the history query, or a malformed receipt row (the
/// schema is stable; a shape mismatch is surfaced, not guessed around).
pub fn history_receipt(
    store: &mut dyn RabsMetadataStore,
    limit: usize,
) -> Result<GcHistoryReceipt, StoreError> {
    let rows = store.query(
        "SELECT seq, mode, planned, reclaimed, skipped, truncated \
         FROM gc_receipts ORDER BY seq DESC, id DESC",
        &[],
    )?;
    let mut entries = Vec::with_capacity(rows.len().min(limit));
    for row in rows.into_iter().take(limit) {
        let mut cols = row.into_iter();
        let Some(SqlValue::Int(seq)) = cols.next() else {
            return Err(StoreError::Backend(
                "gc_receipts.seq missing or not an integer".to_owned(),
            ));
        };
        let Some(SqlValue::Text(mode)) = cols.next() else {
            return Err(StoreError::Backend(
                "gc_receipts.mode missing or not text".to_owned(),
            ));
        };
        // A fixed-size array pattern always matches; the counters are
        // Option<SqlValue> and mapped to 0 below when absent.
        let numbers = [cols.next(), cols.next(), cols.next()];
        let [planned, reclaimed, skipped] = numbers.map(|v| match v {
            Some(SqlValue::Int(n)) => u64::try_from(n.max(0)).unwrap_or(0),
            _ => 0,
        });
        let truncated = matches!(cols.next(), Some(SqlValue::Int(1)));
        entries.push(GcHistoryEntry {
            seq: u64::try_from(seq.max(0)).unwrap_or(0),
            mode,
            planned,
            reclaimed,
            skipped,
            truncated,
            unaccounted: i64::try_from(planned).unwrap_or(i64::MAX)
                - i64::try_from(reclaimed).unwrap_or(i64::MAX)
                - i64::try_from(skipped).unwrap_or(i64::MAX),
        });
    }
    Ok(GcHistoryReceipt {
        schema: HISTORY_SCHEMA,
        count: entries.len() as u64,
        entries,
    })
}

fn print_plan(receipt: &GcPlanReceipt) {
    println!(
        "plan seq={} mode={} budget={} reclaim={} protected={} truncated={}",
        receipt.seq,
        receipt.mode,
        receipt.budget,
        receipt.reclaim_total,
        receipt.protected_total,
        receipt.truncated
    );
    print_locations("RECLAIM", &receipt.reclaim);
    if receipt.reclaim_truncated {
        println!("RECLAIM ... listing truncated at {}", receipt.reclaim.len());
    }
    for p in &receipt.protected {
        println!(
            "PROTECTED {} {} {}",
            p.reason_code, p.object_key, p.store_path
        );
    }
    if receipt.protected_truncated {
        println!(
            "PROTECTED ... listing truncated at {}",
            receipt.protected.len()
        );
    }
    for rc in &receipt.reason_counts {
        println!("REASON {} count={}", rc.reason_code, rc.count);
    }
    if receipt.quarantine_reclaim_candidates > 0 {
        println!(
            "{} count={}",
            RC_QUARANTINE_RECLAIM_CANDIDATE, receipt.quarantine_reclaim_candidates
        );
    }
}

/// One line per reclaimed-or-skipped location, prefixed by its section label.
fn print_locations(label: &str, locations: &[LocationDto]) {
    for location in locations {
        println!("{label} {} {}", location.object_key, location.store_path);
    }
}

fn print_run(receipt: &GcRunReceipt) {
    println!(
        "run seq={} mode={} planned={} reclaimed={} skipped={} truncated={}",
        receipt.seq,
        receipt.mode,
        receipt.planned,
        receipt.reclaimed.len(),
        receipt.skipped.len(),
        receipt.truncated
    );
    print_locations("RECLAIMED", &receipt.reclaimed);
    print_locations("SKIPPED", &receipt.skipped);
    if receipt.quarantine_reclaimed > 0 {
        println!(
            "{} count={}",
            RC_QUARANTINE_RECLAIM_CANDIDATE, receipt.quarantine_reclaimed
        );
    }
}

fn print_history(receipt: &GcHistoryReceipt) {
    println!("history count={}", receipt.count);
    for e in &receipt.entries {
        println!(
            "run seq={} mode={} planned={} reclaimed={} skipped={} truncated={} unaccounted={}",
            e.seq, e.mode, e.planned, e.reclaimed, e.skipped, e.truncated, e.unaccounted
        );
    }
}

/// Entry point for `rch rabs gc <action>`.
///
/// # Errors
/// Propagates store/mount/parse failures under the caller's exit-code
/// convention.
pub async fn run_gc(action: GcAction, ctx: &OutputContext) -> anyhow::Result<()> {
    run_gc_inner(action, ctx).await
}

async fn run_gc_inner(action: GcAction, ctx: &OutputContext) -> anyhow::Result<()> {
    match action {
        GcAction::Plan {
            cas_root,
            mode,
            protect,
            budget,
            reconciled,
            max_listed,
        } => {
            let parsed = parse_mode(mode.as_deref())?;
            let mut store = open_store(&resolve_cas_root(cas_root.as_deref())?)?;
            let world = build_world(
                &protect,
                budget.unwrap_or(DEFAULT_RECLAIM_BUDGET),
                reconciled,
            );
            let receipt = plan_receipt(&mut store, &world, parsed, max_listed)?;
            if ctx.is_json() || ctx.is_toon() {
                ctx.json(&ApiResponse::ok("rabs gc plan", &receipt))?;
            } else {
                print_plan(&receipt);
            }
        }
        GcAction::Run {
            cas_root,
            mode,
            protect,
            budget,
            reconciled,
            max_listed,
        } => {
            let parsed = parse_mode(mode.as_deref())?;
            let mut store = open_store(&resolve_cas_root(cas_root.as_deref())?)?;
            let world = build_world(
                &protect,
                budget.unwrap_or(DEFAULT_RECLAIM_BUDGET),
                reconciled,
            );
            let receipt = run_receipt(&mut store, &world, parsed, max_listed)?;
            if ctx.is_json() || ctx.is_toon() {
                ctx.json(&ApiResponse::ok("rabs gc run", &receipt))?;
            } else {
                print_run(&receipt);
            }
        }
        GcAction::History { cas_root, limit } => {
            let mut store = open_store(&resolve_cas_root(cas_root.as_deref())?)?;
            let receipt = history_receipt(
                &mut store,
                limit
                    .unwrap_or(DEFAULT_HISTORY_LIMIT)
                    .min(MAX_HISTORY_LIMIT),
            )?;
            if ctx.is_json() || ctx.is_toon() {
                ctx.json(&ApiResponse::ok("rabs gc history", &receipt))?;
            } else {
                print_history(&receipt);
            }
        }
    }
    Ok(())
}

/// Entry point for `rch rabs worker reconcile <worker>` (R006).
///
/// # Errors
/// Propagates store/mount failures under the caller's exit-code
/// convention.
pub async fn run_worker_reconcile(
    worker: String,
    cas_root: Option<PathBuf>,
    ctx: &OutputContext,
) -> anyhow::Result<()> {
    let root = resolve_cas_root(cas_root.as_deref())?;
    let mut store = open_store(&root)?;
    let now_seq = operations_watermark(&mut store)?;
    let fs = CasFilesystem { root };
    let report = rabs_cas::worker_reconcile::reconcile_worker(
        &mut store,
        &fs,
        &worker,
        now_seq,
        DEFAULT_MIN_SEQ_LAG,
    )?;
    if ctx.is_json() || ctx.is_toon() {
        ctx.json(&ApiResponse::ok(
            "rabs worker reconcile",
            &JsonReport::of(&report),
        ))?;
    } else {
        print_worker_report(&report);
    }
    Ok(())
}

/// Entry point for `rch rabs doctor` (R006, read-only half).
///
/// # Errors
/// Propagates store/mount failures under the caller's exit-code
/// convention.
pub async fn run_doctor(
    cas_root: Option<PathBuf>,
    min_seq_lag: u64,
    ctx: &OutputContext,
) -> anyhow::Result<()> {
    let root = resolve_cas_root(cas_root.as_deref())?;
    let mut store = open_store(&root)?;
    let now_seq = operations_watermark(&mut store)?;
    let proposals = rabs_cas::worker_reconcile::find_stale_state(&mut store, now_seq, min_seq_lag)?;
    if ctx.is_json() || ctx.is_toon() {
        let shim: Vec<JsonProposal> = proposals.iter().map(JsonProposal::of).collect();
        ctx.json(&ApiResponse::ok("rabs doctor", &shim))?;
    } else if proposals.is_empty() {
        println!("rabs doctor: no stale operations or expired-looking pins");
    } else {
        println!("rabs doctor: {} proposed resolution(s):", proposals.len());
        for p in &proposals {
            println!("  {} -> {}", p.target, p.action);
            println!("      {}", p.remediation);
        }
    }
    Ok(())
}

/// Entry point for `rch rabs inventory` (K010).
///
/// # Errors
/// Propagates store/mount failures under the caller's exit-code
/// convention.
pub async fn run_inventory(
    cas_root: Option<PathBuf>,
    l2_root: Option<PathBuf>,
    allow_namespace: Vec<String>,
    ctx: &OutputContext,
) -> anyhow::Result<()> {
    let root = resolve_cas_root(cas_root.as_deref())?;
    let mut store = open_store(&root)?;
    let l2 = l2_root.unwrap_or_else(default_l2_root);
    let policy = rabs_cas::cache_inventory::NamespacePolicy::allowing(allow_namespace.clone());
    let report = rabs_cas::cache_inventory::build_report(&mut store, None, &l2, &policy)?;

    if ctx.is_json() || ctx.is_toon() {
        ctx.json(&ApiResponse::ok(
            "rabs inventory",
            &JsonInventory::of(&report),
        ))?;
    } else {
        print_inventory(&report);
    }
    Ok(())
}

fn default_l2_root() -> PathBuf {
    if let Some(home) = std::env::var_os("HOME") {
        PathBuf::from(home).join(".cache").join("rch")
    } else {
        PathBuf::from("/tmp")
    }
}

#[derive(Debug, Serialize)]
struct JsonInventory {
    l1_present: bool,
    l1_capacity: Option<usize>,
    l1_live_entries: Option<usize>,
    restricted_project_count: u32,
    visible_projects: Vec<String>,
    toolchain_workers: Vec<String>,
    action_entries: u64,
}

impl JsonInventory {
    fn of(r: &rabs_cas::cache_inventory::CacheInventoryReport) -> Self {
        Self {
            l1_present: r.l1.is_some(),
            l1_capacity: r.l1.as_ref().map(|l| l.capacity),
            l1_live_entries: r.l1.as_ref().map(|l| l.entries.len()),
            restricted_project_count: r.restricted_project_count,
            visible_projects: r.l2_visible.iter().map(|p| p.project.clone()).collect(),
            toolchain_workers: r.toolchains.iter().map(|t| t.worker.clone()).collect(),
            action_entries: r.store.action_entries,
        }
    }
}

fn print_inventory(report: &rabs_cas::cache_inventory::CacheInventoryReport) {
    match &report.l1 {
        Some(l1) => println!(
            "L1 edge cache: capacity {}, live entries {}",
            l1.capacity,
            l1.entries.len()
        ),
        None => println!("L1 edge cache: not mounted in this process"),
    }
    for p in &report.l2_visible {
        println!("L2 project {}: {} result dir(s)", p.project, p.hash_dirs);
    }
    println!(
        "restricted projects (names hidden): {}",
        report.restricted_project_count
    );
    for t in &report.toolchains {
        println!("toolchains on {}: {}", t.worker, t.toolchains.join(", "));
    }
    println!(
        "store: {} action entries, {} workers with recorded capabilities",
        report.store.action_entries, report.store.workers_with_capabilities
    );
}

/// Operations lagging the live-progress watermark by more than this are
/// stale by default.
pub const DEFAULT_MIN_SEQ_LAG: u64 = 1_000;

fn operations_watermark<E: rabs_cas::metadata_store::SqlEngine>(
    store: &mut rabs_cas::metadata_store::SqlMetadataStore<E>,
) -> anyhow::Result<u64> {
    Ok(store.operation_update_high_water()?)
}

/// The real CAS directory, viewed through [`FilesystemReality`].
struct CasFilesystem {
    root: PathBuf,
}

impl rabs_cas::startup_reconciliation::FilesystemReality for CasFilesystem {
    fn exists(&self, store_path: &str) -> bool {
        self.root.join(store_path).exists()
    }

    fn all_paths(&self) -> Vec<String> {
        let mut out = Vec::new();
        self.walk(&self.root, &mut out, 0);
        out
    }
}

impl CasFilesystem {
    fn walk(&self, dir: &Path, out: &mut Vec<String>, depth: u8) {
        const MAX_DEPTH: u8 = 8;
        const MAX_ENTRIES: usize = 50_000;
        if depth > MAX_DEPTH || out.len() >= MAX_ENTRIES {
            return;
        }
        let Ok(entries) = std::fs::read_dir(dir) else {
            return;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                self.walk(&path, out, depth + 1);
            } else if let Ok(rel) = path.strip_prefix(&self.root) {
                out.push(rel.to_string_lossy().into_owned());
            }
            if out.len() >= MAX_ENTRIES {
                return;
            }
        }
    }
}

#[derive(Debug, Serialize)]
struct JsonProposal {
    target: String,
    action: String,
    remediation: String,
}

impl JsonProposal {
    fn of(p: &rabs_cas::worker_reconcile::ProposedResolution) -> Self {
        Self {
            target: p.target.clone(),
            action: p.action.clone(),
            remediation: p.remediation.clone(),
        }
    }
}

#[derive(Debug, Serialize)]
struct JsonReport {
    worker: String,
    sessions_ended: u32,
    repaired_count: usize,
    reported_orphans: Vec<String>,
    serving_allowed: bool,
    stale_operations: Vec<JsonProposal>,
    proposals: Vec<JsonProposal>,
}

impl JsonReport {
    fn of(r: &rabs_cas::worker_reconcile::WorkerReconcileReport) -> Self {
        Self {
            worker: r.worker.clone(),
            sessions_ended: r.sessions_ended,
            repaired_count: r.repaired.len(),
            reported_orphans: r.reported_orphans.clone(),
            serving_allowed: matches!(
                r.serving,
                rabs_cas::startup_reconciliation::ServingDecision::Allowed
            ),
            stale_operations: r
                .stale_operations
                .iter()
                .map(operation_json_proposal)
                .collect(),
            proposals: r.proposals.iter().map(JsonProposal::of).collect(),
        }
    }
}

fn operation_json_proposal(op: &rabs_cas::worker_reconcile::StaleOperation) -> JsonProposal {
    JsonProposal {
        target: format!("operation:{}", op.id_hex),
        action: format!("update_operation_state({}, \"abandoned\")", op.id_hex),
        remediation: format!("non-terminal '{}' untouched for {} seqs", op.state, op.lag),
    }
}

fn print_worker_report(report: &rabs_cas::worker_reconcile::WorkerReconcileReport) {
    println!(
        "worker reconcile {}: {} session(s) ended, {} location drift repaired, \
         {} orphan(s) reported, serving {}",
        report.worker,
        report.sessions_ended,
        report.repaired.len(),
        report.reported_orphans.len(),
        if matches!(
            report.serving,
            rabs_cas::startup_reconciliation::ServingDecision::Allowed
        ) {
            "allowed"
        } else {
            "REFUSED"
        }
    );
    if report.proposals.is_empty() {
        println!("  no stale operations or expired-looking pins");
    } else {
        println!("  proposed resolution(s): {}", report.proposals.len());
        for p in &report.proposals {
            println!("    {} -> {}", p.target, p.action);
            println!("        {}", p.remediation);
        }
    }
}

/// Schema identifier for `rch rabs release-verdict` receipts (`bd-dockb`).
const RELEASE_VERDICT_SCHEMA: &str = "rch.rabs-release-verdict.v1";

/// Serialized durable [`rabs_protocol::release_authorization::ReleaseVerdict`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct JsonReleaseVerdict {
    pub build: String,
    pub corpus: String,
    pub replayed: u64,
    pub explained: u64,
    pub evaluated_at_unix_micros: i64,
    pub maximum_age_micros: Option<u64>,
    pub clock_uncertainty_micros: u64,
    pub coordinator_clock_epoch: u64,
}

impl From<&rabs_protocol::release_authorization::ReleaseVerdict> for JsonReleaseVerdict {
    fn from(v: &rabs_protocol::release_authorization::ReleaseVerdict) -> Self {
        Self {
            build: v.build.clone(),
            corpus: v.corpus.clone(),
            replayed: v.replayed,
            explained: v.explained,
            evaluated_at_unix_micros: v.validity.evaluated_at_unix_micros,
            maximum_age_micros: v.validity.maximum_age_micros,
            clock_uncertainty_micros: v.validity.clock_uncertainty_micros,
            coordinator_clock_epoch: v.validity.coordinator_clock_epoch,
        }
    }
}

/// Receipt emitted by `rch rabs release-verdict show` and `record` (`bd-dockb`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ReleaseVerdictReceipt {
    pub schema: &'static str,
    pub cas_root: String,
    pub build: String,
    pub standing: &'static str,
    pub permits_advisory: bool,
    pub permits_required: bool,
    pub evaluated_at_unix_micros: i64,
    pub clock_epoch: u64,
    pub verdict: Option<JsonReleaseVerdict>,
}

fn current_unix_micros() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| i64::try_from(d.as_micros()).unwrap_or(i64::MAX))
}

fn build_release_verdict_receipt(
    store: &mut dyn RabsMetadataStore,
    cas_root: &Path,
    build: &str,
    now_unix_micros: i64,
    clock_epoch: u64,
) -> anyhow::Result<ReleaseVerdictReceipt> {
    use rabs_protocol::release_authorization::{ReleaseAuthorizationMode, authorization};

    let stored = store
        .release_verdict(build)
        .map_err(|e| anyhow::anyhow!("read release verdict: {e:?}"))?;
    let standing = authorization(stored.as_ref(), build, now_unix_micros, clock_epoch);
    Ok(ReleaseVerdictReceipt {
        schema: RELEASE_VERDICT_SCHEMA,
        cas_root: cas_root.display().to_string(),
        build: build.to_owned(),
        standing: standing.token(),
        permits_advisory: standing.permits_serving(ReleaseAuthorizationMode::Advisory),
        permits_required: standing.permits_serving(ReleaseAuthorizationMode::Required),
        evaluated_at_unix_micros: now_unix_micros,
        clock_epoch,
        verdict: stored.as_ref().map(JsonReleaseVerdict::from),
    })
}

fn record_and_verify_release_verdict(
    store: &mut dyn RabsMetadataStore,
    cas_root: &Path,
    verdict: &rabs_protocol::release_authorization::ReleaseVerdict,
    now_unix_micros: i64,
    clock_epoch: u64,
) -> anyhow::Result<ReleaseVerdictReceipt> {
    if verdict.build.trim().is_empty() {
        anyhow::bail!("release verdict build identity must not be empty");
    }
    if verdict.corpus.trim().is_empty() {
        anyhow::bail!("release verdict corpus identity must not be empty");
    }
    if verdict.replayed == 0 {
        anyhow::bail!(
            "release verdict requires replayed > 0 (zero replayed records can never authorize serving)"
        );
    }
    store
        .record_release_verdict(verdict)
        .map_err(|e| anyhow::anyhow!("record release verdict: {e:?}"))?;
    build_release_verdict_receipt(
        store,
        cas_root,
        &verdict.build,
        now_unix_micros,
        clock_epoch,
    )
}

fn open_or_init_store(cas_root: &Path) -> anyhow::Result<SqlMetadataStore<RusqliteEngine>> {
    std::fs::create_dir_all(cas_root)
        .map_err(|e| anyhow::anyhow!("create CAS root directory {}: {e}", cas_root.display()))?;
    let meta = cas_root.join("meta.sqlite");
    let engine =
        RusqliteEngine::open(&meta).map_err(|e| anyhow::anyhow!("metadata engine: {e:?}"))?;
    SqlMetadataStore::open(engine).map_err(|e| anyhow::anyhow!("metadata store: {e:?}"))
}

fn print_release_verdict(receipt: &ReleaseVerdictReceipt) {
    println!(
        "release verdict [{}]: build={} standing={} (advisory={}, required={})",
        receipt.cas_root,
        receipt.build,
        receipt.standing,
        if receipt.permits_advisory {
            "permitted"
        } else {
            "refused"
        },
        if receipt.permits_required {
            "permitted"
        } else {
            "refused"
        },
    );
    if let Some(v) = &receipt.verdict {
        println!(
            "  corpus={} replayed={} explained={} evaluated_at_us={} max_age_us={:?} epoch={}",
            v.corpus,
            v.replayed,
            v.explained,
            v.evaluated_at_unix_micros,
            v.maximum_age_micros,
            v.coordinator_clock_epoch,
        );
    } else {
        println!(
            "  no verdict recorded for build {} (run `rch rabs release-verdict record ...`)",
            receipt.build
        );
    }
}

/// Entry point for `rch rabs release-verdict <action>` (`bd-dockb`).
///
/// # Errors
/// Propagates store and validation failures under the caller's exit-code
/// convention.
pub async fn run_release_verdict(
    action: ReleaseVerdictAction,
    ctx: &OutputContext,
) -> anyhow::Result<()> {
    match action {
        ReleaseVerdictAction::Show {
            cas_root,
            build,
            now_micros,
            clock_epoch,
        } => {
            let root = resolve_cas_root(cas_root.as_deref())?;
            let mut store = open_store(&root)?;
            let build =
                build.unwrap_or_else(rabs_protocol::release_authorization::default_build_identity);
            let now = now_micros.unwrap_or_else(current_unix_micros);
            let receipt =
                build_release_verdict_receipt(&mut store, &root, &build, now, clock_epoch)?;
            if ctx.is_json() || ctx.is_toon() {
                ctx.json(&ApiResponse::ok("rabs release-verdict show", &receipt))?;
            } else {
                print_release_verdict(&receipt);
            }
            Ok(())
        }
        ReleaseVerdictAction::Record {
            cas_root,
            build,
            corpus,
            replayed,
            explained,
            max_age_secs,
            evaluated_at_micros,
            clock_uncertainty_micros,
            clock_epoch,
        } => {
            let root = resolve_cas_root(cas_root.as_deref())?;
            let mut store = open_or_init_store(&root)?;
            let build =
                build.unwrap_or_else(rabs_protocol::release_authorization::default_build_identity);
            let evaluated_at = evaluated_at_micros.unwrap_or_else(current_unix_micros);
            let maximum_age_micros = max_age_secs.map(|s| s.saturating_mul(1_000_000));
            let verdict = rabs_protocol::release_authorization::ReleaseVerdict {
                build,
                corpus,
                replayed,
                explained,
                validity: rabs_protocol::serving::ServingValidity {
                    evaluated_at_unix_micros: evaluated_at,
                    maximum_age_micros,
                    clock_uncertainty_micros,
                    coordinator_clock_epoch: clock_epoch,
                },
            };
            let receipt = record_and_verify_release_verdict(
                &mut store,
                &root,
                &verdict,
                evaluated_at,
                clock_epoch,
            )?;
            if ctx.is_json() || ctx.is_toon() {
                ctx.json(&ApiResponse::ok("rabs release-verdict record", &receipt))?;
            } else {
                print_release_verdict(&receipt);
            }
            Ok(())
        }
    }
}

// ---------------------------------------------------------------------
// R004: CAS verify, locate, and quarantine list/inspect/release commands
// ---------------------------------------------------------------------

const VERIFY_SCHEMA: &str = "rch.rabs-cas-verify.v1";
const LOCATE_SCHEMA: &str = "rch.rabs-cas-locate.v1";
const QUARANTINE_LIST_SCHEMA: &str = "rch.rabs-quarantine-list.v1";
const QUARANTINE_INSPECT_SCHEMA: &str = "rch.rabs-quarantine-inspect.v1";
const QUARANTINE_RELEASE_SCHEMA: &str = "rch.rabs-quarantine-release.v1";

/// Receipt emitted by `rch rabs verify` (R004 / H023).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CasVerifyReceipt {
    pub schema: &'static str,
    pub cas_root: String,
    pub scanned_locations: usize,
    pub healthy_locations: usize,
    pub quarantined_locations: Vec<String>,
    pub repaired_locations: Vec<String>,
    pub escalated_logical_objects: Vec<String>,
}

/// Replica location row emitted by `rch rabs locate` (R004).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct LocatedReplicaDto {
    pub store_path: String,
    pub encoding_profile: String,
    pub verified_raw: bool,
    pub quarantined: bool,
    pub exists_on_disk: bool,
}

/// Receipt emitted by `rch rabs locate <object_key>` (R004).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CasLocateReceipt {
    pub schema: &'static str,
    pub object_key: String,
    pub logical_quarantined: bool,
    pub replicas: Vec<LocatedReplicaDto>,
}

/// Serialized quarantine row for `rch rabs quarantine` (R004 / H012).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct QuarantineEntryDto {
    pub scope: String,
    pub subject: String,
    pub reason: String,
}

impl From<&rabs_cas::materialization::QuarantineRow> for QuarantineEntryDto {
    fn from(row: &rabs_cas::materialization::QuarantineRow) -> Self {
        Self {
            scope: row.scope.as_str().to_owned(),
            subject: row.subject.clone(),
            reason: row.reason.clone(),
        }
    }
}

/// Receipt emitted by `rch rabs quarantine list` (R004).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct QuarantineListReceipt {
    pub schema: &'static str,
    pub count: usize,
    pub entries: Vec<QuarantineEntryDto>,
}

/// Receipt emitted by `rch rabs quarantine inspect` (R004).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct QuarantineInspectReceipt {
    pub schema: &'static str,
    pub scope: String,
    pub subject: String,
    pub quarantined: bool,
    pub entry: Option<QuarantineEntryDto>,
}

/// Receipt emitted by `rch rabs quarantine release` (R004).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct QuarantineReleaseReceipt {
    pub schema: &'static str,
    pub scope: String,
    pub subject: String,
    pub repair_receipt_id: String,
    pub seq: u64,
    pub released: bool,
}

fn parse_quarantine_scope(
    scope: &str,
) -> anyhow::Result<rabs_cas::metadata_store::QuarantineScope> {
    rabs_cas::metadata_store::QuarantineScope::from_str_name(&scope.to_ascii_lowercase())
        .ok_or_else(|| {
            anyhow::anyhow!(
                "invalid quarantine scope '{scope}' (expected location|logical-object|action-entry)"
            )
        })
}

/// Compute the `rch rabs verify` receipt over `store` (R004 / H023).
pub fn verify_cas_receipt(
    store: &mut dyn RabsMetadataStore,
    cas_root: &Path,
) -> anyhow::Result<CasVerifyReceipt> {
    let seq = next_seq(store).map_err(|e| anyhow::anyhow!("allocate verify seq: {e:?}"))?;
    let report = rabs_cas::materialization::scrub_and_repair_locations(store, seq)
        .map_err(|e| anyhow::anyhow!("CAS verify/scrub failed: {e:?}"))?;
    Ok(CasVerifyReceipt {
        schema: VERIFY_SCHEMA,
        cas_root: cas_root.display().to_string(),
        scanned_locations: report.scanned_locations,
        healthy_locations: report.healthy_locations,
        quarantined_locations: report.quarantined_locations,
        repaired_locations: report.repaired_locations,
        escalated_logical_objects: report.escalated_logical_objects,
    })
}

/// Compute the `rch rabs locate <object_key>` receipt over `store` (R004).
pub fn locate_object_receipt(
    store: &mut dyn RabsMetadataStore,
    object_key: &str,
) -> anyhow::Result<CasLocateReceipt> {
    let rows = store
        .query(
            "SELECT store_path, encoding, durable, quarantined \
             FROM object_locations WHERE object_key = ?1 ORDER BY store_path ASC",
            &[SqlValue::Text(object_key.to_owned())],
        )
        .map_err(|e| anyhow::anyhow!("query object_locations: {e:?}"))?;
    let mut replicas = Vec::with_capacity(rows.len());
    for row in rows {
        if let [
            SqlValue::Text(store_path),
            SqlValue::Text(encoding_profile),
            SqlValue::Int(verified_raw),
            SqlValue::Int(quarantined),
        ] = row.as_slice()
        {
            let exists_on_disk = Path::new(store_path).exists();
            replicas.push(LocatedReplicaDto {
                store_path: store_path.clone(),
                encoding_profile: encoding_profile.clone(),
                verified_raw: *verified_raw != 0,
                quarantined: *quarantined != 0,
                exists_on_disk,
            });
        }
    }
    let logical_quarantined = rabs_cas::materialization::inspect_quarantine(
        store,
        rabs_cas::metadata_store::QuarantineScope::LogicalObject,
        object_key,
    )
    .map_err(|e| anyhow::anyhow!("inspect logical quarantine: {e:?}"))?
    .is_some();

    Ok(CasLocateReceipt {
        schema: LOCATE_SCHEMA,
        object_key: object_key.to_owned(),
        logical_quarantined,
        replicas,
    })
}

/// Compute the `rch rabs quarantine list` receipt over `store` (R004).
pub fn quarantine_list_receipt(
    store: &mut dyn RabsMetadataStore,
    scope: Option<&str>,
) -> anyhow::Result<QuarantineListReceipt> {
    let parsed_scope = match scope {
        Some(s) => Some(parse_quarantine_scope(s)?),
        None => None,
    };
    let rows = rabs_cas::materialization::list_quarantines(store, parsed_scope)
        .map_err(|e| anyhow::anyhow!("list quarantines: {e:?}"))?;
    let entries: Vec<QuarantineEntryDto> = rows.iter().map(QuarantineEntryDto::from).collect();
    Ok(QuarantineListReceipt {
        schema: QUARANTINE_LIST_SCHEMA,
        count: entries.len(),
        entries,
    })
}

/// Compute the `rch rabs quarantine inspect` receipt over `store` (R004).
pub fn quarantine_inspect_receipt(
    store: &mut dyn RabsMetadataStore,
    scope: &str,
    subject: &str,
) -> anyhow::Result<QuarantineInspectReceipt> {
    let parsed_scope = parse_quarantine_scope(scope)?;
    let row = rabs_cas::materialization::inspect_quarantine(store, parsed_scope, subject)
        .map_err(|e| anyhow::anyhow!("inspect quarantine: {e:?}"))?;
    let entry = row.as_ref().map(QuarantineEntryDto::from);
    Ok(QuarantineInspectReceipt {
        schema: QUARANTINE_INSPECT_SCHEMA,
        scope: parsed_scope.as_str().to_owned(),
        subject: subject.to_owned(),
        quarantined: entry.is_some(),
        entry,
    })
}

/// Execute `rch rabs quarantine release` over `store` (R004 / H012).
///
/// Requires a durable verified repair receipt (`rabs-quarantine-repair-v1`)
/// matching `(subject, repair_receipt_id)`.
pub fn quarantine_release_receipt(
    store: &mut dyn RabsMetadataStore,
    scope: &str,
    subject: &str,
    repair_receipt_id: &str,
    seq: Option<u64>,
) -> anyhow::Result<QuarantineReleaseReceipt> {
    let parsed_scope = parse_quarantine_scope(scope)?;
    let release_seq = match seq {
        Some(s) => s,
        None => next_seq(store).map_err(|e| anyhow::anyhow!("allocate release seq: {e:?}"))?,
    };
    let released = store
        .release_quarantine_with_receipt(parsed_scope, subject, repair_receipt_id, release_seq)
        .map_err(|e| anyhow::anyhow!("release quarantine refused: {e:?}"))?;
    Ok(QuarantineReleaseReceipt {
        schema: QUARANTINE_RELEASE_SCHEMA,
        scope: parsed_scope.as_str().to_owned(),
        subject: subject.to_owned(),
        repair_receipt_id: repair_receipt_id.to_owned(),
        seq: release_seq,
        released,
    })
}

/// Entry point for `rch rabs verify` (R004).
pub async fn run_verify(cas_root: Option<PathBuf>, ctx: &OutputContext) -> anyhow::Result<()> {
    let root = resolve_cas_root(cas_root.as_deref())?;
    let mut store = open_store(&root)?;
    let receipt = verify_cas_receipt(&mut store, &root)?;
    if ctx.is_json() || ctx.is_toon() {
        ctx.json(&ApiResponse::ok("rabs verify", &receipt))?;
    } else {
        println!(
            "rabs verify [{}]: scanned={} healthy={} quarantined={} repaired={} escalated={}",
            receipt.cas_root,
            receipt.scanned_locations,
            receipt.healthy_locations,
            receipt.quarantined_locations.len(),
            receipt.repaired_locations.len(),
            receipt.escalated_logical_objects.len(),
        );
    }
    Ok(())
}

/// Entry point for `rch rabs locate <object_key>` (R004).
pub async fn run_locate(
    object_key: String,
    cas_root: Option<PathBuf>,
    ctx: &OutputContext,
) -> anyhow::Result<()> {
    let root = resolve_cas_root(cas_root.as_deref())?;
    let mut store = open_store(&root)?;
    let receipt = locate_object_receipt(&mut store, &object_key)?;
    if ctx.is_json() || ctx.is_toon() {
        ctx.json(&ApiResponse::ok("rabs locate", &receipt))?;
    } else {
        println!(
            "rabs locate {}: logical_quarantined={} replicas={}",
            receipt.object_key,
            receipt.logical_quarantined,
            receipt.replicas.len()
        );
        for r in &receipt.replicas {
            println!(
                "  {} profile={} verified_raw={} quarantined={} exists={}",
                r.store_path, r.encoding_profile, r.verified_raw, r.quarantined, r.exists_on_disk
            );
        }
    }
    Ok(())
}

/// Entry point for `rch rabs quarantine <action>` (R004).
pub async fn run_quarantine(action: QuarantineAction, ctx: &OutputContext) -> anyhow::Result<()> {
    match action {
        QuarantineAction::List { cas_root, scope } => {
            let root = resolve_cas_root(cas_root.as_deref())?;
            let mut store = open_store(&root)?;
            let receipt = quarantine_list_receipt(&mut store, scope.as_deref())?;
            if ctx.is_json() || ctx.is_toon() {
                ctx.json(&ApiResponse::ok("rabs quarantine list", &receipt))?;
            } else {
                println!("rabs quarantine list: count={}", receipt.count);
                for e in &receipt.entries {
                    println!("  [{}] {} -> {}", e.scope, e.subject, e.reason);
                }
            }
            Ok(())
        }
        QuarantineAction::Inspect {
            scope,
            subject,
            cas_root,
        } => {
            let root = resolve_cas_root(cas_root.as_deref())?;
            let mut store = open_store(&root)?;
            let receipt = quarantine_inspect_receipt(&mut store, &scope, &subject)?;
            if ctx.is_json() || ctx.is_toon() {
                ctx.json(&ApiResponse::ok("rabs quarantine inspect", &receipt))?;
            } else if let Some(entry) = &receipt.entry {
                println!(
                    "rabs quarantine inspect: [{}] {} QUARANTINED ({})",
                    entry.scope, entry.subject, entry.reason
                );
            } else {
                println!(
                    "rabs quarantine inspect: [{}] {} not quarantined",
                    receipt.scope, receipt.subject
                );
            }
            Ok(())
        }
        QuarantineAction::Release {
            scope,
            subject,
            receipt_id,
            seq,
            cas_root,
        } => {
            let root = resolve_cas_root(cas_root.as_deref())?;
            let mut store = open_store(&root)?;
            let receipt =
                quarantine_release_receipt(&mut store, &scope, &subject, &receipt_id, seq)?;
            if ctx.is_json() || ctx.is_toon() {
                ctx.json(&ApiResponse::ok("rabs quarantine release", &receipt))?;
            } else {
                println!(
                    "rabs quarantine release: [{}] {} receipt_id={} seq={} released={}",
                    receipt.scope,
                    receipt.subject,
                    receipt.repair_receipt_id,
                    receipt.seq,
                    receipt.released
                );
            }
            Ok(())
        }
    }
}

/// `rch rabs <group>` command groups (R004 lands `verify`, `locate`,
/// `quarantine`; R005 lands `gc`; R006 lands `worker` + `doctor`;
/// `bd-dockb` lands `release-verdict`).
#[derive(Debug, Subcommand)]
pub enum RabsCommand {
    /// Content-addressed store garbage collection (H014 engine)
    #[command(
        after_help = "EXAMPLES:\n    rch rabs gc plan\n    rch rabs gc plan --mode emergency --protect sha256:abc --budget 32\n    rch rabs gc run --json\n    rch rabs gc history --limit 20"
    )]
    Gc {
        /// GC operation
        #[command(subcommand)]
        action: GcAction,
    },
    /// Worker reconciliation + stale-operation doctor (R006)
    #[command(
        after_help = "EXAMPLES:\n    rch rabs worker reconcile worker-a\n    rch rabs worker reconcile worker-a --json\n    rch rabs doctor --min-seq-lag 1000"
    )]
    Worker {
        /// Worker operation
        #[command(subcommand)]
        action: WorkerAction,
    },
    /// Find stale operations/pins and propose safe resolution (read-only)
    Doctor {
        /// CAS root directory (default: rabsd's state dir)
        #[arg(long, value_name = "DIR")]
        cas_root: Option<PathBuf>,
        /// Operations lagging the live-progress watermark by more than this
        /// many seqs count as stale
        #[arg(long, value_name = "SEQS", default_value_t = 1_000)]
        min_seq_lag: u64,
    },
    /// Scrub and verify physical CAS locations, repairing corrupt copies from healthy replicas (R004 / H023)
    Verify {
        /// CAS root directory (default: rabsd's state dir)
        #[arg(long, value_name = "DIR")]
        cas_root: Option<PathBuf>,
    },
    /// Locate physical CAS replicas and quarantine state for an object key (R004)
    Locate {
        /// Object digest key (`domain:hex`)
        #[arg(value_name = "OBJECT_KEY")]
        object_key: String,
        /// CAS root directory (default: rabsd's state dir)
        #[arg(long, value_name = "DIR")]
        cas_root: Option<PathBuf>,
    },
    /// List, inspect, or release CAS quarantines with a verified repair receipt (R004 / H012)
    Quarantine {
        /// Quarantine operation
        #[command(subcommand)]
        action: QuarantineAction,
    },
    /// What is cached where: edge L1, local L2 projects, toolchains,
    /// store facts — with namespace existence-hiding (K006/K010 ACL)
    Inventory {
        /// CAS root directory (default: rabsd's state dir)
        #[arg(long, value_name = "DIR")]
        cas_root: Option<PathBuf>,
        /// L2 cache root to enumerate (default: ~/.cache/rch)
        #[arg(long, value_name = "DIR")]
        l2_root: Option<PathBuf>,
        /// Project namespace whose names this viewer may see
        /// (repeatable; unlisted namespaces collapse into a count)
        #[arg(long, value_name = "NAMESPACE")]
        allow_namespace: Vec<String>,
    },
    /// Inspect or record durable T011 release-gate verdicts (`bd-dockb`)
    #[command(
        name = "release-verdict",
        after_help = "EXAMPLES:\n    rch rabs release-verdict show\n    rch rabs release-verdict show --build rabs-2.1.34 --json\n    rch rabs release-verdict record --corpus shadow-ci --replayed 128 --max-age-secs 86400"
    )]
    ReleaseVerdict {
        /// Release-verdict operation
        #[command(subcommand)]
        action: ReleaseVerdictAction,
    },
}

/// One quarantine operation (R004 / H012).
#[derive(Debug, Subcommand)]
pub enum QuarantineAction {
    /// List active quarantines (optionally filtered by scope)
    List {
        /// CAS root directory (default: rabsd's state dir)
        #[arg(long, value_name = "DIR")]
        cas_root: Option<PathBuf>,
        /// Optional scope filter (`location|logical-object|action-entry`)
        #[arg(long, value_name = "SCOPE")]
        scope: Option<String>,
    },
    /// Inspect quarantine status for a specific (scope, subject)
    Inspect {
        /// Quarantine scope (`location|logical-object|action-entry`)
        #[arg(value_name = "SCOPE")]
        scope: String,
        /// Quarantine subject (store path, object key, or action key)
        #[arg(value_name = "SUBJECT")]
        subject: String,
        /// CAS root directory (default: rabsd's state dir)
        #[arg(long, value_name = "DIR")]
        cas_root: Option<PathBuf>,
    },
    /// Release a quarantine using a verified repair receipt ID (`rabs-quarantine-repair-v1`)
    Release {
        /// Quarantine scope (`location|logical-object|action-entry`)
        #[arg(value_name = "SCOPE")]
        scope: String,
        /// Quarantine subject (store path, object key, or action key)
        #[arg(value_name = "SUBJECT")]
        subject: String,
        /// Verified repair receipt ID (`rabs-quarantine-repair-v1`)
        #[arg(long, value_name = "RECEIPT_ID")]
        receipt_id: String,
        /// Optional decision sequence override
        #[arg(long, value_name = "SEQ")]
        seq: Option<u64>,
        /// CAS root directory (default: rabsd's state dir)
        #[arg(long, value_name = "DIR")]
        cas_root: Option<PathBuf>,
    },
}

/// One release-verdict operation (`bd-dockb`).
#[derive(Debug, Subcommand)]
pub enum ReleaseVerdictAction {
    /// Inspect the durable release verdict and standing for a build
    Show {
        /// CAS root directory (default: rabsd's state dir)
        #[arg(long, value_name = "DIR")]
        cas_root: Option<PathBuf>,
        /// Build identity to inspect (default: this binary's derived identity)
        #[arg(long, value_name = "BUILD")]
        build: Option<String>,
        /// Evaluation timestamp in Unix microseconds (default: current wall clock)
        #[arg(long, value_name = "MICROS")]
        now_micros: Option<i64>,
        /// Coordinator clock epoch to evaluate against
        #[arg(long, value_name = "EPOCH", default_value_t = 0)]
        clock_epoch: u64,
    },
    /// Record a durable release verdict for a build after a passing corpus run
    Record {
        /// CAS root directory (default: rabsd's state dir; initialized if absent)
        #[arg(long, value_name = "DIR")]
        cas_root: Option<PathBuf>,
        /// Build identity to authorize (default: this binary's derived identity)
        #[arg(long, value_name = "BUILD")]
        build: Option<String>,
        /// Corpus identifier that produced this verdict
        #[arg(long, value_name = "CORPUS")]
        corpus: String,
        /// Number of records that replayed under both stock and RABS (> 0)
        #[arg(long, value_name = "N")]
        replayed: u64,
        /// Number of divergences explicitly explained by operator policy
        #[arg(long, value_name = "N", default_value_t = 0)]
        explained: u64,
        /// Optional validity window in seconds
        #[arg(long, value_name = "SECS")]
        max_age_secs: Option<u64>,
        /// Evaluation timestamp in Unix microseconds (default: current wall clock)
        #[arg(long, value_name = "MICROS")]
        evaluated_at_micros: Option<i64>,
        /// Conservative clock uncertainty in microseconds
        #[arg(long, value_name = "MICROS", default_value_t = 0)]
        clock_uncertainty_micros: u64,
        /// Coordinator clock epoch
        #[arg(long, value_name = "EPOCH", default_value_t = 0)]
        clock_epoch: u64,
    },
}

/// One worker operation.
#[derive(Debug, Subcommand)]
pub enum WorkerAction {
    /// A gone worker's open sessions are ended, store drift is repaired
    /// against filesystem reality, and safe-resolution proposals are
    /// listed for anything stale. Proposals are NEVER auto-applied.
    Reconcile {
        /// Worker identity
        #[arg(value_name = "WORKER")]
        worker: String,
        /// CAS root directory (default: rabsd's state dir)
        #[arg(long, value_name = "DIR")]
        cas_root: Option<PathBuf>,
    },
}

/// One GC operation.
#[derive(Debug, Subcommand)]
pub enum GcAction {
    /// Dry-run receipt: what would be reclaimed, why, per layer
    Plan {
        /// CAS root directory (default: rabsd's state dir)
        #[arg(long, value_name = "DIR")]
        cas_root: Option<PathBuf>,
        /// GC mode
        #[arg(long, value_name = "normal|emergency")]
        mode: Option<String>,
        /// Object key to hold as an active build (repeatable)
        #[arg(long = "protect", value_name = "KEY")]
        protect: Vec<String>,
        /// Maximum locations one run may reclaim
        #[arg(long, value_name = "N")]
        budget: Option<usize>,
        /// Assert reconciliation has completed (unlocks provisional eviction)
        #[arg(long)]
        reconciled: bool,
        /// Maximum locations listed per receipt section
        #[arg(long, value_name = "N", default_value_t = DEFAULT_MAX_LISTED)]
        max_listed: usize,
    },
    /// Execute a fresh plan; emits the actual reclaim receipt
    Run {
        /// CAS root directory (default: rabsd's state dir)
        #[arg(long, value_name = "DIR")]
        cas_root: Option<PathBuf>,
        /// GC mode
        #[arg(long, value_name = "normal|emergency")]
        mode: Option<String>,
        /// Object key to hold as an active build (repeatable)
        #[arg(long = "protect", value_name = "KEY")]
        protect: Vec<String>,
        /// Maximum locations one run may reclaim
        #[arg(long, value_name = "N")]
        budget: Option<usize>,
        /// Assert reconciliation has completed (unlocks provisional eviction)
        #[arg(long)]
        reconciled: bool,
        /// Maximum locations listed per receipt section
        #[arg(long, value_name = "N", default_value_t = DEFAULT_MAX_LISTED)]
        max_listed: usize,
    },
    /// Prior runs with planned-vs-actual deltas
    History {
        /// CAS root directory (default: rabsd's state dir)
        #[arg(long, value_name = "DIR")]
        cas_root: Option<PathBuf>,
        /// Rows to show (newest first)
        #[arg(long, value_name = "N")]
        limit: Option<usize>,
    },
}

#[cfg(test)]
mod tests {
    use super::*;
    use rabs_protocol::result_identity::{DigestAlgorithm, TypedDigest};
    use tempfile::TempDir;

    struct TestStore {
        _dir: TempDir,
        store: SqlMetadataStore<RusqliteEngine>,
    }

    fn fresh_store(_tag: &str) -> TestStore {
        let dir = TempDir::new().expect("tempdir");
        let engine = RusqliteEngine::open(&dir.path().join("meta.sqlite")).expect("engine opens");
        let store = SqlMetadataStore::open(engine).expect("store opens");
        TestStore { _dir: dir, store }
    }

    fn digest(tag: u8) -> TypedDigest {
        TypedDigest {
            algorithm: DigestAlgorithm::Sha256V1,
            domain: "rabs.object.sha256.v1",
            bytes: [tag; 32],
        }
    }

    fn key(tag: u8) -> String {
        rabs_cas::metadata_store::digest_key(&digest(tag))
    }

    /// Seed: cold committed 1..=3 (reclaimable), hot dependency 4,
    /// toolchain 5, authoritative evidence 6, provisional 7.
    fn seed(store: &mut SqlMetadataStore<RusqliteEngine>) -> GcWorld {
        for tag in 1..=7_u8 {
            store.record_object(&digest(tag), 64).expect("object");
            store
                .add_location(&digest(tag), &format!("/cas/{tag}"), Some(1), "raw", true)
                .expect("location");
        }
        let mut policies = BTreeMap::new();
        for (tag, class, last_use) in [
            (4_u8, PolicyClass::HotDependency, 9_u64),
            (5, PolicyClass::Toolchain, 9),
            (6, PolicyClass::AuthoritativeEvidence, 9),
            (7, PolicyClass::ProvisionalStaging, 1),
        ] {
            policies.insert(
                key(tag),
                ObjectPolicy {
                    class,
                    last_use_seq: last_use,
                },
            );
        }
        GcWorld {
            protections: ActiveProtections::default(),
            policies,
            reconciliation_complete: false,
            reclaim_budget: DEFAULT_RECLAIM_BUDGET,
        }
    }

    #[test]
    fn reason_codes_cover_every_protection_reason_and_prefix() {
        for reason in [
            ProtectionReason::PinnedOrReachable,
            ProtectionReason::ActiveBuild,
            ProtectionReason::Materialization,
            ProtectionReason::Transfer,
            ProtectionReason::OpenReader,
            ProtectionReason::AuthoritativeEvidence,
            ProtectionReason::AwaitingReconciliation,
            ProtectionReason::RetainedByPolicy,
            ProtectionReason::BudgetTruncated,
        ] {
            let code = reason_code_for(reason);
            assert!(
                code.starts_with("STORAGE_") || code.starts_with("QUARANTINE_"),
                "{code} outside the stable families"
            );
        }
    }

    #[test]
    fn normal_mode_plans_only_cold_committed_results() {
        let mut ts = fresh_store("plan-normal");
        let world = seed(&mut ts.store);
        let receipt = plan_receipt(&mut ts.store, &world, GcMode::Normal, 50).expect("plan");
        assert_eq!(receipt.schema, PLAN_SCHEMA);
        assert_eq!(receipt.seq, 1);
        assert!(!receipt.truncated);
        let reclaimed_keys: BTreeSet<String> = receipt
            .reclaim
            .iter()
            .map(|l| l.object_key.clone())
            .collect();
        assert_eq!(
            reclaimed_keys.len(),
            3,
            "cold committed 1..=3: {reclaimed_keys:?}"
        );
        for tag in 4..=7_u8 {
            assert!(!reclaimed_keys.contains(&key(tag)));
        }
        let codes: BTreeSet<&str> = receipt
            .reason_counts
            .iter()
            .map(|rc| rc.reason_code)
            .collect();
        assert!(codes.contains(RC_RETAINED_BY_POLICY), "{codes:?}");
        assert!(codes.contains(RC_AUTHORITATIVE_EVIDENCE), "{codes:?}");
        assert!(
            codes.contains(RC_AWAITING_RECONCILIATION),
            "unreconciled provisional must be protected: {codes:?}"
        );
    }

    #[test]
    fn emergency_mode_widens_to_hot_dependency_and_toolchain() {
        let mut ts = fresh_store("plan-emergency");
        let mut world = seed(&mut ts.store);
        world.reconciliation_complete = true;
        let receipt = plan_receipt(&mut ts.store, &world, GcMode::Emergency, 50).expect("plan");
        let reclaimed_keys: BTreeSet<String> = receipt
            .reclaim
            .iter()
            .map(|l| l.object_key.clone())
            .collect();
        assert!(reclaimed_keys.contains(&key(4)), "hot dep under emergency");
        assert!(
            reclaimed_keys.contains(&key(5)),
            "toolchain under emergency"
        );
        assert!(reclaimed_keys.contains(&key(7)), "reconciled provisional");
        assert!(!reclaimed_keys.contains(&key(6)), "evidence never evicted");
    }

    #[test]
    fn budget_truncation_marks_overflow_as_budget_truncated() {
        let mut ts = fresh_store("plan-budget");
        let world = seed(&mut ts.store);
        let mut world = world;
        world.reclaim_budget = 1;
        let receipt = plan_receipt(&mut ts.store, &world, GcMode::Normal, 50).expect("plan");
        assert!(receipt.truncated);
        assert_eq!(receipt.reclaim_total, 1);
        // Normal mode admits exactly the three cold committed results as
        // candidates (see `normal_mode_plans_only_cold_committed_results`);
        // policy-protected objects keep their own reason code and never
        // enter the budget pass. Budget 1 therefore truncates the other 2.
        assert!(
            receipt
                .reason_counts
                .iter()
                .any(|rc| rc.reason_code == RC_BUDGET_TRUNCATED && rc.count == 2),
            "{:?}",
            receipt.reason_counts
        );
        assert_eq!(receipt.protected_total, 6, "4 by policy + 2 by budget");
    }

    #[test]
    fn listing_bounds_apply_with_truncation_flags() {
        let mut ts = fresh_store("plan-bounds");
        let world = seed(&mut ts.store);
        let receipt = plan_receipt(&mut ts.store, &world, GcMode::Normal, 2).expect("plan");
        assert_eq!(receipt.reclaim.len(), 2);
        assert!(receipt.reclaim_truncated);
        assert_eq!(receipt.reclaim_total, 3);
    }

    #[test]
    fn run_executes_and_history_records_planned_vs_actual() {
        let mut ts = fresh_store("run-history");
        let world = seed(&mut ts.store);
        let run = run_receipt(&mut ts.store, &world, GcMode::Normal, 50).expect("run");
        assert_eq!(run.planned, 3);
        assert_eq!(run.reclaimed.len(), 3, "all three exist, none skipped");
        assert_eq!(run.seq, 1);

        let history = history_receipt(&mut ts.store, 10).expect("history");
        assert_eq!(history.count, 1);
        let entry = &history.entries[0];
        assert_eq!(entry.seq, 1);
        assert_eq!(entry.mode, "normal");
        assert_eq!(entry.planned, 3);
        assert_eq!(entry.reclaimed, 3);
        assert_eq!(entry.skipped, 0);
        assert_eq!(entry.unaccounted, 0);

        // Second run sees a bumped sequence and nothing left to reclaim.
        let second = run_receipt(&mut ts.store, &world, GcMode::Normal, 50).expect("run 2");
        assert_eq!(second.seq, 2);
        assert_eq!(second.planned, 0);
    }

    #[test]
    fn vanished_planned_location_is_skipped_never_silent() {
        let mut ts = fresh_store("run-skip");
        let world = seed(&mut ts.store);
        // Compute the plan manually so we can delete one candidate between
        // plan and execute — the exact SKIP contract.
        let seq = next_seq(&mut ts.store).expect("seq");
        let plan = rabs_cas::gc::plan_gc(&mut ts.store, &world, GcMode::Normal, seq).expect("plan");
        assert_eq!(plan.reclaim.len(), 3);
        let victim = plan.reclaim[0].clone();
        assert!(
            ts.store
                .remove_location_by_key(&victim.object_key, &victim.store_path)
                .expect("remove")
        );
        let receipt = rabs_cas::gc::execute_gc(&mut ts.store, &plan).expect("execute");
        assert_eq!(receipt.planned, 3);
        assert_eq!(receipt.reclaimed.len(), 2);
        assert_eq!(receipt.skipped.len(), 1);
        let history = history_receipt(&mut ts.store, 5).expect("history");
        assert_eq!(history.entries[0].skipped, 1);
        assert_eq!(history.entries[0].unaccounted, 0);
    }

    #[test]
    fn protect_flag_holds_objects_out_of_the_plan() {
        let mut ts = fresh_store("plan-protect");
        let world = seed(&mut ts.store);
        let mut world = world;
        let held = key(2);
        world.protections.active_builds.insert(held.clone());
        let receipt = plan_receipt(&mut ts.store, &world, GcMode::Normal, 50).expect("plan");
        assert!(!receipt.reclaim.iter().any(|l| l.object_key == held));
        assert!(
            receipt
                .protected
                .iter()
                .any(|p| p.object_key == held && p.reason_code == RC_ACTIVE_BUILD)
        );
    }

    #[test]
    fn quarantine_intersection_is_informational_only() {
        let mut ts = fresh_store("plan-quarantine");
        let world = seed(&mut ts.store);
        ts.store
            .set_location_quarantined(&digest(1), "/cas/1", true)
            .expect("quarantine");
        let receipt = plan_receipt(&mut ts.store, &world, GcMode::Normal, 50).expect("plan");
        assert_eq!(receipt.quarantine_reclaim_candidates, 1);
        // Engine semantics untouched: object 1 remains reclaim-planned.
        assert!(receipt.reclaim.iter().any(|l| l.object_key == key(1)));
    }

    #[test]
    fn mode_parsing_is_strict() {
        assert!(matches!(parse_mode(None), Ok(GcMode::Normal)));
        assert!(matches!(
            parse_mode(Some("EMERGENCY")),
            Ok(GcMode::Emergency)
        ));
        assert!(parse_mode(Some("bogus")).is_err());
    }

    #[test]
    fn history_on_fresh_store_is_empty_not_an_error() {
        let mut ts = fresh_store("history-empty");
        let receipt = history_receipt(&mut ts.store, 10).expect("history");
        assert_eq!(receipt.count, 0);
        assert!(receipt.entries.is_empty());
    }

    #[test]
    fn missing_cas_root_refuses_without_creating() {
        let dir = TempDir::new().expect("tempdir");
        let root = dir.path().join("nope");
        let err = match open_store(&root) {
            Err(err) => err,
            Ok(_) => panic!("must refuse a missing CAS root"),
        };
        assert!(err.to_string().contains(RC_CAS_ROOT_MISSING), "{err}");
        assert!(!root.exists(), "must not create anything");
    }

    #[test]
    fn release_verdict_show_and_record_round_trip_and_enforce_evidence_and_expiry() {
        let mut ts = fresh_store("release-verdict");
        let build = rabs_protocol::release_authorization::default_build_identity();
        let root = ts._dir.path().to_path_buf();

        let initial =
            build_release_verdict_receipt(&mut ts.store, &root, &build, 1_000, 0).expect("show");
        assert_eq!(initial.standing, "absent");
        assert!(initial.permits_advisory);
        assert!(!initial.permits_required);
        assert!(initial.verdict.is_none());

        let zero_replayed = rabs_protocol::release_authorization::ReleaseVerdict {
            build: build.clone(),
            corpus: "shadow-ci".to_owned(),
            replayed: 0,
            explained: 0,
            validity: rabs_protocol::serving::ServingValidity {
                evaluated_at_unix_micros: 1_000,
                maximum_age_micros: Some(10_000),
                clock_uncertainty_micros: 0,
                coordinator_clock_epoch: 0,
            },
        };
        assert!(
            record_and_verify_release_verdict(&mut ts.store, &root, &zero_replayed, 1_000, 0)
                .is_err(),
            "zero-replayed verdicts must be refused at record time"
        );

        let valid = rabs_protocol::release_authorization::ReleaseVerdict {
            build: build.clone(),
            corpus: "shadow-ci".to_owned(),
            replayed: 64,
            explained: 1,
            validity: rabs_protocol::serving::ServingValidity {
                evaluated_at_unix_micros: 1_000,
                maximum_age_micros: Some(10_000),
                clock_uncertainty_micros: 0,
                coordinator_clock_epoch: 0,
            },
        };
        let recorded = record_and_verify_release_verdict(&mut ts.store, &root, &valid, 2_000, 0)
            .expect("record");
        assert_eq!(recorded.standing, "authorized");
        assert!(recorded.permits_advisory);
        assert!(recorded.permits_required);
        assert_eq!(
            recorded.verdict.as_ref().map(|v| v.replayed),
            Some(64),
            "{recorded:?}"
        );

        let expired = build_release_verdict_receipt(&mut ts.store, &root, &build, 25_000, 0)
            .expect("show expired");
        assert_eq!(expired.standing, "expired");
        assert!(expired.permits_advisory);
        assert!(!expired.permits_required);
    }

    #[test]
    fn r004_verify_locate_and_quarantine_list_inspect_release_enforce_receipts() {
        let mut ts = fresh_store("r004");
        let root = ts._dir.path().to_path_buf();
        let bytes = b"r004-verified-cas-payload";
        let obj = rabs_cas::digest_set::digest_set(
            bytes,
            rabs_cas::digest_set::DigestRequest::default(),
            None,
        )
        .expect("digest")
        .atp_content_id;
        let obj_key = rabs_cas::metadata_store::digest_key(&obj);

        let replica_path = root.join("replica.bin");
        std::fs::write(&replica_path, bytes).expect("write replica");
        let replica_str = replica_path.to_str().expect("utf8").to_owned();

        ts.store
            .record_object(&obj, bytes.len() as u64)
            .expect("record object");
        ts.store
            .add_location(&obj, &replica_str, Some(1), "raw-v1", true)
            .expect("add location");

        // 1. Locate healthy replica
        let located = locate_object_receipt(&mut ts.store, &obj_key).expect("locate");
        assert!(!located.logical_quarantined);
        assert_eq!(located.replicas.len(), 1);
        assert!(!located.replicas[0].quarantined);
        assert!(located.replicas[0].exists_on_disk);

        // 2. Corrupt the single replica and run `verify` -> escalates to logical-object quarantine
        std::fs::write(&replica_path, b"corrupt-r004-bytes").expect("corrupt replica");
        let verify = verify_cas_receipt(&mut ts.store, &root).expect("verify");
        assert_eq!(verify.scanned_locations, 1);
        assert_eq!(verify.healthy_locations, 0);
        assert_eq!(verify.quarantined_locations, vec![replica_str.clone()]);
        assert_eq!(verify.escalated_logical_objects, vec![obj_key.clone()]);

        // 3. Quarantine list and inspect
        let list = quarantine_list_receipt(&mut ts.store, None).expect("list");
        assert_eq!(list.count, 2);
        let loc_list = quarantine_list_receipt(&mut ts.store, Some("location")).expect("list loc");
        assert_eq!(loc_list.count, 1);
        assert_eq!(loc_list.entries[0].subject, replica_str);

        let inspected =
            quarantine_inspect_receipt(&mut ts.store, "logical-object", &obj_key).expect("inspect");
        assert!(inspected.quarantined);

        // 4. Release without a verified repair receipt must be refused
        assert!(
            quarantine_release_receipt(
                &mut ts.store,
                "logical-object",
                &obj_key,
                "missing-receipt-id",
                None,
            )
            .is_err(),
            "quarantine release without a verified repair receipt must be refused"
        );

        // 5. Restore bytes, record verified repair receipt, and release both quarantines
        std::fs::write(&replica_path, bytes).expect("restore replica");
        rabs_cas::materialization::record_verified_repair_receipt(
            &mut ts.store,
            &replica_str,
            "repair-loc-1",
            "restored-from-source",
            50,
        )
        .expect("loc receipt");
        rabs_cas::materialization::record_verified_repair_receipt(
            &mut ts.store,
            &obj_key,
            "repair-obj-1",
            "restored-from-source",
            51,
        )
        .expect("obj receipt");

        let rel_loc = quarantine_release_receipt(
            &mut ts.store,
            "location",
            &replica_str,
            "repair-loc-1",
            None,
        )
        .expect("release location");
        assert!(rel_loc.released);
        let rel_obj = quarantine_release_receipt(
            &mut ts.store,
            "logical-object",
            &obj_key,
            "repair-obj-1",
            None,
        )
        .expect("release logical object");
        assert!(rel_obj.released);

        let after_verify = verify_cas_receipt(&mut ts.store, &root).expect("verify after repair");
        assert_eq!(after_verify.scanned_locations, 1);
        assert_eq!(after_verify.healthy_locations, 1);
        assert!(after_verify.quarantined_locations.is_empty());
    }
}
