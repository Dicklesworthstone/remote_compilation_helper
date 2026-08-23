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
    Ok(match rows.first().and_then(|r| r.first()) {
        // MAX over persisted u64 counts is non-negative by construction;
        // a negative value would be store corruption, clamped to restart.
        Some(SqlValue::Int(n)) => u64::try_from((*n).max(0)).unwrap_or(1),
        _ => 1,
    })
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
        let numbers @ [_, _, _] = [cols.next(), cols.next(), cols.next()] else {
            return Err(StoreError::Backend(
                "gc_receipts counters incomplete".to_owned(),
            ));
        };
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
pub async fn run(action: GcAction, ctx: &OutputContext) -> anyhow::Result<()> {
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

/// `rch rabs <group>` command groups (R005 lands the `gc` group).
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
        assert!(
            receipt
                .reason_counts
                .iter()
                .any(|rc| rc.reason_code == RC_BUDGET_TRUNCATED && rc.count == 6)
        );
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
}
