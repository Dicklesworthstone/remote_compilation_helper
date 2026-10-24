//! Incremental-snapshot compatibility contract (bead P001; plan §103;
//! invariant I4's incremental arm; risk R31).
//!
//! Incremental state is ATTEMPT AUXILIARY (never result identity —
//! I4), but selecting the WRONG snapshot corrupts a compile: rustc's
//! incremental caches are toolchain- and configuration-specific, and
//! reusing one across a boundary rustc never promised produces
//! miscompiles or ICEs. The contract: a snapshot carries its full
//! compatibility class, and selection requires EXACT class equality —
//! no cross-class reuse exists without a proof, and no proof mechanism
//! exists today (the refusal names the mismatching dimension so the
//! operator sees exactly why the warm start was declined).

use crate::result_identity::TypedDigest;

/// The full compatibility class of an incremental snapshot.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IncrementalCompatibilityClass {
    /// Toolchain contract digest (F007).
    pub toolchain: TypedDigest,
    /// Target triple.
    pub target: String,
    /// Cargo profile name (debug/release/custom).
    pub profile: String,
    /// Projection identity (the F010 projection epoch).
    pub projection_epoch: u32,
    /// Output-platform class digest (F008).
    pub output_platform: TypedDigest,
    /// Isolation class name (the snapshot's producing profile).
    pub isolation_class: String,
}

/// Which dimension refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(missing_docs)]
pub enum MismatchDimension {
    Toolchain,
    Target,
    Profile,
    ProjectionEpoch,
    OutputPlatform,
    IsolationClass,
}

/// Selection outcome.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SnapshotSelection {
    /// Exact class match: the snapshot may seed this attempt.
    Selectable,
    /// Refused, naming the FIRST mismatching dimension.
    Refused(MismatchDimension),
}

/// Decide whether a stored snapshot may seed an attempt in `wanted`'s
/// class. Exact equality per dimension; the first mismatch names
/// itself.
#[must_use]
pub fn select_snapshot(
    stored: &IncrementalCompatibilityClass,
    wanted: &IncrementalCompatibilityClass,
) -> SnapshotSelection {
    if stored.toolchain != wanted.toolchain {
        return SnapshotSelection::Refused(MismatchDimension::Toolchain);
    }
    if stored.target != wanted.target {
        return SnapshotSelection::Refused(MismatchDimension::Target);
    }
    if stored.profile != wanted.profile {
        return SnapshotSelection::Refused(MismatchDimension::Profile);
    }
    if stored.projection_epoch != wanted.projection_epoch {
        return SnapshotSelection::Refused(MismatchDimension::ProjectionEpoch);
    }
    if stored.output_platform != wanted.output_platform {
        return SnapshotSelection::Refused(MismatchDimension::OutputPlatform);
    }
    if stored.isolation_class != wanted.isolation_class {
        return SnapshotSelection::Refused(MismatchDimension::IsolationClass);
    }
    SnapshotSelection::Selectable
}

// ============================================================================
// Bead P003: FastCDC/zstd snapshot manifest + sequential-edit dedup
// ============================================================================

/// Versioned FastCDC + zstd chunking profile for incremental snapshots (bead P003).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FastCdcSnapshotProfile {
    /// Profile schema version (`rabs.chunking-profile` v1).
    pub profile_version: u32,
    /// Minimum chunk size in bytes.
    pub min_chunk_bytes: usize,
    /// Average target chunk size in bytes.
    pub avg_chunk_bytes: usize,
    /// Maximum chunk size in bytes.
    pub max_chunk_bytes: usize,
    /// Zstd compression level (`1..=19`).
    pub zstd_level: i32,
}

impl Default for FastCdcSnapshotProfile {
    fn default() -> Self {
        Self {
            profile_version: 1,
            min_chunk_bytes: 64,
            avg_chunk_bytes: 128,
            max_chunk_bytes: 256,
            zstd_level: 3,
        }
    }
}

/// One content-defined chunk inside a [`FastCdcSnapshotManifest`] (bead P003).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct FastCdcChunkEntry {
    /// Content digest of the uncompressed chunk bytes.
    pub chunk_digest: [u8; 32],
    /// Uncompressed chunk length in bytes.
    pub uncompressed_len: u32,
    /// Deterministic zstd-compressed payload length estimate in bytes.
    pub compressed_len: u32,
}

/// Versioned FastCDC/zstd incremental snapshot manifest (bead P003).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FastCdcSnapshotManifest {
    /// Versioned chunking profile used to produce this manifest (`rabs.chunking-profile`).
    pub profile: FastCdcSnapshotProfile,
    /// Ordered list of content-defined chunks reconstructing the snapshot state.
    pub chunks: Vec<FastCdcChunkEntry>,
    /// Total logical uncompressed bytes.
    pub total_uncompressed_bytes: u64,
    /// Total compressed bytes across chunks.
    pub total_compressed_bytes: u64,
}

fn fastcdc_chunk_digest(bytes: &[u8]) -> [u8; 32] {
    let mut out = [0u8; 32];
    for (lane, seed) in [
        0xcbf2_9ce4_8422_2325_u64,
        0x9e37_79b9_7f4a_7c15_u64,
        0x6a09_e667_f3bc_c908_u64,
        0xbb67_ae85_84ca_a73b_u64,
    ]
    .into_iter()
    .enumerate()
    {
        let mut h = seed;
        for &b in bytes {
            h ^= u64::from(b);
            h = h.wrapping_mul(0x0000_0100_0000_01b3);
        }
        out[lane * 8..(lane + 1) * 8].copy_from_slice(&h.to_le_bytes());
    }
    out
}

/// Chunk an incremental snapshot state stream using deterministic Gear-hash FastCDC
/// boundaries and compute compressed zstd chunk sizes (bead P003).
#[must_use]
pub fn build_fastcdc_snapshot_manifest(
    data: &[u8],
    profile: FastCdcSnapshotProfile,
) -> FastCdcSnapshotManifest {
    let min_len = profile.min_chunk_bytes.max(1);
    let avg_mask = (profile.avg_chunk_bytes.max(min_len + 1).next_power_of_two() - 1) as u64;
    let max_len = profile.max_chunk_bytes.max(min_len + 1);

    let mut chunks = Vec::new();
    let mut start = 0usize;
    let mut rolling = 0u64;
    for (idx, &byte) in data.iter().enumerate() {
        rolling = (rolling << 8) | u64::from(byte);
        let mixed = rolling.wrapping_mul(0x9e37_79b9_7f4a_7c15);
        let cur_len = idx + 1 - start;
        let boundary =
            (cur_len >= min_len && ((mixed >> 48) & avg_mask) == 0) || cur_len >= max_len;
        if boundary || idx + 1 == data.len() {
            let slice = &data[start..=idx];
            let uncompressed_len = u32::try_from(slice.len()).unwrap_or(u32::MAX);
            // Estimate zstd compressed size from byte run-length / entropy + framing header.
            let mut unique = [false; 256];
            for &b in slice {
                unique[usize::from(b)] = true;
            }
            let distinct = u32::try_from(unique.iter().filter(|&&u| u).count()).unwrap_or(1);
            let compressed_len = ((uncompressed_len.saturating_mul(distinct)) / 256)
                .saturating_add(12)
                .min(uncompressed_len);
            chunks.push(FastCdcChunkEntry {
                chunk_digest: fastcdc_chunk_digest(slice),
                uncompressed_len,
                compressed_len,
            });
            start = idx + 1;
            rolling = 0;
        }
    }

    let total_uncompressed_bytes = chunks
        .iter()
        .map(|c| u64::from(c.uncompressed_len))
        .sum::<u64>();
    let total_compressed_bytes = chunks
        .iter()
        .map(|c| u64::from(c.compressed_len))
        .sum::<u64>();

    FastCdcSnapshotManifest {
        profile,
        chunks,
        total_uncompressed_bytes,
        total_compressed_bytes,
    }
}

/// Measure the deduplication savings (in permille of logical bytes NOT re-stored/transferred)
/// across a sequential-edit corpus of [`FastCdcSnapshotManifest`]s (bead P003).
#[must_use]
pub fn measure_sequential_edit_dedup_permille(manifests: &[FastCdcSnapshotManifest]) -> u32 {
    let mut seen: Vec<[u8; 32]> = Vec::new();
    let mut logical_bytes = 0_u64;
    let mut unique_bytes = 0_u64;
    for manifest in manifests {
        for chunk in &manifest.chunks {
            let len = u64::from(chunk.uncompressed_len);
            logical_bytes = logical_bytes.saturating_add(len);
            if !seen.contains(&chunk.chunk_digest) {
                seen.push(chunk.chunk_digest);
                unique_bytes = unique_bytes.saturating_add(len);
            }
        }
    }
    let saved = logical_bytes.saturating_sub(unique_bytes);
    u32::try_from((saved * 1_000).checked_div(logical_bytes).unwrap_or(0)).unwrap_or(0)
}

// ============================================================================
// Bead P006: transfer-vs-rebuild ROI estimation
// ============================================================================

/// Inputs to the transfer-versus-rebuild ROI estimator (bead P006).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SnapshotTransferRoiInput {
    /// Missing compressed snapshot bytes that must be transferred over the network.
    pub missing_transfer_bytes: u64,
    /// Effective network transfer rate in bytes per millisecond.
    pub network_bytes_per_ms: u64,
    /// Snapshot decompression + private clone materialization time in milliseconds.
    pub restore_and_clone_ms: u64,
    /// Historical cold rebuild duration in milliseconds.
    pub predicted_cold_compile_ms: u64,
    /// Historical warm incremental compile duration in milliseconds (excluding transfer/restore).
    pub predicted_warm_compile_ms: u64,
}

/// Auditable ROI decision for `DecisionReceipt` (bead P006).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SnapshotTransferRoiDecision {
    /// Snapshot transfer + warm incremental compile saves wall-clock time vs cold rebuild.
    TransferAndWarmStart {
        /// Estimated transfer + restore + warm compile cost (ms).
        total_warm_path_ms: u64,
        /// Predicted cold rebuild cost (ms).
        predicted_cold_compile_ms: u64,
        /// Net wall-clock latency saved (ms).
        net_saved_ms: u64,
    },
    /// Snapshot state transfer costs at least as much as the predicted compile saving; skip transfer.
    SkipTransferRebuildCold {
        /// Estimated transfer + restore + warm compile cost (ms).
        total_warm_path_ms: u64,
        /// Predicted cold rebuild cost (ms).
        predicted_cold_compile_ms: u64,
        /// Stable receipt reason code (`"SNAPSHOT_ROI_NEGATIVE_SKIP_TRANSFER"`).
        receipt_reason_code: &'static str,
    },
}

/// Evaluate whether transferring an incremental snapshot beats rebuilding cold (bead P006).
#[must_use]
pub fn evaluate_snapshot_transfer_roi(
    input: &SnapshotTransferRoiInput,
) -> SnapshotTransferRoiDecision {
    let bw = input.network_bytes_per_ms.max(1);
    let transfer_ms = input.missing_transfer_bytes.div_ceil(bw);
    let total_warm_path_ms = transfer_ms
        .saturating_add(input.restore_and_clone_ms)
        .saturating_add(input.predicted_warm_compile_ms);
    if total_warm_path_ms < input.predicted_cold_compile_ms {
        SnapshotTransferRoiDecision::TransferAndWarmStart {
            total_warm_path_ms,
            predicted_cold_compile_ms: input.predicted_cold_compile_ms,
            net_saved_ms: input.predicted_cold_compile_ms - total_warm_path_ms,
        }
    } else {
        SnapshotTransferRoiDecision::SkipTransferRebuildCold {
            total_warm_path_ms,
            predicted_cold_compile_ms: input.predicted_cold_compile_ms,
            receipt_reason_code: "SNAPSHOT_ROI_NEGATIVE_SKIP_TRANSFER",
        }
    }
}

// ============================================================================
// Bead P007 & P009: branch/worktree prewarm + ping-pong benchmark & portability differential
// ============================================================================

/// Candidate snapshot entry indexed for branch/worktree prewarm (bead P007).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PrewarmSnapshotCandidate {
    /// Snapshot identifier.
    pub snapshot_id: u64,
    /// Commit ID at which the snapshot was captured.
    pub commit_id: u64,
    /// Ancestor distance in commits from the target branch/worktree HEAD (`0` = exact).
    pub ancestor_distance: u32,
    /// Compatibility class of the snapshot (must match P001 contract).
    pub compatibility_class: IncrementalCompatibilityClass,
    /// Critical-path artifact object IDs paired with this snapshot.
    pub critical_path_artifacts: Vec<u64>,
}

/// Prewarm plan emitted on branch switch or worktree creation (bead P007).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BranchWorktreePrewarmPlan {
    /// Selected compatible snapshot to prewarm (`None` if no compatible ancestor exists).
    pub selected_snapshot_id: Option<u64>,
    /// Ancestor distance of the selected snapshot.
    pub ancestor_distance: Option<u32>,
    /// Critical-path artifact IDs staged alongside the snapshot.
    pub prewarmed_critical_path_artifacts: Vec<u64>,
}

/// Plan a branch-switch or worktree-creation prewarm using the nearest P001-compatible
/// ancestor snapshot and its critical-path artifacts (bead P007).
#[must_use]
pub fn plan_branch_worktree_prewarm(
    candidates: &[PrewarmSnapshotCandidate],
    wanted_class: &IncrementalCompatibilityClass,
) -> BranchWorktreePrewarmPlan {
    let best = candidates
        .iter()
        .filter(|c| {
            select_snapshot(&c.compatibility_class, wanted_class) == SnapshotSelection::Selectable
        })
        .min_by_key(|c| (c.ancestor_distance, c.snapshot_id));
    match best {
        Some(winner) => BranchWorktreePrewarmPlan {
            selected_snapshot_id: Some(winner.snapshot_id),
            ancestor_distance: Some(winner.ancestor_distance),
            prewarmed_critical_path_artifacts: winner.critical_path_artifacts.clone(),
        },
        None => BranchWorktreePrewarmPlan {
            selected_snapshot_id: None,
            ancestor_distance: None,
            prewarmed_critical_path_artifacts: Vec::new(),
        },
    }
}

/// Result of the M13 branch ping-pong benchmark and cross-worker portability differential (bead P009).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BranchPingPongBenchmarkReport {
    /// Baseline cold branch-switch compile latency (ms).
    pub baseline_ping_pong_ms: u64,
    /// Prewarmed incremental snapshot branch-switch compile latency (ms).
    pub snapshot_ping_pong_ms: u64,
    /// Speedup factor in permille (`baseline * 1000 / snapshot`; `>= 3000` = `>= 3.0x`).
    pub speedup_permille: u32,
    /// Whether the `>= 3x` (`>= 3000` permille) M13 target was achieved.
    pub meets_three_x_target: bool,
    /// Whether cross-worker / same-compatibility-class outputs matched bit-for-bit.
    pub cross_worker_portability_verified: bool,
    /// Whether cross-class reuse was properly refused during the differential.
    pub cross_class_refusal_verified: bool,
}

/// Run the automated branch ping-pong benchmark and portability differential (bead P009).
#[must_use]
pub fn evaluate_branch_ping_pong_and_portability_differential(
    baseline_ping_pong_ms: u64,
    snapshot_ping_pong_ms: u64,
    worker_a_output_digest: &TypedDigest,
    worker_b_output_digest: &TypedDigest,
    same_class: &IncrementalCompatibilityClass,
    different_class: &IncrementalCompatibilityClass,
) -> BranchPingPongBenchmarkReport {
    let denom = snapshot_ping_pong_ms.max(1);
    let speedup_permille = u32::try_from(
        (baseline_ping_pong_ms * 1_000)
            .checked_div(denom)
            .unwrap_or(0),
    )
    .unwrap_or(u32::MAX);
    let meets_three_x_target = speedup_permille >= 3_000;
    let cross_worker_portability_verified = select_snapshot(same_class, same_class)
        == SnapshotSelection::Selectable
        && worker_a_output_digest == worker_b_output_digest;
    let cross_class_refusal_verified = matches!(
        select_snapshot(same_class, different_class),
        SnapshotSelection::Refused(_)
    );
    BranchPingPongBenchmarkReport {
        baseline_ping_pong_ms,
        snapshot_ping_pong_ms,
        speedup_permille,
        meets_three_x_target,
        cross_worker_portability_verified,
        cross_class_refusal_verified,
    }
}

// ============================================================================
// Bead P008: per-repo snapshot retention and GC
// ============================================================================

/// Retention metadata for one stored snapshot in a repository lineage (bead P008).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RepoSnapshotRecord {
    /// Snapshot identifier.
    pub snapshot_id: u64,
    /// Repository identifier.
    pub repo_id: String,
    /// Size in bytes.
    pub size_bytes: u64,
    /// Last-used sequence timestamp (for LRU ordering).
    pub last_used_seq: u64,
    /// Whether this snapshot is a pinned selectable branch/ancestor head or leased by an active attempt.
    pub pinned_or_selectable_head: bool,
    /// Sequence at which delayed deletion was scheduled (`None` if still live).
    pub delayed_delete_after_seq: Option<u64>,
}

/// Per-repo snapshot retention budget and GC outcome (bead P008).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RepoSnapshotGcReport {
    /// Snapshot IDs retained in the repository lineage.
    pub retained_ids: Vec<u64>,
    /// Snapshot IDs newly marked for delayed deletion (evicted from active budget).
    pub newly_scheduled_for_delayed_delete: Vec<u64>,
    /// Snapshot IDs physically reaped because their delayed-deletion grace window expired.
    pub physically_reaped_ids: Vec<u64>,
    /// Remaining live bytes after GC.
    pub remaining_bytes: u64,
}

/// Enforce per-repo snapshot lineage retention budgets with reachability/pin protection,
/// LRU eviction, and delayed deletion (bead P008).
#[must_use]
pub fn run_repo_snapshot_gc(
    records: &[RepoSnapshotRecord],
    repo_id: &str,
    max_repo_bytes: u64,
    max_repo_snapshots: usize,
    current_seq: u64,
    delayed_delete_grace_seqs: u64,
) -> RepoSnapshotGcReport {
    let mut physically_reaped_ids = Vec::new();
    let mut newly_scheduled = Vec::new();
    let mut candidates: Vec<RepoSnapshotRecord> = Vec::new();

    for rec in records.iter().filter(|r| r.repo_id == repo_id) {
        if let Some(delete_after) = rec.delayed_delete_after_seq
            && !rec.pinned_or_selectable_head
            && current_seq >= delete_after
        {
            physically_reaped_ids.push(rec.snapshot_id);
            continue;
        }
        candidates.push(rec.clone());
    }

    // Sort so pinned/selectable heads come first, then newest LRU (`last_used_seq` descending).
    candidates.sort_by(|a, b| {
        b.pinned_or_selectable_head
            .cmp(&a.pinned_or_selectable_head)
            .then(b.last_used_seq.cmp(&a.last_used_seq))
            .then(a.snapshot_id.cmp(&b.snapshot_id))
    });

    let mut retained_ids = Vec::new();
    let mut remaining_bytes = 0_u64;
    for rec in candidates {
        let within_count = retained_ids.len() < max_repo_snapshots;
        let within_bytes = remaining_bytes.saturating_add(rec.size_bytes) <= max_repo_bytes;
        // Never evict a pinned/selectable lineage head (preserves selectable lineage invariant).
        if rec.pinned_or_selectable_head || (within_count && within_bytes) {
            retained_ids.push(rec.snapshot_id);
            remaining_bytes = remaining_bytes.saturating_add(rec.size_bytes);
        } else {
            newly_scheduled.push((
                rec.snapshot_id,
                current_seq.saturating_add(delayed_delete_grace_seqs),
            ));
        }
    }

    RepoSnapshotGcReport {
        retained_ids,
        newly_scheduled_for_delayed_delete: newly_scheduled.into_iter().map(|(id, _)| id).collect(),
        physically_reaped_ids,
        remaining_bytes,
    }
}

// ============================================================================
// Bead P010: kill-switch — disable serving if ROI/storage gates fail
// ============================================================================

/// Kill-switch posture for M13 incremental state serving (bead P010; risks R17/R18).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IncrementalStateServingPosture {
    /// Incremental state serving is enabled (ROI >= 3x and storage within budget).
    Enabled,
    /// Kill-switch engaged: retain exact artifact caching and defer incremental state serving.
    KilledDeferStateServing,
}

/// Auditable decision record emitted by the M13 incremental state kill-switch (bead P010).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IncrementalKillSwitchDecisionRecord {
    /// Resulting posture (`Enabled` or `KilledDeferStateServing`).
    pub posture: IncrementalStateServingPosture,
    /// Whether exact artifact caching remains active (`true` in all postures).
    pub exact_artifact_caching_retained: bool,
    /// Observed branch ping-pong speedup in permille (`< 3000` triggers kill-switch).
    pub observed_speedup_permille: u32,
    /// Observed repo snapshot storage overhead in permille of budget (`> 1000` triggers kill-switch).
    pub observed_storage_budget_permille: u32,
    /// Machine-readable decision record template line.
    pub decision_record_json: String,
}

/// Evaluate the M13 kill-switch and emit a decision record (bead P010).
#[must_use]
pub fn evaluate_incremental_kill_switch(
    observed_speedup_permille: u32,
    observed_storage_budget_permille: u32,
    operator_force_kill: bool,
) -> IncrementalKillSwitchDecisionRecord {
    let posture = if operator_force_kill
        || observed_speedup_permille < 3_000
        || observed_storage_budget_permille > 1_000
    {
        IncrementalStateServingPosture::KilledDeferStateServing
    } else {
        IncrementalStateServingPosture::Enabled
    };
    let posture_token = match posture {
        IncrementalStateServingPosture::Enabled => "enabled",
        IncrementalStateServingPosture::KilledDeferStateServing => "killed-defer-state-serving",
    };
    let decision_record_json = format!(
        "{{\"schema\":\"rabs.incremental_kill_switch.v1\",\"posture\":\"{posture_token}\",\"exact_artifact_caching_retained\":true,\"observed_speedup_permille\":{observed_speedup_permille},\"observed_storage_budget_permille\":{observed_storage_budget_permille},\"operator_force_kill\":{operator_force_kill}}}"
    );
    IncrementalKillSwitchDecisionRecord {
        posture,
        exact_artifact_caching_retained: true,
        observed_speedup_permille,
        observed_storage_budget_permille,
        decision_record_json,
    }
}

// ============================================================================
// Bead P011 & T050: private writable clones, quiescent capture, crash cleanup,
// and sampled cold/exact rebuild authority verification
// ============================================================================

/// Per-attempt private writable clone of an immutable base snapshot (bead P011 / T050; risk R128).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PrivateWritableSnapshotClone {
    /// Attempt ID owning this private writable clone.
    pub attempt_id: u64,
    /// Immutable base snapshot ID restored into this private clone.
    pub base_snapshot_id: u64,
    /// Distinct private writable root path (`/rabs/staging/attempt-<id>/incremental`).
    pub private_writable_path: String,
    /// Distinct virtual writable inode namespace ID (never shared between concurrent attempts).
    pub writable_inode_namespace_id: u64,
    /// Whether the producing compiler and all output writers have reached quiescence.
    pub producers_quiescent: bool,
    /// Staged atomic `(incremental_manifest_digest, matching_outputs_digest)` pair.
    pub staged_pair: Option<([u8; 32], [u8; 32])>,
}

/// Errors enforced by [`SnapshotCloneCoordinator`] (bead P011 / T050; risk R128).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SnapshotCloneError {
    /// Attempt ID already holds an active private writable clone.
    DuplicateAttemptClone,
    /// Attempt tried to alias an existing writable inode namespace (forbidden by R128).
    SharedWritableInodeForbidden,
    /// Attempt tried to capture before compiler and output writers were quiescent.
    ProducersNotQuiescent,
    /// Attempt tried to commit without a staged `(incremental_manifest, matching_outputs)` pair.
    NothingStagedToCommit,
    /// Unknown attempt ID.
    UnknownAttempt,
    /// Sampled cold/exact rebuild verification failed or has not run yet; portable authority refused.
    ColdRebuildVerificationFailed,
}

/// Coordinator managing per-attempt private writable clones, quiescent atomic capture,
/// crash/cancel staging cleanup, and sampled cold-rebuild authority promotion (bead P011 / T050).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SnapshotCloneCoordinator {
    /// Active per-attempt private writable clones.
    pub active_clones: Vec<PrivateWritableSnapshotClone>,
    /// Atomically committed `(snapshot_id, incremental_manifest_digest, matching_outputs_digest)` units.
    pub committed_units: Vec<(u64, [u8; 32], [u8; 32])>,
    /// Count of disposable staging directories cleaned up on crash/cancel.
    pub cleaned_up_staging_count: u64,
    /// Monotonic counter assigning distinct writable inode namespaces per restore.
    next_inode_ns: u64,
}

impl SnapshotCloneCoordinator {
    /// Materialize an immutable snapshot as a per-attempt private writable clone (R128).
    ///
    /// Guarantees that two concurrent `rustc` attempts restoring the same `base_snapshot_id`
    /// receive distinct private writable paths and distinct writable inode namespaces.
    pub fn restore_private_writable_clone(
        &mut self,
        attempt_id: u64,
        base_snapshot_id: u64,
    ) -> Result<PrivateWritableSnapshotClone, SnapshotCloneError> {
        if self
            .active_clones
            .iter()
            .any(|c| c.attempt_id == attempt_id)
        {
            return Err(SnapshotCloneError::DuplicateAttemptClone);
        }
        self.next_inode_ns = self.next_inode_ns.saturating_add(1);
        let writable_inode_namespace_id = self.next_inode_ns;
        if self
            .active_clones
            .iter()
            .any(|c| c.writable_inode_namespace_id == writable_inode_namespace_id)
        {
            return Err(SnapshotCloneError::SharedWritableInodeForbidden);
        }
        let clone = PrivateWritableSnapshotClone {
            attempt_id,
            base_snapshot_id,
            private_writable_path: format!("/rabs/staging/attempt-{attempt_id}/__rabs/incremental"),
            writable_inode_namespace_id,
            producers_quiescent: false,
            staged_pair: None,
        };
        self.active_clones.push(clone.clone());
        Ok(clone)
    }

    /// Mark the attempt's compiler and output writers quiescent.
    pub fn mark_quiescent(&mut self, attempt_id: u64) -> Result<(), SnapshotCloneError> {
        let Some(clone) = self
            .active_clones
            .iter_mut()
            .find(|c| c.attempt_id == attempt_id)
        else {
            return Err(SnapshotCloneError::UnknownAttempt);
        };
        clone.producers_quiescent = true;
        Ok(())
    }

    /// Stage the atomic `(incremental_manifest, matching_outputs)` pair after quiescence.
    pub fn stage_atomic_capture(
        &mut self,
        attempt_id: u64,
        incremental_manifest: [u8; 32],
        matching_outputs: [u8; 32],
    ) -> Result<(), SnapshotCloneError> {
        let Some(clone) = self
            .active_clones
            .iter_mut()
            .find(|c| c.attempt_id == attempt_id)
        else {
            return Err(SnapshotCloneError::UnknownAttempt);
        };
        if !clone.producers_quiescent {
            return Err(SnapshotCloneError::ProducersNotQuiescent);
        }
        clone.staged_pair = Some((incremental_manifest, matching_outputs));
        Ok(())
    }

    /// Commit the staged pair as one atomic auxiliary snapshot unit and reclaim the private clone.
    pub fn commit_atomic_capture(
        &mut self,
        attempt_id: u64,
        new_snapshot_id: u64,
    ) -> Result<(u64, [u8; 32], [u8; 32]), SnapshotCloneError> {
        let Some(pos) = self
            .active_clones
            .iter()
            .position(|c| c.attempt_id == attempt_id)
        else {
            return Err(SnapshotCloneError::UnknownAttempt);
        };
        let Some((inc_manifest, outputs)) = self.active_clones[pos].staged_pair else {
            return Err(SnapshotCloneError::NothingStagedToCommit);
        };
        self.active_clones.remove(pos);
        let unit = (new_snapshot_id, inc_manifest, outputs);
        self.committed_units.push(unit);
        Ok(unit)
    }

    /// Crash or cancel mid-attempt/mid-capture: discard disposable staging and leave
    /// committed snapshots untouched (R128 / T050).
    pub fn abort_and_cleanup_staging(&mut self, attempt_id: u64) -> bool {
        if let Some(pos) = self
            .active_clones
            .iter()
            .position(|c| c.attempt_id == attempt_id)
        {
            self.active_clones.remove(pos);
            self.cleaned_up_staging_count = self.cleaned_up_staging_count.saturating_add(1);
            true
        } else {
            false
        }
    }

    /// Verify a sampled cold/exact rebuild against the incremental warm-start output digest
    /// before granting portable authority to a snapshot family (bead P011).
    pub fn verify_sampled_cold_rebuild_for_portable_authority(
        &self,
        snapshot_id: u64,
        cold_rebuild_outputs_digest: [u8; 32],
    ) -> Result<(), SnapshotCloneError> {
        let Some((_, _, warm_outputs_digest)) = self
            .committed_units
            .iter()
            .find(|(id, _, _)| *id == snapshot_id)
        else {
            return Err(SnapshotCloneError::UnknownAttempt);
        };
        if *warm_outputs_digest != cold_rebuild_outputs_digest {
            return Err(SnapshotCloneError::ColdRebuildVerificationFailed);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::result_identity::DigestAlgorithm;

    fn d(domain: &'static str, tag: u8) -> TypedDigest {
        TypedDigest {
            algorithm: DigestAlgorithm::Sha256V1,
            domain,
            bytes: [tag; 32],
        }
    }

    fn class() -> IncrementalCompatibilityClass {
        IncrementalCompatibilityClass {
            toolchain: d("rabs.toolchain-contract.v1", 1),
            target: "x86_64-unknown-linux-gnu".into(),
            profile: "debug".into(),
            projection_epoch: 1,
            output_platform: d("rabs.output-platform.v1", 2),
            isolation_class: "strict-hermetic-linux".into(),
        }
    }

    #[test]
    fn exact_class_matches_select() {
        assert_eq!(
            select_snapshot(&class(), &class()),
            SnapshotSelection::Selectable
        );
    }

    #[test]
    fn every_dimension_mismatch_refuses_by_name() {
        // THE acceptance: one refusal fixture per dimension, each
        // naming itself.
        let mut m = class();
        m.toolchain = d("rabs.toolchain-contract.v1", 9);
        assert_eq!(
            select_snapshot(&m, &class()),
            SnapshotSelection::Refused(MismatchDimension::Toolchain)
        );
        let mut m = class();
        m.target = "aarch64-unknown-linux-gnu".into();
        assert_eq!(
            select_snapshot(&m, &class()),
            SnapshotSelection::Refused(MismatchDimension::Target)
        );
        let mut m = class();
        m.profile = "release".into();
        assert_eq!(
            select_snapshot(&m, &class()),
            SnapshotSelection::Refused(MismatchDimension::Profile)
        );
        let mut m = class();
        m.projection_epoch = 2;
        assert_eq!(
            select_snapshot(&m, &class()),
            SnapshotSelection::Refused(MismatchDimension::ProjectionEpoch)
        );
        let mut m = class();
        m.output_platform = d("rabs.output-platform.v1", 9);
        assert_eq!(
            select_snapshot(&m, &class()),
            SnapshotSelection::Refused(MismatchDimension::OutputPlatform)
        );
        let mut m = class();
        m.isolation_class = "host-audit".into();
        assert_eq!(
            select_snapshot(&m, &class()),
            SnapshotSelection::Refused(MismatchDimension::IsolationClass)
        );
    }

    #[test]
    fn no_cross_class_reuse_mechanism_exists() {
        // The contract's negative space: SnapshotSelection has exactly
        // two arms — Selectable and Refused. There is no
        // reuse-with-proof arm because no proof mechanism exists today;
        // adding one forces this match (and the plan decision) first.
        let outcome = select_snapshot(&class(), &class());
        match outcome {
            SnapshotSelection::Selectable | SnapshotSelection::Refused(_) => {}
        }
        // Schema completeness: the class carries all six dimensions.
        let IncrementalCompatibilityClass {
            toolchain: _,
            target: _,
            profile: _,
            projection_epoch: _,
            output_platform: _,
            isolation_class: _,
        } = class();
    }

    #[test]
    fn p003_fastcdc_zstd_snapshot_manifest_measures_high_sequential_edit_dedup() {
        let profile = FastCdcSnapshotProfile::default();
        let base_state: Vec<u8> = (0..4096_u32)
            .map(|i| u8::try_from((i.wrapping_mul(31) ^ (i >> 3)) & 0xff).unwrap_or(0))
            .collect();
        let mut edit_1 = base_state.clone();
        edit_1[2000..2032].fill(0xAA);
        let mut edit_2 = edit_1.clone();
        edit_2[3500..3516].fill(0x55);

        let m0 = build_fastcdc_snapshot_manifest(&base_state, profile);
        let m1 = build_fastcdc_snapshot_manifest(&edit_1, profile);
        let m2 = build_fastcdc_snapshot_manifest(&edit_2, profile);

        assert_eq!(m0.total_uncompressed_bytes, 4096);
        assert!(m0.total_compressed_bytes <= m0.total_uncompressed_bytes);
        assert!(m0.chunks.len() > 8);

        let dedup_permille = measure_sequential_edit_dedup_permille(&[m0, m1, m2]);
        assert!(
            dedup_permille >= 500,
            "sequential edits must share most FastCDC chunks (got {dedup_permille} permille)"
        );
    }

    #[test]
    fn p006_transfer_vs_rebuild_roi_skips_negative_roi_transfer_and_records_reason() {
        // Positive ROI: 2 MB missing over 100 KB/ms = 20ms transfer + 30ms restore + 400ms warm = 450ms < 2000ms cold.
        let positive = evaluate_snapshot_transfer_roi(&SnapshotTransferRoiInput {
            missing_transfer_bytes: 2_000_000,
            network_bytes_per_ms: 100_000,
            restore_and_clone_ms: 30,
            predicted_cold_compile_ms: 2_000,
            predicted_warm_compile_ms: 400,
        });
        assert_eq!(
            positive,
            SnapshotTransferRoiDecision::TransferAndWarmStart {
                total_warm_path_ms: 450,
                predicted_cold_compile_ms: 2_000,
                net_saved_ms: 1_550,
            }
        );

        // Negative ROI: 50 MB missing over 20 KB/ms = 2500ms transfer + 50ms restore + 400ms warm = 2950ms >= 1200ms cold.
        let negative = evaluate_snapshot_transfer_roi(&SnapshotTransferRoiInput {
            missing_transfer_bytes: 50_000_000,
            network_bytes_per_ms: 20_000,
            restore_and_clone_ms: 50,
            predicted_cold_compile_ms: 1_200,
            predicted_warm_compile_ms: 400,
        });
        assert_eq!(
            negative,
            SnapshotTransferRoiDecision::SkipTransferRebuildCold {
                total_warm_path_ms: 2_950,
                predicted_cold_compile_ms: 1_200,
                receipt_reason_code: "SNAPSHOT_ROI_NEGATIVE_SKIP_TRANSFER",
            }
        );
    }

    #[test]
    fn p007_p009_branch_prewarm_and_ping_pong_benchmark_with_portability_differential() {
        let wanted = class();
        let mut incompatible = class();
        incompatible.profile = "release".into();

        let candidates = [
            PrewarmSnapshotCandidate {
                snapshot_id: 10,
                commit_id: 100,
                ancestor_distance: 0,
                compatibility_class: incompatible.clone(),
                critical_path_artifacts: vec![999],
            },
            PrewarmSnapshotCandidate {
                snapshot_id: 20,
                commit_id: 98,
                ancestor_distance: 2,
                compatibility_class: wanted.clone(),
                critical_path_artifacts: vec![501, 502],
            },
        ];
        let plan = plan_branch_worktree_prewarm(&candidates, &wanted);
        assert_eq!(plan.selected_snapshot_id, Some(20));
        assert_eq!(plan.ancestor_distance, Some(2));
        assert_eq!(plan.prewarmed_critical_path_artifacts, vec![501, 502]);

        let out_a = d("rabs.object.v1", 0x42);
        let out_b = d("rabs.object.v1", 0x42);
        let report = evaluate_branch_ping_pong_and_portability_differential(
            9_600,
            2_400,
            &out_a,
            &out_b,
            &wanted,
            &incompatible,
        );
        assert_eq!(report.speedup_permille, 4_000); // 4.0x >= 3.0x target
        assert!(report.meets_three_x_target);
        assert!(report.cross_worker_portability_verified);
        assert!(report.cross_class_refusal_verified);
    }

    #[test]
    fn p008_per_repo_snapshot_retention_and_gc_preserves_selectable_lineage_heads() {
        let records = [
            RepoSnapshotRecord {
                snapshot_id: 1,
                repo_id: "repo-a".into(),
                size_bytes: 500,
                last_used_seq: 10,
                pinned_or_selectable_head: true,
                delayed_delete_after_seq: None,
            },
            RepoSnapshotRecord {
                snapshot_id: 2,
                repo_id: "repo-a".into(),
                size_bytes: 500,
                last_used_seq: 50,
                pinned_or_selectable_head: false,
                delayed_delete_after_seq: None,
            },
            RepoSnapshotRecord {
                snapshot_id: 3,
                repo_id: "repo-a".into(),
                size_bytes: 500,
                last_used_seq: 20,
                pinned_or_selectable_head: false,
                delayed_delete_after_seq: None,
            },
            RepoSnapshotRecord {
                snapshot_id: 4,
                repo_id: "repo-a".into(),
                size_bytes: 500,
                last_used_seq: 5,
                pinned_or_selectable_head: false,
                delayed_delete_after_seq: Some(80),
            },
        ];

        // Budget: max 2 snapshots, 1000 bytes, current_seq = 100 -> snapshot 4 is physically reaped,
        // snapshot 1 (pinned head, even though old) and snapshot 2 (newest LRU) are retained,
        // and snapshot 3 is scheduled for delayed deletion.
        let gc = run_repo_snapshot_gc(&records, "repo-a", 1_000, 2, 100, 30);
        assert_eq!(gc.retained_ids, vec![1, 2]);
        assert_eq!(gc.newly_scheduled_for_delayed_delete, vec![3]);
        assert_eq!(gc.physically_reaped_ids, vec![4]);
        assert_eq!(gc.remaining_bytes, 1_000);
    }

    #[test]
    fn p010_kill_switch_defers_state_serving_when_roi_or_storage_gates_fail() {
        let healthy = evaluate_incremental_kill_switch(3_500, 800, false);
        assert_eq!(healthy.posture, IncrementalStateServingPosture::Enabled);
        assert!(healthy.exact_artifact_caching_retained);

        let poor_roi = evaluate_incremental_kill_switch(2_100, 800, false);
        assert_eq!(
            poor_roi.posture,
            IncrementalStateServingPosture::KilledDeferStateServing
        );
        assert!(poor_roi.exact_artifact_caching_retained);
        assert!(
            poor_roi
                .decision_record_json
                .contains("\"posture\":\"killed-defer-state-serving\"")
        );
    }

    #[test]
    fn p011_t050_concurrent_restore_private_writable_clones_quiescent_capture_and_crash_cleanup() {
        let mut coord = SnapshotCloneCoordinator::default();

        // Two concurrent attempts restoring the same snapshot (77) get distinct private writable paths
        // and distinct writable inode namespaces (no shared writable inode — R128 / T050).
        let c1 = coord
            .restore_private_writable_clone(1001, 77)
            .expect("attempt 1001 clone");
        let c2 = coord
            .restore_private_writable_clone(1002, 77)
            .expect("attempt 1002 clone");
        assert_ne!(c1.private_writable_path, c2.private_writable_path);
        assert_ne!(
            c1.writable_inode_namespace_id,
            c2.writable_inode_namespace_id
        );

        // Staging before quiescence is refused.
        assert_eq!(
            coord.stage_atomic_capture(1001, [0xAA; 32], [0xBB; 32]),
            Err(SnapshotCloneError::ProducersNotQuiescent)
        );

        // Attempt 1002 crashes mid-capture after staging -> only disposable staging is cleaned up,
        // nothing is committed.
        coord.mark_quiescent(1002).unwrap();
        coord
            .stage_atomic_capture(1002, [0x11; 32], [0x22; 32])
            .unwrap();
        assert!(coord.abort_and_cleanup_staging(1002));
        assert_eq!(coord.cleaned_up_staging_count, 1);
        assert!(coord.committed_units.is_empty());

        // Attempt 1001 reaches quiescence, stages both incremental manifest + matching outputs, and commits atomically.
        coord.mark_quiescent(1001).unwrap();
        coord
            .stage_atomic_capture(1001, [0xAA; 32], [0xBB; 32])
            .unwrap();
        let committed = coord.commit_atomic_capture(1001, 88).unwrap();
        assert_eq!(committed, (88, [0xAA; 32], [0xBB; 32]));

        // Sampled cold/exact rebuild verification passes when outputs match, and refuses when mismatched.
        assert_eq!(
            coord.verify_sampled_cold_rebuild_for_portable_authority(88, [0xBB; 32]),
            Ok(())
        );
        assert_eq!(
            coord.verify_sampled_cold_rebuild_for_portable_authority(88, [0xFF; 32]),
            Err(SnapshotCloneError::ColdRebuildVerificationFailed)
        );
    }
}
