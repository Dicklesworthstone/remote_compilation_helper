//! Mount-aware build-root and cargo-home selection policy
//! (bd-session-history-remediation-ocv9i.11.1).
//!
//! Session history showed builds landing on a RAM-backed `/tmp` (tmpfs) or a
//! tiny root filesystem, then exhausting RAM or disk mid-compile. The remote
//! execution path already keeps caches off tmpfs `/tmp` via a shell prelude
//! (`$TMPDIR → /data/tmp → /tmp`, see
//! [`rch_common::remote_compilation::remote_cargo_home_base_prelude`]), but
//! that heuristic is unexplained and does not consider free space or inodes.
//!
//! This module adds a structured, **explainable** policy the daemon applies
//! before admission: given per-root [`MountStats`] (free bytes + inodes + the
//! filesystem backing kind, supplied by worker telemetry / worker facts — the
//! daemon does not probe worker mounts locally), it
//! - rejects roots below the free-bytes or free-inode thresholds,
//! - avoids RAM-backed (tmpfs) roots whenever a disk-backed safe root exists,
//! - honors an explicit worker override when it is itself safe,
//! - and reports the chosen root with a rationale plus every rejection reason,
//!   or declares the worker unsafe when no root qualifies.
//!
//! The selection is a pure function over gathered stats so the four required
//! scenarios — tmpfs pressure, disk-backed fallback, inode exhaustion, and
//! worker-specific overrides — are unit-tested without touching a real
//! filesystem.

// Foundational policy for bd-...-11.1: the pre-admission caller (admission /
// worker-fact consumer, bd-...-6.x / .12.1) wires this in as a follow-on.
#![allow(dead_code)]

use serde::Serialize;

/// Default minimum free bytes a build root must have to be considered safe.
/// A cold cargo build of a medium workspace plus its target dir comfortably
/// exceeds 1 GiB; 2 GiB leaves headroom for incremental artifacts.
pub const DEFAULT_MIN_FREE_BYTES: u64 = 2 * 1024 * 1024 * 1024;

/// Default minimum free inodes. A cargo target dir creates tens of thousands of
/// small files; 50k is a conservative floor that still rejects a nearly
/// inode-exhausted filesystem.
pub const DEFAULT_MIN_FREE_INODES: u64 = 50_000;

/// Filesystem backing kind of a candidate root.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FsKind {
    /// A persistent disk-backed filesystem (ext4, xfs, btrfs, overlay, …).
    Disk,
    /// A RAM-backed filesystem (tmpfs / ramfs) — avoided when a disk root
    /// exists, since large build trees would consume RAM.
    Tmpfs,
    /// Backing kind could not be determined; treated as neither preferred nor
    /// RAM-avoided.
    Unknown,
}

/// The role a candidate root plays, for diagnostics.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RootRole {
    /// The filesystem root `/`.
    FilesystemRoot,
    /// `/tmp`.
    Tmp,
    /// Configured cargo home base.
    CargoHome,
    /// Configured cargo target root.
    TargetRoot,
    /// RCH source-sync root.
    SyncRoot,
    /// A worker-specific override path.
    Override,
}

/// Free-space / inode stats for one candidate root. `free_inodes == u64::MAX`
/// encodes "filesystem does not report inode counts" (e.g. some tmpfs), which
/// is treated as "inodes not a constraint".
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MountStats {
    pub path: String,
    pub fs_kind: FsKind,
    pub free_bytes: u64,
    pub free_inodes: u64,
}

/// A candidate root plus whether it is an explicit worker override (overrides
/// win when safe).
#[derive(Debug, Clone)]
pub struct RootCandidate {
    pub role: RootRole,
    pub stats: MountStats,
    pub is_override: bool,
}

impl RootCandidate {
    pub fn new(role: RootRole, stats: MountStats, is_override: bool) -> Self {
        Self {
            role,
            stats,
            is_override,
        }
    }
}

/// Thresholds below which a root is unsafe.
#[derive(Debug, Clone, Copy)]
pub struct RootSafetyThresholds {
    pub min_free_bytes: u64,
    pub min_free_inodes: u64,
}

impl Default for RootSafetyThresholds {
    fn default() -> Self {
        Self {
            min_free_bytes: DEFAULT_MIN_FREE_BYTES,
            min_free_inodes: DEFAULT_MIN_FREE_INODES,
        }
    }
}

/// Why a candidate was rejected.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RejectReason {
    /// Free bytes below the threshold.
    InsufficientBytes,
    /// Free inodes below the threshold.
    InsufficientInodes,
    /// RAM-backed root skipped because a disk-backed safe root exists.
    RamBackedAvoided,
}

/// A rejected candidate and the reason.
#[derive(Debug, Clone, Serialize)]
pub struct RejectedRoot {
    pub path: String,
    pub role: RootRole,
    pub fs_kind: FsKind,
    pub reason: RejectReason,
    pub detail: String,
}

/// The selected root and the rationale for choosing it.
#[derive(Debug, Clone, Serialize)]
pub struct ChosenRoot {
    pub path: String,
    pub role: RootRole,
    pub fs_kind: FsKind,
    pub free_bytes: u64,
    pub free_inodes: u64,
    pub rationale: String,
}

/// The full mount-aware decision. The chosen root is where both the cargo
/// target dir and the isolated CARGO_HOME staging base should live (they
/// colocate, matching the remote prelude).
#[derive(Debug, Clone, Serialize)]
pub struct BuildRootDecision {
    /// The selected build/cargo root, or `None` when no candidate is safe.
    pub chosen: Option<ChosenRoot>,
    /// Every candidate that was not chosen, with the reason.
    pub rejected: Vec<RejectedRoot>,
    /// True iff a safe root was chosen. When false the worker must be rejected
    /// for builds requiring a safe root.
    pub safe: bool,
    /// Operator/agent-facing explanation of the decision.
    pub explanation: String,
}

/// Whether a candidate meets the byte/inode thresholds (ignoring tmpfs policy).
fn threshold_rejection(
    stats: &MountStats,
    thresholds: RootSafetyThresholds,
) -> Option<(RejectReason, String)> {
    if stats.free_bytes < thresholds.min_free_bytes {
        return Some((
            RejectReason::InsufficientBytes,
            format!(
                "{} free < {} required",
                stats.free_bytes, thresholds.min_free_bytes
            ),
        ));
    }
    if stats.free_inodes < thresholds.min_free_inodes {
        return Some((
            RejectReason::InsufficientInodes,
            format!(
                "{} free inodes < {} required",
                stats.free_inodes, thresholds.min_free_inodes
            ),
        ));
    }
    None
}

/// Rank a *threshold-safe* candidate. Higher tuple sorts first:
/// 1. explicit overrides win,
/// 2. disk-backed beats unknown beats tmpfs,
/// 3. then more free bytes.
fn candidate_rank(c: &RootCandidate) -> (u8, u8, u64) {
    let override_rank = u8::from(c.is_override);
    let fs_rank = match c.stats.fs_kind {
        FsKind::Disk => 2,
        FsKind::Unknown => 1,
        FsKind::Tmpfs => 0,
    };
    (override_rank, fs_rank, c.stats.free_bytes)
}

/// Apply the mount-aware policy to a pool of candidate roots.
///
/// See the module docs for the full contract. Pure — no filesystem access.
pub fn evaluate_build_roots(
    candidates: &[RootCandidate],
    thresholds: RootSafetyThresholds,
) -> BuildRootDecision {
    let mut rejected = Vec::new();

    // Phase 1: split on the hard byte/inode thresholds.
    let mut threshold_safe: Vec<&RootCandidate> = Vec::new();
    for c in candidates {
        match threshold_rejection(&c.stats, thresholds) {
            Some((reason, detail)) => rejected.push(RejectedRoot {
                path: c.stats.path.clone(),
                role: c.role,
                fs_kind: c.stats.fs_kind,
                reason,
                detail,
            }),
            None => threshold_safe.push(c),
        }
    }

    // Phase 2: RAM-backed avoidance. If any threshold-safe disk-backed root
    // exists, drop the tmpfs ones (they would eat RAM). An override is exempt
    // — an operator who points the build at a tmpfs path on purpose keeps it.
    let has_safe_disk = threshold_safe
        .iter()
        .any(|c| c.stats.fs_kind == FsKind::Disk);
    let mut eligible: Vec<&RootCandidate> = Vec::new();
    for c in threshold_safe {
        if c.stats.fs_kind == FsKind::Tmpfs && has_safe_disk && !c.is_override {
            rejected.push(RejectedRoot {
                path: c.stats.path.clone(),
                role: c.role,
                fs_kind: c.stats.fs_kind,
                reason: RejectReason::RamBackedAvoided,
                detail: "RAM-backed root skipped; a disk-backed root is available".to_string(),
            });
        } else {
            eligible.push(c);
        }
    }

    // Phase 3: rank the survivors and choose (highest rank first).
    eligible.sort_by_key(|c| std::cmp::Reverse(candidate_rank(c)));
    match eligible.first() {
        Some(best) => {
            let kind_note = match best.stats.fs_kind {
                FsKind::Disk => "disk-backed",
                FsKind::Tmpfs => "RAM-backed (no disk-backed root available)",
                FsKind::Unknown => "unknown-backing",
            };
            let override_note = if best.is_override {
                " (worker override)"
            } else {
                ""
            };
            let rationale = format!(
                "selected {} {root}{override_note}: {kind_note}, {} bytes / {} inodes free",
                best.role_str(),
                best.stats.free_bytes,
                best.stats.free_inodes,
                root = best.stats.path,
            );
            let explanation = format!("{rationale}; {} candidate(s) rejected", rejected.len());
            BuildRootDecision {
                chosen: Some(ChosenRoot {
                    path: best.stats.path.clone(),
                    role: best.role,
                    fs_kind: best.stats.fs_kind,
                    free_bytes: best.stats.free_bytes,
                    free_inodes: best.stats.free_inodes,
                    rationale,
                }),
                rejected,
                safe: true,
                explanation,
            }
        }
        None => BuildRootDecision {
            chosen: None,
            rejected,
            safe: false,
            explanation: "no safe build root: every candidate is below the free-bytes/inode \
                threshold or RAM-backed with no disk-backed alternative"
                .to_string(),
        },
    }
}

impl RootCandidate {
    fn role_str(&self) -> &'static str {
        match self.role {
            RootRole::FilesystemRoot => "/",
            RootRole::Tmp => "/tmp",
            RootRole::CargoHome => "cargo-home",
            RootRole::TargetRoot => "target-root",
            RootRole::SyncRoot => "sync-root",
            RootRole::Override => "override",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const GIB: u64 = 1024 * 1024 * 1024;

    fn stats(path: &str, fs_kind: FsKind, free_gib: u64, free_inodes: u64) -> MountStats {
        MountStats {
            path: path.to_string(),
            fs_kind,
            free_bytes: free_gib * GIB,
            free_inodes,
        }
    }

    fn cand(role: RootRole, stats: MountStats) -> RootCandidate {
        RootCandidate::new(role, stats, false)
    }

    #[test]
    fn tmpfs_pressure_prefers_disk_backed_root() {
        // A roomy tmpfs /tmp and a disk-backed /data/tmp: the disk wins, and
        // the tmpfs is rejected as RAM-backed even though it has space.
        let candidates = vec![
            cand(RootRole::Tmp, stats("/tmp", FsKind::Tmpfs, 30, 1_000_000)),
            cand(
                RootRole::TargetRoot,
                stats("/data/tmp", FsKind::Disk, 50, 2_000_000),
            ),
        ];
        let decision = evaluate_build_roots(&candidates, RootSafetyThresholds::default());
        assert!(decision.safe);
        let chosen = decision.chosen.unwrap();
        assert_eq!(chosen.path, "/data/tmp");
        assert_eq!(chosen.fs_kind, FsKind::Disk);
        assert!(
            decision
                .rejected
                .iter()
                .any(|r| r.path == "/tmp" && r.reason == RejectReason::RamBackedAvoided)
        );
    }

    #[test]
    fn falls_back_to_tmpfs_when_no_disk_root_available() {
        // Only a tmpfs root with space: it is used (better than failing), and
        // the rationale records it is RAM-backed.
        let candidates = vec![cand(
            RootRole::Tmp,
            stats("/tmp", FsKind::Tmpfs, 20, 800_000),
        )];
        let decision = evaluate_build_roots(&candidates, RootSafetyThresholds::default());
        assert!(decision.safe);
        let chosen = decision.chosen.unwrap();
        assert_eq!(chosen.fs_kind, FsKind::Tmpfs);
        assert!(chosen.rationale.contains("RAM-backed"));
        assert!(decision.rejected.is_empty());
    }

    #[test]
    fn inode_exhaustion_rejects_root() {
        // Plenty of bytes but almost no inodes => rejected.
        let candidates = vec![cand(
            RootRole::TargetRoot,
            stats("/data", FsKind::Disk, 500, 10),
        )];
        let decision = evaluate_build_roots(&candidates, RootSafetyThresholds::default());
        assert!(!decision.safe);
        assert!(decision.chosen.is_none());
        assert_eq!(
            decision.rejected[0].reason,
            RejectReason::InsufficientInodes
        );
    }

    #[test]
    fn insufficient_bytes_rejects_root() {
        let candidates = vec![cand(
            RootRole::FilesystemRoot,
            stats("/", FsKind::Disk, 0, 5_000_000),
        )];
        let decision = evaluate_build_roots(&candidates, RootSafetyThresholds::default());
        assert!(!decision.safe);
        assert_eq!(decision.rejected[0].reason, RejectReason::InsufficientBytes);
    }

    #[test]
    fn worker_override_is_chosen_when_safe_even_over_bigger_disk() {
        // An explicit override (smaller, but safe) beats a larger non-override
        // disk root.
        let candidates = vec![
            cand(
                RootRole::TargetRoot,
                stats("/data/big", FsKind::Disk, 500, 9_000_000),
            ),
            RootCandidate::new(
                RootRole::Override,
                stats("/mnt/builds", FsKind::Disk, 10, 1_000_000),
                true,
            ),
        ];
        let decision = evaluate_build_roots(&candidates, RootSafetyThresholds::default());
        assert!(decision.safe);
        assert_eq!(decision.chosen.unwrap().path, "/mnt/builds");
    }

    #[test]
    fn override_on_tmpfs_is_kept_not_ram_avoided() {
        // An operator who deliberately overrides to a tmpfs path keeps it even
        // when a disk root exists (override is exempt from RAM avoidance), but
        // it must still pass the thresholds.
        let candidates = vec![
            cand(
                RootRole::TargetRoot,
                stats("/data", FsKind::Disk, 50, 2_000_000),
            ),
            RootCandidate::new(
                RootRole::Override,
                stats("/dev/shm/builds", FsKind::Tmpfs, 40, 1_000_000),
                true,
            ),
        ];
        let decision = evaluate_build_roots(&candidates, RootSafetyThresholds::default());
        assert!(decision.safe);
        assert_eq!(decision.chosen.unwrap().path, "/dev/shm/builds");
        assert!(
            !decision
                .rejected
                .iter()
                .any(|r| r.reason == RejectReason::RamBackedAvoided)
        );
    }

    #[test]
    fn missing_inode_counts_do_not_constrain() {
        // free_inodes == u64::MAX => inode constraint not applied.
        let candidates = vec![cand(
            RootRole::Tmp,
            MountStats {
                path: "/tmp".to_string(),
                fs_kind: FsKind::Tmpfs,
                free_bytes: 20 * GIB,
                free_inodes: u64::MAX,
            },
        )];
        let decision = evaluate_build_roots(&candidates, RootSafetyThresholds::default());
        assert!(decision.safe);
    }

    #[test]
    fn picks_most_free_bytes_among_equal_disk_roots() {
        let candidates = vec![
            cand(
                RootRole::TargetRoot,
                stats("/a", FsKind::Disk, 20, 2_000_000),
            ),
            cand(RootRole::SyncRoot, stats("/b", FsKind::Disk, 80, 2_000_000)),
            cand(
                RootRole::FilesystemRoot,
                stats("/", FsKind::Disk, 50, 2_000_000),
            ),
        ];
        let decision = evaluate_build_roots(&candidates, RootSafetyThresholds::default());
        assert_eq!(decision.chosen.unwrap().path, "/b");
    }

    #[test]
    fn empty_candidate_pool_is_unsafe() {
        let decision = evaluate_build_roots(&[], RootSafetyThresholds::default());
        assert!(!decision.safe);
        assert!(decision.chosen.is_none());
    }

    #[test]
    fn decision_serializes_for_status_surfaces() {
        let candidates = vec![cand(
            RootRole::TargetRoot,
            stats("/data", FsKind::Disk, 50, 2_000_000),
        )];
        let decision = evaluate_build_roots(&candidates, RootSafetyThresholds::default());
        let json = serde_json::to_string(&decision).expect("serialize");
        assert!(json.contains("\"safe\":true"));
        assert!(json.contains("/data"));
    }
}
