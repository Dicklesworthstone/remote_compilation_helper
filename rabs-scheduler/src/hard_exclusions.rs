//! Hard eligibility exclusions BEFORE scoring (bead I008; plan §84;
//! risk R25).
//!
//! Scoring never sees an ineligible candidate: the nine hard rules run
//! first and each carries a stable `WORKER_*` reason code so `rch why`
//! explains every exclusion. Stale or contradictory health evidence
//! FAILS CLOSED for remote-required work (R25) — a worker whose
//! evidence cannot be trusted is not a lower-scored candidate, it is
//! not a candidate.

use rabs_protocol::pressure::{AdminIntent, Freshness, WorkerPressureSnapshot};

/// The nine hard-exclusion rules with their reason codes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HardExclusion {
    /// Incompatible platform/toolchain.
    IncompatiblePlatform,
    /// Stale or contradictory health evidence (remote-required: closed).
    UntrustedHealthEvidence,
    /// Insufficient disk/memory headroom for the envelope.
    InsufficientHeadroom,
    /// Admin disabled/draining.
    AdminExcluded,
    /// Project-level worker exclusion list.
    ProjectExcluded,
    /// Artifact retrieval reliability below policy.
    UnreliableRetrieval,
    /// Sandbox capability mismatch.
    SandboxCapabilityMismatch,
    /// Trust/identity mismatch (F029 fence disagreement).
    IdentityMismatch,
    /// Transfer break-even fails under remote-required policy.
    TransferBreakEvenFailure,
}

impl HardExclusion {
    /// Stable reason code.
    #[must_use]
    pub const fn reason_code(self) -> &'static str {
        match self {
            Self::IncompatiblePlatform => "WORKER_EXCLUDED_INCOMPATIBLE_PLATFORM",
            Self::UntrustedHealthEvidence => "WORKER_EXCLUDED_UNTRUSTED_HEALTH_EVIDENCE",
            Self::InsufficientHeadroom => "WORKER_EXCLUDED_INSUFFICIENT_HEADROOM",
            Self::AdminExcluded => "WORKER_EXCLUDED_ADMIN",
            Self::ProjectExcluded => "WORKER_EXCLUDED_PROJECT_POLICY",
            Self::UnreliableRetrieval => "WORKER_EXCLUDED_UNRELIABLE_RETRIEVAL",
            Self::SandboxCapabilityMismatch => "WORKER_EXCLUDED_SANDBOX_CAPABILITY",
            Self::IdentityMismatch => "WORKER_EXCLUDED_IDENTITY_MISMATCH",
            Self::TransferBreakEvenFailure => "WORKER_EXCLUDED_TRANSFER_BREAK_EVEN",
        }
    }
}

/// Everything the exclusion pass consults beyond the snapshot.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExclusionContext {
    /// Snapshot freshness (coordinator-judged, I006).
    pub freshness: Freshness,
    /// Whether the snapshot's own claims contradict fleet records
    /// (e.g. boot generation regressed).
    pub evidence_contradictory: bool,
    /// Required platform class.
    pub required_platform: String,
    /// Required sandbox capability names.
    pub required_sandbox_capabilities: Vec<String>,
    /// Worker capability names actually enforceable.
    pub worker_sandbox_capabilities: Vec<String>,
    /// Disk bytes the envelope demands.
    pub demanded_disk_bytes: u64,
    /// Project-excluded worker identities.
    pub project_exclusions: Vec<String>,
    /// Retrieval-reliability floor (permille).
    pub retrieval_floor_permille: u16,
    /// F029 fence verdict for the worker's claimed identity tuple.
    pub identity_verified: bool,
    /// Predicted remote benefit is non-negative.
    pub transfer_break_even_ok: bool,
    /// The action REQUIRES remote execution (policy).
    pub remote_required: bool,
}

/// Run the hard-exclusion pass. Returns the FIRST firing rule (rules
/// run in fixed order) or Ok if the candidate may proceed to scoring.
///
/// # Errors
/// The first [`HardExclusion`] that fires.
pub fn check_hard_exclusions(
    snapshot: &WorkerPressureSnapshot,
    context: &ExclusionContext,
) -> Result<(), HardExclusion> {
    // R25: stale/contradictory evidence fails CLOSED for remote work.
    if context.freshness != Freshness::Fresh || context.evidence_contradictory {
        return Err(HardExclusion::UntrustedHealthEvidence);
    }
    if !snapshot
        .supported_platforms
        .contains(&context.required_platform)
    {
        return Err(HardExclusion::IncompatiblePlatform);
    }
    if snapshot.free_disk_bytes < context.demanded_disk_bytes {
        return Err(HardExclusion::InsufficientHeadroom);
    }
    if snapshot.admin_intent != AdminIntent::Active {
        return Err(HardExclusion::AdminExcluded);
    }
    if context.project_exclusions.contains(&snapshot.identity.0) {
        return Err(HardExclusion::ProjectExcluded);
    }
    if snapshot.retrieval_reliability_permille < context.retrieval_floor_permille {
        return Err(HardExclusion::UnreliableRetrieval);
    }
    if !context
        .required_sandbox_capabilities
        .iter()
        .all(|c| context.worker_sandbox_capabilities.contains(c))
    {
        return Err(HardExclusion::SandboxCapabilityMismatch);
    }
    if !context.identity_verified {
        return Err(HardExclusion::IdentityMismatch);
    }
    if context.remote_required && !context.transfer_break_even_ok {
        return Err(HardExclusion::TransferBreakEvenFailure);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use rabs_protocol::generation::{WorkerBootGeneration, WorkerIncarnationId};
    use rabs_protocol::result_identity::{DigestAlgorithm, TypedDigest};
    use rabs_protocol::wire_time::PeerId;

    fn snapshot() -> WorkerPressureSnapshot {
        WorkerPressureSnapshot {
            identity: PeerId("wkr-1".into()),
            boot_generation: WorkerBootGeneration(1),
            incarnation: WorkerIncarnationId(1),
            captured_at_causal: 1,
            valid_for_ms: 5_000,
            admin_intent: AdminIntent::Active,
            eligible: true,
            supported_platforms: vec!["x86_64-linux-gnu".into()],
            isolation_profiles: vec!["strict-hermetic-linux".into()],
            queue_depth: 0,
            cpu_utilization_permille: 100,
            memory_psi_permille: 10,
            io_psi_permille: 10,
            free_disk_bytes: 10 << 30,
            cache_warmth_permille: 500,
            toolchain_inventory_digest: TypedDigest {
                algorithm: DigestAlgorithm::Sha256V1,
                domain: "rabs.toolchain-inventory.v1",
                bytes: [1; 32],
            },
            retrieval_reliability_permille: 950,
            cancellation_debt: 0,
            path_quality_permille: 900,
            confidence_permille: 900,
        }
    }

    fn context() -> ExclusionContext {
        ExclusionContext {
            freshness: Freshness::Fresh,
            evidence_contradictory: false,
            required_platform: "x86_64-linux-gnu".into(),
            required_sandbox_capabilities: vec!["user-ns".into()],
            worker_sandbox_capabilities: vec!["user-ns".into(), "mount-ns".into()],
            demanded_disk_bytes: 1 << 30,
            project_exclusions: vec![],
            retrieval_floor_permille: 900,
            identity_verified: true,
            transfer_break_even_ok: true,
            remote_required: true,
        }
    }

    #[test]
    fn eligible_candidates_pass_to_scoring() {
        assert_eq!(check_hard_exclusions(&snapshot(), &context()), Ok(()));
    }

    #[test]
    fn every_rule_fires_with_its_reason_code() {
        // THE acceptance: one fixture per rule.
        // 1. Stale health fails CLOSED (R25).
        let mut c = context();
        c.freshness = Freshness::StaleByAge;
        assert_eq!(
            check_hard_exclusions(&snapshot(), &c),
            Err(HardExclusion::UntrustedHealthEvidence)
        );
        // 1b. CONTRADICTORY evidence too, even when fresh.
        let mut c = context();
        c.evidence_contradictory = true;
        assert_eq!(
            check_hard_exclusions(&snapshot(), &c),
            Err(HardExclusion::UntrustedHealthEvidence)
        );
        // 2. Incompatible platform.
        let mut c = context();
        c.required_platform = "aarch64-apple-darwin".into();
        assert_eq!(
            check_hard_exclusions(&snapshot(), &c),
            Err(HardExclusion::IncompatiblePlatform)
        );
        // 3. Insufficient headroom.
        let mut c = context();
        c.demanded_disk_bytes = 100 << 30;
        assert_eq!(
            check_hard_exclusions(&snapshot(), &c),
            Err(HardExclusion::InsufficientHeadroom)
        );
        // 4. Admin draining.
        let mut s = snapshot();
        s.admin_intent = AdminIntent::Draining;
        assert_eq!(
            check_hard_exclusions(&s, &context()),
            Err(HardExclusion::AdminExcluded)
        );
        // 5. Project exclusion.
        let mut c = context();
        c.project_exclusions = vec!["wkr-1".into()];
        assert_eq!(
            check_hard_exclusions(&snapshot(), &c),
            Err(HardExclusion::ProjectExcluded)
        );
        // 6. Unreliable retrieval.
        let mut s = snapshot();
        s.retrieval_reliability_permille = 500;
        assert_eq!(
            check_hard_exclusions(&s, &context()),
            Err(HardExclusion::UnreliableRetrieval)
        );
        // 7. Sandbox capability mismatch.
        let mut c = context();
        c.required_sandbox_capabilities = vec!["cgroup-v2-delegation".into()];
        assert_eq!(
            check_hard_exclusions(&snapshot(), &c),
            Err(HardExclusion::SandboxCapabilityMismatch)
        );
        // 8. Identity mismatch (F029 fence disagreement).
        let mut c = context();
        c.identity_verified = false;
        assert_eq!(
            check_hard_exclusions(&snapshot(), &c),
            Err(HardExclusion::IdentityMismatch)
        );
        // 9. Transfer break-even under remote-required.
        let mut c = context();
        c.transfer_break_even_ok = false;
        assert_eq!(
            check_hard_exclusions(&snapshot(), &c),
            Err(HardExclusion::TransferBreakEvenFailure)
        );
        // 9b. …but break-even is NOT an exclusion when remote is
        // optional (local execution simply wins).
        let mut c = context();
        c.transfer_break_even_ok = false;
        c.remote_required = false;
        assert_eq!(check_hard_exclusions(&snapshot(), &c), Ok(()));
    }

    #[test]
    fn reason_codes_are_stable_and_distinct() {
        let all = [
            HardExclusion::IncompatiblePlatform,
            HardExclusion::UntrustedHealthEvidence,
            HardExclusion::InsufficientHeadroom,
            HardExclusion::AdminExcluded,
            HardExclusion::ProjectExcluded,
            HardExclusion::UnreliableRetrieval,
            HardExclusion::SandboxCapabilityMismatch,
            HardExclusion::IdentityMismatch,
            HardExclusion::TransferBreakEvenFailure,
        ];
        let mut codes: Vec<&str> = all.iter().map(|e| e.reason_code()).collect();
        assert!(codes.iter().all(|c| c.starts_with("WORKER_EXCLUDED_")));
        codes.sort_unstable();
        let before = codes.len();
        codes.dedup();
        assert_eq!(before, codes.len());
    }
}
