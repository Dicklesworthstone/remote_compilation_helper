//! Worker candidate-receipt health/admission policy core (bead I007;
//! plan §84; the Asupersync RCH health model adapted with RABS action
//! dimensions).
//!
//! Placement decisions must be EXPLAINABLE and REPLAYABLE: for every
//! candidate worker the policy produces a structured receipt — every
//! rule consulted, every score contributed, the final decision — and
//! the whole computation is a pure function of its inputs: identical
//! inputs give byte-identical receipts (no clocks, no randomness, no
//! iteration-order dependence).

use rabs_protocol::pressure::{AdminIntent, Freshness, WorkerPressureSnapshot};
use rabs_protocol::resource_envelope::ResourceEnvelope;

/// One rule's contribution to the receipt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuleFinding {
    /// Stable rule name.
    pub rule: &'static str,
    /// What the rule concluded.
    pub outcome: RuleOutcome,
}

/// A rule's conclusion.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RuleOutcome {
    /// Hard exclusion (candidate cannot serve this action).
    Exclude {
        /// Why.
        reason: &'static str,
    },
    /// Score contribution (higher = better placement), permille scale.
    Score {
        /// Signed contribution.
        delta: i32,
    },
    /// Rule consulted, nothing to add.
    Neutral,
}

/// The final decision.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AdmissionDecision {
    /// Admitted with the summed placement score.
    Admit {
        /// Total score (ordering across candidates).
        score: i32,
    },
    /// Excluded by the named rule.
    Exclude {
        /// The excluding rule.
        rule: &'static str,
        /// Its reason.
        reason: &'static str,
    },
}

/// The structured candidate receipt: every rule in a FIXED order, plus
/// the decision. Deterministic and replayable by construction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CandidateReceipt {
    /// Findings in rule order.
    pub findings: Vec<RuleFinding>,
    /// The decision.
    pub decision: AdmissionDecision,
}

/// The action's placement demands (RABS action dimensions).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ActionDemands {
    /// Required isolation profile name.
    pub required_isolation_profile: String,
    /// Required platform class name.
    pub required_platform: String,
    /// Estimated resource envelope.
    pub envelope: ResourceEnvelope,
}

/// Evaluate one candidate. Pure: snapshot + freshness + demands in,
/// receipt out.
#[must_use]
pub fn evaluate_candidate(
    snapshot: &WorkerPressureSnapshot,
    freshness: Freshness,
    demands: &ActionDemands,
) -> CandidateReceipt {
    let mut findings = Vec::new();
    let mut exclusion: Option<(&'static str, &'static str)> = None;
    let mut score: i32 = 0;
    let push = |findings: &mut Vec<RuleFinding>,
                exclusion: &mut Option<(&'static str, &'static str)>,
                score: &mut i32,
                rule: &'static str,
                outcome: RuleOutcome| {
        if let RuleOutcome::Exclude { reason } = &outcome
            && exclusion.is_none()
        {
            *exclusion = Some((rule, reason));
        }
        if let RuleOutcome::Score { delta } = &outcome {
            *score += delta;
        }
        findings.push(RuleFinding { rule, outcome });
    };

    // Rules in FIXED order (the receipt's shape is part of the API).
    push(
        &mut findings,
        &mut exclusion,
        &mut score,
        "snapshot-freshness",
        match freshness {
            Freshness::Fresh => RuleOutcome::Neutral,
            Freshness::StaleByAge | Freshness::StaleByReconnect => RuleOutcome::Exclude {
                reason: "stale evidence fails closed for remote-required work",
            },
        },
    );
    push(
        &mut findings,
        &mut exclusion,
        &mut score,
        "admin-intent",
        match snapshot.admin_intent {
            AdminIntent::Active => RuleOutcome::Neutral,
            AdminIntent::Draining | AdminIntent::Maintenance => RuleOutcome::Exclude {
                reason: "operator intent excludes new work",
            },
        },
    );
    push(
        &mut findings,
        &mut exclusion,
        &mut score,
        "hard-eligibility",
        if snapshot.eligible {
            RuleOutcome::Neutral
        } else {
            RuleOutcome::Exclude {
                reason: "capability probes failed",
            }
        },
    );
    push(
        &mut findings,
        &mut exclusion,
        &mut score,
        "isolation-profile",
        if snapshot
            .isolation_profiles
            .contains(&demands.required_isolation_profile)
        {
            RuleOutcome::Neutral
        } else {
            RuleOutcome::Exclude {
                reason: "required isolation profile not enforceable",
            }
        },
    );
    push(
        &mut findings,
        &mut exclusion,
        &mut score,
        "platform-class",
        if snapshot
            .supported_platforms
            .contains(&demands.required_platform)
        {
            RuleOutcome::Neutral
        } else {
            RuleOutcome::Exclude {
                reason: "platform class unsupported",
            }
        },
    );
    push(
        &mut findings,
        &mut exclusion,
        &mut score,
        "disk-envelope",
        if snapshot.free_disk_bytes
            >= demands.envelope.temp_space_bytes + demands.envelope.disk_write_bytes
        {
            RuleOutcome::Neutral
        } else {
            RuleOutcome::Exclude {
                reason: "insufficient disk for the action envelope",
            }
        },
    );
    // Soft scores (only meaningful when nothing excluded, but computed
    // deterministically regardless so receipts are stable).
    push(
        &mut findings,
        &mut exclusion,
        &mut score,
        "queue-pressure",
        RuleOutcome::Score {
            delta: -(i32::try_from(snapshot.queue_depth).unwrap_or(i32::MAX) * 10),
        },
    );
    push(
        &mut findings,
        &mut exclusion,
        &mut score,
        "cpu-headroom",
        RuleOutcome::Score {
            delta: 1000 - i32::from(snapshot.cpu_utilization_permille),
        },
    );
    push(
        &mut findings,
        &mut exclusion,
        &mut score,
        "memory-psi",
        RuleOutcome::Score {
            delta: -i32::from(snapshot.memory_psi_permille),
        },
    );
    push(
        &mut findings,
        &mut exclusion,
        &mut score,
        "cache-warmth",
        RuleOutcome::Score {
            delta: i32::from(snapshot.cache_warmth_permille) / 2,
        },
    );
    push(
        &mut findings,
        &mut exclusion,
        &mut score,
        "retrieval-reliability",
        RuleOutcome::Score {
            delta: i32::from(snapshot.retrieval_reliability_permille) / 4,
        },
    );

    let decision = match exclusion {
        Some((rule, reason)) => AdmissionDecision::Exclude { rule, reason },
        None => AdmissionDecision::Admit { score },
    };
    CandidateReceipt { findings, decision }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rabs_protocol::generation::{WorkerBootGeneration, WorkerIncarnationId};
    use rabs_protocol::resource_envelope::{Heaviness, MemoryPeakClass};
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
            queue_depth: 2,
            cpu_utilization_permille: 300,
            memory_psi_permille: 40,
            io_psi_permille: 10,
            free_disk_bytes: 10 << 30,
            cache_warmth_permille: 600,
            toolchain_inventory_digest: TypedDigest {
                algorithm: DigestAlgorithm::Sha256V1,
                domain: "rabs.toolchain-inventory.v1",
                bytes: [1; 32],
            },
            retrieval_reliability_permille: 900,
            cancellation_debt: 0,
            path_quality_permille: 900,
            confidence_permille: 900,
        }
    }

    fn demands() -> ActionDemands {
        ActionDemands {
            required_isolation_profile: "strict-hermetic-linux".into(),
            required_platform: "x86_64-linux-gnu".into(),
            envelope: ResourceEnvelope {
                cpu_threads: 4,
                memory_bytes: 1 << 30,
                memory_peak_class: MemoryPeakClass::SinglePeak,
                disk_read_bytes: 1 << 20,
                disk_write_bytes: 1 << 20,
                temp_space_bytes: 1 << 20,
                network_in_bytes: 0,
                network_out_bytes: 0,
                linker_heaviness: Heaviness::None,
                lto_heaviness: Heaviness::None,
                process_count: 1,
                expected_duration_ms: 10_000,
                uncertainty_permille: 100,
            },
        }
    }

    #[test]
    fn identical_inputs_give_identical_receipts() {
        // THE acceptance: pure and replayable — byte-identical output.
        let a = evaluate_candidate(&snapshot(), Freshness::Fresh, &demands());
        let b = evaluate_candidate(&snapshot(), Freshness::Fresh, &demands());
        assert_eq!(a, b);
        assert!(matches!(a.decision, AdmissionDecision::Admit { .. }));
        // The receipt lists every rule in fixed order.
        let rules: Vec<&str> = a.findings.iter().map(|f| f.rule).collect();
        assert_eq!(
            rules,
            [
                "snapshot-freshness",
                "admin-intent",
                "hard-eligibility",
                "isolation-profile",
                "platform-class",
                "disk-envelope",
                "queue-pressure",
                "cpu-headroom",
                "memory-psi",
                "cache-warmth",
                "retrieval-reliability",
            ]
        );
    }

    #[test]
    fn hard_exclusions_name_their_rule_and_stale_evidence_fails_closed() {
        // Stale evidence: excluded by the freshness rule (I-series
        // supervision law: stale evidence fails closed).
        let stale = evaluate_candidate(&snapshot(), Freshness::StaleByReconnect, &demands());
        assert_eq!(
            stale.decision,
            AdmissionDecision::Exclude {
                rule: "snapshot-freshness",
                reason: "stale evidence fails closed for remote-required work",
            }
        );
        // Draining worker.
        let mut draining = snapshot();
        draining.admin_intent = AdminIntent::Draining;
        let receipt = evaluate_candidate(&draining, Freshness::Fresh, &demands());
        assert!(matches!(
            receipt.decision,
            AdmissionDecision::Exclude {
                rule: "admin-intent",
                ..
            }
        ));
        // Missing isolation profile.
        let mut wrong_profile = snapshot();
        wrong_profile.isolation_profiles = vec!["host-audit".into()];
        let receipt = evaluate_candidate(&wrong_profile, Freshness::Fresh, &demands());
        assert!(matches!(
            receipt.decision,
            AdmissionDecision::Exclude {
                rule: "isolation-profile",
                ..
            }
        ));
        // Insufficient disk for the envelope (RABS action dimension).
        let mut full_disk = snapshot();
        full_disk.free_disk_bytes = 1024;
        let receipt = evaluate_candidate(&full_disk, Freshness::Fresh, &demands());
        assert!(matches!(
            receipt.decision,
            AdmissionDecision::Exclude {
                rule: "disk-envelope",
                ..
            }
        ));
    }

    #[test]
    fn scores_order_candidates_deterministically() {
        // A busier worker scores lower; the receipts explain why.
        let idle = evaluate_candidate(&snapshot(), Freshness::Fresh, &demands());
        let mut busy_snapshot = snapshot();
        busy_snapshot.queue_depth = 20;
        busy_snapshot.cpu_utilization_permille = 950;
        let busy = evaluate_candidate(&busy_snapshot, Freshness::Fresh, &demands());
        let (
            AdmissionDecision::Admit { score: idle_score },
            AdmissionDecision::Admit { score: busy_score },
        ) = (&idle.decision, &busy.decision)
        else {
            panic!("both admit");
        };
        assert!(idle_score > busy_score);
        // The queue-pressure finding carries the exact contribution.
        let queue_finding = busy
            .findings
            .iter()
            .find(|f| f.rule == "queue-pressure")
            .unwrap();
        assert_eq!(queue_finding.outcome, RuleOutcome::Score { delta: -200 });
    }
}
