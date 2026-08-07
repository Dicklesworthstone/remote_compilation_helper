//! Schema/protocol compatibility doctor (bead R009; plan §105;
//! composes J002 negotiation, the schema-registry fingerprint, and
//! the wrapper-contract matrix).
//!
//! `rch doctor --fleet` collects one [`NodeReport`] per node and this
//! module diagnoses the set against the coordinator's own report:
//!
//! - PROTOCOL: every node must negotiate with the coordinator (J002
//!   overlap on transport AND application) — a refusal becomes a
//!   finding carrying both ranges and a remediation naming exactly
//!   what to upgrade;
//! - N/N-1 POLICY: application `current` more than one behind the
//!   fleet maximum is flagged even when it still negotiates — the
//!   fleet must never depend on older-than-N-1 skew;
//! - SCHEMA EPOCH: a node whose schema-registry fingerprint differs
//!   from the coordinator's is flagged (same version number with
//!   different schemas is the WORST skew — it would misread, not
//!   refuse);
//! - WRAPPER CONTRACT: the wrapper-contract version each node
//!   enforces must sit inside the supported matrix.
//!
//! A healthy fleet diagnoses to ZERO findings (the suite proves the
//! doctor is not a scold that always finds something).

use crate::version_negotiation::{Negotiation, VersionHello, negotiate};

/// The wrapper-contract versions this build supports (inclusive).
pub const SUPPORTED_WRAPPER_CONTRACTS: core::ops::RangeInclusive<u32> = 3..=4;

/// One node's compatibility report.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NodeReport {
    /// Node identity.
    pub node_id: u64,
    /// Transport + application version ranges (the J002 hello).
    pub hello: VersionHello,
    /// The node's schema-registry fingerprint.
    pub schema_fingerprint: u64,
    /// The wrapper contract version the node's wrappers enforce.
    pub wrapper_contract: u32,
}

/// One diagnosed problem, with its remediation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Finding {
    /// The affected node.
    pub node_id: u64,
    /// What is wrong (stable code).
    pub code: &'static str,
    /// The operator remediation.
    pub remediation: String,
}

/// The doctor's verdict for a fleet.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DoctorReport {
    /// Findings, node order (empty = healthy fleet).
    pub findings: Vec<Finding>,
}

impl DoctorReport {
    /// Whether the fleet is fully compatible.
    #[must_use]
    pub fn healthy(&self) -> bool {
        self.findings.is_empty()
    }
}

/// Diagnose a fleet against the coordinator's own report.
#[must_use]
pub fn diagnose(coordinator: &NodeReport, fleet: &[NodeReport]) -> DoctorReport {
    let mut findings = Vec::new();
    let fleet_app_max = fleet
        .iter()
        .map(|n| n.hello.application.current)
        .chain([coordinator.hello.application.current])
        .max()
        .unwrap_or(0);
    for node in fleet {
        // 1. Protocol negotiation with the coordinator.
        if let Negotiation::Refused(refusal) = negotiate(&coordinator.hello, &node.hello) {
            findings.push(Finding {
                node_id: node.node_id,
                code: "PROTOCOL_NEGOTIATION_REFUSED",
                remediation: format!(
                    "node {} cannot negotiate ({:?} layer): coordinator speaks \
                     {}..={}, node speaks {}..={}; upgrade the older side into \
                     the overlap",
                    node.node_id,
                    refusal.layer,
                    refusal.ours.minimum_compatible,
                    refusal.ours.current,
                    refusal.theirs.minimum_compatible,
                    refusal.theirs.current,
                ),
            });
        }
        // 2. N/N-1: more than one behind the fleet max application.
        if node.hello.application.current + 1 < fleet_app_max {
            findings.push(Finding {
                node_id: node.node_id,
                code: "OLDER_THAN_N_MINUS_1",
                remediation: format!(
                    "node {} runs application v{} while the fleet max is v{}; \
                     the N/N-1 policy supports at most one version of skew — \
                     upgrade node {} to v{} or v{}",
                    node.node_id,
                    node.hello.application.current,
                    fleet_app_max,
                    node.node_id,
                    fleet_app_max - 1,
                    fleet_app_max,
                ),
            });
        }
        // 3. Schema fingerprint agreement.
        if node.schema_fingerprint != coordinator.schema_fingerprint {
            findings.push(Finding {
                node_id: node.node_id,
                code: "SCHEMA_FINGERPRINT_MISMATCH",
                remediation: format!(
                    "node {} schema fingerprint {:#x} differs from the \
                     coordinator's {:#x}: same-version/different-schema skew \
                     would MISREAD rather than refuse — redeploy node {} from \
                     the coordinator's build",
                    node.node_id,
                    node.schema_fingerprint,
                    coordinator.schema_fingerprint,
                    node.node_id,
                ),
            });
        }
        // 4. Wrapper-contract matrix.
        if !SUPPORTED_WRAPPER_CONTRACTS.contains(&node.wrapper_contract) {
            findings.push(Finding {
                node_id: node.node_id,
                code: "WRAPPER_CONTRACT_UNSUPPORTED",
                remediation: format!(
                    "node {} enforces wrapper contract v{} outside the \
                     supported matrix v{}..=v{}; update its rch wrappers",
                    node.node_id,
                    node.wrapper_contract,
                    SUPPORTED_WRAPPER_CONTRACTS.start(),
                    SUPPORTED_WRAPPER_CONTRACTS.end(),
                ),
            });
        }
    }
    DoctorReport { findings }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::version_negotiation::VersionRange;

    fn healthy_node(node_id: u64) -> NodeReport {
        NodeReport {
            node_id,
            hello: VersionHello {
                transport: VersionRange {
                    minimum_compatible: 1,
                    current: 2,
                },
                application: VersionRange {
                    minimum_compatible: 3,
                    current: 5,
                },
            },
            schema_fingerprint: 0xABCD_EF01,
            wrapper_contract: 4,
        }
    }

    #[test]
    fn a_healthy_fleet_diagnoses_to_zero_findings() {
        // The doctor is not a scold: a compatible fleet is HEALTHY.
        let coordinator = healthy_node(0);
        let fleet = [healthy_node(1), healthy_node(2), healthy_node(3)];
        let report = diagnose(&coordinator, &fleet);
        assert!(
            report.healthy(),
            "unexpected findings: {:?}",
            report.findings
        );
    }

    #[test]
    fn n_minus_1_skew_is_healthy_older_is_flagged() {
        // One-behind negotiates and passes policy.
        let coordinator = healthy_node(0);
        let mut n_minus_1 = healthy_node(1);
        n_minus_1.hello.application = VersionRange {
            minimum_compatible: 3,
            current: 4,
        };
        assert!(diagnose(&coordinator, &[n_minus_1]).healthy());
        // Two-behind: SEEDED skew — flagged with remediation naming
        // the exact upgrade target (THE acceptance).
        // Still negotiates (overlap at v3) — the finding is the
        // POLICY violation alone, not a protocol refusal.
        let mut stale = healthy_node(2);
        stale.hello.application = VersionRange {
            minimum_compatible: 2,
            current: 3,
        };
        let report = diagnose(&coordinator, &[stale]);
        assert_eq!(report.findings.len(), 1);
        let finding = &report.findings[0];
        assert_eq!(finding.code, "OLDER_THAN_N_MINUS_1");
        assert_eq!(finding.node_id, 2);
        assert!(finding.remediation.contains("upgrade node 2 to v4 or v5"));
    }

    #[test]
    fn negotiation_refusal_carries_both_ranges_in_the_remediation() {
        // A node whose transport range has NO overlap with the
        // coordinator: the finding names both ranges.
        let coordinator = healthy_node(0);
        let mut ancient = healthy_node(7);
        ancient.hello.transport = VersionRange {
            minimum_compatible: 0,
            current: 0,
        };
        let report = diagnose(&coordinator, &[ancient]);
        let finding = report
            .findings
            .iter()
            .find(|f| f.code == "PROTOCOL_NEGOTIATION_REFUSED")
            .expect("refusal flagged");
        assert!(finding.remediation.contains("coordinator speaks 1..=2"));
        assert!(finding.remediation.contains("node speaks 0..=0"));
    }

    #[test]
    fn schema_fingerprint_mismatch_is_the_worst_skew() {
        // Same versions, DIFFERENT schema fingerprints: negotiation
        // succeeds, and the doctor still flags it — misreading is
        // worse than refusing.
        let coordinator = healthy_node(0);
        let mut drifted = healthy_node(4);
        drifted.schema_fingerprint = 0xDEAD_BEEF;
        let report = diagnose(&coordinator, &[drifted]);
        assert_eq!(report.findings.len(), 1);
        assert_eq!(report.findings[0].code, "SCHEMA_FINGERPRINT_MISMATCH");
        assert!(report.findings[0].remediation.contains("redeploy node 4"));
    }

    #[test]
    fn wrapper_contract_matrix_is_enforced_and_multiple_findings_stack() {
        // A node can be wrong in several ways at once; every finding
        // surfaces (the doctor never stops at the first).
        let coordinator = healthy_node(0);
        let mut broken = healthy_node(9);
        broken.wrapper_contract = 1; // outside 3..=4
        broken.schema_fingerprint = 0x1111;
        let report = diagnose(&coordinator, &[broken]);
        let codes: Vec<&str> = report.findings.iter().map(|f| f.code).collect();
        assert!(codes.contains(&"WRAPPER_CONTRACT_UNSUPPORTED"));
        assert!(codes.contains(&"SCHEMA_FINGERPRINT_MISMATCH"));
        assert_eq!(report.findings.len(), 2);
    }
}
