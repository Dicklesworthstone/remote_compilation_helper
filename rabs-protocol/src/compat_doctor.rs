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

    #[test]
    fn e019_sandbox_doctor_reports_capability_matrix_and_findings() {
        let full_probe = SandboxDoctorProbeInput {
            node_id: 1,
            user_mount_pid_net_namespaces: true,
            cgroup_v2_delegated: true,
            seccomp_bpf_tsync: true,
            landlock_abi_version: 3,
        };
        let matrix = probe_host_sandbox_capabilities(&full_probe);
        assert!(matrix.strict_hermetic_capable());
        assert_eq!(
            matrix.effective_profile,
            crate::authority_matrix::IsolationProfile::StrictHermeticLinux
        );
        assert!(
            matrix.findings.is_empty(),
            "fully capable host should produce zero doctor findings"
        );

        // Missing cgroup v2 delegation and seccomp degrades profile and reports actionable findings.
        let degraded_probe = SandboxDoctorProbeInput {
            node_id: 2,
            user_mount_pid_net_namespaces: true,
            cgroup_v2_delegated: false,
            seccomp_bpf_tsync: false,
            landlock_abi_version: 0,
        };
        let degraded = probe_host_sandbox_capabilities(&degraded_probe);
        assert!(!degraded.strict_hermetic_capable());
        assert_eq!(
            degraded.effective_profile,
            crate::authority_matrix::IsolationProfile::HostSandboxAudit
        );
        let codes: Vec<&str> = degraded.findings.iter().map(|f| f.code).collect();
        assert!(codes.contains(&"SANDBOX_CGROUP_V2_UNAVAILABLE"));
        assert!(codes.contains(&"SANDBOX_SECCOMP_BPF_UNAVAILABLE"));
        assert!(codes.contains(&"SANDBOX_LANDLOCK_UNAVAILABLE"));

        // Missing namespaces degrades all the way to VolatileLocal.
        let no_ns_probe = SandboxDoctorProbeInput {
            node_id: 3,
            user_mount_pid_net_namespaces: false,
            cgroup_v2_delegated: false,
            seccomp_bpf_tsync: false,
            landlock_abi_version: 0,
        };
        let no_ns = probe_host_sandbox_capabilities(&no_ns_probe);
        assert_eq!(
            no_ns.effective_profile,
            crate::authority_matrix::IsolationProfile::VolatileLocal
        );
        assert!(
            no_ns
                .findings
                .iter()
                .any(|f| f.code == "SANDBOX_NAMESPACES_UNAVAILABLE")
        );
    }

    #[test]
    fn e019_failure_bundle_generated_on_induced_sandbox_setup_failure() {
        let probe = SandboxDoctorProbeInput {
            node_id: 7,
            user_mount_pid_net_namespaces: true,
            cgroup_v2_delegated: false,
            seccomp_bpf_tsync: true,
            landlock_abi_version: 2,
        };
        let capability_matrix = probe_host_sandbox_capabilities(&probe);

        let bundle = generate_sandbox_failure_bundle(
            [0x42; 32],
            99,
            SandboxFailurePhase::CgroupV2Attach,
            13, // EACCES
            vec![
                SandboxMountEntry {
                    source: "overlay".into(),
                    target: "/rabs/execroot/ws".into(),
                    fstype: "overlay".into(),
                    read_only: true,
                },
                SandboxMountEntry {
                    source: "tmpfs".into(),
                    target: "/rabs/execroot/out".into(),
                    fstype: "tmpfs".into(),
                    read_only: false,
                },
            ],
            vec![
                SandboxNamespaceEntry {
                    ns_kind: "mnt".into(),
                    entered: true,
                    detail: "mnt:[4026532210]".into(),
                },
                SandboxNamespaceEntry {
                    ns_kind: "cgroup".into(),
                    entered: false,
                    detail: "permission denied opening cgroup.procs".into(),
                },
            ],
            SandboxCgroupState {
                slice_path: "/sys/fs/cgroup/rabs.slice/act-99".into(),
                controllers_enabled: vec!["cpu".into(), "memory".into()],
                memory_peak_bytes: 0,
                oom_kill_count: 0,
                pids_current: 1,
            },
            vec![
                "helper: entered user+mount+pid namespaces".into(),
                "helper: failed to write PID to /sys/fs/cgroup/rabs.slice/act-99/cgroup.procs (EACCES)".into(),
            ],
            vec![SandboxDeniedOperation {
                operation: "openat(O_WRONLY)".into(),
                target: "/sys/fs/cgroup/rabs.slice/act-99/cgroup.procs".into(),
                enforcer: "dac_cgroup_v2".into(),
                errno: 13,
            }],
            capability_matrix,
        );

        assert_eq!(bundle.attempt_id, 99);
        assert_eq!(bundle.phase, SandboxFailurePhase::CgroupV2Attach);
        assert_eq!(bundle.errno, 13);
        assert_eq!(bundle.mounts.len(), 2);
        assert_eq!(bundle.namespaces.len(), 2);
        assert_eq!(
            bundle.cgroup_state.slice_path,
            "/sys/fs/cgroup/rabs.slice/act-99"
        );
        assert_eq!(bundle.helper_logs.len(), 2);
        assert_eq!(bundle.denied_operations.len(), 1);
        assert!(
            !bundle.capability_matrix.strict_hermetic_capable(),
            "bundle records the host capability matrix at the moment of failure"
        );
        assert_ne!(bundle.bundle_digest, [0u8; 32]);
    }
}

/// Host sandbox capability probe inputs collected by `rch doctor` (bead E019).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SandboxDoctorProbeInput {
    /// Host/worker node identifier.
    pub node_id: u64,
    /// Whether `CLONE_NEWUSER | CLONE_NEWNS | CLONE_NEWPID | CLONE_NEWNET` works.
    pub user_mount_pid_net_namespaces: bool,
    /// Whether a writable cgroup v2 slice with delegated `cpu`, `memory`, `io`, `pids` is available.
    pub cgroup_v2_delegated: bool,
    /// Whether `SECCOMP_SET_MODE_FILTER` with `SECCOMP_FILTER_FLAG_TSYNC` works.
    pub seccomp_bpf_tsync: bool,
    /// Supported Landlock ABI version (`0` if unsupported/disabled on host kernel).
    pub landlock_abi_version: u32,
}

/// Host sandbox capability matrix and doctor findings (bead E019).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SandboxCapabilityMatrix {
    /// Host/worker node identifier.
    pub node_id: u64,
    /// Namespace isolation available.
    pub namespaces_ok: bool,
    /// cgroup v2 resource envelope available.
    pub cgroup_v2_ok: bool,
    /// seccomp-bpf syscall filter available.
    pub seccomp_ok: bool,
    /// Landlock LSM ABI version (`0` = unavailable).
    pub landlock_abi_version: u32,
    /// Highest `IsolationProfile` the host can legitimately claim.
    pub effective_profile: crate::authority_matrix::IsolationProfile,
    /// Remediation findings for any missing capability.
    pub findings: Vec<Finding>,
}

impl SandboxCapabilityMatrix {
    /// Whether the host meets the full `StrictHermeticLinux` capability contract.
    #[must_use]
    pub const fn strict_hermetic_capable(&self) -> bool {
        self.namespaces_ok && self.cgroup_v2_ok && self.seccomp_ok
    }
}

/// Probe and evaluate host sandbox capabilities for `rch doctor` (bead E019).
#[must_use]
pub fn probe_host_sandbox_capabilities(input: &SandboxDoctorProbeInput) -> SandboxCapabilityMatrix {
    let mut findings = Vec::new();
    if !input.user_mount_pid_net_namespaces {
        findings.push(Finding {
            node_id: input.node_id,
            code: "SANDBOX_NAMESPACES_UNAVAILABLE",
            remediation: format!(
                "node {} cannot create user/mount/pid/net namespaces; enable \
                 kernel.unprivileged_userns_clone=1 or install the audited namespace helper",
                input.node_id
            ),
        });
    }
    if !input.cgroup_v2_delegated {
        findings.push(Finding {
            node_id: input.node_id,
            code: "SANDBOX_CGROUP_V2_UNAVAILABLE",
            remediation: format!(
                "node {} lacks a delegated cgroup v2 slice (cpu, memory, io, pids); \
                 configure systemd Delegate=yes on rabs-wkr.service",
                input.node_id
            ),
        });
    }
    if !input.seccomp_bpf_tsync {
        findings.push(Finding {
            node_id: input.node_id,
            code: "SANDBOX_SECCOMP_BPF_UNAVAILABLE",
            remediation: format!(
                "node {} lacks seccomp-bpf TSYNC support; verify CONFIG_SECCOMP_FILTER=y \
                 and container seccomp profile",
                input.node_id
            ),
        });
    }
    if input.landlock_abi_version == 0 {
        findings.push(Finding {
            node_id: input.node_id,
            code: "SANDBOX_LANDLOCK_UNAVAILABLE",
            remediation: format!(
                "node {} reports Landlock ABI 0; enable lsm=landlock,... in kernel boot parameters \
                 for defense-in-depth filesystem restriction",
                input.node_id
            ),
        });
    }

    let effective_profile = if input.user_mount_pid_net_namespaces
        && input.cgroup_v2_delegated
        && input.seccomp_bpf_tsync
    {
        crate::authority_matrix::IsolationProfile::StrictHermeticLinux
    } else if input.user_mount_pid_net_namespaces {
        crate::authority_matrix::IsolationProfile::HostSandboxAudit
    } else {
        crate::authority_matrix::IsolationProfile::VolatileLocal
    };

    SandboxCapabilityMatrix {
        node_id: input.node_id,
        namespaces_ok: input.user_mount_pid_net_namespaces,
        cgroup_v2_ok: input.cgroup_v2_delegated,
        seccomp_ok: input.seccomp_bpf_tsync,
        landlock_abi_version: input.landlock_abi_version,
        effective_profile,
        findings,
    }
}

/// Phase in which a sandbox setup or enforcement failure occurred (bead E019).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SandboxFailurePhase {
    /// Creating `CLONE_NEWUSER | CLONE_NEWNS | CLONE_NEWPID | CLONE_NEWNET`.
    NamespaceSetup,
    /// Bind-mounting canonical execroot directories or `pivot_root`.
    MountAndPivotRoot,
    /// Attaching child PID or configuring limits in cgroup v2 slice.
    CgroupV2Attach,
    /// Installing seccomp-bpf or Landlock ruleset pre-exec.
    SeccompOrLandlockInstall,
    /// Runtime enforcement denied an operation (e.g. closed-view read escape or forbidden syscall).
    RuntimeEnforcementDenied,
}

/// Captured mount-table entry in a sandbox failure bundle (bead E019).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SandboxMountEntry {
    /// Mount source device or fstype tag.
    pub source: String,
    /// Canonical mount target inside the sandbox.
    pub target: String,
    /// Filesystem type (`overlay`, `bind`, `tmpfs`, `proc`).
    pub fstype: String,
    /// Whether mounted `MS_RDONLY`.
    pub read_only: bool,
}

/// Captured namespace state entry in a sandbox failure bundle (bead E019).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SandboxNamespaceEntry {
    /// Namespace kind (`user`, `mnt`, `pid`, `net`, `uts`, `ipc`, `cgroup`).
    pub ns_kind: String,
    /// Whether the helper successfully entered/configured this namespace.
    pub entered: bool,
    /// Inode or diagnostic detail.
    pub detail: String,
}

/// Captured cgroup v2 resource state in a sandbox failure bundle (bead E019).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SandboxCgroupState {
    /// Delegated cgroup v2 slice path.
    pub slice_path: String,
    /// Active controllers in `cgroup.subtree_control`.
    pub controllers_enabled: Vec<String>,
    /// Peak memory usage (`memory.peak`).
    pub memory_peak_bytes: u64,
    /// Recorded OOM kills (`memory.events` `oom_kill`).
    pub oom_kill_count: u64,
    /// Current PIDs (`pids.current`).
    pub pids_current: u32,
}

/// Denied operation recorded during sandbox setup or runtime enforcement (bead E019).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SandboxDeniedOperation {
    /// Syscall or filesystem operation name.
    pub operation: String,
    /// Target path or resource.
    pub target: String,
    /// Enforcing layer (`seccomp`, `landlock`, `canonical_mount_ro`, `dac_cgroup_v2`).
    pub enforcer: String,
    /// OS errno returned (`EACCES = 13`, `EPERM = 1`, `EROFS = 30`, etc.).
    pub errno: i32,
}

/// Diagnostic bundle emitted when sandbox setup or enforcement fails (bead E019).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SandboxFailureBundle {
    /// Action key digest that triggered the sandboxed execution.
    pub action_key_digest: [u8; 32],
    /// Attempt identifier.
    pub attempt_id: u64,
    /// Setup/enforcement phase that failed.
    pub phase: SandboxFailurePhase,
    /// OS errno code at failure.
    pub errno: i32,
    /// Mount table snapshot at failure time.
    pub mounts: Vec<SandboxMountEntry>,
    /// Namespace status snapshot at failure time.
    pub namespaces: Vec<SandboxNamespaceEntry>,
    /// cgroup v2 state snapshot at failure time.
    pub cgroup_state: SandboxCgroupState,
    /// Bounded helper log lines.
    pub helper_logs: Vec<String>,
    /// Denied operations leading to the failure.
    pub denied_operations: Vec<SandboxDeniedOperation>,
    /// Host capability matrix captured by the doctor probe.
    pub capability_matrix: SandboxCapabilityMatrix,
    /// Deterministic content digest over the failure bundle.
    pub bundle_digest: [u8; 32],
}

/// Generate a deterministic `SandboxFailureBundle` on induced or live sandbox setup/enforcement failure (bead E019).
#[must_use]
#[allow(clippy::too_many_arguments)]
pub fn generate_sandbox_failure_bundle(
    action_key_digest: [u8; 32],
    attempt_id: u64,
    phase: SandboxFailurePhase,
    errno: i32,
    mounts: Vec<SandboxMountEntry>,
    namespaces: Vec<SandboxNamespaceEntry>,
    cgroup_state: SandboxCgroupState,
    helper_logs: Vec<String>,
    denied_operations: Vec<SandboxDeniedOperation>,
    capability_matrix: SandboxCapabilityMatrix,
) -> SandboxFailureBundle {
    let mut acc: u64 = 0xCBF2_9CE4_8422_2325;
    for b in action_key_digest {
        acc ^= u64::from(b);
        acc = acc.wrapping_mul(0x0100_0000_01B3);
    }
    acc ^= attempt_id;
    acc = acc.wrapping_mul(0x0100_0000_01B3);
    acc ^= errno as u64;
    acc = acc.wrapping_mul(0x0100_0000_01B3);
    acc ^= (mounts.len() as u64)
        .wrapping_shl(16)
        .wrapping_add(namespaces.len() as u64)
        .wrapping_add(denied_operations.len() as u64);
    let mut bundle_digest = [0u8; 32];
    for (i, chunk) in bundle_digest.as_chunks_mut::<8>().0.iter_mut().enumerate() {
        let word = acc.wrapping_add((i as u64).wrapping_mul(0x9E37_79B9_7F4A_7C15));
        *chunk = word.to_le_bytes();
    }

    SandboxFailureBundle {
        action_key_digest,
        attempt_id,
        phase,
        errno,
        mounts,
        namespaces,
        cgroup_state,
        helper_logs,
        denied_operations,
        capability_matrix,
        bundle_digest,
    }
}
