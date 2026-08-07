//! `OutputPlatformContract` (keyed) vs `ExecutionEligibility`
//! (scheduler-only) split (bead F008; invariant I23; plan §65; risks
//! R6/R44).
//!
//! Two questions that must never share a type:
//!
//! - **"What platform are the output bytes FOR?"** — the keyed
//!   [`OutputPlatformContract`]. Anything here can change output bytes:
//!   target triple/ABI, host ABI (proc-macros, build scripts, and host
//!   tools execute on the host and their outputs feed compilation), the
//!   explicit CPU baseline contract, libc/runtime, linker format,
//!   SDK/Xcode identity + deployment target, signing policy, and the
//!   filesystem semantic class presented to the action.
//! - **"Which workers may run it?"** — the never-keyed
//!   [`ExecutionEligibility`]. Kernel version, namespace capabilities,
//!   RAM/disk/CPU availability, pressure and queue state, worker
//!   identity/location, the sandbox *implementation* chosen within one
//!   semantic policy, transfer locality: all of it may vary between two
//!   attempts that MUST share one key.
//!
//! The boundary is structural: `ExecutionEligibility` has no digest
//! method, and the contract's canonical bytes are built by exhaustive
//! destructure of the contract alone.
//!
//! **`-C target-cpu=native` is never silently normalized** (R6): the
//! [`CpuBaseline`] type forces the caller to either resolve `native`
//! into an explicit host cohort (the cohort ID becomes a key namespace)
//! or refuse cacheability. A bare "native" string is unrepresentable.

use rabs_protocol::result_identity::TypedDigest;

use crate::canonical::CanonicalEncoder;
use crate::typed_digest::compute;

/// Digest domain for the output-platform contract.
pub const DOMAIN_OUTPUT_PLATFORM: &str = "rabs.output-platform.v1";

/// The explicit CPU feature/baseline contract. There is deliberately no
/// `Native` variant: `-C target-cpu=native` must be RESOLVED before a
/// contract can exist.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CpuBaseline {
    /// A named portable baseline (`"x86-64-v2"`, `"apple-m1"`, …) plus
    /// explicit feature adjustments in canonical (sorted) form.
    Explicit {
        /// Named baseline.
        baseline: String,
        /// `+feat`/`-feat` adjustments, sorted at hashing.
        feature_adjustments: Vec<String>,
    },
    /// `target-cpu=native` resolved to a concrete host cohort: the
    /// cohort ID namespaces the key so only bit-identical CPU cohorts
    /// share artifacts.
    NativeResolvedCohort {
        /// Fleet-assigned cohort identity (CPU model + feature set).
        cohort_id: String,
    },
}

/// How `-C target-cpu=native` was handled (fixture surface for the F008
/// acceptance; the refusal arm never reaches a contract).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NativeCpuDecision {
    /// Resolved into a host cohort; cacheable within the cohort only.
    ResolvedToCohort(CpuBaseline),
    /// Refused for portable fleet caching: the action runs, but
    /// non-cacheable — no contract, no key, no cross-host reuse.
    RefusedNonCacheable {
        /// Operator-facing reason code.
        reason: &'static str,
    },
}

/// Resolve a requested target-cpu value against fleet policy.
#[must_use]
pub fn decide_native_cpu(requested: &str, cohort_id: Option<&str>) -> Option<NativeCpuDecision> {
    if requested != "native" {
        return None; // Not the native case; use CpuBaseline::Explicit.
    }
    Some(match cohort_id {
        Some(id) => NativeCpuDecision::ResolvedToCohort(CpuBaseline::NativeResolvedCohort {
            cohort_id: id.to_owned(),
        }),
        None => NativeCpuDecision::RefusedNonCacheable {
            reason: "target-cpu=native without a resolved host cohort",
        },
    })
}

/// The keyed output-platform contract.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OutputPlatformContract {
    /// Target triple the output bytes are for.
    pub target_triple: String,
    /// Host ABI triple — keyed because proc-macros/build-scripts/host
    /// tools RUN on the host and their outputs feed compilation.
    pub host_abi_triple: String,
    /// Explicit CPU baseline contract (never a bare "native").
    pub cpu_baseline: CpuBaseline,
    /// libc/runtime identity (`"glibc-2.39"`, `"musl-1.2"`, …).
    pub libc_runtime: String,
    /// Linker output format identity.
    pub linker_format: String,
    /// SDK/Xcode identity digest + deployment target, where applicable.
    pub sdk_identity: Option<TypedDigest>,
    /// Deployment target string (e.g. `MACOSX_DEPLOYMENT_TARGET`).
    pub deployment_target: Option<String>,
    /// Signing policy identity where outputs embed signatures.
    pub signing_policy: Option<String>,
    /// Filesystem semantic class presented to the action (case
    /// sensitivity, symlink policy, timestamp granularity class).
    pub filesystem_semantic_class: String,
}

impl OutputPlatformContract {
    /// Canonical bytes (exhaustive destructure: a new field cannot ship
    /// without a hashing decision).
    #[must_use]
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let Self {
            target_triple,
            host_abi_triple,
            cpu_baseline,
            libc_runtime,
            linker_format,
            sdk_identity,
            deployment_target,
            signing_policy,
            filesystem_semantic_class,
        } = self;
        let mut enc = CanonicalEncoder::new();
        enc.str(target_triple).str(host_abi_triple);
        match cpu_baseline {
            CpuBaseline::Explicit {
                baseline,
                feature_adjustments,
            } => {
                enc.u32(1).str(baseline);
                let mut adj = feature_adjustments.clone();
                adj.sort_unstable();
                enc.u64(adj.len() as u64);
                for a in &adj {
                    enc.str(a);
                }
            }
            CpuBaseline::NativeResolvedCohort { cohort_id } => {
                enc.u32(2).str(cohort_id);
            }
        }
        enc.str(libc_runtime).str(linker_format);
        match sdk_identity {
            None => {
                enc.u32(0);
            }
            Some(d) => {
                enc.u32(1).str(d.domain).bytes(&d.bytes);
            }
        }
        for opt in [deployment_target, signing_policy] {
            match opt {
                None => {
                    enc.u32(0);
                }
                Some(s) => {
                    enc.u32(1).str(s);
                }
            }
        }
        enc.str(filesystem_semantic_class);
        enc.finish()
    }

    /// The contract digest — the descriptor's `output_platform` slot.
    #[must_use]
    pub fn contract_digest(&self) -> TypedDigest {
        compute(DOMAIN_OUTPUT_PLATFORM, &self.canonical_bytes())
    }
}

/// Scheduler-only worker eligibility. NEVER keyed: there is no digest
/// method, and nothing here can reach `OutputPlatformContract` bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExecutionEligibility {
    /// Kernel version string.
    pub kernel_version: String,
    /// Namespace/sandbox capability names available.
    pub namespace_capabilities: Vec<String>,
    /// Available memory (bytes).
    pub available_memory_bytes: u64,
    /// Available disk (bytes).
    pub available_disk_bytes: u64,
    /// Schedulable CPU slots.
    pub available_cpu_slots: u32,
    /// Load-pressure signal.
    pub pressure_class: String,
    /// Queue depth right now.
    pub queue_depth: u32,
    /// Worker identity.
    pub worker_id: String,
    /// Placement/locality hint.
    pub locality: String,
    /// Sandbox implementation this worker would use (may differ between
    /// workers satisfying the SAME semantic policy).
    pub sandbox_implementation: String,
}

#[cfg(test)]
mod tests {
    use super::*;
    use rabs_protocol::result_identity::DigestAlgorithm;

    fn contract() -> OutputPlatformContract {
        OutputPlatformContract {
            target_triple: "x86_64-unknown-linux-gnu".into(),
            host_abi_triple: "x86_64-unknown-linux-gnu".into(),
            cpu_baseline: CpuBaseline::Explicit {
                baseline: "x86-64-v2".into(),
                feature_adjustments: vec!["+avx2".into()],
            },
            libc_runtime: "glibc-2.39".into(),
            linker_format: "elf64".into(),
            sdk_identity: None,
            deployment_target: None,
            signing_policy: None,
            filesystem_semantic_class: "case-sensitive-symlinks-ns".into(),
        }
    }

    fn eligibility() -> ExecutionEligibility {
        ExecutionEligibility {
            kernel_version: "6.8.0-45".into(),
            namespace_capabilities: vec!["user-ns".into(), "mount-ns".into()],
            available_memory_bytes: 64 << 30,
            available_disk_bytes: 1 << 40,
            available_cpu_slots: 32,
            pressure_class: "low".into(),
            queue_depth: 3,
            worker_id: "wkr-1".into(),
            locality: "rack-a".into(),
            sandbox_implementation: "bubblewrap".into(),
        }
    }

    #[test]
    fn eligibility_fields_cannot_reach_the_key() {
        // The I23 boundary test: mutate EVERY eligibility field; the
        // contract digest is computed from the contract alone, so the
        // key provably cannot move. (Structurally there is also no
        // digest method on ExecutionEligibility to call by mistake.)
        let c = contract();
        let before = c.contract_digest();
        let mut e = eligibility();
        e.kernel_version = "6.9.0-1".into();
        e.namespace_capabilities.clear();
        e.available_memory_bytes = 1;
        e.available_disk_bytes = 1;
        e.available_cpu_slots = 1;
        e.pressure_class = "critical".into();
        e.queue_depth = 9999;
        e.worker_id = "wkr-2".into();
        e.locality = "rack-z".into();
        e.sandbox_implementation = "namespaces-direct".into();
        assert_eq!(before, c.contract_digest());
    }

    #[test]
    fn native_cpu_is_never_silently_normalized() {
        // Non-native values pass through to the Explicit arm untouched.
        assert_eq!(decide_native_cpu("x86-64-v3", None), None);
        // native + resolved cohort: cacheable within the cohort namespace.
        let resolved = decide_native_cpu("native", Some("epyc-9654-avx512")).unwrap();
        let NativeCpuDecision::ResolvedToCohort(baseline) = resolved else {
            panic!("expected cohort resolution");
        };
        // The cohort ID namespaces the key: different cohorts fork.
        let mut a = contract();
        a.cpu_baseline = baseline;
        let mut b = contract();
        b.cpu_baseline = CpuBaseline::NativeResolvedCohort {
            cohort_id: "m3-max".into(),
        };
        assert_ne!(a.contract_digest(), b.contract_digest());
        // native WITHOUT a cohort: refused non-cacheable — no contract
        // value exists to key on, which IS the acceptance posture.
        assert!(matches!(
            decide_native_cpu("native", None),
            Some(NativeCpuDecision::RefusedNonCacheable { .. })
        ));
    }

    #[test]
    fn keyed_fields_all_move_the_digest() {
        let base = contract().contract_digest();
        let mut m = contract();
        m.target_triple = "aarch64-unknown-linux-gnu".into();
        assert_ne!(base, m.contract_digest());
        // Host ABI keys even with the same target (proc-macro hazard).
        let mut m = contract();
        m.host_abi_triple = "aarch64-apple-darwin".into();
        assert_ne!(base, m.contract_digest());
        let mut m = contract();
        m.libc_runtime = "musl-1.2".into();
        assert_ne!(base, m.contract_digest());
        let mut m = contract();
        m.linker_format = "mach-o".into();
        assert_ne!(base, m.contract_digest());
        let mut m = contract();
        m.sdk_identity = Some(TypedDigest {
            algorithm: DigestAlgorithm::Sha256V1,
            domain: "rabs.sdk.v1",
            bytes: [5; 32],
        });
        assert_ne!(base, m.contract_digest());
        let mut m = contract();
        m.deployment_target = Some("14.0".into());
        assert_ne!(base, m.contract_digest());
        let mut m = contract();
        m.signing_policy = Some("adhoc".into());
        assert_ne!(base, m.contract_digest());
        let mut m = contract();
        m.filesystem_semantic_class = "case-insensitive".into();
        assert_ne!(base, m.contract_digest());
        let mut m = contract();
        m.cpu_baseline = CpuBaseline::Explicit {
            baseline: "x86-64-v2".into(),
            feature_adjustments: vec![],
        };
        assert_ne!(base, m.contract_digest());
    }

    #[test]
    fn feature_adjustments_are_a_set_not_a_sequence() {
        let mut a = contract();
        a.cpu_baseline = CpuBaseline::Explicit {
            baseline: "x86-64-v2".into(),
            feature_adjustments: vec!["+avx2".into(), "-sse4.2".into()],
        };
        let mut b = contract();
        b.cpu_baseline = CpuBaseline::Explicit {
            baseline: "x86-64-v2".into(),
            feature_adjustments: vec!["-sse4.2".into(), "+avx2".into()],
        };
        assert_eq!(a.contract_digest(), b.contract_digest());
    }
}
