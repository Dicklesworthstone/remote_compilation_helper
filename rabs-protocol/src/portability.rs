//! Platform portability classes (bead D014; invariants I25/I28; plan
//! §65; risk R37).
//!
//! WHICH (platform, isolation profile, filesystem semantic class,
//! SDK/ABI) combinations may share results — the machine-readable
//! answer serving policy and the scheduler both consume. Rules:
//!
//! - **no optimistic parity labels**: platforms never share by analogy
//!   (a Linux namespace proof implies nothing about macOS — the
//!   authority matrix's own words); cross-platform sharing is a HARD
//!   exclusion, not a downgraded maybe;
//! - authority comes from the A005 matrix: a profile whose authority
//!   for the scope is `ShadowOnly`/`NotAuthorized` excludes hard, with
//!   the matrix's boundary text as the reason;
//! - filesystem semantic class and SDK/ABI class must match EXACTLY;
//!   an unsupported/unknown property REDUCES authority explicitly
//!   (exclusion with a named reason), never silently passes.

use crate::authority_matrix::{Authority, IsolationProfile, ServingScope, authority};

/// Platform families (no parity between them, ever).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(missing_docs)]
pub enum Platform {
    Linux,
    MacOs,
    Windows,
}

/// The portability-relevant facts about one side (producer or
/// consumer) of a proposed share.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlatformFacts {
    /// Platform family.
    pub platform: Platform,
    /// Isolation profile the result was produced under / the consumer
    /// requires.
    pub profile: IsolationProfile,
    /// Filesystem semantic class keying string (D022).
    pub filesystem_class: String,
    /// SDK/ABI class identity (F008 contract digest hex or class
    /// name); `None` = unknown, which EXCLUDES.
    pub sdk_abi_class: Option<String>,
}

/// The sharing decision (machine-readable; the scheduler treats every
/// `ExcludedHard` as a hard placement exclusion).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SharingDecision {
    /// The combination may share results in this scope.
    Shareable,
    /// Hard exclusion with the governing reason.
    ExcludedHard {
        /// Why (matrix boundary text or the named mismatch).
        reason: &'static str,
    },
}

/// Decide whether `producer`'s results may serve `consumer` in `scope`.
#[must_use]
pub fn may_share(
    producer: &PlatformFacts,
    consumer: &PlatformFacts,
    scope: ServingScope,
) -> SharingDecision {
    // 1. Platform families never share by analogy (R37).
    if producer.platform != consumer.platform {
        return SharingDecision::ExcludedHard {
            reason: "cross-platform sharing is never inferred; no parity labels",
        };
    }
    // 2. The producing profile's authority for this scope (A005).
    let cell = authority(producer.profile, scope);
    match cell.authority {
        Authority::NotAuthorized | Authority::ShadowOnly => {
            return SharingDecision::ExcludedHard {
                reason: cell.boundary,
            };
        }
        Authority::SelectedImmutableClassesOnly
        | Authority::EligibleAfterGates
        | Authority::EligibleWithinPlatformClass => {}
    }
    // 3. The consumer must accept the producing profile (a consumer
    //    requiring strict isolation cannot take host-audit output).
    if producer.profile != consumer.profile {
        return SharingDecision::ExcludedHard {
            reason: "producer/consumer isolation profiles differ; authority is per-profile",
        };
    }
    // 4. Filesystem semantic class equality (D022 default rule).
    if producer.filesystem_class != consumer.filesystem_class {
        return SharingDecision::ExcludedHard {
            reason: "filesystem semantic classes differ",
        };
    }
    // 5. SDK/ABI class: exact match required; unknown excludes.
    match (&producer.sdk_abi_class, &consumer.sdk_abi_class) {
        (Some(p), Some(c)) if p == c => SharingDecision::Shareable,
        (Some(_), Some(_)) => SharingDecision::ExcludedHard {
            reason: "SDK/ABI classes differ",
        },
        _ => SharingDecision::ExcludedHard {
            reason: "unknown SDK/ABI class reduces authority explicitly",
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn linux_strict() -> PlatformFacts {
        PlatformFacts {
            platform: Platform::Linux,
            profile: IsolationProfile::StrictHermeticLinux,
            filesystem_class:
                "case-sensitive.unicode-bytes.symlink-posix.hardlink-posix.perm-execbit.xattr-hidden"
                    .into(),
            sdk_abi_class: Some("x86_64-linux-gnu.glibc-2.39".into()),
        }
    }

    #[test]
    fn matching_strict_linux_facts_share() {
        assert_eq!(
            may_share(
                &linux_strict(),
                &linux_strict(),
                ServingScope::CrossMachinePublication
            ),
            SharingDecision::Shareable
        );
    }

    #[test]
    fn platforms_never_share_by_analogy() {
        // R37: identical-LOOKING facts across platform families exclude
        // hard — there is no optimistic parity label to grant.
        let mut mac = linux_strict();
        mac.platform = Platform::MacOs;
        mac.profile = IsolationProfile::StrictHermeticVm;
        let decision = may_share(&linux_strict(), &mac, ServingScope::DependencyServing);
        assert!(matches!(decision, SharingDecision::ExcludedHard { .. }));
    }

    #[test]
    fn shadow_only_profiles_exclude_with_the_matrix_boundary() {
        // Host-audit workspace serving is ShadowOnly in the A005
        // matrix: the exclusion carries the matrix's own boundary text.
        let mut audit = linux_strict();
        audit.profile = IsolationProfile::HostSandboxAudit;
        let decision = may_share(&audit, &audit, ServingScope::WorkspaceServing);
        let SharingDecision::ExcludedHard { reason } = decision else {
            panic!("host-audit workspace serving must exclude");
        };
        assert!(reason.contains("NO authoritative shared workspace"));
    }

    #[test]
    fn class_mismatches_and_unknowns_exclude_explicitly() {
        // Filesystem semantic class differs.
        let mut insensitive = linux_strict();
        insensitive.filesystem_class = "case-ins-preserving.rest".into();
        assert!(matches!(
            may_share(
                &linux_strict(),
                &insensitive,
                ServingScope::WorkspaceServing
            ),
            SharingDecision::ExcludedHard { reason } if reason.contains("filesystem")
        ));
        // SDK/ABI differs.
        let mut other_abi = linux_strict();
        other_abi.sdk_abi_class = Some("x86_64-linux-musl.musl-1.2".into());
        assert!(matches!(
            may_share(&linux_strict(), &other_abi, ServingScope::WorkspaceServing),
            SharingDecision::ExcludedHard { reason } if reason.contains("SDK/ABI classes differ")
        ));
        // UNKNOWN SDK/ABI: reduces authority explicitly, never passes.
        let mut unknown = linux_strict();
        unknown.sdk_abi_class = None;
        assert!(matches!(
            may_share(&linux_strict(), &unknown, ServingScope::WorkspaceServing),
            SharingDecision::ExcludedHard { reason } if reason.contains("unknown SDK/ABI")
        ));
    }

    #[test]
    fn profile_mismatch_excludes_even_on_one_platform() {
        // A strict-hermetic consumer cannot take volatile-local output.
        let mut volatile = linux_strict();
        volatile.profile = IsolationProfile::VolatileLocal;
        assert!(matches!(
            may_share(&volatile, &linux_strict(), ServingScope::WorkspaceServing),
            SharingDecision::ExcludedHard { .. }
        ));
    }
}
