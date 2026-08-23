//! Build-script policy routing: registry-aggressive vs
//! workspace-audit-first (bead N005; plan §196 Epic N; consumes the N006
//! [`crate::generator_detection`] volatility classification).
//!
//! THE SPLIT, executable form:
//!
//! - **Registry / git dependency build scripts** get the AGGRESSIVE
//!   posture: sandboxing + discovery + interception + a determinism
//!   audit must ALL be complete before broad sharing is even considered.
//!   An incomplete audit blocks sharing regardless of policy flags —
//!   you cannot flag your way out of an un-audited third-party script.
//! - **Workspace build scripts** are AUDIT-FIRST: caching requires the
//!   project's explicit policy allow-flags for whatever volatility the
//!   N006 scan detected (git / clock / network; randomness + secrets
//!   flags exist for the wider policy surface). VOLATILITY IS PREFERRED
//!   OVER OPTIMISTIC CACHING: a missing allow-flag is a typed refusal
//!   with an actionable why-code (`rch why` consumes these verbatim),
//!   never an optimistic cache-and-hope.
//!
//! Flag requirements per detected reason (V1 conservative mapping,
//! measured against what each generator actually embeds):
//! - `volatile-clock-read` requires `clock`;
//! - `volatile-git-state` requires `git`;
//! - `volatile-network-fetch` requires `network`;
//! - `volatile-generator-vergen` / `-built` require BOTH `clock` and
//!   `git` (those crates emit build timestamps and VCS state);
//! - `randomness` / `secrets` flags are reserved surface (N007+).
//!
//! Zero deps; pure routing like everything in this crate.

use crate::generator_detection::{Detection, Volatility};

/// Where the build script's package came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DependencyOrigin {
    /// Fetched from a registry or a git dependency: not audited code.
    RegistryOrGit,
    /// A workspace member: the operator's own tree.
    WorkspaceMember,
}

/// The resulting posture for one build script.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuditPosture {
    /// Registry/git scripts: aggressive sandboxing + discovery +
    /// interception + determinism audit BEFORE broad sharing.
    RegistryAggressive,
    /// Workspace scripts: audit-first with explicit project policy.
    WorkspaceAuditFirst,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ProjectPolicyFlags {
    /// Git state reads/describes may be cached.
    pub git: bool,
    /// Clock reads / timestamp embedding may be cached.
    pub clock: bool,
    /// Randomness use may be cached.
    pub randomness: bool,
    /// Network fetches may be cached.
    pub network: bool,
    /// Secret-adjacent operations may proceed (N007+ surface).
    pub secrets: bool,
}

/// One actionable refusal: the why-code is stable and quotable by
/// `rch why`; the requirement names the flag that would change it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyRefusal {
    /// Stable why-code (`volatile-clock-read`, …).
    pub code: &'static str,
    /// The policy flag that would admit this behavior.
    pub required_flag: &'static str,
}

/// The full routing result for one build script.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyRouting {
    /// Posture assigned from dependency origin.
    pub posture: AuditPosture,
    /// Whether caching/sharing may proceed AT ALL under current policy.
    pub allowed: bool,
    /// Actionable refusals (empty when allowed).
    pub refusals: Vec<PolicyRefusal>,
    /// Registry/git scripts only: broad sharing stays blocked until the
    /// determinism audit completes, independent of policy flags.
    pub broad_sharing_blocked_pending_audit: bool,
}

/// Route one build script through the policy split.
///
/// Laws, in evaluation order:
/// 1. Posture follows origin (registry/git ⇒ aggressive; workspace ⇒
///    audit-first).
/// 2. Every DETECTED volatility reason must be covered by its project
///    flag; uncovered reasons produce one actionable refusal EACH
///    (volatility preferred over optimistic caching).
/// 3. Registry/git origins additionally require a COMPLETED determinism
///    audit before broad sharing; flags do not substitute.
#[must_use]
pub fn route_build_script_policy(
    origin: DependencyOrigin,
    volatility: &Volatility,
    flags: &ProjectPolicyFlags,
    determinism_audit_complete: bool,
) -> PolicyRouting {
    let posture = match origin {
        DependencyOrigin::RegistryOrGit => AuditPosture::RegistryAggressive,
        DependencyOrigin::WorkspaceMember => AuditPosture::WorkspaceAuditFirst,
    };

    let mut refusals = Vec::new();
    if let Volatility::Volatile { reasons } = volatility {
        for code in reasons {
            // Each detection reason maps to the flag(s) that would
            // admit it. Generator crates embed build timestamps AND
            // VCS state: conservative aggregate of both needs, each
            // unmet need its own refusal (same detection code).
            let required_flags: &[&str] = match *code {
                "volatile-clock-read" => &["clock"],
                "volatile-git-state" => &["git"],
                "volatile-network-fetch" => &["network"],
                "volatile-generator-vergen" | "volatile-generator-built" => &["clock", "git"],
                _ => &[],
            };
            for flag in required_flags {
                let covered = match *flag {
                    "clock" => flags.clock,
                    "git" => flags.git,
                    "network" => flags.network,
                    _ => false,
                };
                if !covered {
                    refusals.push(PolicyRefusal {
                        code,
                        required_flag: flag,
                    });
                }
            }
        }
    }

    let broad_sharing_blocked_pending_audit =
        matches!(origin, DependencyOrigin::RegistryOrGit) && !determinism_audit_complete;
    if broad_sharing_blocked_pending_audit {
        refusals.push(PolicyRefusal {
            code: "determinism-audit-incomplete",
            required_flag: "n/a-complete-the-determinism-audit",
        });
    }

    let allowed = refusals.is_empty();
    PolicyRouting {
        posture,
        allowed,
        refusals,
        broad_sharing_blocked_pending_audit,
    }
}

/// Convenience: run the N006 scan + classification + routing in one call.
#[must_use]
pub fn route_scanned_source(
    origin: DependencyOrigin,
    source: &[u8],
    flags: &ProjectPolicyFlags,
    determinism_audit_complete: bool,
) -> (Vec<Detection>, PolicyRouting) {
    let detections = crate::generator_detection::detect_generators(source);
    let volatility = crate::generator_detection::classify_volatility(&detections);
    let routing = route_build_script_policy(origin, &volatility, flags, determinism_audit_complete);
    (detections, routing)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::generator_detection::{classify_volatility, detect_generators};

    fn route(
        origin: DependencyOrigin,
        source: &[u8],
        flags: &ProjectPolicyFlags,
        audit_done: bool,
    ) -> PolicyRouting {
        let ds = detect_generators(source);
        let vol = classify_volatility(&ds);
        route_build_script_policy(origin, &vol, flags, audit_done)
    }

    fn all_allowed() -> ProjectPolicyFlags {
        ProjectPolicyFlags {
            git: true,
            clock: true,
            randomness: true,
            network: true,
            secrets: true,
        }
    }

    #[test]
    fn n005_registry_origin_gets_aggressive_posture_and_audit_gate() {
        // Even a CLEAN registry script is blocked from broad sharing
        // until the determinism audit completes.
        let r = route(
            DependencyOrigin::RegistryOrGit,
            b"println!(\"cargo:rerun-if-changed=build.rs\");",
            &all_allowed(),
            false,
        );
        assert_eq!(r.posture, AuditPosture::RegistryAggressive);
        assert!(!r.allowed);
        assert!(r.broad_sharing_blocked_pending_audit);
        assert_eq!(r.refusals[0].code, "determinism-audit-incomplete");

        // Audit complete + clean script: allowed.
        let r2 = route(
            DependencyOrigin::RegistryOrGit,
            b"println!(\"cargo:rerun-if-changed=build.rs\");",
            &all_allowed(),
            true,
        );
        assert!(r2.allowed);
        assert!(!r2.broad_sharing_blocked_pending_audit);
    }

    #[test]
    fn n005_workspace_volatile_without_flags_is_refused_actionably() {
        let r = route(
            DependencyOrigin::WorkspaceMember,
            b"let t = SystemTime::now();",
            &ProjectPolicyFlags::default(),
            true,
        );
        assert_eq!(r.posture, AuditPosture::WorkspaceAuditFirst);
        assert!(!r.allowed);
        assert_eq!(
            r.refusals,
            vec![PolicyRefusal {
                code: "volatile-clock-read",
                required_flag: "clock",
            }]
        );
    }

    #[test]
    fn n005_workspace_with_matching_flags_is_allowed() {
        let flags = ProjectPolicyFlags {
            clock: true,
            git: true,
            ..ProjectPolicyFlags::default()
        };
        let r = route(
            DependencyOrigin::WorkspaceMember,
            b"SystemTime::now();\ngit describe --dirty;",
            &flags,
            true,
        );
        assert!(r.allowed, "refusals: {:?}", r.refusals);
    }

    /// Generator-crate detection requires BOTH underlying needs: clock
    /// alone is insufficient until git is also allowed.
    #[test]
    fn n005_generator_crates_need_clock_and_git() {
        let src = b"vergen::emit();";
        let partial_flags = ProjectPolicyFlags {
            clock: true,
            ..ProjectPolicyFlags::default()
        };
        let partial = route(DependencyOrigin::WorkspaceMember, src, &partial_flags, true);
        assert_eq!(
            partial.refusals,
            vec![PolicyRefusal {
                code: "volatile-generator-vergen",
                required_flag: "git",
            }]
        );
        let full_flags = ProjectPolicyFlags {
            clock: true,
            git: true,
            ..ProjectPolicyFlags::default()
        };
        let full = route(DependencyOrigin::WorkspaceMember, src, &full_flags, true);
        assert!(full.allowed, "{:?}", full.refusals);
    }

    #[test]
    fn n005_network_detection_requires_the_network_flag() {
        let mut flags = ProjectPolicyFlags {
            git: true,
            clock: true,
            ..ProjectPolicyFlags::default()
        };
        let r = route(
            DependencyOrigin::WorkspaceMember,
            b"ureq::get(u);",
            &flags,
            true,
        );
        assert_eq!(
            r.refusals,
            vec![PolicyRefusal {
                code: "volatile-network-fetch",
                required_flag: "network",
            }]
        );
        flags.network = true;
        assert!(
            route(
                DependencyOrigin::WorkspaceMember,
                b"ureq::get(u);",
                &flags,
                true
            )
            .allowed
        );
    }
}
