//! Platform/isolation authority matrix with explicit no-claims (bead A015).
//!
//! The machine-readable form of the plan's platform maturity matrix
//! (Part VII §26) and isolation-profile table (Part VIII §19), consumed by
//! serving policy and by scheduler hard exclusions. Two invariants govern
//! everything here:
//!
//! - **I25 — isolation authority is explicit.** Every result records the
//!   profile that produced it; different profiles never silently share the
//!   same serving authority.
//! - **I28 — unknown behavior loses authority, not visibility.** Anything
//!   this matrix does not affirmatively grant is denied: unknown profiles,
//!   unknown scopes, and unproven combinations reduce to no authority
//!   rather than optimistic parity (risk R37: cross-platform semantics are
//!   overclaimed).
//!
//! A profile names what was **actually enforced**, not what was intended:
//! `SOURCE_DATE_EPOCH`, a fixed hostname, or best-effort syscall tracing
//! are controls, not proof.

/// Isolation/input-observation profiles a result can be produced under.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum IsolationProfile {
    /// Linux namespaces + cgroups, explicit env, closed filesystem/process/
    /// network view, validated time/randomness policy.
    StrictHermeticLinux,
    /// VM/chroot-style stable root with a validated input/effect boundary
    /// (the macOS strict path: APFS clones alone are NOT this — risk R47).
    StrictHermeticVm,
    /// Useful tracing and containment, but raw clock/randomness or read
    /// closure may escape (includes macOS host-audit mode).
    HostSandboxAudit,
    /// Immutable checksummed dependency source plus conservative exact
    /// inputs — the narrowly admitted dependency lane.
    DependencyImmutableFastPath,
    /// Real ambient effects exposed; local execution only.
    VolatileLocal,
    /// Windows initial support: observation and limited classes only; no
    /// implied parity with any Unix profile.
    WindowsInitial,
}

impl IsolationProfile {
    /// All profiles, for exhaustiveness checks.
    pub const ALL: [Self; 6] = [
        Self::StrictHermeticLinux,
        Self::StrictHermeticVm,
        Self::HostSandboxAudit,
        Self::DependencyImmutableFastPath,
        Self::VolatileLocal,
        Self::WindowsInitial,
    ];
}

/// What kind of serving is being asked about.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ServingScope {
    /// Serving immutable registry/git dependency action results.
    DependencyServing,
    /// Serving workspace-member action results across worktrees.
    WorkspaceServing,
    /// Publishing results for consumption on other machines.
    CrossMachinePublication,
}

impl ServingScope {
    /// All scopes, for exhaustiveness checks.
    pub const ALL: [Self; 3] = [
        Self::DependencyServing,
        Self::WorkspaceServing,
        Self::CrossMachinePublication,
    ];
}

/// The authority a (profile, scope) pair carries.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Authority {
    /// Authorized once the ordinary correctness gates pass (shadow corpus,
    /// zero divergence, SLOs).
    EligibleAfterGates,
    /// Authorized after gates, and only within the matching
    /// output-platform / SDK-ABI / filesystem-semantic class.
    EligibleWithinPlatformClass,
    /// Authorized only for explicitly admitted immutable dependency
    /// classes; nothing broader.
    SelectedImmutableClassesOnly,
    /// Shadow/observation value only; never authoritative shared serving.
    ShadowOnly,
    /// Not authorized. The accompanying no-claim explains what is
    /// deliberately NOT being promised.
    NotAuthorized,
}

impl Authority {
    /// Whether this authority permits authoritative shared serving at all.
    #[must_use]
    pub const fn may_serve(self) -> bool {
        !matches!(self, Self::ShadowOnly | Self::NotAuthorized)
    }
}

/// One matrix cell: the authority plus the explicit claim boundary.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AuthorityCell {
    /// Authority granted to this (profile, scope) pair.
    pub authority: Authority,
    /// The explicit claim/no-claim boundary. Never empty: even a grant
    /// states what it does not promise.
    pub boundary: &'static str,
}

/// Look up the authority for a (profile, scope) pair.
///
/// This is a total function over the known enums, and its default posture
/// is denial: every arm that grants authority is an explicit, cited
/// decision from the plan; everything else is `NotAuthorized`.
#[must_use]
pub const fn authority(profile: IsolationProfile, scope: ServingScope) -> AuthorityCell {
    use Authority as A;
    use IsolationProfile as P;
    use ServingScope as S;
    match (profile, scope) {
        // ---- Linux strict hermetic: the first full-authority platform ----
        (P::StrictHermeticLinux, S::DependencyServing | S::WorkspaceServing) => AuthorityCell {
            authority: A::EligibleAfterGates,
            boundary: "Requires proof the selected namespace/cgroup/seccomp \
                       combination enforces the documented boundary; a \
                       Linux/epoll proof implies nothing about macOS.",
        },
        (P::StrictHermeticLinux, S::CrossMachinePublication) => AuthorityCell {
            authority: A::EligibleWithinPlatformClass,
            boundary: "Only within the matching output-platform contract \
                       (target/host ABI, CPU baseline, libc, filesystem \
                       semantic class).",
        },
        // ---- macOS/other VM-chroot strict ---------------------------------
        (P::StrictHermeticVm, S::DependencyServing) => AuthorityCell {
            authority: A::EligibleAfterGates,
            boundary: "VM/chroot boundary must be validated per host; APFS \
                       clones alone do not give concurrent processes one \
                       canonical visible path (risk R47).",
        },
        (P::StrictHermeticVm, S::WorkspaceServing) => AuthorityCell {
            authority: A::EligibleAfterGates,
            boundary: "Additionally requires the macOS platform proof \
                       (canonical process root + authoritative input \
                       observation); FSEvents observes changes, not reads.",
        },
        (P::StrictHermeticVm, S::CrossMachinePublication) => AuthorityCell {
            authority: A::EligibleWithinPlatformClass,
            boundary: "Only within the matching SDK/ABI/deployment-target \
                       class.",
        },
        // ---- Host-audit (incl. macOS host-audit) --------------------------
        (P::HostSandboxAudit, S::DependencyServing) => AuthorityCell {
            authority: A::SelectedImmutableClassesOnly,
            boundary: "Selected immutable dependency classes only; raw \
                       clock/randomness or read closure may escape the \
                       tracer, so nothing broader is authoritative.",
        },
        (P::HostSandboxAudit, S::WorkspaceServing | S::CrossMachinePublication) => AuthorityCell {
            authority: A::ShadowOnly,
            boundary: "NO authoritative shared workspace results and NO \
                       cross-machine publication from host-audit mode; \
                       shadow/dev-local value only.",
        },
        // ---- Dependency immutable fast path -------------------------------
        (P::DependencyImmutableFastPath, S::DependencyServing) => AuthorityCell {
            authority: A::SelectedImmutableClassesOnly,
            boundary: "Authoritative only for admitted dependency classes \
                       with checksummed immutable sources and conservative \
                       exact inputs.",
        },
        (P::DependencyImmutableFastPath, S::CrossMachinePublication) => AuthorityCell {
            authority: A::SelectedImmutableClassesOnly,
            boundary: "Admitted immutable dependency classes within the \
                       matching output-platform class only.",
        },
        (P::DependencyImmutableFastPath, S::WorkspaceServing) => AuthorityCell {
            authority: A::NotAuthorized,
            boundary: "The fast path proves nothing about workspace \
                       members; workspace authority requires canonical \
                       Cargo planning (I19).",
        },
        // ---- Volatile local ------------------------------------------------
        (P::VolatileLocal, _) => AuthorityCell {
            authority: A::NotAuthorized,
            boundary: "Real ambient effects are exposed; results are local \
                       observations, never shared cache entries.",
        },
        // ---- Windows initial ----------------------------------------------
        (P::WindowsInitial, S::DependencyServing) => AuthorityCell {
            authority: A::ShadowOnly,
            boundary: "Observation and limited classes only; no implied \
                       parity with any Unix profile; separately versioned \
                       path/environment encoding contract required first.",
        },
        (P::WindowsInitial, S::WorkspaceServing | S::CrossMachinePublication) => AuthorityCell {
            authority: A::NotAuthorized,
            boundary: "Workspace serving is deferred on Windows and \
                       cross-machine publication carries no implied parity.",
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The exact matrix the plan states, cell by cell — a deliberate-change
    /// detector stronger than a fingerprint: any drift names the cell.
    #[test]
    fn matrix_matches_the_plan() {
        use Authority as A;
        use IsolationProfile as P;
        use ServingScope as S;
        let expect = [
            (
                P::StrictHermeticLinux,
                S::DependencyServing,
                A::EligibleAfterGates,
            ),
            (
                P::StrictHermeticLinux,
                S::WorkspaceServing,
                A::EligibleAfterGates,
            ),
            (
                P::StrictHermeticLinux,
                S::CrossMachinePublication,
                A::EligibleWithinPlatformClass,
            ),
            (
                P::StrictHermeticVm,
                S::DependencyServing,
                A::EligibleAfterGates,
            ),
            (
                P::StrictHermeticVm,
                S::WorkspaceServing,
                A::EligibleAfterGates,
            ),
            (
                P::StrictHermeticVm,
                S::CrossMachinePublication,
                A::EligibleWithinPlatformClass,
            ),
            (
                P::HostSandboxAudit,
                S::DependencyServing,
                A::SelectedImmutableClassesOnly,
            ),
            (P::HostSandboxAudit, S::WorkspaceServing, A::ShadowOnly),
            (
                P::HostSandboxAudit,
                S::CrossMachinePublication,
                A::ShadowOnly,
            ),
            (
                P::DependencyImmutableFastPath,
                S::DependencyServing,
                A::SelectedImmutableClassesOnly,
            ),
            (
                P::DependencyImmutableFastPath,
                S::WorkspaceServing,
                A::NotAuthorized,
            ),
            (
                P::DependencyImmutableFastPath,
                S::CrossMachinePublication,
                A::SelectedImmutableClassesOnly,
            ),
            (P::VolatileLocal, S::DependencyServing, A::NotAuthorized),
            (P::VolatileLocal, S::WorkspaceServing, A::NotAuthorized),
            (
                P::VolatileLocal,
                S::CrossMachinePublication,
                A::NotAuthorized,
            ),
            (P::WindowsInitial, S::DependencyServing, A::ShadowOnly),
            (P::WindowsInitial, S::WorkspaceServing, A::NotAuthorized),
            (
                P::WindowsInitial,
                S::CrossMachinePublication,
                A::NotAuthorized,
            ),
        ];
        assert_eq!(
            expect.len(),
            IsolationProfile::ALL.len() * ServingScope::ALL.len(),
            "expectation table must cover the full matrix"
        );
        for (p, s, want) in expect {
            let got = authority(p, s);
            assert_eq!(
                got.authority, want,
                "matrix cell ({p:?}, {s:?}) drifted from the plan"
            );
        }
    }

    /// I28: weaker profiles must never outrank stricter ones, and host-audit
    /// or volatile profiles can never reach authoritative workspace serving.
    #[test]
    fn reduced_profiles_never_gain_workspace_authority() {
        for p in [
            IsolationProfile::HostSandboxAudit,
            IsolationProfile::VolatileLocal,
            IsolationProfile::WindowsInitial,
            IsolationProfile::DependencyImmutableFastPath,
        ] {
            let cell = authority(p, ServingScope::WorkspaceServing);
            assert!(
                !cell.authority.may_serve(),
                "{p:?} must not serve workspace results, got {:?}",
                cell.authority
            );
        }
    }

    /// Every cell — including grants — states an explicit claim boundary.
    #[test]
    fn every_cell_has_a_nonempty_boundary_statement() {
        for p in IsolationProfile::ALL {
            for s in ServingScope::ALL {
                let cell = authority(p, s);
                assert!(
                    !cell.boundary.trim().is_empty(),
                    "cell ({p:?}, {s:?}) is missing its claim/no-claim boundary"
                );
            }
        }
    }

    /// may_serve is the single serving gate: shadow-only and not-authorized
    /// both deny; everything else affirms.
    #[test]
    fn may_serve_partitions_authorities() {
        assert!(Authority::EligibleAfterGates.may_serve());
        assert!(Authority::EligibleWithinPlatformClass.may_serve());
        assert!(Authority::SelectedImmutableClassesOnly.may_serve());
        assert!(!Authority::ShadowOnly.may_serve());
        assert!(!Authority::NotAuthorized.may_serve());
    }
}
