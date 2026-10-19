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

    #[test]
    fn d013_concurrent_macos_actions_observe_identical_canonical_roots_and_ledger_is_verified() {
        const LEDGER_DOC: &str = include_str!("../../docs/rabs-unsafe-boundary-ledger.md");
        assert!(
            LEDGER_DOC.contains("rabs-macos-root-helper"),
            "docs/rabs-unsafe-boundary-ledger.md must record rabs-macos-root-helper (D013)"
        );
        assert!(
            LEDGER_DOC.contains("rabs-macos-es-observer"),
            "docs/rabs-unsafe-boundary-ledger.md must record rabs-macos-es-observer (E017)"
        );

        // Two concurrent actions backed by distinct APFS clone staging directories on the host.
        let req_a = MacOsRootLaunchRequest {
            action_id: 101,
            mechanism: MacOsRootMechanism::ValidatedChrootHelper,
            host_apfs_clone_stage_dir: "/private/var/rabs/stage/act-101".into(),
            canonical_mounts: MacOsRootLaunchRequest::default_canonical_mounts(),
            contains_symlink_to_caller_space: false,
            request_bytes: 2048,
        };
        let req_b = MacOsRootLaunchRequest {
            action_id: 102,
            mechanism: MacOsRootMechanism::ValidatedChrootHelper,
            host_apfs_clone_stage_dir: "/private/var/rabs/stage/act-102".into(),
            canonical_mounts: MacOsRootLaunchRequest::default_canonical_mounts(),
            contains_symlink_to_caller_space: false,
            request_bytes: 2048,
        };

        let view_a = validate_macos_root_helper_request(&req_a).expect("valid chroot helper req A");
        let view_b = validate_macos_root_helper_request(&req_b).expect("valid chroot helper req B");

        // D013 ACCEPTANCE: two concurrent macOS actions observe identical canonical roots,
        // even though their underlying APFS clone directories are distinct on the host.
        assert_ne!(
            view_a.host_backing_stage_dir, view_b.host_backing_stage_dir,
            "host APFS clone backing directories must be isolated per concurrent action"
        );
        assert_eq!(
            view_a.visible_root, "/rabs/execroot",
            "action A must observe canonical root /rabs/execroot"
        );
        assert_eq!(
            view_a.visible_root, view_b.visible_root,
            "concurrent actions must observe the exact same canonical process root"
        );
        assert_eq!(
            view_a.visible_mounts, view_b.visible_mounts,
            "concurrent actions must observe identical canonical mount paths"
        );
        assert!(view_a.canonical_path_identity_proven);
        assert_eq!(
            view_a.authority_profile,
            IsolationProfile::StrictHermeticVm,
            "validated chroot helper with canonical root qualifies for StrictHermeticVm"
        );

        // Virtualization.framework VM also proves identical canonical roots.
        let mut req_vm = req_a.clone();
        req_vm.mechanism = MacOsRootMechanism::VirtualizationFrameworkVm;
        let view_vm = validate_macos_root_helper_request(&req_vm).expect("valid VM req");
        assert_eq!(view_vm.visible_root, view_a.visible_root);
        assert!(view_vm.canonical_path_identity_proven);
        assert_eq!(
            view_vm.authority_profile,
            IsolationProfile::StrictHermeticVm
        );

        // Risk R47: APFS clones ALONE do NOT give concurrent processes the same visible path!
        let mut req_clone_only = req_a.clone();
        req_clone_only.mechanism = MacOsRootMechanism::ApfsCloneOnly;
        let mut req_clone_only_b = req_b.clone();
        req_clone_only_b.mechanism = MacOsRootMechanism::ApfsCloneOnly;
        let clone_view_a = validate_macos_root_helper_request(&req_clone_only).unwrap();
        let clone_view_b = validate_macos_root_helper_request(&req_clone_only_b).unwrap();
        assert_ne!(
            clone_view_a.visible_root, clone_view_b.visible_root,
            "APFS clones alone expose distinct host staging paths to concurrent actions (R47)"
        );
        assert!(!clone_view_a.canonical_path_identity_proven);
        assert_eq!(
            clone_view_a.authority_profile,
            IsolationProfile::HostSandboxAudit,
            "APFS clone without chroot/VM is downgraded to HostSandboxAudit"
        );

        // Protocol bounds enforcement: traversal, symlink escape, or oversized payload refuses.
        let mut traversal = req_a.clone();
        traversal.host_apfs_clone_stage_dir = "/private/var/rabs/stage/../escape".into();
        assert_eq!(
            validate_macos_root_helper_request(&traversal),
            Err(MacOsRootHelperRefusal::PathTraversalOrOutsideStageRoot)
        );
        let mut symlink_escape = req_a.clone();
        symlink_escape.contains_symlink_to_caller_space = true;
        assert_eq!(
            validate_macos_root_helper_request(&symlink_escape),
            Err(MacOsRootHelperRefusal::SymlinkEscapeIntoCallerSpace)
        );
    }

    #[test]
    fn d021_and_e017_macos_observation_soundness_and_differential_authority() {
        // 1. Strict VM/chroot + EndpointSecurity (0 dropped events) -> StrictHermeticVm:
        //    DependencyServing = EligibleAfterGates,
        //    WorkspaceServing = EligibleAfterGates,
        //    CrossMachinePublication = EligibleWithinPlatformClass.
        let strict_es = evaluate_macos_observation_soundness(
            MacOsRootMechanism::ValidatedChrootHelper,
            MacOsObservationMechanism::EndpointSecurityValidated { dropped_events: 0 },
            true,
        );
        assert_eq!(strict_es.profile, IsolationProfile::StrictHermeticVm);
        assert!(!strict_es.speculation_watcher_only);
        assert_eq!(
            strict_es.dependency_cell.authority,
            Authority::EligibleAfterGates
        );
        assert_eq!(
            strict_es.workspace_cell.authority,
            Authority::EligibleAfterGates
        );
        assert_eq!(
            strict_es.cross_machine_cell.authority,
            Authority::EligibleWithinPlatformClass
        );

        // 2. EndpointSecurity with dropped_events > 0 loses read-closure soundness -> HostSandboxAudit!
        let dropped_es = evaluate_macos_observation_soundness(
            MacOsRootMechanism::ValidatedChrootHelper,
            MacOsObservationMechanism::EndpointSecurityValidated { dropped_events: 3 },
            true,
        );
        assert_eq!(dropped_es.profile, IsolationProfile::HostSandboxAudit);
        assert_eq!(
            dropped_es.dependency_cell.authority,
            Authority::SelectedImmutableClassesOnly
        );
        assert_eq!(dropped_es.workspace_cell.authority, Authority::ShadowOnly);
        assert_eq!(
            dropped_es.cross_machine_cell.authority,
            Authority::ShadowOnly
        );

        // 3. E017 FSEvents is ONLY an edit/speculation watcher — never an input-observation proof!
        let fsevents = evaluate_macos_observation_soundness(
            MacOsRootMechanism::ValidatedChrootHelper,
            MacOsObservationMechanism::FsEventsWatcherOnly,
            true,
        );
        assert_eq!(fsevents.profile, IsolationProfile::VolatileLocal);
        assert!(fsevents.speculation_watcher_only);
        assert_eq!(
            fsevents.non_claim_code,
            NO_CLAIM_MACOS_FSEVENTS_READ_OBSERVATION
        );
        assert!(!fsevents.dependency_cell.authority.may_serve());
        assert!(!fsevents.workspace_cell.authority.may_serve());
        assert!(!fsevents.cross_machine_cell.authority.may_serve());

        // 4. D021 Host-audit mode (ApfsCloneOnly + HostBestEffortTrace):
        //    SelectedImmutableClassesOnly for deps; ShadowOnly for workspace & cross-machine.
        let host_audit = evaluate_macos_observation_soundness(
            MacOsRootMechanism::ApfsCloneOnly,
            MacOsObservationMechanism::HostBestEffortTrace,
            true,
        );
        assert_eq!(host_audit.profile, IsolationProfile::HostSandboxAudit);
        assert_eq!(
            host_audit.dependency_cell.authority,
            Authority::SelectedImmutableClassesOnly
        );
        assert_eq!(host_audit.workspace_cell.authority, Authority::ShadowOnly);
        assert_eq!(
            host_audit.cross_machine_cell.authority,
            Authority::ShadowOnly
        );

        // 5. D021 False-parity differential gate: attempting to claim WorkspaceServing or
        //    CrossMachinePublication from host-audit or FSEvents or APFS-clone-only fails closed!
        assert_eq!(
            verify_macos_authority_claim(
                &host_audit,
                ServingScope::WorkspaceServing,
                Authority::EligibleAfterGates,
            ),
            Err(
                MacOsFalseParityRefusal::HostAuditCannotServeWorkspaceOrCrossMachine {
                    requested_scope: ServingScope::WorkspaceServing,
                    actual_authority: Authority::ShadowOnly,
                }
            )
        );
        assert_eq!(
            verify_macos_authority_claim(
                &host_audit,
                ServingScope::CrossMachinePublication,
                Authority::EligibleWithinPlatformClass,
            ),
            Err(
                MacOsFalseParityRefusal::HostAuditCannotServeWorkspaceOrCrossMachine {
                    requested_scope: ServingScope::CrossMachinePublication,
                    actual_authority: Authority::ShadowOnly,
                }
            )
        );
        assert_eq!(
            verify_macos_authority_claim(
                &fsevents,
                ServingScope::DependencyServing,
                Authority::SelectedImmutableClassesOnly,
            ),
            Err(MacOsFalseParityRefusal::FsEventsIsSpeculationWatcherOnly {
                non_claim: NO_CLAIM_MACOS_FSEVENTS_READ_OBSERVATION,
            })
        );
        assert_eq!(
            verify_macos_authority_claim(
                &strict_es,
                ServingScope::WorkspaceServing,
                Authority::EligibleAfterGates,
            ),
            Ok(())
        );
    }
}

/// Explicit non-claim code for macOS `FSEvents`: observes directory/file mutations only,
/// never read closures (`open(O_RDONLY)`), failed lookups, or exec resolutions (bead E017).
pub const NO_CLAIM_MACOS_FSEVENTS_READ_OBSERVATION: &str =
    "NO_CLAIM_MACOS_FSEVENTS_READ_OBSERVATION";

/// Explicit non-claim code for macOS host-audit mode: best-effort tracing without a
/// canonical root or complete read closure cannot publish cross-worktree workspace
/// results or cross-machine artifacts (beads D021/E017).
pub const NO_CLAIM_MACOS_HOST_AUDIT_WORKSPACE_PARITY: &str =
    "NO_CLAIM_MACOS_HOST_AUDIT_WORKSPACE_PARITY";

/// Maximum request payload size accepted by `rabs-macos-root-helper` (bead D013).
pub const MAX_MACOS_ROOT_HELPER_REQUEST_BYTES: usize = 16 * 1024;

/// Maximum mount bindings accepted by `rabs-macos-root-helper` (bead D013).
pub const MAX_MACOS_ROOT_HELPER_MOUNTS: usize = 8;

/// Mechanism used on macOS to present an action's filesystem root (bead D013; risk R47).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MacOsRootMechanism {
    /// APFS `clonefile(2)` staging directory only, without chroot or VM root remapping.
    /// Gives fast copy-on-write data copies, but concurrent actions observe distinct
    /// host paths (risk R47) — NEVER sufficient for `StrictHermeticVm`.
    ApfsCloneOnly,
    /// Privileged `rabs-macos-root-helper` chrooting into an APFS-cloned staging root
    /// so every concurrent action observes `/rabs/execroot/...`.
    ValidatedChrootHelper,
    /// Lightweight `Virtualization.framework` VM mounting the action's root at
    /// `/rabs/execroot/...`.
    VirtualizationFrameworkVm,
}

/// Mechanism used on macOS to observe filesystem reads, execs, and network activity (bead E017).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MacOsObservationMechanism {
    /// Privileged Endpoint Security client (`ES_EVENT_TYPE_NOTIFY_OPEN`, `EXEC`, `LOOKUP`,
    /// `STAT`, `READLINK`) with ring-buffer drop accounting.
    EndpointSecurityValidated {
        /// Number of events dropped by the ES ring buffer during the attempt (`0` required for strict authority).
        dropped_events: u64,
    },
    /// Hypervisor/virtiofs-mediated read/exec/network observation inside a `Virtualization.framework` VM.
    VmMediatedObservation,
    /// Host best-effort tracing (`dtrace`/`ktrace`/fixed env & process ownership) without complete read closure.
    HostBestEffortTrace,
    /// Unprivileged `FSEvents` stream. Observes file/directory modifications ONLY, never reads!
    /// Permitted exclusively as an edit/speculation watcher (E017).
    FsEventsWatcherOnly,
}

/// Bounded request sent to `rabs-macos-root-helper` (bead D013).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MacOsRootLaunchRequest {
    /// Action attempt identifier.
    pub action_id: u64,
    /// Root presentation mechanism.
    pub mechanism: MacOsRootMechanism,
    /// Daemon-owned APFS clone staging directory on the host (`/private/var/rabs/stage/...`).
    pub host_apfs_clone_stage_dir: String,
    /// Canonical visible mount subdirectories under `/rabs/execroot`.
    pub canonical_mounts: Vec<String>,
    /// Whether `O_NOFOLLOW` inspection detected any symlink resolving into caller-controlled space.
    pub contains_symlink_to_caller_space: bool,
    /// Serialized request byte length.
    pub request_bytes: usize,
}

impl MacOsRootLaunchRequest {
    /// The six standard RABS canonical execroot mount subdirectories.
    #[must_use]
    pub fn default_canonical_mounts() -> Vec<String> {
        vec![
            "/rabs/execroot/ws".into(),
            "/rabs/execroot/target".into(),
            "/rabs/execroot/cargo-home".into(),
            "/rabs/execroot/toolchain".into(),
            "/rabs/execroot/tmp".into(),
            "/rabs/execroot/out".into(),
        ]
    }
}

/// Validated canonical process root view observed by a macOS action (bead D013).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MacOsCanonicalActionView {
    /// Action attempt identifier.
    pub action_id: u64,
    /// Underlying isolated host APFS clone directory.
    pub host_backing_stage_dir: String,
    /// Process-visible root path inside the action (`"/rabs/execroot"` when chrooted/VM-backed).
    pub visible_root: String,
    /// Process-visible mount paths inside the action.
    pub visible_mounts: Vec<String>,
    /// Whether two concurrent actions under this mechanism observe byte-identical canonical roots.
    pub canonical_path_identity_proven: bool,
    /// Highest isolation profile this root mechanism can support.
    pub authority_profile: IsolationProfile,
}

/// Refusal from `rabs-macos-root-helper` protocol validation (bead D013).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MacOsRootHelperRefusal {
    /// Request exceeds `MAX_MACOS_ROOT_HELPER_REQUEST_BYTES` or `MAX_MACOS_ROOT_HELPER_MOUNTS`.
    RequestBoundsExceeded,
    /// Stage path is not under `/private/var/rabs/stage/` or contains `..` traversal.
    PathTraversalOrOutsideStageRoot,
    /// A mount target is outside `/rabs/execroot/` or contains `..` traversal.
    InvalidCanonicalMountTarget,
    /// `O_NOFOLLOW` check found a symlink escaping into caller-controlled space.
    SymlinkEscapeIntoCallerSpace,
}

/// Validate a `MacOsRootLaunchRequest` against the D013 unsafe-boundary ledger contract
/// and compute the resulting `MacOsCanonicalActionView`.
///
/// # Errors
/// Returns [`MacOsRootHelperRefusal`] if protocol bounds or path-safety rules are violated.
pub fn validate_macos_root_helper_request(
    req: &MacOsRootLaunchRequest,
) -> Result<MacOsCanonicalActionView, MacOsRootHelperRefusal> {
    if req.request_bytes > MAX_MACOS_ROOT_HELPER_REQUEST_BYTES
        || req.canonical_mounts.is_empty()
        || req.canonical_mounts.len() > MAX_MACOS_ROOT_HELPER_MOUNTS
    {
        return Err(MacOsRootHelperRefusal::RequestBoundsExceeded);
    }
    if req.contains_symlink_to_caller_space {
        return Err(MacOsRootHelperRefusal::SymlinkEscapeIntoCallerSpace);
    }
    if !req
        .host_apfs_clone_stage_dir
        .starts_with("/private/var/rabs/stage/")
        || req.host_apfs_clone_stage_dir.split('/').any(|c| c == "..")
    {
        return Err(MacOsRootHelperRefusal::PathTraversalOrOutsideStageRoot);
    }
    for m in &req.canonical_mounts {
        if !m.starts_with("/rabs/execroot/") || m.split('/').any(|c| c == "..") {
            return Err(MacOsRootHelperRefusal::InvalidCanonicalMountTarget);
        }
    }

    match req.mechanism {
        MacOsRootMechanism::ValidatedChrootHelper
        | MacOsRootMechanism::VirtualizationFrameworkVm => Ok(MacOsCanonicalActionView {
            action_id: req.action_id,
            host_backing_stage_dir: req.host_apfs_clone_stage_dir.clone(),
            visible_root: "/rabs/execroot".into(),
            visible_mounts: req.canonical_mounts.clone(),
            canonical_path_identity_proven: true,
            authority_profile: IsolationProfile::StrictHermeticVm,
        }),
        MacOsRootMechanism::ApfsCloneOnly => {
            let visible_mounts = req
                .canonical_mounts
                .iter()
                .map(|m| {
                    let suffix = m.strip_prefix("/rabs/execroot").unwrap_or(m);
                    format!("{}{}", req.host_apfs_clone_stage_dir, suffix)
                })
                .collect();
            Ok(MacOsCanonicalActionView {
                action_id: req.action_id,
                host_backing_stage_dir: req.host_apfs_clone_stage_dir.clone(),
                visible_root: req.host_apfs_clone_stage_dir.clone(),
                visible_mounts,
                canonical_path_identity_proven: false,
                authority_profile: IsolationProfile::HostSandboxAudit,
            })
        }
    }
}

/// Complete macOS observation + root soundness verdict across all serving scopes (beads D021/E017).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MacOsAuthorityEvaluation {
    /// Effective isolation profile earned by the `(root, observation)` combination.
    pub profile: IsolationProfile,
    /// Whether the mechanism is restricted to edit/speculation watching only (`FSEvents`).
    pub speculation_watcher_only: bool,
    /// Explicit non-claim code governing this evaluation.
    pub non_claim_code: &'static str,
    /// Authority cell for `DependencyServing`.
    pub dependency_cell: AuthorityCell,
    /// Authority cell for `WorkspaceServing`.
    pub workspace_cell: AuthorityCell,
    /// Authority cell for `CrossMachinePublication`.
    pub cross_machine_cell: AuthorityCell,
}

/// Evaluate the effective `IsolationProfile` and per-scope `AuthorityCell`s for a macOS
/// root + observation combination (beads D013, D021, E017).
#[must_use]
pub const fn evaluate_macos_observation_soundness(
    root: MacOsRootMechanism,
    observation: MacOsObservationMechanism,
    helper_ledger_validated: bool,
) -> MacOsAuthorityEvaluation {
    // E017: FSEvents is strictly an edit/speculation watcher — never an input-observation proof.
    if matches!(observation, MacOsObservationMechanism::FsEventsWatcherOnly) {
        let profile = IsolationProfile::VolatileLocal;
        return MacOsAuthorityEvaluation {
            profile,
            speculation_watcher_only: true,
            non_claim_code: NO_CLAIM_MACOS_FSEVENTS_READ_OBSERVATION,
            dependency_cell: authority(profile, ServingScope::DependencyServing),
            workspace_cell: authority(profile, ServingScope::WorkspaceServing),
            cross_machine_cell: authority(profile, ServingScope::CrossMachinePublication),
        };
    }

    let canonical_root_valid = helper_ledger_validated
        && matches!(
            root,
            MacOsRootMechanism::ValidatedChrootHelper
                | MacOsRootMechanism::VirtualizationFrameworkVm
        );

    let strict_observation_valid = matches!(
        observation,
        MacOsObservationMechanism::EndpointSecurityValidated { dropped_events: 0 }
            | MacOsObservationMechanism::VmMediatedObservation
    );

    let profile = if canonical_root_valid && strict_observation_valid {
        IsolationProfile::StrictHermeticVm
    } else {
        IsolationProfile::HostSandboxAudit
    };

    MacOsAuthorityEvaluation {
        profile,
        speculation_watcher_only: false,
        non_claim_code: NO_CLAIM_MACOS_HOST_AUDIT_WORKSPACE_PARITY,
        dependency_cell: authority(profile, ServingScope::DependencyServing),
        workspace_cell: authority(profile, ServingScope::WorkspaceServing),
        cross_machine_cell: authority(profile, ServingScope::CrossMachinePublication),
    }
}

/// Refusal when a caller attempts false parity on macOS (bead D021).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MacOsFalseParityRefusal {
    /// `FSEvents` was used to claim build input-observation authority instead of speculation watching.
    FsEventsIsSpeculationWatcherOnly {
        /// Explicit non-claim code (`NO_CLAIM_MACOS_FSEVENTS_READ_OBSERVATION`).
        non_claim: &'static str,
    },
    /// Host-audit mode (or APFS clone without chroot/VM) attempted authoritative workspace or cross-machine serving.
    HostAuditCannotServeWorkspaceOrCrossMachine {
        /// Scope the caller attempted to serve.
        requested_scope: ServingScope,
        /// Actual authority granted by the A015 matrix (`ShadowOnly`).
        actual_authority: Authority,
    },
    /// Claimed authority does not match the A015 matrix cell for the evaluated profile.
    AuthorityMismatch {
        /// Claimed authority.
        claimed: Authority,
        /// Actual authority from the A015 matrix.
        actual: Authority,
    },
}

/// Verify that a claimed `Authority` for `scope` does not exceed the evaluated macOS
/// soundness boundary (bead D021 differential authority gate).
///
/// # Errors
/// Returns [`MacOsFalseParityRefusal`] on any false-parity attempt.
pub fn verify_macos_authority_claim(
    eval: &MacOsAuthorityEvaluation,
    scope: ServingScope,
    claimed: Authority,
) -> Result<(), MacOsFalseParityRefusal> {
    if eval.speculation_watcher_only {
        return Err(MacOsFalseParityRefusal::FsEventsIsSpeculationWatcherOnly {
            non_claim: eval.non_claim_code,
        });
    }
    let actual = authority(eval.profile, scope).authority;
    if eval.profile == IsolationProfile::HostSandboxAudit
        && matches!(
            scope,
            ServingScope::WorkspaceServing | ServingScope::CrossMachinePublication
        )
        && claimed.may_serve()
    {
        return Err(
            MacOsFalseParityRefusal::HostAuditCannotServeWorkspaceOrCrossMachine {
                requested_scope: scope,
                actual_authority: actual,
            },
        );
    }
    if claimed != actual {
        return Err(MacOsFalseParityRefusal::AuthorityMismatch { claimed, actual });
    }
    Ok(())
}
