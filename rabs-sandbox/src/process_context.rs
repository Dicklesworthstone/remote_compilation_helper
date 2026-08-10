//! Canonical process-context capture (bead D026; risk R78; plan §28).
//!
//! A compiler's output is a function of more than argv and files:
//! umask decides created-file modes, rlimits can change codegen
//! behavior under pressure, CPU count leaks into build-script feature
//! probes, argv0/cwd leak into diagnostics and `file!()`-adjacent
//! surfaces, and an inherited descriptor is a covert input channel.
//! R78's rule: every such channel is either **pinned to a canonical
//! value** by the launch (umask, cwd, argv0) or **captured as an
//! explicit semantic input** that participates in action identity
//! (CPU view, rlimits) — never silently inherited.
//!
//! Inherited FDs are default-closed before spawn. The one approved
//! exception class — a local jobserver pipe — is capability-scoped and
//! excluded from semantic identity ONLY when proven output-neutral;
//! an unproven jobserver stays inside the identity so two runs with
//! different unproven descriptors can never alias.

use std::collections::BTreeMap;

/// The CPU view a launch presents — an explicit semantic input.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CpuView {
    /// Pinned logical CPU count presented to the action.
    Pinned(u32),
    /// Host count captured and recorded as a semantic input.
    CapturedHost(u32),
}

/// One rlimit the launch pins (soft value).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RlimitSpec {
    /// Resource name (`NOFILE`, `NPROC`, `STACK`, …).
    pub resource: String,
    /// Pinned soft limit.
    pub soft: u64,
}

/// The canonical process context for one action launch.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CanonicalProcessContext {
    /// Pinned umask (canonical `0o022`).
    pub umask: u32,
    /// Pinned working directory (the canonical workspace).
    pub cwd: String,
    /// Pinned argv0 (the canonical binary path, never a host alias).
    pub argv0: String,
    /// Pinned rlimits, sorted by resource.
    pub rlimits: Vec<RlimitSpec>,
    /// The CPU view (pinned or captured-as-input).
    pub cpu_view: CpuView,
}

impl CanonicalProcessContext {
    /// The canonical default: umask 022, cwd at the workspace, argv0
    /// canonical, a pinned NOFILE floor, and an explicitly captured
    /// host CPU count.
    #[must_use]
    pub fn canonical_default(argv0: &str, host_cpus: u32) -> Self {
        Self {
            umask: 0o022,
            cwd: crate::layout::WORKSPACE.to_string(),
            argv0: argv0.to_string(),
            rlimits: vec![RlimitSpec {
                resource: "NOFILE".to_string(),
                soft: 4096,
            }],
            cpu_view: CpuView::CapturedHost(host_cpus),
        }
    }
}

/// Classification of one inherited descriptor at spawn time.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FdClass {
    /// stdin/stdout/stderr — approved, semantics owned by the harness.
    Stdio,
    /// A local jobserver pipe, capability-scoped.
    Jobserver {
        /// Whether output-neutrality has been PROVEN for this lane.
        proven_output_neutral: bool,
    },
    /// Anything else the process happened to inherit.
    Unapproved,
}

/// What the spawner does with one inherited descriptor.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FdDisposition {
    /// Kept open (approved).
    Keep,
    /// Closed before spawn (default for everything unapproved).
    CloseBeforeSpawn,
}

/// Decide every inherited descriptor's fate: unapproved ⇒ closed.
#[must_use]
pub fn fd_plan(inherited: &[(i32, FdClass)]) -> Vec<(i32, FdDisposition)> {
    inherited
        .iter()
        .map(|(fd, class)| {
            let disposition = match class {
                FdClass::Stdio | FdClass::Jobserver { .. } => FdDisposition::Keep,
                FdClass::Unapproved => FdDisposition::CloseBeforeSpawn,
            };
            (*fd, disposition)
        })
        .collect()
}

/// The semantic-identity inputs this context contributes to the action
/// key. Everything pinned or captured participates; an approved
/// jobserver is EXCLUDED only when proven output-neutral — an unproven
/// one is recorded so it can never silently alias two runs.
#[must_use]
pub fn semantic_identity_inputs(
    context: &CanonicalProcessContext,
    descriptors: &[(i32, FdClass)],
) -> BTreeMap<String, String> {
    let mut inputs = BTreeMap::new();
    inputs.insert("umask".to_string(), format!("{:03o}", context.umask));
    inputs.insert("cwd".to_string(), context.cwd.clone());
    inputs.insert("argv0".to_string(), context.argv0.clone());
    for limit in &context.rlimits {
        inputs.insert(format!("rlimit.{}", limit.resource), limit.soft.to_string());
    }
    match context.cpu_view {
        CpuView::Pinned(count) => {
            inputs.insert("cpu.pinned".to_string(), count.to_string());
        }
        CpuView::CapturedHost(count) => {
            inputs.insert("cpu.captured".to_string(), count.to_string());
        }
    }
    for (fd, class) in descriptors {
        match class {
            FdClass::Jobserver {
                proven_output_neutral: true,
            }
            | FdClass::Stdio => {} // excluded: proven neutral / harness-owned
            FdClass::Jobserver {
                proven_output_neutral: false,
            } => {
                inputs.insert(format!("fd.{fd}"), "jobserver-unproven".to_string());
            }
            FdClass::Unapproved => {
                // Closed before spawn — but its PRESENCE is recorded so
                // a spawn plan that failed to close cannot alias.
                inputs.insert(format!("fd.{fd}"), "unapproved-closed".to_string());
            }
        }
    }
    inputs
}

/// Capture the REAL host process context on Linux (`/proc` surfaces).
/// Umask comes from `/proc/self/status` (readable without mutation);
/// unavailable fields are typed `None`, never guessed.
#[cfg(target_os = "linux")]
#[must_use]
pub fn capture_host_umask() -> Option<u32> {
    let status = std::fs::read_to_string("/proc/self/status").ok()?;
    status
        .lines()
        .find_map(|line| line.strip_prefix("Umask:"))
        .and_then(|value| u32::from_str_radix(value.trim(), 8).ok())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn context() -> CanonicalProcessContext {
        CanonicalProcessContext::canonical_default("/__rabs/toolchain/bin/rustc", 8)
    }

    #[test]
    fn canonical_default_pins_the_canonical_world() {
        let ctx = context();
        assert_eq!(ctx.umask, 0o022);
        assert_eq!(ctx.cwd, "/__rabs/workspace");
        assert_eq!(ctx.argv0, "/__rabs/toolchain/bin/rustc");
        assert_eq!(ctx.cpu_view, CpuView::CapturedHost(8));
    }

    #[test]
    fn t024_differential_fixtures_split_identity_on_every_context_channel() {
        // THE T024 acceptance shape: same base context, one channel
        // perturbed at a time — each perturbation MUST change the
        // semantic identity.
        let base = semantic_identity_inputs(&context(), &[]);
        let mut umask_differs = context();
        umask_differs.umask = 0o077;
        let mut cpu_differs = context();
        cpu_differs.cpu_view = CpuView::CapturedHost(64);
        let mut rlimit_differs = context();
        rlimit_differs.rlimits[0].soft = 1024;
        let mut cwd_differs = context();
        cwd_differs.cwd = "/__rabs/repos/dep-a".to_string();
        let mut argv0_differs = context();
        argv0_differs.argv0 = "/usr/bin/rustc".to_string();
        for (label, perturbed) in [
            ("umask", umask_differs),
            ("cpu", cpu_differs),
            ("rlimit", rlimit_differs),
            ("cwd", cwd_differs),
            ("argv0", argv0_differs),
        ] {
            assert_ne!(
                base,
                semantic_identity_inputs(&perturbed, &[]),
                "{label} perturbation must change semantic identity"
            );
        }
        // And pinned-vs-captured CPU is itself a semantic distinction.
        let mut pinned = context();
        pinned.cpu_view = CpuView::Pinned(8);
        assert_ne!(base, semantic_identity_inputs(&pinned, &[]));
    }

    #[test]
    fn unapproved_fds_close_before_spawn_and_are_recorded() {
        let inherited = vec![
            (0, FdClass::Stdio),
            (
                7,
                FdClass::Jobserver {
                    proven_output_neutral: true,
                },
            ),
            (9, FdClass::Unapproved),
        ];
        let plan = fd_plan(&inherited);
        assert_eq!(plan[0], (0, FdDisposition::Keep));
        assert_eq!(plan[1], (7, FdDisposition::Keep));
        assert_eq!(plan[2], (9, FdDisposition::CloseBeforeSpawn));
        // The unapproved fd's presence is still recorded in identity.
        let identity = semantic_identity_inputs(&context(), &inherited);
        assert_eq!(identity["fd.9"], "unapproved-closed");
    }

    #[test]
    fn jobserver_exclusion_requires_proof_of_output_neutrality() {
        let proven = vec![(
            7,
            FdClass::Jobserver {
                proven_output_neutral: true,
            },
        )];
        let unproven = vec![(
            7,
            FdClass::Jobserver {
                proven_output_neutral: false,
            },
        )];
        let base = semantic_identity_inputs(&context(), &[]);
        // Proven-neutral jobserver: EXCLUDED — identity unchanged.
        assert_eq!(base, semantic_identity_inputs(&context(), &proven));
        // Unproven: INCLUDED — identity differs.
        let with_unproven = semantic_identity_inputs(&context(), &unproven);
        assert_ne!(base, with_unproven);
        assert_eq!(with_unproven["fd.7"], "jobserver-unproven");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn real_umask_capture_reads_proc_without_mutation() {
        let umask = capture_host_umask().expect("/proc/self/status has Umask on Linux");
        assert!(umask <= 0o777);
    }
}
