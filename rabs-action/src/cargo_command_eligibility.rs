//! Cargo whole-command eligibility matrix enforcement (bead K016;
//! plan Epic K; the enforcement twin of K015's provenance contract).
//!
//! RABS accelerates CARGO COMMANDS, but not all of them, and never by
//! guessing. This module owns the explicit matrix: given a cargo
//! invocation in its POST-EXPANSION form — aliases already resolved
//! through the effective config (K015), wrapper argv NOT re-guessed —
//! it decides which acceleration plane, if any, the command admits.
//!
//! The families and their law (bead text, made total):
//!
//! - **Probes** (`--version`, `-V`, `--help`, `-h`, `rustc -vV`-style
//!   via the cargo driver): local, result tiny-cached;
//! - **Compile phases** (`build`, `check`, `clippy`, `doc`):
//!   unit-decomposition accelerated with a bounded whole-command
//!   fallback;
//! - **Test family** (`test`, `nextest`): admitted test-actions
//!   preferred; bounded whole-command allowed under admission rules —
//!   execution-result SERVING itself is earned elsewhere (O011), this
//!   matrix only admits the shape;
//! - **`run`**: compile-only acceleration — units accelerate, the
//!   final binary execution is always fresh and local;
//! - **`bench`**: timing is NEVER cached or served — compile units
//!   may accelerate, measured execution may not;
//! - **Source-mutating / publishing** (`clean`, `fix`, `install`,
//!   `uninstall`, `publish`, `package`, `vendor`, `add`, `remove`,
//!   `yank`, `login`, `logout`): local or side-effecting
//!   whole-command only — no cache, no serving, no remote;
//! - **Watch/interactive/PTY**: local only, never intercepted;
//! - **Unrecognized subcommands**: fail-closed to local-only. An
//!   unknown name is NEVER assumed pure: an alias named `tidy`
//!   expanding to `clean` must classify by its EXPANSION, and the
//!   structural way this module guarantees that is by accepting ONLY
//!   expanded argv as input — there is no API that takes a raw alias
//!   token;
//! - **Unstable modes** (`-Z build-std`, artifact dependencies,
//!   custom runners, other `-Z` flags): each concern is checked
//!   against the compatibility matrix ([`COMPATIBILITY_MATRIX`]);
//!   unadmitted concerns produce an EXPLAINED BYPASS — the wrapper
//!   steps aside and says why — never a silent refusal.
//!
//! Pure classification over the expanded invocation shape: no
//! filesystem, network, process, or clock access, per the crate's
//! dependency rules.

use rabs_protocol::descriptor::ActionClass;

/// The coarse command family an expanded invocation belongs to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CargoCommandFamily {
    /// Version/help probes.
    Probe,
    /// `build` / `check` / `clippy` / `doc`.
    CompilePhase,
    /// `test` / `nextest`.
    Test,
    /// `run`.
    RunCommand,
    /// `bench`.
    Bench,
    /// Source-mutating or publishing commands.
    Mutating,
    /// Watch/interactive commands (or any PTY request).
    Interactive,
    /// Anything unrecognized — fail-closed.
    Unrecognized,
}

/// The acceleration plane a family's base matrix row grants.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BaseEligibility {
    /// Local execution; the tiny result may be cached.
    TinyCachedProbe,
    /// Units accelerate; a bounded whole-command run is the fallback
    /// shape when decomposition cannot admit.
    UnitDecompositionAccelerated,
    /// Test-actions are the preferred shape; bounded whole-command is
    /// allowed. Serving is governed by O011 gates, not this matrix.
    AdmittedTestActionsPreferred,
    /// Compile units accelerate; final execution is always fresh.
    CompileOnlyAcceleration,
    /// Compile units may accelerate; measured timing NEVER caches.
    TimingNeverCached,
    /// Admissible only as a side-effecting whole-command: no remote,
    /// no cache, no serving.
    SideEffectingWholeCommandOnly,
    /// Never intercepted.
    LocalOnly,
}

impl BaseEligibility {
    /// Whether cached/served RESULTS may exist for this base shape at
    /// all. Timing, side effects, and interactive work cannot.
    #[must_use]
    pub const fn may_serve_results(self) -> bool {
        matches!(
            self,
            Self::TinyCachedProbe
                | Self::UnitDecompositionAccelerated
                | Self::AdmittedTestActionsPreferred
                | Self::CompileOnlyAcceleration
        )
    }
}

/// A compatibility concern detected in the invocation shape.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum CompatibilityConcern {
    /// `-Z build-std`: std codegen depends on host sysroot layout.
    BuildStd,
    /// A custom target runner is configured (from the config contract
    /// layer): runner behavior is outside the hermetic contract.
    CustomRunner,
    /// Artifact dependencies (`-Zartifact-dependencies`).
    ArtifactDependencies,
    /// Any other `-Z` flag, named exactly.
    UnstableFlag(String),
}

/// One row of the compatibility matrix: is interception ADMITTED for
/// this concern class?
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CompatibilityRow {
    /// Stable tag this row governs (matched against concern names).
    pub concern_tag: &'static str,
    /// Whether the matrix admits interception despite the concern.
    pub admitted: bool,
    /// Human-readable rationale surfaced verbatim in bypass reasons.
    pub notes: &'static str,
}

/// The compatibility matrix. Modeled on
/// [`rabs_protocol::nextest_runner::NEXTEST_VERSION_MATRIX`]: rows are
/// appended as shadow proofs land; anything UNLISTED refuses with an
/// explanation rather than guessing.
pub const COMPATIBILITY_MATRIX: &[CompatibilityRow] = &[
    CompatibilityRow {
        concern_tag: "build-std",
        admitted: false,
        notes: "build-std codegen couples to the worker sysroot layout; \
                interception would serve results the local toolchain cannot vouch for",
    },
    CompatibilityRow {
        concern_tag: "custom-runner",
        admitted: false,
        notes: "custom target runners execute outside the hermetic contract; \
                affected executions stay local",
    },
    CompatibilityRow {
        concern_tag: "artifact-dependencies",
        admitted: false,
        notes: "artifact-dependency resolution semantics are nightly-unstable; \
                admission awaits a shadow semantics proof",
    },
    CompatibilityRow {
        concern_tag: "unstable-flag:check-cfg",
        admitted: true,
        notes: "check-cfg affects diagnostics only; unit identity unaffected",
    },
];

/// The expanded invocation shape this module classifies. There is NO
/// field carrying a raw alias token: input is post-expansion by
/// construction, so "classify what the user typed" is unrepresentable.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExpandedCargoInvocation {
    /// Post-expansion arguments, argv[0] being the driver name
    /// (`cargo`) or absent-equivalent (empty vec = bare flags).
    pub argv: Vec<String>,
    /// Whether a PTY was requested for this command.
    pub pty_requested: bool,
    /// Whether the config layer resolved a custom target runner into
    /// effect for this invocation.
    pub custom_runner_declared: bool,
}

/// Why the wrapper stepped aside (an EXPLAINED bypass).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EnforcementOutcome {
    /// Interception proceeds under the base eligibility.
    Admitted,
    /// The wrapper steps aside; the reason names the failing concern
    /// and the matrix row's notes verbatim.
    ExplainedBypass { reason: String },
}

/// The enforced decision for one invocation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EligibilityDecision {
    /// Family classification.
    pub family: CargoCommandFamily,
    /// Base matrix grant.
    pub base: BaseEligibility,
    /// Every compatibility concern detected (all, never first-only).
    pub concerns: Vec<CompatibilityConcern>,
    /// Admitted, or the explained bypass.
    pub outcome: EnforcementOutcome,
}

impl EligibilityDecision {
    /// The action-class vocabulary slot this decision maps to, if any.
    /// Probes map to [`ActionClass::ToolchainProbe`]; every accelerated
    /// or bounded whole-command shape maps to
    /// [`ActionClass::CargoWholeCommandBounded`]; non-accelerated
    /// shapes map to nothing (they are not actions).
    #[must_use]
    pub fn action_class_hint(&self) -> Option<ActionClass> {
        if self.outcome != EnforcementOutcome::Admitted {
            return None;
        }
        match self.base {
            BaseEligibility::TinyCachedProbe => Some(ActionClass::ToolchainProbe),
            BaseEligibility::UnitDecompositionAccelerated
            | BaseEligibility::AdmittedTestActionsPreferred
            | BaseEligibility::CompileOnlyAcceleration
            | BaseEligibility::TimingNeverCached => Some(ActionClass::CargoWholeCommandBounded),
            BaseEligibility::SideEffectingWholeCommandOnly | BaseEligibility::LocalOnly => None,
        }
    }
}

/// Enforce the eligibility matrix for one expanded invocation.
#[must_use]
pub fn enforce(invocation: &ExpandedCargoInvocation) -> EligibilityDecision {
    let concerns = detect_concerns(invocation);
    let (family, base) = classify_family(invocation);

    // PTY requests are always local regardless of family: an
    // intercepted TTY is an unusable TTY.
    let (family, base) = if invocation.pty_requested {
        (CargoCommandFamily::Interactive, BaseEligibility::LocalOnly)
    } else {
        (family, base)
    };

    // Concerns only matter where interception would otherwise happen:
    // local-only shapes have nothing to bypass.
    let intercepting = !matches!(base, BaseEligibility::LocalOnly);
    let outcome = if intercepting {
        match first_unadmitted_concern(&concerns) {
            Some((tag, notes)) => EnforcementOutcome::ExplainedBypass {
                reason: format!("compatibility matrix refuses '{tag}': {notes}"),
            },
            None => EnforcementOutcome::Admitted,
        }
    } else {
        EnforcementOutcome::Admitted
    };

    EligibilityDecision {
        family,
        base,
        concerns,
        outcome,
    }
}

fn detect_concerns(invocation: &ExpandedCargoInvocation) -> Vec<CompatibilityConcern> {
    let mut concerns = Vec::new();
    if invocation.custom_runner_declared {
        concerns.push(CompatibilityConcern::CustomRunner);
    }
    // `-Z` takes its flag joined ("-Zbuild-std") or as the NEXT argv
    // token ("-Z build-std"); both spellings must detect identically.
    let mut pending_z = false;
    for arg in &invocation.argv {
        let payload = if pending_z {
            pending_z = false;
            Some(arg.as_str())
        } else {
            if arg == "-Z" {
                pending_z = true;
            }
            arg.strip_prefix("-Z").map(str::trim_start)
        };
        let Some(payload) = payload.filter(|p| !p.is_empty()) else {
            continue;
        };
        if payload.starts_with("build-std") {
            concerns.push(CompatibilityConcern::BuildStd);
        } else if payload.starts_with("artifact-dependencies") {
            concerns.push(CompatibilityConcern::ArtifactDependencies);
        } else {
            let flag = payload.split('=').next().unwrap_or(payload);
            concerns.push(CompatibilityConcern::UnstableFlag(format!(
                "unstable-flag:{flag}"
            )));
        }
    }
    concerns.sort();
    concerns.dedup();
    concerns
}

/// `(tag, explanation)` of the first concern the matrix refuses.
fn first_unadmitted_concern(concerns: &[CompatibilityConcern]) -> Option<(String, String)> {
    concerns.iter().find_map(|concern| {
        let tag = concern_tag(concern);
        match COMPATIBILITY_MATRIX
            .iter()
            .find(|row| row.concern_tag == tag)
        {
            // Admitted: no bypass.
            Some(row) if row.admitted => None,
            // Refused with the row's rationale.
            Some(row) => Some((tag, row.notes.to_owned())),
            // Unlisted: refuse rather than guess, and say so.
            None => Some((
                tag,
                "unlisted in the compatibility matrix: unverified, \
                 interception refuses until a shadow proof lands"
                    .to_owned(),
            )),
        }
    })
}

fn concern_tag(concern: &CompatibilityConcern) -> String {
    match concern {
        CompatibilityConcern::BuildStd => "build-std".to_owned(),
        CompatibilityConcern::CustomRunner => "custom-runner".to_owned(),
        CompatibilityConcern::ArtifactDependencies => "artifact-dependencies".to_owned(),
        CompatibilityConcern::UnstableFlag(tagged) => tagged.clone(),
    }
}

fn classify_family(invocation: &ExpandedCargoInvocation) -> (CargoCommandFamily, BaseEligibility) {
    // Skip a leading driver name ("cargo") and global flags that do
    // not change what the command IS.
    let mut args = invocation.argv.as_slice();
    if args.first().map(String::as_str) == Some("cargo") {
        args = &args[1..];
    }
    while matches!(
        args.first().map(String::as_str),
        Some("--quiet") | Some("-q") | Some("--verbose") | Some("-v")
    ) {
        args = &args[1..];
    }
    let first = args.first().map(String::as_str);

    // Probe forms: --version/-V/--help/-h anywhere leading.
    if matches!(
        first,
        Some("--version") | Some("-V") | Some("--help") | Some("-h") | Some("help")
    ) {
        return (CargoCommandFamily::Probe, BaseEligibility::TinyCachedProbe);
    }

    match first {
        Some("build") | Some("check") | Some("clippy") | Some("doc") | Some("rustdoc") => (
            CargoCommandFamily::CompilePhase,
            BaseEligibility::UnitDecompositionAccelerated,
        ),
        Some("test") => (
            CargoCommandFamily::Test,
            BaseEligibility::AdmittedTestActionsPreferred,
        ),
        Some("nextest") => {
            // `cargo nextest <sub>`: only `run` (and `list`) are test
            // shapes; `cargo nextest archive` etc. are not.
            match args.get(1).map(String::as_str) {
                Some("run") | Some("list") | None => (
                    CargoCommandFamily::Test,
                    BaseEligibility::AdmittedTestActionsPreferred,
                ),
                Some(_) => (CargoCommandFamily::Unrecognized, BaseEligibility::LocalOnly),
            }
        }
        Some("run") => (
            CargoCommandFamily::RunCommand,
            BaseEligibility::CompileOnlyAcceleration,
        ),
        Some("bench") => (
            CargoCommandFamily::Bench,
            BaseEligibility::TimingNeverCached,
        ),
        Some("clean") | Some("fix") | Some("install") | Some("uninstall") | Some("publish")
        | Some("package") | Some("vendor") | Some("add") | Some("remove") | Some("yank")
        | Some("login") | Some("logout") => (
            CargoCommandFamily::Mutating,
            BaseEligibility::SideEffectingWholeCommandOnly,
        ),
        Some("watch") => (CargoCommandFamily::Interactive, BaseEligibility::LocalOnly),
        _ => (CargoCommandFamily::Unrecognized, BaseEligibility::LocalOnly),
    }
}

// ---------------------------------------------------------------------
// Tests — the K016 acceptance matrix: enforcement fixtures per family.
// ---------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn inv(args: &[&str]) -> ExpandedCargoInvocation {
        ExpandedCargoInvocation {
            argv: args.iter().map(|s| (*s).to_owned()).collect(),
            pty_requested: false,
            custom_runner_declared: false,
        }
    }

    #[test]
    fn probe_family_fixture_tiny_cached() {
        for argv in [
            vec!["cargo", "--version"],
            vec!["cargo", "-V"],
            vec!["cargo", "--help"],
            vec!["cargo", "help", "build"],
        ] {
            let d = enforce(&inv(&argv));
            assert_eq!(d.family, CargoCommandFamily::Probe, "{argv:?}");
            assert_eq!(d.base, BaseEligibility::TinyCachedProbe);
            assert!(d.base.may_serve_results());
            assert_eq!(d.outcome, EnforcementOutcome::Admitted);
            assert_eq!(d.action_class_hint(), Some(ActionClass::ToolchainProbe));
        }
    }

    #[test]
    fn compile_phase_fixtures_accelerated_with_fallback() {
        for cmd in ["build", "check", "clippy", "doc"] {
            let d = enforce(&inv(&["cargo", cmd]));
            assert_eq!(d.family, CargoCommandFamily::CompilePhase, "{cmd}");
            assert_eq!(d.base, BaseEligibility::UnitDecompositionAccelerated);
            assert!(d.base.may_serve_results());
            assert_eq!(d.outcome, EnforcementOutcome::Admitted);
            assert_eq!(
                d.action_class_hint(),
                Some(ActionClass::CargoWholeCommandBounded)
            );
        }
    }

    #[test]
    fn test_family_fixture_admitted_actions_or_bounded() {
        for argv in [
            vec!["cargo", "test"],
            vec!["cargo", "test", "--workspace"],
            vec!["cargo", "nextest", "run"],
            vec!["cargo", "nextest", "list"],
        ] {
            let d = enforce(&inv(&argv));
            assert_eq!(d.family, CargoCommandFamily::Test, "{argv:?}");
            assert_eq!(d.base, BaseEligibility::AdmittedTestActionsPreferred);
            assert_eq!(d.outcome, EnforcementOutcome::Admitted);
        }
        // nextest non-test subcommands fail closed.
        let d = enforce(&inv(&["cargo", "nextest", "archive"]));
        assert_eq!(d.family, CargoCommandFamily::Unrecognized);
        assert_eq!(d.base, BaseEligibility::LocalOnly);
    }

    #[test]
    fn run_fixture_compile_only_acceleration() {
        let d = enforce(&inv(&["cargo", "run", "--bin", "rch"]));
        assert_eq!(d.family, CargoCommandFamily::RunCommand);
        assert_eq!(d.base, BaseEligibility::CompileOnlyAcceleration);
        // Compile units may be served; the RUN itself is not a servable
        // result — the distinction lives in the base grant, and this
        // matrix never marks plain execution cacheable.
        assert_eq!(
            d.action_class_hint(),
            Some(ActionClass::CargoWholeCommandBounded)
        );
    }

    #[test]
    fn bench_fixture_timing_never_cached() {
        let d = enforce(&inv(&["cargo", "bench"]));
        assert_eq!(d.family, CargoCommandFamily::Bench);
        assert_eq!(d.base, BaseEligibility::TimingNeverCached);
        assert!(!d.base.may_serve_results(), "bench timing must never serve");
        // With an unstable flag the compile-phase acceleration also
        // bypasses rather than silently running remotely uncached.
        let z = enforce(&inv(&["cargo", "bench", "-Zsome-flag"]));
        assert!(matches!(
            z.outcome,
            EnforcementOutcome::ExplainedBypass { .. }
        ));
    }

    #[test]
    fn mutating_family_fixture_side_effecting_only() {
        for cmd in [
            "clean",
            "fix",
            "install",
            "uninstall",
            "publish",
            "package",
            "vendor",
            "add",
            "remove",
            "yank",
            "login",
            "logout",
        ] {
            let d = enforce(&inv(&["cargo", cmd]));
            assert_eq!(d.family, CargoCommandFamily::Mutating, "{cmd}");
            assert_eq!(d.base, BaseEligibility::SideEffectingWholeCommandOnly);
            assert!(!d.base.may_serve_results(), "{cmd} must never serve");
            assert_eq!(d.action_class_hint(), None, "{cmd} is not an action");
        }
    }

    #[test]
    fn interactive_and_pty_fixture_local_only() {
        let watch = enforce(&inv(&["cargo", "watch", "-x", "check"]));
        assert_eq!(watch.family, CargoCommandFamily::Interactive);
        assert_eq!(watch.base, BaseEligibility::LocalOnly);

        // Even an otherwise-accelerated command goes local on PTY.
        let mut pty = inv(&["cargo", "check"]);
        pty.pty_requested = true;
        let d = enforce(&pty);
        assert_eq!(d.family, CargoCommandFamily::Interactive);
        assert_eq!(d.base, BaseEligibility::LocalOnly);
        assert_eq!(d.action_class_hint(), None);
    }

    #[test]
    fn unstable_modes_bypass_is_explained_per_matrix_row() {
        // build-std: refused, with the matrix row's notes verbatim.
        let d = enforce(&inv(&["cargo", "build", "-Zbuild-std=core"]));
        assert_eq!(d.family, CargoCommandFamily::CompilePhase);
        assert!(d.concerns.contains(&CompatibilityConcern::BuildStd));
        match &d.outcome {
            EnforcementOutcome::ExplainedBypass { reason } => {
                assert!(reason.contains("build-std"), "{reason}");
                assert!(reason.contains("sysroot"), "{reason}");
            }
            other => panic!("expected explained bypass, got {other:?}"),
        }
        assert_eq!(d.action_class_hint(), None, "bypasses are not actions");

        // Space-separated spelling detected identically.
        let d2 = enforce(&inv(&["cargo", "build", "-Z", "build-std"]));
        assert!(d2.concerns.contains(&CompatibilityConcern::BuildStd));
        assert!(matches!(
            d2.outcome,
            EnforcementOutcome::ExplainedBypass { .. }
        ));

        // An ADMITTED row stays admitted while recording the concern.
        let ok = enforce(&inv(&["cargo", "check", "-Zcheck-cfg=names"]));
        assert_eq!(ok.outcome, EnforcementOutcome::Admitted);
        assert!(ok.concerns.contains(&CompatibilityConcern::UnstableFlag(
            "unstable-flag:check-cfg".to_owned()
        )));

        // Custom runner overlay records its concern.
        let mut runner = inv(&["cargo", "test"]);
        runner.custom_runner_declared = true;
        let rd = enforce(&runner);
        assert_eq!(rd.concerns, vec![CompatibilityConcern::CustomRunner]);
        // ...and the bypass names the row.
        assert!(matches!(
            rd.outcome,
            EnforcementOutcome::ExplainedBypass { .. }
        ));
    }

    #[test]
    fn aliases_classify_after_expansion_never_from_raw_token() {
        // An alias `tidy` that expands to `clean --release`: the
        // EXPANDED form is what arrives here, and it classifies as
        // mutating — the wrapper can never mistake it for pure.
        let d = enforce(&inv(&["cargo", "clean", "--release"]));
        assert_eq!(d.family, CargoCommandFamily::Mutating);
        assert_eq!(d.base, BaseEligibility::SideEffectingWholeCommandOnly);

        // Structurally: there is no API taking a raw alias token. The
        // closest mistake — feeding the un-expanded alias name — fails
        // CLOSED to local-only instead of guessing purity.
        let raw = enforce(&inv(&["cargo", "tidy"]));
        assert_eq!(raw.family, CargoCommandFamily::Unrecognized);
        assert_eq!(raw.base, BaseEligibility::LocalOnly);
        assert!(!raw.base.may_serve_results());
    }

    #[test]
    fn unrecognized_subcommands_fail_closed() {
        for argv in [
            vec!["cargo", "frobnicate"],
            vec!["cargo", "nextest", "exotic"],
            vec![],
        ] {
            let d = enforce(&inv(&argv));
            assert_eq!(d.family, CargoCommandFamily::Unrecognized, "{argv:?}");
            assert_eq!(d.base, BaseEligibility::LocalOnly);
            assert_eq!(d.outcome, EnforcementOutcome::Admitted);
        }
    }

    #[test]
    fn global_flags_do_not_change_the_command() {
        let d = enforce(&inv(&["cargo", "--quiet", "build", "--release"]));
        assert_eq!(d.family, CargoCommandFamily::CompilePhase);
        assert_eq!(d.base, BaseEligibility::UnitDecompositionAccelerated);
    }

    #[test]
    fn compatibility_matrix_rows_are_total_over_named_tags() {
        // Every concern tag the detector can emit has a matrix row, so
        // no concern ever hits the generic unlisted path silently.
        let emitted = [
            "build-std".to_owned(),
            "custom-runner".to_owned(),
            "artifact-dependencies".to_owned(),
            "unstable-flag:check-cfg".to_owned(),
        ];
        for tag in emitted {
            assert!(
                COMPATIBILITY_MATRIX
                    .iter()
                    .any(|row| row.concern_tag == tag),
                "no matrix row for {tag}"
            );
        }
        // And every row carries non-empty notes (bypass reasons quote them).
        for row in COMPATIBILITY_MATRIX {
            assert!(!row.notes.is_empty(), "{} has empty notes", row.concern_tag);
        }
    }
}
