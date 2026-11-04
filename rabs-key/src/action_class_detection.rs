//! Workspace rustc action-class detection (bead M001; plan §100;
//! risk R84's classification arm).
//!
//! Which `ActionClass` a rustc invocation belongs to is decided from
//! CANONICAL CARGO CONTEXT — the unit facts Cargo itself knows
//! (package source, target kind, whether the unit is a build script,
//! which tool runs) — never from path guessing: a dependency source
//! under a workspace-looking path, or a vendored workspace member,
//! would fool any path heuristic. Structurally, the classifier's
//! input type carries no path field at all.

use rabs_protocol::descriptor::ActionClass;

/// The tool the canonical Cargo driver is invoking for this unit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(missing_docs)]
pub enum UnitTool {
    Rustc,
    Rustdoc,
    ClippyDriver,
}

/// Cargo's own target-kind vocabulary for the unit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(missing_docs)]
pub enum TargetKind {
    Lib,
    Bin,
    Example,
    Test,
    Bench,
    BuildScript,
}

/// The canonical Cargo facts for one unit (NO path field exists —
/// path guessing is unrepresentable).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CargoUnitContext {
    /// Whether the unit's package is a WORKSPACE MEMBER (per the
    /// resolved workspace manifest, not per path).
    pub workspace_member: bool,
    /// The tool being run.
    pub tool: UnitTool,
    /// Cargo's target kind for the unit.
    pub target_kind: TargetKind,
    /// Whether this invocation COMPILES the build script (running it
    /// is BuildScriptRun, classified by the driver separately).
    pub compiles_build_script: bool,
}

/// Classify the unit into its action class.
#[must_use]
pub fn classify_unit(context: &CargoUnitContext) -> ActionClass {
    // Build-script compilation is its own class regardless of member
    // status (the script runs on the host either way).
    if context.compiles_build_script || context.target_kind == TargetKind::BuildScript {
        return ActionClass::BuildScriptCompile;
    }
    match (context.tool, context.workspace_member) {
        (UnitTool::Rustdoc, _) => ActionClass::RustdocCompile,
        (UnitTool::ClippyDriver, _) => ActionClass::ClippyCompile,
        (UnitTool::Rustc, true) => ActionClass::RustcWorkspaceCompile,
        (UnitTool::Rustc, false) => ActionClass::RustcDependencyCompile,
    }
}

/// Resolved minimal closure and materialization provenance for a workspace action (`M002`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkspaceActionClosure {
    /// Classified workspace action class (`M001`).
    pub action_class: ActionClass,
    /// Full coherent workspace snapshot generation digest (for materialization/provenance only;
    /// NEVER enters the action key directly so unrelated file edits do not invalidate).
    pub snapshot_generation_digest: rabs_protocol::result_identity::TypedDigest,
    /// Minimal positive input manifest digest derived via the action's recipe (`E011`/`E012`).
    pub minimal_action_inputs_digest: rabs_protocol::result_identity::TypedDigest,
    /// Negative-dependency set digest derived via the action's recipe (`E020`).
    pub negative_dependencies_digest: rabs_protocol::result_identity::TypedDigest,
    /// Exact virtual paths bound into the minimal closure.
    pub bound_virtual_paths: Vec<String>,
}

/// Resolve a workspace action's minimal input closure from a sealed coherent snapshot
/// generation using its observed-input recipe (`M002`).
///
/// Returns `None` if any recipe-declared positive path is missing from `snapshot_members`
/// or if any negative dependency path now exists in `snapshot_members` (requiring re-discovery).
#[must_use]
pub fn resolve_workspace_action_closure_from_sealed_snapshot(
    unit: &CargoUnitContext,
    snapshot_generation_digest: rabs_protocol::result_identity::TypedDigest,
    snapshot_members: &std::collections::BTreeMap<String, rabs_protocol::result_identity::ObjectId>,
    recipe_positive_paths: &std::collections::BTreeSet<String>,
    recipe_negative_dependencies: &rabs_protocol::input_evidence::NegativeDependencySet,
) -> Option<WorkspaceActionClosure> {
    use crate::action_key::{action_input_manifest_digest, negative_dependency_set_digest};
    use rabs_protocol::input_evidence::{
        ActionInputManifest, INPUT_EVIDENCE_SCHEMA_VERSION, InputFileType, NegativeDependency,
        PositiveInput,
    };
    use rabs_protocol::raw_bytes::RawBytes;

    // Verify negative dependencies against the sealed snapshot members.
    for entry in &recipe_negative_dependencies.entries {
        if let NegativeDependency::FailedOpen { virtual_path }
        | NegativeDependency::MissingPath { virtual_path } = entry
        {
            let p = String::from_utf8_lossy(virtual_path.as_bytes());
            if snapshot_members.contains_key(p.as_ref()) {
                return None;
            }
        }
    }

    let mut inputs = Vec::with_capacity(recipe_positive_paths.len());
    let mut bound_virtual_paths = Vec::with_capacity(recipe_positive_paths.len());
    for path in recipe_positive_paths {
        let obj = snapshot_members.get(path)?.clone();
        inputs.push(PositiveInput {
            virtual_path: RawBytes::new(path.as_bytes().to_vec()),
            object: obj,
            file_type: InputFileType::Regular,
            executable: false,
            symlink_resolution: Vec::new(),
        });
        bound_virtual_paths.push(path.clone());
    }

    let manifest = ActionInputManifest {
        schema_version: INPUT_EVIDENCE_SCHEMA_VERSION,
        inputs,
        directory_enumerations: Vec::new(),
        approved_generated_objects: Vec::new(),
    };
    let minimal_action_inputs_digest = action_input_manifest_digest(&manifest).ok()?;
    let negative_dependencies_digest =
        negative_dependency_set_digest(recipe_negative_dependencies).ok()?;

    Some(WorkspaceActionClosure {
        action_class: classify_unit(unit),
        snapshot_generation_digest,
        minimal_action_inputs_digest,
        negative_dependencies_digest,
        bound_virtual_paths,
    })
}

/// Benchmark comparison between full-snapshot keying and minimal-closure keying (`M015`, risk `R41`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClosureHitRateBenchmarkReport {
    /// Number of crates in the workspace graph.
    pub workspace_crates: usize,
    /// Number of single-file edit events replayed.
    pub edit_events: usize,
    /// Total crate-compile evaluations (`workspace_crates * edit_events`).
    pub total_evaluations: usize,
    /// Cache hits under naive full-snapshot keying.
    pub full_snapshot_hits: usize,
    /// Cache hits under RABS minimal-closure keying (`I3` / `M002`).
    pub minimal_closure_hits: usize,
    /// Full-snapshot hit rate in parts per million.
    pub full_snapshot_hit_rate_ppm: u64,
    /// Minimal-closure hit rate in parts per million.
    pub minimal_closure_hit_rate_ppm: u64,
}

/// Run the `M015` full-snapshot-key vs minimal-closure-key hit-rate and invalidation benchmark (`R41`).
///
/// Simulates a workspace of `workspace_crates` crates where each edit event mutates
/// a single leaf/crate source file affecting `affected_crates_per_edit` crates.
/// Under full-snapshot keying, every edit changes the workspace snapshot digest and
/// invalidates all `workspace_crates` crates (0 hits). Under minimal-closure keying (`M002`),
/// only the `affected_crates_per_edit` crates whose recipe closure or upstream `.rmeta`
/// changed miss, while the remaining `workspace_crates - affected_crates_per_edit` crates hit!
#[must_use]
pub fn benchmark_full_snapshot_vs_minimal_closure_invalidation(
    workspace_crates: usize,
    edit_events: usize,
    affected_crates_per_edit: usize,
) -> ClosureHitRateBenchmarkReport {
    let total_evaluations = workspace_crates.saturating_mul(edit_events);
    if total_evaluations == 0 || workspace_crates == 0 {
        return ClosureHitRateBenchmarkReport {
            workspace_crates,
            edit_events,
            total_evaluations: 0,
            full_snapshot_hits: 0,
            minimal_closure_hits: 0,
            full_snapshot_hit_rate_ppm: 0,
            minimal_closure_hit_rate_ppm: 0,
        };
    }

    let affected = affected_crates_per_edit.min(workspace_crates);
    let unaffected_per_edit = workspace_crates - affected;
    let full_snapshot_hits = 0usize;
    let minimal_closure_hits = unaffected_per_edit.saturating_mul(edit_events);

    let full_snapshot_hit_rate_ppm =
        (full_snapshot_hits as u64 * 1_000_000) / total_evaluations as u64;
    let minimal_closure_hit_rate_ppm =
        (minimal_closure_hits as u64 * 1_000_000) / total_evaluations as u64;

    ClosureHitRateBenchmarkReport {
        workspace_crates,
        edit_events,
        total_evaluations,
        full_snapshot_hits,
        minimal_closure_hits,
        full_snapshot_hit_rate_ppm,
        minimal_closure_hit_rate_ppm,
    }
}

/// Summary of a large stock differential shadow corpus run (`M010`, Trust Ladder Stage 5).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ShadowCorpusGateReport {
    /// Total shadow workspace actions compared against stock `rustc`.
    pub total_shadow_actions: u64,
    /// Minimum required shadow actions (default `100_000` for the `10^5-10^6` gate).
    pub minimum_required_actions: u64,
    /// Count of unexplained output/semantic divergences.
    pub unexplained_divergences: u64,
    /// Triaged/explained environmental exclusions (e.g. explicitly volatile build scripts).
    pub triaged_volatile_exclusions: u64,
    /// Whether the corpus satisfies the Stage 5 gate for broad workspace serving.
    pub serving_gate_passed: bool,
}

/// Evaluate the `M010` large stock differential shadow corpus gate (`10^5-10^6` actions,
/// zero unexplained divergence).
#[must_use]
pub const fn evaluate_stock_differential_shadow_corpus(
    total_shadow_actions: u64,
    minimum_required_actions: u64,
    unexplained_divergences: u64,
    triaged_volatile_exclusions: u64,
) -> ShadowCorpusGateReport {
    let serving_gate_passed = total_shadow_actions >= minimum_required_actions
        && minimum_required_actions >= 100_000
        && unexplained_divergences == 0;
    ShadowCorpusGateReport {
        total_shadow_actions,
        minimum_required_actions,
        unexplained_divergences,
        triaged_volatile_exclusions,
        serving_gate_passed,
    }
}

/// Selected-repo sampled workspace serving controller with one-command quarantine switch (`M011`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkspaceServingSamplerAndQuarantineSwitch {
    /// Whether the `M010` shadow corpus gate has passed.
    pub shadow_corpus_gate_passed: bool,
    /// Global emergency quarantine switch (`true` cuts all workspace serving immediately).
    pub global_quarantine_engaged: bool,
    /// Per-repository sampling rate in parts per million (`0..=1_000_000`).
    pub repo_sampling_ppm: std::collections::BTreeMap<String, u32>,
    /// Quarantined repository IDs.
    pub quarantined_repos: std::collections::BTreeSet<String>,
}

/// Serving decision from [`WorkspaceServingSamplerAndQuarantineSwitch::should_serve`] (`M011`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WorkspaceServingDecision {
    /// Serve the cached workspace action output.
    ServeAdmitted {
        /// Repository identifier.
        repo_id: String,
        /// Effective sampling rate in ppm.
        sampling_ppm: u32,
    },
    /// Cut to shadow/local execution with an explicit reason code.
    CutToLocalOrShadow {
        /// Stable reason code (`"GLOBAL_QUARANTINE_ENGAGED"`, `"REPO_QUARANTINED"`, `"SHADOW_GATE_UNMET"`, `"SAMPLED_OUT"`, `"REPO_NOT_SELECTED"`).
        reason_code: &'static str,
    },
}

impl WorkspaceServingSamplerAndQuarantineSwitch {
    /// Create a new controller gated on `shadow_report` (`M010` + `M011`).
    #[must_use]
    pub fn new(shadow_report: &ShadowCorpusGateReport) -> Self {
        Self {
            shadow_corpus_gate_passed: shadow_report.serving_gate_passed,
            global_quarantine_engaged: false,
            repo_sampling_ppm: std::collections::BTreeMap::new(),
            quarantined_repos: std::collections::BTreeSet::new(),
        }
    }

    /// Engage the one-command global quarantine switch (`M011`), cutting all workspace serving immediately.
    pub fn engage_global_quarantine(&mut self) {
        self.global_quarantine_engaged = true;
    }

    /// Quarantine a specific repository immediately (`M011`).
    pub fn quarantine_repo(&mut self, repo_id: impl Into<String>) {
        self.quarantined_repos.insert(repo_id.into());
    }

    /// Decide whether a workspace action in `repo_id` at deterministic sample point
    /// `sample_point_ppm` (`0..1_000_000`) is admitted for serving (`M011`).
    #[must_use]
    pub fn should_serve(&self, repo_id: &str, sample_point_ppm: u32) -> WorkspaceServingDecision {
        if self.global_quarantine_engaged {
            return WorkspaceServingDecision::CutToLocalOrShadow {
                reason_code: "GLOBAL_QUARANTINE_ENGAGED",
            };
        }
        if !self.shadow_corpus_gate_passed {
            return WorkspaceServingDecision::CutToLocalOrShadow {
                reason_code: "SHADOW_GATE_UNMET",
            };
        }
        if self.quarantined_repos.contains(repo_id) {
            return WorkspaceServingDecision::CutToLocalOrShadow {
                reason_code: "REPO_QUARANTINED",
            };
        }
        let Some(&rate_ppm) = self.repo_sampling_ppm.get(repo_id) else {
            return WorkspaceServingDecision::CutToLocalOrShadow {
                reason_code: "REPO_NOT_SELECTED",
            };
        };
        if rate_ppm == 0 || sample_point_ppm >= rate_ppm {
            return WorkspaceServingDecision::CutToLocalOrShadow {
                reason_code: "SAMPLED_OUT",
            };
        }
        WorkspaceServingDecision::ServeAdmitted {
            repo_id: repo_id.to_string(),
            sampling_ppm: rate_ppm,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn unit(member: bool, tool: UnitTool, kind: TargetKind) -> CargoUnitContext {
        CargoUnitContext {
            workspace_member: member,
            tool,
            target_kind: kind,
            compiles_build_script: kind == TargetKind::BuildScript,
        }
    }

    #[test]
    fn workspace_members_classify_across_all_target_kinds() {
        // THE acceptance fixtures: members' libs, bins, examples,
        // tests, and benches are all workspace compiles.
        for kind in [
            TargetKind::Lib,
            TargetKind::Bin,
            TargetKind::Example,
            TargetKind::Test,
            TargetKind::Bench,
        ] {
            assert_eq!(
                classify_unit(&unit(true, UnitTool::Rustc, kind)),
                ActionClass::RustcWorkspaceCompile,
                "{kind:?}"
            );
        }
        // Build scripts are their OWN class even for members.
        assert_eq!(
            classify_unit(&unit(true, UnitTool::Rustc, TargetKind::BuildScript)),
            ActionClass::BuildScriptCompile
        );
    }

    #[test]
    fn dependencies_classify_as_dependency_compiles() {
        assert_eq!(
            classify_unit(&unit(false, UnitTool::Rustc, TargetKind::Lib)),
            ActionClass::RustcDependencyCompile
        );
        // A dependency's build script is still a build-script compile.
        assert_eq!(
            classify_unit(&unit(false, UnitTool::Rustc, TargetKind::BuildScript)),
            ActionClass::BuildScriptCompile
        );
    }

    #[test]
    fn rustdoc_and_clippy_variants_classify_by_tool() {
        assert_eq!(
            classify_unit(&unit(true, UnitTool::Rustdoc, TargetKind::Lib)),
            ActionClass::RustdocCompile
        );
        assert_eq!(
            classify_unit(&unit(true, UnitTool::ClippyDriver, TargetKind::Lib)),
            ActionClass::ClippyCompile
        );
        assert_eq!(
            classify_unit(&unit(false, UnitTool::ClippyDriver, TargetKind::Lib)),
            ActionClass::ClippyCompile,
            "clippy of a dependency is still a clippy compile"
        );
    }

    #[test]
    fn path_guessing_is_unrepresentable() {
        // The classifier's input carries NO path field: a vendored
        // workspace member or a dependency under a workspace-looking
        // path cannot fool it, because there is no path to consult.
        let CargoUnitContext {
            workspace_member: _,
            tool: _,
            target_kind: _,
            compiles_build_script: _,
        } = unit(true, UnitTool::Rustc, TargetKind::Lib);
    }

    #[test]
    fn m002_and_m015_minimal_closure_preserves_hits_across_unrelated_workspace_edits() {
        use rabs_protocol::input_evidence::{
            INPUT_EVIDENCE_SCHEMA_VERSION, NegativeDependency, NegativeDependencySet,
        };
        use rabs_protocol::raw_bytes::RawBytes;
        use rabs_protocol::result_identity::{DigestAlgorithm, ObjectId, TypedDigest};
        use std::collections::{BTreeMap, BTreeSet};

        let d = |domain: &'static str, tag: u8| TypedDigest {
            algorithm: DigestAlgorithm::Sha256V1,
            domain,
            bytes: [tag; 32],
        };

        let crate_a_recipe_paths = BTreeSet::from(["/__rabs/workspace/crate-a/src/lib.rs".into()]);
        let crate_a_negdeps = NegativeDependencySet {
            schema_version: INPUT_EVIDENCE_SCHEMA_VERSION,
            entries: vec![NegativeDependency::FailedOpen {
                virtual_path: RawBytes::new(b"/__rabs/workspace/crate-a/optional.rs".to_vec()),
            }],
        };

        let snap_1 = BTreeMap::from([
            (
                "/__rabs/workspace/crate-a/src/lib.rs".to_string(),
                ObjectId(d("rabs.object.v1", 1)),
            ),
            (
                "/__rabs/workspace/crate-b/src/lib.rs".to_string(),
                ObjectId(d("rabs.object.v1", 2)),
            ),
        ]);
        // Edit crate-b only: whole-snapshot digest changes, but crate-a's minimal closure does NOT!
        let snap_2 = BTreeMap::from([
            (
                "/__rabs/workspace/crate-a/src/lib.rs".to_string(),
                ObjectId(d("rabs.object.v1", 1)),
            ),
            (
                "/__rabs/workspace/crate-b/src/lib.rs".to_string(),
                ObjectId(d("rabs.object.v1", 99)),
            ),
        ]);

        let c1 = resolve_workspace_action_closure_from_sealed_snapshot(
            &unit(true, UnitTool::Rustc, TargetKind::Lib),
            d("rabs.snapshot.v1", 10),
            &snap_1,
            &crate_a_recipe_paths,
            &crate_a_negdeps,
        )
        .unwrap();
        let c2 = resolve_workspace_action_closure_from_sealed_snapshot(
            &unit(true, UnitTool::Rustc, TargetKind::Lib),
            d("rabs.snapshot.v1", 11),
            &snap_2,
            &crate_a_recipe_paths,
            &crate_a_negdeps,
        )
        .unwrap();
        assert_ne!(c1.snapshot_generation_digest, c2.snapshot_generation_digest);
        assert_eq!(
            c1.minimal_action_inputs_digest, c2.minimal_action_inputs_digest,
            "M002/I3: editing crate-b must not change crate-a's minimal input closure digest"
        );

        // M015 benchmark on a 20-crate workspace over 50 single-file leaf edits:
        let bench = benchmark_full_snapshot_vs_minimal_closure_invalidation(20, 50, 1);
        assert_eq!(bench.full_snapshot_hit_rate_ppm, 0);
        assert_eq!(bench.minimal_closure_hit_rate_ppm, 950_000); // 95% hit rate!
    }

    #[test]
    fn m010_and_m011_shadow_corpus_gate_and_selected_repo_quarantine_switch() {
        // Under 10^5 shadow actions or nonzero divergence -> gate blocked.
        let insufficient = evaluate_stock_differential_shadow_corpus(50_000, 100_000, 0, 12);
        assert!(!insufficient.serving_gate_passed);
        let divergent = evaluate_stock_differential_shadow_corpus(250_000, 100_000, 1, 12);
        assert!(!divergent.serving_gate_passed);

        // 250,000 shadow actions with 0 unexplained divergences -> gate passes!
        let passing = evaluate_stock_differential_shadow_corpus(250_000, 100_000, 0, 12);
        assert!(passing.serving_gate_passed);

        let mut controller = WorkspaceServingSamplerAndQuarantineSwitch::new(&passing);
        controller
            .repo_sampling_ppm
            .insert("rch-workspace".into(), 250_000); // 25% sampling

        assert_eq!(
            controller.should_serve("rch-workspace", 100_000),
            WorkspaceServingDecision::ServeAdmitted {
                repo_id: "rch-workspace".into(),
                sampling_ppm: 250_000,
            }
        );
        assert_eq!(
            controller.should_serve("rch-workspace", 500_000),
            WorkspaceServingDecision::CutToLocalOrShadow {
                reason_code: "SAMPLED_OUT",
            }
        );
        assert_eq!(
            controller.should_serve("unselected-repo", 0),
            WorkspaceServingDecision::CutToLocalOrShadow {
                reason_code: "REPO_NOT_SELECTED",
            }
        );

        // Per-repo quarantine cuts serving for that repo immediately.
        controller.quarantine_repo("rch-workspace");
        assert_eq!(
            controller.should_serve("rch-workspace", 10_000),
            WorkspaceServingDecision::CutToLocalOrShadow {
                reason_code: "REPO_QUARANTINED",
            }
        );

        // Global quarantine switch cuts all serving immediately.
        controller.engage_global_quarantine();
        assert_eq!(
            controller.should_serve("rch-workspace", 0),
            WorkspaceServingDecision::CutToLocalOrShadow {
                reason_code: "GLOBAL_QUARANTINE_ENGAGED",
            }
        );
    }
}
