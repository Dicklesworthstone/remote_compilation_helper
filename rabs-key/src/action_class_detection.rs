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
}
