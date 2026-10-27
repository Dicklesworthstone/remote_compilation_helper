//! Admission of the units Cargo actually selected for a check, build or test.
//!
//! `cargo metadata` describes packages, including optional and development
//! dependencies that a particular command will never execute. Cargo's nightly
//! `--unit-graph -Z unstable-options` output instead describes that command's
//! compiler/build-script units without building them. The canonical driver
//! obtains this graph from its captured Cargo before exposing a cache endpoint.
//!
//! This validator accepts a bounded graph of Cargo compilation units, including
//! build scripts and procedural macros that Cargo must execute while compiling.
//! It does not infer feature resolution, grant cache authority, or establish
//! provenance from JSON alone. The caller must run the trusted captured Cargo
//! with the same command selection, semantic environment, configuration and
//! mount view as the subsequent compilation, and bind every returned source path to
//! its captured input roots. The driver may add its trusted wrapper and socket
//! control variables only after admission; these controls cannot select Cargo
//! packages, features or targets. A graph containing project executors requires
//! closed per-action worker execution for dependency caching: project code can
//! access the wrapper endpoint, so its claimed local completions are not trusted
//! compiler evidence. Every test operation requires the same boundary because
//! its test executables and doctests can reach that endpoint too. Unknown modes
//! and unrelated program commands remain refused; test outcomes are not cached.

use serde_json::Value;
use std::collections::BTreeSet;
use std::io;

mod selection;
pub use selection::{CompilationCommand, CompilationSelection};

const MAX_UNITS: usize = 16_384;
const MAX_DEPENDENCIES: usize = 262_144;
const MAX_FEATURES: usize = 4_096;
const MAX_TEXT: usize = 8_192;
const LIBRARY_TYPES: &[&str] = &["lib", "rlib", "dylib", "cdylib", "staticlib"];

/// A validated selected compilation graph. Counts are explanatory, not authority.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompilationUnitGraph {
    /// Number of selected compiler units, including distinct feature/profile units.
    pub units: usize,
    /// Number of distinct opaque Cargo package identities in those units.
    pub packages: usize,
    /// Number of Cargo-selected root units.
    pub roots: usize,
    source_paths: Vec<String>,
    library_units: Vec<CompilationLibraryUnit>,
    project_executors: bool,
    doctests: bool,
}

/// One ordinary library compilation selected by the captured Cargo graph.
/// The driver must bind its source to retained mounts before using it to admit
/// workspace execution. This record never grants result-cache authority.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct CompilationLibraryUnit {
    package_id: String,
    source_path: String,
    crate_name: String,
    crate_types: Vec<String>,
    mode: String,
    platform: Option<String>,
    features: Vec<String>,
}

impl CompilationLibraryUnit {
    /// Cargo's opaque selected package identity.
    pub fn package_id(&self) -> &str {
        &self.package_id
    }
    /// Exact normalized source path returned by Cargo.
    pub fn source_path(&self) -> &str {
        &self.source_path
    }
    /// Rust compiler spelling of the selected target name.
    pub fn crate_name(&self) -> &str {
        &self.crate_name
    }
    /// Selected ordinary Rust library output kinds.
    pub fn crate_types(&self) -> &[String] {
        &self.crate_types
    }
    /// Cargo selected check or build mode, excluding test harnesses.
    pub fn mode(&self) -> &str {
        &self.mode
    }
    /// Explicit target platform, or Cargo's host platform.
    pub fn platform(&self) -> Option<&str> {
        self.platform.as_deref()
    }
    /// Sorted selected Cargo features.
    pub fn features(&self) -> &[String] {
        &self.features
    }
}

impl CompilationUnitGraph {
    /// Sorted, deduplicated compiler source paths for captured-root validation.
    /// These retain Cargo's exact spelling; no host or namespace rewriting occurs.
    #[must_use]
    pub fn source_paths(&self) -> &[String] {
        &self.source_paths
    }

    /// Selected ordinary library compilations, retaining distinct features,
    /// modes and target platforms even when several units share one source.
    pub fn library_units(&self) -> &[CompilationLibraryUnit] {
        &self.library_units
    }

    /// Project code can run while Cargo compiles this graph. A cache endpoint
    /// visible to that code must not accept local wrapper-completion claims;
    /// only independently supervised closed worker executions may supply hits.
    #[must_use]
    pub fn requires_closed_dependency_execution(&self) -> bool {
        self.project_executors
    }

    /// Cargo selected documentation tests, so execution must bind the captured
    /// rustdoc executable as well as Cargo and rustc. This is a tool requirement,
    /// not permission to reuse a previously observed documentation-test result.
    #[must_use]
    pub fn contains_doctests(&self) -> bool {
        self.doctests
    }
}

fn invalid(reason: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, reason.into())
}

fn require(condition: bool, reason: &str) -> io::Result<()> {
    if condition {
        Ok(())
    } else {
        Err(invalid(reason))
    }
}

fn text<'a>(value: &'a Value, field: &str) -> io::Result<&'a str> {
    value
        .as_str()
        .filter(|value| {
            !value.is_empty() && value.len() <= MAX_TEXT && !value.chars().any(char::is_control)
        })
        .ok_or_else(|| invalid(format!("invalid Cargo unit graph {field}")))
}

fn optional_bool(object: &Value, field: &str) -> io::Result<()> {
    if let Some(value) = object.get(field) {
        require(value.is_boolean(), "invalid Cargo unit graph boolean")?;
    }
    Ok(())
}

fn ordinary_absolute(path: &str) -> bool {
    path.starts_with('/')
        && path.len() > 1
        && !path.contains('\\')
        && path
            .split('/')
            .skip(1)
            .all(|part| !matches!(part, "" | "." | ".."))
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum TargetClass {
    Ordinary,
    BuildScript,
    ProcMacro,
}

fn target_source(unit: &Value) -> io::Result<(&str, TargetClass)> {
    let target = &unit["target"];
    require(target.is_object(), "Cargo unit target is missing")?;
    text(&target["name"], "target name")?;
    let source = text(&target["src_path"], "target source path")?;
    require(
        ordinary_absolute(source),
        "Cargo unit source path must be normalized and absolute",
    )?;
    for field in ["kind", "crate_types"] {
        let kinds = target[field]
            .as_array()
            .filter(|kinds| !kinds.is_empty() && kinds.len() <= 8)
            .ok_or_else(|| invalid("Cargo unit target kinds are missing or excessive"))?;
        let mut seen = BTreeSet::new();
        for kind in kinds {
            let kind = text(kind, "target kind")?;
            let allowed = LIBRARY_TYPES.contains(&kind)
                || kind == "bin"
                || kind == "proc-macro"
                || (field == "kind"
                    && matches!(kind, "example" | "test" | "bench" | "custom-build"));
            require(allowed, "unknown Cargo unit target kind or crate type")?;
            require(seen.insert(kind), "duplicate Cargo unit target kind")?;
        }
    }
    for field in ["doc", "doctest", "test"] {
        optional_bool(target, field)?;
    }
    let kinds = target["kind"].as_array().expect("validated target kinds");
    let crate_types = target["crate_types"]
        .as_array()
        .expect("validated crate types");
    let contains = |values: &[Value], kind: &str| values.iter().any(|value| value == kind);
    let exact = |values: &[Value], kind: &str| values.len() == 1 && values[0] == kind;
    let class = if contains(kinds, "custom-build") {
        require(
            exact(kinds, "custom-build") && exact(crate_types, "bin"),
            "Cargo build-script targets require exactly custom-build kind and bin crate type",
        )?;
        TargetClass::BuildScript
    } else if contains(kinds, "proc-macro") || contains(crate_types, "proc-macro") {
        require(
            exact(kinds, "proc-macro") && exact(crate_types, "proc-macro"),
            "Cargo procedural-macro targets require matching exclusive kind and crate type",
        )?;
        TargetClass::ProcMacro
    } else {
        TargetClass::Ordinary
    };
    Ok((source, class))
}

fn index(value: &Value, units: usize) -> io::Result<usize> {
    value
        .as_u64()
        .and_then(|index| usize::try_from(index).ok())
        .filter(|index| *index < units)
        .ok_or_else(|| invalid("Cargo unit graph index is absent or outside its units"))
}

/// Validate a version-1 Cargo compilation graph for a selected command.
///
/// All nodes are validated, including any node not reachable from a selected
/// root. Unreachable nodes, cycles, invalid dependency references and unknown
/// execution modes refuse the whole graph. Merely omitting a dangerous node
/// from `roots` therefore cannot make it an admitted compilation graph.
/// `Build` may contain `test` units: `cargo build --tests` compiles those harnesses
/// without running them. The same mode is refused for `Check`. The caller must
/// bind this command to both its trusted Cargo graph query and final invocation;
/// a graph from `cargo test` never establishes compile-only execution authority.
/// `Test` additionally admits `doctest` units and marks the entire operation as
/// executing project code, including a `--no-run` selection. The command's
/// no-run behavior remains Cargo's responsibility; it cannot restore local
/// compiler-result authority through a graph that happens to have no executors.
///
/// The parser deliberately does not reconstruct Cargo's feature resolver or
/// package selection from `cargo metadata`. Multiple units for the same package
/// are normal, and retained source paths must be checked by the caller against
/// the actual captured source/Cargo-home mounts before execution.
/// `run-custom-build` requires a custom-build binary target and a dependency on
/// that same package's compiled build script. Build-script and procedural-macro
/// units require the caller to disable local compiler-result authority for the
/// entire operation via [`CompilationUnitGraph::requires_closed_dependency_execution`].
///
/// # Errors
/// Returns `InvalidInput` for malformed, excessive or unsupported graphs, or
/// for any selected execution mode outside the chosen Cargo compilation command.
/// This is an execution eligibility check only, never a
/// result-publication or compiler-skip authorization.
pub fn validate_compilation_unit_graph(
    graph: &Value,
    command: CompilationCommand,
) -> io::Result<CompilationUnitGraph> {
    require(
        graph["version"].as_u64() == Some(1),
        "unsupported Cargo unit graph version",
    )?;
    let units = graph["units"]
        .as_array()
        .filter(|units| !units.is_empty() && units.len() <= MAX_UNITS)
        .ok_or_else(|| invalid("Cargo unit graph has no units or exceeds its bound"))?;
    let roots = graph["roots"]
        .as_array()
        .filter(|roots| !roots.is_empty() && roots.len() <= units.len())
        .ok_or_else(|| invalid("Cargo unit graph has no roots or exceeds its bound"))?;
    let mut selected = BTreeSet::new();
    for root in roots {
        require(
            selected.insert(index(root, units.len())?),
            "duplicate Cargo unit graph root",
        )?;
    }

    let mut packages = BTreeSet::new();
    let mut source_paths = BTreeSet::new();
    let mut library_units = BTreeSet::new();
    let mut project_executors = command == CompilationCommand::Test;
    let mut doctests = false;
    let mut dependencies = Vec::with_capacity(units.len());
    let mut dependency_count = 0_usize;
    for (unit_index, unit) in units.iter().enumerate() {
        require(unit.is_object(), "Cargo graph unit is not an object")?;
        packages.insert(text(&unit["pkg_id"], "package identity")?);
        let mode = text(&unit["mode"], "unit mode")?;
        let (source, class) = target_source(unit)?;
        let allowed_mode = match class {
            // Running a build script is part of compilation, but the same
            // mode on an ordinary binary cannot authorize program execution.
            TargetClass::BuildScript => matches!(mode, "build" | "run-custom-build"),
            TargetClass::Ordinary | TargetClass::ProcMacro => match command {
                CompilationCommand::Check => matches!(mode, "check" | "build"),
                CompilationCommand::Build => matches!(mode, "build" | "test"),
                CompilationCommand::Test => matches!(mode, "build" | "test" | "doctest"),
            },
        };
        require(
            allowed_mode,
            "selected Cargo compilation contains an unsupported execution mode for its command",
        )?;
        if mode == "doctest" {
            // Cargo's documentation tests operate on library targets, including
            // procedural macro libraries. A binary/test/example source cannot
            // borrow this mode to select an unrelated rustdoc command.
            let kinds = unit["target"]["kind"]
                .as_array()
                .expect("validated target kinds");
            require(
                kinds.iter().all(|kind| {
                    kind.as_str()
                        .is_some_and(|kind| LIBRARY_TYPES.contains(&kind) || kind == "proc-macro")
                }),
                "Cargo doctest mode requires a library target",
            )?;
            doctests = true;
        }
        project_executors |= class != TargetClass::Ordinary;
        source_paths.insert(source.to_owned());
        require(unit["profile"].is_object(), "Cargo unit profile is missing")?;
        match unit.get("platform") {
            Some(Value::Null) => {}
            Some(platform) => {
                text(platform, "unit platform")?;
            }
            None => return Err(invalid("Cargo unit platform is missing")),
        }
        optional_bool(unit, "is_std")?;
        require(
            unit.get("is_std").and_then(Value::as_bool) != Some(true),
            "building the standard library is outside the captured compilation profile",
        )?;
        let features = unit["features"]
            .as_array()
            .filter(|features| features.len() <= MAX_FEATURES)
            .ok_or_else(|| invalid("Cargo unit features are missing or excessive"))?;
        let mut feature_names = BTreeSet::new();
        for feature in features {
            require(
                feature_names.insert(text(feature, "unit feature")?),
                "duplicate Cargo unit feature",
            )?;
        }
        let crate_types = unit["target"]["crate_types"]
            .as_array()
            .expect("validated crate types");
        let target_kinds = unit["target"]["kind"]
            .as_array()
            .expect("validated target kinds");
        if class == TargetClass::Ordinary
            && matches!(mode, "check" | "build")
            && crate_types
                .iter()
                .all(|kind| matches!(kind.as_str(), Some("lib" | "rlib")))
            && target_kinds
                .iter()
                .all(|kind| matches!(kind.as_str(), Some("lib" | "rlib")))
        {
            let mut crate_types = crate_types
                .iter()
                .map(|kind| kind.as_str().unwrap().to_owned())
                .collect::<Vec<_>>();
            crate_types.sort();
            library_units.insert(CompilationLibraryUnit {
                package_id: text(&unit["pkg_id"], "package identity")?.to_owned(),
                source_path: source.to_owned(),
                crate_name: text(&unit["target"]["name"], "target name")?.replace('-', "_"),
                crate_types,
                mode: mode.to_owned(),
                platform: unit["platform"].as_str().map(str::to_owned),
                features: feature_names.into_iter().map(str::to_owned).collect(),
            });
        }
        let edges = unit["dependencies"]
            .as_array()
            .filter(|edges| edges.len() <= MAX_UNITS)
            .ok_or_else(|| invalid("Cargo unit dependencies are missing or excessive"))?;
        dependency_count = dependency_count
            .checked_add(edges.len())
            .filter(|total| *total <= MAX_DEPENDENCIES)
            .ok_or_else(|| invalid("Cargo unit graph exceeds its dependency bound"))?;
        let mut seen = BTreeSet::new();
        let mut next = Vec::with_capacity(edges.len());
        for dependency in edges {
            let target = index(&dependency["index"], units.len())?;
            require(target != unit_index, "Cargo unit depends on itself")?;
            let name = text(&dependency["extern_crate_name"], "dependency crate name")?;
            require(
                seen.insert((target, name)),
                "duplicate Cargo unit dependency",
            )?;
            for field in ["public", "noprelude"] {
                optional_bool(dependency, field)?;
            }
            next.push(target);
        }
        dependencies.push(next);
    }
    for (unit_index, unit) in units.iter().enumerate() {
        if unit["mode"] == "run-custom-build" {
            let producers = dependencies[unit_index]
                .iter()
                .filter(|&&dependency| {
                    let producer = &units[dependency];
                    producer["mode"] == "build"
                        && producer["pkg_id"] == unit["pkg_id"]
                        && producer["target"] == unit["target"]
                })
                .count();
            require(
                producers == 1,
                "Cargo build-script execution must depend on its matching compiled build script",
            )?;
        }
    }
    validate_reachability(&dependencies, &selected)?;
    Ok(CompilationUnitGraph {
        units: units.len(),
        packages: packages.len(),
        roots: selected.len(),
        source_paths: source_paths.into_iter().collect(),
        library_units: library_units.into_iter().collect(),
        project_executors,
        doctests,
    })
}

/// Iterative depth-first traversal: bounded graphs must not consume the native
/// call stack, and a back edge must not turn reachability into an infinite walk.
fn validate_reachability(dependencies: &[Vec<usize>], roots: &BTreeSet<usize>) -> io::Result<()> {
    let mut colors = vec![0_u8; dependencies.len()];
    let mut visited = 0;
    let mut stack = Vec::new();
    for &root in roots {
        if colors[root] == 2 {
            continue;
        }
        colors[root] = 1;
        stack.push((root, 0_usize));
        while let Some((unit, next)) = stack.last_mut() {
            if *next == dependencies[*unit].len() {
                colors[*unit] = 2;
                visited += 1;
                stack.pop();
                continue;
            }
            let dependency = dependencies[*unit][*next];
            *next += 1;
            match colors[dependency] {
                0 => {
                    colors[dependency] = 1;
                    stack.push((dependency, 0));
                }
                1 => return Err(invalid("Cargo unit graph contains a dependency cycle")),
                _ => {}
            }
        }
    }
    require(
        visited == dependencies.len(),
        "Cargo unit graph contains units unreachable from its selected roots",
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn unit(name: &str, dependencies: &[usize]) -> Value {
        json!({
            "pkg_id":format!("path+file:///__rabs/workspace/{name}#{name}@0.1.0"),
            "target":{"kind":["lib"], "crate_types":["lib"], "name":name,
                "src_path":format!("/__rabs/workspace/{name}/src/lib.rs"),
                "edition":"2024", "doc":true, "doctest":true, "test":true},
            "profile":{"name":"dev"}, "platform":null, "mode":"check", "features":[],
            "dependencies":dependencies.iter().map(|index| json!({"index":index,
                "extern_crate_name":format!("dependency_{index}"), "public":false,
                "noprelude":false})).collect::<Vec<_>>()
        })
    }

    fn graph() -> Value {
        json!({"version":1, "units":[unit("app", &[1]),unit("dependency", &[])],
            "roots":[0]})
    }

    #[test]
    fn selected_compiler_graph_retains_unique_source_paths_and_counts() {
        let report = validate_compilation_unit_graph(&graph(), CompilationCommand::Check).unwrap();
        assert_eq!((report.units, report.packages, report.roots), (2, 2, 1));
        assert!(!report.requires_closed_dependency_execution());
        assert!(!report.contains_doctests());
        assert_eq!(
            report.source_paths(),
            [
                "/__rabs/workspace/app/src/lib.rs",
                "/__rabs/workspace/dependency/src/lib.rs"
            ]
        );
    }

    #[test]
    fn multiple_compiler_units_for_a_package_are_not_merged() {
        let mut graph = graph();
        graph["units"][1] = graph["units"][0].clone();
        graph["units"][1]["mode"] = json!("build");
        graph["units"][1]["dependencies"] = json!([]);
        graph["units"][1]["features"] = json!(["extra"]);
        graph["units"][1]["platform"] = json!("x86_64-unknown-linux-gnu");
        let report = validate_compilation_unit_graph(&graph, CompilationCommand::Check).unwrap();
        assert_eq!((report.units, report.packages, report.roots), (2, 1, 1));
        assert_eq!(report.source_paths().len(), 1);
        assert_eq!(report.library_units().len(), 2);
        assert_ne!(
            report.library_units()[0].mode(),
            report.library_units()[1].mode()
        );
        assert_ne!(
            report.library_units()[0].features(),
            report.library_units()[1].features()
        );
    }

    #[test]
    fn workspace_execution_membership_retains_only_selected_ordinary_libraries() {
        let mut selected = graph();
        selected["units"][0]["target"]["name"] = json!("project-library");
        selected["units"][0]["features"] = json!(["z-last", "a-first"]);
        let report = validate_compilation_unit_graph(&selected, CompilationCommand::Check).unwrap();
        let unit = report
            .library_units()
            .iter()
            .find(|unit| unit.crate_name() == "project_library")
            .unwrap();
        assert_eq!(unit.source_path(), "/__rabs/workspace/app/src/lib.rs");
        assert_eq!(unit.features(), ["a-first", "z-last"]);
        assert_eq!(unit.crate_types(), ["lib"]);
        for (kind, crate_type, mode) in [
            ("bin", "bin", "build"),
            ("proc-macro", "proc-macro", "build"),
            ("custom-build", "bin", "build"),
            ("lib", "lib", "test"),
            ("lib", "cdylib", "build"),
        ] {
            let mut excluded = graph();
            excluded["units"][0]["target"]["kind"] = json!([kind]);
            excluded["units"][0]["target"]["crate_types"] = json!([crate_type]);
            excluded["units"][0]["mode"] = json!(mode);
            excluded["units"][1]["mode"] = json!("build");
            let report =
                validate_compilation_unit_graph(&excluded, CompilationCommand::Build).unwrap();
            assert_eq!(
                report.library_units().len(),
                1,
                "{kind}/{crate_type}/{mode}"
            );
            assert_eq!(report.library_units()[0].crate_name(), "dependency");
        }
    }

    #[test]
    fn check_targets_may_be_binaries_tests_examples_or_library_artifacts() {
        for (kind, crate_type) in [
            ("bin", "bin"),
            ("test", "bin"),
            ("bench", "bin"),
            ("example", "rlib"),
            ("cdylib", "cdylib"),
            ("staticlib", "staticlib"),
            ("dylib", "dylib"),
        ] {
            let mut graph = graph();
            graph["units"][0]["target"]["kind"] = json!([kind]);
            graph["units"][0]["target"]["crate_types"] = json!([crate_type]);
            validate_compilation_unit_graph(&graph, CompilationCommand::Check).unwrap();
        }
    }

    #[test]
    fn inconsistent_executor_targets_and_unknown_execution_modes_refuse() {
        for field in ["kind", "crate_types"] {
            for kind in ["custom-build", "proc-macro", "future-target"] {
                let mut graph = graph();
                graph["units"][1]["target"][field] = json!([kind]);
                assert!(
                    validate_compilation_unit_graph(&graph, CompilationCommand::Check).is_err(),
                    "{field}: {kind}"
                );
            }
        }
        for mode in [
            "run-custom-build",
            "doc",
            "doctest",
            "test",
            "future-mode",
            "",
        ] {
            let mut graph = graph();
            graph["units"][1]["mode"] = json!(mode);
            assert!(
                validate_compilation_unit_graph(&graph, CompilationCommand::Check).is_err(),
                "{mode}"
            );
        }
        let mut graph = graph();
        graph["units"][0]["is_std"] = json!(true);
        assert!(validate_compilation_unit_graph(&graph, CompilationCommand::Check).is_err());
    }

    fn script_graph(command: CompilationCommand) -> Value {
        let mut app = unit("app", &[1]);
        app["mode"] = json!(command.as_str());
        let mut compiled = unit("generator", &[]);
        compiled["mode"] = json!("build");
        compiled["target"]["kind"] = json!(["custom-build"]);
        compiled["target"]["crate_types"] = json!(["bin"]);
        compiled["target"]["name"] = json!("build-script-build");
        compiled["target"]["src_path"] = json!("/__rabs/workspace/generator/build.rs");
        let mut run = compiled.clone();
        run["mode"] = json!("run-custom-build");
        run["dependencies"] = json!([{"index":2,"extern_crate_name":"build_script_build"}]);
        json!({"version":1,"units":[app,run,compiled],"roots":[0]})
    }

    #[test]
    fn admitted_project_executors_require_closed_dependency_execution_for_the_whole_graph() {
        for command in [
            CompilationCommand::Check,
            CompilationCommand::Build,
            CompilationCommand::Test,
        ] {
            let graph = script_graph(command);
            let report = validate_compilation_unit_graph(&graph, command).unwrap();
            assert!(report.requires_closed_dependency_execution());
            assert_eq!((report.units, report.packages, report.roots), (3, 2, 1));
            assert_eq!(report.source_paths().len(), 2);

            let mut macros = graph;
            macros["units"].as_array_mut().unwrap().pop();
            macros["units"][1]["mode"] = json!("build");
            macros["units"][1]["dependencies"] = json!([]);
            macros["units"][1]["target"]["kind"] = json!(["proc-macro"]);
            macros["units"][1]["target"]["crate_types"] = json!(["proc-macro"]);
            let report = validate_compilation_unit_graph(&macros, command).unwrap();
            assert!(report.requires_closed_dependency_execution());
        }
    }

    #[test]
    fn build_script_execution_requires_its_exact_compiled_producer() {
        for command in [
            CompilationCommand::Check,
            CompilationCommand::Build,
            CompilationCommand::Test,
        ] {
            for mutation in [
                "no-producer",
                "package",
                "source",
                "target-name",
                "producer-mode",
            ] {
                let mut graph = script_graph(command);
                match mutation {
                    "no-producer" => graph["units"][1]["dependencies"] = json!([]),
                    "package" => graph["units"][2]["pkg_id"] = json!("different-package"),
                    "source" => {
                        graph["units"][2]["target"]["src_path"] =
                            json!("/__rabs/workspace/generator/other.rs")
                    }
                    "target-name" => graph["units"][2]["target"]["name"] = json!("other-script"),
                    "producer-mode" => graph["units"][2]["mode"] = json!("check"),
                    _ => unreachable!(),
                }
                assert!(
                    validate_compilation_unit_graph(&graph, command).is_err(),
                    "{mutation}"
                );
            }
            for mode in ["check", "test", "run", "doc", "doctest"] {
                let mut graph = script_graph(command);
                graph["units"][1]["mode"] = json!(mode);
                assert!(
                    validate_compilation_unit_graph(&graph, command).is_err(),
                    "{mode}"
                );
            }
        }
    }

    #[test]
    fn invalid_versions_roots_indices_and_edges_are_refused() {
        for version in [json!(0), json!(2), json!("1"), Value::Null] {
            let mut graph = graph();
            graph["version"] = version;
            assert!(validate_compilation_unit_graph(&graph, CompilationCommand::Check).is_err());
        }
        for roots in [
            json!([]),
            json!([0, 0]),
            json!([2]),
            json!([-1]),
            json!(["0"]),
        ] {
            let mut graph = graph();
            graph["roots"] = roots;
            assert!(validate_compilation_unit_graph(&graph, CompilationCommand::Check).is_err());
        }
        for index in [
            json!(0),
            json!(2),
            json!(-1),
            json!(1.5),
            json!("1"),
            Value::Null,
        ] {
            let mut graph = graph();
            graph["units"][0]["dependencies"][0]["index"] = index;
            assert!(validate_compilation_unit_graph(&graph, CompilationCommand::Check).is_err());
        }
        let mut graph = graph();
        let edge = graph["units"][0]["dependencies"][0].clone();
        graph["units"][0]["dependencies"] = json!([edge.clone(), edge]);
        assert!(validate_compilation_unit_graph(&graph, CompilationCommand::Check).is_err());
    }

    #[test]
    fn cycles_and_dangling_units_cannot_hide_outside_selected_roots() {
        let mut cyclic = graph();
        cyclic["units"][1] = unit("dependency", &[0]);
        assert!(
            validate_compilation_unit_graph(&cyclic, CompilationCommand::Check)
                .unwrap_err()
                .to_string()
                .contains("cycle")
        );
        let mut dangling = graph();
        dangling["units"][0]["dependencies"] = json!([]);
        assert!(
            validate_compilation_unit_graph(&dangling, CompilationCommand::Check)
                .unwrap_err()
                .to_string()
                .contains("unreachable")
        );
        dangling["units"][1]["target"]["kind"] = json!(["proc-macro"]);
        assert!(validate_compilation_unit_graph(&dangling, CompilationCommand::Check).is_err());
        dangling["units"][1] = unit("dependency", &[]);
        dangling["roots"] = json!([0, 1]);
        assert_eq!(
            validate_compilation_unit_graph(&dangling, CompilationCommand::Check)
                .unwrap()
                .roots,
            2
        );
    }

    #[test]
    fn malformed_unit_surfaces_and_non_normalized_sources_are_refused() {
        for field in [
            "pkg_id",
            "target",
            "profile",
            "platform",
            "features",
            "dependencies",
        ] {
            let mut graph = graph();
            graph["units"][0].as_object_mut().unwrap().remove(field);
            assert!(
                validate_compilation_unit_graph(&graph, CompilationCommand::Check).is_err(),
                "{field}"
            );
        }
        for source in [
            "src/lib.rs",
            "/",
            "/source/../lib.rs",
            "/source//lib.rs",
            "/source/./lib.rs",
            "/source/lib.rs/",
            "/source\\lib.rs",
            "/source/\nlib.rs",
        ] {
            let mut graph = graph();
            graph["units"][0]["target"]["src_path"] = json!(source);
            assert!(
                validate_compilation_unit_graph(&graph, CompilationCommand::Check).is_err(),
                "{source:?}"
            );
        }
        let mut graph = graph();
        graph["units"][0]["features"] = json!(["duplicate", "duplicate"]);
        assert!(validate_compilation_unit_graph(&graph, CompilationCommand::Check).is_err());
        graph["units"][0]["features"] = json!([]);
        graph["units"][0]["target"]["test"] = json!("true");
        assert!(validate_compilation_unit_graph(&graph, CompilationCommand::Check).is_err());
    }

    #[test]
    fn deep_graph_walk_is_bounded_without_recursion() {
        let units = (0..MAX_UNITS)
            .map(|index| {
                if index + 1 < MAX_UNITS {
                    unit(&format!("p{index}"), &[index + 1])
                } else {
                    unit(&format!("p{index}"), &[])
                }
            })
            .collect::<Vec<_>>();
        let mut graph = json!({"version":1, "units":units, "roots":[0]});
        assert_eq!(
            validate_compilation_unit_graph(&graph, CompilationCommand::Check)
                .unwrap()
                .units,
            MAX_UNITS
        );
        graph["units"]
            .as_array_mut()
            .unwrap()
            .push(unit("excessive", &[]));
        assert!(validate_compilation_unit_graph(&graph, CompilationCommand::Check).is_err());
    }

    #[test]
    fn build_graphs_admit_compiled_test_harnesses_only_under_build_authority() {
        let mut graph = graph();
        graph["units"][0]["mode"] = json!("test");
        graph["units"][0]["target"]["kind"] = json!(["test"]);
        graph["units"][0]["target"]["crate_types"] = json!(["bin"]);
        graph["units"][1]["mode"] = json!("build");
        let report = validate_compilation_unit_graph(&graph, CompilationCommand::Build).unwrap();
        assert_eq!((report.units, report.packages, report.roots), (2, 2, 1));
        assert!(validate_compilation_unit_graph(&graph, CompilationCommand::Check).is_err());
        graph["units"][0]["mode"] = json!("build");
        validate_compilation_unit_graph(&graph, CompilationCommand::Build).unwrap();
        for mode in [
            "check",
            "run",
            "doc",
            "doctest",
            "run-custom-build",
            "future-mode",
        ] {
            graph["units"][0]["mode"] = json!(mode);
            assert!(
                validate_compilation_unit_graph(&graph, CompilationCommand::Build).is_err(),
                "{mode}"
            );
        }
        graph["units"][0]["mode"] = json!("build");
        for kind in ["proc-macro", "custom-build"] {
            for field in ["kind", "crate_types"] {
                let mut rejected = graph.clone();
                rejected["units"][1]["target"][field] = json!([kind]);
                assert!(
                    validate_compilation_unit_graph(&rejected, CompilationCommand::Build).is_err(),
                    "{kind}: {field}"
                );
            }
        }
    }

    #[test]
    fn test_graphs_require_closed_cache_authority_even_without_build_scripts_or_macros() {
        let mut graph = graph();
        graph["units"][1]["mode"] = json!("build");
        for mode in ["build", "test"] {
            graph["units"][0]["mode"] = json!(mode);
            let report = validate_compilation_unit_graph(&graph, CompilationCommand::Test).unwrap();
            assert!(report.requires_closed_dependency_execution());
            assert!(!report.contains_doctests());
            // The identical compile graph under cargo build does not authorize
            // test execution and therefore retains its previous local policy.
            let build = validate_compilation_unit_graph(&graph, CompilationCommand::Build).unwrap();
            assert!(!build.requires_closed_dependency_execution());
        }
    }

    #[test]
    fn doctests_require_test_command_and_report_captured_rustdoc_requirement() {
        let mut graph = graph();
        graph["units"][0]["mode"] = json!("doctest");
        graph["units"][1]["mode"] = json!("build");
        for kind in ["lib", "rlib", "proc-macro"] {
            graph["units"][0]["target"]["kind"] = json!([kind]);
            graph["units"][0]["target"]["crate_types"] = json!([kind]);
            let report = validate_compilation_unit_graph(&graph, CompilationCommand::Test).unwrap();
            assert!(report.contains_doctests());
            assert!(report.requires_closed_dependency_execution());
            assert_eq!((report.units, report.packages, report.roots), (2, 2, 1));
            for command in [CompilationCommand::Check, CompilationCommand::Build] {
                assert!(validate_compilation_unit_graph(&graph, command).is_err());
            }
        }
        for kind in ["bin", "example", "test", "bench", "custom-build"] {
            graph["units"][0]["target"]["kind"] = json!([kind]);
            graph["units"][0]["target"]["crate_types"] = json!(["bin"]);
            assert!(validate_compilation_unit_graph(&graph, CompilationCommand::Test).is_err());
        }
    }

    #[test]
    fn test_command_never_admits_unrelated_program_or_documentation_modes() {
        let mut graph = graph();
        graph["units"][1]["mode"] = json!("build");
        for mode in ["check", "run", "doc", "run-custom-build", "future-mode"] {
            graph["units"][0]["mode"] = json!(mode);
            assert!(
                validate_compilation_unit_graph(&graph, CompilationCommand::Test).is_err(),
                "{mode}"
            );
        }
    }
}
