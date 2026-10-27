//! Admission of the units Cargo selected for check, build, Clippy, test, run or bench.
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
//! compiler evidence. Test, run and bench operations require the same boundary
//! because their executables can reach that endpoint too. Unknown modes remain
//! refused; program, test and benchmark outcomes are not cached.

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

/// Resolve the compilation target of `cargo run` without running a program.
///
/// Cargo's run command cannot reliably emit a unit graph: the pinned Cargo
/// attempts to retrieve an executable after its graph-only compiler returns.
/// The driver instead asks Cargo metadata for the selected workspace's default
/// members and default-run declarations, then queries `cargo build` for the
/// exact binary/example. The final command remains the user's original run.
/// An explicit package spec is resolved by the captured `cargo pkgid`, supplied
/// here as `package_id`; this function does not approximate Cargo's spec parser.
/// Named bin/example selectors are already exact Cargo selectors and need no
/// metadata resolution. The subsequent graph must have one runnable root.
pub fn run_build_selection(
    selection: &CompilationSelection,
    metadata: &Value,
    package_id: Option<&str>,
) -> io::Result<CompilationSelection> {
    selection.cargo_arguments(CompilationCommand::Run)?;
    let mut compilation = selection.clone();
    compilation.run_args.clear();
    if !selection.bin.is_empty() || !selection.example.is_empty() {
        return Ok(compilation);
    }
    require(
        metadata["version"].as_u64() == Some(1),
        "unsupported Cargo metadata version",
    )?;
    let packages = metadata["packages"]
        .as_array()
        .filter(|packages| packages.len() <= MAX_UNITS)
        .ok_or_else(|| invalid("Cargo metadata packages are missing or excessive"))?;
    require(
        selection.packages.is_empty() == package_id.is_none(),
        "run package selection requires its captured Cargo pkgid result",
    )?;
    let selected = if let Some(package) = package_id {
        vec![package]
    } else {
        metadata["workspace_default_members"]
            .as_array()
            .filter(|members| !members.is_empty() && members.len() <= MAX_UNITS)
            .ok_or_else(|| invalid("Cargo metadata has no bounded default members"))?
            .iter()
            .map(|id| text(id, "default package identity"))
            .collect::<io::Result<Vec<_>>>()?
    };
    let mut bins = Vec::new();
    let mut defaults = Vec::new();
    let mut selected_ids = BTreeSet::new();
    for id in selected {
        require(
            selected_ids.insert(id),
            "duplicate default package identity",
        )?;
        let matching = packages
            .iter()
            .filter(|package| package["id"] == id)
            .collect::<Vec<_>>();
        require(
            matching.len() == 1,
            "selected run package is not a unique captured workspace member",
        )?;
        let package = matching[0];
        if !package["default_run"].is_null() {
            defaults.push(text(&package["default_run"], "default-run target")?);
        }
        let targets = package["targets"]
            .as_array()
            .filter(|targets| targets.len() <= MAX_UNITS)
            .ok_or_else(|| invalid("Cargo package targets are missing or excessive"))?;
        for target in targets {
            if target["kind"] == serde_json::json!(["bin"]) {
                bins.push(text(&target["name"], "binary target")?);
            }
        }
    }
    // Cargo selects a unique default-run across the selected packages. With
    // zero or several defaults it requires a unique binary instead; packages
    // without binaries do not make an otherwise unambiguous run ambiguous.
    let name = if defaults.len() == 1 {
        defaults[0]
    } else if bins.len() == 1 {
        bins[0]
    } else {
        return Err(invalid(
            "cargo run cannot determine one binary; select --bin/--example or set one default-run",
        ));
    };
    require(
        bins.iter().filter(|bin| **bin == name).count() == 1,
        "cargo run selected an absent or ambiguous binary; specify its package and --bin",
    )?;
    compilation.bin.push(name.to_owned());
    Ok(compilation)
}

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
    workspace_units: Vec<CompilationUnit>,
    project_executors: bool,
    doctests: bool,
}

/// One ordinary compilation selected by the captured Cargo graph.
/// The driver must bind its source to retained mounts before using it to admit
/// workspace execution. This record never grants result-cache authority.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct CompilationUnit {
    package_id: String,
    source_path: String,
    crate_name: String,
    crate_types: Vec<String>,
    target_kinds: Vec<String>,
    mode: String,
    platform: Option<String>,
    features: Vec<String>,
    is_root: bool,
    testable: bool,
    multiple_check_roots: bool,
}

impl CompilationUnit {
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
    /// Selected ordinary Rust output kinds, before any test-harness override.
    pub fn crate_types(&self) -> &[String] {
        &self.crate_types
    }
    /// Cargo target kinds, including binary, example, integration test or bench.
    pub fn target_kinds(&self) -> &[String] {
        &self.target_kinds
    }
    /// Cargo selected check or build mode; executable test mode is excluded.
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
    /// The selected command named this unit as a root rather than only as a prerequisite.
    pub fn is_root(&self) -> bool {
        self.is_root
    }
    /// Cargo's target test eligibility, not proof that this check uses `--test`.
    pub fn testable(&self) -> bool {
        self.testable
    }
    /// Distinct selected check roots share this family, target and profile.
    /// Cargo omits Check's harness discriminator from JSON; retain multiplicity
    /// before deduplication without claiming which root uses `--test`.
    pub fn has_multiple_check_roots(&self) -> bool {
        self.multiple_check_roots
    }
}

impl CompilationUnitGraph {
    /// Sorted, deduplicated compiler source paths for captured-root validation.
    /// These retain Cargo's exact spelling; no host or namespace rewriting occurs.
    #[must_use]
    pub fn source_paths(&self) -> &[String] {
        &self.source_paths
    }

    /// Selected ordinary library compiles and metadata-only checks of binaries,
    /// examples, integration tests and benches. Distinct features, modes,
    /// target platforms and root membership remain separate records.
    pub fn workspace_units(&self) -> &[CompilationUnit] {
        &self.workspace_units
    }

    /// Project code or a lint driver can run while Cargo compiles this graph. A cache endpoint
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
/// `Test` additionally admits `doctest` units. `Bench` uses build/test units;
/// `Run` requires the build graph of exactly one binary/example. All three mark
/// the entire operation as executing project code, including a `--no-run` selection. The command's
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
    if command == CompilationCommand::Run {
        require(
            selected.len() == 1,
            "cargo run requires exactly one runnable graph root",
        )?;
        let root = &units[*selected.first().expect("validated nonempty roots")];
        require(
            root["mode"] == "build"
                && matches!(root["target"]["kind"].as_array().map(Vec::as_slice),
                Some([kind]) if kind == "bin" || kind == "example")
                && root["target"]["crate_types"] == serde_json::json!(["bin"]),
            "cargo run graph root must be its selected binary or executable example",
        )?;
    }

    let mut packages = BTreeSet::new();
    let mut source_paths = BTreeSet::new();
    let mut workspace_units = BTreeSet::new();
    let mut check_roots = BTreeSet::new();
    let mut multiple_check_roots = BTreeSet::new();
    // A lint driver is not rustc: it can inspect captured configuration beyond
    // compiler dep-info and must never acquire local rustc-result authority.
    let mut project_executors = matches!(
        command,
        CompilationCommand::Test
            | CompilationCommand::Clippy
            | CompilationCommand::Run
            | CompilationCommand::Bench
    );
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
                CompilationCommand::Check | CompilationCommand::Clippy => {
                    matches!(mode, "check" | "build")
                }
                CompilationCommand::Build | CompilationCommand::Bench => {
                    matches!(mode, "build" | "test")
                }
                CompilationCommand::Test => matches!(mode, "build" | "test" | "doctest"),
                CompilationCommand::Run => mode == "build",
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
        let ordinary_library = crate_types
            .iter()
            .all(|kind| matches!(kind.as_str(), Some("lib" | "rlib")))
            && target_kinds
                .iter()
                .all(|kind| matches!(kind.as_str(), Some("lib" | "rlib")));
        let metadata_target = mode == "check"
            && crate_types
                .iter()
                .all(|kind| matches!(kind.as_str(), Some("lib" | "rlib" | "bin")))
            && target_kinds.iter().all(|kind| {
                matches!(
                    kind.as_str(),
                    Some("lib" | "rlib" | "bin" | "example" | "test" | "bench")
                )
            });
        if class == TargetClass::Ordinary
            && ((ordinary_library && matches!(mode, "check" | "build")) || metadata_target)
        {
            let mut crate_types = crate_types
                .iter()
                .map(|kind| kind.as_str().unwrap().to_owned())
                .collect::<Vec<_>>();
            crate_types.sort();
            let mut target_kinds = target_kinds
                .iter()
                .map(|kind| kind.as_str().unwrap().to_owned())
                .collect::<Vec<_>>();
            target_kinds.sort();
            let compilation = CompilationUnit {
                package_id: text(&unit["pkg_id"], "package identity")?.to_owned(),
                source_path: source.to_owned(),
                crate_name: text(&unit["target"]["name"], "target name")?.replace('-', "_"),
                crate_types,
                target_kinds,
                mode: mode.to_owned(),
                platform: unit["platform"].as_str().map(str::to_owned),
                features: feature_names.into_iter().map(str::to_owned).collect(),
                is_root: selected.contains(&unit_index),
                testable: unit["target"]["test"].as_bool().unwrap_or(false),
                multiple_check_roots: false,
            };
            if compilation.is_root
                && mode == "check"
                && !check_roots.insert((
                    compilation.clone(),
                    unit["target"].to_string(),
                    unit["profile"].to_string(),
                ))
            {
                multiple_check_roots.insert(compilation.clone());
            }
            workspace_units.insert(compilation);
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
        workspace_units: workspace_units
            .into_iter()
            .map(|mut unit| {
                unit.multiple_check_roots = multiple_check_roots.contains(&unit);
                unit
            })
            .collect(),
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
        assert_eq!(report.workspace_units().len(), 2);
        assert_ne!(
            report.workspace_units()[0].mode(),
            report.workspace_units()[1].mode()
        );
        assert_ne!(
            report.workspace_units()[0].features(),
            report.workspace_units()[1].features()
        );
    }

    #[test]
    fn workspace_execution_membership_keeps_library_codegen_and_rejects_other_linking() {
        let mut selected = graph();
        selected["units"][0]["target"]["name"] = json!("project-library");
        selected["units"][0]["features"] = json!(["z-last", "a-first"]);
        let report = validate_compilation_unit_graph(&selected, CompilationCommand::Check).unwrap();
        let unit = report
            .workspace_units()
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
                report.workspace_units().len(),
                1,
                "{kind}/{crate_type}/{mode}"
            );
            assert_eq!(report.workspace_units()[0].crate_name(), "dependency");
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
    fn workspace_metadata_membership_retains_selected_target_kinds_and_root_boundaries() {
        for (kind, crate_type) in [
            ("bin", "bin"),
            ("example", "bin"),
            ("example", "rlib"),
            ("test", "bin"),
            ("bench", "bin"),
        ] {
            let mut graph = graph();
            graph["units"][0]["target"]["kind"] = json!([kind]);
            graph["units"][0]["target"]["crate_types"] = json!([crate_type]);
            graph["units"][0]["target"]["test"] = json!(true);
            let report =
                validate_compilation_unit_graph(&graph, CompilationCommand::Check).unwrap();
            assert_eq!(report.workspace_units().len(), 2, "{kind}/{crate_type}");
            let selected = report
                .workspace_units()
                .iter()
                .find(|unit| unit.is_root())
                .unwrap();
            assert_eq!(selected.source_path(), "/__rabs/workspace/app/src/lib.rs");
            assert_eq!(selected.target_kinds(), [kind]);
            assert_eq!(selected.crate_types(), [crate_type]);
            assert_eq!(selected.mode(), "check");
            assert!(selected.testable());
            let dependency = report
                .workspace_units()
                .iter()
                .find(|unit| !unit.is_root())
                .unwrap();
            assert_eq!(dependency.crate_name(), "dependency");
        }
    }

    #[test]
    fn identical_check_units_keep_root_membership_without_inventing_a_harness_flag() {
        let mut graph = graph();
        graph["units"][1] = graph["units"][0].clone();
        graph["units"][1]["dependencies"] = json!([]);
        let report = validate_compilation_unit_graph(&graph, CompilationCommand::Check).unwrap();
        assert_eq!(report.workspace_units().len(), 2);
        assert_eq!(
            report.workspace_units()[0].source_path(),
            report.workspace_units()[1].source_path()
        );
        assert_ne!(
            report.workspace_units()[0].is_root(),
            report.workspace_units()[1].is_root()
        );
        assert!(
            report
                .workspace_units()
                .iter()
                .all(|unit| !unit.has_multiple_check_roots())
        );
    }

    #[test]
    fn selected_check_family_multiplicity_survives_deduplication_without_merging_profiles() {
        let root = unit("app", &[]);
        let graph = json!({"version":1,"roots":[0,1],"units":[root.clone(),root]});
        let report = validate_compilation_unit_graph(&graph, CompilationCommand::Check).unwrap();
        assert_eq!(report.roots, 2);
        assert_eq!(report.workspace_units().len(), 1);
        assert!(report.workspace_units()[0].has_multiple_check_roots());

        for (field, value) in [
            ("profile", json!({"name":"dev", "debug_assertions":false})),
            ("features", json!(["other"])),
            ("platform", json!("aarch64-unknown-linux-gnu")),
            ("mode", json!("build")),
        ] {
            let mut different = graph.clone();
            different["units"][1][field] = value;
            let report =
                validate_compilation_unit_graph(&different, CompilationCommand::Check).unwrap();
            assert!(
                report
                    .workspace_units()
                    .iter()
                    .all(|unit| !unit.has_multiple_check_roots()),
                "distinct {field} cannot establish a duplicate selected metadata family"
            );
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
        app["mode"] = json!(if command == CompilationCommand::Clippy {
            "check"
        } else {
            command.as_str()
        });
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
            CompilationCommand::Clippy,
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
            CompilationCommand::Clippy,
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
    fn clippy_graphs_never_grant_local_rustc_cache_authority_or_program_execution() {
        let mut graph = graph();
        for mode in ["check", "build"] {
            graph["units"][0]["mode"] = json!(mode);
            let report =
                validate_compilation_unit_graph(&graph, CompilationCommand::Clippy).unwrap();
            assert!(report.requires_closed_dependency_execution());
            assert!(!report.contains_doctests());
            let checked =
                validate_compilation_unit_graph(&graph, CompilationCommand::Check).unwrap();
            assert_eq!(report.workspace_units(), checked.workspace_units());
        }
        for mode in [
            "clippy",
            "test",
            "doctest",
            "run",
            "doc",
            "run-custom-build",
            "future-mode",
        ] {
            graph["units"][0]["mode"] = json!(mode);
            assert!(
                validate_compilation_unit_graph(&graph, CompilationCommand::Clippy).is_err(),
                "{mode}"
            );
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

    #[test]
    fn run_resolves_defaults_and_cargo_package_identity_without_rewriting_runtime_arguments() {
        let metadata = json!({"version":1, "workspace_default_members":["app", "other"],
            "packages":[
                {"id":"app", "default_run":"server", "targets":[
                    {"name":"app", "kind":["lib"]}, {"name":"server", "kind":["bin"]},
                    {"name":"admin", "kind":["bin"]}]},
                {"id":"other", "targets":[{"name":"other", "kind":["bin"]}]}]});
        let mut selection = CompilationSelection {
            features: vec!["app/fast".into()],
            run_args: vec!["--unit-graph".into(), "".into()],
            ..CompilationSelection::default()
        };
        let planned = run_build_selection(&selection, &metadata, None).unwrap();
        assert_eq!(planned.bin, ["server"]);
        assert_eq!(planned.features, selection.features);
        assert!(planned.run_args.is_empty());
        assert!(
            planned.packages.is_empty(),
            "target resolution must preserve package/feature selection"
        );
        assert_eq!(
            selection.run_args,
            ["--unit-graph", ""],
            "runtime arguments changed"
        );
        selection.packages = vec!["other@1.0.0".into()];
        assert_eq!(
            run_build_selection(&selection, &metadata, Some("other"))
                .unwrap()
                .bin,
            ["other"]
        );
        assert!(run_build_selection(&selection, &metadata, None).is_err());
        assert!(run_build_selection(&selection, &metadata, Some("absent")).is_err());
        selection.example = vec!["demo".into()];
        assert_eq!(
            run_build_selection(&selection, &Value::Null, None)
                .unwrap()
                .example,
            ["demo"]
        );
    }

    #[test]
    fn run_default_resolution_refuses_ambiguity_and_respects_metadata_default_members() {
        let mut metadata = json!({"version":1, "workspace_default_members":["app", "other"],
            "packages":[
                {"id":"app", "targets":[{"name":"app", "kind":["bin"]}]},
                {"id":"other", "targets":[{"name":"other", "kind":["bin"]}]}]});
        let selection = CompilationSelection::default();
        assert!(run_build_selection(&selection, &metadata, None).is_err());
        metadata["workspace_default_members"] = json!(["app"]);
        assert_eq!(
            run_build_selection(&selection, &metadata, None)
                .unwrap()
                .bin,
            ["app"]
        );
        metadata["packages"][0]["default_run"] = json!("missing");
        assert!(run_build_selection(&selection, &metadata, None).is_err());
        metadata["packages"][0]["default_run"] = json!("app");
        metadata["packages"][1]["default_run"] = json!("other");
        metadata["workspace_default_members"] = json!(["app", "other"]);
        assert!(run_build_selection(&selection, &metadata, None).is_err());
        metadata["packages"][1]["default_run"] = Value::Null;
        metadata["packages"][1]["targets"][0]["name"] = json!("app");
        assert!(run_build_selection(&selection, &metadata, None).is_err());
    }

    #[test]
    fn run_and_bench_graphs_require_closed_worker_authority_and_never_admit_doctests() {
        let mut graph = graph();
        for unit in graph["units"].as_array_mut().unwrap() {
            unit["mode"] = json!("build");
        }
        for kind in ["bin", "example"] {
            graph["units"][0]["target"]["kind"] = json!([kind]);
            graph["units"][0]["target"]["crate_types"] = json!(["bin"]);
            let report = validate_compilation_unit_graph(&graph, CompilationCommand::Run).unwrap();
            assert!(report.requires_closed_dependency_execution());
            assert!(!report.contains_doctests());
            assert_eq!(
                report.workspace_units().len(),
                1,
                "only the prerequisite library may offload codegen"
            );
        }
        graph["roots"] = json!([0, 1]);
        assert!(validate_compilation_unit_graph(&graph, CompilationCommand::Run).is_err());
        graph["roots"] = json!([0]);
        graph["units"][0]["target"]["kind"] = json!(["bench"]);
        graph["units"][0]["mode"] = json!("test");
        let report = validate_compilation_unit_graph(&graph, CompilationCommand::Bench).unwrap();
        assert!(report.requires_closed_dependency_execution());
        assert!(!report.contains_doctests());
        assert!(validate_compilation_unit_graph(&graph, CompilationCommand::Run).is_err());
        for mode in ["check", "doctest", "bench", "run", "doc"] {
            graph["units"][0]["mode"] = json!(mode);
            assert!(
                validate_compilation_unit_graph(&graph, CompilationCommand::Bench).is_err(),
                "{mode}"
            );
        }
    }
}
