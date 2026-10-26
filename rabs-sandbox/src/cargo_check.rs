//! Admission of the units Cargo actually selected for a library/workspace check.
//!
//! `cargo metadata` describes packages, including optional and development
//! dependencies that a particular check will never execute. Cargo's nightly
//! `--unit-graph -Z unstable-options` output instead describes that command's
//! compiler/build-script units without building them. The canonical driver
//! obtains this graph from its captured Cargo before exposing a cache endpoint.
//!
//! This validator accepts only a bounded graph of ordinary Rust compiler units.
//! It does not infer feature resolution, grant cache authority, or establish
//! provenance from JSON alone. The caller must run the trusted captured Cargo
//! with the same command selection, semantic environment, configuration and
//! mount view as the subsequent check, and bind every returned source path to
//! its captured input roots. The driver may add its trusted wrapper and socket
//! control variables only after admission; these controls cannot select Cargo
//! packages, features or targets. Build scripts, proc macros and unknown unit modes
//! remain outside this profile even if their outputs could otherwise be cached.

use serde_json::Value;
use std::collections::BTreeSet;
use std::io;

mod selection;
pub use selection::CheckSelection;

const MAX_UNITS: usize = 16_384;
const MAX_DEPENDENCIES: usize = 262_144;
const MAX_FEATURES: usize = 4_096;
const MAX_TEXT: usize = 8_192;
const LIBRARY_TYPES: &[&str] = &["lib", "rlib", "dylib", "cdylib", "staticlib"];

/// A validated selected check graph. Counts are explanatory, not authority.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CheckUnitGraph {
    /// Number of selected compiler units, including distinct feature/profile units.
    pub units: usize,
    /// Number of distinct opaque Cargo package identities in those units.
    pub packages: usize,
    /// Number of Cargo-selected root units.
    pub roots: usize,
    source_paths: Vec<String>,
}

impl CheckUnitGraph {
    /// Sorted, deduplicated compiler source paths for captured-root validation.
    /// These retain Cargo's exact spelling; no host or namespace rewriting occurs.
    #[must_use]
    pub fn source_paths(&self) -> &[String] {
        &self.source_paths
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

fn target_source(unit: &Value) -> io::Result<&str> {
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
            require(
                !matches!(kind, "custom-build" | "proc-macro"),
                "selected Cargo check contains build scripts or procedural macros",
            )?;
            let allowed = LIBRARY_TYPES.contains(&kind)
                || kind == "bin"
                || (field == "kind" && matches!(kind, "example" | "test" | "bench"));
            require(allowed, "unknown Cargo unit target kind or crate type")?;
            require(seen.insert(kind), "duplicate Cargo unit target kind")?;
        }
    }
    for field in ["doc", "doctest", "test"] {
        optional_bool(target, field)?;
    }
    Ok(source)
}

fn index(value: &Value, units: usize) -> io::Result<usize> {
    value
        .as_u64()
        .and_then(|index| usize::try_from(index).ok())
        .filter(|index| *index < units)
        .ok_or_else(|| invalid("Cargo unit graph index is absent or outside its units"))
}

/// Validate a version-1, nonexecuting Cargo unit graph for a selected check.
///
/// All nodes are validated, including any node not reachable from a selected
/// root. Unreachable nodes, cycles, invalid dependency references and unknown
/// execution modes refuse the whole graph. Merely omitting a dangerous node
/// from `roots` therefore cannot make it an admitted check graph.
///
/// The parser deliberately does not reconstruct Cargo's feature resolver or
/// package selection from `cargo metadata`. Multiple units for the same package
/// are normal, and retained source paths must be checked by the caller against
/// the actual captured source/Cargo-home mounts before execution.
///
/// # Errors
/// Returns `InvalidInput` for malformed, excessive or unsupported graphs, or
/// for any selected build-script/proc-macro/execution mode outside ordinary
/// Rust compilation. This is an execution eligibility check only, never a
/// result-publication or compiler-skip authorization.
pub fn validate_check_unit_graph(graph: &Value) -> io::Result<CheckUnitGraph> {
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
    let mut dependencies = Vec::with_capacity(units.len());
    let mut dependency_count = 0_usize;
    for (unit_index, unit) in units.iter().enumerate() {
        require(unit.is_object(), "Cargo graph unit is not an object")?;
        packages.insert(text(&unit["pkg_id"], "package identity")?);
        let mode = text(&unit["mode"], "unit mode")?;
        require(
            mode != "run-custom-build",
            "selected Cargo check contains build scripts or procedural macros",
        )?;
        require(
            matches!(mode, "check" | "build"),
            "selected Cargo check contains an unsupported execution mode",
        )?;
        source_paths.insert(target_source(unit)?.to_owned());
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
            "building the standard library is outside the captured check profile",
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
    validate_reachability(&dependencies, &selected)?;
    Ok(CheckUnitGraph {
        units: units.len(),
        packages: packages.len(),
        roots: selected.len(),
        source_paths: source_paths.into_iter().collect(),
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
        let report = validate_check_unit_graph(&graph()).unwrap();
        assert_eq!((report.units, report.packages, report.roots), (2, 2, 1));
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
        let report = validate_check_unit_graph(&graph).unwrap();
        assert_eq!((report.units, report.packages, report.roots), (2, 1, 1));
        assert_eq!(report.source_paths().len(), 1);
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
            validate_check_unit_graph(&graph).unwrap();
        }
    }

    #[test]
    fn scripts_macros_and_unknown_execution_modes_refuse_before_execution() {
        for field in ["kind", "crate_types"] {
            for kind in ["custom-build", "proc-macro", "future-target"] {
                let mut graph = graph();
                graph["units"][1]["target"][field] = json!([kind]);
                assert!(
                    validate_check_unit_graph(&graph).is_err(),
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
            assert!(validate_check_unit_graph(&graph).is_err(), "{mode}");
        }
        let mut graph = graph();
        graph["units"][0]["is_std"] = json!(true);
        assert!(validate_check_unit_graph(&graph).is_err());
    }

    #[test]
    fn invalid_versions_roots_indices_and_edges_are_refused() {
        for version in [json!(0), json!(2), json!("1"), Value::Null] {
            let mut graph = graph();
            graph["version"] = version;
            assert!(validate_check_unit_graph(&graph).is_err());
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
            assert!(validate_check_unit_graph(&graph).is_err());
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
            assert!(validate_check_unit_graph(&graph).is_err());
        }
        let mut graph = graph();
        let edge = graph["units"][0]["dependencies"][0].clone();
        graph["units"][0]["dependencies"] = json!([edge.clone(), edge]);
        assert!(validate_check_unit_graph(&graph).is_err());
    }

    #[test]
    fn cycles_and_dangling_units_cannot_hide_outside_selected_roots() {
        let mut cyclic = graph();
        cyclic["units"][1] = unit("dependency", &[0]);
        assert!(
            validate_check_unit_graph(&cyclic)
                .unwrap_err()
                .to_string()
                .contains("cycle")
        );
        let mut dangling = graph();
        dangling["units"][0]["dependencies"] = json!([]);
        assert!(
            validate_check_unit_graph(&dangling)
                .unwrap_err()
                .to_string()
                .contains("unreachable")
        );
        dangling["units"][1]["target"]["kind"] = json!(["proc-macro"]);
        assert!(validate_check_unit_graph(&dangling).is_err());
        dangling["units"][1] = unit("dependency", &[]);
        dangling["roots"] = json!([0, 1]);
        assert_eq!(validate_check_unit_graph(&dangling).unwrap().roots, 2);
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
            assert!(validate_check_unit_graph(&graph).is_err(), "{field}");
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
            assert!(validate_check_unit_graph(&graph).is_err(), "{source:?}");
        }
        let mut graph = graph();
        graph["units"][0]["features"] = json!(["duplicate", "duplicate"]);
        assert!(validate_check_unit_graph(&graph).is_err());
        graph["units"][0]["features"] = json!([]);
        graph["units"][0]["target"]["test"] = json!("true");
        assert!(validate_check_unit_graph(&graph).is_err());
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
        assert_eq!(validate_check_unit_graph(&graph).unwrap().units, MAX_UNITS);
        graph["units"]
            .as_array_mut()
            .unwrap()
            .push(unit("excessive", &[]));
        assert!(validate_check_unit_graph(&graph).is_err());
    }
}
