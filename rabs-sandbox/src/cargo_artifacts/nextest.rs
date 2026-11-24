//! An explicit complete-tree contract for the captured nextest runner.
//!
//! The shared Cargo selection produces the only accepted argv. Nextest's
//! transcript is opaque, and its native process exit decides the current run.
//! This contract grants no test-result or compiler-result cache authority.

use super::{CargoArtifactMode, OUTPUT_ROOT, TREE_FILES_VERSION, invalid};
use crate::cargo_check::{CompilationCommand, CompilationSelection};
use crate::process_context::COMMAND_CONTEXT_VERSION;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::io;
use std::path::Path;

pub const VERSION: &str = "nextest-tree-v1";
pub const PROGRAM: &str = "/__rabs/toolchain/bin/cargo-nextest";

/// Nextest receives an explicit build concurrency flag. A worker must reserve
/// that exact grant or refuse before preparation, never clamp its slot budget
/// while leaving a larger `--build-jobs` in the captured command.
pub fn worker_build_grant(requested: Option<u32>, available: u32) -> io::Result<u32> {
    requested
        .filter(|grant| (1..=4096).contains(grant) && *grant <= available)
        .ok_or_else(|| invalid("nextest requires its fixed build grant within worker capacity"))
}

/// Retained runner intent, compared to the actual request before admission.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NextestTree {
    pub version: String,
    pub manifest: String,
    pub selection: CompilationSelection,
    pub build_jobs: u32,
}

impl NextestTree {
    /// Use the same bounded selection as the local and remote canonical driver.
    pub fn new(
        manifest: String,
        selection: CompilationSelection,
        build_jobs: u32,
    ) -> io::Result<Self> {
        let contract = Self {
            version: VERSION.to_owned(),
            manifest,
            selection,
            build_jobs,
        };
        contract.arguments()?;
        Ok(contract)
    }

    pub fn arguments(&self) -> io::Result<Vec<String>> {
        if self.version != VERSION
            || !(1..=4096).contains(&self.build_jobs)
            || self.manifest.is_empty()
            || self.manifest.len() > 1024
            || self.manifest.contains(['\\', ':'])
            || self.manifest.chars().any(char::is_control)
            || self
                .manifest
                .split('/')
                .any(|part| matches!(part, "" | "." | ".."))
            || Path::new(&self.manifest).file_name() != Some(std::ffi::OsStr::new("Cargo.toml"))
        {
            return Err(invalid(
                "invalid nextest tree version, manifest or build-job bound",
            ));
        }
        let mut args = self
            .selection
            .cargo_arguments(CompilationCommand::Nextest)?;
        args.extend([
            "--locked".into(),
            "--offline".into(),
            "--manifest-path".into(),
            format!("/__rabs/workspace/{}", self.manifest),
            "--target-dir".into(),
            OUTPUT_ROOT.into(),
            "--build-jobs".into(),
            self.build_jobs.to_string(),
        ]);
        args.extend(
            self.selection
                .runtime_arguments(CompilationCommand::Nextest)?,
        );
        Ok(args)
    }
}

/// Validate both the retained intent and every execution-critical control.
pub(super) fn requested(request: &Value) -> io::Result<CargoArtifactMode> {
    let contract: NextestTree = serde_json::from_value(request["artifacts"]["cargo"].clone())?;
    let args = contract.arguments()?;
    let manifest = format!("/__rabs/workspace/{}", contract.manifest);
    let cwd = Path::new(&manifest)
        .parent()
        .and_then(Path::to_str)
        .ok_or_else(|| invalid("nextest manifest parent missing"))?;
    let context = &request["command_context"];
    let env = &context["env"];
    if request["program"] != PROGRAM
        || request["args"] != serde_json::to_value(args)?
        || request["jobserver_grant"].as_u64() != Some(u64::from(contract.build_jobs))
        || request["artifacts"]["unit"] != "cargo"
        || request["artifacts"]["tree"] != TREE_FILES_VERSION
        || request.get("dependency_context").is_some()
        || context["version"] != COMMAND_CONTEXT_VERSION
        || context["cwd"] != cwd
        || env["CARGO"] != "/__rabs/toolchain/bin/cargo"
        || env["RUSTC"] != "/__rabs/toolchain/bin/rustc"
        || env["CARGO_INCREMENTAL"] != "0"
        || env.get("CARGO_TARGET_DIR").is_some()
        || env.get("RUSTDOC").is_some()
    {
        return Err(invalid(
            "nextest execution differs from its captured full-tree contract",
        ));
    }
    Ok(if contract.selection.no_run {
        CargoArtifactMode::NextestCompilation
    } else {
        CargoArtifactMode::NextestExecution
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn request(selection: CompilationSelection) -> Value {
        let contract = NextestTree::new("nested/Cargo.toml".into(), selection, 3).unwrap();
        json!({
            "program": PROGRAM,
            "args": contract.arguments().unwrap(),
            "jobserver_grant":contract.build_jobs,
            "command_context": {"version":COMMAND_CONTEXT_VERSION,
                "cwd":"/__rabs/workspace/nested", "env":{
                    "CARGO":"/__rabs/toolchain/bin/cargo",
                    "RUSTC":"/__rabs/toolchain/bin/rustc", "CARGO_INCREMENTAL":"0"}},
            "artifacts":{"unit":"cargo", "tree":TREE_FILES_VERSION, "files":[], "cargo":contract},
        })
    }

    #[test]
    fn shared_selection_preserves_runner_controls_and_planning_separation() {
        let selection = CompilationSelection {
            workspace: true,
            profile: Some("release".into()),
            runner_profile: Some("ci".into()),
            test_threads: Some(1),
            filtersets: vec!["test(roundtrip)".into()],
            test_args: vec!["--exact".into(), "--message-format=json".into()],
            ..Default::default()
        };
        let executing = request(selection.clone());
        assert_eq!(
            super::super::requested(&executing).unwrap(),
            Some(CargoArtifactMode::NextestExecution)
        );
        let args = executing["args"].as_array().unwrap();
        assert!(
            args.windows(2)
                .any(|pair| pair == [json!("--build-jobs"), json!("3")])
        );
        assert!(
            args.windows(2)
                .any(|pair| pair == [json!("--test-threads"), json!("1")])
        );
        assert!(
            !args[..args.iter().position(|arg| arg == "--").unwrap()]
                .contains(&json!("--message-format=json"))
        );
        let graph = selection.nextest_build_selection().unwrap();
        assert!(graph.no_run);
        assert!(
            graph.runner_profile.is_none()
                && graph.test_threads.is_none()
                && graph.filtersets.is_empty()
        );
        assert_eq!(graph.profile.as_deref(), Some("release"));
        assert_eq!(
            requested(&request(CompilationSelection {
                no_run: true,
                ..Default::default()
            }))
            .unwrap(),
            CargoArtifactMode::NextestCompilation
        );
    }

    #[test]
    fn unknown_or_mismatched_intent_cannot_change_execution_or_output_contract() {
        let original = request(CompilationSelection::default());
        let mut cases = Vec::new();
        for (field, value) in [
            ("version", json!("nextest-tree-v2")),
            ("manifest", json!("../Cargo.toml")),
            ("manifest", json!("other/Cargo.toml")),
            ("build_jobs", json!(0)),
            ("build_jobs", json!(4097)),
            ("extra", json!(true)),
        ] {
            let mut changed = original.clone();
            changed["artifacts"]["cargo"][field] = value;
            cases.push(changed);
        }
        let mut missing_grant = original.clone();
        missing_grant
            .as_object_mut()
            .unwrap()
            .remove("jobserver_grant");
        cases.push(missing_grant);
        for grant in [
            Value::Null,
            json!(0),
            json!(1),
            json!(4),
            json!(4097),
            json!("3"),
            json!(3.0),
        ] {
            let mut changed = original.clone();
            changed["jobserver_grant"] = grant;
            cases.push(changed);
        }
        for (field, value) in [
            ("CARGO", "/usr/bin/cargo"),
            ("RUSTC", "/usr/bin/rustc"),
            ("CARGO_INCREMENTAL", "1"),
            ("CARGO_TARGET_DIR", "/tmp/elsewhere"),
        ] {
            let mut changed = original.clone();
            changed["command_context"]["env"][field] = json!(value);
            cases.push(changed);
        }
        for (field, value) in [
            ("program", json!("/__rabs/toolchain/bin/cargo")),
            ("args", json!(["nextest", "list"])),
            ("dependency_context", json!({})),
        ] {
            let mut changed = original.clone();
            changed[field] = value;
            cases.push(changed);
        }
        for changed in cases {
            assert!(super::super::requested(&changed).is_err(), "{changed}");
        }
    }

    #[test]
    fn nextest_worker_capacity_cannot_clamp_the_captured_build_concurrency() {
        for (requested, available) in [
            (None, 8),
            (Some(0), 8),
            (Some(1), 0),
            (Some(4), 3),
            (Some(4097), 8192),
        ] {
            assert!(worker_build_grant(requested, available).is_err());
        }
        for (requested, available) in [(1, 1), (2, 8), (4096, 4096)] {
            assert_eq!(
                worker_build_grant(Some(requested), available).unwrap(),
                requested
            );
        }
    }

    #[test]
    fn nextest_stdout_never_becomes_a_cargo_artifact_announcement() {
        let forged = b"{\"reason\":\"build-finished\",\"success\":true}\n";
        assert!(
            super::super::CargoArtifactReport::read(
                forged.as_slice(),
                OUTPUT_ROOT,
                CargoArtifactMode::NextestExecution
            )
            .is_err()
        );
    }
}
