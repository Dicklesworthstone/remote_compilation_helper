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
/// Fresh execution reserves both compiler and runner concurrency.
pub const RUNTIME_ADMISSION_VERSION: &str = "nextest-runtime-admission-v1";

/// The host reservation covers whichever phase has the larger concurrency.
/// This policy applies only to new execution, not retained v1 validation.
pub fn execution_slots(
    selection: &CompilationSelection,
    build_jobs: u32,
) -> io::Result<u32> {
    if !(1..=4096).contains(&build_jobs) {
        return Err(invalid("nextest build jobs must be between 1 and 4096"));
    }
    selection.cargo_arguments(CompilationCommand::Nextest)?;
    // Nextest interprets its tail as emulated harness arguments. Keep resource
    // controls exclusively in the typed selection, even for captured runners
    // whose compatibility parser accepts additional aliases.
    if selection.test_args.iter().any(|arg| {
        matches!(
            arg.split_once('=').map_or(arg.as_str(), |(name, _)| name),
            "--test-threads" | "--jobs" | "--build-jobs"
        ) || arg.starts_with("-j")
    }) {
        return Err(invalid(
            "nextest concurrency must be selected before --, not in test arguments",
        ));
    }
    if selection.no_run {
        return Ok(build_jobs);
    }
    let test_threads = selection.test_threads.ok_or_else(|| {
        invalid("nextest execution requires explicit --test-threads within the admitted capacity")
    })?;
    Ok(build_jobs.max(test_threads))
}

/// Apply current execution admission without changing historical v1 decoding.
/// An absent contract cannot turn the captured nextest program into an
/// unaccounted ordinary command. Other programs retain their own validation.
pub fn fresh_execution_slots(request: &Value) -> io::Result<Option<u32>> {
    if request["program"] != PROGRAM && !request["artifacts"]["cargo"].is_object() {
        return Ok(None);
    }
    requested(request)?;
    let contract: NextestTree = serde_json::from_value(request["artifacts"]["cargo"].clone())?;
    contract.execution_slots().map(Some)
}

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

    /// Fresh execution policy is separate from the exact retained argv.
    pub fn execution_slots(&self) -> io::Result<u32> {
        self.arguments()?;
        execution_slots(&self.selection, self.build_jobs)
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
    fn partition_is_bound_to_retained_argv_without_discounting_runtime_capacity() {
        for partition in ["hash:2/5", "slice:3/5", "count:4/5"] {
            let selection = CompilationSelection {
                partition: Some(partition.into()),
                test_threads: Some(7),
                ..Default::default()
            };
            let original = request(selection);
            assert_eq!(
                requested(&original).unwrap(),
                CargoArtifactMode::NextestExecution
            );
            assert_eq!(fresh_execution_slots(&original).unwrap(), Some(7));
            assert_eq!(
                original["artifacts"]["cargo"]["selection"]["partition"],
                partition
            );
            let args = original["args"].as_array().unwrap();
            let at = args.iter().position(|arg| arg == "--partition").unwrap();
            assert_eq!(args[at + 1], partition);

            let mut changed = original.clone();
            changed["artifacts"]["cargo"]["selection"]["partition"] = json!("hash:1/5");
            assert!(requested(&changed).is_err());
            let mut changed = original.clone();
            changed["args"][at + 1] = json!("hash:1/5");
            assert!(requested(&changed).is_err());
            let mut changed = original.clone();
            changed["artifacts"]["cargo"]["selection"]
                .as_object_mut()
                .unwrap()
                .remove("partition");
            assert!(requested(&changed).is_err());

            let compile_only = request(CompilationSelection {
                partition: Some(partition.into()),
                no_run: true,
                ..Default::default()
            });
            assert_eq!(
                requested(&compile_only).unwrap(),
                CargoArtifactMode::NextestCompilation
            );
            assert_eq!(fresh_execution_slots(&compile_only).unwrap(), Some(3));
        }
        let historical = request(CompilationSelection::default());
        assert!(
            historical["artifacts"]["cargo"]["selection"]
                .get("partition")
                .is_none()
        );
        assert_eq!(
            requested(&historical).unwrap(),
            CargoArtifactMode::NextestExecution
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
    fn fresh_admission_reserves_the_larger_phase_without_rewriting_runner_intent() {
        for (build_jobs, test_threads, expected) in [(2, 8, 8), (8, 1, 8), (3, 3, 3)] {
            let contract = NextestTree::new(
                "Cargo.toml".into(),
                CompilationSelection {
                    runner_profile: Some("serial".into()),
                    test_threads: Some(test_threads),
                    ..Default::default()
                },
                build_jobs,
            )
            .unwrap();
            let original = contract.arguments().unwrap();
            assert_eq!(contract.execution_slots().unwrap(), expected);
            assert_eq!(contract.arguments().unwrap(), original);
            assert!(original.windows(2).any(|pair| {
                pair[0] == "--build-jobs" && pair[1] == build_jobs.to_string()
            }));
            assert!(original.windows(2).any(|pair| {
                pair[0] == "--test-threads" && pair[1] == test_threads.to_string()
            }));
        }
        let mut selection = CompilationSelection {
            test_threads: Some(1),
            ..Default::default()
        };
        for jobs in [0, 4097, u32::MAX] {
            assert!(execution_slots(&selection, jobs).is_err());
        }
        for threads in [0, 4097, u32::MAX] {
            selection.test_threads = Some(threads);
            assert!(execution_slots(&selection, 1).is_err());
        }
    }

    #[test]
    fn fresh_refusal_preserves_v1_recovery_and_compile_only_requests() {
        let legacy = request(CompilationSelection {
            runner_profile: Some("serial".into()),
            ..Default::default()
        });
        let retained = serde_json::to_vec(&legacy).unwrap();
        assert_eq!(requested(&legacy).unwrap(), CargoArtifactMode::NextestExecution);
        assert!(fresh_execution_slots(&legacy).is_err());
        assert_eq!(serde_json::to_vec(&legacy).unwrap(), retained);
        assert_eq!(requested(&legacy).unwrap(), CargoArtifactMode::NextestExecution);

        let compile_only = request(CompilationSelection {
            no_run: true,
            ..Default::default()
        });
        assert_eq!(fresh_execution_slots(&compile_only).unwrap(), Some(3));
        assert_eq!(fresh_execution_slots(&json!({"program":"other"})).unwrap(), None);
        let mut missing = legacy.clone();
        missing.as_object_mut().unwrap().remove("artifacts");
        assert!(fresh_execution_slots(&missing).is_err());
        let mut mismatched = legacy;
        mismatched["program"] = json!("/__rabs/toolchain/bin/cargo");
        assert!(fresh_execution_slots(&mismatched).is_err());
    }

    #[test]
    fn fresh_admission_never_takes_concurrency_from_the_runtime_tail() {
        for args in [
            vec!["--test-threads", "8"],
            vec!["--test-threads=8"],
            vec!["--jobs", "8"],
            vec!["--jobs=8"],
            vec!["-j", "8"],
            vec!["-j8"],
            vec!["-j=8"],
            vec!["--build-jobs", "8"],
            vec!["--build-jobs=8"],
        ] {
            let retained = request(CompilationSelection {
                test_threads: Some(1),
                test_args: args.into_iter().map(str::to_owned).collect(),
                ..Default::default()
            });
            assert!(requested(&retained).is_ok(), "historical validation remains exact");
            assert!(fresh_execution_slots(&retained).is_err());
        }
        let serial = request(CompilationSelection {
            test_threads: Some(1),
            test_args: vec!["--nocapture".into(), "test_threads::literal".into()],
            ..Default::default()
        });
        assert_eq!(fresh_execution_slots(&serial).unwrap(), Some(3));
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
