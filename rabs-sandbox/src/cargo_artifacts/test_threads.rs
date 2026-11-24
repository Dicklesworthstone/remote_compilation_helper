//! Admission for explicit Cargo test and benchmark harness concurrency.
//!
//! Preserve the complete command and reserve the larger of its compiler grant
//! and every explicit harness thread count. No option is inserted, removed,
//! reordered or clamped. A custom harness may use the same spelling, so this
//! is conservative resource admission, not proof of libtest or a cached pass.
//! Default thread counts and arbitrary threads created by test bodies remain
//! outside this contract.

use super::CargoArtifactMode;
use crate::cargo_check::{CompilationCommand, CompilationSelection};
use serde_json::Value;
use std::io;

pub const RUNTIME_ADMISSION_VERSION: &str = "cargo-test-runtime-admission-v1";
const PROGRAM: &str = "/__rabs/toolchain/bin/cargo";

fn invalid(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message)
}

fn positive_count(value: &str) -> io::Result<u32> {
    if value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(invalid(
            "explicit execution concurrency requires a positive integer",
        ));
    }
    value
        .parse::<u32>()
        .ok()
        .filter(|count| (1..=4096).contains(count))
        .ok_or_else(|| invalid("explicit execution concurrency must be between 1 and 4096"))
}

/// Inspect only the harness option portion. A second literal `--` belongs to
/// the harness and ends option interpretation even if later strings resemble
/// thread controls. Repeated controls reserve their maximum without selecting
/// a winner or changing a custom harness's interpretation.
pub fn explicit_threads(arguments: &[String]) -> io::Result<Option<u32>> {
    let mut maximum: Option<u32> = None;
    let mut at = 0;
    while let Some(argument) = arguments.get(at) {
        if argument == "--" {
            break;
        }
        let value = if argument == "--test-threads" {
            at += 1;
            Some(
                arguments
                    .get(at)
                    .ok_or_else(|| invalid("--test-threads requires a positive integer"))?
                    .as_str(),
            )
        } else {
            argument.strip_prefix("--test-threads=")
        };
        if let Some(value) = value {
            let count = positive_count(value)?;
            maximum = Some(maximum.map_or(count, |previous| previous.max(count)));
        }
        at += 1;
    }
    Ok(maximum)
}

/// Local/coordinator profiles already own a fixed compiler grant. Their
/// selection and the worker's actual argv use exactly the same tail parser.
pub fn selection_execution_slots(
    command: CompilationCommand,
    selection: &CompilationSelection,
    build_jobs: u32,
) -> io::Result<u32> {
    if !matches!(
        command,
        CompilationCommand::Test | CompilationCommand::Bench
    ) || selection.no_run
    {
        return Ok(build_jobs);
    }
    selection.cargo_arguments(command)?;
    Ok(build_jobs.max(explicit_threads(&selection.test_args)?.unwrap_or(0)))
}

/// An immutable resource binding to the original validated request. Keeping
/// the complete argv and grant makes a changed request unequal even when its
/// new thread count would fit the same worker. Worker ArtifactPlan additionally
/// binds the parsed command context before this record can admit execution.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExplicitTestExecution {
    program: String,
    arguments: Vec<String>,
    requested_build_grant: Option<u32>,
    argument_build_jobs: Option<u32>,
    test_threads: u32,
}

impl ExplicitTestExecution {
    /// Recompute demand from actual executable arguments, independently of an
    /// artifact plan or a caller's claimed selection. This method alone grants
    /// no execution authority; fresh requests must also pass `requested` below.
    pub fn from_command(
        program: &str,
        arguments: &[String],
        requested_build_grant: Option<u32>,
    ) -> io::Result<Option<Self>> {
        if program != PROGRAM
            || !matches!(
                arguments.first().map(String::as_str),
                Some("test" | "bench")
            )
        {
            return Ok(None);
        }
        let Some(separator) = arguments.iter().position(|argument| argument == "--") else {
            return Ok(None);
        };
        if arguments[..separator]
            .iter()
            .any(|argument| argument == "--no-run")
        {
            return Ok(None);
        }
        let Some(test_threads) = explicit_threads(&arguments[separator + 1..])? else {
            return Ok(None);
        };
        if arguments.len() > 272
            || arguments
                .iter()
                .any(|argument| argument.len() > 4096 || argument.contains('\0'))
            || requested_build_grant.is_some_and(|grant| !(1..=4096).contains(&grant))
        {
            return Err(invalid(
                "explicit test execution has invalid arguments or compiler grant",
            ));
        }
        // An explicit Cargo -j must not bypass a smaller retained jobserver
        // grant. The canonical worker frontend normally inherits that grant
        // without a -j option; raw requests still need the same accounting.
        let mut argument_build_jobs: Option<u32> = None;
        let mut at = 1;
        while at < separator {
            let argument = &arguments[at];
            let value = if matches!(argument.as_str(), "--jobs" | "-j") {
                at += 1;
                Some(
                    arguments
                        .get(at)
                        .filter(|_| at < separator)
                        .ok_or_else(|| invalid("Cargo jobs requires an explicit positive count"))?
                        .as_str(),
                )
            } else {
                argument.strip_prefix("--jobs=").or_else(|| {
                    argument
                        .strip_prefix("-j")
                        .filter(|value| !value.is_empty())
                })
            };
            if let Some(value) = value {
                let jobs = positive_count(value)?;
                argument_build_jobs = Some(argument_build_jobs.map_or(jobs, |old| old.max(jobs)));
            }
            at += 1;
        }
        if let (Some(requested), Some(arguments)) = (requested_build_grant, argument_build_jobs)
            && arguments > requested
        {
            return Err(invalid("Cargo jobs exceeds the retained compiler grant"));
        }
        Ok(Some(Self {
            program: program.to_owned(),
            arguments: arguments.to_vec(),
            requested_build_grant,
            argument_build_jobs,
            test_threads,
        }))
    }

    /// Preserve the ordinary worker's host-sized default when no compiler
    /// grant was supplied. A requested grant is never silently reduced.
    pub fn build_grant(&self, available: u32) -> io::Result<u32> {
        let grant = self.requested_build_grant.unwrap_or(available);
        if grant == 0
            || grant > available
            || self.argument_build_jobs.is_some_and(|jobs| jobs > grant)
        {
            return Err(invalid(
                "explicit test compiler grant exceeds worker capacity",
            ));
        }
        Ok(grant)
    }

    pub fn execution_slots(&self, available: u32) -> io::Result<u32> {
        let slots = self.build_grant(available)?.max(self.test_threads);
        if slots > available {
            return Err(invalid("explicit test threads exceed worker capacity"));
        }
        Ok(slots)
    }
}

/// Fresh admission only. Existing result decoding retains its original Cargo
/// artifact contract and does not require a new capability to collect outputs.
/// Ordinary/default and compile-only requests keep their previous route.
pub fn requested(request: &Value) -> io::Result<Option<ExplicitTestExecution>> {
    if request["program"] != PROGRAM {
        return Ok(None);
    }
    let Some(arguments) = request["args"].as_array() else {
        return Ok(None);
    };
    if !matches!(
        arguments.first().and_then(Value::as_str),
        Some("test" | "bench")
    ) {
        return Ok(None);
    }
    if arguments.len() > 272 {
        return Err(invalid("Cargo test execution arguments exceed their bound"));
    }
    let arguments = arguments
        .iter()
        .map(|argument| {
            argument
                .as_str()
                .map(str::to_owned)
                .ok_or_else(|| invalid("invalid Cargo test execution argument"))
        })
        .collect::<io::Result<Vec<_>>>()?;
    // Do not change legacy grant decoding for a command without this explicit
    // control. Its worker remains responsible for ordinary request validation.
    if ExplicitTestExecution::from_command(PROGRAM, &arguments, None)?.is_none() {
        return Ok(None);
    }
    let grant = request
        .get("jobserver_grant")
        .map(|value| {
            value
                .as_u64()
                .and_then(|value| u32::try_from(value).ok())
                .ok_or_else(|| invalid("explicit test compiler grant must be an unsigned integer"))
        })
        .transpose()?;
    let contract = ExplicitTestExecution::from_command(PROGRAM, &arguments, grant)?;
    if !matches!(
        super::requested(request)?,
        Some(CargoArtifactMode::TestExecution | CargoArtifactMode::BenchExecution)
    ) {
        return Err(invalid(
            "explicit test execution requires its validated Cargo artifact contract",
        ));
    }
    Ok(contract)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn strings(values: &[&str]) -> Vec<String> {
        values.iter().map(|value| (*value).to_owned()).collect()
    }

    fn request(command: &str, grant: Option<u32>, tail: &[&str]) -> Value {
        let mut arguments = strings(&[
            command,
            "--message-format=json",
            "--target-dir=/__rabs/out/cargo",
            "--",
        ]);
        arguments.extend(strings(tail));
        let mut request = json!({
            "program":PROGRAM, "args":arguments,
            "artifacts":{"unit":"cargo", "files":[], "tree":"tree-files-v1",
                "cargo":format!("cargo-{command}-json-v1")},
        });
        if let Some(grant) = grant {
            request["jobserver_grant"] = json!(grant);
        }
        request
    }

    #[test]
    fn explicit_options_reserve_the_maximum_and_preserve_literal_boundaries() {
        for (arguments, expected) in [
            (vec!["--test-threads", "8"], Some(8)),
            (vec!["filter", "--test-threads=3", "--nocapture"], Some(3)),
            (vec!["--test-threads=8", "--test-threads", "2"], Some(8)),
            (
                vec!["--test-threads=1", "--", "--test-threads=4097"],
                Some(1),
            ),
            (vec!["--", "--test-threads", "8"], None),
            (vec!["test_threads::literal", "--nocapture"], None),
        ] {
            let arguments = strings(&arguments);
            let original = arguments.clone();
            assert_eq!(explicit_threads(&arguments).unwrap(), expected);
            assert_eq!(arguments, original);
        }
        for arguments in [
            vec!["--test-threads"],
            vec!["--test-threads", "--"],
            vec!["--test-threads="],
            vec!["--test-threads=0"],
            vec!["--test-threads=-1"],
            vec!["--test-threads=+1"],
            vec!["--test-threads=4097"],
            vec!["--test-threads=4294967296"],
            vec!["--test-threads=custom"],
            vec!["--test-threads=2", "--test-threads=0"],
        ] {
            assert!(
                explicit_threads(&strings(&arguments)).is_err(),
                "{arguments:?}"
            );
        }
    }

    #[test]
    fn profile_demand_preserves_build_jobs_and_does_not_bound_defaults() {
        for command in [CompilationCommand::Test, CompilationCommand::Bench] {
            for (jobs, threads, expected) in [(2, 8, 8), (8, 1, 8)] {
                let selection = CompilationSelection {
                    test_args: strings(&["--test-threads", &threads.to_string()]),
                    ..Default::default()
                };
                assert_eq!(
                    selection_execution_slots(command, &selection, jobs).unwrap(),
                    expected
                );
                let mut compile_only = selection;
                compile_only.no_run = true;
                assert_eq!(
                    selection_execution_slots(command, &compile_only, jobs).unwrap(),
                    jobs
                );
            }
            assert_eq!(
                selection_execution_slots(command, &CompilationSelection::default(), 2).unwrap(),
                2,
            );
        }
    }

    #[test]
    fn actual_requests_bind_thread_demand_and_keep_host_sized_default_grants() {
        for command in ["test", "bench"] {
            let original = request(command, Some(2), &["--test-threads=8"]);
            let contract = requested(&original).unwrap().unwrap();
            assert_eq!(contract.build_grant(8).unwrap(), 2);
            assert_eq!(contract.execution_slots(8).unwrap(), 8);
            assert!(contract.execution_slots(4).is_err());
            let mut changed = original.clone();
            changed["args"]
                .as_array_mut()
                .unwrap()
                .push(json!("--test-threads=4"));
            assert_ne!(requested(&changed).unwrap().unwrap(), contract);
            changed = original.clone();
            changed["jobserver_grant"] = json!(1);
            assert_ne!(requested(&changed).unwrap().unwrap(), contract);
            for grant in [
                json!(null),
                json!("2"),
                json!(-1),
                json!(0),
                json!(4097),
                json!(4294967296_u64),
            ] {
                changed = original.clone();
                changed["jobserver_grant"] = grant;
                assert!(requested(&changed).is_err(), "{changed}");
            }
            changed = original.clone();
            changed.as_object_mut().unwrap().remove("artifacts");
            assert!(requested(&changed).is_err());
            changed = original;
            changed["artifacts"]["cargo"] = json!(super::super::CARGO_ARTIFACTS_VERSION);
            assert!(requested(&changed).is_err());
            let default = requested(&request(command, None, &["--test-threads=2"]))
                .unwrap()
                .unwrap();
            assert_eq!(default.build_grant(8).unwrap(), 8);
            assert_eq!(default.execution_slots(8).unwrap(), 8);
            assert!(default.execution_slots(0).is_err());
        }
    }

    #[test]
    fn unrelated_default_and_compile_only_requests_keep_existing_admission() {
        assert!(requested(&json!({"program":"other"})).unwrap().is_none());
        for command in ["test", "bench"] {
            assert!(
                requested(&request(command, Some(2), &["--nocapture"]))
                    .unwrap()
                    .is_none()
            );
            assert!(
                requested(&request(command, Some(2), &["--", "--test-threads=8"]))
                    .unwrap()
                    .is_none()
            );
            let mut compile_only = request(command, Some(2), &["--test-threads=8"]);
            compile_only["args"]
                .as_array_mut()
                .unwrap()
                .insert(1, json!("--no-run"));
            compile_only["artifacts"]["cargo"] = json!(super::super::CARGO_ARTIFACTS_VERSION);
            assert!(requested(&compile_only).unwrap().is_none());
        }
    }

    #[test]
    fn explicit_cargo_jobs_cannot_bypass_the_retained_compiler_grant() {
        for option in [vec!["--jobs", "8"], vec!["--jobs=8"], vec!["-j8"]] {
            let mut original = request("test", Some(2), &["--test-threads=1"]);
            for value in option.into_iter().rev() {
                original["args"]
                    .as_array_mut()
                    .unwrap()
                    .insert(1, json!(value));
            }
            assert!(requested(&original).is_err());
            original["jobserver_grant"] = json!(8);
            assert_eq!(
                requested(&original)
                    .unwrap()
                    .unwrap()
                    .execution_slots(8)
                    .unwrap(),
                8
            );
        }
    }
}
