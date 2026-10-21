//! Cargo-selected output names for canonical build, check, Clippy and tests.
//!
//! Cargo owns target selection and hashed output names. Its complete bounded JSON
//! stream supplies the required artifacts; the existing tree capture must still
//! retain every output, verify bytes and drain all writers. These messages never
//! authorize cache publication, compiler skipping or test execution success.

use crate::artifact_tree::{MAX_TREE_FILES, TREE_FILES_VERSION, validate_tree_names};
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};
use std::io::{self, BufRead, BufReader, Read};

/// Explicit opt-in under artifacts.cargo; old endpoints must reject this field.
pub const CARGO_ARTIFACTS_VERSION: &str = "cargo-json-v1";
/// Test execution has arbitrary program output after Cargo's build-finished.
/// Its native final process status, never that JSON record, decides success.
pub const CARGO_TEST_ARTIFACTS_VERSION: &str = "cargo-test-json-v1";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CargoArtifactMode {
    Compilation,
    TestExecution,
}
/// Bound the whole stream, including non-JSON output from procedural macros.
pub const MAX_CARGO_REPORT_BYTES: u64 = 64 * 1024 * 1024;
/// Do not allocate an unbounded line before checking the stream budget.
pub const MAX_CARGO_MESSAGE_BYTES: usize = 1024 * 1024;
const OUTPUT_ROOT: &str = "/__rabs/out/cargo";

fn invalid(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

/// Validate the command as well as the version before execution admission.
/// The version distinguishes compilation-only output from tests' arbitrary
/// stdout after build-finished. The caller separately validates artifact names
/// and the final native process status before offering a successful result.
pub fn requested(request: &Value) -> io::Result<Option<CargoArtifactMode>> {
    let Some(contract) = request
        .get("artifacts")
        .and_then(|value| value.get("cargo"))
    else {
        return Ok(None);
    };
    let mode = match contract.as_str() {
        Some(CARGO_ARTIFACTS_VERSION) => CargoArtifactMode::Compilation,
        Some(CARGO_TEST_ARTIFACTS_VERSION) => CargoArtifactMode::TestExecution,
        _ => return Err(invalid("unsupported Cargo artifact contract")),
    };
    if request["artifacts"]["tree"].as_str() != Some(TREE_FILES_VERSION)
        || request["artifacts"]["unit"].as_str() != Some("cargo")
        || request.get("dependency_context").is_some()
    {
        return Err(invalid("unsupported Cargo artifact contract"));
    }
    let args = request["args"]
        .as_array()
        .filter(|args| !args.is_empty() && args.len() <= 272)
        .ok_or_else(|| invalid("Cargo artifact contract requires bounded arguments"))?
        .iter()
        .map(|arg| {
            arg.as_str()
                .filter(|arg| arg.len() <= 4096 && !arg.contains('\0'))
                .ok_or_else(|| invalid("invalid Cargo artifact argument"))
        })
        .collect::<io::Result<Vec<_>>>()?;
    let command = args[0];
    if !matches!(command, "build" | "check" | "clippy" | "test") {
        return Err(invalid(
            "Cargo artifact contract requires build, check, clippy or test",
        ));
    }
    // cargo-clippy is an external Cargo command. Naming its retained binary
    // directly prevents a missing component from falling through to a host
    // PATH entry. It locates clippy-driver beside itself; its child Cargo and
    // rustc are explicitly bound to the same captured toolchain.
    let program = if command == "clippy" {
        if request["command_context"]["env"]["CARGO"] != "/__rabs/toolchain/bin/cargo"
            || request["command_context"]["env"]["RUSTC"] != "/__rabs/toolchain/bin/rustc"
        {
            return Err(invalid("Clippy requires captured Cargo and rustc bindings"));
        }
        "/__rabs/toolchain/bin/cargo-clippy"
    } else {
        "/__rabs/toolchain/bin/cargo"
    };
    if request["program"].as_str() != Some(program) {
        return Err(invalid("Cargo artifact command requires its captured tool"));
    }
    let mut format = false;
    let mut target = false;
    let mut no_run = false;
    let mut at = 1;
    while at < args.len() {
        if args[at] == "--" && command == "clippy" && mode == CargoArtifactMode::Compilation {
            validate_clippy_lints(&args[at + 1..])?;
            break;
        }
        // Every remaining byte belongs to the selected test harness. In
        // particular --no-run/--help/--target-dir here are not Cargo options.
        if args[at] == "--" && mode == CargoArtifactMode::TestExecution {
            break;
        }
        let (option, inline) = args[at]
            .split_once('=')
            .map_or((args[at], None), |(option, value)| (option, Some(value)));
        match option {
            "--message-format" | "--target-dir" => {
                let value = match inline {
                    Some(value) => value,
                    None => {
                        at += 1;
                        *args
                            .get(at)
                            .ok_or_else(|| invalid("missing Cargo artifact option value"))?
                    }
                };
                if option == "--message-format" {
                    if format || value != "json" {
                        return Err(invalid(
                            "Cargo artifact contract requires one JSON message format",
                        ));
                    }
                    format = true;
                } else {
                    if target || value != OUTPUT_ROOT {
                        return Err(invalid(
                            "Cargo artifact contract requires one canonical target directory",
                        ));
                    }
                    target = true;
                }
            }
            "--no-run" if inline.is_none() && command == "test" && !no_run => no_run = true,
            "--fix" | "--allow-dirty" | "--allow-staged" | "--allow-no-vcs" | "--explain"
                if command == "clippy" =>
            {
                return Err(invalid(
                    "Clippy artifact capture requires a read-only lint run",
                ));
            }
            "--no-run" | "--" | "--help" | "-h" | "--version" | "-V" => {
                return Err(invalid(
                    "Cargo artifact command does not compile the selected targets",
                ));
            }
            _ => {}
        }
        at += 1;
    }
    let matching_command = match mode {
        CargoArtifactMode::Compilation => command != "test" || no_run,
        CargoArtifactMode::TestExecution => command == "test" && !no_run,
    };
    if !format || !target || !matching_command {
        return Err(invalid("incomplete Cargo compilation artifact contract"));
    }
    Ok(Some(mode))
}

/// Only lint controls may cross Clippy's argument separator. In particular,
/// cargo-clippy's CLIPPY_ARGS delimiter cannot occur in lowercase lint names,
/// so an encoded argument cannot become a second compiler option.
fn validate_clippy_lints(args: &[&str]) -> io::Result<()> {
    if args.len() > 128 || args.iter().map(|arg| arg.len()).sum::<usize>() > 16 * 1024 {
        return Err(invalid("Clippy lint arguments exceed their bounds"));
    }
    let short = ["-A", "-W", "-D", "-F"];
    let long = [
        "--allow",
        "--warn",
        "--force-warn",
        "--deny",
        "--forbid",
        "--cap-lints",
    ];
    let mut args = args.iter().copied();
    while let Some(arg) = args.next() {
        let (option, value) = if short.contains(&arg) || long.contains(&arg) {
            (
                arg,
                args.next()
                    .ok_or_else(|| invalid("Clippy lint option lacks its value"))?,
            )
        } else if let Some((option, value)) = arg.split_once('=')
            && long.contains(&option)
        {
            (option, value)
        } else if let Some(option) = short.into_iter().find(|option| arg.starts_with(option)) {
            (option, &arg[option.len()..])
        } else {
            return Err(invalid("Clippy accepts only lint controls after --"));
        };
        let valid = if option == "--cap-lints" {
            matches!(value, "allow" | "warn" | "deny" | "forbid")
        } else {
            value.len() <= 256
                && value.split("::").all(|part| {
                    part.as_bytes().first().is_some_and(u8::is_ascii_lowercase)
                        && part.bytes().all(|byte| {
                            byte.is_ascii_lowercase()
                                || byte.is_ascii_digit()
                                || matches!(byte, b'_' | b'-')
                        })
                })
        };
        if !valid {
            return Err(invalid(
                "Clippy requires literal lowercase lint names or a lint cap",
            ));
        }
    }
    Ok(())
}

/// Required real compiler outputs, reconstructed independently by both peers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CargoArtifactReport {
    files: BTreeSet<String>,
    executables: BTreeSet<String>,
}

impl CargoArtifactReport {
    /// Read Cargo's actual stdout, preserving unrelated output in its original
    /// diagnostic stream. Non-JSON lines are allowed, as Cargo cannot control
    /// procedural macro stdout. Malformed JSON-shaped records fail closed in
    /// the compilation report; test output after build-finished stays opaque.
    pub fn read(reader: impl Read, output_root: &str, mode: CargoArtifactMode) -> io::Result<Self> {
        if !output_root.starts_with('/') || output_root.ends_with('/') {
            return Err(invalid("Cargo output root must be an absolute directory"));
        }
        let prefix = format!("{output_root}/");
        let mut reader = BufReader::new(reader);
        let mut line = Vec::new();
        let mut total = 0_u64;
        let mut files = BTreeSet::new();
        let mut executables = BTreeSet::new();
        let mut finished = false;
        let mut compiled_target = false;
        let mut artifact_messages = 0_usize;
        loop {
            if finished && mode == CargoArtifactMode::TestExecution {
                // Stock Cargo emits build-finished before starting test
                // programs. Their stdout is opaque: even a JSON-shaped record
                // or an unterminated/long line cannot add an artifact or change
                // compilation success. Still consume and bound the entire
                // verified stream without buffering an arbitrary test line.
                loop {
                    let available = reader.fill_buf()?;
                    if available.is_empty() {
                        break;
                    }
                    let count = available.len();
                    total = total
                        .checked_add(count as u64)
                        .filter(|total| *total <= MAX_CARGO_REPORT_BYTES)
                        .ok_or_else(|| invalid("Cargo artifact report exceeds its byte bound"))?;
                    reader.consume(count);
                }
                break;
            }
            line.clear();
            loop {
                let available = reader.fill_buf()?;
                if available.is_empty() {
                    break;
                }
                let newline = available.iter().position(|byte| *byte == b'\n');
                let count = newline.map_or(available.len(), |index| index + 1);
                total = total
                    .checked_add(count as u64)
                    .filter(|total| *total <= MAX_CARGO_REPORT_BYTES)
                    .ok_or_else(|| invalid("Cargo artifact report exceeds its byte bound"))?;
                if line.len() + count > MAX_CARGO_MESSAGE_BYTES {
                    return Err(invalid("Cargo artifact message exceeds its line bound"));
                }
                line.extend_from_slice(&available[..count]);
                reader.consume(count);
                if newline.is_some() {
                    break;
                }
            }
            if line.is_empty() {
                break;
            }
            if line.first() != Some(&b'{') {
                continue;
            }
            if line.last() != Some(&b'\n') {
                return Err(invalid("truncated Cargo JSON message"));
            }
            let value: Value = serde_json::from_slice(&line)
                .map_err(|_| invalid("malformed Cargo JSON message"))?;
            let reason = value.get("reason").and_then(Value::as_str);
            if finished && reason.is_some() {
                return Err(invalid("Cargo message follows build-finished"));
            }
            match reason {
                Some("build-finished") => {
                    if value["success"].as_bool() != Some(true) {
                        return Err(invalid("Cargo did not report a successful build"));
                    }
                    finished = true;
                }
                Some("compiler-artifact") => {
                    artifact_messages += 1;
                    if artifact_messages > MAX_TREE_FILES {
                        return Err(invalid("too many Cargo artifact records"));
                    }
                    let kinds = value["target"]["kind"]
                        .as_array()
                        .filter(|kinds| !kinds.is_empty() && kinds.len() <= 16)
                        .ok_or_else(|| invalid("Cargo artifact target kind is missing"))?;
                    if kinds.iter().any(|kind| kind.as_str().is_none()) {
                        return Err(invalid("invalid Cargo artifact target kind"));
                    }
                    let paths = value["filenames"]
                        .as_array()
                        .filter(|paths| !paths.is_empty() && paths.len() <= MAX_TREE_FILES)
                        .ok_or_else(|| invalid("Cargo artifact filenames are missing"))?;
                    let relative = |value: &Value| -> io::Result<String> {
                        value
                            .as_str()
                            .and_then(|path| path.strip_prefix(&prefix))
                            .map(str::to_owned)
                            .ok_or_else(|| {
                                invalid("Cargo artifact escapes the declared output root")
                            })
                    };
                    let paths = paths.iter().map(relative).collect::<io::Result<Vec<_>>>()?;
                    let names = validate_tree_names(paths.iter().map(String::as_str))?;
                    if !kinds.iter().any(|kind| kind == "custom-build") {
                        compiled_target = true;
                    }
                    match value.get("executable") {
                        Some(Value::Null) => {}
                        Some(value) => {
                            let executable = relative(value)?;
                            if !names.contains(&executable) {
                                return Err(invalid("Cargo executable is not in its artifact set"));
                            }
                            executables.insert(executable);
                        }
                        None => return Err(invalid("Cargo artifact executable field is missing")),
                    }
                    files.extend(names);
                    if files.len() > MAX_TREE_FILES {
                        return Err(invalid("Cargo artifact file count exceeds its bound"));
                    }
                }
                _ => {}
            }
        }
        if !finished || !compiled_target {
            return Err(invalid(
                "Cargo did not complete a real non-build-script target",
            ));
        }
        validate_tree_names(files.iter().map(String::as_str))?;
        Ok(Self { files, executables })
    }

    /// Dynamic minimum for the complete, quiescent tree capture.
    pub fn files(&self) -> impl Iterator<Item = &str> {
        self.files.iter().map(String::as_str)
    }

    /// Recheck reported artifacts against the complete verified manifest. Merely
    /// receiving Cargo JSON, a fingerprint file or build-finished is insufficient.
    pub fn validate_outputs<'a>(
        &self,
        files: impl IntoIterator<Item = (&'a str, bool)>,
    ) -> io::Result<()> {
        let mut observed = BTreeMap::new();
        for (name, executable) in files {
            if observed.len() >= MAX_TREE_FILES || observed.insert(name, executable).is_some() {
                return Err(invalid(
                    "duplicate or excessive Cargo output manifest entries",
                ));
            }
        }
        validate_tree_names(observed.keys().copied())?;
        if self
            .files
            .iter()
            .any(|name| !observed.contains_key(name.as_str()))
        {
            return Err(invalid(
                "Cargo-reported output is absent from the captured tree",
            ));
        }
        if self
            .executables
            .iter()
            .any(|name| observed.get(name.as_str()) != Some(&true))
        {
            return Err(invalid(
                "Cargo-reported executable lost its executable mode",
            ));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn record(kind: &str, files: &[&str], executable: Option<&str>) -> Value {
        json!({"reason":"compiler-artifact", "target":{"kind":[kind]},
            "filenames":files, "executable":executable})
    }

    fn stream(records: &[Value]) -> Vec<u8> {
        records
            .iter()
            .flat_map(|value| {
                let mut bytes = serde_json::to_vec(value).unwrap();
                bytes.push(b'\n');
                bytes
            })
            .collect()
    }

    #[test]
    fn compilation_commands_require_the_exact_output_contract() {
        let base = json!({"program":"/__rabs/toolchain/bin/cargo",
            "args":["build", "--message-format=json", "--target-dir", OUTPUT_ROOT],
            "artifacts":{"unit":"cargo", "tree":TREE_FILES_VERSION,
                "files":[], "cargo":CARGO_ARTIFACTS_VERSION}});
        assert_eq!(
            requested(&base).unwrap(),
            Some(CargoArtifactMode::Compilation)
        );
        for command in ["check", "test"] {
            let mut request = base.clone();
            request["args"][0] = json!(command);
            if command == "test" {
                assert!(requested(&request).is_err());
                request["args"]
                    .as_array_mut()
                    .unwrap()
                    .push(json!("--no-run"));
            }
            assert_eq!(
                requested(&request).unwrap(),
                Some(CargoArtifactMode::Compilation)
            );
        }
        for extra in [
            "--message-format=human",
            "--target-dir=/tmp/out",
            "--",
            "--help",
            "--no-run",
        ] {
            let mut request = base.clone();
            request["args"].as_array_mut().unwrap().push(json!(extra));
            assert!(requested(&request).is_err(), "{extra}");
        }
        for version in [Value::Null, json!(true), json!("cargo-json-v2")] {
            let mut request = base.clone();
            request["artifacts"]["cargo"] = version;
            assert!(requested(&request).is_err());
        }
        let mut plain = base;
        plain["artifacts"].as_object_mut().unwrap().remove("cargo");
        assert_eq!(requested(&plain).unwrap(), None);
    }

    fn clippy_request() -> Value {
        json!({"program":"/__rabs/toolchain/bin/cargo-clippy",
            "args":["clippy", "--workspace", "--all-targets", "--message-format=json",
                "--target-dir", OUTPUT_ROOT],
            "command_context":{"env":{"CARGO":"/__rabs/toolchain/bin/cargo",
                "RUSTC":"/__rabs/toolchain/bin/rustc"}},
            "artifacts":{"unit":"cargo", "tree":TREE_FILES_VERSION,
                "files":[], "cargo":CARGO_ARTIFACTS_VERSION}})
    }

    #[test]
    fn clippy_requires_captured_tools_and_preserves_compilation_report_semantics() {
        for lints in [
            vec![],
            vec!["-D", "warnings"],
            vec![
                "--warn=clippy::pedantic",
                "-Aclippy::module-name-repetitions",
            ],
            vec![
                "--allow",
                "dead_code",
                "-Funsafe-code",
                "--force-warn",
                "unused",
            ],
            vec!["--cap-lints=warn"],
        ] {
            let mut request = clippy_request();
            request["args"]
                .as_array_mut()
                .unwrap()
                .extend(std::iter::once("--").chain(lints).map(|arg| json!(arg)));
            assert_eq!(
                requested(&request).unwrap(),
                Some(CargoArtifactMode::Compilation)
            );
            request["artifacts"]["cargo"] = json!(CARGO_TEST_ARTIFACTS_VERSION);
            assert!(requested(&request).is_err());
        }
        for (field, value) in [("CARGO", "/usr/bin/cargo"), ("RUSTC", "rustc")] {
            let mut request = clippy_request();
            request["command_context"]["env"][field] = json!(value);
            assert!(requested(&request).is_err());
        }
        let mut request = clippy_request();
        request["program"] = json!("/__rabs/toolchain/bin/cargo");
        assert!(
            requested(&request).is_err(),
            "Cargo's external-command search is not a captured Clippy identity"
        );
        request["program"] = json!("/__rabs/toolchain/bin/cargo-clippy");
        request["args"][0] = json!("build");
        assert!(requested(&request).is_err());
    }

    #[test]
    fn clippy_lint_tail_cannot_replace_inputs_outputs_or_request_source_mutation() {
        for lints in [
            vec!["-D"],
            vec!["-D", "--emit=link"],
            vec!["-D", "warnings__CLIPPY_HACKERY__--print"],
            vec!["--warn=clippy:all"],
            vec!["--warn=clippy::all\n--print=sysroot"],
            vec!["--cap-lints=unknown"],
            vec!["--fix"],
            vec!["--emit=metadata"],
            vec!["--sysroot=/outside"],
            vec!["--out-dir=/outside"],
            vec!["--extern=other=/outside"],
            vec!["--cfg=hidden_mode"],
            vec!["-Copt-level=3"],
            vec!["-Zthreads=4"],
            vec!["@response"],
            vec!["--message-format=json", "--target-dir", OUTPUT_ROOT],
        ] {
            let mut request = clippy_request();
            request["args"].as_array_mut().unwrap().extend(
                std::iter::once("--")
                    .chain(lints.iter().copied())
                    .map(|arg| json!(arg)),
            );
            assert!(
                requested(&request).is_err(),
                "unmodeled Clippy tail: {lints:?}"
            );
        }
        for option in [
            "--fix",
            "--allow-dirty",
            "--allow-staged",
            "--allow-no-vcs",
            "--explain",
            "--no-run",
        ] {
            let mut request = clippy_request();
            request["args"].as_array_mut().unwrap().push(json!(option));
            assert!(
                requested(&request).is_err(),
                "unmodeled Clippy option: {option}"
            );
        }
        let mut request = clippy_request();
        request["args"] = json!([
            "clippy",
            "--",
            "--message-format=json",
            "--target-dir",
            OUTPUT_ROOT
        ]);
        assert!(
            requested(&request).is_err(),
            "lint arguments cannot supply Cargo controls"
        );
        assert!(validate_clippy_lints(&vec!["-Awarnings"; 129]).is_err());
        let long = format!("-A{}", "a".repeat(257));
        assert!(validate_clippy_lints(&[&long]).is_err());
        let ordinary = format!("-A{}", "a".repeat(256));
        assert!(validate_clippy_lints(&vec![ordinary.as_str(); 128]).is_err());
    }

    #[test]
    fn test_execution_requires_its_own_contract_and_keeps_harness_options_opaque() {
        let base = json!({"program":"/__rabs/toolchain/bin/cargo",
            "args":["test", "--workspace", "--message-format=json", "--target-dir", OUTPUT_ROOT],
            "artifacts":{"unit":"cargo", "tree":TREE_FILES_VERSION,
                "files":[], "cargo":CARGO_TEST_ARTIFACTS_VERSION}});
        assert_eq!(
            requested(&base).unwrap(),
            Some(CargoArtifactMode::TestExecution)
        );
        for command in ["build", "check", "run"] {
            let mut request = base.clone();
            request["args"][0] = json!(command);
            assert!(requested(&request).is_err());
        }
        let mut compilation = base.clone();
        compilation["args"]
            .as_array_mut()
            .unwrap()
            .push(json!("--no-run"));
        assert!(requested(&compilation).is_err());
        compilation["artifacts"]["cargo"] = json!(CARGO_ARTIFACTS_VERSION);
        assert_eq!(
            requested(&compilation).unwrap(),
            Some(CargoArtifactMode::Compilation)
        );
        let mut harness = base.clone();
        harness["args"].as_array_mut().unwrap().extend(
            [
                "--",
                "--nocapture",
                "--no-run",
                "--help",
                "--target-dir",
                "/elsewhere",
                "--message-format=json",
            ]
            .map(|arg| json!(arg)),
        );
        assert_eq!(
            requested(&harness).unwrap(),
            Some(CargoArtifactMode::TestExecution)
        );
        harness["artifacts"]["cargo"] = json!(CARGO_ARTIFACTS_VERSION);
        assert!(requested(&harness).is_err());
        let mut late_options = base;
        late_options["args"] = json!([
            "test",
            "--",
            "--message-format=json",
            "--target-dir",
            OUTPUT_ROOT
        ]);
        assert!(
            requested(&late_options).is_err(),
            "test arguments cannot supply Cargo controls"
        );
    }

    #[test]
    fn test_stdout_cannot_change_the_completed_cargo_artifact_report() {
        let prefix = stream(&[
            record(
                "test",
                &["/out/deps/integration-123"],
                Some("/out/deps/integration-123"),
            ),
            json!({"reason":"build-finished", "success":true}),
        ]);
        for tail in [
            b"test result: ok. 1 passed\n".as_slice(),
            b"{not a Cargo message}\n".as_slice(),
            b"{\"reason\":\"build-finished\",\"success\":false}\n".as_slice(),
            b"{\"reason\":\"compiler-artifact\",\"filenames\":[\"/outside/fake\"]}\n".as_slice(),
            b"\xff\x00unterminated test stdout".as_slice(),
        ] {
            let report = CargoArtifactReport::read(
                prefix.as_slice().chain(tail),
                "/out",
                CargoArtifactMode::TestExecution,
            )
            .unwrap();
            assert_eq!(report.files().collect::<Vec<_>>(), ["deps/integration-123"]);
            report
                .validate_outputs([("deps/integration-123", true)])
                .unwrap();
        }
        assert!(
            CargoArtifactReport::read(
                prefix
                    .as_slice()
                    .chain(b"{not a Cargo message}\n".as_slice()),
                "/out",
                CargoArtifactMode::Compilation,
            )
            .is_err(),
            "compilation-only messages must retain strict framing"
        );
        for records in [
            vec![record("test", &["/out/deps/integration-123"], None)],
            vec![
                record("test", &["/out/deps/integration-123"], None),
                json!({"reason":"build-finished", "success":false}),
            ],
            vec![
                json!({"reason":"build-finished", "success":true}),
                record("test", &["/out/deps/integration-123"], None),
            ],
        ] {
            assert!(
                CargoArtifactReport::read(
                    stream(&records).as_slice(),
                    "/out",
                    CargoArtifactMode::TestExecution,
                )
                .is_err()
            );
        }
    }

    #[test]
    fn test_stdout_has_a_total_byte_bound_without_a_json_line_limit() {
        let prefix = stream(&[
            record("test", &["/out/deps/test-123"], Some("/out/deps/test-123")),
            json!({"reason":"build-finished", "success":true}),
        ]);
        let budget = MAX_CARGO_REPORT_BYTES - prefix.len() as u64;
        assert!(
            CargoArtifactReport::read(
                prefix.as_slice().chain(io::repeat(b'x').take(budget)),
                "/out",
                CargoArtifactMode::TestExecution,
            )
            .is_ok()
        );
        assert!(
            CargoArtifactReport::read(
                prefix.as_slice().chain(io::repeat(b'x').take(budget + 1)),
                "/out",
                CargoArtifactMode::TestExecution,
            )
            .is_err()
        );
    }

    #[test]
    fn metadata_libraries_tests_and_build_script_artifacts_are_retained() {
        let bytes = stream(&[
            record(
                "custom-build",
                &["/out/build/helper"],
                Some("/out/build/helper"),
            ),
            record(
                "lib",
                &["/out/deps/libdep.rmeta", "/out/deps/libdep.rlib"],
                None,
            ),
            record(
                "test",
                &["/out/deps/integration-123"],
                Some("/out/deps/integration-123"),
            ),
            json!({"reason":"build-finished", "success":true}),
        ]);
        let report =
            CargoArtifactReport::read(bytes.as_slice(), "/out", CargoArtifactMode::Compilation)
                .unwrap();
        assert_eq!(report.files().count(), 4);
        report
            .validate_outputs([
                ("build/helper", true),
                ("deps/libdep.rmeta", false),
                ("deps/libdep.rlib", false),
                ("deps/integration-123", true),
                (".fingerprint/extra", false),
            ])
            .unwrap();
        assert!(
            report
                .validate_outputs([(".fingerprint/extra", false)])
                .is_err()
        );
        assert!(
            report
                .validate_outputs(report.files().map(|name| (name, false)))
                .is_err()
        );
    }

    #[test]
    fn missing_failed_truncated_or_late_completion_never_becomes_success() {
        let artifact = record("lib", &["/out/deps/libapp.rmeta"], None);
        for records in [
            vec![],
            vec![artifact.clone()],
            vec![
                artifact.clone(),
                json!({"reason":"build-finished", "success":false}),
            ],
            vec![
                json!({"reason":"build-finished", "success":true}),
                artifact.clone(),
            ],
            vec![
                record("custom-build", &["/out/build/helper"], None),
                json!({"reason":"build-finished", "success":true}),
            ],
        ] {
            assert!(
                CargoArtifactReport::read(
                    stream(&records).as_slice(),
                    "/out",
                    CargoArtifactMode::Compilation,
                )
                .is_err()
            );
        }
        let mut bytes = stream(&[artifact, json!({"reason":"build-finished", "success":true})]);
        bytes.pop();
        assert!(
            CargoArtifactReport::read(bytes.as_slice(), "/out", CargoArtifactMode::Compilation,)
                .is_err()
        );
    }

    #[test]
    fn traversal_aliases_and_external_executables_are_refused() {
        for paths in [
            vec!["/outside/app"],
            vec!["/out/../app"],
            vec!["/out//app"],
            vec!["/out/a", "/out/A"],
            vec!["/out/a", "/out/a/b"],
            vec!["/out/a", "/out/a"],
        ] {
            let bytes = stream(&[
                record("bin", &paths, None),
                json!({"reason":"build-finished", "success":true}),
            ]);
            assert!(
                CargoArtifactReport::read(
                    bytes.as_slice(), "/out", CargoArtifactMode::Compilation,
                ).is_err(),
                "{paths:?}"
            );
        }
        let bytes = stream(&[
            record("bin", &["/out/app"], Some("/out/other")),
            json!({"reason":"build-finished", "success":true}),
        ]);
        assert!(
            CargoArtifactReport::read(bytes.as_slice(), "/out", CargoArtifactMode::Compilation,)
                .is_err()
        );
    }

    #[test]
    fn unrelated_macro_stdout_is_retained_but_message_allocations_are_bounded() {
        let mut bytes = b"macro output \xff\n".to_vec();
        bytes.extend(stream(&[
            record("lib", &["/out/deps/libapp.rmeta"], None),
            json!({"reason":"build-finished", "success":true}),
        ]));
        assert!(
            CargoArtifactReport::read(bytes.as_slice(), "/out", CargoArtifactMode::Compilation,)
                .is_ok()
        );
        let huge = vec![b'a'; MAX_CARGO_MESSAGE_BYTES + 1];
        assert!(
            CargoArtifactReport::read(huge.as_slice(), "/out", CargoArtifactMode::Compilation,)
                .is_err()
        );
        assert!(
            CargoArtifactReport::read(
                b"{bad json}\n".as_slice(),
                "/out",
                CargoArtifactMode::Compilation,
            )
            .is_err()
        );
    }
}
