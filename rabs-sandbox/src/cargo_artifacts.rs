//! Cargo-selected output names for canonical build, check and test compilation.
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
/// Bound the whole stream, including non-JSON output from procedural macros.
pub const MAX_CARGO_REPORT_BYTES: u64 = 64 * 1024 * 1024;
/// Do not allocate an unbounded line before checking the stream budget.
pub const MAX_CARGO_MESSAGE_BYTES: usize = 1024 * 1024;
const OUTPUT_ROOT: &str = "/__rabs/out/cargo";

fn invalid(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

/// Validate the command as well as the version before execution admission.
/// The JSON contract applies only to compilation commands, never run/test output
/// after build-finished. The caller separately validates the artifact names.
pub fn requested(request: &Value) -> io::Result<bool> {
    let Some(contract) = request
        .get("artifacts")
        .and_then(|value| value.get("cargo"))
    else {
        return Ok(false);
    };
    if contract.as_str() != Some(CARGO_ARTIFACTS_VERSION)
        || request["artifacts"]["tree"].as_str() != Some(TREE_FILES_VERSION)
        || request["artifacts"]["unit"].as_str() != Some("cargo")
        || request["program"].as_str() != Some("/__rabs/toolchain/bin/cargo")
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
    if !matches!(command, "build" | "check" | "test") {
        return Err(invalid(
            "Cargo artifact contract requires build, check or test --no-run",
        ));
    }
    let mut format = false;
    let mut target = false;
    let mut no_run = false;
    let mut at = 1;
    while at < args.len() {
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
            "--no-run" | "--" | "--help" | "-h" | "--version" | "-V" => {
                return Err(invalid(
                    "Cargo artifact command does not compile the selected targets",
                ));
            }
            _ => {}
        }
        at += 1;
    }
    if !format || !target || (command == "test" && !no_run) {
        return Err(invalid("incomplete Cargo compilation artifact contract"));
    }
    Ok(true)
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
    /// procedural macro stdout. Malformed JSON-shaped records fail closed.
    pub fn read(reader: impl Read, output_root: &str) -> io::Result<Self> {
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
        assert!(requested(&base).unwrap());
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
            assert!(requested(&request).unwrap());
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
        assert!(!requested(&plain).unwrap());
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
        let report = CargoArtifactReport::read(bytes.as_slice(), "/out").unwrap();
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
            assert!(CargoArtifactReport::read(stream(&records).as_slice(), "/out").is_err());
        }
        let mut bytes = stream(&[artifact, json!({"reason":"build-finished", "success":true})]);
        bytes.pop();
        assert!(CargoArtifactReport::read(bytes.as_slice(), "/out").is_err());
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
                CargoArtifactReport::read(bytes.as_slice(), "/out").is_err(),
                "{paths:?}"
            );
        }
        let bytes = stream(&[
            record("bin", &["/out/app"], Some("/out/other")),
            json!({"reason":"build-finished", "success":true}),
        ]);
        assert!(CargoArtifactReport::read(bytes.as_slice(), "/out").is_err());
    }

    #[test]
    fn unrelated_macro_stdout_is_retained_but_message_allocations_are_bounded() {
        let mut bytes = b"macro output \xff\n".to_vec();
        bytes.extend(stream(&[
            record("lib", &["/out/deps/libapp.rmeta"], None),
            json!({"reason":"build-finished", "success":true}),
        ]));
        assert!(CargoArtifactReport::read(bytes.as_slice(), "/out").is_ok());
        let huge = vec![b'a'; MAX_CARGO_MESSAGE_BYTES + 1];
        assert!(CargoArtifactReport::read(huge.as_slice(), "/out").is_err());
        assert!(CargoArtifactReport::read(b"{bad json}\n".as_slice(), "/out").is_err());
    }
}
