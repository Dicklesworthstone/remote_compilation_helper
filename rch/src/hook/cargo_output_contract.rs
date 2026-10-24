//! Bind named Cargo executable delivery to the completed invocation's JSON.
//!
//! Transfer globs remain useful for runtime support files, but cannot prove
//! that every requested executable was returned. This contract records Cargo's
//! actual executable paths and checks them before any staged output publishes,
//! including explicitly named test/benchmark targets built with `--no-run`.
//! Commands selecting examples keep the existing artifact policy: their
//! library metadata can belong to a separately configured Cargo build directory.

use super::artifact_patterns::cargo_bins;
use anyhow::{Context, Result};
use rch_common::CompilationKind;
use rch_telemetry::protocol::PIGGYBACK_MARKER;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::path::{Component, Path, PathBuf};

/// The transport must return the complete receipt or report an error. The
/// ordinary SSH output accumulator is smaller and must not supply this proof.
pub(crate) const MAX_CARGO_OUTPUT_RECEIPT_BYTES: usize = 64 * 1024 * 1024;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
enum TargetKind {
    Bin,
    Test,
    Bench,
}

impl TargetKind {
    fn as_str(&self) -> &'static str {
        match self {
            Self::Bin => "bin",
            Self::Test => "test",
            Self::Bench => "bench",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
struct SelectedTarget {
    kind: TargetKind,
    name: String,
}

/// Persist before execution so a replacement collector knows which Cargo
/// records the original invocation must have produced. Only the existing
/// bounded, literal named-target grammar can create an enabled capture.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub(super) struct CargoOutputCapture {
    selected: BTreeSet<SelectedTarget>,
    instrumented: bool,
}

/// Required executable paths, relative to the project/target output phase.
/// Cargo's `executable` field is authoritative; sidecars and intermediates in
/// `filenames` retain the existing transfer policy and are not this contract.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub(super) struct CargoOutputContract {
    pub(super) required_files: BTreeSet<PathBuf>,
}

#[derive(Deserialize)]
struct ArtifactTarget {
    name: String,
    kind: Vec<String>,
}

#[derive(Deserialize)]
struct CompilerArtifact {
    target: ArtifactTarget,
    filenames: Vec<String>,
    executable: Option<String>,
    // A fresh output is just as necessary to the caller as a newly built one.
    #[serde(rename = "fresh")]
    _fresh: bool,
}

impl CargoOutputCapture {
    pub(super) fn for_command(kind: Option<CompilationKind>, command: &str) -> Option<Self> {
        let selection = cargo_bins::selection(kind, command)?;
        if !selection.examples.is_empty() {
            return None;
        }
        let instrumented = match selection.message_formats.as_slice() {
            [] => true,
            [format] if explicit_json_format(format) => false,
            // Do not silently convert a caller's human/short/unknown format,
            // or resolve conflicting repeated options on Cargo's behalf.
            _ => return None,
        };
        let selected = [
            (TargetKind::Bin, selection.bins),
            (TargetKind::Test, selection.tests),
            (TargetKind::Bench, selection.benches),
        ]
        .into_iter()
        .flat_map(|(kind, names)| {
            names.into_iter().map(move |name| SelectedTarget {
                kind,
                name: name.to_owned(),
            })
        })
        .collect();
        Some(Self {
            selected,
            instrumented,
        })
    }

    /// Apply to the managed Cargo command before telemetry/timeout wrappers.
    /// Eligibility was checked against the original caller command; managed
    /// commands may legitimately contain generated quoting and config flags.
    pub(super) fn execution_command(&self, command: &str) -> String {
        if self.instrumented {
            format!("{command} --message-format=json,json-render-diagnostics")
        } else {
            command.to_owned()
        }
    }

    /// Preserve explicitly requested JSON byte for byte. For an instrumented
    /// human invocation only the well-framed Cargo control records are hidden;
    /// ordinary output and diagnostics still reach the existing display path.
    pub(super) fn suppress_stdout_line(&self, line: &str) -> bool {
        if !self.instrumented {
            return false;
        }
        let Ok(value) = serde_json::from_str::<serde_json::Value>(line) else {
            return false;
        };
        matches!(
            value.get("reason").and_then(serde_json::Value::as_str),
            Some("compiler-artifact" | "build-script-executed" | "build-finished")
        )
    }

    /// Parse the completed supervisor receipt, independently of live output
    /// truncation. The completion identity is verified by the caller before
    /// reading this immutable file. A partial set never authorizes publication.
    #[cfg(test)]
    pub(super) fn parse_receipt(
        &self,
        stdout: &[u8],
        remote_phase_root: &Path,
    ) -> Result<CargoOutputContract> {
        self.parse_receipt_with_roots(stdout, &[remote_phase_root])
    }

    /// The caller verifies these are alternate spellings of the same worker
    /// output root before supplying them. Cargo can emit either spelling even
    /// within one receipt (for example under a symlinked custom target root).
    pub(super) fn parse_receipt_with_roots(
        &self,
        stdout: &[u8],
        remote_phase_roots: &[&Path],
    ) -> Result<CargoOutputContract> {
        anyhow::ensure!(
            !self.selected.is_empty(),
            "Cargo output capture has no selected targets"
        );
        anyhow::ensure!(
            !stdout.is_empty() && stdout.len() <= MAX_CARGO_OUTPUT_RECEIPT_BYTES,
            "Cargo output receipt is empty or exceeds the 64 MiB limit"
        );
        anyhow::ensure!(
            stdout.last() == Some(&b'\n'),
            "Cargo output receipt ends in an incomplete line"
        );
        anyhow::ensure!(
            !remote_phase_roots.is_empty(),
            "Cargo output capture has no remote phase root"
        );
        for root in remote_phase_roots {
            validate_absolute_path(root)?;
            anyhow::ensure!(
                root.parent().is_some(),
                "Cargo output phase cannot be the filesystem root"
            );
        }
        let text = std::str::from_utf8(stdout).context("Cargo output receipt is not UTF-8")?;
        let mut seen = BTreeSet::new();
        let mut required_files = BTreeSet::new();
        let mut finished = false;
        for line in text.lines() {
            if line == PIGGYBACK_MARKER {
                anyhow::ensure!(
                    finished,
                    "Cargo output receipt reached telemetry before build-finished"
                );
                // The supervisor appends telemetry after Cargo's terminal
                // record. It is not compiler output or artifact authority.
                break;
            }
            let value: serde_json::Value = match serde_json::from_str(line) {
                Ok(value) => value,
                Err(error) if looks_like_cargo_record(line) => {
                    return Err(error).context("malformed JSON in Cargo output receipt");
                }
                Err(_) => continue,
            };
            let Some(reason) = value.get("reason") else {
                continue;
            };
            let reason = reason.as_str().context("invalid Cargo record reason")?;
            match reason {
                "compiler-artifact" => {
                    anyhow::ensure!(!finished, "Cargo artifact appeared after build-finished");
                    let artifact: CompilerArtifact = serde_json::from_value(value)
                        .context("malformed Cargo compiler-artifact record")?;
                    anyhow::ensure!(
                        !artifact.target.name.is_empty() && !artifact.target.kind.is_empty(),
                        "Cargo compiler-artifact has no target identity"
                    );
                    let matched: Vec<_> = self
                        .selected
                        .iter()
                        .filter(|target| {
                            target.name == artifact.target.name
                                && artifact
                                    .target
                                    .kind
                                    .iter()
                                    .any(|kind| kind == target.kind.as_str())
                        })
                        .collect();
                    if matched.is_empty() {
                        // Managed Cargo may place dependency/build-script
                        // intermediates in a separate build.build-dir. They
                        // are not selected outputs or publication authority.
                        continue;
                    }
                    let executable = artifact.executable.as_deref().with_context(|| {
                        format!(
                            "Cargo selected target {} has no executable filename",
                            artifact.target.name
                        )
                    })?;
                    anyhow::ensure!(
                        artifact
                            .filenames
                            .iter()
                            .any(|filename| filename == executable),
                        "Cargo selected target {} executable is not among its emitted filenames",
                        artifact.target.name
                    );
                    let executable = relative_output_path(executable, remote_phase_roots)?;
                    for target in matched {
                        seen.insert(target.clone());
                        required_files.insert(executable.clone());
                    }
                }
                "build-finished" => {
                    anyhow::ensure!(!finished, "duplicate Cargo build-finished record");
                    anyhow::ensure!(
                        value.get("success").and_then(serde_json::Value::as_bool) == Some(true),
                        "Cargo output receipt has no successful build-finished record"
                    );
                    finished = true;
                }
                "compiler-message" | "build-script-executed" => {
                    anyhow::ensure!(!finished, "Cargo record appeared after build-finished");
                }
                _ => {}
            }
        }
        anyhow::ensure!(finished, "Cargo output receipt is missing build-finished");
        let missing: Vec<_> = self
            .selected
            .difference(&seen)
            .map(|target| format!("{} {}", target.kind.as_str(), target.name))
            .collect();
        anyhow::ensure!(
            missing.is_empty(),
            "Cargo output receipt is missing selected executables: {}",
            missing.join(", ")
        );
        anyhow::ensure!(!required_files.is_empty(), "Cargo output contract is empty");
        Ok(CargoOutputContract { required_files })
    }
}

impl CargoOutputContract {
    /// Verify the owned staging tree, never a pre-existing local executable
    /// that could hide a failed delivery. Symlinks anywhere below the stage
    /// root cannot satisfy a required executable, even when their targets exist.
    pub(super) fn verify_staged(&self, stage_root: &Path) -> Result<()> {
        anyhow::ensure!(
            !self.required_files.is_empty(),
            "Cargo output contract is empty"
        );
        let root = std::fs::symlink_metadata(stage_root).with_context(|| {
            format!(
                "Cargo staging directory is missing: {}",
                stage_root.display()
            )
        })?;
        anyhow::ensure!(
            root.is_dir() && !root.file_type().is_symlink(),
            "Cargo staging root is not a directory: {}",
            stage_root.display()
        );
        for relative in &self.required_files {
            validate_relative_path(relative)?;
            let mut path = stage_root.to_owned();
            let mut components = relative.components().peekable();
            while let Some(component) = components.next() {
                path.push(component.as_os_str());
                let metadata = std::fs::symlink_metadata(&path).with_context(|| {
                    format!("required Cargo output is missing: {}", path.display())
                })?;
                anyhow::ensure!(
                    !metadata.file_type().is_symlink(),
                    "required Cargo output has a symlink component: {}",
                    path.display()
                );
                let correct_kind = if components.peek().is_some() {
                    metadata.is_dir()
                } else {
                    metadata.is_file()
                };
                anyhow::ensure!(
                    correct_kind,
                    "required Cargo output is not a regular file under directories: {}",
                    path.display()
                );
            }
        }
        Ok(())
    }
}

fn explicit_json_format(value: &str) -> bool {
    let mut seen = BTreeSet::new();
    value.split(',').all(|format| {
        matches!(
            format,
            "json"
                | "json-diagnostic-short"
                | "json-diagnostic-rendered-ansi"
                | "json-render-diagnostics"
        ) && seen.insert(format)
    }) && seen.contains("json")
}

fn looks_like_cargo_record(line: &str) -> bool {
    // Cargo's tagged records start with `reason`. Proc macros may print
    // arbitrary stdout, including bracket/brace-prefixed non-JSON text; that
    // output is not a malformed compiler record or artifact evidence.
    line.trim_start()
        .strip_prefix('{')
        .is_some_and(|body| body.trim_start().starts_with("\"reason\""))
}

fn validate_absolute_path(path: &Path) -> Result<()> {
    let text = path.to_str().context("Cargo output path is not UTF-8")?;
    anyhow::ensure!(
        path.is_absolute()
            && !text.contains(['\0', '\r', '\n'])
            && !text
                .split('/')
                .any(|component| matches!(component, "." | ".."))
            && path
                .components()
                .all(|component| matches!(component, Component::RootDir | Component::Normal(_))),
        "Cargo output path is not an absolute normalized path: {}",
        path.display()
    );
    Ok(())
}

fn validate_relative_path(path: &Path) -> Result<()> {
    let text = path.to_str().context("Cargo output path is not UTF-8")?;
    anyhow::ensure!(
        !text.is_empty()
            && !text.contains(['\0', '\r', '\n'])
            && !text
                .split('/')
                .any(|component| matches!(component, "." | ".."))
            && path
                .components()
                .all(|component| matches!(component, Component::Normal(_))),
        "Cargo required output is not a safe relative path: {}",
        path.display()
    );
    Ok(())
}

fn relative_output_path(name: &str, roots: &[&Path]) -> Result<PathBuf> {
    let path = Path::new(name);
    validate_absolute_path(path)?;
    // A symlink alias can itself lie below the canonical directory. Prefer
    // the most specific verified spelling, not its ancestor's apparent suffix.
    let relative = roots
        .iter()
        .filter_map(|root| {
            path.strip_prefix(root)
                .ok()
                .map(|relative| (root.components().count(), relative))
        })
        .max_by_key(|(depth, _)| *depth)
        .map(|(_, relative)| relative)
        .with_context(|| {
            format!(
                "Cargo output is outside its recorded phase root: {}",
                path.display()
            )
        })?;
    validate_relative_path(relative)?;
    Ok(relative.to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn capture(command: &str) -> CargoOutputCapture {
        CargoOutputCapture::for_command(Some(CompilationKind::CargoBuild), command).unwrap()
    }

    fn artifact(
        kind: &str,
        name: &str,
        files: &[&str],
        executable: Option<&str>,
        fresh: bool,
    ) -> serde_json::Value {
        json!({"reason":"compiler-artifact", "target":{"name":name,"kind":[kind]},
            "filenames":files,"executable":executable,"fresh":fresh})
    }

    fn receipt(records: &[serde_json::Value]) -> Vec<u8> {
        let mut text = records
            .iter()
            .map(|record| format!("{record}\n"))
            .collect::<String>();
        text.push_str("{\"reason\":\"build-finished\",\"success\":true}\n");
        text.into_bytes()
    }

    #[test]
    fn capture_reuses_literal_selection_and_preserves_explicit_formats() {
        let implicit = capture("env CARGO_TARGET_DIR=/tmp/out cargo build --bin app --bin helper");
        assert_eq!(
            implicit
                .execution_command("cargo build --bin app --bin helper --config 'build.jobs=1'"),
            "cargo build --bin app --bin helper --config 'build.jobs=1' --message-format=json,json-render-diagnostics"
        );
        let control = "{\"reason\":\"compiler-artifact\"}\n";
        assert!(implicit.suppress_stdout_line(control));
        assert!(!implicit.suppress_stdout_line("ordinary diagnostic\n"));
        assert!(!implicit.suppress_stdout_line("{\"reason\":\"compiler-artifact\""));
        for format in [
            "json",
            "json,json-render-diagnostics",
            "json,json-diagnostic-rendered-ansi",
        ] {
            let command = format!("cargo build --bin app --message-format={format}");
            let explicit = capture(&command);
            assert_eq!(explicit.execution_command(&command), command);
            assert!(!explicit.suppress_stdout_line(control));
        }
        for command in [
            "cargo build --bin app --message-format=human",
            "cargo build --bin app --message-format=short",
            "cargo build --bin app --message-format=json,human",
            "cargo build --bin app --message-format=json,json",
            "cargo build --bin app --message-format=json --message-format=json",
            "cargo build --bin app --config build.target=x86_64-unknown-linux-gnu",
            "cargo build --bin '$APP'",
            "cargo build --bins",
            "cargo build --example demo",
            "cargo build --bin app --example demo",
        ] {
            assert!(
                CargoOutputCapture::for_command(Some(CompilationKind::CargoBuild), command)
                    .is_none(),
                "{command}"
            );
        }
        assert!(
            CargoOutputCapture::for_command(
                Some(CompilationKind::CargoTest),
                "cargo test --bin app"
            )
            .is_none()
        );
    }

    #[test]
    fn named_tests_and_benches_require_cargos_own_no_run_mode() {
        for (kind, command, target_kind) in [
            (
                CompilationKind::CargoTest,
                "cargo test --no-run --test alpha --test=beta --test alpha",
                TargetKind::Test,
            ),
            (
                CompilationKind::CargoTest,
                "env CARGO_TARGET_DIR=/tmp/out rustup run nightly cargo t --test alpha --no-run --test beta --profile test",
                TargetKind::Test,
            ),
            (
                CompilationKind::CargoBench,
                "cargo +nightly bench --bench alpha --bench=beta --no-run --profile bench",
                TargetKind::Bench,
            ),
        ] {
            let capture = CargoOutputCapture::for_command(Some(kind), command).unwrap();
            assert_eq!(capture.selected.len(), 2, "{command}");
            assert!(
                capture
                    .selected
                    .iter()
                    .all(|target| target.kind == target_kind)
            );
            assert!(
                capture
                    .execution_command(command)
                    .ends_with(" --message-format=json,json-render-diagnostics")
            );
            let restored: CargoOutputCapture =
                serde_json::from_slice(&serde_json::to_vec(&capture).unwrap()).unwrap();
            assert_eq!(restored, capture);
            let explicit = format!("{command} --message-format=json");
            let capture = CargoOutputCapture::for_command(Some(kind), &explicit).unwrap();
            assert_eq!(capture.execution_command(&explicit), explicit);
            // Test/bench capture must not turn into bin-name glob narrowing.
            assert_eq!(
                crate::hook::artifact_patterns::get_artifact_patterns(Some(kind), Some(command)),
                crate::transfer::default_rust_artifact_patterns()
            );
        }
        for (kind, command) in [
            (CompilationKind::CargoTest, "cargo test --test alpha"),
            (
                CompilationKind::CargoTest,
                "cargo test --test alpha -- --no-run",
            ),
            (
                CompilationKind::CargoTest,
                "cargo test --test alpha --config --no-run",
            ),
            (
                CompilationKind::CargoTest,
                "cargo test --no-run --test alpha filter",
            ),
            (CompilationKind::CargoTest, "cargo test --no-run --lib"),
            (
                CompilationKind::CargoTest,
                "cargo test --no-run --test alpha --lib",
            ),
            (CompilationKind::CargoTest, "cargo test --no-run --tests"),
            (
                CompilationKind::CargoTest,
                "cargo test --no-run --all-targets",
            ),
            (
                CompilationKind::CargoTest,
                "cargo test --no-run --test alpha --bin tool",
            ),
            (
                CompilationKind::CargoTest,
                "cargo test --no-run --bench alpha",
            ),
            (
                CompilationKind::CargoTest,
                "cargo test --no-run --test '../alpha'",
            ),
            (
                CompilationKind::CargoTest,
                "cargo test --no-run --test alpha --message-format=human",
            ),
            (CompilationKind::CargoBench, "cargo bench --bench alpha"),
            (
                CompilationKind::CargoBench,
                "cargo bench --no-run --benches",
            ),
            (
                CompilationKind::CargoBench,
                "cargo bench --no-run --bench alpha --example demo",
            ),
            (
                CompilationKind::CargoBench,
                "cargo test --no-run --test alpha",
            ),
            (
                CompilationKind::CargoBuild,
                "cargo test --no-run --test alpha",
            ),
            (
                CompilationKind::CargoTest,
                "cargo bench --no-run --bench alpha",
            ),
        ] {
            assert!(
                CargoOutputCapture::for_command(Some(kind), command).is_none(),
                "{kind:?}: {command}"
            );
        }
    }

    #[test]
    fn no_run_receipts_require_each_target_kind_and_actual_executable_path() {
        for (kind, subcommand, selector, target_kind) in [
            (CompilationKind::CargoTest, "test", "test", "test"),
            (CompilationKind::CargoBench, "bench", "bench", "bench"),
        ] {
            let command =
                format!("cargo {subcommand} --no-run --{selector} alpha --{selector} beta");
            let capture = CargoOutputCapture::for_command(Some(kind), &command).unwrap();
            let alpha = "/worker/target/debug/deps/alpha-0123456789abcdef";
            let beta = "/worker/target/custom/build/pkg/unit/out/beta-fedcba9876543210";
            let first = artifact(target_kind, "alpha", &[alpha], Some(alpha), true);
            for wrong_kind in ["bin", "lib", "example"] {
                let incomplete = receipt(&[
                    first.clone(),
                    artifact(wrong_kind, "beta", &[beta], Some(beta), true),
                ]);
                let error = capture
                    .parse_receipt(&incomplete, Path::new("/worker/target"))
                    .unwrap_err();
                assert!(error.to_string().contains(&format!("{target_kind} beta")));
            }
            let complete = receipt(&[
                first,
                artifact(target_kind, "beta", &[beta], Some(beta), true),
            ]);
            let contract = capture
                .parse_receipt(&complete, Path::new("/worker/target"))
                .unwrap();
            assert_eq!(
                contract.required_files,
                BTreeSet::from([
                    PathBuf::from("debug/deps/alpha-0123456789abcdef"),
                    PathBuf::from("custom/build/pkg/unit/out/beta-fedcba9876543210"),
                ])
            );
        }
    }

    #[test]
    fn emitted_executables_cover_each_selected_binary_including_fresh_outputs() {
        let capture = capture("cargo build --bin app --bin helper");
        let data = receipt(&[
            // Intermediates may be outside the final target root under the
            // managed command's independent build.build-dir.
            artifact(
                "lib",
                "dependency",
                &["/worker/build-intermediates/debug/deps/libdep.rlib"],
                None,
                true,
            ),
            artifact(
                "bin",
                "app",
                &[
                    "/worker/target/debug/surprising-name",
                    "/worker/target/debug/symbols.pdb",
                    "/worker/target/debug/app-executable",
                ],
                Some("/worker/target/debug/app-executable"),
                true,
            ),
            artifact(
                "example",
                "app",
                &["/worker/target/debug/examples/app"],
                Some("/worker/target/debug/examples/app"),
                false,
            ),
            // The required-file contract is specifically executable delivery.
            // A reported sidecar bundle or intermediate retains normal policy.
            artifact(
                "bin",
                "helper",
                &[
                    "/worker/target/debug/helper.dSYM",
                    "/worker/build-intermediates/helper.rmeta",
                    "/worker/target/debug/custom-helper-name",
                ],
                Some("/worker/target/debug/custom-helper-name"),
                true,
            ),
        ]);
        let contract = capture
            .parse_receipt(&data, Path::new("/worker/target"))
            .unwrap();
        let expected: BTreeSet<PathBuf> = ["debug/app-executable", "debug/custom-helper-name"]
            .into_iter()
            .map(PathBuf::from)
            .collect();
        assert_eq!(contract.required_files, expected);
        let project = capture.parse_receipt(&data, Path::new("/worker")).unwrap();
        assert!(
            project
                .required_files
                .iter()
                .all(|path| path.starts_with("target"))
        );
        let restored: CargoOutputCapture =
            serde_json::from_slice(&serde_json::to_vec(&capture).unwrap()).unwrap();
        assert_eq!(
            restored
                .parse_receipt(&data, Path::new("/worker/target"))
                .unwrap(),
            contract
        );
    }

    #[test]
    fn unrelated_output_cannot_satisfy_missing_selected_target() {
        let capture = capture("cargo build --bin app --bin helper");
        let data = receipt(&[
            artifact(
                "bin",
                "app",
                &["/worker/target/debug/app"],
                Some("/worker/target/debug/app"),
                true,
            ),
            artifact(
                "example",
                "helper",
                &["/worker/target/debug/examples/helper"],
                Some("/worker/target/debug/examples/helper"),
                true,
            ),
            artifact(
                "lib",
                "helper",
                &["/worker/target/debug/libhelper.so"],
                None,
                true,
            ),
        ]);
        let error = capture
            .parse_receipt(&data, Path::new("/worker/target"))
            .unwrap_err();
        assert!(error.to_string().contains("bin helper"));
        assert!(
            capture
                .parse_receipt(&receipt(&[]), Path::new("/worker/target"))
                .is_err()
        );
    }

    #[test]
    fn verified_root_aliases_map_mixed_cargo_spelling_to_one_output_tree() {
        let capture = capture("cargo build --bin app --bin helper");
        let data = receipt(&[
            artifact(
                "bin",
                "app",
                &["/real/target/debug/app"],
                Some("/real/target/debug/app"),
                true,
            ),
            artifact(
                "bin",
                "helper",
                &["/worker/alias/debug/helper"],
                Some("/worker/alias/debug/helper"),
                true,
            ),
        ]);
        let contract = capture
            .parse_receipt_with_roots(
                &data,
                &[Path::new("/worker/alias"), Path::new("/real/target")],
            )
            .unwrap();
        assert_eq!(
            contract.required_files,
            [PathBuf::from("debug/app"), PathBuf::from("debug/helper")]
                .into_iter()
                .collect()
        );
        assert!(
            capture
                .parse_receipt(&data, Path::new("/worker/alias"))
                .is_err()
        );
        assert!(capture.parse_receipt_with_roots(&data, &[]).is_err());
        let capture = self::capture("cargo build --bin app");
        let nested = receipt(&[artifact(
            "bin",
            "app",
            &["/real/target/alias/debug/app"],
            Some("/real/target/alias/debug/app"),
            true,
        )]);
        let contract = capture
            .parse_receipt_with_roots(
                &nested,
                &[Path::new("/real/target"), Path::new("/real/target/alias")],
            )
            .unwrap();
        assert_eq!(
            contract.required_files,
            [PathBuf::from("debug/app")].into_iter().collect()
        );
    }

    #[test]
    fn receipt_requires_a_complete_successful_terminal_record() {
        let capture = capture("cargo build --bin app");
        let output = artifact(
            "bin",
            "app",
            &["/worker/target/debug/app"],
            Some("/worker/target/debug/app"),
            false,
        );
        let valid = receipt(std::slice::from_ref(&output));
        let root = Path::new("/worker/target");
        let incomplete = &valid[..valid.len() - 1];
        assert!(capture.parse_receipt(incomplete, root).is_err());
        assert!(
            capture
                .parse_receipt(format!("{output}\n").as_bytes(), root)
                .is_err()
        );
        for tail in [
            "{\"reason\":\"build-finished\",\"success\":false}\n",
            "{\"reason\":\"build-finished\"}\n",
            "{\"reason\":\"build-finished\",\"success\":true}\n{\"reason\":\"build-finished\",\"success\":true}\n",
            "{\"reason\":\"compiler-artifact\"\n",
            "  {  \"reason\":\"compiler-artifact\"\n",
        ] {
            assert!(
                capture
                    .parse_receipt(format!("{output}\n{tail}").as_bytes(), root)
                    .is_err(),
                "{tail}"
            );
        }
        let mut late = valid.clone();
        late.extend_from_slice(format!("{output}\n").as_bytes());
        assert!(capture.parse_receipt(&late, root).is_err());
        let mut with_telemetry = valid;
        with_telemetry
            .extend_from_slice(format!("{PIGGYBACK_MARKER}\n{{\"worker\":\"test\"}}\n").as_bytes());
        capture.parse_receipt(&with_telemetry, root).unwrap();
        let incidental = format!(
            "[generator] ready\n{{generator}} ready\n{output}\n[generator] done\n{{\"reason\":\"build-finished\",\"success\":true}}\n"
        );
        capture.parse_receipt(incidental.as_bytes(), root).unwrap();
        let oversized = vec![b'\n'; MAX_CARGO_OUTPUT_RECEIPT_BYTES + 1];
        assert!(capture.parse_receipt(&oversized, root).is_err());
    }

    #[test]
    fn receipt_rejects_unsafe_paths_empty_outputs_and_non_executables() {
        let capture = capture("cargo build --bin app");
        for name in [
            "/elsewhere/app",
            "/worker/target-other/app",
            "/worker/target/debug/../app",
            "/worker/target/./app",
            "debug/app",
            "/worker/target",
            "/worker/target/a\nb",
            "/worker/target/a\0b",
        ] {
            let data = receipt(&[artifact("bin", "app", &[name], Some(name), true)]);
            assert!(
                capture
                    .parse_receipt(&data, Path::new("/worker/target"))
                    .is_err(),
                "{name:?}"
            );
        }
        for output in [
            artifact("bin", "app", &[], Some("/worker/target/debug/app"), true),
            artifact("bin", "app", &["/worker/target/debug/app"], None, true),
            artifact(
                "bin",
                "app",
                &["/worker/target/debug/unrelated"],
                Some("/worker/target/debug/app"),
                true,
            ),
            json!({"reason":"compiler-artifact","target":{"kind":["bin"],"name":"app"},"filenames":["/worker/target/debug/app"],"executable":"/worker/target/debug/app"}),
        ] {
            assert!(
                capture
                    .parse_receipt(&receipt(&[output]), Path::new("/worker/target"))
                    .is_err()
            );
        }
    }

    #[test]
    fn staged_contract_cannot_use_existing_outputs_to_hide_a_missing_file() {
        let root = tempfile::tempdir().unwrap();
        let stage = root.path().join("stage");
        let local = root.path().join("local");
        std::fs::create_dir_all(stage.join("debug")).unwrap();
        std::fs::create_dir_all(local.join("debug")).unwrap();
        std::fs::write(local.join("debug/helper"), b"old helper").unwrap();
        std::fs::write(stage.join("debug/app"), b"new app").unwrap();
        std::fs::write(stage.join("debug/libsupport.so"), b"support").unwrap();
        let contract = CargoOutputContract {
            required_files: ["debug/app", "debug/helper"]
                .into_iter()
                .map(PathBuf::from)
                .collect(),
        };
        assert!(contract.verify_staged(&stage).is_err());
        assert_eq!(
            std::fs::read(local.join("debug/helper")).unwrap(),
            b"old helper"
        );
        std::fs::write(stage.join("debug/helper"), b"new helper").unwrap();
        contract.verify_staged(&stage).unwrap();
        let restored: CargoOutputContract =
            serde_json::from_slice(&serde_json::to_vec(&contract).unwrap()).unwrap();
        restored.verify_staged(&stage).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn staged_contract_rejects_symlink_files_and_directories() {
        let root = tempfile::tempdir().unwrap();
        let stage = root.path().join("stage");
        let outside = root.path().join("outside");
        std::fs::create_dir_all(&stage).unwrap();
        std::fs::create_dir_all(&outside).unwrap();
        std::fs::write(outside.join("app"), b"wrong tree").unwrap();
        std::os::unix::fs::symlink(&outside, stage.join("linked-dir")).unwrap();
        std::os::unix::fs::symlink(outside.join("app"), stage.join("linked-file")).unwrap();
        for name in ["linked-dir/app", "linked-file", "../outside/app"] {
            let contract = CargoOutputContract {
                required_files: [PathBuf::from(name)].into_iter().collect(),
            };
            assert!(contract.verify_staged(&stage).is_err(), "{name}");
        }
    }
}
