//! Bind Cargo output delivery to the completed invocation's JSON.
//!
//! Transfer globs remain useful for runtime support files, but cannot prove
//! that every requested executable was returned. This contract records Cargo's
//! actual executable paths and checks them before any staged output publishes,
//! including explicitly named test/benchmark targets built with `--no-run`.
//! Supported ordinary full builds and explicit retrieval exclusions also bind
//! selected libraries, examples, and sidecars while keeping Cargo's separate
//! compiler intermediates private.

use super::artifact_patterns::cargo_bins;
use anyhow::{Context, Result};
use rch_common::CompilationKind;
use rch_telemetry::protocol::PIGGYBACK_MARKER;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Component, Path, PathBuf};

#[cfg(test)]
#[path = "cargo_output_contract/default_build_tests.rs"]
mod default_build_tests;

/// The transport must return the complete receipt or report an error. The
/// ordinary SSH output accumulator is smaller and must not supply this proof.
pub(crate) const MAX_CARGO_OUTPUT_RECEIPT_BYTES: usize = 64 * 1024 * 1024;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
enum TargetKind {
    Bin,
    Example,
    Test,
    Bench,
}

impl TargetKind {
    fn as_str(&self) -> &'static str {
        match self {
            Self::Bin => "bin",
            Self::Example => "example",
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
/// records the original invocation must have produced. Named executable
/// capture and supported human-output full builds are automatic; explicit
/// retrieval exclusions require complete evidence for the same bounded grammar.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub(super) struct CargoOutputCapture {
    selected: BTreeSet<SelectedTarget>,
    instrumented: bool,
    /// Complete delivery needs every originally selected Cargo output,
    /// including libraries and sidecars. Freeze the original policy so detached
    /// collection cannot silently use current configuration instead.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    retrieval_baseline: Option<Vec<String>>,
    /// Distinguish automatic full-build proof from an opt-in exclusion policy.
    /// Legacy recipes default to false: losing their configured exclusions
    /// must never be reinterpreted as a newly admitted automatic contract.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    automatic_complete_outputs: bool,
    /// Broad selectors combined with a named target still require the other
    /// selected target-root outputs during detached collection.
    #[serde(default)]
    broad_targets: bool,
    /// Earlier recipes never admitted examples to caller JSON. Only an
    /// explicit, literal JSON command can grant this mode on resumption.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    named_example_json: bool,
}

/// Required executable paths, relative to the project/target output phase.
/// Cargo's `executable` field is authoritative. With retrieval exclusions,
/// originally selected `filenames` also become required, protecting libraries
/// and sidecars without promoting private intermediates into deliverables.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub(super) struct CargoOutputContract {
    pub(super) required_files: BTreeSet<PathBuf>,
    /// Cargo lists macOS debug-symbol bundles in `filenames`, although they
    /// are directory trees. Their contents must be collected and validated as
    /// a whole instead of treating the bundle root as a regular file.
    #[serde(default, skip_serializing_if = "BTreeSet::is_empty")]
    pub(super) required_directories: BTreeSet<PathBuf>,
}

pub(super) struct CargoCallerPaths<'a> {
    pub(super) remote_output_roots: &'a [&'a Path],
    pub(super) local_output_root: &'a Path,
    pub(super) remote_project_roots: &'a [&'a Path],
    pub(super) local_project_root: &'a Path,
    pub(super) published: &'a BTreeMap<PathBuf, String>,
    pub(super) receipt_binding: &'a serde_json::Value,
}

pub(super) struct CargoCallerOutput {
    pub(super) stdout: Vec<u8>,
    /// Only caller-visible selected files need another fingerprint read.
    pub(super) files: BTreeSet<PathBuf>,
}

#[derive(Deserialize)]
struct ArtifactTarget {
    name: String,
    kind: Vec<String>,
    #[serde(default)]
    crate_types: Vec<String>,
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
    /// Build selections may combine named binaries and examples. A test or
    /// benchmark selection must be homogeneous and use Cargo's --no-run mode.
    /// Restored human-output recipes cannot opt into caller JSON.
    pub(super) fn caller_json_supported(&self) -> bool {
        let Some(first) = self.selected.first() else {
            return false;
        };
        if self.instrumented || self.broad_targets {
            return false;
        }
        if self.named_example_json {
            return self
                .selected
                .iter()
                .any(|target| target.kind == TargetKind::Example)
                && self
                    .selected
                    .iter()
                    .all(|target| matches!(target.kind, TargetKind::Bin | TargetKind::Example));
        }
        first.kind != TargetKind::Example
            && self.selected.iter().all(|target| target.kind == first.kind)
    }

    /// Share target/mode validation between pre-publication checks and the
    /// caller projection. Cargo sets profile.test for both tests and benches,
    /// including harness=false targets; it describes the compilation mode,
    /// not whether libtest supplied main(). An unrelated binary may have the
    /// same name as a selected integration test and must remain unprojected.
    fn caller_target(&self, value: &serde_json::Value) -> Result<Option<&SelectedTarget>> {
        if value.get("reason").and_then(serde_json::Value::as_str) != Some("compiler-artifact") {
            return Ok(None);
        }
        let Some(name) = value
            .pointer("/target/name")
            .and_then(serde_json::Value::as_str)
        else {
            return Ok(None);
        };
        let kinds = value
            .pointer("/target/kind")
            .and_then(serde_json::Value::as_array)
            .context("Cargo target kinds are not an array")?;
        let Some(target) = self.selected.iter().find(|target| {
            target.name == name
                && kinds
                    .iter()
                    .any(|kind| kind.as_str() == Some(target.kind.as_str()))
        }) else {
            return Ok(None);
        };
        anyhow::ensure!(
            kinds.len() == 1
                && value.get("executable").is_some()
                && value
                    .pointer("/profile/test")
                    .and_then(serde_json::Value::as_bool)
                    == Some(matches!(target.kind, TargetKind::Test | TargetKind::Bench)),
            "caller JSON selected an ambiguous target or a different compilation mode"
        );
        Ok(Some(target))
    }

    pub(super) fn for_command(kind: Option<CompilationKind>, command: &str) -> Option<Self> {
        let selection = cargo_bins::selection(kind, command)?;
        let instrumented = match selection.message_formats.as_slice() {
            [] => true,
            [format] if explicit_json_format(format) => false,
            // Do not silently convert a caller's human/short/unknown format,
            // or resolve conflicting repeated options on Cargo's behalf.
            _ => return None,
        };
        let named_example_json = !selection.examples.is_empty();
        if named_example_json && instrumented {
            // Human-output examples already use the complete retrieval baseline,
            // including library examples that Cargo reports without an executable.
            return None;
        }
        let selected = [
            (TargetKind::Bin, selection.bins),
            (TargetKind::Example, selection.examples),
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
            retrieval_baseline: None,
            automatic_complete_outputs: false,
            broad_targets: false,
            named_example_json,
        })
    }

    pub(super) fn for_retrieval_policy(
        kind: Option<CompilationKind>,
        command: &str,
        baseline: &[String],
        directories: &[String],
    ) -> Result<Option<Self>> {
        let automatic_complete_outputs = directories.is_empty();
        if automatic_complete_outputs {
            let named = Self::for_command(kind, command);
            if named.is_some()
                || baseline.is_empty()
                || !matches!(
                    kind,
                    Some(
                        CompilationKind::CargoBuild
                            | CompilationKind::CargoTest
                            | CompilationKind::CargoBench
                    )
                )
            {
                return Ok(named);
            }
        }
        let selection = match cargo_bins::retrieval_selection(kind, command) {
            Some(selection) => selection,
            None if automatic_complete_outputs => return Ok(None),
            None => anyhow::bail!(
                "transfer.cargo_retrieval_exclude_dirs requires a supported literal Cargo build, zigbuild, or test/bench --no-run command with a complete output receipt"
            ),
        };
        if automatic_complete_outputs && !selection.message_formats.is_empty() {
            // This lane instruments only the default human output. Explicit
            // formats and unsupported commands keep their existing contract;
            // they cannot acquire a guessed or partial output proof.
            return Ok(None);
        }
        retrieval_baseline_filters(baseline)?;
        let instrumented = match selection.message_formats.as_slice() {
            [] => true,
            [format] if explicit_json_format(format) => false,
            _ => anyhow::bail!(
                "transfer.cargo_retrieval_exclude_dirs cannot establish complete outputs with this Cargo --message-format"
            ),
        };
        anyhow::ensure!(
            instrumented
                || Self::for_command(kind, command)
                    .is_some_and(|capture| capture.caller_json_supported()),
            "Cargo retrieval exclusions require human output for a full build; caller JSON projection requires named build outputs or --no-run executables"
        );
        let named_example_json = !instrumented && !selection.examples.is_empty();
        let selected = [
            (TargetKind::Bin, selection.bins),
            (TargetKind::Example, selection.examples),
            (TargetKind::Test, selection.tests),
            (TargetKind::Bench, selection.benches),
        ]
        .into_iter()
        .flat_map(|(kind, names)| {
            names
                .into_iter()
                .map(move |name| SelectedTarget { kind, name })
        })
        .collect();
        Ok(Some(Self {
            selected,
            instrumented,
            retrieval_baseline: Some(baseline.to_vec()),
            automatic_complete_outputs,
            broad_targets: selection.broad_targets,
            named_example_json,
        }))
    }

    pub(super) fn retrieval_baseline(&self) -> Option<&[String]> {
        self.retrieval_baseline.as_deref()
    }

    pub(super) fn automatic_complete_outputs(&self) -> bool {
        self.automatic_complete_outputs
    }

    /// A restored recipe must retain both its original positive selection and
    /// a capture mode that can prove every selected output. A baseline alone
    /// cannot turn an unsupported caller JSON stream into complete evidence.
    pub(super) fn supports_retrieval_exclusions(&self) -> bool {
        self.retrieval_exclusion_filters().is_ok()
    }

    fn retrieval_exclusion_filters(&self) -> Result<crate::transfer::ArtifactFilters> {
        let baseline = self
            .retrieval_baseline()
            .context("Cargo retrieval exclusions lack an original output baseline")?;
        anyhow::ensure!(
            !self.automatic_complete_outputs || self.instrumented,
            "automatic Cargo output capture lost its human-output instrumentation"
        );
        anyhow::ensure!(
            self.instrumented || self.caller_json_supported(),
            "Cargo retrieval exclusions lack a supported complete output capture mode"
        );
        retrieval_baseline_filters(baseline)
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
            !self.selected.is_empty() || self.retrieval_baseline.is_some(),
            "Cargo output capture has no selected targets"
        );
        let retrieval_filters = self
            .retrieval_baseline
            .as_ref()
            .map(|_| self.retrieval_exclusion_filters())
            .transpose()?;
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
        let mut required_directories = BTreeSet::new();
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
                    let named_example = self.named_example_json
                        && matched.iter().any(|target| target.kind == TargetKind::Example);
                    if named_example {
                        validate_named_example(&artifact)?;
                        for filename in &artifact.filenames {
                            anyhow::ensure!(
                                !filename.chars().any(char::is_control),
                                "Cargo example filename contains a control character"
                            );
                            let relative = relative_output_path(filename, remote_phase_roots)?;
                            if relative.extension().is_some_and(|ext| ext == "dSYM") {
                                required_directories.insert(relative);
                            } else {
                                required_files.insert(relative);
                            }
                        }
                    }
                    if let Some(filters) = &retrieval_filters {
                        // Private build-script and separate build-directory
                        // outputs are exceptions to delivery, not to receipt
                        // validation. Check every declared path before either
                        // exception can discard an unsafe filename.
                        for filename in artifact.filenames.iter().chain(artifact.executable.iter())
                        {
                            validate_absolute_path(Path::new(filename))?;
                            anyhow::ensure!(
                                !filename.chars().any(char::is_control),
                                "Cargo output filename contains a control character"
                            );
                        }
                        anyhow::ensure!(
                            artifact.target.kind.iter().all(|kind| matches!(
                                kind.as_str(),
                                "bin"
                                    | "example"
                                    | "test"
                                    | "bench"
                                    | "lib"
                                    | "rlib"
                                    | "dylib"
                                    | "cdylib"
                                    | "staticlib"
                                    | "proc-macro"
                                    | "custom-build"
                            )),
                            "Cargo retrieval exclusions cannot establish an unknown target kind"
                        );
                        // Build-script executables belong to Cargo's private
                        // cache, not its deliverables. Every other filename
                        // must be understood before an exclusion can be used.
                        let build_script = artifact
                            .target
                            .kind
                            .iter()
                            .any(|kind| kind == "custom-build");
                        anyhow::ensure!(
                            !build_script || artifact.target.kind.len() == 1,
                            "ambiguous Cargo build-script target kinds"
                        );
                        if !build_script {
                            anyhow::ensure!(
                                !artifact.filenames.is_empty(),
                                "Cargo compiler-artifact has no emitted filenames"
                            );
                            anyhow::ensure!(
                                artifact.executable.is_some()
                                    || !artifact.target.kind.iter().any(|kind| {
                                        matches!(kind.as_str(), "bin" | "test" | "bench")
                                    }),
                                "Cargo executable target has no executable filename"
                            );
                            if let Some(executable) = &artifact.executable {
                                anyhow::ensure!(
                                    artifact.filenames.contains(executable),
                                    "Cargo executable is not among its emitted filenames"
                                );
                                // Executables are required even when a newer
                                // Cargo layout places them under build/. The
                                // publisher adds an exact priority include.
                                required_files
                                    .insert(relative_output_path(executable, remote_phase_roots)?);
                            }
                            let library_intermediate = artifact.executable.is_none()
                                && artifact.target.kind.iter().all(|kind| {
                                    matches!(
                                        kind.as_str(),
                                        "lib"
                                            | "rlib"
                                            | "dylib"
                                            | "cdylib"
                                            | "staticlib"
                                            | "proc-macro"
                                    )
                                });
                            let relevant = artifact.executable.is_some()
                                || self.broad_targets
                                || self.selected.is_empty()
                                || !matched.is_empty();
                            let mut has_deliverable = false;
                            for filename in &artifact.filenames {
                                let path = Path::new(filename);
                                let private_intermediate =
                                    path.extension().is_some_and(|extension| {
                                        extension == "rlib"
                                            || extension == "rmeta"
                                            || (artifact.target.kind.as_slice() == ["proc-macro"]
                                                && matches!(
                                                    extension.to_str(),
                                                    Some("so" | "dylib")
                                                ))
                                    });
                                if library_intermediate
                                    && private_intermediate
                                    && remote_phase_roots
                                        .iter()
                                        .all(|root| !path.starts_with(root))
                                {
                                    // Cargo may place rlib/rmeta intermediates
                                    // and compiler plugins in a separate
                                    // build.build-dir. Target-root exclusions
                                    // cannot affect them. Executables and
                                    // runtime/static libraries remain bound
                                    // to the admitted output roots.
                                    continue;
                                }
                                let relative = relative_output_path(filename, remote_phase_roots)?;
                                let name =
                                    relative.to_str().context("non-UTF-8 Cargo output path")?;
                                let directory = relative
                                    .extension()
                                    .is_some_and(|extension| extension == "dSYM");
                                // A sidecar-only glob such as `*.dSYM/**`
                                // selects the bundle contents without matching
                                // its bare root, which is what Cargo reports.
                                let admitted = artifact.executable.as_ref() == Some(filename)
                                    || filters.selects(name)
                                    || (directory && filters.selects(&format!("{name}/")));
                                let metadata = path.extension().is_some_and(|extension| {
                                    matches!(extension.to_str(), Some("rmeta" | "d"))
                                });
                                // Private outside-root intermediates above do
                                // not belong to delivery. For returning targets,
                                // another crate type or executable must not hide
                                // a missing library format or required sidecar.
                                anyhow::ensure!(
                                    !relevant || metadata || admitted,
                                    "Cargo artifact policy omits required output {} for target {}; refusing a partial output set",
                                    relative.display(),
                                    artifact.target.name
                                );
                                if admitted {
                                    has_deliverable |= !metadata;
                                    if directory {
                                        required_directories.insert(relative);
                                    } else {
                                        required_files.insert(relative);
                                    }
                                }
                            }
                            anyhow::ensure!(
                                has_deliverable
                                    || !matched
                                        .iter()
                                        .any(|target| target.kind == TargetKind::Example),
                                "Cargo selected example {} has no admitted deliverable",
                                artifact.target.name
                            );
                        }
                        for target in matched {
                            seen.insert(target.clone());
                        }
                        continue;
                    }
                    if matched.is_empty() {
                        // Managed Cargo may place dependency/build-script
                        // intermediates in a separate build.build-dir. They
                        // are not selected outputs or publication authority.
                        continue;
                    }
                    if named_example {
                        seen.extend(matched.into_iter().cloned());
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
                _ => {
                    anyhow::ensure!(
                        retrieval_filters.is_none(),
                        "Cargo retrieval exclusions cannot establish complete outputs from unknown Cargo record reason {reason:?}"
                    );
                }
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
            "Cargo output receipt is missing selected targets: {}",
            missing.join(", ")
        );
        anyhow::ensure!(
            !required_files.is_empty() || !required_directories.is_empty(),
            "Cargo output contract is empty"
        );
        Ok(CargoOutputContract {
            required_files,
            required_directories,
        })
    }

    /// Validate selected caller metadata before any file can be published and
    /// return every filename advertised by those records, including sidecars.
    pub(super) fn validate_caller_metadata(
        &self,
        stdout: &[u8],
        remote_output_roots: &[&Path],
        remote_project_roots: &[&Path],
        local_project_root: &Path,
    ) -> Result<BTreeSet<PathBuf>> {
        anyhow::ensure!(
            self.caller_json_supported(),
            "caller JSON requires named build outputs or --no-run executables and an explicit JSON format"
        );
        self.parse_receipt_with_roots(stdout, remote_output_roots)?;
        let mut selected = BTreeSet::new();
        let mut executables = BTreeSet::new();
        let mut required_files = BTreeSet::new();
        for line in std::str::from_utf8(stdout)?.lines() {
            if line == PIGGYBACK_MARKER {
                break;
            }
            let Ok(value) = serde_json::from_str::<serde_json::Value>(line) else {
                continue;
            };
            let Some(target) = self.caller_target(&value)? else {
                continue;
            };
            // One selector can match several workspace packages, and Cargo
            // can build each target for more than one platform. The emitted
            // executable distinguishes those records, not the selector name.
            // Repeated or colliding executable paths remain ambiguous: one
            // published file cannot independently satisfy both Cargo records.
            selected.insert(target.clone());
            if let Some(executable) = value["executable"].as_str() {
                anyhow::ensure!(
                    executables.insert(relative_output_path(executable, remote_output_roots)?),
                    "caller JSON has duplicate or colliding selected executable paths"
                );
            }
            let manifest = value
                .get("manifest_path")
                .and_then(serde_json::Value::as_str)
                .context("selected Cargo record has no manifest path")?;
            let relative = relative_output_path(manifest, remote_project_roots)?;
            anyhow::ensure!(
                relative
                    .file_name()
                    .is_some_and(|name| name == "Cargo.toml"),
                "selected Cargo manifest is not Cargo.toml"
            );
            let local = local_project_root
                .join(relative)
                .canonicalize()
                .context("selected caller Cargo manifest is unavailable")?;
            anyhow::ensure!(
                local.starts_with(local_project_root) && local.is_file(),
                "selected caller Cargo manifest escapes its source root"
            );
            if let Some(source) = value
                .pointer("/target/src_path")
                .and_then(serde_json::Value::as_str)
            {
                relative_output_path(source, remote_project_roots)?;
            }
            for filename in value
                .get("filenames")
                .and_then(serde_json::Value::as_array)
                .context("selected Cargo record has no filenames")?
            {
                let filename = filename
                    .as_str()
                    .context("selected Cargo filename is not a string")?;
                let relative = relative_output_path(filename, remote_output_roots)?;
                let new = required_files.insert(relative);
                anyhow::ensure!(
                    new || !self.named_example_json,
                    "caller JSON has duplicate or colliding selected output paths"
                );
            }
            anyhow::ensure!(
                value.get("rch").is_none(),
                "Cargo record already contains an RCH binding"
            );
        }
        anyhow::ensure!(
            selected == self.selected,
            "caller JSON did not bind every selected target"
        );
        Ok(required_files)
    }

    /// Project selected executable records into the caller's delivered tree.
    /// The caller checks publication fingerprints under the output-root lock.
    /// Unselected dependency records retain their original worker metadata.
    pub(super) fn caller_json(
        &self,
        stdout: &[u8],
        paths: &CargoCallerPaths<'_>,
    ) -> Result<CargoCallerOutput> {
        let CargoCallerPaths {
            remote_output_roots,
            local_output_root,
            remote_project_roots,
            local_project_root,
            published,
            receipt_binding,
        } = paths;
        anyhow::ensure!(
            self.caller_json_supported(),
            "caller JSON requires named build outputs or --no-run executables and an explicit JSON format"
        );
        let contract = self.parse_receipt_with_roots(stdout, remote_output_roots)?;
        self.validate_caller_metadata(
            stdout,
            remote_output_roots,
            remote_project_roots,
            local_project_root,
        )?;
        validate_absolute_path(local_output_root)?;
        for root in *remote_project_roots {
            validate_absolute_path(root)?;
        }
        validate_absolute_path(local_project_root)?;
        anyhow::ensure!(
            contract
                .required_files
                .iter()
                .all(|file| published.contains_key(file)),
            "caller JSON cannot name an executable outside this invocation's published set"
        );
        for directory in &contract.required_directories {
            anyhow::ensure!(
                published
                    .keys()
                    .any(|path| path != directory && path.starts_with(directory)),
                "caller JSON cannot name a bundle without published contents: {}",
                directory.display()
            );
        }
        let mut output = Vec::new();
        let mut all_files = BTreeSet::new();
        for line in std::str::from_utf8(stdout)?.split_inclusive('\n') {
            if line.trim_end_matches(['\r', '\n']) == PIGGYBACK_MARKER {
                break;
            }
            let Ok(mut value) = serde_json::from_str::<serde_json::Value>(line) else {
                output.extend_from_slice(line.as_bytes());
                continue;
            };
            if self.caller_target(&value)?.is_none() {
                output.extend_from_slice(line.as_bytes());
                continue;
            }
            let original = value.clone();
            let mut files = BTreeSet::new();
            let manifest = value
                .get("manifest_path")
                .and_then(serde_json::Value::as_str)
                .context("selected Cargo record has no manifest path")?;
            let relative_manifest = relative_output_path(manifest, remote_project_roots)?;
            anyhow::ensure!(
                relative_manifest
                    .file_name()
                    .is_some_and(|name| name == "Cargo.toml"),
                "selected Cargo manifest is not Cargo.toml"
            );
            let local_manifest = local_project_root.join(relative_manifest);
            let canonical_manifest = local_manifest
                .canonicalize()
                .context("selected caller Cargo manifest is unavailable")?;
            anyhow::ensure!(
                canonical_manifest.starts_with(local_project_root) && canonical_manifest.is_file(),
                "selected caller Cargo manifest escapes its source root"
            );
            value["manifest_path"] = serde_json::to_value(canonical_manifest)?;
            let executable = original["executable"]
                .as_str()
                .map(|path| relative_output_path(path, remote_output_roots))
                .transpose()?;
            if let Some(relative) = &executable {
                value["executable"] = serde_json::to_value(local_output_root.join(relative))?;
            }
            let filenames = original
                .get("filenames")
                .and_then(serde_json::Value::as_array)
                .context("selected Cargo record has no filenames")?;
            let mut local_filenames = Vec::new();
            for filename in filenames {
                let filename = filename
                    .as_str()
                    .context("selected Cargo filename is not a string")?;
                let relative = relative_output_path(filename, remote_output_roots)?;
                if relative
                    .extension()
                    .is_some_and(|extension| extension == "dSYM")
                {
                    let mut descendants = 0usize;
                    for path in published
                        .keys()
                        .filter(|path| *path != &relative && path.starts_with(&relative))
                    {
                        validate_relative_path(path)?;
                        files.insert(path.clone());
                        descendants += 1;
                    }
                    anyhow::ensure!(
                        descendants > 0,
                        "selected Cargo bundle has no published contents: {}",
                        relative.display()
                    );
                } else {
                    anyhow::ensure!(
                        published.contains_key(&relative),
                        "selected Cargo filename was not published by this invocation: {}",
                        relative.display()
                    );
                    files.insert(relative.clone());
                }
                local_filenames.push(local_output_root.join(&relative));
            }
            value["filenames"] = serde_json::to_value(local_filenames)?;
            if let Some(source) = original
                .pointer("/target/src_path")
                .and_then(serde_json::Value::as_str)
            {
                let relative = relative_output_path(source, remote_project_roots)?;
                value["target"]["src_path"] =
                    serde_json::to_value(local_project_root.join(relative))?;
            }
            anyhow::ensure!(
                value.get("rch").is_none(),
                "Cargo record already contains an RCH binding"
            );
            value["rch"] = serde_json::json!({
                "worker_record": original,
                "receipt": receipt_binding,
            });
            if let Some(relative) = executable {
                let hash = published
                    .get(&relative)
                    .context("selected executable has no publication fingerprint")?;
                value["rch"]["executable_blake3"] = serde_json::to_value(hash)?;
            } else {
                // Library examples have no executable. Bind the files and bundle
                // members copied to this invocation's private delivery directory.
                let hashes: BTreeMap<_, _> = files
                    .iter()
                    .map(|path| (path, &published[path]))
                    .collect();
                value["rch"]["file_blake3"] = serde_json::to_value(hashes)?;
            }
            all_files.extend(files);
            serde_json::to_writer(&mut output, &value)?;
            output.push(b'\n');
        }
        Ok(CargoCallerOutput {
            stdout: output,
            files: all_files,
        })
    }
}

impl CargoOutputContract {
    /// Staged presence cannot prove delivery if the publication filters later
    /// reject required files or any part of a required bundle. Check the exact
    /// partition before the publisher changes its journal or destination.
    pub(super) fn validate_publication_selection(&self, outside: &[PathBuf]) -> Result<()> {
        for path in outside {
            anyhow::ensure!(
                !self.required_files.contains(path)
                    && !path
                        .ancestors()
                        .any(|ancestor| self.required_directories.contains(ancestor)),
                "required Cargo output is outside the effective publication policy: {}",
                path.display()
            );
        }
        Ok(())
    }

    /// Verify the owned staging tree, never a pre-existing local executable
    /// that could hide a failed delivery. Symlinks anywhere below the stage
    /// root cannot satisfy a required executable, even when their targets exist.
    pub(super) fn verify_staged(&self, stage_root: &Path) -> Result<()> {
        anyhow::ensure!(
            !self.required_files.is_empty() || !self.required_directories.is_empty(),
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
        for (relative, directory) in self
            .required_files
            .iter()
            .map(|path| (path, false))
            .chain(self.required_directories.iter().map(|path| (path, true)))
        {
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
                let correct_kind = if components.peek().is_some() || directory {
                    metadata.is_dir()
                } else {
                    metadata.is_file()
                };
                anyhow::ensure!(
                    correct_kind,
                    "required Cargo output has an unexpected file type: {}",
                    path.display()
                );
            }
            if directory {
                anyhow::ensure!(
                    directory_has_output(&path)?,
                    "required Cargo output bundle is empty: {}",
                    path.display()
                );
            }
        }
        Ok(())
    }
}

/// Cargo examples can be binaries or libraries. A JSON null executable is
/// meaningful only for a declared library with its primary output present.
fn validate_named_example(artifact: &CompilerArtifact) -> Result<()> {
    let types = &artifact.target.crate_types;
    anyhow::ensure!(
        artifact.target.kind.as_slice() == ["example"] && !types.is_empty(),
        "selected Cargo example has no unambiguous crate type"
    );
    if let Some(executable) = &artifact.executable {
        anyhow::ensure!(
            types.as_slice() == ["bin"] && artifact.filenames.contains(executable),
            "Cargo example executable contradicts its crate types or filenames"
        );
    } else {
        for kind in types {
            let extensions: &[&str] = match kind.as_str() {
                "lib" | "rlib" => &["rlib"],
                "staticlib" => &["a", "lib"],
                "cdylib" | "dylib" | "proc-macro" => &["so", "dylib", "dll", "wasm"],
                _ => anyhow::bail!("unsupported crate type for library example: {kind}"),
            };
            anyhow::ensure!(
                artifact.filenames.iter().any(|name| {
                    // Windows emits an import archive alongside a DLL. Both
                    // MSVC and GNU use an archive extension for that sidecar.
                    let path = Path::new(name);
                    let import_archive = path
                        .file_stem()
                        .and_then(|stem| Path::new(stem).extension())
                        .and_then(|inner| inner.to_str())
                        .is_some_and(|inner| inner.eq_ignore_ascii_case("dll"));
                    path.extension()
                        .and_then(|ext| ext.to_str())
                        .is_some_and(|ext| extensions.contains(&ext))
                        && !(kind == "staticlib" && import_archive)
                }),
                "Cargo library example is missing its {kind} output"
            );
        }
    }
    Ok(())
}

fn directory_has_output(root: &Path) -> Result<bool> {
    let mut pending = vec![root.to_owned()];
    let mut inspected = 0usize;
    let mut has_output = false;
    while let Some(directory) = pending.pop() {
        for entry in std::fs::read_dir(directory)? {
            inspected += 1;
            anyhow::ensure!(
                inspected <= 100_000,
                "Cargo output bundle exceeds inspection bound"
            );
            let entry = entry?;
            let kind = entry.file_type()?;
            anyhow::ensure!(!kind.is_symlink(), "Cargo output bundle contains a symlink");
            if kind.is_file() {
                has_output = true;
                continue;
            }
            anyhow::ensure!(kind.is_dir(), "Cargo output bundle contains a special file");
            pending.push(entry.path());
        }
    }
    Ok(has_output)
}

fn retrieval_baseline_filters(baseline: &[String]) -> Result<crate::transfer::ArtifactFilters> {
    anyhow::ensure!(
        baseline.iter().any(|pattern| !pattern.starts_with("- ")),
        "Cargo retrieval exclusions require a nonempty positive output baseline"
    );
    crate::transfer::ArtifactFilters::from_patterns(baseline)
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

    #[test]
    fn named_xwin_instrumentation_preserves_the_actual_plugin_argv() {
        let command = "cargo +nightly xwin build --locked --release --target x86_64-pc-windows-msvc --bin cli";
        let capture =
            CargoOutputCapture::for_command(Some(CompilationKind::CargoBuild), command).unwrap();
        assert_eq!(
            capture.execution_command(command),
            format!("{command} --message-format=json,json-render-diagnostics")
        );
        assert!(!capture.caller_json_supported());
        let explicit = format!("{command} --message-format=json");
        let capture =
            CargoOutputCapture::for_command(Some(CompilationKind::CargoBuild), &explicit).unwrap();
        assert_eq!(capture.execution_command(&explicit), explicit);
        assert!(capture.caller_json_supported());
        let reconstructed = "cargo +nightly xwin build '--target=x86_64-pc-windows-msvc' --bin cli '--message-format=json'";
        let classification = rch_common::classify_command(reconstructed);
        assert_eq!(classification.kind, Some(CompilationKind::CargoBuild));
        let capture = CargoOutputCapture::for_command(classification.kind, reconstructed).unwrap();
        assert!(capture.caller_json_supported());
        assert_eq!(capture.execution_command(reconstructed), reconstructed);
    }

    #[test]
    fn caller_json_support_requires_explicit_named_executable_json() {
        for (command, expected) in [
            (
                "cargo build --bin cli --bin alias --locked --release --message-format=json,json-render-diagnostics",
                true,
            ),
            ("cargo build --bin cli --message-format=json", true),
            ("cargo build --bin cli", false),
            ("cargo build --bins --message-format=json", false),
            ("cargo build --bin cli --message-format=human", false),
            ("cargo build --example cli --message-format=json", true),
            ("cargo build --bin cli --example cli --message-format=json", true),
            (
                "cargo xwin build --release --target x86_64-pc-windows-msvc --bin cli --message-format=json",
                true,
            ),
            (
                "cargo-xwin xwin build --bin cli --message-format=json,json-render-diagnostics",
                true,
            ),
            ("cargo xwin build --bins --message-format=json", false),
            ("cargo xwin check --bin cli --message-format=json", false),
        ] {
            assert_eq!(
                CargoOutputCapture::for_command(Some(CompilationKind::CargoBuild), command)
                    .is_some_and(|capture| capture.caller_json_supported()),
                expected,
                "{command}"
            );
        }
        for (kind, selector) in [
            (CompilationKind::CargoTest, "test"),
            (CompilationKind::CargoBench, "bench"),
        ] {
            for (arguments, expected) in [
                ("--no-run --message-format=json", true),
                (
                    "--no-run --message-format=json,json-render-diagnostics",
                    true,
                ),
                ("--message-format=json", false),
                ("--no-run", false),
                ("--no-run --message-format=human", false),
                ("--message-format=json -- --no-run", false),
                ("--no-run --all-targets --message-format=json", false),
            ] {
                let command = format!("cargo {selector} --{selector} integration {arguments}");
                assert_eq!(
                    CargoOutputCapture::for_command(Some(kind), &command)
                        .is_some_and(|capture| capture.caller_json_supported()),
                    expected,
                    "{command}"
                );
            }
        }
        let mut mixed = capture("cargo build --bin cli --message-format=json");
        mixed.selected.insert(SelectedTarget {
            kind: TargetKind::Test,
            name: "integration".to_owned(),
        });
        assert!(!mixed.caller_json_supported());
    }

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

    fn retrieval_capture(command: &str) -> CargoOutputCapture {
        let kind = rch_common::classify_command(command).kind;
        let baseline = super::super::artifact_patterns::get_custom_target_artifact_patterns(
            kind,
            Some(command),
        );
        CargoOutputCapture::for_retrieval_policy(
            kind,
            command,
            &baseline,
            &["debug/.wrapper-shims".into()],
        )
        .unwrap()
        .unwrap()
    }

    #[test]
    fn cargo_retrieval_capture_requires_valid_positive_baselines_and_supported_restored_modes() {
        let kind = Some(CompilationKind::CargoBuild);
        let baseline = vec!["debug/**".into(), "- debug/.cache/".into()];
        let directories = vec!["debug/.wrapper-shims".into()];
        let make = |command: &str| {
            CargoOutputCapture::for_retrieval_policy(kind, command, &baseline, &directories)
                .unwrap()
                .unwrap()
        };
        let stdout = receipt(&[artifact(
            "bin",
            "app",
            &["/target/debug/app"],
            Some("/target/debug/app"),
            true,
        )]);
        for invalid in [
            vec![],
            vec!["- debug/.cache/".into()],
            vec![String::new()],
            vec!["debug/[".into()],
            vec!["+ ".into()],
        ] {
            assert!(
                CargoOutputCapture::for_retrieval_policy(
                    kind,
                    "cargo build --workspace",
                    &invalid,
                    &directories,
                )
                .is_err(),
                "{invalid:?}"
            );
            // Without the setting, capture keeps its original behavior even
            // when the unused retrieval baseline would not establish outputs.
            assert_eq!(
                CargoOutputCapture::for_retrieval_policy(
                    kind,
                    "cargo build --bin app",
                    &invalid,
                    &[],
                )
                .unwrap(),
                CargoOutputCapture::for_command(kind, "cargo build --bin app")
            );
            let mut corrupt = make("cargo build --workspace");
            corrupt.retrieval_baseline = Some(invalid);
            let restored: CargoOutputCapture =
                serde_json::from_slice(&serde_json::to_vec(&corrupt).unwrap()).unwrap();
            assert!(!restored.supports_retrieval_exclusions());
            assert!(
                restored
                    .parse_receipt(&stdout, Path::new("/target"))
                    .is_err()
            );
        }
        for command in [
            "cargo build --workspace",
            "cargo build --bin app",
            "cargo build --bin app --message-format=json",
        ] {
            let original = make(command);
            let restored: CargoOutputCapture =
                serde_json::from_slice(&serde_json::to_vec(&original).unwrap()).unwrap();
            assert!(restored.supports_retrieval_exclusions(), "{command}");
            restored
                .parse_receipt(&stdout, Path::new("/target"))
                .unwrap();
        }
        for command in [
            "cargo build --workspace",
            "cargo build --bin app --bins",
            "cargo build --example sample",
            "cargo build --bin app --test suite",
        ] {
            let mut corrupt = make(command);
            corrupt.instrumented = false;
            let restored: CargoOutputCapture =
                serde_json::from_slice(&serde_json::to_vec(&corrupt).unwrap()).unwrap();
            assert!(!restored.supports_retrieval_exclusions(), "{command}");
            let error = restored
                .parse_receipt(&stdout, Path::new("/target"))
                .unwrap_err();
            assert!(
                error
                    .to_string()
                    .contains("supported complete output capture mode")
            );
        }
        assert!(!capture("cargo build --bin app").supports_retrieval_exclusions());
    }

    #[test]
    fn cargo_retrieval_capture_validates_private_artifact_paths_before_skipping() {
        let capture = CargoOutputCapture::for_retrieval_policy(
            Some(CompilationKind::CargoBuild),
            "cargo build --workspace",
            &["debug/**".into(), "- debug/build/".into()],
            &["debug/.wrapper-shims".into()],
        )
        .unwrap()
        .unwrap();
        let app = artifact(
            "bin",
            "app",
            &["/target/debug/app"],
            Some("/target/debug/app"),
            true,
        );
        let script = "/cache/debug/build/package/build-script-build";
        let contract = capture
            .parse_receipt(
                &receipt(&[
                    app.clone(),
                    artifact(
                        "custom-build",
                        "build-script-build",
                        &[script],
                        Some(script),
                        true,
                    ),
                    artifact(
                        "lib",
                        "dependency",
                        &[
                            "/cache/debug/deps/libdependency.rlib",
                            "/cache/debug/deps/libdependency.rmeta",
                        ],
                        None,
                        true,
                    ),
                    artifact(
                        "proc-macro",
                        "macro",
                        &["/cache/debug/deps/libmacro.so"],
                        None,
                        true,
                    ),
                ]),
                Path::new("/target"),
            )
            .unwrap();
        assert_eq!(contract.required_files, [PathBuf::from("debug/app")].into());
        assert!(contract.required_directories.is_empty());
        for invalid in [
            "relative/libdependency.rlib",
            "/cache/./libdependency.rlib",
            "/cache/../libdependency.rlib",
            "/cache/lib\tdependency.rlib",
            "/cache/lib\u{7f}dependency.rlib",
            "/cache/lib\0dependency.rlib",
        ] {
            for invalid_record in [
                artifact(
                    "custom-build",
                    "build-script-build",
                    &[invalid],
                    Some(script),
                    true,
                ),
                artifact(
                    "custom-build",
                    "build-script-build",
                    &[script],
                    Some(invalid),
                    true,
                ),
                artifact("lib", "dependency", &[invalid], None, true),
            ] {
                assert!(
                    capture
                        .parse_receipt(
                            &receipt(&[app.clone(), invalid_record]),
                            Path::new("/target")
                        )
                        .is_err(),
                    "{invalid:?}"
                );
            }
        }
        // This stricter proof belongs only to the opt-in complete receipt.
        CargoOutputCapture::for_command(Some(CompilationKind::CargoBuild), "cargo build --bin app")
            .unwrap()
            .parse_receipt(
                &receipt(&[
                    app,
                    artifact(
                        "custom-build",
                        "build-script-build",
                        &["relative"],
                        Some("relative"),
                        true,
                    ),
                ]),
                Path::new("/target"),
            )
            .unwrap();
    }

    #[test]
    fn cargo_retrieval_capture_requires_each_named_example_to_have_a_deliverable() {
        let capture = CargoOutputCapture::for_retrieval_policy(
            Some(CompilationKind::CargoBuild),
            "cargo build --bin app --example sample",
            &["debug/**".into(), "- **/*.d".into(), "- **/*.rmeta".into()],
            &["debug/.wrapper-shims".into()],
        )
        .unwrap()
        .unwrap();
        let app = artifact(
            "bin",
            "app",
            &["/target/debug/app"],
            Some("/target/debug/app"),
            true,
        );
        for extension in ["d", "rmeta"] {
            let relative = format!("debug/examples/sample.{extension}");
            let output = format!("/target/{relative}");
            for admitted in [false, true] {
                let mut selection = capture.clone();
                if admitted {
                    selection
                        .retrieval_baseline
                        .as_mut()
                        .unwrap()
                        .push(format!("+ {relative}"));
                }
                let error = selection
                    .parse_receipt(
                        &receipt(&[
                            app.clone(),
                            artifact("example", "sample", &[output.as_str()], None, true),
                        ]),
                        Path::new("/target"),
                    )
                    .unwrap_err();
                assert!(
                    error
                        .to_string()
                        .contains("selected example sample has no admitted deliverable")
                );
            }
        }
        for (files, executable, required, bundle) in [
            (
                &["/target/debug/examples/libsample.rlib"][..],
                None,
                "debug/examples/libsample.rlib",
                None,
            ),
            (
                &[
                    "/target/debug/examples/sample",
                    "/target/debug/examples/sample.dSYM",
                ][..],
                Some("/target/debug/examples/sample"),
                "debug/examples/sample",
                Some("debug/examples/sample.dSYM"),
            ),
        ] {
            let example = artifact("example", "sample", files, executable, true);
            // Repeated valid fresh records may name an already-required path.
            // Deliverability is a property of this record, not set growth.
            let contract = capture
                .parse_receipt(
                    &receipt(&[app.clone(), example.clone(), example]),
                    Path::new("/target"),
                )
                .unwrap();
            assert_eq!(
                contract.required_files,
                [PathBuf::from("debug/app"), PathBuf::from(required)].into()
            );
            assert_eq!(
                contract.required_directories,
                bundle.into_iter().map(PathBuf::from).collect()
            );
        }
    }

    #[test]
    fn cargo_retrieval_capture_instruments_supported_zigbuild_commands() {
        let kind = Some(CompilationKind::CargoZigbuild);
        let baseline = vec!["*/lean/**".into(), "- **/*.rmeta".into()];
        let directories = vec!["aarch64-unknown-linux-gnu/lean/.wrapper-shims".into()];
        let app = "/target/aarch64-unknown-linux-gnu/lean/app";
        let bundle = "/target/aarch64-unknown-linux-gnu/lean/app.dSYM";
        let library = "/target/aarch64-unknown-linux-gnu/lean/libsupport.rlib";
        let stdout = receipt(&[
            artifact("bin", "app", &[app, bundle], Some(app), true),
            artifact("lib", "support", &[library], None, true),
            artifact(
                "lib",
                "dependency",
                &["/cache/debug/deps/libdependency.rlib"],
                None,
                true,
            ),
        ]);
        for command in [
            "cargo zigbuild --profile lean --target aarch64-unknown-linux-gnu --workspace",
            "cargo +nightly zigbuild --profile=lean --bin app --lib",
            "env -i /opt/bin/cargo-zigbuild build --profile lean --lib",
            "env -- cargo-zigbuild b --profile lean --bin app",
            "cargo-zigbuild zigbuild --profile lean",
        ] {
            let capture =
                CargoOutputCapture::for_retrieval_policy(kind, command, &baseline, &directories)
                    .unwrap()
                    .unwrap();
            assert!(capture.supports_retrieval_exclusions());
            assert!(!capture.caller_json_supported());
            assert_eq!(
                capture.execution_command(command),
                format!("{command} --message-format=json,json-render-diagnostics")
            );
            assert!(CargoOutputCapture::for_command(kind, command).is_none());
            assert!(
                CargoOutputCapture::for_retrieval_policy(kind, command, &baseline, &[])
                    .unwrap()
                    .is_none()
            );
            let restored: CargoOutputCapture =
                serde_json::from_slice(&serde_json::to_vec(&capture).unwrap()).unwrap();
            let contract = restored
                .parse_receipt(&stdout, Path::new("/target"))
                .unwrap();
            assert_eq!(
                contract.required_files,
                [
                    PathBuf::from("aarch64-unknown-linux-gnu/lean/app"),
                    PathBuf::from("aarch64-unknown-linux-gnu/lean/libsupport.rlib")
                ]
                .into()
            );
            assert_eq!(
                contract.required_directories,
                [PathBuf::from("aarch64-unknown-linux-gnu/lean/app.dSYM")].into()
            );
        }
        for command in [
            "cargo zigbuild --bin app --message-format=json",
            "cargo-zigbuild build --bin app --message-format=json",
            "cargo zigbuild --message-format=short",
            "cargo zigbuild --target universal2-apple-darwin",
            "cargo-zigbuild build --target x86_64-apple-darwin --target=universal2-apple-darwin",
            "cargo-zigbuild +nightly build",
            "rustup run nightly cargo-zigbuild b --profile lean --bin app",
            "cargo zigbuild --target aarch64-unknown-linux-gnu.2.17",
            "cargo zigbuild --no-run",
            "cargo-zigbuild test --no-run",
            "cargo build",
        ] {
            assert!(
                CargoOutputCapture::for_retrieval_policy(kind, command, &baseline, &directories)
                    .is_err(),
                "{command}"
            );
        }
    }

    #[test]
    fn cargo_retrieval_capture_requires_complete_returning_target_outputs() {
        let full = retrieval_capture("cargo build --workspace");
        let app = artifact(
            "bin",
            "app",
            &["/target/debug/app"],
            Some("/target/debug/app"),
            true,
        );
        for incomplete in [
            artifact(
                "lib",
                "core",
                &["/target/debug/build/libcore.rlib"],
                None,
                true,
            ),
            artifact(
                "lib",
                "core",
                &[
                    "/target/debug/deps/libcore.rlib",
                    "/target/debug/build/libcore.so",
                ],
                None,
                true,
            ),
            artifact(
                "bin",
                "other",
                &["/target/debug/build/other", "/target/debug/build/other.pdb"],
                Some("/target/debug/build/other"),
                true,
            ),
            artifact(
                "bin",
                "other",
                &[
                    "/target/debug/build/other",
                    "/target/debug/build/other.dSYM",
                ],
                Some("/target/debug/build/other"),
                true,
            ),
        ] {
            assert!(
                full.parse_receipt(&receipt(&[app.clone(), incomplete]), Path::new("/target"))
                    .is_err()
            );
        }
        let named = retrieval_capture("cargo build --bin app");
        let extra = "/target/debug/build/other";
        let dependency = artifact(
            "lib",
            "dependency",
            &["/target/debug/build/libdependency.rlib"],
            None,
            true,
        );
        let outputs = receipt(&[
            app.clone(),
            dependency.clone(),
            artifact("test", "suite", &[extra], Some(extra), true),
        ]);
        assert_eq!(
            named
                .parse_receipt(&outputs, Path::new("/target"))
                .unwrap()
                .required_files,
            BTreeSet::from([
                PathBuf::from("debug/app"),
                PathBuf::from("debug/build/other")
            ])
        );
        for sidecar in [
            "/target/debug/build/other.pdb",
            "/target/debug/build/other.dSYM",
        ] {
            assert!(
                named
                    .parse_receipt(
                        &receipt(&[
                            app.clone(),
                            artifact("bin", "other", &[extra, sidecar], Some(extra), true),
                        ]),
                        Path::new("/target")
                    )
                    .is_err(),
                "{sidecar}"
            );
        }
        for flag in [
            "--lib",
            "--bins",
            "--examples",
            "--tests",
            "--benches",
            "--all-targets",
        ] {
            let capture = retrieval_capture(&format!("cargo build --bin app {flag}"));
            let restored: CargoOutputCapture =
                serde_json::from_slice(&serde_json::to_vec(&capture).unwrap()).unwrap();
            assert!(restored.broad_targets);
            assert!(
                restored
                    .parse_receipt(
                        &receipt(&[app.clone(), dependency.clone()]),
                        Path::new("/target")
                    )
                    .is_err(),
                "{flag}"
            );
        }
    }

    #[test]
    fn cargo_retrieval_capture_preserves_all_explicit_target_obligations() {
        let app = artifact(
            "bin",
            "app",
            &["/target/debug/app"],
            Some("/target/debug/app"),
            true,
        );
        for command in [
            "cargo build --example sample",
            "cargo build --test suite",
            "cargo build --bench speed",
            "cargo build --bin app --example sample",
            "cargo build --bin app --lib --example sample",
            "cargo test --no-run --example sample",
            "cargo bench --no-run --bin other",
        ] {
            assert!(
                retrieval_capture(command)
                    .parse_receipt(&receipt(std::slice::from_ref(&app)), Path::new("/target"))
                    .is_err(),
                "{command}"
            );
        }
        let example = retrieval_capture("cargo build --example sample");
        let data = receipt(&[artifact(
            "example",
            "sample",
            &["/target/debug/examples/libsample.rlib"],
            None,
            true,
        )]);
        assert_eq!(
            example
                .parse_receipt(&data, Path::new("/target"))
                .unwrap()
                .required_files,
            BTreeSet::from([PathBuf::from("debug/examples/libsample.rlib")])
        );
        let named_json = retrieval_capture("cargo build --bin app --message-format=json");
        assert!(named_json.caller_json_supported());
        let bundle = receipt(&[artifact(
            "bin",
            "app",
            &["/target/debug/app", "/target/debug/app.dSYM"],
            Some("/target/debug/app"),
            true,
        )]);
        assert_eq!(
            named_json
                .parse_receipt(&bundle, Path::new("/target"))
                .unwrap()
                .required_directories,
            BTreeSet::from([PathBuf::from("debug/app.dSYM")])
        );
    }

    #[test]
    fn cargo_retrieval_capture_keeps_private_intermediates_outside_returning_contract() {
        let capture = retrieval_capture("cargo build --workspace");
        let app = artifact(
            "bin",
            "app",
            &["/target/debug/app"],
            Some("/target/debug/app"),
            true,
        );
        let core = artifact(
            "lib",
            "core",
            &[
                "/target/debug/libcore.rlib",
                "/cache/debug/deps/libcore.rlib",
                "/cache/debug/deps/libcore.rmeta",
            ],
            None,
            true,
        );
        let contract = capture
            .parse_receipt(
                &receipt(&[
                    app.clone(),
                    core.clone(),
                    artifact(
                        "lib",
                        "dependency",
                        &["/cache/debug/deps/libdependency.rlib"],
                        None,
                        true,
                    ),
                    artifact(
                        "proc-macro",
                        "macro",
                        &["/cache/debug/deps/libmacro.so"],
                        None,
                        true,
                    ),
                ]),
                Path::new("/target"),
            )
            .unwrap();
        assert_eq!(
            contract.required_files,
            BTreeSet::from([
                PathBuf::from("debug/app"),
                PathBuf::from("debug/libcore.rlib"),
            ])
        );
        for incomplete in [
            artifact(
                "lib",
                "core",
                &["/target/debug/libcore.rlib", "/cache/debug/libcore.so"],
                None,
                true,
            ),
            artifact(
                "bin",
                "app",
                &["/target/debug/app", "/cache/debug/app.pdb"],
                Some("/target/debug/app"),
                true,
            ),
            artifact(
                "bin",
                "app",
                &["/target/debug/app", "/cache/debug/app.dSYM"],
                Some("/target/debug/app"),
                true,
            ),
            artifact("lib", "core", &["/cache/debug/libcore\t.rlib"], None, true),
        ] {
            assert!(
                capture
                    .parse_receipt(
                        &receipt(&[app.clone(), core.clone(), incomplete]),
                        Path::new("/target")
                    )
                    .is_err()
            );
        }
    }

    #[test]
    fn cargo_retrieval_capture_refuses_unknown_protocol_records_and_target_kinds() {
        let full = retrieval_capture("cargo build");
        let app = artifact(
            "bin",
            "app",
            &["/target/debug/app"],
            Some("/target/debug/app"),
            true,
        );
        for unknown in [
            artifact(
                "future-kind",
                "future",
                &["/target/debug/future"],
                None,
                true,
            ),
            json!({"reason":"future-artifact","filenames":["/target/debug/future"]}),
        ] {
            let data = receipt(&[app.clone(), unknown]);
            assert!(full.parse_receipt(&data, Path::new("/target")).is_err());
            assert!(
                capture("cargo build --bin app")
                    .parse_receipt(&data, Path::new("/target"))
                    .is_ok()
            );
        }
        let ordinary = [
            "proc macro diagnostic text",
            "[macro debug text]",
            "{\"macro_debug\":\"ordinary JSON\"}",
        ];
        let mut data = ordinary.join("\n").into_bytes();
        data.push(b'\n');
        data.extend(receipt(&[
            app,
            json!({"reason":"compiler-message","message":{"rendered":"diagnostic"}}),
            json!({"reason":"build-script-executed","out_dir":"/target/debug/build/generated"}),
        ]));
        assert!(full.parse_receipt(&data, Path::new("/target")).is_ok());
        for line in ordinary {
            assert!(!full.suppress_stdout_line(line));
        }
    }

    #[test]
    fn cargo_retrieval_capture_protects_full_fresh_library_and_binary_sets() {
        let kind = Some(CompilationKind::CargoBuild);
        let baseline = super::super::artifact_patterns::get_custom_target_artifact_patterns(
            kind,
            Some("cargo build --workspace"),
        );
        let capture = CargoOutputCapture::for_retrieval_policy(
            kind,
            "cargo build --workspace",
            &baseline,
            &["debug/.wrapper-shims".into()],
        )
        .unwrap()
        .unwrap();
        assert!(!capture.caller_json_supported());
        assert!(
            capture
                .execution_command("cargo build --workspace")
                .ends_with(" --message-format=json,json-render-diagnostics")
        );
        let records = [
            artifact(
                "lib",
                "core",
                &[
                    "/target/debug/deps/libcore.rlib",
                    "/target/debug/deps/libcore.so",
                ],
                None,
                true,
            ),
            artifact(
                "bin",
                "app",
                &["/target/debug/app", "/target/debug/app.pdb"],
                Some("/target/debug/app"),
                true,
            ),
            artifact(
                "bin",
                "helper",
                &["/target/debug/helper"],
                Some("/target/debug/helper"),
                false,
            ),
            artifact(
                "custom-build",
                "build-script-build",
                &["/outside/private/build-script-build"],
                Some("/outside/private/build-script-build"),
                true,
            ),
        ];
        let contract = capture
            .parse_receipt(&receipt(&records), Path::new("/target"))
            .unwrap();
        assert_eq!(
            contract.required_files,
            BTreeSet::from([
                "debug/deps/libcore.rlib".into(),
                "debug/deps/libcore.so".into(),
                "debug/app".into(),
                "debug/app.pdb".into(),
                "debug/helper".into(),
            ])
        );
        assert!(
            capture
                .parse_receipt(&receipt(&[]), Path::new("/target"))
                .is_err()
        );
        assert!(
            capture
                .parse_receipt(
                    &receipt(&[artifact(
                        "bin",
                        "outside",
                        &["/outside/app"],
                        Some("/outside/app"),
                        true
                    )]),
                    Path::new("/target")
                )
                .is_err()
        );
        let missing_terminal = format!("{}\n", records[0]);
        assert!(
            capture
                .parse_receipt(missing_terminal.as_bytes(), Path::new("/target"))
                .is_err()
        );
        let restored: CargoOutputCapture =
            serde_json::from_slice(&serde_json::to_vec(&capture).unwrap()).unwrap();
        assert_eq!(
            restored
                .parse_receipt(&receipt(&records), Path::new("/target"))
                .unwrap(),
            contract
        );
    }

    #[test]
    fn cargo_retrieval_capture_refuses_unsupported_argv_and_formats() {
        let kind = Some(CompilationKind::CargoBuild);
        let baseline = super::super::artifact_patterns::get_custom_target_artifact_patterns(
            kind,
            Some("cargo build"),
        );
        for command in [
            "cargo build --message-format=json",
            "cargo build --message-format=short",
            "cargo build --message-format=human",
            "cargo build --message-format=json --message-format=json",
            "cargo build --out-dir /outside",
            "cargo build && echo done",
            "cargo build -- --message-format=json",
            "cargo build --config alias.build=other",
        ] {
            assert!(
                CargoOutputCapture::for_retrieval_policy(
                    kind,
                    command,
                    &baseline,
                    &["debug/.wrapper-shims".into()]
                )
                .is_err(),
                "{command}"
            );
        }
        assert!(
            CargoOutputCapture::for_retrieval_policy(
                Some(CompilationKind::CargoDoc),
                "cargo doc",
                &baseline,
                &["debug/.wrapper-shims".into()]
            )
            .is_err()
        );
        assert!(
            CargoOutputCapture::for_retrieval_policy(
                Some(CompilationKind::CargoCheck),
                "cargo check",
                &[],
                &["debug/.wrapper-shims".into()]
            )
            .is_err()
        );
        assert!(
            CargoOutputCapture::for_retrieval_policy(
                Some(CompilationKind::CargoCheck),
                "cargo check",
                &[],
                &[],
            )
            .unwrap()
            .is_none()
        );
        assert!(CargoOutputCapture::for_command(kind, "cargo build").is_none());
        for (kind, command) in [
            (CompilationKind::CargoTest, "cargo test --no-run --bin app"),
            (
                CompilationKind::CargoTest,
                "cargo test --no-run --example sample",
            ),
            (
                CompilationKind::CargoBench,
                "cargo bench --no-run --bin app",
            ),
            (
                CompilationKind::CargoBench,
                "cargo bench --no-run --example sample",
            ),
        ] {
            let baseline = super::super::artifact_patterns::get_custom_target_artifact_patterns(
                Some(kind),
                Some(command),
            );
            let capture = CargoOutputCapture::for_retrieval_policy(
                Some(kind),
                command,
                &baseline,
                &["debug/.wrapper-shims".into()],
            )
            .unwrap()
            .unwrap();
            assert!(!capture.caller_json_supported());
            assert!(
                capture
                    .execution_command(command)
                    .ends_with(" --message-format=json,json-render-diagnostics")
            );
        }
    }

    #[cfg(unix)]
    #[test]
    fn cargo_retrieval_real_cargo_full_build_and_fresh_receipts() {
        let root = tempfile::tempdir().unwrap();
        let source = root.path().join("source");
        let target = root.path().join("custom target");
        std::fs::create_dir_all(source.join("src/bin")).unwrap();
        std::fs::write(source.join("Cargo.toml"), "[package]\nname='retrieval_fixture'\nversion='0.1.0'\nedition='2024'\n[workspace]\n[profile.ci-fast]\ninherits='dev'\n").unwrap();
        std::fs::write(source.join("src/lib.rs"), "pub fn answer() -> u8 { 42 }\n").unwrap();
        std::fs::write(
            source.join("src/bin/app.rs"),
            "fn main() { println!(\"{}\", retrieval_fixture::answer()); }\n",
        )
        .unwrap();
        std::fs::write(
            source.join("src/bin/helper.rs"),
            "fn main() { assert_eq!(retrieval_fixture::answer(), 42); }\n",
        )
        .unwrap();
        std::fs::write(source.join("build.rs"), r#"fn main() {
            let out = std::path::PathBuf::from(std::env::var_os("OUT_DIR").unwrap());
            let profile = out.ancestors().find(|path| path.file_name().is_some_and(|name| name == "build")).unwrap().parent().unwrap();
            let cache = profile.join(".wrapper-shims");
            std::fs::create_dir_all(&cache).unwrap();
            std::fs::write(cache.join("helper.bin"), b"worker-private cache").unwrap();
            println!("cargo:rerun-if-changed=build.rs");
        }"#).unwrap();
        let command = "cargo build --workspace --profile ci-fast --offline --jobs=1";
        let kind = Some(CompilationKind::CargoBuild);
        let baseline = super::super::artifact_patterns::get_custom_target_artifact_patterns(
            kind,
            Some(command),
        );
        let transfer = rch_common::TransferConfig {
            cargo_retrieval_exclude_dirs: vec!["ci-fast/.wrapper-shims".into()],
            ..rch_common::TransferConfig::default()
        };
        let capture = CargoOutputCapture::for_retrieval_policy(
            kind,
            command,
            &baseline,
            &transfer.cargo_retrieval_exclude_dirs,
        )
        .unwrap()
        .unwrap();
        let automatic = CargoOutputCapture::for_retrieval_policy(kind, command, &baseline, &[])
            .unwrap()
            .unwrap();
        assert!(automatic.automatic_complete_outputs());
        assert_eq!(
            automatic.execution_command(command),
            capture.execution_command(command)
        );
        for warm in [false, true] {
            let output = std::process::Command::new(env!("CARGO"))
                .args([
                    "build",
                    "--workspace",
                    "--profile",
                    "ci-fast",
                    "--offline",
                    "--jobs=1",
                    "--message-format=json,json-render-diagnostics",
                    "--target-dir",
                ])
                .arg(&target)
                .current_dir(&source)
                .env_remove("RUSTC_WRAPPER")
                .env_remove("RUSTC_WORKSPACE_WRAPPER")
                .env_remove("CARGO_BUILD_BUILD_DIR")
                .env_remove("CARGO_ENCODED_RUSTFLAGS")
                .env_remove("RUSTFLAGS")
                .output()
                .unwrap();
            assert!(
                output.status.success(),
                "{}",
                String::from_utf8_lossy(&output.stderr)
            );
            let canonical_target = target.canonicalize().unwrap();
            let contract = capture
                .parse_receipt_with_roots(&output.stdout, &[&target, &canonical_target])
                .unwrap();
            assert_eq!(
                automatic
                    .parse_receipt_with_roots(&output.stdout, &[&target, &canonical_target])
                    .unwrap(),
                contract,
                "default delivery must protect the same complete native Cargo outputs"
            );
            assert!(contract.required_files.contains(Path::new("ci-fast/app")));
            assert!(
                contract
                    .required_files
                    .contains(Path::new("ci-fast/helper"))
            );
            assert!(
                contract
                    .required_files
                    .iter()
                    .any(|path| path.extension().is_some_and(|ext| ext == "rlib"))
            );
            assert!(target.join("ci-fast/.wrapper-shims/helper.bin").is_file());
            let patterns = super::super::artifact_patterns::cargo_retrieval_patterns(
                &baseline,
                &transfer,
                Some(&contract.required_files),
            )
            .unwrap();
            let filters = crate::transfer::ArtifactFilters::from_patterns(&patterns).unwrap();
            assert!(!filters.selects("ci-fast/.wrapper-shims/helper.bin"));
            for path in &contract.required_files {
                assert!(filters.selects(path.to_str().unwrap()));
                assert!(target.join(path).is_file());
            }
            if warm {
                for line in std::str::from_utf8(&output.stdout).unwrap().lines() {
                    let value: serde_json::Value = serde_json::from_str(line).unwrap();
                    if value["reason"] == "compiler-artifact" {
                        assert_eq!(value["fresh"], true);
                    }
                }
            }
        }
    }

    #[cfg(unix)]
    #[test]
    fn cargo_retrieval_real_cargo_keeps_separate_build_dir_intermediates_private() {
        let fixture = tempfile::tempdir().unwrap();
        let source = fixture.path().join("source");
        let target = fixture.path().join("target");
        let intermediates = fixture.path().join("private build cache");
        for directory in ["app/src", "helper/src", "compile_macro/src", ".cargo"] {
            std::fs::create_dir_all(source.join(directory)).unwrap();
        }
        std::fs::write(
            source.join("Cargo.toml"),
            "[workspace]\nmembers = [\"app\", \"helper\", \"compile_macro\"]\nresolver = \"2\"\n",
        )
        .unwrap();
        std::fs::write(
            source.join("helper/Cargo.toml"),
            "[package]\nname = \"helper\"\nversion = \"0.0.0\"\nedition = \"2024\"\n",
        )
        .unwrap();
        std::fs::write(
            source.join("helper/src/lib.rs"),
            "pub fn value() -> u32 { 42 }\n",
        )
        .unwrap();
        std::fs::write(
            source.join("compile_macro/Cargo.toml"),
            "[package]\nname = \"compile_macro\"\nversion = \"0.0.0\"\nedition = \"2024\"\n[lib]\nproc-macro = true\n",
        )
        .unwrap();
        std::fs::write(
            source.join("compile_macro/src/lib.rs"),
            "extern crate proc_macro;\n#[proc_macro]\npub fn answer(_: proc_macro::TokenStream) -> proc_macro::TokenStream { \"42u32\".parse().unwrap() }\n",
        )
        .unwrap();
        std::fs::write(
            source.join("app/Cargo.toml"),
            "[package]\nname = \"app\"\nversion = \"0.0.0\"\nedition = \"2024\"\n[dependencies]\nhelper = { path = \"../helper\" }\ncompile_macro = { path = \"../compile_macro\" }\n",
        )
        .unwrap();
        std::fs::write(
            source.join("app/src/main.rs"),
            "fn main() { assert_eq!(helper::value(), compile_macro::answer!()); }\n",
        )
        .unwrap();
        // Ordinary mirroring preserves this Cargo configuration. The owned
        // source/clean-overlay route separately binds build-dir into its pool.
        std::fs::write(
            source.join(".cargo/config.toml"),
            format!(
                "[build]\nbuild-dir = {}\n",
                serde_json::to_string(&intermediates).unwrap()
            ),
        )
        .unwrap();
        let command = "cargo build --package app --offline --jobs=1";
        let kind = Some(CompilationKind::CargoBuild);
        let baseline = super::super::artifact_patterns::get_custom_target_artifact_patterns(
            kind,
            Some(command),
        );
        let capture = CargoOutputCapture::for_retrieval_policy(
            kind,
            command,
            &baseline,
            &["debug/.wrapper-shims".into()],
        )
        .unwrap()
        .unwrap();
        let automatic = CargoOutputCapture::for_retrieval_policy(kind, command, &baseline, &[])
            .unwrap()
            .unwrap();
        assert!(automatic.automatic_complete_outputs());
        assert_eq!(
            automatic.execution_command(command),
            capture.execution_command(command)
        );
        for warm in [false, true] {
            let output = std::process::Command::new(env!("CARGO"))
                .args([
                    "build",
                    "--package",
                    "app",
                    "--offline",
                    "--jobs=1",
                    "--message-format=json,json-render-diagnostics",
                    "--target-dir",
                ])
                .arg(&target)
                .current_dir(&source)
                .env("CARGO_HOME", fixture.path().join("cargo-home"))
                .env_remove("RUSTC_WRAPPER")
                .env_remove("RUSTC_WORKSPACE_WRAPPER")
                .env_remove("CARGO_BUILD_BUILD_DIR")
                .env_remove("CARGO_BUILD_TARGET")
                .env_remove("CARGO_BUILD_TARGET_DIR")
                .env_remove("CARGO_BUILD_RUSTFLAGS")
                .env_remove("CARGO_ENCODED_RUSTFLAGS")
                .env_remove("RUSTFLAGS")
                .output()
                .unwrap();
            assert!(
                output.status.success(),
                "{}",
                String::from_utf8_lossy(&output.stderr)
            );
            let records: Vec<serde_json::Value> = std::str::from_utf8(&output.stdout)
                .unwrap()
                .lines()
                .map(|line| serde_json::from_str(line).unwrap())
                .collect();
            let canonical_intermediates = intermediates.canonicalize().unwrap();
            for name in ["helper", "compile_macro"] {
                let dependency = records
                    .iter()
                    .find(|record| {
                        record["reason"] == "compiler-artifact" && record["target"]["name"] == name
                    })
                    .unwrap();
                assert!(dependency["executable"].is_null());
                let files = dependency["filenames"].as_array().unwrap();
                assert!(!files.is_empty());
                for file in files {
                    let path = Path::new(file.as_str().unwrap());
                    assert!(
                        path.starts_with(&intermediates)
                            || path.starts_with(&canonical_intermediates)
                    );
                }
                if name == "compile_macro" {
                    assert_eq!(dependency["target"]["kind"], json!(["proc-macro"]));
                    assert!(files.iter().any(|file| {
                        Path::new(file.as_str().unwrap())
                            .extension()
                            .is_some_and(|extension| {
                                matches!(extension.to_str(), Some("so" | "dylib"))
                            })
                    }));
                }
                if warm {
                    assert_eq!(dependency["fresh"], true);
                }
            }
            let canonical_target = target.canonicalize().unwrap();
            let roots = [target.as_path(), canonical_target.as_path()];
            let contract = capture
                .parse_receipt_with_roots(&output.stdout, &roots)
                .unwrap();
            assert_eq!(
                automatic
                    .parse_receipt_with_roots(&output.stdout, &roots)
                    .unwrap(),
                contract,
                "default delivery must preserve separate build-directory semantics"
            );
            assert_eq!(contract.required_files, [PathBuf::from("debug/app")].into());
            assert!(contract.required_directories.is_empty());
            contract.verify_staged(&target).unwrap();

            // Ignoring private library bytes does not authorize an executable
            // outside the output root, nor a malformed intermediate path.
            for invalid_case in [
                "outside executable",
                "outside runtime library",
                "malformed path",
                "missing executable",
            ] {
                let mut invalid = records.clone();
                let dependency = invalid
                    .iter_mut()
                    .find(|record| record["target"]["name"] == "helper")
                    .unwrap();
                match invalid_case {
                    "outside executable" => {
                        dependency["executable"] = dependency["filenames"][0].clone();
                    }
                    "outside runtime library" => {
                        dependency["target"]["kind"] = json!(["dylib"]);
                        dependency["filenames"] =
                            json!([canonical_intermediates.join("libhelper.so")]);
                    }
                    "malformed path" => {
                        dependency["filenames"][0] = json!(format!(
                            "{}/../escaped.rlib",
                            canonical_intermediates.display()
                        ));
                    }
                    _ => {
                        dependency["target"]["kind"] = json!(["bin"]);
                        dependency["filenames"] = json!([canonical_target.join("debug/app")]);
                    }
                }
                let invalid = invalid
                    .iter()
                    .map(|record| format!("{record}\n"))
                    .collect::<String>();
                assert!(
                    capture
                        .parse_receipt_with_roots(invalid.as_bytes(), &roots)
                        .is_err(),
                    "accepted {invalid_case}"
                );
            }
        }
    }

    #[test]
    fn no_run_caller_json_binds_exact_modes_files_and_recovery_metadata() {
        let root = tempfile::tempdir().unwrap();
        let local = root.path().join("caller with spaces λ");
        std::fs::create_dir_all(&local).unwrap();
        std::fs::write(local.join("Cargo.toml"), "[workspace]\n").unwrap();
        let local = local.canonicalize().unwrap();
        let target_root = local.join("artifacts");
        let binding = json!({"wrapper_id":"original-invocation", "worker_id":"worker"});
        for (kind, selector) in [
            (CompilationKind::CargoTest, "test"),
            (CompilationKind::CargoBench, "bench"),
        ] {
            let command = format!(
                "cargo {selector} --no-run --{selector} alpha --{selector} beta --message-format=json"
            );
            let capture = CargoOutputCapture::for_command(Some(kind), &command).unwrap();
            // A recovery recipe must keep exactly the same mode, not upgrade
            // a normal test execution into a build-only stdout contract.
            let restored: CargoOutputCapture =
                serde_json::from_slice(&serde_json::to_vec(&capture).unwrap()).unwrap();
            assert_eq!(restored, capture);
            let alpha_path = "/worker/target/lean/deps/alpha-0123456789abcdef";
            let beta_path = "/worker/target/lean/deps/beta-fedcba9876543210";
            let sidecar = "/worker/target/lean/deps/alpha-0123456789abcdef.pdb";
            let mut alpha = artifact(
                selector,
                "alpha",
                &[alpha_path, sidecar],
                Some(alpha_path),
                true,
            );
            alpha["profile"] = json!({"test":true});
            alpha["manifest_path"] = json!("/worker/source/Cargo.toml");
            alpha["target"]["src_path"] = json!("/worker/source/tests/alpha.rs");
            let mut beta = artifact(selector, "beta", &[beta_path], Some(beta_path), false);
            beta["profile"] = json!({"test":true});
            beta["manifest_path"] = json!("/worker/source/Cargo.toml");
            // Cargo also builds binaries needed by integration tests. They
            // are not the selected test, even when target names coincide.
            let unrelated = artifact(
                "bin",
                "alpha",
                &["/worker/target/lean/alpha"],
                Some("/worker/target/lean/alpha"),
                true,
            );
            let data = receipt(&[unrelated.clone(), alpha.clone(), beta.clone()]);
            let published: BTreeMap<_, _> = [alpha_path, beta_path, sidecar]
                .into_iter()
                .map(|path| {
                    (
                        Path::new(path)
                            .strip_prefix("/worker/target")
                            .unwrap()
                            .to_owned(),
                        blake3::hash(path.as_bytes()).to_hex().to_string(),
                    )
                })
                .collect();
            let paths = CargoCallerPaths {
                remote_output_roots: &[Path::new("/worker/target")],
                local_output_root: &target_root,
                remote_project_roots: &[Path::new("/worker/source")],
                local_project_root: &local,
                published: &published,
                receipt_binding: &binding,
            };
            let output = capture.caller_json(&data, &paths).unwrap();
            assert_eq!(output.files, published.keys().cloned().collect());
            assert_eq!(
                restored.caller_json(&data, &paths).unwrap().stdout,
                output.stdout
            );
            assert!(
                output
                    .stdout
                    .starts_with(format!("{unrelated}\n").as_bytes())
            );
            let records: Vec<serde_json::Value> = std::str::from_utf8(&output.stdout)
                .unwrap()
                .lines()
                .map(|line| serde_json::from_str(line).unwrap())
                .collect();
            for (record, original) in records[1..3].iter().zip([&alpha, &beta]) {
                let relative = Path::new(original["executable"].as_str().unwrap())
                    .strip_prefix("/worker/target")
                    .unwrap();
                assert_eq!(record["executable"], json!(target_root.join(relative)));
                assert_eq!(record["manifest_path"], json!(local.join("Cargo.toml")));
                assert_eq!(record["profile"]["test"], true);
                assert_eq!(record["rch"]["worker_record"], *original);
                assert_eq!(record["rch"]["receipt"], binding);
                assert_eq!(
                    record["rch"]["executable_blake3"],
                    json!(published[relative])
                );
            }
            // A stale local file cannot stand in for a missing member of this
            // invocation's publication, including non-executable sidecars.
            for missing in published.keys() {
                let mut incomplete = published.clone();
                incomplete.remove(missing);
                let paths = CargoCallerPaths {
                    published: &incomplete,
                    ..paths
                };
                assert!(capture.caller_json(&data, &paths).is_err());
            }
            for bad in [json!(false), json!(null), json!("true")] {
                let mut changed = alpha.clone();
                changed["profile"]["test"] = bad;
                assert!(
                    capture
                        .caller_json(&receipt(&[changed, beta.clone()]), &paths)
                        .is_err()
                );
            }
            let mut ambiguous = alpha.clone();
            ambiguous["target"]["kind"] = json!([selector, "bin"]);
            assert!(
                capture
                    .caller_json(&receipt(&[ambiguous, beta.clone()]), &paths)
                    .is_err()
            );
            assert!(
                capture
                    .caller_json(&receipt(&[alpha.clone(), alpha, beta]), &paths)
                    .is_err()
            );
        }
        // Binary builds retain the inverse mode check; enabling no-run JSON
        // must not turn an unexpected test binary into an installable tool.
        let bin = capture("cargo build --bin alpha --message-format=json");
        let mut record = artifact("bin", "alpha", &[], None, false);
        record["profile"] = json!({"test":true});
        assert!(bin.caller_target(&record).is_err());
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn real_cargo_no_run_json_projects_harness_and_custom_harness_outputs() {
        use std::process::Stdio;
        use std::time::Duration;
        use tokio::process::Command;

        let root = tempfile::tempdir().unwrap();
        let source = root.path().join("producer");
        let local = root.path().join("consumer");
        for directory in [&source, &local] {
            std::fs::create_dir_all(directory.join("tests")).unwrap();
            std::fs::create_dir_all(directory.join("benches")).unwrap();
            std::fs::write(directory.join("Cargo.toml"), concat!(
                "[package]\nname = \"rch_no_run_json_fixture\"\nversion = \"0.0.0\"\nedition = \"2024\"\n",
                "[workspace]\n",
                "[[test]]\nname = \"harness\"\npath = \"tests/harness.rs\"\n",
                "[[test]]\nname = \"custom\"\npath = \"tests/custom.rs\"\nharness = false\n",
                "[[bench]]\nname = \"measure\"\npath = \"benches/measure.rs\"\nharness = false\n",
            )).unwrap();
            std::fs::write(
                directory.join("tests/harness.rs"),
                "#[test] fn not_executed() { panic!(\"no-run must not execute tests\"); }\n",
            )
            .unwrap();
            for path in ["tests/custom.rs", "benches/measure.rs"] {
                std::fs::write(
                    directory.join(path),
                    "fn main() { panic!(\"no-run must not execute custom harnesses\"); }\n",
                )
                .unwrap();
            }
        }
        let source = source.canonicalize().unwrap();
        let local = local.canonicalize().unwrap();
        let remote_target = root.path().canonicalize().unwrap().join("producer-target");
        let local_target = local.join("artifacts");
        let binding = json!({"fixture":"actual-cargo-no-run"});
        for (kind, command) in [
            (
                CompilationKind::CargoTest,
                "cargo test --test harness --test custom --no-run --message-format=json --offline --jobs=1",
            ),
            (
                CompilationKind::CargoBench,
                "cargo bench --bench measure --no-run --message-format=json --offline --jobs=1",
            ),
        ] {
            let capture = CargoOutputCapture::for_command(Some(kind), command).unwrap();
            for warm in [false, true] {
                let cargo = std::env::var_os("CARGO").unwrap_or_else(|| "cargo".into());
                let mut compile = Command::new(cargo);
                compile
                    .current_dir(&source)
                    .args(command.split_ascii_whitespace().skip(1))
                    .env("CARGO_HOME", root.path().join("cargo-home"))
                    .env("CARGO_TARGET_DIR", &remote_target)
                    .env_remove("RUSTC_WRAPPER")
                    .env_remove("RUSTC_WORKSPACE_WRAPPER")
                    .env_remove("RUSTFLAGS")
                    .env_remove("CARGO_ENCODED_RUSTFLAGS")
                    .env_remove("CARGO_BUILD_TARGET")
                    .env_remove("CARGO_BUILD_TARGET_DIR")
                    .env_remove("CARGO_BUILD_BUILD_DIR")
                    .env_remove("CARGO_MAKEFLAGS")
                    .env_remove("MAKEFLAGS")
                    .stdin(Stdio::null())
                    .kill_on_drop(true);
                let result = tokio::time::timeout(Duration::from_secs(90), compile.output())
                    .await
                    .expect("owned Cargo no-run fixture timed out")
                    .expect("Cargo is required for native no-run coverage");
                assert!(
                    result.status.success(),
                    "{}",
                    String::from_utf8_lossy(&result.stderr)
                );
                let files = capture
                    .validate_caller_metadata(&result.stdout, &[&remote_target], &[&source], &local)
                    .unwrap();
                let mut published = BTreeMap::new();
                for relative in &files {
                    let bytes = std::fs::read(remote_target.join(relative)).unwrap();
                    let destination = local_target.join(relative);
                    std::fs::create_dir_all(destination.parent().unwrap()).unwrap();
                    std::fs::write(&destination, &bytes).unwrap();
                    published.insert(relative.clone(), blake3::hash(&bytes).to_hex().to_string());
                }
                capture
                    .parse_receipt(&result.stdout, &remote_target)
                    .unwrap()
                    .verify_staged(&local_target)
                    .unwrap();
                let paths = CargoCallerPaths {
                    remote_output_roots: &[&remote_target],
                    local_output_root: &local_target,
                    remote_project_roots: &[&source],
                    local_project_root: &local,
                    published: &published,
                    receipt_binding: &binding,
                };
                let output = capture.caller_json(&result.stdout, &paths).unwrap();
                let records: Vec<serde_json::Value> = std::str::from_utf8(&output.stdout)
                    .unwrap()
                    .lines()
                    .map(|line| serde_json::from_str(line).unwrap())
                    .filter(|record: &serde_json::Value| record.get("rch").is_some())
                    .collect();
                assert_eq!(records.len(), capture.selected.len());
                for record in records {
                    assert_eq!(record["profile"]["test"], true);
                    assert_eq!(record["fresh"], warm);
                    let executable = Path::new(record["executable"].as_str().unwrap());
                    assert!(executable.starts_with(&local_target));
                    assert_eq!(
                        blake3::hash(&std::fs::read(executable).unwrap())
                            .to_hex()
                            .as_str(),
                        record["rch"]["executable_blake3"].as_str().unwrap()
                    );
                    assert_eq!(record["rch"]["receipt"], binding);
                }
            }
        }
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn real_cargo_workspace_json_delivers_same_named_tests_and_benches() {
        use std::process::Stdio;
        use std::time::Duration;
        use tokio::process::Command;

        let root = tempfile::tempdir().unwrap();
        let source = root.path().join("producer");
        let local = root.path().join("consumer");
        for directory in [&source, &local] {
            std::fs::create_dir_all(directory).unwrap();
            std::fs::write(
                directory.join("Cargo.toml"),
                "[workspace]\nmembers = [\"alpha\", \"beta\"]\nresolver = \"3\"\n",
            )
            .unwrap();
            for member in ["alpha", "beta"] {
                let package = directory.join(member);
                std::fs::create_dir_all(package.join("tests")).unwrap();
                std::fs::create_dir_all(package.join("benches")).unwrap();
                std::fs::write(
                    package.join("Cargo.toml"),
                    format!(
                        "[package]\nname = \"rch_workspace_{member}_fixture\"\nversion = \"0.0.0\"\nedition = \"2024\"\n\
                         [[bench]]\nname = \"smoke\"\npath = \"benches/smoke.rs\"\nharness = false\n"
                    ),
                )
                .unwrap();
                std::fs::write(
                    package.join("tests/smoke.rs"),
                    "#[test] fn not_executed() { panic!(\"no-run must not execute tests\"); }\n",
                )
                .unwrap();
                std::fs::write(
                    package.join("benches/smoke.rs"),
                    "fn main() { panic!(\"no-run must not execute benches\"); }\n",
                )
                .unwrap();
            }
        }
        let source = source.canonicalize().unwrap();
        let local = local.canonicalize().unwrap();
        let remote_target = root.path().canonicalize().unwrap().join("producer-target");
        let local_target = local.join("artifacts");
        let binding = json!({"fixture":"actual-cargo-workspace-named-outputs"});
        for (kind, selector) in [
            (CompilationKind::CargoTest, "test"),
            (CompilationKind::CargoBench, "bench"),
        ] {
            let command = format!(
                "cargo {selector} --workspace --{selector} smoke --no-run --message-format=json --offline --jobs=1"
            );
            let capture = CargoOutputCapture::for_command(Some(kind), &command).unwrap();
            // Recovery restores the same selector; it must also preserve all
            // matching package outputs from this invocation's immutable receipt.
            let restored: CargoOutputCapture =
                serde_json::from_slice(&serde_json::to_vec(&capture).unwrap()).unwrap();
            assert_eq!(capture.selected.len(), 1);
            for warm in [false, true] {
                let cargo = std::env::var_os("CARGO").unwrap_or_else(|| "cargo".into());
                let mut compile = Command::new(cargo);
                compile
                    .current_dir(&source)
                    .args(command.split_ascii_whitespace().skip(1))
                    .env("CARGO_HOME", root.path().join("cargo-home"))
                    .env("CARGO_TARGET_DIR", &remote_target)
                    .env_remove("RUSTC_WRAPPER")
                    .env_remove("RUSTC_WORKSPACE_WRAPPER")
                    .env_remove("RUSTFLAGS")
                    .env_remove("CARGO_ENCODED_RUSTFLAGS")
                    .env_remove("CARGO_BUILD_TARGET")
                    .env_remove("CARGO_BUILD_TARGET_DIR")
                    .env_remove("CARGO_BUILD_BUILD_DIR")
                    .env_remove("CARGO_MAKEFLAGS")
                    .env_remove("MAKEFLAGS")
                    .stdin(Stdio::null())
                    .kill_on_drop(true);
                let result = tokio::time::timeout(Duration::from_secs(90), compile.output())
                    .await
                    .expect("owned Cargo workspace fixture timed out")
                    .expect("Cargo is required for native workspace output coverage");
                assert!(
                    result.status.success(),
                    "{}",
                    String::from_utf8_lossy(&result.stderr)
                );
                let files = restored
                    .validate_caller_metadata(&result.stdout, &[&remote_target], &[&source], &local)
                    .unwrap();
                let mut published = BTreeMap::new();
                for relative in &files {
                    let destination = local_target.join(relative);
                    std::fs::create_dir_all(destination.parent().unwrap()).unwrap();
                    std::fs::copy(remote_target.join(relative), &destination).unwrap();
                    let bytes = std::fs::read(destination).unwrap();
                    published.insert(relative.clone(), blake3::hash(&bytes).to_hex().to_string());
                }
                let contract = restored
                    .parse_receipt(&result.stdout, &remote_target)
                    .unwrap();
                assert_eq!(contract.required_files.len(), 2);
                contract.verify_staged(&local_target).unwrap();
                let paths = CargoCallerPaths {
                    remote_output_roots: &[&remote_target],
                    local_output_root: &local_target,
                    remote_project_roots: &[&source],
                    local_project_root: &local,
                    published: &published,
                    receipt_binding: &binding,
                };
                let output = restored.caller_json(&result.stdout, &paths).unwrap();
                assert_eq!(output.files, files);
                let records: Vec<serde_json::Value> = std::str::from_utf8(&output.stdout)
                    .unwrap()
                    .lines()
                    .map(|line| serde_json::from_str(line).unwrap())
                    .filter(|record: &serde_json::Value| record.get("rch").is_some())
                    .collect();
                assert_eq!(records.len(), 2);
                assert_ne!(records[0]["package_id"], records[1]["package_id"]);
                assert_ne!(records[0]["manifest_path"], records[1]["manifest_path"]);
                assert_ne!(records[0]["executable"], records[1]["executable"]);
                for record in records {
                    assert_eq!(record["target"]["name"], "smoke");
                    assert_eq!(record["profile"]["test"], true);
                    assert_eq!(record["fresh"], warm);
                    let executable = Path::new(record["executable"].as_str().unwrap());
                    assert!(executable.starts_with(&local_target));
                    assert_eq!(
                        blake3::hash(&std::fs::read(executable).unwrap())
                            .to_hex()
                            .as_str(),
                        record["rch"]["executable_blake3"].as_str().unwrap()
                    );
                    assert_eq!(record["rch"]["receipt"], binding);
                }
                // Retaining one old local executable cannot stand in for a
                // lost publication of the other package's same-named target.
                let mut incomplete = published.clone();
                incomplete.remove(contract.required_files.first().unwrap());
                assert!(
                    restored
                        .caller_json(
                            &result.stdout,
                            &CargoCallerPaths {
                                published: &incomplete,
                                ..paths
                            },
                        )
                        .is_err()
                );
            }
        }
    }

    #[test]
    fn caller_json_distinguishes_platform_outputs_but_refuses_executable_collisions() {
        let root = tempfile::tempdir().unwrap();
        std::fs::create_dir(root.path().join("other")).unwrap();
        for manifest in ["Cargo.toml", "other/Cargo.toml"] {
            std::fs::write(root.path().join(manifest), "[workspace]\n").unwrap();
        }
        let local = root.path().canonicalize().unwrap();
        let capture = capture(
            "cargo build --bin app --target x86_64-unknown-linux-gnu --target aarch64-unknown-linux-gnu --message-format=json",
        );
        let records: Vec<_> = ["x86_64-unknown-linux-gnu", "aarch64-unknown-linux-gnu"]
            .into_iter()
            .map(|platform| {
                let executable = format!("/worker/target/{platform}/debug/app");
                let mut record = artifact("bin", "app", &[&executable], Some(&executable), false);
                record["manifest_path"] = json!("/worker/source/Cargo.toml");
                record["profile"] = json!({"test":false});
                record
            })
            .collect();
        let data = receipt(&records);
        let published: BTreeMap<_, _> = records
            .iter()
            .map(|record| {
                (
                    relative_output_path(
                        record["executable"].as_str().unwrap(),
                        &[Path::new("/worker/target")],
                    )
                    .unwrap(),
                    "fixture-fingerprint".to_owned(),
                )
            })
            .collect();
        let target = local.join("target");
        let binding = json!({"fixture":"multiple-platform-records"});
        let paths = CargoCallerPaths {
            remote_output_roots: &[Path::new("/worker/target"), Path::new("/alias/target")],
            local_output_root: &target,
            remote_project_roots: &[Path::new("/worker/source")],
            local_project_root: &local,
            published: &published,
            receipt_binding: &binding,
        };
        let output = capture.caller_json(&data, &paths).unwrap();
        assert_eq!(output.files, published.keys().cloned().collect());
        let projected: Vec<serde_json::Value> = std::str::from_utf8(&output.stdout)
            .unwrap()
            .lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect();
        for (record, original) in projected.iter().zip(&records) {
            let relative = Path::new(original["executable"].as_str().unwrap())
                .strip_prefix("/worker/target")
                .unwrap();
            assert_eq!(record["executable"], json!(target.join(relative)));
            assert_eq!(record["rch"]["worker_record"], *original);
        }
        for (manifest, executable) in [
            (
                "/worker/source/Cargo.toml",
                records[0]["executable"].as_str().unwrap(),
            ),
            (
                "/worker/source/other/Cargo.toml",
                records[0]["executable"].as_str().unwrap(),
            ),
            (
                "/worker/source/Cargo.toml",
                "/alias/target/x86_64-unknown-linux-gnu/debug/app",
            ),
        ] {
            let mut collision = records[1].clone();
            collision["manifest_path"] = json!(manifest);
            collision["executable"] = json!(executable);
            collision["filenames"] = json!([executable]);
            let error = capture
                .caller_json(&receipt(&[records[0].clone(), collision]), &paths)
                .err()
                .expect("duplicate or colliding executable must not publish caller JSON");
            assert!(error.to_string().contains("colliding selected executable"));
        }
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn real_cargo_json_delivers_named_binary_and_library_examples() {
        let root = tempfile::tempdir().unwrap();
        let root = root.path().canonicalize().unwrap();
        let source = root.join("producer");
        let consumer = root.join("consumer");
        let target = root.join("target");
        for project in [&source, &consumer] {
            std::fs::create_dir_all(project.join("examples")).unwrap();
            std::fs::create_dir_all(project.join("src")).unwrap();
            std::fs::write(
                project.join("Cargo.toml"),
                concat!(
                    "[package]\nname='viewer'\nversion='0.1.0'\nedition='2024'\n[workspace]\n",
                    "[[example]]\nname='sample'\ncrate-type=['rlib','staticlib']\n",
                ),
            )
            .unwrap();
            std::fs::write(project.join("src/main.rs"), "fn main() {}").unwrap();
            std::fs::write(project.join("examples/viewer.rs"), "fn main() {}").unwrap();
            std::fs::write(
                project.join("examples/sample.rs"),
                "pub fn value() -> u8 { 2 }",
            )
            .unwrap();
        }
        let command = "cargo build --offline --bin viewer --example viewer --example sample --message-format=json";
        let capture = capture(command);
        let restored: CargoOutputCapture =
            serde_json::from_slice(&serde_json::to_vec(&capture).unwrap()).unwrap();
        let mut cargo = tokio::process::Command::new(std::env::var_os("CARGO").unwrap());
        cargo.current_dir(&source)
            .args(command.split_ascii_whitespace().skip(1))
            .env("CARGO_TARGET_DIR", &target)
            .env("CARGO_PROFILE_DEV_DEBUG", "0")
            .env("CARGO_HOME", root.join("cargo-home"))
            .env_remove("CARGO_BUILD_TARGET")
            .env_remove("CARGO_BUILD_BUILD_DIR")
            .env_remove("RUSTC_WRAPPER")
            .env_remove("RUSTC_WORKSPACE_WRAPPER")
            .env_remove("RUSTFLAGS")
            .env_remove("CARGO_ENCODED_RUSTFLAGS")
            .kill_on_drop(true);
        for fresh in [false, true] {
            let output = tokio::time::timeout(std::time::Duration::from_secs(90), cargo.output())
                .await
                .unwrap()
                .unwrap();
            assert!(
                output.status.success(),
                "{}",
                String::from_utf8_lossy(&output.stderr)
            );
            let contract = restored.parse_receipt(&output.stdout, &target).unwrap();
            contract.verify_staged(&target).unwrap();
            let selected = restored
                .validate_caller_metadata(&output.stdout, &[&target], &[&source], &consumer)
                .unwrap();
            let published: BTreeMap<_, _> = selected
                .into_iter()
                .map(|path| {
                    let bytes = std::fs::read(target.join(&path)).unwrap();
                    (path, blake3::hash(&bytes).to_hex().to_string())
                })
                .collect();
            let binding = json!({"wrapper_id":"named-example"});
            let paths = CargoCallerPaths {
                remote_output_roots: &[&target],
                local_output_root: &consumer,
                remote_project_roots: &[&source],
                local_project_root: &consumer,
                published: &published,
                receipt_binding: &binding,
            };
            let output = restored.caller_json(&output.stdout, &paths).unwrap();
            let records: Vec<serde_json::Value> = std::str::from_utf8(&output.stdout)
                .unwrap()
                .lines()
                .map(|line| serde_json::from_str(line).unwrap())
                .filter(|value: &serde_json::Value| value.get("rch").is_some())
                .collect();
            assert_eq!(records.len(), 3);
            for record in records {
                let original = &record["rch"]["worker_record"];
                assert_eq!(record["fresh"], fresh);
                assert_eq!(record["manifest_path"], json!(consumer.join("Cargo.toml")));
                assert_eq!(record["rch"]["receipt"], binding);
                if record["target"]["name"] == "sample" {
                    assert!(record["executable"].is_null());
                    assert!(record["rch"].get("executable_blake3").is_none());
                    for filename in original["filenames"].as_array().unwrap() {
                        let relative = Path::new(filename.as_str().unwrap())
                            .strip_prefix(&target)
                            .unwrap();
                        assert_eq!(
                            record["rch"]["file_blake3"][relative.to_str().unwrap()],
                            json!(published[relative])
                        );
                        assert!(record["filenames"]
                            .as_array()
                            .unwrap()
                            .contains(&json!(consumer.join(relative))));
                    }
                } else {
                    let relative = Path::new(original["executable"].as_str().unwrap())
                        .strip_prefix(&target)
                        .unwrap();
                    assert_eq!(record["executable"], json!(consumer.join(relative)));
                    assert_eq!(record["rch"]["executable_blake3"], json!(published[relative]));
                }
            }
        }
    }

    #[test]
    fn library_example_json_requires_every_declared_output_and_rejects_collisions() {
        let root = tempfile::tempdir().unwrap();
        let local = root.path().canonicalize().unwrap();
        std::fs::write(local.join("Cargo.toml"), "[workspace]\n").unwrap();
        let capture = capture("cargo build --example sample --message-format=json");
        let filename = "/target/debug/examples/libsample.rlib";
        let mut library = artifact("example", "sample", &[filename], None, true);
        library["target"]["crate_types"] = json!(["rlib"]);
        library["profile"] = json!({"test":false});
        library["manifest_path"] = json!("/src/Cargo.toml");
        let validate = |records: &[serde_json::Value]| {
            capture.validate_caller_metadata(
                &receipt(records),
                &[Path::new("/target")],
                &[Path::new("/src")],
                &local,
            )
        };
        assert!(validate(std::slice::from_ref(&library)).is_ok());
        assert!(validate(&[library.clone(), library.clone()]).is_err());
        for (field, value) in [
            ("filenames", json!(["/target/debug/examples/sample.pdb"])),
            ("filenames", json!(["/outside/libsample.rlib"])),
            ("executable", json!(filename)),
            ("profile", json!({"test":true})),
        ] {
            let mut bad = library.clone();
            bad[field] = value;
            assert!(validate(&[bad]).is_err(), "{field}");
        }
        for types in [json!([]), json!(["bin"]), json!(["rlib","staticlib"])] {
            let mut bad = library.clone();
            bad["target"]["crate_types"] = types;
            assert!(validate(&[bad]).is_err());
        }
        for (import, archive) in [
            ("sample.dll.lib", "sample.lib"),
            ("libsample.dll.a", "libsample.a"),
        ] {
            let mut mixed = library.clone();
            mixed["target"]["crate_types"] = json!(["cdylib", "staticlib"]);
            let dll = "/target/debug/examples/sample.dll";
            let import = format!("/target/debug/examples/{import}");
            let archive = format!("/target/debug/examples/{archive}");
            mixed["filenames"] = json!([dll, import]);
            assert!(validate(std::slice::from_ref(&mixed)).is_err());
            mixed["filenames"] = json!([dll, import, archive]);
            assert!(validate(&[mixed]).is_ok());
        }
        let empty = BTreeMap::new();
        let binding = json!({});
        let paths = CargoCallerPaths {
            remote_output_roots: &[Path::new("/target")],
            local_output_root: &local,
            remote_project_roots: &[Path::new("/src")],
            local_project_root: &local,
            published: &empty,
            receipt_binding: &binding,
        };
        assert!(capture.caller_json(&receipt(&[library]), &paths).is_err());
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
    fn complete_receipt_requires_nonempty_debug_bundles() {
        let baseline = crate::hook::artifact_patterns::get_custom_target_artifact_patterns(
            Some(CompilationKind::CargoBuild),
            Some("cargo build --bin app"),
        );
        let filters = crate::transfer::ArtifactFilters::from_patterns(&baseline).unwrap();
        assert!(filters.selects("debug/app.dSYM"));
        assert!(!filters.selects("debug/deps/libneeded.dSYM"));
        let captured = CargoOutputCapture::for_retrieval_policy(
            Some(CompilationKind::CargoBuild),
            "cargo build --bin app",
            &baseline,
            &["debug/.cache".into()],
        )
        .unwrap()
        .unwrap();
        let data = receipt(&[
            artifact(
                "bin",
                "app",
                &["/worker/target/debug/app", "/worker/target/debug/app.dSYM"],
                Some("/worker/target/debug/app"),
                true,
            ),
            artifact(
                "lib",
                "needed",
                &[
                    "/worker/target/debug/deps/libneeded.dylib",
                    "/worker/target/debug/deps/libneeded.dSYM",
                ],
                None,
                true,
            ),
        ]);
        let contract = captured
            .parse_receipt(&data, Path::new("/worker/target"))
            .unwrap();
        assert_eq!(
            contract.required_directories,
            [
                PathBuf::from("debug/app.dSYM"),
                PathBuf::from("debug/deps/libneeded.dSYM"),
            ]
            .into()
        );
        assert_eq!(
            contract.required_files,
            [
                PathBuf::from("debug/app"),
                PathBuf::from("debug/deps/libneeded.dylib"),
            ]
            .into()
        );
        let restored: CargoOutputContract =
            serde_json::from_slice(&serde_json::to_vec(&contract).unwrap()).unwrap();
        assert_eq!(restored, contract);
        let legacy: CargoOutputContract =
            serde_json::from_value(json!({"required_files":["debug/app"]})).unwrap();
        assert!(legacy.required_directories.is_empty());

        let stage = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(stage.path().join("debug/deps")).unwrap();
        std::fs::write(stage.path().join("debug/app"), b"executable").unwrap();
        std::fs::write(stage.path().join("debug/deps/libneeded.dylib"), b"library").unwrap();
        assert!(contract.verify_staged(stage.path()).is_err());
        for bundle in &contract.required_directories {
            std::fs::create_dir_all(stage.path().join(bundle).join("Contents/Resources")).unwrap();
        }
        assert!(contract.verify_staged(stage.path()).is_err());
        for bundle in &contract.required_directories {
            std::fs::write(
                stage.path().join(bundle).join("Contents/Resources/symbols"),
                b"debug symbols",
            )
            .unwrap();
        }
        contract.verify_staged(stage.path()).unwrap();
    }

    #[test]
    fn caller_json_bundle_requires_strict_published_file_descendants() {
        let source = tempfile::tempdir().unwrap();
        std::fs::write(source.path().join("Cargo.toml"), "[workspace]\n").unwrap();
        let source_root = source.path().canonicalize().unwrap();
        let local_output = source_root.join("delivered");
        let capture = capture("cargo build --bin app --message-format=json");
        let mut record = artifact(
            "bin",
            "app",
            &["/worker/target/debug/app", "/worker/target/debug/app.dSYM"],
            Some("/worker/target/debug/app"),
            true,
        );
        record["manifest_path"] = json!("/worker/source/Cargo.toml");
        record["profile"] = json!({"test":false});
        let data = receipt(&[record]);
        let bundle = PathBuf::from("debug/app.dSYM");
        let mut published = BTreeMap::from([
            (PathBuf::from("debug/app"), "executable-fingerprint".into()),
            (bundle.clone(), "root-is-not-file-evidence".into()),
        ]);
        let binding = json!({"fixture":"caller-bundle"});
        let project = |published: &BTreeMap<PathBuf, String>| {
            capture.caller_json(
                &data,
                &CargoCallerPaths {
                    remote_output_roots: &[Path::new("/worker/target")],
                    local_output_root: &local_output,
                    remote_project_roots: &[Path::new("/worker/source")],
                    local_project_root: &source_root,
                    published,
                    receipt_binding: &binding,
                },
            )
        };
        assert!(project(&published).is_err());
        let symbols = bundle.join("Contents/Resources/DWARF/app");
        published.insert(symbols.clone(), "symbols-fingerprint".into());
        let projected = project(&published).unwrap();
        assert_eq!(
            projected.files,
            [PathBuf::from("debug/app"), symbols].into()
        );
        let record: serde_json::Value = serde_json::from_str(
            std::str::from_utf8(&projected.stdout)
                .unwrap()
                .lines()
                .next()
                .unwrap(),
        )
        .unwrap();
        assert_eq!(record["filenames"][1], json!(local_output.join(&bundle)));
        assert!(!projected.files.contains(&bundle));
    }

    #[cfg(unix)]
    #[test]
    fn complete_bundle_validation_checks_entries_after_a_regular_file() {
        let stage = tempfile::tempdir().unwrap();
        let bundle = stage.path().join("debug/app.dSYM");
        std::fs::create_dir_all(bundle.join("Contents/Resources")).unwrap();
        std::fs::write(bundle.join("Contents/Info.plist"), b"bundle metadata").unwrap();
        std::os::unix::fs::symlink(
            "/unowned/symbols",
            bundle.join("Contents/Resources/symbols"),
        )
        .unwrap();
        let contract = CargoOutputContract {
            required_directories: [PathBuf::from("debug/app.dSYM")].into(),
            ..Default::default()
        };
        assert!(
            contract
                .verify_staged(stage.path())
                .unwrap_err()
                .to_string()
                .contains("symlink")
        );
    }

    #[test]
    fn publication_selection_preserves_required_files_and_bundle_contents() {
        let contract = CargoOutputContract {
            required_files: [
                PathBuf::from("target/lean/app"),
                PathBuf::from("target/lean/deps/libsupport.rlib"),
            ]
            .into(),
            required_directories: [PathBuf::from("target/lean/app.dSYM")].into(),
        };
        for excluded in [
            "target/lean/app",
            "target/lean/deps/libsupport.rlib",
            "target/lean/app.dSYM",
            "target/lean/app.dSYM/Contents/Info.plist",
            "target/lean/app.dSYM/Contents/Resources/DWARF/app",
        ] {
            let error = contract
                .validate_publication_selection(&[
                    PathBuf::from("target/lean/.worker-cache/private"),
                    PathBuf::from(excluded),
                ])
                .unwrap_err();
            assert!(error.to_string().contains(excluded));
        }
        // Removing a whole bundle and removing only one member must both
        // fail, even if other bundle files are still eligible for publication.
        assert!(
            contract
                .validate_publication_selection(&[
                    PathBuf::from("target/lean/app.dSYM/Contents/Info.plist"),
                    PathBuf::from("target/lean/app.dSYM/Contents/Resources/DWARF/app"),
                ])
                .is_err()
        );
        contract.validate_publication_selection(&[]).unwrap();
        contract
            .validate_publication_selection(&[
                PathBuf::from("target/lean/app-helper"),
                PathBuf::from("target/lean/deps/libsupport.rlib.backup"),
                PathBuf::from("target/lean/app.dSYM-other/Contents/Info.plist"),
                PathBuf::from("other/target/lean/app.dSYM/Contents/Info.plist"),
                PathBuf::from("target/lean/.worker-cache/private"),
            ])
            .unwrap();
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
            ..Default::default()
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
                ..Default::default()
            };
            assert!(contract.verify_staged(&stage).is_err(), "{name}");
        }
    }
}
