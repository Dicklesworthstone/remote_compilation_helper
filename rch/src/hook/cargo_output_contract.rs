//! Bind named Cargo executable delivery to the completed invocation's JSON.
//!
//! Transfer globs remain useful for runtime support files, but cannot prove
//! that every requested executable was returned. This contract records Cargo's
//! actual executable paths and checks them before any staged output publishes,
//! including explicitly named test/benchmark targets built with `--no-run`.
//! Commands selecting examples keep the existing artifact policy: their
//! library metadata can belong to a separately configured Cargo build directory.
//! An explicit retrieval-exclusion policy instead captures every reported
//! deliverable in the target tree, so another surviving file cannot conceal an
//! excluded library, executable or sidecar from the same completed invocation.

use super::artifact_patterns::cargo_bins;
use anyhow::{Context, Result};
use rch_common::CompilationKind;
use rch_telemetry::protocol::PIGGYBACK_MARKER;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
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
    Example,
}

impl TargetKind {
    fn as_str(&self) -> &'static str {
        match self {
            Self::Bin => "bin",
            Self::Test => "test",
            Self::Bench => "bench",
            Self::Example => "example",
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
/// capture is automatic; explicit retrieval exclusions additionally admit a
/// bounded full-build grammar and protect the original output selection.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub(super) struct CargoOutputCapture {
    selected: BTreeSet<SelectedTarget>,
    instrumented: bool,
    /// Opt-in exclusion safety needs every originally selected Cargo output,
    /// including libraries and sidecars. Freeze the pre-exclusion policy so
    /// detached collection cannot silently use current configuration instead.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    retrieval_baseline: Option<Vec<String>>,
}

/// Required regular files, relative to the project/target output phase.
/// Cargo's `executable` field is authoritative. With retrieval exclusions,
/// originally selected `filenames` also become required, protecting libraries
/// and sidecars without promoting private intermediates into deliverables.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub(super) struct CargoOutputContract {
    pub(super) required_files: BTreeSet<PathBuf>,
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
    /// The caller explicitly requested Cargo JSON for one supported family of
    /// named executables. Test/bench selections can only be constructed from
    /// Cargo's own --no-run mode; executing a test suite is not output capture.
    /// Instrumentation and mixed families in a restored recipe never opt in.
    pub(super) fn caller_json_supported(&self) -> bool {
        let Some(first) = self.selected.first() else {
            return false;
        };
        !self.instrumented
            && first.kind != TargetKind::Example
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
                && value
                    .pointer("/profile/test")
                    .and_then(serde_json::Value::as_bool)
                    == Some(target.kind != TargetKind::Bin),
            "caller JSON selected an ambiguous target or a different compilation mode"
        );
        Ok(Some(target))
    }

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
            retrieval_baseline: None,
        })
    }

    pub(super) fn for_retrieval_policy(
        kind: Option<CompilationKind>,
        command: &str,
        baseline: &[String],
        directories: &[String],
    ) -> Result<Option<Self>> {
        if directories.is_empty() {
            return Ok(Self::for_command(kind, command));
        }
        anyhow::ensure!(
            baseline.iter().any(|pattern| !pattern.starts_with("- ")),
            "Cargo retrieval exclusions require a nonempty original output selection"
        );
        crate::transfer::ArtifactFilters::from_patterns(baseline)
            .context("invalid original Cargo retrieval selection")?;
        let selection = cargo_bins::retrieval_selection(kind, command).context(
            "transfer.cargo_retrieval_exclude_dirs requires a literal Cargo build or test/bench --no-run command with a complete output receipt",
        )?;
        let instrumented = match selection.message_formats.as_slice() {
            [] => true,
            [format] if explicit_json_format(format) => false,
            _ => anyhow::bail!(
                "transfer.cargo_retrieval_exclude_dirs cannot establish complete outputs with this Cargo --message-format"
            ),
        };
        let mut capture = match Self::for_command(kind, command) {
            Some(capture) => capture,
            None => {
                anyhow::ensure!(
                    instrumented,
                    "Cargo retrieval exclusions require human output for a full build; caller JSON projection supports named executables only"
                );
                let selected = [
                    (TargetKind::Bin, selection.bins),
                    (TargetKind::Test, selection.tests),
                    (TargetKind::Bench, selection.benches),
                    (TargetKind::Example, selection.examples),
                ]
                .into_iter()
                .flat_map(|(kind, names)| {
                    names
                        .into_iter()
                        .map(move |name| SelectedTarget { kind, name })
                })
                .collect();
                Self {
                    selected,
                    instrumented,
                    retrieval_baseline: None,
                }
            }
        };
        anyhow::ensure!(
            instrumented || capture.caller_json_supported(),
            "Cargo retrieval exclusions require human output for a full build; caller JSON projection supports named executables only"
        );
        capture.retrieval_baseline = Some(baseline.to_vec());
        Ok(Some(capture))
    }

    pub(super) fn retrieval_baseline(&self) -> Option<&[String]> {
        self.retrieval_baseline.as_deref()
    }

    pub(super) fn supports_retrieval_exclusions(&self) -> bool {
        (self.instrumented || self.caller_json_supported())
            && self.retrieval_baseline.as_ref().is_some_and(|baseline| {
                baseline.iter().any(|pattern| !pattern.starts_with("- "))
                    && crate::transfer::ArtifactFilters::from_patterns(baseline).is_ok()
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
            !self.selected.is_empty() || self.supports_retrieval_exclusions(),
            "Cargo output capture has no selected targets"
        );
        let retrieval_filters = self
            .retrieval_baseline
            .as_ref()
            .map(|patterns| crate::transfer::ArtifactFilters::from_patterns(patterns))
            .transpose()?;
        anyhow::ensure!(
            self.retrieval_baseline.is_none() || self.supports_retrieval_exclusions(),
            "Cargo retrieval exclusions have no valid admitted output selection"
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
                    if let Some(filters) = &retrieval_filters {
                        let emitted =
                            complete_artifact_outputs(&artifact, remote_phase_roots, filters)?;
                        if matched
                            .iter()
                            .any(|target| target.kind == TargetKind::Example)
                        {
                            anyhow::ensure!(
                                !emitted.is_empty(),
                                "Cargo selected example {} has no deliverable in its recorded phase root",
                                artifact.target.name
                            );
                        }
                        required_files.extend(emitted);
                        for target in matched
                            .iter()
                            .filter(|target| target.kind == TargetKind::Example)
                        {
                            seen.insert((*target).clone());
                        }
                    }
                    let matched: Vec<_> = matched
                        .into_iter()
                        .filter(|target| target.kind != TargetKind::Example)
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
            "caller JSON requires named build or --no-run executables and an explicit JSON format"
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
            let executable = value
                .get("executable")
                .and_then(serde_json::Value::as_str)
                .context("selected Cargo record has no executable")?;
            anyhow::ensure!(
                executables.insert(relative_output_path(executable, remote_output_roots)?),
                "caller JSON has duplicate or colliding selected executable paths"
            );
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
                required_files.insert(relative_output_path(
                    filename
                        .as_str()
                        .context("selected Cargo filename is not a string")?,
                    remote_output_roots,
                )?);
            }
            anyhow::ensure!(
                value.get("rch").is_none(),
                "Cargo record already contains an RCH binding"
            );
        }
        anyhow::ensure!(
            selected == self.selected,
            "caller JSON did not bind every selected executable target"
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
            "caller JSON requires named build or --no-run executables and an explicit JSON format"
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
        let mut output = Vec::new();
        let mut files = BTreeSet::new();
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
            let executable = original
                .get("executable")
                .and_then(serde_json::Value::as_str)
                .context("selected Cargo record has no executable")?;
            let relative = relative_output_path(executable, remote_output_roots)?;
            value["executable"] = serde_json::to_value(local_output_root.join(&relative))?;
            files.insert(relative.clone());
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
                anyhow::ensure!(
                    published.contains_key(&relative),
                    "selected Cargo filename was not published by this invocation: {}",
                    relative.display()
                );
                local_filenames.push(local_output_root.join(&relative));
                files.insert(relative);
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
                "executable_blake3": published.get(&relative).context("selected executable has no publication fingerprint")?,
            });
            serde_json::to_writer(&mut output, &value)?;
            output.push(b'\n');
        }
        Ok(CargoCallerOutput {
            stdout: output,
            files,
        })
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

/// Validate every emitted pathname before ignoring build-script cache state.
/// All other outputs must resolve within the verified phase roots: the receipt
/// alone cannot prove that an external library is a dispensable dependency.
fn complete_artifact_outputs(
    artifact: &CompilerArtifact,
    roots: &[&Path],
    baseline: &crate::transfer::ArtifactFilters,
) -> Result<BTreeSet<PathBuf>> {
    let filenames = artifact
        .filenames
        .iter()
        .map(|name| complete_output_path(name, roots))
        .collect::<Result<Vec<_>>>()?;
    let executable = artifact
        .executable
        .as_deref()
        .map(|name| complete_output_path(name, roots))
        .transpose()?;
    let custom_build = artifact
        .target
        .kind
        .iter()
        .any(|kind| kind == "custom-build");
    anyhow::ensure!(
        !custom_build || artifact.target.kind.len() == 1,
        "Cargo compiler-artifact mixes a build script with deliverable target kinds"
    );
    if custom_build {
        // The build-script program is worker cache state, including when a
        // separate build.build-dir stores it outside the target directory.
        return Ok(BTreeSet::new());
    }
    anyhow::ensure!(
        !artifact.filenames.is_empty(),
        "Cargo compiler-artifact has no emitted filenames"
    );

    let executable = match executable {
        Some(relative) => {
            let relative =
                relative.context("Cargo executable is outside its recorded phase root")?;
            anyhow::ensure!(
                artifact
                    .filenames
                    .iter()
                    .any(|name| Some(name) == artifact.executable.as_ref()),
                "Cargo executable is not among its emitted filenames"
            );
            Some(relative)
        }
        None => None,
    };
    let mut required = BTreeSet::new();
    let mut bundled_files = BTreeSet::new();
    for (name, relative) in artifact.filenames.iter().zip(filenames) {
        let relative = relative
            .with_context(|| format!("Cargo output is outside its recorded phase root: {name}"))?;
        if let Some(companion) = name.strip_suffix(".dSYM") {
            // Cargo reports the bundle directory, not regular member files.
            // Its sibling must be another emitted, required output. Then an
            // exclusion of an ancestor necessarily conflicts with that file;
            // the exclusion policy rejects paths at or beneath a dSYM bundle.
            anyhow::ensure!(
                !companion.ends_with(".dSYM")
                    && artifact.filenames.iter().any(|name| name == companion),
                "Cargo dSYM bundle has no emitted companion file: {name}"
            );
            let companion = complete_output_path(companion, roots)?
                .context("Cargo dSYM bundle companion is outside its recorded phase root")?;
            bundled_files.insert(companion);
            continue;
        }
        // Build-only test/bench executables in the new layout live under
        // build/<pkg>/<hash>/out/. An executable remains required even when
        // the baseline excluded its cache parent or no target was named.
        let executable_file = executable.as_ref() == Some(&relative);
        let relative_name = relative.to_str().context("non-UTF-8 Cargo output path")?;
        if executable_file || baseline.selects(relative_name) {
            required.insert(relative);
        }
    }
    if let Some(executable) = executable {
        required.insert(executable);
    }
    anyhow::ensure!(
        bundled_files.iter().all(|file| required.contains(file)),
        "Cargo dSYM bundle companion is not a required deliverable file"
    );
    Ok(required)
}

fn complete_output_path(name: &str, roots: &[&Path]) -> Result<Option<PathBuf>> {
    let path = Path::new(name);
    validate_absolute_path(path)?;
    anyhow::ensure!(
        !name.chars().any(char::is_control)
            && !name.contains(['\\', ':'])
            && !name.split('/').skip(1).any(str::is_empty),
        "Cargo output path is not a literal normalized pathname: {name:?}"
    );
    if roots.iter().any(|root| path.starts_with(root)) {
        relative_output_path(name, roots).map(Some)
    } else {
        Ok(None)
    }
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
            ("cargo build --example cli --message-format=json", false),
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

    #[test]
    fn retrieval_exclusion_capture_accepts_complete_literal_builds_only() {
        for (kind, command) in [
            (CompilationKind::CargoBuild, "cargo build"),
            (
                CompilationKind::CargoBuild,
                "cargo b --workspace --all-targets --offline",
            ),
            (
                CompilationKind::CargoBuild,
                "cargo build --lib --bins --examples --tests --benches",
            ),
            (
                CompilationKind::CargoBuild,
                "env 'CARGO_TARGET_DIR=/tmp/output with spaces' rustup run nightly cargo build --workspace --profile lean --manifest-path 'project λ/Cargo.toml'",
            ),
            (
                CompilationKind::CargoBuild,
                "cargo build --bin app --example demo --test smoke --bench measure",
            ),
            (
                CompilationKind::CargoTest,
                "cargo +nightly t --no-run --workspace --all-targets",
            ),
            (
                CompilationKind::CargoBench,
                "cargo bench --no-run --bench measure --lib",
            ),
            (
                CompilationKind::CargoZigbuild,
                "cargo zigbuild --target aarch64-unknown-linux-gnu --release --workspace",
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
            .unwrap_or_else(|error| panic!("refused complete capture for {command}: {error:#}"))
            .unwrap();
            assert!(capture.supports_retrieval_exclusions(), "{command}");
            assert!(!capture.caller_json_supported(), "{command}");
            assert_eq!(
                capture.execution_command(command),
                format!("{command} --message-format=json,json-render-diagnostics")
            );
            let restored: CargoOutputCapture =
                serde_json::from_slice(&serde_json::to_vec(&capture).unwrap()).unwrap();
            assert_eq!(capture, restored);
            assert!(restored.supports_retrieval_exclusions());
        }
        for (kind, command) in [
            (
                CompilationKind::CargoBuild,
                "cargo build --message-format=json",
            ),
            (
                CompilationKind::CargoBuild,
                "cargo build --bin app --message-format=human",
            ),
            (
                CompilationKind::CargoBuild,
                "cargo build --config 'build.target=\"custom.json\"'",
            ),
            (
                CompilationKind::CargoBuild,
                "cargo build -Z unstable-options",
            ),
            (
                CompilationKind::CargoBuild,
                "cargo build --target custom.json",
            ),
            (CompilationKind::CargoBuild, "cargo build --bin '$APP'"),
            (CompilationKind::CargoBuild, "cargo build; true"),
            (CompilationKind::CargoBuild, "cargo build --no-run"),
            (CompilationKind::CargoBuild, "cargo build --lib=true"),
            (CompilationKind::CargoBuild, "cargo package"),
            (CompilationKind::CargoTest, "cargo test --workspace"),
            (CompilationKind::CargoTest, "cargo test -- --no-run"),
            (CompilationKind::CargoBench, "cargo bench --bench measure"),
            (CompilationKind::CargoDoc, "cargo doc"),
        ] {
            let baseline = vec!["debug/***".into()];
            assert!(
                CargoOutputCapture::for_retrieval_policy(
                    Some(kind),
                    command,
                    &baseline,
                    &["debug/.wrapper-shims".into()],
                )
                .is_err(),
                "{command}"
            );
        }
        assert!(
            CargoOutputCapture::for_command(Some(CompilationKind::CargoBuild), "cargo build")
                .is_none()
        );
        let named = capture("cargo build --bin app --message-format=json");
        assert!(named.caller_json_supported());
        assert!(!named.supports_retrieval_exclusions());
        let kind = Some(CompilationKind::CargoBuild);
        let command = "cargo build --bin app --message-format=json";
        let baseline = super::super::artifact_patterns::get_custom_target_artifact_patterns(
            kind,
            Some(command),
        );
        let named = CargoOutputCapture::for_retrieval_policy(
            kind,
            command,
            &baseline,
            &["debug/.wrapper-shims".into()],
        )
        .unwrap()
        .unwrap();
        assert!(named.caller_json_supported());
        assert!(named.supports_retrieval_exclusions());
        assert_eq!(named.execution_command(command), command);
        let legacy: CargoOutputCapture = serde_json::from_value(json!({
            "selected":[{"kind":"bin","name":"app"}],"instrumented":true
        }))
        .unwrap();
        assert!(!legacy.supports_retrieval_exclusions());
    }

    #[test]
    fn cargo_retrieval_capture_protects_full_fresh_library_and_binary_sets() {
        let kind = Some(CompilationKind::CargoBuild);
        let command = "cargo build --workspace --profile lean --target aarch64-unknown-linux-gnu";
        let baseline = super::super::artifact_patterns::get_custom_target_artifact_patterns(
            kind,
            Some(command),
        );
        let capture = CargoOutputCapture::for_retrieval_policy(
            kind,
            command,
            &baseline,
            &["lean/.wrapper-shims".into()],
        )
        .unwrap()
        .unwrap();
        let records = [
            artifact(
                "lib",
                "support",
                &[
                    "/worker/target/lean/libsupport.rlib",
                    "/worker/target/lean/deps/libsupport-123.rlib",
                    "/worker/target/lean/deps/libsupport-123.rmeta",
                    "/worker/target/lean/libsupport.d",
                    "/worker/target/lean/build/support/hash/out/libsupport.rmeta",
                ],
                None,
                true,
            ),
            artifact(
                "bin",
                "alpha",
                &[
                    "/worker/target/lean/alpha",
                    "/worker/target/lean/alpha.pdb",
                    "/worker/target/lean/alpha.dSYM",
                ],
                Some("/worker/target/lean/alpha"),
                false,
            ),
            artifact(
                "bin",
                "beta",
                &["/alias/target/aarch64-unknown-linux-gnu/lean/beta"],
                Some("/alias/target/aarch64-unknown-linux-gnu/lean/beta"),
                true,
            ),
            artifact(
                "custom-build",
                "build-script-build",
                &["/outside/private/build-script-build"],
                Some("/outside/private/build-script-build"),
                true,
            ),
        ];
        let roots = [Path::new("/worker/target"), Path::new("/alias/target")];
        let contract = capture
            .parse_receipt_with_roots(&receipt(&records), &roots)
            .unwrap();
        assert_eq!(
            contract.required_files,
            BTreeSet::from([
                "lean/libsupport.rlib".into(),
                "lean/deps/libsupport-123.rlib".into(),
                "lean/deps/libsupport-123.rmeta".into(),
                "lean/alpha".into(),
                "lean/alpha.pdb".into(),
                "aarch64-unknown-linux-gnu/lean/beta".into(),
            ])
        );
        assert!(
            capture
                .parse_receipt_with_roots(&receipt(&[]), &roots)
                .is_err()
        );
        assert!(
            capture
                .parse_receipt_with_roots(
                    &receipt(&[artifact(
                        "bin",
                        "outside",
                        &["/outside/app"],
                        Some("/outside/app"),
                        true
                    )]),
                    &roots
                )
                .is_err()
        );
        let missing_terminal = format!("{}\n", records[0]);
        assert!(
            capture
                .parse_receipt_with_roots(missing_terminal.as_bytes(), &roots)
                .is_err()
        );
        let restored: CargoOutputCapture =
            serde_json::from_slice(&serde_json::to_vec(&capture).unwrap()).unwrap();
        assert_eq!(
            restored
                .parse_receipt_with_roots(&receipt(&records), &roots)
                .unwrap(),
            contract
        );

        // A surviving executable cannot cover a missing library from the
        // same receipt; only the complete owned staging set satisfies it.
        let stage = tempfile::tempdir().unwrap();
        for relative in contract
            .required_files
            .iter()
            .filter(|path| !path.ends_with("libsupport.rlib"))
        {
            let file = stage.path().join(relative);
            std::fs::create_dir_all(file.parent().unwrap()).unwrap();
            std::fs::write(file, relative.as_os_str().as_encoded_bytes()).unwrap();
        }
        assert!(contract.verify_staged(stage.path()).is_err());
        std::fs::write(
            stage.path().join("lean/libsupport.rlib"),
            b"required library",
        )
        .unwrap();
        contract.verify_staged(stage.path()).unwrap();
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
                true,
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

    #[test]
    fn retrieval_exclusion_capture_preserves_unnamed_new_layout_executables() {
        for (kind, command, target_kind) in [
            (
                CompilationKind::CargoTest,
                "cargo test --no-run --profile lean",
                "test",
            ),
            (
                CompilationKind::CargoBench,
                "cargo bench --no-run --profile lean",
                "bench",
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
                &["lean/.wrapper-shims".into()],
            )
            .unwrap()
            .unwrap();
            assert!(capture.selected.is_empty());
            let executable = "/worker/target/lean/build/pkg/hash/out/smoke-0123456789abcdef";
            let data = receipt(&[artifact(
                target_kind,
                "smoke",
                &[executable],
                Some(executable),
                true,
            )]);
            let contract = capture
                .parse_receipt(&data, Path::new("/worker/target"))
                .unwrap();
            assert_eq!(
                contract.required_files,
                [PathBuf::from(
                    "lean/build/pkg/hash/out/smoke-0123456789abcdef"
                )]
                .into_iter()
                .collect()
            );
        }
    }

    #[test]
    fn retrieval_exclusion_capture_requires_a_deliverable_companion_for_each_bundle() {
        let kind = Some(CompilationKind::CargoBuild);
        let baseline = super::super::artifact_patterns::get_custom_target_artifact_patterns(
            kind,
            Some("cargo build"),
        );
        let capture = CargoOutputCapture::for_retrieval_policy(
            kind,
            "cargo build",
            &baseline,
            &["debug/.wrapper-shims".into()],
        )
        .unwrap()
        .unwrap();
        let root = Path::new("/worker/target");
        let app = artifact(
            "bin",
            "app",
            &["/worker/target/debug/app"],
            Some("/worker/target/debug/app"),
            true,
        );
        for files in [
            vec!["/worker/target/debug/.private/library.dSYM"],
            vec![
                "/worker/build-dir/library",
                "/worker/build-dir/library.dSYM",
            ],
            vec![
                "/worker/target/debug/build/pkg/library",
                "/worker/target/debug/build/pkg/library.dSYM",
            ],
        ] {
            let unsupported = artifact("lib", "library", &files, None, true);
            assert!(
                capture
                    .parse_receipt(&receipt(&[app.clone(), unsupported]), root)
                    .is_err(),
                "{files:?}"
            );
        }
        // The actual emitted sibling is protected regardless of placement;
        // no profile-directory guess can bless an unpaired private bundle.
        let paired = artifact(
            "lib",
            "library",
            &[
                "/worker/target/debug/.private/library",
                "/worker/target/debug/.private/library.dSYM",
            ],
            None,
            true,
        );
        let contract = capture
            .parse_receipt(&receipt(&[app, paired]), root)
            .unwrap();
        assert!(
            contract
                .required_files
                .contains(&PathBuf::from("debug/.private/library"))
        );
        assert!(
            !contract
                .required_files
                .contains(&PathBuf::from("debug/.private/library.dSYM"))
        );
    }

    #[test]
    fn retrieval_exclusion_capture_keeps_named_executable_and_example_requirements() {
        let kind = Some(CompilationKind::CargoBuild);
        let command = "cargo build --bin app --example library --lib";
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
        let root = Path::new("/worker/target");
        let app = artifact(
            "bin",
            "app",
            &["/worker/target/debug/app"],
            Some("/worker/target/debug/app"),
            true,
        );
        let example = artifact(
            "example",
            "library",
            &["/worker/target/debug/examples/liblibrary.a"],
            None,
            true,
        );
        assert!(
            capture
                .parse_receipt(&receipt(std::slice::from_ref(&app)), root)
                .is_err()
        );
        assert!(
            capture
                .parse_receipt(&receipt(std::slice::from_ref(&example)), root)
                .is_err()
        );
        let contract = capture
            .parse_receipt(&receipt(&[app, example]), root)
            .unwrap();
        assert_eq!(contract.required_files.len(), 2);
    }

    #[test]
    fn retrieval_exclusion_capture_validates_paths_before_ignoring_cache_records() {
        let kind = Some(CompilationKind::CargoBuild);
        let baseline = super::super::artifact_patterns::get_custom_target_artifact_patterns(
            kind,
            Some("cargo build"),
        );
        let capture = CargoOutputCapture::for_retrieval_policy(
            kind,
            "cargo build",
            &baseline,
            &["debug/.wrapper-shims".into()],
        )
        .unwrap()
        .unwrap();
        let root = Path::new("/worker/target");
        let app = artifact(
            "bin",
            "app",
            &["/worker/target/debug/app"],
            Some("/worker/target/debug/app"),
            true,
        );
        for path in [
            "/worker/build-dir/../escape.rlib",
            "/worker/target/debug/./bad.rlib",
            "/worker/target/debug//bad.rlib",
            "relative/libbad.rlib",
            "/worker/target",
            "/worker/build-dir/bad\nfile",
            "/worker/target/debug/bad\0file",
            "/worker/target/debug/bad\tfile",
            "/worker/target/debug/bad\\file",
        ] {
            for kind in ["lib", "custom-build"] {
                let invalid = artifact(kind, "unselected", &[path], None, true);
                assert!(
                    capture
                        .parse_receipt(&receipt(&[app.clone(), invalid]), root)
                        .is_err(),
                    "{kind}: {path:?}"
                );
            }
        }
        for path in ["/worker/other/app", "/worker/target-other/app"] {
            let outside = artifact("bin", "outside", &[path], Some(path), true);
            assert!(
                capture
                    .parse_receipt(&receipt(&[app.clone(), outside]), root)
                    .is_err()
            );
        }
        // A receipt does not identify which out-of-root libraries are merely
        // dependencies. Even a valid in-root executable cannot bless their loss.
        for path in [
            "/worker/build-dir/debug/deps/libdependency.rmeta",
            "/worker/build-dir/debug/libprimary.rlib",
        ] {
            let outside = artifact("lib", "outside", &[path], None, true);
            assert!(
                capture
                    .parse_receipt(&receipt(&[app.clone(), outside]), root)
                    .is_err(),
                "{path}"
            );
        }
        let mixed = json!({
            "reason":"compiler-artifact",
            "target":{"name":"mixed","kind":["custom-build","lib"]},
            "filenames":["/worker/build-dir/debug/libprimary.rlib"],
            "executable":null,
            "fresh":true,
        });
        assert!(
            capture
                .parse_receipt(&receipt(&[app.clone(), mixed]), root)
                .is_err()
        );
        let missing = artifact(
            "bin",
            "outside",
            &["/worker/target/debug/unrelated"],
            Some("/worker/target/debug/outside"),
            true,
        );
        assert!(
            capture
                .parse_receipt(&receipt(&[app, missing]), root)
                .is_err()
        );
    }

    #[test]
    fn retrieval_exclusion_capture_rejects_incomplete_or_empty_output_evidence() {
        let kind = Some(CompilationKind::CargoBuild);
        let command = "cargo build --lib";
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
        let root = Path::new("/worker/target");
        let output = artifact(
            "lib",
            "support",
            &["/worker/target/debug/libsupport.rlib"],
            None,
            true,
        );
        let valid = receipt(std::slice::from_ref(&output));
        assert!(
            capture
                .parse_receipt(&valid[..valid.len() - 1], root)
                .is_err()
        );
        assert!(
            capture
                .parse_receipt(format!("{output}\n").as_bytes(), root)
                .is_err()
        );
        for tail in [
            "{\"reason\":\"build-finished\",\"success\":false}\n",
            "{\"reason\":\"compiler-artifact\"\n",
            "{\"reason\":\"build-finished\",\"success\":true}\n{\"reason\":\"build-finished\",\"success\":true}\n",
        ] {
            assert!(
                capture
                    .parse_receipt(format!("{output}\n{tail}").as_bytes(), root)
                    .is_err()
            );
        }
        assert!(capture.parse_receipt(&receipt(&[]), root).is_err());
        assert!(
            capture
                .parse_receipt(
                    &receipt(&[artifact(
                        "lib",
                        "support",
                        &["/worker/build-dir/debug/libsupport.rmeta"],
                        None,
                        true
                    )]),
                    root
                )
                .is_err()
        );
        let mut late = valid.clone();
        late.extend_from_slice(format!("{output}\n").as_bytes());
        assert!(capture.parse_receipt(&late, root).is_err());
        capture.parse_receipt(&valid, root).unwrap();
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn real_cargo_retrieval_exclusion_capture_covers_fresh_workspace_libs_and_bins() {
        use std::process::Stdio;
        use std::time::Duration;
        use tokio::process::Command;

        let root = tempfile::tempdir().unwrap();
        let source = root.path().join("workspace λ with spaces");
        std::fs::create_dir_all(&source).unwrap();
        std::fs::write(
            source.join("Cargo.toml"),
            "[workspace]\nmembers = [\"alpha\", \"beta\"]\nresolver = \"3\"\n",
        )
        .unwrap();
        for member in ["alpha", "beta"] {
            let package = source.join(member);
            std::fs::create_dir_all(package.join("src")).unwrap();
            std::fs::write(package.join("Cargo.toml"), format!("[package]\nname = \"rch_capture_{member}\"\nversion = \"0.0.0\"\nedition = \"2024\"\n")).unwrap();
            std::fs::write(package.join("src/lib.rs"), "pub fn value() -> u32 { 42 }\n").unwrap();
            std::fs::write(
                package.join("src/main.rs"),
                format!("fn main() {{ println!(\"{{}}\", rch_capture_{member}::value()); }}\n"),
            )
            .unwrap();
        }
        let target = root.path().canonicalize().unwrap().join("worker target λ");
        let command = "cargo build --workspace --offline --jobs=1";
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
        let restored: CargoOutputCapture =
            serde_json::from_slice(&serde_json::to_vec(&capture).unwrap()).unwrap();
        let mut previous = None;
        for warm in [false, true] {
            let cargo = std::env::var_os("CARGO").unwrap_or_else(|| "cargo".into());
            let mut compile = Command::new(cargo);
            compile
                .current_dir(&source)
                .args(
                    capture
                        .execution_command(command)
                        .split_ascii_whitespace()
                        .skip(1),
                )
                .env("CARGO_HOME", root.path().join("cargo-home"))
                .env("CARGO_TARGET_DIR", &target)
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
                .expect("owned Cargo complete-output fixture timed out")
                .expect("Cargo is required for native complete-output coverage");
            assert!(
                result.status.success(),
                "{}",
                String::from_utf8_lossy(&result.stderr)
            );
            let contract = restored.parse_receipt(&result.stdout, &target).unwrap();
            contract.verify_staged(&target).unwrap();
            for member in ["alpha", "beta"] {
                assert!(
                    contract
                        .required_files
                        .contains(&PathBuf::from(format!("debug/rch_capture_{member}")))
                );
                assert!(contract.required_files.contains(&PathBuf::from(format!(
                    "debug/librch_capture_{member}.rlib"
                ))));
            }
            let records: Vec<serde_json::Value> = std::str::from_utf8(&result.stdout)
                .unwrap()
                .lines()
                .map(|line| serde_json::from_str(line).unwrap())
                .filter(|record: &serde_json::Value| record["reason"] == "compiler-artifact")
                .collect();
            assert_eq!(records.len(), 4);
            assert!(records.iter().all(|record| record["fresh"] == warm));
            if let Some(previous) = previous.as_ref() {
                assert_eq!(&contract, previous);
            }
            previous = Some(contract);
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
