//! Opt-in planning of the command Cargo will actually compile.
//!
//! The complete source anchor and lock/index inputs remain retained. Cargo's
//! unit graph, rather than a second feature resolver or a target-filtered
//! metadata graph, selects both host and target compiler inputs. This is input
//! preparation only; it grants no execution or action-cache authority.

use super::{
    MAX_PACKAGES, OUTPUT_LIMIT, PreparationContext, PreparationControl, captured_metadata_path,
    graph, invalid, registry::RegistryCache, require, validate_metadata_packages_controlled,
};
use rabs_sandbox::cargo_check::{CompilationCommand, CompilationSelection, run_build_selection};
use rabs_sandbox::process_context::{COMMAND_CONTEXT_VERSION, CommandContext};
use rabs_sandbox::snapshot_capture::SealedSourceSnapshot;
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};
use std::io;
use std::path::Path;
use std::process::Command;

pub(super) const VERSION: &str = "cargo-unit-graph-v1";

#[derive(Debug)]
pub(super) struct SelectedCommand {
    manifest: String,
    pub(super) command: CompilationCommand,
    selection: CompilationSelection,
    environment: Vec<(String, String)>,
    jobs: Option<u32>,
}

impl SelectedCommand {
    /// Derive the selection from the actual request, never from a second caller
    /// supplied feature/target declaration. Refuse mismatched execution context
    /// before any source, cache or toolchain is opened for this new mode.
    pub(super) fn parse(
        request: &Value,
        manifest: &str,
        preparation: PreparationContext,
    ) -> io::Result<Self> {
        require(
            request["program"] == "/__rabs/toolchain/bin/cargo",
            "selected Cargo preparation requires the canonical Cargo executable",
        )?;
        let args = request["args"]
            .as_array()
            .filter(|args| !args.is_empty() && args.len() <= 256)
            .ok_or_else(|| invalid("selected Cargo arguments are missing or excessive"))?
            .iter()
            .map(|value| {
                value
                    .as_str()
                    .filter(|value| value.len() <= 4096 && !value.contains('\0'))
                    .ok_or_else(|| invalid("invalid selected Cargo argument"))
            })
            .collect::<io::Result<Vec<_>>>()?;
        let command = match args[0] {
            "build" => CompilationCommand::Build,
            "check" => CompilationCommand::Check,
            "test" => CompilationCommand::Test,
            "run" => CompilationCommand::Run,
            "bench" => CompilationCommand::Bench,
            _ => {
                return Err(invalid(
                    "selected Cargo preparation supports build, check, test, run and bench",
                ));
            }
        };
        let canonical_manifest = format!("/__rabs/workspace/{manifest}");
        let cwd = Path::new(&canonical_manifest)
            .parent()
            .and_then(Path::to_str)
            .ok_or_else(|| invalid("selected Cargo manifest parent missing"))?;
        let context = request["command_context"]
            .as_object()
            .filter(|fields| {
                fields.len() == 3
                    && fields.get("version").and_then(Value::as_str)
                        == Some(COMMAND_CONTEXT_VERSION)
                    && fields.get("cwd").and_then(Value::as_str) == Some(cwd)
            })
            .ok_or_else(|| {
                invalid("selected Cargo preparation requires its manifest-parent context")
            })?;
        let native = preparation == PreparationContext::CanonicalLocal;
        let inputs = context
            .get("env")
            .and_then(Value::as_object)
            .ok_or_else(|| {
                invalid("selected Cargo preparation requires an explicit environment")
            })?;
        if native {
            require(
                inputs.get("CARGO_INCREMENTAL").and_then(Value::as_str) == Some("0")
                    && inputs.get("CARGO_TARGET_DIR").and_then(Value::as_str)
                        == Some("/__rabs/out/cargo")
                    && inputs.get("RUSTC").and_then(Value::as_str)
                        == Some("/__rabs/toolchain/bin/rustc")
                    && if command == CompilationCommand::Test {
                        inputs.get("RUSTDOC").and_then(Value::as_str)
                            == Some("/__rabs/toolchain/bin/rustdoc")
                    } else {
                        !inputs.contains_key("RUSTDOC")
                    },
                "selected native Cargo preparation requires the driver's exact compiler controls",
            )?;
        }
        let environment = inputs
            .iter()
            .map(|(name, value)| {
                let value = value
                    .as_str()
                    .ok_or_else(|| invalid("selected Cargo environment values must be strings"))?;
                if name == "CARGO_INCREMENTAL" {
                    require(matches!(value, "0" | "1"), "invalid selected Cargo incremental policy")?;
                } else if !native || !matches!(name.as_str(), "CARGO_TARGET_DIR" | "RUSTC" | "RUSTDOC") {
                    // Only the complete fixed native control set checked above
                    // bypasses this rule. Public requests retain the same boundary.
                    require(
                        !matches!(name.as_str(), "CARGO" | "RUSTC" | "RUSTDOC" | "RUSTFLAGS" | "RUSTDOCFLAGS" | "GLIBC_TUNABLES")
                            && !["CARGO_", "RUSTUP_", "RUSTC_", "RUSTDOC_", "CLIPPY_", "LD_", "DYLD_", "GIT_", "RABS_", "RCH_"]
                                .iter().any(|prefix| name.starts_with(prefix)),
                        "selected Cargo preparation refuses compiler and resolution environment overrides",
                    )?;
                }
                Ok((name.clone(), value.to_owned()))
            })
            .collect::<io::Result<Vec<_>>>()?;
        let context = CommandContext::new(cwd, environment)
            .map_err(|_| invalid("invalid selected Cargo command context"))?;

        let mut selection = CompilationSelection::default();
        let mut controls = BTreeSet::new();
        let mut jobs = None;
        let mut at = 1;
        while at < args.len() {
            if args[at] == "--" {
                require(
                    matches!(
                        command,
                        CompilationCommand::Test
                            | CompilationCommand::Run
                            | CompilationCommand::Bench
                    ) && !selection.no_run,
                    "selected Cargo program arguments require test, run or bench execution",
                )?;
                // The remaining bounded argv belongs to the program or harness,
                // including option-looking values and literal control bytes.
                // Keep it in the original request, never pass it to planning:
                // otherwise it could swallow the nonexecuting unit-graph switch.
                break;
            }
            if !args[at].starts_with('-')
                && matches!(
                    command,
                    CompilationCommand::Test | CompilationCommand::Bench
                )
            {
                require(
                    selection.test_filter.is_none(),
                    "selected Cargo accepts one test or benchmark name filter",
                )?;
                selection.test_filter = Some(args[at].to_owned());
                at += 1;
                continue;
            }
            let (option, inline) = args[at]
                .split_once('=')
                .map_or((args[at], None), |(option, value)| (option, Some(value)));
            match option {
                "--package" | "-p" | "--exclude" | "--features" | "-F" | "--bin" | "--test"
                | "--example" | "--bench" | "--target" | "--profile" | "--manifest-path"
                | "--target-dir" | "--message-format" | "--color" | "--jobs" => {
                    let value = match inline {
                        Some(value) => value,
                        None => {
                            at += 1;
                            *args
                                .get(at)
                                .ok_or_else(|| invalid("selected Cargo option requires a value"))?
                        }
                    };
                    require(
                        !value.is_empty() && !value.starts_with('-'),
                        "invalid selected Cargo option value",
                    )?;
                    match option {
                        "--package" | "-p" => selection.packages.push(value.to_owned()),
                        "--exclude" => selection.exclude.push(value.to_owned()),
                        "--features" | "-F" => selection.features.push(value.to_owned()),
                        "--bin" => selection.bin.push(value.to_owned()),
                        "--test" => selection.test.push(value.to_owned()),
                        "--example" => selection.example.push(value.to_owned()),
                        "--bench" => selection.bench.push(value.to_owned()),
                        "--target" => {
                            require(
                                selection.target.is_empty()
                                    && matches!(
                                        value,
                                        "x86_64-unknown-linux-gnu"
                                            | "aarch64-unknown-linux-gnu"
                                            | "x86_64-unknown-linux-musl"
                                            | "aarch64-unknown-linux-musl"
                                    ),
                                "selected Cargo requires one supported Linux target",
                            )?;
                            selection.target.push(value.to_owned());
                        }
                        "--profile" => {
                            require(
                                selection.profile.is_none(),
                                "duplicate selected Cargo profile",
                            )?;
                            selection.profile = Some(value.to_owned());
                        }
                        "--jobs" => {
                            let count = value.parse::<u32>().ok().filter(|count| {
                                (1..=4096).contains(count) && count.to_string() == value
                            });
                            require(
                                native && jobs.is_none() && count.is_some(),
                                "selected native Cargo jobs must be one integer between 1 and 4096",
                            )?;
                            jobs = count;
                        }
                        "--color" => require(
                            matches!(value, "auto" | "always" | "never"),
                            "invalid Cargo color",
                        )?,
                        _ => {
                            let expected = match option {
                                "--manifest-path" => canonical_manifest.as_str(),
                                "--target-dir" => "/__rabs/out/cargo",
                                "--message-format" => "json",
                                _ => unreachable!(),
                            };
                            require(
                                value == expected
                                    && controls.insert(option)
                                    && (!native || option != "--target-dir"),
                                "selected Cargo transport controls differ from execution",
                            )?;
                        }
                    }
                }
                "--locked" | "--offline" | "--frozen" if inline.is_none() => {
                    require(
                        controls.insert(option),
                        "duplicate selected Cargo resolution control",
                    )?;
                }
                "--verbose" | "-v" | "-vv" | "--quiet" | "-q" if inline.is_none() => {}
                _ if inline.is_none() => {
                    let flag = match option {
                        "--workspace" => &mut selection.workspace,
                        "--all-features" => &mut selection.all_features,
                        "--no-default-features" => &mut selection.no_default_features,
                        "--lib" => &mut selection.lib,
                        "--bins" => &mut selection.bins,
                        "--tests" => &mut selection.tests,
                        "--examples" => &mut selection.examples,
                        "--benches" => &mut selection.benches,
                        "--all-targets" => &mut selection.all_targets,
                        "--release" | "-r" => &mut selection.release,
                        "--doc" => &mut selection.doc,
                        "--no-run" => &mut selection.no_run,
                        "--no-fail-fast" => &mut selection.no_fail_fast,
                        _ => return Err(invalid("unsupported selected Cargo argument")),
                    };
                    require(!*flag, "duplicate selected Cargo flag")?;
                    *flag = true;
                }
                _ => return Err(invalid("unsupported selected Cargo argument")),
            }
            at += 1;
        }
        require(
            ["--manifest-path", "--message-format"]
                .iter()
                .all(|name| controls.contains(name))
                && if native {
                    jobs.is_some()
                } else {
                    controls.contains("--target-dir")
                }
                && (controls.contains("--frozen")
                    || (controls.contains("--locked") && controls.contains("--offline"))),
            "selected Cargo requires its exact locked offline transport controls",
        )?;
        require(
            !selection.no_run || (!selection.doc && selection.test_filter.is_none()),
            "selected Cargo filters and documentation tests require execution",
        )?;
        selection.cargo_arguments(command)?;
        Ok(Self {
            manifest: manifest.to_owned(),
            command,
            selection,
            environment: context.environment().to_vec(),
            jobs,
        })
    }

    /// The retained request keeps canonical paths. Only the private planner
    /// receives their counterparts inside the captured toolchain and scratch.
    pub(super) fn configure(&self, command: &mut Command, rustc: &Path, planning: &Path) {
        for (name, value) in &self.environment {
            match name.as_str() {
                "RUSTC" => command.env(name, rustc),
                "RUSTDOC" => command.env(name, rustc.with_file_name("rustdoc")),
                "CARGO_TARGET_DIR" => command.env(name, planning.join("target")),
                _ => command.env(name, value),
            };
        }
    }

    /// `cargo run` does not reliably return a graph without looking for its
    /// executable. Resolve only its planning target with Cargo's own metadata
    /// and pkgid output, then query an exact build. The execution request stays
    /// a run with its original argument tail.
    pub(super) fn graph_arguments(
        &self,
        metadata: &Value,
        package_id: Option<&str>,
    ) -> io::Result<Vec<String>> {
        let mut arguments = if self.command == CompilationCommand::Run {
            run_build_selection(&self.selection, metadata, package_id)?
                .cargo_arguments(CompilationCommand::Build)?
        } else {
            self.selection.cargo_arguments(self.command)?
        };
        if let Some(jobs) = self.jobs {
            arguments.extend(["--jobs".into(), jobs.to_string()]);
        }
        Ok(arguments)
    }

    /// An explicit target already lets Cargo resolve its ordinary package
    /// selector. A default-run target additionally needs the exact package ID;
    /// its spelling comes from captured Cargo, never a second spec parser.
    pub(super) fn run_package(&self) -> Option<&str> {
        (self.command == CompilationCommand::Run
            && self.selection.bin.is_empty()
            && self.selection.example.is_empty())
        .then(|| self.selection.packages.first().map(String::as_str))
        .flatten()
    }
}

/// Cargo's target cfg must not depend on the coordinator's physical CPU.
pub(super) fn validate_host_independent_config(
    image: &SealedSourceSnapshot,
    manifest: &str,
    control: &PreparationControl<'_>,
) -> io::Result<()> {
    for path in super::active_cargo_configs(image, manifest)? {
        control.checkpoint()?;
        let bytes = image
            .file_bytes("workspace", &path)
            .filter(|bytes| bytes.len() <= OUTPUT_LIMIT as usize)
            .ok_or_else(|| invalid("selected Cargo configuration is missing or excessive"))?;
        let value: toml::Value = toml::from_str(
            std::str::from_utf8(bytes)
                .map_err(|_| invalid("selected Cargo configuration is not UTF-8"))?,
        )
        .map_err(|_| invalid("selected Cargo configuration is malformed"))?;
        let mut configurations = Vec::new();
        if let Some(flags) = value.get("build").and_then(|value| value.get("rustflags")) {
            configurations.push(flags);
        }
        if let Some(targets) = value.get("target").and_then(toml::Value::as_table) {
            configurations.extend(
                targets
                    .values()
                    .filter_map(|target| target.get("rustflags")),
            );
        }
        for flags in configurations {
            let mut arguments = super::compiler_flag_arguments(flags)?.into_iter();
            while let Some(argument) = arguments.next() {
                let codegen = if matches!(argument, "-C" | "--codegen") {
                    arguments.next()
                } else {
                    argument
                        .strip_prefix("-C")
                        .or_else(|| argument.strip_prefix("--codegen="))
                };
                require(
                    codegen != Some("target-cpu=native"),
                    "selected Cargo preparation requires an explicit CPU, not host-dependent target-cpu=native",
                )?;
            }
        }
    }
    Ok(())
}

/// Modern Cargo package IDs keep the source URL and package name/version.
/// The short fragment is admitted only when the URL itself names that package;
/// registry packages sharing one index can never alias by version alone.
pub(super) fn package_id_matches(id: &str, source: &str, name: &str, version: &str) -> bool {
    let Some(fragment) = id
        .strip_prefix(source)
        .and_then(|tail| tail.strip_prefix('#'))
    else {
        return false;
    };
    if fragment == format!("{name}@{version}") {
        return true;
    }
    let url = source.split_once('?').map_or(source, |(url, _)| url);
    fragment == version
        && url.rsplit('/').next().is_some_and(|leaf| {
            leaf == name || source.starts_with("git+") && leaf.strip_suffix(".git") == Some(name)
        })
}

/// Decode only the local file URL form Cargo emits for a path package. The
/// resulting exact directory must later name a captured control manifest.
pub(super) fn local_package_directory(id: &str) -> io::Result<(&str, String)> {
    let (source, fragment) = id
        .rsplit_once('#')
        .ok_or_else(|| invalid("selected path package lacks an identity"))?;
    let path = source
        .strip_prefix("path+file://")
        .filter(|path| path.starts_with('/'))
        .ok_or_else(|| invalid("selected local package requires an absolute file URL"))?;
    let mut decoded = Vec::with_capacity(path.len());
    let mut at = 0;
    while at < path.len() {
        let byte = path.as_bytes()[at];
        if byte == b'%' {
            let pair = path
                .get(at + 1..at + 3)
                .ok_or_else(|| invalid("invalid path package URL escape"))?;
            let byte = u8::from_str_radix(pair, 16)
                .map_err(|_| invalid("invalid path package URL escape"))?;
            require(
                !matches!(byte, b'/' | b'\\'),
                "path package URL encodes a separator",
            )?;
            decoded.push(byte);
            at += 3;
        } else {
            decoded.push(byte);
            at += 1;
        }
    }
    let decoded =
        String::from_utf8(decoded).map_err(|_| invalid("path package URL is not UTF-8"))?;
    require(
        !decoded.contains(['\\', ':'])
            && !decoded.chars().any(char::is_control)
            && decoded.strip_prefix('/').is_some_and(|tail| {
                tail.split('/')
                    .all(|part| !part.is_empty() && !matches!(part, "." | ".."))
            }),
        "noncanonical selected path package URL",
    )?;
    Ok((fragment, decoded))
}

pub(super) fn selected_units<'a>(
    graph: &'a Value,
    command: CompilationCommand,
    control: &PreparationControl<'_>,
) -> io::Result<&'a [Value]> {
    control.checkpoint()?;
    rabs_sandbox::cargo_check::validate_compilation_unit_graph(graph, command)?;
    graph["units"]
        .as_array()
        .map(Vec::as_slice)
        .ok_or_else(|| invalid("selected Cargo unit graph missing"))
}

/// Bind every raw unit, including host executors, to its retained source owner.
/// Metadata without dependencies supplies workspace boundaries only; its empty
/// resolve field is never treated as evidence for the compilation closure.
pub(super) fn validate_selected_graph(
    image: &SealedSourceSnapshot,
    root: &Path,
    selection: &SelectedCommand,
    metadata: &Value,
    units: &Value,
    registry: Option<(&RegistryCache, &Path)>,
    control: &PreparationControl<'_>,
) -> io::Result<BTreeSet<String>> {
    let manifest = selection.manifest.as_str();
    require(
        metadata.get("resolve").is_some_and(Value::is_null),
        "selected Cargo workspace metadata must omit dependency resolution",
    )?;
    validate_metadata_packages_controlled(image, root, manifest, metadata, None, None, control)?;
    let controls = graph::ControlInputs::discover_controlled(
        image,
        manifest,
        None,
        registry.is_some(),
        control,
    )?;
    let workspace = Path::new(
        metadata["workspace_root"]
            .as_str()
            .ok_or_else(|| invalid("selected Cargo workspace root missing"))?,
    );
    require(
        workspace.join("Cargo.lock") == root.join(&controls.lock),
        "selected Cargo graph uses a different retained workspace lock",
    )?;
    if let Some((registry, _)) = registry {
        registry.check_lock(Path::new(&controls.lock))?;
    }
    let lock: toml::Value = toml::from_str(
        std::str::from_utf8(
            image
                .file_bytes("workspace", &controls.lock)
                .filter(|bytes| bytes.len() <= OUTPUT_LIMIT as usize)
                .ok_or_else(|| invalid("selected Cargo lock is missing or excessive"))?,
        )
        .map_err(|_| invalid("selected Cargo lock is not UTF-8"))?,
    )
    .map_err(|_| invalid("selected Cargo lock is malformed"))?;
    let locked = lock
        .get("package")
        .and_then(toml::Value::as_array)
        .filter(|packages| packages.len() <= MAX_PACKAGES)
        .ok_or_else(|| invalid("selected Cargo lock package list is missing or excessive"))?;
    let mut local = BTreeSet::new();
    for package in locked
        .iter()
        .filter(|package| package.get("source").is_none())
    {
        let name = package
            .get("name")
            .and_then(toml::Value::as_str)
            .ok_or_else(|| invalid("selected local lock package name missing"))?;
        let version = package
            .get("version")
            .and_then(toml::Value::as_str)
            .ok_or_else(|| invalid("selected local lock package version missing"))?;
        require(
            local.insert((name, version)),
            "duplicate selected local lock identity",
        )?;
    }
    let mut packages: BTreeMap<&str, BTreeSet<&str>> = BTreeMap::new();
    for unit in selected_units(units, selection.command, control)? {
        control.checkpoint()?;
        let id = unit["pkg_id"]
            .as_str()
            .ok_or_else(|| invalid("selected Cargo unit lacks a package identity"))?;
        let source = unit["target"]["src_path"]
            .as_str()
            .ok_or_else(|| invalid("selected Cargo unit lacks a source path"))?;
        packages.entry(id).or_default().insert(source);
        require(
            packages.len() <= MAX_PACKAGES,
            "selected Cargo package graph exceeds its bound",
        )?;
    }
    let mut external = Vec::new();
    let mut parsed = BTreeMap::new();
    for (id, sources) in packages {
        control.checkpoint()?;
        if id.starts_with("path+") {
            let (fragment, directory) = local_package_directory(id)?;
            let path = Path::new(&directory).join("Cargo.toml");
            let path_value = Value::String(
                path.to_str()
                    .ok_or_else(|| invalid("selected local manifest is not UTF-8"))?
                    .to_owned(),
            );
            let path = captured_metadata_path(image, root, &path_value)?;
            let relative = path
                .strip_prefix(root)
                .ok()
                .and_then(Path::to_str)
                .ok_or_else(|| invalid("selected local manifest escapes its capture"))?;
            require(
                controls.manifests.contains(relative),
                "selected local package is not a reached Cargo control manifest",
            )?;
            let value = graph::manifest_value(image, relative, &mut parsed)?;
            let package = value
                .get("package")
                .or_else(|| value.get("project"))
                .ok_or_else(|| invalid("selected local manifest is not a package"))?;
            let name = package
                .get("name")
                .and_then(toml::Value::as_str)
                .ok_or_else(|| invalid("selected local package name missing"))?;
            let version = if let Some((selected_name, version)) = fragment.rsplit_once('@') {
                require(
                    selected_name == name,
                    "selected local package name differs from its manifest",
                )?;
                version
            } else {
                require(
                    Path::new(&directory)
                        .file_name()
                        .and_then(|name| name.to_str())
                        == Some(name),
                    "selected local short identity differs from its directory",
                )?;
                fragment
            };
            require(
                local.contains(&(name, version)),
                "selected local package identity differs from its retained lock",
            )?;
            let mut retained = |path: &str| {
                control.checkpoint()?;
                if image.file_bytes("workspace", path).is_none() {
                    return Ok(None);
                }
                graph::manifest_value(image, path, &mut parsed).map(Some)
            };
            if package
                .get("version")
                .and_then(|version| version.get("workspace"))
                .and_then(toml::Value::as_bool)
                == Some(true)
            {
                // Ancestor lookup may read an excluding workspace without
                // admitting it as an owner. Keep these retained negative reads
                // available, but bind the actual inherited owner to the graph.
                let workspace = graph::retained_workspace_root(
                    relative,
                    &value,
                    &mut BTreeSet::new(),
                    &mut retained,
                    control,
                )?;
                require(
                    controls.manifests.contains(&workspace),
                    "selected package version uses an unreached workspace manifest",
                )?;
            }
            let declared =
                graph::retained_package_version(relative, &value, &mut retained, control)?;
            require(
                declared == version,
                "selected local package version differs from its retained manifest owner",
            )?;
            for source in sources {
                captured_metadata_path(image, root, &Value::String(source.to_owned()))?;
            }
        } else {
            let (registry, home) = registry.ok_or_else(|| {
                invalid("selected external package requires an approved Cargo home")
            })?;
            external.push(registry.selected_package(
                home,
                id,
                &sources.into_iter().collect::<Vec<_>>(),
                control,
            )?);
        }
    }
    if let Some((registry, home)) = registry {
        // The existing complete checkout comparison still covers Git package
        // data, include! inputs and executable modes, not just target entrypoints.
        registry.verify_git_checkouts(home, &external, control)?;
        return registry.selected_archive_paths(home, &external, control);
    }
    Ok(BTreeSet::new())
}

#[cfg(test)]
#[path = "selection_tests.rs"]
mod tests;
