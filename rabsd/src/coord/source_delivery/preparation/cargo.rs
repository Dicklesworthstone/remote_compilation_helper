//! Bounded local Cargo graph discovery from retained, coherent source bytes.
//!
//! Supports locked local workspaces and explicitly approved registry/Git vendor trees.
//! Directory-source files and lock checksums are validated before reuse. The
//! approved anchor is the upload boundary, not a guessed set of Rust files:
//! build scripts, include! inputs, and optional/target dependencies retain their
//! relative layout. No descriptor, cache authority, or compiler result is minted.

mod registry;
mod vendor;

use super::super::{SourceUpload, invalid, require};
use rabs_asupersync::process_groups::{GroupSignal, ManagedProcessGroup};
use rabs_asupersync::region_tree::Attribution;
use rabs_sandbox::snapshot_capture::{MemberKind, SealedSourceSnapshot, capture_sealed_source};
use rabs_sandbox::source_transfer::{MAX_SOURCE_BYTES, MAX_SOURCE_FILES};
use registry::RegistryCache;
use serde_json::{Value, json};
use std::collections::BTreeSet;
use std::fs::{self, File};
use std::io::{self, Read};
use std::path::{Component, Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::Arc;
use std::time::{Duration, Instant};
use vendor::{SourceReplacements, VendoredSources};

const OUTPUT_LIMIT: u64 = 8 * 1024 * 1024;
const METADATA_TIMEOUT: Duration = Duration::from_secs(30);
const MAX_PACKAGES: usize = 1024;

#[derive(Debug)]
pub(super) struct CargoSource {
    manifest: String,
    vendor: Option<String>,
    cargo_home_source: Option<PathBuf>,
}

impl CargoSource {
    pub(super) fn parse(value: &Value) -> io::Result<Self> {
        require(
            value.as_object().is_some_and(|fields| {
                fields.contains_key("manifest")
                    && fields.keys().all(|key| {
                        matches!(key.as_str(), "manifest" | "vendor" | "cargo_home_source")
                    })
            }),
            "cargo_source requires manifest and optional vendor or cargo_home_source",
        )?;
        let manifest = value["manifest"]
            .as_str()
            .ok_or_else(|| invalid("cargo_source manifest must be a relative Cargo.toml path"))?;
        require(
            manifest.len() <= 4096
                && !manifest.contains(['\\', ':'])
                && !manifest.chars().any(char::is_control)
                && manifest
                    .split('/')
                    .all(|part| !part.is_empty() && !matches!(part, "." | ".."))
                && Path::new(manifest)
                    .file_name()
                    .is_some_and(|name| name == "Cargo.toml"),
            "cargo_source manifest must be a safe relative Cargo.toml path",
        )?;
        let vendor = value
            .get("vendor")
            .map(|value| {
                let directory = value
                    .as_str()
                    .ok_or_else(|| invalid("cargo_source vendor must be a string"))?;
                vendor::validate_directory(directory)?;
                Ok::<_, io::Error>(directory.to_owned())
            })
            .transpose()?;
        let cargo_home_source = value
            .get("cargo_home_source")
            .map(registry::approved_home)
            .transpose()?;
        require(
            vendor.is_none() || cargo_home_source.is_none(),
            "cargo_source vendor and cargo_home_source are mutually exclusive",
        )?;
        Ok(Self {
            manifest: manifest.to_owned(),
            vendor,
            cargo_home_source,
        })
    }

    pub(super) fn manifest(&self) -> &str {
        &self.manifest
    }

    pub(super) fn cargo_home_projection(&self) -> Option<Value> {
        self.cargo_home_source.as_ref().map(|_| {
            json!({"version":rabs_sandbox::cargo_home::ISOLATED_CARGO_HOME_SOURCE_VERSION,
                "prefix":registry::CACHE_PREFIX})
        })
    }

    pub(super) fn validate_cache_boundary(&self, source: &Path) -> io::Result<()> {
        if let Some(home) = &self.cargo_home_source {
            let source = fs::canonicalize(source)?;
            require(
                !source.starts_with(home) && !home.starts_with(&source),
                "cargo_home_source must be separate from the approved source anchor",
            )?;
        }
        Ok(())
    }

    pub(super) fn prepare(&self, image: Arc<SealedSourceSnapshot>) -> io::Result<SourceUpload> {
        let vendor = self
            .vendor
            .as_deref()
            .map(|directory| VendoredSources::verify(&image, &self.manifest, directory))
            .transpose()?;
        let files = validate_capture(
            &image,
            &self.manifest,
            vendor.as_ref(),
            self.cargo_home_source.is_some(),
        )?;
        // Planning starts only after a complete paired capture. Cargo never sees
        // a mutable original checkout or a mixture of pre/post-mutation files.
        let planning = tempfile::Builder::new()
            .prefix("rabs-cargo-source-")
            .tempdir()?;
        let planning_root = fs::canonicalize(planning.path())?;
        reject_ancestor_configuration(&planning_root)?;
        image
            .materialize_into(&planning_root.join("image"))
            .map_err(|error| invalid(&format!("Cargo planning copy failed: {error:?}")))?;
        let root = fs::canonicalize(planning_root.join("image/workspace"))?;
        let tools = planning_root.join("tools");
        fs::create_dir(&tools)?;
        let cargo = local_tool("cargo", &tools)?;
        let rustc = match std::env::var_os("RUSTC") {
            Some(_) => local_tool("rustc", &tools)?,
            None if cargo
                .parent()
                .is_some_and(|parent| parent.join("rustc").is_file()) =>
            {
                cargo
                    .parent()
                    .ok_or_else(|| invalid("Cargo executable parent"))?
                    .join("rustc")
            }
            None => local_tool("rustc", &tools)?,
        };
        let home = planning_root.join("home");
        fs::create_dir(&home)?;
        let cargo_home = planning_root.join("cargo-home");
        fs::create_dir(&cargo_home)?;
        let registry = self
            .cargo_home_source
            .as_ref()
            .map(|approved| {
                let mut locate =
                    planning_command(&cargo, &rustc, &root, &self.manifest, &planning_root)?;
                locate
                    .args(["locate-project", "--workspace", "--message-format=json"])
                    .arg("--manifest-path")
                    .arg(root.join(&self.manifest));
                let located: Value = serde_json::from_slice(&bounded_command(
                    locate,
                    &planning_root,
                    METADATA_TIMEOUT,
                    OUTPUT_LIMIT,
                )?)
                .map_err(|_| invalid("invalid Cargo workspace location"))?;
                let workspace_manifest = captured_metadata_path(&image, &root, &located["root"])?;
                let lock = workspace_manifest
                    .parent()
                    .ok_or_else(|| invalid("Cargo workspace manifest parent"))?
                    .join("Cargo.lock")
                    .strip_prefix(&root)
                    .map_err(|_| invalid("Cargo workspace lock escapes captured source"))?
                    .to_path_buf();
                RegistryCache::capture(&image, &lock, approved, &cargo_home)
            })
            .transpose()?;
        let mut command = planning_command(&cargo, &rustc, &root, &self.manifest, &planning_root)?;
        command
            .args([
                "metadata",
                "--format-version=1",
                "--locked",
                "--offline",
                "--all-features",
            ])
            .arg("--manifest-path")
            .arg(root.join(&self.manifest));
        let output = bounded_command(command, &planning_root, METADATA_TIMEOUT, OUTPUT_LIMIT)?;
        let metadata: Value = serde_json::from_slice(&output)
            .map_err(|error| invalid(&format!("invalid Cargo metadata JSON: {error}")))?;
        validate_metadata(
            &image,
            &root,
            &self.manifest,
            &metadata,
            vendor.as_ref(),
            registry
                .as_ref()
                .map(|registry| (registry, cargo_home.as_path())),
        )?;
        verify_planning_bytes(&image, &root, &files)?;
        if let Some(registry) = registry {
            let mut selected = files;
            selected.extend(
                registry
                    .materialize(&root.join(registry::CACHE_PREFIX))?
                    .into_iter()
                    .map(|path| format!("{}/{path}", registry::CACHE_PREFIX)),
            );
            // Planning and byte comparison are complete; the private copy now
            // owns the derived inputs. Release the original retained maps before
            // paired recapture so a full cache does not require a third copy in
            // memory merely to construct the final transfer image.
            drop(registry);
            drop(image);
            let derived = Arc::new(
                capture_sealed_source(
                    &[("workspace".to_owned(), root)],
                    false,
                    2,
                    MAX_SOURCE_BYTES,
                )
                .map_err(|error| {
                    invalid(&format!("retained Cargo cache capture refused: {error:?}"))
                })?,
            );
            // This new image is derived solely from the retained source and
            // checksum-bound cache bytes. It is input delivery, not a resealed
            // authoritative action descriptor or a cache-publication claim.
            SourceUpload::from_snapshot(derived, "workspace", &selected)
        } else {
            SourceUpload::from_snapshot(image, "workspace", &files)
        }
    }
}

fn planning_command(
    cargo: &Path,
    rustc: &Path,
    root: &Path,
    manifest: &str,
    planning: &Path,
) -> io::Result<Command> {
    let mut command = Command::new(cargo);
    command
        .env_clear()
        .current_dir(
            root.join(manifest)
                .parent()
                .ok_or_else(|| invalid("Cargo manifest parent"))?,
        )
        .env("HOME", planning.join("home"))
        .env("CARGO_HOME", planning.join("cargo-home"))
        .env("RUSTC", rustc)
        .env("CARGO_TARGET_DIR", planning.join("target"));
    for key in ["PATH", "LD_LIBRARY_PATH", "DYLD_LIBRARY_PATH"] {
        if let Some(value) = std::env::var_os(key) {
            command.env(key, value);
        }
    }
    Ok(command)
}

fn validate_capture(
    image: &SealedSourceSnapshot,
    manifest: &str,
    vendor: Option<&VendoredSources>,
    cached_registry: bool,
) -> io::Result<Vec<String>> {
    let captured = image
        .manifest("workspace")
        .ok_or_else(|| invalid("missing captured Cargo anchor"))?;
    let mut files = Vec::new();
    for (path, kind) in &captured.members {
        require(
            !cached_registry
                || (path != registry::CACHE_PREFIX
                    && !path.starts_with(&format!("{}/", registry::CACHE_PREFIX))),
            "approved source collides with the reserved rabs-cargo-home directory",
        )?;
        require(
            !matches!(kind, MemberKind::Symlink { .. }),
            "automatic Cargo source preparation does not support symlinks",
        )?;
        if matches!(kind, MemberKind::Regular { .. }) {
            files.push(path.clone());
            require(
                files.len() <= MAX_SOURCE_FILES,
                "Cargo source anchor exceeds the file-count bound",
            )?;
            // Vendor packages were checked as complete checksum-covered trees.
            // Their nested test Cargo.toml/config/lock fixtures are ordinary data,
            // not independent workspace roots for the planning command.
            if vendor.is_some_and(|vendor| vendor.contains(path)) {
                continue;
            }
            if is_cargo_config(Path::new(path)) {
                if let Some(vendor) = vendor {
                    // The vendor adapter validates its one source-replacement
                    // config, including the shared compiler settings below.
                    require(
                        vendor.allows_config(path),
                        "vendor preparation does not admit another Cargo config layer",
                    )?;
                } else {
                    let bytes = image
                        .file_bytes("workspace", path)
                        .filter(|bytes| bytes.len() <= OUTPUT_LIMIT as usize)
                        .ok_or_else(|| invalid("missing or oversized captured Cargo config"))?;
                    let text = std::str::from_utf8(bytes)
                        .map_err(|_| invalid("captured Cargo config is not UTF-8"))?;
                    let value = toml::from_str(text)
                        .map_err(|_| invalid("malformed captured Cargo config"))?;
                    validate_cargo_config(&value, false)?;
                }
            }
            if Path::new(path)
                .file_name()
                .is_some_and(|name| name == "Cargo.toml")
            {
                let text = std::str::from_utf8(
                    image
                        .file_bytes("workspace", path)
                        .filter(|bytes| bytes.len() <= OUTPUT_LIMIT as usize)
                        .ok_or_else(|| invalid("missing captured Cargo manifest"))?,
                )
                .map_err(|_| invalid("Cargo manifest is not UTF-8"))?;
                let value: toml::Value = toml::from_str(text).map_err(|error| {
                    invalid(&format!("captured Cargo manifest {path}: {error}"))
                })?;
                validate_manifest_paths(
                    Path::new(path).parent().unwrap_or(Path::new("")),
                    &value,
                    vendor.map(|vendor| &vendor.sources),
                    false,
                )?;
            }
            if Path::new(path)
                .file_name()
                .is_some_and(|name| name == "Cargo.lock")
            {
                let text = std::str::from_utf8(
                    image
                        .file_bytes("workspace", path)
                        .filter(|bytes| bytes.len() <= OUTPUT_LIMIT as usize)
                        .ok_or_else(|| invalid("missing captured Cargo lockfile"))?,
                )
                .map_err(|_| invalid("Cargo lockfile is not UTF-8"))?;
                let lock: toml::Value = toml::from_str(text).map_err(|error| {
                    invalid(&format!("captured Cargo lockfile {path}: {error}"))
                })?;
                if let Some(vendor) = vendor {
                    vendor.validate_lock_sources(&lock)?;
                } else if cached_registry {
                    registry::validate_lock_sources(&lock)?;
                } else if let Some(packages) = lock.get("package").and_then(toml::Value::as_array) {
                    require(
                        packages
                            .iter()
                            .all(|package| package.get("source").is_none()),
                        "automatic Cargo source preparation requires a lockfile containing only local packages",
                    )?;
                }
            }
        }
    }
    require(
        files.iter().any(|path| path == manifest),
        "Cargo manifest is absent from the captured anchor",
    )?;
    Ok(files)
}

fn is_cargo_config(path: &Path) -> bool {
    path.file_name()
        .is_some_and(|name| name == "config" || name == "config.toml")
        && path
            .parent()
            .and_then(Path::file_name)
            .is_some_and(|name| name == ".cargo")
}

/// Admit captured compiler configuration without delegating command, input or
/// output ownership to it. These bytes remain unchanged in both the planning
/// copy and the worker upload; Cargo owns config layering and flag precedence.
/// Source replacements need the vendor adapter's separate closure validation.
fn validate_cargo_config(value: &toml::Value, vendor_sources: bool) -> io::Result<()> {
    let top = value
        .as_table()
        .ok_or_else(|| invalid("captured Cargo config must be a table"))?;
    for (section, value) in top {
        match section.as_str() {
            "source" | "registries" if vendor_sources => {}
            "build" => {
                let build = value
                    .as_table()
                    .ok_or_else(|| invalid("Cargo build config must be a table"))?;
                for (name, value) in build {
                    require(
                        matches!(name.as_str(), "rustflags" | "rustdocflags"),
                        "captured Cargo build config supports only rustflags and rustdocflags",
                    )?;
                    validate_compiler_flags(value)?;
                }
            }
            "target" => {
                let targets = value
                    .as_table()
                    .filter(|targets| targets.len() <= 64)
                    .ok_or_else(|| invalid("Cargo target config must be a bounded table"))?;
                for (target, value) in targets {
                    // Named triples and Cargo's cfg selectors are not file
                    // paths. Cargo, rather than a second cfg parser, resolves
                    // and merges matching selectors in its ordinary order.
                    let named = !target.is_empty()
                        && target.len() <= 128
                        && target
                            .bytes()
                            .all(|byte| byte.is_ascii_alphanumeric() || b"_-".contains(&byte));
                    let conditional = target.starts_with("cfg(")
                        && target.ends_with(')')
                        && target.len() <= 1024
                        && !target.chars().any(char::is_control);
                    require(
                        named || conditional,
                        "Cargo target config requires a named triple or cfg selector",
                    )?;
                    let fields = value
                        .as_table()
                        .ok_or_else(|| invalid("Cargo target settings must be a table"))?;
                    for (name, value) in fields {
                        require(
                            name == "rustflags",
                            "captured Cargo target config supports only rustflags",
                        )?;
                        validate_compiler_flags(value)?;
                    }
                }
            }
            "llvm-cov" => {
                // Stock Cargo does not consume this tool's exclude globs.
                // Retain this repository's existing metadata without treating
                // arbitrary unknown tables as permission to configure Cargo.
                let fields = value
                    .as_table()
                    .ok_or_else(|| invalid("llvm-cov metadata must be a table"))?;
                for (name, value) in fields {
                    require(name == "exclude", "unsupported llvm-cov metadata")?;
                    let patterns = value
                        .as_array()
                        .filter(|patterns| patterns.len() <= 256)
                        .ok_or_else(|| invalid("llvm-cov exclude must be a bounded array"))?;
                    for pattern in patterns {
                        require(
                            pattern.as_str().is_some_and(|pattern| {
                                pattern.len() <= 4096 && !pattern.chars().any(char::is_control)
                            }),
                            "llvm-cov exclude entries must be bounded strings",
                        )?;
                    }
                }
            }
            _ => return Err(invalid("unsupported captured Cargo configuration section")),
        }
    }
    Ok(())
}

fn compiler_flag_arguments(value: &toml::Value) -> io::Result<Vec<&str>> {
    // Cargo splits string-form flags on whitespace; it does not shell-parse
    // them. Array elements retain their exact argument boundaries, including
    // spaces inside a cfg expression. Never normalize or rewrite either form.
    let flags = match value {
        toml::Value::String(text) if text.len() <= 16 * 1024 => {
            text.split_whitespace().collect::<Vec<_>>()
        }
        toml::Value::Array(values) if values.len() <= 256 => values
            .iter()
            .map(|value| {
                value
                    .as_str()
                    .ok_or_else(|| invalid("Cargo compiler flag arrays require strings"))
            })
            .collect::<io::Result<Vec<_>>>()?,
        _ => {
            return Err(invalid(
                "Cargo compiler flags require a bounded string or array",
            ));
        }
    };
    require(
        flags.len() <= 256
            && flags.iter().map(|flag| flag.len()).sum::<usize>() <= 16 * 1024
            && flags.iter().all(|flag| {
                !flag.is_empty() && flag.len() <= 4096 && !flag.chars().any(char::is_control)
            }),
        "captured Cargo compiler flags exceed their bounds",
    )?;
    Ok(flags)
}

fn validate_compiler_flags(value: &toml::Value) -> io::Result<()> {
    let flags = compiler_flag_arguments(value)?;
    let mut flags = flags.into_iter();
    while let Some(flag) = flags.next() {
        if matches!(flag, "-g" | "-O") {
            continue;
        }
        let (option, value) = if matches!(
            flag,
            "--cfg"
                | "--check-cfg"
                | "-A"
                | "--allow"
                | "-W"
                | "--warn"
                | "-D"
                | "--deny"
                | "-F"
                | "--forbid"
                | "-C"
                | "--codegen"
                | "-Z"
        ) {
            (
                flag,
                flags
                    .next()
                    .ok_or_else(|| invalid("Cargo compiler flag lacks its value"))?,
            )
        } else if let Some((option, value)) = flag.split_once('=')
            && option.starts_with("--")
        {
            (option, value)
        } else if let Some(option) = ["-A", "-W", "-D", "-F", "-C", "-Z"]
            .into_iter()
            .find(|option| flag.starts_with(option))
        {
            (option, &flag[option.len()..])
        } else {
            return Err(invalid("unsupported captured Cargo compiler flag"));
        };
        require(
            !value.is_empty() && !value.starts_with(['-', '@']),
            "invalid captured Cargo compiler flag value",
        )?;
        match option {
            "--cfg" | "--check-cfg" => {}
            "-A" | "--allow" | "-W" | "--warn" | "-D" | "--deny" | "-F" | "--forbid" => {
                require(
                    value
                        .bytes()
                        .all(|byte| byte.is_ascii_alphanumeric() || b"_:-".contains(&byte)),
                    "captured Cargo lint flags require a literal lint name",
                )?;
            }
            "-C" | "--codegen" => validate_scalar_codegen(value)?,
            "-Z" => {
                require(
                    value.strip_prefix("threads=").is_some_and(positive_count),
                    "captured Cargo unstable flags support only explicit bounded threads",
                )?;
            }
            _ => return Err(invalid("unsupported captured Cargo compiler option")),
        }
    }
    Ok(())
}

fn positive_count(value: &str) -> bool {
    !value.is_empty()
        && value.bytes().all(|byte| byte.is_ascii_digit())
        && value
            .parse::<u32>()
            .is_ok_and(|value| (1..=4096).contains(&value))
}

fn validate_scalar_codegen(value: &str) -> io::Result<()> {
    let (name, value) = value
        .split_once('=')
        .ok_or_else(|| invalid("captured Cargo codegen flags require explicit values"))?;
    let boolean = || {
        matches!(
            value,
            "y" | "yes" | "on" | "true" | "n" | "no" | "off" | "false"
        )
    };
    let accepted = match name {
        "opt-level" => matches!(value, "0" | "1" | "2" | "3" | "s" | "z"),
        "debuginfo" => matches!(
            value,
            "0" | "1"
                | "2"
                | "none"
                | "limited"
                | "full"
                | "line-tables-only"
                | "line-directives-only"
        ),
        "debug-assertions" | "overflow-checks" | "embed-bitcode" | "force-frame-pointers" => {
            boolean()
        }
        "codegen-units" => positive_count(value),
        "panic" => matches!(value, "abort" | "unwind"),
        "lto" => matches!(value, "thin" | "fat") || boolean(),
        "strip" => matches!(value, "none" | "debuginfo" | "symbols"),
        _ => false,
    };
    require(
        accepted,
        "unsupported or non-scalar captured Cargo codegen option",
    )
}

// This is a containment preflight, not a second dependency resolver. Cargo owns
// graph resolution; checking path-bearing manifest fields before it runs prevents
// Cargo from opening absolute/escaping local dependencies outside the copy.
fn validate_manifest_paths(
    base: &Path,
    value: &toml::Value,
    sources: Option<&SourceReplacements>,
    vendored_git: bool,
) -> io::Result<()> {
    for field in ["package", "project"] {
        if let Some(package) = value.get(field) {
            for field in ["workspace", "readme", "license-file", "build"] {
                validate_path_field(base, package, field)?;
            }
            if !vendored_git
                && let (Some(sources), Some(path)) = (
                    sources,
                    package.get("workspace").and_then(toml::Value::as_str),
                )
            {
                sources.check_local_package_path(&contained_relative(base, path)?, false)?;
            }
            if let Some(scripts) = package.get("build").and_then(toml::Value::as_array) {
                for script in scripts {
                    if let Some(path) = script.as_str() {
                        contained_relative(base, path)?;
                    }
                }
            }
            // Cargo's package target JSON paths are interpreted relative to its
            // invocation cwd, not each package root. This initial mode accepts
            // named triples only, avoiding a second path-resolution policy.
            for field in ["default-target", "forced-target"] {
                if let Some(target) = package.get(field).and_then(toml::Value::as_str) {
                    require(
                        !target.is_empty()
                            && !target.ends_with(".json")
                            && !target.contains(['/', '\\', ':'])
                            && !target.chars().any(char::is_control),
                        "automatic Cargo source preparation requires named package targets, not target JSON paths",
                    )?;
                }
            }
        }
    }
    if let Some(library) = value.get("lib") {
        validate_path_field(base, library, "path")?;
    }
    for field in ["bin", "example", "test", "bench"] {
        if let Some(targets) = value.get(field).and_then(toml::Value::as_array) {
            for target in targets {
                validate_path_field(base, target, "path")?;
            }
        }
    }
    validate_dependency_sections(base, value, sources, vendored_git)?;
    if let Some(targets) = value.get("target").and_then(toml::Value::as_table) {
        for target in targets.values() {
            validate_dependency_sections(base, target, sources, vendored_git)?;
        }
    }
    if let Some(workspace) = value.get("workspace") {
        validate_dependency_sections(base, workspace, sources, vendored_git)?;
        for field in ["members", "default-members", "exclude"] {
            if let Some(paths) = workspace.get(field).and_then(toml::Value::as_array) {
                for path in paths {
                    if let Some(path) = path.as_str() {
                        let path = contained_relative(base, path)?;
                        if !vendored_git
                            && field != "exclude"
                            && let Some(sources) = sources
                        {
                            sources.check_local_package_path(&path, true)?;
                        }
                    }
                }
            }
        }
        if let Some(package) = workspace.get("package") {
            for field in ["readme", "license-file"] {
                validate_path_field(base, package, field)?;
            }
        }
    }
    if let Some(patches) = value.get("patch").and_then(toml::Value::as_table) {
        for dependencies in patches.values() {
            validate_dependencies(base, dependencies, sources, vendored_git)?;
        }
    }
    if let Some(replacements) = value.get("replace") {
        validate_dependencies(base, replacements, sources, vendored_git)?;
    }
    Ok(())
}

fn validate_path_field(base: &Path, value: &toml::Value, field: &str) -> io::Result<()> {
    if let Some(path) = value.get(field).and_then(toml::Value::as_str) {
        contained_relative(base, path)?;
    }
    Ok(())
}

fn validate_dependency_sections(
    base: &Path,
    value: &toml::Value,
    sources: Option<&SourceReplacements>,
    vendored_git: bool,
) -> io::Result<()> {
    for field in [
        "dependencies",
        "dev-dependencies",
        "build-dependencies",
        "dev_dependencies",
        "build_dependencies",
    ] {
        if let Some(dependencies) = value.get(field) {
            validate_dependencies(base, dependencies, sources, vendored_git)?;
        }
    }
    Ok(())
}

fn validate_dependencies(
    base: &Path,
    value: &toml::Value,
    sources: Option<&SourceReplacements>,
    vendored_git: bool,
) -> io::Result<()> {
    if let Some(dependencies) = value.as_table() {
        for dependency in dependencies.values() {
            if let Some(fields) = dependency.as_table() {
                if fields.contains_key("registry") || fields.contains_key("registry-index") {
                    sources
                        .ok_or_else(|| invalid("alternate registry dependencies require an explicitly verified vendor source"))?
                        .check_registry_dependency(fields)?;
                }
                if fields.contains_key("git") {
                    sources
                        .ok_or_else(|| {
                            invalid("Git dependencies require an explicitly verified vendor source")
                        })?
                        .check_dependency(fields)?;
                }
                // Cargo keeps original sibling paths in vendored Git manifests,
                // but resolves those dependencies from that Git source's directory
                // replacement. Do not reinterpret an ignored path as a local
                // input. The resolved package source/manifest/targets are checked
                // against the exact captured lock and vendor tree afterward.
                if !vendored_git {
                    validate_path_field(base, dependency, "path")?;
                    if let (Some(sources), Some(path)) = (
                        sources,
                        dependency.get("path").and_then(toml::Value::as_str),
                    ) {
                        sources
                            .check_local_package_path(&contained_relative(base, path)?, false)?;
                    }
                }
            }
        }
    }
    Ok(())
}

fn contained_relative(base: &Path, path: &str) -> io::Result<PathBuf> {
    require(
        !path.is_empty()
            && path.len() <= 4096
            && !path.contains(['\\', ':'])
            && !path.chars().any(char::is_control),
        "invalid Cargo source path declaration",
    )?;
    let mut relative = base.to_path_buf();
    for part in Path::new(path).components() {
        match part {
            Component::Normal(part) => relative.push(part),
            Component::CurDir => {}
            Component::ParentDir => require(
                relative.pop(),
                "Cargo source path escapes the approved anchor",
            )?,
            _ => {
                return Err(invalid(
                    "absolute Cargo source paths are outside the approved anchor",
                ));
            }
        }
    }
    Ok(relative)
}

fn reject_ancestor_configuration(path: &Path) -> io::Result<()> {
    let canonical = fs::canonicalize(path)?;
    for parent in canonical.ancestors() {
        for name in [
            ".cargo/config",
            ".cargo/config.toml",
            "Cargo.toml",
            "rust-toolchain",
            "rust-toolchain.toml",
        ] {
            match fs::symlink_metadata(parent.join(name)) {
                Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                Err(error) => return Err(error),
                Ok(_) => {
                    return Err(invalid(
                        "Cargo planning directory has ambient Cargo/rustup configuration",
                    ));
                }
            }
        }
    }
    Ok(())
}

fn local_tool(name: &str, scratch: &Path) -> io::Result<PathBuf> {
    let selected = if let Some(explicit) = std::env::var_os(name.to_ascii_uppercase()) {
        let explicit = PathBuf::from(explicit);
        require(
            explicit.is_absolute(),
            "explicit CARGO/RUSTC must name an absolute local executable",
        )?;
        explicit
    } else {
        let mut directories: Vec<PathBuf> = std::env::var_os("PATH")
            .map(|path| std::env::split_paths(&path).collect())
            .unwrap_or_default();
        if let Some(home) = std::env::var_os("HOME") {
            directories.push(PathBuf::from(home).join(".cargo/bin"));
        }
        directories
            .into_iter()
            .filter(|path| path.is_absolute())
            .map(|path| path.join(name))
            .find(|path| path.is_file())
            .ok_or_else(|| invalid(&format!("local {name} executable unavailable")))?
    };
    let resolved = fs::canonicalize(selected)?;
    if resolved.file_name().is_some_and(|file| file == "rustup") {
        // `which` selects an already installed toolchain without invoking a
        // captured rust-toolchain file. Disable rustup's automatic installation.
        let mut command = Command::new(resolved);
        command
            .env_clear()
            .current_dir(scratch)
            .args(["which", name])
            .env("RUSTUP_AUTO_INSTALL", "0");
        for key in [
            "HOME",
            "RUSTUP_HOME",
            "RUSTUP_TOOLCHAIN",
            "PATH",
            "LD_LIBRARY_PATH",
        ] {
            if let Some(value) = std::env::var_os(key) {
                command.env(key, value);
            }
        }
        let output = bounded_command(command, scratch, Duration::from_secs(5), 64 * 1024)?;
        let path = std::str::from_utf8(&output)
            .map_err(|_| invalid("rustup which returned non-UTF-8"))?
            .trim();
        let path = PathBuf::from(path);
        require(
            path.is_absolute() && path.is_file(),
            "rustup did not resolve an installed local tool",
        )?;
        return fs::canonicalize(path);
    }
    require(
        resolved.is_file(),
        "Cargo tool must be a local regular executable",
    )?;
    Ok(resolved)
}

struct OwnedGroup {
    process: ManagedProcessGroup,
    reaped: bool,
}

impl Drop for OwnedGroup {
    fn drop(&mut self) {
        if !self.reaped {
            if self.process.signal_group(GroupSignal::Kill).is_err() {
                // Minimal operator PATHs can still run absolute Cargo/rustc.
                // Reach their whole group through the host signal utility before
                // the direct-child fallback, including compiler grandchildren.
                let _ = Command::new("/bin/kill")
                    .args(["-KILL", "--", &format!("-{}", self.process.pgid())])
                    .stdin(Stdio::null())
                    .stdout(Stdio::null())
                    .stderr(Stdio::null())
                    .status();
            }
            // No PATH dependency: a missing kill(1) must not turn the deadline
            // into an unbounded wait for the directly owned Cargo process.
            let _ = self.process.kill_leader();
            let _ = self.process.wait_leader();
            let _ = self.process.reap_residuals();
        }
    }
}

fn bounded_command(
    mut command: Command,
    scratch: &Path,
    timeout: Duration,
    limit: u64,
) -> io::Result<Vec<u8>> {
    let logs = tempfile::Builder::new()
        .prefix("metadata-output-")
        .tempdir_in(scratch)?;
    let stdout = logs.path().join("stdout");
    let stderr = logs.path().join("stderr");
    command
        .stdin(Stdio::null())
        .stdout(File::create(&stdout)?)
        .stderr(File::create(&stderr)?);
    let mut owned = OwnedGroup {
        process: ManagedProcessGroup::spawn_command(
            command,
            Attribution {
                build_operation: Some("local-cargo-source-preparation".to_owned()),
                ..Attribution::default()
            },
        )?,
        reaped: false,
    };
    let deadline = Instant::now() + timeout;
    let status = loop {
        require(
            fs::metadata(&stdout)?.len() <= limit && fs::metadata(&stderr)?.len() <= limit,
            "Cargo metadata exceeded its output bound",
        )?;
        if let Some(status) = owned.process.leader_try_wait()? {
            break status;
        }
        require(
            Instant::now() < deadline,
            "Cargo metadata exceeded its runtime bound",
        )?;
        std::thread::sleep(Duration::from_millis(5));
    };
    require(
        owned.process.reap_residuals() == 0,
        "Cargo metadata left live process-group members",
    )?;
    owned.reaped = true;
    let read = |path: &Path| -> io::Result<Vec<u8>> {
        let mut bytes = Vec::new();
        File::open(path)?.take(limit + 1).read_to_end(&mut bytes)?;
        require(
            bytes.len() as u64 <= limit,
            "Cargo metadata exceeded its output bound",
        )?;
        Ok(bytes)
    };
    let errors = read(&stderr)?;
    require(
        status.success(),
        &format!(
            "locked offline Cargo metadata failed ({status}): {}",
            String::from_utf8_lossy(&errors[..errors.len().min(8192)])
        ),
    )?;
    read(&stdout)
}

fn captured_metadata_path<'a>(
    image: &SealedSourceSnapshot,
    root: &Path,
    value: &'a Value,
) -> io::Result<&'a Path> {
    let path = Path::new(
        value
            .as_str()
            .ok_or_else(|| invalid("Cargo metadata path missing"))?,
    );
    let relative = path
        .strip_prefix(root)
        .map_err(|_| invalid("Cargo metadata path escapes the captured anchor"))?;
    require(
        relative
            .components()
            .all(|part| matches!(part, Component::Normal(_))),
        "noncanonical Cargo metadata path",
    )?;
    let relative = relative
        .to_str()
        .ok_or_else(|| invalid("non-UTF-8 Cargo metadata path"))?;
    require(
        image.file_bytes("workspace", relative).is_some(),
        "Cargo metadata refers to an uncaptured source file",
    )?;
    Ok(path)
}

fn validate_metadata(
    image: &SealedSourceSnapshot,
    root: &Path,
    manifest: &str,
    value: &Value,
    vendor: Option<&VendoredSources>,
    registry: Option<(&RegistryCache, &Path)>,
) -> io::Result<()> {
    require(value["version"] == 1, "unsupported Cargo metadata format")?;
    let workspace = Path::new(
        value["workspace_root"]
            .as_str()
            .ok_or_else(|| invalid("Cargo workspace root missing"))?,
    );
    let relative_workspace = workspace
        .strip_prefix(root)
        .map_err(|_| invalid("Cargo workspace escapes the approved anchor"))?;
    require(
        relative_workspace
            .components()
            .all(|part| matches!(part, Component::Normal(_))),
        "noncanonical Cargo workspace root",
    )?;
    let lock = relative_workspace.join("Cargo.lock");
    require(
        lock.to_str()
            .is_some_and(|path| image.file_bytes("workspace", path).is_some()),
        "automatic Cargo source preparation requires the captured workspace Cargo.lock",
    )?;
    let locked = vendor
        .map(|vendor| vendor.bind_lock(image, &lock))
        .transpose()?;
    if let Some((registry, _)) = registry {
        registry.check_lock(&lock)?;
    }
    let packages = value["packages"]
        .as_array()
        .filter(|packages| !packages.is_empty() && packages.len() <= MAX_PACKAGES)
        .ok_or_else(|| invalid("Cargo package graph is missing or exceeds its bound"))?;
    let mut ids = BTreeSet::new();
    let mut selected = false;
    for package in packages {
        if let (Some(vendor), Some(locked)) = (vendor, locked.as_ref()) {
            vendor.check_package(root, package, locked)?;
        } else if let Some((registry, home)) = registry {
            registry.check_package(home, package)?;
        } else {
            require(
                package.get("source").is_some_and(Value::is_null),
                "registry and Git packages require an explicitly validated vendor source",
            )?;
        }
        let id = package["id"]
            .as_str()
            .ok_or_else(|| invalid("Cargo package identity missing"))?;
        require(ids.insert(id), "duplicate Cargo package identity")?;
        let external = package
            .get("source")
            .is_some_and(|source| !source.is_null());
        if registry.is_none() || !external {
            let path = captured_metadata_path(image, root, &package["manifest_path"])?;
            selected |= path == root.join(manifest);
        }
        let targets = package["targets"]
            .as_array()
            .filter(|targets| !targets.is_empty())
            .ok_or_else(|| invalid("Cargo package has no target graph"))?;
        if registry.is_none() || !external {
            for target in targets {
                captured_metadata_path(image, root, &target["src_path"])?;
            }
        }
    }
    // A virtual workspace manifest is not itself a package but is an exact
    // captured Cargo input and must be the metadata workspace's manifest.
    require(
        selected || workspace.join("Cargo.toml") == root.join(manifest),
        "Cargo metadata did not resolve the selected manifest",
    )?;
    for field in ["workspace_members", "workspace_default_members"] {
        let members = value[field]
            .as_array()
            .ok_or_else(|| invalid("Cargo workspace members missing"))?;
        for member in members {
            require(
                member.as_str().is_some_and(|id| ids.contains(id)),
                "Cargo workspace contains an unresolved package",
            )?;
        }
    }
    let nodes = value["resolve"]["nodes"]
        .as_array()
        .ok_or_else(|| invalid("Cargo dependency resolution missing"))?;
    let mut resolved = BTreeSet::new();
    for node in nodes {
        let id = node["id"]
            .as_str()
            .ok_or_else(|| invalid("Cargo resolve node missing identity"))?;
        require(
            ids.contains(id) && resolved.insert(id),
            "unknown or duplicate Cargo resolve node",
        )?;
        let dependencies = node["dependencies"]
            .as_array()
            .ok_or_else(|| invalid("Cargo dependencies missing"))?;
        for dependency in dependencies {
            require(
                dependency.as_str().is_some_and(|id| ids.contains(id)),
                "Cargo graph has an unresolved dependency",
            )?;
        }
    }
    require(resolved == ids, "Cargo package graph is incomplete")
}

fn verify_planning_bytes(
    image: &SealedSourceSnapshot,
    root: &Path,
    files: &[String],
) -> io::Result<()> {
    for path in files {
        let original = image
            .file_bytes("workspace", path)
            .ok_or_else(|| invalid("missing retained source bytes"))?;
        let local = root.join(path);
        let metadata = fs::symlink_metadata(&local)?;
        require(
            metadata.is_file() && metadata.len() == original.len() as u64,
            "Cargo planning changed a captured input",
        )?;
        let mut bytes = Vec::new();
        File::open(local)?
            .take(original.len() as u64 + 1)
            .read_to_end(&mut bytes)?;
        require(
            bytes == original,
            "Cargo planning changed captured source/manifest/lock bytes",
        )?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use rabs_sandbox::snapshot_capture::capture_sealed_source;
    use serde_json::json;

    #[test]
    fn captured_compiler_config_preserves_common_flags_and_cargo_target_selectors() {
        for text in [
            "[build]\nrustflags=['-Z','threads=4']\nrustdocflags=['-Dwarnings']\n[llvm-cov]\nexclude=['*/tests/*','*/benches/*','*/examples/*']\n",
            "[build]\nrustflags='--cfg rabs_fixture -Copt-level=2 --deny=warnings'\n",
            "[build]\nrustflags=['--cfg', 'label=\"two words\"', '--check-cfg=cfg(label, values(\"two words\"))']\n",
            "[target.x86_64-unknown-linux-gnu]\nrustflags=['-C','panic=abort']\n[target.'cfg(unix)']\nrustflags=['--cfg=on_unix', '-Zthreads=4']\n",
            "[build]\nrustflags=[]\nrustdocflags=''\n",
        ] {
            let value: toml::Value = toml::from_str(text).unwrap();
            let original = value.clone();
            validate_cargo_config(&value, false).unwrap();
            assert_eq!(value, original, "validation must not rewrite Cargo intent");
        }
    }

    #[test]
    fn compiler_flag_strings_follow_cargo_whitespace_not_shell_quoting() {
        let value = toml::Value::String("--cfg 'label=two words'".into());
        assert_eq!(
            compiler_flag_arguments(&value).unwrap(),
            ["--cfg", "'label=two", "words'"]
        );
        assert!(validate_compiler_flags(&value).is_err());
        let value = toml::Value::Array(vec![
            toml::Value::String("--cfg".into()),
            toml::Value::String("label=\"two words\"".into()),
        ]);
        validate_compiler_flags(&value).unwrap();
        assert_eq!(
            compiler_flag_arguments(&value).unwrap()[1],
            "label=\"two words\""
        );
    }

    #[test]
    fn captured_config_cannot_replace_tools_inputs_outputs_or_execution_policy() {
        for text in [
            "[build]\nrustc='outside-rustc'",
            "[build]\nrustc-wrapper='outside-wrapper'",
            "[build]\nrustc-workspace-wrapper='outside-wrapper'",
            "[build]\nrustdoc='outside-rustdoc'",
            "[build]\ntarget-dir='../outside'",
            "[build]\nbuild-dir='../outside'",
            "[build]\ntarget='../outside.json'",
            "[build]\njobs=999",
            "[build]\nincremental=true",
            "[env]\nRUSTC_WRAPPER={value='outside',force=true}",
            "[alias]\nbuild='!outside'",
            "[unstable]\nbuild-std=true",
            "[source.crates-io]\nreplace-with='outside'",
            "[registries.other]\nindex='file:///outside'",
            "[target.x86_64-unknown-linux-gnu]\nlinker='outside-linker'",
            "[target.'cfg(unix)']\nrunner=['outside-runner']",
            "[target.x86_64-unknown-linux-gnu.native]\nrustc-link-search=['/outside']",
            "[target.'../outside.json']\nrustflags=['-Dwarnings']",
            "[llvm-cov]\nunknown-command='outside'",
        ] {
            let value: toml::Value = toml::from_str(text).unwrap();
            assert!(validate_cargo_config(&value, false).is_err(), "{text}");
        }
    }

    #[test]
    fn captured_flags_refuse_path_effects_response_files_and_unmodeled_modes() {
        for flags in [
            vec!["@/outside/flags"],
            vec!["--sysroot", "/outside"],
            vec!["-L", "native=/outside"],
            vec!["--extern=dep=/outside/libdep.rmeta"],
            vec!["--out-dir=/outside"],
            vec!["--emit=metadata=/outside/result"],
            vec!["--error-format=human"],
            vec!["-Clinker=/outside/linker"],
            vec!["-Clink-arg=@/outside/response"],
            vec!["-Cincremental=/outside"],
            vec!["-Csave-temps=yes"],
            vec!["-Cextra-filename=owned"],
            vec!["-Cllvm-args=-load=/outside/plugin.so"],
            vec!["-Zcodegen-backend=/outside/backend.so"],
            vec!["-Zunstable-options"],
            vec!["-Zthreads"],
            vec!["-Zthreads=0"],
            vec!["-Zthreads=4097"],
            vec!["-Zthreads=4294967296"],
            vec!["--cfg", "--sysroot=/outside"],
            vec!["-C"],
            vec!["-D", "@/outside"],
            vec!["--cfg", "contains\nnewline"],
            vec!["--unknown=value"],
        ] {
            let value = toml::Value::Array(flags.iter().map(|flag| (*flag).into()).collect());
            assert!(validate_compiler_flags(&value).is_err(), "{flags:?}");
        }
        for flags in [
            vec!["-g", "-O", "-Coverflow-checks=yes", "-Cdebug-assertions=no"],
            vec!["-C", "codegen-units=1", "--codegen=embed-bitcode=false"],
            vec![
                "-Cdebuginfo=line-tables-only",
                "-Cstrip=symbols",
                "-Clto=thin",
            ],
            vec!["-Adead_code", "--warn=clippy::all", "-F", "unsafe-code"],
        ] {
            let value = toml::Value::Array(flags.iter().map(|flag| (*flag).into()).collect());
            validate_compiler_flags(&value).unwrap();
        }
    }

    #[test]
    fn captured_config_rejects_wrong_types_and_excessive_flag_payloads() {
        for text in [
            "build='bad'",
            "[build]\nrustflags=7",
            "[build]\nrustflags=['--cfg',true]",
            "[target]\nx86_64-unknown-linux-gnu='bad'",
            "[llvm-cov]\nexclude='not-an-array'",
            "[llvm-cov]\nexclude=[42]",
        ] {
            assert!(
                validate_cargo_config(&toml::from_str(text).unwrap(), false).is_err(),
                "{text}"
            );
        }
        for value in [
            toml::Value::String(" ".repeat(16 * 1024 + 1)),
            toml::Value::Array(vec![toml::Value::String("-g".into()); 257]),
            toml::Value::Array(vec![toml::Value::String("--cfg=long".repeat(4096))]),
        ] {
            assert!(validate_compiler_flags(&value).is_err());
        }
    }

    #[test]
    fn declaration_and_manifest_paths_cannot_escape_the_approved_anchor() {
        for manifest in [
            "/Cargo.toml",
            "../Cargo.toml",
            "x/../Cargo.toml",
            "x//Cargo.toml",
            "x\\Cargo.toml",
            "src/lib.rs",
            "",
        ] {
            assert!(
                CargoSource::parse(&json!({"manifest":manifest})).is_err(),
                "{manifest}"
            );
        }
        assert!(CargoSource::parse(&json!({"manifest":"Cargo.toml", "unknown":true})).is_err());
        assert_eq!(
            contained_relative(Path::new("app"), "../dep").unwrap(),
            PathBuf::from("dep")
        );
        assert!(contained_relative(Path::new("app"), "../../outside").is_err());
        assert!(contained_relative(Path::new("app"), "/outside").is_err());
        let manifest: toml::Value = toml::from_str(
            "[target.'cfg(windows)'.build-dependencies]\nx = { path = \"../../outside\" }\n",
        )
        .unwrap();
        assert!(validate_manifest_paths(Path::new("app"), &manifest, None, false).is_err());
        for declaration in [
            "[dependencies]\nx = { git = 'file:///outside/repository' }",
            "[workspace.dependencies]\nx = { registry = 'outside' }",
            "[target.'cfg(windows)'.dev-dependencies]\nx = { git = 'file:///outside', path = '../local' }",
            "[patch.crates-io]\nx = { git = 'file:///outside' }",
            "[replace]\n'x:0.1.0' = { git = 'file:///outside' }",
            "[package]\nbuild = ['../../outside.rs']",
            "[package]\nforced-target = '../../outside.json'",
            "[package]\ndefault-target = 'custom.json'",
        ] {
            let manifest: toml::Value = toml::from_str(declaration).unwrap();
            assert!(
                validate_manifest_paths(Path::new("app"), &manifest, None, false).is_err(),
                "{declaration}"
            );
        }
        let metadata: toml::Value = toml::from_str("[package.metadata.example]\npath = '/not-a-Cargo-path'\ngit = 'file:///not-a-dependency'\n").unwrap();
        validate_manifest_paths(Path::new("app"), &metadata, None, false).unwrap();
        let target: toml::Value =
            toml::from_str("[package]\nforced-target = 'x86_64-unknown-linux-gnu'\n").unwrap();
        validate_manifest_paths(Path::new("app"), &target, None, false).unwrap();
    }

    #[test]
    fn retained_manifest_and_lock_validation_detects_post_capture_mutation() {
        let original = tempfile::tempdir().unwrap();
        fs::write(
            original.path().join("Cargo.toml"),
            "[package]\nname='fixture'\nversion='0.1.0'\n",
        )
        .unwrap();
        fs::write(original.path().join("Cargo.lock"), "version = 4\n").unwrap();
        let image = capture_sealed_source(
            &[("workspace".into(), original.path().to_owned())],
            false,
            2,
            1024,
        )
        .unwrap();
        let files = validate_capture(&image, "Cargo.toml", None, false).unwrap();
        let copy = tempfile::tempdir().unwrap();
        image.materialize_into(&copy.path().join("image")).unwrap();
        let root = copy.path().join("image/workspace");
        verify_planning_bytes(&image, &root, &files).unwrap();
        fs::write(root.join("Cargo.lock"), "version = 3\n").unwrap();
        assert!(verify_planning_bytes(&image, &root, &files).is_err());
        fs::write(
            original.path().join("Cargo.toml"),
            "changed original after capture",
        )
        .unwrap();
        assert!(
            image
                .file_bytes("workspace", "Cargo.toml")
                .unwrap()
                .starts_with(b"[package]")
        );
    }

    #[test]
    fn metadata_subprocess_deadline_and_output_bounds_kill_and_reap() {
        let scratch = tempfile::tempdir().unwrap();
        let group_path = scratch.path().join("owned-group");
        let mut timeout = Command::new("/bin/sh");
        timeout
            .args([
                "-c",
                "printf '%s' \"$$\" > \"$1\"; sleep 30 & wait",
                "fixture",
            ])
            .arg(&group_path);
        let started = Instant::now();
        let error =
            bounded_command(timeout, scratch.path(), Duration::from_millis(50), 1024).unwrap_err();
        assert!(error.to_string().contains("runtime bound"), "{error}");
        assert!(started.elapsed() < Duration::from_secs(5));
        let group: u32 = fs::read_to_string(&group_path).unwrap().parse().unwrap();
        assert!(
            rabs_asupersync::process_groups::members_from_proc(group).is_empty(),
            "timed-out Cargo probe must leave no live descendants"
        );
        let mut output = Command::new("/bin/sh");
        output.args([
            "-c",
            "while :; do printf 'excessive-output-output-output'; done",
        ]);
        let error =
            bounded_command(output, scratch.path(), Duration::from_secs(5), 1024).unwrap_err();
        assert!(error.to_string().contains("output bound"), "{error}");
        let mut valid = Command::new("/bin/sh");
        valid.args(["-c", "printf '%s' bounded"]);
        assert_eq!(
            bounded_command(valid, scratch.path(), Duration::from_secs(5), 1024).unwrap(),
            b"bounded"
        );
    }

    #[test]
    fn unresolved_cargo_plans_are_refused_before_execution_or_resume() {
        let request = json!({"cargo_source":{"manifest":"Cargo.toml"}});
        let error = super::super::super::request_manifest(&request).unwrap_err();
        assert!(error.to_string().contains("--worker-prepare"));
    }

    #[test]
    fn metadata_deadline_survives_missing_kill_in_supervisor_path() {
        let scratch = tempfile::tempdir().unwrap();
        if std::env::var_os("RABS_TEST_CARGO_MISSING_KILL").is_some() {
            let group_path = scratch.path().join("owned-group");
            let mut sleeper = Command::new("/bin/sh");
            sleeper
                .args([
                    "-c",
                    "printf '%s' \"$$\" > \"$1\"; /bin/sleep 30 & wait",
                    "fixture",
                ])
                .arg(&group_path);
            let started = Instant::now();
            let error = bounded_command(sleeper, scratch.path(), Duration::from_millis(50), 1024)
                .unwrap_err();
            assert!(error.to_string().contains("runtime bound"), "{error}");
            assert!(started.elapsed() < Duration::from_secs(5));
            let group: u32 = fs::read_to_string(group_path).unwrap().parse().unwrap();
            assert!(
                rabs_asupersync::process_groups::members_from_proc(group).is_empty(),
                "missing-PATH signal fallback must also kill compiler descendants"
            );
            return;
        }
        // Isolate the supervisor environment in a subprocess, avoiding global
        // environment mutation and interference with concurrently running tests.
        let mut isolated = Command::new(std::env::current_exe().unwrap());
        isolated.args(["--exact", "coord::source_delivery::preparation::cargo::tests::metadata_deadline_survives_missing_kill_in_supervisor_path", "--nocapture"])
            .env("RABS_TEST_CARGO_MISSING_KILL", "1").env("PATH", "/rabs-no-signal-helpers");
        let output =
            bounded_command(isolated, scratch.path(), Duration::from_secs(5), 64 * 1024).unwrap();
        assert!(
            String::from_utf8_lossy(&output).contains("1 passed; 0 failed"),
            "isolated supervisor regression must run exactly its named test, not pass an empty selection"
        );
    }

    #[test]
    fn symlinked_planning_directory_cannot_hide_ambient_workspace_configuration() {
        let fixture = tempfile::tempdir().unwrap();
        let real = fixture.path().join("real-parent");
        fs::create_dir_all(real.join("planning")).unwrap();
        fs::write(real.join("Cargo.toml"), "[workspace]\n").unwrap();
        let alias = fixture.path().join("tmp-alias");
        std::os::unix::fs::symlink(real.join("planning"), &alias).unwrap();
        assert!(reject_ancestor_configuration(&alias).is_err());
    }
}
