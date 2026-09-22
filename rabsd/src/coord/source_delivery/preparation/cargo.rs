//! Bounded local Cargo graph discovery from retained, coherent source bytes.
//!
//! This intentionally supports locked local workspaces/path dependencies. The
//! approved anchor is the upload boundary, not a guessed set of Rust files:
//! build scripts, include! inputs, and optional/target dependencies retain their
//! relative layout. No descriptor, cache authority, or compiler result is minted.

use super::super::{SourceUpload, invalid, require};
use rabs_asupersync::process_groups::{GroupSignal, ManagedProcessGroup};
use rabs_asupersync::region_tree::Attribution;
use rabs_sandbox::snapshot_capture::{MemberKind, SealedSourceSnapshot};
use rabs_sandbox::source_transfer::MAX_SOURCE_FILES;
use serde_json::Value;
use std::collections::BTreeSet;
use std::fs::{self, File};
use std::io::{self, Read};
use std::path::{Component, Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::Arc;
use std::time::{Duration, Instant};

const OUTPUT_LIMIT: u64 = 8 * 1024 * 1024;
const METADATA_TIMEOUT: Duration = Duration::from_secs(30);
const MAX_PACKAGES: usize = 1024;

#[derive(Debug)]
pub(super) struct CargoSource {
    manifest: String,
}

impl CargoSource {
    pub(super) fn parse(value: &Value) -> io::Result<Self> {
        require(
            value.as_object().is_some_and(|fields| fields.len() == 1),
            "cargo_source requires exactly manifest",
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
        Ok(Self {
            manifest: manifest.to_owned(),
        })
    }

    pub(super) fn manifest(&self) -> &str {
        &self.manifest
    }

    pub(super) fn prepare(&self, image: Arc<SealedSourceSnapshot>) -> io::Result<SourceUpload> {
        let files = validate_capture(&image, &self.manifest)?;
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
        let mut command = Command::new(cargo);
        command
            .env_clear()
            .current_dir(
                root.join(&self.manifest)
                    .parent()
                    .ok_or_else(|| invalid("Cargo manifest parent"))?,
            )
            .args([
                "metadata",
                "--format-version=1",
                "--locked",
                "--offline",
                "--all-features",
            ])
            .arg("--manifest-path")
            .arg(root.join(&self.manifest))
            .env("HOME", home)
            .env("CARGO_HOME", cargo_home)
            .env("RUSTC", rustc)
            .env("CARGO_TARGET_DIR", planning_root.join("target"));
        for key in ["PATH", "LD_LIBRARY_PATH", "DYLD_LIBRARY_PATH"] {
            if let Some(value) = std::env::var_os(key) {
                command.env(key, value);
            }
        }
        let output = bounded_command(command, &planning_root, METADATA_TIMEOUT, OUTPUT_LIMIT)?;
        let metadata: Value = serde_json::from_slice(&output)
            .map_err(|error| invalid(&format!("invalid Cargo metadata JSON: {error}")))?;
        validate_metadata(&image, &root, &self.manifest, &metadata)?;
        verify_planning_bytes(&image, &root, &files)?;
        SourceUpload::from_snapshot(image, "workspace", &files)
    }
}

fn validate_capture(image: &SealedSourceSnapshot, manifest: &str) -> io::Result<Vec<String>> {
    let captured = image
        .manifest("workspace")
        .ok_or_else(|| invalid("missing captured Cargo anchor"))?;
    let mut files = Vec::new();
    for (path, kind) in &captured.members {
        require(
            !matches!(kind, MemberKind::Symlink { .. }),
            "automatic Cargo source preparation does not support symlinks",
        )?;
        if matches!(kind, MemberKind::Regular { .. }) {
            require(
                !is_cargo_config(Path::new(path)),
                "automatic Cargo source preparation does not yet support .cargo/config or config.toml; use explicit source selection",
            )?;
            files.push(path.clone());
            require(
                files.len() <= MAX_SOURCE_FILES,
                "Cargo source anchor exceeds the file-count bound",
            )?;
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
                validate_manifest_paths(Path::new(path).parent().unwrap_or(Path::new("")), &value)?;
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
                if let Some(packages) = lock.get("package").and_then(toml::Value::as_array) {
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

// This is a containment preflight, not a second dependency resolver. Cargo owns
// graph resolution; checking path-bearing manifest fields before it runs prevents
// Cargo from opening absolute/escaping local dependencies outside the copy.
fn validate_manifest_paths(base: &Path, value: &toml::Value) -> io::Result<()> {
    for field in ["package", "project"] {
        if let Some(package) = value.get(field) {
            for field in ["workspace", "readme", "license-file", "build"] {
                validate_path_field(base, package, field)?;
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
    validate_dependency_sections(base, value)?;
    if let Some(targets) = value.get("target").and_then(toml::Value::as_table) {
        for target in targets.values() {
            validate_dependency_sections(base, target)?;
        }
    }
    if let Some(workspace) = value.get("workspace") {
        validate_dependency_sections(base, workspace)?;
        for field in ["members", "default-members", "exclude"] {
            if let Some(paths) = workspace.get(field).and_then(toml::Value::as_array) {
                for path in paths {
                    if let Some(path) = path.as_str() {
                        contained_relative(base, path)?;
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
            validate_dependencies(base, dependencies)?;
        }
    }
    if let Some(replacements) = value.get("replace") {
        validate_dependencies(base, replacements)?;
    }
    Ok(())
}

fn validate_path_field(base: &Path, value: &toml::Value, field: &str) -> io::Result<()> {
    if let Some(path) = value.get(field).and_then(toml::Value::as_str) {
        contained_relative(base, path)?;
    }
    Ok(())
}

fn validate_dependency_sections(base: &Path, value: &toml::Value) -> io::Result<()> {
    for field in [
        "dependencies",
        "dev-dependencies",
        "build-dependencies",
        "dev_dependencies",
        "build_dependencies",
    ] {
        if let Some(dependencies) = value.get(field) {
            validate_dependencies(base, dependencies)?;
        }
    }
    Ok(())
}

fn validate_dependencies(base: &Path, value: &toml::Value) -> io::Result<()> {
    if let Some(dependencies) = value.as_table() {
        for dependency in dependencies.values() {
            if let Some(fields) = dependency.as_table() {
                require(
                    !fields.contains_key("git")
                        && !fields.contains_key("registry")
                        && !fields.contains_key("registry-index"),
                    "automatic Cargo source preparation does not import git or registry dependency selectors",
                )?;
                validate_path_field(base, dependency, "path")?;
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
    let packages = value["packages"]
        .as_array()
        .filter(|packages| !packages.is_empty() && packages.len() <= MAX_PACKAGES)
        .ok_or_else(|| invalid("Cargo package graph is missing or exceeds its bound"))?;
    let mut ids = BTreeSet::new();
    let mut selected = false;
    for package in packages {
        require(
            package.get("source").is_some_and(Value::is_null),
            "automatic Cargo source preparation supports local path packages only; registry/git sources require explicit preparation",
        )?;
        let id = package["id"]
            .as_str()
            .ok_or_else(|| invalid("Cargo package identity missing"))?;
        require(ids.insert(id), "duplicate Cargo package identity")?;
        let path = captured_metadata_path(image, root, &package["manifest_path"])?;
        selected |= path == root.join(manifest);
        let targets = package["targets"]
            .as_array()
            .filter(|targets| !targets.is_empty())
            .ok_or_else(|| invalid("Cargo package has no target graph"))?;
        for target in targets {
            captured_metadata_path(image, root, &target["src_path"])?;
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
            Path::new("dep")
        );
        assert!(contained_relative(Path::new("app"), "../../outside").is_err());
        assert!(contained_relative(Path::new("app"), "/outside").is_err());
        let manifest: toml::Value = toml::from_str(
            "[target.'cfg(windows)'.build-dependencies]\nx = { path = \"../../outside\" }\n",
        )
        .unwrap();
        assert!(validate_manifest_paths(Path::new("app"), &manifest).is_err());
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
                validate_manifest_paths(Path::new("app"), &manifest).is_err(),
                "{declaration}"
            );
        }
        let metadata: toml::Value = toml::from_str("[package.metadata.example]\npath = '/not-a-Cargo-path'\ngit = 'file:///not-a-dependency'\n").unwrap();
        validate_manifest_paths(Path::new("app"), &metadata).unwrap();
        let target: toml::Value =
            toml::from_str("[package]\nforced-target = 'x86_64-unknown-linux-gnu'\n").unwrap();
        validate_manifest_paths(Path::new("app"), &target).unwrap();
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
        let files = validate_capture(&image, "Cargo.toml").unwrap();
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
