//! Berry's effective install layout and non-manifest inputs.
//!
//! Ask the selected Yarn binary for its configuration rather than reproducing
//! YAML precedence, home settings, environment overrides or plugin defaults.
//! The first PnP class owns the standard project-local layout. Global/custom
//! dependency stores need a separate ownership contract and are refused here.

use super::{DependencyLayout, InputIdentity, PrepareTransaction, environment};
use anyhow::{Context, Result, ensure};
use serde::Deserialize;
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};
use std::fs::File;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::time::Duration;

const MAX_QUERY_BYTES: usize = 1024 * 1024;
const MAX_INPUT_FILES: usize = 4096;
const MAX_INPUT_DEPTH: usize = 32;
const MAX_RUNTIME_INPUT_VALUES: usize = 100_000;
const MAX_LOCATOR_DECODING_PASSES: usize = 8;

#[derive(Debug, PartialEq, Eq)]
pub(super) struct Observation {
    project: PathBuf,
    pub(super) layout: DependencyLayout,
    pub(super) digest: blake3::Hash,
    require_data: bool,
    require_esm: bool,
    invocation: Option<InvocationPolicy>,
    inputs: environment::CapturedEnvironment,
    directories: Vec<(PathBuf, Vec<String>)>,
}

impl Observation {
    pub(super) fn unchanged_after_install(&self, after: &Self) -> bool {
        self.project == after.project
            && self.layout == after.layout
            && self.digest == after.digest
            && self.require_data == after.require_data
            && self.require_esm == after.require_esm
            && self.invocation == after.invocation
            && self.directories == after.directories
            && self
                .inputs
                .same_after_yarn_parent_created(&after.inputs, &self.project)
    }

    pub(super) fn outputs_ready(&self, project: &Path) -> bool {
        let regular = |name: &str| {
            std::fs::symlink_metadata(project.join(name))
                .is_ok_and(|metadata| metadata.file_type().is_file())
        };
        match self.layout {
            DependencyLayout::NodeModules => project.join("node_modules").is_dir(),
            DependencyLayout::YarnPnp => {
                regular(".pnp.cjs")
                    && regular(".yarn/install-state.gz")
                    && (!self.require_data || regular(".pnp.data.json"))
                    && (!self.require_esm || regular(".pnp.loader.mjs"))
            }
        }
    }

    pub(super) fn verify_invocation(&self, preparation: &Path, invocation: &Path) -> Result<()> {
        if let Some(policy) = &self.invocation {
            policy.verify(preparation, invocation)?;
        }
        Ok(())
    }
}

fn verify_pnp_output_paths(project: &Path) -> Result<()> {
    // Check generated ancestors before their descendants; lstat on a leaf
    // alone would still traverse a planted `.yarn` directory symlink. Existing
    // selected zero-install files are admitted without rewriting any bytes.
    for (name, directory) in [
        (".yarn", true),
        (".yarn/cache", true),
        (".yarn/unplugged", true),
        (".pnp.cjs", false),
        (".pnp.data.json", false),
        (".pnp.loader.mjs", false),
        (".yarn/install-state.gz", false),
    ] {
        let metadata = match std::fs::symlink_metadata(project.join(name)) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(error) => return Err(error).context("inspect Yarn generated output path"),
        };
        ensure!(
            if directory {
                metadata.file_type().is_dir()
            } else {
                metadata.file_type().is_file()
            },
            "Yarn generated output path is not the required real file or directory: {name}"
        );
    }
    Ok(())
}

fn external_runtime_locator(value: &str) -> Result<bool> {
    fn hex(byte: u8) -> Option<u8> {
        match byte {
            b'0'..=b'9' => Some(byte - b'0'),
            b'a'..=b'f' => Some(byte - b'a' + 10),
            b'A'..=b'F' => Some(byte - b'A' + 10),
            _ => None,
        }
    }

    // A patch/virtual locator can embed another locator, including percent
    // encoded separators and names. Decode a bounded number of nesting levels
    // rather than checking only the outer protocol's spelling.
    let mut bytes = value.as_bytes().to_vec();
    for _ in 0..=MAX_LOCATOR_DECODING_PASSES {
        for protocol in [b"portal:".as_slice(), b"link:".as_slice()] {
            if bytes
                .windows(protocol.len())
                .enumerate()
                .any(|(index, word)| {
                    word.eq_ignore_ascii_case(protocol)
                        && (index == 0
                            || matches!(bytes[index - 1], b'@' | b'#' | b':' | b'=' | b',' | b' '))
                })
            {
                return Ok(true);
            }
        }
        let mut decoded = Vec::with_capacity(bytes.len());
        let mut index = 0;
        let mut changed = false;
        while index < bytes.len() {
            if bytes[index] == b'%'
                && let (Some(high), Some(low)) = (
                    bytes.get(index + 1).copied().and_then(hex),
                    bytes.get(index + 2).copied().and_then(hex),
                )
            {
                decoded.push((high << 4) | low);
                index += 3;
                changed = true;
            } else {
                decoded.push(bytes[index]);
                index += 1;
            }
        }
        if !changed {
            return Ok(false);
        }
        bytes = decoded;
    }
    anyhow::bail!("Yarn locator encoding exceeds the bounded runtime ownership contract")
}

fn verify_runtime_values(value: &Value, remaining: &mut usize) -> Result<()> {
    let mut pending = vec![value];
    while let Some(value) = pending.pop() {
        *remaining = remaining
            .checked_sub(1)
            .context("Yarn runtime input value limit exceeded")?;
        match value {
            Value::String(value) => ensure!(
                !external_runtime_locator(value)?,
                "Yarn PnP portal/link dependencies require a separate runtime ownership contract"
            ),
            Value::Array(values) => {
                ensure!(
                    pending.len().saturating_add(values.len()) <= *remaining,
                    "Yarn runtime input value limit exceeded"
                );
                pending.extend(values);
            }
            Value::Object(values) => {
                ensure!(
                    pending.len().saturating_add(values.len()) <= *remaining,
                    "Yarn runtime input value limit exceeded"
                );
                for (key, value) in values {
                    ensure!(
                        !external_runtime_locator(key)?,
                        "Yarn PnP portal/link dependencies require a separate runtime ownership contract"
                    );
                    pending.push(value);
                }
            }
            _ => {}
        }
    }
    Ok(())
}

fn verify_pnp_resolution_policy(config: &BTreeMap<String, Value>) -> Result<()> {
    ensure!(
        config
            .get("pnpIgnorePatterns")
            .and_then(Value::as_array)
            .is_some_and(Vec::is_empty),
        "Yarn PnP ignore patterns require an ambient resolution contract"
    );
    // PnP fallback and loose hoisting consult registered package locations;
    // unlike ignored issuers, they do not switch to ambient CommonJS lookup.
    ensure!(
        matches!(
            string(config, "pnpFallbackMode")?,
            "none" | "dependencies-only" | "all"
        ) && matches!(string(config, "pnpMode")?, "strict" | "loose"),
        "unsupported Yarn PnP fallback or hoisting mode"
    );
    Ok(())
}

fn verify_pnp_runtime_inputs(
    project: &Path,
    sources: &[String],
    config: &BTreeMap<String, Value>,
) -> Result<()> {
    verify_pnp_resolution_policy(config)?;
    let mut remaining = MAX_RUNTIME_INPUT_VALUES;
    for name in ["defaultProtocol", "packageExtensions"] {
        if let Some(value) = config.get(name) {
            verify_runtime_values(value, &mut remaining)?;
        }
    }
    let mut bytes_left = super::MAX_INPUT_BYTES;
    let mut read = |name: &str| -> Result<Vec<u8>> {
        let bytes = read_input(&project.join(name))?;
        bytes_left = bytes_left
            .checked_sub(bytes.len() as u64)
            .context("Yarn runtime inputs exceed byte limit")?;
        Ok(bytes)
    };
    let lock: Value = serde_yaml_ng::from_slice(&read("yarn.lock")?)
        .map_err(|_| anyhow::anyhow!("Yarn lockfile could not be decoded for PnP ownership"))?;
    verify_runtime_values(&lock, &mut remaining)?;
    for entry in lock
        .as_object()
        .context("Yarn PnP lockfile is not a mapping")?
        .values()
    {
        if let Some(link_type) = entry.get("linkType") {
            match link_type.as_str() {
                Some("hard") => {}
                Some("soft") => {
                    let resolution = entry
                        .get("resolution")
                        .and_then(Value::as_str)
                        .context("Yarn soft link has no runtime resolution")?;
                    let name_start = usize::from(resolution.starts_with('@'));
                    ensure!(
                        resolution[name_start..]
                            .split_once('@')
                            .is_some_and(|(_, reference)| reference.starts_with("workspace:")),
                        "Yarn PnP non-workspace soft links require a separate runtime ownership contract"
                    );
                }
                _ => anyhow::bail!("unsupported Yarn package link type"),
            }
        }
    }
    // Member manifests matter even when the root lock is unchanged. Include
    // declared overrides and optional/peer dependencies, not just dependencies.
    for name in sources
        .iter()
        .filter(|name| name.as_str() == "package.json" || name.ends_with("/package.json"))
    {
        let manifest: Value = serde_json::from_slice(&read(name)?)
            .map_err(|_| anyhow::anyhow!("Yarn manifest could not be decoded for PnP ownership"))?;
        for field in [
            "dependencies",
            "devDependencies",
            "optionalDependencies",
            "peerDependencies",
            "resolutions",
        ] {
            if let Some(value) = manifest.get(field) {
                verify_runtime_values(value, &mut remaining)?;
            }
        }
    }
    Ok(())
}

#[derive(Debug, PartialEq, Eq)]
struct InvocationPolicy {
    rc_filename: String,
    relative_environment_files: Vec<PathBuf>,
}

impl InvocationPolicy {
    fn capture(project: &Path, config: &BTreeMap<String, Value>) -> Result<Self> {
        let rc_filename = string(config, "rcFilename")?;
        ensure!(
            !rc_filename.is_empty()
                && rc_filename.len() <= 255
                && !matches!(rc_filename, "." | "..")
                && !rc_filename.contains(['/', '\\'])
                && !rc_filename.chars().any(char::is_control),
            "Yarn configuration filename must be a literal filename"
        );
        let mut relative_environment_files = BTreeSet::new();
        if let Some(Value::Array(files)) = config.get("injectEnvironmentFiles") {
            ensure!(
                files.len() <= MAX_INPUT_FILES,
                "Yarn environment file limit exceeded"
            );
            for file in files {
                let file = file.as_str().context("invalid Yarn environment filename")?;
                let file = file.strip_suffix('?').unwrap_or(file);
                let resolved = input_path(project, file)?;
                if !Path::new(file).is_absolute() {
                    relative_environment_files.insert(PathBuf::from(file));
                } else if let Ok(relative) = resolved.strip_prefix(project) {
                    // An effective absolute setting does not expose whether
                    // its source was cwd-relative. Keep member admission
                    // conservative for project-local environment files.
                    relative_environment_files.insert(relative.to_owned());
                }
            }
        }
        Ok(Self {
            rc_filename: rc_filename.to_owned(),
            relative_environment_files: relative_environment_files.into_iter().collect(),
        })
    }

    fn verify(&self, preparation: &Path, invocation: &Path) -> Result<()> {
        let preparation = preparation.canonicalize()?;
        let invocation = invocation.canonicalize()?;
        ensure!(
            invocation.starts_with(&preparation),
            "Yarn execution is outside its preparation root"
        );
        if invocation == preparation {
            return Ok(());
        }
        let present = |path: &Path| -> Result<bool> {
            match std::fs::symlink_metadata(path) {
                Ok(_) => Ok(true),
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
                Err(error) => Err(error).context("inspect member Yarn configuration"),
            }
        };
        let mut directory = invocation.as_path();
        while directory != preparation {
            for name in [".yarnrc.yml", self.rc_filename.as_str()] {
                ensure!(
                    !present(&directory.join(name))?,
                    "member Yarn configuration is outside the bounded preparation contract"
                );
            }
            directory = directory
                .parent()
                .context("Yarn invocation has no preparation ancestor")?;
        }
        for relative in &self.relative_environment_files {
            let prepared = preparation.join(relative);
            let invoked = invocation.join(relative);
            ensure!(
                prepared == invoked || (!present(&prepared)? && !present(&invoked)?),
                "member Yarn environment files are outside the bounded preparation contract"
            );
        }
        Ok(())
    }
}

fn read_input(path: &Path) -> Result<Vec<u8>> {
    let before = InputIdentity::of(&std::fs::symlink_metadata(path)?)?;
    ensure!(
        before.len <= super::MAX_INPUT_BYTES,
        "Yarn input exceeds byte limit"
    );
    #[cfg(unix)]
    let mut file = {
        use rustix::fs::{Mode, OFlags};
        File::from(rustix::fs::open(
            path,
            OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::NONBLOCK,
            Mode::empty(),
        )?)
    };
    #[cfg(not(unix))]
    let mut file = File::open(path)?;
    ensure!(
        InputIdentity::of(&file.metadata()?)? == before,
        "Yarn input changed before read"
    );
    let mut bytes = Vec::new();
    (&mut file).take(before.len + 1).read_to_end(&mut bytes)?;
    ensure!(
        bytes.len() as u64 == before.len
            && InputIdentity::of(&file.metadata()?)? == before
            && InputIdentity::of(&std::fs::symlink_metadata(path)?)? == before,
        "Yarn input changed during read"
    );
    Ok(bytes)
}

fn berry_version(project: &Path, sources: &[String]) -> Result<Option<Option<String>>> {
    if !sources.iter().any(|name| name == "yarn.lock") {
        return Ok(None);
    }
    let manifest: Value = serde_json::from_slice(&read_input(&project.join("package.json"))?)?;
    let declared = manifest
        .get("packageManager")
        .and_then(Value::as_str)
        .and_then(|value| value.strip_prefix("yarn@"))
        .map(|value| value.split('+').next().unwrap_or(value).to_owned());
    if declared
        .as_deref()
        .and_then(|version| version.split('.').next())
        .and_then(|major| major.parse::<u32>().ok())
        .is_some_and(|major| major >= 2)
    {
        return Ok(Some(declared));
    }
    // A Berry lock has this unindented top-level entry. Do not execute a
    // configuration query for Yarn Classic or every unrelated npm project.
    let lock = read_input(&project.join("yarn.lock"))?;
    let berry = lock
        .split(|byte| *byte == b'\n')
        .any(|line| line == b"__metadata:" || line == b"__metadata:\r");
    Ok(berry.then_some(declared))
}

pub(super) fn requires_query(project: &Path, sources: &[String]) -> Result<bool> {
    berry_version(project, sources).map(|version| version.is_some())
}

#[derive(Deserialize)]
struct Setting {
    key: String,
    #[serde(default, deserialize_with = "present_setting_value")]
    effective: Option<Value>,
    source: Option<String>,
    description: Option<String>,
    #[serde(rename = "type")]
    kind: Option<String>,
    #[serde(rename = "valueDefinition")]
    value_definition: Option<Value>,
    properties: Option<Value>,
    #[serde(rename = "defaultText")]
    default_text: Option<String>,
}

fn present_setting_value<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> std::result::Result<Option<Value>, D::Error> {
    // Keep an explicit JSON null distinct from an omitted effective field.
    Value::deserialize(deserializer).map(Some)
}

fn settings(bytes: &[u8]) -> Result<BTreeMap<String, Value>> {
    ensure!(
        bytes.len() <= MAX_QUERY_BYTES,
        "Yarn configuration response exceeds byte limit"
    );
    let mut settings = BTreeMap::new();
    for line in bytes
        .split(|byte| *byte == b'\n')
        .filter(|line| !line.is_empty())
    {
        let setting: Setting = serde_json::from_slice(line)
            .map_err(|_| anyhow::anyhow!("invalid Yarn configuration record"))?;
        let effective = match setting.effective {
            Some(value) => value,
            None => {
                // Berry omits empty MAP/SHAPE values and its unset default
                // progress style. Only their actual definition-bearing shapes
                // authorize omission; an arbitrary incomplete record does not.
                let definition = setting.kind.as_deref();
                let described = setting.source.is_some() && setting.description.is_some();
                if described
                    && match definition {
                        Some("MAP") => setting
                            .value_definition
                            .as_ref()
                            .is_some_and(Value::is_object),
                        Some("SHAPE") => setting.properties.as_ref().is_some_and(Value::is_object),
                        _ => false,
                    }
                {
                    Value::Object(serde_json::Map::new())
                } else if described
                    && setting.key == "progressBarStyle"
                    && definition == Some("STRING")
                    && setting.source.as_deref() == Some("<default>")
                    && setting.default_text.is_some()
                {
                    Value::Null
                } else {
                    anyhow::bail!("invalid Yarn configuration record");
                }
            }
        };
        ensure!(
            settings.len() < 512,
            "Yarn configuration exceeds setting limit"
        );
        ensure!(
            settings.insert(setting.key, effective).is_none(),
            "duplicate Yarn configuration setting"
        );
    }
    Ok(settings)
}

fn setting_map(bytes: &[u8]) -> Result<Value> {
    ensure!(
        bytes.len() <= MAX_QUERY_BYTES,
        "Yarn configuration map exceeds byte limit"
    );
    // `config get --json` emits this exact token for an empty map, while
    // nonempty maps are converted to JSON objects before serialization.
    if bytes == b"undefined\n" {
        return Ok(Value::Object(serde_json::Map::new()));
    }
    let value: Value = serde_json::from_slice(bytes)
        .map_err(|_| anyhow::anyhow!("invalid Yarn configuration map"))?;
    ensure!(value.is_object(), "invalid Yarn configuration map");
    Ok(value)
}

async fn query_settings(
    project: &Path,
    deadline: tokio::time::Instant,
    transaction: &mut PrepareTransaction,
) -> Result<BTreeMap<String, Value>> {
    let mut settings =
        settings(&query(project, &["config", "--json"], deadline, transaction).await?)?;
    if settings.get("nodeLinker").and_then(Value::as_str) == Some("pnp") {
        // `config --json` serializes even nonempty MAP values as `{}`. Their
        // raw configuration/environment inputs remain fingerprinted, but that
        // placeholder is not an effective-map proof. Package extensions can
        // introduce unowned runtime links, so query their full effective map.
        let extensions = query(
            project,
            &["config", "get", "packageExtensions", "--json"],
            deadline,
            transaction,
        )
        .await?;
        settings.insert("packageExtensions".to_owned(), setting_map(&extensions)?);
    }
    Ok(settings)
}

fn string<'a>(settings: &'a BTreeMap<String, Value>, key: &str) -> Result<&'a str> {
    settings
        .get(key)
        .and_then(Value::as_str)
        .with_context(|| format!("Yarn configuration lacks string {key}"))
}

fn layout(project: &Path, settings: &BTreeMap<String, Value>) -> Result<DependencyLayout> {
    match string(settings, "nodeLinker")? {
        "node-modules" => Ok(DependencyLayout::NodeModules),
        "pnp" => {
            ensure!(
                settings.get("enableGlobalCache") == Some(&Value::Bool(false)),
                "qualified Yarn PnP requires enableGlobalCache: false and project-local dependencies"
            );
            for (key, relative) in [
                ("cacheFolder", ".yarn/cache"),
                ("pnpUnpluggedFolder", ".yarn/unplugged"),
                ("installStatePath", ".yarn/install-state.gz"),
                ("virtualFolder", ".yarn/__virtual__"),
            ] {
                ensure!(
                    Path::new(string(settings, key)?) == project.join(relative),
                    "Yarn PnP {key} requires the standard project-local output layout"
                );
            }
            Ok(DependencyLayout::YarnPnp)
        }
        _ => anyhow::bail!("unsupported Yarn dependency linker"),
    }
}

fn input_path(project: &Path, value: &str) -> Result<PathBuf> {
    ensure!(
        !value.is_empty() && value.len() <= 4096 && !value.chars().any(char::is_control),
        "invalid Yarn input path"
    );
    let path = Path::new(value);
    Ok(if path.is_absolute() {
        path.to_owned()
    } else {
        project.join(path)
    })
}

fn auxiliary_paths(project: &Path, config: &BTreeMap<String, Value>) -> Result<BTreeSet<PathBuf>> {
    let mut paths = BTreeSet::new();
    if let Some(Value::String(path)) = config.get("yarnPath") {
        paths.insert(input_path(project, path)?);
    }
    if let Some(Value::Array(files)) = config.get("injectEnvironmentFiles") {
        ensure!(
            files.len() <= MAX_INPUT_FILES,
            "Yarn environment file limit exceeded"
        );
        for file in files {
            let file = file.as_str().context("invalid Yarn environment filename")?;
            paths.insert(input_path(project, file.strip_suffix('?').unwrap_or(file))?);
        }
    }
    Ok(paths)
}

/// Capture every entry in the authored Yarn input directories, never cache,
/// unplugged or generated loader outputs. Directory membership is part of the
/// observation, so adding a patch/plugin/release invalidates a retained stamp.
fn authored_inputs(
    path: &Path,
    depth: usize,
    files: &mut BTreeSet<PathBuf>,
    directories: &mut Vec<(PathBuf, Vec<String>)>,
) -> Result<()> {
    ensure!(
        depth <= MAX_INPUT_DEPTH && directories.len() <= MAX_INPUT_FILES,
        "Yarn input tree exceeds depth or directory limit"
    );
    let metadata = match std::fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            files.insert(path.to_owned());
            return Ok(());
        }
        Err(error) => return Err(error.into()),
    };
    if metadata.file_type().is_file() {
        ensure!(
            files.len() < MAX_INPUT_FILES,
            "Yarn input file limit exceeded"
        );
        files.insert(path.to_owned());
        return Ok(());
    }
    ensure!(
        metadata.file_type().is_dir(),
        "Yarn authored input is not a regular file or directory"
    );
    let mut names = Vec::new();
    for entry in std::fs::read_dir(path)? {
        ensure!(
            names.len() < MAX_INPUT_FILES,
            "Yarn input directory entry limit exceeded"
        );
        names.push(
            entry?
                .file_name()
                .into_string()
                .map_err(|_| anyhow::anyhow!("Yarn input path is not UTF-8"))?,
        );
    }
    names.sort();
    for name in &names {
        authored_inputs(&path.join(name), depth + 1, files, directories)?;
    }
    directories.push((path.to_owned(), names));
    Ok(())
}

#[cfg(target_os = "linux")]
async fn query(
    project: &Path,
    arguments: &[&str],
    deadline: tokio::time::Instant,
    transaction: &mut PrepareTransaction,
) -> Result<Vec<u8>> {
    ensure!(
        tokio::time::Instant::now() < deadline,
        "Yarn configuration query deadline expired"
    );
    let mut command = crate::executor::managed_command(
        std::env::current_exe().context("resolve Yarn configuration supervisor")?,
    );
    command
        .args([
            "prepare-installer",
            "--",
            "/bin/sh",
            "-c",
            "exec yarn \"$@\" 2>/dev/null",
            "rch-yarn-query",
        ])
        .args(arguments)
        .current_dir(project);
    let already_running = transaction.begin_query()?;
    let output = rch_common::ssh::capture_supervised_output_inherited_group(
        &mut command,
        None,
        super::install::INSTALLER_RECEIPT_LIMIT as usize,
        MAX_QUERY_BYTES,
        deadline,
    )
    .await
    .context("Yarn configuration query did not complete")?;
    // The existing supervisor sends child stdout to its stderr descriptor;
    // only the complete descendant receipt reaches stdout. Query diagnostics
    // may contain credentials, and must not enter a decoded-data error chain.
    ensure!(
        output.status.success(),
        "Yarn configuration supervisor failed ({})",
        output.status
    );
    let succeeded = super::install::completed_installer_succeeded(&output.stdout)?;
    transaction.finish_query(already_running)?;
    ensure!(succeeded, "Yarn configuration query failed");
    Ok(output.stderr)
}

#[cfg(not(target_os = "linux"))]
async fn query(
    _project: &Path,
    _arguments: &[&str],
    _deadline: tokio::time::Instant,
    _transaction: &mut PrepareTransaction,
) -> Result<Vec<u8>> {
    anyhow::bail!("Yarn Berry preparation requires Linux descendant completion")
}

#[derive(Debug, PartialEq, Eq)]
struct AuxiliaryInputs {
    environment: environment::CapturedEnvironment,
    directories: Vec<(PathBuf, Vec<String>)>,
}

fn capture_auxiliary_inputs(
    project: &Path,
    config: &BTreeMap<String, Value>,
    base: &environment::CapturedEnvironment,
) -> Result<AuxiliaryInputs> {
    let mut paths = auxiliary_paths(project, config)?;
    // Plugin records are special configuration, absent from `yarn config`.
    // Bind their exact local executable files in addition to the YAML bytes.
    for rc in base.configuration_paths() {
        let bytes = match read_input(rc) {
            Ok(bytes) => bytes,
            Err(error) if !rc.try_exists()? => {
                let _ = error;
                continue;
            }
            Err(error) => return Err(error),
        };
        let document: Value = serde_yaml_ng::from_slice(&bytes)
            .map_err(|_| anyhow::anyhow!("invalid Yarn configuration YAML"))?;
        if let Some(plugins) = document.get("plugins") {
            for plugin in plugins.as_array().context("invalid Yarn plugin list")? {
                let value = plugin
                    .as_str()
                    .or_else(|| plugin.get("path").and_then(Value::as_str))
                    .context("Yarn plugin has no literal path")?;
                ensure!(
                    !value.contains("${"),
                    "interpolated Yarn plugin paths require an explicit input contract"
                );
                paths.insert(input_path(
                    rc.parent().context("Yarn configuration has no parent")?,
                    value,
                )?);
            }
        }
    }
    let mut directories = Vec::new();
    for name in [".yarn/patches", ".yarn/plugins", ".yarn/releases"] {
        authored_inputs(&project.join(name), 0, &mut paths, &mut directories)?;
    }
    ensure!(
        paths.len() <= MAX_INPUT_FILES,
        "Yarn auxiliary input file limit exceeded"
    );
    let inputs = environment::capture_yarn(project, &paths.iter().cloned().collect::<Vec<_>>())?;
    // A newly added patch/plugin/release must not slip between enumeration and
    // the final input read. Recheck both membership and all file observations.
    let mut observed_paths = auxiliary_paths(project, config)?;
    let mut observed_directories = Vec::new();
    for name in [".yarn/patches", ".yarn/plugins", ".yarn/releases"] {
        authored_inputs(
            &project.join(name),
            0,
            &mut observed_paths,
            &mut observed_directories,
        )?;
    }
    ensure!(
        directories == observed_directories
            && observed_paths.iter().all(|path| paths.contains(path)),
        "Yarn authored input directory membership changed during capture"
    );
    ensure!(
        environment::capture_yarn(project, &paths.into_iter().collect::<Vec<_>>())? == inputs,
        "Yarn auxiliary inputs changed during capture"
    );
    ensure!(
        environment::capture_yarn(project, &[])? == *base,
        "Yarn configuration changed during its query"
    );
    Ok(AuxiliaryInputs {
        environment: inputs,
        directories,
    })
}

pub(super) async fn capture(
    project: &Path,
    sources: &[String],
    transaction: &mut PrepareTransaction,
) -> Result<Option<Observation>> {
    let Some(declared) = berry_version(project, sources)? else {
        return Ok(None);
    };
    let before = environment::capture_yarn(project, &[])?;
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    let version = query(project, &["--version"], deadline, transaction).await?;
    let version = std::str::from_utf8(&version)?.trim();
    ensure!(
        version.len() <= 128
            && !version.chars().any(char::is_control)
            && version
                .split('.')
                .next()
                .and_then(|major| major.parse::<u32>().ok())
                .is_some_and(|major| major >= 2),
        "Yarn Berry configuration requires a Berry executable"
    );
    if let Some(expected) = declared {
        ensure!(
            version == expected,
            "Yarn executable does not match packageManager version"
        );
    }
    let config = query_settings(project, deadline, transaction).await?;
    let layout = layout(project, &config)?;
    if layout == DependencyLayout::YarnPnp {
        verify_pnp_output_paths(project)?;
        verify_pnp_runtime_inputs(project, sources, &config)?;
    }
    let invocation = (layout == DependencyLayout::YarnPnp)
        .then(|| InvocationPolicy::capture(project, &config))
        .transpose()?;
    let inputs = capture_auxiliary_inputs(project, &config, &before)?;
    // The first query discovers effective auxiliary paths. Only a repeated
    // result bracketed by their exact files proves that configuration and its
    // executable/environment inputs belong to the same generation.
    let confirmed_version = query(project, &["--version"], deadline, transaction).await?;
    ensure!(
        std::str::from_utf8(&confirmed_version)?.trim() == version,
        "Yarn executable changed during configuration capture"
    );
    let confirmed_config = query_settings(project, deadline, transaction).await?;
    ensure!(
        config == confirmed_config,
        "Yarn effective configuration changed during capture"
    );
    let after = capture_auxiliary_inputs(project, &confirmed_config, &before)?;
    ensure!(
        inputs == after,
        "Yarn auxiliary inputs changed during configuration query"
    );
    let mut digest = blake3::Hasher::new();
    digest.update(b"rch-yarn-install-v1\0");
    digest.update(version.as_bytes());
    digest.update(inputs.environment.digest.as_bytes());
    digest.update(&serde_json::to_vec(&config)?);
    digest.update(&serde_json::to_vec(&inputs.directories)?);
    Ok(Some(Observation {
        project: project.to_owned(),
        layout,
        digest: digest.finalize(),
        require_data: config.get("pnpEnableInlining") == Some(&Value::Bool(false)),
        require_esm: config.get("pnpEnableEsmLoader") == Some(&Value::Bool(true)),
        invocation,
        inputs: inputs.environment,
        directories: inputs.directories,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pnp_settings(project: &Path) -> BTreeMap<String, Value> {
        let mut settings = BTreeMap::from([
            ("nodeLinker".to_owned(), Value::String("pnp".to_owned())),
            ("enableGlobalCache".to_owned(), Value::Bool(false)),
            ("pnpIgnorePatterns".to_owned(), serde_json::json!([])),
            (
                "pnpFallbackMode".to_owned(),
                Value::String("dependencies-only".to_owned()),
            ),
            ("pnpMode".to_owned(), Value::String("strict".to_owned())),
        ]);
        for (key, relative) in [
            ("cacheFolder", ".yarn/cache"),
            ("pnpUnpluggedFolder", ".yarn/unplugged"),
            ("installStatePath", ".yarn/install-state.gz"),
            ("virtualFolder", ".yarn/__virtual__"),
        ] {
            settings.insert(
                key.to_owned(),
                Value::String(project.join(relative).to_str().unwrap().to_owned()),
            );
        }
        settings
    }

    #[test]
    fn runtime_locators_refuse_direct_transitive_and_encoded_external_references() {
        for value in [
            "portal:../external",
            "link:./local",
            "pkg@portal:/outside",
            "pkg@virtual:peer#link:../outside",
            "pkg@patch:pkg@portal%3A../outside#patch.diff",
            "pkg@patch:pkg@%70%6f%72%74%61%6c%3a../outside#patch.diff",
            "pkg@patch:pkg@link%253A../outside#patch.diff",
        ] {
            assert!(external_runtime_locator(value).unwrap(), "{value}");
        }
        for value in [
            "npm:^1.0.0",
            "workspace:*",
            "file:./vendor/archive.tgz",
            "file:/selected/vendor/archive.tgz::locator=pkg%40workspace%3A.",
            "typescript@patch:typescript@npm%3A5.9.3#builtin<compat/typescript>",
            "https://example.invalid/hyperlink:archive.tgz",
        ] {
            assert!(!external_runtime_locator(value).unwrap(), "{value}");
        }
        let mut deeply_encoded = "portal%3A../outside".to_owned();
        for _ in 0..=MAX_LOCATOR_DECODING_PASSES {
            deeply_encoded = deeply_encoded.replace('%', "%25");
        }
        assert!(external_runtime_locator(&deeply_encoded).is_err());
        let mut budget = 2;
        assert!(verify_runtime_values(&serde_json::json!(["one", "two"]), &mut budget).is_err());
    }

    #[test]
    fn pnp_resolution_policy_keeps_registered_fallback_and_refuses_ambient_issuers() {
        let valid = pnp_settings(Path::new("/owned/project"));
        for fallback in ["none", "dependencies-only", "all"] {
            for mode in ["strict", "loose"] {
                let mut config = valid.clone();
                config.insert(
                    "pnpFallbackMode".to_owned(),
                    Value::String(fallback.to_owned()),
                );
                config.insert("pnpMode".to_owned(), Value::String(mode.to_owned()));
                verify_pnp_resolution_policy(&config).unwrap();
            }
        }
        for ignored in [
            serde_json::json!(["./member/*"]),
            Value::Null,
            Value::Bool(false),
        ] {
            let mut config = valid.clone();
            config.insert("pnpIgnorePatterns".to_owned(), ignored);
            assert!(verify_pnp_resolution_policy(&config).is_err());
        }
        for key in ["pnpIgnorePatterns", "pnpFallbackMode", "pnpMode"] {
            let mut config = valid.clone();
            config.remove(key);
            assert!(verify_pnp_resolution_policy(&config).is_err(), "{key}");
        }
    }

    #[test]
    fn runtime_inputs_check_every_member_dependency_override_and_transitive_lock() {
        let fixture = tempfile::tempdir().unwrap();
        let project = fixture.path();
        std::fs::create_dir_all(project.join("packages/app")).unwrap();
        let sources = vec![
            "package.json".to_owned(),
            "packages/app/package.json".to_owned(),
            "yarn.lock".to_owned(),
        ];
        let config = pnp_settings(project);
        let valid_lock = "__metadata:\n  version: 10\n\
                          'pkg@npm:1.0.0':\n  resolution: 'pkg@npm:1.0.0'\n  linkType: hard\n\
                          '@scope/app@workspace:packages/@scope/app':\n  resolution: '@scope/app@workspace:packages/@scope/app'\n  linkType: soft\n";
        std::fs::write(project.join("yarn.lock"), valid_lock).unwrap();
        for name in &sources[..2] {
            std::fs::write(project.join(name), b"{}").unwrap();
        }
        verify_pnp_runtime_inputs(project, &sources, &config).unwrap();
        for source in &sources[..2] {
            for field in [
                "dependencies",
                "devDependencies",
                "optionalDependencies",
                "peerDependencies",
                "resolutions",
            ] {
                let mut manifest = serde_json::Map::new();
                manifest.insert(
                    field.to_owned(),
                    serde_json::json!({"pkg": "portal:../private-external"}),
                );
                std::fs::write(project.join(source), serde_json::to_vec(&manifest).unwrap())
                    .unwrap();
                let error = verify_pnp_runtime_inputs(project, &sources, &config).unwrap_err();
                assert!(
                    error.to_string().contains("portal/link"),
                    "{source}: {field}"
                );
                assert!(!error.to_string().contains("private-external"));
                std::fs::write(project.join(source), b"{}").unwrap();
            }
        }
        for resolution in [
            "pkg@link:../outside",
            "pkg@patch:pkg@portal%3A../outside#patch.diff",
        ] {
            std::fs::write(
                project.join("yarn.lock"),
                format!("__metadata:\n  version: 10\n'pkg@npm:1.0.0':\n  resolution: '{resolution}'\n  linkType: hard\n"),
            ).unwrap();
            assert!(verify_pnp_runtime_inputs(project, &sources, &config).is_err());
        }
        std::fs::write(
            project.join("yarn.lock"),
            "__metadata:\n  version: 10\n'pkg@custom:outside':\n  resolution: 'pkg@custom:outside'\n  linkType: soft\n",
        ).unwrap();
        assert!(
            verify_pnp_runtime_inputs(project, &sources, &config)
                .unwrap_err()
                .to_string()
                .contains("non-workspace soft links")
        );
        std::fs::write(project.join("yarn.lock"), valid_lock).unwrap();
        for (key, value) in [
            ("defaultProtocol", serde_json::json!("portal:")),
            (
                "packageExtensions",
                serde_json::json!({"pkg@*": {"dependencies": {"other": "link:../outside"}}}),
            ),
        ] {
            let mut changed = config.clone();
            changed.insert(key.to_owned(), value);
            assert!(
                verify_pnp_runtime_inputs(project, &sources, &changed).is_err(),
                "{key}"
            );
        }
        std::fs::write(project.join("packages/app/package.json"), br#"{"dependencies":{"local":"file:./vendor/local","archive":"file:/selected/vendor/package.tgz","sibling":"workspace:*"},"description":"portal: documentation"}"#).unwrap();
        verify_pnp_runtime_inputs(project, &sources, &config).unwrap();
    }

    #[test]
    fn effective_layout_refuses_global_custom_and_prefix_named_outputs() {
        let project = Path::new("/owned/project");
        let valid = pnp_settings(project);
        assert_eq!(layout(project, &valid).unwrap(), DependencyLayout::YarnPnp);
        for key in [
            "cacheFolder",
            "pnpUnpluggedFolder",
            "installStatePath",
            "virtualFolder",
        ] {
            let mut changed = valid.clone();
            changed.insert(
                key.to_owned(),
                Value::String(format!("{}-other", string(&valid, key).unwrap())),
            );
            assert!(layout(project, &changed).is_err(), "{key}");
        }
        let mut global = valid.clone();
        global.insert("enableGlobalCache".to_owned(), Value::Bool(true));
        assert!(layout(project, &global).is_err());
        global.remove("enableGlobalCache");
        assert!(layout(project, &global).is_err());
        global.insert(
            "nodeLinker".to_owned(),
            Value::String("node-modules".to_owned()),
        );
        assert_eq!(
            layout(project, &global).unwrap(),
            DependencyLayout::NodeModules
        );
    }

    #[test]
    fn query_records_require_complete_unique_typed_settings() {
        let record = b"{\"key\":\"nodeLinker\",\"effective\":\"pnp\"}\n";
        assert_eq!(
            string(&settings(record).unwrap(), "nodeLinker").unwrap(),
            "pnp"
        );
        assert_eq!(
            settings(br#"{"key":"pnpEnableEsmLoader","effective":null}"#).unwrap()["pnpEnableEsmLoader"],
            Value::Null
        );
        assert!(settings(&[record.as_slice(), record.as_slice()].concat()).is_err());
        assert!(settings(&record[..record.len() - 3]).is_err());
        assert!(settings(b"{\"key\":\"nodeLinker\"}\n").is_err());
        assert!(
            settings(br#"{"key":"nodeLinker","effective":"pnp","effective":"node-modules"}"#)
                .is_err()
        );
        assert!(layout(Path::new("/project"), &settings(record).unwrap()).is_err());
        assert!(settings(&vec![b' '; MAX_QUERY_BYTES + 1]).is_err());
    }

    #[test]
    fn real_berry_records_allow_only_defined_omitted_values() {
        // Yarn 4.18.1 config --json omits effective for empty MAP values and
        // its unset progress style, while retaining their setting definitions.
        let records = br#"{"key":"nodeLinker","effective":"pnp"}
{"key":"packageExtensions","source":"<default>","description":"Package extensions","type":"MAP","valueDefinition":{"type":"SHAPE","properties":{}}}
{"key":"progressBarStyle","source":"<default>","description":"Progress display style","type":"STRING","defaultText":"Progress style"}
"#;
        let observed = settings(records).unwrap();
        assert_eq!(observed["packageExtensions"], serde_json::json!({}));
        assert_eq!(observed["progressBarStyle"], Value::Null);
        assert_eq!(observed["nodeLinker"], "pnp");
        for malformed in [
            br#"{"key":"packageExtensions","type":"MAP"}"#.as_slice(),
            br#"{"key":"packageExtensions","source":"<default>","description":"Map","type":"MAP","valueDefinition":false}"#,
            br#"{"key":"nodeLinker","source":"<default>","description":"Linker","type":"STRING"}"#,
            br#"{"key":"progressBarStyle","source":"project","description":"Style","type":"STRING","defaultText":"Style"}"#,
            br#"{"type":"warning","data":"private diagnostic"}"#,
        ] {
            assert_eq!(
                settings(malformed).unwrap_err().to_string(),
                "invalid Yarn configuration record"
            );
        }
    }

    #[test]
    fn effective_map_query_preserves_extensions_hidden_by_config_listing() {
        // The ordinary listing serializes even a populated JavaScript Map as
        // {}, whereas config get converts it into a complete JSON object.
        let listing = br#"{"key":"packageExtensions","effective":{},"source":"project","description":"Package extensions","type":"MAP","valueDefinition":{"type":"SHAPE","properties":{}}}"#;
        let mut observed = settings(listing).unwrap();
        assert_eq!(observed["packageExtensions"], serde_json::json!({}));
        let effective = setting_map(
            br#"{"@rch/example@*":{"dependencies":{"@rch/external":"portal:./external"}}}"#,
        )
        .unwrap();
        observed.insert("packageExtensions".to_owned(), effective);
        let mut budget = MAX_RUNTIME_INPUT_VALUES;
        assert!(verify_runtime_values(&observed["packageExtensions"], &mut budget).is_err());
        assert_eq!(setting_map(b"undefined\n").unwrap(), serde_json::json!({}));
        assert_eq!(setting_map(b"{}\n").unwrap(), serde_json::json!({}));
        for malformed in [
            b"".as_slice(),
            b"undefined",
            b"undefined\n{}\n",
            b"null\n",
            b"[]\n",
            b"{}\n{}\n",
            b"private diagnostic",
        ] {
            assert_eq!(
                setting_map(malformed).unwrap_err().to_string(),
                "invalid Yarn configuration map"
            );
        }
    }

    #[test]
    fn only_berry_locks_or_declared_berry_versions_trigger_queries() {
        let fixture = tempfile::tempdir().unwrap();
        let project = fixture.path();
        std::fs::write(project.join("package.json"), b"{}").unwrap();
        std::fs::write(project.join("yarn.lock"), b"# yarn lockfile v1\n").unwrap();
        let sources = vec!["package.json".to_owned(), "yarn.lock".to_owned()];
        assert_eq!(berry_version(project, &sources).unwrap(), None);
        std::fs::write(
            project.join("yarn.lock"),
            b"# generated\n__metadata:\n  version: 8\n",
        )
        .unwrap();
        assert_eq!(berry_version(project, &sources).unwrap(), Some(None));
        std::fs::write(
            project.join("package.json"),
            br#"{"packageManager":"yarn@4.18.1+sha512.abc"}"#,
        )
        .unwrap();
        assert_eq!(
            berry_version(project, &sources).unwrap(),
            Some(Some("4.18.1".to_owned()))
        );
        assert_eq!(
            berry_version(project, &["package.json".to_owned()]).unwrap(),
            None
        );
    }

    #[test]
    fn authored_inputs_include_membership_without_taking_runtime_directories() {
        let fixture = tempfile::tempdir().unwrap();
        let project = fixture.path();
        for directory in ["patches", "plugins", "releases", "cache", "unplugged"] {
            std::fs::create_dir_all(project.join(".yarn").join(directory)).unwrap();
            std::fs::write(
                project.join(".yarn").join(directory).join("entry"),
                directory,
            )
            .unwrap();
        }
        let mut files = BTreeSet::new();
        let mut directories = Vec::new();
        for name in ["patches", "plugins", "releases"] {
            authored_inputs(
                &project.join(".yarn").join(name),
                0,
                &mut files,
                &mut directories,
            )
            .unwrap();
        }
        assert_eq!(files.len(), 3);
        assert_eq!(directories.len(), 3);
        assert!(
            !files
                .iter()
                .any(|path| path.starts_with(project.join(".yarn/cache")))
        );
        assert!(
            !files
                .iter()
                .any(|path| path.starts_with(project.join(".yarn/unplugged")))
        );
        std::fs::write(project.join(".yarn/patches/new.patch"), b"patch").unwrap();
        let mut updated_files = BTreeSet::new();
        let mut updated_directories = Vec::new();
        authored_inputs(
            &project.join(".yarn/patches"),
            0,
            &mut updated_files,
            &mut updated_directories,
        )
        .unwrap();
        assert!(updated_files.contains(&project.join(".yarn/patches/new.patch")));
        assert_eq!(updated_directories[0].1, ["entry", "new.patch"]);
    }

    #[test]
    fn member_invocations_refuse_unobserved_config_and_relocated_environment_files() {
        for name in [".yarnrc.yml", "custom-yarnrc.yml", ".env.yarn", "root-env"] {
            let fixture = tempfile::tempdir().unwrap();
            let project = fixture.path();
            let member = project.join("packages/member");
            std::fs::create_dir_all(&member).unwrap();
            let mut config = pnp_settings(project);
            config.insert(
                "rcFilename".to_owned(),
                Value::String("custom-yarnrc.yml".to_owned()),
            );
            config.insert(
                "injectEnvironmentFiles".to_owned(),
                serde_json::json!([".env.yarn?"]),
            );
            let policy = InvocationPolicy::capture(project, &config).unwrap();
            policy.verify(project, &member).unwrap();
            if name == "root-env" {
                std::fs::write(project.join(".env.yarn"), b"ROOT_ONLY=1\n").unwrap();
            } else {
                std::fs::write(member.join(name), b"member-only configuration\n").unwrap();
            }
            assert!(policy.verify(project, &member).is_err(), "{name}");
            policy.verify(project, project).unwrap();
        }
        let fixture = tempfile::tempdir().unwrap();
        let project = fixture.path();
        let member = project.join("packages/group/member");
        std::fs::create_dir_all(&member).unwrap();
        let policy = InvocationPolicy {
            rc_filename: ".yarnrc.yml".to_owned(),
            relative_environment_files: Vec::new(),
        };
        std::fs::write(
            project.join("packages/.yarnrc.yml"),
            b"intermediate: true\n",
        )
        .unwrap();
        assert!(policy.verify(project, &member).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn standard_pnp_layout_refuses_generated_aliases_and_preserves_selected_files() {
        use std::os::unix::fs::symlink;
        for name in [".yarn", ".yarn/cache", ".yarn/unplugged", ".pnp.cjs"] {
            let fixture = tempfile::tempdir().unwrap();
            let outside = tempfile::tempdir().unwrap();
            let project = fixture.path();
            verify_pnp_output_paths(project).unwrap();
            if name.starts_with(".yarn/") {
                std::fs::create_dir(project.join(".yarn")).unwrap();
            }
            symlink(outside.path(), project.join(name)).unwrap();
            assert!(verify_pnp_output_paths(project).is_err(), "{name}");
        }
        let fixture = tempfile::tempdir().unwrap();
        let project = fixture.path();
        std::fs::create_dir(project.join(".yarn")).unwrap();
        std::fs::write(project.join(".pnp.cjs"), b"selected zero-install loader\n").unwrap();
        verify_pnp_output_paths(project).unwrap();
        assert_eq!(
            std::fs::read(project.join(".pnp.cjs")).unwrap(),
            b"selected zero-install loader\n"
        );
    }
}
