//! Exact source-content manifests and worker-side verification for proof runs.
//!
//! This is deliberately a transfer-boundary proof. The file universe comes
//! from the configured `TransferPipeline`'s own rsync filters, uploads use
//! checksum mode, a no-delta rsync barrier reopens the synchronized tree, and a
//! worker-side verifier re-hashes every selected regular file before Cargo.

use super::dependency_closure::{SyncClosureMode, SyncClosurePlanEntry};
use super::ssh::run_offload_ssh_command_with_stdin;
use super::*;
use serde::Serialize;
use sha2::{Digest as _, Sha256};
use std::fs::File;

const ROOT_SCHEMA: &str = "rch.source_content_root.v1";
const RECEIPT_SCHEMA: &str = "rch.source_content_receipt.v1";
// Large tracked conformance corpora are legitimate source inputs.  The
// FrankenNetworkX dependency currently contributes about 74k selected files,
// so keep a finite one-over boundary without rejecting that authentic tree.
const MAX_SOURCE_CONTENT_FILES: usize = 100_000;
const MAX_SOURCE_CONTENT_BYTES: u64 = 8 * 1024 * 1024 * 1024;
const MAX_REMOTE_MANIFEST_BYTES: usize = 32 * 1024 * 1024;
// The receipt repeats each selected path and SHA-256 for independently synced
// workspace and crate roots.  A 32 MiB cap closes the current ~100k-entry
// dependency closure while remaining equal to the bounded rsync/remote-manifest
// capture budget.
const MAX_SOURCE_CONTENT_RECEIPT_BYTES: usize = 32 * 1024 * 1024;
const REMOTE_VERIFY_TIMEOUT: Duration = Duration::from_secs(180);

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub(super) struct SourceContentFilterPolicy {
    schema: &'static str,
    include_patterns: Option<Vec<String>>,
    exclude_patterns: Vec<String>,
    delete_extraneous: bool,
    checksum_transfer: bool,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub(super) struct SourceContentFile {
    path: String,
    sha256: String,
    byte_count: u64,
    executable: bool,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub(super) struct SourceContentRootManifest {
    schema: &'static str,
    ordinal: usize,
    project_id: String,
    local_root: String,
    remote_root: String,
    root_hash: String,
    is_primary: bool,
    mode: SyncClosureMode,
    filter_policy: SourceContentFilterPolicy,
    file_count: usize,
    byte_count: u64,
    files: Vec<SourceContentFile>,
    content_root: String,
}

#[derive(Debug, Serialize)]
struct SourceContentRootPreimage<'a> {
    schema: &'static str,
    ordinal: usize,
    project_id: &'a str,
    local_root: &'a str,
    remote_root: &'a str,
    root_hash: &'a str,
    is_primary: bool,
    mode: SyncClosureMode,
    filter_policy: &'a SourceContentFilterPolicy,
    file_count: usize,
    byte_count: u64,
    files: &'a [SourceContentFile],
}

#[derive(Clone)]
pub(super) struct PreparedSourceContentRoot {
    pipeline: TransferPipeline,
    manifest: SourceContentRootManifest,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub(super) struct SourceContentReceipt {
    schema: &'static str,
    worker_id: String,
    /// Decimal string because daemon build IDs exceed JavaScript's exact
    /// integer range and receipts are consumed by Node validators.
    build_id: String,
    command_sha256: String,
    command_exit_code: i32,
    root_count: usize,
    roots: Vec<SourceContentRootManifest>,
    receipt_root: String,
}

impl SourceContentReceipt {
    pub(super) fn canonical_json(&self) -> anyhow::Result<String> {
        let bytes = serde_json::to_vec(self)?;
        if bytes.len() > MAX_SOURCE_CONTENT_RECEIPT_BYTES {
            anyhow::bail!(
                "source-content receipt cap exceeded: {} > {}",
                bytes.len(),
                MAX_SOURCE_CONTENT_RECEIPT_BYTES
            );
        }
        String::from_utf8(bytes).context("source-content receipt JSON was not UTF-8")
    }
}

#[derive(Debug, Serialize)]
struct SourceContentReceiptPreimage<'a> {
    schema: &'static str,
    worker_id: &'a str,
    build_id: &'a str,
    command_sha256: &'a str,
    command_exit_code: i32,
    root_count: usize,
    roots: &'a [SourceContentRootManifest],
}

fn sha256_hex(bytes: &[u8]) -> String {
    hex_lower(&Sha256::digest(bytes))
}

fn hex_lower(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        encoded.push(char::from(DIGITS[usize::from(byte >> 4)]));
        encoded.push(char::from(DIGITS[usize::from(byte & 0x0f)]));
    }
    encoded
}

fn hash_file(path: &Path) -> anyhow::Result<(String, u64, bool)> {
    let metadata = std::fs::symlink_metadata(path)
        .with_context(|| format!("stat source-content file {}", path.display()))?;
    if !metadata.file_type().is_file() || metadata.file_type().is_symlink() {
        anyhow::bail!(
            "source-content proof requires a regular non-symlink file: {}",
            path.display()
        );
    }
    let byte_count = metadata.len();
    let mut file =
        File::open(path).with_context(|| format!("open source-content file {}", path.display()))?;
    let mut hasher = Sha256::new();
    let mut buffer = [0_u8; 1024 * 1024];
    loop {
        let read = std::io::Read::read(&mut file, &mut buffer)
            .with_context(|| format!("read source-content file {}", path.display()))?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    #[cfg(unix)]
    let executable = std::os::unix::fs::PermissionsExt::mode(&metadata.permissions()) & 0o111 != 0;
    #[cfg(not(unix))]
    let executable = false;
    Ok((hex_lower(&hasher.finalize()), byte_count, executable))
}

fn canonical_root_path(path: &Path) -> anyhow::Result<String> {
    let canonical = path
        .canonicalize()
        .with_context(|| format!("canonicalize source-content root {}", path.display()))?;
    let value = canonical
        .to_str()
        .ok_or_else(|| anyhow::anyhow!("source-content root is not UTF-8: {}", path.display()))?;
    if value.chars().any(char::is_control) {
        anyhow::bail!("source-content root contains control characters");
    }
    Ok(value.to_string())
}

async fn capture_manifest(
    ordinal: usize,
    entry: &SyncClosurePlanEntry,
    pipeline: &TransferPipeline,
) -> anyhow::Result<SourceContentRootManifest> {
    let paths = pipeline.enumerate_source_content_files().await?;
    if paths.is_empty() {
        anyhow::bail!(
            "source-content transfer universe is empty for {}",
            entry.local_root.display()
        );
    }
    if paths.len() > MAX_SOURCE_CONTENT_FILES {
        anyhow::bail!(
            "source-content file cap exceeded for {}: {} > {}",
            entry.local_root.display(),
            paths.len(),
            MAX_SOURCE_CONTENT_FILES
        );
    }

    let local_root = canonical_root_path(&entry.local_root)?;
    let hash_root = PathBuf::from(&local_root);
    let files = tokio::task::spawn_blocking(move || {
        let mut files = Vec::with_capacity(paths.len());
        let mut total_bytes = 0_u64;
        for relative in paths {
            let path = relative.to_str().ok_or_else(|| {
                anyhow::anyhow!("source-content relative path is not UTF-8: {relative:?}")
            })?;
            if path.chars().any(char::is_control) {
                anyhow::bail!("source-content relative path contains control characters");
            }
            let (sha256, byte_count, executable) = hash_file(&hash_root.join(&relative))?;
            total_bytes = total_bytes
                .checked_add(byte_count)
                .ok_or_else(|| anyhow::anyhow!("source-content byte count overflow"))?;
            if total_bytes > MAX_SOURCE_CONTENT_BYTES {
                anyhow::bail!(
                    "source-content byte cap exceeded: {} > {}",
                    total_bytes,
                    MAX_SOURCE_CONTENT_BYTES
                );
            }
            files.push(SourceContentFile {
                path: path.to_string(),
                sha256,
                byte_count,
                executable,
            });
        }
        Ok::<_, anyhow::Error>((files, total_bytes))
    })
    .await
    .context("join source-content hashing task")??;
    let (files, byte_count) = files;

    let (include_patterns, exclude_patterns, delete_extraneous, checksum_transfer) =
        pipeline.source_content_filter_policy();
    if !checksum_transfer {
        anyhow::bail!("source-content proof requires checksum transfer mode");
    }
    let filter_policy = SourceContentFilterPolicy {
        schema: "rch.source_content_filter.v1",
        include_patterns,
        exclude_patterns,
        delete_extraneous,
        checksum_transfer,
    };
    let preimage = SourceContentRootPreimage {
        schema: ROOT_SCHEMA,
        ordinal,
        project_id: &entry.project_id,
        local_root: &local_root,
        remote_root: &entry.remote_root,
        root_hash: &entry.root_hash,
        is_primary: entry.is_primary,
        mode: entry.mode,
        filter_policy: &filter_policy,
        file_count: files.len(),
        byte_count,
        files: &files,
    };
    let content_root = sha256_hex(&serde_json::to_vec(&preimage)?);
    Ok(SourceContentRootManifest {
        schema: ROOT_SCHEMA,
        ordinal,
        project_id: entry.project_id.clone(),
        local_root,
        remote_root: entry.remote_root.clone(),
        root_hash: entry.root_hash.clone(),
        is_primary: entry.is_primary,
        mode: entry.mode,
        filter_policy,
        file_count: files.len(),
        byte_count,
        files,
        content_root,
    })
}

pub(super) async fn prepare_source_content_root(
    ordinal: usize,
    entry: &SyncClosurePlanEntry,
    pipeline: &TransferPipeline,
) -> anyhow::Result<PreparedSourceContentRoot> {
    Ok(PreparedSourceContentRoot {
        pipeline: pipeline.clone(),
        manifest: capture_manifest(ordinal, entry, pipeline).await?,
    })
}

/// Stable selected bytes and policy for the predecessor-only timestamp ledger.
/// Receipt ordinals and Git/root provenance can change without changing bytes.
pub(super) fn owned_source_content_freshness_identity(
    prepared: &[PreparedSourceContentRoot],
) -> anyhow::Result<String> {
    anyhow::ensure!(
        !prepared.is_empty(),
        "owned source closure has no captured roots"
    );
    let mut roots: Vec<_> = prepared.iter().map(|root| &root.manifest).collect();
    roots.sort_by(|left, right| {
        (&left.remote_root, &left.local_root).cmp(&(&right.remote_root, &right.local_root))
    });
    fn field(hasher: &mut Sha256, value: &[u8]) {
        hasher.update((value.len() as u64).to_le_bytes());
        hasher.update(value);
    }
    let mut hasher = Sha256::new();
    hasher.update(b"rch.owned_source_content_freshness.v1\0");
    for root in roots {
        field(
            &mut hasher,
            &serde_json::to_vec(&(
                &root.local_root,
                &root.remote_root,
                root.is_primary,
                root.mode,
                &root.filter_policy,
            ))?,
        );
        let mut files: Vec<_> = root.files.iter().collect();
        files.sort_by(|left, right| left.path.cmp(&right.path));
        for file in files {
            field(&mut hasher, &serde_json::to_vec(file)?);
        }
    }
    Ok(hex_lower(&hasher.finalize()))
}

/// Validate Cargo against the exact captured transfer universe, then map its
/// actual manifest selector into the owned closure. Only captured metadata
/// paths are read, and their bytes must still match the captured hashes.
pub(super) fn validate_owned_source_content_closure(
    prepared: &[PreparedSourceContentRoot],
    source_root: &str,
    local_build_dir: &Path,
    selected_manifest_root: Option<&Path>,
    command: &str,
    topology_policy: &PathTopologyPolicy,
) -> anyhow::Result<String> {
    use rch_common::cargo_path_deps::{
        SelectedCargoEntry, validate_selected_cargo_config_at, validate_selected_cargo_path,
        validate_selected_cargo_tree_at,
    };
    use std::collections::BTreeMap;
    use std::io::Read as _;

    let container = Path::new(source_root);
    anyhow::ensure!(
        container.is_absolute()
            && !source_root.chars().any(char::is_control)
            && !source_root.contains('\\')
            && !source_root
                .split('/')
                .any(|part| part == "." || part == ".."),
        "invalid owned source container"
    );
    let normalize = |path: &Path| -> anyhow::Result<PathBuf> {
        Ok(normalize_project_path_with_policy(path, topology_policy)
            .with_context(|| format!("normalize selected Cargo path {}", path.display()))?
            .canonical_path()
            .to_path_buf())
    };
    let cwd = normalize(local_build_dir)?;
    let mut entries = BTreeMap::new();
    let mut local_files = BTreeMap::new();
    let mut primary_directory = None;
    let mut metadata_bytes = 0_u64;
    for root in prepared {
        let manifest = &root.manifest;
        let local_root = Path::new(&manifest.local_root);
        anyhow::ensure!(
            normalize(local_root)? == local_root,
            "captured source root changed its physical topology"
        );
        let projection = Path::new(&manifest.remote_root)
            .strip_prefix(container)
            .context("captured source root is outside its owned container")?;
        anyhow::ensure!(
            !projection.as_os_str().is_empty()
                && projection
                    .components()
                    .all(|part| matches!(part, std::path::Component::Normal(_))),
            "captured source root is not a strict literal descendant of its container"
        );
        if manifest.is_primary {
            anyhow::ensure!(
                primary_directory.is_none()
                    && manifest.mode == SyncClosureMode::Full
                    && local_root == cwd,
                "owned closure must have one full primary matching Cargo's invocation directory"
            );
            primary_directory = Some(projection.to_path_buf());
        }
        for file in &manifest.files {
            let relative = Path::new(&file.path);
            anyhow::ensure!(
                !file.path.is_empty()
                    && !file.path.chars().any(char::is_control)
                    && !file.path.contains('\\')
                    && relative
                        .components()
                        .all(|part| matches!(part, std::path::Component::Normal(_))),
                "captured source file has an invalid relative path"
            );
            let local = local_root.join(relative);
            let selected = projection.join(relative);
            let contents = if is_selected_cargo_metadata(relative) {
                metadata_bytes = metadata_bytes
                    .checked_add(file.byte_count)
                    .filter(|total| *total <= MAX_REMOTE_MANIFEST_BYTES as u64)
                    .ok_or_else(|| anyhow::anyhow!("selected Cargo metadata byte cap exceeded"))?;
                let metadata = std::fs::symlink_metadata(&local)
                    .with_context(|| format!("stat captured Cargo metadata {}", local.display()))?;
                anyhow::ensure!(
                    metadata.is_file()
                        && !metadata.file_type().is_symlink()
                        && local.canonicalize()? == local,
                    "captured Cargo metadata is no longer a regular literal path: {}",
                    local.display()
                );
                let mut bytes = Vec::new();
                File::open(&local)?
                    .take(file.byte_count + 1)
                    .read_to_end(&mut bytes)?;
                anyhow::ensure!(
                    bytes.len() as u64 == file.byte_count && sha256_hex(&bytes) == file.sha256,
                    "captured Cargo metadata changed: {}",
                    local.display()
                );
                Some(String::from_utf8(bytes).with_context(|| {
                    format!("captured Cargo metadata is not UTF-8: {}", local.display())
                })?)
            } else {
                None
            };
            anyhow::ensure!(
                entries
                    .insert(selected.clone(), SelectedCargoEntry::File(contents))
                    .is_none()
                    && local_files.insert(local, selected).is_none(),
                "owned source closure has overlapping captured files"
            );
        }
    }
    let primary_directory = primary_directory.ok_or_else(|| {
        anyhow::anyhow!("owned source closure has no primary invocation directory")
    })?;
    let selected_local_manifest = normalize(
        &selected_manifest_root
            .unwrap_or(local_build_dir)
            .join("Cargo.toml"),
    )?;
    let selected_manifest = local_files.get(&selected_local_manifest).ok_or_else(|| {
        anyhow::anyhow!("Cargo entrypoint is not present in the captured source closure")
    })?;
    validate_selected_cargo_tree_at(&entries, selected_manifest)?;

    // Brace expansion and comments also change meaning when shell words are
    // joined. The shared parser rejects other nonliteral shell constructs.
    let mut quote = None;
    let mut escaped = false;
    for ch in command.chars() {
        if escaped {
            escaped = false;
        } else if ch == '\\' && quote != Some('\'') {
            escaped = true;
        } else if quote == Some(ch) {
            quote = None;
        } else if quote.is_none() && matches!(ch, '\'' | '"') {
            quote = Some(ch);
        } else if quote.is_none() && matches!(ch, '{' | '}' | '#') {
            anyhow::bail!("owned Cargo command requires literal shell arguments");
        }
    }
    let (mut tokens, cargo_index) = cargo_target_dir::managed_clean_overlay_cargo_tokens(command)?;
    anyhow::ensure!(
        !tokens[..cargo_index].iter().any(|token| {
            matches!(token.as_str(), "-C" | "--chdir") || token.starts_with("--chdir=")
        }),
        "owned Cargo source validation does not support wrapper chdir"
    );
    anyhow::ensure!(
        !tokens[..cargo_index].iter().any(|token| {
            token
                .split_once('=')
                .is_some_and(|(name, _)| matches!(name, "CARGO_TARGET_DIR" | "CARGO_HOME"))
        }),
        "owned Cargo command cannot override its managed target or Cargo home"
    );
    let mut manifest_count = 0;
    let mut index = cargo_index + 1;
    while index < tokens.len() {
        let token = tokens[index].clone();
        if token == "--" {
            break;
        }
        anyhow::ensure!(
            !token.starts_with("-C"),
            "owned Cargo source validation does not support Cargo -C"
        );
        let (name, inline) = token
            .split_once('=')
            .map_or((token.as_str(), None), |(name, value)| (name, Some(value)));
        anyhow::ensure!(
            !matches!(
                name,
                "--target-dir" | "--build-dir" | "--artifact-dir" | "--out-dir" | "--lockfile-path"
            ),
            "owned Cargo command cannot select an unmanaged output path: {name}"
        );
        let takes_value = matches!(
            name,
            "--manifest-path"
                | "--config"
                | "--target"
                | "--profile"
                | "--package"
                | "-p"
                | "--exclude"
                | "--features"
                | "-F"
                | "--bin"
                | "--example"
                | "--test"
                | "--bench"
                | "--color"
                | "--message-format"
                | "--jobs"
                | "-j"
                | "-Z"
        );
        if takes_value {
            let value_index = if inline.is_some() { index } else { index + 1 };
            let value = inline
                .map(str::to_owned)
                .or_else(|| tokens.get(value_index).cloned())
                .ok_or_else(|| anyhow::anyhow!("missing owned Cargo option value for {name}"))?;
            anyhow::ensure!(
                !value.is_empty() && value != "--",
                "missing owned Cargo option value for {name}"
            );
            if name == "--manifest-path" {
                manifest_count += 1;
                anyhow::ensure!(
                    manifest_count == 1,
                    "multiple owned Cargo manifest selectors are unsupported"
                );
                let actual = normalize(&cwd.join(&value))?;
                anyhow::ensure!(
                    actual == selected_local_manifest,
                    "Cargo manifest selector differs from the planned entrypoint"
                );
                let selected = validate_selected_cargo_path(&entries, selected_manifest)?;
                let mapped = container
                    .join(selected)
                    .to_str()
                    .ok_or_else(|| anyhow::anyhow!("mapped Cargo manifest is not UTF-8"))?
                    .to_owned();
                tokens[value_index] = if inline.is_some() {
                    format!("--manifest-path={mapped}")
                } else {
                    mapped
                };
            } else if name == "--config" {
                let _: toml::Table = toml::from_str(&value).context(
                    "owned Cargo supports inline TOML --config only; config files require a selected mapping",
                )?;
                validate_selected_cargo_config_at(
                    &entries,
                    selected_manifest,
                    &primary_directory,
                    &value,
                )?;
            } else if name == "--target" {
                anyhow::ensure!(
                    !value.contains('/') && !value.contains('\\') && !value.ends_with(".json"),
                    "owned Cargo target specifications require a selected file mapping"
                );
            }
            index = value_index + 1;
            continue;
        }
        if token.starts_with('-') {
            anyhow::ensure!(
                matches!(
                    token.as_str(),
                    "--lib"
                        | "--bins"
                        | "--examples"
                        | "--tests"
                        | "--benches"
                        | "--all-targets"
                        | "--all-features"
                        | "--no-default-features"
                        | "--workspace"
                        | "--all"
                        | "--release"
                        | "-r"
                        | "--frozen"
                        | "--locked"
                        | "--offline"
                        | "--verbose"
                        | "-v"
                        | "-vv"
                        | "--quiet"
                        | "-q"
                        | "--keep-going"
                        | "--future-incompat-report"
                        | "--timings"
                        | "--no-run"
                        | "--no-fail-fast"
                        | "--doc"
                        | "--open"
                        | "--no-deps"
                        | "--document-private-items"
                        | "--dry-run"
                        | "--allow-dirty"
                        | "--no-metadata"
                        | "--list"
                ) || ["-j", "-p", "-F", "-Z"]
                    .iter()
                    .any(|prefix| { token.starts_with(*prefix) && token.len() > prefix.len() }),
                "unsupported owned Cargo option: {token}"
            );
        }
        index += 1;
    }
    anyhow::ensure!(
        (manifest_count == 1) == selected_manifest_root.is_some(),
        "Cargo manifest selection changed since closure planning"
    );
    Ok(join_exec_command(&tokens))
}

/// Check configuration after command prefixes establish Cargo's environment.
/// Selected workspace ancestor configs retain Cargo's usual search rules; home
/// and unrelated ancestor configs remain outside this source receipt.
pub(super) fn guard_owned_source_content_cargo_config(
    command: &str,
    prepared: &[PreparedSourceContentRoot],
) -> anyhow::Result<String> {
    let (mut tokens, cargo_index) = cargo_target_dir::managed_clean_overlay_cargo_tokens(command)?;
    let mut allowed = std::collections::BTreeSet::new();
    for root in prepared {
        for file in &root.manifest.files {
            let path = Path::new(&file.path);
            if path
                .parent()
                .and_then(Path::file_name)
                .is_some_and(|name| name == ".cargo")
                && path
                    .file_name()
                    .is_some_and(|name| name == "config" || name == "config.toml")
            {
                allowed.insert(Path::new(&root.manifest.remote_root).join(path));
            }
        }
    }
    let allowed = allowed
        .into_iter()
        .map(|path| {
            path.to_str()
                .map(|value| shell_escape::escape(value.into()).into_owned())
                .ok_or_else(|| anyhow::anyhow!("captured Cargo config path is not UTF-8"))
        })
        .collect::<anyhow::Result<Vec<_>>>()?;
    // The walk below sees physical directories (`pwd -P`, as Cargo does), so
    // compare against the captured paths' physical spelling: a remote root
    // reached through a symlink (macOS /tmp and /var) must not refuse them.
    let resolve = if allowed.is_empty() {
        String::new()
    } else {
        format!(
            r#"for rch_config_path in {}; do
    rch_config_dir=$(CDPATH= cd -P -- "${{rch_config_path%/*}}" 2>/dev/null && pwd -P) || continue
    rch_config_allowed="$rch_config_allowed$rch_config_dir/${{rch_config_path##*/}}
"
done
"#,
            allowed.join(" ")
        )
    };
    let guard = format!(
        r#"rch_config_refuse() {{
    printf '%s\n' 'RCH-E413 owned source closure has unselected Cargo configuration' >&2
    exit 113
}}
rch_config_allowed='
'
{resolve}rch_config_selected() {{
    case "$rch_config_allowed" in
        *"
$1
"*) return 0 ;;
        *) return 1 ;;
    esac
}}
case "${{CARGO_HOME-}}" in /*) ;; *) rch_config_refuse ;; esac
[ -d "$CARGO_HOME" ] && [ -r "$CARGO_HOME" ] && [ -x "$CARGO_HOME" ] || rch_config_refuse
/bin/ls -a "$CARGO_HOME" >/dev/null 2>&1 || rch_config_refuse
for rch_config_name in config config.toml; do
    if [ -e "$CARGO_HOME/$rch_config_name" ] || [ -L "$CARGO_HOME/$rch_config_name" ]; then
        rch_config_refuse
    fi
done
rch_config_parent=$(pwd -P) || rch_config_refuse
while :; do
    [ -d "$rch_config_parent" ] && [ -r "$rch_config_parent" ] && [ -x "$rch_config_parent" ] || rch_config_refuse
    /bin/ls -a "$rch_config_parent" >/dev/null 2>&1 || rch_config_refuse
    if [ -e "$rch_config_parent/.cargo" ] || [ -L "$rch_config_parent/.cargo" ]; then
        [ -d "$rch_config_parent/.cargo" ] && [ ! -L "$rch_config_parent/.cargo" ] && [ -r "$rch_config_parent/.cargo" ] && [ -x "$rch_config_parent/.cargo" ] || rch_config_refuse
        /bin/ls -a "$rch_config_parent/.cargo" >/dev/null 2>&1 || rch_config_refuse
        for rch_config_name in config config.toml; do
            rch_config_path="$rch_config_parent/.cargo/$rch_config_name"
            if [ -e "$rch_config_path" ] || [ -L "$rch_config_path" ]; then
                [ -f "$rch_config_path" ] && [ ! -L "$rch_config_path" ] && rch_config_selected "$rch_config_path" || rch_config_refuse
            fi
        done
    fi
    [ "$rch_config_parent" != / ] || break
    rch_config_parent=${{rch_config_parent%/*}}
    [ -n "$rch_config_parent" ] || rch_config_parent=/
done
exec "$@""#
    );
    tokens.splice(
        cargo_index..cargo_index,
        [
            "/bin/sh".to_owned(),
            "-c".to_owned(),
            guard,
            "rch-owned-source-config".to_owned(),
        ],
    );
    Ok(join_exec_command(&tokens))
}

fn remote_manifest_payload(manifest: &SourceContentRootManifest) -> anyhow::Result<Vec<u8>> {
    let mut payload = Vec::new();
    for file in &manifest.files {
        if file.path.chars().any(|ch| matches!(ch, '\t' | '\n' | '\r')) {
            anyhow::bail!("unsafe source-content manifest path: {:?}", file.path);
        }
        use std::io::Write as _;
        writeln!(
            payload,
            "{}\t{}\t{}\t{}",
            file.sha256,
            file.byte_count,
            u8::from(file.executable),
            file.path
        )?;
        if payload.len() > MAX_REMOTE_MANIFEST_BYTES {
            anyhow::bail!(
                "source-content remote manifest cap exceeded: {} > {}",
                payload.len(),
                MAX_REMOTE_MANIFEST_BYTES
            );
        }
    }
    Ok(payload)
}

// The portable shell verifier forks several utilities for every file. Large
// admitted source trees can exhaust the verification deadline before Cargo
// starts. When available, an isolated Python process streams the same bytes
// and checks the same hash, length, type, executable bit and total denominator.
// A failed Python verification never falls back to another verifier.
const REMOTE_VERIFY_PYTHON: &str = r#"
import hashlib
import os
import stat
import sys

def refuse(code, reason, relative=""):
    if isinstance(relative, bytes):
        relative = relative.decode("utf-8", errors="backslashreplace")
    suffix = ":" + relative if relative else ""
    sys.stderr.write("RCH_SOURCE_CONTENT_ERROR:" + reason + suffix + "\n")
    raise SystemExit(code)

root, expected_count, expected_total = sys.argv[1:]
root = os.fsencode(root)
count = 0
total = 0
try:
    for line in sys.stdin.buffer:
        if not line.endswith(b"\n"):
            refuse(67, "count")
        expected_hash, expected_bytes, expected_exec, relative = line[:-1].split(b"\t", 3)
        relative.decode("utf-8")
        if not relative:
            refuse(62, "empty_path")
        file = root + b"/" + relative
        try:
            metadata = os.lstat(file)
        except OSError:
            refuse(63, "not_regular", relative)
        if not stat.S_ISREG(metadata.st_mode):
            refuse(63, "not_regular", relative)
        hasher = hashlib.sha256()
        actual_bytes = 0
        with open(file, "rb") as source:
            while True:
                chunk = source.read(1024 * 1024)
                if not chunk:
                    break
                actual_bytes += len(chunk)
                hasher.update(chunk)
        if str(actual_bytes).encode("ascii") != expected_bytes:
            refuse(64, "size", relative)
        if hasher.hexdigest().encode("ascii") != expected_hash:
            refuse(65, "sha256", relative)
        actual_exec = b"1" if os.access(file, os.X_OK, effective_ids=True) else b"0"
        if actual_exec != expected_exec:
            refuse(66, "mode", relative)
        count += 1
        total += actual_bytes
    if str(count) != expected_count:
        refuse(67, "count", str(count))
    if str(total) != expected_total:
        refuse(68, "bytes", str(total))
except (OSError, UnicodeError, ValueError, NotImplementedError) as error:
    refuse(69, "read_or_manifest_" + type(error).__name__)
sys.stdout.write("RCH_SOURCE_CONTENT_VERIFIED\t" + str(count) + "\t" + str(total) + "\n")
"#;

fn remote_verify_command(manifest: &SourceContentRootManifest) -> String {
    let root = shell_escape::escape(manifest.remote_root.clone().into());
    let python = shell_escape::escape(REMOTE_VERIFY_PYTHON.into());
    format!(
        "set -eu; root={root}; tab=$(printf '\\t'); count=0; total=0; \
         if command -v python3 >/dev/null 2>&1; then exec python3 -I -c {python} \"$root\" {file_count} {byte_count}; fi; \
         if command -v sha256sum >/dev/null 2>&1; then hash_file() {{ sha256sum -- \"$1\" | awk '{{print $1}}'; }}; \
         elif command -v shasum >/dev/null 2>&1; then hash_file() {{ shasum -a 256 -- \"$1\" | awk '{{print $1}}'; }}; \
         else printf 'RCH_SOURCE_CONTENT_ERROR:sha256_tool_missing\\n' >&2; exit 61; fi; \
         while IFS=\"$tab\" read -r expected_hash expected_bytes expected_exec relative; do \
           [ -n \"$relative\" ] || {{ printf 'RCH_SOURCE_CONTENT_ERROR:empty_path\\n' >&2; exit 62; }}; \
           file=\"$root/$relative\"; \
           [ -f \"$file\" ] && [ ! -L \"$file\" ] || {{ printf 'RCH_SOURCE_CONTENT_ERROR:not_regular:%s\\n' \"$relative\" >&2; exit 63; }}; \
           actual_bytes=$(wc -c < \"$file\" | tr -d '[:space:]'); \
           [ \"$actual_bytes\" = \"$expected_bytes\" ] || {{ printf 'RCH_SOURCE_CONTENT_ERROR:size:%s\\n' \"$relative\" >&2; exit 64; }}; \
           actual_hash=$(hash_file \"$file\"); \
           [ \"$actual_hash\" = \"$expected_hash\" ] || {{ printf 'RCH_SOURCE_CONTENT_ERROR:sha256:%s\\n' \"$relative\" >&2; exit 65; }}; \
           actual_exec=0; [ -x \"$file\" ] && actual_exec=1; \
           [ \"$actual_exec\" = \"$expected_exec\" ] || {{ printf 'RCH_SOURCE_CONTENT_ERROR:mode:%s\\n' \"$relative\" >&2; exit 66; }}; \
           count=$((count + 1)); total=$((total + actual_bytes)); \
         done; \
         [ \"$count\" -eq {file_count} ] || {{ printf 'RCH_SOURCE_CONTENT_ERROR:count:%s\\n' \"$count\" >&2; exit 67; }}; \
         [ \"$total\" -eq {byte_count} ] || {{ printf 'RCH_SOURCE_CONTENT_ERROR:bytes:%s\\n' \"$total\" >&2; exit 68; }}; \
         printf 'RCH_SOURCE_CONTENT_VERIFIED\\t%s\\t%s\\n' \"$count\" \"$total\"",
        file_count = manifest.file_count,
        byte_count = manifest.byte_count,
    )
}

async fn verify_remote_root(
    worker: &WorkerConfig,
    root: &PreparedSourceContentRoot,
    source_identity: Option<&str>,
    owned_timestamps: Option<bool>,
) -> anyhow::Result<()> {
    if let Some(managed_timestamps) = owned_timestamps {
        root.pipeline
            .verify_owned_source_content_rsync_barrier(worker, managed_timestamps)
            .await?;
    } else {
        root.pipeline
            .verify_source_content_rsync_barrier(worker)
            .await?;
    }
    let payload = remote_manifest_payload(&root.manifest)?;
    let command = remote_verify_command(&root.manifest);
    let command = match source_identity {
        Some(identity) => super::ssh::wrap_remote_source_activity(&command, identity)?,
        None => command,
    };
    let output =
        run_offload_ssh_command_with_stdin(worker, &command, &payload, REMOTE_VERIFY_TIMEOUT)
            .await?;
    if !output.status.success() {
        anyhow::bail!(
            "remote source-content verification failed on {} for {} (exit {:?}): {}",
            worker.id,
            root.manifest.project_id,
            output.status.code(),
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    if !output.stderr.is_empty() {
        anyhow::bail!(
            "remote source-content verification produced stderr on {} for {}: {}",
            worker.id,
            root.manifest.project_id,
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    let expected = format!(
        "RCH_SOURCE_CONTENT_VERIFIED\t{}\t{}\n",
        root.manifest.file_count, root.manifest.byte_count
    );
    if output.stdout != expected.as_bytes() {
        anyhow::bail!(
            "remote source-content verification envelope mismatch on {} for {}: {:?}",
            worker.id,
            root.manifest.project_id,
            String::from_utf8_lossy(&output.stdout)
        );
    }
    Ok(())
}

pub(super) async fn verify_source_content_roots(
    worker: &WorkerConfig,
    prepared: &[PreparedSourceContentRoot],
    source_identity: Option<&str>,
) -> anyhow::Result<()> {
    verify_source_content_roots_with_policy(worker, prepared, source_identity, None).await
}

/// Owned materializations always reject surplus selected files. Only the
/// post-ledger pass ignores mtimes; checksum, type, permissions, file universe,
/// remote SHA-256, and local recapture retain their full verification.
pub(super) async fn verify_owned_source_content_roots(
    worker: &WorkerConfig,
    prepared: &[PreparedSourceContentRoot],
    source_identity: Option<&str>,
    managed_timestamps: bool,
) -> anyhow::Result<()> {
    verify_source_content_roots_with_policy(
        worker,
        prepared,
        source_identity,
        Some(managed_timestamps),
    )
    .await
}

async fn verify_source_content_roots_with_policy(
    worker: &WorkerConfig,
    prepared: &[PreparedSourceContentRoot],
    source_identity: Option<&str>,
    owned_timestamps: Option<bool>,
) -> anyhow::Result<()> {
    if prepared.is_empty() {
        anyhow::bail!("source-content proof has no synchronized roots");
    }
    for root in prepared {
        verify_remote_root(worker, root, source_identity, owned_timestamps).await?;
    }

    // Re-enumerate and re-hash after every remote verification. A lasting local
    // edit, added file, deletion, mode change, or filter drift therefore refuses
    // the receipt. The caller's recursive watcher supplies ABA/overflow proof.
    for root in prepared {
        let recaptured = capture_manifest(
            root.manifest.ordinal,
            &SyncClosurePlanEntry {
                local_root: PathBuf::from(&root.manifest.local_root),
                remote_root: root.manifest.remote_root.clone(),
                project_id: root.manifest.project_id.clone(),
                root_hash: root.manifest.root_hash.clone(),
                is_primary: root.manifest.is_primary,
                mode: root.manifest.mode,
            },
            &root.pipeline,
        )
        .await?;
        if recaptured != root.manifest {
            anyhow::bail!(
                "local source-content changed during transfer proof for {}",
                root.manifest.project_id
            );
        }
    }
    Ok(())
}

pub(super) async fn finalize_source_content_receipt(
    worker: &WorkerConfig,
    build_id: u64,
    command: &str,
    command_exit_code: i32,
    prepared: &[PreparedSourceContentRoot],
    source_identity: Option<&str>,
) -> anyhow::Result<SourceContentReceipt> {
    verify_source_content_roots(worker, prepared, source_identity).await?;
    source_content_receipt_for_verified_roots(
        worker,
        build_id,
        command,
        command_exit_code,
        prepared,
    )
}

pub(super) async fn finalize_owned_source_content_receipt(
    worker: &WorkerConfig,
    build_id: u64,
    command: &str,
    command_exit_code: i32,
    prepared: &[PreparedSourceContentRoot],
    source_identity: Option<&str>,
) -> anyhow::Result<SourceContentReceipt> {
    verify_owned_source_content_roots(worker, prepared, source_identity, true).await?;
    source_content_receipt_for_verified_roots(
        worker,
        build_id,
        command,
        command_exit_code,
        prepared,
    )
}

fn source_content_receipt_for_verified_roots(
    worker: &WorkerConfig,
    build_id: u64,
    command: &str,
    command_exit_code: i32,
    prepared: &[PreparedSourceContentRoot],
) -> anyhow::Result<SourceContentReceipt> {
    let roots = prepared
        .iter()
        .map(|root| root.manifest.clone())
        .collect::<Vec<_>>();
    let command_sha256 = sha256_hex(command.as_bytes());
    let build_id = build_id.to_string();
    let preimage = SourceContentReceiptPreimage {
        schema: RECEIPT_SCHEMA,
        worker_id: worker.id.as_str(),
        build_id: &build_id,
        command_sha256: &command_sha256,
        command_exit_code,
        root_count: roots.len(),
        roots: &roots,
    };
    let receipt_root = sha256_hex(&serde_json::to_vec(&preimage)?);
    Ok(SourceContentReceipt {
        schema: RECEIPT_SCHEMA,
        worker_id: worker.id.as_str().to_string(),
        build_id,
        command_sha256,
        command_exit_code,
        root_count: roots.len(),
        roots,
        receipt_root,
    })
}

fn stamp_commit_hash(value: &str) -> bool {
    (7..=64).contains(&value.len()) && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

pub(super) fn build_source_commit_env<F>(mut lookup: F) -> std::collections::HashMap<String, String>
where
    F: FnMut(&str) -> Option<String>,
{
    rch_common::BUILD_COMMIT_ENV_VARS
        .iter()
        .filter_map(|&key| lookup(key).map(|value| (key.to_owned(), value)))
        .collect()
}

/// Remove inherited worker aliases before restoring the caller's environment.
/// Unset and empty are different to Cargo's `[env]` defaults: absent aliases
/// must stay unset so selected configuration can supply an explicit revision.
/// Present values are preserved exactly, even if empty or invalid as a commit;
/// their presence suppresses Cargo defaults just as it does locally. The build
/// script owns revision validation after Cargo resolves its environment.
/// Caller command prefixes run inside this boundary, preserving `env -i` and
/// `env -u` as well as inline assignments without changing shell evaluation.
pub(super) fn bind_build_source_aliases(
    command: &str,
    aliases: &std::collections::HashMap<String, String>,
) -> String {
    let mut prefix = String::from("env");
    for key in rch_common::BUILD_COMMIT_ENV_VARS {
        prefix.push_str(" -u ");
        prefix.push_str(key);
    }
    for key in rch_common::BUILD_COMMIT_ENV_VARS {
        if let Some(value) = aliases.get(*key) {
            prefix.push(' ');
            prefix.push_str(key);
            prefix.push('=');
            prefix.push_str(&shell_words::quote(value));
        }
    }
    format!("{prefix} sh -c {}", shell_words::quote(command))
}

async fn build_source_git_output(root: &Path, args: &[&str]) -> Option<Vec<u8>> {
    let mut command = Command::new("git");
    configure_clean_git_command(&mut command);
    command
        .arg("--no-optional-locks")
        .args(["-c", "core.fsmonitor=false"])
        .current_dir(root)
        .args(args)
        .stdin(Stdio::null())
        .kill_on_drop(true);
    let output = timeout(Duration::from_secs(5), command.output())
        .await
        .ok()?
        .ok()?;
    output.status.success().then_some(output.stdout)
}

fn clean_overlay_build_source_stamp(spec: &CleanOverlaySpec) -> String {
    if spec.is_base_only() && spec.dependencies.is_empty() {
        return spec.base_commit().to_owned();
    }
    if spec.dependencies.is_empty() {
        return format!(
            "{}-overlay-{}",
            spec.base_commit(),
            spec.overlay_fingerprint()
        );
    }
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"rch-build-source-selection-v1\0");
    hasher.update(spec.base_commit().as_bytes());
    hasher.update(b"\0");
    hasher.update(spec.tree_object.as_bytes());
    hasher.update(b"\0");
    hasher.update(spec.overlay_fingerprint().as_bytes());
    let mut dependencies = spec.dependencies.iter().collect::<Vec<_>>();
    dependencies.sort_by(|(left, _), (right, _)| left.cmp(right));
    for (root, dependency) in dependencies {
        hasher.update(b"\0dependency\0");
        hasher.update(root.file_name().unwrap_or_default().as_encoded_bytes());
        hasher.update(b"\0");
        hasher.update(clean_overlay_build_source_stamp(dependency).as_bytes());
        hasher.update(b"\0");
        hasher.update(dependency.tree_object.as_bytes());
    }
    format!(
        "{}-overlay-{}",
        spec.base_commit(),
        hasher.finalize().to_hex()
    )
}

pub(super) async fn capture_build_source_stamp(
    root: &Path,
    overlay: Option<&CleanOverlaySpec>,
) -> String {
    if let Some(spec) = overlay {
        return clean_overlay_build_source_stamp(spec);
    }
    let Some(head) = build_source_git_output(root, &["rev-parse", "--verify", "HEAD"])
        .await
        .and_then(|bytes| String::from_utf8(bytes).ok())
        .map(|value| value.trim().to_owned())
        .filter(|value| stamp_commit_hash(value))
    else {
        return "unknown".to_owned();
    };
    if build_source_git_output(root, &["ls-files", "--error-unmatch", "--", "Cargo.toml"])
        .await
        .is_none()
    {
        return "unknown".to_owned();
    }
    match build_source_git_output(
        root,
        &[
            "status",
            "--porcelain=v1",
            "--untracked-files=normal",
            "--ignore-submodules=none",
        ],
    )
    .await
    {
        Some(status) if status.is_empty() => head,
        Some(_) => format!("{head}-dirty"),
        None => "unknown".to_owned(),
    }
}

pub(super) fn reconcile_build_source_stamps(before: &str, after: &str) -> String {
    if before == after {
        before.to_owned()
    } else {
        "unknown".to_owned()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(unix)]
    mod owned_closure {
        use super::*;
        use crate::hook::dependency_closure::{
            OwnedSyncClosureLayout, build_owned_sync_closure_layout, build_sync_closure_plan,
            workspace_metadata_sync_patterns,
        };
        use std::fs;

        async fn fixture() -> (
            tempfile::TempDir,
            PathTopologyPolicy,
            OwnedSyncClosureLayout,
            Vec<PreparedSourceContentRoot>,
        ) {
            let temp = tempfile::tempdir().unwrap();
            let local = temp.path().join("local");
            fs::create_dir_all(&local).unwrap();
            let local = local.canonicalize().unwrap();
            let files = [
                (
                    "workspace/Cargo.toml",
                    "[workspace]\nmembers = [\"apps/app\"]\n[workspace.package]\nedition = \"2021\"\n",
                ),
                ("workspace/.cargo/config.toml", "[build]\njobs = 2\n"),
                (
                    "workspace/apps/app/Cargo.toml",
                    "[package]\nname = \"app\"\nversion = \"0.1.0\"\nedition.workspace = true\n[dependencies]\nmember = { path = \"../../../foreign/crates/member\" }\n",
                ),
                (
                    "workspace/apps/app/src/lib.rs",
                    "pub fn value() -> u32 { member::value() }\n",
                ),
                (
                    "foreign/Cargo.toml",
                    "[workspace]\nmembers = [\"crates/member\"]\n",
                ),
                (
                    "foreign/crates/member/Cargo.toml",
                    "[package]\nname = \"member\"\nversion = \"0.1.0\"\n",
                ),
                (
                    "foreign/crates/member/src/lib.rs",
                    "pub fn value() -> u32 { 7 }\n",
                ),
            ];
            for (relative, contents) in files {
                let path = local.join(relative);
                fs::create_dir_all(path.parent().unwrap()).unwrap();
                fs::write(path, contents).unwrap();
            }
            let policy = PathTopologyPolicy::new(local.clone(), local.clone());
            let primary = local.join("workspace/apps/app");
            let plan = build_sync_closure_plan(
                &[primary.clone(), local.join("foreign/crates/member")],
                &primary,
                "fixture-source",
                &policy,
            );
            let base = temp.path().join("worker/staging");
            let layout = build_owned_sync_closure_layout(
                &plan,
                &policy,
                base.to_str().unwrap(),
                ".rch-target-worker-pool-0123456789abcdef0123456789abcdef",
            )
            .unwrap();
            let mut prepared = Vec::new();
            for (ordinal, entry) in layout.plan.iter().enumerate() {
                let mut pipeline = TransferPipeline::new(
                    entry.local_root.clone(),
                    entry.project_id.clone(),
                    entry.root_hash.clone(),
                    rch_common::TransferConfig::default(),
                )
                .with_remote_path_override(entry.remote_root.clone())
                .with_owned_source_materialization();
                if entry.mode == SyncClosureMode::WorkspaceMetadata {
                    pipeline =
                        pipeline.with_sync_include_patterns(workspace_metadata_sync_patterns());
                }
                prepared.push(
                    prepare_source_content_root(ordinal, entry, &pipeline)
                        .await
                        .unwrap(),
                );
            }
            (temp, policy, layout, prepared)
        }

        #[tokio::test]
        async fn captured_closure_maps_actual_manifest_args_and_preserves_payloads() {
            let (_temp, policy, layout, prepared) = fixture().await;
            let cwd = policy.canonical_root().join("workspace/apps/app");
            let dependency = policy.canonical_root().join("foreign/crates/member");
            for selected in [&cwd, &dependency] {
                for equals in [false, true] {
                    let manifest = selected.join("Cargo.toml");
                    let mut argv = vec![
                        "env".to_owned(),
                        "RCH_NOTE=--manifest-path=/decoy".to_owned(),
                        "cargo".to_owned(),
                        "test".to_owned(),
                        "--features".to_owned(),
                        "--manifest-path=/opaque-value".to_owned(),
                    ];
                    if equals {
                        argv.push(format!("--manifest-path={}", manifest.display()));
                    } else {
                        argv.extend([
                            "--manifest-path".to_owned(),
                            manifest.to_str().unwrap().to_owned(),
                        ]);
                    }
                    argv.extend(["--".to_owned(), "--manifest-path=/test-payload".to_owned()]);
                    let command = shell_words::join(&argv);
                    let mapped = validate_owned_source_content_closure(
                        &prepared,
                        &layout.source_root,
                        &cwd,
                        Some(selected),
                        &command,
                        &policy,
                    )
                    .unwrap();
                    let remote = layout
                        .plan
                        .iter()
                        .find(|entry| entry.local_root == *selected)
                        .unwrap();
                    let expected = format!("{}/Cargo.toml", remote.remote_root);
                    if equals {
                        argv[6] = format!("--manifest-path={expected}");
                    } else {
                        argv[7] = expected;
                    }
                    assert_eq!(shell_words::split(&mapped).unwrap(), argv);
                }
            }
            let relative = "cargo check --manifest-path ../../../foreign/crates/member/Cargo.toml --config 'build.jobs=2'";
            let mapped = validate_owned_source_content_closure(
                &prepared,
                &layout.source_root,
                &cwd,
                Some(&dependency),
                relative,
                &policy,
            )
            .unwrap();
            assert!(shell_words::split(&mapped).unwrap().contains(&format!(
                "{}/projects/foreign/crates/member/Cargo.toml",
                layout.source_root,
            )));
            validate_owned_source_content_closure(
                &prepared,
                &layout.source_root,
                &cwd,
                None,
                "cargo check --workspace --locked",
                &policy,
            )
            .unwrap();
        }

        #[tokio::test]
        async fn captured_closure_refuses_ambient_sources_outputs_and_metadata_drift() {
            let (_temp, policy, layout, prepared) = fixture().await;
            let cwd = policy.canonical_root().join("workspace/apps/app");
            for command in [
                "cargo build --target-dir /canonical/out",
                "cargo build --target-dir=/canonical/out",
                "cargo build --build-dir=/canonical/out",
                "cargo build --artifact-dir=/canonical/out",
                "cargo build --out-dir=/canonical/out",
                "cargo build --lockfile-path=/canonical/Cargo.lock",
                "env CARGO_TARGET_DIR=/canonical/out cargo build",
                "CARGO_HOME=/canonical/home cargo build",
                "env -C /canonical cargo build",
                "cargo -C /canonical build",
                "cargo build --config /canonical/config.toml",
                "cargo build --config 'patch.crates-io.member.path=\"/canonical/member\"'",
                "cargo build --target=/canonical/target.json",
                "cargo build --unknown --manifest-path=/canonical/Cargo.toml",
                "cargo build {--manifest-path=/canonical/Cargo.toml,}",
            ] {
                assert!(
                    validate_owned_source_content_closure(
                        &prepared,
                        &layout.source_root,
                        &cwd,
                        None,
                        command,
                        &policy,
                    )
                    .is_err(),
                    "{command}"
                );
            }
            let mut missing = prepared.clone();
            missing.retain(|root| !root.manifest.local_root.ends_with("foreign/crates/member"));
            assert!(
                validate_owned_source_content_closure(
                    &missing,
                    &layout.source_root,
                    &cwd,
                    None,
                    "cargo build",
                    &policy,
                )
                .is_err(),
                "the ambient dependency still exists but is not captured"
            );
            fs::write(
                policy.canonical_root().join("workspace/.cargo/config.toml"),
                "[build]\njobs = 3\n",
            )
            .unwrap();
            let error = validate_owned_source_content_closure(
                &prepared,
                &layout.source_root,
                &cwd,
                None,
                "cargo build",
                &policy,
            )
            .unwrap_err();
            assert!(
                error
                    .to_string()
                    .contains("captured Cargo metadata changed"),
                "{error:#}"
            );
        }

        #[tokio::test]
        async fn captured_freshness_identity_tracks_bytes_modes_and_policy_not_receipt_order() {
            let (_temp, _policy, _layout, prepared) = fixture().await;
            let baseline = owned_source_content_freshness_identity(&prepared).unwrap();
            assert_eq!(baseline.len(), 64);
            let mut reordered = prepared.clone();
            reordered.reverse();
            for root in &mut reordered {
                root.manifest.ordinal += 42;
                root.manifest.root_hash = "different-git-provenance".into();
                root.manifest.content_root = "different-receipt-provenance".into();
                root.manifest.files.reverse();
            }
            assert_eq!(
                baseline,
                owned_source_content_freshness_identity(&reordered).unwrap()
            );
            let mut changed = prepared.clone();
            changed[0].manifest.files[0].sha256 = "f".repeat(64);
            assert_ne!(
                baseline,
                owned_source_content_freshness_identity(&changed).unwrap()
            );
            let mut changed = prepared.clone();
            changed[0].manifest.files[0].executable = !changed[0].manifest.files[0].executable;
            assert_ne!(
                baseline,
                owned_source_content_freshness_identity(&changed).unwrap()
            );
            let mut changed = prepared;
            changed[0]
                .manifest
                .filter_policy
                .exclude_patterns
                .push("new-exclusion".into());
            assert_ne!(
                baseline,
                owned_source_content_freshness_identity(&changed).unwrap()
            );
        }

        #[tokio::test]
        async fn owned_config_guard_allows_captured_workspace_and_refuses_home_or_extra_config() {
            use std::os::unix::fs::PermissionsExt as _;
            let (temp, _policy, layout, prepared) = fixture().await;
            for root in &prepared {
                for file in &root.manifest.files {
                    let target = Path::new(&root.manifest.remote_root).join(&file.path);
                    fs::create_dir_all(target.parent().unwrap()).unwrap();
                    fs::copy(
                        Path::new(&root.manifest.local_root).join(&file.path),
                        target,
                    )
                    .unwrap();
                }
            }
            let bin = temp.path().join("bin");
            fs::create_dir(&bin).unwrap();
            let cargo = bin.join("cargo");
            fs::write(&cargo, "#!/bin/sh\nprintf '%s\\n' cargo-entered\n").unwrap();
            fs::set_permissions(&cargo, fs::Permissions::from_mode(0o755)).unwrap();
            let command = shell_words::join([cargo.to_str().unwrap(), "check"]);
            let guarded = guard_owned_source_content_cargo_config(&command, &prepared).unwrap();
            let home = temp.path().join("cargo-home");
            fs::create_dir(&home).unwrap();
            let cwd = layout.plan.iter().find(|entry| entry.is_primary).unwrap();
            let run_guard = |guard: &str, home: &Path| {
                std::process::Command::new("/bin/sh")
                    .args(["-c", guard])
                    .current_dir(&cwd.remote_root)
                    .env("CARGO_HOME", home)
                    .output()
                    .unwrap()
            };
            let run = |home: &Path| run_guard(&guarded, home);
            let accepted = run(&home);
            assert!(accepted.status.success(), "{accepted:?}");
            assert_eq!(accepted.stdout, b"cargo-entered\n");
            // The guard walks physical directories; a remote root spelled
            // through a symlink must still select its captured config.
            let alias = temp.path().join("alias");
            std::os::unix::fs::symlink(temp.path(), &alias).unwrap();
            let mut aliased = prepared.clone();
            for root in &mut aliased {
                root.manifest.remote_root = root.manifest.remote_root.replacen(
                    temp.path().to_str().unwrap(),
                    alias.to_str().unwrap(),
                    1,
                );
                assert!(root.manifest.remote_root.contains("/alias/"));
            }
            let aliased_guard =
                guard_owned_source_content_cargo_config(&command, &aliased).unwrap();
            let accepted = run_guard(&aliased_guard, &home);
            assert!(accepted.status.success(), "{accepted:?}");
            assert_eq!(accepted.stdout, b"cargo-entered\n");
            fs::write(home.join("config.toml"), "[build]\njobs = 1\n").unwrap();
            let rejected = run(&home);
            assert_eq!(rejected.status.code(), Some(113));
            assert!(rejected.stdout.is_empty());
            let other_home = temp.path().join("other-cargo-home");
            fs::create_dir(&other_home).unwrap();
            let extra = Path::new(&layout.source_root).join("projects/.cargo");
            fs::create_dir(&extra).unwrap();
            fs::write(extra.join("config.toml"), "[build]\njobs = 1\n").unwrap();
            let rejected = run(&other_home);
            assert_eq!(rejected.status.code(), Some(113));
            assert!(rejected.stdout.is_empty());
        }
    }

    #[test]
    fn receipt_root_changes_with_worker_command_exit_and_file_identity() {
        let filter_policy = SourceContentFilterPolicy {
            schema: "rch.source_content_filter.v1",
            include_patterns: None,
            exclude_patterns: vec!["target/".to_string()],
            delete_extraneous: true,
            checksum_transfer: true,
        };
        let file = SourceContentFile {
            path: "src/lib.rs".to_string(),
            sha256: "a".repeat(64),
            byte_count: 7,
            executable: false,
        };
        let root = SourceContentRootManifest {
            schema: ROOT_SCHEMA,
            ordinal: 0,
            project_id: "fixture".to_string(),
            local_root: "/data/projects/fixture".to_string(),
            remote_root: "/data/tmp/rch/fixture/proof".to_string(),
            root_hash: "b".repeat(64),
            is_primary: true,
            mode: SyncClosureMode::Full,
            filter_policy,
            file_count: 1,
            byte_count: 7,
            files: vec![file],
            content_root: "c".repeat(64),
        };
        let roots = vec![root.clone()];
        let root_for =
            |worker: &str, command: &str, exit_code: i32, roots: &[SourceContentRootManifest]| {
                let command_sha256 = sha256_hex(command.as_bytes());
                sha256_hex(
                    &serde_json::to_vec(&SourceContentReceiptPreimage {
                        schema: RECEIPT_SCHEMA,
                        worker_id: worker,
                        build_id: "42",
                        command_sha256: &command_sha256,
                        command_exit_code: exit_code,
                        root_count: roots.len(),
                        roots,
                    })
                    .unwrap(),
                )
            };
        let baseline = root_for("worker-a", "cargo check", 0, &roots);
        assert_ne!(baseline, root_for("worker-b", "cargo check", 0, &roots));
        assert_ne!(baseline, root_for("worker-a", "cargo test", 0, &roots));
        assert_ne!(baseline, root_for("worker-a", "cargo check", 1, &roots));
        let mut mutated = roots;
        mutated[0].files[0].sha256 = "d".repeat(64);
        assert_ne!(baseline, root_for("worker-a", "cargo check", 0, &mutated));

        let receipt = SourceContentReceipt {
            schema: RECEIPT_SCHEMA,
            worker_id: "worker-a".to_string(),
            build_id: "9007199254740993".to_string(),
            command_sha256: sha256_hex(b"cargo check"),
            command_exit_code: 0,
            root_count: 1,
            roots: vec![root],
            receipt_root: baseline,
        };
        let wire: serde_json::Value = serde_json::from_str(&receipt.canonical_json().unwrap())
            .expect("receipt JSON should parse");
        assert_eq!(wire["build_id"], "9007199254740993");
    }

    #[test]
    fn remote_manifest_payload_is_bounded_and_unambiguous() {
        let manifest = SourceContentRootManifest {
            schema: ROOT_SCHEMA,
            ordinal: 0,
            project_id: "fixture".to_string(),
            local_root: "/local".to_string(),
            remote_root: "/remote".to_string(),
            root_hash: "a".repeat(64),
            is_primary: true,
            mode: SyncClosureMode::Full,
            filter_policy: SourceContentFilterPolicy {
                schema: "rch.source_content_filter.v1",
                include_patterns: None,
                exclude_patterns: vec![],
                delete_extraneous: true,
                checksum_transfer: true,
            },
            file_count: 1,
            byte_count: 3,
            files: vec![SourceContentFile {
                path: "src/lib.rs".to_string(),
                sha256: "f".repeat(64),
                byte_count: 3,
                executable: false,
            }],
            content_root: "b".repeat(64),
        };
        assert_eq!(
            String::from_utf8(remote_manifest_payload(&manifest).unwrap()).unwrap(),
            format!("{}\t3\t0\tsrc/lib.rs\n", "f".repeat(64))
        );
        let mut invalid = manifest;
        invalid.files[0].path = "src\tlib.rs".to_string();
        assert!(remote_manifest_payload(&invalid).is_err());
    }

    #[cfg(unix)]
    fn run_source_verifier(
        manifest: &SourceContentRootManifest,
        payload: &[u8],
        path_override: Option<&Path>,
    ) -> std::process::Output {
        use std::io::Write as _;
        use std::process::Stdio;

        let mut command = std::process::Command::new("/bin/sh");
        command
            .args(["-c", &remote_verify_command(manifest)])
            .current_dir(&manifest.remote_root)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        if let Some(path) = path_override {
            command.env("PATH", path);
        }
        let mut child = command.spawn().expect("source verifier shell starts");
        child
            .stdin
            .take()
            .expect("source verifier has piped stdin")
            .write_all(payload)
            .expect("source manifest reaches verifier");
        child.wait_with_output().expect("source verifier completes")
    }

    #[cfg(unix)]
    fn check_source_verifier_controls(path_override: Option<&Path>) {
        use std::os::unix::fs::PermissionsExt as _;

        let temp = tempfile::tempdir().expect("private verifier test directory");
        let root = temp.path().join("source root with spaces and ' quotes");
        std::fs::create_dir(&root).unwrap();
        let mut files = Vec::new();
        for name in [
            "ordinary.rs",
            "literal ' ; café.rs",
            "empty.rs",
            "executable.sh",
        ] {
            let path = root.join(name);
            let contents: &[u8] = if name == "empty.rs" {
                b""
            } else if name == "executable.sh" {
                b"#!/bin/sh\nexit 0\n"
            } else {
                b"pub fn source_bytes() {}\n"
            };
            std::fs::write(&path, contents).unwrap();
            let mode = if name == "executable.sh" {
                0o755
            } else {
                0o644
            };
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode)).unwrap();
            let (sha256, byte_count, executable) = hash_file(&path).unwrap();
            files.push(SourceContentFile {
                path: name.to_owned(),
                sha256,
                byte_count,
                executable,
            });
        }
        // A compiler source tree cannot replace the verifier's standard
        // library imports. Python's isolated mode must ignore this module.
        std::fs::write(
            root.join("hashlib.py"),
            b"raise RuntimeError('untrusted source import')\n",
        )
        .unwrap();
        let manifest = SourceContentRootManifest {
            schema: ROOT_SCHEMA,
            ordinal: 0,
            project_id: "verifier-test".to_owned(),
            local_root: root.to_str().unwrap().to_owned(),
            remote_root: root.to_str().unwrap().to_owned(),
            root_hash: "a".repeat(64),
            is_primary: true,
            mode: SyncClosureMode::Full,
            filter_policy: SourceContentFilterPolicy {
                schema: "rch.source_content_filter.v1",
                include_patterns: None,
                exclude_patterns: vec![],
                delete_extraneous: true,
                checksum_transfer: true,
            },
            file_count: files.len(),
            byte_count: files.iter().map(|file| file.byte_count).sum(),
            files,
            content_root: "b".repeat(64),
        };
        let payload = remote_manifest_payload(&manifest).unwrap();
        let output = run_source_verifier(&manifest, &payload, path_override);
        assert!(output.status.success(), "{:?}", output);
        assert!(output.stderr.is_empty(), "{:?}", output);
        assert_eq!(
            output.stdout,
            format!(
                "RCH_SOURCE_CONTENT_VERIFIED\t{}\t{}\n",
                manifest.file_count, manifest.byte_count
            )
            .as_bytes()
        );

        let mut wrong_size = manifest.clone();
        wrong_size.files[0].byte_count += 1;
        let mut wrong_hash = manifest.clone();
        wrong_hash.files[0].sha256 = "0".repeat(64);
        let mut wrong_mode = manifest.clone();
        wrong_mode.files[0].executable = true;
        let mut wrong_executable = manifest.clone();
        wrong_executable.files[3].executable = false;
        let mut missing = manifest.clone();
        missing.files[0].path = "missing.rs".to_owned();
        let mut directory = manifest.clone();
        std::fs::create_dir(root.join("directory.rs")).unwrap();
        directory.files[0].path = "directory.rs".to_owned();
        let mut symlink = manifest.clone();
        std::os::unix::fs::symlink("ordinary.rs", root.join("symlink.rs")).unwrap();
        symlink.files[0].path = "symlink.rs".to_owned();
        let mut short = manifest.clone();
        short.files.pop();
        let mut extra = manifest.clone();
        extra.files.push(extra.files[0].clone());
        let mut wrong_total = manifest.clone();
        wrong_total.byte_count += 1;
        for (mutated, code) in [
            (wrong_size, 64),
            (wrong_hash, 65),
            (wrong_mode, 66),
            (wrong_executable, 66),
            (missing, 63),
            (directory, 63),
            (symlink, 63),
            (short, 67),
            (extra, 67),
            (wrong_total, 68),
        ] {
            let output = run_source_verifier(
                &mutated,
                &remote_manifest_payload(&mutated).unwrap(),
                path_override,
            );
            assert_eq!(output.status.code(), Some(code), "{:?}", output);
            assert!(output.stdout.is_empty(), "{:?}", output);
            assert!(
                output.stderr.starts_with(b"RCH_SOURCE_CONTENT_ERROR:"),
                "{:?}",
                output
            );
        }
        for truncated in [&payload[..payload.len() - 1], &payload[..0]] {
            let output = run_source_verifier(&manifest, truncated, path_override);
            assert_eq!(output.status.code(), Some(67), "{:?}", output);
            assert!(output.stdout.is_empty(), "{:?}", output);
        }
        if path_override.is_none() {
            // This deliberately failing interpreter is a must-reject control.
            // Its exit must survive; a failed Python run cannot be retried as
            // portable verification, even when that would also reject input.
            let bin = temp.path().join("failed-python-bin");
            std::fs::create_dir(&bin).unwrap();
            let python = bin.join("python3");
            std::fs::write(
                &python,
                b"#!/bin/sh\nwhile IFS= read -r line; do :; done\nexit 73\n",
            )
            .unwrap();
            std::fs::set_permissions(&python, std::fs::Permissions::from_mode(0o755)).unwrap();
            let output = run_source_verifier(&manifest, &payload, Some(&bin));
            assert_eq!(output.status.code(), Some(73), "{:?}", output);
            assert!(output.stdout.is_empty(), "{:?}", output);
        }
    }

    #[cfg(unix)]
    #[test]
    fn isolated_python_verifier_preserves_all_source_checks() {
        let python = std::process::Command::new("python3")
            .args(["-I", "-c", "import hashlib, os, stat, sys"])
            .status()
            .expect("Python verification must execute, not skip its assertions");
        assert!(python.success());
        check_source_verifier_controls(None);
    }

    #[cfg(unix)]
    #[test]
    fn portable_verifier_without_python_preserves_all_source_checks() {
        let search = std::env::var_os("PATH").expect("test has a tool search path");
        let resolve = |name: &str| {
            std::env::split_paths(&search)
                .map(|directory| directory.join(name))
                .find(|path| path.is_file())
        };
        let mut verified_hash_tools = 0;
        for hash_tool in ["sha256sum", "shasum"] {
            let Some(hash_path) = resolve(hash_tool) else {
                continue;
            };
            let bin = tempfile::tempdir().expect("private portable verifier PATH");
            for (name, path) in std::iter::once((hash_tool, hash_path)).chain(
                ["awk", "wc", "tr"].into_iter().map(|name| {
                    (
                        name,
                        resolve(name).expect("portable verifier utility must be present"),
                    )
                }),
            ) {
                let executable = path
                    .canonicalize()
                    .expect("portable verifier utility path resolves");
                std::os::unix::fs::symlink(executable, bin.path().join(name)).unwrap();
            }
            check_source_verifier_controls(Some(bin.path()));
            verified_hash_tools += 1;
        }
        assert!(
            verified_hash_tools > 0,
            "portable verification must execute with a genuine SHA-256 tool"
        );
    }

    fn build_source_stamp_git(root: &Path, args: &[&str]) -> String {
        let output = std::process::Command::new("git")
            .current_dir(root)
            .args(args)
            .output()
            .expect("git fixture command runs");
        assert!(
            output.status.success(),
            "git {args:?}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        String::from_utf8(output.stdout).unwrap().trim().to_owned()
    }

    fn build_source_stamp_git_commit(root: &Path, message: &str) {
        build_source_stamp_git(
            root,
            &[
                "-c",
                "user.name=RCH-Test",
                "-c",
                "user.email=rch-test@example.invalid",
                "commit",
                "-q",
                "--no-gpg-sign",
                "-m",
                message,
            ],
        );
    }

    fn build_source_stamp_fixture_repo() -> (PathBuf, String) {
        let root = tempfile::tempdir().unwrap().keep();
        build_source_stamp_git(&root, &["init", "-q", "-b", "main"]);
        std::fs::create_dir_all(root.join("src")).unwrap();
        std::fs::write(
            root.join("Cargo.toml"),
            "[package]\nname='stamp-fixture'\nversion='0.1.0'\n",
        )
        .unwrap();
        std::fs::write(root.join("src/lib.rs"), "pub fn baseline() {}\n").unwrap();
        build_source_stamp_git(&root, &["add", "Cargo.toml", "src/lib.rs"]);
        build_source_stamp_git_commit(&root, "initial");
        let head = build_source_stamp_git(&root, &["rev-parse", "HEAD"]);
        assert!(stamp_commit_hash(&head));
        (root, head)
    }

    fn build_source_stamp_overlay_spec(
        base_commit: &str,
        tree_object: &str,
        overlay_fingerprint: &str,
        overlay_paths: Vec<PathBuf>,
        dependencies: Vec<(PathBuf, CleanOverlaySpec)>,
    ) -> CleanOverlaySpec {
        CleanOverlaySpec {
            base_commit: base_commit.to_owned(),
            tree_object: tree_object.to_owned(),
            overlay_paths,
            overlay_fingerprint: overlay_fingerprint.to_owned(),
            dependencies,
            primary_directory: None,
        }
    }

    #[tokio::test]
    async fn build_source_stamp_clean_repo_is_head() {
        let (root, head) = build_source_stamp_fixture_repo();
        assert_eq!(capture_build_source_stamp(&root, None).await, head);
        eprintln!(
            "build-source clean-repo fixture retained at {}",
            root.display()
        );
    }

    #[tokio::test]
    async fn build_source_stamp_tracked_edit_is_dirty() {
        let (root, head) = build_source_stamp_fixture_repo();
        std::fs::write(root.join("src/lib.rs"), "pub fn changed() {}\n").unwrap();
        assert_eq!(
            capture_build_source_stamp(&root, None).await,
            format!("{head}-dirty")
        );
        eprintln!("build-source dirty fixture retained at {}", root.display());
    }

    #[tokio::test]
    async fn build_source_stamp_untracked_source_is_dirty() {
        let (root, first) = build_source_stamp_fixture_repo();
        std::fs::write(root.join("src/lib.rs"), "pub fn second() {}\n").unwrap();
        build_source_stamp_git(&root, &["add", "src/lib.rs"]);
        build_source_stamp_git_commit(&root, "second");
        let second = build_source_stamp_git(&root, &["rev-parse", "HEAD"]);
        assert_ne!(first, second);
        assert_eq!(capture_build_source_stamp(&root, None).await, second);
        std::fs::write(root.join("src/extra.rs"), "pub fn extra() {}\n").unwrap();
        assert_eq!(
            capture_build_source_stamp(&root, None).await,
            format!("{second}-dirty")
        );
        eprintln!(
            "build-source untracked fixture retained at {}",
            root.display()
        );
    }

    #[tokio::test]
    async fn build_source_stamp_non_git_root_is_unknown() {
        let root = tempfile::tempdir().unwrap().keep();
        std::fs::write(
            root.join("Cargo.toml"),
            "[package]\nname='not-git'\nversion='0.1.0'\n",
        )
        .unwrap();
        assert_eq!(capture_build_source_stamp(&root, None).await, "unknown");
        eprintln!(
            "build-source non-git fixture retained at {}",
            root.display()
        );
    }

    #[tokio::test]
    async fn build_source_stamp_ignored_nested_package_is_unknown() {
        let (root, _head) = build_source_stamp_fixture_repo();
        std::fs::write(root.join(".gitignore"), "generated/\n").unwrap();
        build_source_stamp_git(&root, &["add", ".gitignore"]);
        build_source_stamp_git_commit(&root, "ignore generated");
        let nested = root.join("generated");
        std::fs::create_dir_all(&nested).unwrap();
        std::fs::write(
            nested.join("Cargo.toml"),
            "[package]\nname='generated'\nversion='0.1.0'\n",
        )
        .unwrap();
        assert_eq!(capture_build_source_stamp(&nested, None).await, "unknown");
        eprintln!(
            "build-source ignored-package fixture retained at {}",
            root.display()
        );
    }

    #[tokio::test]
    async fn build_source_stamp_missing_root_is_unknown() {
        let root = tempfile::tempdir().unwrap().keep();
        let missing = root.join("absent");
        assert_eq!(capture_build_source_stamp(&missing, None).await, "unknown");
        eprintln!(
            "build-source missing-root fixture retained at {}",
            root.display()
        );
    }

    #[test]
    fn build_source_stamp_reconcile_downgrades_on_mutation() {
        let head = "a".repeat(40);
        let other = "b".repeat(40);
        assert_eq!(reconcile_build_source_stamps(&head, &head), head);
        assert_eq!(
            reconcile_build_source_stamps(&head, &format!("{head}-dirty")),
            "unknown"
        );
        assert_eq!(reconcile_build_source_stamps(&head, &other), "unknown");
        let dirty = format!("{head}-dirty");
        assert_eq!(reconcile_build_source_stamps(&dirty, &dirty), dirty);
        assert_eq!(
            reconcile_build_source_stamps("unknown", "unknown"),
            "unknown"
        );
    }

    #[tokio::test]
    async fn build_source_stamp_overlay_base_only_ignores_ambient_worktree() {
        let (root, _head) = build_source_stamp_fixture_repo();
        std::fs::write(root.join("src/lib.rs"), "pub fn ambient_dirt() {}\n").unwrap();
        let spec = build_source_stamp_overlay_spec(
            &"a".repeat(40),
            &"c".repeat(40),
            &"d".repeat(64),
            vec![],
            vec![],
        );
        assert_eq!(
            capture_build_source_stamp(&root, Some(&spec)).await,
            "a".repeat(40)
        );
        eprintln!(
            "build-source base-only fixture retained at {}",
            root.display()
        );
    }

    #[test]
    fn build_source_stamp_overlay_stamp_tracks_selection() {
        let base = "a".repeat(40);
        let tree = "c".repeat(40);
        let fingerprint = "d".repeat(64);
        let selected = build_source_stamp_overlay_spec(
            &base,
            &tree,
            &fingerprint,
            vec![PathBuf::from("src/lib.rs")],
            vec![],
        );
        let stamp = clean_overlay_build_source_stamp(&selected);
        assert_eq!(stamp, format!("{base}-overlay-{fingerprint}"));

        let changed_fingerprint = build_source_stamp_overlay_spec(
            &base,
            &tree,
            &"e".repeat(64),
            vec![PathBuf::from("src/lib.rs")],
            vec![],
        );
        assert_ne!(
            stamp,
            clean_overlay_build_source_stamp(&changed_fingerprint)
        );

        let dep_root_a = PathBuf::from("/data/projects/dep-a");
        let dep_root_b = PathBuf::from("/data/projects/dep-b");
        let dep_a = build_source_stamp_overlay_spec(
            &"1".repeat(40),
            &"2".repeat(40),
            &"3".repeat(64),
            vec![],
            vec![],
        );
        let dep_b = build_source_stamp_overlay_spec(
            &"4".repeat(40),
            &"5".repeat(40),
            &"6".repeat(64),
            vec![],
            vec![],
        );
        let with_deps = build_source_stamp_overlay_spec(
            &base,
            &tree,
            &fingerprint,
            vec![PathBuf::from("src/lib.rs")],
            vec![
                (dep_root_a.clone(), dep_a.clone()),
                (dep_root_b.clone(), dep_b.clone()),
            ],
        );
        let stamp_with_deps = clean_overlay_build_source_stamp(&with_deps);
        assert!(stamp_with_deps.starts_with(&format!("{base}-overlay-")));
        assert_ne!(stamp_with_deps, stamp);

        let reordered = build_source_stamp_overlay_spec(
            &base,
            &tree,
            &fingerprint,
            vec![PathBuf::from("src/lib.rs")],
            vec![
                (dep_root_b.clone(), dep_b.clone()),
                (dep_root_a.clone(), dep_a.clone()),
            ],
        );
        assert_eq!(
            stamp_with_deps,
            clean_overlay_build_source_stamp(&reordered)
        );

        let dep_a_changed = build_source_stamp_overlay_spec(
            &"7".repeat(40),
            &dep_a.tree_object,
            &dep_a.overlay_fingerprint,
            vec![],
            vec![],
        );
        let changed_dep = build_source_stamp_overlay_spec(
            &base,
            &tree,
            &fingerprint,
            vec![PathBuf::from("src/lib.rs")],
            vec![(dep_root_a, dep_a_changed), (dep_root_b, dep_b)],
        );
        assert_ne!(
            stamp_with_deps,
            clean_overlay_build_source_stamp(&changed_dep)
        );
    }

    #[test]
    fn build_source_stamp_commit_env_preserves_exact_present_aliases() {
        let valid_a = "a".repeat(40);
        let valid_b = "b".repeat(7);
        let values: std::collections::HashMap<String, String> = [
            ("RCH_GIT_COMMIT", format!("  {valid_a}  ")),
            ("VERGEN_GIT_SHA", valid_b.clone()),
            ("GIT_COMMIT", "not-a-hash\n".to_owned()),
        ]
        .into_iter()
        .map(|(key, value)| (key.to_owned(), value))
        .collect();
        let env = build_source_commit_env(|key| values.get(key).cloned());
        assert_eq!(env.len(), 3);
        assert_eq!(env["RCH_GIT_COMMIT"], format!("  {valid_a}  "));
        assert_eq!(env["VERGEN_GIT_SHA"], valid_b);
        assert_eq!(env["GIT_COMMIT"], "not-a-hash\n");
        assert!(!env.contains_key("GITHUB_SHA"));
        assert_ne!(env["RCH_GIT_COMMIT"], env["VERGEN_GIT_SHA"]);
        let empty = build_source_commit_env(|key| (key == "GITHUB_SHA").then(String::new));
        assert_eq!(empty.len(), 1);
        assert_eq!(empty["GITHUB_SHA"], "");
    }

    #[cfg(unix)]
    #[test]
    fn build_source_stamp_alias_boundary_preserves_unset_and_caller_wrappers() {
        let report = r#"printf '%s\n' "${RCH_GIT_COMMIT-unset}" "${VERGEN_GIT_SHA-unset}" "${GIT_COMMIT-unset}" "${GITHUB_SHA-unset}""#;
        let caller_commit = "a".repeat(40);
        let caller_vergen = "b".repeat(40);
        let inline_commit = "c".repeat(40);
        let aliases = build_source_commit_env(|key| match key {
            "RCH_GIT_COMMIT" => Some(caller_commit.clone()),
            "VERGEN_GIT_SHA" => Some(caller_vergen.clone()),
            _ => None,
        });
        let empty = std::collections::HashMap::new();
        let literal = "  'quoted' \"double\" $HOME $(printf EVALUATED >&2) `printf EVALUATED >&2`;\ntrailing  ";
        let raw_aliases = build_source_commit_env(|key| match key {
            "RCH_GIT_COMMIT" => Some(String::new()),
            "VERGEN_GIT_SHA" => Some("not-a-hash".to_owned()),
            "GIT_COMMIT" => Some(literal.to_owned()),
            _ => None,
        });
        let inline = format!(
            "RCH_GIT_COMMIT={inline_commit} sh -c {}",
            shell_words::quote(report)
        );
        let unset = format!("env -u RCH_GIT_COMMIT sh -c {}", shell_words::quote(report));
        let cleared = format!(
            "env -i PATH=/usr/bin:/bin sh -c {}",
            shell_words::quote(report)
        );
        for (command, caller, expected) in [
            (report, &empty, "unset\nunset\nunset\nunset\n".to_owned()),
            (
                report,
                &raw_aliases,
                format!("\nnot-a-hash\n{literal}\nunset\n"),
            ),
            (
                report,
                &aliases,
                format!("{caller_commit}\n{caller_vergen}\nunset\nunset\n"),
            ),
            (
                inline.as_str(),
                &aliases,
                format!("{inline_commit}\n{caller_vergen}\nunset\nunset\n"),
            ),
            (
                unset.as_str(),
                &aliases,
                format!("unset\n{caller_vergen}\nunset\nunset\n"),
            ),
            (
                cleared.as_str(),
                &aliases,
                "unset\nunset\nunset\nunset\n".to_owned(),
            ),
        ] {
            let mut process = std::process::Command::new("sh");
            process.env_clear().env("PATH", "/usr/bin:/bin");
            for key in rch_common::BUILD_COMMIT_ENV_VARS {
                process.env(key, "d".repeat(40));
            }
            let output = process
                .args(["-c", &bind_build_source_aliases(command, caller)])
                .output()
                .expect("run real shell alias boundary");
            assert!(
                output.status.success(),
                "{command}: {}",
                String::from_utf8_lossy(&output.stderr)
            );
            assert_eq!(
                String::from_utf8(output.stdout).unwrap(),
                expected,
                "{command}"
            );
            assert!(
                output.stderr.is_empty(),
                "alias bytes must not be evaluated"
            );
        }
    }

    #[cfg(unix)]
    #[test]
    fn build_source_stamp_alias_boundary_preserves_output_and_remote_exit() {
        let command = "printf '%s\\n' 'literal $HOME `id` \"quoted\"'; printf '%s\\n' 'diagnostic' >&2; exit 7";
        let output = std::process::Command::new("sh")
            .env_clear()
            .env("PATH", "/usr/bin:/bin")
            .args([
                "-c",
                &bind_build_source_aliases(command, &Default::default()),
            ])
            .output()
            .expect("run real shell preserving command bytes");
        assert_eq!(output.status.code(), Some(7));
        assert_eq!(output.stdout, b"literal $HOME `id` \"quoted\"\n");
        assert_eq!(output.stderr, b"diagnostic\n");
    }
}
