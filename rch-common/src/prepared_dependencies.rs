//! Exact dependency outputs admitted alongside an unchanged selected source tree.
//!
//! These values describe evidence, not filesystem ownership. The worker must
//! capture and revalidate the named files under its preparation transaction and
//! the caller's source grant. A retained state never authorizes an installer or
//! substitutes for the selected-source proof. Newly published states contain
//! only nonselected files, so a later selection cannot turn old source into
//! runtime-owned output.

use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::io::Write;

pub const PREPARED_DEPENDENCY_VERSION: u32 = 1;
pub const MAX_PREPARED_DEPENDENCY_JSON_BYTES: usize = 32 * 1024 * 1024;
pub const MAX_PREPARED_DEPENDENCY_FILES: usize = 100_000;
pub const MAX_PREPARED_DEPENDENCY_DIRECTORIES: usize = 100_000;
pub const MAX_PREPARED_DEPENDENCY_BYTES: u64 = 8 * 1024 * 1024 * 1024;
const MAX_PATH_BYTES: usize = 4096;
const MAX_IDENTITY_BYTES: usize = 128;
const MAX_LINK_HOPS: usize = 64;

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("prepared dependency contract: {0}")]
pub struct PreparedDependencyError(String);

type Result<T> = std::result::Result<T, PreparedDependencyError>;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PreparedDependencyFileKind {
    Regular,
    Symlink,
}

/// Paths are literal UTF-8 names relative to the selected source root.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PreparedDependencyFile {
    pub path: String,
    pub kind: PreparedDependencyFileKind,
    pub sha256: String,
    pub byte_count: u64,
    pub executable: bool,
    pub symlink_target: Option<String>,
}

/// Both vectors use strict Rust `String` order, with no duplicate names.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PreparedDependencyInventory {
    pub files: Vec<PreparedDependencyFile>,
    pub directories: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PreparedDependencyRequest {
    pub schema_version: u32,
    pub attempt_id: String,
    pub source_owner: String,
    /// Decimal string preserves the daemon's full integer identity in JSON.
    pub build_id: String,
    pub command_sha256: String,
    pub source_content_root: String,
    pub source_root: String,
    /// Empty denotes the source root; `.` is not a canonical spelling.
    pub project_relative: String,
    pub files: Vec<PreparedDependencyFile>,
    pub directories: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PreparedDependencyState {
    pub version: u32,
    pub project: String,
    /// Device and inode of the canonical preparation project directory. Their
    /// decimal-string wire representation preserves all bits in Node/Bun.
    #[serde(with = "decimal_u64")]
    pub root_device: u64,
    #[serde(with = "decimal_u64")]
    pub root_inode: u64,
    pub input_fingerprint: String,
    pub package_manager: String,
    pub frozen: bool,
    pub inventory: PreparedDependencyInventory,
    pub inventory_digest: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PreparedDependencyDisposition {
    Fresh,
    Retained,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PreparedDependencyAttestation {
    pub version: u32,
    pub request_digest: String,
    pub state_digest: String,
    pub state: PreparedDependencyState,
    pub disposition: PreparedDependencyDisposition,
}

mod decimal_u64 {
    use serde::{Deserialize, Deserializer, Serializer, de::Error};

    pub(super) fn serialize<S: Serializer>(value: &u64, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_str(value)
    }

    pub(super) fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<u64, D::Error> {
        // String deserialization deliberately refuses JSON numbers, including
        // small ones: one canonical wire type keeps digest reconstruction exact.
        let value = String::deserialize(deserializer)?;
        let parsed = value.parse::<u64>().map_err(D::Error::custom)?;
        if parsed.to_string() != value {
            return Err(D::Error::custom("expected a canonical decimal u64 string"));
        }
        Ok(parsed)
    }
}

fn require(condition: bool, reason: impl Into<String>) -> Result<()> {
    if condition {
        Ok(())
    } else {
        Err(PreparedDependencyError(reason.into()))
    }
}

fn digest_string(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn relative_path(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_PATH_BYTES
        && !value.contains('\\')
        && !value.chars().any(char::is_control)
        && value
            .split('/')
            .all(|component| !matches!(component, "" | "." | ".."))
}

fn absolute_path(value: &str) -> bool {
    value == "/"
        || value
            .strip_prefix('/')
            .is_some_and(|relative| value.len() <= MAX_PATH_BYTES && relative_path(relative))
}

fn below(path: &str, root: &str) -> bool {
    path.strip_prefix(root)
        .is_some_and(|suffix| suffix.starts_with('/'))
}

fn join_relative(parent: &str, child: &str) -> String {
    if parent.is_empty() {
        child.to_owned()
    } else {
        format!("{parent}/{child}")
    }
}

fn project_path(request: &PreparedDependencyRequest) -> String {
    if request.project_relative.is_empty() {
        request.source_root.clone()
    } else {
        format!(
            "{}/{}",
            request.source_root.trim_end_matches('/'),
            request.project_relative
        )
    }
}

fn validate_link(path: &str, target: &str) -> Result<()> {
    require(
        !target.is_empty()
            && target.len() <= MAX_PATH_BYTES
            && !target.starts_with('/')
            && !target.contains('\\')
            && !target.chars().any(char::is_control),
        format!("invalid relative symlink target at {path}"),
    )?;
    let mut depth = path.split('/').count() - 1;
    for component in target.split('/') {
        match component {
            "" | "." => {}
            ".." => {
                depth = depth.checked_sub(1).ok_or_else(|| {
                    PreparedDependencyError(format!("symlink escapes source root: {path}"))
                })?;
            }
            _ => depth += 1,
        }
    }
    Ok(())
}

fn validate_entries(files: &[PreparedDependencyFile], directories: &[String]) -> Result<()> {
    require(
        files.len() <= MAX_PREPARED_DEPENDENCY_FILES
            && directories.len() <= MAX_PREPARED_DEPENDENCY_DIRECTORIES,
        "inventory entry count exceeds limit",
    )?;
    let mut total = 0_u64;
    let mut previous = None;
    for file in files {
        require(relative_path(&file.path), "invalid inventory file path")?;
        require(
            previous.is_none_or(|path: &str| path < file.path.as_str()),
            "files must be unique and in literal String order",
        )?;
        previous = Some(file.path.as_str());
        require(digest_string(&file.sha256), "invalid file SHA-256")?;
        total = total
            .checked_add(file.byte_count)
            .filter(|total| *total <= MAX_PREPARED_DEPENDENCY_BYTES)
            .ok_or_else(|| PreparedDependencyError("inventory bytes exceed limit".to_owned()))?;
        match file.kind {
            PreparedDependencyFileKind::Regular => {
                require(
                    file.symlink_target.is_none(),
                    "regular file has a link target",
                )?;
            }
            PreparedDependencyFileKind::Symlink => {
                let target = file.symlink_target.as_deref().ok_or_else(|| {
                    PreparedDependencyError("symlink has no literal target".to_owned())
                })?;
                require(
                    !file.executable && file.byte_count == target.len() as u64,
                    "invalid symlink size or executable state",
                )?;
                validate_link(&file.path, target)?;
            }
        }
    }
    require(
        directories.windows(2).all(|pair| pair[0] < pair[1]),
        "directories must be unique and in literal String order",
    )?;
    for directory in directories {
        require(relative_path(directory), "invalid inventory directory path")?;
        require(
            files
                .binary_search_by(|file| file.path.as_str().cmp(directory))
                .is_err(),
            "file and directory have the same name",
        )?;
    }
    Ok(())
}

fn validate_parents(files: &[PreparedDependencyFile], directories: &[String]) -> Result<()> {
    for path in files
        .iter()
        .map(|file| file.path.as_str())
        .chain(directories.iter().map(String::as_str))
    {
        if let Some((parent, _)) = path.rsplit_once('/') {
            require(
                directories
                    .binary_search_by(|directory| directory.as_str().cmp(parent))
                    .is_ok(),
                format!("entry has an unlisted or non-directory parent: {path}"),
            )?;
        }
    }
    Ok(())
}

/// Hash canonical struct serialization without first allocating an unbounded
/// JSON buffer. The limit applies to encoded bytes, including string escapes.
fn canonical_digest(value: &impl Serialize) -> Result<String> {
    struct DigestWriter {
        hasher: blake3::Hasher,
        bytes: usize,
    }
    impl Write for DigestWriter {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            self.bytes = self
                .bytes
                .checked_add(bytes.len())
                .filter(|length| *length <= MAX_PREPARED_DEPENDENCY_JSON_BYTES)
                .ok_or_else(|| std::io::Error::other("prepared dependency JSON exceeds limit"))?;
            self.hasher.update(bytes);
            Ok(bytes.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    let mut writer = DigestWriter {
        hasher: blake3::Hasher::new(),
        bytes: 0,
    };
    serde_json::to_writer(&mut writer, value)
        .map_err(|error| PreparedDependencyError(error.to_string()))?;
    Ok(writer.hasher.finalize().to_hex().to_string())
}

fn validate_request_shape(request: &PreparedDependencyRequest) -> Result<()> {
    require(
        request.schema_version == PREPARED_DEPENDENCY_VERSION,
        "unknown request version",
    )?;
    require(
        !request.attempt_id.is_empty()
            && request.attempt_id.len() <= MAX_IDENTITY_BYTES
            && request
                .attempt_id
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.')),
        "invalid attempt identity",
    )?;
    require(
        !request.source_owner.is_empty()
            && request.source_owner.len() <= MAX_IDENTITY_BYTES
            && request
                .source_owner
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte) || byte == b'-'),
        "invalid source owner identity",
    )?;
    require(
        request
            .build_id
            .parse::<u64>()
            .is_ok_and(|value| value.to_string() == request.build_id),
        "build identity is not a canonical decimal u64",
    )?;
    require(
        digest_string(&request.command_sha256) && digest_string(&request.source_content_root),
        "invalid command or source content digest",
    )?;
    require(
        absolute_path(&request.source_root),
        "source root is not canonical and absolute",
    )?;
    require(
        request.project_relative.is_empty() || relative_path(&request.project_relative),
        "project path is not a canonical relative path",
    )?;
    require(
        absolute_path(&project_path(request)),
        "project path exceeds limit",
    )?;
    validate_entries(&request.files, &request.directories)?;
    validate_parents(&request.files, &request.directories)?;
    if !request.project_relative.is_empty() {
        require(
            request
                .directories
                .binary_search(&request.project_relative)
                .is_ok(),
            "preparation project is not a selected directory",
        )?;
    }
    let manifest = join_relative(&request.project_relative, "package.json");
    require(
        request
            .files
            .binary_search_by(|file| file.path.cmp(&manifest))
            .ok()
            .is_some_and(|index| request.files[index].kind == PreparedDependencyFileKind::Regular),
        "preparation project has no selected regular package.json",
    )
}

/// Validate the complete selected-source request and its serialized size.
pub fn validate_request(request: &PreparedDependencyRequest) -> Result<()> {
    request_digest(request).map(|_| ())
}

/// Canonical BLAKE3 digest of the validated request JSON.
pub fn request_digest(request: &PreparedDependencyRequest) -> Result<String> {
    validate_request_shape(request)?;
    canonical_digest(request)
}

/// Candidate dependency roots from selected package manifests. The worker
/// further restricts this set to its captured workspace member inventory.
pub fn admitted_dependency_roots(request: &PreparedDependencyRequest) -> Result<Vec<String>> {
    validate_request(request)?;
    let mut roots = BTreeSet::new();
    roots.insert(join_relative(&request.project_relative, "node_modules"));
    for file in &request.files {
        if file.kind != PreparedDependencyFileKind::Regular {
            continue;
        }
        let Some(parent) = file.path.strip_suffix("/package.json") else {
            continue;
        };
        if !request.project_relative.is_empty()
            && parent != request.project_relative
            && !below(parent, &request.project_relative)
        {
            continue;
        }
        if parent
            .split('/')
            .any(|part| matches!(part, "node_modules" | ".git"))
        {
            continue;
        }
        roots.insert(join_relative(parent, "node_modules"));
    }
    Ok(roots.into_iter().collect())
}

fn merge_inventory(
    request: &PreparedDependencyRequest,
    inventory: &PreparedDependencyInventory,
) -> Result<PreparedDependencyInventory> {
    let mut files = request
        .files
        .iter()
        .map(|file| (file.path.clone(), file.clone()))
        .collect::<BTreeMap<_, _>>();
    for file in &inventory.files {
        if let Some(selected) = files.get(&file.path) {
            require(
                selected == file,
                format!("runtime output changes selected source: {}", file.path),
            )?;
        } else {
            files.insert(file.path.clone(), file.clone());
        }
    }
    let directories = request
        .directories
        .iter()
        .chain(&inventory.directories)
        .cloned()
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect();
    let union = PreparedDependencyInventory {
        files: files.into_values().collect(),
        directories,
    };
    validate_entries(&union.files, &union.directories)?;
    validate_parents(&union.files, &union.directories)?;
    Ok(union)
}

fn validate_runtime_links(
    inventory: &PreparedDependencyInventory,
    union: &PreparedDependencyInventory,
) -> Result<()> {
    let files = union
        .files
        .iter()
        .map(|file| (file.path.as_str(), file))
        .collect::<BTreeMap<_, _>>();
    let directories = union
        .directories
        .iter()
        .map(String::as_str)
        .collect::<BTreeSet<_>>();
    for file in &inventory.files {
        let Some(target) = &file.symlink_target else {
            continue;
        };
        let mut resolved = file
            .path
            .split('/')
            .map(ToOwned::to_owned)
            .collect::<Vec<_>>();
        resolved.pop();
        let mut pending = target
            .split('/')
            .map(ToOwned::to_owned)
            .collect::<VecDeque<_>>();
        let mut hops = 0;
        let mut current_is_directory = true;
        while let Some(component) = pending.pop_front() {
            require(
                current_is_directory,
                "runtime symlink traverses a regular file",
            )?;
            match component.as_str() {
                "" | "." => {}
                ".." => {
                    require(
                        resolved.pop().is_some(),
                        "runtime symlink escapes source root",
                    )?;
                }
                _ => {
                    resolved.push(component);
                    let path = resolved.join("/");
                    if let Some(next) = files.get(path.as_str()) {
                        if let Some(target) = &next.symlink_target {
                            hops += 1;
                            require(hops <= MAX_LINK_HOPS, "runtime symlink cycle or hop limit")?;
                            validate_link(&path, target)?;
                            resolved.pop();
                            let mut continuation = target
                                .split('/')
                                .map(ToOwned::to_owned)
                                .collect::<VecDeque<_>>();
                            continuation.append(&mut pending);
                            pending = continuation;
                        } else {
                            current_is_directory = false;
                        }
                    } else {
                        require(
                            directories.contains(path.as_str()),
                            "runtime symlink names an unregistered path",
                        )?;
                    }
                }
            }
        }
    }
    Ok(())
}

fn has_admitted_ancestor(path: &str, roots: &[String], include_self: bool) -> bool {
    let contains = |candidate: &str| {
        roots
            .binary_search_by(|root| root.as_str().cmp(candidate))
            .is_ok()
    };
    // Probe only literal component boundaries. Scanning every package root
    // for every output is quadratic for otherwise bounded large inventories.
    (include_self && contains(path))
        || path
            .match_indices('/')
            .any(|(boundary, _)| contains(&path[..boundary]))
}

/// Validate runtime paths and links against the selected source namespace.
pub fn validate_inventory(
    request: &PreparedDependencyRequest,
    inventory: &PreparedDependencyInventory,
) -> Result<()> {
    let roots = admitted_dependency_roots(request)?;
    inventory_digest(inventory)?;
    for file in &inventory.files {
        require(
            has_admitted_ancestor(&file.path, &roots, false),
            "runtime file is outside admitted dependency roots",
        )?;
    }
    for directory in &inventory.directories {
        require(
            has_admitted_ancestor(directory, &roots, true),
            "runtime directory is outside admitted dependency roots",
        )?;
    }
    let union = merge_inventory(request, inventory)?;
    validate_runtime_links(inventory, &union)
}

/// Digest a bounded, ordered inventory. Contextual path authority additionally
/// requires [`validate_inventory`], which checks the selected-source union.
pub fn inventory_digest(inventory: &PreparedDependencyInventory) -> Result<String> {
    validate_entries(&inventory.files, &inventory.directories)?;
    canonical_digest(inventory)
}

fn validate_state_shape(state: &PreparedDependencyState) -> Result<()> {
    require(
        state.version == PREPARED_DEPENDENCY_VERSION,
        "unknown state version",
    )?;
    require(
        absolute_path(&state.project),
        "state project is not canonical and absolute",
    )?;
    require(
        digest_string(&state.input_fingerprint),
        "invalid dependency input fingerprint",
    )?;
    require(
        state.frozen
            && matches!(
                state.package_manager.as_str(),
                "bun" | "npm" | "pnpm" | "yarn"
            ),
        "state does not describe an admitted frozen package-manager plan",
    )?;
    require(
        state.inventory_digest == inventory_digest(&state.inventory)?,
        "state inventory digest mismatch",
    )
}

/// A prior state's input fingerprint may differ. This validates ownership of
/// its exact output inventory, not eligibility to skip the next installation.
/// The worker independently checks the recorded project device and inode.
pub fn validate_state(
    request: &PreparedDependencyRequest,
    state: &PreparedDependencyState,
) -> Result<()> {
    validate_request(request)?;
    validate_state_shape(state)?;
    require(
        state.project == project_path(request),
        "state belongs to another preparation project",
    )?;
    validate_inventory(request, &state.inventory)?;
    canonical_digest(state).map(|_| ())
}

/// Digest completed state without assigning it current-attempt authority.
pub fn state_digest(state: &PreparedDependencyState) -> Result<String> {
    validate_state_shape(state)?;
    canonical_digest(state)
}

fn validate_attestation_shape(attestation: &PreparedDependencyAttestation) -> Result<()> {
    require(
        attestation.version == PREPARED_DEPENDENCY_VERSION,
        "unknown attestation version",
    )?;
    require(
        digest_string(&attestation.request_digest),
        "invalid attestation request digest",
    )?;
    require(
        attestation.state_digest == state_digest(&attestation.state)?,
        "attestation state digest mismatch",
    )
}

/// A new attestation must preserve selected files as source, even if a prior
/// state overlapped files that have since become selected inputs.
pub fn validate_attestation(
    request: &PreparedDependencyRequest,
    attestation: &PreparedDependencyAttestation,
) -> Result<()> {
    validate_attestation_shape(attestation)?;
    require(
        attestation.request_digest == request_digest(request)?,
        "attestation belongs to another request",
    )?;
    validate_state(request, &attestation.state)?;
    for file in &attestation.state.inventory.files {
        require(
            request
                .files
                .binary_search_by(|selected| selected.path.cmp(&file.path))
                .is_err(),
            "new preparation state must not claim selected source files",
        )?;
    }
    canonical_digest(attestation).map(|_| ())
}

/// Digest the complete evidence envelope, including its fresh/retained status.
pub fn attestation_digest(attestation: &PreparedDependencyAttestation) -> Result<String> {
    validate_attestation_shape(attestation)?;
    canonical_digest(attestation)
}

/// Construct the exact namespace used by both proof barriers. Every selected
/// file retains its original tuple; duplicate directory names remain one name.
pub fn union_selected_inventory(
    request: &PreparedDependencyRequest,
    inventory: &PreparedDependencyInventory,
) -> Result<PreparedDependencyInventory> {
    validate_inventory(request, inventory)?;
    merge_inventory(request, inventory)
}

impl PreparedDependencyRequest {
    pub fn validate(&self) -> Result<()> {
        validate_request(self)
    }
    pub fn digest(&self) -> Result<String> {
        request_digest(self)
    }
}

impl PreparedDependencyInventory {
    pub fn validate_for(&self, request: &PreparedDependencyRequest) -> Result<()> {
        validate_inventory(request, self)
    }
    pub fn digest(&self) -> Result<String> {
        inventory_digest(self)
    }
}

impl PreparedDependencyState {
    /// Standalone shape only; use `validate_for` for current source binding.
    pub fn validate(&self) -> Result<()> {
        state_digest(self).map(|_| ())
    }
    pub fn validate_for(&self, request: &PreparedDependencyRequest) -> Result<()> {
        validate_state(request, self)
    }
    pub fn digest(&self) -> Result<String> {
        state_digest(self)
    }
}

impl PreparedDependencyAttestation {
    pub fn validate_for(&self, request: &PreparedDependencyRequest) -> Result<()> {
        validate_attestation(request, self)
    }
    pub fn digest(&self) -> Result<String> {
        attestation_digest(self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn regular(path: &str) -> PreparedDependencyFile {
        PreparedDependencyFile {
            path: path.to_owned(),
            kind: PreparedDependencyFileKind::Regular,
            sha256: "a".repeat(64),
            byte_count: 7,
            executable: false,
            symlink_target: None,
        }
    }

    fn link(path: &str, target: &str) -> PreparedDependencyFile {
        PreparedDependencyFile {
            path: path.to_owned(),
            kind: PreparedDependencyFileKind::Symlink,
            sha256: "b".repeat(64),
            byte_count: target.len() as u64,
            executable: false,
            symlink_target: Some(target.to_owned()),
        }
    }

    fn request() -> PreparedDependencyRequest {
        PreparedDependencyRequest {
            schema_version: 1,
            attempt_id: "rchw-native-fixture".to_owned(),
            source_owner: "ab12-34cd".to_owned(),
            build_id: "30095696984016289".to_owned(),
            command_sha256: "c".repeat(64),
            source_content_root: "d".repeat(64),
            source_root: "/tmp/source".to_owned(),
            project_relative: "vittles".to_owned(),
            files: vec![
                regular("vittles/bun.lock"),
                regular("vittles/node_modules/pinned.txt"),
                regular("vittles/package.json"),
                regular("vittles/src/index.ts"),
            ],
            directories: vec![
                "vittles".to_owned(),
                "vittles/node_modules".to_owned(),
                "vittles/src".to_owned(),
            ],
        }
    }

    fn inventory() -> PreparedDependencyInventory {
        PreparedDependencyInventory {
            files: vec![
                link("vittles/node_modules/.bin/tool", "../pkg/bin.js"),
                regular("vittles/node_modules/pkg/bin.js"),
            ],
            directories: vec![
                "vittles/node_modules/.bin".to_owned(),
                "vittles/node_modules/empty".to_owned(),
                "vittles/node_modules/pkg".to_owned(),
            ],
        }
    }

    fn state() -> PreparedDependencyState {
        let inventory = inventory();
        PreparedDependencyState {
            version: 1,
            project: "/tmp/source/vittles".to_owned(),
            root_device: 7,
            root_inode: 19,
            input_fingerprint: "e".repeat(64),
            package_manager: "bun".to_owned(),
            frozen: true,
            inventory_digest: inventory.digest().unwrap(),
            inventory,
        }
    }

    fn attestation() -> PreparedDependencyAttestation {
        let state = state();
        PreparedDependencyAttestation {
            version: 1,
            request_digest: request().digest().unwrap(),
            state_digest: state.digest().unwrap(),
            state,
            disposition: PreparedDependencyDisposition::Fresh,
        }
    }

    #[test]
    fn fresh_and_retained_attestations_bind_the_same_complete_inventory() {
        let request = request();
        let fresh = attestation();
        fresh.validate_for(&request).unwrap();
        let mut retained = fresh.clone();
        retained.disposition = PreparedDependencyDisposition::Retained;
        retained.validate_for(&request).unwrap();
        assert_ne!(fresh.digest().unwrap(), retained.digest().unwrap());
        let union = union_selected_inventory(&request, &fresh.state.inventory).unwrap();
        assert!(
            union
                .directories
                .contains(&"vittles/node_modules/empty".to_owned())
        );
        for selected in &request.files {
            assert_eq!(
                union.files.iter().find(|file| file.path == selected.path),
                Some(selected)
            );
        }
    }

    #[test]
    fn every_attempt_binding_is_part_of_the_attestation_request() {
        let attestation = attestation();
        for field in 0..7 {
            let mut changed = request();
            match field {
                0 => changed.attempt_id.push('x'),
                1 => changed.source_owner.push('a'),
                2 => changed.build_id = "30095696984016290".to_owned(),
                3 => changed.command_sha256 = "f".repeat(64),
                4 => changed.source_content_root = "f".repeat(64),
                5 => changed.source_root.push_str("-other"),
                _ => changed.files[0].sha256 = "f".repeat(64),
            }
            assert!(
                attestation.validate_for(&changed).is_err(),
                "binding field {field}"
            );
        }
    }

    #[test]
    fn selected_node_modules_source_is_never_overridden_or_published_as_runtime() {
        let request = request();
        let selected = request.files[1].clone();
        let mut prior = state();
        prior.inventory.files.push(selected.clone());
        prior
            .inventory
            .files
            .sort_by(|left, right| left.path.cmp(&right.path));
        prior.inventory_digest = prior.inventory.digest().unwrap();
        prior.validate_for(&request).unwrap();
        let mut current = attestation();
        current.state = prior.clone();
        current.state_digest = prior.digest().unwrap();
        assert!(current.validate_for(&request).is_err());
        for change in 0..4 {
            let mut inventory = prior.inventory.clone();
            let file = inventory
                .files
                .iter_mut()
                .find(|file| file.path == selected.path)
                .unwrap();
            match change {
                0 => file.sha256 = "f".repeat(64),
                1 => file.byte_count += 1,
                2 => file.executable = true,
                _ => *file = link(&selected.path, "pkg/bin.js"),
            }
            assert!(union_selected_inventory(&request, &inventory).is_err());
        }
    }

    #[test]
    fn runtime_namespace_does_not_admit_arbitrary_source_or_neighboring_projects() {
        for path in [
            "vittles/Cargo.toml",
            "vittles/.cargo/config.toml",
            "vittles/src/generated.ts",
            "node_modules/wrong-project.js",
            "vittles2/node_modules/file.js",
            "vittles/not_node_modules/file.js",
            "vittles/node_modules",
        ] {
            let inventory = PreparedDependencyInventory {
                files: vec![regular(path)],
                directories: vec![],
            };
            assert!(inventory.validate_for(&request()).is_err(), "{path}");
        }
    }

    #[test]
    fn admitted_roots_match_complete_ancestors_and_keep_nested_dependencies() {
        let request = request();
        let mut inventory = PreparedDependencyInventory {
            files: vec![regular(
                "vittles/node_modules/pkg/node_modules/child/index.js",
            )],
            directories: vec![
                "vittles/node_modules".to_owned(),
                "vittles/node_modules/pkg".to_owned(),
                "vittles/node_modules/pkg/node_modules".to_owned(),
                "vittles/node_modules/pkg/node_modules/child".to_owned(),
            ],
        };
        inventory.validate_for(&request).unwrap();
        for path in [
            "vittles/node_modules-extra/index.js",
            "vittles/node_modulesx/index.js",
            "vittles/node_modules",
        ] {
            inventory.files = vec![regular(path)];
            assert!(inventory.validate_for(&request).is_err(), "{path}");
        }
    }

    #[test]
    fn workspace_runtime_roots_require_selected_regular_package_manifests() {
        let mut request = request();
        request.directories.extend([
            "vittles/packages".to_owned(),
            "vittles/packages/ui".to_owned(),
        ]);
        request.directories.sort();
        request
            .files
            .push(regular("vittles/packages/ui/package.json"));
        request
            .files
            .sort_by(|left, right| left.path.cmp(&right.path));
        let inventory = PreparedDependencyInventory {
            files: vec![regular("vittles/packages/ui/node_modules/tool.js")],
            directories: vec!["vittles/packages/ui/node_modules".to_owned()],
        };
        inventory.validate_for(&request).unwrap();
        let index = request
            .files
            .iter()
            .position(|file| file.path == "vittles/packages/ui/package.json")
            .unwrap();
        request.files[index] = link("vittles/packages/ui/package.json", "../../package.json");
        assert!(inventory.validate_for(&request).is_err());
    }

    #[test]
    fn runtime_symlinks_require_closed_targets_and_cannot_escape_or_cycle() {
        for target in [
            "../../../../outside",
            "../unknown.js",
            "/absolute",
            "tool",
            "../pkg/bin.js/child",
        ] {
            let mut inventory = inventory();
            inventory.files[0] = link("vittles/node_modules/.bin/tool", target);
            assert!(inventory.validate_for(&request()).is_err(), "{target}");
        }
        let mut selected_target = inventory();
        selected_target.files[0] = link("vittles/node_modules/.bin/tool", "../../src/index.ts");
        selected_target.validate_for(&request()).unwrap();
    }

    #[test]
    fn literal_string_order_and_explicit_parents_are_required() {
        let mut request = request();
        request.directories.push("vittles/src-extra".to_owned());
        request.directories.sort();
        request.files.push(regular("vittles/src-extra/fixture.ts"));
        request
            .files
            .sort_by(|left, right| left.path.cmp(&right.path));
        request.validate().unwrap();
        let count = request.files.len();
        request.files.swap(count - 1, count - 2);
        assert!(request.validate().is_err());
        let mut missing_parent = inventory();
        missing_parent
            .directories
            .retain(|directory| directory != "vittles/node_modules/pkg");
        assert!(missing_parent.validate_for(&self::request()).is_err());
        let mut collision = inventory();
        collision
            .directories
            .push("vittles/node_modules/pkg/bin.js".to_owned());
        collision.directories.sort();
        assert!(collision.validate_for(&self::request()).is_err());
    }

    #[test]
    fn prior_input_changes_do_not_erase_output_ownership() {
        let request = request();
        let mut prior = state();
        prior.input_fingerprint = "f".repeat(64);
        prior.validate_for(&request).unwrap();
        prior.project.push_str("-another");
        assert!(prior.validate_for(&request).is_err());
    }

    #[test]
    fn state_and_inventory_changes_invalidate_recorded_digests() {
        let request = request();
        let mut changed = attestation();
        changed.state.inventory.files[1].sha256 = "f".repeat(64);
        assert!(changed.validate_for(&request).is_err());
        let mut changed = attestation();
        changed.state.root_inode += 1;
        assert!(changed.validate_for(&request).is_err());
        let mut changed = state();
        changed.frozen = false;
        assert!(changed.validate_for(&request).is_err());
    }

    #[test]
    fn filesystem_identifiers_preserve_full_u64_values_in_json_strings() {
        let mut state = state();
        state.root_device = (1_u64 << 53) + 1;
        state.root_inode = u64::MAX;
        let wire = serde_json::to_value(&state).unwrap();
        assert_eq!(wire["root_device"], "9007199254740993");
        assert_eq!(wire["root_inode"], "18446744073709551615");
        let restored: PreparedDependencyState = serde_json::from_value(wire).unwrap();
        assert_eq!(restored, state);
        assert_eq!(restored.digest().unwrap(), state.digest().unwrap());
        state.root_device = 0;
        state.root_inode = 1;
        let wire = serde_json::to_value(&state).unwrap();
        assert_eq!(wire["root_device"], "0");
        assert_eq!(wire["root_inode"], "1");
        assert_eq!(
            serde_json::from_value::<PreparedDependencyState>(wire).unwrap(),
            state
        );
    }

    #[test]
    fn filesystem_identifiers_refuse_numeric_and_noncanonical_wire_values() {
        for field in ["root_device", "root_inode"] {
            for value in [
                serde_json::json!(0),
                serde_json::json!(1),
                serde_json::json!((1_u64 << 53) + 1),
                serde_json::json!(u64::MAX),
                serde_json::json!(""),
                serde_json::json!("01"),
                serde_json::json!("+1"),
                serde_json::json!("-1"),
                serde_json::json!(" 1"),
                serde_json::json!("1 "),
                serde_json::json!("1.0"),
                serde_json::json!("1e3"),
                serde_json::json!("18446744073709551616"),
                serde_json::json!(null),
            ] {
                let mut wire = serde_json::to_value(state()).unwrap();
                wire[field] = value.clone();
                assert!(
                    serde_json::from_value::<PreparedDependencyState>(wire).is_err(),
                    "{field} accepted {value}"
                );
            }
        }
    }

    #[test]
    fn malformed_names_shapes_versions_and_bounds_are_refused() {
        for path in [
            "",
            "/absolute",
            "../escape",
            "a//b",
            "a/./b",
            "a/../b",
            "a\\b",
            "a\nb",
        ] {
            let inventory = PreparedDependencyInventory {
                files: vec![regular(path)],
                directories: vec![],
            };
            assert!(inventory.digest().is_err(), "{path:?}");
        }
        let mut excessive = inventory();
        excessive.files =
            vec![regular("vittles/node_modules/a"); MAX_PREPARED_DEPENDENCY_FILES + 1];
        assert!(excessive.digest().is_err());
        let mut excessive = inventory();
        excessive.files[1].byte_count = MAX_PREPARED_DEPENDENCY_BYTES + 1;
        assert!(excessive.digest().is_err());
        let mut duplicate = inventory();
        duplicate.files.push(duplicate.files[1].clone());
        assert!(duplicate.digest().is_err());
        let mut unknown = request();
        unknown.schema_version += 1;
        assert!(unknown.validate().is_err());
        let mut ambiguous_build = request();
        ambiguous_build.build_id.insert(0, '0');
        assert!(ambiguous_build.validate().is_err());
        let mut malformed_link = inventory();
        malformed_link.files[0].byte_count += 1;
        assert!(malformed_link.digest().is_err());
        let mut value = serde_json::to_value(request()).unwrap();
        value["ignore_unknown_sources"] = serde_json::json!(true);
        assert!(serde_json::from_value::<PreparedDependencyRequest>(value).is_err());
    }

    #[test]
    fn serialized_byte_limit_counts_json_escaping() {
        let plain = "x".repeat(MAX_PREPARED_DEPENDENCY_JSON_BYTES - 2);
        canonical_digest(&plain).unwrap();
        let escaped = "\\".repeat(MAX_PREPARED_DEPENDENCY_JSON_BYTES / 2);
        assert!(canonical_digest(&escaped).is_err());
    }

    #[test]
    fn canonical_digest_matches_exact_serde_json_and_root_cwd_is_empty() {
        let request = request();
        assert_eq!(
            request.digest().unwrap(),
            blake3::hash(&serde_json::to_vec(&request).unwrap())
                .to_hex()
                .to_string()
        );
        let mut root = request;
        root.project_relative.clear();
        root.files = vec![regular("package.json")];
        root.directories.clear();
        root.validate().unwrap();
        assert_eq!(admitted_dependency_roots(&root).unwrap(), ["node_modules"]);
        root.project_relative = ".".to_owned();
        assert!(root.validate().is_err());
    }
}
