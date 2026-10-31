//! The live rustc-output adapter. The CAS owns verification/private staging;
//! the edge owns subscriber dep-info derivation. Never drop a logical output
//! merely because it is not tagged `Materializable`.
//!
//! This connects rustc file materialization, not Cargo's subscriber delivery WAL.
//! A returned error or a lost socket reply never authorizes compiler execution.

use super::{ExpectedOutputs, ServeError, resolve_destination};
use crate::edge::dep_info::{
    DEP_INFO_DERIVATION_CONTRACT, DepInfoLine, DerivedDepInfo, derive_subscriber_dep_info,
    parse_dep_info, render_dep_info, rewritten_dep_info_token_len,
};
use rabs_cas::manifest_validation::{ManifestMember, ManifestMemberKind, validate_manifest};
use rabs_cas::materialization::{
    MaterializationMode, PlannedActionOutput, materialize_object,
    staged::{PreparationFailure, PreparedActionOutputs, SelectedActionOutputs},
};
use rabs_cas::metadata_store::{RabsMetadataStore, digest_key};
use rabs_protocol::result_identity::{CanonicalActionResultManifest, OutputRole, ResultKind};
use std::collections::{BTreeMap, BTreeSet};
use std::io::{Read, Seek, Write};
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::path::{Component, Path, PathBuf};
use std::time::SystemTime;

const MAX_DEP_INFO_BYTES: usize = 4 * 1024 * 1024;
const MAX_TOTAL_DEP_INFO_BYTES: usize = 16 * 1024 * 1024;
const MAX_MAPPINGS: usize = 64;
const MAX_MAPPING_PATH_BYTES: usize = 4096;

pub(super) struct PreparedOutputs {
    pub(super) outputs: Vec<PlannedActionOutput>,
    dep_info: BTreeMap<PathBuf, DerivedDepInfo>,
    freshness: SystemTime,
    action_key: String,
}

fn preparation(path: &Path, reason: impl ToString) -> ServeError {
    ServeError::Preparation {
        path: path.to_string_lossy().into_owned(),
        reason: reason.to_string(),
    }
}

fn expected_paths(expected: &ExpectedOutputs) -> Option<&BTreeSet<String>> {
    match expected {
        ExpectedOutputs::Exactly(paths)
        | ExpectedOutputs::WithDepInfo { paths, .. }
        | ExpectedOutputs::CanonicalCargo { paths, .. } => Some(paths),
        ExpectedOutputs::WhateverWasCommitted => None,
    }
}

/// Canonical-directory to subscriber-directory rewrites, longest match first.
type DirectoryMappings = Vec<(Vec<u8>, Vec<u8>)>;

/// Mappings name directories, not arbitrary byte prefixes. A trailing separator
/// guarantees that `workspace` cannot rewrite `workspace-other`. Longest match
/// wins and conflicting mappings for one canonical directory are refused.
/// The exact source `.` explicitly binds relative rustc paths to the
/// subscriber's compiler working directory. It is never inferred from root.
/// For example, `dep_info_mappings: [[".", "/home/agent/project"]]` resolves
/// `src/lib.rs` and `target/debug/libcrate.rlib` in that subscriber only.
fn directory_mappings(expected: &ExpectedOutputs) -> Result<DirectoryMappings, String> {
    let mappings = match expected {
        ExpectedOutputs::WithDepInfo { mappings, .. }
        | ExpectedOutputs::CanonicalCargo { mappings, .. } => mappings,
        _ => return Ok(Vec::new()),
    };
    if mappings.len() > MAX_MAPPINGS {
        return Err("too many dep-info mappings".into());
    }
    let directory = |raw: &[u8]| -> Result<Vec<u8>, String> {
        if raw.is_empty()
            || raw.len() > MAX_MAPPING_PATH_BYTES
            || raw[0] != b'/'
            || raw
                .iter()
                .any(|byte| matches!(byte, 0 | b'\n' | b'\r' | b'\t' | b':'))
        {
            return Err("dep-info mapping must be a bounded absolute Unix directory".into());
        }
        let raw = raw.strip_suffix(b"/").unwrap_or(raw);
        if raw.is_empty()
            || raw[1..]
                .split(|byte| *byte == b'/')
                .any(|part| part.is_empty() || part == b"." || part == b"..")
        {
            return Err("root, traversal and ambiguous dep-info mappings are unsupported".into());
        }
        let mut result = raw.to_vec();
        result.push(b'/');
        Ok(result)
    };
    let mut unique = BTreeMap::new();
    for (canonical, subscriber) in mappings {
        if canonical.as_slice() == b"."
            && matches!(expected, ExpectedOutputs::CanonicalCargo { .. })
        {
            return Err("canonical Cargo I/O mappings must name complete namespace roots".into());
        }
        let canonical = if canonical.as_slice() == b"." {
            canonical.clone()
        } else {
            directory(canonical)?
        };
        let subscriber = directory(subscriber)?;
        if (canonical.as_slice() != b"." && !canonical.starts_with(b"/__rabs/"))
            || subscriber.starts_with(b"/__rabs/")
        {
            return Err(
                "mapping must translate a canonical RABS directory or explicit . working directory to a subscriber directory"
                    .into(),
            );
        }
        if let Some(prior) = unique.insert(canonical, subscriber.clone())
            && prior != subscriber
        {
            return Err("conflicting dep-info mappings".into());
        }
    }
    let mut mappings: Vec<_> = unique.into_iter().collect();
    mappings.sort_by(|a, b| b.0.len().cmp(&a.0.len()).then_with(|| a.0.cmp(&b.0)));
    Ok(mappings)
}

/// Translate a canonical dep-info token for coordinator I/O only. Resolve
/// relative paths against the explicit compiler cwd, then normalize within the
/// selected retained root. Parent components cannot escape that root even
/// temporarily. The original .d bytes are never changed by this projection.
fn canonical_io_path(
    token: &[u8],
    working_directory: &[u8],
    mappings: &DirectoryMappings,
) -> Result<PathBuf, String> {
    if working_directory.len() > MAX_MAPPING_PATH_BYTES
        || !working_directory.starts_with(b"/__rabs/")
        || working_directory
            .iter()
            .any(|byte| matches!(byte, 0 | b'\n' | b'\r' | b'\t' | b':'))
        || working_directory
            .split(|byte| *byte == b'/')
            .skip(1)
            .any(|part| part.is_empty() || part == b"." || part == b"..")
        || !mappings.iter().any(|(source, _)| {
            source.strip_suffix(b"/") == Some(working_directory)
                || working_directory.starts_with(source)
        })
    {
        return Err("canonical dep-info cwd is outside its retained normalized roots".into());
    }
    if token.is_empty()
        || token
            .iter()
            .any(|byte| matches!(byte, 0 | b'\n' | b'\r' | b'\t'))
    {
        return Err("canonical dep-info contains an invalid path".into());
    }
    let absolute = if token.starts_with(b"/") {
        std::borrow::Cow::Borrowed(token)
    } else {
        let mut absolute = working_directory.to_vec();
        absolute.push(b'/');
        absolute.extend_from_slice(token);
        std::borrow::Cow::Owned(absolute)
    };
    let (source, backing) = mappings
        .iter()
        .find(|(source, _)| absolute.starts_with(source))
        .ok_or("canonical dep-info path is outside its retained roots")?;
    let mut components = Vec::new();
    for component in absolute[source.len()..].split(|byte| *byte == b'/') {
        match component {
            b"" | b"." => {}
            b".." => {
                components
                    .pop()
                    .ok_or("canonical dep-info path escapes its retained root")?;
            }
            component => components.push(component),
        }
    }
    if components.is_empty() {
        return Err("canonical dep-info path does not name a file".into());
    }
    let mut projected = backing.clone();
    for (index, component) in components.into_iter().enumerate() {
        if index != 0 {
            projected.push(b'/');
        }
        projected.extend_from_slice(component);
    }
    Ok(PathBuf::from(std::ffi::OsString::from_vec(projected)))
}

/// Bound the rendered expansion BEFORE derivation allocates replacement tokens.
/// The parser is the same versioned D028 parser used for the actual derivation.
fn check_expansion(canonical: &[u8], mappings: &[(Vec<u8>, Vec<u8>)]) -> Result<usize, String> {
    let parsed = parse_dep_info(canonical).map_err(|error| error.reason)?;
    if render_dep_info(&parsed) != canonical {
        return Err("dep-info is outside the lossless canonical grammar".into());
    }
    let token_len =
        |token: &[u8]| rewritten_dep_info_token_len(token, mappings).map_err(|error| error.reason);
    let mut total = 0_usize;
    for line in &parsed.lines {
        let length = match line {
            DepInfoLine::Rule { target, deps } => {
                let mut length = token_len(target)?.saturating_add(2);
                for dep in deps {
                    length = length.saturating_add(token_len(dep)?.saturating_add(1));
                }
                length
            }
            DepInfoLine::Comment(bytes) => bytes.len().saturating_add(1),
            DepInfoLine::Blank => 1,
        };
        total = total.saturating_add(length);
        if total > MAX_DEP_INFO_BYTES {
            return Err("derived dep-info exceeds byte limit".into());
        }
    }
    Ok(total)
}

/// Static path preflight complements, but does not replace, destination
/// ownership. This is not a claim of hostile-process or symlink-race isolation.
fn preflight_destination(path: &Path) -> Result<(), ServeError> {
    if !path.is_absolute()
        || path.components().any(|part| part == Component::ParentDir)
        || path.as_os_str().as_bytes().contains(&0)
    {
        return Err(preparation(
            path,
            "destination must be absolute and traversal-free",
        ));
    }
    let mut prefix = PathBuf::new();
    for part in path.components() {
        prefix.push(part.as_os_str());
        match std::fs::symlink_metadata(&prefix) {
            Ok(meta) if meta.file_type().is_symlink() => {
                return Err(preparation(path, "symlink in destination path"));
            }
            Ok(meta) if prefix != path && !meta.is_dir() => {
                return Err(preparation(path, "non-directory destination ancestor"));
            }
            Ok(meta) if prefix == path && !meta.is_file() => {
                return Err(preparation(path, "destination is not a regular file"));
            }
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => break,
            Err(error) => return Err(preparation(path, error)),
        }
    }
    Ok(())
}

/// Apply H027 to the COMPLETE output namespace before dep-info scratch reads
/// or destination writes. Exact-path checks alone miss case/normalization
/// aliases, including aliases in implicit parent directories.
///
/// The text projection is only a conservative REFUSAL key, never a pathname
/// or an action identity. Invalid UTF-8 sequences may collapse and cause a
/// safe refusal; accepted paths still use their original RawBytes throughout
/// resolution and installation. A lone non-UTF-8 filename remains lossless.
fn validate_output_namespace(
    manifest: &CanonicalActionResultManifest,
    root: &Path,
) -> Result<(), ServeError> {
    let members: Vec<_> = manifest
        .logical_outputs
        .iter()
        .map(|output| ManifestMember {
            path: String::from_utf8_lossy(output.virtual_path.as_bytes()).into_owned(),
            // This endpoint installs files, never directory/link declarations.
            kind: ManifestMemberKind::File,
        })
        .collect();
    validate_manifest(&members)
        .map_err(|error| preparation(root, format!("invalid output namespace: {error:?}")))
}

pub(super) fn prepare(
    store: &mut dyn RabsMetadataStore,
    manifest: &CanonicalActionResultManifest,
    root: &Path,
    expected: &ExpectedOutputs,
) -> Result<Result<PreparedOutputs, super::ServeOutcome>, ServeError> {
    if !root.is_absolute()
        || root.components().any(|part| part == Component::ParentDir)
        || root.as_os_str().as_bytes().contains(&0)
    {
        return Err(preparation(
            root,
            "destination root must be absolute and traversal-free",
        ));
    }
    // The file-only endpoint cannot replay a deterministic failure's exit or
    // observations. An empty output map is not evidence of compiler success.
    if manifest.result_kind != ResultKind::Success {
        return Err(preparation(
            root,
            "deterministic failure requires terminal-result delivery",
        ));
    }
    validate_output_namespace(manifest, root)?;
    if let Some(expected) = expected_paths(expected) {
        let committed = manifest
            .logical_outputs
            .iter()
            .map(|output| {
                std::str::from_utf8(output.virtual_path.as_bytes())
                    .map(str::to_owned)
                    .map_err(|_| ServeError::UnsafeVirtualPath {
                        path: output.virtual_path.escaped(),
                    })
            })
            .collect::<Result<BTreeSet<_>, _>>()?;
        if *expected != committed {
            return Ok(Err(super::ServeOutcome::OutputSetMismatch {
                missing: expected.difference(&committed).cloned().collect(),
                unexpected: committed.difference(expected).cloned().collect(),
            }));
        }
    }
    let mappings = directory_mappings(expected).map_err(|error| preparation(root, error))?;
    let mut outputs = Vec::with_capacity(manifest.logical_outputs.len());
    let mut destinations = BTreeSet::new();
    for output in &manifest.logical_outputs {
        if !matches!(
            output.role,
            OutputRole::Materializable | OutputRole::ProvisionalMetadata | OutputRole::DepInfo
        ) {
            return Err(preparation(
                root,
                format!("unsupported output role: {:?}", output.role),
            ));
        }
        let destination =
            resolve_destination(root, output.virtual_path.as_bytes()).ok_or_else(|| {
                ServeError::UnsafeVirtualPath {
                    path: output.virtual_path.escaped(),
                }
            })?;
        preflight_destination(&destination)?;
        let normalized: PathBuf = destination
            .components()
            .filter(|part| *part != Component::CurDir)
            .collect();
        if !destinations.insert(normalized) {
            return Err(preparation(
                &destination,
                "different logical outputs alias one destination",
            ));
        }
        outputs.push(PlannedActionOutput {
            role: output.role,
            virtual_path: output.virtual_path.clone(),
            object: output.object.0.clone(),
            destination,
        });
    }
    let ordered: Vec<_> = destinations.iter().collect();
    if ordered.windows(2).any(|pair| pair[1].starts_with(pair[0])) {
        return Err(preparation(
            root,
            "one output is an ancestor of another output",
        ));
    }

    // Every .d is byte-verified and its complete I/O contract checked before ANY
    // target output is installed. Canonical Cargo keeps its original bytes;
    // ordinary subscribers receive a private derivation. Refusal writes scratch only.
    let mut dep_info = BTreeMap::new();
    let mut total_derived_bytes = 0_usize;
    let mut freshness = SystemTime::now();
    for (index, output) in outputs
        .iter()
        .enumerate()
        .filter(|(_, out)| out.role == OutputRole::DepInfo)
    {
        let scratch =
            tempfile::tempdir().map_err(|error| preparation(&output.destination, error))?;
        let canonical_path = scratch.path().join(format!("dep-{index}"));
        materialize_object(
            store,
            &output.object,
            &canonical_path,
            MaterializationMode::PrivateCopy,
        )
        .map_err(|error| preparation(&output.destination, error))?;
        let file = std::fs::File::open(&canonical_path)
            .map_err(|error| preparation(&output.destination, error))?;
        let mut canonical = Vec::new();
        file.take(MAX_DEP_INFO_BYTES as u64 + 1)
            .read_to_end(&mut canonical)
            .map_err(|error| preparation(&output.destination, error))?;
        if canonical.len() > MAX_DEP_INFO_BYTES {
            return Err(preparation(
                &output.destination,
                "canonical dep-info exceeds byte limit",
            ));
        }
        let canonical_cwd = match expected {
            ExpectedOutputs::CanonicalCargo {
                working_directory, ..
            } => Some(working_directory),
            _ => None,
        };
        let expanded = if canonical_cwd.is_some() {
            canonical.len()
        } else {
            check_expansion(&canonical, &mappings)
                .map_err(|error| preparation(&output.destination, error))?
        };
        total_derived_bytes = total_derived_bytes
            .checked_add(expanded)
            .filter(|total| *total <= MAX_TOTAL_DEP_INFO_BYTES)
            .ok_or_else(|| {
                preparation(
                    &output.destination,
                    "complete dep-info set exceeds byte limit",
                )
            })?;
        let (derived, parsed) = if canonical_cwd.is_some() {
            let parsed = parse_dep_info(&canonical)
                .map_err(|error| preparation(&output.destination, error.reason))?;
            if render_dep_info(&parsed) != canonical {
                return Err(preparation(
                    &output.destination,
                    "canonical dep-info is outside the lossless grammar",
                ));
            }
            (None, parsed)
        } else {
            let derived = derive_subscriber_dep_info(&canonical, &mappings)
                .map_err(|error| preparation(&output.destination, error.reason))?;
            if derived.bytes.len() != expanded {
                return Err(preparation(
                    &output.destination,
                    "dep-info derivation size differs from the validated grammar",
                ));
            }
            let parsed = parse_dep_info(&derived.bytes)
                .map_err(|error| preparation(&output.destination, error.reason))?;
            (Some(derived), parsed)
        };
        let io_path = |bytes: Vec<u8>| -> Result<PathBuf, ServeError> {
            match canonical_cwd {
                Some(cwd) => canonical_io_path(&bytes, cwd, &mappings)
                    .map_err(|error| preparation(&output.destination, error)),
                None => Ok(PathBuf::from(std::ffi::OsString::from_vec(bytes))),
            }
        };
        let mut declared_target_seen = false;
        for line in parsed.lines {
            if let DepInfoLine::Rule { target, deps } = line {
                let target = io_path(target)?;
                let normalized: PathBuf = target
                    .components()
                    .filter(|part| *part != Component::CurDir)
                    .collect();
                let declared = destinations.contains(&normalized);
                declared_target_seen |= declared;
                // Empty dependency rules are rustc's source-file phony rules.
                // Rules WITH prerequisites must describe one declared output,
                // not another worktree selected by a mistaken mapping.
                if !deps.is_empty() && !declared {
                    return Err(preparation(
                        &output.destination,
                        "dep-info target is outside the declared output set",
                    ));
                }
                for dep in deps {
                    let input = io_path(dep)?;
                    // rustc reports `include_str!("../../README.md")` from
                    // `src/` as `<abs>/src/../../README.md`. Publication's
                    // closure check already proved such a read inside the
                    // keyed, symlink-free capture, and Cargo stats exactly
                    // this spelling for freshness, so stat it as written.
                    // Only a cwd-relative spelling lacks a contract.
                    if !input.is_absolute() {
                        return Err(preparation(
                            &output.destination,
                            "relative dep-info inputs require a subscriber working-directory contract",
                        ));
                    }
                    let modified = std::fs::metadata(&input)
                        .and_then(|meta| meta.modified())
                        .map_err(|error| {
                            preparation(
                                &output.destination,
                                format!("dep-info input unavailable: {error}"),
                            )
                        })?;
                    freshness = freshness.max(modified);
                }
            }
        }
        if !declared_target_seen {
            return Err(preparation(
                &output.destination,
                "dep-info has no declared output target",
            ));
        }
        if let Some(derived) = derived {
            dep_info.insert(output.destination.clone(), derived);
        }
    }
    Ok(Ok(PreparedOutputs {
        outputs,
        dep_info,
        freshness,
        action_key: digest_key(&manifest.action_key),
    }))
}

pub(super) fn select_for_install(
    store: &mut dyn RabsMetadataStore,
    plan: &PreparedOutputs,
) -> Result<SelectedActionOutputs, ServeError> {
    SelectedActionOutputs::select(
        store,
        &plan.outputs,
        MaterializationMode::VerifiedCowReflink,
        plan.freshness,
    )
    .map_err(ServeError::Materialize)
}

#[allow(clippy::result_large_err)]
pub(super) fn stage_for_install(
    selected: SelectedActionOutputs,
    plan: &PreparedOutputs,
) -> Result<PreparedActionOutputs, PreparationFailure> {
    selected.stage(&|output, staged| {
        if let Some(derived) = plan.dep_info.get(&output.destination) {
            let mut staged = staged.try_clone()?;
            staged.rewind()?;
            staged.set_len(0)?;
            staged.write_all(&derived.bytes)?;
        }
        Ok(())
    })
}

pub(super) fn settle_stage_failure(
    store: &mut dyn RabsMetadataStore,
    failure: PreparationFailure,
) -> ServeError {
    ServeError::Materialize(failure.settle(store))
}

/// Recheck every installed dep-info file before early artifact notification.
/// Ordinary subscribers receive derived bytes, whose identity deliberately
/// differs from the canonical CAS object. Canonical Cargo keeps the original.
/// The coordinator calls this without its store lock and retains the complete
/// destination reservation; no receipt or serving authority is created here.
pub(super) fn verify_installed_dep_info(
    plan: &PreparedOutputs,
    installed: &[PathBuf],
) -> Result<(), ServeError> {
    use crate::edge::live_facts::read_stable;
    use rabs_cas::digest_set::{DigestRequest, digest_set};

    for output in plan
        .outputs
        .iter()
        .filter(|output| output.role == OutputRole::DepInfo)
    {
        let path = &output.destination;
        if !installed.contains(path) {
            return Err(preparation(
                path,
                "dep-info is absent from the installed metadata head",
            ));
        }
        let derived = plan.dep_info.get(path);
        let limit = derived.map_or(MAX_DEP_INFO_BYTES, |derived| derived.bytes.len());
        let (_, bytes) =
            read_stable(path, limit as u64).map_err(|error| preparation(path, error))?;
        let matches = match derived {
            Some(derived) => bytes == derived.bytes,
            None => {
                digest_set(&bytes, DigestRequest::default(), None)
                    .map_err(|error| preparation(path, format!("{error:?}")))?
                    .atp_content_id
                    == output.object
            }
        };
        if !matches {
            return Err(preparation(
                path,
                "installed dep-info differs from its prepared bytes",
            ));
        }
    }
    Ok(())
}

pub(super) fn install_prepared(
    store: &mut dyn RabsMetadataStore,
    plan: &PreparedOutputs,
    prepared: PreparedActionOutputs,
) -> Result<Vec<PathBuf>, ServeError> {
    install_prepared_logged(store, plan, prepared, &mut std::io::stderr().lock())
}

fn install_prepared_logged(
    store: &mut dyn RabsMetadataStore,
    plan: &PreparedOutputs,
    prepared: PreparedActionOutputs,
    log: &mut impl Write,
) -> Result<Vec<PathBuf>, ServeError> {
    let receipt = prepared.install(store).map_err(ServeError::Materialize)?;
    for output in &receipt.installed {
        let destination = &output.destination;
        let Some(derived) = plan.dep_info.get(destination) else {
            continue;
        };
        // Digests distinguish canonical identity from subscriber derivation.
        // Never log raw dep-info or source/environment contents.
        // A diagnostic sink failure must not hide a completed installation.
        let _ = writeln!(
            log,
            "{}",
            serde_json::json!({
                "kind": "rabs-dep-info-installed", "action_key": plan.action_key,
                "contract": DEP_INFO_DERIVATION_CONTRACT,
                "destination_bytes": destination.as_os_str().as_bytes(),
                "canonical_sha256": derived.derivation.canonical_sha256,
                "derived_sha256": derived.derivation.derived_sha256,
            })
        );
    }
    Ok(receipt
        .installed
        .into_iter()
        .map(|output| output.destination)
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn expected(mappings: &[(&[u8], &[u8])]) -> ExpectedOutputs {
        ExpectedOutputs::WithDepInfo {
            paths: BTreeSet::new(),
            mappings: mappings
                .iter()
                .map(|(a, b)| (a.to_vec(), b.to_vec()))
                .collect(),
        }
    }

    #[test]
    fn directory_boundaries_and_longest_prefix_are_enforced_before_derivation() {
        let mappings = directory_mappings(&expected(&[
            (b"/__rabs/workspace", b"/local/workspace"),
            (b"/__rabs/workspace/vendor", b"/local/dependencies"),
        ]))
        .unwrap();
        assert_eq!(mappings[0].0, b"/__rabs/workspace/vendor/");
        let canonical = b"/__rabs/workspace/out.rmeta: /__rabs/workspace/vendor/lib.rs\n";
        check_expansion(canonical, &mappings).unwrap();
        let derived = derive_subscriber_dep_info(canonical, &mappings).unwrap();
        assert_eq!(
            derived.bytes,
            b"/local/workspace/out.rmeta: /local/dependencies/lib.rs\n"
        );
        let neighboring = b"/__rabs/workspace-other/out.rmeta: /__rabs/workspace/src/lib.rs\n";
        assert!(derive_subscriber_dep_info(neighboring, &mappings).is_err());
    }

    #[test]
    fn mapping_bytes_are_lossless_but_ambiguous_directories_refuse() {
        let mappings = directory_mappings(&expected(&[(
            b"/__rabs/workspace/",
            b"/local/nonutf8-\xff/",
        )]))
        .unwrap();
        let derived = derive_subscriber_dep_info(b"/__rabs/workspace/out:\n", &mappings);
        assert!(derived.is_ok());
        assert!(
            derived
                .unwrap()
                .bytes
                .starts_with(b"/local/nonutf8-\xff/out:")
        );
        for invalid in [
            &b"relative"[..],
            &b"/"[..],
            &b"/local//tree"[..],
            &b"/local/../tree"[..],
            &b"/local/./tree"[..],
            &b"/local\0tree"[..],
            &b"/local:\n"[..],
            &b"/__rabs/out"[..],
        ] {
            assert!(directory_mappings(&expected(&[(b"/__rabs/workspace", invalid)])).is_err());
        }
        assert!(
            directory_mappings(&expected(&[
                (b"/__rabs/workspace", b"/first"),
                (b"/__rabs/workspace/", b"/second"),
            ]))
            .is_err()
        );
    }

    #[test]
    fn expansion_limit_is_checked_before_large_replacement_allocation() {
        let mut long_path = b"/local/".to_vec();
        long_path.resize(MAX_MAPPING_PATH_BYTES, b'x');
        let mappings =
            directory_mappings(&expected(&[(b"/__rabs/workspace", &long_path)])).unwrap();
        let mut canonical = b"/__rabs/workspace/out:".to_vec();
        for _ in 0..1100 {
            canonical.extend_from_slice(b" /__rabs/workspace/in");
        }
        canonical.push(b'\n');
        assert!(canonical.len() < MAX_DEP_INFO_BYTES);
        assert!(check_expansion(&canonical, &mappings).is_err());
    }

    #[test]
    fn noncanonical_dep_info_grammar_cannot_be_silently_rewritten() {
        for bytes in [
            &b"out:  input\n"[..],
            &b"out: input"[..],
            &b"out: input\\\ncontinued\n"[..],
            &b"out: unsupported\\q\n"[..],
        ] {
            assert!(check_expansion(bytes, &[]).is_err(), "{bytes:?}");
        }
    }

    #[test]
    fn a_deterministic_failure_is_not_a_successful_empty_file_delivery() {
        let directory = tempfile::tempdir().unwrap();
        let cas =
            crate::janitor::store::mount_and_reconcile(&directory.path().join("cas")).unwrap();
        let mut manifest = rabs_cas::test_support::sample_manifest();
        manifest.result_kind = ResultKind::DeterministicFailure;
        manifest.logical_outputs.clear();
        manifest.artifact_bundle_root = None;
        let destination = directory.path().join("failure");
        assert!(matches!(
            prepare(
                &mut *cas.store().lock().unwrap(),
                &manifest,
                &destination,
                &ExpectedOutputs::Exactly(BTreeSet::new()),
            ),
            Err(ServeError::Preparation { .. })
        ));
        assert!(!destination.exists());
    }

    fn outputs_named(paths: &[&[u8]]) -> CanonicalActionResultManifest {
        let mut manifest = rabs_cas::test_support::sample_manifest();
        let template = manifest.logical_outputs[0].clone();
        manifest.logical_outputs = paths
            .iter()
            .map(|path| {
                let mut output = template.clone();
                output.virtual_path = rabs_protocol::raw_bytes::RawBytes::new(path.to_vec());
                output
            })
            .collect();
        manifest
    }

    #[test]
    fn complete_namespace_refuses_platform_aliases_before_any_materialization() {
        let directory = tempfile::tempdir().unwrap();
        let cas =
            crate::janitor::store::mount_and_reconcile(&directory.path().join("cas")).unwrap();
        let root = directory.path().join("outputs");
        let cases: &[&[&[u8]]] = &[
            &[b"out/Lib.rlib", b"out/lib.rlib"],
            &[b"Out/head.rmeta", b"out/tail.rlib"],
            &[
                "out/caf\u{e9}/head".as_bytes(),
                "out/cafe\u{301}/tail".as_bytes(),
            ],
            &[b"out/file", b"out/file/child"],
            &[b"out/dir/head", b"out/Dir"],
        ];
        for paths in cases {
            for reverse in [false, true] {
                let mut manifest = outputs_named(paths);
                if reverse {
                    manifest.logical_outputs.reverse();
                }
                let result = prepare(
                    &mut *cas.store().lock().unwrap(),
                    &manifest,
                    &root,
                    &ExpectedOutputs::WhateverWasCommitted,
                );
                assert!(
                    matches!(
                        result,
                        Err(ServeError::Preparation { reason, .. })
                            if reason.starts_with("invalid output namespace:")
                    ),
                    "accepted aliases {paths:?}, reverse={reverse}",
                );
                assert!(!root.exists());
            }
        }
    }

    #[test]
    fn namespace_validation_precedes_even_the_first_dep_info_cas_read() {
        let directory = tempfile::tempdir().unwrap();
        let cas =
            crate::janitor::store::mount_and_reconcile(&directory.path().join("cas")).unwrap();
        let root = directory.path().join("outputs");
        let mut manifest = outputs_named(&[b"Out/crate.d", b"out/crate.rlib"]);
        // This object deliberately has no CAS location. A per-file validator
        // would attempt its materialization before seeing the later alias.
        manifest.logical_outputs[0].role = OutputRole::DepInfo;
        let result = prepare(
            &mut *cas.store().lock().unwrap(),
            &manifest,
            &root,
            &ExpectedOutputs::WhateverWasCommitted,
        );
        assert!(matches!(
            result,
            Err(ServeError::Preparation { reason, .. })
                if reason.starts_with("invalid output namespace:")
        ));
        assert!(!root.exists());
    }

    #[test]
    fn unsafe_member_spellings_never_reach_the_live_destination() {
        let root = Path::new("/unused/output-root");
        for path in [
            &b"out//file"[..],
            b"out/./file",
            b"out/../file",
            b"out/file/",
            b"/absolute",
            b"out/nul\0file",
            b"out/a\\b",
            b"out/a:b",
        ] {
            assert!(validate_output_namespace(&outputs_named(&[path]), root).is_err());
        }
    }

    #[test]
    fn byte_paths_remain_lossless_in_a_valid_live_plan() {
        let directory = tempfile::tempdir().unwrap();
        let cas =
            crate::janitor::store::mount_and_reconcile(&directory.path().join("cas")).unwrap();
        let root = directory
            .path()
            .canonicalize()
            .unwrap()
            .join(std::ffi::OsString::from_vec(b"root-\xfe".to_vec()));
        let paths: &[&[u8]] = &[b"out/crate-\xff.rlib", b"out/crate.rmeta"];
        let manifest = outputs_named(paths);
        let plan = match prepare(
            &mut *cas.store().lock().unwrap(),
            &manifest,
            &root,
            &ExpectedOutputs::WhateverWasCommitted,
        ) {
            Ok(Ok(plan)) => plan,
            _ => panic!("safe byte-preserving output plan refused"),
        };
        for (output, path) in plan.outputs.iter().zip(paths) {
            assert_eq!(output.virtual_path.as_bytes(), *path);
            assert_eq!(
                output.destination,
                root.join(std::ffi::OsStr::from_bytes(path)),
            );
        }
        assert!(!root.exists());
    }

    #[test]
    fn ambiguous_invalid_utf8_projection_refuses_instead_of_renaming_paths() {
        let manifest = outputs_named(&[b"out/crate-\xff.rlib", b"out/crate-\xfe.rlib"]);
        assert!(validate_output_namespace(&manifest, Path::new("/unused/root")).is_err());
        assert_eq!(
            manifest.logical_outputs[0].virtual_path.as_bytes(),
            b"out/crate-\xff.rlib",
        );
        assert_eq!(
            manifest.logical_outputs[1].virtual_path.as_bytes(),
            b"out/crate-\xfe.rlib",
        );
    }

    #[test]
    fn relative_path_expansion_uses_the_same_working_directory_plan_as_derivation() {
        let mappings = directory_mappings(&expected(&[
            (b".", b"/subscriber with#space-\xff"),
            (b"/__rabs/toolchain", b"/local/toolchain"),
        ]))
        .unwrap();
        let canonical =
            b"target/unit.rmeta: ./src/lib.rs /__rabs/toolchain/lib/core.rlib\n\n./src/lib.rs:\n";
        let expanded = check_expansion(canonical, &mappings).unwrap();
        let derived = derive_subscriber_dep_info(canonical, &mappings).unwrap();
        assert_eq!(expanded, derived.bytes.len());
        assert_eq!(
            render_dep_info(&parse_dep_info(&derived.bytes).unwrap()),
            derived.bytes
        );
        assert!(
            derived
                .bytes
                .starts_with(b"/subscriber\\ with\\#space-\xff/target/unit.rmeta:")
        );
    }

    #[test]
    fn working_directory_mapping_is_explicit_unique_and_absolute() {
        let mappings =
            directory_mappings(&expected(&[(b".", b"/worktree"), (b".", b"/worktree/")])).unwrap();
        assert_eq!(mappings, vec![(b".".to_vec(), b"/worktree/".to_vec())]);
        assert!(directory_mappings(&expected(&[(b".", b"/first"), (b".", b"/second"),])).is_err());
        for directory in [
            &b"relative"[..],
            b"/",
            b"/tree/../other",
            b"/__rabs/workspace",
        ] {
            assert!(directory_mappings(&expected(&[(b".", directory)])).is_err());
        }
        for source in [&b"./"[..], b"..", b"src"] {
            assert!(directory_mappings(&expected(&[(source, b"/worktree")])).is_err());
        }
    }

    #[test]
    fn working_directory_growth_is_bounded_before_allocating_relative_replacements() {
        let mut directory = b"/subscriber/".to_vec();
        directory.resize(MAX_MAPPING_PATH_BYTES, b'x');
        let mappings = directory_mappings(&expected(&[(b".", &directory)])).unwrap();
        let mut canonical = b"target/unit:".to_vec();
        for _ in 0..1100 {
            canonical.extend_from_slice(b" src/lib.rs");
        }
        canonical.push(b'\n');
        assert!(canonical.len() < MAX_DEP_INFO_BYTES);
        assert!(check_expansion(&canonical, &mappings).is_err());
    }

    #[test]
    fn canonical_io_projection_resolves_only_inside_retained_roots() {
        let contract = ExpectedOutputs::CanonicalCargo {
            paths: BTreeSet::new(),
            working_directory: b"/__rabs/workspace/member".to_vec(),
            mappings: vec![
                (b"/__rabs/workspace".to_vec(), b"/private/source".to_vec()),
                (b"/__rabs/out/cargo".to_vec(), b"/private/target".to_vec()),
            ],
        };
        let mappings = directory_mappings(&contract).unwrap();
        let cwd = b"/__rabs/workspace/member";
        for (logical, physical) in [
            (&b"src/lib.rs"[..], "/private/source/member/src/lib.rs"),
            (&b"../README.md"[..], "/private/source/README.md"),
            (&b"src/../../README.md"[..], "/private/source/README.md"),
            (
                &b"/__rabs/out/cargo/debug/deps/libunit.rmeta"[..],
                "/private/target/debug/deps/libunit.rmeta",
            ),
        ] {
            assert_eq!(
                canonical_io_path(logical, cwd, &mappings).unwrap(),
                Path::new(physical)
            );
        }
        for logical in [
            &b"../../outside"[..],
            b"/__rabs/workspace/../workspace/member/src/lib.rs",
            b"/__rabs/workspace-other/src/lib.rs",
            b"/unobserved/source.rs",
            b"/__rabs/workspace",
        ] {
            assert!(
                canonical_io_path(logical, cwd, &mappings).is_err(),
                "{logical:?}"
            );
        }
        assert!(canonical_io_path(b"src/lib.rs", b"/__rabs/unknown", &mappings).is_err());
    }

    #[test]
    fn canonical_cargo_install_preserves_dep_info_and_uses_backing_input_freshness() {
        use rabs_cas::blob_store::{DurabilityPolicy, PutLimits, put_if_absent};
        use rabs_cas::digest_set::{DigestRequest, digest_set};
        use rabs_protocol::raw_bytes::RawBytes;
        use rabs_protocol::result_identity::{LogicalOutput, ObjectId};

        let directory = crate::test_util::private_tempdir();
        let cas =
            crate::janitor::store::mount_and_reconcile(&directory.path().join("cas")).unwrap();
        let workspace = directory.path().join("source");
        let target = directory.path().join("target");
        std::fs::create_dir_all(workspace.join("member/src")).unwrap();
        std::fs::create_dir_all(target.join("debug/deps")).unwrap();
        std::fs::write(workspace.join("member/src/lib.rs"), b"pub fn unit() {}\n").unwrap();
        std::fs::write(workspace.join("README.md"), b"workspace documentation\n").unwrap();
        let future = SystemTime::now() + std::time::Duration::from_secs(3600);
        std::fs::File::open(workspace.join("README.md"))
            .unwrap()
            .set_times(std::fs::FileTimes::new().set_modified(future))
            .unwrap();
        let metadata = b"verified compiler metadata";
        let dep_info = b"/__rabs/out/cargo/debug/deps/libunit.rmeta: src/lib.rs ../README.md\n\nsrc/lib.rs:\n../README.md:\n";
        let put = |bytes: &[u8]| {
            let id = digest_set(bytes, DigestRequest::default(), None)
                .unwrap()
                .atp_content_id;
            put_if_absent(
                cas.layout(),
                &mut *cas.store().lock().unwrap(),
                &id,
                &mut &bytes[..],
                PutLimits::default(),
                DurabilityPolicy::FULL,
            )
            .unwrap();
            ObjectId(id)
        };
        let mut manifest = rabs_cas::test_support::sample_manifest();
        manifest.result_kind = ResultKind::Success;
        manifest.artifact_bundle_root = None;
        manifest.logical_outputs = vec![
            LogicalOutput {
                role: OutputRole::ProvisionalMetadata,
                virtual_path: RawBytes::from("libunit.rmeta"),
                object: put(metadata),
            },
            LogicalOutput {
                role: OutputRole::DepInfo,
                virtual_path: RawBytes::from("unit.d"),
                object: put(dep_info),
            },
        ];
        let contract = ExpectedOutputs::CanonicalCargo {
            paths: BTreeSet::from(["libunit.rmeta".into(), "unit.d".into()]),
            working_directory: b"/__rabs/workspace/member".to_vec(),
            mappings: vec![
                (
                    b"/__rabs/workspace".to_vec(),
                    workspace.as_os_str().as_bytes().to_vec(),
                ),
                (
                    b"/__rabs/out/cargo".to_vec(),
                    target.as_os_str().as_bytes().to_vec(),
                ),
            ],
        };
        let destination = target.join("debug/deps");
        let plan = match prepare(
            &mut *cas.store().lock().unwrap(),
            &manifest,
            &destination,
            &contract,
        )
        .unwrap()
        {
            Ok(plan) => plan,
            Err(refusal) => panic!("canonical output plan refused: {refusal:?}"),
        };
        assert!(
            plan.dep_info.is_empty(),
            "canonical bytes must not be replaced by a backing-path derivation"
        );
        let selected = select_for_install(&mut *cas.store().lock().unwrap(), &plan).unwrap();
        let prepared = stage_for_install(selected, &plan).unwrap();
        let files = install_prepared(&mut *cas.store().lock().unwrap(), &plan, prepared).unwrap();
        assert_eq!(files.len(), 2);
        assert_eq!(std::fs::read(destination.join("unit.d")).unwrap(), dep_info);
        assert_eq!(
            std::fs::read(destination.join("libunit.rmeta")).unwrap(),
            metadata
        );
        verify_installed_dep_info(&plan, &files).unwrap();
        for file in &files {
            assert!(std::fs::metadata(file).unwrap().modified().unwrap() >= future);
        }
        std::fs::write(destination.join("unit.d"), b"changed canonical dep-info\n").unwrap();
        assert!(verify_installed_dep_info(&plan, &files).is_err());
    }

    #[test]
    fn phased_install_derives_and_verifies_dep_info_before_metadata_notification() {
        use rabs_cas::blob_store::{DurabilityPolicy, PutLimits, put_if_absent};
        use rabs_cas::digest_set::{DigestRequest, digest_set};
        use rabs_protocol::raw_bytes::RawBytes;
        use rabs_protocol::result_identity::{LogicalOutput, ObjectId};

        let directory = crate::test_util::private_tempdir();
        let cas =
            crate::janitor::store::mount_and_reconcile(&directory.path().join("cas")).unwrap();
        let source = directory.path().join("source");
        let destination = directory.path().join("target");
        std::fs::create_dir(&source).unwrap();
        std::fs::write(source.join("lib.rs"), b"pub fn unit() {}\n").unwrap();
        let future = SystemTime::now() + std::time::Duration::from_secs(3600);
        std::fs::File::open(source.join("lib.rs"))
            .unwrap()
            .set_times(std::fs::FileTimes::new().set_modified(future))
            .unwrap();
        let canonical = b"/__rabs/out/libunit.rmeta: /__rabs/source/lib.rs\n";
        let put = |bytes: &[u8]| {
            let id = digest_set(bytes, DigestRequest::default(), None)
                .unwrap()
                .atp_content_id;
            put_if_absent(
                cas.layout(),
                &mut *cas.store().lock().unwrap(),
                &id,
                &mut &bytes[..],
                PutLimits::default(),
                DurabilityPolicy::FULL,
            )
            .unwrap();
            ObjectId(id)
        };
        let mut manifest = rabs_cas::test_support::sample_manifest();
        manifest.result_kind = ResultKind::Success;
        manifest.artifact_bundle_root = None;
        manifest.logical_outputs = vec![
            LogicalOutput {
                role: OutputRole::ProvisionalMetadata,
                virtual_path: RawBytes::from("libunit.rmeta"),
                object: put(b"metadata"),
            },
            LogicalOutput {
                role: OutputRole::Materializable,
                virtual_path: RawBytes::from("libunit.rlib"),
                object: put(b"archive"),
            },
            LogicalOutput {
                role: OutputRole::DepInfo,
                virtual_path: RawBytes::from("unit.d"),
                object: put(canonical),
            },
        ];
        let contract = ExpectedOutputs::WithDepInfo {
            paths: BTreeSet::from([
                "libunit.rmeta".into(),
                "libunit.rlib".into(),
                "unit.d".into(),
            ]),
            mappings: vec![
                (
                    b"/__rabs/source".to_vec(),
                    source.as_os_str().as_bytes().to_vec(),
                ),
                (
                    b"/__rabs/out".to_vec(),
                    destination.as_os_str().as_bytes().to_vec(),
                ),
            ],
        };
        let plan = match prepare(
            &mut *cas.store().lock().unwrap(),
            &manifest,
            &destination,
            &contract,
        )
        .unwrap()
        {
            Ok(plan) => plan,
            Err(refusal) => panic!("output plan refused: {refusal:?}"),
        };
        assert_eq!(plan.dep_info.len(), 1);
        let expected_dep_info = plan.dep_info[&destination.join("unit.d")].bytes.clone();
        let (head, tail) = select_for_install(&mut *cas.store().lock().unwrap(), &plan)
            .unwrap()
            .split_metadata();
        let mut log = Vec::new();
        let prepared_head = stage_for_install(head.unwrap(), &plan).unwrap();
        let files = install_prepared_logged(
            &mut *cas.store().lock().unwrap(),
            &plan,
            prepared_head,
            &mut log,
        )
        .unwrap();
        assert_eq!(
            files,
            vec![
                destination.join("libunit.rmeta"),
                destination.join("unit.d")
            ]
        );
        assert_eq!(std::fs::read(&files[0]).unwrap(), b"metadata");
        for file in &files {
            assert!(std::fs::metadata(file).unwrap().modified().unwrap() >= future);
        }
        assert_ne!(expected_dep_info, canonical);
        assert_eq!(
            std::fs::read(destination.join("unit.d")).unwrap(),
            expected_dep_info
        );
        verify_installed_dep_info(&plan, &files).unwrap();
        assert!(verify_installed_dep_info(&plan, &files[..1]).is_err());
        assert_eq!(String::from_utf8(log.clone()).unwrap().lines().count(), 1);
        assert!(!destination.join("libunit.rlib").exists());
        let head_files = files;
        let prepared_tail = stage_for_install(tail, &plan).unwrap();
        let files = install_prepared_logged(
            &mut *cas.store().lock().unwrap(),
            &plan,
            prepared_tail,
            &mut log,
        )
        .unwrap();
        assert_eq!(files, vec![destination.join("libunit.rlib")]);
        assert_eq!(
            std::fs::read(destination.join("libunit.rlib")).unwrap(),
            b"archive"
        );
        assert_eq!(
            std::fs::read(destination.join("unit.d")).unwrap(),
            expected_dep_info
        );
        for file in files {
            assert!(std::fs::metadata(file).unwrap().modified().unwrap() >= future);
        }
        let text = String::from_utf8(log).unwrap();
        let events: Vec<serde_json::Value> = text
            .lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0]["kind"], "rabs-dep-info-installed");
        assert_eq!(
            events[0]["destination_bytes"],
            serde_json::json!(destination.join("unit.d").as_os_str().as_bytes())
        );
        // Canonical bytes are valid CAS content but not valid subscriber bytes.
        // A post-install replacement must be refused before forwarding events.
        std::fs::write(destination.join("unit.d"), canonical).unwrap();
        assert!(verify_installed_dep_info(&plan, &head_files).is_err());
    }
}
