//! The live rustc-output adapter. The CAS owns verification/private staging;
//! the edge owns subscriber dep-info derivation. Never drop a logical output
//! merely because it is not tagged `Materializable`.
//!
//! This connects rustc file materialization, not Cargo's subscriber delivery WAL.
//! A returned error or a lost socket reply never authorizes compiler execution.

use super::{ExpectedOutputs, ServeError, resolve_destination};
use crate::edge::dep_info::{
    DEP_INFO_DERIVATION_CONTRACT, DepInfoLine, DerivedDepInfo,
    derive_subscriber_dep_info, parse_dep_info, render_dep_info,
};
use rabs_cas::materialization::{
    MaterializationMode, PlannedActionOutput, materialize_action_outputs_prepared,
    materialize_object,
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
        ExpectedOutputs::Exactly(paths) | ExpectedOutputs::WithDepInfo { paths, .. } => Some(paths),
        ExpectedOutputs::WhateverWasCommitted => None,
    }
}

/// Mappings name directories, not arbitrary byte prefixes. A trailing separator
/// guarantees that `workspace` cannot rewrite `workspace-other`. Longest match
/// wins and conflicting mappings for one canonical directory are refused.
fn directory_mappings(expected: &ExpectedOutputs) -> Result<Vec<(Vec<u8>, Vec<u8>)>, String> {
    let ExpectedOutputs::WithDepInfo { mappings, .. } = expected else { return Ok(Vec::new()); };
    if mappings.len() > MAX_MAPPINGS { return Err("too many dep-info mappings".into()); }
    let directory = |raw: &[u8]| -> Result<Vec<u8>, String> {
        if raw.is_empty() || raw.len() > MAX_MAPPING_PATH_BYTES || raw[0] != b'/'
            || raw.iter().any(|byte| matches!(byte, 0 | b'\n' | b'\r' | b'\t' | b':'))
        {
            return Err("dep-info mapping must be a bounded absolute Unix directory".into());
        }
        let raw = raw.strip_suffix(b"/").unwrap_or(raw);
        if raw.is_empty() || raw[1..].split(|byte| *byte == b'/')
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
        let canonical = directory(canonical)?;
        let subscriber = directory(subscriber)?;
        if !canonical.starts_with(b"/__rabs/") || subscriber.starts_with(b"/__rabs/") {
            return Err("mapping must translate a canonical RABS directory to a subscriber directory".into());
        }
        if let Some(prior) = unique.insert(canonical, subscriber.clone()) && prior != subscriber {
            return Err("conflicting dep-info mappings".into());
        }
    }
    let mut mappings: Vec<_> = unique.into_iter().collect();
    mappings.sort_by(|a, b| b.0.len().cmp(&a.0.len()).then_with(|| a.0.cmp(&b.0)));
    Ok(mappings)
}

/// Bound the rendered expansion BEFORE derivation allocates replacement tokens.
/// The parser is the same versioned D028 parser used for the actual derivation.
fn check_expansion(canonical: &[u8], mappings: &[(Vec<u8>, Vec<u8>)]) -> Result<usize, String> {
    let parsed = parse_dep_info(canonical).map_err(|error| error.reason)?;
    if render_dep_info(&parsed) != canonical {
        return Err("dep-info is outside the lossless canonical grammar".into());
    }
    let escaped_len = |bytes: &[u8]| {
        bytes.len() + bytes.iter().filter(|b| matches!(**b, b' ' | b'\\' | b'#')).count()
    };
    let token_len = |token: &[u8]| {
        match mappings.iter().find(|(prefix, _)| token.starts_with(prefix)) {
            Some((prefix, replacement)) => escaped_len(replacement) + escaped_len(&token[prefix.len()..]),
            None => escaped_len(token),
        }
    };
    let mut total = 0_usize;
    for line in &parsed.lines {
        let length = match line {
            DepInfoLine::Rule { target, deps } => {
                let mut length = token_len(target).saturating_add(2);
                for dep in deps { length = length.saturating_add(1 + token_len(dep)); }
                length
            }
            DepInfoLine::Comment(bytes) => bytes.len().saturating_add(1),
            DepInfoLine::Blank => 1,
        };
        total = total.saturating_add(length);
        if total > MAX_DEP_INFO_BYTES { return Err("derived dep-info exceeds byte limit".into()); }
    }
    Ok(total)
}

/// Static path preflight complements, but does not replace, destination
/// ownership. This is not a claim of hostile-process or symlink-race isolation.
fn preflight_destination(path: &Path) -> Result<(), ServeError> {
    if !path.is_absolute() || path.components().any(|part| part == Component::ParentDir)
        || path.as_os_str().as_bytes().contains(&0)
    {
        return Err(preparation(path, "destination must be absolute and traversal-free"));
    }
    let mut prefix = PathBuf::new();
    for part in path.components() {
        prefix.push(part.as_os_str());
        match std::fs::symlink_metadata(&prefix) {
            Ok(meta) if meta.file_type().is_symlink() => return Err(preparation(path, "symlink in destination path")),
            Ok(meta) if prefix != path && !meta.is_dir() => return Err(preparation(path, "non-directory destination ancestor")),
            Ok(meta) if prefix == path && !meta.is_file() => return Err(preparation(path, "destination is not a regular file")),
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => break,
            Err(error) => return Err(preparation(path, error)),
        }
    }
    Ok(())
}

pub(super) fn prepare(
    store: &mut dyn RabsMetadataStore,
    manifest: &CanonicalActionResultManifest,
    root: &Path,
    expected: &ExpectedOutputs,
) -> Result<Result<PreparedOutputs, super::ServeOutcome>, ServeError> {
    if !root.is_absolute() || root.components().any(|part| part == Component::ParentDir)
        || root.as_os_str().as_bytes().contains(&0)
    {
        return Err(preparation(root, "destination root must be absolute and traversal-free"));
    }
    // The file-only endpoint cannot replay a deterministic failure's exit or
    // observations. An empty output map is not evidence of compiler success.
    if manifest.result_kind != ResultKind::Success {
        return Err(preparation(root, "deterministic failure requires terminal-result delivery"));
    }
    if let Some(expected) = expected_paths(expected) {
        let committed = manifest.logical_outputs.iter().map(|output| {
            std::str::from_utf8(output.virtual_path.as_bytes())
                .map(str::to_owned)
                .map_err(|_| ServeError::UnsafeVirtualPath { path: output.virtual_path.escaped() })
        }).collect::<Result<BTreeSet<_>, _>>()?;
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
        if !matches!(output.role, OutputRole::Materializable | OutputRole::ProvisionalMetadata | OutputRole::DepInfo) {
            return Err(preparation(root, format!("unsupported output role: {:?}", output.role)));
        }
        let destination = resolve_destination(root, output.virtual_path.as_bytes())
            .ok_or_else(|| ServeError::UnsafeVirtualPath { path: output.virtual_path.escaped() })?;
        preflight_destination(&destination)?;
        let normalized: PathBuf = destination.components().filter(|part| *part != Component::CurDir).collect();
        if !destinations.insert(normalized) {
            return Err(preparation(&destination, "different logical outputs alias one destination"));
        }
        outputs.push(PlannedActionOutput {
            role: output.role, virtual_path: output.virtual_path.clone(),
            object: output.object.0.clone(), destination,
        });
    }
    let ordered: Vec<_> = destinations.iter().collect();
    if ordered.windows(2).any(|pair| pair[1].starts_with(pair[0])) {
        return Err(preparation(root, "one output is an ancestor of another output"));
    }

    // Every .d is byte-verified and derived before ANY target output is installed.
    // Only private scratch files are written on a derivation/input refusal.
    let mut dep_info = BTreeMap::new();
    let mut total_derived_bytes = 0_usize;
    let mut freshness = SystemTime::now();
    for (index, output) in outputs.iter().enumerate().filter(|(_, out)| out.role == OutputRole::DepInfo) {
        let scratch = tempfile::tempdir().map_err(|error| preparation(&output.destination, error))?;
        let canonical_path = scratch.path().join(format!("dep-{index}"));
        materialize_object(store, &output.object, &canonical_path, MaterializationMode::PrivateCopy)
            .map_err(|error| preparation(&output.destination, error))?;
        let file = std::fs::File::open(&canonical_path).map_err(|error| preparation(&output.destination, error))?;
        let mut canonical = Vec::new();
        file.take(MAX_DEP_INFO_BYTES as u64 + 1).read_to_end(&mut canonical)
            .map_err(|error| preparation(&output.destination, error))?;
        if canonical.len() > MAX_DEP_INFO_BYTES { return Err(preparation(&output.destination, "canonical dep-info exceeds byte limit")); }
        let expanded = check_expansion(&canonical, &mappings)
            .map_err(|error| preparation(&output.destination, error))?;
        total_derived_bytes = total_derived_bytes.checked_add(expanded)
            .filter(|total| *total <= MAX_TOTAL_DEP_INFO_BYTES)
            .ok_or_else(|| preparation(&output.destination, "complete dep-info set exceeds byte limit"))?;
        let derived = derive_subscriber_dep_info(&canonical, &mappings)
            .map_err(|error| preparation(&output.destination, error.reason))?;
        if derived.bytes.len() != expanded {
            return Err(preparation(&output.destination, "dep-info derivation size differs from the validated grammar"));
        }
        let parsed = parse_dep_info(&derived.bytes).map_err(|error| preparation(&output.destination, error.reason))?;
        let mut declared_target_seen = false;
        for line in parsed.lines {
            if let DepInfoLine::Rule { target, deps } = line {
                let target = PathBuf::from(std::ffi::OsString::from_vec(target));
                let normalized: PathBuf = target.components().filter(|part| *part != Component::CurDir).collect();
                let declared = destinations.contains(&normalized);
                declared_target_seen |= declared;
                // Empty dependency rules are rustc's source-file phony rules.
                // Rules WITH prerequisites must describe one declared output,
                // not another worktree selected by a mistaken mapping.
                if !deps.is_empty() && !declared {
                    return Err(preparation(&output.destination, "dep-info target is outside the declared output set"));
                }
                for dep in deps {
                    let input = PathBuf::from(std::ffi::OsString::from_vec(dep));
                    if !input.is_absolute() || input.components().any(|part| part == Component::ParentDir) {
                        return Err(preparation(&output.destination, "relative dep-info inputs require a subscriber working-directory contract"));
                    }
                    let modified = std::fs::metadata(&input).and_then(|meta| meta.modified())
                        .map_err(|error| preparation(&output.destination, format!("dep-info input unavailable: {error}")))?;
                    freshness = freshness.max(modified);
                }
            }
        }
        if !declared_target_seen {
            return Err(preparation(&output.destination, "dep-info has no declared output target"));
        }
        dep_info.insert(output.destination.clone(), derived);
    }
    Ok(Ok(PreparedOutputs { outputs, dep_info, freshness, action_key: digest_key(&manifest.action_key) }))
}

pub(super) fn install(store: &mut dyn RabsMetadataStore, plan: &PreparedOutputs) -> Result<Vec<PathBuf>, ServeError> {
    let receipt = materialize_action_outputs_prepared(
        store, &plan.outputs, MaterializationMode::VerifiedCowReflink, plan.freshness,
        &|output, staged| {
            if let Some(derived) = plan.dep_info.get(&output.destination) {
                let mut staged = staged.try_clone()?;
                staged.rewind()?;
                staged.set_len(0)?;
                staged.write_all(&derived.bytes)?;
            }
            Ok(())
        },
    ).map_err(ServeError::Materialize)?;
    for (destination, derived) in &plan.dep_info {
        // Digests distinguish canonical identity from subscriber derivation.
        // Never log raw dep-info or source/environment contents.
        // A diagnostic sink failure must not hide a completed installation.
        let _ = writeln!(std::io::stderr().lock(), "{}", serde_json::json!({
            "kind": "rabs-dep-info-installed", "action_key": plan.action_key,
            "contract": DEP_INFO_DERIVATION_CONTRACT,
            "destination_bytes": destination.as_os_str().as_bytes(),
            "canonical_sha256": derived.derivation.canonical_sha256,
            "derived_sha256": derived.derivation.derived_sha256,
        }));
    }
    Ok(receipt.installed.into_iter().map(|output| output.destination).collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn expected(mappings: &[(&[u8], &[u8])]) -> ExpectedOutputs {
        ExpectedOutputs::WithDepInfo {
            paths: BTreeSet::new(),
            mappings: mappings.iter().map(|(a, b)| (a.to_vec(), b.to_vec())).collect(),
        }
    }

    #[test]
    fn directory_boundaries_and_longest_prefix_are_enforced_before_derivation() {
        let mappings = directory_mappings(&expected(&[
            (b"/__rabs/workspace", b"/local/workspace"),
            (b"/__rabs/workspace/vendor", b"/local/dependencies"),
        ])).unwrap();
        assert_eq!(mappings[0].0, b"/__rabs/workspace/vendor/");
        let canonical = b"/__rabs/workspace/out.rmeta: /__rabs/workspace/vendor/lib.rs\n";
        check_expansion(canonical, &mappings).unwrap();
        let derived = derive_subscriber_dep_info(canonical, &mappings).unwrap();
        assert_eq!(derived.bytes, b"/local/workspace/out.rmeta: /local/dependencies/lib.rs\n");
        let neighboring = b"/__rabs/workspace-other/out.rmeta: /__rabs/workspace/src/lib.rs\n";
        assert!(derive_subscriber_dep_info(neighboring, &mappings).is_err());
    }

    #[test]
    fn mapping_bytes_are_lossless_but_ambiguous_directories_refuse() {
        let mappings = directory_mappings(&expected(&[
            (b"/__rabs/workspace/", b"/local/nonutf8-\xff/"),
        ])).unwrap();
        let derived = derive_subscriber_dep_info(b"/__rabs/workspace/out:\n", &mappings);
        assert!(derived.is_ok());
        assert!(derived.unwrap().bytes.starts_with(b"/local/nonutf8-\xff/out:"));
        for invalid in [
            &b"relative"[..], &b"/"[..], &b"/local//tree"[..], &b"/local/../tree"[..],
            &b"/local/./tree"[..], &b"/local\0tree"[..], &b"/local:\n"[..], &b"/__rabs/out"[..],
        ] {
            assert!(directory_mappings(&expected(&[(b"/__rabs/workspace", invalid)])).is_err());
        }
        assert!(directory_mappings(&expected(&[
            (b"/__rabs/workspace", b"/first"),
            (b"/__rabs/workspace/", b"/second"),
        ])).is_err());
    }

    #[test]
    fn expansion_limit_is_checked_before_large_replacement_allocation() {
        let mut long_path = b"/local/".to_vec();
        long_path.resize(MAX_MAPPING_PATH_BYTES, b'x');
        let mappings = directory_mappings(&expected(&[(b"/__rabs/workspace", &long_path)])).unwrap();
        let mut canonical = b"/__rabs/workspace/out:".to_vec();
        for _ in 0..1100 { canonical.extend_from_slice(b" /__rabs/workspace/in"); }
        canonical.push(b'\n');
        assert!(canonical.len() < MAX_DEP_INFO_BYTES);
        assert!(check_expansion(&canonical, &mappings).is_err());
    }

    #[test]
    fn noncanonical_dep_info_grammar_cannot_be_silently_rewritten() {
        for bytes in [
            &b"out:  input\n"[..], &b"out: input"[..], &b"out: input\\\ncontinued\n"[..],
            &b"out: unsupported\\q\n"[..],
        ] {
            assert!(check_expansion(bytes, &[]).is_err(), "{bytes:?}");
        }
    }

    #[test]
    fn a_deterministic_failure_is_not_a_successful_empty_file_delivery() {
        let directory = tempfile::tempdir().unwrap();
        let cas = crate::janitor::store::mount_and_reconcile(&directory.path().join("cas")).unwrap();
        let mut manifest = rabs_cas::test_support::sample_manifest();
        manifest.result_kind = ResultKind::DeterministicFailure;
        manifest.logical_outputs.clear();
        manifest.artifact_bundle_root = None;
        let destination = directory.path().join("failure");
        assert!(matches!(prepare(
            &mut *cas.store().lock().unwrap(), &manifest, &destination,
            &ExpectedOutputs::Exactly(BTreeSet::new()),
        ), Err(ServeError::Preparation { .. })));
        assert!(!destination.exists());
    }
}
