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
    let ExpectedOutputs::WithDepInfo { mappings, .. } = expected else {
        return Ok(Vec::new());
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

/// Bound the rendered expansion BEFORE derivation allocates replacement tokens.
/// The parser is the same versioned D028 parser used for the actual derivation.
fn check_expansion(canonical: &[u8], mappings: &[(Vec<u8>, Vec<u8>)]) -> Result<usize, String> {
    let parsed = parse_dep_info(canonical).map_err(|error| error.reason)?;
    if render_dep_info(&parsed) != canonical {
        return Err("dep-info is outside the lossless canonical grammar".into());
    }
    let token_len = |token: &[u8]| {
        rewritten_dep_info_token_len(token, mappings).map_err(|error| error.reason)
    };
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

    // Every .d is byte-verified and derived before ANY target output is installed.
    // Only private scratch files are written on a derivation/input refusal.
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
        let expanded = check_expansion(&canonical, &mappings)
            .map_err(|error| preparation(&output.destination, error))?;
        total_derived_bytes = total_derived_bytes
            .checked_add(expanded)
            .filter(|total| *total <= MAX_TOTAL_DEP_INFO_BYTES)
            .ok_or_else(|| {
                preparation(
                    &output.destination,
                    "complete dep-info set exceeds byte limit",
                )
            })?;
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
        let mut declared_target_seen = false;
        for line in parsed.lines {
            if let DepInfoLine::Rule { target, deps } = line {
                let target = PathBuf::from(std::ffi::OsString::from_vec(target));
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
                    let input = PathBuf::from(std::ffi::OsString::from_vec(dep));
                    if !input.is_absolute()
                        || input.components().any(|part| part == Component::ParentDir)
                    {
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
        dep_info.insert(output.destination.clone(), derived);
    }
    Ok(Ok(PreparedOutputs {
        outputs,
        dep_info,
        freshness,
        action_key: digest_key(&manifest.action_key),
    }))
}

pub(super) fn install(
    store: &mut dyn RabsMetadataStore,
    plan: &PreparedOutputs,
) -> Result<Vec<PathBuf>, ServeError> {
    let receipt = materialize_action_outputs_prepared(
        store,
        &plan.outputs,
        MaterializationMode::VerifiedCowReflink,
        plan.freshness,
        &|output, staged| {
            if let Some(derived) = plan.dep_info.get(&output.destination) {
                let mut staged = staged.try_clone()?;
                staged.rewind()?;
                staged.set_len(0)?;
                staged.write_all(&derived.bytes)?;
            }
            Ok(())
        },
    )
    .map_err(ServeError::Materialize)?;
    for (destination, derived) in &plan.dep_info {
        // Digests distinguish canonical identity from subscriber derivation.
        // Never log raw dep-info or source/environment contents.
        // A diagnostic sink failure must not hide a completed installation.
        let _ = writeln!(
            std::io::stderr().lock(),
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
        let root = directory.path().canonicalize().unwrap().join(
            std::ffi::OsString::from_vec(b"root-\xfe".to_vec()),
        );
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
        ])).unwrap();
        let canonical = b"target/unit.rmeta: ./src/lib.rs /__rabs/toolchain/lib/core.rlib\n\n./src/lib.rs:\n";
        let expanded = check_expansion(canonical, &mappings).unwrap();
        let derived = derive_subscriber_dep_info(canonical, &mappings).unwrap();
        assert_eq!(expanded, derived.bytes.len());
        assert_eq!(render_dep_info(&parse_dep_info(&derived.bytes).unwrap()), derived.bytes);
        assert!(derived.bytes.starts_with(b"/subscriber\\ with\\#space-\xff/target/unit.rmeta:"));
    }

    #[test]
    fn working_directory_mapping_is_explicit_unique_and_absolute() {
        let mappings = directory_mappings(&expected(&[
            (b".", b"/worktree"), (b".", b"/worktree/"),
        ])).unwrap();
        assert_eq!(mappings, vec![(b".".to_vec(), b"/worktree/".to_vec())]);
        assert!(directory_mappings(&expected(&[
            (b".", b"/first"), (b".", b"/second"),
        ])).is_err());
        for directory in [&b"relative"[..], b"/", b"/tree/../other", b"/__rabs/workspace"] {
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
}
