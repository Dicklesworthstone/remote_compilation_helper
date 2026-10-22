//! Conservative source-edit reuse for PRIVATE Cargo targets, not action results.
//!
//! Cargo tracks local/path-package source mtimes, but does not do so for registry
//! and Git packages. Keep all directory-source packages (identified by their
//! checksum document), non-Rust files and executable inputs exact. Local Rust
//! files may be edited, added, removed or renamed. Isolated Cargo-home projections
//! bind their validated cache partition byte-for-byte before normalizing workspace
//! inputs. The legacy visible-prefix projection remains exact-source only.
//! Unknown Cargo arguments/commands are excluded by the caller's existing gate.
//!
//! A matching family only selects a seed. Both trees are independently verified
//! and copied; every changed input and its parent directories must become newer
//! than ALL retained source and target timestamps. Membership changes also dirty
//! ancestor Cargo manifests for old-style build-script package scans. All other
//! unchanged input times and every output timestamp are preserved. A regressed
//! clock or a filesystem that cannot represent the requested timestamps yields
//! a cold build, not a stale fingerprint. The current command and its artifact
//! report still run.

use super::{Seed, SourceTimes, WorkspaceInputs, checkpoint, invalid};
use rabs_sandbox::source_transfer::{SourceFile, SourceManifest};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::io;
use std::path::Path;
use std::time::SystemTime;

fn protected_roots(manifest: &SourceManifest) -> BTreeSet<&Path> {
    manifest
        .files()
        .iter()
        .filter_map(|file| {
            let path = Path::new(&file.path);
            if path.file_name()?.to_str()? == ".cargo-checksum.json" {
                path.parent()
            } else {
                None
            }
        })
        .collect()
}

fn editable(file: &SourceFile, protected: &BTreeSet<&Path>) -> bool {
    if file.executable || !file.path.ends_with(".rs") {
        return false;
    }
    !Path::new(&file.path)
        .ancestors()
        .skip(1)
        .any(|parent| protected.contains(parent))
}

/// A length-framed family digest retains every non-editable input's name, mode
/// and bytes. Editable Rust membership is checked by the timestamp planner, not
/// collapsed into an action key: the exact source manifest remains unchanged.
pub(super) fn identity(inputs: &WorkspaceInputs) -> Option<[u8; 32]> {
    let mut hash = Sha256::new();
    if let Some(home) = &inputs.projection {
        // The projection was admitted with the complete transferred manifest.
        // A supplied hint cannot hide changed cache bytes or be paired with a
        // different workspace. Legacy projections have no isolated partition.
        let workspace = home.workspace_manifest()?;
        if home.source_digest() != inputs.full_source_digest
            || workspace.digest() != inputs.manifest.digest()
        {
            return None;
        }
        hash.update(b"rabs.private-cargo-projected-source-edits.v2\0");
        for value in [home.version(), home.prefix()] {
            hash.update((value.len() as u64).to_be_bytes());
            hash.update(value.as_bytes());
        }
        hash.update(home.cache_manifest().digest());
    } else {
        if inputs.full_source_digest != inputs.manifest.digest() {
            return None;
        }
        hash.update(b"rabs.private-cargo-source-edits.v2\0");
    }
    let protected = protected_roots(&inputs.manifest);
    let immutable = inputs
        .manifest
        .files()
        .iter()
        .filter(|file| !editable(file, &protected))
        .count();
    hash.update((immutable as u64).to_be_bytes());
    for file in inputs.manifest.files() {
        if editable(file, &protected) {
            continue;
        }
        hash.update((file.path.len() as u64).to_be_bytes());
        hash.update(file.path.as_bytes());
        hash.update([u8::from(file.executable)]);
        hash.update(file.len.to_be_bytes());
        hash.update(file.sha256);
    }
    (immutable < inputs.manifest.files().len()).then(|| hash.finalize().into())
}

/// Compute a timestamp plan before copying. The existing descriptor-anchored
/// SourceTimes::restore applies AND reads back every requested timestamp only
/// on the execution's private workspace, with full content verification.
pub(super) fn timestamps(
    seed: &Seed,
    inputs: &WorkspaceInputs,
    now: SystemTime,
    stopped: &impl Fn() -> bool,
) -> io::Result<SourceTimes> {
    checkpoint(stopped)?;
    let family = identity(inputs);
    if seed.source_manifest.digest() == inputs.manifest.digest() {
        if seed.edit_family.is_some() && family != seed.edit_family {
            return Err(invalid(
                "target state cache projection differs from the retained Cargo seed family",
            ));
        }
        return Ok(seed.source.clone());
    }
    if family.is_none() || family != seed.edit_family {
        return Err(invalid(
            "source edit is outside the retained Cargo seed family",
        ));
    }
    let previous: BTreeMap<_, _> = seed
        .source_manifest
        .files()
        .iter()
        .map(|file| (file.path.as_str(), file))
        .collect();
    let current: BTreeMap<_, _> = inputs
        .manifest
        .files()
        .iter()
        .map(|file| (file.path.as_str(), file))
        .collect();
    // Do not invent future times or move outputs backwards. On a clock rollback
    // we can always execute cold. Include source times for Cargo's old-style
    // build-script newest-file checks, and directories for recursive directives.
    let newest = seed
        .tree
        .files
        .values()
        .map(|file| file.modified)
        .chain(seed.tree.directories.values().map(|dir| dir.modified))
        .chain(seed.source.files.values().copied())
        .chain(seed.source.directories.values().map(|dir| dir.modified))
        .max();
    if newest.is_some_and(|latest| now <= latest) {
        return Err(invalid(
            "clock cannot order edited sources after the retained target",
        ));
    }
    let protected = protected_roots(&inputs.manifest);
    let old_protected = protected_roots(&seed.source_manifest);
    let mut changed = BTreeSet::new();
    for (name, old) in &previous {
        checkpoint(stopped)?;
        if !current.contains_key(name) {
            if !editable(old, &old_protected) {
                return Err(invalid("source edit removed an immutable Cargo input"));
            }
            changed.insert(*name);
        }
    }
    for (name, new) in &current {
        checkpoint(stopped)?;
        if let Some(old) = previous.get(name) {
            if old.executable != new.executable {
                return Err(invalid("source-edit executable mode changed"));
            }
            if old.len == new.len && old.sha256 == new.sha256 {
                continue;
            }
        }
        if !editable(new, &protected) {
            return Err(invalid("source edit changed an immutable Cargo input"));
        }
        changed.insert(*name);
    }
    if changed.is_empty() {
        return Err(invalid(
            "changed manifest contains no supported Rust-source edit",
        ));
    }
    let mut parents = BTreeSet::new();
    for name in &changed {
        checkpoint(stopped)?;
        for parent in Path::new(name).ancestors().skip(1) {
            parents.insert(
                parent
                    .to_str()
                    .ok_or_else(|| invalid("non-UTF-8 source-edit parent"))?,
            );
        }
    }
    // Reconstruct membership from the CURRENT verified tree, never from the
    // retained workspace. Removed files/directories must not be resurrected.
    // Keep the old fast path for content-only edits with the same file names.
    let membership_changed = !previous.keys().eq(current.keys());
    let mut wanted = if !membership_changed {
        seed.source.clone()
    } else {
        let mut current_times = SourceTimes::capture(inputs, stopped)?;
        for (name, modified) in &mut current_times.files {
            if let Some(old) = seed.source.files.get(name) {
                *modified = *old;
            }
        }
        for (name, directory) in &mut current_times.directories {
            checkpoint(stopped)?;
            if let Some(old) = seed.source.directories.get(name) {
                if directory.mode != old.mode {
                    return Err(invalid("source-edit directory mode changed"));
                }
                directory.modified = old.modified;
            } else if !parents.contains(name.as_str()) {
                return Err(invalid("source edit introduced an unrelated directory"));
            }
        }
        for name in seed.source.directories.keys() {
            if !current_times.directories.contains_key(name) && !parents.contains(name.as_str()) {
                return Err(invalid("source edit removed an unrelated directory"));
            }
        }
        current_times
    };
    for name in &changed {
        checkpoint(stopped)?;
        if let Some(modified) = wanted.files.get_mut(*name) {
            *modified = now;
        }
    }
    // A removal has no file to timestamp. Dirty every surviving ancestor,
    // including the root, so directory-scanning build scripts see removals and
    // renames as well as additions. Missing ancestors stay absent in the clone.
    for name in parents {
        checkpoint(stopped)?;
        if let Some(directory) = wanted.directories.get_mut(name) {
            directory.modified = now;
        }
        if membership_changed {
            // A removed file may no longer contribute to Cargo's old-style
            // package newest-file fingerprint. Its containing Cargo.toml is
            // still present and content-exact, but must signal that membership
            // changed. Unrelated packages retain their original timestamps.
            let manifest = Path::new(name).join("Cargo.toml");
            if let Some(manifest) = manifest.to_str()
                && let Some(modified) = wanted.files.get_mut(manifest)
            {
                *modified = now;
            }
        }
    }
    Ok(wanted)
}

#[cfg(all(test, target_os = "linux"))]
mod projected_tests;

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::super::{
        ArtifactPlan, PreparedArtifacts, TargetCache, TargetCacheScope, TargetKey,
        private_directory, target_compatibility_key, target_key,
    };
    use super::*;
    use crate::result_spool::ResultRecipient;
    use crate::session::CanonicalExecRequest;
    use rabs_sandbox::canonical_namespace::{CanonicalNamespaceSpec, HostIsolationSupport};
    use rabs_sandbox::process_context::CommandContext;
    use rabs_sandbox::toolchain_dataset::ToolchainIdentity;
    use std::fs::{self, File, FileTimes};
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    use std::path::PathBuf;
    use std::process::Command;
    use std::sync::Arc;
    use std::time::Duration;

    pub(super) fn write(root: &Path, name: &str, bytes: impl AsRef<[u8]>) {
        let path = root.join(name);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, bytes).unwrap();
    }

    pub(super) fn observe(root: &Path) -> WorkspaceInputs {
        let mut files = Vec::new();
        let mut pending = vec![root.to_path_buf()];
        while let Some(directory) = pending.pop() {
            for entry in fs::read_dir(directory).unwrap() {
                let entry = entry.unwrap();
                let meta = fs::symlink_metadata(entry.path()).unwrap();
                if meta.is_dir() {
                    pending.push(entry.path());
                } else {
                    assert!(meta.is_file());
                    let bytes = fs::read(entry.path()).unwrap();
                    files.push(SourceFile {
                        path: entry
                            .path()
                            .strip_prefix(root)
                            .unwrap()
                            .to_str()
                            .unwrap()
                            .into(),
                        len: bytes.len() as u64,
                        sha256: Sha256::digest(&bytes).into(),
                        executable: meta.permissions().mode() & 0o111 != 0,
                    });
                }
            }
        }
        let manifest = SourceManifest::new(files).unwrap();
        WorkspaceInputs {
            root: root.to_path_buf(),
            full_source_digest: manifest.digest(),
            manifest,
            projection: None,
            runtime_owner: None,
        }
    }

    pub(super) fn source() -> tempfile::TempDir {
        let source = private_directory("rabs-edits-source-").unwrap();
        write(
            source.path(),
            "src/lib.rs",
            "pub fn answer() -> u32 { 1 }\n",
        );
        write(source.path(), "dep/lib.rs", "pub fn stable() {}\n");
        write(source.path(), "Cargo.toml", "[package]\nname='fixture'\n");
        source
    }

    pub(super) fn stage_fixture(cache: &Arc<TargetCache>, input: WorkspaceInputs) {
        // Structural target-cache fixture, not a claim of Cargo execution.
        let plan = ArtifactPlan::new_tree("cargo".into(), vec!["artifact".into()]).unwrap();
        let target = PreparedArtifacts::new(plan.clone()).unwrap();
        fs::write(target.backing().join("artifact"), b"retained target").unwrap();
        let captured = target
            .capture_with_dependency_inputs(None, || false)
            .unwrap();
        let key = TargetKey(input.full_source_digest);
        let compatible = identity(&input).map(TargetKey);
        let (attempt, restored) = cache
            .acquire(
                key,
                compatible,
                input,
                || PreparedArtifacts::new(plan),
                1,
                &|| false,
            )
            .unwrap();
        assert!(restored.is_none());
        attempt
            .stage(&target, &captured, &|| false)
            .unwrap()
            .unwrap()
            .publish();
    }

    pub(super) fn restore_fixture(
        cache: &Arc<TargetCache>,
        input: WorkspaceInputs,
    ) -> (super::super::TargetAttempt, Option<PreparedArtifacts>) {
        let plan = ArtifactPlan::new_tree("cargo".into(), vec!["artifact".into()]).unwrap();
        cache
            .acquire(
                TargetKey(input.full_source_digest),
                identity(&input).map(TargetKey),
                input,
                || PreparedArtifacts::new(plan),
                2,
                &|| false,
            )
            .unwrap()
    }

    #[test]
    fn edit_family_keeps_non_rust_bytes_vendor_sources_and_modes_exact() {
        let root = source();
        write(root.path(), "vendor/dep/.cargo-checksum.json", "{}");
        write(
            root.path(),
            "vendor/dep/src/lib.rs",
            "pub fn dependency() {}\n",
        );
        let original = observe(root.path());
        let expected = identity(&original).unwrap();
        write(
            root.path(),
            "src/lib.rs",
            "pub fn answer() -> u32 { 999 }\n",
        );
        assert_eq!(identity(&observe(root.path())), Some(expected));
        for name in [
            "Cargo.toml",
            "vendor/dep/src/lib.rs",
            "vendor/dep/.cargo-checksum.json",
        ] {
            let before = fs::read(root.path().join(name)).unwrap();
            write(root.path(), name, b"different bytes");
            assert_ne!(identity(&observe(root.path())), Some(expected), "{name}");
            write(root.path(), name, before);
        }
        fs::set_permissions(
            root.path().join("src/lib.rs"),
            fs::Permissions::from_mode(0o700),
        )
        .unwrap();
        assert_ne!(identity(&observe(root.path())), Some(expected));
        fs::set_permissions(
            root.path().join("src/lib.rs"),
            fs::Permissions::from_mode(0o600),
        )
        .unwrap();
        write(root.path(), "src/added.rs", b"new member");
        assert_eq!(identity(&observe(root.path())), Some(expected));
        write(root.path(), "src/added.txt", b"new immutable member");
        assert_ne!(identity(&observe(root.path())), Some(expected));
    }

    #[test]
    fn unbound_transport_and_root_directory_sources_never_enter_the_edit_family() {
        let root = source();
        let mut input = observe(root.path());
        assert!(identity(&input).is_some());
        input.full_source_digest[0] ^= 1;
        assert!(identity(&input).is_none());
        write(root.path(), ".cargo-checksum.json", "{}");
        assert!(identity(&observe(root.path())).is_none());
    }

    #[test]
    fn edited_copy_is_newer_than_fingerprints_without_touching_the_seal_or_target_times() {
        let source = source();
        let cache = Arc::new(TargetCache::new(4096).unwrap());
        stage_fixture(&cache, observe(source.path()));
        let seed = Arc::clone(&cache.state.lock().unwrap().entries[0]);
        let target_time = seed.tree.files["artifact"].modified;
        let old_source = seed.source.clone();
        write(
            source.path(),
            "src/lib.rs",
            "pub fn answer() -> u32 { 2 }\n",
        );
        // A restored/forged old source mtime must not conceal changed bytes.
        File::open(source.path().join("src/lib.rs"))
            .unwrap()
            .set_times(FileTimes::new().set_modified(old_source.files["src/lib.rs"]))
            .unwrap();
        let input = observe(source.path());
        let before = SourceTimes::capture(&input, &|| false).unwrap();
        let (attempt, restored) = restore_fixture(&cache, input.clone());
        let restored = restored.expect("source edit should retain compiled dependencies");
        assert!(attempt.times.files["src/lib.rs"] > target_time);
        assert!(attempt.times.directories["src"].modified > target_time);
        assert!(attempt.times.directories[""].modified > target_time);
        assert_eq!(
            attempt.times.files["dep/lib.rs"],
            old_source.files["dep/lib.rs"]
        );
        assert_eq!(
            attempt.times.directories["dep"],
            old_source.directories["dep"]
        );
        assert_eq!(
            fs::metadata(restored.backing().join("artifact"))
                .unwrap()
                .modified()
                .unwrap(),
            target_time,
        );
        assert_eq!(SourceTimes::capture(&input, &|| false).unwrap(), before);
        assert_ne!(
            fs::metadata(attempt.inputs.root.join("src/lib.rs"))
                .unwrap()
                .ino(),
            fs::metadata(source.path().join("src/lib.rs"))
                .unwrap()
                .ino()
        );
        assert_eq!(
            fs::read(attempt.inputs.root.join("src/lib.rs")).unwrap(),
            fs::read(source.path().join("src/lib.rs")).unwrap()
        );
        assert_eq!(seed.source, old_source, "old generation remains immutable");
    }

    #[test]
    fn clock_regression_refuses_the_edit_but_not_identical_source() {
        let root = source();
        let cache = Arc::new(TargetCache::new(4096).unwrap());
        let original = observe(root.path());
        stage_fixture(&cache, original.clone());
        let seed = Arc::clone(&cache.state.lock().unwrap().entries[0]);
        let newest = seed
            .tree
            .files
            .values()
            .map(|file| file.modified)
            .chain(
                seed.tree
                    .directories
                    .values()
                    .map(|directory| directory.modified),
            )
            .chain(seed.source.files.values().copied())
            .chain(
                seed.source
                    .directories
                    .values()
                    .map(|directory| directory.modified),
            )
            .max()
            .unwrap();
        write(root.path(), "src/lib.rs", b"edited");
        let changed = observe(root.path());
        for now in [SystemTime::UNIX_EPOCH, newest] {
            assert!(timestamps(&seed, &changed, now, &|| false).is_err());
            assert_eq!(
                timestamps(&seed, &original, now, &|| false).unwrap(),
                seed.source
            );
        }
        assert!(timestamps(&seed, &changed, newest + Duration::from_secs(1), &|| false).is_ok());
    }

    #[test]
    fn incompatible_edits_cannot_be_forced_by_a_forged_family_hint() {
        let root = source();
        let cache = Arc::new(TargetCache::new(4096).unwrap());
        let original = observe(root.path());
        let family = identity(&original).map(TargetKey);
        stage_fixture(&cache, original);
        write(root.path(), "Cargo.toml", b"changed manifest");
        let changed = observe(root.path());
        let before = SourceTimes::capture(&changed, &|| false).unwrap();
        let (attempt, restored) = cache
            .acquire(
                TargetKey(changed.manifest.digest()),
                family,
                changed.clone(),
                || panic!("incompatible edit must refuse before output allocation"),
                2,
                &|| false,
            )
            .unwrap();
        assert!(restored.is_none());
        assert!(attempt.inputs.runtime_owner.is_none());
        assert_eq!(SourceTimes::capture(&changed, &|| false).unwrap(), before);
        assert_eq!(cache.state.lock().unwrap().entries.len(), 1);
    }

    #[test]
    fn mutation_after_an_edited_restore_cannot_publish_a_new_seed() {
        let root = source();
        let cache = Arc::new(TargetCache::new(4096).unwrap());
        stage_fixture(&cache, observe(root.path()));
        write(root.path(), "src/lib.rs", b"first edit");
        let (attempt, restored) = restore_fixture(&cache, observe(root.path()));
        let restored = restored.unwrap();
        write(
            &attempt.inputs.root,
            "src/lib.rs",
            b"changed during execution",
        );
        let captured = restored
            .capture_with_dependency_inputs(None, || false)
            .unwrap();
        assert!(attempt.stage(&restored, &captured, &|| false).is_err());
        let state = cache.state.lock().unwrap();
        assert_eq!(state.entries.len(), 1);
        assert_eq!(state.reserved_bytes, 0);
        assert_eq!(state.reservations, 0);
    }

    #[test]
    fn cancelled_edit_keeps_the_original_seed_available() {
        let root = source();
        let cache = Arc::new(TargetCache::new(4096).unwrap());
        stage_fixture(&cache, observe(root.path()));
        write(root.path(), "src/lib.rs", b"edited source");
        let changed = observe(root.path());
        let before = SourceTimes::capture(&changed, &|| false).unwrap();
        let stopped = std::cell::Cell::new(false);
        let plan = ArtifactPlan::new_tree("cargo".into(), vec!["artifact".into()]).unwrap();
        let result = cache.acquire(
            TargetKey(changed.manifest.digest()),
            identity(&changed).map(TargetKey),
            changed.clone(),
            || {
                stopped.set(true);
                PreparedArtifacts::new(plan)
            },
            2,
            &|| stopped.get(),
        );
        assert_eq!(result.unwrap_err().kind(), io::ErrorKind::Interrupted);
        assert_eq!(cache.state.lock().unwrap().entries.len(), 1);
        assert_eq!(SourceTimes::capture(&changed, &|| false).unwrap(), before);
        assert!(restore_fixture(&cache, changed).1.is_some());
    }

    #[test]
    fn module_membership_restores_only_the_current_tree_and_dirties_surviving_parents() {
        for operation in ["add", "remove-file", "remove-directory", "rename"] {
            let root = source();
            let parked = private_directory("rabs-removed-modules-").unwrap();
            write(root.path(), "src/nested/old.rs", "pub fn old() {}\n");
            write(root.path(), "dep/Cargo.toml", "[package]\nname='stable'\n");
            let cache = Arc::new(TargetCache::new(4096).unwrap());
            stage_fixture(&cache, observe(root.path()));
            let seed = Arc::clone(&cache.state.lock().unwrap().entries[0]);
            let target_time = seed.tree.files["artifact"].modified;
            let retained = seed.source.clone();
            match operation {
                "add" => write(root.path(), "src/new/deep.rs", b"new Rust source"),
                "remove-file" => fs::rename(
                    root.path().join("src/nested/old.rs"),
                    parked.path().join("old.rs"),
                )
                .unwrap(),
                "remove-directory" => {
                    fs::rename(root.path().join("src/nested"), parked.path().join("nested"))
                        .unwrap()
                }
                "rename" => fs::rename(
                    root.path().join("src/nested"),
                    root.path().join("src/renamed"),
                )
                .unwrap(),
                _ => unreachable!(),
            }
            let current = observe(root.path());
            let original_times = SourceTimes::capture(&current, &|| false).unwrap();
            let (attempt, restored) = restore_fixture(&cache, current.clone());
            let restored = restored.expect("local Rust membership should retain the target");
            assert!(
                attempt.times.directories[""].modified > target_time,
                "{operation}"
            );
            assert!(
                attempt.times.directories["src"].modified > target_time,
                "{operation}"
            );
            assert!(
                attempt.times.files["Cargo.toml"] > target_time,
                "{operation}"
            );
            assert_eq!(
                attempt.times.files["dep/lib.rs"],
                retained.files["dep/lib.rs"]
            );
            assert_eq!(
                attempt.times.files["dep/Cargo.toml"],
                retained.files["dep/Cargo.toml"]
            );
            assert_eq!(
                attempt.times.directories["dep"],
                retained.directories["dep"]
            );
            assert_eq!(
                attempt
                    .times
                    .files
                    .keys()
                    .map(String::as_str)
                    .collect::<Vec<_>>(),
                current
                    .manifest
                    .files()
                    .iter()
                    .map(|file| file.path.as_str())
                    .collect::<Vec<_>>()
            );
            for file in current.manifest.files() {
                let original = root.path().join(&file.path);
                let copied = attempt.inputs.root.join(&file.path);
                assert_eq!(fs::read(&copied).unwrap(), fs::read(&original).unwrap());
                assert_ne!(
                    fs::metadata(&copied).unwrap().ino(),
                    fs::metadata(original).unwrap().ino()
                );
                if !retained.files.contains_key(&file.path) {
                    assert!(attempt.times.files[&file.path] > target_time);
                }
            }
            if operation != "add" {
                assert!(!attempt.inputs.root.join("src/nested/old.rs").exists());
            }
            if matches!(operation, "remove-directory" | "rename") {
                assert!(!attempt.inputs.root.join("src/nested").exists());
                assert!(!attempt.times.directories.contains_key("src/nested"));
            }
            assert_eq!(
                fs::metadata(restored.backing().join("artifact"))
                    .unwrap()
                    .modified()
                    .unwrap(),
                target_time
            );
            assert_eq!(
                SourceTimes::capture(&current, &|| false).unwrap(),
                original_times
            );
            assert_eq!(
                seed.source, retained,
                "a predecessor's evidence is immutable"
            );
            let captured = restored
                .capture_with_dependency_inputs(None, || false)
                .unwrap();
            attempt
                .stage(&restored, &captured, &|| false)
                .unwrap()
                .unwrap()
                .publish();
            let (again, _) = restore_fixture(&cache, current.clone());
            assert_eq!(again.inputs.manifest.digest(), current.manifest.digest());
        }
    }

    #[test]
    fn immutable_membership_refuses_even_with_a_forged_compatible_hint() {
        for (name, operation) in [
            ("data.txt", "add"),
            ("data.txt", "remove"),
            ("data.txt", "rename"),
            ("vendor/pkg/src/lib.rs", "add"),
            ("vendor/pkg/src/lib.rs", "remove"),
            ("vendor/pkg/src/lib.rs", "rename"),
            ("script.rs", "executable"),
        ] {
            let root = source();
            let parked = private_directory("rabs-immutable-inputs-").unwrap();
            write(root.path(), "vendor/pkg/.cargo-checksum.json", "{}");
            if operation != "add" {
                write(root.path(), name, b"retained input");
            }
            let cache = Arc::new(TargetCache::new(4096).unwrap());
            let original = observe(root.path());
            let family = identity(&original).map(TargetKey);
            stage_fixture(&cache, original);
            match operation {
                "add" => write(root.path(), name, b"new input"),
                "remove" => fs::rename(root.path().join(name), parked.path().join("old")).unwrap(),
                "rename" => fs::rename(
                    root.path().join(name),
                    root.path().join(format!("{name}.moved")),
                )
                .unwrap(),
                "executable" => {
                    fs::set_permissions(root.path().join(name), fs::Permissions::from_mode(0o700))
                        .unwrap()
                }
                _ => unreachable!(),
            }
            let changed = observe(root.path());
            assert_ne!(
                identity(&changed).map(TargetKey),
                family,
                "{name} {operation}"
            );
            let before = SourceTimes::capture(&changed, &|| false).unwrap();
            let (attempt, restored) = cache
                .acquire(
                    TargetKey(changed.manifest.digest()),
                    family,
                    changed.clone(),
                    || panic!("immutable membership reached target allocation"),
                    2,
                    &|| false,
                )
                .unwrap();
            assert!(restored.is_none());
            assert!(attempt.inputs.runtime_owner.is_none());
            assert_eq!(cache.state.lock().unwrap().entries.len(), 1);
            assert_eq!(SourceTimes::capture(&changed, &|| false).unwrap(), before);
        }
    }

    #[test]
    fn membership_cannot_smuggle_unrelated_directory_changes_or_modes() {
        for mode_change in [false, true] {
            let root = source();
            let cache = Arc::new(TargetCache::new(4096).unwrap());
            stage_fixture(&cache, observe(root.path()));
            let seed = Arc::clone(&cache.state.lock().unwrap().entries[0]);
            write(root.path(), "src/new.rs", b"new Rust input");
            if mode_change {
                let old = seed.source.directories["dep"].mode;
                fs::set_permissions(
                    root.path().join("dep"),
                    fs::Permissions::from_mode(old ^ 0o050),
                )
                .unwrap();
            } else {
                fs::create_dir(root.path().join("unrelated-empty-directory")).unwrap();
            }
            let changed = observe(root.path());
            let before = SourceTimes::capture(&changed, &|| false).unwrap();
            let latest = seed.tree.files["artifact"].modified + Duration::from_secs(10);
            assert!(timestamps(&seed, &changed, latest, &|| false).is_err());
            let (attempt, restored) = restore_fixture(&cache, changed.clone());
            assert!(restored.is_none());
            assert!(attempt.inputs.runtime_owner.is_none());
            assert_eq!(cache.state.lock().unwrap().entries.len(), 1);
            assert_eq!(SourceTimes::capture(&changed, &|| false).unwrap(), before);
        }
    }

    #[test]
    fn membership_refuses_clock_rollback_and_cancellation_without_losing_the_seed() {
        let root = source();
        let cache = Arc::new(TargetCache::new(4096).unwrap());
        stage_fixture(&cache, observe(root.path()));
        let seed = Arc::clone(&cache.state.lock().unwrap().entries[0]);
        write(root.path(), "src/nested/added.rs", b"new Rust input");
        let current = observe(root.path());
        let before = SourceTimes::capture(&current, &|| false).unwrap();
        assert!(timestamps(&seed, &current, SystemTime::UNIX_EPOCH, &|| false).is_err());
        assert_eq!(
            timestamps(&seed, &current, SystemTime::now(), &|| true)
                .unwrap_err()
                .kind(),
            io::ErrorKind::Interrupted
        );
        let stop = std::cell::Cell::new(false);
        let output_path = std::cell::RefCell::new(None::<PathBuf>);
        let plan = ArtifactPlan::new_tree("cargo".into(), vec!["artifact".into()]).unwrap();
        let result = cache.acquire(
            TargetKey(current.manifest.digest()),
            identity(&current).map(TargetKey),
            current.clone(),
            || {
                let output = PreparedArtifacts::new(plan)?;
                *output_path.borrow_mut() = Some(output.backing().to_path_buf());
                stop.set(true);
                Ok(output)
            },
            2,
            &|| stop.get(),
        );
        assert_eq!(result.unwrap_err().kind(), io::ErrorKind::Interrupted);
        assert!(!output_path.borrow().as_ref().unwrap().exists());
        assert_eq!(cache.state.lock().unwrap().entries.len(), 1);
        assert_eq!(SourceTimes::capture(&current, &|| false).unwrap(), before);
        assert!(restore_fixture(&cache, current).1.is_some());
    }

    #[test]
    fn a_new_module_changed_after_observation_cannot_reuse_or_publish_target_state() {
        let root = source();
        let cache = Arc::new(TargetCache::new(4096).unwrap());
        stage_fixture(&cache, observe(root.path()));
        write(root.path(), "src/added.rs", b"admitted bytes");
        let observed = observe(root.path());
        write(
            root.path(),
            "src/added.rs",
            b"different bytes after observation",
        );
        let plan = ArtifactPlan::new_tree("cargo".into(), vec!["artifact".into()]).unwrap();
        assert!(
            cache
                .acquire(
                    TargetKey(observed.manifest.digest()),
                    identity(&observed).map(TargetKey),
                    observed,
                    || PreparedArtifacts::new(plan),
                    2,
                    &|| false,
                )
                .is_err()
        );
        let current = observe(root.path());
        let (attempt, output) = restore_fixture(&cache, current);
        let output = output.unwrap();
        write(
            &attempt.inputs.root,
            "src/added.rs",
            b"changed after restoration",
        );
        let captured = output
            .capture_with_dependency_inputs(None, || false)
            .unwrap();
        assert!(attempt.stage(&output, &captured, &|| false).is_err());
        let state = cache.state.lock().unwrap();
        assert_eq!(state.entries.len(), 1);
        assert_eq!(state.reservations, 0);
        assert_eq!(state.reserved_bytes, 0);
    }

    const MAIN: &str = r#"fn answer() -> u32 { edit_dep::value() + include!(concat!(env!("OUT_DIR"), "/generated.rs")) + OFFSET }
fn main() { println!("{}", answer()); }
#[cfg(test)] mod tests {
    #[test] fn runs_again() {
        assert!(super::answer() > 0);
        let path = std::path::Path::new(env!("OUT_DIR")).join("test-runs");
        let count = std::fs::read_to_string(&path).ok().map(|v| v.parse::<u32>().unwrap()).unwrap_or(0);
        std::fs::write(path, (count + 1).to_string()).unwrap();
    }
}
"#;
    const BUILD: &str = r#"fn main() {
    std::fs::write(std::path::Path::new(&std::env::var("OUT_DIR").unwrap()).join("generated.rs"), "GENERATED").unwrap();
    println!("cargo:rerun-if-changed=build.rs");
}
"#;

    pub(super) struct CargoFixture {
        pub(super) root: tempfile::TempDir,
        pub(super) source: PathBuf,
    }

    pub(super) struct Run {
        artifacts: Vec<serde_json::Value>,
        pub(super) output: Option<(Vec<u8>, Vec<u8>)>,
        test_runs: u32,
    }

    impl Run {
        pub(super) fn fresh(&self, name: &str, fresh: bool) {
            let reports: Vec<_> = self
                .artifacts
                .iter()
                .filter(|report| {
                    report["target"]["name"] == name && report["profile"]["test"] == false
                })
                .collect();
            assert!(
                !reports.is_empty(),
                "missing artifact {name}: {:?}",
                self.artifacts
            );
            assert!(
                reports.iter().all(|report| report["fresh"] == fresh),
                "{name}: {reports:?}"
            );
        }
    }

    impl CargoFixture {
        pub(super) fn new() -> Self {
            let root = private_directory("rabs-real-source-edits-").unwrap();
            let source = root.path().join("source");
            fs::create_dir(&source).unwrap();
            fs::set_permissions(&source, fs::Permissions::from_mode(0o700)).unwrap();
            write(
                &source,
                "Cargo.toml",
                "[package]\nname='edit_app'\nversion='0.1.0'\nedition='2021'\n[workspace]\nmembers=['dep']\n[dependencies]\nedit_dep={path='dep'}\n",
            );
            write(
                &source,
                "Cargo.lock",
                "version=4\n[[package]]\nname='edit_app'\nversion='0.1.0'\ndependencies=['edit_dep']\n[[package]]\nname='edit_dep'\nversion='0.1.0'\n",
            );
            write(
                &source,
                "dep/Cargo.toml",
                "[package]\nname='edit_dep'\nversion='0.1.0'\nedition='2021'\n",
            );
            write(&source, "dep/src/lib.rs", "pub fn value() -> u32 { 1 }\n");
            write(&source, "src/main.rs", MAIN.replace("OFFSET", "0"));
            write(&source, "build.rs", BUILD.replace("GENERATED", "10"));
            Self { root, source }
        }

        pub(super) fn edit(&self, name: &str, bytes: impl AsRef<[u8]>) {
            let old = fs::metadata(self.source.join(name))
                .unwrap()
                .modified()
                .unwrap();
            write(&self.source, name, bytes);
            // Content changes with the old mtime deliberately restored.
            File::open(self.source.join(name))
                .unwrap()
                .set_times(FileTimes::new().set_modified(old))
                .unwrap();
        }

        fn run(&self, cache: &Arc<TargetCache>, command: &str, hit: bool) -> Run {
            self.run_with_inputs(cache, command, hit, observe(&self.source), None)
        }

        pub(super) fn run_with_inputs(
            &self,
            cache: &Arc<TargetCache>,
            command: &str,
            hit: bool,
            input: WorkspaceInputs,
            cargo_home: Option<&Path>,
        ) -> Run {
            use rabs_sandbox::cargo_artifacts::{
                CARGO_ARTIFACTS_VERSION, CARGO_TEST_ARTIFACTS_VERSION,
            };
            let before = SourceTimes::capture(&input, &|| false).unwrap();
            let original = input.clone();
            // Stable physical paths model canonical mount destinations here;
            // this is real Cargo/rustc, not a namespace or TLS qualification.
            let runtime = tempfile::Builder::new()
                .prefix("workspace")
                .rand_bytes(0)
                .permissions(fs::Permissions::from_mode(0o700))
                .tempdir_in(self.root.path())
                .unwrap();
            let input = input.clone_into(runtime, &|| false).unwrap();
            let workspace = input.root.clone();
            let request = CanonicalExecRequest {
                request_id: 1,
                program: "/__rabs/toolchain/bin/cargo".into(),
                args: [
                    command,
                    "--workspace",
                    "--frozen",
                    "--offline",
                    "--message-format=json",
                    "--target-dir=/__rabs/out/cargo",
                    "--jobs=1",
                ]
                .into_iter()
                .map(str::to_owned)
                .collect(),
                command_context: CommandContext::default(),
                dependency_context: None,
                toolchain_backing: "/fixture/toolchain".into(),
                toolchain_identity: Some(ToolchainIdentity {
                    sha256: [1; 32],
                    files: 2,
                    bytes: 3,
                }),
                workspace_backing: "/fixture/source".into(),
                jobserver_grant: Some(1),
            };
            let contract = if command == "test" {
                CARGO_TEST_ARTIFACTS_VERSION
            } else {
                CARGO_ARTIFACTS_VERSION
            };
            let plan = crate::artifacts::parse_plan(&serde_json::json!({
                "program":request.program,"args":request.args,
                "artifacts":{"unit":"cargo","files":[],"tree":"tree-files-v1","cargo":contract}
            }))
            .unwrap()
            .unwrap();
            let mut spec = CanonicalNamespaceSpec::new();
            spec.env = vec![
                ("CARGO_INCREMENTAL".into(), "0".into()),
                ("RUSTFLAGS".into(), "-C debuginfo=0".into()),
            ];
            if cargo_home.is_some() {
                spec.env
                    .push(("CARGO_HOME".into(), rabs_sandbox::layout::CARGO_HOME.into()));
            }
            let support = HostIsolationSupport {
                bubblewrap: Some("key-only-fixture".into()),
                unprivileged_userns: true,
                overlayfs: false,
                cgroup_v2: false,
                landlock: false,
            };
            let scope =
                TargetCacheScope::new("worker", "coordinator", &ResultRecipient::LoopbackFixture);
            let exact = target_key(scope, &request, &input, &spec, &support, &plan, 1).unwrap();
            let compatible =
                target_compatibility_key(scope, &request, &input, &spec, &support, &plan, 1)
                    .unwrap();
            let (attempt, restored) = cache
                .acquire(
                    exact,
                    compatible,
                    input,
                    || PreparedArtifacts::fixture(plan.clone(), self.root.path()),
                    1,
                    &|| false,
                )
                .unwrap();
            assert_eq!(restored.is_some(), hit, "{command}: seed selection");
            let target = restored
                .unwrap_or_else(|| PreparedArtifacts::fixture(plan, self.root.path()).unwrap());
            let args = request.args.iter().map(|argument| {
                if argument == "--target-dir=/__rabs/out/cargo" {
                    format!("--target-dir={}", target.backing().display())
                } else {
                    argument.clone()
                }
            });
            let mut cargo =
                Command::new(std::env::var_os("CARGO").unwrap_or_else(|| "cargo".into()));
            cargo
                .args(args)
                .current_dir(workspace)
                .env_remove("RUSTC_WRAPPER")
                .env_remove("RUSTC_WORKSPACE_WRAPPER")
                .env_remove("CARGO_ENCODED_RUSTFLAGS")
                .env("CARGO_INCREMENTAL", "0")
                .env("RUSTFLAGS", "-C debuginfo=0");
            if let Some(home) = cargo_home {
                cargo.env("CARGO_HOME", home);
            }
            let result = cargo
                .output()
                .expect("run real Cargo/rustc for source-edit invalidation");
            assert!(
                result.status.success(),
                "{command}: {}\n{}",
                String::from_utf8_lossy(&result.stdout),
                String::from_utf8_lossy(&result.stderr),
            );
            let artifacts = result
                .stdout
                .split(|byte| *byte == b'\n')
                .filter_map(|line| serde_json::from_slice::<serde_json::Value>(line).ok())
                .filter(|report| report["reason"] == "compiler-artifact")
                .collect();
            let captured = target
                .capture_fixture_cargo_output(result.stdout.as_slice(), || false)
                .unwrap();
            let output = (command == "build").then(|| {
                let path = target.backing().join("debug/edit_app");
                let ran = Command::new(&path).output().unwrap();
                assert!(ran.status.success());
                (ran.stdout, fs::read(path).unwrap())
            });
            let counts: Vec<_> = captured
                .file_names()
                .filter(|name| name.ends_with("/out/test-runs"))
                .map(|name| {
                    fs::read_to_string(target.backing().join(name))
                        .unwrap()
                        .parse::<u32>()
                        .unwrap()
                })
                .collect();
            assert!(counts.len() <= 1);
            let test_runs = counts.first().copied().unwrap_or(0);
            attempt
                .stage(&target, &captured, &|| false)
                .unwrap()
                .unwrap()
                .publish();
            assert_eq!(SourceTimes::capture(&original, &|| false).unwrap(), before);
            Run {
                artifacts,
                output,
                test_runs,
            }
        }
    }

    #[test]
    fn real_cargo_edits_rebuild_changed_units_keep_dependencies_and_match_a_cold_build() {
        let fixture = CargoFixture::new();
        let cache = Arc::new(TargetCache::new(128 * 1024 * 1024).unwrap());
        let cold = fixture.run(&cache, "build", false);
        cold.fresh("edit_dep", false);
        assert_eq!(cold.output.unwrap().0, b"11\n");
        fixture.edit("src/main.rs", MAIN.replace("OFFSET", "2"));
        let edited = fixture.run(&cache, "build", true);
        edited.fresh("edit_dep", true);
        edited.fresh("edit_app", false);
        assert_eq!(edited.output.unwrap().0, b"13\n");
        fixture.edit("build.rs", BUILD.replace("GENERATED", "20"));
        let generated = fixture.run(&cache, "build", true);
        generated.fresh("edit_dep", true);
        generated.fresh("build-script-build", false);
        assert_eq!(generated.output.unwrap().0, b"23\n");
        fixture.edit("dep/src/lib.rs", "pub fn value() -> u32 { 2 }\n");
        let dependent = fixture.run(&cache, "build", true);
        dependent.fresh("edit_dep", false);
        dependent.fresh("edit_app", false);
        let expected = dependent.output.unwrap();
        assert_eq!(expected.0, b"24\n");
        let independent = Arc::new(TargetCache::new(128 * 1024 * 1024).unwrap());
        let rebuilt = fixture.run(&independent, "build", false);
        rebuilt.fresh("edit_dep", false);
        assert_eq!(
            rebuilt.output.unwrap(),
            expected,
            "warm and cold compiler bytes/results differ"
        );
    }

    #[test]
    fn real_cargo_tests_execute_again_after_an_edit_and_non_rust_changes_start_cold() {
        let fixture = CargoFixture::new();
        let cache = Arc::new(TargetCache::new(128 * 1024 * 1024).unwrap());
        assert_eq!(fixture.run(&cache, "test", false).test_runs, 1);
        fixture.edit("src/main.rs", MAIN.replace("OFFSET", "7"));
        let edited = fixture.run(&cache, "test", true);
        edited.fresh("edit_dep", true);
        assert_eq!(
            edited.test_runs, 2,
            "compiled state is never a cached test result"
        );
        let unchanged = fixture.run(&cache, "test", true);
        assert_eq!(unchanged.test_runs, 3);
        let mut manifest = fs::read(fixture.source.join("Cargo.toml")).unwrap();
        manifest.extend_from_slice(b"\n# changed non-Rust input\n");
        fixture.edit("Cargo.toml", manifest);
        let cold = fixture.run(&cache, "test", false);
        cold.fresh("edit_dep", false);
        assert_eq!(cold.test_runs, 1);
    }

    #[test]
    fn real_cargo_module_add_rename_remove_reuses_dependencies_and_matches_cold_outputs() {
        let fixture = CargoFixture::new();
        let cache = Arc::new(TargetCache::new(128 * 1024 * 1024).unwrap());
        assert_eq!(
            fixture.run(&cache, "build", false).output.unwrap().0,
            b"11\n"
        );
        write(
            &fixture.source,
            "src/extra.rs",
            "pub fn bonus() -> u32 { 3 }\n",
        );
        fixture.edit(
            "src/main.rs",
            format!("mod extra;\n{}", MAIN.replace("OFFSET", "extra::bonus()")),
        );
        let added = fixture.run(&cache, "build", true);
        added.fresh("edit_dep", true);
        added.fresh("edit_app", false);
        assert_eq!(added.output.unwrap().0, b"14\n");

        fs::rename(
            fixture.source.join("src/extra.rs"),
            fixture.source.join("src/renamed.rs"),
        )
        .unwrap();
        fixture.edit(
            "src/main.rs",
            format!(
                "mod renamed;\n{}",
                MAIN.replace("OFFSET", "renamed::bonus()")
            ),
        );
        let renamed = fixture.run(&cache, "build", true);
        renamed.fresh("edit_dep", true);
        renamed.fresh("edit_app", false);
        assert_eq!(renamed.output.unwrap().0, b"14\n");

        fs::rename(
            fixture.source.join("src/renamed.rs"),
            fixture.root.path().join("retired-module.rs"),
        )
        .unwrap();
        // Different from the initial exact key: this must restore the most
        // recent compatible seed and genuinely handle the removed member.
        fixture.edit("src/main.rs", MAIN.replace("OFFSET", "5"));
        let removed = fixture.run(&cache, "build", true);
        removed.fresh("edit_dep", true);
        removed.fresh("edit_app", false);
        let expected = removed.output.unwrap();
        assert_eq!(expected.0, b"16\n");
        let independent = Arc::new(TargetCache::new(128 * 1024 * 1024).unwrap());
        let cold = fixture.run(&independent, "build", false);
        cold.fresh("edit_dep", false);
        assert_eq!(
            cold.output.unwrap(),
            expected,
            "refactored warm and cold outputs differ"
        );
    }

    const DIRECTORY_BUILD: &str = r#"fn sum(path: &std::path::Path) -> u32 {
    std::fs::read_dir(path).unwrap().map(|entry| {
        let path = entry.unwrap().path();
        if path.is_dir() { sum(&path) }
        else { std::fs::read_to_string(path).unwrap().trim().parse::<u32>().unwrap() }
    }).sum()
}
fn main() {
    let out = std::path::PathBuf::from(std::env::var_os("OUT_DIR").unwrap());
    let count = std::fs::read_to_string(out.join("build-runs")).ok()
        .map(|v| v.parse::<u32>().unwrap()).unwrap_or(0) + 1;
    std::fs::write(out.join("build-runs"), count.to_string()).unwrap();
    std::fs::write(out.join("generated.rs"), (100 * count + sum(std::path::Path::new("scan"))).to_string()).unwrap();
    println!("cargo:rerun-if-changed=scan");
}
"#;

    #[test]
    fn real_cargo_directory_build_scripts_observe_additions_removals_and_renames() {
        let fixture = CargoFixture::new();
        fixture.edit("build.rs", DIRECTORY_BUILD);
        write(&fixture.source, "scan/left.rs", b"2");
        write(&fixture.source, "scan/nested/right.rs", b"3");
        let cache = Arc::new(TargetCache::new(128 * 1024 * 1024).unwrap());
        assert_eq!(
            fixture.run(&cache, "build", false).output.unwrap().0,
            b"106\n"
        );
        write(&fixture.source, "scan/new/deep.rs", b"5");
        File::open(fixture.source.join("scan/new/deep.rs"))
            .unwrap()
            .set_times(
                FileTimes::new().set_modified(SystemTime::UNIX_EPOCH + Duration::from_secs(1)),
            )
            .unwrap();
        let added = fixture.run(&cache, "build", true);
        added.fresh("edit_dep", true);
        assert_eq!(added.output.unwrap().0, b"211\n");
        fs::rename(
            fixture.source.join("scan/nested"),
            fixture.root.path().join("removed-scan"),
        )
        .unwrap();
        let removed = fixture.run(&cache, "build", true);
        removed.fresh("edit_dep", true);
        assert_eq!(removed.output.unwrap().0, b"308\n");
        fs::rename(
            fixture.source.join("scan/new"),
            fixture.source.join("scan/renamed"),
        )
        .unwrap();
        let renamed = fixture.run(&cache, "build", true);
        renamed.fresh("edit_dep", true);
        assert_eq!(
            renamed.output.unwrap().0,
            b"408\n",
            "same-byte rename must rerun the scanner"
        );
        // An exact repeat must remain genuinely fresh, not invalidate the
        // build script on every target restore merely because dirs were copied.
        assert_eq!(
            fixture.run(&cache, "build", true).output.unwrap().0,
            b"408\n"
        );
    }

    #[test]
    fn real_cargo_default_build_script_detects_a_removal_with_no_changed_remaining_rust_file() {
        let fixture = CargoFixture::new();
        fixture.edit(
            "build.rs",
            DIRECTORY_BUILD.replace("    println!(\"cargo:rerun-if-changed=scan\");\n", ""),
        );
        write(&fixture.source, "scan/left.rs", b"2");
        write(&fixture.source, "scan/right.rs", b"3");
        let cache = Arc::new(TargetCache::new(128 * 1024 * 1024).unwrap());
        assert_eq!(
            fixture.run(&cache, "build", false).output.unwrap().0,
            b"106\n"
        );
        fs::rename(
            fixture.source.join("scan/right.rs"),
            fixture.root.path().join("removed.rs"),
        )
        .unwrap();
        let removed = fixture.run(&cache, "build", true);
        removed.fresh("edit_dep", true);
        assert_eq!(removed.output.unwrap().0, b"203\n");
        assert_eq!(
            fixture.run(&cache, "build", true).output.unwrap().0,
            b"203\n"
        );
    }
}
