//! Conservative source-edit reuse for PRIVATE Cargo targets, not action results.
//!
//! Cargo tracks local/path-package source mtimes, but does not do so for registry
//! and Git packages. Keep all directory-source packages (identified by their
//! checksum document), non-Rust files, file membership and executable modes
//! exact. Captured Cargo-home projections remain outside this first edit family:
//! their full transport identity cannot be derived from the workspace alone.
//! Unknown Cargo arguments/commands are excluded by the caller's existing gate.
//!
//! A matching family only selects a seed. Both trees are independently verified
//! and copied; every changed input and its parent directories must become newer
//! than ALL retained source and target timestamps. Unchanged input timestamps
//! and every output timestamp are preserved. A regressed clock or a filesystem
//! that cannot represent the requested timestamps yields a cold build, not a
//! stale fingerprint. The current command and its artifact report still run.

use super::{Seed, SourceTimes, WorkspaceInputs, checkpoint, invalid};
use rabs_sandbox::source_transfer::{SourceFile, SourceManifest};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
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

/// A length-framed family digest retains names, membership, modes and all
/// non-editable bytes. An eligible .rs file retains its name/mode, not its old
/// size/content. This value is NEVER a source manifest or a compiler action key.
pub(super) fn identity(inputs: &WorkspaceInputs) -> Option<[u8; 32]> {
    if inputs.projection.is_some() || inputs.full_source_digest != inputs.manifest.digest() {
        return None;
    }
    let protected = protected_roots(&inputs.manifest);
    let mut hash = Sha256::new();
    hash.update(b"rabs.private-cargo-source-edits.v1\0");
    hash.update((inputs.manifest.files().len() as u64).to_be_bytes());
    let mut has_editable = false;
    for file in inputs.manifest.files() {
        let edit = editable(file, &protected);
        has_editable |= edit;
        hash.update((file.path.len() as u64).to_be_bytes());
        hash.update(file.path.as_bytes());
        hash.update([u8::from(file.executable), u8::from(edit)]);
        if !edit {
            hash.update(file.len.to_be_bytes());
            hash.update(file.sha256);
        }
    }
    has_editable.then(|| hash.finalize().into())
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
    if seed.source_manifest.digest() == inputs.manifest.digest() {
        return Ok(seed.source.clone());
    }
    if identity(inputs).is_none_or(|family| seed.edit_family != Some(family)) {
        return Err(invalid("source edit is outside the retained Cargo seed family"));
    }
    let previous = seed.source_manifest.files();
    let current = inputs.manifest.files();
    if previous.len() != current.len() {
        return Err(invalid("source-edit file membership changed"));
    }
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
    let mut wanted = seed.source.clone();
    let mut edits = 0;
    for (old, new) in previous.iter().zip(current) {
        checkpoint(stopped)?;
        if old.path != new.path || old.executable != new.executable {
            return Err(invalid("source-edit layout or executable mode changed"));
        }
        if old.len == new.len && old.sha256 == new.sha256 {
            continue;
        }
        if !editable(new, &protected) {
            return Err(invalid("source edit changed an immutable Cargo input"));
        }
        *wanted
            .files
            .get_mut(&new.path)
            .ok_or_else(|| invalid("edited source has no retained timestamp"))? = now;
        for parent in Path::new(&new.path).ancestors().skip(1) {
            let name = parent
                .to_str()
                .ok_or_else(|| invalid("non-UTF-8 source-edit parent"))?;
            wanted
                .directories
                .get_mut(name)
                .ok_or_else(|| invalid("edited source has no retained parent"))?
                .modified = now;
        }
        edits += 1;
    }
    if edits == 0 {
        return Err(invalid(
            "changed manifest contains no supported Rust-source edit",
        ));
    }
    Ok(wanted)
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;
    use super::super::{
        ArtifactPlan, PreparedArtifacts, TargetCache, TargetCacheScope, TargetKey,
        private_directory, target_compatibility_key, target_key,
    };
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

    fn write(root: &Path, name: &str, bytes: impl AsRef<[u8]>) {
        let path = root.join(name);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, bytes).unwrap();
    }

    fn observe(root: &Path) -> WorkspaceInputs {
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
                        path: entry.path().strip_prefix(root).unwrap().to_str().unwrap().into(),
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

    fn source() -> tempfile::TempDir {
        let source = private_directory("rabs-edits-source-").unwrap();
        write(source.path(), "src/lib.rs", "pub fn answer() -> u32 { 1 }\n");
        write(source.path(), "dep/lib.rs", "pub fn stable() {}\n");
        write(source.path(), "Cargo.toml", "[package]\nname='fixture'\n");
        source
    }

    fn stage_fixture(cache: &Arc<TargetCache>, input: WorkspaceInputs) {
        // Structural target-cache fixture, not a claim of Cargo execution.
        let plan = ArtifactPlan::new_tree("cargo".into(), vec!["artifact".into()]).unwrap();
        let target = PreparedArtifacts::new(plan.clone()).unwrap();
        fs::write(target.backing().join("artifact"), b"retained target").unwrap();
        let captured = target.capture_with_dependency_inputs(None, || false).unwrap();
        let key = TargetKey(input.manifest.digest());
        let compatible = identity(&input).map(TargetKey);
        let (attempt, restored) = cache.acquire(
            key, compatible, input, || PreparedArtifacts::new(plan), 1, &|| false,
        ).unwrap();
        assert!(restored.is_none());
        attempt.stage(&target, &captured, &|| false).unwrap().unwrap().publish();
    }

    fn restore_fixture(cache: &Arc<TargetCache>, input: WorkspaceInputs)
        -> (super::super::TargetAttempt, Option<PreparedArtifacts>)
    {
        let plan = ArtifactPlan::new_tree("cargo".into(), vec!["artifact".into()]).unwrap();
        cache.acquire(
            TargetKey(input.manifest.digest()), identity(&input).map(TargetKey), input,
            || PreparedArtifacts::new(plan), 2, &|| false,
        ).unwrap()
    }

    #[test]
    fn edit_family_keeps_non_rust_bytes_vendor_sources_membership_and_modes_exact() {
        let root = source();
        write(root.path(), "vendor/dep/.cargo-checksum.json", "{}");
        write(root.path(), "vendor/dep/src/lib.rs", "pub fn dependency() {}\n");
        let original = observe(root.path());
        let expected = identity(&original).unwrap();
        write(root.path(), "src/lib.rs", "pub fn answer() -> u32 { 999 }\n");
        assert_eq!(identity(&observe(root.path())), Some(expected));
        for name in ["Cargo.toml", "vendor/dep/src/lib.rs", "vendor/dep/.cargo-checksum.json"] {
            let before = fs::read(root.path().join(name)).unwrap();
            write(root.path(), name, b"different bytes");
            assert_ne!(identity(&observe(root.path())), Some(expected), "{name}");
            write(root.path(), name, before);
        }
        fs::set_permissions(root.path().join("src/lib.rs"), fs::Permissions::from_mode(0o700)).unwrap();
        assert_ne!(identity(&observe(root.path())), Some(expected));
        fs::set_permissions(root.path().join("src/lib.rs"), fs::Permissions::from_mode(0o600)).unwrap();
        write(root.path(), "src/added.rs", b"new member");
        assert_ne!(identity(&observe(root.path())), Some(expected));
    }

    #[test]
    fn hidden_cargo_home_bytes_and_root_directory_sources_never_enter_the_edit_family() {
        let root = source();
        let mut input = observe(root.path());
        assert!(identity(&input).is_some());
        input.full_source_digest[0] ^= 1;
        assert!(identity(&input).is_none());
        input.full_source_digest = input.manifest.digest();
        input.projection = Some(("isolated-registry-cargo-home-v1".into(), "cache".into()));
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
        write(source.path(), "src/lib.rs", "pub fn answer() -> u32 { 2 }\n");
        // A restored/forged old source mtime must not conceal changed bytes.
        File::open(source.path().join("src/lib.rs")).unwrap()
            .set_times(FileTimes::new().set_modified(old_source.files["src/lib.rs"])).unwrap();
        let input = observe(source.path());
        let before = SourceTimes::capture(&input, &|| false).unwrap();
        let (attempt, restored) = restore_fixture(&cache, input.clone());
        let restored = restored.expect("source edit should retain compiled dependencies");
        assert!(attempt.times.files["src/lib.rs"] > target_time);
        assert!(attempt.times.directories["src"].modified > target_time);
        assert!(attempt.times.directories[""].modified > target_time);
        assert_eq!(attempt.times.files["dep/lib.rs"], old_source.files["dep/lib.rs"]);
        assert_eq!(attempt.times.directories["dep"], old_source.directories["dep"]);
        assert_eq!(
            fs::metadata(restored.backing().join("artifact")).unwrap().modified().unwrap(),
            target_time,
        );
        assert_eq!(SourceTimes::capture(&input, &|| false).unwrap(), before);
        assert_ne!(fs::metadata(attempt.inputs.root.join("src/lib.rs")).unwrap().ino(),
            fs::metadata(source.path().join("src/lib.rs")).unwrap().ino());
        assert_eq!(fs::read(attempt.inputs.root.join("src/lib.rs")).unwrap(),
            fs::read(source.path().join("src/lib.rs")).unwrap());
        assert_eq!(seed.source, old_source, "old generation remains immutable");
    }

    #[test]
    fn clock_regression_refuses_the_edit_but_not_identical_source() {
        let root = source();
        let cache = Arc::new(TargetCache::new(4096).unwrap());
        let original = observe(root.path());
        stage_fixture(&cache, original.clone());
        let seed = Arc::clone(&cache.state.lock().unwrap().entries[0]);
        let newest = seed.tree.files.values().map(|file| file.modified)
            .chain(seed.tree.directories.values().map(|directory| directory.modified))
            .chain(seed.source.files.values().copied())
            .chain(seed.source.directories.values().map(|directory| directory.modified)).max().unwrap();
        write(root.path(), "src/lib.rs", b"edited");
        let changed = observe(root.path());
        for now in [SystemTime::UNIX_EPOCH, newest] {
            assert!(timestamps(&seed, &changed, now, &|| false).is_err());
            assert_eq!(timestamps(&seed, &original, now, &|| false).unwrap(), seed.source);
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
        let (attempt, restored) = cache.acquire(
            TargetKey(changed.manifest.digest()), family, changed.clone(),
            || panic!("incompatible edit must refuse before output allocation"), 2, &|| false,
        ).unwrap();
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
        write(&attempt.inputs.root, "src/lib.rs", b"changed during execution");
        let captured = restored.capture_with_dependency_inputs(None, || false).unwrap();
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
            TargetKey(changed.manifest.digest()), identity(&changed).map(TargetKey), changed.clone(),
            || { stopped.set(true); PreparedArtifacts::new(plan) }, 2, &|| stopped.get(),
        );
        assert_eq!(result.unwrap_err().kind(), io::ErrorKind::Interrupted);
        assert_eq!(cache.state.lock().unwrap().entries.len(), 1);
        assert_eq!(SourceTimes::capture(&changed, &|| false).unwrap(), before);
        assert!(restore_fixture(&cache, changed).1.is_some());
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

    struct CargoFixture {
        root: tempfile::TempDir,
        source: PathBuf,
    }

    struct Run {
        artifacts: Vec<serde_json::Value>,
        output: Option<(Vec<u8>, Vec<u8>)>,
        test_runs: u32,
    }

    impl Run {
        fn fresh(&self, name: &str, fresh: bool) {
            let reports: Vec<_> = self.artifacts.iter()
                .filter(|report| {
                    report["target"]["name"] == name && report["profile"]["test"] == false
                })
                .collect();
            assert!(!reports.is_empty(), "missing artifact {name}: {:?}", self.artifacts);
            assert!(reports.iter().all(|report| report["fresh"] == fresh), "{name}: {reports:?}");
        }
    }

    impl CargoFixture {
        fn new() -> Self {
            let root = private_directory("rabs-real-source-edits-").unwrap();
            let source = root.path().join("source");
            fs::create_dir(&source).unwrap();
            fs::set_permissions(&source, fs::Permissions::from_mode(0o700)).unwrap();
            write(&source, "Cargo.toml", "[package]\nname='edit_app'\nversion='0.1.0'\nedition='2021'\n[workspace]\nmembers=['dep']\n[dependencies]\nedit_dep={path='dep'}\n");
            write(&source, "Cargo.lock", "version=4\n[[package]]\nname='edit_app'\nversion='0.1.0'\ndependencies=['edit_dep']\n[[package]]\nname='edit_dep'\nversion='0.1.0'\n");
            write(&source, "dep/Cargo.toml", "[package]\nname='edit_dep'\nversion='0.1.0'\nedition='2021'\n");
            write(&source, "dep/src/lib.rs", "pub fn value() -> u32 { 1 }\n");
            write(&source, "src/main.rs", MAIN.replace("OFFSET", "0"));
            write(&source, "build.rs", BUILD.replace("GENERATED", "10"));
            Self { root, source }
        }

        fn edit(&self, name: &str, bytes: impl AsRef<[u8]>) {
            let old = fs::metadata(self.source.join(name)).unwrap().modified().unwrap();
            write(&self.source, name, bytes);
            // Content changes with the old mtime deliberately restored.
            File::open(self.source.join(name)).unwrap()
                .set_times(FileTimes::new().set_modified(old)).unwrap();
        }

        fn run(&self, cache: &Arc<TargetCache>, command: &str, hit: bool) -> Run {
            use rabs_sandbox::cargo_artifacts::{CARGO_ARTIFACTS_VERSION, CARGO_TEST_ARTIFACTS_VERSION};
            let input = observe(&self.source);
            let before = SourceTimes::capture(&input, &|| false).unwrap();
            // Stable physical paths model canonical mount destinations here;
            // this is real Cargo/rustc, not a namespace or TLS qualification.
            let runtime = tempfile::Builder::new().prefix("workspace").rand_bytes(0)
                .permissions(fs::Permissions::from_mode(0o700)).tempdir_in(self.root.path()).unwrap();
            let input = input.clone_into(runtime, &|| false).unwrap();
            let workspace = input.root.clone();
            let request = CanonicalExecRequest {
                request_id: 1,
                program: "/__rabs/toolchain/bin/cargo".into(),
                args: [command, "--workspace", "--frozen", "--offline", "--message-format=json", "--target-dir=/__rabs/out/cargo", "--jobs=1"]
                    .into_iter().map(str::to_owned).collect(),
                command_context: CommandContext::default(),
                dependency_context: None,
                toolchain_backing: "/fixture/toolchain".into(),
                toolchain_identity: Some(ToolchainIdentity { sha256: [1; 32], files: 2, bytes: 3 }),
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
            })).unwrap().unwrap();
            let mut spec = CanonicalNamespaceSpec::new();
            spec.env = vec![("CARGO_INCREMENTAL".into(), "0".into()), ("RUSTFLAGS".into(), "-C debuginfo=0".into())];
            let support = HostIsolationSupport {
                bubblewrap: Some("key-only-fixture".into()), unprivileged_userns: true,
                overlayfs: false, cgroup_v2: false, landlock: false,
            };
            let scope = TargetCacheScope::new("worker", "coordinator", &ResultRecipient::LoopbackFixture);
            let exact = target_key(scope, &request, &input, &spec, &support, &plan, 1).unwrap();
            let compatible = target_compatibility_key(scope, &request, &input, &spec, &support, &plan, 1).unwrap();
            let (attempt, restored) = cache.acquire(exact, compatible, input,
                || PreparedArtifacts::fixture(plan.clone(), self.root.path()), 1, &|| false).unwrap();
            assert_eq!(restored.is_some(), hit, "{command}: seed selection");
            let target = restored.unwrap_or_else(|| PreparedArtifacts::fixture(plan, self.root.path()).unwrap());
            let args = request.args.iter().map(|argument| {
                if argument == "--target-dir=/__rabs/out/cargo" {
                    format!("--target-dir={}", target.backing().display())
                } else { argument.clone() }
            });
            let result = Command::new(std::env::var_os("CARGO").unwrap_or_else(|| "cargo".into()))
                .args(args).current_dir(workspace)
                .env_remove("RUSTC_WRAPPER").env_remove("RUSTC_WORKSPACE_WRAPPER")
                .env_remove("CARGO_ENCODED_RUSTFLAGS")
                .env("CARGO_INCREMENTAL", "0").env("RUSTFLAGS", "-C debuginfo=0")
                .output().expect("run real Cargo/rustc for source-edit invalidation");
            assert!(
                result.status.success(),
                "{command}: {}\n{}",
                String::from_utf8_lossy(&result.stdout),
                String::from_utf8_lossy(&result.stderr),
            );
            let artifacts = result.stdout.split(|byte| *byte == b'\n')
                .filter_map(|line| serde_json::from_slice::<serde_json::Value>(line).ok())
                .filter(|report| report["reason"] == "compiler-artifact").collect();
            let captured = target.capture_fixture_cargo_output(result.stdout.as_slice(), || false).unwrap();
            let output = (command == "build").then(|| {
                let path = target.backing().join("debug/edit_app");
                let ran = Command::new(&path).output().unwrap();
                assert!(ran.status.success());
                (ran.stdout, fs::read(path).unwrap())
            });
            let counts: Vec<_> = captured.file_names().filter(|name| name.ends_with("/out/test-runs"))
                .map(|name| fs::read_to_string(target.backing().join(name)).unwrap().parse::<u32>().unwrap()).collect();
            assert!(counts.len() <= 1);
            let test_runs = counts.first().copied().unwrap_or(0);
            attempt.stage(&target, &captured, &|| false).unwrap().unwrap().publish();
            assert_eq!(SourceTimes::capture(&observe(&self.source), &|| false).unwrap(), before);
            Run { artifacts, output, test_runs }
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
        assert_eq!(rebuilt.output.unwrap(), expected, "warm and cold compiler bytes/results differ");
    }

    #[test]
    fn real_cargo_tests_execute_again_after_an_edit_and_non_rust_changes_start_cold() {
        let fixture = CargoFixture::new();
        let cache = Arc::new(TargetCache::new(128 * 1024 * 1024).unwrap());
        assert_eq!(fixture.run(&cache, "test", false).test_runs, 1);
        fixture.edit("src/main.rs", MAIN.replace("OFFSET", "7"));
        let edited = fixture.run(&cache, "test", true);
        edited.fresh("edit_dep", true);
        assert_eq!(edited.test_runs, 2, "compiled state is never a cached test result");
        let unchanged = fixture.run(&cache, "test", true);
        assert_eq!(unchanged.test_runs, 3);
        let mut manifest = fs::read(fixture.source.join("Cargo.toml")).unwrap();
        manifest.extend_from_slice(b"\n# changed non-Rust input\n");
        fixture.edit("Cargo.toml", manifest);
        let cold = fixture.run(&cache, "test", false);
        cold.fresh("edit_dep", false);
        assert_eq!(cold.test_runs, 1);
    }
}
