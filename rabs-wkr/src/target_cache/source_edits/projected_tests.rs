//! Projected dependency identities and real offline Cargo edit reuse. Structural
//! Git fixtures test manifest binding, not Git object closure or native replay.

use super::super::{ArtifactPlan, PreparedArtifacts, TargetCache, TargetKey};
use super::tests::{CargoFixture, Run, observe, restore_fixture, source, stage_fixture, write};
use super::*;
use rabs_sandbox::canonical_namespace::{Bind, CanonicalNamespaceSpec};
use rabs_sandbox::cargo_home::{
    CAPTURED_GIT_CONFIG, CARGO_HOME_SOURCE_VERSION, CargoHomeProjection,
    ISOLATED_CARGO_HOME_SOURCE_VERSION, ISOLATED_GIT_CARGO_HOME_SOURCE_VERSION,
};
use rabs_sandbox::source_transfer::{MAX_SOURCE_CHUNK, SourceReceiver};
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::process::Command;
use std::sync::Arc;

const PREFIX: &str = "captured-cache";
const INDEX: &str = "index.crates.io-1949cf8c6b5b557f";

fn member(path: &str, bytes: &[u8]) -> SourceFile {
    SourceFile {
        path: path.into(),
        len: bytes.len() as u64,
        sha256: Sha256::digest(bytes).into(),
        executable: false,
    }
}

fn registry_members() -> Vec<SourceFile> {
    vec![
        member("registry/cache/example/dep-1.crate", b"archive"),
        member(
            "registry/src/example/dep-1/src/lib.rs",
            b"pub fn dependency() {}",
        ),
        member("registry/index/example/config.json", b"{}"),
    ]
}

fn git_members() -> Vec<SourceFile> {
    let database = "git/db/dep-0123456789abcdef";
    let pack = "objects/pack/pack-0123456789abcdef0123456789abcdef01234567";
    let revision = b"0123456789abcdef0123456789abcdef01234567\n";
    [
        ("config".to_owned(), CAPTURED_GIT_CONFIG.to_vec()),
        ("HEAD".to_owned(), revision.to_vec()),
        ("shallow".to_owned(), revision.to_vec()),
        ("refs/heads/rabs-captured".to_owned(), revision.to_vec()),
        (format!("{pack}.pack"), vec![0; 32]),
        (format!("{pack}.idx"), vec![0; 1072]),
    ]
    .into_iter()
    .map(|(path, bytes)| member(&format!("{database}/{path}"), &bytes))
    .collect()
}

fn transport(workspace: &SourceManifest, cache: &[SourceFile], prefix: &str) -> SourceManifest {
    let mut files = workspace.files().to_vec();
    files.extend(cache.iter().cloned().map(|mut file| {
        file.path = format!("{prefix}/{}", file.path);
        file
    }));
    SourceManifest::new(files).unwrap()
}

fn projected(
    mut inputs: WorkspaceInputs,
    cache: &[SourceFile],
    version: &str,
    prefix: &str,
) -> WorkspaceInputs {
    let source = transport(&inputs.manifest, cache, prefix);
    inputs.full_source_digest = source.digest();
    inputs.projection = Some(Arc::new(
        CargoHomeProjection::for_version(version, prefix, &source).unwrap(),
    ));
    inputs
}

#[test]
fn projected_edits_keep_registry_and_git_cache_bytes_modes_and_membership_exact() {
    for version in [
        ISOLATED_CARGO_HOME_SOURCE_VERSION,
        ISOLATED_GIT_CARGO_HOME_SOURCE_VERSION,
    ] {
        let root = source();
        let mut members = registry_members();
        if version == ISOLATED_GIT_CARGO_HOME_SOURCE_VERSION {
            members.extend(git_members());
        }
        let original = projected(observe(root.path()), &members, version, PREFIX);
        let family = identity(&original).unwrap();
        let old_digest = original.full_source_digest;
        let cache = Arc::new(TargetCache::new(4096).unwrap());
        stage_fixture(&cache, original);
        write(root.path(), "src/lib.rs", "pub fn answer() -> u32 { 9 }\n");
        let edited = projected(observe(root.path()), &members, version, PREFIX);
        assert_ne!(
            edited.full_source_digest, old_digest,
            "exact input identity still changes"
        );
        assert_eq!(identity(&edited), Some(family));
        assert!(restore_fixture(&cache, edited).1.is_some(), "{version}");

        let mut variants = Vec::new();
        for at in 0..members.len() {
            let mut changed = members.clone();
            changed[at].sha256[0] ^= 1;
            variants.push((format!("changed bytes: {}", changed[at].path), changed));
        }
        let mut changed = members.clone();
        changed[0].executable = true;
        variants.push(("executable bit".into(), changed));
        let mut changed = members.clone();
        changed[0].len += 1;
        variants.push(("file size".into(), changed));
        let mut changed = members.clone();
        changed.remove(0);
        variants.push(("removed cache member".into(), changed));
        let mut changed = members.clone();
        changed.push(member(
            "registry/src/injected/src/lib.rs",
            b"pub fn injected() {}",
        ));
        variants.push(("injected Rust cache member".into(), changed));
        let mut changed = members.clone();
        changed[0].path.push_str(".renamed");
        variants.push(("renamed cache member".into(), changed));
        for (label, changed) in variants {
            let inputs = projected(observe(root.path()), &changed, version, PREFIX);
            assert_ne!(identity(&inputs), Some(family), "{version}: {label}");
            assert!(
                restore_fixture(&cache, inputs).1.is_none(),
                "{version}: {label}"
            );
        }
        let moved = projected(observe(root.path()), &members, version, "other-cache");
        assert_ne!(
            identity(&moved),
            Some(family),
            "transport prefix remains exact"
        );
        assert!(restore_fixture(&cache, moved).1.is_none());
    }
}

#[test]
fn a_projection_cannot_hide_missing_injected_or_mismatched_transport_inputs() {
    let root = source();
    let members = registry_members();
    let input = projected(
        observe(root.path()),
        &members,
        ISOLATED_CARGO_HOME_SOURCE_VERSION,
        PREFIX,
    );
    assert!(identity(&input).is_some());
    let mut wrong = input.clone();
    wrong.full_source_digest[0] ^= 1;
    assert!(identity(&wrong).is_none());
    let mut wrong = input.clone();
    wrong.projection = None;
    assert!(identity(&wrong).is_none());
    let mut wrong = input.clone();
    let mut files = wrong.manifest.files().to_vec();
    files[0].sha256[0] ^= 1;
    wrong.manifest = SourceManifest::new(files).unwrap();
    assert!(
        identity(&wrong).is_none(),
        "projection must belong to this workspace"
    );
    let mut changed = members.clone();
    changed[0].sha256[0] ^= 1;
    let mut wrong = input.clone();
    wrong.projection = projected(
        observe(root.path()),
        &changed,
        ISOLATED_CARGO_HOME_SOURCE_VERSION,
        PREFIX,
    )
    .projection;
    assert!(
        identity(&wrong).is_none(),
        "another transport's cache cannot supply a digest hint"
    );

    let source = transport(&input.manifest, &members, PREFIX);
    assert!(CargoHomeProjection::for_version("unknown", PREFIX, &source).is_err());
    assert!(
        CargoHomeProjection::for_version(
            ISOLATED_CARGO_HOME_SOURCE_VERSION,
            PREFIX,
            &input.manifest
        )
        .is_err(),
        "removing the whole cache is not a valid projection"
    );
    let mut injected = members;
    injected.push(member("credentials.toml", b"must not be imported"));
    let injected = transport(&input.manifest, &injected, PREFIX);
    assert!(
        CargoHomeProjection::for_version(ISOLATED_CARGO_HOME_SOURCE_VERSION, PREFIX, &injected)
            .is_err()
    );
    let mut legacy = input;
    legacy.projection = Some(Arc::new(
        CargoHomeProjection::for_version(CARGO_HOME_SOURCE_VERSION, PREFIX, &source).unwrap(),
    ));
    legacy.manifest = source;
    assert!(
        identity(&legacy).is_none(),
        "legacy visible-prefix layout remains exact-source only"
    );
}

#[test]
fn forged_compatibility_cannot_restore_an_edited_source_with_different_cache_bytes() {
    let root = source();
    let members = registry_members();
    let original = projected(
        observe(root.path()),
        &members,
        ISOLATED_CARGO_HOME_SOURCE_VERSION,
        PREFIX,
    );
    let family = identity(&original).map(TargetKey);
    let cache = Arc::new(TargetCache::new(4096).unwrap());
    stage_fixture(&cache, original);
    let mut changed = members.clone();
    changed[0].sha256[0] ^= 1;
    for edit in [false, true] {
        if edit {
            write(root.path(), "src/lib.rs", "pub fn answer() -> u32 { 2 }\n");
        }
        let inputs = projected(
            observe(root.path()),
            &changed,
            ISOLATED_CARGO_HOME_SOURCE_VERSION,
            PREFIX,
        );
        let (_, restored) = cache
            .acquire(
                TargetKey(inputs.full_source_digest),
                family,
                inputs,
                || panic!("cache mismatch must refuse before output allocation"),
                2,
                &|| false,
            )
            .unwrap();
        assert!(restored.is_none());
        assert_eq!(cache.state.lock().unwrap().entries.len(), 1);
    }

    let original = projected(
        observe(root.path()),
        &members,
        ISOLATED_CARGO_HOME_SOURCE_VERSION,
        PREFIX,
    );
    let (attempt, restored) = restore_fixture(&cache, original.clone());
    let restored = restored.unwrap();
    let plan = ArtifactPlan::new_tree("cargo".into(), vec!["artifact".into()]).unwrap();
    let fresh = PreparedArtifacts::new(plan.clone()).unwrap();
    let mut spec = CanonicalNamespaceSpec::new();
    spec.ro_binds.push(Bind {
        backing: original.root.clone(),
        visible: rabs_sandbox::layout::WORKSPACE.into(),
    });
    spec.rw_binds.push(Bind {
        backing: fresh.backing().to_path_buf(),
        visible: plan.virtual_root().into(),
    });
    let before = spec.clone();
    let mut wrong = original.clone();
    wrong.projection = projected(
        observe(root.path()),
        &changed,
        ISOLATED_CARGO_HOME_SOURCE_VERSION,
        PREFIX,
    )
    .projection;
    assert!(
        attempt
            .bind_restored(&mut spec, &wrong, &fresh, &restored, &plan)
            .is_err()
    );
    assert_eq!(
        spec, before,
        "neither owned mount may change on a projection mismatch"
    );
    attempt
        .bind_restored(&mut spec, &original, &fresh, &restored, &plan)
        .unwrap();
    assert_eq!(spec.ro_binds[0].backing, attempt.inputs.root);
    assert_eq!(spec.rw_binds[0].backing, restored.backing());
}

struct RegistryFixture {
    cargo: CargoFixture,
    cache: std::path::PathBuf,
}

impl RegistryFixture {
    fn new() -> Self {
        let cargo = CargoFixture::new();
        let package = cargo.root.path().join("registry-package");
        write(
            &package,
            "Cargo.toml",
            "[package]\nname='registry_dep'\nversion='1.0.0'\nedition='2021'\n[workspace]\n",
        );
        write(&package, "src/lib.rs", "pub fn answer() -> u32 { 40 }\n");
        let packaged = Command::new(std::env::var_os("CARGO").unwrap_or_else(|| "cargo".into()))
            .args(["package", "--no-verify", "--offline", "--allow-dirty"])
            .current_dir(&package)
            .env("CARGO_HOME", cargo.root.path().join("package-home"))
            .env("CARGO_TARGET_DIR", cargo.root.path().join("package-target"))
            .output()
            .expect("package the local registry fixture with stock Cargo");
        assert!(
            packaged.status.success(),
            "{}",
            String::from_utf8_lossy(&packaged.stderr)
        );
        let archive = fs::read(
            cargo
                .root
                .path()
                .join("package-target/package/registry_dep-1.0.0.crate"),
        )
        .unwrap();
        let checksum = crate::source_transfer::hex(&Sha256::digest(&archive));
        let cache = cargo.root.path().join("captured-cargo-home");
        write(
            &cache,
            &format!("registry/cache/{INDEX}/registry_dep-1.0.0.crate"),
            archive,
        );
        write(
            &cache,
            &format!("registry/index/{INDEX}/config.json"),
            br#"{"dl":"https://static.crates.io/crates","api":"https://crates.io"}"#,
        );
        let entry = serde_json::json!({"name":"registry_dep","vers":"1.0.0","deps":[],"cksum":checksum,"features":{},"yanked":false,"links":null});
        // A synthetic local sparse-cache record consumed by stock Cargo. The
        // production worker copies these bytes opaquely; it is not a resolver.
        let mut record = vec![3, 2, 0, 0, 0];
        record.extend_from_slice(b"etag: \"offline-edit-fixture\"\0");
        record.extend_from_slice(b"1.0.0\0");
        record.extend_from_slice(&serde_json::to_vec(&entry).unwrap());
        record.push(0);
        write(
            &cache,
            &format!("registry/index/{INDEX}/.cache/re/gi/registry_dep"),
            record,
        );
        let mut manifest = fs::read_to_string(cargo.source.join("Cargo.toml")).unwrap();
        manifest.push_str("registry_dep='=1.0.0'\n");
        cargo.edit("Cargo.toml", manifest);
        let lock = format!(
            "version=4\n[[package]]\nname='edit_app'\nversion='0.1.0'\ndependencies=['edit_dep','registry_dep']\n[[package]]\nname='edit_dep'\nversion='0.1.0'\n[[package]]\nname='registry_dep'\nversion='1.0.0'\nsource='registry+https://github.com/rust-lang/crates.io-index'\nchecksum='{checksum}'\n"
        );
        cargo.edit("Cargo.lock", lock);
        let main = fs::read_to_string(cargo.source.join("src/main.rs")).unwrap();
        cargo.edit(
            "src/main.rs",
            main.replace(
                "edit_dep::value()",
                "edit_dep::value() + registry_dep::answer()",
            ),
        );
        Self { cargo, cache }
    }

    fn run(&self, target: &Arc<TargetCache>, hit: bool) -> Run {
        let workspace = observe(&self.cargo.source);
        let cache = observe(&self.cache).manifest;
        let manifest = transport(&workspace.manifest, cache.files(), PREFIX);
        let projection = Arc::new(
            CargoHomeProjection::for_version(ISOLATED_CARGO_HOME_SOURCE_VERSION, PREFIX, &manifest)
                .unwrap(),
        );
        // Fixed host fixture paths model canonical mount destinations. Every
        // attempt still owns a new sealed source and independent writable home.
        let owner = tempfile::Builder::new()
            .prefix("projection")
            .rand_bytes(0)
            .permissions(fs::Permissions::from_mode(0o700))
            .tempdir_in(self.cargo.root.path())
            .unwrap();
        let mut receiver =
            SourceReceiver::create(&owner.path().join("source"), manifest.clone()).unwrap();
        for file in manifest.files() {
            let path = file.path.strip_prefix(&format!("{PREFIX}/")).map_or_else(
                || self.cargo.source.join(&file.path),
                |relative| self.cache.join(relative),
            );
            let bytes = fs::read(path).unwrap();
            for (at, chunk) in bytes.chunks(MAX_SOURCE_CHUNK).enumerate() {
                receiver
                    .write_chunk(
                        &file.path,
                        (at * MAX_SOURCE_CHUNK) as u64,
                        chunk,
                        Sha256::digest(chunk).into(),
                    )
                    .unwrap();
            }
        }
        receiver.seal().unwrap();
        let home = projection
            .prepare(&receiver, &owner.path().join("runtime"), || false)
            .unwrap();
        let workspace = home.projected_workspace().unwrap();
        assert!(!workspace.join(PREFIX).exists());
        assert!(
            !home.root().join("registry/src").exists(),
            "each execution starts from archive-only cache input"
        );
        let input = WorkspaceInputs {
            root: workspace.to_path_buf(),
            manifest: projection.workspace_manifest().unwrap().clone(),
            full_source_digest: manifest.digest(),
            projection: Some(projection),
            runtime_owner: None,
        };
        let result = self
            .cargo
            .run_with_inputs(target, "build", hit, input, Some(home.root()));
        assert!(
            home.root().join("registry/src").is_dir(),
            "Cargo must unpack its own captured dependency"
        );
        result
    }
}

#[test]
fn real_offline_registry_cargo_keeps_dependencies_fresh_after_a_workspace_edit() {
    let fixture = RegistryFixture::new();
    let target = Arc::new(TargetCache::new(128 * 1024 * 1024).unwrap());
    let first = fixture.run(&target, false);
    first.fresh("registry_dep", false);
    assert_eq!(first.output.unwrap().0, b"51\n");
    let main = fs::read_to_string(fixture.cargo.source.join("src/main.rs")).unwrap();
    fixture
        .cargo
        .edit("src/main.rs", main.replace("+ 0 }", "+ 2 }"));
    let edited = fixture.run(&target, true);
    edited.fresh("registry_dep", true);
    edited.fresh("edit_dep", true);
    edited.fresh("edit_app", false);
    assert_eq!(edited.output.unwrap().0, b"53\n");
    // The admitted Cargo-home partition remains byte-exact while the CURRENT
    // projected workspace gains, renames and loses local Rust modules.
    write(
        &fixture.cargo.source,
        "src/bonus.rs",
        "pub fn value() -> u32 { 4 }\n",
    );
    fixture.cargo.edit(
        "src/main.rs",
        format!(
            "mod bonus;\n{}",
            main.replace("+ 0 }", "+ bonus::value() }")
        ),
    );
    let added = fixture.run(&target, true);
    added.fresh("registry_dep", true);
    added.fresh("edit_dep", true);
    added.fresh("edit_app", false);
    assert_eq!(added.output.unwrap().0, b"55\n");
    fs::rename(
        fixture.cargo.source.join("src/bonus.rs"),
        fixture.cargo.source.join("src/renamed.rs"),
    )
    .unwrap();
    fixture.cargo.edit(
        "src/main.rs",
        format!(
            "mod renamed;\n{}",
            main.replace("+ 0 }", "+ renamed::value() }")
        ),
    );
    let renamed = fixture.run(&target, true);
    renamed.fresh("registry_dep", true);
    renamed.fresh("edit_app", false);
    assert_eq!(renamed.output.unwrap().0, b"55\n");
    fs::rename(
        fixture.cargo.source.join("src/renamed.rs"),
        fixture.cargo.root.path().join("retired-module.rs"),
    )
    .unwrap();
    fixture
        .cargo
        .edit("src/main.rs", main.replace("+ 0 }", "+ 5 }"));
    let removed = fixture.run(&target, true);
    removed.fresh("registry_dep", true);
    removed.fresh("edit_dep", true);
    removed.fresh("edit_app", false);
    let expected = removed.output.unwrap();
    assert_eq!(expected.0, b"56\n");
    let cold = fixture.run(
        &Arc::new(TargetCache::new(128 * 1024 * 1024).unwrap()),
        false,
    );
    cold.fresh("registry_dep", false);
    assert_eq!(
        cold.output.unwrap(),
        expected,
        "warm and cold compiler bytes/results differ"
    );
    let config = format!("registry/index/{INDEX}/config.json");
    let mut bytes = fs::read(fixture.cache.join(&config)).unwrap();
    bytes.push(b'\n');
    write(&fixture.cache, &config, bytes);
    let changed_cache = fixture.run(&target, false);
    changed_cache.fresh("registry_dep", false);
    assert_eq!(changed_cache.output.unwrap().0, b"56\n");
}
