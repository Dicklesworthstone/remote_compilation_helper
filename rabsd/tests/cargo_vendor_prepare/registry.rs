//! Real Cargo consumes archive-only crates.io inputs through the production
//! automatic preparer and the worker's isolated Cargo-home/workspace projection.

use super::*;
use flate2::Compression;
use flate2::write::GzEncoder;
use rabs_sandbox::cargo_home::{CargoHomeProjection, ISOLATED_CARGO_HOME_SOURCE_VERSION};
use rabs_sandbox::source_transfer::{MAX_SOURCE_CHUNK, SourceReceiver};

const INDEX: &str = "index.crates.io-1949cf8c6b5b557f";
const PRIVATE_MARKER: &str = "private-cache-input-must-never-be-uploaded";

fn archive(home: &Path, name: &str, files: &[(&str, &str)], dependencies: Value) -> String {
    let mut tar = tar::Builder::new(GzEncoder::new(Vec::new(), Compression::fast()));
    for (path, bytes) in files {
        let mut header = tar::Header::new_gnu();
        header.set_mode(0o644);
        header.set_size(bytes.len() as u64);
        header.set_cksum();
        tar.append_data(
            &mut header,
            format!("{name}-1.0.0/{path}"),
            bytes.as_bytes(),
        )
        .unwrap();
    }
    let bytes = tar.into_inner().unwrap().finish().unwrap();
    let checksum = hash(&bytes);
    write(
        home,
        &format!("registry/cache/{INDEX}/{name}-1.0.0.crate"),
        bytes,
    );
    let entry = json!({"name":name,"vers":"1.0.0","deps":dependencies,
        "cksum":checksum,"features":{},"yanked":false,"links":null});
    // Cargo's real sparse-cache reader consumes this format. The production
    // importer copies selected records opaquely and never implements a resolver.
    let mut cache = vec![3, 2, 0, 0, 0];
    cache.extend_from_slice(b"etag: \"offline-fixture\"\0");
    cache.extend_from_slice(b"1.0.0\0");
    cache.extend_from_slice(&serde_json::to_vec(&entry).unwrap());
    cache.push(0);
    write(
        home,
        &format!(
            "registry/index/{INDEX}/.cache/{}/{}/{name}",
            &name[..2],
            &name[2..4]
        ),
        cache,
    );
    checksum
}

fn fixture() -> Fixture {
    let owner = private_tempdir();
    let anchor = owner.path().join("approved source");
    let home = owner.path().join("approved cargo home");
    fs::create_dir(&anchor).unwrap();
    fs::create_dir(&home).unwrap();
    let cargo = fs::canonicalize(std::env::var_os("CARGO").expect("Cargo test runner")).unwrap();
    let rustc = cargo.parent().unwrap().join("rustc");
    assert!(
        rustc.is_file(),
        "fixture requires a complete installed toolchain"
    );
    write(
        &anchor,
        "Cargo.toml",
        "[workspace]\nmembers=['app','local_dep']\nresolver='2'\n",
    );
    write(
        &anchor,
        "app/Cargo.toml",
        "[package]\nname='vendor_app'\nversion='0.1.0'\nedition='2021'\nbuild='build.rs'\n[dependencies]\nlocal_dep={path='../local_dep'}\ncache_dep='=1.0.0'\n",
    );
    write(
        &anchor,
        "app/src/main.rs",
        "fn main() { println!(\"{}:{}\", cache_dep::answer()+local_dep::answer(), env!(\"BUILD_LABEL\")); }\n",
    );
    write(
        &anchor,
        "app/build.rs",
        "fn main() { let workspace=std::path::PathBuf::from(std::env::var_os(\"CARGO_MANIFEST_DIR\").unwrap()).parent().unwrap().to_owned(); assert!(!workspace.join(\"rabs-cargo-home\").exists(), \"transport cache changed the Cargo workspace\"); assert_eq!(std::fs::read_dir(&workspace).unwrap().count(),4, \"original workspace membership must be preserved\"); }\n",
    );
    write(
        &anchor,
        "local_dep/Cargo.toml",
        "[package]\nname='local_dep'\nversion='0.1.0'\nedition='2021'\n",
    );
    write(
        &anchor,
        "local_dep/src/lib.rs",
        "pub fn answer() -> u32 { 2 }\n",
    );
    write(
        &home,
        &format!("registry/index/{INDEX}/config.json"),
        br#"{"dl":"https://static.crates.io/crates","api":"https://crates.io"}"#,
    );
    let leaf = archive(
        &home,
        "cache_leaf",
        &[
            (
                "Cargo.toml",
                "[package]\nname='cache_leaf'\nversion='1.0.0'\nedition='2021'\n",
            ),
            ("src/lib.rs", "pub fn answer() -> u32 { 40 }\n"),
        ],
        json!([]),
    );
    let dependency = |kind| {
        json!({"name":"cache_leaf","req":"=1.0.0","features":[],
        "optional":false,"default_features":true,"target":null,"kind":kind,"registry":null})
    };
    let dep = archive(
        &home,
        "cache_dep",
        &[
            (
                "Cargo.toml",
                "[package]\nname='cache_dep'\nversion='1.0.0'\nedition='2021'\nbuild='build.rs'\n[dependencies]\ncache_leaf='=1.0.0'\n[build-dependencies]\ncache_leaf='=1.0.0'\n",
            ),
            (
                "build.rs",
                "fn main() { let n:u32=std::fs::read_to_string(\"payload.txt\").unwrap().trim().parse().unwrap(); assert_eq!(n,cache_leaf::answer()); let out=std::path::PathBuf::from(std::env::var_os(\"OUT_DIR\").unwrap()); std::fs::write(out.join(\"generated.rs\"),format!(\"pub const GENERATED:u32={n};\")).unwrap(); println!(\"cargo:rerun-if-changed=payload.txt\"); }\n",
            ),
            (
                "src/lib.rs",
                "include!(concat!(env!(\"OUT_DIR\"),\"/generated.rs\")); pub fn answer()->u32 { GENERATED+cache_leaf::answer()-40 }\n",
            ),
            ("payload.txt", "40\n"),
            (
                "nested-fixtures/Cargo.toml",
                "this is package data, not a manifest to resolve\n",
            ),
        ],
        json!([dependency("normal"), dependency("build")]),
    );
    write(
        &anchor,
        "Cargo.lock",
        format!(
            "version=4\n\n[[package]]\nname='local_dep'\nversion='0.1.0'\n\n[[package]]\nname='cache_dep'\nversion='1.0.0'\nsource='{REGISTRY}'\nchecksum='{dep}'\ndependencies=['cache_leaf']\n\n[[package]]\nname='cache_leaf'\nversion='1.0.0'\nsource='{REGISTRY}'\nchecksum='{leaf}'\n\n[[package]]\nname='vendor_app'\nversion='0.1.0'\ndependencies=['cache_dep','local_dep']\n"
        ),
    );
    // Any use of the original expanded source or user configuration would fail
    // the actual Cargo run. These files must not even enter the upload manifest.
    write(&home, "credentials.toml", PRIVATE_MARKER);
    write(
        &home,
        "config.toml",
        "[source.crates-io]\nreplace-with='must-not-be-read'\n",
    );
    write(&home, ".global-cache", PRIVATE_MARKER);
    write(
        &home,
        &format!("registry/src/{INDEX}/cache_leaf-1.0.0/Cargo.toml"),
        PRIVATE_MARKER,
    );
    write(
        &home,
        &format!("registry/src/{INDEX}/cache_leaf-1.0.0/src/lib.rs"),
        "compile_error!(\"mutable expanded source was used\");\n",
    );
    write(
        &home,
        &format!("registry/cache/{INDEX}/unrelated-9.9.9.crate"),
        PRIVATE_MARKER,
    );
    write(
        &home,
        &format!("registry/index/{INDEX}/.cache/un/re/unrelated"),
        PRIVATE_MARKER,
    );
    write(&home, "git/db/private", PRIVATE_MARKER);
    let specification = json!({"kind":"canonical-exec","request_id":93,
        "program":"/__rabs/toolchain/bin/cargo","args":["build","--frozen","--jobs=1","-p","vendor_app"],
        "toolchain_backing":cargo.parent().and_then(Path::parent).unwrap(),
        "timeout_ms":90000,"jobserver_grant":1,
        "cargo_source":{"manifest":"Cargo.toml","cargo_home_source":home},
        "command_context":{"version":"env-cwd-v1","cwd":"/__rabs/workspace",
            "env":{"CARGO_TARGET_DIR":"/__rabs/out/build","CARGO_INCREMENTAL":"0","BUILD_LABEL":LABEL}},
        "artifacts":{"unit":"build","files":["debug/vendor_app"],"tree":"tree-files-v1"}});
    Fixture {
        owner,
        anchor,
        cargo,
        rustc,
        specification,
    }
}

#[test]
fn cached_crates_io_preparation_and_real_build_use_only_locked_archives_in_an_isolated_home() {
    let fixture = fixture();
    let original_lock = fs::read(fixture.anchor.join("Cargo.lock")).unwrap();
    let (bundle, request) = fixture.prepared();
    assert_eq!(
        request["cargo_home"]["version"],
        ISOLATED_CARGO_HOME_SOURCE_VERSION
    );
    let approved = PathBuf::from(
        fixture.specification["cargo_source"]["cargo_home_source"]
            .as_str()
            .unwrap(),
    );
    assert!(!request.to_string().contains(approved.to_str().unwrap()));
    let manifest = rabsd::coord::source_delivery::request_manifest(&request)
        .unwrap()
        .unwrap();
    let cache_files: Vec<_> = manifest
        .files()
        .iter()
        .filter(|file| file.path.starts_with("rabs-cargo-home/"))
        .collect();
    assert_eq!(
        cache_files.len(),
        5,
        "two exact archives, two sparse records, one config"
    );
    for file in manifest.files() {
        assert!(
            !file.path.contains("registry/src/")
                && !file.path.contains("credentials")
                && !file.path.contains("unrelated")
                && !file.path.contains("git/db")
        );
        let bytes = fs::read(bundle.join("source").join(&file.path)).unwrap();
        assert!(
            !bytes
                .windows(PRIVATE_MARKER.len())
                .any(|window| window == PRIVATE_MARKER.as_bytes())
        );
    }
    assert_eq!(
        fs::read(fixture.anchor.join("Cargo.lock")).unwrap(),
        original_lock
    );
    fs::rename(
        &approved,
        fixture.owner.path().join("retired-original-cargo-home"),
    )
    .unwrap();
    fs::rename(
        &fixture.anchor,
        fixture.owner.path().join("retired-original-workspace"),
    )
    .unwrap();

    let projection = CargoHomeProjection::for_version(
        ISOLATED_CARGO_HOME_SOURCE_VERSION,
        "rabs-cargo-home",
        &manifest,
    )
    .unwrap();
    let mut received =
        SourceReceiver::create(&fixture.owner.path().join("received"), manifest.clone()).unwrap();
    for file in manifest.files() {
        let bytes = fs::read(bundle.join("source").join(&file.path)).unwrap();
        for (index, chunk) in bytes.chunks(MAX_SOURCE_CHUNK).enumerate() {
            received
                .write_chunk(
                    &file.path,
                    (index * MAX_SOURCE_CHUNK) as u64,
                    chunk,
                    Sha256::digest(chunk).into(),
                )
                .unwrap();
        }
    }
    received.seal().unwrap();
    let projected = projection
        .prepare(
            &received,
            &fixture.owner.path().join("runtime-cargo-home"),
            || false,
        )
        .unwrap();
    let workspace = projected
        .projected_workspace()
        .expect("automatic registry cache must be absent from the workspace view");
    assert!(!workspace.join("rabs-cargo-home").exists());
    assert!(!projected.root().join("credentials.toml").exists());
    assert!(!projected.root().join("config.toml").exists());
    assert!(!projected.root().join("registry/src").exists());
    let target = fixture.owner.path().join("local-target");
    let mut cargo = command(&fixture.cargo);
    cargo
        .current_dir(workspace)
        .args(["build", "--frozen", "--jobs=1", "-p", "vendor_app"])
        .arg("--target-dir")
        .arg(&target)
        .env("CARGO_HOME", projected.root())
        .env("RUSTC", &fixture.rustc)
        .env("CARGO_INCREMENTAL", "0")
        .env("BUILD_LABEL", LABEL);
    let (status, _, stderr) =
        Process::spawn(fixture.owner.path(), "cached-registry-build", &mut cargo)
            .wait(Duration::from_secs(90));
    assert!(status.success(), "{}", String::from_utf8_lossy(&stderr));
    let (status, stdout, stderr) = Process::spawn(
        fixture.owner.path(),
        "cached-registry-binary",
        &mut command(target.join("debug/vendor_app")),
    )
    .wait(Duration::from_secs(5));
    assert!(status.success(), "{}", String::from_utf8_lossy(&stderr));
    assert_eq!(stdout, format!("42:{LABEL}\n").as_bytes());
    assert_eq!(
        fs::read(workspace.join("Cargo.lock")).unwrap(),
        original_lock
    );
}

#[test]
fn cached_git_and_registry_sources_rebuild_offline_without_original_history_or_configuration() {
    use rabs_sandbox::cargo_home::{CAPTURED_GIT_CONFIG, ISOLATED_GIT_CARGO_HOME_SOURCE_VERSION};
    let fixture = fixture();
    let (git_fixture, revision) = Fixture::git_with_history(true);
    let git_lock: toml::Value =
        toml::from_str(&fs::read_to_string(git_fixture.anchor.join("Cargo.lock")).unwrap())
            .unwrap();
    let git_packages = git_lock["package"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|package| {
            package
                .get("source")
                .and_then(toml::Value::as_str)
                .is_some_and(|source| source.starts_with("git+"))
        })
        .cloned()
        .collect::<Vec<_>>();
    assert_eq!(
        git_packages.len(),
        2,
        "workspace-inherited Git packages remain distinct"
    );
    let source = git_packages[0]["source"].as_str().unwrap();
    let url = source
        .strip_prefix("git+")
        .unwrap()
        .split_once("?rev=")
        .unwrap()
        .0;
    let manifest_path = fixture.anchor.join("app/Cargo.toml");
    let original_manifest = fs::read_to_string(&manifest_path).unwrap();
    fs::write(
        manifest_path,
        format!("{original_manifest}git_dep={{git='{url}',rev='{revision}'}}\n"),
    )
    .unwrap();
    write(
        &fixture.anchor,
        "app/src/main.rs",
        "fn main() { println!(\"{}:{}:{}\", cache_dep::answer()+local_dep::answer(), git_dep::answer(), env!(\"BUILD_LABEL\")); }\n",
    );
    let mut lock: toml::Value =
        toml::from_str(&fs::read_to_string(fixture.anchor.join("Cargo.lock")).unwrap()).unwrap();
    let packages = lock["package"].as_array_mut().unwrap();
    packages
        .iter_mut()
        .find(|package| package["name"].as_str() == Some("vendor_app"))
        .unwrap()["dependencies"]
        .as_array_mut()
        .unwrap()
        .push("git_dep".into());
    packages.extend(git_packages);
    write(
        &fixture.anchor,
        "Cargo.lock",
        toml::to_string(&lock).unwrap(),
    );
    let original_lock = fs::read(fixture.anchor.join("Cargo.lock")).unwrap();
    let approved = PathBuf::from(
        fixture.specification["cargo_source"]["cargo_home_source"]
            .as_str()
            .unwrap(),
    );
    let original_db = fs::read_dir(
        git_fixture
            .owner
            .path()
            .join("retired-seed-cargo-home/git/db"),
    )
    .unwrap()
    .map(Result::unwrap)
    .next()
    .unwrap()
    .path();
    let namespace = original_db
        .file_name()
        .unwrap()
        .to_str()
        .unwrap()
        .to_owned();
    let database = approved.join("git/db").join(&namespace);
    fs::rename(&original_db, &database).unwrap();
    let mut parent = command("git");
    parent
        .arg("-C")
        .arg(git_fixture.owner.path().join("retired-original-git"))
        .args(["rev-parse", &format!("{revision}^")])
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", "/dev/null");
    let (status, stdout, stderr) = Process::spawn(fixture.owner.path(), "git-parent", &mut parent)
        .wait(Duration::from_secs(10));
    assert!(status.success(), "{}", String::from_utf8_lossy(&stderr));
    let parent = String::from_utf8(stdout).unwrap().trim().to_owned();
    assert_eq!(parent.len(), 40);
    // These bytes would poison native Git/Cargo if original configuration or
    // expanded checkouts were used before constructing the private object view.
    write(&database, "config", PRIVATE_MARKER);
    write(&database, "HEAD", PRIVATE_MARKER);
    write(&database, "refs/heads/private", PRIVATE_MARKER);
    let hook_marker = fixture.owner.path().join("original-hook-executed");
    write(
        &database,
        "hooks/post-checkout",
        format!("#!/bin/sh\nprintf executed > '{}'\n", hook_marker.display()),
    );
    fs::set_permissions(
        database.join("hooks/post-checkout"),
        fs::Permissions::from_mode(0o755),
    )
    .unwrap();
    write(
        &approved,
        &format!(
            "git/checkouts/{namespace}/{}/dep/src/lib.rs",
            &revision[..7]
        ),
        "compile_error!(\"mutable original Git checkout was used\");\n",
    );
    let (bundle, request) = fixture.prepared();
    assert_eq!(
        request["cargo_home"]["version"],
        ISOLATED_GIT_CARGO_HOME_SOURCE_VERSION
    );
    assert!(!request.to_string().contains(approved.to_str().unwrap()));
    assert!(!hook_marker.exists());
    let manifest = rabsd::coord::source_delivery::request_manifest(&request)
        .unwrap()
        .unwrap();
    let prefix = format!("rabs-cargo-home/git/db/{namespace}/");
    let git_files = manifest
        .files()
        .iter()
        .filter(|file| file.path.starts_with(&prefix))
        .collect::<Vec<_>>();
    assert_eq!(git_files.len(), 6);
    assert_eq!(
        manifest
            .files()
            .iter()
            .filter(|file| file.path.starts_with("rabs-cargo-home/registry/"))
            .count(),
        5
    );
    assert_eq!(
        fs::read(bundle.join("source").join(&prefix).join("config")).unwrap(),
        CAPTURED_GIT_CONFIG
    );
    for path in ["HEAD", "shallow", "refs/heads/rabs-captured"] {
        assert_eq!(
            fs::read(bundle.join("source").join(&prefix).join(path)).unwrap(),
            format!("{revision}\n").as_bytes()
        );
    }
    for file in manifest.files() {
        assert!(
            !file.path.contains("git/checkouts/")
                && !file.path.contains("/hooks/")
                && !file.path.contains("credentials")
        );
        let bytes = fs::read(bundle.join("source").join(&file.path)).unwrap();
        assert!(
            !bytes
                .windows(PRIVATE_MARKER.len())
                .any(|window| window == PRIVATE_MARKER.as_bytes())
        );
    }
    // An alternate database is not a permitted escape hatch for a missing
    // object, even when the explicitly selected commit is otherwise complete.
    write(&database, "objects/info/alternates", "/outside/objects\n");
    let (refused_bundle, status, _, stderr) = fixture.prepare("git-alternate-refused");
    assert!(!status.success());
    assert!(
        String::from_utf8_lossy(&stderr).contains("alternates"),
        "{}",
        String::from_utf8_lossy(&stderr)
    );
    assert!(!refused_bundle.exists());
    assert_eq!(
        fs::read(fixture.anchor.join("Cargo.lock")).unwrap(),
        original_lock
    );
    fs::rename(
        &approved,
        fixture.owner.path().join("retired-original-cargo-home"),
    )
    .unwrap();
    fs::rename(
        &fixture.anchor,
        fixture.owner.path().join("retired-original-workspace"),
    )
    .unwrap();

    let projection = CargoHomeProjection::for_version(
        ISOLATED_GIT_CARGO_HOME_SOURCE_VERSION,
        "rabs-cargo-home",
        &manifest,
    )
    .unwrap();
    let mut received =
        SourceReceiver::create(&fixture.owner.path().join("received-git"), manifest.clone())
            .unwrap();
    for file in manifest.files() {
        let bytes = fs::read(bundle.join("source").join(&file.path)).unwrap();
        for (index, chunk) in bytes.chunks(MAX_SOURCE_CHUNK).enumerate() {
            received
                .write_chunk(
                    &file.path,
                    (index * MAX_SOURCE_CHUNK) as u64,
                    chunk,
                    Sha256::digest(chunk).into(),
                )
                .unwrap();
        }
    }
    received.seal().unwrap();
    let projected = projection
        .prepare(
            &received,
            &fixture.owner.path().join("runtime-git-home"),
            || false,
        )
        .unwrap();
    let workspace = projected.projected_workspace().unwrap();
    assert!(!workspace.join("rabs-cargo-home").exists());
    assert!(!projected.root().join("git/checkouts").exists());
    let mut history = command("git");
    history
        .arg("--git-dir")
        .arg(projected.root().join("git/db").join(&namespace))
        .args(["cat-file", "-e", &parent])
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", "/dev/null");
    let (status, _, _) = Process::spawn(fixture.owner.path(), "excluded-git-parent", &mut history)
        .wait(Duration::from_secs(10));
    assert!(
        !status.success(),
        "unselected Git ancestors must not be delivered"
    );
    let target = fixture.owner.path().join("mixed-native-target");
    let mut cargo = command(&fixture.cargo);
    cargo
        .current_dir(workspace)
        .args(["build", "--frozen", "--jobs=1", "-p", "vendor_app"])
        .arg("--target-dir")
        .arg(&target)
        .env("CARGO_HOME", projected.root())
        .env("RUSTC", &fixture.rustc)
        .env("CARGO_INCREMENTAL", "0")
        .env("BUILD_LABEL", LABEL);
    let (status, _, stderr) = Process::spawn(
        fixture.owner.path(),
        "mixed-cached-source-build",
        &mut cargo,
    )
    .wait(Duration::from_secs(90));
    assert!(status.success(), "{}", String::from_utf8_lossy(&stderr));
    let (status, stdout, stderr) = Process::spawn(
        fixture.owner.path(),
        "mixed-cached-source-binary",
        &mut command(target.join("debug/vendor_app")),
    )
    .wait(Duration::from_secs(5));
    assert!(status.success(), "{}", String::from_utf8_lossy(&stderr));
    assert_eq!(stdout, format!("42:40:{LABEL}\n").as_bytes());
    assert_eq!(
        fs::read(workspace.join("Cargo.lock")).unwrap(),
        original_lock
    );
    assert!(!hook_marker.exists());
}

fn cached_git_fixture(selector: &str) -> (Fixture, String) {
    let (mut fixture, revision) = Fixture::git_with_reference(true, selector);
    // Retire the alternate vendor route entirely. The production preparer must
    // reconstruct this graph exclusively from the approved Git object store.
    fs::rename(
        fixture.anchor.join("vendor"),
        fixture.owner.path().join("retired-vendor"),
    )
    .unwrap();
    fs::rename(
        fixture.anchor.join(".cargo"),
        fixture.owner.path().join("retired-vendor-config"),
    )
    .unwrap();
    fixture.specification["cargo_source"] = json!({
        "manifest":"Cargo.toml",
        "cargo_home_source":fixture.owner.path().join("retired-seed-cargo-home")
    });
    (fixture, revision)
}

fn submodule_git(owner: &Path, repository: &Path, label: &str, args: &[&str]) -> String {
    let mut git = command("git");
    git.arg("-C")
        .arg(repository)
        .args([
            "-c",
            "core.hooksPath=/dev/null",
            "-c",
            "user.name=Fixture",
            "-c",
            "user.email=fixture@example.invalid",
        ])
        .args(args)
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", "/dev/null");
    let (status, stdout, stderr) =
        Process::spawn(owner, label, &mut git).wait(Duration::from_secs(15));
    assert!(
        status.success(),
        "{label}: {}",
        String::from_utf8_lossy(&stderr)
    );
    String::from_utf8(stdout).unwrap().trim().to_owned()
}

fn cached_git_submodule_fixture() -> (Fixture, BTreeMap<String, String>) {
    let owner = private_tempdir();
    let origins = owner.path().join("origins");
    let anchor = owner.path().join("approved-source");
    let home = owner.path().join("approved-cargo-home");
    let cargo = fs::canonicalize(std::env::var_os("CARGO").expect("Cargo test runner")).unwrap();
    let rustc = cargo.parent().unwrap().join("rustc");
    assert!(
        rustc.is_file(),
        "submodule fixture requires the installed toolchain"
    );
    let mut pins = BTreeMap::new();
    for (name, child, path) in [
        ("leaf", None, ""),
        ("middle", Some("leaf"), "nested"),
        ("outer", Some("middle"), "vendor"),
    ] {
        let repository = origins.join(name);
        fs::create_dir_all(&repository).unwrap();
        submodule_git(
            owner.path(),
            &repository,
            &format!("{name}-init"),
            &["init", "--initial-branch=main"],
        );
        if let Some(child) = child {
            let url = format!("file://{}", origins.join(child).display());
            submodule_git(
                owner.path(),
                &repository,
                &format!("{name}-submodule"),
                &[
                    "-c",
                    "protocol.file.allow=always",
                    "submodule",
                    "add",
                    "--",
                    &url,
                    path,
                ],
            );
            // Cargo resolves a relative child URL from the exact parent's
            // original URL. No rewritten private destination enters the blob.
            submodule_git(
                owner.path(),
                &repository,
                &format!("{name}-relative-url"),
                &[
                    "config",
                    "--file",
                    ".gitmodules",
                    &format!("submodule.{path}.url"),
                    &format!("../{child}"),
                ],
            );
        } else {
            write(&repository, "value.rs", "pub const VALUE:u32=40;\n");
            write(&repository, "README.md", "pinned child input\n");
            write(&repository, "helper.sh", "#!/bin/sh\nprintf pinned\n");
            fs::set_permissions(
                repository.join("helper.sh"),
                fs::Permissions::from_mode(0o755),
            )
            .unwrap();
        }
        if name == "outer" {
            write(
                &repository,
                "Cargo.toml",
                "[package]\nname='git_dep'\nversion='1.0.0'\nedition='2021'\nreadme='vendor/nested/README.md'\n",
            );
            write(
                &repository,
                "src/lib.rs",
                "include!(\"../vendor/nested/value.rs\"); pub fn answer()->u32 { VALUE }\n",
            );
        }
        submodule_git(
            owner.path(),
            &repository,
            &format!("{name}-add"),
            &["add", "."],
        );
        submodule_git(
            owner.path(),
            &repository,
            &format!("{name}-commit"),
            &["commit", "--no-gpg-sign", "-m", "pinned input"],
        );
        let revision = submodule_git(
            owner.path(),
            &repository,
            &format!("{name}-revision"),
            &["rev-parse", "HEAD"],
        );
        pins.insert(name.to_owned(), revision);
    }
    write(
        &anchor,
        "Cargo.toml",
        "[workspace]\nmembers=['app']\nresolver='2'\n",
    );
    write(
        &anchor,
        "app/Cargo.toml",
        format!(
            "[package]\nname='vendor_app'\nversion='0.1.0'\nedition='2021'\n[dependencies]\ngit_dep={{git='file://{}',rev='{}'}}\n",
            origins.join("outer").display(),
            pins["outer"],
        ),
    );
    write(
        &anchor,
        "app/src/main.rs",
        "fn main(){println!(\"{}:{}\",git_dep::answer()+2,env!(\"BUILD_LABEL\"));}\n",
    );
    let mut generate = command(&cargo);
    generate
        .current_dir(&anchor)
        .arg("generate-lockfile")
        .env("CARGO_HOME", &home)
        .env("RUSTC", &rustc)
        .env("CARGO_NET_GIT_FETCH_WITH_CLI", "true")
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", "/dev/null");
    let (status, _, stderr) =
        Process::spawn(owner.path(), "submodule-lock", &mut generate).wait(Duration::from_secs(30));
    assert!(status.success(), "{}", String::from_utf8_lossy(&stderr));
    assert_eq!(fs::read_dir(home.join("git/db")).unwrap().count(), 3);
    fs::rename(&origins, owner.path().join("retired-origins")).unwrap();
    let specification = json!({"kind":"canonical-exec","request_id":92,
        "program":"/__rabs/toolchain/bin/cargo","args":["build","--frozen","--jobs=1","-p","vendor_app"],
        "toolchain_backing":cargo.parent().and_then(Path::parent).unwrap(),
        "timeout_ms":90000,"jobserver_grant":1,
        "cargo_source":{"manifest":"Cargo.toml","cargo_home_source":home},
        "command_context":{"version":"env-cwd-v1","cwd":"/__rabs/workspace",
            "env":{"CARGO_TARGET_DIR":"/__rabs/out/build","CARGO_INCREMENTAL":"0","BUILD_LABEL":LABEL}},
        "artifacts":{"unit":"build","files":["debug/vendor_app"],"tree":"tree-files-v1"}});
    (
        Fixture {
            owner,
            anchor,
            cargo,
            rustc,
            specification,
        },
        pins,
    )
}

#[test]
fn cached_git_submodules_rebuild_frozen_from_pins_despite_newer_dirty_checkouts() {
    use rabs_sandbox::cargo_home::{CAPTURED_GIT_CONFIG, ISOLATED_GIT_CARGO_HOME_SOURCE_VERSION};
    let (fixture, pins) = cached_git_submodule_fixture();
    let home = fixture.owner.path().join("approved-cargo-home");
    let namespaces = fs::read_dir(home.join("git/db"))
        .unwrap()
        .map(|entry| entry.unwrap().file_name().into_string().unwrap())
        .collect::<Vec<_>>();
    let outer = namespaces
        .iter()
        .find(|name| name.starts_with("outer-"))
        .unwrap();
    let checkout = fs::read_dir(home.join("git/checkouts").join(outer))
        .unwrap()
        .next()
        .unwrap()
        .unwrap()
        .path();
    let nested = checkout.join("vendor/nested");
    write(&nested, "value.rs", "pub const VALUE:u32=99;\n");
    submodule_git(
        fixture.owner.path(),
        &nested,
        "newer-checkout-add",
        &["add", "value.rs"],
    );
    submodule_git(
        fixture.owner.path(),
        &nested,
        "newer-checkout-commit",
        &[
            "commit",
            "--no-gpg-sign",
            "-m",
            "newer checkout must not ship",
        ],
    );
    assert_ne!(
        submodule_git(
            fixture.owner.path(),
            &nested,
            "newer-checkout-head",
            &["rev-parse", "HEAD"]
        ),
        pins["leaf"]
    );
    write(
        &nested,
        "value.rs",
        "compile_error!(\"dirty submodule checkout was imported\");\n",
    );
    write(&nested, "unlisted-private.txt", PRIVATE_MARKER);
    write(&checkout, ".gitmodules", PRIVATE_MARKER);
    for namespace in &namespaces {
        write(
            &home.join("git/db").join(namespace),
            "config",
            PRIVATE_MARKER,
        );
    }
    let original_lock = fs::read(fixture.anchor.join("Cargo.lock")).unwrap();
    let (bundle, request) = fixture.prepared();
    let manifest = rabsd::coord::source_delivery::request_manifest(&request)
        .unwrap()
        .unwrap();
    assert_eq!(
        request["cargo_home"]["version"],
        ISOLATED_GIT_CARGO_HOME_SOURCE_VERSION
    );
    assert_eq!(
        manifest
            .files()
            .iter()
            .filter(|file| file.path.starts_with("rabs-cargo-home/git/db/"))
            .count(),
        18
    );
    assert!(
        !manifest
            .files()
            .iter()
            .any(|file| file.path.contains("git/checkouts"))
    );
    for namespace in &namespaces {
        let root = bundle.join("source/rabs-cargo-home/git/db").join(namespace);
        assert_eq!(fs::read(root.join("config")).unwrap(), CAPTURED_GIT_CONFIG);
        let name = namespace.split('-').next().unwrap();
        assert_eq!(
            fs::read_to_string(root.join("HEAD")).unwrap(),
            format!("{}\n", pins[name])
        );
    }
    let projection = CargoHomeProjection::for_version(
        ISOLATED_GIT_CARGO_HOME_SOURCE_VERSION,
        "rabs-cargo-home",
        &manifest,
    )
    .unwrap();
    let mut received = SourceReceiver::create(
        &fixture.owner.path().join("received-submodules"),
        manifest.clone(),
    )
    .unwrap();
    for file in manifest.files() {
        let bytes = fs::read(bundle.join("source").join(&file.path)).unwrap();
        for (index, chunk) in bytes.chunks(MAX_SOURCE_CHUNK).enumerate() {
            received
                .write_chunk(
                    &file.path,
                    (index * MAX_SOURCE_CHUNK) as u64,
                    chunk,
                    Sha256::digest(chunk).into(),
                )
                .unwrap();
        }
    }
    received.seal().unwrap();
    fs::rename(&home, fixture.owner.path().join("retired-approved-home")).unwrap();
    fs::rename(
        &fixture.anchor,
        fixture.owner.path().join("retired-workspace"),
    )
    .unwrap();
    let projected = projection
        .prepare(
            &received,
            &fixture.owner.path().join("runtime-submodule-home"),
            || false,
        )
        .unwrap();
    let workspace = projected.projected_workspace().unwrap();
    let target = fixture.owner.path().join("submodule-target");
    let mut cargo = command(&fixture.cargo);
    cargo
        .current_dir(workspace)
        .args(["build", "--frozen", "--jobs=1", "-p", "vendor_app"])
        .arg("--target-dir")
        .arg(&target)
        .env("CARGO_HOME", projected.root())
        .env("RUSTC", &fixture.rustc)
        .env("CARGO_INCREMENTAL", "0")
        .env("BUILD_LABEL", LABEL);
    let (status, _, stderr) =
        Process::spawn(fixture.owner.path(), "submodule-frozen-build", &mut cargo)
            .wait(Duration::from_secs(90));
    assert!(status.success(), "{}", String::from_utf8_lossy(&stderr));
    let (status, stdout, stderr) = Process::spawn(
        fixture.owner.path(),
        "submodule-binary",
        &mut command(target.join("debug/vendor_app")),
    )
    .wait(Duration::from_secs(5));
    assert!(status.success(), "{}", String::from_utf8_lossy(&stderr));
    assert_eq!(stdout, format!("42:{LABEL}\n").as_bytes());
    assert_eq!(
        fs::read(workspace.join("Cargo.lock")).unwrap(),
        original_lock
    );
    let checkout = fs::read_dir(projected.root().join("git/checkouts").join(outer))
        .unwrap()
        .next()
        .unwrap()
        .unwrap()
        .path();
    assert_eq!(
        fs::read_to_string(checkout.join("vendor/nested/value.rs")).unwrap(),
        "pub const VALUE:u32=40;\n"
    );
    assert!(
        fs::metadata(checkout.join("vendor/nested/helper.sh"))
            .unwrap()
            .permissions()
            .mode()
            & 0o111
            != 0
    );
    assert!(!checkout.join("vendor/nested/unlisted-private.txt").exists());
}

#[test]
fn cached_git_submodule_missing_objects_refuse_without_using_original_checkouts() {
    let (fixture, _) = cached_git_submodule_fixture();
    let home = fixture.owner.path().join("approved-cargo-home");
    let database = fs::read_dir(home.join("git/db"))
        .unwrap()
        .map(Result::unwrap)
        .find(|entry| entry.file_name().to_str().unwrap().starts_with("leaf-"))
        .unwrap()
        .path();
    fs::rename(
        &database,
        fixture.owner.path().join("retired-child-database"),
    )
    .unwrap();
    let lock = fs::read(fixture.anchor.join("Cargo.lock")).unwrap();
    let (bundle, status, _, stderr) = fixture.prepare("missing-submodule");
    assert!(!status.success());
    assert!(
        String::from_utf8_lossy(&stderr).contains("pinned submodule"),
        "{}",
        String::from_utf8_lossy(&stderr)
    );
    assert!(!bundle.join("request.json").exists());
    assert_eq!(fs::read(fixture.anchor.join("Cargo.lock")).unwrap(), lock);
}

#[test]
fn cached_git_submodule_pin_changes_replace_the_captured_child_object_identity() {
    let (fixture, pins) = cached_git_submodule_fixture();
    let (first_bundle, first_request) = fixture.prepared();
    let first_manifest = rabsd::coord::source_delivery::request_manifest(&first_request)
        .unwrap()
        .unwrap();
    let home = fixture.owner.path().join("approved-cargo-home");
    let leaf_namespace = fs::read_dir(home.join("git/db"))
        .unwrap()
        .map(Result::unwrap)
        .find(|entry| entry.file_name().to_str().unwrap().starts_with("leaf-"))
        .unwrap()
        .file_name();
    let origins = fixture.owner.path().join("origins");
    fs::rename(fixture.owner.path().join("retired-origins"), &origins).unwrap();
    let leaf = origins.join("leaf");
    write(&leaf, "value.rs", "pub const VALUE:u32=41;\n");
    submodule_git(
        fixture.owner.path(),
        &leaf,
        "repin-leaf-add",
        &["add", "value.rs"],
    );
    submodule_git(
        fixture.owner.path(),
        &leaf,
        "repin-leaf-commit",
        &["commit", "--no-gpg-sign", "-m", "changed pinned input"],
    );
    let new_leaf = submodule_git(
        fixture.owner.path(),
        &leaf,
        "repin-leaf-head",
        &["rev-parse", "HEAD"],
    );
    let mut child = new_leaf.clone();
    for (name, path) in [("middle", "nested"), ("outer", "vendor")] {
        let repository = origins.join(name);
        submodule_git(
            fixture.owner.path(),
            &repository,
            &format!("repin-{name}-index"),
            &["update-index", "--cacheinfo", "160000", &child, path],
        );
        submodule_git(
            fixture.owner.path(),
            &repository,
            &format!("repin-{name}-commit"),
            &["commit", "--no-gpg-sign", "-m", "changed child pin"],
        );
        child = submodule_git(
            fixture.owner.path(),
            &repository,
            &format!("repin-{name}-head"),
            &["rev-parse", "HEAD"],
        );
    }
    let manifest_path = fixture.anchor.join("app/Cargo.toml");
    let manifest = fs::read_to_string(&manifest_path).unwrap();
    fs::write(manifest_path, manifest.replace(&pins["outer"], &child)).unwrap();
    let mut generate = command(&fixture.cargo);
    generate
        .current_dir(&fixture.anchor)
        .arg("generate-lockfile")
        .env("CARGO_HOME", &home)
        .env("RUSTC", &fixture.rustc)
        .env("CARGO_NET_GIT_FETCH_WITH_CLI", "true")
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", "/dev/null");
    let (status, _, stderr) = Process::spawn(fixture.owner.path(), "repin-lock", &mut generate)
        .wait(Duration::from_secs(30));
    assert!(status.success(), "{}", String::from_utf8_lossy(&stderr));
    fs::rename(&origins, fixture.owner.path().join("retired-origins")).unwrap();
    let (second_bundle, status, _, stderr) = fixture.prepare("repinned-bundle");
    assert!(status.success(), "{}", String::from_utf8_lossy(&stderr));
    let request: Value =
        serde_json::from_slice(&fs::read(second_bundle.join("request.json")).unwrap()).unwrap();
    let second_manifest = rabsd::coord::source_delivery::request_manifest(&request)
        .unwrap()
        .unwrap();
    assert_ne!(first_manifest.digest(), second_manifest.digest());
    let child_root = Path::new("source/rabs-cargo-home/git/db").join(&leaf_namespace);
    assert_eq!(
        fs::read_to_string(first_bundle.join(&child_root).join("HEAD")).unwrap(),
        format!("{}\n", pins["leaf"])
    );
    assert_eq!(
        fs::read_to_string(second_bundle.join(&child_root).join("HEAD")).unwrap(),
        format!("{new_leaf}\n")
    );
    let packs = |bundle: &Path| {
        fs::read_dir(bundle.join(&child_root).join("objects/pack"))
            .unwrap()
            .map(|entry| entry.unwrap().file_name())
            .collect::<std::collections::BTreeSet<_>>()
    };
    assert_ne!(
        packs(&first_bundle),
        packs(&second_bundle),
        "the child bytes, not just Cargo.lock, must change the delivered identity"
    );
}

#[test]
fn cached_git_reference_selectors_build_locked_commits_after_origin_and_refs_move() {
    use rabs_sandbox::cargo_home::ISOLATED_GIT_CARGO_HOME_SOURCE_VERSION;
    for selector in ["default", "branch", "tag", "short-rev"] {
        let (fixture, revision) = cached_git_fixture(selector);
        let home = fixture.owner.path().join("retired-seed-cargo-home");
        let database = fs::read_dir(home.join("git/db"))
            .unwrap()
            .map(Result::unwrap)
            .next()
            .unwrap()
            .path();
        let namespace = database.file_name().unwrap().to_owned();
        let mut latest = command("git");
        latest
            .arg("-C")
            .arg(fixture.owner.path().join("retired-original-git"))
            .args(["rev-parse", "HEAD"])
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env("GIT_CONFIG_GLOBAL", "/dev/null");
        let (status, stdout, stderr) =
            Process::spawn(fixture.owner.path(), "advanced-git-tip", &mut latest)
                .wait(Duration::from_secs(10));
        assert!(status.success(), "{}", String::from_utf8_lossy(&stderr));
        let advanced = String::from_utf8(stdout).unwrap().trim().to_owned();
        assert_ne!(advanced, revision, "{selector} must have a moving-ref trap");
        let original_lock = fs::read(fixture.anchor.join("Cargo.lock")).unwrap();
        let original_manifest = fs::read(fixture.anchor.join("app/Cargo.toml")).unwrap();
        // These original files are never part of the approved object closure.
        write(&home, "config.toml", PRIVATE_MARKER);
        write(&database, "config", PRIVATE_MARKER);
        write(&database, "HEAD", PRIVATE_MARKER);
        write(&database, "refs/heads/private", PRIVATE_MARKER);
        let (bundle, request) = fixture.prepared();
        assert_eq!(
            request["cargo_home"]["version"],
            ISOLATED_GIT_CARGO_HOME_SOURCE_VERSION
        );
        let manifest = rabsd::coord::source_delivery::request_manifest(&request)
            .unwrap()
            .unwrap();
        let projection = CargoHomeProjection::for_version(
            ISOLATED_GIT_CARGO_HOME_SOURCE_VERSION,
            "rabs-cargo-home",
            &manifest,
        )
        .unwrap();
        let mut received = SourceReceiver::create(
            &fixture.owner.path().join("received-locked-git"),
            manifest.clone(),
        )
        .unwrap();
        for file in manifest.files() {
            let bytes = fs::read(bundle.join("source").join(&file.path)).unwrap();
            for (index, chunk) in bytes.chunks(MAX_SOURCE_CHUNK).enumerate() {
                received
                    .write_chunk(
                        &file.path,
                        (index * MAX_SOURCE_CHUNK) as u64,
                        chunk,
                        Sha256::digest(chunk).into(),
                    )
                    .unwrap();
            }
        }
        received.seal().unwrap();
        fs::rename(&home, fixture.owner.path().join("retired-approved-home")).unwrap();
        fs::rename(
            &fixture.anchor,
            fixture.owner.path().join("retired-workspace"),
        )
        .unwrap();
        let projected = projection
            .prepare(
                &received,
                &fixture.owner.path().join("runtime-locked-git-home"),
                || false,
            )
            .unwrap();
        let workspace = projected.projected_workspace().unwrap();
        assert!(!projected.root().join("git/checkouts").exists());
        for (commit, expected) in [(&revision, true), (&advanced, false)] {
            let mut check = command("git");
            check
                .arg("--git-dir")
                .arg(projected.root().join("git/db").join(&namespace))
                .args(["cat-file", "-e", commit])
                .env("GIT_CONFIG_NOSYSTEM", "1")
                .env("GIT_CONFIG_GLOBAL", "/dev/null");
            let (status, _, _) =
                Process::spawn(fixture.owner.path(), "selected-git-object", &mut check)
                    .wait(Duration::from_secs(10));
            assert_eq!(status.success(), expected, "{selector}: {commit}");
        }
        let target = fixture.owner.path().join("locked-git-target");
        let mut cargo = command(&fixture.cargo);
        cargo
            .current_dir(workspace)
            .args(["build", "--frozen", "--jobs=1", "-p", "vendor_app"])
            .arg("--target-dir")
            .arg(&target)
            .env("CARGO_HOME", projected.root())
            .env("RUSTC", &fixture.rustc)
            .env("CARGO_INCREMENTAL", "0")
            .env("BUILD_LABEL", LABEL);
        let (status, _, stderr) =
            Process::spawn(fixture.owner.path(), "locked-git-build", &mut cargo)
                .wait(Duration::from_secs(90));
        assert!(
            status.success(),
            "{selector}: {}",
            String::from_utf8_lossy(&stderr)
        );
        let (status, stdout, stderr) = Process::spawn(
            fixture.owner.path(),
            "locked-git-binary",
            &mut command(target.join("debug/vendor_app")),
        )
        .wait(Duration::from_secs(5));
        assert!(status.success(), "{}", String::from_utf8_lossy(&stderr));
        assert_eq!(stdout, format!("42:{LABEL}\n").as_bytes(), "{selector}");
        assert_eq!(
            fs::read(workspace.join("Cargo.lock")).unwrap(),
            original_lock
        );
        assert_eq!(
            fs::read(workspace.join("app/Cargo.toml")).unwrap(),
            original_manifest
        );
    }
}

#[test]
fn cached_git_selector_drift_and_missing_locked_commit_refuse_without_lock_mutation() {
    let (fixture, revision) = cached_git_fixture("branch");
    let lock_path = fixture.anchor.join("Cargo.lock");
    let manifest_path = fixture.anchor.join("app/Cargo.toml");
    let lock = fs::read_to_string(&lock_path).unwrap();
    let manifest = fs::read_to_string(&manifest_path).unwrap();
    for case in [
        "missing-commit",
        "short-lock",
        "selector-drift",
        "ambiguous-selector",
    ] {
        let selected_lock = match case {
            "missing-commit" => lock.replace(&revision, &"f".repeat(40)),
            "short-lock" => lock.replace(&revision, &revision[..7]),
            _ => lock.clone(),
        };
        let selected_manifest = match case {
            "selector-drift" => manifest.replace("branch='main'", "branch='unlocked-branch'"),
            "ambiguous-selector" => {
                manifest.replace("branch='main'", "branch='main',tag='release'")
            }
            _ => manifest.clone(),
        };
        fs::write(&lock_path, &selected_lock).unwrap();
        fs::write(&manifest_path, &selected_manifest).unwrap();
        let (bundle, status, stdout, stderr) = fixture.prepare(case);
        assert!(!status.success(), "{case} must refuse");
        assert!(stdout.is_empty(), "{case} must not publish a source bundle");
        assert!(!bundle.exists(), "{case} published an input bundle");
        let failure: Value = serde_json::from_slice(&stderr).unwrap();
        assert_eq!(failure["kind"], "worker-prepare-failed", "{case}");
        assert_eq!(
            fs::read_to_string(&lock_path).unwrap(),
            selected_lock,
            "{case}"
        );
        assert_eq!(
            fs::read_to_string(&manifest_path).unwrap(),
            selected_manifest,
            "{case}"
        );
    }
}

#[test]
fn corrupt_missing_or_unapproved_registry_inputs_refuse_before_bundle_publication() {
    for case in 0..7 {
        let mut fixture = fixture();
        let home = PathBuf::from(
            fixture.specification["cargo_source"]["cargo_home_source"]
                .as_str()
                .unwrap(),
        );
        match case {
            0 => write(
                &home,
                &format!("registry/cache/{INDEX}/cache_leaf-1.0.0.crate"),
                "wrong checksum",
            ),
            1 => {
                let path = home.join(format!("registry/cache/{INDEX}/cache_leaf-1.0.0.crate"));
                fs::rename(&path, home.join("retired-archive")).unwrap();
            }
            2 => {
                let path = home.join(format!("registry/index/{INDEX}/.cache/ca/ch/cache_leaf"));
                fs::rename(&path, home.join("retired-index")).unwrap();
            }
            3 => fs::create_dir(fixture.anchor.join("rabs-cargo-home")).unwrap(),
            4 => {
                let alias = fixture.owner.path().join("aliased-cargo-home");
                std::os::unix::fs::symlink(&home, &alias).unwrap();
                fixture.specification["cargo_source"]["cargo_home_source"] = json!(alias);
            }
            5 => fixture.specification["cargo_source"]["vendor"] = json!("vendor"),
            _ => write(
                &fixture.anchor,
                ".cargo/config.toml",
                "[source.crates-io]\nreplace-with='unapproved'\n",
            ),
        }
        let lock = fs::read(fixture.anchor.join("Cargo.lock")).unwrap();
        let (bundle, status, stdout, stderr) = fixture.prepare("refused-cache");
        assert!(!status.success(), "case {case}");
        assert!(
            stdout.is_empty(),
            "case {case}: {}",
            String::from_utf8_lossy(&stdout)
        );
        assert!(!bundle.exists(), "case {case} published an input bundle");
        let failure: Value = serde_json::from_slice(&stderr).unwrap();
        assert_eq!(failure["kind"], "worker-prepare-failed");
        assert_eq!(fs::read(fixture.anchor.join("Cargo.lock")).unwrap(), lock);
    }
}

#[test]
#[ignore = "requires canonical-capable Linux, OpenSSL and matching RABS_TEST_WORKER_BIN; run explicitly"]
fn cached_crates_io_builds_over_native_tls_without_user_cache_and_replays_outputs_offline() {
    run_native_tls_build(fixture(), false);
}

#[test]
#[ignore = "requires canonical-capable Linux, OpenSSL and matching RABS_TEST_WORKER_BIN; run explicitly"]
fn cargo_selected_workspace_outputs_survive_native_tls_and_offline_recovery() {
    let mut fixture = fixture();
    fixture.specification["args"] = json!([
        "build",
        "--workspace",
        "--frozen",
        "--jobs=1",
        "--message-format=json",
        "--target-dir",
        "/__rabs/out/cargo"
    ]);
    fixture.specification["command_context"]["env"]["CARGO_TARGET_DIR"] =
        json!("/__rabs/out/cargo");
    fixture.specification["artifacts"] = json!({
        "unit":"cargo", "tree":"tree-files-v1", "files":[], "cargo":"cargo-json-v1"
    });
    // The shared fixture retires the original checkout/cache, executes the
    // installed binary, and replays the same verified delivery without a worker.
    run_native_tls_build(fixture, false);
}
