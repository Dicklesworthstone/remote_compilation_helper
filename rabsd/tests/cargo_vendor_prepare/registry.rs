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
    let owner = tempfile::tempdir().unwrap();
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
