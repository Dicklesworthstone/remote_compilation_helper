//! Filesystem/manifest regressions. These do not run Cargo or assert package
//! authenticity: generated checksum metadata supplies consistency fixtures.
use super::*;
use super::super::{CargoSource, validate_capture, validate_metadata};
use rabs_sandbox::snapshot_capture::capture_sealed_source;
use serde_json::json;
use std::fs;

const CONFIG: &str = "[source.crates-io]\nreplace-with = 'vendored-sources'\n[source.vendored-sources]\ndirectory = '../vendor'\n";
const DEP: &str = "vendor/arbitrary-folder";

fn write(root: &Path, path: &str, bytes: impl AsRef<[u8]>) {
    let path = root.join(path);
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(path, bytes).unwrap();
}

fn package(root: &Path, directory: &str, name: &str, version: &str) -> String {
    let contents = BTreeMap::from([
        ("Cargo.toml", format!("[package]\nname='{name}'\nversion='{version}'\nedition='2021'\n")),
        ("src/lib.rs", "pub fn answer() -> u32 { 42 }\n".to_owned()),
        ("data.txt", "include inputs are checksummed too\n".to_owned()),
    ]);
    let mut hashes = serde_json::Map::new();
    for (path, text) in contents {
        write(root, &format!("{directory}/{path}"), text.as_bytes());
        hashes.insert(path.to_owned(), json!(hash(text.as_bytes())));
    }
    let package_hash = hash(format!("fixture archive {name}@{version}").as_bytes());
    write(root, &format!("{directory}/{CHECKSUM_FILE}"),
        serde_json::to_vec(&json!({"package":package_hash, "files":hashes})).unwrap());
    package_hash
}

fn fixture(root: &Path) -> String {
    let checksum = package(root, DEP, "fixture_dep", "1.0.0");
    write(root, "app/.cargo/config.toml", CONFIG);
    write(root, "app/Cargo.toml", "[package]\nname='app'\nversion='0.1.0'\nedition='2021'\n[workspace]\n[dependencies]\nfixture_dep='=1.0.0'\n");
    write(root, "app/src/main.rs", "fn main() { println!(\"{}\", fixture_dep::answer()); }\n");
    write(root, "app/Cargo.lock", format!("version=4\n[[package]]\nname='app'\nversion='0.1.0'\ndependencies=['fixture_dep']\n[[package]]\nname='fixture_dep'\nversion='1.0.0'\nsource='{CRATES_IO}'\nchecksum='{checksum}'\n"));
    checksum
}

fn image(root: &Path) -> SealedSourceSnapshot {
    capture_sealed_source(&[("workspace".into(), root.to_path_buf())], false, 2, 2_000_000).unwrap()
}

fn verify(root: &Path) -> io::Result<VendoredSources> {
    VendoredSources::verify(&image(root), "app/Cargo.toml", "vendor")
}

fn metadata(root: &Path) -> Value {
    json!({"version":1,"workspace_root":root.join("app"),
        "workspace_members":["app"],"workspace_default_members":["app"],
        "packages":[
            {"id":"app","source":null,"name":"app","version":"0.1.0",
                "manifest_path":root.join("app/Cargo.toml"),"targets":[{"src_path":root.join("app/src/main.rs")}]},
            {"id":"dep","source":CRATES_IO,"name":"fixture_dep","version":"1.0.0",
                "manifest_path":root.join(DEP).join("Cargo.toml"),"targets":[{"src_path":root.join(DEP).join("src/lib.rs")}]}],
        "resolve":{"nodes":[{"id":"app","dependencies":["dep"]},{"id":"dep","dependencies":[]}]}})
}

#[test]
fn vendor_selection_is_explicit_bounded_and_does_not_change_legacy_mode() {
    assert!(CargoSource::parse(&json!({"manifest":"app/Cargo.toml"})).unwrap().vendor.is_none());
    assert_eq!(CargoSource::parse(&json!({"manifest":"app/Cargo.toml","vendor":"vendor"})).unwrap().vendor.as_deref(), Some("vendor"));
    for value in [Value::Null, json!(true), json!([]), json!(""), json!("/vendor"),
        json!("../vendor"), json!("x//y"), json!("vendor/"), json!("x\\y"), json!("x\0y")] {
        assert!(CargoSource::parse(&json!({"manifest":"app/Cargo.toml","vendor":value})).is_err());
    }
    assert!(CargoSource::parse(&json!({"manifest":"app/Cargo.toml","vendor":"vendor","fetch":true})).is_err());
    let root = tempfile::tempdir().unwrap(); fixture(root.path());
    assert!(validate_capture(&image(root.path()), "app/Cargo.toml", None).is_err());
}

#[test]
fn coherent_vendor_tree_binds_lock_and_metadata_without_rereading_checkout() {
    let root = tempfile::tempdir().unwrap(); fixture(root.path());
    let retained = image(root.path());
    let vendor = VendoredSources::verify(&retained, "app/Cargo.toml", "vendor").unwrap();
    let files = validate_capture(&retained, "app/Cargo.toml", Some(&vendor)).unwrap();
    assert_eq!(files.len(), 8);
    assert!(files.contains(&format!("{DEP}/data.txt")));
    let locked = vendor.bind_lock(&retained, Path::new("app/Cargo.lock")).unwrap();
    assert_eq!(locked, BTreeSet::from([("fixture_dep".to_owned(), "1.0.0".to_owned())]));
    write(root.path(), &format!("{DEP}/src/lib.rs"), "changed after capture");
    let planning = Path::new("/private/planning");
    validate_metadata(&retained, planning, "app/Cargo.toml", &metadata(planning), Some(&vendor)).unwrap();
    assert!(verify(root.path()).is_err());
    assert_eq!(retained.file_bytes("workspace", "app/.cargo/config.toml").unwrap(), CONFIG.as_bytes());
}

#[test]
fn vendor_config_refuses_ambient_layers_aliases_and_escaping_directories() {
    for bad in [
        CONFIG.replace("../vendor", "/vendor"),
        CONFIG.replace("../vendor", "../../vendor"),
        CONFIG.replace("../vendor", "../other"),
        CONFIG.replace("directory", "local-registry"),
        CONFIG.replace("replace-with = 'vendored-sources'", "replace-with = 'crates-io'"),
        format!("{CONFIG}\n[env]\nSECRET='private-marker'\n"),
        format!("{CONFIG}\n[build]\nrustc-wrapper='malicious-helper'\n"),
        format!("{CONFIG}\n[source.other]\ngit='file:///outside'\n"),
    ] {
        let root = tempfile::tempdir().unwrap(); fixture(root.path());
        write(root.path(), "app/.cargo/config.toml", bad);
        let error = verify(root.path()).unwrap_err();
        assert!(!error.to_string().contains("private-marker"));
    }
    let root = tempfile::tempdir().unwrap(); fixture(root.path());
    write(root.path(), "app/.cargo/config", CONFIG);
    assert!(verify(root.path()).is_err(), "legacy config must not shadow validated TOML");
    let root = tempfile::tempdir().unwrap(); fixture(root.path());
    fs::rename(root.path().join("app/.cargo"), root.path().join("unrelated")).unwrap();
    write(root.path(), "other/.cargo/config.toml", CONFIG);
    assert!(verify(root.path()).is_err(), "unrelated config cannot authorize a source");
}

#[test]
fn checksums_require_every_file_exactly_once_with_no_missing_extra_or_changed_member() {
    for case in 0..8 {
        let root = tempfile::tempdir().unwrap(); fixture(root.path());
        let checksum = root.path().join(DEP).join(CHECKSUM_FILE);
        let mut value: Value = serde_json::from_slice(&fs::read(&checksum).unwrap()).unwrap();
        match case {
            0 => write(root.path(), &format!("{DEP}/src/lib.rs"), "same path different bytes"),
            1 => write(root.path(), &format!("{DEP}/unlisted.rs"), "extra"),
            2 => { fs::rename(root.path().join(DEP).join("data.txt"), root.path().join("saved-data")).unwrap(); }
            3 => { value["files"]["data.txt"] = json!("00".repeat(32)); fs::write(&checksum, value.to_string()).unwrap(); }
            4 => { value["package"] = Value::Null; fs::write(&checksum, value.to_string()).unwrap(); }
            5 => { value["files"]["../outside"] = value["files"]["data.txt"].clone(); value["files"].as_object_mut().unwrap().remove("data.txt"); fs::write(&checksum, value.to_string()).unwrap(); }
            6 => { value["files"][CHECKSUM_FILE] = value["files"]["data.txt"].clone(); value["files"].as_object_mut().unwrap().remove("data.txt"); fs::write(&checksum, value.to_string()).unwrap(); }
            _ => { let text = value.to_string().replacen("\"files\":{", "\"files\":{\"data.txt\":\"00\",", 1); fs::write(&checksum, text).unwrap(); }
        }
        assert!(verify(root.path()).is_err(), "case {case}");
    }
}

#[test]
fn checksum_consistency_is_bound_to_the_actual_workspace_lock_not_a_neighbor() {
    for case in 0..5 {
        let root = tempfile::tempdir().unwrap(); fixture(root.path());
        let path = root.path().join("app/Cargo.lock");
        let before = fs::read_to_string(&path).unwrap();
        let changed = match case {
            0 => before.replace("checksum='", "checksum='00"),
            1 => before.replace("version='1.0.0'", "version='2.0.0'"),
            2 => before.replace(CRATES_IO, "git+file:///outside#revision"),
            3 => before.replace(CRATES_IO, "registry+https://example.com/index"),
            _ => before.lines().filter(|line| !line.starts_with("checksum=")).collect::<Vec<_>>().join("\n"),
        };
        write(root.path(), "other/Cargo.lock", before);
        fs::write(&path, changed).unwrap();
        let retained = image(root.path());
        let vendor = VendoredSources::verify(&retained, "app/Cargo.toml", "vendor").unwrap();
        assert!(vendor.bind_lock(&retained, Path::new("app/Cargo.lock")).is_err(), "case {case}");
    }
}

#[test]
fn resolved_registry_packages_cannot_change_source_name_version_root_or_lock_membership() {
    let root = tempfile::tempdir().unwrap(); fixture(root.path());
    package(root.path(), "vendor/another-version", "fixture_dep", "2.0.0");
    let retained = image(root.path());
    let vendor = VendoredSources::verify(&retained, "app/Cargo.toml", "vendor").unwrap();
    let planning = Path::new("/private/planning");
    let good = metadata(planning);
    for case in 0..7 {
        let mut changed = good.clone();
        match case {
            0 => changed["packages"][1]["source"] = Value::Null,
            1 => changed["packages"][1]["name"] = json!("foreign"),
            2 => changed["packages"][1]["manifest_path"] = json!(planning.join("app/Cargo.toml")),
            3 => changed["packages"][1]["targets"][0]["src_path"] = json!(planning.join("app/src/main.rs")),
            4 => changed["resolve"]["nodes"][0]["dependencies"] = json!(["missing"]),
            5 => changed["packages"][1]["source"] = json!("git+file:///outside"),
            _ => {
                changed["packages"][1]["version"] = json!("2.0.0");
                changed["packages"][1]["manifest_path"] = json!(planning.join("vendor/another-version/Cargo.toml"));
                changed["packages"][1]["targets"][0]["src_path"] = json!(planning.join("vendor/another-version/src/lib.rs"));
            }
        }
        assert!(validate_metadata(&retained, planning, "app/Cargo.toml", &changed, Some(&vendor)).is_err(), "case {case}");
    }
}

#[test]
fn symlink_and_duplicate_package_identity_refuse_the_entire_vendor_source() {
    let root = tempfile::tempdir().unwrap(); fixture(root.path());
    package(root.path(), "vendor/duplicate", "fixture_dep", "1.0.0");
    assert!(verify(root.path()).is_err());
    let root = tempfile::tempdir().unwrap(); fixture(root.path());
    std::os::unix::fs::symlink("src/lib.rs", root.path().join(DEP).join("alias")).unwrap();
    assert!(verify(root.path()).is_err());
    let root = tempfile::tempdir().unwrap(); fixture(root.path());
    assert!(VendoredSources::verify(&image(root.path()), &format!("{DEP}/Cargo.toml"), "vendor").is_err());
}
