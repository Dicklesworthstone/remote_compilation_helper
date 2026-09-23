//! Filesystem/manifest regressions. These do not run Cargo or assert package
//! authenticity: generated checksum metadata supplies consistency fixtures.
use super::super::{CargoSource, validate_capture, validate_metadata};
use super::*;
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
        (
            "Cargo.toml",
            format!("[package]\nname='{name}'\nversion='{version}'\nedition='2021'\n"),
        ),
        ("src/lib.rs", "pub fn answer() -> u32 { 42 }\n".to_owned()),
        (
            "data.txt",
            "include inputs are checksummed too\n".to_owned(),
        ),
    ]);
    let mut hashes = serde_json::Map::new();
    for (path, text) in contents {
        write(root, &format!("{directory}/{path}"), text.as_bytes());
        hashes.insert(path.to_owned(), json!(hash(text.as_bytes())));
    }
    let package_hash = hash(format!("fixture archive {name}@{version}").as_bytes());
    write(
        root,
        &format!("{directory}/{CHECKSUM_FILE}"),
        serde_json::to_vec(&json!({"package":package_hash, "files":hashes})).unwrap(),
    );
    package_hash
}

fn fixture(root: &Path) -> String {
    let checksum = package(root, DEP, "fixture_dep", "1.0.0");
    write(root, "app/.cargo/config.toml", CONFIG);
    write(
        root,
        "app/Cargo.toml",
        "[package]\nname='app'\nversion='0.1.0'\nedition='2021'\n[workspace]\n[dependencies]\nfixture_dep='=1.0.0'\n",
    );
    write(
        root,
        "app/src/main.rs",
        "fn main() { println!(\"{}\", fixture_dep::answer()); }\n",
    );
    write(
        root,
        "app/Cargo.lock",
        format!(
            "version=4\n[[package]]\nname='app'\nversion='0.1.0'\ndependencies=['fixture_dep']\n[[package]]\nname='fixture_dep'\nversion='1.0.0'\nsource='{CRATES_IO}'\nchecksum='{checksum}'\n"
        ),
    );
    checksum
}

fn image(root: &Path) -> SealedSourceSnapshot {
    capture_sealed_source(
        &[("workspace".into(), root.to_path_buf())],
        false,
        2,
        2_000_000,
    )
    .unwrap()
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
    assert!(
        CargoSource::parse(&json!({"manifest":"app/Cargo.toml"}))
            .unwrap()
            .vendor
            .is_none()
    );
    assert_eq!(
        CargoSource::parse(&json!({"manifest":"app/Cargo.toml","vendor":"vendor"}))
            .unwrap()
            .vendor
            .as_deref(),
        Some("vendor")
    );
    for value in [
        Value::Null,
        json!(true),
        json!([]),
        json!(""),
        json!("/vendor"),
        json!("../vendor"),
        json!("x//y"),
        json!("vendor/"),
        json!("x\\y"),
        json!("x\0y"),
    ] {
        assert!(CargoSource::parse(&json!({"manifest":"app/Cargo.toml","vendor":value})).is_err());
    }
    assert!(
        CargoSource::parse(&json!({"manifest":"app/Cargo.toml","vendor":"vendor","fetch":true}))
            .is_err()
    );
    let root = tempfile::tempdir().unwrap();
    fixture(root.path());
    assert!(validate_capture(&image(root.path()), "app/Cargo.toml", None).is_err());
}

#[test]
fn coherent_vendor_tree_binds_lock_and_metadata_without_rereading_checkout() {
    let root = tempfile::tempdir().unwrap();
    fixture(root.path());
    let retained = image(root.path());
    let vendor = VendoredSources::verify(&retained, "app/Cargo.toml", "vendor").unwrap();
    let files = validate_capture(&retained, "app/Cargo.toml", Some(&vendor)).unwrap();
    assert_eq!(files.len(), 8);
    assert!(files.contains(&format!("{DEP}/data.txt")));
    let locked = vendor
        .bind_lock(&retained, Path::new("app/Cargo.lock"))
        .unwrap();
    assert_eq!(
        locked,
        BTreeSet::from([(
            "fixture_dep".to_owned(),
            "1.0.0".to_owned(),
            CRATES_IO.to_owned()
        )])
    );
    write(
        root.path(),
        &format!("{DEP}/src/lib.rs"),
        "changed after capture",
    );
    let planning = Path::new("/private/planning");
    validate_metadata(
        &retained,
        planning,
        "app/Cargo.toml",
        &metadata(planning),
        Some(&vendor),
    )
    .unwrap();
    assert!(verify(root.path()).is_err());
    assert_eq!(
        retained
            .file_bytes("workspace", "app/.cargo/config.toml")
            .unwrap(),
        CONFIG.as_bytes()
    );
}

#[test]
fn vendor_config_refuses_ambient_layers_aliases_and_escaping_directories() {
    for bad in [
        CONFIG.replace("../vendor", "/vendor"),
        CONFIG.replace("../vendor", "../../vendor"),
        CONFIG.replace("../vendor", "../other"),
        CONFIG.replace("directory", "local-registry"),
        CONFIG.replace(
            "replace-with = 'vendored-sources'",
            "replace-with = 'crates-io'",
        ),
        format!("{CONFIG}\n[env]\nSECRET='private-marker'\n"),
        format!("{CONFIG}\n[build]\nrustc-wrapper='malicious-helper'\n"),
        format!("{CONFIG}\n[source.other]\ngit='file:///outside'\n"),
    ] {
        let root = tempfile::tempdir().unwrap();
        fixture(root.path());
        write(root.path(), "app/.cargo/config.toml", bad);
        let error = verify(root.path()).unwrap_err();
        assert!(!error.to_string().contains("private-marker"));
    }
    let root = tempfile::tempdir().unwrap();
    fixture(root.path());
    write(root.path(), "app/.cargo/config", CONFIG);
    assert!(
        verify(root.path()).is_err(),
        "legacy config must not shadow validated TOML"
    );
    let root = tempfile::tempdir().unwrap();
    fixture(root.path());
    fs::rename(
        root.path().join("app/.cargo"),
        root.path().join("unrelated"),
    )
    .unwrap();
    write(root.path(), "other/.cargo/config.toml", CONFIG);
    assert!(
        verify(root.path()).is_err(),
        "unrelated config cannot authorize a source"
    );
}

#[test]
fn checksums_require_every_file_exactly_once_with_no_missing_extra_or_changed_member() {
    for case in 0..8 {
        let root = tempfile::tempdir().unwrap();
        fixture(root.path());
        let checksum = root.path().join(DEP).join(CHECKSUM_FILE);
        let mut value: Value = serde_json::from_slice(&fs::read(&checksum).unwrap()).unwrap();
        match case {
            0 => write(
                root.path(),
                &format!("{DEP}/src/lib.rs"),
                "same path different bytes",
            ),
            1 => write(root.path(), &format!("{DEP}/unlisted.rs"), "extra"),
            2 => {
                fs::rename(
                    root.path().join(DEP).join("data.txt"),
                    root.path().join("saved-data"),
                )
                .unwrap();
            }
            3 => {
                value["files"]["data.txt"] = json!("00".repeat(32));
                fs::write(&checksum, value.to_string()).unwrap();
            }
            4 => {
                value["package"] = Value::Null;
                fs::write(&checksum, value.to_string()).unwrap();
            }
            5 => {
                value["files"]["../outside"] = value["files"]["data.txt"].clone();
                value["files"].as_object_mut().unwrap().remove("data.txt");
                fs::write(&checksum, value.to_string()).unwrap();
            }
            6 => {
                value["files"][CHECKSUM_FILE] = value["files"]["data.txt"].clone();
                value["files"].as_object_mut().unwrap().remove("data.txt");
                fs::write(&checksum, value.to_string()).unwrap();
            }
            _ => {
                let text =
                    value
                        .to_string()
                        .replacen("\"files\":{", "\"files\":{\"data.txt\":\"00\",", 1);
                fs::write(&checksum, text).unwrap();
            }
        }
        assert!(verify(root.path()).is_err(), "case {case}");
    }
}

#[test]
fn checksum_consistency_is_bound_to_the_actual_workspace_lock_not_a_neighbor() {
    for case in 0..5 {
        let root = tempfile::tempdir().unwrap();
        fixture(root.path());
        let path = root.path().join("app/Cargo.lock");
        let before = fs::read_to_string(&path).unwrap();
        let changed = match case {
            0 => before.replace("checksum='", "checksum='00"),
            1 => before.replace("version='1.0.0'", "version='2.0.0'"),
            2 => before.replace(CRATES_IO, "git+file:///outside#revision"),
            3 => before.replace(CRATES_IO, "registry+https://example.com/index"),
            _ => before
                .lines()
                .filter(|line| !line.starts_with("checksum="))
                .collect::<Vec<_>>()
                .join("\n"),
        };
        write(root.path(), "other/Cargo.lock", before);
        fs::write(&path, changed).unwrap();
        let retained = image(root.path());
        let vendor = VendoredSources::verify(&retained, "app/Cargo.toml", "vendor").unwrap();
        assert!(
            vendor
                .bind_lock(&retained, Path::new("app/Cargo.lock"))
                .is_err(),
            "case {case}"
        );
    }
}

#[test]
fn resolved_registry_packages_cannot_change_source_name_version_root_or_lock_membership() {
    let root = tempfile::tempdir().unwrap();
    fixture(root.path());
    package(
        root.path(),
        "vendor/another-version",
        "fixture_dep",
        "2.0.0",
    );
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
            3 => {
                changed["packages"][1]["targets"][0]["src_path"] =
                    json!(planning.join("app/src/main.rs"))
            }
            4 => changed["resolve"]["nodes"][0]["dependencies"] = json!(["missing"]),
            5 => changed["packages"][1]["source"] = json!("git+file:///outside"),
            _ => {
                changed["packages"][1]["version"] = json!("2.0.0");
                changed["packages"][1]["manifest_path"] =
                    json!(planning.join("vendor/another-version/Cargo.toml"));
                changed["packages"][1]["targets"][0]["src_path"] =
                    json!(planning.join("vendor/another-version/src/lib.rs"));
            }
        }
        assert!(
            validate_metadata(
                &retained,
                planning,
                "app/Cargo.toml",
                &changed,
                Some(&vendor)
            )
            .is_err(),
            "case {case}"
        );
    }
}

#[test]
fn symlink_and_duplicate_package_identity_refuse_the_entire_vendor_source() {
    let root = tempfile::tempdir().unwrap();
    fixture(root.path());
    package(root.path(), "vendor/duplicate", "fixture_dep", "1.0.0");
    assert!(verify(root.path()).is_err());
    let root = tempfile::tempdir().unwrap();
    fixture(root.path());
    std::os::unix::fs::symlink("src/lib.rs", root.path().join(DEP).join("alias")).unwrap();
    assert!(verify(root.path()).is_err());
    let root = tempfile::tempdir().unwrap();
    fixture(root.path());
    assert!(
        VendoredSources::verify(&image(root.path()), &format!("{DEP}/Cargo.toml"), "vendor")
            .is_err()
    );
}

const GIT_URL: &str = "https://example.invalid/immutable-source";
const GIT_REVISION: &str = "0123456789abcdef0123456789abcdef01234567";
const GIT_DEP: &str = "vendor/git-package-directory";

fn git_fixture(root: &Path, selector: Option<(&str, &str)>) -> String {
    fixture(root);
    package(root, GIT_DEP, "git_dep", "2.0.0");
    let checksum = root.join(GIT_DEP).join(CHECKSUM_FILE);
    let mut value: Value = serde_json::from_slice(&fs::read(&checksum).unwrap()).unwrap();
    value["package"] = Value::Null;
    value["$comment"] = json!("Cargo-generated Git packages have no registry archive checksum");
    fs::write(checksum, value.to_string()).unwrap();
    let field = selector.map_or(String::new(), |(kind, value)| format!("{kind}='{value}'\n"));
    write(
        root,
        "app/.cargo/config.toml",
        format!(
            "{CONFIG}\n[source.arbitrary_git_alias]\ngit='{GIT_URL}'\n{field}replace-with='vendored-sources'\n"
        ),
    );
    let manifest = fs::read_to_string(root.join("app/Cargo.toml")).unwrap();
    let field = selector.map_or(String::new(), |(kind, value)| format!(", {kind}='{value}'"));
    write(
        root,
        "app/Cargo.toml",
        format!("{manifest}git_dep={{ git='{GIT_URL}'{field} }}\n"),
    );
    let query = selector.map_or(String::new(), |(kind, value)| format!("?{kind}={value}"));
    let source = format!("git+{GIT_URL}{query}#{GIT_REVISION}");
    let lock = fs::read_to_string(root.join("app/Cargo.lock"))
        .unwrap()
        .replace(
            "dependencies=['fixture_dep']",
            "dependencies=['fixture_dep','git_dep']",
        );
    write(
        root,
        "app/Cargo.lock",
        format!("{lock}\n[[package]]\nname='git_dep'\nversion='2.0.0'\nsource='{source}'\n"),
    );
    source
}

fn git_metadata(root: &Path, source: &str) -> Value {
    let mut value = metadata(root);
    value["packages"].as_array_mut().unwrap().push(json!({
        "id":"git", "source":source, "name":"git_dep", "version":"2.0.0",
        "manifest_path":root.join(GIT_DEP).join("Cargo.toml"),
        "targets":[{"src_path":root.join(GIT_DEP).join("src/lib.rs")}]}));
    value["resolve"]["nodes"][0]["dependencies"]
        .as_array_mut()
        .unwrap()
        .push(json!("git"));
    value["resolve"]["nodes"]
        .as_array_mut()
        .unwrap()
        .push(json!({"id":"git","dependencies":[]}));
    value
}

#[test]
fn locked_git_sources_preserve_literal_selectors_and_coexist_with_registry_packages() {
    for selector in [
        None,
        Some(("rev", GIT_REVISION)),
        Some(("rev", "0123456")),
        Some(("tag", "v2")),
        Some(("branch", "feature/slash+percent%2Fhash#amp&equal=雪")),
    ] {
        let root = tempfile::tempdir().unwrap();
        let source = git_fixture(root.path(), selector);
        let retained = image(root.path());
        let vendor = VendoredSources::verify(&retained, "app/Cargo.toml", "vendor").unwrap();
        let selected = validate_capture(&retained, "app/Cargo.toml", Some(&vendor)).unwrap();
        assert!(selected.contains(&format!("{GIT_DEP}/{CHECKSUM_FILE}")));
        let locked = vendor
            .bind_lock(&retained, Path::new("app/Cargo.lock"))
            .unwrap();
        assert!(locked.contains(&("git_dep".to_owned(), "2.0.0".to_owned(), source.clone())));
        let planning = Path::new("/private/planning");
        validate_metadata(
            &retained,
            planning,
            "app/Cargo.toml",
            &git_metadata(planning, &source),
            Some(&vendor),
        )
        .unwrap();
    }
}

#[test]
fn git_lock_and_metadata_bind_the_full_revision_not_only_name_version_or_reference() {
    let root = tempfile::tempdir().unwrap();
    let source = git_fixture(root.path(), Some(("branch", "stable")));
    let retained = image(root.path());
    let vendor = VendoredSources::verify(&retained, "app/Cargo.toml", "vendor").unwrap();
    let planning = Path::new("/private/planning");
    for wrong in [
        source.replace(GIT_REVISION, &"a".repeat(40)),
        source.replace("stable", "other"),
        source.replace("immutable-source", "foreign-source"),
        source.replace(GIT_REVISION, "short"),
        source.replace(GIT_REVISION, ""),
        CRATES_IO.to_owned(),
    ] {
        assert!(
            validate_metadata(
                &retained,
                planning,
                "app/Cargo.toml",
                &git_metadata(planning, &wrong),
                Some(&vendor)
            )
            .is_err(),
            "{wrong}"
        );
    }
    let mut value = git_metadata(planning, &source);
    value["packages"][2]["source"] = Value::Null;
    assert!(
        validate_metadata(&retained, planning, "app/Cargo.toml", &value, Some(&vendor)).is_err()
    );
    let exact = format!("git+{GIT_URL}?rev={GIT_REVISION}#{}", "a".repeat(40));
    assert!(
        GitSource::parse(&exact).is_err(),
        "a full rev selector cannot silently change commit"
    );
    assert!(
        GitSource::parse(&format!(
            "git+{GIT_URL}?rev={}#{}",
            GIT_REVISION.to_ascii_uppercase(),
            "a".repeat(40)
        ))
        .is_err()
    );
    assert!(
        GitSource::parse(&format!(
            "git+{GIT_URL}?rev={}#{GIT_REVISION}",
            GIT_REVISION.to_ascii_uppercase()
        ))
        .is_ok()
    );
}

#[test]
fn git_and_registry_checksum_kinds_cannot_be_substituted_or_omit_evidence() {
    for case in 0..6 {
        let root = tempfile::tempdir().unwrap();
        git_fixture(root.path(), Some(("rev", GIT_REVISION)));
        let git_checksum = root.path().join(GIT_DEP).join(CHECKSUM_FILE);
        let mut value: Value = serde_json::from_slice(&fs::read(&git_checksum).unwrap()).unwrap();
        match case {
            0 => {
                value["package"] = json!("0".repeat(64));
                fs::write(&git_checksum, value.to_string()).unwrap();
            }
            1 => {
                value.as_object_mut().unwrap().remove("package");
                fs::write(&git_checksum, value.to_string()).unwrap();
            }
            2 => {
                value["unknown"] = json!(true);
                fs::write(&git_checksum, value.to_string()).unwrap();
            }
            3 => {
                let path = root.path().join("app/Cargo.lock");
                let text = fs::read_to_string(&path).unwrap();
                fs::write(path, format!("{text}checksum='{}'\n", "0".repeat(64))).unwrap();
            }
            4 => write(
                root.path(),
                &format!("{GIT_DEP}/data.txt"),
                "changed Git source bytes",
            ),
            _ => {
                let path = root.path().join(DEP).join(CHECKSUM_FILE);
                let mut value: Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
                value["package"] = Value::Null;
                fs::write(path, value.to_string()).unwrap();
            }
        }
        let retained = image(root.path());
        let checked = VendoredSources::verify(&retained, "app/Cargo.toml", "vendor")
            .and_then(|vendor| vendor.bind_lock(&retained, Path::new("app/Cargo.lock")));
        assert!(checked.is_err(), "case {case}");
    }
}

#[test]
fn undeclared_git_dependencies_and_ambiguous_replacements_are_refused_before_cargo() {
    for case in 0..5 {
        let root = tempfile::tempdir().unwrap();
        git_fixture(root.path(), Some(("branch", "feature+literal")));
        match case {
            0 => {
                let path = root.path().join("app/Cargo.toml");
                let text = fs::read_to_string(&path).unwrap();
                fs::write(path, text.replace("feature+literal", "feature literal")).unwrap();
            }
            1 => {
                let path = root.path().join("app/.cargo/config.toml");
                let text = fs::read_to_string(&path).unwrap();
                fs::write(path, format!("{text}rev='{GIT_REVISION}'\n")).unwrap();
            }
            2 => {
                let path = root.path().join("app/.cargo/config.toml");
                let text = fs::read_to_string(&path).unwrap();
                fs::write(path, format!("{text}\n[source.duplicate]\ngit='{GIT_URL}'\nbranch='feature+literal'\nreplace-with='vendored-sources'\n")).unwrap();
            }
            3 => {
                let path = root.path().join("app/Cargo.lock");
                let text = fs::read_to_string(&path).unwrap();
                fs::write(path, format!("{text}\n[[package]]\nname='git_dep'\nversion='2.0.0'\nsource='git+{GIT_URL}?branch=feature+literal#{}'\n", "a".repeat(40))).unwrap();
            }
            _ => {
                let path = root.path().join("app/Cargo.toml");
                let text = fs::read_to_string(&path).unwrap();
                fs::write(path, text.replace("git_dep={", "git_dep={path='../local',")).unwrap();
            }
        }
        let retained = image(root.path());
        let checked =
            VendoredSources::verify(&retained, "app/Cargo.toml", "vendor").and_then(|vendor| {
                validate_capture(&retained, "app/Cargo.toml", Some(&vendor))?;
                vendor.bind_lock(&retained, Path::new("app/Cargo.lock"))
            });
        assert!(checked.is_err(), "case {case}");
    }
}

#[test]
fn git_directory_source_path_semantics_do_not_relax_targets_or_local_inputs() {
    let root = tempfile::tempdir().unwrap();
    git_fixture(root.path(), Some(("rev", GIT_REVISION)));
    let retained = image(root.path());
    let vendor = VendoredSources::verify(&retained, "app/Cargo.toml", "vendor").unwrap();
    for declaration in [
        "[dependencies]\nsibling={path='../sibling',version='1'}",
        "[target.'cfg(unix)'.build-dependencies]\nsibling={path='/original/git/checkout/sibling',version='1'}",
    ] {
        let value = toml::from_str(declaration).unwrap();
        assert!(
            super::super::validate_manifest_paths(
                Path::new(""),
                &value,
                Some(&vendor.sources),
                true
            )
            .is_ok()
        );
        assert!(
            super::super::validate_manifest_paths(
                Path::new(""),
                &value,
                Some(&vendor.sources),
                false
            )
            .is_err()
        );
    }
    for declaration in [
        "[lib]\npath='../outside.rs'",
        "[package]\nbuild='../outside.rs'",
        "[package]\nreadme='/outside'",
        "[package]\nlicense-file='../private'",
    ] {
        let value = toml::from_str(declaration).unwrap();
        assert!(
            super::super::validate_manifest_paths(
                Path::new(""),
                &value,
                Some(&vendor.sources),
                true
            )
            .is_err()
        );
    }
}

#[test]
fn local_reclassification_of_vendor_packages_is_refused_before_metadata_can_read_paths() {
    let root = tempfile::tempdir().unwrap();
    git_fixture(root.path(), Some(("rev", GIT_REVISION)));
    let vendor = verify(root.path()).unwrap();
    for declaration in [
        "[dependencies]\ngit_dep={path='../vendor/git-package-directory'}",
        "[workspace.dependencies]\ngit_dep={path='../vendor/git-package-directory'}",
        "[target.'cfg(unix)'.build-dependencies]\ngit_dep={path='../vendor/git-package-directory'}",
        "[patch.crates-io]\ngit_dep={path='../vendor/git-package-directory'}",
        "[replace]\n'git_dep:2.0.0'={path='../vendor/git-package-directory'}",
        "[package]\nworkspace='../vendor/git-package-directory'",
        "[workspace]\nmembers=['../vendor/*']",
        "[workspace]\ndefault-members=['../vendor/git-package-directory']",
        "[workspace]\nmembers=['../*/*']",
    ] {
        let value = toml::from_str(declaration).unwrap();
        let error = super::super::validate_manifest_paths(
            Path::new("app"),
            &value,
            Some(&vendor.sources),
            false,
        )
        .unwrap_err();
        assert!(
            error.to_string().contains("local Cargo package selection"),
            "{declaration}: {error}"
        );
    }
    // Disjoint workspace patterns and ordinary local dependencies retain the
    // existing Cargo semantics; excludes never load a package.
    for declaration in [
        "[workspace]\nmembers=['crates/*']",
        "[workspace]\nmembers=['.']\ndefault-members=['.']",
        "[dependencies]\nlocal={path='../local'}",
        "[workspace]\nexclude=['../vendor/*']",
    ] {
        let value = toml::from_str(declaration).unwrap();
        super::super::validate_manifest_paths(
            Path::new("app"),
            &value,
            Some(&vendor.sources),
            false,
        )
        .unwrap();
    }
    // Exercise the actual retained-capture preflight, not only its helper.
    let path = root.path().join("app/Cargo.toml");
    let text = fs::read_to_string(&path).unwrap();
    fs::write(
        path,
        format!("{text}local_alias={{path='../vendor/git-package-directory',package='git_dep'}}\n"),
    )
    .unwrap();
    assert!(
        validate_capture(&image(root.path()), "app/Cargo.toml", Some(&vendor))
            .unwrap_err()
            .to_string()
            .contains("local Cargo package selection")
    );
}
