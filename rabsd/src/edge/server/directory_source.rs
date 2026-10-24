//! Admit Cargo directory-source packages through the existing live lane.
//!
//! A `.cargo-checksum.json` is a source-layout witness, NOT a digest oracle.
//! We bind the exact observed document to the subsequently sealed package.
//! Every file (listed or not) is still captured and keyed by LiveFacts, and
//! ordinary post-execution closure, serving and publication checks remain.

use crate::edge::live_facts::read_stable;
use rabs_cas::digest_set::{DigestRequest, digest_set};
use rabs_key::live_dependency::{
    DependencyActionPlan, LiveRefusal, LiveRustcRequest, plan_directory_dependency_action,
};
use serde::de::{Error as _, MapAccess, Visitor};
use std::collections::BTreeSet;
use std::path::Path;

const MAX_CHECKSUM_BYTES: u64 = 1024 * 1024;
const MAX_CHECKSUM_FILES: usize = 20_000;

fn checksum_hex(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn relative_member(value: &str) -> bool {
    !value.is_empty()
        && !value.contains(['\\', '\0', ':'])
        && value
            .split('/')
            .all(|part| !matches!(part, "" | "." | ".." | ".git"))
}

/// Validate names and hashes without using either to choose captured inputs.
struct FileChecksums;

impl<'de> serde::Deserialize<'de> for FileChecksums {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct FilesVisitor;

        impl<'de> Visitor<'de> for FilesVisitor {
            type Value = FileChecksums;

            fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.write_str("a bounded map of relative file names to SHA-256 strings")
            }

            fn visit_map<M: MapAccess<'de>>(self, mut map: M) -> Result<Self::Value, M::Error> {
                let mut names = BTreeSet::new();
                while let Some((name, digest)) = map.next_entry::<String, String>()? {
                    if names.len() >= MAX_CHECKSUM_FILES
                        || !relative_member(&name)
                        || !checksum_hex(&digest)
                        || !names.insert(name)
                    {
                        return Err(M::Error::custom("invalid directory-source file checksums"));
                    }
                }
                Ok(FileChecksums)
            }
        }

        deserializer.deserialize_map(FilesVisitor)
    }
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct DirectoryChecksum {
    #[serde(rename = "files")]
    _files: FileChecksums,
    package: Option<String>,
}

fn validate_checksum(bytes: &[u8]) -> Result<(), LiveRefusal> {
    let refused = || LiveRefusal::Facts("invalid Cargo directory-source checksum document".into());
    if bytes.len() as u64 > MAX_CHECKSUM_BYTES {
        return Err(refused());
    }
    let document: DirectoryChecksum = serde_json::from_slice(bytes).map_err(|_| refused())?;
    if document
        .package
        .as_deref()
        .is_some_and(|digest| !checksum_hex(digest))
    {
        return Err(refused());
    }
    Ok(())
}

/// Try the unchanged registry/Git planner first. Only its unsupported-source
/// result can reach the directory-source adapter; primary-package, duplicate
/// environment and other earlier refusals retain their original behavior.
pub(super) fn plan_dependency_action(
    request: LiveRustcRequest<'_>,
    host: &str,
) -> Result<DependencyActionPlan, LiveRefusal> {
    let package = match rabs_key::live_dependency::plan_dependency_action(request, host) {
        Err(LiveRefusal::NotDependencySource(package)) => package,
        result => return result,
    };
    if request.cwd != package {
        return Err(LiveRefusal::WorkingDirectory(request.cwd.to_owned()));
    }
    let root = Path::new(&package);
    if !std::fs::symlink_metadata(root).is_ok_and(|meta| meta.is_dir()) {
        return Err(LiveRefusal::NotDependencySource(package));
    }
    let (_, document) = read_stable(&root.join(".cargo-checksum.json"), MAX_CHECKSUM_BYTES)
        .map_err(|_| LiveRefusal::NotDependencySource(package.clone()))?;
    validate_checksum(&document)?;
    let witness = digest_set(&document, DigestRequest::default(), None)
        .map_err(|_| {
            LiveRefusal::Facts("cannot identify directory-source checksum document".into())
        })?
        .atp_content_id;
    plan_directory_dependency_action(request, host, witness)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::edge::live_facts::{LiveFacts, PackageFacts};
    use rabs_key::live_dependency::{DependencySourceKind, ToolchainFacts, live_dependency_key};
    use rabs_key::typed_digest::compute;
    use rabs_protocol::input_evidence::{
        ActionInputManifest, INPUT_EVIDENCE_SCHEMA_VERSION, InputFileType, PositiveInput,
    };
    use rabs_protocol::raw_bytes::RawBytes;
    use rabs_protocol::result_identity::{ObjectId, TypedDigest};
    use std::path::PathBuf;

    const HOST: &str = "x86_64-unknown-linux-gnu";
    const CHECKSUM: &[u8] = br#"{"files":{},"package":null}"#;

    struct Fixture {
        _temp: tempfile::TempDir,
        package: PathBuf,
        argv: Vec<String>,
        env: Vec<(String, String)>,
    }

    impl Fixture {
        fn new() -> Self {
            let temp = tempfile::tempdir().unwrap();
            let root = temp.path().canonicalize().unwrap();
            let package = root.join("vendor/demo-1.0.0");
            let out = root.join("target/deps");
            std::fs::create_dir_all(package.join("src")).unwrap();
            std::fs::create_dir_all(&out).unwrap();
            std::fs::write(
                package.join("Cargo.toml"),
                b"[package]\nname = \"demo\"\nversion = \"1.0.0\"\n",
            )
            .unwrap();
            std::fs::write(package.join("src/lib.rs"), b"pub const VALUE: u32 = 7;\n").unwrap();
            std::fs::write(package.join(".cargo-checksum.json"), CHECKSUM).unwrap();
            let argv = vec![
                "/toolchain/bin/rustc".into(),
                "--crate-name=demo".into(),
                "--crate-type=lib".into(),
                "--emit=metadata,dep-info".into(),
                "--out-dir".into(),
                out.to_str().unwrap().to_owned(),
                "--cap-lints=allow".into(),
                "--error-format=json".into(),
                package.join("src/lib.rs").to_str().unwrap().to_owned(),
            ];
            let env = vec![
                (
                    "CARGO_HOME".into(),
                    root.join("cargo-home").to_str().unwrap().to_owned(),
                ),
                (
                    "CARGO_MANIFEST_DIR".into(),
                    package.to_str().unwrap().to_owned(),
                ),
                ("CARGO_PKG_NAME".into(), "demo".into()),
            ];
            Self {
                _temp: temp,
                package,
                argv,
                env,
            }
        }

        fn request(&self) -> LiveRustcRequest<'_> {
            LiveRustcRequest {
                argv: &self.argv,
                cwd: self.package.to_str().unwrap(),
                env: &self.env,
            }
        }

        fn plan(&self) -> DependencyActionPlan {
            plan_dependency_action(self.request(), HOST).unwrap()
        }

        fn capture(&self, plan: &DependencyActionPlan) -> std::sync::Arc<PackageFacts> {
            LiveFacts::new()
                .package(&self.package, plan.source_kind, None)
                .unwrap()
        }
    }

    fn captured_key(
        plan: &DependencyActionPlan,
        package: &PackageFacts,
    ) -> Result<TypedDigest, LiveRefusal> {
        let inputs = ActionInputManifest {
            schema_version: INPUT_EVIDENCE_SCHEMA_VERSION,
            inputs: package
                .files
                .iter()
                .map(|(relative, object, executable)| PositiveInput {
                    virtual_path: RawBytes::new(plan.input_virtual_path(relative).into_bytes()),
                    object: ObjectId(object.clone()),
                    file_type: InputFileType::Regular,
                    executable: *executable,
                    symlink_resolution: Vec::new(),
                })
                .collect(),
            ..ActionInputManifest::default()
        };
        let identity = compute("rabs.test-object.v1", b"toolchain");
        let toolchain = ToolchainFacts {
            compiler_binary_digest: identity.clone(),
            verbose_version: format!("rustc fixture\nhost: {HOST}\n"),
            sysroot_root_digest: identity,
            runtime_libraries: Vec::new(),
        };
        live_dependency_key(plan, &toolchain, &[], &[], None, &inputs).map(|key| key.action_key)
    }

    #[test]
    fn checksum_shape_is_bounded_unambiguous_and_never_a_file_digest_oracle() {
        assert!(validate_checksum(CHECKSUM).is_ok());
        assert!(validate_checksum(br#"{"files":{}}"#).is_ok());
        let digest = "ab".repeat(32);
        let valid = format!(r#"{{"files":{{"src/lib.rs":"{digest}"}},"package":"{digest}"}}"#);
        assert!(validate_checksum(valid.as_bytes()).is_ok());
        for invalid in [
            "null",
            "{}",
            r#"{"files":[]}"#,
            r#"{"files":null}"#,
            r#"{"files":{},"files":{}}"#,
            r#"{"files":{},"package":true}"#,
            r#"{"files":{},"package":"bad"}"#,
            r#"{"files":{},"extra":0}"#,
            r#"{"files":{"src/lib.rs":0}}"#,
            r#"{"files":{"src/lib.rs":"bad"}}"#,
        ] {
            assert!(validate_checksum(invalid.as_bytes()).is_err(), "{invalid}");
        }
        for name in [
            "/absolute",
            "../outside",
            "src/../lib.rs",
            "src//lib.rs",
            ".git/HEAD",
        ] {
            let invalid = format!(r#"{{"files":{{"{name}":"{digest}"}}}}"#);
            assert!(validate_checksum(invalid.as_bytes()).is_err());
        }
        let duplicate = format!(r#"{{"files":{{"lib.rs":"{digest}","lib.rs":"{digest}"}}}}"#);
        assert!(validate_checksum(duplicate.as_bytes()).is_err());
        let mut oversized = CHECKSUM.to_vec();
        oversized.resize(MAX_CHECKSUM_BYTES as usize + 1, b' ');
        assert!(validate_checksum(&oversized).is_err());
        assert!(validate_checksum(b"\xff").is_err());
    }

    #[test]
    fn directory_capture_keys_actual_unlisted_sources_not_declared_checksums() {
        let fixture = Fixture::new();
        let plan = fixture.plan();
        assert_eq!(plan.source_kind, DependencySourceKind::DirectoryPackage);
        let original = fixture.capture(&plan);
        assert_eq!(original.files.len(), 3);
        let key = captured_key(&plan, &original).unwrap();
        std::fs::write(
            fixture.package.join("src/lib.rs"),
            b"pub const VALUE: u32 = 8;\n",
        )
        .unwrap();
        assert!(original.verify_unchanged(&fixture.package).is_err());
        let changed = fixture.capture(&plan);
        assert_ne!(key, captured_key(&plan, &changed).unwrap());
        let changed_key = captured_key(&plan, &changed).unwrap();
        std::fs::write(fixture.package.join("unlisted.txt"), b"new input").unwrap();
        assert!(changed.verify_unchanged(&fixture.package).is_err());
        assert_ne!(
            changed_key,
            captured_key(&plan, &fixture.capture(&plan)).unwrap()
        );
        assert_eq!(
            std::fs::read(fixture.package.join(".cargo-checksum.json")).unwrap(),
            CHECKSUM
        );
    }

    #[test]
    fn checksum_change_between_planning_and_capture_cannot_admit_a_key() {
        let fixture = Fixture::new();
        let before = fixture.plan();
        let original = fixture.capture(&before);
        let key = captured_key(&before, &original).unwrap();
        std::fs::write(
            fixture.package.join(".cargo-checksum.json"),
            b"{\"files\":{}}\n",
        )
        .unwrap();
        assert!(original.verify_unchanged(&fixture.package).is_err());
        let changed = fixture.capture(&before);
        assert!(captured_key(&before, &changed).is_err());
        let after = fixture.plan();
        assert_ne!(key, captured_key(&after, &changed).unwrap());
    }

    #[test]
    fn missing_linked_or_non_file_witnesses_do_not_admit_directory_sources() {
        let fixture = Fixture::new();
        let witness = fixture.package.join(".cargo-checksum.json");
        let retained = fixture.package.join("retained-checksum.json");
        std::fs::rename(&witness, &retained).unwrap();
        assert!(matches!(
            plan_dependency_action(fixture.request(), HOST),
            Err(LiveRefusal::NotDependencySource(_))
        ));
        std::os::unix::fs::symlink(&retained, &witness).unwrap();
        assert!(plan_dependency_action(fixture.request(), HOST).is_err());
        std::fs::rename(&witness, fixture.package.join("retained-link")).unwrap();
        std::fs::create_dir(&witness).unwrap();
        assert!(plan_dependency_action(fixture.request(), HOST).is_err());
    }

    #[test]
    fn existing_source_and_primary_package_classification_is_not_overridden() {
        let mut fixture = Fixture::new();
        fixture
            .env
            .push(("CARGO_PRIMARY_PACKAGE".into(), "1".into()));
        assert!(matches!(
            plan_dependency_action(fixture.request(), HOST),
            Err(LiveRefusal::RefusedEnv(_))
        ));
        let mut request = fixture.request();
        request.cwd = "/different/caller";
        assert!(matches!(
            plan_dependency_action(request, HOST),
            Err(LiveRefusal::RefusedEnv(_))
        ));
        fixture.env.pop();
        let mut request = fixture.request();
        request.cwd = "/different/caller";
        assert!(matches!(
            plan_dependency_action(request, HOST),
            Err(LiveRefusal::WorkingDirectory(_))
        ));
        // A registry-layout request never needs this adapter's checksum read.
        // Pure planning has no filesystem effects; this directory is absent.
        let package = "/cargo/registry/src/index/demo-1.0.0";
        let argv: Vec<_> = fixture
            .argv
            .iter()
            .map(|arg| arg.replace(fixture.package.to_str().unwrap(), package))
            .collect();
        let env = vec![
            ("CARGO_HOME".into(), "/cargo".into()),
            ("CARGO_MANIFEST_DIR".into(), package.into()),
            ("CARGO_PKG_NAME".into(), "demo".into()),
        ];
        let request = LiveRustcRequest {
            argv: &argv,
            cwd: package,
            env: &env,
        };
        assert_eq!(
            plan_dependency_action(request, HOST).unwrap(),
            rabs_key::live_dependency::plan_dependency_action(request, HOST).unwrap()
        );
    }
}
