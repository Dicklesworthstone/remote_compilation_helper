//! Real filesystem preparation binds the submitted compiler identity while
//! keeping its local installation path out of the executable worker request.
#![cfg(target_os = "linux")]

use rabs_sandbox::toolchain_dataset::{
    TOOLCHAIN_DATASET_VERSION, ToolchainIdentity, ToolchainLimits, fingerprint_toolchain,
};
use rabsd::coord::source_delivery::prepare_source_bundle;
use serde_json::{Value, json};
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

const ORIGINAL: &[u8] = b"#!/bin/sh\nprintf 'toolchain-v1\\n'\n";
const REPLACEMENT: &[u8] = b"#!/bin/sh\nprintf 'toolchain-v2\\n'\n";
const SOURCE: &[u8] = b"fn main() {}\n";

struct Fixture {
    owner: tempfile::TempDir,
    source: PathBuf,
    toolchain: PathBuf,
    specification: Value,
}

impl Fixture {
    fn new() -> Self {
        let owner = tempfile::tempdir().unwrap();
        let source = owner.path().join("checkout");
        let toolchain = owner.path().join("local compiler installation");
        fs::create_dir(&source).unwrap();
        fs::create_dir_all(toolchain.join("bin")).unwrap();
        fs::write(source.join("main.rs"), SOURCE).unwrap();
        fs::write(toolchain.join("bin/probe"), ORIGINAL).unwrap();
        fs::set_permissions(
            toolchain.join("bin/probe"),
            fs::Permissions::from_mode(0o755),
        )
        .unwrap();
        let specification = json!({
            "kind": "canonical-exec", "request_id": 41,
            "program": "/__rabs/toolchain/bin/probe", "args": [],
            "toolchain_backing": "/worker/toolchains/probe",
            "toolchain_source": toolchain, "source_files": ["main.rs"]
        });
        Self {
            owner,
            source,
            toolchain,
            specification,
        }
    }

    fn fingerprint(&self) -> ToolchainIdentity {
        fingerprint_toolchain(&self.toolchain, &ToolchainLimits::default(), || false).unwrap()
    }

    fn destination(&self, name: &str) -> PathBuf {
        self.owner.path().join(name)
    }
}

fn identity_value(identity: &ToolchainIdentity) -> Value {
    let sha256: String = identity
        .sha256
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    json!({"version": TOOLCHAIN_DATASET_VERSION, "sha256": sha256,
        "files": identity.files, "bytes": identity.bytes})
}

fn read_request(destination: &Path) -> Value {
    serde_json::from_slice(&fs::read(destination.join("request.json")).unwrap()).unwrap()
}

#[test]
fn preparation_fingerprints_real_toolchain_and_strips_local_path() {
    let fixture = Fixture::new();
    let original_specification = fixture.specification.clone();
    let expected = fixture.fingerprint();
    let destination = fixture.destination("prepared");
    let summary = prepare_source_bundle(&fixture.source, &fixture.specification, &destination)
        .expect("prepare the real source and local toolchain identity");
    let request = read_request(&destination);
    assert_eq!(request["toolchain_identity"], identity_value(&expected));
    assert_eq!(summary["toolchain_identity"], request["toolchain_identity"]);
    assert_eq!(summary["executed"], false);
    assert_eq!(summary["publication_authorized"], false);
    assert_eq!(expected.files, 1);
    assert_eq!(expected.bytes, ORIGINAL.len() as u64);
    assert!(request.get("toolchain_source").is_none());
    assert!(request.get("source_files").is_none());
    assert!(
        !request
            .to_string()
            .contains(fixture.toolchain.to_str().unwrap())
    );
    assert_eq!(request["toolchain_backing"], "/worker/toolchains/probe");
    assert_eq!(
        fs::read(destination.join("source/main.rs")).unwrap(),
        SOURCE
    );
    assert_eq!(fixture.specification, original_specification);
    assert_eq!(
        fs::read(fixture.toolchain.join("bin/probe")).unwrap(),
        ORIGINAL
    );

    // A matching caller-supplied identity is accepted only after independently
    // fingerprinting the actual local installation again.
    let mut pinned = fixture.specification.clone();
    pinned["toolchain_identity"] = identity_value(&expected);
    let pinned_destination = fixture.destination("pinned");
    prepare_source_bundle(&fixture.source, &pinned, &pinned_destination).unwrap();
    assert_eq!(read_request(&pinned_destination), request);

    // Preserve size and executable mode: observing metadata alone cannot detect
    // this compiler change. Previously prepared requests keep their old binding.
    assert_eq!(ORIGINAL.len(), REPLACEMENT.len());
    fs::write(fixture.toolchain.join("bin/probe"), REPLACEMENT).unwrap();
    assert_eq!(
        fs::metadata(fixture.toolchain.join("bin/probe"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o755
    );
    let changed_destination = fixture.destination("changed");
    prepare_source_bundle(
        &fixture.source,
        &fixture.specification,
        &changed_destination,
    )
    .unwrap();
    let changed = read_request(&changed_destination);
    assert_ne!(
        changed["toolchain_identity"]["sha256"],
        request["toolchain_identity"]["sha256"]
    );
    assert_eq!(
        changed["toolchain_identity"],
        identity_value(&fixture.fingerprint())
    );
    assert_eq!(changed["source_manifest"], request["source_manifest"]);
    assert_eq!(read_request(&destination), request);
    assert_eq!(fs::read(fixture.source.join("main.rs")).unwrap(), SOURCE);
}

#[test]
fn preparation_rejects_mismatched_toolchain_before_publishing_request() {
    for change in [
        "equal-size-content",
        "executable-mode",
        "declared-files",
        "declared-bytes",
    ] {
        let mut fixture = Fixture::new();
        let expected = fixture.fingerprint();
        fixture.specification["toolchain_identity"] = identity_value(&expected);
        match change {
            "equal-size-content" => {
                assert_eq!(ORIGINAL.len(), REPLACEMENT.len());
                fs::write(fixture.toolchain.join("bin/probe"), REPLACEMENT).unwrap();
            }
            "executable-mode" => fs::set_permissions(
                fixture.toolchain.join("bin/probe"),
                fs::Permissions::from_mode(0o644),
            )
            .unwrap(),
            "declared-files" => {
                fixture.specification["toolchain_identity"]["files"] = json!(expected.files + 1)
            }
            "declared-bytes" => {
                fixture.specification["toolchain_identity"]["bytes"] = json!(expected.bytes + 1)
            }
            _ => unreachable!(),
        }
        let destination = fixture.destination("refused");
        let error = prepare_source_bundle(&fixture.source, &fixture.specification, &destination)
            .expect_err("a changed local toolchain cannot author a prepared request");
        assert!(
            error
                .to_string()
                .contains("local toolchain does not match the specified toolchain_identity"),
            "{change}: {error}"
        );
        assert!(
            !destination.exists(),
            "{change}: refusal left a prepared bundle"
        );
        assert_eq!(fs::read(fixture.source.join("main.rs")).unwrap(), SOURCE);
    }
}
