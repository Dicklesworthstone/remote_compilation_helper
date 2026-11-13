//! Native staging collection, including the exact dispatcher's witness,
//! custody and filesystem regression suite against the real worker binary.

#![cfg(unix)]
#![forbid(unsafe_code)]

#[path = "../../rch/src/cache_gc.rs"]
pub mod dispatcher;

use std::ffi::OsString;
use std::fs;
use std::os::unix::fs::MetadataExt as _;
use std::path::PathBuf;
use std::process::{Command, Output};

struct Fixture {
    root: PathBuf,
    base: PathBuf,
    tree: PathBuf,
}

impl Fixture {
    fn new() -> Self {
        let root = tempfile::Builder::new()
            .prefix("rch-native-staging-")
            .tempdir()
            .unwrap()
            .keep()
            .canonicalize()
            .unwrap();
        let base = root.join("base with ' quotes");
        let tree = base.join("project/hash");
        fs::create_dir_all(&tree).unwrap();
        fs::write(tree.join("input"), b"retain unless fully authorized").unwrap();
        Self { root, base, tree }
    }

    fn witness(&self) -> String {
        let identity = |path: &std::path::Path| {
            let metadata = fs::symlink_metadata(path).unwrap();
            serde_json::json!({"device":metadata.dev(), "inode":metadata.ino()})
        };
        // Preview binds identities without reading contents. The intentionally
        // false metadata digest must never authorize the apply operation.
        serde_json::json!({
            "canonical_base": self.base,
            "base": identity(&self.base),
            "parent": identity(self.tree.parent().unwrap()),
            "tree": identity(&self.tree),
            "metadata_digest": "0".repeat(64),
        })
        .to_string()
    }

    fn arguments(&self, mode: &str) -> Vec<OsString> {
        vec![
            "--protocol".into(),
            "v1".into(),
            self.tree.as_os_str().to_owned(),
            self.base.as_os_str().to_owned(),
            mode.into(),
            self.witness().into(),
            "0".into(),
            self.tree.as_os_str().to_owned(),
        ]
    }

    fn run(&self, arguments: &[OsString]) -> Output {
        Command::new(env!("CARGO_BIN_EXE_rch-wkr"))
            .arg("staging-gc")
            .args(arguments)
            .env_clear()
            .env("PATH", "")
            .env("TOKIO_WORKER_THREADS", "0")
            .env("TMPDIR", self.root.join("absent"))
            .env("RCH_LOG_FILE", self.root.join("absent/log"))
            .output()
            .unwrap()
    }

    fn assert_retained(&self) {
        assert_eq!(
            fs::read(self.tree.join("input")).unwrap(),
            b"retain unless fully authorized"
        );
        assert!(!self.root.join("absent").exists());
    }
}

#[test]
fn native_preview_needs_no_runtime_interpreter_or_writable_scratch() {
    let fixture = Fixture::new();
    let result = fixture.run(&fixture.arguments("preview"));
    assert!(result.status.success(), "{result:?}");
    assert_eq!(result.stdout, b"ready\n");
    assert!(result.stderr.is_empty(), "{result:?}");
    fixture.assert_retained();
}

#[test]
fn native_apply_refuses_unverified_metadata() {
    let fixture = Fixture::new();
    let result = fixture.run(&fixture.arguments("apply"));
    assert!(result.status.success(), "{result:?}");
    assert_eq!(result.stdout, b"changed\n");
    fixture.assert_retained();
}

#[test]
fn native_protocol_refuses_unknown_or_ambiguous_inputs() {
    let fixture = Fixture::new();
    for (index, value) in [
        (1, "v2"),
        (4, "delete"),
        (5, "{}"),
        (6, "-1"),
        (6, "+1"),
        (6, "1.5"),
        (6, "340282366920938463463374607431768211456"),
    ] {
        let mut arguments = fixture.arguments("apply");
        arguments[index] = value.into();
        let result = fixture.run(&arguments);
        assert_eq!(result.status.code(), Some(73), "{index}:{value} {result:?}");
        assert_eq!(result.stdout, b"unavailable\n", "{result:?}");
        fixture.assert_retained();
    }
}

#[test]
fn native_preview_refuses_foreign_claim_and_replaced_parent() {
    let fixture = Fixture::new();
    let mut arguments = fixture.arguments("preview");
    arguments[7] = fixture.root.join("foreign/project/hash").into_os_string();
    let result = fixture.run(&arguments);
    assert!(result.status.success(), "{result:?}");
    assert_eq!(result.stdout, b"changed\n");
    fixture.assert_retained();

    let arguments = fixture.arguments("preview");
    let retained = fixture.root.join("retained-project");
    fs::rename(fixture.tree.parent().unwrap(), &retained).unwrap();
    std::os::unix::fs::symlink(&retained, fixture.tree.parent().unwrap()).unwrap();
    let result = fixture.run(&arguments);
    assert!(result.status.success(), "{result:?}");
    assert_eq!(result.stdout, b"changed\n");
    fixture.assert_retained();
}
