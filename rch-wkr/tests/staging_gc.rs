//! Native staging collection, including the exact dispatcher's witness,
//! custody and filesystem regression suite against the real worker binary.

#![cfg(unix)]
#![forbid(unsafe_code)]

#[path = "../../rch/src/cache_gc.rs"]
pub mod dispatcher;

use std::ffi::OsString;
use std::fs;
use std::os::unix::fs::MetadataExt as _;
use std::path::{Path, PathBuf};
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


fn force_resync_custody(fixture: &Fixture) -> (PathBuf, PathBuf) {
    use sha2::{Digest as _, Sha256};
    use std::os::unix::fs::PermissionsExt as _;

    let registry = fixture.root.join("claims");
    fs::create_dir_all(&registry).unwrap();
    fs::set_permissions(&registry, fs::Permissions::from_mode(0o700)).unwrap();
    let bytes = format!("{}\n", fixture.tree.parent().unwrap().display());
    let digest = format!("{:x}", Sha256::digest(bytes.as_bytes()));
    let claim = registry.join(format!(
        "fc-12345678-1234-1234-1234-123456789abc.{digest}.claim"
    ));
    fs::write(&claim, bytes).unwrap();
    fs::set_permissions(&claim, fs::Permissions::from_mode(0o600)).unwrap();
    (registry, claim)
}

fn force_resync_command(fixture: &Fixture, operation: &str, witness: Option<&str>) -> Command {
    let mut command = if operation == "apply" {
        let (registry, claim) = force_resync_custody(fixture);
        let flock = std::env::split_paths(&std::env::var_os("PATH").unwrap_or_default())
            .map(|directory| directory.join("flock"))
            .find(|path| path.is_file())
            .expect("native custody fixture requires the worker's flock dependency");
        let mut command = Command::new("/bin/sh");
        // Establish the real inherited transaction descriptor, including the
        // permissive lock-file mode produced by a normal fleet umask.
        command
            .args([
                "-c",
                "umask 002; exec 8>\"$1/metadata.lock\" || exit 73; \"$2\" -x 8 || exit 73; shift 2; exec \"$@\"",
                "force-resync-fixture",
            ])
            .arg(&registry)
            .arg(flock)
            .arg(env!("CARGO_BIN_EXE_rch-wkr"))
            .arg("force-resync")
            .arg(operation)
            .arg(fixture.tree.parent().unwrap())
            .arg(witness.expect("apply witness"))
            .arg(registry)
            .arg(claim);
        command
    } else {
        let mut command = Command::new(env!("CARGO_BIN_EXE_rch-wkr"));
        command
            .arg("force-resync")
            .arg(operation)
            .arg(fixture.tree.parent().unwrap());
        command
    };
    command
        .current_dir(&fixture.base)
        .env_clear()
        .env("PATH", "")
        .env("TOKIO_WORKER_THREADS", "0")
        .env("TMPDIR", fixture.root.join("absent"))
        .env("RCH_LOG_FILE", fixture.root.join("absent/log"));
    command
}

fn force_resync_witness(fixture: &Fixture) -> String {
    let result = force_resync_command(fixture, "inspect", None)
        .output()
        .unwrap();
    assert!(result.status.success(), "{result:?}");
    assert!(result.stderr.is_empty(), "{result:?}");
    String::from_utf8(result.stdout).unwrap().trim().to_owned()
}

#[test]
fn force_resync_owns_native_deletion_without_spawning_an_unlabelled_rm() {
    use std::os::unix::fs::{PermissionsExt as _, symlink};

    let fixture = Fixture::new();
    let outside = fixture.root.join("outside");
    fs::create_dir(&outside).unwrap();
    fs::write(outside.join("sentinel"), b"outside cache").unwrap();
    symlink(&outside, fixture.tree.join("nested-link")).unwrap();
    let tools = fixture.root.join("tools");
    fs::create_dir(&tools).unwrap();
    let poison = tools.join("rm");
    fs::write(
        &poison,
        "#!/bin/sh\nprintf invoked > \"$RCH_TEST_RM_MARKER\"\nexit 74\n",
    )
    .unwrap();
    fs::set_permissions(&poison, fs::Permissions::from_mode(0o700)).unwrap();
    let marker = fixture.root.join("rm-invoked");
    let witness = force_resync_witness(&fixture);
    let mut command = force_resync_command(&fixture, "apply", Some(&witness));
    command.env("PATH", &tools).env("RCH_TEST_RM_MARKER", &marker);
    // The native process retains this ordinary argv field until its own
    // descriptor-relative deletion has completed; it never execs a child rm.
    assert!(
        command
            .get_args()
            .any(|argument| argument == fixture.tree.parent().unwrap().as_os_str())
    );
    let result = command.output().unwrap();
    assert!(result.status.success(), "{result:?}");
    assert_eq!(result.stdout, b"removed\n");
    assert!(!fixture.tree.parent().unwrap().exists());
    assert_eq!(fs::read(outside.join("sentinel")).unwrap(), b"outside cache");
    assert!(!marker.exists());
    assert!(!fixture.root.join("absent").exists());
    assert_eq!(
        fs::metadata(fixture.root.join("claims/metadata.lock"))
            .unwrap()
            .mode()
            & 0o777,
        0o664
    );
}

#[test]
fn force_resync_requires_inherited_lock_and_exact_active_claim() {
    for failure in ["missing-fd", "foreign-fd", "changed-claim"] {
        let fixture = Fixture::new();
        let witness = force_resync_witness(&fixture);
        let (registry, claim) = force_resync_custody(&fixture);
        let mut command = if failure == "changed-claim" {
            let command = force_resync_command(&fixture, "apply", Some(&witness));
            fs::write(&claim, b"/another/source\n").unwrap();
            command
        } else {
            fs::write(registry.join("metadata.lock"), b"").unwrap();
            let script = if failure == "missing-fd" {
                "exec 8>&-; shift; exec \"$@\""
            } else {
                "exec 8>\"$1\"; shift; exec \"$@\""
            };
            let mut command = Command::new("/bin/sh");
            command
                .args(["-c", script, "force-resync-custody"])
                .arg(fixture.root.join("foreign.lock"))
                .arg(env!("CARGO_BIN_EXE_rch-wkr"))
                .arg("force-resync")
                .arg("apply")
                .arg(fixture.tree.parent().unwrap())
                .arg(&witness)
                .arg(&registry)
                .arg(&claim)
                .current_dir(&fixture.base)
                .env_clear()
                .env("PATH", "")
                .env("TOKIO_WORKER_THREADS", "0");
            command
        };
        let result = command.output().unwrap();
        assert_eq!(result.status.code(), Some(73), "{failure}: {result:?}");
        assert!(result.stdout.is_empty(), "{failure}: {result:?}");
        fixture.assert_retained();
    }
}

#[test]
fn force_resync_rejects_changed_or_malformed_native_witnesses() {
    let fixture = Fixture::new();
    let original = force_resync_witness(&fixture);
    for field in ["base", "tree"] {
        let mut witness: serde_json::Value = serde_json::from_str(&original).unwrap();
        witness[field]["inode"] = serde_json::json!(0);
        let result = force_resync_command(&fixture, "apply", Some(&witness.to_string()))
            .output()
            .unwrap();
        assert_eq!(result.status.code(), Some(73), "{field}: {result:?}");
        assert!(result.stdout.is_empty(), "{result:?}");
        fixture.assert_retained();
    }
    for witness in ["{}".to_owned(), "x".repeat(16 * 1024 + 1)] {
        let result = force_resync_command(&fixture, "apply", Some(&witness))
            .output()
            .unwrap();
        assert_eq!(result.status.code(), Some(73), "{result:?}");
        assert!(result.stdout.is_empty(), "{result:?}");
        fixture.assert_retained();
    }
}

#[test]
fn force_resync_preserves_replaced_base_and_original_tree() {
    let fixture = Fixture::new();
    let witness = force_resync_witness(&fixture);
    let retained = fixture.root.join("retained-base");
    fs::rename(&fixture.base, &retained).unwrap();
    fs::create_dir_all(&fixture.tree).unwrap();
    fs::write(fixture.tree.join("input"), b"replacement cache").unwrap();
    let result = force_resync_command(&fixture, "apply", Some(&witness))
        .output()
        .unwrap();
    assert_eq!(result.status.code(), Some(73), "{result:?}");
    assert!(result.stdout.is_empty(), "{result:?}");
    assert_eq!(
        fs::read(fixture.tree.join("input")).unwrap(),
        b"replacement cache"
    );
    assert_eq!(
        fs::read(retained.join("project/hash/input")).unwrap(),
        b"retain unless fully authorized"
    );
}

#[test]
fn force_resync_preserves_replaced_target_and_refuses_a_symlink_leaf() {
    for substitute_symlink in [false, true] {
        let fixture = Fixture::new();
        let witness = force_resync_witness(&fixture);
        let candidate = fixture.tree.parent().unwrap();
        let retained = fixture.root.join("retained-project");
        fs::rename(candidate, &retained).unwrap();
        if substitute_symlink {
            std::os::unix::fs::symlink(&retained, candidate).unwrap();
        } else {
            fs::create_dir_all(&fixture.tree).unwrap();
            fs::write(fixture.tree.join("input"), b"replacement cache").unwrap();
        }
        let result = force_resync_command(&fixture, "apply", Some(&witness))
            .output()
            .unwrap();
        assert_eq!(result.status.code(), Some(73), "{result:?}");
        assert!(result.stdout.is_empty(), "{result:?}");
        assert_eq!(
            fs::read(retained.join("hash/input")).unwrap(),
            b"retain unless fully authorized"
        );
        assert!(candidate.exists());
        if substitute_symlink {
            let inspected = force_resync_command(&fixture, "inspect", None)
                .output()
                .unwrap();
            assert_eq!(inspected.status.code(), Some(73), "{inspected:?}");
        } else {
            assert_eq!(
                fs::read(fixture.tree.join("input")).unwrap(),
                b"replacement cache"
            );
        }
    }
}

fn invalidation_fixture() -> (tempfile::TempDir, PathBuf, PathBuf, PathBuf) {
    use std::os::unix::fs::PermissionsExt as _;

    let temporary = tempfile::Builder::new()
        .prefix("rch-force-resync-")
        .tempdir()
        .unwrap();
    let root = temporary.path().canonicalize().unwrap();
    let base = root.join("managed ' $HOME α");
    let candidate = base.join("project");
    let registry = root.join("claims");
    fs::create_dir_all(&candidate).unwrap();
    fs::create_dir(&registry).unwrap();
    fs::set_permissions(&registry, fs::Permissions::from_mode(0o700)).unwrap();
    fs::write(candidate.join("output"), b"retain recovery output").unwrap();
    (temporary, base, candidate, registry)
}

fn run_invalidation_fixture(base: &Path, candidate: &Path, registry: &Path) -> Output {
    let script = rch_common::force_resync::remote_invalidation_script(
        candidate,
        base,
        registry.to_str().unwrap(),
    )
    .unwrap();
    Command::new("/bin/sh")
        .args(["-c", &script])
        .env("RCH_WKR_BIN", env!("CARGO_BIN_EXE_rch-wkr"))
        .env_remove("RCH_RECOVERY_RESERVE_FD")
        .env_remove("RCH_LEGACY_SOURCE_CLAIM_REGISTRY")
        .output()
        .unwrap()
}

#[test]
fn invalidation_preserves_active_pending_and_retained_recovery_trees() {
    use sha2::{Digest as _, Sha256};

    for (extension, scope) in [
        ("claim", "exact"),
        ("claim", "ancestor"),
        ("claim", "descendant"),
        ("pending", "exact"),
        ("pending", "descendant"),
    ] {
        let (_temporary, base, candidate, registry) = invalidation_fixture();
        let path = match scope {
            "ancestor" => base.clone(),
            "descendant" => candidate.join("nested"),
            _ => candidate.clone(),
        };
        let bytes = format!("{}\n", path.display());
        let digest = format!("{:x}", Sha256::digest(bytes.as_bytes()));
        let record = registry.join(format!("aa.{digest}.{extension}"));
        fs::write(&record, &bytes).unwrap();
        let result = run_invalidation_fixture(&base, &candidate, &registry);
        assert_eq!(
            result.status.code(),
            Some(73),
            "{extension}/{scope}: {result:?}"
        );
        assert!(
            String::from_utf8_lossy(&result.stderr).contains("source-or-retention-1"),
            "{result:?}"
        );
        assert_eq!(fs::read(&record).unwrap(), bytes.as_bytes());
        assert_eq!(
            fs::read(candidate.join("output")).unwrap(),
            b"retain recovery output"
        );
        assert!(!String::from_utf8_lossy(&result.stdout).contains("RCH_SYNC_INVALIDATED"));
    }
    for marker in [".rch-retention-v1", ".sbh-protect"] {
        let (_temporary, base, candidate, registry) = invalidation_fixture();
        let marker = base.join(marker);
        fs::write(&marker, b"retain").unwrap();
        let result = run_invalidation_fixture(&base, &candidate, &registry);
        assert_eq!(result.status.code(), Some(73), "{result:?}");
        assert!(
            String::from_utf8_lossy(&result.stderr).contains("source-or-retention-3"),
            "{result:?}"
        );
        assert_eq!(fs::read(&marker).unwrap(), b"retain");
        assert_eq!(
            fs::read(candidate.join("output")).unwrap(),
            b"retain recovery output"
        );
    }
}

#[test]
fn invalidation_refuses_symlinked_base_or_leaf_without_following_it() {
    for substitute_base in [false, true] {
        let (temporary, base, candidate, registry) = invalidation_fixture();
        let original = if substitute_base { &base } else { &candidate };
        let retained = temporary.path().join("retained-original");
        fs::rename(original, &retained).unwrap();
        std::os::unix::fs::symlink(&retained, original).unwrap();
        let result = run_invalidation_fixture(&base, &candidate, &registry);
        assert_eq!(result.status.code(), Some(73), "{result:?}");
        assert!(fs::symlink_metadata(original).unwrap().is_symlink());
        assert_eq!(
            fs::read(candidate.join("output")).unwrap(),
            b"retain recovery output"
        );
        assert!(!String::from_utf8_lossy(&result.stdout).contains("RCH_SYNC_INVALIDATED"));
    }
}

#[test]
fn invalidation_absence_is_not_a_confirmed_removal() {
    let (_temporary, base, _candidate, registry) = invalidation_fixture();
    let absent = base.join("missing-project");
    let result = run_invalidation_fixture(&base, &absent, &registry);
    assert!(result.status.success(), "{result:?}");
    assert_eq!(result.stdout, b"RCH_SYNC_INVALIDATED absent\n");
    assert_eq!(fs::read_dir(&registry).unwrap().count(), 0);
}
