//! Live local-output capture against the real coordinator, actor and CAS.
//!
//! Artifact bytes and toolchain identity are fixtures, not a rustc execution
//! proof. These tests exercise the actual admission/capture/publication seam:
//! no pointer before publication, immutable bytes after capture, and exact
//! attempt cleanup when the subscriber never authorizes the captured result.
#![cfg(target_os = "linux")]

use rabs_cas::digest_set::{DigestRequest, digest_set};
use rabs_cas::metadata_store::RabsMetadataStore;
use rabs_key::live_dependency::{
    LiveRustcRequest, ToolchainFacts, live_dependency_key, plan_dependency_action,
};
use rabs_key::typed_digest::compute;
use rabs_protocol::input_evidence::{
    ActionInputManifest, INPUT_EVIDENCE_SCHEMA_VERSION, InputFileType, PositiveInput,
};
use rabs_protocol::raw_bytes::RawBytes;
use rabs_protocol::result_identity::{ObjectId, TypedDigest};
use rabsd::coord::live::CoordLive;
use rabsd::coord::live_dependency::{
    CapturedLocalAttempt, CompletionOutcome, CompletionReport, LiveDecision, LiveDependencyLane,
    LiveDependencyRequest, LocalAttempt,
};
use rabsd::edge::live_facts::LiveFacts;
use rabsd::janitor::store::{LiveCas, mount_and_reconcile};
use std::path::PathBuf;
use std::sync::Arc;

struct Fixture {
    _dir: tempfile::TempDir,
    package: PathBuf,
    out: PathBuf,
    argv: Vec<String>,
    env: Vec<(String, String)>,
    facts: Arc<LiveFacts>,
    cas: Arc<LiveCas>,
    coord: Arc<CoordLive>,
    lane: LiveDependencyLane,
}

impl Fixture {
    fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let cargo = dir.path().join("cargo");
        let package = cargo.join("registry/src/fixture-index/foo-1.0.0");
        let out = dir.path().join("target/debug/deps");
        std::fs::create_dir_all(&package).unwrap();
        std::fs::create_dir_all(&out).unwrap();
        std::fs::write(package.join("lib.rs"), "pub fn answer() -> u32 { 42 }\n").unwrap();
        let mut argv: Vec<String> = [
            "/fixture/toolchain/bin/rustc",
            "--crate-name",
            "foo",
            "--crate-type",
            "lib",
            "--emit=metadata,dep-info",
            "--cap-lints=allow",
            "--error-format=json",
            "-Cextra-filename=-123",
            "--out-dir",
        ]
        .into_iter()
        .map(str::to_owned)
        .collect();
        argv.push(out.to_str().unwrap().to_owned());
        argv.push(package.join("lib.rs").to_str().unwrap().to_owned());
        let env = vec![
            ("CARGO_HOME".into(), cargo.to_str().unwrap().to_owned()),
            (
                "CARGO_MANIFEST_DIR".into(),
                package.to_str().unwrap().to_owned(),
            ),
            ("CARGO_PKG_NAME".into(), "foo".into()),
        ];
        let cas = Arc::new(mount_and_reconcile(&dir.path().join("cas")).unwrap());
        let coord = Arc::new(CoordLive::with_cas(Arc::clone(&cas)));
        coord
            .acquire_boot_authority("live-output-capture-fixture")
            .unwrap();
        coord.mark_up();
        let lane = LiveDependencyLane::new(Arc::clone(&coord));
        Self {
            _dir: dir,
            package,
            out,
            argv,
            env,
            facts: LiveFacts::new(),
            cas,
            coord,
            lane,
        }
    }

    fn request(&self) -> LiveDependencyRequest {
        let plan = plan_dependency_action(
            LiveRustcRequest {
                argv: &self.argv,
                cwd: self.package.to_str().unwrap(),
                env: &self.env,
            },
            "x86_64-unknown-linux-gnu",
        )
        .unwrap();
        let package = self
            .facts
            .package(&self.package, plan.source_kind, None)
            .unwrap();
        let dependencies = self.facts.dependencies(&plan).unwrap();
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
        let toolchain = ToolchainFacts {
            compiler_binary_digest: compute("rabs.tool-binary.v1", b"fixture compiler"),
            verbose_version: "rustc fixture\nhost: x86_64-unknown-linux-gnu\nLLVM version: fixture"
                .into(),
            sysroot_root_digest: compute(
                "rabs.live-dependency.sysroot-tree.v1",
                b"fixture sysroot",
            ),
            runtime_libraries: Vec::new(),
        };
        let key = live_dependency_key(
            &plan,
            &toolchain,
            &[],
            &dependencies.directories,
            None,
            &inputs,
        )
        .unwrap();
        LiveDependencyRequest {
            key,
            plan,
            inputs,
            package,
            dependencies,
            externs: Vec::new(),
        }
    }

    fn begin(&self) -> LocalAttempt {
        match self.lane.decide(self.request()) {
            LiveDecision::Execute(attempt) => attempt,
            other => panic!("expected actual admitted execution, got {other:?}"),
        }
    }

    fn outputs(&self) {
        std::fs::write(
            self.out.join("libfoo-123.rmeta"),
            b"original metadata fixture",
        )
        .unwrap();
        std::fs::write(
            self.out.join("foo-123.d"),
            format!(
                "{}/libfoo-123.rmeta: {}/lib.rs\n\n{}/lib.rs:\n",
                self.out.display(),
                self.package.display(),
                self.package.display(),
            ),
        )
        .unwrap();
    }

    fn capture(&self) -> CapturedLocalAttempt {
        let attempt = self.begin();
        self.outputs();
        attempt.capture(&success()).unwrap()
    }

    fn published(&self, key: &TypedDigest) -> Option<String> {
        self.cas
            .store()
            .lock()
            .unwrap()
            .published_manifest_key(key)
            .unwrap()
    }
}

fn success() -> CompletionReport {
    CompletionReport {
        exit_code: Some(0),
        signal: None,
        stdout: Vec::new(),
        stderr: Vec::new(),
    }
}

#[test]
fn capture_is_durable_but_not_published_and_abandonment_releases_the_flight() {
    let fixture = Fixture::new();
    let captured = fixture.capture();
    let key = captured.action_key().clone();
    assert!(fixture.published(&key).is_none());
    assert!(!captured.manifest_key().is_empty());
    assert_eq!(captured.attempt_hex().len(), 32);
    // Capture holds no store mutex while the connection awaits confirmation.
    assert!(fixture.cas.store().try_lock().is_ok());
    assert!(matches!(
        fixture.lane.decide(fixture.request()),
        LiveDecision::InFlight
    ));
    drop(captured);
    assert!(fixture.published(&key).is_none());
    assert!(fixture.coord.submitted_actor(&key).unwrap().is_none());
    drop(fixture.begin());
}

#[test]
fn publication_uses_captured_bytes_even_after_the_callers_entire_tree_is_replaced() {
    let fixture = Fixture::new();
    let captured = fixture.capture();
    let key = captured.action_key().clone();
    let manifest_key = captured.manifest_key().to_owned();
    let retained = fixture.out.with_file_name("retained-old-outputs");
    std::fs::rename(&fixture.out, &retained).unwrap();
    std::fs::create_dir_all(&fixture.out).unwrap();
    std::fs::write(
        fixture.out.join("libfoo-123.rmeta"),
        b"unrelated later build",
    )
    .unwrap();
    std::fs::write(fixture.package.join("lib.rs"), "pub fn changed() {}\n").unwrap();
    let (outcome, known) = captured.publish();
    assert_eq!(outcome, CompletionOutcome::Committed);
    assert_eq!(fixture.published(&key), Some(manifest_key));
    assert_eq!(known.len(), 1);
    let expected = digest_set(b"original metadata fixture", DigestRequest::default(), None)
        .unwrap()
        .atp_content_id;
    assert_eq!(known[0].digest, expected);
    let locations = fixture
        .cas
        .store()
        .lock()
        .unwrap()
        .object_locations(&expected)
        .unwrap();
    assert!(locations.iter().any(|(path, _, _)| {
        std::fs::read(path).is_ok_and(|bytes| bytes == b"original metadata fixture")
    }));
    assert_eq!(
        std::fs::read(fixture.out.join("libfoo-123.rmeta")).unwrap(),
        b"unrelated later build"
    );
}

#[test]
fn successful_capture_still_uses_the_real_same_key_conflict_gate() {
    let fixture = Fixture::new();
    let first = fixture.capture();
    let key = first.action_key().clone();
    let manifest = first.manifest_key().to_owned();
    assert_eq!(first.publish().0, CompletionOutcome::Committed);
    let next = fixture.begin();
    fixture.outputs();
    std::fs::write(
        fixture.out.join("libfoo-123.rmeta"),
        b"divergent metadata fixture",
    )
    .unwrap();
    assert_eq!(
        next.capture(&success()).unwrap().publish().0,
        CompletionOutcome::Quarantined
    );
    assert_eq!(
        fixture.published(&key),
        Some(manifest),
        "quarantine must not replace publication"
    );
}

#[test]
fn incomplete_or_changed_outputs_never_form_a_publishable_capture() {
    let fixture = Fixture::new();
    let attempt = fixture.begin();
    let key = attempt.action_key().clone();
    std::fs::write(
        fixture.out.join("libfoo-123.rmeta"),
        b"only one of two outputs",
    )
    .unwrap();
    assert!(attempt.capture(&success()).is_err());
    assert!(fixture.published(&key).is_none());
    let attempt = fixture.begin();
    fixture.outputs();
    std::fs::write(
        fixture.package.join("lib.rs"),
        "pub fn changed_during_compile() {}\n",
    )
    .unwrap();
    assert!(attempt.capture(&success()).is_err());
    assert!(fixture.published(&key).is_none());
}

#[test]
fn failed_or_signalled_compilers_cannot_capture_success() {
    for (exit_code, signal, stdout) in [
        (Some(7), None, Vec::new()),
        (None, Some(15), Vec::new()),
        (Some(0), None, b"unexpected stdout".to_vec()),
    ] {
        let fixture = Fixture::new();
        let attempt = fixture.begin();
        let key = attempt.action_key().clone();
        fixture.outputs();
        let report = CompletionReport {
            exit_code,
            signal,
            stdout,
            stderr: Vec::new(),
        };
        assert!(attempt.capture(&report).is_err());
        assert!(fixture.published(&key).is_none());
    }
}
