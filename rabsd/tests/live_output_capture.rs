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
use rabsd::edge::live_facts::{FactsMiss, LiveFacts};
use rabsd::janitor::store::{LiveCas, mount_and_reconcile};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

/// Script only the two identity probes. The actual LiveFacts observer reads
/// these files and retains their generations; no compiler execution is claimed.
fn write_toolchain(root: &Path) -> PathBuf {
    std::fs::create_dir_all(root.join("bin")).unwrap();
    std::fs::create_dir_all(root.join("lib/rustlib/fixture-host/lib")).unwrap();
    std::fs::write(root.join("lib/libdriver.so"), b"runtime-v1").unwrap();
    std::fs::write(
        root.join("lib/rustlib/fixture-host/lib/libcore.rlib"),
        b"core-v1",
    )
    .unwrap();
    let compiler = root.join("bin/rustc");
    std::fs::write(
        &compiler,
        br#"#!/bin/sh
case "$*" in
    '-vV') printf 'rustc fixture\nhost: x86_64-unknown-linux-gnu\nLLVM version: fixture\n' ;;
    '--print sysroot') printf '%s\n' "${0%/bin/rustc}" ;;
    *) exit 64 ;;
esac
"#,
    )
    .unwrap();
    std::fs::set_permissions(&compiler, std::fs::Permissions::from_mode(0o700)).unwrap();
    compiler
}

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
        let compiler = write_toolchain(&dir.path().join("toolchain"));
        let mut argv: Vec<String> = [
            compiler.to_str().unwrap(),
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

    fn compiler(&self) -> &Path {
        Path::new(&self.argv[0])
    }

    fn toolchain_root(&self) -> &Path {
        self.compiler().parent().unwrap().parent().unwrap()
    }

    fn toolchain_facts(&self) -> ToolchainFacts {
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            match self.facts.toolchain(self.compiler(), &self.env) {
                Ok(toolchain) => return toolchain,
                Err(FactsMiss::Pending) => {
                    assert!(Instant::now() < deadline, "fixture toolchain did not warm");
                    std::thread::sleep(Duration::from_millis(5));
                }
                Err(error) => panic!("fixture toolchain: {error}"),
            }
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
        let toolchain = self.toolchain_facts();
        let toolchain_guard = self
            .facts
            .toolchain_guard(self.compiler(), &toolchain)
            .unwrap();
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
            toolchain: toolchain_guard,
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

fn change_toolchain(fixture: &Fixture, mutation: &str) {
    let root = fixture.toolchain_root();
    match mutation {
        "runtime" => std::fs::write(root.join("lib/libdriver.so"), b"runtime-v2").unwrap(),
        "target" => {
            let target = root.join("lib/rustlib/new-target/lib");
            std::fs::create_dir_all(&target).unwrap();
            std::fs::write(target.join("libcore.rlib"), b"another target").unwrap();
        }
        "compiler" => {
            let retained = root.parent().unwrap().join("retained-compiler");
            std::fs::rename(fixture.compiler(), &retained).unwrap();
            std::fs::copy(&retained, fixture.compiler()).unwrap();
        }
        _ => panic!("unknown fixture mutation"),
    }
}

#[test]
fn changed_toolchain_is_refused_before_live_admission_without_output_writes() {
    for mutation in ["runtime", "target", "compiler"] {
        let fixture = Fixture::new();
        let request = fixture.request();
        let key = request.key.action_key.clone();
        change_toolchain(&fixture, mutation);
        request.package.verify_unchanged(&fixture.package).unwrap();
        request.dependencies.verify_unchanged().unwrap();
        assert!(matches!(
            fixture.lane.decide(request),
            LiveDecision::PassThrough(reason) if reason.contains("toolchain inputs changed")
        ));
        assert!(fixture.published(&key).is_none());
        assert!(fixture.coord.submitted_actor(&key).unwrap().is_none());
        assert_eq!(std::fs::read_dir(&fixture.out).unwrap().count(), 0);
    }
}

#[test]
fn changed_toolchain_cannot_publish_success_from_an_admitted_compiler() {
    for mutation in ["runtime", "target", "compiler"] {
        let fixture = Fixture::new();
        let attempt = fixture.begin();
        let key = attempt.action_key().clone();
        fixture.outputs();
        change_toolchain(&fixture, mutation);
        let report = success();
        let error = attempt.capture(&report).unwrap_err();
        assert!(error.contains("toolchain inputs changed"), "{error}");
        assert!(fixture.published(&key).is_none());
        assert!(fixture.coord.submitted_actor(&key).unwrap().is_none());
        assert_eq!(report.exit_code, Some(0));
        assert_eq!(
            std::fs::read(fixture.out.join("libfoo-123.rmeta")).unwrap(),
            b"original metadata fixture"
        );
        // The failure retires only this attempt. A freshly observed toolchain
        // can admit a new invocation rather than leave a stuck flight.
        drop(fixture.begin());
    }
}

#[test]
fn an_old_attempt_cannot_adopt_a_rewarmed_equal_byte_toolchain() {
    let fixture = Fixture::new();
    let before = fixture.toolchain_facts();
    let attempt = fixture.begin();
    let key = attempt.action_key().clone();
    fixture.outputs();
    change_toolchain(&fixture, "compiler");
    assert_eq!(fixture.toolchain_facts(), before);
    let fresh = fixture.request();
    assert_eq!(
        fresh.key.action_key, key,
        "canonical input bytes are identical"
    );
    fresh
        .toolchain
        .verify_unchanged(fixture.compiler())
        .unwrap();
    assert!(
        attempt
            .capture(&success())
            .unwrap_err()
            .contains("toolchain inputs changed")
    );
    assert!(fixture.published(&key).is_none());
    assert!(matches!(
        fixture.lane.decide(fresh),
        LiveDecision::Execute(_)
    ));
}

#[test]
fn immutable_capture_publishes_without_reopening_a_replaced_toolchain() {
    let fixture = Fixture::new();
    let captured = fixture.capture();
    let key = captured.action_key().clone();
    let manifest = captured.manifest_key().to_owned();
    let retained = fixture
        .toolchain_root()
        .with_file_name("retained-toolchain");
    std::fs::rename(fixture.toolchain_root(), &retained).unwrap();
    assert!(!fixture.compiler().exists());
    let (outcome, known) = captured.publish();
    assert_eq!(outcome, CompletionOutcome::Committed);
    assert_eq!(fixture.published(&key), Some(manifest));
    assert_eq!(known.len(), 1);
    assert!(fixture.coord.submitted_actor(&key).unwrap().is_none());
    assert!(
        !fixture.compiler().exists(),
        "publication must not repair the toolchain"
    );
}

#[test]
fn a_guard_for_one_compiler_cannot_admit_another_compiler_path() {
    let fixture = Fixture::new();
    let mut request = fixture.request();
    let key = request.key.action_key.clone();
    request.plan.compiler = fixture
        .compiler()
        .with_file_name("another-rustc")
        .to_str()
        .unwrap()
        .to_owned();
    assert!(matches!(
        fixture.lane.decide(request),
        LiveDecision::PassThrough(reason) if reason.contains("different compiler")
    ));
    assert!(fixture.published(&key).is_none());
    assert!(fixture.coord.submitted_actor(&key).unwrap().is_none());
}

fn linked_fixture() -> Fixture {
    let mut fixture = Fixture::new();
    *fixture
        .argv
        .iter_mut()
        .find(|arg| arg.as_str() == "--emit=metadata,dep-info")
        .unwrap() = "--emit=dep-info,metadata,link".to_owned();
    fixture
}

/// Real files large enough to cross the streaming buffer boundary, not a
/// claim that these fixture bytes are a valid rustc archive.
fn linked_outputs(fixture: &Fixture) -> Vec<u8> {
    fixture.outputs();
    let archive = (0_u8..=255)
        .cycle()
        .take(2 * 64 * 1024 + 7)
        .collect::<Vec<_>>();
    std::fs::write(fixture.out.join("libfoo-123.rlib"), &archive).unwrap();
    archive
}

fn gc_candidates(fixture: &Fixture) -> Vec<String> {
    use rabs_cas::gc::{GcMode, GcWorld, plan_gc};
    plan_gc(
        &mut *fixture.cas.store().lock().unwrap(),
        &GcWorld {
            reclaim_budget: 1000,
            reconciliation_complete: true,
            ..GcWorld::default()
        },
        GcMode::Emergency,
        u64::MAX / 2,
    )
    .unwrap()
    .reclaim
    .into_iter()
    .map(|location| location.object_key)
    .collect()
}

#[test]
fn streamed_multiple_outputs_publish_only_as_one_complete_immutable_result() {
    let fixture = linked_fixture();
    let attempt = fixture.begin();
    let key = attempt.action_key().clone();
    let archive = linked_outputs(&fixture);
    let expected = [
        ("libfoo-123.rmeta", b"original metadata fixture".as_slice()),
        ("libfoo-123.rlib", archive.as_slice()),
    ]
    .map(|(name, bytes)| {
        (
            name,
            digest_set(bytes, DigestRequest::default(), None)
                .unwrap()
                .atp_content_id,
        )
    });
    let captured = attempt.capture(&success()).unwrap();
    assert!(fixture.published(&key).is_none());
    let candidates = gc_candidates(&fixture);
    for (_, digest) in &expected {
        assert!(
            fixture
                .cas
                .store()
                .lock()
                .unwrap()
                .object_durably_located(digest)
                .unwrap()
        );
        assert!(!candidates.contains(&rabs_cas::metadata_store::digest_key(digest)));
    }
    let manifest = captured.manifest_key().to_owned();
    std::fs::rename(&fixture.out, fixture.out.with_file_name("captured-outputs")).unwrap();
    let (outcome, known) = captured.publish();
    assert_eq!(outcome, CompletionOutcome::Committed);
    assert_eq!(fixture.published(&key), Some(manifest));
    assert_eq!(known.len(), expected.len());
    for (name, digest) in &expected {
        let output = known
            .iter()
            .find(|output| output.path == fixture.out.join(name))
            .unwrap();
        assert_eq!(&output.digest, digest);
        let stored = fixture
            .cas
            .store()
            .lock()
            .unwrap()
            .object_locations(digest)
            .unwrap()[0]
            .0
            .clone();
        assert_eq!(
            rabsd::edge::live_facts::digest_stable(Path::new(&stored))
                .unwrap()
                .1,
            *digest
        );
    }
    assert!(
        !fixture.out.exists(),
        "publication must not reopen or recreate outputs"
    );
    assert!(fixture.coord.submitted_actor(&key).unwrap().is_none());
}

#[test]
fn missing_later_output_retires_streamed_attempt_without_partial_publication() {
    let fixture = linked_fixture();
    let request = fixture.request();
    let declared = request.plan.output_names();
    let capture_order = request
        .plan
        .outputs
        .declarations
        .iter()
        .map(|declaration| declaration.virtual_path.clone())
        .collect::<Vec<_>>();
    assert_eq!(declared.len(), 3);
    let key = request.key.action_key.clone();
    let LiveDecision::Execute(attempt) = fixture.lane.decide(request) else {
        panic!("expected an admitted multi-output attempt");
    };
    linked_outputs(&fixture);
    // Omit the last DECLARED artifact so the real capture must already have
    // staged and pinned at least one native output before the later failure.
    let missing = fixture.out.join(capture_order.last().unwrap());
    let retained = fixture.out.with_file_name("retained-missing-output");
    std::fs::rename(&missing, &retained).unwrap();
    let earlier = capture_order[..capture_order.len() - 1]
        .iter()
        .filter(|name| name.ends_with(".rlib") || name.ends_with(".rmeta"))
        .map(|name| {
            rabsd::edge::live_facts::digest_stable(&fixture.out.join(name))
                .unwrap()
                .1
        })
        .collect::<Vec<_>>();
    assert!(!earlier.is_empty());
    let report = success();
    assert!(attempt.capture(&report).is_err());
    assert_eq!(report.exit_code, Some(0));
    assert!(fixture.published(&key).is_none());
    assert!(fixture.coord.submitted_actor(&key).unwrap().is_none());
    let candidates = gc_candidates(&fixture);
    for digest in &earlier {
        assert!(
            fixture
                .cas
                .store()
                .lock()
                .unwrap()
                .object_durably_located(digest)
                .unwrap()
        );
        assert!(candidates.contains(&rabs_cas::metadata_store::digest_key(digest)));
    }
    assert_eq!(
        std::fs::read_dir(fixture.cas.layout().root().join("staging"))
            .unwrap()
            .count(),
        0
    );
    // A later complete invocation owns a fresh attempt; the earlier failure
    // cannot strand singleflight or leave released capture pins reusable.
    std::fs::rename(&retained, &missing).unwrap();
    let (outcome, known) = fixture.begin().complete(&success());
    assert_eq!(outcome, CompletionOutcome::Committed);
    assert_eq!(known.len(), 2);
    assert!(fixture.published(&key).is_some());
}
