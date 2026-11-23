//! Live local-output capture against the real coordinator, actor and CAS.
//!
//! Artifact bytes and toolchain identity are fixtures, not a rustc execution
//! proof. These tests exercise the actual admission/capture/publication seam:
//! no pointer before publication, immutable bytes after capture, and exact
//! attempt cleanup when the subscriber never authorizes the captured result,
//! and transcript quarantine enforcement through every replay frontier.
#![cfg(target_os = "linux")]

use rabs_cas::blob_store::RAW_PROFILE_V1;
use rabs_cas::digest_set::{DigestRequest, digest_set};
use rabs_cas::metadata_store::{
    QuarantineScope, RabsMetadataStore, RusqliteEngine, SqlEngine, SqlValue, digest_key,
};
use rabs_key::live_dependency::{
    LiveRustcRequest, ToolchainFacts, canonicalize_compiler_transcript, live_dependency_key,
    plan_dependency_action,
};
use rabs_protocol::input_evidence::{
    ActionInputManifest, INPUT_EVIDENCE_SCHEMA_VERSION, InputFileType, PositiveInput,
};
use rabs_protocol::raw_bytes::RawBytes;
use rabs_protocol::result_identity::{ObjectId, TypedDigest};
use rabsd::coord::live::CoordLive;
use rabsd::coord::live_dependency::{
    CapturedLocalAttempt, CompletionOutcome, CompletionReport, InstallResult,
    LIVE_TRANSCRIPT_RECEIPT, LiveDecision, LiveDependencyLane, LiveDependencyRequest, LocalAttempt,
    MAX_TRANSCRIPT_BYTES, PendingServe,
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
    /// Inject durable faults through a separate connection to this fixture's
    /// private database. Keep the live store locked while changing its rows;
    /// production callers retain only the transactional metadata API.
    fn inject_metadata_fault(&self, sql: &str, params: &[SqlValue]) -> usize {
        let _store = self.cas.store().lock().unwrap();
        let mut engine = RusqliteEngine::open(&self.cas.cas_root().join("meta.sqlite")).unwrap();
        engine.execute(sql, params).unwrap()
    }

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
            canonical_paths: None,
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

    /// Earn the normal replay allowance through independent admitted attempts.
    /// These are scripted identity/artifact fixtures, not real rustc or fleet
    /// evidence; all capture, comparison and publication code is production.
    fn replayable() -> (Self, CompletionReport, TypedDigest) {
        let mut fixture = Self::new();
        fixture.argv.push("--json=artifacts".into());
        let report = CompletionReport {
            stderr: format!(
                "{{\"$message_type\":\"artifact\",\"artifact\":\"{}/foo-123.d\",\"emit\":\"dep-info\"}}\n\
                 {{\"$message_type\":\"artifact\",\"artifact\":\"{}/libfoo-123.rmeta\",\"emit\":\"metadata\"}}\n\
                 fixture diagnostic after metadata\n",
                fixture.out.display(),
                fixture.out.display(),
            )
            .into_bytes(),
            ..success()
        };
        let canonical =
            canonicalize_compiler_transcript(&report.stderr, &fixture.request().plan).unwrap();
        let transcript = digest_set(&canonical, DigestRequest::default(), None)
            .unwrap()
            .atp_content_id;
        for expected in [
            CompletionOutcome::Committed,
            CompletionOutcome::Verified,
            CompletionOutcome::Verified,
        ] {
            let attempt = fixture.begin();
            fixture.outputs();
            assert_eq!(attempt.capture(&report).unwrap().publish().0, expected);
        }
        // Every replay assertion starts from an empty destination. Retain the
        // originally captured files so refusing a hit cannot be mistaken for
        // successfully reinstalling files left by the fixture executions.
        std::fs::rename(
            &fixture.out,
            fixture.out.with_file_name("retained-local-outputs"),
        )
        .unwrap();
        std::fs::create_dir_all(&fixture.out).unwrap();
        (fixture, report, transcript)
    }

    fn hit(&self) -> PendingServe {
        match self.lane.decide(self.request()) {
            LiveDecision::Hit(pending) => pending,
            other => panic!("earned replay did not preview a hit: {other:?}"),
        }
    }

    fn quarantine_transcript(&self, transcript: &TypedDigest) {
        self.cas
            .store()
            .lock()
            .unwrap()
            .add_quarantine(
                QuarantineScope::LogicalObject,
                &digest_key(transcript),
                "unresolved transcript fixture incident",
            )
            .unwrap();
    }

    fn transcript_replica(&self, transcript: &TypedDigest) -> (String, PathBuf, Vec<u8>) {
        let primary = self
            .cas
            .store()
            .lock()
            .unwrap()
            .object_locations(transcript)
            .unwrap()[0]
            .0
            .clone();
        let bytes = std::fs::read(&primary).unwrap();
        // The primary sorts before this replica, exercising refusal/failover
        // rather than accidentally succeeding on the healthy copy first.
        let replica = self.cas.cas_root().join("zz-transcript-replica");
        std::fs::write(&replica, &bytes).unwrap();
        self.cas
            .store()
            .lock()
            .unwrap()
            .add_location(
                transcript,
                replica.to_str().unwrap(),
                Some(1),
                RAW_PROFILE_V1,
                false,
            )
            .unwrap();
        assert!(primary.as_str() < replica.to_str().unwrap());
        (primary, replica, bytes)
    }

    fn assert_no_outputs(&self) {
        assert_eq!(std::fs::read_dir(&self.out).unwrap().count(), 0);
    }
}

/// Isolate the process-wide policy memo without unsafe environment mutation.
/// Fixed sampling is the production default; the fixture earns both required
/// comparisons. The deadline also turns a callback/store-lock deadlock into a
/// test failure rather than hanging the entire integration-test binary.
fn run_with_fixed_sampling(test_name: &str) -> bool {
    const CHILD: &str = "RABS_TRANSCRIPT_REPLAY_TEST_CHILD";
    if std::env::var(CHILD).ok().as_deref() == Some(test_name) {
        return false;
    }
    let mut command = std::process::Command::new(std::env::current_exe().unwrap());
    for (name, _) in std::env::vars_os() {
        if name.as_encoded_bytes().starts_with(b"RABS_") {
            command.env_remove(name);
        }
    }
    let mut child = command
        .args(["--exact", test_name, "--nocapture"])
        .env(CHILD, test_name)
        .env("RABS_SPRT_SAMPLING", "0")
        .stdin(std::process::Stdio::null())
        .spawn()
        .unwrap();
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        if let Some(status) = child.try_wait().unwrap() {
            assert!(
                status.success(),
                "transcript fixture child failed: {status}"
            );
            return true;
        }
        if Instant::now() >= deadline {
            child.kill().unwrap();
            child.wait().unwrap();
            panic!("transcript fixture exceeded its deadline: {test_name}");
        }
        std::thread::sleep(Duration::from_millis(10));
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
fn transcript_replay_quarantines_bad_replicas_and_replays_the_verified_copy() {
    if run_with_fixed_sampling(
        "transcript_replay_quarantines_bad_replicas_and_replays_the_verified_copy",
    ) {
        return;
    }
    for (replacement, quarantined) in [
        (b"corrupt transcript fixture".to_vec(), true),
        (vec![b'x'; MAX_TRANSCRIPT_BYTES + 1], false),
    ] {
        let (fixture, report, transcript) = Fixture::replayable();
        let (primary, replica, canonical) = fixture.transcript_replica(&transcript);
        let original_locations = fixture
            .cas
            .store()
            .lock()
            .unwrap()
            .object_locations(&transcript)
            .unwrap();
        std::fs::write(&primary, &replacement).unwrap();
        let pending = fixture.hit();
        fixture.assert_no_outputs();
        let mut replayed = Vec::new();
        let result = pending.install_with_metadata(|prefix| {
            // Both the lane's transcript recheck and the subscriber callback
            // need the store. Neither may run beneath the materializer lock.
            assert!(fixture.cas.store().try_lock().is_ok());
            assert_eq!(
                std::fs::read(fixture.out.join("libfoo-123.rmeta")).unwrap(),
                b"original metadata fixture"
            );
            replayed.extend_from_slice(prefix);
            Ok(())
        });
        let InstallResult::Served {
            transcript: suffix,
            installed,
        } = result
        else {
            panic!("healthy transcript replica did not replay: {result:?}");
        };
        assert!(!replayed.is_empty(), "metadata prefix was not delivered");
        replayed.extend_from_slice(&suffix);
        assert_eq!(replayed, report.stderr);
        assert_eq!(installed.len(), 1);
        assert_eq!(std::fs::read(&primary).unwrap(), replacement);
        assert_eq!(std::fs::read(&replica).unwrap(), canonical);
        let mut store = fixture.cas.store().lock().unwrap();
        assert_eq!(
            store.object_locations(&transcript).unwrap(),
            if quarantined {
                vec![(
                    replica.to_str().unwrap().to_owned(),
                    RAW_PROFILE_V1.into(),
                    false,
                )]
            } else {
                // This reader never computed the over-limit copy's complete
                // digest. A bound refusal must not claim corruption.
                original_locations
            }
        );
        assert_eq!(
            store
                .query(
                    "SELECT quarantined FROM object_locations WHERE object_key = ?1 AND store_path = ?2",
                    &[SqlValue::Text(digest_key(&transcript)), SqlValue::Text(primary)],
                )
                .unwrap(),
            vec![vec![SqlValue::Int(i64::from(quarantined))]]
        );
        assert!(
            store
                .query(
                    "SELECT 1 FROM quarantines WHERE scope = 'logical-object' AND subject = ?1",
                    &[SqlValue::Text(digest_key(&transcript))],
                )
                .unwrap()
                .is_empty(),
            "one corrupt replica must not quarantine the healthy logical object"
        );
    }
}

#[test]
fn logical_transcript_quarantine_blocks_preview_with_either_hex_spelling() {
    if run_with_fixed_sampling(
        "logical_transcript_quarantine_blocks_preview_with_either_hex_spelling",
    ) {
        return;
    }
    for uppercase in [false, true] {
        let (fixture, _, transcript) = Fixture::replayable();
        // Prove the unchanged publication is eligible before introducing the
        // quarantine. Merely lacking evidence must not explain the refusal.
        let pending = fixture.hit();
        let key = pending.action_key().clone();
        let manifest = pending.manifest_key().to_owned();
        drop(pending);
        if uppercase {
            let canonical = digest_key(&transcript);
            let (domain, hex) = canonical.rsplit_once(':').unwrap();
            let alternate = format!("{domain}:{}", hex.to_ascii_uppercase());
            assert_ne!(canonical, alternate);
            let changed = fixture.inject_metadata_fault(
                "UPDATE decision_receipts SET decision = ?1 WHERE kind = ?2 AND subject = ?3 AND seq = 0",
                &[
                    SqlValue::Text(alternate),
                    SqlValue::Text(LIVE_TRANSCRIPT_RECEIPT.into()),
                    SqlValue::Text(digest_key(&key)),
                ],
            );
            assert_eq!(changed, 1, "fixture transcript receipt was not replaced");
        }
        fixture.quarantine_transcript(&transcript);
        match fixture.lane.decide(fixture.request()) {
            LiveDecision::Execute(attempt) => drop(attempt),
            other => panic!("quarantined transcript must require fresh execution: {other:?}"),
        }
        assert_eq!(fixture.published(&key), Some(manifest));
        fixture.assert_no_outputs();
    }
}

#[test]
fn logical_transcript_quarantine_revokes_an_already_previewed_hit() {
    if run_with_fixed_sampling("logical_transcript_quarantine_revokes_an_already_previewed_hit") {
        return;
    }
    for metadata in [false, true] {
        let (fixture, _, transcript) = Fixture::replayable();
        let pending = fixture.hit();
        fixture.quarantine_transcript(&transcript);
        let result = if metadata {
            pending.install_with_metadata(|_| panic!("quarantined bytes reached the subscriber"))
        } else {
            pending.install()
        };
        assert!(
            matches!(result, InstallResult::Declined(ref reason) if reason.contains("transcript")),
            "revocation before installation must decline without writes: {result:?}"
        );
        fixture.assert_no_outputs();
    }
}

#[test]
fn transcript_quarantine_after_staging_prevents_metadata_and_terminal_replay() {
    if run_with_fixed_sampling(
        "transcript_quarantine_after_staging_prevents_metadata_and_terminal_replay",
    ) {
        return;
    }
    for metadata in [false, true] {
        let (fixture, _, transcript) = Fixture::replayable();
        let pending = fixture.hit();
        // Inject a real store mutation at the post-staging install receipt,
        // after the lane's initial check but before destination publication.
        // This exercises the actual callback/final-delivery boundaries without
        // relying on filesystem timing or a production-only test hook.
        fixture.inject_metadata_fault(
            &format!(
                "CREATE TRIGGER quarantine_transcript_on_install AFTER INSERT ON decision_receipts \
                 WHEN NEW.kind = 'rabs-live-replay-install-v1' BEGIN \
                 INSERT INTO quarantines (scope, subject, reason) \
                 VALUES ('logical-object', '{}', 'fixture post-staging quarantine'); END",
                digest_key(&transcript),
            ),
            &[],
        );
        let result = if metadata {
            pending.install_with_metadata(|_| panic!("post-staging quarantine leaked a prefix"))
        } else {
            pending.install()
        };
        let refused = match &result {
            InstallResult::ExposedFault(reason) if metadata => reason.contains("transcript"),
            InstallResult::Fault(reason) if !metadata => reason.contains("transcript"),
            _ => false,
        };
        assert!(
            refused,
            "quarantine did not fence transcript delivery: {result:?}"
        );
        assert_eq!(
            std::fs::read(fixture.out.join("libfoo-123.rmeta")).unwrap(),
            b"original metadata fixture",
            "the refusal must preserve the actual installed frontier"
        );
        assert_eq!(
            fixture
                .cas
                .store()
                .lock()
                .unwrap()
                .query(
                    "SELECT reason FROM quarantines WHERE scope = 'logical-object' AND subject = ?1",
                    &[SqlValue::Text(digest_key(&transcript))],
                )
                .unwrap(),
            vec![vec![SqlValue::Text("fixture post-staging quarantine".into())]]
        );
    }
}

#[test]
fn transcript_quarantine_during_metadata_ack_prevents_terminal_success() {
    if run_with_fixed_sampling(
        "transcript_quarantine_during_metadata_ack_prevents_terminal_success",
    ) {
        return;
    }
    let (fixture, report, transcript) = Fixture::replayable();
    let pending = fixture.hit();
    let mut replayed = Vec::new();
    let result = pending.install_with_metadata(|prefix| {
        replayed.extend_from_slice(prefix);
        let mut store = fixture
            .cas
            .store()
            .try_lock()
            .expect("callback retained CAS lock");
        store
            .add_quarantine(
                QuarantineScope::LogicalObject,
                &digest_key(&transcript),
                "fixture quarantine while metadata was acknowledged",
            )
            .unwrap();
        Ok(())
    });
    assert_eq!(
        replayed,
        report
            .stderr
            .strip_suffix(b"fixture diagnostic after metadata\n")
            .unwrap()
    );
    assert!(
        matches!(result, InstallResult::ExposedFault(ref reason) if reason.contains("transcript")),
        "an acknowledged prefix cannot authorize success or fallback after quarantine: {result:?}"
    );
}

#[test]
fn transcript_quarantine_store_failure_never_falls_through_to_a_healthy_replica() {
    if run_with_fixed_sampling(
        "transcript_quarantine_store_failure_never_falls_through_to_a_healthy_replica",
    ) {
        return;
    }
    let (fixture, _, transcript) = Fixture::replayable();
    let (primary, replica, canonical) = fixture.transcript_replica(&transcript);
    std::fs::write(&primary, b"corrupt transcript fixture").unwrap();
    fixture.inject_metadata_fault(
        "CREATE TRIGGER refuse_transcript_quarantine BEFORE UPDATE OF quarantined ON object_locations \
         WHEN NEW.quarantined = 1 BEGIN SELECT RAISE(ABORT, 'fixture quarantine unavailable'); END",
        &[],
    );
    let decision = fixture.lane.decide(fixture.request());
    assert!(
        !matches!(decision, LiveDecision::Hit(_)),
        "failed quarantine persistence must not authorize another replica: {decision:?}"
    );
    fixture.assert_no_outputs();
    assert_eq!(
        std::fs::read(&primary).unwrap(),
        b"corrupt transcript fixture"
    );
    assert_eq!(std::fs::read(&replica).unwrap(), canonical);
    assert_eq!(
        fixture
            .cas
            .store()
            .lock()
            .unwrap()
            .object_locations(&transcript)
            .unwrap()
            .len(),
        2
    );
}

#[test]
fn transcript_store_read_failure_revokes_preview_without_destination_writes() {
    if run_with_fixed_sampling(
        "transcript_store_read_failure_revokes_preview_without_destination_writes",
    ) {
        return;
    }
    for table in ["decision_receipts", "quarantines"] {
        let (fixture, _, _) = Fixture::replayable();
        let pending = fixture.hit();
        // Retain the fixture's metadata while making the next lookup fail.
        // Neither an unreadable binding nor an unreadable quarantine index
        // may be interpreted as permission to replay already retained bytes.
        fixture.inject_metadata_fault(
            &format!("ALTER TABLE {table} RENAME TO retained_{table}"),
            &[],
        );
        let result = pending.install_with_metadata(|_| {
            panic!("failed transcript metadata lookup exposed a replay prefix")
        });
        assert!(
            matches!(result, InstallResult::Declined(ref reason) if reason.contains("transcript")),
            "failed {table} lookup must decline before installation: {result:?}"
        );
        fixture.assert_no_outputs();
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

#[test]
fn codegen_cannot_create_an_actor_or_use_an_existing_metadata_publication() {
    let fixture = linked_fixture();
    let request = fixture.request();
    let key = request.key.action_key.clone();
    assert!(matches!(
        fixture.lane.decide(request),
        LiveDecision::PassThrough(reason) if reason.starts_with("LIVE_DEP_CODEGEN_READ_CLOSURE")
    ));
    assert!(fixture.published(&key).is_none());
    assert!(fixture.coord.submitted_actor(&key).unwrap().is_none());
    assert_eq!(std::fs::read_dir(&fixture.out).unwrap().count(), 0);

    let fixture = Fixture::new();
    fixture.outputs();
    let (outcome, _) = fixture.begin().complete(&success());
    assert_eq!(outcome, CompletionOutcome::Committed);
    let mut request = fixture.request();
    let key = request.key.action_key.clone();
    let manifest = fixture.published(&key).unwrap();
    // Even a stale caller holding a known persisted key cannot bypass the
    // current serving gate by attaching a codegen invocation to that key.
    request.plan.invocation.emit.push("link".into());
    assert!(matches!(
        fixture.lane.decide(request),
        LiveDecision::PassThrough(reason) if reason.starts_with("LIVE_DEP_CODEGEN_READ_CLOSURE")
    ));
    assert_eq!(fixture.published(&key).as_deref(), Some(manifest.as_str()));
    assert!(fixture.coord.submitted_actor(&key).unwrap().is_none());
}

/// Real files large enough to cross the streaming buffer boundary, not a
/// claim that these fixture bytes are valid rustc metadata.
fn streamed_outputs(fixture: &Fixture) -> Vec<u8> {
    fixture.outputs();
    let metadata = (0_u8..=255)
        .cycle()
        .take(2 * 64 * 1024 + 7)
        .collect::<Vec<_>>();
    std::fs::write(fixture.out.join("libfoo-123.rmeta"), &metadata).unwrap();
    metadata
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
    let fixture = Fixture::new();
    let attempt = fixture.begin();
    let key = attempt.action_key().clone();
    let metadata = streamed_outputs(&fixture);
    let expected = [("libfoo-123.rmeta", metadata.as_slice())].map(|(name, bytes)| {
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
    let fixture = Fixture::new();
    let request = fixture.request();
    let declared = request.plan.output_names();
    let capture_order = request
        .plan
        .outputs
        .declarations
        .iter()
        .map(|declaration| declaration.virtual_path.clone())
        .collect::<Vec<_>>();
    assert_eq!(declared.len(), 2);
    let key = request.key.action_key.clone();
    let LiveDecision::Execute(attempt) = fixture.lane.decide(request) else {
        panic!("expected an admitted multi-output attempt");
    };
    streamed_outputs(&fixture);
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
    assert_eq!(known.len(), 1);
    assert!(fixture.published(&key).is_some());
}
