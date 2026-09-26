//! Actual coordinator, serving gates, CAS and filesystem materialization.
//! Admission/class evidence is synthetic; no test claims automatic Cargo reuse.
#![cfg(unix)]

use std::collections::BTreeSet;
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, UNIX_EPOCH};

use rabs_cas::blob_store::{DurabilityPolicy, PutLimits, put_if_absent};
use rabs_cas::digest_set::{DigestRequest, digest_set};
use rabs_cas::manifest_codec::encode_manifest_v1;
use rabs_cas::metadata_store::{RabsMetadataStore, digest_key};
use rabs_cas::publication::{OfferPreparedActionResult, PublicationOutcome};
use rabs_cas::test_support::{
    FixtureAttemptIds, attempt_authority_for, install_admission_world,
    install_admission_world_with_ids, install_offer_closure, sample_action_key,
    sample_evidence, sample_expected_descriptor, sample_manifest, tagged_digest, tagged_object,
};
use rabs_protocol::generation::{ActionGenerationId, AttemptId, ExecutionLeaseId};
use rabs_protocol::raw_bytes::RawBytes;
use rabs_protocol::result_identity::{LogicalOutput, ObjectId, OutputRole};
use rabsd::coord::live::{CoordLive, ExpectedOutputs, ServeError, ServeOutcome};
use rabsd::janitor::store::{LiveCas, mount_and_reconcile};

const DEP: &[u8] = b"/__rabs/out/unit/libunit.rmeta: /__rabs/workspace/src/lib.rs\n\n/__rabs/workspace/src/lib.rs:\n";

fn put(cas: &LiveCas, bytes: &[u8]) -> ObjectId {
    let object = digest_set(bytes, DigestRequest::default(), None).unwrap().atp_content_id;
    put_if_absent(
        cas.layout(), &mut *cas.store().lock().unwrap(), &object, &mut &bytes[..],
        PutLimits::default(), DurabilityPolicy::FULL,
    ).unwrap();
    ObjectId(object)
}

struct Fixture {
    dir: tempfile::TempDir,
    cas: Arc<LiveCas>,
    coord: Arc<CoordLive>,
    outputs: Vec<LogicalOutput>,
}

impl Fixture {
    fn new(rows: &[(OutputRole, &str, &[u8])]) -> Self {
        // macOS's default temporary directory can contain a /var symlink.
        // The actual serving root deliberately requires a canonical ancestor.
        let temporary_root = std::fs::canonicalize(std::env::temp_dir()).unwrap();
        let dir = tempfile::tempdir_in(temporary_root).unwrap();
        std::fs::create_dir_all(dir.path().join("workspace/src")).unwrap();
        std::fs::write(dir.path().join("workspace/src/lib.rs"), b"pub fn value() {}\n").unwrap();
        let cas = Arc::new(mount_and_reconcile(&dir.path().join("cas")).unwrap());
        let coord = Arc::new(CoordLive::with_cas(Arc::clone(&cas)));
        let authority = coord.acquire_boot_authority("complete-output-fixture").unwrap();
        coord.mark_up();
        let outputs: Vec<_> = rows.iter().map(|(role, name, bytes)| LogicalOutput {
            role: *role, virtual_path: RawBytes::from(*name), object: put(&cas, bytes),
        }).collect();
        let declared: Vec<_> = outputs.iter().map(|out| (out.role, out.virtual_path.clone())).collect();
        let mut manifest = sample_manifest();
        manifest.logical_outputs = outputs.clone();
        let make_offer = |manifest, id: ObjectId| OfferPreparedActionResult::build(
            attempt_authority_for(&authority), manifest, id.clone(), sample_evidence(&id),
            tagged_object(51), tagged_digest("rabs.observation-stream.sha256.v1", 9),
            &declared, Vec::new(),
        ).unwrap();
        let first = make_offer(manifest, tagged_object(50));
        let bytes = encode_manifest_v1(&first.manifest);
        let id = put(&cas, &bytes);
        let offer = make_offer(first.manifest, id);
        assert_eq!(encode_manifest_v1(&offer.manifest), bytes);
        {
            let mut store = cas.store().lock().unwrap();
            install_admission_world(&mut *store, &authority);
            install_offer_closure(&mut *store, &offer);
            store.record_decision_receipt(
                "rabs-live-action-class-v1", &digest_key(&sample_action_key()), 0,
                "rustc-dependency-compile", "synthetic fixture enrollment",
            ).unwrap();
        }
        assert!(matches!(coord.commit_offer(&offer, &sample_expected_descriptor()).unwrap(), PublicationOutcome::Committed(_)));
        // The real edge's verification floor needs two independent comparisons,
        // not a replay of the winning attempt or bypassing its sampling policy.
        for n in 1..=2_u128 {
            let ids = FixtureAttemptIds { generation: 11 + n, attempt: 20 + n, lease: 30 + n };
            install_admission_world_with_ids(&mut *cas.store().lock().unwrap(), &authority, ids);
            let mut compared = offer.clone();
            compared.authority.action_generation.generation_id = ActionGenerationId(ids.generation);
            compared.authority.attempt_id = AttemptId(ids.attempt);
            compared.authority.execution_lease_id = ExecutionLeaseId(ids.lease);
            assert_eq!(coord.commit_offer(&compared, &sample_expected_descriptor()).unwrap(), PublicationOutcome::IdempotentEvidenceAppended);
        }
        Self { dir, cas, coord, outputs }
    }

    fn complete() -> Self {
        Self::new(&[
            (OutputRole::Materializable, "libunit.rlib", b"library\0\xff"),
            (OutputRole::DepInfo, "unit.d", DEP),
            (OutputRole::ProvisionalMetadata, "libunit.rmeta", b"metadata\0\xfe"),
        ])
    }

    fn names(&self) -> BTreeSet<String> {
        self.outputs.iter().map(|out| std::str::from_utf8(out.virtual_path.as_bytes()).unwrap().to_owned()).collect()
    }

    fn expected(&self, root: &Path) -> ExpectedOutputs {
        ExpectedOutputs::WithDepInfo {
            paths: self.names(),
            mappings: vec![
                (b"/__rabs/workspace".to_vec(), self.dir.path().join("workspace").as_os_str().as_bytes().to_vec()),
                (b"/__rabs/out/unit".to_vec(), root.as_os_str().as_bytes().to_vec()),
            ],
        }
    }

    fn serve(&self, root: &Path, expected: &ExpectedOutputs) -> Result<ServeOutcome, ServeError> {
        let now = std::time::SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_micros();
        self.coord.edge_subscriber().serve_action(&sample_action_key(), root, expected, i64::try_from(now).unwrap(), 0)
    }

    fn location(&self, name: &str) -> PathBuf {
        let output = self.outputs.iter().find(|out| out.virtual_path.as_bytes() == name.as_bytes()).unwrap();
        self.cas.store().lock().unwrap().object_locations(&output.object.0).unwrap().into_iter()
            .map(|(path, _, _)| PathBuf::from(path)).find(|path| path.is_file()).unwrap()
    }
}

#[test]
fn two_subscribers_receive_metadata_library_and_correct_private_dep_info() {
    let fixture = Fixture::complete();
    let canonical = fixture.location("unit.d");
    let before = std::fs::read(&canonical).unwrap();
    for target in ["first target#", "second target"] {
        let root = fixture.dir.path().join(target);
        let ServeOutcome::Served { files } = fixture.serve(&root, &fixture.expected(&root)).unwrap() else { panic!("not served"); };
        assert_eq!(files.len(), 3);
        assert_eq!(files[0], root.join("libunit.rmeta"), "metadata must lead the live receipt");
        assert_eq!(std::fs::read(root.join("libunit.rlib")).unwrap(), b"library\0\xff");
        assert_eq!(std::fs::read(root.join("libunit.rmeta")).unwrap(), b"metadata\0\xfe");
        let dep = std::fs::read(root.join("unit.d")).unwrap();
        assert!(!dep.windows(7).any(|window| window == b"/__rabs"));
        let parsed = rabsd::edge::dep_info::parse_dep_info(&dep).unwrap();
        assert!(parsed.lines.iter().any(|line| matches!(line,
            rabsd::edge::dep_info::DepInfoLine::Rule { target, deps }
                if target.as_slice() == root.join("libunit.rmeta").as_os_str().as_bytes()
                    && deps == &vec![fixture.dir.path().join("workspace/src/lib.rs").as_os_str().as_bytes().to_vec()]
        )));
    }
    assert_eq!(std::fs::read(canonical).unwrap(), before, "subscriber paths cannot poison the canonical CAS object");
}

#[test]
fn every_installed_output_respects_a_future_live_input_mtime() {
    let fixture = Fixture::complete();
    let source = fixture.dir.path().join("workspace/src/lib.rs");
    let floor = UNIX_EPOCH + Duration::from_secs(2_000_000_000);
    std::fs::File::options().write(true).open(source).unwrap().set_modified(floor).unwrap();
    let root = fixture.dir.path().join("future-input");
    let ServeOutcome::Served { files } = fixture.serve(&root, &fixture.expected(&root)).unwrap() else { panic!("not served"); };
    for file in files { assert!(std::fs::metadata(file).unwrap().modified().unwrap() >= floor); }
}

#[test]
fn non_utf8_subscriber_input_paths_survive_real_dep_info_installation() {
    use std::os::unix::ffi::OsStringExt;
    let fixture = Fixture::complete();
    let workspace = fixture.dir.path().join(std::ffi::OsString::from_vec(b"workspace-\xff".to_vec()));
    std::fs::create_dir_all(workspace.join("src")).unwrap();
    std::fs::write(workspace.join("src/lib.rs"), b"pub fn value() {}\n").unwrap();
    let root = fixture.dir.path().join("raw-source-target");
    let mut expected = fixture.expected(&root);
    if let ExpectedOutputs::WithDepInfo { mappings, .. } = &mut expected {
        mappings[0].1 = workspace.as_os_str().as_bytes().to_vec();
    }
    assert!(matches!(fixture.serve(&root, &expected).unwrap(), ServeOutcome::Served { .. }));
    let installed = std::fs::read(root.join("unit.d")).unwrap();
    let parsed = rabsd::edge::dep_info::parse_dep_info(&installed).unwrap();
    let wanted = workspace.join("src/lib.rs").as_os_str().as_bytes().to_vec();
    assert!(parsed.lines.iter().any(|line| matches!(line,
        rabsd::edge::dep_info::DepInfoLine::Rule { deps, .. } if deps.contains(&wanted)
    )));
}

#[test]
fn missing_mapping_or_input_refuses_before_the_metadata_head_is_installed() {
    let fixture = Fixture::complete();
    let root = fixture.dir.path().join("no-mapping");
    assert!(matches!(fixture.serve(&root, &ExpectedOutputs::Exactly(fixture.names())), Err(ServeError::Preparation { .. })));
    assert!(!root.exists());
    let root = fixture.dir.path().join("missing-source");
    let mut expected = fixture.expected(&root);
    if let ExpectedOutputs::WithDepInfo { mappings, .. } = &mut expected {
        mappings[0].1 = fixture.dir.path().join("absent-workspace").as_os_str().as_bytes().to_vec();
    }
    assert!(matches!(fixture.serve(&root, &expected), Err(ServeError::Preparation { .. })));
    assert!(!root.exists());
}

#[test]
fn expected_output_interlock_includes_metadata_and_dep_info() {
    let fixture = Fixture::complete();
    let root = fixture.dir.path().join("incomplete-expectation");
    let expected = ExpectedOutputs::Exactly(BTreeSet::from(["libunit.rlib".to_owned()]));
    let ServeOutcome::OutputSetMismatch { missing, unexpected } = fixture.serve(&root, &expected).unwrap() else { panic!("must refuse incomplete expectation"); };
    assert!(missing.is_empty());
    assert_eq!(unexpected, vec!["libunit.rmeta", "unit.d"]);
    assert!(!root.exists());
}

#[test]
fn corrupted_tail_reports_the_metadata_prefix_instead_of_an_untouched_tree() {
    use std::os::unix::fs::PermissionsExt;
    let fixture = Fixture::new(&[
        (OutputRole::Materializable, "a.rlib", b"library"),
        (OutputRole::ProvisionalMetadata, "z.rmeta", b"metadata"),
    ]);
    let tail = fixture.location("a.rlib");
    std::fs::set_permissions(&tail, std::fs::Permissions::from_mode(0o600)).unwrap();
    std::fs::write(tail, b"corrupt").unwrap();
    let root = fixture.dir.path().join("partial");
    let Err(ServeError::Materialize(failure)) = fixture.serve(&root, &ExpectedOutputs::Exactly(fixture.names())) else { panic!("must report partial materialization"); };
    assert_eq!(failure.installed.len(), 1);
    assert_eq!(failure.installed[0].destination, root.join("z.rmeta"));
    assert_eq!(std::fs::read(root.join("z.rmeta")).unwrap(), b"metadata");
    assert!(!root.join("a.rlib").exists());
}

#[test]
fn unsupported_output_roles_cannot_be_silently_dropped() {
    for role in [OutputRole::BuildScriptMetadata, OutputRole::TestSideEffect] {
        let fixture = Fixture::new(&[(role, "metadata", b"not a raw rustc output")]);
        let root = fixture.dir.path().join("unsupported");
        assert!(matches!(fixture.serve(&root, &ExpectedOutputs::Exactly(fixture.names())), Err(ServeError::Preparation { .. })));
        assert!(!root.exists());
    }
}

#[test]
fn symlinked_ancestor_cannot_redirect_installs_outside_the_requested_tree() {
    let fixture = Fixture::complete();
    let outside = fixture.dir.path().join("outside");
    std::fs::create_dir(&outside).unwrap();
    let alias = fixture.dir.path().join("target-alias");
    std::os::unix::fs::symlink(&outside, &alias).unwrap();
    assert!(matches!(fixture.serve(&alias, &fixture.expected(&alias)), Err(ServeError::Preparation { .. })));
    assert_eq!(std::fs::read_dir(outside).unwrap().count(), 0);
}

#[test]
fn mismapped_dep_info_targets_cannot_certify_another_output_tree() {
    let fixture = Fixture::complete();
    let root = fixture.dir.path().join("target");
    let mut expected = fixture.expected(&root);
    if let ExpectedOutputs::WithDepInfo { mappings, .. } = &mut expected {
        mappings[1].1 = fixture.dir.path().join("another-target").as_os_str().as_bytes().to_vec();
    }
    assert!(matches!(fixture.serve(&root, &expected), Err(ServeError::Preparation { .. })));
    assert!(!root.exists());
}

#[test]
fn different_roles_and_ancestor_paths_cannot_claim_overlapping_outputs() {
    for other in ["shared", "shared/nested"] {
        let fixture = Fixture::new(&[
            (OutputRole::Materializable, "shared", b"library"),
            (OutputRole::ProvisionalMetadata, other, b"metadata"),
        ]);
        let root = fixture.dir.path().join("overlap");
        assert!(matches!(fixture.serve(&root, &ExpectedOutputs::Exactly(fixture.names())), Err(ServeError::Preparation { .. })));
        assert!(!root.exists(), "the entire conflicting bundle must refuse before writes");
    }
}

const RELATIVE_DEP: &[u8] = b"target/libunit.rmeta: ./src/lib.rs\n\n./src/lib.rs:\n# env-dep:NAME=unchanged\n";

fn relative_fixture(dep_info: &[u8]) -> Fixture {
    Fixture::new(&[
        (OutputRole::Materializable, "libunit.rlib", b"library\0\xff"),
        (OutputRole::DepInfo, "unit.d", dep_info),
        (OutputRole::ProvisionalMetadata, "libunit.rmeta", b"metadata\0\xfe"),
    ])
}

#[test]
fn relative_dep_info_serves_two_worktrees_without_mutating_the_shared_cas_object() {
    use std::os::unix::ffi::OsStringExt;
    use rabsd::edge::dep_info::{DepInfoLine, parse_dep_info};

    let fixture = relative_fixture(RELATIVE_DEP);
    let canonical = fixture.location("unit.d");
    let before = std::fs::read(&canonical).unwrap();
    let before_mtime = std::fs::metadata(&canonical).unwrap().modified().unwrap();
    let mut deliveries = Vec::new();
    for name in [&b"first worktree#"[..], &b"second worktree-\xff"[..]] {
        let cwd = fixture.dir.path().join(std::ffi::OsString::from_vec(name.to_vec()));
        std::fs::create_dir_all(cwd.join("src")).unwrap();
        let source = cwd.join("src/lib.rs");
        std::fs::write(&source, b"pub fn value() {}\n").unwrap();
        let floor = UNIX_EPOCH + Duration::from_secs(2_000_000_000);
        std::fs::File::options().write(true).open(&source).unwrap()
            .set_modified(floor).unwrap();
        let root = cwd.join("target");
        let expected = ExpectedOutputs::WithDepInfo {
            paths: fixture.names(),
            mappings: vec![(b".".to_vec(), cwd.as_os_str().as_bytes().to_vec())],
        };
        let ServeOutcome::Served { files } = fixture.serve(&root, &expected).unwrap() else {
            panic!("relative dep-info with an explicit cwd was not served");
        };
        assert_eq!(files.len(), 3);
        assert_eq!(files[0], root.join("libunit.rmeta"));
        assert_eq!(std::fs::read(root.join("libunit.rlib")).unwrap(), b"library\0\xff");
        assert_eq!(std::fs::read(root.join("libunit.rmeta")).unwrap(), b"metadata\0\xfe");
        for file in files {
            assert!(std::fs::metadata(file).unwrap().modified().unwrap() >= floor);
        }
        let delivered = std::fs::read(root.join("unit.d")).unwrap();
        assert_eq!(parse_dep_info(&delivered).unwrap().lines, vec![
            DepInfoLine::Rule {
                target: root.join("libunit.rmeta").as_os_str().as_bytes().to_vec(),
                deps: vec![source.as_os_str().as_bytes().to_vec()],
            },
            DepInfoLine::Blank,
            DepInfoLine::Rule {
                target: source.as_os_str().as_bytes().to_vec(), deps: vec![],
            },
            DepInfoLine::Comment(b"# env-dep:NAME=unchanged".to_vec()),
        ]);
        deliveries.push(delivered);
    }
    assert_ne!(deliveries[0], deliveries[1]);
    assert_eq!(std::fs::read(&canonical).unwrap(), before);
    assert_eq!(std::fs::metadata(&canonical).unwrap().modified().unwrap(), before_mtime);
}

#[test]
fn relative_inputs_without_cwd_or_with_missing_source_refuse_before_any_output() {
    let fixture = relative_fixture(
        b"/__rabs/out/unit/libunit.rmeta: src/lib.rs\n\nsrc/lib.rs:\n",
    );
    for absent_cwd in [false, true] {
        let root = fixture.dir.path().join(if absent_cwd { "missing-input" } else { "no-cwd" });
        let mut expected = fixture.expected(&root);
        if absent_cwd
            && let ExpectedOutputs::WithDepInfo { mappings, .. } = &mut expected
        {
            mappings.push((
                b".".to_vec(),
                fixture.dir.path().join("missing-worktree").as_os_str().as_bytes().to_vec(),
            ));
        }
        assert!(matches!(fixture.serve(&root, &expected), Err(ServeError::Preparation { .. })));
        assert!(!root.exists());
    }
}

#[test]
fn relative_parent_traversal_refuses_before_even_the_metadata_head() {
    for dep_info in [
        &b"target/libunit.rmeta: ../outside.rs\n"[..],
        &b"target/libunit.rmeta: src/../lib.rs\n"[..],
        &b"../target/libunit.rmeta: src/lib.rs\n"[..],
    ] {
        let fixture = relative_fixture(dep_info);
        let cwd = fixture.dir.path().join("workspace");
        let root = cwd.join("target");
        let expected = ExpectedOutputs::WithDepInfo {
            paths: fixture.names(),
            mappings: vec![(b".".to_vec(), cwd.as_os_str().as_bytes().to_vec())],
        };
        assert!(matches!(fixture.serve(&root, &expected), Err(ServeError::Preparation { .. })));
        assert!(!root.exists());
    }
}

#[test]
fn relative_targets_cannot_certify_a_different_subscriber_output_tree() {
    let fixture = relative_fixture(RELATIVE_DEP);
    let cwd = fixture.dir.path().join("workspace");
    let root = fixture.dir.path().join("wrong-target");
    let expected = ExpectedOutputs::WithDepInfo {
        paths: fixture.names(),
        mappings: vec![(b".".to_vec(), cwd.as_os_str().as_bytes().to_vec())],
    };
    assert!(matches!(fixture.serve(&root, &expected), Err(ServeError::Preparation { .. })));
    assert!(!root.exists());
    assert!(!cwd.join("target").exists());
}
