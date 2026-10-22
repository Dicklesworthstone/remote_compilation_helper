//! Exercise the real durable queue and source preparation with shared inputs.
//! Worker identities and toolchain pins are structural fixtures. No worker,
//! TLS session, compiler result, or cache publication is claimed by these tests.

use super::*;
use crate::coord::source_delivery::{prepare_source_bundle, prepare_source_template};
use serde_json::json;
use std::collections::BTreeSet;
use std::os::unix::fs::PermissionsExt;
use std::sync::Barrier;

struct Fixture {
    owner: tempfile::TempDir,
    bundle: PathBuf,
    allocated: bool,
}

impl Fixture {
    fn new(allocated: bool) -> Self {
        let owner = tempfile::tempdir().unwrap();
        let root = owner.path().canonicalize().unwrap();
        let source = root.join("source");
        let bundle = root.join("bundle");
        fs::create_dir(&source).unwrap();
        fs::set_permissions(&source, fs::Permissions::from_mode(0o700)).unwrap();
        fs::write(source.join("lib.rs"), b"pub fn value() -> u32 { 42 }\n").unwrap();
        let mut request = json!({
            "kind":"canonical-exec", "request_id":41,
            "program":"/__rabs/toolchain/bin/rustc",
            "toolchain_backing":"/opt/shared-input-fixture",
            "toolchain_identity":{
                "version":"toolchain-dataset-v1", "sha256":"ab".repeat(32),
                "files":1, "bytes":4,
            },
            "source_files":["lib.rs"],
            "args":["lib.rs", "--crate-type", "lib", "--emit", "metadata",
                "-o", "/__rabs/out/compile/libfixture.rmeta"],
            "artifacts":{"unit":"compile", "files":["libfixture.rmeta"]},
            "timeout_ms":10000,
        });
        if allocated {
            request["request_id"] = json!("allocate");
            prepare_source_template(&source, &request, &bundle).unwrap();
        } else {
            prepare_source_bundle(&source, &request, &bundle).unwrap();
        }
        Self {
            owner,
            bundle,
            allocated,
        }
    }

    fn root(&self) -> PathBuf {
        self.owner.path().canonicalize().unwrap()
    }

    fn open(&self) -> Arc<PreparedOperationStore> {
        PreparedOperationStore::open(&self.root().join("operations")).unwrap()
    }

    fn spec(&self, sequence: u16, worker: u16) -> PreparedOperationSpec {
        PreparedOperationSpec {
            id: format!("{sequence:032x}"),
            address: format!("127.0.0.1:{}", 31000 + worker),
            worker: format!("worker-{worker}"),
            worker_spki_sha256: format!("{worker:064x}"),
            bundle: self.bundle.clone(),
            delivery: self.root().join(format!("delivery-{sequence}")),
            output: self.root().join(format!("output-{sequence}")),
        }
    }

    fn submit(
        &self,
        store: &PreparedOperationStore,
        spec: PreparedOperationSpec,
    ) -> OperationStatus {
        if self.allocated {
            store.submit_allocated(spec).unwrap()
        } else {
            store.submit(spec).unwrap()
        }
    }
}

fn no_dispatch(claim: OperationClaim) -> OperationStatus {
    claim
        .finish(OperationOutcome::Failed {
            detail: "fixture stopped before dispatch".into(),
            execution_may_have_run: false,
        })
        .unwrap()
}

#[test]
fn one_captured_template_fills_four_independent_slots_without_rewriting_inputs() {
    let fixture = Fixture::new(true);
    let store = fixture.open();
    let saved = fs::read(fixture.bundle.join("request.json")).unwrap();
    let source = fs::read(fixture.bundle.join("source/lib.rs")).unwrap();
    let mut fingerprints = BTreeSet::new();
    for id in 1..=5 {
        fingerprints.insert(fixture.submit(&store, fixture.spec(id, id)).request_sha256);
    }
    assert_eq!(fingerprints.len(), 1);
    assert_eq!(MAX_RUNNING, 4);
    let mut claims = Vec::new();
    for id in 1..=4 {
        let mut claim = store
            .claim_next()
            .unwrap()
            .expect("independent worker must make progress");
        assert_eq!(claim.spec().id, fixture.spec(id, id).id);
        assert!(claim.needs_request_allocation());
        claim.bind_request_id(500 + u64::from(id)).unwrap();
        assert_eq!(claim.request()["request_id"], 500 + u64::from(id));
        assert_eq!(
            store.status(&claim.spec().id).unwrap().unwrap().attempt,
            1
        );
        claims.push(claim);
    }
    assert!(
        store.claim_next().unwrap().is_none(),
        "the four-owner bound is unchanged"
    );
    let fifth = store.status(&fixture.spec(5, 5).id).unwrap().unwrap();
    assert_eq!(fifth.state, OperationState::Queued);
    assert_eq!(fifth.request_id, None);
    assert_eq!(fifth.attempt, 0);
    assert_eq!(fs::read(fixture.bundle.join("request.json")).unwrap(), saved);
    assert_eq!(
        fs::read(fixture.bundle.join("source/lib.rs")).unwrap(),
        source
    );
    no_dispatch(claims.remove(0));
    let next = store.claim_next().unwrap().unwrap();
    assert_eq!(next.spec().id, fifth.id);
    no_dispatch(next);
    for claim in claims {
        no_dispatch(claim);
    }
}

#[test]
fn numeric_requests_can_share_read_only_inputs_across_distinct_workers() {
    let fixture = Fixture::new(false);
    let store = fixture.open();
    for id in 1..=2 {
        fixture.submit(&store, fixture.spec(id, id));
    }
    let first = store.claim_next().unwrap().unwrap();
    let second = store
        .claim_next()
        .unwrap()
        .expect("numeric bundles are read-only too");
    assert!(!first.needs_request_allocation());
    assert!(!second.needs_request_allocation());
    assert_eq!(first.request(), second.request());
    assert_ne!(first.spec().worker, second.spec().worker);
    assert_ne!(first.spec().delivery, second.spec().delivery);
    assert_ne!(first.spec().output, second.spec().output);
    no_dispatch(first);
    no_dispatch(second);
}

#[test]
fn a_blocked_worker_does_not_serialize_other_workers_using_the_same_inputs() {
    let fixture = Fixture::new(true);
    let store = fixture.open();
    for (id, worker) in [(1, 1), (2, 1), (3, 2)] {
        fixture.submit(&store, fixture.spec(id, worker));
    }
    let first = store.claim_next().unwrap().unwrap();
    let third = store
        .claim_next()
        .unwrap()
        .expect("oldest eligible job must pass a blocked worker");
    assert_eq!(third.spec().id, fixture.spec(3, 2).id);
    let blocked = store.status(&fixture.spec(2, 1).id).unwrap().unwrap();
    assert_eq!(blocked.attempt, 0);
    assert_eq!(blocked.request_id, None);
    no_dispatch(first);
    let second = store.claim_next().unwrap().unwrap();
    assert_eq!(second.spec().id, blocked.id);
    no_dispatch(second);
    no_dispatch(third);
}

#[test]
fn worker_names_pins_and_bound_endpoints_remain_exclusive_during_cancellation() {
    for collision in ["name", "pin", "endpoint", "bound-endpoint"] {
        let fixture = Fixture::new(true);
        let store = fixture.open();
        let mut first = fixture.spec(1, 1);
        let mut second = fixture.spec(2, 2);
        match collision {
            "name" => second.worker = first.worker.clone(),
            "pin" => second.worker_spki_sha256 = first.worker_spki_sha256.clone(),
            "endpoint" => second.address = first.address.clone(),
            "bound-endpoint" => first.address = "127.0.0.1:0".into(),
            _ => unreachable!(),
        }
        fixture.submit(&store, first.clone());
        fixture.submit(&store, second.clone());
        let mut owner = store.claim_next().unwrap().unwrap();
        owner.bind_request_id(600).unwrap();
        if collision == "bound-endpoint" {
            owner.listening(second.address.parse().unwrap()).unwrap();
        }
        assert!(store.claim_next().unwrap().is_none(), "{collision}");
        store.cancel(&first.id).unwrap();
        assert!(owner.cancellation().is_cancelled());
        assert!(
            store.claim_next().unwrap().is_none(),
            "cancellation is not completion"
        );
        assert_eq!(no_dispatch(owner).state, OperationState::Cancelled);
        let next = store.claim_next().unwrap().unwrap();
        assert_eq!(next.spec().id, second.id);
        no_dispatch(next);
    }
}

#[test]
fn changing_the_saved_input_identity_at_the_same_path_does_not_enable_sharing() {
    let fixture = Fixture::new(true);
    let store = fixture.open();
    let first = fixture.submit(&store, fixture.spec(1, 1));
    let path = fixture.bundle.join("request.json");
    let mut changed: Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
    changed["args"]
        .as_array_mut()
        .unwrap()
        .push(json!("--cfg=other_input"));
    fs::write(&path, serde_json::to_vec(&changed).unwrap()).unwrap();
    let second = fixture.submit(&store, fixture.spec(2, 2));
    assert_ne!(first.request_sha256, second.request_sha256);
    let claim = store.claim_next().unwrap().unwrap();
    assert!(
        store.claim_next().unwrap().is_none(),
        "path equality is not input identity"
    );
    no_dispatch(claim);
    let next = store.claim_next().unwrap().unwrap();
    assert_eq!(next.spec().id, second.id);
    no_dispatch(next);
}

#[test]
fn concurrent_claimers_never_exceed_capacity_or_claim_one_job_twice() {
    let fixture = Fixture::new(true);
    let store = fixture.open();
    for id in 1..=8 {
        fixture.submit(&store, fixture.spec(id, id));
    }
    let barrier = Arc::new(Barrier::new(8));
    let claims = std::thread::scope(|scope| {
        let mut handles = Vec::new();
        for _ in 0..8 {
            let store = Arc::clone(&store);
            let barrier = Arc::clone(&barrier);
            handles.push(scope.spawn(move || {
                barrier.wait();
                store.claim_next().unwrap()
            }));
        }
        handles
            .into_iter()
            .filter_map(|handle| handle.join().unwrap())
            .collect::<Vec<_>>()
    });
    assert_eq!(claims.len(), 4);
    let ids: BTreeSet<_> = claims.iter().map(|claim| claim.spec().id.clone()).collect();
    assert_eq!(
        ids,
        (1..=4)
            .map(|id| fixture.spec(id, id).id)
            .collect::<BTreeSet<_>>()
    );
    assert_eq!(store.lock_state().unwrap().active.len(), 4);
    for claim in claims {
        no_dispatch(claim);
    }
    assert!(store.lock_state().unwrap().active.is_empty());
}

#[test]
fn restart_keeps_each_uncertain_execution_and_recovery_bound_to_its_worker() {
    let fixture = Fixture::new(true);
    let store = fixture.open();
    for (id, worker) in [(1, 1), (2, 2), (3, 1), (4, 3)] {
        fixture.submit(&store, fixture.spec(id, worker));
    }
    let mut first = store.claim_next().unwrap().unwrap();
    first.bind_request_id(701).unwrap();
    let first_request = first.request().clone();
    let mut second = store.claim_next().unwrap().unwrap();
    second.bind_request_id(702).unwrap();
    drop((first, second, store));
    let reopened = fixture.open();
    for (id, request_id) in [(1, 701), (2, 702)] {
        let status = reopened.status(&fixture.spec(id, id).id).unwrap().unwrap();
        assert_eq!(status.state, OperationState::Uncertain);
        assert_eq!(status.request_id, Some(request_id));
        assert!(status.execution_may_have_run);
    }
    let independent = reopened.claim_next().unwrap().unwrap();
    assert_eq!(independent.spec().id, fixture.spec(4, 3).id);
    reopened
        .resume(&fixture.spec(1, 1).id, fixture.root().join("resume-1"), None)
        .unwrap();
    let resumed = reopened
        .claim_next()
        .unwrap()
        .expect("result-only recovery may share input reads");
    assert_eq!(resumed.mode(), DeliveryMode::Resume);
    assert_eq!(resumed.request(), &first_request);
    assert!(!resumed.needs_request_allocation());
    assert!(
        reopened.claim_next().unwrap().is_none(),
        "worker 1 still has an unresolved owner"
    );
    no_dispatch(independent);
    assert_eq!(no_dispatch(resumed).state, OperationState::Uncertain);
}

fn replace_path(record: &mut Record, role: usize, path: PathBuf) {
    match role {
        0 => record.spec.bundle = path,
        1 => record.delivery = path,
        2 => record.spec.output = path,
        3 => record.prior_deliveries = vec![path],
        4 => record.resume_from = Some(path),
        _ => unreachable!(),
    }
}

#[test]
fn every_non_bundle_role_retains_symmetric_overlap_protection() {
    let fixture = Fixture::new(true);
    let store = fixture.open();
    for id in 1..=2 {
        fixture.submit(&store, fixture.spec(id, id));
    }
    let state = store.lock_state().unwrap();
    let mut left = state.records[&fixture.spec(1, 1).id].clone();
    let mut right = state.records[&fixture.spec(2, 2).id].clone();
    drop(state);
    for (record, tag) in [(&mut left, "left"), (&mut right, "right")] {
        record.prior_deliveries = vec![fixture.root().join(format!("{tag}-prior"))];
        record.resume_from = Some(fixture.root().join(format!("{tag}-prefix")));
    }
    assert!(!conflicting_active_paths(&left, &right));
    for left_role in 0..5 {
        for right_role in 0..5 {
            for nested in [false, true] {
                let mut candidate = right.clone();
                let path = left.paths()[left_role].to_path_buf();
                replace_path(
                    &mut candidate,
                    right_role,
                    if nested { path.join("child") } else { path },
                );
                let expected = nested || left_role != 0 || right_role != 0;
                assert_eq!(conflicting_active_paths(&left, &candidate), expected);
                assert_eq!(conflicting_active_paths(&candidate, &left), expected);
            }
        }
    }
    let mut changed = right.clone();
    changed.request_sha256 = "ff".repeat(32);
    assert!(conflicting_active_paths(&left, &changed));
    changed = right.clone();
    changed.version = 1;
    assert!(conflicting_active_paths(&left, &changed));
    changed = right;
    changed.spec.bundle = fixture.root().join("bundle-other");
    assert!(
        !conflicting_active_paths(&left, &changed),
        "path components, not string prefixes"
    );
}

#[test]
fn shared_input_admission_never_allows_destinations_to_overlap_retained_state() {
    let fixture = Fixture::new(true);
    let store = fixture.open();
    let first = fixture.spec(1, 1);
    fs::create_dir(&first.delivery).unwrap();
    fs::create_dir(&first.output).unwrap();
    fixture.submit(&store, first.clone());
    for protected in [&first.bundle, &first.delivery, &first.output] {
        for nested in [false, true] {
            for delivery in [false, true] {
                let mut spec = fixture.spec(2, 2);
                let path = if nested {
                    protected.join("child")
                } else {
                    protected.to_path_buf()
                };
                if delivery {
                    spec.delivery = path;
                } else {
                    spec.output = path;
                }
                let error = store.submit_allocated(spec).unwrap_err();
                assert!(error.to_string().contains("overlap"), "{error}");
                assert!(store.status(&fixture.spec(2, 2).id).unwrap().is_none());
            }
        }
    }
    assert_eq!(store.lock_state().unwrap().records.len(), 1);
}
