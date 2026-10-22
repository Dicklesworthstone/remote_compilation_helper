//! Real capture and durable queue tests, without claiming worker execution.
//! Request binding and interrupted owners exercise control-state ownership;
//! these fixtures do not authenticate workers or run a compiler.

use super::*;
use crate::coord::source_delivery::prepare_source_template;
use serde_json::json;
use std::sync::Barrier;

struct Fixture {
    _owner: tempfile::TempDir,
    root: PathBuf,
    bundle: PathBuf,
}

impl Fixture {
    fn new() -> Self {
        let owner = tempfile::tempdir().unwrap();
        let root = owner.path().canonicalize().unwrap();
        let source = root.join("source");
        let bundle = root.join("bundle");
        fs::create_dir(&source).unwrap();
        fs::write(source.join("lib.rs"), b"pub fn value() -> u32 { 42 }\n").unwrap();
        let request = json!({
            "kind":"canonical-exec", "request_id":"allocate",
            "program":"/__rabs/toolchain/bin/rustc",
            "toolchain_backing":"/opt/pool-fixture",
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
        prepare_source_template(&source, &request, &bundle).unwrap();
        Self {
            _owner: owner,
            root,
            bundle,
        }
    }

    fn open(&self) -> Arc<PreparedOperationStore> {
        PreparedOperationStore::open(&self.root.join("operations")).unwrap()
    }

    fn worker(number: u16) -> PreparedWorker {
        PreparedWorker {
            address: format!("127.0.0.1:{}", 32000 + number),
            worker: format!("worker-{number}"),
            worker_spki_sha256: format!("{number:064x}"),
        }
    }

    fn spec(&self, sequence: u16, count: u16) -> PreparedPoolOperationSpec {
        PreparedPoolOperationSpec {
            id: format!("{sequence:032x}"),
            workers: (1..=count).map(Self::worker).collect(),
            bundle: self.bundle.clone(),
            delivery: self.root.join(format!("delivery-{sequence}")),
            output: self.root.join(format!("output-{sequence}")),
        }
    }

    fn singleton(&self, sequence: u16, number: u16) -> PreparedOperationSpec {
        let pool = self.spec(sequence, 1);
        let worker = Self::worker(number);
        PreparedOperationSpec {
            id: pool.id,
            address: worker.address,
            worker: worker.worker,
            worker_spki_sha256: worker.worker_spki_sha256,
            bundle: pool.bundle,
            delivery: pool.delivery,
            output: pool.output,
        }
    }
}

fn no_dispatch(claim: OperationClaim) {
    claim
        .finish(OperationOutcome::Failed {
            detail: "pool fixture stopped before dispatch".into(),
            execution_may_have_run: false,
        })
        .unwrap();
}

fn interrupted(mut claim: OperationClaim, request_id: u64) {
    claim.bind_request_id(request_id).unwrap();
    drop(claim);
}

#[test]
fn pool_balances_queued_jobs_and_fills_four_independent_execution_slots() {
    let fixture = Fixture::new();
    let store = fixture.open();
    let original = fs::read(fixture.bundle.join("request.json")).unwrap();
    for sequence in 1..=8 {
        let status = store
            .submit_allocated_pool(fixture.spec(sequence, 4))
            .unwrap();
        assert_eq!(status.worker, format!("worker-{}", (sequence - 1) % 4 + 1));
        assert_eq!(status.state, OperationState::Queued);
        assert_eq!(status.request_id, None);
    }
    let mut claims = Vec::new();
    for number in 1..=4 {
        let claim = store.claim_next().unwrap().unwrap();
        assert_eq!(claim.spec().worker, format!("worker-{number}"));
        assert!(claim.needs_request_allocation());
        claims.push(claim);
    }
    assert!(store.claim_next().unwrap().is_none());
    no_dispatch(claims.remove(0));
    let next = store.claim_next().unwrap().unwrap();
    assert_eq!(next.spec().id, fixture.spec(5, 4).id);
    assert_eq!(next.spec().worker, "worker-1");
    no_dispatch(next);
    for claim in claims {
        no_dispatch(claim);
    }
    assert_eq!(
        fs::read(fixture.bundle.join("request.json")).unwrap(),
        original
    );
}

#[test]
fn singleton_queued_and_active_owners_contribute_to_pool_load() {
    let fixture = Fixture::new();
    let store = fixture.open();
    store.submit_allocated(fixture.singleton(1, 1)).unwrap();
    let active = store.claim_next().unwrap().unwrap();
    store.submit_allocated(fixture.singleton(2, 1)).unwrap();
    let choices: Vec<_> = (3..=7)
        .map(|sequence| {
            store
                .submit_allocated_pool(fixture.spec(sequence, 3))
                .unwrap()
                .worker
        })
        .collect();
    assert_eq!(
        choices,
        ["worker-2", "worker-3", "worker-2", "worker-3", "worker-1"]
    );
    no_dispatch(active);
}

#[test]
fn concurrent_pool_admission_balances_under_one_durable_placement_lock() {
    let fixture = Fixture::new();
    let store = fixture.open();
    let gate = Arc::new(Barrier::new(16));
    let mut threads = Vec::new();
    for sequence in 1..=16 {
        let store = Arc::clone(&store);
        let gate = Arc::clone(&gate);
        let spec = fixture.spec(sequence, 4);
        threads.push(std::thread::spawn(move || {
            gate.wait();
            store.submit_allocated_pool(spec).unwrap().worker
        }));
    }
    let mut counts = BTreeMap::new();
    for thread in threads {
        *counts.entry(thread.join().unwrap()).or_insert(0) += 1;
    }
    assert_eq!(counts.len(), 4);
    assert!(counts.values().all(|count| *count == 4));
    assert_eq!(store.lock_state().unwrap().records.len(), 16);
}

#[test]
fn same_id_concurrent_retries_keep_one_choice_and_one_queue_position() {
    let fixture = Fixture::new();
    let store = fixture.open();
    let gate = Arc::new(Barrier::new(8));
    let mut threads = Vec::new();
    for _ in 0..8 {
        let store = Arc::clone(&store);
        let gate = Arc::clone(&gate);
        let spec = fixture.spec(1, 2);
        threads.push(std::thread::spawn(move || {
            gate.wait();
            store.submit_allocated_pool(spec).unwrap().worker
        }));
    }
    for thread in threads {
        assert_eq!(thread.join().unwrap(), "worker-1");
    }
    assert_eq!(store.lock_state().unwrap().records.len(), 1);
    assert_eq!(
        store
            .submit_allocated_pool(fixture.spec(2, 2))
            .unwrap()
            .worker,
        "worker-2"
    );
}

#[test]
fn retry_and_restart_keep_selected_worker_after_load_changes_and_id_binding() {
    let fixture = Fixture::new();
    let store = fixture.open();
    let fixed = fixture.singleton(1, 1);
    store.submit_allocated(fixed.clone()).unwrap();
    let spec = fixture.spec(2, 2);
    let initial = store.submit_allocated_pool(spec.clone()).unwrap();
    assert_eq!(initial.worker, "worker-2");
    store.cancel(&fixed.id).unwrap();
    interrupted(store.claim_next().unwrap().unwrap(), 7001);
    let retried = store.submit_allocated_pool(spec.clone()).unwrap();
    assert_eq!(retried.worker, initial.worker);
    assert_eq!(retried.request_sha256, initial.request_sha256);
    assert_eq!(retried.request_id, Some(7001));
    assert_eq!(retried.state, OperationState::Uncertain);
    drop(store);
    let reopened = fixture.open();
    let restarted = reopened.submit_allocated_pool(spec.clone()).unwrap();
    assert_eq!(restarted.worker, "worker-2");
    assert_eq!(restarted.request_id, Some(7001));
    reopened
        .resume(&spec.id, fixture.root.join("resumed-delivery"), None)
        .unwrap();
    let recovery = reopened.claim_next().unwrap().unwrap();
    assert_eq!(recovery.spec().worker, "worker-2");
    assert_eq!(recovery.request()["request_id"], 7001);
    assert!(!recovery.needs_request_allocation());
    drop(recovery);
}

#[test]
fn queued_restart_keeps_selected_worker_when_the_original_load_is_gone() {
    let fixture = Fixture::new();
    let store = fixture.open();
    let fixed = fixture.singleton(1, 1);
    store.submit_allocated(fixed.clone()).unwrap();
    let spec = fixture.spec(2, 2);
    assert_eq!(
        store.submit_allocated_pool(spec.clone()).unwrap().worker,
        "worker-2"
    );
    store.cancel(&fixed.id).unwrap();
    drop(store);
    let reopened = fixture.open();
    let status = reopened.submit_allocated_pool(spec).unwrap();
    assert_eq!(status.worker, "worker-2");
    assert_eq!(status.request_id, None);
    let claim = reopened.claim_next().unwrap().unwrap();
    assert_eq!(claim.spec().worker, "worker-2");
    no_dispatch(claim);
}

#[test]
fn uncertain_admission_write_retains_the_selected_worker_on_restart() {
    let fixture = Fixture::new();
    let store = fixture.open();
    store.submit_allocated(fixture.singleton(1, 1)).unwrap();
    let spec = fixture.spec(2, 2);
    store
        .fail_after_rename
        .store(true, std::sync::atomic::Ordering::SeqCst);
    assert!(store.submit_allocated_pool(spec.clone()).is_err());
    assert!(store.claim_next().is_err());
    drop(store);
    let reopened = fixture.open();
    let status = reopened.submit_allocated_pool(spec).unwrap();
    assert_eq!(status.worker, "worker-2");
    assert_eq!(status.state, OperationState::Queued);
    assert_eq!(status.request_id, None);
    assert_eq!(reopened.lock_state().unwrap().records.len(), 2);
}

#[test]
fn changed_pool_order_members_destinations_and_template_refuse_same_id() {
    let fixture = Fixture::new();
    let store = fixture.open();
    let spec = fixture.spec(1, 2);
    store.submit_allocated_pool(spec.clone()).unwrap();
    for variant in 0..5 {
        let mut changed = spec.clone();
        match variant {
            0 => changed.workers.reverse(),
            1 => changed.workers.push(Fixture::worker(3)),
            2 => changed.workers[1] = Fixture::worker(3),
            3 => changed.delivery = fixture.root.join("different-delivery"),
            4 => changed.output = fixture.root.join("different-output"),
            _ => unreachable!(),
        }
        assert!(
            store.submit_allocated_pool(changed).is_err(),
            "variant {variant}"
        );
    }
    assert!(store.submit_allocated(fixture.singleton(1, 1)).is_err());
    let request_path = fixture.bundle.join("request.json");
    let original = fs::read(&request_path).unwrap();
    let mut changed: Value = serde_json::from_slice(&original).unwrap();
    changed["timeout_ms"] = json!(9999);
    fs::write(&request_path, serde_json::to_vec(&changed).unwrap()).unwrap();
    assert!(store.submit_allocated_pool(spec.clone()).is_err());
    fs::write(&request_path, original).unwrap();
    assert_eq!(
        store.submit_allocated_pool(spec).unwrap().worker,
        "worker-1"
    );
}

#[test]
fn unresolved_names_pins_endpoints_and_mapped_aliases_exclude_candidates() {
    for conflict in ["name", "pin", "endpoint", "mapped-endpoint"] {
        let fixture = Fixture::new();
        let store = fixture.open();
        let mut fixed = fixture.singleton(1, 99);
        let candidate = Fixture::worker(1);
        match conflict {
            "name" => fixed.worker = candidate.worker,
            "pin" => fixed.worker_spki_sha256 = candidate.worker_spki_sha256,
            "endpoint" => fixed.address = candidate.address,
            "mapped-endpoint" => fixed.address = "[::ffff:127.0.0.1]:32001".into(),
            _ => unreachable!(),
        }
        store.submit_allocated(fixed).unwrap();
        interrupted(store.claim_next().unwrap().unwrap(), 8001);
        assert_eq!(
            store
                .submit_allocated_pool(fixture.spec(2, 2))
                .unwrap()
                .worker,
            "worker-2",
            "{conflict}"
        );
    }
}

#[test]
fn entirely_unresolved_pool_refuses_without_creating_or_reselecting_a_job() {
    let fixture = Fixture::new();
    let store = fixture.open();
    for number in 1..=2 {
        store
            .submit_allocated(fixture.singleton(number, number))
            .unwrap();
        interrupted(
            store.claim_next().unwrap().unwrap(),
            8100 + u64::from(number),
        );
    }
    let spec = fixture.spec(3, 2);
    let order = store.lock_state().unwrap().next_order;
    let error = store.submit_allocated_pool(spec.clone()).unwrap_err();
    assert!(error.to_string().contains("unresolved ownership"));
    assert!(store.status(&spec.id).unwrap().is_none());
    assert_eq!(store.lock_state().unwrap().next_order, order);
    assert!(
        !fixture
            .root
            .join("operations")
            .join(format!("{}.json", spec.id))
            .exists()
    );
    assert!(store.claim_next().unwrap().is_none());
}

#[test]
fn pool_shape_rejects_duplicate_and_alias_placements_before_admission() {
    let fixture = Fixture::new();
    let store = fixture.open();
    for case in [
        "empty",
        "too-many",
        "name",
        "pin",
        "endpoint",
        "ipv6-alias",
        "mapped",
        "mapped-wildcard",
        "wildcard",
        "dual-wildcard",
        "zero-port",
        "dns",
        "zero-pin",
        "name-control",
        "name-long",
    ] {
        let mut spec = fixture.spec(1, 2);
        match case {
            "empty" => spec.workers.clear(),
            "too-many" => spec.workers = (1..=33).map(Fixture::worker).collect(),
            "name" => spec.workers[1].worker = spec.workers[0].worker.clone(),
            "pin" => {
                spec.workers[1].worker_spki_sha256 = spec.workers[0].worker_spki_sha256.clone()
            }
            "endpoint" => spec.workers[1].address = spec.workers[0].address.clone(),
            "ipv6-alias" => {
                spec.workers[0].address = "[::1]:32001".into();
                spec.workers[1].address = "[0:0:0:0:0:0:0:1]:32001".into();
            }
            "mapped" => spec.workers[1].address = "[::ffff:127.0.0.1]:32001".into(),
            "mapped-wildcard" => spec.workers[1].address = "[::ffff:0.0.0.0]:32001".into(),
            "wildcard" => spec.workers[1].address = "0.0.0.0:32001".into(),
            "dual-wildcard" => spec.workers[1].address = "[::]:32001".into(),
            "zero-port" => spec.workers[1].address = "127.0.0.1:0".into(),
            "dns" => spec.workers[1].address = "localhost:32002".into(),
            "zero-pin" => spec.workers[1].worker_spki_sha256 = "0".repeat(64),
            "name-control" => spec.workers[1].worker = "worker\n2".into(),
            "name-long" => spec.workers[1].worker = "w".repeat(129),
            _ => unreachable!(),
        }
        assert!(spec.validate().is_err(), "{case}");
        assert!(store.submit_allocated_pool(spec).is_err(), "{case}");
    }
    assert!(store.lock_state().unwrap().records.is_empty());
    fixture.spec(2, 32).validate().unwrap();
}

#[test]
fn pool_rejects_numeric_requests_instead_of_reinterpreting_an_execution_identity() {
    let fixture = Fixture::new();
    let store = fixture.open();
    let request_path = fixture.bundle.join("request.json");
    let mut request: Value = serde_json::from_slice(&fs::read(&request_path).unwrap()).unwrap();
    request["request_id"] = json!(9001);
    fs::write(request_path, serde_json::to_vec(&request).unwrap()).unwrap();
    assert!(store.submit_allocated_pool(fixture.spec(1, 2)).is_err());
    assert!(store.lock_state().unwrap().records.is_empty());
}

#[test]
fn archive_retains_pool_identity_and_exact_placement_after_restart() {
    let fixture = Fixture::new();
    let store = fixture.open();
    let spec = fixture.spec(1, 2);
    store.submit_allocated_pool(spec.clone()).unwrap();
    store.cancel(&spec.id).unwrap();
    {
        let mut state = store.lock_state().unwrap();
        store.make_room(&mut state, MAX_RETAINED_BYTES).unwrap();
        assert!(state.records.is_empty());
    }
    assert_eq!(
        store.submit_allocated_pool(spec.clone()).unwrap().worker,
        "worker-1"
    );
    let mut changed = spec.clone();
    changed.workers.reverse();
    assert!(store.submit_allocated_pool(changed.clone()).is_err());
    drop(store);
    let reopened = fixture.open();
    let status = reopened.submit_allocated_pool(spec).unwrap();
    assert_eq!(status.worker, "worker-1");
    assert_eq!(status.state, OperationState::Cancelled);
    assert!(reopened.submit_allocated_pool(changed).is_err());
    assert!(reopened.claim_next().unwrap().is_none());
}

#[test]
fn corrupt_archived_pool_membership_blocks_admission_and_restart() {
    for corruption in ["member", "empty", "duplicate", "numeric-version"] {
        let fixture = Fixture::new();
        let store = fixture.open();
        let spec = fixture.spec(1, 2);
        store.submit_allocated_pool(spec.clone()).unwrap();
        store.cancel(&spec.id).unwrap();
        {
            let mut state = store.lock_state().unwrap();
            store.make_room(&mut state, MAX_RETAINED_BYTES).unwrap();
        }
        let path = fixture
            .root
            .join("operations/archive")
            .join(format!("{}.json", spec.id));
        let mut record: Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        match corruption {
            "member" => record["spec"]["worker"] = json!("not-approved"),
            "empty" => record["worker_pool"] = json!([]),
            "duplicate" => record["worker_pool"][1] = record["worker_pool"][0].clone(),
            "numeric-version" => record["version"] = json!(1),
            _ => unreachable!(),
        }
        let corrupted = serde_json::to_vec(&record).unwrap();
        fs::write(&path, &corrupted).unwrap();
        assert!(store.status(&spec.id).is_err(), "{corruption}");
        assert!(
            store.submit_allocated_pool(fixture.spec(2, 2)).is_err(),
            "{corruption}"
        );
        drop(store);
        assert!(
            PreparedOperationStore::open(&fixture.root.join("operations")).is_err(),
            "{corruption}"
        );
        assert_eq!(fs::read(path).unwrap(), corrupted);
    }
}

#[test]
fn pooled_destinations_cannot_overlap_other_jobs_or_the_shared_input_bundle() {
    let fixture = Fixture::new();
    let store = fixture.open();
    let first = fixture.spec(1, 2);
    store.submit_allocated_pool(first.clone()).unwrap();
    for (sequence, destination) in [first.delivery, first.output, fixture.bundle.clone()]
        .into_iter()
        .enumerate()
    {
        let mut spec = fixture.spec(sequence as u16 + 2, 2);
        spec.output = destination;
        assert!(store.submit_allocated_pool(spec).is_err());
    }
    assert_eq!(store.lock_state().unwrap().records.len(), 1);
}
