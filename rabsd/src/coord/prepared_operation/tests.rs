//! Filesystem and ownership regressions for the operation store. These tests
//! exercise durable control state; terminal adapter values are not evidence of
//! a real compiler execution or authenticated worker delivery.

use super::*;
use crate::coord::source_delivery::prepare_source_bundle;
use serde_json::json;
use sha2::{Digest, Sha256};
use std::future::Future;
use std::io::Write;
use std::process::Command;
use std::sync::{Barrier, mpsc};
use std::task::{Context, Poll, Wake, Waker};

struct Fixture {
    _temporary: tempfile::TempDir,
    root: PathBuf,
    store_root: PathBuf,
}

impl Fixture {
    fn new() -> Self {
        let temporary = tempfile::tempdir().unwrap();
        let root = temporary.path().canonicalize().unwrap();
        Self {
            store_root: root.join("operations"),
            root,
            _temporary: temporary,
        }
    }

    fn open(&self) -> Arc<PreparedOperationStore> {
        PreparedOperationStore::open(&self.store_root).unwrap()
    }

    fn spec(&self, sequence: u64, worker: u16) -> PreparedOperationSpec {
        let checkout = self.root.join(format!("checkout-{sequence}"));
        let bundle = self.root.join(format!("bundle-{sequence}"));
        fs::create_dir(&checkout).unwrap();
        fs::write(checkout.join("lib.rs"), b"pub fn answer() -> u32 { 42 }\n").unwrap();
        // This content pin is structurally valid input to the preparation API.
        // No test claims that it names an installed or executed toolchain.
        let request = json!({
            "kind":"canonical-exec", "request_id":sequence,
            "program":"/__rabs/toolchain/bin/rustc",
            "toolchain_backing":"/opt/operation-test-toolchain",
            "toolchain_identity":{
                "version":"toolchain-dataset-v1", "sha256":"ab".repeat(32),
                "files":1, "bytes":4,
            },
            "source_files":["lib.rs"],
            "args":["lib.rs", "--crate-type", "lib", "--emit", "metadata",
                "-o", "/__rabs/out/compile/libfixture.rmeta"],
            "artifacts":{"unit":"compile", "files":["libfixture.rmeta"]},
            "timeout_ms":10000,
            "test_extension":{"retain":"exactly", "sequence":sequence},
        });
        prepare_source_bundle(&checkout, &request, &bundle).unwrap();
        PreparedOperationSpec {
            id: format!("{sequence:032x}"),
            address: format!("127.0.0.1:{}", 30000 + worker),
            worker: format!("worker-{worker}"),
            worker_spki_sha256: format!("{worker:064x}"),
            bundle,
            delivery: self.root.join(format!("delivery-{sequence}")),
            output: self.root.join(format!("output-{sequence}")),
        }
    }
}

fn prepared_request(spec: &PreparedOperationSpec) -> Value {
    serde_json::from_slice(&fs::read(spec.bundle.join("request.json")).unwrap()).unwrap()
}

fn delivery_request_digest(request: &Value) -> String {
    Sha256::digest(serde_json::to_vec(request).unwrap())
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn operation_request_digest(request: &Value) -> String {
    let bytes = serde_json::to_vec(request).unwrap();
    let mut identity = b"rabs.prepared-operation.request.v1\0".to_vec();
    identity.extend_from_slice(&(bytes.len() as u64).to_le_bytes());
    identity.extend_from_slice(&bytes);
    Sha256::digest(identity)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn fail_before_dispatch(claim: OperationClaim) {
    claim
        .finish(OperationOutcome::Failed {
            detail: "test adapter stopped before execution dispatch".to_owned(),
            execution_may_have_run: false,
        })
        .unwrap();
}

fn uncertain(claim: OperationClaim) {
    claim
        .finish(OperationOutcome::Failed {
            detail: "execution write lost its response".to_owned(),
            execution_may_have_run: true,
        })
        .unwrap();
}

fn adapter_result(claim: &OperationClaim, exit_code: i32, stop: Value, ack: bool) -> Value {
    let installed = if !claim.acknowledgment_only() && exit_code == 0 && stop.is_null() {
        json!({
            "kind":"worker-output-install", "directory":claim.spec().output,
            "publication_authorized":false, "reexecute":false,
            "files":0, "total_bytes":0, "reused":false,
        })
    } else {
        Value::Null
    };
    let mut result = json!({
        "kind":"worker-build", "bundle":claim.spec().bundle,
        "delivery":{
            "kind":"worker-delivery", "directory":claim.spec().delivery,
            "receipt":{
                "kind":"verified-worker-delivery", "version":1,
                "request_id":claim.request()["request_id"],
                "request_sha256":delivery_request_digest(claim.request()),
                "worker_id":claim.spec().worker,
                "worker_spki_sha256":claim.spec().worker_spki_sha256,
                "transport_authenticated":true,
                "exit_code":exit_code, "stop_reason":stop,
                "publication_authorized":false, "reexecute":false,
            },
            "acknowledgments_confirmed":ack,
            "acknowledgment_error":if ack { Value::Null } else { json!("ACK response lost") },
            "reexecute":false,
        },
        "installed_outputs":installed, "publication_authorized":false, "reexecute":false,
    });
    if claim.acknowledgment_only() {
        result["operation"] = json!("acknowledge");
    }
    result
}

#[test]
fn submission_is_idempotent_and_retains_the_exact_request_across_reopen() {
    let fixture = Fixture::new();
    let spec = fixture.spec(1, 1);
    let original = prepared_request(&spec);
    let store = fixture.open();
    let first = store.submit(spec.clone()).unwrap();
    assert_eq!(first.id, spec.id);
    assert_eq!(first.state, OperationState::Queued);
    assert_eq!(first.request_sha256, operation_request_digest(&original));
    assert!(!first.execution_may_have_run);
    assert!(!first.cancel_requested);
    assert_eq!(
        serde_json::to_value(store.submit(spec.clone()).unwrap()).unwrap(),
        serde_json::to_value(&first).unwrap(),
    );
    assert!(store.status(&format!("{:032x}", 999)).unwrap().is_none());
    drop(store);

    let reopened = fixture.open();
    let status = reopened.status(&spec.id).unwrap().unwrap();
    assert_eq!(status.state, OperationState::Queued);
    assert_eq!(status.request_sha256, first.request_sha256);
    let claim = reopened.claim_next().unwrap().unwrap();
    assert_eq!(claim.spec().id, spec.id);
    assert_eq!(claim.request(), &original);
    assert_eq!(claim.mode(), DeliveryMode::Execute);
    assert!(claim.resume_from().is_none());
    assert!(reopened.claim_next().unwrap().is_none());
    fail_before_dispatch(claim);
    assert_eq!(
        reopened.status(&spec.id).unwrap().unwrap().state,
        OperationState::FailedBeforeStart,
    );
}

#[test]
fn changed_request_or_target_cannot_rebind_an_accepted_operation() {
    let fixture = Fixture::new();
    let spec = fixture.spec(2, 1);
    let original = prepared_request(&spec);
    let store = fixture.open();
    store.submit(spec.clone()).unwrap();

    let mut changed_pin = spec.clone();
    changed_pin.worker_spki_sha256 = "cd".repeat(32);
    assert!(store.submit(changed_pin).is_err());
    let mut changed_worker = spec.clone();
    changed_worker.worker = "different-worker".to_owned();
    assert!(store.submit(changed_worker).is_err());
    let mut changed_address = spec.clone();
    changed_address.address = "127.0.0.1:39000".to_owned();
    assert!(store.submit(changed_address).is_err());

    let mut edited = original.clone();
    edited["args"][0] = json!("different.rs");
    fs::write(
        spec.bundle.join("request.json"),
        serde_json::to_vec(&edited).unwrap(),
    )
    .unwrap();
    assert!(store.submit(spec.clone()).is_err());
    assert_eq!(
        store.status(&spec.id).unwrap().unwrap().request_sha256,
        operation_request_digest(&original),
    );
    drop(store);

    let reopened = fixture.open();
    let claim = reopened.claim_next().unwrap().unwrap();
    assert_eq!(
        claim.request(),
        &original,
        "dispatch must use the saved request"
    );
    fail_before_dispatch(claim);
}

#[test]
fn queued_cancellation_is_durable_and_never_creates_a_claim() {
    let fixture = Fixture::new();
    let spec = fixture.spec(3, 1);
    let store = fixture.open();
    store.submit(spec.clone()).unwrap();
    let cancelled = store.cancel(&spec.id).unwrap();
    assert_eq!(cancelled.state, OperationState::Cancelled);
    assert!(cancelled.cancel_requested);
    assert!(!cancelled.execution_may_have_run);
    assert_eq!(
        store.cancel(&spec.id).unwrap().state,
        OperationState::Cancelled
    );
    assert!(store.claim_next().unwrap().is_none());
    drop(store);

    let reopened = fixture.open();
    let status = reopened.status(&spec.id).unwrap().unwrap();
    assert_eq!(status.state, OperationState::Cancelled);
    assert!(status.cancel_requested);
    assert!(!status.execution_may_have_run);
    assert!(reopened.claim_next().unwrap().is_none());
}

struct CancellationWake(mpsc::Sender<()>);

impl Wake for CancellationWake {
    fn wake(self: Arc<Self>) {
        self.0.send(()).unwrap();
    }
}

#[test]
fn racing_claimers_get_one_owner_and_cancellation_wakes_that_owner() {
    let fixture = Fixture::new();
    let spec = fixture.spec(4, 1);
    let store = fixture.open();
    store.submit(spec.clone()).unwrap();
    let barrier = Arc::new(Barrier::new(12));
    let threads: Vec<_> = (0..12)
        .map(|_| {
            let store = Arc::clone(&store);
            let barrier = Arc::clone(&barrier);
            std::thread::spawn(move || {
                barrier.wait();
                store.claim_next().unwrap()
            })
        })
        .collect();
    // Retain every returned guard until all contenders have finished. Dropping
    // one early would test recovery instead of simultaneous claim ownership.
    let mut claims: Vec<_> = threads
        .into_iter()
        .filter_map(|thread| thread.join().unwrap())
        .collect();
    assert_eq!(claims.len(), 1);
    let claim = claims.pop().unwrap();
    let cancellation = claim.cancellation();
    let (send, receive) = mpsc::channel();
    let waker = Waker::from(Arc::new(CancellationWake(send)));
    let mut context = Context::from_waker(&waker);
    let mut waiter = Box::pin(cancellation.cancelled());
    assert_eq!(waiter.as_mut().poll(&mut context), Poll::Pending);
    let cancelling = store.cancel(&spec.id).unwrap();
    assert_eq!(cancelling.state, OperationState::Cancelling);
    assert!(cancelling.cancel_requested);
    receive.recv_timeout(Duration::from_secs(2)).unwrap();
    assert!(cancellation.is_cancelled());
    assert_eq!(waiter.as_mut().poll(&mut context), Poll::Ready(()));
    assert_eq!(
        store.cancel(&spec.id).unwrap().state,
        OperationState::Cancelling
    );
    assert!(store.claim_next().unwrap().is_none());
    drop(claim);
    assert_eq!(
        store.status(&spec.id).unwrap().unwrap().state,
        OperationState::Uncertain,
        "local cancellation intent does not prove that remote execution stopped",
    );
}

#[test]
fn four_distinct_workers_can_run_and_the_fifth_waits_for_a_slot() {
    let fixture = Fixture::new();
    let store = fixture.open();
    for sequence in 10..15 {
        store
            .submit(fixture.spec(sequence, sequence as u16))
            .unwrap();
    }
    let mut claims: Vec<_> = (0..4)
        .map(|_| store.claim_next().unwrap().unwrap())
        .collect();
    let workers: std::collections::BTreeSet<_> = claims
        .iter()
        .map(|claim| claim.spec().worker.clone())
        .collect();
    assert_eq!(workers.len(), 4);
    assert!(store.claim_next().unwrap().is_none());
    fail_before_dispatch(claims.pop().unwrap());
    let fifth = store.claim_next().unwrap().unwrap();
    assert!(!workers.contains(&fifth.spec().worker));
    fail_before_dispatch(fifth);
    for claim in claims {
        fail_before_dispatch(claim);
    }
}

#[test]
fn distinct_workers_requesting_ephemeral_ports_can_hold_concurrent_claims() {
    let fixture = Fixture::new();
    let mut first = fixture.spec(130, 1);
    let mut second = fixture.spec(131, 2);
    first.address = "127.0.0.1:0".to_owned();
    second.address = first.address.clone();
    let store = fixture.open();
    store.submit(first.clone()).unwrap();
    store.submit(second.clone()).unwrap();
    let first_claim = store.claim_next().unwrap().unwrap();
    let second_claim = store.claim_next().unwrap().unwrap();
    assert_eq!(first_claim.spec().id, first.id);
    assert_eq!(second_claim.spec().id, second.id);

    let first_listener = std::net::TcpListener::bind(&first_claim.spec().address).unwrap();
    let second_listener = std::net::TcpListener::bind(&second_claim.spec().address).unwrap();
    let first_address = first_listener.local_addr().unwrap();
    let second_address = second_listener.local_addr().unwrap();
    assert_ne!(first_address.port(), 0);
    assert_ne!(second_address.port(), 0);
    assert_ne!(first_address, second_address);
    first_claim.listening(first_address).unwrap();
    second_claim.listening(second_address).unwrap();
    for (spec, address) in [(&first, first_address), (&second, second_address)] {
        let status = store.status(&spec.id).unwrap().unwrap();
        assert_eq!(status.state, OperationState::Running);
        assert_eq!(status.address, "127.0.0.1:0");
        assert_eq!(status.listen_address, Some(address.to_string()));
    }
    fail_before_dispatch(first_claim);
    fail_before_dispatch(second_claim);
}

#[test]
fn worker_name_pin_and_address_each_fence_simultaneous_operations() {
    for collision in ["worker", "pin", "address"] {
        let fixture = Fixture::new();
        let first = fixture.spec(20, 1);
        let mut second = fixture.spec(21, 2);
        match collision {
            "worker" => second.worker = first.worker.clone(),
            "pin" => second.worker_spki_sha256 = first.worker_spki_sha256.clone(),
            "address" => second.address = first.address.clone(),
            _ => unreachable!(),
        }
        let store = fixture.open();
        store.submit(first.clone()).unwrap();
        let claim = store.claim_next().unwrap().unwrap();
        if store.submit(second).is_ok() {
            assert!(
                store.claim_next().unwrap().is_none(),
                "collision: {collision}"
            );
        }
        assert_eq!(claim.spec().id, first.id);
        assert!(!claim.cancellation().is_cancelled());
        fail_before_dispatch(claim);
    }
}

#[test]
fn output_and_delivery_paths_cannot_alias_another_live_operation() {
    for collision in [
        "delivery",
        "output",
        "delivery-output",
        "output-delivery",
        "bundle",
    ] {
        let fixture = Fixture::new();
        let first = fixture.spec(30, 1);
        let mut second = fixture.spec(31, 2);
        match collision {
            "delivery" => second.delivery = first.delivery.clone(),
            "output" => second.output = first.output.clone(),
            "delivery-output" => second.delivery = first.output.clone(),
            "output-delivery" => second.output = first.delivery.clone(),
            "bundle" => second.output = first.bundle.join("source/new-output"),
            _ => unreachable!(),
        }
        let store = fixture.open();
        store.submit(first).unwrap();
        let claim = store.claim_next().unwrap().unwrap();
        if store.submit(second).is_ok() {
            assert!(
                store.claim_next().unwrap().is_none(),
                "collision: {collision}"
            );
        }
        fail_before_dispatch(claim);
    }
}

#[test]
fn uncertain_worker_blocks_later_execution_until_explicit_resume_completes() {
    let fixture = Fixture::new();
    let first = fixture.spec(40, 1);
    let second = fixture.spec(41, 1);
    let original = prepared_request(&first);
    let store = fixture.open();
    store.submit(first.clone()).unwrap();
    store.submit(second.clone()).unwrap();
    let claim = store.claim_next().unwrap().unwrap();
    assert_eq!(claim.spec().id, first.id);
    uncertain(claim);
    assert!(store.claim_next().unwrap().is_none());
    drop(store);

    let reopened = fixture.open();
    assert!(reopened.claim_next().unwrap().is_none());
    let new_delivery = fixture.root.join("resumed-delivery");
    let resumed = reopened
        .resume(&first.id, new_delivery.clone(), None)
        .unwrap();
    assert_eq!(resumed.state, OperationState::Queued);
    assert!(resumed.execution_may_have_run);
    let claim = reopened.claim_next().unwrap().unwrap();
    assert_eq!(claim.spec().id, first.id);
    assert_eq!(claim.spec().delivery, new_delivery);
    assert_eq!(claim.request(), &original);
    assert_eq!(claim.mode(), DeliveryMode::Resume);
    assert!(reopened.claim_next().unwrap().is_none());
    let result = adapter_result(&claim, 0, Value::Null, true);
    claim
        .finish(OperationOutcome::Completed { result })
        .unwrap();
    let completed = reopened.status(&first.id).unwrap().unwrap();
    assert_eq!(completed.state, OperationState::Completed);
    assert_eq!(completed.exit_code, Some(0));
    assert_eq!(completed.acknowledgments_confirmed, Some(true));
    assert!(completed.outputs_installed);
    assert!(completed.succeeded);
    let later = reopened.claim_next().unwrap().unwrap();
    assert_eq!(later.spec().id, second.id);
    assert_eq!(later.mode(), DeliveryMode::Execute);
    fail_before_dispatch(later);
}

#[test]
fn failed_resume_never_erases_uncertainty_from_the_original_execution() {
    let fixture = Fixture::new();
    let spec = fixture.spec(42, 1);
    let store = fixture.open();
    store.submit(spec.clone()).unwrap();
    uncertain(store.claim_next().unwrap().unwrap());
    assert!(store.resume(&spec.id, spec.delivery.clone(), None).is_err());
    let destination = fixture.root.join("resume-42");
    fs::create_dir(&spec.delivery).unwrap();
    fs::write(spec.delivery.join("partial"), b"retained hint").unwrap();
    store
        .resume(&spec.id, destination.clone(), Some(spec.delivery.clone()))
        .unwrap();
    let claim = store.claim_next().unwrap().unwrap();
    assert_eq!(claim.mode(), DeliveryMode::Resume);
    assert_eq!(claim.spec().delivery, destination);
    assert_eq!(claim.resume_from(), Some(spec.delivery.as_path()));
    fail_before_dispatch(claim);
    let status = store.status(&spec.id).unwrap().unwrap();
    assert_eq!(status.state, OperationState::Uncertain);
    assert!(status.execution_may_have_run);
    assert_eq!(
        fs::read(spec.delivery.join("partial")).unwrap(),
        b"retained hint"
    );
    assert!(store.claim_next().unwrap().is_none());
}

#[test]
fn acknowledgment_reuses_only_owned_deliveries_and_fences_queued_execution() {
    for use_prior_delivery in [false, true] {
        let fixture = Fixture::new();
        let first = fixture.spec(120, 1);
        let later = fixture.spec(121, 1);
        let store = fixture.open();
        store.submit(first.clone()).unwrap();
        store.submit(later.clone()).unwrap();
        let claim = store.claim_next().unwrap().unwrap();
        fs::create_dir(&first.delivery).unwrap();
        let result = adapter_result(&claim, 101, Value::Null, false);
        claim
            .finish(OperationOutcome::Completed { result })
            .unwrap();
        if use_prior_delivery {
            let resumed_directory = fixture.root.join("newer-delivery");
            store
                .resume(&first.id, resumed_directory.clone(), None)
                .unwrap();
            let claim = store.claim_next().unwrap().unwrap();
            fs::create_dir(resumed_directory).unwrap();
            let result = adapter_result(&claim, 101, Value::Null, false);
            claim
                .finish(OperationOutcome::Completed { result })
                .unwrap();
        }
        assert!(store.claim_next().unwrap().is_none());
        let unowned = fixture.root.join("unowned-delivery");
        let nested = first.delivery.join("nested");
        fs::create_dir(&unowned).unwrap();
        fs::create_dir(&nested).unwrap();
        fs::create_dir(&later.delivery).unwrap();
        for rejected in [
            unowned,
            nested,
            later.delivery.clone(),
            first.bundle.clone(),
        ] {
            assert!(store.acknowledge(&first.id, rejected).is_err());
        }
        let queued = store
            .acknowledge(&first.id, first.delivery.clone())
            .unwrap();
        assert_eq!(queued.state, OperationState::Queued);
        assert_eq!(queued.mode, "acknowledge");
        assert!(queued.execution_may_have_run);
        drop(store);
        let store = fixture.open();
        assert_eq!(
            store.status(&first.id).unwrap().unwrap().mode,
            "acknowledge"
        );
        let acknowledgment = store.claim_next().unwrap().unwrap();
        assert_eq!(acknowledgment.spec().id, first.id);
        assert_eq!(acknowledgment.spec().delivery, first.delivery);
        assert_eq!(acknowledgment.mode(), DeliveryMode::Resume);
        assert!(acknowledgment.acknowledgment_only());
        assert_eq!(acknowledgment.request(), &prepared_request(&first));
        assert!(store.claim_next().unwrap().is_none());
        let result = adapter_result(&acknowledgment, 101, Value::Null, true);
        acknowledgment
            .finish(OperationOutcome::Completed { result })
            .unwrap();
        let completed = store.status(&first.id).unwrap().unwrap();
        assert_eq!(completed.state, OperationState::Completed);
        assert_eq!(completed.exit_code, Some(101));
        assert_eq!(completed.acknowledgments_confirmed, Some(true));
        let next = store.claim_next().unwrap().unwrap();
        assert_eq!(next.spec().id, later.id);
        fail_before_dispatch(next);
    }
}

#[test]
fn acknowledgment_preserves_installation_history_without_claiming_a_new_install() {
    for previously_installed in [false, true] {
        let fixture = Fixture::new();
        let spec = fixture.spec(123, 1);
        let store = fixture.open();
        store.submit(spec.clone()).unwrap();
        let claim = store.claim_next().unwrap().unwrap();
        fs::create_dir(&spec.delivery).unwrap();
        if previously_installed {
            let result = adapter_result(&claim, 0, Value::Null, false);
            claim
                .finish(OperationOutcome::Completed { result })
                .unwrap();
        } else {
            uncertain(claim);
        }
        assert_eq!(
            store.status(&spec.id).unwrap().unwrap().outputs_installed,
            previously_installed,
        );
        store.acknowledge(&spec.id, spec.delivery.clone()).unwrap();
        let acknowledgment = store.claim_next().unwrap().unwrap();
        assert!(acknowledgment.acknowledgment_only());
        let result = adapter_result(&acknowledgment, 0, Value::Null, true);
        assert_eq!(result["operation"], "acknowledge");
        assert!(result["installed_outputs"].is_null());
        let status = acknowledgment
            .finish(OperationOutcome::Completed { result })
            .unwrap();
        assert_eq!(status.state, OperationState::Completed);
        assert_eq!(status.exit_code, Some(0));
        assert_eq!(status.acknowledgments_confirmed, Some(true));
        assert_eq!(status.outputs_installed, previously_installed);
        assert_eq!(status.succeeded, previously_installed);
        drop(store);
        let reopened = fixture.open();
        let recovered = reopened.status(&spec.id).unwrap().unwrap();
        assert_eq!(recovered.outputs_installed, previously_installed);
        assert_eq!(recovered.succeeded, previously_installed);
    }
}

#[test]
fn ephemeral_listener_address_is_retained_for_explicit_resume_after_restart() {
    let fixture = Fixture::new();
    let mut spec = fixture.spec(122, 1);
    spec.address = "127.0.0.1:0".to_owned();
    let store = fixture.open();
    store.submit(spec.clone()).unwrap();
    let claim = store.claim_next().unwrap().unwrap();
    let listener = std::net::TcpListener::bind(&claim.spec().address).unwrap();
    let actual = listener.local_addr().unwrap();
    assert_ne!(actual.port(), 0);
    claim.listening(actual).unwrap();
    let running = store.status(&spec.id).unwrap().unwrap();
    assert_eq!(running.address, "127.0.0.1:0");
    assert_eq!(running.listen_address, Some(actual.to_string()));
    uncertain(claim);
    assert!(
        store
            .status(&spec.id)
            .unwrap()
            .unwrap()
            .listen_address
            .is_none()
    );
    drop(store);

    let reopened = fixture.open();
    let queued = reopened
        .resume(&spec.id, fixture.root.join("resumed-port"), None)
        .unwrap();
    assert_eq!(queued.address, "127.0.0.1:0");
    assert!(queued.listen_address.is_none());
    let recovery = reopened.claim_next().unwrap().unwrap();
    assert_eq!(recovery.spec().address, actual.to_string());
    assert_eq!(recovery.mode(), DeliveryMode::Resume);
    // Keep the first listener until the recovery claim owns the persisted port;
    // then perform a real bind of that exact port, without any worker connection.
    drop(listener);
    let replacement = std::net::TcpListener::bind(&recovery.spec().address).unwrap();
    assert_eq!(replacement.local_addr().unwrap(), actual);
    recovery.listening(actual).unwrap();
    assert_eq!(
        reopened.status(&spec.id).unwrap().unwrap().listen_address,
        Some(actual.to_string()),
    );
    uncertain(recovery);
    assert!(
        reopened
            .status(&spec.id)
            .unwrap()
            .unwrap()
            .listen_address
            .is_none()
    );
}

#[test]
fn verified_delivery_with_lost_ack_stays_completed_but_fences_the_worker() {
    let fixture = Fixture::new();
    let first = fixture.spec(43, 1);
    let later = fixture.spec(44, 1);
    let store = fixture.open();
    store.submit(first.clone()).unwrap();
    store.submit(later.clone()).unwrap();
    let claim = store.claim_next().unwrap().unwrap();
    let result = adapter_result(&claim, 101, Value::Null, false);
    claim
        .finish(OperationOutcome::Completed { result })
        .unwrap();
    let completed = store.status(&first.id).unwrap().unwrap();
    assert_eq!(completed.state, OperationState::Completed);
    assert_eq!(completed.exit_code, Some(101));
    assert_eq!(completed.acknowledgments_confirmed, Some(false));
    assert!(!completed.outputs_installed);
    assert!(!completed.succeeded);
    assert!(store.claim_next().unwrap().is_none());
    drop(store);

    let reopened = fixture.open();
    assert_eq!(
        reopened.status(&first.id).unwrap().unwrap().state,
        OperationState::Completed,
        "lost ACK must not discard already verified compiler status",
    );
    assert!(reopened.claim_next().unwrap().is_none());
    reopened
        .resume(&first.id, fixture.root.join("ack-recovery"), None)
        .unwrap();
    let recovery = reopened.claim_next().unwrap().unwrap();
    assert_eq!(recovery.spec().id, first.id);
    assert_eq!(recovery.mode(), DeliveryMode::Resume);
    let result = adapter_result(&recovery, 101, Value::Null, true);
    recovery
        .finish(OperationOutcome::Completed { result })
        .unwrap();
    let next = reopened.claim_next().unwrap().unwrap();
    assert_eq!(next.spec().id, later.id);
    fail_before_dispatch(next);
}

#[test]
fn cancellation_status_follows_observed_completion_instead_of_local_intent() {
    for (sequence, interrupted) in [(45, true), (46, false)] {
        let fixture = Fixture::new();
        let spec = fixture.spec(sequence, 1);
        let store = fixture.open();
        store.submit(spec.clone()).unwrap();
        let claim = store.claim_next().unwrap().unwrap();
        store.cancel(&spec.id).unwrap();
        let result = adapter_result(
            &claim,
            if interrupted { 130 } else { 0 },
            if interrupted {
                json!("cancelled")
            } else {
                Value::Null
            },
            true,
        );
        let outcome = if interrupted {
            OperationOutcome::Cancelled { result }
        } else {
            OperationOutcome::Completed { result }
        };
        let status = claim.finish(outcome).unwrap();
        assert!(status.cancel_requested);
        assert!(status.execution_may_have_run);
        assert_eq!(status.acknowledgments_confirmed, Some(true));
        assert_eq!(
            status.state,
            if interrupted {
                OperationState::Cancelled
            } else {
                OperationState::Completed
            },
        );
        assert_eq!(status.exit_code, Some(if interrupted { 130 } else { 0 }));
    }
}

#[test]
fn cancelling_queued_recovery_preserves_the_original_execution_uncertainty() {
    let fixture = Fixture::new();
    let spec = fixture.spec(48, 1);
    let store = fixture.open();
    store.submit(spec.clone()).unwrap();
    uncertain(store.claim_next().unwrap().unwrap());
    store
        .resume(&spec.id, fixture.root.join("cancelled-resume"), None)
        .unwrap();
    let cancelled = store.cancel(&spec.id).unwrap();
    assert_eq!(cancelled.state, OperationState::Uncertain);
    assert!(cancelled.cancel_requested);
    assert!(cancelled.execution_may_have_run);
    assert!(store.claim_next().unwrap().is_none());
    drop(store);
    let reopened = fixture.open();
    let recovered = reopened.status(&spec.id).unwrap().unwrap();
    assert_eq!(recovered.state, OperationState::Uncertain);
    assert!(recovered.execution_may_have_run);
    assert!(reopened.claim_next().unwrap().is_none());
}

#[test]
fn active_cancellation_confirmed_before_dispatch_is_terminal_without_execution() {
    let fixture = Fixture::new();
    let spec = fixture.spec(49, 1);
    let store = fixture.open();
    store.submit(spec.clone()).unwrap();
    let claim = store.claim_next().unwrap().unwrap();
    store.cancel(&spec.id).unwrap();
    fail_before_dispatch(claim);
    let cancelled = store.status(&spec.id).unwrap().unwrap();
    assert_eq!(cancelled.state, OperationState::Cancelled);
    assert_eq!(cancelled.exit_code, Some(130));
    assert!(cancelled.cancel_requested);
    assert!(!cancelled.execution_may_have_run);
    drop(store);
    let reopened = fixture.open();
    assert_eq!(
        reopened.status(&spec.id).unwrap().unwrap().state,
        OperationState::Cancelled,
    );
    assert!(reopened.claim_next().unwrap().is_none());
}

#[test]
fn another_request_or_worker_cannot_supply_completion_for_a_claim() {
    for mismatch in [
        "request",
        "worker",
        "pin",
        "authentication",
        "publication",
        "exit",
    ] {
        let fixture = Fixture::new();
        let spec = fixture.spec(47, 1);
        let store = fixture.open();
        store.submit(spec.clone()).unwrap();
        let claim = store.claim_next().unwrap().unwrap();
        let mut result = adapter_result(&claim, 0, Value::Null, true);
        let receipt = &mut result["delivery"]["receipt"];
        match mismatch {
            "request" => receipt["request_sha256"] = json!("cd".repeat(32)),
            "worker" => receipt["worker_id"] = json!("another-worker"),
            "pin" => receipt["worker_spki_sha256"] = json!("cd".repeat(32)),
            "authentication" => receipt["transport_authenticated"] = json!(false),
            "publication" => receipt["publication_authorized"] = json!(true),
            "exit" => receipt["exit_code"] = json!(256),
            _ => unreachable!(),
        }
        assert!(
            claim
                .finish(OperationOutcome::Completed { result })
                .is_err(),
            "mismatch: {mismatch}"
        );
        let status = store.status(&spec.id).unwrap().unwrap();
        assert_eq!(status.state, OperationState::Uncertain);
        assert!(status.execution_may_have_run);
        assert!(status.exit_code.is_none());
    }
}

#[test]
fn successful_compiler_status_requires_installation_in_the_owned_output_directory() {
    for missing in [false, true] {
        let fixture = Fixture::new();
        let spec = fixture.spec(52, 1);
        let store = fixture.open();
        store.submit(spec.clone()).unwrap();
        let claim = store.claim_next().unwrap().unwrap();
        let mut result = adapter_result(&claim, 0, Value::Null, true);
        if missing {
            result["installed_outputs"] = Value::Null;
        } else {
            result["installed_outputs"]["directory"] = json!(fixture.root.join("another-output"));
        }
        assert!(
            claim
                .finish(OperationOutcome::Completed { result })
                .is_err()
        );
        let status = store.status(&spec.id).unwrap().unwrap();
        assert_eq!(status.state, OperationState::Uncertain);
        assert!(status.execution_may_have_run);
        assert!(!status.outputs_installed);
        assert!(!status.succeeded);
        drop(store);
        let reopened = fixture.open();
        let recovered = reopened.status(&spec.id).unwrap().unwrap();
        assert_eq!(recovered.state, OperationState::Uncertain);
        assert!(!recovered.outputs_installed);
        assert!(!recovered.succeeded);
    }
}

#[test]
fn stop_cancels_active_ownership_and_keeps_unclaimed_work_for_restart() {
    let fixture = Fixture::new();
    let first = fixture.spec(50, 1);
    let queued = fixture.spec(51, 2);
    let store = fixture.open();
    store.submit(first.clone()).unwrap();
    store.submit(queued.clone()).unwrap();
    let claim = store.claim_next().unwrap().unwrap();
    assert_eq!(claim.spec().id, first.id);
    let cancellation = claim.cancellation();
    store.stop().unwrap();
    assert!(cancellation.is_cancelled());
    assert!(store.claim_next().unwrap().is_none());
    let queued_status = store.status(&queued.id).unwrap().unwrap();
    assert_eq!(queued_status.state, OperationState::Queued);
    assert!(!queued_status.cancel_requested);
    assert!(!queued_status.execution_may_have_run);
    drop(claim);
    drop(store);

    let reopened = fixture.open();
    let interrupted = reopened.status(&first.id).unwrap().unwrap();
    assert_eq!(interrupted.state, OperationState::Uncertain);
    assert!(interrupted.execution_may_have_run);
    let next = reopened.claim_next().unwrap().unwrap();
    assert_eq!(next.spec().id, queued.id);
    fail_before_dispatch(next);
}

const CRASH_CHILD_ROOT: &str = "RABS_PREPARED_OPERATION_TEST_CRASH_ROOT";

#[test]
fn crash_child_claims_without_running_destructors() {
    let Some(root) = std::env::var_os(CRASH_CHILD_ROOT) else {
        return;
    };
    let store = PreparedOperationStore::open(Path::new(&root)).unwrap();
    let claim = store.claim_next().unwrap().unwrap();
    println!("prepared-operation-claimed:{}", claim.spec().id);
    io::stdout().flush().unwrap();
    // This runs only in the isolated subprocess below. It deliberately leaves
    // the persisted Running record without invoking Claim::drop or Store::stop.
    std::process::exit(0);
}

#[test]
fn actual_process_exit_recovers_running_as_uncertain_without_dispatching_again() {
    let fixture = Fixture::new();
    let first = fixture.spec(60, 1);
    let queued = fixture.spec(61, 2);
    let store = fixture.open();
    store.submit(first.clone()).unwrap();
    store.submit(queued.clone()).unwrap();
    drop(store);

    let module = module_path!().split_once("::").unwrap().1;
    let child = Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            &format!("{module}::crash_child_claims_without_running_destructors"),
            "--nocapture",
            "--test-threads=1",
        ])
        .env(CRASH_CHILD_ROOT, &fixture.store_root)
        .output()
        .unwrap();
    assert!(
        child.status.success(),
        "crash child failed: {}",
        String::from_utf8_lossy(&child.stderr),
    );
    assert!(
        String::from_utf8_lossy(&child.stdout)
            .contains(&format!("prepared-operation-claimed:{}", first.id)),
        "child must really claim the operation; a filtered-out test is not crash evidence",
    );
    let reopened = fixture.open();
    let recovered = reopened.status(&first.id).unwrap().unwrap();
    assert_eq!(recovered.state, OperationState::Uncertain);
    assert!(recovered.execution_may_have_run);
    let next = reopened.claim_next().unwrap().unwrap();
    assert_eq!(next.spec().id, queued.id);
    fail_before_dispatch(next);
    assert!(reopened.claim_next().unwrap().is_none());
}

#[test]
fn exclusive_store_lock_remains_owned_while_a_claim_retains_the_store() {
    let fixture = Fixture::new();
    let spec = fixture.spec(70, 1);
    let store = fixture.open();
    store.submit(spec.clone()).unwrap();
    let claim = store.claim_next().unwrap().unwrap();
    let before = fs::read(fixture.store_root.join(format!("{}.json", spec.id))).unwrap();
    assert!(PreparedOperationStore::open(&fixture.store_root).is_err());
    drop(store);
    assert!(PreparedOperationStore::open(&fixture.store_root).is_err());
    assert_eq!(
        fs::read(fixture.store_root.join(format!("{}.json", spec.id))).unwrap(),
        before,
        "a rejected second owner must not reconcile another owner's records",
    );
    drop(claim);
    let reopened = fixture.open();
    assert_eq!(
        reopened.status(&spec.id).unwrap().unwrap().state,
        OperationState::Uncertain,
    );
}

#[test]
fn corrupt_durable_record_refuses_open_without_erasing_the_record() {
    let fixture = Fixture::new();
    let spec = fixture.spec(80, 1);
    let store = fixture.open();
    store.submit(spec.clone()).unwrap();
    drop(store);
    let record = fixture.store_root.join(format!("{}.json", spec.id));
    fs::write(&record, b"{torn durable operation").unwrap();
    assert!(PreparedOperationStore::open(&fixture.store_root).is_err());
    assert_eq!(fs::read(&record).unwrap(), b"{torn durable operation");
}

#[test]
fn durable_record_cannot_move_to_a_different_operation_id() {
    let fixture = Fixture::new();
    let spec = fixture.spec(81, 1);
    let store = fixture.open();
    store.submit(spec.clone()).unwrap();
    drop(store);
    let original = fixture.store_root.join(format!("{}.json", spec.id));
    let other = fixture.store_root.join(format!("{:032x}.json", 82));
    fs::rename(&original, &other).unwrap();
    assert!(PreparedOperationStore::open(&fixture.store_root).is_err());
    assert!(other.is_file());
}

#[test]
fn changed_persisted_request_cannot_reuse_its_original_operation_digest() {
    let fixture = Fixture::new();
    let spec = fixture.spec(83, 1);
    let store = fixture.open();
    store.submit(spec.clone()).unwrap();
    drop(store);
    let path = fixture.store_root.join(format!("{}.json", spec.id));
    let mut record: Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
    record["request"]["args"][0] = json!("different-source.rs");
    let changed = serde_json::to_vec(&record).unwrap();
    fs::write(&path, &changed).unwrap();
    assert!(PreparedOperationStore::open(&fixture.store_root).is_err());
    assert_eq!(fs::read(&path).unwrap(), changed);
}

#[test]
fn failure_after_record_rename_cancels_owners_and_requires_reopen() {
    let fixture = Fixture::new();
    let first = fixture.spec(84, 1);
    let next = fixture.spec(85, 2);
    let store = fixture.open();
    store.submit(first.clone()).unwrap();
    store.submit(next.clone()).unwrap();
    let active = store.claim_next().unwrap().unwrap();
    let cancellation = active.cancellation();
    store
        .fail_after_rename
        .store(true, std::sync::atomic::Ordering::SeqCst);
    assert!(store.claim_next().is_err());
    assert!(cancellation.is_cancelled());
    assert!(store.status(&first.id).is_err());
    assert!(store.claim_next().is_err());
    drop(active);
    drop(store);

    let reopened = fixture.open();
    for spec in [&first, &next] {
        let recovered = reopened.status(&spec.id).unwrap().unwrap();
        assert_eq!(recovered.state, OperationState::Uncertain);
        assert!(recovered.execution_may_have_run);
    }
    assert!(reopened.claim_next().unwrap().is_none());
}

#[test]
fn recovered_terminal_records_cannot_erase_execution_or_result_evidence() {
    for field in [
        "execution_may_have_run",
        "exit_code",
        "acknowledgments_confirmed",
    ] {
        let fixture = Fixture::new();
        let spec = fixture.spec(86, 1);
        let store = fixture.open();
        store.submit(spec.clone()).unwrap();
        let claim = store.claim_next().unwrap().unwrap();
        let result = adapter_result(&claim, 0, Value::Null, true);
        claim
            .finish(OperationOutcome::Completed { result })
            .unwrap();
        drop(store);
        let path = fixture.store_root.join(format!("{}.json", spec.id));
        let mut record: Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        record[field] = if field == "execution_may_have_run" {
            json!(false)
        } else {
            Value::Null
        };
        let changed = serde_json::to_vec(&record).unwrap();
        fs::write(&path, &changed).unwrap();
        assert!(
            PreparedOperationStore::open(&fixture.store_root).is_err(),
            "field: {field}"
        );
        assert_eq!(fs::read(&path).unwrap(), changed);
    }
}

#[test]
fn recovered_uncertain_record_cannot_claim_that_execution_was_impossible() {
    let fixture = Fixture::new();
    let spec = fixture.spec(87, 1);
    let store = fixture.open();
    store.submit(spec.clone()).unwrap();
    uncertain(store.claim_next().unwrap().unwrap());
    drop(store);
    let path = fixture.store_root.join(format!("{}.json", spec.id));
    let mut record: Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
    record["execution_may_have_run"] = json!(false);
    fs::write(&path, serde_json::to_vec(&record).unwrap()).unwrap();
    assert!(PreparedOperationStore::open(&fixture.store_root).is_err());
}

#[test]
fn oversized_state_file_is_rejected_before_reading_its_payload() {
    let fixture = Fixture::new();
    let spec = fixture.spec(88, 1);
    let store = fixture.open();
    store.submit(spec.clone()).unwrap();
    drop(store);
    let path = fixture.store_root.join(format!("{}.json", spec.id));
    let oversized = MAX_RECORD_BYTES as u64 + 1;
    OpenOptions::new()
        .write(true)
        .open(&path)
        .unwrap()
        .set_len(oversized)
        .unwrap();
    assert!(PreparedOperationStore::open(&fixture.store_root).is_err());
    assert_eq!(fs::metadata(path).unwrap().len(), oversized);
}

#[test]
fn invalid_identity_and_request_sizes_never_enter_the_queue() {
    let fixture = Fixture::new();
    let spec = fixture.spec(90, 1);
    let store = fixture.open();
    for id in [
        "".to_owned(),
        "a".repeat(31),
        "a".repeat(33),
        "AB".repeat(16),
        "../escape".to_owned(),
    ] {
        let mut invalid = spec.clone();
        invalid.id = id;
        assert!(store.submit(invalid).is_err());
    }
    for pin in [
        "".to_owned(),
        "ab".repeat(31),
        "AB".repeat(32),
        "00".repeat(32),
    ] {
        let mut invalid = spec.clone();
        invalid.worker_spki_sha256 = pin;
        assert!(store.submit(invalid).is_err());
    }
    for worker in ["".to_owned(), "worker\nother".to_owned(), "a".repeat(1025)] {
        let mut invalid = spec.clone();
        invalid.worker = worker;
        assert!(store.submit(invalid).is_err());
    }
    for path in [
        PathBuf::from("relative-output"),
        fixture.root.join("../escape"),
        fixture.root.join("x".repeat(4097)),
    ] {
        let mut invalid = spec.clone();
        invalid.output = path;
        assert!(store.submit(invalid).is_err());
    }
    let mut request = prepared_request(&spec);
    request["oversized_extension"] = json!("x".repeat(1024 * 1024));
    fs::write(
        spec.bundle.join("request.json"),
        serde_json::to_vec(&request).unwrap(),
    )
    .unwrap();
    assert!(store.submit(spec.clone()).is_err());
    assert!(store.status(&spec.id).unwrap().is_none());
    assert!(store.claim_next().unwrap().is_none());
}

#[cfg(unix)]
#[test]
fn store_paths_are_private_and_symlink_aliases_are_rejected() {
    use std::os::unix::fs::{PermissionsExt, symlink};

    let fixture = Fixture::new();
    assert!(PreparedOperationStore::open(Path::new("relative-store")).is_err());
    assert!(PreparedOperationStore::open(&fixture.root.join("missing/store")).is_err());
    let public = fixture.root.join("public-store");
    fs::create_dir(&public).unwrap();
    fs::set_permissions(&public, fs::Permissions::from_mode(0o755)).unwrap();
    assert!(PreparedOperationStore::open(&public).is_err());

    let spec = fixture.spec(100, 1);
    let store = fixture.open();
    store.submit(spec.clone()).unwrap();
    for (path, expected) in [
        (fixture.store_root.clone(), 0o700),
        (fixture.store_root.join(format!("{}.json", spec.id)), 0o600),
        (fixture.store_root.join(".operations.lock"), 0o600),
    ] {
        assert_eq!(
            fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            expected
        );
    }
    let alias = fixture.root.join("alias-store");
    symlink(&fixture.store_root, &alias).unwrap();
    assert!(PreparedOperationStore::open(&alias).is_err());

    let second = fixture.spec(101, 2);
    let bundle_alias = fixture.root.join("alias-bundle");
    symlink(&second.bundle, &bundle_alias).unwrap();
    let mut invalid = second.clone();
    invalid.bundle = bundle_alias;
    assert!(store.submit(invalid).is_err());
    let output_alias = fixture.root.join("alias-parent");
    symlink(&fixture.root, &output_alias).unwrap();
    let mut invalid = second;
    invalid.output = output_alias.join("new-output");
    assert!(store.submit(invalid).is_err());

    let third = fixture.spec(102, 3);
    let request = third.bundle.join("request.json");
    let retained = third.bundle.join("retained-request.json");
    fs::rename(&request, &retained).unwrap();
    symlink(&retained, &request).unwrap();
    assert!(store.submit(third).is_err());
}
