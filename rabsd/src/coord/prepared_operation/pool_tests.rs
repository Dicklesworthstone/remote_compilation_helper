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
        Self::capture(json!({
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
        }))
    }

    fn cargo(command: &str) -> Self {
        Self::capture(Self::cargo_template(command))
    }

    fn cargo_template(command: &str) -> Value {
        json!({
            "kind":"canonical-exec", "request_id":"allocate",
            "program":if command == "clippy" {
                "/__rabs/toolchain/bin/cargo-clippy"
            } else {
                "/__rabs/toolchain/bin/cargo"
            },
            "toolchain_backing":"/opt/pool-fixture",
            "toolchain_identity":{
                "version":"toolchain-dataset-v1", "sha256":"ab".repeat(32),
                "files":1, "bytes":4,
            },
            "source_files":["Cargo.toml", "Cargo.lock", ".cargo/config.toml", "lib.rs"],
            "args":[command, "--workspace", "--frozen", "--offline",
                "--message-format=json", "--manifest-path=/__rabs/workspace/Cargo.toml",
                "--target-dir=/__rabs/out/cargo"],
            "command_context":{
                "version":"env-cwd-v1", "cwd":"/__rabs/workspace",
                "env":{"CARGO":"/__rabs/toolchain/bin/cargo",
                    "RUSTC":"/__rabs/toolchain/bin/rustc", "RUSTFLAGS":"-C debuginfo=0"},
            },
            "artifacts":{"unit":"cargo", "files":[], "tree":"tree-files-v1",
                "cargo":if command == "test" { "cargo-test-json-v1" } else { "cargo-json-v1" }},
            "timeout_ms":10000,
        })
    }

    fn capture(request: Value) -> Self {
        let owner = tempfile::tempdir().unwrap();
        let root = owner.path().canonicalize().unwrap();
        let source = root.join("source");
        let bundle = root.join("bundle");
        fs::create_dir(&source).unwrap();
        fs::write(source.join("lib.rs"), b"pub fn value() -> u32 { 42 }\n").unwrap();
        if request["artifacts"].get("cargo").is_some() {
            fs::write(source.join("Cargo.toml"),
                b"[package]\nname=\"pool-fixture\"\nversion=\"0.1.0\"\nedition=\"2024\"\n[lib]\npath=\"lib.rs\"\n").unwrap();
            fs::write(
                source.join("Cargo.lock"),
                b"version = 4\n[[package]]\nname=\"pool-fixture\"\nversion=\"0.1.0\"\n",
            )
            .unwrap();
            fs::create_dir(source.join(".cargo")).unwrap();
            fs::write(
                source.join(".cargo/config.toml"),
                b"[env]\nAPP_MODE=\"one\"\n",
            )
            .unwrap();
        }
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

/// Supply adapter-shaped terminal evidence to the real durable queue. This
/// exercises placement and recovery bookkeeping, not TLS or target retention.
fn completed(
    mut claim: OperationClaim,
    request_id: u64,
    exit_code: i32,
    stop: Value,
    ack: bool,
) -> OperationStatus {
    if claim.needs_request_allocation() {
        claim.bind_request_id(request_id).unwrap();
    }
    let installed = if exit_code == 0 && stop.is_null() {
        json!({
            "kind":"worker-output-install", "directory":claim.spec().output,
            "publication_authorized":false, "reexecute":false,
            "files":0, "total_bytes":0, "reused":false,
        })
    } else {
        Value::Null
    };
    let digest = Sha256::digest(serde_json::to_vec(claim.request()).unwrap())
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    let result = json!({
        "delivery":{
            "receipt":{
                "request_id":claim.request()["request_id"], "request_sha256":digest,
                "worker_id":claim.spec().worker,
                "worker_spki_sha256":claim.spec().worker_spki_sha256,
                "transport_authenticated":true, "publication_authorized":false,
                "exit_code":exit_code, "stop_reason":stop,
            },
            "acknowledgments_confirmed":ack,
        },
        "installed_outputs":installed, "publication_authorized":false,
    });
    claim
        .finish(OperationOutcome::Completed { result })
        .unwrap()
}

#[test]
fn cargo_locality_follows_resolved_success_and_ordinary_failure_across_fresh_captures() {
    for command in ["build", "check", "clippy", "test"] {
        for exit_code in [0, 101] {
            let fixture = Fixture::cargo(command);
            let store = fixture.open();
            store.submit_allocated(fixture.singleton(1, 2)).unwrap();
            completed(
                store.claim_next().unwrap().unwrap(),
                9001,
                exit_code,
                Value::Null,
                true,
            );
            let mut next = fixture.spec(2, 2);
            next.bundle = fixture.root.join("fresh-capture");
            prepare_source_template(
                &fixture.root.join("source"),
                &Fixture::cargo_template(command),
                &next.bundle,
            )
            .unwrap();
            let selected = store.submit_allocated_pool(next).unwrap();
            assert_eq!(selected.worker, "worker-2", "{command}, exit {exit_code}");
            assert_eq!(selected.request_id, None);
            assert_eq!(selected.mode, "execute");
            assert!(!selected.outputs_installed);
            let claim = store.claim_next().unwrap().unwrap();
            assert!(claim.needs_request_allocation());
            no_dispatch(claim);
        }
    }
}

#[test]
fn cargo_locality_preserves_load_priority_then_prefers_the_most_recent_match() {
    let fixture = Fixture::cargo("build");
    let store = fixture.open();
    store.submit_allocated(fixture.singleton(1, 2)).unwrap();
    completed(
        store.claim_next().unwrap().unwrap(),
        9001,
        0,
        Value::Null,
        true,
    );
    store.submit_allocated(fixture.singleton(2, 2)).unwrap();
    let active = store.claim_next().unwrap().unwrap();
    let first = fixture.spec(3, 2);
    assert_eq!(
        store.submit_allocated_pool(first.clone()).unwrap().worker,
        "worker-1"
    );
    // Equal pending loads now favor the worker with matching captured inputs.
    let second = fixture.spec(4, 2);
    assert_eq!(
        store.submit_allocated_pool(second.clone()).unwrap().worker,
        "worker-2"
    );
    store.cancel(&first.id).unwrap();
    store.cancel(&second.id).unwrap();
    no_dispatch(active);

    store.submit_allocated(fixture.singleton(5, 1)).unwrap();
    completed(
        store.claim_next().unwrap().unwrap(),
        9005,
        0,
        Value::Null,
        true,
    );
    let mut next = fixture.spec(6, 2);
    next.workers.reverse();
    assert_eq!(
        store.submit_allocated_pool(next).unwrap().worker,
        "worker-1"
    );
}

#[test]
fn cargo_locality_follows_source_edits_and_build_check_test_selections() {
    for (previous, current) in [
        ("build", "build"),
        ("build", "check"),
        ("check", "test"),
        ("test", "build"),
        ("clippy", "clippy"),
    ] {
        for exit_code in [0, 101] {
            let fixture = Fixture::cargo(previous);
            let store = fixture.open();
            let original = store.submit_allocated(fixture.singleton(1, 2)).unwrap();
            completed(
                store.claim_next().unwrap().unwrap(),
                9001,
                exit_code,
                Value::Null,
                true,
            );
            let source = fixture.root.join("source");
            fs::write(source.join("lib.rs"), b"pub fn value() -> u32 { 43 }\n").unwrap();
            let mut request = Fixture::cargo_template(current);
            if current != "clippy" {
                request["args"].as_array_mut().unwrap().push(json!("--lib"));
            }
            let mut next = fixture.spec(2, 2);
            next.bundle = fixture.root.join("edited-capture");
            prepare_source_template(&source, &request, &next.bundle).unwrap();
            let selected = store.submit_allocated_pool(next).unwrap();
            assert_eq!(selected.worker, "worker-2", "{previous} -> {current}");
            assert_ne!(selected.request_sha256, original.request_sha256);
            assert_eq!(selected.request_id, None);
            assert!(!selected.outputs_installed);
            let claim = store.claim_next().unwrap().unwrap();
            assert!(claim.needs_request_allocation());
            assert_eq!(claim.request()["args"], request["args"]);
            assert_eq!(claim.request()["artifacts"], request["artifacts"]);
            let source_file = claim.request()["source_manifest"]["files"]
                .as_array()
                .unwrap()
                .iter()
                .find(|file| file["path"] == "lib.rs")
                .unwrap();
            let changed_digest = Sha256::digest(b"pub fn value() -> u32 { 43 }\n")
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect::<String>();
            assert_eq!(source_file["sha256"], changed_digest);
            no_dispatch(claim);
        }
    }
}

#[test]
fn exact_cargo_locality_precedes_newer_compatible_history_but_load_still_wins() {
    let fixture = Fixture::cargo("build");
    let store = fixture.open();
    store.submit_allocated(fixture.singleton(1, 2)).unwrap();
    completed(
        store.claim_next().unwrap().unwrap(),
        9001,
        0,
        Value::Null,
        true,
    );
    let source = fixture.root.join("source");
    fs::write(source.join("lib.rs"), b"pub fn value() -> u32 { 43 }\n").unwrap();
    let mut newer = fixture.singleton(2, 1);
    newer.bundle = fixture.root.join("newer-capture");
    prepare_source_template(&source, &Fixture::cargo_template("build"), &newer.bundle).unwrap();
    store.submit_allocated(newer).unwrap();
    completed(
        store.claim_next().unwrap().unwrap(),
        9002,
        0,
        Value::Null,
        true,
    );

    // The original retained bundle is still exact, even though the live source
    // now differs. A newer compatible target must not displace that exact hit.
    let exact = fixture.spec(3, 2);
    assert_eq!(
        store.submit_allocated_pool(exact.clone()).unwrap().worker,
        "worker-2"
    );
    let active = store.claim_next().unwrap().unwrap();
    assert_eq!(
        store
            .submit_allocated_pool(fixture.spec(4, 2))
            .unwrap()
            .worker,
        "worker-1",
        "a loaded exact worker must not displace an idle compatible worker"
    );
    store.cancel(&fixture.spec(4, 2).id).unwrap();
    no_dispatch(active);

    fs::write(source.join("lib.rs"), b"pub fn value() -> u32 { 44 }\n").unwrap();
    let mut edited = fixture.spec(5, 2);
    edited.bundle = fixture.root.join("latest-capture");
    prepare_source_template(&source, &Fixture::cargo_template("build"), &edited.bundle).unwrap();
    assert_eq!(
        store.submit_allocated_pool(edited).unwrap().worker,
        "worker-1",
        "recency breaks ties between compatible targets"
    );
}

#[test]
fn cargo_locality_requires_exact_immutable_inputs_and_command_controls() {
    for change in 1..10 {
        let fixture = Fixture::cargo("build");
        let store = fixture.open();
        store.submit_allocated(fixture.singleton(1, 2)).unwrap();
        completed(
            store.claim_next().unwrap().unwrap(),
            9001,
            0,
            Value::Null,
            true,
        );
        let mut request = Fixture::cargo_template("build");
        let source = fixture.root.join("source");
        match change {
            1 => fs::write(
                source.join("Cargo.toml"),
                b"[package]\nname=\"pool-fixture\"\nversion=\"0.2.0\"\n[lib]\npath=\"lib.rs\"\n",
            )
            .unwrap(),
            2 => fs::write(source.join("Cargo.lock"), b"version = 4\n# changed lock\n").unwrap(),
            3 => fs::write(
                source.join(".cargo/config.toml"),
                b"[env]\nAPP_MODE=\"two\"\n",
            )
            .unwrap(),
            4 => request["command_context"]["env"]["RUSTFLAGS"] = json!("-C debuginfo=2"),
            5 => request["args"]
                .as_array_mut()
                .unwrap()
                .push(json!("--release")),
            6 => request["toolchain_identity"]["sha256"] = json!("cd".repeat(32)),
            7 => request["artifacts"]["files"] = json!(["extra-output"]),
            8 => request["jobserver_grant"] = json!(2),
            9 => request["future_execution_control"] = json!({"value":true}),
            _ => unreachable!(),
        }
        let mut next = fixture.spec(2, 2);
        next.bundle = fixture.root.join("changed-capture");
        prepare_source_template(&source, &request, &next.bundle).unwrap();
        assert_eq!(
            store.submit_allocated_pool(next).unwrap().worker,
            "worker-1",
            "changed control {change}",
        );
    }
}

#[test]
fn compatible_cargo_locality_keeps_clippy_lints_selections_and_unknown_arguments_exact() {
    for change in 0..5 {
        let fixture = Fixture::cargo("clippy");
        let store = fixture.open();
        store.submit_allocated(fixture.singleton(1, 2)).unwrap();
        completed(
            store.claim_next().unwrap().unwrap(),
            9001,
            0,
            Value::Null,
            true,
        );
        let mut request = Fixture::cargo_template("clippy");
        match change {
            0 => request = Fixture::cargo_template("check"),
            1 => request["args"].as_array_mut().unwrap().push(json!("--lib")),
            2 => request["args"].as_array_mut().unwrap().extend([
                json!("--"),
                json!("-D"),
                json!("warnings"),
            ]),
            3 => request["args"]
                .as_array_mut()
                .unwrap()
                .push(json!("--no-deps")),
            4 => request["args"]
                .as_array_mut()
                .unwrap()
                .push(json!("--future-cargo-option")),
            _ => unreachable!(),
        }
        let source = fixture.root.join("source");
        fs::write(source.join("lib.rs"), b"pub fn value() -> u32 { 43 }\n").unwrap();
        let mut next = fixture.spec(2, 2);
        next.bundle = fixture.root.join("changed-clippy-capture");
        prepare_source_template(&source, &request, &next.bundle).unwrap();
        assert_eq!(
            store.submit_allocated_pool(next).unwrap().worker,
            "worker-1",
            "changed Clippy control {change}",
        );
    }
}

#[test]
fn source_edit_locality_binds_isolated_dependency_cache_and_refuses_legacy_projection_edits() {
    use rabs_sandbox::cargo_home::{CARGO_HOME_SOURCE_VERSION, ISOLATED_CARGO_HOME_SOURCE_VERSION};

    for version in [
        ISOLATED_CARGO_HOME_SOURCE_VERSION,
        CARGO_HOME_SOURCE_VERSION,
    ] {
        for changed_cache in [false, true] {
            let fixture = Fixture::cargo("build");
            let source = fixture.root.join("source");
            let cache_path = "cache/registry/cache/test-index/dependency-0.1.0.crate";
            fs::create_dir_all(source.join("cache/registry/cache/test-index")).unwrap();
            fs::write(
                source.join(cache_path),
                b"first captured dependency archive",
            )
            .unwrap();
            let mut request = Fixture::cargo_template("build");
            request["cargo_home"] = json!({"version":version, "prefix":"cache"});
            request["source_files"]
                .as_array_mut()
                .unwrap()
                .push(json!(cache_path));
            let mut first = fixture.singleton(1, 2);
            first.bundle = fixture.root.join("first-home-capture");
            prepare_source_template(&source, &request, &first.bundle).unwrap();
            let store = fixture.open();
            store.submit_allocated(first).unwrap();
            completed(
                store.claim_next().unwrap().unwrap(),
                9001,
                0,
                Value::Null,
                true,
            );
            fs::write(source.join("lib.rs"), b"pub fn value() -> u32 { 43 }\n").unwrap();
            if changed_cache {
                fs::write(
                    source.join(cache_path),
                    b"changed captured dependency archive",
                )
                .unwrap();
            }
            let mut next = fixture.spec(2, 2);
            next.bundle = fixture.root.join("next-home-capture");
            prepare_source_template(&source, &request, &next.bundle).unwrap();
            let expected = if version == ISOLATED_CARGO_HOME_SOURCE_VERSION && !changed_cache {
                "worker-2"
            } else {
                "worker-1"
            };
            assert_eq!(
                store.submit_allocated_pool(next).unwrap().worker,
                expected,
                "{version}, cache changed: {changed_cache}",
            );
        }
    }
}

#[test]
fn source_edit_locality_preserves_private_incremental_policy_across_test_mode() {
    use rabs_sandbox::cargo_artifacts::{
        CARGO_PRIVATE_INCREMENTAL_ARTIFACTS_VERSION,
        CARGO_PRIVATE_INCREMENTAL_TEST_ARTIFACTS_VERSION,
    };

    for (prior_incremental, next_incremental) in [(true, true), (false, true), (true, false)] {
        let fixture = Fixture::cargo("build");
        let source = fixture.root.join("source");
        let request = |command: &str, incremental: bool| {
            let mut request = Fixture::cargo_template(command);
            request["command_context"]["env"]
                .as_object_mut()
                .unwrap()
                .remove("RUSTFLAGS");
            request["command_context"]["env"]["CARGO_INCREMENTAL"] =
                json!(if incremental { "1" } else { "0" });
            if incremental {
                request["artifacts"]["cargo"] = json!(if command == "test" {
                    CARGO_PRIVATE_INCREMENTAL_TEST_ARTIFACTS_VERSION
                } else {
                    CARGO_PRIVATE_INCREMENTAL_ARTIFACTS_VERSION
                });
            }
            request
        };
        let mut first = fixture.singleton(1, 2);
        first.bundle = fixture.root.join("first-incremental-capture");
        prepare_source_template(&source, &request("build", prior_incremental), &first.bundle)
            .unwrap();
        let store = fixture.open();
        store.submit_allocated(first).unwrap();
        completed(
            store.claim_next().unwrap().unwrap(),
            9001,
            0,
            Value::Null,
            true,
        );
        fs::write(source.join("lib.rs"), b"pub fn value() -> u32 { 43 }\n").unwrap();
        let mut next = fixture.spec(2, 2);
        next.bundle = fixture.root.join("next-incremental-capture");
        prepare_source_template(&source, &request("test", next_incremental), &next.bundle).unwrap();
        assert_eq!(
            store.submit_allocated_pool(next).unwrap().worker,
            if prior_incremental == next_incremental {
                "worker-2"
            } else {
                "worker-1"
            },
            "incremental {prior_incremental} -> {next_incremental}",
        );
    }
}

#[test]
fn cargo_locality_requires_the_exact_worker_endpoint_identity_and_pin() {
    for change in 0..3 {
        let fixture = Fixture::cargo("build");
        let store = fixture.open();
        store.submit_allocated(fixture.singleton(1, 2)).unwrap();
        completed(
            store.claim_next().unwrap().unwrap(),
            9001,
            0,
            Value::Null,
            true,
        );
        let mut next = fixture.spec(2, 2);
        match change {
            0 => next.workers[1].address = "127.0.0.1:33002".into(),
            1 => next.workers[1].worker = "replacement-worker".into(),
            2 => next.workers[1].worker_spki_sha256 = "cd".repeat(32),
            _ => unreachable!(),
        }
        assert_eq!(
            store.submit_allocated_pool(next).unwrap().worker,
            "worker-1"
        );
    }
}

#[test]
fn cargo_locality_ignores_nondispatched_unresolved_cancelled_and_stopped_attempts() {
    for outcome in 0..7 {
        let fixture = Fixture::cargo("build");
        let store = fixture.open();
        store.submit_allocated(fixture.singleton(1, 2)).unwrap();
        let claim = store.claim_next().unwrap().unwrap();
        match outcome {
            0 => no_dispatch(claim),
            1 => interrupted(claim, 9001),
            2 => {
                completed(claim, 9001, 0, Value::Null, false);
            }
            3 => {
                completed(claim, 9001, 130, json!("cancelled"), true);
            }
            4 => {
                completed(claim, 9001, 124, json!("timeout"), true);
            }
            5 => {
                completed(claim, 9001, 137, Value::Null, true);
            }
            6 => {
                let mut claim = claim;
                claim.bind_request_id(9001).unwrap();
                store.cancel(&fixture.singleton(1, 2).id).unwrap();
                completed(claim, 9001, 0, Value::Null, true);
            }
            _ => unreachable!(),
        }
        assert_eq!(
            store
                .submit_allocated_pool(fixture.spec(2, 2))
                .unwrap()
                .worker,
            "worker-1",
            "ineligible outcome {outcome}",
        );
    }
}

#[test]
fn cargo_locality_never_overrides_an_unresolved_workers_ownership() {
    let fixture = Fixture::cargo("build");
    let store = fixture.open();
    store.submit_allocated(fixture.singleton(1, 2)).unwrap();
    completed(
        store.claim_next().unwrap().unwrap(),
        9001,
        0,
        Value::Null,
        true,
    );
    store.submit_allocated(fixture.singleton(2, 2)).unwrap();
    interrupted(store.claim_next().unwrap().unwrap(), 9002);
    store.submit_allocated(fixture.singleton(3, 1)).unwrap();
    assert_eq!(
        store
            .submit_allocated_pool(fixture.spec(4, 2))
            .unwrap()
            .worker,
        "worker-1"
    );
}

#[test]
fn cargo_locality_uses_numeric_history_without_reusing_its_request_id() {
    let fixture = Fixture::cargo("build");
    let store = fixture.open();
    let mut request = Fixture::cargo_template("build");
    request["request_id"] = json!(9001);
    let mut first = fixture.singleton(1, 2);
    first.bundle = fixture.root.join("numeric-capture");
    crate::coord::source_delivery::prepare_source_bundle(
        &fixture.root.join("source"),
        &request,
        &first.bundle,
    )
    .unwrap();
    store.submit(first).unwrap();
    completed(
        store.claim_next().unwrap().unwrap(),
        9001,
        0,
        Value::Null,
        true,
    );
    let selected = store.submit_allocated_pool(fixture.spec(2, 2)).unwrap();
    assert_eq!(selected.worker, "worker-2");
    assert_eq!(selected.request_id, None);
}

#[test]
fn compatible_cargo_locality_survives_restart_without_reassigning_admitted_or_recovering_jobs() {
    let fixture = Fixture::cargo("build");
    let store = fixture.open();
    store.submit_allocated(fixture.singleton(1, 2)).unwrap();
    completed(
        store.claim_next().unwrap().unwrap(),
        9001,
        0,
        Value::Null,
        true,
    );
    drop(store);
    let store = fixture.open();
    let source = fixture.root.join("source");
    fs::write(source.join("lib.rs"), b"pub fn value() -> u32 { 43 }\n").unwrap();
    let mut selected_spec = fixture.spec(2, 2);
    selected_spec.bundle = fixture.root.join("after-restart-capture");
    prepare_source_template(
        &source,
        &Fixture::cargo_template("build"),
        &selected_spec.bundle,
    )
    .unwrap();
    let selected = store.submit_allocated_pool(selected_spec.clone()).unwrap();
    assert_eq!(selected.worker, "worker-2");
    let selected_claim = store.claim_next().unwrap().unwrap();
    store.submit_allocated(fixture.singleton(3, 1)).unwrap();
    completed(
        store.claim_next().unwrap().unwrap(),
        9003,
        0,
        Value::Null,
        true,
    );
    assert_eq!(
        store
            .submit_allocated_pool(selected_spec.clone())
            .unwrap()
            .worker,
        "worker-2"
    );
    interrupted(selected_claim, 9002);
    drop(store);
    let store = fixture.open();
    let retried = store.submit_allocated_pool(selected_spec.clone()).unwrap();
    assert_eq!(retried.worker, "worker-2");
    assert_eq!(retried.request_id, Some(9002));
    assert_eq!(retried.request_sha256, selected.request_sha256);
    store
        .resume(
            &selected_spec.id,
            fixture.root.join("resumed-delivery"),
            None,
        )
        .unwrap();
    let recovery = store.claim_next().unwrap().unwrap();
    assert_eq!(recovery.spec().worker, "worker-2");
    assert_eq!(recovery.request()["request_id"], 9002);
    assert!(!recovery.needs_request_allocation());
    drop(recovery);
}

#[test]
fn cargo_locality_expires_outside_the_bounded_recent_admission_window() {
    let fixture = Fixture::cargo("build");
    let store = fixture.open();
    store.submit_allocated(fixture.singleton(1, 2)).unwrap();
    completed(
        store.claim_next().unwrap().unwrap(),
        9001,
        0,
        Value::Null,
        true,
    );
    let window = u16::try_from(CARGO_LOCALITY_WINDOW).unwrap();
    for sequence in 2..=window {
        let spec = fixture.singleton(sequence, 1);
        store.submit_allocated(spec.clone()).unwrap();
        store.cancel(&spec.id).unwrap();
    }
    let boundary = fixture.spec(window + 1, 2);
    assert_eq!(
        store
            .submit_allocated_pool(boundary.clone())
            .unwrap()
            .worker,
        "worker-2"
    );
    store.cancel(&boundary.id).unwrap();
    assert_eq!(
        store
            .submit_allocated_pool(fixture.spec(window + 2, 2))
            .unwrap()
            .worker,
        "worker-1"
    );
}

#[test]
fn non_cargo_commands_keep_configured_order_when_workers_are_idle() {
    let fixture = Fixture::new();
    let store = fixture.open();
    store.submit_allocated(fixture.singleton(1, 2)).unwrap();
    completed(
        store.claim_next().unwrap().unwrap(),
        9001,
        0,
        Value::Null,
        true,
    );
    assert_eq!(
        store
            .submit_allocated_pool(fixture.spec(2, 2))
            .unwrap()
            .worker,
        "worker-1"
    );
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
