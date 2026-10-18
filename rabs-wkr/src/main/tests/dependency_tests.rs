//! The production decoder and session admission gates, without a fake compiler
//! result. Real namespace/compiler execution is exercised in process_tree_linux.
use super::*;
use serde_json::{Value, json};

fn context() -> Value {
    json!({
        "version":DEPENDENCY_CONTEXT_VERSION,
        "source_root":"/home/user/registry/package",
        "cwd":"/home/user/registry/package",
        "toolchain_root":"/home/user/toolchains/pinned",
        "compiler":"/home/user/toolchains/pinned/bin/rustc",
        "out_dir":"/work/target/debug/deps",
        "dependency_dirs":["/work/target/debug/deps"],
        "env":[["DEPENDENCY_FLAVOR","spaces \"quotes\" $HOME\n雪"],["EXPLICIT_EMPTY",""]],
        "runtime_cohort_sha256":"ab".repeat(32),
    })
}

fn dependency_request() -> Value {
    use rabs_sandbox::source_transfer::{SourceFile, SourceManifest};
    let manifest = SourceManifest::new(vec![SourceFile {
        path: "src/lib.rs".to_owned(),
        len: 1,
        sha256: [1; 32],
        executable: false,
    }])
    .unwrap();
    json!({
        "kind":"canonical-exec", "request_id":712,
        "program":"/home/user/toolchains/pinned/bin/rustc",
        "args":["--crate-name","leaf","--crate-type","lib","--emit=dep-info,metadata","src/lib.rs"],
        "source_manifest":{"files":[{"path":"src/lib.rs","bytes":1,"sha256":"01".repeat(32),"executable":false}],
            "manifest_sha256":rabs_wkr::source_transfer::hex(&manifest.digest())},
        "toolchain_transfer":TOOLCHAIN_TRANSFER_VERSION,
        "toolchain_identity":{"version":rabs_sandbox::toolchain_dataset::TOOLCHAIN_DATASET_VERSION,
            "sha256":"cd".repeat(32),"files":1,"bytes":1},
        "artifacts":{"unit":"leaf","files":["leaf.d","libleaf.rmeta"]},
        "dependency_context":context(),
    })
}

#[test]
fn complete_dependency_decode_preserves_paths_values_and_input_owner_slots() {
    let original = dependency_request();
    let parsed = parse_exec_request(&original).unwrap();
    let context = parsed.dependency_context.as_ref().unwrap();
    assert_eq!(parsed.program, context.compiler());
    assert_eq!(context.cwd(), "/home/user/registry/package");
    assert_eq!(context.out_dir(), "/work/target/debug/deps");
    assert_eq!(
        context.env(),
        &[
            (
                "DEPENDENCY_FLAVOR".to_owned(),
                "spaces \"quotes\" $HOME\n雪".to_owned()
            ),
            ("EXPLICIT_EMPTY".to_owned(), String::new()),
        ]
    );
    assert!(!context.env().iter().any(|(name, _)| name == "NUM_JOBS"));
    assert!(parsed.toolchain_backing.is_empty() && parsed.workspace_backing.is_empty());
    assert!(parsed.toolchain_identity.is_some());
    assert_eq!(
        original,
        dependency_request(),
        "decoder does not project wire identity in place"
    );
}

#[test]
fn cargo_loader_parent_is_explicit_and_old_context_versions_cannot_ignore_it() {
    let mut request = dependency_request();
    request["dependency_context"]["loader_dirs"] =
        json!(["/work/target/debug/deps", "/work/target/debug"]);
    let value = "/work/target/debug/deps:/work/target/debug:/home/user/toolchains/pinned/lib";
    request["dependency_context"]["env"]
        .as_array_mut()
        .unwrap()
        .push(json!(["LD_LIBRARY_PATH", value]));
    let parsed = parse_exec_request(&request).unwrap();
    let context = parsed.dependency_context.unwrap();
    assert_eq!(
        context.loader_dirs(),
        &[
            "/work/target/debug".to_owned(),
            "/work/target/debug/deps".to_owned()
        ]
    );
    assert!(
        context
            .env()
            .contains(&("LD_LIBRARY_PATH".to_owned(), value.to_owned()))
    );
    request["dependency_context"]["version"] = json!("dependency-exec-v1");
    assert!(
        parse_exec_request(&request).is_err(),
        "an old worker contract cannot represent loader parents"
    );
    request["dependency_context"]["version"] = json!(DEPENDENCY_CONTEXT_VERSION);
    for invalid in [
        Value::Null,
        json!(["/work/target/debug/deps/nested"]),
        json!(["/usr/lib"]),
        json!([42]),
    ] {
        request["dependency_context"]["loader_dirs"] = invalid;
        assert!(parse_exec_request(&request).is_err());
    }
}

#[test]
fn dependency_context_requires_exact_negotiation_and_complete_authenticated_transfer() {
    let grant =
        json!({"kind":"session-ok","dependency_context":DEPENDENCY_CONTEXT_VERSION}).to_string();
    assert!(!dependency_context_selection("{}", true, true, true, true, true).unwrap());
    assert!(dependency_context_selection(&grant, true, true, true, true, true).unwrap());
    for flags in [
        [false, true, true, true, true],
        [true, false, true, true, true],
        [true, true, false, true, true],
        [true, true, true, false, true],
        [true, true, true, true, false],
    ] {
        assert!(
            dependency_context_selection(&grant, flags[0], flags[1], flags[2], flags[3], flags[4])
                .is_err()
        );
    }
    for bad in [Value::Null, json!(true), json!("dependency-exec-v999")] {
        assert!(
            dependency_context_selection(
                &json!({"dependency_context":bad}).to_string(),
                true,
                true,
                true,
                true,
                true
            )
            .is_err()
        );
    }
}

#[test]
fn dependency_decoder_refuses_unowned_inputs_ambiguous_context_and_unmodeled_loader() {
    for (key, value) in [
        (
            "command_context",
            json!({"version":"env-cwd-v1","cwd":"/__rabs/workspace","env":{}}),
        ),
        (
            "workspace_backing",
            json!("/private/caller-selected-source"),
        ),
        (
            "toolchain_backing",
            json!("/private/caller-selected-toolchain"),
        ),
        ("program", json!("/bin/sh")),
        ("dependency_context", Value::Null),
    ] {
        let mut request = dependency_request();
        request[key] = value;
        assert!(parse_exec_request(&request).is_err(), "{key}");
    }
    for removed in [
        "source_manifest",
        "toolchain_transfer",
        "toolchain_identity",
    ] {
        let mut request = dependency_request();
        request.as_object_mut().unwrap().remove(removed);
        assert!(parse_exec_request(&request).is_err(), "{removed}");
    }
    for (key, value) in [
        ("version", json!("dependency-exec-v999")),
        ("extra_backing", json!("/private/hidden")),
        ("runtime_cohort_sha256", json!("AB".repeat(32))),
        ("env", json!([["SECRET", "first"], ["SECRET", "second"]])),
        ("env", json!([["LD_PRELOAD", "/secret/control"]])),
    ] {
        let mut request = dependency_request();
        request["dependency_context"][key] = value;
        let reason = parse_exec_request(&request).unwrap_err();
        assert!(
            !reason.contains("/secret/control")
                && !reason.contains("first")
                && !reason.contains("second")
        );
    }
}

#[cfg(unix)]
#[test]
fn unnegotiated_dependency_request_never_burns_durable_admission() {
    let root = private_root();
    let mut journal = WorkerJournal::open(root.path(), "session-test", "coord").unwrap();
    let mut wire = Wire::default();
    let peer = wire.clone();
    peer.frame(dependency_request());
    peer.frame(json!({"kind":"request-status","request_id":712}));
    peer.close();
    wait(drive_session(
        &mut wire,
        &report(),
        false,
        Some(&mut journal),
        false,
        |_, _, _| panic!("unnegotiated dependency reached executor"),
        pressure,
    ))
    .unwrap();
    let replies = peer.replies();
    assert_eq!(replies[0]["kind"], "error");
    assert_eq!(replies[0]["reason"], "dependency context not negotiated");
    assert_eq!(replies[1]["status"], "unknown");
    assert_eq!(journal.high_water(), None);
    let hello: Value = serde_json::from_str(&worker_hello(&report(), &journal)).unwrap();
    assert_eq!(
        hello["dependency_contexts"],
        json!([DEPENDENCY_CONTEXT_VERSION])
    );
}

#[cfg(unix)]
#[test]
fn retained_dependency_result_resumes_without_execution_or_input_grants() {
    assert_retained_dependency_resume(DEPENDENCY_CONTEXT_VERSION);
}

#[cfg(unix)]
#[test]
fn retained_v1_dependency_result_remains_recoverable_after_context_upgrade() {
    assert_retained_dependency_resume("dependency-exec-v1");
}

#[cfg(unix)]
fn assert_retained_dependency_resume(version: &str) {
    let root = private_root();
    let mut original = dependency_request();
    // This fixture seals known bytes to exercise result recovery only. It does
    // not claim rustc execution; the real compiler oracle is separate.
    original["artifacts"] = json!({"unit":"leaf","files":["lib.rlib"]});
    let execution = parse_exec_request(&original).unwrap();
    // Simulate bytes durably retained under the older accepted execution
    // context. The current worker must reject it for new execution, while the
    // exact saved fingerprint still authorizes retrieval-only recovery.
    original["dependency_context"]["version"] = json!(version);
    if version != DEPENDENCY_CONTEXT_VERSION {
        assert!(parse_exec_request(&original).is_err());
    }
    let id = original["request_id"].as_u64().unwrap();
    {
        let mut journal = WorkerJournal::open(root.path(), "session-test", "coord").unwrap();
        assert_eq!(
            journal.admit(&original, DEFAULT_EXECUTION_TIMEOUT).unwrap(),
            None
        );
        let mut task = retained_launch(
            root.path(),
            execution,
            DEFAULT_EXECUTION_TIMEOUT,
            artifacts::parse_plan(&original).unwrap(),
        )
        .unwrap();
        let completion = wait(task.wait());
        assert!(completion.is_ok(), "{completion:?}");
        journal_completion(
            Some(&mut journal),
            id,
            &completion,
            task.retained_result_digest().as_deref(),
        )
        .unwrap();
        assert!(journal.has_retained_result());
    }
    let mut journal = WorkerJournal::open(root.path(), "session-test", "coord").unwrap();
    journal.authorize_result_recipient(ResultRecipient::TlsSpki([7; 32]));
    let mut wire = Wire::default();
    let peer = wire.clone();
    let mut changed = original.clone();
    changed["dependency_context"]["cwd"] = json!("/home/user/registry/package/src");
    peer.frame(json!({"kind":"result-resume","request_id":id,"request":changed}));
    peer.frame(json!({"kind":"result-resume","request_id":id,"request":original}));
    let report = report();
    // This production compatibility wrapper selects no source, toolchain,
    // dependency context or execution-lease grant. Recovery needs only the
    // exact original request and authorized retained-result recipient.
    let mut driver = Box::pin(drive_session(
        &mut wire,
        &report,
        true,
        Some(&mut journal),
        true,
        |_, _, _| panic!("retained dependency recovery invoked execution"),
        pressure,
    ));
    pump(driver.as_mut(), &peer, 2);
    assert_eq!(peer.replies()[0]["kind"], "error");
    let resumed = peer.replies()[1].clone();
    assert_eq!(resumed["kind"], "exec-result");
    assert_eq!(resumed["resumed"], true);
    peer.frame(output_read(id, "stdout", 1, 3));
    peer.frame(
        json!({"kind":"artifact-read","request_id":id,"name":"lib.rlib","offset":0,"max_bytes":64}),
    );
    pump(driver.as_mut(), &peer, 4);
    assert_eq!(peer.replies()[2]["data_hex"], "00ff42");
    assert_eq!(peer.replies()[3]["data_hex"], "6172636869766500ff");
    peer.frame(output_ack(id));
    peer.frame(json!({"kind":"artifact-ack","request_id":id,
        "manifest_sha256":resumed["artifact_manifest"]["manifest_sha256"],
        "total_bytes":resumed["artifact_manifest"]["total_bytes"]}));
    wait(driver).unwrap();
    assert_eq!(
        journal.status(id)["receipt"]["retained_result_released"],
        true
    );
}
