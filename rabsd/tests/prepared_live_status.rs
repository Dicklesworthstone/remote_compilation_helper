//! Real prepared-store and preview-registry integration, without a compiler or
//! worker connection. Injected observations are not execution/completion proof.
#![cfg(unix)]

use rabs_asupersync::stream_drain::preview::{MAX_PREVIEW_BYTES, OutputPreview, PreviewStream};
use rabsd::coord::prepared_operation::{
    OperationOutcome, OperationState, PreparedOperationSpec, PreparedOperationStore,
};
use rabsd::coord::source_delivery::prepare_source_bundle;
use serde_json::{Value, json};
use std::fs;
use std::path::PathBuf;
use std::sync::Arc;

struct Fixture {
    temporary: tempfile::TempDir,
    root: PathBuf,
    store: Arc<PreparedOperationStore>,
}

impl Fixture {
    fn new() -> Self {
        let temporary = tempfile::tempdir().unwrap();
        let root = temporary.path().canonicalize().unwrap();
        let store = PreparedOperationStore::open(&root.join("operations")).unwrap();
        Self { temporary, root, store }
    }

    fn submit(&self, number: u64) -> PreparedOperationSpec {
        let source = self.root.join(format!("source-{number}"));
        let bundle = self.root.join(format!("bundle-{number}"));
        fs::create_dir(&source).unwrap();
        fs::write(source.join("lib.rs"), b"pub fn answer() -> u32 { 42 }\n").unwrap();
        prepare_source_bundle(
            &source,
            &json!({
                "kind":"canonical-exec", "request_id":number,
                "program":"/__rabs/toolchain/bin/rustc",
                "toolchain_backing":"/opt/status-test-toolchain",
                "toolchain_identity":{
                    "version":"toolchain-dataset-v1", "sha256":"ab".repeat(32),
                    "files":1, "bytes":4,
                },
                "source_files":["lib.rs"],
                "args":["lib.rs", "--crate-type", "lib", "--emit", "metadata",
                    "-o", "/__rabs/out/compile/libfixture.rmeta"],
                "artifacts":{"unit":"compile", "files":["libfixture.rmeta"]},
                "timeout_ms":10000,
            }),
            &bundle,
        )
        .unwrap();
        let spec = PreparedOperationSpec {
            id: format!("{number:032x}"),
            address: "127.0.0.1:0".into(),
            worker: format!("worker-{number}"),
            worker_spki_sha256: format!("{number:064x}"),
            bundle,
            delivery: self.root.join(format!("delivery-{number}")),
            output: self.root.join(format!("output-{number}")),
        };
        self.store.submit(spec.clone()).unwrap();
        spec
    }

    fn status(&self, id: &str) -> Value {
        serde_json::to_value(self.store.status(id).unwrap().unwrap()).unwrap()
    }
}

fn segment(stream: PreviewStream, offset: u64, bytes: &[u8]) -> OutputPreview {
    OutputPreview {
        stream,
        offset,
        bytes: bytes.to_vec(),
        skipped_bytes: 0,
        observed_bytes: offset + bytes.len() as u64,
    }
}

#[test]
fn status_omits_unavailable_observations_and_preserves_lookup_errors() {
    let f = Fixture::new();
    let spec = f.submit(1);
    assert!(f.status(&spec.id).get("live_diagnostics").is_none());
    let claim = f.store.claim_next().unwrap().unwrap();
    assert!(f.status(&spec.id).get("live_diagnostics").is_none());
    assert!(f.store.status("not-an-id").is_err());
    assert!(f.store.status(&format!("{:032x}", 99)).unwrap().is_none());
    let observer = claim.preview_observer().unwrap();
    assert!(observer.observe(true, &[]));
    let status = f.status(&spec.id);
    assert_eq!(status["state"], "running");
    assert_eq!(status["live_diagnostics"]["available"], true);
    assert_eq!(status["live_diagnostics"]["segments"][0]["data_hex"], "");
    assert_eq!(status["live_diagnostics"]["segments"][1]["data_hex"], "");
    assert_eq!(status["live_diagnostics"]["complete"], false);
}

#[test]
fn status_reads_share_binary_tails_without_consuming_or_persisting_them() {
    let f = Fixture::new();
    let spec = f.submit(1);
    let claim = f.store.claim_next().unwrap().unwrap();
    let observer = claim.preview_observer().unwrap();
    let record_path = f.root.join("operations").join(format!("{}.json", spec.id));
    let before = fs::read(&record_path).unwrap();
    assert!(observer.observe(true, &[
        segment(PreviewStream::Stdout, 0, b"out\0\xff"),
        segment(PreviewStream::Stderr, 0, "雪".as_bytes()),
    ]));
    let first = f.status(&spec.id);
    assert_eq!(first, f.status(&spec.id));
    let diagnostics = &first["live_diagnostics"];
    assert_eq!(diagnostics["segments"][0]["data_hex"], "6f757400ff");
    assert_eq!(diagnostics["segments"][1]["data_hex"], "e99baa");
    assert_eq!(diagnostics["operation_id"], first["id"]);
    assert_eq!(diagnostics["request_sha256"], first["request_sha256"]);
    assert_eq!(diagnostics["attempt"], first["attempt"]);
    assert_eq!(*diagnostics, f.store.preview(
        &spec.id, first["request_sha256"].as_str().unwrap(), 1, 0, 0,
    ).unwrap());
    assert_eq!(before, fs::read(record_path).unwrap());
    assert!(!spec.delivery.exists());
    assert!(!spec.output.exists());
}

#[test]
fn status_bounds_each_stream_and_reports_the_same_gaps_as_follow() {
    let f = Fixture::new();
    let spec = f.submit(1);
    let claim = f.store.claim_next().unwrap().unwrap();
    let observer = claim.preview_observer().unwrap();
    for (offset, byte) in [(0, 0xff), (MAX_PREVIEW_BYTES as u64, 0xfe)] {
        assert!(observer.observe(true, &[
            segment(PreviewStream::Stdout, offset, &vec![byte; MAX_PREVIEW_BYTES]),
            segment(PreviewStream::Stderr, offset, &vec![byte; MAX_PREVIEW_BYTES]),
        ]));
    }
    let status = f.status(&spec.id);
    for row in status["live_diagnostics"]["segments"].as_array().unwrap() {
        assert_eq!(row["offset"], MAX_PREVIEW_BYTES);
        assert_eq!(row["skipped_bytes"], MAX_PREVIEW_BYTES);
        assert_eq!(row["next_offset"], 2 * MAX_PREVIEW_BYTES);
        assert_eq!(row["observed_bytes"], 2 * MAX_PREVIEW_BYTES);
        assert_eq!(row["data_hex"], "fe".repeat(MAX_PREVIEW_BYTES));
    }
    assert_eq!(status["live_diagnostics"]["complete"], false);
    assert_eq!(status["live_diagnostics"]["publication_authorized"], false);
    assert!(status["exit_code"].is_null());
    assert_eq!(status["succeeded"], false);
}

#[test]
fn concurrent_job_status_is_fenced_by_operation_request_and_attempt() {
    let f = Fixture::new();
    let a = f.submit(1);
    let b = f.submit(2);
    let first = f.store.claim_next().unwrap().unwrap();
    let second = f.store.claim_next().unwrap().unwrap();
    assert_eq!(first.spec().id, a.id);
    assert_eq!(second.spec().id, b.id);
    assert!(first.preview_observer().unwrap().observe(true, &[
        segment(PreviewStream::Stdout, 0, b"a"),
    ]));
    assert!(second.preview_observer().unwrap().observe(true, &[
        segment(PreviewStream::Stdout, 0, b"b"),
    ]));
    let one = f.status(&a.id);
    let two = f.status(&b.id);
    assert_ne!(one["request_sha256"], two["request_sha256"]);
    assert_eq!(one["live_diagnostics"]["segments"][0]["data_hex"], "61");
    assert_eq!(two["live_diagnostics"]["segments"][0]["data_hex"], "62");
    for status in [one, two] {
        assert_eq!(status["live_diagnostics"]["operation_id"], status["id"]);
        assert_eq!(status["live_diagnostics"]["request_sha256"], status["request_sha256"]);
        assert_eq!(status["live_diagnostics"]["attempt"], status["attempt"]);
    }
}

#[test]
fn inactive_or_cancelling_previews_do_not_manufacture_a_terminal_outcome() {
    let f = Fixture::new();
    let spec = f.submit(1);
    let claim = f.store.claim_next().unwrap().unwrap();
    let observer = claim.preview_observer().unwrap();
    assert!(observer.observe(true, &[segment(PreviewStream::Stdout, 0, b"tail")]));
    assert!(observer.observe(false, &[]));
    let status = f.status(&spec.id);
    assert_eq!(status["state"], "running");
    assert_eq!(status["live_diagnostics"]["active"], false);
    assert!(status["exit_code"].is_null());
    assert_eq!(status["succeeded"], false);
    f.store.cancel(&spec.id).unwrap();
    let status = f.status(&spec.id);
    assert_eq!(status["state"], "cancelling");
    assert_eq!(status["live_diagnostics"]["segments"][0]["data_hex"], "7461696c");
    assert_eq!(status["outputs_installed"], false);
    claim.finish(OperationOutcome::Failed {
        detail: "fixture owner lost; no terminal result was verified".into(),
        execution_may_have_run: true,
    }).unwrap();
    let status = f.status(&spec.id);
    assert_eq!(status["state"], "uncertain");
    assert!(status.get("live_diagnostics").is_none());
    assert!(!observer.observe(true, &[]));
}

#[test]
fn dropped_claim_recovery_and_restart_cannot_reanimate_old_status_output() {
    let f = Fixture::new();
    let spec = f.submit(1);
    let claim = f.store.claim_next().unwrap().unwrap();
    let observer = claim.preview_observer().unwrap();
    assert!(observer.observe(true, &[segment(PreviewStream::Stdout, 0, b"old")]));
    assert!(f.status(&spec.id).get("live_diagnostics").is_some());
    drop(claim);
    assert!(f.status(&spec.id).get("live_diagnostics").is_none());
    f.store.resume(&spec.id, f.root.join("resumed-delivery"), None).unwrap();
    let resumed = f.store.claim_next().unwrap().unwrap();
    assert!(resumed.preview_observer().is_none());
    assert_eq!(f.status(&spec.id)["attempt"], 2);
    assert!(f.status(&spec.id).get("live_diagnostics").is_none());
    assert!(!observer.observe(true, &[segment(PreviewStream::Stdout, 3, b"late")]));
    drop(resumed);
    let Fixture { temporary, root, store } = f;
    drop(store);
    let reopened = PreparedOperationStore::open(&root.join("operations")).unwrap();
    let status = reopened.status(&spec.id).unwrap().unwrap();
    assert_eq!(status.state, OperationState::Uncertain);
    assert_eq!(status.attempt, 2);
    assert!(status.live_diagnostics.is_none());
    assert!(reopened.claim_next().unwrap().is_none());
    drop(reopened);
    drop(temporary);
}

#[test]
fn stopping_the_store_revokes_optional_status_output_without_losing_job_state() {
    let f = Fixture::new();
    let spec = f.submit(1);
    let claim = f.store.claim_next().unwrap().unwrap();
    let observer = claim.preview_observer().unwrap();
    assert!(observer.observe(true, &[segment(PreviewStream::Stderr, 0, b"tail")]));
    assert!(f.status(&spec.id).get("live_diagnostics").is_some());
    f.store.stop().unwrap();
    assert!(claim.cancellation().is_cancelled());
    let status = f.status(&spec.id);
    assert_eq!(status["state"], "running");
    assert_eq!(status["attempt"], 1);
    assert!(status.get("live_diagnostics").is_none());
    assert!(!observer.observe(true, &[]));
}
