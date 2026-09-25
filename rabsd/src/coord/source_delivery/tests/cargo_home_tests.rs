//! Coordinator preparation and transfer against the real source-byte receiver.
//! The wire peer is a fixture; Cargo-home copying uses the shared production
//! implementation. These tests do not claim compiler execution or TLS proof.

use super::*;
use rabs_sandbox::cargo_home::PreparedCargoHome;
use crate::coord::worker_delivery::receive_execution;

const CACHE_PATH: &str = "cache/registry/cache/example/dep-1.crate";
fn selection() -> Value { json!({"version":CARGO_HOME_SOURCE_VERSION, "prefix":"cache"}) }

fn registry_fixture(root: &Path) -> (SourceUpload, Value, Vec<u8>) {
    fs::create_dir_all(root.join("app")).unwrap();
    fs::create_dir_all(root.join("cache/registry/cache/example")).unwrap();
    fs::write(root.join("app/lib.rs"), b"source").unwrap();
    fs::write(root.join("cache/credentials.toml"), b"never selected").unwrap();
    let bytes: Vec<_> = (0..MAX_SOURCE_CHUNK + 17).map(|index| (index % 251) as u8).collect();
    fs::write(root.join(CACHE_PATH), &bytes).unwrap();
    let image = Arc::new(capture_sealed_source(&[("workspace".into(), root.to_path_buf())], false, 2, 200_000).unwrap());
    let upload = SourceUpload::from_snapshot(image, "workspace", &["app/lib.rs".into(), CACHE_PATH.into()]).unwrap();
    let request = json!({"kind":"canonical-exec", "request_id":7, "program":"cargo",
        "args":["build", "--frozen"], "toolchain_backing":"/tc",
        "source_manifest":upload.wire_manifest(), "cargo_home":selection()});
    (upload, request, bytes)
}

struct RegistryPeer {
    inner: ReceiverPeer,
    initial_echo: Option<Value>,
    final_echo: Option<Value>,
    requested: Option<Value>,
    prepared: Option<PreparedCargoHome>,
}
impl RegistryPeer {
    fn new() -> Self {
        Self { inner:ReceiverPeer::new(), initial_echo:Some(selection()),
            final_echo:Some(selection()), requested:None, prepared:None }
    }
}
impl WorkerPeer for RegistryPeer {
    fn send(&mut self, frame: &Value) -> io::Result<()> {
        self.inner.send(frame)?;
        if frame["kind"] == "source-begin" {
            self.requested = frame.get("cargo_home").cloned();
            if let Some(home) = &self.initial_echo {
                self.inner.replies.back_mut().unwrap()["cargo_home"] = home.clone();
            }
        }
        if frame["kind"] == "source-seal" {
            if let Some(home) = &self.requested {
                let source = self.inner.receiver.as_ref().unwrap();
                let projection = CargoHomeProjection::new(home["prefix"].as_str().unwrap(), source.manifest())?;
                self.prepared = Some(projection.prepare(source,
                    &self.inner.owner.path().join("cargo-home-runtime"), || false)?);
            }
            if let Some(home) = &self.final_echo {
                self.inner.replies.back_mut().unwrap()["cargo_home"] = home.clone();
            }
        }
        Ok(())
    }
    fn receive(&mut self) -> io::Result<Value> { self.inner.receive() }
}

#[test]
fn captured_registry_bytes_transfer_and_replay_without_credentials_or_request_rewriting() {
    let root = tempfile::tempdir().unwrap();
    let (upload, request, bytes) = registry_fixture(root.path());
    let original = serde_json::to_vec(&request).unwrap();
    fs::write(root.path().join(CACHE_PATH), b"changed after capture").unwrap();
    let mut peer = RegistryPeer::new();
    SourcePeer::new(&mut peer, &upload, &request).unwrap()
        .negotiate(&json!({"source_transfers":[SOURCE_TRANSFER]}), &json!({"kind":"session-ok"})).unwrap();
    assert_eq!(peer.inner.sent[1]["cargo_home"], selection());
    assert!(peer.inner.replies.is_empty());
    assert!(peer.prepared.is_some());
    assert_eq!(serde_json::to_vec(&request).unwrap(), original);
    let home = peer.inner.owner.path().join("cargo-home-runtime");
    assert_eq!(fs::read(home.join("registry/cache/example/dep-1.crate")).unwrap(), bytes);
    assert!(!home.join("credentials.toml").exists());
    assert!(!peer.inner.owner.path().join("workspace/cache/credentials.toml").exists());
    assert!(peer.inner.sent.iter().all(|frame| frame["kind"] != "canonical-exec"));
    assert_eq!(peer.inner.sent.iter().filter(|frame| frame["kind"] == "source-chunk" && frame["path"] == CACHE_PATH).count(), 2);
}

#[test]
fn missing_or_changed_registry_support_stops_before_bytes_and_execution() {
    let root = tempfile::tempdir().unwrap();
    let (upload, request, _) = registry_fixture(root.path());
    for echo in [None, Some(Value::Null), Some(json!(true)),
        Some(json!({"version":"registry-cargo-home-v2", "prefix":"cache"})),
        Some(json!({"version":CARGO_HOME_SOURCE_VERSION, "prefix":"other"}))] {
        let mut peer = RegistryPeer::new();
        peer.initial_echo = echo;
        let mut source = SourcePeer::new(&mut peer, &upload, &request).unwrap();
        let hello = json!({"source_transfers":[SOURCE_TRANSFER]});
        assert!(source.negotiate(&hello, &json!({"kind":"session-ok"})).is_err());
        assert!(source.negotiate(&hello, &json!({"kind":"session-ok"})).is_err());
        assert_eq!(peer.inner.sent.len(), 2); // grant and metadata; never a byte or execution.
        assert_eq!(peer.inner.sent[1]["kind"], "source-begin");
        assert!(peer.prepared.is_none());
    }
    let mut ordinary = request;
    ordinary.as_object_mut().unwrap().remove("cargo_home");
    let mut peer = RegistryPeer::new();
    assert!(upload.transmit(&mut peer, &ordinary, false).is_err(), "unsolicited Cargo home selection is not authority");
    assert_eq!(peer.inner.sent.len(), 1);
}

#[test]
fn missing_final_registry_seal_never_crosses_the_real_delivery_execution_frontier() {
    let root = tempfile::tempdir().unwrap();
    let (upload, request, _) = registry_fixture(root.path());
    let destination_parent = tempfile::tempdir().unwrap();
    let destination = destination_parent.path().join("delivery");
    let mut peer = RegistryPeer::new();
    peer.final_echo = None;
    peer.inner.replies.push_front(json!({"kind":"worker-hello", "worker_id":"worker",
        "canonical":true, "slots":1, "boot_generation":1,
        "incarnation":"00000000000000000000000000000001", "request_high_water":null,
        "source_transfers":[SOURCE_TRANSFER], "output_transfers":["ranges-v1"],
        "recovery_protocols":["request-journal-v1"]}));
    let failure = receive_execution(
        &mut SourcePeer::new(&mut peer, &upload, &request).unwrap(),
        &request, "worker", &destination,
    ).unwrap_err();
    assert!(!failure.execution_may_have_run);
    assert!(failure.detail.contains("Cargo home"));
    assert!(peer.prepared.is_some(), "even a prepared remote copy cannot waive the missing final echo");
    assert!(peer.inner.sent.iter().all(|frame| !matches!(frame["kind"].as_str(),
        Some("canonical-exec" | "output-ack" | "artifact-ack"))));
    assert!(!destination.join("delivery.json").exists());
}

#[test]
fn registry_request_validation_and_preparation_refuse_unsupported_or_unselected_state() {
    let root = tempfile::tempdir().unwrap();
    let (upload, request, _) = registry_fixture(root.path());
    for value in [Value::Null, json!([]), json!({"prefix":"cache"}),
        json!({"version":CARGO_HOME_SOURCE_VERSION, "prefix":"../private-marker"}),
        json!({"version":CARGO_HOME_SOURCE_VERSION, "prefix":"cache", "extra":"private-marker"}),
        json!({"version":"v2", "prefix":"cache"})] {
        let mut changed = request.clone(); changed["cargo_home"] = value;
        let error = validate_request(&changed).unwrap_err();
        assert!(!error.to_string().contains("private-marker"));
        let mut peer = RegistryPeer::new();
        assert!(SourcePeer::new(&mut peer, &upload, &changed).is_err());
        assert!(peer.inner.sent.is_empty());
        changed.as_object_mut().unwrap().remove("source_manifest");
        changed["workspace_backing"] = json!("/worker/path");
        assert!(validate_request(&changed).is_err());
    }
    let owner = tempfile::tempdir().unwrap();
    let spec = json!({"kind":"canonical-exec", "request_id":7, "program":"cargo",
        "toolchain_backing":"/tc", "cargo_home":selection(),
        "source_files":["app/lib.rs", CACHE_PATH, "cache/credentials.toml"]});
    assert!(prepare_source_bundle(root.path(), &spec, &owner.path().join("refused")).is_err());
    assert!(!owner.path().join("refused").exists());
}

#[test]
fn prepared_registry_bundle_retains_selection_and_warm_transfer_still_requires_seal() {
    let root = tempfile::tempdir().unwrap();
    registry_fixture(root.path());
    let owner = tempfile::tempdir().unwrap();
    let bundle = owner.path().join("bundle");
    let spec = json!({"kind":"canonical-exec", "request_id":7, "program":"cargo",
        "toolchain_backing":"/tc", "args":["build", "--frozen"], "cargo_home":selection(),
        "source_roots":{
            "app":{"path":"app", "files":["lib.rs"]},
            "cache":{"path":"cache", "files":["registry/cache/example/dep-1.crate"]}}});
    let summary = prepare_source_bundle(root.path(), &spec, &bundle).unwrap();
    let request_bytes = fs::read(bundle.join("request.json")).unwrap();
    let request: Value = serde_json::from_slice(&request_bytes).unwrap();
    assert_eq!(request["cargo_home"], selection());
    assert_eq!(request["args"], spec["args"]);
    assert!(request.get("source_roots").is_none());
    assert_eq!(summary["request_sha256"], hex(&Sha256::digest(&request_bytes)));
    assert_eq!(summary["executed"], false);
    assert_eq!(summary["publication_authorized"], false);
    assert!(!request.to_string().contains(root.path().to_str().unwrap()));
    fs::rename(root.path().join("cache"), root.path().join("retired-cache")).unwrap();
    let image = Arc::new(capture_sealed_source(&[("workspace".into(), bundle.join("source"))], false, 2, 200_000).unwrap());
    let upload = SourceUpload::for_request(image, "workspace", &request).unwrap();
    let mut peer = RegistryPeer::new();
    for file in upload.manifest.files() {
        peer.inner.prefilled.insert(file.path.clone(), upload.file_bytes(&file.path).unwrap().to_vec());
    }
    peer.inner.missing = Some(json!([]));
    upload.transmit(&mut peer, &request, false).unwrap();
    assert_eq!(peer.inner.sent.len(), 2);
    assert_eq!(peer.inner.sent[0]["cargo_home"], selection());
    assert_eq!(peer.inner.sent[1]["kind"], "source-seal");
    assert!(peer.prepared.is_some());
    assert_eq!(fs::read(bundle.join("request.json")).unwrap(), request_bytes);
}
