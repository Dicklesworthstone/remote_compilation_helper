//! Real source receiver and execution namespace integration for registry-cache
//! replay. No host Cargo installation, credentials or compiler are involved.

use super::*;
use rabs_sandbox::layout;
use std::fs;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::Path;

const CACHE_FILE: &str = "cache/registry/cache/example/dep-1.crate";
const ARCHIVE: &[u8] = b"archive\0\xff";

fn selection() -> Value {
    json!({"version":CARGO_HOME_SOURCE_VERSION, "prefix":"cache"})
}
fn declarations(id: u64) -> (Value, Value, Value) {
    let manifest = projection(&[("app/lib.rs", b"source", false), (CACHE_FILE, ARCHIVE, false)]);
    let start = json!({"kind":"source-begin", "request_id":id, "manifest":manifest,
        "cargo_home":selection()});
    let request = json!({"kind":"canonical-exec", "request_id":id, "program":"cargo",
        "source_manifest":manifest, "cargo_home":selection()});
    (manifest, start, request)
}
fn send_files(state: &mut SourceTransferState, manifest: &Value, id: u64) {
    upload(state, manifest, id, "app/lib.rs", b"source");
    upload(state, manifest, id, CACHE_FILE, ARCHIVE);
}

#[test]
fn ready_echo_and_seal_precede_private_cargo_home_execution_ownership() {
    let (manifest, start, request) = declarations(7);
    let original_request = request.clone();
    let mut state = SourceTransferState::default();
    let ready = state.handle(&start, true, false).unwrap();
    assert_eq!(ready["cargo_home"], selection());
    assert_eq!(ready["sealed"], false);
    assert!(state.prepared_path(&request, true).is_err());
    let deadline = state.pending.as_ref().unwrap().deadline;
    send_files(&mut state, &manifest, 7);
    let sealed = state.handle(&seal(&manifest, 7), true, false).unwrap();
    assert_eq!(sealed["sealed"], true);
    assert_eq!(sealed["cargo_home"], selection());
    assert_eq!(state.handle(&start, true, false).unwrap(), sealed);
    assert_eq!(state.pending.as_ref().unwrap().deadline, deadline);
    assert!(!sealed.to_string().contains("rabs-source-"));
    let owner = state.take_prepared(&request).unwrap().unwrap();
    let runtime = tempfile::tempdir().unwrap();
    let mut spec = namespace_for_source(&owner, runtime.path());
    let before = spec.clone();
    let original_cargo_home = before.rw_binds.iter()
        .find(|bind| bind.visible == Path::new(layout::CARGO_HOME)).unwrap().backing.clone();
    fs::write(original_cargo_home.join("credentials.toml"), b"keep private").unwrap();
    owner.protect_workspace(7, &mut spec).unwrap();
    assert!(spec.ro_binds.iter().any(|bind| bind.visible == Path::new(layout::WORKSPACE)));
    assert!(!spec.rw_binds.iter().any(|bind| bind.visible == Path::new(layout::WORKSPACE)));
    assert_eq!(spec.env, before.env);
    assert_eq!(spec.cwd, before.cwd);
    assert!(!spec.allows_network());
    let home = &spec.rw_binds.iter().find(|bind| bind.visible == Path::new(layout::CARGO_HOME)).unwrap().backing;
    let copied = home.join("registry/cache/example/dep-1.crate");
    let source = owner.receiver.sealed_root().unwrap().join(CACHE_FILE);
    assert_eq!(fs::read(&copied).unwrap(), ARCHIVE);
    assert_ne!(fs::metadata(&copied).unwrap().ino(), fs::metadata(&source).unwrap().ino());
    assert_eq!(fs::metadata(&copied).unwrap().permissions().mode() & 0o777, 0o600);
    assert!(!home.join("credentials.toml").exists());
    fs::write(home.join(".package-cache"), b"runtime lock").unwrap();
    fs::write(copied, b"private mutation").unwrap();
    assert_eq!(fs::read(source).unwrap(), ARCHIVE);
    assert_eq!(fs::read(original_cargo_home.join("credentials.toml")).unwrap(), b"keep private");
    for visible in [layout::HOME, "/__rabs/out/dep"] {
        assert_eq!(spec.rw_binds.iter().find(|bind| bind.visible == Path::new(visible)),
            before.rw_binds.iter().find(|bind| bind.visible == Path::new(visible)));
    }
    assert_eq!(request, original_request);
}

#[test]
fn changed_or_removed_selection_cannot_rebind_source_or_consume_ownership() {
    let (manifest, start, request) = declarations(7);
    let mut state = SourceTransferState::default();
    state.handle(&start, true, false).unwrap();
    send_files(&mut state, &manifest, 7);
    state.handle(&seal(&manifest, 7), true, false).unwrap();
    let expected = state.prepared_path(&request, true).unwrap();
    for value in [None, Some(Value::Null), Some(json!({"version":CARGO_HOME_SOURCE_VERSION, "prefix":"app"}))] {
        let mut changed_start = start.clone();
        let mut changed_request = request.clone();
        for changed in [&mut changed_start, &mut changed_request] {
            if let Some(value) = &value { changed["cargo_home"] = value.clone(); }
            else { changed.as_object_mut().unwrap().remove("cargo_home"); }
        }
        assert!(state.handle(&changed_start, true, false).is_err());
        assert!(state.prepared_path(&changed_request, true).is_err());
        assert!(state.take_prepared(&changed_request).is_err());
        assert_eq!(state.prepared_path(&request, true).unwrap(), expected);
    }
    // Adding the extension after an ordinary upload is equally forbidden.
    let mut ordinary = SourceTransferState::default();
    let mut legacy = start.clone(); legacy.as_object_mut().unwrap().remove("cargo_home");
    ordinary.handle(&legacy, true, false).unwrap();
    send_files(&mut ordinary, &manifest, 7);
    ordinary.handle(&seal(&manifest, 7), true, false).unwrap();
    assert!(ordinary.prepared_path(&request, true).is_err());
    assert!(ordinary.take_prepared(&request).is_err());
}

#[test]
fn malformed_or_unuploaded_cache_intent_refuses_before_storage() {
    let (_, start, request) = declarations(7);
    for value in [Value::Null, json!(true), json!([]), json!({"version":"v2", "prefix":"cache"}),
        json!({"version":CARGO_HOME_SOURCE_VERSION, "prefix":"../private-marker"}),
        json!({"version":CARGO_HOME_SOURCE_VERSION, "prefix":"cache", "host":"private-marker"})] {
        let mut start = start.clone(); start["cargo_home"] = value.clone();
        let mut request = request.clone(); request["cargo_home"] = value;
        let mut state = SourceTransferState::default();
        let error = state.handle(&start, true, false).unwrap_err();
        assert!(!error.contains("private-marker"));
        assert!(state.pending.is_none());
        assert!(request_manifest(&request).is_err());
        request.as_object_mut().unwrap().remove("source_manifest");
        request["workspace_backing"] = json!("/worker/workspace");
        assert!(request_manifest(&request).is_err());
        assert!(state.prepared_path(&request, true).is_err());
        assert!(state.take_prepared(&request).is_err());
    }
}

#[test]
fn cache_preparation_failure_permanently_fences_the_source_owner() {
    let (manifest, start, request) = declarations(7);
    let mut state = SourceTransferState::default();
    state.handle(&start, true, false).unwrap();
    send_files(&mut state, &manifest, 7);
    let blocked = state.pending.as_ref().unwrap()._directory.path().join("cargo-home-runtime");
    fs::create_dir(&blocked).unwrap();
    fs::write(blocked.join("sentinel"), b"preserve").unwrap();
    let deadline = state.pending.as_ref().unwrap().deadline;
    assert!(state.handle(&seal(&manifest, 7), true, false).is_err());
    assert!(state.pending.as_ref().unwrap().source_failed);
    assert!(state.pending.as_ref().unwrap().prepared_cargo_home.is_none());
    assert!(state.handle(&start, true, false).is_err());
    assert!(state.prepared_path(&request, true).is_err());
    assert!(state.take_prepared(&request).is_err());
    assert_eq!(state.pending.as_ref().unwrap().deadline, deadline);
    assert_eq!(fs::read(blocked.join("sentinel")).unwrap(), b"preserve");
}

#[test]
fn warm_source_cache_still_prepares_an_independent_request_owned_cargo_home() {
    let cache = tempfile::tempdir().unwrap();
    let (manifest, mut start, request) = declarations(7);
    start["allow_cached_files"] = json!(true);
    let mut cold = cached_state(cache.path());
    cold.handle(&start, true, false).unwrap();
    send_files(&mut cold, &manifest, 7);
    cold.handle(&seal(&manifest, 7), true, false).unwrap();
    let first = cold.take_prepared(&request).unwrap().unwrap();
    let mut warm = cached_state(cache.path());
    let ready = warm.handle(&start, true, false).unwrap();
    assert_eq!(ready["cargo_home"], selection());
    assert_eq!(ready["missing_files"], json!([]));
    assert_eq!(ready["sealed"], false);
    assert!(warm.prepared_path(&request, true).is_err());
    warm.handle(&seal(&manifest, 7), true, false).unwrap();
    let second = warm.take_prepared(&request).unwrap().unwrap();
    let runtime = tempfile::tempdir().unwrap();
    let mut a = namespace_for_source(&first, runtime.path());
    let mut b = namespace_for_source(&second, runtime.path());
    first.protect_workspace(7, &mut a).unwrap();
    second.protect_workspace(7, &mut b).unwrap();
    let home = |spec: &rabs_sandbox::canonical_namespace::CanonicalNamespaceSpec| {
        spec.rw_binds.iter().find(|bind| bind.visible == Path::new(layout::CARGO_HOME))
            .unwrap().backing.join("registry/cache/example/dep-1.crate")
    };
    assert_ne!(fs::metadata(home(&a)).unwrap().ino(), fs::metadata(home(&b)).unwrap().ino());
    fs::write(home(&a), b"changed first runtime").unwrap();
    assert_eq!(fs::read(home(&b)).unwrap(), ARCHIVE);
}
