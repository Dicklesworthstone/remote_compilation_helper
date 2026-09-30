//! Invocation-derived output contracts for the live `serve` lane (bd-14t4j).
//!
//! A caller can supply `rustc_invocation: { argv, cwd, host_target }` instead
//! of `expected_outputs`. The destination must be that invocation's out-dir;
//! relative dep-info paths are bound to its compiler working directory.
//! This adapter does not turn caller argv into an authoritative action key,
//! bypass serving evidence, or authorize compiler skip/reexecution.

use crate::coord::live::EdgeSubscriber;
use rabs_key::invocation::parse;
use rabs_key::output_declarations::OutputClass;
use rabs_key::output_derivation::derive_dependency_output_declarations;
use serde::Deserialize;
use serde_json::{Value, json};
use std::os::unix::ffi::OsStrExt;
use std::path::{Component, Path};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RustcInvocation {
    argv: Vec<String>,
    cwd: String,
    host_target: String,
}

pub(super) fn serve_reply(coord: &EdgeSubscriber, request: &Value) -> String {
    if request.get("rustc_invocation").is_none() {
        return super::serve_reply(coord, request);
    }
    match derive_frame(request) {
        Ok(frame) => super::serve_reply(coord, &frame),
        Err(detail) => json!({
            "kind": "refusal", "reason": "unsupported-rustc-outputs", "detail": detail,
            "materialization_started": false, "installed_path_bytes": [],
            "compiler_skip_authorized": false, "reexecution_authorized": false,
        })
        .to_string(),
    }
}

/// No filesystem access or coordinator mutation until the complete contract
/// and placement agree. Path comparison is lexical: never canonicalize an
/// untrusted symlink into a different destination. The materializer retains
/// its existing destination preflight and ownership checks.
fn derive_frame(request: &Value) -> Result<Value, String> {
    if request.get("expected_outputs").is_some()
        || request.get("expected_outputs_bytes").is_some()
    {
        return Err("rustc_invocation and expected_outputs are mutually exclusive".into());
    }
    let spec: RustcInvocation = serde_json::from_value(request["rustc_invocation"].clone())
        .map_err(|error| format!("invalid rustc_invocation: {error}"))?;
    if spec.argv.is_empty()
        || spec.argv.len() > 4096
        || spec.argv.iter().any(|arg| arg.as_bytes().contains(&0))
        || spec.argv.iter().map(String::len).sum::<usize>() > super::MAX_FRAME_BYTES
    {
        return Err("argv must be a bounded nonempty array of NUL-free strings".into());
    }
    if spec.host_target.is_empty() {
        return Err("host_target must be explicit".into());
    }
    let cwd = Path::new(&spec.cwd);
    let destination = request["destination_root"]
        .as_str()
        .map(Path::new)
        .ok_or("destination_root must be a string")?;
    let absolute_directory = |path: &Path| {
        path.is_absolute()
            && !path.components().any(|part| part == Component::ParentDir)
            && !path.as_os_str().as_bytes().contains(&0)
    };
    if !absolute_directory(cwd) || !absolute_directory(destination) {
        return Err("cwd and destination_root must be absolute, NUL-free and traversal-free".into());
    }
    let invocation = parse(&spec.argv, None)
        .map_err(|error| format!("invalid rustc argv: {error:?}"))?;
    let declarations = derive_dependency_output_declarations(&invocation, &spec.host_target)
        .map_err(|error| error.to_string())?;
    let out_dir = invocation.out_dir.as_deref().ok_or("missing --out-dir")?;
    let out_dir = cwd.join(out_dir);
    if !absolute_directory(&out_dir) || out_dir != destination {
        return Err("destination_root must equal --out-dir resolved against rustc_invocation.cwd".into());
    }

    let mut frame = request.clone();
    frame["expected_outputs"] = json!(
        declarations
            .declarations
            .iter()
            .map(|output| output.virtual_path.as_str())
            .collect::<Vec<_>>()
    );
    if declarations.declarations.iter().any(|output| output.class == OutputClass::DepInfo) {
        let mut mappings = match request.get("dep_info_mappings") {
            Some(value) => super::parse_dep_info_mappings(value)
                .ok_or("invalid dep_info_mappings")?,
            None => Vec::new(),
        };
        // `.` has explicit semantics in the existing live dep-info adapter.
        // Do not allow a caller mapping to contradict the supplied rustc cwd.
        for (canonical, subscriber) in &mappings {
            if canonical.as_slice() == b"." && subscriber.as_slice() != spec.cwd.as_bytes() {
                return Err("relative dep-info mapping disagrees with rustc_invocation.cwd".into());
            }
        }
        if !mappings.iter().any(|(canonical, _)| canonical.as_slice() == b".") {
            mappings.push((b".".to_vec(), spec.cwd.as_bytes().to_vec()));
        }
        if mappings.len() > 64 {
            return Err("dep-info mappings leave no room for the compiler working directory".into());
        }
        // Retain Unix bytes in explicitly supplied canonical mappings. The
        // live materializer validates mapping grammar, coverage and expansion.
        frame["dep_info_mappings"] = json!(mappings);
    }
    Ok(frame)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    fn request(root: &str, emit: &str) -> Value {
        json!({
            "kind": "serve", "action_key": "01".repeat(32),
            "destination_root": format!("{root}/target/debug/deps"),
            "rustc_invocation": {
                "argv": ["rustc", "--crate-name", "foo", "--crate-type", "lib",
                    "--emit", emit, "--out-dir", "target/debug/deps",
                    "-Cextra-filename=-123", "src/lib.rs"],
                "cwd": root, "host_target": "x86_64-unknown-linux-gnu",
            },
        })
    }

    #[test]
    fn build_and_check_derive_complete_sets_and_bind_relative_dep_info_in_two_worktrees() {
        for root in ["/first worktree", "/second worktree"] {
            let build = derive_frame(&request(root, "dep-info,metadata,link")).unwrap();
            assert_eq!(build["expected_outputs"], json!([
                "foo-123.d", "libfoo-123.rmeta", "libfoo-123.rlib"
            ]));
            let mappings = super::super::parse_dep_info_mappings(&build["dep_info_mappings"])
                .unwrap();
            assert_eq!(mappings, vec![(b".".to_vec(), root.as_bytes().to_vec())]);
            let check = derive_frame(&request(root, "dep-info,metadata")).unwrap();
            assert_eq!(check["expected_outputs"], json!(["foo-123.d", "libfoo-123.rmeta"]));
        }
    }

    #[test]
    fn accepts_an_absolute_out_dir_but_never_a_different_destination() {
        let mut frame = request("/workspace", "link");
        frame["rustc_invocation"]["argv"][8] = json!("/workspace/target/debug/deps");
        assert!(derive_frame(&frame).is_ok());
        for destination in ["/elsewhere", "relative", "/workspace/../elsewhere", "/bad\0path"] {
            frame["destination_root"] = json!(destination);
            assert!(derive_frame(&frame).is_err(), "{destination:?}");
        }
    }

    #[test]
    fn rejects_malformed_or_ambiguous_contracts_instead_of_using_manifest_defaults() {
        let original = request("/workspace", "link");
        for malformed in [Value::Null, json!({}), json!([]), json!(false)] {
            let mut frame = original.clone();
            frame["rustc_invocation"] = malformed;
            assert!(derive_frame(&frame).is_err());
        }
        for field in ["argv", "cwd", "host_target"] {
            let mut frame = original.clone();
            frame["rustc_invocation"].as_object_mut().unwrap().remove(field);
            assert!(derive_frame(&frame).is_err());
        }
        for argument in [json!(null), json!(17), json!("bad\0argument")] {
            let mut frame = original.clone();
            frame["rustc_invocation"]["argv"].as_array_mut().unwrap().push(argument);
            assert!(derive_frame(&frame).is_err());
        }
        let mut frame = original.clone();
        frame["expected_outputs"] = json!([]);
        assert!(derive_frame(&frame).is_err());
        frame["expected_outputs"] = Value::Null;
        assert!(derive_frame(&frame).is_err());
        let mut frame = original.clone();
        frame["rustc_invocation"]["verified"] = json!(true);
        assert!(derive_frame(&frame).is_err());
        for cwd in ["relative", "/work/../other", "/bad\0cwd"] {
            let mut frame = original.clone();
            frame["rustc_invocation"]["cwd"] = json!(cwd);
            assert!(derive_frame(&frame).is_err());
        }
    }

    #[test]
    fn preserves_explicit_raw_mappings_but_rejects_conflicting_working_directories() {
        let mut frame = request("/workspace", "dep-info,metadata");
        let raw = b"/source/\xff".to_vec();
        frame["dep_info_mappings"] = json!([["/__rabs/workspace", raw]]);
        let derived = derive_frame(&frame).unwrap();
        let mappings = super::super::parse_dep_info_mappings(&derived["dep_info_mappings"])
            .unwrap();
        assert_eq!(mappings[0], (b"/__rabs/workspace".to_vec(), raw));
        frame["dep_info_mappings"] = json!([[".", "/different"]]);
        assert!(derive_frame(&frame).is_err());
        frame["dep_info_mappings"] = json!([[".", "/workspace"]]);
        let derived = derive_frame(&frame).unwrap();
        assert_eq!(derived["dep_info_mappings"].as_array().unwrap().len(), 1);
    }

    #[test]
    fn live_lane_refuses_unsupported_invocations_before_any_destination_write() {
        let dir = tempfile::tempdir().unwrap();
        let coord = Arc::new(crate::coord::live::CoordLive::new());
        let original = request(dir.path().to_str().unwrap(), "dep-info,metadata,link");
        for flag in ["--test", "-Csave-temps=yes", "-Cincremental=state", "--print=file-names"] {
            let mut frame = original.clone();
            frame["rustc_invocation"]["argv"].as_array_mut().unwrap().push(json!(flag));
            let reply: Value = serde_json::from_str(&serve_reply(&coord.edge_subscriber(), &frame))
                .unwrap();
            assert_eq!(reply["reason"], "unsupported-rustc-outputs");
            assert_eq!(reply["materialization_started"], false);
            assert_eq!(reply["compiler_skip_authorized"], false);
            assert_eq!(reply["reexecution_authorized"], false);
            assert!(!dir.path().join("target").exists());
        }
        // Supported derivation reaches the real coordinator, not a fabricated
        // hit. With no committed action there can be no installed artifact.
        let reply: Value = serde_json::from_str(&serve_reply(&coord.edge_subscriber(), &original))
            .unwrap();
        assert_eq!(reply["kind"], "serve-result");
        assert_ne!(reply["outcome"], "served");
        assert!(!dir.path().join("target").exists());
    }

    #[test]
    fn actual_materialization_lane_never_discards_a_malformed_invocation() {
        let dir = tempfile::tempdir().unwrap();
        let coord = Arc::new(crate::coord::live::CoordLive::new());
        let mut frame = request(dir.path().to_str().unwrap(), "link");
        frame["rustc_invocation"] = Value::Null;
        let lane = super::super::Limit::new(1);
        let runtime = asupersync::runtime::RuntimeBuilder::current_thread().build().unwrap();
        let reply = runtime.block_on(super::super::serve_on_lane(
            &lane, coord.edge_subscriber(), frame,
        ));
        let reply: Value = serde_json::from_str(&reply).unwrap();
        assert_eq!(reply["reason"], "unsupported-rustc-outputs");
        assert_eq!(reply["materialization_started"], false);
        assert!(!dir.path().join("target").exists());
    }

    #[test]
    fn derived_outputs_do_not_bypass_the_live_coordinators_evidence_floor() {
        use rabs_cas::test_support::{
            install_admission_world, install_offer_closure, offer_under, sample_action_key,
            sample_expected_descriptor,
        };
        let dir = tempfile::tempdir().unwrap();
        let cas = Arc::new(
            crate::janitor::store::mount_and_reconcile(&dir.path().join("cas")).unwrap(),
        );
        let coord = Arc::new(crate::coord::live::CoordLive::with_cas(Arc::clone(&cas)));
        let authority = coord.acquire_boot_authority("derived-output-fixture").unwrap();
        coord.mark_up();
        let offer = offer_under(&authority);
        {
            let mut store = cas.store().lock().unwrap();
            install_admission_world(&mut *store, &authority);
            install_offer_closure(&mut *store, &offer);
        }
        coord.commit_offer(&offer, &sample_expected_descriptor()).unwrap();
        let mut frame = request(dir.path().to_str().unwrap(), "link");
        frame["action_key"] = json!(sample_action_key().bytes.iter()
            .map(|byte| format!("{byte:02x}")).collect::<String>());
        frame["verified"] = json!(true);
        frame["min_samples"] = json!(0);
        let reply: Value = serde_json::from_str(&serve_reply(&coord.edge_subscriber(), &frame))
            .unwrap();
        assert_eq!(reply["outcome"], "execute-privately");
        assert!(reply["reason"].as_str().unwrap().contains("ElevatedClassRisk"));
        assert!(!dir.path().join("target").exists());
    }
}
