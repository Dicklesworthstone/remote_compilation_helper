use super::*;
use crate::hook::artifact_patterns::get_custom_target_artifact_patterns;
use serde_json::json;

fn default_capture(kind: CompilationKind, command: &str) -> Option<CargoOutputCapture> {
    let baseline = get_custom_target_artifact_patterns(Some(kind), Some(command));
    CargoOutputCapture::for_retrieval_policy(Some(kind), command, &baseline, &[]).unwrap()
}

fn completed_receipt() -> Vec<u8> {
    let records = [
        json!({"reason":"compiler-artifact", "target":{"name":"model","kind":["lib"]},
            "filenames":["/target/debug/libmodel.rlib"], "executable":null, "fresh":true}),
        json!({"reason":"compiler-artifact", "target":{"name":"app","kind":["bin"]},
            "filenames":["/target/debug/app", "/target/debug/app.pdb"],
            "executable":"/target/debug/app", "fresh":false}),
        json!({"reason":"build-finished", "success":true}),
    ];
    records
        .iter()
        .map(|record| format!("{record}\n"))
        .collect::<String>()
        .into_bytes()
}

#[test]
fn default_human_builds_capture_complete_outputs_without_exclusion_configuration() {
    for (kind, command) in [
        (CompilationKind::CargoBuild, "cargo build"),
        (
            CompilationKind::CargoBuild,
            "cargo +nightly build --workspace --all-targets --locked --profile ci-fast --target aarch64-unknown-linux-gnu",
        ),
        (CompilationKind::CargoBuild, "cargo build --lib"),
        (
            CompilationKind::CargoBuild,
            "cargo build --bin app --example sample",
        ),
        (CompilationKind::CargoTest, "cargo test --no-run"),
        (
            CompilationKind::CargoBench,
            "cargo bench --workspace --no-run",
        ),
    ] {
        let capture = default_capture(kind, command).expect(command);
        assert!(capture.automatic_complete_outputs(), "{command}");
        assert!(capture.supports_retrieval_exclusions(), "{command}");
        assert!(!capture.caller_json_supported(), "{command}");
        assert_eq!(
            capture.execution_command(command),
            format!("{command} --message-format=json,json-render-diagnostics")
        );
        assert_eq!(
            capture.retrieval_baseline().unwrap(),
            get_custom_target_artifact_patterns(Some(kind), Some(command))
        );
        assert!(capture.suppress_stdout_line(
            r#"{"reason":"build-finished","success":true}"#
        ));
        for diagnostic in [
            "warning: unused variable: value",
            "custom build output",
            r#"{"message":"ordinary program JSON"}"#,
        ] {
            assert!(!capture.suppress_stdout_line(diagnostic));
        }
    }
}

#[test]
fn automatic_capture_preserves_explicit_and_unsupported_output_contracts() {
    for (kind, command) in [
        (CompilationKind::CargoBuild, "cargo build --message-format=json"),
        (CompilationKind::CargoBuild, "cargo build --message-format=human"),
        (CompilationKind::CargoBuild, "cargo build --message-format=short"),
        (CompilationKind::CargoBuild, "cargo build --config build.jobs=1"),
        (CompilationKind::CargoBuild, "cargo build --out-dir other"),
        (CompilationKind::CargoBuild, "cargo build && echo done"),
        (CompilationKind::CargoBuild, "cargo package"),
        (CompilationKind::CargoDoc, "cargo doc"),
        (CompilationKind::CargoZigbuild, "cargo zigbuild"),
        (CompilationKind::CargoCheck, "cargo check"),
        (CompilationKind::CargoTest, "cargo test"),
        (CompilationKind::CargoBench, "cargo bench -- --no-run"),
    ] {
        assert!(default_capture(kind, command).is_none(), "{command}");
    }
    for command in [
        "cargo build --bin app",
        "cargo build --bin app --message-format=json",
    ] {
        let capture = default_capture(CompilationKind::CargoBuild, command).unwrap();
        assert_eq!(
            Some(capture.clone()),
            CargoOutputCapture::for_command(Some(CompilationKind::CargoBuild), command)
        );
        assert!(!capture.automatic_complete_outputs());
    }
    // No target-root phase means this lane has no original selection to bind.
    assert!(
        CargoOutputCapture::for_retrieval_policy(
            Some(CompilationKind::CargoBuild),
            "cargo build",
            &[],
            &[],
        )
        .unwrap()
        .is_none()
    );
}

#[test]
fn automatic_capture_retains_every_emitted_output_and_complete_receipt_requirements() {
    let capture = default_capture(CompilationKind::CargoBuild, "cargo build --workspace").unwrap();
    let stdout = completed_receipt();
    let contract = capture.parse_receipt(&stdout, Path::new("/target")).unwrap();
    assert_eq!(
        contract.required_files,
        BTreeSet::from([
            PathBuf::from("debug/libmodel.rlib"),
            PathBuf::from("debug/app"),
            PathBuf::from("debug/app.pdb"),
        ])
    );
    let restored: CargoOutputCapture =
        serde_json::from_slice(&serde_json::to_vec(&capture).unwrap()).unwrap();
    assert!(restored.automatic_complete_outputs());
    assert_eq!(
        restored.parse_receipt(&stdout, Path::new("/target")).unwrap(),
        contract
    );
    for invalid in [
        &b""[..],
        &b"{\"reason\":\"build-finished\",\"success\":true}\n"[..],
        &b"{\"reason\":\"build-finished\",\"success\":false}\n"[..],
        &stdout[..stdout.len() - 1],
    ] {
        assert!(restored.parse_receipt(invalid, Path::new("/target")).is_err());
    }
    let missing_terminal = stdout
        .split_inclusive(|byte| *byte == b'\n')
        .take(2)
        .flatten()
        .copied()
        .collect::<Vec<_>>();
    assert!(
        restored
            .parse_receipt(&missing_terminal, Path::new("/target"))
            .is_err()
    );
}

#[test]
fn automatic_capture_provenance_does_not_upgrade_legacy_or_explicit_exclusion_recipes() {
    let old = CargoOutputCapture::for_command(
        Some(CompilationKind::CargoBuild),
        "cargo build --bin app",
    )
    .unwrap();
    let encoded = serde_json::to_value(&old).unwrap();
    assert!(encoded.get("automatic_complete_outputs").is_none());
    let restored: CargoOutputCapture = serde_json::from_value(encoded).unwrap();
    assert!(!restored.automatic_complete_outputs());
    let baseline = get_custom_target_artifact_patterns(
        Some(CompilationKind::CargoBuild),
        Some("cargo build"),
    );
    let explicit = CargoOutputCapture::for_retrieval_policy(
        Some(CompilationKind::CargoBuild),
        "cargo build",
        &baseline,
        &["debug/.wrapper-shims".into()],
    )
    .unwrap()
    .unwrap();
    assert!(!explicit.automatic_complete_outputs());
    assert!(explicit.supports_retrieval_exclusions());

    let mut corrupted = default_capture(CompilationKind::CargoBuild, "cargo build").unwrap();
    corrupted.instrumented = false;
    assert!(!corrupted.supports_retrieval_exclusions());
    assert!(
        corrupted
            .parse_receipt(&completed_receipt(), Path::new("/target"))
            .is_err()
    );
}
