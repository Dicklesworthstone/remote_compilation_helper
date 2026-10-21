//! Real Cargo output discovery for workspace builds, checks, Clippy and tests.
//! Stock local Cargo and an opt-in canonical namespace exercise production
//! JSON/tree validation. Neither substitutes for worker/TLS integration or
//! authorizes cache serving.
#![cfg(target_os = "linux")]

use rabs_sandbox::artifact_tree::TreeInventory;
use rabs_sandbox::canonical_mounts::{CanonicalMountPlan, UnitMount};
use rabs_sandbox::canonical_namespace::{HostIsolationSupport, build_canonical_argv, command_for};
use rabs_sandbox::cargo_artifacts::{CargoArtifactMode, CargoArtifactReport};
use rabs_sandbox::snapshot_capture::capture_sealed_source;
use std::collections::BTreeSet;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;

fn toolchain() -> PathBuf {
    let rustc = std::env::var_os("RUSTC").unwrap_or_else(|| "rustc".into());
    let output = Command::new(rustc).arg("--print=sysroot").output().unwrap();
    assert!(
        output.status.success(),
        "a real installed Rust toolchain is required"
    );
    PathBuf::from(String::from_utf8(output.stdout).unwrap().trim())
}

fn cargo(toolchain: &Path, root: &Path, home: &Path) -> Command {
    cargo_tool(toolchain, root, home, "cargo")
}

fn cargo_tool(toolchain: &Path, root: &Path, home: &Path, program: &str) -> Command {
    let mut command = Command::new(toolchain.join("bin").join(program));
    command
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env("HOME", home)
        .env("CARGO_HOME", home.join("cargo"))
        .env("RUSTC", toolchain.join("bin/rustc"))
        .env("CARGO_INCREMENTAL", "0")
        .env("CARGO_BUILD_JOBS", "1")
        .env("CARGO_PROFILE_DEV_DEBUG", "0")
        .env("CARGO_PROFILE_TEST_DEBUG", "0")
        .current_dir(root);
    command
}

fn workspace_fixture() -> (tempfile::TempDir, PathBuf, PathBuf, PathBuf) {
    let owner = tempfile::tempdir().unwrap();
    let root = owner.path().join("workspace");
    let home = owner.path().join("home");
    fs::create_dir_all(root.join("library/src")).unwrap();
    fs::create_dir_all(root.join("app/src")).unwrap();
    fs::create_dir_all(root.join("app/tests")).unwrap();
    fs::create_dir(&home).unwrap();
    fs::write(
        root.join("Cargo.toml"),
        "[workspace]\nmembers=['library','app']\nresolver='2'\n",
    )
    .unwrap();
    fs::write(
        root.join("library/Cargo.toml"),
        "[package]\nname='artifact_library'\nversion='0.1.0'\nedition='2024'\n",
    )
    .unwrap();
    fs::write(root.join("library/build.rs"),
        r#"fn main() { std::fs::write(std::path::Path::new(&std::env::var_os("OUT_DIR").unwrap()).join("generated.rs"), "pub const VALUE: u32 = 42;").unwrap(); }"#).unwrap();
    fs::write(root.join("library/src/lib.rs"),
        "include!(concat!(env!(\"OUT_DIR\"), \"/generated.rs\"));\n#[test] fn value() { assert_eq!(VALUE, 42); }\n").unwrap();
    fs::write(root.join("app/Cargo.toml"),
        "[package]\nname='artifact_app'\nversion='0.1.0'\nedition='2024'\n[dependencies]\nartifact_library={path='../library'}\n").unwrap();
    fs::write(
        root.join("app/src/main.rs"),
        "fn main() { println!(\"{}\", artifact_library::VALUE); }\n",
    )
    .unwrap();
    fs::write(
        root.join("app/tests/integration.rs"),
        "#[test] fn generated_dependency() { assert_eq!(artifact_library::VALUE, 42); }\n",
    )
    .unwrap();
    let tools = toolchain();
    let lock = cargo(&tools, &root, &home)
        .args(["generate-lockfile", "--offline"])
        .output()
        .unwrap();
    assert!(
        lock.status.success(),
        "{}",
        String::from_utf8_lossy(&lock.stderr)
    );
    (owner, root, home, tools)
}

#[test]
fn real_workspace_build_check_and_test_compilation_capture_actual_outputs() {
    let (owner, root, home, tools) = workspace_fixture();
    for mode in ["build", "check", "test"] {
        let output_root = owner.path().join(format!("outputs-{mode}"));
        fs::create_dir(&output_root).unwrap();
        fs::set_permissions(&output_root, fs::Permissions::from_mode(0o700)).unwrap();
        let mut command = cargo(&tools, &root, &home);
        command
            .args([
                mode,
                "--workspace",
                "--locked",
                "--offline",
                "--message-format=json",
                "--target-dir",
            ])
            .arg(&output_root);
        if mode == "test" {
            command.arg("--no-run");
        }
        let output = command.output().unwrap();
        assert!(
            output.status.success(),
            "{mode}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        let report = CargoArtifactReport::read(
            output.stdout.as_slice(),
            output_root.to_str().unwrap(),
            CargoArtifactMode::Compilation,
        )
        .unwrap();
        let required = report.files().map(str::to_owned).collect::<BTreeSet<_>>();
        let inventory =
            TreeInventory::scan(&output_root, &required, 128 * 1024 * 1024, &|| false).unwrap();
        let observed = inventory
            .names()
            .map(|name| {
                let executable = fs::metadata(output_root.join(name))
                    .unwrap()
                    .permissions()
                    .mode()
                    & 0o111
                    != 0;
                (name, executable)
            })
            .collect::<Vec<_>>();
        report.validate_outputs(observed).unwrap();
        assert!(
            report.files().any(|name| name.contains("artifact_library")),
            "{mode}: library output absent"
        );
        assert!(
            report.files().any(|name| name.contains("artifact_app")),
            "{mode}: app output absent"
        );
        match mode {
            "build" => {
                assert!(required.contains("debug/artifact_app"));
                let ran = Command::new(output_root.join("debug/artifact_app"))
                    .output()
                    .unwrap();
                assert!(ran.status.success());
                assert_eq!(ran.stdout, b"42\n");
            }
            "check" => assert!(required.iter().any(|name| name.ends_with(".rmeta"))),
            "test" => {
                let executable = required
                    .iter()
                    .find(|name| {
                        Path::new(name)
                            .file_name()
                            .is_some_and(|name| name.to_string_lossy().starts_with("integration-"))
                    })
                    .unwrap_or_else(|| {
                        panic!("Cargo did not report the integration test executable: {required:?}")
                    });
                let ran = Command::new(output_root.join(executable)).output().unwrap();
                assert!(
                    ran.status.success(),
                    "{}",
                    String::from_utf8_lossy(&ran.stdout)
                );
                assert!(String::from_utf8_lossy(&ran.stdout).contains("1 passed"));
            }
            _ => unreachable!(),
        }
        inventory.verify(&|| false).unwrap();
    }
    fs::write(
        root.join("app/src/main.rs"),
        "fn main() { this_does_not_compile(); }\n",
    )
    .unwrap();
    let broken = cargo(&tools, &root, &home)
        .args([
            "check",
            "--workspace",
            "--locked",
            "--offline",
            "--message-format=json",
            "--target-dir",
        ])
        .arg(owner.path().join("broken-output"))
        .output()
        .unwrap();
    assert!(!broken.status.success());
    assert!(
        CargoArtifactReport::read(
            broken.stdout.as_slice(),
            owner.path().join("broken-output").to_str().unwrap(),
            CargoArtifactMode::Compilation,
        )
        .is_err()
    );
}

#[test]
fn real_clippy_uses_captured_companions_and_denied_lints_cannot_report_success() {
    let (owner, root, home, tools) = workspace_fixture();
    for name in ["cargo-clippy", "clippy-driver"] {
        let path = tools.join("bin").join(name);
        let metadata = fs::symlink_metadata(&path)
            .unwrap_or_else(|error| panic!("the pinned toolchain requires {name}: {error}"));
        assert!(metadata.is_file() && metadata.permissions().mode() & 0o111 != 0);
    }
    let library = root.join("library/src/lib.rs");
    let original = fs::read_to_string(&library).unwrap();
    fs::write(
        &library,
        format!("{original}\npub fn lint_probe(value: bool) -> bool {{ value == true }}\n"),
    )
    .unwrap();
    for (label, lints, successful) in [
        ("warning", vec!["-W", "clippy::bool_comparison"], true),
        ("denied", vec!["-Dclippy::bool_comparison"], false),
        ("clean", vec!["-D", "warnings"], true),
    ] {
        if label == "clean" {
            fs::write(&library, &original).unwrap();
        }
        let output_root = owner.path().join(format!("clippy-{label}"));
        fs::create_dir(&output_root).unwrap();
        fs::set_permissions(&output_root, fs::Permissions::from_mode(0o700)).unwrap();
        // This is the frontend's exact direct-program contract. The fixture
        // PATH contains no Rust toolchain; adjacent clippy-driver plus the
        // explicit CARGO/RUSTC bindings must supply every compiler tool.
        let output = cargo_tool(&tools, &root, &home, "cargo-clippy")
            .env("CARGO", tools.join("bin/cargo"))
            .args([
                "clippy",
                "--workspace",
                "--all-targets",
                "--all-features",
                "--locked",
                "--offline",
                "--message-format=json",
                "--target-dir",
            ])
            .arg(&output_root)
            .arg("--")
            .args(lints)
            .output()
            .unwrap();
        assert_eq!(
            output.status.success(),
            successful,
            "{label}: {}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        if label != "clean" {
            assert!(
                output.stdout.split(|byte| *byte == b'\n').any(|line| {
                    serde_json::from_slice::<serde_json::Value>(line).is_ok_and(|message| {
                        message["reason"] == "compiler-message"
                            && message["message"]["code"]["code"] == "clippy::bool_comparison"
                            && message["message"]["level"]
                                == if successful { "warning" } else { "error" }
                    })
                }),
                "the real Clippy lint must execute, not just ordinary cargo check"
            );
        }
        let report = CargoArtifactReport::read(
            output.stdout.as_slice(),
            output_root.to_str().unwrap(),
            CargoArtifactMode::Compilation,
        );
        if successful {
            let report = report.unwrap();
            let required = report.files().map(str::to_owned).collect::<BTreeSet<_>>();
            assert!(required.iter().any(|name| name.ends_with(".rmeta")));
            let inventory =
                TreeInventory::scan(&output_root, &required, 128 * 1024 * 1024, &|| false).unwrap();
            report
                .validate_outputs(inventory.names().map(|name| {
                    let executable = fs::metadata(output_root.join(name))
                        .unwrap()
                        .permissions()
                        .mode()
                        & 0o111
                        != 0;
                    (name, executable)
                }))
                .unwrap();
            inventory.verify(&|| false).unwrap();
        } else {
            assert_eq!(output.status.code(), Some(101));
            assert!(
                report.is_err(),
                "denied lints must never offer a successful artifact report"
            );
        }
    }
}

#[test]
fn real_test_execution_reports_keep_harness_output_and_native_failure_status() {
    let (owner, root, home, tools) = workspace_fixture();
    fs::write(
        root.join("app/tests/integration.rs"),
        r#"#[test]
fn selected() {
    assert_eq!(artifact_library::VALUE, 42);
    assert!(std::env::args().any(|arg| arg == "--nocapture"));
    println!("test-program-stdout");
    println!("{{\"reason\":\"compiler-artifact\",\"filenames\":[\"/unowned/fake\"]}}");
    println!("{{\"reason\":\"build-finished\",\"success\":false}}");
    eprintln!("test-program-stderr");
}
#[test]
fn deliberate_failure() { panic!("intentional test failure after successful compilation"); }
"#,
    )
    .unwrap();
    let output_root = owner.path().join("test-execution-output");
    fs::create_dir(&output_root).unwrap();
    fs::set_permissions(&output_root, fs::Permissions::from_mode(0o700)).unwrap();
    for (filter, successful) in [("selected", true), ("deliberate_failure", false)] {
        let output = cargo(&tools, &root, &home)
            .args([
                "test",
                "--workspace",
                "--tests",
                filter,
                "--locked",
                "--offline",
                "--message-format=json",
                "--target-dir",
            ])
            .arg(&output_root)
            .args(["--", "--exact", "--nocapture", "--test-threads=1"])
            .output()
            .unwrap();
        assert_eq!(
            output.status.success(),
            successful,
            "{}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        let report = CargoArtifactReport::read(
            output.stdout.as_slice(),
            output_root.to_str().unwrap(),
            CargoArtifactMode::TestExecution,
        )
        .unwrap();
        let required = report.files().map(str::to_owned).collect::<BTreeSet<_>>();
        let inventory =
            TreeInventory::scan(&output_root, &required, 128 * 1024 * 1024, &|| false).unwrap();
        report
            .validate_outputs(inventory.names().map(|name| {
                let executable = fs::metadata(output_root.join(name))
                    .unwrap()
                    .permissions()
                    .mode()
                    & 0o111
                    != 0;
                (name, executable)
            }))
            .unwrap();
        assert!(required.iter().any(|name| name.contains("integration-")));
        assert!(!required.iter().any(|name| name.contains("fake")));
        if successful {
            let stdout = String::from_utf8_lossy(&output.stdout);
            let finished = stdout
                .find("\"reason\":\"build-finished\"")
                .expect("real Cargo completion");
            let ran = stdout
                .find("test-program-stdout")
                .expect("test harness ran");
            assert!(
                finished < ran,
                "Cargo must complete the report before starting tests"
            );
            assert!(stdout.contains("1 passed"));
            assert!(
                stdout.contains("/unowned/fake"),
                "test stdout must retain its literal bytes"
            );
            assert!(String::from_utf8_lossy(&output.stderr).contains("test-program-stderr"));
            assert!(
                CargoArtifactReport::read(
                    output.stdout.as_slice(),
                    output_root.to_str().unwrap(),
                    CargoArtifactMode::Compilation,
                )
                .is_err(),
                "test stdout is not a compilation-only report"
            );
        } else {
            // The compilation report legitimately succeeds; the worker must
            // use the final Cargo process status before offering artifacts.
            assert_eq!(output.status.code(), Some(101));
            assert!(String::from_utf8_lossy(&output.stdout).contains("1 failed"));
            assert!(String::from_utf8_lossy(&output.stderr).contains("intentional test failure"));
        }
        inventory.verify(&|| false).unwrap();
    }
}

#[test]
fn real_doctest_execution_follows_the_same_cargo_report_boundary() {
    let (owner, root, home, tools) = workspace_fixture();
    fs::write(root.join("library/src/lib.rs"),
        "/// ```\n/// assert_eq!(artifact_library::VALUE, 42);\n/// ```\npub fn documented() {}\ninclude!(concat!(env!(\"OUT_DIR\"), \"/generated.rs\"));\n").unwrap();
    let output_root = owner.path().join("doctest-output");
    let output = cargo(&tools, &root, &home)
        .env("RUSTDOC", tools.join("bin/rustdoc"))
        .args([
            "test",
            "-p",
            "artifact_library",
            "--doc",
            "--locked",
            "--offline",
            "--message-format=json",
            "--target-dir",
        ])
        .arg(&output_root)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let report = CargoArtifactReport::read(
        output.stdout.as_slice(),
        output_root.to_str().unwrap(),
        CargoArtifactMode::TestExecution,
    )
    .unwrap();
    assert!(report.files().any(|name| name.ends_with(".rlib")));
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("1 passed"),
        "the documentation example must actually execute"
    );
    assert!(
        stdout.find("\"reason\":\"build-finished\"").unwrap()
            < stdout.find("running 1 test").unwrap()
    );
}

/// Explicitly requested namespace evidence must fail on an unsupported host;
/// an ignored test is never converted into a successful no-op by probing.
#[test]
#[ignore = "requires working Linux user namespaces, bubblewrap and an installed Rust toolchain"]
fn canonical_namespace_build_check_and_test_compilation_capture_actual_outputs() {
    let support = HostIsolationSupport::probe();
    assert!(
        support.missing_for_canonical().is_empty(),
        "canonical Cargo execution requires real host isolation; missing {:?}",
        support.missing_for_canonical()
    );
    let (owner, root, home, tools) = workspace_fixture();
    fs::write(
        root.join("library/build.rs"),
        r#"fn main() {
    assert_eq!(std::env::var("CARGO_MANIFEST_DIR").unwrap(), "/__rabs/workspace/library");
    assert_eq!(std::env::current_dir().unwrap(), std::path::Path::new("/__rabs/workspace/library"));
    let out = std::path::PathBuf::from(std::env::var_os("OUT_DIR").unwrap());
    assert!(out.starts_with("/__rabs/out/cargo"));
    assert!(std::fs::OpenOptions::new().append(true)
        .open("/__rabs/workspace/library/src/lib.rs").is_err(),
        "the captured source must not be writable");
    assert!(std::fs::OpenOptions::new().write(true).create_new(true)
        .open("/__rabs/workspace/injected.rs").is_err(),
        "the captured source must not accept new files");
    std::fs::write(out.join("generated.rs"), "pub const VALUE: u32 = 42;").unwrap();
}
"#,
    )
    .unwrap();
    let image = capture_sealed_source(
        &[("workspace".to_owned(), root.clone())],
        false,
        3,
        1024 * 1024,
    )
    .unwrap();
    let provenance = image.provenance("workspace").unwrap();
    let materialized = image
        .materialize_into(&owner.path().join("snapshot"))
        .unwrap();
    let backing = materialized.backing("workspace").unwrap();
    assert_ne!(backing, root);
    fs::write(
        root.join("app/src/main.rs"),
        "compile_error!(\"the live checkout changed after capture\");\n",
    )
    .unwrap();

    for mode in ["build", "check", "test"] {
        let output_root = owner.path().join(format!("canonical-outputs-{mode}"));
        let cargo_home = owner.path().join(format!("canonical-cargo-home-{mode}"));
        fs::create_dir(&output_root).unwrap();
        fs::set_permissions(&output_root, fs::Permissions::from_mode(0o700)).unwrap();
        fs::create_dir(&cargo_home).unwrap();
        let mut plan = CanonicalMountPlan::new(&tools, backing, &cargo_home, &home)
            .with_immutable_source(backing, provenance.clone());
        plan.out_units.push(UnitMount {
            unit: "cargo".into(),
            backing: output_root.clone(),
        });
        plan.extra_env.extend(
            [
                ("RUSTC", "/__rabs/toolchain/bin/rustc"),
                ("CARGO_INCREMENTAL", "0"),
                ("CARGO_BUILD_JOBS", "1"),
                ("CARGO_PROFILE_DEV_DEBUG", "0"),
                ("CARGO_PROFILE_TEST_DEBUG", "0"),
            ]
            .map(|(key, value)| (key.to_owned(), value.to_owned())),
        );
        let spec = plan.to_spec().unwrap();
        let mut args = [
            mode,
            "--workspace",
            "--locked",
            "--offline",
            "--message-format=json",
            "--target-dir",
            "/__rabs/out/cargo",
        ]
        .map(str::to_owned)
        .to_vec();
        if mode == "test" {
            args.push("--no-run".into());
        }
        let launch =
            build_canonical_argv(&spec, &support, "/__rabs/toolchain/bin/cargo", &args).unwrap();
        let output = command_for(&launch).output().unwrap();
        assert!(
            output.status.success(),
            "canonical {mode}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        let report = CargoArtifactReport::read(
            output.stdout.as_slice(),
            "/__rabs/out/cargo",
            CargoArtifactMode::Compilation,
        )
        .unwrap();
        let required = report.files().map(str::to_owned).collect::<BTreeSet<_>>();
        let inventory =
            TreeInventory::scan(&output_root, &required, 128 * 1024 * 1024, &|| false).unwrap();
        report
            .validate_outputs(inventory.names().map(|name| {
                let executable = fs::metadata(output_root.join(name))
                    .unwrap()
                    .permissions()
                    .mode()
                    & 0o111
                    != 0;
                (name, executable)
            }))
            .unwrap();
        assert!(report.files().any(|name| name.contains("artifact_library")));
        assert!(report.files().any(|name| name.contains("artifact_app")));
        // Cargo reports compiler outputs, while delivery must also preserve
        // the generated build-script files and all remaining tree entries.
        assert!(!required.iter().any(|name| name.ends_with("/generated.rs")));
        assert!(
            inventory
                .names()
                .any(|name| name.ends_with("/generated.rs"))
        );
        let executable = match mode {
            "build" => {
                assert!(required.contains("debug/artifact_app"));
                Some("debug/artifact_app".to_owned())
            }
            "check" => {
                assert!(required.iter().any(|name| name.ends_with(".rmeta")));
                None
            }
            "test" => Some(
                required
                    .iter()
                    .find(|name| {
                        Path::new(name)
                            .file_name()
                            .is_some_and(|name| name.to_string_lossy().starts_with("integration-"))
                    })
                    .unwrap_or_else(|| panic!("Cargo omitted the integration test: {required:?}"))
                    .clone(),
            ),
            _ => unreachable!(),
        };
        if let Some(executable) = executable {
            // Execute the produced programs as independent assertions, using
            // the same canonical mounts rather than hidden physical paths.
            let launch = build_canonical_argv(
                &spec,
                &support,
                &format!("/__rabs/out/cargo/{executable}"),
                &[],
            )
            .unwrap();
            let ran = command_for(&launch).output().unwrap();
            assert!(
                ran.status.success(),
                "canonical {mode} output: {}{}",
                String::from_utf8_lossy(&ran.stdout),
                String::from_utf8_lossy(&ran.stderr)
            );
            if mode == "build" {
                assert_eq!(ran.stdout, b"42\n");
            } else {
                assert!(String::from_utf8_lossy(&ran.stdout).contains("1 passed"));
            }
        }
        inventory.verify(&|| false).unwrap();
        assert_eq!(
            fs::read(backing.join("app/src/main.rs")).unwrap(),
            image.file_bytes("workspace", "app/src/main.rs").unwrap()
        );
        assert!(!backing.join("injected.rs").exists());
        assert!(!backing.join("target").exists());
    }
    assert_eq!(
        fs::read_to_string(root.join("app/src/main.rs")).unwrap(),
        "compile_error!(\"the live checkout changed after capture\");\n"
    );
}
