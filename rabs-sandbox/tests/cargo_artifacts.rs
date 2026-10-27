//! Real Cargo output discovery for compilation, tests, programs and benchmarks.
//! Stock local Cargo and an opt-in canonical namespace exercise production
//! JSON/tree validation. Neither substitutes for worker/TLS integration or
//! authorizes cache serving.
#![cfg(target_os = "linux")]

use rabs_sandbox::artifact_tree::TreeInventory;
use rabs_sandbox::canonical_mounts::{CanonicalMountPlan, UnitMount};
use rabs_sandbox::canonical_namespace::{HostIsolationSupport, build_canonical_argv, command_for};
use rabs_sandbox::cargo_artifacts::{
    CARGO_PRIVATE_INCREMENTAL_ARTIFACTS_VERSION, CargoArtifactMode, CargoArtifactReport,
    is_private_incremental_file, private_incremental_roots,
};
use rabs_sandbox::cargo_target::{compatible_arguments, source_edit_identity};
use rabs_sandbox::snapshot_capture::{MemberKind, capture_sealed_source};
use rabs_sandbox::source_transfer::{SourceFile, SourceManifest};
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
fn real_private_incremental_projection_preserves_outputs_and_reuses_edited_compilation() {
    let (owner, root, home, tools) = workspace_fixture();
    let manifest = root.join("Cargo.toml");
    fs::write(
        &manifest,
        format!(
            "{}\n[profile.incremental]\ninherits='dev'\nincremental=false\n",
            fs::read_to_string(&manifest).unwrap()
        ),
    )
    .unwrap();
    let version = Command::new(tools.join("bin/rustc"))
        .arg("-vV")
        .output()
        .unwrap();
    assert!(version.status.success());
    let version = String::from_utf8(version.stdout).unwrap();
    let host = version
        .lines()
        .find_map(|line| line.strip_prefix("host: "))
        .expect("real rustc must identify its host triple");

    // This is the shared production JSON/tree boundary with native Cargo.
    // It does not exercise worker transport or persistent target-cache restore.
    for custom in [false, true] {
        let label = if custom { "custom-host" } else { "default" };
        let output_root = owner.path().join(label);
        fs::create_dir(&output_root).unwrap();
        fs::set_permissions(&output_root, fs::Permissions::from_mode(0o700)).unwrap();
        let mut args = [
            "build",
            "--workspace",
            "--locked",
            "--offline",
            "--message-format=json",
            "--target-dir=/__rabs/out/cargo",
        ]
        .map(str::to_owned)
        .to_vec();
        let executable = if custom {
            args.extend(["--profile=incremental".into(), format!("--target={host}")]);
            format!("{host}/incremental/artifact_app")
        } else {
            "debug/artifact_app".to_owned()
        };
        let request = serde_json::json!({
            "program":"/__rabs/toolchain/bin/cargo", "args":args,
            "command_context":{"version":"env-cwd-v1", "cwd":"/__rabs/workspace",
                "env":{"CARGO_INCREMENTAL":"1"}},
            "artifacts":{"unit":"cargo", "tree":"tree-files-v1", "files":[],
                "cargo":CARGO_PRIVATE_INCREMENTAL_ARTIFACTS_VERSION}
        });
        let roots = private_incremental_roots(&request).unwrap().unwrap();
        let mut expected_roots = if custom {
            vec![
                "incremental/incremental".to_owned(),
                format!("{host}/incremental/incremental"),
            ]
        } else {
            vec!["debug/incremental".to_owned()]
        };
        expected_roots.sort();
        assert_eq!(roots, expected_roots);

        for offset in [0, 1] {
            fs::write(
                root.join("app/src/main.rs"),
                format!(
                    "fn main() {{ println!(\"{{}}\", artifact_library::VALUE + {offset}); }}\n"
                ),
            )
            .unwrap();
            let output = cargo(&tools, &root, &home)
                .env("CARGO_INCREMENTAL", "1")
                // Diagnostic instrumentation only; this flag is not admitted
                // as a production command-context override.
                .env("RUSTFLAGS", "-Zincremental-info")
                .args(args.iter().map(|argument| {
                    if argument == "--target-dir=/__rabs/out/cargo" {
                        format!("--target-dir={}", output_root.display())
                    } else {
                        argument.clone()
                    }
                }))
                .output()
                .unwrap();
            let stderr = String::from_utf8_lossy(&output.stderr);
            assert!(output.status.success(), "{label} edit={offset}: {stderr}");
            let reused_files: usize = stderr
                .lines()
                .filter_map(|line| {
                    line.strip_prefix("[incremental] session directory: ")?
                        .strip_suffix(" files hard-linked")?
                        .parse::<usize>()
                        .ok()
                })
                .sum();
            if offset == 0 {
                assert_eq!(reused_files, 0, "a cold build has no prior session");
            } else {
                assert!(
                    reused_files > 0,
                    "{label}: edited rustc did not reuse its prior session: {stderr}"
                );
            }
            let report = CargoArtifactReport::read(
                output.stdout.as_slice(),
                output_root.to_str().unwrap(),
                CargoArtifactMode::Compilation,
            )
            .unwrap();
            let required = report.files().map(str::to_owned).collect::<BTreeSet<_>>();
            assert!(required.contains(&executable));
            assert!(
                required
                    .iter()
                    .all(|name| !is_private_incremental_file(&roots, name)),
                "no Cargo-reported output may disappear into private state"
            );
            let inventory =
                TreeInventory::scan(&output_root, &required, 128 * 1024 * 1024, &|| false).unwrap();
            let private = inventory
                .names()
                .filter(|name| is_private_incremental_file(&roots, name))
                .collect::<Vec<_>>();
            for suffix in ["dep-graph.bin", "query-cache.bin", "work-products.bin"] {
                assert!(
                    private.iter().any(|name| name.ends_with(suffix)),
                    "{label}: real rustc did not retain {suffix} under {roots:?}"
                );
                assert!(
                    inventory
                        .names()
                        .filter(|name| name.ends_with(suffix))
                        .all(|name| is_private_incremental_file(&roots, name)),
                    "{label}: compiler state escaped the derived roots"
                );
            }
            let mut public = Vec::new();
            let mut public_bytes = 0_u64;
            let mut private_bytes = 0_u64;
            for name in inventory.names() {
                let mut file = inventory.open_file(name).unwrap();
                let metadata = file.metadata().unwrap();
                if is_private_incremental_file(&roots, name) {
                    private_bytes += metadata.len();
                } else {
                    public_bytes += std::io::copy(&mut file, &mut std::io::sink()).unwrap();
                    public.push((name, metadata.permissions().mode() & 0o111 != 0));
                }
                inventory.verify_file(name, &file).unwrap();
            }
            report.validate_outputs(public).unwrap();
            assert!(private_bytes > 0);
            assert!(public_bytes > 0 && public_bytes < inventory.total_bytes());
            assert_eq!(public_bytes + private_bytes, inventory.total_bytes());
            inventory.verify(&|| false).unwrap();
            let ran = Command::new(output_root.join(&executable))
                .output()
                .unwrap();
            assert!(ran.status.success());
            assert_eq!(ran.stdout, format!("{}\n", 42 + offset).as_bytes());
            eprintln!(
                "{label} edit={offset}: {} private files, {private_bytes} private bytes, \
                 {public_bytes} public bytes, {reused_files} prior-session files reused",
                private.len()
            );
        }
    }
}

/// Exercise the shared private-target selection policy against actual Cargo
/// fingerprints and captured source bytes. This is not daemon placement, worker
/// target restoration or a result-cache test: every command below executes.
#[test]
fn real_cargo_feature_family_keeps_dependencies_fresh_and_reexecutes_current_program() {
    let (owner, root, home, tools) = workspace_fixture();
    fs::write(
        root.join("app/Cargo.toml"),
        "[package]\nname='artifact_app'\nversion='0.1.0'\nedition='2024'\n\
         [dependencies]\nartifact_library={path='../library'}\n\
         [features]\ndefault=['baseline']\nbaseline=[]\nextra=[]\n",
    )
    .unwrap();
    fs::write(
        root.join("app/build.rs"),
        r#"fn main() {
    let baseline = u32::from(std::env::var_os("CARGO_FEATURE_BASELINE").is_some());
    let extra = u32::from(std::env::var_os("CARGO_FEATURE_EXTRA").is_some());
    std::fs::write(std::path::Path::new(&std::env::var_os("OUT_DIR").unwrap()).join("features.rs"),
        (baseline * 100 + extra * 1000).to_string()).unwrap();
    println!("cargo:rerun-if-changed=build.rs");
}
"#,
    )
    .unwrap();
    fs::write(
        root.join("app/src/main.rs"),
        r#"fn main() {
    let generated: u32 = include!(concat!(env!("OUT_DIR"), "/features.rs"));
    let compiled = u32::from(cfg!(feature = "baseline")) * 100
        + u32::from(cfg!(feature = "extra")) * 1000;
    assert_eq!(generated, compiled, "build-script and compiler features must agree");
    println!("feature-value:{}", artifact_library::VALUE + generated);
}
"#,
    )
    .unwrap();
    let output_root = owner.path().join("feature-target");
    fs::create_dir(&output_root).unwrap();
    fs::set_permissions(&output_root, fs::Permissions::from_mode(0o700)).unwrap();
    let mode = CargoArtifactMode::RunExecution;
    let arguments = |selection: &[&str]| {
        [
            "run",
            "--package=artifact_app",
            "--locked",
            "--offline",
            "--message-format=json",
            "--target-dir=/__rabs/out/cargo",
        ]
        .into_iter()
        .chain(selection.iter().copied())
        .map(str::to_owned)
        .collect::<Vec<_>>()
    };
    let family = compatible_arguments("/__rabs/toolchain/bin/cargo", &arguments(&[]), mode)
        .expect("ordinary Cargo feature-family fixture");
    for (index, (selection, value, fresh)) in [
        (vec![], 142, false),
        (vec!["--no-default-features"], 42, false),
        (
            vec!["--no-default-features", "--features", "extra"],
            1042,
            false,
        ),
        (vec!["--all-features"], 1142, false),
        (vec!["-F", "baseline"], 142, true),
        (
            vec!["--features=extra", "--no-default-features"],
            1042,
            true,
        ),
    ]
    .into_iter()
    .enumerate()
    {
        let args = arguments(&selection);
        assert_eq!(
            compatible_arguments("/__rabs/toolchain/bin/cargo", &args, mode),
            Some(family.clone()),
            "feature selection must preserve the private target family",
        );
        let output = cargo(&tools, &root, &home)
            .args(args.iter().map(|argument| {
                if argument == "--target-dir=/__rabs/out/cargo" {
                    format!("--target-dir={}", output_root.display())
                } else {
                    argument.clone()
                }
            }))
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{selection:?}: {}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr),
        );
        let artifacts = output
            .stdout
            .split(|byte| *byte == b'\n')
            .filter_map(|line| serde_json::from_slice::<serde_json::Value>(line).ok())
            .filter(|message| message["reason"] == "compiler-artifact")
            .collect::<Vec<_>>();
        for (package, expected) in [("artifact_library", index != 0), ("artifact_app", fresh)] {
            let selected = artifacts
                .iter()
                .filter(|artifact| artifact["target"]["name"] == package)
                .collect::<Vec<_>>();
            assert_eq!(selected.len(), 1, "one actual {package} artifact");
            assert_eq!(selected[0]["fresh"], expected, "{selection:?}: {package}");
        }
        let app_manifest = root.join("app/Cargo.toml");
        let script = artifacts
            .iter()
            .find(|artifact| {
                artifact["manifest_path"] == app_manifest.to_str().unwrap()
                    && artifact["target"]["kind"] == serde_json::json!(["custom-build"])
            })
            .expect("actual feature-dependent app build-script artifact");
        assert_eq!(script["fresh"], fresh, "{selection:?}: build script");
        assert!(
            output
                .stdout
                .ends_with(format!("feature-value:{value}\n").as_bytes()),
            "current feature-selected program output: {}",
            String::from_utf8_lossy(&output.stdout),
        );
        let report = CargoArtifactReport::read(
            output.stdout.as_slice(),
            output_root.to_str().unwrap(),
            mode,
        )
        .unwrap();
        let inventory =
            TreeInventory::scan_complete(&output_root, 128 * 1024 * 1024, &|| false).unwrap();
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
    }
}

/// Exercise source-edit family selection with real Cargo while keeping every
/// invocation's actual compiler and runtime behavior observable.
#[test]
fn real_cargo_source_edit_family_reuses_dependencies_across_commands_and_membership() {
    let (owner, root, home, tools) = workspace_fixture();
    let output_root = owner.path().join("compatible-target");
    let capture = || {
        let image = capture_sealed_source(
            &[("workspace".to_owned(), root.clone())],
            false,
            3,
            1024 * 1024,
        )
        .unwrap();
        let files = image
            .manifest("workspace")
            .unwrap()
            .members
            .iter()
            .filter_map(|(path, member)| match member {
                MemberKind::Regular {
                    size,
                    content_sha256,
                    mode,
                    ..
                } => Some(SourceFile {
                    path: path.clone(),
                    len: *size,
                    sha256: *content_sha256,
                    executable: mode & 0o111 != 0,
                }),
                MemberKind::Directory => None,
                MemberKind::Symlink { .. } => panic!("fixture contains no symlink"),
            })
            .collect();
        SourceManifest::new(files).unwrap()
    };
    let arguments = |command: &str, selection: &[&str]| {
        let mut args = [
            command,
            "--locked",
            "--offline",
            "--message-format=json",
            "--manifest-path=/__rabs/workspace/Cargo.toml",
            "--target-dir=/__rabs/out/cargo",
        ]
        .map(str::to_owned)
        .to_vec();
        args.extend(selection.iter().map(|argument| (*argument).to_owned()));
        args
    };
    let run = |args: &[String], mode| {
        let output = cargo(&tools, &root, &home)
            .args(args.iter().map(|argument| match argument.as_str() {
                "--manifest-path=/__rabs/workspace/Cargo.toml" => {
                    format!("--manifest-path={}", root.join("Cargo.toml").display())
                }
                "--target-dir=/__rabs/out/cargo" => {
                    format!("--target-dir={}", output_root.display())
                }
                _ => argument.clone(),
            }))
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{args:?}: {}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr),
        );
        let report = CargoArtifactReport::read(
            output.stdout.as_slice(),
            output_root.to_str().unwrap(),
            mode,
        )
        .unwrap();
        assert!(report.files().next().is_some());
        output
    };
    let base = capture();
    let family = source_edit_identity(&base, base.digest(), None).unwrap();
    let build_shape = compatible_arguments(
        "/__rabs/toolchain/bin/cargo",
        &arguments("build", &["--workspace"]),
        CargoArtifactMode::Compilation,
    )
    .unwrap();
    let mut previous = base.digest();

    for (step, expected, selection) in [
        ("cold", 42, vec!["--workspace"]),
        ("source-edit", 43, vec!["-p", "artifact_app"]),
        ("module-added", 44, vec!["--bin", "artifact_app"]),
        ("module-removed", 49, vec!["--workspace"]),
        ("data-added", 45, vec!["-p", "artifact_app"]),
        ("data-edited", 46, vec!["--bin", "artifact_app"]),
    ] {
        match step {
            "source-edit" => fs::write(
                root.join("app/src/main.rs"),
                "fn main() { println!(\"{}\", artifact_library::VALUE + 1); }\n",
            )
            .unwrap(),
            "module-added" => {
                fs::write(root.join("app/src/bonus.rs"), "pub const BONUS: u32 = 2;\n").unwrap();
                fs::write(
                    root.join("app/src/main.rs"),
                    "mod bonus; fn main() { println!(\"{}\", artifact_library::VALUE + bonus::BONUS); }\n",
                )
                .unwrap();
            }
            "module-removed" => {
                // Move outside the captured workspace so the old module is
                // absent while preserving its bytes for inspection.
                fs::rename(root.join("app/src/bonus.rs"), owner.path().join("bonus.rs")).unwrap();
                fs::write(
                    root.join("app/src/main.rs"),
                    "fn main() { println!(\"{}\", artifact_library::VALUE + 7); }\n",
                )
                .unwrap();
            }
            "data-added" => {
                fs::write(root.join("app/src/offset.txt"), "3\n").unwrap();
                fs::write(
                    root.join("app/src/main.rs"),
                    "fn main() { println!(\"{}\", artifact_library::VALUE + include_str!(\"offset.txt\").trim().parse::<u32>().unwrap()); }\n",
                )
                .unwrap();
            }
            "data-edited" => fs::write(root.join("app/src/offset.txt"), "4\n").unwrap(),
            "cold" => {}
            _ => unreachable!(),
        }
        let captured = capture();
        assert_eq!(
            source_edit_identity(&captured, captured.digest(), None),
            Some(family),
            "{step} must retain the private Cargo seed family",
        );
        if step != "cold" {
            assert_ne!(
                captured.digest(),
                previous,
                "{step} must still have a different exact source identity",
            );
        }
        previous = captured.digest();
        let args = arguments("build", &selection);
        assert_eq!(
            compatible_arguments(
                "/__rabs/toolchain/bin/cargo",
                &args,
                CargoArtifactMode::Compilation,
            ),
            Some(build_shape.clone()),
        );
        let output = run(&args, CargoArtifactMode::Compilation);
        let artifacts = output
            .stdout
            .split(|byte| *byte == b'\n')
            .filter_map(|line| serde_json::from_slice::<serde_json::Value>(line).ok())
            .filter(|message| message["reason"] == "compiler-artifact")
            .collect::<Vec<_>>();
        for (name, expected_fresh) in [
            ("artifact_library", step != "cold"),
            ("artifact_app", false),
        ] {
            let artifact = artifacts
                .iter()
                .find(|message| message["target"]["name"] == name)
                .unwrap_or_else(|| panic!("{step}: missing real Cargo artifact for {name}"));
            assert_eq!(artifact["fresh"], expected_fresh, "{step}: {name}");
        }
        let executed = Command::new(output_root.join("debug/artifact_app"))
            .output()
            .unwrap();
        assert!(executed.status.success());
        assert_eq!(executed.stdout, format!("{expected}\n").as_bytes());
        eprintln!(
            "{step}: output={expected}, dependency fresh={}",
            step != "cold"
        );
    }

    for (command, selection, mode) in [
        ("check", vec!["--workspace"], CargoArtifactMode::Compilation),
        (
            "test",
            vec!["--workspace", "--no-run"],
            CargoArtifactMode::Compilation,
        ),
        (
            "test",
            vec!["-p", "artifact_library", "--lib", "value", "--", "--exact"],
            CargoArtifactMode::TestExecution,
        ),
    ] {
        let args = arguments(command, &selection);
        assert_eq!(
            compatible_arguments("/__rabs/toolchain/bin/cargo", &args, mode),
            Some(build_shape.clone()),
        );
        let output = run(&args, mode);
        if mode == CargoArtifactMode::TestExecution {
            assert!(
                String::from_utf8_lossy(&output.stdout).contains("1 passed"),
                "test selection must execute the real test after compilation",
            );
        }
    }
    let clippy = compatible_arguments(
        "/__rabs/toolchain/bin/cargo-clippy",
        &arguments("clippy", &["--workspace", "--", "-Dwarnings"]),
        CargoArtifactMode::Compilation,
    )
    .unwrap();
    assert_ne!(clippy, build_shape, "Clippy retains a separate seed family");
    assert_ne!(
        Some(clippy),
        compatible_arguments(
            "/__rabs/toolchain/bin/cargo-clippy",
            &arguments("clippy", &["-p", "artifact_library", "--", "-Dwarnings"]),
            CargoArtifactMode::Compilation,
        ),
        "Clippy package selection must not erase lint execution",
    );

    let manifest = root.join("Cargo.toml");
    fs::write(
        &manifest,
        format!(
            "{}\n# resolution/configuration boundary changed\n",
            fs::read_to_string(&manifest).unwrap()
        ),
    )
    .unwrap();
    let changed = capture();
    assert_ne!(
        source_edit_identity(&changed, changed.digest(), None),
        Some(family),
        "Cargo manifests remain exact even when the edited comment changes no output",
    );
}

/// The driver keeps Cargo-visible paths stable while replacing their hidden
/// backing directories. These stock-Cargo tests reproduce that replacement at
/// one stable host path, exercising the production snapshot/timestamp helpers.
/// They establish private-copy and Cargo freshness behavior; the separate
/// canonical driver tests establish namespace relocation and cache serving.
mod private_target_state {
    use super::*;
    use rabs_sandbox::cargo_target::state::{PrivateTreeSnapshot, SourceTimestamps};
    use std::fs::File;
    use std::os::unix::fs::{DirBuilderExt, MetadataExt};
    use std::time::SystemTime;

    const BUDGET: u64 = 128 * 1024 * 1024;

    fn private(path: &Path) {
        fs::DirBuilder::new().mode(0o700).create(path).unwrap();
    }

    fn manifest(root: &Path) -> SourceManifest {
        let captured = capture_sealed_source(
            &[("workspace".to_owned(), root.to_path_buf())],
            false,
            3,
            1024 * 1024,
        )
        .unwrap();
        SourceManifest::new(
            captured
                .manifest("workspace")
                .unwrap()
                .members
                .iter()
                .filter_map(|(path, member)| match member {
                    MemberKind::Regular {
                        size,
                        content_sha256,
                        mode,
                        ..
                    } => Some(SourceFile {
                        path: path.clone(),
                        len: *size,
                        sha256: *content_sha256,
                        executable: mode & 0o111 != 0,
                    }),
                    MemberKind::Directory => None,
                    MemberKind::Symlink { .. } => panic!("fixture has no source symlinks"),
                })
                .collect(),
        )
        .unwrap()
    }

    fn compile(
        tools: &Path,
        root: &Path,
        home: &Path,
        target: &Path,
        mode: &str,
        selection: &[&str],
    ) -> Vec<serde_json::Value> {
        let output = cargo(tools, root, home)
            .args([
                mode,
                "--workspace",
                "--offline",
                "--locked",
                "--message-format=json",
                "--target-dir",
            ])
            .arg(target)
            .args(selection)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{mode} {selection:?}: {}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr),
        );
        let report = CargoArtifactReport::read(
            output.stdout.as_slice(),
            target.to_str().unwrap(),
            CargoArtifactMode::Compilation,
        )
        .unwrap();
        assert!(!validated_products(target, &report).is_empty());
        output
            .stdout
            .split(|byte| *byte == b'\n')
            .filter_map(|line| serde_json::from_slice::<serde_json::Value>(line).ok())
            .filter(|message| message["reason"] == "compiler-artifact")
            .collect()
    }

    fn freshness(artifacts: &[serde_json::Value], library: bool, app: bool) {
        for (name, expected) in [("artifact_library", library), ("artifact_app", app)] {
            let selected = artifacts
                .iter()
                .filter(|artifact| artifact["target"]["name"] == name)
                .collect::<Vec<_>>();
            assert_eq!(selected.len(), 1, "one compiled target for {name}");
            assert_eq!(selected[0]["fresh"], expected, "{name}: {artifacts:?}");
        }
    }

    fn run(target: &Path, expected: u32) {
        let output = Command::new(target.join("debug/artifact_app"))
            .output()
            .unwrap();
        assert!(output.status.success());
        assert_eq!(output.stdout, format!("{expected}\n").as_bytes());
    }

    fn seed(target: &Path, destination: &Path) -> PrivateTreeSnapshot {
        let snapshot = PrivateTreeSnapshot::capture(target, BUDGET, &|| false).unwrap();
        assert!(snapshot.total_bytes() > 0);
        private(destination);
        snapshot
            .restore_into(target, destination, &|| false)
            .unwrap();
        snapshot
    }

    fn restore(target: &Path, seed: &Path, snapshot: &PrivateTreeSnapshot, retired: &Path) {
        fs::rename(target, retired).unwrap();
        private(target);
        snapshot.restore_into(seed, target, &|| false).unwrap();
        let installed = fs::metadata(target.join("debug/artifact_app")).unwrap();
        let retained = fs::metadata(seed.join("debug/artifact_app")).unwrap();
        let delivered = fs::metadata(retired.join("debug/artifact_app")).unwrap();
        assert_ne!(
            (installed.dev(), installed.ino()),
            (retained.dev(), retained.ino())
        );
        assert_ne!(
            (delivered.dev(), delivered.ino()),
            (retained.dev(), retained.ino())
        );
    }

    #[test]
    fn real_cargo_proc_macro_untracked_reads_require_exact_source_identity() {
        let (owner, root, home, tools) = workspace_fixture();
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
        fs::create_dir_all(root.join("reader/src")).unwrap();
        fs::write(
            root.join("Cargo.toml"),
            "[workspace]\nmembers=['library','app','reader']\nresolver='2'\n",
        )
        .unwrap();
        fs::write(
            root.join("reader/Cargo.toml"),
            "[package]\nname='artifact_reader'\nversion='0.1.0'\nedition='2024'\n[lib]\nproc-macro=true\n",
        )
        .unwrap();
        fs::write(
            root.join("reader/src/lib.rs"),
            r#"
extern crate proc_macro;
#[proc_macro]
pub fn value(_: proc_macro::TokenStream) -> proc_macro::TokenStream {
    let root = std::env::var_os("CARGO_MANIFEST_DIR").unwrap();
    // Ordinary procedural-macro filesystem reads are not rustc dep-info.
    std::fs::read_to_string(std::path::Path::new(&root).join("macro-value.txt"))
        .unwrap().trim().parse().unwrap()
}
"#,
        )
        .unwrap();
        fs::write(
            root.join("app/Cargo.toml"),
            "[package]\nname='artifact_app'\nversion='0.1.0'\nedition='2024'\n\
             [dependencies]\nartifact_library={path='../library'}\nartifact_reader={path='../reader'}\n",
        )
        .unwrap();
        fs::write(
            root.join("app/src/main.rs"),
            "fn main(){println!(\"{}\",artifact_library::VALUE+artifact_reader::value!());}\n",
        )
        .unwrap();
        fs::write(root.join("app/macro-value.txt"), b"1u32\n").unwrap();
        let lock = cargo(&tools, &root, &home)
            .args(["generate-lockfile", "--offline"])
            .output()
            .unwrap();
        assert!(
            lock.status.success(),
            "{}",
            String::from_utf8_lossy(&lock.stderr)
        );

        let source = manifest(&root);
        let times = SourceTimestamps::capture(&root, &source, &|| false).unwrap();
        let target = owner.path().join("macro-target");
        private(&target);
        freshness(
            &compile(&tools, &root, &home, &target, "build", &[]),
            false,
            false,
        );
        run(&target, 43);
        let retained = owner.path().join("macro-seed");
        let snapshot = seed(&target, &retained);
        restore(
            &target,
            &retained,
            &snapshot,
            &owner.path().join("macro-cold-output"),
        );
        freshness(
            &compile(&tools, &root, &home, &target, "build", &[]),
            true,
            true,
        );
        run(&target, 43);

        fs::write(root.join("app/macro-value.txt"), b"2u32\n").unwrap();
        let edited = manifest(&root);
        assert_ne!(edited.digest(), source.digest());
        assert_eq!(
            source_edit_identity(&edited, edited.digest(), None),
            source_edit_identity(&source, source.digest(), None),
            "the compiler-only family deliberately ignores ordinary data edits",
        );
        let current_times = SourceTimestamps::capture(&root, &edited, &|| false).unwrap();
        let edited_times = times
            .for_edits(
                &source,
                &edited,
                &current_times,
                &snapshot,
                SystemTime::now(),
            )
            .unwrap();
        edited_times
            .restore_exact(&root, &edited, &|| false)
            .unwrap();
        restore(
            &target,
            &retained,
            &snapshot,
            &owner.path().join("macro-identical-output"),
        );
        // Negative control: retiming an untracked read does not invalidate
        // Cargo's consumer fingerprint. This is precisely why executor graphs
        // must bind the full source digest instead of the source-edit family.
        freshness(
            &compile(&tools, &root, &home, &target, "build", &[]),
            true,
            true,
        );
        run(&target, 43);

        // The changed exact source identity cannot select the old generation.
        // Keep its output for comparison, then execute into an empty target.
        fs::rename(&target, owner.path().join("macro-stale-negative-control")).unwrap();
        private(&target);
        freshness(
            &compile(&tools, &root, &home, &target, "build", &[]),
            false,
            false,
        );
        run(&target, 44);
        let edited_seed = owner.path().join("macro-edited-seed");
        let edited_snapshot = seed(&target, &edited_seed);
        restore(
            &target,
            &edited_seed,
            &edited_snapshot,
            &owner.path().join("macro-current-output"),
        );
        freshness(
            &compile(&tools, &root, &home, &target, "build", &[]),
            true,
            true,
        );
        run(&target, 44);
    }

    #[test]
    fn real_cargo_assembler_untracked_reads_require_exact_source_identity() {
        let (owner, root, home, tools) = workspace_fixture();
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
        fs::write(
            root.join("library/Cargo.toml"),
            "[package]\nname='artifact_library'\nversion='0.1.0'\nedition='2024'\nbuild=false\n",
        )
        .unwrap();
        fs::write(
            root.join("library/src/lib.rs"),
            r#"
core::arch::global_asm!(concat!(
    ".pushsection .rodata.rabs_payload,\"a\"\n.incbin \"",
    env!("CARGO_MANIFEST_DIR"), "/payload.bin\"\n.popsection"
));
pub const VALUE:u32=42;
"#,
        )
        .unwrap();
        const OLD: &[u8] = b"RABS_UNTRACKED_ASSEMBLER_PAYLOAD_OLD_735891";
        const NEW: &[u8] = b"RABS_UNTRACKED_ASSEMBLER_PAYLOAD_NEW_735891";
        fs::write(root.join("library/payload.bin"), OLD).unwrap();
        let source = manifest(&root);
        let times = SourceTimestamps::capture(&root, &source, &|| false).unwrap();
        let target = owner.path().join("assembler-target");
        private(&target);
        let archive = |wanted: &[u8], unwanted: &[u8]| {
            let files = fs::read_dir(target.join("debug/deps"))
                .unwrap()
                .map(|entry| entry.unwrap().path())
                .filter(|path| {
                    path.file_name()
                        .unwrap()
                        .to_str()
                        .unwrap()
                        .starts_with("libartifact_library")
                        && path
                            .extension()
                            .is_some_and(|extension| extension == "rlib")
                })
                .collect::<Vec<_>>();
            assert_eq!(files.len(), 1, "one actual library archive");
            let bytes = fs::read(&files[0]).unwrap();
            assert!(bytes.windows(wanted.len()).any(|window| window == wanted));
            assert!(
                !bytes
                    .windows(unwanted.len())
                    .any(|window| window == unwanted)
            );
        };
        freshness(
            &compile(&tools, &root, &home, &target, "build", &[]),
            false,
            false,
        );
        archive(OLD, NEW);
        let retained = owner.path().join("assembler-seed");
        let snapshot = seed(&target, &retained);
        restore(
            &target,
            &retained,
            &snapshot,
            &owner.path().join("assembler-cold-output"),
        );
        freshness(
            &compile(&tools, &root, &home, &target, "build", &[]),
            true,
            true,
        );
        archive(OLD, NEW);
        fs::write(root.join("library/payload.bin"), NEW).unwrap();
        let edited = manifest(&root);
        assert_ne!(source.digest(), edited.digest());
        assert_eq!(
            source_edit_identity(&source, source.digest(), None),
            source_edit_identity(&edited, edited.digest(), None)
        );
        let current = SourceTimestamps::capture(&root, &edited, &|| false).unwrap();
        times
            .for_edits(&source, &edited, &current, &snapshot, SystemTime::now())
            .unwrap()
            .restore_exact(&root, &edited, &|| false)
            .unwrap();
        restore(
            &target,
            &retained,
            &snapshot,
            &owner.path().join("assembler-identical-output"),
        );
        // Negative control: LLVM's .incbin file read is absent from rustc
        // dep-info. Cargo keeps the archive fresh despite the newer input.
        freshness(
            &compile(&tools, &root, &home, &target, "build", &[]),
            true,
            true,
        );
        archive(OLD, NEW);
        fs::rename(
            &target,
            owner.path().join("assembler-stale-negative-control"),
        )
        .unwrap();
        private(&target);
        freshness(
            &compile(&tools, &root, &home, &target, "build", &[]),
            false,
            false,
        );
        archive(NEW, OLD);
        let updated_seed = owner.path().join("assembler-updated-seed");
        let updated_snapshot = seed(&target, &updated_seed);
        restore(
            &target,
            &updated_seed,
            &updated_snapshot,
            &owner.path().join("assembler-current-output"),
        );
        freshness(
            &compile(&tools, &root, &home, &target, "build", &[]),
            true,
            true,
        );
        archive(NEW, OLD);
    }

    #[test]
    fn real_cargo_private_snapshots_restore_freshness_and_rebuild_edited_sources() {
        let (owner, root, home, tools) = workspace_fixture();
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
        // Exercise snapshot/timestamp mechanics with tracked inputs. This is
        // not codegen-reuse authority: production build keys bind exact source
        // because other programs may use untracked assembler input reads.
        // The existing fixture's dormant build.rs remains a captured input.
        fs::write(
            root.join("library/Cargo.toml"),
            "[package]\nname='artifact_library'\nversion='0.1.0'\nedition='2024'\nbuild=false\n",
        )
        .unwrap();
        fs::write(root.join("library/src/lib.rs"), "pub const VALUE:u32=42;\n").unwrap();
        fs::write(
            root.join("app/Cargo.toml"),
            "[package]\nname='artifact_app'\nversion='0.1.0'\nedition='2024'\n\
             [dependencies]\nartifact_library={path='../library'}\n\
             [features]\nextra=[]\n",
        )
        .unwrap();
        let app_source = |extra: u32| {
            format!(
                "fn main(){{println!(\"{{}}\",artifact_library::VALUE+{extra}+u32::from(cfg!(feature=\"extra\"))*100);}}\n"
            )
        };
        fs::write(root.join("app/src/main.rs"), app_source(0)).unwrap();
        let source = manifest(&root);
        let times = SourceTimestamps::capture(&root, &source, &|| false).unwrap();
        let target = owner.path().join("private-target");
        private(&target);
        freshness(
            &compile(&tools, &root, &home, &target, "build", &[]),
            false,
            false,
        );
        run(&target, 42);

        let retained = owner.path().join("retained-target");
        let snapshot = seed(&target, &retained);
        let old_source = owner.path().join("source-before-recapture");
        fs::rename(&root, &old_source).unwrap();
        private(&root);
        // Real source recapture creates independent files with new mtimes.
        // Restoring those times is necessary for Cargo's existing fingerprints.
        for file in source.files() {
            let destination = root.join(&file.path);
            fs::create_dir_all(destination.parent().unwrap()).unwrap();
            fs::copy(old_source.join(&file.path), &destination).unwrap();
            File::open(destination)
                .unwrap()
                .set_modified(SystemTime::now())
                .unwrap();
        }
        times.restore_exact(&root, &source, &|| false).unwrap();
        let delivered = owner.path().join("delivered-cold-target");
        restore(&target, &retained, &snapshot, &delivered);
        freshness(
            &compile(&tools, &root, &home, &target, "build", &[]),
            true,
            true,
        );
        run(&target, 42);

        // A caller may mutate its delivered executable. The retained seed and
        // the next private target must never share that writable inode.
        fs::write(
            delivered.join("debug/artifact_app"),
            b"caller replaced output",
        )
        .unwrap();
        restore(
            &target,
            &retained,
            &snapshot,
            &owner.path().join("delivered-warm-target"),
        );
        freshness(
            &compile(&tools, &root, &home, &target, "build", &[]),
            true,
            true,
        );
        run(&target, 42);

        fs::write(root.join("app/src/main.rs"), app_source(1)).unwrap();
        let edited = manifest(&root);
        assert_ne!(edited.digest(), source.digest());
        assert_eq!(
            source_edit_identity(&edited, edited.digest(), None),
            source_edit_identity(&source, source.digest(), None),
        );
        let current_times = SourceTimestamps::capture(&root, &edited, &|| false).unwrap();
        let edited_times = times
            .for_edits(
                &source,
                &edited,
                &current_times,
                &snapshot,
                SystemTime::now(),
            )
            .unwrap();
        edited_times
            .restore_exact(&root, &edited, &|| false)
            .unwrap();
        restore(
            &target,
            &retained,
            &snapshot,
            &owner.path().join("delivered-before-edit"),
        );
        freshness(
            &compile(&tools, &root, &home, &target, "build", &[]),
            true,
            false,
        );
        run(&target, 43);

        let edited_seed = owner.path().join("edited-seed");
        let edited_snapshot = seed(&target, &edited_seed);
        restore(
            &target,
            &edited_seed,
            &edited_snapshot,
            &owner.path().join("delivered-edited"),
        );
        freshness(
            &compile(
                &tools,
                &root,
                &home,
                &target,
                "build",
                &["--features=extra"],
            ),
            true,
            false,
        );
        run(&target, 143);

        // Check emits its own compiler artifacts. Run it once, retain the real
        // result, then demand Cargo's fresh report from an independently copied
        // target generation instead of assuming build/check compatibility.
        compile(&tools, &root, &home, &target, "check", &[]);
        let checked_seed = owner.path().join("checked-seed");
        let checked_snapshot = seed(&target, &checked_seed);
        restore(
            &target,
            &checked_seed,
            &checked_snapshot,
            &owner.path().join("delivered-checked"),
        );
        freshness(
            &compile(&tools, &root, &home, &target, "check", &[]),
            true,
            true,
        );

        // The metadata document is not authority for altered retained bytes.
        // A corrupt seed must be rejected before the caller selects it as the
        // next target; there is deliberately no Cargo run after this refusal.
        fs::write(checked_seed.join("debug/artifact_app"), b"corrupt seed").unwrap();
        let rejected = owner.path().join("rejected-private-target");
        private(&rejected);
        assert!(
            checked_snapshot
                .restore_into(&checked_seed, &rejected, &|| false)
                .is_err()
        );
        run(&target, 143);
    }
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
fn real_cargo_run_keeps_program_arguments_and_reports_native_failure() {
    let (owner, root, home, tools) = workspace_fixture();
    fs::write(
        root.join("app/src/main.rs"),
        r#"fn main() {
    assert_eq!(artifact_library::VALUE, 42);
    let args: Vec<_> = std::env::args().skip(1).collect();
    println!("run-arguments={args:?}");
    println!("{{\"reason\":\"compiler-artifact\",\"filenames\":[\"/unowned/run-fake\"]}}");
    println!("{{\"reason\":\"build-finished\",\"success\":false}}");
    eprintln!("run-program-stderr");
    if args.iter().any(|arg| arg == "--fail") { std::process::exit(23); }
}
"#,
    )
    .unwrap();
    let output_root = owner.path().join("run-execution-output");
    fs::create_dir(&output_root).unwrap();
    fs::set_permissions(&output_root, fs::Permissions::from_mode(0o700)).unwrap();
    for successful in [true, false] {
        let mut command = cargo(&tools, &root, &home);
        command
            .env("CARGO_INCREMENTAL", "1")
            .args([
                "run",
                "--package=artifact_app",
                "--bin=artifact_app",
                "--locked",
                "--offline",
                "--message-format=json",
                "--target-dir",
            ])
            .arg(&output_root)
            .args(["--", "two words", "--no-run", "--message-format=json"]);
        if !successful {
            command.arg("--fail");
        }
        let output = command.output().unwrap();
        assert_eq!(
            output.status.code(),
            Some(if successful { 0 } else { 23 }),
            "{}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        // A successful compilation report never overrides the native program
        // exit status. Worker integration separately denies failed delivery.
        let report = CargoArtifactReport::read(
            output.stdout.as_slice(),
            output_root.to_str().unwrap(),
            CargoArtifactMode::RunExecution,
        )
        .unwrap();
        let required = validated_products(&output_root, &report);
        assert!(required.contains("debug/artifact_app"));
        assert!(required.iter().any(|name| name.ends_with(".rlib")));
        assert!(!required.iter().any(|name| name.contains("run-fake")));
        assert!(output_root.join("debug/incremental").is_dir());
        let stdout = String::from_utf8_lossy(&output.stdout);
        let finished = stdout.find("\"reason\":\"build-finished\"").unwrap();
        let ran = stdout.find("run-arguments=").unwrap();
        assert!(finished < ran);
        assert!(stdout.contains("\"two words\", \"--no-run\", \"--message-format=json\""));
        assert!(stdout.contains("/unowned/run-fake"));
        assert!(String::from_utf8_lossy(&output.stderr).contains("run-program-stderr"));
        assert!(
            CargoArtifactReport::read(
                output.stdout.as_slice(),
                output_root.to_str().unwrap(),
                CargoArtifactMode::Compilation,
            )
            .is_err()
        );
        if !successful {
            assert_compilation_fresh(&output.stdout, "artifact_app");
            assert_compilation_fresh(&output.stdout, "artifact_library");
        }
    }
}

#[test]
fn real_cargo_bench_no_run_and_execution_keep_the_default_release_profile() {
    let (owner, root, home, tools) = workspace_fixture();
    let manifest = root.join("app/Cargo.toml");
    fs::write(
        &manifest,
        format!(
            "{}\n[[bench]]\nname='measured'\nharness=false\n",
            fs::read_to_string(&manifest).unwrap()
        ),
    )
    .unwrap();
    fs::create_dir(root.join("app/benches")).unwrap();
    fs::write(
        root.join("app/benches/measured.rs"),
        r#"fn main() {
    assert_eq!(artifact_library::VALUE, 42);
    std::fs::write(std::env::var_os("RABS_BENCH_MARKER").unwrap(), "executed").unwrap();
    let args: Vec<_> = std::env::args().skip(1).collect();
    println!("bench-arguments={args:?}");
    println!("{{\"reason\":\"compiler-artifact\",\"filenames\":[\"/unowned/bench-fake\"]}}");
    println!("{{\"reason\":\"build-finished\",\"success\":false}}");
    eprintln!("bench-program-stderr");
    if args.iter().any(|arg| arg == "--fail") { std::process::exit(29); }
}
"#,
    )
    .unwrap();
    let output_root = owner.path().join("bench-execution-output");
    fs::create_dir(&output_root).unwrap();
    fs::set_permissions(&output_root, fs::Permissions::from_mode(0o700)).unwrap();
    for (iteration, no_run, successful) in [(0, true, true), (1, false, true), (2, false, false)] {
        let marker = owner.path().join(format!("benchmark-ran-{iteration}"));
        let mut command = cargo(&tools, &root, &home);
        command
            .env("CARGO_INCREMENTAL", "1")
            .env("RABS_BENCH_MARKER", &marker)
            .args([
                "bench",
                "--package=artifact_app",
                "--bench=measured",
                "--locked",
                "--offline",
                "--message-format=json",
                "--target-dir",
            ])
            .arg(&output_root);
        if no_run {
            command.arg("--no-run");
        } else {
            command.args(["--", "two words", "--no-run", "--profile=dev"]);
            if !successful {
                command.arg("--fail");
            }
        }
        let output = command.output().unwrap();
        assert_eq!(
            output.status.success(),
            successful,
            "{}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        assert_eq!(marker.exists(), !no_run, "Cargo must honor --no-run");
        let report = CargoArtifactReport::read(
            output.stdout.as_slice(),
            output_root.to_str().unwrap(),
            if no_run {
                CargoArtifactMode::Compilation
            } else {
                CargoArtifactMode::BenchExecution
            },
        )
        .unwrap();
        let required = validated_products(&output_root, &report);
        assert!(
            required.iter().any(|name| {
                Path::new(name)
                    .file_name()
                    .is_some_and(|name| name.to_string_lossy().starts_with("measured-"))
            }),
            "Cargo benchmark outputs: {required:?}"
        );
        assert!(required.iter().all(|name| name.starts_with("release/")));
        assert!(!required.iter().any(|name| name.contains("bench-fake")));
        assert!(output_root.join("release/incremental").is_dir());
        if !no_run {
            let stdout = String::from_utf8_lossy(&output.stdout);
            let finished = stdout.find("\"reason\":\"build-finished\"").unwrap();
            let ran = stdout.find("bench-arguments=").unwrap();
            assert!(finished < ran);
            assert!(stdout.contains("\"two words\", \"--no-run\", \"--profile=dev\""));
            assert!(stdout.contains("/unowned/bench-fake"));
            assert!(String::from_utf8_lossy(&output.stderr).contains("bench-program-stderr"));
            assert_compilation_fresh(&output.stdout, "measured");
            assert_compilation_fresh(&output.stdout, "artifact_library");
        }
        if !successful {
            assert_eq!(output.status.code(), Some(29));
            assert!(String::from_utf8_lossy(&output.stderr).contains("exit status: 29"));
        }
    }
}

fn validated_products(output_root: &Path, report: &CargoArtifactReport) -> BTreeSet<String> {
    let required = report.files().map(str::to_owned).collect::<BTreeSet<_>>();
    let inventory =
        TreeInventory::scan(output_root, &required, 128 * 1024 * 1024, &|| false).unwrap();
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
    required
}

fn assert_compilation_fresh(stdout: &[u8], name: &str) {
    let artifacts = stdout
        .split(|byte| *byte == b'\n')
        .filter_map(|line| serde_json::from_slice::<serde_json::Value>(line).ok())
        .take_while(|value| value["reason"] != "build-finished")
        .filter(|value| value["reason"] == "compiler-artifact" && value["target"]["name"] == name)
        .collect::<Vec<_>>();
    assert!(!artifacts.is_empty(), "Cargo did not report {name}");
    assert!(
        artifacts.iter().all(|artifact| artifact["fresh"] == true),
        "Cargo recompiled {name}: {artifacts:?}"
    );
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
