//! Request binding and real Cargo regressions for the selected source adapter.

#[test]
fn selected_local_inheritance_skips_retained_excluding_ancestors() {
    let fixture = tempfile::tempdir().unwrap();
    let root = fixture.path();
    fs::create_dir_all(root.join("app/src")).unwrap();
    fs::create_dir_all(root.join("middle/helper/src")).unwrap();
    fs::write(root.join("Cargo.toml"),
        "[workspace]\nmembers=['app','middle/helper']\nresolver='2'\n[workspace.package]\nversion='0.7.0'\n").unwrap();
    fs::write(
        root.join("middle/Cargo.toml"),
        "[workspace]\nexclude=['helper']\n",
    )
    .unwrap();
    fs::write(root.join("app/Cargo.toml"),
        "[package]\nname='app'\nversion='0.1.0'\nedition='2021'\n[dependencies]\nhelper={path='../middle/helper'}\n").unwrap();
    fs::write(
        root.join("middle/helper/Cargo.toml"),
        "[package]\nname='helper'\nversion.workspace=true\nedition='2021'\n",
    )
    .unwrap();
    fs::write(root.join("app/src/lib.rs"), "").unwrap();
    fs::write(root.join("middle/helper/src/lib.rs"), "").unwrap();
    fs::write(root.join("Cargo.lock"),
        "version=4\n[[package]]\nname='app'\nversion='0.1.0'\n[[package]]\nname='helper'\nversion='0.7.0'\n").unwrap();
    let image = capture(root);
    let control = PreparationControl::uncontrolled();
    let controls =
        graph::ControlInputs::discover_controlled(&image, "Cargo.toml", None, false, &control)
            .unwrap();
    assert!(controls.manifests.contains("Cargo.toml"));
    assert!(controls.manifests.contains("middle/helper/Cargo.toml"));
    assert!(!controls.manifests.contains("middle/Cargo.toml"));
    let app = unit(root, "app", "app", &[1]);
    let mut helper = unit(root, "helper", "middle/helper", &[]);
    helper["pkg_id"] = json!(format!(
        "path+file://{}/middle/helper#helper@0.7.0",
        root.display(),
    ));
    let graph = json!({"version":1,"units":[app.clone(),helper.clone()],"roots":[0,1]});
    let metadata = json!({
        "version":1,"workspace_root":root,
        "packages":[
            {"id":app["pkg_id"],"name":"app","version":"0.1.0","source":null,
                "manifest_path":root.join("app/Cargo.toml"),"targets":[app["target"]]},
            {"id":helper["pkg_id"],"name":"helper","version":"0.7.0","source":null,
                "manifest_path":root.join("middle/helper/Cargo.toml"),"targets":[helper["target"]]},
        ],
        "workspace_members":[app["pkg_id"],helper["pkg_id"]],
        "workspace_default_members":[app["pkg_id"],helper["pkg_id"]],"resolve":null,
    });
    let selection = SelectedCommand {
        manifest: "Cargo.toml".into(),
        command: CompilationCommand::Check,
        selection: CompilationSelection::default(),
        environment: Vec::new(),
        jobs: None,
    };
    validate_selected_graph(&image, root, &selection, &metadata, &graph, None, &control).unwrap();
}

use super::super::{CargoSource, RegistryCache};
use super::*;
use flate2::Compression;
use flate2::write::GzEncoder;
use rabs_sandbox::snapshot_capture::capture_sealed_source;
use rabs_sandbox::source_transfer::MAX_SOURCE_BYTES;
use serde_json::json;
use sha2::{Digest, Sha256};
use std::fs;
use std::path::PathBuf;
use std::sync::Arc;

const DEPENDENCY: &str = "rabs-selection-missing";
const NAMESPACE: &str = "index.crates.io-1949cf8c6b5b557f";
const DEPENDENCY_MANIFEST: &str =
    "[package]\nname='rabs-selection-missing'\nversion='1.0.0'\nedition='2021'\n";
const DEPENDENCY_LIB: &str = "pub fn answer() -> u32 { 42 }\n";

fn request(command: &str, extra: &[&str]) -> Value {
    let mut args = vec![command.to_owned()];
    let separator = extra
        .iter()
        .position(|value| *value == "--")
        .unwrap_or(extra.len());
    args.extend(extra[..separator].iter().map(|value| (*value).to_owned()));
    args.extend([
        "--locked".into(),
        "--offline".into(),
        "--manifest-path".into(),
        "/__rabs/workspace/Cargo.toml".into(),
        "--target-dir".into(),
        "/__rabs/out/cargo".into(),
        "--message-format=json".into(),
    ]);
    args.extend(extra[separator..].iter().map(|value| (*value).to_owned()));
    json!({
        "program":"/__rabs/toolchain/bin/cargo",
        "args":args,
        "command_context":{"version":COMMAND_CONTEXT_VERSION,"cwd":"/__rabs/workspace","env":{}},
    })
}

fn source(approved: &Path, selected: bool) -> Value {
    let mut source = json!({"manifest":"Cargo.toml","cargo_home_source":approved});
    if selected {
        source["selection"] = json!(VERSION);
    }
    source
}

#[cfg(target_os = "linux")]
fn native_profile(command: &str, selection: Value) -> Value {
    json!({
        "version":"canonical-compile-local-v1", "source_root":"/source",
        "toolchain_root":"/toolchain", "state_root":"/state", "operation_root":"/operations",
        "wrapper":"/bin/rabs-wrap", "source_selection":VERSION, "command":command,
        "selection":selection, "jobs":2, "env":{"APP_INPUT":"literal\nvalue"},
    })
}

#[cfg(target_os = "linux")]
fn native_specification(profile: Value) -> Value {
    crate::coord::canonical_local::source_specification_for_test(profile).unwrap()
}

#[cfg(target_os = "linux")]
#[test]
fn selected_native_commands_map_driver_controls_without_widening_public_requests() {
    for command in ["check", "build", "test", "run", "bench"] {
        let selection = if command == "run" {
            json!({"bin":["app"], "run_args":["--unit-graph", "--jobs=100"]})
        } else {
            json!({})
        };
        let input = native_specification(native_profile(command, selection));
        let original = input.clone();
        let selected =
            SelectedCommand::parse(&input, "Cargo.toml", PreparationContext::CanonicalLocal)
                .unwrap();
        let arguments = selected.graph_arguments(&Value::Null, None).unwrap();
        assert_eq!(
            arguments[0],
            if command == "run" { "build" } else { command }
        );
        assert_eq!(&arguments[arguments.len() - 2..], ["--jobs", "2"]);
        assert!(!arguments.iter().any(|argument| argument == "--unit-graph"));
        let mut process = Command::new("/captured/toolchain/bin/cargo");
        selected.configure(
            &mut process,
            Path::new("/captured/toolchain/bin/rustc"),
            Path::new("/private/planning"),
        );
        let mut expected = BTreeMap::from([
            ("APP_INPUT".to_owned(), "literal\nvalue".to_owned()),
            ("CARGO_INCREMENTAL".into(), "0".into()),
            ("CARGO_TARGET_DIR".into(), "/private/planning/target".into()),
            ("RUSTC".into(), "/captured/toolchain/bin/rustc".into()),
        ]);
        if command == "test" {
            expected.insert("RUSTDOC".into(), "/captured/toolchain/bin/rustdoc".into());
        }
        let actual = process
            .get_envs()
            .map(|(name, value)| {
                (
                    name.to_str().unwrap().to_owned(),
                    value.unwrap().to_str().unwrap().to_owned(),
                )
            })
            .collect::<BTreeMap<_, _>>();
        assert_eq!(actual, expected);
        assert_eq!(
            input, original,
            "planning must not rewrite retained execution intent"
        );
        super::super::super::SourcePreparation::parse(
            Path::new("/not-opened-native-source"),
            &input,
            PreparationContext::CanonicalLocal,
        )
        .unwrap();
        assert!(
            super::super::super::SourcePreparation::parse(
                Path::new("/not-opened-native-source"),
                &input,
                PreparationContext::RemoteRequest,
            )
            .is_err()
        );
    }
}

#[cfg(target_os = "linux")]
#[test]
fn selected_native_commands_refuse_mutated_controls_and_unbounded_jobs() {
    let input = native_specification(native_profile("check", json!({})));
    for (name, value) in [
        ("RUSTC", "/host/rustc"),
        ("RUSTDOC", "/__rabs/toolchain/bin/rustdoc"),
        ("CARGO_TARGET_DIR", "/outside/target"),
        ("CARGO_INCREMENTAL", "1"),
        ("CARGO", "/__rabs/toolchain/bin/cargo"),
        ("RUSTC_WRAPPER", "/host/wrapper"),
        ("CARGO_BUILD_JOBS", "3"),
        ("GIT_CONFIG_COUNT", "1"),
        ("HOME", "/host/home"),
    ] {
        let mut changed = input.clone();
        changed["command_context"]["env"][name] = json!(value);
        assert!(
            SelectedCommand::parse(&changed, "Cargo.toml", PreparationContext::CanonicalLocal,)
                .is_err(),
            "{name}"
        );
    }
    for name in ["RUSTC", "CARGO_TARGET_DIR", "CARGO_INCREMENTAL"] {
        let mut changed = input.clone();
        changed["command_context"]["env"]
            .as_object_mut()
            .unwrap()
            .remove(name);
        assert!(
            SelectedCommand::parse(&changed, "Cargo.toml", PreparationContext::CanonicalLocal,)
                .is_err(),
            "missing {name}"
        );
    }
    let mut missing_rustdoc = native_specification(native_profile("test", json!({"doc":true})));
    missing_rustdoc["command_context"]["env"]
        .as_object_mut()
        .unwrap()
        .remove("RUSTDOC");
    assert!(
        SelectedCommand::parse(
            &missing_rustdoc,
            "Cargo.toml",
            PreparationContext::CanonicalLocal,
        )
        .is_err()
    );
    for value in ["0", "4097", "-1", "2.5", "02", "all"] {
        let mut changed = input.clone();
        *changed["args"].as_array_mut().unwrap().last_mut().unwrap() = json!(value);
        assert!(
            SelectedCommand::parse(&changed, "Cargo.toml", PreparationContext::CanonicalLocal,)
                .is_err(),
            "jobs {value}"
        );
    }
    for extra in [
        vec!["--jobs", "2"],
        vec!["--target-dir", "/__rabs/out/cargo"],
    ] {
        let mut changed = input.clone();
        changed["args"]
            .as_array_mut()
            .unwrap()
            .extend(extra.into_iter().map(|arg| json!(arg)));
        assert!(
            SelectedCommand::parse(&changed, "Cargo.toml", PreparationContext::CanonicalLocal,)
                .is_err()
        );
    }
    let mut missing_jobs = input;
    let arguments = missing_jobs["args"].as_array_mut().unwrap();
    arguments.truncate(arguments.len() - 2);
    assert!(
        SelectedCommand::parse(
            &missing_jobs,
            "Cargo.toml",
            PreparationContext::CanonicalLocal,
        )
        .is_err()
    );
}

#[cfg(target_os = "linux")]
#[test]
fn installed_cargo_native_source_specification_prepares_and_replays_selected_commands() {
    let fixture = tempfile::tempdir().unwrap();
    let workspace = fixture.path().join("workspace");
    let seed = fixture.path().join("seed");
    let tools = fixture.path().join("tools");
    for directory in [
        workspace.join("app/src"),
        workspace.join("other/src"),
        workspace.join("host-helper/src"),
        seed.join("home"),
        seed.join("cargo-home"),
        tools.clone(),
    ] {
        fs::create_dir_all(directory).unwrap();
    }
    let cargo = super::super::local_tool("cargo", &tools).unwrap();
    let toolchain = cargo.parent().unwrap().parent().unwrap();
    fs::write(workspace.join("Cargo.toml"),
        "[workspace]\nmembers=['app','other','host-helper']\ndefault-members=['app']\nresolver='2'\n").unwrap();
    fs::write(
        workspace.join("app/Cargo.toml"),
        "[package]\nname='selected-native'\nversion='0.1.0'\nedition='2021'\n\
         [dependencies]\nrabs-selection-missing={version='=1.0.0',optional=true}\n\
         [build-dependencies]\nhost-helper={path='../host-helper'}\n",
    )
    .unwrap();
    fs::write(
        workspace.join("app/src/lib.rs"),
        "/// ```\n/// assert_eq!(selected_native::ready(), 42);\n/// ```\n\
         pub fn ready() -> u32 { env!(\"HOST_ANSWER\").parse().unwrap() }\n",
    )
    .unwrap();
    fs::write(
        workspace.join("app/src/main.rs"),
        "fn main() { println!(\"{}\", selected_native::ready()); }\n",
    )
    .unwrap();
    fs::write(
        workspace.join("app/build.rs"),
        "fn main() { println!(\"cargo:rustc-env=HOST_ANSWER={}\", host_helper::answer()); }\n",
    )
    .unwrap();
    fs::write(
        workspace.join("host-helper/Cargo.toml"),
        "[package]\nname='host-helper'\nversion='0.1.0'\nedition='2021'\n",
    )
    .unwrap();
    fs::write(
        workspace.join("host-helper/src/lib.rs"),
        "pub fn answer() -> u32 { 42 }\n",
    )
    .unwrap();
    fs::write(
        workspace.join("other/Cargo.toml"),
        "[package]\nname='unselected-native'\nversion='0.1.0'\nedition='2021'\n\
         [dependencies]\nrabs-selection-missing='=1.0.0'\n",
    )
    .unwrap();
    fs::write(
        workspace.join("other/src/lib.rs"),
        "pub fn answer() -> u32 { rabs_selection_missing::answer() }\n",
    )
    .unwrap();
    let approved = seed.join("cargo-home");
    seed_index(&approved, &archive());
    cargo_output(
        &cargo,
        toolchain,
        &workspace,
        &seed,
        &["generate-lockfile", "--offline"],
    )
    .unwrap();
    assert!(!approved.join("registry/cache").exists());
    let control = PreparationControl::uncontrolled();
    for command in ["check", "build", "test"] {
        let mut selection = json!({"packages":["selected-native"]});
        let mut baseline = vec![
            command,
            "--locked",
            "--offline",
            "--package",
            "selected-native",
        ];
        if command == "test" {
            selection["doc"] = json!(true);
            baseline.push("--doc");
        }
        cargo_output(&cargo, toolchain, &workspace, &seed, &baseline).unwrap();
        let mut profile = native_profile(command, selection);
        profile["source_root"] = json!(workspace);
        profile["toolchain_root"] = json!(toolchain);
        profile["cargo_home_source"] = json!(approved);
        let specification = native_specification(profile.clone());
        let original = specification.clone();
        let inputs = super::super::super::SourcePreparation::parse(
            &workspace,
            &specification,
            PreparationContext::CanonicalLocal,
        )
        .unwrap();
        assert!(inputs.requires_selected_toolchain());
        let upload = inputs
            .capture_controlled(Some(toolchain), &control)
            .unwrap();
        assert_eq!(specification, original);
        assert!(
            upload
                .manifest
                .files()
                .iter()
                .all(|file| !file.path.ends_with(".crate"))
        );
        for member in [
            "Cargo.lock",
            "app/build.rs",
            "host-helper/src/lib.rs",
            "other/src/lib.rs",
        ] {
            assert_eq!(
                upload.image.file_bytes("workspace", member).unwrap(),
                fs::read(workspace.join(member)).unwrap()
            );
        }

        // Exercise the exact native argv and mapped compiler controls with
        // delivered bytes, an empty target and only the projected Cargo home.
        // This proves native preparation/replay, not a compiler-cache hit.
        let delivered = fixture.path().join(format!("delivered-native-{command}"));
        upload.image.materialize_into(&delivered).unwrap();
        let replay = fixture.path().join(format!("replay-native-{command}"));
        fs::create_dir_all(replay.join("home")).unwrap();
        let replay_workspace = delivered.join("workspace");
        let mut process = super::super::planning_command(
            &cargo,
            &toolchain.join("bin/rustc"),
            &replay_workspace,
            "Cargo.toml",
            &replay,
            Some(toolchain),
        )
        .unwrap();
        let selected = SelectedCommand::parse(
            &specification,
            "Cargo.toml",
            PreparationContext::CanonicalLocal,
        )
        .unwrap();
        selected.configure(&mut process, &toolchain.join("bin/rustc"), &replay);
        process
            .args(
                specification["args"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(|argument| {
                        let argument = argument.as_str().unwrap();
                        if argument == "/__rabs/workspace/Cargo.toml" {
                            replay_workspace
                                .join("Cargo.toml")
                                .to_str()
                                .unwrap()
                                .to_owned()
                        } else {
                            argument.to_owned()
                        }
                    }),
            )
            .env("CARGO_HOME", replay_workspace.join("rabs-cargo-home"));
        super::super::bounded_command(
            process,
            &replay,
            std::time::Duration::from_secs(30),
            OUTPUT_LIMIT,
        )
        .unwrap();
        if command == "build" {
            let stock = Command::new(seed.join("target/debug/selected-native"))
                .output()
                .unwrap();
            let prepared = Command::new(replay.join("target/debug/selected-native"))
                .output()
                .unwrap();
            assert!(stock.status.success() && prepared.status.success());
            assert_eq!(prepared.stdout, b"42\n");
            assert_eq!(prepared.stdout, stock.stdout);
            assert_eq!(prepared.stderr, stock.stderr);
        }
        if command == "check" {
            profile.as_object_mut().unwrap().remove("source_selection");
            let complete = native_specification(profile.clone());
            let inputs = super::super::super::SourcePreparation::parse(
                &workspace,
                &complete,
                PreparationContext::CanonicalLocal,
            )
            .unwrap();
            assert!(
                inputs
                    .capture_controlled(Some(toolchain), &control)
                    .unwrap_err()
                    .to_string()
                    .contains("checksum-matching locked registry archive")
            );
            profile["source_selection"] = json!(VERSION);
            for selection in [
                json!({"packages":["selected-native"],"all_features":true}),
                json!({"packages":["unselected-native"]}),
            ] {
                profile["selection"] = selection;
                let required = native_specification(profile.clone());
                let inputs = super::super::super::SourcePreparation::parse(
                    &workspace,
                    &required,
                    PreparationContext::CanonicalLocal,
                )
                .unwrap();
                assert!(
                    inputs
                        .capture_controlled(Some(toolchain), &control)
                        .is_err()
                );
            }
        }
    }
    assert!(!approved.join("registry/cache").exists());
}

#[test]
fn selected_command_binds_build_check_features_profiles_and_target_to_actual_argv() {
    for command in ["build", "check"] {
        let mut input = request(
            command,
            &[
                "--workspace",
                "--exclude=other",
                "-p",
                "app",
                "-F",
                "one,two",
                "--no-default-features",
                "--all-targets",
                "--target=x86_64-unknown-linux-gnu",
                "--profile=ci",
                "--color=never",
                "-vv",
            ],
        );
        input["command_context"]["env"] =
            json!({"PROJECT_SETTING":"literal value","CARGO_INCREMENTAL":"0"});
        let selected =
            SelectedCommand::parse(&input, "Cargo.toml", PreparationContext::RemoteRequest)
                .unwrap();
        assert_eq!(
            selected.graph_arguments(&Value::Null, None).unwrap(),
            [
                command,
                "--workspace",
                "--no-default-features",
                "--all-targets",
                "--package",
                "app",
                "--exclude",
                "other",
                "--features",
                "one,two",
                "--target",
                "x86_64-unknown-linux-gnu",
                "--profile",
                "ci",
            ]
        );
        let mut process = Command::new("/unused");
        selected.configure(
            &mut process,
            Path::new("/captured/toolchain/bin/rustc"),
            Path::new("/private/planning"),
        );
        let environment = process
            .get_envs()
            .map(|(name, value)| {
                (
                    name.to_str().unwrap().to_owned(),
                    value.unwrap().to_str().unwrap().to_owned(),
                )
            })
            .collect::<BTreeMap<_, _>>();
        assert_eq!(
            environment,
            BTreeMap::from([
                ("CARGO_INCREMENTAL".into(), "0".into()),
                ("PROJECT_SETTING".into(), "literal value".into()),
            ])
        );
    }
}

#[test]
fn selected_harness_commands_preserve_selection_without_interpreting_runtime_arguments() {
    for command in ["test", "bench"] {
        let input = request(
            command,
            &[
                "-p",
                "app@0.1.0",
                "--features=selected",
                "--no-default-features",
                "--target=x86_64-unknown-linux-gnu",
                "--profile=ci",
                "--no-fail-fast",
                "needle=value",
                "--",
                "--no-run",
                "--unit-graph",
                "--target-dir",
                "literal runtime path",
                "",
                "line\nvalue",
            ],
        );
        let original = input.clone();
        let selected =
            SelectedCommand::parse(&input, "Cargo.toml", PreparationContext::RemoteRequest)
                .unwrap();
        assert_eq!(
            selected.graph_arguments(&Value::Null, None).unwrap(),
            [
                command,
                "--no-default-features",
                "--no-fail-fast",
                "--package",
                "app@0.1.0",
                "--features",
                "selected",
                "--target",
                "x86_64-unknown-linux-gnu",
                "--profile",
                "ci",
                "needle=value",
            ]
        );
        assert_eq!(input, original);
        assert!(selected.run_package().is_none());
        let no_run = SelectedCommand::parse(
            &request(command, &["--no-run"]),
            "Cargo.toml",
            PreparationContext::RemoteRequest,
        )
        .unwrap();
        assert_eq!(
            no_run.graph_arguments(&Value::Null, None).unwrap(),
            [command, "--no-run"]
        );
    }
    let docs = SelectedCommand::parse(
        &request("test", &["--doc"]),
        "Cargo.toml",
        PreparationContext::RemoteRequest,
    )
    .unwrap();
    assert_eq!(
        docs.graph_arguments(&Value::Null, None).unwrap(),
        ["test", "--doc"]
    );
}

#[test]
fn selected_run_queries_one_build_target_and_leaves_the_execution_request_intact() {
    for target in ["--bin", "--example"] {
        let input = request(
            "run",
            &[
                "--package=app@0.1.0",
                target,
                "chosen",
                "--release",
                "--",
                "--no-run",
                "--manifest-path=literal",
                "",
                "line\nvalue",
            ],
        );
        let original = input.clone();
        let selected =
            SelectedCommand::parse(&input, "Cargo.toml", PreparationContext::RemoteRequest)
                .unwrap();
        assert_eq!(selected.command, CompilationCommand::Run);
        assert!(selected.run_package().is_none());
        assert_eq!(
            selected.graph_arguments(&Value::Null, None).unwrap(),
            [
                "build",
                "--release",
                "--package",
                "app@0.1.0",
                target,
                "chosen"
            ]
        );
        assert_eq!(input, original);
    }
    let selected = SelectedCommand::parse(
        &request("run", &["--package=app@0.1.0"]),
        "Cargo.toml",
        PreparationContext::RemoteRequest,
    )
    .unwrap();
    assert_eq!(selected.run_package(), Some("app@0.1.0"));
    assert!(selected.graph_arguments(&Value::Null, None).is_err());
}

#[test]
fn selected_execution_refuses_conflicting_modes_and_transport_controls_hidden_in_tails() {
    for (command, extra) in [
        ("test", vec!["--no-run", "filter"]),
        ("test", vec!["--no-run", "--doc"]),
        ("test", vec!["--no-run", "--", "--exact"]),
        ("test", vec!["first", "second"]),
        ("bench", vec!["--doc"]),
        ("bench", vec!["--release"]),
        ("bench", vec!["--no-run", "--"]),
        ("run", vec!["--no-run"]),
        ("run", vec!["--workspace"]),
        ("run", vec!["--all-targets"]),
        ("run", vec!["-p", "first", "-p", "second"]),
        ("run", vec!["--bin", "first", "--bin", "second"]),
        ("run", vec!["--", "NUL\0value"]),
    ] {
        assert!(
            SelectedCommand::parse(
                &request(command, &extra),
                "Cargo.toml",
                PreparationContext::RemoteRequest,
            )
            .is_err(),
            "{command} {extra:?}"
        );
    }
    let mut input = request("test", &[]);
    input["args"].as_array_mut().unwrap().insert(1, json!("--"));
    assert!(
        SelectedCommand::parse(&input, "Cargo.toml", PreparationContext::RemoteRequest).is_err()
    );
}

#[test]
fn selected_command_refuses_independent_resolution_and_execution_controls() {
    for extra in [
        vec!["--config", "build.target='outside'"],
        vec!["-Z", "unstable-options"],
        vec!["--jobs", "2"],
        vec!["--target", "/outside/target.json"],
        vec!["--target", "x86_64-pc-windows-msvc"],
        vec![
            "--target",
            "x86_64-unknown-linux-gnu",
            "--target",
            "aarch64-unknown-linux-gnu",
        ],
        vec!["--manifest-path", "/__rabs/workspace/other/Cargo.toml"],
        vec!["--target-dir", "/__rabs/out/other"],
        vec!["--message-format=human"],
        vec!["--", "program-tail"],
        vec!["--exclude", "app"],
        vec!["--release", "--profile", "ci"],
        vec!["--all-features", "--all-features"],
        vec!["--unknown-selection"],
    ] {
        assert!(
            SelectedCommand::parse(
                &request("check", &extra),
                "Cargo.toml",
                PreparationContext::RemoteRequest,
            )
            .is_err(),
            "{extra:?}"
        );
    }
    for command in ["clippy", "metadata", "install", "publish", "clean"] {
        assert!(
            SelectedCommand::parse(
                &request(command, &[]),
                "Cargo.toml",
                PreparationContext::RemoteRequest,
            )
            .is_err()
        );
    }
    let mut missing = request("check", &[]);
    missing["args"] = json!(["check"]);
    assert!(
        SelectedCommand::parse(&missing, "Cargo.toml", PreparationContext::RemoteRequest).is_err()
    );
    let mut changed = request("check", &[]);
    changed["program"] = json!("/host/cargo");
    assert!(
        SelectedCommand::parse(&changed, "Cargo.toml", PreparationContext::RemoteRequest).is_err()
    );
}

#[test]
fn selected_context_refuses_cwd_version_ambient_control_and_missing_environment() {
    for context in [
        json!({"version":COMMAND_CONTEXT_VERSION,"cwd":"/__rabs/workspace/sub","env":{}}),
        json!({"version":"future","cwd":"/__rabs/workspace","env":{}}),
        json!({"version":COMMAND_CONTEXT_VERSION,"cwd":"/__rabs/workspace","unknown":{}}),
        json!({"version":COMMAND_CONTEXT_VERSION,"cwd":"/__rabs/workspace","env":{},"extra":true}),
        json!({"version":COMMAND_CONTEXT_VERSION,"cwd":"/__rabs/workspace","env":[]}),
    ] {
        let mut input = request("check", &[]);
        input["command_context"] = context;
        assert!(
            SelectedCommand::parse(&input, "Cargo.toml", PreparationContext::RemoteRequest)
                .is_err()
        );
    }
    for name in [
        "CARGO_BUILD_TARGET",
        "CARGO_PROFILE_DEV_OPT_LEVEL",
        "RUSTUP_TOOLCHAIN",
        "RUSTC",
        "RUSTFLAGS",
        "RUSTC_BOOTSTRAP",
        "RUSTDOCFLAGS",
        "GIT_CONFIG_COUNT",
        "LD_PRELOAD",
        "GLIBC_TUNABLES",
        "PATH",
        "CARGO_HOME",
        "RABS_CACHE_MODE",
    ] {
        let mut input = request("check", &[]);
        input["command_context"]["env"] = json!({name:"untrusted"});
        assert!(
            SelectedCommand::parse(&input, "Cargo.toml", PreparationContext::RemoteRequest)
                .is_err(),
            "{name}"
        );
    }
    let mut invalid = request("check", &[]);
    invalid["command_context"]["env"] = json!({"CARGO_INCREMENTAL":"2"});
    assert!(
        SelectedCommand::parse(&invalid, "Cargo.toml", PreparationContext::RemoteRequest).is_err()
    );
    invalid["command_context"]["env"] = json!({"PROJECT_SETTING":"bad\0value"});
    assert!(
        SelectedCommand::parse(&invalid, "Cargo.toml", PreparationContext::RemoteRequest).is_err()
    );
}

#[test]
fn selection_is_explicit_and_invalid_request_refuses_before_cache_access() {
    let legacy = json!({"manifest":"Cargo.toml"});
    CargoSource::parse(&legacy).unwrap();
    CargoSource::parse_request(&legacy, &json!({}), PreparationContext::RemoteRequest).unwrap();
    for version in [Value::Null, json!("future"), json!(true), json!({})] {
        let source = json!({"manifest":"Cargo.toml","selection":version,"cargo_home_source":"/missing-selected-cache"});
        let error = CargoSource::parse_request(
            &source,
            &request("check", &[]),
            PreparationContext::RemoteRequest,
        )
        .unwrap_err();
        assert!(error.to_string().contains("selection version"));
    }
    let selected = json!({"manifest":"Cargo.toml","selection":VERSION,"cargo_home_source":"/missing-selected-cache"});
    assert!(CargoSource::parse(&selected).is_err());
    let mut input = request("check", &[]);
    input["command_context"]["cwd"] = json!("/__rabs/workspace/other");
    let error = CargoSource::parse_request(&selected, &input, PreparationContext::RemoteRequest)
        .unwrap_err();
    assert!(error.to_string().contains("manifest-parent context"));
    let selected_vendor = json!({"manifest":"Cargo.toml","selection":VERSION,"vendor":"vendor"});
    assert!(
        CargoSource::parse_request(
            &selected_vendor,
            &request("check", &[]),
            PreparationContext::RemoteRequest,
        )
        .is_err()
    );
    CargoSource::parse(&json!({"manifest":"Cargo.toml","vendor":"vendor"})).unwrap();
}

#[test]
fn package_ids_and_local_file_urls_do_not_alias_distinct_owners() {
    let source = "registry+https://github.com/rust-lang/crates.io-index";
    assert!(package_id_matches(
        &format!("{source}#a@1.0.0"),
        source,
        "a",
        "1.0.0"
    ));
    assert!(!package_id_matches(
        &format!("{source}#1.0.0"),
        source,
        "a",
        "1.0.0"
    ));
    assert!(!package_id_matches(
        &format!("{source}#b@1.0.0"),
        source,
        "a",
        "1.0.0"
    ));
    assert!(!package_id_matches(
        &format!("{source}-other#a@1.0.0"),
        source,
        "a",
        "1.0.0"
    ));
    assert!(package_id_matches(
        "git+https://example.invalid/a.git#1.0.0",
        "git+https://example.invalid/a.git",
        "a",
        "1.0.0"
    ));
    assert_eq!(
        local_package_directory("path+file:///capture/has%20space#a@1.0.0").unwrap(),
        ("a@1.0.0", "/capture/has space".into())
    );
    for id in [
        "path+file://host/capture#a@1.0.0",
        "path+file:///capture/../outside#a@1.0.0",
        "path+file:///capture/%2e%2e/outside#a@1.0.0",
        "path+file:///capture%2foutside#a@1.0.0",
        "path+file:///capture%5coutside#a@1.0.0",
        "path+file:///capture/%ff#a@1.0.0",
        "path+file:///capture/%00#a@1.0.0",
        "path+file:///capture/%#a@1.0.0",
    ] {
        assert!(local_package_directory(id).is_err(), "{id}");
    }
}

fn archive() -> Vec<u8> {
    let mut archive = tar::Builder::new(GzEncoder::new(Vec::new(), Compression::fast()));
    for (path, bytes) in [
        (
            "rabs-selection-missing-1.0.0/Cargo.toml",
            DEPENDENCY_MANIFEST.as_bytes(),
        ),
        (
            "rabs-selection-missing-1.0.0/src/lib.rs",
            DEPENDENCY_LIB.as_bytes(),
        ),
    ] {
        let mut header = tar::Header::new_gnu();
        header.set_mode(0o644);
        header.set_size(bytes.len() as u64);
        header.set_cksum();
        archive.append_data(&mut header, path, bytes).unwrap();
    }
    archive.into_inner().unwrap().finish().unwrap()
}

fn seed_index(home: &Path, archive: &[u8]) -> String {
    let checksum = rabs_protocol::raw_bytes::encode_hex(Sha256::digest(archive).as_ref());
    let index = home.join("registry/index").join(NAMESPACE);
    fs::create_dir_all(index.join(".cache/ra/bs")).unwrap();
    fs::write(
        index.join("config.json"),
        br#"{"dl":"https://static.crates.io/crates","api":"https://crates.io"}"#,
    )
    .unwrap();
    let record = json!({
        "name":DEPENDENCY,"vers":"1.0.0","deps":[],"cksum":checksum,"features":{},"yanked":false,
    });
    // Cargo's sparse cache v3 header, index format2 and one exact version
    // record. The native tests below must consume this with installed Cargo;
    // constructing the record alone does not claim resolver compatibility.
    let mut bytes = vec![3, 2, 0, 0, 0];
    bytes.extend_from_slice(b"etag: \"rabs-selection-fixture\"\0");
    bytes.extend_from_slice(b"1.0.0\0");
    bytes.extend_from_slice(&serde_json::to_vec(&record).unwrap());
    bytes.push(0);
    fs::write(index.join(".cache/ra/bs/rabs-selection-missing"), bytes).unwrap();
    checksum
}

fn capture(root: &Path) -> Arc<SealedSourceSnapshot> {
    Arc::new(
        capture_sealed_source(
            &[("workspace".into(), root.to_owned())],
            false,
            2,
            MAX_SOURCE_BYTES,
        )
        .unwrap(),
    )
}

fn write_lock(root: &Path, checksum: &str) {
    fs::write(root.join("Cargo.lock"), format!(
        "version = 4\n[[package]]\nname='selected-app'\nversion='0.1.0'\ndependencies=['{DEPENDENCY}']\n\
         [[package]]\nname='{DEPENDENCY}'\nversion='1.0.0'\n\
         source='registry+https://github.com/rust-lang/crates.io-index'\nchecksum='{checksum}'\n",
    )).unwrap();
}

#[test]
fn selected_registry_capture_defers_only_absent_archives_and_checks_selected_owners() {
    let scratch = tempfile::tempdir().unwrap();
    let root = scratch.path().join("workspace");
    let approved = scratch.path().join("approved");
    fs::create_dir_all(root.join("src")).unwrap();
    fs::write(root.join("Cargo.toml"),
        "[package]\nname='selected-app'\nversion='0.1.0'\nedition='2021'\n[dependencies]\nrabs-selection-missing={version='=1.0.0',optional=true}\n").unwrap();
    fs::write(root.join("src/lib.rs"), "pub fn ready() {}\n").unwrap();
    let archive = archive();
    let checksum = seed_index(&approved, &archive);
    write_lock(&root, &checksum);
    let image = capture(&root);
    let missing = scratch.path().join("missing-archive");
    let legacy = RegistryCache::capture_controlled(
        &image,
        Path::new("Cargo.lock"),
        &approved,
        &missing,
        false,
        &PreparationControl::uncontrolled(),
    );
    assert!(
        legacy
            .unwrap_err()
            .to_string()
            .contains("checksum-matching locked registry archive")
    );
    let private = scratch.path().join("selected-archive");
    let selected = RegistryCache::capture_controlled(
        &image,
        Path::new("Cargo.lock"),
        &approved,
        &private,
        true,
        &PreparationControl::uncontrolled(),
    )
    .unwrap();
    assert!(
        private
            .join("registry/index")
            .join(NAMESPACE)
            .join("config.json")
            .is_file()
    );
    let id = format!("registry+https://github.com/rust-lang/crates.io-index#{DEPENDENCY}@1.0.0");
    let expanded = private
        .join("registry/src")
        .join(NAMESPACE)
        .join(format!("{DEPENDENCY}-1.0.0"));
    let target = expanded.join("src/lib.rs");
    assert!(
        selected
            .selected_package(
                &private,
                &id,
                &[target.to_str().unwrap()],
                &PreparationControl::uncontrolled()
            )
            .is_err()
    );

    let cached = approved.join("registry/cache").join(NAMESPACE);
    fs::create_dir_all(&cached).unwrap();
    fs::write(cached.join(format!("{DEPENDENCY}-1.0.0.crate")), &archive).unwrap();
    let private = scratch.path().join("present-archive");
    let selected = RegistryCache::capture_controlled(
        &image,
        Path::new("Cargo.lock"),
        &approved,
        &private,
        true,
        &PreparationControl::uncontrolled(),
    )
    .unwrap();
    let expanded = private
        .join("registry/src")
        .join(NAMESPACE)
        .join(format!("{DEPENDENCY}-1.0.0"));
    fs::create_dir_all(expanded.join("src")).unwrap();
    fs::write(expanded.join("Cargo.toml"), DEPENDENCY_MANIFEST).unwrap();
    fs::write(expanded.join("src/lib.rs"), DEPENDENCY_LIB).unwrap();
    let target = expanded.join("src/lib.rs");
    let package = selected
        .selected_package(
            &private,
            &id,
            &[target.to_str().unwrap()],
            &PreparationControl::uncontrolled(),
        )
        .unwrap();
    let delivered = selected
        .selected_archive_paths(
            &private,
            std::slice::from_ref(&package),
            &PreparationControl::uncontrolled(),
        )
        .unwrap();
    assert_eq!(
        delivered,
        BTreeSet::from([format!(
            "registry/cache/{NAMESPACE}/{DEPENDENCY}-1.0.0.crate",
        )])
    );
    for (field, value) in [
        ("source", Value::Null),
        ("source", json!("sparse+https://other.invalid/index/")),
        ("name", json!("other")),
        ("version", json!("2.0.0")),
        (
            "manifest_path",
            json!(
                private
                    .join("registry/src/other-0123456789abcdef")
                    .join(format!("{DEPENDENCY}-1.0.0/Cargo.toml"))
            ),
        ),
    ] {
        let mut substituted = package.clone();
        substituted[field] = value;
        assert!(
            selected
                .selected_archive_paths(
                    &private,
                    &[substituted],
                    &PreparationControl::uncontrolled(),
                )
                .is_err(),
            "{field} cannot redirect archive selection"
        );
    }
    let unknown = scratch.path().join("unknown-selected-archive");
    assert!(
        selected
            .materialize_controlled(
                &unknown,
                Some(&BTreeSet::from([
                    "registry/cache/unknown/missing-1.0.0.crate".into()
                ])),
                &PreparationControl::uncontrolled(),
            )
            .is_err()
    );
    assert!(
        !unknown.exists(),
        "invalid selection must refuse before writing"
    );
    for bad_id in [
        "registry+https://github.com/rust-lang/crates.io-index#other@1.0.0".to_owned(),
        format!("registry+https://github.com/rust-lang/crates.io-index#{DEPENDENCY}@2.0.0"),
        format!("sparse+https://other.invalid/index/#{DEPENDENCY}@1.0.0"),
    ] {
        assert!(
            selected
                .selected_package(
                    &private,
                    &bad_id,
                    &[target.to_str().unwrap()],
                    &PreparationControl::uncontrolled()
                )
                .is_err()
        );
    }
    let outside = scratch.path().join("outside.rs");
    assert!(
        selected
            .selected_package(
                &private,
                &id,
                &[target.to_str().unwrap(), outside.to_str().unwrap()],
                &PreparationControl::uncontrolled()
            )
            .is_err()
    );
    fs::write(&target, "pub fn answer() -> u32 { 99 }\n").unwrap();
    assert!(
        selected
            .selected_package(
                &private,
                &id,
                &[target.to_str().unwrap()],
                &PreparationControl::uncontrolled()
            )
            .is_err()
    );
    fs::write(
        cached.join(format!("{DEPENDENCY}-1.0.0.crate")),
        b"corrupt archive",
    )
    .unwrap();
    assert!(
        RegistryCache::capture_controlled(
            &image,
            Path::new("Cargo.lock"),
            &approved,
            &scratch.path().join("corrupt-unused"),
            true,
            &PreparationControl::uncontrolled()
        )
        .unwrap_err()
        .to_string()
        .contains("checksum")
    );
}

fn unit(root: &Path, name: &str, folder: &str, dependencies: &[usize]) -> Value {
    let directory = root.join(folder);
    json!({
        "pkg_id":format!("path+file://{}#{name}@0.1.0", directory.display()),
        "target":{"kind":["lib"],"crate_types":["lib"],"name":name,
            "src_path":directory.join("src/lib.rs"),"edition":"2021","doc":true,"doctest":true,"test":true},
        "profile":{"name":"dev"},"platform":null,"mode":"check","features":[],
        "dependencies":dependencies.iter().map(|index| json!({
            "index":index,"extern_crate_name":format!("dependency_{index}"),"public":false,"noprelude":false,
        })).collect::<Vec<_>>(),
    })
}

#[test]
fn selected_graph_checks_host_sources_and_reached_manifests_inside_the_complete_anchor() {
    let scratch = tempfile::tempdir().unwrap();
    let root = scratch.path();
    for (directory, name, dependency) in [
        ("app", "app", "[dependencies]\nhelper={path='../helper'}\n"),
        ("helper", "helper", ""),
        ("unrelated", "unrelated", ""),
    ] {
        fs::create_dir_all(root.join(directory).join("src")).unwrap();
        fs::write(
            root.join(directory).join("Cargo.toml"),
            format!("[package]\nname='{name}'\nversion='0.1.0'\nedition='2021'\n{dependency}",),
        )
        .unwrap();
        fs::write(
            root.join(directory).join("src/lib.rs"),
            "pub fn value() {}\n",
        )
        .unwrap();
    }
    fs::write(
        root.join("app/Cargo.lock"),
        "version=4\n[[package]]\nname='app'\nversion='0.1.0'\n\
        [[package]]\nname='helper'\nversion='0.1.0'\n\
        [[package]]\nname='unrelated'\nversion='0.1.0'\n",
    )
    .unwrap();
    let image = capture(root);
    let selection = SelectedCommand {
        manifest: "app/Cargo.toml".into(),
        command: CompilationCommand::Check,
        selection: CompilationSelection::default(),
        environment: Vec::new(),
        jobs: None,
    };
    let app = unit(root, "app", "app", &[1]);
    let mut helper = unit(root, "helper", "helper", &[]);
    helper["mode"] = json!("build");
    helper["target"]["kind"] = json!(["proc-macro"]);
    helper["target"]["crate_types"] = json!(["proc-macro"]);
    let graph = json!({"version":1,"units":[app.clone(),helper],"roots":[0]});
    let metadata = json!({
        "version":1,"workspace_root":root.join("app"),
        "packages":[{"id":app["pkg_id"],"name":"app","version":"0.1.0","source":null,
            "manifest_path":root.join("app/Cargo.toml"),"targets":[app["target"]]}],
        "workspace_members":[app["pkg_id"]],"workspace_default_members":[app["pkg_id"]],"resolve":null,
    });
    validate_selected_graph(
        &image,
        root,
        &selection,
        &metadata,
        &graph,
        None,
        &PreparationControl::uncontrolled(),
    )
    .unwrap();
    let mut outside = graph.clone();
    outside["units"][1]["target"]["src_path"] = json!("/outside/host-macro.rs");
    assert!(
        validate_selected_graph(
            &image,
            root,
            &selection,
            &metadata,
            &outside,
            None,
            &PreparationControl::uncontrolled()
        )
        .is_err()
    );
    let mut unrelated = graph.clone();
    unrelated["units"][1]["pkg_id"] =
        json!(format!("path+file://{}/unrelated#0.1.0", root.display()));
    unrelated["units"][1]["target"]["src_path"] = json!(root.join("unrelated/src/lib.rs"));
    let error = validate_selected_graph(
        &image,
        root,
        &selection,
        &metadata,
        &unrelated,
        None,
        &PreparationControl::uncontrolled(),
    )
    .unwrap_err();
    assert!(
        error
            .to_string()
            .contains("not a reached Cargo control manifest")
    );
    let mut wrong = graph;
    wrong["units"][1]["pkg_id"] = json!(format!(
        "path+file://{}/helper#helper@9.0.0",
        root.display()
    ));
    assert!(
        validate_selected_graph(
            &image,
            root,
            &selection,
            &metadata,
            &wrong,
            None,
            &PreparationControl::uncontrolled()
        )
        .is_err()
    );
}

#[test]
fn selected_registry_capture_requires_complete_lock_index_and_config_without_archives() {
    let scratch = tempfile::tempdir().unwrap();
    let root = scratch.path().join("workspace");
    fs::create_dir_all(root.join("src")).unwrap();
    fs::write(root.join("Cargo.toml"),
        "[package]\nname='selected-app'\nversion='0.1.0'\nedition='2021'\n[dependencies]\nrabs-selection-missing={version='=1.0.0',optional=true}\n").unwrap();
    fs::write(root.join("src/lib.rs"), "pub fn ready() {}\n").unwrap();
    let approved = scratch.path().join("complete-index");
    let checksum = seed_index(&approved, &archive());
    write_lock(&root, &checksum);
    let image = capture(&root);
    let record = PathBuf::from("registry/index")
        .join(NAMESPACE)
        .join(".cache/ra/bs/rabs-selection-missing");
    let config = PathBuf::from("registry/index")
        .join(NAMESPACE)
        .join("config.json");
    for problem in [
        "missing-record",
        "missing-config",
        "wrong-checksum",
        "malformed-record",
    ] {
        let home = scratch.path().join(problem);
        if problem == "wrong-checksum" {
            seed_index(&home, b"different locked bytes");
        } else {
            fs::create_dir_all(home.join(record.parent().unwrap())).unwrap();
            if problem != "missing-record" {
                fs::write(
                    home.join(&record),
                    if problem == "malformed-record" {
                        b"malformed sparse cache".to_vec()
                    } else {
                        fs::read(approved.join(&record)).unwrap()
                    },
                )
                .unwrap();
            }
            if problem != "missing-config" {
                fs::write(
                    home.join(&config),
                    fs::read(approved.join(&config)).unwrap(),
                )
                .unwrap();
            }
        }
        let result = RegistryCache::capture_controlled(
            &image,
            Path::new("Cargo.lock"),
            &home,
            &scratch.path().join(format!("{problem}-private")),
            true,
            &PreparationControl::uncontrolled(),
        );
        assert!(result.is_err(), "{problem}");
    }
}

#[test]
fn selected_graph_refuses_only_host_dependent_cpu_flags_in_active_configuration() {
    let fixture = tempfile::tempdir().unwrap();
    for (index, flags) in [
        "['-C','target-cpu=native']",
        "['-Ctarget-cpu=native']",
        "['--codegen=target-cpu=native']",
        "'--codegen target-cpu=native'",
        "['--cfg=ordinary','-C','target-cpu=native']",
    ]
    .iter()
    .enumerate()
    {
        for section in [
            "build",
            "target.x86_64-unknown-linux-gnu",
            "target.'cfg(unix)'",
        ] {
            let root = fixture
                .path()
                .join(format!("refuse-{index}-{}", section.len()));
            fs::create_dir_all(root.join("src")).unwrap();
            fs::create_dir_all(root.join(".cargo")).unwrap();
            fs::write(
                root.join("Cargo.toml"),
                "[package]\nname='selected-app'\nversion='0.1.0'\nedition='2021'\n",
            )
            .unwrap();
            fs::write(root.join("Cargo.lock"), "version=4\n").unwrap();
            fs::write(root.join("src/lib.rs"), "").unwrap();
            fs::write(
                root.join(".cargo/config.toml"),
                format!("[{section}]\nrustflags={flags}\n"),
            )
            .unwrap();
            let image = capture(&root);
            super::super::validate_capture(&image, "Cargo.toml", None, false).unwrap();
            assert!(
                validate_host_independent_config(
                    &image,
                    "Cargo.toml",
                    &PreparationControl::uncontrolled()
                )
                .is_err(),
                "{section}/{flags}"
            );
        }
    }
    let root = fixture.path().join("explicit");
    fs::create_dir_all(root.join("src")).unwrap();
    fs::create_dir_all(root.join(".cargo")).unwrap();
    fs::write(
        root.join("Cargo.toml"),
        "[package]\nname='selected-app'\nversion='0.1.0'\nedition='2021'\n",
    )
    .unwrap();
    fs::write(root.join("Cargo.lock"), "version=4\n").unwrap();
    fs::write(root.join("src/lib.rs"), "").unwrap();
    fs::write(
        root.join(".cargo/config.toml"),
        "[build]\nrustflags=['-Ctarget-cpu=x86-64-v3','-Ctarget-feature=+sse2']\n",
    )
    .unwrap();
    validate_host_independent_config(
        &capture(&root),
        "Cargo.toml",
        &PreparationControl::uncontrolled(),
    )
    .unwrap();
}

fn cargo_output(
    cargo: &Path,
    toolchain: &Path,
    workspace: &Path,
    seed: &Path,
    args: &[&str],
) -> io::Result<Vec<u8>> {
    let mut command = super::super::planning_command(
        cargo,
        &toolchain.join("bin/rustc"),
        workspace,
        "Cargo.toml",
        seed,
        Some(toolchain),
    )?;
    command
        .args(args)
        .arg("--manifest-path")
        .arg(workspace.join("Cargo.toml"));
    super::super::bounded_command(
        command,
        seed,
        std::time::Duration::from_secs(30),
        OUTPUT_LIMIT,
    )
}

#[cfg(target_os = "linux")]
#[test]
fn installed_cargo_prepares_with_absent_unselected_archives_and_keeps_host_build_units() {
    let fixture = tempfile::tempdir().unwrap();
    let tools = fixture.path().join("tools");
    fs::create_dir(&tools).unwrap();
    let cargo = super::super::local_tool("cargo", &tools).unwrap();
    let toolchain = cargo.parent().unwrap().parent().unwrap();
    assert!(toolchain.join("bin/rustc").is_file());
    let archive = archive();
    for conditional in ["optional", "windows"] {
        let case = fixture.path().join(conditional);
        let workspace = case.join("workspace");
        let seed = case.join("seed");
        for directory in [
            workspace.join("src"),
            workspace.join("host-helper/src"),
            seed.join("home"),
            seed.join("cargo-home"),
        ] {
            fs::create_dir_all(directory).unwrap();
        }
        let declaration = if conditional == "optional" {
            "[dependencies]\nrabs-selection-missing={version='=1.0.0',optional=true}\n"
        } else {
            "[target.'cfg(windows)'.dependencies]\nrabs-selection-missing='=1.0.0'\n"
        };
        fs::write(
            workspace.join("Cargo.toml"),
            format!(
                "[package]\nname='selected-app'\nversion='0.1.0'\nedition='2021'\n\
             [build-dependencies]\nhost-helper={{path='host-helper'}}\n{declaration}",
            ),
        )
        .unwrap();
        fs::write(workspace.join("src/lib.rs"),
            "#[cfg(feature=\"rabs-selection-missing\")]\npub fn ready() -> u32 { rabs_selection_missing::answer() }\n\
             #[cfg(not(feature=\"rabs-selection-missing\"))]\npub fn ready() -> u32 { 42 }\n").unwrap();
        fs::write(
            workspace.join("host-helper/Cargo.toml"),
            "[package]\nname='host-helper'\nversion='0.1.0'\nedition='2021'\n",
        )
        .unwrap();
        fs::write(
            workspace.join("host-helper/src/lib.rs"),
            "pub fn answer() -> u32 { 42 }\n",
        )
        .unwrap();
        fs::write(
            workspace.join("build.rs"),
            "fn main() { assert_eq!(host_helper::answer(), 42); }\n",
        )
        .unwrap();
        let approved = seed.join("cargo-home");
        seed_index(&approved, &archive);
        cargo_output(
            &cargo,
            toolchain,
            &workspace,
            &seed,
            &["generate-lockfile", "--offline"],
        )
        .unwrap();
        // The actual baseline compile must succeed with no registry archive.
        // A fake Cargo or a mere JSON fixture cannot satisfy this assertion.
        cargo_output(
            &cargo,
            toolchain,
            &workspace,
            &seed,
            &["check", "--locked", "--offline"],
        )
        .unwrap();
        assert!(
            !approved
                .join("registry/cache")
                .join(NAMESPACE)
                .join(format!("{DEPENDENCY}-1.0.0.crate"))
                .exists()
        );
        let image = capture(&workspace);
        let legacy = CargoSource::parse(&source(&approved, false)).unwrap();
        assert!(
            legacy
                .prepare(Arc::clone(&image), Some(toolchain))
                .unwrap_err()
                .to_string()
                .contains("checksum-matching locked registry archive")
        );
        for target in [None, Some("x86_64-unknown-linux-gnu")] {
            let extra = target.map_or_else(Vec::new, |target| vec!["--target", target]);
            let input = request("check", &extra);
            let selected = CargoSource::parse_request(
                &source(&approved, true),
                &input,
                PreparationContext::RemoteRequest,
            )
            .unwrap();
            let (retained, files) = selected
                .prepare(Arc::clone(&image), Some(toolchain))
                .unwrap();
            assert!(
                files
                    .iter()
                    .any(|path| path.ends_with(".cache/ra/bs/rabs-selection-missing"))
            );
            assert!(
                files
                    .iter()
                    .all(|path| !path.ends_with(".crate") && !path.contains("registry/src/"))
            );
            for path in [
                "Cargo.toml",
                "Cargo.lock",
                "src/lib.rs",
                "build.rs",
                "host-helper/Cargo.toml",
                "host-helper/src/lib.rs",
            ] {
                assert_eq!(
                    retained.file_bytes("workspace", path),
                    image.file_bytes("workspace", path)
                );
            }
            let mut arguments = vec![
                "check",
                "--locked",
                "--offline",
                "--unit-graph",
                "-Zunstable-options",
            ];
            arguments.extend(extra);
            let graph: Value = serde_json::from_slice(
                &cargo_output(&cargo, toolchain, &workspace, &seed, &arguments).unwrap(),
            )
            .unwrap();
            let units = selected_units(
                &graph,
                CompilationCommand::Check,
                &PreparationControl::uncontrolled(),
            )
            .unwrap();
            assert!(units.iter().any(
                |unit| unit["pkg_id"].as_str().unwrap().contains("host-helper")
                    && unit["platform"].is_null()
                    && unit["mode"] == "build"
            ));
            assert!(units.iter().any(|unit| unit["mode"] == "run-custom-build"));
            assert!(
                units
                    .iter()
                    .any(|unit| unit["target"]["kind"] == json!(["custom-build"])
                        && unit["mode"] == "build"
                        && unit["platform"].is_null())
            );
            assert!(
                units
                    .iter()
                    .all(|unit| !unit["pkg_id"].as_str().unwrap().contains(DEPENDENCY))
            );
        }
        let input = request("check", &["--all-features"]);
        let selected = CargoSource::parse_request(
            &source(&approved, true),
            &input,
            PreparationContext::RemoteRequest,
        )
        .unwrap();
        if conditional == "optional" {
            assert!(
                selected
                    .prepare(Arc::clone(&image), Some(toolchain))
                    .is_err(),
                "a genuinely selected absent archive must refuse"
            );
            let cache = approved.join("registry/cache").join(NAMESPACE);
            fs::create_dir_all(&cache).unwrap();
            fs::write(cache.join(format!("{DEPENDENCY}-1.0.0.crate")), &archive).unwrap();
            // Confirm the synthetic fixture is a real Cargo-consumable crate.
            cargo_output(
                &cargo,
                toolchain,
                &workspace,
                &seed,
                &["check", "--locked", "--offline", "--all-features"],
            )
            .unwrap();
            for command in ["check", "build"] {
                let input = request(command, &["--all-features"]);
                let selected = CargoSource::parse_request(
                    &source(&approved, true),
                    &input,
                    PreparationContext::RemoteRequest,
                )
                .unwrap();
                let (_, files) = selected
                    .prepare(Arc::clone(&image), Some(toolchain))
                    .unwrap();
                assert!(
                    files
                        .iter()
                        .any(|path| path.ends_with("/rabs-selection-missing-1.0.0.crate"))
                );
            }
        } else {
            selected
                .prepare(Arc::clone(&image), Some(toolchain))
                .unwrap();
        }
    }
}

#[cfg(target_os = "linux")]
#[test]
fn installed_cargo_replays_only_selected_registry_archives_from_a_fresh_home() {
    let fixture = tempfile::tempdir().unwrap();
    let tools = fixture.path().join("tools");
    fs::create_dir(&tools).unwrap();
    let cargo = super::super::local_tool("cargo", &tools).unwrap();
    let toolchain = cargo.parent().unwrap().parent().unwrap();
    let workspace = fixture.path().join("workspace");
    let seed = fixture.path().join("seed");
    let approved = seed.join("cargo-home");
    let index = approved.join("registry/index").join(NAMESPACE);
    let cache = approved.join("registry/cache").join(NAMESPACE);
    for directory in [
        workspace.join("src"),
        seed.join("home"),
        index.join(".cache/ra/bs"),
        cache.clone(),
    ] {
        fs::create_dir_all(directory).unwrap();
    }
    fs::write(
        index.join("config.json"),
        br#"{"dl":"https://static.crates.io/crates","api":"https://crates.io"}"#,
    )
    .unwrap();
    let mut archives = BTreeMap::new();
    for (name, answer) in [
        ("rabs-selection-runtime", 35),
        ("rabs-selection-host", 7),
        ("rabs-selection-extra", 1),
        ("rabs-selection-windows", 99),
    ] {
        let manifest = format!("[package]\nname='{name}'\nversion='1.0.0'\nedition='2021'\n");
        let code = format!("pub fn answer() -> u32 {{ {answer} }}\n");
        let mut archive = tar::Builder::new(GzEncoder::new(Vec::new(), Compression::fast()));
        for (path, bytes) in [
            ("Cargo.toml", manifest.as_bytes()),
            ("src/lib.rs", code.as_bytes()),
        ] {
            let mut header = tar::Header::new_gnu();
            header.set_mode(0o644);
            header.set_size(bytes.len() as u64);
            header.set_cksum();
            archive
                .append_data(&mut header, format!("{name}-1.0.0/{path}"), bytes)
                .unwrap();
        }
        let archive = archive.into_inner().unwrap().finish().unwrap();
        let checksum = rabs_protocol::raw_bytes::encode_hex(Sha256::digest(&archive).as_ref());
        let record = json!({
            "name":name,"vers":"1.0.0","deps":[],"cksum":checksum,
            "features":{},"yanked":false,
        });
        let mut bytes = vec![3, 2, 0, 0, 0];
        bytes.extend_from_slice(b"etag: \"rabs-selected-archive-fixture\"\0");
        bytes.extend_from_slice(b"1.0.0\0");
        bytes.extend_from_slice(&serde_json::to_vec(&record).unwrap());
        bytes.push(0);
        fs::write(index.join(".cache/ra/bs").join(name), bytes).unwrap();
        fs::write(cache.join(format!("{name}-1.0.0.crate")), &archive).unwrap();
        archives.insert(name, archive);
    }
    fs::write(
        workspace.join("Cargo.toml"),
        "[package]\nname='selected-archives'\nversion='0.1.0'\nedition='2021'\n\
         [dependencies]\nrabs-selection-runtime='=1.0.0'\n\
         rabs-selection-extra={version='=1.0.0',optional=true}\n\
         [features]\nextra=['dep:rabs-selection-extra']\n\
         [build-dependencies]\nrabs-selection-host='=1.0.0'\n\
         [target.'cfg(windows)'.dependencies]\nrabs-selection-windows='=1.0.0'\n",
    )
    .unwrap();
    fs::write(
        workspace.join("build.rs"),
        "fn main() { assert_eq!(rabs_selection_host::answer(), 7); println!(\"cargo:rustc-env=HOST_ANSWER=7\"); }\n",
    )
    .unwrap();
    fs::write(
        workspace.join("src/main.rs"),
        "#[cfg(feature=\"extra\")] fn extra() -> u32 { rabs_selection_extra::answer() }\n\
         #[cfg(not(feature=\"extra\"))] fn extra() -> u32 { 0 }\n\
         fn main() { println!(\"{}\", rabs_selection_runtime::answer() + env!(\"HOST_ANSWER\").parse::<u32>().unwrap() + extra()); }\n",
    )
    .unwrap();
    cargo_output(
        &cargo,
        toolchain,
        &workspace,
        &seed,
        &["generate-lockfile", "--offline"],
    )
    .unwrap();
    let image = capture(&workspace);
    let mut default_digest = None;
    for (mode, extra, expected) in [
        ("default", Vec::new(), b"42\n".as_slice()),
        ("feature", vec!["--features=extra"], b"43\n".as_slice()),
    ] {
        let mut args = vec!["build", "--locked", "--offline"];
        args.extend(extra.iter().copied());
        cargo_output(&cargo, toolchain, &workspace, &seed, &args).unwrap();
        let stock = Command::new(seed.join("target/debug/selected-archives"))
            .output()
            .unwrap();
        assert!(stock.status.success());
        assert_eq!(stock.stdout, expected);
        let selected = CargoSource::parse_request(
            &source(&approved, true),
            &request("build", &extra),
            super::super::super::PreparationContext::RemoteRequest,
        )
        .unwrap();
        let (retained, files) = selected
            .prepare(Arc::clone(&image), Some(toolchain))
            .unwrap();
        let prefix = format!("rabs-cargo-home/registry/cache/{NAMESPACE}");
        let delivered_archives = files
            .iter()
            .filter(|path| path.starts_with(&prefix))
            .cloned()
            .collect::<BTreeSet<_>>();
        let mut expected_archives = BTreeSet::from([
            format!("{prefix}/rabs-selection-runtime-1.0.0.crate"),
            format!("{prefix}/rabs-selection-host-1.0.0.crate"),
        ]);
        if mode == "feature" {
            expected_archives.insert(format!("{prefix}/rabs-selection-extra-1.0.0.crate"));
        } else {
            default_digest = Some(retained.closure_digest());
        }
        assert_eq!(delivered_archives, expected_archives);
        for (name, bytes) in &archives {
            let archive = format!("{prefix}/{name}-1.0.0.crate");
            assert_eq!(
                retained.file_bytes("workspace", &archive),
                expected_archives
                    .contains(&archive)
                    .then_some(bytes.as_slice()),
            );
            assert!(
                retained
                    .file_bytes(
                        "workspace",
                        &format!("rabs-cargo-home/registry/index/{NAMESPACE}/.cache/ra/bs/{name}",)
                    )
                    .is_some(),
                "the full locked sparse index must remain available"
            );
        }
        for path in ["Cargo.toml", "Cargo.lock", "src/main.rs", "build.rs"] {
            assert_eq!(
                retained.file_bytes("workspace", path),
                image.file_bytes("workspace", path)
            );
        }
        assert!(files.iter().all(|path| !path.contains("registry/src/")));

        // Replay the exact delivered bytes into an empty Cargo home and a new
        // target directory. The original home and its expanded sources cannot
        // supply a missing archive. Build.rs genuinely compiles its host input,
        // and the delivered native executable must agree with stock Cargo.
        let delivered = fixture.path().join(format!("delivered-{mode}"));
        retained.materialize_into(&delivered).unwrap();
        let replay = fixture.path().join(format!("replay-{mode}"));
        fs::create_dir_all(replay.join("home")).unwrap();
        let replay_workspace = delivered.join("workspace");
        let mut command = super::super::planning_command(
            &cargo,
            &toolchain.join("bin/rustc"),
            &replay_workspace,
            "Cargo.toml",
            &replay,
            Some(toolchain),
        )
        .unwrap();
        command
            .args(&args)
            .arg("--manifest-path")
            .arg(replay_workspace.join("Cargo.toml"))
            .env("CARGO_HOME", replay_workspace.join("rabs-cargo-home"));
        super::super::bounded_command(
            command,
            &replay,
            std::time::Duration::from_secs(30),
            OUTPUT_LIMIT,
        )
        .unwrap();
        let built = Command::new(replay.join("target/debug/selected-archives"))
            .output()
            .unwrap();
        assert!(built.status.success());
        assert_eq!(built.stdout, stock.stdout);
        assert_eq!(built.stderr, stock.stderr);
    }

    // An unused available archive must not perturb delivered source identity.
    // Keep its bytes, but make it unavailable to the next capture; the same
    // default request still produces exactly the same complete input closure.
    fs::rename(
        cache.join("rabs-selection-extra-1.0.0.crate"),
        fixture.path().join("retained-unused.crate"),
    )
    .unwrap();
    let selected = CargoSource::parse_request(
        &source(&approved, true),
        &request("build", &[]),
        super::super::super::PreparationContext::RemoteRequest,
    )
    .unwrap();
    let (retained, _) = selected
        .prepare(Arc::clone(&image), Some(toolchain))
        .unwrap();
    assert_eq!(Some(retained.closure_digest()), default_digest);
    let selected = CargoSource::parse_request(
        &source(&approved, true),
        &request("build", &["--features=extra"]),
        super::super::super::PreparationContext::RemoteRequest,
    )
    .unwrap();
    assert!(selected.prepare(image, Some(toolchain)).is_err());
}

#[cfg(target_os = "linux")]
#[test]
fn installed_cargo_prepares_execution_commands_without_running_project_code() {
    let fixture = tempfile::tempdir().unwrap();
    let tools = fixture.path().join("tools");
    fs::create_dir(&tools).unwrap();
    let cargo = super::super::local_tool("cargo", &tools).unwrap();
    let toolchain = cargo.parent().unwrap().parent().unwrap();
    let workspace = fixture.path().join("workspace");
    let seed = fixture.path().join("seed");
    for directory in [
        workspace.join("app/src/bin"),
        workspace.join("app/examples"),
        workspace.join("app/tests"),
        workspace.join("app/benches"),
        workspace.join("host-helper/src"),
        workspace.join("dev-helper/src"),
        workspace.join("unselected/src/bin"),
        seed.join("home"),
        seed.join("cargo-home"),
    ] {
        fs::create_dir_all(directory).unwrap();
    }
    fs::write(
        workspace.join("Cargo.toml"),
        "[workspace]\nmembers=['app','host-helper','dev-helper','unselected']\n\
         default-members=['app']\nresolver='2'\n",
    )
    .unwrap();
    fs::write(
        workspace.join("app/Cargo.toml"),
        "[package]\nname='selected-app'\nversion='0.1.0'\nedition='2021'\ndefault-run='chosen'\n\
         [dependencies]\nrabs-selection-missing={version='=1.0.0',optional=true}\n\
         [features]\nremote=['dep:rabs-selection-missing']\n\
         [build-dependencies]\nhost-helper={path='../host-helper'}\n\
         [dev-dependencies]\ndev-helper={path='../dev-helper'}\n\
         [[bin]]\nname='chosen'\npath='src/main.rs'\n\
         [[bin]]\nname='other'\npath='src/bin/other.rs'\nrequired-features=['remote']\n\
         [[bench]]\nname='measure'\nharness=false\n",
    )
    .unwrap();
    fs::write(
        workspace.join("app/src/lib.rs"),
        "/// A selected documentation test.\n/// ```\n/// assert_eq!(2 + 2, 4);\n/// ```\n\
         pub fn ready() {}\n#[test] fn selected_test() { panic!(\"must not execute\"); }\n",
    )
    .unwrap();
    for path in [
        "app/src/main.rs",
        "app/src/bin/other.rs",
        "app/examples/demo.rs",
        "app/benches/measure.rs",
        "unselected/src/main.rs",
        "unselected/src/bin/alternate.rs",
    ] {
        fs::write(
            workspace.join(path),
            "fn main() { panic!(\"planning must not execute a project program\"); }\n",
        )
        .unwrap();
    }
    fs::write(
        workspace.join("app/tests/integration.rs"),
        "#[test] fn selected_test() { panic!(\"planning must not execute tests\"); }\n",
    )
    .unwrap();
    // Any attempt to compile, let alone execute, the selected build script
    // fails. These successes therefore require Cargo's nonexecuting graph path.
    fs::write(
        workspace.join("app/build.rs"),
        "compile_error!(\"planning must not compile project code\");\n\
         fn main() { panic!(\"planning must not execute build scripts\"); }\n",
    )
    .unwrap();
    for name in ["host-helper", "dev-helper"] {
        fs::write(
            workspace.join(name).join("Cargo.toml"),
            format!("[package]\nname='{name}'\nversion='0.1.0'\nedition='2021'\n"),
        )
        .unwrap();
        fs::write(
            workspace.join(name).join("src/lib.rs"),
            "pub fn ready() {}\n",
        )
        .unwrap();
    }
    fs::write(
        workspace.join("unselected/Cargo.toml"),
        "[package]\nname='unselected'\nversion='0.1.0'\nedition='2021'\n\
         [dependencies]\nrabs-selection-missing='=1.0.0'\n",
    )
    .unwrap();
    let approved = seed.join("cargo-home");
    let archive = archive();
    seed_index(&approved, &archive);
    cargo_output(
        &cargo,
        toolchain,
        &workspace,
        &seed,
        &["generate-lockfile", "--offline"],
    )
    .unwrap();
    let metadata: Value = serde_json::from_slice(
        &cargo_output(
            &cargo,
            toolchain,
            &workspace,
            &seed,
            &[
                "metadata",
                "--format-version=1",
                "--no-deps",
                "--locked",
                "--offline",
            ],
        )
        .unwrap(),
    )
    .unwrap();
    let image = capture(&workspace);
    for (command, extra) in [
        ("test", vec![]),
        ("test", vec!["--no-run", "--all-targets"]),
        ("test", vec!["--doc"]),
        (
            "test",
            vec![
                "--test",
                "integration",
                "needle=value",
                "--",
                "--no-run",
                "--unit-graph",
                "",
            ],
        ),
        (
            "test",
            vec!["--workspace", "--exclude", "unselected", "--no-run"],
        ),
        ("bench", vec![]),
        ("bench", vec!["--no-run", "--bench", "measure"]),
        (
            "bench",
            vec![
                "--bench",
                "measure",
                "needle=value",
                "--",
                "--no-run",
                "line\nvalue",
            ],
        ),
        ("run", vec![]),
        (
            "run",
            vec![
                "--package",
                "selected-app@0.1.0",
                "--",
                "--no-run",
                "--unit-graph",
                "",
            ],
        ),
        ("run", vec!["--bin", "chosen"]),
        (
            "run",
            vec![
                "--package",
                "selected-app",
                "--example",
                "demo",
                "--",
                "literal program argument",
            ],
        ),
    ] {
        let input = request(command, &extra);
        let selected = CargoSource::parse_request(
            &source(&approved, true),
            &input,
            PreparationContext::RemoteRequest,
        )
        .unwrap();
        let (retained, files) = selected
            .prepare(Arc::clone(&image), Some(toolchain))
            .unwrap_or_else(|error| panic!("{command} {extra:?}: {error}"));
        assert!(files.iter().all(|path| !path.ends_with(".crate")));
        for path in [
            "Cargo.toml",
            "Cargo.lock",
            "app/Cargo.toml",
            "app/build.rs",
            "app/src/lib.rs",
            "app/src/main.rs",
            "app/src/bin/other.rs",
            "app/examples/demo.rs",
            "app/tests/integration.rs",
            "app/benches/measure.rs",
            "host-helper/Cargo.toml",
            "dev-helper/Cargo.toml",
            "unselected/Cargo.toml",
        ] {
            assert_eq!(
                retained.file_bytes("workspace", path),
                image.file_bytes("workspace", path)
            );
        }
        let selection =
            SelectedCommand::parse(&input, "Cargo.toml", PreparationContext::RemoteRequest)
                .unwrap();
        let package_id = selection.run_package().map(|package| {
            String::from_utf8(
                cargo_output(
                    &cargo,
                    toolchain,
                    &workspace,
                    &seed,
                    &["pkgid", "--package", package, "--locked", "--offline"],
                )
                .unwrap(),
            )
            .unwrap()
        });
        let mut arguments = selection
            .graph_arguments(&metadata, package_id.as_deref().map(str::trim))
            .unwrap();
        arguments.extend(
            [
                "--locked",
                "--offline",
                "--unit-graph",
                "-Zunstable-options",
            ]
            .map(String::from),
        );
        let graph: Value = serde_json::from_slice(
            &cargo_output(
                &cargo,
                toolchain,
                &workspace,
                &seed,
                &arguments.iter().map(String::as_str).collect::<Vec<_>>(),
            )
            .unwrap(),
        )
        .unwrap();
        let units = selected_units(
            &graph,
            selection.command,
            &PreparationControl::uncontrolled(),
        )
        .unwrap();
        assert!(
            units
                .iter()
                .any(|unit| unit["pkg_id"].as_str().unwrap().contains("host-helper"))
        );
        assert!(units.iter().any(|unit| unit["mode"] == "run-custom-build"));
        assert!(
            units
                .iter()
                .all(|unit| !unit["pkg_id"].as_str().unwrap().contains(DEPENDENCY))
        );
        if command == "run" {
            let roots = graph["roots"].as_array().unwrap();
            assert_eq!(roots.len(), 1);
            let root = &graph["units"][roots[0].as_u64().unwrap() as usize];
            assert_eq!(
                root["target"]["name"],
                if extra.contains(&"--example") {
                    "demo"
                } else {
                    "chosen"
                }
            );
        }
        if matches!(command, "test" | "bench") || extra.contains(&"--example") {
            assert!(
                units
                    .iter()
                    .any(|unit| unit["pkg_id"].as_str().unwrap().contains("dev-helper"))
            );
        }
    }
    let selected_missing = [
        ("test", vec!["--all-features"]),
        ("bench", vec!["--all-features"]),
        ("run", vec!["--bin", "other", "--features", "remote"]),
        (
            "run",
            vec!["--package", "unselected", "--bin", "unselected"],
        ),
    ];
    for (command, extra) in &selected_missing {
        let selected = CargoSource::parse_request(
            &source(&approved, true),
            &request(command, extra),
            PreparationContext::RemoteRequest,
        )
        .unwrap();
        assert!(
            selected
                .prepare(Arc::clone(&image), Some(toolchain))
                .is_err(),
            "{command} {extra:?}"
        );
    }
    let cache = approved.join("registry/cache").join(NAMESPACE);
    fs::create_dir_all(&cache).unwrap();
    fs::write(cache.join(format!("{DEPENDENCY}-1.0.0.crate")), archive).unwrap();
    for (command, extra) in &selected_missing {
        let selected = CargoSource::parse_request(
            &source(&approved, true),
            &request(command, extra),
            PreparationContext::RemoteRequest,
        )
        .unwrap();
        let (_, files) = selected
            .prepare(Arc::clone(&image), Some(toolchain))
            .unwrap();
        assert!(
            files
                .iter()
                .any(|path| path.ends_with("/rabs-selection-missing-1.0.0.crate"))
        );
    }
    let ambiguous = CargoSource::parse_request(
        &source(&approved, true),
        &request("run", &["--package", "unselected"]),
        PreparationContext::RemoteRequest,
    )
    .unwrap();
    assert!(
        ambiguous
            .prepare(image, Some(toolchain))
            .unwrap_err()
            .to_string()
            .contains("cannot determine one binary")
    );
}

#[cfg(target_os = "linux")]
#[test]
fn installed_cargo_selected_graph_retains_full_git_owners_and_checkouts() {
    let fixture = tempfile::tempdir().unwrap();
    let tools = fixture.path().join("tools");
    let repository = fixture.path().join("git-repository");
    fs::create_dir(&tools).unwrap();
    fs::create_dir_all(repository.join("src")).unwrap();
    fs::write(
        repository.join("Cargo.toml"),
        "[package]\nname='git-helper'\nversion='0.1.0'\nedition='2021'\n",
    )
    .unwrap();
    fs::write(
        repository.join("src/lib.rs"),
        "pub fn answer() -> u32 { 7 }\n",
    )
    .unwrap();
    let cargo = super::super::local_tool("cargo", &tools).unwrap();
    let toolchain = cargo.parent().unwrap().parent().unwrap();
    let git = super::super::local_tool("git", &tools).unwrap();
    for args in [
        vec!["init", "--initial-branch=main"],
        vec!["add", "Cargo.toml", "src/lib.rs"],
        vec![
            "-c",
            "user.name=RABS fixture",
            "-c",
            "user.email=fixture@example.invalid",
            "commit",
            "-m",
            "fixture",
        ],
        vec!["tag", "release+tag"],
    ] {
        let mut command = Command::new(&git);
        command
            .env_clear()
            .env("PATH", "/usr/bin:/bin")
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env("GIT_CONFIG_GLOBAL", "/dev/null")
            .arg("-C")
            .arg(&repository)
            .args(args);
        super::super::bounded_command(
            command,
            fixture.path(),
            std::time::Duration::from_secs(30),
            OUTPUT_LIMIT,
        )
        .unwrap();
    }
    for (name, selector, refused) in [
        ("default", "", false),
        ("branch", ",branch='main'", false),
        ("encoded", ",tag='release+tag'", true),
    ] {
        let case = fixture.path().join(name);
        let workspace = case.join("workspace");
        let seed = case.join("seed");
        for directory in [
            workspace.join("src"),
            seed.join("home"),
            seed.join("cargo-home"),
        ] {
            fs::create_dir_all(directory).unwrap();
        }
        let manifest = format!(
            "[package]\nname='selected-git-app'\nversion='0.1.0'\nedition='2021'\n\
             [dependencies]\ngit-helper={{git='file://{}'{selector}}}\n",
            repository.display(),
        );
        fs::write(workspace.join("Cargo.toml"), &manifest).unwrap();
        fs::write(
            workspace.join("src/lib.rs"),
            "pub fn ready() -> u32 { git_helper::answer() }\n",
        )
        .unwrap();
        // The only source before seeding is a local file:// repository. No
        // registry server or network access is needed to populate Git objects.
        cargo_output(&cargo, toolchain, &workspace, &seed, &["generate-lockfile"]).unwrap();
        let approved = seed.join("cargo-home");
        seed_index(&approved, &archive());
        fs::write(workspace.join("Cargo.toml"), format!(
            "{manifest}\n[target.'cfg(windows)'.dependencies]\nrabs-selection-missing='=1.0.0'\n",
        )).unwrap();
        cargo_output(
            &cargo,
            toolchain,
            &workspace,
            &seed,
            &["generate-lockfile", "--offline"],
        )
        .unwrap();
        cargo_output(
            &cargo,
            toolchain,
            &workspace,
            &seed,
            &["check", "--locked", "--offline"],
        )
        .unwrap();
        let image = capture(&workspace);
        let selected = CargoSource::parse_request(
            &source(&approved, true),
            &request("check", &[]),
            PreparationContext::RemoteRequest,
        )
        .unwrap();
        let result = selected.prepare(Arc::clone(&image), Some(toolchain));
        if refused {
            assert!(
                result
                    .unwrap_err()
                    .to_string()
                    .contains("ambiguous encoded selector")
            );
        } else {
            let (_, files) = result.unwrap();
            assert!(
                files
                    .iter()
                    .any(|path| path.starts_with("rabs-cargo-home/git/db/"))
            );
            assert!(
                files
                    .iter()
                    .all(|path| !path.contains("git/checkouts/") && !path.ends_with(".crate"))
            );
            let selected = CargoSource::parse_request(
                &source(&approved, true),
                &request("build", &[]),
                PreparationContext::RemoteRequest,
            )
            .unwrap();
            selected
                .prepare(Arc::clone(&image), Some(toolchain))
                .unwrap();
        }
    }
}

#[test]
fn selected_local_versions_bind_declared_inherited_and_default_manifest_identity() {
    let fixture = tempfile::tempdir().unwrap();
    for mode in ["literal", "inherited", "default"] {
        let root = fixture.path().join(mode);
        let old_version = if mode == "default" { "0.0.0" } else { "0.1.0" };
        fs::create_dir_all(root.join("app/src")).unwrap();
        fs::write(root.join("app/Cargo.toml"),
            "[package]\nname='app'\nversion='0.1.0'\nedition='2021'\n\
             [dependencies]\nold={package='helper',path='../helper-old'}\nnew={package='helper',path='../helper-new'}\n").unwrap();
        fs::write(root.join("app/src/lib.rs"), "").unwrap();
        for (directory, version) in [("helper-old", old_version), ("helper-new", "9.0.0")] {
            fs::create_dir_all(root.join(directory).join("src")).unwrap();
            let version = if mode == "inherited" {
                format!(
                    "version={{workspace=true}}\nedition='2021'\n[workspace.package]\nversion='{version}'\n"
                )
            } else if mode == "default" && directory == "helper-old" {
                "edition='2021'\n".to_owned()
            } else {
                format!("version='{version}'\nedition='2021'\n")
            };
            fs::write(
                root.join(directory).join("Cargo.toml"),
                format!("[package]\nname='helper'\n{version}"),
            )
            .unwrap();
            fs::write(root.join(directory).join("src/lib.rs"), "").unwrap();
        }
        fs::write(
            root.join("app/Cargo.lock"),
            format!(
                "version=4\n[[package]]\nname='app'\nversion='0.1.0'\n\
             [[package]]\nname='helper'\nversion='{old_version}'\n\
             [[package]]\nname='helper'\nversion='9.0.0'\n"
            ),
        )
        .unwrap();
        let image = capture(&root);
        let selection = SelectedCommand {
            manifest: "app/Cargo.toml".into(),
            command: CompilationCommand::Check,
            selection: CompilationSelection::default(),
            environment: Vec::new(),
            jobs: None,
        };
        let app = unit(&root, "app", "app", &[1, 2]);
        let mut old = unit(&root, "helper", "helper-old", &[]);
        old["pkg_id"] = json!(format!(
            "path+file://{}/helper-old#helper@{old_version}",
            root.display()
        ));
        let mut new = unit(&root, "helper", "helper-new", &[]);
        new["pkg_id"] = json!(format!(
            "path+file://{}/helper-new#helper@9.0.0",
            root.display()
        ));
        let graph = json!({"version":1,"units":[app.clone(),old,new],"roots":[0]});
        let metadata = json!({
            "version":1,"workspace_root":root.join("app"),
            "packages":[{"id":app["pkg_id"],"name":"app","version":"0.1.0","source":null,
                "manifest_path":root.join("app/Cargo.toml"),"targets":[app["target"]]}],
            "workspace_members":[app["pkg_id"]],"workspace_default_members":[app["pkg_id"]],"resolve":null,
        });
        validate_selected_graph(
            &image,
            &root,
            &selection,
            &metadata,
            &graph,
            None,
            &PreparationControl::uncontrolled(),
        )
        .unwrap();
        let mut forged = graph;
        forged["units"][1]["pkg_id"] = json!(format!(
            "path+file://{}/helper-old#helper@9.0.0",
            root.display(),
        ));
        let error = validate_selected_graph(
            &image,
            &root,
            &selection,
            &metadata,
            &forged,
            None,
            &PreparationControl::uncontrolled(),
        )
        .unwrap_err();
        assert!(
            error.to_string().contains("retained manifest owner"),
            "{error}"
        );
    }
}
