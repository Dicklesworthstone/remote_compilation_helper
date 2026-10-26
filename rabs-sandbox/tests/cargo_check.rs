//! Real Cargo planning proves the admission gate follows the selected units.
//! The fixture contains deliberately uncompilable Rust and executable build
//! code, so a successful graph command cannot be mistaken for a real build.
//! This test needs the project's pinned nightly Cargo, but no bubblewrap or
//! network. It does not qualify cache serving or namespace enforcement.
#![cfg(target_os = "linux")]

use rabs_sandbox::cargo_check::{CheckSelection, validate_check_unit_graph};
use serde_json::Value;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

struct Fixture {
    owner: tempfile::TempDir,
    tools: PathBuf,
}

impl Fixture {
    fn new() -> Self {
        let rustc = std::env::var_os("RUSTC").unwrap_or_else(|| "rustc".into());
        let probe = Command::new(rustc).arg("--print=sysroot").output().unwrap();
        assert!(
            probe.status.success(),
            "an installed native Rust toolchain is required"
        );
        let tools = PathBuf::from(String::from_utf8(probe.stdout).unwrap().trim());
        let owner = tempfile::tempdir().unwrap();
        let root = owner.path().join("workspace");
        for directory in [
            "src",
            "ordinary/src",
            "optional-script/src",
            "dev-macro/src",
        ] {
            fs::create_dir_all(root.join(directory)).unwrap();
        }
        fs::create_dir(owner.path().join("home")).unwrap();
        fs::write(
            root.join("Cargo.toml"),
            r#"
[package]
name = "selected_graph_app"
version = "0.1.0"
edition = "2024"

[workspace]
members = ["ordinary"]
exclude = ["optional-script", "dev-macro"]
resolver = "2"

[features]
script = ["dep:optional_script"]

[dependencies]
ordinary = { path = "ordinary" }
optional_script = { path = "optional-script", optional = true }

[dev-dependencies]
dev_macro = { path = "dev-macro" }
"#,
        )
        .unwrap();
        fs::write(
            root.join("src/lib.rs"),
            "compile_error!(\"unit graph must not compile this library\");\n",
        )
        .unwrap();
        fs::write(
            root.join("src/main.rs"),
            "compile_error!(\"unit graph must not compile this binary\"); fn main() {}\n",
        )
        .unwrap();
        fs::write(
            root.join("ordinary/Cargo.toml"),
            "[package]\nname='ordinary'\nversion='0.1.0'\nedition='2024'\n",
        )
        .unwrap();
        fs::write(
            root.join("ordinary/src/lib.rs"),
            "compile_error!(\"unit graph must not compile a selected dependency\");\n",
        )
        .unwrap();
        fs::write(
            root.join("optional-script/Cargo.toml"),
            "[package]\nname='optional_script'\nversion='0.1.0'\nedition='2024'\n",
        )
        .unwrap();
        fs::write(
            root.join("optional-script/src/lib.rs"),
            "pub const VALUE: u8 = 7;\n",
        )
        .unwrap();
        fs::write(
            root.join("optional-script/build.rs"),
            r#"
fn main() {
    std::fs::write("build-script-was-executed", b"unexpected").unwrap();
    panic!("unit-graph planning must not run a build script");
}
"#,
        )
        .unwrap();
        fs::write(root.join("dev-macro/Cargo.toml"), "[package]\nname='dev_macro'\nversion='0.1.0'\nedition='2024'\n[lib]\nproc-macro=true\n").unwrap();
        fs::write(
            root.join("dev-macro/src/lib.rs"),
            r#"
compile_error!("unit graph must not compile a procedural macro");
extern crate proc_macro;
#[proc_macro]
pub fn marker(_: proc_macro::TokenStream) -> proc_macro::TokenStream {
    std::fs::write("proc-macro-was-executed", b"unexpected").unwrap();
    panic!("unit-graph planning must not run a procedural macro");
}
"#,
        )
        .unwrap();
        let fixture = Self { owner, tools };
        let lock = fixture
            .command()
            .args(["generate-lockfile", "--offline"])
            .output()
            .unwrap();
        assert!(
            lock.status.success(),
            "{}",
            String::from_utf8_lossy(&lock.stderr)
        );
        fixture
    }

    fn root(&self) -> PathBuf {
        self.owner.path().join("workspace")
    }

    fn command(&self) -> Command {
        let mut command = Command::new(self.tools.join("bin/cargo"));
        command
            .env_clear()
            .env("PATH", "/usr/bin:/bin")
            .env("HOME", self.owner.path().join("home"))
            .env("CARGO_HOME", self.owner.path().join("home/cargo"))
            .env("RUSTC", self.tools.join("bin/rustc"))
            .env("CARGO_TARGET_DIR", self.owner.path().join("target"))
            .env("CARGO_INCREMENTAL", "0")
            .env("CARGO_BUILD_JOBS", "1")
            .current_dir(self.root());
        command
    }

    fn graph(&self, selection: CheckSelection) -> Value {
        let output = self
            .command()
            .args(selection.cargo_arguments().unwrap())
            .args([
                "--offline",
                "--locked",
                "--unit-graph",
                "-Z",
                "unstable-options",
            ])
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "selected {selection:?}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        let graph: Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(graph["version"], 1);
        graph
    }

    fn assert_no_compilation_or_project_execution(&self) {
        fn walk(path: &Path) {
            for entry in fs::read_dir(path).unwrap() {
                let entry = entry.unwrap();
                let file_type = entry.file_type().unwrap();
                if file_type.is_dir() {
                    walk(&entry.path());
                } else {
                    let path = entry.path();
                    assert!(
                        !matches!(
                            path.file_name().and_then(|name| name.to_str()),
                            Some("build-script-was-executed" | "proc-macro-was-executed")
                        ),
                        "project code executed before graph admission: {}",
                        path.display()
                    );
                    assert!(
                        !matches!(
                            path.extension().and_then(|extension| extension.to_str()),
                            Some("rlib" | "rmeta" | "so" | "o")
                        ),
                        "unit graph produced compiler output: {}",
                        path.display()
                    );
                }
            }
        }
        walk(self.owner.path());
    }
}

#[test]
fn real_cargo_unit_graph_admits_only_selected_pure_check_units() {
    let fixture = Fixture::new();
    // Metadata contains both executable packages even though this library
    // check does not select either. A package-wide ban therefore rejects a
    // safe compiler-only command that the unit graph can admit precisely.
    let metadata = fixture
        .command()
        .args([
            "metadata",
            "--offline",
            "--locked",
            "--all-features",
            "--format-version=1",
        ])
        .output()
        .unwrap();
    assert!(
        metadata.status.success(),
        "{}",
        String::from_utf8_lossy(&metadata.stderr)
    );
    let metadata: Value = serde_json::from_slice(&metadata.stdout).unwrap();
    for name in ["optional_script", "dev_macro"] {
        assert!(
            metadata["packages"]
                .as_array()
                .unwrap()
                .iter()
                .any(|package| package["name"] == name)
        );
    }

    let default = fixture.graph(CheckSelection {
        lib: true,
        ..CheckSelection::default()
    });
    let admitted = validate_check_unit_graph(&default).unwrap();
    assert_eq!(
        (admitted.units, admitted.packages, admitted.roots),
        (2, 2, 1)
    );
    assert!(
        admitted
            .source_paths()
            .iter()
            .all(|path| Path::new(path).starts_with(fixture.root()))
    );
    assert!(
        !admitted
            .source_paths()
            .iter()
            .any(|path| path.contains("optional-script") || path.contains("dev-macro"))
    );

    let workspace = validate_check_unit_graph(&fixture.graph(CheckSelection {
        workspace: true,
        lib: true,
        ..CheckSelection::default()
    }))
    .unwrap();
    assert_eq!(workspace.roots, 2);
    let package = validate_check_unit_graph(&fixture.graph(CheckSelection {
        packages: vec!["ordinary".into()],
        lib: true,
        ..CheckSelection::default()
    }))
    .unwrap();
    assert_eq!((package.units, package.packages, package.roots), (1, 1, 1));
    let all_targets = validate_check_unit_graph(&fixture.graph(CheckSelection {
        packages: vec!["ordinary".into()],
        all_targets: true,
        ..CheckSelection::default()
    }))
    .unwrap();
    assert_eq!(
        (all_targets.units, all_targets.packages, all_targets.roots),
        (2, 1, 2),
        "Cargo plans ordinary library and test-check units without executing tests"
    );
    let binaries = validate_check_unit_graph(&fixture.graph(CheckSelection {
        bins: true,
        release: true,
        ..CheckSelection::default()
    }))
    .unwrap();
    assert!(
        binaries
            .source_paths()
            .iter()
            .any(|path| path.ends_with("/src/main.rs"))
    );

    let script = fixture.graph(CheckSelection {
        lib: true,
        features: vec!["script".into()],
        ..CheckSelection::default()
    });
    assert!(
        script["units"]
            .as_array()
            .unwrap()
            .iter()
            .any(|unit| unit["mode"] == "run-custom-build")
    );
    assert!(validate_check_unit_graph(&script).is_err());
    let development = fixture.graph(CheckSelection {
        tests: true,
        ..CheckSelection::default()
    });
    assert!(
        development["units"]
            .as_array()
            .unwrap()
            .iter()
            .any(|unit| unit["target"]["kind"] == serde_json::json!(["proc-macro"]))
    );
    assert!(validate_check_unit_graph(&development).is_err());
    fixture.assert_no_compilation_or_project_execution();
}

fn host_target(fixture: &Fixture) -> String {
    let output = Command::new(fixture.tools.join("bin/rustc"))
        .arg("-vV")
        .output()
        .unwrap();
    assert!(output.status.success());
    String::from_utf8(output.stdout)
        .unwrap()
        .lines()
        .find_map(|line| line.strip_prefix("host: "))
        .expect("captured compiler host triple")
        .to_owned()
}

fn add_check_profile(fixture: &Fixture) {
    use std::io::Write;
    fs::OpenOptions::new()
        .append(true)
        .open(fixture.root().join("Cargo.toml"))
        .unwrap()
        .write_all(
            b"\n[profile.check-fast]\ninherits = 'dev'\nopt-level = 2\ndebug-assertions = false\n",
        )
        .unwrap();
}

#[test]
fn real_cargo_graph_retains_each_compilation_target_and_named_profile() {
    let fixture = Fixture::new();
    let host = host_target(&fixture);
    add_check_profile(&fixture);
    let selection = CheckSelection {
        lib: true,
        target: vec![host.clone(), "wasm32-unknown-unknown".into()],
        profile: Some("check-fast".into()),
        ..CheckSelection::default()
    };
    // Graph queries need no cross-target standard library installation: they
    // describe compiler units without compiling their deliberately invalid Rust.
    let graph = fixture.graph(selection);
    let admitted = validate_check_unit_graph(&graph).unwrap();
    assert_eq!(admitted.roots, 2);
    assert_eq!(admitted.packages, 2);
    let mut platforms = std::collections::BTreeSet::new();
    for root in graph["roots"].as_array().unwrap() {
        let index = usize::try_from(root.as_u64().unwrap()).unwrap();
        let unit = &graph["units"][index];
        platforms.insert(unit["platform"].as_str().unwrap());
        assert_eq!(unit["profile"]["opt_level"], "2");
        assert_eq!(unit["profile"]["debug_assertions"], false);
    }
    assert_eq!(
        platforms,
        std::collections::BTreeSet::from([host.as_str(), "wasm32-unknown-unknown"])
    );
    let alias = fixture.graph(CheckSelection {
        lib: true,
        target: vec!["host-tuple".into()],
        profile: Some("check-fast".into()),
        ..CheckSelection::default()
    });
    assert_eq!(validate_check_unit_graph(&alias).unwrap().roots, 1);
    let root = usize::try_from(alias["roots"][0].as_u64().unwrap()).unwrap();
    assert_eq!(alias["units"][root]["platform"], host);
    fixture.assert_no_compilation_or_project_execution();
}

#[test]
fn a_test_profile_does_not_bypass_selected_proc_macro_admission() {
    let fixture = Fixture::new();
    let pure = fixture.graph(CheckSelection {
        lib: true,
        profile: Some("dev".into()),
        ..CheckSelection::default()
    });
    validate_check_unit_graph(&pure).unwrap();
    let development = fixture.graph(CheckSelection {
        lib: true,
        profile: Some("test".into()),
        ..CheckSelection::default()
    });
    assert!(
        development["units"]
            .as_array()
            .unwrap()
            .iter()
            .any(|unit| unit["target"]["kind"] == serde_json::json!(["proc-macro"]))
    );
    assert!(validate_check_unit_graph(&development).is_err());
    fixture.assert_no_compilation_or_project_execution();
}

#[test]
fn one_unsafe_target_refuses_a_multi_target_check_before_any_project_execution() {
    let fixture = Fixture::new();
    let host = host_target(&fixture);
    // The executable dependency is selected only for WebAssembly. Querying
    // the native graph and then compiling other targets would miss it entirely.
    fs::write(
        fixture.root().join("Cargo.toml"),
        r#"
[package]
name = "selected_graph_app"
version = "0.1.0"
edition = "2024"
[workspace]
members = ["ordinary"]
exclude = ["optional-script", "dev-macro"]
resolver = "2"
[dependencies]
ordinary = { path = "ordinary" }
[target.'cfg(target_arch = "wasm32")'.dependencies]
optional_script = { path = "optional-script" }
"#,
    )
    .unwrap();
    let lock = fixture.command().args(["generate-lockfile", "--offline"]).output().unwrap();
    assert!(lock.status.success(), "{}", String::from_utf8_lossy(&lock.stderr));
    let native = fixture.graph(CheckSelection {
        lib: true,
        target: vec![host.clone()],
        ..CheckSelection::default()
    });
    validate_check_unit_graph(&native).unwrap();
    for targets in [
        vec!["wasm32-unknown-unknown".to_owned()],
        vec![host, "wasm32-unknown-unknown".to_owned()],
    ] {
        let graph = fixture.graph(CheckSelection {
            lib: true,
            target: targets,
            ..CheckSelection::default()
        });
        assert!(
            graph["units"].as_array().unwrap().iter()
                .any(|unit| unit["mode"] == "run-custom-build")
        );
        assert!(validate_check_unit_graph(&graph).is_err());
    }
    fixture.assert_no_compilation_or_project_execution();
}

#[test]
fn a_native_target_check_uses_the_named_profile_and_reports_real_metadata() {
    let fixture = Fixture::new();
    let host = host_target(&fixture);
    add_check_profile(&fixture);
    // Unlike the graph-only tests, this case intentionally runs rustc for one
    // pure package. The default profile is a negative control: it must fail.
    fs::write(
        fixture.root().join("ordinary/src/lib.rs"),
        "#![no_std]\n#[cfg(debug_assertions)]\ncompile_error!(\"custom check profile was not applied\");\npub const VALUE: u32 = 17;\n",
    )
    .unwrap();
    let mut selection = CheckSelection {
        packages: vec!["ordinary".into()],
        lib: true,
        target: vec![host.clone()],
        profile: Some("check-fast".into()),
        ..CheckSelection::default()
    };
    validate_check_unit_graph(&fixture.graph(selection.clone())).unwrap();
    let check = |selection: &CheckSelection| {
        fixture.command()
            .args(selection.cargo_arguments().unwrap())
            .args(["--offline", "--locked", "--message-format=json"])
            .output().unwrap()
    };
    let compiled = check(&selection);
    assert!(compiled.status.success(), "{}", String::from_utf8_lossy(&compiled.stderr));
    let messages: Vec<Value> = String::from_utf8(compiled.stdout).unwrap()
        .lines().map(|line| serde_json::from_str(line).unwrap()).collect();
    assert!(messages.iter().any(|message| {
        message["reason"] == "build-finished" && message["success"] == true
    }));
    let artifact = messages.iter().find(|message| {
        message["reason"] == "compiler-artifact" && message["target"]["name"] == "ordinary"
    }).expect("Cargo must report the compiled ordinary package");
    let metadata: Vec<_> = artifact["filenames"].as_array().unwrap().iter()
        .filter_map(Value::as_str).map(Path::new)
        .filter(|path| path.extension().is_some_and(|extension| extension == "rmeta"))
        .collect();
    assert!(!metadata.is_empty(), "check did not report any metadata output");
    let expected = fixture.owner.path().join("target").join(host).join("check-fast");
    for path in metadata {
        assert!(path.starts_with(&expected), "{}", path.display());
        assert!(fs::metadata(path).unwrap().len() > 0);
    }
    selection.profile = Some("dev".into());
    let wrong = check(&selection);
    assert!(!wrong.status.success(), "default-profile negative control passed");
    assert!(String::from_utf8_lossy(&wrong.stdout)
        .contains("custom check profile was not applied"));
}

#[test]
fn unavailable_target_or_profile_never_falls_back_to_default_units() {
    let fixture = Fixture::new();
    for selection in [
        CheckSelection {
            lib: true,
            target: vec!["rabs-nonexistent-compile-target".into()],
            ..CheckSelection::default()
        },
        CheckSelection {
            lib: true,
            profile: Some("rabs-nonexistent-profile".into()),
            ..CheckSelection::default()
        },
    ] {
        let output = fixture.command()
            .args(selection.cargo_arguments().unwrap())
            .args(["--offline", "--locked", "--unit-graph", "-Z", "unstable-options"])
            .output().unwrap();
        assert!(!output.status.success(), "{selection:?} silently fell back");
    }
    fixture.assert_no_compilation_or_project_execution();
}
