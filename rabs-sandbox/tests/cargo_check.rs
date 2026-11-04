//! Real Cargo planning proves the admission gate follows the selected units.
//! Graph cases contain deliberately uncompilable Rust and executable build
//! code, so a successful graph command cannot be mistaken for a real build.
//! Separate compilation cases replace selected sources, then consume the real
//! metadata, archive, binary and test-harness artifacts produced by Cargo.
//! This test needs the project's pinned nightly Cargo, but no bubblewrap or
//! network. It does not qualify cache serving or namespace enforcement.
#![cfg(target_os = "linux")]

use CompilationCommand::{Bench, Build, Check, Clippy, Run, Test};
use rabs_sandbox::cargo_check::{
    CompilationCommand, CompilationSelection, run_build_selection, validate_compilation_unit_graph,
};
use serde_json::Value;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

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
        self.tool_command("cargo")
    }

    fn tool_command(&self, name: &str) -> Command {
        let mut command = Command::new(self.tools.join("bin").join(name));
        command
            .env_clear()
            .env("PATH", "/usr/bin:/bin")
            .env("HOME", self.owner.path().join("home"))
            .env("CARGO_HOME", self.owner.path().join("home/cargo"))
            .env("RUSTC", self.tools.join("bin/rustc"))
            .env("RUSTDOC", self.tools.join("bin/rustdoc"))
            .env("CARGO_TARGET_DIR", self.owner.path().join("target"))
            .env("CARGO_INCREMENTAL", "0")
            .env("CARGO_BUILD_JOBS", "1")
            .current_dir(self.root());
        if name == "cargo-clippy" {
            command.env("CARGO", self.tools.join("bin/cargo"));
        }
        command
    }

    fn graph(&self, command: CompilationCommand, selection: CompilationSelection) -> Value {
        let mut invocation = if command == Clippy {
            self.tool_command("cargo-clippy")
        } else {
            self.command()
        };
        let planned = if command == Run {
            self.run_build_selection(&selection)
        } else {
            selection.clone()
        };
        invocation
            .args(
                planned
                    .cargo_arguments(if command == Run { Build } else { command })
                    .unwrap(),
            )
            .args([
                "--offline",
                "--locked",
                "--unit-graph",
                "-Z",
                "unstable-options",
            ]);
        if command == Clippy {
            invocation.args(selection.runtime_arguments(command).unwrap());
        }
        let output = invocation.output().unwrap();
        assert!(
            output.status.success(),
            "selected {selection:?}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        let graph: Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(graph["version"], 1);
        graph
    }

    fn run_build_selection(&self, selection: &CompilationSelection) -> CompilationSelection {
        if !selection.bin.is_empty() || !selection.example.is_empty() {
            return run_build_selection(selection, &Value::Null, None).unwrap();
        }
        let metadata = self
            .command()
            .args([
                "metadata",
                "--no-deps",
                "--format-version=1",
                "--offline",
                "--locked",
            ])
            .output()
            .unwrap();
        assert!(
            metadata.status.success(),
            "{}",
            String::from_utf8_lossy(&metadata.stderr)
        );
        let metadata: Value = serde_json::from_slice(&metadata.stdout).unwrap();
        let package = selection.packages.first().map(|spec| {
            let output = self
                .command()
                .args(["pkgid", "--offline", "--locked", "--package", spec])
                .output()
                .unwrap();
            assert!(
                output.status.success(),
                "{}",
                String::from_utf8_lossy(&output.stderr)
            );
            String::from_utf8(output.stdout).unwrap().trim().to_owned()
        });
        run_build_selection(selection, &metadata, package.as_deref()).unwrap()
    }

    fn runtime(
        &self,
        command: CompilationCommand,
        selection: &CompilationSelection,
        input: &[u8],
    ) -> std::process::Output {
        assert!(matches!(command, Run | Bench));
        let mut child = self
            .command()
            .args(selection.cargo_arguments(command).unwrap())
            .args(["--offline", "--locked", "--message-format=json"])
            .args(selection.runtime_arguments(command).unwrap())
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        child.stdin.take().unwrap().write_all(input).unwrap();
        child.wait_with_output().unwrap()
    }

    fn test(&self, selection: &CompilationSelection) -> std::process::Output {
        self.command()
            .args(selection.cargo_arguments(Test).unwrap())
            .args(["--offline", "--locked", "--message-format=json"])
            .args(selection.runtime_arguments(Test).unwrap())
            .output()
            .unwrap()
    }

    fn clippy(&self, selection: &CompilationSelection) -> std::process::Output {
        self.tool_command("cargo-clippy")
            .args(selection.cargo_arguments(Clippy).unwrap())
            .args(["--offline", "--locked", "--message-format=json"])
            .args(selection.runtime_arguments(Clippy).unwrap())
            .output()
            .unwrap()
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
fn real_clippy_unit_graph_preserves_selection_without_compilation_or_lint_authority() {
    let fixture = Fixture::new();
    for selection in [
        CompilationSelection {
            lib: true,
            ..CompilationSelection::default()
        },
        CompilationSelection {
            workspace: true,
            all_targets: true,
            all_features: true,
            no_deps: true,
            lint_args: vec![
                "-D".into(),
                "warnings".into(),
                "-Aclippy::needless_return".into(),
            ],
            ..CompilationSelection::default()
        },
    ] {
        let report =
            validate_compilation_unit_graph(&fixture.graph(Clippy, selection), Clippy).unwrap();
        assert!(report.requires_closed_dependency_execution());
        assert!(!report.contains_doctests());
    }
    fixture.assert_no_compilation_or_project_execution();
}

#[test]
fn native_clippy_reports_current_lints_after_check_and_lint_option_changes() {
    let fixture = Fixture::new();
    fs::write(
        fixture.root().join("ordinary/src/lib.rs"),
        "pub fn answer() -> u32 { return 23; }\n",
    )
    .unwrap();
    let checked = fixture
        .command()
        .args(["check", "--offline", "--locked", "-p", "ordinary", "--lib"])
        .output()
        .unwrap();
    assert!(
        checked.status.success(),
        "{}",
        String::from_utf8_lossy(&checked.stderr)
    );
    let mut selection = CompilationSelection {
        packages: vec!["ordinary".into()],
        lib: true,
        no_deps: true,
        lint_args: vec!["-Dclippy::needless_return".into()],
        ..CompilationSelection::default()
    };
    for round in 0..2 {
        let rejected = fixture.clippy(&selection);
        assert_eq!(
            rejected.status.code(),
            Some(101),
            "round {round}: {}",
            String::from_utf8_lossy(&rejected.stderr)
        );
        assert!(
            String::from_utf8_lossy(&rejected.stdout).contains("clippy::needless_return"),
            "{}",
            String::from_utf8_lossy(&rejected.stdout)
        );
        selection.lint_args = vec!["-Aclippy::needless_return".into()];
        let allowed = fixture.clippy(&selection);
        assert!(
            allowed.status.success(),
            "{}",
            String::from_utf8_lossy(&allowed.stderr)
        );
        selection.lint_args = vec!["-Dclippy::needless_return".into()];
    }
}

#[test]
fn real_check_graph_retains_binary_example_test_and_bench_metadata_families() {
    let fixture = Fixture::new();
    for directory in ["examples", "tests", "benches"] {
        fs::create_dir(fixture.root().join(directory)).unwrap();
    }
    for path in [
        "examples/demo.rs",
        "tests/integration.rs",
        "tests/manual.rs",
        "benches/timing.rs",
    ] {
        fs::write(
            fixture.root().join(path),
            "compile_error!(\"planning must not compile a check target\"); fn main() {}\n",
        )
        .unwrap();
    }
    let manifest = fs::read_to_string(fixture.root().join("Cargo.toml")).unwrap();
    fs::write(
        fixture.root().join("Cargo.toml"),
        format!(
            "{manifest}\n[[test]]\nname='manual'\nharness=false\n[[bench]]\nname='timing'\nharness=false\n"
        ),
    )
    .unwrap();
    let selected = fixture.graph(
        Check,
        CompilationSelection {
            all_targets: true,
            ..CompilationSelection::default()
        },
    );
    let report = validate_compilation_unit_graph(&selected, Check).unwrap();
    for (name, kind, crate_type) in [
        ("selected_graph_app", "bin", "bin"),
        ("demo", "example", "bin"),
        ("integration", "test", "bin"),
        ("manual", "test", "bin"),
        ("timing", "bench", "bin"),
    ] {
        assert!(
            report.workspace_units().iter().any(|unit| {
                unit.crate_name() == name
                    && unit.target_kinds() == [kind]
                    && unit.crate_types() == [crate_type]
                    && unit.mode() == "check"
                    && unit.is_root()
            }),
            "missing selected {kind} metadata family {name}: {:?}",
            report.workspace_units()
        );
    }
    // The graph does not serialize Cargo's Check { test } discriminator.
    // Preserve the selected family; the driver additionally binds the trusted
    // command selectors before admitting an unmodified --test invocation.
    let ordinary = fixture.graph(
        Check,
        CompilationSelection {
            packages: vec!["ordinary".into()],
            all_targets: true,
            ..CompilationSelection::default()
        },
    );
    let units = ordinary["units"].as_array().unwrap();
    assert_eq!(units.len(), 2);
    assert_eq!(units[0]["target"], units[1]["target"]);
    assert_eq!(units[0]["mode"], "check");
    assert_eq!(units[1]["mode"], "check");
    fixture.assert_no_compilation_or_project_execution();
}

#[test]
fn real_cargo_unit_graph_distinguishes_pure_checks_from_selected_project_executors() {
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

    let default = fixture.graph(
        Check,
        CompilationSelection {
            lib: true,
            ..CompilationSelection::default()
        },
    );
    let admitted = validate_compilation_unit_graph(&default, Check).unwrap();
    assert!(!admitted.requires_closed_dependency_execution());
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

    let workspace = validate_compilation_unit_graph(
        &fixture.graph(
            Check,
            CompilationSelection {
                workspace: true,
                lib: true,
                ..CompilationSelection::default()
            },
        ),
        Check,
    )
    .unwrap();
    assert_eq!(workspace.roots, 2);
    let package = validate_compilation_unit_graph(
        &fixture.graph(
            Check,
            CompilationSelection {
                packages: vec!["ordinary".into()],
                lib: true,
                ..CompilationSelection::default()
            },
        ),
        Check,
    )
    .unwrap();
    assert_eq!((package.units, package.packages, package.roots), (1, 1, 1));
    let all_targets = validate_compilation_unit_graph(
        &fixture.graph(
            Check,
            CompilationSelection {
                packages: vec!["ordinary".into()],
                all_targets: true,
                ..CompilationSelection::default()
            },
        ),
        Check,
    )
    .unwrap();
    assert_eq!(
        (all_targets.units, all_targets.packages, all_targets.roots),
        (2, 1, 2),
        "Cargo plans ordinary library and test-check units without executing tests"
    );
    let binaries = validate_compilation_unit_graph(
        &fixture.graph(
            Check,
            CompilationSelection {
                bins: true,
                release: true,
                ..CompilationSelection::default()
            },
        ),
        Check,
    )
    .unwrap();
    assert!(
        binaries
            .source_paths()
            .iter()
            .any(|path| path.ends_with("/src/main.rs"))
    );

    let script = fixture.graph(
        Check,
        CompilationSelection {
            lib: true,
            features: vec!["script".into()],
            ..CompilationSelection::default()
        },
    );
    assert!(
        script["units"]
            .as_array()
            .unwrap()
            .iter()
            .any(|unit| unit["mode"] == "run-custom-build")
    );
    assert!(
        validate_compilation_unit_graph(&script, Check)
            .unwrap()
            .requires_closed_dependency_execution()
    );
    let development = fixture.graph(
        Check,
        CompilationSelection {
            tests: true,
            ..CompilationSelection::default()
        },
    );
    assert!(
        development["units"]
            .as_array()
            .unwrap()
            .iter()
            .any(|unit| unit["target"]["kind"] == serde_json::json!(["proc-macro"]))
    );
    assert!(
        validate_compilation_unit_graph(&development, Check)
            .unwrap()
            .requires_closed_dependency_execution()
    );
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
    let selection = CompilationSelection {
        lib: true,
        target: vec![host.clone(), "wasm32-unknown-unknown".into()],
        profile: Some("check-fast".into()),
        ..CompilationSelection::default()
    };
    // Graph queries need no cross-target standard library installation: they
    // describe compiler units without compiling their deliberately invalid Rust.
    let graph = fixture.graph(Check, selection);
    let admitted = validate_compilation_unit_graph(&graph, Check).unwrap();
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
    let alias = fixture.graph(
        Check,
        CompilationSelection {
            lib: true,
            target: vec!["host-tuple".into()],
            profile: Some("check-fast".into()),
            ..CompilationSelection::default()
        },
    );
    assert_eq!(
        validate_compilation_unit_graph(&alias, Check)
            .unwrap()
            .roots,
        1
    );
    let root = usize::try_from(alias["roots"][0].as_u64().unwrap()).unwrap();
    assert_eq!(alias["units"][root]["platform"], host);
    fixture.assert_no_compilation_or_project_execution();
}

#[test]
fn a_test_profile_cannot_hide_its_selected_proc_macro_execution_policy() {
    let fixture = Fixture::new();
    let pure = fixture.graph(
        Check,
        CompilationSelection {
            lib: true,
            profile: Some("dev".into()),
            ..CompilationSelection::default()
        },
    );
    assert!(
        !validate_compilation_unit_graph(&pure, Check)
            .unwrap()
            .requires_closed_dependency_execution()
    );
    let development = fixture.graph(
        Check,
        CompilationSelection {
            lib: true,
            profile: Some("test".into()),
            ..CompilationSelection::default()
        },
    );
    assert!(
        development["units"]
            .as_array()
            .unwrap()
            .iter()
            .any(|unit| unit["target"]["kind"] == serde_json::json!(["proc-macro"]))
    );
    assert!(
        validate_compilation_unit_graph(&development, Check)
            .unwrap()
            .requires_closed_dependency_execution()
    );
    fixture.assert_no_compilation_or_project_execution();
}

#[test]
fn one_project_executor_requires_closed_dependency_execution_for_a_multi_target_check() {
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
    let native = fixture.graph(
        Check,
        CompilationSelection {
            lib: true,
            target: vec![host.clone()],
            ..CompilationSelection::default()
        },
    );
    assert!(
        !validate_compilation_unit_graph(&native, Check)
            .unwrap()
            .requires_closed_dependency_execution()
    );
    for targets in [
        vec!["wasm32-unknown-unknown".to_owned()],
        vec![host, "wasm32-unknown-unknown".to_owned()],
    ] {
        let graph = fixture.graph(
            Check,
            CompilationSelection {
                lib: true,
                target: targets,
                ..CompilationSelection::default()
            },
        );
        assert!(
            graph["units"]
                .as_array()
                .unwrap()
                .iter()
                .any(|unit| unit["mode"] == "run-custom-build")
        );
        assert!(
            validate_compilation_unit_graph(&graph, Check)
                .unwrap()
                .requires_closed_dependency_execution()
        );
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
    let mut selection = CompilationSelection {
        packages: vec!["ordinary".into()],
        lib: true,
        target: vec![host.clone()],
        profile: Some("check-fast".into()),
        ..CompilationSelection::default()
    };
    validate_compilation_unit_graph(&fixture.graph(Check, selection.clone()), Check).unwrap();
    let check = |selection: &CompilationSelection| {
        fixture
            .command()
            .args(selection.cargo_arguments(Check).unwrap())
            .args(["--offline", "--locked", "--message-format=json"])
            .output()
            .unwrap()
    };
    let compiled = check(&selection);
    assert!(
        compiled.status.success(),
        "{}",
        String::from_utf8_lossy(&compiled.stderr)
    );
    let messages: Vec<Value> = String::from_utf8(compiled.stdout)
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect();
    assert!(
        messages
            .iter()
            .any(|message| { message["reason"] == "build-finished" && message["success"] == true })
    );
    let artifact = messages
        .iter()
        .find(|message| {
            message["reason"] == "compiler-artifact" && message["target"]["name"] == "ordinary"
        })
        .expect("Cargo must report the compiled ordinary package");
    let metadata: Vec<_> = artifact["filenames"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(Value::as_str)
        .map(Path::new)
        .filter(|path| {
            path.extension()
                .is_some_and(|extension| extension == "rmeta")
        })
        .collect();
    assert!(
        !metadata.is_empty(),
        "check did not report any metadata output"
    );
    let expected = fixture
        .owner
        .path()
        .join("target")
        .join(host)
        .join("check-fast");
    for path in metadata {
        assert!(path.starts_with(&expected), "{}", path.display());
        assert!(fs::metadata(path).unwrap().len() > 0);
    }
    selection.profile = Some("dev".into());
    let wrong = check(&selection);
    assert!(
        !wrong.status.success(),
        "default-profile negative control passed"
    );
    assert!(
        String::from_utf8_lossy(&wrong.stdout).contains("custom check profile was not applied")
    );
}

#[test]
fn unavailable_target_or_profile_never_falls_back_to_default_units() {
    let fixture = Fixture::new();
    for selection in [
        CompilationSelection {
            lib: true,
            target: vec!["rabs-nonexistent-compile-target".into()],
            ..CompilationSelection::default()
        },
        CompilationSelection {
            lib: true,
            profile: Some("rabs-nonexistent-profile".into()),
            ..CompilationSelection::default()
        },
    ] {
        let output = fixture
            .command()
            .args(selection.cargo_arguments(Check).unwrap())
            .args([
                "--offline",
                "--locked",
                "--unit-graph",
                "-Z",
                "unstable-options",
            ])
            .output()
            .unwrap();
        assert!(!output.status.success(), "{selection:?} silently fell back");
    }
    fixture.assert_no_compilation_or_project_execution();
}

#[test]
fn real_cargo_build_graph_admits_compile_only_targets_and_identifies_project_executors() {
    let fixture = Fixture::new();
    let library = fixture.graph(
        Build,
        CompilationSelection {
            lib: true,
            ..CompilationSelection::default()
        },
    );
    let admitted = validate_compilation_unit_graph(&library, Build).unwrap();
    assert!(!admitted.requires_closed_dependency_execution());
    assert_eq!(
        (admitted.units, admitted.packages, admitted.roots),
        (2, 2, 1)
    );
    assert!(
        library["units"]
            .as_array()
            .unwrap()
            .iter()
            .all(|unit| unit["mode"] == "build")
    );

    let harnesses = fixture.graph(
        Build,
        CompilationSelection {
            packages: vec!["ordinary".into()],
            all_targets: true,
            ..CompilationSelection::default()
        },
    );
    let admitted = validate_compilation_unit_graph(&harnesses, Build).unwrap();
    assert_eq!(
        (admitted.units, admitted.packages, admitted.roots),
        (2, 1, 2)
    );
    assert!(
        harnesses["units"]
            .as_array()
            .unwrap()
            .iter()
            .any(|unit| unit["mode"] == "test")
    );
    assert!(validate_compilation_unit_graph(&harnesses, Check).is_err());

    for selection in [
        CompilationSelection {
            lib: true,
            features: vec!["script".into()],
            ..CompilationSelection::default()
        },
        CompilationSelection {
            tests: true,
            ..CompilationSelection::default()
        },
    ] {
        let graph = fixture.graph(Build, selection);
        assert!(
            validate_compilation_unit_graph(&graph, Build)
                .unwrap()
                .requires_closed_dependency_execution()
        );
    }
    fixture.assert_no_compilation_or_project_execution();
}

#[test]
fn real_compilation_consumes_generated_source_and_proc_macros_without_running_tests() {
    for command in [Check, Build] {
        let fixture = Fixture::new();
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
optional_script = { path = "optional-script" }
dev_macro = { path = "dev-macro" }
"#,
        )
        .unwrap();
        fs::write(
            fixture.root().join("ordinary/src/lib.rs"),
            "pub const VALUE: u32 = 3;\n",
        )
        .unwrap();
        fs::write(
            fixture.root().join("optional-script/build.rs"),
            r#"
fn main() {
    let output = std::path::PathBuf::from(std::env::var_os("OUT_DIR").unwrap());
    std::fs::write(output.join("generated.rs"), "pub const VALUE: u32 = 19;\n").unwrap();
    println!("cargo::rerun-if-changed=build.rs");
}
"#,
        )
        .unwrap();
        fs::write(
            fixture.root().join("optional-script/src/lib.rs"),
            "include!(concat!(env!(\"OUT_DIR\"), \"/generated.rs\"));\n",
        )
        .unwrap();
        fs::write(
            fixture.root().join("dev-macro/src/lib.rs"),
            r#"
extern crate proc_macro;
#[proc_macro]
pub fn value(_: proc_macro::TokenStream) -> proc_macro::TokenStream {
    eprintln!("RABS_GRAPH_PROC_MACRO_EXECUTED");
    "23u32".parse().unwrap()
}
"#,
        )
        .unwrap();
        fs::write(
            fixture.root().join("src/lib.rs"),
            r#"
pub const VALUE: u32 = ordinary::VALUE + optional_script::VALUE + dev_macro::value!();
const _: [(); 45] = [(); VALUE as usize];
#[test]
fn compilation_must_not_run_this_test() {
    std::fs::write("test-was-executed", b"unexpected").unwrap();
    panic!("Cargo check/build must not run tests");
}
"#,
        )
        .unwrap();
        fs::write(
            fixture.root().join("src/main.rs"),
            "fn main() { std::fs::write(\"program-was-executed\", b\"unexpected\").unwrap(); }\n",
        )
        .unwrap();
        let selection = CompilationSelection {
            lib: true,
            tests: true,
            ..CompilationSelection::default()
        };
        let graph = fixture.graph(command, selection.clone());
        let admitted = validate_compilation_unit_graph(&graph, command).unwrap();
        assert!(admitted.requires_closed_dependency_execution());
        fixture.assert_no_compilation_or_project_execution();

        let compiled = fixture
            .command()
            .args(selection.cargo_arguments(command).unwrap())
            .args(["--offline", "--locked", "--message-format=json"])
            .output()
            .unwrap();
        assert!(
            compiled.status.success(),
            "{command:?}: {}",
            String::from_utf8_lossy(&compiled.stderr)
        );
        assert!(
            String::from_utf8_lossy(&compiled.stderr).contains("RABS_GRAPH_PROC_MACRO_EXECUTED")
        );
        let messages: Vec<Value> = String::from_utf8(compiled.stdout)
            .unwrap()
            .lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect();
        let generated = messages
            .iter()
            .find(|event| event["reason"] == "build-script-executed")
            .expect("the selected build script must actually run");
        let output = Path::new(generated["out_dir"].as_str().unwrap());
        assert_eq!(
            fs::read_to_string(output.join("generated.rs")).unwrap(),
            "pub const VALUE: u32 = 19;\n"
        );
        assert!(
            messages
                .iter()
                .any(|event| event["reason"] == "build-finished" && event["success"] == true)
        );
        assert!(!fixture.root().join("test-was-executed").exists());
        assert!(!fixture.root().join("program-was-executed").exists());
    }
}

#[test]
fn native_run_resolves_default_binary_preserves_stdin_and_arguments_and_reexecutes_warm_programs() {
    let fixture = Fixture::new();
    let manifest = fs::read_to_string(fixture.root().join("Cargo.toml")).unwrap();
    fs::write(
        fixture.root().join("Cargo.toml"),
        manifest.replacen(
            "[package]",
            "[package]\ndefault-run = 'selected_graph_app'",
            1,
        ),
    )
    .unwrap();
    fs::create_dir_all(fixture.root().join("src/bin")).unwrap();
    fs::write(
        fixture.root().join("src/bin/unselected.rs"),
        "compile_error!(\"run selected an unrelated binary\");fn main(){}\n",
    )
    .unwrap();
    fs::write(
        fixture.root().join("ordinary/src/lib.rs"),
        "pub const VALUE: u32 = 37;\n",
    )
    .unwrap();
    fs::write(
        fixture.root().join("src/lib.rs"),
        "pub const VALUE: u32 = ordinary::VALUE;\n",
    )
    .unwrap();
    fs::write(
        fixture.root().join("src/main.rs"),
        r#"use std::io::{Read, Write};
fn main() {
    let args = std::env::args().skip(1).collect::<Vec<_>>();
    let mut input = Vec::new();
    std::io::stdin().read_to_end(&mut input).unwrap();
    println!("RUN:{}:{args:?}", selected_graph_app::VALUE);
    std::io::stdout().write_all(&input).unwrap();
    if args.iter().any(|arg| arg == "--fail") { std::process::exit(7); }
}
"#,
    )
    .unwrap();
    let mut selection = CompilationSelection {
        run_args: vec![
            "".into(),
            "雪".into(),
            "--manifest-path=/not-cargo".into(),
            "line\nvalue".into(),
        ],
        ..CompilationSelection::default()
    };
    let graph = fixture.graph(Run, selection.clone());
    let report = validate_compilation_unit_graph(&graph, Run).unwrap();
    assert!(report.requires_closed_dependency_execution());
    assert_eq!(report.roots, 1);
    assert!(
        !graph["units"]
            .as_array()
            .unwrap()
            .iter()
            .any(|unit| unit["target"]["name"] == "unselected")
    );
    fixture.assert_no_compilation_or_project_execution();
    let input = b"piped input\0\xff\n";
    for number in 0..2 {
        let output = fixture.runtime(Run, &selection, input);
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let mut expected = format!("RUN:37:{:?}\n", selection.run_args).into_bytes();
        expected.extend(input);
        assert!(
            output.stdout.ends_with(&expected),
            "{}",
            String::from_utf8_lossy(&output.stdout)
        );
        let artifacts = String::from_utf8_lossy(&output.stdout)
            .lines()
            .filter_map(|line| serde_json::from_str::<Value>(line).ok())
            .filter(|message| message["reason"] == "compiler-artifact")
            .collect::<Vec<_>>();
        assert!(!artifacts.is_empty());
        assert!(
            artifacts
                .iter()
                .all(|artifact| artifact["fresh"] == (number == 1))
        );
    }
    selection.packages = vec!["selected_graph_app@0.1.0".into()];
    validate_compilation_unit_graph(&fixture.graph(Run, selection.clone()), Run).unwrap();
    selection.run_args.push("--fail".into());
    let failed = fixture.runtime(Run, &selection, input);
    assert_eq!(
        failed.status.code(),
        Some(7),
        "{}",
        String::from_utf8_lossy(&failed.stderr)
    );
    assert!(failed.stdout.ends_with(input));

    fs::create_dir_all(fixture.root().join("examples")).unwrap();
    fs::write(
        fixture.root().join("examples/demo.rs"),
        "fn main(){println!(\"EXAMPLE:{}\", selected_graph_app::VALUE);}\n",
    )
    .unwrap();
    fs::write(
        fixture.root().join("dev-macro/src/lib.rs"),
        "extern crate proc_macro;\n",
    )
    .unwrap();
    let example = CompilationSelection {
        example: vec!["demo".into()],
        ..CompilationSelection::default()
    };
    validate_compilation_unit_graph(&fixture.graph(Run, example.clone()), Run).unwrap();
    let output = fixture.runtime(Run, &example, &[]);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(output.stdout.ends_with(b"EXAMPLE:37\n"));
}

#[test]
fn native_bench_respects_custom_harness_no_run_optimized_default_and_current_execution() {
    let fixture = Fixture::new();
    fs::create_dir_all(fixture.root().join("benches")).unwrap();
    let manifest = fs::read_to_string(fixture.root().join("Cargo.toml")).unwrap();
    fs::write(
        fixture.root().join("Cargo.toml"),
        format!("{manifest}\n[[bench]]\nname='timing'\npath='benches/timing.rs'\nharness=false\n"),
    )
    .unwrap();
    fs::write(
        fixture.root().join("ordinary/src/lib.rs"),
        "pub const VALUE: u32 = 42;\n",
    )
    .unwrap();
    fs::write(
        fixture.root().join("src/lib.rs"),
        "pub const VALUE: u32 = ordinary::VALUE;\n",
    )
    .unwrap();
    fs::write(
        fixture.root().join("src/main.rs"),
        "fn main(){panic!(\"bench must not run the application\");}\n",
    )
    .unwrap();
    fs::write(
        fixture.root().join("dev-macro/src/lib.rs"),
        "extern crate proc_macro;\n",
    )
    .unwrap();
    fs::write(fixture.root().join("benches/timing.rs"), r#"fn main() {
    assert_eq!(selected_graph_app::VALUE, 42);
    let args = std::env::args().skip(1).collect::<Vec<_>>();
    std::fs::write("benchmark-args", args.join("\0")).unwrap();
    let previous: u32 = std::fs::read_to_string("benchmark-count").ok().map(|value| value.parse().unwrap()).unwrap_or(0);
    std::fs::write("benchmark-count", (previous + 1).to_string()).unwrap();
    println!("BENCH:{}:{}", previous + 1, cfg!(debug_assertions));
    if args.iter().any(|arg| arg == "--fail") { std::process::exit(11); }
}
"#).unwrap();
    let mut selection = CompilationSelection {
        bench: vec!["timing".into()],
        no_run: true,
        ..CompilationSelection::default()
    };
    let graph = fixture.graph(Bench, selection.clone());
    let report = validate_compilation_unit_graph(&graph, Bench).unwrap();
    assert!(report.requires_closed_dependency_execution());
    assert!(!report.contains_doctests());
    let root = graph["roots"][0].as_u64().unwrap() as usize;
    assert_eq!(graph["units"][root]["mode"], "test");
    assert_eq!(graph["units"][root]["profile"]["opt_level"], "3");
    fixture.assert_no_compilation_or_project_execution();
    let compiled = fixture.runtime(Bench, &selection, &[]);
    assert!(
        compiled.status.success(),
        "{}",
        String::from_utf8_lossy(&compiled.stderr)
    );
    assert!(!fixture.root().join("benchmark-count").exists());
    selection.no_run = false;
    selection.test_filter = Some("selected".into());
    selection.test_args = vec!["--literal-program-option".into(), "".into(), "雪".into()];
    for number in 1..=2 {
        let output = fixture.runtime(Bench, &selection, &[]);
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(String::from_utf8_lossy(&output.stdout).contains(&format!("BENCH:{number}:false")));
        assert_eq!(
            fs::read_to_string(fixture.root().join("benchmark-count")).unwrap(),
            number.to_string()
        );
        let arguments = fs::read_to_string(fixture.root().join("benchmark-args")).unwrap();
        let arguments = arguments.split('\0').collect::<Vec<_>>();
        assert!(arguments.contains(&"selected") && arguments.contains(&"--bench"));
        assert!(
            arguments
                .windows(3)
                .any(|args| args == ["--literal-program-option", "", "雪"])
        );
        let artifacts = String::from_utf8_lossy(&output.stdout)
            .lines()
            .filter_map(|line| serde_json::from_str::<Value>(line).ok())
            .filter(|message| message["reason"] == "compiler-artifact")
            .collect::<Vec<_>>();
        assert!(
            !artifacts.is_empty() && artifacts.iter().all(|artifact| artifact["fresh"] == true)
        );
    }
    selection.profile = Some("dev".into());
    let output = fixture.runtime(Bench, &selection, &[]);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(String::from_utf8_lossy(&output.stdout).contains("BENCH:3:true"));
    selection.test_args.push("--fail".into());
    let failed = fixture.runtime(Bench, &selection, &[]);
    assert!(
        !failed.status.success(),
        "a warm benchmark failure must remain a failure"
    );
    assert_eq!(
        fs::read_to_string(fixture.root().join("benchmark-count")).unwrap(),
        "4"
    );
}

#[test]
fn native_build_produces_real_archives_and_a_linked_binary_under_the_selected_profile() {
    let fixture = Fixture::new();
    let host = host_target(&fixture);
    add_check_profile(&fixture);
    fs::write(
        fixture.root().join("ordinary/src/lib.rs"),
        "#[cfg(debug_assertions)]\ncompile_error!(\"selected build profile was not applied\");\npub const VALUE: u32 = 17;\n",
    ).unwrap();
    fs::write(
        fixture.root().join("src/lib.rs"),
        "pub const VALUE: u32 = ordinary::VALUE;\n",
    )
    .unwrap();
    fs::write(
        fixture.root().join("src/main.rs"),
        "fn main() { std::fs::write(\"program-was-executed\", b\"ran\").unwrap(); println!(\"{}\", selected_graph_app::VALUE); }\n",
    ).unwrap();
    let mut selection = CompilationSelection {
        lib: true,
        bin: vec!["selected_graph_app".into()],
        target: vec![host.clone()],
        profile: Some("check-fast".into()),
        ..CompilationSelection::default()
    };
    let graph = fixture.graph(Build, selection.clone());
    validate_compilation_unit_graph(&graph, Build).unwrap();
    fixture.assert_no_compilation_or_project_execution();
    let build = |selection: &CompilationSelection| {
        fixture
            .command()
            .args(selection.cargo_arguments(Build).unwrap())
            .args(["--offline", "--locked", "--message-format=json"])
            .output()
            .unwrap()
    };
    let output = build(&selection);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let messages: Vec<Value> = String::from_utf8(output.stdout)
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect();
    assert!(
        messages
            .iter()
            .any(|message| message["reason"] == "build-finished" && message["success"] == true)
    );
    let expected = fixture
        .owner
        .path()
        .join("target")
        .join(host)
        .join("check-fast");
    for name in ["ordinary", "selected_graph_app"] {
        let artifact = messages
            .iter()
            .find(|message| {
                message["reason"] == "compiler-artifact"
                    && message["target"]["name"] == name
                    && message["target"]["kind"] == serde_json::json!(["lib"])
            })
            .expect("Cargo must report each real archive dependency");
        assert_eq!(artifact["fresh"], false);
        let archive = artifact["filenames"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(Value::as_str)
            .map(Path::new)
            .find(|path| {
                path.extension()
                    .is_some_and(|extension| extension == "rlib")
            })
            .expect("Cargo build must report a linked rlib, not metadata alone");
        assert!(archive.starts_with(&expected), "{}", archive.display());
        assert!(fs::read(archive).unwrap().starts_with(b"!<arch>\n"));
    }
    let binary = messages
        .iter()
        .find_map(|message| {
            (message["reason"] == "compiler-artifact"
                && message["target"]["name"] == "selected_graph_app")
                .then(|| message["executable"].as_str())
                .flatten()
        })
        .expect("Cargo must report its real linked binary");
    assert!(Path::new(binary).starts_with(expected));
    assert!(
        !fixture.root().join("program-was-executed").exists(),
        "cargo build ran the program"
    );
    let executed = Command::new(binary)
        .current_dir(fixture.root())
        .output()
        .unwrap();
    assert!(
        executed.status.success(),
        "{}",
        String::from_utf8_lossy(&executed.stderr)
    );
    assert_eq!(executed.stdout, b"17\n");
    assert_eq!(
        fs::read(fixture.root().join("program-was-executed")).unwrap(),
        b"ran"
    );
    selection.profile = Some("dev".into());
    let wrong_profile = build(&selection);
    assert!(
        !wrong_profile.status.success(),
        "default-profile negative control passed"
    );
    assert!(
        String::from_utf8_lossy(&wrong_profile.stdout)
            .contains("selected build profile was not applied")
    );
}

#[test]
fn native_build_compiles_test_harnesses_without_executing_the_tests() {
    let fixture = Fixture::new();
    fs::write(
        fixture.root().join("ordinary/src/lib.rs"),
        "pub const VALUE: u32 = 23;\n#[test]\nfn writes_marker() { std::fs::write(\"test-was-executed\", b\"ran\").unwrap(); assert_eq!(VALUE, 23); }\n",
    ).unwrap();
    let selection = CompilationSelection {
        packages: vec!["ordinary".into()],
        tests: true,
        ..CompilationSelection::default()
    };
    validate_compilation_unit_graph(&fixture.graph(Build, selection.clone()), Build).unwrap();
    let output = fixture
        .command()
        .args(selection.cargo_arguments(Build).unwrap())
        .args(["--offline", "--locked", "--message-format=json"])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let messages: Vec<Value> = String::from_utf8(output.stdout)
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect();
    let test = messages
        .iter()
        .find_map(|message| {
            (message["reason"] == "compiler-artifact" && message["profile"]["test"] == true)
                .then(|| message["executable"].as_str())
                .flatten()
        })
        .expect("Cargo build --tests must report its compiled harness");
    assert!(fs::metadata(test).unwrap().len() > 0);
    assert!(
        !fixture.root().join("test-was-executed").exists(),
        "cargo build ran its test harness"
    );
    // Exercise the resulting harness after proving that build did not run it.
    let executed = Command::new(test)
        .args(["writes_marker", "--exact"])
        .current_dir(fixture.root())
        .output()
        .unwrap();
    assert!(
        executed.status.success(),
        "{}",
        String::from_utf8_lossy(&executed.stderr)
    );
    assert_eq!(
        fs::read(fixture.root().join("test-was-executed")).unwrap(),
        b"ran"
    );
}

#[test]
fn real_cargo_test_graph_distinguishes_doctests_and_no_run_without_execution() {
    let fixture = Fixture::new();
    let selection = CompilationSelection {
        packages: vec!["ordinary".into()],
        ..CompilationSelection::default()
    };
    let default =
        validate_compilation_unit_graph(&fixture.graph(Test, selection.clone()), Test).unwrap();
    assert!(default.requires_closed_dependency_execution());
    assert!(default.contains_doctests());
    let no_run = validate_compilation_unit_graph(
        &fixture.graph(
            Test,
            CompilationSelection {
                no_run: true,
                ..selection.clone()
            },
        ),
        Test,
    )
    .unwrap();
    assert!(no_run.requires_closed_dependency_execution());
    // Cargo emits the same units for --no-run, including doctests it will not
    // execute. Runtime authority must follow the bound command selection, not
    // an inference that missing graph nodes prove compilation-only behavior.
    assert_eq!(no_run, default);
    let docs = validate_compilation_unit_graph(
        &fixture.graph(
            Test,
            CompilationSelection {
                doc: true,
                ..selection
            },
        ),
        Test,
    )
    .unwrap();
    assert!(docs.requires_closed_dependency_execution());
    assert!(docs.contains_doctests());
    fixture.assert_no_compilation_or_project_execution();
}

#[test]
fn native_cargo_test_no_run_filters_repeat_execution_and_preserves_failure() {
    let fixture = Fixture::new();
    fs::write(
        fixture.root().join("ordinary/src/lib.rs"),
        r#"
pub const VALUE: u32 = 23;
#[test]
fn selected_success() {
    let marker = std::path::PathBuf::from(std::env::var_os("CARGO_TARGET_DIR").unwrap())
        .join("unit-test-runs");
    let mut runs = std::fs::read(&marker).unwrap_or_default();
    runs.push(b'u');
    std::fs::write(marker, runs).unwrap();
    println!("selected-test-stdout");
    assert_eq!(VALUE, 23);
}
#[test]
#[ignore]
fn selected_failure() {
    panic!("selected-test-failure");
}
"#,
    )
    .unwrap();
    let mut selection = CompilationSelection {
        packages: vec!["ordinary".into()],
        lib: true,
        no_run: true,
        ..CompilationSelection::default()
    };
    let graph =
        validate_compilation_unit_graph(&fixture.graph(Test, selection.clone()), Test).unwrap();
    assert!(graph.requires_closed_dependency_execution());
    assert!(!graph.contains_doctests());
    let compiled = fixture.test(&selection);
    assert!(
        compiled.status.success(),
        "{}",
        String::from_utf8_lossy(&compiled.stderr)
    );
    assert!(
        String::from_utf8_lossy(&compiled.stdout)
            .lines()
            .filter_map(|line| serde_json::from_str::<Value>(line).ok())
            .any(|message| message["reason"] == "compiler-artifact"
                && message["profile"]["test"] == true
                && message["executable"]
                    .as_str()
                    .is_some_and(|path| fs::metadata(path).is_ok_and(|meta| meta.len() > 0)))
    );
    let marker = fixture.owner.path().join("target/unit-test-runs");
    assert!(!marker.exists(), "cargo test --no-run executed its harness");

    selection.no_run = false;
    selection.test_filter = Some("selected_success".into());
    selection.test_args = vec!["--exact".into(), "--nocapture".into()];
    for runs in [b"u".as_slice(), b"uu".as_slice()] {
        let executed = fixture.test(&selection);
        assert!(
            executed.status.success(),
            "{}",
            String::from_utf8_lossy(&executed.stderr)
        );
        let stdout = String::from_utf8(executed.stdout).unwrap();
        assert!(stdout.contains("selected-test-stdout"));
        assert!(!stdout.contains("selected-test-failure"));
        assert_eq!(fs::read(&marker).unwrap(), runs);
        assert!(
            stdout
                .lines()
                .filter_map(|line| serde_json::from_str::<Value>(line).ok())
                .any(|message| message["reason"] == "compiler-artifact"
                    && message["target"]["name"] == "ordinary"
                    && message["fresh"] == true),
            "the test must execute even when Cargo reuses its compiled harness"
        );
    }
    selection.test_filter = Some("selected_failure".into());
    selection.test_args.push("--ignored".into());
    let failed = fixture.test(&selection);
    assert_eq!(failed.status.code(), Some(101));
    assert!(
        String::from_utf8_lossy(&failed.stdout).contains("selected-test-failure")
            || String::from_utf8_lossy(&failed.stderr).contains("selected-test-failure")
    );
    assert_eq!(fs::read(marker).unwrap(), b"uu");
}

#[test]
fn native_cargo_doctests_execute_again_on_fresh_builds_and_return_test_failure() {
    let fixture = Fixture::new();
    let source = fixture.root().join("ordinary/src/lib.rs");
    fs::write(
        &source,
        r#"
/// ```
/// let marker = std::path::PathBuf::from(std::env::var_os("CARGO_TARGET_DIR").unwrap())
///     .join("doctest-runs");
/// let mut runs = std::fs::read(&marker).unwrap_or_default();
/// runs.push(b'd');
/// std::fs::write(marker, runs).unwrap();
/// assert_eq!(ordinary::answer(), 23);
/// ```
pub fn answer() -> u32 { 23 }
"#,
    )
    .unwrap();
    let selection = CompilationSelection {
        packages: vec!["ordinary".into()],
        doc: true,
        ..CompilationSelection::default()
    };
    let graph =
        validate_compilation_unit_graph(&fixture.graph(Test, selection.clone()), Test).unwrap();
    assert!(graph.requires_closed_dependency_execution());
    assert!(graph.contains_doctests());
    let marker = fixture.owner.path().join("target/doctest-runs");
    for runs in [b"d".as_slice(), b"dd".as_slice()] {
        let executed = fixture.test(&selection);
        assert!(
            executed.status.success(),
            "stdout={}\nstderr={}",
            String::from_utf8_lossy(&executed.stdout),
            String::from_utf8_lossy(&executed.stderr)
        );
        assert_eq!(fs::read(&marker).unwrap(), runs);
    }
    fs::write(
        source,
        "/// ```\n/// assert_eq!(ordinary::answer(), 99);\n/// ```\npub fn answer() -> u32 { 23 }\n",
    )
    .unwrap();
    let failed = fixture.test(&selection);
    assert_eq!(failed.status.code(), Some(101));
    assert!(String::from_utf8_lossy(&failed.stdout).contains("test result: FAILED"));
    assert_eq!(fs::read(marker).unwrap(), b"dd");
}
