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
