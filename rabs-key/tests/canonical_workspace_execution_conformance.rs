//! Real Cargo/rustc conformance for execution-only canonical workspace units.
//!
//! Cargo supplies the actual graph, compiler argv, cwd, primary-package
//! environment, lint policy, dependency artifacts and build-script outputs.
//! Compiler executions use the physical fixture tree. Only explicit owned
//! prefixes are translated when exercising the pure canonical planner. This
//! is not evidence that a canonical namespace executed on this host.
#![cfg(target_os = "linux")]

use std::fs;
use std::io::Read;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use rabs_key::canonical::CanonicalEncoder;
use rabs_key::invocation::SourceInput;
use rabs_key::live_dependency::remote::{RUNTIME_COHORT_DOMAIN, remote_dependency_key};
use rabs_key::live_dependency::{
    DependencyActionPlan, DependencyDirectoryFact, DependencySourceKind, ExternFact,
    LiveRustcRequest, PlannedExtern, ToolchainFacts, canonical_cargo_dependency_key,
    live_dependency_key, plan_canonical_workspace_execution, plan_dependency_action,
    remote_workspace_execution_key, workspace_source_path,
};
use rabs_key::typed_digest::compute;
use rabs_protocol::descriptor::ActionClass;
use rabs_protocol::input_evidence::{
    ActionInputManifest, DirectoryEnumeration, INPUT_EVIDENCE_SCHEMA_VERSION, InputFileType,
    PositiveInput,
};
use rabs_protocol::raw_bytes::RawBytes;
use rabs_protocol::result_identity::{DigestAlgorithm, ObjectId, TypedDigest};

const MEMBER: &str = "workspace_member_fixture";
const LEAF: &str = "workspace_leaf_fixture";
const MEMBER_SOURCE: &str = r#"
#[cfg(not(feature = "fixture_feature"))]
compile_error!("the actual Cargo-selected feature must survive execution");
pub const PRIMARY: &str = env!("CARGO_PRIMARY_PACKAGE");
pub const SHARED: &str = include_str!("../../../shared/empty/../value.txt");
pub const BUILD_TOKEN: &str = env!("WORKSPACE_FIXTURE_BUILD_TOKEN");
include!(concat!(env!("OUT_DIR"), "/nested/empty/../value.rs"));
pub fn value() -> (&'static str, &'static str, &'static str, &'static str) {
    (SHARED, GENERATED, workspace_leaf_fixture::VALUE, BUILD_TOKEN)
}
"#;

// A transparent wrapper around Cargo's selected real compiler. No simulated
// compiler result or invented source/dependency graph enters this fixture.
const RECORDER: &str = r#"
use std::io::Write;
use std::os::unix::process::CommandExt;
use std::path::Path;
use std::process::Command;

fn fields(path: &Path, values: impl IntoIterator<Item = String>) {
    let mut bytes = Vec::new();
    for value in values {
        bytes.extend_from_slice(value.as_bytes());
        bytes.push(0);
    }
    std::fs::write(path, bytes).unwrap();
}

fn main() {
    let argv: Vec<_> = std::env::args().skip(1).collect();
    let mut compiler = Command::new(&argv[0]);
    compiler.args(&argv[1..]);
    let package = std::env::var("CARGO_PKG_NAME").unwrap_or_default();
    if !matches!(package.as_str(), "workspace_member_fixture" | "workspace_leaf_fixture")
        || std::env::var("CARGO_CRATE_NAME").is_ok_and(|name| name == "build_script_build")
    {
        panic!("compiler exec: {}", compiler.exec());
    }
    let root = std::path::PathBuf::from(std::env::var_os("RABS_WORKSPACE_RECORD").unwrap())
        .join(package);
    std::fs::create_dir_all(&root).unwrap();
    fields(&root.join("argv"), argv);
    fields(&root.join("env"), std::env::vars().flat_map(|(name, value)| [name, value]));
    std::fs::write(root.join("cwd"), std::env::current_dir().unwrap().to_str().unwrap()).unwrap();
    let output = compiler.output().unwrap();
    std::fs::write(root.join("stderr"), &output.stderr).unwrap();
    std::io::stdout().write_all(&output.stdout).unwrap();
    std::io::stderr().write_all(&output.stderr).unwrap();
    std::process::exit(output.status.code().unwrap_or(1));
}
"#;

fn checked(command: &mut Command) -> Output {
    let output = command.output().unwrap();
    assert!(
        output.status.success(),
        "{command:?} failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    output
}

fn assert_whole_empty_loader_path_has_no_current_directory_search(root: &Path) {
    let probe = root.join("loader-probe");
    fs::create_dir(&probe).unwrap();
    fs::write(
        probe.join("library.c"),
        "int rabs_empty_loader_value(void) { return 42; }\n",
    )
    .unwrap();
    fs::write(
        probe.join("main.c"),
        "extern int rabs_empty_loader_value(void);\nint main(void) { return rabs_empty_loader_value() == 42 ? 0 : 1; }\n",
    ).unwrap();
    let library = probe.join("librabs_empty_loader_probe.so");
    let executable = probe.join("probe");
    checked(
        Command::new("cc")
            .args(["-shared", "-fPIC"])
            .arg(probe.join("library.c"))
            .arg("-o")
            .arg(&library)
            .env_remove("LD_LIBRARY_PATH")
            .env_remove("LD_PRELOAD")
            .env_remove("LD_AUDIT")
            .env_remove("LD_RUN_PATH"),
    );
    checked(
        Command::new("cc")
            .arg(probe.join("main.c"))
            .arg(format!("-L{}", probe.display()))
            .arg("-lrabs_empty_loader_probe")
            .arg("-o")
            .arg(&executable)
            .env_remove("LD_LIBRARY_PATH")
            .env_remove("LD_PRELOAD")
            .env_remove("LD_AUDIT")
            .env_remove("LD_RUN_PATH"),
    );
    let run = |value: Option<&str>| {
        let mut command = Command::new(&executable);
        command
            .current_dir(&probe)
            .env_remove("LD_LIBRARY_PATH")
            .env_remove("LD_PRELOAD")
            .env_remove("LD_AUDIT");
        if let Some(value) = value {
            command.env("LD_LIBRARY_PATH", value);
        }
        command.output().unwrap()
    };
    let absent = run(None);
    let empty = run(Some(""));
    assert!(!absent.status.success());
    assert!(!empty.status.success());
    assert!(String::from_utf8_lossy(&absent.stderr).contains("librabs_empty_loader_probe.so"));
    assert_eq!(empty.stderr, absent.stderr);
    assert!(
        run(Some(":")).status.success(),
        "empty colon segments really search cwd"
    );
    assert!(run(Some(probe.to_str().unwrap())).status.success());
}

fn object_file(path: &Path) -> TypedDigest {
    use sha2::{Digest, Sha256};
    const DOMAIN: &str = "rabs.object.sha256.v1";
    let mut hash = Sha256::new();
    hash.update((DOMAIN.len() as u64).to_be_bytes());
    hash.update(DOMAIN.as_bytes());
    let mut file = fs::File::open(path).unwrap();
    let mut buffer = [0; 256 * 1024];
    loop {
        let count = file.read(&mut buffer).unwrap();
        if count == 0 {
            break;
        }
        hash.update(&buffer[..count]);
    }
    TypedDigest {
        algorithm: DigestAlgorithm::Sha256V1,
        domain: DOMAIN,
        bytes: hash.finalize().into(),
    }
}

fn toolchain_facts(root: &Path, verbose_version: String) -> ToolchainFacts {
    let mut runtime = Vec::new();
    for entry in fs::read_dir(root.join("lib")).unwrap() {
        let path = entry.unwrap().path();
        if path.file_name().unwrap().to_str().unwrap().contains(".so")
            && fs::symlink_metadata(&path).unwrap().is_file()
        {
            runtime.push(path);
        }
    }
    runtime.sort();
    let mut pending = vec![root.join("lib/rustlib")];
    let mut files = Vec::new();
    while let Some(directory) = pending.pop() {
        for entry in fs::read_dir(directory).unwrap() {
            let path = entry.unwrap().path();
            let metadata = fs::symlink_metadata(&path).unwrap();
            if metadata.is_dir() {
                pending.push(path);
            } else if metadata.is_file() {
                files.push((
                    path.strip_prefix(root)
                        .unwrap()
                        .to_str()
                        .unwrap()
                        .to_owned(),
                    object_file(&path),
                ));
            }
        }
    }
    files.sort_by(|a, b| a.0.cmp(&b.0));
    let mut encoder = CanonicalEncoder::new();
    encoder.u64(files.len() as u64);
    for (path, digest) in files {
        encoder.str(&path).str(digest.domain).bytes(&digest.bytes);
    }
    ToolchainFacts {
        compiler_binary_digest: object_file(&root.join("bin/rustc")),
        verbose_version,
        sysroot_root_digest: compute("rabs.live-dependency.sysroot-tree.v1", &encoder.finish()),
        runtime_libraries: runtime.iter().map(|path| object_file(path)).collect(),
    }
}

struct Layout {
    workspace: PathBuf,
    target: PathBuf,
    cargo_home: PathBuf,
    home: PathBuf,
    toolchain: PathBuf,
}

impl Layout {
    fn roots(&self) -> [(&Path, &str); 5] {
        [
            (&self.workspace, "/__rabs/workspace"),
            (&self.target, "/__rabs/out/cargo"),
            (&self.cargo_home, "/__rabs/cargo-home"),
            (&self.home, "/__rabs/home"),
            (&self.toolchain, "/__rabs/toolchain"),
        ]
    }

    fn canonical(&self, value: &str) -> String {
        self.roots()
            .into_iter()
            .fold(value.to_owned(), |value, (physical, logical)| {
                value.replace(physical.to_str().unwrap(), logical)
            })
    }

    fn physical(&self, value: &str) -> PathBuf {
        for (physical, logical) in self.roots() {
            if value == logical {
                return physical.to_owned();
            }
            if let Some(relative) = value.strip_prefix(&format!("{logical}/")) {
                return physical.join(relative);
            }
        }
        panic!("path is outside the fixture's explicit canonical mappings: {value}");
    }
}

struct Recorded {
    argv: Vec<String>,
    env: Vec<(String, String)>,
    cwd: String,
    stderr: Vec<u8>,
}

impl Recorded {
    fn load(root: &Path) -> Self {
        let fields = |name: &str| {
            fs::read_to_string(root.join(name))
                .unwrap()
                .split_terminator('\0')
                .map(str::to_owned)
                .collect::<Vec<_>>()
        };
        let environment = fields("env");
        let (pairs, remainder) = environment.as_chunks::<2>();
        assert!(remainder.is_empty());
        Self {
            argv: fields("argv"),
            env: pairs
                .iter()
                .map(|[name, value]| (name.clone(), value.clone()))
                .collect(),
            cwd: fs::read_to_string(root.join("cwd")).unwrap(),
            stderr: fs::read(root.join("stderr")).unwrap(),
        }
    }

    fn env(&self, name: &str) -> Option<&str> {
        self.env
            .iter()
            .find(|(key, _)| key == name)
            .map(|(_, value)| value.as_str())
    }

    fn canonical(&self, layout: &Layout) -> Self {
        Self {
            argv: self
                .argv
                .iter()
                .map(|value| layout.canonical(value))
                .collect(),
            env: self
                .env
                .iter()
                .map(|(name, value)| (name.clone(), layout.canonical(value)))
                .collect(),
            cwd: layout.canonical(&self.cwd),
            stderr: self.stderr.clone(),
        }
    }

    fn request(&self) -> LiveRustcRequest<'_> {
        LiveRustcRequest {
            argv: &self.argv,
            cwd: &self.cwd,
            env: &self.env,
        }
    }

    fn replay(&self, root: &Path, case: &str) -> Output {
        use std::io::Write;
        // Cargo's original jobserver FDs are closed after it returns. Supply
        // a real FIFO jobserver for this transport-only control, preserving
        // every semantic compiler argument and environment value.
        let fifo = root.join(format!("{case}.fifo"));
        checked(Command::new("mkfifo").arg(&fifo));
        let mut jobserver = fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(&fifo)
            .unwrap();
        jobserver.write_all(b"+").unwrap();
        let flags = format!("-j --jobserver-auth=fifo:{}", fifo.display());
        Command::new(&self.argv[0])
            .args(&self.argv[1..])
            .current_dir(&self.cwd)
            .env_clear()
            .envs(self.env.iter().map(|(name, value)| {
                (
                    name,
                    if matches!(name.as_str(), "CARGO_MAKEFLAGS" | "MAKEFLAGS" | "MFLAGS") {
                        flags.as_str()
                    } else {
                        value.as_str()
                    },
                )
            }))
            .output()
            .unwrap()
    }
}

fn input_tree(root: &Path, visible: &str, inputs: &mut ActionInputManifest) {
    let mut pending = vec![root.to_owned()];
    while let Some(directory) = pending.pop() {
        let relative = directory.strip_prefix(root).unwrap().to_str().unwrap();
        let mut entries = Vec::new();
        for entry in fs::read_dir(&directory).unwrap() {
            let entry = entry.unwrap();
            entries.push(RawBytes::new(entry.file_name().as_encoded_bytes().to_vec()));
            let path = entry.path();
            let metadata = fs::symlink_metadata(&path).unwrap();
            if metadata.is_dir() {
                pending.push(path);
            } else {
                assert!(
                    metadata.is_file(),
                    "only real regular fixture inputs are admitted"
                );
                inputs.inputs.push(PositiveInput {
                    virtual_path: RawBytes::new(
                        format!(
                            "{visible}/{}",
                            path.strip_prefix(root).unwrap().to_str().unwrap()
                        )
                        .into_bytes(),
                    ),
                    object: ObjectId(object_file(&path)),
                    file_type: InputFileType::Regular,
                    executable: metadata.permissions().mode() & 0o111 != 0,
                    symlink_resolution: Vec::new(),
                });
            }
        }
        entries.sort();
        inputs.directory_enumerations.push(DirectoryEnumeration {
            virtual_path: RawBytes::new(
                if relative.is_empty() {
                    visible.to_owned()
                } else {
                    format!("{visible}/{relative}")
                }
                .into_bytes(),
            ),
            entries,
        });
    }
}

fn observed_inputs(layout: &Layout, plan: &DependencyActionPlan) -> ActionInputManifest {
    let mut inputs = ActionInputManifest {
        schema_version: INPUT_EVIDENCE_SCHEMA_VERSION,
        ..ActionInputManifest::default()
    };
    input_tree(&layout.workspace, &plan.source_virtual_root(), &mut inputs);
    if let Some(root) = &plan.generated_root {
        input_tree(
            &layout.physical(root),
            &plan.generated_virtual_root(),
            &mut inputs,
        );
    }
    inputs
        .inputs
        .sort_by(|a, b| a.virtual_path.cmp(&b.virtual_path));
    inputs
        .directory_enumerations
        .sort_by(|a, b| a.virtual_path.cmp(&b.virtual_path));
    inputs
}

fn observed_directories(
    layout: &Layout,
    plan: &DependencyActionPlan,
) -> Vec<DependencyDirectoryFact> {
    plan.dependency_dirs
        .iter()
        .map(|directory| {
            let physical = layout.physical(directory);
            let mut artifacts = Vec::new();
            for entry in fs::read_dir(&physical).unwrap() {
                let path = entry.unwrap().path();
                let name = path.file_name().unwrap().to_str().unwrap();
                if !name.starts_with("lib")
                    || (directory == &plan.out_dir
                        && plan.output_names().iter().any(|output| output == name))
                {
                    continue;
                }
                assert!(fs::symlink_metadata(&path).unwrap().is_file());
                assert!(name.ends_with(".rmeta") || name.ends_with(".rlib"));
                // Match rustc's metadata-first candidate rule, while retaining an
                // explicitly selected rlib even beside a detached metadata file.
                let logical = format!("{directory}/{name}");
                let explicit = plan.externs.iter().any(|external| {
                matches!(external, PlannedExtern::File { path, .. } if path == &logical)
            });
                let shadowed = name.strip_suffix(".rlib").is_some_and(|stem| {
                    fs::metadata(physical.join(format!("{stem}.rmeta")))
                        .is_ok_and(|metadata| metadata.len() > 0)
                });
                if explicit || !shadowed {
                    artifacts.push(ExternFact {
                        path: logical,
                        content_digest: object_file(&path),
                    });
                }
            }
            artifacts.sort_by(|a, b| a.path.cmp(&b.path));
            DependencyDirectoryFact {
                path: directory.clone(),
                artifacts,
            }
        })
        .collect()
}

fn cargo(layout: &Layout, wrapper: &Path, record: &Path) -> Command {
    let mut cargo = Command::new(env!("CARGO"));
    cargo
        .current_dir(&layout.workspace)
        .env("HOME", &layout.home)
        .env("CARGO_HOME", &layout.cargo_home)
        .env("CARGO_INCREMENTAL", "0")
        .env("RUSTC", layout.toolchain.join("bin/rustc"))
        .env("RUSTC_WRAPPER", wrapper)
        .env("RABS_WORKSPACE_RECORD", record);
    for name in [
        "RUSTFLAGS",
        "CARGO_ENCODED_RUSTFLAGS",
        "RUSTC_WORKSPACE_WRAPPER",
        "CARGO_TARGET_DIR",
        "CARGO_BUILD_TARGET",
        "CARGO_PRIMARY_PACKAGE",
        "OUT_DIR",
        "WORKSPACE_FIXTURE_BUILD_TOKEN",
    ] {
        cargo.env_remove(name);
    }
    cargo
}

fn assert_selected_unit(
    graph: &serde_json::Value,
    layout: &Layout,
    plan: &DependencyActionPlan,
    mode: &str,
) {
    assert_eq!(graph["version"], 1);
    let source = workspace_source_path(plan).unwrap();
    let units = graph["units"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|unit| {
            unit["target"]["src_path"]
                .as_str()
                .is_some_and(|path| layout.canonical(path) == source)
                && unit["mode"] == mode
        })
        .collect::<Vec<_>>();
    assert_eq!(units.len(), 1, "one real Cargo-selected library unit");
    let unit = units[0];
    assert_eq!(unit["target"]["kind"], serde_json::json!(["lib"]));
    assert_eq!(
        unit["target"]["name"].as_str().unwrap().replace('-', "_"),
        plan.invocation.crate_name.as_deref().unwrap()
    );
    assert_eq!(
        unit["target"]["crate_types"],
        serde_json::json!(plan.invocation.crate_types)
    );
    assert!(
        unit["platform"].is_null(),
        "the fixture selects the host unit"
    );
    let package = unit["pkg_id"]
        .as_str()
        .unwrap()
        .strip_prefix("path+file://")
        .unwrap()
        .split_once('#')
        .unwrap()
        .0;
    assert_eq!(layout.canonical(package), plan.package_root);
    let mut expected_features = plan.invocation.features.clone();
    expected_features.sort();
    assert_eq!(unit["features"], serde_json::json!(expected_features));
}

#[test]
fn actual_cargo_workspace_units_preserve_execution_and_refuse_dependency_cache_authority() {
    let scratch = tempfile::tempdir().unwrap();
    let root = scratch.path();
    let workspace = root.join("workspace");
    let member = workspace.join("crates/member");
    let leaf = workspace.join("crates/leaf");
    let source = member.join("src/lib.rs");
    for directory in [
        member.join("src"),
        leaf.join("src"),
        workspace.join("shared/empty"),
        root.join("home"),
        root.join("cargo-home"),
    ] {
        fs::create_dir_all(directory).unwrap();
    }
    assert_whole_empty_loader_path_has_no_current_directory_search(root);
    fs::write(
        workspace.join("Cargo.toml"),
        r#"
[workspace]
members = ["crates/member", "crates/leaf"]
resolver = "2"
[workspace.lints.rust]
unused_variables = "deny"
"#,
    )
    .unwrap();
    fs::write(
        member.join("Cargo.toml"),
        r#"
[package]
name = "workspace_member_fixture"
version = "1.0.0"
edition = "2021"
[features]
default = ["fixture_feature"]
fixture_feature = []
[dependencies]
workspace_leaf_fixture = { path = "../leaf" }
[lints]
workspace = true
"#,
    )
    .unwrap();
    fs::write(
        leaf.join("Cargo.toml"),
        r#"
[package]
name = "workspace_leaf_fixture"
version = "1.0.0"
edition = "2021"
[lints]
workspace = true
"#,
    )
    .unwrap();
    fs::write(
        leaf.join("src/lib.rs"),
        "pub const VALUE: &str = \"real workspace dependency\";\n",
    )
    .unwrap();
    fs::write(&source, MEMBER_SOURCE).unwrap();
    fs::write(workspace.join("shared/value.txt"), "real sibling source").unwrap();
    fs::write(
        member.join("build.rs"),
        r#"
fn main() {
    let out = std::path::PathBuf::from(std::env::var_os("OUT_DIR").unwrap());
    std::fs::create_dir_all(out.join("nested/empty")).unwrap();
    std::fs::write(out.join("nested/value.rs"),
        "pub const GENERATED: &str = \"real generated value\";\n").unwrap();
    println!("cargo::rerun-if-changed=build.rs");
    println!("cargo::rustc-env=WORKSPACE_FIXTURE_BUILD_TOKEN=real-cargo-build-script");
}
"#,
    )
    .unwrap();
    let wrapper_source = root.join("recorder.rs");
    let wrapper = root.join("recorder");
    fs::write(&wrapper_source, RECORDER).unwrap();
    let sysroot =
        String::from_utf8(checked(Command::new("rustc").args(["--print", "sysroot"])).stdout)
            .unwrap();
    let toolchain = PathBuf::from(sysroot.trim());
    let compiler = toolchain.join("bin/rustc");
    checked(
        Command::new(&compiler)
            .args(["--edition=2021", "--crate-name", "recorder"])
            .arg(&wrapper_source)
            .arg("-o")
            .arg(&wrapper),
    );
    let verbose = String::from_utf8(checked(Command::new(&compiler).arg("-vV")).stdout).unwrap();
    let facts = toolchain_facts(&toolchain, verbose.trim_end().to_owned());
    let host = facts.host_triple().unwrap();
    // These pure-key test identities derive from real observed toolchain
    // bytes. They are not a claim that an uploaded dataset or a production
    // retained ELF runtime was independently validated by a remote worker.
    let mut runtime = CanonicalEncoder::new();
    for library in &facts.runtime_libraries {
        runtime.str(library.domain).bytes(&library.bytes);
    }
    let runtime = compute(RUNTIME_COHORT_DOMAIN, &runtime.finish());
    let retained = facts.sysroot_root_digest.bytes;

    for mode in ["check", "build"] {
        let record = root.join(format!("records-{mode}"));
        let layout = Layout {
            workspace: workspace.clone(),
            target: root.join(format!("target-{mode}")),
            cargo_home: root.join("cargo-home"),
            home: root.join("home"),
            toolchain: toolchain.clone(),
        };
        let metadata: serde_json::Value = serde_json::from_slice(
            &checked(
                cargo(&layout, &wrapper, &record)
                    .args(["metadata", "--offline", "--format-version=1"])
                    .env("CARGO_TARGET_DIR", &layout.target),
            )
            .stdout,
        )
        .unwrap();
        assert_eq!(metadata["workspace_root"], workspace.to_str().unwrap());
        for package in [MEMBER, LEAF] {
            let found = metadata["packages"]
                .as_array()
                .unwrap()
                .iter()
                .find(|row| row["name"] == package)
                .unwrap();
            assert!(found["source"].is_null());
            assert!(
                metadata["workspace_members"]
                    .as_array()
                    .unwrap()
                    .contains(&found["id"])
            );
        }
        let primary = metadata["packages"]
            .as_array()
            .unwrap()
            .iter()
            .find(|row| row["name"] == MEMBER)
            .unwrap();
        let node = metadata["resolve"]["nodes"]
            .as_array()
            .unwrap()
            .iter()
            .find(|row| row["id"] == primary["id"])
            .unwrap();
        assert!(
            node["deps"]
                .as_array()
                .unwrap()
                .iter()
                .any(|dependency| dependency["name"] == LEAF)
        );
        let selected_command = || {
            let mut command = cargo(&layout, &wrapper, &record);
            command
                .args([
                    mode,
                    "--offline",
                    "--locked",
                    "--jobs=1",
                    "--package",
                    MEMBER,
                    "--lib",
                    "--target-dir",
                ])
                .arg(&layout.target);
            command
        };
        let graph: serde_json::Value = serde_json::from_slice(
            &checked(selected_command().args(["--unit-graph", "-Z", "unstable-options"])).stdout,
        )
        .unwrap();
        checked(&mut selected_command());
        assert!(!workspace.join("target").exists());

        for (package, directory, is_primary) in [(LEAF, "leaf", false), (MEMBER, "member", true)] {
            let actual = Recorded::load(&record.join(package));
            assert_eq!(Path::new(&actual.cwd), workspace);
            assert_eq!(
                actual.env("CARGO_MANIFEST_DIR"),
                workspace.join(format!("crates/{directory}")).to_str()
            );
            assert_ne!(actual.env("CARGO_MANIFEST_DIR"), Some(actual.cwd.as_str()));
            assert_eq!(
                actual.env("CARGO_PRIMARY_PACKAGE"),
                is_primary.then_some("1")
            );
            let relative_source = format!("crates/{directory}/src/lib.rs");
            assert!(
                actual.argv.contains(&relative_source),
                "Cargo source spelling: {:?}",
                actual.argv
            );
            assert!(plan_dependency_action(actual.request(), host).is_err());
            let canonical = actual.canonical(&layout);
            let plan = plan_canonical_workspace_execution(canonical.request(), host)
                .unwrap_or_else(|error| {
                    panic!(
                        "real Cargo {mode} request refused: {error}; loader={:?}; physical_loader={:?}; {:#?}",
                        canonical.env("LD_LIBRARY_PATH"),
                        actual.env("LD_LIBRARY_PATH"),
                        canonical.argv
                    )
                });
            assert_eq!(
                plan.source_kind,
                DependencySourceKind::WorkspaceExecutionOnly
            );
            assert_eq!(plan.cwd, "/__rabs/workspace");
            assert_eq!(
                plan.package_root,
                format!("/__rabs/workspace/crates/{directory}")
            );
            assert_eq!(
                plan.invocation.source,
                Some(SourceInput::Path(relative_source.clone()))
            );
            assert_eq!(
                workspace_source_path(&plan).unwrap(),
                format!("/__rabs/workspace/{relative_source}")
            );
            assert_selected_unit(&graph, &layout, &plan, mode);
            assert!(
                plan.invocation
                    .lints
                    .iter()
                    .any(|lint| lint.name == "unused_variables" && lint.level == "deny")
            );
            let mut expected_env = canonical.env.clone();
            expected_env.sort();
            assert_eq!(plan.execution_env, expected_env);
            assert_eq!(
                plan.invocation.emit.iter().any(|kind| kind == "link"),
                mode == "build"
            );
            let inputs = observed_inputs(&layout, &plan);
            let directories = observed_directories(&layout, &plan);
            let externs = plan
                .externs
                .iter()
                .filter_map(|external| match external {
                    PlannedExtern::File { path, .. } => Some(ExternFact {
                        path: path.clone(),
                        content_digest: object_file(&layout.physical(path)),
                    }),
                    PlannedExtern::Toolchain { .. } => None,
                })
                .collect::<Vec<_>>();
            let script = plan.generated_root.as_ref().map(|generated| {
                fs::read(
                    layout
                        .physical(generated)
                        .parent()
                        .unwrap()
                        .join("run/stdout"),
                )
                .unwrap()
            });
            assert_eq!(script.is_some(), is_primary);
            let key = remote_workspace_execution_key(
                &plan,
                &facts,
                &directories,
                &inputs,
                script.as_deref(),
                "/__rabs/toolchain",
                &retained,
                &runtime,
            )
            .unwrap();
            assert_eq!(
                key.descriptor.action_class,
                ActionClass::RustcWorkspaceCompile
            );
            assert!(
                live_dependency_key(
                    &plan,
                    &facts,
                    &externs,
                    &directories,
                    script.as_deref(),
                    &inputs
                )
                .is_err()
            );
            assert!(
                canonical_cargo_dependency_key(
                    &plan,
                    &facts,
                    &externs,
                    &directories,
                    script.as_deref(),
                    &inputs
                )
                .is_err()
            );
            assert!(
                remote_dependency_key(
                    &plan,
                    &facts,
                    &directories,
                    &inputs,
                    script.as_deref(),
                    "/__rabs/toolchain",
                    &retained,
                    &runtime,
                )
                .is_err()
            );
            assert!(inputs.directory_enumerations.iter().any(|entry| {
                entry.virtual_path.as_bytes() == plan.input_virtual_path("shared/empty").as_bytes()
                    && entry.entries.is_empty()
            }));
            for output in plan.output_names() {
                assert!(layout.physical(&plan.out_dir).join(output).is_file());
            }
            if !is_primary {
                continue;
            }
            assert_eq!(
                actual.env("WORKSPACE_FIXTURE_BUILD_TOKEN"),
                Some("real-cargo-build-script")
            );
            let generated = PathBuf::from(actual.env("OUT_DIR").unwrap());
            assert!(generated.join("nested/empty").is_dir());
            let mut missing = inputs.clone();
            missing.directory_enumerations.retain(|entry| {
                entry.virtual_path.as_bytes() != plan.input_virtual_path("shared/empty").as_bytes()
            });
            assert!(
                remote_workspace_execution_key(
                    &plan,
                    &facts,
                    &directories,
                    &missing,
                    script.as_deref(),
                    "/__rabs/toolchain",
                    &retained,
                    &runtime,
                )
                .is_err(),
                "a partial source directory inventory is not execution authority"
            );
            let success = actual.replay(root, &format!("{mode}-complete"));
            assert!(
                success.status.success(),
                "{}",
                String::from_utf8_lossy(&success.stderr)
            );
            assert_eq!(
                success.stderr, actual.stderr,
                "real compiler diagnostics remain byte-preserving"
            );

            let empty = workspace.join("shared/empty");
            let parked = root.join(format!("{mode}-parked-source-directory"));
            fs::rename(&empty, &parked).unwrap();
            assert!(
                !actual
                    .replay(root, &format!("{mode}-missing-source-directory"))
                    .status
                    .success()
            );
            fs::rename(parked, empty).unwrap();
            let empty = generated.join("nested/empty");
            let parked = root.join(format!("{mode}-parked-generated-directory"));
            fs::rename(&empty, &parked).unwrap();
            assert!(
                !actual
                    .replay(root, &format!("{mode}-missing-generated-directory"))
                    .status
                    .success()
            );
            fs::rename(parked, empty).unwrap();
            fs::write(
                &source,
                format!("{MEMBER_SOURCE}\npub fn lint_guard() {{ let unused_guard = 1; }}\n"),
            )
            .unwrap();
            let rejected = actual.replay(root, &format!("{mode}-lint-policy"));
            assert!(!rejected.status.success());
            assert!(String::from_utf8_lossy(&rejected.stderr).contains("unused_guard"));
            fs::write(&source, MEMBER_SOURCE).unwrap();
        }
    }
}
