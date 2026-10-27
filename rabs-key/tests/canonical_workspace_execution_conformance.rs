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
#[cfg(feature = "native_fixture")]
extern "C" { fn rabs_workspace_native_answer() -> u32; }
#[cfg(feature = "native_fixture")]
pub fn native_answer() -> u32 { unsafe { rabs_workspace_native_answer() } }
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
    let mut root = std::path::PathBuf::from(std::env::var_os("RABS_WORKSPACE_RECORD").unwrap())
        .join(package);
    if std::env::var_os("RABS_WORKSPACE_RECORD_ALL").is_some() {
        root = root.join(format!("unit-{}", std::process::id()));
    }
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
        // `cargo test` adds the outer test target directory to this loader
        // path. It is not part of the nested fixture's toolchain or inputs;
        // let the nested Cargo invocation construct its own compiler path.
        "LD_LIBRARY_PATH",
        "RUSTC_WORKSPACE_WRAPPER",
        "CARGO_TARGET_DIR",
        "CARGO_BUILD_TARGET",
        "CARGO_PRIMARY_PACKAGE",
        "OUT_DIR",
        "WORKSPACE_FIXTURE_BUILD_TOKEN",
        "RABS_WORKSPACE_RECORD_ALL",
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

fn actual_all_target_metadata_units(
    root: &Path,
    workspace: &Path,
    wrapper: &Path,
    toolchain: &Path,
    facts: &ToolchainFacts,
    runtime: &TypedDigest,
) {
    use std::collections::BTreeMap;

    let record = root.join("records-all-targets");
    let layout = Layout {
        workspace: workspace.to_owned(),
        target: root.join("target-all-targets"),
        cargo_home: root.join("cargo-home"),
        home: root.join("home"),
        toolchain: toolchain.to_owned(),
    };
    let selected_command = || {
        let mut command = cargo(&layout, wrapper, &record);
        command
            .args([
                "check",
                "--offline",
                "--locked",
                "--jobs=1",
                "--package",
                MEMBER,
                "--all-targets",
                "--target-dir",
            ])
            .arg(&layout.target)
            .env("RABS_WORKSPACE_RECORD_ALL", "1");
        command
    };
    let graph: serde_json::Value = serde_json::from_slice(
        &checked(selected_command().args(["--unit-graph", "-Z", "unstable-options"])).stdout,
    )
    .unwrap();
    checked(&mut selected_command());
    let host = facts.host_triple().unwrap();
    let mut recordings = BTreeMap::new();
    for entry in fs::read_dir(record.join(MEMBER)).unwrap() {
        let actual = Recorded::load(&entry.unwrap().path());
        let canonical = actual.canonical(&layout);
        let plan =
            plan_canonical_workspace_execution(canonical.request(), host).unwrap_or_else(|error| {
                panic!(
                    "real Cargo all-target metadata request refused: {error}; {:#?}",
                    canonical.argv
                )
            });
        let Some(SourceInput::Path(source)) = &plan.invocation.source else {
            panic!("real Cargo target must have a source path");
        };
        let harness = actual.argv.iter().any(|argument| argument == "--test");
        assert!(
            recordings
                .insert((source.clone(), harness), (actual, canonical, plan))
                .is_none()
        );
    }
    let expected = [
        ("src/lib.rs", "lib", false, None, false),
        ("src/lib.rs", "lib", true, None, false),
        (
            "src/main.rs",
            "bin",
            false,
            Some("workspace-member-bin"),
            false,
        ),
        (
            "src/main.rs",
            "bin",
            true,
            Some("workspace-member-bin"),
            false,
        ),
        (
            "examples/example.rs",
            "example",
            false,
            Some("workspace-member-example"),
            false,
        ),
        ("tests/integration.rs", "test", true, None, false),
        ("tests/custom.rs", "test", false, None, true),
        ("benches/bench.rs", "bench", true, None, false),
        ("benches/custom.rs", "bench", false, None, true),
    ];
    assert_eq!(
        recordings.len(),
        expected.len(),
        "every selected target must really compile"
    );
    let mut keys = BTreeMap::new();
    for (index, (relative, target_kind, harness, binary_name, custom)) in
        expected.into_iter().enumerate()
    {
        let source = format!("crates/member/{relative}");
        let (actual, canonical, plan) = recordings.remove(&(source.clone(), harness)).unwrap();
        assert_eq!(Path::new(&actual.cwd), workspace);
        assert_eq!(
            actual.env("CARGO_MANIFEST_DIR"),
            workspace.join("crates/member").to_str()
        );
        assert_ne!(actual.env("CARGO_MANIFEST_DIR"), Some(actual.cwd.as_str()));
        assert_eq!(actual.env("CARGO_PRIMARY_PACKAGE"), Some("1"));
        assert_eq!(actual.env("CARGO_BIN_NAME"), binary_name);
        assert_eq!(
            actual.env("WORKSPACE_FIXTURE_BUILD_TOKEN"),
            Some("real-cargo-build-script")
        );
        assert!(actual.argv.contains(&source));
        assert_eq!(
            plan.source_kind,
            DependencySourceKind::WorkspaceExecutionOnly
        );
        assert_eq!(plan.cwd, "/__rabs/workspace");
        assert_eq!(plan.package_root, "/__rabs/workspace/crates/member");
        assert_eq!(
            plan.invocation
                .passthrough
                .iter()
                .any(|argument| argument == "--test"),
            harness
        );
        assert_eq!(plan.invocation.cfgs.iter().any(|cfg| cfg == "test"), custom);
        if harness || custom {
            assert!(
                plan.invocation.crate_types.is_empty(),
                "Cargo relies on the actual implicit binary/harness shape"
            );
        } else {
            assert_eq!(
                plan.invocation.crate_types,
                [if target_kind == "lib" { "lib" } else { "bin" }]
            );
        }
        let mut emits = plan.invocation.emit.clone();
        emits.sort();
        assert_eq!(emits, ["dep-info", "metadata"]);
        let mut expected_environment = canonical.env.clone();
        expected_environment.sort();
        assert_eq!(plan.execution_env, expected_environment);
        assert!(
            plan.invocation
                .lints
                .iter()
                .any(|lint| lint.name == "unused_variables" && lint.level == "deny")
        );
        assert!(plan_dependency_action(actual.request(), host).is_err());

        let resolved_source = workspace_source_path(&plan).unwrap();
        let units = graph["units"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|unit| {
                unit["mode"] == "check"
                    && unit["target"]["src_path"]
                        .as_str()
                        .is_some_and(|path| layout.canonical(path) == resolved_source)
            })
            .collect::<Vec<_>>();
        assert!(
            !units.is_empty(),
            "the actual Cargo graph must retain this source family"
        );
        for unit in &units {
            assert_eq!(unit["target"]["kind"], serde_json::json!([target_kind]));
            assert_eq!(
                unit["target"]["crate_types"],
                serde_json::json!([if target_kind == "lib" { "lib" } else { "bin" }])
            );
            assert_eq!(
                unit["target"]["name"].as_str().unwrap().replace('-', "_"),
                plan.invocation.crate_name.as_deref().unwrap()
            );
            assert!(unit["platform"].is_null());
            let mut features = plan.invocation.features.clone();
            features.sort();
            assert_eq!(unit["features"], serde_json::json!(features));
            let package = unit["pkg_id"]
                .as_str()
                .unwrap()
                .strip_prefix("path+file://")
                .unwrap()
                .split_once('#')
                .unwrap()
                .0;
            assert_eq!(layout.canonical(package), plan.package_root);
            assert!(unit["profile"].get("test").is_none());
            assert!(unit["target"].get("harness").is_none());
        }
        if matches!(relative, "src/lib.rs" | "src/main.rs") {
            assert_eq!(units.len(), 2);
            assert_eq!(
                units[0], units[1],
                "pinned Cargo does not serialize the normal versus --test discriminator; selected-family membership must not invent it"
            );
        } else {
            assert_eq!(units.len(), 1);
        }

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
        let generated = plan.generated_root.as_deref().unwrap();
        let script = fs::read(
            layout
                .physical(generated)
                .parent()
                .unwrap()
                .join("run/stdout"),
        )
        .unwrap();
        let key = remote_workspace_execution_key(
            &plan,
            facts,
            &directories,
            &inputs,
            Some(&script),
            "/__rabs/toolchain",
            &facts.sysroot_root_digest.bytes,
            runtime,
        )
        .unwrap();
        assert_eq!(
            key.descriptor.action_class,
            ActionClass::RustcWorkspaceCompile
        );
        assert!(
            live_dependency_key(&plan, facts, &externs, &directories, Some(&script), &inputs)
                .is_err()
        );
        assert!(
            canonical_cargo_dependency_key(
                &plan,
                facts,
                &externs,
                &directories,
                Some(&script),
                &inputs
            )
            .is_err()
        );
        assert!(
            remote_dependency_key(
                &plan,
                facts,
                &directories,
                &inputs,
                Some(&script),
                "/__rabs/toolchain",
                &facts.sysroot_root_digest.bytes,
                runtime
            )
            .is_err()
        );
        keys.insert((source.clone(), harness), key.action_key);

        let output_names = plan.output_names();
        assert_eq!(output_names.len(), 2);
        let metadata = output_names
            .iter()
            .find(|name| name.ends_with(".rmeta"))
            .unwrap();
        let dep_info = output_names
            .iter()
            .find(|name| name.ends_with(".d"))
            .unwrap();
        let output_root = layout.physical(&plan.out_dir);
        let metadata_size = fs::metadata(output_root.join(metadata)).unwrap().len();
        if target_kind == "lib" && !harness {
            assert!(metadata_size > 0);
        } else {
            assert_eq!(
                metadata_size, 0,
                "successful binary/harness checking emits an empty metadata file"
            );
        }
        assert!(fs::metadata(output_root.join(dep_info)).unwrap().len() > 0);
        let mut actual_names = fs::read_dir(&output_root)
            .unwrap()
            .map(|entry| entry.unwrap().file_name().into_string().unwrap())
            .collect::<Vec<_>>();
        actual_names.sort();
        assert_eq!(
            actual_names, output_names,
            "metadata checking produces no executable or archive"
        );
        let mut metadata_announced = false;
        for line in actual
            .stderr
            .split(|byte| *byte == b'\n')
            .filter(|line| !line.is_empty())
        {
            let message: serde_json::Value = serde_json::from_slice(line).unwrap();
            if let Some(path) = message["artifact"].as_str() {
                let name = Path::new(path)
                    .strip_prefix(&output_root)
                    .unwrap()
                    .to_str()
                    .unwrap();
                assert!(output_names.iter().any(|expected| expected == name));
                if message["emit"] == "metadata" {
                    assert_eq!(name, metadata);
                    metadata_announced = true;
                }
            }
        }
        assert!(
            metadata_announced,
            "rustc announces even the empty metadata artifact"
        );
        let replay = actual.replay(root, &format!("all-targets-{index}-complete"));
        assert!(
            replay.status.success(),
            "{}",
            String::from_utf8_lossy(&replay.stderr)
        );
        assert_eq!(
            replay.stderr, actual.stderr,
            "metadata and harness diagnostics remain byte-preserving"
        );

        if target_kind != "lib" || harness {
            let mut linked_argv = canonical.argv.clone();
            let emit = linked_argv
                .iter_mut()
                .find(|argument| argument.starts_with("--emit="))
                .unwrap();
            *emit = "--emit=dep-info,link".into();
            assert!(
                plan_canonical_workspace_execution(
                    LiveRustcRequest {
                        argv: &linked_argv,
                        cwd: &canonical.cwd,
                        env: &canonical.env
                    },
                    host
                )
                .is_err(),
                "execution-only metadata admission must not authorize linking or test execution"
            );
        }
        let original = fs::read(workspace.join(&source)).unwrap();
        let mut denied = original.clone();
        denied.extend_from_slice(
            b"\npub fn all_target_lint_guard() { let unused_metadata_guard = 1; }\n",
        );
        fs::write(workspace.join(&source), denied).unwrap();
        let refused = actual.replay(root, &format!("all-targets-{index}-lint-policy"));
        fs::write(workspace.join(&source), original).unwrap();
        assert!(!refused.status.success());
        assert!(String::from_utf8_lossy(&refused.stderr).contains("unused_metadata_guard"));
        // A rejected compiler may retire its previous output. Restore the real
        // successful artifact before replaying a later target that depends on
        // this unit; no hand-written metadata substitutes for that execution.
        let restored = actual.replay(root, &format!("all-targets-{index}-restored"));
        assert!(
            restored.status.success(),
            "{}",
            String::from_utf8_lossy(&restored.stderr)
        );
        assert_eq!(restored.stderr, actual.stderr);
    }
    for source in ["crates/member/src/lib.rs", "crates/member/src/main.rs"] {
        assert_ne!(
            keys[&(source.to_owned(), false)],
            keys[&(source.to_owned(), true)],
            "normal and --test invocations retain distinct exact execution identities"
        );
    }
}

fn actual_native_workspace_archive(
    root: &Path,
    workspace: &Path,
    wrapper: &Path,
    toolchain: &Path,
    facts: &ToolchainFacts,
    runtime: &TypedDigest,
) {
    let record = root.join("records-native");
    let layout = Layout {
        workspace: workspace.to_owned(),
        target: root.join("target-native"),
        cargo_home: root.join("cargo-home"),
        home: root.join("home"),
        toolchain: toolchain.to_owned(),
    };
    let selected_command = || {
        let mut command = cargo(&layout, wrapper, &record);
        command
            .args([
                "build",
                "--offline",
                "--locked",
                "--jobs=1",
                "--package",
                MEMBER,
                "--lib",
                "--features=native_fixture",
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
    let actual = Recorded::load(&record.join(MEMBER));
    let canonical = actual.canonical(&layout);
    let plan =
        plan_canonical_workspace_execution(canonical.request(), facts.host_triple().unwrap())
            .unwrap_or_else(|error| {
                panic!(
                    "actual Cargo native workspace request refused: {error}; {:?}",
                    canonical.argv
                )
            });
    assert_selected_unit(&graph, &layout, &plan, "build");
    assert_eq!(
        plan.source_kind,
        DependencySourceKind::WorkspaceExecutionOnly
    );
    assert_eq!(
        plan.invocation.native_libs,
        ["static=rabs_workspace_answer"]
    );
    let generated = plan.generated_root.as_ref().unwrap();
    let native_root = format!("{generated}/native");
    assert!(
        plan.invocation
            .lib_search
            .contains(&format!("native={native_root}"))
    );
    assert!(
        plan.dependency_dirs
            .iter()
            .all(|directory| directory != &native_root)
    );
    let physical_generated = layout.physical(generated);
    let archive = physical_generated.join("native/librabs_workspace_answer.a");
    let archive_virtual = plan.generated_input_virtual_path("native/librabs_workspace_answer.a");
    let directory_virtual = plan.generated_input_virtual_path("native");
    // The real build script ran at physical fixture paths. Translate only the
    // fixture's owned prefixes for the pure canonical key, just as for argv/env.
    let script = layout.canonical(
        &fs::read_to_string(physical_generated.parent().unwrap().join("run/stdout")).unwrap(),
    );
    assert!(script.contains(&format!("cargo::rustc-link-search=native={native_root}")));
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
    let key = |candidate: &DependencyActionPlan, inputs: &ActionInputManifest| {
        remote_workspace_execution_key(
            candidate,
            facts,
            &directories,
            inputs,
            Some(script.as_bytes()),
            "/__rabs/toolchain",
            &facts.sysroot_root_digest.bytes,
            runtime,
        )
    };
    let physical_output = layout.physical(&plan.out_dir);
    let output = |suffix: &str| {
        physical_output.join(
            plan.output_names()
                .into_iter()
                .find(|name| name.ends_with(suffix))
                .unwrap(),
        )
    };
    let mut previous: Option<(ActionInputManifest, Vec<u8>, Vec<u8>, TypedDigest)> = None;
    for answer in [37, 41] {
        if answer == 41 {
            // Rebuild outside every captured source/generated root, then replace
            // only the static archive. This isolates archive-byte identity from
            // source edits or stale intermediate C/object files in OUT_DIR.
            let source = root.join("native-next.c");
            let object = root.join("native-next.o");
            let replacement = root.join("native-next.a");
            fs::write(
                &source,
                "unsigned int rabs_workspace_native_answer(void) { return 41; }\n",
            )
            .unwrap();
            checked(
                Command::new("cc")
                    .args(["-c", "-fPIC", "-o"])
                    .arg(&object)
                    .arg(&source),
            );
            checked(
                Command::new("ar")
                    .arg("crsD")
                    .arg(&replacement)
                    .arg(&object),
            );
            fs::copy(replacement, &archive).unwrap();
        }
        let inputs = observed_inputs(&layout, &plan);
        let identity = key(&plan, &inputs).unwrap();
        let replay = actual.replay(root, &format!("native-{answer}"));
        assert!(
            replay.status.success(),
            "{}",
            String::from_utf8_lossy(&replay.stderr)
        );
        let dep_info = fs::read(output(".d")).unwrap();
        let rlib = fs::read(output(".rlib")).unwrap();
        assert!(
            !String::from_utf8_lossy(&dep_info).contains("librabs_workspace_answer.a"),
            "the oracle must cover a real native read absent from rustc dep-info"
        );
        if let Some((old_inputs, old_dep_info, old_rlib, old_key)) = &previous {
            assert_eq!(
                inputs.directory_enumerations,
                old_inputs.directory_enumerations
            );
            let changed = inputs
                .inputs
                .iter()
                .zip(&old_inputs.inputs)
                .filter(|(current, old)| current != old)
                .map(|(current, old)| {
                    assert_eq!(current.virtual_path, old.virtual_path);
                    current.virtual_path.as_bytes()
                })
                .collect::<Vec<_>>();
            assert_eq!(
                changed,
                [archive_virtual.as_bytes()],
                "only the retained archive changed"
            );
            assert_eq!(
                &dep_info, old_dep_info,
                "dep-info does not close native archive reads"
            );
            assert_ne!(&rlib, old_rlib, "real bundled object bytes must change");
            assert_ne!(
                &identity.action_key, old_key,
                "archive bytes must bind fresh execution identity"
            );
        }
        assert!(
            live_dependency_key(
                &plan,
                facts,
                &externs,
                &directories,
                Some(script.as_bytes()),
                &inputs
            )
            .is_err()
        );
        assert!(
            canonical_cargo_dependency_key(
                &plan,
                facts,
                &externs,
                &directories,
                Some(script.as_bytes()),
                &inputs
            )
            .is_err()
        );
        assert!(
            remote_dependency_key(
                &plan,
                facts,
                &directories,
                &inputs,
                Some(script.as_bytes()),
                "/__rabs/toolchain",
                &facts.sysroot_root_digest.bytes,
                runtime
            )
            .is_err()
        );

        let mut missing = inputs.clone();
        missing
            .inputs
            .retain(|input| input.virtual_path.as_bytes() != archive_virtual.as_bytes());
        missing
            .directory_enumerations
            .iter_mut()
            .find(|entry| entry.virtual_path.as_bytes() == directory_virtual.as_bytes())
            .unwrap()
            .entries
            .retain(|entry| entry.as_bytes() != b"librabs_workspace_answer.a");
        assert!(
            key(&plan, &missing).is_err(),
            "a complete tree without the selected archive must refuse"
        );
        let mut missing_tree = inputs.clone();
        missing_tree
            .directory_enumerations
            .retain(|entry| entry.virtual_path.as_bytes() != directory_virtual.as_bytes());
        assert!(
            key(&plan, &missing_tree).is_err(),
            "native lookup requires retained directory evidence"
        );
        let mut foreign = plan.clone();
        *foreign
            .invocation
            .lib_search
            .iter_mut()
            .find(|path| path.starts_with("native="))
            .unwrap() = "native=/__rabs/out/cargo/debug/build/other-package/out/native".into();
        assert!(
            key(&foreign, &inputs).is_err(),
            "another package's OUT_DIR is not owned by this request"
        );
        let mut metadata = plan.clone();
        metadata.invocation.emit = vec!["dep-info".into(), "metadata".into()];
        metadata.outputs = rabs_key::output_derivation::derive_workspace_output_declarations(
            &metadata.invocation,
            &metadata.host_triple,
        )
        .unwrap();
        assert!(
            key(&metadata, &inputs).is_err(),
            "native inputs cannot use metadata isolation"
        );

        let main = root.join(format!("native-main-{answer}.rs"));
        let binary = root.join(format!("native-linked-{answer}"));
        fs::write(&main, format!("fn main() {{ let answer = workspace_member_fixture::native_answer(); assert_eq!(answer, {answer}); println!(\"{{answer}}\"); }}\n")).unwrap();
        let mut link = Command::new(toolchain.join("bin/rustc"));
        link.arg(&main)
            .args(["--edition=2021", "--crate-name=native_behavior", "--extern"])
            .arg(format!("{MEMBER}={}", output(".rmeta").display()))
            .arg("--extern")
            .arg(format!("{MEMBER}={}", output(".rlib").display()))
            .arg(format!("-Ldependency={}", physical_output.display()))
            .arg("-o")
            .arg(&binary);
        for directory in &plan.dependency_dirs {
            link.arg(format!(
                "-Ldependency={}",
                layout.physical(directory).display()
            ));
        }
        // Cargo emits detached metadata: pass both the complete rmeta and
        // its corresponding rlib for final linking, exactly as a downstream Rust
        // consumer must. No native search path is supplied, so the workspace
        // rlib must really contain the retained archive's object bytes.
        checked(&mut link);
        assert_eq!(
            checked(&mut Command::new(&binary)).stdout,
            format!("{answer}\n").as_bytes()
        );
        previous = Some((inputs, dep_info, rlib, identity.action_key));
    }
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
native_fixture = []
[dependencies]
workspace_leaf_fixture = { path = "../leaf" }
[lints]
workspace = true

[[bin]]
name = "workspace-member-bin"
path = "src/main.rs"

[[example]]
name = "workspace-member-example"
path = "examples/example.rs"

[[test]]
name = "workspace-member-integration"
path = "tests/integration.rs"

[[test]]
name = "workspace-member-custom-test"
path = "tests/custom.rs"
harness = false

[[bench]]
name = "workspace-member-bench"
path = "benches/bench.rs"

[[bench]]
name = "workspace-member-custom-bench"
path = "benches/custom.rs"
harness = false
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
    for (path, custom, named_binary) in [
        ("src/main.rs", false, true),
        ("examples/example.rs", false, true),
        ("tests/integration.rs", false, false),
        ("tests/custom.rs", true, false),
        ("benches/bench.rs", false, false),
        ("benches/custom.rs", true, false),
    ] {
        let path = member.join(path);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        let mut bytes = MEMBER_SOURCE.to_owned();
        if named_binary {
            bytes.push_str("\nconst _: &str = env!(\"CARGO_BIN_NAME\");\n");
        }
        if custom {
            bytes.push_str(
                "\n#[cfg(not(test))]\ncompile_error!(\"custom harness check lost cfg(test)\");\n",
            );
        }
        if named_binary || custom {
            bytes.push_str("\nfn main() { panic!(\"metadata compilation must never execute this target\"); }\n");
        }
        bytes.push_str("\n#[test]\nfn metadata_only_test() { panic!(\"cargo check must never execute a test\"); }\n");
        fs::write(path, bytes).unwrap();
    }
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
    if std::env::var_os("CARGO_FEATURE_NATIVE_FIXTURE").is_some() {
        let native = out.join("native");
        std::fs::create_dir(&native).unwrap();
        let source = native.join("answer.c");
        let object = native.join("answer.o");
        let archive = native.join("librabs_workspace_answer.a");
        std::fs::write(&source, "unsigned int rabs_workspace_native_answer(void) { return 37; }\n").unwrap();
        assert!(std::process::Command::new("cc").args(["-c", "-fPIC", "-o"])
            .arg(&object).arg(&source).status().unwrap().success());
        assert!(std::process::Command::new("ar").arg("crsD")
            .arg(&archive).arg(&object).status().unwrap().success());
        println!("cargo::rustc-link-search=native={}", native.display());
        println!("cargo::rustc-link-lib=static=rabs_workspace_answer");
    }
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
    actual_all_target_metadata_units(root, &workspace, &wrapper, &toolchain, &facts, &runtime);
    actual_native_workspace_archive(root, &workspace, &wrapper, &toolchain, &facts, &runtime);
}
