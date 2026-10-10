//! Real Cargo/Git/rustc conformance for the live Git dependency class.
//! Cargo fetches a local repository at an actual commit, selects a nested
//! workspace member, and supplies the compiler requests used by the planner.
//! This checks output and closure semantics; daemon serving is exercised by
//! rabs-wrap's separate live-dependency end-to-end suite.
#![cfg(target_os = "linux")]

use std::path::Path;
use std::process::{Command, Output};

use rabs_key::live_dependency::{
    DependencyActionPlan, DependencyDirectoryFact, DependencySourceKind, ExternFact,
    LiveRustcRequest, PlannedExtern, ToolchainFacts, canonicalize_out_dir, canonicalize_placements,
    dep_info_closure_violation, live_dependency_key, plan_dependency_action, render_out_dir,
    render_placements,
};

// A transparent recorder around the actual compiler Cargo selected. The
// compiler executes normally; its argv, cwd, environment and stderr are
// recorded verbatim. No simulated compiler or cache result enters this test.
const RECORDING_WRAPPER: &str = r#"
use std::io::Write;
use std::os::unix::process::CommandExt;
use std::path::PathBuf;
use std::process::Command;

fn fields(path: PathBuf, values: impl IntoIterator<Item = String>) {
    let mut bytes = Vec::new();
    for value in values {
        bytes.extend_from_slice(value.as_bytes());
        bytes.push(0);
    }
    std::fs::write(path, bytes).unwrap();
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let mut compiler = Command::new(&args[0]);
    compiler.args(&args[1..]);
    let package = std::env::var("CARGO_PKG_NAME").unwrap_or_default();
    if !matches!(package.as_str(), "git_fixture" | "chain_leaf" | "chain_middle" | "generated_fixture")
        || std::env::var("CARGO_CRATE_NAME").is_ok_and(|name| name == "build_script_build") {
        panic!("compiler exec: {}", compiler.exec());
    }
    let record = PathBuf::from(std::env::var_os("RABS_TEST_RECORD").unwrap());
    let record = if package == "git_fixture" { record } else { record.join(package) };
    std::fs::create_dir_all(&record).unwrap();
    fields(record.join("argv"), args);
    fields(record.join("env"), std::env::vars().flat_map(|(name, value)| [name, value]));
    std::fs::write(record.join("cwd"), std::env::current_dir().unwrap().to_str().unwrap()).unwrap();
    let output = compiler.output().unwrap();
    std::fs::write(record.join("stderr"), &output.stderr).unwrap();
    std::io::stdout().write_all(&output.stdout).unwrap();
    std::io::stderr().write_all(&output.stderr).unwrap();
    std::process::exit(output.status.code().unwrap_or(1));
}
"#;

// Real bytes, using the CAS object-domain framing. This test-only observer
// deliberately has no dependency on the daemon or its async runtime.
fn object_file(path: &Path) -> rabs_protocol::result_identity::TypedDigest {
    use sha2::{Digest, Sha256};
    use std::io::Read;
    const DOMAIN: &str = "rabs.object.sha256.v1";
    let mut hasher = Sha256::new();
    hasher.update((DOMAIN.len() as u64).to_be_bytes());
    hasher.update(DOMAIN.as_bytes());
    let mut file = std::fs::File::open(path).unwrap();
    let mut buffer = vec![0; 256 * 1024];
    loop {
        let count = file.read(&mut buffer).unwrap();
        if count == 0 {
            break;
        }
        hasher.update(&buffer[..count]);
    }
    rabs_protocol::result_identity::TypedDigest {
        algorithm: rabs_protocol::result_identity::DigestAlgorithm::Sha256V1,
        domain: DOMAIN,
        bytes: hasher.finalize().into(),
    }
}

fn real_toolchain(plan: &DependencyActionPlan) -> ToolchainFacts {
    use rabs_key::canonical::CanonicalEncoder;
    let compiler = Path::new(&plan.compiler);
    let sysroot = compiler.parent().unwrap().parent().unwrap();
    let run = |args: &[&str]| {
        checked(
            Command::new(compiler)
                .args(args)
                .env_clear()
                .envs(plan.execution_env.iter().map(|(name, value)| (name, value))),
        )
    };
    assert_eq!(
        String::from_utf8(run(&["--print", "sysroot"]).stdout)
            .unwrap()
            .trim(),
        sysroot.to_str().unwrap()
    );
    let verbose_version = String::from_utf8(run(&["-vV"]).stdout)
        .unwrap()
        .trim_end()
        .to_owned();
    let mut runtime_paths: Vec<_> = std::fs::read_dir(sysroot.join("lib"))
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .filter(|path| {
            path.file_name().unwrap().to_str().unwrap().contains(".so")
                && std::fs::symlink_metadata(path).unwrap().is_file()
        })
        .collect();
    runtime_paths.sort();
    let mut pending: Vec<_> = std::fs::read_dir(sysroot.join("lib/rustlib"))
        .unwrap()
        .map(|entry| entry.unwrap().path().join("lib"))
        .filter(|path| path.is_dir())
        .collect();
    let mut tree = Vec::new();
    while let Some(directory) = pending.pop() {
        for entry in std::fs::read_dir(directory).unwrap() {
            let path = entry.unwrap().path();
            let meta = std::fs::symlink_metadata(&path).unwrap();
            if meta.is_dir() {
                pending.push(path);
            } else if meta.is_file() {
                tree.push((
                    path.strip_prefix(sysroot)
                        .unwrap()
                        .to_str()
                        .unwrap()
                        .to_owned(),
                    object_file(&path),
                ));
            }
        }
    }
    tree.sort_by(|a, b| a.0.cmp(&b.0));
    let mut enc = CanonicalEncoder::new();
    enc.u64(tree.len() as u64);
    for (path, digest) in tree {
        enc.str(&path).str(digest.domain).bytes(&digest.bytes);
    }
    ToolchainFacts {
        compiler_binary_digest: object_file(compiler),
        verbose_version,
        sysroot_root_digest: rabs_key::typed_digest::compute(
            "rabs.live-dependency.sysroot-tree.v1",
            &enc.finish(),
        ),
        runtime_libraries: runtime_paths.iter().map(|path| object_file(path)).collect(),
    }
}

fn try_actual_key(
    plan: &DependencyActionPlan,
    toolchain: &ToolchainFacts,
) -> Result<rabs_key::live_dependency::LiveDependencyKey, rabs_key::live_dependency::LiveRefusal> {
    use rabs_protocol::input_evidence::{
        ActionInputManifest, INPUT_EVIDENCE_SCHEMA_VERSION, InputFileType, PositiveInput,
    };
    use rabs_protocol::raw_bytes::RawBytes;
    use rabs_protocol::result_identity::ObjectId;
    use std::os::unix::fs::PermissionsExt;
    let mut inputs = ActionInputManifest {
        schema_version: INPUT_EVIDENCE_SCHEMA_VERSION,
        ..ActionInputManifest::default()
    };
    let mut roots = vec![(Path::new(&plan.source_root), plan.source_virtual_root())];
    if let Some(root) = &plan.generated_root {
        roots.push((Path::new(root), plan.generated_virtual_root()));
    }
    for (root, visible) in roots {
        let mut pending = vec![root.to_path_buf()];
        while let Some(directory) = pending.pop() {
            for entry in std::fs::read_dir(&directory).unwrap() {
                let entry = entry.unwrap();
                if directory == root
                    && root == Path::new(&plan.source_root)
                    && entry.file_name() == ".git"
                {
                    continue;
                }
                let path = entry.path();
                let meta = std::fs::symlink_metadata(&path).unwrap();
                if meta.is_dir() {
                    pending.push(path);
                } else {
                    assert!(meta.is_file());
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
                        executable: meta.permissions().mode() & 0o111 != 0,
                        symlink_resolution: Vec::new(),
                    });
                }
            }
        }
    }
    let externs: Vec<_> = plan
        .externs
        .iter()
        .filter_map(|planned| match planned {
            PlannedExtern::File { path, .. } => Some(ExternFact {
                path: path.clone(),
                content_digest: object_file(Path::new(path)),
            }),
            PlannedExtern::Toolchain { .. } => None,
        })
        .collect();
    let directories: Vec<_> = plan
        .dependency_dirs
        .iter()
        .map(|root| {
            // The edge's rule (rustc's crate locator): only `lib*` entries can
            // be opened as crates, and a library compile never opens an
            // `.rlib` once a non-empty same-stem `.rmeta` supplies metadata.
            let mut artifacts = Vec::new();
            for entry in std::fs::read_dir(root).unwrap() {
                let path = entry.unwrap().path();
                let name = path.file_name().unwrap().to_str().unwrap().to_owned();
                if !name.starts_with("lib")
                    || (root == &plan.out_dir && plan.output_names().contains(&name))
                {
                    continue;
                }
                assert!(std::fs::symlink_metadata(&path).unwrap().is_file());
                assert!(name.ends_with(".rlib") || name.ends_with(".rmeta"));
                let shadowed = name.strip_suffix(".rlib").is_some_and(|stem| {
                    std::fs::metadata(Path::new(root).join(format!("{stem}.rmeta")))
                        .is_ok_and(|meta| meta.len() > 0)
                });
                if !shadowed {
                    artifacts.push(ExternFact {
                        path: path.to_str().unwrap().to_owned(),
                        content_digest: object_file(&path),
                    });
                }
            }
            artifacts.sort_by(|a, b| a.path.cmp(&b.path));
            DependencyDirectoryFact {
                path: root.clone(),
                artifacts,
            }
        })
        .collect();
    let script_output = plan
        .generated_root
        .as_ref()
        .map(|root| std::fs::read(Path::new(root).parent().unwrap().join("run/stdout")).unwrap());
    live_dependency_key(
        plan,
        toolchain,
        &externs,
        &directories,
        script_output.as_deref(),
        &inputs,
    )
}

fn actual_key(
    plan: &DependencyActionPlan,
    toolchain: &ToolchainFacts,
) -> rabs_key::live_dependency::LiveDependencyKey {
    try_actual_key(plan, toolchain).unwrap()
}

#[test]
fn actual_cargo_generated_inputs_bind_bytes_and_preserve_unkeyed_env_fallback() {
    let scratch = tempfile::tempdir().unwrap();
    let root = scratch.path();
    let repository = root.join("upstream");
    let app = root.join("application");
    std::fs::create_dir_all(repository.join("src")).unwrap();
    std::fs::create_dir_all(app.join("src")).unwrap();
    std::fs::write(
        repository.join("Cargo.toml"),
        "[package]\nname=\"generated_fixture\"\nversion=\"1.0.0\"\nedition=\"2021\"\n",
    )
    .unwrap();
    std::fs::write(
        repository.join("src/lib.rs"),
        r#"
include!(concat!(env!("OUT_DIR"), "/value.rs"));
pub fn generated_path() -> &'static str { env!("OUT_DIR") }
pub fn custom() -> &'static str { option_env!("MY_VALUE").unwrap_or("unset") }
"#,
    )
    .unwrap();
    std::fs::write(
        repository.join("build.rs"),
        r#"
fn main() {
    let out = std::path::PathBuf::from(std::env::var_os("OUT_DIR").unwrap());
    std::fs::write(out.join("value.rs"), "pub fn value() -> u32 { 17 }\n").unwrap();
    println!("cargo::rerun-if-env-changed=RABS_TEST_UNKEYED_ENV");
    println!("cargo::rustc-cfg=generated_input");
    println!("cargo::rustc-check-cfg=cfg(generated_input)");
    if std::env::var_os("RABS_TEST_UNKEYED_ENV").is_some() {
        println!("cargo::rustc-env=MY_VALUE=example");
    }
}
"#,
    )
    .unwrap();
    git(&repository, &["init", "--quiet"]);
    git(&repository, &["add", "Cargo.toml", "build.rs", "src"]);
    git(
        &repository,
        &[
            "-c",
            "user.name=RABS fixture",
            "-c",
            "user.email=rabs@example.invalid",
            "commit",
            "--quiet",
            "-m",
            "generated Rust inputs",
        ],
    );
    let revision = String::from_utf8(git(&repository, &["rev-parse", "HEAD"]).stdout).unwrap();
    std::fs::write(app.join("Cargo.toml"), format!("[package]\nname=\"generated_consumer\"\nversion=\"1.0.0\"\nedition=\"2021\"\n[dependencies]\ngenerated_fixture={{git=\"file://{}\",rev=\"{}\"}}\n", repository.display(), revision.trim())).unwrap();
    std::fs::write(app.join("src/main.rs"), "fn main(){println!(\"{}:{}:{}\", generated_fixture::value(), generated_fixture::custom(), generated_fixture::generated_path());}\n").unwrap();
    let wrapper = root.join("recording-wrapper");
    let wrapper_source = root.join("record.rs");
    std::fs::write(&wrapper_source, RECORDING_WRAPPER).unwrap();
    checked(
        Command::new("rustc")
            .args(["--edition=2021", "--crate-name", "recording_wrapper"])
            .arg(&wrapper_source)
            .arg("-o")
            .arg(&wrapper),
    );
    let version = String::from_utf8(checked(Command::new("rustc").arg("-vV")).stdout).unwrap();
    let host = version
        .lines()
        .find_map(|line| line.strip_prefix("host: "))
        .unwrap();
    let target = root.join("target");
    let record = root.join("record");
    let mut cargo = Command::new(env!("CARGO"));
    cargo
        .current_dir(&app)
        .args(["build", "--jobs", "1", "--target-dir"])
        .arg(&target)
        .env("CARGO_HOME", root.join("cargo-home"))
        .env("CARGO_INCREMENTAL", "0")
        .env("RUSTC_WRAPPER", &wrapper)
        .env("RABS_TEST_RECORD", &record);
    for name in [
        "RUSTFLAGS",
        "CARGO_ENCODED_RUSTFLAGS",
        "RUSTC_WORKSPACE_WRAPPER",
        "RUSTC",
        "CARGO_TARGET_DIR",
        "CARGO_BUILD_TARGET",
        "RABS_TEST_UNKEYED_ENV",
        "MY_VALUE",
    ] {
        cargo.env_remove(name);
    }
    checked(&mut cargo);
    let recorded = Recorded::load(&record.join("generated_fixture"));
    let plan = recorded.plan(host);
    let generated = Path::new(plan.generated_root.as_ref().expect("real OUT_DIR"));
    let script_record = std::fs::read(generated.parent().unwrap().join("run/stdout")).unwrap();
    assert_eq!(
        std::fs::read(generated.parent().unwrap().join("run/root-output")).unwrap(),
        generated.to_str().unwrap().as_bytes()
    );
    assert!(String::from_utf8_lossy(&script_record).contains("cargo::rustc-cfg=generated_input"));
    let expected_stdout = format!("17:unset:{}\n", generated.display());
    assert_eq!(
        checked(&mut Command::new(target.join("debug/generated_consumer"))).stdout,
        expected_stdout.as_bytes()
    );
    let toolchain = real_toolchain(&plan);
    let baseline = actual_key(&plan, &toolchain);
    let repeat_out = root.join("repeat-out");
    let repeat = recorded.execute_at(&plan, &repeat_out);
    let mut repeat_argv = recorded.argv.clone();
    for arg in &mut repeat_argv {
        *arg = arg.replace(&plan.out_dir, repeat_out.to_str().unwrap());
    }
    let repeat_plan = plan_dependency_action(
        LiveRustcRequest {
            argv: &repeat_argv,
            cwd: &plan.cwd,
            env: &plan.execution_env,
        },
        host,
    )
    .unwrap();
    assert_eq!(baseline, actual_key(&repeat_plan, &toolchain));
    assert_eq!(
        canonicalize_placements(&recorded.stderr, &plan).unwrap(),
        canonicalize_placements(&repeat.stderr, &repeat_plan).unwrap()
    );
    for name in plan.output_names() {
        let original = std::fs::read(Path::new(&plan.out_dir).join(&name)).unwrap();
        let repeated = std::fs::read(repeat_out.join(&name)).unwrap();
        if name.ends_with(".d") {
            assert_eq!(
                dep_info_closure_violation(&plan, &original, |path| {
                    path.strip_prefix(&format!("{}/", plan.source_virtual_root()))
                        .is_some_and(|relative| {
                            Path::new(&plan.source_root).join(relative).is_file()
                        })
                        || path == plan.generated_input_virtual_path("value.rs")
                }),
                None
            );
            assert!(String::from_utf8_lossy(&original).contains("# env-dep:OUT_DIR="));
            assert_eq!(
                canonicalize_placements(&original, &plan).unwrap(),
                canonicalize_placements(&repeated, &repeat_plan).unwrap()
            );
        } else {
            assert_eq!(
                original, repeated,
                "constructed compiler environment must preserve actual Cargo output {name}"
            );
        }
    }
    let generated_file = generated.join("value.rs");
    let original = std::fs::read(&generated_file).unwrap();
    let mutated = b"pub fn value() -> u32 { 23 }\n";
    assert_eq!(original.len(), mutated.len());
    std::fs::write(&generated_file, mutated).unwrap();
    assert_ne!(
        baseline.action_key,
        actual_key(&plan, &toolchain).action_key
    );
    let changed_out = root.join("changed-out");
    recorded.execute_at(&plan, &changed_out);
    let rlib = plan
        .output_names()
        .into_iter()
        .find(|name| name.ends_with(".rlib"))
        .unwrap();
    assert_ne!(
        std::fs::read(Path::new(&plan.out_dir).join(&rlib)).unwrap(),
        std::fs::read(changed_out.join(&rlib)).unwrap()
    );
    std::fs::write(&generated_file, &original).unwrap();
    assert_eq!(baseline, actual_key(&plan, &toolchain));
    // Cargo executes its build script again. An arbitrary rustc-env value
    // stays on the ordinary compiler path, where the stock result proves
    // it was preserved; the cache must refuse before private execution.
    cargo
        .args(["--locked", "--offline"])
        .env("RABS_TEST_UNKEYED_ENV", "1");
    checked(&mut cargo);
    let fallback_request = Recorded::load(&record.join("generated_fixture"));
    let fallback_plan = fallback_request.plan(host);
    assert!(
        fallback_request
            .env
            .contains(&("MY_VALUE".into(), "example".into()))
    );
    assert!(
        !fallback_plan
            .execution_env
            .iter()
            .any(|(name, _)| name == "MY_VALUE")
    );
    assert!(
        matches!(try_actual_key(&fallback_plan, &toolchain), Err(rabs_key::live_dependency::LiveRefusal::RefusedEnv(name)) if name == "MY_VALUE")
    );
    assert_eq!(
        checked(&mut Command::new(target.join("debug/generated_consumer"))).stdout,
        format!("17:example:{}\n", generated.display()).as_bytes()
    );
}

#[test]
fn actual_cargo_dependency_chain_reuses_complete_keys_across_target_directories() {
    let scratch = tempfile::tempdir().unwrap();
    let root = scratch.path();
    let repository = root.join("upstream");
    let app = root.join("application");
    for path in [
        repository.join("leaf/src"),
        repository.join("middle/src"),
        app.join("src"),
    ] {
        std::fs::create_dir_all(path).unwrap();
    }
    std::fs::write(
        repository.join("Cargo.toml"),
        "[workspace]\nmembers=[\"leaf\",\"middle\"]\nresolver=\"2\"\n",
    )
    .unwrap();
    std::fs::write(
        repository.join("leaf/Cargo.toml"),
        "[package]\nname=\"chain_leaf\"\nversion=\"1.0.0\"\nedition=\"2021\"\n",
    )
    .unwrap();
    std::fs::write(
        repository.join("leaf/src/lib.rs"),
        "pub fn value()->u32 {7}\n",
    )
    .unwrap();
    std::fs::write(repository.join("middle/Cargo.toml"), "[package]\nname=\"chain_middle\"\nversion=\"1.0.0\"\nedition=\"2021\"\n[dependencies]\nchain_leaf={path=\"../leaf\"}\n").unwrap();
    std::fs::write(
        repository.join("middle/src/lib.rs"),
        "pub fn doubled()->u32 {chain_leaf::value()*2}\n",
    )
    .unwrap();
    git(&repository, &["init", "--quiet"]);
    git(&repository, &["add", "Cargo.toml", "leaf", "middle"]);
    git(
        &repository,
        &[
            "-c",
            "user.name=RABS fixture",
            "-c",
            "user.email=rabs@example.invalid",
            "commit",
            "--quiet",
            "-m",
            "real dependency chain",
        ],
    );
    let revision = String::from_utf8(git(&repository, &["rev-parse", "HEAD"]).stdout).unwrap();
    std::fs::write(app.join("Cargo.toml"), format!("[package]\nname=\"chain_consumer\"\nversion=\"1.0.0\"\nedition=\"2021\"\n[dependencies]\nchain_middle={{git=\"file://{}\",rev=\"{}\"}}\n", repository.display(), revision.trim())).unwrap();
    std::fs::write(
        app.join("src/main.rs"),
        "fn main(){println!(\"{}\",chain_middle::doubled());}\n",
    )
    .unwrap();
    let wrapper_source = root.join("record.rs");
    let wrapper = root.join("recording-wrapper");
    std::fs::write(&wrapper_source, RECORDING_WRAPPER).unwrap();
    checked(
        Command::new("rustc")
            .args(["--edition=2021", "--crate-name", "recording_wrapper"])
            .arg(wrapper_source)
            .arg("-o")
            .arg(&wrapper),
    );
    let version = String::from_utf8(checked(Command::new("rustc").arg("-vV")).stdout).unwrap();
    let host = version
        .lines()
        .find_map(|line| line.strip_prefix("host: "))
        .unwrap();
    let mut builds = Vec::new();
    for (index, name) in ["first", "second"].into_iter().enumerate() {
        let target = root.join(name).join("target");
        let record = root.join(name).join("record");
        let mut cargo = Command::new(env!("CARGO"));
        cargo
            .current_dir(&app)
            .args(["build", "--jobs", "1", "--target-dir"])
            .arg(&target)
            .env("CARGO_HOME", root.join("cargo-home"))
            .env("CARGO_INCREMENTAL", "0")
            .env("RUSTC_WRAPPER", &wrapper)
            .env("RABS_TEST_RECORD", &record);
        for name in [
            "RUSTFLAGS",
            "CARGO_ENCODED_RUSTFLAGS",
            "RUSTC_WORKSPACE_WRAPPER",
            "RUSTC",
            "CARGO_TARGET_DIR",
            "CARGO_BUILD_TARGET",
        ] {
            cargo.env_remove(name);
        }
        if index != 0 {
            cargo.args(["--locked", "--offline"]);
        }
        checked(&mut cargo);
        assert_eq!(
            checked(&mut Command::new(target.join("debug/chain_consumer"))).stdout,
            b"14\n"
        );
        builds.push(["chain_leaf", "chain_middle"].map(|name| {
            let request = Recorded::load(&record.join(name));
            let plan = request.plan(host);
            (request, plan)
        }));
    }
    let toolchain = real_toolchain(&builds[0][0].1);
    for index in 0..2 {
        let (request_a, a) = &builds[0][index];
        let (request_b, b) = &builds[1][index];
        assert_eq!(
            actual_key(a, &toolchain),
            actual_key(b, &toolchain),
            "complete key differs for real Cargo request {index}"
        );
        assert_eq!(
            canonicalize_placements(&request_a.stderr, a).unwrap(),
            canonicalize_placements(&request_b.stderr, b).unwrap()
        );
        for name in a.output_names() {
            let left = std::fs::read(Path::new(&a.out_dir).join(&name)).unwrap();
            let right = std::fs::read(Path::new(&b.out_dir).join(&name)).unwrap();
            if name.ends_with(".d") {
                assert_eq!(
                    dep_info_closure_violation(a, &left, |virtual_path| virtual_path
                        .strip_prefix(&format!("{}/", a.source_virtual_root()))
                        .is_some_and(|relative| Path::new(&a.source_root)
                            .join(relative)
                            .is_file())),
                    None
                );
                let canonical = canonicalize_placements(&left, a).unwrap();
                assert_eq!(canonical, canonicalize_placements(&right, b).unwrap());
                assert_eq!(render_placements(&canonical, b), right);
            } else {
                assert_eq!(left, right, "real output {name} depends on placement");
            }
        }
    }
    let middle = &builds[0][1].1;
    assert!(
        middle
            .dependency_dirs
            .iter()
            .any(|directory| directory != &middle.out_dir),
        "fixture must exercise Cargo's sibling per-unit dependency directory"
    );
    let original = actual_key(middle, &toolchain).action_key;
    let direct = middle
        .externs
        .iter()
        .find_map(|planned| match planned {
            PlannedExtern::File { path, .. } => Some(path),
            _ => None,
        })
        .unwrap();
    let mut bytes = std::fs::read(direct).unwrap();
    let pristine = bytes.clone();
    bytes[0] ^= 1;
    std::fs::write(direct, &bytes).unwrap();
    assert_ne!(
        actual_key(middle, &toolchain).action_key,
        original,
        "same-length dependency mutation must miss"
    );
    std::fs::write(direct, pristine).unwrap();
    assert_eq!(actual_key(middle, &toolchain).action_key, original);
}
fn checked(command: &mut Command) -> Output {
    let output = command
        .output()
        .expect("run Cargo/Git/rustc conformance command");
    assert!(
        output.status.success(),
        "{command:?} failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    output
}

fn git(root: &Path, args: &[&str]) -> Output {
    checked(
        Command::new("git")
            .args([
                "-c",
                "core.hooksPath=/dev/null",
                "-c",
                "commit.gpgsign=false",
            ])
            .arg("-C")
            .arg(root)
            .args(args)
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env("GIT_CONFIG_GLOBAL", "/dev/null"),
    )
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
            std::fs::read_to_string(root.join(name))
                .unwrap()
                .split_terminator('\0')
                .map(str::to_owned)
                .collect::<Vec<_>>()
        };
        let env = fields("env");
        let (environment, remainder) = env.as_chunks::<2>();
        assert!(remainder.is_empty());
        Self {
            argv: fields("argv"),
            env: environment
                .iter()
                .map(|[name, value]| (name.clone(), value.clone()))
                .collect(),
            cwd: std::fs::read_to_string(root.join("cwd")).unwrap(),
            stderr: std::fs::read(root.join("stderr")).unwrap(),
        }
    }

    fn plan(&self, host: &str) -> DependencyActionPlan {
        plan_dependency_action(
            LiveRustcRequest {
                argv: &self.argv,
                cwd: &self.cwd,
                env: &self.env,
            },
            host,
        )
        .unwrap_or_else(|error| {
            panic!(
                "actual Cargo Git request was refused: {error}; {:#?}",
                self.argv
            )
        })
    }

    fn execute_at(&self, plan: &DependencyActionPlan, out: &Path) -> Output {
        use std::io::Write;
        std::fs::create_dir_all(out).unwrap();
        // Cargo's recorded descriptors belonged to the completed Cargo
        // process. Reconstruct this explicitly unkeyed transport with a
        // real FIFO jobserver instead of passing closed FDs or suppressing
        // the compiler's resulting diagnostics. One available token plus
        // the compiler's implicit token bounds this tiny replay to two jobs.
        let fifo = out.with_extension("jobserver-fifo");
        checked(Command::new("mkfifo").arg(&fifo));
        let mut jobserver = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(&fifo)
            .unwrap();
        jobserver.write_all(b"+").unwrap();
        let jobserver_flags = format!("-j --jobserver-auth=fifo:{}", fifo.display());
        let out = out.to_str().unwrap();
        checked(
            Command::new(&self.argv[0])
                .args(
                    self.argv[1..]
                        .iter()
                        .map(|arg| arg.replace(&plan.out_dir, out)),
                )
                .current_dir(&plan.cwd)
                .env_clear()
                .envs(plan.execution_env.iter().map(|(name, value)| {
                    (
                        name,
                        if matches!(name.as_str(), "CARGO_MAKEFLAGS" | "MAKEFLAGS" | "MFLAGS") {
                            jobserver_flags.clone()
                        } else {
                            value.replace(&plan.out_dir, out)
                        },
                    )
                })),
        )
    }
}

#[test]
fn cargo_git_member_outputs_and_observed_closure_match_the_live_plan() {
    let scratch = tempfile::tempdir().unwrap();
    let root = scratch.path();
    let repository = root.join("upstream");
    let member = repository.join("crates/leaf");
    let app = root.join("application");
    let cargo_home = root.join("cargo-home");
    for directory in [
        member.join("src"),
        repository.join("shared"),
        app.join("src"),
        cargo_home.clone(),
    ] {
        std::fs::create_dir_all(directory).unwrap();
    }
    std::fs::write(
        repository.join("Cargo.toml"),
        "[workspace]\nmembers = [\"crates/leaf\"]\nresolver = \"2\"\n",
    )
    .unwrap();
    std::fs::write(
        member.join("Cargo.toml"),
        "[package]\nname = \"git_fixture\"\nversion = \"1.0.0\"\nedition = \"2021\"\n",
    )
    .unwrap();
    let source = "pub fn value() -> &'static str { include_str!(\"../../../shared/value.txt\") }\n\
                  pub fn version() -> &'static str { env!(\"CARGO_PKG_VERSION\") }\n";
    std::fs::write(member.join("src/lib.rs"), source).unwrap();
    std::fs::write(repository.join("shared/value.txt"), b"alpha\n").unwrap();
    git(&repository, &["init", "--quiet"]);
    git(&repository, &["add", "Cargo.toml", "crates", "shared"]);
    git(
        &repository,
        &[
            "-c",
            "user.name=RABS fixture",
            "-c",
            "user.email=rabs@example.invalid",
            "-c",
            "commit.gpgsign=false",
            "commit",
            "--quiet",
            "-m",
            "Git dependency fixture",
        ],
    );
    let revision = String::from_utf8(git(&repository, &["rev-parse", "HEAD"]).stdout).unwrap();
    std::fs::write(
        app.join("Cargo.toml"),
        format!(
            "[package]\nname = \"git_consumer\"\nversion = \"1.0.0\"\nedition = \"2021\"\n\
                 [dependencies]\ngit_fixture = {{ git = \"file://{}\", rev = \"{}\" }}\n",
            repository.display(),
            revision.trim()
        ),
    )
    .unwrap();
    std::fs::write(
        app.join("src/main.rs"),
        "fn main() { print!(\"{}{}\", git_fixture::value(), git_fixture::version()); }\n",
    )
    .unwrap();

    let wrapper_source = root.join("record.rs");
    let wrapper = root.join("recording-wrapper");
    std::fs::write(&wrapper_source, RECORDING_WRAPPER).unwrap();
    checked(
        Command::new("rustc")
            .args(["--edition=2021", "--crate-name", "recording_wrapper"])
            .arg(&wrapper_source)
            .arg("-o")
            .arg(&wrapper),
    );
    let version = checked(Command::new("rustc").arg("-vV"));
    let version = String::from_utf8(version.stdout).unwrap();
    let host = version
        .lines()
        .find_map(|line| line.strip_prefix("host: "))
        .unwrap();

    let mut builds = Vec::new();
    for (index, name) in ["first", "second"].into_iter().enumerate() {
        let target = root.join(name).join("target");
        let record = root.join(name).join("record");
        std::fs::create_dir_all(&record).unwrap();
        let mut cargo = Command::new(env!("CARGO"));
        cargo
            .current_dir(&app)
            .args(["build", "--jobs", "1", "--target-dir"])
            .arg(&target)
            .env("CARGO_HOME", &cargo_home)
            .env("CARGO_INCREMENTAL", "0")
            .env("RUSTC_WRAPPER", &wrapper)
            .env("RABS_TEST_RECORD", &record);
        // The fixture has no registry dependencies. Its first build fetches
        // only the file:// repository; subsequent builds are locked/offline.
        if index != 0 {
            cargo.args(["--locked", "--offline"]);
        }
        for name in [
            "RUSTFLAGS",
            "CARGO_ENCODED_RUSTFLAGS",
            "RUSTC_WORKSPACE_WRAPPER",
            "RUSTC",
            "CARGO_TARGET_DIR",
            "CARGO_BUILD_TARGET",
        ] {
            cargo.env_remove(name);
        }
        checked(&mut cargo);
        assert_eq!(
            checked(&mut Command::new(target.join("debug/git_consumer"))).stdout,
            b"alpha\n1.0.0"
        );
        let recorded = Recorded::load(&record);
        let plan = recorded.plan(host);
        assert_eq!(plan.source_kind, DependencySourceKind::GitCheckout);
        assert!(Path::new(&plan.source_root).starts_with(cargo_home.join("git/checkouts")));
        assert_eq!(
            Path::new(&plan.package_root),
            Path::new(&plan.source_root).join("crates/leaf")
        );
        let observed_revision =
            String::from_utf8(git(Path::new(&plan.source_root), &["rev-parse", "HEAD"]).stdout)
                .unwrap();
        assert_eq!(observed_revision, revision);
        builds.push((recorded, plan));
    }

    let (first, a) = &builds[0];
    let (second, b) = &builds[1];
    assert_eq!(a.source_root, b.source_root);
    assert_eq!(a.package_root, b.package_root);
    assert_eq!(a.output_names(), b.output_names());
    for name in a.output_names() {
        let left = std::fs::read(Path::new(&a.out_dir).join(&name)).unwrap();
        let right = std::fs::read(Path::new(&b.out_dir).join(&name)).unwrap();
        if name.ends_with(".d") {
            let canonical = canonicalize_out_dir(&left, &a.out_dir).unwrap();
            assert_eq!(canonical, canonicalize_out_dir(&right, &b.out_dir).unwrap());
            assert_eq!(render_out_dir(&canonical, &b.out_dir), right);
            assert!(String::from_utf8_lossy(&left).contains("shared/value.txt"));
            assert_eq!(
                dep_info_closure_violation(a, &left, |virtual_path| {
                    virtual_path
                        .strip_prefix(&format!("{}/", a.source_virtual_root()))
                        .is_some_and(|relative| Path::new(&a.source_root).join(relative).is_file())
                }),
                None
            );
        } else {
            assert_eq!(
                left, right,
                "actual Cargo output {name} depends on placement"
            );
        }
    }
    let canonical = canonicalize_out_dir(&first.stderr, &a.out_dir).unwrap();
    assert_eq!(
        canonical,
        canonicalize_out_dir(&second.stderr, &b.out_dir).unwrap()
    );
    assert_eq!(render_out_dir(&canonical, &b.out_dir), second.stderr);

    // Execute the same actual request with the constructed live environment.
    // A same-length dirty sibling edit changes compiler bytes even though the
    // Cargo checkout's revision name is unchanged.
    std::fs::write(
        Path::new(&a.source_root).join("shared/value.txt"),
        b"bravo\n",
    )
    .unwrap();
    let dirty_out = root.join("dirty/deps");
    first.execute_at(a, &dirty_out);
    let library = a
        .output_names()
        .into_iter()
        .find(|name| name.ends_with(".rlib"))
        .unwrap();
    assert_ne!(
        std::fs::read(Path::new(&a.out_dir).join(&library)).unwrap(),
        std::fs::read(dirty_out.join(library)).unwrap()
    );

    // Git metadata is readable to this unsandboxed compiler, but the real
    // emitted dep-info must prevent that execution from being published.
    std::fs::write(
        Path::new(&a.package_root).join("src/lib.rs"),
        "pub const HEAD: &str = include_str!(\"../../../.git/HEAD\");\n",
    )
    .unwrap();
    let metadata_out = root.join("metadata/deps");
    first.execute_at(a, &metadata_out);
    let depfile = a
        .output_names()
        .into_iter()
        .find(|name| name.ends_with(".d"))
        .unwrap();
    let dep_info = std::fs::read(metadata_out.join(depfile)).unwrap();
    let mut metadata_plan = a.clone();
    metadata_plan.out_dir = metadata_out.to_str().unwrap().to_owned();
    assert!(
        dep_info_closure_violation(&metadata_plan, &dep_info, |_| true)
            .is_some_and(|reason| reason.contains("Git metadata"))
    );
}
