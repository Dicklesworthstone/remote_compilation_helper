//! Real Cargo/Git/rustc conformance for the live Git dependency class.
//! Cargo fetches a local repository at an actual commit, selects a nested
//! workspace member, and supplies the compiler requests used by the planner.
//! This checks output and closure semantics; daemon serving is exercised by
//! rabs-wrap's separate live-dependency end-to-end suite.
#![cfg(target_os = "linux")]

use std::path::Path;
use std::process::{Command, Output};

use rabs_key::live_dependency::{
    DependencyActionPlan, DependencySourceKind, LiveRustcRequest, canonicalize_out_dir,
    dep_info_closure_violation, plan_dependency_action, render_out_dir,
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
    if std::env::var("CARGO_PKG_NAME").as_deref() != Ok("git_fixture") {
        panic!("compiler exec: {}", compiler.exec());
    }
    let record = PathBuf::from(std::env::var_os("RABS_TEST_RECORD").unwrap());
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
        std::fs::create_dir_all(out).unwrap();
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
                .envs(
                    plan.execution_env
                        .iter()
                        .map(|(name, value)| (name, value.replace(&plan.out_dir, out))),
                ),
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
                dep_info_closure_violation(a, &left, |relative| {
                    Path::new(&a.source_root).join(relative).is_file()
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
