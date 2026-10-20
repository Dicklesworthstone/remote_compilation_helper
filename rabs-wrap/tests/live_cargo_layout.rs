//! Real Cargo acceptance of the opt-in final/intermediate layout projection.
//!
//! No hand-built rustc requests or preseeded CAS entries: offline Cargo plans
//! a dependency, the real wrapper captures it, and independent checks must
//! verify before a fresh layout can skip its compiler. A stock Cargo check in
//! the same test supplies the metadata-byte oracle, and downstream constant
//! assertions verify values read from the dependency metadata.
//! These tiny fixtures establish semantics, not a fleet speedup claim.
#![cfg(target_os = "linux")]

#[path = "support/rabsd.rs"]
mod daemon_binary;

use serde_json::Value;
use std::collections::BTreeMap;
use std::ffi::OsStr;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};
use std::time::{Duration, Instant};

const VARIABLES: [&str; 3] = [
    "CARGO_TARGET_DIR",
    "CARGO_BUILD_TARGET_DIR",
    "CARGO_BUILD_BUILD_DIR",
];
const WRAPPER: &str = env!("CARGO_BIN_EXE_rabs-wrap");

// Native Linux acceptance requires coreutils timeout. Its owned process group
// bounds each fixture command, including descendants, without a test timer
// retaining an obsolete PID. Missing tools fail the test instead of skipping it.
fn timed(program: impl AsRef<OsStr>) -> Command {
    let mut command = Command::new("timeout");
    command
        .args(["--signal=TERM", "--kill-after=5s", "240s"])
        .arg(program)
        .stdin(Stdio::null());
    command
}

fn successful(command: &mut Command) -> Output {
    let output = command.output().expect("execute real fixture command");
    assert!(
        output.status.success(),
        "{command:?} exited {}\nstdout:\n{}\nstderr:\n{}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    output
}

struct Fixture {
    temporary: tempfile::TempDir,
    package: PathBuf,
    rustc: PathBuf,
}

struct Layout {
    workspace: PathBuf,
    final_dir: PathBuf,
    alias_dir: PathBuf,
    intermediate: PathBuf,
}

impl Fixture {
    fn new() -> Self {
        let temporary = tempfile::Builder::new()
            .prefix("rl")
            .tempdir_in("/tmp")
            .unwrap();
        std::fs::set_permissions(temporary.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let root = temporary.path();
        let package = root.join("vendor/layout_dep-1.0.0");
        std::fs::create_dir_all(package.join("src")).unwrap();
        std::fs::create_dir_all(root.join("home")).unwrap();
        std::fs::create_dir_all(root.join("cargo-home")).unwrap();
        std::fs::write(
            package.join("Cargo.toml"),
            "[package]\nname='layout_dep'\nversion='1.0.0'\nedition='2021'\n",
        )
        .unwrap();
        std::fs::write(package.join(".cargo-checksum.json"), "{\"files\":{}}\n").unwrap();
        std::fs::write(
            root.join("cargo-home/config.toml"),
            format!(
                "[source.crates-io]\nreplace-with='fixture'\n\
                 [source.fixture]\ndirectory='{}'\n[net]\noffline=true\n",
                root.join("vendor").display()
            ),
        )
        .unwrap();
        let sysroot = successful(timed("rustc").args(["--print", "sysroot"]));
        let rustc = Path::new(String::from_utf8(sysroot.stdout).unwrap().trim()).join("bin/rustc");
        Self {
            temporary,
            package,
            rustc,
        }
    }

    fn root(&self) -> &Path {
        self.temporary.path()
    }

    fn source(&self, body: &str) {
        std::fs::write(self.package.join("src/lib.rs"), body).unwrap();
    }

    fn layout(&self, name: &str) -> Layout {
        let workspace = self.root().join(name);
        std::fs::create_dir_all(workspace.join("src")).unwrap();
        std::fs::write(
            workspace.join("Cargo.toml"),
            "[package]\nname='layout_app'\nversion='0.1.0'\nedition='2021'\n\
             [dependencies]\nlayout_dep='1.0'\n",
        )
        .unwrap();
        std::fs::write(
            workspace.join("src/main.rs"),
            "fn main() { println!(\"{}\", layout_dep::message()); }\n",
        )
        .unwrap();
        Layout {
            final_dir: workspace.join("final"),
            alias_dir: workspace.join("configured-final"),
            intermediate: workspace.join("intermediate"),
            workspace,
        }
    }

    fn check(&self, layout: &Layout, wrapped: bool) -> Output {
        self.check_with_env(layout, wrapped, &[])
    }

    fn check_with_env(&self, layout: &Layout, wrapped: bool, overrides: &[(&str, &str)]) -> Output {
        let mut command = timed(env!("CARGO"));
        command
            .current_dir(&layout.workspace)
            .env_clear()
            .env("PATH", "/usr/local/bin:/usr/bin:/bin")
            .env("HOME", self.root().join("home"))
            .env("CARGO_HOME", self.root().join("cargo-home"))
            .env("RUSTC", &self.rustc)
            .env("CARGO_TERM_COLOR", "never")
            .env(VARIABLES[0], &layout.final_dir)
            .env(VARIABLES[1], &layout.alias_dir)
            .env(VARIABLES[2], &layout.intermediate)
            .env("RABS_SOCKET_PATH", self.root().join("d.sock"))
            .env("RABS_BREAKER_FILE", self.root().join("breaker"))
            // Real shells supply these per-worktree/process hints. They must
            // reach rustc without splitting keys when no source reads them.
            .env("PWD", &layout.workspace)
            .env("OLDPWD", self.root())
            .env("SHLVL", "2")
            .env("_", env!("CARGO"))
            .envs(overrides.iter().copied())
            .args(["check", "--offline", "--jobs=1", "--message-format=json"]);
        if wrapped {
            command.env("RUSTC_WRAPPER", WRAPPER);
        }
        successful(&mut command)
    }
}

fn artifacts(output: &Output) -> Vec<Value> {
    output
        .stdout
        .split(|byte| *byte == b'\n')
        .filter(|line| !line.is_empty())
        .map(|line| serde_json::from_slice::<Value>(line).expect("Cargo JSON"))
        .filter(|record| record["reason"] == "compiler-artifact")
        .collect()
}

fn expect_values(layout: &Layout, values: &[(&str, Option<&str>)]) {
    let mut source = String::from("fn main() {}\n");
    for (expression, expected) in values {
        source.push_str(&format!(
            "const _: () = {{\n\
             let actual: Option<&str> = {expression};\n\
             let expected: Option<&str> = {expected:?};\n\
             match (actual, expected) {{\n\
                 (None, None) => (),\n\
                 (Some(actual), Some(expected)) => {{\n\
                     assert!(actual.len() == expected.len());\n\
                     let mut index = 0;\n\
                     while index < expected.len() {{\n\
                         assert!(actual.as_bytes()[index] == expected.as_bytes()[index]);\n\
                         index += 1;\n\
                     }}\n\
                 }},\n\
                 _ => panic!(\"dependency metadata changed an optional value\"),\n\
             }}\n\
             }};\n"
        ));
    }
    std::fs::write(layout.workspace.join("src/main.rs"), source).unwrap();
}

fn library_bytes(layout: &Layout) -> BTreeMap<String, Vec<u8>> {
    let mut pending = vec![layout.intermediate.join("debug")];
    let mut files = BTreeMap::new();
    while let Some(directory) = pending.pop() {
        // A toolchain ignoring the intermediate-dir setting must fail here;
        // searching a fallback target tree would not exercise the claimed path.
        for entry in std::fs::read_dir(directory).unwrap() {
            let entry = entry.unwrap();
            let kind = entry.file_type().unwrap();
            if kind.is_dir() {
                pending.push(entry.path());
            } else if kind.is_file() {
                let name = entry.file_name().into_string().unwrap();
                if name.starts_with("liblayout_dep-") && name.ends_with(".rmeta") {
                    assert!(
                        files
                            .insert(name, std::fs::read(entry.path()).unwrap())
                            .is_none()
                    );
                }
            }
        }
    }
    assert_eq!(files.len(), 1, "one complete metadata output");
    files
}

struct Daemon {
    child: Child,
    log: PathBuf,
}

impl Daemon {
    fn start(fixture: &Fixture) -> Self {
        let root = fixture.root();
        let log = root.join("rabsd.log");
        let child = Command::new(daemon_binary::binary(WRAPPER))
            .env_clear()
            .env("PATH", "/usr/local/bin:/usr/bin:/bin")
            .env("HOME", root.join("home"))
            .env("RABS_CONFIG", root.join("absent.toml"))
            .env("RABS_STATE_DIR", root.join("state"))
            .env("RABS_SOCKET_PATH", root.join("d.sock"))
            .env("RABS_LIVE_DEPENDENCY", "1")
            .env("RABS_REUSE_CARGO_LAYOUT", "1")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(std::fs::File::create(&log).unwrap())
            .spawn()
            .expect("start real prepared daemon");
        // Own the child before any assertion so failed startup still reaps it.
        let mut daemon = Self { child, log };
        let deadline = Instant::now() + Duration::from_secs(30);
        while !root.join("d.sock").exists() {
            assert!(daemon.child.try_wait().unwrap().is_none(), "daemon exited");
            assert!(Instant::now() < deadline, "daemon never listened");
            std::thread::sleep(Duration::from_millis(20));
        }
        daemon
    }

    fn decisions(&self) -> Vec<Value> {
        std::fs::read_to_string(&self.log)
            .unwrap()
            .lines()
            .filter_map(|line| serde_json::from_str::<Value>(line).ok())
            .filter(|record| record["kind"] == "rabsd-live-dependency")
            .collect()
    }

    fn since(&self, mark: usize) -> Vec<Value> {
        self.decisions().get(mark..).expect("log retained").to_vec()
    }

    fn settled(&self, mark: usize, terminal: &str) -> Vec<Value> {
        let deadline = Instant::now() + Duration::from_secs(60);
        loop {
            let decisions = self.since(mark);
            if count(&decisions, terminal) != 0 {
                return decisions;
            }
            assert!(
                Instant::now() < deadline,
                "no {terminal} after real Cargo check: {decisions:?}"
            );
            std::thread::sleep(Duration::from_millis(20));
        }
    }
}

impl Drop for Daemon {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn count(decisions: &[Value], kind: &str) -> usize {
    decisions
        .iter()
        .filter(|record| record["decision"] == kind)
        .count()
}

#[test]
fn real_cargo_split_layouts_share_verified_artifacts_and_remain_fresh() {
    let fixture = Fixture::new();
    fixture.source("pub const MESSAGE: &str = \"layout fixture\";\n");
    let stock = fixture.layout("stock");
    expect_values(
        &stock,
        &[("Some(layout_dep::MESSAGE)", Some("layout fixture"))],
    );
    fixture.check_with_env(&stock, false, &[("RCH_BUILD_SOURCE", "stock-workspace")]);
    let expected_artifacts = library_bytes(&stock);
    let daemon = Daemon::start(&fixture);
    let mut action_key: Option<String> = None;
    for (name, terminal, executions) in [
        ("cold", "committed", 1),
        ("verify-one", "verified", 1),
        ("verify-two", "verified", 1),
        ("served", "served", 0),
    ] {
        let layout = fixture.layout(name);
        expect_values(
            &layout,
            &[("Some(layout_dep::MESSAGE)", Some("layout fixture"))],
        );
        let mark = daemon.decisions().len();
        fixture.check_with_env(&layout, true, &[("RCH_BUILD_SOURCE", name)]);
        let decisions = daemon.settled(mark, terminal);
        assert_eq!(count(&decisions, terminal), 1, "{decisions:?}");
        assert_eq!(count(&decisions, "execute"), executions, "{decisions:?}");
        assert_eq!(count(&decisions, "hit"), usize::from(executions == 0));
        let key = decisions
            .iter()
            .find(|record| record["decision"] == terminal)
            .and_then(|record| record["key"].as_str())
            .unwrap();
        if let Some(expected_key) = &action_key {
            assert_eq!(
                key,
                expected_key.as_str(),
                "layout changes must not rename the action"
            );
        } else {
            action_key = Some(key.to_owned());
        }
        assert_eq!(library_bytes(&layout), expected_artifacts);
        if executions == 0 {
            // A cache installation must satisfy Cargo freshness, not just let
            // this one typecheck finish with plausible files.
            let mark = daemon.decisions().len();
            let rebuild = fixture.check_with_env(&layout, true, &[("RCH_BUILD_SOURCE", name)]);
            assert!(artifacts(&rebuild).iter().any(|record| {
                record["target"]["name"] == "layout_dep" && record["fresh"] == true
            }));
            assert_eq!(daemon.decisions().len(), mark, "fresh build consulted RABS");
        }
    }
}

#[test]
fn real_environment_reads_keep_each_layouts_value_and_never_replay() {
    let fixture = Fixture::new();
    let daemon = Daemon::start(&fixture);
    for (index, variable) in VARIABLES.iter().enumerate() {
        for read in ["env", "option_env"] {
            let expression = if read == "env" {
                format!("env!(\"{variable}\")")
            } else {
                format!("option_env!(\"{variable}\").unwrap_or(\"ABSENT\")")
            };
            fixture.source(&format!("pub const MESSAGE: &str = {expression};\n"));
            for round in 0..2 {
                let layout = fixture.layout(&format!("read-{index}-{read}-{round}"));
                let expected = [&layout.final_dir, &layout.alias_dir, &layout.intermediate][index];
                expect_values(
                    &layout,
                    &[(
                        "Some(layout_dep::MESSAGE)",
                        Some(expected.to_str().unwrap()),
                    )],
                );
                let mark = daemon.decisions().len();
                fixture.check(&layout, true);
                // Capture refusal is not a build failure. Both invocations
                // must still execute and observe their OWN inherited value.
                // No reliance on a cache-denial diagnostic being printed.
                let decisions = daemon.since(mark);
                assert_eq!(count(&decisions, "execute"), 1, "{decisions:?}");
                assert_eq!(count(&decisions, "hit"), 0, "{decisions:?}");
                assert_eq!(count(&decisions, "served"), 0, "{decisions:?}");
            }
        }
    }
    let decisions = daemon.decisions();
    assert_eq!(count(&decisions, "committed"), 0, "{decisions:?}");
    assert_eq!(count(&decisions, "verified"), 0, "{decisions:?}");
}

#[test]
fn real_cargo_custom_environment_values_preserve_stock_behavior_and_cache_identity() {
    let fixture = Fixture::new();
    fixture.source(
        "pub const FLAVOR: &str = env!(\"DEPENDENCY_FLAVOR\");\n\
         pub const OPTIONAL: Option<&str> = option_env!(\"DEPENDENCY_OPTION\");\n",
    );
    let daemon = Daemon::start(&fixture);
    let mut distinct_keys = Vec::new();
    for (index, flavor, optional) in [
        (0, "vanilla", None),
        (1, "vanilla", Some("")),
        (2, "vanilla", Some("extra")),
        (3, "spiced = balanced", Some("extra")),
    ] {
        let mut variables = vec![("DEPENDENCY_FLAVOR", flavor)];
        if let Some(value) = optional {
            variables.push(("DEPENDENCY_OPTION", value));
        }
        let stock = fixture.layout(&format!("env-{index}-stock"));
        let values = [
            ("Some(layout_dep::FLAVOR)", Some(flavor)),
            ("layout_dep::OPTIONAL", optional),
        ];
        expect_values(&stock, &values);
        fixture.check_with_env(&stock, false, &variables);
        let expected_artifacts = library_bytes(&stock);
        let mut action_key: Option<String> = None;
        for (round, terminal, executions) in [
            ("cold", "committed", 1),
            ("verify-one", "verified", 1),
            ("verify-two", "verified", 1),
            ("served", "served", 0),
        ] {
            let layout = fixture.layout(&format!("env-{index}-{round}"));
            expect_values(&layout, &values);
            let mark = daemon.decisions().len();
            fixture.check_with_env(&layout, true, &variables);
            let decisions = daemon.settled(mark, terminal);
            assert_eq!(count(&decisions, terminal), 1, "{decisions:?}");
            assert_eq!(count(&decisions, "execute"), executions, "{decisions:?}");
            assert_eq!(count(&decisions, "hit"), usize::from(executions == 0));
            let key = decisions
                .iter()
                .find(|record| record["decision"] == terminal)
                .and_then(|record| record["key"].as_str())
                .unwrap();
            if let Some(expected_key) = &action_key {
                assert_eq!(key, expected_key.as_str(), "unchanged semantic environment");
            } else {
                assert!(
                    !distinct_keys.iter().any(|previous| previous == key),
                    "changed custom value or absent/empty option_env! reused an old action"
                );
                action_key = Some(key.to_owned());
            }
            assert_eq!(library_bytes(&layout), expected_artifacts);
        }
        distinct_keys.push(action_key.unwrap());
    }
}

#[test]
fn real_cargo_unkeyed_control_reads_preserve_values_and_never_publish_absence() {
    let fixture = Fixture::new();
    let daemon = Daemon::start(&fixture);
    for (index, name) in ["RABS_TEST_HINT", "CARGO_RABS_TEST_HINT", "RCH_BUILD_SOURCE"]
        .into_iter()
        .enumerate()
    {
        fixture.source(&format!(
            "pub const HINT: Option<&str> = option_env!(\"{name}\");\n"
        ));
        for (round, value) in [
            ("absent", None),
            ("empty", Some("")),
            ("present", Some("exact control")),
        ] {
            let variables: Vec<_> = value.map(|value| (name, value)).into_iter().collect();
            let stock = fixture.layout(&format!("control-{index}-{round}-stock"));
            expect_values(&stock, &[("layout_dep::HINT", value)]);
            fixture.check_with_env(&stock, false, &variables);
            let layout = fixture.layout(&format!("control-{index}-{round}-wrapped"));
            expect_values(&layout, &[("layout_dep::HINT", value)]);
            let mark = daemon.decisions().len();
            fixture.check_with_env(&layout, true, &variables);
            assert_eq!(library_bytes(&layout), library_bytes(&stock));
            let decisions = daemon.settled(mark, "not-published");
            assert_eq!(count(&decisions, "execute"), 1, "{decisions:?}");
            assert_eq!(count(&decisions, "hit"), 0, "{decisions:?}");
            assert_eq!(count(&decisions, "committed"), 0, "{decisions:?}");
        }
    }
}
