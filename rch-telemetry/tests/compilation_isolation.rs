//! Exercise the public compilation benchmark through separate OS processes.
//!
//! The default suite uses deliberately synthetic Cargo/rustc executables to
//! check orchestration and file custody, not performance. The separately named
//! opt-in test runs real Cargo/rustc and fails when either is unavailable.
#![cfg(unix)]

use rch_telemetry::benchmarks::CompilationBenchmark;
use serde_json::Value;
use std::collections::BTreeSet;
use std::ffi::OsString;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::time::{Duration, Instant};

const PROTECTED: &[u8] = b"unrelated worker artifact: preserve byte for byte\n";
const CHILD: &str = "compilation_isolation_child";

const RUSTC_FIXTURE: &str = r#"#!/bin/sh
set -eu
root=$RCH_BENCH_FIXTURE
case "$1" in
    -vV|--version)
        case "$0:$RCH_BENCH_FIXTURE_MODE" in
            */sysroot/bin/rustc:mismatch) printf 'rustc different-fixture\n';;
            *) printf 'rustc fixture-identity\n';;
        esac
        printf 'host: x86_64-unknown-linux-gnu\n'
        ;;
    --print=sysroot) printf '%s/sysroot\n' "$root";;
    *) exit 94;;
esac
"#;

const CARGO_FIXTURE: &str = r#"#!/bin/sh
set -eu
root=$RCH_BENCH_FIXTURE
log=$root/calls
n=0
if [ -f "$log/count" ]; then IFS= read -r n < "$log/count"; fi
n=$((n + 1))
printf '%s\n' "$n" > "$log/count"
printf '%s\n' "$@" > "$log/$n.args"
pwd -P > "$log/$n.cwd"
# Old behavior is observable without letting a fixture perform any deletion.
[ "$1" = build ] || { printf 'non-build Cargo invocation\n' >&2; exit 91; }
shift
target= host= profile= manifest= jobs= offline=0
while [ "$#" -gt 0 ]; do
    case "$1" in
        --offline) offline=1; shift;;
        --target-dir) target=$2; shift 2;;
        --target) host=$2; shift 2;;
        --profile) profile=$2; shift 2;;
        --manifest-path) manifest=$2; shift 2;;
        --jobs) jobs=$2; shift 2;;
        --config) shift 2;;
        *) printf 'unexpected Cargo option: %s\n' "$1" >&2; exit 92;;
    esac
done
cwd=$(pwd -P)
[ "$target" = "$cwd/target" ] && [ "$manifest" = "$cwd/Cargo.toml" ] || exit 96
[ "$host" = x86_64-unknown-linux-gnu ] && [ "$jobs" = 1 ] && [ "$offline" = 1 ] || exit 96
for value in "$CARGO_TARGET_DIR" "$CARGO_BUILD_TARGET_DIR" "$CARGO_BUILD_BUILD_DIR"; do
    [ "$value" = "$target" ] || exit 96
done
[ "$RUSTC" = "$root/sysroot/bin/rustc" ] && [ "$CARGO_BUILD_RUSTC" = "$RUSTC" ] || exit 96
[ "$RUSTC_WRAPPER" = '' ] && [ "$RUSTC_WORKSPACE_WRAPPER" = '' ] || exit 96
[ "$CARGO_BUILD_RUSTC_WRAPPER" = '' ] && [ "$CARGO_BUILD_RUSTC_WORKSPACE_WRAPPER" = '' ] || exit 96
[ "$CARGO_ENCODED_RUSTFLAGS" = '' ] && [ "${RUSTFLAGS+set}" != set ] || exit 96
[ "${CARGO_BUILD_RUSTFLAGS+set}" != set ] || exit 96
[ "$CARGO_CACHE_AUTO_CLEAN_FREQUENCY" = never ] || exit 96
[ "$RCH_CARGO_WRAPPER_BYPASS" = 1 ] && [ "$RCH_ENABLED" = 0 ] || exit 96
if IFS= read -r unexpected; then printf 'benchmark stdin was not closed\n' >&2; exit 93; fi
printf '%s\n' "$CARGO_INCREMENTAL" > "$log/$n.incremental"
printf '%s\n' "$RUSTC" > "$log/$n.compiler"
cp src/main.rs "$log/$n.source"
phase=${cwd%/*}
phase=${phase##*/}
printf '%s\n' "$phase" > "$log/$n.phase"
case "$profile" in dev) profile_dir=debug;; release) profile_dir=release;; *) exit 95;; esac
output=$target/$host/$profile_dir/rch_benchmark
if [ -e "$output" ]; then printf seeded; else printf cold; fi > "$log/$n.state"
case "$RCH_BENCH_FIXTURE_MODE:$phase" in
    fail-warmup:warmup|fail-release:release)
        printf 'fixture-build-failed\n' >&2; exit 23;;
    missing-output:warmup) exit 0;;
esac
mkdir -p "${output%/*}"
if [ "$RCH_BENCH_FIXTURE_MODE:$phase" = symlink-output:warmup ]; then
    ln -s "$root/protected/target/sentinel" "$output"
else
    printf 'fixture executable, not a compiler measurement\n' > "$output"
fi
"#;

struct OwnedChild(Child);

impl Drop for OwnedChild {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn executable(path: &Path, body: &str) {
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(path, body).unwrap();
    fs::set_permissions(path, fs::Permissions::from_mode(0o755)).unwrap();
}

struct Fixture {
    directory: tempfile::TempDir,
    root: PathBuf,
}

impl Fixture {
    fn new() -> Self {
        let directory = tempfile::Builder::new()
            .prefix("rch benchmark ' isolation ")
            .tempdir()
            .unwrap();
        let root = directory.path().canonicalize().unwrap();
        for name in [
            "calls",
            "scratch",
            "cargo-home",
            "protected/target",
            "protected/build",
        ] {
            fs::create_dir_all(root.join(name)).unwrap();
        }
        for name in ["target", "build"] {
            fs::write(
                root.join("protected").join(name).join("sentinel"),
                PROTECTED,
            )
            .unwrap();
        }
        executable(&root.join("tools/cargo recorder"), CARGO_FIXTURE);
        executable(&root.join("tools/selected rustc"), RUSTC_FIXTURE);
        executable(&root.join("sysroot/bin/rustc"), RUSTC_FIXTURE);
        executable(
            &root.join("forbidden-wrapper"),
            "#!/bin/sh\nprintf invoked > \"$RCH_BENCH_FIXTURE/unexpected-wrapper\"\nexit 99\n",
        );
        let quoted = |path: PathBuf| serde_json::to_string(path.to_str().unwrap()).unwrap();
        let config = format!(
            "[build]\ntarget-dir = {}\nbuild-dir = {}\nrustc = {}\nrustc-wrapper = {}\n\
             rustc-workspace-wrapper = {}\nrustflags = ['--cfg=unrelated_worker_flags']\n\
             [cache]\nauto-clean-frequency = 'always'\n",
            quoted(root.join("protected/target")),
            quoted(root.join("protected/build")),
            quoted(root.join("not-the-selected-compiler")),
            quoted(root.join("forbidden-wrapper")),
            quoted(root.join("forbidden-wrapper")),
        );
        fs::write(root.join("cargo-home/config.toml"), config).unwrap();
        Self { directory, root }
    }

    fn child(&self, mode: &str) -> Command {
        let mut command = Command::new(std::env::current_exe().unwrap());
        command
            .args(["--exact", CHILD, "--ignored", "--nocapture"])
            .current_dir(&self.root)
            .env("RCH_BENCH_FIXTURE", &self.root)
            .env("RCH_BENCH_FIXTURE_MODE", mode)
            .env("TMPDIR", self.root.join("scratch"))
            .env("CARGO_HOME", self.root.join("cargo-home"))
            .env("CARGO_TARGET_DIR", self.root.join("protected/target"))
            .env("CARGO_BUILD_TARGET_DIR", self.root.join("protected/target"))
            .env("CARGO_BUILD_BUILD_DIR", self.root.join("protected/build"))
            .env("RUSTC", self.root.join("not-the-selected-compiler"))
            .env(
                "CARGO_BUILD_RUSTC",
                self.root.join("not-the-selected-compiler"),
            )
            .env("RUSTC_WRAPPER", self.root.join("forbidden-wrapper"))
            .env(
                "RUSTC_WORKSPACE_WRAPPER",
                self.root.join("forbidden-wrapper"),
            )
            .env(
                "CARGO_BUILD_RUSTC_WRAPPER",
                self.root.join("forbidden-wrapper"),
            )
            .env(
                "CARGO_BUILD_RUSTC_WORKSPACE_WRAPPER",
                self.root.join("forbidden-wrapper"),
            )
            .env("CARGO_ENCODED_RUSTFLAGS", "--invalid-ambient-flag")
            .env("RUSTFLAGS", "--also-invalid")
            .env("CARGO_BUILD_RUSTFLAGS", "--not-the-benchmark")
            .env("CARGO_CACHE_AUTO_CLEAN_FREQUENCY", "always")
            .stdin(Stdio::null())
            .stdout(fs::File::create(self.root.join("child.stdout")).unwrap())
            .stderr(fs::File::create(self.root.join("child.stderr")).unwrap());
        command
    }

    fn finish(&self, command: &mut Command) -> Value {
        let mut child = OwnedChild(command.spawn().unwrap());
        let deadline = Instant::now() + Duration::from_secs(120);
        let status: ExitStatus = loop {
            if let Some(status) = child.0.try_wait().unwrap() {
                break status;
            }
            assert!(
                Instant::now() < deadline,
                "benchmark child exceeded fixture deadline"
            );
            std::thread::sleep(Duration::from_millis(10));
        };
        assert!(
            status.success(),
            "child failed {status}: stdout={} stderr={}",
            fs::read_to_string(self.root.join("child.stdout")).unwrap(),
            fs::read_to_string(self.root.join("child.stderr")).unwrap(),
        );
        self.assert_protected();
        serde_json::from_slice(&fs::read(self.root.join("result.json")).unwrap()).unwrap()
    }

    fn run(&self, mode: &str) -> Value {
        self.finish(&mut self.child(mode))
    }

    fn count(&self) -> usize {
        match fs::read_to_string(self.root.join("calls/count")) {
            Ok(text) => text.trim().parse().unwrap(),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => 0,
            Err(error) => panic!("cannot inspect calls: {error}"),
        }
    }

    fn call(&self, index: usize, field: &str) -> String {
        fs::read_to_string(self.root.join(format!("calls/{index}.{field}"))).unwrap()
    }

    fn assert_protected(&self) {
        for name in ["target", "build"] {
            let protected = self.root.join("protected").join(name);
            assert_eq!(fs::read(protected.join("sentinel")).unwrap(), PROTECTED);
            assert_eq!(
                fs::read_dir(protected).unwrap().count(),
                1,
                "no shared output writes"
            );
        }
        assert!(!self.root.join("unexpected-wrapper").exists());
        assert!(self.directory.path().exists());
    }
}

fn ambient_state() -> Vec<(String, Option<OsString>)> {
    [
        "CARGO_TARGET_DIR",
        "CARGO_BUILD_TARGET_DIR",
        "CARGO_BUILD_BUILD_DIR",
        "CARGO_HOME",
        "RUSTC",
        "CARGO_BUILD_RUSTC",
        "RUSTC_WRAPPER",
        "RUSTC_WORKSPACE_WRAPPER",
        "CARGO_BUILD_RUSTC_WRAPPER",
        "CARGO_BUILD_RUSTC_WORKSPACE_WRAPPER",
        "CARGO_ENCODED_RUSTFLAGS",
        "RUSTFLAGS",
        "CARGO_BUILD_RUSTFLAGS",
        "CARGO_CACHE_AUTO_CLEAN_FREQUENCY",
    ]
    .into_iter()
    .map(|name| (name.to_owned(), std::env::var_os(name)))
    .collect()
}

#[test]
#[ignore = "internal child entry point: requires isolated fixture environment"]
fn compilation_isolation_child() {
    let root = PathBuf::from(std::env::var_os("RCH_BENCH_FIXTURE").expect("fixture root"));
    let mode = std::env::var("RCH_BENCH_FIXTURE_MODE").expect("fixture mode");
    let before = ambient_state();
    let (cargo, rustc) = if mode == "real" {
        (
            PathBuf::from(std::env::var_os("RCH_BENCH_REAL_CARGO").expect("real Cargo path")),
            PathBuf::from(std::env::var_os("RCH_BENCH_REAL_RUSTC").expect("real rustc path")),
        )
    } else if mode == "relative" {
        (
            PathBuf::from("tools/cargo recorder"),
            PathBuf::from("tools/selected rustc"),
        )
    } else {
        (
            root.join("tools/cargo recorder"),
            root.join("tools/selected rustc"),
        )
    };
    let mut benchmark = CompilationBenchmark::new()
        .with_cargo_path(cargo)
        .with_rustc_path(rustc);
    if mode == "stable" || mode == "real" {
        benchmark = benchmark
            .with_debug(false)
            .with_incremental(false)
            .with_warmup(false);
    }
    let result = if mode == "stable" {
        benchmark.run_stable(3)
    } else {
        benchmark.run()
    };
    let json = match result {
        Ok(measurement) => serde_json::json!({"measurement": measurement}),
        Err(error) => serde_json::json!({"error": error}),
    };
    assert_eq!(
        ambient_state(),
        before,
        "benchmark mutated its caller's environment"
    );
    fs::write(root.join("result.json"), serde_json::to_vec(&json).unwrap()).unwrap();
}

#[test]
fn phases_are_isolated_and_only_the_incremental_pair_reuses_outputs() {
    let fixture = Fixture::new();
    let result = fixture.run("success");
    assert!(result.get("measurement").is_some(), "{result}");
    assert_eq!(fixture.count(), 5);
    let mut roots = BTreeSet::new();
    for (index, phase) in ["warmup", "debug", "release", "incremental", "incremental"]
        .into_iter()
        .enumerate()
    {
        let n = index + 1;
        assert_eq!(fixture.call(n, "phase").trim(), phase);
        let root = PathBuf::from(fixture.call(n, "cwd").trim());
        assert!(root.starts_with(fixture.root.join("scratch")));
        roots.insert(root.clone());
        assert_eq!(
            fixture.call(n, "compiler").trim(),
            fixture.root.join("sysroot/bin/rustc").to_str().unwrap()
        );
        assert_eq!(
            fixture.call(n, "state"),
            if n == 5 { "seeded" } else { "cold" }
        );
        assert_eq!(
            fixture.call(n, "incremental").trim(),
            if n >= 4 { "1" } else { "0" }
        );
        let args = fixture.call(n, "args");
        let build_dir = format!(
            "build.build-dir={}",
            serde_json::to_string(root.join("target").to_str().unwrap()).unwrap()
        );
        assert!(args.lines().any(|line| line == build_dir));
        assert!(
            args.lines()
                .any(|line| line == "cache.auto-clean-frequency=\"never\"")
        );
    }
    assert_eq!(roots.len(), 4);
    let original = fixture.call(1, "source");
    for n in 2..=4 {
        assert_eq!(fixture.call(n, "source"), original);
    }
    let rebuilt = fixture.call(5, "source");
    assert!(rebuilt.starts_with(&original) && rebuilt.contains("// touched:"));
}

#[test]
fn independent_stable_iterations_have_disjoint_target_roots() {
    let fixture = Fixture::new();
    let result = fixture.run("stable");
    assert!(result.get("measurement").is_some(), "{result}");
    assert_eq!(fixture.count(), 3);
    let roots: BTreeSet<_> = (1..=3).map(|n| fixture.call(n, "cwd")).collect();
    assert_eq!(roots.len(), 3);
    for n in 1..=3 {
        assert_eq!(fixture.call(n, "state"), "cold");
        assert_eq!(fixture.call(n, "phase").trim(), "release");
    }
}

#[test]
fn caller_relative_tool_paths_survive_switching_to_private_projects() {
    let fixture = Fixture::new();
    let result = fixture.run("relative");
    assert!(result.get("measurement").is_some(), "{result}");
    assert_eq!(fixture.count(), 5);
}

#[test]
fn compiler_identity_mismatch_stops_before_any_cargo_invocation() {
    let fixture = Fixture::new();
    let result = fixture.run("mismatch");
    assert!(
        result["error"]["message"]
            .as_str()
            .unwrap()
            .contains("identities differ")
    );
    assert_eq!(fixture.count(), 0);
}

#[test]
fn failed_warmups_and_unproven_outputs_never_become_measurements() {
    for (mode, count, phase) in [
        ("fail-warmup", 1, "debug_build"),
        ("fail-release", 3, "release_build"),
        ("missing-output", 1, "debug_build"),
        ("symlink-output", 1, "debug_build"),
    ] {
        let fixture = Fixture::new();
        let result = fixture.run(mode);
        assert!(result.get("measurement").is_none(), "{mode}: {result}");
        assert_eq!(result["error"]["phase"], phase);
        assert_eq!(fixture.count(), count);
        if mode.starts_with("fail-") {
            assert!(
                result["error"]["stderr"]
                    .as_str()
                    .unwrap()
                    .contains("fixture-build-failed")
            );
        }
    }
}

#[test]
#[ignore = "runs real Cargo/rustc; explicitly select on an idle or admitted machine"]
fn real_cargo_preserves_unrelated_target_build_and_wrapper_state() {
    let fixture = Fixture::new();
    // Resolve in the unmodified caller environment, not inside the synthetic
    // CARGO_HOME. The child then executes the actual production public API.
    let probe = Command::new("rustc")
        .arg("--print=sysroot")
        .output()
        .unwrap();
    assert!(
        probe.status.success(),
        "{}",
        String::from_utf8_lossy(&probe.stderr)
    );
    let sysroot = PathBuf::from(String::from_utf8(probe.stdout).unwrap().trim());
    assert!(sysroot.is_absolute());
    let mut child = fixture.child("real");
    child
        .env("RCH_BENCH_REAL_RUSTC", sysroot.join("bin/rustc"))
        .env("RCH_BENCH_REAL_CARGO", env!("CARGO"));
    let result = fixture.finish(&mut child);
    assert!(result.get("measurement").is_some(), "{result}");
    assert!(result["measurement"]["release_build_ms"].as_u64().unwrap() > 0);
    assert_eq!(
        fixture.count(),
        0,
        "the real test must not invoke synthetic Cargo"
    );
}
