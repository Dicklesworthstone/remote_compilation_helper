//! Exercise the actual worker CLI with isolated rustup/cargo executables.
//! No real compiler installation, network access, or process-global env edits.
#![cfg(unix)]

use std::fs;
use std::os::unix::fs::{PermissionsExt, symlink};
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::time::{Duration, Instant};

const TOOLCHAIN: &str = "nightly-2024-01-15";
const USER_COMMAND: &str = "cargo build --features 'feature with spaces' --release";

const RUSTUP: &str = r#"#!/bin/sh
set -eu
case "$1" in
    --version)
        printf 'version\n' >> "$RCH_TEST_STATE/events"
        [ "$RCH_TEST_MODE" != unavailable ] || exit 1
        printf 'rustup fixture\n'
        ;;
    run)
        shift
        [ "$1" = "$RCH_TEST_TOOLCHAIN" ] || exit 90
        selected=$1
        shift
        if [ "$#" = 2 ] && [ "$1" = rustc ] && [ "$2" = --version ]; then
            printf 'probe\n' >> "$RCH_TEST_STATE/events"
            case "$RCH_TEST_MODE" in
                available) ;;
                installable) [ -f "$RCH_TEST_STATE/installed" ] || exit 1;;
                *) exit 1;;
            esac
            printf 'rustc fixture\n'
        else
            printf 'execute\n' >> "$RCH_TEST_STATE/events"
            case "$RCH_TEST_MODE" in
                available) ;;
                installable) [ -f "$RCH_TEST_STATE/installed" ] || exit 1;;
                *) exit 1;;
            esac
            RCH_TEST_SELECTED_TOOLCHAIN=$selected
            export RCH_TEST_SELECTED_TOOLCHAIN
            exec "$@"
        fi
        ;;
    toolchain)
        [ "$#" = 5 ] && [ "$2" = install ] &&
            [ "$3" = "$RCH_TEST_TOOLCHAIN" ] &&
            [ "$4" = --profile ] && [ "$5" = minimal ] || exit 91
        printf 'install\n' >> "$RCH_TEST_STATE/events"
        if [ "$RCH_TEST_MODE" = install_failure ]; then
            printf 'fixture: install rejected\n' >&2
            exit 1
        fi
        : > "$RCH_TEST_STATE/installed"
        ;;
    *) exit 92;;
esac
"#;

const CARGO: &str = r#"#!/bin/sh
set -eu
printf '%s\n' "${RCH_TEST_SELECTED_TOOLCHAIN:-default}" "$@" >> "$RCH_TEST_STATE/cargo"
printf '%s|%s\n' "${RCH_CARGO_WRAPPER_BYPASS-unset}" "${RCH_CARGO_WRAPPER_ORIGIN-unset}" >> "$RCH_TEST_STATE/markers"
printf 'fixture compiler output\n'
if [ "$RCH_TEST_COMMAND_STATUS" = signal ]; then
    kill -TERM "$$"
    exit 99
fi
exit "$RCH_TEST_COMMAND_STATUS"
"#;

struct Fixture {
    root: tempfile::TempDir,
    mode: &'static str,
}

fn executable(path: &Path, source: &str) {
    fs::write(path, source).expect("write fixture executable");
    fs::set_permissions(path, fs::Permissions::from_mode(0o755)).expect("set executable mode");
}

impl Fixture {
    fn new(mode: &'static str) -> Self {
        let root = tempfile::tempdir().expect("create fixture");
        for directory in ["bin", "work", "home", "home/.rustup"] {
            fs::create_dir(root.path().join(directory)).expect("create fixture directory");
        }
        // PATH contains only fixtures, so even an installed host rustup cannot
        // repair a deliberately missing executable or contact the network.
        symlink("/bin/sh", root.path().join("bin/sh")).expect("provide worker's shell");
        let python = std::env::var_os("PATH")
            .into_iter()
            .flat_map(|paths| std::env::split_paths(&paths).collect::<Vec<_>>())
            .map(|path| path.join("python3"))
            .find(|path| path.is_file())
            .and_then(|path| fs::canonicalize(path).ok())
            .expect("guarded worker integration tests require Python 3.8+");
        symlink(python, root.path().join("bin/python3"))
            .expect("provide the stdlib-only disk supervisor");
        executable(&root.path().join("bin/cargo"), CARGO);
        if mode != "missing" {
            executable(&root.path().join("bin/rustup"), RUSTUP);
        }
        Self { root, mode }
    }

    fn path(&self, name: &str) -> PathBuf {
        self.root.path().join(name)
    }

    fn worker_command(&self) -> Command {
        let mut command = Command::new(env!("CARGO_BIN_EXE_rch-wkr"));
        command
            .env_clear()
            .env("PATH", self.path("bin"))
            .env("HOME", self.path("home"))
            .env("XDG_CACHE_HOME", self.path("home/.cache"))
            .env("XDG_CONFIG_HOME", self.path("home/.config"))
            .env("XDG_STATE_HOME", self.path("home/.local/state"))
            .env("RUSTUP_HOME", self.path("home/.rustup"))
            .env("CARGO_HOME", self.path("home/.cargo"))
            .env("LC_ALL", "C")
            .env("TOKIO_WORKER_THREADS", "2")
            .env("RCH_TEST_STATE", self.root.path())
            .env("RCH_TEST_MODE", self.mode)
            .env("RCH_TEST_TOOLCHAIN", TOOLCHAIN)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        command
    }

    fn run(&self, toolchain: Option<&str>, command_status: &str) -> Output {
        let mut command = self.worker_command();
        command
            .args(["execute", "--workdir"])
            .arg(self.path("work"))
            .args(["--command", USER_COMMAND])
            // These fixtures write only a few KiB. Exercise the real guard
            // with an explicit small budget without depending on host GiB.
            .args([
                "--disk-budget-bytes",
                "8388608",
                "--disk-min-free-bytes",
                "1048576",
            ])
            .env("RCH_TEST_COMMAND_STATUS", command_status);
        if let Some(toolchain) = toolchain {
            command.args(["--toolchain", toolchain]);
        }
        Self::collect(command)
    }

    fn collect(mut command: Command) -> Output {
        let mut child = command.spawn().expect("start worker CLI");
        let started = Instant::now();
        loop {
            if child.try_wait().expect("poll worker").is_some() {
                return child.wait_with_output().expect("collect worker output");
            }
            if started.elapsed() >= Duration::from_secs(20) {
                let _ = child.kill();
                let output = child.wait_with_output().expect("reap timed-out worker");
                panic!("worker fixture timed out: {output:?}");
            }
            std::thread::sleep(Duration::from_millis(10));
        }
    }

    fn events(&self) -> Vec<String> {
        match fs::read_to_string(self.path("events")) {
            Ok(text) => text.lines().map(str::to_owned).collect(),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Vec::new(),
            Err(error) => panic!("read fixture events: {error}"),
        }
    }

    fn assert_not_run(&self, output: &Output) {
        assert!(!output.status.success(), "unexpected success: {output:?}");
        assert!(
            !self.path("cargo").exists(),
            "default compiler was executed"
        );
        assert!(
            !self.events().iter().any(|event| event == "execute"),
            "a user-command dispatch was attempted after preparation failure"
        );
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(stderr.contains(TOOLCHAIN), "missing toolchain: {stderr}");
        assert!(
            stderr.contains("command was not run"),
            "missing boundary: {stderr}"
        );
    }

    fn assert_compiler(&self, selected: &str) {
        // Exact arguments, compiler selection, and a single execution. A
        // second fallback execution would append another complete record.
        assert_eq!(
            fs::read_to_string(self.path("cargo")).expect("compiler execution record"),
            format!("{selected}\nbuild\n--features\nfeature with spaces\n--release\n")
        );
    }
}

#[test]
fn missing_rustup_does_not_execute_with_the_default_compiler() {
    let fixture = Fixture::new("missing");
    let output = fixture.run(Some(TOOLCHAIN), "0");
    fixture.assert_not_run(&output);
    assert!(fixture.events().is_empty());
}

#[test]
fn failed_rustup_probe_does_not_execute_with_the_default_compiler() {
    let fixture = Fixture::new("unavailable");
    let output = fixture.run(Some(TOOLCHAIN), "0");
    fixture.assert_not_run(&output);
    assert_eq!(fixture.events(), ["version"]);
}

#[test]
fn failed_install_does_not_execute_with_the_default_compiler() {
    let fixture = Fixture::new("install_failure");
    let output = fixture.run(Some(TOOLCHAIN), "0");
    fixture.assert_not_run(&output);
    assert_eq!(fixture.events(), ["version", "probe", "install"]);
    assert!(String::from_utf8_lossy(&output.stderr).contains("fixture: install rejected"));
}

#[test]
fn installer_success_without_a_runnable_compiler_is_rejected() {
    let fixture = Fixture::new("broken_install");
    let output = fixture.run(Some(TOOLCHAIN), "0");
    fixture.assert_not_run(&output);
    // This must be a real post-install probe, not the cache entry previously
    // created merely because the installer returned zero.
    assert_eq!(fixture.events(), ["version", "probe", "install", "probe"]);
    assert!(String::from_utf8_lossy(&output.stderr).contains("not available after installation"));
}

#[test]
fn existing_toolchain_runs_once_with_exact_arguments() {
    let fixture = Fixture::new("available");
    let output = fixture.run(Some(TOOLCHAIN), "0");
    assert!(output.status.success(), "{output:?}");
    assert_eq!(fixture.events(), ["version", "probe", "execute"]);
    fixture.assert_compiler(TOOLCHAIN);
    assert_eq!(output.stdout.as_slice(), b"fixture compiler output\n");
}

#[test]
fn installed_toolchain_is_probed_before_user_command_dispatch() {
    let fixture = Fixture::new("installable");
    let output = fixture.run(Some(TOOLCHAIN), "0");
    assert!(output.status.success(), "{output:?}");
    assert_eq!(
        fixture.events(),
        ["version", "probe", "install", "probe", "execute"]
    );
    fixture.assert_compiler(TOOLCHAIN);
}

#[test]
fn compiler_failure_is_preserved_without_default_compiler_retry() {
    let fixture = Fixture::new("available");
    let output = fixture.run(Some(TOOLCHAIN), "101");
    assert_eq!(output.status.code(), Some(101), "{output:?}");
    assert_eq!(fixture.events(), ["version", "probe", "execute"]);
    fixture.assert_compiler(TOOLCHAIN);
}

#[test]
fn compiler_signal_is_preserved_without_default_compiler_retry() {
    let fixture = Fixture::new("available");
    let output = fixture.run(Some(TOOLCHAIN), "signal");
    assert_eq!(output.status.code(), Some(143), "{output:?}");
    assert_eq!(fixture.events(), ["version", "probe", "execute"]);
    fixture.assert_compiler(TOOLCHAIN);
}

#[test]
fn no_requested_toolchain_preserves_default_execution_without_rustup() {
    let fixture = Fixture::new("missing");
    let output = fixture.run(None, "0");
    assert!(output.status.success(), "{output:?}");
    assert!(fixture.events().is_empty());
    fixture.assert_compiler("default");
}

#[test]
fn plain_and_guarded_worker_jobs_stamp_provenance_for_every_cargo_child() {
    // A dual-role worker may inherit the reported stale BYPASS=1 without its
    // origin, neither marker, or conflicting caller values. The executor must
    // establish its own pair after remote admission in every case. Merely
    // forwarding the caller's environment would fail the marker assertions.
    for guarded in [false, true] {
        for (bypass, origin) in [
            (None, None),
            (Some("1"), None),
            (Some("1"), Some("")),
            (Some("0"), Some("caller")),
            (None, Some("rch")),
        ] {
            for exit_code in [0, 101] {
                let fixture = Fixture::new("missing");
                // The outer command deliberately contains no compilation
                // keyword, so omitting --disk-budget-bytes really exercises
                // the executor's plain shell path rather than automatic Cargo
                // disk admission. Each Cargo below is a separate subprocess.
                fs::write(
                    fixture.path("work/job.sh"),
                    r#"#!/bin/sh
set -eu
printf '%s|%s\n' "${RCH_CARGO_WRAPPER_BYPASS-unset}" "${RCH_CARGO_WRAPPER_ORIGIN-unset}" > "$RCH_TEST_STATE/job-markers"
RCH_TEST_COMMAND_STATUS=0 cargo --version
sh -c 'RCH_TEST_COMMAND_STATUS=0 cargo test --features "feature with spaces"'
cargo build --release
"#,
                )
                .expect("write worker job");
                let mut command = fixture.worker_command();
                command
                    .args(["execute", "--workdir"])
                    .arg(fixture.path("work"))
                    .args(["--command", "sh ./job.sh"])
                    .env("RCH_TEST_COMMAND_STATUS", exit_code.to_string())
                    .env("RCH_REQUIRE_REMOTE", "1");
                if let Some(value) = bypass {
                    command.env("RCH_CARGO_WRAPPER_BYPASS", value);
                }
                if let Some(value) = origin {
                    command.env("RCH_CARGO_WRAPPER_ORIGIN", value);
                }
                if guarded {
                    command.args([
                        "--disk-budget-bytes",
                        "8388608",
                        "--disk-min-free-bytes",
                        "1048576",
                    ]);
                }
                let output = Fixture::collect(command);
                assert_eq!(
                    output.status.code(),
                    Some(exit_code),
                    "guarded={guarded}, bypass={bypass:?}, origin={origin:?}: {output:?}"
                );
                assert_eq!(
                    fs::read_to_string(fixture.path("job-markers")).unwrap(),
                    "1|rch\n",
                    "the outer job must receive the managed pair"
                );
                assert_eq!(
                    fs::read_to_string(fixture.path("markers")).unwrap(),
                    "1|rch\n1|rch\n1|rch\n",
                    "each shell descendant must inherit the complete pair"
                );
                assert_eq!(
                    fs::read_to_string(fixture.path("cargo")).unwrap(),
                    "default\n--version\ndefault\ntest\n--features\nfeature with spaces\ndefault\nbuild\n--release\n",
                    "Cargo arguments and invocation count must be conserved"
                );
                assert_eq!(
                    output.stdout.as_slice(),
                    b"fixture compiler output\nfixture compiler output\nfixture compiler output\n",
                    "worker output must be preserved"
                );
                assert!(
                    fixture.events().is_empty(),
                    "no recursive toolchain dispatch"
                );
            }
        }
    }
}

// These executables are explicit test doubles. The real worker CLI, shell,
// disk supervisor, timeout, and environment propagation are exercised here;
// the generated production shims have their own integration coverage in rch.
const MANAGED_CARGO: &str = r#"#!/bin/sh
set -eu
if [ "$0" = "$RCH_TEST_STATE/bin/cargo" ]; then
    route=PATH
else
    route=toolchain
fi
printf '%s|%s|%s' "$route" "${RCH_CARGO_WRAPPER_BYPASS:-unset}" "${RCH_CARGO_WRAPPER_ORIGIN:-unset}" >> "$RCH_TEST_STATE/cargo-probes"
for arg in "$@"; do printf '|%s' "$arg" >> "$RCH_TEST_STATE/cargo-probes"; done
printf '\n' >> "$RCH_TEST_STATE/cargo-probes"
if [ "${RCH_CARGO_WRAPPER_BYPASS:-}" != 1 ] || [ "${RCH_CARGO_WRAPPER_ORIGIN:-}" != rch ]; then
    printf 'fixture: missing managed Cargo environment\n' >&2
    exit 91
fi
case "${RCH_TEST_PROBE_MODE:-ok}:$route" in
    path_refusal:PATH|toolchain_refusal:toolchain)
        printf 'fixture: incompatible Cargo wrapper\n' >&2
        exit 1
        ;;
    timeout:PATH)
        printf '%s\n' "$$" > "$RCH_TEST_STATE/probe-pid"
        exec python3 -c 'import time; time.sleep(30)'
        ;;
    oversized:PATH)
        exec python3 -c 'import sys; sys.stdout.write("x" * 32768)'
        ;;
esac
printf 'cargo 1.99.0 (fixture)\n'
"#;

const CAPABILITY_RUSTUP: &str = r#"#!/bin/sh
set -eu
case "$1" in
    which)
        [ "$#" = 2 ] && [ "$2" = cargo ] || exit 92
        [ "${RCH_CARGO_WRAPPER_BYPASS:-}" = 1 ] && [ "${RCH_CARGO_WRAPPER_ORIGIN:-}" = rch ] || exit 93
        printf '%s\n' "$RCH_TEST_STATE/toolchain bin/cargo"
        ;;
    toolchain)
        [ "$#" = 2 ] && [ "$2" = list ] || exit 94
        # No installed inventory entries are needed for this execution check.
        ;;
    *) exit 95;;
esac
"#;

impl Fixture {
    fn prepare_managed_cargo(&self) {
        fs::create_dir(self.path("toolchain bin")).expect("create direct Cargo directory");
        executable(&self.path("bin/cargo"), MANAGED_CARGO);
        executable(&self.path("toolchain bin/cargo"), MANAGED_CARGO);
    }

    fn cargo_probes(&self) -> String {
        fs::read_to_string(self.path("cargo-probes")).expect("read Cargo execution records")
    }

    fn capability_command(&self, mode: &str) -> Command {
        self.prepare_managed_cargo();
        executable(&self.path("bin/rustup"), CAPABILITY_RUSTUP);
        executable(
            &self.path("bin/rustc"),
            "#!/bin/sh\nprintf 'rustc 1.99.0 (fixture)\\n'\n",
        );
        executable(&self.path("bin/node"), "#!/bin/sh\nprintf 'v20.11.0\\n'\n");
        executable(&self.path("bin/npm"), "#!/bin/sh\nexit 1\n");
        let mut command = self.worker_command();
        command
            .arg("capabilities")
            .current_dir(self.path("work"))
            .env("RCH_REQUIRE_REMOTE", "1")
            .env("RCH_CARGO_WRAPPER_BYPASS", "0")
            .env("RCH_CARGO_WRAPPER_ORIGIN", "caller")
            .env("RCH_TEST_PROBE_MODE", mode)
            .env("RCH_WKR_CANONICAL_ROOT", self.path("work"))
            .env("RCH_WKR_ALIAS_ROOT", self.path("work"));
        command
    }

    fn capabilities(&self, mode: &str) -> (rch_common::WorkerCapabilities, Duration) {
        let command = self.capability_command(mode);
        let started = Instant::now();
        let output = Self::collect(command);
        assert!(output.status.success(), "{output:?}");
        let capabilities = serde_json::from_slice(&output.stdout).expect("worker capability JSON");
        (capabilities, started.elapsed())
    }
}

#[test]
fn opaque_worker_jobs_stamp_both_markers_for_shell_and_disk_guard() {
    for guarded in [false, true] {
        for (bypass, origin) in [("0", "caller"), ("1", "")] {
            let fixture = Fixture::new("available");
            fixture.prepare_managed_cargo();
            executable(
                &fixture.path("work/job.sh"),
                "#!/bin/sh\nset -eu\ncargo test -- 'filter with spaces'\n\"$RCH_TEST_STATE/toolchain bin/cargo\" --version\n",
            );
            let mut command = fixture.worker_command();
            command
                .args(["execute", "--workdir"])
                .arg(fixture.path("work"))
                // The worker cannot infer Cargo from this opaque command.
                .args(["--command", "sh job.sh"])
                .env("RCH_REQUIRE_REMOTE", "1")
                .env("RCH_CARGO_WRAPPER_BYPASS", bypass)
                .env("RCH_CARGO_WRAPPER_ORIGIN", origin);
            if guarded {
                command.args([
                    "--disk-budget-bytes",
                    "8388608",
                    "--disk-min-free-bytes",
                    "1048576",
                ]);
            }
            let output = Fixture::collect(command);
            assert!(
                output.status.success(),
                "guarded={guarded} inherited={bypass}/{origin}: {output:?}"
            );
            assert_eq!(
                fixture.cargo_probes(),
                "PATH|1|rch|test|--|filter with spaces\ntoolchain|1|rch|--version\n"
            );
            assert_eq!(fixture.path("work/.rch-run").exists(), guarded);
        }
    }
}

#[test]
fn worker_capabilities_execute_path_and_direct_toolchain_cargo() {
    let fixture = Fixture::new("available");
    let (capabilities, _) = fixture.capabilities("ok");
    assert!(capabilities.has_rust(), "{capabilities:?}");
    assert!(
        !capabilities
            .probe_warnings
            .iter()
            .any(|warning| warning.contains("Cargo execution check failed")),
        "{capabilities:?}"
    );
    assert_eq!(
        fixture.cargo_probes(),
        "PATH|1|rch|--version\ntoolchain|1|rch|--version\n"
    );
}

#[test]
fn declared_tool_probes_stamp_both_markers_for_cargo_descendants() {
    for (bypass, origin) in [
        (None, None),
        (Some("1"), None),
        (Some("1"), Some("")),
        (Some("0"), Some("caller")),
        (None, Some("rch")),
    ] {
        let fixture = Fixture::new("available");
        let mut command = fixture.capability_command("ok");
        let probes = serde_json::json!([
            {"name": "cargo-path", "command": ["cargo", "--version"]},
            {
                "name": "cargo-toolchain",
                "command": [fixture.path("toolchain bin/cargo"), "--version"]
            },
            {
                "name": "cargo-nested",
                "command": ["sh", "-c", "cargo --version && sh -c 'cargo --version'"]
            },
            {
                "name": "cargo-failing",
                "command": ["sh", "-c", "cargo --version && exit 23"]
            }
        ]);
        command.args(["--tool-probe", &probes.to_string()]);
        for (key, value) in [
            ("RCH_CARGO_WRAPPER_BYPASS", bypass),
            ("RCH_CARGO_WRAPPER_ORIGIN", origin),
        ] {
            match value {
                Some(value) => command.env(key, value),
                None => command.env_remove(key),
            };
        }

        let output = Fixture::collect(command);
        assert!(output.status.success(), "{bypass:?}/{origin:?}: {output:?}");
        let capabilities: rch_common::WorkerCapabilities =
            serde_json::from_slice(&output.stdout).expect("worker capability JSON");
        assert!(capabilities.has_rust(), "{capabilities:?}");
        assert_eq!(
            capabilities.tools_present,
            ["cargo-path", "cargo-toolchain", "cargo-nested"],
            "{bypass:?}/{origin:?}: {capabilities:?}"
        );
        assert_eq!(capabilities.tools_absent, ["cargo-failing"]);
        assert_eq!(
            fixture.cargo_probes(),
            concat!(
                "PATH|1|rch|--version\ntoolchain|1|rch|--version\n",
                "PATH|1|rch|--version\ntoolchain|1|rch|--version\n",
                "PATH|1|rch|--version\nPATH|1|rch|--version\n",
                "PATH|1|rch|--version\n",
            ),
            "{bypass:?}/{origin:?}"
        );
    }
}

#[test]
fn declared_tool_probe_deadline_preserves_partial_facts_and_reaps_owned_child() {
    let fixture = Fixture::new("available");
    let mut command = fixture.capability_command("ok");
    // The finite sleeper exceeds the named-probe phase budget but stays below
    // this harness's outer timeout. The old blocking implementation therefore
    // fails this test after naturally reaping its child, without leaking it.
    let sleeper = r#"import os, pathlib, time
state = pathlib.Path(os.environ["RCH_TEST_STATE"])
(state / "named-probe-pid").write_text(str(os.getpid()))
(state / "named-probe-markers").write_text(
    os.environ.get("RCH_CARGO_WRAPPER_BYPASS", "unset") + "|" +
    os.environ.get("RCH_CARGO_WRAPPER_ORIGIN", "unset"))
time.sleep(12)
"#;
    let late_probe = r#"import os, pathlib
pathlib.Path(os.environ["RCH_TEST_STATE"], "late-probe-started").write_text("started")
"#;
    let probes = serde_json::json!([
        {"name": "healthy-tool", "command": ["sh", "-c", "exit 0"]},
        {"name": "hung-tool", "command": ["python3", "-I", "-c", sleeper]},
        {"name": "late-tool", "command": ["python3", "-I", "-c", late_probe]}
    ]);
    command.args(["--tool-probe", &probes.to_string()]);

    let started = Instant::now();
    let output = Fixture::collect(command);
    let elapsed = started.elapsed();
    assert!(output.status.success(), "{output:?}");
    let capabilities: rch_common::WorkerCapabilities =
        serde_json::from_slice(&output.stdout).expect("worker capability JSON");
    assert!(elapsed < Duration::from_secs(10), "{elapsed:?}");
    assert!(capabilities.has_rust(), "{capabilities:?}");
    assert!(capabilities.has_node(), "{capabilities:?}");
    assert_eq!(capabilities.tools_present, ["healthy-tool"]);
    assert!(capabilities.tools_absent.is_empty(), "{capabilities:?}");
    assert_eq!(capabilities.tools_pending, ["hung-tool", "late-tool"]);
    for name in ["hung-tool", "late-tool"] {
        assert!(
            capabilities.probe_warnings.iter().any(|warning| {
                warning.contains(name)
                    && (warning.contains("timed out")
                        || warning.contains("deadline")
                        || warning.contains("budget"))
            }),
            "missing deadline diagnostic for {name}: {capabilities:?}"
        );
    }
    assert!(
        !fixture.path("late-probe-started").exists(),
        "the shared deadline must prevent later declarations from starting"
    );
    assert_eq!(
        fs::read_to_string(fixture.path("named-probe-markers")).unwrap(),
        "1|rch"
    );
    let pid = fs::read_to_string(fixture.path("named-probe-pid")).expect("owned probe PID");
    assert!(pid.parse::<u32>().expect("numeric probe PID") > 1);
    // kill(0) observes zombies too, so ESRCH confirms the foreground child
    // was reaped. Inspecting /proc by PID is unreliable in nested namespaces.
    let reaped = Command::new(fixture.path("bin/python3"))
        .args([
            "-I",
            "-c",
            "import os, sys\ntry:\n    os.kill(int(sys.argv[1]), 0)\nexcept ProcessLookupError:\n    pass\nelse:\n    raise SystemExit('named probe is still alive or unreaped')\n",
            &pid,
        ])
        .status()
        .expect("inspect owned probe lifecycle");
    assert!(
        reaped.success(),
        "owned named probe must be killed and reaped"
    );
}

#[test]
fn declared_tool_probes_discard_large_non_utf8_output_and_use_exit_status() {
    let fixture = Fixture::new("available");
    let mut command = fixture.capability_command("ok");
    // Named probes are fixed argv judged only by status. Their output is not
    // a version string and must not enter the Cargo/inventory output parser.
    let noisy_probe = r#"import os, sys
assert os.read(0, 1) == b""
assert os.environ["RCH_CARGO_WRAPPER_BYPASS"] == "1"
assert os.environ["RCH_CARGO_WRAPPER_ORIGIN"] == "rch"
os.write(1, b"\xff" * 65536)
os.write(2, b"\xfe" * 65536)
sys.exit(int(sys.argv[1]))
"#;
    let probes = serde_json::json!([
        {"name": "loud-success", "command": ["python3", "-I", "-c", noisy_probe, "0"]},
        {"name": "loud-failure", "command": ["python3", "-I", "-c", noisy_probe, "23"]},
        {"name": "missing", "command": ["rch-no-such-declared-tool-fixture"]}
    ]);
    command.args(["--tool-probe", &probes.to_string()]);

    let output = Fixture::collect(command);
    assert!(output.status.success(), "{output:?}");
    let capabilities: rch_common::WorkerCapabilities =
        serde_json::from_slice(&output.stdout).expect("only capability JSON reaches stdout");
    assert!(capabilities.has_rust(), "{capabilities:?}");
    assert!(capabilities.has_node(), "{capabilities:?}");
    assert_eq!(capabilities.tools_present, ["loud-success"]);
    assert_eq!(capabilities.tools_absent, ["loud-failure", "missing"]);
    assert!(capabilities.tools_pending.is_empty(), "{capabilities:?}");
    assert!(
        !output.stderr.contains(&0xfe),
        "probe stderr must be discarded"
    );
}

#[test]
fn worker_capabilities_refuse_unusable_cargo_without_hiding_other_runtimes() {
    for (mode, route, expected_probes) in [
        ("path_refusal", "PATH Cargo", "PATH|1|rch|--version\n"),
        (
            "toolchain_refusal",
            "toolchain Cargo",
            "PATH|1|rch|--version\ntoolchain|1|rch|--version\n",
        ),
    ] {
        let fixture = Fixture::new("available");
        let (capabilities, _) = fixture.capabilities(mode);
        assert!(!capabilities.has_rust(), "{capabilities:?}");
        assert!(capabilities.has_node(), "{capabilities:?}");
        let warning = capabilities
            .probe_warnings
            .iter()
            .find(|warning| warning.contains("Cargo execution check failed"))
            .expect("failed execution must have an actionable diagnostic");
        assert!(warning.contains(route), "{warning}");
        assert!(
            warning.contains("fixture: incompatible Cargo wrapper"),
            "{warning}"
        );
        assert!(
            warning.contains("RCH_CARGO_WRAPPER_ORIGIN=rch"),
            "{warning}"
        );
        assert_eq!(fixture.cargo_probes(), expected_probes);
    }
}

#[test]
fn worker_capabilities_bound_and_reap_hung_cargo_probes() {
    let fixture = Fixture::new("available");
    let (capabilities, elapsed) = fixture.capabilities("timeout");
    assert!(!capabilities.has_rust(), "{capabilities:?}");
    assert!(capabilities.has_node(), "{capabilities:?}");
    assert!(
        capabilities.probe_warnings.iter().any(|warning| {
            warning.contains("PATH Cargo command timed out")
                && warning.contains("Cargo execution check failed")
        }),
        "{capabilities:?}"
    );
    assert!(elapsed < Duration::from_secs(12), "{elapsed:?}");
    assert_eq!(fixture.cargo_probes(), "PATH|1|rch|--version\n");
    #[cfg(target_os = "linux")]
    {
        let pid = fs::read_to_string(fixture.path("probe-pid")).expect("hung probe PID");
        assert!(
            !Path::new("/proc").join(pid.trim()).exists(),
            "timed-out Cargo probe must be killed and reaped"
        );
    }
}

#[test]
fn worker_capabilities_bound_cargo_probe_output() {
    let fixture = Fixture::new("available");
    let (capabilities, _) = fixture.capabilities("oversized");
    assert!(!capabilities.has_rust(), "{capabilities:?}");
    assert!(
        capabilities
            .probe_warnings
            .iter()
            .any(|warning| { warning.contains("PATH Cargo output exceeds shared byte limit") }),
        "{capabilities:?}"
    );
    assert_eq!(fixture.cargo_probes(), "PATH|1|rch|--version\n");
}
