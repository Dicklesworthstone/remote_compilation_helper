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
        for directory in ["bin", "work", "home"] {
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

    fn worker_command(&self, workload: &str, command_status: &str) -> Command {
        let mut command = Command::new(env!("CARGO_BIN_EXE_rch-wkr"));
        command
            .args(["execute", "--workdir"])
            .arg(self.path("work"))
            .args(["--command", workload])
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
            .env("RCH_TEST_COMMAND_STATUS", command_status)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        command
    }

    fn run(&self, toolchain: Option<&str>, command_status: &str) -> Output {
        let mut command = self.worker_command(USER_COMMAND, command_status);
        // These fixtures write only a few KiB. Exercise the real guard
        // with an explicit small budget without depending on host GiB.
        command.args([
            "--disk-budget-bytes",
            "8388608",
            "--disk-min-free-bytes",
            "1048576",
        ]);
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
                let mut command = fixture.worker_command("sh ./job.sh", &exit_code.to_string());
                command.env("RCH_REQUIRE_REMOTE", "1");
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
