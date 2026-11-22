//! Native local-cache frontend processes with explicit worker/Cargo doubles.
//! These exercise the real exec boundary, opaque argv, streams and inherited
//! descriptors. The worker's own tests cover native daemon setup and fallback;
//! these fixtures do not claim compiler cache hits or remote execution.

#![cfg(target_os = "linux")]
#![forbid(unsafe_code)]

use std::ffi::{OsStr, OsString};
use std::fs;
use std::io::Write as _;
use std::os::unix::ffi::{OsStrExt as _, OsStringExt as _};
use std::os::unix::fs::{PermissionsExt as _, symlink};
use std::os::unix::process::ExitStatusExt as _;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

const BINARY: &str = env!("CARGO_BIN_EXE_rabs-cargo");
const SUBCOMMAND: &str = env!("CARGO_BIN_EXE_cargo-rabs");
const INPUT: &[u8] = b"original input\0\xff\n";

fn executable(path: &Path, source: &str) {
    fs::write(path, source).unwrap();
    fs::set_permissions(path, fs::Permissions::from_mode(0o700)).unwrap();
}

struct Fixture {
    root: PathBuf,
    worker: PathBuf,
    cargo: PathBuf,
}

impl Fixture {
    fn new() -> Self {
        let root = tempfile::Builder::new()
            .prefix("rabs-cache-entry-")
            .tempdir()
            .unwrap()
            .keep();
        let worker = root.join("native worker 'α'");
        let cargo = root.join("cargo 'original'");
        executable(
            &worker,
            r#"#!/bin/sh
printf 'worker\n' >> "$CACHE_TEST_ROOT/worker.calls"
printf '%s\0' "$@" > "$CACHE_TEST_ROOT/worker.argv"
printf '%s' "$$" > "$CACHE_TEST_ROOT/worker.pid"
if [ "${CACHE_TEST_WORKER_REFUSE-0}" != 0 ]; then exit "$CACHE_TEST_WORKER_REFUSE"; fi
[ "$1" = worker-cache ] && [ "$2" = --protocol ] && [ "$3" = v1 ] || exit 91
shift 3
while [ "$1" != -- ]; do
    case "$1" in --no-start|--require-daemon) shift ;; *) exit 91 ;; esac
done
shift
exec "$@"
"#,
        );
        executable(
            &cargo,
            r#"#!/bin/sh
printf 'cargo\n' >> "$CACHE_TEST_ROOT/cargo.calls"
printf '%s\0' "$@" > "$CACHE_TEST_ROOT/cargo.argv"
printf '%s\0' "${RUSTUP_TOOLCHAIN-unset}" "${RUSTC_WRAPPER-unset}" "${CARGO_MAKEFLAGS-unset}" "${RCH_RABS_WORKER_ACTIVE-unset}" > "$CACHE_TEST_ROOT/cargo.env"
printf '%s' "$PWD" > "$CACHE_TEST_ROOT/cargo.cwd"
printf '%s' "$0" > "$CACHE_TEST_ROOT/cargo.program"
printf '%s' "$$" > "$CACHE_TEST_ROOT/cargo.pid"
/bin/cat > "$CACHE_TEST_ROOT/cargo.stdin"
if [ -n "${CACHE_TEST_JOB_FD-}" ]; then
    IFS= read -r token <&"$CACHE_TEST_JOB_FD" || exit 92
    printf '%s' "$token" > "$CACHE_TEST_ROOT/cargo.token"
fi
printf 'cargo stdout\000\377\n'
printf 'cargo stderr\000\376\n' >&2
if [ -n "${CACHE_TEST_SIGNAL-}" ]; then kill -s "$CACHE_TEST_SIGNAL" "$$"; exit 93; fi
exit "${CACHE_TEST_EXIT-23}"
"#,
        );
        Self {
            root,
            worker,
            cargo,
        }
    }

    fn command(&self) -> Command {
        self.command_using(BINARY, "--cache")
    }

    fn subcommand(&self) -> Command {
        self.command_using(SUBCOMMAND, "rabs")
    }

    fn command_using(&self, binary: &str, mode: &str) -> Command {
        let mut command = Command::new(binary);
        command
            .arg(mode)
            .env_clear()
            .env("PATH", "/usr/bin:/bin")
            .env("HOME", &self.root)
            .env("CACHE_TEST_ROOT", &self.root)
            .env("CARGO_RABS_WORKER", &self.worker)
            .env("CARGO", &self.cargo)
            .env("RUSTUP_TOOLCHAIN", "nightly-selected")
            .env("RUSTC_WRAPPER", "")
            .current_dir(&self.root)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        command
    }

    fn fields(&self, name: &str) -> Vec<Vec<u8>> {
        let bytes = fs::read(self.root.join(name)).unwrap();
        bytes
            .strip_suffix(&[0])
            .unwrap()
            .split(|byte| *byte == 0)
            .map(<[u8]>::to_vec)
            .collect()
    }

    fn assert_cargo(&self, output: &Output, arguments: &[OsString]) {
        assert_eq!(output.status.code(), Some(23), "{output:?}");
        assert_eq!(output.stdout, b"cargo stdout\0\xff\n");
        assert_eq!(output.stderr, b"cargo stderr\0\xfe\n");
        assert_eq!(fs::read(self.root.join("cargo.stdin")).unwrap(), INPUT);
        assert_eq!(
            fs::read(self.root.join("worker.calls")).unwrap(),
            b"worker\n"
        );
        assert_eq!(fs::read(self.root.join("cargo.calls")).unwrap(), b"cargo\n");
        assert_eq!(
            self.fields("cargo.argv"),
            arguments
                .iter()
                .map(|value| value.as_bytes().to_vec())
                .collect::<Vec<_>>()
        );
        assert_eq!(
            fs::read(self.root.join("cargo.cwd")).unwrap(),
            self.root.as_os_str().as_bytes()
        );
        assert_eq!(
            fs::read(self.root.join("cargo.pid")).unwrap(),
            fs::read(self.root.join("worker.pid")).unwrap()
        );
    }

    fn assert_unstarted(&self, output: &Output) {
        assert_eq!(output.status.code(), Some(2), "{output:?}");
        assert!(output.stdout.is_empty(), "{output:?}");
        assert!(!self.root.join("worker.calls").exists());
        assert!(!self.root.join("cargo.calls").exists());
    }
}

fn run(command: &mut Command) -> Output {
    let mut child = command.spawn().unwrap();
    if let Err(error) = child.stdin.take().unwrap().write_all(INPUT) {
        assert_eq!(error.kind(), std::io::ErrorKind::BrokenPipe);
    }
    child.wait_with_output().unwrap()
}

#[test]
fn native_cache_preserves_opaque_arguments_streams_environment_and_status() {
    let fixture = Fixture::new();
    let args = vec![
        "test".into(),
        "--".into(),
        "literal 'quotes' and spaces".into(),
        OsString::new(),
        OsString::from_vec(b"opaque-\xff".to_vec()),
        "--remote".into(),
    ];
    let result = run(fixture.command().args(&args));
    fixture.assert_cargo(&result, &args);
    assert_eq!(
        fixture.fields("cargo.env"),
        vec![
            b"nightly-selected".to_vec(),
            Vec::new(),
            b"unset".to_vec(),
            b"unset".to_vec()
        ]
    );
}

#[test]
fn native_cache_defaults_to_build_and_keeps_explicit_cargo_toolchain() {
    for args in [
        Vec::<OsString>::new(),
        vec!["--".into(), "+nightly-other".into(), "check".into()],
    ] {
        let fixture = Fixture::new();
        let result = run(fixture.command().args(&args));
        let expected = if args.is_empty() {
            vec!["build".into()]
        } else {
            args[1..].to_vec()
        };
        fixture.assert_cargo(&result, &expected);
    }
}

#[test]
fn native_cache_preserves_cargo_proxy_spelling_and_path_selection() {
    let fixture = Fixture::new();
    let bin = fixture.root.join("bin");
    fs::create_dir(&bin).unwrap();
    let proxy = bin.join("cargo");
    symlink(&fixture.cargo, &proxy).unwrap();
    let output = run(fixture.command().env_remove("CARGO").env("PATH", &bin));
    fixture.assert_cargo(&output, &["build".into()]);
    assert_eq!(
        fs::read(fixture.root.join("cargo.program")).unwrap(),
        proxy.as_os_str().as_bytes()
    );
}

#[test]
fn native_cache_refuses_missing_recursive_and_conflicting_selections_before_handoff() {
    for case in 0..8 {
        let fixture = Fixture::new();
        let mut command = fixture.command();
        match case {
            0 => {
                command.env("CARGO_RABS_WORKER", fixture.root.join("missing"));
            }
            1 => {
                command.env("CARGO_RABS_WORKER", BINARY);
            }
            2 => {
                command.env("CARGO", BINARY);
            }
            3 => {
                command.env("CARGO", &fixture.worker);
            }
            4 => {
                command.env("CARGO", "");
            }
            5 => {
                command.arg("--local").arg("profile.json");
            }
            6 => {
                command.arg("--rabs-require-daemon");
            }
            _ => {
                command.env("CARGO_RABS_ROOT_CAPACITY", "2");
            }
        }
        fixture.assert_unstarted(&run(&mut command));
    }
}

#[test]
fn native_cache_preserves_worker_refusal_without_starting_or_retrying_cargo() {
    let fixture = Fixture::new();
    let output = run(fixture.command().env("CACHE_TEST_WORKER_REFUSE", "73"));
    assert_eq!(output.status.code(), Some(73));
    assert!(output.stdout.is_empty());
    assert!(output.stderr.is_empty());
    assert_eq!(
        fs::read(fixture.root.join("worker.calls")).unwrap(),
        b"worker\n"
    );
    assert!(!fixture.root.join("cargo.calls").exists());
}

#[test]
fn native_cache_exec_retains_signal_termination() {
    let fixture = Fixture::new();
    let output = run(fixture.command().env("CACHE_TEST_SIGNAL", "TERM"));
    assert_eq!(output.status.signal(), Some(15));
    assert_eq!(
        fs::read(fixture.root.join("cargo.calls")).unwrap(),
        b"cargo\n"
    );
}

#[test]
fn native_cache_keeps_inherited_jobserver_descriptors() {
    assert_inherited_jobserver(BINARY, "--cache");
}

fn assert_inherited_jobserver(binary: &str, mode: &str) {
    let fixture = Fixture::new();
    // The shell intentionally opens inherited FD 7 before exec, exactly like
    // an existing Cargo jobserver owner. The frontend never closes/reopens it.
    let token = fixture.root.join("job-token");
    fs::write(&token, b"original jobserver token\n").unwrap();
    let command = fixture.command();
    let vars: Vec<_> = command
        .get_envs()
        .map(|(key, value)| (key.to_owned(), value.map(OsStr::to_owned)))
        .collect();
    let mut shell = Command::new("/bin/sh");
    shell
        .arg("-c")
        .arg("exec 7<\"$CACHE_TEST_TOKEN\"; exec \"$CACHE_TEST_BINARY\" \"$CACHE_TEST_MODE\" -- check")
        .env_clear()
        .current_dir(&fixture.root)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    for (key, value) in vars {
        if let Some(value) = value {
            shell.env(key, value);
        }
    }
    shell
        .env("CACHE_TEST_BINARY", binary)
        .env("CACHE_TEST_MODE", mode)
        .env("CACHE_TEST_TOKEN", &token)
        .env("CACHE_TEST_JOB_FD", "7")
        .env("CARGO_MAKEFLAGS", "--jobserver-auth=7,8 -j");
    let output = run(&mut shell);
    fixture.assert_cargo(&output, &["check".into()]);
    assert_eq!(
        fs::read(fixture.root.join("cargo.token")).unwrap(),
        b"original jobserver token"
    );
    assert_eq!(fixture.fields("cargo.env")[2], b"--jobserver-auth=7,8 -j");
}

#[test]
fn native_cache_retains_explicit_root_admission_in_the_exec_chain() {
    let fixture = Fixture::new();
    let root_helper = fixture.root.join("rabs-cargo-root");
    executable(
        &root_helper,
        r#"#!/bin/sh
printf '%s\0' "$@" > "$CACHE_TEST_ROOT/root.argv"
[ "$1" = -- ] || exit 94
shift
exec "$@"
"#,
    );
    let output = run(fixture
        .command()
        .env("CARGO_RABS_ROOT_BUDGET_DIR", fixture.root.join("budget"))
        .env("CARGO_RABS_ROOT_CAPACITY", "2")
        .env("CARGO_RABS_ROOT_CGROUP", "/sys/fs/cgroup/explicit-test")
        .env("CARGO_RABS_ROOT_HELPER", &root_helper)
        .arg("check"));
    fixture.assert_cargo(&output, &["check".into()]);
    assert_eq!(
        fixture.fields("root.argv"),
        vec![
            b"--".to_vec(),
            fixture.cargo.as_os_str().as_bytes().to_vec(),
            b"check".to_vec()
        ]
    );
    assert_eq!(
        fixture.fields("worker.argv")[4],
        root_helper.as_os_str().as_bytes()
    );
}

#[test]
fn cargo_subcommand_preserves_opaque_arguments_and_streams_without_an_interpreter_path() {
    let fixture = Fixture::new();
    let path = fixture.root.join("native-only-bin");
    fs::create_dir(&path).unwrap();
    symlink(SUBCOMMAND, path.join("cargo-rabs")).unwrap();
    let arguments = vec![
        "+nightly-selected".into(),
        "test".into(),
        "--".into(),
        "literal 'quotes' and spaces".into(),
        OsString::new(),
        OsString::from_vec(b"opaque-\xff".to_vec()),
        "--rabs-remote".into(),
    ];
    let output = run(fixture.subcommand().env("PATH", &path).args(&arguments));
    fixture.assert_cargo(&output, &arguments);
    assert_eq!(fs::read_dir(path).unwrap().count(), 1);
}

#[test]
fn cargo_subcommand_emits_exact_cache_policy_before_the_owned_command() {
    for (controls, expected) in [
        (vec!["--rabs-no-start"], vec!["--no-start"]),
        (vec!["--rabs-require-daemon"], vec!["--require-daemon"]),
        (
            vec!["--rabs-no-start", "--rabs-require-daemon"],
            vec!["--no-start", "--require-daemon"],
        ),
    ] {
        let fixture = Fixture::new();
        let output = run(fixture.subcommand().args(controls).arg("check"));
        fixture.assert_cargo(&output, &["check".into()]);
        let mut argv: Vec<Vec<u8>> = ["worker-cache", "--protocol", "v1"]
            .into_iter()
            .chain(expected)
            .chain(["--"])
            .map(|value| value.as_bytes().to_vec())
            .collect();
        argv.push(fixture.cargo.as_os_str().as_bytes().to_vec());
        argv.push(b"check".to_vec());
        assert_eq!(fixture.fields("worker.argv"), argv);
    }
}

#[test]
fn cargo_subcommand_defaults_and_delimiters_are_preserved_exactly() {
    for (input, expected) in [
        (vec![], vec!["build"]),
        (vec!["--"], vec!["build"]),
        (vec!["--", "--rabs-remote"], vec!["--rabs-remote"]),
        (
            vec!["--", "--", "--rabs-recover"],
            vec!["--", "--rabs-recover"],
        ),
    ] {
        let fixture = Fixture::new();
        let output = run(fixture.subcommand().args(input));
        fixture.assert_cargo(
            &output,
            &expected.iter().map(OsString::from).collect::<Vec<_>>(),
        );
    }
}

#[test]
fn cargo_subcommand_keeps_jobserver_signal_and_terminal_worker_refusal() {
    assert_inherited_jobserver(SUBCOMMAND, "rabs");
    let fixture = Fixture::new();
    let output = run(fixture.subcommand().env("CACHE_TEST_SIGNAL", "TERM"));
    assert_eq!(output.status.signal(), Some(15));
    assert_eq!(
        fs::read(fixture.root.join("cargo.calls")).unwrap(),
        b"cargo\n"
    );

    let fixture = Fixture::new();
    let output = run(fixture.subcommand().env("CACHE_TEST_WORKER_REFUSE", "255"));
    assert_eq!(output.status.code(), Some(255));
    assert!(!fixture.root.join("cargo.calls").exists());
    assert_eq!(
        fs::read(fixture.root.join("worker.calls")).unwrap(),
        b"worker\n"
    );
}

#[test]
fn real_cargo_discovers_the_native_subcommand_with_only_it_on_path() {
    let fixture = Fixture::new();
    let path = fixture.root.join("cargo-extensions");
    fs::create_dir(&path).unwrap();
    symlink(SUBCOMMAND, path.join("cargo-rabs")).unwrap();
    // This is Cargo's real external-subcommand discovery and injected `rabs`
    // argument. No worker, daemon, compiler or cache hit is claimed by help.
    for argument in ["--help", "--version", "--rabs-build-info"] {
        let output = Command::new(env!("CARGO"))
            .args(["rabs", argument])
            .env("PATH", &path)
            .env("CARGO_RABS_WORKER", "/missing/native-worker")
            .current_dir(&fixture.root)
            .output()
            .unwrap();
        assert!(output.status.success(), "{argument}: {output:?}");
        assert!(output.stderr.is_empty(), "{output:?}");
        if argument == "--rabs-build-info" {
            let info: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
            assert_eq!(info["tool"], "cargo-rabs");
        } else {
            assert!(!output.stdout.is_empty());
        }
    }
    assert!(!fixture.root.join("worker.calls").exists());
    assert!(!fixture.root.join("cargo.calls").exists());
}
