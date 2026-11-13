//! Real processes, pipes and Unix sockets for native worker-cache preparation.
//! The tiny Cargo script and native daemon are explicit protocol fixtures;
//! these tests do not claim real Cargo compilation or cache-hit qualification.

#![cfg(target_os = "linux")]
#![forbid(unsafe_code)]

use rustix::fd::OwnedFd;
use rustix::fs::{FlockOperation, OFlags};
use rustix::io::{Errno, FdFlags};
use rustix::process::{Pid, PidfdFlags, Signal};
use serde_json::{Value, json};
use std::ffi::{OsStr, OsString};
use std::fs::{self, File, OpenOptions};
use std::io::{BufRead as _, BufReader, Write as _};
use std::os::unix::ffi::{OsStrExt as _, OsStringExt as _};
use std::os::unix::fs::PermissionsExt as _;
use std::os::unix::net::{UnixListener, UnixStream};
use std::os::unix::process::ExitStatusExt as _;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};
use std::time::{Duration, Instant};

const WORKER: &str = env!("CARGO_BIN_EXE_rch-wkr");
const INPUT: &[u8] = b"original stdin\0bytes\n";

fn quote(value: impl AsRef<OsStr>) -> String {
    format!(
        "'{}'",
        value.as_ref().to_str().unwrap().replace('\'', "'\\''")
    )
}

fn executable(path: &Path, script: &str) {
    fs::write(path, script).unwrap();
    fs::set_permissions(path, fs::Permissions::from_mode(0o755)).unwrap();
}

struct Fixture {
    root: PathBuf,
    cargo: PathBuf,
    wrapper: PathBuf,
    daemon: PathBuf,
    socket: PathBuf,
}

impl Fixture {
    fn new() -> Self {
        // Keep the native socket below SUN_LEN even under managed scratch.
        let root = tempfile::Builder::new()
            .prefix("rch-wc-")
            .tempdir_in("/tmp")
            .unwrap()
            .keep();
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
        fs::create_dir(root.join("bin")).unwrap();
        let cargo = root.join("bin/cargo");
        let wrapper = root.join("bin/rabs-wrap");
        let daemon = root.join("bin/rabsd");
        let socket = root.join("edge.sock");
        executable(
            &cargo,
            r#"#!/bin/sh
printf 'cargo\n' >> "$RCH_TEST_CACHE_ROOT/cargo.calls"
printf '%s\0' "$@" > "$RCH_TEST_CACHE_ROOT/cargo.argv"
printf '%s\0' "${RCH_TEST_OPAQUE-unset}" "${RUSTC_WRAPPER-unset}" "${RABS_SOCKET_PATH-unset}" "${RCH_RABS_WORKER_ACTIVE-unset}" "${RABS_REUSE_CARGO_LAYOUT-unset}" "${CARGO_MAKEFLAGS-unset}" > "$RCH_TEST_CACHE_ROOT/cargo.env"
/bin/cat > "$RCH_TEST_CACHE_ROOT/cargo.stdin"
if [ -n "${RCH_TEST_JOB_READ-}" ]; then
    IFS= read -r token <&"$RCH_TEST_JOB_READ" || exit 94
    printf '%s' "$token" > "$RCH_TEST_CACHE_ROOT/cargo.token"
fi
printf 'cargo stdout\n'
if [ "${RCH_TEST_CARGO_STDERR-1}" = 1 ]; then printf 'cargo stderr\n' >&2; fi
if [ -n "${RCH_TEST_CARGO_SIGNAL-}" ]; then
    kill -s "$RCH_TEST_CARGO_SIGNAL" "$$"
    exit 95
fi
exit 23
"#,
        );
        executable(&wrapper, "#!/bin/sh\nexit 0\n");
        executable(
            &daemon,
            &format!(
                "#!/bin/sh\nif [ \"${{1-}}\" = --check-config ]; then\n  RCH_TEST_CACHE_ROLE=config; export RCH_TEST_CACHE_ROLE\n  exec 3>&1\nelse\n  RCH_TEST_CACHE_ROLE=daemon; export RCH_TEST_CACHE_ROLE\nfi\nexec {} --ignored --exact worker_cache_fixture --nocapture >/dev/null\n",
                quote(std::env::current_exe().unwrap()),
            ),
        );
        Self {
            root,
            cargo,
            wrapper,
            daemon,
            socket,
        }
    }

    fn configure(&self, command: &mut Command) {
        command
            .env_clear()
            .env(
                "PATH",
                format!("{}:/usr/bin:/bin", self.root.join("bin").display()),
            )
            .env("HOME", self.root.join("home"))
            .env("TMPDIR", self.root.join("missing-scratch"))
            .env("RCH_LOG_FILE", self.root.join("missing-scratch/log"))
            .env("TOKIO_WORKER_THREADS", "0")
            .env("RCH_WKR_BIN", WORKER)
            .env("RCH_TEST_CACHE_ROOT", &self.root)
            .env("CARGO_RABS_WRAP", &self.wrapper)
            .env("CARGO_RABS_DAEMON", &self.daemon)
            .env("RABS_STATE_DIR", self.root.join("state"))
            .env("RABS_SOCKET_PATH", &self.socket)
            .env("RCH_RABS_PREPARE_TIMEOUT_MS", "4000")
            .env("CARGO_RABS_STARTUP_MS", "3500")
            .env(
                "RCH_TEST_OPAQUE",
                OsString::from_vec(b"original-\xff".to_vec()),
            );
    }

    fn command(&self, arguments: &[OsString]) -> Command {
        let mut command = Command::new(WORKER);
        command.args(["worker-cache", "--protocol", "v1", "--"]);
        command.arg(&self.cargo).args(arguments);
        self.configure(&mut command);
        command
    }

    fn fields(&self) -> Vec<Vec<u8>> {
        let bytes = fs::read(self.root.join("cargo.env")).unwrap();
        bytes
            .strip_suffix(&[0])
            .unwrap()
            .split(|byte| *byte == 0)
            .map(<[u8]>::to_vec)
            .collect()
    }

    fn assert_cargo(&self, output: &Output, arguments: &[OsString], calls: usize) {
        assert_eq!(output.status.code(), Some(23), "{output:?}");
        assert_eq!(output.stdout, b"cargo stdout\n", "{output:?}");
        assert_eq!(fs::read(self.root.join("cargo.stdin")).unwrap(), INPUT);
        let expected: Vec<u8> = arguments
            .iter()
            .flat_map(|arg| arg.as_bytes().iter().copied().chain([0]))
            .collect();
        assert_eq!(fs::read(self.root.join("cargo.argv")).unwrap(), expected);
        assert_eq!(
            fs::read(self.root.join("cargo.calls")).unwrap(),
            b"cargo\n".repeat(calls)
        );
        assert_eq!(self.fields()[0], b"original-\xff");
        assert!(!self.root.join("missing-scratch").exists());
    }

    fn assert_stock(&self) {
        let fields = self.fields();
        assert_eq!(fields[1], b"unset");
        assert_eq!(fields[2], self.socket.as_os_str().as_bytes());
        assert_eq!(fields[3], b"unset");
        assert_eq!(fields[4], b"unset");
    }

    fn daemon(&self) -> Process {
        Process::from_record(&self.root.join("daemon.pid"))
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        // Every helper has a separate 30s lifetime bound as a final backstop.
        // Normal cleanup requests only this fixture's daemon to stop.
        let _ = fs::write(self.root.join("daemon.stop"), b"stop");
        if let Some(process) = Process::try_from_record(&self.root.join("daemon.pid"))
            && !process.wait_dead(Duration::from_secs(1))
        {
            process.signal(Signal::KILL);
            assert!(
                process.wait_dead(Duration::from_secs(1)),
                "fixture daemon did not stop"
            );
        }
    }
}

struct Running(Option<Child>);

impl Running {
    fn start(command: &mut Command) -> Self {
        let mut child = command
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
            .unwrap();
        child.stdin.take().unwrap().write_all(INPUT).unwrap();
        Self(Some(child))
    }

    fn child(&mut self) -> &mut Child {
        self.0.as_mut().unwrap()
    }

    fn finish(mut self) -> Output {
        let until = Instant::now() + Duration::from_secs(8);
        while self.child().try_wait().unwrap().is_none() {
            assert!(
                Instant::now() < until,
                "worker-cache failed to settle within 8s"
            );
            std::thread::sleep(Duration::from_millis(10));
        }
        self.0.take().unwrap().wait_with_output().unwrap()
    }
}

impl Drop for Running {
    fn drop(&mut self) {
        if let Some(child) = &mut self.0 {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

fn run(command: &mut Command) -> Output {
    command.stderr(Stdio::piped());
    Running::start(command).finish()
}

fn wait_file(path: &Path) {
    let until = Instant::now() + Duration::from_secs(4);
    while !path.is_file() {
        assert!(
            Instant::now() < until,
            "fixture never produced {}",
            path.display()
        );
        std::thread::sleep(Duration::from_millis(5));
    }
}

fn process_identity(pid: u32) -> Option<(u64, u8)> {
    let bytes = fs::read(format!("/proc/{pid}/stat")).ok()?;
    let end = bytes.windows(2).rposition(|bytes| bytes == b") ")?;
    let fields: Vec<_> = bytes[end + 2..]
        .split(|byte| byte.is_ascii_whitespace())
        .collect();
    let start = std::str::from_utf8(fields.get(19)?).ok()?.parse().ok()?;
    Some((start, *fields.first()?.first()?))
}

struct Process {
    pid: u32,
    start: u64,
    descriptor: OwnedFd,
}

impl Process {
    fn try_from_record(path: &Path) -> Option<Self> {
        let value: Value = serde_json::from_slice(&fs::read(path).ok()?).ok()?;
        let pid = u32::try_from(value["pid"].as_u64()?).ok()?;
        let start = value["start"].as_u64()?;
        let descriptor =
            rustix::process::pidfd_open(Pid::from_raw(pid as i32)?, PidfdFlags::empty()).ok()?;
        if process_identity(pid).map(|identity| identity.0) != Some(start) {
            return None;
        }
        Some(Self {
            pid,
            start,
            descriptor,
        })
    }

    fn from_record(path: &Path) -> Self {
        wait_file(path);
        Self::try_from_record(path)
            .unwrap_or_else(|| panic!("fixture identity was not live: {}", path.display()))
    }

    fn dead(&self) -> bool {
        process_identity(self.pid)
            .is_none_or(|(start, state)| start != self.start || matches!(state, b'Z' | b'X' | b'x'))
    }

    fn wait_dead(&self, budget: Duration) -> bool {
        let until = Instant::now() + budget;
        while !self.dead() && Instant::now() < until {
            std::thread::sleep(Duration::from_millis(5));
        }
        self.dead()
    }

    fn signal(&self, signal: Signal) {
        let result = rustix::process::pidfd_send_signal(&self.descriptor, signal);
        assert!(matches!(result, Ok(()) | Err(Errno::SRCH)), "{result:?}");
    }
}

impl Drop for Process {
    fn drop(&mut self) {
        if !self.dead() {
            let _ = rustix::process::pidfd_send_signal(&self.descriptor, Signal::KILL);
        }
    }
}

fn opaque_arguments() -> Vec<OsString> {
    ["build", "", "a b", "literal;$(not-a-command)", "'quotes'"]
        .into_iter()
        .map(OsString::from)
        .chain([OsString::from_vec(b"opaque-\xff".to_vec())])
        .collect()
}

#[test]
fn native_prepare_starts_once_preserves_cargo_and_keeps_shared_daemon() {
    let fixture = Fixture::new();
    let arguments = opaque_arguments();
    let output = run(&mut fixture.command(&arguments));
    fixture.assert_cargo(&output, &arguments, 1);
    assert_eq!(output.stderr, b"cargo stderr\n", "{output:?}");
    let fields = fixture.fields();
    assert_eq!(fields[1], fixture.wrapper.as_os_str().as_bytes());
    assert_eq!(fields[3], b"1");
    assert_eq!(fields[4], b"unset", "daemon-only default leaked into Cargo");
    let daemon = fixture.daemon();
    assert!(
        !daemon.dead(),
        "preparation cleanup killed the shared daemon"
    );
    let state = fixture.root.join("state/cargo-launcher");
    let daemon_env: Value =
        serde_json::from_slice(&fs::read(fixture.root.join("daemon.env")).unwrap()).unwrap();
    assert_eq!(daemon_env["TMPDIR"], state.to_str().unwrap());
    assert_eq!(daemon_env["RABS_REUSE_CARGO_LAYOUT"], "1");
    for lock in [
        state.join("startup.lock"),
        fixture.root.join(".rabs-edge.sock.startup.lock"),
    ] {
        let lock = File::open(lock).unwrap();
        assert_eq!(
            rustix::fs::flock(&lock, FlockOperation::NonBlockingLockExclusive),
            Err(Errno::WOULDBLOCK)
        );
    }
    let output = run(&mut fixture.command(&arguments));
    fixture.assert_cargo(&output, &arguments, 2);
    assert_eq!(
        fs::read(fixture.root.join("daemon.calls")).unwrap(),
        b"daemon\n"
    );
    assert!(!daemon.dead());
}

#[test]
fn common_command_adapter_preserves_selector_and_shell_arguments() {
    let fixture = Fixture::new();
    // The public builder reads its opt-in flag. Give only the isolated helper
    // process that environment; never mutate the libtest process environment.
    let mut render = Command::new(std::env::current_exe().unwrap());
    fixture.configure(&mut render);
    let output = render
        .args([
            "--ignored",
            "--exact",
            "worker_cache_fixture",
            "--nocapture",
        ])
        .env("RCH_RABS_WORKER_CACHE", "1")
        .env("RCH_TEST_CACHE_ROLE", "render-adapter")
        .output()
        .unwrap();
    assert!(output.status.success(), "{output:?}");
    let wrapped = fs::read_to_string(fixture.root.join("adapter.sh")).unwrap();
    let mut command = Command::new("/bin/sh");
    command.args(["-c", &wrapped]);
    fixture.configure(&mut command);
    command.env("RCH_RABS_PREPARE_TIMEOUT_MS", "0");
    let output = run(&mut command);
    let arguments = ["+stable", "check", "--features", "a b", "--", ";literal"].map(OsString::from);
    fixture.assert_cargo(&output, &arguments, 1);
    assert!(!fixture.root.join("config.pid").exists());
}

#[test]
fn missing_native_helpers_fall_back_once_with_original_environment() {
    for missing in ["CARGO_RABS_WRAP", "CARGO_RABS_DAEMON"] {
        let fixture = Fixture::new();
        let arguments = opaque_arguments();
        let mut command = fixture.command(&arguments);
        command.env(missing, fixture.root.join("missing"));
        let output = run(&mut command);
        fixture.assert_cargo(&output, &arguments, 1);
        fixture.assert_stock();
        assert!(String::from_utf8_lossy(&output.stderr).contains("using stock Cargo"));
        assert!(!fixture.root.join("daemon.pid").exists());
    }
}

#[test]
fn zero_budget_and_active_invocations_never_start_preparation() {
    for active in [false, true] {
        let fixture = Fixture::new();
        let arguments = opaque_arguments();
        let mut command = fixture.command(&arguments);
        command.env("RCH_TEST_CONFIG_MODE", "stopped-tree");
        if active {
            command.env("RCH_RABS_WORKER_ACTIVE", "1");
        } else {
            command.env("RCH_RABS_PREPARE_TIMEOUT_MS", "0");
        }
        let output = run(&mut command);
        fixture.assert_cargo(&output, &arguments, 1);
        assert_eq!(output.stderr, b"cargo stderr\n");
        assert_eq!(fixture.fields()[1], b"unset");
        assert_eq!(
            fixture.fields()[3],
            if active {
                b"1".as_slice()
            } else {
                b"unset".as_slice()
            }
        );
        assert!(!fixture.root.join("config.pid").exists());
    }
}

#[test]
fn custom_or_explicitly_disabled_wrappers_are_preserved() {
    for value in ["custom", ""] {
        let fixture = Fixture::new();
        let custom = fixture.root.join("bin/custom");
        executable(&custom, "#!/bin/sh\nexit 0\n");
        let selected = if value.is_empty() {
            OsString::new()
        } else {
            custom.into_os_string()
        };
        let arguments = opaque_arguments();
        let mut command = fixture.command(&arguments);
        command.env("RUSTC_WRAPPER", &selected);
        let output = run(&mut command);
        fixture.assert_cargo(&output, &arguments, 1);
        assert_eq!(fixture.fields()[1], selected.as_bytes());
        assert_eq!(fixture.fields()[3], b"unset");
        assert!(!fixture.root.join("config.pid").exists());
    }
}

#[test]
fn bounded_configuration_failure_reaps_stopped_descendants_before_cargo() {
    let fixture = Fixture::new();
    let arguments = opaque_arguments();
    let mut command = fixture.command(&arguments);
    command
        .env("RCH_TEST_CONFIG_MODE", "stopped-tree")
        .env("RCH_RABS_PREPARE_TIMEOUT_MS", "500")
        .stderr(Stdio::piped());
    let running = Running::start(&mut command);
    let config = Process::from_record(&fixture.root.join("config.pid"));
    let descendant = Process::from_record(&fixture.root.join("descendant.pid"));
    let output = running.finish();
    fixture.assert_cargo(&output, &arguments, 1);
    fixture.assert_stock();
    assert!(config.dead(), "configuration survived fallback");
    assert!(descendant.dead(), "descendant survived fallback");
}

#[test]
fn setup_cancellation_settles_every_descendant_before_reporting_signal() {
    for signal in [Signal::INT, Signal::TERM, Signal::HUP] {
        let fixture = Fixture::new();
        let mut command = fixture.command(&opaque_arguments());
        command
            .env("RCH_TEST_CONFIG_MODE", "stopped-tree")
            .stderr(Stdio::piped());
        let mut running = Running::start(&mut command);
        let config = Process::from_record(&fixture.root.join("config.pid"));
        let descendant = Process::from_record(&fixture.root.join("descendant.pid"));
        rustix::process::kill_process(Pid::from_child(running.child()), signal).unwrap();
        let output = running.finish();
        assert_eq!(
            output.status.code(),
            Some(128 + signal.as_raw()),
            "{signal:?} {output:?}"
        );
        assert!(
            config.dead(),
            "{signal:?} reported before configuration stopped"
        );
        assert!(
            descendant.dead(),
            "{signal:?} reported before descendant stopped"
        );
        assert!(
            !fixture.root.join("cargo.calls").exists(),
            "cancellation ran Cargo"
        );
        assert!(output.stdout.is_empty(), "{output:?}");
    }
}

#[test]
fn cargo_exec_keeps_default_signal_termination() {
    for (name, signal) in [("PIPE", Signal::PIPE), ("TERM", Signal::TERM)] {
        let fixture = Fixture::new();
        let mut command = fixture.command(&opaque_arguments());
        command
            .env("CARGO_RABS_WRAP", fixture.root.join("missing"))
            .env("RCH_TEST_CARGO_SIGNAL", name);
        let output = run(&mut command);
        assert_eq!(output.status.signal(), Some(signal.as_raw()), "{output:?}");
        assert_eq!(output.stdout, b"cargo stdout\n");
        assert_eq!(
            fs::read(fixture.root.join("cargo.calls")).unwrap(),
            b"cargo\n"
        );
        assert_eq!(fs::read(fixture.root.join("cargo.stdin")).unwrap(), INPUT);
        fixture.assert_stock();
    }
}

#[test]
fn adapter_death_revokes_preparation_and_stopped_adapter_keeps_its_deadline() {
    for stopped in [false, true] {
        let fixture = Fixture::new();
        let arguments = opaque_arguments();
        let mut command = fixture.command(&arguments);
        command
            .env("RCH_TEST_CONFIG_MODE", "stopped-tree")
            .env("RCH_RABS_PREPARE_TIMEOUT_MS", "1500")
            .stderr(Stdio::piped());
        let mut running = Running::start(&mut command);
        let config = Process::from_record(&fixture.root.join("config.pid"));
        let descendant = Process::from_record(&fixture.root.join("descendant.pid"));
        let pid = Pid::from_child(running.child());
        rustix::process::kill_process(pid, if stopped { Signal::STOP } else { Signal::KILL })
            .unwrap();
        assert!(
            config.wait_dead(Duration::from_secs(3)),
            "config survived owner/deadline revocation"
        );
        assert!(
            descendant.wait_dead(Duration::from_secs(1)),
            "descendant survived owner/deadline revocation"
        );
        assert!(
            !fixture.root.join("cargo.calls").exists(),
            "Cargo ran before setup settled"
        );
        if stopped {
            rustix::process::kill_process(pid, Signal::CONT).unwrap();
            let output = running.finish();
            fixture.assert_cargo(&output, &arguments, 1);
        } else {
            let output = running.finish();
            assert!(!output.status.success());
            assert!(!fixture.root.join("cargo.calls").exists());
        }
    }
}

#[test]
fn adapter_death_does_not_kill_a_shared_daemon_started_during_preparation() {
    let fixture = Fixture::new();
    let mut command = fixture.command(&opaque_arguments());
    command
        .env("RCH_TEST_DAEMON_MODE", "stall")
        .stderr(Stdio::piped());
    let mut running = Running::start(&mut command);
    let daemon = fixture.daemon();
    running.child().kill().unwrap();
    let output = running.finish();
    assert!(!output.status.success());
    assert!(!daemon.dead(), "shared daemon was killed with setup");
    assert!(!fixture.root.join("cargo.calls").exists());
}

#[test]
fn closed_or_stalled_diagnostic_reader_cannot_block_stock_cargo() {
    for closed in [false, true] {
        let fixture = Fixture::new();
        let arguments = opaque_arguments();
        let (read, write) = rustix::pipe::pipe_with(rustix::pipe::PipeFlags::CLOEXEC).unwrap();
        if !closed {
            let flags = rustix::fs::fcntl_getfl(&write).unwrap();
            rustix::fs::fcntl_setfl(&write, flags | OFlags::NONBLOCK).unwrap();
            loop {
                match rustix::io::write(&write, &[b'x'; 4096]) {
                    Ok(_) => (),
                    Err(Errno::AGAIN) => break,
                    result => panic!("fill diagnostic pipe: {result:?}"),
                }
            }
            rustix::fs::fcntl_setfl(&write, flags).unwrap();
        }
        let read = (!closed).then_some(read);
        let mut command = fixture.command(&arguments);
        command
            .env("CARGO_RABS_WRAP", fixture.root.join("missing"))
            .env("RCH_TEST_CARGO_STDERR", "0")
            .stderr(Stdio::from(write));
        let output = Running::start(&mut command).finish();
        fixture.assert_cargo(&output, &arguments, 1);
        fixture.assert_stock();
        drop(read);
    }
}

#[test]
fn cargo_keeps_jobserver_descriptors_that_preparation_does_not_inherit() {
    use std::os::fd::AsRawFd as _;
    let fixture = Fixture::new();
    let arguments = opaque_arguments();
    let (read, write) = rustix::pipe::pipe_with(rustix::pipe::PipeFlags::CLOEXEC).unwrap();
    rustix::io::write(&write, b"jobserver token\n").unwrap();
    let target = fs::read_link(format!("/proc/self/fd/{}", read.as_raw_fd())).unwrap();
    let flags = format!(
        "--jobserver-auth={},{} -j",
        read.as_raw_fd(),
        write.as_raw_fd()
    );
    let mut command = fixture.command(&arguments);
    command
        .env("CARGO_MAKEFLAGS", &flags)
        .env("RCH_TEST_JOB_READ", read.as_raw_fd().to_string())
        .stderr(Stdio::piped());
    rustix::io::fcntl_setfd(&read, FdFlags::empty()).unwrap();
    rustix::io::fcntl_setfd(&write, FdFlags::empty()).unwrap();
    let running = Running::start(&mut command);
    rustix::io::fcntl_setfd(&read, FdFlags::CLOEXEC).unwrap();
    rustix::io::fcntl_setfd(&write, FdFlags::CLOEXEC).unwrap();
    let output = running.finish();
    fixture.assert_cargo(&output, &arguments, 1);
    assert_eq!(
        fs::read(fixture.root.join("cargo.token")).unwrap(),
        b"jobserver token"
    );
    assert_eq!(fixture.fields()[5], flags.as_bytes());
    let inherited: Vec<String> =
        serde_json::from_slice(&fs::read(fixture.root.join("daemon.fds")).unwrap()).unwrap();
    assert!(
        !inherited.contains(&target.to_string_lossy().into_owned()),
        "shared daemon retained Cargo's jobserver"
    );
}

fn record_process(root: &Path, role: &str) {
    let pid = std::process::id();
    let start = process_identity(pid).unwrap().0;
    fs::write(
        root.join(format!("{role}.pid")),
        serde_json::to_vec(&json!({"pid":pid,"start":start})).unwrap(),
    )
    .unwrap();
}

fn fixture_config(root: &Path) {
    let mode = std::env::var("RCH_TEST_CONFIG_MODE").unwrap_or_default();
    if mode == "stopped-tree" {
        let mut child = Command::new(std::env::current_exe().unwrap())
            .args([
                "--ignored",
                "--exact",
                "worker_cache_fixture",
                "--nocapture",
            ])
            .env("RCH_TEST_CACHE_ROLE", "descendant")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        wait_file(&root.join("descendant.pid"));
        record_process(root, "config");
        rustix::process::kill_process(rustix::process::getpid(), Signal::STOP).unwrap();
        let _ = child.wait();
        return;
    }
    record_process(root, "config");
    let mut output = OpenOptions::new()
        .write(true)
        .open("/proc/self/fd/3")
        .unwrap();
    let config = json!({"kind":"rabsd-config","live_dependency":true,"socket_path":std::env::var("RABS_SOCKET_PATH").unwrap()});
    output
        .write_all(&serde_json::to_vec(&config).unwrap())
        .unwrap();
}

fn fixture_daemon(root: &Path) {
    let socket = PathBuf::from(std::env::var_os("RABS_SOCKET_PATH").unwrap());
    let listener = UnixListener::bind(&socket).unwrap();
    fs::set_permissions(&socket, fs::Permissions::from_mode(0o600)).unwrap();
    listener.set_nonblocking(true).unwrap();
    let selected = [
        "TMPDIR",
        "RABS_REUSE_CARGO_LAYOUT",
        "RCH_RABS_WORKER_ACTIVE",
    ]
    .map(|name| (name, std::env::var(name).unwrap_or_default()))
    .into_iter()
    .collect::<std::collections::BTreeMap<_, _>>();
    fs::write(
        root.join("daemon.env"),
        serde_json::to_vec(&selected).unwrap(),
    )
    .unwrap();
    let descriptors = fs::read_dir("/proc/self/fd")
        .unwrap()
        .filter_map(Result::ok)
        .filter_map(|entry| fs::read_link(entry.path()).ok())
        .map(|path| path.to_string_lossy().into_owned())
        .collect::<Vec<_>>();
    fs::write(
        root.join("daemon.fds"),
        serde_json::to_vec(&descriptors).unwrap(),
    )
    .unwrap();
    OpenOptions::new()
        .create(true)
        .append(true)
        .open(root.join("daemon.calls"))
        .unwrap()
        .write_all(b"daemon\n")
        .unwrap();
    record_process(root, "daemon");
    let until = Instant::now() + Duration::from_secs(30);
    while Instant::now() < until && !root.join("daemon.stop").exists() {
        match listener.accept() {
            Ok((stream, _)) => serve_fixture(stream, root),
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                std::thread::sleep(Duration::from_millis(5))
            }
            Err(error) => panic!("fixture accept: {error}"),
        }
    }
}

fn serve_fixture(mut stream: UnixStream, root: &Path) {
    stream
        .set_read_timeout(Some(Duration::from_millis(250)))
        .unwrap();
    stream
        .set_write_timeout(Some(Duration::from_millis(250)))
        .unwrap();
    let mut reader = BufReader::new(stream.try_clone().unwrap());
    let mut line = String::new();
    if !matches!(reader.read_line(&mut line), Ok(1..)) {
        return;
    }
    let request: Value = serde_json::from_str(&line).unwrap();
    assert_eq!(request["kind"], "hello");
    if std::env::var("RCH_TEST_DAEMON_MODE").as_deref() == Ok("stall") {
        while !root.join("daemon.stop").exists() {
            std::thread::sleep(Duration::from_millis(10));
        }
        return;
    }
    if stream
        .write_all(b"{\"kind\":\"hello-ok\",\"transport\":1,\"application\":1}\n")
        .is_err()
    {
        return;
    }
    line.clear();
    if !matches!(reader.read_line(&mut line), Ok(1..)) {
        return;
    }
    let request: Value = serde_json::from_str(&line).unwrap();
    assert_eq!(request["kind"], "status");
    let _ = stream.write_all(b"{\"kind\":\"coord-status\",\"live_dependency\":true}\n");
}

#[test]
#[ignore = "native subprocess fixture, invoked only by the parent regression tests"]
fn worker_cache_fixture() {
    let root = PathBuf::from(std::env::var_os("RCH_TEST_CACHE_ROOT").unwrap());
    match std::env::var("RCH_TEST_CACHE_ROLE").unwrap().as_str() {
        "config" => fixture_config(&root),
        "daemon" => fixture_daemon(&root),
        "render-adapter" => {
            let command =
                "RCH_TEST_PREFIX='two words' cargo +stable check --features 'a b' -- ';literal'";
            let wrapped = rch_common::toolchain::wrap_command_with_toolchain(command, None);
            fs::write(root.join("adapter.sh"), wrapped).unwrap();
        }
        "descendant" => {
            record_process(&root, "descendant");
            rustix::process::kill_process(rustix::process::getpid(), Signal::STOP).unwrap();
            std::thread::sleep(Duration::from_secs(30));
        }
        role => panic!("unknown fixture role {role}"),
    }
    std::process::exit(0);
}
