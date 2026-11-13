//! Native disk supervision with real worker processes and allocated output.
//! These local Unix checks do not qualify remote fleet behavior.

#![cfg(unix)]

use std::cell::Cell;
use std::fs;
use std::io::Write as _;
use std::os::unix::process::CommandExt as _;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use rustix::process::{Pid, Signal, WaitId, WaitIdOptions};
use serde_json::{Value, json};

const WORKER: &str = env!("CARGO_BIN_EXE_rch-wkr");
const MARKER: &str = "RCH_NATIVE_TEST_DISK_BUDGET:";
const USAGE: &str = "RCH_NATIVE_TEST_DISK_USAGE:";
const MIB: u64 = 1 << 20;

struct Fixture {
    root: PathBuf,
    target: PathBuf,
    next: Cell<usize>,
}

impl Fixture {
    fn new() -> Self {
        let root = tempfile::tempdir().unwrap().keep().canonicalize().unwrap();
        let target = root.join("target ' $literal cache");
        fs::create_dir(&target).unwrap();
        Self {
            root,
            target,
            next: Cell::new(0),
        }
    }

    fn invocation(&self, budget: u64, floor: u64) -> (PathBuf, Value, Command) {
        let index = self.next.get();
        self.next.set(index + 1);
        let receipt = self.root.join(format!("receipt-{index}"));
        let plan = json!({
            "probe": [&self.target], "output": [&self.target], "receipt": &receipt,
            "receipt_initialized": false, "timeout_seconds": 0,
            "warm_policy": null, "require_incremental_tracking": false,
        });
        let mut command = Command::new(WORKER);
        command
            .args([
                "disk-supervise",
                &budget.to_string(),
                &floor.to_string(),
                MARKER,
            ])
            .arg(&self.target)
            .env("RCH_TIMING_SCALE", "1")
            .env("TOKIO_WORKER_THREADS", "0")
            .current_dir(&self.target);
        (receipt, plan, command)
    }

    fn shell(&self, budget: u64, floor: u64, body: &str) -> (PathBuf, OwnedGroup) {
        let (receipt, plan, mut command) = self.invocation(budget, floor);
        command
            .arg(plan.to_string())
            .args(["tracked", "/bin/sh", "-c", body]);
        (receipt, OwnedGroup::spawn(command, None))
    }
}

/// The leader stays unreaped until every observation and cleanup signal ends.
/// A failed assertion therefore cannot turn a remembered PID into authority.
struct OwnedGroup {
    child: Option<Child>,
    pid: Pid,
}

impl OwnedGroup {
    fn spawn(mut command: Command, input: Option<&[u8]>) -> Self {
        let mut child = command
            .process_group(0)
            .stdin(if input.is_some() {
                Stdio::piped()
            } else {
                Stdio::null()
            })
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        if let Some(input) = input {
            child.stdin.take().unwrap().write_all(input).unwrap();
        }
        let pid = Pid::from_child(&child);
        Self {
            child: Some(child),
            pid,
        }
    }

    fn exited(&self) -> bool {
        rustix::process::waitid(
            WaitId::Pid(self.pid),
            WaitIdOptions::EXITED | WaitIdOptions::NOHANG | WaitIdOptions::NOWAIT,
        )
        .unwrap()
        .is_some()
    }

    fn ready(&self, path: &Path) {
        let deadline = Instant::now() + Duration::from_secs(10);
        while !fs::metadata(path).is_ok_and(|info| info.len() > 0) {
            assert!(
                !self.exited(),
                "supervisor exited before payload became ready"
            );
            assert!(Instant::now() < deadline, "payload did not become ready");
            thread::sleep(Duration::from_millis(10));
        }
    }

    fn wait_for_exit(&self) {
        let deadline = Instant::now() + Duration::from_secs(15);
        while !self.exited() {
            assert!(Instant::now() < deadline, "disk supervisor did not finish");
            thread::sleep(Duration::from_millis(10));
        }
    }

    fn finish(mut self) -> Output {
        self.wait_for_exit();
        let _ = rustix::process::kill_process_group(self.pid, Signal::KILL);
        self.child.take().unwrap().wait_with_output().unwrap()
    }
}

impl Drop for OwnedGroup {
    fn drop(&mut self) {
        if let Some(mut child) = self.child.take() {
            let _ = rustix::process::kill_process_group(self.pid, Signal::KILL);
            let _ = child.wait();
        }
    }
}

fn receipt(path: &Path, prefix: &str) -> Value {
    let text = fs::read_to_string(path).unwrap();
    let value = text
        .lines()
        .find_map(|line| line.strip_prefix(prefix))
        .unwrap_or_else(|| panic!("missing {prefix} in {text:?}"));
    serde_json::from_str(value).unwrap()
}

#[test]
fn native_probe_and_invalid_input_never_launch_a_payload() {
    let output = Command::new(WORKER)
        .args(["disk-supervise", "probe"])
        .env("TOKIO_WORKER_THREADS", "0")
        .output()
        .unwrap();
    assert!(output.status.success(), "{output:?}");
    assert_eq!(output.stdout, b"rch-wkr disk-supervise v1\n");
    assert!(output.stderr.is_empty());
    for budget in [0, u64::MAX] {
        let fixture = Fixture::new();
        let (_, child) = fixture.shell(budget, 0, "printf started > payload-started");
        let output = child.finish();
        assert!(!output.status.success(), "{output:?}");
        assert!(!fixture.target.join("payload-started").exists());
    }
    for scale in ["0", "NaN", "11", "1 trailing"] {
        let fixture = Fixture::new();
        let (_, plan, mut command) = fixture.invocation(8 * MIB, 0);
        command
            .arg(plan.to_string())
            .args(["tracked", "/bin/sh", "-c", "touch payload-started"])
            .env("RCH_TIMING_SCALE", scale);
        let output = OwnedGroup::spawn(command, None).finish();
        assert!(!output.status.success(), "{scale}: {output:?}");
        assert!(!fixture.target.join("payload-started").exists());
    }
}

#[test]
fn completed_commands_preserve_bytes_status_and_bound_receipts() {
    for status in [0, 37] {
        let fixture = Fixture::new();
        let body = format!(
            "printf 'compiler-output\\n'; printf unterminated-error >&2; printf small > artifact; exit {status}"
        );
        let (path, child) = fixture.shell(8 * MIB, 0, &body);
        let output = child.finish();
        assert_eq!(output.status.code(), Some(status), "{output:?}");
        assert_eq!(output.stdout, b"compiler-output\n");
        assert!(output.stderr.starts_with(b"unterminated-error"));
        let usage = receipt(&path, USAGE);
        assert_eq!(usage["complete"], true);
        assert_eq!(usage["exit_code"], status);
        assert!(usage["peak_output_bytes"].as_u64().unwrap() >= 4096);
        assert_eq!(fs::read(fixture.target.join("artifact")).unwrap(), b"small");
        assert!(fs::metadata(path).unwrap().len() <= 8192);
    }
}

#[test]
fn binary_stdin_and_literal_arguments_survive_supervision() {
    let fixture = Fixture::new();
    let (path, plan, mut command) = fixture.invocation(8 * MIB, 0);
    let argument = "space ' dollar $value ; literal";
    command.arg(plan.to_string()).args([
        "tracked",
        "/bin/sh",
        "-c",
        "printf '%s\\0' \"$1\"; cat",
        "payload",
        argument,
    ]);
    let input = b"\0rsync-input\xff\n\0";
    let output = OwnedGroup::spawn(command, Some(input)).finish();
    assert!(output.status.success(), "{output:?}");
    let mut expected = argument.as_bytes().to_vec();
    expected.push(0);
    expected.extend_from_slice(input);
    assert_eq!(output.stdout, expected);
    assert_eq!(receipt(&path, USAGE)["complete"], true);
}

#[test]
fn admission_refuses_before_start_and_receipt_ownership_cannot_be_reused() {
    let fixture = Fixture::new();
    let (path, child) = fixture.shell(MIB, 1 << 62, "touch payload-started");
    let output = child.finish();
    assert_eq!(output.status.code(), Some(120), "{output:?}");
    let refusal = receipt(&path, MARKER);
    assert_eq!(refusal["reason"], "admission");
    assert_eq!(refusal["started"], false);
    assert!(!fixture.target.join("payload-started").exists());

    let (path, mut plan, mut command) = fixture.invocation(8 * MIB, 0);
    let original = format!("{MARKER}{{\"reason\":\"growth\",\"started\":true}}\n");
    fs::write(&path, &original).unwrap();
    use std::os::unix::fs::PermissionsExt as _;
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
    plan["receipt_initialized"] = true.into();
    command
        .arg(plan.to_string())
        .args(["tracked", "/bin/sh", "-c", "touch payload-started"]);
    let output = OwnedGroup::spawn(command, None).finish();
    assert_eq!(output.status.code(), Some(120), "{output:?}");
    assert_eq!(fs::read_to_string(path).unwrap(), original);
    assert!(!fixture.target.join("payload-started").exists());
}

#[test]
fn excess_growth_stops_the_writer_and_retains_artifacts() {
    let fixture = Fixture::new();
    let (path, child) = fixture.shell(
        MIB,
        0,
        "head -c 4194304 /dev/urandom > large-output; printf ready > ready; sleep 30",
    );
    child.ready(&fixture.target.join("ready"));
    let output = child.finish();
    assert!(!output.status.success(), "{output:?}");
    let failure = receipt(&path, MARKER);
    assert_eq!(failure["reason"], "growth");
    assert_eq!(failure["started"], true);
    assert!(failure["growth_bytes"].as_u64().unwrap() >= 4 * MIB);
    assert_eq!(
        fs::metadata(fixture.target.join("large-output"))
            .unwrap()
            .len(),
        4 * MIB
    );
}

#[test]
fn stale_warm_pool_proof_requires_cold_readmission_before_payload() {
    let fixture = Fixture::new();
    let (path, child) = fixture.shell(8 * MIB, 0, "head -c 2097152 /dev/urandom > retained");
    let output = child.finish();
    assert!(output.status.success(), "{output:?}");
    let pool = receipt(&path, USAGE)["incremental"]["final_pool"].clone();
    assert!(pool.is_object());
    let policy = json!({"cold_growth_bytes": 8 * MIB, "pools": [pool, null, null, null, null, null, null, null]});
    let (path, mut plan, mut command) = fixture.invocation(MIB / 2, 0);
    plan["warm_policy"] = policy.clone();
    command
        .arg(plan.to_string())
        .args(["tracked", "/bin/sh", "-c", "exit 0"]);
    let output = OwnedGroup::spawn(command, None).finish();
    assert!(output.status.success(), "{output:?}");
    assert_eq!(receipt(&path, USAGE)["admitted_pool"], policy["pools"][0]);

    fs::write(
        fixture.target.join("retained"),
        vec![7_u8; 2 * MIB as usize],
    )
    .unwrap();
    let (path, mut plan, mut command) = fixture.invocation(MIB / 2, 0);
    plan["warm_policy"] = policy;
    command
        .arg(plan.to_string())
        .args(["tracked", "/bin/sh", "-c", "touch payload-started"]);
    let output = OwnedGroup::spawn(command, None).finish();
    assert_eq!(output.status.code(), Some(120), "{output:?}");
    let failure = receipt(&path, MARKER);
    assert_eq!(failure["reason"], "cold_required");
    assert_eq!(failure["required_growth_bytes"], 8 * MIB);
    assert_eq!(failure["started"], false);
    assert!(!fixture.target.join("payload-started").exists());
}

#[test]
fn execution_deadline_keeps_an_incomplete_usage_receipt() {
    let fixture = Fixture::new();
    let (path, mut plan, mut command) = fixture.invocation(8 * MIB, 0);
    plan["timeout_seconds"] = 1.into();
    command.arg(plan.to_string()).args([
        "tracked",
        "/bin/sh",
        "-c",
        "printf ready > ready; sleep 30",
    ]);
    let child = OwnedGroup::spawn(command, None);
    child.ready(&fixture.target.join("ready"));
    let output = child.finish();
    assert!(!output.status.success(), "{output:?}");
    let text = fs::read_to_string(&path).unwrap();
    assert!(text.lines().any(|line| line == "RCH_NATIVE_TEST"), "{text}");
    assert_eq!(receipt(&path, USAGE)["complete"], false);
}

#[cfg(target_os = "linux")]
fn assert_writer_stopped(path: &Path, group: Pid) {
    let pid: u32 = fs::read_to_string(path).unwrap().trim().parse().unwrap();
    let record = match fs::read_to_string(format!("/proc/{pid}/stat")) {
        Ok(record) => record,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return,
        Err(error) => panic!("inspect owned writer: {error}"),
    };
    let (_, tail) = record.rsplit_once(") ").unwrap();
    let fields: Vec<_> = tail.split_ascii_whitespace().collect();
    // A recycled PID in another group is no longer this test's writer.
    if fields[2].parse::<i32>().unwrap() == group.as_raw_nonzero().get() {
        assert!(
            matches!(fields[0], "Z" | "X"),
            "writer still alive before test cleanup: {record}"
        );
    }
}

#[cfg(target_os = "linux")]
#[test]
fn guardian_death_and_supervisor_death_revoke_live_writers() {
    for kill_guardian in [false, true] {
        let fixture = Fixture::new();
        let body = if kill_guardian {
            "printf '%s\\n' $$ > writer; printf ready > ready; while :; do printf x >> artifact; sleep 0.05; done"
        } else {
            "printf '%s\\n' $$ > writer; printf ready > ready; kill -KILL \"$PPID\"; while :; do printf x >> artifact; sleep 0.05; done"
        };
        let (_, child) = fixture.shell(8 * MIB, 0, body);
        child.ready(&fixture.target.join("ready"));
        if kill_guardian {
            rustix::process::kill_process(child.pid, Signal::KILL).unwrap();
        }
        child.wait_for_exit();
        let deadline = Instant::now() + Duration::from_secs(4);
        // An abruptly killed guardian exits before the lifetime watcher gets
        // scheduled. Observe the writer before the test's own group cleanup.
        loop {
            let pid = fs::read_to_string(fixture.target.join("writer")).unwrap();
            let state = fs::read_to_string(format!("/proc/{}/stat", pid.trim())).ok();
            if state.as_deref().is_none_or(|record| {
                record
                    .rsplit_once(") ")
                    .is_some_and(|(_, tail)| tail.starts_with("Z ") || tail.starts_with("X "))
            }) {
                break;
            }
            assert!(
                Instant::now() < deadline,
                "writer survived loss of supervision"
            );
            thread::sleep(Duration::from_millis(10));
        }
        assert_writer_stopped(&fixture.target.join("writer"), child.pid);
        assert!(!child.finish().status.success());
    }
}

#[cfg(target_os = "linux")]
#[test]
fn foreground_success_stops_background_writers_before_confirmation() {
    let fixture = Fixture::new();
    let (path, child) = fixture.shell(8 * MIB, 0,
        "sh -c 'printf \"%s\\n\" $$ > writer; while :; do printf x >> artifact; sleep 0.05; done' & while [ ! -s writer ]; do sleep 0.01; done; exit 0");
    child.ready(&fixture.target.join("writer"));
    child.wait_for_exit();
    assert_writer_stopped(&fixture.target.join("writer"), child.pid);
    let output = child.finish();
    assert!(output.status.success(), "{output:?}");
    assert_eq!(receipt(&path, USAGE)["complete"], true);
}
